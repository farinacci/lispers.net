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
   self . curve25519 = curve25519 . Private ( III )
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
  if ( type ( key ) == long ) : key = self . normalize_pub_key ( key )
  return ( old_div ( len ( key ) , 2 ) )
  if 9 - 9: OoooooooOO / I11i
  if 47 - 47: OoooooooOO
 def print_key ( self , key ) :
  o00oOOo0Oo = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( o00oOOo0Oo [ 0 : 4 ] , o00oOOo0Oo [ - 4 : : ] , self . key_length ( o00oOOo0Oo ) ) )
  if 48 - 48: OoOoOO00 . IiII % I1IiiI + I11i
  if 37 - 37: Oo0Ooo + I1Ii111 * oO0o / o0oOOo0O0Ooo
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == long ) :
   key = lisp_hex_string ( key ) . zfill ( 256 )
   return ( key )
   if 78 - 78: IiII + I11i - o0oOOo0O0Ooo + OoO0O00 / iIii1I11I1II1
  if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
  return ( key )
  if 47 - 47: OOooOOo
  if 20 - 20: I1Ii111 % ooOoO0o - I1Ii111 * OoooooooOO / I1ii11iIi11i
 def print_keys ( self , do_bold = True ) :
  oOO0O00o0O0 = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   oOO0O00o0O0 += "none"
  else :
   oOO0O00o0O0 += self . print_key ( self . local_public_key )
   if 57 - 57: IiII % I11i * OOooOOo % I1ii11iIi11i
  iiiI1I = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   iiiI1I += "none"
  else :
   iiiI1I += self . print_key ( self . remote_public_key )
   if 65 - 65: i1IIi - OoooooooOO
  OO0o = "ECDH" if ( self . curve25519 ) else "DH"
  oOO00o0 = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( OO0o , oOO00o0 , oOO0O00o0O0 , iiiI1I ) )
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
  III = self . local_private_key
  Oo = self . dh_g_value
  iIIiiIi = self . dh_p_value
  return ( int ( ( Oo ** III ) % iIIiiIi ) )
  if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
  if 100 - 100: II111iiii / I1Ii111 / iII111i - I1ii11iIi11i * iIii1I11I1II1
 def compute_shared_key ( self , ed , print_shared = False ) :
  III = self . local_private_key
  Ii1Oo = self . remote_public_key
  if 58 - 58: I1ii11iIi11i % i11iIiiIii + OoOoOO00 / I11i - OoooooooOO
  oO = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( oO , self . print_keys ( ) ) )
  if 48 - 48: O0 - ooOoO0o
  if ( self . curve25519 ) :
   iii = curve25519 . Public ( Ii1Oo )
   self . shared_key = self . curve25519 . get_shared_key ( iii )
  else :
   iIIiiIi = self . dh_p_value
   self . shared_key = ( Ii1Oo ** III ) % iIIiiIi
   if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
   if 41 - 41: OoooooooOO
   if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
   if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
   if 78 - 78: Ii1I
   if 29 - 29: II111iiii
   if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
  if ( print_shared ) :
   o00oOOo0Oo = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( o00oOOo0Oo ) )
   if 84 - 84: Oo0Ooo % I11i * O0 * I11i
   if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
   if 12 - 12: Oo0Ooo + I1IiiI
   if 37 - 37: i1IIi * i11iIiiIii
   if 95 - 95: i11iIiiIii % I1Ii111 * Oo0Ooo + i1IIi . O0 + I1ii11iIi11i
  self . compute_encrypt_icv_keys ( )
  if 7 - 7: OoO0O00 * i11iIiiIii * iIii1I11I1II1 / OOooOOo / I1Ii111
  if 35 - 35: iII111i * OOooOOo
  if 65 - 65: II111iiii % i1IIi
  if 13 - 13: OoO0O00 * I1Ii111 + Oo0Ooo - IiII
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 31 - 31: OoO0O00
  if 68 - 68: OoO0O00 + i1IIi / iIii1I11I1II1 + II111iiii * iIii1I11I1II1 + I1ii11iIi11i
 def compute_encrypt_icv_keys ( self ) :
  Ooo00OoO = hashlib . sha256
  if ( self . curve25519 ) :
   oOO = self . shared_key
  else :
   oOO = lisp_hex_string ( self . shared_key )
   if 52 - 52: OoO0O00 % i11iIiiIii . ooOoO0o % OoOoOO00 % OoooooooOO
   if 5 - 5: OoOoOO00 / O0 / i11iIiiIii
   if 88 - 88: II111iiii - iII111i / OoooooooOO
   if 71 - 71: I1ii11iIi11i
   if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
  oOO0O00o0O0 = self . local_public_key
  if ( type ( oOO0O00o0O0 ) != int ) : oOO0O00o0O0 = int ( binascii . hexlify ( oOO0O00o0O0 ) , 16 )
  iiiI1I = self . remote_public_key
  if ( type ( iiiI1I ) != int ) : iiiI1I = int ( binascii . hexlify ( iiiI1I ) , 16 )
  i1iI11IiII = "0001" + "lisp-crypto" + lisp_hex_string ( oOO0O00o0O0 ^ iiiI1I ) + "0100"
  if 83 - 83: I1ii11iIi11i
  OOo0OOooO0 = hmac . new ( i1iI11IiII . encode ( ) , oOO , Ooo00OoO ) . hexdigest ( )
  OOo0OOooO0 = int ( OOo0OOooO0 , 16 )
  if 80 - 80: I1ii11iIi11i
  if 67 - 67: II111iiii
  if 2 - 2: o0oOOo0O0Ooo - O0 * Ii1I % IiII
  if 64 - 64: i1IIi . ooOoO0o
  IIO000O = ( OOo0OOooO0 >> 128 ) & LISP_16_128_MASK
  OOoO00OOo = OOo0OOooO0 & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( IIO000O ) . zfill ( 32 )
  iiiiiiii = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( OOoO00OOo ) . zfill ( iiiiiiii )
  if 74 - 74: I1ii11iIi11i % I1Ii111 - OoO0O00 * I11i . OoooooooOO * OoO0O00
  if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   ii1Ii1111 = self . icv . poly1305aes
   III11Iii111 = self . icv . binascii . hexlify
   nonce = III11Iii111 ( nonce )
   O0O00000oo0O0 = ii1Ii1111 ( self . encrypt_key , self . icv_key , nonce , packet )
   O0O00000oo0O0 = III11Iii111 ( O0O00000oo0O0 . encode ( "raw_unicode_escape" ) )
  else :
   III = binascii . unhexlify ( self . icv_key )
   O0O00000oo0O0 = hmac . new ( III , packet , self . icv ) . hexdigest ( )
   O0O00000oo0O0 = O0O00000oo0O0 [ 0 : 40 ]
   if 36 - 36: I1ii11iIi11i * o0oOOo0O0Ooo + i11iIiiIii + OoooooooOO
  return ( O0O00000oo0O0 )
  if 82 - 82: OoOoOO00 . OoOoOO00
  if 10 - 10: Oo0Ooo * I1ii11iIi11i . oO0o . OoooooooOO . OOooOOo * I1ii11iIi11i
 def add_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 80 - 80: I1Ii111 + I11i . I1Ii111 + OOooOOo
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
  if 43 - 43: IiII . OoooooooOO - II111iiii
 def delete_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
  if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
 def add_key_by_rloc ( self , addr_str , encap ) :
  IIiI = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 11 - 11: ooOoO0o
  if 36 - 36: OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
  if ( addr_str not in IIiI ) :
   IIiI [ addr_str ] = [ None , None , None , None ]
   if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
  IIiI [ addr_str ] [ self . key_id ] = self
  if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
  if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
  if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
  if 28 - 28: iIii1I11I1II1 . O0
  if 32 - 32: OoooooooOO
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , IIiI [ addr_str ] )
   if 29 - 29: I1ii11iIi11i
   if 41 - 41: Ii1I
   if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
 def encode_lcaf ( self , rloc_addr ) :
  Iii = self . normalize_pub_key ( self . local_public_key )
  O0O0O0OOO0o = self . key_length ( Iii )
  oO0Oo0oOo = ( 6 + O0O0O0OOO0o + 2 )
  if ( rloc_addr != None ) : oO0Oo0oOo += rloc_addr . addr_length ( )
  if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
  Oo00oo = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( oO0Oo0oOo ) , 1 , 0 )
  if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
  if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
  if 49 - 49: I1ii11iIi11i
  if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
  if 18 - 18: Oo0Ooo + IiII
  if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
  oOO00o0 = self . cipher_suite
  Oo00oo += struct . pack ( "BBH" , oOO00o0 , 0 , socket . htons ( O0O0O0OOO0o ) )
  if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
  if 31 - 31: Ii1I / iII111i
  if 3 - 3: IiII
  if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
  for iIi1iIIIiIiI in range ( 0 , O0O0O0OOO0o * 2 , 16 ) :
   III = int ( Iii [ iIi1iIIIiIiI : iIi1iIIIiIiI + 16 ] , 16 )
   Oo00oo += struct . pack ( "Q" , byte_swap_64 ( III ) )
   if 61 - 61: OOooOOo . OOooOOo
   if 17 - 17: II111iiii / ooOoO0o
   if 80 - 80: OOooOOo * OoO0O00 + Ii1I
   if 62 - 62: OoooooooOO . O0 % Oo0Ooo
   if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
  if ( rloc_addr ) :
   Oo00oo += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   Oo00oo += rloc_addr . pack_address ( )
   if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
  return ( Oo00oo )
  if 88 - 88: I1Ii111 - OoO0O00
  if 79 - 79: iII111i
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
  if 48 - 48: I1ii11iIi11i + Oo0Ooo
  if 76 - 76: I1ii11iIi11i
  if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
  if ( lcaf_len == 0 ) :
   iiII1iiI = "HHBBH"
   ooo0000oo0 = struct . calcsize ( iiII1iiI )
   if ( len ( packet ) < ooo0000oo0 ) : return ( None )
   if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
   i1I1iiiI , I1i , oO000O0oO00 , I1i , lcaf_len = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
   if 25 - 25: I11i - OoOoOO00
   if 4 - 4: Oo0Ooo - O0 / I11i + O0 - oO0o * Oo0Ooo
   if ( oO000O0oO00 != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 25 - 25: I1IiiI
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ ooo0000oo0 : : ]
   if 64 - 64: oO0o
   if 80 - 80: o0oOOo0O0Ooo % iIii1I11I1II1
   if 63 - 63: IiII * i11iIiiIii
   if 86 - 86: I11i % I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
   if 26 - 26: II111iiii * iII111i + o0oOOo0O0Ooo / O0 + i1IIi - I11i
   if 56 - 56: OOooOOo
  oO000O0oO00 = LISP_LCAF_SECURITY_TYPE
  iiII1iiI = "BBBBH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 76 - 76: i1IIi % iIii1I11I1II1 - o0oOOo0O0Ooo + IiII - I11i
  OOOo00o , I1i , oOO00o0 , I1i , O0O0O0OOO0o = struct . unpack ( iiII1iiI ,
 packet [ : ooo0000oo0 ] )
  if 100 - 100: iIii1I11I1II1 - OoOoOO00
  if 28 - 28: Oo0Ooo . O0 . I11i
  if 60 - 60: II111iiii + I1Ii111 / oO0o % OoooooooOO - i1IIi
  if 57 - 57: ooOoO0o
  if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if 52 - 52: I1ii11iIi11i
  packet = packet [ ooo0000oo0 : : ]
  O0O0O0OOO0o = socket . ntohs ( O0O0O0OOO0o )
  if ( len ( packet ) < O0O0O0OOO0o ) : return ( None )
  if 93 - 93: iII111i . i11iIiiIii
  if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
  if 49 - 49: O0 . Oo0Ooo / Ii1I
  if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
  Oo0O = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( oOO00o0 not in Oo0O ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( Oo0O ,
 oOO00o0 ) )
   packet = packet [ O0O0O0OOO0o : : ]
   return ( packet )
   if 84 - 84: OoooooooOO . i11iIiiIii % OoO0O00 * Oo0Ooo / iII111i
   if 95 - 95: OoO0O00 - i11iIiiIii . OoO0O00 % OOooOOo * O0 + i11iIiiIii
  self . cipher_suite = oOO00o0
  if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
  if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
  if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
  if 63 - 63: oO0o
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  Iii = 0
  for iIi1iIIIiIiI in range ( 0 , O0O0O0OOO0o , 8 ) :
   III = byte_swap_64 ( struct . unpack ( "Q" , packet [ iIi1iIIIiIiI : iIi1iIIIiIiI + 8 ] ) [ 0 ] )
   Iii <<= 64
   Iii |= III
   if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
  self . remote_public_key = Iii
  if 60 - 60: I1Ii111
  if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
  if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
  if 14 - 14: Ii1I - O0
  if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
  if ( self . curve25519 ) :
   III = lisp_hex_string ( self . remote_public_key )
   III = III . zfill ( 64 )
   I1i1ii1IiI1i = ""
   for iIi1iIIIiIiI in range ( 0 , len ( III ) , 2 ) :
    I1i1ii1IiI1i += chr ( int ( III [ iIi1iIIIiIiI : iIi1iIIIiIiI + 2 ] , 16 ) )
    if 78 - 78: iII111i
   self . remote_public_key = I1i1ii1IiI1i
   if 15 - 15: iII111i + i11iIiiIii % O0 % I1Ii111 + OoO0O00 * ooOoO0o
   if 46 - 46: iII111i . OoOoOO00
  packet = packet [ O0O0O0OOO0o : : ]
  return ( packet )
  if 18 - 18: I1ii11iIi11i
  if 33 - 33: i11iIiiIii % o0oOOo0O0Ooo . iII111i * OOooOOo / I11i
  if 25 - 25: OoO0O00
  if 39 - 39: Ii1I * OoOoOO00 + Oo0Ooo . OOooOOo - O0 * I1ii11iIi11i
  if 98 - 98: IiII * iII111i . OoooooooOO . O0
  if 89 - 89: iII111i / O0 % OoooooooOO - O0 . OoO0O00
  if 32 - 32: ooOoO0o
  if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
class lisp_thread ( object ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 57 - 57: I1ii11iIi11i - OoO0O00 * iIii1I11I1II1
  if 26 - 26: OoO0O00 % ooOoO0o % o0oOOo0O0Ooo % OoOoOO00 . iII111i % O0
  if 91 - 91: II111iiii . Oo0Ooo . oO0o - OoooooooOO / OoOoOO00
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
  if 82 - 82: iIii1I11I1II1 . I11i / IiII / OOooOOo * II111iiii % oO0o
  if 62 - 62: II111iiii
 def decode ( self , packet ) :
  iiII1iiI = "BBBBQ"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( False )
  if 96 - 96: I11i % OoOoOO00 * I1ii11iIi11i
  OOoo0ooO0 , Oo0OoO00OO0 , oO000OO0 , self . record_count , self . nonce = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 96 - 96: i1IIi % I1ii11iIi11i + iIii1I11I1II1
  if 37 - 37: O0
  self . type = OOoo0ooO0 >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( OOoo0ooO0 & 0x01 ) else False
   self . rloc_probe = True if ( OOoo0ooO0 & 0x02 ) else False
   self . smr_invoked_bit = True if ( Oo0OoO00OO0 & 0x40 ) else False
   if 97 - 97: oO0o - OoO0O00 + iII111i * O0
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( OOoo0ooO0 & 0x04 ) else False
   self . to_etr = True if ( OOoo0ooO0 & 0x02 ) else False
   self . to_ms = True if ( OOoo0ooO0 & 0x01 ) else False
   if 55 - 55: i11iIiiIii + i1IIi % II111iiii + I11i % ooOoO0o
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( OOoo0ooO0 & 0x08 ) else False
   if 67 - 67: I1ii11iIi11i / Oo0Ooo * i11iIiiIii / OoOoOO00
  return ( True )
  if 38 - 38: I1IiiI . oO0o / O0 % Oo0Ooo / IiII / OoooooooOO
  if 11 - 11: O0 / I1Ii111 / iIii1I11I1II1 % Ii1I
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
  if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 93 - 93: ooOoO0o % I1Ii111
  if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 43 - 43: ooOoO0o . i1IIi
  if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 45 - 45: I1IiiI
  if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
  if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
  if 61 - 61: Oo0Ooo - I1Ii111
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 51 - 51: iII111i * ooOoO0o / O0 / O0
  if 52 - 52: OoooooooOO % O0
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 98 - 98: OoooooooOO
  if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
 def print_map_register ( self ) :
  Oo00Ooo0O0O0o = lisp_hex_string ( self . xtr_id )
  if 86 - 86: I1IiiI + iIii1I11I1II1 % ooOoO0o / OOooOOo / OoooooooOO
  IiiiI1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 96 - 96: oO0o - II111iiii % I1IiiI * IiII * I11i - OOooOOo
  lprint ( IiiiI1 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # OoooooooOO * OoO0O00 * iII111i + ooOoO0o - i1IIi
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , Oo00Ooo0O0O0o , self . site_id ) )
  if 66 - 66: IiII / OoOoOO00 % O0 % o0oOOo0O0Ooo - OOooOOo / OoOoOO00
  if 11 - 11: I1IiiI + IiII
  if 95 - 95: I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
  if 67 - 67: OoOoOO00 % Oo0Ooo
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
   if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
   if 73 - 73: I1ii11iIi11i
   if 92 - 92: i11iIiiIii + O0 * I11i
   if 60 - 60: o0oOOo0O0Ooo / Oo0Ooo
   if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 76 - 76: OoO0O00 * oO0o - OoO0O00
    if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
    if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
  Oo00oo = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  Oo00oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
  Oo00oo = self . zero_auth ( Oo00oo )
  return ( Oo00oo )
  if 70 - 70: O0 . Ii1I
  if 33 - 33: OOooOOo * Ii1I
 def zero_auth ( self , packet ) :
  oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  ooo = b""
  III1II1I1iI = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   ooo = struct . pack ( "QQI" , 0 , 0 , 0 )
   III1II1I1iI = struct . calcsize ( "QQI" )
   if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   ooo = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   III1II1I1iI = struct . calcsize ( "QQQQ" )
   if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
  packet = packet [ 0 : oo00 ] + ooo + packet [ oo00 + III1II1I1iI : : ]
  return ( packet )
  if 70 - 70: I11i . I1ii11iIi11i * oO0o
  if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
 def encode_auth ( self , packet ) :
  oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  III1II1I1iI = self . auth_len
  ooo = self . auth_data
  packet = packet [ 0 : oo00 ] + ooo + packet [ oo00 + III1II1I1iI : : ]
  return ( packet )
  if 23 - 23: I1ii11iIi11i % I11i
  if 18 - 18: OoooooooOO . i1IIi + II111iiii
 def decode ( self , packet ) :
  O0OOOOO0O = packet
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  if 44 - 44: II111iiii / I1Ii111
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  iIiIii = socket . ntohl ( iIiIii [ 0 ] )
  packet = packet [ ooo0000oo0 : : ]
  if 93 - 93: II111iiii / IiII . Oo0Ooo - I1ii11iIi11i * Ii1I
  iiII1iiI = "QBBH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  if 25 - 25: II111iiii * i1IIi + IiII * o0oOOo0O0Ooo / OOooOOo
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 66 - 66: i11iIiiIii . OoO0O00 / OoOoOO00 - I1Ii111
  if 99 - 99: Ii1I - IiII - i1IIi / i11iIiiIii . IiII
  self . nonce = byte_swap_64 ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( iIiIii & 0x08000000 ) else False
  if 58 - 58: OOooOOo
  self . lisp_sec_present = True if ( iIiIii & 0x04000000 ) else False
  self . xtr_id_present = True if ( iIiIii & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( iIiIii & 0x800 ) else False
  self . map_register_refresh = True if ( iIiIii & 0x1000 ) else False
  self . merge_register_requested = True if ( iIiIii & 0x400 ) else False
  self . mobile_node = True if ( iIiIii & 0x200 ) else False
  self . map_notify_requested = True if ( iIiIii & 0x100 ) else False
  self . record_count = iIiIii & 0xff
  if 12 - 12: I1IiiI . o0oOOo0O0Ooo * OoooooooOO
  if 64 - 64: OoOoOO00 + IiII - i1IIi . II111iiii . OoO0O00
  if 31 - 31: oO0o . iII111i - I11i . iIii1I11I1II1 + I11i . OoOoOO00
  if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
  self . encrypt_bit = True if iIiIii & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( iIiIii >> 14 ) & 0x7
   if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
   if 30 - 30: OoooooooOO % OOooOOo
   if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
   if 81 - 81: iII111i % Ii1I . ooOoO0o
   if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( O0OOOOO0O ) == False ) : return ( [ None , None ] )
   if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
   if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
  packet = packet [ ooo0000oo0 : : ]
  if 20 - 20: ooOoO0o
  if 63 - 63: iIii1I11I1II1 . OoO0O00
  if 100 - 100: i1IIi * i1IIi
  if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 94 - 94: IiII
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 15 - 15: Ii1I - IiII / O0
    if 28 - 28: I1Ii111 . i1IIi / I1ii11iIi11i
   III1II1I1iI = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    ooo0000oo0 = struct . calcsize ( "QQI" )
    if ( III1II1I1iI < ooo0000oo0 ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 77 - 77: i11iIiiIii / I1Ii111 / i11iIiiIii % OoOoOO00 - I1Ii111
    O0oOoo0o0o0 , O0O0o , Oooo0O00oO = struct . unpack ( "QQI" , packet [ : III1II1I1iI ] )
    Oo0OO0ooO0O0O = b""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    ooo0000oo0 = struct . calcsize ( "QQQQ" )
    if ( III1II1I1iI < ooo0000oo0 ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 76 - 76: o0oOOo0O0Ooo / I11i
    O0oOoo0o0o0 , O0O0o , Oooo0O00oO , Oo0OO0ooO0O0O = struct . unpack ( "QQQQ" ,
 packet [ : III1II1I1iI ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 95 - 95: OoOoOO00 - O0 % OoooooooOO
    return ( [ None , None ] )
    if 13 - 13: i11iIiiIii
   self . auth_data = lisp_concat_auth_data ( self . alg_id , O0oOoo0o0o0 , O0O0o ,
 Oooo0O00oO , Oo0OO0ooO0O0O )
   O0OOOOO0O = self . zero_auth ( O0OOOOO0O )
   packet = packet [ self . auth_len : : ]
   if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
  return ( [ O0OOOOO0O , packet ] )
  if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
  if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
 def encode_xtr_id ( self , packet ) :
  I1iIii1iii11i = self . xtr_id >> 64
  o00oOo0oO0oOO = self . xtr_id & 0xffffffffffffffff
  I1iIii1iii11i = byte_swap_64 ( I1iIii1iii11i )
  o00oOo0oO0oOO = byte_swap_64 ( o00oOo0oO0oOO )
  Oooo0 = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , I1iIii1iii11i , o00oOo0oO0oOO , Oooo0 )
  return ( packet )
  if 62 - 62: I1IiiI - IiII - OoooooooOO
  if 69 - 69: I1Ii111 - oO0o + i1IIi
 def decode_xtr_id ( self , packet ) :
  ooo0000oo0 = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - ooo0000oo0 : : ]
  I1iIii1iii11i , o00oOo0oO0oOO , Oooo0 = struct . unpack ( "QQQ" ,
 packet [ : ooo0000oo0 ] )
  I1iIii1iii11i = byte_swap_64 ( I1iIii1iii11i )
  o00oOo0oO0oOO = byte_swap_64 ( o00oOo0oO0oOO )
  self . xtr_id = ( I1iIii1iii11i << 64 ) | o00oOo0oO0oOO
  self . site_id = byte_swap_64 ( Oooo0 )
  return ( True )
  if 95 - 95: i1IIi / I1Ii111 / Ii1I + OoooooooOO
  if 36 - 36: OoO0O00
  if 89 - 89: iII111i . OOooOOo . I1ii11iIi11i
  if 93 - 93: II111iiii
  if 8 - 8: Ii1I * OoooooooOO / Ii1I / OoO0O00 % OoOoOO00 + I11i
  if 16 - 16: I11i % ooOoO0o - i11iIiiIii
  if 38 - 38: o0oOOo0O0Ooo / I1ii11iIi11i - O0
  if 21 - 21: OOooOOo
  if 77 - 77: II111iiii
  if 54 - 54: OoooooooOO % O0 % O0 * Ii1I % II111iiii + OOooOOo
  if 89 - 89: IiII - o0oOOo0O0Ooo - II111iiii * Ii1I . iIii1I11I1II1
  if 33 - 33: I1IiiI . iIii1I11I1II1 / i11iIiiIii * Ii1I
  if 18 - 18: OoOoOO00 * OoOoOO00 - o0oOOo0O0Ooo % ooOoO0o % II111iiii - IiII
  if 75 - 75: OoO0O00 . II111iiii . oO0o / OoO0O00 % iIii1I11I1II1
  if 8 - 8: O0 / II111iiii
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
  if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
  if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
 def print_notify ( self ) :
  ooo = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( ooo ) != 40 ) :
   ooo = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( ooo ) != 64 ) :
   ooo = self . auth_data
   if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
  IiiiI1 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( IiiiI1 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # OOooOOo - oO0o
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , ooo ) )
  if 1 - 1: iIii1I11I1II1 / i11iIiiIii * II111iiii
  if 48 - 48: I1ii11iIi11i + O0 * oO0o + I1ii11iIi11i + I1ii11iIi11i
  if 60 - 60: II111iiii % Oo0Ooo
  if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   ooo = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 47 - 47: I1Ii111 + I1IiiI
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   ooo = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
  packet += ooo
  return ( packet )
  if 80 - 80: oO0o
  if 81 - 81: OoooooooOO / ooOoO0o * iIii1I11I1II1 . Oo0Ooo + oO0o / O0
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   iIiIii = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   iIiIii = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 84 - 84: II111iiii - o0oOOo0O0Ooo
  Oo00oo = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  Oo00oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 78 - 78: IiII
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = Oo00oo + eid_records
   return ( self . packet )
   if 58 - 58: i11iIiiIii - OoOoOO00
   if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
   if 99 - 99: ooOoO0o . Ii1I
   if 92 - 92: i1IIi
   if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
  Oo00oo = self . zero_auth ( Oo00oo )
  Oo00oo += eid_records
  if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
  II1Iii1iI = lisp_hash_me ( Oo00oo , self . alg_id , password , False )
  if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
  oo00 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  III1II1I1iI = self . auth_len
  self . auth_data = II1Iii1iI
  Oo00oo = Oo00oo [ 0 : oo00 ] + II1Iii1iI + Oo00oo [ oo00 + III1II1I1iI : : ]
  self . packet = Oo00oo
  return ( Oo00oo )
  if 4 - 4: Ii1I
  if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
 def decode ( self , packet ) :
  O0OOOOO0O = packet
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  iIiIii = socket . ntohl ( iIiIii [ 0 ] )
  self . map_notify_ack = ( ( iIiIii >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = iIiIii & 0xff
  packet = packet [ ooo0000oo0 : : ]
  if 32 - 32: I1Ii111 / oO0o / I1IiiI
  iiII1iiI = "QBBH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 69 - 69: oO0o - I1IiiI
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ ooo0000oo0 : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
  if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
  if 35 - 35: I1ii11iIi11i % OoooooooOO
  if 59 - 59: I1IiiI % I11i
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 32 - 32: I1IiiI * O0 + O0
  III1II1I1iI = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   O0oOoo0o0o0 , O0O0o , Oooo0O00oO = struct . unpack ( "QQI" , packet [ : III1II1I1iI ] )
   Oo0OO0ooO0O0O = ""
   if 34 - 34: IiII
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   O0oOoo0o0o0 , O0O0o , Oooo0O00oO , Oo0OO0ooO0O0O = struct . unpack ( "QQQQ" ,
 packet [ : III1II1I1iI ] )
   if 5 - 5: OoO0O00 . I1IiiI
  self . auth_data = lisp_concat_auth_data ( self . alg_id , O0oOoo0o0o0 , O0O0o ,
 Oooo0O00oO , Oo0OO0ooO0O0O )
  if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
  ooo0000oo0 = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( O0OOOOO0O [ : ooo0000oo0 ] )
  ooo0000oo0 += III1II1I1iI
  packet += O0OOOOO0O [ ooo0000oo0 : : ]
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
  Oo00Ooo0O0O0o = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   Oo00Ooo0O0O0o = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 30 - 30: II111iiii
   if 27 - 27: i1IIi - iIii1I11I1II1 + O0 % Oo0Ooo / OOooOOo + i1IIi
   if 48 - 48: Oo0Ooo
  IiiiI1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 70 - 70: OoooooooOO * i11iIiiIii
  lprint ( IiiiI1 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , Oo00Ooo0O0O0o ) )
  if 96 - 96: OoOoOO00 . i11iIiiIii - i1IIi . I1IiiI
  iI1iiiiiii = self . keys
  for OOooOooOOoO0O in self . itr_rlocs :
   if ( OOooOooOOoO0O . afi == LISP_AFI_LCAF and self . json_telemetry != None ) :
    continue
    if 50 - 50: iII111i . I1IiiI
   O00oo00Ooo = red ( OOooOooOOoO0O . print_address_no_iid ( ) , False )
   lprint ( "  itr-rloc: afi {} {}{}" . format ( OOooOooOOoO0O . afi , O00oo00Ooo ,
 "" if ( iI1iiiiiii == None ) else ", " + iI1iiiiiii [ 1 ] . print_keys ( ) ) )
   iI1iiiiiii = None
   if 25 - 25: ooOoO0o
  if ( self . json_telemetry != None ) :
   lprint ( "  itr-rloc: afi {} telemetry: {}" . format ( LISP_AFI_LCAF ,
 self . json_telemetry ) )
   if 83 - 83: Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
   if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
   if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
 def sign_map_request ( self , privkey ) :
  i1i1i11IIii = self . signature_eid . print_address ( )
  I1I = self . source_eid . print_address ( )
  oOO0oOOOOO0 = self . target_eid . print_address ( )
  OO0OOo0O = lisp_hex_string ( self . nonce ) + I1I + oOO0oOOOOO0
  self . map_request_signature = privkey . sign ( OO0OOo0O )
  Oooo0oOoO0000 = binascii . b2a_base64 ( self . map_request_signature )
  Oooo0oOoO0000 = { "source-eid" : I1I , "signature-eid" : i1i1i11IIii ,
 "signature" : Oooo0oOoO0000 }
  return ( json . dumps ( Oooo0oOoO0000 ) )
  if 95 - 95: I11i - iIii1I11I1II1
  if 20 - 20: o0oOOo0O0Ooo / o0oOOo0O0Ooo
 def verify_map_request_sig ( self , pubkey ) :
  IiIii1ii = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( IiIii1ii ) )
   return ( False )
   if 17 - 17: I1Ii111 + i11iIiiIii . i11iIiiIii * i1IIi / O0
   if 2 - 2: II111iiii / OoO0O00 % iIii1I11I1II1 / i11iIiiIii
  I1I = self . source_eid . print_address ( )
  oOO0oOOOOO0 = self . target_eid . print_address ( )
  OO0OOo0O = lisp_hex_string ( self . nonce ) + I1I + oOO0oOOOOO0
  pubkey = binascii . a2b_base64 ( pubkey )
  if 52 - 52: ooOoO0o % iIii1I11I1II1 . i11iIiiIii % ooOoO0o
  oO0oO00OO00 = True
  try :
   III = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 75 - 75: o0oOOo0O0Ooo + I1IiiI % ooOoO0o * I1Ii111
   oO0oO00OO00 = False
   if 87 - 87: II111iiii + O0 / iII111i * ooOoO0o
   if 52 - 52: iIii1I11I1II1 / iII111i . O0 * IiII . I1IiiI
  if ( oO0oO00OO00 ) :
   try :
    oO0oO00OO00 = III . verify ( self . map_request_signature , OO0OOo0O )
   except :
    oO0oO00OO00 = False
    if 67 - 67: II111iiii + Ii1I - I1IiiI * ooOoO0o
    if 19 - 19: i11iIiiIii * Oo0Ooo
    if 33 - 33: i11iIiiIii + I1IiiI
  OO00O = bold ( "passed" if oO0oO00OO00 else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( OO00O , IiIii1ii ) )
  return ( oO0oO00OO00 )
  if 15 - 15: O0
  if 14 - 14: iII111i % o0oOOo0O0Ooo % o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i - Ii1I
 def encode_json ( self , json_string ) :
  oO000O0oO00 = LISP_LCAF_JSON_TYPE
  ooOOooooo0Oo = socket . htons ( LISP_AFI_LCAF )
  I1ii = socket . htons ( len ( json_string ) + 4 )
  i1IiI11I11I = socket . htons ( len ( json_string ) )
  Oo00oo = struct . pack ( "HBBBBHH" , ooOOooooo0Oo , 0 , 0 , oO000O0oO00 , 0 , I1ii ,
 i1IiI11I11I )
  Oo00oo += json_string . encode ( )
  Oo00oo += struct . pack ( "H" , 0 )
  return ( Oo00oo )
  if 2 - 2: iIii1I11I1II1 * OoOoOO00 . O0 / OoO0O00
  if 3 - 3: I1ii11iIi11i
 def encode ( self , probe_dest , probe_port ) :
  iIiIii = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  if 53 - 53: I11i . OoooooooOO % ooOoO0o
  IIIiIiIIII1i1 = lisp_telemetry_configured ( ) if ( self . rloc_probe ) else None
  if ( IIIiIiIIII1i1 != None ) : self . itr_rloc_count += 1
  iIiIii = iIiIii | ( self . itr_rloc_count << 8 )
  if 90 - 90: I1IiiI % ooOoO0o % OoooooooOO / OoO0O00 . IiII * II111iiii
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
  if 83 - 83: oO0o
  Oo00oo = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  if 34 - 34: OoOoOO00
  if 75 - 75: I11i / iIii1I11I1II1 + I1ii11iIi11i / OoO0O00
  if 50 - 50: I1Ii111 / I11i % iIii1I11I1II1
  if 46 - 46: ooOoO0o + iII111i - Oo0Ooo % OOooOOo + OoooooooOO + iIii1I11I1II1
  if 99 - 99: OoO0O00 - IiII * IiII + oO0o / iII111i + OOooOOo
  if 58 - 58: i11iIiiIii + iIii1I11I1II1 * o0oOOo0O0Ooo - OoOoOO00
  i11i = False
  iIiii1Ii1I = self . privkey_filename
  if ( iIiii1Ii1I != None and os . path . exists ( iIiii1Ii1I ) ) :
   I1Ii = open ( iIiii1Ii1I , "r" ) ; III = I1Ii . read ( ) ; I1Ii . close ( )
   try :
    III = ecdsa . SigningKey . from_pem ( III )
   except :
    return ( None )
    if 29 - 29: iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / OoOoOO00 - i11iIiiIii
   o00O = self . sign_map_request ( III )
   i11i = True
  elif ( self . map_request_signature != None ) :
   Oooo0oOoO0000 = binascii . b2a_base64 ( self . map_request_signature )
   o00O = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : Oooo0oOoO0000 }
   o00O = json . dumps ( o00O )
   i11i = True
   if 87 - 87: o0oOOo0O0Ooo % iII111i / ooOoO0o - IiII + i11iIiiIii
  if ( i11i ) :
   Oo00oo += self . encode_json ( o00O )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    Oo00oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    Oo00oo += self . source_eid . lcaf_encode_iid ( )
   else :
    Oo00oo += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    Oo00oo += self . source_eid . pack_address ( )
    if 85 - 85: OoooooooOO * IiII . OOooOOo / iII111i / OoooooooOO
    if 87 - 87: OoO0O00
    if 32 - 32: i11iIiiIii - OoOoOO00 * I11i . Oo0Ooo * ooOoO0o
    if 21 - 21: OOooOOo
    if 11 - 11: oO0o % i11iIiiIii * O0
    if 28 - 28: I1Ii111 / iIii1I11I1II1 + OOooOOo . I1ii11iIi11i % OOooOOo + OoO0O00
    if 79 - 79: oO0o
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   O0O0 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 39 - 39: I1Ii111 % oO0o % O0 % O0 - iII111i - oO0o
   if ( O0O0 in lisp_crypto_keys_by_rloc_encap ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
    if 83 - 83: i11iIiiIii + iIii1I11I1II1
    if 21 - 21: o0oOOo0O0Ooo / i11iIiiIii % I1Ii111
    if 56 - 56: o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
    if 11 - 11: OOooOOo
    if 12 - 12: OoooooooOO * OOooOOo * I1ii11iIi11i * ooOoO0o
    if 26 - 26: OoooooooOO . i1IIi + OoO0O00
    if 42 - 42: i11iIiiIii * o0oOOo0O0Ooo % I11i % Oo0Ooo + o0oOOo0O0Ooo * i11iIiiIii
  for OOooOooOOoO0O in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( OOooOooOOoO0O ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     iI1iiiiiii = lisp_keys ( 1 )
     self . keys = [ None , iI1iiiiiii , None , None ]
     if 66 - 66: Ii1I / IiII . OoooooooOO * Oo0Ooo % i11iIiiIii
    iI1iiiiiii = self . keys [ 1 ]
    iI1iiiiiii . add_key_by_nonce ( self . nonce )
    Oo00oo += iI1iiiiiii . encode_lcaf ( OOooOooOOoO0O )
   else :
    Oo00oo += struct . pack ( "H" , socket . htons ( OOooOooOOoO0O . afi ) )
    Oo00oo += OOooOooOOoO0O . pack_address ( )
    if 100 - 100: I1ii11iIi11i % II111iiii * i11iIiiIii - iII111i
    if 69 - 69: OOooOOo + iII111i / I1Ii111
    if 37 - 37: iIii1I11I1II1 * I11i / IiII * Oo0Ooo % i11iIiiIii
    if 93 - 93: ooOoO0o + ooOoO0o
    if 65 - 65: OoooooooOO * I11i * oO0o % I1ii11iIi11i * II111iiii
    if 86 - 86: i11iIiiIii / I11i * iII111i - iII111i
  if ( IIIiIiIIII1i1 != None ) :
   i1 = str ( time . time ( ) )
   IIIiIiIIII1i1 = lisp_encode_telemetry ( IIIiIiIIII1i1 , io = i1 )
   self . json_telemetry = IIIiIiIIII1i1
   Oo00oo += self . encode_json ( IIIiIiIIII1i1 )
   if 32 - 32: Oo0Ooo . O0
   if 48 - 48: I1ii11iIi11i % II111iiii + I11i
  I1iIii11iIi1I = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 83 - 83: ooOoO0o + i1IIi / I11i + I1Ii111
  if 12 - 12: OoO0O00 . iII111i + I1ii11iIi11i . Ii1I
  ii1I11 = 0
  if ( self . subscribe_bit ) :
   ii1I11 = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 47 - 47: OoooooooOO + Ii1I
    if 44 - 44: Ii1I * OoOoOO00 + Oo0Ooo . i11iIiiIii + i1IIi
    if 83 - 83: iII111i + OoOoOO00 % ooOoO0o
  iiII1iiI = "BB"
  Oo00oo += struct . pack ( iiII1iiI , ii1I11 , I1iIii11iIi1I )
  if 76 - 76: i1IIi % I1IiiI + i1IIi
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
   if 2 - 2: iII111i + iII111i
   if 51 - 51: OoooooooOO + i11iIiiIii
   if 57 - 57: Oo0Ooo % o0oOOo0O0Ooo
   if 99 - 99: o0oOOo0O0Ooo / i11iIiiIii / II111iiii + OOooOOo . i1IIi + OoOoOO00
   if 7 - 7: I1IiiI / ooOoO0o % OoO0O00 + oO0o . o0oOOo0O0Ooo / I11i
  if ( self . subscribe_bit ) : Oo00oo = self . encode_xtr_id ( Oo00oo )
  return ( Oo00oo )
  if 84 - 84: OOooOOo + II111iiii . o0oOOo0O0Ooo * Oo0Ooo
  if 68 - 68: Ii1I % Ii1I
 def lcaf_decode_json ( self , packet ) :
  iiII1iiI = "BBBBHH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 26 - 26: o0oOOo0O0Ooo . Ii1I * OoOoOO00
  Oo0OoooOoO0O0 , iIi1i , oO000O0oO00 , OooIiii1ii , I1ii , i1IiI11I11I = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 77 - 77: OOooOOo % oO0o + iIii1I11I1II1 * Ii1I . IiII . Oo0Ooo
  if 29 - 29: I1ii11iIi11i + OoooooooOO . OoO0O00 . i1IIi - OoooooooOO * i11iIiiIii
  if ( oO000O0oO00 != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 19 - 19: I1ii11iIi11i * O0 - ooOoO0o
  if 27 - 27: iII111i / o0oOOo0O0Ooo . OoOoOO00 * Ii1I * I1Ii111
  if 81 - 81: I1Ii111
  if 45 - 45: OOooOOo * II111iiii * OoooooooOO / OoooooooOO * I1Ii111
  I1ii = socket . ntohs ( I1ii )
  i1IiI11I11I = socket . ntohs ( i1IiI11I11I )
  packet = packet [ ooo0000oo0 : : ]
  if ( len ( packet ) < I1ii ) : return ( None )
  if ( I1ii != i1IiI11I11I + 4 ) : return ( None )
  if 38 - 38: iII111i . OoooooooOO
  if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
  if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
  if 61 - 61: I11i
  o00O = packet [ 0 : i1IiI11I11I ]
  packet = packet [ i1IiI11I11I : : ]
  if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
  if 35 - 35: ooOoO0o
  if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  if 18 - 18: I1IiiI - I1ii11iIi11i * I11i / i11iIiiIii - o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if ( lisp_is_json_telemetry ( o00O ) != None ) :
   self . json_telemetry = o00O
   if 31 - 31: I11i
   if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
   if 17 - 17: Ii1I * IiII * i11iIiiIii / I1ii11iIi11i / i11iIiiIii
   if 23 - 23: OoooooooOO + i11iIiiIii / Oo0Ooo / iII111i . iII111i * I1IiiI
   if 98 - 98: IiII
  iiII1iiI = "H"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if ( i1I1iiiI != 0 ) : return ( packet )
  if 23 - 23: I11i / i1IIi * OoO0O00
  if ( self . json_telemetry != None ) : return ( packet )
  if 51 - 51: OOooOOo - OoooooooOO / OoooooooOO % OoooooooOO
  if 85 - 85: OoO0O00 . o0oOOo0O0Ooo . I1IiiI
  if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
  if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
  try :
   o00O = json . loads ( o00O )
  except :
   return ( None )
   if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
   if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
   if 24 - 24: IiII * I1IiiI / OOooOOo
   if 51 - 51: iIii1I11I1II1 / I11i * OoO0O00 * Ii1I + I1ii11iIi11i . OoooooooOO
   if 75 - 75: IiII / OoooooooOO / O0 % OOooOOo
  if ( "source-eid" not in o00O ) : return ( packet )
  oo0oO = o00O [ "source-eid" ]
  i1I1iiiI = LISP_AFI_IPV4 if oo0oO . count ( "." ) == 3 else LISP_AFI_IPV6 if oo0oO . count ( ":" ) == 7 else None
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00
  if ( i1I1iiiI == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( oo0oO ) )
   return ( None )
   if 92 - 92: OoOoOO00 . Oo0Ooo * I11i
   if 86 - 86: O0
  self . source_eid . afi = i1I1iiiI
  self . source_eid . store_address ( oo0oO )
  if 55 - 55: Ii1I / I1Ii111 / I1ii11iIi11i % ooOoO0o % I1IiiI
  if ( "signature-eid" not in o00O ) : return ( packet )
  oo0oO = o00O [ "signature-eid" ]
  if ( oo0oO . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( oo0oO ) )
   return ( None )
   if 55 - 55: oO0o + OoooooooOO % i1IIi
   if 24 - 24: I1ii11iIi11i - Oo0Ooo
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( oo0oO )
  if 36 - 36: I1IiiI . OOooOOo % II111iiii * IiII
  if ( "signature" not in o00O ) : return ( packet )
  Oooo0oOoO0000 = binascii . a2b_base64 ( o00O [ "signature" ] )
  self . map_request_signature = Oooo0oOoO0000
  return ( packet )
  if 34 - 34: I11i % iII111i - ooOoO0o - I1IiiI
  if 44 - 44: Ii1I . o0oOOo0O0Ooo . iIii1I11I1II1 + OoooooooOO - I1IiiI
 def decode ( self , packet , source , port ) :
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 22 - 22: I11i * I1ii11iIi11i . OoooooooOO / Oo0Ooo / Ii1I
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  iIiIii = iIiIii [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if 54 - 54: I1Ii111 % Ii1I + ooOoO0o
  iiII1iiI = "Q"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 45 - 45: Ii1I / oO0o * I1Ii111 . Ii1I
  o0Oo0o = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  packet = packet [ ooo0000oo0 : : ]
  if 25 - 25: I1ii11iIi11i / I1ii11iIi11i
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
  if 79 - 79: Oo0Ooo - OoO0O00 % Oo0Ooo . II111iiii
  if 84 - 84: ooOoO0o * OoooooooOO + O0
  if 84 - 84: i1IIi . I11i . i1IIi . Oo0Ooo
  if 21 - 21: II111iiii . O0 + Oo0Ooo - i11iIiiIii
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 5 - 5: iIii1I11I1II1 * i11iIiiIii + OoO0O00 + I11i * O0 % ooOoO0o
   if 88 - 88: o0oOOo0O0Ooo / i11iIiiIii * I1ii11iIi11i
  ooo0000oo0 = struct . calcsize ( "H" )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 23 - 23: O0 / iII111i
  i1I1iiiI = struct . unpack ( "H" , packet [ : ooo0000oo0 ] )
  self . source_eid . afi = socket . ntohs ( i1I1iiiI [ 0 ] )
  packet = packet [ ooo0000oo0 : : ]
  if 66 - 66: i1IIi % OoooooooOO * i11iIiiIii + oO0o * O0 / OoO0O00
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   iI1IiI1 = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( iI1IiI1 )
    if ( packet == None ) : return ( None )
    if 53 - 53: I1Ii111 + IiII . i1IIi
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 26 - 26: i11iIiiIii - II111iiii
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 43 - 43: I1IiiI
  I11IIii = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  Iii1i = self . itr_rloc_count + 1
  if 50 - 50: Ii1I + Ii1I
  while ( Iii1i != 0 ) :
   ooo0000oo0 = struct . calcsize ( "H" )
   if ( len ( packet ) < ooo0000oo0 ) : return ( None )
   if 51 - 51: I1ii11iIi11i / OoooooooOO * IiII
   i1I1iiiI = socket . ntohs ( struct . unpack ( "H" , packet [ : ooo0000oo0 ] ) [ 0 ] )
   OOooOooOOoO0O = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   OOooOooOOoO0O . afi = i1I1iiiI
   if 78 - 78: iII111i / I1ii11iIi11i . i11iIiiIii
   if 69 - 69: I11i - II111iiii
   if 66 - 66: I1IiiI . I1IiiI - OoOoOO00 * OoooooooOO * II111iiii + I1IiiI
   if 59 - 59: Ii1I
   if 59 - 59: II111iiii - OoO0O00
   if ( OOooOooOOoO0O . afi == LISP_AFI_LCAF ) :
    O0OOOOO0O = packet
    I1iI1IiII = packet [ ooo0000oo0 : : ]
    packet = self . lcaf_decode_json ( I1iI1IiII )
    if ( packet == None ) : return ( None )
    if ( packet == I1iI1IiII ) : packet = O0OOOOO0O
    if 38 - 38: OOooOOo + IiII * OoO0O00 / OoOoOO00
    if 68 - 68: I1ii11iIi11i / ooOoO0o % O0
    if 66 - 66: Oo0Ooo . oO0o - O0 . I1Ii111 + iII111i / i11iIiiIii
    if 52 - 52: oO0o % Oo0Ooo * II111iiii
    if 24 - 24: i11iIiiIii * i1IIi * i1IIi
    if 27 - 27: i1IIi - oO0o + OOooOOo
   if ( OOooOooOOoO0O . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < OOooOooOOoO0O . addr_length ( ) ) : return ( None )
    packet = OOooOooOOoO0O . unpack_address ( packet [ ooo0000oo0 : : ] )
    if ( packet == None ) : return ( None )
    if 3 - 3: IiII % I1Ii111 . OoooooooOO
    if ( I11IIii ) :
     self . itr_rlocs . append ( OOooOooOOoO0O )
     Iii1i -= 1
     continue
     if 19 - 19: I1Ii111 * Ii1I - oO0o
     if 78 - 78: OoO0O00 - Ii1I / OOooOOo
    O0O0 = lisp_build_crypto_decap_lookup_key ( OOooOooOOoO0O , port )
    if 81 - 81: OoOoOO00
    if 21 - 21: iII111i / OOooOOo % IiII
    if 51 - 51: I11i + ooOoO0o / I1IiiI
    if 3 - 3: iIii1I11I1II1 / OOooOOo % oO0o . Ii1I - Ii1I
    if 55 - 55: i11iIiiIii % OoooooooOO + O0
    if ( lisp_nat_traversal and OOooOooOOoO0O . is_private_address ( ) and source ) : OOooOooOOoO0O = source
    if 7 - 7: ooOoO0o - i11iIiiIii * iII111i / Ii1I - o0oOOo0O0Ooo
    OOooo000 = lisp_crypto_keys_by_rloc_decap
    if ( O0O0 in OOooo000 ) : OOooo000 . pop ( O0O0 )
    if 78 - 78: I11i . I1Ii111
    if 54 - 54: II111iiii / II111iiii + I11i . OOooOOo - OOooOOo
    if 98 - 98: Ii1I
    if 96 - 96: oO0o * i11iIiiIii
    if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
    if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
    lisp_write_ipc_decap_key ( O0O0 , None )
    if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
   elif ( self . json_telemetry == None ) :
    if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
    if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
    if 64 - 64: IiII
    if 21 - 21: o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO
    O0OOOOO0O = packet
    II111i1I = lisp_keys ( 1 )
    packet = II111i1I . decode_lcaf ( O0OOOOO0O , 0 )
    if 2 - 2: o0oOOo0O0Ooo
    if ( packet == None ) : return ( None )
    if 58 - 58: oO0o - II111iiii + O0
    if 54 - 54: iIii1I11I1II1 - IiII - IiII
    if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
    if 63 - 63: iII111i - OoO0O00 * OOooOOo
    Oo0O = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( II111i1I . cipher_suite in Oo0O ) :
     if ( II111i1I . cipher_suite == LISP_CS_25519_CBC or
 II111i1I . cipher_suite == LISP_CS_25519_GCM ) :
      III = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 89 - 89: iII111i / Oo0Ooo
     if ( II111i1I . cipher_suite == LISP_CS_25519_CHACHA ) :
      III = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 66 - 66: o0oOOo0O0Ooo + OoOoOO00 % OoooooooOO . I11i
    else :
     III = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 30 - 30: II111iiii - Oo0Ooo - i11iIiiIii + O0
    packet = III . decode_lcaf ( O0OOOOO0O , 0 )
    if ( packet == None ) : return ( None )
    if 93 - 93: i1IIi + I1Ii111 / OoO0O00 - I11i % Oo0Ooo / Ii1I
    if ( len ( packet ) < ooo0000oo0 ) : return ( None )
    i1I1iiiI = struct . unpack ( "H" , packet [ : ooo0000oo0 ] ) [ 0 ]
    OOooOooOOoO0O . afi = socket . ntohs ( i1I1iiiI )
    if ( len ( packet ) < OOooOooOOoO0O . addr_length ( ) ) : return ( None )
    if 1 - 1: Oo0Ooo / Ii1I . i11iIiiIii % OOooOOo + o0oOOo0O0Ooo + O0
    packet = OOooOooOOoO0O . unpack_address ( packet [ ooo0000oo0 : : ] )
    if ( packet == None ) : return ( None )
    if 54 - 54: I1Ii111 + ooOoO0o % IiII
    if ( I11IIii ) :
     self . itr_rlocs . append ( OOooOooOOoO0O )
     Iii1i -= 1
     continue
     if 83 - 83: o0oOOo0O0Ooo * iIii1I11I1II1
     if 36 - 36: OoOoOO00 + II111iiii - OoO0O00 % ooOoO0o * i1IIi
    O0O0 = lisp_build_crypto_decap_lookup_key ( OOooOooOOoO0O , port )
    if 4 - 4: Ii1I + OoO0O00 * I1ii11iIi11i
    II111iii = None
    if ( lisp_nat_traversal and OOooOooOOoO0O . is_private_address ( ) and source ) : OOooOooOOoO0O = source
    if 61 - 61: OoO0O00 . i11iIiiIii - OoO0O00
    if 8 - 8: I1ii11iIi11i * IiII / Oo0Ooo
    if ( O0O0 in lisp_crypto_keys_by_rloc_decap ) :
     iI1iiiiiii = lisp_crypto_keys_by_rloc_decap [ O0O0 ]
     II111iii = iI1iiiiiii [ 1 ] if iI1iiiiiii and iI1iiiiiii [ 1 ] else None
     if 99 - 99: OOooOOo * I1Ii111 . ooOoO0o - i1IIi - I11i % IiII
     if 40 - 40: OoOoOO00 % I1Ii111 / I1IiiI + i1IIi
    o000ooOo0o0Oo = True
    if ( II111iii ) :
     if ( II111iii . compare_keys ( III ) ) :
      self . keys = [ None , II111iii , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( O0O0 , False ) ) )
      if 90 - 90: ooOoO0o . OOooOOo
     else :
      o000ooOo0o0Oo = False
      o0o00O000 = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( o0o00O000 , red ( O0O0 ,
 False ) ) )
      III . copy_keypair ( II111iii )
      III . uptime = II111iii . uptime
      II111iii = None
      if 57 - 57: i1IIi . iII111i
      if 50 - 50: oO0o
      if 55 - 55: I1ii11iIi11i
    if ( II111iii == None ) :
     self . keys = [ None , III , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      III . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( O0O0 , False ) ) )
     elif ( III . remote_public_key != None ) :
      if ( o000ooOo0o0Oo ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # iII111i - OoooooooOO + I1Ii111 % iIii1I11I1II1
 red ( O0O0 , False ) ) )
       if 91 - 91: oO0o * O0
      III . compute_shared_key ( "decap" )
      III . add_key_by_rloc ( O0O0 , False )
      if 19 - 19: I1ii11iIi11i / OoO0O00 + oO0o
      if 81 - 81: I1Ii111 / I1Ii111 + ooOoO0o - Ii1I
      if 93 - 93: ooOoO0o . o0oOOo0O0Ooo + O0 * i1IIi - OoO0O00 * OoO0O00
      if 11 - 11: ooOoO0o - Ii1I . oO0o * Ii1I
   self . itr_rlocs . append ( OOooOooOOoO0O )
   Iii1i -= 1
   if 85 - 85: i1IIi
   if 94 - 94: OoooooooOO . O0 / OoooooooOO
  ooo0000oo0 = struct . calcsize ( "BBH" )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 67 - 67: i11iIiiIii + OoOoOO00
  ii1I11 , I1iIii11iIi1I , i1I1iiiI = struct . unpack ( "BBH" , packet [ : ooo0000oo0 ] )
  self . subscribe_bit = ( ii1I11 & 0x80 )
  self . target_eid . afi = socket . ntohs ( i1I1iiiI )
  packet = packet [ ooo0000oo0 : : ]
  if 50 - 50: ooOoO0o . i1IIi + I1ii11iIi11i . OOooOOo
  self . target_eid . mask_len = I1iIii11iIi1I
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , oO0Ooo = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( oO0Ooo ) : self . target_group = oO0Ooo
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ ooo0000oo0 : : ]
   if 49 - 49: II111iiii . OoooooooOO
  return ( packet )
  if 30 - 30: OoO0O00 / i11iIiiIii - OoO0O00 / ooOoO0o + iIii1I11I1II1 + i1IIi
  if 99 - 99: OOooOOo * I1IiiI + oO0o % oO0o % OOooOOo * IiII
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 98 - 98: OOooOOo
  if 97 - 97: o0oOOo0O0Ooo
 def encode_xtr_id ( self , packet ) :
  I1iIii1iii11i = self . xtr_id >> 64
  o00oOo0oO0oOO = self . xtr_id & 0xffffffffffffffff
  I1iIii1iii11i = byte_swap_64 ( I1iIii1iii11i )
  o00oOo0oO0oOO = byte_swap_64 ( o00oOo0oO0oOO )
  packet += struct . pack ( "QQ" , I1iIii1iii11i , o00oOo0oO0oOO )
  return ( packet )
  if 35 - 35: ooOoO0o + i11iIiiIii
  if 82 - 82: i11iIiiIii + I11i + iII111i % I1IiiI
 def decode_xtr_id ( self , packet ) :
  ooo0000oo0 = struct . calcsize ( "QQ" )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  packet = packet [ len ( packet ) - ooo0000oo0 : : ]
  I1iIii1iii11i , o00oOo0oO0oOO = struct . unpack ( "QQ" , packet [ : ooo0000oo0 ] )
  I1iIii1iii11i = byte_swap_64 ( I1iIii1iii11i )
  o00oOo0oO0oOO = byte_swap_64 ( o00oOo0oO0oOO )
  self . xtr_id = ( I1iIii1iii11i << 64 ) | o00oOo0oO0oOO
  return ( True )
  if 84 - 84: oO0o % OOooOOo
  if 25 - 25: i11iIiiIii * OoOoOO00 + i11iIiiIii . i1IIi
  if 83 - 83: I1IiiI
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
  if 97 - 97: I1IiiI / o0oOOo0O0Ooo
  if 13 - 13: I1ii11iIi11i
  if 72 - 72: Oo0Ooo + IiII / Ii1I * Oo0Ooo
  if 41 - 41: OOooOOo - OoOoOO00 . I1IiiI + i11iIiiIii + OoO0O00 * iII111i
  if 85 - 85: OoO0O00 + II111iiii
class lisp_map_reply ( object ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 87 - 87: OoO0O00
  if 93 - 93: OoooooooOO
 def print_map_reply ( self ) :
  IiiiI1 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 80 - 80: o0oOOo0O0Ooo
  lprint ( IiiiI1 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # Oo0Ooo
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 20 - 20: OoO0O00
  if 68 - 68: OoOoOO00 . OoO0O00 . OoO0O00 + O0
 def encode ( self ) :
  iIiIii = ( LISP_MAP_REPLY << 28 ) | self . record_count
  iIiIii |= self . hop_count << 8
  if ( self . rloc_probe ) : iIiIii |= 0x08000000
  if ( self . echo_nonce_capable ) : iIiIii |= 0x04000000
  if ( self . security ) : iIiIii |= 0x02000000
  if 13 - 13: i1IIi . I1IiiI
  Oo00oo = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  return ( Oo00oo )
  if 45 - 45: ooOoO0o % I11i
  if 37 - 37: iII111i
 def decode ( self , packet ) :
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 70 - 70: O0 + iIii1I11I1II1 % O0 * o0oOOo0O0Ooo - Oo0Ooo - ooOoO0o
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  iIiIii = iIiIii [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if 94 - 94: i1IIi + IiII / OoooooooOO - oO0o / OOooOOo / OoOoOO00
  iiII1iiI = "Q"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 55 - 55: OOooOOo
  o0Oo0o = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  packet = packet [ ooo0000oo0 : : ]
  if 5 - 5: I11i / OoOoOO00
  iIiIii = socket . ntohl ( iIiIii )
  self . rloc_probe = True if ( iIiIii & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( iIiIii & 0x04000000 ) else False
  self . security = True if ( iIiIii & 0x02000000 ) else False
  self . hop_count = ( iIiIii >> 8 ) & 0xff
  self . record_count = iIiIii & 0xff
  self . nonce = o0Oo0o [ 0 ]
  if 48 - 48: i1IIi - oO0o . OoooooooOO - OoO0O00 - i1IIi
  if ( self . nonce in lisp_crypto_keys_by_nonce ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 19 - 19: oO0o % Ii1I + I1ii11iIi11i . II111iiii * i11iIiiIii
  return ( packet )
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
  if 42 - 42: O0 . I1Ii111 / I11i
  if 69 - 69: OoOoOO00 / I1Ii111 * I1IiiI
  if 76 - 76: O0 + II111iiii * OoO0O00
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
  if 1 - 1: o0oOOo0O0Ooo
  if 34 - 34: o0oOOo0O0Ooo + OOooOOo . OoO0O00 + I1IiiI + OoooooooOO
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 90 - 90: Ii1I / OoOoOO00 - iIii1I11I1II1 / i1IIi * I1Ii111 - ooOoO0o
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 2 - 2: iII111i * I11i * ooOoO0o + i11iIiiIii + oO0o
  if 81 - 81: o0oOOo0O0Ooo * OoO0O00
 def print_ttl ( self ) :
  IiIIi = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   IiIIi = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( IiIIi % 60 ) == 0 ) :
   IiIIi = str ( old_div ( IiIIi , 60 ) ) + " hours"
  else :
   IiIIi = str ( IiIIi ) + " mins"
   if 61 - 61: i1IIi % i11iIiiIii % oO0o % OoOoOO00 % iII111i + iII111i
  return ( IiIIi )
  if 58 - 58: I1IiiI * II111iiii . i1IIi
  if 39 - 39: I1IiiI . i11iIiiIii
 def store_ttl ( self ) :
  IiIIi = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : IiIIi = self . record_ttl & 0x7fffffff
  return ( IiIIi )
  if 21 - 21: OOooOOo + o0oOOo0O0Ooo / I1ii11iIi11i * oO0o + i1IIi
  if 26 - 26: I1IiiI
 def print_record ( self , indent , ddt ) :
  OOiiI1iii1I = ""
  o0ooo = ""
  iIIIII1iiI = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    iIIIII1iiI = lisp_map_referral_action_string [ self . action ]
    iIIIII1iiI = bold ( iIIIII1iiI , False )
    OOiiI1iii1I = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 43 - 43: o0oOOo0O0Ooo * OoooooooOO
    o0ooo = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 1 - 1: iII111i % oO0o / OOooOOo * iII111i
    if 28 - 28: oO0o . ooOoO0o / I11i + Oo0Ooo
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    iIIIII1iiI = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     iIIIII1iiI = bold ( iIIIII1iiI , False )
     if 55 - 55: OoooooooOO % OoOoOO00 + i1IIi * OoO0O00 * OOooOOo
     if 39 - 39: OOooOOo - oO0o
     if 69 - 69: o0oOOo0O0Ooo * Ii1I * OoOoOO00
     if 51 - 51: Oo0Ooo . Oo0Ooo
  i1I1iiiI = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  IiiiI1 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 34 - 34: I1ii11iIi11i - i11iIiiIii
  lprint ( IiiiI1 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 iIIIII1iiI , "auth" if ( self . authoritative is True ) else "non-auth" ,
 OOiiI1iii1I , o0ooo , self . map_version , i1I1iiiI ,
 green ( self . print_prefix ( ) , False ) ) )
  if 43 - 43: iIii1I11I1II1
  if 73 - 73: OoOoOO00 + o0oOOo0O0Ooo
 def encode ( self ) :
  Oo0Oo00O000O = self . action << 13
  if ( self . authoritative ) : Oo0Oo00O000O |= 0x1000
  if ( self . ddt_incomplete ) : Oo0Oo00O000O |= 0x800
  if 45 - 45: iII111i - I1ii11iIi11i * O0 % OoO0O00 % I1IiiI
  if 21 - 21: IiII * oO0o - OoOoOO00 . i1IIi
  if 52 - 52: OoOoOO00 . I1ii11iIi11i . Oo0Ooo
  if 99 - 99: OoooooooOO - i1IIi % o0oOOo0O0Ooo / o0oOOo0O0Ooo + IiII
  i1I1iiiI = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( i1I1iiiI < 0 ) : i1I1iiiI = LISP_AFI_LCAF
  OoO0o0 = ( self . group . is_null ( ) == False )
  if ( OoO0o0 ) : i1I1iiiI = LISP_AFI_LCAF
  if 79 - 79: I1IiiI - IiII . OoooooooOO - I1ii11iIi11i
  OO0Oo0 = ( self . signature_count << 12 ) | self . map_version
  I1iIii11iIi1I = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 65 - 65: Oo0Ooo * ooOoO0o % i11iIiiIii
  Oo00oo = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , I1iIii11iIi1I , socket . htons ( Oo0Oo00O000O ) ,
 socket . htons ( OO0Oo0 ) , socket . htons ( i1I1iiiI ) )
  if 12 - 12: OoOoOO00 . I1ii11iIi11i . Oo0Ooo
  if 61 - 61: I11i / OOooOOo
  if 85 - 85: OoOoOO00 - I11i . OoOoOO00 . OoOoOO00
  if 62 - 62: IiII % OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % iII111i
  if ( OoO0o0 ) :
   Oo00oo += self . eid . lcaf_encode_sg ( self . group )
   return ( Oo00oo )
   if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
   if 68 - 68: I11i - i11iIiiIii / o0oOOo0O0Ooo + ooOoO0o / I1IiiI
   if 31 - 31: I1Ii111 . OoooooooOO . i1IIi
   if 65 - 65: OoO0O00 . ooOoO0o
   if 12 - 12: I1Ii111 + O0 - oO0o . IiII
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   Oo00oo = Oo00oo [ 0 : - 2 ]
   Oo00oo += self . eid . address . encode_geo ( )
   return ( Oo00oo )
   if 46 - 46: IiII . ooOoO0o / iII111i
   if 63 - 63: II111iiii - I1ii11iIi11i * II111iiii
   if 92 - 92: OoO0O00 % ooOoO0o * O0 % iIii1I11I1II1 / i1IIi / OoOoOO00
   if 67 - 67: I1Ii111 + I11i + I1Ii111 . OOooOOo % o0oOOo0O0Ooo / ooOoO0o
   if 78 - 78: I1ii11iIi11i . O0
  if ( i1I1iiiI == LISP_AFI_LCAF ) :
   Oo00oo += self . eid . lcaf_encode_iid ( )
   return ( Oo00oo )
   if 56 - 56: oO0o - i1IIi * O0 / I11i * I1IiiI . I11i
   if 54 - 54: i11iIiiIii % i1IIi + Oo0Ooo / OoOoOO00
   if 26 - 26: I11i . I1ii11iIi11i
   if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
   if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
  Oo00oo += self . eid . pack_address ( )
  return ( Oo00oo )
  if 28 - 28: O0 % iII111i - i1IIi
  if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
 def decode ( self , packet ) :
  iiII1iiI = "IBBHHH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
  self . record_ttl , self . rloc_count , self . eid . mask_len , Oo0Oo00O000O , self . map_version , self . eid . afi = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 97 - 97: oO0o - iII111i + IiII . OoOoOO00 + iIii1I11I1II1
  if 75 - 75: ooOoO0o + ooOoO0o . I1Ii111 % iII111i / iIii1I11I1II1 * iII111i
  if 13 - 13: II111iiii * i11iIiiIii - i1IIi * OoO0O00 + i1IIi
  self . record_ttl = socket . ntohl ( self . record_ttl )
  Oo0Oo00O000O = socket . ntohs ( Oo0Oo00O000O )
  self . action = ( Oo0Oo00O000O >> 13 ) & 0x7
  self . authoritative = True if ( ( Oo0Oo00O000O >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( Oo0Oo00O000O >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ ooo0000oo0 : : ]
  if 43 - 43: O0 % oO0o * I1IiiI
  if 64 - 64: II111iiii + i11iIiiIii
  if 17 - 17: O0 * I1IiiI
  if 40 - 40: iIii1I11I1II1 * iII111i % iIii1I11I1II1
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , iiI = self . eid . lcaf_decode_eid ( packet )
   if ( iiI ) : self . group = iiI
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 79 - 79: Oo0Ooo * I1IiiI - I1ii11iIi11i
   if 16 - 16: Oo0Ooo % IiII
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 82 - 82: i1IIi . IiII
  if 80 - 80: ooOoO0o / I1IiiI % I11i . I1Ii111 / ooOoO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 78 - 78: o0oOOo0O0Ooo / OoooooooOO + i1IIi * OoOoOO00 . i1IIi / II111iiii
  if 37 - 37: O0 % II111iiii % iII111i
  if 15 - 15: II111iiii
  if 79 - 79: I1ii11iIi11i - O0 / IiII
  if 1 - 1: I1IiiI
  if 25 - 25: O0 + OOooOOo / iII111i
  if 51 - 51: I11i
  if 54 - 54: i1IIi . O0 . i1IIi . OoO0O00 + I1Ii111 - i11iIiiIii
  if 80 - 80: OoOoOO00
  if 5 - 5: I1IiiI - I1IiiI / O0 + OOooOOo - i11iIiiIii
  if 87 - 87: i1IIi - O0 % OoooooooOO * i11iIiiIii % i11iIiiIii
  if 19 - 19: ooOoO0o
  if 44 - 44: I1Ii111 - i11iIiiIii * I1IiiI
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 8 - 8: IiII
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
  if 68 - 68: IiII . OoooooooOO - i11iIiiIii + i11iIiiIii
  if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
 def print_ecm ( self ) :
  IiiiI1 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
  lprint ( IiiiI1 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 58 - 58: ooOoO0o
  if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
   if 39 - 39: oO0o + OoOoOO00
   if 68 - 68: i1IIi * oO0o / i11iIiiIii
   if 96 - 96: I1IiiI
   if 78 - 78: OoO0O00
   if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
  iIiIii = ( LISP_ECM << 28 )
  if ( self . security ) : iIiIii |= 0x08000000
  if ( self . ddt ) : iIiIii |= 0x04000000
  if ( self . to_etr ) : iIiIii |= 0x02000000
  if ( self . to_ms ) : iIiIii |= 0x01000000
  if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
  O000O = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  if 22 - 22: II111iiii
  O0O = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   O0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   O0O += self . source . pack_address ( )
   O0O += self . dest . pack_address ( )
   O0O = lisp_ip_checksum ( O0O )
   if 55 - 55: i11iIiiIii
  if ( self . afi == LISP_AFI_IPV6 ) :
   O0O = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   O0O += self . source . pack_address ( )
   O0O += self . dest . pack_address ( )
   if 29 - 29: OOooOOo - i11iIiiIii % IiII / OoooooooOO
   if 92 - 92: I1ii11iIi11i
  I111 = socket . htons ( self . udp_sport )
  IiI11I111 = socket . htons ( self . udp_dport )
  oOO0O00o0O0 = socket . htons ( self . udp_length )
  I1i11i = socket . htons ( self . udp_checksum )
  O0I1II1 = struct . pack ( "HHHH" , I111 , IiI11I111 , oOO0O00o0O0 , I1i11i )
  return ( O000O + O0O + O0I1II1 )
  if 89 - 89: OoO0O00 * i11iIiiIii - IiII * i1IIi - ooOoO0o . Ii1I
  if 26 - 26: I1IiiI * OoooooooOO / I1IiiI . O0 . ooOoO0o + O0
 def decode ( self , packet ) :
  if 84 - 84: I1Ii111 . O0 + O0 % O0 % i1IIi + iIii1I11I1II1
  if 71 - 71: iII111i / iIii1I11I1II1 . OOooOOo * i11iIiiIii
  if 98 - 98: O0 % iIii1I11I1II1 . IiII - II111iiii
  if 14 - 14: Ii1I % ooOoO0o - OoOoOO00
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 52 - 52: OoO0O00 / i1IIi - Ii1I
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 8 - 8: oO0o + ooOoO0o . I1ii11iIi11i . i1IIi / I1IiiI . IiII
  iIiIii = socket . ntohl ( iIiIii [ 0 ] )
  self . security = True if ( iIiIii & 0x08000000 ) else False
  self . ddt = True if ( iIiIii & 0x04000000 ) else False
  self . to_etr = True if ( iIiIii & 0x02000000 ) else False
  self . to_ms = True if ( iIiIii & 0x01000000 ) else False
  packet = packet [ ooo0000oo0 : : ]
  if 8 - 8: i1IIi * O0
  if 60 - 60: Oo0Ooo - II111iiii + I1IiiI
  if 17 - 17: OoOoOO00 % I1IiiI
  if 8 - 8: Oo0Ooo
  if ( len ( packet ) < 1 ) : return ( None )
  I1IiI = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  I1IiI = I1IiI >> 4
  if 49 - 49: OoOoOO00 * I11i - o0oOOo0O0Ooo / OoO0O00 * oO0o
  if ( I1IiI == 4 ) :
   ooo0000oo0 = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < ooo0000oo0 ) : return ( None )
   if 51 - 51: ooOoO0o - iIii1I11I1II1 . I11i * OoOoOO00 + I1Ii111 * i1IIi
   I1iIiiI1IIi1 , oOO0O00o0O0 , I1iIiiI1IIi1 , I1 , iIIiiIi , I1i11i = struct . unpack ( "HHIBBH" , packet [ : ooo0000oo0 ] )
   self . length = socket . ntohs ( oOO0O00o0O0 )
   self . ttl = I1
   self . protocol = iIIiiIi
   self . ip_checksum = socket . ntohs ( I1i11i )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 66 - 66: i11iIiiIii * iII111i
   if 51 - 51: OoooooooOO + I11i . iII111i + i11iIiiIii * iII111i - OoO0O00
   if 60 - 60: iII111i * iIii1I11I1II1 . OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
   if 36 - 36: i1IIi . OoooooooOO - II111iiii - OoOoOO00 - IiII
   iIIiiIi = struct . pack ( "H" , 0 )
   oOooo0oOo = struct . calcsize ( "HHIBB" )
   I1Ii11i111 = struct . calcsize ( "H" )
   packet = packet [ : oOooo0oOo ] + iIIiiIi + packet [ oOooo0oOo + I1Ii11i111 : ]
   if 17 - 17: I1Ii111 - I1Ii111 . oO0o / I1Ii111
   packet = packet [ ooo0000oo0 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 36 - 36: I1ii11iIi11i * i1IIi + iIii1I11I1II1
   if 55 - 55: I1IiiI . I1Ii111 - I1IiiI % oO0o / iIii1I11I1II1 * Ii1I
  if ( I1IiI == 6 ) :
   ooo0000oo0 = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < ooo0000oo0 ) : return ( None )
   if 77 - 77: OOooOOo
   I1iIiiI1IIi1 , oOO0O00o0O0 , iIIiiIi , I1 = struct . unpack ( "IHBB" , packet [ : ooo0000oo0 ] )
   self . length = socket . ntohs ( oOO0O00o0O0 )
   self . protocol = iIIiiIi
   self . ttl = I1
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 29 - 29: II111iiii % iIii1I11I1II1 * O0 . o0oOOo0O0Ooo
   packet = packet [ ooo0000oo0 : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 56 - 56: i1IIi . ooOoO0o + I11i - i11iIiiIii
   if 100 - 100: iIii1I11I1II1 - i1IIi . OOooOOo
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 73 - 73: I1Ii111 / I11i / i11iIiiIii - I1ii11iIi11i % ooOoO0o
  ooo0000oo0 = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 92 - 92: I1IiiI - o0oOOo0O0Ooo % I1ii11iIi11i / iII111i % oO0o
  I111 , IiI11I111 , oOO0O00o0O0 , I1i11i = struct . unpack ( "HHHH" , packet [ : ooo0000oo0 ] )
  self . udp_sport = socket . ntohs ( I111 )
  self . udp_dport = socket . ntohs ( IiI11I111 )
  self . udp_length = socket . ntohs ( oOO0O00o0O0 )
  self . udp_checksum = socket . ntohs ( I1i11i )
  packet = packet [ ooo0000oo0 : : ]
  return ( packet )
  if 43 - 43: Oo0Ooo % oO0o . i11iIiiIii - O0
  if 5 - 5: i1IIi + Ii1I
  if 38 - 38: I1IiiI . O0 + OOooOOo / I1ii11iIi11i . iIii1I11I1II1 - i1IIi
  if 3 - 3: Oo0Ooo + oO0o
  if 65 - 65: I1IiiI / OoOoOO00 % I1IiiI * i11iIiiIii * OoooooooOO / I11i
  if 91 - 91: i11iIiiIii / i11iIiiIii
  if 9 - 9: I11i / I1Ii111 + iIii1I11I1II1 + I1IiiI - II111iiii
  if 96 - 96: iII111i + Oo0Ooo - OoooooooOO . i1IIi + i1IIi % iIii1I11I1II1
  if 80 - 80: OoooooooOO / O0 / I1Ii111 - Oo0Ooo . i11iIiiIii
  if 3 - 3: Oo0Ooo - OOooOOo * OoO0O00 - II111iiii . OoooooooOO
  if 14 - 14: I1IiiI
  if 41 - 41: I1Ii111 % i1IIi + OoO0O00 / oO0o
  if 48 - 48: i1IIi . Oo0Ooo . i1IIi . I1ii11iIi11i * I1IiiI - Ii1I
  if 83 - 83: OoooooooOO
  if 42 - 42: I1ii11iIi11i . i1IIi - OoOoOO00 - oO0o + i11iIiiIii
  if 65 - 65: I1IiiI - O0
  if 15 - 15: I11i + OoOoOO00 / Oo0Ooo - I1IiiI * I1ii11iIi11i % oO0o
  if 90 - 90: Ii1I / I11i
  if 98 - 98: i1IIi
  if 97 - 97: I1Ii111 + O0 - II111iiii / I11i
  if 84 - 84: iIii1I11I1II1 % Ii1I / OoooooooOO
  if 62 - 62: OOooOOo * OoO0O00 * OoO0O00 + OoooooooOO . IiII + OoO0O00
  if 13 - 13: O0 . I1IiiI % OoO0O00 - I11i . O0
  if 14 - 14: iIii1I11I1II1
  if 48 - 48: i11iIiiIii * OoOoOO00 - I1IiiI + iIii1I11I1II1
  if 20 - 20: I1ii11iIi11i - iIii1I11I1II1 . iII111i
  if 52 - 52: OoO0O00 - I1Ii111
  if 9 - 9: I1IiiI . i11iIiiIii
  if 3 - 3: I1IiiI + I1ii11iIi11i * I1Ii111 - i1IIi . OOooOOo
  if 21 - 21: OOooOOo + o0oOOo0O0Ooo
  if 39 - 39: OoOoOO00 . I11i * OOooOOo . i1IIi
  if 69 - 69: IiII - i1IIi + o0oOOo0O0Ooo
  if 5 - 5: II111iiii
  if 88 - 88: OoooooooOO % II111iiii + IiII + IiII * Oo0Ooo
  if 81 - 81: I1IiiI * ooOoO0o + I1Ii111
  if 49 - 49: I1IiiI % oO0o % II111iiii * II111iiii + OoooooooOO + iII111i
  if 58 - 58: i11iIiiIii % iIii1I11I1II1 + OoO0O00 . I1ii11iIi11i . I1IiiI
  if 54 - 54: iII111i . OoO0O00 . iIii1I11I1II1
  if 45 - 45: I1ii11iIi11i + I1IiiI / i11iIiiIii
  if 45 - 45: IiII / O0 * I1IiiI - OOooOOo * I1Ii111
  if 19 - 19: OoOoOO00 / IiII - OOooOOo * i11iIiiIii % I1Ii111
  if 98 - 98: IiII + IiII + OOooOOo / i1IIi + oO0o
  if 53 - 53: OoOoOO00
  if 69 - 69: iIii1I11I1II1 * OoO0O00 / OoooooooOO % I1ii11iIi11i . I1IiiI % I11i
  if 40 - 40: i11iIiiIii % oO0o / OOooOOo
  if 85 - 85: OoO0O00 % O0 . Ii1I . iII111i . iII111i
  if 90 - 90: o0oOOo0O0Ooo - Oo0Ooo / ooOoO0o / i1IIi - Ii1I
  if 43 - 43: i11iIiiIii - OoooooooOO % ooOoO0o
  if 55 - 55: oO0o % Oo0Ooo % IiII
  if 65 - 65: IiII * IiII
  if 60 - 60: ooOoO0o
  if 92 - 92: O0 % IiII
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
  if 11 - 11: OOooOOo
  if 58 - 58: OoO0O00 * OoooooooOO
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  i1Ii1iiI = self . rloc_name
  if ( cour ) : i1Ii1iiI = lisp_print_cour ( i1Ii1iiI )
  return ( 'rloc-name: {}' . format ( blue ( i1Ii1iiI , cour ) ) )
  if 23 - 23: Oo0Ooo % II111iiii
  if 96 - 96: ooOoO0o % Ii1I
 def print_record ( self , indent ) :
  IIIOo0O = self . print_rloc_name ( )
  if ( IIIOo0O != "" ) : IIIOo0O = ", " + IIIOo0O
  OooO0OO0o = ""
  if ( self . geo ) :
   iii1IiII1ii = ""
   if ( self . geo . geo_name ) : iii1IiII1ii = "'{}' " . format ( self . geo . geo_name )
   OooO0OO0o = ", geo: {}{}" . format ( iii1IiII1ii , self . geo . print_geo ( ) )
   if 32 - 32: I11i * I11i % Ii1I
  iiii1IIiIiI = ""
  if ( self . elp ) :
   iii1IiII1ii = ""
   if ( self . elp . elp_name ) : iii1IiII1ii = "'{}' " . format ( self . elp . elp_name )
   iiii1IIiIiI = ", elp: {}{}" . format ( iii1IiII1ii , self . elp . print_elp ( True ) )
   if 9 - 9: Ii1I / oO0o / O0 + I1Ii111 % I1IiiI
  iIi111Ii1 = ""
  if ( self . rle ) :
   iii1IiII1ii = ""
   if ( self . rle . rle_name ) : iii1IiII1ii = "'{}' " . format ( self . rle . rle_name )
   iIi111Ii1 = ", rle: {}{}" . format ( iii1IiII1ii , self . rle . print_rle ( False ,
 True ) )
   if 95 - 95: Ii1I / o0oOOo0O0Ooo % ooOoO0o - I1IiiI / OOooOOo * OOooOOo
  iII1ii1iiI1 = ""
  if ( self . json ) :
   iii1IiII1ii = ""
   if ( self . json . json_name ) :
    iii1IiII1ii = "'{}' " . format ( self . json . json_name )
    if 45 - 45: O0 - II111iiii % i11iIiiIii
   iII1ii1iiI1 = ", json: {}" . format ( self . json . print_json ( False ) )
   if 29 - 29: o0oOOo0O0Ooo * I11i
   if 65 - 65: Oo0Ooo * I1Ii111
  ii1IiIiI1 = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   ii1IiIiI1 = ", " + self . keys [ 1 ] . print_keys ( )
   if 12 - 12: iIii1I11I1II1 + ooOoO0o * I1Ii111 % OoooooooOO / iIii1I11I1II1
   if 43 - 43: O0 . i1IIi - OoooooooOO - i1IIi - I1ii11iIi11i
  IiiiI1 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( IiiiI1 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , IIIOo0O , OooO0OO0o ,
 iiii1IIiIiI , iIi111Ii1 , iII1ii1iiI1 , ii1IiIiI1 ) )
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
   iii1IiII1ii = rloc_entry . geo_name
   if ( iii1IiII1ii and iii1IiII1ii in lisp_geo_list ) :
    self . geo = lisp_geo_list [ iii1IiII1ii ]
    if 55 - 55: i11iIiiIii / OoooooooOO - I11i
    if 89 - 89: I11i - i1IIi - i1IIi * OOooOOo - O0
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   iii1IiII1ii = rloc_entry . elp_name
   if ( iii1IiII1ii and iii1IiII1ii in lisp_elp_list ) :
    self . elp = lisp_elp_list [ iii1IiII1ii ]
    if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
    if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   iii1IiII1ii = rloc_entry . rle_name
   if ( iii1IiII1ii and iii1IiII1ii in lisp_rle_list ) :
    self . rle = lisp_rle_list [ iii1IiII1ii ]
    if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
    if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   iii1IiII1ii = rloc_entry . json_name
   if ( iii1IiII1ii and iii1IiII1ii in lisp_json_list ) :
    self . json = lisp_json_list [ iii1IiII1ii ]
    if 9 - 9: Ii1I
    if 76 - 76: I1IiiI % Oo0Ooo / iIii1I11I1II1 - Oo0Ooo
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 34 - 34: OoOoOO00 - i1IIi + OOooOOo + Ii1I . o0oOOo0O0Ooo
  if 42 - 42: OoO0O00
 def encode_json ( self , lisp_json ) :
  o00O = lisp_json . json_string
  oO0 = 0
  if ( lisp_json . json_encrypted ) :
   oO0 = ( lisp_json . json_key_id << 5 ) | 0x02
   if 93 - 93: i11iIiiIii / i1IIi + O0
   if 55 - 55: II111iiii + OoooooooOO * OOooOOo . Ii1I * Oo0Ooo / O0
  oO000O0oO00 = LISP_LCAF_JSON_TYPE
  ooOOooooo0Oo = socket . htons ( LISP_AFI_LCAF )
  iIiii1 = self . rloc . addr_length ( ) + 2
  if 8 - 8: OOooOOo % OOooOOo / Oo0Ooo
  I1ii = socket . htons ( len ( o00O ) + iIiii1 )
  if 30 - 30: ooOoO0o - I11i
  i1IiI11I11I = socket . htons ( len ( o00O ) )
  Oo00oo = struct . pack ( "HBBBBHH" , ooOOooooo0Oo , 0 , 0 , oO000O0oO00 , oO0 ,
 I1ii , i1IiI11I11I )
  Oo00oo += o00O . encode ( )
  if 21 - 21: i11iIiiIii / I1IiiI / I1ii11iIi11i - I1Ii111 - i1IIi * I1ii11iIi11i
  if 78 - 78: o0oOOo0O0Ooo . OoOoOO00
  if 61 - 61: i1IIi + Ii1I * OoooooooOO - ooOoO0o
  if 78 - 78: iIii1I11I1II1 * OoOoOO00 - I1IiiI . O0 / I1Ii111
  if ( lisp_is_json_telemetry ( o00O ) ) :
   Oo00oo += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   Oo00oo += self . rloc . pack_address ( )
  else :
   Oo00oo += struct . pack ( "H" , 0 )
   if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
  return ( Oo00oo )
  if 54 - 54: ooOoO0o - O0 + iII111i
  if 34 - 34: Ii1I - OOooOOo % iII111i
 def encode_lcaf ( self ) :
  ooOOooooo0Oo = socket . htons ( LISP_AFI_LCAF )
  iIii1iii1 = b""
  if ( self . geo ) :
   iIii1iii1 = self . geo . encode_geo ( )
   if 80 - 80: I11i + o0oOOo0O0Ooo - I1Ii111 . OoO0O00 * oO0o + OOooOOo
   if 96 - 96: i1IIi + i1IIi * I1ii11iIi11i . Oo0Ooo * Oo0Ooo
  OoOOo0Oo0o0 = b""
  if ( self . elp ) :
   OoO00oo0OOOo = b""
   for o00Oo0 in self . elp . elp_nodes :
    i1I1iiiI = socket . htons ( o00Oo0 . address . afi )
    iIi1i = 0
    if ( o00Oo0 . eid ) : iIi1i |= 0x4
    if ( o00Oo0 . probe ) : iIi1i |= 0x2
    if ( o00Oo0 . strict ) : iIi1i |= 0x1
    iIi1i = socket . htons ( iIi1i )
    OoO00oo0OOOo += struct . pack ( "HH" , iIi1i , i1I1iiiI )
    OoO00oo0OOOo += o00Oo0 . address . pack_address ( )
    if 8 - 8: II111iiii - iII111i . oO0o / O0
    if 48 - 48: Oo0Ooo
   Ii111 = socket . htons ( len ( OoO00oo0OOOo ) )
   OoOOo0Oo0o0 = struct . pack ( "HBBBBH" , ooOOooooo0Oo , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , Ii111 )
   OoOOo0Oo0o0 += OoO00oo0OOOo
   if 24 - 24: Ii1I - OoOoOO00 . I11i / oO0o
   if 16 - 16: IiII % iII111i . oO0o . I1IiiI % O0 * I11i
  OOOo0 = b""
  if ( self . rle ) :
   OOo0OOoo00 = b""
   for oO0oOOOO0oO0o0 in self . rle . rle_nodes :
    i1I1iiiI = socket . htons ( oO0oOOOO0oO0o0 . address . afi )
    OOo0OOoo00 += struct . pack ( "HBBH" , 0 , 0 , oO0oOOOO0oO0o0 . level , i1I1iiiI )
    OOo0OOoo00 += oO0oOOOO0oO0o0 . address . pack_address ( )
    if ( oO0oOOOO0oO0o0 . rloc_name ) :
     OOo0OOoo00 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     OOo0OOoo00 += ( oO0oOOOO0oO0o0 . rloc_name + "\0" ) . encode ( )
     if 58 - 58: I1Ii111 - ooOoO0o . oO0o
     if 87 - 87: oO0o + I1IiiI * I1Ii111 * o0oOOo0O0Ooo + O0
     if 21 - 21: I1Ii111 + OoOoOO00 + OoOoOO00 . II111iiii / I1Ii111 . I1IiiI
   O0oO00o0O0 = socket . htons ( len ( OOo0OOoo00 ) )
   OOOo0 = struct . pack ( "HBBBBH" , ooOOooooo0Oo , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , O0oO00o0O0 )
   OOOo0 += OOo0OOoo00
   if 19 - 19: I1Ii111 / O0
   if 55 - 55: II111iiii / ooOoO0o / II111iiii * OOooOOo
  o00oO = b""
  if ( self . json ) :
   o00oO = self . encode_json ( self . json )
   if 44 - 44: O0 * o0oOOo0O0Ooo % OOooOOo
   if 98 - 98: oO0o / iIii1I11I1II1 - OoOoOO00
  I1Ii1i111I = b""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   I1Ii1i111I = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 51 - 51: O0 + Ii1I * OoooooooOO . oO0o + OoooooooOO
   if 58 - 58: ooOoO0o . Oo0Ooo / I1ii11iIi11i + OoO0O00 * OoooooooOO / I1IiiI
  iii11i11 = b""
  if ( self . rloc_name ) :
   iii11i11 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   iii11i11 += ( self . rloc_name + "\0" ) . encode ( )
   if 80 - 80: II111iiii / iIii1I11I1II1 - OoO0O00 . I11i / II111iiii
   if 20 - 20: o0oOOo0O0Ooo % i1IIi / Oo0Ooo / I11i * Oo0Ooo
  oOOoOO = len ( iIii1iii1 ) + len ( OoOOo0Oo0o0 ) + len ( OOOo0 ) + len ( I1Ii1i111I ) + 2 + len ( o00oO ) + self . rloc . addr_length ( ) + len ( iii11i11 )
  if 63 - 63: I1IiiI
  oOOoOO = socket . htons ( oOOoOO )
  i1II11 = struct . pack ( "HBBBBHH" , ooOOooooo0Oo , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , oOOoOO , socket . htons ( self . rloc . afi ) )
  i1II11 += self . rloc . pack_address ( )
  return ( i1II11 + iii11i11 + iIii1iii1 + OoOOo0Oo0o0 + OOOo0 + I1Ii1i111I + o00oO )
  if 64 - 64: ooOoO0o % IiII - iII111i * i1IIi * I1Ii111 + IiII
  if 43 - 43: O0 / IiII
 def encode ( self ) :
  iIi1i = 0
  if ( self . local_bit ) : iIi1i |= 0x0004
  if ( self . probe_bit ) : iIi1i |= 0x0002
  if ( self . reach_bit ) : iIi1i |= 0x0001
  if 41 - 41: OoOoOO00
  Oo00oo = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( iIi1i ) ,
 socket . htons ( self . rloc . afi ) )
  if 81 - 81: Ii1I . I1IiiI % o0oOOo0O0Ooo . OoOoOO00
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 94 - 94: oO0o % Oo0Ooo + OoO0O00 * oO0o - i11iIiiIii / I11i
   try :
    Oo00oo = Oo00oo [ 0 : - 2 ] + self . encode_lcaf ( )
   except :
    lprint ( "Could not encode LCAF for RLOC-record" )
    if 46 - 46: IiII - OoO0O00 * iII111i . I1Ii111 - ooOoO0o . i1IIi
  else :
   Oo00oo += self . rloc . pack_address ( )
   if 53 - 53: I1Ii111 * I1IiiI + Oo0Ooo + I1IiiI + OOooOOo
  return ( Oo00oo )
  if 8 - 8: i11iIiiIii + OoOoOO00 . I1ii11iIi11i / OoooooooOO % II111iiii
  if 21 - 21: oO0o - o0oOOo0O0Ooo + ooOoO0o . I1IiiI * oO0o * Ii1I
 def decode_lcaf ( self , packet , nonce , ms_json_encrypt ) :
  iiII1iiI = "HBBBBH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
  i1I1iiiI , Oo0OoooOoO0O0 , iIi1i , oO000O0oO00 , OooIiii1ii , I1ii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
  if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
  I1ii = socket . ntohs ( I1ii )
  packet = packet [ ooo0000oo0 : : ]
  if ( I1ii > len ( packet ) ) : return ( None )
  if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
  if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
  if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
  if 86 - 86: IiII
  if ( oO000O0oO00 == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( I1ii > 0 ) :
    iiII1iiI = "H"
    ooo0000oo0 = struct . calcsize ( iiII1iiI )
    if ( I1ii < ooo0000oo0 ) : return ( None )
    if 71 - 71: Ii1I - i1IIi . I1IiiI
    oo = len ( packet )
    i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
    i1I1iiiI = socket . ntohs ( i1I1iiiI )
    if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
    if ( i1I1iiiI == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ ooo0000oo0 : : ]
     self . rloc_name = None
     if ( i1I1iiiI == LISP_AFI_NAME ) :
      packet , i1Ii1iiI = lisp_decode_dist_name ( packet )
      self . rloc_name = i1Ii1iiI
     else :
      self . rloc . afi = i1I1iiiI
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
      if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
      if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
    I1ii -= oo - len ( packet )
    if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
    if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
  elif ( oO000O0oO00 == LISP_LCAF_GEO_COORD_TYPE ) :
   if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
   if 87 - 87: I1IiiI + OoooooooOO + O0
   if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
   if 65 - 65: IiII
   OOOooo = lisp_geo ( "" )
   packet = OOOooo . decode_geo ( packet , I1ii , OooIiii1ii )
   if ( packet == None ) : return ( None )
   self . geo = OOOooo
   if 25 - 25: OOooOOo % i1IIi + I1Ii111 * iIii1I11I1II1 * ooOoO0o + oO0o
  elif ( oO000O0oO00 == LISP_LCAF_JSON_TYPE ) :
   O0i1i11I1IIi1II = OooIiii1ii & 0x02
   if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
   if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
   if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
   if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
   iiII1iiI = "H"
   ooo0000oo0 = struct . calcsize ( iiII1iiI )
   if ( I1ii < ooo0000oo0 ) : return ( None )
   if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
   i1IiI11I11I = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
   i1IiI11I11I = socket . ntohs ( i1IiI11I11I )
   if ( I1ii < ooo0000oo0 + i1IiI11I11I ) : return ( None )
   if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
   packet = packet [ ooo0000oo0 : : ]
   self . json = lisp_json ( "" , packet [ 0 : i1IiI11I11I ] , O0i1i11I1IIi1II ,
 ms_json_encrypt )
   packet = packet [ i1IiI11I11I : : ]
   if 38 - 38: IiII / i1IIi
   if 60 - 60: OoOoOO00
   if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
   if 61 - 61: IiII . IiII
   i1I1iiiI = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
   if ( i1I1iiiI != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = i1I1iiiI
    packet = self . rloc . unpack_address ( packet )
    if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
    if 95 - 95: iII111i / ooOoO0o + I1Ii111
  elif ( oO000O0oO00 == LISP_LCAF_ELP_TYPE ) :
   if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
   if 81 - 81: I1ii11iIi11i
   if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
   if 76 - 76: I1Ii111 - O0
   Ii11111iiIi11 = lisp_elp ( None )
   Ii11111iiIi11 . elp_nodes = [ ]
   while ( I1ii > 0 ) :
    iIi1i , i1I1iiiI = struct . unpack ( "HH" , packet [ : 4 ] )
    if 18 - 18: oO0o . OoOoOO00 + ooOoO0o * iII111i * iIii1I11I1II1 % O0
    i1I1iiiI = socket . ntohs ( i1I1iiiI )
    if ( i1I1iiiI == LISP_AFI_LCAF ) : return ( None )
    if 32 - 32: O0 / I11i . O0
    o00Oo0 = lisp_elp_node ( )
    Ii11111iiIi11 . elp_nodes . append ( o00Oo0 )
    if 25 - 25: Oo0Ooo - iII111i
    iIi1i = socket . ntohs ( iIi1i )
    o00Oo0 . eid = ( iIi1i & 0x4 )
    o00Oo0 . probe = ( iIi1i & 0x2 )
    o00Oo0 . strict = ( iIi1i & 0x1 )
    o00Oo0 . address . afi = i1I1iiiI
    o00Oo0 . address . mask_len = o00Oo0 . address . host_mask_len ( )
    packet = o00Oo0 . address . unpack_address ( packet [ 4 : : ] )
    I1ii -= o00Oo0 . address . addr_length ( ) + 4
    if 96 - 96: O0 . I1IiiI
   Ii11111iiIi11 . select_elp_node ( )
   self . elp = Ii11111iiIi11
   if 2 - 2: I11i . oO0o * IiII
  elif ( oO000O0oO00 == LISP_LCAF_RLE_TYPE ) :
   if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
   if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
   if 31 - 31: oO0o
   if 74 - 74: OoO0O00
   ooo0o0O = lisp_rle ( None )
   ooo0o0O . rle_nodes = [ ]
   while ( I1ii > 0 ) :
    I1iIiiI1IIi1 , II1ii1 , OoOo0Oo0 , i1I1iiiI = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 93 - 93: O0
    i1I1iiiI = socket . ntohs ( i1I1iiiI )
    if ( i1I1iiiI == LISP_AFI_LCAF ) : return ( None )
    if 82 - 82: OoooooooOO - iII111i % I1ii11iIi11i
    oO0oOOOO0oO0o0 = lisp_rle_node ( )
    ooo0o0O . rle_nodes . append ( oO0oOOOO0oO0o0 )
    if 39 - 39: o0oOOo0O0Ooo
    oO0oOOOO0oO0o0 . level = OoOo0Oo0
    oO0oOOOO0oO0o0 . address . afi = i1I1iiiI
    oO0oOOOO0oO0o0 . address . mask_len = oO0oOOOO0oO0o0 . address . host_mask_len ( )
    packet = oO0oOOOO0oO0o0 . address . unpack_address ( packet [ 6 : : ] )
    if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
    I1ii -= oO0oOOOO0oO0o0 . address . addr_length ( ) + 6
    if ( I1ii >= 2 ) :
     i1I1iiiI = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( i1I1iiiI ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , oO0oOOOO0oO0o0 . rloc_name = lisp_decode_dist_name ( packet )
      if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
      if ( packet == None ) : return ( None )
      I1ii -= len ( oO0oOOOO0oO0o0 . rloc_name ) + 1 + 2
      if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
      if 30 - 30: i11iIiiIii % OOooOOo
      if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
   self . rle = ooo0o0O
   self . rle . build_forwarding_list ( )
   if 27 - 27: I1IiiI + OoOoOO00 + iII111i
  elif ( oO000O0oO00 == LISP_LCAF_SECURITY_TYPE ) :
   if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
   if 34 - 34: i1IIi % Oo0Ooo . oO0o
   if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
   if 62 - 62: Oo0Ooo . OoO0O00 * I1Ii111 . i11iIiiIii * O0
   if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
   O0OOOOO0O = packet
   II111i1I = lisp_keys ( 1 )
   packet = II111i1I . decode_lcaf ( O0OOOOO0O , I1ii )
   if ( packet == None ) : return ( None )
   if 62 - 62: I1IiiI . Ii1I
   if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
   if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
   if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
   Oo0O = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( II111i1I . cipher_suite in Oo0O ) :
    if ( II111i1I . cipher_suite == LISP_CS_25519_CBC ) :
     III = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 52 - 52: Ii1I - I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo
    if ( II111i1I . cipher_suite == LISP_CS_25519_CHACHA ) :
     III = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
   else :
    III = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
   packet = III . decode_lcaf ( O0OOOOO0O , I1ii )
   if ( packet == None ) : return ( None )
   if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
   if ( len ( packet ) < 2 ) : return ( None )
   i1I1iiiI = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( i1I1iiiI )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 40 - 40: OoOoOO00 - II111iiii
   if 29 - 29: I1IiiI - O0
   if 36 - 36: I1IiiI * I1IiiI
   if 79 - 79: I1Ii111 - I11i
   if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
   if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
   IIi1Ii = self . rloc_name
   if ( IIi1Ii ) : IIi1Ii = blue ( self . rloc_name , False )
   if 4 - 4: OoOoOO00 / OoooooooOO - iIii1I11I1II1 / o0oOOo0O0Ooo / I11i
   if 31 - 31: Oo0Ooo / I1ii11iIi11i - II111iiii - OOooOOo
   if 5 - 5: oO0o
   if 51 - 51: i11iIiiIii
   if 21 - 21: O0 - IiII * i1IIi + o0oOOo0O0Ooo % I11i + iIii1I11I1II1
   if 35 - 35: i11iIiiIii + i1IIi
   II111iii = self . keys [ 1 ] if self . keys else None
   if ( II111iii == None ) :
    if ( III . remote_public_key == None ) :
     i1i111III1 = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( i1i111III1 , IIi1Ii ) )
     III = None
    else :
     i1i111III1 = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( i1i111III1 , IIi1Ii ) )
     III . compute_shared_key ( "encap" )
     if 16 - 16: OoO0O00 - I1Ii111 * iII111i
     if 41 - 41: i11iIiiIii + i1IIi / IiII * I1ii11iIi11i / iIii1I11I1II1
     if 70 - 70: I1IiiI % oO0o + iII111i % i11iIiiIii + ooOoO0o
     if 88 - 88: I11i * oO0o * I1ii11iIi11i - OOooOOo * IiII + o0oOOo0O0Ooo
     if 9 - 9: OoooooooOO
     if 26 - 26: OoOoOO00 + II111iiii - OoO0O00 + iII111i - iII111i % O0
     if 79 - 79: iIii1I11I1II1 - OoOoOO00 - O0 + I1ii11iIi11i
     if 69 - 69: oO0o % OoooooooOO
     if 21 - 21: I1Ii111
     if 62 - 62: Ii1I % o0oOOo0O0Ooo
   if ( II111iii ) :
    if ( III . remote_public_key == None ) :
     III = None
     o0o00O000 = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( o0o00O000 , IIi1Ii ) )
    elif ( II111iii . compare_keys ( III ) ) :
     III = II111iii
     lprint ( "    Maintain stored encap-keys for {}" . format ( IIi1Ii ) )
     if 65 - 65: OoO0O00 + Oo0Ooo + IiII / OoOoOO00
    else :
     if ( II111iii . remote_public_key == None ) :
      i1i111III1 = "New encap-keying for existing state"
     else :
      i1i111III1 = "Remote encap-rekeying"
      if 37 - 37: oO0o - I11i
     lprint ( "    {} for {}" . format ( bold ( i1i111III1 , False ) ,
 IIi1Ii ) )
     II111iii . remote_public_key = III . remote_public_key
     II111iii . compute_shared_key ( "encap" )
     III = II111iii
     if 64 - 64: OoO0O00 * OoOoOO00
     if 50 - 50: I1ii11iIi11i + I11i * iII111i
   self . keys = [ None , III , None , None ]
   if 27 - 27: OoOoOO00 * OOooOOo * iIii1I11I1II1 / i1IIi
  else :
   if 60 - 60: OOooOOo * I1Ii111 . oO0o
   if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
   if 51 - 51: I1IiiI . I11i - OoOoOO00
   if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
   packet = packet [ I1ii : : ]
   if 97 - 97: Ii1I . Ii1I % iII111i
  return ( packet )
  if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
  if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
 def decode ( self , packet , nonce , ms_json_encrypt = False ) :
  iiII1iiI = "BBBBHH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
  self . priority , self . weight , self . mpriority , self . mweight , iIi1i , i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 25 - 25: I11i - I1ii11iIi11i
  if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
  iIi1i = socket . ntohs ( iIi1i )
  i1I1iiiI = socket . ntohs ( i1I1iiiI )
  self . local_bit = True if ( iIi1i & 0x0004 ) else False
  self . probe_bit = True if ( iIi1i & 0x0002 ) else False
  self . reach_bit = True if ( iIi1i & 0x0001 ) else False
  if 83 - 83: O0
  if ( i1I1iiiI == LISP_AFI_LCAF ) :
   packet = packet [ ooo0000oo0 - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
  else :
   self . rloc . afi = i1I1iiiI
   packet = packet [ ooo0000oo0 : : ]
   packet = self . rloc . unpack_address ( packet )
   if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
  if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
 def end_of_rlocs ( self , packet , rloc_count ) :
  for iIi1iIIIiIiI in range ( rloc_count ) :
   packet = self . decode ( packet , None , False )
   if ( packet == None ) : return ( None )
   if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
  return ( packet )
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
class lisp_map_referral ( object ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 64 - 64: IiII . OoO0O00 * i11iIiiIii
  if 18 - 18: Ii1I % o0oOOo0O0Ooo - Oo0Ooo
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # IiII . I1Ii111
 lisp_hex_string ( self . nonce ) ) )
  if 24 - 24: i1IIi + II111iiii - oO0o % OoO0O00 . OoO0O00
  if 89 - 89: I1IiiI . I1Ii111
 def encode ( self ) :
  iIiIii = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  Oo00oo = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  return ( Oo00oo )
  if 38 - 38: I1IiiI % i11iIiiIii
  if 17 - 17: i11iIiiIii
 def decode ( self , packet ) :
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 81 - 81: I1Ii111
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  iIiIii = socket . ntohl ( iIiIii [ 0 ] )
  self . record_count = iIiIii & 0xff
  packet = packet [ ooo0000oo0 : : ]
  if 25 - 25: I1IiiI
  iiII1iiI = "Q"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
  self . nonce = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  return ( packet )
  if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
  if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
  if 33 - 33: II111iiii + Ii1I
  if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
  if 59 - 59: I11i % Ii1I / OoOoOO00
  if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
  if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
class lisp_ddt_entry ( object ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
  if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 80 - 80: Oo0Ooo
  if 58 - 58: I1Ii111 + OOooOOo
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
  if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  I1iII1iI1 = self . delegation_set [ 0 ]
  return ( I1iII1iI1 . print_node_type ( ) )
  if 15 - 15: OoooooooOO + I11i
  if 76 - 76: O0 % Ii1I * ooOoO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 13 - 13: OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
  if 21 - 21: Ii1I % O0
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   IiI11111I1ii1 = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( IiI11111I1ii1 == None ) :
    IiI11111I1ii1 = lisp_ddt_entry ( )
    IiI11111I1ii1 . eid . copy_address ( self . group )
    IiI11111I1ii1 . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , IiI11111I1ii1 )
    if 40 - 40: I1IiiI . Oo0Ooo - Ii1I
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IiI11111I1ii1 . group )
   IiI11111I1ii1 . add_source_entry ( self )
   if 60 - 60: o0oOOo0O0Ooo
   if 25 - 25: Ii1I . II111iiii * iII111i - o0oOOo0O0Ooo + Ii1I
   if 35 - 35: ooOoO0o
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 64 - 64: i11iIiiIii - Oo0Ooo / iIii1I11I1II1 / I1IiiI % ooOoO0o
  if 42 - 42: Oo0Ooo * OoOoOO00 % ooOoO0o * oO0o - Oo0Ooo + OOooOOo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 5 - 5: OoooooooOO * O0 / I1Ii111 + ooOoO0o . I1Ii111
  if 57 - 57: ooOoO0o * OOooOOo % OoOoOO00 - OoOoOO00 - o0oOOo0O0Ooo * i1IIi
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 80 - 80: iII111i
  if 81 - 81: OoooooooOO % OoOoOO00 % Oo0Ooo - I1IiiI
  if 43 - 43: o0oOOo0O0Ooo % o0oOOo0O0Ooo
class lisp_ddt_node ( object ) :
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
  if ( self . nonce in lisp_ddt_map_requestQ ) :
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
  iIiIii = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : iIiIii |= ( 1 << 27 )
  if 3 - 3: oO0o - Oo0Ooo * I1IiiI / I1ii11iIi11i / OOooOOo
  if 45 - 45: II111iiii
  if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
  if 84 - 84: o0oOOo0O0Ooo
  if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
  if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
  if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
  Oo00oo = struct . pack ( "I" , socket . htonl ( iIiIii ) )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  Oo00oo += struct . pack ( "III" , 0 , 0 , 0 )
  if 66 - 66: OOooOOo * Oo0Ooo
  if 58 - 58: OOooOOo
  if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
  if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    Oo00oo += struct . pack ( "H" , 0 )
   else :
    Oo00oo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    Oo00oo += ( self . hostname + "\0" ) . encode ( )
    if 13 - 13: ooOoO0o
   return ( Oo00oo )
   if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
   if 3 - 3: iIii1I11I1II1 / oO0o
   if 61 - 61: I1Ii111 / O0 - iII111i
   if 44 - 44: i1IIi
   if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
  i1I1iiiI = socket . htons ( LISP_AFI_LCAF )
  oO000O0oO00 = LISP_LCAF_NAT_TYPE
  I1ii = socket . htons ( 16 )
  OOoOOO = socket . htons ( self . ms_port )
  I1iiiI1i = socket . htons ( self . etr_port )
  Oo00oo += struct . pack ( "HHBBHHHH" , i1I1iiiI , 0 , oO000O0oO00 , 0 , I1ii ,
 OOoOOO , I1iiiI1i , socket . htons ( self . global_etr_rloc . afi ) )
  Oo00oo += self . global_etr_rloc . pack_address ( )
  Oo00oo += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  Oo00oo += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : Oo00oo += struct . pack ( "H" , 0 )
  if 69 - 69: iII111i * I11i
  if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
  if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
  if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
  for IiIi1I1i1iIiI in self . rtr_list :
   Oo00oo += struct . pack ( "H" , socket . htons ( IiIi1I1i1iIiI . afi ) )
   Oo00oo += IiIi1I1i1iIiI . pack_address ( )
   if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
  return ( Oo00oo )
  if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
  if 63 - 63: I1ii11iIi11i - Ii1I + I11i
 def decode ( self , packet ) :
  O0OOOOO0O = packet
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  iIiIii = iIiIii [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if 72 - 72: O0 . OOooOOo
  iiII1iiI = "Q"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
  o0Oo0o = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 74 - 74: i1IIi
  iIiIii = socket . ntohl ( iIiIii )
  self . nonce = o0Oo0o [ 0 ]
  self . info_reply = iIiIii & 0x08000000
  self . hostname = None
  packet = packet [ ooo0000oo0 : : ]
  if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
  if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
  if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
  if 35 - 35: i11iIiiIii + oO0o
  if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
  iiII1iiI = "HH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
  if 12 - 12: II111iiii - iIii1I11I1II1
  if 43 - 43: i11iIiiIii % OoO0O00
  if 100 - 100: i1IIi
  if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
  IiII11iI1 , III1II1I1iI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if ( III1II1I1iI != 0 ) : return ( None )
  if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
  packet = packet [ ooo0000oo0 : : ]
  iiII1iiI = "IBBH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 71 - 71: IiII + OoO0O00
  IiIIi , I1i , Iii1iii1II , iIIi1iIi11 = struct . unpack ( iiII1iiI ,
 packet [ : ooo0000oo0 ] )
  if 17 - 17: iIii1I11I1II1
  if ( iIIi1iIi11 != 0 ) : return ( None )
  packet = packet [ ooo0000oo0 : : ]
  if 10 - 10: i11iIiiIii / iII111i - oO0o
  if 98 - 98: Ii1I % iII111i . I11i
  if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i % o0oOOo0O0Ooo . ooOoO0o - oO0o
  if 64 - 64: I11i * ooOoO0o
  if ( self . info_reply == False ) :
   iiII1iiI = "H"
   ooo0000oo0 = struct . calcsize ( iiII1iiI )
   if ( len ( packet ) >= ooo0000oo0 ) :
    i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
    if ( socket . ntohs ( i1I1iiiI ) == LISP_AFI_NAME ) :
     packet = packet [ ooo0000oo0 : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 86 - 86: OoooooooOO * I1IiiI
     if 88 - 88: Ii1I + O0
   return ( O0OOOOO0O )
   if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
   if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
   if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
   if 85 - 85: OoooooooOO * ooOoO0o
   if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
  iiII1iiI = "HHBBHHH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
  i1I1iiiI , I1iIiiI1IIi1 , oO000O0oO00 , I1i , I1ii , OOoOOO , I1iiiI1i = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
  if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
  if ( socket . ntohs ( i1I1iiiI ) != LISP_AFI_LCAF ) : return ( None )
  if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
  self . ms_port = socket . ntohs ( OOoOOO )
  self . etr_port = socket . ntohs ( I1iiiI1i )
  packet = packet [ ooo0000oo0 : : ]
  if 62 - 62: I1Ii111 % II111iiii
  if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
  if 91 - 91: i11iIiiIii + Ii1I
  if 85 - 85: I11i % IiII
  iiII1iiI = "H"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
  if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
  if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
  i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
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
  if ( len ( packet ) < ooo0000oo0 ) : return ( O0OOOOO0O )
  if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
  i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if ( i1I1iiiI != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( i1I1iiiI )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( O0OOOOO0O )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 72 - 72: I1Ii111 . OoO0O00
   if 59 - 59: I1IiiI * I11i % i1IIi
   if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
   if 60 - 60: iIii1I11I1II1
   if 13 - 13: II111iiii + Ii1I
  if ( len ( packet ) < ooo0000oo0 ) : return ( O0OOOOO0O )
  if 33 - 33: i1IIi
  i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if ( i1I1iiiI != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( i1I1iiiI )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( O0OOOOO0O )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
   if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
   if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
   if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
   if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
   if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
  while ( len ( packet ) >= ooo0000oo0 ) :
   i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
   packet = packet [ ooo0000oo0 : : ]
   if ( i1I1iiiI == 0 ) : continue
   IiIi1I1i1iIiI = lisp_address ( socket . ntohs ( i1I1iiiI ) , "" , 0 , 0 )
   packet = IiIi1I1i1iIiI . unpack_address ( packet )
   if ( packet == None ) : return ( O0OOOOO0O )
   IiIi1I1i1iIiI . mask_len = IiIi1I1i1iIiI . host_mask_len ( )
   self . rtr_list . append ( IiIi1I1i1iIiI )
   if 81 - 81: i1IIi % iIii1I11I1II1
  return ( O0OOOOO0O )
  if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
  if 82 - 82: ooOoO0o
  if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
class lisp_nat_info ( object ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
  if 59 - 59: i11iIiiIii / OoO0O00
 def timed_out ( self ) :
  i1i111Iiiiiii = time . time ( ) - self . uptime
  return ( i1i111Iiiiiii >= ( LISP_INFO_INTERVAL * 2 ) )
  if 48 - 48: iIii1I11I1II1
  if 19 - 19: oO0o
  if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
class lisp_info_source ( object ) :
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
  III = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ III ] = self
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
  ooo = auth1 + auth2 + auth3
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
  ooo = auth1 + auth2 + auth3 + auth4
  if 6 - 6: I1ii11iIi11i
 return ( ooo )
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
  iii1IiII1ii = port
  if ( os . path . exists ( iii1IiII1ii ) ) :
   os . system ( "rm " + iii1IiII1ii )
   time . sleep ( 1 )
   if 38 - 38: o0oOOo0O0Ooo . OoO0O00 + I1ii11iIi11i - I1IiiI * i1IIi
  iIIiIiiI = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  iIIiIiiI . bind ( iii1IiII1ii )
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
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
def lisp_packet_ipc ( packet , source , sport ) :
 IiIii1iIIII = "packet@{}@{}@{}@" . format ( str ( len ( packet ) ) , source , str ( sport ) )
 return ( IiIii1iIIII . encode ( ) + packet )
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
 if 49 - 49: I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 IiIii1iIIII = "control-packet@{}@{}@" . format ( dest , str ( dport ) )
 return ( IiIii1iIIII . encode ( ) + packet )
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
 if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
 if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
 if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
 if 30 - 30: I11i + O0 / Ii1I / OoOoOO00 - oO0o + II111iiii
 if 21 - 21: iIii1I11I1II1 % OoooooooOO * OOooOOo % i1IIi
def lisp_data_packet_ipc ( packet , source ) :
 IiIii1iIIII = "data-packet@{}@{}@@" . format ( str ( len ( packet ) ) , source )
 return ( IiIii1iIIII . encode ( ) + packet )
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
def lisp_command_ipc ( ipc , source ) :
 Oo00oo = "command@{}@{}@@" . format ( len ( ipc ) , source ) + ipc
 return ( Oo00oo . encode ( ) )
 if 45 - 45: Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
 if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
 if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
 if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
 if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 if 92 - 92: OoO0O00 . i1IIi
def lisp_api_ipc ( source , data ) :
 Oo00oo = "api@" + str ( len ( data ) ) + "@" + source + "@@" + data
 return ( Oo00oo . encode ( ) )
 if 22 - 22: Ii1I . I1IiiI
 if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
 if 66 - 66: I11i + iII111i
 if 50 - 50: IiII
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 if 8 - 8: I11i - I11i % IiII
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
def lisp_ipc ( packet , send_socket , node ) :
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 if 81 - 81: OOooOOo * oO0o
 if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 50 - 50: i1IIi
  if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
 o0oO0O = 1500 if ( packet . find ( b"control-packet" ) == - 1 ) else 9000
 if 3 - 3: i11iIiiIii / I1ii11iIi11i % I1Ii111 + o0oOOo0O0Ooo + O0
 oo00 = 0
 i1iIii = len ( packet )
 I11ii = 0
 o000o = .001
 while ( i1iIii > 0 ) :
  oO0O0o0 = min ( i1iIii , o0oO0O )
  o0Ooo = packet [ oo00 : oO0O0o0 + oo00 ]
  if 9 - 9: iII111i % Oo0Ooo % OoOoOO00 + i11iIiiIii / i11iIiiIii
  try :
   if ( type ( o0Ooo ) == str ) : o0Ooo = o0Ooo . encode ( )
   send_socket . sendto ( o0Ooo , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( o0Ooo ) , len ( packet ) , node ) )
   if 42 - 42: IiII * O0 % i1IIi * I1ii11iIi11i / OOooOOo % I1IiiI
   I11ii = 0
   o000o = .001
   if 19 - 19: OoO0O00 . i1IIi
  except socket . error as oO0ooOOO :
   if ( I11ii == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 23 - 23: II111iiii
    if 74 - 74: OOooOOo % i11iIiiIii % i11iIiiIii . I1ii11iIi11i
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( o0Ooo ) , len ( packet ) , node , oO0ooOOO ) )
   if 95 - 95: I11i
   if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
   I11ii += 1
   time . sleep ( o000o )
   if 94 - 94: OOooOOo / IiII
   lprint ( "Retrying after {} ms ..." . format ( o000o * 1000 ) )
   o000o *= 2
   continue
   if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
   if 22 - 22: OoOoOO00 - Oo0Ooo
  oo00 += oO0O0o0
  i1iIii -= oO0O0o0
  if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 return
 if 33 - 33: I11i + O0
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
 if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
 if 12 - 12: II111iiii + I11i
 if 9 - 9: I1ii11iIi11i
 if 51 - 51: I1ii11iIi11i
 if 37 - 37: I1IiiI % I1Ii111
 if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 oo00 = 0
 o000ooOo0o0Oo = b""
 i1iIii = len ( packet ) * 2
 while ( oo00 < i1iIii ) :
  o000ooOo0o0Oo += packet [ oo00 : oo00 + 8 ] + b" "
  oo00 += 8
  i1iIii -= 4
  if 98 - 98: I11i * O0 + IiII - oO0o
 return ( o000ooOo0o0Oo . decode ( ) )
 if 35 - 35: OoooooooOO * Ii1I
 if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
 if 67 - 67: o0oOOo0O0Ooo . I11i + i1IIi
 if 100 - 100: Oo0Ooo - I1IiiI . OOooOOo % iIii1I11I1II1 . I11i
 if 83 - 83: OoOoOO00 * iII111i
 if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
 if 94 - 94: iII111i . Ii1I
def lisp_send ( lisp_sockets , dest , port , packet ) :
 OOooo0O0O00o = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 41 - 41: OoOoOO00
 if 29 - 29: Oo0Ooo % OoO0O00 + OOooOOo + I1ii11iIi11i . iIii1I11I1II1 . ooOoO0o
 if 28 - 28: IiII + OoooooooOO % I1IiiI
 if 14 - 14: OoooooooOO
 if 98 - 98: i1IIi * iII111i / Oo0Ooo
 if 96 - 96: I1Ii111 / ooOoO0o
 if 23 - 23: I1Ii111
 if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 I1IIIi = dest . print_address_no_iid ( )
 if ( I1IIIi . find ( "::ffff:" ) != - 1 and I1IIIi . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : OOooo0O0O00o = lisp_sockets [ 0 ]
  if ( OOooo0O0O00o == None ) :
   OOooo0O0O00o = lisp_sockets [ 0 ]
   I1IIIi = I1IIIi . split ( "::ffff:" ) [ - 1 ]
   if 21 - 21: iII111i
   if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
   if 75 - 75: OoooooooOO
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + I1IIIi , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
 if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 if 63 - 63: Oo0Ooo * I1IiiI
 oOOoOo = ( LISP_RLOC_PROBE_TTL == 128 )
 if ( oOOoOo ) :
  iIII1IIIi1 = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  oOOoOo = ( iIII1IIIi1 in [ 0x12 , 0x28 ] )
  if ( oOOoOo ) : lisp_set_ttl ( OOooo0O0O00o , LISP_RLOC_PROBE_TTL )
  if 14 - 14: iII111i / oO0o . oO0o - OOooOOo * i1IIi - i1IIi
  if 70 - 70: OoooooooOO
 try : OOooo0O0O00o . sendto ( packet , ( I1IIIi , port ) )
 except socket . error as oO0ooOOO :
  lprint ( "socket.sendto() failed: {}" . format ( oO0ooOOO ) )
  if 60 - 60: OOooOOo - Ii1I * Ii1I
  if 69 - 69: i11iIiiIii . IiII + o0oOOo0O0Ooo % Ii1I - OoO0O00
  if 46 - 46: OoOoOO00 + iII111i * o0oOOo0O0Ooo - I1ii11iIi11i / oO0o + IiII
  if 1 - 1: iIii1I11I1II1 / OoooooooOO + Oo0Ooo . Ii1I
  if 25 - 25: I1ii11iIi11i / i1IIi * oO0o - II111iiii * i1IIi
 if ( oOOoOo ) : lisp_set_ttl ( OOooo0O0O00o , 64 )
 return
 if 57 - 57: OoO0O00 % OoO0O00
 if 67 - 67: O0 . i11iIiiIii + iIii1I11I1II1
 if 86 - 86: iIii1I11I1II1
 if 81 - 81: OOooOOo / I11i / OoooooooOO
 if 74 - 74: I11i + OoooooooOO % II111iiii % o0oOOo0O0Ooo
 if 27 - 27: OoO0O00 * Oo0Ooo
 if 80 - 80: i11iIiiIii . OoO0O00 - I11i % I11i
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 94 - 94: ooOoO0o
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 if 95 - 95: II111iiii
 if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
 if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
 oO0O0o0 = total_length - len ( packet )
 if ( oO0O0o0 == 0 ) : return ( [ True , packet ] )
 if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 75 - 75: I1Ii111 - i1IIi - OoO0O00
 if 25 - 25: iII111i . o0oOOo0O0Ooo
 if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
 if 68 - 68: ooOoO0o % OoooooooOO
 if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
 i1iIii = oO0O0o0
 while ( i1iIii > 0 ) :
  try : o0Ooo = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 60 - 60: iII111i . OOooOOo
  o0Ooo = o0Ooo [ 0 ]
  if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
  if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
  if 19 - 19: I1IiiI
  if 99 - 99: OOooOOo - OOooOOo
  if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
  ooooO0Oo = o0Ooo . decode ( )
  if ( ooooO0Oo . find ( "packet@" ) == 0 ) :
   ooooO0Oo = ooooO0Oo . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( o0Ooo ) ,
   # I1IiiI - IiII . I1IiiI / OoooooooOO * o0oOOo0O0Ooo
 ooooO0Oo [ 1 ] if len ( ooooO0Oo ) > 2 else "?" )
   return ( [ False , o0Ooo ] )
   if 11 - 11: OoooooooOO . Oo0Ooo / ooOoO0o + Oo0Ooo . I11i . OOooOOo
   if 10 - 10: I1ii11iIi11i - OoooooooOO
  i1iIii -= len ( o0Ooo )
  packet += o0Ooo
  if 41 - 41: IiII + I1ii11iIi11i + I11i % iII111i - I1ii11iIi11i
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( o0Ooo ) , total_length , source ) )
  if 54 - 54: OoO0O00
  if 67 - 67: i11iIiiIii
 return ( [ True , packet ] )
 if 2 - 2: I1ii11iIi11i * i1IIi
 if 17 - 17: I1ii11iIi11i * Ii1I % Oo0Ooo * I1Ii111 + OoO0O00 . OoooooooOO
 if 60 - 60: Ii1I . II111iiii
 if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
 if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
 if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
 if 50 - 50: iIii1I11I1II1
 if 56 - 56: oO0o
 if 55 - 55: iIii1I11I1II1 % oO0o % OOooOOo / I1Ii111 * OoooooooOO / Oo0Ooo
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 Oo00oo = b""
 for o0Ooo in payload : Oo00oo += o0Ooo + b"\x40"
 return ( Oo00oo [ : - 1 ] )
 if 88 - 88: I11i + OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: OOooOOo - ooOoO0o % iII111i % IiII
 if 71 - 71: OoO0O00 - ooOoO0o - I1IiiI + O0
 if 15 - 15: i1IIi
 if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
 if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
 if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
 if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
 if 15 - 15: oO0o . IiII + I1Ii111 - OoooooooOO
 if 85 - 85: II111iiii - Oo0Ooo + oO0o . i11iIiiIii + Oo0Ooo
 if 86 - 86: ooOoO0o . OoO0O00
 if 47 - 47: IiII % I1IiiI
 if 91 - 91: Ii1I
 if 69 - 69: iII111i
 if 96 - 96: Ii1I
 if 39 - 39: OoO0O00 - I1IiiI % II111iiii - IiII * I1ii11iIi11i
 if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
 if 7 - 7: ooOoO0o * I11i / iIii1I11I1II1
 if 15 - 15: OoooooooOO / iII111i
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 40 - 40: o0oOOo0O0Ooo
  if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
  if 78 - 78: Oo0Ooo
  if 74 - 74: O0 / I11i
  try : oo0Ooo = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 15 - 15: i11iIiiIii % iIii1I11I1II1 . II111iiii * I11i / I11i
  if 80 - 80: Ii1I % II111iiii
  if 4 - 4: OoOoOO00 * OOooOOo / OoooooooOO % OoOoOO00 * I1ii11iIi11i * o0oOOo0O0Ooo
  if 69 - 69: O0 % iIii1I11I1II1
  if 94 - 94: O0
  if 50 - 50: I1Ii111 * o0oOOo0O0Ooo - ooOoO0o - I1ii11iIi11i % I1IiiI . ooOoO0o
  if ( internal == False ) :
   Oo00oo = oo0Ooo [ 0 ]
   O0oo0OoO0oo = lisp_convert_6to4 ( oo0Ooo [ 1 ] [ 0 ] )
   ooO0 = oo0Ooo [ 1 ] [ 1 ]
   if 35 - 35: Ii1I % i1IIi + I1IiiI
   if ( ooO0 == LISP_DATA_PORT ) :
    o0OooOo000oo0ooooO = lisp_data_plane_logging
    Oooo = lisp_format_packet ( Oo00oo [ 0 : 60 ] ) + " ..."
   else :
    o0OooOo000oo0ooooO = True
    Oooo = lisp_format_packet ( Oo00oo )
    if 34 - 34: OoooooooOO % ooOoO0o
    if 16 - 16: OoOoOO00 + Oo0Ooo + iIii1I11I1II1 . OoOoOO00 - OOooOOo / o0oOOo0O0Ooo
   if ( o0OooOo000oo0ooooO ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( Oo00oo ) , bold ( "from " + O0oo0OoO0oo , False ) , ooO0 ,
 Oooo ) )
    if 8 - 8: OoOoOO00 . OOooOOo / I11i % Oo0Ooo
   return ( [ "packet" , O0oo0OoO0oo , ooO0 , Oo00oo ] )
   if 36 - 36: Ii1I + iIii1I11I1II1
   if 13 - 13: iII111i . I1Ii111 % ooOoO0o / i1IIi
   if 64 - 64: iII111i
   if 9 - 9: I1ii11iIi11i + Oo0Ooo * I11i / I1Ii111 / I1ii11iIi11i / oO0o
   if 48 - 48: Oo0Ooo % i1IIi / I1ii11iIi11i / oO0o + iII111i
   if 47 - 47: Ii1I
  OoOO0 = False
  oOO = oo0Ooo [ 0 ]
  if ( type ( oOO ) == str ) : oOO = oOO . encode ( )
  oOoOO0OO = False
  if 95 - 95: iIii1I11I1II1 % I1ii11iIi11i + II111iiii + ooOoO0o + iIii1I11I1II1 / I1Ii111
  while ( OoOO0 == False ) :
   oOO = oOO . split ( b"@" )
   if 59 - 59: I1Ii111
   if ( len ( oOO ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( oOO [ 0 ] ) )
    if 22 - 22: OoooooooOO
    oOoOO0OO = True
    break
    if 88 - 88: I1Ii111 - OoO0O00
    if 29 - 29: I1IiiI . I1Ii111
   OOOOoo = oOO [ 0 ] . decode ( )
   try :
    i1Ii1I1i11i11 = int ( oOO [ 1 ] )
   except :
    o00O0OO0 = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( o00O0OO0 , oo0Ooo ) )
    oOoOO0OO = True
    break
    if 77 - 77: II111iiii
   O0oo0OoO0oo = oOO [ 2 ] . decode ( )
   ooO0 = oOO [ 3 ] . decode ( )
   if 80 - 80: i11iIiiIii / Ii1I / ooOoO0o - OoO0O00
   if 17 - 17: OoO0O00 * i11iIiiIii * Oo0Ooo / OoooooooOO / II111iiii
   if 92 - 92: iII111i + II111iiii
   if 88 - 88: o0oOOo0O0Ooo . IiII / O0 + ooOoO0o
   if 19 - 19: Oo0Ooo
   if 24 - 24: Ii1I . I1ii11iIi11i . i1IIi % Oo0Ooo
   if 63 - 63: OoO0O00 . I1IiiI + ooOoO0o + I1ii11iIi11i
   if 63 - 63: OoooooooOO * OoOoOO00 - Ii1I
   if ( len ( oOO ) > 5 ) :
    Oo00oo = lisp_bit_stuff ( oOO [ 4 : : ] )
   else :
    Oo00oo = oOO [ 4 ]
    if 93 - 93: OoooooooOO * OOooOOo
    if 34 - 34: OoOoOO00 + OoOoOO00 - Oo0Ooo
    if 21 - 21: i1IIi + O0 % I1ii11iIi11i / i1IIi - iII111i
    if 56 - 56: Ii1I - Ii1I / OoooooooOO * i11iIiiIii - iII111i % iIii1I11I1II1
    if 87 - 87: O0
    if 23 - 23: I1IiiI
   OoOO0 , Oo00oo = lisp_receive_segments ( lisp_socket , Oo00oo ,
 O0oo0OoO0oo , i1Ii1I1i11i11 )
   if ( Oo00oo == None ) : return ( [ "" , "" , "" , "" ] )
   if 97 - 97: OoooooooOO / ooOoO0o
   if 50 - 50: O0
   if 100 - 100: IiII . Oo0Ooo - Oo0Ooo % iII111i
   if 83 - 83: i11iIiiIii % ooOoO0o * I1ii11iIi11i - ooOoO0o . OoOoOO00
   if 54 - 54: oO0o + OoOoOO00 - OoOoOO00 / I1ii11iIi11i * i11iIiiIii + OoooooooOO
   if ( OoOO0 == False ) :
    oOO = Oo00oo
    continue
    if 20 - 20: OOooOOo / O0
    if 51 - 51: ooOoO0o - I1Ii111 * oO0o
   if ( ooO0 == "" ) : ooO0 = "no-port"
   if ( OOOOoo == "command" and lisp_i_am_core == False ) :
    OOOooo0OooOoO = Oo00oo . find ( b" {" )
    II1Ii1IiiI1 = Oo00oo if OOOooo0OooOoO == - 1 else Oo00oo [ : OOOooo0OooOoO ]
    II1Ii1IiiI1 = ": '" + II1Ii1IiiI1 . decode ( ) + "'"
   else :
    II1Ii1IiiI1 = ""
    if 10 - 10: i1IIi % I11i % i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo + OOooOOo
    if 87 - 87: O0 + o0oOOo0O0Ooo * OoOoOO00 % o0oOOo0O0Ooo * ooOoO0o
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( Oo00oo ) , bold ( "from " + O0oo0OoO0oo , False ) , ooO0 , OOOOoo ,
 II1Ii1IiiI1 if ( OOOOoo in [ "command" , "api" ] ) else ": ... " if ( OOOOoo == "data-packet" ) else ": " + lisp_format_packet ( Oo00oo ) ) )
   if 48 - 48: I1ii11iIi11i * I1Ii111 % ooOoO0o * II111iiii + OoOoOO00
   if 17 - 17: iII111i + OOooOOo
   if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
   if 59 - 59: O0 + Oo0Ooo
   if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
  if ( oOoOO0OO ) : continue
  return ( [ OOOOoo , O0oo0OoO0oo , ooO0 , Oo00oo ] )
  if 50 - 50: I11i . I11i % I1IiiI - i1IIi
  if 63 - 63: OoO0O00 . iII111i
  if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
  if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
  if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
  if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
  if 30 - 30: OoO0O00 / ooOoO0o % ooOoO0o
  if 40 - 40: i1IIi . iIii1I11I1II1 * OoOoOO00
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 OoO000o = False
 ooO = time . time ( )
 if 5 - 5: IiII . Oo0Ooo / II111iiii * OoOoOO00 * oO0o
 IiIii1iIIII = lisp_control_header ( )
 if ( IiIii1iIIII . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( OoO000o )
  if 21 - 21: iII111i / OoO0O00
  if 27 - 27: IiII / Oo0Ooo
  if 71 - 71: IiII - iII111i . I1IiiI
  if 76 - 76: i11iIiiIii / i11iIiiIii % o0oOOo0O0Ooo + I1IiiI
  if 76 - 76: O0
 Oooo0Ooooo = source
 if ( source . find ( "lisp" ) == - 1 ) :
  I111 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  I111 . string_to_afi ( source )
  I111 . store_address ( source )
  source = I111
  if 47 - 47: o0oOOo0O0Ooo - OOooOOo / OOooOOo
  if 97 - 97: OoO0O00 / i11iIiiIii - o0oOOo0O0Ooo * OoOoOO00 * i11iIiiIii . iII111i
 if ( IiIii1iIIII . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , ooO )
  if 41 - 41: i11iIiiIii . i11iIiiIii + OoOoOO00 . i1IIi
 elif ( IiIii1iIIII . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , ooO )
  if 54 - 54: I11i + OoooooooOO - II111iiii . iII111i
 elif ( IiIii1iIIII . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 36 - 36: I1IiiI * II111iiii
 elif ( IiIii1iIIII . type == LISP_MAP_NOTIFY ) :
  if ( Oooo0Ooooo == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-rtr" ) ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-itr" ) ) :
   lisp_process_unicast_map_notify ( lisp_sockets , packet , source )
   if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
   if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
 elif ( IiIii1iIIII . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 66 - 66: I1ii11iIi11i * ooOoO0o . i11iIiiIii * Oo0Ooo - I11i . I1IiiI
 elif ( IiIii1iIIII . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 43 - 43: I11i . iII111i . IiII - oO0o
 elif ( IiIii1iIIII . type == LISP_NAT_INFO and IiIii1iIIII . is_info_reply ( ) ) :
  I1iIiiI1IIi1 , II1ii1 , OoO000o = lisp_process_info_reply ( source , packet , True )
  if 60 - 60: i1IIi + iII111i * i1IIi . iII111i
 elif ( IiIii1iIIII . type == LISP_NAT_INFO and IiIii1iIIII . is_info_reply ( ) == False ) :
  O0O0 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , O0O0 , udp_sport ,
 None )
  if 40 - 40: i1IIi . OoO0O00
 elif ( IiIii1iIIII . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 65 - 65: Oo0Ooo
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( IiIii1iIIII . type ) )
  if 81 - 81: OOooOOo % OoooooooOO / IiII . Oo0Ooo - ooOoO0o . I1IiiI
 return ( OoO000o )
 if 3 - 3: O0
 if 95 - 95: i11iIiiIii
 if 100 - 100: iIii1I11I1II1 * I1IiiI * Ii1I * i1IIi . I1Ii111 * I1IiiI
 if 54 - 54: o0oOOo0O0Ooo / iII111i + IiII - o0oOOo0O0Ooo - I11i
 if 28 - 28: I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * IiII + OoooooooOO
 if 52 - 52: I1Ii111
 if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp ) :
 if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
 iIIiiIi = bold ( "RLOC-probe" , False )
 if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( iIIiiIi ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
  if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( iIIiiIi ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
  if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( iIIiiIi ) )
 return
 if 88 - 88: i1IIi
 if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 if 55 - 55: OoO0O00 % IiII
 if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
 if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
 if 63 - 63: I1Ii111 + iII111i
 if 6 - 6: I1ii11iIi11i + Ii1I
 if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
 if 97 - 97: ooOoO0o + OOooOOo
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
 if 6 - 6: Oo0Ooo + I1IiiI
 if 48 - 48: oO0o . I1ii11iIi11i
 if 59 - 59: IiII - Ii1I
 if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
 if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
 if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , map_request ,
 keys , enc , auth , mr_ttl = - 1 ) :
 if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
 oO0OOO0o0oooO = map_request . rloc_probe if ( map_request != None ) else False
 iIii1IiiII = map_request . json_telemetry if ( map_request != None ) else None
 if 77 - 77: I1ii11iIi11i % i1IIi + OOooOOo - OOooOOo - o0oOOo0O0Ooo
 if 45 - 45: I1ii11iIi11i / o0oOOo0O0Ooo / I1IiiI - Oo0Ooo * ooOoO0o - I1ii11iIi11i
 ooOooOooO00 = lisp_map_reply ( )
 ooOooOooO00 . rloc_probe = oO0OOO0o0oooO
 ooOooOooO00 . echo_nonce_capable = enc
 ooOooOooO00 . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 ooOooOooO00 . record_count = 1
 ooOooOooO00 . nonce = nonce
 Oo00oo = ooOooOooO00 . encode ( )
 ooOooOooO00 . print_map_reply ( )
 if 85 - 85: II111iiii % Oo0Ooo * ooOoO0o + ooOoO0o - ooOoO0o . OoooooooOO
 IIIOOo0o = lisp_eid_record ( )
 IIIOOo0o . rloc_count = len ( rloc_set )
 if ( iIii1IiiII != None ) : IIIOOo0o . rloc_count += 1
 IIIOOo0o . authoritative = auth
 IIIOOo0o . record_ttl = ttl
 IIIOOo0o . action = action
 IIIOOo0o . eid = eid
 IIIOOo0o . group = group
 if 21 - 21: II111iiii - OOooOOo * O0
 Oo00oo += IIIOOo0o . encode ( )
 IIIOOo0o . print_record ( "  " , False )
 if 52 - 52: IiII / I1IiiI - o0oOOo0O0Ooo
 iI11i = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 78 - 78: OOooOOo - Oo0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i
 I1iI1I = None
 for iiIiIIi1I in rloc_set :
  Ooo0 = iiIiIIi1I . rloc . is_multicast_address ( )
  ooOooOo = lisp_rloc_record ( )
  ooOOoo0Oooooo = oO0OOO0o0oooO and ( Ooo0 or iIii1IiiII == None )
  O0O0 = iiIiIIi1I . rloc . print_address_no_iid ( )
  if ( O0O0 in iI11i or Ooo0 ) :
   ooOooOo . local_bit = True
   ooOooOo . probe_bit = ooOOoo0Oooooo
   ooOooOo . keys = keys
   if ( iiIiIIi1I . priority == 254 and lisp_i_am_rtr ) :
    ooOooOo . rloc_name = "RTR"
    if 19 - 19: OoOoOO00 * I11i + IiII / OOooOOo
   if ( I1iI1I == None ) : I1iI1I = iiIiIIi1I . rloc
   if 70 - 70: II111iiii
  ooOooOo . store_rloc_entry ( iiIiIIi1I )
  ooOooOo . reach_bit = True
  ooOooOo . print_record ( "    " )
  Oo00oo += ooOooOo . encode ( )
  if 21 - 21: i11iIiiIii . iII111i * O0 - iII111i
  if 5 - 5: O0 . OoOoOO00 / iII111i
  if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
  if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
  if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
 if ( iIii1IiiII != None ) :
  ooOooOo = lisp_rloc_record ( )
  if ( I1iI1I ) : ooOooOo . rloc . copy_address ( I1iI1I )
  ooOooOo . local_bit = True
  ooOooOo . probe_bit = True
  ooOooOo . reach_bit = True
  if ( lisp_i_am_rtr ) :
   ooOooOo . priority = 254
   ooOooOo . rloc_name = "RTR"
   if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
  iiIII1 = lisp_encode_telemetry ( iIii1IiiII , eo = str ( time . time ( ) ) )
  ooOooOo . json = lisp_json ( "telemetry" , iiIII1 )
  ooOooOo . print_record ( "    " )
  Oo00oo += ooOooOo . encode ( )
  if 18 - 18: OoO0O00 . Oo0Ooo
 return ( Oo00oo )
 if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 if 14 - 14: i1IIi
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
 if 48 - 48: OoO0O00
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 iIi = lisp_map_referral ( )
 iIi . record_count = 1
 iIi . nonce = nonce
 Oo00oo = iIi . encode ( )
 iIi . print_map_referral ( )
 if 28 - 28: I11i / oO0o % OOooOOo
 IIIOOo0o = lisp_eid_record ( )
 if 74 - 74: i11iIiiIii . Ii1I . I1IiiI * I1IiiI
 OOo = 0
 if ( ddt_entry == None ) :
  IIIOOo0o . eid = eid
  IIIOOo0o . group = group
 else :
  OOo = len ( ddt_entry . delegation_set )
  IIIOOo0o . eid = ddt_entry . eid
  IIIOOo0o . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 40 - 40: ooOoO0o / i1IIi / I1IiiI
 IIIOOo0o . rloc_count = OOo
 IIIOOo0o . authoritative = True
 if 71 - 71: OoOoOO00 / i11iIiiIii * iII111i
 if 90 - 90: Ii1I
 if 27 - 27: oO0o + Ii1I . i11iIiiIii
 if 97 - 97: iII111i . I1IiiI
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 OOiiI1iii1I = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( OOo == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   I1iII1iI1 = ddt_entry . delegation_set [ 0 ]
   if ( I1iII1iI1 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
   if ( I1iII1iI1 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 45 - 45: oO0o
    if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
    if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
    if 100 - 100: i11iIiiIii - iII111i - I11i
    if 5 - 5: oO0o % IiII * iII111i
    if 98 - 98: iII111i / OOooOOo + IiII
    if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : OOiiI1iii1I = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  OOiiI1iii1I = ( lisp_i_am_ms and I1iII1iI1 . is_ms_peer ( ) == False )
  if 82 - 82: ooOoO0o % OOooOOo % Ii1I
  if 82 - 82: I1ii11iIi11i
 IIIOOo0o . action = action
 IIIOOo0o . ddt_incomplete = OOiiI1iii1I
 IIIOOo0o . record_ttl = ttl
 if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 Oo00oo += IIIOOo0o . encode ( )
 IIIOOo0o . print_record ( "  " , True )
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 if ( OOo == 0 ) : return ( Oo00oo )
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 for I1iII1iI1 in ddt_entry . delegation_set :
  ooOooOo = lisp_rloc_record ( )
  ooOooOo . rloc = I1iII1iI1 . delegate_address
  ooOooOo . priority = I1iII1iI1 . priority
  ooOooOo . weight = I1iII1iI1 . weight
  ooOooOo . mpriority = 255
  ooOooOo . mweight = 0
  ooOooOo . reach_bit = True
  Oo00oo += ooOooOo . encode ( )
  ooOooOo . print_record ( "    " )
  if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 return ( Oo00oo )
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
 i1iiii = map_request . print_prefix ( )
 if 80 - 80: i1IIi + I1IiiI / OoooooooOO + OOooOOo . Ii1I
 if ( oooOOoO0oo0 == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( i1iiii , False ) ) )
  if 96 - 96: iIii1I11I1II1 - I1ii11iIi11i
  return
  if 41 - 41: II111iiii - OoOoOO00 + OoooooooOO - I1ii11iIi11i . oO0o . o0oOOo0O0Ooo
  if 34 - 34: I1ii11iIi11i % I11i / Oo0Ooo * oO0o % ooOoO0o / OOooOOo
 iiiiiiiiII1i = oooOOoO0oo0 . print_eid_tuple ( )
 if 34 - 34: iIii1I11I1II1 * OoooooooOO * oO0o
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( iiiiiiiiII1i , False ) , green ( i1iiii , False ) ) )
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
 o0Oo0o = map_request . nonce
 i1iIii1 = lisp_nonce_echoing
 iI1iiiiiii = map_request . keys
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
 Oo00oo = lisp_build_map_reply ( oooOOoO0oo0 . eid , oooOOoO0oo0 . group , oooOOoO0oo0 . rloc_set , o0Oo0o ,
 LISP_NO_ACTION , 1440 , map_request , iI1iiiiiii , i1iIii1 , True , ttl )
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
  iii = ( oO0o0o00O . is_private_address ( ) == False )
  IiIi1I1i1iIiI = oO0o0o00O . print_address_no_iid ( )
  if ( iii and IiIi1I1i1iIiI in lisp_rtr_list or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , oO0o0o00O , None , Oo00oo )
   return
   if 40 - 40: o0oOOo0O0Ooo . IiII * OoOoOO00
   if 14 - 14: OOooOOo
   if 18 - 18: i11iIiiIii % iII111i
   if 70 - 70: O0 + iII111i % I11i % I1Ii111 + OoOoOO00 / ooOoO0o
   if 35 - 35: IiII + OoO0O00
   if 82 - 82: i1IIi - ooOoO0o / I11i + I11i % I1IiiI - OoooooooOO
 lisp_send_map_reply ( lisp_sockets , Oo00oo , oO0o0o00O , sport )
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
 o0Oo0o = map_request . nonce
 if 33 - 33: II111iiii
 oo0oO = map_request . target_eid
 iiI = map_request . target_group
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
 iI1iiiiiii = map_request . keys
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
 Oo00oo = lisp_build_map_reply ( oo0oO , iiI , oOO000OOO , o0Oo0o , LISP_NO_ACTION ,
 1440 , map_request , iI1iiiiiii , i1iIii1 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , Oo00oo , oO0o0o00O , sport )
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
 iii1I11I1II1I1I1i = [ ]
 for iiIiIIi1I in oOO000OOO :
  if ( iiIiIIi1I . is_rtr ( ) ) : continue
  if ( iiIiIIi1I . rloc . is_private_address ( ) ) :
   o0OoO0o0o0ooo = copy . deepcopy ( iiIiIIi1I )
   iii1I11I1II1I1I1i . append ( o0OoO0o0o0ooo )
   continue
   if 41 - 41: OoOoOO00 + IiII % I1Ii111 / OOooOOo . I1IiiI
  OOI1I1 = iiIiIIi1I
  break
  if 43 - 43: II111iiii - ooOoO0o / iIii1I11I1II1
 if ( OOI1I1 == None ) : return ( oOO000OOO )
 OOI1I1 = OOI1I1 . rloc . print_address_no_iid ( )
 if 30 - 30: O0 * o0oOOo0O0Ooo / iIii1I11I1II1 + iIii1I11I1II1 . OoOoOO00
 if 78 - 78: OoOoOO00 . i11iIiiIii
 if 29 - 29: i11iIiiIii % i1IIi
 if 31 - 31: o0oOOo0O0Ooo + IiII * OOooOOo
 I1Ii1i11II = None
 for iiIiIIi1I in O0ooO0O0O00 . registered_rlocs :
  if ( iiIiIIi1I . is_rtr ( ) ) : continue
  if ( iiIiIIi1I . rloc . is_private_address ( ) ) : continue
  I1Ii1i11II = iiIiIIi1I
  break
  if 75 - 75: II111iiii - OoooooooOO * II111iiii + iIii1I11I1II1 - OoooooooOO * O0
 if ( I1Ii1i11II == None ) : return ( oOO000OOO )
 I1Ii1i11II = I1Ii1i11II . rloc . print_address_no_iid ( )
 if 43 - 43: i1IIi / I1Ii111 % iII111i % Ii1I . Oo0Ooo . O0
 if 82 - 82: i1IIi
 if 25 - 25: I11i / IiII . OoOoOO00 % iII111i . ooOoO0o
 if 69 - 69: O0 . oO0o
 Oooo0 = target_site_eid . site_id
 if ( Oooo0 == 0 ) :
  if ( I1Ii1i11II == OOI1I1 ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( OOI1I1 ) )
   if 16 - 16: iII111i
   return ( iii1I11I1II1I1I1i )
   if 26 - 26: iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
  return ( oOO000OOO )
  if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
  if 65 - 65: OOooOOo * I11i * Oo0Ooo
  if 21 - 21: Ii1I . iIii1I11I1II1
  if 84 - 84: OOooOOo
  if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
  if 33 - 33: ooOoO0o % I1IiiI
  if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
 if ( Oooo0 == O0ooO0O0O00 . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( Oooo0 ) )
  return ( iii1I11I1II1I1I1i )
  if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
 return ( oOO000OOO )
 if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
 if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
 if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
 if 59 - 59: OoO0O00
 if 81 - 81: i11iIiiIii
 if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
 if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
 if 85 - 85: OoooooooOO
 if 37 - 37: OoooooooOO + O0 + I1ii11iIi11i + IiII * iII111i
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 IiIIiOOo = [ ]
 oOO000OOO = [ ]
 if 69 - 69: Oo0Ooo / i1IIi - OOooOOo % i1IIi - oO0o
 if 51 - 51: I1Ii111 * I1ii11iIi11i + I1Ii111 . OoO0O00
 if 79 - 79: I1ii11iIi11i * I1IiiI % Ii1I
 if 61 - 61: oO0o + I11i * OoooooooOO * I11i % OoOoOO00
 if 88 - 88: iII111i * iIii1I11I1II1 + IiII / II111iiii * i11iIiiIii
 if 22 - 22: OOooOOo + Oo0Ooo . I1Ii111 + i11iIiiIii / ooOoO0o - II111iiii
 ooOooo = False
 i1i = False
 for iiIiIIi1I in registered_rloc_set :
  if ( iiIiIIi1I . priority != 254 ) : continue
  i1i |= True
  if ( iiIiIIi1I . rloc . is_exact_match ( mr_source ) == False ) : continue
  ooOooo = True
  break
  if 72 - 72: OoOoOO00
  if 65 - 65: Oo0Ooo + I1Ii111 % I1Ii111 * I1Ii111 + OoO0O00
  if 49 - 49: i1IIi / OOooOOo
  if 22 - 22: ooOoO0o % I11i + OoO0O00 . oO0o * Ii1I
  if 58 - 58: ooOoO0o
  if 12 - 12: Oo0Ooo
  if 49 - 49: OoooooooOO . II111iiii - o0oOOo0O0Ooo * I1ii11iIi11i * Ii1I
 if ( i1i == False ) : return ( registered_rloc_set )
 if 98 - 98: IiII + I1Ii111 . iIii1I11I1II1 + OoooooooOO . I1ii11iIi11i - O0
 if 46 - 46: iII111i
 if 99 - 99: oO0o
 if 85 - 85: I1Ii111 * iIii1I11I1II1 . OoOoOO00
 if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
 if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
 if 48 - 48: iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
 if 24 - 24: I1IiiI
 if 63 - 63: I11i - iIii1I11I1II1 * Ii1I + OoooooooOO . i11iIiiIii
 if 94 - 94: OoO0O00 . oO0o . OoOoOO00 * i11iIiiIii
 OooIII1i1I = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 100 - 100: O0 - II111iiii + OoO0O00 % I1Ii111
 if 40 - 40: iIii1I11I1II1 % OoO0O00 / o0oOOo0O0Ooo + iIii1I11I1II1
 if 77 - 77: I1IiiI
 if 97 - 97: Ii1I - I1IiiI
 if 5 - 5: OoO0O00 / IiII . OoooooooOO / IiII / I1Ii111 * iIii1I11I1II1
 for iiIiIIi1I in registered_rloc_set :
  if ( OooIII1i1I and iiIiIIi1I . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and iiIiIIi1I . priority == 255 ) : continue
  if ( multicast and iiIiIIi1I . mpriority == 255 ) : continue
  if ( iiIiIIi1I . priority == 254 ) :
   IiIIiOOo . append ( iiIiIIi1I )
  else :
   oOO000OOO . append ( iiIiIIi1I )
   if 79 - 79: IiII % ooOoO0o + IiII + IiII - o0oOOo0O0Ooo + iII111i
   if 94 - 94: o0oOOo0O0Ooo * oO0o + O0 * iII111i + oO0o + ooOoO0o
   if 29 - 29: OoO0O00
   if 24 - 24: IiII - OoOoOO00 / OoooooooOO . I1ii11iIi11i
   if 88 - 88: I11i
   if 36 - 36: iIii1I11I1II1 - ooOoO0o * OoO0O00 * OoO0O00 . II111iiii
 if ( ooOooo ) : return ( oOO000OOO )
 if 49 - 49: O0 + OoO0O00 - I1ii11iIi11i + ooOoO0o
 if 90 - 90: O0 . Ii1I * OOooOOo * OoooooooOO * ooOoO0o * Ii1I
 if 12 - 12: ooOoO0o * OoooooooOO * i1IIi
 if 3 - 3: o0oOOo0O0Ooo + Ii1I - i1IIi . OoooooooOO % Ii1I
 if 39 - 39: o0oOOo0O0Ooo
 if 73 - 73: IiII
 if 92 - 92: OOooOOo / ooOoO0o . I1Ii111 . iII111i / ooOoO0o
 if 83 - 83: iIii1I11I1II1 - OoO0O00 - I1Ii111
 if 27 - 27: IiII - iII111i * i11iIiiIii % i11iIiiIii + OoOoOO00 . I1Ii111
 if 10 - 10: IiII / i11iIiiIii
 if 6 - 6: I11i - OOooOOo
 if 100 - 100: Oo0Ooo / OOooOOo + iII111i - o0oOOo0O0Ooo + OoO0O00 % IiII
 oOO000OOO = [ ]
 for iiIiIIi1I in registered_rloc_set :
  if ( iiIiIIi1I . rloc . is_ipv6 ( ) ) : oOO000OOO . append ( iiIiIIi1I )
  if ( iiIiIIi1I . rloc . is_private_address ( ) ) : oOO000OOO . append ( iiIiIIi1I )
  if 91 - 91: Ii1I % I11i % Oo0Ooo / OoO0O00 - II111iiii - o0oOOo0O0Ooo
 oOO000OOO += IiIIiOOo
 return ( oOO000OOO )
 if 50 - 50: OoooooooOO
 if 51 - 51: II111iiii - oO0o % OoooooooOO - II111iiii / O0 - OoooooooOO
 if 21 - 21: iII111i * o0oOOo0O0Ooo
 if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
 if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
 if 40 - 40: I1ii11iIi11i + i1IIi
 if 9 - 9: OOooOOo
 if 74 - 74: OoOoOO00 - OOooOOo % OoOoOO00
 if 82 - 82: I11i % IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 if 65 - 65: IiII / O0 * II111iiii + oO0o
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 OO0OoooO0 = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 OO0OoooO0 . add ( reply_eid )
 return ( OO0OoooO0 )
 if 56 - 56: oO0o + o0oOOo0O0Ooo - i1IIi % Ii1I - II111iiii
 if 7 - 7: OoO0O00 . i1IIi * OoooooooOO . II111iiii * O0
 if 9 - 9: iII111i * iII111i / iIii1I11I1II1 * IiII . II111iiii
 if 3 - 3: I1IiiI - I1IiiI - iIii1I11I1II1
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
def lisp_convert_reply_to_notify ( packet ) :
 if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
 if 10 - 10: oO0o / I1IiiI
 if 95 - 95: II111iiii - IiII % IiII . o0oOOo0O0Ooo
 if 19 - 19: II111iiii . ooOoO0o . I11i - OoooooooOO / I1ii11iIi11i . I1Ii111
 OoIiII = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 OoIiII = socket . ntohl ( OoIiII ) & 0xff
 o0Oo0o = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 10 - 10: I1IiiI / I1Ii111 % IiII . OoOoOO00
 if 65 - 65: II111iiii + OoO0O00 + OoO0O00
 if 48 - 48: I1ii11iIi11i / iIii1I11I1II1
 if 47 - 47: I1Ii111
 iIiIii = ( LISP_MAP_NOTIFY << 28 ) | OoIiII
 IiIii1iIIII = struct . pack ( "I" , socket . htonl ( iIiIii ) )
 i111 = struct . pack ( "I" , 0 )
 if 41 - 41: IiII
 if 25 - 25: I11i % iIii1I11I1II1
 if 27 - 27: iIii1I11I1II1 . O0 . oO0o
 if 21 - 21: oO0o * I1ii11iIi11i
 packet = IiIii1iIIII + o0Oo0o + i111 + packet
 return ( packet )
 if 44 - 44: o0oOOo0O0Ooo * IiII - o0oOOo0O0Ooo
 if 90 - 90: i1IIi + I1ii11iIi11i * oO0o % i11iIiiIii - OoO0O00
 if 12 - 12: OoO0O00 . I1ii11iIi11i - I1IiiI % OOooOOo
 if 9 - 9: Ii1I / O0
 if 95 - 95: iII111i / I11i
 if 86 - 86: O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
 if 22 - 22: Ii1I
 if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
def lisp_notify_subscribers ( lisp_sockets , eid_record , rloc_records ,
 registered_eid , site ) :
 if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
 for iIOoOo0o0ooO0Oo in lisp_pubsub_cache :
  for OO0OoooO0 in list ( lisp_pubsub_cache [ iIOoOo0o0ooO0Oo ] . values ( ) ) :
   oO0ooOOO = OO0OoooO0 . eid_prefix
   if ( oO0ooOOO . is_more_specific ( registered_eid ) == False ) : continue
   if 98 - 98: OoO0O00 % I1Ii111 * IiII
   OOooOooOOoO0O = OO0OoooO0 . itr
   ooO0 = OO0OoooO0 . port
   O00oo00Ooo = red ( OOooOooOOoO0O . print_address_no_iid ( ) , False )
   iIIiIi = bold ( "subscriber" , False )
   Oo00Ooo0O0O0o = "0x" + lisp_hex_string ( OO0OoooO0 . xtr_id )
   o0Oo0o = "0x" + lisp_hex_string ( OO0OoooO0 . nonce )
   if 29 - 29: i1IIi - iII111i % Ii1I + OoO0O00 % IiII
   lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( iIIiIi , O00oo00Ooo , ooO0 , Oo00Ooo0O0O0o , green ( iIOoOo0o0ooO0Oo , False ) , o0Oo0o ) )
   if 29 - 29: II111iiii . i1IIi + I1IiiI . ooOoO0o / Ii1I
   if 82 - 82: I11i . Oo0Ooo * Oo0Ooo % iII111i
   if 37 - 37: OoO0O00 / I1Ii111 . I1Ii111 * i1IIi
   if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
   if 13 - 13: II111iiii
   if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
   Iiooo0O0o0o = copy . deepcopy ( eid_record )
   Iiooo0O0o0o . eid . copy_address ( oO0ooOOO )
   Iiooo0O0o0o = Iiooo0O0o0o . encode ( ) + rloc_records
   lisp_build_map_notify ( lisp_sockets , Iiooo0O0o0o , [ iIOoOo0o0ooO0Oo ] , 1 , OOooOooOOoO0O ,
 ooO0 , OO0OoooO0 . nonce , 0 , 0 , 0 , site , False )
   if 16 - 16: O0 + OOooOOo * I1ii11iIi11i * IiII
   OO0OoooO0 . map_notify_count += 1
   if 56 - 56: iII111i
   if 68 - 68: OoooooooOO % o0oOOo0O0Ooo . i1IIi - II111iiii * OoOoOO00
 return
 if 46 - 46: ooOoO0o . I1IiiI - ooOoO0o + Oo0Ooo
 if 31 - 31: OOooOOo + ooOoO0o . i1IIi - OoO0O00
 if 16 - 16: I11i + I1IiiI - Ii1I / I1ii11iIi11i + Ii1I
 if 38 - 38: i1IIi * iIii1I11I1II1 * iII111i + OoOoOO00
 if 64 - 64: OoO0O00 % o0oOOo0O0Ooo
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 if 98 - 98: Oo0Ooo . II111iiii * I11i
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
 if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
 if 91 - 91: OoO0O00 - OoO0O00 % O0
 if 67 - 67: ooOoO0o * i1IIi
 OO0OoooO0 = lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl ,
 xtr_id )
 if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
 oo0oO = green ( reply_eid . print_prefix ( ) , False )
 OOooOooOOoO0O = red ( itr_rloc . print_address_no_iid ( ) , False )
 OOO0o0o0oOo = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( OOO0o0o0oOo ,
 oo0oO , OOooOooOOoO0O , xtr_id ) )
 if 77 - 77: OoooooooOO . I1ii11iIi11i
 if 37 - 37: i1IIi * iII111i
 if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
 if 43 - 43: OoooooooOO * I1IiiI
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 OO0OoooO0 . map_notify_count += 1
 return
 if 2 - 2: OOooOOo / oO0o + I1ii11iIi11i + i11iIiiIii % iIii1I11I1II1 . I1ii11iIi11i
 if 100 - 100: Oo0Ooo * ooOoO0o + Ii1I / iII111i * o0oOOo0O0Ooo
 if 26 - 26: I1Ii111 * OoOoOO00
 if 38 - 38: II111iiii
 if 50 - 50: OoOoOO00 . IiII - OOooOOo
 if 46 - 46: iIii1I11I1II1
 if 97 - 97: O0 * OOooOOo - o0oOOo0O0Ooo % o0oOOo0O0Ooo * II111iiii % I11i
 if 65 - 65: iIii1I11I1II1 / OOooOOo
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
 if 14 - 14: I11i + Oo0Ooo + i11iIiiIii - i1IIi . O0
 if 47 - 47: o0oOOo0O0Ooo / i1IIi * IiII
 if 50 - 50: I11i
 if 9 - 9: iII111i . OoOoOO00 * iII111i
 if 54 - 54: i11iIiiIii * I1IiiI / IiII - OoO0O00 % i1IIi
 oo0oO = map_request . target_eid
 iiI = map_request . target_group
 i1iiii = lisp_print_eid_tuple ( oo0oO , iiI )
 oO0o0o00O = map_request . itr_rlocs [ 0 ]
 Oo00Ooo0O0O0o = map_request . xtr_id
 o0Oo0o = map_request . nonce
 Oo0Oo00O000O = LISP_NO_ACTION
 OO0OoooO0 = map_request . subscribe_bit
 if 2 - 2: II111iiii - OoOoOO00
 if 81 - 81: IiII / OOooOOo / OoooooooOO + II111iiii - OOooOOo . i11iIiiIii
 if 33 - 33: o0oOOo0O0Ooo - OoooooooOO
 if 30 - 30: i1IIi + II111iiii + OoOoOO00 + I1ii11iIi11i % ooOoO0o % OOooOOo
 if 40 - 40: I1IiiI % I1IiiI - i11iIiiIii % OoOoOO00
 i1i1IIi11 = True
 ii1 = ( lisp_get_eid_hash ( oo0oO ) != None )
 if ( ii1 ) :
  Oooo0oOoO0000 = map_request . map_request_signature
  if ( Oooo0oOoO0000 == None ) :
   i1i1IIi11 = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 26 - 26: Oo0Ooo / IiII . I1ii11iIi11i
  else :
   i1i1i11IIii = map_request . signature_eid
   iiii111I1iI1 , iIiIi111 , i1i1IIi11 = lisp_lookup_public_key ( i1i1i11IIii )
   if ( i1i1IIi11 ) :
    i1i1IIi11 = map_request . verify_map_request_sig ( iIiIi111 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( i1i1i11IIii . print_address ( ) , iiii111I1iI1 . print_address ( ) ) )
    if 45 - 45: oO0o . O0 - ooOoO0o / o0oOOo0O0Ooo
    if 58 - 58: Ii1I . iII111i * OoO0O00 + OoO0O00 % I1Ii111 + I1ii11iIi11i
   iiII1I = bold ( "passed" , False ) if i1i1IIi11 else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( iiII1I ) )
   if 31 - 31: IiII
   if 88 - 88: iIii1I11I1II1 % i1IIi . i11iIiiIii
   if 71 - 71: OoOoOO00 / OoO0O00 * OOooOOo
 if ( OO0OoooO0 and i1i1IIi11 == False ) :
  OO0OoooO0 = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 33 - 33: oO0o . Oo0Ooo
  if 59 - 59: o0oOOo0O0Ooo - Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
  if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
  if 67 - 67: o0oOOo0O0Ooo - Ii1I
  if 29 - 29: OoOoOO00 . I1ii11iIi11i
  if 24 - 24: OOooOOo + i1IIi . I11i . OoOoOO00 + OoooooooOO
  if 98 - 98: ooOoO0o + i1IIi / I1IiiI
  if 1 - 1: IiII . OoooooooOO + II111iiii
  if 6 - 6: O0 * Oo0Ooo
  if 20 - 20: OoooooooOO * i1IIi * IiII / OoooooooOO - Oo0Ooo / i11iIiiIii
  if 28 - 28: iIii1I11I1II1 % OOooOOo * I1IiiI
  if 28 - 28: O0 . OoOoOO00
  if 27 - 27: I1ii11iIi11i / II111iiii + O0 % I1ii11iIi11i
  if 72 - 72: I1IiiI - i1IIi
 ii1IiiIiIIIi = oO0o0o00O if ( oO0o0o00O . afi == ecm_source . afi ) else ecm_source
 if 73 - 73: oO0o - o0oOOo0O0Ooo
 IiiiI1i1 = lisp_site_eid_lookup ( oo0oO , iiI , False )
 if 66 - 66: II111iiii / OoooooooOO * i1IIi % OoOoOO00 + IiII
 if ( IiiiI1i1 == None or IiiiI1i1 . is_star_g ( ) ) :
  ii1i = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( ii1i ,
 green ( i1iiii , False ) ) )
  if 26 - 26: i1IIi * oO0o + Oo0Ooo % i1IIi / iII111i . O0
  if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
  if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
  if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
  lisp_send_negative_map_reply ( lisp_sockets , oo0oO , iiI , o0Oo0o , oO0o0o00O ,
 mr_sport , 15 , Oo00Ooo0O0O0o , OO0OoooO0 )
  if 32 - 32: ooOoO0o
  return ( [ oo0oO , iiI , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 9 - 9: I1Ii111
  if 77 - 77: OoooooooOO * I1Ii111
 iiiiiiiiII1i = IiiiI1i1 . print_eid_tuple ( )
 o00OooO0o0Ooo = IiiiI1i1 . site . site_name
 if 47 - 47: oO0o + ooOoO0o - o0oOOo0O0Ooo
 if 27 - 27: O0
 if 7 - 7: iII111i
 if 14 - 14: i1IIi - i1IIi + iII111i
 if 92 - 92: ooOoO0o
 if ( ii1 == False and IiiiI1i1 . require_signature ) :
  Oooo0oOoO0000 = map_request . map_request_signature
  i1i1i11IIii = map_request . signature_eid
  if ( Oooo0oOoO0000 == None or i1i1i11IIii . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( o00OooO0o0Ooo ) )
   i1i1IIi11 = False
  else :
   i1i1i11IIii = map_request . signature_eid
   iiii111I1iI1 , iIiIi111 , i1i1IIi11 = lisp_lookup_public_key ( i1i1i11IIii )
   if ( i1i1IIi11 ) :
    i1i1IIi11 = map_request . verify_map_request_sig ( iIiIi111 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( i1i1i11IIii . print_address ( ) , iiii111I1iI1 . print_address ( ) ) )
    if 58 - 58: iII111i % I11i
    if 71 - 71: I1IiiI + OoO0O00 + IiII * I11i
   iiII1I = bold ( "passed" , False ) if i1i1IIi11 else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( iiII1I ) )
   if 61 - 61: I1IiiI / OoOoOO00
   if 58 - 58: o0oOOo0O0Ooo - Oo0Ooo % OoOoOO00 + I11i
   if 10 - 10: II111iiii / iIii1I11I1II1 % i11iIiiIii
   if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
   if 43 - 43: oO0o
   if 22 - 22: I1Ii111 + i11iIiiIii
 if ( i1i1IIi11 and IiiiI1i1 . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( o00OooO0o0Ooo , green ( iiiiiiiiII1i , False ) , green ( i1iiii , False ) ) )
  if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
  if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
  if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
  if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
  if 30 - 30: oO0o - OoOoOO00 . I1IiiI
  if 17 - 17: OoOoOO00
  if ( IiiiI1i1 . accept_more_specifics == False ) :
   oo0oO = IiiiI1i1 . eid
   iiI = IiiiI1i1 . group
   if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
   if 57 - 57: O0
   if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
   if 13 - 13: I1ii11iIi11i
   if 32 - 32: OOooOOo / I11i + I1Ii111 / Oo0Ooo * OoooooooOO / II111iiii
  IiIIi = 1
  if ( IiiiI1i1 . force_ttl != None ) :
   IiIIi = IiiiI1i1 . force_ttl | 0x80000000
   if 8 - 8: OoO0O00
   if 17 - 17: iIii1I11I1II1 - Oo0Ooo
   if 25 - 25: O0 + I1ii11iIi11i
   if 53 - 53: OoooooooOO . Oo0Ooo
   if 35 - 35: OOooOOo % i11iIiiIii % ooOoO0o . O0
  lisp_send_negative_map_reply ( lisp_sockets , oo0oO , iiI , o0Oo0o , oO0o0o00O ,
 mr_sport , IiIIi , Oo00Ooo0O0O0o , OO0OoooO0 )
  if 9 - 9: ooOoO0o + iII111i / i1IIi % Oo0Ooo - o0oOOo0O0Ooo / I1IiiI
  return ( [ oo0oO , iiI , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 42 - 42: OOooOOo + oO0o % O0 * I1ii11iIi11i + i11iIiiIii
  if 16 - 16: i1IIi . I11i + OoO0O00 % Ii1I * IiII + I1IiiI
  if 96 - 96: II111iiii + O0 - II111iiii
  if 97 - 97: I1IiiI
  if 87 - 87: I11i + iIii1I11I1II1
 oOOooO0oo = False
 O00o = ""
 oooOoo0oO0 = False
 if ( IiiiI1i1 . force_nat_proxy_reply ) :
  O00o = ", nat-forced"
  oOOooO0oo = True
  oooOoo0oO0 = True
 elif ( IiiiI1i1 . force_proxy_reply ) :
  O00o = ", forced"
  oooOoo0oO0 = True
 elif ( IiiiI1i1 . proxy_reply_requested ) :
  O00o = ", requested"
  oooOoo0oO0 = True
 elif ( map_request . pitr_bit and IiiiI1i1 . pitr_proxy_reply_drop ) :
  O00o = ", drop-to-pitr"
  Oo0Oo00O000O = LISP_DROP_ACTION
 elif ( IiiiI1i1 . proxy_reply_action != "" ) :
  Oo0Oo00O000O = IiiiI1i1 . proxy_reply_action
  O00o = ", forced, action {}" . format ( Oo0Oo00O000O )
  Oo0Oo00O000O = LISP_DROP_ACTION if ( Oo0Oo00O000O == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 32 - 32: II111iiii % OoOoOO00 % I1Ii111 . OoO0O00 * ooOoO0o / I11i
  if 26 - 26: OOooOOo
  if 84 - 84: OoooooooOO / OoO0O00 / OoOoOO00 / OoooooooOO
  if 17 - 17: i1IIi
  if 80 - 80: i1IIi - iIii1I11I1II1 + OoooooooOO + ooOoO0o / IiII - I1ii11iIi11i
  if 90 - 90: I1IiiI * ooOoO0o - I11i + O0 - I11i
  if 59 - 59: OOooOOo % II111iiii
 iiIii = False
 i11 = None
 if ( oooOoo0oO0 and IiiiI1i1 . policy in lisp_policies ) :
  iIIiiIi = lisp_policies [ IiiiI1i1 . policy ]
  if ( iIIiiIi . match_policy_map_request ( map_request , mr_source ) ) : i11 = iIIiiIi
  if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
  if ( i11 ) :
   iiI1I = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( iiI1I ,
 iIIiiIi . policy_name , iIIiiIi . set_action ) )
  else :
   iiI1I = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( iiI1I ,
 iIIiiIi . policy_name ) )
   iiIii = True
   if 47 - 47: Ii1I % OOooOOo . Oo0Ooo
   if 94 - 94: Ii1I - iIii1I11I1II1 + I1IiiI - iIii1I11I1II1 . o0oOOo0O0Ooo
   if 3 - 3: O0 / I11i + OoOoOO00 % IiII / i11iIiiIii
 if ( O00o != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( i1iiii , False ) , o00OooO0o0Ooo , green ( iiiiiiiiII1i , False ) ,
  # i1IIi + II111iiii
 O00o ) )
  if 75 - 75: OOooOOo . IiII . I1IiiI + OoooooooOO
  oOO000OOO = IiiiI1i1 . registered_rlocs
  IiIIi = 1440
  if ( oOOooO0oo ) :
   if ( IiiiI1i1 . site_id != 0 ) :
    I1IiiII1I1 = map_request . source_eid
    oOO000OOO = lisp_get_private_rloc_set ( IiiiI1i1 , I1IiiII1I1 , iiI )
    if 96 - 96: IiII + o0oOOo0O0Ooo - I11i + I1IiiI . iII111i
   if ( oOO000OOO == IiiiI1i1 . registered_rlocs ) :
    oOOooo0 = ( IiiiI1i1 . group . is_null ( ) == False )
    iii1I11I1II1I1I1i = lisp_get_partial_rloc_set ( oOO000OOO , ii1IiiIiIIIi , oOOooo0 )
    if ( iii1I11I1II1I1I1i != oOO000OOO ) :
     IiIIi = 15
     oOO000OOO = iii1I11I1II1I1I1i
     if 24 - 24: I1IiiI - IiII
     if 32 - 32: I1Ii111 . I1ii11iIi11i / OoooooooOO + I1Ii111 . I1Ii111
     if 52 - 52: O0 - I1Ii111 . oO0o
     if 43 - 43: IiII * Ii1I - I1ii11iIi11i * I1ii11iIi11i
     if 53 - 53: oO0o % I11i * OoO0O00 . i1IIi
     if 35 - 35: I11i . IiII + ooOoO0o
     if 19 - 19: O0 - i1IIi / I1Ii111
     if 14 - 14: I11i - i11iIiiIii
  if ( IiiiI1i1 . force_ttl != None ) :
   IiIIi = IiiiI1i1 . force_ttl | 0x80000000
   if 49 - 49: oO0o . I1ii11iIi11i
   if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
   if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
   if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
   if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
   if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
  if ( i11 ) :
   if ( i11 . set_record_ttl ) :
    IiIIi = i11 . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( IiIIi ) )
    if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
   if ( i11 . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    Oo0Oo00O000O = LISP_POLICY_DENIED_ACTION
    oOO000OOO = [ ]
   else :
    IIIi1iI1 = i11 . set_policy_map_reply ( )
    if ( IIIi1iI1 ) : oOO000OOO = [ IIIi1iI1 ]
    if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
    if 72 - 72: I1Ii111
    if 51 - 51: OoOoOO00
  if ( iiIii ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   Oo0Oo00O000O = LISP_POLICY_DENIED_ACTION
   oOO000OOO = [ ]
   if 61 - 61: Oo0Ooo / i1IIi + I1Ii111 - OoooooooOO / O0
   if 25 - 25: I1ii11iIi11i * i11iIiiIii / i1IIi
  i1iIii1 = IiiiI1i1 . echo_nonce_capable
  if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
  if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
  if 46 - 46: oO0o
  if 5 - 5: i1IIi % o0oOOo0O0Ooo + OoOoOO00 - I11i . Ii1I
  if ( i1i1IIi11 ) :
   iiIiI1III111 = IiiiI1i1 . eid
   iIIIi1III = IiiiI1i1 . group
  else :
   iiIiI1III111 = oo0oO
   iIIIi1III = iiI
   Oo0Oo00O000O = LISP_AUTH_FAILURE_ACTION
   oOO000OOO = [ ]
   if 35 - 35: ooOoO0o * iII111i % iII111i + OOooOOo
   if 66 - 66: iII111i - ooOoO0o * I1ii11iIi11i - Ii1I / OoooooooOO
   if 86 - 86: I1IiiI % iII111i + Oo0Ooo + i1IIi % o0oOOo0O0Ooo
   if 85 - 85: Ii1I + I1Ii111 * I11i
   if 59 - 59: Oo0Ooo
   if 35 - 35: OoooooooOO + I1ii11iIi11i * OOooOOo
  if ( OO0OoooO0 ) :
   iiIiI1III111 = oo0oO
   iIIIi1III = iiI
   if 75 - 75: Ii1I * Oo0Ooo % iIii1I11I1II1 . O0 % oO0o
   if 4 - 4: I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
   if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
   if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
   if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
   if 66 - 66: iII111i % iII111i
  packet = lisp_build_map_reply ( iiIiI1III111 , iIIIi1III , oOO000OOO ,
 o0Oo0o , Oo0Oo00O000O , IiIIi , map_request , None , i1iIii1 , False )
  if 59 - 59: II111iiii . i1IIi % i1IIi
  if ( OO0OoooO0 ) :
   lisp_process_pubsub ( lisp_sockets , packet , iiIiI1III111 , oO0o0o00O ,
 mr_sport , o0Oo0o , IiIIi , Oo00Ooo0O0O0o )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , oO0o0o00O , mr_sport )
   if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
   if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
  return ( [ IiiiI1i1 . eid , IiiiI1i1 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
  if 13 - 13: Ii1I % i11iIiiIii
  if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
  if 50 - 50: I1ii11iIi11i + iII111i
  if 64 - 64: oO0o
 OOo = len ( IiiiI1i1 . registered_rlocs )
 if ( OOo == 0 ) :
  lprint ( ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" ) . format ( green ( i1iiii , False ) , o00OooO0o0Ooo ,
  # iIii1I11I1II1
 green ( iiiiiiiiII1i , False ) ) )
  return ( [ IiiiI1i1 . eid , IiiiI1i1 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 54 - 54: O0 + iIii1I11I1II1 / Oo0Ooo * OOooOOo . OOooOOo - I11i
  if 36 - 36: O0
  if 91 - 91: Oo0Ooo / I11i / OoooooooOO - I1ii11iIi11i
  if 7 - 7: oO0o - I11i
  if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
 OO000000ooO0 = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 56 - 56: OOooOOo / i11iIiiIii - OoooooooOO . i1IIi
 II1Iii1iI = map_request . target_eid . hash_address ( OO000000ooO0 )
 II1Iii1iI %= OOo
 OO0O = IiiiI1i1 . registered_rlocs [ II1Iii1iI ]
 if 1 - 1: o0oOOo0O0Ooo + OoOoOO00 * I1IiiI
 if ( OO0O . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( i1iiii , False ) ,
  # I1IiiI . i1IIi
 o00OooO0o0Ooo , green ( iiiiiiiiII1i , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( i1iiii , False ) ,
  # iII111i . O0 - OoO0O00 + OoOoOO00 * I1ii11iIi11i
 red ( OO0O . rloc . print_address ( ) , False ) , o00OooO0o0Ooo ,
 green ( iiiiiiiiII1i , False ) ) )
  if 99 - 99: I1ii11iIi11i % Ii1I - O0 * ooOoO0o . ooOoO0o
  if 32 - 32: o0oOOo0O0Ooo . OoooooooOO % OOooOOo
  if 2 - 2: OoOoOO00 + I1ii11iIi11i + oO0o
  if 27 - 27: OoooooooOO - Ii1I / OoooooooOO + OoO0O00
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , OO0O . rloc , to_etr = True )
  if 58 - 58: OOooOOo * I11i . I1IiiI
 return ( [ IiiiI1i1 . eid , IiiiI1i1 . group , LISP_DDT_ACTION_MS_ACK ] )
 if 46 - 46: I11i + II111iiii * iII111i % ooOoO0o - I1IiiI
 if 73 - 73: I1ii11iIi11i * iIii1I11I1II1 . I1Ii111 - Ii1I
 if 11 - 11: I11i
 if 48 - 48: IiII / O0
 if 46 - 46: ooOoO0o + oO0o
 if 7 - 7: ooOoO0o * oO0o . i1IIi
 if 74 - 74: i1IIi * I11i + OoOoOO00 / OoO0O00 - oO0o / I11i
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 90 - 90: IiII % I1ii11iIi11i % i1IIi
 if 63 - 63: Ii1I . I1IiiI + IiII / OoOoOO00 + ooOoO0o - iIii1I11I1II1
 if 20 - 20: i1IIi % II111iiii . IiII % iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo
 oo0oO = map_request . target_eid
 iiI = map_request . target_group
 i1iiii = lisp_print_eid_tuple ( oo0oO , iiI )
 o0Oo0o = map_request . nonce
 Oo0Oo00O000O = LISP_DDT_ACTION_NULL
 if 68 - 68: OOooOOo % Oo0Ooo * ooOoO0o * OoO0O00 / iII111i
 if 96 - 96: i11iIiiIii - I1IiiI % OoOoOO00 * Ii1I % OoO0O00 % O0
 if 100 - 100: oO0o . OoooooooOO
 if 58 - 58: I11i % OoooooooOO
 if 97 - 97: OOooOOo - IiII
 OoO0 = None
 if ( lisp_i_am_ms ) :
  IiiiI1i1 = lisp_site_eid_lookup ( oo0oO , iiI , False )
  if ( IiiiI1i1 == None ) : return
  if 10 - 10: Oo0Ooo / o0oOOo0O0Ooo . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if ( IiiiI1i1 . registered ) :
   Oo0Oo00O000O = LISP_DDT_ACTION_MS_ACK
   IiIIi = 1440
  else :
   oo0oO , iiI , Oo0Oo00O000O = lisp_ms_compute_neg_prefix ( oo0oO , iiI )
   Oo0Oo00O000O = LISP_DDT_ACTION_MS_NOT_REG
   IiIIi = 1
   if 93 - 93: i11iIiiIii / IiII
 else :
  OoO0 = lisp_ddt_cache_lookup ( oo0oO , iiI , False )
  if ( OoO0 == None ) :
   Oo0Oo00O000O = LISP_DDT_ACTION_NOT_AUTH
   IiIIi = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( i1iiii , False ) ) )
   if 35 - 35: I1Ii111 / o0oOOo0O0Ooo
  elif ( OoO0 . is_auth_prefix ( ) ) :
   if 44 - 44: IiII % i11iIiiIii
   if 99 - 99: ooOoO0o % iIii1I11I1II1 + o0oOOo0O0Ooo % I11i
   if 66 - 66: iIii1I11I1II1
   if 74 - 74: OoooooooOO - I1Ii111 - I1IiiI
   Oo0Oo00O000O = LISP_DDT_ACTION_DELEGATION_HOLE
   IiIIi = 15
   II1I1 = OoO0 . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( II1I1 ,
   # I1ii11iIi11i / o0oOOo0O0Ooo * I1ii11iIi11i / OOooOOo
 green ( i1iiii , False ) ) )
   if 29 - 29: i1IIi * Oo0Ooo / i1IIi
   if ( iiI . is_null ( ) ) :
    oo0oO = lisp_ddt_compute_neg_prefix ( oo0oO , OoO0 ,
 lisp_ddt_cache )
   else :
    iiI = lisp_ddt_compute_neg_prefix ( iiI , OoO0 ,
 lisp_ddt_cache )
    oo0oO = lisp_ddt_compute_neg_prefix ( oo0oO , OoO0 ,
 OoO0 . source_cache )
    if 86 - 86: OoOoOO00 . I11i
   OoO0 = None
  else :
   II1I1 = OoO0 . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( II1I1 , green ( i1iiii , False ) ) )
   if 97 - 97: Ii1I
   IiIIi = 1440
   if 24 - 24: I1IiiI * i11iIiiIii
   if 83 - 83: OoOoOO00 * I1ii11iIi11i
   if 64 - 64: II111iiii * i1IIi - ooOoO0o
   if 4 - 4: ooOoO0o . OoO0O00 . OoO0O00 % ooOoO0o * Oo0Ooo - I1IiiI
   if 8 - 8: I1IiiI - I1Ii111 - OoooooooOO * Oo0Ooo * Ii1I
   if 11 - 11: I1IiiI
 Oo00oo = lisp_build_map_referral ( oo0oO , iiI , OoO0 , Oo0Oo00O000O , IiIIi , o0Oo0o )
 o0Oo0o = map_request . nonce >> 32
 if ( map_request . nonce != 0 and o0Oo0o != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , Oo00oo , ecm_source , port )
 return
 if 43 - 43: I11i
 if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
 if 67 - 67: oO0o % I1Ii111
 if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
 if 15 - 15: I1IiiI
 if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
 if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
 if 45 - 45: I1Ii111 + OOooOOo
 if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
 if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
 if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
 if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
 if 75 - 75: oO0o / i1IIi / Ii1I * Oo0Ooo
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 oOo0O = eid . hash_address ( entry_prefix )
 o0OOOoOOo000oo = eid . addr_length ( ) * 8
 I1iIii11iIi1I = 0
 if 3 - 3: O0 / OOooOOo - iII111i
 if 60 - 60: I1IiiI
 if 3 - 3: II111iiii % IiII % I1IiiI - I1IiiI . I1Ii111 - OoOoOO00
 if 18 - 18: O0
 for I1iIii11iIi1I in range ( o0OOOoOOo000oo ) :
  iiiii11i = 1 << ( o0OOOoOOo000oo - I1iIii11iIi1I - 1 )
  if ( oOo0O & iiiii11i ) : break
  if 21 - 21: OOooOOo + o0oOOo0O0Ooo
  if 28 - 28: OOooOOo + i1IIi + II111iiii / Oo0Ooo + iIii1I11I1II1 . Oo0Ooo
 if ( I1iIii11iIi1I > neg_prefix . mask_len ) : neg_prefix . mask_len = I1iIii11iIi1I
 return
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
def lisp_neg_prefix_walk ( entry , parms ) :
 oo0oO , iIIII , O00OOO = parms
 if 61 - 61: I1Ii111
 if ( iIIII == None ) :
  if ( entry . eid . instance_id != oo0oO . instance_id ) :
   return ( [ True , parms ] )
   if 67 - 67: I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
  if ( entry . eid . afi != oo0oO . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( iIIII ) == False ) :
   return ( [ True , parms ] )
   if 75 - 75: OOooOOo . ooOoO0o
   if 32 - 32: i1IIi / I11i + iIii1I11I1II1 . OOooOOo
   if 67 - 67: iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
   if 51 - 51: I1IiiI + O0
   if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
   if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
 lisp_find_negative_mask_len ( oo0oO , entry . eid , O00OOO )
 return ( [ True , parms ] )
 if 85 - 85: OoOoOO00
 if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
 if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
 if 72 - 72: Ii1I
 if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
 if 85 - 85: i11iIiiIii / I11i
 if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
 if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
 if 87 - 87: IiII
 if 92 - 92: OoO0O00 / IiII - ooOoO0o
 if 45 - 45: iII111i - I11i * ooOoO0o * OOooOOo / I1Ii111 * iII111i
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 33 - 33: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo % iIii1I11I1II1 + I11i / i11iIiiIii
 O00OOO = lisp_address ( eid . afi , "" , 0 , 0 )
 O00OOO . copy_address ( eid )
 O00OOO . mask_len = 0
 if 64 - 64: I11i * ooOoO0o / OoooooooOO
 IioOOO0O = ddt_entry . print_eid_tuple ( )
 iIIII = ddt_entry . eid
 if 100 - 100: I11i - iIii1I11I1II1 % I11i + OoO0O00 / II111iiii % ooOoO0o
 if 46 - 46: i11iIiiIii - o0oOOo0O0Ooo / OoOoOO00 - I11i
 if 47 - 47: IiII
 if 85 - 85: I1IiiI . O0 / oO0o
 if 100 - 100: I1IiiI / IiII + OoO0O00 . iII111i
 eid , iIIII , O00OOO = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , iIIII , O00OOO ) )
 if 39 - 39: OoooooooOO * OOooOOo - OoO0O00
 if 3 - 3: I11i . i11iIiiIii % Oo0Ooo % II111iiii . I11i
 if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
 if 72 - 72: ooOoO0o + i11iIiiIii / i1IIi
 O00OOO . mask_address ( O00OOO . mask_len )
 if 64 - 64: OOooOOo - OOooOOo
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # i1IIi - OoooooooOO / ooOoO0o
 IioOOO0O , O00OOO . print_prefix ( ) ) )
 return ( O00OOO )
 if 75 - 75: OOooOOo + IiII + ooOoO0o / I1IiiI . iIii1I11I1II1 / Oo0Ooo
 if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
 if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
 if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
 if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
 if 70 - 70: i1IIi * II111iiii * I1IiiI
 if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
 if 20 - 20: Oo0Ooo % OOooOOo
def lisp_ms_compute_neg_prefix ( eid , group ) :
 O00OOO = lisp_address ( eid . afi , "" , 0 , 0 )
 O00OOO . copy_address ( eid )
 O00OOO . mask_len = 0
 i11i1i1i1I = lisp_address ( group . afi , "" , 0 , 0 )
 i11i1i1i1I . copy_address ( group )
 i11i1i1i1I . mask_len = 0
 iIIII = None
 if 75 - 75: i11iIiiIii * OOooOOo / I11i / O0
 if 56 - 56: I1ii11iIi11i % IiII
 if 66 - 66: I1Ii111 % I1ii11iIi11i
 if 77 - 77: I11i % iIii1I11I1II1 . iIii1I11I1II1 + oO0o % i11iIiiIii . IiII
 if 33 - 33: IiII - OOooOOo / i11iIiiIii * iIii1I11I1II1
 if ( group . is_null ( ) ) :
  OoO0 = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( OoO0 == None ) :
   O00OOO . mask_len = O00OOO . host_mask_len ( )
   i11i1i1i1I . mask_len = i11i1i1i1I . host_mask_len ( )
   return ( [ O00OOO , i11i1i1i1I , LISP_DDT_ACTION_NOT_AUTH ] )
   if 2 - 2: i11iIiiIii % ooOoO0o
  O0O00OO0O0 = lisp_sites_by_eid
  if ( OoO0 . is_auth_prefix ( ) ) : iIIII = OoO0 . eid
 else :
  OoO0 = lisp_ddt_cache . lookup_cache ( group , False )
  if ( OoO0 == None ) :
   O00OOO . mask_len = O00OOO . host_mask_len ( )
   i11i1i1i1I . mask_len = i11i1i1i1I . host_mask_len ( )
   return ( [ O00OOO , i11i1i1i1I , LISP_DDT_ACTION_NOT_AUTH ] )
   if 60 - 60: OoooooooOO
  if ( OoO0 . is_auth_prefix ( ) ) : iIIII = OoO0 . group
  if 11 - 11: OoO0O00 . OoO0O00
  group , iIIII , i11i1i1i1I = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , iIIII , i11i1i1i1I ) )
  if 31 - 31: iIii1I11I1II1
  if 64 - 64: ooOoO0o
  i11i1i1i1I . mask_address ( i11i1i1i1I . mask_len )
  if 30 - 30: OoO0O00 + o0oOOo0O0Ooo / iIii1I11I1II1
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , iIIII . print_prefix ( ) if ( iIIII != None ) else "'not found'" ,
  # I1ii11iIi11i % Oo0Ooo * OoOoOO00 . oO0o % iII111i
  # I1Ii111 / I1ii11iIi11i % Oo0Ooo * iIii1I11I1II1 * i1IIi
  # iII111i
 i11i1i1i1I . print_prefix ( ) ) )
  if 75 - 75: Oo0Ooo * IiII % Ii1I
  O0O00OO0O0 = OoO0 . source_cache
  if 40 - 40: o0oOOo0O0Ooo * i11iIiiIii . ooOoO0o
  if 63 - 63: I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / IiII + I11i
  if 57 - 57: iIii1I11I1II1 % iIii1I11I1II1
  if 23 - 23: II111iiii . ooOoO0o % I1Ii111
  if 39 - 39: OoooooooOO
 Oo0Oo00O000O = LISP_DDT_ACTION_DELEGATION_HOLE if ( iIIII != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 10 - 10: Oo0Ooo * iII111i
 if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
 if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
 if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
 if 44 - 44: OoooooooOO + I1Ii111 + OoO0O00
 if 15 - 15: iIii1I11I1II1 % i1IIi + iII111i
 eid , iIIII , O00OOO = O0O00OO0O0 . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , iIIII , O00OOO ) )
 if 48 - 48: o0oOOo0O0Ooo / oO0o
 if 61 - 61: I1IiiI + iII111i * Ii1I % I1Ii111 . Ii1I
 if 83 - 83: i11iIiiIii * OoOoOO00 * i11iIiiIii % II111iiii . i11iIiiIii * I11i
 if 67 - 67: i1IIi / i1IIi + IiII . oO0o
 O00OOO . mask_address ( O00OOO . mask_len )
 if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # IiII * IiII - OoOoOO00 + OoOoOO00 % oO0o
 # O0
 iIIII . print_prefix ( ) if ( iIIII != None ) else "'not found'" , O00OOO . print_prefix ( ) ) )
 if 93 - 93: IiII
 if 30 - 30: i1IIi - I1ii11iIi11i + Ii1I + oO0o
 return ( [ O00OOO , i11i1i1i1I , Oo0Oo00O000O ] )
 if 45 - 45: Ii1I % OoooooooOO - I1Ii111 * I1IiiI . I1ii11iIi11i
 if 95 - 95: II111iiii
 if 37 - 37: Ii1I + II111iiii + I1IiiI + iIii1I11I1II1 . iII111i
 if 53 - 53: I1Ii111 . I1IiiI / ooOoO0o
 if 23 - 23: I1ii11iIi11i - Ii1I + OoOoOO00
 if 84 - 84: Ii1I / Ii1I % I1IiiI / OOooOOo % I1ii11iIi11i - Oo0Ooo
 if 51 - 51: OoOoOO00 + I1ii11iIi11i * iII111i * OOooOOo
 if 18 - 18: oO0o . ooOoO0o . I1IiiI
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 41 - 41: I11i % ooOoO0o + ooOoO0o + o0oOOo0O0Ooo - o0oOOo0O0Ooo % Ii1I
 oo0oO = map_request . target_eid
 iiI = map_request . target_group
 o0Oo0o = map_request . nonce
 if 52 - 52: I11i % i1IIi . I1ii11iIi11i
 if ( action == LISP_DDT_ACTION_MS_ACK ) : IiIIi = 1440
 if 62 - 62: ooOoO0o - I1ii11iIi11i
 if 71 - 71: I11i
 if 34 - 34: oO0o / O0 * oO0o
 if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
 iIi = lisp_map_referral ( )
 iIi . record_count = 1
 iIi . nonce = o0Oo0o
 Oo00oo = iIi . encode ( )
 iIi . print_map_referral ( )
 if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
 OOiiI1iii1I = False
 if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
 if 60 - 60: I1IiiI / I1IiiI / II111iiii
 if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
 if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
 if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
 if 34 - 34: I1Ii111 / i1IIi
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( oo0oO ,
 iiI )
  IiIIi = 15
  if 95 - 95: OoOoOO00 * OOooOOo
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : IiIIi = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : IiIIi = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : IiIIi = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : IiIIi = 0
 if 68 - 68: I1Ii111 / iIii1I11I1II1 % Ii1I
 OoOo0OO = False
 OOo = 0
 OoO0 = lisp_ddt_cache_lookup ( oo0oO , iiI , False )
 if ( OoO0 != None ) :
  OOo = len ( OoO0 . delegation_set )
  OoOo0OO = OoO0 . is_ms_peer_entry ( )
  OoO0 . map_referrals_sent += 1
  if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
  if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
  if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
  if 77 - 77: OOooOOo + ooOoO0o / O0
  if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : OOiiI1iii1I = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  OOiiI1iii1I = ( OoOo0OO == False )
  if 49 - 49: ooOoO0o . Ii1I
  if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
  if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
  if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
  if 4 - 4: iII111i - Oo0Ooo
 IIIOOo0o = lisp_eid_record ( )
 IIIOOo0o . rloc_count = OOo
 IIIOOo0o . authoritative = True
 IIIOOo0o . action = action
 IIIOOo0o . ddt_incomplete = OOiiI1iii1I
 IIIOOo0o . eid = eid_prefix
 IIIOOo0o . group = group_prefix
 IIIOOo0o . record_ttl = IiIIi
 if 100 - 100: OOooOOo . i1IIi
 Oo00oo += IIIOOo0o . encode ( )
 IIIOOo0o . print_record ( "  " , True )
 if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
 if 31 - 31: i1IIi . Ii1I - OoooooooOO * I11i * ooOoO0o % oO0o
 if 61 - 61: I1Ii111 . Ii1I * I1ii11iIi11i
 if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
 if ( OOo != 0 ) :
  for I1iII1iI1 in OoO0 . delegation_set :
   ooOooOo = lisp_rloc_record ( )
   ooOooOo . rloc = I1iII1iI1 . delegate_address
   ooOooOo . priority = I1iII1iI1 . priority
   ooOooOo . weight = I1iII1iI1 . weight
   ooOooOo . mpriority = 255
   ooOooOo . mweight = 0
   ooOooOo . reach_bit = True
   Oo00oo += ooOooOo . encode ( )
   ooOooOo . print_record ( "    " )
   if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
   if 13 - 13: iII111i % i1IIi
   if 13 - 13: iII111i / OoooooooOO + Ii1I / iII111i
   if 29 - 29: OOooOOo + ooOoO0o % o0oOOo0O0Ooo
   if 18 - 18: I11i + OoO0O00 + OoO0O00 . ooOoO0o
   if 37 - 37: i1IIi . IiII + I1IiiI % OoOoOO00
   if 3 - 3: i11iIiiIii + Ii1I % IiII - I1Ii111 / Oo0Ooo % iIii1I11I1II1
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , Oo00oo , ecm_source , port )
 return
 if 86 - 86: Oo0Ooo + Oo0Ooo * oO0o * I1IiiI
 if 95 - 95: IiII - OoO0O00 + OOooOOo
 if 33 - 33: o0oOOo0O0Ooo . i11iIiiIii . ooOoO0o
 if 100 - 100: i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / i11iIiiIii + OOooOOo
 if 55 - 55: i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
 if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
 if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
 if 41 - 41: I1ii11iIi11i * IiII
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # I1IiiI / OoooooooOO
 red ( dest . print_address ( ) , False ) ) )
 if 61 - 61: I1Ii111
 Oo0Oo00O000O = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 1 - 1: i11iIiiIii % I1Ii111 + I1ii11iIi11i
 if 17 - 17: Oo0Ooo
 if 59 - 59: OoO0O00 * o0oOOo0O0Ooo . I11i
 if 32 - 32: I1ii11iIi11i
 if 44 - 44: i1IIi * OoO0O00
 if ( lisp_get_eid_hash ( eid ) != None ) :
  Oo0Oo00O000O = LISP_SEND_MAP_REQUEST_ACTION
  if 21 - 21: Oo0Ooo - II111iiii + I11i
  if 69 - 69: Oo0Ooo - iIii1I11I1II1 . oO0o
 Oo00oo = lisp_build_map_reply ( eid , group , [ ] , nonce , Oo0Oo00O000O , ttl , None ,
 None , False , False )
 if 54 - 54: Ii1I / Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
 if 85 - 85: iII111i % i11iIiiIii
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , Oo00oo , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , Oo00oo , dest , port )
  if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 return
 if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 if 41 - 41: Ii1I + IiII
 if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
 if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
 if 99 - 99: i1IIi * OoOoOO00 - i1IIi
 if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
 if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
def lisp_retransmit_ddt_map_request ( mr ) :
 O00oOoo0OoOOO = mr . mr_source . print_address ( )
 I1IiIiI111 = mr . print_eid_tuple ( )
 o0Oo0o = mr . nonce
 if 45 - 45: I1ii11iIi11i - I11i
 if 60 - 60: OOooOOo - OOooOOo * OoOoOO00 / Ii1I % iII111i % Oo0Ooo
 if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
 if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
 if 61 - 61: iIii1I11I1II1 . Oo0Ooo . i1IIi
 if ( mr . last_request_sent_to ) :
  iI11iI11i11ii = mr . last_request_sent_to . print_address ( )
  i1OOOoO0O0O0O = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( i1OOOoO0O0O0O and iI11iI11i11ii in i1OOOoO0O0O0O . referral_set ) :
   i1OOOoO0O0O0O . referral_set [ iI11iI11i11ii ] . no_responses += 1
   if 13 - 13: Oo0Ooo / OoO0O00 + I1Ii111
   if 48 - 48: I1ii11iIi11i * i1IIi + I1Ii111
   if 80 - 80: I1IiiI % I11i
   if 64 - 64: OOooOOo + i11iIiiIii + I1IiiI . I11i % I11i - o0oOOo0O0Ooo
   if 3 - 3: I1IiiI / i1IIi + II111iiii + Oo0Ooo
   if 48 - 48: o0oOOo0O0Ooo
   if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( I1IiIiI111 , False ) , lisp_hex_string ( o0Oo0o ) ) )
  if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
  mr . dequeue_map_request ( )
  return
  if 66 - 66: i11iIiiIii
  if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
 mr . retry_count += 1
 if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
 I111 = green ( O00oOoo0OoOOO , False )
 IiI11I111 = green ( I1IiIiI111 , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # I1Ii111 * OOooOOo / i1IIi / iIii1I11I1II1 / OoooooooOO
 red ( mr . itr . print_address ( ) , False ) , I111 , IiI11I111 ,
 lisp_hex_string ( o0Oo0o ) ) )
 if 37 - 37: O0 * I11i . O0 / II111iiii % oO0o
 if 19 - 19: Ii1I - oO0o
 if 72 - 72: oO0o / I11i % II111iiii
 if 22 - 22: i11iIiiIii % IiII % IiII % I11i - OoooooooOO + I1IiiI
 lisp_send_ddt_map_request ( mr , False )
 if 31 - 31: I11i + I1ii11iIi11i . i1IIi * i11iIiiIii + I1ii11iIi11i
 if 97 - 97: ooOoO0o * iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - o0oOOo0O0Ooo
 if 37 - 37: II111iiii
 if 27 - 27: Oo0Ooo * OoooooooOO / I1IiiI
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 43 - 43: OoO0O00
 if 51 - 51: OoooooooOO % IiII % Oo0Ooo
 if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
 if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
 if 95 - 95: iII111i
 if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
 if 19 - 19: OOooOOo * o0oOOo0O0Ooo
 if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 80 - 80: i1IIi
 if 74 - 74: I1ii11iIi11i . OoO0O00 + i11iIiiIii
 if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
 if 68 - 68: iII111i
 Ii1i1 = [ ]
 for iiiIii in list ( referral . referral_set . values ( ) ) :
  if ( iiiIii . updown == False ) : continue
  if ( len ( Ii1i1 ) == 0 or Ii1i1 [ 0 ] . priority == iiiIii . priority ) :
   Ii1i1 . append ( iiiIii )
  elif ( Ii1i1 [ 0 ] . priority > iiiIii . priority ) :
   Ii1i1 = [ ]
   Ii1i1 . append ( iiiIii )
   if 82 - 82: O0 . I1Ii111 - IiII
   if 37 - 37: i11iIiiIii
   if 67 - 67: ooOoO0o . Oo0Ooo
 iIOo000OOo = len ( Ii1i1 )
 if ( iIOo000OOo == 0 ) : return ( None )
 if 19 - 19: OoooooooOO % oO0o
 II1Iii1iI = dest_eid . hash_address ( source_eid )
 II1Iii1iI = II1Iii1iI % iIOo000OOo
 return ( Ii1i1 [ II1Iii1iI ] )
 if 49 - 49: i1IIi % OoooooooOO + OoooooooOO / OoO0O00 + OoO0O00 * II111iiii
 if 89 - 89: o0oOOo0O0Ooo - oO0o . II111iiii
 if 39 - 39: OoOoOO00 - OOooOOo / II111iiii * OoooooooOO - OoO0O00 . I1IiiI
 if 89 - 89: IiII
 if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
 if 19 - 19: I1Ii111 + I11i
 if 21 - 21: OoOoOO00
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 iioO0O = mr . lisp_sockets
 o0Oo0o = mr . nonce
 OOooOooOOoO0O = mr . itr
 oOIII = mr . mr_source
 i1iiii = mr . print_eid_tuple ( )
 if 87 - 87: o0oOOo0O0Ooo / I1Ii111 % Oo0Ooo - iIii1I11I1II1 / IiII / IiII
 if 57 - 57: OoOoOO00 . O0 / iII111i / i11iIiiIii
 if 38 - 38: iII111i - Oo0Ooo / O0
 if 40 - 40: ooOoO0o + iIii1I11I1II1 / OoOoOO00 * iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
 if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( i1iiii , False ) , lisp_hex_string ( o0Oo0o ) ) )
  if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
  mr . dequeue_map_request ( )
  return
  if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
  if 5 - 5: OoooooooOO + ooOoO0o - II111iiii . i11iIiiIii / oO0o - ooOoO0o
  if 3 - 3: iII111i
  if 74 - 74: i11iIiiIii + OoooooooOO . OOooOOo
  if 29 - 29: IiII % OoO0O00
  if 53 - 53: OoooooooOO - OoOoOO00 / IiII - I1Ii111
 if ( send_to_root ) :
  IiI1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  ooO00O0oOO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( i1iiii , False ) ) )
 else :
  IiI1 = mr . eid
  ooO00O0oOO = mr . group
  if 41 - 41: OoOoOO00 - O0
  if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
  if 53 - 53: ooOoO0o + oO0o - II111iiii
  if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
  if 6 - 6: iIii1I11I1II1 + oO0o
 iIIiii = lisp_referral_cache_lookup ( IiI1 , ooO00O0oOO , False )
 if ( iIIiii == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( iioO0O , IiI1 , ooO00O0oOO ,
 o0Oo0o , OOooOooOOoO0O , mr . sport , 15 , None , False )
  return
  if 76 - 76: II111iiii - O0 . O0 + OoooooooOO - I1Ii111
  if 21 - 21: OoO0O00 * ooOoO0o
 oo00oO0ooo = iIIiii . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( oo00oO0ooo ,
 iIIiii . print_referral_type ( ) ) )
 if 6 - 6: iIii1I11I1II1 . O0 . oO0o + I1ii11iIi11i
 iiiIii = lisp_get_referral_node ( iIIiii , oOIII , mr . eid )
 if ( iiiIii == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( iioO0O , iIIiii . eid ,
 iIIiii . group , o0Oo0o , OOooOooOOoO0O , mr . sport , 1 , None , False )
  return
  if 32 - 32: I1IiiI / OOooOOo . i11iIiiIii - IiII . iII111i . Ii1I
  if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( iiiIii . referral_address . print_address ( ) ,
 # i1IIi / OoooooooOO * OoooooooOO
 iIIiii . print_referral_type ( ) , green ( i1iiii , False ) ,
 lisp_hex_string ( o0Oo0o ) ) )
 if 93 - 93: OoOoOO00 % Oo0Ooo . OoO0O00 / OoooooooOO
 if 59 - 59: OoO0O00 + O0 + i11iIiiIii / OoOoOO00 + iIii1I11I1II1 / OoOoOO00
 if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
 if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
 o0oo0 = ( iIIiii . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 iIIiii . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( iioO0O , mr . packet , oOIII , mr . sport , mr . eid ,
 iiiIii . referral_address , to_ms = o0oo0 , ddt = True )
 if 32 - 32: OoO0O00 / I1Ii111 / I1Ii111
 if 45 - 45: iII111i + O0 % i11iIiiIii * I1ii11iIi11i + I1Ii111 / OOooOOo
 if 55 - 55: OoooooooOO % iIii1I11I1II1 . ooOoO0o
 if 10 - 10: O0 * iIii1I11I1II1 . OOooOOo
 mr . last_request_sent_to = iiiIii . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 iiiIii . map_requests_sent += 1
 return
 if 4 - 4: iIii1I11I1II1
 if 22 - 22: ooOoO0o . oO0o
 if 65 - 65: i1IIi . I1ii11iIi11i / Oo0Ooo
 if 84 - 84: I1ii11iIi11i . OOooOOo
 if 86 - 86: II111iiii * Oo0Ooo . IiII . iII111i + II111iiii . iIii1I11I1II1
 if 88 - 88: OoooooooOO % ooOoO0o
 if 71 - 71: II111iiii * I1IiiI * Oo0Ooo / II111iiii + iIii1I11I1II1 % i1IIi
 if 85 - 85: IiII * O0 . I1Ii111 . II111iiii
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 6 - 6: I1ii11iIi11i * oO0o + iIii1I11I1II1 + II111iiii
 oo0oO = map_request . target_eid
 iiI = map_request . target_group
 I1IiIiI111 = map_request . print_eid_tuple ( )
 O00oOoo0OoOOO = mr_source . print_address ( )
 o0Oo0o = map_request . nonce
 if 69 - 69: iII111i . OoO0O00 + I1IiiI
 I111 = green ( O00oOoo0OoOOO , False )
 IiI11I111 = green ( I1IiIiI111 , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # I1Ii111 / II111iiii % i11iIiiIii % I1IiiI . iII111i
 red ( ecm_source . print_address ( ) , False ) , I111 , IiI11I111 ,
 lisp_hex_string ( o0Oo0o ) ) )
 if 11 - 11: ooOoO0o / iIii1I11I1II1 * OOooOOo / I11i - Ii1I
 if 64 - 64: OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - OOooOOo - I1IiiI
 if 75 - 75: I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 . OOooOOo
 OO0ooo000 = lisp_ddt_map_request ( lisp_sockets , packet , oo0oO , iiI , o0Oo0o )
 OO0ooo000 . packet = packet
 OO0ooo000 . itr = ecm_source
 OO0ooo000 . mr_source = mr_source
 OO0ooo000 . sport = sport
 OO0ooo000 . from_pitr = map_request . pitr_bit
 OO0ooo000 . queue_map_request ( )
 if 47 - 47: i11iIiiIii - o0oOOo0O0Ooo - Oo0Ooo
 lisp_send_ddt_map_request ( OO0ooo000 , False )
 return
 if 84 - 84: OOooOOo / OoOoOO00 * IiII
 if 5 - 5: i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + oO0o + I11i
 if 36 - 36: Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
 if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
 if 40 - 40: oO0o * IiII
 if 29 - 29: O0 - II111iiii + iII111i
 if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
 O0OOOOO0O = packet
 oooO = lisp_map_request ( )
 packet = oooO . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 14 - 14: OOooOOo
  if 84 - 84: Ii1I + OoO0O00 + OOooOOo % ooOoO0o
 oooO . print_map_request ( )
 if 27 - 27: OoOoOO00 % I11i
 if 19 - 19: i1IIi - OoOoOO00
 if 26 - 26: IiII . i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / o0oOOo0O0Ooo
 if 7 - 7: I1IiiI / OOooOOo * iIii1I11I1II1 * Ii1I * i1IIi
 if ( oooO . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , oooO , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 87 - 87: IiII * Oo0Ooo - OOooOOo * OoOoOO00
  if 61 - 61: Oo0Ooo - OoooooooOO % I1ii11iIi11i / i1IIi + O0 % ooOoO0o
  if 79 - 79: I1ii11iIi11i
  if 9 - 9: IiII . O0
  if 66 - 66: i11iIiiIii
 if ( oooO . smr_bit ) :
  lisp_process_smr ( oooO )
  if 33 - 33: i11iIiiIii % OoO0O00 * I1ii11iIi11i
  if 96 - 96: I11i % OoooooooOO * I11i . IiII / I1Ii111
  if 56 - 56: I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
  if 84 - 84: OoOoOO00
  if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
 if ( oooO . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( oooO )
  if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
  if 85 - 85: o0oOOo0O0Ooo % Ii1I
  if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
  if 23 - 23: II111iiii . II111iiii
  if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , oooO , mr_source ,
 mr_port , ttl , timestamp )
  if 21 - 21: OOooOOo % Ii1I
  if 3 - 3: OOooOOo / ooOoO0o / I1Ii111 . I11i
  if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
  if 36 - 36: OoO0O00 * I1IiiI / iII111i
  if 95 - 95: Ii1I . Oo0Ooo
 if ( lisp_i_am_ms ) :
  packet = O0OOOOO0O
  oo0oO , iiI , I1ooO00000OOoO = lisp_ms_process_map_request ( lisp_sockets ,
 O0OOOOO0O , oooO , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , oooO , ecm_source ,
 ecm_port , I1ooO00000OOoO , oo0oO , iiI )
   if 50 - 50: II111iiii * OoOoOO00 . ooOoO0o - I1Ii111 . OoOoOO00
  return
  if 64 - 64: iII111i + I1ii11iIi11i
  if 88 - 88: I1Ii111 / i11iIiiIii - O0 . II111iiii / II111iiii * II111iiii
  if 56 - 56: Oo0Ooo / I1IiiI % I1Ii111 % I1ii11iIi11i * I1IiiI - IiII
  if 39 - 39: oO0o + iII111i . I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + OOooOOo
  if 61 - 61: ooOoO0o / I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * iII111i
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , O0OOOOO0O , oooO ,
 ecm_source , mr_port , mr_source )
  if 94 - 94: I1IiiI / I11i
  if 100 - 100: Ii1I % OoO0O00 % OoooooooOO / II111iiii * I1Ii111
  if 64 - 64: I1Ii111 * OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / Oo0Ooo
  if 50 - 50: OOooOOo % i11iIiiIii
  if 99 - 99: IiII
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = O0OOOOO0O
  lisp_ddt_process_map_request ( lisp_sockets , oooO , ecm_source ,
 ecm_port )
  if 87 - 87: IiII
 return
 if 35 - 35: oO0o . O0 . Ii1I / ooOoO0o
 if 36 - 36: i11iIiiIii . II111iiii . I11i . II111iiii
 if 36 - 36: Ii1I + ooOoO0o / Oo0Ooo % Oo0Ooo
 if 2 - 2: oO0o - Oo0Ooo * OoO0O00 . ooOoO0o . OOooOOo - oO0o
 if 74 - 74: o0oOOo0O0Ooo
 if 18 - 18: Oo0Ooo % OOooOOo / OOooOOo . I1IiiI + i1IIi . I1IiiI
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
def lisp_store_mr_stats ( source , nonce ) :
 OO0ooo000 = lisp_get_map_resolver ( source , None )
 if ( OO0ooo000 == None ) : return
 if 6 - 6: O0 * I1Ii111 - II111iiii
 if 60 - 60: oO0o % oO0o
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
 OO0ooo000 . neg_map_replies_received += 1
 OO0ooo000 . last_reply = lisp_get_timestamp ( )
 if 82 - 82: I1ii11iIi11i
 if 75 - 75: I11i - II111iiii
 if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
 if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
 if ( ( OO0ooo000 . neg_map_replies_received % 100 ) == 0 ) : OO0ooo000 . total_rtt = 0
 if 76 - 76: OOooOOo - iII111i + IiII
 if 48 - 48: I1IiiI - II111iiii
 if 15 - 15: O0
 if 54 - 54: iIii1I11I1II1
 if ( OO0ooo000 . last_nonce == nonce ) :
  OO0ooo000 . total_rtt += ( time . time ( ) - OO0ooo000 . last_used )
  OO0ooo000 . last_nonce = 0
  if 54 - 54: iII111i + OOooOOo + OoO0O00
 if ( ( OO0ooo000 . neg_map_replies_received % 10 ) == 0 ) : OO0ooo000 . last_nonce = 0
 return
 if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
 if 65 - 65: IiII + OoOoOO00
 if 93 - 93: Ii1I
 if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
 if 5 - 5: OoO0O00 / ooOoO0o
 if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
 if 97 - 97: oO0o / Ii1I
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 ooOooOooO00 = lisp_map_reply ( )
 packet = ooOooOooO00 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 ooOooOooO00 . print_map_reply ( )
 if 91 - 91: IiII * Ii1I * OOooOOo
 if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
 if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
 OoOO0O = None
 for iIi1iIIIiIiI in range ( ooOooOooO00 . record_count ) :
  IIIOOo0o = lisp_eid_record ( )
  packet = IIIOOo0o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 53 - 53: OoOoOO00
  IIIOOo0o . print_record ( "  " , False )
  if 43 - 43: I1ii11iIi11i * Oo0Ooo
  if 95 - 95: IiII + iII111i % I1IiiI
  if 18 - 18: Oo0Ooo
  if 8 - 8: O0 + iIii1I11I1II1 - O0
  if 67 - 67: O0
  if ( IIIOOo0o . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , ooOooOooO00 . nonce )
   if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
   if 28 - 28: O0 - Oo0Ooo
  Ooo0 = ( IIIOOo0o . group . is_null ( ) == False )
  if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
  if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
  if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
  if 99 - 99: Oo0Ooo - OoO0O00 + OoooooooOO - I1Ii111 - I1ii11iIi11i % i1IIi
  if 49 - 49: IiII % OoooooooOO / Oo0Ooo - OoOoOO00 + o0oOOo0O0Ooo / Ii1I
  if ( lisp_decent_push_configured ) :
   Oo0Oo00O000O = IIIOOo0o . action
   if ( Ooo0 and Oo0Oo00O000O == LISP_DROP_ACTION ) :
    if ( IIIOOo0o . eid . is_local ( ) ) : continue
    if 6 - 6: I11i % IiII
    if 48 - 48: Ii1I
    if 100 - 100: OoO0O00 % I1Ii111 + OoooooooOO / OoO0O00
    if 62 - 62: IiII
    if 66 - 66: o0oOOo0O0Ooo % OOooOOo
    if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
    if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
  if ( Ooo0 == False and IIIOOo0o . eid . is_null ( ) ) : continue
  if 62 - 62: i11iIiiIii
  if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
  if 6 - 6: i11iIiiIii
  if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
  if 53 - 53: oO0o
  if ( Ooo0 ) :
   iIIiiiiI11i = lisp_map_cache_lookup ( IIIOOo0o . eid , IIIOOo0o . group )
  else :
   iIIiiiiI11i = lisp_map_cache . lookup_cache ( IIIOOo0o . eid , True )
   if 22 - 22: i11iIiiIii
  oOOo0O000 = ( iIIiiiiI11i == None )
  if 1 - 1: I11i % ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
  if 88 - 88: IiII
  if 29 - 29: iII111i . ooOoO0o
  if 62 - 62: IiII
  if 95 - 95: ooOoO0o / i1IIi + II111iiii + OoO0O00 % OoO0O00
  if ( iIIiiiiI11i == None ) :
   I1iI111i11i1 , I1iIiiI1IIi1 , II1ii1 = lisp_allow_gleaning ( IIIOOo0o . eid , IIIOOo0o . group ,
 None )
   if ( I1iI111i11i1 ) : continue
  else :
   if ( iIIiiiiI11i . gleaned ) : continue
   if 96 - 96: I1IiiI . O0 / iIii1I11I1II1
   if 95 - 95: ooOoO0o * OoO0O00 % OoooooooOO % OoO0O00
   if 79 - 79: II111iiii % Ii1I * oO0o * iII111i + II111iiii
   if 51 - 51: I1IiiI + iII111i + I1IiiI / Ii1I * IiII + OOooOOo
   if 70 - 70: I11i . IiII + IiII
  oOO000OOO = [ ]
  oooO0oo0ooO = None
  for oooOO0oooo00 in range ( IIIOOo0o . rloc_count ) :
   ooOooOo = lisp_rloc_record ( )
   ooOooOo . keys = ooOooOooO00 . keys
   packet = ooOooOo . decode ( packet , ooOooOooO00 . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 28 - 28: ooOoO0o
   ooOooOo . print_record ( "    " )
   if 27 - 27: OoO0O00
   o00o0o0O = None
   if ( iIIiiiiI11i ) : o00o0o0O = iIIiiiiI11i . get_rloc ( ooOooOo . rloc )
   if ( o00o0o0O ) :
    IIIi1iI1 = o00o0o0O
   else :
    IIIi1iI1 = lisp_rloc ( )
    if 98 - 98: II111iiii + ooOoO0o - iIii1I11I1II1 . I11i . iIii1I11I1II1 - iIii1I11I1II1
    if 91 - 91: ooOoO0o
    if 66 - 66: OOooOOo
    if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
    if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
    if 9 - 9: Ii1I
    if 44 - 44: iII111i
   ooO0 = IIIi1iI1 . store_rloc_from_record ( ooOooOo , ooOooOooO00 . nonce ,
 source )
   IIIi1iI1 . echo_nonce_capable = ooOooOooO00 . echo_nonce_capable
   if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
   if ( IIIi1iI1 . echo_nonce_capable ) :
    O0O0 = IIIi1iI1 . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , O0O0 ) == None ) :
     lisp_echo_nonce ( O0O0 )
     if 37 - 37: OoO0O00 - Ii1I + OoO0O00
     if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
     if 60 - 60: Oo0Ooo
     if 46 - 46: OoOoOO00 + i1IIi
     if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
     if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
   if ( IIIi1iI1 . json ) :
    if ( lisp_is_json_telemetry ( IIIi1iI1 . json . json_string ) ) :
     iiIII1 = IIIi1iI1 . json . json_string
     iiIII1 = lisp_encode_telemetry ( iiIII1 , ii = itr_in_ts )
     IIIi1iI1 . json . json_string = iiIII1
     if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
     if 4 - 4: OoO0O00
     if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
     if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
     if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
     if 38 - 38: iII111i * OoooooooOO - IiII
     if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
     if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
     if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
     if 76 - 76: I11i . I1IiiI
   if ( ooOooOooO00 . rloc_probe and ooOooOo . probe_bit ) :
    if ( IIIi1iI1 . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( IIIi1iI1 , source , ooO0 ,
 ooOooOooO00 , ttl , oooO0oo0ooO )
     if 66 - 66: oO0o % oO0o * IiII
    if ( IIIi1iI1 . rloc . is_multicast_address ( ) ) : oooO0oo0ooO = IIIi1iI1
    if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
    if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
    if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
    if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
    if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
   oOO000OOO . append ( IIIi1iI1 )
   if 23 - 23: OOooOOo
   if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
   if 47 - 47: OoO0O00
   if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
   if ( lisp_data_plane_security and IIIi1iI1 . rloc_recent_rekey ( ) ) :
    OoOO0O = IIIi1iI1
    if 9 - 9: I11i
    if 83 - 83: i11iIiiIii
    if 72 - 72: oO0o + II111iiii . O0 * oO0o + iII111i
    if 22 - 22: I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
    if 84 - 84: OoooooooOO - Oo0Ooo
    if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
    if 82 - 82: OoOoOO00
    if 61 - 61: oO0o . o0oOOo0O0Ooo
    if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
    if 70 - 70: I1IiiI
    if 74 - 74: ooOoO0o * II111iiii
  if ( ooOooOooO00 . rloc_probe == False and lisp_nat_traversal ) :
   iii1I11I1II1I1I1i = [ ]
   OoOi111i = [ ]
   for IIIi1iI1 in oOO000OOO :
    if 45 - 45: OoO0O00 + ooOoO0o / iIii1I11I1II1 % i11iIiiIii
    if 16 - 16: i1IIi / oO0o - OOooOOo / Ii1I + I1IiiI
    if 62 - 62: i11iIiiIii . Ii1I . iII111i / I1Ii111 * OoO0O00
    if 31 - 31: OoOoOO00
    if 16 - 16: OoooooooOO
    if ( IIIi1iI1 . rloc . is_private_address ( ) ) :
     IIIi1iI1 . priority = 1
     IIIi1iI1 . state = LISP_RLOC_UNREACH_STATE
     iii1I11I1II1I1I1i . append ( IIIi1iI1 )
     OoOi111i . append ( IIIi1iI1 . rloc . print_address_no_iid ( ) )
     continue
     if 32 - 32: ooOoO0o - o0oOOo0O0Ooo / ooOoO0o + o0oOOo0O0Ooo + iII111i
     if 78 - 78: OoooooooOO . I1ii11iIi11i * oO0o . o0oOOo0O0Ooo * OoOoOO00 / oO0o
     if 47 - 47: OOooOOo
     if 40 - 40: I1ii11iIi11i
     if 67 - 67: I1Ii111 - OoO0O00 * ooOoO0o - oO0o / OoO0O00 . I1Ii111
     if 39 - 39: Ii1I
    if ( IIIi1iI1 . priority == 254 and lisp_i_am_rtr == False ) :
     iii1I11I1II1I1I1i . append ( IIIi1iI1 )
     OoOi111i . append ( IIIi1iI1 . rloc . print_address_no_iid ( ) )
     if 90 - 90: I1Ii111 - I1Ii111 . i11iIiiIii + OoooooooOO % OOooOOo / Oo0Ooo
    if ( IIIi1iI1 . priority != 254 and lisp_i_am_rtr ) :
     iii1I11I1II1I1I1i . append ( IIIi1iI1 )
     OoOi111i . append ( IIIi1iI1 . rloc . print_address_no_iid ( ) )
     if 51 - 51: o0oOOo0O0Ooo
     if 8 - 8: oO0o . oO0o . Ii1I
     if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
   if ( OoOi111i != [ ] ) :
    oOO000OOO = iii1I11I1II1I1I1i
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( OoOi111i ) )
    if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
    if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
    if 10 - 10: ooOoO0o
    if 69 - 69: I11i + I1IiiI / oO0o
    if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
    if 85 - 85: I1Ii111 - oO0o
    if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
  iii1I11I1II1I1I1i = [ ]
  for IIIi1iI1 in oOO000OOO :
   if ( IIIi1iI1 . json != None ) : continue
   iii1I11I1II1I1I1i . append ( IIIi1iI1 )
   if 96 - 96: oO0o
  if ( iii1I11I1II1I1I1i != [ ] ) :
   O0oo0oOo = len ( oOO000OOO ) - len ( iii1I11I1II1I1I1i )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( O0oo0oOo ) )
   if 44 - 44: OoooooooOO / iII111i * Oo0Ooo % OoOoOO00 . oO0o
   oOO000OOO = iii1I11I1II1I1I1i
   if 97 - 97: iIii1I11I1II1 / ooOoO0o
   if 16 - 16: Oo0Ooo % IiII
   if 48 - 48: I1IiiI . I1Ii111 . o0oOOo0O0Ooo
   if 72 - 72: Ii1I * OoO0O00 / OoO0O00
   if 39 - 39: oO0o
   if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
   if 57 - 57: oO0o + O0 - OoOoOO00
   if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
  if ( ooOooOooO00 . rloc_probe and iIIiiiiI11i != None ) : oOO000OOO = iIIiiiiI11i . rloc_set
  if 93 - 93: o0oOOo0O0Ooo + i1IIi
  if 24 - 24: i1IIi
  if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
  if 99 - 99: Oo0Ooo
  if 38 - 38: I1ii11iIi11i - I1IiiI
  I1IIIIiIii = oOOo0O000
  if ( iIIiiiiI11i and oOO000OOO != iIIiiiiI11i . rloc_set ) :
   iIIiiiiI11i . delete_rlocs_from_rloc_probe_list ( )
   I1IIIIiIii = True
   if 83 - 83: Oo0Ooo / I1ii11iIi11i % OoO0O00
   if 29 - 29: IiII - I1ii11iIi11i . Oo0Ooo + IiII - I1IiiI
   if 95 - 95: O0 / o0oOOo0O0Ooo + OoO0O00 / IiII - IiII % OOooOOo
   if 16 - 16: I1IiiI * iIii1I11I1II1 % o0oOOo0O0Ooo - IiII - OOooOOo
   if 83 - 83: Ii1I
  iI1I1iII1I111 = iIIiiiiI11i . uptime if ( iIIiiiiI11i ) else None
  if ( iIIiiiiI11i == None ) :
   iIIiiiiI11i = lisp_mapping ( IIIOOo0o . eid , IIIOOo0o . group , oOO000OOO )
   iIIiiiiI11i . mapping_source = source
   if 10 - 10: oO0o / ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
   if 26 - 26: I1IiiI - OOooOOo
   if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
   if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
   if 50 - 50: OoooooooOO * II111iiii
   if 7 - 7: ooOoO0o / I11i * iII111i
   if ( lisp_i_am_rtr and IIIOOo0o . group . is_null ( ) == False ) :
    iIIiiiiI11i . map_cache_ttl = LISP_MCAST_TTL
   else :
    iIIiiiiI11i . map_cache_ttl = IIIOOo0o . store_ttl ( )
    if 17 - 17: O0 % I1Ii111
   iIIiiiiI11i . action = IIIOOo0o . action
   iIIiiiiI11i . add_cache ( I1IIIIiIii )
   if 28 - 28: i1IIi * ooOoO0o
   if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
  oo0o0OOoO = "Add"
  if ( iI1I1iII1I111 ) :
   iIIiiiiI11i . uptime = iI1I1iII1I111
   iIIiiiiI11i . refresh_time = lisp_get_timestamp ( )
   oo0o0OOoO = "Replace"
   if 40 - 40: OoooooooOO - IiII
   if 74 - 74: II111iiii - i11iIiiIii - IiII + OOooOOo
  lprint ( "{} {} map-cache with {} RLOCs" . format ( oo0o0OOoO ,
 green ( iIIiiiiI11i . print_eid_tuple ( ) , False ) , len ( oOO000OOO ) ) )
  if 8 - 8: I1ii11iIi11i
  if 56 - 56: o0oOOo0O0Ooo / I1ii11iIi11i
  if 25 - 25: iIii1I11I1II1 / OoO0O00 - o0oOOo0O0Ooo
  if 97 - 97: ooOoO0o % OoooooooOO * o0oOOo0O0Ooo
  if 8 - 8: I1ii11iIi11i + Oo0Ooo - iII111i
  if ( lisp_ipc_dp_socket and OoOO0O != None ) :
   lisp_write_ipc_keys ( OoOO0O )
   if 53 - 53: ooOoO0o / IiII
   if 36 - 36: iIii1I11I1II1
   if 78 - 78: II111iiii * I11i
   if 47 - 47: Ii1I
   if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
   if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
   if 53 - 53: iIii1I11I1II1
  if ( oOOo0O000 ) :
   iiIii11Ii = bold ( "RLOC-probe" , False )
   for IIIi1iI1 in iIIiiiiI11i . best_rloc_set :
    O0O0 = red ( IIIi1iI1 . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( iiIii11Ii , O0O0 ) )
    lisp_send_map_request ( lisp_sockets , 0 , iIIiiiiI11i . eid , iIIiiiiI11i . group , IIIi1iI1 )
    if 47 - 47: O0 . OoO0O00 * I1Ii111 - oO0o % Oo0Ooo * i1IIi
    if 45 - 45: OOooOOo / Ii1I
    if 99 - 99: I1IiiI
 return
 if 16 - 16: o0oOOo0O0Ooo + OoOoOO00 / oO0o + iII111i % oO0o / o0oOOo0O0Ooo
 if 50 - 50: OOooOOo % oO0o
 if 63 - 63: I1ii11iIi11i / o0oOOo0O0Ooo . II111iiii + iII111i * i1IIi - o0oOOo0O0Ooo
 if 37 - 37: OoooooooOO * iII111i . i11iIiiIii % I1Ii111 + oO0o . I1ii11iIi11i
 if 17 - 17: iII111i + ooOoO0o % Oo0Ooo * i1IIi / O0 * oO0o
 if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
 if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
 if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 88 - 88: i11iIiiIii
 packet = map_register . zero_auth ( packet )
 II1Iii1iI = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 13 - 13: I1IiiI
 if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
 if 84 - 84: OoooooooOO - oO0o - I1Ii111
 if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
 map_register . auth_data = II1Iii1iI
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 20 - 20: IiII
 if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
 if 66 - 66: OoooooooOO + IiII . II111iiii
 if 66 - 66: iIii1I11I1II1 % I11i
 if 38 - 38: I1ii11iIi11i * ooOoO0o
 if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
 if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 65 - 65: OOooOOo
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  o00oO0OOo0O = hashlib . sha1
  if 43 - 43: iII111i - OOooOOo % ooOoO0o % O0 % II111iiii / i11iIiiIii
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  o00oO0OOo0O = hashlib . sha256
  if 9 - 9: Oo0Ooo + OOooOOo + OoO0O00 + Ii1I - Oo0Ooo * OoOoOO00
  if 20 - 20: oO0o
 if ( do_hex ) :
  II1Iii1iI = hmac . new ( password . encode ( ) , packet , o00oO0OOo0O ) . hexdigest ( )
 else :
  II1Iii1iI = hmac . new ( password . encode ( ) , packet , o00oO0OOo0O ) . digest ( )
  if 48 - 48: I1IiiI % OoO0O00
 return ( II1Iii1iI )
 if 33 - 33: Ii1I
 if 73 - 73: Ii1I . IiII
 if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
 if 90 - 90: i11iIiiIii * i1IIi
 if 88 - 88: i11iIiiIii - OoOoOO00
 if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
 if 6 - 6: iII111i
 if 44 - 44: oO0o
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 23 - 23: I1IiiI + iIii1I11I1II1 . iII111i + OOooOOo - OoO0O00 + i1IIi
 II1Iii1iI = lisp_hash_me ( packet , alg_id , password , True )
 Oo0OoO = ( II1Iii1iI == auth_data )
 if 62 - 62: iIii1I11I1II1 * o0oOOo0O0Ooo * OOooOOo . o0oOOo0O0Ooo + I11i
 if 46 - 46: o0oOOo0O0Ooo - i1IIi / OoO0O00 + o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 * o0oOOo0O0Ooo / i1IIi * I1Ii111 * I1ii11iIi11i
 if 45 - 45: iII111i / Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
 if ( Oo0OoO == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( II1Iii1iI , auth_data ) )
  if 66 - 66: I1IiiI
  if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
 return ( Oo0OoO )
 if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
 if 22 - 22: I1Ii111
 if 41 - 41: O0 * i1IIi
 if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
 if 5 - 5: I1ii11iIi11i / I1IiiI . iII111i
 if 7 - 7: Ii1I
 if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
def lisp_retransmit_map_notify ( map_notify ) :
 IIi11ii = map_notify . etr
 ooO0 = map_notify . etr_port
 if 63 - 63: OOooOOo + iII111i - IiII - I1IiiI % IiII . OoO0O00
 if 73 - 73: OoOoOO00
 if 47 - 47: oO0o
 if 17 - 17: IiII
 if 47 - 47: I11i . I1IiiI % ooOoO0o . i11iIiiIii
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( IIi11ii . print_address ( ) , False ) ) )
  if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
  if 100 - 100: O0
  III = map_notify . nonce_key
  if ( III in lisp_map_notify_queue ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( III ) )
   if 9 - 9: Ii1I
   try :
    lisp_map_notify_queue . pop ( III )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 87 - 87: I1IiiI
    if 56 - 56: OOooOOo % oO0o - OoOoOO00
  return
  if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
  if 81 - 81: oO0o / iIii1I11I1II1
 iioO0O = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 15 - 15: Ii1I + I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # II111iiii % Ii1I
 red ( IIi11ii . print_address ( ) , False ) , map_notify . retry_count ) )
 if 10 - 10: iIii1I11I1II1 . I1IiiI - II111iiii + O0
 lisp_send_map_notify ( iioO0O , map_notify . packet , IIi11ii , ooO0 )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 97 - 97: oO0o . Oo0Ooo % ooOoO0o + I1Ii111 . i11iIiiIii + Ii1I
 if 61 - 61: IiII + iII111i
 if 15 - 15: II111iiii / iIii1I11I1II1 / I1ii11iIi11i % OoOoOO00 % OoO0O00 - I1Ii111
 if 17 - 17: OoooooooOO
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 23 - 23: OoO0O00
 if 26 - 26: I11i % IiII . OoooooooOO % i11iIiiIii * IiII
 if 55 - 55: I11i / I11i - IiII - I11i
 if 3 - 3: oO0o % o0oOOo0O0Ooo + OoOoOO00
 if 22 - 22: O0
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
 for OOOo in parent . registered_rlocs :
  ooOooOo = lisp_rloc_record ( )
  ooOooOo . store_rloc_entry ( OOOo )
  ooOooOo . local_bit = True
  ooOooOo . probe_bit = False
  ooOooOo . reach_bit = True
  IiI1I1 += ooOooOo . encode ( )
  ooOooOo . print_record ( "  " )
  del ( ooOooOo )
  if 39 - 39: I11i / O0 - I1ii11iIi11i . Oo0Ooo * OoooooooOO / o0oOOo0O0Ooo
  if 71 - 71: O0 . OoooooooOO + Oo0Ooo . ooOoO0o / Ii1I
  if 92 - 92: I1ii11iIi11i . oO0o
  if 8 - 8: o0oOOo0O0Ooo / oO0o
  if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 for OOOo in parent . registered_rlocs :
  IIi11ii = OOOo . rloc
  ii11i1IiI = lisp_map_notify ( lisp_sockets )
  ii11i1IiI . record_count = 1
  IiII11iI1 = map_register . key_id
  ii11i1IiI . key_id = IiII11iI1
  ii11i1IiI . alg_id = map_register . alg_id
  ii11i1IiI . auth_len = map_register . auth_len
  ii11i1IiI . nonce = map_register . nonce
  ii11i1IiI . nonce_key = lisp_hex_string ( ii11i1IiI . nonce )
  ii11i1IiI . etr . copy_address ( IIi11ii )
  ii11i1IiI . etr_port = map_register . sport
  ii11i1IiI . site = parent . site
  Oo00oo = ii11i1IiI . encode ( IiI1I1 , parent . site . auth_key [ IiII11iI1 ] )
  ii11i1IiI . print_notify ( )
  if 99 - 99: Ii1I / iII111i / Ii1I + iII111i
  if 18 - 18: OoOoOO00 % OoO0O00 + Ii1I * I1Ii111 / O0 % I1Ii111
  if 6 - 6: II111iiii - i1IIi
  if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
  III = ii11i1IiI . nonce_key
  if ( III in lisp_map_notify_queue ) :
   oO00oo0 = lisp_map_notify_queue [ III ]
   oO00oo0 . retransmit_timer . cancel ( )
   del ( oO00oo0 )
   if 36 - 36: i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
  lisp_map_notify_queue [ III ] = ii11i1IiI
  if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
  if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
  if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
  if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( IIi11ii . print_address ( ) , False ) ) )
  if 32 - 32: I1Ii111
  lisp_send ( lisp_sockets , IIi11ii , LISP_CTRL_PORT , Oo00oo )
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
 III = lisp_hex_string ( nonce ) + source . print_address ( )
 if 47 - 47: II111iiii % Oo0Ooo . iIii1I11I1II1 . oO0o
 if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
 if 15 - 15: iII111i
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
 if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( III in lisp_map_notify_queue ) :
  ii11i1IiI = lisp_map_notify_queue [ III ]
  I111 = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( ii11i1IiI . nonce ) , I111 ) )
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
  III = ii11i1IiI . nonce_key
  lisp_map_notify_queue [ III ] = ii11i1IiI
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
 Oo00oo = ii11i1IiI . encode ( eid_records , site . auth_key [ key_id ] )
 ii11i1IiI . print_notify ( )
 if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
 if ( map_register_ack == False ) :
  IIIOOo0o = lisp_eid_record ( )
  IIIOOo0o . decode ( eid_records )
  IIIOOo0o . print_record ( "  " , False )
  if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
  if 69 - 69: IiII
  if 13 - 13: i11iIiiIii
  if 49 - 49: OoOoOO00
  if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
 lisp_send_map_notify ( lisp_sockets , Oo00oo , ii11i1IiI . etr , port )
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
 Oo00oo = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 9 - 9: I1ii11iIi11i + I11i
 if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
 if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
 if 4 - 4: OoOoOO00 / OoO0O00
 IIi11ii = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( IIi11ii . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , IIi11ii , LISP_CTRL_PORT , Oo00oo )
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
 III = ii11i1IiI . nonce_key
 if 4 - 4: I11i
 if 8 - 8: IiII
 if 1 - 1: ooOoO0o . IiII
 if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
 if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
 if 66 - 66: i1IIi . I1ii11iIi11i
 lisp_remove_eid_from_map_notify_queue ( ii11i1IiI . eid_list )
 if ( III in lisp_map_notify_queue ) :
  ii11i1IiI = lisp_map_notify_queue [ III ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( ii11i1IiI . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 86 - 86: Oo0Ooo
  return
  if 48 - 48: OoO0O00
  if 55 - 55: OoO0O00 * i1IIi * I11i / iII111i
  if 42 - 42: IiII
  if 28 - 28: OoOoOO00 + OoOoOO00
  if 53 - 53: II111iiii % i1IIi + ooOoO0o . I1Ii111
 lisp_map_notify_queue [ III ] = ii11i1IiI
 if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
 if 27 - 27: Oo0Ooo
 if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
 if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
 ii111iII1I = site_eid . rtrs_in_rloc_set ( )
 if ( ii111iII1I ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : ii111iII1I = False
  if 1 - 1: IiII / OoO0O00 . oO0o * I1Ii111 - i11iIiiIii
  if 50 - 50: oO0o - O0 / I1IiiI . OoOoOO00 . Oo0Ooo
  if 30 - 30: IiII . OoO0O00 + Oo0Ooo
  if 48 - 48: iIii1I11I1II1 / i11iIiiIii . OoOoOO00 * I11i
  if 1 - 1: IiII . OoOoOO00 * o0oOOo0O0Ooo
 IIIOOo0o = lisp_eid_record ( )
 IIIOOo0o . record_ttl = 1440
 IIIOOo0o . eid . copy_address ( site_eid . eid )
 IIIOOo0o . group . copy_address ( site_eid . group )
 IIIOOo0o . rloc_count = 0
 for iiIiIIi1I in site_eid . registered_rlocs :
  if ( ii111iII1I ^ iiIiIIi1I . is_rtr ( ) ) : continue
  IIIOOo0o . rloc_count += 1
  if 63 - 63: O0 / Ii1I + I1Ii111 % OoO0O00 % OOooOOo * O0
 Oo00oo = IIIOOo0o . encode ( )
 if 35 - 35: OoO0O00 + OoooooooOO % Oo0Ooo / I11i - O0 . i1IIi
 if 76 - 76: IiII % I1IiiI * Ii1I / Ii1I / OoooooooOO + Ii1I
 if 19 - 19: OoooooooOO
 if 88 - 88: I1IiiI % ooOoO0o % Oo0Ooo - O0
 ii11i1IiI . print_notify ( )
 IIIOOo0o . print_record ( "  " , False )
 if 71 - 71: OOooOOo % Ii1I - i11iIiiIii - oO0o . ooOoO0o / I1Ii111
 if 53 - 53: iII111i . Oo0Ooo
 if 91 - 91: oO0o * OoooooooOO * oO0o % oO0o * II111iiii % I1Ii111
 if 8 - 8: Ii1I
 for iiIiIIi1I in site_eid . registered_rlocs :
  if ( ii111iII1I ^ iiIiIIi1I . is_rtr ( ) ) : continue
  ooOooOo = lisp_rloc_record ( )
  ooOooOo . store_rloc_entry ( iiIiIIi1I )
  ooOooOo . local_bit = True
  ooOooOo . probe_bit = False
  ooOooOo . reach_bit = True
  Oo00oo += ooOooOo . encode ( )
  ooOooOo . print_record ( "    " )
  if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
  if 94 - 94: oO0o
  if 95 - 95: ooOoO0o * O0 + OOooOOo
  if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
  if 21 - 21: ooOoO0o
 Oo00oo = ii11i1IiI . encode ( Oo00oo , "" )
 if ( Oo00oo == None ) : return
 if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
 if 81 - 81: oO0o
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
 if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
 lisp_send_map_notify ( lisp_sockets , Oo00oo , xtr , LISP_CTRL_PORT )
 if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
 if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
 if 33 - 33: I11i
 if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
 ii11i1IiI . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ii11i1IiI ] )
 ii11i1IiI . retransmit_timer . start ( )
 return
 if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
 if 32 - 32: oO0o
 if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
 if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
 if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
 if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 oo0OOooO0oO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 4 - 4: II111iiii + ooOoO0o
 for OoO0o0 in rle_list :
  iIiiIi1I = lisp_site_eid_lookup ( OoO0o0 [ 0 ] , OoO0o0 [ 1 ] , True )
  if ( iIiiIi1I == None ) : continue
  if 85 - 85: oO0o * I1Ii111 * i11iIiiIii . OOooOOo . OoooooooOO
  if 2 - 2: i11iIiiIii + oO0o
  if 40 - 40: i11iIiiIii + oO0o * IiII
  if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
  if 70 - 70: OoO0O00
  if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
  if 85 - 85: O0 . II111iiii
  oo0000000oOoo = iIiiIi1I . registered_rlocs
  if ( len ( oo0000000oOoo ) == 0 ) :
   o0OooO0oO = { }
   for Ii1iIi1I1I1I in list ( iIiiIi1I . individual_registrations . values ( ) ) :
    for iiIiIIi1I in Ii1iIi1I1I1I . registered_rlocs :
     if ( iiIiIIi1I . is_rtr ( ) == False ) : continue
     o0OooO0oO [ iiIiIIi1I . rloc . print_address ( ) ] = iiIiIIi1I
     if 31 - 31: IiII
     if 95 - 95: I11i - oO0o - OOooOOo * ooOoO0o % I1IiiI
   oo0000000oOoo = list ( o0OooO0oO . values ( ) )
   if 82 - 82: oO0o / ooOoO0o
   if 43 - 43: IiII - oO0o % ooOoO0o + Ii1I . Ii1I
   if 100 - 100: Ii1I % iII111i
   if 25 - 25: OoOoOO00 % O0 / I1IiiI * IiII + IiII
   if 14 - 14: OOooOOo % I1IiiI
   if 27 - 27: O0 . OOooOOo - iIii1I11I1II1 - Ii1I - I1IiiI
  oo0oooo = [ ]
  O00O0 = False
  if ( iIiiIi1I . eid . address == 0 and iIiiIi1I . eid . mask_len == 0 ) :
   ii11iI11I = [ ]
   Iiii1I = [ ]
   if ( len ( oo0000000oOoo ) != 0 and oo0000000oOoo [ 0 ] . rle != None ) :
    Iiii1I = oo0000000oOoo [ 0 ] . rle . rle_nodes
    if 77 - 77: oO0o / IiII
   for oO0oOOOO0oO0o0 in Iiii1I :
    oo0oooo . append ( oO0oOOOO0oO0o0 . address )
    ii11iI11I . append ( oO0oOOOO0oO0o0 . address . print_address_no_iid ( ) )
    if 15 - 15: Ii1I % I1IiiI + ooOoO0o * IiII % OoOoOO00 / Oo0Ooo
   lprint ( "Notify existing RLE-nodes {}" . format ( ii11iI11I ) )
  else :
   if 35 - 35: i1IIi - i1IIi * I1ii11iIi11i / O0 / Oo0Ooo - ooOoO0o
   if 51 - 51: OoO0O00 + Ii1I * o0oOOo0O0Ooo
   if 86 - 86: OoOoOO00 - iII111i % OoO0O00 / OOooOOo / O0
   if 61 - 61: oO0o + OOooOOo * II111iiii
   if 76 - 76: iII111i % I1IiiI % OOooOOo + OOooOOo
   for iiIiIIi1I in oo0000000oOoo :
    if ( iiIiIIi1I . is_rtr ( ) ) : oo0oooo . append ( iiIiIIi1I . rloc )
    if 38 - 38: I1Ii111 * I1Ii111 + iII111i
    if 51 - 51: I1IiiI + I1ii11iIi11i % i11iIiiIii
    if 14 - 14: OOooOOo * II111iiii . Ii1I
    if 59 - 59: OoOoOO00
    if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
   O00O0 = ( len ( oo0oooo ) != 0 )
   if ( O00O0 == False ) :
    IiiiI1i1 = lisp_site_eid_lookup ( OoO0o0 [ 0 ] , oo0OOooO0oO , False )
    if ( IiiiI1i1 == None ) : continue
    if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
    for iiIiIIi1I in IiiiI1i1 . registered_rlocs :
     if ( iiIiIIi1I . rloc . is_null ( ) ) : continue
     oo0oooo . append ( iiIiIIi1I . rloc )
     if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
     if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
     if 7 - 7: OOooOOo
     if 22 - 22: Oo0Ooo + ooOoO0o
     if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
     if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
   if ( len ( oo0oooo ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( iIiiIi1I . print_eid_tuple ( ) , False ) ) )
    if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
    continue
    if 26 - 26: Oo0Ooo . Ii1I
    if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
    if 8 - 8: iIii1I11I1II1
    if 6 - 6: oO0o
    if 51 - 51: I1Ii111 - o0oOOo0O0Ooo
    if 5 - 5: O0
  for OOOo in oo0oooo :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if O00O0 else "x" , red ( OOOo . print_address_no_iid ( ) , False ) ,
   # I1IiiI
 green ( iIiiIi1I . print_eid_tuple ( ) , False ) ) )
   if 40 - 40: OoO0O00 * oO0o / OoOoOO00
   I1iI1iI1iIIi = [ iIiiIi1I . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , iIiiIi1I , I1iI1iI1iIIi , OOOo )
   time . sleep ( .001 )
   if 98 - 98: I11i % oO0o - I1Ii111 % o0oOOo0O0Ooo - IiII
   if 32 - 32: i11iIiiIii . I1IiiI
 return
 if 22 - 22: II111iiii / iII111i
 if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
 if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
 if 21 - 21: o0oOOo0O0Ooo % O0
 if 81 - 81: i1IIi + i1IIi
 if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
 if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
 if 71 - 71: I1IiiI + iII111i
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for iIi1iIIIiIiI in range ( rloc_count ) :
  ooOooOo = lisp_rloc_record ( )
  packet = ooOooOo . decode ( packet , None )
  iiii1111111 = ooOooOo . json
  if ( iiii1111111 == None ) : continue
  if 92 - 92: I1IiiI
  try :
   iiii1111111 = json . loads ( iiii1111111 . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 94 - 94: OoOoOO00 % OoOoOO00 . i11iIiiIii
   if 40 - 40: II111iiii - iII111i * iIii1I11I1II1
  if ( "signature" not in iiii1111111 ) : continue
  return ( ooOooOo )
  if 48 - 48: iII111i * OoO0O00
 return ( None )
 if 57 - 57: ooOoO0o + I1IiiI
 if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
 if 82 - 82: Oo0Ooo % Oo0Ooo
 if 91 - 91: I11i
 if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
 if 65 - 65: OoO0O00
 if 65 - 65: oO0o
 if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
 if 50 - 50: O0 - oO0o . oO0o
 if 98 - 98: IiII % Ii1I / Ii1I
 if 10 - 10: Ii1I
 if 69 - 69: I1Ii111 * OoooooooOO . o0oOOo0O0Ooo % I1IiiI
 if 70 - 70: iII111i . i11iIiiIii * I1Ii111
 if 54 - 54: o0oOOo0O0Ooo . i1IIi / iII111i
 if 21 - 21: O0 + ooOoO0o
 if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
 if 91 - 91: OoOoOO00 % iIii1I11I1II1
 if 81 - 81: i11iIiiIii / OoOoOO00 + iIii1I11I1II1
 if 65 - 65: o0oOOo0O0Ooo
def lisp_get_eid_hash ( eid ) :
 O0OOo0oo = None
 for II1i1i in lisp_eid_hashes :
  if 53 - 53: Ii1I
  if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
  if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
  if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
  oooo = II1i1i . instance_id
  if ( oooo == - 1 ) : II1i1i . instance_id = eid . instance_id
  if 33 - 33: oO0o . oO0o / IiII + II111iiii
  IIiiIiI = eid . is_more_specific ( II1i1i )
  II1i1i . instance_id = oooo
  if ( IIiiIiI ) :
   O0OOo0oo = 128 - II1i1i . mask_len
   break
   if 5 - 5: Oo0Ooo / OoooooooOO / Ii1I * I1Ii111
   if 37 - 37: Ii1I * o0oOOo0O0Ooo
 if ( O0OOo0oo == None ) : return ( None )
 if 39 - 39: OoooooooOO
 I1IIIi = eid . address
 iI1ii1Ii = ""
 for iIi1iIIIiIiI in range ( 0 , old_div ( O0OOo0oo , 16 ) ) :
  IiI = I1IIIi & 0xffff
  IiI = hex ( IiI ) [ 2 : : ]
  iI1ii1Ii = IiI . zfill ( 4 ) + ":" + iI1ii1Ii
  I1IIIi >>= 16
  if 10 - 10: i1IIi + OOooOOo - OoooooooOO . iII111i - i1IIi
 if ( O0OOo0oo % 16 != 0 ) :
  IiI = I1IIIi & 0xff
  IiI = hex ( IiI ) [ 2 : : ]
  iI1ii1Ii = IiI . zfill ( 2 ) + ":" + iI1ii1Ii
  if 81 - 81: ooOoO0o / OOooOOo % OoOoOO00 . iIii1I11I1II1
 return ( iI1ii1Ii [ 0 : - 1 ] )
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
def lisp_lookup_public_key ( eid ) :
 oooo = eid . instance_id
 if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
 if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
 if 27 - 27: O0 - iIii1I11I1II1
 if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
 if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
 OoOOo0 = lisp_get_eid_hash ( eid )
 if ( OoOOo0 == None ) : return ( [ None , None , False ] )
 if 61 - 61: IiII * I1Ii111 * OoO0O00 / oO0o - OoooooooOO
 OoOOo0 = "hash-" + OoOOo0
 iiii111I1iI1 = lisp_address ( LISP_AFI_NAME , OoOOo0 , len ( OoOOo0 ) , oooo )
 iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 if 5 - 5: o0oOOo0O0Ooo % OOooOOo % II111iiii
 if 86 - 86: O0 . ooOoO0o * OoooooooOO + Ii1I / I11i / II111iiii
 if 26 - 26: OoooooooOO - I1Ii111 / Oo0Ooo - iII111i % OoOoOO00 * OoooooooOO
 if 3 - 3: oO0o
 IiiiI1i1 = lisp_site_eid_lookup ( iiii111I1iI1 , iiI , True )
 if ( IiiiI1i1 == None ) : return ( [ iiii111I1iI1 , None , False ] )
 if 3 - 3: I1ii11iIi11i . IiII + ooOoO0o
 if 66 - 66: OOooOOo + oO0o - ooOoO0o / Ii1I * OoO0O00 * i11iIiiIii
 if 69 - 69: I11i % i11iIiiIii
 if 34 - 34: Ii1I . OoooooooOO + II111iiii % oO0o
 iIiIi111 = None
 for IIIi1iI1 in IiiiI1i1 . registered_rlocs :
  Oo0OOo0Oo0 = IIIi1iI1 . json
  if ( Oo0OOo0Oo0 == None ) : continue
  try :
   Oo0OOo0Oo0 = json . loads ( Oo0OOo0Oo0 . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( OoOOo0 ) )
   if 79 - 79: I1Ii111
   return ( [ iiii111I1iI1 , None , False ] )
   if 81 - 81: OoooooooOO + OoOoOO00 / II111iiii
  if ( "public-key" not in Oo0OOo0Oo0 ) : continue
  iIiIi111 = Oo0OOo0Oo0 [ "public-key" ]
  break
  if 39 - 39: I1Ii111 * I1IiiI - o0oOOo0O0Ooo . oO0o . OOooOOo * i11iIiiIii
 return ( [ iiii111I1iI1 , iIiIi111 , True ] )
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
 Oooo0oOoO0000 = json . loads ( rloc_record . json . json_string )
 if 58 - 58: oO0o / ooOoO0o
 if ( lisp_get_eid_hash ( eid ) ) :
  i1i1i11IIii = eid
 elif ( "signature-eid" in Oooo0oOoO0000 ) :
  iII1II11II = Oooo0oOoO0000 [ "signature-eid" ]
  i1i1i11IIii = lisp_address ( LISP_AFI_IPV6 , iII1II11II , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 46 - 46: o0oOOo0O0Ooo % O0
  if 30 - 30: oO0o
  if 64 - 64: O0
  if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
  if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
 iiii111I1iI1 , iIiIi111 , IIi1 = lisp_lookup_public_key ( i1i1i11IIii )
 if ( iiii111I1iI1 == None ) :
  i1iiii = green ( i1i1i11IIii . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( i1iiii ) )
  return ( False )
  if 11 - 11: I1IiiI % iIii1I11I1II1 * Ii1I % ooOoO0o
  if 33 - 33: iII111i / O0 % II111iiii % OoOoOO00 / I1Ii111
 OO0o0oo0oOo = "found" if IIi1 else bold ( "not found" , False )
 i1iiii = green ( iiii111I1iI1 . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( i1iiii , OO0o0oo0oOo ) )
 if ( IIi1 == False ) : return ( False )
 if 21 - 21: ooOoO0o - I11i . i11iIiiIii
 if ( iIiIi111 == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 39 - 39: Oo0Ooo * II111iiii % OOooOOo / oO0o . ooOoO0o
  if 75 - 75: I11i / O0 + OoooooooOO + OOooOOo % iII111i + I1IiiI
 IiI111iiiIIi = iIiIi111 [ 0 : 8 ] + "..." + iIiIi111 [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( IiI111iiiIIi ) )
 if 74 - 74: Oo0Ooo / oO0o + iII111i % I1IiiI * OOooOOo
 if 16 - 16: I1IiiI . I11i
 if 37 - 37: Ii1I / ooOoO0o * oO0o * Oo0Ooo . o0oOOo0O0Ooo
 if 61 - 61: OoooooooOO * o0oOOo0O0Ooo / i11iIiiIii
 if 38 - 38: ooOoO0o * I1IiiI / OoO0O00 * o0oOOo0O0Ooo
 oO0O0o0Oo00 = Oooo0oOoO0000 [ "signature" ]
 if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
 try :
  Oooo0oOoO0000 = binascii . a2b_base64 ( oO0O0o0Oo00 )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
  if 4 - 4: Oo0Ooo - IiII - I11i
 ooooI111I11i = len ( Oooo0oOoO0000 )
 if ( ooooI111I11i & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( ooooI111I11i ) )
  return ( False )
  if 76 - 76: OOooOOo . iII111i % ooOoO0o
  if 15 - 15: iII111i
  if 55 - 55: iII111i
  if 22 - 22: I1Ii111 % II111iiii % iIii1I11I1II1 % II111iiii
  if 33 - 33: II111iiii
 OO0OOo0O = i1i1i11IIii . print_address ( )
 if 60 - 60: iIii1I11I1II1 / OOooOOo
 if 78 - 78: i11iIiiIii
 if 20 - 20: OoooooooOO * OoooooooOO - OOooOOo
 if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
 iIiIi111 = binascii . a2b_base64 ( iIiIi111 )
 try :
  III = ecdsa . VerifyingKey . from_pem ( iIiIi111 )
 except :
  III11i1 = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( III11i1 ) )
  return ( False )
  if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
  if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
  if 24 - 24: OoOoOO00
  if 19 - 19: ooOoO0o
  if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
  if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
  if 7 - 7: OoooooooOO - I1Ii111 * IiII
  if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
  if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
  if 8 - 8: OoooooooOO * ooOoO0o
  if 26 - 26: i11iIiiIii + oO0o - i1IIi
 try :
  oO0oO00OO00 = III . verify ( Oooo0oOoO0000 , OO0OOo0O , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( OO0OOo0O ) )
  if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
  lprint ( "  Signature used '{}'" . format ( oO0O0o0Oo00 ) )
  return ( False )
  if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
 return ( oO0oO00OO00 )
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
 IiIii1iIIII = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 oo0O00O0O0O00Ooo = ( IiIii1iIIII >> 13 ) & 0x1
 if ( oo0O00O0O0O00Ooo == 0 ) : return ( packet )
 if 97 - 97: i1IIi . I1ii11iIi11i . OOooOOo - ooOoO0o
 iiIi1iIIII1 = ( IiIii1iIIII >> 14 ) & 0x7
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
 Ooi1IIii1i = chacha . ChaCha ( OooOo0o , OoOooO , 20 ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + Ooi1IIii1i )
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
 O0OOOOO0O , packet = iiIio0o0 . decode ( packet )
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
 Oooo0o00oOO0o0 = [ ]
 if 5 - 5: OOooOOo + OOooOOo
 if 81 - 81: OoO0O00 + i11iIiiIii / Ii1I
 if 20 - 20: I1Ii111 + IiII - O0 + IiII / i1IIi
 if 100 - 100: OoooooooOO
 i1iIiII1II11i = None
 OOoO00 = packet
 oOII = [ ]
 OoIiII = iiIio0o0 . record_count
 for iIi1iIIIiIiI in range ( OoIiII ) :
  IIIOOo0o = lisp_eid_record ( )
  ooOooOo = lisp_rloc_record ( )
  packet = IIIOOo0o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 26 - 26: Oo0Ooo
  IIIOOo0o . print_record ( "  " , False )
  if 3 - 3: I11i . OoO0O00 . i1IIi - I1IiiI * oO0o
  if 93 - 93: i1IIi + I1ii11iIi11i % Oo0Ooo + iIii1I11I1II1 / II111iiii
  if 100 - 100: iIii1I11I1II1 / II111iiii / Ii1I * Ii1I - OoO0O00
  if 36 - 36: ooOoO0o % i1IIi / OoOoOO00 % OoOoOO00 + Ii1I
  IiiiI1i1 = lisp_site_eid_lookup ( IIIOOo0o . eid , IIIOOo0o . group ,
 False )
  if 35 - 35: Ii1I . ooOoO0o - ooOoO0o % OoO0O00 / oO0o
  i1iiI = IiiiI1i1 . print_eid_tuple ( ) if IiiiI1i1 else None
  if 44 - 44: OoOoOO00 * Oo0Ooo
  if 51 - 51: OOooOOo / IiII % I1Ii111 . OoOoOO00 % Ii1I
  if 88 - 88: OoO0O00
  if 28 - 28: I1Ii111 - iIii1I11I1II1
  if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
  if 65 - 65: iII111i . oO0o
  if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
  if ( IiiiI1i1 and IiiiI1i1 . accept_more_specifics == False ) :
   if ( IiiiI1i1 . eid_record_matches ( IIIOOo0o ) == False ) :
    i11I1Ii1 = IiiiI1i1 . parent_for_more_specifics
    if ( i11I1Ii1 ) : IiiiI1i1 = i11I1Ii1
    if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
    if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
    if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
    if 43 - 43: Oo0Ooo % I11i
    if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
    if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
    if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
    if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
  iI111Ii111I1i = ( IiiiI1i1 and IiiiI1i1 . accept_more_specifics )
  if ( iI111Ii111I1i ) :
   IIiII1I1ii11i = lisp_site_eid ( IiiiI1i1 . site )
   IIiII1I1ii11i . dynamic = True
   IIiII1I1ii11i . eid . copy_address ( IIIOOo0o . eid )
   IIiII1I1ii11i . group . copy_address ( IIIOOo0o . group )
   IIiII1I1ii11i . parent_for_more_specifics = IiiiI1i1
   IIiII1I1ii11i . add_cache ( )
   IIiII1I1ii11i . inherit_from_ams_parent ( )
   IiiiI1i1 . more_specific_registrations . append ( IIiII1I1ii11i )
   IiiiI1i1 = IIiII1I1ii11i
  else :
   IiiiI1i1 = lisp_site_eid_lookup ( IIIOOo0o . eid , IIIOOo0o . group ,
 True )
   if 25 - 25: II111iiii + I1IiiI
   if 99 - 99: i1IIi * I11i % OoooooooOO % i11iIiiIii % I1Ii111 . OOooOOo
  i1iiii = IIIOOo0o . print_eid_tuple ( )
  if 46 - 46: II111iiii - oO0o - Ii1I * OoOoOO00 % i1IIi
  if ( IiiiI1i1 == None ) :
   ii1i = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( ii1i , green ( i1iiii , False ) ,
 ", matched non-ams {}" . format ( green ( i1iiI , False ) if i1iiI else "" ) ) )
   if 71 - 71: o0oOOo0O0Ooo + Oo0Ooo % OoooooooOO
   if 5 - 5: i1IIi % Oo0Ooo / OoooooooOO * OoOoOO00 + OOooOOo - ooOoO0o
   if 24 - 24: oO0o / ooOoO0o % I1IiiI / I1ii11iIi11i
   if 88 - 88: OoO0O00
   if 96 - 96: IiII % I1ii11iIi11i % Oo0Ooo - i11iIiiIii % iIii1I11I1II1
   packet = ooOooOo . end_of_rlocs ( packet , IIIOOo0o . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 100 - 100: IiII - Ii1I
   continue
   if 9 - 9: II111iiii / Ii1I / O0 - OoOoOO00 - IiII
   if 6 - 6: OoOoOO00 / O0 * i1IIi * OoooooooOO
  i1iIiII1II11i = IiiiI1i1 . site
  if 60 - 60: iII111i - iII111i - Oo0Ooo . i11iIiiIii
  if ( iI111Ii111I1i ) :
   oO0ooOOO = IiiiI1i1 . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( oO0ooOOO , False ) , i1iIiII1II11i . site_name , green ( i1iiii , False ) ) )
   if 67 - 67: oO0o * OoOoOO00 * OoO0O00 + O0 * oO0o
  else :
   oO0ooOOO = green ( IiiiI1i1 . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( oO0ooOOO , i1iIiII1II11i . site_name , green ( i1iiii , False ) ) )
   if 39 - 39: i1IIi
   if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
   if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
   if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
   if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
  if ( i1iIiII1II11i . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( i1iIiII1II11i . site_name ) )
   packet = ooOooOo . end_of_rlocs ( packet , IIIOOo0o . rloc_count )
   continue
   if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
   if 22 - 22: ooOoO0o - OOooOOo
   if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
   if 20 - 20: ooOoO0o - i11iIiiIii
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
   if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
   if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
   if 29 - 29: oO0o
  IiII11iI1 = iiIio0o0 . key_id
  if ( IiII11iI1 in i1iIiII1II11i . auth_key ) :
   iiIo0O0O0 = i1iIiII1II11i . auth_key [ IiII11iI1 ]
  else :
   iiIo0O0O0 = ""
   if 37 - 37: o0oOOo0O0Ooo
   if 84 - 84: Oo0Ooo * i11iIiiIii * OoooooooOO % I1ii11iIi11i / i11iIiiIii
  O0o0OOO0 = lisp_verify_auth ( O0OOOOO0O , iiIio0o0 . alg_id ,
 iiIio0o0 . auth_data , iiIo0O0O0 )
  OooOooo0 = "dynamic " if IiiiI1i1 . dynamic else ""
  if 80 - 80: I1IiiI - OOooOOo + OoOoOO00
  OO00O = bold ( "passed" if O0o0OOO0 else "failed" , False )
  IiII11iI1 = "key-id {}" . format ( IiII11iI1 ) if IiII11iI1 == iiIio0o0 . key_id else "bad key-id {}" . format ( iiIio0o0 . key_id )
  if 53 - 53: OoooooooOO . I11i * OOooOOo + i11iIiiIii * O0 . iIii1I11I1II1
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( OO00O , OooOooo0 , green ( i1iiii , False ) , IiII11iI1 ) )
  if 72 - 72: IiII . ooOoO0o . Oo0Ooo - iIii1I11I1II1 % IiII
  if 97 - 97: OoooooooOO
  if 26 - 26: I11i . I1IiiI / IiII / Oo0Ooo % Oo0Ooo / O0
  if 27 - 27: I11i - I11i % OoO0O00 - iII111i . OOooOOo - iIii1I11I1II1
  if 15 - 15: OoO0O00 + iIii1I11I1II1
  if 89 - 89: OoooooooOO * Ii1I
  i11Iii = True
  ooo0Ooo0o0 = ( lisp_get_eid_hash ( IIIOOo0o . eid ) != None )
  if ( ooo0Ooo0o0 or IiiiI1i1 . require_signature ) :
   iII1I1iII1i = "Required " if IiiiI1i1 . require_signature else ""
   i1iiii = green ( i1iiii , False )
   IIIi1iI1 = lisp_find_sig_in_rloc_set ( packet , IIIOOo0o . rloc_count )
   if ( IIIi1iI1 == None ) :
    i11Iii = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( iII1I1iII1i ,
    # i1IIi . IiII / o0oOOo0O0Ooo / I11i
 bold ( "failed" , False ) , i1iiii ) )
   else :
    i11Iii = lisp_verify_cga_sig ( IIIOOo0o . eid , IIIi1iI1 )
    OO00O = bold ( "passed" if i11Iii else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( iII1I1iII1i , OO00O , i1iiii ) )
    if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
    if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
    if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
    if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
  if ( O0o0OOO0 == False or i11Iii == False ) :
   packet = ooOooOo . end_of_rlocs ( packet , IIIOOo0o . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 38 - 38: I1ii11iIi11i - Ii1I % OoooooooOO
   continue
   if 43 - 43: iIii1I11I1II1 / OoOoOO00
   if 13 - 13: o0oOOo0O0Ooo / I1Ii111
   if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
   if 32 - 32: oO0o
   if 72 - 72: I1IiiI
   if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
  if ( iiIio0o0 . merge_register_requested ) :
   i11I1Ii1 = IiiiI1i1
   i11I1Ii1 . inconsistent_registration = False
   if 87 - 87: Oo0Ooo
   if 7 - 7: iIii1I11I1II1
   if 85 - 85: iIii1I11I1II1 . O0
   if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
   if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
   if ( IiiiI1i1 . group . is_null ( ) ) :
    if ( i11I1Ii1 . site_id != iiIio0o0 . site_id ) :
     i11I1Ii1 . site_id = iiIio0o0 . site_id
     i11I1Ii1 . registered = False
     i11I1Ii1 . individual_registrations = { }
     i11I1Ii1 . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
     if 8 - 8: OoO0O00 . OoO0O00
     if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
   III = iiIio0o0 . xtr_id
   if ( III in IiiiI1i1 . individual_registrations ) :
    IiiiI1i1 = IiiiI1i1 . individual_registrations [ III ]
   else :
    IiiiI1i1 = lisp_site_eid ( i1iIiII1II11i )
    IiiiI1i1 . eid . copy_address ( i11I1Ii1 . eid )
    IiiiI1i1 . group . copy_address ( i11I1Ii1 . group )
    IiiiI1i1 . encrypt_json = i11I1Ii1 . encrypt_json
    i11I1Ii1 . individual_registrations [ III ] = IiiiI1i1
    if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
  else :
   IiiiI1i1 . inconsistent_registration = IiiiI1i1 . merge_register_requested
   if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
   if 24 - 24: IiII
   if 95 - 95: IiII + OoOoOO00 * OOooOOo
  IiiiI1i1 . map_registers_received += 1
  if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
  if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
  if 41 - 41: i1IIi / IiII
  if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
  if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
  III11i1 = ( IiiiI1i1 . is_rloc_in_rloc_set ( source ) == False )
  if ( IIIOOo0o . record_ttl == 0 and III11i1 ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
   continue
   if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
   if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
   if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
   if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
   if 13 - 13: oO0o + IiII
   if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
  OO0ooOo0o = IiiiI1i1 . registered_rlocs
  IiiiI1i1 . registered_rlocs = [ ]
  if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
  if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
  if 41 - 41: OoooooooOO + iII111i . OOooOOo
  OOOoooO = packet
  for oooOO0oooo00 in range ( IIIOOo0o . rloc_count ) :
   ooOooOo = lisp_rloc_record ( )
   packet = ooOooOo . decode ( packet , None , IiiiI1i1 . encrypt_json )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
   ooOooOo . print_record ( "    " )
   if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
   if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
   if 57 - 57: II111iiii % OoO0O00 * i1IIi
   if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
   if ( len ( i1iIiII1II11i . allowed_rlocs ) > 0 ) :
    O0O0 = ooOooOo . rloc . print_address ( )
    if ( O0O0 not in i1iIiII1II11i . allowed_rlocs ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( O0O0 , False ) ) )
     if 9 - 9: II111iiii % OoooooooOO
     if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
     IiiiI1i1 . registered = False
     packet = ooOooOo . end_of_rlocs ( packet ,
 IIIOOo0o . rloc_count - oooOO0oooo00 - 1 )
     break
     if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
     if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
     if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
     if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
     if 26 - 26: iII111i
     if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
   IIIi1iI1 = lisp_rloc ( )
   IIIi1iI1 . store_rloc_from_record ( ooOooOo , None , source )
   if 6 - 6: IiII
   if 68 - 68: Oo0Ooo
   if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
   if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
   if 93 - 93: i11iIiiIii
   if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
   if ( source . is_exact_match ( IIIi1iI1 . rloc ) ) :
    IIIi1iI1 . map_notify_requested = iiIio0o0 . map_notify_requested
    if 40 - 40: IiII % IiII
    if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
    if 8 - 8: iII111i
    if 51 - 51: I1IiiI
    if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
   IiiiI1i1 . registered_rlocs . append ( IIIi1iI1 )
   if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
   if 68 - 68: OOooOOo
  O0O0oOOOoOoo = ( IiiiI1i1 . do_rloc_sets_match ( OO0ooOo0o ) == False )
  if 82 - 82: Oo0Ooo - oO0o
  if 36 - 36: Oo0Ooo / Oo0Ooo - o0oOOo0O0Ooo - i11iIiiIii
  if 59 - 59: i11iIiiIii / iIii1I11I1II1 / ooOoO0o
  if 2 - 2: iII111i + II111iiii
  if 88 - 88: i1IIi - iII111i / OOooOOo / i1IIi
  if 48 - 48: iII111i / OoooooooOO / iIii1I11I1II1
  if ( iiIio0o0 . map_register_refresh and O0O0oOOOoOoo and
 IiiiI1i1 . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   IiiiI1i1 . registered_rlocs = OO0ooOo0o
   continue
   if 41 - 41: II111iiii - II111iiii - OoO0O00 + oO0o * I11i
   if 77 - 77: IiII % iIii1I11I1II1 - OOooOOo / I1Ii111 / ooOoO0o . iII111i
   if 62 - 62: I1Ii111
   if 42 - 42: o0oOOo0O0Ooo
   if 59 - 59: I1ii11iIi11i % O0 - i1IIi . Oo0Ooo
   if 18 - 18: II111iiii
  if ( IiiiI1i1 . registered == False ) :
   IiiiI1i1 . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 31 - 31: Oo0Ooo / Oo0Ooo / iIii1I11I1II1 / I11i % OoooooooOO
  IiiiI1i1 . last_registered = lisp_get_timestamp ( )
  IiiiI1i1 . registered = ( IIIOOo0o . record_ttl != 0 )
  IiiiI1i1 . last_registerer = source
  if 90 - 90: I1IiiI
  if 35 - 35: O0
  if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
  if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
  IiiiI1i1 . auth_sha1_or_sha2 = i1IiIIi11I
  IiiiI1i1 . proxy_reply_requested = iiIio0o0 . proxy_reply_requested
  IiiiI1i1 . lisp_sec_present = iiIio0o0 . lisp_sec_present
  IiiiI1i1 . map_notify_requested = iiIio0o0 . map_notify_requested
  IiiiI1i1 . mobile_node_requested = iiIio0o0 . mobile_node
  IiiiI1i1 . merge_register_requested = iiIio0o0 . merge_register_requested
  if 78 - 78: I1IiiI - iIii1I11I1II1
  IiiiI1i1 . use_register_ttl_requested = iiIio0o0 . use_ttl_for_timeout
  if ( IiiiI1i1 . use_register_ttl_requested ) :
   IiiiI1i1 . register_ttl = IIIOOo0o . store_ttl ( )
  else :
   IiiiI1i1 . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
  IiiiI1i1 . xtr_id_present = iiIio0o0 . xtr_id_present
  if ( IiiiI1i1 . xtr_id_present ) :
   IiiiI1i1 . xtr_id = iiIio0o0 . xtr_id
   IiiiI1i1 . site_id = iiIio0o0 . site_id
   if 85 - 85: I11i + OoOoOO00 * O0 * O0
   if 92 - 92: i11iIiiIii
   if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
   if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
   if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
  if ( iiIio0o0 . merge_register_requested ) :
   if ( i11I1Ii1 . merge_in_site_eid ( IiiiI1i1 ) ) :
    Oooo0o00oOO0o0 . append ( [ IIIOOo0o . eid , IIIOOo0o . group ] )
    if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
   if ( iiIio0o0 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , i11I1Ii1 , iiIio0o0 ,
 IIIOOo0o )
    if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
    if 42 - 42: OoOoOO00 . I11i % II111iiii
    if 19 - 19: OoooooooOO
  if ( O0O0oOOOoOoo == False ) : continue
  if ( len ( Oooo0o00oOO0o0 ) != 0 ) : continue
  if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
  oOII . append ( IiiiI1i1 . print_eid_tuple ( ) )
  if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
  if 56 - 56: I11i
  if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
  if 32 - 32: OOooOOo / i1IIi / OOooOOo
  if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
  if 45 - 45: Oo0Ooo
  if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
  II1i11iI = copy . deepcopy ( IIIOOo0o )
  IIIOOo0o = IIIOOo0o . encode ( )
  IIIOOo0o += OOOoooO
  I1iI1iI1iIIi = [ IiiiI1i1 . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 31 - 31: OoO0O00 % ooOoO0o * Ii1I
  for IIIi1iI1 in OO0ooOo0o :
   if ( IIIi1iI1 . map_notify_requested == False ) : continue
   if ( IIIi1iI1 . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , IIIOOo0o , I1iI1iI1iIIi , 1 , IIIi1iI1 . rloc ,
 LISP_CTRL_PORT , iiIio0o0 . nonce , iiIio0o0 . key_id ,
 iiIio0o0 . alg_id , iiIio0o0 . auth_len , i1iIiII1II11i , False )
   if 67 - 67: I11i . II111iiii + iIii1I11I1II1 - I1IiiI
   if 25 - 25: i1IIi . OoO0O00 - Ii1I
   if 42 - 42: O0 * iII111i . i1IIi / i11iIiiIii + Ii1I
   if 80 - 80: O0 + II111iiii + oO0o . Oo0Ooo * i1IIi
   if 8 - 8: Ii1I
  lisp_notify_subscribers ( lisp_sockets , II1i11iI , OOOoooO ,
 IiiiI1i1 . eid , i1iIiII1II11i )
  if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
  if 15 - 15: O0
  if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
  if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
  if 25 - 25: ooOoO0o
 if ( len ( Oooo0o00oOO0o0 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , Oooo0o00oOO0o0 )
  if 33 - 33: Oo0Ooo
  if 11 - 11: I11i
  if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
  if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
  if 74 - 74: I1IiiI / o0oOOo0O0Ooo
  if 53 - 53: iIii1I11I1II1 * oO0o
 if ( iiIio0o0 . merge_register_requested ) : return
 if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
 if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
 if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
 if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
 if 60 - 60: oO0o * I1Ii111
 if ( iiIio0o0 . map_notify_requested and i1iIiII1II11i != None ) :
  lisp_build_map_notify ( lisp_sockets , OOoO00 , oOII ,
 iiIio0o0 . record_count , source , sport , iiIio0o0 . nonce ,
 iiIio0o0 . key_id , iiIio0o0 . alg_id , iiIio0o0 . auth_len ,
 i1iIiII1II11i , True )
  if 81 - 81: oO0o - OOooOOo - oO0o
 return
 if 54 - 54: oO0o % I11i
 if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
 if 22 - 22: iIii1I11I1II1 - OoooooooOO
 if 8 - 8: ooOoO0o % i11iIiiIii
 if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
 if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
 if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
 if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
def lisp_process_unicast_map_notify ( lisp_sockets , packet , source ) :
 ii11i1IiI = lisp_map_notify ( "" )
 packet = ii11i1IiI . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 73 - 73: O0 % i11iIiiIii
  if 16 - 16: O0
 ii11i1IiI . print_notify ( )
 if ( ii11i1IiI . record_count == 0 ) : return
 if 15 - 15: i1IIi % i11iIiiIii
 I1i1IIiIIiIiIi = ii11i1IiI . eid_records
 if 97 - 97: Ii1I + I1Ii111 / II111iiii
 for iIi1iIIIiIiI in range ( ii11i1IiI . record_count ) :
  IIIOOo0o = lisp_eid_record ( )
  I1i1IIiIIiIiIi = IIIOOo0o . decode ( I1i1IIiIIiIiIi )
  if ( packet == None ) : return
  IIIOOo0o . print_record ( "  " , False )
  i1iiii = IIIOOo0o . print_eid_tuple ( )
  if 14 - 14: iII111i / IiII / oO0o
  if 55 - 55: OoO0O00 % O0
  if 92 - 92: OoooooooOO / O0
  if 14 - 14: i11iIiiIii
  if 43 - 43: OOooOOo
  iIIiiiiI11i = lisp_map_cache_lookup ( IIIOOo0o . eid , IIIOOo0o . eid )
  if ( iIIiiiiI11i == None ) :
   oO0ooOOO = green ( i1iiii , False )
   lprint ( "Ignoring Map-Notify EID {}, no subscribe-request entry" . format ( oO0ooOOO ) )
   if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
   continue
   if 93 - 93: OoOoOO00
   if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
   if 72 - 72: ooOoO0o
   if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
   if 53 - 53: OOooOOo * O0 . iII111i
   if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
   if 78 - 78: iII111i
  if ( iIIiiiiI11i . action != LISP_SEND_PUBSUB_ACTION ) :
   if ( iIIiiiiI11i . subscribed_eid == None ) :
    oO0ooOOO = green ( i1iiii , False )
    lprint ( "Ignoring Map-Notify for non-subscribed EID {}" . format ( oO0ooOOO ) )
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
  if ( iIIiiiiI11i . action == LISP_SEND_PUBSUB_ACTION ) :
   iIIiiiiI11i = lisp_mapping ( IIIOOo0o . eid , IIIOOo0o . group , [ ] )
   iIIiiiiI11i . add_cache ( )
   i11o0o0OoOo00O0O = copy . deepcopy ( IIIOOo0o . eid )
   oo0ooOo0oo0Oo = copy . deepcopy ( IIIOOo0o . group )
  else :
   i11o0o0OoOo00O0O = iIIiiiiI11i . subscribed_eid
   oo0ooOo0oo0Oo = iIIiiiiI11i . subscribed_group
   O0000oo0Oo = iIIiiiiI11i . rloc_set
   iIIiiiiI11i . delete_rlocs_from_rloc_probe_list ( )
   iIIiiiiI11i . rloc_set = [ ]
   if 35 - 35: Oo0Ooo / OoooooooOO * O0 / Ii1I . OoO0O00
   if 93 - 93: I11i / OoooooooOO % Oo0Ooo . OoO0O00
   if 54 - 54: OoooooooOO . OoooooooOO / i1IIi * Oo0Ooo
   if 90 - 90: oO0o / Oo0Ooo + Oo0Ooo
   if 16 - 16: I1Ii111 / I1ii11iIi11i / I11i - I1IiiI
  iIIiiiiI11i . mapping_source = None if source == "lisp-itr" else source
  iIIiiiiI11i . map_cache_ttl = IIIOOo0o . store_ttl ( )
  iIIiiiiI11i . subscribed_eid = i11o0o0OoOo00O0O
  iIIiiiiI11i . subscribed_group = oo0ooOo0oo0Oo
  if 30 - 30: I1Ii111 + OoO0O00 % OoOoOO00 / I11i - iII111i
  if 35 - 35: o0oOOo0O0Ooo / I1Ii111 - ooOoO0o
  if 44 - 44: I1IiiI * I11i + I1ii11iIi11i / IiII
  if 95 - 95: OoOoOO00
  if 73 - 73: IiII * Oo0Ooo . I1IiiI - iIii1I11I1II1
  if ( len ( O0000oo0Oo ) != 0 and IIIOOo0o . rloc_count == 0 ) :
   iIIiiiiI11i . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , iIIiiiiI11i )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( i1iiii , False ) ) )
   if 100 - 100: i11iIiiIii - IiII
   continue
   if 43 - 43: oO0o - I11i . i11iIiiIii
   if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
   if 30 - 30: I1IiiI % oO0o * OoooooooOO
   if 64 - 64: I1IiiI
   if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
   if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
   if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
  o000ooOo0o0Oo = OOOOO0OO00OOO = 0
  for oooOO0oooo00 in range ( IIIOOo0o . rloc_count ) :
   ooOooOo = lisp_rloc_record ( )
   I1i1IIiIIiIiIi = ooOooOo . decode ( I1i1IIiIIiIiIi , None )
   ooOooOo . print_record ( "    " )
   if 14 - 14: I1IiiI - i11iIiiIii . O0 % OOooOOo . Ii1I
   if 46 - 46: II111iiii . i1IIi - i11iIiiIii + I11i - I1Ii111
   if 6 - 6: ooOoO0o / Ii1I / iIii1I11I1II1 - IiII - ooOoO0o
   if 7 - 7: OoOoOO00 + i1IIi % ooOoO0o * I11i + i11iIiiIii / II111iiii
   OO0o0oo0oOo = False
   for iiiI1I in O0000oo0Oo :
    if ( iiiI1I . rloc . is_exact_match ( ooOooOo . rloc ) ) :
     OO0o0oo0oOo = True
     break
     if 2 - 2: O0 / o0oOOo0O0Ooo - OoO0O00 * II111iiii
     if 4 - 4: I1IiiI + Oo0Ooo . iIii1I11I1II1
   if ( OO0o0oo0oOo ) :
    IIIi1iI1 = copy . deepcopy ( iiiI1I )
    OOOOO0OO00OOO += 1
   else :
    IIIi1iI1 = lisp_rloc ( )
    o000ooOo0o0Oo += 1
    if 100 - 100: i11iIiiIii
    if 21 - 21: OoOoOO00 + iII111i . OoO0O00
    if 79 - 79: i11iIiiIii - OoO0O00 * OoO0O00 * i1IIi / iIii1I11I1II1 + iII111i
    if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
    if 62 - 62: iIii1I11I1II1
   IIIi1iI1 . store_rloc_from_record ( ooOooOo , None , iIIiiiiI11i . mapping_source )
   iIIiiiiI11i . rloc_set . append ( IIIi1iI1 )
   if 60 - 60: Oo0Ooo % IiII % OoO0O00 - i11iIiiIii
   if 53 - 53: i11iIiiIii + OoooooooOO
  lprint ( "Update {} map-cache entry with {}/{} new/replaced RLOCs" . format ( green ( i1iiii , False ) , o000ooOo0o0Oo , OOOOO0OO00OOO ) )
  if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  if 79 - 79: II111iiii / OoooooooOO
  if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
  if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
  if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  iIIiiiiI11i . build_best_rloc_set ( )
  lisp_write_ipc_map_cache ( True , iIIiiiiI11i )
  if 17 - 17: I1Ii111
  if 2 - 2: O0 % OoOoOO00 + oO0o
  if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
  if 51 - 51: IiII
  if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
  if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 IIiiIiI = lisp_get_map_server ( source )
 if ( IIiiIiI == None ) :
  lprint ( "Cannot find Map-Server for Map-Notify source address {}" . format ( source . print_address_no_iid ( ) ) )
  if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
  return
  if 95 - 95: O0 - OoOoOO00
 lisp_send_map_notify_ack ( lisp_sockets , I1i1IIiIIiIiIi , ii11i1IiI , IIiiIiI )
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
 I1i1IIiIIiIiIi = ii11i1IiI . eid_records
 if 88 - 88: OOooOOo / Oo0Ooo
 for iIi1iIIIiIiI in range ( ii11i1IiI . record_count ) :
  IIIOOo0o = lisp_eid_record ( )
  I1i1IIiIIiIiIi = IIIOOo0o . decode ( I1i1IIiIIiIiIi )
  if ( packet == None ) : return
  IIIOOo0o . print_record ( "  " , False )
  if 31 - 31: II111iiii
  if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 67 - 67: IiII + oO0o * IiII
  if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
  iIIiiiiI11i = lisp_map_cache_lookup ( IIIOOo0o . eid , IIIOOo0o . group )
  if ( iIIiiiiI11i == None ) :
   o00000o , I1iIiiI1IIi1 , II1ii1 = lisp_allow_gleaning ( IIIOOo0o . eid , IIIOOo0o . group ,
 None )
   if ( o00000o == False ) : continue
   if 16 - 16: I1IiiI . Ii1I
   iIIiiiiI11i = lisp_mapping ( IIIOOo0o . eid , IIIOOo0o . group , [ ] )
   iIIiiiiI11i . add_cache ( )
   if 80 - 80: OOooOOo * O0 / iIii1I11I1II1 / IiII / OoOoOO00
   if 15 - 15: I1ii11iIi11i * iII111i + i11iIiiIii
   if 68 - 68: i1IIi / oO0o * I1ii11iIi11i - OoOoOO00 + Oo0Ooo / O0
   if 1 - 1: ooOoO0o - Oo0Ooo + I1Ii111
   if 90 - 90: I1Ii111 * O0 . iII111i - Oo0Ooo % iIii1I11I1II1
   if 7 - 7: I1ii11iIi11i % o0oOOo0O0Ooo % O0 % iIii1I11I1II1
   if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
  if ( iIIiiiiI11i . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( iIIiiiiI11i . print_eid_tuple ( ) , False ) ) )
   if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
   continue
   if 77 - 77: II111iiii - IiII % OOooOOo
   if 22 - 22: OoooooooOO / oO0o
  iIIiiiiI11i . mapping_source = None if source == "lisp-etr" else source
  iIIiiiiI11i . map_cache_ttl = IIIOOo0o . store_ttl ( )
  if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
  if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
  if 12 - 12: I1Ii111
  if 17 - 17: I1Ii111 % oO0o + O0
  if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
  if ( len ( iIIiiiiI11i . rloc_set ) != 0 and IIIOOo0o . rloc_count == 0 ) :
   iIIiiiiI11i . rloc_set = [ ]
   iIIiiiiI11i . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , iIIiiiiI11i )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( iIIiiiiI11i . print_eid_tuple ( ) , False ) ) )
   if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
   continue
   if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
   if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
  iIiI1III = iIIiiiiI11i . rtrs_in_rloc_set ( )
  if 86 - 86: Ii1I - o0oOOo0O0Ooo % iII111i
  if 37 - 37: Oo0Ooo
  if 87 - 87: I1ii11iIi11i . OoooooooOO . ooOoO0o + iIii1I11I1II1 + O0 % I1ii11iIi11i
  if 53 - 53: IiII
  if 96 - 96: Oo0Ooo . i11iIiiIii / Ii1I . I1ii11iIi11i % I1Ii111
  for oooOO0oooo00 in range ( IIIOOo0o . rloc_count ) :
   ooOooOo = lisp_rloc_record ( )
   I1i1IIiIIiIiIi = ooOooOo . decode ( I1i1IIiIIiIiIi , None )
   ooOooOo . print_record ( "    " )
   if ( IIIOOo0o . group . is_null ( ) ) : continue
   if ( ooOooOo . rle == None ) : continue
   if 68 - 68: ooOoO0o
   if 58 - 58: iII111i * I1IiiI
   if 82 - 82: Oo0Ooo / OoO0O00 % Oo0Ooo . ooOoO0o * O0
   if 39 - 39: I1Ii111 * IiII
   if 16 - 16: ooOoO0o + OoO0O00 / I11i * OoO0O00 . Oo0Ooo % OoOoOO00
   OO000 = iIIiiiiI11i . rloc_set [ 0 ] . stats if len ( iIIiiiiI11i . rloc_set ) != 0 else None
   if 30 - 30: Oo0Ooo % II111iiii % Oo0Ooo * o0oOOo0O0Ooo - Oo0Ooo
   if 23 - 23: iII111i
   if 96 - 96: oO0o . Ii1I / OoOoOO00 - O0 * iIii1I11I1II1 + Oo0Ooo
   if 35 - 35: Oo0Ooo - O0 * I11i % II111iiii % i11iIiiIii / I1IiiI
   IIIi1iI1 = lisp_rloc ( )
   IIIi1iI1 . store_rloc_from_record ( ooOooOo , None , iIIiiiiI11i . mapping_source )
   if ( OO000 != None ) : IIIi1iI1 . stats = copy . deepcopy ( OO000 )
   if 68 - 68: OoOoOO00 * ooOoO0o
   if ( iIiI1III and IIIi1iI1 . is_rtr ( ) == False ) : continue
   if 7 - 7: i11iIiiIii * i1IIi % I11i - IiII
   iIIiiiiI11i . rloc_set = [ IIIi1iI1 ]
   iIIiiiiI11i . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , iIIiiiiI11i )
   if 99 - 99: OoO0O00 * oO0o / Ii1I + OoO0O00
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( iIIiiiiI11i . print_eid_tuple ( ) , False ) ,
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
 Oo00oo = ii11i1IiI . decode ( orig_packet )
 if ( Oo00oo == None ) :
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
 I111 = source . print_address ( )
 if ( ii11i1IiI . alg_id != 0 or ii11i1IiI . auth_len != 0 ) :
  IIiiIiI = None
  for III in lisp_map_servers_list :
   if ( III . find ( I111 ) == - 1 ) : continue
   IIiiIiI = lisp_map_servers_list [ III ]
   if 75 - 75: ooOoO0o
  if ( IIiiIiI == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( I111 ) )
   if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
   return
   if 85 - 85: ooOoO0o
   if 29 - 29: iII111i . Ii1I
  IIiiIiI . map_notifies_received += 1
  if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
  O0o0OOO0 = lisp_verify_auth ( Oo00oo , ii11i1IiI . alg_id ,
 ii11i1IiI . auth_data , IIiiIiI . password )
  if 45 - 45: IiII
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if O0o0OOO0 else "failed" ) )
  if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
  if ( O0o0OOO0 == False ) : return
 else :
  IIiiIiI = lisp_ms ( I111 , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 9 - 9: iIii1I11I1II1 * Ii1I / O0 - OOooOOo
  if 95 - 95: i11iIiiIii * II111iiii * OOooOOo * iIii1I11I1II1
  if 22 - 22: iIii1I11I1II1 / I1IiiI + OoOoOO00 - OOooOOo . i11iIiiIii / i11iIiiIii
  if 10 - 10: iIii1I11I1II1 % i1IIi
  if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
  if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
 I1i1IIiIIiIiIi = ii11i1IiI . eid_records
 if ( ii11i1IiI . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , I1i1IIiIIiIiIi , ii11i1IiI , IIiiIiI )
  return
  if 44 - 44: I1ii11iIi11i
  if 39 - 39: iII111i + Oo0Ooo / oO0o
  if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
  if 99 - 99: I1IiiI * II111iiii
  if 84 - 84: II111iiii - I1IiiI
  if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
  if 35 - 35: I11i + i1IIi
  if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
 IIIOOo0o = lisp_eid_record ( )
 Oo00oo = IIIOOo0o . decode ( I1i1IIiIIiIiIi )
 if ( Oo00oo == None ) : return
 if 97 - 97: oO0o % iIii1I11I1II1
 IIIOOo0o . print_record ( "  " , False )
 if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
 for oooOO0oooo00 in range ( IIIOOo0o . rloc_count ) :
  ooOooOo = lisp_rloc_record ( )
  Oo00oo = ooOooOo . decode ( Oo00oo , None )
  if ( Oo00oo == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 16 - 16: I1IiiI
  ooOooOo . print_record ( "    " )
  if 39 - 39: ooOoO0o * II111iiii
  if 90 - 90: OoooooooOO * ooOoO0o
  if 14 - 14: I1IiiI % i1IIi
  if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
  if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
 if ( IIIOOo0o . group . is_null ( ) == False ) :
  if 55 - 55: i1IIi
  if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
  if 88 - 88: O0
  if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
  if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( IIIOOo0o . print_eid_tuple ( ) , False ) ) )
  if 90 - 90: i11iIiiIii - iII111i * oO0o
  if 79 - 79: IiII
  OO = lisp_control_packet_ipc ( orig_packet , I111 , "lisp-itr" , 0 )
  lisp_ipc ( OO , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 38 - 38: I1Ii111
  if 56 - 56: i11iIiiIii
  if 58 - 58: i11iIiiIii / OoOoOO00
  if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  if 39 - 39: Oo0Ooo . OoO0O00
 lisp_send_map_notify_ack ( lisp_sockets , I1i1IIiIIiIiIi , ii11i1IiI , IIiiIiI )
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
 IIIOOo0o = lisp_eid_record ( )
 if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
 if ( IIIOOo0o . decode ( ii11i1IiI . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 94 - 94: IiII * i1IIi
 IIIOOo0o . print_record ( "  " , False )
 if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 i1iiii = IIIOOo0o . print_eid_tuple ( )
 if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
 if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
 if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
 if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
 if ( ii11i1IiI . alg_id != LISP_NONE_ALG_ID and ii11i1IiI . auth_len != 0 ) :
  IiiiI1i1 = lisp_sites_by_eid . lookup_cache ( IIIOOo0o . eid , True )
  if ( IiiiI1i1 == None ) :
   ii1i = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( ii1i , green ( i1iiii , False ) ) )
   if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
   return
   if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
  i1iIiII1II11i = IiiiI1i1 . site
  if 66 - 66: i1IIi
  if 98 - 98: Oo0Ooo / iIii1I11I1II1
  if 33 - 33: O0 - iII111i
  if 40 - 40: iII111i * I11i
  i1iIiII1II11i . map_notify_acks_received += 1
  if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  IiII11iI1 = ii11i1IiI . key_id
  if ( IiII11iI1 in i1iIiII1II11i . auth_key ) :
   iiIo0O0O0 = i1iIiII1II11i . auth_key [ IiII11iI1 ]
  else :
   iiIo0O0O0 = ""
   if 87 - 87: OoOoOO00
   if 30 - 30: IiII % OoOoOO00 + I1Ii111
  O0o0OOO0 = lisp_verify_auth ( packet , ii11i1IiI . alg_id ,
 ii11i1IiI . auth_data , iiIo0O0O0 )
  if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
  IiII11iI1 = "key-id {}" . format ( IiII11iI1 ) if IiII11iI1 == ii11i1IiI . key_id else "bad key-id {}" . format ( ii11i1IiI . key_id )
  if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
  if 87 - 87: I11i
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if O0o0OOO0 else "failed" , IiII11iI1 ) )
  if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
  if ( O0o0OOO0 == False ) : return
  if 72 - 72: OoO0O00 * Oo0Ooo - IiII
  if 74 - 74: Ii1I
  if 26 - 26: I11i . O0
  if 68 - 68: Ii1I
  if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
 if ( ii11i1IiI . retransmit_timer ) : ii11i1IiI . retransmit_timer . cancel ( )
 if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
 OO0O = source . print_address ( )
 III = ii11i1IiI . nonce_key
 if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
 if ( III in lisp_map_notify_queue ) :
  ii11i1IiI = lisp_map_notify_queue . pop ( III )
  if ( ii11i1IiI . retransmit_timer ) : ii11i1IiI . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( III ) )
  if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( ii11i1IiI . nonce_key , red ( OO0O , False ) ) )
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
 oOoOO0OO = False
 if ( group . is_null ( ) == False ) :
  oOoOO0OO = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 23 - 23: I1IiiI
 if ( oOoOO0OO == False ) :
  oOoOO0OO = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
  if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
 if ( oOoOO0OO ) :
  iiiiiiiiII1i = lisp_print_eid_tuple ( eid , group )
  O0o0O0Ooo000 = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 26 - 26: I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( iiiiiiiiII1i , False ) , s ,
  # i11iIiiIii * I1IiiI % OoooooooOO % iIii1I11I1II1 % IiII
 O0o0O0Ooo000 ) )
  if 20 - 20: ooOoO0o . O0 . Oo0Ooo . OoO0O00 / Oo0Ooo
 return ( oOoOO0OO )
 if 85 - 85: o0oOOo0O0Ooo / I11i - OoOoOO00 - o0oOOo0O0Ooo
 if 99 - 99: I11i - I11i + Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . oO0o
 if 30 - 30: IiII
 if 6 - 6: I1Ii111 % oO0o % I1ii11iIi11i
 if 36 - 36: IiII
 if 97 - 97: i1IIi % OoOoOO00 . Oo0Ooo - OoO0O00 - ooOoO0o
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 99 - 99: i11iIiiIii / I1Ii111 / I1IiiI * oO0o
 iIi = lisp_map_referral ( )
 packet = iIi . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 100 - 100: II111iiii * Ii1I . OoO0O00 . iII111i + i1IIi * I1IiiI
 iIi . print_map_referral ( )
 if 84 - 84: OoO0O00 + i1IIi
 I111 = source . print_address ( )
 o0Oo0o = iIi . nonce
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo * I1Ii111 % OoooooooOO % I11i
 if 48 - 48: o0oOOo0O0Ooo / OoO0O00
 if 45 - 45: OOooOOo
 if 57 - 57: iIii1I11I1II1 + IiII - I1IiiI
 for iIi1iIIIiIiI in range ( iIi . record_count ) :
  IIIOOo0o = lisp_eid_record ( )
  packet = IIIOOo0o . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 64 - 64: II111iiii . IiII / I1IiiI
  IIIOOo0o . print_record ( "  " , True )
  if 20 - 20: OoooooooOO - I1ii11iIi11i * I1ii11iIi11i * I1ii11iIi11i
  if 87 - 87: OoooooooOO * ooOoO0o
  if 6 - 6: I1Ii111 / ooOoO0o / OoooooooOO . iIii1I11I1II1
  if 68 - 68: OoO0O00
  III = str ( o0Oo0o )
  if ( III not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( o0Oo0o ) , I111 ) )
   if 26 - 26: I11i % i1IIi / iIii1I11I1II1 % IiII . iII111i + I1ii11iIi11i
   if 49 - 49: O0 . IiII + I1Ii111 - I11i % II111iiii
   continue
   if 15 - 15: O0 - OoOoOO00 % II111iiii + O0 % O0 + OoOoOO00
  OO0ooo000 = lisp_ddt_map_requestQ [ III ]
  if ( OO0ooo000 == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( o0Oo0o ) , I111 ) )
   if 34 - 34: I1Ii111
   continue
   if 69 - 69: iIii1I11I1II1 . OOooOOo % I11i
   if 28 - 28: I1Ii111 . ooOoO0o % I1IiiI
   if 62 - 62: II111iiii + ooOoO0o + I1IiiI
   if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
   if 13 - 13: I1ii11iIi11i
   if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
  if ( lisp_map_referral_loop ( OO0ooo000 , IIIOOo0o . eid , IIIOOo0o . group ,
 IIIOOo0o . action , I111 ) ) :
   OO0ooo000 . dequeue_map_request ( )
   continue
   if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
   if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
  OO0ooo000 . last_cached_prefix [ 0 ] = IIIOOo0o . eid
  OO0ooo000 . last_cached_prefix [ 1 ] = IIIOOo0o . group
  if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
  if 18 - 18: OoooooooOO - I1ii11iIi11i
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  if 79 - 79: OOooOOo + Oo0Ooo
  oo0o0OOoO = False
  iIIiii = lisp_referral_cache_lookup ( IIIOOo0o . eid , IIIOOo0o . group ,
 True )
  if ( iIIiii == None ) :
   oo0o0OOoO = True
   iIIiii = lisp_referral ( )
   iIIiii . eid = IIIOOo0o . eid
   iIIiii . group = IIIOOo0o . group
   if ( IIIOOo0o . ddt_incomplete == False ) : iIIiii . add_cache ( )
  elif ( iIIiii . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( iIIiii . print_eid_tuple ( ) , False ) ) )
   if 33 - 33: iIii1I11I1II1
   OO0ooo000 . dequeue_map_request ( )
   continue
   if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
   if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
  Oo0Oo00O000O = IIIOOo0o . action
  iIIiii . referral_source = source
  iIIiii . referral_type = Oo0Oo00O000O
  IiIIi = IIIOOo0o . store_ttl ( )
  iIIiii . referral_ttl = IiIIi
  iIIiii . expires = lisp_set_timestamp ( IiIIi )
  if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
  if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
  if 99 - 99: OOooOOo
  if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
  OOOoO = iIIiii . is_referral_negative ( )
  if ( I111 in iIIiii . referral_set ) :
   iiiIii = iIIiii . referral_set [ I111 ]
   if 39 - 39: IiII / oO0o % Ii1I
   if ( iiiIii . updown == False and OOOoO == False ) :
    iiiIii . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( I111 ) )
    if 62 - 62: I11i - o0oOOo0O0Ooo
   elif ( iiiIii . updown == True and OOOoO == True ) :
    iiiIii . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( I111 ) )
    if 82 - 82: I11i / I1ii11iIi11i + I1IiiI - iIii1I11I1II1
    if 45 - 45: ooOoO0o % ooOoO0o . I11i + i1IIi
    if 4 - 4: iII111i - i1IIi - OoOoOO00 - Oo0Ooo % iIii1I11I1II1
    if 61 - 61: I1Ii111
    if 26 - 26: OOooOOo + I1Ii111 * I1Ii111 / I11i % Oo0Ooo . OoooooooOO
    if 72 - 72: OoooooooOO - O0 . OoO0O00
    if 46 - 46: o0oOOo0O0Ooo % OoO0O00 + I11i % o0oOOo0O0Ooo + oO0o . Oo0Ooo
    if 58 - 58: I1Ii111 + I1ii11iIi11i
  o0o0oo = { }
  for III in iIIiii . referral_set : o0o0oo [ III ] = None
  if 39 - 39: i1IIi
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
  if 59 - 59: i1IIi
  if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
  for iIi1iIIIiIiI in range ( IIIOOo0o . rloc_count ) :
   ooOooOo = lisp_rloc_record ( )
   packet = ooOooOo . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
   ooOooOo . print_record ( "    " )
   if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
   if 71 - 71: OOooOOo
   if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
   if 73 - 73: iII111i / I1IiiI * ooOoO0o
   O0O0 = ooOooOo . rloc . print_address ( )
   if ( O0O0 not in iIIiii . referral_set ) :
    iiiIii = lisp_referral_node ( )
    iiiIii . referral_address . copy_address ( ooOooOo . rloc )
    iIIiii . referral_set [ O0O0 ] = iiiIii
    if ( I111 == O0O0 and OOOoO ) : iiiIii . updown = False
   else :
    iiiIii = iIIiii . referral_set [ O0O0 ]
    if ( O0O0 in o0o0oo ) : o0o0oo . pop ( O0O0 )
    if 85 - 85: I11i + I11i + oO0o - OoOoOO00
   iiiIii . priority = ooOooOo . priority
   iiiIii . weight = ooOooOo . weight
   if 15 - 15: OoO0O00
   if 88 - 88: Ii1I % i1IIi / I1Ii111
   if 2 - 2: Ii1I . IiII % OoOoOO00
   if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
   if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
  for III in o0o0oo : iIIiii . referral_set . pop ( III )
  if 35 - 35: i11iIiiIii
  i1iiii = iIIiii . print_eid_tuple ( )
  if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
  if ( oo0o0OOoO ) :
   if ( IIIOOo0o . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( i1iiii , False ) ) )
    if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( i1iiii , False ) , IIIOOo0o . rloc_count ) )
    if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
    if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( i1iiii , False ) , IIIOOo0o . rloc_count ) )
   if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
   if 12 - 12: i11iIiiIii / Ii1I + i1IIi
   if 54 - 54: I1IiiI
   if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
   if 37 - 37: Oo0Ooo
   if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
  if ( Oo0Oo00O000O == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( OO0ooo000 . lisp_sockets , iIIiii . eid ,
 iIIiii . group , OO0ooo000 . nonce , OO0ooo000 . itr , OO0ooo000 . sport , 15 , None , False )
   OO0ooo000 . dequeue_map_request ( )
   if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
   if 19 - 19: O0 * II111iiii * OoOoOO00
  if ( Oo0Oo00O000O == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( OO0ooo000 . tried_root ) :
    lisp_send_negative_map_reply ( OO0ooo000 . lisp_sockets , iIIiii . eid ,
 iIIiii . group , OO0ooo000 . nonce , OO0ooo000 . itr , OO0ooo000 . sport , 0 , None , False )
    OO0ooo000 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( OO0ooo000 , True )
    if 53 - 53: Oo0Ooo
    if 16 - 16: Ii1I
    if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
  if ( Oo0Oo00O000O == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( I111 in iIIiii . referral_set ) :
    iiiIii = iIIiii . referral_set [ I111 ]
    iiiIii . updown = False
    if 78 - 78: OoO0O00 + oO0o
   if ( len ( iIIiii . referral_set ) == 0 ) :
    OO0ooo000 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( OO0ooo000 , False )
    if 86 - 86: ooOoO0o . ooOoO0o + oO0o
    if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
    if 31 - 31: IiII + iII111i
  if ( Oo0Oo00O000O in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( OO0ooo000 . eid . is_exact_match ( IIIOOo0o . eid ) ) :
    if ( not OO0ooo000 . tried_root ) :
     lisp_send_ddt_map_request ( OO0ooo000 , True )
    else :
     lisp_send_negative_map_reply ( OO0ooo000 . lisp_sockets ,
 iIIiii . eid , iIIiii . group , OO0ooo000 . nonce , OO0ooo000 . itr ,
 OO0ooo000 . sport , 15 , None , False )
     OO0ooo000 . dequeue_map_request ( )
     if 5 - 5: O0 * Ii1I
   else :
    lisp_send_ddt_map_request ( OO0ooo000 , False )
    if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
    if 77 - 77: OOooOOo / OoooooooOO
    if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
  if ( Oo0Oo00O000O == LISP_DDT_ACTION_MS_ACK ) : OO0ooo000 . dequeue_map_request ( )
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
 O000O = lisp_ecm ( 0 )
 packet = O000O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
  if 86 - 86: Ii1I / oO0o
 O000O . print_ecm ( )
 if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
 IiIii1iIIII = lisp_control_header ( )
 if ( IiIii1iIIII . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 60 - 60: II111iiii / Ii1I
  if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
 OoO0OOoo = IiIii1iIIII . type
 del ( IiIii1iIIII )
 if 68 - 68: iII111i + I1Ii111
 if ( OoO0OOoo != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 90 - 90: o0oOOo0O0Ooo
  if 48 - 48: iII111i + Ii1I
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
  if 67 - 67: oO0o
 OoOoo0oOOO = O000O . udp_sport
 ooO = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 O000O . source , OoOoo0oOOO , O000O . ddt , - 1 , ooO )
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
 IIi11ii = ms . map_server
 if ( lisp_decent_push_configured and IIi11ii . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  IIi11ii = copy . deepcopy ( IIi11ii )
  IIi11ii . address = 0x7f000001
  I11 = bold ( "Bootstrap" , False )
  Oo = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( I11 , Oo ) )
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
  oO0ooOOO = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( oO0ooOOO , ms . ekey_id ) )
  if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
  if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
 Iii1IIi11ii1i = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  Iii1IIi11ii1i = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 80 - 80: I1IiiI % Ii1I
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( IIi11ii . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , Iii1IIi11ii1i ) )
 if 38 - 38: IiII . I1Ii111
 lisp_send ( lisp_sockets , IIi11ii , LISP_CTRL_PORT , packet )
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
 O0oo0OoO0oo = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 69 - 69: iII111i % I1ii11iIi11i
 if 19 - 19: IiII
 packet = lisp_control_packet_ipc ( packet , O0oo0OoO0oo , dest , port )
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
  oooooO0oO0ooO = lisp_get_any_translated_port ( )
  if ( oooooO0oO0ooO != None ) : inner_sport = oooooO0oO0ooO
  if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
 O000O = lisp_ecm ( inner_sport )
 if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
 O000O . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 O000O . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 O000O . ddt = ddt
 ooO0ooO0OO = O000O . encode ( packet , inner_source , inner_dest )
 if ( ooO0ooO0OO == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 26 - 26: iIii1I11I1II1 % oO0o * I1Ii111 / OoooooooOO * I11i * OoooooooOO
 O000O . print_ecm ( )
 if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
 packet = ooO0ooO0OO + packet
 if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
 O0O0 = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( O0O0 ) )
 IIi11ii = lisp_convert_4to6 ( O0O0 )
 lisp_send ( lisp_sockets , IIi11ii , LISP_CTRL_PORT , packet )
 return
 if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
 if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
 if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
 if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
 if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
 if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
 if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
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
if 58 - 58: O0 * OOooOOo
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 60 - 60: ooOoO0o
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 47 - 47: i11iIiiIii
if 21 - 21: i1IIi - oO0o - Oo0Ooo
if 11 - 11: i1IIi
if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
if 56 - 56: Ii1I . iII111i
if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
if 52 - 52: i11iIiiIii
if 1 - 1: i1IIi * iIii1I11I1II1
if 29 - 29: I11i
if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
if 6 - 6: IiII / OoO0O00
def byte_swap_64 ( address ) :
 IiI = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
 if 77 - 77: Ii1I
 if 9 - 9: OOooOOo / OoooooooOO + iII111i
 if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
 if 20 - 20: I1Ii111
 if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
 if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 return ( IiI )
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
 if 42 - 42: I1Ii111 - ooOoO0o % o0oOOo0O0Ooo * I1IiiI . o0oOOo0O0Ooo
 if 84 - 84: iIii1I11I1II1
class lisp_cache_entries ( object ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 39 - 39: Ii1I . II111iiii / I1IiiI
  if 44 - 44: Ii1I / Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
  if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
class lisp_cache ( object ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 81 - 81: I1Ii111 % OoO0O00 / O0
  if 55 - 55: i1IIi - I1Ii111 + I11i
 def cache_size ( self ) :
  return ( self . cache_count )
  if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
  if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   Iii1iii1II = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   Iii1iii1II = prefix . mask_len
  else :
   Iii1iii1II = prefix . mask_len + 48
   if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
   if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
  oooo = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  i1I1iiiI = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    i1iIii = prefix . addr_length ( ) * 2
    IiI = lisp_hex_string ( prefix . address ) . zfill ( i1iIii )
   else :
    IiI = prefix . address
    if 24 - 24: Ii1I % II111iiii - i11iIiiIii
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   i1I1iiiI = "8003"
   IiI = prefix . address . print_geo ( )
  else :
   i1I1iiiI = ""
   IiI = ""
   if 52 - 52: OoO0O00
   if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
  III = oooo + i1I1iiiI + IiI
  return ( [ Iii1iii1II , III ] )
  if 50 - 50: IiII . i11iIiiIii % I11i
  if 22 - 22: i1IIi - II111iiii - OoOoOO00 . iII111i
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  Iii1iii1II , III = self . build_key ( prefix )
  if ( Iii1iii1II not in self . cache ) :
   self . cache [ Iii1iii1II ] = lisp_cache_entries ( )
   self . cache_sorted = self . sort_in_entry ( self . cache_sorted , Iii1iii1II )
   if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
  if ( III not in self . cache [ Iii1iii1II ] . entries ) :
   self . cache_count += 1
   if 34 - 34: iII111i . OoOoOO00
  self . cache [ Iii1iii1II ] . entries [ III ] = entry
  if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
 def lookup_cache ( self , prefix , exact ) :
  IiI1II11I1 , III = self . build_key ( prefix )
  if ( exact ) :
   if ( IiI1II11I1 not in self . cache ) : return ( None )
   if ( III not in self . cache [ IiI1II11I1 ] . entries ) : return ( None )
   return ( self . cache [ IiI1II11I1 ] . entries [ III ] )
   if 32 - 32: OOooOOo % I1Ii111 % OOooOOo % oO0o
   if 36 - 36: oO0o - I1Ii111
  OO0o0oo0oOo = None
  for Iii1iii1II in self . cache_sorted :
   if ( IiI1II11I1 < Iii1iii1II ) : return ( OO0o0oo0oOo )
   for oo0O00OOOOO in list ( self . cache [ Iii1iii1II ] . entries . values ( ) ) :
    if ( prefix . is_more_specific ( oo0O00OOOOO . eid ) ) :
     if ( OO0o0oo0oOo == None or
 oo0O00OOOOO . eid . is_more_specific ( OO0o0oo0oOo . eid ) ) : OO0o0oo0oOo = oo0O00OOOOO
     if 55 - 55: oO0o
     if 10 - 10: I1IiiI
     if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
  return ( OO0o0oo0oOo )
  if 34 - 34: OoooooooOO / iII111i / O0
  if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
 def delete_cache ( self , prefix ) :
  Iii1iii1II , III = self . build_key ( prefix )
  if ( Iii1iii1II not in self . cache ) : return
  if ( III not in self . cache [ Iii1iii1II ] . entries ) : return
  self . cache [ Iii1iii1II ] . entries . pop ( III )
  self . cache_count -= 1
  if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
  if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
 def walk_cache ( self , function , parms ) :
  for Iii1iii1II in self . cache_sorted :
   for oo0O00OOOOO in list ( self . cache [ Iii1iii1II ] . entries . values ( ) ) :
    i1iII1iI , parms = function ( oo0O00OOOOO , parms )
    if ( i1iII1iI == False ) : return ( parms )
    if 49 - 49: OOooOOo . i11iIiiIii
    if 31 - 31: OOooOOo / I1Ii111 / OoooooooOO * I11i . ooOoO0o
  return ( parms )
  if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
  if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
 def sort_in_entry ( self , table , value ) :
  if ( table == [ ] ) : return ( [ value ] )
  if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
  I1 = table
  while ( True ) :
   if ( len ( I1 ) == 1 ) :
    if ( value == I1 [ 0 ] ) : return ( table )
    OOOooo0OooOoO = table . index ( I1 [ 0 ] )
    if ( value < I1 [ 0 ] ) :
     return ( table [ 0 : OOOooo0OooOoO ] + [ value ] + table [ OOOooo0OooOoO : : ] )
     if 76 - 76: OoO0O00 * ooOoO0o
    if ( value > I1 [ 0 ] ) :
     return ( table [ 0 : OOOooo0OooOoO + 1 ] + [ value ] + table [ OOOooo0OooOoO + 1 : : ] )
     if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
     if 98 - 98: iII111i . II111iiii % O0
   OOOooo0OooOoO = old_div ( len ( I1 ) , 2 )
   I1 = I1 [ 0 : OOOooo0OooOoO ] if ( value < I1 [ OOOooo0OooOoO ] ) else I1 [ OOOooo0OooOoO : : ]
   if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
   if 17 - 17: OoooooooOO - i1IIi * I11i
  return ( [ ] )
  if 33 - 33: i1IIi . Oo0Ooo + I11i
  if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 78 - 78: I1Ii111 + I1Ii111
  for Iii1iii1II in self . cache_sorted :
   for III in self . cache [ Iii1iii1II ] . entries :
    oo0O00OOOOO = self . cache [ Iii1iii1II ] . entries [ III ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( Iii1iii1II , III ,
 oo0O00OOOOO ) )
    if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
    if 19 - 19: Ii1I
    if 51 - 51: oO0o
    if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
    if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
    if 70 - 70: I1ii11iIi11i . II111iiii
    if 54 - 54: OOooOOo
    if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 63 - 63: OoOoOO00 - OoOoOO00
if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
if 14 - 14: IiII . I11i
if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
def lisp_map_cache_lookup ( source , dest ) :
 if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
 Ooo0 = dest . is_multicast_address ( )
 if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
 if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
 if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
 if 9 - 9: iIii1I11I1II1
 iIIiiiiI11i = lisp_map_cache . lookup_cache ( dest , False )
 if ( iIIiiiiI11i == None ) :
  i1iiii = source . print_sg ( dest ) if Ooo0 else dest . print_address ( )
  i1iiii = green ( i1iiii , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( i1iiii ) )
  return ( None )
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
  if 34 - 34: iIii1I11I1II1
 if ( Ooo0 == False ) :
  oOOooo0 = green ( iIIiiiiI11i . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , oOOooo0 ) )
  if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
  return ( iIIiiiiI11i )
  if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
  if 20 - 20: OoO0O00
  if 93 - 93: ooOoO0o + o0oOOo0O0Ooo - I1ii11iIi11i
  if 56 - 56: Ii1I / Oo0Ooo
  if 96 - 96: o0oOOo0O0Ooo . II111iiii
 iIIiiiiI11i = iIIiiiiI11i . lookup_source_cache ( source , False )
 if ( iIIiiiiI11i == None ) :
  i1iiii = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( i1iiii ) )
  return ( None )
  if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
  if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
  if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
  if 6 - 6: OoooooooOO
  if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
 oOOooo0 = green ( iIIiiiiI11i . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , oOOooo0 ) )
 if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
 return ( iIIiiiiI11i )
 if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
 if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
 if 14 - 14: OOooOOo * IiII
 if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
 if 33 - 33: OoO0O00
 if 91 - 91: I11i % I11i % iII111i
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  i1OOOoO0O0O0O = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( i1OOOoO0O0O0O )
  if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
  if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
  if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
  if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
  if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
 if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
 if 42 - 42: i11iIiiIii / O0
 if 8 - 8: I1Ii111
 if 51 - 51: i11iIiiIii
 if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
 i1OOOoO0O0O0O = lisp_referral_cache . lookup_cache ( group , exact )
 if ( i1OOOoO0O0O0O == None ) : return ( None )
 if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
 iiiIIiIII111 = i1OOOoO0O0O0O . lookup_source_cache ( eid , exact )
 if ( iiiIIiIII111 ) : return ( iiiIIiIII111 )
 if 20 - 20: Oo0Ooo
 if ( exact ) : i1OOOoO0O0O0O = None
 return ( i1OOOoO0O0O0O )
 if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
 if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
 if 84 - 84: OOooOOo
 if 68 - 68: I1Ii111
 if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
 if 54 - 54: oO0o + I11i - OoO0O00
 if 86 - 86: OoooooooOO
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  IiI11111I1ii1 = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( IiI11111I1ii1 )
  if 51 - 51: i11iIiiIii
  if 91 - 91: OOooOOo
  if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
  if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
  if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
 if ( eid . is_null ( ) ) : return ( None )
 if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
 if 61 - 61: ooOoO0o / ooOoO0o
 if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
 if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 % OoooooooOO
 if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
 IiI11111I1ii1 = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( IiI11111I1ii1 == None ) : return ( None )
 if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
 O0Oo = IiI11111I1ii1 . lookup_source_cache ( eid , exact )
 if ( O0Oo ) : return ( O0Oo )
 if 5 - 5: I1IiiI + iII111i % OoOoOO00
 if ( exact ) : IiI11111I1ii1 = None
 return ( IiI11111I1ii1 )
 if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
 if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
 if 87 - 87: iII111i
 if 86 - 86: IiII - I11i
 if 99 - 99: i1IIi + I1ii11iIi11i
 if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
 if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 44 - 44: II111iiii / I1ii11iIi11i
 if ( group . is_null ( ) ) :
  IiiiI1i1 = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( IiiiI1i1 )
  if 39 - 39: OoooooooOO % OoO0O00
  if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
  if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
  if 29 - 29: IiII
  if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
 if ( eid . is_null ( ) ) : return ( None )
 if 91 - 91: I1Ii111 * iII111i * OoO0O00
 if 79 - 79: iII111i + oO0o
 if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
 if 97 - 97: O0 / OoOoOO00 / ooOoO0o
 if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
 if 10 - 10: OOooOOo * OoooooooOO
 IiiiI1i1 = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( IiiiI1i1 == None ) : return ( None )
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
 if 53 - 53: i11iIiiIii % I1ii11iIi11i
 if 59 - 59: OOooOOo
 if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
 I1IiiII1I1 = IiiiI1i1 . lookup_source_cache ( eid , exact )
 if ( I1IiiII1I1 ) : return ( I1IiiII1I1 )
 if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
 if ( exact ) :
  IiiiI1i1 = None
 else :
  i11I1Ii1 = IiiiI1i1 . parent_for_more_specifics
  if ( i11I1Ii1 and i11I1Ii1 . accept_more_specifics ) :
   if ( group . is_more_specific ( i11I1Ii1 . group ) ) : IiiiI1i1 = i11I1Ii1
   if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
   if 11 - 11: Ii1I - ooOoO0o % i11iIiiIii / OoooooooOO - O0 - IiII
 return ( IiiiI1i1 )
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
 if 36 - 36: IiII % I11i
 if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
 if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
class lisp_address ( object ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 82 - 82: OoooooooOO
  if 14 - 14: OoO0O00 / oO0o - OOooOOo
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
  if 16 - 16: IiII + Oo0Ooo % I11i
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 16 - 16: ooOoO0o / I1Ii111
  if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 54 - 54: iIii1I11I1II1 % ooOoO0o
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
   if 92 - 92: I11i + OoO0O00 . OoooooooOO
   if 3 - 3: OoO0O00 % iIii1I11I1II1
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
  if 59 - 59: iIii1I11I1II1
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  IiI = self . address
  if ( ( ( IiI & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( IiI & 0xff000000 ) >> 24 ) == 172 ) :
   I1iiIii11Ii = ( IiI & 0x00ff0000 ) >> 16
   if ( I1iiIii11Ii >= 16 and I1iiIii11Ii <= 31 ) : return ( True )
   if 48 - 48: o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  if ( ( ( IiI & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 63 - 63: I11i
  if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 44 - 44: OoooooooOO
  return ( 0 )
  if 18 - 18: i11iIiiIii
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  IiI = self . address >> 96
  return ( IiI == 0x20010005 )
  if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
  if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
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
   if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
  return ( 0 )
  if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
  if 53 - 53: OOooOOo % ooOoO0o
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
  if 83 - 83: OOooOOo * I1ii11iIi11i * iII111i * I1ii11iIi11i . OoO0O00
 def packet_format ( self ) :
  if 87 - 87: ooOoO0o . O0 - oO0o
  if 75 - 75: Oo0Ooo
  if 22 - 22: oO0o * I1Ii111 . II111iiii / Ii1I * O0
  if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
  if 35 - 35: I1Ii111
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
  if 12 - 12: Oo0Ooo + I1IiiI
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
   iIi1 = IiI & 0xffff
   Oo00oo = struct . pack ( iiII1iiI , IiIiI , iI1Ii11 , iIi1 )
  elif ( self . is_e164 ( ) ) :
   IiI = self . address
   IiIiI = ( IiI >> 32 ) & 0xffffffff
   iI1Ii11 = ( IiI & 0xffffffff )
   Oo00oo = struct . pack ( iiII1iiI , IiIiI , iI1Ii11 )
  elif ( self . is_dist_name ( ) ) :
   Oo00oo += ( self . address + "\0" ) . encode ( )
   if 75 - 75: O0 - iIii1I11I1II1 . i1IIi * II111iiii . II111iiii
  return ( Oo00oo )
  if 16 - 16: I1Ii111 / I1IiiI % OOooOOo
  if 61 - 61: I1ii11iIi11i . OOooOOo - O0 * OoOoOO00
 def unpack_address ( self , packet ) :
  iiII1iiI = self . packet_format ( )
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 12 - 12: I1ii11iIi11i / I1Ii111
  IiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 5 - 5: Oo0Ooo / o0oOOo0O0Ooo % i11iIiiIii - ooOoO0o
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( IiI [ 0 ] )
   if 62 - 62: i11iIiiIii
  elif ( self . is_ipv6 ( ) ) :
   if 88 - 88: i11iIiiIii
   if 59 - 59: oO0o - OoooooooOO % ooOoO0o
   if 90 - 90: OoOoOO00
   if 96 - 96: II111iiii % Ii1I
   if 84 - 84: I1IiiI . I1IiiI
   if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
   if 45 - 45: iII111i . oO0o * iII111i
   if 3 - 3: OoOoOO00 / Oo0Ooo - Oo0Ooo
   if ( IiI [ 0 ] <= 0xffff and ( IiI [ 0 ] & 0xff ) == 0 ) :
    OO0I11iI = ( IiI [ 0 ] << 48 ) << 64
   else :
    OO0I11iI = byte_swap_64 ( IiI [ 0 ] ) << 64
    if 52 - 52: OoO0O00 % I11i - oO0o . I11i % IiII
   OooOOoO0o0 = byte_swap_64 ( IiI [ 1 ] )
   self . address = OO0I11iI | OooOOoO0o0
   if 13 - 13: I1IiiI / iIii1I11I1II1 - I11i - iIii1I11I1II1 - OoOoOO00 % O0
  elif ( self . is_mac ( ) ) :
   i1oO00o = IiI [ 0 ]
   I1IoOo = IiI [ 1 ]
   iI1IIiI1i11Ii = IiI [ 2 ]
   self . address = ( i1oO00o << 32 ) + ( I1IoOo << 16 ) + iI1IIiI1i11Ii
   if 70 - 70: I1IiiI . I1IiiI - OoooooooOO - I11i
  elif ( self . is_e164 ( ) ) :
   self . address = ( IiI [ 0 ] << 32 ) + IiI [ 1 ]
   if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   ooo0000oo0 = 0
   if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
  packet = packet [ ooo0000oo0 : : ]
  return ( packet )
  if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
  if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 14 - 14: iIii1I11I1II1
  if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
  if 84 - 84: OoO0O00 % OoooooooOO
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 66 - 66: OoOoOO00 . iII111i
  if 1 - 1: iII111i * i1IIi . iIii1I11I1II1 % O0 - OoooooooOO
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 87 - 87: iII111i . Oo0Ooo * i11iIiiIii % o0oOOo0O0Ooo + Ii1I
  if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
  if 46 - 46: OoOoOO00
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 75 - 75: I1IiiI
  if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 14 - 14: i1IIi / ooOoO0o
  if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 16 - 16: O0
  if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
  if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
  if 19 - 19: o0oOOo0O0Ooo % I1Ii111 % I11i
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 1 - 1: I1IiiI / o0oOOo0O0Ooo - I1Ii111
  if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 26 - 26: IiII . Ii1I
  if 35 - 35: I1ii11iIi11i + OOooOOo
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 88 - 88: O0
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 4 - 4: OoOoOO00 % iIii1I11I1II1 % OoooooooOO . oO0o
  return ( False )
  if 27 - 27: II111iiii - OoOoOO00
  if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 27 - 27: Oo0Ooo
  if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
  if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
  if 22 - 22: O0 + ooOoO0o + I1Ii111
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
  if 85 - 85: I1IiiI * OoO0O00
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 63 - 63: I1IiiI - i11iIiiIii
  if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 64 - 64: OoOoOO00
  if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
  if 27 - 27: i11iIiiIii + iIii1I11I1II1
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 15 - 15: oO0o
  if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
  if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
  if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
  iIi1iIIIiIiI = addr_str . find ( "[" )
  oooOO0oooo00 = addr_str . find ( "]" )
  if ( iIi1iIIIiIiI != - 1 and oooOO0oooo00 != - 1 ) :
   self . instance_id = int ( addr_str [ iIi1iIIIiIiI + 1 : oooOO0oooo00 ] )
   addr_str = addr_str [ oooOO0oooo00 + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
    if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
    if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
    if 34 - 34: OoO0O00 * II111iiii
    if 43 - 43: OoOoOO00 . I1IiiI
    if 44 - 44: O0 / o0oOOo0O0Ooo
  if ( self . is_ipv4 ( ) ) :
   i1i11i1Iii = addr_str . split ( "." )
   oOO0 = int ( i1i11i1Iii [ 0 ] ) << 24
   oOO0 += int ( i1i11i1Iii [ 1 ] ) << 16
   oOO0 += int ( i1i11i1Iii [ 2 ] ) << 8
   oOO0 += int ( i1i11i1Iii [ 3 ] )
   self . address = oOO0
  elif ( self . is_ipv6 ( ) ) :
   if 11 - 11: I11i * Ii1I * I1IiiI - I1IiiI % OoooooooOO
   if 83 - 83: i11iIiiIii % iII111i * O0 % OoooooooOO
   if 99 - 99: I1ii11iIi11i % I1ii11iIi11i * iII111i % oO0o
   if 56 - 56: Oo0Ooo + i11iIiiIii - oO0o . Ii1I + IiII
   if 19 - 19: I11i * OoooooooOO . i1IIi
   if 100 - 100: II111iiii
   if 95 - 95: iII111i
   if 94 - 94: OoOoOO00 + OoooooooOO
   if 92 - 92: i11iIiiIii * IiII * I1IiiI - oO0o / iII111i
   if 1 - 1: ooOoO0o - OoO0O00 - o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i - I1Ii111
   if 78 - 78: Oo0Ooo
   if 27 - 27: Ii1I / oO0o - Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I
   if 79 - 79: Ii1I % O0 * OOooOOo
   if 41 - 41: I1ii11iIi11i . OoooooooOO * I1ii11iIi11i - oO0o
   if 40 - 40: I1IiiI % OoO0O00 + i11iIiiIii / oO0o
   if 98 - 98: oO0o + iIii1I11I1II1 . ooOoO0o / I1ii11iIi11i
   if 77 - 77: OoOoOO00 / Oo0Ooo * OoOoOO00 % I1IiiI . II111iiii % OoO0O00
   I1iIIii1 = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 12 - 12: Oo0Ooo % ooOoO0o % O0 . OoO0O00 + OoOoOO00 + OoooooooOO
   addr_str = binascii . hexlify ( addr_str )
   if 41 - 41: i1IIi % I1IiiI
   if ( I1iIIii1 ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 2 - 2: OOooOOo . I1ii11iIi11i % iIii1I11I1II1 / OOooOOo / O0 . O0
   self . address = int ( addr_str , 16 )
   if 75 - 75: O0
  elif ( self . is_geo_prefix ( ) ) :
   OOOooo = lisp_geo ( None )
   OOOooo . name = "geo-prefix-{}" . format ( OOOooo )
   OOOooo . parse_geo_string ( addr_str )
   self . address = OOOooo
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
   if 46 - 46: I1ii11iIi11i / ooOoO0o
  self . mask_len = self . host_mask_len ( )
  if 69 - 69: I1ii11iIi11i . IiII % o0oOOo0O0Ooo / OoooooooOO
  if 7 - 7: o0oOOo0O0Ooo % II111iiii
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   OOOooo0OooOoO = prefix_str . find ( "]" )
   I1iIii11iIi1I = len ( prefix_str [ OOOooo0OooOoO + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , I1iIii11iIi1I = prefix_str . split ( "/" )
  else :
   iIi1I1 = prefix_str . find ( "'" )
   if ( iIi1I1 == - 1 ) : return
   II = prefix_str . find ( "'" , iIi1I1 + 1 )
   if ( II == - 1 ) : return
   I1iIii11iIi1I = len ( prefix_str [ iIi1I1 + 1 : II ] ) * 8
   if 78 - 78: i11iIiiIii - I1ii11iIi11i + oO0o + II111iiii + OoooooooOO
   if 70 - 70: II111iiii
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( I1iIii11iIi1I )
  if 68 - 68: OoooooooOO . iIii1I11I1II1 - Ii1I / OoO0O00 / oO0o
  if 14 - 14: OOooOOo + iIii1I11I1II1 - Ii1I % I11i % OoO0O00 - i11iIiiIii
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  O0o0 = ( 2 ** self . mask_len ) - 1
  I1ii1iiI1I1I1 = self . addr_length ( ) * 8 - self . mask_len
  O0o0 <<= I1ii1iiI1I1I1
  self . address &= O0o0
  if 56 - 56: OoooooooOO * o0oOOo0O0Ooo
  if 42 - 42: Oo0Ooo
 def is_geo_string ( self , addr_str ) :
  OOOooo0OooOoO = addr_str . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : addr_str = addr_str [ OOOooo0OooOoO + 1 : : ]
  if 97 - 97: IiII / IiII . iII111i * O0 + II111iiii
  OOOooo = addr_str . split ( "/" )
  if ( len ( OOOooo ) == 2 ) :
   if ( OOOooo [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 33 - 33: oO0o * IiII / i11iIiiIii
  OOOooo = OOOooo [ 0 ]
  OOOooo = OOOooo . split ( "-" )
  o0o0o0o0 = len ( OOOooo )
  if ( o0o0o0o0 < 8 or o0o0o0o0 > 9 ) : return ( False )
  if 18 - 18: oO0o . I1ii11iIi11i % oO0o
  for IIi1IIi in range ( 0 , o0o0o0o0 ) :
   if ( IIi1IIi == 3 ) :
    if ( OOOooo [ IIi1IIi ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
   if ( IIi1IIi == 7 ) :
    if ( OOOooo [ IIi1IIi ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 8 - 8: O0 + o0oOOo0O0Ooo / O0 - I1ii11iIi11i % I1ii11iIi11i
   if ( OOOooo [ IIi1IIi ] . isdigit ( ) == False ) : return ( False )
   if 55 - 55: OoooooooOO * OoooooooOO % I1Ii111 / Ii1I / ooOoO0o
  return ( True )
  if 12 - 12: i11iIiiIii + Ii1I % iIii1I11I1II1 + I1Ii111
  if 12 - 12: Ii1I + I1Ii111 / O0 * II111iiii
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 67 - 67: iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111 * oO0o
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 100 - 100: OoooooooOO % I1IiiI / OoOoOO00 % OoOoOO00 . o0oOOo0O0Ooo
  if 81 - 81: Ii1I - II111iiii + I11i / Ii1I
 def print_address ( self ) :
  IiI = self . print_address_no_iid ( )
  oooo = "[" + str ( self . instance_id )
  for iIi1iIIIiIiI in self . iid_list : oooo += "," + str ( iIi1iIIIiIiI )
  oooo += "]"
  IiI = "{}{}" . format ( oooo , IiI )
  return ( IiI )
  if 89 - 89: i11iIiiIii + I1ii11iIi11i - ooOoO0o . ooOoO0o + Oo0Ooo % Ii1I
  if 96 - 96: I1Ii111 - I11i * I1Ii111
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IiI = self . address
   Iiii = IiI >> 24
   OoO00oO00O0 = ( IiI >> 16 ) & 0xff
   o0o00OOoO00Oo = ( IiI >> 8 ) & 0xff
   OoOo0 = IiI & 0xff
   return ( "{}.{}.{}.{}" . format ( Iiii , OoO00oO00O0 , o0o00OOoO00Oo , OoOo0 ) )
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
   if 16 - 16: IiII
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 70 - 70: OoO0O00 . I1IiiI - OoOoOO00 + i1IIi / IiII . OoOoOO00
  if 31 - 31: Ii1I % Ii1I
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   o00OO00Oo0 = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , o00OO00Oo0 ) )
   if 98 - 98: iIii1I11I1II1 - I11i % i11iIiiIii * I1IiiI / OoOoOO00 * ooOoO0o
  IiI = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( IiI )
  if ( self . is_geo_prefix ( ) ) : return ( IiI )
  if 78 - 78: i11iIiiIii % oO0o % Ii1I / I1Ii111 / I1Ii111
  OOOooo0OooOoO = IiI . find ( "no-address" )
  if ( OOOooo0OooOoO == - 1 ) :
   IiI = "{}/{}" . format ( IiI , str ( self . mask_len ) )
  else :
   IiI = IiI [ 0 : OOOooo0OooOoO ]
   if 20 - 20: iII111i / I11i / iIii1I11I1II1
  return ( IiI )
  if 94 - 94: i11iIiiIii % I1ii11iIi11i % IiII - I1Ii111
  if 55 - 55: I11i - ooOoO0o - iIii1I11I1II1 + I1ii11iIi11i / IiII
 def print_prefix_no_iid ( self ) :
  IiI = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( IiI )
  if ( self . is_geo_prefix ( ) ) : return ( IiI )
  return ( "{}/{}" . format ( IiI , str ( self . mask_len ) ) )
  if 49 - 49: I1ii11iIi11i
  if 91 - 91: OOooOOo % iII111i
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  IiI = self . print_address ( )
  OOOooo0OooOoO = IiI . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : IiI = IiI [ OOOooo0OooOoO + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   IiI = IiI . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , IiI ) )
   if 40 - 40: i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i1IIi . O0
  return ( "{}-{}-{}" . format ( self . instance_id , IiI , self . mask_len ) )
  if 39 - 39: I1ii11iIi11i
  if 26 - 26: oO0o . I1Ii111 % I11i
 def print_sg ( self , g ) :
  I111 = self . print_prefix ( )
  OooOo = I111 . find ( "]" ) + 1
  g = g . print_prefix ( )
  i1iii = g . find ( "]" ) + 1
  i1iIiIii = "[{}]({}, {})" . format ( self . instance_id , I111 [ OooOo : : ] , g [ i1iii : : ] )
  return ( i1iIiIii )
  if 51 - 51: OoOoOO00
  if 34 - 34: i11iIiiIii * OoooooooOO
 def hash_address ( self , addr ) :
  IiIiI = self . address
  iI1Ii11 = addr . address
  if 74 - 74: OoooooooOO * iII111i % OOooOOo . OoooooooOO * I11i % I1Ii111
  if ( self . is_geo_prefix ( ) ) : IiIiI = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : iI1Ii11 = addr . address . print_geo ( )
  if 67 - 67: I11i * i1IIi
  if ( type ( IiIiI ) == str ) :
   IiIiI = int ( binascii . hexlify ( IiIiI [ 0 : 1 ] ) )
   if 7 - 7: i1IIi * OoOoOO00 . Ii1I
  if ( type ( iI1Ii11 ) == str ) :
   iI1Ii11 = int ( binascii . hexlify ( iI1Ii11 [ 0 : 1 ] ) )
   if 80 - 80: OoOoOO00 + o0oOOo0O0Ooo - II111iiii
  return ( IiIiI ^ iI1Ii11 )
  if 3 - 3: ooOoO0o * I1Ii111
  if 34 - 34: Ii1I / Oo0Ooo . II111iiii - ooOoO0o - I1ii11iIi11i % OoOoOO00
  if 43 - 43: Ii1I * oO0o
  if 57 - 57: OoooooooOO + I1IiiI % I1ii11iIi11i % ooOoO0o * I1Ii111
  if 9 - 9: i11iIiiIii
  if 85 - 85: IiII / o0oOOo0O0Ooo * ooOoO0o
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 74 - 74: O0 - o0oOOo0O0Ooo
  I1iIii11iIi1I = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   oooOOo0o0ooO = 2 ** ( 32 - I1iIii11iIi1I )
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
   IiI = self . address
   O000 = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    IiI = self . address . print_geo ( )
    O000 = prefix . address . print_geo ( )
    if 12 - 12: OoooooooOO . OoooooooOO * I11i
   if ( len ( IiI ) < len ( O000 ) ) : return ( False )
   return ( IiI . find ( O000 ) == 0 )
   if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
   if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
   if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
   if 98 - 98: II111iiii - i1IIi - ooOoO0o
   if 36 - 36: IiII + o0oOOo0O0Ooo
  if ( self . mask_len < I1iIii11iIi1I ) : return ( False )
  if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
  I1ii1iiI1I1I1 = ( prefix . addr_length ( ) * 8 ) - I1iIii11iIi1I
  O0o0 = ( 2 ** I1iIii11iIi1I - 1 ) << I1ii1iiI1I1I1
  return ( ( self . address & O0o0 ) == prefix . address )
  if 10 - 10: oO0o / i11iIiiIii
  if 73 - 73: OoO0O00 - i1IIi
 def mask_address ( self , mask_len ) :
  I1ii1iiI1I1I1 = ( self . addr_length ( ) * 8 ) - mask_len
  O0o0 = ( 2 ** mask_len - 1 ) << I1ii1iiI1I1I1
  self . address &= O0o0
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
  oO000O0oO00 = LISP_LCAF_INSTANCE_ID_TYPE
  o0ooOo000oo = socket . htons ( self . lcaf_length ( oO000O0oO00 ) )
  oooo = self . instance_id
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
  I11Ii111iiii1 = struct . pack ( "BBBBH" , 0 , 0 , oO000O0oO00 , Iii1iii1II , o0ooOo000oo )
  I11Ii111iiii1 += struct . pack ( "IH" , socket . htonl ( oooo ) , socket . htons ( i1I1iiiI ) )
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
  iiII1iiI = "BBBBH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 92 - 92: iIii1I11I1II1
  I1iIiiI1IIi1 , II1ii1 , oO000O0oO00 , i1iIi , i1iIii = struct . unpack ( iiII1iiI ,
 packet [ : ooo0000oo0 ] )
  packet = packet [ ooo0000oo0 : : ]
  if 84 - 84: iII111i - ooOoO0o
  if ( oO000O0oO00 != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 23 - 23: Oo0Ooo / I11i - OOooOOo
  iiII1iiI = "IH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( None )
  if 53 - 53: ooOoO0o / OoOoOO00 - OoooooooOO * oO0o
  oooo , i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  packet = packet [ ooo0000oo0 : : ]
  if 45 - 45: o0oOOo0O0Ooo . I1Ii111 % Ii1I
  i1iIii = socket . ntohs ( i1iIii )
  self . instance_id = socket . ntohl ( oooo )
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
   iiII1iiI = "BBBBH"
   ooo0000oo0 = struct . calcsize ( iiII1iiI )
   if ( len ( packet ) < ooo0000oo0 ) : return ( None )
   if 95 - 95: IiII - O0 * oO0o * O0
   Oo0OoooOoO0O0 , iIi1i , oO000O0oO00 , OooIiii1ii , I1ii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
   if 47 - 47: I1IiiI
   if 20 - 20: I1Ii111
   if ( oO000O0oO00 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
   I1ii = socket . ntohs ( I1ii )
   packet = packet [ ooo0000oo0 : : ]
   if ( I1ii > len ( packet ) ) : return ( None )
   if 73 - 73: OOooOOo / Oo0Ooo
   OOOooo = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = OOOooo
   packet = OOOooo . decode_geo ( packet , I1ii , OooIiii1ii )
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
  oO000O0oO00 = LISP_LCAF_MCAST_INFO_TYPE
  oooo = socket . htonl ( self . instance_id )
  o0ooOo000oo = socket . htons ( self . lcaf_length ( oO000O0oO00 ) )
  I11Ii111iiii1 = struct . pack ( "BBBBHIHBB" , 0 , 0 , oO000O0oO00 , 0 , o0ooOo000oo , oooo ,
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
  iiII1iiI = "BBBBHIHBB"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  I1iIiiI1IIi1 , II1ii1 , oO000O0oO00 , I1i , i1iIii , oooo , O00o00Oo0 , IiIIIi1 , i1II1iIi111I1 = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
  if 8 - 8: OOooOOo
  packet = packet [ ooo0000oo0 : : ]
  if 85 - 85: O0 % OOooOOo . Ii1I
  if ( oO000O0oO00 != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 74 - 74: I1ii11iIi11i - I1Ii111 + i11iIiiIii / I1Ii111 / OoooooooOO + o0oOOo0O0Ooo
  self . instance_id = socket . ntohl ( oooo )
  i1iIii = socket . ntohs ( i1iIii ) - 8
  if 23 - 23: Oo0Ooo
  if 91 - 91: I1Ii111
  if 59 - 59: i1IIi % OOooOOo
  if 81 - 81: i11iIiiIii / OoO0O00 * OoOoOO00 % iII111i - iIii1I11I1II1 + I1ii11iIi11i
  if 20 - 20: O0 . I1Ii111 * Ii1I * II111iiii
  iiII1iiI = "H"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  if ( i1iIii < ooo0000oo0 ) : return ( [ None , None ] )
  if 66 - 66: Ii1I % OoO0O00 % II111iiii - OOooOOo * o0oOOo0O0Ooo
  i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  i1iIii -= ooo0000oo0
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
  iiII1iiI = "H"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  if ( i1iIii < ooo0000oo0 ) : return ( [ None , None ] )
  if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
  i1I1iiiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  i1iIii -= ooo0000oo0
  iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  iiI . afi = socket . ntohs ( i1I1iiiI )
  iiI . mask_len = i1II1iIi111I1
  iiI . instance_id = self . instance_id
  o0ooOo000oo = self . addr_length ( )
  if ( i1iIii < o0ooOo000oo ) : return ( [ None , None ] )
  if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
  packet = iiI . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 64 - 64: i1IIi
  return ( [ packet , iiI ] )
  if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
  if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
 def lcaf_decode_eid ( self , packet ) :
  iiII1iiI = "BBB"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( [ None , None ] )
  if 5 - 5: OoOoOO00 % i1IIi
  if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
  if 76 - 76: Oo0Ooo + I1IiiI - O0
  if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
  if 73 - 73: Oo0Ooo . OoOoOO00
  I1i , iIi1i , oO000O0oO00 = struct . unpack ( iiII1iiI ,
 packet [ : ooo0000oo0 ] )
  if 50 - 50: IiII / o0oOOo0O0Ooo
  if ( oO000O0oO00 == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( oO000O0oO00 == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , iiI = self . lcaf_decode_sg ( packet )
   return ( [ packet , iiI ] )
  elif ( oO000O0oO00 == LISP_LCAF_GEO_COORD_TYPE ) :
   iiII1iiI = "BBBBH"
   ooo0000oo0 = struct . calcsize ( iiII1iiI )
   if ( len ( packet ) < ooo0000oo0 ) : return ( None )
   if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
   Oo0OoooOoO0O0 , iIi1i , oO000O0oO00 , OooIiii1ii , I1ii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] )
   if 52 - 52: O0
   if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
   if ( oO000O0oO00 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
   I1ii = socket . ntohs ( I1ii )
   packet = packet [ ooo0000oo0 : : ]
   if ( I1ii > len ( packet ) ) : return ( None )
   if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
   OOOooo = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = OOOooo
   packet = OOOooo . decode_geo ( packet , I1ii , OooIiii1ii )
   self . mask_len = self . host_mask_len ( )
   if 83 - 83: oO0o / OoO0O00
  return ( [ packet , None ] )
  if 34 - 34: OoooooooOO - i1IIi * O0
  if 83 - 83: I1IiiI + OoO0O00
  if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
  if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
  if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
  if 62 - 62: Ii1I / Oo0Ooo . OoO0O00 - OOooOOo
class lisp_elp_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 89 - 89: o0oOOo0O0Ooo % OoO0O00
  if 53 - 53: OoOoOO00 . ooOoO0o - OoO0O00
 def copy_elp_node ( self ) :
  o00Oo0 = lisp_elp_node ( )
  o00Oo0 . copy_address ( self . address )
  o00Oo0 . probe = self . probe
  o00Oo0 . strict = self . strict
  o00Oo0 . eid = self . eid
  o00Oo0 . we_are_last = self . we_are_last
  return ( o00Oo0 )
  if 26 - 26: ooOoO0o - oO0o + OOooOOo * Ii1I - I11i % I1IiiI
  if 73 - 73: ooOoO0o + Ii1I . O0 . iII111i
  if 77 - 77: OOooOOo % I1IiiI - iII111i % I1Ii111
class lisp_elp ( object ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
  if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
 def copy_elp ( self ) :
  Ii11111iiIi11 = lisp_elp ( self . elp_name )
  Ii11111iiIi11 . use_elp_node = self . use_elp_node
  Ii11111iiIi11 . we_are_last = self . we_are_last
  for o00Oo0 in self . elp_nodes :
   Ii11111iiIi11 . elp_nodes . append ( o00Oo0 . copy_elp_node ( ) )
   if 46 - 46: I1ii11iIi11i * ooOoO0o
  return ( Ii11111iiIi11 )
  if 4 - 4: I1Ii111 * II111iiii
  if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
 def print_elp ( self , want_marker ) :
  iiii1IIiIiI = ""
  for o00Oo0 in self . elp_nodes :
   IIii = ""
   if ( want_marker ) :
    if ( o00Oo0 == self . use_elp_node ) :
     IIii = "*"
    elif ( o00Oo0 . we_are_last ) :
     IIii = "x"
     if 56 - 56: II111iiii * iIii1I11I1II1 % I1ii11iIi11i
     if 83 - 83: i1IIi . i11iIiiIii / iII111i
   iiii1IIiIiI += "{}{}({}{}{}), " . format ( IIii ,
 o00Oo0 . address . print_address_no_iid ( ) ,
 "r" if o00Oo0 . eid else "R" , "P" if o00Oo0 . probe else "p" ,
 "S" if o00Oo0 . strict else "s" )
   if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
  return ( iiii1IIiIiI [ 0 : - 2 ] if iiii1IIiIiI != "" else "" )
  if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
  if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
 def select_elp_node ( self ) :
  Iii1 , O0O0O0O , ooO000OO = lisp_myrlocs
  OOOooo0OooOoO = None
  if 50 - 50: OoOoOO00 / iII111i . I1ii11iIi11i
  for o00Oo0 in self . elp_nodes :
   if ( Iii1 and o00Oo0 . address . is_exact_match ( Iii1 ) ) :
    OOOooo0OooOoO = self . elp_nodes . index ( o00Oo0 )
    break
    if 26 - 26: Oo0Ooo
   if ( O0O0O0O and o00Oo0 . address . is_exact_match ( O0O0O0O ) ) :
    OOOooo0OooOoO = self . elp_nodes . index ( o00Oo0 )
    break
    if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
    if 43 - 43: OoO0O00 * OoO0O00 * oO0o
    if 24 - 24: oO0o
    if 77 - 77: i11iIiiIii - I1Ii111 - I1ii11iIi11i * Oo0Ooo / i11iIiiIii
    if 79 - 79: Oo0Ooo % Oo0Ooo . oO0o + ooOoO0o * iII111i * I11i
    if 87 - 87: o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
    if 89 - 89: II111iiii
  if ( OOOooo0OooOoO == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   o00Oo0 . we_are_last = False
   return
   if 41 - 41: iIii1I11I1II1
   if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
   if 76 - 76: I1ii11iIi11i * i1IIi % oO0o
   if 80 - 80: i1IIi * II111iiii . O0 % I1ii11iIi11i / ooOoO0o
   if 58 - 58: I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
   if 24 - 24: I11i + I11i % I11i
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ OOOooo0OooOoO ] ) :
   self . use_elp_node = None
   o00Oo0 . we_are_last = True
   return
   if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
   if 21 - 21: II111iiii
   if 89 - 89: OOooOOo % i11iIiiIii * OoOoOO00 % oO0o / O0 * i1IIi
   if 16 - 16: IiII
   if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
  self . use_elp_node = self . elp_nodes [ OOOooo0OooOoO + 1 ]
  return
  if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
  if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
  if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
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
  if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
  if 99 - 99: i11iIiiIii - I1Ii111
 def copy_geo ( self ) :
  OOOooo = lisp_geo ( self . geo_name )
  OOOooo . latitude = self . latitude
  OOOooo . lat_mins = self . lat_mins
  OOOooo . lat_secs = self . lat_secs
  OOOooo . longitude = self . longitude
  OOOooo . long_mins = self . long_mins
  OOOooo . long_secs = self . long_secs
  OOOooo . altitude = self . altitude
  OOOooo . radius = self . radius
  return ( OOOooo )
  if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 54 - 54: II111iiii * I1IiiI
  if 49 - 49: I1ii11iIi11i
 def parse_geo_string ( self , geo_str ) :
  OOOooo0OooOoO = geo_str . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : geo_str = geo_str [ OOOooo0OooOoO + 1 : : ]
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
  I1OooO0o = "E" if self . longitude < 0 else "W"
  if 44 - 44: I11i . OoOoOO00 . I1Ii111 * II111iiii
  OooO0OO0o = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , oOOoO000 , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , I1OooO0o )
  if 1 - 1: iII111i % oO0o - i11iIiiIii . I11i % Ii1I
  if ( self . no_geo_altitude ( ) == False ) :
   OooO0OO0o += "-" + str ( self . altitude )
   if 86 - 86: iII111i / OoO0O00 % OoooooooOO
   if 37 - 37: iII111i % Ii1I
   if 87 - 87: ooOoO0o . iIii1I11I1II1
   if 99 - 99: Ii1I + OoooooooOO * IiII * i11iIiiIii - iIii1I11I1II1
   if 58 - 58: IiII % i1IIi . i11iIiiIii
  if ( self . radius != 0 ) : OooO0OO0o += "/{}" . format ( self . radius )
  return ( OooO0OO0o )
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
  OOOooo = self . print_geo ( )
  if ( self . radius == 0 ) :
   o0000O = self . geo_url ( )
   i1i111III1 = "<a href='{}'>{}</a>" . format ( o0000O , OOOooo )
  else :
   o0000O = OOOooo . replace ( "/" , "-" )
   i1i111III1 = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( o0000O , OOOooo )
   if 80 - 80: iIii1I11I1II1 . II111iiii
  return ( i1i111III1 )
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
  ooOOooooo0Oo = socket . htons ( LISP_AFI_LCAF )
  o0o0o0o0 = socket . htons ( 20 + 2 )
  iIi1i = 0
  if 50 - 50: oO0o % OoOoOO00 + I1IiiI
  ooOO00o = abs ( self . latitude )
  iii1I11I = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : iIi1i |= 0x40
  if 77 - 77: I1Ii111 / IiII - OoOoOO00 + I1Ii111 % Oo0Ooo
  iiiIIiII111I = abs ( self . longitude )
  OO00o0 = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : iIi1i |= 0x20
  if 42 - 42: O0 + oO0o - OoooooooOO - OoOoOO00 + O0
  IIii1I = 0
  if ( self . no_geo_altitude ( ) == False ) :
   IIii1I = socket . htonl ( self . altitude )
   iIi1i |= 0x10
   if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  oooO0OO0 = socket . htons ( self . radius )
  if ( oooO0OO0 != 0 ) : iIi1i |= 0x06
  if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  II11 = struct . pack ( "HBBBBH" , ooOOooooo0Oo , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , o0o0o0o0 )
  II11 += struct . pack ( "BBHBBHBBHIHHH" , iIi1i , 0 , 0 , ooOO00o , iii1I11I >> 16 ,
 socket . htons ( iii1I11I & 0x0ffff ) , iiiIIiII111I , OO00o0 >> 16 ,
 socket . htons ( OO00o0 & 0xffff ) , IIii1I , oooO0OO0 , 0 , 0 )
  if 23 - 23: OoOoOO00
  return ( II11 )
  if 54 - 54: i1IIi / I11i % O0 - Ii1I - Oo0Ooo - OoO0O00
  if 63 - 63: o0oOOo0O0Ooo
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  iiII1iiI = "BBHBBHBBHIHHH"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( lcaf_len < ooo0000oo0 ) : return ( None )
  if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
  iIi1i , Oo0OO0o , I11II , ooOO00o , o0o0000OoO0oO , iii1I11I , iiiIIiII111I , o00O0oOoO , OO00o0 , IIii1I , oooO0OO0 , i1iI , i1I1iiiI = struct . unpack ( iiII1iiI ,
  # OoooooooOO
 packet [ : ooo0000oo0 ] )
  if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
  if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
  if 42 - 42: OOooOOo
  i1I1iiiI = socket . ntohs ( i1I1iiiI )
  if ( i1I1iiiI == LISP_AFI_LCAF ) : return ( None )
  if 36 - 36: OoooooooOO + ooOoO0o + iII111i
  if ( iIi1i & 0x40 ) : ooOO00o = - ooOO00o
  self . latitude = ooOO00o
  ii1i11IiIi1 = old_div ( ( ( o0o0000OoO0oO << 16 ) | socket . ntohs ( iii1I11I ) ) , 1000 )
  self . lat_mins = old_div ( ii1i11IiIi1 , 60 )
  self . lat_secs = ii1i11IiIi1 % 60
  if 90 - 90: OoO0O00
  if ( iIi1i & 0x20 ) : iiiIIiII111I = - iiiIIiII111I
  self . longitude = iiiIIiII111I
  I1iI1I1 = old_div ( ( ( o00O0oOoO << 16 ) | socket . ntohs ( OO00o0 ) ) , 1000 )
  self . long_mins = old_div ( I1iI1I1 , 60 )
  self . long_secs = I1iI1I1 % 60
  if 96 - 96: IiII % iII111i . OoOoOO00 / oO0o . OoO0O00
  self . altitude = socket . ntohl ( IIii1I ) if ( iIi1i & 0x10 ) else - 1
  oooO0OO0 = socket . ntohs ( oooO0OO0 )
  self . radius = oooO0OO0 if ( iIi1i & 0x02 ) else oooO0OO0 * 1000
  if 85 - 85: iIii1I11I1II1 / OoOoOO00 * I1ii11iIi11i
  self . geo_name = None
  packet = packet [ ooo0000oo0 : : ]
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
class lisp_rle_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
  if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
 def copy_rle_node ( self ) :
  oO0oOOOO0oO0o0 = lisp_rle_node ( )
  oO0oOOOO0oO0o0 . address . copy_address ( self . address )
  oO0oOOOO0oO0o0 . level = self . level
  oO0oOOOO0oO0o0 . translated_port = self . translated_port
  oO0oOOOO0oO0o0 . rloc_name = self . rloc_name
  return ( oO0oOOOO0oO0o0 )
  if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 100 - 100: I11i - I1ii11iIi11i . i1IIi
  if 85 - 85: II111iiii
 def get_encap_keys ( self ) :
  ooO0 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  O0O0 = self . address . print_address_no_iid ( ) + ":" + ooO0
  if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
  try :
   iI1iiiiiii = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
   if ( iI1iiiiiii [ 1 ] ) : return ( iI1iiiiiii [ 1 ] . encrypt_key , iI1iiiiiii [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 4 - 4: I11i % I1IiiI
   if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
   if 96 - 96: OoOoOO00 % Ii1I
   if 50 - 50: IiII - II111iiii
class lisp_rle ( object ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
  if 13 - 13: II111iiii
 def copy_rle ( self ) :
  ooo0o0O = lisp_rle ( self . rle_name )
  for oO0oOOOO0oO0o0 in self . rle_nodes :
   ooo0o0O . rle_nodes . append ( oO0oOOOO0oO0o0 . copy_rle_node ( ) )
   if 14 - 14: i11iIiiIii . IiII
  ooo0o0O . build_forwarding_list ( )
  return ( ooo0o0O )
  if 70 - 70: Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
  if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
 def print_rle ( self , html , do_formatting ) :
  iIi111Ii1 = ""
  for oO0oOOOO0oO0o0 in self . rle_nodes :
   ooO0 = oO0oOOOO0oO0o0 . translated_port
   if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
   Ooo00oo = ""
   if ( oO0oOOOO0oO0o0 . rloc_name != None ) :
    Ooo00oo = oO0oOOOO0oO0o0 . rloc_name
    if ( do_formatting ) : Ooo00oo = blue ( Ooo00oo , html )
    Ooo00oo = "({})" . format ( Ooo00oo )
    if 39 - 39: OoO0O00 . II111iiii + iII111i + I1IiiI + ooOoO0o . OoooooooOO
    if 20 - 20: IiII * iII111i * I1Ii111 * I1ii11iIi11i * oO0o
   O0O0 = oO0oOOOO0oO0o0 . address . print_address_no_iid ( )
   if ( oO0oOOOO0oO0o0 . address . is_local ( ) ) : O0O0 = red ( O0O0 , html )
   iIi111Ii1 += "{}{}{}, " . format ( O0O0 , "" if ooO0 == 0 else ":" + str ( ooO0 ) , Ooo00oo )
   if 58 - 58: o0oOOo0O0Ooo
   if 5 - 5: O0
  return ( iIi111Ii1 [ 0 : - 2 ] if iIi111Ii1 != "" else "" )
  if 23 - 23: OOooOOo . i11iIiiIii % o0oOOo0O0Ooo - OoOoOO00 * OoooooooOO - OoO0O00
  if 51 - 51: iIii1I11I1II1 / I1ii11iIi11i
 def build_forwarding_list ( self ) :
  OoOo0Oo0 = - 1
  for oO0oOOOO0oO0o0 in self . rle_nodes :
   if ( OoOo0Oo0 == - 1 ) :
    if ( oO0oOOOO0oO0o0 . address . is_local ( ) ) : OoOo0Oo0 = oO0oOOOO0oO0o0 . level
   else :
    if ( oO0oOOOO0oO0o0 . level > OoOo0Oo0 ) : break
    if 83 - 83: ooOoO0o % I1IiiI - OoOoOO00 - I11i
    if 12 - 12: I1Ii111 . OoO0O00 + I11i * OoO0O00 - IiII + I11i
  OoOo0Oo0 = 0 if OoOo0Oo0 == - 1 else oO0oOOOO0oO0o0 . level
  if 98 - 98: iII111i . I1Ii111 * IiII - Ii1I * OoooooooOO
  self . rle_forwarding_list = [ ]
  for oO0oOOOO0oO0o0 in self . rle_nodes :
   if ( oO0oOOOO0oO0o0 . level == OoOo0Oo0 or ( OoOo0Oo0 == 0 and
 oO0oOOOO0oO0o0 . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and oO0oOOOO0oO0o0 . address . is_local ( ) ) :
     O0O0 = oO0oOOOO0oO0o0 . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( O0O0 ) )
     continue
     if 13 - 13: iII111i
    self . rle_forwarding_list . append ( oO0oOOOO0oO0o0 )
    if 76 - 76: iIii1I11I1II1 + Oo0Ooo
    if 40 - 40: oO0o % i1IIi % ooOoO0o . oO0o % oO0o
    if 69 - 69: OoooooooOO . oO0o / OoooooooOO / OoOoOO00
    if 41 - 41: ooOoO0o + o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * IiII
    if 96 - 96: IiII % O0 + Ii1I / o0oOOo0O0Ooo + I1ii11iIi11i * II111iiii
class lisp_json ( object ) :
 def __init__ ( self , name , string , encrypted = False , ms_encrypt = False ) :
  if 65 - 65: Ii1I * Oo0Ooo * Oo0Ooo . Ii1I
  if 4 - 4: i11iIiiIii - iIii1I11I1II1 % o0oOOo0O0Ooo * oO0o
  if 19 - 19: Ii1I
  if 47 - 47: IiII - IiII
  if ( type ( string ) == bytes ) : string = string . decode ( )
  if 33 - 33: ooOoO0o
  self . json_name = name
  self . json_encrypted = False
  try :
   json . loads ( string )
  except :
   lprint ( "Invalid JSON string: '{}'" . format ( string ) )
   string = '{ "?" : "?" }'
   if 23 - 23: I1Ii111 + OoO0O00
  self . json_string = string
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 - I1Ii111 % OOooOOo
  if 59 - 59: i1IIi
  if 38 - 38: Oo0Ooo . o0oOOo0O0Ooo % oO0o / i11iIiiIii * OoO0O00 % OoOoOO00
  if 18 - 18: OOooOOo
  if 12 - 12: I1Ii111 % II111iiii / o0oOOo0O0Ooo - iIii1I11I1II1 + II111iiii
  if 41 - 41: OOooOOo
  if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
  if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
  if 87 - 87: i1IIi / OoooooooOO
  if 68 - 68: I1Ii111 / iIii1I11I1II1
  if ( len ( lisp_ms_json_keys ) != 0 ) :
   if ( ms_encrypt == False ) : return
   self . json_key_id = list ( lisp_ms_json_keys . keys ( ) ) [ 0 ]
   self . json_key = lisp_ms_json_keys [ self . json_key_id ]
   self . encrypt_json ( )
   if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
   if 40 - 40: i11iIiiIii + OoooooooOO
  if ( lisp_log_id == "lig" and encrypted ) :
   III = os . getenv ( "LISP_JSON_KEY" )
   if ( III != None ) :
    OOOooo0OooOoO = - 1
    if ( III [ 0 ] == "[" and "]" in III ) :
     OOOooo0OooOoO = III . find ( "]" )
     self . json_key_id = int ( III [ 1 : OOOooo0OooOoO ] )
     if 2 - 2: o0oOOo0O0Ooo * OoO0O00
    self . json_key = III [ OOOooo0OooOoO + 1 : : ]
    if 88 - 88: Oo0Ooo + oO0o + iII111i
    self . decrypt_json ( )
    if 51 - 51: i1IIi + i11iIiiIii * I11i / iII111i + OoooooooOO
    if 89 - 89: i11iIiiIii - I1Ii111 - O0 % iIii1I11I1II1 / IiII - O0
    if 63 - 63: OOooOOo
    if 23 - 23: Oo0Ooo / i1IIi - OOooOOo / Oo0Ooo
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 16 - 16: o0oOOo0O0Ooo - iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i + IiII
  if 73 - 73: OOooOOo % I1Ii111 + OoooooooOO / I1ii11iIi11i * oO0o % oO0o
 def delete ( self ) :
  if ( self . json_name in lisp_json_list ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 25 - 25: I1Ii111
   if 93 - 93: OoO0O00
   if 62 - 62: Oo0Ooo . iII111i
 def print_json ( self , html ) :
  iiI1IIii1IIi1 = self . json_string
  III11i1 = "***"
  if ( html ) : III11i1 = red ( III11i1 , html )
  OoO0o0oOoOo = III11i1 + self . json_string + III11i1
  if ( self . valid_json ( ) ) : return ( iiI1IIii1IIi1 )
  return ( OoO0o0oOoOo )
  if 30 - 30: II111iiii / OOooOOo
  if 42 - 42: IiII + OoO0O00 . i1IIi
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 88 - 88: OoooooooOO
  return ( True )
  if 47 - 47: OOooOOo + Oo0Ooo * I11i
  if 8 - 8: Ii1I % i1IIi
 def encrypt_json ( self ) :
  OooOo0o = self . json_key . zfill ( 32 )
  OoOooO = "0" * 8
  if 29 - 29: oO0o % OoOoOO00 / OoOoOO00
  o0oO0o00O0 = json . loads ( self . json_string )
  for III in o0oO0o00O0 :
   oOO0 = o0oO0o00O0 [ III ]
   if ( type ( oOO0 ) != str ) : oOO0 = str ( oOO0 )
   oOO0 = chacha . ChaCha ( OooOo0o , OoOooO ) . encrypt ( oOO0 )
   o0oO0o00O0 [ III ] = binascii . hexlify ( oOO0 )
   if 97 - 97: Ii1I
  self . json_string = json . dumps ( o0oO0o00O0 )
  self . json_encrypted = True
  if 51 - 51: II111iiii . oO0o % iII111i
  if 47 - 47: II111iiii - iII111i * I1IiiI . IiII
 def decrypt_json ( self ) :
  OooOo0o = self . json_key . zfill ( 32 )
  OoOooO = "0" * 8
  if 41 - 41: OoOoOO00 / O0 + I1Ii111 . I1ii11iIi11i
  o0oO0o00O0 = json . loads ( self . json_string )
  for III in o0oO0o00O0 :
   oOO0 = binascii . unhexlify ( o0oO0o00O0 [ III ] )
   o0oO0o00O0 [ III ] = chacha . ChaCha ( OooOo0o , OoOooO ) . encrypt ( oOO0 )
   if 48 - 48: Ii1I . o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
  try :
   self . json_string = json . dumps ( o0oO0o00O0 )
   self . json_encrypted = False
  except :
   pass
   if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
   if 3 - 3: iIii1I11I1II1 + i11iIiiIii
   if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
   if 38 - 38: i11iIiiIii
   if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
   if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
   if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
class lisp_stats ( object ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 93 - 93: iII111i
  if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 32 - 32: II111iiii
  if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  i1i111Iiiiiii = time . time ( ) - self . last_increment
  return ( i1i111Iiiiiii <= 1 )
  if 41 - 41: iII111i . I1Ii111 - IiII / O0
  if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  i1i111Iiiiiii = time . time ( ) - self . last_increment
  return ( i1i111Iiiiiii <= 60 )
  if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
  if 25 - 25: Oo0Ooo * oO0o
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 78 - 78: OoOoOO00 / II111iiii
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 6 - 6: I1Ii111 . OoOoOO00
  return ( c1 , c2 )
  if 75 - 75: Oo0Ooo + I11i
  if 87 - 87: I1IiiI
 def normalize ( self , count ) :
  count = str ( count )
  IIIiIII = len ( count )
  if ( IIIiIII > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 3 - 3: OoOoOO00 * OOooOOo - IiII - II111iiii * oO0o
  if ( IIIiIII > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 23 - 23: I11i * I1ii11iIi11i . I11i
  if ( IIIiIII > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 70 - 70: i1IIi * I1ii11iIi11i . oO0o - I1IiiI * Ii1I * iII111i
  return ( count )
  if 11 - 11: Oo0Ooo + I1ii11iIi11i
  if 92 - 92: iII111i / II111iiii + i1IIi / I1ii11iIi11i
 def get_stats ( self , summary , html ) :
  O0O0O = self . last_rate_check
  I1IIiI1IIIii = self . last_packet_count
  oo0ooO0o0 = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 40 - 40: Ii1I - ooOoO0o + OoOoOO00 % o0oOOo0O0Ooo
  oO0OO00O = self . last_rate_check - O0O0O
  if ( oO0OO00O == 0 ) :
   ooO0O00o = 0
   o0ooOoooO0oOO = 0
  else :
   ooO0O00o = int ( old_div ( ( self . packet_count - I1IIiI1IIIii ) ,
 oO0OO00O ) )
   o0ooOoooO0oOO = old_div ( ( self . byte_count - oo0ooO0o0 ) , oO0OO00O )
   o0ooOoooO0oOO = old_div ( ( o0ooOoooO0oOO * 8 ) , 1000000 )
   o0ooOoooO0oOO = round ( o0ooOoooO0oOO , 2 )
   if 42 - 42: OoOoOO00 % OOooOOo * iII111i
   if 24 - 24: Oo0Ooo % i1IIi
   if 50 - 50: OoO0O00
   if 52 - 52: o0oOOo0O0Ooo + O0
   if 13 - 13: OoO0O00
  OO0O0O0oO0o0 = self . normalize ( self . packet_count )
  Oo0OOOooO0 = self . normalize ( self . byte_count )
  if 40 - 40: I1Ii111 - II111iiii . OOooOOo + OoO0O00 - I1IiiI * OoooooooOO
  if 16 - 16: I11i
  if 6 - 6: I1IiiI * I1Ii111 % I1IiiI - II111iiii . oO0o
  if 9 - 9: I1Ii111 . i11iIiiIii * I11i + o0oOOo0O0Ooo
  if 85 - 85: i11iIiiIii * iII111i
  if ( summary ) :
   I1111I1 = "<br>" if html else ""
   OO0O0O0oO0o0 , Oo0OOOooO0 = self . stat_colors ( OO0O0O0oO0o0 , Oo0OOOooO0 , html )
   oOi1I1I = "packet-count: {}{}byte-count: {}" . format ( OO0O0O0oO0o0 , I1111I1 , Oo0OOOooO0 )
   OO000 = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( ooO0O00o , o0ooOoooO0oOO )
   if 37 - 37: I11i . O0 - Oo0Ooo % iII111i
   if ( html != "" ) : OO000 = lisp_span ( oOi1I1I , OO000 )
  else :
   i1i111iIiii = str ( ooO0O00o )
   O000Oo = str ( o0ooOoooO0oOO )
   if ( html ) :
    OO0O0O0oO0o0 = lisp_print_cour ( OO0O0O0oO0o0 )
    i1i111iIiii = lisp_print_cour ( i1i111iIiii )
    Oo0OOOooO0 = lisp_print_cour ( Oo0OOOooO0 )
    O000Oo = lisp_print_cour ( O000Oo )
    if 56 - 56: O0 - i11iIiiIii / Ii1I % OOooOOo . ooOoO0o / OoOoOO00
   I1111I1 = "<br>" if html else ", "
   if 70 - 70: I1IiiI / Ii1I
   OO000 = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( OO0O0O0oO0o0 , I1111I1 , i1i111iIiii , I1111I1 , Oo0OOOooO0 , I1111I1 ,
   # Oo0Ooo + Oo0Ooo + oO0o % i1IIi / ooOoO0o
 O000Oo )
   if 24 - 24: i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1 . I1IiiI
  return ( OO000 )
  if 81 - 81: OoOoOO00 * OoOoOO00 + OOooOOo . I11i - oO0o
  if 85 - 85: O0 * I1IiiI . Oo0Ooo - IiII
  if 84 - 84: I1Ii111 . iIii1I11I1II1 . O0 * I1ii11iIi11i
  if 59 - 59: i1IIi . o0oOOo0O0Ooo . Oo0Ooo * I1Ii111 + OoooooooOO
  if 11 - 11: I11i * ooOoO0o % iIii1I11I1II1 - O0
  if 68 - 68: ooOoO0o * OoooooooOO - OoooooooOO
  if 59 - 59: Ii1I / I11i / I1Ii111 + IiII * I1ii11iIi11i
  if 18 - 18: O0
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 60 - 60: II111iiii % O0 - I1Ii111 / iII111i / I1IiiI
if 59 - 59: O0 / iIii1I11I1II1
if 49 - 49: O0 + I1IiiI
if 52 - 52: oO0o
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
  if 56 - 56: ooOoO0o
  if ( recurse == False ) : return
  if 94 - 94: OoOoOO00
  if 12 - 12: I11i * OoooooooOO + ooOoO0o
  if 16 - 16: IiII
  if 100 - 100: OoO0O00 % Oo0Ooo - OoooooooOO
  if 48 - 48: IiII / I11i * OoooooooOO
  if 1 - 1: I1ii11iIi11i + I11i
  O00oO0Ooo00O = lisp_get_default_route_next_hops ( )
  if ( O00oO0Ooo00O == [ ] or len ( O00oO0Ooo00O ) == 1 ) : return
  if 10 - 10: iII111i + iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  self . rloc_next_hop = O00oO0Ooo00O [ 0 ]
  i11iII11I1III = self
  for o0o0O0o0000 in O00oO0Ooo00O [ 1 : : ] :
   oo0oooOOO0 = lisp_rloc ( False )
   oo0oooOOO0 = copy . deepcopy ( self )
   oo0oooOOO0 . rloc_next_hop = o0o0O0o0000
   i11iII11I1III . next_rloc = oo0oooOOO0
   i11iII11I1III = oo0oooOOO0
   if 53 - 53: I1Ii111 . i11iIiiIii * i1IIi . Oo0Ooo + I11i * i11iIiiIii
   if 75 - 75: OoOoOO00 % OoooooooOO + OoOoOO00
   if 46 - 46: IiII
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 53 - 53: iII111i + oO0o % O0
  if 92 - 92: O0 / iIii1I11I1II1
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 72 - 72: o0oOOo0O0Ooo / iII111i - I1ii11iIi11i . II111iiii
  if 95 - 95: II111iiii / I11i / ooOoO0o - I1Ii111 % i11iIiiIii
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 53 - 53: iII111i
  if 45 - 45: OOooOOo * I1IiiI / oO0o . Ii1I - OoO0O00 % OOooOOo
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 40 - 40: I11i
  if 69 - 69: OoOoOO00 + OoOoOO00 + o0oOOo0O0Ooo / iIii1I11I1II1 * OoO0O00
  if 44 - 44: II111iiii / o0oOOo0O0Ooo
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
  if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
  if 79 - 79: ooOoO0o - O0
 def print_rloc ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , i1 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 56 - 56: ooOoO0o
  if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  i1Ii1iiI = self . rloc_name
  if ( cour ) : i1Ii1iiI = lisp_print_cour ( i1Ii1iiI )
  return ( 'rloc-name: {}' . format ( blue ( i1Ii1iiI , cour ) ) )
  if 60 - 60: IiII % i11iIiiIii / OOooOOo
  if 43 - 43: i11iIiiIii * II111iiii + ooOoO0o - OoooooooOO * II111iiii / OoO0O00
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  ooO0 = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 92 - 92: O0 - ooOoO0o % iII111i
  if 83 - 83: I1ii11iIi11i / OoOoOO00 % OoooooooOO
  if 54 - 54: I11i / I1IiiI * IiII - iII111i
  if 37 - 37: i1IIi * I1Ii111 / I11i * II111iiii + OoooooooOO . OoO0O00
  IIIi1iI1 = self . rloc
  if ( IIIi1iI1 . is_null ( ) == False ) :
   iIIi11I = lisp_get_nat_info ( IIIi1iI1 , self . rloc_name )
   if ( iIIi11I ) :
    ooO0 = iIIi11I . port
    O000OooOOooO = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    O0O0 = IIIi1iI1 . print_address_no_iid ( )
    IIIOo0O = red ( O0O0 , False )
    Ooo00O0O000o = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 42 - 42: I11i - i1IIi . Oo0Ooo - i1IIi
    if 87 - 87: O0 . o0oOOo0O0Ooo % OOooOOo / I11i - I1Ii111 % i11iIiiIii
    if 3 - 3: oO0o + iII111i + OOooOOo
    if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
    if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
    if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
    if ( iIIi11I . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( IIIOo0O , ooO0 , Ooo00O0O000o ) )
     if 84 - 84: i1IIi
     if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
     iIIi11I = None if ( iIIi11I == O000OooOOooO ) else O000OooOOooO
     if ( iIIi11I and iIIi11I . timed_out ( ) ) :
      ooO0 = iIIi11I . port
      IIIOo0O = red ( iIIi11I . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( IIIOo0O , ooO0 ,
      # IiII * iIii1I11I1II1 / Ii1I * OoOoOO00
 Ooo00O0O000o ) )
      iIIi11I = None
      if 58 - 58: IiII
      if 12 - 12: I1ii11iIi11i * iII111i / i11iIiiIii / OoOoOO00
      if 62 - 62: O0 - IiII + I1ii11iIi11i
      if 67 - 67: i1IIi + i11iIiiIii * I1ii11iIi11i / ooOoO0o * OoO0O00
      if 52 - 52: II111iiii / Ii1I - iII111i
      if 33 - 33: I1IiiI
      if 41 - 41: OoOoOO00 * i1IIi
    if ( iIIi11I ) :
     if ( iIIi11I . address != O0O0 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( IIIOo0O , red ( iIIi11I . address , False ) ) )
      if 94 - 94: I11i
      self . rloc . store_address ( iIIi11I . address )
      if 28 - 28: OOooOOo
     IIIOo0O = red ( iIIi11I . address , False )
     ooO0 = iIIi11I . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( IIIOo0O , ooO0 , Ooo00O0O000o ) )
     if 82 - 82: II111iiii
     self . store_translated_rloc ( IIIi1iI1 , ooO0 )
     if 66 - 66: iII111i % I1Ii111 * oO0o
     if 81 - 81: i11iIiiIii - O0 . iIii1I11I1II1 - I11i + iIii1I11I1II1
     if 50 - 50: Oo0Ooo . OoO0O00 + i11iIiiIii / i11iIiiIii
     if 27 - 27: OoOoOO00 - OoOoOO00 % II111iiii + i1IIi + I1IiiI
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 75 - 75: OoooooooOO . I11i - OoOoOO00
  if 93 - 93: OoOoOO00 . I1Ii111 % I1ii11iIi11i
  if 58 - 58: OoooooooOO . i1IIi . Oo0Ooo - o0oOOo0O0Ooo / oO0o * I1Ii111
  if 6 - 6: oO0o - OoO0O00
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for oO0oOOOO0oO0o0 in self . rle . rle_nodes :
    i1Ii1iiI = oO0oOOOO0oO0o0 . rloc_name
    iIIi11I = lisp_get_nat_info ( oO0oOOOO0oO0o0 . address , i1Ii1iiI )
    if ( iIIi11I == None ) : continue
    if 44 - 44: Oo0Ooo + I1ii11iIi11i % Oo0Ooo / I11i
    ooO0 = iIIi11I . port
    IIi1Ii = i1Ii1iiI
    if ( IIi1Ii ) : IIi1Ii = blue ( i1Ii1iiI , False )
    if 57 - 57: Oo0Ooo + Ii1I * OoooooooOO
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( ooO0 ,
    # O0 . OOooOOo
 oO0oOOOO0oO0o0 . address . print_address_no_iid ( ) , IIi1Ii ) )
    oO0oOOOO0oO0o0 . translated_port = ooO0
    if 14 - 14: i11iIiiIii * i11iIiiIii . I1ii11iIi11i + iII111i
    if 18 - 18: I11i
    if 46 - 46: I1IiiI . OoooooooOO / iIii1I11I1II1 - ooOoO0o * OOooOOo
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 55 - 55: o0oOOo0O0Ooo + iIii1I11I1II1 / I11i
  if 97 - 97: i11iIiiIii
  if 71 - 71: oO0o + Oo0Ooo
  if 7 - 7: OoOoOO00 / I1ii11iIi11i * i1IIi
  OoO00o0Ooo0o = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 93 - 93: iIii1I11I1II1 - II111iiii
  if ( rloc_record . keys != None and OoO00o0Ooo0o ) :
   III = rloc_record . keys [ 1 ]
   if ( III != None ) :
    O0O0 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( ooO0 )
    if 1 - 1: Ii1I / OoO0O00 % iIii1I11I1II1 / I1Ii111
    III . add_key_by_rloc ( O0O0 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( O0O0 , False ) ) )
    if 31 - 31: I11i
    if 89 - 89: IiII
    if 39 - 39: I1IiiI % OoOoOO00
  return ( ooO0 )
  if 69 - 69: ooOoO0o
  if 96 - 96: OoO0O00 . o0oOOo0O0Ooo - I1IiiI / oO0o
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 90 - 90: I1Ii111 / i1IIi + IiII . II111iiii
  if 42 - 42: I1ii11iIi11i . Oo0Ooo * I1IiiI / Oo0Ooo
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 83 - 83: i11iIiiIii / OoOoOO00
  if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 43 - 43: II111iiii - OoooooooOO
  return ( True )
  if 11 - 11: I1IiiI
  if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 64 - 64: OoO0O00 - OoO0O00
  if 93 - 93: Oo0Ooo . O0
  if 75 - 75: iII111i * II111iiii - I1IiiI
 def print_state_change ( self , new_state ) :
  iii1o00Oo0oOO0 = self . print_state ( )
  i1i111III1 = "{} -> {}" . format ( iii1o00Oo0oOO0 , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   i1i111III1 = bold ( i1i111III1 , False )
   if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
  return ( i1i111III1 )
  if 46 - 46: I1Ii111
  if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
  if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
 def print_recent_rloc_probe_rtts ( self ) :
  O0iIIiii1ii1III = str ( self . recent_rloc_probe_rtts )
  O0iIIiii1ii1III = O0iIIiii1ii1III . replace ( "-1" , "?" )
  return ( O0iIIiii1ii1III )
  if 91 - 91: OoOoOO00 * I1IiiI - Oo0Ooo
  if 36 - 36: O0 - IiII % iII111i
 def compute_rloc_probe_rtt ( self ) :
  i11iII11I1III = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  Oo0 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ i11iII11I1III ] + Oo0 [ 0 : - 1 ]
  if 14 - 14: OoOoOO00 + I11i
  if 83 - 83: O0 % O0 - oO0o * Oo0Ooo
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 28 - 28: I1Ii111
  if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
 def print_recent_rloc_probe_hops ( self ) :
  iiIIiIiiII = str ( self . recent_rloc_probe_hops )
  return ( iiIIiIiiII )
  if 23 - 23: II111iiii / iII111i
  if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 92 - 92: iIii1I11I1II1
  if ( from_ttl < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   II1II1 = "!"
  else :
   II1II1 = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 48 - 48: O0 / I1IiiI % II111iiii
   if 10 - 10: Ii1I / I1Ii111 / O0 - II111iiii % IiII - ooOoO0o
  i11iII11I1III = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + II1II1
  Oo0 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ i11iII11I1III ] + Oo0 [ 0 : - 1 ]
  if 48 - 48: OOooOOo * OoOoOO00 / oO0o + II111iiii - I1ii11iIi11i
  if 85 - 85: I1ii11iIi11i * OoooooooOO . OOooOOo * OOooOOo
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  IiI1i = lisp_decode_telemetry ( json_telemetry )
  if 47 - 47: IiII / o0oOOo0O0Ooo - IiII . I11i - I1Ii111 * o0oOOo0O0Ooo
  oOOo0 = round ( float ( IiI1i [ "etr-in" ] ) - float ( IiI1i [ "itr-out" ] ) , 3 )
  oOOOOooo0ooo = round ( float ( IiI1i [ "itr-in" ] ) - float ( IiI1i [ "etr-out" ] ) , 3 )
  if 87 - 87: Ii1I + o0oOOo0O0Ooo + OoooooooOO . Ii1I
  i11iII11I1III = self . rloc_probe_latency
  self . rloc_probe_latency = str ( oOOo0 ) + "/" + str ( oOOOOooo0ooo )
  Oo0 = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ i11iII11I1III ] + Oo0 [ 0 : - 1 ]
  if 73 - 73: o0oOOo0O0Ooo + OoooooooOO - I1Ii111 . iIii1I11I1II1
  if 25 - 25: OoooooooOO % I1ii11iIi11i % Oo0Ooo % i11iIiiIii
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 8 - 8: O0 - O0 % Ii1I
  if 22 - 22: OoOoOO00
 def print_recent_rloc_probe_latencies ( self ) :
  ooo0OOoO = str ( self . recent_rloc_probe_latencies )
  return ( ooo0OOoO )
  if 28 - 28: OOooOOo + OoO0O00 * Ii1I * O0 / I1IiiI
  if 99 - 99: Oo0Ooo + ooOoO0o - I1ii11iIi11i + I1Ii111 + Ii1I * I1IiiI
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  IIIi1iI1 = self
  while ( True ) :
   if ( IIIi1iI1 . last_rloc_probe_nonce == nonce ) : break
   IIIi1iI1 = IIIi1iI1 . next_rloc
   if ( IIIi1iI1 == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 68 - 68: OoO0O00
    return
    if 79 - 79: Ii1I . IiII + OoOoOO00
    if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
    if 71 - 71: Ii1I + IiII
    if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
    if 2 - 2: OoooooooOO / IiII % Oo0Ooo % iIii1I11I1II1
    if 62 - 62: oO0o
  IIIi1iI1 . last_rloc_probe_reply = ts
  IIIi1iI1 . compute_rloc_probe_rtt ( )
  IiIiiII1I = IIIi1iI1 . print_state_change ( "up" )
  if ( IIIi1iI1 . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( IIIi1iI1 . rloc , True )
   IIIi1iI1 . state = LISP_RLOC_UP_STATE
   IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
   iIIiiiiI11i = lisp_map_cache . lookup_cache ( eid , True )
   if ( iIIiiiiI11i ) : lisp_write_ipc_map_cache ( True , iIIiiiiI11i )
   if 53 - 53: OoO0O00 . I1ii11iIi11i / OoO0O00 % OoOoOO00
   if 43 - 43: OOooOOo + o0oOOo0O0Ooo
   if 44 - 44: o0oOOo0O0Ooo % OoO0O00 . OoooooooOO
   if 21 - 21: Oo0Ooo * Oo0Ooo - iII111i - O0
   if 87 - 87: OOooOOo / I1Ii111 - Ii1I + O0 - oO0o - O0
  IIIi1iI1 . store_rloc_probe_hops ( hc , ttl )
  if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
  if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
  if 3 - 3: ooOoO0o * Ii1I
  if 29 - 29: OoooooooOO + OOooOOo
  if ( jt ) : IIIi1iI1 . store_rloc_probe_latencies ( jt )
  if 68 - 68: O0 + IiII / iII111i - OoOoOO00
  iiIii11Ii = bold ( "RLOC-probe reply" , False )
  O0O0 = IIIi1iI1 . rloc . print_address_no_iid ( )
  iIIiiIii11I1i = bold ( str ( IIIi1iI1 . print_rloc_probe_rtt ( ) ) , False )
  iIIiiIi = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 21 - 21: II111iiii
  o0o0O0o0000 = ""
  if ( IIIi1iI1 . rloc_next_hop != None ) :
   IiI11I111 , IiI1iI = IIIi1iI1 . rloc_next_hop
   o0o0O0o0000 = ", nh {}({})" . format ( IiI1iI , IiI11I111 )
   if 17 - 17: Ii1I * i1IIi % OoO0O00
   if 12 - 12: I1ii11iIi11i
  ooOO00o = bold ( IIIi1iI1 . print_rloc_probe_latency ( ) , False )
  ooOO00o = ", latency {}" . format ( ooOO00o ) if jt else ""
  if 86 - 86: iIii1I11I1II1 % iII111i
  oO0ooOOO = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 80 - 80: Oo0Ooo
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( iiIii11Ii , red ( O0O0 , False ) , iIIiiIi , oO0ooOOO ,
  # I1ii11iIi11i / I1Ii111 . OoOoOO00
 IiIiiII1I , iIIiiIii11I1i , o0o0O0o0000 , str ( hc ) + "/" + str ( ttl ) , ooOO00o ) )
  if 97 - 97: i1IIi / Ii1I
  if ( IIIi1iI1 . rloc_next_hop == None ) : return
  if 38 - 38: O0 % I11i - I11i / iIii1I11I1II1 - II111iiii
  if 13 - 13: II111iiii * OoO0O00 - iIii1I11I1II1
  if 30 - 30: O0 - O0 - I1Ii111
  if 88 - 88: o0oOOo0O0Ooo % I1Ii111
  IIIi1iI1 = None
  Ii1II11 = None
  while ( True ) :
   IIIi1iI1 = self if IIIi1iI1 == None else IIIi1iI1 . next_rloc
   if ( IIIi1iI1 == None ) : break
   if ( IIIi1iI1 . up_state ( ) == False ) : continue
   if ( IIIi1iI1 . rloc_probe_rtt == - 1 ) : continue
   if 58 - 58: OoOoOO00 * I1Ii111 % i11iIiiIii + O0
   if ( Ii1II11 == None ) : Ii1II11 = IIIi1iI1
   if ( IIIi1iI1 . rloc_probe_rtt < Ii1II11 . rloc_probe_rtt ) : Ii1II11 = IIIi1iI1
   if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
   if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
  if ( Ii1II11 != None ) :
   IiI11I111 , IiI1iI = Ii1II11 . rloc_next_hop
   o0o0O0o0000 = bold ( "nh {}({})" . format ( IiI1iI , IiI11I111 ) , False )
   lprint ( "    Install host-route via best {}" . format ( o0o0O0o0000 ) )
   lisp_install_host_route ( O0O0 , None , False )
   lisp_install_host_route ( O0O0 , IiI1iI , True )
   if 15 - 15: I1ii11iIi11i
   if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
   if 56 - 56: I1IiiI . ooOoO0o
 def add_to_rloc_probe_list ( self , eid , group ) :
  O0O0 = self . rloc . print_address_no_iid ( )
  ooO0 = self . translated_port
  if ( ooO0 != 0 ) : O0O0 += ":" + str ( ooO0 )
  if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
  if ( O0O0 not in lisp_rloc_probe_list ) :
   lisp_rloc_probe_list [ O0O0 ] = [ ]
   if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
   if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
  if ( group . is_null ( ) ) : group . instance_id = 0
  for iiiI1I , oO0ooOOO , Oo in lisp_rloc_probe_list [ O0O0 ] :
   if ( oO0ooOOO . is_exact_match ( eid ) and Oo . is_exact_match ( group ) ) :
    if ( iiiI1I == self ) :
     if ( lisp_rloc_probe_list [ O0O0 ] == [ ] ) :
      lisp_rloc_probe_list . pop ( O0O0 )
      if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
     return
     if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
    lisp_rloc_probe_list [ O0O0 ] . remove ( [ iiiI1I , oO0ooOOO , Oo ] )
    break
    if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
    if 19 - 19: i11iIiiIii
  lisp_rloc_probe_list [ O0O0 ] . append ( [ self , eid , group ] )
  if 20 - 20: i11iIiiIii . II111iiii - I1ii11iIi11i / ooOoO0o % i11iIiiIii
  if 35 - 35: Oo0Ooo - I1ii11iIi11i . Oo0Ooo
  if 13 - 13: II111iiii / OoOoOO00 * iII111i % O0 % I1ii11iIi11i * i11iIiiIii
  if 92 - 92: i11iIiiIii + OoO0O00
  if 94 - 94: I1ii11iIi11i + OoO0O00 . II111iiii + oO0o . II111iiii
  IIIi1iI1 = lisp_rloc_probe_list [ O0O0 ] [ 0 ] [ 0 ]
  if ( IIIi1iI1 . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 96 - 96: i11iIiiIii
   if 66 - 66: ooOoO0o * iII111i - iII111i - O0 . o0oOOo0O0Ooo
   if 23 - 23: iIii1I11I1II1 / I11i % OoOoOO00 . OoO0O00
 def delete_from_rloc_probe_list ( self , eid , group ) :
  O0O0 = self . rloc . print_address_no_iid ( )
  ooO0 = self . translated_port
  if ( ooO0 != 0 ) : O0O0 += ":" + str ( ooO0 )
  if ( O0O0 not in lisp_rloc_probe_list ) : return
  if 90 - 90: iIii1I11I1II1 - OOooOOo . Ii1I % OoO0O00
  o0Ooooo0 = [ ]
  for oo0O00OOOOO in lisp_rloc_probe_list [ O0O0 ] :
   if ( oo0O00OOOOO [ 0 ] != self ) : continue
   if ( oo0O00OOOOO [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( oo0O00OOOOO [ 2 ] . is_exact_match ( group ) == False ) : continue
   o0Ooooo0 = oo0O00OOOOO
   break
   if 71 - 71: OoO0O00 + oO0o + o0oOOo0O0Ooo . iIii1I11I1II1 * I1Ii111
  if ( o0Ooooo0 == [ ] ) : return
  if 39 - 39: OoOoOO00 * oO0o
  try :
   lisp_rloc_probe_list [ O0O0 ] . remove ( o0Ooooo0 )
   if ( lisp_rloc_probe_list [ O0O0 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( O0O0 )
    if 62 - 62: OoOoOO00 / OoOoOO00 * OoO0O00
  except :
   return
   if 38 - 38: I1Ii111 + ooOoO0o % I11i
   if 22 - 22: I1Ii111 . Ii1I % I1Ii111 * I1IiiI / iIii1I11I1II1
   if 12 - 12: Oo0Ooo / IiII % ooOoO0o / iIii1I11I1II1 % O0 / i11iIiiIii
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  oOo0OOoooO = ""
  IIIi1iI1 = self
  while ( True ) :
   ooo0oOOOooOoO = IIIi1iI1 . last_rloc_probe
   if ( ooo0oOOOooOoO == None ) : ooo0oOOOooOoO = 0
   ooO0oO = IIIi1iI1 . last_rloc_probe_reply
   if ( ooO0oO == None ) : ooO0oO = 0
   iIIiiIii11I1i = IIIi1iI1 . print_rloc_probe_rtt ( )
   I111 = space ( 4 )
   if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
   if ( IIIi1iI1 . rloc_next_hop == None ) :
    oOo0OOoooO += "RLOC-Probing:\n"
   else :
    IiI11I111 , IiI1iI = IIIi1iI1 . rloc_next_hop
    oOo0OOoooO += "RLOC-Probing for nh {}({}):\n" . format ( IiI1iI , IiI11I111 )
    if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
    if 57 - 57: OoooooooOO . iIii1I11I1II1 % iII111i % Oo0Ooo
   oOo0OOoooO += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( I111 , lisp_print_elapsed ( ooo0oOOOooOoO ) ,
   # oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
 I111 , lisp_print_elapsed ( ooO0oO ) , iIIiiIii11I1i )
   if 81 - 81: o0oOOo0O0Ooo . OoOoOO00 . i11iIiiIii
   if ( trailing_linefeed ) : oOo0OOoooO += "\n"
   if 13 - 13: i1IIi
   IIIi1iI1 = IIIi1iI1 . next_rloc
   if ( IIIi1iI1 == None ) : break
   oOo0OOoooO += "\n"
   if 70 - 70: O0 / II111iiii
  return ( oOo0OOoooO )
  if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
  if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
 def get_encap_keys ( self ) :
  ooO0 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 77 - 77: i1IIi . I1IiiI
  O0O0 = self . rloc . print_address_no_iid ( ) + ":" + ooO0
  if 59 - 59: O0 + OoooooooOO - i1IIi
  try :
   iI1iiiiiii = lisp_crypto_keys_by_rloc_encap [ O0O0 ]
   if ( iI1iiiiiii [ 1 ] ) : return ( iI1iiiiiii [ 1 ] . encrypt_key , iI1iiiiiii [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
   if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
   if 12 - 12: I1IiiI
 def rloc_recent_rekey ( self ) :
  ooO0 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 99 - 99: II111iiii - OoOoOO00
  O0O0 = self . rloc . print_address_no_iid ( ) + ":" + ooO0
  if 22 - 22: i11iIiiIii * II111iiii
  try :
   III = lisp_crypto_keys_by_rloc_encap [ O0O0 ] [ 1 ]
   if ( III == None ) : return ( False )
   if ( III . last_rekey == None ) : return ( True )
   return ( time . time ( ) - III . last_rekey < 1 )
  except :
   return ( False )
   if 11 - 11: Oo0Ooo % i1IIi
   if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
   if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
   if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
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
  if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
  if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
 def print_mapping ( self , eid_indent , rloc_indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  iiI = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 8 - 8: OoooooooOO
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , iiI , i1 ,
 len ( self . rloc_set ) ) )
  for IIIi1iI1 in self . rloc_set : IIIi1iI1 . print_rloc ( rloc_indent )
  if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
  if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
  if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
 def print_ttl ( self ) :
  IiIIi = self . map_cache_ttl
  if ( IiIIi == None ) : return ( "forever" )
  if 76 - 76: OOooOOo % iII111i
  if ( IiIIi >= 3600 ) :
   if ( ( IiIIi % 3600 ) == 0 ) :
    IiIIi = str ( old_div ( IiIIi , 3600 ) ) + " hours"
   else :
    IiIIi = str ( IiIIi * 60 ) + " mins"
    if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
  elif ( IiIIi >= 60 ) :
   if ( ( IiIIi % 60 ) == 0 ) :
    IiIIi = str ( old_div ( IiIIi , 60 ) ) + " mins"
   else :
    IiIIi = str ( IiIIi ) + " secs"
    if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
  else :
   IiIIi = str ( IiIIi ) + " secs"
   if 81 - 81: iII111i % OOooOOo * oO0o
  return ( IiIIi )
  if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
  if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
  if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
  if 15 - 15: OOooOOo - OOooOOo - OoooooooOO * OoO0O00
 def refresh_multicast ( self ) :
  if 12 - 12: II111iiii * I1Ii111 / I1Ii111 * oO0o * Oo0Ooo
  if 17 - 17: OoOoOO00 % I1Ii111 / iII111i * I1Ii111
  if 96 - 96: Oo0Ooo % o0oOOo0O0Ooo . OoOoOO00 % i11iIiiIii / OoooooooOO
  if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
  if 86 - 86: i1IIi . oO0o % OOooOOo
  i1i111Iiiiiii = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  OO000OoOOOo = ( i1i111Iiiiiii in [ 0 , 1 , 2 ] )
  if ( OO000OoOOOo == False ) : return ( False )
  if 77 - 77: I1ii11iIi11i % o0oOOo0O0Ooo - I1IiiI - I1Ii111
  if 16 - 16: OoO0O00 . Ii1I
  if 19 - 19: II111iiii % I1IiiI - II111iiii / OoooooooOO
  if 4 - 4: I11i * OoOoOO00
  IiII1IIiI1i = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( IiII1IIiI1i ) : return ( False )
  if 3 - 3: iIii1I11I1II1 % oO0o . oO0o + IiII
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 36 - 36: OoOoOO00 * iIii1I11I1II1 + oO0o * IiII . IiII . OOooOOo
  if 64 - 64: I1ii11iIi11i / OoOoOO00 + O0 % i1IIi - ooOoO0o + o0oOOo0O0Ooo
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  i1i111Iiiiiii = time . time ( ) - self . last_refresh_time
  if ( i1i111Iiiiiii >= self . map_cache_ttl ) : return ( True )
  if 67 - 67: Oo0Ooo
  if 52 - 52: I1IiiI % I1Ii111 - i1IIi . o0oOOo0O0Ooo % I1ii11iIi11i
  if 34 - 34: o0oOOo0O0Ooo / OoOoOO00
  if 74 - 74: IiII + i1IIi . II111iiii
  if 1 - 1: Ii1I - o0oOOo0O0Ooo / i11iIiiIii
  iI1o00Ooo = self . map_cache_ttl - ( old_div ( self . map_cache_ttl , 10 ) )
  if ( i1i111Iiiiiii >= iI1o00Ooo ) : return ( True )
  return ( False )
  if 67 - 67: OOooOOo % OOooOOo
  if 8 - 8: Ii1I / ooOoO0o
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  i1i111Iiiiiii = time . time ( ) - self . stats . last_increment
  return ( i1i111Iiiiiii <= 60 )
  if 11 - 11: oO0o * OoooooooOO
  if 88 - 88: I1Ii111 % OOooOOo - iIii1I11I1II1 / I1ii11iIi11i
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
  if 81 - 81: Ii1I
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 87 - 87: O0 % iII111i
  if 57 - 57: Ii1I
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for IIIi1iI1 in self . best_rloc_set :
   IIIi1iI1 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 49 - 49: I11i
   if 22 - 22: Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
   if 42 - 42: O0
 def build_best_rloc_set ( self ) :
  oo0oooOooO = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 57 - 57: i1IIi / I11i + OoO0O00 * OOooOOo + OoooooooOO
  if 30 - 30: I1Ii111 . IiII . iIii1I11I1II1 % o0oOOo0O0Ooo + iIii1I11I1II1
  if 83 - 83: I1IiiI % OoOoOO00 - o0oOOo0O0Ooo
  if 85 - 85: OoO0O00 * I1IiiI - I1Ii111 . ooOoO0o * II111iiii
  OO000OOOOOoO = 256
  for IIIi1iI1 in self . rloc_set :
   if ( IIIi1iI1 . up_state ( ) ) : OO000OOOOOoO = min ( IIIi1iI1 . priority , OO000OOOOOoO )
   if 60 - 60: iII111i / oO0o
   if 98 - 98: OoOoOO00 / OOooOOo
   if 31 - 31: II111iiii % I11i - I11i
   if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
   if 100 - 100: i11iIiiIii - O0 . OoO0O00 / O0 - Ii1I - IiII
   if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
   if 66 - 66: II111iiii % I1IiiI
   if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
   if 96 - 96: I1ii11iIi11i
   if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
  for IIIi1iI1 in self . rloc_set :
   if ( IIIi1iI1 . priority <= OO000OOOOOoO ) :
    if ( IIIi1iI1 . unreach_state ( ) and IIIi1iI1 . last_rloc_probe == None ) :
     IIIi1iI1 . last_rloc_probe = lisp_get_timestamp ( )
     if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
    self . best_rloc_set . append ( IIIi1iI1 )
    if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
    if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
    if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
    if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
    if 35 - 35: II111iiii
    if 28 - 28: I1Ii111 + IiII + I1ii11iIi11i . Ii1I
    if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
    if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
  for IIIi1iI1 in oo0oooOooO :
   if ( IIIi1iI1 . priority < OO000OOOOOoO ) : continue
   IIIi1iI1 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
  for IIIi1iI1 in self . best_rloc_set :
   if ( IIIi1iI1 . rloc . is_null ( ) ) : continue
   IIIi1iI1 . add_to_rloc_probe_list ( self . eid , self . group )
   if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
   if 98 - 98: IiII
   if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  Oo00oo = lisp_packet . packet
  ooO0oOoO0O0 = lisp_packet . inner_version
  i1iIii = len ( self . best_rloc_set )
  if ( i1iIii == 0 ) :
   self . stats . increment ( len ( Oo00oo ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 53 - 53: oO0o - Ii1I
   if 24 - 24: oO0o
  O00oIi11I11iIi1i1 = 4 if lisp_load_split_pings else 0
  II1Iii1iI = lisp_packet . hash_ports ( )
  if ( ooO0oOoO0O0 == 4 ) :
   for iIi1iIIIiIiI in range ( 8 + O00oIi11I11iIi1i1 ) :
    II1Iii1iI = II1Iii1iI ^ struct . unpack ( "B" , Oo00oo [ iIi1iIIIiIiI + 12 : iIi1iIIIiIiI + 13 ] ) [ 0 ]
    if 95 - 95: OoO0O00 * i1IIi
  elif ( ooO0oOoO0O0 == 6 ) :
   for iIi1iIIIiIiI in range ( 0 , 32 + O00oIi11I11iIi1i1 , 4 ) :
    II1Iii1iI = II1Iii1iI ^ struct . unpack ( "I" , Oo00oo [ iIi1iIIIiIiI + 8 : iIi1iIIIiIiI + 12 ] ) [ 0 ]
    if 43 - 43: Oo0Ooo % iII111i % O0 + i1IIi
   II1Iii1iI = ( II1Iii1iI >> 16 ) + ( II1Iii1iI & 0xffff )
   II1Iii1iI = ( II1Iii1iI >> 8 ) + ( II1Iii1iI & 0xff )
  else :
   for iIi1iIIIiIiI in range ( 0 , 12 + O00oIi11I11iIi1i1 , 4 ) :
    II1Iii1iI = II1Iii1iI ^ struct . unpack ( "I" , Oo00oo [ iIi1iIIIiIiI : iIi1iIIIiIiI + 4 ] ) [ 0 ]
    if 45 - 45: ooOoO0o
    if 89 - 89: iIii1I11I1II1 . I1Ii111
    if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
  if ( lisp_data_plane_logging ) :
   O0ooo = [ ]
   for iiiI1I in self . best_rloc_set :
    if ( iiiI1I . rloc . is_null ( ) ) : continue
    O0ooo . append ( [ iiiI1I . rloc . print_address_no_iid ( ) , iiiI1I . print_state ( ) ] )
    if 33 - 33: Ii1I
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( II1Iii1iI ) , II1Iii1iI % i1iIii , red ( str ( O0ooo ) , False ) ) )
   if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
   if 40 - 40: I1IiiI / OOooOOo * Ii1I
   if 98 - 98: I1IiiI
   if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
   if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
   if 42 - 42: I1ii11iIi11i
  IIIi1iI1 = self . best_rloc_set [ II1Iii1iI % i1iIii ]
  if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
  if 14 - 14: I1ii11iIi11i . OoO0O00
  if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
  if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
  if 29 - 29: O0 + iII111i
  I111Ii1I1I1iI = lisp_get_echo_nonce ( IIIi1iI1 . rloc , None )
  if ( I111Ii1I1I1iI ) :
   I111Ii1I1I1iI . change_state ( IIIi1iI1 )
   if ( IIIi1iI1 . no_echoed_nonce_state ( ) ) :
    I111Ii1I1I1iI . request_nonce_sent = None
    if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
    if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
    if 76 - 76: OoooooooOO - O0
    if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
    if 32 - 32: O0 % O0
    if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
  if ( IIIi1iI1 . up_state ( ) == False ) :
   OOO0OOO0O00 = II1Iii1iI % i1iIii
   OOOooo0OooOoO = ( OOO0OOO0O00 + 1 ) % i1iIii
   while ( OOOooo0OooOoO != OOO0OOO0O00 ) :
    IIIi1iI1 = self . best_rloc_set [ OOOooo0OooOoO ]
    if ( IIIi1iI1 . up_state ( ) ) : break
    OOOooo0OooOoO = ( OOOooo0OooOoO + 1 ) % i1iIii
    if 94 - 94: i11iIiiIii - I1IiiI - OoOoOO00 . I1IiiI * I11i * OoooooooOO
   if ( OOOooo0OooOoO == OOO0OOO0O00 ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 39 - 39: OoooooooOO % i11iIiiIii / IiII - ooOoO0o
    if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
    if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
    if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
    if 11 - 11: OOooOOo
    if 25 - 25: i1IIi
  IIIi1iI1 . stats . increment ( len ( Oo00oo ) )
  if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
  if 75 - 75: iII111i
  if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
  if 22 - 22: OOooOOo
  if ( IIIi1iI1 . rle_name and IIIi1iI1 . rle == None ) :
   if ( IIIi1iI1 . rle_name in lisp_rle_list ) :
    IIIi1iI1 . rle = lisp_rle_list [ IIIi1iI1 . rle_name ]
    if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
    if 17 - 17: o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - i1IIi / I1IiiI
  if ( IIIi1iI1 . rle ) : return ( [ None , None , None , None , IIIi1iI1 . rle , None ] )
  if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
  if 100 - 100: iII111i - i11iIiiIii + OoO0O00
  if 50 - 50: II111iiii
  if 42 - 42: OOooOOo * I1Ii111
  if ( IIIi1iI1 . elp and IIIi1iI1 . elp . use_elp_node ) :
   return ( [ IIIi1iI1 . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
   if 91 - 91: iII111i . OoooooooOO
   if 90 - 90: i11iIiiIii - I1IiiI
   if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
   if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
  OoOooO00 = None if ( IIIi1iI1 . rloc . is_null ( ) ) else IIIi1iI1 . rloc
  ooO0 = IIIi1iI1 . translated_port
  Oo0Oo00O000O = self . action if ( OoOooO00 == None ) else None
  if 66 - 66: i1IIi + I1IiiI
  if 45 - 45: I1Ii111 . iII111i + OoO0O00 - O0
  if 71 - 71: Oo0Ooo + OOooOOo
  if 94 - 94: OOooOOo
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
  o0Oo0o = None
  if ( I111Ii1I1I1iI and I111Ii1I1I1iI . request_nonce_timeout ( ) == False ) :
   o0Oo0o = I111Ii1I1I1iI . get_request_or_echo_nonce ( ipc_socket , OoOooO00 )
   if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
   if 31 - 31: I11i . o0oOOo0O0Ooo
   if 82 - 82: I11i - Oo0Ooo
   if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
   if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
  return ( [ OoOooO00 , ooO0 , o0Oo0o , Oo0Oo00O000O , None , IIIi1iI1 ] )
  if 79 - 79: oO0o + IiII
  if 4 - 4: iII111i + OoooooooOO / I1Ii111
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
  if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
  if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
  if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
  if 97 - 97: i11iIiiIii / O0 % OoO0O00
  for iiIiIIi1I in self . rloc_set :
   for IIIi1iI1 in rloc_address_set :
    if ( IIIi1iI1 . is_exact_match ( iiIiIIi1I . rloc ) == False ) : continue
    IIIi1iI1 = None
    break
    if 88 - 88: i1IIi . I1IiiI
   if ( IIIi1iI1 == rloc_address_set [ - 1 ] ) : return ( False )
   if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
  return ( True )
  if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
  if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
 def get_rloc ( self , rloc ) :
  for iiIiIIi1I in self . rloc_set :
   iiiI1I = iiIiIIi1I . rloc
   if ( rloc . is_exact_match ( iiiI1I ) ) : return ( iiIiIIi1I )
   if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
  return ( None )
  if 84 - 84: I1IiiI + OOooOOo
  if 80 - 80: OOooOOo / OoOoOO00
 def get_rloc_by_interface ( self , interface ) :
  for iiIiIIi1I in self . rloc_set :
   if ( iiIiIIi1I . interface == interface ) : return ( iiIiIIi1I )
   if 93 - 93: OOooOOo
  return ( None )
  if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
  if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   oooOOoO0oo0 = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( oooOOoO0oo0 == None ) :
    oooOOoO0oo0 = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , oooOOoO0oo0 )
    if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
   oooOOoO0oo0 . add_source_entry ( self )
   if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
   if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
   if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   iIIiiiiI11i = lisp_map_cache . lookup_cache ( self . group , True )
   if ( iIIiiiiI11i == None ) :
    iIIiiiiI11i = lisp_mapping ( self . group , self . group , [ ] )
    iIIiiiiI11i . eid . copy_address ( self . group )
    iIIiiiiI11i . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , iIIiiiiI11i )
    if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( iIIiiiiI11i . group )
   iIIiiiiI11i . add_source_entry ( self )
   if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
  if 91 - 91: II111iiii * o0oOOo0O0Ooo
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    o00oO0ooO000 = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( o00oO0ooO000 ) )
    if 29 - 29: iII111i * IiII % II111iiii - i11iIiiIii / ooOoO0o . I11i
  else :
   iIIiiiiI11i = lisp_map_cache . lookup_cache ( self . group , True )
   if ( iIIiiiiI11i == None ) : return
   if 23 - 23: OoOoOO00 / ooOoO0o * IiII * OOooOOo / OOooOOo
   iI1III1111I1 = iIIiiiiI11i . lookup_source_cache ( self . eid , True )
   if ( iI1III1111I1 == None ) : return
   if 32 - 32: I1IiiI % oO0o
   iIIiiiiI11i . source_cache . delete_cache ( self . eid )
   if ( iIIiiiiI11i . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 32 - 32: OoooooooOO / O0 + Ii1I * oO0o % Oo0Ooo . OoooooooOO
    if 19 - 19: i1IIi - oO0o
    if 100 - 100: Ii1I
    if 73 - 73: IiII - O0
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 54 - 54: OOooOOo
  if 28 - 28: i1IIi - Oo0Ooo * OoO0O00 + OoooooooOO - Ii1I * i11iIiiIii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 71 - 71: iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 32 - 32: iIii1I11I1II1 . II111iiii / IiII % O0 / iII111i
  if 97 - 97: iIii1I11I1II1
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  oooo = "," + str ( self . secondary_iid )
  return ( prefix . replace ( oooo , oooo + "*" ) )
  if 18 - 18: OOooOOo
  if 87 - 87: O0 - i1IIi . I11i / Ii1I % iIii1I11I1II1
 def increment_decap_stats ( self , packet ) :
  ooO0 = packet . udp_dport
  if ( ooO0 == LISP_DATA_PORT ) :
   IIIi1iI1 = self . get_rloc ( packet . outer_dest )
  else :
   if 57 - 57: I11i . IiII / iIii1I11I1II1 - ooOoO0o
   if 50 - 50: O0 / II111iiii
   if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
   if 15 - 15: I1IiiI
   for IIIi1iI1 in self . rloc_set :
    if ( IIIi1iI1 . translated_port != 0 ) : break
    if 48 - 48: Ii1I * IiII % O0 - II111iiii
    if 66 - 66: iIii1I11I1II1 / OOooOOo
  if ( IIIi1iI1 != None ) : IIIi1iI1 . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
  if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
 def rtrs_in_rloc_set ( self ) :
  for IIIi1iI1 in self . rloc_set :
   if ( IIIi1iI1 . is_rtr ( ) ) : return ( True )
   if 67 - 67: I1Ii111
  return ( False )
  if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
  if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 46 - 46: I11i - ooOoO0o . I1IiiI
  if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
  if 90 - 90: i11iIiiIii / i1IIi
class lisp_dynamic_eid ( object ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
  if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
 def get_timeout ( self , interface ) :
  try :
   Oo0OOooOo00Oo = lisp_myinterfaces [ interface ]
   self . timeout = Oo0OOooOo00Oo . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 69 - 69: Ii1I
   if 75 - 75: I1IiiI
   if 55 - 55: i11iIiiIii - I1IiiI . oO0o - OoooooooOO
   if 44 - 44: I1Ii111
class lisp_group_mapping ( object ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 98 - 98: I1IiiI % OOooOOo % iII111i
  if 15 - 15: OoO0O00
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 52 - 52: II111iiii / ooOoO0o
  if 23 - 23: i11iIiiIii % OoO0O00 - o0oOOo0O0Ooo + OoooooooOO
  if 12 - 12: Ii1I / I1IiiI . oO0o . I1IiiI + ooOoO0o - II111iiii
  if 6 - 6: Oo0Ooo + Oo0Ooo - OoOoOO00 - II111iiii
  if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
  if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
  if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
  if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
  if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
  if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 oooo = group_mapping . group_prefix . instance_id
 I1iIii11iIi1I = group_mapping . group_prefix . mask_len
 iiI = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , oooo )
 if ( iiI . is_more_specific ( group_mapping . group_prefix ) ) : return ( I1iIii11iIi1I )
 return ( - 1 )
 if 92 - 92: I11i
 if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
 if 98 - 98: iII111i % IiII + OoO0O00
 if 23 - 23: OOooOOo
 if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
 if 99 - 99: II111iiii + O0
 if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
def lisp_lookup_group ( group ) :
 O0ooo = None
 for oO0O000Oo in list ( lisp_group_mapping_list . values ( ) ) :
  I1iIii11iIi1I = lisp_is_group_more_specific ( group , oO0O000Oo )
  if ( I1iIii11iIi1I == - 1 ) : continue
  if ( O0ooo == None or I1iIii11iIi1I > O0ooo . group_prefix . mask_len ) : O0ooo = oO0O000Oo
  if 22 - 22: Oo0Ooo + O0 + OoO0O00
 return ( O0ooo )
 if 83 - 83: i1IIi + OoooooooOO * IiII
 if 65 - 65: II111iiii / I1Ii111 + I1IiiI - OoooooooOO + ooOoO0o - I1ii11iIi11i
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 29 - 29: OoOoOO00 / OOooOOo / OoO0O00
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
  if 95 - 95: ooOoO0o
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
  if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
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
  if 32 - 32: OoOoOO00 % i11iIiiIii
  if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 44 - 44: I1Ii111 + ooOoO0o
  if 15 - 15: I11i + OoO0O00 + OoOoOO00
 def print_flags ( self , html ) :
  if ( html == False ) :
   oOo0OOoooO = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # I1Ii111 . i11iIiiIii % OoooooooOO + Ii1I % OOooOOo * OoO0O00
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   Oo0OoO00OO0 = self . print_flags ( False )
   Oo0OoO00OO0 = Oo0OoO00OO0 . split ( "-" )
   oOo0OOoooO = ""
   for oOOO00Ooo0oo0 in Oo0OoO00OO0 :
    o0Oo = lisp_site_flags [ oOOO00Ooo0oo0 . upper ( ) ]
    o0Oo = o0Oo . format ( "" if oOOO00Ooo0oo0 . isupper ( ) else "not " )
    oOo0OOoooO += lisp_span ( oOOO00Ooo0oo0 , o0Oo )
    if ( oOOO00Ooo0oo0 . lower ( ) != "n" ) : oOo0OOoooO += "-"
    if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
    if 53 - 53: I1ii11iIi11i
  return ( oOo0OOoooO )
  if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
  if 64 - 64: ooOoO0o
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 23 - 23: Oo0Ooo . OoO0O00
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
  Iii1iii1II , III = oo0oO0OO . build_key ( self . eid )
  Iii11iIII = ""
  if ( self . group . is_null ( ) == False ) :
   i1II1iIi111I1 , Iii11iIII = oo0oO0OO . build_key ( self . group )
   Iii11iIII = "-" + Iii11iIII [ 0 : 12 ] + "-" + str ( i1II1iIi111I1 ) + "-" + Iii11iIII [ 12 : : ]
   if 99 - 99: Ii1I
  III = III [ 0 : 12 ] + "-" + str ( Iii1iii1II ) + "-" + III [ 12 : : ] + Iii11iIII
  del ( oo0oO0OO )
  return ( III )
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
  for iiIiIIi1I in self . registered_rlocs :
   oOO0IiiiI . append ( copy . deepcopy ( iiIiIIi1I ) )
   if 43 - 43: oO0o / Ii1I % OOooOOo
  return ( oOO0IiiiI )
  if 45 - 45: II111iiii
  if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for IiiiI1i1 in list ( self . individual_registrations . values ( ) ) :
   if ( self . site_id != IiiiI1i1 . site_id ) : continue
   if ( IiiiI1i1 . registered == False ) : continue
   self . registered_rlocs += IiiiI1i1 . copy_rloc_records ( )
   if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
   if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
   if 43 - 43: OOooOOo . O0
   if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
   if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
   if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
  oOO0IiiiI = [ ]
  for iiIiIIi1I in self . registered_rlocs :
   if ( iiIiIIi1I . rloc . is_null ( ) or len ( oOO0IiiiI ) == 0 ) :
    oOO0IiiiI . append ( iiIiIIi1I )
    continue
    if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
   for I1I11I1IIi in oOO0IiiiI :
    if ( I1I11I1IIi . rloc . is_null ( ) ) : continue
    if ( iiIiIIi1I . rloc . is_exact_match ( I1I11I1IIi . rloc ) ) : break
    if 3 - 3: i1IIi + OoOoOO00 - OoOoOO00
   if ( I1I11I1IIi == oOO0IiiiI [ - 1 ] ) : oOO0IiiiI . append ( iiIiIIi1I )
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
  for iiIiIIi1I in self . registered_rlocs :
   if ( iiIiIIi1I . rle == None ) : continue
   for oO0oOOOO0oO0o0 in iiIiIIi1I . rle . rle_nodes :
    IiI = oO0oOOOO0oO0o0 . address . print_address_no_iid ( )
    iiIOoOoo [ IiI ] = oO0oOOOO0oO0o0 . address
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
  for iiIiIIi1I in self . registered_rlocs :
   if ( self . registered_rlocs . index ( iiIiIIi1I ) == 0 ) :
    i11IiIi11I . append ( iiIiIIi1I )
    continue
    if 84 - 84: I1IiiI . o0oOOo0O0Ooo * I1ii11iIi11i
   if ( iiIiIIi1I . rle == None ) : i11IiIi11I . append ( iiIiIIi1I )
   if 41 - 41: o0oOOo0O0Ooo * Ii1I + I11i . O0
  self . registered_rlocs = i11IiIi11I
  if 17 - 17: Ii1I % I1Ii111
  if 69 - 69: iIii1I11I1II1
  if 65 - 65: IiII % OOooOOo / o0oOOo0O0Ooo * II111iiii - oO0o
  if 38 - 38: I1Ii111 * o0oOOo0O0Ooo
  if 32 - 32: iII111i / Ii1I / I1Ii111 - OoOoOO00 / OOooOOo * OoO0O00
  if 32 - 32: I1ii11iIi11i + ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
  if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
  ooo0o0O = lisp_rle ( "" )
  I1iiIi1iI1I11 = { }
  i1Ii1iiI = None
  for IiiiI1i1 in list ( self . individual_registrations . values ( ) ) :
   if ( IiiiI1i1 . registered == False ) : continue
   O0o = IiiiI1i1 . registered_rlocs [ 0 ] . rle
   if ( O0o == None ) : continue
   if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
   i1Ii1iiI = IiiiI1i1 . registered_rlocs [ 0 ] . rloc_name
   for IIiiiIiI in O0o . rle_nodes :
    IiI = IIiiiIiI . address . print_address_no_iid ( )
    if ( IiI in I1iiIi1iI1I11 ) : break
    if 16 - 16: OoO0O00 . Oo0Ooo + oO0o + Ii1I - OoooooooOO . ooOoO0o
    oO0oOOOO0oO0o0 = lisp_rle_node ( )
    oO0oOOOO0oO0o0 . address . copy_address ( IIiiiIiI . address )
    oO0oOOOO0oO0o0 . level = IIiiiIiI . level
    oO0oOOOO0oO0o0 . rloc_name = i1Ii1iiI
    ooo0o0O . rle_nodes . append ( oO0oOOOO0oO0o0 )
    I1iiIi1iI1I11 [ IiI ] = IIiiiIiI . address
    if 44 - 44: O0
    if 91 - 91: ooOoO0o * OoOoOO00 * i1IIi * o0oOOo0O0Ooo - ooOoO0o % Ii1I
    if 46 - 46: O0 / iIii1I11I1II1
    if 65 - 65: OOooOOo
    if 88 - 88: OOooOOo * iIii1I11I1II1 + I11i . iII111i
    if 55 - 55: I1IiiI + Ii1I % I1ii11iIi11i + iIii1I11I1II1
  if ( len ( ooo0o0O . rle_nodes ) == 0 ) : ooo0o0O = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = ooo0o0O
   if ( i1Ii1iiI ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 64 - 64: i1IIi / O0 - oO0o
   if 7 - 7: IiII . IiII * Ii1I
   if 1 - 1: i11iIiiIii
   if 91 - 91: I1ii11iIi11i . OoO0O00 / OoO0O00 / I1ii11iIi11i + iII111i
   if 20 - 20: o0oOOo0O0Ooo . I1Ii111 + O0
  if ( list ( iiIOoOoo . keys ( ) ) == list ( I1iiIi1iI1I11 . keys ( ) ) ) : return ( False )
  if 99 - 99: O0 / IiII . oO0o
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # ooOoO0o + OoooooooOO
 list ( iiIOoOoo . keys ( ) ) , list ( I1iiIi1iI1I11 . keys ( ) ) ) )
  if 99 - 99: iIii1I11I1II1 * II111iiii * i11iIiiIii
  return ( True )
  if 10 - 10: OOooOOo
  if 75 - 75: I11i * ooOoO0o * Oo0Ooo . i1IIi . ooOoO0o . ooOoO0o
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   Ii1iIi1I1I1I = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( Ii1iIi1I1I1I == None ) :
    Ii1iIi1I1I1I = lisp_site_eid ( self . site )
    Ii1iIi1I1I1I . eid . copy_address ( self . group )
    Ii1iIi1I1I1I . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , Ii1iIi1I1I1I )
    if 24 - 24: iIii1I11I1II1
    if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
    if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
    if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
    if 62 - 62: o0oOOo0O0Ooo
    Ii1iIi1I1I1I . parent_for_more_specifics = self . parent_for_more_specifics
    if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( Ii1iIi1I1I1I . group )
   Ii1iIi1I1I1I . add_source_entry ( self )
   if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
   if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
   if 84 - 84: OoOoOO00
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   Ii1iIi1I1I1I = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( Ii1iIi1I1I1I == None ) : return
   if 80 - 80: oO0o
   IiiiI1i1 = Ii1iIi1I1I1I . lookup_source_cache ( self . eid , True )
   if ( IiiiI1i1 == None ) : return
   if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
   if ( Ii1iIi1I1I1I . source_cache == None ) : return
   if 92 - 92: iII111i
   Ii1iIi1I1I1I . source_cache . delete_cache ( self . eid )
   if ( Ii1iIi1I1I1I . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
    if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
    if 92 - 92: I1Ii111 - IiII / IiII
    if 42 - 42: IiII
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 7 - 7: iIii1I11I1II1
  if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
  if 56 - 56: iII111i
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
  if 60 - 60: i11iIiiIii - OOooOOo
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
  if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
 def inherit_from_ams_parent ( self ) :
  i11I1Ii1 = self . parent_for_more_specifics
  if ( i11I1Ii1 == None ) : return
  self . force_proxy_reply = i11I1Ii1 . force_proxy_reply
  self . force_nat_proxy_reply = i11I1Ii1 . force_nat_proxy_reply
  self . force_ttl = i11I1Ii1 . force_ttl
  self . pitr_proxy_reply_drop = i11I1Ii1 . pitr_proxy_reply_drop
  self . proxy_reply_action = i11I1Ii1 . proxy_reply_action
  self . echo_nonce_capable = i11I1Ii1 . echo_nonce_capable
  self . policy = i11I1Ii1 . policy
  self . require_signature = i11I1Ii1 . require_signature
  self . encrypt_json = i11I1Ii1 . encrypt_json
  if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
  if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
 def rtrs_in_rloc_set ( self ) :
  for iiIiIIi1I in self . registered_rlocs :
   if ( iiIiIIi1I . is_rtr ( ) ) : return ( True )
   if 58 - 58: Ii1I / Oo0Ooo % IiII
  return ( False )
  if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
  if 60 - 60: iII111i . o0oOOo0O0Ooo
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for iiIiIIi1I in self . registered_rlocs :
   if ( iiIiIIi1I . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( iiIiIIi1I . is_rtr ( ) ) : return ( True )
   if 56 - 56: I1ii11iIi11i
  return ( False )
  if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
  if 70 - 70: o0oOOo0O0Ooo + O0 % I1IiiI
 def is_rloc_in_rloc_set ( self , rloc ) :
  for iiIiIIi1I in self . registered_rlocs :
   if ( iiIiIIi1I . rle ) :
    for ooo0o0O in iiIiIIi1I . rle . rle_nodes :
     if ( ooo0o0O . address . is_exact_match ( rloc ) ) : return ( True )
     if 56 - 56: Ii1I
     if 84 - 84: iII111i
   if ( iiIiIIi1I . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 21 - 21: i11iIiiIii
  return ( False )
  if 30 - 30: OoO0O00 + OoooooooOO
  if 98 - 98: I1ii11iIi11i % I1IiiI
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
  for iiIiIIi1I in prev_rloc_set :
   o00o0o0O = iiIiIIi1I . rloc
   if ( self . is_rloc_in_rloc_set ( o00o0o0O ) == False ) : return ( False )
   if 66 - 66: IiII
  return ( True )
  if 56 - 56: oO0o + OoooooooOO
  if 75 - 75: O0 % Ii1I
  if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
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
   if 23 - 23: iII111i / iIii1I11I1II1
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 5 - 5: O0
  if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
  try :
   ooo0o0 = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   ii1iIiIIi = ooo0o0 [ 2 ]
  except :
   return
   if 63 - 63: i11iIiiIii / oO0o % O0
   if 70 - 70: IiII * I11i . iII111i . I1IiiI % iIii1I11I1II1 * OoooooooOO
   if 51 - 51: O0 * Oo0Ooo - OoooooooOO % OoOoOO00 . I1ii11iIi11i
   if 44 - 44: ooOoO0o / IiII + O0 . II111iiii
   if 12 - 12: Oo0Ooo
   if 54 - 54: OoOoOO00 . O0 % I1ii11iIi11i - II111iiii % I11i
  if ( len ( ii1iIiIIi ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 34 - 34: OoOoOO00 % ooOoO0o * I1IiiI % IiII
   if 62 - 62: OoooooooOO . OoooooooOO / I11i % OoOoOO00
  IiI = ii1iIiIIi [ self . a_record_index ]
  if ( IiI != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( IiI )
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
  for IiI in ii1iIiIIi [ 1 : : ] :
   OO0O00o0 = lisp_address ( LISP_AFI_NONE , IiI , 0 , 0 )
   OO0ooo000 = lisp_get_map_resolver ( OO0O00o0 , None )
   if ( OO0ooo000 != None and OO0ooo000 . a_record_index == ii1iIiIIi . index ( IiI ) ) :
    continue
    if 24 - 24: I11i / Oo0Ooo / i1IIi + IiII
   OO0ooo000 = lisp_mr ( IiI , None , None )
   OO0ooo000 . a_record_index = ii1iIiIIi . index ( IiI )
   OO0ooo000 . dns_name = self . dns_name
   OO0ooo000 . last_dns_resolve = lisp_get_timestamp ( )
   if 10 - 10: I11i - IiII / II111iiii / oO0o % O0 / I1Ii111
   if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
   if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
   if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
   if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
  oo0Oo00OO0000 = [ ]
  for OO0ooo000 in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( self . dns_name != OO0ooo000 . dns_name ) : continue
   OO0O00o0 = OO0ooo000 . map_resolver . print_address_no_iid ( )
   if ( OO0O00o0 in ii1iIiIIi ) : continue
   oo0Oo00OO0000 . append ( OO0ooo000 )
   if 74 - 74: Ii1I - OoOoOO00 + i11iIiiIii - II111iiii - i11iIiiIii . ooOoO0o
  for OO0ooo000 in oo0Oo00OO0000 : OO0ooo000 . delete_mr ( )
  if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
  if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
 def insert_mr ( self ) :
  III = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ III ] = self
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
  if 78 - 78: i1IIi
 def delete_mr ( self ) :
  III = self . mr_name + self . map_resolver . print_address ( )
  if ( III not in lisp_map_resolvers_list ) : return
  lisp_map_resolvers_list . pop ( III )
  if 25 - 25: Ii1I * II111iiii / OoOoOO00
  if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
  if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
class lisp_ddt_root ( object ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
  if 15 - 15: i11iIiiIii
  if 85 - 85: I1Ii111 + iII111i - oO0o
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
  if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
  if 64 - 64: OoOoOO00
 def print_referral ( self , eid_indent , referral_indent ) :
  II1i1 = lisp_print_elapsed ( self . uptime )
  oOOOOOO0oO = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , II1i1 ,
  # O0 . O0 % ooOoO0o
 oOOOOOO0oO , len ( self . referral_set ) ) )
  if 35 - 35: OoOoOO00
  for iiiIii in list ( self . referral_set . values ( ) ) :
   iiiIii . print_ref_node ( referral_indent )
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
  IiIIi = self . referral_ttl
  if ( IiIIi < 60 ) : return ( str ( IiIIi ) + " secs" )
  if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
  if ( ( IiIIi % 60 ) == 0 ) :
   IiIIi = str ( old_div ( IiIIi , 60 ) ) + " mins"
  else :
   IiIIi = str ( IiIIi ) + " secs"
   if 65 - 65: I1ii11iIi11i + OoOoOO00
  return ( IiIIi )
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
   i1OOOoO0O0O0O = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( i1OOOoO0O0O0O == None ) :
    i1OOOoO0O0O0O = lisp_referral ( )
    i1OOOoO0O0O0O . eid . copy_address ( self . group )
    i1OOOoO0O0O0O . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , i1OOOoO0O0O0O )
    if 48 - 48: OoooooooOO + II111iiii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( i1OOOoO0O0O0O . group )
   i1OOOoO0O0O0O . add_source_entry ( self )
   if 46 - 46: I1IiiI - II111iiii * OoO0O00 % OoooooooOO / OoO0O00 + II111iiii
   if 92 - 92: OoOoOO00 - iIii1I11I1II1
   if 10 - 10: iII111i - I1IiiI / I1ii11iIi11i - i1IIi - II111iiii % i11iIiiIii
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   i1OOOoO0O0O0O = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( i1OOOoO0O0O0O == None ) : return
   if 2 - 2: ooOoO0o % ooOoO0o
   iiiIIiIII111 = i1OOOoO0O0O0O . lookup_source_cache ( self . eid , True )
   if ( iiiIIiIII111 == None ) : return
   if 94 - 94: ooOoO0o / OoooooooOO * i1IIi . Oo0Ooo * i11iIiiIii
   i1OOOoO0O0O0O . source_cache . delete_cache ( self . eid )
   if ( i1OOOoO0O0O0O . source_cache . cache_size ( ) == 0 ) :
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
class lisp_referral_node ( object ) :
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
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , i1 ,
  # i1IIi % o0oOOo0O0Ooo * iIii1I11I1II1 - iII111i - iIii1I11I1II1 / OoooooooOO
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 25 - 25: O0 % OoOoOO00 - Ii1I * OoOoOO00 . i1IIi
  if 15 - 15: I1Ii111
  if 64 - 64: OOooOOo * Oo0Ooo
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
   ii1iIiIIi = ooo0o0 [ 2 ]
  except :
   return
   if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
   if 22 - 22: iII111i % I11i % O0 - I11i
   if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
   if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
   if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
   if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
  if ( len ( ii1iIiIIi ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
   if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
  IiI = ii1iIiIIi [ self . a_record_index ]
  if ( IiI != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( IiI )
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
  for IiI in ii1iIiIIi [ 1 : : ] :
   OO0O00o0 = lisp_address ( LISP_AFI_NONE , IiI , 0 , 0 )
   IIiiIiI = lisp_get_map_server ( OO0O00o0 )
   if ( IIiiIiI != None and IIiiIiI . a_record_index == ii1iIiIIi . index ( IiI ) ) :
    continue
    if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
   IIiiIiI = copy . deepcopy ( self )
   IIiiIiI . map_server . store_address ( IiI )
   IIiiIiI . a_record_index = ii1iIiIIi . index ( IiI )
   IIiiIiI . last_dns_resolve = lisp_get_timestamp ( )
   IIiiIiI . insert_ms ( )
   if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
   if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
   if 86 - 86: I1Ii111 + I1ii11iIi11i
   if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
   if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
  oo0Oo00OO0000 = [ ]
  for IIiiIiI in list ( lisp_map_servers_list . values ( ) ) :
   if ( self . dns_name != IIiiIiI . dns_name ) : continue
   OO0O00o0 = IIiiIiI . map_server . print_address_no_iid ( )
   if ( OO0O00o0 in ii1iIiIIi ) : continue
   oo0Oo00OO0000 . append ( IIiiIiI )
   if 69 - 69: OOooOOo
  for IIiiIiI in oo0Oo00OO0000 : IIiiIiI . delete_ms ( )
  if 9 - 9: i11iIiiIii * Oo0Ooo
  if 33 - 33: oO0o / ooOoO0o
 def insert_ms ( self ) :
  III = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ III ] = self
  if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
  if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
 def delete_ms ( self ) :
  III = self . ms_name + self . map_server . print_address ( )
  if ( III not in lisp_map_servers_list ) : return
  lisp_map_servers_list . pop ( III )
  if 44 - 44: o0oOOo0O0Ooo
  if 1 - 1: OoooooooOO / i11iIiiIii . o0oOOo0O0Ooo
  if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
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
  I111 = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  I111 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   I111 . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   I111 . close ( )
   I111 = None
   if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
  self . raw_socket = I111
  if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
  if 11 - 11: I1IiiI
 def set_bridge_socket ( self , device ) :
  I111 = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   I111 = I111 . bind ( ( device , 0 ) )
   self . bridge_socket = I111
  except :
   return
   if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
   if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
   if 91 - 91: OoO0O00
   if 8 - 8: oO0o
class lisp_datetime ( object ) :
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
  i1 = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  i1 = lisp_datetime ( i1 )
  return ( i1 )
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
  i1 = str ( self . datetime ) [ 0 : 4 ]
  return ( i1 == iiI1 )
  if 39 - 39: I1ii11iIi11i * I1Ii111 . i1IIi * I1IiiI / o0oOOo0O0Ooo % II111iiii
  if 22 - 22: II111iiii % II111iiii
 def this_month ( self ) :
  iiI1 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  i1 = str ( self . datetime ) [ 0 : 6 ]
  return ( i1 == iiI1 )
  if 38 - 38: I1ii11iIi11i + I1Ii111 / IiII % oO0o
  if 42 - 42: ooOoO0o
 def today ( self ) :
  iiI1 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  i1 = str ( self . datetime ) [ 0 : 8 ]
  return ( i1 == iiI1 )
  if 62 - 62: OOooOOo + OoOoOO00 . iII111i
  if 26 - 26: OOooOOo
  if 89 - 89: i11iIiiIii . o0oOOo0O0Ooo % iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
  if 17 - 17: I1Ii111
  if 59 - 59: OoOoOO00 . OoOoOO00 * iII111i - Ii1I . i11iIiiIii
  if 68 - 68: iII111i
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
  if 68 - 68: I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
  if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
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
  if 59 - 59: iII111i
  if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
 def match_policy_map_request ( self , mr , srloc ) :
  for oOOooo0 in self . match_clauses :
   iIIiiIi = oOOooo0 . source_eid
   I1 = mr . source_eid
   if ( iIIiiIi and I1 and I1 . is_more_specific ( iIIiiIi ) == False ) : continue
   if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
   iIIiiIi = oOOooo0 . dest_eid
   I1 = mr . target_eid
   if ( iIIiiIi and I1 and I1 . is_more_specific ( iIIiiIi ) == False ) : continue
   if 65 - 65: I1Ii111 + OOooOOo
   iIIiiIi = oOOooo0 . source_rloc
   I1 = srloc
   if ( iIIiiIi and I1 and I1 . is_more_specific ( iIIiiIi ) == False ) : continue
   oOO0O00o0O0 = oOOooo0 . datetime_lower
   OO0O0OOooo = oOOooo0 . datetime_upper
   if ( oOO0O00o0O0 and OO0O0OOooo and oOO0O00o0O0 . now_in_range ( OO0O0OOooo ) == False ) : continue
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
   IiI = IIIi1iI1 . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( IiI ) )
   if 22 - 22: OoooooooOO / O0 / I1IiiI * I1ii11iIi11i % I11i + iII111i
  if ( self . set_rloc_record_name ) :
   IIIi1iI1 . rloc_name = self . set_rloc_record_name
   iii1IiII1ii = blue ( IIIi1iI1 . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( iii1IiII1ii ) )
   if 26 - 26: I1ii11iIi11i - o0oOOo0O0Ooo - i1IIi - Ii1I
  if ( self . set_geo_name ) :
   IIIi1iI1 . geo_name = self . set_geo_name
   iii1IiII1ii = IIIi1iI1 . geo_name
   oo0O0o = "" if ( iii1IiII1ii in lisp_geo_list ) else "(not configured)"
   if 76 - 76: I1IiiI - oO0o
   lprint ( "Policy set-geo-name '{}' {}" . format ( iii1IiII1ii , oo0O0o ) )
   if 93 - 93: I1ii11iIi11i - OOooOOo - II111iiii * OoO0O00 . O0 - ooOoO0o
  if ( self . set_elp_name ) :
   IIIi1iI1 . elp_name = self . set_elp_name
   iii1IiII1ii = IIIi1iI1 . elp_name
   oo0O0o = "" if ( iii1IiII1ii in lisp_elp_list ) else "(not configured)"
   if 53 - 53: OoO0O00 / i11iIiiIii . OoooooooOO
   lprint ( "Policy set-elp-name '{}' {}" . format ( iii1IiII1ii , oo0O0o ) )
   if 84 - 84: I1ii11iIi11i
  if ( self . set_rle_name ) :
   IIIi1iI1 . rle_name = self . set_rle_name
   iii1IiII1ii = IIIi1iI1 . rle_name
   oo0O0o = "" if ( iii1IiII1ii in lisp_rle_list ) else "(not configured)"
   if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
   lprint ( "Policy set-rle-name '{}' {}" . format ( iii1IiII1ii , oo0O0o ) )
   if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
  if ( self . set_json_name ) :
   IIIi1iI1 . json_name = self . set_json_name
   iii1IiII1ii = IIIi1iI1 . json_name
   oo0O0o = "" if ( iii1IiII1ii in lisp_json_list ) else "(not configured)"
   if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
   lprint ( "Policy set-json-name '{}' {}" . format ( iii1IiII1ii , oo0O0o ) )
   if 67 - 67: i1IIi * I1Ii111 * O0
  return ( IIIi1iI1 )
  if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
  if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
  if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
  if 75 - 75: i11iIiiIii
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
  if 58 - 58: iII111i
  if 48 - 48: OoO0O00 * OOooOOo / iII111i
 def add ( self , eid_prefix ) :
  self . eid_prefix = eid_prefix
  IiIIi = self . ttl
  oo0oO = eid_prefix . print_prefix ( )
  if ( oo0oO not in lisp_pubsub_cache ) :
   lisp_pubsub_cache [ oo0oO ] = { }
   if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
  OO0OoooO0 = lisp_pubsub_cache [ oo0oO ]
  if 82 - 82: Oo0Ooo
  I11IiI1i11i1 = "Add"
  if ( self . xtr_id in OO0OoooO0 ) :
   I11IiI1i11i1 = "Replace"
   del ( OO0OoooO0 [ self . xtr_id ] )
   if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
  OO0OoooO0 [ self . xtr_id ] = self
  if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
  oo0oO = green ( oo0oO , False )
  OOooOooOOoO0O = red ( self . itr . print_address_no_iid ( ) , False )
  Oo00Ooo0O0O0o = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( I11IiI1i11i1 , oo0oO ,
 OOooOooOOoO0O , Oo00Ooo0O0O0o , IiIIi ) )
  if 20 - 20: OoOoOO00 - IiII
  if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
 def delete ( self , eid_prefix ) :
  oo0oO = eid_prefix . print_prefix ( )
  OOooOooOOoO0O = red ( self . itr . print_address_no_iid ( ) , False )
  Oo00Ooo0O0O0o = "0x" + lisp_hex_string ( self . xtr_id )
  if ( oo0oO in lisp_pubsub_cache ) :
   OO0OoooO0 = lisp_pubsub_cache [ oo0oO ]
   if ( self . xtr_id in OO0OoooO0 ) :
    OO0OoooO0 . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( oo0oO ,
 OOooOooOOoO0O , Oo00Ooo0O0O0o ) )
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
class lisp_trace ( object ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 57 - 57: Ii1I / I1IiiI * i1IIi
  if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
 def print_trace ( self ) :
  o0oO0o00O0 = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( o0oO0o00O0 ) )
  if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
  if 30 - 30: Ii1I / iII111i * Ii1I
 def encode ( self ) :
  iIiIii = socket . htonl ( 0x90000000 )
  Oo00oo = struct . pack ( "II" , iIiIii , 0 )
  Oo00oo += struct . pack ( "Q" , self . nonce )
  Oo00oo += json . dumps ( self . packet_json )
  return ( Oo00oo )
  if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
  if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
 def decode ( self , packet ) :
  iiII1iiI = "I"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( False )
  iIiIii = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  iIiIii = socket . ntohl ( iIiIii )
  if ( ( iIiIii & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 71 - 71: i1IIi % O0 % ooOoO0o
  if ( len ( packet ) < ooo0000oo0 ) : return ( False )
  IiI = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if 24 - 24: O0
  IiI = socket . ntohl ( IiI )
  oooOO000OO000 = IiI >> 24
  iI111IiI1I1Ii = ( IiI >> 16 ) & 0xff
  iiIoOoO0000oo = ( IiI >> 8 ) & 0xff
  Iii1 = IiI & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( oooOO000OO000 , iI111IiI1I1Ii , iiIoOoO0000oo , Iii1 )
  self . local_port = str ( iIiIii & 0xffff )
  if 73 - 73: iII111i
  iiII1iiI = "Q"
  ooo0000oo0 = struct . calcsize ( iiII1iiI )
  if ( len ( packet ) < ooo0000oo0 ) : return ( False )
  self . nonce = struct . unpack ( iiII1iiI , packet [ : ooo0000oo0 ] ) [ 0 ]
  packet = packet [ ooo0000oo0 : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 13 - 13: OOooOOo + iII111i . OoOoOO00 % iIii1I11I1II1
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 43 - 43: I1ii11iIi11i / iIii1I11I1II1
  return ( True )
  if 84 - 84: OoOoOO00
  if 42 - 42: OoO0O00
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 85 - 85: I1IiiI
  if 35 - 35: i11iIiiIii . I11i . OoOoOO00 - i11iIiiIii / oO0o / IiII
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  IIIi1iI1 , ooO0 = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( IIIi1iI1 == None ) :
   IIIi1iI1 , ooO0 = rts_rloc . split ( ":" )
   ooO0 = int ( ooO0 )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( IIIi1iI1 , ooO0 ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( IIIi1iI1 ,
 ooO0 ) )
   if 84 - 84: I11i . oO0o + ooOoO0o
   if 75 - 75: I1Ii111
  if ( lisp_socket == None ) :
   I111 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   I111 . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   I111 . sendto ( packet , ( IIIi1iI1 , ooO0 ) )
   I111 . close ( )
  else :
   lisp_socket . sendto ( packet , ( IIIi1iI1 , ooO0 ) )
   if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
   if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
   if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
 def packet_length ( self ) :
  O0I1II1 = 8 ; I11III1i111 = 4 + 4 + 8
  return ( O0I1II1 + I11III1i111 + len ( json . dumps ( self . packet_json ) ) )
  if 17 - 17: OoO0O00 % II111iiii . i1IIi . OOooOOo
  if 49 - 49: II111iiii / OoOoOO00 * IiII % OoO0O00
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  III = self . local_rloc + ":" + self . local_port
  oOO0 = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ III ] = oOO0
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( III , oOO0 ) )
  if 77 - 77: OoOoOO00 + OOooOOo % o0oOOo0O0Ooo
  if 3 - 3: ooOoO0o / i1IIi
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  III = local_rloc_and_port
  try : oOO0 = lisp_rtr_nat_trace_cache [ III ]
  except : oOO0 = ( None , None )
  return ( oOO0 )
  if 71 - 71: Ii1I + oO0o % IiII
  if 15 - 15: ooOoO0o . Oo0Ooo
  if 42 - 42: OOooOOo . i11iIiiIii % O0 - OoO0O00
  if 34 - 34: OOooOOo % oO0o * OOooOOo * iIii1I11I1II1
  if 18 - 18: I1IiiI / I11i
  if 64 - 64: I11i * i11iIiiIii
  if 16 - 16: I1Ii111 * II111iiii * I1Ii111 . o0oOOo0O0Ooo
  if 96 - 96: ooOoO0o - o0oOOo0O0Ooo % O0 * Ii1I . OoOoOO00
  if 80 - 80: I1IiiI
  if 31 - 31: I1Ii111 + o0oOOo0O0Ooo . I1IiiI + I11i . oO0o
  if 50 - 50: Ii1I . OOooOOo
def lisp_get_map_server ( address ) :
 for IIiiIiI in list ( lisp_map_servers_list . values ( ) ) :
  if ( IIiiIiI . map_server . is_exact_match ( address ) ) : return ( IIiiIiI )
  if 84 - 84: OoOoOO00 * OoO0O00 + I1IiiI
 return ( None )
 if 38 - 38: OoooooooOO % I1IiiI
 if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
 if 75 - 75: ooOoO0o
 if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
 if 14 - 14: I11i / I11i
 if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
 if 93 - 93: oO0o / ooOoO0o - I1Ii111
def lisp_get_any_map_server ( ) :
 for IIiiIiI in list ( lisp_map_servers_list . values ( ) ) : return ( IIiiIiI )
 return ( None )
 if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
 if 26 - 26: O0 + Oo0Ooo
 if 30 - 30: IiII
 if 6 - 6: O0
 if 92 - 92: I11i
 if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
 if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
 if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
 if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
 if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  IiI = address . print_address ( )
  OO0ooo000 = None
  for III in lisp_map_resolvers_list :
   if ( III . find ( IiI ) == - 1 ) : continue
   OO0ooo000 = lisp_map_resolvers_list [ III ]
   if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
  return ( OO0ooo000 )
  if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
  if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
  if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
  if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
  if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
  if 83 - 83: OOooOOo . ooOoO0o / IiII
  if 80 - 80: I1Ii111 . I11i - I11i + I1ii11iIi11i
 if ( eid == "" ) :
  I111ooo0oO = ""
 elif ( eid == None ) :
  I111ooo0oO = "all"
 else :
  oooOOoO0oo0 = lisp_db_for_lookups . lookup_cache ( eid , False )
  I111ooo0oO = "all" if oooOOoO0oo0 == None else oooOOoO0oo0 . use_mr_name
  if 63 - 63: iIii1I11I1II1 % i11iIiiIii . oO0o + Oo0Ooo - I11i . OoOoOO00
  if 69 - 69: Oo0Ooo . Oo0Ooo * ooOoO0o
 IiI1I11 = None
 for OO0ooo000 in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( I111ooo0oO == "" ) : return ( OO0ooo000 )
  if ( OO0ooo000 . mr_name != I111ooo0oO ) : continue
  if ( IiI1I11 == None or OO0ooo000 . last_used < IiI1I11 . last_used ) : IiI1I11 = OO0ooo000
  if 46 - 46: OOooOOo - I11i * iIii1I11I1II1 - I1Ii111 % i11iIiiIii
 return ( IiI1I11 )
 if 32 - 32: Oo0Ooo * i1IIi . iII111i . iII111i
 if 77 - 77: OOooOOo
 if 74 - 74: O0
 if 86 - 86: OoOoOO00
 if 4 - 4: OoooooooOO * OoO0O00
 if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
 if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
 if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
def lisp_get_decent_map_resolver ( eid ) :
 OOOooo0OooOoO = lisp_get_decent_index ( eid )
 iIIIIII1I = str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix
 if 31 - 31: oO0o / Oo0Ooo / OoO0O00 + I1ii11iIi11i
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( iIIIIII1I , False ) , eid . print_prefix ( ) ) )
 if 34 - 34: OOooOOo * Oo0Ooo / I1Ii111 / OOooOOo
 if 92 - 92: O0 * O0
 IiI1I11 = None
 for OO0ooo000 in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( iIIIIII1I != OO0ooo000 . dns_name ) : continue
  if ( IiI1I11 == None or OO0ooo000 . last_used < IiI1I11 . last_used ) : IiI1I11 = OO0ooo000
  if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
 return ( IiI1I11 )
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
 if ( ord ( packet [ 9 : 10 ] ) == 2 ) : return ( [ True , packet ] )
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
 IiIIi = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( IiIIi == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( IiIIi == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 36 - 36: iIii1I11I1II1 % i11iIiiIii
  return ( [ False , None ] )
  if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
  if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 IiIIi -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , IiIIi ) + packet [ 9 : : ]
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
 IIi11ii = packet . inner_dest
 packet = packet . packet
 if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
 if 2 - 2: Oo0Ooo - OoOoOO00
 if 22 - 22: OoO0O00 - oO0o - O0
 if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
 if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
 IiIIi = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( IiIIi == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( IiIIi == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 2 - 2: i11iIiiIii
  return ( None )
  if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
  if 17 - 17: iIii1I11I1II1
  if 32 - 32: IiII - OoOoOO00
  if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
  if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
 if ( IIi11ii . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
  if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 IiIIi -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , IiIIi ) + packet [ 8 : : ]
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
 i1i111Iiiiiii = iiI1 - lisp_no_map_request_rate_limit
 if ( i1i111Iiiiiii < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  iIi1I1 = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - i1i111Iiiiiii )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( iIi1I1 ) )
  return ( False )
  if 36 - 36: O0
  if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
  if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
  if 21 - 21: i1IIi * iII111i + OoO0O00
  if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if ( lisp_last_map_request_sent == None ) : return ( False )
 i1i111Iiiiiii = iiI1 - lisp_last_map_request_sent
 IiII1IIiI1i = ( i1i111Iiiiiii < LISP_MAP_REQUEST_RATE_LIMIT )
 if 85 - 85: OoooooooOO
 if ( IiII1IIiI1i ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( i1i111Iiiiiii , 3 ) ) )
  if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
  if 8 - 8: I1Ii111
 return ( IiII1IIiI1i )
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
 IIiIiII , iIIiI , ooO000OO = lisp_myrlocs
 if ( IIiIiII == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 64 - 64: oO0o - i11iIiiIii
 if ( iIIiI == None and i1I1 != None and i1I1 . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
  if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
 oooO = lisp_map_request ( )
 oooO . record_count = 1
 oooO . nonce = lisp_get_control_nonce ( )
 oooO . rloc_probe = ( i1I1 != None )
 oooO . subscribe_bit = pubsub
 oooO . xtr_id_present = pubsub
 if 21 - 21: OoOoOO00 / OoooooooOO + I1Ii111 - IiII
 if 62 - 62: Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % iII111i % iIii1I11I1II1
 if 54 - 54: IiII + OoOoOO00 / II111iiii % i11iIiiIii . I1Ii111
 if 69 - 69: i1IIi + ooOoO0o + Ii1I
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if ( rloc ) : rloc . last_rloc_probe_nonce = oooO . nonce
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 OoO0o0 = deid . is_multicast_address ( )
 if ( OoO0o0 ) :
  oooO . target_eid = seid
  oooO . target_group = deid
 else :
  oooO . target_eid = deid
  if 8 - 8: i1IIi
  if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
  if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
  if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
  if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
  if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
  if 54 - 54: OOooOOo
  if 86 - 86: oO0o * Oo0Ooo / OOooOOo
  if 18 - 18: II111iiii - I1Ii111
 if ( oooO . rloc_probe == False ) :
  oooOOoO0oo0 = lisp_get_signature_eid ( )
  if ( oooOOoO0oo0 ) :
   oooO . signature_eid . copy_address ( oooOOoO0oo0 . eid )
   oooO . privkey_filename = "./lisp-sig.pem"
   if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
   if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
   if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
   if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
   if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
   if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
 if ( seid == None or OoO0o0 ) :
  oooO . source_eid . afi = LISP_AFI_NONE
 else :
  oooO . source_eid = seid
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
  oooO . itr_rlocs . append ( IIiIiII )
  if 23 - 23: OoOoOO00 / O0 * OoOoOO00 . I1IiiI + Oo0Ooo . iII111i
 if ( i1I1 == None or i1I1 . is_ipv6 ( ) ) :
  if ( iIIiI == None or iIIiI . is_ipv6_link_local ( ) ) :
   iIIiI = None
  else :
   oooO . itr_rloc_count = 1 if ( i1I1 == None ) else 0
   oooO . itr_rlocs . append ( iIIiI )
   if 1 - 1: i11iIiiIii * OoO0O00 - OoooooooOO + OoooooooOO
   if 31 - 31: OoooooooOO - OoOoOO00 * II111iiii % ooOoO0o - ooOoO0o / i11iIiiIii
   if 8 - 8: I1IiiI . i1IIi - I11i
   if 85 - 85: OOooOOo * IiII % O0 / I1ii11iIi11i
   if 17 - 17: Oo0Ooo / i11iIiiIii / I11i - I1Ii111
   if 3 - 3: I1Ii111 - Oo0Ooo / iIii1I11I1II1
   if 71 - 71: o0oOOo0O0Ooo + i11iIiiIii + OoooooooOO % OoOoOO00 - I1ii11iIi11i / OoooooooOO
   if 26 - 26: II111iiii
   if 41 - 41: Oo0Ooo . OoOoOO00 . iII111i / i11iIiiIii
 if ( i1I1 != None and oooO . itr_rlocs != [ ] ) :
  oO0o0o00O = oooO . itr_rlocs [ 0 ]
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
 Oo00oo = oooO . encode ( i1I1 , o0OoOO )
 oooO . print_map_request ( )
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
 if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
 if 21 - 21: I1ii11iIi11i - ooOoO0o
 if 81 - 81: iII111i / i11iIiiIii / I1Ii111
 if 70 - 70: I1ii11iIi11i / i11iIiiIii
 if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
 if ( i1I1 != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   iIIi11I = lisp_get_nat_info ( i1I1 , rloc . rloc_name )
   if 76 - 76: OoooooooOO
   if 78 - 78: IiII % i11iIiiIii
   if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
   if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
   if ( iIIi11I == None ) :
    iiiI1I = rloc . rloc . print_address_no_iid ( )
    Oo = "gleaned-{}" . format ( iiiI1I )
    iIIiiIi = rloc . translated_port
    iIIi11I = lisp_nat_info ( iiiI1I , Oo , iIIiiIi )
    if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
   lisp_encapsulate_rloc_probe ( lisp_sockets , i1I1 , iIIi11I ,
 Oo00oo )
   return
   if 19 - 19: o0oOOo0O0Ooo
   if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
  O0O0 = i1I1 . print_address_no_iid ( )
  IIi11ii = lisp_convert_4to6 ( O0O0 )
  lisp_send ( lisp_sockets , IIi11ii , LISP_CTRL_PORT , Oo00oo )
  return
  if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
  if 71 - 71: OoO0O00 - I11i
  if 96 - 96: I1Ii111 / Ii1I
  if 65 - 65: I1ii11iIi11i * O0 . IiII
  if 11 - 11: I11i / Ii1I % oO0o
  if 50 - 50: i11iIiiIii
 Oo00 = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  OO0ooo000 = lisp_get_decent_map_resolver ( deid )
 else :
  OO0ooo000 = lisp_get_map_resolver ( None , Oo00 )
  if 57 - 57: Oo0Ooo . oO0o
 if ( OO0ooo000 == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 50 - 50: I1ii11iIi11i / I11i / ooOoO0o % OOooOOo
  return
  if 97 - 97: iII111i - I1IiiI + o0oOOo0O0Ooo . I1ii11iIi11i
 OO0ooo000 . last_used = lisp_get_timestamp ( )
 OO0ooo000 . map_requests_sent += 1
 if ( OO0ooo000 . last_nonce == 0 ) : OO0ooo000 . last_nonce = oooO . nonce
 if 15 - 15: i11iIiiIii . O0 . Oo0Ooo + i11iIiiIii
 if 76 - 76: OoOoOO00 / i1IIi . OOooOOo - OoOoOO00 + II111iiii
 if 30 - 30: iII111i . OoooooooOO + Oo0Ooo . OoOoOO00 / OoooooooOO + OOooOOo
 if 76 - 76: Ii1I * iII111i . OoooooooOO
 if ( seid == None ) : seid = oO0o0o00O
 lisp_send_ecm ( lisp_sockets , Oo00oo , seid , lisp_ephem_port , deid ,
 OO0ooo000 . map_resolver )
 if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
 if 44 - 44: I1Ii111 - II111iiii / OOooOOo
 if 50 - 50: I11i / I1ii11iIi11i
 if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
 if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 OO0ooo000 . resolve_dns_name ( )
 return
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
 if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
 if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
 if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
 if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 79 - 79: oO0o
 if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 IiI1I1iiIii1ii1I1I = lisp_info ( )
 IiI1I1iiIii1ii1I1I . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : IiI1I1iiIii1ii1I1I . hostname += "-" + device_name
 if 38 - 38: Oo0Ooo - II111iiii * o0oOOo0O0Ooo / i1IIi + i11iIiiIii
 O0O0 = dest . print_address_no_iid ( )
 if 44 - 44: Oo0Ooo / O0 * OoOoOO00 + oO0o
 if 25 - 25: II111iiii / OoooooooOO / Oo0Ooo % iII111i
 if 57 - 57: Ii1I / oO0o . I1IiiI % I1Ii111
 if 8 - 8: oO0o
 if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
 if 1 - 1: OoooooooOO . Ii1I
 if 68 - 68: Ii1I
 if 98 - 98: iII111i
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
 if 67 - 67: o0oOOo0O0Ooo
 if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
 if 33 - 33: II111iiii
 if 61 - 61: I1Ii111
 if 56 - 56: I1ii11iIi11i - OoooooooOO
 OOO0O0Oo = False
 if ( device_name ) :
  OOOo0o0OO = lisp_get_host_route_next_hop ( O0O0 )
  if 35 - 35: Oo0Ooo
  if 90 - 90: I1IiiI - ooOoO0o + II111iiii + IiII * O0 . I1Ii111
  if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
  if 82 - 82: o0oOOo0O0Ooo
  if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
  if 92 - 92: iII111i + OoO0O00
  if 70 - 70: iIii1I11I1II1
  if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
  if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
  if ( port == LISP_CTRL_PORT and OOOo0o0OO != None ) :
   while ( True ) :
    time . sleep ( .01 )
    OOOo0o0OO = lisp_get_host_route_next_hop ( O0O0 )
    if ( OOOo0o0OO == None ) : break
    if 14 - 14: I1Ii111 + Oo0Ooo
    if 35 - 35: i11iIiiIii * Ii1I
    if 100 - 100: O0 . iII111i / iIii1I11I1II1
  i1I1II = lisp_get_default_route_next_hops ( )
  for ooO000OO , o0o0O0o0000 in i1I1II :
   if ( ooO000OO != device_name ) : continue
   if 86 - 86: OOooOOo - ooOoO0o / i11iIiiIii * o0oOOo0O0Ooo % II111iiii / I1ii11iIi11i
   if 25 - 25: Ii1I
   if 88 - 88: OoooooooOO
   if 73 - 73: ooOoO0o % iII111i * IiII - iIii1I11I1II1 + i1IIi + o0oOOo0O0Ooo
   if 63 - 63: iIii1I11I1II1
   if 88 - 88: OoooooooOO
   if ( OOOo0o0OO != o0o0O0o0000 ) :
    if ( OOOo0o0OO != None ) :
     lisp_install_host_route ( O0O0 , OOOo0o0OO , False )
     if 23 - 23: iII111i - IiII % i11iIiiIii
    lisp_install_host_route ( O0O0 , o0o0O0o0000 , True )
    OOO0O0Oo = True
    if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
   break
   if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
   if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
   if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
   if 11 - 11: II111iiii + i1IIi
   if 1 - 1: OOooOOo
   if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
 Oo00oo = IiI1I1iiIii1ii1I1I . encode ( )
 IiI1I1iiIii1ii1I1I . print_info ( )
 if 83 - 83: OoooooooOO
 if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
 if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
 if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
 iIiiI1II11 = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 iIiiI1II11 = bold ( iIiiI1II11 , False )
 iIIiiIi = bold ( "{}" . format ( port ) , False )
 OO0O00o0 = red ( O0O0 , False )
 IiIi1I1i1iIiI = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( IiIi1I1i1iIiI , OO0O00o0 , iIIiiIi , iIiiI1II11 ) )
 if 65 - 65: I1ii11iIi11i + O0 + iII111i + II111iiii
 if 100 - 100: I1Ii111
 if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
 if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
 if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
 if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , Oo00oo )
 else :
  IiIii1iIIII = lisp_data_header ( )
  IiIii1iIIII . instance_id ( 0xffffff )
  IiIii1iIIII = IiIii1iIIII . encode ( )
  if ( IiIii1iIIII ) :
   Oo00oo = IiIii1iIIII + Oo00oo
   if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
   if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
   if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
   if 74 - 74: OoooooooOO + Ii1I
   if 100 - 100: I1IiiI
   if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
   if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
   if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
   if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , Oo00oo )
   if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
   if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
   if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
   if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
   if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
   if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
   if 40 - 40: I1ii11iIi11i
 if ( OOO0O0Oo ) :
  lisp_install_host_route ( O0O0 , None , False )
  if ( OOOo0o0OO != None ) : lisp_install_host_route ( O0O0 , OOOo0o0OO , True )
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
 IiI1I1iiIii1ii1I1I = lisp_info ( )
 packet = IiI1I1iiIii1ii1I1I . decode ( packet )
 if ( packet == None ) : return
 IiI1I1iiIii1ii1I1I . print_info ( )
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 IiI1I1iiIii1ii1I1I . info_reply = True
 IiI1I1iiIii1ii1I1I . global_etr_rloc . store_address ( addr_str )
 IiI1I1iiIii1ii1I1I . etr_port = sport
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
 if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
 if 44 - 44: O0
 if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if ( IiI1I1iiIii1ii1I1I . hostname != None ) :
  IiI1I1iiIii1ii1I1I . private_etr_rloc . afi = LISP_AFI_NAME
  IiI1I1iiIii1ii1I1I . private_etr_rloc . store_address ( IiI1I1iiIii1ii1I1I . hostname )
  if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
  if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 if ( rtr_list != None ) : IiI1I1iiIii1ii1I1I . rtr_list = rtr_list
 packet = IiI1I1iiIii1ii1I1I . encode ( )
 IiI1I1iiIii1ii1I1I . print_info ( )
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
 if 79 - 79: II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 if 32 - 32: O0 + IiII
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 IIi11ii = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , IIi11ii , sport , packet )
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 17 - 17: OOooOOo
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 if 46 - 46: II111iiii * OoO0O00
 o00000OO0ooOo = lisp_info_source ( IiI1I1iiIii1ii1I1I . hostname , addr_str , sport )
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
  for iiIiIIi1I in oooOOoO0oo0 . rloc_set :
   if ( iiIiIIi1I . translated_rloc . is_null ( ) ) : continue
   return ( iiIiIIi1I . translated_port )
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
  for iiIiIIi1I in oooOOoO0oo0 . rloc_set :
   if ( iiIiIIi1I . translated_rloc . is_null ( ) ) : continue
   return ( iiIiIIi1I . translated_rloc )
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
  for iiIiIIi1I in oooOOoO0oo0 . rloc_set :
   if ( iiIiIIi1I . is_rloc_translated ( ) == False ) : continue
   IiI = iiIiIIi1I . translated_rloc . print_address_no_iid ( )
   O00O00Oo0O . append ( IiI )
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
 OooIII1i1I = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 31 - 31: Oo0Ooo / oO0o
 IIiIIiiI11 = { }
 for IIIi1iI1 in rtr_list :
  if ( IIIi1iI1 == None ) : continue
  IiI = rtr_list [ IIIi1iI1 ]
  if ( OooIII1i1I and IiI . is_private_address ( ) ) : continue
  IIiIIiiI11 [ IIIi1iI1 ] = IiI
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
  o00oO0ooO000 = lisp_address ( i1I1iiiI , "" , 0 , iid )
  o00oO0ooO000 . make_default_route ( o00oO0ooO000 )
  iIIiiiiI11i = lisp_map_cache . lookup_cache ( o00oO0ooO000 , True )
  if ( iIIiiiiI11i ) :
   if ( iIIiiiiI11i . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( iIIiiiiI11i . print_eid_tuple ( ) , False ) ) )
    if 87 - 87: oO0o / OoO0O00 - oO0o
   elif ( iIIiiiiI11i . do_rloc_sets_match ( list ( rtr_list . values ( ) ) ) ) :
    continue
    if 69 - 69: i11iIiiIii
   iIIiiiiI11i . delete_cache ( )
   if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
   if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
  Oo0oO0Oo0 . append ( [ o00oO0ooO000 , "" ] )
  if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
  if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
  if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
  if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
  iiI = lisp_address ( i1I1iiiI , "" , 0 , iid )
  iiI . make_default_multicast_route ( iiI )
  oOoOooO = lisp_map_cache . lookup_cache ( iiI , True )
  if ( oOoOooO ) : oOoOooO = oOoOooO . source_cache . lookup_cache ( o00oO0ooO000 , True )
  if ( oOoOooO ) : oOoOooO . delete_cache ( )
  if 11 - 11: OOooOOo + i11iIiiIii
  Oo0oO0Oo0 . append ( [ o00oO0ooO000 , iiI ] )
  if 21 - 21: OoOoOO00 * OoooooooOO . I11i . I1Ii111
 if ( len ( Oo0oO0Oo0 ) == 0 ) : return
 if 95 - 95: iIii1I11I1II1 - I1Ii111 - I1ii11iIi11i
 if 91 - 91: I1IiiI
 if 19 - 19: i1IIi / OOooOOo + i1IIi * OoooooooOO
 if 61 - 61: oO0o / OoooooooOO . Ii1I / o0oOOo0O0Ooo . oO0o
 oOO000OOO = [ ]
 for IiIi1I1i1iIiI in rtr_list :
  IIiii111IIi1 = rtr_list [ IiIi1I1i1iIiI ]
  iiIiIIi1I = lisp_rloc ( )
  iiIiIIi1I . rloc . copy_address ( IIiii111IIi1 )
  iiIiIIi1I . priority = 254
  iiIiIIi1I . mpriority = 255
  iiIiIIi1I . rloc_name = "RTR"
  oOO000OOO . append ( iiIiIIi1I )
  if 87 - 87: oO0o
  if 52 - 52: i11iIiiIii
 for o00oO0ooO000 in Oo0oO0Oo0 :
  iIIiiiiI11i = lisp_mapping ( o00oO0ooO000 [ 0 ] , o00oO0ooO000 [ 1 ] , oOO000OOO )
  iIIiiiiI11i . mapping_source = map_resolver
  iIIiiiiI11i . map_cache_ttl = LISP_MR_TTL * 60
  iIIiiiiI11i . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( iIIiiiiI11i . print_eid_tuple ( ) , False ) , list ( rtr_list . keys ( ) ) ) )
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
 IiI1I1iiIii1ii1I1I = lisp_info ( )
 packet = IiI1I1iiIii1ii1I1I . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 IiI1I1iiIii1ii1I1I . print_info ( )
 if 65 - 65: i11iIiiIii
 if 46 - 46: i11iIiiIii
 if 70 - 70: i1IIi + o0oOOo0O0Ooo
 if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
 iiiII1Ii11I1 = False
 for IiIi1I1i1iIiI in IiI1I1iiIii1ii1I1I . rtr_list :
  O0O0 = IiIi1I1i1iIiI . print_address_no_iid ( )
  if ( O0O0 in lisp_rtr_list ) :
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
   for oooo in list ( lisp_iid_to_interface . keys ( ) ) :
    lisp_update_default_routes ( source , int ( oooo ) , lisp_rtr_list )
    if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
    if 34 - 34: Ii1I
    if 5 - 5: II111iiii . I1ii11iIi11i
    if 85 - 85: I1Ii111 . IiII + II111iiii
    if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
    if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
    if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
 if ( store == False ) :
  return ( [ IiI1I1iiIii1ii1I1I . global_etr_rloc , IiI1I1iiIii1ii1I1I . etr_port , iiiII1Ii11I1 ] )
  if 87 - 87: OOooOOo
  if 44 - 44: Oo0Ooo + iIii1I11I1II1
  if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
  if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
  if 10 - 10: O0 / I11i
  if 29 - 29: i11iIiiIii % I11i
 for oooOOoO0oo0 in lisp_db_list :
  for iiIiIIi1I in oooOOoO0oo0 . rloc_set :
   IIIi1iI1 = iiIiIIi1I . rloc
   i111IIiIiiI1 = iiIiIIi1I . interface
   if ( i111IIiIiiI1 == None ) :
    if ( IIIi1iI1 . is_null ( ) ) : continue
    if ( IIIi1iI1 . is_local ( ) == False ) : continue
    if ( IiI1I1iiIii1ii1I1I . private_etr_rloc . is_null ( ) == False and
 IIIi1iI1 . is_exact_match ( IiI1I1iiIii1ii1I1I . private_etr_rloc ) == False ) :
     continue
     if 49 - 49: I11i
   elif ( IiI1I1iiIii1ii1I1I . private_etr_rloc . is_dist_name ( ) ) :
    i1Ii1iiI = IiI1I1iiIii1ii1I1I . private_etr_rloc . address
    if ( i1Ii1iiI != iiIiIIi1I . rloc_name ) : continue
    if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
    if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
   i1iiii = green ( oooOOoO0oo0 . eid . print_prefix ( ) , False )
   IIIOo0O = red ( IIIi1iI1 . print_address_no_iid ( ) , False )
   if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
   OO0oooo00 = IiI1I1iiIii1ii1I1I . global_etr_rloc . is_exact_match ( IIIi1iI1 )
   if ( iiIiIIi1I . translated_port == 0 and OO0oooo00 ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( IIIOo0O ,
 i111IIiIiiI1 , i1iiii ) )
    continue
    if 60 - 60: Ii1I . Ii1I . I11i / OoooooooOO + I1IiiI % iIii1I11I1II1
    if 8 - 8: IiII + IiII / I1ii11iIi11i
    if 49 - 49: I11i + OOooOOo - I1ii11iIi11i
    if 23 - 23: OOooOOo % I1ii11iIi11i + iIii1I11I1II1 + iII111i
    if 9 - 9: OOooOOo * o0oOOo0O0Ooo / I11i . i11iIiiIii
   i1iI11Ii1 = IiI1I1iiIii1ii1I1I . global_etr_rloc
   oOOOOo0 = iiIiIIi1I . translated_rloc
   if ( oOOOOo0 . is_exact_match ( i1iI11Ii1 ) and
 IiI1I1iiIii1ii1I1I . etr_port == iiIiIIi1I . translated_port ) : continue
   if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( IiI1I1iiIii1ii1I1I . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # OoooooooOO - iII111i
 IiI1I1iiIii1ii1I1I . etr_port , IIIOo0O , i111IIiIiiI1 , i1iiii ) )
   if 9 - 9: II111iiii % I1ii11iIi11i
   iiIiIIi1I . store_translated_rloc ( IiI1I1iiIii1ii1I1I . global_etr_rloc ,
 IiI1I1iiIii1ii1I1I . etr_port )
   if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
   if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
 return ( [ IiI1I1iiIii1ii1I1I . global_etr_rloc , IiI1I1iiIii1ii1I1I . etr_port , iiiII1Ii11I1 ] )
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
 oo0oO = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 oOOO0O = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 67 - 67: I1IiiI / i11iIiiIii - I1Ii111 % OoooooooOO
 if 36 - 36: oO0o % iII111i % oO0o
 if 56 - 56: ooOoO0o - O0 + iII111i % I11i / i1IIi
 if 78 - 78: i1IIi . iIii1I11I1II1
 oo0oO . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , oo0oO , None )
 oo0oO . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , oo0oO , None )
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
 IiI = lisp_get_interface_address ( rloc . interface )
 if ( IiI == None ) : return
 if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
 I1iii = rloc . rloc . print_address_no_iid ( )
 o000ooOo0o0Oo = IiI . print_address_no_iid ( )
 if 7 - 7: ooOoO0o * o0oOOo0O0Ooo + ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
 if ( I1iii == o000ooOo0o0Oo ) : return
 if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , I1iii , o000ooOo0o0Oo ) )
 if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
 if 72 - 72: i11iIiiIii * I11i
 rloc . rloc . copy_address ( IiI )
 lisp_myrlocs [ 0 ] = IiI
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
  iIIi11I = lisp_get_nat_info ( IIIi1iI1 . rloc , IIIi1iI1 . rloc_name )
  if ( iIIi11I == None ) : continue
  if ( IIIi1iI1 . translated_port == iIIi11I . port ) : continue
  if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( IIIi1iI1 . translated_port , iIIi11I . port ,
  # iII111i . I1ii11iIi11i % Ii1I . ooOoO0o
 red ( IIIi1iI1 . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 84 - 84: Ii1I / I1Ii111 % OoO0O00 % OoOoOO00 * i11iIiiIii . O0
  IIIi1iI1 . store_translated_rloc ( IIIi1iI1 . rloc , iIIi11I . port )
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
 i1i111Iiiiiii = lisp_print_elapsed ( mc . last_refresh_time )
 iiiiiiiiII1i = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( iiiiiiiiII1i , False ) , bold ( "timed out" , False ) , i1i111Iiiiiii ) )
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
  i1iII1iI , oo0Oo00OO0000 = lisp_timeout_map_cache_entry ( mc , oo0Oo00OO0000 )
  if ( oo0Oo00OO0000 == [ ] or mc != oo0Oo00OO0000 [ - 1 ] ) :
   iiOoOo = lisp_write_checkpoint_entry ( iiOoOo , mc )
   if 80 - 80: I1ii11iIi11i + Ii1I
  return ( [ i1iII1iI , parms ] )
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
 I1iII1IIi1IiI = [ [ ] , [ ] ]
 I1iII1IIi1IiI = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , I1iII1IIi1IiI )
 if 58 - 58: Ii1I
 if 20 - 20: OOooOOo
 if 93 - 93: i1IIi . IiII % O0 * iII111i
 if 84 - 84: I11i
 if 99 - 99: I1ii11iIi11i
 oo0Oo00OO0000 = I1iII1IIi1IiI [ 0 ]
 for iIIiiiiI11i in oo0Oo00OO0000 : iIIiiiiI11i . delete_cache ( )
 if 78 - 78: I1Ii111 . IiII - OOooOOo
 if 93 - 93: iIii1I11I1II1
 if 33 - 33: OOooOOo . i1IIi
 if 63 - 63: II111iiii . oO0o * IiII
 iiOoOo = I1iII1IIi1IiI [ 1 ]
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
 if ( hostname not in lisp_nat_state_info ) :
  lisp_nat_state_info [ hostname ] = [ o0OO0o0oOo0Oo ]
  lprint ( iiII1Ii1 . format ( "Store initial" ) )
  return ( True )
  if 21 - 21: IiII * I1IiiI
  if 95 - 95: O0 - i11iIiiIii - o0oOOo0O0Ooo
  if 97 - 97: OoooooooOO + oO0o . iIii1I11I1II1 / Ii1I / Oo0Ooo
  if 13 - 13: i1IIi - ooOoO0o % i11iIiiIii
  if 10 - 10: Ii1I % oO0o + oO0o * OoOoOO00 % iII111i / o0oOOo0O0Ooo
  if 17 - 17: iII111i / I1IiiI . II111iiii - OoO0O00 + iII111i
 iIIi11I = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( iIIi11I . address == O0O0 and iIIi11I . port == port ) :
  iIIi11I . uptime = lisp_get_timestamp ( )
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
 for iIIi11I in lisp_nat_state_info [ hostname ] :
  if ( iIIi11I . address == O0O0 and iIIi11I . port == port ) :
   o0o0000 = iIIi11I
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
 if ( hostname not in lisp_nat_state_info ) : return ( None )
 if 18 - 18: oO0o
 O0O0 = rloc . print_address_no_iid ( )
 for iIIi11I in lisp_nat_state_info [ hostname ] :
  if ( iIIi11I . address == O0O0 ) : return ( iIIi11I )
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
  for OO0ooo000 in list ( lisp_map_resolvers_list . values ( ) ) :
   O0oooooo0 . append ( OO0ooo000 . map_resolver )
   if 10 - 10: OoO0O00 / i1IIi - I1Ii111 - I11i * i1IIi
  OoOO0O0O0Ooo = O0oooooo0
  if ( OoOO0O0O0Ooo == [ ] ) :
   for IIiiIiI in list ( lisp_map_servers_list . values ( ) ) :
    OoOO0O0O0Ooo . append ( IIiiIiI . map_server )
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
  for iiIiIIi1I in oooOOoO0oo0 . rloc_set :
   lisp_update_local_rloc ( iiIiIIi1I )
   if ( iiIiIIi1I . rloc . is_null ( ) ) : continue
   if ( iiIiIIi1I . interface == None ) : continue
   if 83 - 83: oO0o
   IiI = iiIiIIi1I . rloc . print_address_no_iid ( )
   if ( IiI in O00O00Oo0O ) : continue
   O00O00Oo0O [ IiI ] = iiIiIIi1I . interface
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
 for IiI in O00O00Oo0O :
  i111IIiIiiI1 = O00O00Oo0O [ IiI ]
  OO0O00o0 = red ( IiI , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OO0O00o0 ,
 i111IIiIiiI1 ) )
  ooO000OO = i111IIiIiiI1 if len ( O00O00Oo0O ) > 1 else None
  for dest in OoOO0O0O0Ooo :
   lisp_send_info_request ( lisp_sockets , dest , port , ooO000OO )
   if 20 - 20: I11i
   if 37 - 37: I1Ii111
   if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
   if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
   if 41 - 41: O0 / OoooooooOO - i1IIi
   if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 if ( O0oooooo0 != [ ] ) :
  for OO0ooo000 in list ( lisp_map_resolvers_list . values ( ) ) :
   OO0ooo000 . resolve_dns_name ( )
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
  IiI = value . split ( "." )
  if ( len ( IiI ) != 4 ) : return ( False )
  if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
  for oooO0OoO in IiI :
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
  IiI = value . split ( "-" )
  for iIi1iIIIiIiI in [ "N" , "S" , "W" , "E" ] :
   if ( iIi1iIIIiIiI in IiI ) :
    if ( len ( IiI ) < 8 ) : return ( False )
    return ( True )
    if 86 - 86: Oo0Ooo
    if 97 - 97: I1IiiI
    if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
    if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
    if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
    if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
    if 64 - 64: I1IiiI % ooOoO0o
 if ( value . find ( "-" ) != - 1 ) :
  IiI = value . split ( "-" )
  if ( len ( IiI ) != 3 ) : return ( False )
  if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
  for O0o0O0OoOOoO in IiI :
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
  IiI = value . split ( ":" )
  if ( len ( IiI ) < 2 ) : return ( False )
  if 28 - 28: ooOoO0o
  I11IIoO0oOoOo0oO0O = False
  O0oo0oOo = 0
  for O0o0O0OoOOoO in IiI :
   O0oo0oOo += 1
   if ( O0o0O0OoOOoO == "" ) :
    if ( I11IIoO0oOoOo0oO0O ) :
     if ( len ( IiI ) == O0oo0oOo ) : break
     if ( O0oo0oOo > 2 ) : return ( False )
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
  IiI = value [ 1 : : ]
  for Oooo0Oo0O in IiI :
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
 if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
 if 67 - 67: I1IiiI
def lisp_process_api ( process , lisp_socket , data_structure ) :
 IIIi111II1Iii , I1iII1IIi1IiI = data_structure . split ( "%" )
 if 32 - 32: II111iiii - iIii1I11I1II1 + I11i
 lprint ( "Process API request '{}', parameters: '{}'" . format ( IIIi111II1Iii ,
 I1iII1IIi1IiI ) )
 if 32 - 32: I1ii11iIi11i / i11iIiiIii . OOooOOo . Oo0Ooo
 oOO = [ ]
 if ( IIIi111II1Iii == "map-cache" ) :
  if ( I1iII1IIi1IiI == "" ) :
   oOO = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , oOO )
  else :
   oOO = lisp_process_api_map_cache_entry ( json . loads ( I1iII1IIi1IiI ) )
   if 3 - 3: o0oOOo0O0Ooo
   if 68 - 68: OoOoOO00 + I1ii11iIi11i % i11iIiiIii
 if ( IIIi111II1Iii == "site-cache" ) :
  if ( I1iII1IIi1IiI == "" ) :
   oOO = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 oOO )
  else :
   oOO = lisp_process_api_site_cache_entry ( json . loads ( I1iII1IIi1IiI ) )
   if 58 - 58: OoO0O00 / Oo0Ooo + Ii1I
   if 63 - 63: OOooOOo / I1ii11iIi11i
 if ( IIIi111II1Iii == "site-cache-summary" ) :
  oOO = lisp_process_api_site_cache_summary ( lisp_sites_by_eid )
  if 86 - 86: O0 + iII111i + OoooooooOO / iII111i * I1ii11iIi11i * OoooooooOO
 if ( IIIi111II1Iii == "map-server" ) :
  I1iII1IIi1IiI = { } if ( I1iII1IIi1IiI == "" ) else json . loads ( I1iII1IIi1IiI )
  oOO = lisp_process_api_ms_or_mr ( True , I1iII1IIi1IiI )
  if 89 - 89: oO0o - OOooOOo / iII111i - I1IiiI
 if ( IIIi111II1Iii == "map-resolver" ) :
  I1iII1IIi1IiI = { } if ( I1iII1IIi1IiI == "" ) else json . loads ( I1iII1IIi1IiI )
  oOO = lisp_process_api_ms_or_mr ( False , I1iII1IIi1IiI )
  if 78 - 78: iIii1I11I1II1 + O0 + IiII . I11i / i11iIiiIii . O0
 if ( IIIi111II1Iii == "database-mapping" ) :
  oOO = lisp_process_api_database_mapping ( )
  if 21 - 21: OoOoOO00 * OOooOOo + oO0o + O0
  if 59 - 59: i1IIi / OoooooooOO . OoO0O00 / OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
  if 58 - 58: IiII . Ii1I + II111iiii
  if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
  if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 oOO = json . dumps ( oOO )
 OO = lisp_api_ipc ( process , oOO )
 lisp_ipc ( OO , lisp_socket , "lisp-core" )
 return
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 if 54 - 54: oO0o * II111iiii
def lisp_process_api_map_cache ( mc , data ) :
 if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 if 98 - 98: ooOoO0o
 if 73 - 73: I1Ii111
 if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
 if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
 if 76 - 76: iII111i * OOooOOo
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if 40 - 40: iII111i
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
 if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
def lisp_gather_map_cache_data ( mc , data ) :
 oo0O00OOOOO = { }
 oo0O00OOOOO [ "instance-id" ] = str ( mc . eid . instance_id )
 oo0O00OOOOO [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  oo0O00OOOOO [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
 oo0O00OOOOO [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 oo0O00OOOOO [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 oo0O00OOOOO [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 oo0O00OOOOO [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 5 - 5: Oo0Ooo . I1Ii111
 if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
 if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
 if 23 - 23: iIii1I11I1II1 - I1IiiI
 if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
 oOO000OOO = [ ]
 for IIIi1iI1 in mc . rloc_set :
  iiiI1I = lisp_fill_rloc_in_json ( IIIi1iI1 )
  if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
  if 25 - 25: ooOoO0o * I1Ii111 * oO0o
  if 64 - 64: Ii1I / I1ii11iIi11i
  if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
  if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
  if ( IIIi1iI1 . rloc . is_multicast_address ( ) ) :
   iiiI1I [ "multicast-rloc-set" ] = [ ]
   for oooO0oo0ooO in list ( IIIi1iI1 . multicast_rloc_probe_list . values ( ) ) :
    OO0ooo000 = lisp_fill_rloc_in_json ( oooO0oo0ooO )
    iiiI1I [ "multicast-rloc-set" ] . append ( OO0ooo000 )
    if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
    if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
    if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
  oOO000OOO . append ( iiiI1I )
  if 55 - 55: OoO0O00
 oo0O00OOOOO [ "rloc-set" ] = oOO000OOO
 if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
 data . append ( oo0O00OOOOO )
 return ( [ True , data ] )
 if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 if 43 - 43: Oo0Ooo
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
 if 66 - 66: o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
def lisp_fill_rloc_in_json ( rloc ) :
 iiiI1I = { }
 if ( rloc . rloc_exists ( ) ) :
  iiiI1I [ "address" ] = rloc . rloc . print_address_no_iid ( )
  if 38 - 38: ooOoO0o
  if 5 - 5: OoooooooOO + iII111i - I11i
 if ( rloc . translated_port != 0 ) :
  iiiI1I [ "encap-port" ] = str ( rloc . translated_port )
  if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
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
 iIiiii11i = rloc . last_rloc_probe_reply
 if ( iIiiii11i ) :
  iiiI1I [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( iIiiii11i )
  iiiI1I [ "rloc-probe-rtt" ] = str ( rloc . rloc_probe_rtt )
  if 54 - 54: OoO0O00 * OOooOOo / I11i
 iiiI1I [ "rloc-hop-count" ] = rloc . rloc_probe_hops
 iiiI1I [ "recent-rloc-hop-counts" ] = rloc . recent_rloc_probe_hops
 if 77 - 77: Oo0Ooo
 iiiI1I [ "rloc-probe-latency" ] = rloc . rloc_probe_latency
 iiiI1I [ "recent-rloc-probe-latencies" ] = rloc . recent_rloc_probe_latencies
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
 IIiiiiIiiiIIiI1 = [ ]
 for iIIiiIii11I1i in rloc . recent_rloc_probe_rtts : IIiiiiIiiiIIiI1 . append ( str ( iIIiiIii11I1i ) )
 iiiI1I [ "recent-rloc-probe-rtts" ] = IIiiiiIiiiIIiI1
 return ( iiiI1I )
 if 48 - 48: O0 - iII111i / ooOoO0o + I1IiiI - IiII % oO0o
 if 99 - 99: IiII
 if 62 - 62: II111iiii - iII111i . oO0o
 if 96 - 96: O0 . I11i % I1IiiI % o0oOOo0O0Ooo
 if 80 - 80: IiII / iIii1I11I1II1
 if 17 - 17: I11i * I11i - O0 / IiII + OoOoOO00
 if 65 - 65: I1Ii111 * i1IIi
def lisp_process_api_map_cache_entry ( parms ) :
 oooo = parms [ "instance-id" ]
 oooo = 0 if ( oooo == "" ) else int ( oooo )
 if 10 - 10: OOooOOo % IiII
 if 20 - 20: I11i / OoooooooOO % OoOoOO00 . oO0o * I1IiiI % IiII
 if 84 - 84: I1ii11iIi11i % I11i / OOooOOo % O0
 if 63 - 63: Ii1I / I1ii11iIi11i / Oo0Ooo
 oo0oO = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 oo0oO . store_prefix ( parms [ "eid-prefix" ] )
 IIi11ii = oo0oO
 O0oo0OoO0oo = oo0oO
 if 74 - 74: i1IIi
 if 38 - 38: II111iiii * i1IIi
 if 43 - 43: O0 - OOooOOo / I1IiiI * II111iiii . OoooooooOO / OoOoOO00
 if 77 - 77: OoOoOO00
 if 10 - 10: IiII / i11iIiiIii
 iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 if ( "group-prefix" in parms ) :
  iiI . store_prefix ( parms [ "group-prefix" ] )
  IIi11ii = iiI
  if 19 - 19: OoO0O00
  if 100 - 100: I1ii11iIi11i - I1ii11iIi11i
 oOO = [ ]
 iIIiiiiI11i = lisp_map_cache_lookup ( O0oo0OoO0oo , IIi11ii )
 if ( iIIiiiiI11i ) : i1iII1iI , oOO = lisp_process_api_map_cache ( iIIiiiiI11i , oOO )
 return ( oOO )
 if 38 - 38: I1Ii111
 if 23 - 23: Ii1I . I1ii11iIi11i + I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
 if 2 - 2: I11i - II111iiii / I1Ii111
 if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
 if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
def lisp_process_api_site_cache_summary ( site_cache ) :
 i1iIiII1II11i = { "site" : "" , "registrations" : [ ] }
 oo0O00OOOOO = { "eid-prefix" : "" , "count" : 0 , "registered-count" : 0 }
 if 76 - 76: ooOoO0o . I11i * OoO0O00
 OooO = { }
 for Iii1iii1II in site_cache . cache_sorted :
  for Ii1iIi1I1I1I in list ( site_cache . cache [ Iii1iii1II ] . entries . values ( ) ) :
   if ( Ii1iIi1I1I1I . accept_more_specifics == False ) : continue
   if ( Ii1iIi1I1I1I . site . site_name not in OooO ) :
    OooO [ Ii1iIi1I1I1I . site . site_name ] = [ ]
    if 89 - 89: o0oOOo0O0Ooo - OOooOOo * I1Ii111 . i1IIi % I1IiiI . I11i
   oO0ooOOO = copy . deepcopy ( oo0O00OOOOO )
   oO0ooOOO [ "eid-prefix" ] = Ii1iIi1I1I1I . eid . print_prefix ( )
   oO0ooOOO [ "count" ] = len ( Ii1iIi1I1I1I . more_specific_registrations )
   for o00oo0oOOoo0O in Ii1iIi1I1I1I . more_specific_registrations :
    if ( o00oo0oOOoo0O . registered ) : oO0ooOOO [ "registered-count" ] += 1
    if 37 - 37: OoO0O00 . I1IiiI + I1ii11iIi11i - iIii1I11I1II1 % O0 * OoOoOO00
   OooO [ Ii1iIi1I1I1I . site . site_name ] . append ( oO0ooOOO )
   if 28 - 28: ooOoO0o + Oo0Ooo - I1ii11iIi11i
   if 16 - 16: O0 - OoO0O00 % Ii1I % O0
   if 51 - 51: iIii1I11I1II1 * i11iIiiIii . I1IiiI + o0oOOo0O0Ooo / iII111i - I1IiiI
 oOO = [ ]
 for o00OooO0o0Ooo in OooO :
  I111 = copy . deepcopy ( i1iIiII1II11i )
  I111 [ "site" ] = o00OooO0o0Ooo
  I111 [ "registrations" ] = OooO [ o00OooO0o0Ooo ]
  oOO . append ( I111 )
  if 73 - 73: OOooOOo
 return ( oOO )
 if 100 - 100: o0oOOo0O0Ooo - OoOoOO00
 if 91 - 91: II111iiii / i11iIiiIii . Oo0Ooo * iIii1I11I1II1
 if 6 - 6: ooOoO0o * Oo0Ooo . OoO0O00
 if 24 - 24: O0 * oO0o % O0 * iIii1I11I1II1 - OoO0O00
 if 18 - 18: Ii1I + I1ii11iIi11i % I1ii11iIi11i + II111iiii
 if 86 - 86: iII111i . O0 - iIii1I11I1II1 - iIii1I11I1II1
 if 79 - 79: OoOoOO00 + Ii1I - oO0o - iIii1I11I1II1 + OoooooooOO
def lisp_process_api_site_cache ( se , data ) :
 if 87 - 87: ooOoO0o
 if 74 - 74: o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1IiiI - I1ii11iIi11i
 if 40 - 40: II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
 if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
 if 45 - 45: OOooOOo / Ii1I % O0
 if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 I1IIIi = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 iIIIIII1I = data [ "dns-name" ] if ( "dns-name" in data ) else None
 if ( "address" in data ) :
  I1IIIi . store_address ( data [ "address" ] )
  if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
  if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
 oOO0 = { }
 if ( ms_or_mr ) :
  for IIiiIiI in list ( lisp_map_servers_list . values ( ) ) :
   if ( iIIIIII1I ) :
    if ( iIIIIII1I != IIiiIiI . dns_name ) : continue
   else :
    if ( I1IIIi . is_exact_match ( IIiiIiI . map_server ) == False ) : continue
    if 96 - 96: oO0o
    if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
   oOO0 [ "dns-name" ] = IIiiIiI . dns_name
   oOO0 [ "address" ] = IIiiIiI . map_server . print_address_no_iid ( )
   oOO0 [ "ms-name" ] = "" if IIiiIiI . ms_name == None else IIiiIiI . ms_name
   return ( [ oOO0 ] )
   if 64 - 64: I1IiiI % i11iIiiIii / oO0o
 else :
  for OO0ooo000 in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( iIIIIII1I ) :
    if ( iIIIIII1I != OO0ooo000 . dns_name ) : continue
   else :
    if ( I1IIIi . is_exact_match ( OO0ooo000 . map_resolver ) == False ) : continue
    if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
    if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
   oOO0 [ "dns-name" ] = OO0ooo000 . dns_name
   oOO0 [ "address" ] = OO0ooo000 . map_resolver . print_address_no_iid ( )
   oOO0 [ "mr-name" ] = "" if OO0ooo000 . mr_name == None else OO0ooo000 . mr_name
   return ( [ oOO0 ] )
   if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
   if 31 - 31: OoO0O00
 return ( [ ] )
 if 89 - 89: II111iiii
 if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
 if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
 if 85 - 85: O0 * OOooOOo % I1Ii111
 if 33 - 33: O0
 if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
 if 43 - 43: iIii1I11I1II1
 if 88 - 88: I1IiiI - OoO0O00 . O0 . oO0o
def lisp_process_api_database_mapping ( ) :
 oOO = [ ]
 if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
 for oooOOoO0oo0 in lisp_db_list :
  oo0O00OOOOO = { }
  oo0O00OOOOO [ "eid-prefix" ] = oooOOoO0oo0 . eid . print_prefix ( )
  if ( oooOOoO0oo0 . group . is_null ( ) == False ) :
   oo0O00OOOOO [ "group-prefix" ] = oooOOoO0oo0 . group . print_prefix ( )
   if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
   if 59 - 59: OOooOOo - o0oOOo0O0Ooo
  OOOO00 = [ ]
  for iiiI1I in oooOOoO0oo0 . rloc_set :
   IIIi1iI1 = { }
   if ( iiiI1I . rloc . is_null ( ) == False ) :
    IIIi1iI1 [ "rloc" ] = iiiI1I . rloc . print_address_no_iid ( )
    if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
   if ( iiiI1I . rloc_name != None ) : IIIi1iI1 [ "rloc-name" ] = iiiI1I . rloc_name
   if ( iiiI1I . interface != None ) : IIIi1iI1 [ "interface" ] = iiiI1I . interface
   O0o0oOOo0O = iiiI1I . translated_rloc
   if ( O0o0oOOo0O . is_null ( ) == False ) :
    IIIi1iI1 [ "translated-rloc" ] = O0o0oOOo0O . print_address_no_iid ( )
    if 25 - 25: ooOoO0o * Oo0Ooo / I11i - i1IIi / II111iiii
   if ( IIIi1iI1 != { } ) : OOOO00 . append ( IIIi1iI1 )
   if 60 - 60: I1IiiI . Oo0Ooo / IiII - OoooooooOO
   if 65 - 65: OoO0O00 - Ii1I
   if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
   if 15 - 15: Oo0Ooo
   if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
  oo0O00OOOOO [ "rlocs" ] = OOOO00
  if 84 - 84: o0oOOo0O0Ooo * I11i
  if 22 - 22: i1IIi + OOooOOo % OoooooooOO
  if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
  if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
  oOO . append ( oo0O00OOOOO )
  if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 return ( oOO )
 if 66 - 66: OoooooooOO
 if 90 - 90: IiII - OoOoOO00
 if 98 - 98: Oo0Ooo / oO0o . Ii1I
 if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
 if 37 - 37: iII111i - Ii1I . oO0o
 if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
 if 25 - 25: oO0o
def lisp_gather_site_cache_data ( se , data ) :
 oo0O00OOOOO = { }
 oo0O00OOOOO [ "site-name" ] = se . site . site_name
 oo0O00OOOOO [ "instance-id" ] = str ( se . eid . instance_id )
 oo0O00OOOOO [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  oo0O00OOOOO [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
 oo0O00OOOOO [ "registered" ] = "yes" if se . registered else "no"
 oo0O00OOOOO [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 oo0O00OOOOO [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
 IiI = se . last_registerer
 IiI = "none" if IiI . is_null ( ) else IiI . print_address ( )
 oo0O00OOOOO [ "last-registerer" ] = IiI
 oo0O00OOOOO [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 oo0O00OOOOO [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 oo0O00OOOOO [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  oo0O00OOOOO [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 39 - 39: iIii1I11I1II1 % ooOoO0o
  if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
  if 36 - 36: IiII / I1IiiI % iII111i / iII111i
  if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
  if 65 - 65: O0 + O0 * I1Ii111
 oOO000OOO = [ ]
 for IIIi1iI1 in se . registered_rlocs :
  iiiI1I = { }
  iiiI1I [ "address" ] = IIIi1iI1 . rloc . print_address_no_iid ( ) if IIIi1iI1 . rloc_exists ( ) else "none"
  if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
  if 16 - 16: I11i % iII111i
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
  if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
  oOO000OOO . append ( iiiI1I )
  if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
 oo0O00OOOOO [ "registered-rlocs" ] = oOO000OOO
 if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
 data . append ( oo0O00OOOOO )
 return ( [ True , data ] )
 if 1 - 1: O0 / iIii1I11I1II1
 if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
 if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
 if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
 if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
 if 16 - 16: o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii . I1ii11iIi11i
def lisp_process_api_site_cache_entry ( parms ) :
 oooo = parms [ "instance-id" ]
 oooo = 0 if ( oooo == "" ) else int ( oooo )
 if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
 if 100 - 100: o0oOOo0O0Ooo
 if 95 - 95: iII111i * oO0o * i1IIi
 oo0oO = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 oo0oO . store_prefix ( parms [ "eid-prefix" ] )
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
 if ( "group-prefix" in parms ) :
  iiI . store_prefix ( parms [ "group-prefix" ] )
  if 76 - 76: OoO0O00
  if 92 - 92: iIii1I11I1II1 * O0 % I11i
 oOO = [ ]
 Ii1iIi1I1I1I = lisp_site_eid_lookup ( oo0oO , iiI , False )
 if ( Ii1iIi1I1I1I ) : lisp_gather_site_cache_data ( Ii1iIi1I1I1I , oOO )
 return ( oOO )
 if 92 - 92: OoOoOO00 + oO0o
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
 if 28 - 28: I1IiiI . iIii1I11I1II1
 if 12 - 12: I1Ii111 * OOooOOo
 if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
 if 45 - 45: OoooooooOO * oO0o
 if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
def lisp_get_interface_instance_id ( device , source_eid ) :
 i111IIiIiiI1 = None
 if ( device in lisp_myinterfaces ) :
  i111IIiIiiI1 = lisp_myinterfaces [ device ]
  if 16 - 16: Oo0Ooo
  if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
  if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
  if 67 - 67: I1IiiI
  if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
  if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 if ( i111IIiIiiI1 == None or i111IIiIiiI1 . instance_id == None ) :
  return ( lisp_default_iid )
  if 33 - 33: OOooOOo - OoooooooOO . iII111i
  if 2 - 2: I11i + i1IIi
  if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
  if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
  if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
  if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
  if 12 - 12: II111iiii * O0 - Oo0Ooo + o0oOOo0O0Ooo . Oo0Ooo + iIii1I11I1II1
  if 4 - 4: I1Ii111 - I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / oO0o
  if 18 - 18: iIii1I11I1II1 . ooOoO0o
 oooo = i111IIiIiiI1 . get_instance_id ( )
 if ( source_eid == None ) : return ( oooo )
 if 68 - 68: o0oOOo0O0Ooo
 IIIi1iI1IiI1IiI = source_eid . instance_id
 O0ooo = None
 for i111IIiIiiI1 in lisp_multi_tenant_interfaces :
  if ( i111IIiIiiI1 . device != device ) : continue
  o00oO0ooO000 = i111IIiIiiI1 . multi_tenant_eid
  source_eid . instance_id = o00oO0ooO000 . instance_id
  if ( source_eid . is_more_specific ( o00oO0ooO000 ) == False ) : continue
  if ( O0ooo == None or O0ooo . multi_tenant_eid . mask_len < o00oO0ooO000 . mask_len ) :
   O0ooo = i111IIiIiiI1
   if 41 - 41: iII111i
   if 52 - 52: I1ii11iIi11i / I1ii11iIi11i
 source_eid . instance_id = IIIi1iI1IiI1IiI
 if 45 - 45: i1IIi * OoooooooOO . oO0o
 if ( O0ooo == None ) : return ( oooo )
 return ( O0ooo . get_instance_id ( ) )
 if 38 - 38: I1ii11iIi11i / o0oOOo0O0Ooo
 if 95 - 95: iIii1I11I1II1 / OoOoOO00 % I1Ii111
 if 54 - 54: OoooooooOO % Ii1I
 if 100 - 100: OOooOOo - I11i . O0 * i1IIi % OoooooooOO - ooOoO0o
 if 54 - 54: O0 + I11i
 if 71 - 71: OoOoOO00
 if 29 - 29: O0 . i11iIiiIii
 if 51 - 51: IiII
 if 53 - 53: O0
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( device not in lisp_myinterfaces ) : return ( None )
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 i111IIiIiiI1 = lisp_myinterfaces [ device ]
 o00OoOoO = device if i111IIiIiiI1 . dynamic_eid_device == None else i111IIiIiiI1 . dynamic_eid_device
 if 24 - 24: iII111i . OoO0O00 * Ii1I - OOooOOo . I11i
 if 90 - 90: I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - i1IIi
 if ( i111IIiIiiI1 . does_dynamic_eid_match ( eid ) ) : return ( o00OoOoO )
 return ( None )
 if 94 - 94: OoooooooOO
 if 80 - 80: O0 * OOooOOo + i1IIi + i11iIiiIii * o0oOOo0O0Ooo
 if 14 - 14: II111iiii * OOooOOo - O0 / I1ii11iIi11i . OoO0O00 . ooOoO0o
 if 98 - 98: o0oOOo0O0Ooo . i1IIi
 if 83 - 83: i11iIiiIii + OOooOOo % iII111i
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
 for III in lisp_rloc_probe_list :
  II1111 = lisp_rloc_probe_list [ III ]
  lprint ( "RLOC {}:" . format ( III ) )
  for iiiI1I , oO0ooOOO , Oo in II1111 :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( iiiI1I ) ) , oO0ooOOO . print_prefix ( ) ,
 Oo . print_prefix ( ) , iiiI1I . translated_port ) )
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
 IIIi1iI1 , oO0ooOOO , Oo = eid_list [ 0 ]
 O0O0oO0O0 = [ lisp_print_eid_tuple ( oO0ooOOO , Oo ) ]
 if 83 - 83: ooOoO0o . iII111i / Ii1I * I11i % iIii1I11I1II1 * I1ii11iIi11i
 for IIIi1iI1 , oO0ooOOO , Oo in eid_list [ 1 : : ] :
  IIIi1iI1 . state = LISP_RLOC_UNREACH_STATE
  IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
  O0O0oO0O0 . append ( lisp_print_eid_tuple ( oO0ooOOO , Oo ) )
  if 83 - 83: I11i . I1ii11iIi11i / I1Ii111 / II111iiii
  if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 o0Oooo0oO0o0O = bold ( "unreachable" , False )
 IIIOo0O = red ( IIIi1iI1 . rloc . print_address_no_iid ( ) , False )
 if 77 - 77: ooOoO0o * Oo0Ooo - ooOoO0o * iII111i
 for oo0oO in O0O0oO0O0 :
  oO0ooOOO = green ( oo0oO , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( IIIOo0O , o0Oooo0oO0o0O , oO0ooOOO ) )
  if 31 - 31: I1ii11iIi11i / iIii1I11I1II1 / iII111i
  if 14 - 14: O0 * Oo0Ooo / i1IIi
  if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
  if 78 - 78: II111iiii % OOooOOo
  if 6 - 6: OOooOOo
  if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 for IIIi1iI1 , oO0ooOOO , Oo in eid_list :
  iIIiiiiI11i = lisp_map_cache . lookup_cache ( oO0ooOOO , True )
  if ( iIIiiiiI11i ) : lisp_write_ipc_map_cache ( True , iIIiiiiI11i )
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
 I1IiIIiI11i1Ii = lisp_get_default_route_next_hops ( )
 if 84 - 84: iIii1I11I1II1 . Oo0Ooo - OoooooooOO % Oo0Ooo
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 27 - 27: I1ii11iIi11i - ooOoO0o + I11i - I1ii11iIi11i
 if 57 - 57: Oo0Ooo
 if 31 - 31: I1IiiI % Ii1I / OOooOOo + OoooooooOO . i11iIiiIii
 if 87 - 87: iII111i + IiII * I1ii11iIi11i . iII111i + Ii1I - II111iiii
 if 87 - 87: OoOoOO00 . o0oOOo0O0Ooo + I1ii11iIi11i
 O0oo0oOo = 0
 iiIii11Ii = bold ( "RLOC-probe" , False )
 for oOOoo0O000OO in list ( lisp_rloc_probe_list . values ( ) ) :
  if 79 - 79: Ii1I
  if 56 - 56: I1ii11iIi11i
  if 40 - 40: OoooooooOO
  if 100 - 100: IiII - I11i
  if 79 - 79: iII111i % O0
  oooOO0 = None
  for i1Ii1IiII1i , oo0oO , iiI in oOOoo0O000OO :
   O0O0 = i1Ii1IiII1i . rloc . print_address_no_iid ( )
   if 30 - 30: Oo0Ooo + I1Ii111 / OOooOOo
   if 74 - 74: iIii1I11I1II1
   if 69 - 69: ooOoO0o % iIii1I11I1II1 * o0oOOo0O0Ooo + OoOoOO00 % I1Ii111 % Oo0Ooo
   if 64 - 64: iIii1I11I1II1 * Ii1I * ooOoO0o * i11iIiiIii
   I1iI111i11i1 , o00oo0OOooO0oOo , II1ii1 = lisp_allow_gleaning ( oo0oO , None , i1Ii1IiII1i )
   if ( I1iI111i11i1 and o00oo0OOooO0oOo == False ) :
    oO0ooOOO = green ( oo0oO . print_address ( ) , False )
    O0O0 += ":{}" . format ( i1Ii1IiII1i . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( O0O0 , False ) , oO0ooOOO ) )
    if 76 - 76: Ii1I
    continue
    if 31 - 31: ooOoO0o
    if 70 - 70: O0
    if 42 - 42: I1Ii111 + OoooooooOO + I11i
    if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
    if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
    if 27 - 27: O0 / Oo0Ooo . oO0o
    if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
   if ( i1Ii1IiII1i . down_state ( ) ) : continue
   if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
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
   if ( oooOO0 ) :
    i1Ii1IiII1i . last_rloc_probe_nonce = oooOO0 . last_rloc_probe_nonce
    if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
    if ( oooOO0 . translated_port == i1Ii1IiII1i . translated_port and oooOO0 . rloc_name == i1Ii1IiII1i . rloc_name ) :
     if 51 - 51: OoO0O00 - OoO0O00 * IiII
     oO0ooOOO = green ( lisp_print_eid_tuple ( oo0oO , iiI ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( O0O0 , False ) , oO0ooOOO ) )
     if 24 - 24: OoooooooOO . II111iiii
     if 97 - 97: II111iiii . O0
     if 18 - 18: iII111i
     if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
     if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
     if 25 - 25: OoO0O00
     i1Ii1IiII1i . last_rloc_probe = oooOO0 . last_rloc_probe
     continue
     if 54 - 54: O0
     if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
     if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
   o0o0O0o0000 = None
   IIIi1iI1 = None
   while ( True ) :
    IIIi1iI1 = i1Ii1IiII1i if IIIi1iI1 == None else IIIi1iI1 . next_rloc
    if ( IIIi1iI1 == None ) : break
    if 92 - 92: ooOoO0o - iII111i
    if 69 - 69: iII111i
    if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
    if 63 - 63: oO0o * OoO0O00 * oO0o
    if 31 - 31: Oo0Ooo
    if ( IIIi1iI1 . rloc_next_hop != None ) :
     if ( IIIi1iI1 . rloc_next_hop not in I1IiIIiI11i1Ii ) :
      if ( IIIi1iI1 . up_state ( ) ) :
       IiI11I111 , IiI1iI = IIIi1iI1 . rloc_next_hop
       IIIi1iI1 . state = LISP_RLOC_UNREACH_STATE
       IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( IIIi1iI1 . rloc , False )
       if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
      o0Oooo0oO0o0O = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( IiI1iI , IiI11I111 ,
 red ( O0O0 , False ) , o0Oooo0oO0o0O ) )
      continue
      if 67 - 67: I1Ii111 . I1ii11iIi11i
      if 2 - 2: O0 + I1Ii111
      if 82 - 82: Ii1I / iII111i
      if 13 - 13: I11i + iII111i
      if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
      if 59 - 59: Oo0Ooo + I1ii11iIi11i
    i11iII11I1III = IIIi1iI1 . last_rloc_probe
    O0OoOOOO00Ooo = 0 if i11iII11I1III == None else time . time ( ) - i11iII11I1III
    if ( IIIi1iI1 . unreach_state ( ) and O0OoOOOO00Ooo < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( O0O0 , False ) ) )
     if 27 - 27: O0 % OoOoOO00 * Oo0Ooo * Ii1I * iII111i
     continue
     if 37 - 37: i11iIiiIii + OoO0O00 . OoOoOO00 / I1ii11iIi11i / I1IiiI + iIii1I11I1II1
     if 3 - 3: I1ii11iIi11i * ooOoO0o - OOooOOo - iII111i
     if 67 - 67: O0 / Oo0Ooo / Oo0Ooo / ooOoO0o
     if 72 - 72: o0oOOo0O0Ooo . i11iIiiIii
     if 59 - 59: OoOoOO00 . Ii1I - ooOoO0o - oO0o
     if 13 - 13: OoOoOO00 . IiII / i11iIiiIii - OOooOOo
    I111Ii1I1I1iI = lisp_get_echo_nonce ( None , O0O0 )
    if ( I111Ii1I1I1iI and I111Ii1I1I1iI . request_nonce_timeout ( ) ) :
     IIIi1iI1 . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
     o0Oooo0oO0o0O = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( O0O0 , False ) , o0Oooo0oO0o0O ) )
     if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
     lisp_update_rtr_updown ( IIIi1iI1 . rloc , False )
     continue
     if 55 - 55: I1Ii111 + ooOoO0o
     if 58 - 58: iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
     if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
     if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
     if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
     if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
    if ( I111Ii1I1I1iI and I111Ii1I1I1iI . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( O0O0 , False ) ) )
     if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
     continue
     if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
     if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
     if 62 - 62: iII111i - I1IiiI + OoooooooOO
     if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
     if 49 - 49: II111iiii
     if 99 - 99: Oo0Ooo . OOooOOo
    if ( IIIi1iI1 . last_rloc_probe != None ) :
     i11iII11I1III = IIIi1iI1 . last_rloc_probe_reply
     if ( i11iII11I1III == None ) : i11iII11I1III = 0
     O0OoOOOO00Ooo = time . time ( ) - i11iII11I1III
     if ( IIIi1iI1 . up_state ( ) and O0OoOOOO00Ooo >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
      IIIi1iI1 . state = LISP_RLOC_UNREACH_STATE
      IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( IIIi1iI1 . rloc , False )
      o0Oooo0oO0o0O = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( O0O0 , False ) , o0Oooo0oO0o0O ) )
      if 70 - 70: O0 % I1Ii111
      if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
      lisp_mark_rlocs_for_other_eids ( oOOoo0O000OO )
      if 82 - 82: ooOoO0o % Oo0Ooo
      if 26 - 26: OoO0O00 + i11iIiiIii % I11i . I1ii11iIi11i
      if 76 - 76: i1IIi + ooOoO0o - Oo0Ooo + OoOoOO00 / I1ii11iIi11i . OOooOOo
    IIIi1iI1 . last_rloc_probe = lisp_get_timestamp ( )
    if 50 - 50: IiII - Ii1I % iIii1I11I1II1
    oOO00OOo0 = "" if IIIi1iI1 . unreach_state ( ) == False else " unreachable"
    if 76 - 76: iII111i / II111iiii / I11i
    if 62 - 62: I1ii11iIi11i
    if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
    if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
    if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
    if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
    if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
    I1III1iIIIi1i = ""
    IiI1iI = None
    if ( IIIi1iI1 . rloc_next_hop != None ) :
     IiI11I111 , IiI1iI = IIIi1iI1 . rloc_next_hop
     lisp_install_host_route ( O0O0 , IiI1iI , True )
     I1III1iIIIi1i = ", send on nh {}({})" . format ( IiI1iI , IiI11I111 )
     if 22 - 22: IiII % II111iiii * II111iiii . OOooOOo % O0
     if 21 - 21: Ii1I % oO0o / OOooOOo - I11i
     if 5 - 5: oO0o / iIii1I11I1II1 % Ii1I
     if 2 - 2: iII111i + I11i * I1ii11iIi11i - IiII
     if 97 - 97: iIii1I11I1II1 . II111iiii - II111iiii + I1ii11iIi11i
    iIIiiIii11I1i = IIIi1iI1 . print_rloc_probe_rtt ( )
    ii1i111i1II = O0O0
    if ( IIIi1iI1 . translated_port != 0 ) :
     ii1i111i1II += ":{}" . format ( IIIi1iI1 . translated_port )
     if 59 - 59: IiII
    ii1i111i1II = red ( ii1i111i1II , False )
    if ( IIIi1iI1 . rloc_name != None ) :
     ii1i111i1II += " (" + blue ( IIIi1iI1 . rloc_name , False ) + ")"
     if 4 - 4: OoO0O00 . iIii1I11I1II1
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( iiIii11Ii , oOO00OOo0 ,
 ii1i111i1II , iIIiiIii11I1i , I1III1iIIIi1i ) )
    if 50 - 50: I1ii11iIi11i - IiII + OoO0O00 . OoO0O00 + II111iiii - oO0o
    if 90 - 90: Oo0Ooo % Oo0Ooo + oO0o - OoooooooOO + OOooOOo % I11i
    if 61 - 61: I1IiiI % oO0o + OOooOOo - I1Ii111
    if 5 - 5: ooOoO0o . OoO0O00
    if 40 - 40: iII111i
    if 87 - 87: IiII / II111iiii
    if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
    if 84 - 84: OOooOOo . OOooOOo . oO0o % iII111i * Oo0Ooo - iIii1I11I1II1
    if ( IIIi1iI1 . rloc_next_hop != None ) :
     o0o0O0o0000 = lisp_get_host_route_next_hop ( O0O0 )
     if ( o0o0O0o0000 ) : lisp_install_host_route ( O0O0 , o0o0O0o0000 , False )
     if 4 - 4: iII111i
     if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
     if 65 - 65: Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
     if 17 - 17: I1ii11iIi11i * OOooOOo % II111iiii
     if 30 - 30: I1Ii111 . Ii1I . Oo0Ooo / OOooOOo * OoooooooOO / I1ii11iIi11i
     if 41 - 41: i1IIi
    if ( IIIi1iI1 . rloc . is_null ( ) ) :
     IIIi1iI1 . rloc . copy_address ( i1Ii1IiII1i . rloc )
     if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
     if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
     if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
     if 100 - 100: OoO0O00 . Oo0Ooo
     if 29 - 29: OoO0O00
    I1IiiII1I1 = None if ( iiI . is_null ( ) ) else oo0oO
    Ii1Ii11I = oo0oO if ( iiI . is_null ( ) ) else iiI
    lisp_send_map_request ( lisp_sockets , 0 , I1IiiII1I1 , Ii1Ii11I , IIIi1iI1 )
    oooOO0 = i1Ii1IiII1i
    if 88 - 88: I11i * iIii1I11I1II1 . iIii1I11I1II1 . o0oOOo0O0Ooo
    if 89 - 89: Ii1I % i1IIi
    if 47 - 47: II111iiii * I1ii11iIi11i
    if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
    if ( IiI1iI ) : lisp_install_host_route ( O0O0 , IiI1iI , False )
    if 71 - 71: I1ii11iIi11i * i1IIi
    if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
    if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
    if 57 - 57: OOooOOo . I11i % OoOoOO00
    if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
   if ( o0o0O0o0000 ) : lisp_install_host_route ( O0O0 , o0o0O0o0000 , True )
   if 78 - 78: iII111i - OOooOOo / I1Ii111
   if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
   if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
   if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
   O0oo0oOo += 1
   if ( ( O0oo0oOo % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 56 - 56: I11i % OoOoOO00 - OoO0O00
   if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
   if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
 if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
 if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
 if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
 if 66 - 66: OoO0O00 * Ii1I . OoO0O00
 if 90 - 90: II111iiii % Ii1I
 if 67 - 67: I1IiiI - I11i - i11iIiiIii
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
 if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if ( lisp_i_am_itr == False ) : return
 if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
 if 57 - 57: I1Ii111 - IiII
 if 89 - 89: oO0o + iII111i
 if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
 if ( lisp_register_all_rtrs ) : return
 if 7 - 7: II111iiii
 Iii11iIiIi11 = rtr . print_address_no_iid ( )
 if 38 - 38: I11i / iII111i - iIii1I11I1II1 + ooOoO0o + o0oOOo0O0Ooo . I1IiiI
 if 96 - 96: IiII - I1IiiI . I1ii11iIi11i . O0
 if 82 - 82: Ii1I % o0oOOo0O0Ooo . Oo0Ooo * OoO0O00 - Oo0Ooo
 if 49 - 49: i11iIiiIii - I1IiiI * IiII
 if 92 - 92: Oo0Ooo % O0 * Oo0Ooo
 if ( Iii11iIiIi11 not in lisp_rtr_list ) : return
 if 29 - 29: I1IiiI * iIii1I11I1II1 % ooOoO0o * OoO0O00 % Ii1I * I1ii11iIi11i
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( Iii11iIiIi11 , False ) , bold ( updown , False ) ) )
 if 90 - 90: Ii1I + O0 % OoOoOO00
 if 18 - 18: iII111i . iIii1I11I1II1 . I1ii11iIi11i / OoO0O00 % OOooOOo
 if 30 - 30: OoOoOO00 * i1IIi / i1IIi . IiII
 if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
 OO = "rtr%{}%{}" . format ( Iii11iIiIi11 , updown )
 OO = lisp_command_ipc ( OO , "lisp-itr" )
 lisp_ipc ( OO , lisp_ipc_socket , "lisp-etr" )
 return
 if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
 if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
 if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
 if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
 if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
 if 42 - 42: i1IIi . OoO0O00 % iII111i
 if 57 - 57: I1ii11iIi11i / I1IiiI
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl ,
 mrloc ) :
 IIIi1iI1 = rloc_entry . rloc
 o0Oo0o = map_reply . nonce
 O0o0oOOOO = map_reply . hop_count
 iiIii11Ii = bold ( "RLOC-probe reply" , False )
 I1i1II1iiIiIi = IIIi1iI1 . print_address_no_iid ( )
 Oo0OOo0oo = source . print_address_no_iid ( )
 ooO0o = lisp_rloc_probe_list
 ooo0 = rloc_entry . json . json_string if rloc_entry . json else None
 i1 = lisp_get_timestamp ( )
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 if 39 - 39: OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
 if 41 - 41: II111iiii . o0oOOo0O0Ooo
 if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
 if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
 if ( mrloc != None ) :
  iIIiIIi = mrloc . rloc . print_address_no_iid ( )
  if ( I1i1II1iiIiIi not in mrloc . multicast_rloc_probe_list ) :
   oOOoooO0 = lisp_rloc ( )
   oOOoooO0 = copy . deepcopy ( mrloc )
   oOOoooO0 . rloc . copy_address ( IIIi1iI1 )
   oOOoooO0 . multicast_rloc_probe_list = { }
   mrloc . multicast_rloc_probe_list [ I1i1II1iiIiIi ] = oOOoooO0
   if 53 - 53: II111iiii / iIii1I11I1II1
  oOOoooO0 = mrloc . multicast_rloc_probe_list [ I1i1II1iiIiIi ]
  oOOoooO0 . last_rloc_probe_nonce = mrloc . last_rloc_probe_nonce
  oOOoooO0 . last_rloc_probe = mrloc . last_rloc_probe
  iiiI1I , oo0oO , iiI = lisp_rloc_probe_list [ iIIiIIi ] [ 0 ]
  oOOoooO0 . process_rloc_probe_reply ( i1 , o0Oo0o , oo0oO , iiI , O0o0oOOOO , ttl , ooo0 )
  mrloc . process_rloc_probe_reply ( i1 , o0Oo0o , oo0oO , iiI , O0o0oOOOO , ttl , ooo0 )
  return
  if 25 - 25: I1Ii111
  if 58 - 58: OoOoOO00 * i1IIi
  if 20 - 20: IiII
  if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
  if 30 - 30: i11iIiiIii . I1IiiI
  if 5 - 5: Ii1I / O0 + iIii1I11I1II1
  if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 IiI = I1i1II1iiIiIi
 if ( IiI not in ooO0o ) :
  IiI += ":" + str ( port )
  if ( IiI not in ooO0o ) :
   IiI = Oo0OOo0oo
   if ( IiI not in ooO0o ) :
    IiI += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( iiIii11Ii , red ( I1i1II1iiIiIi , False ) , red ( Oo0OOo0oo ,
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
 for IIIi1iI1 , oo0oO , iiI in lisp_rloc_probe_list [ IiI ] :
  if ( lisp_i_am_rtr ) :
   if ( IIIi1iI1 . translated_port != 0 and IIIi1iI1 . translated_port != port ) :
    continue
    if 13 - 13: OOooOOo / OoooooooOO
    if 7 - 7: II111iiii - ooOoO0o
  IIIi1iI1 . process_rloc_probe_reply ( i1 , o0Oo0o , oo0oO , iiI , O0o0oOOOO , ttl , ooo0 )
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
 O0oo0oOo = 0
 for oooOOoO0oo0 in lisp_db_list :
  O0oo0oOo += len ( oooOOoO0oo0 . dynamic_eids ) if oooOOoO0oo0 . dynamic_eid_configured ( ) else 1
  O0oo0oOo += len ( oooOOoO0oo0 . eid . iid_list )
  if 70 - 70: iIii1I11I1II1
 return ( O0oo0oOo )
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
 I111Ii1I1I1iI = None
 if ( rloc_str in lisp_nonce_echo_list ) :
  I111Ii1I1I1iI = lisp_nonce_echo_list [ rloc_str ]
  if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
 return ( I111Ii1I1I1iI )
 if 21 - 21: O0
 if 14 - 14: IiII / I1ii11iIi11i + Ii1I
 if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
 if 38 - 38: I1IiiI * Ii1I + Oo0Ooo - OoooooooOO
 if 63 - 63: I1ii11iIi11i
 if 99 - 99: I1Ii111 % oO0o - II111iiii . ooOoO0o
 if 26 - 26: I1ii11iIi11i * iII111i . OoooooooOO - Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
def lisp_decode_dist_name ( packet ) :
 O0oo0oOo = 0
 iiiIi = b""
 if 89 - 89: I11i + II111iiii
 while ( packet [ 0 : 1 ] != b"\x00" ) :
  if ( O0oo0oOo == 255 ) : return ( [ None , None ] )
  iiiIi += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  O0oo0oOo += 1
  if 72 - 72: iII111i - Oo0Ooo / O0 + I1IiiI * Ii1I
  if 23 - 23: II111iiii % I11i * I11i + O0 . iII111i
 packet = packet [ 1 : : ]
 return ( packet , iiiIi . decode ( ) )
 if 100 - 100: o0oOOo0O0Ooo
 if 65 - 65: iIii1I11I1II1
 if 11 - 11: O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
def lisp_write_flow_log ( flow_log ) :
 I1Ii = open ( "./logs/lisp-flow.log" , "a" )
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 O0oo0oOo = 0
 for oo000o in flow_log :
  Oo00oo = oo000o [ 3 ]
  oooOOOo00OoO0 = Oo00oo . print_flow ( oo000o [ 0 ] , oo000o [ 1 ] , oo000o [ 2 ] )
  I1Ii . write ( oooOOOo00OoO0 )
  O0oo0oOo += 1
  if 74 - 74: Oo0Ooo - oO0o + OoooooooOO
 I1Ii . close ( )
 del ( flow_log )
 if 44 - 44: o0oOOo0O0Ooo % ooOoO0o . oO0o - Oo0Ooo % OOooOOo
 O0oo0oOo = bold ( str ( O0oo0oOo ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( O0oo0oOo ) )
 return
 if 15 - 15: o0oOOo0O0Ooo - Oo0Ooo / IiII
 if 94 - 94: Ii1I + o0oOOo0O0Ooo / II111iiii
 if 18 - 18: I1IiiI
 if 27 - 27: ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
 if 93 - 93: OoooooooOO / I1Ii111
def lisp_policy_command ( kv_pair ) :
 iIIiiIi = lisp_policy ( "" )
 ooo000OOo0Ooo = None
 if 15 - 15: OoO0O00 * i1IIi % OoO0O00 - oO0o / iIii1I11I1II1 - o0oOOo0O0Ooo
 o0o0ooo0oOOOO = [ ]
 for iIi1iIIIiIiI in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  o0o0ooo0oOOOO . append ( lisp_policy_match ( ) )
  if 57 - 57: O0 - I1Ii111 . IiII
  if 56 - 56: OoooooooOO
 for i1iiiI1iI1iiI in list ( kv_pair . keys ( ) ) :
  oOO0 = kv_pair [ i1iiiI1iI1iiI ]
  if 81 - 81: Ii1I - OoooooooOO - i11iIiiIii . OoOoOO00
  if 14 - 14: iII111i . I1Ii111 - O0 - i11iIiiIii + o0oOOo0O0Ooo
  if 20 - 20: O0 % OoooooooOO + iII111i - ooOoO0o
  if 10 - 10: iII111i . iIii1I11I1II1 % ooOoO0o / oO0o
  if ( i1iiiI1iI1iiI == "instance-id" ) :
   for iIi1iIIIiIiI in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = oOO0 [ iIi1iIIIiIiI ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ iIi1iIIIiIiI ]
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
   for iIi1iIIIiIiI in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = oOO0 [ iIi1iIIIiIiI ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ iIi1iIIIiIiI ]
    if ( oOOoOo0O0 . source_eid == None ) :
     oOOoOo0O0 . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 96 - 96: ooOoO0o * iII111i . IiII
    oooo = oOOoOo0O0 . source_eid . instance_id
    oOOoOo0O0 . source_eid . store_prefix ( i1i11i )
    oOOoOo0O0 . source_eid . instance_id = oooo
    if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
    if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
  if ( i1iiiI1iI1iiI == "destination-eid" ) :
   for iIi1iIIIiIiI in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = oOO0 [ iIi1iIIIiIiI ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ iIi1iIIIiIiI ]
    if ( oOOoOo0O0 . dest_eid == None ) :
     oOOoOo0O0 . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
    oooo = oOOoOo0O0 . dest_eid . instance_id
    oOOoOo0O0 . dest_eid . store_prefix ( i1i11i )
    oOOoOo0O0 . dest_eid . instance_id = oooo
    if 22 - 22: i1IIi
    if 33 - 33: O0
  if ( i1iiiI1iI1iiI == "source-rloc" ) :
   for iIi1iIIIiIiI in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = oOO0 [ iIi1iIIIiIiI ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ iIi1iIIIiIiI ]
    oOOoOo0O0 . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    oOOoOo0O0 . source_rloc . store_prefix ( i1i11i )
    if 34 - 34: I1Ii111 . IiII % iII111i
    if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
  if ( i1iiiI1iI1iiI == "destination-rloc" ) :
   for iIi1iIIIiIiI in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = oOO0 [ iIi1iIIIiIiI ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ iIi1iIIIiIiI ]
    oOOoOo0O0 . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    oOOoOo0O0 . dest_rloc . store_prefix ( i1i11i )
    if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
    if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
  if ( i1iiiI1iI1iiI == "rloc-record-name" ) :
   for iIi1iIIIiIiI in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = oOO0 [ iIi1iIIIiIiI ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ iIi1iIIIiIiI ]
    oOOoOo0O0 . rloc_record_name = i1i11i
    if 75 - 75: i1IIi * i11iIiiIii
    if 40 - 40: I1ii11iIi11i + OoO0O00
  if ( i1iiiI1iI1iiI == "geo-name" ) :
   for iIi1iIIIiIiI in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = oOO0 [ iIi1iIIIiIiI ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ iIi1iIIIiIiI ]
    oOOoOo0O0 . geo_name = i1i11i
    if 8 - 8: i11iIiiIii - iIii1I11I1II1
    if 73 - 73: OoOoOO00
  if ( i1iiiI1iI1iiI == "elp-name" ) :
   for iIi1iIIIiIiI in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = oOO0 [ iIi1iIIIiIiI ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ iIi1iIIIiIiI ]
    oOOoOo0O0 . elp_name = i1i11i
    if 25 - 25: iII111i / oO0o
    if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
  if ( i1iiiI1iI1iiI == "rle-name" ) :
   for iIi1iIIIiIiI in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = oOO0 [ iIi1iIIIiIiI ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ iIi1iIIIiIiI ]
    oOOoOo0O0 . rle_name = i1i11i
    if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
    if 61 - 61: I1IiiI / OOooOOo
  if ( i1iiiI1iI1iiI == "json-name" ) :
   for iIi1iIIIiIiI in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = oOO0 [ iIi1iIIIiIiI ]
    if ( i1i11i == "" ) : continue
    oOOoOo0O0 = o0o0ooo0oOOOO [ iIi1iIIIiIiI ]
    oOOoOo0O0 . json_name = i1i11i
    if 67 - 67: OoOoOO00
    if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
  if ( i1iiiI1iI1iiI == "datetime-range" ) :
   for iIi1iIIIiIiI in range ( len ( o0o0ooo0oOOOO ) ) :
    i1i11i = oOO0 [ iIi1iIIIiIiI ]
    oOOoOo0O0 = o0o0ooo0oOOOO [ iIi1iIIIiIiI ]
    if ( i1i11i == "" ) : continue
    oOO0O00o0O0 = lisp_datetime ( i1i11i [ 0 : 19 ] )
    OO0O0OOooo = lisp_datetime ( i1i11i [ 19 : : ] )
    if ( oOO0O00o0O0 . valid_datetime ( ) and OO0O0OOooo . valid_datetime ( ) ) :
     oOOoOo0O0 . datetime_lower = oOO0O00o0O0
     oOOoOo0O0 . datetime_upper = OO0O0OOooo
     if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
     if 95 - 95: ooOoO0o % OOooOOo
     if 17 - 17: i1IIi + Ii1I
     if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
     if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
     if 26 - 26: oO0o / I1ii11iIi11i - oO0o
     if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
  if ( i1iiiI1iI1iiI == "set-action" ) :
   iIIiiIi . set_action = oOO0
   if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
  if ( i1iiiI1iI1iiI == "set-record-ttl" ) :
   iIIiiIi . set_record_ttl = int ( oOO0 )
   if 96 - 96: Ii1I
  if ( i1iiiI1iI1iiI == "set-instance-id" ) :
   if ( iIIiiIi . set_source_eid == None ) :
    iIIiiIi . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 90 - 90: II111iiii
   if ( iIIiiIi . set_dest_eid == None ) :
    iIIiiIi . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
   ooo000OOo0Ooo = int ( oOO0 )
   iIIiiIi . set_source_eid . instance_id = ooo000OOo0Ooo
   iIIiiIi . set_dest_eid . instance_id = ooo000OOo0Ooo
   if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
  if ( i1iiiI1iI1iiI == "set-source-eid" ) :
   if ( iIIiiIi . set_source_eid == None ) :
    iIIiiIi . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 52 - 52: i11iIiiIii * ooOoO0o
   iIIiiIi . set_source_eid . store_prefix ( oOO0 )
   if ( ooo000OOo0Ooo != None ) : iIIiiIi . set_source_eid . instance_id = ooo000OOo0Ooo
   if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
  if ( i1iiiI1iI1iiI == "set-destination-eid" ) :
   if ( iIIiiIi . set_dest_eid == None ) :
    iIIiiIi . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 91 - 91: ooOoO0o
   iIIiiIi . set_dest_eid . store_prefix ( oOO0 )
   if ( ooo000OOo0Ooo != None ) : iIIiiIi . set_dest_eid . instance_id = ooo000OOo0Ooo
   if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
  if ( i1iiiI1iI1iiI == "set-rloc-address" ) :
   iIIiiIi . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   iIIiiIi . set_rloc_address . store_address ( oOO0 )
   if 9 - 9: O0 + IiII
  if ( i1iiiI1iI1iiI == "set-rloc-record-name" ) :
   iIIiiIi . set_rloc_record_name = oOO0
   if 69 - 69: I1IiiI
  if ( i1iiiI1iI1iiI == "set-elp-name" ) :
   iIIiiIi . set_elp_name = oOO0
   if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
  if ( i1iiiI1iI1iiI == "set-geo-name" ) :
   iIIiiIi . set_geo_name = oOO0
   if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
  if ( i1iiiI1iI1iiI == "set-rle-name" ) :
   iIIiiIi . set_rle_name = oOO0
   if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
  if ( i1iiiI1iI1iiI == "set-json-name" ) :
   iIIiiIi . set_json_name = oOO0
   if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
  if ( i1iiiI1iI1iiI == "policy-name" ) :
   iIIiiIi . policy_name = oOO0
   if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
   if 19 - 19: I1ii11iIi11i
   if 42 - 42: OoOoOO00 / IiII
   if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
   if 99 - 99: I11i % ooOoO0o . I1Ii111
   if 34 - 34: ooOoO0o + oO0o + II111iiii . I1Ii111 . i1IIi
 iIIiiIi . match_clauses = o0o0ooo0oOOOO
 iIIiiIi . save_policy ( )
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
 oO00o00 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 oOo0OOoooO = getoutput ( "FastCli -c '{}'" . format ( oO00o00 ) )
 if 50 - 50: OoOoOO00 % I1IiiI + I1Ii111 . iII111i . iII111i
 if 89 - 89: oO0o / I1ii11iIi11i % I1Ii111
 if 86 - 86: Ii1I * II111iiii % ooOoO0o
 if 82 - 82: OOooOOo . Oo0Ooo * ooOoO0o % II111iiii % II111iiii - oO0o
 oOo0OOoooO = oOo0OOoooO . split ( "\n" ) [ 1 ]
 OoooOOOOO0 = oOo0OOoooO . split ( " " )
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
 II1i1i = mc . eid . print_prefix_no_iid ( )
 IIIi1iI1 = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 75 - 75: IiII / O0
 if 72 - 72: I11i
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 iII = getoutput ( "ip route get {} | egrep vlan4094" . format ( II1i1i ) )
 if 63 - 63: OoOoOO00 / Oo0Ooo * OOooOOo - i11iIiiIii + OoO0O00
 if ( iII != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( II1i1i , False ) , iII ) )
  if 98 - 98: i11iIiiIii . OoooooooOO
  return
  if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
  if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
  if 88 - 88: I1Ii111
  if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
  if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
  if 83 - 83: oO0o
  if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
 OoO00oo = getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( OoO00oo . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 38 - 38: I11i - i11iIiiIii
 if ( OoO00oo . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 38 - 38: I1IiiI * i1IIi / OoO0O00 + iIii1I11I1II1 / I1Ii111 % II111iiii
 oOOo0O000ooO = getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( oOOo0O000ooO == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 59 - 59: ooOoO0o / I11i
 oOOo0O000ooO = oOOo0O000ooO . split ( "inet " ) [ 1 ]
 oOOo0O000ooO = oOOo0O000ooO . split ( "/" ) [ 0 ]
 if 32 - 32: iIii1I11I1II1 % oO0o / I1Ii111
 if 42 - 42: I11i / I1ii11iIi11i - I1IiiI * iII111i / I1IiiI / i11iIiiIii
 if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
 if 95 - 95: OoOoOO00
 if 78 - 78: I11i
 if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
 if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
 O00O00OOo0oo0 = [ ]
 Ooo00oO = getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for IiiiI1 in Ooo00oO :
  if ( IiiiI1 . find ( "vlan4094" ) == - 1 ) : continue
  if ( IiiiI1 . find ( "(incomplete)" ) == - 1 ) : continue
  o0o0O0o0000 = IiiiI1 . split ( " " ) [ 0 ]
  O00O00OOo0oo0 . append ( o0o0O0o0000 )
  if 59 - 59: iII111i * O0
  if 88 - 88: ooOoO0o / OoOoOO00 % IiII - iIii1I11I1II1 / I11i
 o0o0O0o0000 = None
 Ii1IiI = oOOo0O000ooO
 oOOo0O000ooO = oOOo0O000ooO . split ( "." )
 for iIi1iIIIiIiI in range ( 1 , 255 ) :
  oOOo0O000ooO [ 3 ] = str ( iIi1iIIIiIiI )
  IiI = "." . join ( oOOo0O000ooO )
  if ( IiI in O00O00OOo0oo0 ) : continue
  if ( IiI == Ii1IiI ) : continue
  o0o0O0o0000 = IiI
  break
  if 15 - 15: O0 . II111iiii
 if ( o0o0O0o0000 == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 14 - 14: oO0o . I11i . i1IIi + I1ii11iIi11i
  return
  if 53 - 53: Ii1I
  if 35 - 35: oO0o * i1IIi / IiII / iII111i
  if 19 - 19: I1IiiI + iIii1I11I1II1 * O0 - OOooOOo
  if 32 - 32: O0 - II111iiii - i1IIi + O0 + OOooOOo
  if 44 - 44: I11i * oO0o % OoooooooOO % OoO0O00 / o0oOOo0O0Ooo
  if 37 - 37: OoO0O00 + OoOoOO00 - I1IiiI
  if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
 Oo0ooo0O0 = IIIi1iI1 . split ( "." )
 IIiiIiii = lisp_hex_string ( Oo0ooo0O0 [ 1 ] ) . zfill ( 2 )
 oO00o = lisp_hex_string ( Oo0ooo0O0 [ 2 ] ) . zfill ( 2 )
 iI1i1iI1i = lisp_hex_string ( Oo0ooo0O0 [ 3 ] ) . zfill ( 2 )
 iiiI1IiIIii = "00:00:00:{}:{}:{}" . format ( IIiiIiii , oO00o , iI1i1iI1i )
 I1IiI1iIIII1 = "0000.00{}.{}{}" . format ( IIiiIiii , oO00o , iI1i1iI1i )
 iI1II1i = "arp -i vlan4094 -s {} {}" . format ( o0o0O0o0000 , iiiI1IiIIii )
 os . system ( iI1II1i )
 if 64 - 64: OoOoOO00 % I11i / I1IiiI . o0oOOo0O0Ooo + IiII + O0
 if 32 - 32: Oo0Ooo % O0 * I1Ii111 . I11i - OoO0O00
 if 22 - 22: I1IiiI * I1IiiI / iIii1I11I1II1 . o0oOOo0O0Ooo - I1ii11iIi11i
 if 53 - 53: iIii1I11I1II1 * II111iiii
 o0o00 = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( I1IiI1iIIII1 , IIIi1iI1 )
 if 13 - 13: i1IIi * I1IiiI . I1Ii111 % OoOoOO00 % iII111i . II111iiii
 lisp_send_to_arista ( o0o00 , None )
 if 55 - 55: II111iiii / I1IiiI . iII111i / oO0o * O0 - I1IiiI
 if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
 if 31 - 31: I11i * o0oOOo0O0Ooo
 if 17 - 17: Ii1I * iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo - IiII
 ooOOOOo0oOOOO0 = "ip route add {} via {}" . format ( II1i1i , o0o0O0o0000 )
 os . system ( ooOOOOo0oOOOO0 )
 if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 lprint ( "Hardware programmed with commands:" )
 ooOOOOo0oOOOO0 = ooOOOOo0oOOOO0 . replace ( II1i1i , green ( II1i1i , False ) )
 lprint ( "  " + ooOOOOo0oOOOO0 )
 lprint ( "  " + iI1II1i )
 o0o00 = o0o00 . replace ( IIIi1iI1 , red ( IIIi1iI1 , False ) )
 lprint ( "  " + o0o00 )
 return
 if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
 if 23 - 23: Ii1I % i1IIi - I1Ii111
 if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
 if 11 - 11: IiII / I1IiiI . I1IiiI
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
def lisp_clear_hardware_walk ( mc , parms ) :
 o00oO0ooO000 = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( o00oO0ooO000 ) )
 return ( [ True , None ] )
 if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
 if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
 if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
 if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
 if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
 if 3 - 3: I1Ii111
 if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
 if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
 ooO0I11i11i = bold ( "User cleared" , False )
 O0oo0oOo = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( ooO0I11i11i , O0oo0oOo ) )
 if 22 - 22: I1Ii111 - I1ii11iIi11i . Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 lisp_map_cache = lisp_cache ( )
 if 46 - 46: oO0o + OoOoOO00
 if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 if 59 - 59: O0
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 lisp_rloc_probe_list = { }
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 if 72 - 72: IiII / II111iiii
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 21 - 21: I1ii11iIi11i
 if 60 - 60: i1IIi / OoO0O00 . Ii1I
 if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
 if 26 - 26: iII111i
 if 31 - 31: iII111i
 lisp_rtr_list = { }
 if 45 - 45: OoO0O00
 if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 + I11i - ooOoO0o + I1IiiI * O0
 if 47 - 47: ooOoO0o + iIii1I11I1II1 * OOooOOo . I1IiiI . o0oOOo0O0Ooo
 if 49 - 49: Oo0Ooo . OoOoOO00 * OOooOOo
 lisp_gleaned_groups = { }
 if 86 - 86: IiII * OOooOOo + Ii1I
 if 62 - 62: I11i
 if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
 if 15 - 15: I1IiiI / I1Ii111 % iII111i
 lisp_process_data_plane_restart ( True )
 return
 if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
 if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
 if 43 - 43: oO0o . OoO0O00 * i1IIi
 if 1 - 1: ooOoO0o / i1IIi
 if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
 if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
 if 75 - 75: I11i * IiII * ooOoO0o
 if 31 - 31: Ii1I
 if 72 - 72: OOooOOo * Ii1I % OoO0O00
 if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
 if 42 - 42: oO0o / i1IIi . IiII
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 12 - 12: i11iIiiIii . ooOoO0o
 Oo0o0 = lisp_myrlocs [ 0 ]
 if 85 - 85: i11iIiiIii * i11iIiiIii
 if 47 - 47: OoooooooOO / I1IiiI . OoO0O00 . I1Ii111 - i11iIiiIii - oO0o
 if 7 - 7: i1IIi
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 i1iIii = len ( packet ) + 28
 O0O = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( i1iIii ) , 0 , 64 ,
 17 , 0 , socket . htonl ( Oo0o0 . address ) , socket . htonl ( rloc . address ) )
 O0O = lisp_ip_checksum ( O0O )
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 O0I1II1 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( i1iIii - 20 ) , 0 )
 if 29 - 29: II111iiii % i11iIiiIii % O0
 if 38 - 38: o0oOOo0O0Ooo * IiII
 if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
 packet = lisp_packet ( O0O + O0I1II1 + packet )
 if 19 - 19: OoooooooOO
 if 34 - 34: OoOoOO00 . oO0o
 if 53 - 53: oO0o + OoooooooOO * ooOoO0o
 if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( Oo0o0 )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( Oo0o0 )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 IIIOo0O = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  III11iI1 = " {}" . format ( blue ( nat_info . hostname , False ) )
  iiIii11Ii = bold ( "RLOC-probe request" , False )
 else :
  III11iI1 = ""
  iiIii11Ii = bold ( "RLOC-probe reply" , False )
  if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
  if 80 - 80: II111iiii . i11iIiiIii
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( iiIii11Ii , IIIOo0O , III11iI1 , packet . encap_port ) )
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 52 - 52: iIii1I11I1II1 + O0
 if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 29 - 29: iII111i % I1Ii111
 O000oo0o = lisp_sockets [ 3 ]
 packet . send_packet ( O000oo0o , packet . outer_dest )
 del ( packet )
 return
 if 6 - 6: oO0o * ooOoO0o . I1Ii111 / OOooOOo . OoOoOO00
 if 4 - 4: Ii1I / II111iiii + o0oOOo0O0Ooo / IiII
 if 9 - 9: ooOoO0o + i1IIi / ooOoO0o / I11i * I1ii11iIi11i / OoooooooOO
 if 28 - 28: o0oOOo0O0Ooo
 if 97 - 97: I1Ii111 - I1Ii111 * OoO0O00 % II111iiii * IiII
 if 2 - 2: I1Ii111 % iII111i . OoooooooOO - o0oOOo0O0Ooo
 if 30 - 30: i1IIi / I1Ii111 * oO0o - oO0o / oO0o
 if 9 - 9: IiII / o0oOOo0O0Ooo . IiII * O0 % i11iIiiIii % OoOoOO00
def lisp_get_default_route_next_hops ( ) :
 if 29 - 29: I1ii11iIi11i % ooOoO0o . OOooOOo . Ii1I . IiII
 if 69 - 69: o0oOOo0O0Ooo . i11iIiiIii * I11i + IiII / I11i
 if 66 - 66: I1ii11iIi11i % I1Ii111 - i11iIiiIii % I11i
 if 62 - 62: i11iIiiIii % iIii1I11I1II1 / IiII . I1IiiI * O0
 if ( lisp_is_macos ( ) ) :
  oO00o00 = "route -n get default"
  II11Ii1II = getoutput ( oO00o00 ) . split ( "\n" )
  I1iiI11ii = i111IIiIiiI1 = None
  for I1Ii in II11Ii1II :
   if ( I1Ii . find ( "gateway: " ) != - 1 ) : I1iiI11ii = I1Ii . split ( ": " ) [ 1 ]
   if ( I1Ii . find ( "interface: " ) != - 1 ) : i111IIiIiiI1 = I1Ii . split ( ": " ) [ 1 ]
   if 56 - 56: I11i % I1ii11iIi11i / i11iIiiIii
  return ( [ [ i111IIiIiiI1 , I1iiI11ii ] ] )
  if 4 - 4: Oo0Ooo / I1IiiI * i1IIi . II111iiii
  if 13 - 13: i1IIi
  if 39 - 39: OOooOOo
  if 73 - 73: OoO0O00 . ooOoO0o
  if 13 - 13: o0oOOo0O0Ooo - OoOoOO00
 oO00o00 = "ip route | egrep 'default via'"
 i1I1II = getoutput ( oO00o00 ) . split ( "\n" )
 if 60 - 60: OoO0O00
 O00oO0Ooo00O = [ ]
 for iII in i1I1II :
  if ( iII . find ( " metric " ) != - 1 ) : continue
  iiiI1I = iII . split ( " " )
  try :
   Ii1i1iI1I1I = iiiI1I . index ( "via" ) + 1
   if ( Ii1i1iI1I1I >= len ( iiiI1I ) ) : continue
   I1II = iiiI1I . index ( "dev" ) + 1
   if ( I1II >= len ( iiiI1I ) ) : continue
  except :
   continue
   if 44 - 44: iIii1I11I1II1 - OoOoOO00 / iII111i * OoooooooOO . Ii1I / i11iIiiIii
   if 85 - 85: OoO0O00
  O00oO0Ooo00O . append ( [ iiiI1I [ I1II ] , iiiI1I [ Ii1i1iI1I1I ] ] )
  if 29 - 29: IiII
 return ( O00oO0Ooo00O )
 if 57 - 57: OoooooooOO + IiII + II111iiii
 if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
 if 49 - 49: II111iiii * I1IiiI / oO0o
 if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
 if 15 - 15: Oo0Ooo
 if 53 - 53: OoooooooOO * O0 / iII111i * ooOoO0o % I1Ii111 + OOooOOo
 if 95 - 95: I1Ii111 % OoOoOO00 . IiII * iII111i % Ii1I
def lisp_get_host_route_next_hop ( rloc ) :
 oO00o00 = "ip route | egrep '{} via'" . format ( rloc )
 iII = getoutput ( oO00o00 ) . split ( " " )
 if 18 - 18: iIii1I11I1II1 / ooOoO0o / I1Ii111 % oO0o * Ii1I
 try : OOOooo0OooOoO = iII . index ( "via" ) + 1
 except : return ( None )
 if 14 - 14: oO0o
 if ( OOOooo0OooOoO >= len ( iII ) ) : return ( None )
 return ( iII [ OOOooo0OooOoO ] )
 if 72 - 72: iIii1I11I1II1 / II111iiii * II111iiii + I1IiiI + iIii1I11I1II1 + oO0o
 if 46 - 46: I1Ii111
 if 23 - 23: Oo0Ooo * IiII - I1Ii111 . OoooooooOO
 if 78 - 78: OoOoOO00 - iIii1I11I1II1
 if 20 - 20: i1IIi
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 I1III1iIIIi1i = "none" if nh == None else nh
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , I1III1iIIIi1i ) )
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if ( nh == None ) :
  I11IiI1i11i1 = "ip route {} {}/32" . format ( install , dest )
 else :
  I11IiI1i11i1 = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 os . system ( I11IiI1i11i1 )
 return
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
 if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
 if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
 if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 if 38 - 38: Ii1I
 if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 I1Ii = open ( lisp_checkpoint_filename , "w" )
 for oo0O00OOOOO in checkpoint_list :
  I1Ii . write ( oo0O00OOOOO + "\n" )
  if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
 I1Ii . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
 if 59 - 59: i11iIiiIii / I1IiiI * iII111i
 if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
 if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
 if 89 - 89: O0 * ooOoO0o
 if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
 if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
 if 82 - 82: iII111i * iII111i . IiII * II111iiii
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 17 - 17: OoooooooOO % I1Ii111 * I1Ii111 / II111iiii . OoOoOO00 * iII111i
 I1Ii = open ( lisp_checkpoint_filename , "r" )
 if 80 - 80: IiII % i11iIiiIii
 O0oo0oOo = 0
 for oo0O00OOOOO in I1Ii :
  O0oo0oOo += 1
  oO0ooOOO = oo0O00OOOOO . split ( " rloc " )
  OOOO00 = [ ] if ( oO0ooOOO [ 1 ] in [ "native-forward\n" , "\n" ] ) else oO0ooOOO [ 1 ] . split ( ", " )
  if 6 - 6: II111iiii + i11iIiiIii - Oo0Ooo % OOooOOo + Oo0Ooo
  if 46 - 46: iII111i
  oOO000OOO = [ ]
  for IIIi1iI1 in OOOO00 :
   iiIiIIi1I = lisp_rloc ( False )
   iiiI1I = IIIi1iI1 . split ( " " )
   iiIiIIi1I . rloc . store_address ( iiiI1I [ 0 ] )
   iiIiIIi1I . priority = int ( iiiI1I [ 1 ] )
   iiIiIIi1I . weight = int ( iiiI1I [ 2 ] )
   oOO000OOO . append ( iiIiIIi1I )
   if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
   if 11 - 11: ooOoO0o - OoOoOO00
  iIIiiiiI11i = lisp_mapping ( "" , "" , oOO000OOO )
  if ( iIIiiiiI11i != None ) :
   iIIiiiiI11i . eid . store_prefix ( oO0ooOOO [ 0 ] )
   iIIiiiiI11i . checkpoint_entry = True
   iIIiiiiI11i . map_cache_ttl = LISP_NMR_TTL * 60
   if ( oOO000OOO == [ ] ) : iIIiiiiI11i . action = LISP_NATIVE_FORWARD_ACTION
   iIIiiiiI11i . add_cache ( )
   continue
   if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
   if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
  O0oo0oOo -= 1
  if 4 - 4: OoO0O00 - OOooOOo
  if 21 - 21: I1Ii111 * i11iIiiIii
 I1Ii . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , O0oo0oOo , lisp_checkpoint_filename ) )
 return
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
 if 57 - 57: IiII - i1IIi * ooOoO0o
 if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
 if 75 - 75: OOooOOo * OoOoOO00
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 82 - 82: Ii1I
 oo0O00OOOOO = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 83 - 83: I1IiiI
 for iiIiIIi1I in mc . rloc_set :
  if ( iiIiIIi1I . rloc . is_null ( ) ) : continue
  oo0O00OOOOO += "{} {} {}, " . format ( iiIiIIi1I . rloc . print_address_no_iid ( ) ,
 iiIiIIi1I . priority , iiIiIIi1I . weight )
  if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
  if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
 if ( mc . rloc_set != [ ] ) :
  oo0O00OOOOO = oo0O00OOOOO [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  oo0O00OOOOO += "native-forward"
  if 45 - 45: I11i - iIii1I11I1II1
  if 20 - 20: OoOoOO00
 checkpoint_list . append ( oo0O00OOOOO )
 return
 if 84 - 84: OoOoOO00
 if 59 - 59: Ii1I / I1Ii111 + i11iIiiIii
 if 20 - 20: O0 / I1Ii111 - OOooOOo % iIii1I11I1II1
 if 89 - 89: O0 * OoOoOO00 . ooOoO0o
 if 11 - 11: iIii1I11I1II1 * OoO0O00 . I1IiiI * OoOoOO00 / II111iiii
 if 72 - 72: I11i
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
def lisp_check_dp_socket ( ) :
 OOOOoO0OO0OOO = lisp_ipc_dp_socket_name
 if ( os . path . exists ( OOOOoO0OO0OOO ) == False ) :
  iIIi1i11iI = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( OOOOoO0OO0OOO , iIIi1i11iI ) )
  return ( False )
  if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
 return ( True )
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 if 9 - 9: i1IIi % iII111i / Ii1I
 if 83 - 83: oO0o
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if 29 - 29: OoooooooOO
 if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
def lisp_write_to_dp_socket ( entry ) :
 try :
  o0o = json . dumps ( entry )
  o00o0o0O0o0 = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( o00o0o0O0o0 , o0o ) )
  lisp_ipc_dp_socket . sendto ( o0o , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( o0o ) )
  if 12 - 12: oO0o - ooOoO0o
 return
 if 71 - 71: OoOoOO00 * o0oOOo0O0Ooo + oO0o - Ii1I
 if 79 - 79: I1IiiI + oO0o
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 if 74 - 74: i1IIi % i11iIiiIii + oO0o
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
 if 97 - 97: I11i
 if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
 if 20 - 20: oO0o % OoOoOO00
def lisp_write_ipc_keys ( rloc ) :
 O0O0 = rloc . rloc . print_address_no_iid ( )
 ooO0 = rloc . translated_port
 if ( ooO0 != 0 ) : O0O0 += ":" + str ( ooO0 )
 if ( O0O0 not in lisp_rloc_probe_list ) : return
 if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
 for iiiI1I , oO0ooOOO , Oo in lisp_rloc_probe_list [ O0O0 ] :
  iIIiiiiI11i = lisp_map_cache . lookup_cache ( oO0ooOOO , True )
  if ( iIIiiiiI11i == None ) : continue
  lisp_write_ipc_map_cache ( True , iIIiiiiI11i )
  if 82 - 82: OOooOOo
 return
 if 27 - 27: I1Ii111 / IiII - i1IIi * Ii1I
 if 90 - 90: ooOoO0o
 if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
 if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
 if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
 if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
 if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 55 - 55: Oo0Ooo - OOooOOo - O0
 if 40 - 40: OoOoOO00 - OOooOOo
 if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 if 35 - 35: II111iiii
 oOOoo = "add" if add_or_delete else "delete"
 oo0O00OOOOO = { "type" : "map-cache" , "opcode" : oOOoo }
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 Ooo0 = ( mc . group . is_null ( ) == False )
 if ( Ooo0 ) :
  oo0O00OOOOO [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  oo0O00OOOOO [ "rles" ] = [ ]
 else :
  oo0O00OOOOO [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  oo0O00OOOOO [ "rlocs" ] = [ ]
  if 96 - 96: O0
 oo0O00OOOOO [ "instance-id" ] = str ( mc . eid . instance_id )
 if 15 - 15: i1IIi . iIii1I11I1II1
 if ( Ooo0 ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for oO0oOOOO0oO0o0 in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    IiI = oO0oOOOO0oO0o0 . address . print_address_no_iid ( )
    ooO0 = str ( 4341 ) if oO0oOOOO0oO0o0 . translated_port == 0 else str ( oO0oOOOO0oO0o0 . translated_port )
    if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
    iiiI1I = { "rle" : IiI , "port" : ooO0 }
    OooOo0o , II111iIIiI = oO0oOOOO0oO0o0 . get_encap_keys ( )
    iiiI1I = lisp_build_json_keys ( iiiI1I , OooOo0o , II111iIIiI , "encrypt-key" )
    oo0O00OOOOO [ "rles" ] . append ( iiiI1I )
    if 42 - 42: Oo0Ooo * I1IiiI % OoOoOO00
    if 9 - 9: OoooooooOO - Oo0Ooo - I1ii11iIi11i * o0oOOo0O0Ooo * I11i
 else :
  for IIIi1iI1 in mc . rloc_set :
   if ( IIIi1iI1 . rloc . is_ipv4 ( ) == False and IIIi1iI1 . rloc . is_ipv6 ( ) == False ) :
    continue
    if 27 - 27: OoOoOO00 % OoO0O00 * oO0o . II111iiii - i11iIiiIii
   if ( IIIi1iI1 . up_state ( ) == False ) : continue
   if 56 - 56: OOooOOo . IiII - OOooOOo / i11iIiiIii * I1ii11iIi11i
   ooO0 = str ( 4341 ) if IIIi1iI1 . translated_port == 0 else str ( IIIi1iI1 . translated_port )
   if 66 - 66: oO0o + ooOoO0o
   iiiI1I = { "rloc" : IIIi1iI1 . rloc . print_address_no_iid ( ) , "priority" :
 str ( IIIi1iI1 . priority ) , "weight" : str ( IIIi1iI1 . weight ) , "port" :
 ooO0 }
   OooOo0o , II111iIIiI = IIIi1iI1 . get_encap_keys ( )
   iiiI1I = lisp_build_json_keys ( iiiI1I , OooOo0o , II111iIIiI , "encrypt-key" )
   oo0O00OOOOO [ "rlocs" ] . append ( iiiI1I )
   if 1 - 1: ooOoO0o
   if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
   if 75 - 75: Ii1I
 if ( dont_send == False ) : lisp_write_to_dp_socket ( oo0O00OOOOO )
 return ( oo0O00OOOOO )
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
 if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
 if 82 - 82: II111iiii
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
 OooOo0o = keys [ 1 ] . encrypt_key
 II111iIIiI = keys [ 1 ] . icv_key
 if 53 - 53: Ii1I
 if 63 - 63: I11i % OoOoOO00
 if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
 if 52 - 52: I11i + iII111i
 IIii11IIIii = rloc_addr . split ( ":" )
 if ( len ( IIii11IIIii ) == 1 ) :
  oo0O00OOOOO = { "type" : "decap-keys" , "rloc" : IIii11IIIii [ 0 ] }
 else :
  oo0O00OOOOO = { "type" : "decap-keys" , "rloc" : IIii11IIIii [ 0 ] , "port" : IIii11IIIii [ 1 ] }
  if 43 - 43: OoooooooOO * O0
 oo0O00OOOOO = lisp_build_json_keys ( oo0O00OOOOO , OooOo0o , II111iIIiI , "decrypt-key" )
 if 62 - 62: IiII . O0
 lisp_write_to_dp_socket ( oo0O00OOOOO )
 return
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
 if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
 if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
 if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
 if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
 if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
 if 24 - 24: OoOoOO00
 if 87 - 87: I1ii11iIi11i / ooOoO0o * i1IIi
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 71 - 71: OoOoOO00 - I11i
 entry [ "keys" ] = [ ]
 III = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( III )
 return ( entry )
 if 83 - 83: oO0o + oO0o - Oo0Ooo . Oo0Ooo - iII111i . OOooOOo
 if 56 - 56: OoOoOO00 * IiII + i1IIi
 if 40 - 40: I1ii11iIi11i / O0
 if 87 - 87: ooOoO0o
 if 100 - 100: iII111i + II111iiii * Oo0Ooo * OOooOOo
 if 6 - 6: IiII % OOooOOo
 if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 41 - 41: oO0o
 if 12 - 12: I1IiiI + I1Ii111
 if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
 oo0O00OOOOO = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 79 - 79: Ii1I + IiII
 if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
 if 98 - 98: I1ii11iIi11i
 if 58 - 58: IiII / i11iIiiIii % I11i
 for oooOOoO0oo0 in lisp_db_list :
  if ( oooOOoO0oo0 . eid . is_ipv4 ( ) == False and oooOOoO0oo0 . eid . is_ipv6 ( ) == False ) : continue
  OoOO0Oo0 = { "instance-id" : str ( oooOOoO0oo0 . eid . instance_id ) ,
 "eid-prefix" : oooOOoO0oo0 . eid . print_prefix_no_iid ( ) }
  oo0O00OOOOO [ "database-mappings" ] . append ( OoOO0Oo0 )
  if 54 - 54: Ii1I . I11i
 lisp_write_to_dp_socket ( oo0O00OOOOO )
 if 97 - 97: I1Ii111
 if 18 - 18: I1Ii111 - i1IIi
 if 76 - 76: I1ii11iIi11i - I1Ii111 % IiII . Ii1I + OoooooooOO * OoOoOO00
 if 47 - 47: Oo0Ooo
 if 81 - 81: I1Ii111 * o0oOOo0O0Ooo . oO0o % iIii1I11I1II1 - OoOoOO00 * OoO0O00
 oo0O00OOOOO = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( oo0O00OOOOO )
 return
 if 32 - 32: I1Ii111 + Ii1I / Oo0Ooo - OoO0O00
 if 30 - 30: iIii1I11I1II1
 if 68 - 68: Oo0Ooo / I1Ii111 / i1IIi + iII111i
 if 46 - 46: OOooOOo
 if 68 - 68: o0oOOo0O0Ooo . OoooooooOO + OoOoOO00 + OoOoOO00 + oO0o * OoOoOO00
 if 18 - 18: ooOoO0o . II111iiii . OOooOOo * I11i + O0 / iIii1I11I1II1
 if 31 - 31: O0 - OoOoOO00
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 90 - 90: O0
 if 62 - 62: iIii1I11I1II1
 if 65 - 65: ooOoO0o / Ii1I + I11i . i1IIi + i1IIi . o0oOOo0O0Ooo
 if 21 - 21: I1IiiI + Oo0Ooo / Ii1I * OoooooooOO
 oo0O00OOOOO = { "type" : "interfaces" , "interfaces" : [ ] }
 if 71 - 71: o0oOOo0O0Ooo % ooOoO0o / oO0o - oO0o / OoooooooOO
 for i111IIiIiiI1 in list ( lisp_myinterfaces . values ( ) ) :
  if ( i111IIiIiiI1 . instance_id == None ) : continue
  OoOO0Oo0 = { "interface" : i111IIiIiiI1 . device ,
 "instance-id" : str ( i111IIiIiiI1 . instance_id ) }
  oo0O00OOOOO [ "interfaces" ] . append ( OoOO0Oo0 )
  if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
  if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 lisp_write_to_dp_socket ( oo0O00OOOOO )
 return
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
def lisp_parse_auth_key ( value ) :
 oOOoo0O000OO = value . split ( "[" )
 oOoo = { }
 if ( len ( oOOoo0O000OO ) == 1 ) :
  oOoo [ 0 ] = value
  return ( oOoo )
  if 72 - 72: II111iiii . II111iiii / iII111i % i1IIi / OoO0O00
  if 83 - 83: I11i % iIii1I11I1II1 * OoO0O00 - I1IiiI
 for i1i11i in oOOoo0O000OO :
  if ( i1i11i == "" ) : continue
  OOOooo0OooOoO = i1i11i . find ( "]" )
  IiII11iI1 = i1i11i [ 0 : OOOooo0OooOoO ]
  try : IiII11iI1 = int ( IiII11iI1 )
  except : return
  if 80 - 80: ooOoO0o - OoO0O00 . I1IiiI - I1IiiI
  oOoo [ IiII11iI1 ] = i1i11i [ OOOooo0OooOoO + 1 : : ]
  if 61 - 61: II111iiii - iIii1I11I1II1 + OoOoOO00
 return ( oOoo )
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
def lisp_reassemble ( packet ) :
 Oo0ooo = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if ( Oo0ooo == 0 or Oo0ooo == 0x4000 ) : return ( packet )
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if 4 - 4: iII111i
 if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
 if 32 - 32: iII111i
 OOoo0 = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 oOOo0 = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 59 - 59: OoOoOO00 - I1Ii111
 I1iiii11iiIii1Ii = ( Oo0ooo & 0x2000 == 0 and ( Oo0ooo & 0x1fff ) != 0 )
 oo0O00OOOOO = [ ( Oo0ooo & 0x1fff ) * 8 , oOOo0 - 20 , packet , I1iiii11iiIii1Ii ]
 if 35 - 35: OoooooooOO / OoooooooOO % Oo0Ooo / I11i % iIii1I11I1II1 * OOooOOo
 if 58 - 58: i11iIiiIii / OoOoOO00
 if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
 if 83 - 83: OoO0O00 - Oo0Ooo * I1IiiI % Oo0Ooo % oO0o
 if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
 if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
 if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
 if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
 if ( Oo0ooo == 0x2000 ) :
  oooooO0oO0ooO , iIII1IiI = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  oooooO0oO0ooO = socket . ntohs ( oooooO0oO0ooO )
  iIII1IiI = socket . ntohs ( iIII1IiI )
  if ( iIII1IiI not in [ 4341 , 8472 , 4789 ] and oooooO0oO0ooO != 4341 ) :
   lisp_reassembly_queue [ OOoo0 ] = [ ]
   oo0O00OOOOO [ 2 ] = None
   if 21 - 21: IiII
   if 43 - 43: IiII
   if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
   if 8 - 8: IiII * iIii1I11I1II1
   if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
   if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
 if ( OOoo0 not in lisp_reassembly_queue ) :
  lisp_reassembly_queue [ OOoo0 ] = [ ]
  if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
  if 84 - 84: OoooooooOO
  if 95 - 95: o0oOOo0O0Ooo
  if 22 - 22: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
  if 41 - 41: oO0o . II111iiii
 queue = lisp_reassembly_queue [ OOoo0 ]
 if 47 - 47: I1ii11iIi11i
 if 5 - 5: Oo0Ooo
 if 23 - 23: i11iIiiIii / I11i + i1IIi % I1Ii111
 if 100 - 100: Oo0Ooo
 if 13 - 13: I1IiiI + ooOoO0o * II111iiii
 if ( len ( queue ) == 1 and queue [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( OOoo0 ) . zfill ( 4 ) ) )
  if 32 - 32: iIii1I11I1II1 + O0 + i1IIi
  return ( None )
  if 28 - 28: IiII + I11i
  if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
  if 56 - 56: Ii1I . OoO0O00
  if 43 - 43: iII111i * iII111i
  if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 queue . append ( oo0O00OOOOO )
 queue = sorted ( queue )
 if 96 - 96: OoooooooOO * iIii1I11I1II1 * Oo0Ooo
 if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
 if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
 if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
 IiI = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IiI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 iIIIi1iiii11 = IiI . print_address_no_iid ( )
 IiI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 III11iII1i = IiI . print_address_no_iid ( )
 IiI = red ( "{} -> {}" . format ( iIIIi1iiii11 , III11iII1i ) , False )
 if 52 - 52: iII111i / OoOoOO00
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if oo0O00OOOOO [ 2 ] == None else "" , IiI , lisp_hex_string ( OOoo0 ) . zfill ( 4 ) ,
 # OoooooooOO - OoOoOO00 / o0oOOo0O0Ooo
 # Ii1I / OoOoOO00 . OOooOOo * IiII . OoooooooOO
 lisp_hex_string ( Oo0ooo ) . zfill ( 4 ) ) )
 if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
 if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
 if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
 if 75 - 75: IiII
 if 74 - 74: o0oOOo0O0Ooo - iIii1I11I1II1
 if ( queue [ 0 ] [ 0 ] != 0 or queue [ - 1 ] [ 3 ] == False ) : return ( None )
 OoOoo0oo0Ooo = queue [ 0 ]
 for Ii in queue [ 1 : : ] :
  Oo0ooo = Ii [ 0 ]
  iII1iii1iiII1 , OO00OoO0o = OoOoo0oo0Ooo [ 0 ] , OoOoo0oo0Ooo [ 1 ]
  if ( iII1iii1iiII1 + OO00OoO0o != Oo0ooo ) : return ( None )
  OoOoo0oo0Ooo = Ii
  if 7 - 7: i11iIiiIii % I1IiiI % II111iiii - II111iiii
 lisp_reassembly_queue . pop ( OOoo0 )
 if 44 - 44: o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
 if 87 - 87: OOooOOo * OoO0O00
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 if 86 - 86: II111iiii
 packet = queue [ 0 ] [ 2 ]
 for Ii in queue [ 1 : : ] : packet += Ii [ 2 ] [ 20 : : ]
 if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( OOoo0 ) . zfill ( 4 ) , len ( packet ) ) )
 if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
 if 91 - 91: Ii1I
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 72 - 72: I1ii11iIi11i
 if 5 - 5: i1IIi
 i1iIii = socket . htons ( len ( packet ) )
 IiIii1iIIII = packet [ 0 : 2 ] + struct . pack ( "H" , i1iIii ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 31 - 31: iII111i - OoooooooOO + oO0o / OoooooooOO + I1ii11iIi11i
 if 93 - 93: o0oOOo0O0Ooo * I1ii11iIi11i % I1IiiI * ooOoO0o
 IiIii1iIIII = lisp_ip_checksum ( IiIii1iIIII )
 return ( IiIii1iIIII + packet [ 20 : : ] )
 if 37 - 37: OoO0O00 * OoooooooOO / oO0o * I11i * I1ii11iIi11i
 if 42 - 42: OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
 if 53 - 53: o0oOOo0O0Ooo
 if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
 if 31 - 31: OoO0O00 % I1Ii111
 if 62 - 62: oO0o / O0 - I1Ii111 . IiII
 if 81 - 81: i11iIiiIii
 if 57 - 57: O0
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 O0O0 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( O0O0 in lisp_crypto_keys_by_rloc_decap ) : return ( O0O0 )
 if 85 - 85: i11iIiiIii - i11iIiiIii - OoOoOO00 / II111iiii - II111iiii
 O0O0 = addr . print_address_no_iid ( )
 if ( O0O0 in lisp_crypto_keys_by_rloc_decap ) : return ( O0O0 )
 if 4 - 4: I1ii11iIi11i * O0 / OoO0O00 * II111iiii . iIii1I11I1II1 / OOooOOo
 if 97 - 97: i1IIi - OoOoOO00 . OoooooooOO
 if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
 if 64 - 64: IiII . I1ii11iIi11i - o0oOOo0O0Ooo - ooOoO0o + OoooooooOO
 if 95 - 95: iII111i . I1ii11iIi11i + ooOoO0o + o0oOOo0O0Ooo % OoO0O00
 for i11ii1IIIIiII in lisp_crypto_keys_by_rloc_decap :
  OO0O00o0 = i11ii1IIIIiII . split ( ":" )
  if ( len ( OO0O00o0 ) == 1 ) : continue
  OO0O00o0 = OO0O00o0 [ 0 ] if len ( OO0O00o0 ) == 2 else ":" . join ( OO0O00o0 [ 0 : - 1 ] )
  if ( OO0O00o0 == O0O0 ) :
   iI1iiiiiii = lisp_crypto_keys_by_rloc_decap [ i11ii1IIIIiII ]
   lisp_crypto_keys_by_rloc_decap [ O0O0 ] = iI1iiiiiii
   return ( O0O0 )
   if 41 - 41: Ii1I
   if 78 - 78: OOooOOo
 return ( None )
 if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
 if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
 if 81 - 81: IiII
 if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
 if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
 if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
 if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
 if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
 if 79 - 79: IiII + I1Ii111
 if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 O00OOooO = addr + ":" + str ( port )
 if 99 - 99: OoooooooOO / i11iIiiIii / ooOoO0o - O0 - I1ii11iIi11i
 if ( lisp_i_am_rtr ) :
  if ( addr in lisp_rloc_probe_list ) : return ( addr )
  if 14 - 14: OoOoOO00 . i1IIi + Oo0Ooo / O0 - IiII
  if 80 - 80: I1IiiI + ooOoO0o
  if 43 - 43: OoooooooOO * iIii1I11I1II1
  if 82 - 82: i1IIi - I11i % ooOoO0o . OoOoOO00 * o0oOOo0O0Ooo
  if 20 - 20: i11iIiiIii - O0 / i11iIiiIii
  if 51 - 51: iII111i . ooOoO0o
  for iIIi11I in list ( lisp_nat_state_info . values ( ) ) :
   for oOOooO0oo in iIIi11I :
    if ( addr == oOOooO0oo . address ) : return ( O00OOooO )
    if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
    if 6 - 6: I11i + II111iiii - I1Ii111
  return ( addr )
  if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
 return ( O00OOooO )
 if 56 - 56: I11i + I1Ii111
 if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
 if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
 if 64 - 64: O0 / OoooooooOO
 if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
 if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_MULTICAST_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 return
 if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
 if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
 if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
 if 77 - 77: OoO0O00
 if 95 - 95: II111iiii
 if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
 if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
 if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
 if 97 - 97: I1Ii111
 if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
 if 56 - 56: O0 - i1IIi % o0oOOo0O0Ooo + IiII
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo % I11i - OoOoOO00
 if 38 - 38: OoooooooOO
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
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
 if 85 - 85: I1ii11iIi11i / IiII + oO0o
 if 95 - 95: IiII . OoO0O00
 if 36 - 36: IiII % Ii1I - OoOoOO00 + OoO0O00 + IiII * Ii1I
def lisp_is_rloc_probe ( packet , rr ) :
 O0I1II1 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == 17 )
 if ( O0I1II1 == False ) : return ( [ packet , None , None , None ] )
 if 15 - 15: I1IiiI / O0 % I1ii11iIi11i % OoOoOO00 . OoOoOO00 + iII111i
 oooooO0oO0ooO = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 iIII1IiI = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 OOo0o0o = ( socket . htons ( LISP_CTRL_PORT ) in [ oooooO0oO0ooO , iIII1IiI ] )
 if ( OOo0o0o == False ) : return ( [ packet , None , None , None ] )
 if 37 - 37: O0 . II111iiii
 if ( rr == 0 ) :
  iiIii11Ii = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( iiIii11Ii == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  iiIii11Ii = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
  if ( iiIii11Ii == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  iiIii11Ii = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( iiIii11Ii == False ) :
   iiIii11Ii = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
   if ( iiIii11Ii == False ) : return ( [ packet , None , None , None ] )
   if 56 - 56: II111iiii / oO0o + o0oOOo0O0Ooo / OOooOOo * OoO0O00
   if 29 - 29: O0
   if 43 - 43: Oo0Ooo / OoO0O00 * Oo0Ooo . IiII + I11i
   if 46 - 46: iIii1I11I1II1 % i1IIi - OoooooooOO . Ii1I
   if 91 - 91: iII111i - i11iIiiIii
   if 27 - 27: iII111i
 O0oo0OoO0oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O0oo0OoO0oo . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 66 - 66: O0 . iIii1I11I1II1 * II111iiii * OOooOOo * IiII
 if 44 - 44: i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo + I1ii11iIi11i + Ii1I
 if 43 - 43: i1IIi . iIii1I11I1II1
 if 86 - 86: OOooOOo + OoOoOO00 - OoO0O00 + i1IIi + iIii1I11I1II1
 if ( O0oo0OoO0oo . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 68 - 68: OoOoOO00 . I1IiiI + ooOoO0o - o0oOOo0O0Ooo
 if 62 - 62: Ii1I - OOooOOo
 if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
 if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
 O0oo0OoO0oo = O0oo0OoO0oo . print_address_no_iid ( )
 ooO0 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 IiIIi = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
 iiiI1I = bold ( "Receive(pcap)" , False )
 I1Ii = bold ( "from " + O0oo0OoO0oo , False )
 iIIiiIi = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( iiiI1I , len ( packet ) , I1Ii , ooO0 , iIIiiIi ) )
 if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
 return ( [ packet , O0oo0OoO0oo , ooO0 , IiIIi ] )
 if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
 if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
 if 2 - 2: I1ii11iIi11i
 if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
 if 54 - 54: ooOoO0o
 if 47 - 47: I11i * I1IiiI / oO0o
 if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
 if 4 - 4: i1IIi
 if 43 - 43: oO0o * ooOoO0o - I11i
 if 70 - 70: oO0o / Ii1I
 if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 16 - 16: iII111i
 OO = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 50 - 50: iIii1I11I1II1 - II111iiii % i1IIi
 lisp_write_to_dp_socket ( OO )
 return
 if 48 - 48: O0
 if 60 - 60: ooOoO0o - IiII % i1IIi
 if 5 - 5: oO0o
 if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
 if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
 if 58 - 58: oO0o . OoO0O00 / ooOoO0o
 if 61 - 61: I11i + I1Ii111
 if 27 - 27: ooOoO0o / i1IIi . oO0o - OoooooooOO
def lisp_external_data_plane ( ) :
 oO00o00 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( getoutput ( oO00o00 ) != "" ) : return ( True )
 if 48 - 48: ooOoO0o % ooOoO0o / OoooooooOO + i1IIi * oO0o + ooOoO0o
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
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
 if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
 if 79 - 79: I11i . I11i - OoOoOO00
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 86 - 86: OoO0O00 * Oo0Ooo . iIii1I11I1II1 * O0
 O0OoOOoO0 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 66 - 66: Ii1I * I1Ii111 - O0 . oO0o
 if ( do_clear == False ) :
  Oo00o0oOO0oo = O0OoOOoO0 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , Oo00o0oOO0oo )
  if 62 - 62: I1Ii111 % OoO0O00
  if 45 - 45: o0oOOo0O0Ooo . i1IIi - I1IiiI + iIii1I11I1II1 * O0 . I1Ii111
 lisp_write_to_dp_socket ( O0OoOOoO0 )
 return
 if 61 - 61: I1Ii111 . i1IIi % OoooooooOO
 if 54 - 54: Oo0Ooo
 if 26 - 26: II111iiii
 if 15 - 15: OoooooooOO * oO0o
 if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
 if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
 if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
 if 54 - 54: OoOoOO00 - I1IiiI - iII111i
 if 49 - 49: i11iIiiIii * Oo0Ooo
 if 100 - 100: Oo0Ooo * oO0o
 if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
 if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
 if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
 if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( "entries" not in msg ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 85 - 85: OoO0O00 - Ii1I / O0
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 45 - 45: IiII + I1Ii111 / I11i
  if 84 - 84: iII111i % II111iiii
 for msg in msg [ "entries" ] :
  if ( "eid-prefix" not in msg ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
  i1iiii = msg [ "eid-prefix" ]
  if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
  if ( "instance-id" not in msg ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
  oooo = int ( msg [ "instance-id" ] )
  if 68 - 68: O0 % oO0o * IiII % O0
  if 55 - 55: O0 % I1IiiI % O0
  if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
  if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
  oo0oO = lisp_address ( LISP_AFI_NONE , "" , 0 , oooo )
  oo0oO . store_prefix ( i1iiii )
  iIIiiiiI11i = lisp_map_cache_lookup ( None , oo0oO )
  if ( iIIiiiiI11i == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( i1iiii ) )
   if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
   continue
   if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
   if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
  if ( "rlocs" not in msg ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( i1iiii ) )
   if 23 - 23: I1Ii111 / iII111i . O0 % II111iiii
   continue
   if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
  oOoO0O00 = msg [ "rlocs" ]
  if 100 - 100: iII111i % i11iIiiIii % I1Ii111
  if 77 - 77: OoOoOO00 . IiII
  if 86 - 86: I1Ii111 + iII111i . Ii1I
  if 65 - 65: i11iIiiIii % i11iIiiIii
  for OOooOooO in oOoO0O00 :
   if ( "rloc" not in OOooOooO ) : continue
   if 82 - 82: i1IIi % Ii1I
   IIIOo0O = OOooOooO [ "rloc" ]
   if ( IIIOo0O == "no-address" ) : continue
   if 85 - 85: I1Ii111 * i11iIiiIii * iIii1I11I1II1 % iIii1I11I1II1
   IIIi1iI1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   IIIi1iI1 . store_address ( IIIOo0O )
   if 64 - 64: OoO0O00 / Ii1I
   iiIiIIi1I = iIIiiiiI11i . get_rloc ( IIIi1iI1 )
   if ( iiIiIIi1I == None ) : continue
   if 79 - 79: Ii1I % OOooOOo
   if 39 - 39: I1ii11iIi11i / Ii1I - II111iiii . i1IIi
   if 59 - 59: II111iiii
   if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
   O0oO0oO = 0 if ( "packet-count" not in OOooOooO ) else OOooOooO [ "packet-count" ]
   if 13 - 13: I11i % iIii1I11I1II1 % iII111i
   Oo0OOOooO0 = 0 if ( "byte-count" not in OOooOooO ) else OOooOooO [ "byte-count" ]
   if 92 - 92: ooOoO0o / OoO0O00 + ooOoO0o + OOooOOo * i11iIiiIii - OoO0O00
   i1 = 0 if ( "seconds-last-packet" not in OOooOooO ) else OOooOooO [ "seconds-last-packet" ]
   if 1 - 1: OOooOOo . OoooooooOO / oO0o
   if 15 - 15: I11i - i1IIi
   iiIiIIi1I . stats . packet_count += O0oO0oO
   iiIiIIi1I . stats . byte_count += Oo0OOOooO0
   iiIiIIi1I . stats . last_increment = lisp_get_timestamp ( ) - i1
   if 15 - 15: ooOoO0o % I1Ii111 * OoooooooOO % IiII + I1ii11iIi11i - Ii1I
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( O0oO0oO , Oo0OOOooO0 ,
 i1 , i1iiii , IIIOo0O ) )
   if 67 - 67: i1IIi % I1ii11iIi11i * OOooOOo . Oo0Ooo
   if 82 - 82: iII111i . O0 / Oo0Ooo / OoooooooOO
   if 68 - 68: OoooooooOO . iIii1I11I1II1 / iII111i / OOooOOo
   if 35 - 35: I1ii11iIi11i * I11i % o0oOOo0O0Ooo + i1IIi % iII111i / IiII
   if 41 - 41: IiII . OOooOOo % ooOoO0o
  if ( iIIiiiiI11i . group . is_null ( ) and iIIiiiiI11i . has_ttl_elapsed ( ) ) :
   i1iiii = green ( iIIiiiiI11i . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( i1iiii ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , iIIiiiiI11i . eid , None )
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
 if 44 - 44: O0 . OOooOOo . o0oOOo0O0Ooo . I1ii11iIi11i - II111iiii
 if 71 - 71: I1ii11iIi11i + o0oOOo0O0Ooo . i11iIiiIii * oO0o . i1IIi
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 40 - 40: OoO0O00 - IiII
 if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
 if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
 if 38 - 38: iII111i - I1IiiI / ooOoO0o
 if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  OO = "stats%{}" . format ( json . dumps ( msg ) )
  OO = lisp_command_ipc ( OO , "lisp-itr" )
  lisp_ipc ( OO , lisp_ipc_socket , "lisp-etr" )
  return
  if 19 - 19: I11i / Oo0Ooo + I1Ii111
  if 43 - 43: I1ii11iIi11i
  if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
  if 22 - 22: iII111i
  if 88 - 88: I11i + OoOoOO00 % IiII % OoO0O00 * O0 / OoooooooOO
  if 83 - 83: IiII + I1Ii111 . I1ii11iIi11i * iIii1I11I1II1
  if 9 - 9: ooOoO0o % IiII - OoOoOO00
  if 66 - 66: oO0o % Oo0Ooo
 OO = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( OO , msg ) )
 if 40 - 40: i11iIiiIii . O0 * I11i - oO0o / OOooOOo . oO0o
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 86 - 86: OOooOOo - I1Ii111 * IiII - i1IIi + ooOoO0o + I11i
 i1iii1I11III = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 47 - 47: IiII * I11i / o0oOOo0O0Ooo * I1ii11iIi11i
 for OoII11iIIiiI in i1iii1I11III :
  O0oO0oO = 0 if ( OoII11iIIiiI not in msg ) else msg [ OoII11iIIiiI ] [ "packet-count" ]
  lisp_decap_stats [ OoII11iIIiiI ] . packet_count += O0oO0oO
  if 91 - 91: I1IiiI + OoooooooOO / OoooooooOO + I11i
  Oo0OOOooO0 = 0 if ( OoII11iIIiiI not in msg ) else msg [ OoII11iIIiiI ] [ "byte-count" ]
  lisp_decap_stats [ OoII11iIIiiI ] . byte_count += Oo0OOOooO0
  if 95 - 95: iII111i % I1IiiI . ooOoO0o
  i1 = 0 if ( OoII11iIIiiI not in msg ) else msg [ OoII11iIIiiI ] [ "seconds-last-packet" ]
  if 70 - 70: OoOoOO00 - iII111i . IiII + iIii1I11I1II1
  lisp_decap_stats [ OoII11iIIiiI ] . last_increment = lisp_get_timestamp ( ) - i1
  if 13 - 13: oO0o * I1Ii111 / I1Ii111 . I1IiiI
 return
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
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 i11i1i , O0oo0OoO0oo = punt_socket . recvfrom ( 4000 )
 if 11 - 11: i1IIi * I1Ii111 / OoOoOO00 . I1Ii111 + OoOoOO00 % IiII
 iiII1Ii1 = json . loads ( i11i1i )
 if ( type ( iiII1Ii1 ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( O0oo0OoO0oo ) )
  if 18 - 18: OoooooooOO / Ii1I / i1IIi / oO0o
  return
  if 24 - 24: OoO0O00 * iII111i - i11iIiiIii + oO0o
 OOo0OoOoOO00 = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( OOo0OoOoOO00 , O0oo0OoO0oo , iiII1Ii1 ) )
 if 15 - 15: Oo0Ooo . Ii1I - OoooooooOO % OoO0O00 + i11iIiiIii + iII111i
 if ( "type" not in iiII1Ii1 ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 91 - 91: OoooooooOO % Oo0Ooo - Ii1I
  if 54 - 54: O0 - iIii1I11I1II1 . OoO0O00 . IiII % OoO0O00
  if 28 - 28: O0 % i1IIi % OoO0O00 / o0oOOo0O0Ooo . iIii1I11I1II1 - iII111i
  if 50 - 50: o0oOOo0O0Ooo + iII111i / i1IIi % II111iiii
  if 61 - 61: IiII
 if ( iiII1Ii1 [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( iiII1Ii1 , lisp_send_sockets , lisp_ephem_port )
  return
  if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
 if ( iiII1Ii1 [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( iiII1Ii1 , punt_socket )
  return
  if 48 - 48: IiII * oO0o
  if 53 - 53: i1IIi * iIii1I11I1II1 . OOooOOo
  if 68 - 68: IiII % IiII - iII111i . IiII + OoooooooOO
  if 82 - 82: Ii1I . II111iiii / i1IIi * OoO0O00
  if 80 - 80: I11i
 if ( iiII1Ii1 [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 96 - 96: i1IIi - I1ii11iIi11i * iII111i . OOooOOo . OoO0O00
  if 93 - 93: oO0o * Oo0Ooo * IiII
  if 26 - 26: o0oOOo0O0Ooo + O0 % i11iIiiIii . ooOoO0o . I1IiiI + Oo0Ooo
  if 90 - 90: IiII * OoooooooOO + II111iiii / iII111i + i11iIiiIii / ooOoO0o
  if 20 - 20: II111iiii % I1ii11iIi11i - OoooooooOO * Ii1I / I11i - OoooooooOO
 if ( iiII1Ii1 [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 11 - 11: I1IiiI + Ii1I + i11iIiiIii * I1ii11iIi11i - oO0o
 if ( "interface" not in iiII1Ii1 ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( O0oo0OoO0oo ) )
  if 46 - 46: OoooooooOO - Oo0Ooo
  return
  if 4 - 4: II111iiii . OOooOOo - Ii1I - i11iIiiIii
  if 27 - 27: iII111i * iII111i - OoO0O00 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 64 - 64: I1ii11iIi11i * ooOoO0o - OoooooooOO - I1IiiI
  if 59 - 59: I1ii11iIi11i . I1Ii111 - OOooOOo / Oo0Ooo + OOooOOo . I1ii11iIi11i
  if 69 - 69: Oo0Ooo
 ooO000OO = iiII1Ii1 [ "interface" ]
 if ( ooO000OO == "" ) :
  oooo = int ( iiII1Ii1 [ "instance-id" ] )
  if ( oooo == - 1 ) : return
 else :
  oooo = lisp_get_interface_instance_id ( ooO000OO , None )
  if 34 - 34: I1Ii111 - ooOoO0o . o0oOOo0O0Ooo
  if 52 - 52: o0oOOo0O0Ooo % I11i * I11i / iIii1I11I1II1
  if 77 - 77: OoOoOO00
  if 67 - 67: OoooooooOO / OoooooooOO + IiII - ooOoO0o
  if 72 - 72: Ii1I
 I1IiiII1I1 = None
 if ( "source-eid" in iiII1Ii1 ) :
  I1I = iiII1Ii1 [ "source-eid" ]
  I1IiiII1I1 = lisp_address ( LISP_AFI_NONE , I1I , 0 , oooo )
  if ( I1IiiII1I1 . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( I1I ) )
   return
   if 21 - 21: ooOoO0o + iII111i
   if 39 - 39: o0oOOo0O0Ooo % I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo
 Ii1Ii11I = None
 if ( "dest-eid" in iiII1Ii1 ) :
  OOoO0 = iiII1Ii1 [ "dest-eid" ]
  Ii1Ii11I = lisp_address ( LISP_AFI_NONE , OOoO0 , 0 , oooo )
  if ( Ii1Ii11I . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( OOoO0 ) )
   return
   if 6 - 6: i1IIi - Oo0Ooo % o0oOOo0O0Ooo - oO0o . II111iiii
   if 67 - 67: iII111i + I11i - OoO0O00 . OOooOOo * iIii1I11I1II1
   if 44 - 44: OoooooooOO * i1IIi % i1IIi - i11iIiiIii % OOooOOo - OoO0O00
   if 62 - 62: OOooOOo + OoooooooOO / I1Ii111 % iIii1I11I1II1
   if 59 - 59: i11iIiiIii . IiII
   if 91 - 91: Oo0Ooo / iII111i + I1Ii111
   if 32 - 32: i1IIi - iII111i + o0oOOo0O0Ooo * I1Ii111 % I1ii11iIi11i / i11iIiiIii
   if 91 - 91: IiII / OoooooooOO . OoooooooOO + OoooooooOO * I1ii11iIi11i . OoOoOO00
 if ( I1IiiII1I1 ) :
  oO0ooOOO = green ( I1IiiII1I1 . print_address ( ) , False )
  oooOOoO0oo0 = lisp_db_for_lookups . lookup_cache ( I1IiiII1I1 , False )
  if ( oooOOoO0oo0 != None ) :
   if 22 - 22: iIii1I11I1II1 - OoO0O00
   if 77 - 77: I1IiiI + IiII - oO0o - I1ii11iIi11i * II111iiii + i1IIi
   if 79 - 79: I1ii11iIi11i + O0 * OoooooooOO
   if 43 - 43: I11i
   if 29 - 29: o0oOOo0O0Ooo / I11i
   if ( oooOOoO0oo0 . dynamic_eid_configured ( ) ) :
    i111IIiIiiI1 = lisp_allow_dynamic_eid ( ooO000OO , I1IiiII1I1 )
    if ( i111IIiIiiI1 != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( oooOOoO0oo0 , I1IiiII1I1 , ooO000OO , i111IIiIiiI1 )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( oO0ooOOO , ooO000OO ) )
     if 88 - 88: OoOoOO00 - Ii1I . O0 % I1Ii111 % I1ii11iIi11i
     if 56 - 56: OoOoOO00 - iIii1I11I1II1 / I1IiiI - i1IIi / o0oOOo0O0Ooo * I11i
     if 70 - 70: OOooOOo
  else :
   lprint ( "Punt from non-EID source {}" . format ( oO0ooOOO ) )
   if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
   if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
   if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
   if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
   if 63 - 63: I1IiiI
   if 20 - 20: oO0o + OoOoOO00
 if ( Ii1Ii11I ) :
  iIIiiiiI11i = lisp_map_cache_lookup ( I1IiiII1I1 , Ii1Ii11I )
  if ( iIIiiiiI11i == None or lisp_mr_or_pubsub ( iIIiiiiI11i . action ) ) :
   if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
   if 4 - 4: OOooOOo % oO0o
   if 18 - 18: Ii1I * I11i
   if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
   if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
   if ( lisp_rate_limit_map_request ( Ii1Ii11I ) ) : return
   if 56 - 56: Oo0Ooo . I1ii11iIi11i - i11iIiiIii / iIii1I11I1II1 . ooOoO0o
   OO0OoooO0 = ( iIIiiiiI11i and iIIiiiiI11i . action == LISP_SEND_PUBSUB_ACTION )
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 I1IiiII1I1 , Ii1Ii11I , None , OO0OoooO0 )
  else :
   oO0ooOOO = green ( Ii1Ii11I . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( oO0ooOOO ) )
   if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
   if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
 return
 if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
 if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 66 - 66: I1IiiI . Oo0Ooo - oO0o
 if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
 if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
 if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
 if 68 - 68: OoOoOO00 - iII111i - I1IiiI
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 oo0O00OOOOO = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( oo0O00OOOOO )
 return ( [ True , jdata ] )
 if 37 - 37: iII111i - I1Ii111 + i1IIi / o0oOOo0O0Ooo % iII111i / iII111i
 if 8 - 8: i1IIi % I11i
 if 12 - 12: ooOoO0o / II111iiii + ooOoO0o * I1ii11iIi11i / i1IIi - iIii1I11I1II1
 if 71 - 71: IiII - i11iIiiIii
 if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
 if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
 if 80 - 80: I11i
 if 98 - 98: iII111i / I1ii11iIi11i
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
 if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
 if 56 - 56: IiII * II111iiii + Oo0Ooo - O0 - OoO0O00 . I1Ii111
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 53 - 53: i1IIi + IiII
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 90 - 90: II111iiii / oO0o / oO0o . OoOoOO00 / OoO0O00 / iIii1I11I1II1
 if 96 - 96: iIii1I11I1II1 % I1ii11iIi11i
 if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
 if 72 - 72: I1Ii111 / OoO0O00 + II111iiii
 if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 25 - 25: IiII * IiII
 if 54 - 54: I1Ii111
 if 90 - 90: Oo0Ooo / Ii1I
 if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
 if 77 - 77: OoO0O00 / OOooOOo
 if 97 - 97: OoOoOO00 / Ii1I * I1IiiI - Oo0Ooo % O0
 if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 i1iiii = eid . print_address ( )
 if ( i1iiii in db . dynamic_eids ) :
  db . dynamic_eids [ i1iiii ] . last_packet = lisp_get_timestamp ( )
  return
  if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
  if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
  if 93 - 93: O0
  if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
  if 73 - 73: OoooooooOO
 IIIII1IIiIi = lisp_dynamic_eid ( )
 IIIII1IIiIi . dynamic_eid . copy_address ( eid )
 IIIII1IIiIi . interface = routed_interface
 IIIII1IIiIi . last_packet = lisp_get_timestamp ( )
 IIIII1IIiIi . get_timeout ( routed_interface )
 db . dynamic_eids [ i1iiii ] = IIIII1IIiIi
 if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
 ooO0O0 = ""
 if ( input_interface != routed_interface ) :
  ooO0O0 = ", routed-interface " + routed_interface
  if 56 - 56: I1ii11iIi11i
  if 76 - 76: Oo0Ooo / OoO0O00 - OoooooooOO
 I1iI1iI11 = green ( i1iiii , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( I1iI1iI11 , input_interface , ooO0O0 , IIIII1IIiIi . timeout ) )
 if 77 - 77: O0 * Ii1I - I11i / O0 . I11i
 if 55 - 55: i1IIi - i1IIi * iIii1I11I1II1 / II111iiii + iII111i / Ii1I
 if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 if 24 - 24: IiII / Oo0Ooo
 if 90 - 90: ooOoO0o . OOooOOo - Ii1I
 OO = "learn%{}%{}" . format ( i1iiii , routed_interface )
 OO = lisp_command_ipc ( OO , "lisp-itr" )
 lisp_ipc ( OO , lisp_ipc_listen_socket , "lisp-etr" )
 return
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
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 22 - 22: Oo0Ooo + ooOoO0o . OOooOOo % Oo0Ooo . IiII
 if 34 - 34: Ii1I . OoOoOO00 - OOooOOo * Oo0Ooo - ooOoO0o . oO0o
 if 42 - 42: O0 + OoO0O00
 if 47 - 47: O0 % OoOoOO00 + Ii1I * iIii1I11I1II1
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 55 - 55: Ii1I
 i11I1Ii1 = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 93 - 93: iII111i + OOooOOo . OoooooooOO . I1Ii111 . O0
 for III in lisp_crypto_keys_by_rloc_decap :
  if 46 - 46: i11iIiiIii
  if 26 - 26: I11i * Oo0Ooo % OoO0O00 + Oo0Ooo - I1ii11iIi11i
  if 74 - 74: i1IIi + OoO0O00 . II111iiii + I1Ii111
  if 59 - 59: Ii1I . i11iIiiIii . o0oOOo0O0Ooo * iIii1I11I1II1 . OoOoOO00 . II111iiii
  if ( III . find ( addr_str ) == - 1 ) : continue
  if 67 - 67: OoO0O00 - Oo0Ooo + OOooOOo / OoOoOO00 + OOooOOo
  if 18 - 18: Oo0Ooo % OoOoOO00 % i1IIi
  if 66 - 66: OoOoOO00 % II111iiii
  if 16 - 16: i11iIiiIii - I1IiiI + ooOoO0o * oO0o
  if ( III == addr_str ) : continue
  if 30 - 30: II111iiii / o0oOOo0O0Ooo
  if 57 - 57: I11i / I1ii11iIi11i . I11i
  if 68 - 68: OoOoOO00 + O0 . I1IiiI
  if 26 - 26: I1ii11iIi11i
  oo0O00OOOOO = lisp_crypto_keys_by_rloc_decap [ III ]
  if ( oo0O00OOOOO == i11I1Ii1 ) : continue
  if 98 - 98: Oo0Ooo
  if 72 - 72: oO0o + OoooooooOO . O0 + IiII
  if 49 - 49: i1IIi - i11iIiiIii + II111iiii + Ii1I / OoO0O00
  if 34 - 34: I1ii11iIi11i * i11iIiiIii
  IIiI1i1 = oo0O00OOOOO [ 1 ]
  if ( packet_icv != IIiI1i1 . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( III , False ) ) )
   continue
   if 72 - 72: O0 / iII111i + O0
   if 91 - 91: o0oOOo0O0Ooo * I11i + iIii1I11I1II1 * OoO0O00 . OoO0O00 + i1IIi
  lprint ( "Changing decap crypto key to {}" . format ( red ( III , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = oo0O00OOOOO
  if 19 - 19: I1Ii111 * I1ii11iIi11i
 return
 if 51 - 51: i1IIi * i11iIiiIii * iIii1I11I1II1 % I11i % OoooooooOO + OoO0O00
 if 18 - 18: iIii1I11I1II1 - IiII
 if 97 - 97: i11iIiiIii - O0 * o0oOOo0O0Ooo - IiII + I1IiiI
 if 7 - 7: oO0o + I1Ii111 . o0oOOo0O0Ooo / IiII + iIii1I11I1II1 % I1Ii111
 if 24 - 24: i11iIiiIii + iIii1I11I1II1
 if 22 - 22: i11iIiiIii . II111iiii / o0oOOo0O0Ooo / Ii1I . O0 . OoOoOO00
 if 89 - 89: O0 * Oo0Ooo + I1Ii111 + ooOoO0o * OoOoOO00
 if 20 - 20: OoO0O00 - OoOoOO00
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 84 - 84: iIii1I11I1II1 + ooOoO0o . o0oOOo0O0Ooo % iII111i
 if 35 - 35: I11i - oO0o * oO0o / OoooooooOO + iII111i + OoOoOO00
 if 48 - 48: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / o0oOOo0O0Ooo % O0
 if 38 - 38: OoO0O00 + o0oOOo0O0Ooo / OoO0O00
 if 74 - 74: oO0o - i1IIi . Oo0Ooo / I1IiiI + o0oOOo0O0Ooo . OoOoOO00
 if 35 - 35: iII111i / Ii1I
 if 57 - 57: ooOoO0o . I1IiiI * OOooOOo
 if 87 - 87: I11i - I11i % iII111i - Ii1I
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 iii1IiII1ii = dns_name . split ( "." )
 iii1IiII1ii = "." . join ( iii1IiII1ii [ 1 : : ] )
 return ( iii1IiII1ii == lisp_decent_dns_suffix )
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
def lisp_get_decent_index ( eid ) :
 i1iiii = eid . print_prefix ( )
 IIi1ii1 = hmac . new ( b"lisp-decent" , i1iiii , hashlib . sha256 ) . hexdigest ( )
 if 15 - 15: Ii1I - I11i % II111iiii % OoooooooOO * OoooooooOO
 if 100 - 100: OoOoOO00 / o0oOOo0O0Ooo / O0 / OoO0O00
 if 23 - 23: Ii1I + i11iIiiIii % IiII
 if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
 i1IIii1IiiIiI1i = os . getenv ( "LISP_DECENT_HASH_WIDTH" )
 if ( i1IIii1IiiIiI1i in [ "" , None ] ) :
  i1IIii1IiiIiI1i = 12
 else :
  i1IIii1IiiIiI1i = int ( i1IIii1IiiIiI1i )
  if ( i1IIii1IiiIiI1i > 32 ) :
   i1IIii1IiiIiI1i = 12
  else :
   i1IIii1IiiIiI1i *= 2
   if 76 - 76: I1ii11iIi11i
   if 68 - 68: iII111i + I11i
   if 61 - 61: oO0o . I1Ii111
 OoOOO0o0OOO00O = IIi1ii1 [ 0 : i1IIii1IiiIiI1i ]
 OOOooo0OooOoO = int ( OoOOO0o0OOO00O , 16 ) % lisp_decent_modulus
 if 17 - 17: I1Ii111 % I1Ii111 * o0oOOo0O0Ooo
 lprint ( "LISP-Decent modulus {}, hash-width {}, mod-value {}, index {}" . format ( lisp_decent_modulus , old_div ( i1IIii1IiiIiI1i , 2 ) , OoOOO0o0OOO00O , OOOooo0OooOoO ) )
 if 84 - 84: I1Ii111 + iII111i . i1IIi / O0 / I1Ii111 + o0oOOo0O0Ooo
 if 70 - 70: O0 % ooOoO0o - iII111i + oO0o
 return ( OOOooo0OooOoO )
 if 12 - 12: I1Ii111 - OoO0O00 % II111iiii % ooOoO0o / II111iiii % OoOoOO00
 if 74 - 74: iII111i . OOooOOo * Ii1I / Oo0Ooo . OoO0O00 . I11i
 if 65 - 65: i11iIiiIii - OoO0O00 / OoooooooOO * I1IiiI % iII111i
 if 15 - 15: OOooOOo * Ii1I / ooOoO0o
 if 70 - 70: i11iIiiIii * oO0o . I11i - OoooooooOO / I1ii11iIi11i
 if 10 - 10: IiII * OoOoOO00 . II111iiii . II111iiii * Oo0Ooo
 if 23 - 23: I1ii11iIi11i + I11i
def lisp_get_decent_dns_name ( eid ) :
 OOOooo0OooOoO = lisp_get_decent_index ( eid )
 return ( str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix )
 if 74 - 74: i1IIi % I1IiiI
 if 44 - 44: Oo0Ooo - OoooooooOO % ooOoO0o + II111iiii
 if 60 - 60: o0oOOo0O0Ooo - ooOoO0o + i11iIiiIii % I1ii11iIi11i % II111iiii
 if 62 - 62: Ii1I
 if 30 - 30: iII111i % O0 + II111iiii * I1IiiI
 if 91 - 91: i11iIiiIii
 if 35 - 35: OoOoOO00 * I1Ii111 / Oo0Ooo - i1IIi - IiII + OOooOOo
 if 96 - 96: Oo0Ooo + I1ii11iIi11i . O0
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 oo0oO = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 OOOooo0OooOoO = lisp_get_decent_index ( oo0oO )
 return ( str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix )
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
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 37 - 37: iIii1I11I1II1 * O0
 oo00 = 28 if packet . inner_version == 4 else 48
 O0Oo0O00O = packet . packet [ oo00 : : ]
 I11III1i111 = lisp_trace ( )
 if ( I11III1i111 . decode ( O0Oo0O00O ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
  if 27 - 27: OoOoOO00 . I11i / OoOoOO00
 oOo0OOoOO = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 92 - 92: oO0o % OoO0O00 . i1IIi
 if 84 - 84: Oo0Ooo + OoOoOO00 / OoooooooOO
 if 32 - 32: iIii1I11I1II1 / i1IIi % Oo0Ooo + Ii1I . i11iIiiIii
 if 31 - 31: oO0o / O0 - II111iiii * I1ii11iIi11i
 if 91 - 91: o0oOOo0O0Ooo * I11i * II111iiii
 if 39 - 39: IiII % i1IIi % OoooooooOO - O0
 if ( oOo0OOoOO != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : oOo0OOoOO += ":{}" . format ( packet . encap_port )
  if 39 - 39: i11iIiiIii / Ii1I / ooOoO0o
  if 93 - 93: o0oOOo0O0Ooo - Oo0Ooo / oO0o / OoOoOO00
  if 75 - 75: o0oOOo0O0Ooo * ooOoO0o % Ii1I
  if 94 - 94: OoooooooOO + II111iiii / iIii1I11I1II1 * ooOoO0o
  if 85 - 85: ooOoO0o / IiII
 oo0O00OOOOO = { }
 oo0O00OOOOO [ "n" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 28 - 28: i11iIiiIii - OoOoOO00
 i1i1I1II1Ii = packet . outer_source
 if ( i1i1I1II1Ii . is_null ( ) ) : i1i1I1II1Ii = lisp_myrlocs [ 0 ]
 oo0O00OOOOO [ "sr" ] = i1i1I1II1Ii . print_address_no_iid ( )
 if 62 - 62: O0 / OoO0O00 / i1IIi * OoOoOO00 + Ii1I
 if 48 - 48: Ii1I % IiII + OoO0O00 . IiII
 if 42 - 42: Ii1I
 if 70 - 70: I11i
 if 82 - 82: O0
 if ( oo0O00OOOOO [ "n" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  oo0O00OOOOO [ "sr" ] += ":{}" . format ( packet . inner_sport )
  if 58 - 58: II111iiii . O0 - OoO0O00 - IiII
  if 4 - 4: i11iIiiIii + i11iIiiIii / O0
 oo0O00OOOOO [ "hn" ] = lisp_hostname
 III = ed [ 0 ] + "ts"
 oo0O00OOOOO [ III ] = lisp_get_timestamp ( )
 if 46 - 46: I11i % ooOoO0o - Ii1I
 if 25 - 25: O0 / i11iIiiIii . O0
 if 24 - 24: I1ii11iIi11i - i11iIiiIii / iII111i . Oo0Ooo / I1ii11iIi11i
 if 92 - 92: I11i % OoooooooOO
 if 14 - 14: i11iIiiIii * i11iIiiIii * OoOoOO00
 if 84 - 84: OOooOOo % I1Ii111 + I11i / I1IiiI . iII111i
 if ( oOo0OOoOO == "?" and oo0O00OOOOO [ "n" ] == "ETR" ) :
  oooOOoO0oo0 = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( oooOOoO0oo0 != None and len ( oooOOoO0oo0 . rloc_set ) >= 1 ) :
   oOo0OOoOO = oooOOoO0oo0 . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 78 - 78: oO0o . Oo0Ooo
   if 18 - 18: IiII
 oo0O00OOOOO [ "dr" ] = oOo0OOoOO
 if 35 - 35: OoooooooOO / i1IIi - OoO0O00 + Oo0Ooo - o0oOOo0O0Ooo
 if 100 - 100: II111iiii % i11iIiiIii % oO0o + O0
 if 46 - 46: OoO0O00 / I1IiiI - Oo0Ooo . o0oOOo0O0Ooo . Oo0Ooo % I11i
 if 43 - 43: IiII - O0 + I1Ii111 % OoooooooOO % OoO0O00 / I1Ii111
 if ( oOo0OOoOO == "?" and reason != None ) :
  oo0O00OOOOO [ "dr" ] += " ({})" . format ( reason )
  if 48 - 48: I1ii11iIi11i . i1IIi % i1IIi - iII111i * o0oOOo0O0Ooo + IiII
  if 45 - 45: II111iiii . II111iiii + I1IiiI / I1Ii111 . OoO0O00 - o0oOOo0O0Ooo
  if 20 - 20: ooOoO0o % oO0o
  if 28 - 28: i1IIi . II111iiii + O0 / O0 % OoOoOO00 + OOooOOo
  if 24 - 24: OoooooooOO
 if ( rloc_entry != None ) :
  oo0O00OOOOO [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  oo0O00OOOOO [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  oo0O00OOOOO [ "lats" ] = rloc_entry . recent_rloc_probe_latencies
  if 11 - 11: i11iIiiIii / iIii1I11I1II1 % ooOoO0o + OOooOOo
  if 73 - 73: OoOoOO00 + OoooooooOO + iIii1I11I1II1 + II111iiii * iIii1I11I1II1 - OoOoOO00
  if 71 - 71: O0 * OOooOOo . I1IiiI . I1Ii111 * I11i
  if 45 - 45: O0 . O0 . II111iiii * ooOoO0o
  if 2 - 2: OoO0O00 . o0oOOo0O0Ooo
  if 48 - 48: Ii1I
 I1IiiII1I1 = packet . inner_source . print_address ( )
 Ii1Ii11I = packet . inner_dest . print_address ( )
 if ( I11III1i111 . packet_json == [ ] ) :
  o0o = { }
  o0o [ "se" ] = I1IiiII1I1
  o0o [ "de" ] = Ii1Ii11I
  o0o [ "paths" ] = [ ]
  I11III1i111 . packet_json . append ( o0o )
  if 45 - 45: I1ii11iIi11i - I11i + Ii1I
  if 82 - 82: iII111i
  if 81 - 81: i1IIi % OOooOOo - OoO0O00 - Oo0Ooo
  if 19 - 19: i1IIi
  if 97 - 97: OoO0O00 + i11iIiiIii % I1IiiI * Ii1I
  if 89 - 89: IiII % i11iIiiIii + OoO0O00 . oO0o / I1IiiI . Ii1I
 for o0o in I11III1i111 . packet_json :
  if ( o0o [ "de" ] != Ii1Ii11I ) : continue
  o0o [ "paths" ] . append ( oo0O00OOOOO )
  break
  if 11 - 11: ooOoO0o - I1Ii111 - I11i + OoOoOO00
  if 20 - 20: I11i + O0
  if 27 - 27: Oo0Ooo
  if 12 - 12: I1ii11iIi11i . iII111i - iII111i - OOooOOo - iIii1I11I1II1
  if 50 - 50: I1IiiI - iIii1I11I1II1 . iII111i - Ii1I / I1Ii111 + iII111i
  if 46 - 46: OOooOOo + iII111i % Oo0Ooo * iII111i % OoooooooOO * IiII
  if 27 - 27: I1IiiI + I1IiiI + I1ii11iIi11i - oO0o * OOooOOo
  if 53 - 53: I1ii11iIi11i / OoooooooOO * iIii1I11I1II1
 IiIii1iI1II11 = False
 if ( len ( I11III1i111 . packet_json ) == 1 and oo0O00OOOOO [ "n" ] == "ETR" and
 I11III1i111 . myeid ( packet . inner_dest ) ) :
  o0o = { }
  o0o [ "se" ] = Ii1Ii11I
  o0o [ "de" ] = I1IiiII1I1
  o0o [ "paths" ] = [ ]
  I11III1i111 . packet_json . append ( o0o )
  IiIii1iI1II11 = True
  if 9 - 9: OoO0O00
  if 89 - 89: I1IiiI - II111iiii . Ii1I
  if 42 - 42: iIii1I11I1II1 * iII111i * I1IiiI
  if 66 - 66: Oo0Ooo * i1IIi / I1ii11iIi11i / OoO0O00
  if 12 - 12: OOooOOo + iIii1I11I1II1 % I1Ii111 + OOooOOo
  if 19 - 19: OoO0O00 / I1IiiI - o0oOOo0O0Ooo - i1IIi + I1ii11iIi11i * OoooooooOO
 I11III1i111 . print_trace ( )
 O0Oo0O00O = I11III1i111 . encode ( )
 if 74 - 74: I1Ii111 . I11i / Oo0Ooo
 if 88 - 88: oO0o % OoO0O00 - i11iIiiIii % I1Ii111 / O0 * IiII
 if 99 - 99: o0oOOo0O0Ooo . ooOoO0o / i11iIiiIii
 if 44 - 44: IiII + OOooOOo % OoO0O00 . OoooooooOO * O0
 if 72 - 72: i1IIi - iII111i * I1IiiI % O0 - I11i * O0
 if 78 - 78: I1IiiI - OoO0O00 / Ii1I . i1IIi
 if 30 - 30: IiII
 if 21 - 21: i1IIi . iII111i - I1IiiI
 I1I1 = I11III1i111 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "sr" ]
 if ( oOo0OOoOO == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( I1I1 ) )
  I11III1i111 . return_to_sender ( lisp_socket , I1I1 , O0Oo0O00O )
  return ( False )
  if 60 - 60: oO0o + OoO0O00
  if 100 - 100: OoO0O00 / Ii1I - oO0o * OoooooooOO
  if 67 - 67: OoOoOO00 / I11i / O0
  if 9 - 9: II111iiii
  if 19 - 19: O0 * Ii1I . i1IIi - Oo0Ooo - i11iIiiIii / O0
  if 15 - 15: Ii1I . Oo0Ooo
 Ooo000O00 = I11III1i111 . packet_length ( )
 if 71 - 71: i1IIi / I1IiiI % I11i - I11i
 if 37 - 37: i11iIiiIii * OoOoOO00 * Oo0Ooo * I1IiiI / II111iiii
 if 100 - 100: I1Ii111
 if 23 - 23: Ii1I
 if 74 - 74: OoooooooOO % I1Ii111 + OoO0O00 * i11iIiiIii - I11i - I1ii11iIi11i
 if 98 - 98: Ii1I - Oo0Ooo - o0oOOo0O0Ooo
 IiiIIii = packet . packet [ 0 : oo00 ]
 iIIiiIi = struct . pack ( "HH" , socket . htons ( Ooo000O00 ) , 0 )
 IiiIIii = IiiIIii [ 0 : oo00 - 4 ] + iIIiiIi
 if ( packet . inner_version == 6 and oo0O00OOOOO [ "n" ] == "ETR" and
 len ( I11III1i111 . packet_json ) == 2 ) :
  O0I1II1 = IiiIIii [ oo00 - 8 : : ] + O0Oo0O00O
  O0I1II1 = lisp_udp_checksum ( I1IiiII1I1 , Ii1Ii11I , O0I1II1 )
  IiiIIii = IiiIIii [ 0 : oo00 - 8 ] + O0I1II1 [ 0 : 8 ]
  if 85 - 85: OoooooooOO - Ii1I + II111iiii . O0
  if 46 - 46: iII111i / I1ii11iIi11i / I1ii11iIi11i * Oo0Ooo . oO0o + I11i
  if 50 - 50: I1ii11iIi11i % O0
  if 20 - 20: OOooOOo * I1Ii111 + OoOoOO00
  if 64 - 64: oO0o
  if 77 - 77: oO0o / oO0o + O0 % ooOoO0o
  if 84 - 84: OoO0O00 - o0oOOo0O0Ooo
  if 57 - 57: I11i - i1IIi - II111iiii - O0 . iII111i + OoO0O00
  if 67 - 67: OOooOOo * iII111i / iIii1I11I1II1 / I1ii11iIi11i
 if ( IiIii1iI1II11 ) :
  if ( packet . inner_version == 4 ) :
   IiiIIii = IiiIIii [ 0 : 12 ] + IiiIIii [ 16 : 20 ] + IiiIIii [ 12 : 16 ] + IiiIIii [ 22 : 24 ] + IiiIIii [ 20 : 22 ] + IiiIIii [ 24 : : ]
   if 10 - 10: OoooooooOO % I1ii11iIi11i * i1IIi . iII111i
  else :
   IiiIIii = IiiIIii [ 0 : 8 ] + IiiIIii [ 24 : 40 ] + IiiIIii [ 8 : 24 ] + IiiIIii [ 42 : 44 ] + IiiIIii [ 40 : 42 ] + IiiIIii [ 44 : : ]
   if 96 - 96: II111iiii % i11iIiiIii - Oo0Ooo
   if 70 - 70: O0 * iIii1I11I1II1 - IiII * I11i / Ii1I + i11iIiiIii
  IiI11I111 = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = IiI11I111
  if 26 - 26: II111iiii - I11i % I11i / ooOoO0o + Oo0Ooo
  if 91 - 91: I1IiiI % Ii1I - OOooOOo - Oo0Ooo / I1IiiI / OoO0O00
  if 40 - 40: OoooooooOO
  if 71 - 71: OOooOOo
  if 88 - 88: O0
  if 44 - 44: II111iiii - IiII / I1IiiI + ooOoO0o % iII111i - iII111i
  if 53 - 53: OoooooooOO
 oo00 = 2 if packet . inner_version == 4 else 4
 iiIIi11ii = 20 + Ooo000O00 if packet . inner_version == 4 else Ooo000O00
 I1111I1 = struct . pack ( "H" , socket . htons ( iiIIi11ii ) )
 IiiIIii = IiiIIii [ 0 : oo00 ] + I1111I1 + IiiIIii [ oo00 + 2 : : ]
 if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
 if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
 if 77 - 77: i1IIi
 if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
 if ( packet . inner_version == 4 ) :
  I1i11i = struct . pack ( "H" , 0 )
  IiiIIii = IiiIIii [ 0 : 10 ] + I1i11i + IiiIIii [ 12 : : ]
  I1111I1 = lisp_ip_checksum ( IiiIIii [ 0 : 20 ] )
  IiiIIii = I1111I1 + IiiIIii [ 20 : : ]
  if 65 - 65: O0 / OoOoOO00
  if 77 - 77: OoO0O00
  if 17 - 17: i1IIi
  if 35 - 35: OoOoOO00
  if 61 - 61: I1Ii111
 packet . packet = IiiIIii + O0Oo0O00O
 return ( True )
 if 78 - 78: I1Ii111 * Ii1I % Ii1I + I1IiiI
 if 83 - 83: iIii1I11I1II1 + O0 / IiII . iIii1I11I1II1
 if 74 - 74: Oo0Ooo
 if 60 - 60: OoooooooOO
 if 16 - 16: iIii1I11I1II1 - OoOoOO00 / I1ii11iIi11i % O0 % o0oOOo0O0Ooo
 if 99 - 99: ooOoO0o . o0oOOo0O0Ooo - O0 * I1Ii111 . i11iIiiIii / iIii1I11I1II1
 if 40 - 40: iIii1I11I1II1 + oO0o / iIii1I11I1II1 - i1IIi % OoO0O00
 if 22 - 22: OOooOOo
 if 65 - 65: i1IIi - oO0o . I1Ii111 . ooOoO0o % I1ii11iIi11i % I1ii11iIi11i
 if 1 - 1: I1Ii111 + I1Ii111
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 96 - 96: iII111i + OoOoOO00 - o0oOOo0O0Ooo + Ii1I
 for oo0O00OOOOO in lisp_glean_mappings :
  if ( "instance-id" in oo0O00OOOOO ) :
   oooo = eid . instance_id
   OooOOoO0o0 , OO0I11iI = oo0O00OOOOO [ "instance-id" ]
   if ( oooo < OooOOoO0o0 or oooo > OO0I11iI ) : continue
   if 6 - 6: O0 . I11i
  if ( "eid-prefix" in oo0O00OOOOO ) :
   oO0ooOOO = copy . deepcopy ( oo0O00OOOOO [ "eid-prefix" ] )
   oO0ooOOO . instance_id = eid . instance_id
   if ( eid . is_more_specific ( oO0ooOOO ) == False ) : continue
   if 22 - 22: Oo0Ooo . O0 / i1IIi - OoOoOO00
  if ( "group-prefix" in oo0O00OOOOO ) :
   if ( group == None ) : continue
   Oo = copy . deepcopy ( oo0O00OOOOO [ "group-prefix" ] )
   Oo . instance_id = group . instance_id
   if ( group . is_more_specific ( Oo ) == False ) : continue
   if 41 - 41: II111iiii - I1ii11iIi11i - I1Ii111
  if ( "rloc-prefix" in oo0O00OOOOO ) :
   if ( rloc != None and rloc . is_more_specific ( oo0O00OOOOO [ "rloc-prefix" ] )
 == False ) : continue
   if 82 - 82: I1IiiI * I1IiiI / iIii1I11I1II1
  return ( True , oo0O00OOOOO [ "rloc-probe" ] , oo0O00OOOOO [ "igmp-query" ] )
  if 14 - 14: I11i + Ii1I - OOooOOo % Ii1I / Ii1I
 return ( False , False , False )
 if 86 - 86: I1Ii111 - i11iIiiIii + Ii1I + I11i
 if 96 - 96: Ii1I
 if 28 - 28: i1IIi . oO0o . IiII + Oo0Ooo . Oo0Ooo . i1IIi
 if 34 - 34: Oo0Ooo + IiII / i1IIi
 if 33 - 33: i1IIi
 if 26 - 26: ooOoO0o - Oo0Ooo * II111iiii - Oo0Ooo
 if 15 - 15: OoO0O00 - oO0o . OoOoOO00 / O0 * oO0o
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 IIiI11I1I1i1i = geid . print_address ( )
 i1O000O0O0oO0O = seid . print_address_no_iid ( )
 I111 = green ( "{}" . format ( i1O000O0O0oO0O ) , False )
 oO0ooOOO = green ( "(*, {})" . format ( IIiI11I1I1i1i ) , False )
 iiiI1I = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 21 - 21: I1Ii111 % Ii1I
 if 61 - 61: I1Ii111 - iII111i + IiII . i11iIiiIii + OOooOOo + i11iIiiIii
 if 74 - 74: ooOoO0o
 if 55 - 55: II111iiii
 iIIiiiiI11i = lisp_map_cache_lookup ( seid , geid )
 if ( iIIiiiiI11i == None ) :
  iIIiiiiI11i = lisp_mapping ( "" , "" , [ ] )
  iIIiiiiI11i . group . copy_address ( geid )
  iIIiiiiI11i . eid . copy_address ( geid )
  iIIiiiiI11i . eid . address = 0
  iIIiiiiI11i . eid . mask_len = 0
  iIIiiiiI11i . mapping_source . copy_address ( rloc )
  iIIiiiiI11i . map_cache_ttl = LISP_IGMP_TTL
  iIIiiiiI11i . gleaned = True
  iIIiiiiI11i . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( oO0ooOOO ) )
  if 7 - 7: I1Ii111 % o0oOOo0O0Ooo . oO0o . ooOoO0o % i1IIi / I1IiiI
  if 88 - 88: i11iIiiIii / oO0o - i1IIi / I1IiiI
  if 57 - 57: oO0o + O0 * I11i
  if 87 - 87: o0oOOo0O0Ooo % Oo0Ooo * I1ii11iIi11i / OoooooooOO / o0oOOo0O0Ooo
  if 78 - 78: Ii1I
  if 5 - 5: i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
 iiIiIIi1I = o0OOOO0OOOOO = oO0oOOOO0oO0o0 = None
 if ( iIIiiiiI11i . rloc_set != [ ] ) :
  iiIiIIi1I = iIIiiiiI11i . rloc_set [ 0 ]
  if ( iiIiIIi1I . rle ) :
   o0OOOO0OOOOO = iiIiIIi1I . rle
   for oOOOo00ooo in o0OOOO0OOOOO . rle_nodes :
    if ( oOOOo00ooo . rloc_name != i1O000O0O0oO0O ) : continue
    oO0oOOOO0oO0o0 = oOOOo00ooo
    break
    if 49 - 49: I1ii11iIi11i - I1Ii111 % i11iIiiIii / OOooOOo
    if 94 - 94: OOooOOo
    if 65 - 65: i11iIiiIii + oO0o . O0
    if 39 - 39: O0 - ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo / IiII * O0
    if 5 - 5: ooOoO0o / ooOoO0o * OoooooooOO
    if 41 - 41: oO0o
    if 77 - 77: OOooOOo * OoOoOO00
 if ( iiIiIIi1I == None ) :
  iiIiIIi1I = lisp_rloc ( )
  iIIiiiiI11i . rloc_set = [ iiIiIIi1I ]
  iiIiIIi1I . priority = 253
  iiIiIIi1I . mpriority = 255
  iIIiiiiI11i . build_best_rloc_set ( )
  if 75 - 75: Oo0Ooo * Oo0Ooo - IiII - OoOoOO00 / i11iIiiIii + I1Ii111
 if ( o0OOOO0OOOOO == None ) :
  o0OOOO0OOOOO = lisp_rle ( geid . print_address ( ) )
  iiIiIIi1I . rle = o0OOOO0OOOOO
  if 57 - 57: i11iIiiIii / oO0o
 if ( oO0oOOOO0oO0o0 == None ) :
  oO0oOOOO0oO0o0 = lisp_rle_node ( )
  oO0oOOOO0oO0o0 . rloc_name = i1O000O0O0oO0O
  o0OOOO0OOOOO . rle_nodes . append ( oO0oOOOO0oO0o0 )
  o0OOOO0OOOOO . build_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( iiiI1I , I111 , oO0ooOOO ) )
 elif ( rloc . is_exact_match ( oO0oOOOO0oO0o0 . address ) == False or
 port != oO0oOOOO0oO0o0 . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( iiiI1I , I111 , oO0ooOOO ) )
  if 37 - 37: o0oOOo0O0Ooo + OoOoOO00 - i1IIi . Oo0Ooo
  if 3 - 3: ooOoO0o % OoooooooOO / I1Ii111 + oO0o - O0
  if 72 - 72: oO0o * OoO0O00
  if 89 - 89: OoooooooOO . OOooOOo
  if 96 - 96: o0oOOo0O0Ooo + OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo * i11iIiiIii + OOooOOo
 oO0oOOOO0oO0o0 . store_translated_rloc ( rloc , port )
 if 16 - 16: IiII / I1Ii111 . II111iiii * I11i
 if 33 - 33: I1ii11iIi11i / Oo0Ooo % i11iIiiIii
 if 37 - 37: Oo0Ooo - I1Ii111 - IiII / oO0o % I1IiiI / I1Ii111
 if 80 - 80: iII111i - oO0o % i1IIi * iIii1I11I1II1 . oO0o
 if 86 - 86: Ii1I
 if ( igmp ) :
  O00oOoo0OoOOO = seid . print_address ( )
  if ( O00oOoo0OoOOO not in lisp_gleaned_groups ) :
   lisp_gleaned_groups [ O00oOoo0OoOOO ] = { }
   if 36 - 36: i11iIiiIii % i11iIiiIii
  lisp_gleaned_groups [ O00oOoo0OoOOO ] [ IIiI11I1I1i1i ] = lisp_get_timestamp ( )
  if 91 - 91: Oo0Ooo + I1Ii111 % iII111i
  if 7 - 7: I1Ii111 + II111iiii
  if 63 - 63: OoO0O00 - o0oOOo0O0Ooo / iII111i % II111iiii * IiII
  if 71 - 71: IiII
  if 34 - 34: II111iiii
  if 7 - 7: IiII / I1ii11iIi11i
  if 88 - 88: iIii1I11I1II1 / o0oOOo0O0Ooo
  if 68 - 68: OoooooooOO % Ii1I + ooOoO0o / oO0o
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 60 - 60: i11iIiiIii / O0 / I1IiiI
 if 99 - 99: I1IiiI / oO0o . OoO0O00 / ooOoO0o + IiII
 if 3 - 3: II111iiii . OOooOOo * i11iIiiIii / I11i
 if 16 - 16: I1ii11iIi11i - ooOoO0o + OoO0O00 . I11i / O0
 iIIiiiiI11i = lisp_map_cache_lookup ( seid , geid )
 if ( iIIiiiiI11i == None ) : return
 if 56 - 56: I1IiiI + Oo0Ooo * II111iiii + iIii1I11I1II1
 ooo0o0O = iIIiiiiI11i . rloc_set [ 0 ] . rle
 if ( ooo0o0O == None ) : return
 if 56 - 56: o0oOOo0O0Ooo * I1IiiI - I11i * I1Ii111 - I11i
 i1Ii1iiI = seid . print_address_no_iid ( )
 OO0o0oo0oOo = False
 for oO0oOOOO0oO0o0 in ooo0o0O . rle_nodes :
  if ( oO0oOOOO0oO0o0 . rloc_name == i1Ii1iiI ) :
   OO0o0oo0oOo = True
   break
   if 92 - 92: oO0o % iIii1I11I1II1 * o0oOOo0O0Ooo * OoooooooOO - iIii1I11I1II1
   if 51 - 51: Ii1I - OoO0O00 + i1IIi
 if ( OO0o0oo0oOo == False ) : return
 if 11 - 11: II111iiii - iII111i + oO0o % Oo0Ooo
 if 56 - 56: IiII
 if 72 - 72: Oo0Ooo
 if 37 - 37: i11iIiiIii * I1IiiI % ooOoO0o
 ooo0o0O . rle_nodes . remove ( oO0oOOOO0oO0o0 )
 ooo0o0O . build_forwarding_list ( )
 if 23 - 23: OoO0O00 + o0oOOo0O0Ooo * I1IiiI
 IIiI11I1I1i1i = geid . print_address ( )
 O00oOoo0OoOOO = seid . print_address ( )
 I111 = green ( "{}" . format ( O00oOoo0OoOOO ) , False )
 oO0ooOOO = green ( "(*, {})" . format ( IIiI11I1I1i1i ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( oO0ooOOO , I111 ) )
 if 76 - 76: i1IIi . OOooOOo
 if 78 - 78: OoooooooOO % OoOoOO00 * oO0o . I1ii11iIi11i
 if 79 - 79: OoooooooOO
 if 6 - 6: i11iIiiIii / II111iiii + II111iiii + I1ii11iIi11i % IiII - I1ii11iIi11i
 if ( O00oOoo0OoOOO in lisp_gleaned_groups ) :
  if ( IIiI11I1I1i1i in lisp_gleaned_groups [ O00oOoo0OoOOO ] ) :
   lisp_gleaned_groups [ O00oOoo0OoOOO ] . pop ( IIiI11I1I1i1i )
   if 92 - 92: IiII
   if 49 - 49: O0 . OoOoOO00
   if 7 - 7: i1IIi + II111iiii
   if 96 - 96: I1Ii111 / OoO0O00
   if 27 - 27: Ii1I
   if 90 - 90: I1ii11iIi11i
 if ( ooo0o0O . rle_nodes == [ ] ) :
  iIIiiiiI11i . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( oO0ooOOO ) )
  if 43 - 43: OoO0O00 . I1IiiI . oO0o + Ii1I
  if 7 - 7: iII111i / Oo0Ooo - OoO0O00 + I1Ii111 * II111iiii * ooOoO0o
  if 80 - 80: oO0o - i1IIi / I11i . II111iiii % O0 % I11i
  if 70 - 70: iIii1I11I1II1 * i1IIi * OOooOOo - Oo0Ooo % i1IIi
  if 60 - 60: o0oOOo0O0Ooo . OOooOOo % II111iiii - I1ii11iIi11i
  if 4 - 4: OOooOOo % ooOoO0o
  if 39 - 39: Ii1I
  if 67 - 67: iIii1I11I1II1 - OOooOOo
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 O00oOoo0OoOOO = seid . print_address ( )
 if ( O00oOoo0OoOOO not in lisp_gleaned_groups ) : return
 if 47 - 47: OOooOOo - OOooOOo * I1Ii111
 for iiI in lisp_gleaned_groups [ O00oOoo0OoOOO ] :
  lisp_geid . store_address ( iiI )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
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
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 90 - 90: I1Ii111 . i11iIiiIii - iIii1I11I1II1 + I1Ii111
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 67 - 67: IiII - I1ii11iIi11i + ooOoO0o . iIii1I11I1II1 . IiII
def lisp_process_igmp_packet ( packet ) :
 O0oo0OoO0oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O0oo0OoO0oo . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 O0oo0OoO0oo = bold ( "from {}" . format ( O0oo0OoO0oo . print_address_no_iid ( ) ) , False )
 if 13 - 13: I1IiiI / i11iIiiIii % iIii1I11I1II1 - Oo0Ooo . i11iIiiIii + I1IiiI
 iiiI1I = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( iiiI1I , len ( packet ) , O0oo0OoO0oo ,
 lisp_format_packet ( packet ) ) )
 if 77 - 77: o0oOOo0O0Ooo / II111iiii + i11iIiiIii % Ii1I . iIii1I11I1II1
 if 66 - 66: iII111i / oO0o - OoO0O00 . Oo0Ooo
 if 31 - 31: IiII % O0
 if 46 - 46: iIii1I11I1II1 - OoooooooOO . oO0o % iIii1I11I1II1 / i1IIi + Ii1I
 iIii1Iiii1i = ( struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ] & 0x0f ) * 4
 if 17 - 17: Oo0Ooo + I1ii11iIi11i * i1IIi
 if 70 - 70: ooOoO0o + iIii1I11I1II1 - I11i - I1Ii111 % iII111i
 if 79 - 79: ooOoO0o + Oo0Ooo + i1IIi . I1IiiI + i1IIi % IiII
 if 41 - 41: i11iIiiIii
 Oo00oOO0 = packet [ iIii1Iiii1i : : ]
 ooi1Iiii1 = struct . unpack ( "B" , Oo00oOO0 [ 0 : 1 ] ) [ 0 ]
 if 15 - 15: iIii1I11I1II1 . I1ii11iIi11i - I1Ii111
 if 95 - 95: I1Ii111 - I11i - OoooooooOO * Ii1I
 if 78 - 78: iII111i
 if 44 - 44: oO0o / II111iiii
 if 97 - 97: O0
 iiI = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iiI . address = socket . ntohl ( struct . unpack ( "II" , Oo00oOO0 [ : 8 ] ) [ 1 ] )
 IIiI11I1I1i1i = iiI . print_address_no_iid ( )
 if 6 - 6: Ii1I % OoooooooOO % IiII / iIii1I11I1II1
 if ( ooi1Iiii1 == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( IIiI11I1I1i1i ) )
  return ( True )
  if 71 - 71: Ii1I % OoooooooOO / II111iiii . o0oOOo0O0Ooo
  if 7 - 7: IiII . ooOoO0o
 oo00iiI1IiI = ( ooi1Iiii1 in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( oo00iiI1IiI == False ) :
  I1i111Ii11i1 = "{} ({})" . format ( ooi1Iiii1 , igmp_types [ ooi1Iiii1 ] ) if ( ooi1Iiii1 in igmp_types ) else ooi1Iiii1
  if 39 - 39: oO0o . O0 + Oo0Ooo + Ii1I % IiII
  lprint ( "IGMP type {} not supported" . format ( I1i111Ii11i1 ) )
  return ( [ ] )
  if 89 - 89: oO0o / iII111i + OOooOOo
  if 27 - 27: Ii1I / o0oOOo0O0Ooo % I11i
 if ( len ( Oo00oOO0 ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 96 - 96: i11iIiiIii % O0
  if 11 - 11: II111iiii . i11iIiiIii % ooOoO0o * Ii1I * OoOoOO00 * OoooooooOO
  if 80 - 80: OoO0O00
  if 55 - 55: iIii1I11I1II1 % OoO0O00 / II111iiii - OoO0O00
  if 95 - 95: o0oOOo0O0Ooo / OOooOOo * OOooOOo * O0
 if ( ooi1Iiii1 == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( IIiI11I1I1i1i , False ) ) )
  return ( [ [ None , IIiI11I1I1i1i , False ] ] )
  if 93 - 93: OOooOOo / ooOoO0o
 if ( ooi1Iiii1 in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( ooi1Iiii1 == 0x12 ) else 2 , bold ( IIiI11I1I1i1i , False ) ) )
  if 89 - 89: OoooooooOO + iIii1I11I1II1 / I1ii11iIi11i % iIii1I11I1II1 / iII111i
  if 74 - 74: Ii1I + I1IiiI * iII111i / i11iIiiIii - ooOoO0o * OoooooooOO
  if 98 - 98: I1IiiI
  if 85 - 85: OoooooooOO * i1IIi * O0 * OoooooooOO . IiII
  if 22 - 22: ooOoO0o
  if ( IIiI11I1I1i1i . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , IIiI11I1I1i1i , True ] ] )
   if 44 - 44: I1ii11iIi11i + IiII + IiII * I1ii11iIi11i - OoooooooOO / I1Ii111
   if 3 - 3: I1ii11iIi11i + o0oOOo0O0Ooo * I11i / Oo0Ooo
   if 31 - 31: i11iIiiIii % OoO0O00 - oO0o / o0oOOo0O0Ooo % O0
   if 53 - 53: iIii1I11I1II1 * I1ii11iIi11i
   if 46 - 46: OOooOOo % OoOoOO00 * iII111i
  return ( [ ] )
  if 55 - 55: I1IiiI * iIii1I11I1II1 . OoOoOO00
  if 82 - 82: iIii1I11I1II1 - iII111i % I1IiiI + I1IiiI * i1IIi % O0
  if 63 - 63: I1IiiI + OoOoOO00
  if 55 - 55: o0oOOo0O0Ooo
  if 95 - 95: OoO0O00 * ooOoO0o * oO0o % Oo0Ooo
 OoIiII = iiI . address
 Oo00oOO0 = Oo00oOO0 [ 8 : : ]
 if 36 - 36: I1IiiI - Ii1I + oO0o . iIii1I11I1II1
 ii1iiI1iIi1 = "BBHI"
 OOOo00OoO0O0o = struct . calcsize ( ii1iiI1iIi1 )
 i1I11iIii11i1 = "I"
 iIoOooO000oO = struct . calcsize ( i1I11iIii11i1 )
 O0oo0OoO0oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 11 - 11: o0oOOo0O0Ooo - iII111i . oO0o
 if 83 - 83: i1IIi * OOooOOo
 if 92 - 92: I1IiiI - OoooooooOO % Oo0Ooo
 if 2 - 2: II111iiii - iII111i . I1ii11iIi11i . iIii1I11I1II1 + II111iiii
 oOOoOOoOo0o = [ ]
 for iIi1iIIIiIiI in range ( OoIiII ) :
  if ( len ( Oo00oOO0 ) < OOOo00OoO0O0o ) : return
  o0oIIi1i , I1iIiiI1IIi1 , oo0Ii , I1IIIi = struct . unpack ( ii1iiI1iIi1 ,
 Oo00oOO0 [ : OOOo00OoO0O0o ] )
  if 45 - 45: OoO0O00 + Ii1I
  Oo00oOO0 = Oo00oOO0 [ OOOo00OoO0O0o : : ]
  if 90 - 90: O0 * i1IIi . i1IIi * I1ii11iIi11i + I1ii11iIi11i / i1IIi
  if ( o0oIIi1i not in lisp_igmp_record_types ) :
   lprint ( "Invalid record type {}" . format ( o0oIIi1i ) )
   continue
   if 52 - 52: O0 / iIii1I11I1II1 * IiII
   if 50 - 50: oO0o . Ii1I . OoooooooOO * o0oOOo0O0Ooo
  iI11111ii1 = lisp_igmp_record_types [ o0oIIi1i ]
  oo0Ii = socket . ntohs ( oo0Ii )
  iiI . address = socket . ntohl ( I1IIIi )
  IIiI11I1I1i1i = iiI . print_address_no_iid ( )
  if 55 - 55: I1Ii111 - OOooOOo - OoO0O00 . oO0o
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( iI11111ii1 , IIiI11I1I1i1i , oo0Ii ) )
  if 23 - 23: iII111i + OOooOOo
  if 39 - 39: oO0o * O0
  if 22 - 22: OoOoOO00 . i11iIiiIii
  if 86 - 86: iIii1I11I1II1 / iIii1I11I1II1 + iIii1I11I1II1 . OoO0O00 * iII111i * I1ii11iIi11i
  if 32 - 32: I1ii11iIi11i - OoO0O00
  if 63 - 63: o0oOOo0O0Ooo . ooOoO0o
  if 37 - 37: OoO0O00
  ooO0OO00OOo = False
  if ( o0oIIi1i in ( 1 , 5 ) ) : ooO0OO00OOo = True
  if ( o0oIIi1i in ( 2 , 4 ) and oo0Ii == 0 ) : ooO0OO00OOo = True
  O00ooOo = "join" if ( ooO0OO00OOo ) else "leave"
  if 79 - 79: iIii1I11I1II1 / I11i % i11iIiiIii + OOooOOo . OoOoOO00
  if 93 - 93: OOooOOo % I1ii11iIi11i % IiII
  if 28 - 28: I1Ii111 % oO0o % OOooOOo
  if 19 - 19: OoO0O00 - iII111i
  if ( IIiI11I1I1i1i . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 76 - 76: OoOoOO00 * ooOoO0o - iII111i * I1IiiI + I11i
   if 4 - 4: Oo0Ooo
   if 95 - 95: Oo0Ooo * i11iIiiIii - O0
   if 100 - 100: iIii1I11I1II1 / I1ii11iIi11i - o0oOOo0O0Ooo / iII111i
   if 73 - 73: OoooooooOO
   if 68 - 68: II111iiii / i11iIiiIii % i11iIiiIii % OoooooooOO
   if 81 - 81: i1IIi + O0 . IiII . I1IiiI / ooOoO0o
   if 75 - 75: I1ii11iIi11i / OoOoOO00
  if ( oo0Ii == 0 ) :
   oOOoOOoOo0o . append ( [ None , IIiI11I1I1i1i , ooO0OO00OOo ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( O00ooOo , False ) ,
 bold ( IIiI11I1I1i1i , False ) ) )
   if 59 - 59: OoO0O00 . OoooooooOO % IiII
   if 35 - 35: I1ii11iIi11i + I1Ii111
   if 25 - 25: iIii1I11I1II1 / I11i % OoooooooOO / Oo0Ooo
   if 4 - 4: i1IIi % i1IIi % oO0o
   if 51 - 51: o0oOOo0O0Ooo * i11iIiiIii
  for oooOO0oooo00 in range ( oo0Ii ) :
   if ( len ( Oo00oOO0 ) < iIoOooO000oO ) : return
   I1IIIi = struct . unpack ( i1I11iIii11i1 , Oo00oOO0 [ : iIoOooO000oO ] ) [ 0 ]
   O0oo0OoO0oo . address = socket . ntohl ( I1IIIi )
   IiIIiii11 = O0oo0OoO0oo . print_address_no_iid ( )
   oOOoOOoOo0o . append ( [ IiIIiii11 , IIiI11I1I1i1i , ooO0OO00OOo ] )
   lprint ( "{} ({}, {})" . format ( O00ooOo ,
 green ( IiIIiii11 , False ) , bold ( IIiI11I1I1i1i , False ) ) )
   Oo00oOO0 = Oo00oOO0 [ iIoOooO000oO : : ]
   if 17 - 17: OOooOOo - O0 . II111iiii - OoooooooOO + I1ii11iIi11i
   if 100 - 100: OoOoOO00 * OOooOOo % i11iIiiIii / OoOoOO00
   if 72 - 72: I1IiiI . oO0o
   if 76 - 76: Ii1I - Oo0Ooo * II111iiii
   if 17 - 17: I1Ii111 * O0
   if 8 - 8: i11iIiiIii / OoO0O00 / OOooOOo
   if 26 - 26: I1ii11iIi11i . Ii1I - iIii1I11I1II1 . Ii1I / Ii1I % I11i
   if 56 - 56: OOooOOo . I11i + O0 * oO0o - i11iIiiIii / i11iIiiIii
 return ( oOOoOOoOo0o )
 if 73 - 73: I1ii11iIi11i
 if 59 - 59: iII111i % iIii1I11I1II1 * OoOoOO00
 if 41 - 41: i1IIi * IiII - i11iIiiIii / O0 + Oo0Ooo + ooOoO0o
 if 94 - 94: OoO0O00 . O0 + iIii1I11I1II1 . oO0o % oO0o
 if 7 - 7: I1ii11iIi11i * oO0o / OoOoOO00
 if 89 - 89: OoO0O00 / oO0o % I11i - I1ii11iIi11i . o0oOOo0O0Ooo
 if 46 - 46: i11iIiiIii
 if 99 - 99: i11iIiiIii / oO0o / OoOoOO00 / O0 * I1ii11iIi11i
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 72 - 72: ooOoO0o - I1Ii111 - iIii1I11I1II1 . I1IiiI
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 77 - 77: Oo0Ooo * OoO0O00
 if 67 - 67: OoOoOO00 . I1Ii111 / I1IiiI * II111iiii
 if 45 - 45: I1ii11iIi11i * o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo
 if 58 - 58: OOooOOo + O0
 if 19 - 19: o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * OOooOOo - Ii1I * OoOoOO00 % OoO0O00 * O0
 oo000 = True
 iIIiiiiI11i = lisp_map_cache . lookup_cache ( seid , True )
 if ( iIIiiiiI11i and len ( iIIiiiiI11i . rloc_set ) != 0 ) :
  iIIiiiiI11i . last_refresh_time = lisp_get_timestamp ( )
  if 66 - 66: i11iIiiIii . OoooooooOO % OoO0O00 + i1IIi + I1Ii111
  I1IIiIii1 = iIIiiiiI11i . rloc_set [ 0 ]
  o0o0OOoooo = I1IIiIii1 . rloc
  o0OOoO = I1IIiIii1 . translated_port
  oo000 = ( o0o0OOoooo . is_exact_match ( rloc ) == False or
 o0OOoO != encap_port )
  if 11 - 11: O0
  if ( oo000 ) :
   oO0ooOOO = green ( seid . print_address ( ) , False )
   iiiI1I = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( oO0ooOOO , iiiI1I ) )
   I1IIiIii1 . delete_from_rloc_probe_list ( iIIiiiiI11i . eid , iIIiiiiI11i . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 9 - 9: II111iiii
 else :
  iIIiiiiI11i = lisp_mapping ( "" , "" , [ ] )
  iIIiiiiI11i . eid . copy_address ( seid )
  iIIiiiiI11i . mapping_source . copy_address ( rloc )
  iIIiiiiI11i . map_cache_ttl = LISP_GLEAN_TTL
  iIIiiiiI11i . gleaned = True
  oO0ooOOO = green ( seid . print_address ( ) , False )
  iiiI1I = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( oO0ooOOO , iiiI1I ) )
  iIIiiiiI11i . add_cache ( )
  if 52 - 52: I1Ii111 % I1IiiI - Oo0Ooo . i1IIi
  if 2 - 2: iII111i % OoOoOO00 * iIii1I11I1II1 * ooOoO0o - OoooooooOO - IiII
  if 40 - 40: OoO0O00 . i11iIiiIii + ooOoO0o
  if 30 - 30: OOooOOo . OoO0O00 % iII111i - OoO0O00 % i11iIiiIii
  if 28 - 28: Ii1I + Oo0Ooo / iIii1I11I1II1
 if ( oo000 ) :
  iiIiIIi1I = lisp_rloc ( )
  iiIiIIi1I . store_translated_rloc ( rloc , encap_port )
  iiIiIIi1I . add_to_rloc_probe_list ( iIIiiiiI11i . eid , iIIiiiiI11i . group )
  iiIiIIi1I . priority = 253
  iiIiIIi1I . mpriority = 255
  oOO000OOO = [ iiIiIIi1I ]
  iIIiiiiI11i . rloc_set = oOO000OOO
  iIIiiiiI11i . build_best_rloc_set ( )
  if 57 - 57: o0oOOo0O0Ooo
  if 23 - 23: II111iiii
  if 88 - 88: I1IiiI / II111iiii * i11iIiiIii - oO0o - OOooOOo
  if 41 - 41: iIii1I11I1II1
  if 7 - 7: Oo0Ooo + iII111i . ooOoO0o
 if ( igmp == None ) : return
 if 31 - 31: iIii1I11I1II1 - OoOoOO00 - II111iiii / I1ii11iIi11i
 if 70 - 70: iIii1I11I1II1 / I1ii11iIi11i . I1Ii111 % I1ii11iIi11i
 if 40 - 40: I1Ii111 + o0oOOo0O0Ooo - I11i + OoO0O00
 if 49 - 49: i11iIiiIii % OoO0O00 - Ii1I + I1Ii111
 if 7 - 7: ooOoO0o * I1ii11iIi11i - Ii1I % i1IIi + I11i
 lisp_geid . instance_id = seid . instance_id
 if 22 - 22: I1IiiI - OOooOOo - II111iiii * I1IiiI
 if 93 - 93: OOooOOo + I11i
 if 93 - 93: I1IiiI . I1ii11iIi11i * iII111i
 if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo + OoOoOO00
 if 76 - 76: Oo0Ooo * Oo0Ooo + o0oOOo0O0Ooo % I11i + Oo0Ooo / o0oOOo0O0Ooo
 Oo00o0oOO0oo = lisp_process_igmp_packet ( igmp )
 if ( type ( Oo00o0oOO0oo ) == bool ) : return
 if 76 - 76: OOooOOo . ooOoO0o * iII111i . oO0o
 for O0oo0OoO0oo , iiI , ooO0OO00OOo in Oo00o0oOO0oo :
  if ( O0oo0OoO0oo != None ) : continue
  if 80 - 80: i1IIi . Ii1I
  if 59 - 59: OOooOOo . I11i
  if 88 - 88: i11iIiiIii / I1ii11iIi11i . I11i % OOooOOo
  if 75 - 75: ooOoO0o - OOooOOo
  lisp_geid . store_address ( iiI )
  o00000o , I1iIiiI1IIi1 , II1ii1 = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( o00000o == False ) : continue
  if 97 - 97: i11iIiiIii / I11i % II111iiii
  if ( ooO0OO00OOo ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 20 - 20: I1Ii111 + OoooooooOO . o0oOOo0O0Ooo - ooOoO0o
   if 61 - 61: i11iIiiIii + OoooooooOO
   if 7 - 7: I1IiiI * OoO0O00 * I1IiiI
   if 50 - 50: I1ii11iIi11i
   if 88 - 88: IiII
   if 55 - 55: Oo0Ooo + OOooOOo + IiII
   if 55 - 55: O0 . I1Ii111 * I1ii11iIi11i * o0oOOo0O0Ooo - ooOoO0o
   if 17 - 17: OOooOOo
   if 66 - 66: O0 - i11iIiiIii * O0 / iII111i . I1Ii111 / IiII
   if 96 - 96: OoOoOO00 / i11iIiiIii - OoooooooOO / II111iiii * i1IIi
   if 82 - 82: iII111i
   if 55 - 55: OoOoOO00 + I1ii11iIi11i % ooOoO0o % I1Ii111 . i1IIi % OOooOOo
def lisp_is_json_telemetry ( json_string ) :
 try :
  IiI1i = json . loads ( json_string )
  if ( type ( IiI1i ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 21 - 21: OoO0O00 / Ii1I . IiII
  if 35 - 35: i1IIi
 if ( "type" not in IiI1i ) : return ( None )
 if ( "sub-type" not in IiI1i ) : return ( None )
 if ( IiI1i [ "type" ] != "telemetry" ) : return ( None )
 if ( IiI1i [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( IiI1i )
 if 58 - 58: Ii1I - IiII / ooOoO0o % o0oOOo0O0Ooo + I1ii11iIi11i
 if 89 - 89: IiII / OoooooooOO
 if 13 - 13: II111iiii . OOooOOo - O0 * oO0o
 if 71 - 71: ooOoO0o % ooOoO0o + o0oOOo0O0Ooo + iII111i / OoOoOO00
 if 27 - 27: I1ii11iIi11i * OoO0O00 - OoO0O00
 if 87 - 87: I1IiiI * I11i + iIii1I11I1II1 % i1IIi
 if 6 - 6: o0oOOo0O0Ooo
 if 94 - 94: I1ii11iIi11i * i11iIiiIii
 if 95 - 95: OoooooooOO - II111iiii . I1Ii111
 if 97 - 97: i1IIi * iIii1I11I1II1
 if 44 - 44: O0 - o0oOOo0O0Ooo - I1Ii111 % O0
 if 31 - 31: i11iIiiIii - I11i
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 IiI1i = lisp_is_json_telemetry ( json_string )
 if ( IiI1i == None ) : return ( json_string )
 if 91 - 91: I11i - iII111i
 if ( IiI1i [ "itr-in" ] == "?" ) : IiI1i [ "itr-in" ] = ii
 if ( IiI1i [ "itr-out" ] == "?" ) : IiI1i [ "itr-out" ] = io
 if ( IiI1i [ "etr-in" ] == "?" ) : IiI1i [ "etr-in" ] = ei
 if ( IiI1i [ "etr-out" ] == "?" ) : IiI1i [ "etr-out" ] = eo
 json_string = json . dumps ( IiI1i )
 return ( json_string )
 if 35 - 35: I1IiiI * I11i + I11i
 if 67 - 67: I1ii11iIi11i - I1IiiI + Ii1I * Ii1I + Oo0Ooo
 if 41 - 41: i11iIiiIii
 if 97 - 97: i1IIi / Ii1I / ooOoO0o . Ii1I - ooOoO0o + oO0o
 if 27 - 27: OOooOOo % O0
 if 96 - 96: OoooooooOO / OOooOOo
 if 87 - 87: IiII - OoooooooOO
 if 53 - 53: OoOoOO00 + Oo0Ooo
 if 33 - 33: I11i - OOooOOo + Oo0Ooo - iII111i * iII111i
 if 44 - 44: Oo0Ooo % OoOoOO00 / oO0o
 if 34 - 34: II111iiii + Ii1I + OoOoOO00
 if 9 - 9: I11i / oO0o * OoO0O00
def lisp_decode_telemetry ( json_string ) :
 IiI1i = lisp_is_json_telemetry ( json_string )
 if ( IiI1i == None ) : return ( { } )
 return ( IiI1i )
 if 26 - 26: I1IiiI % OOooOOo * OoOoOO00
 if 14 - 14: I11i * Oo0Ooo . I1Ii111 * Ii1I . i11iIiiIii * I1ii11iIi11i
 if 11 - 11: oO0o + oO0o + o0oOOo0O0Ooo / iIii1I11I1II1 / I11i
 if 68 - 68: OoooooooOO + i1IIi % I1ii11iIi11i . iII111i
 if 69 - 69: ooOoO0o * II111iiii + i11iIiiIii / oO0o + I1Ii111 - OOooOOo
 if 84 - 84: O0
 if 29 - 29: I11i + o0oOOo0O0Ooo . ooOoO0o * I1Ii111 - o0oOOo0O0Ooo * O0
 if 58 - 58: iII111i . oO0o + i11iIiiIii
 if 2 - 2: OOooOOo * Ii1I
def lisp_telemetry_configured ( ) :
 if ( "telemetry" not in lisp_json_list ) : return ( None )
 if 17 - 17: I1ii11iIi11i * O0 / OoOoOO00 + i1IIi
 o00O = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( o00O ) == None ) : return ( None )
 if 71 - 71: oO0o % IiII
 return ( o00O )
 if 77 - 77: i1IIi * o0oOOo0O0Ooo - Oo0Ooo / I1Ii111 - Ii1I * IiII
 if 51 - 51: OoO0O00 * IiII
 if 36 - 36: II111iiii + I11i - O0
 if 24 - 24: I1Ii111 / OoOoOO00
 if 10 - 10: I11i . OoO0O00 / O0 / oO0o / o0oOOo0O0Ooo / ooOoO0o
 if 30 - 30: Oo0Ooo
 if 93 - 93: II111iiii - I1IiiI
def lisp_mr_or_pubsub ( action ) :
 return ( action in [ LISP_SEND_MAP_REQUEST_ACTION , LISP_SEND_PUBSUB_ACTION ] )
 if 80 - 80: I11i . o0oOOo0O0Ooo % IiII - OoOoOO00 % OOooOOo / OoooooooOO
 if 57 - 57: OoooooooOO % o0oOOo0O0Ooo - iIii1I11I1II1 . OoooooooOO
 if 42 - 42: o0oOOo0O0Ooo % OoooooooOO * OoO0O00 - o0oOOo0O0Ooo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
