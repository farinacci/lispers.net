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
from builtins import chr
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
 if 100 - 100: I1IiiI / o0oOOo0O0Ooo * iII111i . O0 / OOooOOo
def debug ( * args ) :
 lisp_process_logfile ( )
 if 83 - 83: I1Ii111
 i1 = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 i1 = i1 [ : - 3 ]
 if 48 - 48: II111iiii * OOooOOo * I1Ii111
 print ( red ( ">>>" , False ) , end = " " )
 print ( "{}:" . format ( i1 ) , end = " " )
 for Ii1 in args : print ( Ii1 , end = " " )
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
  OOOooo0OooOoO = string . find ( Oo )
  if ( OOOooo0OooOoO != - 1 ) : break
  if 51 - 51: i11iIiiIii * o0oOOo0O0Ooo / I1IiiI
  if 40 - 40: I1IiiI
 while ( OOOooo0OooOoO != - 1 ) :
  I1I1 = string [ OOOooo0OooOoO : : ] . find ( o0 )
  O0oOoo0OoO0O = string [ OOOooo0OooOoO + IiI1ii1Ii : OOOooo0OooOoO + I1I1 ]
  string = string [ : OOOooo0OooOoO ] + IiIiIi1I1 ( O0oOoo0OoO0O , True ) + string [ OOOooo0OooOoO + I1I1 + IiI1ii1Ii : : ]
  if 63 - 63: OoooooooOO / ooOoO0o
  OOOooo0OooOoO = string . find ( Oo )
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
 i1oO00O = group . instance_id
 if 77 - 77: i11iIiiIii % i1IIi % IiII
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  OOOooo0OooOoO = iiiii1I1III1 . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( i1oO00O , iiiii1I1III1 [ OOOooo0OooOoO : : ] ) )
  if 15 - 15: iIii1I11I1II1 . O0
  if 70 - 70: Ii1I . i11iIiiIii % Ii1I . O0 - iIii1I11I1II1
 i111i1iIi1 = eid . print_sg ( group )
 return ( i111i1iIi1 )
 if 95 - 95: OoooooooOO + I11i - I1ii11iIi11i / I1ii11iIi11i . i1IIi . OoooooooOO
 if 29 - 29: ooOoO0o - i1IIi . I11i - I1ii11iIi11i + ooOoO0o + OoooooooOO
 if 36 - 36: i1IIi / ooOoO0o . iIii1I11I1II1
 if 12 - 12: Ii1I
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 oOOOo0o = addr_str . split ( ":" )
 return ( oOOOo0o [ - 1 ] )
 if 26 - 26: iIii1I11I1II1 - O0 . O0
 if 68 - 68: OOooOOo + oO0o . O0 . Ii1I % i1IIi % OOooOOo
 if 50 - 50: IiII + o0oOOo0O0Ooo
 if 96 - 96: OoO0O00
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if 87 - 87: OoOoOO00 % iIii1I11I1II1
 if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 if 48 - 48: Oo0Ooo - ooOoO0o + Oo0Ooo - I1IiiI * i11iIiiIii . iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
def lisp_convert_4to6 ( addr_str ) :
 oOOOo0o = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( oOOOo0o . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 oOOOo0o . store_address ( addr_str )
 return ( oOOOo0o )
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
 if 21 - 21: OoOoOO00 - OoooooooOO % i11iIiiIii
 if 71 - 71: i1IIi - I11i * I1Ii111 + oO0o - OoO0O00 % I1ii11iIi11i
 if 63 - 63: iIii1I11I1II1 + OOooOOo . OoO0O00 / I1IiiI
 if 84 - 84: i1IIi
 if 42 - 42: II111iiii - OoO0O00 - OoooooooOO . iII111i / OoOoOO00
def lisp_gethostbyname ( string ) :
 ooooo0Oo0 = string . split ( "." )
 o0I1IIIi11ii11 = string . split ( ":" )
 O0o0oo0oOO0oO = string . split ( "-" )
 if 15 - 15: OoO0O00 * II111iiii
 if ( len ( ooooo0Oo0 ) == 4 ) :
  if ( ooooo0Oo0 [ 0 ] . isdigit ( ) and ooooo0Oo0 [ 1 ] . isdigit ( ) and ooooo0Oo0 [ 2 ] . isdigit ( ) and
 ooooo0Oo0 [ 3 ] . isdigit ( ) ) : return ( string )
  if 59 - 59: I1Ii111 + OoO0O00 / OOooOOo
 if ( len ( o0I1IIIi11ii11 ) > 1 ) :
  try :
   int ( o0I1IIIi11ii11 [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 97 - 97: Oo0Ooo * iII111i % ooOoO0o . iII111i - I1Ii111 - OOooOOo
   if 79 - 79: I1IiiI - ooOoO0o
   if 37 - 37: IiII . Oo0Ooo * Oo0Ooo * II111iiii * O0
   if 83 - 83: IiII / I1Ii111
   if 64 - 64: OoO0O00 % IiII . I1Ii111 % OoO0O00 + I11i * IiII
   if 83 - 83: o0oOOo0O0Ooo % oO0o + I11i % i11iIiiIii + O0
   if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if ( len ( O0o0oo0oOO0oO ) == 3 ) :
  for OoOOoO0oOo in range ( 3 ) :
   try : int ( O0o0oo0oOO0oO [ OoOOoO0oOo ] , 16 )
   except : break
   if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
   if 80 - 80: OoooooooOO + IiII
   if 95 - 95: I1Ii111 / oO0o * I1Ii111 - OoooooooOO * OoooooooOO % OoO0O00
 try :
  oOOOo0o = socket . gethostbyname ( string )
  return ( oOOOo0o )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 43 - 43: Oo0Ooo . I1Ii111
  if 12 - 12: I1Ii111 + OOooOOo + I11i . IiII / Ii1I
  if 29 - 29: IiII . ooOoO0o - II111iiii
  if 68 - 68: iIii1I11I1II1 + II111iiii / oO0o
  if 91 - 91: OoOoOO00 % iIii1I11I1II1 . I1IiiI
 try :
  oOOOo0o = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( oOOOo0o [ 3 ] != string ) : return ( "" )
  oOOOo0o = oOOOo0o [ 4 ] [ 0 ]
 except :
  oOOOo0o = ""
  if 70 - 70: I11i % II111iiii % O0 . i1IIi / I1Ii111
 return ( oOOOo0o )
 if 100 - 100: I1ii11iIi11i * i11iIiiIii % oO0o / Oo0Ooo / ooOoO0o + I1ii11iIi11i
 if 59 - 59: I1Ii111 - IiII
 if 14 - 14: iIii1I11I1II1 - iIii1I11I1II1
 if 5 - 5: IiII
 if 84 - 84: II111iiii * oO0o * II111iiii % IiII / I1IiiI
 if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if 71 - 71: I1Ii111 * Oo0Ooo . I11i
 if 49 - 49: IiII * O0 . IiII
def lisp_ip_checksum ( data , hdrlen = 20 ) :
 if ( len ( data ) < hdrlen ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 19 - 19: II111iiii - IiII
  if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
 o0OO00oo0O = binascii . hexlify ( data )
 if 46 - 46: i11iIiiIii - OOooOOo * I1IiiI * I11i % I1ii11iIi11i * i1IIi
 if 5 - 5: O0 / ooOoO0o . Oo0Ooo + OoooooooOO
 if 97 - 97: IiII . Ii1I . Ii1I / iIii1I11I1II1 - OoO0O00 + iII111i
 if 32 - 32: OOooOOo . o0oOOo0O0Ooo % IiII + I1ii11iIi11i + OoO0O00
 OOOoOOo0o = 0
 for OoOOoO0oOo in range ( 0 , hdrlen * 2 , 4 ) :
  OOOoOOo0o += int ( o0OO00oo0O [ OoOOoO0oOo : OoOOoO0oOo + 4 ] , 16 )
  if 50 - 50: II111iiii - I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1
  if 91 - 91: II111iiii - O0 . iIii1I11I1II1 . O0 + I1ii11iIi11i - II111iiii
  if 26 - 26: o0oOOo0O0Ooo
  if 12 - 12: OoooooooOO / O0 + II111iiii * I1ii11iIi11i
  if 46 - 46: II111iiii - IiII * OoooooooOO / oO0o % IiII
 OOOoOOo0o = ( OOOoOOo0o >> 16 ) + ( OOOoOOo0o & 0xffff )
 OOOoOOo0o += OOOoOOo0o >> 16
 OOOoOOo0o = socket . htons ( ~ OOOoOOo0o & 0xffff )
 if 11 - 11: iIii1I11I1II1 . OoOoOO00 / IiII % ooOoO0o
 if 61 - 61: ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 OOOoOOo0o = struct . pack ( "H" , OOOoOOo0o )
 o0OO00oo0O = data [ 0 : 10 ] + OOOoOOo0o + data [ 12 : : ]
 return ( o0OO00oo0O )
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
 OOOoOOo0o = 0
 for OoOOoO0oOo in range ( 0 , 36 , 4 ) :
  OOOoOOo0o += int ( O0OO0ooO00 [ OoOOoO0oOo : OoOOoO0oOo + 4 ] , 16 )
  if 43 - 43: OoO0O00 % OoO0O00
  if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
  if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
  if 41 - 41: I1IiiI - I1Ii111 % II111iiii . I1Ii111 - I11i
  if 45 - 45: Ii1I - OOooOOo
 OOOoOOo0o = ( OOOoOOo0o >> 16 ) + ( OOOoOOo0o & 0xffff )
 OOOoOOo0o += OOOoOOo0o >> 16
 OOOoOOo0o = socket . htons ( ~ OOOoOOo0o & 0xffff )
 if 70 - 70: OoO0O00 % I1IiiI / I1IiiI . I11i % ooOoO0o . II111iiii
 if 10 - 10: Ii1I - i11iIiiIii . I1ii11iIi11i % i1IIi
 if 78 - 78: iIii1I11I1II1 * Oo0Ooo . Oo0Ooo - OOooOOo . iIii1I11I1II1
 if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
 OOOoOOo0o = struct . pack ( "H" , OOOoOOo0o )
 O0OO0ooO00 = data [ 0 : 2 ] + OOOoOOo0o + data [ 4 : : ]
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
 I1iiIi111I = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 iiIi = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 OooooOo = socket . htonl ( len ( data ) )
 IIIiiiIiI = socket . htonl ( LISP_UDP_PROTOCOL )
 OO0OOoooo0o = I1iiIi111I . pack_address ( )
 OO0OOoooo0o += iiIi . pack_address ( )
 OO0OOoooo0o += struct . pack ( "II" , OooooOo , IIIiiiIiI )
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 if 79 - 79: OoooooooOO / I1ii11iIi11i . O0
 if 79 - 79: oO0o - II111iiii
 Ii1iiI1 = binascii . hexlify ( OO0OOoooo0o + data )
 o0ooOOoO0oO0 = len ( Ii1iiI1 ) % 4
 for OoOOoO0oOo in range ( 0 , o0ooOOoO0oO0 ) : Ii1iiI1 += "0"
 if 86 - 86: i1IIi / Ii1I * I1IiiI
 if 67 - 67: I1ii11iIi11i * I1ii11iIi11i / oO0o * OoooooooOO + OoOoOO00
 if 79 - 79: i1IIi
 if 1 - 1: oO0o / i1IIi
 OOOoOOo0o = 0
 for OoOOoO0oOo in range ( 0 , len ( Ii1iiI1 ) , 4 ) :
  OOOoOOo0o += int ( Ii1iiI1 [ OoOOoO0oOo : OoOOoO0oOo + 4 ] , 16 )
  if 74 - 74: I11i / OoooooooOO / Oo0Ooo * i11iIiiIii . II111iiii . OoooooooOO
  if 59 - 59: i11iIiiIii . OoooooooOO / I11i * I1ii11iIi11i + OoooooooOO
  if 3 - 3: i11iIiiIii * Oo0Ooo % iIii1I11I1II1 % I1IiiI * iII111i / OOooOOo
  if 95 - 95: IiII * O0 * I1Ii111 . OoooooooOO % Oo0Ooo + I1ii11iIi11i
  if 98 - 98: oO0o . OoooooooOO
 OOOoOOo0o = ( OOOoOOo0o >> 16 ) + ( OOOoOOo0o & 0xffff )
 OOOoOOo0o += OOOoOOo0o >> 16
 OOOoOOo0o = socket . htons ( ~ OOOoOOo0o & 0xffff )
 if 54 - 54: O0 / IiII % ooOoO0o * i1IIi * O0
 if 48 - 48: o0oOOo0O0Ooo . oO0o % OoOoOO00 - OoOoOO00
 if 33 - 33: I11i % II111iiii + OoO0O00
 if 93 - 93: i1IIi . IiII / I1IiiI + IiII
 OOOoOOo0o = struct . pack ( "H" , OOOoOOo0o )
 Ii1iiI1 = data [ 0 : 6 ] + OOOoOOo0o + data [ 8 : : ]
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
 OOOoOOo0o = 0
 for OoOOoO0oOo in range ( 0 , 24 , 4 ) :
  OOOoOOo0o += int ( o0O0Ooo [ OoOOoO0oOo : OoOOoO0oOo + 4 ] , 16 )
  if 52 - 52: OoO0O00 * OoooooooOO
  if 12 - 12: O0 + IiII * i1IIi . OoO0O00
  if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
  if 28 - 28: iIii1I11I1II1
  if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
 OOOoOOo0o = ( OOOoOOo0o >> 16 ) + ( OOOoOOo0o & 0xffff )
 OOOoOOo0o += OOOoOOo0o >> 16
 OOOoOOo0o = socket . htons ( ~ OOOoOOo0o & 0xffff )
 if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 if 46 - 46: OoOoOO00 - O0
 OOOoOOo0o = struct . pack ( "H" , OOOoOOo0o )
 igmp = igmp [ 0 : 2 ] + OOOoOOo0o + igmp [ 4 : : ]
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
 for oOOOo0o in O00Oo [ netifaces . AF_INET ] :
  Oo0o = oOOOo0o [ "addr" ]
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
 o00oo = lisp_format_packet ( packet [ 0 : 12 ] ) . replace ( " " , "" )
 O0oO0oo0O = o00oo [ 0 : 12 ]
 oo = o00oo [ 12 : : ]
 if 76 - 76: OoO0O00 * oO0o
 try : OoO = ( oo in lisp_mymacs )
 except : OoO = False
 if 28 - 28: OoOoOO00 - iIii1I11I1II1 % O0
 if ( O0oO0oo0O in lisp_mymacs ) : return ( lisp_mymacs [ O0oO0oo0O ] , oo , O0oO0oo0O , OoO )
 if ( OoO ) : return ( lisp_mymacs [ oo ] , oo , O0oO0oo0O , OoO )
 return ( [ "?" ] , oo , O0oO0oo0O , OoO )
 if 76 - 76: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo
 if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
 if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
 if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
 if 37 - 37: iII111i
def lisp_get_local_interfaces ( ) :
 for iIIiI1111 in netifaces . interfaces ( ) :
  OooOO = lisp_interface ( iIIiI1111 )
  OooOO . add_interface ( )
  if 86 - 86: Ii1I . OOooOOo / IiII - OoooooooOO
 return
 if 45 - 45: OOooOOo
 if 25 - 25: OOooOOo % O0
 if 44 - 44: I1Ii111 . Ii1I * II111iiii / IiII + iIii1I11I1II1
 if 14 - 14: O0 % IiII % Ii1I * oO0o
 if 65 - 65: I11i % oO0o + I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 / O0 . I1Ii111 % iIii1I11I1II1 % Oo0Ooo
 if 86 - 86: i11iIiiIii - o0oOOo0O0Ooo . ooOoO0o * Oo0Ooo / Ii1I % o0oOOo0O0Ooo
def lisp_get_loopback_address ( ) :
 for oOOOo0o in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( oOOOo0o [ "peer" ] == "127.0.0.1" ) : continue
  return ( oOOOo0o [ "peer" ] )
  if 61 - 61: o0oOOo0O0Ooo + OoOoOO00
 return ( None )
 if 15 - 15: OoOoOO00 * oO0o + OOooOOo . I11i % I1IiiI - ooOoO0o
 if 13 - 13: OoOoOO00 % OoOoOO00 % Oo0Ooo % I1IiiI * i1IIi % I11i
 if 82 - 82: IiII . OoOoOO00 / ooOoO0o + iII111i - ooOoO0o
 if 55 - 55: ooOoO0o % Oo0Ooo % o0oOOo0O0Ooo
 if 29 - 29: IiII / iIii1I11I1II1 + I1ii11iIi11i % iII111i % I11i
 if 46 - 46: iIii1I11I1II1
 if 70 - 70: i1IIi . I11i
 if 74 - 74: I11i
def lisp_is_mac_string ( mac_str ) :
 O0o0oo0oOO0oO = mac_str . split ( "/" )
 if ( len ( O0o0oo0oOO0oO ) == 2 ) : mac_str = O0o0oo0oOO0oO [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 58 - 58: iIii1I11I1II1 * OoO0O00 * I1Ii111 * ooOoO0o . OoooooooOO
 if 6 - 6: I1ii11iIi11i - oO0o * i11iIiiIii + OoOoOO00 / ooOoO0o % OOooOOo
 if 38 - 38: OOooOOo % IiII % II111iiii - Oo0Ooo - iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo % I1ii11iIi11i . I1ii11iIi11i
 if 28 - 28: OoooooooOO % oO0o + I1ii11iIi11i + O0 . I1Ii111
 if 80 - 80: i11iIiiIii % I1ii11iIi11i
 if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
 if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
def lisp_get_local_macs ( ) :
 for iIIiI1111 in netifaces . interfaces ( ) :
  if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
  if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
  if 21 - 21: iII111i
  if 24 - 24: iII111i / ooOoO0o
  if 61 - 61: iIii1I11I1II1 + oO0o
  iiIi = iIIiI1111 . replace ( ":" , "" )
  iiIi = iIIiI1111 . replace ( "-" , "" )
  if ( iiIi . isalnum ( ) == False ) : continue
  if 8 - 8: I1Ii111 + OoO0O00
  if 9 - 9: OOooOOo + o0oOOo0O0Ooo
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
  if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
  if 55 - 55: oO0o
  try :
   i1iiI = netifaces . ifaddresses ( iIIiI1111 )
  except :
   continue
   if 97 - 97: I1Ii111 . I11i / I1IiiI
  if ( netifaces . AF_LINK not in i1iiI ) : continue
  O0o0oo0oOO0oO = i1iiI [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  O0o0oo0oOO0oO = O0o0oo0oOO0oO . replace ( ":" , "" )
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
  if 90 - 90: Oo0Ooo * I1IiiI
  if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
  if 28 - 28: IiII * I1IiiI % IiII
  if ( len ( O0o0oo0oOO0oO ) < 12 ) : continue
  if 95 - 95: O0 / I11i . I1Ii111
  if ( O0o0oo0oOO0oO not in lisp_mymacs ) : lisp_mymacs [ O0o0oo0oOO0oO ] = [ ]
  lisp_mymacs [ O0o0oo0oOO0oO ] . append ( iIIiI1111 )
  if 17 - 17: I11i
  if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 if 36 - 36: IiII
def lisp_get_local_rloc ( ) :
 iIi = getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( iIi == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 52 - 52: iIii1I11I1II1
 if 49 - 49: OOooOOo
 if 23 - 23: OoO0O00 / iII111i / iIii1I11I1II1
 if 44 - 44: Oo0Ooo . Oo0Ooo + OoooooooOO * i11iIiiIii / I11i + I1Ii111
 iIi = iIi . split ( "\n" ) [ 0 ]
 iIIiI1111 = iIi . split ( ) [ - 1 ]
 if 17 - 17: OOooOOo + II111iiii
 oOOOo0o = ""
 I1i11I11Iii = lisp_is_macos ( )
 if ( I1i11I11Iii ) :
  iIi = getoutput ( "ifconfig {} | egrep 'inet '" . format ( iIIiI1111 ) )
  if ( iIi == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  i1i1I11I = 'ip addr show | egrep "inet " | egrep "{}"' . format ( iIIiI1111 )
  iIi = getoutput ( i1i1I11I )
  if ( iIi == "" ) :
   i1i1I11I = 'ip addr show | egrep "inet " | egrep "global lo"'
   iIi = getoutput ( i1i1I11I )
   if 29 - 29: i1IIi % o0oOOo0O0Ooo . i1IIi
  if ( iIi == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 77 - 77: i1IIi * OoooooooOO % iII111i % o0oOOo0O0Ooo % ooOoO0o / I1ii11iIi11i
  if 64 - 64: i11iIiiIii . ooOoO0o
  if 93 - 93: O0 - OoO0O00 . I1IiiI
  if 64 - 64: OoOoOO00 + o0oOOo0O0Ooo
  if 65 - 65: II111iiii / Oo0Ooo
  if 42 - 42: i11iIiiIii . O0
 oOOOo0o = ""
 iIi = iIi . split ( "\n" )
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 for IiiiI1 in iIi :
  OoOOOO = IiiiI1 . split ( ) [ 1 ]
  if ( I1i11I11Iii == False ) : OoOOOO = OoOOOO . split ( "/" ) [ 0 ]
  I1IIIi = lisp_address ( LISP_AFI_IPV4 , OoOOOO , 32 , 0 )
  return ( I1IIIi )
  if 39 - 39: I11i . I1ii11iIi11i . OOooOOo * I11i / O0 * o0oOOo0O0Ooo
 return ( lisp_address ( LISP_AFI_IPV4 , oOOOo0o , 32 , 0 ) )
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
 Ooo = None
 OOOooo0OooOoO = 1
 IIi111 = os . getenv ( "LISP_ADDR_SELECT" )
 if ( IIi111 != None and IIi111 != "" ) :
  IIi111 = IIi111 . split ( ":" )
  if ( len ( IIi111 ) == 2 ) :
   Ooo = IIi111 [ 0 ]
   OOOooo0OooOoO = IIi111 [ 1 ]
  else :
   if ( IIi111 [ 0 ] . isdigit ( ) ) :
    OOOooo0OooOoO = IIi111 [ 0 ]
   else :
    Ooo = IIi111 [ 0 ]
    if 61 - 61: I1ii11iIi11i - OOooOOo
    if 16 - 16: iII111i / iIii1I11I1II1 + OOooOOo * iII111i * I11i
  OOOooo0OooOoO = 1 if ( OOOooo0OooOoO == "" ) else int ( OOOooo0OooOoO )
  if 8 - 8: I1Ii111
  if 15 - 15: Oo0Ooo / Ii1I % O0 + I1ii11iIi11i
 o0o = [ None , None , None ]
 i1I1I1I = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iII1III = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 O0oo0oO00o = None
 if 35 - 35: iII111i * iIii1I11I1II1 / ooOoO0o * i1IIi * O0 % iIii1I11I1II1
 for iIIiI1111 in netifaces . interfaces ( ) :
  if ( Ooo != None and Ooo != iIIiI1111 ) : continue
  O00Oo = netifaces . ifaddresses ( iIIiI1111 )
  if ( O00Oo == { } ) : continue
  if 97 - 97: i11iIiiIii + Oo0Ooo * OOooOOo % iII111i . IiII
  if 4 - 4: O0 . iII111i - iIii1I11I1II1
  if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
  if 89 - 89: Ii1I
  O0oo0oO00o = lisp_get_interface_instance_id ( iIIiI1111 , None )
  if 51 - 51: iII111i
  if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
  if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
  if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
  if ( netifaces . AF_INET in O00Oo ) :
   ooooo0Oo0 = O00Oo [ netifaces . AF_INET ]
   Ooo0oOOoo0O = 0
   for oOOOo0o in ooooo0Oo0 :
    i1I1I1I . store_address ( oOOOo0o [ "addr" ] )
    if ( i1I1I1I . is_ipv4_loopback ( ) ) : continue
    if ( i1I1I1I . is_ipv4_link_local ( ) ) : continue
    if ( i1I1I1I . address == 0 ) : continue
    Ooo0oOOoo0O += 1
    i1I1I1I . instance_id = O0oo0oO00o
    if ( Ooo == None and
 lisp_db_for_lookups . lookup_cache ( i1I1I1I , False ) ) : continue
    o0o [ 0 ] = i1I1I1I
    if ( Ooo0oOOoo0O == OOOooo0OooOoO ) : break
    if 57 - 57: I1IiiI . i11iIiiIii * II111iiii + OoooooooOO + Ii1I
    if 73 - 73: O0 % I11i + iII111i . I1ii11iIi11i . I1ii11iIi11i + IiII
  if ( netifaces . AF_INET6 in O00Oo ) :
   o0I1IIIi11ii11 = O00Oo [ netifaces . AF_INET6 ]
   Ooo0oOOoo0O = 0
   for oOOOo0o in o0I1IIIi11ii11 :
    Oo0o = oOOOo0o [ "addr" ]
    iII1III . store_address ( Oo0o )
    if ( iII1III . is_ipv6_string_link_local ( Oo0o ) ) : continue
    if ( iII1III . is_ipv6_loopback ( ) ) : continue
    Ooo0oOOoo0O += 1
    iII1III . instance_id = O0oo0oO00o
    if ( Ooo == None and
 lisp_db_for_lookups . lookup_cache ( iII1III , False ) ) : continue
    o0o [ 1 ] = iII1III
    if ( Ooo0oOOoo0O == OOOooo0OooOoO ) : break
    if 30 - 30: OoOoOO00
    if 89 - 89: I11i
    if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
    if 79 - 79: IiII + IiII + Ii1I
    if 39 - 39: O0 - OoooooooOO
    if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  if ( o0o [ 0 ] == None ) : continue
  if 79 - 79: O0
  o0o [ 2 ] = iIIiI1111
  break
  if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
  if 15 - 15: I1ii11iIi11i
 I11iI1 = o0o [ 0 ] . print_address_no_iid ( ) if o0o [ 0 ] else "none"
 oOo00OO0o0 = o0o [ 1 ] . print_address_no_iid ( ) if o0o [ 1 ] else "none"
 iIIiI1111 = o0o [ 2 ] if o0o [ 2 ] else "none"
 if 1 - 1: OoooooooOO / O0 + OoOoOO00 + OoOoOO00 . I1Ii111 - OoOoOO00
 Ooo = " (user selected)" if Ooo != None else ""
 if 9 - 9: I1Ii111 * OoooooooOO % I1IiiI / OoOoOO00 * I11i
 I11iI1 = red ( I11iI1 , False )
 oOo00OO0o0 = red ( oOo00OO0o0 , False )
 iIIiI1111 = bold ( iIIiI1111 , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( I11iI1 , oOo00OO0o0 , iIIiI1111 , Ooo , O0oo0oO00o ) )
 if 48 - 48: OoooooooOO . OoOoOO00
 if 65 - 65: oO0o . Oo0Ooo
 lisp_myrlocs = o0o
 return ( ( o0o [ 0 ] != None ) )
 if 94 - 94: OoOoOO00 + IiII . ooOoO0o
 if 69 - 69: O0 - O0
 if 41 - 41: IiII % o0oOOo0O0Ooo
 if 67 - 67: O0 % I1Ii111
 if 35 - 35: I1IiiI . OoOoOO00 + OoooooooOO % Oo0Ooo % OOooOOo
 if 39 - 39: Ii1I
 if 60 - 60: OOooOOo
 if 62 - 62: I1Ii111 * I11i
 if 74 - 74: OoOoOO00 . iIii1I11I1II1
def lisp_get_all_addresses ( ) :
 oOOoO0oO0oo0O = [ ]
 for OooOO in netifaces . interfaces ( ) :
  try : oO00Oo = netifaces . ifaddresses ( OooOO )
  except : continue
  if 82 - 82: IiII
  if ( netifaces . AF_INET in oO00Oo ) :
   for oOOOo0o in oO00Oo [ netifaces . AF_INET ] :
    OoOOOO = oOOOo0o [ "addr" ]
    if ( OoOOOO . find ( "127.0.0.1" ) != - 1 ) : continue
    oOOoO0oO0oo0O . append ( OoOOOO )
    if 51 - 51: oO0o % OoO0O00 + o0oOOo0O0Ooo + Ii1I - OoooooooOO . OoO0O00
    if 18 - 18: Oo0Ooo - OOooOOo * II111iiii + oO0o
  if ( netifaces . AF_INET6 in oO00Oo ) :
   for oOOOo0o in oO00Oo [ netifaces . AF_INET6 ] :
    OoOOOO = oOOOo0o [ "addr" ]
    if ( OoOOOO == "::1" ) : continue
    if ( OoOOOO [ 0 : 5 ] == "fe80:" ) : continue
    oOOoO0oO0oo0O . append ( OoOOOO )
    if 93 - 93: iII111i * oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
    if 59 - 59: II111iiii
    if 43 - 43: Oo0Ooo + OoooooooOO
 return ( oOOoO0oO0oo0O )
 if 47 - 47: ooOoO0o
 if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
 if 23 - 23: II111iiii * iII111i
 if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
 if 38 - 38: I1ii11iIi11i % ooOoO0o + i1IIi * OoooooooOO * oO0o
 if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
 if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
 if 21 - 21: OoO0O00
def lisp_get_all_multicast_rles ( ) :
 O0o0oOOO = [ ]
 iIi = getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( iIi == "" ) : return ( O0o0oOOO )
 if 24 - 24: o0oOOo0O0Ooo / Ii1I / Ii1I % II111iiii - oO0o * oO0o
 oOoo0oO = iIi . split ( "\n" )
 for IiiiI1 in oOoo0oO :
  if ( IiiiI1 [ 0 ] == "#" ) : continue
  IIii1i = IiiiI1 . split ( "rle-address = " ) [ 1 ]
  o00ooIi11IIIi1 = int ( IIii1i . split ( "." ) [ 0 ] )
  if ( o00ooIi11IIIi1 >= 224 and o00ooIi11IIIi1 < 240 ) : O0o0oOOO . append ( IIii1i )
  if 93 - 93: i11iIiiIii . o0oOOo0O0Ooo
 return ( O0o0oOOO )
 if 16 - 16: i1IIi . i1IIi / I1Ii111 % OoOoOO00 / I1IiiI * I1ii11iIi11i
 if 30 - 30: o0oOOo0O0Ooo + OoooooooOO + OOooOOo / II111iiii * Oo0Ooo
 if 59 - 59: Ii1I / OoOoOO00 * OoO0O00 * iII111i % oO0o
 if 61 - 61: Oo0Ooo - O0 - OoooooooOO
 if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
 if 18 - 18: Oo0Ooo % O0
 if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
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
  if 86 - 86: IiII
  if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
 def encode ( self , nonce ) :
  if 33 - 33: II111iiii - IiII - ooOoO0o
  if 92 - 92: OoO0O00 * IiII
  if 92 - 92: oO0o
  if 7 - 7: iII111i
  if 73 - 73: OoO0O00 % I1ii11iIi11i
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 32 - 32: OOooOOo + iII111i + iIii1I11I1II1 * Oo0Ooo
  if 62 - 62: i11iIiiIii
  if 2 - 2: I1IiiI
  if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
  if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  if 14 - 14: IiII . IiII % ooOoO0o
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
  if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
  if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
  if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
  if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 6 - 6: oO0o . I11i
  self . lisp_header . key_id ( 0 )
  iIIII1 = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and iIIII1 == False ) :
   Oo0o = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 65 - 65: O0 / II111iiii . iIii1I11I1II1 . oO0o / Oo0Ooo % iIii1I11I1II1
   if ( Oo0o in lisp_crypto_keys_by_rloc_encap ) :
    Oo0Oo = lisp_crypto_keys_by_rloc_encap [ Oo0o ]
    if ( Oo0Oo [ 1 ] ) :
     Oo0Oo [ 1 ] . use_count += 1
     OO0 , iiiii1iiIIii = self . encrypt ( Oo0Oo [ 1 ] , Oo0o )
     if ( iiiii1iiIIii ) : self . packet = OO0
     if 8 - 8: I1ii11iIi11i * I1ii11iIi11i * i1IIi + iII111i . I1ii11iIi11i
     if 100 - 100: OoooooooOO - O0 . I11i / I11i + II111iiii * OoOoOO00
     if 37 - 37: Oo0Ooo
     if 72 - 72: IiII % I1ii11iIi11i * OOooOOo . i11iIiiIii % IiII * OOooOOo
     if 15 - 15: I11i / Oo0Ooo * I11i
     if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
     if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
     if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 5 - 5: O0 - I1IiiI
  else :
   self . udp_sport = LISP_DATA_PORT
   if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 16 - 16: II111iiii
  if 100 - 100: O0 - i1IIi
  if 48 - 48: oO0o % ooOoO0o + O0
  if 27 - 27: I1ii11iIi11i / OOooOOo
  IiiIiiIIII = socket . htons ( self . udp_sport )
  oOo = socket . htons ( self . udp_dport )
  OOOOoO0 = socket . htons ( self . udp_length )
  Ii1iiI1 = struct . pack ( "HHHH" , IiiIiiIIII , oOo , OOOOoO0 , self . udp_checksum )
  if 43 - 43: I1IiiI - o0oOOo0O0Ooo / o0oOOo0O0Ooo . II111iiii - Ii1I
  if 40 - 40: iII111i . OoOoOO00 * O0
  if 6 - 6: I1IiiI - II111iiii . I1IiiI + I11i . OOooOOo
  if 74 - 74: i1IIi
  Ii11ii1 = self . lisp_header . encode ( )
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
   Oo00O0o0O = ""
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
  self . packet = Oo00O0o0O + Ii1iiI1 + Ii11ii1 + self . packet
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
  OO0 = self . cipher_pad ( self . packet )
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
  iiIiIiI111 = iII1I ( OO0 )
  if 82 - 82: I1IiiI % OoO0O00 % I11i + I11i
  if ( iiIiIiI111 == None ) : return ( [ self . packet , False ] )
  i1 = int ( str ( time . time ( ) - i1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 6 - 6: Oo0Ooo
  if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
  if 93 - 93: i11iIiiIii
  if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
  if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
  if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
  if ( iIiiII != None ) : iiIiIiI111 += iIiiII ( )
  if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
  if 58 - 58: I11i
  if 7 - 7: II111iiii / IiII % I11i + I1IiiI - O0
  if 45 - 45: I1IiiI / iII111i + oO0o + IiII
  if 15 - 15: I1IiiI % OoO0O00
  self . lisp_header . key_id ( key . key_id )
  Ii11ii1 = self . lisp_header . encode ( )
  if 66 - 66: oO0o * i11iIiiIii . I1Ii111
  o0O0OOOo0 = key . do_icv ( Ii11ii1 + OoOooO + iiIiIiI111 , OoOooO )
  if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
  IIiIIIi1iii1 = 4 if ( key . do_poly ) else 8
  if 37 - 37: iIii1I11I1II1 % I11i / IiII
  i1IIIII1 = bold ( "Encrypt" , False )
  IIIiiiiiI1I = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  O0oooO00ooO0 = "poly" if key . do_poly else "sha256"
  O0oooO00ooO0 = bold ( O0oooO00ooO0 , False )
  o00OOO0o00OO = "ICV({}): 0x{}...{}" . format ( O0oooO00ooO0 , o0O0OOOo0 [ 0 : IIiIIIi1iii1 ] , o0O0OOOo0 [ - IIiIIIi1iii1 : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( i1IIIII1 , key . key_id , addr_str , o00OOO0o00OO , IIIiiiiiI1I , i1 ) )
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
  return ( [ OoOooO + iiIiIiI111 + o0O0OOOo0 , True ] )
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
  Ii11ii1 = self . lisp_header . encode ( )
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
  Iii1iIIiii1ii = key . do_icv ( Ii11ii1 + packet , OoOooO )
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
   lisp_retry_decap_keys ( addr_str , Ii11ii1 + packet , OoOooO , Oo000 )
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
  i1 = lisp_get_timestamp ( )
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
  i1 = int ( str ( time . time ( ) - i1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 53 - 53: I1IiiI
  if 10 - 10: I1Ii111 / i11iIiiIii - II111iiii
  if 48 - 48: OOooOOo
  if 26 - 26: iII111i * I1Ii111 * oO0o * OoOoOO00
  i1IIIII1 = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  O0oooO00ooO0 = "poly" if key . do_poly else "sha256"
  O0oooO00ooO0 = bold ( O0oooO00ooO0 , False )
  o00OOO0o00OO = "ICV({}): {}" . format ( O0oooO00ooO0 , Ii11iIiiI )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( i1IIIII1 , key . key_id , addr_str , o00OOO0o00OO , IIIiiiiiI1I , i1 ) )
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
   Ii = inner_packet [ IiI1ii1Ii : : ]
   if ( len ( Ii ) > ooOooOooOOO ) : Ii = Ii [ 0 : ooOooOooOOO ]
   ii . append ( Ii )
   IiI1ii1Ii += len ( Ii )
   if 89 - 89: i1IIi . i1IIi
   if 10 - 10: iII111i % Oo0Ooo
   if 48 - 48: OOooOOo + I1Ii111 % OOooOOo
   if 84 - 84: O0 % Ii1I . Ii1I . iII111i * I11i
   if 43 - 43: OoOoOO00 . I1ii11iIi11i % i1IIi
   if 61 - 61: I1IiiI + oO0o % I1Ii111 % iIii1I11I1II1 - OoooooooOO
  iIIiI1 = [ ]
  IiI1ii1Ii = 0
  for Ii in ii :
   if 4 - 4: OoooooooOO + iII111i % O0 + iIii1I11I1II1 % iII111i * i11iIiiIii
   if 32 - 32: OoOoOO00 + ooOoO0o + Ii1I + I1IiiI
   if 26 - 26: iII111i - Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
   if 37 - 37: o0oOOo0O0Ooo * OOooOOo + I1IiiI . I1ii11iIi11i * OoooooooOO
   OoooOO0 = IiI1ii1Ii if ( Ii == ii [ - 1 ] ) else 0x2000 + IiI1ii1Ii
   OoooOO0 = socket . htons ( OoooOO0 )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , OoooOO0 ) + outer_hdr [ 8 : : ]
   if 69 - 69: II111iiii + iII111i
   if 55 - 55: i11iIiiIii + I1IiiI
   if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
   if 64 - 64: ooOoO0o / i1IIi % iII111i
   OOoOo0O0 = socket . htons ( len ( Ii ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , OOoOo0O0 ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   iIIiI1 . append ( outer_hdr + Ii )
   IiI1ii1Ii += len ( Ii ) / 8
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
  O0OO0ooO00 = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , OooOOoO00OO00 )
  O0OO0ooO00 += inner_packet [ 0 : 20 + 8 ]
  O0OO0ooO00 = lisp_icmp_checksum ( O0OO0ooO00 )
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
  I1iIIi = socket . htons ( 20 + 36 )
  o0OO00oo0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , I1iIIi , 0 , 0 , 32 , 1 , 0 ) + III + OoOIiiIi1IiiiI
  o0OO00oo0O = lisp_ip_checksum ( o0OO00oo0O )
  o0OO00oo0O = self . fix_outer_header ( o0OO00oo0O )
  o0OO00oo0O += O0OO0ooO00
  IiIIii1 = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( IiIIii1 , OO0oooOO ,
 lisp_format_packet ( o0OO00oo0O ) ) )
  if 7 - 7: O0 - I1ii11iIi11i / OoOoOO00 - Ii1I - oO0o / OoooooooOO
  try :
   lisp_icmp_raw_socket . sendto ( o0OO00oo0O , ( OO0oooOO , 0 ) )
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
  OO0 = self . fix_outer_header ( self . packet )
  if 54 - 54: Ii1I % i1IIi
  if 51 - 51: iIii1I11I1II1 - I1IiiI
  if 61 - 61: OoooooooOO . Ii1I % oO0o * OoooooooOO
  if 96 - 96: Ii1I - II111iiii % OoOoOO00 * I1IiiI * I1IiiI . Oo0Ooo
  if 75 - 75: Oo0Ooo + Ii1I + OoO0O00
  if 97 - 97: ooOoO0o % i11iIiiIii % I11i
  i1iIii = len ( OO0 )
  if ( i1iIii <= 1500 ) : return ( [ OO0 ] , "Fragment-None" )
  if 21 - 21: Oo0Ooo / Ii1I / I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
  OO0 = self . packet
  if 86 - 86: i1IIi
  if 33 - 33: OoOoOO00 % i11iIiiIii * OOooOOo
  if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
  if 75 - 75: OoO0O00 % OoooooooOO
  if 16 - 16: O0 / i1IIi
  if ( self . inner_version != 4 ) :
   OOoo0 = random . randint ( 0 , 0xffff )
   Ii11I1iIIi = OO0 [ 0 : 4 ] + struct . pack ( "H" , OOoo0 ) + OO0 [ 6 : 20 ]
   O0ooO = OO0 [ 20 : : ]
   iIIiI1 = self . fragment_outer ( Ii11I1iIIi , O0ooO )
   return ( iIIiI1 , "Fragment-Outer" )
   if 40 - 40: o0oOOo0O0Ooo . o0oOOo0O0Ooo * i11iIiiIii
   if 44 - 44: o0oOOo0O0Ooo
   if 80 - 80: I1ii11iIi11i + I11i - ooOoO0o - o0oOOo0O0Ooo % Ii1I
   if 85 - 85: I1Ii111
   if 62 - 62: Ii1I % II111iiii + IiII + OOooOOo % oO0o . I1IiiI
  OOoOo0ooOoo = 56 if ( self . outer_version == 6 ) else 36
  Ii11I1iIIi = OO0 [ 0 : OOoOo0ooOoo ]
  oO0OO00 = OO0 [ OOoOo0ooOoo : OOoOo0ooOoo + 20 ]
  O0ooO = OO0 [ OOoOo0ooOoo + 20 : : ]
  if 16 - 16: OoooooooOO / oO0o . Ii1I * ooOoO0o - I1IiiI
  if 32 - 32: I1IiiI / OoO0O00
  if 28 - 28: Oo0Ooo / IiII . iII111i + OoO0O00 + I11i % Oo0Ooo
  if 45 - 45: Oo0Ooo / O0 % OoooooooOO
  if 92 - 92: Ii1I . OoOoOO00 . I11i - OoooooooOO / ooOoO0o
  ooOo0 = struct . unpack ( "H" , oO0OO00 [ 6 : 8 ] ) [ 0 ]
  ooOo0 = socket . ntohs ( ooOo0 )
  if ( ooOo0 & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    I11I1i = OO0 [ OOoOo0ooOoo : : ]
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
  for Ii in ii :
   if 11 - 11: OOooOOo / I1IiiI
   if 98 - 98: I1ii11iIi11i - Ii1I * OoO0O00 . I1ii11iIi11i - I1Ii111
   if 4 - 4: i11iIiiIii + OoooooooOO / i11iIiiIii . OoooooooOO % I1ii11iIi11i / OoOoOO00
   if 35 - 35: I1ii11iIi11i % i1IIi + o0oOOo0O0Ooo - iIii1I11I1II1
   II1i1III1IIiI = old_div ( ooOo0 , 8 )
   if ( iI1 ) :
    II1i1III1IIiI |= 0x2000
   elif ( Ii != ii [ - 1 ] ) :
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
   i1iIii = len ( Ii )
   ooOo0 += i1iIii
   OOoOo0O0 = socket . htons ( i1iIii + 20 )
   oO0OO00 = oO0OO00 [ 0 : 2 ] + struct . pack ( "H" , OOoOo0O0 ) + oO0OO00 [ 4 : 10 ] + struct . pack ( "H" , 0 ) + oO0OO00 [ 12 : : ]
   if 32 - 32: ooOoO0o - OoO0O00 . iII111i . iII111i % i1IIi * Ii1I
   oO0OO00 = lisp_ip_checksum ( oO0OO00 )
   o0o0 = oO0OO00 + Ii
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
  OO0 = mac_header + self . packet
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
  l2_socket . write ( OO0 )
  return
  if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
  if 91 - 91: I1IiiI / II111iiii * OOooOOo
 def bridge_l2_packet ( self , eid , db ) :
  try : ooOoo000 = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : OooOO = lisp_myinterfaces [ ooOoo000 . interface ]
  except : return
  try :
   socket = OooOO . get_bridge_socket ( )
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
  Ii1iiI1 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( Ii1iiI1 == False ) : return ( False )
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
  OO0 = self . packet
  I1iiIIiI11I = len ( OO0 )
  I11II1I = oOoOo000 = True
  if 37 - 37: iII111i
  if 15 - 15: o0oOOo0O0Ooo % OoO0O00 / iII111i
  if 36 - 36: OoO0O00 + OoO0O00 % Oo0Ooo + Oo0Ooo / i1IIi % i1IIi
  if 20 - 20: OOooOOo * oO0o
  OOOoooOo00O = 0
  i1oO00O = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   iiIIiI1I = struct . unpack ( "B" , OO0 [ 0 : 1 ] ) [ 0 ]
   self . outer_version = iiIIiI1I >> 4
   if ( self . outer_version == 4 ) :
    if 67 - 67: I1ii11iIi11i % OoooooooOO
    if 41 - 41: OoO0O00 / IiII + I1Ii111 . I1Ii111 / oO0o
    if 74 - 74: Ii1I % i11iIiiIii . O0 * I1IiiI * i1IIi * OoooooooOO
    if 22 - 22: I1Ii111 + iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoooooooOO
    if 42 - 42: OoooooooOO - OoOoOO00 - OOooOOo * I1Ii111
    OO0iii111 = struct . unpack ( "H" , OO0 [ 10 : 12 ] ) [ 0 ]
    OO0 = lisp_ip_checksum ( OO0 )
    OOOoOOo0o = struct . unpack ( "H" , OO0 [ 10 : 12 ] ) [ 0 ]
    if ( OOOoOOo0o != 0 ) :
     if ( OO0iii111 != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( I1iiIIiI11I )
       if 59 - 59: ooOoO0o * I1Ii111
       if 57 - 57: IiII * iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % ooOoO0o
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 33 - 33: O0 * Ii1I - IiII . OoooooooOO + IiII
      if 20 - 20: I1Ii111 - OoOoOO00
      if 91 - 91: i1IIi
    ii11IiI = LISP_AFI_IPV4
    IiI1ii1Ii = 12
    self . outer_tos = struct . unpack ( "B" , OO0 [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , OO0 [ 8 : 9 ] ) [ 0 ]
    OOOoooOo00O = 20
   elif ( self . outer_version == 6 ) :
    ii11IiI = LISP_AFI_IPV6
    IiI1ii1Ii = 8
    I1iI1Ii11 = struct . unpack ( "H" , OO0 [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( I1iI1Ii11 ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , OO0 [ 7 : 8 ] ) [ 0 ]
    OOOoooOo00O = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( I1iiIIiI11I )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 34 - 34: Ii1I * I1IiiI + I11i * OoOoOO00 - II111iiii
    if 92 - 92: OOooOOo . o0oOOo0O0Ooo / iII111i . iIii1I11I1II1 % Oo0Ooo . OoooooooOO
   self . outer_source . afi = ii11IiI
   self . outer_dest . afi = ii11IiI
   Ooo00OoO0O00 = self . outer_source . addr_length ( )
   if 11 - 11: I11i
   self . outer_source . unpack_address ( OO0 [ IiI1ii1Ii : IiI1ii1Ii + Ooo00OoO0O00 ] )
   IiI1ii1Ii += Ooo00OoO0O00
   self . outer_dest . unpack_address ( OO0 [ IiI1ii1Ii : IiI1ii1Ii + Ooo00OoO0O00 ] )
   OO0 = OO0 [ OOOoooOo00O : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 20 - 20: O0 . i11iIiiIii * i1IIi % O0 . I1IiiI
   if 53 - 53: ooOoO0o / OoooooooOO - II111iiii
   if 68 - 68: OoooooooOO . OoooooooOO . iIii1I11I1II1 / ooOoO0o - I11i % O0
   if 19 - 19: OoooooooOO * oO0o
   OoO00OO0 = struct . unpack ( "H" , OO0 [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( OoO00OO0 )
   OoO00OO0 = struct . unpack ( "H" , OO0 [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( OoO00OO0 )
   OoO00OO0 = struct . unpack ( "H" , OO0 [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( OoO00OO0 )
   OoO00OO0 = struct . unpack ( "H" , OO0 [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( OoO00OO0 )
   OO0 = OO0 [ 8 : : ]
   if 26 - 26: O0 . I11i + iII111i - Ii1I . I11i
   if 2 - 2: I1ii11iIi11i . Oo0Ooo * OOooOOo % II111iiii . iII111i
   if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
   if 47 - 47: iII111i * OoOoOO00 * IiII
   I11II1I = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   oOoOo000 = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 46 - 46: Ii1I
   if 42 - 42: iIii1I11I1II1
   if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
   if 34 - 34: Oo0Ooo
   if ( self . lisp_header . decode ( OO0 ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( I1iiIIiI11I )
    if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 33 - 33: i1IIi / iII111i * OoO0O00
   OO0 = OO0 [ 8 : : ]
   i1oO00O = self . lisp_header . get_instance_id ( )
   OOOoooOo00O += 16
   if 2 - 2: oO0o . OOooOOo
  if ( i1oO00O == 0xffffff ) : i1oO00O = 0
  if 43 - 43: iIii1I11I1II1
  if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
  if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
  if 98 - 98: i1IIi - iII111i
  iI = False
  IiII11iI1 = self . lisp_header . k_bits
  if ( IiII11iI1 ) :
   Oo0o = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( Oo0o == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( I1iiIIiI11I )
    if 80 - 80: iII111i . O0
    self . print_packet ( "Receive" , is_lisp_packet )
    I1Iii = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( I1Iii , IiII11iI1 ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 33 - 33: o0oOOo0O0Ooo - oO0o % I1ii11iIi11i * I11i . OoooooooOO % Ii1I
    if 29 - 29: iII111i + II111iiii . i11iIiiIii . Ii1I - O0
   IIIOoo = lisp_crypto_keys_by_rloc_decap [ Oo0o ] [ IiII11iI1 ]
   if ( IIIOoo == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( I1iiIIiI11I )
    if 71 - 71: iIii1I11I1II1 . iIii1I11I1II1 * IiII
    self . print_packet ( "Receive" , is_lisp_packet )
    I1Iii = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( I1Iii ,
 red ( Oo0o , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 56 - 56: I11i / oO0o - oO0o
    if 40 - 40: i11iIiiIii * II111iiii
    if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
    if 53 - 53: Ii1I / I1IiiI * Ii1I + o0oOOo0O0Ooo + oO0o - Oo0Ooo
    if 16 - 16: OoO0O00 % I1Ii111 . i1IIi / I1ii11iIi11i - O0
   IIIOoo . use_count += 1
   OO0 , iI = self . decrypt ( OO0 , OOOoooOo00O , IIIOoo ,
 Oo0o )
   if ( iI == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( I1iiIIiI11I )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 85 - 85: i1IIi . i1IIi
    if 16 - 16: I1IiiI - OOooOOo % Ii1I . OOooOOo + I1ii11iIi11i % i11iIiiIii
    if 59 - 59: i11iIiiIii - I11i
    if 59 - 59: OoooooooOO * o0oOOo0O0Ooo / I1Ii111
    if 75 - 75: o0oOOo0O0Ooo - OoooooooOO
    if 21 - 21: I1IiiI + iIii1I11I1II1 / i11iIiiIii / oO0o
  iiIIiI1I = struct . unpack ( "B" , OO0 [ 0 : 1 ] ) [ 0 ]
  self . inner_version = iiIIiI1I >> 4
  if ( I11II1I and self . inner_version == 4 and iiIIiI1I >= 0x45 ) :
   Ooo000 = socket . ntohs ( struct . unpack ( "H" , OO0 [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , OO0 [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , OO0 [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , OO0 [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( OO0 [ 12 : 16 ] )
   self . inner_dest . unpack_address ( OO0 [ 16 : 20 ] )
   ooOo0 = socket . ntohs ( struct . unpack ( "H" , OO0 [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( ooOo0 & 0x2000 or ooOo0 != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , OO0 [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , OO0 [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 21 - 21: iII111i % IiII % Oo0Ooo % O0
  elif ( I11II1I and self . inner_version == 6 and iiIIiI1I >= 0x60 ) :
   Ooo000 = socket . ntohs ( struct . unpack ( "H" , OO0 [ 4 : 6 ] ) [ 0 ] ) + 40
   I1iI1Ii11 = struct . unpack ( "H" , OO0 [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( I1iI1Ii11 ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , OO0 [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , OO0 [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( OO0 [ 8 : 24 ] )
   self . inner_dest . unpack_address ( OO0 [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , OO0 [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , OO0 [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 63 - 63: II111iiii * I1IiiI - OoooooooOO / I1IiiI
  elif ( oOoOo000 ) :
   Ooo000 = len ( OO0 )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( OO0 [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( OO0 [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( I1iiIIiI11I )
   if 50 - 50: OoOoOO00 % Ii1I + OoOoOO00 * Ii1I - OOooOOo
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( iiIIiI1I ) ) )
   if 94 - 94: iIii1I11I1II1
   OO0 = lisp_format_packet ( OO0 [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( OO0 ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 1 - 1: O0
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = i1oO00O
  self . inner_dest . instance_id = i1oO00O
  if 2 - 2: OoO0O00 . I11i
  if 97 - 97: Oo0Ooo
  if 65 - 65: Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1 . I1Ii111 + ooOoO0o
  if 92 - 92: oO0o
  if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   I1 = lisp_get_echo_nonce ( self . outer_source , None )
   if ( I1 == None ) :
    iiIIii = self . outer_source . print_address_no_iid ( )
    I1 = lisp_echo_nonce ( iiIIii )
    if 90 - 90: IiII * I11i % II111iiii / OOooOOo
   o00oO0O000 = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    I1 . receive_request ( lisp_ipc_socket , o00oO0O000 )
   elif ( I1 . request_nonce_sent ) :
    I1 . receive_echo ( lisp_ipc_socket , o00oO0O000 )
    if 75 - 75: Oo0Ooo . iII111i
    if 55 - 55: I11i * I1IiiI - oO0o
    if 41 - 41: ooOoO0o + iIii1I11I1II1 % IiII % OOooOOo
    if 41 - 41: II111iiii . I1Ii111 . OoOoOO00 - OOooOOo - I1IiiI * I1Ii111
    if 99 - 99: I1IiiI
    if 64 - 64: I1ii11iIi11i * Ii1I * Oo0Ooo % IiII % ooOoO0o
    if 55 - 55: II111iiii - I1Ii111 - OOooOOo % Ii1I
  if ( iI ) : self . packet += OO0 [ : Ooo000 ]
  if 49 - 49: Oo0Ooo * I1Ii111
  if 53 - 53: Oo0Ooo / Ii1I + oO0o . iII111i + IiII
  if 19 - 19: Ii1I
  if 51 - 51: iIii1I11I1II1
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 8 - 8: OoO0O00 / o0oOOo0O0Ooo % iII111i . i11iIiiIii . OoooooooOO . Ii1I
  if 8 - 8: OoO0O00 * Oo0Ooo
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
  if 4 - 4: I11i . IiII
 def strip_outer_headers ( self ) :
  IiI1ii1Ii = 16
  IiI1ii1Ii += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ IiI1ii1Ii : : ]
  return ( self )
  if 39 - 39: OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii
  if 4 - 4: OoOoOO00 * O0 - I11i
 def hash_ports ( self ) :
  OO0 = self . packet
  iiIIiI1I = self . inner_version
  O0o0oo0 = 0
  if ( iiIIiI1I == 4 ) :
   ooo000 = struct . unpack ( "B" , OO0 [ 9 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( ooo000 )
   if ( ooo000 in [ 6 , 17 ] ) :
    O0o0oo0 = ooo000
    O0o0oo0 += struct . unpack ( "I" , OO0 [ 20 : 24 ] ) [ 0 ]
    O0o0oo0 = ( O0o0oo0 >> 16 ) ^ ( O0o0oo0 & 0xffff )
    if 45 - 45: OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
    if 70 - 70: II111iiii * II111iiii . I1IiiI
  if ( iiIIiI1I == 6 ) :
   ooo000 = struct . unpack ( "B" , OO0 [ 6 ] ) [ 0 ]
   if ( ooo000 in [ 6 , 17 ] ) :
    O0o0oo0 = ooo000
    O0o0oo0 += struct . unpack ( "I" , OO0 [ 40 : 44 ] ) [ 0 ]
    O0o0oo0 = ( O0o0oo0 >> 16 ) ^ ( O0o0oo0 & 0xffff )
    if 11 - 11: iII111i
    if 20 - 20: Ii1I . I1Ii111 % Ii1I
  return ( O0o0oo0 )
  if 5 - 5: OOooOOo + iII111i
  if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
 def hash_packet ( self ) :
  O0o0oo0 = self . inner_source . address ^ self . inner_dest . address
  O0o0oo0 += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   O0o0oo0 = ( O0o0oo0 >> 16 ) ^ ( O0o0oo0 & 0xffff )
  elif ( self . inner_version == 6 ) :
   O0o0oo0 = ( O0o0oo0 >> 64 ) ^ ( O0o0oo0 & 0xffffffffffffffff )
   O0o0oo0 = ( O0o0oo0 >> 32 ) ^ ( O0o0oo0 & 0xffffffff )
   O0o0oo0 = ( O0o0oo0 >> 16 ) ^ ( O0o0oo0 & 0xffff )
   if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
  self . udp_sport = 0xf000 | ( O0o0oo0 & 0xfff )
  if 11 - 11: I1ii11iIi11i / O0 + II111iiii
  if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   II1Iii1iI = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # iIii1I11I1II1 / I11i . O0 . Ii1I
 green ( II1Iii1iI , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
   if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   oO0 = "decap"
   oO0 += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   oO0 = s_or_r
   if ( oO0 in [ "Send" , "Replicate" ] or oO0 . find ( "Fragment" ) != - 1 ) :
    oO0 = "encap"
    if 7 - 7: I1ii11iIi11i * Ii1I / Oo0Ooo * i1IIi
    if 27 - 27: OoO0O00
  O0o00oO00O0 = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 16 - 16: Ii1I / i11iIiiIii + O0 . IiII
  if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
  if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
  if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
  if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   IiiiI1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 91 - 91: I1IiiI + o0oOOo0O0Ooo % II111iiii + OoO0O00
   IiiiI1 += bold ( "control-packet" , False ) + ": {} ..."
   if 66 - 66: iIii1I11I1II1 * II111iiii % Oo0Ooo % I1IiiI - Ii1I
   dprint ( IiiiI1 . format ( bold ( s_or_r , False ) , red ( O0o00oO00O0 , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   IiiiI1 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 59 - 59: IiII % oO0o
   if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
   if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
   if 93 - 93: I1ii11iIi11i * I1ii11iIi11i / OoooooooOO
  if ( self . lisp_header . k_bits ) :
   if ( oO0 == "encap" ) : oO0 = "encrypt/encap"
   if ( oO0 == "decap" ) : oO0 = "decap/decrypt"
   if 6 - 6: I1ii11iIi11i * Oo0Ooo + iIii1I11I1II1
   if 19 - 19: O0 % II111iiii * o0oOOo0O0Ooo
  II1Iii1iI = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 27 - 27: OOooOOo * IiII / i11iIiiIii - oO0o + II111iiii
  dprint ( IiiiI1 . format ( bold ( s_or_r , False ) , red ( O0o00oO00O0 , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( II1Iii1iI , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( oO0 ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 43 - 43: I1ii11iIi11i - II111iiii
  if 56 - 56: I1ii11iIi11i . i1IIi / iII111i % oO0o / O0 * I11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 98 - 98: O0 + iII111i
  if 23 - 23: OoooooooOO . iIii1I11I1II1 / i1IIi
 def get_raw_socket ( self ) :
  i1oO00O = str ( self . lisp_header . get_instance_id ( ) )
  if ( i1oO00O == "0" ) : return ( None )
  if ( i1oO00O not in lisp_iid_to_interface ) : return ( None )
  if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
  OooOO = lisp_iid_to_interface [ i1oO00O ]
  I1iiIi111I = OooOO . get_socket ( )
  if ( I1iiIi111I == None ) :
   i1IIIII1 = bold ( "SO_BINDTODEVICE" , False )
   oOOo0O0Oo = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( i1IIIII1 , "drop" if oOOo0O0Oo else "forward" ) )
   if 50 - 50: oO0o * I11i + OOooOOo - Oo0Ooo
   if ( oOOo0O0Oo ) : return ( None )
   if 79 - 79: OoO0O00 / i1IIi
   if 30 - 30: OoOoOO00 - i11iIiiIii
  i1oO00O = bold ( i1oO00O , False )
  iiIi = bold ( OooOO . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( i1oO00O , iiIi ) )
  return ( I1iiIi111I )
  if 94 - 94: OoOoOO00 % iII111i
  if 39 - 39: OoOoOO00 + I1Ii111 % O0
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 26 - 26: ooOoO0o + OoOoOO00
  II111I1i1 = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or II111I1i1 ) :
   Iio0o0o = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = Iio0o0o ) . start ( )
   if ( II111I1i1 ) : os . system ( "rm ./log-flows" )
   return
   if 32 - 32: O0 / OOooOOo . ooOoO0o % I1Ii111
   if 18 - 18: IiII * iII111i / I11i / O0
  i1 = datetime . datetime . now ( )
  lisp_flow_log . append ( [ i1 , encap , self . packet , self ] )
  if 11 - 11: iIii1I11I1II1 / Ii1I + OoooooooOO % i1IIi * i11iIiiIii
  if 86 - 86: i11iIiiIii - O0 - i11iIiiIii . iIii1I11I1II1 . IiII
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  Ooooo = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 65 - 65: Oo0Ooo . OoOoOO00 . OOooOOo % o0oOOo0O0Ooo + OoO0O00
  OOO000OOOO0oO = red ( self . outer_source . print_address_no_iid ( ) , False )
  iIIIiiiII = red ( self . outer_dest . print_address_no_iid ( ) , False )
  I1IiiiiIIII = green ( self . inner_source . print_address ( ) , False )
  oo000o = green ( self . inner_dest . print_address ( ) , False )
  if 6 - 6: OOooOOo + I1ii11iIi11i + Oo0Ooo
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   Ooooo += " {}:{} -> {}:{}, LISP control message type {}\n"
   Ooooo = Ooooo . format ( OOO000OOOO0oO , self . udp_sport , iIIIiiiII , self . udp_dport ,
 self . inner_version )
   return ( Ooooo )
   if 52 - 52: IiII * Oo0Ooo + OoooooooOO
   if 93 - 93: ooOoO0o
  if ( self . outer_dest . is_null ( ) == False ) :
   Ooooo += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   Ooooo = Ooooo . format ( OOO000OOOO0oO , self . udp_sport , iIIIiiiII , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 15 - 15: i11iIiiIii / o0oOOo0O0Ooo / OoO0O00 . OoOoOO00 % oO0o
   if 29 - 29: o0oOOo0O0Ooo
   if 13 - 13: Ii1I + Ii1I . I11i
   if 57 - 57: ooOoO0o
   if 94 - 94: OoO0O00 - II111iiii % iIii1I11I1II1
  if ( self . lisp_header . k_bits != 0 ) :
   oOoo0o = "\n"
   if ( self . packet_error != "" ) :
    oOoo0o = " ({})" . format ( self . packet_error ) + oOoo0o
    if 57 - 57: OoooooooOO % II111iiii - I1Ii111
   Ooooo += ", encrypted" + oOoo0o
   return ( Ooooo )
   if 1 - 1: IiII
   if 27 - 27: OoOoOO00 . I1Ii111 * OoOoOO00
   if 8 - 8: oO0o * IiII * ooOoO0o
   if 26 - 26: iII111i * OOooOOo / OOooOOo - iII111i
   if 59 - 59: Ii1I % iII111i / II111iiii + I1IiiI * ooOoO0o
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 100 - 100: I1ii11iIi11i
   if 81 - 81: I1ii11iIi11i % iII111i
  ooo000 = packet [ 9 ] if self . inner_version == 4 else packet [ 6 ]
  ooo000 = struct . unpack ( "B" , ooo000 ) [ 0 ]
  if 22 - 22: OoooooooOO + o0oOOo0O0Ooo . I11i + I1IiiI + OoooooooOO . OoOoOO00
  Ooooo += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  Ooooo = Ooooo . format ( I1IiiiiIIII , oo000o , len ( packet ) , self . inner_tos ,
 self . inner_ttl , ooo000 )
  if 93 - 93: I1IiiI
  if 89 - 89: OoooooooOO % i11iIiiIii + I1Ii111
  if 12 - 12: OoOoOO00 * ooOoO0o
  if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
  if ( ooo000 in [ 6 , 17 ] ) :
   iioOo00O0o = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( iioOo00O0o ) == 4 ) :
    iioOo00O0o = socket . ntohl ( struct . unpack ( "I" , iioOo00O0o ) [ 0 ] )
    Ooooo += ", ports {} -> {}" . format ( iioOo00O0o >> 16 , iioOo00O0o & 0xffff )
    if 18 - 18: ooOoO0o
  elif ( ooo000 == 1 ) :
   IIIi1iiI1I1 = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( IIIi1iiI1I1 ) == 2 ) :
    IIIi1iiI1I1 = socket . ntohs ( struct . unpack ( "H" , IIIi1iiI1I1 ) [ 0 ] )
    Ooooo += ", icmp-seq {}" . format ( IIIi1iiI1I1 )
    if 20 - 20: ooOoO0o + iIii1I11I1II1
    if 60 - 60: iII111i - O0 / II111iiii - oO0o
  if ( self . packet_error != "" ) :
   Ooooo += " ({})" . format ( self . packet_error )
   if 70 - 70: oO0o
  Ooooo += "\n"
  return ( Ooooo )
  if 69 - 69: IiII
  if 67 - 67: Oo0Ooo % II111iiii - OoO0O00 % i1IIi % ooOoO0o
 def is_trace ( self ) :
  iioOo00O0o = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in iioOo00O0o )
  if 31 - 31: iIii1I11I1II1 / OoooooooOO
  if 8 - 8: iIii1I11I1II1 . iIii1I11I1II1 + Ii1I . OOooOOo
  if 58 - 58: iIii1I11I1II1 + I1Ii111 - I1ii11iIi11i - i1IIi * OoOoOO00
  if 4 - 4: OoooooooOO
  if 7 - 7: IiII
  if 26 - 26: OOooOOo + Oo0Ooo
  if 71 - 71: I1IiiI . ooOoO0o
  if 43 - 43: I1ii11iIi11i * OOooOOo
  if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
  if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
  if 51 - 51: OOooOOo / I11i
  if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
  if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
  if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
  if 26 - 26: i11iIiiIii - ooOoO0o
  if 45 - 45: ooOoO0o + II111iiii % iII111i
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 55 - 55: ooOoO0o - oO0o % I1IiiI
class lisp_data_header ( object ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 61 - 61: ooOoO0o
  if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
 def print_header ( self , e_or_d ) :
  II = lisp_hex_string ( self . first_long & 0xffffff )
  o0oO0ooo0 = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 31 - 31: O0 - IiII * i11iIiiIii * i1IIi
  IiiiI1 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 78 - 78: ooOoO0o * OoOoOO00 . Ii1I . OoOoOO00 % iIii1I11I1II1
  return ( IiiiI1 . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 II , o0oO0ooo0 ) )
  if 67 - 67: Ii1I . Oo0Ooo
  if 39 - 39: I11i * I1Ii111
 def encode ( self ) :
  O0oOO0o00OO = "II"
  II = socket . htonl ( self . first_long )
  o0oO0ooo0 = socket . htonl ( self . second_long )
  if 39 - 39: o0oOOo0O0Ooo . i1IIi % oO0o / I11i % O0
  o0O0OOooO = struct . pack ( O0oOO0o00OO , II , o0oO0ooo0 )
  return ( o0O0OOooO )
  if 1 - 1: I1Ii111 * OoO0O00 - iII111i
  if 97 - 97: iII111i . I1ii11iIi11i - iIii1I11I1II1 . ooOoO0o + I1IiiI % oO0o
 def decode ( self , packet ) :
  O0oOO0o00OO = "II"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( False )
  if 99 - 99: IiII % I1Ii111
  II , o0oO0ooo0 = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 61 - 61: O0 + I1IiiI / OoooooooOO * iII111i / II111iiii / iII111i
  if 56 - 56: iII111i * I1ii11iIi11i - II111iiii % I1ii11iIi11i
  self . first_long = socket . ntohl ( II )
  self . second_long = socket . ntohl ( o0oO0ooo0 )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 30 - 30: i11iIiiIii % OoO0O00 * II111iiii - O0 . I1ii11iIi11i * iIii1I11I1II1
  if 48 - 48: o0oOOo0O0Ooo + I1ii11iIi11i / I1ii11iIi11i
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 80 - 80: OoooooooOO
  if 65 - 65: oO0o * i1IIi . OoooooooOO % ooOoO0o
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 87 - 87: i11iIiiIii * II111iiii - Ii1I % OoooooooOO
  if 55 - 55: i1IIi
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 67 - 67: I1IiiI - OoO0O00
  if 60 - 60: i1IIi / iIii1I11I1II1 * oO0o + ooOoO0o + OoooooooOO + II111iiii
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 13 - 13: iIii1I11I1II1 - OOooOOo
  if 14 - 14: ooOoO0o
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 75 - 75: iIii1I11I1II1 % ooOoO0o / OOooOOo - iII111i % i11iIiiIii
  if 11 - 11: I11i . Ii1I
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 87 - 87: OOooOOo + OOooOOo
  if 45 - 45: i1IIi - Oo0Ooo
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 87 - 87: OoOoOO00 - OoO0O00 * OoO0O00 / Ii1I . I11i * o0oOOo0O0Ooo
  if 21 - 21: II111iiii
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 29 - 29: OoOoOO00 % Ii1I
  if 7 - 7: i1IIi / IiII / iII111i
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 97 - 97: OoO0O00 + iIii1I11I1II1
  if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 26 - 26: IiII
  if 52 - 52: O0 + ooOoO0o
  if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
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
  if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
  if 1 - 1: I1IiiI . Ii1I
 def send_ipc ( self , ipc_socket , ipc ) :
  II11IIII1 = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  OO0oooOO = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , II11IIII1 )
  lisp_ipc ( ipc , ipc_socket , OO0oooOO )
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  if 21 - 21: O0 * ooOoO0o % OoO0O00
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  Iii1 = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , Iii1 )
  if 41 - 41: IiII - O0 * oO0o * II111iiii . I11i - I1Ii111
  if 25 - 25: OoooooooOO / I11i % I1Ii111
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  Iii1 = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , Iii1 )
  if 49 - 49: IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . Ii1I * I1ii11iIi11i
  if 17 - 17: I1ii11iIi11i * OoooooooOO % i1IIi % OoooooooOO . iII111i
 def receive_request ( self , ipc_socket , nonce ) :
  iIo0O000O00o = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( iIo0O000O00o != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 38 - 38: OoooooooOO . iII111i
  if 43 - 43: OoooooooOO
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 8 - 8: OOooOOo + I11i . I11i
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 89 - 89: I1ii11iIi11i * I1ii11iIi11i * OoOoOO00 / iII111i
  if 60 - 60: OoO0O00 / iII111i / I1IiiI + oO0o
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 93 - 93: OoooooooOO * Ii1I / O0 + Ii1I - iIii1I11I1II1
  if 6 - 6: IiII - Oo0Ooo - I11i - O0 % OoooooooOO
  if 88 - 88: O0 / o0oOOo0O0Ooo * o0oOOo0O0Ooo . o0oOOo0O0Ooo . O0
  if 27 - 27: i11iIiiIii % iII111i + Ii1I . OOooOOo
  if 9 - 9: OoO0O00
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   I1IIiiiIi1ii11I = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 9 - 9: O0 * Ii1I
   if 54 - 54: I11i % I11i - ooOoO0o
   if ( remote_rloc . address > I1IIiiiIi1ii11I . address ) :
    OoOOOO = "exit"
    self . request_nonce_sent = None
   else :
    OoOOOO = "stay in"
    self . echo_nonce_sent = None
    if 32 - 32: o0oOOo0O0Ooo % II111iiii / o0oOOo0O0Ooo . OOooOOo . o0oOOo0O0Ooo
    if 29 - 29: OoooooooOO % II111iiii % i11iIiiIii - Oo0Ooo
   iIiIII = bold ( "collision" , False )
   OOoOo0O0 = red ( I1IIiiiIi1ii11I . print_address_no_iid ( ) , False )
   OOoooo = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( iIiIII ,
 OOoOo0O0 , OOoooo , OoOOOO ) )
   if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
   if 6 - 6: IiII + I1ii11iIi11i
   if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
   if 13 - 13: iIii1I11I1II1 * o0oOOo0O0Ooo - i11iIiiIii
   if 63 - 63: OoooooooOO * I1Ii111
  if ( self . echo_nonce_sent != None ) :
   o00oO0O000 = self . echo_nonce_sent
   I1i = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( I1i ,
 lisp_hex_string ( o00oO0O000 ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( o00oO0O000 )
   if 50 - 50: Oo0Ooo - o0oOOo0O0Ooo % II111iiii . O0 . oO0o % II111iiii
   if 18 - 18: I11i % OoooooooOO + OoO0O00 / I11i
   if 37 - 37: i1IIi - Ii1I / IiII . II111iiii % ooOoO0o
   if 39 - 39: Ii1I % i11iIiiIii * OoO0O00
   if 23 - 23: OOooOOo + ooOoO0o / i11iIiiIii * Oo0Ooo . OoO0O00
   if 28 - 28: iII111i - o0oOOo0O0Ooo
   if 92 - 92: Oo0Ooo % o0oOOo0O0Ooo - ooOoO0o / ooOoO0o / OoOoOO00
  o00oO0O000 = self . request_nonce_sent
  oo0o0o0o0O = self . last_request_nonce_sent
  if ( o00oO0O000 and oo0o0o0o0O != None ) :
   if ( time . time ( ) - oo0o0o0o0O >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o00oO0O000 ) ) )
    if 83 - 83: I11i / Oo0Ooo
    return ( None )
    if 23 - 23: iIii1I11I1II1
    if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
    if 64 - 64: OoO0O00 / I1IiiI
    if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
    if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
    if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
    if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
    if 8 - 8: o0oOOo0O0Ooo
    if 78 - 78: i1IIi - Oo0Ooo
  if ( o00oO0O000 == None ) :
   o00oO0O000 = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( o00oO0O000 )
   if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
   self . request_nonce_sent = o00oO0O000
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o00oO0O000 ) ) )
   if 42 - 42: I1Ii111
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
   if 80 - 80: OOooOOo
   if 12 - 12: Ii1I
   if 2 - 2: OoooooooOO
   if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
   if ( lisp_i_am_itr == False ) : return ( o00oO0O000 | 0x80000000 )
   self . send_request_ipc ( ipc_socket , o00oO0O000 )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o00oO0O000 ) ) )
   if 46 - 46: O0 % OoooooooOO
   if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
   if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
   if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
   if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
   if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
   if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( o00oO0O000 | 0x80000000 )
  if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
  if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
  Ii1i1 = time . time ( ) - self . last_request_nonce_sent
  oO0oo0O0OOOo0 = self . last_echo_nonce_rcvd
  return ( Ii1i1 >= LISP_NONCE_ECHO_INTERVAL and oO0oo0O0OOOo0 == None )
  if 29 - 29: I1IiiI
  if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
 def recently_requested ( self ) :
  oO0oo0O0OOOo0 = self . last_request_nonce_sent
  if ( oO0oo0O0OOOo0 == None ) : return ( False )
  if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
  Ii1i1 = time . time ( ) - oO0oo0O0OOOo0
  return ( Ii1i1 <= LISP_NONCE_ECHO_INTERVAL )
  if 22 - 22: O0 % IiII % iII111i % I1IiiI
  if 34 - 34: iII111i . Oo0Ooo % I1ii11iIi11i . iII111i % IiII / IiII
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 84 - 84: Ii1I
  if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
  if 9 - 9: iII111i - iII111i
  if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
  oO0oo0O0OOOo0 = self . last_good_echo_nonce_rcvd
  if ( oO0oo0O0OOOo0 == None ) : oO0oo0O0OOOo0 = 0
  Ii1i1 = time . time ( ) - oO0oo0O0OOOo0
  if ( Ii1i1 <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
  if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
  if 41 - 41: I1ii11iIi11i % I1ii11iIi11i + IiII . iII111i % I1Ii111 * ooOoO0o
  if 57 - 57: Ii1I . I1Ii111 . II111iiii % OoooooooOO * O0 + iIii1I11I1II1
  if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
  if 93 - 93: ooOoO0o / OOooOOo * O0
  oO0oo0O0OOOo0 = self . last_new_request_nonce_sent
  if ( oO0oo0O0OOOo0 == None ) : oO0oo0O0OOOo0 = 0
  Ii1i1 = time . time ( ) - oO0oo0O0OOOo0
  return ( Ii1i1 <= LISP_NONCE_ECHO_INTERVAL )
  if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
  if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   OOo0 = bold ( "down" , False )
   iIiiI11II11 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , OOo0 , iIiiI11II11 ) )
   if 75 - 75: I1Ii111 - iII111i . oO0o
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 88 - 88: iII111i - OoooooooOO . ooOoO0o - o0oOOo0O0Ooo / OoOoOO00 % I11i
   if 61 - 61: iII111i + IiII
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 54 - 54: OoooooooOO * I1IiiI % i1IIi . ooOoO0o % Ii1I . I1ii11iIi11i
  if ( self . recently_requested ( ) == False ) :
   o0O0O0oO0o = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , o0O0O0oO0o ) )
   if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 63 - 63: ooOoO0o . OOooOOo
   if 66 - 66: I1IiiI
   if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
 def print_echo_nonce ( self ) :
  o0oOOoOoo = lisp_print_elapsed ( self . last_request_nonce_sent )
  ooO0O = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 55 - 55: OOooOOo - II111iiii - IiII . I11i + oO0o - oO0o
  iI111IIi = lisp_print_elapsed ( self . last_echo_nonce_sent )
  oo0OoO = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  I1iiIi111I = space ( 4 )
  if 28 - 28: O0 * ooOoO0o - o0oOOo0O0Ooo + iIii1I11I1II1 + oO0o
  OoiIIIiIi1I1i = "Nonce-Echoing:\n"
  OoiIIIiIi1I1i += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( I1iiIi111I , o0oOOoOoo , I1iiIi111I , ooO0O )
  if 92 - 92: OoooooooOO % I1IiiI * OoOoOO00 - I11i
  OoiIIIiIi1I1i += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( I1iiIi111I , oo0OoO , I1iiIi111I , iI111IIi )
  if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
  if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
  return ( OoiIIIiIi1I1i )
  if 68 - 68: OoooooooOO * I11i
  if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
  if 40 - 40: iII111i
  if 62 - 62: ooOoO0o / OOooOOo
  if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
  if 92 - 92: I11i % I1Ii111
  if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
  if 94 - 94: I11i
  if 37 - 37: oO0o
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
    if 52 - 52: I1ii11iIi11i * I1IiiI . OOooOOo + i1IIi % oO0o / iIii1I11I1II1
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   IIIOoo = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( IIIOoo )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 68 - 68: I1Ii111 - OoOoOO00 . i11iIiiIii + o0oOOo0O0Ooo
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 71 - 71: i11iIiiIii / i1IIi * I1IiiI / OoOoOO00
  if 33 - 33: I11i . Oo0Ooo
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 89 - 89: iII111i + i1IIi - IiII + ooOoO0o . II111iiii
  if 85 - 85: iIii1I11I1II1 - Ii1I * Oo0Ooo . oO0o + I1Ii111
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 13 - 13: O0 + iIii1I11I1II1 % II111iiii + iIii1I11I1II1
  OoOooO = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   OoOooO = struct . pack ( "Q" , OoOooO & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   OOooo00Ooo0O = struct . pack ( "I" , ( OoOooO >> 64 ) & LISP_4_32_MASK )
   oooOOO0 = struct . pack ( "Q" , OoOooO & LISP_8_64_MASK )
   OoOooO = OOooo00Ooo0O + oooOOO0
  else :
   OoOooO = struct . pack ( "QQ" , OoOooO >> 64 , OoOooO & LISP_8_64_MASK )
  return ( OoOooO )
  if 67 - 67: I1ii11iIi11i + Ii1I * I11i / oO0o
  if 18 - 18: ooOoO0o
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( old_div ( len ( key ) , 2 ) )
  if 92 - 92: OoO0O00 % iIii1I11I1II1 / IiII * iII111i . i1IIi + oO0o
  if 24 - 24: IiII . iII111i * IiII % i11iIiiIii . i11iIiiIii + i1IIi
 def print_key ( self , key ) :
  o00oOOo0Oo = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( o00oOOo0Oo [ 0 : 4 ] , o00oOOo0Oo [ - 4 : : ] , self . key_length ( o00oOOo0Oo ) ) )
  if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
  if 100 - 100: IiII + i1IIi * OoO0O00
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
  if 74 - 74: i1IIi . iIii1I11I1II1
 def print_keys ( self , do_bold = True ) :
  OOoOo0O0 = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   OOoOo0O0 += "none"
  else :
   OOoOo0O0 += self . print_key ( self . local_public_key )
   if 85 - 85: I1IiiI
  OOoooo = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   OOoooo += "none"
  else :
   OOoooo += self . print_key ( self . remote_public_key )
   if 10 - 10: O0 . II111iiii / OoooooooOO
  ooII1 = "ECDH" if ( self . curve25519 ) else "DH"
  o0OOO = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( ooII1 , o0OOO , OOoOo0O0 , OOoooo ) )
  if 38 - 38: I1IiiI * o0oOOo0O0Ooo - OOooOOo % IiII + I11i - Oo0Ooo
  if 55 - 55: iIii1I11I1II1 + OoOoOO00
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 7 - 7: Ii1I / I1Ii111 % ooOoO0o - I1Ii111 * I1IiiI
  if 18 - 18: oO0o - IiII % I11i * Ii1I
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 66 - 66: i1IIi - i1IIi - OOooOOo . I11i
  IIIOoo = self . local_private_key
  o0O0Ooo = self . dh_g_value
  IiIiIII11i1i = self . dh_p_value
  return ( int ( ( o0O0Ooo ** IIIOoo ) % IiIiIII11i1i ) )
  if 95 - 95: II111iiii / Ii1I % I11i - OoooooooOO
  if 45 - 45: OoO0O00 * OoooooooOO / O0 . I1Ii111 / OoOoOO00
 def compute_shared_key ( self , ed , print_shared = False ) :
  IIIOoo = self . local_private_key
  oO0I1ii11i1 = self . remote_public_key
  if 40 - 40: o0oOOo0O0Ooo * IiII / I1ii11iIi11i / I1Ii111 - IiII
  OOo00OOo = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( OOo00OOo , self . print_keys ( ) ) )
  if 64 - 64: iII111i . ooOoO0o % Ii1I
  if ( self . curve25519 ) :
   i1I11 = curve25519 . Public ( oO0I1ii11i1 )
   self . shared_key = self . curve25519 . get_shared_key ( i1I11 )
  else :
   IiIiIII11i1i = self . dh_p_value
   self . shared_key = ( oO0I1ii11i1 ** IIIOoo ) % IiIiIII11i1i
   if 58 - 58: O0
   if 84 - 84: i1IIi
   if 73 - 73: i11iIiiIii * I1ii11iIi11i . I11i % I1IiiI - I1IiiI . OoOoOO00
   if 66 - 66: oO0o / i11iIiiIii / OoOoOO00 + I1ii11iIi11i / O0
   if 97 - 97: i11iIiiIii
   if 16 - 16: i1IIi
   if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  if ( print_shared ) :
   o00oOOo0Oo = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( o00oOOo0Oo ) )
   if 41 - 41: OoooooooOO
   if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
   if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
   if 78 - 78: Ii1I
   if 29 - 29: II111iiii
  self . compute_encrypt_icv_keys ( )
  if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
  if 84 - 84: Oo0Ooo % I11i * O0 * I11i
  if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
  if 12 - 12: Oo0Ooo + I1IiiI
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 37 - 37: i1IIi * i11iIiiIii
  if 95 - 95: i11iIiiIii % I1Ii111 * Oo0Ooo + i1IIi . O0 + I1ii11iIi11i
 def compute_encrypt_icv_keys ( self ) :
  II1iiiiI1Ii11 = hashlib . sha256
  if ( self . curve25519 ) :
   O0oo = self . shared_key
  else :
   O0oo = lisp_hex_string ( self . shared_key )
   if 13 - 13: OoO0O00 * I1Ii111 + Oo0Ooo - IiII
   if 31 - 31: OoO0O00
   if 68 - 68: OoO0O00 + i1IIi / iIii1I11I1II1 + II111iiii * iIii1I11I1II1 + I1ii11iIi11i
   if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
   if 9 - 9: o0oOOo0O0Ooo
  OOoOo0O0 = self . local_public_key
  if ( type ( OOoOo0O0 ) != int ) : OOoOo0O0 = int ( binascii . hexlify ( OOoOo0O0 ) , 16 )
  OOoooo = self . remote_public_key
  if ( type ( OOoooo ) != int ) : OOoooo = int ( binascii . hexlify ( OOoooo ) , 16 )
  O0Ooo000Ooo = "0001" + "lisp-crypto" + lisp_hex_string ( OOoOo0O0 ^ OOoooo ) + "0100"
  if 46 - 46: i1IIi + O0
  IIii1iooOOOOOo = hmac . new ( O0Ooo000Ooo , O0oo , II1iiiiI1Ii11 ) . hexdigest ( )
  IIii1iooOOOOOo = int ( IIii1iooOOOOOo , 16 )
  if 3 - 3: i11iIiiIii
  if 20 - 20: i1IIi * iII111i + OoO0O00 * OoO0O00 / Oo0Ooo
  if 83 - 83: I1ii11iIi11i
  if 53 - 53: OoOoOO00 % ooOoO0o . OoO0O00 + I1IiiI / I1ii11iIi11i
  OO = ( IIii1iooOOOOOo >> 128 ) & LISP_16_128_MASK
  ooOOO = IIii1iooOOOOOo & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( OO ) . zfill ( 32 )
  o00Oooo0o0 = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( ooOOO ) . zfill ( o00Oooo0o0 )
  if 5 - 5: iII111i - iII111i / I1Ii111 % Oo0Ooo
  if 61 - 61: oO0o - I1ii11iIi11i / iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   iiIii = self . icv . poly1305aes
   i111 = self . icv . binascii . hexlify
   nonce = i111 ( nonce )
   O0Oo00oO0OoO = iiIii ( self . encrypt_key , self . icv_key , nonce , packet )
   O0Oo00oO0OoO = i111 ( O0Oo00oO0OoO )
  else :
   IIIOoo = binascii . unhexlify ( self . icv_key )
   O0Oo00oO0OoO = hmac . new ( IIIOoo , packet , self . icv ) . hexdigest ( )
   O0Oo00oO0OoO = O0Oo00oO0OoO [ 0 : 40 ]
   if 52 - 52: OoooooooOO - O0 . OOooOOo . iII111i . oO0o
  return ( O0Oo00oO0OoO )
  if 10 - 10: I1Ii111 * i1IIi % Ii1I % I1ii11iIi11i - Ii1I * OoO0O00
  if 15 - 15: ooOoO0o
 def add_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 97 - 97: oO0o - I1Ii111 * iII111i - ooOoO0o * I1Ii111
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 90 - 90: Ii1I . OoOoOO00
  if 89 - 89: I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
 def delete_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 44 - 44: OoooooooOO
  if 82 - 82: OoOoOO00 . OoOoOO00
 def add_key_by_rloc ( self , addr_str , encap ) :
  IIiIiIii11I1 = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 60 - 60: OoooooooOO * Oo0Ooo % I1Ii111
  if 68 - 68: O0 - Oo0Ooo . II111iiii % Ii1I % Oo0Ooo + i11iIiiIii
  if ( addr_str not in IIiIiIii11I1 ) :
   IIiIiIii11I1 [ addr_str ] = [ None , None , None , None ]
   if 90 - 90: II111iiii / OOooOOo * I1IiiI - Oo0Ooo
  IIiIiIii11I1 [ addr_str ] [ self . key_id ] = self
  if 11 - 11: IiII - oO0o - oO0o / I1Ii111 * II111iiii % oO0o
  if 39 - 39: oO0o / i11iIiiIii
  if 46 - 46: i11iIiiIii . I1ii11iIi11i
  if 11 - 11: ooOoO0o
  if 36 - 36: OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , IIiIiIii11I1 [ addr_str ] )
   if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
   if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
   if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
 def encode_lcaf ( self , rloc_addr ) :
  O0ooOo = self . normalize_pub_key ( self . local_public_key )
  Iiooooo = self . key_length ( O0ooOo )
  iiIIi = ( 6 + Iiooooo + 2 )
  if ( rloc_addr != None ) : iiIIi += rloc_addr . addr_length ( )
  if 76 - 76: I11i * iIii1I11I1II1 % II111iiii
  OO0 = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( iiIIi ) , 1 , 0 )
  if 54 - 54: o0oOOo0O0Ooo - I11i * OoOoOO00 * O0 - O0
  if 28 - 28: Ii1I * oO0o * oO0o * I1Ii111
  if 55 - 55: iII111i - ooOoO0o / oO0o + OoO0O00
  if 94 - 94: IiII / I1IiiI . II111iiii
  if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
  if 37 - 37: OOooOOo + O0 + OOooOOo . iII111i . o0oOOo0O0Ooo
  o0OOO = self . cipher_suite
  OO0 += struct . pack ( "BBH" , o0OOO , 0 , socket . htons ( Iiooooo ) )
  if 78 - 78: I1IiiI / I11i + o0oOOo0O0Ooo . Oo0Ooo / O0
  if 49 - 49: I1ii11iIi11i
  if 66 - 66: o0oOOo0O0Ooo . I1ii11iIi11i
  if 18 - 18: Oo0Ooo + IiII
  for OoOOoO0oOo in range ( 0 , Iiooooo * 2 , 16 ) :
   IIIOoo = int ( O0ooOo [ OoOOoO0oOo : OoOOoO0oOo + 16 ] , 16 )
   OO0 += struct . pack ( "Q" , byte_swap_64 ( IIIOoo ) )
   if 79 - 79: OoO0O00 - O0 + II111iiii % Ii1I . I1IiiI
   if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
   if 31 - 31: Ii1I / iII111i
   if 3 - 3: IiII
   if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
  if ( rloc_addr ) :
   OO0 += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   OO0 += rloc_addr . pack_address ( )
   if 61 - 61: OOooOOo . OOooOOo
  return ( OO0 )
  if 17 - 17: II111iiii / ooOoO0o
  if 80 - 80: OOooOOo * OoO0O00 + Ii1I
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 62 - 62: OoooooooOO . O0 % Oo0Ooo
  if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
  if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
  if 88 - 88: I1Ii111 - OoO0O00
  if ( lcaf_len == 0 ) :
   O0oOO0o00OO = "HHBBH"
   Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
   if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
   if 79 - 79: iII111i
   ii11IiI , Iii1i1 , oo0OoOOO , Iii1i1 , lcaf_len = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
   if 76 - 76: I1ii11iIi11i
   if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
   if ( oo0OoOOO != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
   if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
   if 82 - 82: OoO0O00
   if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
   if 17 - 17: OoOoOO00
   if 72 - 72: iII111i . Oo0Ooo - i11iIiiIii / I1IiiI
   if 64 - 64: oO0o
  oo0OoOOO = LISP_LCAF_SECURITY_TYPE
  O0oOO0o00OO = "BBBBH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 80 - 80: o0oOOo0O0Ooo % iIii1I11I1II1
  o0o0000O0OOo , Iii1i1 , o0OOO , Iii1i1 , Iiooooo = struct . unpack ( O0oOO0o00OO ,
 packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 91 - 91: OoooooooOO + I1Ii111 / II111iiii * iII111i + o0oOOo0O0Ooo / Oo0Ooo
  if 7 - 7: I11i / i11iIiiIii - Ii1I % iII111i
  if 67 - 67: iIii1I11I1II1 - OoOoOO00
  if 51 - 51: I11i * I1ii11iIi11i % I1ii11iIi11i + o0oOOo0O0Ooo
  if 16 - 16: O0 % I1IiiI * iIii1I11I1II1 - II111iiii + iIii1I11I1II1 + Oo0Ooo
  if 4 - 4: I11i
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  Iiooooo = socket . ntohs ( Iiooooo )
  if ( len ( packet ) < Iiooooo ) : return ( None )
  if 60 - 60: II111iiii + I1Ii111 / oO0o % OoooooooOO - i1IIi
  if 57 - 57: ooOoO0o
  if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if 52 - 52: I1ii11iIi11i
  o0oI1 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( o0OOO not in o0oI1 ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( o0oI1 ,
 o0OOO ) )
   packet = packet [ Iiooooo : : ]
   return ( packet )
   if 39 - 39: I1Ii111 . oO0o - OOooOOo
   if 56 - 56: Oo0Ooo + O0 . Oo0Ooo / II111iiii % I1Ii111
  self . cipher_suite = o0OOO
  if 24 - 24: oO0o * O0 - i11iIiiIii - OoOoOO00
  if 43 - 43: oO0o * I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
  if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  if 44 - 44: i11iIiiIii
  if 69 - 69: OOooOOo * O0 + i11iIiiIii
  O0ooOo = 0
  for OoOOoO0oOo in range ( 0 , Iiooooo , 8 ) :
   IIIOoo = byte_swap_64 ( struct . unpack ( "Q" , packet [ OoOOoO0oOo : OoOOoO0oOo + 8 ] ) [ 0 ] )
   O0ooOo <<= 64
   O0ooOo |= IIIOoo
   if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
  self . remote_public_key = O0ooOo
  if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
  if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
  if 63 - 63: oO0o
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
  if ( self . curve25519 ) :
   IIIOoo = lisp_hex_string ( self . remote_public_key )
   IIIOoo = IIIOoo . zfill ( 64 )
   oo00O0OO0oo0O = ""
   for OoOOoO0oOo in range ( 0 , len ( IIIOoo ) , 2 ) :
    oo00O0OO0oo0O += chr ( int ( IIIOoo [ OoOOoO0oOo : OoOOoO0oOo + 2 ] , 16 ) )
    if 1 - 1: Oo0Ooo * O0 . I1IiiI + ooOoO0o / OoOoOO00 + I11i
   self . remote_public_key = oo00O0OO0oo0O
   if 68 - 68: II111iiii
   if 61 - 61: OOooOOo . I1ii11iIi11i * oO0o / I1Ii111 - OoO0O00
  packet = packet [ Iiooooo : : ]
  return ( packet )
  if 18 - 18: I1Ii111
  if 34 - 34: iII111i + I1Ii111 * I11i / II111iiii
  if 14 - 14: II111iiii + iII111i + Ii1I / iII111i . iIii1I11I1II1
  if 85 - 85: I11i % I11i . O0
  if 40 - 40: OoO0O00 * OoOoOO00 * iIii1I11I1II1 / OoOoOO00 * OoooooooOO / I1ii11iIi11i
  if 33 - 33: i11iIiiIii % o0oOOo0O0Ooo . iII111i * OOooOOo / I11i
  if 25 - 25: OoO0O00
  if 39 - 39: Ii1I * OoOoOO00 + Oo0Ooo . OOooOOo - O0 * I1ii11iIi11i
class lisp_thread ( object ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
  if 98 - 98: IiII * iII111i . OoooooooOO . O0
  if 89 - 89: iII111i / O0 % OoooooooOO - O0 . OoO0O00
  if 32 - 32: ooOoO0o
  if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
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
  if 38 - 38: I1Ii111 % OOooOOo
  if 9 - 9: O0 . iIii1I11I1II1
 def decode ( self , packet ) :
  O0oOO0o00OO = "BBBBQ"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( False )
  if 44 - 44: I1ii11iIi11i % IiII
  i11iii1 , II1iIIii1I111 , I1IIii1iiI1I1 , self . record_count , self . nonce = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 78 - 78: OOooOOo
  if 58 - 58: I1IiiI
  self . type = i11iii1 >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( i11iii1 & 0x01 ) else False
   self . rloc_probe = True if ( i11iii1 & 0x02 ) else False
   self . smr_invoked_bit = True if ( II1iIIii1I111 & 0x40 ) else False
   if 94 - 94: o0oOOo0O0Ooo + Ii1I % o0oOOo0O0Ooo . I1Ii111 - ooOoO0o * I1IiiI
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( i11iii1 & 0x04 ) else False
   self . to_etr = True if ( i11iii1 & 0x02 ) else False
   self . to_ms = True if ( i11iii1 & 0x01 ) else False
   if 62 - 62: Oo0Ooo * i1IIi % I1ii11iIi11i + Oo0Ooo . O0 . ooOoO0o
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( i11iii1 & 0x08 ) else False
   if 57 - 57: Oo0Ooo - I1Ii111 + O0 % o0oOOo0O0Ooo
  return ( True )
  if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
  if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 50 - 50: OoooooooOO * i1IIi / oO0o
  if 83 - 83: i1IIi
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 38 - 38: OoooooooOO * iIii1I11I1II1
  if 54 - 54: OoooooooOO . I1Ii111
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 71 - 71: Ii1I
  if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
  if 93 - 93: ooOoO0o % I1Ii111
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  if 43 - 43: ooOoO0o . i1IIi
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
  if 45 - 45: I1IiiI
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
  if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
  if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
  if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
  if 61 - 61: Oo0Ooo - I1Ii111
  if 51 - 51: iII111i * ooOoO0o / O0 / O0
  if 52 - 52: OoooooooOO % O0
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
  if 78 - 78: oO0o % OoooooooOO
  if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
 def print_map_register ( self ) :
  ooOOoOO000 = lisp_hex_string ( self . xtr_id )
  if 79 - 79: OoO0O00 / o0oOOo0O0Ooo
  IiiiI1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 98 - 98: i11iIiiIii . i11iIiiIii * OoooooooOO
  lprint ( IiiiI1 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # iIii1I11I1II1 % OoooooooOO - Oo0Ooo * O0
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , ooOOoOO000 , self . site_id ) )
  if 50 - 50: O0
  if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
  if 71 - 71: Ii1I * OoOoOO00
  if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
 def encode ( self ) :
  II = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : II |= 0x08000000
  if ( self . lisp_sec_present ) : II |= 0x04000000
  if ( self . xtr_id_present ) : II |= 0x02000000
  if ( self . map_register_refresh ) : II |= 0x1000
  if ( self . use_ttl_for_timeout ) : II |= 0x800
  if ( self . merge_register_requested ) : II |= 0x400
  if ( self . mobile_node ) : II |= 0x200
  if ( self . map_notify_requested ) : II |= 0x100
  if ( self . encryption_key_id != None ) :
   II |= 0x2000
   II |= self . encryption_key_id << 14
   if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
   if 87 - 87: OoO0O00 * Oo0Ooo
   if 83 - 83: i1IIi * I1Ii111 - IiII / Ii1I
   if 48 - 48: oO0o . II111iiii - OoOoOO00 % i1IIi . OoOoOO00
   if 32 - 32: Ii1I * I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 67 - 67: OoOoOO00 % Oo0Ooo
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
    if 73 - 73: I1ii11iIi11i
    if 92 - 92: i11iIiiIii + O0 * I11i
  OO0 = struct . pack ( "I" , socket . htonl ( II ) )
  OO0 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 60 - 60: o0oOOo0O0Ooo / Oo0Ooo
  OO0 = self . zero_auth ( OO0 )
  return ( OO0 )
  if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
  if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
 def zero_auth ( self , packet ) :
  IiI1ii1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  oOOOOOOooOOoO = ""
  o0o000OOO = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oOOOOOOooOOoO = struct . pack ( "QQI" , 0 , 0 , 0 )
   o0o000OOO = struct . calcsize ( "QQI" )
   if 36 - 36: I1Ii111 * I1Ii111 % I1IiiI % O0 . I1IiiI % OoooooooOO
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oOOOOOOooOOoO = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   o0o000OOO = struct . calcsize ( "QQQQ" )
   if 96 - 96: oO0o % iIii1I11I1II1 / iIii1I11I1II1 . iII111i . Ii1I
  packet = packet [ 0 : IiI1ii1Ii ] + oOOOOOOooOOoO + packet [ IiI1ii1Ii + o0o000OOO : : ]
  return ( packet )
  if 49 - 49: I1ii11iIi11i * I1Ii111 + OoOoOO00
  if 72 - 72: OoO0O00
 def encode_auth ( self , packet ) :
  IiI1ii1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  o0o000OOO = self . auth_len
  oOOOOOOooOOoO = self . auth_data
  packet = packet [ 0 : IiI1ii1Ii ] + oOOOOOOooOOoO + packet [ IiI1ii1Ii + o0o000OOO : : ]
  return ( packet )
  if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
  if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
 def decode ( self , packet ) :
  o0O0OoOOo0o = packet
  O0oOO0o00OO = "I"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( [ None , None ] )
  if 21 - 21: I11i - I1IiiI / OoooooooOO . i1IIi + II111iiii
  II = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  II = socket . ntohl ( II [ 0 ] )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
  O0oOO0o00OO = "QBBH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( [ None , None ] )
  if 34 - 34: I1Ii111 * I11i
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 31 - 31: IiII . oO0o
  if 40 - 40: Ii1I - I11i / II111iiii * i1IIi + IiII * II111iiii
  self . nonce = byte_swap_64 ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( II & 0x08000000 ) else False
  if 53 - 53: I1ii11iIi11i - i11iIiiIii . OoO0O00 / OoOoOO00 - I1Ii111
  self . lisp_sec_present = True if ( II & 0x04000000 ) else False
  self . xtr_id_present = True if ( II & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( II & 0x800 ) else False
  self . map_register_refresh = True if ( II & 0x1000 ) else False
  self . merge_register_requested = True if ( II & 0x400 ) else False
  self . mobile_node = True if ( II & 0x200 ) else False
  self . map_notify_requested = True if ( II & 0x100 ) else False
  self . record_count = II & 0xff
  if 99 - 99: Ii1I - IiII - i1IIi / i11iIiiIii . IiII
  if 58 - 58: OOooOOo
  if 12 - 12: I1IiiI . o0oOOo0O0Ooo * OoooooooOO
  if 64 - 64: OoOoOO00 + IiII - i1IIi . II111iiii . OoO0O00
  self . encrypt_bit = True if II & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( II >> 14 ) & 0x7
   if 31 - 31: oO0o . iII111i - I11i . iIii1I11I1II1 + I11i . OoOoOO00
   if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
   if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
   if 30 - 30: OoooooooOO % OOooOOo
   if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( o0O0OoOOo0o ) == False ) : return ( [ None , None ] )
   if 81 - 81: iII111i % Ii1I . ooOoO0o
   if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
  if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
  if 20 - 20: ooOoO0o
  if 63 - 63: iIii1I11I1II1 . OoO0O00
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 100 - 100: i1IIi * i1IIi
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
    if 94 - 94: IiII
   o0o000OOO = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    Ii1i1iiiIiIIiIiiii = struct . calcsize ( "QQI" )
    if ( o0o000OOO < Ii1i1iiiIiIIiIiiii ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 15 - 15: Ii1I - IiII / O0
    i1i11iii11 , I11111i , i1i = struct . unpack ( "QQI" , packet [ : o0o000OOO ] )
    o00o0O0o0O0 = ""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    Ii1i1iiiIiIIiIiiii = struct . calcsize ( "QQQQ" )
    if ( o0o000OOO < Ii1i1iiiIiIIiIiiii ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 33 - 33: Ii1I . oO0o
    i1i11iii11 , I11111i , i1i , o00o0O0o0O0 = struct . unpack ( "QQQQ" ,
 packet [ : o0o000OOO ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 87 - 87: Oo0Ooo . o0oOOo0O0Ooo - OoooooooOO * oO0o % IiII + O0
    return ( [ None , None ] )
    if 16 - 16: I1ii11iIi11i % Oo0Ooo % II111iiii % II111iiii
   self . auth_data = lisp_concat_auth_data ( self . alg_id , i1i11iii11 , I11111i ,
 i1i , o00o0O0o0O0 )
   o0O0OoOOo0o = self . zero_auth ( o0O0OoOOo0o )
   packet = packet [ self . auth_len : : ]
   if 51 - 51: OoOoOO00 * OoOoOO00 - O0 % iIii1I11I1II1 / O0
  return ( [ o0O0OoOOo0o , packet ] )
  if 5 - 5: i11iIiiIii * ooOoO0o % iII111i - I11i
  if 5 - 5: O0 * IiII * OOooOOo + I1Ii111 % Oo0Ooo - I1ii11iIi11i
 def encode_xtr_id ( self , packet ) :
  oO00oo = self . xtr_id >> 64
  I1iIii1iii11i = self . xtr_id & 0xffffffffffffffff
  oO00oo = byte_swap_64 ( oO00oo )
  I1iIii1iii11i = byte_swap_64 ( I1iIii1iii11i )
  o00oOo0oO0oOO = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , oO00oo , I1iIii1iii11i , o00oOo0oO0oOO )
  return ( packet )
  if 51 - 51: II111iiii / OoooooooOO . oO0o * Oo0Ooo
  if 51 - 51: IiII - OOooOOo / OoOoOO00
 def decode_xtr_id ( self , packet ) :
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - Ii1i1iiiIiIIiIiiii : : ]
  oO00oo , I1iIii1iii11i , o00oOo0oO0oOO = struct . unpack ( "QQQ" ,
 packet [ : Ii1i1iiiIiIIiIiiii ] )
  oO00oo = byte_swap_64 ( oO00oo )
  I1iIii1iii11i = byte_swap_64 ( I1iIii1iii11i )
  self . xtr_id = ( oO00oo << 64 ) | I1iIii1iii11i
  self . site_id = byte_swap_64 ( o00oOo0oO0oOO )
  return ( True )
  if 63 - 63: oO0o + I1Ii111 / I1IiiI - OoooooooOO / OoOoOO00 * Ii1I
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
  if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
  if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
 def print_notify ( self ) :
  oOOOOOOooOOoO = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( oOOOOOOooOOoO ) != 40 ) :
   oOOOOOOooOOoO = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( oOOOOOOooOOoO ) != 64 ) :
   oOOOOOOooOOoO = self . auth_data
   if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
  IiiiI1 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( IiiiI1 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # O0 - i1IIi / I1ii11iIi11i - OoooooooOO * oO0o / OOooOOo
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , oOOOOOOooOOoO ) )
  if 63 - 63: OoO0O00
  if 30 - 30: IiII
  if 3 - 3: Ii1I + OoO0O00
  if 60 - 60: OoO0O00 . OoOoOO00 - I1ii11iIi11i - I1IiiI - II111iiii % Oo0Ooo
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oOOOOOOooOOoO = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oOOOOOOooOOoO = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 47 - 47: I1Ii111 + I1IiiI
  packet += oOOOOOOooOOoO
  return ( packet )
  if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
  if 80 - 80: oO0o
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   II = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   II = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 81 - 81: OoooooooOO / ooOoO0o * iIii1I11I1II1 . Oo0Ooo + oO0o / O0
  OO0 = struct . pack ( "I" , socket . htonl ( II ) )
  OO0 += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 84 - 84: II111iiii - o0oOOo0O0Ooo
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = OO0 + eid_records
   return ( self . packet )
   if 78 - 78: IiII
   if 58 - 58: i11iIiiIii - OoOoOO00
   if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
   if 99 - 99: ooOoO0o . Ii1I
   if 92 - 92: i1IIi
  OO0 = self . zero_auth ( OO0 )
  OO0 += eid_records
  if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
  O0o0oo0 = lisp_hash_me ( OO0 , self . alg_id , password , False )
  if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
  IiI1ii1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  o0o000OOO = self . auth_len
  self . auth_data = O0o0oo0
  OO0 = OO0 [ 0 : IiI1ii1Ii ] + O0o0oo0 + OO0 [ IiI1ii1Ii + o0o000OOO : : ]
  self . packet = OO0
  return ( OO0 )
  if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
  if 4 - 4: Ii1I
 def decode ( self , packet ) :
  o0O0OoOOo0o = packet
  O0oOO0o00OO = "I"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
  II = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  II = socket . ntohl ( II [ 0 ] )
  self . map_notify_ack = ( ( II >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = II & 0xff
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
  O0oOO0o00OO = "QBBH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 32 - 32: I1Ii111 / oO0o / I1IiiI
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 69 - 69: oO0o - I1IiiI
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
  if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
  if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
  if 35 - 35: I1ii11iIi11i % OoooooooOO
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 59 - 59: I1IiiI % I11i
  o0o000OOO = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   i1i11iii11 , I11111i , i1i = struct . unpack ( "QQI" , packet [ : o0o000OOO ] )
   o00o0O0o0O0 = ""
   if 32 - 32: I1IiiI * O0 + O0
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   i1i11iii11 , I11111i , i1i , o00o0O0o0O0 = struct . unpack ( "QQQQ" ,
 packet [ : o0o000OOO ] )
   if 34 - 34: IiII
  self . auth_data = lisp_concat_auth_data ( self . alg_id , i1i11iii11 , I11111i ,
 i1i , o00o0O0o0O0 )
  if 5 - 5: OoO0O00 . I1IiiI
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( o0O0OoOOo0o [ : Ii1i1iiiIiIIiIiiii ] )
  Ii1i1iiiIiIIiIiiii += o0o000OOO
  packet += o0O0OoOOo0o [ Ii1i1iiiIiIIiIiiii : : ]
  return ( packet )
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
  if 66 - 66: IiII * oO0o
  if 73 - 73: i11iIiiIii + O0 % O0
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
 def print_map_request ( self ) :
  ooOOoOO000 = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   ooOOoOO000 = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 18 - 18: OoOoOO00
   if 30 - 30: II111iiii
   if 27 - 27: i1IIi - iIii1I11I1II1 + O0 % Oo0Ooo / OOooOOo + i1IIi
  IiiiI1 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 48 - 48: Oo0Ooo
  lprint ( IiiiI1 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # I1Ii111 / i11iIiiIii . Ii1I - IiII / OoO0O00
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , ooOOoOO000 ) )
  if 14 - 14: ooOoO0o / i11iIiiIii - oO0o + i11iIiiIii
  Oo0Oo = self . keys
  for i11iII in self . itr_rlocs :
   if ( i11iII . afi == LISP_AFI_LCAF and self . json_telemetry != None ) :
    continue
    if 9 - 9: OoOoOO00 . iIii1I11I1II1 . Oo0Ooo - o0oOOo0O0Ooo . IiII
   oo0o = red ( i11iII . print_address_no_iid ( ) , False )
   lprint ( "  itr-rloc: afi {} {}{}" . format ( i11iII . afi , oo0o ,
 "" if ( Oo0Oo == None ) else ", " + Oo0Oo [ 1 ] . print_keys ( ) ) )
   Oo0Oo = None
   if 93 - 93: Ii1I % iIii1I11I1II1 * iII111i / OoOoOO00 * i11iIiiIii
  if ( self . json_telemetry != None ) :
   lprint ( "  itr-rloc: afi {} telemetry: {}" . format ( LISP_AFI_LCAF ,
 self . json_telemetry ) )
   if 26 - 26: ooOoO0o . iII111i
   if 76 - 76: I1Ii111 % OoooooooOO
   if 15 - 15: I1IiiI . I1ii11iIi11i / iIii1I11I1II1 % I11i
 def sign_map_request ( self , privkey ) :
  Oo00OoOoo = self . signature_eid . print_address ( )
  o0O = self . source_eid . print_address ( )
  i1i1i11IIii = self . target_eid . print_address ( )
  I1I = lisp_hex_string ( self . nonce ) + o0O + i1i1i11IIii
  self . map_request_signature = privkey . sign ( I1I )
  oOO0oOOOOO0 = binascii . b2a_base64 ( self . map_request_signature )
  oOO0oOOOOO0 = { "source-eid" : o0O , "signature-eid" : Oo00OoOoo ,
 "signature" : oOO0oOOOOO0 }
  return ( json . dumps ( oOO0oOOOOO0 ) )
  if 99 - 99: OoOoOO00 . I1Ii111 * II111iiii - i11iIiiIii + I11i
  if 44 - 44: ooOoO0o * i11iIiiIii . iII111i / iIii1I11I1II1
 def verify_map_request_sig ( self , pubkey ) :
  i11111 = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( i11111 ) )
   return ( False )
   if 21 - 21: iIii1I11I1II1 % I1IiiI / o0oOOo0O0Ooo / o0oOOo0O0Ooo
   if 28 - 28: OoooooooOO . ooOoO0o / II111iiii + I11i / O0 . OoooooooOO
  o0O = self . source_eid . print_address ( )
  i1i1i11IIii = self . target_eid . print_address ( )
  I1I = lisp_hex_string ( self . nonce ) + o0O + i1i1i11IIii
  pubkey = binascii . a2b_base64 ( pubkey )
  if 75 - 75: iIii1I11I1II1 * I1Ii111 . i11iIiiIii
  iio0Ooo = True
  try :
   IIIOoo = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 1 - 1: Ii1I - iIii1I11I1II1 * Ii1I . i11iIiiIii
   iio0Ooo = False
   if 96 - 96: Ii1I + iII111i - OoOoOO00 . I11i * o0oOOo0O0Ooo - Ii1I
   if 73 - 73: Oo0Ooo - I11i - ooOoO0o / I1Ii111 * IiII
  if ( iio0Ooo ) :
   try :
    iio0Ooo = IIIOoo . verify ( self . map_request_signature , I1I )
   except :
    iio0Ooo = False
    if 55 - 55: i1IIi / I1Ii111 . iII111i
    if 98 - 98: i1IIi % O0 . ooOoO0o * O0
    if 10 - 10: OOooOOo / Oo0Ooo - o0oOOo0O0Ooo / ooOoO0o % ooOoO0o / OoooooooOO
  IIiii1Ii = bold ( "passed" if iio0Ooo else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( IIiii1Ii , i11111 ) )
  return ( iio0Ooo )
  if 59 - 59: OoO0O00 * O0 . iIii1I11I1II1 . I11i * iII111i
  if 71 - 71: o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i - Ii1I
 def encode_json ( self , json_string ) :
  oo0OoOOO = LISP_LCAF_JSON_TYPE
  ooOOooooo0Oo = socket . htons ( LISP_AFI_LCAF )
  I1ii = socket . htons ( len ( json_string ) + 4 )
  i1IiI11I11I = socket . htons ( len ( json_string ) )
  OO0 = struct . pack ( "HBBBBHH" , ooOOooooo0Oo , 0 , 0 , oo0OoOOO , 0 , I1ii ,
 i1IiI11I11I )
  OO0 += json_string
  OO0 += struct . pack ( "H" , 0 )
  return ( OO0 )
  if 2 - 2: iIii1I11I1II1 * OoOoOO00 . O0 / OoO0O00
  if 3 - 3: I1ii11iIi11i
 def encode ( self , probe_dest , probe_port ) :
  II = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  if 53 - 53: I11i . OoooooooOO % ooOoO0o
  IIIiIiIIII1i1 = lisp_telemetry_configured ( ) if ( self . rloc_probe ) else None
  if ( IIIiIiIIII1i1 != None ) : self . itr_rloc_count += 1
  II = II | ( self . itr_rloc_count << 8 )
  if 90 - 90: I1IiiI % ooOoO0o % OoooooooOO / OoO0O00 . IiII * II111iiii
  if ( self . auth_bit ) : II |= 0x08000000
  if ( self . map_data_present ) : II |= 0x04000000
  if ( self . rloc_probe ) : II |= 0x02000000
  if ( self . smr_bit ) : II |= 0x01000000
  if ( self . pitr_bit ) : II |= 0x00800000
  if ( self . smr_invoked_bit ) : II |= 0x00400000
  if ( self . mobile_node ) : II |= 0x00200000
  if ( self . xtr_id_present ) : II |= 0x00100000
  if ( self . local_xtr ) : II |= 0x00004000
  if ( self . dont_reply_bit ) : II |= 0x00002000
  if 83 - 83: oO0o
  OO0 = struct . pack ( "I" , socket . htonl ( II ) )
  OO0 += struct . pack ( "Q" , self . nonce )
  if 34 - 34: OoOoOO00
  if 75 - 75: I11i / iIii1I11I1II1 + I1ii11iIi11i / OoO0O00
  if 50 - 50: I1Ii111 / I11i % iIii1I11I1II1
  if 46 - 46: ooOoO0o + iII111i - Oo0Ooo % OOooOOo + OoooooooOO + iIii1I11I1II1
  if 99 - 99: OoO0O00 - IiII * IiII + oO0o / iII111i + OOooOOo
  if 58 - 58: i11iIiiIii + iIii1I11I1II1 * o0oOOo0O0Ooo - OoOoOO00
  i11i = False
  iIiii1Ii1I = self . privkey_filename
  if ( iIiii1Ii1I != None and os . path . exists ( iIiii1Ii1I ) ) :
   I1Ii = open ( iIiii1Ii1I , "r" ) ; IIIOoo = I1Ii . read ( ) ; I1Ii . close ( )
   try :
    IIIOoo = ecdsa . SigningKey . from_pem ( IIIOoo )
   except :
    return ( None )
    if 29 - 29: iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / OoOoOO00 - i11iIiiIii
   o00O = self . sign_map_request ( IIIOoo )
   i11i = True
  elif ( self . map_request_signature != None ) :
   oOO0oOOOOO0 = binascii . b2a_base64 ( self . map_request_signature )
   o00O = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : oOO0oOOOOO0 }
   o00O = json . dumps ( o00O )
   i11i = True
   if 87 - 87: o0oOOo0O0Ooo % iII111i / ooOoO0o - IiII + i11iIiiIii
  if ( i11i ) :
   OO0 += self . encode_json ( o00O )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    OO0 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    OO0 += self . source_eid . lcaf_encode_iid ( )
   else :
    OO0 += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    OO0 += self . source_eid . pack_address ( )
    if 85 - 85: OoooooooOO * IiII . OOooOOo / iII111i / OoooooooOO
    if 87 - 87: OoO0O00
    if 32 - 32: i11iIiiIii - OoOoOO00 * I11i . Oo0Ooo * ooOoO0o
    if 21 - 21: OOooOOo
    if 11 - 11: oO0o % i11iIiiIii * O0
    if 28 - 28: I1Ii111 / iIii1I11I1II1 + OOooOOo . I1ii11iIi11i % OOooOOo + OoO0O00
    if 79 - 79: oO0o
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   Oo0o = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 39 - 39: I1Ii111 % oO0o % O0 % O0 - iII111i - oO0o
   if ( Oo0o in lisp_crypto_keys_by_rloc_encap ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ Oo0o ]
    if 83 - 83: i11iIiiIii + iIii1I11I1II1
    if 21 - 21: o0oOOo0O0Ooo / i11iIiiIii % I1Ii111
    if 56 - 56: o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
    if 11 - 11: OOooOOo
    if 12 - 12: OoooooooOO * OOooOOo * I1ii11iIi11i * ooOoO0o
    if 26 - 26: OoooooooOO . i1IIi + OoO0O00
    if 42 - 42: i11iIiiIii * o0oOOo0O0Ooo % I11i % Oo0Ooo + o0oOOo0O0Ooo * i11iIiiIii
  for i11iII in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( i11iII ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     Oo0Oo = lisp_keys ( 1 )
     self . keys = [ None , Oo0Oo , None , None ]
     if 66 - 66: Ii1I / IiII . OoooooooOO * Oo0Ooo % i11iIiiIii
    Oo0Oo = self . keys [ 1 ]
    Oo0Oo . add_key_by_nonce ( self . nonce )
    OO0 += Oo0Oo . encode_lcaf ( i11iII )
   else :
    OO0 += struct . pack ( "H" , socket . htons ( i11iII . afi ) )
    OO0 += i11iII . pack_address ( )
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
   OO0 += self . encode_json ( IIIiIiIIII1i1 )
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
  O0oOO0o00OO = "BB"
  OO0 += struct . pack ( O0oOO0o00OO , ii1I11 , I1iIii11iIi1I )
  if 76 - 76: i1IIi % I1IiiI + i1IIi
  if ( self . target_group . is_null ( ) == False ) :
   OO0 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   OO0 += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   OO0 += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   OO0 += self . target_eid . lcaf_encode_iid ( )
  else :
   OO0 += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   OO0 += self . target_eid . pack_address ( )
   if 2 - 2: iII111i + iII111i
   if 51 - 51: OoooooooOO + i11iIiiIii
   if 57 - 57: Oo0Ooo % o0oOOo0O0Ooo
   if 99 - 99: o0oOOo0O0Ooo / i11iIiiIii / II111iiii + OOooOOo . i1IIi + OoOoOO00
   if 7 - 7: I1IiiI / ooOoO0o % OoO0O00 + oO0o . o0oOOo0O0Ooo / I11i
  if ( self . subscribe_bit ) : OO0 = self . encode_xtr_id ( OO0 )
  return ( OO0 )
  if 84 - 84: OOooOOo + II111iiii . o0oOOo0O0Ooo * Oo0Ooo
  if 68 - 68: Ii1I % Ii1I
 def lcaf_decode_json ( self , packet ) :
  O0oOO0o00OO = "BBBBHH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 26 - 26: o0oOOo0O0Ooo . Ii1I * OoOoOO00
  Oo0OoooOoO0O0 , iIi1i , oo0OoOOO , OooIiii1ii , I1ii , i1IiI11I11I = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 77 - 77: OOooOOo % oO0o + iIii1I11I1II1 * Ii1I . IiII . Oo0Ooo
  if 29 - 29: I1ii11iIi11i + OoooooooOO . OoO0O00 . i1IIi - OoooooooOO * i11iIiiIii
  if ( oo0OoOOO != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 19 - 19: I1ii11iIi11i * O0 - ooOoO0o
  if 27 - 27: iII111i / o0oOOo0O0Ooo . OoOoOO00 * Ii1I * I1Ii111
  if 81 - 81: I1Ii111
  if 45 - 45: OOooOOo * II111iiii * OoooooooOO / OoooooooOO * I1Ii111
  I1ii = socket . ntohs ( I1ii )
  i1IiI11I11I = socket . ntohs ( i1IiI11I11I )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
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
  O0oOO0o00OO = "H"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  ii11IiI = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if ( ii11IiI != 0 ) : return ( packet )
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
  ii11IiI = LISP_AFI_IPV4 if oo0oO . count ( "." ) == 3 else LISP_AFI_IPV6 if oo0oO . count ( ":" ) == 7 else None
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00
  if ( ii11IiI == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( oo0oO ) )
   return ( None )
   if 92 - 92: OoOoOO00 . Oo0Ooo * I11i
   if 86 - 86: O0
  self . source_eid . afi = ii11IiI
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
  oOO0oOOOOO0 = binascii . a2b_base64 ( o00O [ "signature" ] )
  self . map_request_signature = oOO0oOOOOO0
  return ( packet )
  if 34 - 34: I11i % iII111i - ooOoO0o - I1IiiI
  if 44 - 44: Ii1I . o0oOOo0O0Ooo . iIii1I11I1II1 + OoooooooOO - I1IiiI
 def decode ( self , packet , source , port ) :
  O0oOO0o00OO = "I"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 22 - 22: I11i * I1ii11iIi11i . OoooooooOO / Oo0Ooo / Ii1I
  II = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  II = II [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 54 - 54: I1Ii111 % Ii1I + ooOoO0o
  O0oOO0o00OO = "Q"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 45 - 45: Ii1I / oO0o * I1Ii111 . Ii1I
  o00oO0O000 = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 25 - 25: I1ii11iIi11i / I1ii11iIi11i
  II = socket . ntohl ( II )
  self . auth_bit = True if ( II & 0x08000000 ) else False
  self . map_data_present = True if ( II & 0x04000000 ) else False
  self . rloc_probe = True if ( II & 0x02000000 ) else False
  self . smr_bit = True if ( II & 0x01000000 ) else False
  self . pitr_bit = True if ( II & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( II & 0x00400000 ) else False
  self . mobile_node = True if ( II & 0x00200000 ) else False
  self . xtr_id_present = True if ( II & 0x00100000 ) else False
  self . local_xtr = True if ( II & 0x00004000 ) else False
  self . dont_reply_bit = True if ( II & 0x00002000 ) else False
  self . itr_rloc_count = ( ( II >> 8 ) & 0x1f )
  self . record_count = II & 0xff
  self . nonce = o00oO0O000 [ 0 ]
  if 79 - 79: Oo0Ooo - OoO0O00 % Oo0Ooo . II111iiii
  if 84 - 84: ooOoO0o * OoooooooOO + O0
  if 84 - 84: i1IIi . I11i . i1IIi . Oo0Ooo
  if 21 - 21: II111iiii . O0 + Oo0Ooo - i11iIiiIii
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 5 - 5: iIii1I11I1II1 * i11iIiiIii + OoO0O00 + I11i * O0 % ooOoO0o
   if 88 - 88: o0oOOo0O0Ooo / i11iIiiIii * I1ii11iIi11i
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( "H" )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 23 - 23: O0 / iII111i
  ii11IiI = struct . unpack ( "H" , packet [ : Ii1i1iiiIiIIiIiiii ] )
  self . source_eid . afi = socket . ntohs ( ii11IiI [ 0 ] )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
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
   Ii1i1iiiIiIIiIiiii = struct . calcsize ( "H" )
   if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
   if 51 - 51: I1ii11iIi11i / OoooooooOO * IiII
   ii11IiI = socket . ntohs ( struct . unpack ( "H" , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ] )
   i11iII = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   i11iII . afi = ii11IiI
   if 78 - 78: iII111i / I1ii11iIi11i . i11iIiiIii
   if 69 - 69: I11i - II111iiii
   if 66 - 66: I1IiiI . I1IiiI - OoOoOO00 * OoooooooOO * II111iiii + I1IiiI
   if 59 - 59: Ii1I
   if 59 - 59: II111iiii - OoO0O00
   if ( i11iII . afi == LISP_AFI_LCAF ) :
    o0O0OoOOo0o = packet
    I1iI1IiII = packet [ Ii1i1iiiIiIIiIiiii : : ]
    packet = self . lcaf_decode_json ( I1iI1IiII )
    if ( packet == None ) : return ( None )
    if ( packet == I1iI1IiII ) : packet = o0O0OoOOo0o
    if 38 - 38: OOooOOo + IiII * OoO0O00 / OoOoOO00
    if 68 - 68: I1ii11iIi11i / ooOoO0o % O0
    if 66 - 66: Oo0Ooo . oO0o - O0 . I1Ii111 + iII111i / i11iIiiIii
    if 52 - 52: oO0o % Oo0Ooo * II111iiii
    if 24 - 24: i11iIiiIii * i1IIi * i1IIi
    if 27 - 27: i1IIi - oO0o + OOooOOo
   if ( i11iII . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < i11iII . addr_length ( ) ) : return ( None )
    packet = i11iII . unpack_address ( packet [ Ii1i1iiiIiIIiIiiii : : ] )
    if ( packet == None ) : return ( None )
    if 3 - 3: IiII % I1Ii111 . OoooooooOO
    if ( I11IIii ) :
     self . itr_rlocs . append ( i11iII )
     Iii1i -= 1
     continue
     if 19 - 19: I1Ii111 * Ii1I - oO0o
     if 78 - 78: OoO0O00 - Ii1I / OOooOOo
    Oo0o = lisp_build_crypto_decap_lookup_key ( i11iII , port )
    if 81 - 81: OoOoOO00
    if 21 - 21: iII111i / OOooOOo % IiII
    if 51 - 51: I11i + ooOoO0o / I1IiiI
    if 3 - 3: iIii1I11I1II1 / OOooOOo % oO0o . Ii1I - Ii1I
    if 55 - 55: i11iIiiIii % OoooooooOO + O0
    if ( lisp_nat_traversal and i11iII . is_private_address ( ) and source ) : i11iII = source
    if 7 - 7: ooOoO0o - i11iIiiIii * iII111i / Ii1I - o0oOOo0O0Ooo
    OOooo000 = lisp_crypto_keys_by_rloc_decap
    if ( Oo0o in OOooo000 ) : OOooo000 . pop ( Oo0o )
    if 78 - 78: I11i . I1Ii111
    if 54 - 54: II111iiii / II111iiii + I11i . OOooOOo - OOooOOo
    if 98 - 98: Ii1I
    if 96 - 96: oO0o * i11iIiiIii
    if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
    if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
    lisp_write_ipc_decap_key ( Oo0o , None )
    if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
   elif ( self . json_telemetry == None ) :
    if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
    if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
    if 64 - 64: IiII
    if 21 - 21: o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO
    o0O0OoOOo0o = packet
    II111i1I = lisp_keys ( 1 )
    packet = II111i1I . decode_lcaf ( o0O0OoOOo0o , 0 )
    if 2 - 2: o0oOOo0O0Ooo
    if ( packet == None ) : return ( None )
    if 58 - 58: oO0o - II111iiii + O0
    if 54 - 54: iIii1I11I1II1 - IiII - IiII
    if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
    if 63 - 63: iII111i - OoO0O00 * OOooOOo
    o0oI1 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( II111i1I . cipher_suite in o0oI1 ) :
     if ( II111i1I . cipher_suite == LISP_CS_25519_CBC or
 II111i1I . cipher_suite == LISP_CS_25519_GCM ) :
      IIIOoo = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 89 - 89: iII111i / Oo0Ooo
     if ( II111i1I . cipher_suite == LISP_CS_25519_CHACHA ) :
      IIIOoo = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 66 - 66: o0oOOo0O0Ooo + OoOoOO00 % OoooooooOO . I11i
    else :
     IIIOoo = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 30 - 30: II111iiii - Oo0Ooo - i11iIiiIii + O0
    packet = IIIOoo . decode_lcaf ( o0O0OoOOo0o , 0 )
    if ( packet == None ) : return ( None )
    if 93 - 93: i1IIi + I1Ii111 / OoO0O00 - I11i % Oo0Ooo / Ii1I
    if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
    ii11IiI = struct . unpack ( "H" , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
    i11iII . afi = socket . ntohs ( ii11IiI )
    if ( len ( packet ) < i11iII . addr_length ( ) ) : return ( None )
    if 1 - 1: Oo0Ooo / Ii1I . i11iIiiIii % OOooOOo + o0oOOo0O0Ooo + O0
    packet = i11iII . unpack_address ( packet [ Ii1i1iiiIiIIiIiiii : : ] )
    if ( packet == None ) : return ( None )
    if 54 - 54: I1Ii111 + ooOoO0o % IiII
    if ( I11IIii ) :
     self . itr_rlocs . append ( i11iII )
     Iii1i -= 1
     continue
     if 83 - 83: o0oOOo0O0Ooo * iIii1I11I1II1
     if 36 - 36: OoOoOO00 + II111iiii - OoO0O00 % ooOoO0o * i1IIi
    Oo0o = lisp_build_crypto_decap_lookup_key ( i11iII , port )
    if 4 - 4: Ii1I + OoO0O00 * I1ii11iIi11i
    II111iii = None
    if ( lisp_nat_traversal and i11iII . is_private_address ( ) and source ) : i11iII = source
    if 61 - 61: OoO0O00 . i11iIiiIii - OoO0O00
    if 8 - 8: I1ii11iIi11i * IiII / Oo0Ooo
    if ( Oo0o in lisp_crypto_keys_by_rloc_decap ) :
     Oo0Oo = lisp_crypto_keys_by_rloc_decap [ Oo0o ]
     II111iii = Oo0Oo [ 1 ] if Oo0Oo and Oo0Oo [ 1 ] else None
     if 99 - 99: OOooOOo * I1Ii111 . ooOoO0o - i1IIi - I11i % IiII
     if 40 - 40: OoOoOO00 % I1Ii111 / I1IiiI + i1IIi
    o000ooOo0o0Oo = True
    if ( II111iii ) :
     if ( II111iii . compare_keys ( IIIOoo ) ) :
      self . keys = [ None , II111iii , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( Oo0o , False ) ) )
      if 90 - 90: ooOoO0o . OOooOOo
     else :
      o000ooOo0o0Oo = False
      o0o00O000 = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( o0o00O000 , red ( Oo0o ,
 False ) ) )
      IIIOoo . copy_keypair ( II111iii )
      IIIOoo . uptime = II111iii . uptime
      II111iii = None
      if 57 - 57: i1IIi . iII111i
      if 50 - 50: oO0o
      if 55 - 55: I1ii11iIi11i
    if ( II111iii == None ) :
     self . keys = [ None , IIIOoo , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      IIIOoo . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( Oo0o , False ) ) )
     elif ( IIIOoo . remote_public_key != None ) :
      if ( o000ooOo0o0Oo ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # iII111i - OoooooooOO + I1Ii111 % iIii1I11I1II1
 red ( Oo0o , False ) ) )
       if 91 - 91: oO0o * O0
      IIIOoo . compute_shared_key ( "decap" )
      IIIOoo . add_key_by_rloc ( Oo0o , False )
      if 19 - 19: I1ii11iIi11i / OoO0O00 + oO0o
      if 81 - 81: I1Ii111 / I1Ii111 + ooOoO0o - Ii1I
      if 93 - 93: ooOoO0o . o0oOOo0O0Ooo + O0 * i1IIi - OoO0O00 * OoO0O00
      if 11 - 11: ooOoO0o - Ii1I . oO0o * Ii1I
   self . itr_rlocs . append ( i11iII )
   Iii1i -= 1
   if 85 - 85: i1IIi
   if 94 - 94: OoooooooOO . O0 / OoooooooOO
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( "BBH" )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 67 - 67: i11iIiiIii + OoOoOO00
  ii1I11 , I1iIii11iIi1I , ii11IiI = struct . unpack ( "BBH" , packet [ : Ii1i1iiiIiIIiIiiii ] )
  self . subscribe_bit = ( ii1I11 & 0x80 )
  self . target_eid . afi = socket . ntohs ( ii11IiI )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 50 - 50: ooOoO0o . i1IIi + I1ii11iIi11i . OOooOOo
  self . target_eid . mask_len = I1iIii11iIi1I
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , oO0Ooo = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( oO0Ooo ) : self . target_group = oO0Ooo
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
   if 49 - 49: II111iiii . OoooooooOO
  return ( packet )
  if 30 - 30: OoO0O00 / i11iIiiIii - OoO0O00 / ooOoO0o + iIii1I11I1II1 + i1IIi
  if 99 - 99: OOooOOo * I1IiiI + oO0o % oO0o % OOooOOo * IiII
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 98 - 98: OOooOOo
  if 97 - 97: o0oOOo0O0Ooo
 def encode_xtr_id ( self , packet ) :
  oO00oo = self . xtr_id >> 64
  I1iIii1iii11i = self . xtr_id & 0xffffffffffffffff
  oO00oo = byte_swap_64 ( oO00oo )
  I1iIii1iii11i = byte_swap_64 ( I1iIii1iii11i )
  packet += struct . pack ( "QQ" , oO00oo , I1iIii1iii11i )
  return ( packet )
  if 35 - 35: ooOoO0o + i11iIiiIii
  if 82 - 82: i11iIiiIii + I11i + iII111i % I1IiiI
 def decode_xtr_id ( self , packet ) :
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( "QQ" )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  packet = packet [ len ( packet ) - Ii1i1iiiIiIIiIiiii : : ]
  oO00oo , I1iIii1iii11i = struct . unpack ( "QQ" , packet [ : Ii1i1iiiIiIIiIiiii ] )
  oO00oo = byte_swap_64 ( oO00oo )
  I1iIii1iii11i = byte_swap_64 ( I1iIii1iii11i )
  self . xtr_id = ( oO00oo << 64 ) | I1iIii1iii11i
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
  II = ( LISP_MAP_REPLY << 28 ) | self . record_count
  II |= self . hop_count << 8
  if ( self . rloc_probe ) : II |= 0x08000000
  if ( self . echo_nonce_capable ) : II |= 0x04000000
  if ( self . security ) : II |= 0x02000000
  if 13 - 13: i1IIi . I1IiiI
  OO0 = struct . pack ( "I" , socket . htonl ( II ) )
  OO0 += struct . pack ( "Q" , self . nonce )
  return ( OO0 )
  if 45 - 45: ooOoO0o % I11i
  if 37 - 37: iII111i
 def decode ( self , packet ) :
  O0oOO0o00OO = "I"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 70 - 70: O0 + iIii1I11I1II1 % O0 * o0oOOo0O0Ooo - Oo0Ooo - ooOoO0o
  II = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  II = II [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 94 - 94: i1IIi + IiII / OoooooooOO - oO0o / OOooOOo / OoOoOO00
  O0oOO0o00OO = "Q"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 55 - 55: OOooOOo
  o00oO0O000 = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 5 - 5: I11i / OoOoOO00
  II = socket . ntohl ( II )
  self . rloc_probe = True if ( II & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( II & 0x04000000 ) else False
  self . security = True if ( II & 0x02000000 ) else False
  self . hop_count = ( II >> 8 ) & 0xff
  self . record_count = II & 0xff
  self . nonce = o00oO0O000 [ 0 ]
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
  ii11IiI = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  IiiiI1 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 34 - 34: I1ii11iIi11i - i11iIiiIii
  lprint ( IiiiI1 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 iIIIII1iiI , "auth" if ( self . authoritative is True ) else "non-auth" ,
 OOiiI1iii1I , o0ooo , self . map_version , ii11IiI ,
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
  ii11IiI = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( ii11IiI < 0 ) : ii11IiI = LISP_AFI_LCAF
  OoO0o0 = ( self . group . is_null ( ) == False )
  if ( OoO0o0 ) : ii11IiI = LISP_AFI_LCAF
  if 79 - 79: I1IiiI - IiII . OoooooooOO - I1ii11iIi11i
  OO0Oo0 = ( self . signature_count << 12 ) | self . map_version
  I1iIii11iIi1I = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 65 - 65: Oo0Ooo * ooOoO0o % i11iIiiIii
  OO0 = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , I1iIii11iIi1I , socket . htons ( Oo0Oo00O000O ) ,
 socket . htons ( OO0Oo0 ) , socket . htons ( ii11IiI ) )
  if 12 - 12: OoOoOO00 . I1ii11iIi11i . Oo0Ooo
  if 61 - 61: I11i / OOooOOo
  if 85 - 85: OoOoOO00 - I11i . OoOoOO00 . OoOoOO00
  if 62 - 62: IiII % OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % iII111i
  if ( OoO0o0 ) :
   OO0 += self . eid . lcaf_encode_sg ( self . group )
   return ( OO0 )
   if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
   if 68 - 68: I11i - i11iIiiIii / o0oOOo0O0Ooo + ooOoO0o / I1IiiI
   if 31 - 31: I1Ii111 . OoooooooOO . i1IIi
   if 65 - 65: OoO0O00 . ooOoO0o
   if 12 - 12: I1Ii111 + O0 - oO0o . IiII
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   OO0 = OO0 [ 0 : - 2 ]
   OO0 += self . eid . address . encode_geo ( )
   return ( OO0 )
   if 46 - 46: IiII . ooOoO0o / iII111i
   if 63 - 63: II111iiii - I1ii11iIi11i * II111iiii
   if 92 - 92: OoO0O00 % ooOoO0o * O0 % iIii1I11I1II1 / i1IIi / OoOoOO00
   if 67 - 67: I1Ii111 + I11i + I1Ii111 . OOooOOo % o0oOOo0O0Ooo / ooOoO0o
   if 78 - 78: I1ii11iIi11i . O0
  if ( ii11IiI == LISP_AFI_LCAF ) :
   OO0 += self . eid . lcaf_encode_iid ( )
   return ( OO0 )
   if 56 - 56: oO0o - i1IIi * O0 / I11i * I1IiiI . I11i
   if 54 - 54: i11iIiiIii % i1IIi + Oo0Ooo / OoOoOO00
   if 26 - 26: I11i . I1ii11iIi11i
   if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
   if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
  OO0 += self . eid . pack_address ( )
  return ( OO0 )
  if 28 - 28: O0 % iII111i - i1IIi
  if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
 def decode ( self , packet ) :
  O0oOO0o00OO = "IBBHHH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
  self . record_ttl , self . rloc_count , self . eid . mask_len , Oo0Oo00O000O , self . map_version , self . eid . afi = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
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
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
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
  II = ( LISP_ECM << 28 )
  if ( self . security ) : II |= 0x08000000
  if ( self . ddt ) : II |= 0x04000000
  if ( self . to_etr ) : II |= 0x02000000
  if ( self . to_ms ) : II |= 0x01000000
  if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
  O000O = struct . pack ( "I" , socket . htonl ( II ) )
  if 22 - 22: II111iiii
  o0OO00oo0O = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   o0OO00oo0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   o0OO00oo0O += self . source . pack_address ( )
   o0OO00oo0O += self . dest . pack_address ( )
   o0OO00oo0O = lisp_ip_checksum ( o0OO00oo0O )
   if 55 - 55: i11iIiiIii
  if ( self . afi == LISP_AFI_IPV6 ) :
   o0OO00oo0O = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   o0OO00oo0O += self . source . pack_address ( )
   o0OO00oo0O += self . dest . pack_address ( )
   if 29 - 29: OOooOOo - i11iIiiIii % IiII / OoooooooOO
   if 92 - 92: I1ii11iIi11i
  I1iiIi111I = socket . htons ( self . udp_sport )
  iiIi = socket . htons ( self . udp_dport )
  OOoOo0O0 = socket . htons ( self . udp_length )
  iIiIII = socket . htons ( self . udp_checksum )
  Ii1iiI1 = struct . pack ( "HHHH" , I1iiIi111I , iiIi , OOoOo0O0 , iIiIII )
  return ( O000O + o0OO00oo0O + Ii1iiI1 )
  if 89 - 89: OoO0O00 * i11iIiiIii - IiII * i1IIi - ooOoO0o . Ii1I
  if 26 - 26: I1IiiI * OoooooooOO / I1IiiI . O0 . ooOoO0o + O0
 def decode ( self , packet ) :
  if 84 - 84: I1Ii111 . O0 + O0 % O0 % i1IIi + iIii1I11I1II1
  if 71 - 71: iII111i / iIii1I11I1II1 . OOooOOo * i11iIiiIii
  if 98 - 98: O0 % iIii1I11I1II1 . IiII - II111iiii
  if 14 - 14: Ii1I % ooOoO0o - OoOoOO00
  O0oOO0o00OO = "I"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 52 - 52: OoO0O00 / i1IIi - Ii1I
  II = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 8 - 8: oO0o + ooOoO0o . I1ii11iIi11i . i1IIi / I1IiiI . IiII
  II = socket . ntohl ( II [ 0 ] )
  self . security = True if ( II & 0x08000000 ) else False
  self . ddt = True if ( II & 0x04000000 ) else False
  self . to_etr = True if ( II & 0x02000000 ) else False
  self . to_ms = True if ( II & 0x01000000 ) else False
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 8 - 8: i1IIi * O0
  if 60 - 60: Oo0Ooo - II111iiii + I1IiiI
  if 17 - 17: OoOoOO00 % I1IiiI
  if 8 - 8: Oo0Ooo
  if ( len ( packet ) < 1 ) : return ( None )
  iiIIiI1I = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  iiIIiI1I = iiIIiI1I >> 4
  if 49 - 49: OoOoOO00 * I11i - o0oOOo0O0Ooo / OoO0O00 * oO0o
  if ( iiIIiI1I == 4 ) :
   Ii1i1iiiIiIIiIiiii = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
   if 51 - 51: ooOoO0o - iIii1I11I1II1 . I11i * OoOoOO00 + I1Ii111 * i1IIi
   I1iIiiI1IIi1 , OOoOo0O0 , I1iIiiI1IIi1 , I1oo0O0Ooo0O00 , IiIiIII11i1i , iIiIII = struct . unpack ( "HHIBBH" , packet [ : Ii1i1iiiIiIIiIiiii ] )
   self . length = socket . ntohs ( OOoOo0O0 )
   self . ttl = I1oo0O0Ooo0O00
   self . protocol = IiIiIII11i1i
   self . ip_checksum = socket . ntohs ( iIiIII )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 1 - 1: OoO0O00 % OOooOOo - iII111i * iIii1I11I1II1
   if 14 - 14: OoOoOO00
   if 17 - 17: Oo0Ooo . OoooooooOO % I1ii11iIi11i / OoooooooOO
   if 56 - 56: OoOoOO00 - IiII
   IiIiIII11i1i = struct . pack ( "H" , 0 )
   oOooo0oOo = struct . calcsize ( "HHIBB" )
   I1Ii11i111 = struct . calcsize ( "H" )
   packet = packet [ : oOooo0oOo ] + IiIiIII11i1i + packet [ oOooo0oOo + I1Ii11i111 : ]
   if 17 - 17: I1Ii111 - I1Ii111 . oO0o / I1Ii111
   packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 36 - 36: I1ii11iIi11i * i1IIi + iIii1I11I1II1
   if 55 - 55: I1IiiI . I1Ii111 - I1IiiI % oO0o / iIii1I11I1II1 * Ii1I
  if ( iiIIiI1I == 6 ) :
   Ii1i1iiiIiIIiIiiii = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
   if 77 - 77: OOooOOo
   I1iIiiI1IIi1 , OOoOo0O0 , IiIiIII11i1i , I1oo0O0Ooo0O00 = struct . unpack ( "IHBB" , packet [ : Ii1i1iiiIiIIiIiiii ] )
   self . length = socket . ntohs ( OOoOo0O0 )
   self . protocol = IiIiIII11i1i
   self . ttl = I1oo0O0Ooo0O00
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 29 - 29: II111iiii % iIii1I11I1II1 * O0 . o0oOOo0O0Ooo
   packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 56 - 56: i1IIi . ooOoO0o + I11i - i11iIiiIii
   if 100 - 100: iIii1I11I1II1 - i1IIi . OOooOOo
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 73 - 73: I1Ii111 / I11i / i11iIiiIii - I1ii11iIi11i % ooOoO0o
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 92 - 92: I1IiiI - o0oOOo0O0Ooo % I1ii11iIi11i / iII111i % oO0o
  I1iiIi111I , iiIi , OOoOo0O0 , iIiIII = struct . unpack ( "HHHH" , packet [ : Ii1i1iiiIiIIiIiiii ] )
  self . udp_sport = socket . ntohs ( I1iiIi111I )
  self . udp_dport = socket . ntohs ( iiIi )
  self . udp_length = socket . ntohs ( OOoOo0O0 )
  self . udp_checksum = socket . ntohs ( iIiIII )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
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
  iiIIii = self . print_rloc_name ( )
  if ( iiIIii != "" ) : iiIIii = ", " + iiIIii
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
 red ( self . rloc . print_address_no_iid ( ) , False ) , iiIIii , OooO0OO0o ,
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
  oO0ooOo = 0
  if ( lisp_json . json_encrypted ) :
   oO0ooOo = ( lisp_json . json_key_id << 5 ) | 0x02
   if 10 - 10: OoOoOO00 * ooOoO0o / iIii1I11I1II1 . OOooOOo
   if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
  oo0OoOOO = LISP_LCAF_JSON_TYPE
  ooOOooooo0Oo = socket . htons ( LISP_AFI_LCAF )
  IIO0Oo = self . rloc . addr_length ( ) + 2
  if 23 - 23: I11i * I1Ii111 / i11iIiiIii / II111iiii
  I1ii = socket . htons ( len ( o00O ) + IIO0Oo )
  if 32 - 32: I1ii11iIi11i - I1Ii111 * I1ii11iIi11i / Ii1I
  i1IiI11I11I = socket . htons ( len ( o00O ) )
  OO0 = struct . pack ( "HBBBBHH" , ooOOooooo0Oo , 0 , 0 , oo0OoOOO , oO0ooOo ,
 I1ii , i1IiI11I11I )
  OO0 += o00O
  if 24 - 24: o0oOOo0O0Ooo
  if 49 - 49: OoO0O00 - iII111i / I1ii11iIi11i % OoooooooOO
  if 96 - 96: I1Ii111 % oO0o . O0 + i1IIi / O0
  if 91 - 91: I11i
  if ( lisp_is_json_telemetry ( o00O ) ) :
   OO0 += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   OO0 += self . rloc . pack_address ( )
  else :
   OO0 += struct . pack ( "H" , 0 )
   if 69 - 69: OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
  return ( OO0 )
  if 54 - 54: ooOoO0o - O0 + iII111i
  if 34 - 34: Ii1I - OOooOOo % iII111i
 def encode_lcaf ( self ) :
  ooOOooooo0Oo = socket . htons ( LISP_AFI_LCAF )
  iIii1iii1 = ""
  if ( self . geo ) :
   iIii1iii1 = self . geo . encode_geo ( )
   if 80 - 80: I11i + o0oOOo0O0Ooo - I1Ii111 . OoO0O00 * oO0o + OOooOOo
   if 96 - 96: i1IIi + i1IIi * I1ii11iIi11i . Oo0Ooo * Oo0Ooo
  OoOOo0Oo0o0 = ""
  if ( self . elp ) :
   OoO00oo0OOOo = ""
   for o00Oo0 in self . elp . elp_nodes :
    ii11IiI = socket . htons ( o00Oo0 . address . afi )
    iIi1i = 0
    if ( o00Oo0 . eid ) : iIi1i |= 0x4
    if ( o00Oo0 . probe ) : iIi1i |= 0x2
    if ( o00Oo0 . strict ) : iIi1i |= 0x1
    iIi1i = socket . htons ( iIi1i )
    OoO00oo0OOOo += struct . pack ( "HH" , iIi1i , ii11IiI )
    OoO00oo0OOOo += o00Oo0 . address . pack_address ( )
    if 8 - 8: II111iiii - iII111i . oO0o / O0
    if 48 - 48: Oo0Ooo
   Ii111 = socket . htons ( len ( OoO00oo0OOOo ) )
   OoOOo0Oo0o0 = struct . pack ( "HBBBBH" , ooOOooooo0Oo , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , Ii111 )
   OoOOo0Oo0o0 += OoO00oo0OOOo
   if 24 - 24: Ii1I - OoOoOO00 . I11i / oO0o
   if 16 - 16: IiII % iII111i . oO0o . I1IiiI % O0 * I11i
  OOOo0 = ""
  if ( self . rle ) :
   OOo0OOoo00 = ""
   for oO0oOOOO0oO0o0 in self . rle . rle_nodes :
    ii11IiI = socket . htons ( oO0oOOOO0oO0o0 . address . afi )
    OOo0OOoo00 += struct . pack ( "HBBH" , 0 , 0 , oO0oOOOO0oO0o0 . level , ii11IiI )
    OOo0OOoo00 += oO0oOOOO0oO0o0 . address . pack_address ( )
    if ( oO0oOOOO0oO0o0 . rloc_name ) :
     OOo0OOoo00 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     OOo0OOoo00 += oO0oOOOO0oO0o0 . rloc_name + "\0"
     if 58 - 58: I1Ii111 - ooOoO0o . oO0o
     if 87 - 87: oO0o + I1IiiI * I1Ii111 * o0oOOo0O0Ooo + O0
     if 21 - 21: I1Ii111 + OoOoOO00 + OoOoOO00 . II111iiii / I1Ii111 . I1IiiI
   O0oO00o0O0 = socket . htons ( len ( OOo0OOoo00 ) )
   OOOo0 = struct . pack ( "HBBBBH" , ooOOooooo0Oo , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , O0oO00o0O0 )
   OOOo0 += OOo0OOoo00
   if 19 - 19: I1Ii111 / O0
   if 55 - 55: II111iiii / ooOoO0o / II111iiii * OOooOOo
  o00oO = ""
  if ( self . json ) :
   o00oO = self . encode_json ( self . json )
   if 44 - 44: O0 * o0oOOo0O0Ooo % OOooOOo
   if 98 - 98: oO0o / iIii1I11I1II1 - OoOoOO00
  I1Ii1i111I = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   I1Ii1i111I = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 51 - 51: O0 + Ii1I * OoooooooOO . oO0o + OoooooooOO
   if 58 - 58: ooOoO0o . Oo0Ooo / I1ii11iIi11i + OoO0O00 * OoooooooOO / I1IiiI
  iii11i11 = ""
  if ( self . rloc_name ) :
   iii11i11 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   iii11i11 += self . rloc_name + "\0"
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
  OO0 = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( iIi1i ) ,
 socket . htons ( self . rloc . afi ) )
  if 81 - 81: Ii1I . I1IiiI % o0oOOo0O0Ooo . OoOoOO00
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 94 - 94: oO0o % Oo0Ooo + OoO0O00 * oO0o - i11iIiiIii / I11i
   OO0 = OO0 [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   OO0 += self . rloc . pack_address ( )
   if 46 - 46: IiII - OoO0O00 * iII111i . I1Ii111 - ooOoO0o . i1IIi
  return ( OO0 )
  if 53 - 53: I1Ii111 * I1IiiI + Oo0Ooo + I1IiiI + OOooOOo
  if 8 - 8: i11iIiiIii + OoOoOO00 . I1ii11iIi11i / OoooooooOO % II111iiii
 def decode_lcaf ( self , packet , nonce , ms_json_encrypt ) :
  O0oOO0o00OO = "HBBBBH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 21 - 21: oO0o - o0oOOo0O0Ooo + ooOoO0o . I1IiiI * oO0o * Ii1I
  ii11IiI , Oo0OoooOoO0O0 , iIi1i , oo0OoOOO , OooIiii1ii , I1ii = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
  if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
  I1ii = socket . ntohs ( I1ii )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if ( I1ii > len ( packet ) ) : return ( None )
  if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
  if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
  if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
  if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
  if ( oo0OoOOO == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( I1ii > 0 ) :
    O0oOO0o00OO = "H"
    Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
    if ( I1ii < Ii1i1iiiIiIIiIiiii ) : return ( None )
    if 86 - 86: IiII
    Ooo000 = len ( packet )
    ii11IiI = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
    ii11IiI = socket . ntohs ( ii11IiI )
    if 71 - 71: Ii1I - i1IIi . I1IiiI
    if ( ii11IiI == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
     self . rloc_name = None
     if ( ii11IiI == LISP_AFI_NAME ) :
      packet , i1Ii1iiI = lisp_decode_dist_name ( packet )
      self . rloc_name = i1Ii1iiI
     else :
      self . rloc . afi = ii11IiI
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
      if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
      if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
    I1ii -= Ooo000 - len ( packet )
    if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
    if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
  elif ( oo0OoOOO == LISP_LCAF_GEO_COORD_TYPE ) :
   if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
   if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
   if 87 - 87: I1IiiI + OoooooooOO + O0
   if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
   o00OOOoooo00 = lisp_geo ( "" )
   packet = o00OOOoooo00 . decode_geo ( packet , I1ii , OooIiii1ii )
   if ( packet == None ) : return ( None )
   self . geo = o00OOOoooo00
   if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
  elif ( oo0OoOOO == LISP_LCAF_JSON_TYPE ) :
   I11i1ii11 = OooIiii1ii & 0x02
   if 8 - 8: I1ii11iIi11i % Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
   if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
   if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
   if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
   O0oOO0o00OO = "H"
   Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
   if ( I1ii < Ii1i1iiiIiIIiIiiii ) : return ( None )
   if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
   i1IiI11I11I = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
   i1IiI11I11I = socket . ntohs ( i1IiI11I11I )
   if ( I1ii < Ii1i1iiiIiIIiIiiii + i1IiI11I11I ) : return ( None )
   if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
   packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
   self . json = lisp_json ( "" , packet [ 0 : i1IiI11I11I ] , I11i1ii11 ,
 ms_json_encrypt )
   packet = packet [ i1IiI11I11I : : ]
   if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
   if 38 - 38: IiII / i1IIi
   if 60 - 60: OoOoOO00
   if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
   ii11IiI = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 61 - 61: IiII . IiII
   if ( ii11IiI != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = ii11IiI
    packet = self . rloc . unpack_address ( packet )
    if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
    if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
  elif ( oo0OoOOO == LISP_LCAF_ELP_TYPE ) :
   if 95 - 95: iII111i / ooOoO0o + I1Ii111
   if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
   if 81 - 81: I1ii11iIi11i
   if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
   o0ooO0o0 = lisp_elp ( None )
   o0ooO0o0 . elp_nodes = [ ]
   while ( I1ii > 0 ) :
    iIi1i , ii11IiI = struct . unpack ( "HH" , packet [ : 4 ] )
    if 77 - 77: ooOoO0o * II111iiii . II111iiii + ooOoO0o % OoooooooOO
    ii11IiI = socket . ntohs ( ii11IiI )
    if ( ii11IiI == LISP_AFI_LCAF ) : return ( None )
    if 92 - 92: oO0o
    o00Oo0 = lisp_elp_node ( )
    o0ooO0o0 . elp_nodes . append ( o00Oo0 )
    if 37 - 37: ooOoO0o * iII111i * I11i
    iIi1i = socket . ntohs ( iIi1i )
    o00Oo0 . eid = ( iIi1i & 0x4 )
    o00Oo0 . probe = ( iIi1i & 0x2 )
    o00Oo0 . strict = ( iIi1i & 0x1 )
    o00Oo0 . address . afi = ii11IiI
    o00Oo0 . address . mask_len = o00Oo0 . address . host_mask_len ( )
    packet = o00Oo0 . address . unpack_address ( packet [ 4 : : ] )
    I1ii -= o00Oo0 . address . addr_length ( ) + 4
    if 11 - 11: I1IiiI
   o0ooO0o0 . select_elp_node ( )
   self . elp = o0ooO0o0
   if 48 - 48: O0 . I11i
  elif ( oo0OoOOO == LISP_LCAF_RLE_TYPE ) :
   if 9 - 9: oO0o / Oo0Ooo
   if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
   if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
   if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
   IIii1i = lisp_rle ( None )
   IIii1i . rle_nodes = [ ]
   while ( I1ii > 0 ) :
    I1iIiiI1IIi1 , i1iIi1II1 , i11IiIi1Ii1 , ii11IiI = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 93 - 93: O0
    ii11IiI = socket . ntohs ( ii11IiI )
    if ( ii11IiI == LISP_AFI_LCAF ) : return ( None )
    if 82 - 82: OoooooooOO - iII111i % I1ii11iIi11i
    oO0oOOOO0oO0o0 = lisp_rle_node ( )
    IIii1i . rle_nodes . append ( oO0oOOOO0oO0o0 )
    if 39 - 39: o0oOOo0O0Ooo
    oO0oOOOO0oO0o0 . level = i11IiIi1Ii1
    oO0oOOOO0oO0o0 . address . afi = ii11IiI
    oO0oOOOO0oO0o0 . address . mask_len = oO0oOOOO0oO0o0 . address . host_mask_len ( )
    packet = oO0oOOOO0oO0o0 . address . unpack_address ( packet [ 6 : : ] )
    if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
    I1ii -= oO0oOOOO0oO0o0 . address . addr_length ( ) + 6
    if ( I1ii >= 2 ) :
     ii11IiI = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( ii11IiI ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , oO0oOOOO0oO0o0 . rloc_name = lisp_decode_dist_name ( packet )
      if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
      if ( packet == None ) : return ( None )
      I1ii -= len ( oO0oOOOO0oO0o0 . rloc_name ) + 1 + 2
      if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
      if 30 - 30: i11iIiiIii % OOooOOo
      if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
   self . rle = IIii1i
   self . rle . build_forwarding_list ( )
   if 27 - 27: I1IiiI + OoOoOO00 + iII111i
  elif ( oo0OoOOO == LISP_LCAF_SECURITY_TYPE ) :
   if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
   if 34 - 34: i1IIi % Oo0Ooo . oO0o
   if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
   if 62 - 62: Oo0Ooo . OoO0O00 * I1Ii111 . i11iIiiIii * O0
   if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
   o0O0OoOOo0o = packet
   II111i1I = lisp_keys ( 1 )
   packet = II111i1I . decode_lcaf ( o0O0OoOOo0o , I1ii , False )
   if ( packet == None ) : return ( None )
   if 62 - 62: I1IiiI . Ii1I
   if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
   if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
   if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
   o0oI1 = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( II111i1I . cipher_suite in o0oI1 ) :
    if ( II111i1I . cipher_suite == LISP_CS_25519_CBC ) :
     IIIOoo = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 52 - 52: Ii1I - I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo
    if ( II111i1I . cipher_suite == LISP_CS_25519_CHACHA ) :
     IIIOoo = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
   else :
    IIIOoo = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
   packet = IIIOoo . decode_lcaf ( o0O0OoOOo0o , I1ii , False )
   if ( packet == None ) : return ( None )
   if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
   if ( len ( packet ) < 2 ) : return ( None )
   ii11IiI = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( ii11IiI )
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
    if ( IIIOoo . remote_public_key == None ) :
     i1IIIII1 = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( i1IIIII1 , IIi1Ii ) )
     IIIOoo = None
    else :
     i1IIIII1 = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( i1IIIII1 , IIi1Ii ) )
     IIIOoo . compute_shared_key ( "encap" )
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
    if ( IIIOoo . remote_public_key == None ) :
     IIIOoo = None
     o0o00O000 = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( o0o00O000 , IIi1Ii ) )
    elif ( II111iii . compare_keys ( IIIOoo ) ) :
     IIIOoo = II111iii
     lprint ( "    Maintain stored encap-keys for {}" . format ( IIi1Ii ) )
     if 65 - 65: OoO0O00 + Oo0Ooo + IiII / OoOoOO00
    else :
     if ( II111iii . remote_public_key == None ) :
      i1IIIII1 = "New encap-keying for existing state"
     else :
      i1IIIII1 = "Remote encap-rekeying"
      if 37 - 37: oO0o - I11i
     lprint ( "    {} for {}" . format ( bold ( i1IIIII1 , False ) ,
 IIi1Ii ) )
     II111iii . remote_public_key = IIIOoo . remote_public_key
     II111iii . compute_shared_key ( "encap" )
     IIIOoo = II111iii
     if 64 - 64: OoO0O00 * OoOoOO00
     if 50 - 50: I1ii11iIi11i + I11i * iII111i
   self . keys = [ None , IIIOoo , None , None ]
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
  O0oOO0o00OO = "BBBBHH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
  self . priority , self . weight , self . mpriority , self . mweight , iIi1i , ii11IiI = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 25 - 25: I11i - I1ii11iIi11i
  if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
  iIi1i = socket . ntohs ( iIi1i )
  ii11IiI = socket . ntohs ( ii11IiI )
  self . local_bit = True if ( iIi1i & 0x0004 ) else False
  self . probe_bit = True if ( iIi1i & 0x0002 ) else False
  self . reach_bit = True if ( iIi1i & 0x0001 ) else False
  if 83 - 83: O0
  if ( ii11IiI == LISP_AFI_LCAF ) :
   packet = packet [ Ii1i1iiiIiIIiIiiii - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
  else :
   self . rloc . afi = ii11IiI
   packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
   packet = self . rloc . unpack_address ( packet )
   if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
  if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
 def end_of_rlocs ( self , packet , rloc_count ) :
  for OoOOoO0oOo in range ( rloc_count ) :
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
  II = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  OO0 = struct . pack ( "I" , socket . htonl ( II ) )
  OO0 += struct . pack ( "Q" , self . nonce )
  return ( OO0 )
  if 38 - 38: I1IiiI % i11iIiiIii
  if 17 - 17: i11iIiiIii
 def decode ( self , packet ) :
  O0oOO0o00OO = "I"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 81 - 81: I1Ii111
  II = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  II = socket . ntohl ( II [ 0 ] )
  self . record_count = II & 0xff
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 25 - 25: I1IiiI
  O0oOO0o00OO = "Q"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
  self . nonce = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
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
  II = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : II |= ( 1 << 27 )
  if 3 - 3: oO0o - Oo0Ooo * I1IiiI / I1ii11iIi11i / OOooOOo
  if 45 - 45: II111iiii
  if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
  if 84 - 84: o0oOOo0O0Ooo
  if 40 - 40: OoooooooOO - oO0o / O0 * I1Ii111 . O0 + i11iIiiIii
  if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
  if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
  OO0 = struct . pack ( "I" , socket . htonl ( II ) )
  OO0 += struct . pack ( "Q" , self . nonce )
  OO0 += struct . pack ( "III" , 0 , 0 , 0 )
  if 66 - 66: OOooOOo * Oo0Ooo
  if 58 - 58: OOooOOo
  if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
  if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    OO0 += struct . pack ( "H" , 0 )
   else :
    OO0 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    OO0 += self . hostname + "\0"
    if 13 - 13: ooOoO0o
   return ( OO0 )
   if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
   if 3 - 3: iIii1I11I1II1 / oO0o
   if 61 - 61: I1Ii111 / O0 - iII111i
   if 44 - 44: i1IIi
   if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
  ii11IiI = socket . htons ( LISP_AFI_LCAF )
  oo0OoOOO = LISP_LCAF_NAT_TYPE
  I1ii = socket . htons ( 16 )
  OOoOOO = socket . htons ( self . ms_port )
  I1iiiI1i = socket . htons ( self . etr_port )
  OO0 += struct . pack ( "HHBBHHHH" , ii11IiI , 0 , oo0OoOOO , 0 , I1ii ,
 OOoOOO , I1iiiI1i , socket . htons ( self . global_etr_rloc . afi ) )
  OO0 += self . global_etr_rloc . pack_address ( )
  OO0 += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  OO0 += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : OO0 += struct . pack ( "H" , 0 )
  if 69 - 69: iII111i * I11i
  if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
  if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
  if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
  for IiIi1I1i1iIiI in self . rtr_list :
   OO0 += struct . pack ( "H" , socket . htons ( IiIi1I1i1iIiI . afi ) )
   OO0 += IiIi1I1i1iIiI . pack_address ( )
   if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
  return ( OO0 )
  if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
  if 63 - 63: I1ii11iIi11i - Ii1I + I11i
 def decode ( self , packet ) :
  o0O0OoOOo0o = packet
  O0oOO0o00OO = "I"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
  II = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  II = II [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 72 - 72: O0 . OOooOOo
  O0oOO0o00OO = "Q"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
  o00oO0O000 = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 74 - 74: i1IIi
  II = socket . ntohl ( II )
  self . nonce = o00oO0O000 [ 0 ]
  self . info_reply = II & 0x08000000
  self . hostname = None
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
  if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
  if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
  if 35 - 35: i11iIiiIii + oO0o
  if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
  O0oOO0o00OO = "HH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
  if 12 - 12: II111iiii - iIii1I11I1II1
  if 43 - 43: i11iIiiIii % OoO0O00
  if 100 - 100: i1IIi
  if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
  IiII11iI1 , o0o000OOO = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if ( o0o000OOO != 0 ) : return ( None )
  if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  O0oOO0o00OO = "IBBH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 71 - 71: IiII + OoO0O00
  IiIIi , Iii1i1 , Iii1iii1II , iIIi1iIi11 = struct . unpack ( O0oOO0o00OO ,
 packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 17 - 17: iIii1I11I1II1
  if ( iIIi1iIi11 != 0 ) : return ( None )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 10 - 10: i11iIiiIii / iII111i - oO0o
  if 98 - 98: Ii1I % iII111i . I11i
  if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i % o0oOOo0O0Ooo . ooOoO0o - oO0o
  if 64 - 64: I11i * ooOoO0o
  if ( self . info_reply == False ) :
   O0oOO0o00OO = "H"
   Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
   if ( len ( packet ) >= Ii1i1iiiIiIIiIiiii ) :
    ii11IiI = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
    if ( socket . ntohs ( ii11IiI ) == LISP_AFI_NAME ) :
     packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 86 - 86: OoooooooOO * I1IiiI
     if 88 - 88: Ii1I + O0
   return ( o0O0OoOOo0o )
   if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
   if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
   if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
   if 85 - 85: OoooooooOO * ooOoO0o
   if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
  O0oOO0o00OO = "HHBBHHH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
  ii11IiI , I1iIiiI1IIi1 , oo0OoOOO , Iii1i1 , I1ii , OOoOOO , I1iiiI1i = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
  if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
  if ( socket . ntohs ( ii11IiI ) != LISP_AFI_LCAF ) : return ( None )
  if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
  self . ms_port = socket . ntohs ( OOoOOO )
  self . etr_port = socket . ntohs ( I1iiiI1i )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 62 - 62: I1Ii111 % II111iiii
  if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
  if 91 - 91: i11iIiiIii + Ii1I
  if 85 - 85: I11i % IiII
  O0oOO0o00OO = "H"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
  if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
  if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
  ii11IiI = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if ( ii11IiI != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( ii11IiI )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 93 - 93: Ii1I / iII111i
   if 100 - 100: Oo0Ooo
   if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
   if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
   if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
   if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( o0O0OoOOo0o )
  if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
  ii11IiI = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if ( ii11IiI != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( ii11IiI )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( o0O0OoOOo0o )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 72 - 72: I1Ii111 . OoO0O00
   if 59 - 59: I1IiiI * I11i % i1IIi
   if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
   if 60 - 60: iIii1I11I1II1
   if 13 - 13: II111iiii + Ii1I
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( o0O0OoOOo0o )
  if 33 - 33: i1IIi
  ii11IiI = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if ( ii11IiI != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( ii11IiI )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( o0O0OoOOo0o )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
   if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
   if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
   if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
   if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
   if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
  while ( len ( packet ) >= Ii1i1iiiIiIIiIiiii ) :
   ii11IiI = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
   packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
   if ( ii11IiI == 0 ) : continue
   IiIi1I1i1iIiI = lisp_address ( socket . ntohs ( ii11IiI ) , "" , 0 , 0 )
   packet = IiIi1I1i1iIiI . unpack_address ( packet )
   if ( packet == None ) : return ( o0O0OoOOo0o )
   IiIi1I1i1iIiI . mask_len = IiIi1I1i1iIiI . host_mask_len ( )
   self . rtr_list . append ( IiIi1I1i1iIiI )
   if 81 - 81: i1IIi % iIii1I11I1II1
  return ( o0O0OoOOo0o )
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
  Ii1i1 = time . time ( ) - self . uptime
  return ( Ii1i1 >= ( LISP_INFO_INTERVAL * 2 ) )
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
  IIIOoo = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ IIIOoo ] = self
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
  oOOOOOOooOOoO = auth1 + auth2 + auth3
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
  oOOOOOOooOOoO = auth1 + auth2 + auth3 + auth4
  if 6 - 6: I1ii11iIi11i
 return ( oOOOOOOooOOoO )
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
 iiIIiI = .001
 while ( i1iIii > 0 ) :
  I1ii1111iIi = min ( i1iIii , OOOOOooo )
  I1iIi1iiIIII = packet [ IiI1ii1Ii : I1ii1111iIi + IiI1ii1Ii ]
  if 26 - 26: i1IIi - II111iiii - Ii1I * i1IIi * OoOoOO00
  try :
   send_socket . sendto ( I1iIi1iiIIII , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( I1iIi1iiIIII ) , len ( packet ) , node ) )
   if 99 - 99: IiII / oO0o % ooOoO0o / Oo0Ooo * OoO0O00
   I11iIIii = 0
   iiIIiI = .001
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
   time . sleep ( iiIIiI )
   if 86 - 86: IiII + Ii1I / Oo0Ooo / O0 % iII111i - oO0o
   lprint ( "Retrying after {} ms ..." . format ( iiIIiI * 1000 ) )
   iiIIiI *= 2
   continue
   if 3 - 3: i11iIiiIii / I1ii11iIi11i % I1Ii111 + o0oOOo0O0Ooo + O0
   if 42 - 42: IiII / i11iIiiIii % o0oOOo0O0Ooo / II111iiii / IiII
  IiI1ii1Ii += I1ii1111iIi
  i1iIii -= I1ii1111iIi
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
 o000ooOo0o0Oo = ""
 i1iIii = len ( packet ) * 2
 while ( IiI1ii1Ii < i1iIii ) :
  o000ooOo0o0Oo += packet [ IiI1ii1Ii : IiI1ii1Ii + 8 ] + " "
  IiI1ii1Ii += 8
  i1iIii -= 4
  if 94 - 94: OOooOOo / IiII
 return ( o000ooOo0o0Oo )
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
 I1IIIi = dest . print_address_no_iid ( )
 if ( I1IIIi . find ( "::ffff:" ) != - 1 and I1IIIi . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : iIiIIi1i = lisp_sockets [ 0 ]
  if ( iIiIIi1i == None ) :
   iIiIIi1i = lisp_sockets [ 0 ]
   I1IIIi = I1IIIi . split ( "::ffff:" ) [ - 1 ]
   if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
   if 100 - 100: Oo0Ooo + IiII
   if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + I1IIIi , False ) , port ,
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
 try : iIiIIi1i . sendto ( packet , ( I1IIIi , port ) )
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
 I1ii1111iIi = total_length - len ( packet )
 if ( I1ii1111iIi == 0 ) : return ( [ True , packet ] )
 if 74 - 74: I11i + OoooooooOO % II111iiii % o0oOOo0O0Ooo
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 27 - 27: OoO0O00 * Oo0Ooo
 if 80 - 80: i11iIiiIii . OoO0O00 - I11i % I11i
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
 if 94 - 94: ooOoO0o
 if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
 i1iIii = I1ii1111iIi
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
 OO0 = ""
 for I1iIi1iiIIII in payload : OO0 += I1iIi1iiIIII + "\x40"
 return ( OO0 [ : - 1 ] )
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
   OO0 = i1i1i11i11 [ 0 ]
   II11IIII1 = lisp_convert_6to4 ( i1i1i11i11 [ 1 ] [ 0 ] )
   IiO0o = i1i1i11i11 [ 1 ] [ 1 ]
   if 96 - 96: Ii1I
   if ( IiO0o == LISP_DATA_PORT ) :
    iiii1IIIi1 = lisp_data_plane_logging
    oo0 = lisp_format_packet ( OO0 [ 0 : 60 ] ) + " ..."
   else :
    iiii1IIIi1 = True
    oo0 = lisp_format_packet ( OO0 )
    if 72 - 72: O0
    if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
   if ( iiii1IIIi1 ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( OO0 ) , bold ( "from " + II11IIII1 , False ) , IiO0o ,
 oo0 ) )
    if 93 - 93: OOooOOo / OoooooooOO % iII111i
   return ( [ "packet" , II11IIII1 , IiO0o , OO0 ] )
   if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
   if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
   if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
   if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
   if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
   if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
  oo0OOOOooOOo0 = False
  O0oo = i1i1i11i11 [ 0 ]
  ooOo000OO = False
  if 19 - 19: iIii1I11I1II1 % OOooOOo . i11iIiiIii
  while ( oo0OOOOooOOo0 == False ) :
   O0oo = O0oo . split ( "@" )
   if 85 - 85: II111iiii * i1IIi * iIii1I11I1II1 - O0 % I1Ii111
   if ( len ( O0oo ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( O0oo [ 0 ] ) )
    if 36 - 36: Oo0Ooo * I11i / I1Ii111 / i1IIi
    ooOo000OO = True
    break
    if 60 - 60: iII111i + Oo0Ooo % i1IIi / II111iiii
    if 59 - 59: iII111i - O0 + Ii1I
   OoOO0 = O0oo [ 0 ]
   try :
    oOoOO0OO = int ( O0oo [ 1 ] )
   except :
    OoOOOoO0oo0 = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( OoOOOoO0oo0 , i1i1i11i11 ) )
    ooOo000OO = True
    break
    if 59 - 59: I1Ii111
   II11IIII1 = O0oo [ 2 ]
   IiO0o = O0oo [ 3 ]
   if 22 - 22: OoooooooOO
   if 88 - 88: I1Ii111 - OoO0O00
   if 29 - 29: I1IiiI . I1Ii111
   if 74 - 74: Oo0Ooo / OoOoOO00 + OoOoOO00 % i11iIiiIii . OoO0O00 + ooOoO0o
   if 77 - 77: ooOoO0o . I11i + OoooooooOO
   if 100 - 100: ooOoO0o . oO0o % I1ii11iIi11i . IiII * IiII - o0oOOo0O0Ooo
   if 49 - 49: iIii1I11I1II1 % Ii1I / OoooooooOO - II111iiii . Ii1I
   if 65 - 65: OoooooooOO + I1Ii111 % ooOoO0o + II111iiii . i1IIi + OoooooooOO
   if ( len ( O0oo ) > 5 ) :
    OO0 = lisp_bit_stuff ( O0oo [ 4 : : ] )
   else :
    OO0 = O0oo [ 4 ]
    if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
    if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
    if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
    if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
    if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
    if 43 - 43: O0 % II111iiii
   oo0OOOOooOOo0 , OO0 = lisp_receive_segments ( lisp_socket , OO0 ,
 II11IIII1 , oOoOO0OO )
   if ( OO0 == None ) : return ( [ "" , "" , "" , "" ] )
   if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
   if 79 - 79: oO0o / iII111i . iIii1I11I1II1 * i11iIiiIii * i1IIi . iIii1I11I1II1
   if 31 - 31: OoooooooOO / ooOoO0o / OoooooooOO + ooOoO0o . O0 - IiII
   if 53 - 53: Oo0Ooo % iII111i % iII111i
   if 71 - 71: iII111i
   if ( oo0OOOOooOOo0 == False ) :
    O0oo = OO0
    continue
    if 99 - 99: O0 - OoOoOO00 * I1Ii111 - Oo0Ooo
    if 62 - 62: i1IIi + ooOoO0o + Oo0Ooo - i11iIiiIii
   if ( IiO0o == "" ) : IiO0o = "no-port"
   if ( OoOO0 == "command" and lisp_i_am_core == False ) :
    OOOooo0OooOoO = OO0 . find ( " {" )
    ii1i = OO0 if OOOooo0OooOoO == - 1 else OO0 [ : OOOooo0OooOoO ]
    ii1i = ": '" + ii1i + "'"
   else :
    ii1i = ""
    if 51 - 51: ooOoO0o - I1Ii111 * oO0o
    if 47 - 47: Oo0Ooo % OoO0O00 * Ii1I / OoOoOO00
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( OO0 ) , bold ( "from " + II11IIII1 , False ) , IiO0o , OoOO0 ,
 ii1i if ( OoOO0 in [ "command" , "api" ] ) else ": ... " if ( OoOO0 == "data-packet" ) else ": " + lisp_format_packet ( OO0 ) ) )
   if 1 - 1: I1IiiI
   if 68 - 68: ooOoO0o
   if 68 - 68: I11i % IiII
   if 1 - 1: I1IiiI + OOooOOo - OOooOOo * O0 + o0oOOo0O0Ooo * OOooOOo
   if 48 - 48: ooOoO0o - iII111i + I1ii11iIi11i * I1Ii111 % ooOoO0o * OoO0O00
  if ( ooOo000OO ) : continue
  return ( [ OoOO0 , II11IIII1 , IiO0o , OO0 ] )
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
 o0O0OOooO = lisp_control_header ( )
 if ( o0O0OOooO . decode ( packet ) == None ) :
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
 if ( o0O0OOooO . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , iIIiiIiI )
  if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
 elif ( o0O0OOooO . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , iIIiiIiI )
  if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
 elif ( o0O0OOooO . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 52 - 52: II111iiii . iII111i
 elif ( o0O0OOooO . type == LISP_MAP_NOTIFY ) :
  if ( oo0iiiI == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-rtr" ) ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-itr" ) ) :
   lisp_process_unicast_map_notify ( lisp_sockets , packet , source )
   if 36 - 36: I1IiiI * II111iiii
   if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
 elif ( o0O0OOooO . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
 elif ( o0O0OOooO . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 66 - 66: I1ii11iIi11i * ooOoO0o . i11iIiiIii * Oo0Ooo - I11i . I1IiiI
 elif ( o0O0OOooO . type == LISP_NAT_INFO and o0O0OOooO . is_info_reply ( ) ) :
  I1iIiiI1IIi1 , i1iIi1II1 , Iii1i111ii1i = lisp_process_info_reply ( source , packet , True )
  if 43 - 43: I11i . iII111i . IiII - oO0o
 elif ( o0O0OOooO . type == LISP_NAT_INFO and o0O0OOooO . is_info_reply ( ) == False ) :
  Oo0o = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , Oo0o , udp_sport ,
 None )
  if 60 - 60: i1IIi + iII111i * i1IIi . iII111i
 elif ( o0O0OOooO . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 40 - 40: i1IIi . OoO0O00
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( o0O0OOooO . type ) )
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
 IiIiIII11i1i = bold ( "RLOC-probe" , False )
 if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( IiIiIII11i1i ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
  if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( IiIiIII11i1i ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
  if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( IiIiIII11i1i ) )
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
 OO0 = iIO0OOoOOO0OO . encode ( )
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
 OO0 += oOO0O0o0oOooO . encode ( )
 oOO0O0o0oOooO . print_record ( "  " , False )
 if 80 - 80: I1Ii111 * II111iiii % Oo0Ooo * ooOoO0o + o0oOOo0O0Ooo
 ooo0oOO0OoOo0 = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 23 - 23: I1ii11iIi11i + II111iiii
 OOiIiIiiiI11i1 = None
 for O0O0OOo0O in rloc_set :
  o0OooO = O0O0OOo0O . rloc . is_multicast_address ( )
  iIIi = lisp_rloc_record ( )
  o0ooo0OOOoOo = oO0O and ( o0OooO or O0O0O == None )
  Oo0o = O0O0OOo0O . rloc . print_address_no_iid ( )
  if ( Oo0o in ooo0oOO0OoOo0 or o0OooO ) :
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
  OO0 += iIIi . encode ( )
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
  if ( lisp_i_am_rtr ) :
   iIIi . priority = 254
   iIIi . rloc_name = "RTR"
   if 43 - 43: i1IIi % o0oOOo0O0Ooo * I1IiiI / oO0o * IiII + I11i
  iIIII = lisp_encode_telemetry ( O0O0O , eo = str ( time . time ( ) ) )
  iIIi . json = lisp_json ( "telemetry" , iIIII )
  iIIi . print_record ( "    " )
  OO0 += iIIi . encode ( )
  if 29 - 29: OoOoOO00 / OoO0O00 / OoooooooOO * O0 / iIii1I11I1II1
 return ( OO0 )
 if 29 - 29: OoO0O00 / IiII + i1IIi / OoO0O00 . Oo0Ooo
 if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 if 14 - 14: i1IIi
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 iiiiIii = lisp_map_referral ( )
 iiiiIii . record_count = 1
 iiiiIii . nonce = nonce
 OO0 = iiiiIii . encode ( )
 iiiiIii . print_map_referral ( )
 if 40 - 40: Ii1I % oO0o
 oOO0O0o0oOooO = lisp_eid_record ( )
 if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 ooOOo0ooo = 0
 if ( ddt_entry == None ) :
  oOO0O0o0oOooO . eid = eid
  oOO0O0o0oOooO . group = group
 else :
  ooOOo0ooo = len ( ddt_entry . delegation_set )
  oOO0O0o0oOooO . eid = ddt_entry . eid
  oOO0O0o0oOooO . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 71 - 71: OoOoOO00 / i11iIiiIii * iII111i
 oOO0O0o0oOooO . rloc_count = ooOOo0ooo
 oOO0O0o0oOooO . authoritative = True
 if 90 - 90: Ii1I
 if 27 - 27: oO0o + Ii1I . i11iIiiIii
 if 97 - 97: iII111i . I1IiiI
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
 OOiiI1iii1I = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( ooOOo0ooo == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   I1iII1iI1 = ddt_entry . delegation_set [ 0 ]
   if ( I1iII1iI1 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 45 - 45: oO0o
   if ( I1iII1iI1 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
    if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
    if 100 - 100: i11iIiiIii - iII111i - I11i
    if 5 - 5: oO0o % IiII * iII111i
    if 98 - 98: iII111i / OOooOOo + IiII
    if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
    if 82 - 82: ooOoO0o % OOooOOo % Ii1I
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : OOiiI1iii1I = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  OOiiI1iii1I = ( lisp_i_am_ms and I1iII1iI1 . is_ms_peer ( ) == False )
  if 82 - 82: I1ii11iIi11i
  if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 oOO0O0o0oOooO . action = action
 oOO0O0o0oOooO . ddt_incomplete = OOiiI1iii1I
 oOO0O0o0oOooO . record_ttl = ttl
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 OO0 += oOO0O0o0oOooO . encode ( )
 oOO0O0o0oOooO . print_record ( "  " , True )
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 if ( ooOOo0ooo == 0 ) : return ( OO0 )
 if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 for I1iII1iI1 in ddt_entry . delegation_set :
  iIIi = lisp_rloc_record ( )
  iIIi . rloc = I1iII1iI1 . delegate_address
  iIIi . priority = I1iII1iI1 . priority
  iIIi . weight = I1iII1iI1 . weight
  iIIi . mpriority = 255
  iIIi . mweight = 0
  iIIi . reach_bit = True
  OO0 += iIIi . encode ( )
  iIIi . print_record ( "    " )
  if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
 return ( OO0 )
 if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
 if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
 if 73 - 73: Oo0Ooo + iIii1I11I1II1 . iIii1I11I1II1
 if 73 - 73: ooOoO0o + OoOoOO00
 if 61 - 61: I1Ii111 * I1Ii111 % OOooOOo
 if 31 - 31: oO0o + Ii1I - iIii1I11I1II1 / i11iIiiIii
 if 9 - 9: IiII % OoO0O00
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 58 - 58: iII111i
 if ( map_request . target_group . is_null ( ) ) :
  iIiI1ii = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  iIiI1ii = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( iIiI1ii ) : iIiI1ii = iIiI1ii . lookup_source_cache ( map_request . target_eid , False )
  if 77 - 77: I1IiiI / iIii1I11I1II1 + Ii1I
 iIiI1I1ii1I1 = map_request . print_prefix ( )
 if 73 - 73: I1IiiI / OoO0O00 / OoooooooOO
 if ( iIiI1ii == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( iIiI1I1ii1I1 , False ) ) )
  if 14 - 14: ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i . IiII + I1ii11iIi11i
  return
  if 30 - 30: I1ii11iIi11i + iIii1I11I1II1 . I1ii11iIi11i
  if 9 - 9: I1IiiI - Ii1I * II111iiii - I11i
 oOo00OO0ooo = iIiI1ii . print_eid_tuple ( )
 if 13 - 13: I1IiiI / I1IiiI
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( oOo00OO0ooo , False ) , green ( iIiI1I1ii1I1 , False ) ) )
 if 51 - 51: I1IiiI . IiII + ooOoO0o . oO0o . o0oOOo0O0Ooo
 if 74 - 74: IiII - OoOoOO00
 if 36 - 36: II111iiii * iIii1I11I1II1 / o0oOOo0O0Ooo
 if 89 - 89: iII111i * I1IiiI - Ii1I + I1Ii111 / oO0o
 if 28 - 28: I11i . iIii1I11I1II1 . I11i + oO0o + I1IiiI
 oo00O0OO0Ooo0 = map_request . itr_rlocs [ 0 ]
 if ( oo00O0OO0Ooo0 . is_private_address ( ) and lisp_nat_traversal ) :
  oo00O0OO0Ooo0 = source
  if 63 - 63: ooOoO0o + i1IIi
  if 31 - 31: iIii1I11I1II1 - OoOoOO00 / II111iiii * Oo0Ooo
 o00oO0O000 = map_request . nonce
 iI11ii1IiIi11 = lisp_nonce_echoing
 Oo0Oo = map_request . keys
 if 84 - 84: Oo0Ooo / OoooooooOO % OOooOOo
 if 57 - 57: iII111i
 if 9 - 9: i1IIi - I1Ii111 + I1Ii111
 if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
 if 58 - 58: OoooooooOO . II111iiii . O0 % I1Ii111 / OoooooooOO
 oOoOOO = map_request . json_telemetry
 if ( oOoOOO != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( oOoOOO , ei = etr_in_ts )
  if 9 - 9: II111iiii * OOooOOo / Oo0Ooo + iIii1I11I1II1 % I1IiiI
  if 95 - 95: I1Ii111 . IiII % OoO0O00 - OOooOOo - I11i
 iIiI1ii . map_replies_sent += 1
 if 55 - 55: OoooooooOO % I1ii11iIi11i % iII111i / IiII
 OO0 = lisp_build_map_reply ( iIiI1ii . eid , iIiI1ii . group , iIiI1ii . rloc_set , o00oO0O000 ,
 LISP_NO_ACTION , 1440 , map_request , Oo0Oo , iI11ii1IiIi11 , True , ttl )
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
 if 40 - 40: o0oOOo0O0Ooo . IiII * OoOoOO00
 if 14 - 14: OOooOOo
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  i1I11 = ( oo00O0OO0Ooo0 . is_private_address ( ) == False )
  IiIi1I1i1iIiI = oo00O0OO0Ooo0 . print_address_no_iid ( )
  if ( i1I11 and IiIi1I1i1iIiI in lisp_rtr_list or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , oo00O0OO0Ooo0 , None , OO0 )
   return
   if 18 - 18: i11iIiiIii % iII111i
   if 70 - 70: O0 + iII111i % I11i % I1Ii111 + OoOoOO00 / ooOoO0o
   if 35 - 35: IiII + OoO0O00
   if 82 - 82: i1IIi - ooOoO0o / I11i + I11i % I1IiiI - OoooooooOO
   if 56 - 56: I1ii11iIi11i
   if 80 - 80: Oo0Ooo / OOooOOo / iII111i . o0oOOo0O0Ooo
 lisp_send_map_reply ( lisp_sockets , OO0 , oo00O0OO0Ooo0 , sport )
 return
 if 43 - 43: IiII
 if 74 - 74: OoooooooOO
 if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
 if 58 - 58: O0
 if 43 - 43: O0 / i1IIi / I11i % I1IiiI
 if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
 if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
 if 34 - 34: OoooooooOO * i11iIiiIii
 if 33 - 33: II111iiii
 if 59 - 59: iIii1I11I1II1 % I11i
 oo00O0OO0Ooo0 = map_request . itr_rlocs [ 0 ]
 if ( oo00O0OO0Ooo0 . is_private_address ( ) ) : oo00O0OO0Ooo0 = source
 o00oO0O000 = map_request . nonce
 if 93 - 93: I1ii11iIi11i
 oo0oO = map_request . target_eid
 iiI = map_request . target_group
 if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
 IIiii11iiI111 = [ ]
 for I1OOOo in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( I1OOOo == None ) : continue
  IIIi1iI1 = lisp_rloc ( )
  IIIi1iI1 . rloc . copy_address ( I1OOOo )
  IIIi1iI1 . priority = 254
  IIiii11iiI111 . append ( IIIi1iI1 )
  if 9 - 9: Ii1I
  if 53 - 53: Ii1I % IiII + I11i % IiII
 iI11ii1IiIi11 = lisp_nonce_echoing
 Oo0Oo = map_request . keys
 if 33 - 33: iII111i
 if 8 - 8: I11i
 if 95 - 95: OoOoOO00 % O0 % I1IiiI
 if 85 - 85: iIii1I11I1II1 * i11iIiiIii
 if 54 - 54: O0 * Ii1I + Ii1I
 oOoOOO = map_request . json_telemetry
 if ( oOoOOO != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( oOoOOO , ei = etr_in_ts )
  if 59 - 59: i11iIiiIii % iII111i
  if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
 OO0 = lisp_build_map_reply ( oo0oO , iiI , IIiii11iiI111 , o00oO0O000 , LISP_NO_ACTION ,
 1440 , map_request , Oo0Oo , iI11ii1IiIi11 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , OO0 , oo00O0OO0Ooo0 , sport )
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
 IIiii11iiI111 = target_site_eid . registered_rlocs
 if 59 - 59: OoO0O00 % o0oOOo0O0Ooo
 O0ooO0O0O00 = lisp_site_eid_lookup ( seid , group , False )
 if ( O0ooO0O0O00 == None ) : return ( IIiii11iiI111 )
 if 5 - 5: I1IiiI % I1IiiI + OoooooooOO / I1ii11iIi11i
 if 77 - 77: OOooOOo / i11iIiiIii % iII111i * oO0o
 if 77 - 77: OOooOOo + i11iIiiIii / o0oOOo0O0Ooo + iII111i
 if 90 - 90: ooOoO0o
 OOI1I1 = None
 iii1 = [ ]
 for O0O0OOo0O in IIiii11iiI111 :
  if ( O0O0OOo0O . is_rtr ( ) ) : continue
  if ( O0O0OOo0O . rloc . is_private_address ( ) ) :
   I11I1II1I1I1i = copy . deepcopy ( O0O0OOo0O )
   iii1 . append ( I11I1II1I1I1i )
   continue
   if 98 - 98: I1Ii111
  OOI1I1 = O0O0OOo0O
  break
  if 75 - 75: OOooOOo . i11iIiiIii * Ii1I
 if ( OOI1I1 == None ) : return ( IIiii11iiI111 )
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
 if ( IiiI11Ii1 == None ) : return ( IIiii11iiI111 )
 IiiI11Ii1 = IiiI11Ii1 . rloc . print_address_no_iid ( )
 if 94 - 94: iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
 if 94 - 94: OoO0O00 . ooOoO0o
 if 25 - 25: I1Ii111 % OOooOOo
 if 82 - 82: Ii1I
 o00oOo0oO0oOO = target_site_eid . site_id
 if ( o00oOo0oO0oOO == 0 ) :
  if ( IiiI11Ii1 == OOI1I1 ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( OOI1I1 ) )
   if 17 - 17: iII111i . i1IIi . i1IIi
   return ( iii1 )
   if 76 - 76: OoooooooOO % IiII
  return ( IIiii11iiI111 )
  if 81 - 81: iII111i . OOooOOo * i1IIi
  if 14 - 14: oO0o
  if 16 - 16: iII111i
  if 26 - 26: iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
  if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
  if 65 - 65: OOooOOo * I11i * Oo0Ooo
  if 21 - 21: Ii1I . iIii1I11I1II1
 if ( o00oOo0oO0oOO == O0ooO0O0O00 . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( o00oOo0oO0oOO ) )
  return ( iii1 )
  if 84 - 84: OOooOOo
 return ( IIiii11iiI111 )
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
 IIiii11iiI111 = [ ]
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
   IIiii11iiI111 . append ( O0O0OOo0O )
   if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
   if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
   if 77 - 77: ooOoO0o . II111iiii
   if 41 - 41: IiII
   if 27 - 27: IiII / IiII
   if 91 - 91: Ii1I
 if ( IiIIi11IiII ) : return ( IIiii11iiI111 )
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
 IIiii11iiI111 = [ ]
 for O0O0OOo0O in registered_rloc_set :
  if ( O0O0OOo0O . rloc . is_ipv6 ( ) ) : IIiii11iiI111 . append ( O0O0OOo0O )
  if ( O0O0OOo0O . rloc . is_private_address ( ) ) : IIiii11iiI111 . append ( O0O0OOo0O )
  if 90 - 90: IiII * iII111i % OoOoOO00 . i11iIiiIii
 IIiii11iiI111 += OOOo0O00OO00O
 return ( IIiii11iiI111 )
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
 o00oO0O000 = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 28 - 28: I1IiiI - I1Ii111
 if 60 - 60: OOooOOo / O0 * o0oOOo0O0Ooo * OoooooooOO
 if 95 - 95: II111iiii
 if 2 - 2: I11i - OoooooooOO / I1ii11iIi11i . I1ii11iIi11i * i11iIiiIii % II111iiii
 II = ( LISP_MAP_NOTIFY << 28 ) | iIiI1IIi1Ii1i
 o0O0OOooO = struct . pack ( "I" , socket . htonl ( II ) )
 O0oooO00ooO0 = struct . pack ( "I" , 0 )
 if 1 - 1: i11iIiiIii / OoOoOO00 - I1ii11iIi11i . I1IiiI / I1Ii111 % iIii1I11I1II1
 if 87 - 87: OoOoOO00 - II111iiii + Oo0Ooo
 if 44 - 44: i1IIi + I1ii11iIi11i / iIii1I11I1II1
 if 47 - 47: I1Ii111
 packet = o0O0OOooO + o00oO0O000 + O0oooO00ooO0 + packet
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
 for OooooIiii11 in lisp_pubsub_cache :
  for iIiii11 in list ( lisp_pubsub_cache [ OooooIiii11 ] . values ( ) ) :
   I1i = iIiii11 . eid_prefix
   if ( I1i . is_more_specific ( registered_eid ) == False ) : continue
   if 42 - 42: iIii1I11I1II1
   i11iII = iIiii11 . itr
   IiO0o = iIiii11 . port
   oo0o = red ( i11iII . print_address_no_iid ( ) , False )
   OOOo00OOoO = bold ( "subscriber" , False )
   ooOOoOO000 = "0x" + lisp_hex_string ( iIiii11 . xtr_id )
   o00oO0O000 = "0x" + lisp_hex_string ( iIiii11 . nonce )
   if 5 - 5: I1Ii111 * I1IiiI * O0 + I1Ii111
   lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( OOOo00OOoO , oo0o , IiO0o , ooOOoOO000 , green ( OooooIiii11 , False ) , o00oO0O000 ) )
   if 19 - 19: i11iIiiIii / IiII - i1IIi - I1IiiI * I11i
   if 43 - 43: IiII * Oo0Ooo / OoOoOO00 + I1IiiI - i11iIiiIii + II111iiii
   if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
   if 87 - 87: O0 % II111iiii
   if 42 - 42: I1IiiI . i1IIi
   if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
   IIi11 = copy . deepcopy ( eid_record )
   IIi11 . eid . copy_address ( I1i )
   IIi11 = IIi11 . encode ( ) + rloc_records
   lisp_build_map_notify ( lisp_sockets , IIi11 , [ OooooIiii11 ] , 1 , i11iII ,
 IiO0o , iIiii11 . nonce , 0 , 0 , 0 , site , False )
   if 92 - 92: I11i / OoooooooOO
   iIiii11 . map_notify_count += 1
   if 57 - 57: II111iiii / i11iIiiIii . OoooooooOO
   if 98 - 98: O0
 return
 if 27 - 27: oO0o * OoooooooOO * oO0o
 if 23 - 23: O0 . OoO0O00 . i1IIi
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 64 - 64: OoooooooOO + OOooOOo
 if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 * OoO0O00
 if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
 iIiii11 = lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl ,
 xtr_id )
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 oo0oO = green ( reply_eid . print_prefix ( ) , False )
 i11iII = red ( itr_rloc . print_address_no_iid ( ) , False )
 oO0II11II = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( oO0II11II ,
 oo0oO , i11iII , xtr_id ) )
 if 55 - 55: OOooOOo % I1Ii111 * OoooooooOO - oO0o * ooOoO0o
 if 89 - 89: Ii1I % I1Ii111 - o0oOOo0O0Ooo + I11i + OoO0O00
 if 9 - 9: IiII / i1IIi * IiII - o0oOOo0O0Ooo - iIii1I11I1II1
 if 58 - 58: I1ii11iIi11i + iII111i
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 iIiii11 . map_notify_count += 1
 return
 if 65 - 65: ooOoO0o / Ii1I - oO0o - O0 % OOooOOo
 if 16 - 16: Oo0Ooo . Ii1I . i11iIiiIii / I1ii11iIi11i . i1IIi + I1Ii111
 if 25 - 25: OOooOOo - II111iiii % I1ii11iIi11i . OoOoOO00 . OoooooooOO
 if 13 - 13: OoooooooOO + OoooooooOO * i11iIiiIii + iII111i
 if 25 - 25: oO0o + I1ii11iIi11i + i11iIiiIii % i11iIiiIii
 if 11 - 11: I11i * Oo0Ooo * ooOoO0o + i1IIi
 if 76 - 76: o0oOOo0O0Ooo * i1IIi / I1Ii111 * Oo0Ooo + II111iiii . OoOoOO00
 if 44 - 44: OoOoOO00
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source ) :
 if 63 - 63: OoOoOO00 % iIii1I11I1II1 . I1Ii111 * O0 * OOooOOo - I11i
 if 52 - 52: I11i - I11i / OoooooooOO - iIii1I11I1II1 / i11iIiiIii - Oo0Ooo
 if 61 - 61: OOooOOo / iIii1I11I1II1 - Oo0Ooo % Oo0Ooo % Oo0Ooo
 if 66 - 66: OoooooooOO
 if 23 - 23: OoOoOO00
 if 35 - 35: I1Ii111 - i1IIi
 oo0oO = map_request . target_eid
 iiI = map_request . target_group
 iIiI1I1ii1I1 = lisp_print_eid_tuple ( oo0oO , iiI )
 oo00O0OO0Ooo0 = map_request . itr_rlocs [ 0 ]
 ooOOoOO000 = map_request . xtr_id
 o00oO0O000 = map_request . nonce
 Oo0Oo00O000O = LISP_NO_ACTION
 iIiii11 = map_request . subscribe_bit
 if 90 - 90: I11i . OoO0O00 . iIii1I11I1II1
 if 81 - 81: iII111i + I11i - i11iIiiIii * I1IiiI / IiII - Ii1I
 if 44 - 44: OoooooooOO . oO0o
 if 30 - 30: I1Ii111 % IiII / II111iiii
 if 68 - 68: oO0o / O0 / OOooOOo
 iIIii = True
 oOoO = ( lisp_get_eid_hash ( oo0oO ) != None )
 if ( oOoO ) :
  oOO0oOOOOO0 = map_request . map_request_signature
  if ( oOO0oOOOOO0 == None ) :
   iIIii = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 50 - 50: I11i - OOooOOo * OOooOOo + I1IiiI % o0oOOo0O0Ooo
  else :
   Oo00OoOoo = map_request . signature_eid
   IIi1i1IIi11 , ii1 , iIIii = lisp_lookup_public_key ( Oo00OoOoo )
   if ( iIIii ) :
    iIIii = map_request . verify_map_request_sig ( ii1 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Oo00OoOoo . print_address ( ) , IIi1i1IIi11 . print_address ( ) ) )
    if 26 - 26: Oo0Ooo / IiII . I1ii11iIi11i
    if 37 - 37: I1IiiI . O0
   I111I = bold ( "passed" , False ) if iIIii else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( I111I ) )
   if 67 - 67: iII111i + OoO0O00
   if 44 - 44: OoooooooOO + OoooooooOO - Ii1I * iII111i
   if 45 - 45: oO0o . O0 - ooOoO0o / o0oOOo0O0Ooo
 if ( iIiii11 and iIIii == False ) :
  iIiii11 = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 58 - 58: Ii1I . iII111i * OoO0O00 + OoO0O00 % I1Ii111 + I1ii11iIi11i
  if 34 - 34: i11iIiiIii + OoOoOO00
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
 iIiiii1iIi11 = oo00O0OO0Ooo0 if ( oo00O0OO0Ooo0 . afi == ecm_source . afi ) else ecm_source
 if 18 - 18: OoooooooOO / I1ii11iIi11i * i1IIi / i11iIiiIii + Oo0Ooo / Ii1I
 IiiiiiIiI = lisp_site_eid_lookup ( oo0oO , iiI , False )
 if 30 - 30: II111iiii + O0 % I11i - OoooooooOO
 if ( IiiiiiIiI == None or IiiiiiIiI . is_star_g ( ) ) :
  ooOoI1IiiI = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( ooOoI1IiiI ,
 green ( iIiI1I1ii1I1 , False ) ) )
  if 18 - 18: OoO0O00 - I11i / OOooOOo / oO0o
  if 53 - 53: I1ii11iIi11i % i1IIi . i11iIiiIii
  if 47 - 47: ooOoO0o / Ii1I - II111iiii / OoooooooOO * OOooOOo
  if 24 - 24: IiII + I1IiiI / OoooooooOO
  lisp_send_negative_map_reply ( lisp_sockets , oo0oO , iiI , o00oO0O000 , oo00O0OO0Ooo0 ,
 mr_sport , 15 , ooOOoOO000 , iIiii11 )
  if 8 - 8: II111iiii . I1Ii111 * OoOoOO00 / iII111i - Oo0Ooo
  return ( [ oo0oO , iiI , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 17 - 17: iII111i . O0
  if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
 oOo00OO0ooo = IiiiiiIiI . print_eid_tuple ( )
 O00O0o = IiiiiiIiI . site . site_name
 if 86 - 86: I1Ii111
 if 60 - 60: I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
 if 32 - 32: ooOoO0o
 if 9 - 9: I1Ii111
 if 77 - 77: OoooooooOO * I1Ii111
 if ( oOoO == False and IiiiiiIiI . require_signature ) :
  oOO0oOOOOO0 = map_request . map_request_signature
  Oo00OoOoo = map_request . signature_eid
  if ( oOO0oOOOOO0 == None or Oo00OoOoo . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( O00O0o ) )
   iIIii = False
  else :
   Oo00OoOoo = map_request . signature_eid
   IIi1i1IIi11 , ii1 , iIIii = lisp_lookup_public_key ( Oo00OoOoo )
   if ( iIIii ) :
    iIIii = map_request . verify_map_request_sig ( ii1 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Oo00OoOoo . print_address ( ) , IIi1i1IIi11 . print_address ( ) ) )
    if 63 - 63: IiII * oO0o * iIii1I11I1II1
    if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
   I111I = bold ( "passed" , False ) if iIIii else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( I111I ) )
   if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
   if 4 - 4: O0
   if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
   if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
   if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
   if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
 if ( iIIii and IiiiiiIiI . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( O00O0o , green ( oOo00OO0ooo , False ) , green ( iIiI1I1ii1I1 , False ) ) )
  if 22 - 22: iIii1I11I1II1 % i11iIiiIii
  if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
  if 43 - 43: oO0o
  if 22 - 22: I1Ii111 + i11iIiiIii
  if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
  if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
  if ( IiiiiiIiI . accept_more_specifics == False ) :
   oo0oO = IiiiiiIiI . eid
   iiI = IiiiiiIiI . group
   if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
   if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
   if 30 - 30: oO0o - OoOoOO00 . I1IiiI
   if 17 - 17: OoOoOO00
   if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
  IiIIi = 1
  if ( IiiiiiIiI . force_ttl != None ) :
   IiIIi = IiiiiiIiI . force_ttl | 0x80000000
   if 57 - 57: O0
   if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
   if 13 - 13: I1ii11iIi11i
   if 32 - 32: OOooOOo / I11i + I1Ii111 / Oo0Ooo * OoooooooOO / II111iiii
   if 8 - 8: OoO0O00
  lisp_send_negative_map_reply ( lisp_sockets , oo0oO , iiI , o00oO0O000 , oo00O0OO0Ooo0 ,
 mr_sport , IiIIi , ooOOoOO000 , iIiii11 )
  if 17 - 17: iIii1I11I1II1 - Oo0Ooo
  return ( [ oo0oO , iiI , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 25 - 25: O0 + I1ii11iIi11i
  if 53 - 53: OoooooooOO . Oo0Ooo
  if 35 - 35: OOooOOo % i11iIiiIii % ooOoO0o . O0
  if 9 - 9: ooOoO0o + iII111i / i1IIi % Oo0Ooo - o0oOOo0O0Ooo / I1IiiI
  if 42 - 42: OOooOOo + oO0o % O0 * I1ii11iIi11i + i11iIiiIii
 IiII11I1I1II = False
 Iio0oO0 = ""
 IIIiI = False
 if ( IiiiiiIiI . force_nat_proxy_reply ) :
  Iio0oO0 = ", nat-forced"
  IiII11I1I1II = True
  IIIiI = True
 elif ( IiiiiiIiI . force_proxy_reply ) :
  Iio0oO0 = ", forced"
  IIIiI = True
 elif ( IiiiiiIiI . proxy_reply_requested ) :
  Iio0oO0 = ", requested"
  IIIiI = True
 elif ( map_request . pitr_bit and IiiiiiIiI . pitr_proxy_reply_drop ) :
  Iio0oO0 = ", drop-to-pitr"
  Oo0Oo00O000O = LISP_DROP_ACTION
 elif ( IiiiiiIiI . proxy_reply_action != "" ) :
  Oo0Oo00O000O = IiiiiiIiI . proxy_reply_action
  Iio0oO0 = ", forced, action {}" . format ( Oo0Oo00O000O )
  Oo0Oo00O000O = LISP_DROP_ACTION if ( Oo0Oo00O000O == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 76 - 76: OOooOOo / IiII
  if 21 - 21: I1IiiI * I1IiiI - i11iIiiIii % Oo0Ooo . i11iIiiIii
  if 14 - 14: OoO0O00 . I1IiiI % I11i * iII111i / OoOoOO00
  if 16 - 16: OoO0O00 * ooOoO0o / II111iiii % OOooOOo . I1ii11iIi11i * i1IIi
  if 18 - 18: I1IiiI + OoOoOO00
  if 17 - 17: i1IIi . Ii1I
  if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
 O000oO0O0 = False
 oOo0Oooooo = None
 if ( IIIiI and IiiiiiIiI . policy in lisp_policies ) :
  IiIiIII11i1i = lisp_policies [ IiiiiiIiI . policy ]
  if ( IiIiIII11i1i . match_policy_map_request ( map_request , mr_source ) ) : oOo0Oooooo = IiIiIII11i1i
  if 59 - 59: O0
  if ( oOo0Oooooo ) :
   IIiIIIi1iii1 = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( IIiIIIi1iii1 ,
 IiIiIII11i1i . policy_name , IiIiIII11i1i . set_action ) )
  else :
   IIiIIIi1iii1 = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( IIiIIIi1iii1 ,
 IiIiIII11i1i . policy_name ) )
   O000oO0O0 = True
   if 38 - 38: IiII . IiII
   if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
   if 47 - 47: Ii1I % OOooOOo . Oo0Ooo
 if ( Iio0oO0 != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( iIiI1I1ii1I1 , False ) , O00O0o , green ( oOo00OO0ooo , False ) ,
  # oO0o % OoO0O00 % oO0o . i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
 Iio0oO0 ) )
  if 80 - 80: OoOoOO00 . I11i
  IIiii11iiI111 = IiiiiiIiI . registered_rlocs
  IiIIi = 1440
  if ( IiII11I1I1II ) :
   if ( IiiiiiIiI . site_id != 0 ) :
    o0ooO = map_request . source_eid
    IIiii11iiI111 = lisp_get_private_rloc_set ( IiiiiiIiI , o0ooO , iiI )
    if 23 - 23: I1ii11iIi11i % iIii1I11I1II1
   if ( IIiii11iiI111 == IiiiiiIiI . registered_rlocs ) :
    oOooOO00OooO = ( IiiiiiIiI . group . is_null ( ) == False )
    iii1 = lisp_get_partial_rloc_set ( IIiii11iiI111 , iIiiii1iIi11 , oOooOO00OooO )
    if ( iii1 != IIiii11iiI111 ) :
     IiIIi = 15
     IIiii11iiI111 = iii1
     if 40 - 40: I1Ii111 - OOooOOo * IiII + o0oOOo0O0Ooo - I1IiiI
     if 75 - 75: I1IiiI
     if 84 - 84: OoO0O00 . I1ii11iIi11i - i11iIiiIii / I1Ii111 / i1IIi
     if 26 - 26: IiII + OOooOOo / I1Ii111 . i1IIi
     if 59 - 59: iIii1I11I1II1 / I1Ii111 * o0oOOo0O0Ooo
     if 38 - 38: iIii1I11I1II1 . oO0o * I1ii11iIi11i + iII111i
     if 90 - 90: IiII % I1ii11iIi11i - I1ii11iIi11i - iII111i
     if 63 - 63: O0 % i1IIi + OoOoOO00 + I11i . IiII + ooOoO0o
  if ( IiiiiiIiI . force_ttl != None ) :
   IiIIi = IiiiiiIiI . force_ttl | 0x80000000
   if 19 - 19: O0 - i1IIi / I1Ii111
   if 14 - 14: I11i - i11iIiiIii
   if 49 - 49: oO0o . I1ii11iIi11i
   if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
   if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
   if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
  if ( oOo0Oooooo ) :
   if ( oOo0Oooooo . set_record_ttl ) :
    IiIIi = oOo0Oooooo . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( IiIIi ) )
    if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
   if ( oOo0Oooooo . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    Oo0Oo00O000O = LISP_POLICY_DENIED_ACTION
    IIiii11iiI111 = [ ]
   else :
    IIIi1iI1 = oOo0Oooooo . set_policy_map_reply ( )
    if ( IIIi1iI1 ) : IIiii11iiI111 = [ IIIi1iI1 ]
    if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
    if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
    if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
  if ( O000oO0O0 ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   Oo0Oo00O000O = LISP_POLICY_DENIED_ACTION
   IIiii11iiI111 = [ ]
   if 72 - 72: I1Ii111
   if 51 - 51: OoOoOO00
  iI11ii1IiIi11 = IiiiiiIiI . echo_nonce_capable
  if 61 - 61: Oo0Ooo / i1IIi + I1Ii111 - OoooooooOO / O0
  if 25 - 25: I1ii11iIi11i * i11iIiiIii / i1IIi
  if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
  if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
  if ( iIIii ) :
   ii11iIIII = IiiiiiIiI . eid
   Iii1iIiI1II = IiiiiiIiI . group
  else :
   ii11iIIII = oo0oO
   Iii1iIiI1II = iiI
   Oo0Oo00O000O = LISP_AUTH_FAILURE_ACTION
   IIiii11iiI111 = [ ]
   if 51 - 51: I1Ii111 * iIii1I11I1II1 . OoO0O00 - I1ii11iIi11i + I11i / OoO0O00
   if 36 - 36: o0oOOo0O0Ooo + ooOoO0o * I11i
   if 81 - 81: OOooOOo * I11i - I1ii11iIi11i
   if 82 - 82: I1ii11iIi11i * II111iiii - OoooooooOO % iII111i * I1IiiI % OoOoOO00
   if 81 - 81: I11i + o0oOOo0O0Ooo / iII111i
   if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
  if ( iIiii11 ) :
   ii11iIIII = oo0oO
   Iii1iIiI1II = iiI
   if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
   if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
   if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
   if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
   if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
   if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
  packet = lisp_build_map_reply ( ii11iIIII , Iii1iIiI1II , IIiii11iiI111 ,
 o00oO0O000 , Oo0Oo00O000O , IiIIi , map_request , None , iI11ii1IiIi11 , False )
  if 66 - 66: iII111i % iII111i
  if ( iIiii11 ) :
   lisp_process_pubsub ( lisp_sockets , packet , ii11iIIII , oo00O0OO0Ooo0 ,
 mr_sport , o00oO0O000 , IiIIi , ooOOoOO000 )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , oo00O0OO0Ooo0 , mr_sport )
   if 59 - 59: II111iiii . i1IIi % i1IIi
   if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
  return ( [ IiiiiiIiI . eid , IiiiiiIiI . group , LISP_DDT_ACTION_MS_ACK ] )
  if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
  if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
  if 13 - 13: Ii1I % i11iIiiIii
  if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
  if 50 - 50: I1ii11iIi11i + iII111i
 ooOOo0ooo = len ( IiiiiiIiI . registered_rlocs )
 if ( ooOOo0ooo == 0 ) :
  lprint ( ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" ) . format ( green ( iIiI1I1ii1I1 , False ) , O00O0o ,
  # oO0o . iIii1I11I1II1 . I1Ii111 - Oo0Ooo
 green ( oOo00OO0ooo , False ) ) )
  return ( [ IiiiiiIiI . eid , IiiiiiIiI . group , LISP_DDT_ACTION_MS_ACK ] )
  if 7 - 7: ooOoO0o . Oo0Ooo
  if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
  if 66 - 66: I1IiiI + I11i
  if 58 - 58: I1ii11iIi11i
  if 7 - 7: oO0o - I11i
 O0oO = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 45 - 45: IiII + oO0o . iII111i
 O0o0oo0 = map_request . target_eid . hash_address ( O0oO )
 O0o0oo0 %= ooOOo0ooo
 O00000ooO0OOo = IiiiiiIiI . registered_rlocs [ O0o0oo0 ]
 if 67 - 67: O0 . i1IIi / I1ii11iIi11i % i1IIi
 if ( O00000ooO0OOo . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( iIiI1I1ii1I1 , False ) ,
  # OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
 O00O0o , green ( oOo00OO0ooo , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( iIiI1I1ii1I1 , False ) ,
  # I1IiiI + I1IiiI . i1IIi
 red ( O00000ooO0OOo . rloc . print_address ( ) , False ) , O00O0o ,
 green ( oOo00OO0ooo , False ) ) )
  if 83 - 83: iII111i
  if 51 - 51: OoO0O00
  if 45 - 45: I1ii11iIi11i + Ii1I * I1ii11iIi11i % Ii1I - O0 * OoooooooOO
  if 98 - 98: OoO0O00 / o0oOOo0O0Ooo . OoooooooOO % i11iIiiIii % Oo0Ooo + OoOoOO00
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , O00000ooO0OOo . rloc , to_etr = True )
  if 49 - 49: II111iiii - OOooOOo - I1IiiI / Ii1I
 return ( [ IiiiiiIiI . eid , IiiiiiIiI . group , LISP_DDT_ACTION_MS_ACK ] )
 if 47 - 47: I1ii11iIi11i + OoO0O00
 if 95 - 95: I11i . OoOoOO00 / Oo0Ooo % ooOoO0o % II111iiii
 if 82 - 82: ooOoO0o - I11i / I1Ii111 - i11iIiiIii - iIii1I11I1II1
 if 53 - 53: iIii1I11I1II1 % I11i . i1IIi + IiII / OoOoOO00 . II111iiii
 if 43 - 43: O0 - IiII + i11iIiiIii * i1IIi - ooOoO0o % IiII
 if 23 - 23: OoooooooOO % o0oOOo0O0Ooo + OoO0O00
 if 25 - 25: IiII % OOooOOo + Ii1I * I1ii11iIi11i
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 25 - 25: iIii1I11I1II1 * OoOoOO00 % I1IiiI + IiII
 if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
 if 83 - 83: II111iiii . OOooOOo
 if 88 - 88: O0
 oo0oO = map_request . target_eid
 iiI = map_request . target_group
 iIiI1I1ii1I1 = lisp_print_eid_tuple ( oo0oO , iiI )
 o00oO0O000 = map_request . nonce
 Oo0Oo00O000O = LISP_DDT_ACTION_NULL
 if 12 - 12: Ii1I % OOooOOo % Oo0Ooo * I1Ii111
 if 96 - 96: iII111i + ooOoO0o
 if 100 - 100: OOooOOo . ooOoO0o + Ii1I + Ii1I
 if 70 - 70: ooOoO0o . iIii1I11I1II1 / oO0o
 if 18 - 18: Ii1I / OoooooooOO % i1IIi * o0oOOo0O0Ooo
 O0ooO0oOoOo = None
 if ( lisp_i_am_ms ) :
  IiiiiiIiI = lisp_site_eid_lookup ( oo0oO , iiI , False )
  if ( IiiiiiIiI == None ) : return
  if 54 - 54: o0oOOo0O0Ooo
  if ( IiiiiiIiI . registered ) :
   Oo0Oo00O000O = LISP_DDT_ACTION_MS_ACK
   IiIIi = 1440
  else :
   oo0oO , iiI , Oo0Oo00O000O = lisp_ms_compute_neg_prefix ( oo0oO , iiI )
   Oo0Oo00O000O = LISP_DDT_ACTION_MS_NOT_REG
   IiIIi = 1
   if 53 - 53: II111iiii / IiII . i1IIi + I1Ii111 / OoO0O00 - OoooooooOO
 else :
  O0ooO0oOoOo = lisp_ddt_cache_lookup ( oo0oO , iiI , False )
  if ( O0ooO0oOoOo == None ) :
   Oo0Oo00O000O = LISP_DDT_ACTION_NOT_AUTH
   IiIIi = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( iIiI1I1ii1I1 , False ) ) )
   if 67 - 67: ooOoO0o . Ii1I - Oo0Ooo * iII111i . I11i - OOooOOo
  elif ( O0ooO0oOoOo . is_auth_prefix ( ) ) :
   if 10 - 10: I11i
   if 37 - 37: o0oOOo0O0Ooo / I1IiiI * oO0o / II111iiii
   if 39 - 39: IiII - i1IIi - IiII - OoooooooOO - I1ii11iIi11i
   if 66 - 66: IiII + i1IIi
   Oo0Oo00O000O = LISP_DDT_ACTION_DELEGATION_HOLE
   IiIIi = 15
   i1ii = O0ooO0oOoOo . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( i1ii ,
   # ooOoO0o % Ii1I . i1IIi
 green ( iIiI1I1ii1I1 , False ) ) )
   if 21 - 21: i11iIiiIii / II111iiii % OoOoOO00 * oO0o - ooOoO0o + II111iiii
   if ( iiI . is_null ( ) ) :
    oo0oO = lisp_ddt_compute_neg_prefix ( oo0oO , O0ooO0oOoOo ,
 lisp_ddt_cache )
   else :
    iiI = lisp_ddt_compute_neg_prefix ( iiI , O0ooO0oOoOo ,
 lisp_ddt_cache )
    oo0oO = lisp_ddt_compute_neg_prefix ( oo0oO , O0ooO0oOoOo ,
 O0ooO0oOoOo . source_cache )
    if 66 - 66: i11iIiiIii * I1Ii111
   O0ooO0oOoOo = None
  else :
   i1ii = O0ooO0oOoOo . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( i1ii , green ( iIiI1I1ii1I1 , False ) ) )
   if 7 - 7: OoO0O00 . OoO0O00 % ooOoO0o * Oo0Ooo - O0 / Ii1I
   IiIIi = 1440
   if 54 - 54: I1Ii111 - ooOoO0o
   if 16 - 16: Ii1I + i11iIiiIii . OoO0O00 / I11i . I11i % I11i
   if 80 - 80: i11iIiiIii + OoO0O00
   if 2 - 2: II111iiii
   if 67 - 67: oO0o % I1Ii111
   if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
 OO0 = lisp_build_map_referral ( oo0oO , iiI , O0ooO0oOoOo , Oo0Oo00O000O , IiIIi , o00oO0O000 )
 o00oO0O000 = map_request . nonce >> 32
 if ( map_request . nonce != 0 and o00oO0O000 != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , OO0 , ecm_source , port )
 return
 if 15 - 15: I1IiiI
 if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
 if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
 if 45 - 45: I1Ii111 + OOooOOo
 if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
 if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
 if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
 if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
 if 75 - 75: oO0o / i1IIi / Ii1I * Oo0Ooo
 if 75 - 75: Oo0Ooo / OoooooooOO
 if 98 - 98: II111iiii - I1Ii111 . ooOoO0o * iII111i
 if 49 - 49: I1ii11iIi11i / OoooooooOO - I11i
 if 76 - 76: i1IIi . OoO0O00 . O0 / OOooOOo - iII111i
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 oo00o = eid . hash_address ( entry_prefix )
 OOooO0Ooo = eid . addr_length ( ) * 8
 I1iIii11iIi1I = 0
 if 6 - 6: I1ii11iIi11i / i1IIi
 if 11 - 11: iIii1I11I1II1
 if 94 - 94: i1IIi . Oo0Ooo / o0oOOo0O0Ooo % I1Ii111 / OOooOOo + OoOoOO00
 if 21 - 21: Oo0Ooo / Oo0Ooo
 for I1iIii11iIi1I in range ( OOooO0Ooo ) :
  i1111i = 1 << ( OOooO0Ooo - I1iIii11iIi1I - 1 )
  if ( oo00o & i1111i ) : break
  if 15 - 15: OoooooooOO - i1IIi - Oo0Ooo - IiII
  if 80 - 80: II111iiii - I1ii11iIi11i / iIii1I11I1II1 % Oo0Ooo . Ii1I
 if ( I1iIii11iIi1I > neg_prefix . mask_len ) : neg_prefix . mask_len = I1iIii11iIi1I
 return
 if 33 - 33: OOooOOo + I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: iII111i
 if 56 - 56: Oo0Ooo / II111iiii
 if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
 if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
 if 10 - 10: OoOoOO00 % I11i
 if 46 - 46: i1IIi % IiII
 if 45 - 45: I1ii11iIi11i / I1ii11iIi11i - OoO0O00
 if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
 if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
def lisp_neg_prefix_walk ( entry , parms ) :
 oo0oO , o00 , IiI1i = parms
 if 11 - 11: o0oOOo0O0Ooo - iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
 if ( o00 == None ) :
  if ( entry . eid . instance_id != oo0oO . instance_id ) :
   return ( [ True , parms ] )
   if 51 - 51: I1IiiI + O0
  if ( entry . eid . afi != oo0oO . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( o00 ) == False ) :
   return ( [ True , parms ] )
   if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
   if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
   if 85 - 85: OoOoOO00
   if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
   if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
   if 72 - 72: Ii1I
 lisp_find_negative_mask_len ( oo0oO , entry . eid , IiI1i )
 return ( [ True , parms ] )
 if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
 if 85 - 85: i11iIiiIii / I11i
 if 28 - 28: i11iIiiIii + IiII / I11i . Ii1I / OoO0O00
 if 100 - 100: o0oOOo0O0Ooo - I11i . o0oOOo0O0Ooo
 if 90 - 90: OoOoOO00 / II111iiii / I11i * I11i - iIii1I11I1II1
 if 87 - 87: IiII
 if 92 - 92: OoO0O00 / IiII - ooOoO0o
 if 45 - 45: iII111i - I11i * ooOoO0o * OOooOOo / I1Ii111 * iII111i
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 33 - 33: iIii1I11I1II1 % I1ii11iIi11i - OOooOOo % iIii1I11I1II1 + I11i / i11iIiiIii
 if 64 - 64: I11i * ooOoO0o / OoooooooOO
 if 38 - 38: iIii1I11I1II1 . OoO0O00 * OoOoOO00 + OoOoOO00 + ooOoO0o
 if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 IiI1i = lisp_address ( eid . afi , "" , 0 , 0 )
 IiI1i . copy_address ( eid )
 IiI1i . mask_len = 0
 if 63 - 63: OoOoOO00 % IiII . iII111i
 iiiI1I = ddt_entry . print_eid_tuple ( )
 o00 = ddt_entry . eid
 if 32 - 32: IiII + iIii1I11I1II1
 if 42 - 42: OoOoOO00 + OoooooooOO * OOooOOo - i11iIiiIii + OOooOOo
 if 11 - 11: i11iIiiIii % Oo0Ooo % II111iiii . IiII % OoOoOO00
 if 10 - 10: Ii1I
 if 68 - 68: Oo0Ooo % ooOoO0o + i11iIiiIii / oO0o / II111iiii
 eid , o00 , IiI1i = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , o00 , IiI1i ) )
 if 63 - 63: OoO0O00 % i1IIi - OoooooooOO / ooOoO0o
 if 75 - 75: OOooOOo + IiII + ooOoO0o / I1IiiI . iIii1I11I1II1 / Oo0Ooo
 if 81 - 81: I1Ii111 % II111iiii - Oo0Ooo / I1IiiI + i11iIiiIii . I11i
 if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
 IiI1i . mask_address ( IiI1i . mask_len )
 if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # i1IIi * i11iIiiIii + I1IiiI - I1IiiI
 iiiI1I , IiI1i . print_prefix ( ) ) )
 return ( IiI1i )
 if 37 - 37: I1ii11iIi11i % OOooOOo % Oo0Ooo
 if 87 - 87: II111iiii * I1IiiI
 if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
 if 20 - 20: Oo0Ooo % OOooOOo
 if 8 - 8: OOooOOo
 if 92 - 92: iII111i / OOooOOo . IiII / I11i + o0oOOo0O0Ooo
 if 99 - 99: II111iiii
 if 70 - 70: O0 % I1ii11iIi11i
def lisp_ms_compute_neg_prefix ( eid , group ) :
 IiI1i = lisp_address ( eid . afi , "" , 0 , 0 )
 IiI1i . copy_address ( eid )
 IiI1i . mask_len = 0
 I1Ii11I1 = lisp_address ( group . afi , "" , 0 , 0 )
 I1Ii11I1 . copy_address ( group )
 I1Ii11I1 . mask_len = 0
 o00 = None
 if 87 - 87: iIii1I11I1II1 % OoO0O00 . Ii1I . i11iIiiIii - i11iIiiIii
 if 86 - 86: I1ii11iIi11i - IiII
 if 33 - 33: i11iIiiIii * i11iIiiIii . I11i / i11iIiiIii
 if 100 - 100: OOooOOo % I1IiiI * I11i * I1IiiI
 if 65 - 65: iII111i - i11iIiiIii - iIii1I11I1II1 / O0 / OoO0O00
 if ( group . is_null ( ) ) :
  O0ooO0oOoOo = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( O0ooO0oOoOo == None ) :
   IiI1i . mask_len = IiI1i . host_mask_len ( )
   I1Ii11I1 . mask_len = I1Ii11I1 . host_mask_len ( )
   return ( [ IiI1i , I1Ii11I1 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 42 - 42: iIii1I11I1II1 . oO0o
  IIIIi = lisp_sites_by_eid
  if ( O0ooO0oOoOo . is_auth_prefix ( ) ) : o00 = O0ooO0oOoOo . eid
 else :
  O0ooO0oOoOo = lisp_ddt_cache . lookup_cache ( group , False )
  if ( O0ooO0oOoOo == None ) :
   IiI1i . mask_len = IiI1i . host_mask_len ( )
   I1Ii11I1 . mask_len = I1Ii11I1 . host_mask_len ( )
   return ( [ IiI1i , I1Ii11I1 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 51 - 51: OOooOOo
  if ( O0ooO0oOoOo . is_auth_prefix ( ) ) : o00 = O0ooO0oOoOo . group
  if 73 - 73: Oo0Ooo * OoOoOO00 . oO0o % iII111i
  group , o00 , I1Ii11I1 = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , o00 , I1Ii11I1 ) )
  if 79 - 79: I11i * I1ii11iIi11i
  if 85 - 85: iIii1I11I1II1 * O0 / iII111i
  I1Ii11I1 . mask_address ( I1Ii11I1 . mask_len )
  if 75 - 75: Oo0Ooo * IiII % Ii1I
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , o00 . print_prefix ( ) if ( o00 != None ) else "'not found'" ,
  # IiII + O0 - i11iIiiIii
  # iII111i - I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / Oo0Ooo
  # I1ii11iIi11i % Ii1I / iIii1I11I1II1 . OoOoOO00 / II111iiii . I11i
 I1Ii11I1 . print_prefix ( ) ) )
  if 99 - 99: O0 + O0 / IiII / iII111i + OoOoOO00 % I1IiiI
  IIIIi = O0ooO0oOoOo . source_cache
  if 40 - 40: I1IiiI . I1ii11iIi11i - ooOoO0o / o0oOOo0O0Ooo
  if 37 - 37: iII111i * OoOoOO00 % I1ii11iIi11i - I1Ii111
  if 13 - 13: Oo0Ooo + Oo0Ooo
  if 20 - 20: OoO0O00 * OoOoOO00 . OOooOOo
  if 14 - 14: iII111i / i1IIi + II111iiii
 Oo0Oo00O000O = LISP_DDT_ACTION_DELEGATION_HOLE if ( o00 != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 54 - 54: Ii1I - I1IiiI + iII111i * iII111i
 if 78 - 78: I1Ii111
 if 79 - 79: IiII * IiII . OOooOOo + iIii1I11I1II1 . II111iiii
 if 87 - 87: I11i
 if 67 - 67: i1IIi / i1IIi + IiII . oO0o
 if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
 eid , o00 , IiI1i = IIIIi . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , o00 , IiI1i ) )
 if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
 if 8 - 8: I1ii11iIi11i / i1IIi - I1ii11iIi11i + Ii1I + OoO0O00 - I11i
 if 79 - 79: OoooooooOO - I1Ii111 * I1IiiI . I1Ii111 - iIii1I11I1II1
 if 27 - 27: OoOoOO00 % OoOoOO00 % II111iiii
 IiI1i . mask_address ( IiI1i . mask_len )
 if 45 - 45: iIii1I11I1II1 . o0oOOo0O0Ooo % I1IiiI
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # I1Ii111
 # ooOoO0o / i1IIi
 o00 . print_prefix ( ) if ( o00 != None ) else "'not found'" , IiI1i . print_prefix ( ) ) )
 if 38 - 38: Oo0Ooo - OoOoOO00 % IiII % OoooooooOO
 if 79 - 79: II111iiii % OOooOOo / I1ii11iIi11i % Oo0Ooo - o0oOOo0O0Ooo
 return ( [ IiI1i , I1Ii11I1 , Oo0Oo00O000O ] )
 if 60 - 60: IiII + ooOoO0o - iII111i
 if 69 - 69: iIii1I11I1II1 + oO0o
 if 16 - 16: OoO0O00 / I11i * OoOoOO00 % OoO0O00 * oO0o * o0oOOo0O0Ooo
 if 80 - 80: o0oOOo0O0Ooo % I11i + O0 % i1IIi
 if 58 - 58: oO0o / I1ii11iIi11i * O0 % I11i
 if 34 - 34: oO0o / O0 * oO0o
 if 47 - 47: iIii1I11I1II1 - o0oOOo0O0Ooo % Ii1I
 if 38 - 38: ooOoO0o / IiII * I1ii11iIi11i % I1ii11iIi11i % oO0o
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 82 - 82: I1ii11iIi11i . i11iIiiIii - I11i . iII111i / OOooOOo
 oo0oO = map_request . target_eid
 iiI = map_request . target_group
 o00oO0O000 = map_request . nonce
 if 60 - 60: I1IiiI / I1IiiI / II111iiii
 if ( action == LISP_DDT_ACTION_MS_ACK ) : IiIIi = 1440
 if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
 if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
 if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
 if 34 - 34: I1Ii111 / i1IIi
 iiiiIii = lisp_map_referral ( )
 iiiiIii . record_count = 1
 iiiiIii . nonce = o00oO0O000
 OO0 = iiiiIii . encode ( )
 iiiiIii . print_map_referral ( )
 if 95 - 95: OoOoOO00 * OOooOOo
 OOiiI1iii1I = False
 if 68 - 68: I1Ii111 / iIii1I11I1II1 % Ii1I
 if 77 - 77: i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
 if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
 if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
 if 77 - 77: OOooOOo + ooOoO0o / O0
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( oo0oO ,
 iiI )
  IiIIi = 15
  if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : IiIIi = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : IiIIi = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : IiIIi = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : IiIIi = 0
 if 49 - 49: ooOoO0o . Ii1I
 O0Oo = False
 ooOOo0ooo = 0
 O0ooO0oOoOo = lisp_ddt_cache_lookup ( oo0oO , iiI , False )
 if ( O0ooO0oOoOo != None ) :
  ooOOo0ooo = len ( O0ooO0oOoOo . delegation_set )
  O0Oo = O0ooO0oOoOo . is_ms_peer_entry ( )
  O0ooO0oOoOo . map_referrals_sent += 1
  if 47 - 47: OoO0O00 * I1Ii111 % OoooooooOO
  if 38 - 38: Ii1I % i1IIi
  if 41 - 41: I1ii11iIi11i . ooOoO0o / Oo0Ooo + i1IIi / i11iIiiIii * I1IiiI
  if 63 - 63: ooOoO0o + i11iIiiIii / i1IIi - I1Ii111 . O0 % OOooOOo
  if 39 - 39: o0oOOo0O0Ooo
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : OOiiI1iii1I = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  OOiiI1iii1I = ( O0Oo == False )
  if 88 - 88: iII111i % I1IiiI . iIii1I11I1II1 * OOooOOo / IiII % OoooooooOO
  if 94 - 94: ooOoO0o % oO0o - OoooooooOO + IiII * Ii1I
  if 60 - 60: OoO0O00 - O0 + o0oOOo0O0Ooo + I1ii11iIi11i
  if 78 - 78: OOooOOo * Oo0Ooo * Ii1I
  if 94 - 94: OoooooooOO % iII111i
 oOO0O0o0oOooO = lisp_eid_record ( )
 oOO0O0o0oOooO . rloc_count = ooOOo0ooo
 oOO0O0o0oOooO . authoritative = True
 oOO0O0o0oOooO . action = action
 oOO0O0o0oOooO . ddt_incomplete = OOiiI1iii1I
 oOO0O0o0oOooO . eid = eid_prefix
 oOO0O0o0oOooO . group = group_prefix
 oOO0O0o0oOooO . record_ttl = IiIIi
 if 48 - 48: iIii1I11I1II1
 OO0 += oOO0O0o0oOooO . encode ( )
 oOO0O0o0oOooO . print_record ( "  " , True )
 if 25 - 25: i1IIi % o0oOOo0O0Ooo . iII111i / OoooooooOO + i1IIi
 if 76 - 76: Oo0Ooo / OOooOOo + ooOoO0o % OoooooooOO - Oo0Ooo - I11i
 if 36 - 36: OoO0O00 . Oo0Ooo * I1ii11iIi11i
 if 16 - 16: IiII + OOooOOo
 if ( ooOOo0ooo != 0 ) :
  for I1iII1iI1 in O0ooO0oOoOo . delegation_set :
   iIIi = lisp_rloc_record ( )
   iIIi . rloc = I1iII1iI1 . delegate_address
   iIIi . priority = I1iII1iI1 . priority
   iIIi . weight = I1iII1iI1 . weight
   iIIi . mpriority = 255
   iIIi . mweight = 0
   iIIi . reach_bit = True
   OO0 += iIIi . encode ( )
   iIIi . print_record ( "    " )
   if 33 - 33: ooOoO0o . i11iIiiIii + OOooOOo
   if 77 - 77: OoooooooOO * Ii1I * iIii1I11I1II1 + IiII
   if 53 - 53: IiII + I1Ii111 + oO0o
   if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
   if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
   if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
   if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , OO0 , ecm_source , port )
 return
 if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
 if 41 - 41: I1ii11iIi11i * IiII
 if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
 if 29 - 29: OoooooooOO / oO0o
 if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
 if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
 if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
 if 46 - 46: OOooOOo % I1IiiI
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub ) :
 if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # oO0o % Oo0Ooo
 red ( dest . print_address ( ) , False ) ) )
 if 92 - 92: OoooooooOO - OoOoOO00
 Oo0Oo00O000O = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 48 - 48: oO0o / i1IIi . II111iiii
 if 46 - 46: O0 * oO0o * I1Ii111
 if 76 - 76: Oo0Ooo + OOooOOo - i1IIi * iII111i % i11iIiiIii
 if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 if ( lisp_get_eid_hash ( eid ) != None ) :
  Oo0Oo00O000O = LISP_SEND_MAP_REQUEST_ACTION
  if 41 - 41: Ii1I + IiII
  if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
 OO0 = lisp_build_map_reply ( eid , group , [ ] , nonce , Oo0Oo00O000O , ttl , None ,
 None , False , False )
 if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
 if 99 - 99: i1IIi * OoOoOO00 - i1IIi
 if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
 if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , OO0 , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , OO0 , dest , port )
  if 90 - 90: I11i * i11iIiiIii % i1IIi + I1Ii111 / OoO0O00
 return
 if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
 if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
 if 45 - 45: I1ii11iIi11i - I11i
 if 60 - 60: OOooOOo - OOooOOo * OoOoOO00 / Ii1I % iII111i % Oo0Ooo
 if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
 if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
 if 61 - 61: iIii1I11I1II1 . Oo0Ooo . i1IIi
def lisp_retransmit_ddt_map_request ( mr ) :
 iI11iI11i11ii = mr . mr_source . print_address ( )
 i1OOOoO0O0O0O = mr . print_eid_tuple ( )
 o00oO0O000 = mr . nonce
 if 13 - 13: Oo0Ooo / OoO0O00 + I1Ii111
 if 48 - 48: I1ii11iIi11i * i1IIi + I1Ii111
 if 80 - 80: I1IiiI % I11i
 if 64 - 64: OOooOOo + i11iIiiIii + I1IiiI . I11i % I11i - o0oOOo0O0Ooo
 if 3 - 3: I1IiiI / i1IIi + II111iiii + Oo0Ooo
 if ( mr . last_request_sent_to ) :
  ii1iiI11 = mr . last_request_sent_to . print_address ( )
  oOo0 = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( oOo0 and ii1iiI11 in oOo0 . referral_set ) :
   oOo0 . referral_set [ ii1iiI11 ] . no_responses += 1
   if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
   if 66 - 66: i11iIiiIii
   if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
   if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
   if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
   if 10 - 10: I11i
   if 24 - 24: Ii1I
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( i1OOOoO0O0O0O , False ) , lisp_hex_string ( o00oO0O000 ) ) )
  if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
  mr . dequeue_map_request ( )
  return
  if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
  if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
 mr . retry_count += 1
 if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
 I1iiIi111I = green ( iI11iI11i11ii , False )
 iiIi = green ( i1OOOoO0O0O0O , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # I1Ii111 * IiII . oO0o / oO0o / o0oOOo0O0Ooo % Oo0Ooo
 red ( mr . itr . print_address ( ) , False ) , I1iiIi111I , iiIi ,
 lisp_hex_string ( o00oO0O000 ) ) )
 if 11 - 11: OoO0O00 / ooOoO0o
 if 37 - 37: I1IiiI . OoO0O00
 if 13 - 13: Oo0Ooo - OoooooooOO % Ii1I
 if 89 - 89: I11i + I1IiiI - II111iiii
 lisp_send_ddt_map_request ( mr , False )
 if 4 - 4: I1ii11iIi11i
 if 51 - 51: I1Ii111 . O0 - OoOoOO00 + i11iIiiIii * II111iiii
 if 39 - 39: iII111i . OoO0O00 % I1IiiI * II111iiii * OoooooooOO . II111iiii
 if 97 - 97: oO0o - Ii1I - II111iiii % II111iiii * OOooOOo
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 84 - 84: i1IIi . OoOoOO00 % I1ii11iIi11i . OoO0O00 + i11iIiiIii
 if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
 if 68 - 68: iII111i
 if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
 if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
 if 9 - 9: IiII * O0 + OOooOOo . II111iiii
 if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
 if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
 if 16 - 16: I1Ii111 + II111iiii + IiII
 if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
 if 46 - 46: ooOoO0o % II111iiii
 oOI11 = [ ]
 for o00o0 in list ( referral . referral_set . values ( ) ) :
  if ( o00o0 . updown == False ) : continue
  if ( len ( oOI11 ) == 0 or oOI11 [ 0 ] . priority == o00o0 . priority ) :
   oOI11 . append ( o00o0 )
  elif ( oOI11 [ 0 ] . priority > o00o0 . priority ) :
   oOI11 = [ ]
   oOI11 . append ( o00o0 )
   if 23 - 23: oO0o * OoooooooOO / Oo0Ooo / I1Ii111
   if 72 - 72: OoOoOO00 . i11iIiiIii
   if 25 - 25: i1IIi
 oO0OoO = len ( oOI11 )
 if ( oO0OoO == 0 ) : return ( None )
 if 28 - 28: OoO0O00 . IiII - i1IIi * OOooOOo - I1Ii111
 O0o0oo0 = dest_eid . hash_address ( source_eid )
 O0o0oo0 = O0o0oo0 % oO0OoO
 return ( oOI11 [ O0o0oo0 ] )
 if 65 - 65: iIii1I11I1II1 / IiII / IiII
 if 57 - 57: OoOoOO00 . O0 / iII111i / i11iIiiIii
 if 38 - 38: iII111i - Oo0Ooo / O0
 if 40 - 40: ooOoO0o + iIii1I11I1II1 / OoOoOO00 * iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
 if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
 if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
 if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 IiI1iii = mr . lisp_sockets
 o00oO0O000 = mr . nonce
 i11iII = mr . itr
 I1ii11IIi = mr . mr_source
 iIiI1I1ii1I1 = mr . print_eid_tuple ( )
 if 1 - 1: II111iiii - II111iiii
 if 83 - 83: o0oOOo0O0Ooo + o0oOOo0O0Ooo - i1IIi / o0oOOo0O0Ooo + I1Ii111 * OoooooooOO
 if 79 - 79: OoOoOO00 . OOooOOo
 if 97 - 97: II111iiii . OOooOOo
 if 68 - 68: IiII * IiII + oO0o / o0oOOo0O0Ooo
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( iIiI1I1ii1I1 , False ) , lisp_hex_string ( o00oO0O000 ) ) )
  if 41 - 41: OoOoOO00 - O0
  mr . dequeue_map_request ( )
  return
  if 48 - 48: OoooooooOO % Ii1I * OoO0O00 / I1ii11iIi11i
  if 53 - 53: ooOoO0o + oO0o - II111iiii
  if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
  if 6 - 6: iIii1I11I1II1 + oO0o
  if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
  if 29 - 29: Ii1I . OOooOOo
 if ( send_to_root ) :
  ooOI1ii = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  o0O0o00oO0ooo = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( iIiI1I1ii1I1 , False ) ) )
 else :
  ooOI1ii = mr . eid
  o0O0o00oO0ooo = mr . group
  if 6 - 6: iIii1I11I1II1 . O0 . oO0o + I1ii11iIi11i
  if 32 - 32: I1IiiI / OOooOOo . i11iIiiIii - IiII . iII111i . Ii1I
  if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
  if 37 - 37: I1Ii111 / OoooooooOO
  if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
 iiiiiI111 = lisp_referral_cache_lookup ( ooOI1ii , o0O0o00oO0ooo , False )
 if ( iiiiiI111 == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( IiI1iii , ooOI1ii , o0O0o00oO0ooo ,
 o00oO0O000 , i11iII , mr . sport , 15 , None , False )
  return
  if 50 - 50: OoooooooOO % I1IiiI * I1Ii111 + I1Ii111 - I1Ii111
  if 60 - 60: I11i + O0 * I1IiiI * O0 * II111iiii
 o0oOo = iiiiiI111 . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( o0oOo ,
 iiiiiI111 . print_referral_type ( ) ) )
 if 42 - 42: I1Ii111 * OoO0O00
 o00o0 = lisp_get_referral_node ( iiiiiI111 , I1ii11IIi , mr . eid )
 if ( o00o0 == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( IiI1iii , iiiiiI111 . eid ,
 iiiiiI111 . group , o00oO0O000 , i11iII , mr . sport , 1 , None , False )
  return
  if 93 - 93: I11i * IiII . i11iIiiIii
  if 41 - 41: I1Ii111 / o0oOOo0O0Ooo - iII111i + OoooooooOO
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( o00o0 . referral_address . print_address ( ) ,
 # iIii1I11I1II1
 iiiiiI111 . print_referral_type ( ) , green ( iIiI1I1ii1I1 , False ) ,
 lisp_hex_string ( o00oO0O000 ) ) )
 if 99 - 99: OoOoOO00
 if 89 - 89: i11iIiiIii
 if 11 - 11: iIii1I11I1II1 . i1IIi . O0 / ooOoO0o
 if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
 iI111iiI = ( iiiiiI111 . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 iiiiiI111 . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( IiI1iii , mr . packet , I1ii11IIi , mr . sport , mr . eid ,
 o00o0 . referral_address , to_ms = iI111iiI , ddt = True )
 if 6 - 6: iII111i + II111iiii . IiII . Ii1I / ooOoO0o / I11i
 if 85 - 85: ooOoO0o / II111iiii / OoO0O00 + Ii1I / i1IIi . iII111i
 if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
 if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
 mr . last_request_sent_to = o00o0 . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 o00o0 . map_requests_sent += 1
 return
 if 85 - 85: I1IiiI + i1IIi % I1Ii111
 if 76 - 76: i11iIiiIii % i11iIiiIii
 if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
 if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
 if 69 - 69: O0 % I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 . OOooOOo
 if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 if 61 - 61: OOooOOo
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 51 - 51: Oo0Ooo * OOooOOo / iII111i
 oo0oO = map_request . target_eid
 iiI = map_request . target_group
 i1OOOoO0O0O0O = map_request . print_eid_tuple ( )
 iI11iI11i11ii = mr_source . print_address ( )
 o00oO0O000 = map_request . nonce
 if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
 I1iiIi111I = green ( iI11iI11i11ii , False )
 iiIi = green ( i1OOOoO0O0O0O , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # Oo0Ooo % I1IiiI - I1Ii111 % i11iIiiIii
 red ( ecm_source . print_address ( ) , False ) , I1iiIi111I , iiIi ,
 lisp_hex_string ( o00oO0O000 ) ) )
 if 36 - 36: O0 . I11i / o0oOOo0O0Ooo + i1IIi + oO0o * IiII
 if 29 - 29: O0 - II111iiii + iII111i
 if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
 if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
 oooO = lisp_ddt_map_request ( lisp_sockets , packet , oo0oO , iiI , o00oO0O000 )
 oooO . packet = packet
 oooO . itr = ecm_source
 oooO . mr_source = mr_source
 oooO . sport = sport
 oooO . from_pitr = map_request . pitr_bit
 oooO . queue_map_request ( )
 if 14 - 14: OOooOOo
 lisp_send_ddt_map_request ( oooO , False )
 return
 if 84 - 84: Ii1I + OoO0O00 + OOooOOo % ooOoO0o
 if 27 - 27: OoOoOO00 % I11i
 if 19 - 19: i1IIi - OoOoOO00
 if 26 - 26: IiII . i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / o0oOOo0O0Ooo
 if 7 - 7: I1IiiI / OOooOOo * iIii1I11I1II1 * Ii1I * i1IIi
 if 87 - 87: IiII * Oo0Ooo - OOooOOo * OoOoOO00
 if 61 - 61: Oo0Ooo - OoooooooOO % I1ii11iIi11i / i1IIi + O0 % ooOoO0o
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 79 - 79: I1ii11iIi11i
 o0O0OoOOo0o = packet
 i1ioo = lisp_map_request ( )
 packet = i1ioo . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 38 - 38: IiII . I1ii11iIi11i + iII111i * I11i % IiII
  if 18 - 18: I11i
 i1ioo . print_map_request ( )
 if 19 - 19: I1ii11iIi11i * o0oOOo0O0Ooo % I11i / O0 % Ii1I % I1ii11iIi11i
 if 21 - 21: OoOoOO00 . ooOoO0o * OoO0O00 - OoOoOO00 - OoooooooOO
 if 23 - 23: I1Ii111 + iIii1I11I1II1 - o0oOOo0O0Ooo - iII111i - O0 / iIii1I11I1II1
 if 24 - 24: I1IiiI * o0oOOo0O0Ooo % iII111i % OoooooooOO - ooOoO0o - OoO0O00
 if ( i1ioo . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , i1ioo , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 75 - 75: i1IIi . i1IIi
  if 7 - 7: OoooooooOO / iII111i
  if 32 - 32: IiII
  if 89 - 89: I1IiiI
  if 24 - 24: o0oOOo0O0Ooo - i1IIi . II111iiii
 if ( i1ioo . smr_bit ) :
  lisp_process_smr ( i1ioo )
  if 73 - 73: i11iIiiIii % OoooooooOO - i1IIi - O0 * I1Ii111
  if 73 - 73: I1ii11iIi11i + OoooooooOO - OoOoOO00 + Oo0Ooo
  if 47 - 47: II111iiii + iII111i / i1IIi * Ii1I . OoO0O00 + IiII
  if 7 - 7: i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o * I1ii11iIi11i
  if 34 - 34: OoOoOO00 - I11i
 if ( i1ioo . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( i1ioo )
  if 85 - 85: OoOoOO00 . oO0o
  if 98 - 98: I1Ii111
  if 49 - 49: OoO0O00 / I1ii11iIi11i % IiII * II111iiii
  if 92 - 92: iIii1I11I1II1 . OoooooooOO . ooOoO0o / II111iiii
  if 30 - 30: i1IIi * Ii1I + Ii1I / I1Ii111
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , i1ioo , mr_source ,
 mr_port , ttl , timestamp )
  if 84 - 84: I1IiiI - Oo0Ooo * OoO0O00 * oO0o
  if 13 - 13: I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + oO0o - iII111i
  if 32 - 32: I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
  if 33 - 33: ooOoO0o % I11i
  if 72 - 72: OoO0O00 % OoooooooOO / II111iiii * oO0o * I1Ii111
 if ( lisp_i_am_ms ) :
  packet = o0O0OoOOo0o
  oo0oO , iiI , OOO0oOooOOo00 = lisp_ms_process_map_request ( lisp_sockets ,
 o0O0OoOOo0o , i1ioo , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , i1ioo , ecm_source ,
 ecm_port , OOO0oOooOOo00 , oo0oO , iiI )
   if 4 - 4: IiII . O0 * I1IiiI * O0 - i11iIiiIii - O0
  return
  if 26 - 26: Oo0Ooo * i11iIiiIii - i11iIiiIii . i11iIiiIii / I11i
  if 26 - 26: Oo0Ooo - II111iiii % ooOoO0o
  if 81 - 81: i11iIiiIii + I1ii11iIi11i * oO0o
  if 86 - 86: OoO0O00 . ooOoO0o . o0oOOo0O0Ooo
  if 70 - 70: O0 % OoooooooOO - Ii1I * Oo0Ooo
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , o0O0OoOOo0o , i1ioo ,
 ecm_source , mr_port , mr_source )
  if 18 - 18: OOooOOo . I1IiiI + i1IIi . I1IiiI
  if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
  if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
  if 6 - 6: O0 * I1Ii111 - II111iiii
  if 60 - 60: oO0o % oO0o
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = o0O0OoOOo0o
  lisp_ddt_process_map_request ( lisp_sockets , i1ioo , ecm_source ,
 ecm_port )
  if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 return
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
 if 82 - 82: I1ii11iIi11i
 if 75 - 75: I11i - II111iiii
 if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
 if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
 if 76 - 76: OOooOOo - iII111i + IiII
 if 48 - 48: I1IiiI - II111iiii
 if 15 - 15: O0
def lisp_store_mr_stats ( source , nonce ) :
 oooO = lisp_get_map_resolver ( source , None )
 if ( oooO == None ) : return
 if 54 - 54: iIii1I11I1II1
 if 54 - 54: iII111i + OOooOOo + OoO0O00
 if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
 if 65 - 65: IiII + OoOoOO00
 oooO . neg_map_replies_received += 1
 oooO . last_reply = lisp_get_timestamp ( )
 if 93 - 93: Ii1I
 if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
 if 5 - 5: OoO0O00 / ooOoO0o
 if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
 if ( ( oooO . neg_map_replies_received % 100 ) == 0 ) : oooO . total_rtt = 0
 if 97 - 97: oO0o / Ii1I
 if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 if 91 - 91: IiII * Ii1I * OOooOOo
 if ( oooO . last_nonce == nonce ) :
  oooO . total_rtt += ( time . time ( ) - oooO . last_used )
  oooO . last_nonce = 0
  if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 if ( ( oooO . neg_map_replies_received % 10 ) == 0 ) : oooO . last_nonce = 0
 return
 if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
 if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
 if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
 if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
 if 95 - 95: IiII + iII111i % I1IiiI
 if 18 - 18: Oo0Ooo
 if 8 - 8: O0 + iIii1I11I1II1 - O0
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 67 - 67: O0
 iIO0OOoOOO0OO = lisp_map_reply ( )
 packet = iIO0OOoOOO0OO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
 iIO0OOoOOO0OO . print_map_reply ( )
 if 28 - 28: O0 - Oo0Ooo
 if 58 - 58: iIii1I11I1II1 - OoooooooOO - iII111i
 if 43 - 43: ooOoO0o / o0oOOo0O0Ooo
 if 56 - 56: II111iiii * I1ii11iIi11i * O0 . iII111i . I1ii11iIi11i % I1Ii111
 OOOOOoO00 = None
 for OoOOoO0oOo in range ( iIO0OOoOOO0OO . record_count ) :
  oOO0O0o0oOooO = lisp_eid_record ( )
  packet = oOO0O0o0oOooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 56 - 56: IiII + OOooOOo
  oOO0O0o0oOooO . print_record ( "  " , False )
  if 89 - 89: o0oOOo0O0Ooo . Oo0Ooo
  if 48 - 48: o0oOOo0O0Ooo / O0 % i1IIi
  if 82 - 82: OoOoOO00 * Ii1I . I1ii11iIi11i * OoO0O00 % Oo0Ooo
  if 95 - 95: OoO0O00 / oO0o
  if 15 - 15: I1IiiI - o0oOOo0O0Ooo % iIii1I11I1II1 % I11i * OoOoOO00 % IiII
  if ( oOO0O0o0oOooO . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , iIO0OOoOOO0OO . nonce )
   if 74 - 74: iII111i - O0 * o0oOOo0O0Ooo / OoooooooOO + II111iiii + Ii1I
   if 39 - 39: i11iIiiIii . IiII + I1ii11iIi11i % IiII
  o0OooO = ( oOO0O0o0oOooO . group . is_null ( ) == False )
  if 96 - 96: I11i / I1IiiI . i1IIi
  if 67 - 67: i11iIiiIii
  if 3 - 3: IiII
  if 47 - 47: O0
  if 60 - 60: OOooOOo / ooOoO0o + Oo0Ooo / O0 - oO0o
  if ( lisp_decent_push_configured ) :
   Oo0Oo00O000O = oOO0O0o0oOooO . action
   if ( o0OooO and Oo0Oo00O000O == LISP_DROP_ACTION ) :
    if ( oOO0O0o0oOooO . eid . is_local ( ) ) : continue
    if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
    if 4 - 4: I1IiiI
    if 31 - 31: ooOoO0o * i1IIi . O0
    if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
    if 100 - 100: I1Ii111
    if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
    if 88 - 88: IiII
  if ( o0OooO == False and oOO0O0o0oOooO . eid . is_null ( ) ) : continue
  if 29 - 29: iII111i . ooOoO0o
  if 62 - 62: IiII
  if 95 - 95: ooOoO0o / i1IIi + II111iiii + OoO0O00 % OoO0O00
  if 18 - 18: ooOoO0o * I1IiiI / iII111i % iII111i
  if 9 - 9: i11iIiiIii % ooOoO0o % O0 + i1IIi / O0
  if ( o0OooO ) :
   I111I1iI1 = lisp_map_cache_lookup ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group )
  else :
   I111I1iI1 = lisp_map_cache . lookup_cache ( oOO0O0o0oOooO . eid , True )
   if 80 - 80: I1Ii111 / ooOoO0o % OoO0O00 - II111iiii * o0oOOo0O0Ooo
  oO0oo = ( I111I1iI1 == None )
  if 87 - 87: IiII + OOooOOo - iIii1I11I1II1 + OoOoOO00 % IiII
  if 88 - 88: Ii1I . iIii1I11I1II1 . iII111i - O0 . ooOoO0o
  if 3 - 3: OoOoOO00
  if 79 - 79: i11iIiiIii * OoooooooOO
  if 50 - 50: I1IiiI * II111iiii . I1Ii111 / I1Ii111
  if ( I111I1iI1 == None ) :
   iiiI1iI11i1i1 , I1iIiiI1IIi1 , i1iIi1II1 = lisp_allow_gleaning ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ,
 None )
   if ( iiiI1iI11i1i1 ) : continue
  else :
   if ( I111I1iI1 . gleaned ) : continue
   if 66 - 66: OoO0O00 * oO0o / i11iIiiIii * O0 . OOooOOo % iIii1I11I1II1
   if 15 - 15: ooOoO0o . O0 - i11iIiiIii - I1Ii111 - Oo0Ooo / OoOoOO00
   if 68 - 68: Ii1I % Oo0Ooo
   if 74 - 74: iIii1I11I1II1 / O0 + Ii1I . O0 + iII111i
   if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
  IIiii11iiI111 = [ ]
  iII1II1I = None
  for IiIii1Ii in range ( oOO0O0o0oOooO . rloc_count ) :
   iIIi = lisp_rloc_record ( )
   iIIi . keys = iIO0OOoOOO0OO . keys
   packet = iIIi . decode ( packet , iIO0OOoOOO0OO . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 37 - 37: Oo0Ooo / i1IIi + OoO0O00
   iIIi . print_record ( "    " )
   if 83 - 83: OOooOOo / OOooOOo * OOooOOo . I1ii11iIi11i . iII111i % OOooOOo
   O00Oo0o00 = None
   if ( I111I1iI1 ) : O00Oo0o00 = I111I1iI1 . get_rloc ( iIIi . rloc )
   if ( O00Oo0o00 ) :
    IIIi1iI1 = O00Oo0o00
   else :
    IIIi1iI1 = lisp_rloc ( )
    if 7 - 7: i11iIiiIii . I1ii11iIi11i
    if 4 - 4: i11iIiiIii % OoO0O00 . oO0o
    if 72 - 72: i1IIi + I1Ii111 . oO0o * oO0o * I1IiiI
    if 40 - 40: OoO0O00 % ooOoO0o + iII111i + IiII + I11i * Oo0Ooo
    if 99 - 99: Oo0Ooo
    if 99 - 99: I1Ii111 + oO0o % OoooooooOO
    if 88 - 88: ooOoO0o % Oo0Ooo * II111iiii
   IiO0o = IIIi1iI1 . store_rloc_from_record ( iIIi , iIO0OOoOOO0OO . nonce ,
 source )
   IIIi1iI1 . echo_nonce_capable = iIO0OOoOOO0OO . echo_nonce_capable
   if 62 - 62: iII111i * I1Ii111 % OoOoOO00 * O0
   if ( IIIi1iI1 . echo_nonce_capable ) :
    Oo0o = IIIi1iI1 . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , Oo0o ) == None ) :
     lisp_echo_nonce ( Oo0o )
     if 85 - 85: II111iiii - O0 . i11iIiiIii . o0oOOo0O0Ooo + ooOoO0o - ooOoO0o
     if 25 - 25: I1ii11iIi11i % Ii1I * O0 / I1IiiI % OOooOOo
     if 42 - 42: IiII - IiII - I1ii11iIi11i + i1IIi * Oo0Ooo
     if 80 - 80: oO0o + O0
     if 84 - 84: i1IIi - II111iiii
     if 2 - 2: i11iIiiIii - OoO0O00 * Oo0Ooo
   if ( IIIi1iI1 . json ) :
    if ( lisp_is_json_telemetry ( IIIi1iI1 . json . json_string ) ) :
     iIIII = IIIi1iI1 . json . json_string
     iIIII = lisp_encode_telemetry ( iIIII , ii = itr_in_ts )
     IIIi1iI1 . json . json_string = iIIII
     if 100 - 100: I1Ii111
     if 5 - 5: IiII % oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / Ii1I
     if 55 - 55: Oo0Ooo / o0oOOo0O0Ooo
     if 51 - 51: I1IiiI + i11iIiiIii / ooOoO0o % I1IiiI + Oo0Ooo
     if 6 - 6: OoOoOO00 . O0
     if 44 - 44: ooOoO0o % I11i + ooOoO0o . oO0o
     if 70 - 70: O0 - I11i . iIii1I11I1II1 % I11i . OoOoOO00 % oO0o
     if 5 - 5: O0 * OoO0O00
     if 61 - 61: Ii1I / I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
     if 84 - 84: OoooooooOO - Oo0Ooo
   if ( iIO0OOoOOO0OO . rloc_probe and iIIi . probe_bit ) :
    if ( IIIi1iI1 . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( IIIi1iI1 , source , IiO0o ,
 iIO0OOoOOO0OO , ttl , iII1II1I )
     if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
    if ( IIIi1iI1 . rloc . is_multicast_address ( ) ) : iII1II1I = IIIi1iI1
    if 82 - 82: OoOoOO00
    if 61 - 61: oO0o . o0oOOo0O0Ooo
    if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
    if 70 - 70: I1IiiI
    if 74 - 74: ooOoO0o * II111iiii
   IIiii11iiI111 . append ( IIIi1iI1 )
   if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
   if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
   if 83 - 83: o0oOOo0O0Ooo / oO0o
   if 24 - 24: Ii1I + oO0o / OoooooooOO % i11iIiiIii
   if ( lisp_data_plane_security and IIIi1iI1 . rloc_recent_rekey ( ) ) :
    OOOOOoO00 = IIIi1iI1
    if 1 - 1: iII111i / I1Ii111 * I1IiiI + OoOoOO00 . OoooooooOO
    if 5 - 5: I1IiiI
    if 74 - 74: i1IIi * Oo0Ooo - OoOoOO00 * o0oOOo0O0Ooo
    if 85 - 85: iIii1I11I1II1 * IiII / i11iIiiIii - ooOoO0o - o0oOOo0O0Ooo
    if 30 - 30: OoOoOO00 - OOooOOo . Oo0Ooo
    if 11 - 11: IiII - I1Ii111 - OoO0O00 * o0oOOo0O0Ooo
    if 99 - 99: O0 - OoO0O00
    if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
    if 91 - 91: I1Ii111
    if 49 - 49: I11i
    if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
  if ( iIO0OOoOOO0OO . rloc_probe == False and lisp_nat_traversal ) :
   iii1 = [ ]
   IIII1 = [ ]
   for IIIi1iI1 in IIiii11iiI111 :
    if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
    if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
    if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
    if 10 - 10: ooOoO0o
    if 69 - 69: I11i + I1IiiI / oO0o
    if ( IIIi1iI1 . rloc . is_private_address ( ) ) :
     IIIi1iI1 . priority = 1
     IIIi1iI1 . state = LISP_RLOC_UNREACH_STATE
     iii1 . append ( IIIi1iI1 )
     IIII1 . append ( IIIi1iI1 . rloc . print_address_no_iid ( ) )
     continue
     if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
     if 85 - 85: I1Ii111 - oO0o
     if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
     if 96 - 96: oO0o
     if 44 - 44: OoooooooOO / iII111i * Oo0Ooo % OoOoOO00 . oO0o
     if 97 - 97: iIii1I11I1II1 / ooOoO0o
    if ( IIIi1iI1 . priority == 254 and lisp_i_am_rtr == False ) :
     iii1 . append ( IIIi1iI1 )
     IIII1 . append ( IIIi1iI1 . rloc . print_address_no_iid ( ) )
     if 16 - 16: Oo0Ooo % IiII
    if ( IIIi1iI1 . priority != 254 and lisp_i_am_rtr ) :
     iii1 . append ( IIIi1iI1 )
     IIII1 . append ( IIIi1iI1 . rloc . print_address_no_iid ( ) )
     if 48 - 48: I1IiiI . I1Ii111 . o0oOOo0O0Ooo
     if 72 - 72: Ii1I * OoO0O00 / OoO0O00
     if 39 - 39: oO0o
   if ( IIII1 != [ ] ) :
    IIiii11iiI111 = iii1
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( IIII1 ) )
    if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
    if 57 - 57: oO0o + O0 - OoOoOO00
    if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
    if 93 - 93: o0oOOo0O0Ooo + i1IIi
    if 24 - 24: i1IIi
    if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
    if 99 - 99: Oo0Ooo
  iii1 = [ ]
  for IIIi1iI1 in IIiii11iiI111 :
   if ( IIIi1iI1 . json != None ) : continue
   iii1 . append ( IIIi1iI1 )
   if 38 - 38: I1ii11iIi11i - I1IiiI
  if ( iii1 != [ ] ) :
   Ooo0oOOoo0O = len ( IIiii11iiI111 ) - len ( iii1 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( Ooo0oOOoo0O ) )
   if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
   IIiii11iiI111 = iii1
   if 42 - 42: iII111i + I1ii11iIi11i
   if 44 - 44: I1ii11iIi11i % IiII
   if 1 - 1: Oo0Ooo + IiII - I1Ii111 / I1Ii111
   if 25 - 25: OoOoOO00
   if 52 - 52: OOooOOo + IiII
   if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
   if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
   if 5 - 5: OOooOOo - I1Ii111 + IiII
  if ( iIO0OOoOOO0OO . rloc_probe and I111I1iI1 != None ) : IIiii11iiI111 = I111I1iI1 . rloc_set
  if 82 - 82: OOooOOo
  if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
  if 26 - 26: I1IiiI - OOooOOo
  if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
  if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
  iiiiIi1111ii1 = oO0oo
  if ( I111I1iI1 and IIiii11iiI111 != I111I1iI1 . rloc_set ) :
   I111I1iI1 . delete_rlocs_from_rloc_probe_list ( )
   iiiiIi1111ii1 = True
   if 10 - 10: i1IIi / i1IIi * iIii1I11I1II1 * OoOoOO00 * oO0o / II111iiii
   if 23 - 23: I11i . OoOoOO00 + I1Ii111 + oO0o + II111iiii
   if 71 - 71: OoOoOO00 * OoOoOO00
   if 27 - 27: II111iiii + OoooooooOO - I11i * o0oOOo0O0Ooo
   if 67 - 67: i11iIiiIii - OoOoOO00
  OoOoOOo = I111I1iI1 . uptime if ( I111I1iI1 ) else None
  if ( I111I1iI1 == None ) :
   I111I1iI1 = lisp_mapping ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group , IIiii11iiI111 )
   I111I1iI1 . mapping_source = source
   if 38 - 38: o0oOOo0O0Ooo . OoO0O00
   if 51 - 51: Ii1I + IiII * o0oOOo0O0Ooo / I1IiiI . I1ii11iIi11i + I1ii11iIi11i
   if 37 - 37: II111iiii - ooOoO0o / Oo0Ooo * iIii1I11I1II1 . II111iiii % I1Ii111
   if 28 - 28: i11iIiiIii + OoO0O00 % O0 - I1ii11iIi11i % oO0o
   if 30 - 30: I11i + OOooOOo
   if 27 - 27: OoOoOO00 . ooOoO0o
   if ( lisp_i_am_rtr and oOO0O0o0oOooO . group . is_null ( ) == False ) :
    I111I1iI1 . map_cache_ttl = LISP_MCAST_TTL
   else :
    I111I1iI1 . map_cache_ttl = oOO0O0o0oOooO . store_ttl ( )
    if 73 - 73: o0oOOo0O0Ooo
   I111I1iI1 . action = oOO0O0o0oOooO . action
   I111I1iI1 . add_cache ( iiiiIi1111ii1 )
   if 8 - 8: O0
   if 40 - 40: OOooOOo . II111iiii . ooOoO0o % o0oOOo0O0Ooo
  iii1II11I1IiI = "Add"
  if ( OoOoOOo ) :
   I111I1iI1 . uptime = OoOoOOo
   I111I1iI1 . refresh_time = lisp_get_timestamp ( )
   iii1II11I1IiI = "Replace"
   if 18 - 18: Ii1I - ooOoO0o
   if 14 - 14: ooOoO0o . o0oOOo0O0Ooo + II111iiii
  lprint ( "{} {} map-cache with {} RLOCs" . format ( iii1II11I1IiI ,
 green ( I111I1iI1 . print_eid_tuple ( ) , False ) , len ( IIiii11iiI111 ) ) )
  if 50 - 50: Ii1I - i1IIi * oO0o
  if 52 - 52: I11i / oO0o - oO0o
  if 84 - 84: iIii1I11I1II1 - o0oOOo0O0Ooo
  if 37 - 37: iII111i * o0oOOo0O0Ooo
  if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
  if ( lisp_ipc_dp_socket and OOOOOoO00 != None ) :
   lisp_write_ipc_keys ( OOOOOoO00 )
   if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
   if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
   if 34 - 34: O0 * oO0o
   if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
   if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
   if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
   if 88 - 88: i11iIiiIii
  if ( oO0oo ) :
   iII11 = bold ( "RLOC-probe" , False )
   for IIIi1iI1 in I111I1iI1 . best_rloc_set :
    Oo0o = red ( IIIi1iI1 . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( iII11 , Oo0o ) )
    lisp_send_map_request ( lisp_sockets , 0 , I111I1iI1 . eid , I111I1iI1 . group , IIIi1iI1 )
    if 20 - 20: I1Ii111 . iII111i * I1ii11iIi11i + OoooooooOO
    if 56 - 56: OOooOOo * I1Ii111 % OOooOOo + Ii1I
    if 78 - 78: OOooOOo * OoOoOO00
 return
 if 20 - 20: IiII
 if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
 if 66 - 66: OoooooooOO + IiII . II111iiii
 if 66 - 66: iIii1I11I1II1 % I11i
 if 38 - 38: I1ii11iIi11i * ooOoO0o
 if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
 if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
 if 65 - 65: OOooOOo
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 90 - 90: O0
 packet = map_register . zero_auth ( packet )
 O0o0oo0 = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
 if 38 - 38: oO0o * I11i % OOooOOo
 if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
 if 47 - 47: Ii1I - Oo0Ooo * OoOoOO00
 map_register . auth_data = O0o0oo0
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 20 - 20: oO0o
 if 48 - 48: I1IiiI % OoO0O00
 if 33 - 33: Ii1I
 if 73 - 73: Ii1I . IiII
 if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
 if 90 - 90: i11iIiiIii * i1IIi
 if 88 - 88: i11iIiiIii - OoOoOO00
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  iIiIi1IiiiI1 = hashlib . sha1
  if 64 - 64: OoO0O00 + I1ii11iIi11i / OoO0O00 * I1Ii111 . Oo0Ooo
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  iIiIi1IiiiI1 = hashlib . sha256
  if 5 - 5: iII111i - iIii1I11I1II1 * IiII
  if 52 - 52: OOooOOo
 if ( do_hex ) :
  O0o0oo0 = hmac . new ( password , packet , iIiIi1IiiiI1 ) . hexdigest ( )
 else :
  O0o0oo0 = hmac . new ( password , packet , iIiIi1IiiiI1 ) . digest ( )
  if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
 return ( O0o0oo0 )
 if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
 if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
 if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
 if 66 - 66: I1IiiI
 if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
 if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
 if 22 - 22: I1Ii111
 if 41 - 41: O0 * i1IIi
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
 O0o0oo0 = lisp_hash_me ( packet , alg_id , password , True )
 iIiI1 = ( O0o0oo0 == auth_data )
 if 7 - 7: Ii1I
 if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
 if 63 - 63: OOooOOo + iII111i - IiII - I1IiiI % IiII . OoO0O00
 if 73 - 73: OoOoOO00
 if ( iIiI1 == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( O0o0oo0 , auth_data ) )
  if 47 - 47: oO0o
  if 17 - 17: IiII
 return ( iIiI1 )
 if 47 - 47: I11i . I1IiiI % ooOoO0o . i11iIiiIii
 if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
 if 100 - 100: O0
 if 9 - 9: Ii1I
 if 87 - 87: I1IiiI
 if 56 - 56: OOooOOo % oO0o - OoOoOO00
 if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
def lisp_retransmit_map_notify ( map_notify ) :
 OO0oooOO = map_notify . etr
 IiO0o = map_notify . etr_port
 if 81 - 81: oO0o / iIii1I11I1II1
 if 15 - 15: Ii1I + I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
 if 28 - 28: ooOoO0o
 if 88 - 88: oO0o
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( OO0oooOO . print_address ( ) , False ) ) )
  if 77 - 77: ooOoO0o + I1Ii111 . OoOoOO00
  if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
  IIIOoo = map_notify . nonce_key
  if ( IIIOoo in lisp_map_notify_queue ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( IIIOoo ) )
   if 26 - 26: I11i
   try :
    lisp_map_notify_queue . pop ( IIIOoo )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
    if 43 - 43: Ii1I % I11i
  return
  if 5 - 5: OoooooooOO % i11iIiiIii * o0oOOo0O0Ooo * OoooooooOO - o0oOOo0O0Ooo % I11i
  if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
 IiI1iii = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 36 - 36: OOooOOo
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # I1Ii111 % ooOoO0o - ooOoO0o
 red ( OO0oooOO . print_address ( ) , False ) , map_notify . retry_count ) )
 if 38 - 38: O0
 lisp_send_map_notify ( IiI1iii , map_notify . packet , OO0oooOO , IiO0o )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 20 - 20: I1Ii111
 if 75 - 75: I1IiiI / I1Ii111 . I1Ii111 / I1IiiI + OOooOOo + o0oOOo0O0Ooo
 if 68 - 68: i1IIi + OoO0O00
 if 60 - 60: i11iIiiIii . ooOoO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 59 - 59: OoooooooOO . Ii1I . OOooOOo / iII111i - I1IiiI
 if 69 - 69: oO0o / Oo0Ooo % iII111i
 if 34 - 34: I1IiiI
 if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
 if 39 - 39: O0 . OOooOOo
 if 95 - 95: I11i
 if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 8 - 8: I1ii11iIi11i
 if 100 - 100: OoooooooOO / I11i - Ii1I
 if 11 - 11: OoO0O00
 if 20 - 20: Oo0Ooo
 eid_record . rloc_count = len ( parent . registered_rlocs )
 I1iiIIiiiII = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 if 1 - 1: I1ii11iIi11i
 if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
 if 81 - 81: iII111i % IiII / I11i
 for i11i11i in parent . registered_rlocs :
  iIIi = lisp_rloc_record ( )
  iIIi . store_rloc_entry ( i11i11i )
  iIIi . local_bit = True
  iIIi . probe_bit = False
  iIIi . reach_bit = True
  I1iiIIiiiII += iIIi . encode ( )
  iIIi . print_record ( "  " )
  del ( iIIi )
  if 93 - 93: I1IiiI
  if 52 - 52: Ii1I / ooOoO0o
  if 57 - 57: Oo0Ooo * II111iiii % iIii1I11I1II1
  if 13 - 13: iII111i . OoOoOO00 * I1ii11iIi11i + OOooOOo % i1IIi
  if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
 for i11i11i in parent . registered_rlocs :
  OO0oooOO = i11i11i . rloc
  IIiIiii1ii1i = lisp_map_notify ( lisp_sockets )
  IIiIiii1ii1i . record_count = 1
  IiII11iI1 = map_register . key_id
  IIiIiii1ii1i . key_id = IiII11iI1
  IIiIiii1ii1i . alg_id = map_register . alg_id
  IIiIiii1ii1i . auth_len = map_register . auth_len
  IIiIiii1ii1i . nonce = map_register . nonce
  IIiIiii1ii1i . nonce_key = lisp_hex_string ( IIiIiii1ii1i . nonce )
  IIiIiii1ii1i . etr . copy_address ( OO0oooOO )
  IIiIiii1ii1i . etr_port = map_register . sport
  IIiIiii1ii1i . site = parent . site
  OO0 = IIiIiii1ii1i . encode ( I1iiIIiiiII , parent . site . auth_key [ IiII11iI1 ] )
  IIiIiii1ii1i . print_notify ( )
  if 35 - 35: Oo0Ooo / I1ii11iIi11i - I1IiiI . i11iIiiIii . iII111i * OoOoOO00
  if 66 - 66: i1IIi / IiII
  if 17 - 17: O0 - OOooOOo
  if 96 - 96: OOooOOo * I1ii11iIi11i
  IIIOoo = IIiIiii1ii1i . nonce_key
  if ( IIIOoo in lisp_map_notify_queue ) :
   Oo0oO = lisp_map_notify_queue [ IIIOoo ]
   Oo0oO . retransmit_timer . cancel ( )
   del ( Oo0oO )
   if 9 - 9: i11iIiiIii % iIii1I11I1II1 + i11iIiiIii + Oo0Ooo % OOooOOo
  lisp_map_notify_queue [ IIIOoo ] = IIiIiii1ii1i
  if 58 - 58: iII111i + OOooOOo / i1IIi * ooOoO0o
  if 37 - 37: OoO0O00
  if 19 - 19: ooOoO0o
  if 4 - 4: Oo0Ooo - i1IIi . Oo0Ooo * I11i . i1IIi + OOooOOo
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( OO0oooOO . print_address ( ) , False ) ) )
  if 3 - 3: IiII / iII111i * iII111i
  lisp_send ( lisp_sockets , OO0oooOO , LISP_CTRL_PORT , OO0 )
  if 15 - 15: O0 + I1IiiI * OoO0O00 - i1IIi + Ii1I . i1IIi
  parent . site . map_notifies_sent += 1
  if 99 - 99: II111iiii + iIii1I11I1II1 / o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 - iIii1I11I1II1
  if 38 - 38: I1IiiI . oO0o - II111iiii
  if 37 - 37: i1IIi % oO0o / IiII * I11i + ooOoO0o % Oo0Ooo
  if 75 - 75: o0oOOo0O0Ooo . I1Ii111 % i1IIi . i11iIiiIii
  IIiIiii1ii1i . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ IIiIiii1ii1i ] )
  IIiIiii1ii1i . retransmit_timer . start ( )
  if 38 - 38: o0oOOo0O0Ooo - OoO0O00 - i11iIiiIii
 return
 if 60 - 60: i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i * iII111i . oO0o + iII111i
 if 29 - 29: Oo0Ooo
 if 16 - 16: oO0o
 if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
 if 15 - 15: iII111i
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
 IIIOoo = lisp_hex_string ( nonce ) + source . print_address ( )
 if 45 - 45: II111iiii
 if 42 - 42: ooOoO0o
 if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
 if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
 if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
 if 10 - 10: oO0o * Oo0Ooo
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( IIIOoo in lisp_map_notify_queue ) :
  IIiIiii1ii1i = lisp_map_notify_queue [ IIIOoo ]
  I1iiIi111I = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( IIiIiii1ii1i . nonce ) , I1iiIi111I ) )
  if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
  return
  if 91 - 91: I1Ii111
  if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
 IIiIiii1ii1i = lisp_map_notify ( lisp_sockets )
 IIiIiii1ii1i . record_count = record_count
 key_id = key_id
 IIiIiii1ii1i . key_id = key_id
 IIiIiii1ii1i . alg_id = alg_id
 IIiIiii1ii1i . auth_len = auth_len
 IIiIiii1ii1i . nonce = nonce
 IIiIiii1ii1i . nonce_key = lisp_hex_string ( nonce )
 IIiIiii1ii1i . etr . copy_address ( source )
 IIiIiii1ii1i . etr_port = port
 IIiIiii1ii1i . site = site
 IIiIiii1ii1i . eid_list = eid_list
 if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
 if 100 - 100: ooOoO0o / I1ii11iIi11i * OoOoOO00 . I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
 if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
 if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
 if ( map_register_ack == False ) :
  IIIOoo = IIiIiii1ii1i . nonce_key
  lisp_map_notify_queue [ IIIOoo ] = IIiIiii1ii1i
  if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
  if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
  if 69 - 69: IiII
  if 13 - 13: i11iIiiIii
  if 49 - 49: OoOoOO00
  if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
 OO0 = IIiIiii1ii1i . encode ( eid_records , site . auth_key [ key_id ] )
 IIiIiii1ii1i . print_notify ( )
 if 80 - 80: I1IiiI - OOooOOo . oO0o
 if ( map_register_ack == False ) :
  oOO0O0o0oOooO = lisp_eid_record ( )
  oOO0O0o0oOooO . decode ( eid_records )
  oOO0O0o0oOooO . print_record ( "  " , False )
  if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
  if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
  if 8 - 8: OoO0O00 . OOooOOo % I1Ii111 * OOooOOo / I1IiiI
  if 3 - 3: IiII - I1ii11iIi11i . o0oOOo0O0Ooo
  if 39 - 39: oO0o . I1Ii111 + oO0o % OoOoOO00 - i11iIiiIii
 lisp_send_map_notify ( lisp_sockets , OO0 , IIiIiii1ii1i . etr , port )
 site . map_notifies_sent += 1
 if 69 - 69: I11i / OoO0O00
 if ( map_register_ack ) : return
 if 73 - 73: i11iIiiIii / i1IIi
 if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
 if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
 if 80 - 80: I1Ii111 / O0 * O0
 if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
 if 89 - 89: i11iIiiIii - II111iiii
 IIiIiii1ii1i . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ IIiIiii1ii1i ] )
 IIiIiii1ii1i . retransmit_timer . start ( )
 return
 if 67 - 67: IiII % I1Ii111 + i11iIiiIii
 if 53 - 53: OOooOOo
 if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
 if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
 if 52 - 52: Ii1I * I1ii11iIi11i
 if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
 if 9 - 9: I1ii11iIi11i + I11i
 if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
 if 4 - 4: OoOoOO00 / OoO0O00
 if 66 - 66: I1Ii111 / OoOoOO00
 if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
 OO0 = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
 if 25 - 25: oO0o / oO0o / Ii1I / O0
 if 56 - 56: ooOoO0o
 if 19 - 19: O0 * I1IiiI + I1ii11iIi11i
 OO0oooOO = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( OO0oooOO . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , OO0oooOO , LISP_CTRL_PORT , OO0 )
 return
 if 25 - 25: I11i - ooOoO0o / OoO0O00 / iII111i - OoO0O00
 if 86 - 86: OoO0O00
 if 89 - 89: OoooooooOO % iII111i * I1ii11iIi11i + I1ii11iIi11i . Oo0Ooo
 if 4 - 4: I11i
 if 8 - 8: IiII
 if 1 - 1: ooOoO0o . IiII
 if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
 if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 66 - 66: i1IIi . I1ii11iIi11i
 IIiIiii1ii1i = lisp_map_notify ( lisp_sockets )
 IIiIiii1ii1i . record_count = 1
 IIiIiii1ii1i . nonce = lisp_get_control_nonce ( )
 IIiIiii1ii1i . nonce_key = lisp_hex_string ( IIiIiii1ii1i . nonce )
 IIiIiii1ii1i . etr . copy_address ( xtr )
 IIiIiii1ii1i . etr_port = LISP_CTRL_PORT
 IIiIiii1ii1i . eid_list = eid_list
 IIIOoo = IIiIiii1ii1i . nonce_key
 if 86 - 86: Oo0Ooo
 if 48 - 48: OoO0O00
 if 55 - 55: OoO0O00 * i1IIi * I11i / iII111i
 if 42 - 42: IiII
 if 28 - 28: OoOoOO00 + OoOoOO00
 if 53 - 53: II111iiii % i1IIi + ooOoO0o . I1Ii111
 lisp_remove_eid_from_map_notify_queue ( IIiIiii1ii1i . eid_list )
 if ( IIIOoo in lisp_map_notify_queue ) :
  IIiIiii1ii1i = lisp_map_notify_queue [ IIIOoo ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( IIiIiii1ii1i . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
  return
  if 27 - 27: Oo0Ooo
  if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
  if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
  if 21 - 21: II111iiii
  if 23 - 23: I11i * i1IIi . oO0o / IiII + o0oOOo0O0Ooo
 lisp_map_notify_queue [ IIIOoo ] = IIiIiii1ii1i
 if 1 - 1: IiII / OoO0O00 . oO0o * I1Ii111 - i11iIiiIii
 if 50 - 50: oO0o - O0 / I1IiiI . OoOoOO00 . Oo0Ooo
 if 30 - 30: IiII . OoO0O00 + Oo0Ooo
 if 48 - 48: iIii1I11I1II1 / i11iIiiIii . OoOoOO00 * I11i
 i1oO0ooO00 = site_eid . rtrs_in_rloc_set ( )
 if ( i1oO0ooO00 ) :
  if ( site_eid . is_rtr_in_rloc_set ( xtr ) ) : i1oO0ooO00 = False
  if 93 - 93: ooOoO0o + O0 % ooOoO0o + OoO0O00 + iII111i
  if 17 - 17: oO0o + I11i
  if 10 - 10: i1IIi
  if 76 - 76: IiII % I1IiiI * Ii1I / Ii1I / OoooooooOO + Ii1I
  if 19 - 19: OoooooooOO
 oOO0O0o0oOooO = lisp_eid_record ( )
 oOO0O0o0oOooO . record_ttl = 1440
 oOO0O0o0oOooO . eid . copy_address ( site_eid . eid )
 oOO0O0o0oOooO . group . copy_address ( site_eid . group )
 oOO0O0o0oOooO . rloc_count = 0
 for O0O0OOo0O in site_eid . registered_rlocs :
  if ( i1oO0ooO00 ^ O0O0OOo0O . is_rtr ( ) ) : continue
  oOO0O0o0oOooO . rloc_count += 1
  if 88 - 88: I1IiiI % ooOoO0o % Oo0Ooo - O0
 OO0 = oOO0O0o0oOooO . encode ( )
 if 71 - 71: OOooOOo % Ii1I - i11iIiiIii - oO0o . ooOoO0o / I1Ii111
 if 53 - 53: iII111i . Oo0Ooo
 if 91 - 91: oO0o * OoooooooOO * oO0o % oO0o * II111iiii % I1Ii111
 if 8 - 8: Ii1I
 IIiIiii1ii1i . print_notify ( )
 oOO0O0o0oOooO . print_record ( "  " , False )
 if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
 if 94 - 94: oO0o
 if 95 - 95: ooOoO0o * O0 + OOooOOo
 if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
 for O0O0OOo0O in site_eid . registered_rlocs :
  if ( i1oO0ooO00 ^ O0O0OOo0O . is_rtr ( ) ) : continue
  iIIi = lisp_rloc_record ( )
  iIIi . store_rloc_entry ( O0O0OOo0O )
  iIIi . local_bit = True
  iIIi . probe_bit = False
  iIIi . reach_bit = True
  OO0 += iIIi . encode ( )
  iIIi . print_record ( "    " )
  if 21 - 21: ooOoO0o
  if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
  if 81 - 81: oO0o
  if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
  if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
 OO0 = IIiIiii1ii1i . encode ( OO0 , "" )
 if ( OO0 == None ) : return
 if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
 if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
 if 33 - 33: I11i
 if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
 lisp_send_map_notify ( lisp_sockets , OO0 , xtr , LISP_CTRL_PORT )
 if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
 if 32 - 32: oO0o
 if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
 IIiIiii1ii1i . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ IIiIiii1ii1i ] )
 IIiIiii1ii1i . retransmit_timer . start ( )
 return
 if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
 if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
 if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
 if 94 - 94: Ii1I
 if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
 if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
 if 34 - 34: iIii1I11I1II1
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 iI111I11iii1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 17 - 17: i1IIi
 for OoO0o0 in rle_list :
  iIIIi1I1i = lisp_site_eid_lookup ( OoO0o0 [ 0 ] , OoO0o0 [ 1 ] , True )
  if ( iIIIi1I1i == None ) : continue
  if 79 - 79: i11iIiiIii % II111iiii
  if 96 - 96: I1IiiI - OOooOOo % OoO0O00 . iII111i + OoooooooOO - OoO0O00
  if 92 - 92: IiII - i1IIi % OoO0O00 % I1IiiI * O0 . II111iiii
  if 80 - 80: O0 * I11i * I1Ii111
  if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
  if 25 - 25: iII111i + i1IIi
  if 64 - 64: IiII % I11i / iIii1I11I1II1
  oO0O0Ooo000 = iIIIi1I1i . registered_rlocs
  if ( len ( oO0O0Ooo000 ) == 0 ) :
   OO0000O0 = { }
   for i1I1I11II in list ( iIIIi1I1i . individual_registrations . values ( ) ) :
    for O0O0OOo0O in i1I1I11II . registered_rlocs :
     if ( O0O0OOo0O . is_rtr ( ) == False ) : continue
     OO0000O0 [ O0O0OOo0O . rloc . print_address ( ) ] = O0O0OOo0O
     if 99 - 99: Ii1I
     if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
   oO0O0Ooo000 = list ( OO0000O0 . values ( ) )
   if 32 - 32: IiII * II111iiii . Ii1I
   if 68 - 68: I11i / O0
   if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
   if 22 - 22: Ii1I / I1IiiI / II111iiii
   if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
   if 76 - 76: Oo0Ooo
  Oo0Oooo0 = [ ]
  OoO0 = False
  if ( iIIIi1I1i . eid . address == 0 and iIIIi1I1i . eid . mask_len == 0 ) :
   I1II1111iI = [ ]
   iIi1iiIiiII1I = [ ]
   if ( len ( oO0O0Ooo000 ) != 0 and oO0O0Ooo000 [ 0 ] . rle != None ) :
    iIi1iiIiiII1I = oO0O0Ooo000 [ 0 ] . rle . rle_nodes
    if 36 - 36: I1Ii111 + o0oOOo0O0Ooo % IiII
   for oO0oOOOO0oO0o0 in iIi1iiIiiII1I :
    Oo0Oooo0 . append ( oO0oOOOO0oO0o0 . address )
    I1II1111iI . append ( oO0oOOOO0oO0o0 . address . print_address_no_iid ( ) )
    if 68 - 68: I11i + i1IIi % OoooooooOO + OOooOOo
   lprint ( "Notify existing RLE-nodes {}" . format ( I1II1111iI ) )
  else :
   if 8 - 8: Oo0Ooo + IiII - II111iiii % Ii1I
   if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
   if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
   if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
   if 59 - 59: OoOoOO00
   for O0O0OOo0O in oO0O0Ooo000 :
    if ( O0O0OOo0O . is_rtr ( ) ) : Oo0Oooo0 . append ( O0O0OOo0O . rloc )
    if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
    if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
    if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
    if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
    if 7 - 7: OOooOOo
   OoO0 = ( len ( Oo0Oooo0 ) != 0 )
   if ( OoO0 == False ) :
    IiiiiiIiI = lisp_site_eid_lookup ( OoO0o0 [ 0 ] , iI111I11iii1 , False )
    if ( IiiiiiIiI == None ) : continue
    if 22 - 22: Oo0Ooo + ooOoO0o
    for O0O0OOo0O in IiiiiiIiI . registered_rlocs :
     if ( O0O0OOo0O . rloc . is_null ( ) ) : continue
     Oo0Oooo0 . append ( O0O0OOo0O . rloc )
     if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
     if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
     if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
     if 26 - 26: Oo0Ooo . Ii1I
     if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
     if 8 - 8: iIii1I11I1II1
   if ( len ( Oo0Oooo0 ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( iIIIi1I1i . print_eid_tuple ( ) , False ) ) )
    if 6 - 6: oO0o
    continue
    if 51 - 51: I1Ii111 - o0oOOo0O0Ooo
    if 5 - 5: O0
    if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
    if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
    if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
    if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
  for i11i11i in Oo0Oooo0 :
   lprint ( "Build Map-Notify to {}TR {} for {}" . format ( "R" if OoO0 else "x" , red ( i11i11i . print_address_no_iid ( ) , False ) ,
   # i11iIiiIii
 green ( iIIIi1I1i . print_eid_tuple ( ) , False ) ) )
   if 32 - 32: i1IIi / II111iiii
   o0oo0OOOo0O = [ iIIIi1I1i . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , iIIIi1I1i , o0oo0OOOo0O , i11i11i )
   time . sleep ( .001 )
   if 81 - 81: OoO0O00 . I1IiiI - IiII . ooOoO0o . i1IIi
   if 20 - 20: O0 - OoooooooOO % i1IIi + i11iIiiIii / Ii1I
 return
 if 6 - 6: I1ii11iIi11i * iII111i * i11iIiiIii * o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1
 if 78 - 78: I11i / Oo0Ooo / iII111i / OoOoOO00
 if 49 - 49: iIii1I11I1II1
 if 11 - 11: I1ii11iIi11i . ooOoO0o * IiII
 if 88 - 88: ooOoO0o * iIii1I11I1II1 * I1Ii111 + iII111i + O0 + OoOoOO00
 if 1 - 1: oO0o + ooOoO0o / iII111i
 if 11 - 11: IiII / OoO0O00 * I1ii11iIi11i
 if 20 - 20: I1IiiI * OoO0O00 / Oo0Ooo
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for OoOOoO0oOo in range ( rloc_count ) :
  iIIi = lisp_rloc_record ( )
  packet = iIIi . decode ( packet , None )
  O00o0OO0o0 = iIIi . json
  if ( O00o0OO0o0 == None ) : continue
  if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
  try :
   O00o0OO0o0 = json . loads ( O00o0OO0o0 . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 65 - 65: OoO0O00
   if 65 - 65: oO0o
  if ( "signature" not in O00o0OO0o0 ) : continue
  return ( iIIi )
  if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
 return ( None )
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
 if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
 if 71 - 71: I1IiiI
 if 27 - 27: OoO0O00 + i1IIi * OoooooooOO * iIii1I11I1II1 - Ii1I
 if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
 if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
 if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
 if 33 - 33: oO0o . oO0o / IiII + II111iiii
 if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
def lisp_get_eid_hash ( eid ) :
 iIii111 = None
 for i1IIiiIiiI1ii in lisp_eid_hashes :
  if 27 - 27: Ii1I
  if 66 - 66: O0
  if 68 - 68: oO0o / O0 % OoooooooOO
  if 58 - 58: iII111i / II111iiii - I11i * iIii1I11I1II1 % OoOoOO00
  i1oO00O = i1IIiiIiiI1ii . instance_id
  if ( i1oO00O == - 1 ) : i1IIiiIiiI1ii . instance_id = eid . instance_id
  if 14 - 14: iIii1I11I1II1 + oO0o / ooOoO0o
  IIo0o0oo0 = eid . is_more_specific ( i1IIiiIiiI1ii )
  i1IIiiIiiI1ii . instance_id = i1oO00O
  if ( IIo0o0oo0 ) :
   iIii111 = 128 - i1IIiiIiiI1ii . mask_len
   break
   if 98 - 98: OoooooooOO - i11iIiiIii - iII111i + Ii1I - I1IiiI
   if 75 - 75: OOooOOo
 if ( iIii111 == None ) : return ( None )
 if 25 - 25: iII111i / I1ii11iIi11i - ooOoO0o
 I1IIIi = eid . address
 O0ooIII1iIIi = ""
 for OoOOoO0oOo in range ( 0 , old_div ( iIii111 , 16 ) ) :
  oOOOo0o = I1IIIi & 0xffff
  oOOOo0o = hex ( oOOOo0o ) [ 2 : - 1 ]
  O0ooIII1iIIi = oOOOo0o . zfill ( 4 ) + ":" + O0ooIII1iIIi
  I1IIIi >>= 16
  if 70 - 70: I1IiiI
 if ( iIii111 % 16 != 0 ) :
  oOOOo0o = I1IIIi & 0xff
  oOOOo0o = hex ( oOOOo0o ) [ 2 : - 1 ]
  O0ooIII1iIIi = oOOOo0o . zfill ( 2 ) + ":" + O0ooIII1iIIi
  if 20 - 20: Oo0Ooo - OoOoOO00 - I11i . iII111i
 return ( O0ooIII1iIIi [ 0 : - 1 ] )
 if 16 - 16: i11iIiiIii * ooOoO0o . IiII - I11i + i1IIi * I11i
 if 47 - 47: iIii1I11I1II1 + I1IiiI / O0 * I1ii11iIi11i - iII111i + OOooOOo
 if 13 - 13: OoooooooOO - I1ii11iIi11i % I1Ii111 * OoO0O00 - I1IiiI
 if 77 - 77: I11i - Oo0Ooo
 if 56 - 56: o0oOOo0O0Ooo - II111iiii - oO0o / iIii1I11I1II1 . Ii1I
 if 23 - 23: o0oOOo0O0Ooo + I1IiiI
 if 85 - 85: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo / IiII - O0
 if 60 - 60: I1ii11iIi11i * i11iIiiIii + oO0o
 if 59 - 59: I11i
 if 61 - 61: IiII * I1Ii111 * OoO0O00 / oO0o - OoooooooOO
def lisp_lookup_public_key ( eid ) :
 i1oO00O = eid . instance_id
 if 5 - 5: o0oOOo0O0Ooo % OOooOOo % II111iiii
 if 86 - 86: O0 . ooOoO0o * OoooooooOO + Ii1I / I11i / II111iiii
 if 26 - 26: OoooooooOO - I1Ii111 / Oo0Ooo - iII111i % OoOoOO00 * OoooooooOO
 if 3 - 3: oO0o
 if 3 - 3: I1ii11iIi11i . IiII + ooOoO0o
 O0OOo00 = lisp_get_eid_hash ( eid )
 if ( O0OOo00 == None ) : return ( [ None , None , False ] )
 if 76 - 76: i11iIiiIii + II111iiii % I11i % I1IiiI . iIii1I11I1II1 - Ii1I
 O0OOo00 = "hash-" + O0OOo00
 IIi1i1IIi11 = lisp_address ( LISP_AFI_NAME , O0OOo00 , len ( O0OOo00 ) , i1oO00O )
 iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , i1oO00O )
 if 39 - 39: I11i
 if 30 - 30: Ii1I % i11iIiiIii % I1IiiI * I1ii11iIi11i
 if 4 - 4: iIii1I11I1II1 + Ii1I % I1Ii111 . OoOoOO00 % OoooooooOO + II111iiii
 if 48 - 48: ooOoO0o + ooOoO0o
 IiiiiiIiI = lisp_site_eid_lookup ( IIi1i1IIi11 , iiI , True )
 if ( IiiiiiIiI == None ) : return ( [ IIi1i1IIi11 , None , False ] )
 if 95 - 95: iIii1I11I1II1 / i11iIiiIii - IiII - OOooOOo
 if 4 - 4: II111iiii + oO0o + o0oOOo0O0Ooo % IiII % iIii1I11I1II1
 if 68 - 68: i11iIiiIii
 if 79 - 79: OoOoOO00 * Ii1I / I1ii11iIi11i + OOooOOo
 ii1 = None
 for IIIi1iI1 in IiiiiiIiI . registered_rlocs :
  III1IiI = IIIi1iI1 . json
  if ( III1IiI == None ) : continue
  try :
   III1IiI = json . loads ( III1IiI . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( O0OOo00 ) )
   if 33 - 33: i11iIiiIii - Ii1I * II111iiii
   return ( [ IIi1i1IIi11 , None , False ] )
   if 97 - 97: OoO0O00 / o0oOOo0O0Ooo * iIii1I11I1II1
  if ( "public-key" not in III1IiI ) : continue
  ii1 = III1IiI [ "public-key" ]
  break
  if 5 - 5: I1IiiI
 return ( [ IIi1i1IIi11 , ii1 , True ] )
 if 27 - 27: i1IIi + oO0o / I1ii11iIi11i + oO0o
 if 98 - 98: II111iiii + iIii1I11I1II1
 if 70 - 70: I11i / OoooooooOO / i11iIiiIii
 if 61 - 61: O0 . Oo0Ooo . iIii1I11I1II1
 if 54 - 54: OOooOOo * I1ii11iIi11i + OoooooooOO
 if 58 - 58: i1IIi - OoooooooOO * OOooOOo . ooOoO0o + O0 + o0oOOo0O0Ooo
 if 87 - 87: OOooOOo + I1Ii111 + O0 / oO0o / i11iIiiIii
 if 60 - 60: O0 . II111iiii
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 69 - 69: II111iiii / ooOoO0o - OoOoOO00 / OOooOOo
 if 52 - 52: OoO0O00 % I11i + o0oOOo0O0Ooo % OoOoOO00
 if 46 - 46: o0oOOo0O0Ooo % O0
 if 30 - 30: oO0o
 if 64 - 64: O0
 oOO0oOOOOO0 = json . loads ( rloc_record . json . json_string )
 if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
 if ( lisp_get_eid_hash ( eid ) ) :
  Oo00OoOoo = eid
 elif ( "signature-eid" in oOO0oOOOOO0 ) :
  O00OO0OO = oOO0oOOOOO0 [ "signature-eid" ]
  Oo00OoOoo = lisp_address ( LISP_AFI_IPV6 , O00OO0OO , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 38 - 38: OoooooooOO . i1IIi - i1IIi + iIii1I11I1II1 * OOooOOo - I1IiiI
  if 92 - 92: I11i
  if 77 - 77: I11i / iII111i / O0 % II111iiii % OoOoOO00 / I1Ii111
  if 77 - 77: OoOoOO00 % I1IiiI % II111iiii * iII111i . OoOoOO00 / O0
  if 21 - 21: ooOoO0o - I11i . i11iIiiIii
 IIi1i1IIi11 , ii1 , II1ii1iI111i = lisp_lookup_public_key ( Oo00OoOoo )
 if ( IIi1i1IIi11 == None ) :
  iIiI1I1ii1I1 = green ( Oo00OoOoo . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( iIiI1I1ii1I1 ) )
  return ( False )
  if 73 - 73: OoO0O00 . iII111i / OOooOOo
  if 50 - 50: O0 / IiII % oO0o / I1Ii111 % IiII
 iIIiOOOO0 = "found" if II1ii1iI111i else bold ( "not found" , False )
 iIiI1I1ii1I1 = green ( IIi1i1IIi11 . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( iIiI1I1ii1I1 , iIIiOOOO0 ) )
 if ( II1ii1iI111i == False ) : return ( False )
 if 83 - 83: OOooOOo + OoooooooOO . I1IiiI . Oo0Ooo % i1IIi % Ii1I
 if ( ii1 == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 90 - 90: oO0o * Oo0Ooo . oO0o - iII111i + II111iiii . o0oOOo0O0Ooo
  if 4 - 4: I1Ii111 - i1IIi * I1IiiI
 oOo0O0O0 = ii1 [ 0 : 8 ] + "..." + ii1 [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( oOo0O0O0 ) )
 if 30 - 30: i11iIiiIii - I11i * ooOoO0o + iII111i % I1Ii111
 if 1 - 1: iIii1I11I1II1 % i11iIiiIii - i11iIiiIii % II111iiii
 if 89 - 89: iII111i . OoO0O00 . iII111i
 if 35 - 35: oO0o - ooOoO0o
 if 4 - 4: Oo0Ooo - IiII - I11i
 oooo = oOO0oOOOOO0 [ "signature" ]
 if 40 - 40: IiII - IiII % iII111i + i1IIi % Ii1I
 try :
  oOO0oOOOOO0 = binascii . a2b_base64 ( oooo )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 34 - 34: OOooOOo
  if 81 - 81: iIii1I11I1II1 * iII111i . iIii1I11I1II1 - i1IIi % OOooOOo - I1Ii111
 ooooooOooo = len ( oOO0oOOOOO0 )
 if ( ooooooOooo & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( ooooooOooo ) )
  return ( False )
  if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
  if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
  if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
  if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
  if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
 I1I = Oo00OoOoo . print_address ( )
 if 24 - 24: OoOoOO00
 if 19 - 19: ooOoO0o
 if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
 if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
 ii1 = binascii . a2b_base64 ( ii1 )
 try :
  IIIOoo = ecdsa . VerifyingKey . from_pem ( ii1 )
 except :
  ii111i1iI = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( ii111i1iI ) )
  return ( False )
  if 93 - 93: I1IiiI . ooOoO0o
  if 39 - 39: I1ii11iIi11i . I1Ii111 % iII111i
  if 5 - 5: II111iiii . I1IiiI . OoooooooOO * II111iiii * Oo0Ooo
  if 45 - 45: OOooOOo
  if 65 - 65: I1Ii111 % OOooOOo
  if 35 - 35: OOooOOo * oO0o
  if 19 - 19: iIii1I11I1II1 + IiII * iII111i - IiII
  if 87 - 87: o0oOOo0O0Ooo - I1Ii111
  if 37 - 37: iII111i % I1IiiI - I1ii11iIi11i % I11i
  if 35 - 35: O0 - OoooooooOO % iII111i
  if 48 - 48: OOooOOo % i11iIiiIii
 try :
  iio0Ooo = IIIOoo . verify ( oOO0oOOOOO0 , I1I , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( I1I ) )
  if 49 - 49: O0 * iII111i + II111iiii - OOooOOo
  lprint ( "  Signature used '{}'" . format ( oooo ) )
  return ( False )
  if 29 - 29: OoooooooOO % II111iiii - Oo0Ooo / IiII - i11iIiiIii
 return ( iio0Ooo )
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
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
 if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
 if 87 - 87: ooOoO0o
 if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
 if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
 i1o0000ooOo0 = [ ]
 for iiii1 in eid_list :
  for oOoOOoOo in lisp_map_notify_queue :
   IIiIiii1ii1i = lisp_map_notify_queue [ oOoOOoOo ]
   if ( iiii1 not in IIiIiii1ii1i . eid_list ) : continue
   if 44 - 44: iIii1I11I1II1 + o0oOOo0O0Ooo . O0 + I1ii11iIi11i + I11i . I1Ii111
   i1o0000ooOo0 . append ( oOoOOoOo )
   I1ooo0o00o0Oooo = IIiIiii1ii1i . retransmit_timer
   if ( I1ooo0o00o0Oooo ) : I1ooo0o00o0Oooo . cancel ( )
   if 86 - 86: II111iiii . OoOoOO00 % I1IiiI * OOooOOo . OoOoOO00 + O0
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( IIiIiii1ii1i . nonce_key , green ( iiii1 , False ) ) )
   if 15 - 15: i11iIiiIii / I1IiiI - iII111i
   if 75 - 75: o0oOOo0O0Ooo . I11i
   if 4 - 4: iIii1I11I1II1 % i1IIi % i11iIiiIii / OOooOOo
   if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
   if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
   if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
   if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
 for oOoOOoOo in i1o0000ooOo0 : lisp_map_notify_queue . pop ( oOoOOoOo )
 return
 if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
 if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
 if 50 - 50: OoOoOO00 - i11iIiiIii - OOooOOo . iIii1I11I1II1
 if 97 - 97: oO0o % OOooOOo . OoooooooOO * Ii1I
 if 100 - 100: I1ii11iIi11i / Ii1I % Oo0Ooo
 if 83 - 83: O0 . I1Ii111 % I1ii11iIi11i
 if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
 if 12 - 12: ooOoO0o
def lisp_decrypt_map_register ( packet ) :
 if 56 - 56: i1IIi
 if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
 if 53 - 53: i1IIi % I1ii11iIi11i
 if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
 if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
 o0O0OOooO = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 OOi11I1IIi1I = ( o0O0OOooO >> 13 ) & 0x1
 if ( OOi11I1IIi1I == 0 ) : return ( packet )
 if 75 - 75: II111iiii * Oo0Ooo + OOooOOo + Ii1I - I1ii11iIi11i
 ooOI1iIi = ( o0O0OOooO >> 14 ) & 0x7
 if 2 - 2: I1Ii111
 if 45 - 45: OOooOOo * ooOoO0o
 if 77 - 77: i11iIiiIii / OOooOOo % i11iIiiIii
 if 19 - 19: OoooooooOO - I1IiiI * OoO0O00
 try :
  OoooooOoOOO = lisp_ms_encryption_keys [ ooOI1iIi ]
  OoooooOoOOO = OoooooOoOOO . zfill ( 32 )
  OoOooO = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( ooOI1iIi ) )
  return ( None )
  if 37 - 37: IiII * I1IiiI % O0
  if 32 - 32: ooOoO0o % II111iiii
 iiIi = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( iiIi , ooOI1iIi ) )
 if 60 - 60: i11iIiiIii
 if 11 - 11: o0oOOo0O0Ooo
 if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
 if 26 - 26: Ii1I
 o0oO = chacha . ChaCha ( OoooooOoOOO , OoOooO , 20 ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + o0oO )
 if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
 if 50 - 50: IiII / i1IIi . I1ii11iIi11i
 if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
 if 44 - 44: II111iiii
 if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
 if 54 - 54: iII111i - I1Ii111
 if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 7 - 7: i1IIi
 if 30 - 30: oO0o . i1IIi / I11i
 if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
 if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
 if 2 - 2: oO0o - o0oOOo0O0Ooo
 if 80 - 80: i1IIi
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
 i1IIIii11IiI = lisp_map_register ( )
 o0O0OoOOo0o , packet = i1IIIii11IiI . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 56 - 56: I1Ii111 % oO0o
 i1IIIii11IiI . sport = sport
 if 31 - 31: OOooOOo + IiII
 i1IIIii11IiI . print_map_register ( )
 if 56 - 56: OoooooooOO * II111iiii
 if 99 - 99: i11iIiiIii - II111iiii . Oo0Ooo - oO0o . I1IiiI + i1IIi
 if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
 if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
 ooOOOii1 = True
 if ( i1IIIii11IiI . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  ooOOOii1 = True
  if 57 - 57: OOooOOo
 if ( i1IIIii11IiI . alg_id == LISP_SHA_256_128_ALG_ID ) :
  ooOOOii1 = False
  if 76 - 76: Oo0Ooo . I1Ii111 + iII111i / OoooooooOO . Oo0Ooo
  if 68 - 68: OoO0O00 % OoO0O00 + i11iIiiIii / Ii1I
  if 20 - 20: I1Ii111 + IiII - O0 + IiII / i1IIi
  if 100 - 100: OoooooooOO
  if 26 - 26: Ii1I * O0
 iI1II11i1 = [ ]
 if 66 - 66: O0 - OOooOOo - OOooOOo
 if 75 - 75: Oo0Ooo . I1Ii111 / i11iIiiIii
 if 50 - 50: Oo0Ooo . i11iIiiIii
 if 73 - 73: I11i
 ii1iI11I = None
 IIIiii11 = packet
 ii11 = [ ]
 iIiI1IIi1Ii1i = i1IIIii11IiI . record_count
 for OoOOoO0oOo in range ( iIiI1IIi1Ii1i ) :
  oOO0O0o0oOooO = lisp_eid_record ( )
  iIIi = lisp_rloc_record ( )
  packet = oOO0O0o0oOooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
  oOO0O0o0oOooO . print_record ( "  " , False )
  if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
  if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
  if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
  if 71 - 71: Ii1I - IiII
  IiiiiiIiI = lisp_site_eid_lookup ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ,
 False )
  if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
  oO0oOOoo0OO0 = IiiiiiIiI . print_eid_tuple ( ) if IiiiiiIiI else None
  if 25 - 25: iII111i / iII111i
  if 7 - 7: II111iiii * Ii1I * OoO0O00 / o0oOOo0O0Ooo
  if 71 - 71: ooOoO0o - i11iIiiIii - OoO0O00 % iII111i * OoooooooOO * OoooooooOO
  if 44 - 44: OoO0O00 . OoOoOO00 + I1Ii111
  if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
  if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
  if 43 - 43: Oo0Ooo % I11i
  if ( IiiiiiIiI and IiiiiiIiI . accept_more_specifics == False ) :
   if ( IiiiiiIiI . eid_record_matches ( oOO0O0o0oOooO ) == False ) :
    OO0o0OoO0O = IiiiiiIiI . parent_for_more_specifics
    if ( OO0o0OoO0O ) : IiiiiiIiI = OO0o0OoO0O
    if 13 - 13: IiII - OoO0O00 - ooOoO0o
    if 46 - 46: oO0o + I1ii11iIi11i - OoOoOO00
    if 15 - 15: OoooooooOO + ooOoO0o * I1ii11iIi11i
    if 6 - 6: OoooooooOO % i1IIi % II111iiii + ooOoO0o / IiII + Ii1I
    if 97 - 97: ooOoO0o / I1Ii111 * I1ii11iIi11i
    if 83 - 83: Ii1I + ooOoO0o
    if 46 - 46: OoOoOO00
    if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
  I1i111i1ii11 = ( IiiiiiIiI and IiiiiiIiI . accept_more_specifics )
  if ( I1i111i1ii11 ) :
   IiII111Ii = lisp_site_eid ( IiiiiiIiI . site )
   IiII111Ii . dynamic = True
   IiII111Ii . eid . copy_address ( oOO0O0o0oOooO . eid )
   IiII111Ii . group . copy_address ( oOO0O0o0oOooO . group )
   IiII111Ii . parent_for_more_specifics = IiiiiiIiI
   IiII111Ii . add_cache ( )
   IiII111Ii . inherit_from_ams_parent ( )
   IiiiiiIiI . more_specific_registrations . append ( IiII111Ii )
   IiiiiiIiI = IiII111Ii
  else :
   IiiiiiIiI = lisp_site_eid_lookup ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ,
 True )
   if 71 - 71: o0oOOo0O0Ooo + Oo0Ooo % OoooooooOO
   if 5 - 5: i1IIi % Oo0Ooo / OoooooooOO * OoOoOO00 + OOooOOo - ooOoO0o
  iIiI1I1ii1I1 = oOO0O0o0oOooO . print_eid_tuple ( )
  if 24 - 24: oO0o / ooOoO0o % I1IiiI / I1ii11iIi11i
  if ( IiiiiiIiI == None ) :
   ooOoI1IiiI = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( ooOoI1IiiI , green ( iIiI1I1ii1I1 , False ) ,
 ", matched non-ams {}" . format ( green ( oO0oOOoo0OO0 , False ) if oO0oOOoo0OO0 else "" ) ) )
   if 88 - 88: OoO0O00
   if 96 - 96: IiII % I1ii11iIi11i % Oo0Ooo - i11iIiiIii % iIii1I11I1II1
   if 100 - 100: IiII - Ii1I
   if 9 - 9: II111iiii / Ii1I / O0 - OoOoOO00 - IiII
   if 6 - 6: OoOoOO00 / O0 * i1IIi * OoooooooOO
   packet = iIIi . end_of_rlocs ( packet , oOO0O0o0oOooO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 60 - 60: iII111i - iII111i - Oo0Ooo . i11iIiiIii
   continue
   if 67 - 67: oO0o * OoOoOO00 * OoO0O00 + O0 * oO0o
   if 39 - 39: i1IIi
  ii1iI11I = IiiiiiIiI . site
  if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
  if ( I1i111i1ii11 ) :
   I1i = IiiiiiIiI . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( I1i , False ) , ii1iI11I . site_name , green ( iIiI1I1ii1I1 , False ) ) )
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
  else :
   I1i = green ( IiiiiiIiI . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( I1i , ii1iI11I . site_name , green ( iIiI1I1ii1I1 , False ) ) )
   if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
   if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
   if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
   if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
   if 22 - 22: ooOoO0o - OOooOOo
   if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
  if ( ii1iI11I . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( ii1iI11I . site_name ) )
   packet = iIIi . end_of_rlocs ( packet , oOO0O0o0oOooO . rloc_count )
   continue
   if 20 - 20: ooOoO0o - i11iIiiIii
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
   if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
   if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
   if 29 - 29: oO0o
   if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
   if 78 - 78: Oo0Ooo
   if 77 - 77: oO0o % Oo0Ooo % O0
  IiII11iI1 = i1IIIii11IiI . key_id
  if ( IiII11iI1 in ii1iI11I . auth_key ) :
   O0O0o0ooOo = ii1iI11I . auth_key [ IiII11iI1 ]
  else :
   O0O0o0ooOo = ""
   if 80 - 80: ooOoO0o - I1Ii111 / oO0o - Ii1I + oO0o
   if 82 - 82: i11iIiiIii / i1IIi + O0 . ooOoO0o
  ooO0OO0oo = lisp_verify_auth ( o0O0OoOOo0o , i1IIIii11IiI . alg_id ,
 i1IIIii11IiI . auth_data , O0O0o0ooOo )
  OO0ooo = "dynamic " if IiiiiiIiI . dynamic else ""
  if 11 - 11: O0 % i11iIiiIii * o0oOOo0O0Ooo * I11i + iIii1I11I1II1
  IIiii1Ii = bold ( "passed" if ooO0OO0oo else "failed" , False )
  IiII11iI1 = "key-id {}" . format ( IiII11iI1 ) if IiII11iI1 == i1IIIii11IiI . key_id else "bad key-id {}" . format ( i1IIIii11IiI . key_id )
  if 86 - 86: OoooooooOO . I1Ii111 / I11i . I1IiiI / IiII / OOooOOo
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( IIiii1Ii , OO0ooo , green ( iIiI1I1ii1I1 , False ) , IiII11iI1 ) )
  if 39 - 39: O0 + II111iiii
  if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
  if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
  if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
  if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
  if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
  oO0oOooo = True
  o0oOo0O0 = ( lisp_get_eid_hash ( oOO0O0o0oOooO . eid ) != None )
  if ( o0oOo0O0 or IiiiiiIiI . require_signature ) :
   O0I1iIiIIiIiiI = "Required " if IiiiiiIiI . require_signature else ""
   iIiI1I1ii1I1 = green ( iIiI1I1ii1I1 , False )
   IIIi1iI1 = lisp_find_sig_in_rloc_set ( packet , oOO0O0o0oOooO . rloc_count )
   if ( IIIi1iI1 == None ) :
    oO0oOooo = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( O0I1iIiIIiIiiI ,
    # I1Ii111 / ooOoO0o
 bold ( "failed" , False ) , iIiI1I1ii1I1 ) )
   else :
    oO0oOooo = lisp_verify_cga_sig ( oOO0O0o0oOooO . eid , IIIi1iI1 )
    IIiii1Ii = bold ( "passed" if oO0oOooo else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( O0I1iIiIIiIiiI , IIiii1Ii , iIiI1I1ii1I1 ) )
    if 84 - 84: ooOoO0o . OoOoOO00 + IiII
    if 51 - 51: Oo0Ooo * I1ii11iIi11i + I11i - OoooooooOO % i1IIi + I1IiiI
    if 14 - 14: I1IiiI . o0oOOo0O0Ooo / I1Ii111
    if 67 - 67: OoooooooOO . oO0o * OoOoOO00 - OoooooooOO
  if ( ooO0OO0oo == False or oO0oOooo == False ) :
   packet = iIIi . end_of_rlocs ( packet , oOO0O0o0oOooO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 32 - 32: oO0o
   continue
   if 72 - 72: I1IiiI
   if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
   if 87 - 87: Oo0Ooo
   if 7 - 7: iIii1I11I1II1
   if 85 - 85: iIii1I11I1II1 . O0
   if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
  if ( i1IIIii11IiI . merge_register_requested ) :
   OO0o0OoO0O = IiiiiiIiI
   OO0o0OoO0O . inconsistent_registration = False
   if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
   if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
   if 8 - 8: OoO0O00 . OoO0O00
   if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
   if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
   if ( IiiiiiIiI . group . is_null ( ) ) :
    if ( OO0o0OoO0O . site_id != i1IIIii11IiI . site_id ) :
     OO0o0OoO0O . site_id = i1IIIii11IiI . site_id
     OO0o0OoO0O . registered = False
     OO0o0OoO0O . individual_registrations = { }
     OO0o0OoO0O . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
     if 24 - 24: IiII
     if 95 - 95: IiII + OoOoOO00 * OOooOOo
   IIIOoo = i1IIIii11IiI . xtr_id
   if ( IIIOoo in IiiiiiIiI . individual_registrations ) :
    IiiiiiIiI = IiiiiiIiI . individual_registrations [ IIIOoo ]
   else :
    IiiiiiIiI = lisp_site_eid ( ii1iI11I )
    IiiiiiIiI . eid . copy_address ( OO0o0OoO0O . eid )
    IiiiiiIiI . group . copy_address ( OO0o0OoO0O . group )
    IiiiiiIiI . encrypt_json = OO0o0OoO0O . encrypt_json
    OO0o0OoO0O . individual_registrations [ IIIOoo ] = IiiiiiIiI
    if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
  else :
   IiiiiiIiI . inconsistent_registration = IiiiiiIiI . merge_register_requested
   if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
   if 41 - 41: i1IIi / IiII
   if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
  IiiiiiIiI . map_registers_received += 1
  if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
  if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
  if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
  if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
  if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
  ii111i1iI = ( IiiiiiIiI . is_rloc_in_rloc_set ( source ) == False )
  if ( oOO0O0o0oOooO . record_ttl == 0 and ii111i1iI ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
   continue
   if 13 - 13: oO0o + IiII
   if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
   if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
   if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
   if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
   if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
  iii111 = IiiiiiIiI . registered_rlocs
  IiiiiiIiI . registered_rlocs = [ ]
  if 52 - 52: OoOoOO00 - OoooooooOO / i11iIiiIii
  if 58 - 58: I11i * I11i + OoooooooOO * Oo0Ooo / I11i . i11iIiiIii
  if 90 - 90: OOooOOo - I1IiiI % o0oOOo0O0Ooo
  if 26 - 26: Oo0Ooo . II111iiii - I11i . Ii1I % OOooOOo
  I1i1Iii = packet
  for IiIii1Ii in range ( oOO0O0o0oOooO . rloc_count ) :
   iIIi = lisp_rloc_record ( )
   packet = iIIi . decode ( packet , None , IiiiiiIiI . encrypt_json )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 84 - 84: ooOoO0o
   iIIi . print_record ( "    " )
   if 47 - 47: Oo0Ooo
   if 60 - 60: i11iIiiIii - o0oOOo0O0Ooo
   if 36 - 36: II111iiii
   if 80 - 80: i11iIiiIii / iII111i
   if ( len ( ii1iI11I . allowed_rlocs ) > 0 ) :
    Oo0o = iIIi . rloc . print_address ( )
    if ( Oo0o not in ii1iI11I . allowed_rlocs ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( Oo0o , False ) ) )
     if 91 - 91: i11iIiiIii % OoOoOO00
     if 17 - 17: OoOoOO00
     IiiiiiIiI . registered = False
     packet = iIIi . end_of_rlocs ( packet ,
 oOO0O0o0oOooO . rloc_count - IiIii1Ii - 1 )
     break
     if 62 - 62: I1Ii111 * I11i - II111iiii + Oo0Ooo - Ii1I . ooOoO0o
     if 70 - 70: OoOoOO00 * o0oOOo0O0Ooo / IiII
     if 6 - 6: iII111i
     if 4 - 4: I1ii11iIi11i % o0oOOo0O0Ooo * Oo0Ooo
     if 97 - 97: OoOoOO00
     if 34 - 34: iII111i % Oo0Ooo
   IIIi1iI1 = lisp_rloc ( )
   IIIi1iI1 . store_rloc_from_record ( iIIi , None , source )
   if 25 - 25: OOooOOo / Oo0Ooo
   if 26 - 26: iII111i
   if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
   if 6 - 6: IiII
   if 68 - 68: Oo0Ooo
   if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
   if ( source . is_exact_match ( IIIi1iI1 . rloc ) ) :
    IIIi1iI1 . map_notify_requested = i1IIIii11IiI . map_notify_requested
    if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
    if 93 - 93: i11iIiiIii
    if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
    if 40 - 40: IiII % IiII
    if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
   IiiiiiIiI . registered_rlocs . append ( IIIi1iI1 )
   if 8 - 8: iII111i
   if 51 - 51: I1IiiI
  O0oOO0o = ( IiiiiiIiI . do_rloc_sets_match ( iii111 ) == False )
  if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
  if 68 - 68: OOooOOo
  if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
  if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
  if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
  if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
  if ( i1IIIii11IiI . map_register_refresh and O0oOO0o and
 IiiiiiIiI . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   IiiiiiIiI . registered_rlocs = iii111
   continue
   if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
   if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
   if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
   if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
   if 57 - 57: i11iIiiIii
   if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
  if ( IiiiiiIiI . registered == False ) :
   IiiiiiIiI . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
  IiiiiiIiI . last_registered = lisp_get_timestamp ( )
  IiiiiiIiI . registered = ( oOO0O0o0oOooO . record_ttl != 0 )
  IiiiiiIiI . last_registerer = source
  if 71 - 71: iIii1I11I1II1 * I1IiiI
  if 35 - 35: O0
  if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
  if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
  IiiiiiIiI . auth_sha1_or_sha2 = ooOOOii1
  IiiiiiIiI . proxy_reply_requested = i1IIIii11IiI . proxy_reply_requested
  IiiiiiIiI . lisp_sec_present = i1IIIii11IiI . lisp_sec_present
  IiiiiiIiI . map_notify_requested = i1IIIii11IiI . map_notify_requested
  IiiiiiIiI . mobile_node_requested = i1IIIii11IiI . mobile_node
  IiiiiiIiI . merge_register_requested = i1IIIii11IiI . merge_register_requested
  if 78 - 78: I1IiiI - iIii1I11I1II1
  IiiiiiIiI . use_register_ttl_requested = i1IIIii11IiI . use_ttl_for_timeout
  if ( IiiiiiIiI . use_register_ttl_requested ) :
   IiiiiiIiI . register_ttl = oOO0O0o0oOooO . store_ttl ( )
  else :
   IiiiiiIiI . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
  IiiiiiIiI . xtr_id_present = i1IIIii11IiI . xtr_id_present
  if ( IiiiiiIiI . xtr_id_present ) :
   IiiiiiIiI . xtr_id = i1IIIii11IiI . xtr_id
   IiiiiiIiI . site_id = i1IIIii11IiI . site_id
   if 85 - 85: I11i + OoOoOO00 * O0 * O0
   if 92 - 92: i11iIiiIii
   if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
   if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
   if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
  if ( i1IIIii11IiI . merge_register_requested ) :
   if ( OO0o0OoO0O . merge_in_site_eid ( IiiiiiIiI ) ) :
    iI1II11i1 . append ( [ oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ] )
    if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
   if ( i1IIIii11IiI . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , OO0o0OoO0O , i1IIIii11IiI ,
 oOO0O0o0oOooO )
    if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
    if 42 - 42: OoOoOO00 . I11i % II111iiii
    if 19 - 19: OoooooooOO
  if ( O0oOO0o == False ) : continue
  if ( len ( iI1II11i1 ) != 0 ) : continue
  if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
  ii11 . append ( IiiiiiIiI . print_eid_tuple ( ) )
  if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
  if 56 - 56: I11i
  if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
  if 32 - 32: OOooOOo / i1IIi / OOooOOo
  if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
  if 45 - 45: Oo0Ooo
  if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
  II1i11iI = copy . deepcopy ( oOO0O0o0oOooO )
  oOO0O0o0oOooO = oOO0O0o0oOooO . encode ( )
  oOO0O0o0oOooO += I1i1Iii
  o0oo0OOOo0O = [ IiiiiiIiI . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 31 - 31: OoO0O00 % ooOoO0o * Ii1I
  for IIIi1iI1 in iii111 :
   if ( IIIi1iI1 . map_notify_requested == False ) : continue
   if ( IIIi1iI1 . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , oOO0O0o0oOooO , o0oo0OOOo0O , 1 , IIIi1iI1 . rloc ,
 LISP_CTRL_PORT , i1IIIii11IiI . nonce , i1IIIii11IiI . key_id ,
 i1IIIii11IiI . alg_id , i1IIIii11IiI . auth_len , ii1iI11I , False )
   if 67 - 67: I11i . II111iiii + iIii1I11I1II1 - I1IiiI
   if 25 - 25: i1IIi . OoO0O00 - Ii1I
   if 42 - 42: O0 * iII111i . i1IIi / i11iIiiIii + Ii1I
   if 80 - 80: O0 + II111iiii + oO0o . Oo0Ooo * i1IIi
   if 8 - 8: Ii1I
  lisp_notify_subscribers ( lisp_sockets , II1i11iI , I1i1Iii ,
 IiiiiiIiI . eid , ii1iI11I )
  if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
  if 15 - 15: O0
  if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
  if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
  if 25 - 25: ooOoO0o
 if ( len ( iI1II11i1 ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , iI1II11i1 )
  if 33 - 33: Oo0Ooo
  if 11 - 11: I11i
  if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
  if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
  if 74 - 74: I1IiiI / o0oOOo0O0Ooo
  if 53 - 53: iIii1I11I1II1 * oO0o
 if ( i1IIIii11IiI . merge_register_requested ) : return
 if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
 if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
 if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
 if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
 if 60 - 60: oO0o * I1Ii111
 if ( i1IIIii11IiI . map_notify_requested and ii1iI11I != None ) :
  lisp_build_map_notify ( lisp_sockets , IIIiii11 , ii11 ,
 i1IIIii11IiI . record_count , source , sport , i1IIIii11IiI . nonce ,
 i1IIIii11IiI . key_id , i1IIIii11IiI . alg_id , i1IIIii11IiI . auth_len ,
 ii1iI11I , True )
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
 IIiIiii1ii1i = lisp_map_notify ( "" )
 packet = IIiIiii1ii1i . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 73 - 73: O0 % i11iIiiIii
  if 16 - 16: O0
 IIiIiii1ii1i . print_notify ( )
 if ( IIiIiii1ii1i . record_count == 0 ) : return
 if 15 - 15: i1IIi % i11iIiiIii
 I1i1IIiIIiIiIi = IIiIiii1ii1i . eid_records
 if 97 - 97: Ii1I + I1Ii111 / II111iiii
 for OoOOoO0oOo in range ( IIiIiii1ii1i . record_count ) :
  oOO0O0o0oOooO = lisp_eid_record ( )
  I1i1IIiIIiIiIi = oOO0O0o0oOooO . decode ( I1i1IIiIIiIiIi )
  if ( packet == None ) : return
  oOO0O0o0oOooO . print_record ( "  " , False )
  iIiI1I1ii1I1 = oOO0O0o0oOooO . print_eid_tuple ( )
  if 14 - 14: iII111i / IiII / oO0o
  if 55 - 55: OoO0O00 % O0
  if 92 - 92: OoooooooOO / O0
  if 14 - 14: i11iIiiIii
  if 43 - 43: OOooOOo
  I111I1iI1 = lisp_map_cache_lookup ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . eid )
  if ( I111I1iI1 == None ) :
   I1i = green ( iIiI1I1ii1I1 , False )
   lprint ( "Ignoring Map-Notify EID {}, no subscribe-request entry" . format ( I1i ) )
   if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
   continue
   if 93 - 93: OoOoOO00
   if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
   if 72 - 72: ooOoO0o
   if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
   if 53 - 53: OOooOOo * O0 . iII111i
   if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
   if 78 - 78: iII111i
  if ( I111I1iI1 . action != LISP_SEND_PUBSUB_ACTION ) :
   if ( I111I1iI1 . subscribed_eid == None ) :
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
  if ( I111I1iI1 . action == LISP_SEND_PUBSUB_ACTION ) :
   I111I1iI1 = lisp_mapping ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group , [ ] )
   I111I1iI1 . add_cache ( )
   i11 = copy . deepcopy ( oOO0O0o0oOooO . eid )
   o0o0OoOo00O0O = copy . deepcopy ( oOO0O0o0oOooO . group )
  else :
   i11 = I111I1iI1 . subscribed_eid
   o0o0OoOo00O0O = I111I1iI1 . subscribed_group
   O0000oo0Oo = I111I1iI1 . rloc_set
   I111I1iI1 . delete_rlocs_from_rloc_probe_list ( )
   I111I1iI1 . rloc_set = [ ]
   if 58 - 58: ooOoO0o
   if 18 - 18: O0 . iIii1I11I1II1 - O0 % Ii1I . I1ii11iIi11i
   if 18 - 18: I1IiiI % ooOoO0o + OoooooooOO
   if 22 - 22: O0
   if 77 - 77: OOooOOo * I11i / Ii1I
  I111I1iI1 . mapping_source = None if source == "lisp-itr" else source
  I111I1iI1 . map_cache_ttl = oOO0O0o0oOooO . store_ttl ( )
  I111I1iI1 . subscribed_eid = i11
  I111I1iI1 . subscribed_group = o0o0OoOo00O0O
  if 16 - 16: Oo0Ooo
  if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
  if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
  if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
  if 43 - 43: I1ii11iIi11i + I11i
  if ( len ( O0000oo0Oo ) != 0 and oOO0O0o0oOooO . rloc_count == 0 ) :
   I111I1iI1 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , I111I1iI1 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( iIiI1I1ii1I1 , False ) ) )
   if 83 - 83: II111iiii + o0oOOo0O0Ooo - I1Ii111
   continue
   if 100 - 100: IiII - OoOoOO00 / I11i
   if 33 - 33: I1Ii111 * OoOoOO00 . I1ii11iIi11i % I1Ii111
   if 87 - 87: Oo0Ooo
   if 65 - 65: ooOoO0o . I1IiiI
   if 51 - 51: IiII
   if 43 - 43: oO0o - I11i . i11iIiiIii
   if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
  o000ooOo0o0Oo = ii1IiIiIi11 = 0
  for IiIii1Ii in range ( oOO0O0o0oOooO . rloc_count ) :
   iIIi = lisp_rloc_record ( )
   I1i1IIiIIiIiIi = iIIi . decode ( I1i1IIiIIiIiIi , None )
   iIIi . print_record ( "    " )
   if 57 - 57: I11i % II111iiii
   if 83 - 83: iIii1I11I1II1 * i1IIi + O0 * o0oOOo0O0Ooo * IiII / oO0o
   if 32 - 32: OOooOOo
   if 95 - 95: I1ii11iIi11i % i1IIi
   iIIiOOOO0 = False
   for OOoooo in O0000oo0Oo :
    if ( OOoooo . rloc . is_exact_match ( iIIi . rloc ) ) :
     iIIiOOOO0 = True
     break
     if 99 - 99: ooOoO0o * i1IIi
     if 51 - 51: oO0o - oO0o - OoO0O00 % I1IiiI
   if ( iIIiOOOO0 ) :
    IIIi1iI1 = copy . deepcopy ( OOoooo )
    ii1IiIiIi11 += 1
   else :
    IIIi1iI1 = lisp_rloc ( )
    o000ooOo0o0Oo += 1
    if 95 - 95: oO0o - iIii1I11I1II1 + OOooOOo % iIii1I11I1II1 / OOooOOo . O0
    if 9 - 9: OoOoOO00 % iIii1I11I1II1 % oO0o / OoO0O00 / i11iIiiIii
    if 55 - 55: O0 * II111iiii % I1IiiI * oO0o % iIii1I11I1II1
    if 66 - 66: O0 * Oo0Ooo * Ii1I + I1Ii111 / Oo0Ooo * I11i
    if 17 - 17: II111iiii
   IIIi1iI1 . store_rloc_from_record ( iIIi , None , I111I1iI1 . mapping_source )
   I111I1iI1 . rloc_set . append ( IIIi1iI1 )
   if 2 - 2: O0 / o0oOOo0O0Ooo - OoO0O00 * II111iiii
   if 4 - 4: I1IiiI + Oo0Ooo . iIii1I11I1II1
  lprint ( "Update {} map-cache entry with {}/{} new/replaced RLOCs" . format ( green ( iIiI1I1ii1I1 , False ) , o000ooOo0o0Oo , ii1IiIiIi11 ) )
  if 100 - 100: i11iIiiIii
  if 21 - 21: OoOoOO00 + iII111i . OoO0O00
  if 79 - 79: i11iIiiIii - OoO0O00 * OoO0O00 * i1IIi / iIii1I11I1II1 + iII111i
  if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
  if 62 - 62: iIii1I11I1II1
  I111I1iI1 . build_best_rloc_set ( )
  lisp_write_ipc_map_cache ( True , I111I1iI1 )
  if 60 - 60: Oo0Ooo % IiII % OoO0O00 - i11iIiiIii
  if 53 - 53: i11iIiiIii + OoooooooOO
  if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  if 79 - 79: II111iiii / OoooooooOO
  if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
  if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
 IIo0o0oo0 = lisp_get_map_server ( source )
 if ( IIo0o0oo0 == None ) :
  lprint ( "Cannot find Map-Server for Map-Notify source address {}" . format ( source . print_address_no_iid ( ) ) )
  if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  return
  if 17 - 17: I1Ii111
 lisp_send_map_notify_ack ( lisp_sockets , I1i1IIiIIiIiIi , IIiIiii1ii1i , IIo0o0oo0 )
 if 2 - 2: O0 % OoOoOO00 + oO0o
 if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
 if 51 - 51: IiII
 if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
 if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
 if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
 if 95 - 95: O0 - OoOoOO00
 if 68 - 68: ooOoO0o . I1Ii111
 if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
 if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
def lisp_process_multicast_map_notify ( packet , source ) :
 IIiIiii1ii1i = lisp_map_notify ( "" )
 packet = IIiIiii1ii1i . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 41 - 41: Oo0Ooo
  if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
 IIiIiii1ii1i . print_notify ( )
 if ( IIiIiii1ii1i . record_count == 0 ) : return
 if 66 - 66: oO0o % i1IIi % OoooooooOO
 I1i1IIiIIiIiIi = IIiIiii1ii1i . eid_records
 if 58 - 58: OOooOOo
 for OoOOoO0oOo in range ( IIiIiii1ii1i . record_count ) :
  oOO0O0o0oOooO = lisp_eid_record ( )
  I1i1IIiIIiIiIi = oOO0O0o0oOooO . decode ( I1i1IIiIIiIiIi )
  if ( packet == None ) : return
  oOO0O0o0oOooO . print_record ( "  " , False )
  if 89 - 89: iIii1I11I1II1 - i1IIi
  if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
  if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
  if 36 - 36: IiII . OoOoOO00 . Ii1I
  I111I1iI1 = lisp_map_cache_lookup ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group )
  if ( I111I1iI1 == None ) :
   i1I , I1iIiiI1IIi1 , i1iIi1II1 = lisp_allow_gleaning ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ,
 None )
   if ( i1I == False ) : continue
   if 57 - 57: iII111i * IiII / I1IiiI / OOooOOo
   I111I1iI1 = lisp_mapping ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group , [ ] )
   I111I1iI1 . add_cache ( )
   if 37 - 37: II111iiii . I1IiiI
   if 32 - 32: o0oOOo0O0Ooo - Oo0Ooo - IiII + oO0o * IiII
   if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
   if 62 - 62: ooOoO0o + ooOoO0o % I11i
   if 100 - 100: II111iiii . OoooooooOO
   if 32 - 32: I11i % OOooOOo * O0 / iIii1I11I1II1 / i1IIi
   if 87 - 87: OoO0O00 . I1ii11iIi11i * I1IiiI
  if ( I111I1iI1 . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( I111I1iI1 . print_eid_tuple ( ) , False ) ) )
   if 83 - 83: OOooOOo
   continue
   if 86 - 86: I1Ii111 / oO0o
   if 67 - 67: OoOoOO00 + Oo0Ooo / i11iIiiIii . I1IiiI
  I111I1iI1 . mapping_source = None if source == "lisp-etr" else source
  I111I1iI1 . map_cache_ttl = oOO0O0o0oOooO . store_ttl ( )
  if 53 - 53: Oo0Ooo + IiII * ooOoO0o % OoooooooOO * oO0o . iII111i
  if 78 - 78: O0 . Ii1I - I1ii11iIi11i
  if 69 - 69: O0 % O0 . oO0o * OoooooooOO
  if 13 - 13: i1IIi % oO0o . OoooooooOO + I1ii11iIi11i - OOooOOo
  if 99 - 99: OoooooooOO % OOooOOo / I11i
  if ( len ( I111I1iI1 . rloc_set ) != 0 and oOO0O0o0oOooO . rloc_count == 0 ) :
   I111I1iI1 . rloc_set = [ ]
   I111I1iI1 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , I111I1iI1 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( I111I1iI1 . print_eid_tuple ( ) , False ) ) )
   if 77 - 77: II111iiii - IiII % OOooOOo
   continue
   if 22 - 22: OoooooooOO / oO0o
   if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
  OooO000oo0o = I111I1iI1 . rtrs_in_rloc_set ( )
  if 50 - 50: OoO0O00 * O0 - IiII . o0oOOo0O0Ooo - iII111i
  if 18 - 18: II111iiii * OoooooooOO - Oo0Ooo . iII111i - Oo0Ooo
  if 82 - 82: I1Ii111 . OoOoOO00 - iIii1I11I1II1 - OoO0O00
  if 86 - 86: iIii1I11I1II1
  if 54 - 54: II111iiii
  for IiIii1Ii in range ( oOO0O0o0oOooO . rloc_count ) :
   iIIi = lisp_rloc_record ( )
   I1i1IIiIIiIiIi = iIIi . decode ( I1i1IIiIIiIiIi , None )
   iIIi . print_record ( "    " )
   if ( oOO0O0o0oOooO . group . is_null ( ) ) : continue
   if ( iIIi . rle == None ) : continue
   if 98 - 98: Oo0Ooo + IiII . Oo0Ooo / OoOoOO00 + O0
   if 99 - 99: Oo0Ooo
   if 42 - 42: I1IiiI + I1Ii111 - oO0o + o0oOOo0O0Ooo
   if 86 - 86: Ii1I - o0oOOo0O0Ooo % iII111i
   if 37 - 37: Oo0Ooo
   OOo = I111I1iI1 . rloc_set [ 0 ] . stats if len ( I111I1iI1 . rloc_set ) != 0 else None
   if 16 - 16: OoOoOO00 * iII111i . O0
   if 60 - 60: IiII . I11i * Oo0Ooo . i1IIi
   if 3 - 3: Ii1I
   if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
   IIIi1iI1 = lisp_rloc ( )
   IIIi1iI1 . store_rloc_from_record ( iIIi , None , I111I1iI1 . mapping_source )
   if ( OOo != None ) : IIIi1iI1 . stats = copy . deepcopy ( OOo )
   if 81 - 81: I11i % Oo0Ooo / iII111i
   if ( OooO000oo0o and IIIi1iI1 . is_rtr ( ) == False ) : continue
   if 44 - 44: Oo0Ooo
   I111I1iI1 . rloc_set = [ IIIi1iI1 ]
   I111I1iI1 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , I111I1iI1 )
   if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( I111I1iI1 . print_eid_tuple ( ) , False ) ,
   # I11i * OoO0O00 . OOooOOo
 IIIi1iI1 . rle . print_rle ( False , True ) ) )
   if 39 - 39: I1ii11iIi11i - Oo0Ooo / Ii1I
   if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
 return
 if 54 - 54: O0 / ooOoO0o * I1Ii111
 if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
 if 13 - 13: IiII + Oo0Ooo - I1Ii111
 if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
 if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
 if 95 - 95: oO0o / Ii1I + OoO0O00
 if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
 if 39 - 39: OoO0O00 + II111iiii
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 IIiIiii1ii1i = lisp_map_notify ( "" )
 OO0 = IIiIiii1ii1i . decode ( orig_packet )
 if ( OO0 == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 98 - 98: O0 - I1Ii111 % oO0o - iII111i + Ii1I * i1IIi
  if 76 - 76: o0oOOo0O0Ooo
 IIiIiii1ii1i . print_notify ( )
 if 55 - 55: OOooOOo + I1ii11iIi11i * Oo0Ooo
 if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
 if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
 if 49 - 49: iII111i + I11i . Oo0Ooo
 if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
 I1iiIi111I = source . print_address ( )
 if ( IIiIiii1ii1i . alg_id != 0 or IIiIiii1ii1i . auth_len != 0 ) :
  IIo0o0oo0 = None
  for IIIOoo in lisp_map_servers_list :
   if ( IIIOoo . find ( I1iiIi111I ) == - 1 ) : continue
   IIo0o0oo0 = lisp_map_servers_list [ IIIOoo ]
   if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
  if ( IIo0o0oo0 == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( I1iiIi111I ) )
   if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
   return
   if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
   if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
  IIo0o0oo0 . map_notifies_received += 1
  if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
  ooO0OO0oo = lisp_verify_auth ( OO0 , IIiIiii1ii1i . alg_id ,
 IIiIiii1ii1i . auth_data , IIo0o0oo0 . password )
  if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if ooO0OO0oo else "failed" ) )
  if 1 - 1: i11iIiiIii
  if ( ooO0OO0oo == False ) : return
 else :
  IIo0o0oo0 = lisp_ms ( I1iiIi111I , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 1 - 1: iIii1I11I1II1
  if 73 - 73: iII111i + IiII
  if 95 - 95: O0
  if 75 - 75: ooOoO0o
  if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
  if 85 - 85: ooOoO0o
 I1i1IIiIIiIiIi = IIiIiii1ii1i . eid_records
 if ( IIiIiii1ii1i . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , I1i1IIiIIiIiIi , IIiIiii1ii1i , IIo0o0oo0 )
  return
  if 29 - 29: iII111i . Ii1I
  if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
  if 45 - 45: IiII
  if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
  if 9 - 9: iIii1I11I1II1 * Ii1I / O0 - OOooOOo
  if 95 - 95: i11iIiiIii * II111iiii * OOooOOo * iIii1I11I1II1
  if 22 - 22: iIii1I11I1II1 / I1IiiI + OoOoOO00 - OOooOOo . i11iIiiIii / i11iIiiIii
  if 10 - 10: iIii1I11I1II1 % i1IIi
 oOO0O0o0oOooO = lisp_eid_record ( )
 OO0 = oOO0O0o0oOooO . decode ( I1i1IIiIIiIiIi )
 if ( OO0 == None ) : return
 if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
 oOO0O0o0oOooO . print_record ( "  " , False )
 if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
 for IiIii1Ii in range ( oOO0O0o0oOooO . rloc_count ) :
  iIIi = lisp_rloc_record ( )
  OO0 = iIIi . decode ( OO0 , None )
  if ( OO0 == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 44 - 44: I1ii11iIi11i
  iIIi . print_record ( "    " )
  if 39 - 39: iII111i + Oo0Ooo / oO0o
  if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
  if 99 - 99: I1IiiI * II111iiii
  if 84 - 84: II111iiii - I1IiiI
  if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
 if ( oOO0O0o0oOooO . group . is_null ( ) == False ) :
  if 35 - 35: I11i + i1IIi
  if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
  if 97 - 97: oO0o % iIii1I11I1II1
  if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
  if 16 - 16: I1IiiI
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( oOO0O0o0oOooO . print_eid_tuple ( ) , False ) ) )
  if 39 - 39: ooOoO0o * II111iiii
  if 90 - 90: OoooooooOO * ooOoO0o
  Iii1 = lisp_control_packet_ipc ( orig_packet , I1iiIi111I , "lisp-itr" , 0 )
  lisp_ipc ( Iii1 , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 14 - 14: I1IiiI % i1IIi
  if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
  if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
  if 55 - 55: i1IIi
  if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
 lisp_send_map_notify_ack ( lisp_sockets , I1i1IIiIIiIiIi , IIiIiii1ii1i , IIo0o0oo0 )
 return
 if 88 - 88: O0
 if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
 if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
 if 90 - 90: i11iIiiIii - iII111i * oO0o
 if 79 - 79: IiII
 if 38 - 38: I1Ii111
 if 56 - 56: i11iIiiIii
 if 58 - 58: i11iIiiIii / OoOoOO00
def lisp_process_map_notify_ack ( packet , source ) :
 IIiIiii1ii1i = lisp_map_notify ( "" )
 packet = IIiIiii1ii1i . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
  if 39 - 39: Oo0Ooo . OoO0O00
 IIiIiii1ii1i . print_notify ( )
 if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
 if 100 - 100: ooOoO0o / OoooooooOO
 if 73 - 73: i11iIiiIii - Oo0Ooo
 if 100 - 100: iIii1I11I1II1 + I1Ii111
 if 51 - 51: o0oOOo0O0Ooo * I11i
 if ( IIiIiii1ii1i . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 42 - 42: OOooOOo % I11i
  if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
 oOO0O0o0oOooO = lisp_eid_record ( )
 if 81 - 81: I1IiiI
 if ( oOO0O0o0oOooO . decode ( IIiIiii1ii1i . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
 oOO0O0o0oOooO . print_record ( "  " , False )
 if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
 iIiI1I1ii1I1 = oOO0O0o0oOooO . print_eid_tuple ( )
 if 83 - 83: iII111i - I1ii11iIi11i + iII111i
 if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
 if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
 if 20 - 20: IiII - OOooOOo + OoOoOO00
 if ( IIiIiii1ii1i . alg_id != LISP_NONE_ALG_ID and IIiIiii1ii1i . auth_len != 0 ) :
  IiiiiiIiI = lisp_sites_by_eid . lookup_cache ( oOO0O0o0oOooO . eid , True )
  if ( IiiiiiIiI == None ) :
   ooOoI1IiiI = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( ooOoI1IiiI , green ( iIiI1I1ii1I1 , False ) ) )
   if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
   return
   if 74 - 74: OoO0O00
  ii1iI11I = IiiiiiIiI . site
  if 13 - 13: I1ii11iIi11i / OoO0O00
  if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
  if 94 - 94: IiII * i1IIi
  if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  ii1iI11I . map_notify_acks_received += 1
  if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
  IiII11iI1 = IIiIiii1ii1i . key_id
  if ( IiII11iI1 in ii1iI11I . auth_key ) :
   O0O0o0ooOo = ii1iI11I . auth_key [ IiII11iI1 ]
  else :
   O0O0o0ooOo = ""
   if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
   if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
  ooO0OO0oo = lisp_verify_auth ( packet , IIiIiii1ii1i . alg_id ,
 IIiIiii1ii1i . auth_data , O0O0o0ooOo )
  if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
  IiII11iI1 = "key-id {}" . format ( IiII11iI1 ) if IiII11iI1 == IIiIiii1ii1i . key_id else "bad key-id {}" . format ( IIiIiii1ii1i . key_id )
  if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
  if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if ooO0OO0oo else "failed" , IiII11iI1 ) )
  if 66 - 66: i1IIi
  if ( ooO0OO0oo == False ) : return
  if 98 - 98: Oo0Ooo / iIii1I11I1II1
  if 33 - 33: O0 - iII111i
  if 40 - 40: iII111i * I11i
  if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  if 87 - 87: OoOoOO00
 if ( IIiIiii1ii1i . retransmit_timer ) : IIiIiii1ii1i . retransmit_timer . cancel ( )
 if 30 - 30: IiII % OoOoOO00 + I1Ii111
 O00000ooO0OOo = source . print_address ( )
 IIIOoo = IIiIiii1ii1i . nonce_key
 if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
 if ( IIIOoo in lisp_map_notify_queue ) :
  IIiIiii1ii1i = lisp_map_notify_queue . pop ( IIIOoo )
  if ( IIiIiii1ii1i . retransmit_timer ) : IIiIiii1ii1i . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( IIIOoo ) )
  if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( IIiIiii1ii1i . nonce_key , red ( O00000ooO0OOo , False ) ) )
  if 87 - 87: I11i
  if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
 return
 if 72 - 72: OoO0O00 * Oo0Ooo - IiII
 if 74 - 74: Ii1I
 if 26 - 26: I11i . O0
 if 68 - 68: Ii1I
 if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
 if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
 if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
 if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 9 - 9: o0oOOo0O0Ooo
 if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
 if 21 - 21: Ii1I * OoOoOO00
 if 29 - 29: iIii1I11I1II1 / ooOoO0o
 ooOo000OO = False
 if ( group . is_null ( ) == False ) :
  ooOo000OO = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
 if ( ooOo000OO == False ) :
  ooOo000OO = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 88 - 88: OoO0O00 % Ii1I
  if 12 - 12: OoooooooOO . O0
 if ( ooOo000OO ) :
  oOo00OO0ooo = lisp_print_eid_tuple ( eid , group )
  Iii1oOoo = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 2 - 2: OoO0O00 * o0oOOo0O0Ooo - I1IiiI
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( oOo00OO0ooo , False ) , s ,
  # OoO0O00 % I1IiiI
 Iii1oOoo ) )
  if 71 - 71: iII111i . OoOoOO00 * I1ii11iIi11i - OoooooooOO
 return ( ooOo000OO )
 if 76 - 76: o0oOOo0O0Ooo * ooOoO0o * i11iIiiIii / O0 % I1IiiI % i1IIi
 if 77 - 77: I11i . OOooOOo + oO0o
 if 92 - 92: OoOoOO00 / OoOoOO00 / i1IIi + I1IiiI . i1IIi
 if 81 - 81: Ii1I * IiII / OoO0O00 . iII111i % I11i . ooOoO0o
 if 63 - 63: Oo0Ooo * I1Ii111 % Ii1I
 if 88 - 88: IiII - i1IIi * OoO0O00 * OoOoOO00 % I1IiiI
 if 10 - 10: OOooOOo * I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
 iiiiIii = lisp_map_referral ( )
 packet = iiiiIii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 96 - 96: O0
 iiiiIii . print_map_referral ( )
 if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
 I1iiIi111I = source . print_address ( )
 o00oO0O000 = iiiiIii . nonce
 if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
 if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
 if 61 - 61: IiII . O0
 if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
 for OoOOoO0oOo in range ( iiiiIii . record_count ) :
  oOO0O0o0oOooO = lisp_eid_record ( )
  packet = oOO0O0o0oOooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
  oOO0O0o0oOooO . print_record ( "  " , True )
  if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
  if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
  if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
  if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
  IIIOoo = str ( o00oO0O000 )
  if ( IIIOoo not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( o00oO0O000 ) , I1iiIi111I ) )
   if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
   if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
   continue
   if 86 - 86: OOooOOo / OoooooooOO - IiII
  oooO = lisp_ddt_map_requestQ [ IIIOoo ]
  if ( oooO == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( o00oO0O000 ) , I1iiIi111I ) )
   if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
   continue
   if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
   if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
   if 8 - 8: oO0o * iII111i * I11i
   if 30 - 30: I1Ii111
   if 61 - 61: iII111i
   if 50 - 50: Ii1I / I1IiiI . O0
  if ( lisp_map_referral_loop ( oooO , oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ,
 oOO0O0o0oOooO . action , I1iiIi111I ) ) :
   oooO . dequeue_map_request ( )
   continue
   if 49 - 49: I1Ii111 . OoO0O00 % O0
   if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
  oooO . last_cached_prefix [ 0 ] = oOO0O0o0oOooO . eid
  oooO . last_cached_prefix [ 1 ] = oOO0O0o0oOooO . group
  if 62 - 62: II111iiii + ooOoO0o + I1IiiI
  if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
  if 13 - 13: I1ii11iIi11i
  if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
  iii1II11I1IiI = False
  iiiiiI111 = lisp_referral_cache_lookup ( oOO0O0o0oOooO . eid , oOO0O0o0oOooO . group ,
 True )
  if ( iiiiiI111 == None ) :
   iii1II11I1IiI = True
   iiiiiI111 = lisp_referral ( )
   iiiiiI111 . eid = oOO0O0o0oOooO . eid
   iiiiiI111 . group = oOO0O0o0oOooO . group
   if ( oOO0O0o0oOooO . ddt_incomplete == False ) : iiiiiI111 . add_cache ( )
  elif ( iiiiiI111 . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( iiiiiI111 . print_eid_tuple ( ) , False ) ) )
   if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
   oooO . dequeue_map_request ( )
   continue
   if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
   if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
  Oo0Oo00O000O = oOO0O0o0oOooO . action
  iiiiiI111 . referral_source = source
  iiiiiI111 . referral_type = Oo0Oo00O000O
  IiIIi = oOO0O0o0oOooO . store_ttl ( )
  iiiiiI111 . referral_ttl = IiIIi
  iiiiiI111 . expires = lisp_set_timestamp ( IiIIi )
  if 18 - 18: OoooooooOO - I1ii11iIi11i
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  if 79 - 79: OOooOOo + Oo0Ooo
  if 33 - 33: iIii1I11I1II1
  o0oo = iiiiiI111 . is_referral_negative ( )
  if ( I1iiIi111I in iiiiiI111 . referral_set ) :
   o00o0 = iiiiiI111 . referral_set [ I1iiIi111I ]
   if 18 - 18: II111iiii + OoO0O00 . i1IIi / I11i % II111iiii . I1Ii111
   if ( o00o0 . updown == False and o0oo == False ) :
    o00o0 . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( I1iiIi111I ) )
    if 37 - 37: i1IIi - I1ii11iIi11i / OoO0O00 - iII111i / II111iiii
   elif ( o00o0 . updown == True and o0oo == True ) :
    o00o0 . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( I1iiIi111I ) )
    if 44 - 44: ooOoO0o
    if 16 - 16: OoOoOO00 - i11iIiiIii . o0oOOo0O0Ooo / o0oOOo0O0Ooo * Ii1I
    if 28 - 28: i1IIi - Oo0Ooo - i1IIi + IiII
    if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
    if 56 - 56: Oo0Ooo % I1ii11iIi11i
    if 53 - 53: OoO0O00 . I11i - ooOoO0o
    if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
    if 74 - 74: oO0o . I1Ii111 . II111iiii
  o00o000oOo = { }
  for IIIOoo in iiiiiI111 . referral_set : o00o000oOo [ IIIOoo ] = None
  if 72 - 72: OoooooooOO - O0 . OoO0O00
  if 46 - 46: o0oOOo0O0Ooo % OoO0O00 + I11i % o0oOOo0O0Ooo + oO0o . Oo0Ooo
  if 58 - 58: I1Ii111 + I1ii11iIi11i
  if 57 - 57: OOooOOo + II111iiii
  for OoOOoO0oOo in range ( oOO0O0o0oOooO . rloc_count ) :
   iIIi = lisp_rloc_record ( )
   packet = iIIi . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 67 - 67: II111iiii
   iIIi . print_record ( "    " )
   if 39 - 39: i1IIi
   if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
   if 59 - 59: i1IIi
   if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
   Oo0o = iIIi . rloc . print_address ( )
   if ( Oo0o not in iiiiiI111 . referral_set ) :
    o00o0 = lisp_referral_node ( )
    o00o0 . referral_address . copy_address ( iIIi . rloc )
    iiiiiI111 . referral_set [ Oo0o ] = o00o0
    if ( I1iiIi111I == Oo0o and o0oo ) : o00o0 . updown = False
   else :
    o00o0 = iiiiiI111 . referral_set [ Oo0o ]
    if ( Oo0o in o00o000oOo ) : o00o000oOo . pop ( Oo0o )
    if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
   o00o0 . priority = iIIi . priority
   o00o0 . weight = iIIi . weight
   if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
   if 71 - 71: OOooOOo
   if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
   if 73 - 73: iII111i / I1IiiI * ooOoO0o
   if 85 - 85: I11i + I11i + oO0o - OoOoOO00
  for IIIOoo in o00o000oOo : iiiiiI111 . referral_set . pop ( IIIOoo )
  if 15 - 15: OoO0O00
  iIiI1I1ii1I1 = iiiiiI111 . print_eid_tuple ( )
  if 88 - 88: Ii1I % i1IIi / I1Ii111
  if ( iii1II11I1IiI ) :
   if ( oOO0O0o0oOooO . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( iIiI1I1ii1I1 , False ) ) )
    if 2 - 2: Ii1I . IiII % OoOoOO00
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( iIiI1I1ii1I1 , False ) , oOO0O0o0oOooO . rloc_count ) )
    if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
    if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( iIiI1I1ii1I1 , False ) , oOO0O0o0oOooO . rloc_count ) )
   if 35 - 35: i11iIiiIii
   if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
   if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
   if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
   if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
   if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
  if ( Oo0Oo00O000O == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( oooO . lisp_sockets , iiiiiI111 . eid ,
 iiiiiI111 . group , oooO . nonce , oooO . itr , oooO . sport , 15 , None , False )
   oooO . dequeue_map_request ( )
   if 12 - 12: i11iIiiIii / Ii1I + i1IIi
   if 54 - 54: I1IiiI
  if ( Oo0Oo00O000O == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( oooO . tried_root ) :
    lisp_send_negative_map_reply ( oooO . lisp_sockets , iiiiiI111 . eid ,
 iiiiiI111 . group , oooO . nonce , oooO . itr , oooO . sport , 0 , None , False )
    oooO . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( oooO , True )
    if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
    if 37 - 37: Oo0Ooo
    if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
  if ( Oo0Oo00O000O == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( I1iiIi111I in iiiiiI111 . referral_set ) :
    o00o0 = iiiiiI111 . referral_set [ I1iiIi111I ]
    o00o0 . updown = False
    if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
   if ( len ( iiiiiI111 . referral_set ) == 0 ) :
    oooO . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( oooO , False )
    if 19 - 19: O0 * II111iiii * OoOoOO00
    if 53 - 53: Oo0Ooo
    if 16 - 16: Ii1I
  if ( Oo0Oo00O000O in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( oooO . eid . is_exact_match ( oOO0O0o0oOooO . eid ) ) :
    if ( not oooO . tried_root ) :
     lisp_send_ddt_map_request ( oooO , True )
    else :
     lisp_send_negative_map_reply ( oooO . lisp_sockets ,
 iiiiiI111 . eid , iiiiiI111 . group , oooO . nonce , oooO . itr ,
 oooO . sport , 15 , None , False )
     oooO . dequeue_map_request ( )
     if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
   else :
    lisp_send_ddt_map_request ( oooO , False )
    if 78 - 78: OoO0O00 + oO0o
    if 86 - 86: ooOoO0o . ooOoO0o + oO0o
    if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
  if ( Oo0Oo00O000O == LISP_DDT_ACTION_MS_ACK ) : oooO . dequeue_map_request ( )
  if 31 - 31: IiII + iII111i
 return
 if 5 - 5: O0 * Ii1I
 if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
 if 77 - 77: OOooOOo / OoooooooOO
 if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
 if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
 if 31 - 31: IiII / o0oOOo0O0Ooo
 if 27 - 27: Oo0Ooo
 if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
def lisp_process_ecm ( lisp_sockets , packet , source , ecm_port ) :
 O000O = lisp_ecm ( 0 )
 packet = O000O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
  if 81 - 81: I1ii11iIi11i - i11iIiiIii
 O000O . print_ecm ( )
 if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
 o0O0OOooO = lisp_control_header ( )
 if ( o0O0OOooO . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
  if 60 - 60: i11iIiiIii + IiII
 i1III1ii1III = o0O0OOooO . type
 del ( o0O0OOooO )
 if 81 - 81: oO0o + I1ii11iIi11i + OoooooooOO
 if ( i1III1ii1III != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 23 - 23: iIii1I11I1II1 % IiII
  if 57 - 57: Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - IiII / o0oOOo0O0Ooo
  if 24 - 24: I1Ii111 + OOooOOo
  if 76 - 76: O0 - OoooooooOO
  if 68 - 68: iII111i + I1Ii111
 oOoO00O0 = O000O . udp_sport
 iIIiiIiI = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 O000O . source , oOoO00O0 , O000O . ddt , - 1 , iIIiiIiI )
 return
 if 23 - 23: iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
 if 89 - 89: OOooOOo - I1Ii111 - iII111i
 if 67 - 67: oO0o
 if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
 if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
 if 15 - 15: o0oOOo0O0Ooo
 if 60 - 60: I1ii11iIi11i / I1Ii111
 if 13 - 13: I1Ii111
 if 52 - 52: II111iiii / OoO0O00 . Ii1I
 if 68 - 68: iII111i
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 67 - 67: I1IiiI * I1IiiI
 if 100 - 100: iII111i * iII111i . Oo0Ooo
 if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
 if 48 - 48: ooOoO0o + II111iiii
 if 73 - 73: II111iiii
 if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
 if 35 - 35: II111iiii + IiII
 OO0oooOO = ms . map_server
 if ( lisp_decent_push_configured and OO0oooOO . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  OO0oooOO = copy . deepcopy ( OO0oooOO )
  OO0oooOO . address = 0x7f000001
  ooOo0O0O0oOO0 = bold ( "Bootstrap" , False )
  o0O0Ooo = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( ooOo0O0O0oOO0 , o0O0Ooo ) )
  if 66 - 66: o0oOOo0O0Ooo % IiII
  if 39 - 39: IiII
  if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
  if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
  if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
  if 62 - 62: O0
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 52 - 52: OoooooooOO . oO0o
 if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
 if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
 if 59 - 59: Ii1I
 if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
 if 6 - 6: i11iIiiIii . I11i - OoooooooOO
 if ( ms . ekey != None ) :
  OoooooOoOOO = ms . ekey . zfill ( 32 )
  OoOooO = "0" * 8
  iiIiIiI111 = chacha . ChaCha ( OoooooOoOOO , OoOooO , 20 ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + iiIiIiI111
  I1i = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( I1i , ms . ekey_id ) )
  if 26 - 26: I1IiiI
  if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
 OoOo0Ooo0Oooo = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  OoOo0Ooo0Oooo = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 37 - 37: OoooooooOO * I1IiiI - I1ii11iIi11i
  if 37 - 37: OoooooooOO - OoOoOO00 . I1IiiI * oO0o - Oo0Ooo + I1IiiI
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( OO0oooOO . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , OoOo0Ooo0Oooo ) )
 if 17 - 17: OOooOOo % I1IiiI - o0oOOo0O0Ooo + OoO0O00 + OoOoOO00 + i1IIi
 lisp_send ( lisp_sockets , OO0oooOO , LISP_CTRL_PORT , packet )
 return
 if 74 - 74: iIii1I11I1II1
 if 8 - 8: OOooOOo % o0oOOo0O0Ooo
 if 36 - 36: Ii1I % OoooooooOO
 if 31 - 31: Ii1I / Ii1I / Ii1I / o0oOOo0O0Ooo / I11i
 if 24 - 24: i1IIi - Oo0Ooo % Oo0Ooo
 if 29 - 29: IiII
 if 94 - 94: I1IiiI * Oo0Ooo * OOooOOo + Oo0Ooo / I1Ii111
 if 3 - 3: I11i * iII111i - OoooooooOO % OoOoOO00 % ooOoO0o
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 II11IIII1 = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 48 - 48: i11iIiiIii * i11iIiiIii
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 92 - 92: i1IIi
 if 3 - 3: iIii1I11I1II1 . I1ii11iIi11i
 packet = lisp_control_packet_ipc ( packet , II11IIII1 , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 97 - 97: O0
 if 82 - 82: OoooooooOO / I1Ii111 - ooOoO0o . I1Ii111
 if 41 - 41: I11i . I11i
 if 12 - 12: OoOoOO00 / I1IiiI
 if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
 if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
 if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
 if 69 - 69: iII111i % I1ii11iIi11i
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 19 - 19: IiII
 if 35 - 35: OoOoOO00
 if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
 if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
 if 73 - 73: OOooOOo
 if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
 if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
 if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
 if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
 if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
 if 8 - 8: O0 + i1IIi . O0
 if 67 - 67: I1IiiI
 if 42 - 42: ooOoO0o - o0oOOo0O0Ooo % oO0o - ooOoO0o
 if 87 - 87: OoooooooOO / O0
 if 57 - 57: iIii1I11I1II1 / IiII + OoO0O00 * oO0o + Ii1I
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 76 - 76: i11iIiiIii . OOooOOo / I11i * oO0o % iIii1I11I1II1 . ooOoO0o
 if 75 - 75: O0 + I1IiiI
 if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
 if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
 if 73 - 73: II111iiii
 if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
 if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
  if 44 - 44: iIii1I11I1II1 * iII111i
  if 32 - 32: OoOoOO00
  if 65 - 65: iIii1I11I1II1 + iII111i
  if 90 - 90: i11iIiiIii - Oo0Ooo
  if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
 if ( lisp_nat_traversal ) :
  IiiIiiIIII = lisp_get_any_translated_port ( )
  if ( IiiIiiIIII != None ) : inner_sport = IiiIiiIIII
  if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
 O000O = lisp_ecm ( inner_sport )
 if 45 - 45: OoooooooOO * I1Ii111
 O000O . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 O000O . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 O000O . ddt = ddt
 iIiIiiIiI1i1I1 = O000O . encode ( packet , inner_source , inner_dest )
 if ( iIiIiiIiI1i1I1 == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
 O000O . print_ecm ( )
 if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
 packet = iIiIiiIiI1i1I1 + packet
 if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
 Oo0o = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( Oo0o ) )
 OO0oooOO = lisp_convert_4to6 ( Oo0o )
 lisp_send ( lisp_sockets , OO0oooOO , LISP_CTRL_PORT , packet )
 return
 if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
 if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
 if 65 - 65: I1IiiI . ooOoO0o
 if 51 - 51: I1Ii111
 if 89 - 89: Oo0Ooo
 if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
 if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
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
if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 58 - 58: O0 * OOooOOo
if 60 - 60: ooOoO0o
if 47 - 47: i11iIiiIii
if 21 - 21: i1IIi - oO0o - Oo0Ooo
if 11 - 11: i1IIi
if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
def byte_swap_64 ( address ) :
 oOOOo0o = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
 if 56 - 56: Ii1I . iII111i
 if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
 if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
 if 52 - 52: i11iIiiIii
 if 1 - 1: i1IIi * iIii1I11I1II1
 if 29 - 29: I11i
 if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
 return ( oOOOo0o )
 if 6 - 6: IiII / OoO0O00
 if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
 if 77 - 77: Ii1I
 if 9 - 9: OOooOOo / OoooooooOO + iII111i
 if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
 if 20 - 20: I1Ii111
 if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
 if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
 if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
 if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
 if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
 if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
 if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
class lisp_cache_entries ( object ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
  if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
  if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
class lisp_cache ( object ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 74 - 74: i11iIiiIii / II111iiii
  if 62 - 62: O0
 def cache_size ( self ) :
  return ( self . cache_count )
  if 63 - 63: Oo0Ooo + Oo0Ooo
  if 48 - 48: Oo0Ooo * I1ii11iIi11i % II111iiii
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   Iii1iii1II = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   Iii1iii1II = prefix . mask_len
  else :
   Iii1iii1II = prefix . mask_len + 48
   if 42 - 42: I1Ii111 - ooOoO0o % o0oOOo0O0Ooo * I1IiiI . o0oOOo0O0Ooo
   if 84 - 84: iIii1I11I1II1
  i1oO00O = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  ii11IiI = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 39 - 39: Ii1I . II111iiii / I1IiiI
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    i1iIii = prefix . addr_length ( ) * 2
    oOOOo0o = lisp_hex_string ( prefix . address ) . zfill ( i1iIii )
   else :
    oOOOo0o = prefix . address
    if 44 - 44: Ii1I / Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   ii11IiI = "8003"
   oOOOo0o = prefix . address . print_geo ( )
  else :
   ii11IiI = ""
   oOOOo0o = ""
   if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
   if 81 - 81: I1Ii111 % OoO0O00 / O0
  IIIOoo = i1oO00O + ii11IiI + oOOOo0o
  return ( [ Iii1iii1II , IIIOoo ] )
  if 55 - 55: i1IIi - I1Ii111 + I11i
  if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  Iii1iii1II , IIIOoo = self . build_key ( prefix )
  if ( Iii1iii1II not in self . cache ) :
   self . cache [ Iii1iii1II ] = lisp_cache_entries ( )
   self . cache_sorted = self . sort_in_entry ( self . cache_sorted , Iii1iii1II )
   if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
  if ( IIIOoo not in self . cache [ Iii1iii1II ] . entries ) :
   self . cache_count += 1
   if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
  self . cache [ Iii1iii1II ] . entries [ IIIOoo ] = entry
  if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
  if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
 def lookup_cache ( self , prefix , exact ) :
  i1IiiIiI11I , IIIOoo = self . build_key ( prefix )
  if ( exact ) :
   if ( i1IiiIiI11I not in self . cache ) : return ( None )
   if ( IIIOoo not in self . cache [ i1IiiIiI11I ] . entries ) : return ( None )
   return ( self . cache [ i1IiiIiI11I ] . entries [ IIIOoo ] )
   if 96 - 96: i1IIi % OoooooooOO * OOooOOo - Oo0Ooo + iIii1I11I1II1
   if 87 - 87: I11i . I1ii11iIi11i / i1IIi - II111iiii - i11iIiiIii
  iIIiOOOO0 = None
  for Iii1iii1II in self . cache_sorted :
   if ( i1IiiIiI11I < Iii1iii1II ) : return ( iIIiOOOO0 )
   for oO00Oo in list ( self . cache [ Iii1iii1II ] . entries . values ( ) ) :
    if ( prefix . is_more_specific ( oO00Oo . eid ) ) :
     if ( iIIiOOOO0 == None or
 oO00Oo . eid . is_more_specific ( iIIiOOOO0 . eid ) ) : iIIiOOOO0 = oO00Oo
     if 49 - 49: I1ii11iIi11i + I1Ii111 * OOooOOo - IiII . i11iIiiIii
     if 34 - 34: iII111i . OoOoOO00
     if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  return ( iIIiOOOO0 )
  if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
  if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
 def delete_cache ( self , prefix ) :
  Iii1iii1II , IIIOoo = self . build_key ( prefix )
  if ( Iii1iii1II not in self . cache ) : return
  if ( IIIOoo not in self . cache [ Iii1iii1II ] . entries ) : return
  self . cache [ Iii1iii1II ] . entries . pop ( IIIOoo )
  self . cache_count -= 1
  if 89 - 89: I1IiiI % I11i - OOooOOo
  if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
 def walk_cache ( self , function , parms ) :
  for Iii1iii1II in self . cache_sorted :
   for oO00Oo in list ( self . cache [ Iii1iii1II ] . entries . values ( ) ) :
    iiI1i , parms = function ( oO00Oo , parms )
    if ( iiI1i == False ) : return ( parms )
    if 4 - 4: I1IiiI * I1IiiI + II111iiii . iII111i
    if 9 - 9: I11i % o0oOOo0O0Ooo % I1Ii111 - ooOoO0o + I11i
  return ( parms )
  if 87 - 87: IiII
  if 12 - 12: O0 - iII111i * IiII . i11iIiiIii
 def sort_in_entry ( self , table , value ) :
  if ( table == [ ] ) : return ( [ value ] )
  if 25 - 25: Ii1I % i1IIi * I11i * Ii1I - IiII . i11iIiiIii
  I1oo0O0Ooo0O00 = table
  while ( True ) :
   if ( len ( I1oo0O0Ooo0O00 ) == 1 ) :
    if ( value == I1oo0O0Ooo0O00 [ 0 ] ) : return ( table )
    OOOooo0OooOoO = table . index ( I1oo0O0Ooo0O00 [ 0 ] )
    if ( value < I1oo0O0Ooo0O00 [ 0 ] ) :
     return ( table [ 0 : OOOooo0OooOoO ] + [ value ] + table [ OOOooo0OooOoO : : ] )
     if 40 - 40: OOooOOo - OoooooooOO
    if ( value > I1oo0O0Ooo0O00 [ 0 ] ) :
     return ( table [ 0 : OOOooo0OooOoO + 1 ] + [ value ] + table [ OOOooo0OooOoO + 1 : : ] )
     if 36 - 36: i1IIi % OoOoOO00 - i1IIi
     if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
   OOOooo0OooOoO = old_div ( len ( I1oo0O0Ooo0O00 ) , 2 )
   I1oo0O0Ooo0O00 = I1oo0O0Ooo0O00 [ 0 : OOOooo0OooOoO ] if ( value < I1oo0O0Ooo0O00 [ OOOooo0OooOoO ] ) else I1oo0O0Ooo0O00 [ OOOooo0OooOoO : : ]
   if 97 - 97: I11i . ooOoO0o
   if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
  return ( [ ] )
  if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
  if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 76 - 76: OoO0O00 * ooOoO0o
  for Iii1iii1II in self . cache_sorted :
   for IIIOoo in self . cache [ Iii1iii1II ] . entries :
    oO00Oo = self . cache [ Iii1iii1II ] . entries [ IIIOoo ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( Iii1iii1II , IIIOoo ,
 oO00Oo ) )
    if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
    if 98 - 98: iII111i . II111iiii % O0
    if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
    if 17 - 17: OoooooooOO - i1IIi * I11i
    if 33 - 33: i1IIi . Oo0Ooo + I11i
    if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
    if 78 - 78: I1Ii111 + I1Ii111
    if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 19 - 19: Ii1I
if 51 - 51: oO0o
if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
if 70 - 70: I1ii11iIi11i . II111iiii
if 54 - 54: OOooOOo
if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
def lisp_map_cache_lookup ( source , dest ) :
 if 63 - 63: OoOoOO00 - OoOoOO00
 o0OooO = dest . is_multicast_address ( )
 if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
 if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
 if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
 if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
 I111I1iI1 = lisp_map_cache . lookup_cache ( dest , False )
 if ( I111I1iI1 == None ) :
  iIiI1I1ii1I1 = source . print_sg ( dest ) if o0OooO else dest . print_address ( )
  iIiI1I1ii1I1 = green ( iIiI1I1ii1I1 , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( iIiI1I1ii1I1 ) )
  return ( None )
  if 14 - 14: IiII . I11i
  if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
  if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
  if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
 if ( o0OooO == False ) :
  oOooOO00OooO = green ( I111I1iI1 . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , oOooOO00OooO ) )
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
  return ( I111I1iI1 )
  if 9 - 9: iIii1I11I1II1
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
 I111I1iI1 = I111I1iI1 . lookup_source_cache ( source , False )
 if ( I111I1iI1 == None ) :
  iIiI1I1ii1I1 = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( iIiI1I1ii1I1 ) )
  return ( None )
  if 34 - 34: iIii1I11I1II1
  if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
  if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
  if 20 - 20: OoO0O00
  if 93 - 93: ooOoO0o + o0oOOo0O0Ooo - I1ii11iIi11i
 oOooOO00OooO = green ( I111I1iI1 . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , oOooOO00OooO ) )
 if 56 - 56: Ii1I / Oo0Ooo
 return ( I111I1iI1 )
 if 96 - 96: o0oOOo0O0Ooo . II111iiii
 if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
 if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
 if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
 if 6 - 6: OoooooooOO
 if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
 if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  oOo0 = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( oOo0 )
  if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
  if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
  if 14 - 14: OOooOOo * IiII
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 33 - 33: OoO0O00
 if 91 - 91: I11i % I11i % iII111i
 if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
 if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
 if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
 if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
 oOo0 = lisp_referral_cache . lookup_cache ( group , exact )
 if ( oOo0 == None ) : return ( None )
 if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
 IIIIIIi1i1I = oOo0 . lookup_source_cache ( eid , exact )
 if ( IIIIIIi1i1I ) : return ( IIIIIIi1i1I )
 if 57 - 57: II111iiii - ooOoO0o % i1IIi
 if ( exact ) : oOo0 = None
 return ( oOo0 )
 if 42 - 42: i11iIiiIii / O0
 if 8 - 8: I1Ii111
 if 51 - 51: i11iIiiIii
 if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
 if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
 if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
 if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  IiI11111I1ii1 = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( IiI11111I1ii1 )
  if 20 - 20: Oo0Ooo
  if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
  if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
  if 84 - 84: OOooOOo
  if 68 - 68: I1Ii111
 if ( eid . is_null ( ) ) : return ( None )
 if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
 if 54 - 54: oO0o + I11i - OoO0O00
 if 86 - 86: OoooooooOO
 if 51 - 51: i11iIiiIii
 if 91 - 91: OOooOOo
 if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
 IiI11111I1ii1 = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( IiI11111I1ii1 == None ) : return ( None )
 if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
 OoOoO = IiI11111I1ii1 . lookup_source_cache ( eid , exact )
 if ( OoOoO ) : return ( OoOoO )
 if 37 - 37: iII111i + OOooOOo . i11iIiiIii . Oo0Ooo
 if ( exact ) : IiI11111I1ii1 = None
 return ( IiI11111I1ii1 )
 if 9 - 9: Oo0Ooo - II111iiii - i1IIi - ooOoO0o / o0oOOo0O0Ooo * I1ii11iIi11i
 if 29 - 29: ooOoO0o
 if 65 - 65: i1IIi * ooOoO0o * I1IiiI
 if 36 - 36: o0oOOo0O0Ooo - Ii1I + O0 + OOooOOo
 if 11 - 11: I11i / OoooooooOO . I11i . II111iiii / oO0o - i11iIiiIii
 if 67 - 67: o0oOOo0O0Ooo . I1Ii111 % iIii1I11I1II1 / I1Ii111
 if 18 - 18: I11i * ooOoO0o
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 46 - 46: IiII
 if ( group . is_null ( ) ) :
  IiiiiiIiI = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( IiiiiiIiI )
  if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
  if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
  if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
  if 87 - 87: iII111i
  if 86 - 86: IiII - I11i
 if ( eid . is_null ( ) ) : return ( None )
 if 99 - 99: i1IIi + I1ii11iIi11i
 if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
 if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
 if 44 - 44: II111iiii / I1ii11iIi11i
 if 39 - 39: OoooooooOO % OoO0O00
 if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
 IiiiiiIiI = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( IiiiiiIiI == None ) : return ( None )
 if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
 if 29 - 29: IiII
 if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
 if 91 - 91: I1Ii111 * iII111i * OoO0O00
 if 79 - 79: iII111i + oO0o
 if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
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
 o0ooO = IiiiiiIiI . lookup_source_cache ( eid , exact )
 if ( o0ooO ) : return ( o0ooO )
 if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
 if ( exact ) :
  IiiiiiIiI = None
 else :
  OO0o0OoO0O = IiiiiiIiI . parent_for_more_specifics
  if ( OO0o0OoO0O and OO0o0OoO0O . accept_more_specifics ) :
   if ( group . is_more_specific ( OO0o0OoO0O . group ) ) : IiiiiiIiI = OO0o0OoO0O
   if 66 - 66: iII111i + i1IIi
   if 24 - 24: O0 / OoooooooOO - OoOoOO00
 return ( IiiiiiIiI )
 if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
 if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
 if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
 if 53 - 53: i11iIiiIii % I1ii11iIi11i
 if 59 - 59: OOooOOo
 if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
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
class lisp_address ( object ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 14 - 14: I11i + ooOoO0o . oO0o * I11i
  if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
  if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 33 - 33: I11i
  if 37 - 37: Oo0Ooo
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 36 - 36: IiII % I11i
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
   if 82 - 82: OoooooooOO
   if 14 - 14: OoO0O00 / oO0o - OOooOOo
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
  if 16 - 16: IiII + Oo0Ooo % I11i
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  oOOOo0o = self . address
  if ( ( ( oOOOo0o & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( oOOOo0o & 0xff000000 ) >> 24 ) == 172 ) :
   i1111 = ( oOOOo0o & 0x00ff0000 ) >> 16
   if ( i1111 >= 16 and i1111 <= 31 ) : return ( True )
   if 55 - 55: II111iiii - OOooOOo + OoO0O00
  if ( ( ( oOOOo0o & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 32 - 32: I1IiiI . I1ii11iIi11i
  if 67 - 67: OOooOOo
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 19 - 19: i1IIi / II111iiii . II111iiii
  if 54 - 54: iIii1I11I1II1 % ooOoO0o
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
  return ( 0 )
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
  if 3 - 3: OoO0O00 % iIii1I11I1II1
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  oOOOo0o = self . address >> 96
  return ( oOOOo0o == 0x20010005 )
  if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
  if 59 - 59: iIii1I11I1II1
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
   if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
  return ( 0 )
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  if 63 - 63: I11i
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
  if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
 def packet_format ( self ) :
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
  if 44 - 44: OoooooooOO
  if 18 - 18: i11iIiiIii
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
  if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
  if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
 def pack_address ( self ) :
  O0oOO0o00OO = self . packet_format ( )
  OO0 = ""
  if ( self . is_ipv4 ( ) ) :
   OO0 = struct . pack ( O0oOO0o00OO , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   I11iI1 = byte_swap_64 ( self . address >> 64 )
   oOo00OO0o0 = byte_swap_64 ( self . address & 0xffffffffffffffff )
   OO0 = struct . pack ( O0oOO0o00OO , I11iI1 , oOo00OO0o0 )
  elif ( self . is_mac ( ) ) :
   oOOOo0o = self . address
   I11iI1 = ( oOOOo0o >> 32 ) & 0xffff
   oOo00OO0o0 = ( oOOOo0o >> 16 ) & 0xffff
   IiiI1IiiiI = oOOOo0o & 0xffff
   OO0 = struct . pack ( O0oOO0o00OO , I11iI1 , oOo00OO0o0 , IiiI1IiiiI )
  elif ( self . is_e164 ( ) ) :
   oOOOo0o = self . address
   I11iI1 = ( oOOOo0o >> 32 ) & 0xffffffff
   oOo00OO0o0 = ( oOOOo0o & 0xffffffff )
   OO0 = struct . pack ( O0oOO0o00OO , I11iI1 , oOo00OO0o0 )
  elif ( self . is_dist_name ( ) ) :
   OO0 += self . address + "\0"
   if 51 - 51: Ii1I / ooOoO0o % OOooOOo * o0oOOo0O0Ooo
  return ( OO0 )
  if 67 - 67: I1IiiI . OOooOOo * iII111i / iII111i
  if 69 - 69: I1Ii111 % IiII - O0 % OoO0O00 - OoOoOO00 * i11iIiiIii
 def unpack_address ( self , packet ) :
  O0oOO0o00OO = self . packet_format ( )
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 99 - 99: oO0o . i11iIiiIii % i1IIi + iII111i
  oOOOo0o = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 91 - 91: I1Ii111 . II111iiii / Ii1I * O0
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( oOOOo0o [ 0 ] )
   if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
  elif ( self . is_ipv6 ( ) ) :
   if 35 - 35: I1Ii111
   if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
   if 12 - 12: Oo0Ooo + I1IiiI
   if 12 - 12: OoOoOO00 / II111iiii
   if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
   if 28 - 28: I1IiiI
   if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
   if 46 - 46: II111iiii
   if ( oOOOo0o [ 0 ] <= 0xffff and ( oOOOo0o [ 0 ] & 0xff ) == 0 ) :
    IiIiI1IIi1Ii = ( oOOOo0o [ 0 ] << 48 ) << 64
   else :
    IiIiI1IIi1Ii = byte_swap_64 ( oOOOo0o [ 0 ] ) << 64
    if 5 - 5: i11iIiiIii . OoO0O00 - oO0o - OoooooooOO % IiII * O0
   I1i1 = byte_swap_64 ( oOOOo0o [ 1 ] )
   self . address = IiIiI1IIi1Ii | I1i1
   if 84 - 84: I1IiiI . I1IiiI
  elif ( self . is_mac ( ) ) :
   OOooOoOOO = oOOOo0o [ 0 ]
   II1iIiIIIIIIi = oOOOo0o [ 1 ]
   I1i11iI = oOOOo0o [ 2 ]
   self . address = ( OOooOoOOO << 32 ) + ( II1iIiIIIIIIi << 16 ) + I1i11iI
   if 52 - 52: OoO0O00 % I11i - oO0o . I11i % IiII
  elif ( self . is_e164 ( ) ) :
   self . address = ( oOOOo0o [ 0 ] << 32 ) + oOOOo0o [ 1 ]
   if 100 - 100: OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   Ii1i1iiiIiIIiIiiii = 0
   if 74 - 74: ooOoO0o
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  return ( packet )
  if 18 - 18: iIii1I11I1II1 - I11i - oO0o
  if 12 - 12: O0 + O0 + ooOoO0o . I1IiiI * II111iiii
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 47 - 47: i11iIiiIii % OOooOOo / ooOoO0o . IiII - I1IiiI
  if 10 - 10: Oo0Ooo / ooOoO0o / I1ii11iIi11i
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 98 - 98: O0 - I1Ii111 - i11iIiiIii
  if 85 - 85: II111iiii - I1ii11iIi11i % I1IiiI . I1IiiI - OoooooooOO - I11i
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
  if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
  if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 14 - 14: iIii1I11I1II1
  if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
  if 84 - 84: OoO0O00 % OoooooooOO
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 66 - 66: OoOoOO00 . iII111i
  if 1 - 1: iII111i * i1IIi . iIii1I11I1II1 % O0 - OoooooooOO
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 87 - 87: iII111i . Oo0Ooo * i11iIiiIii % o0oOOo0O0Ooo + Ii1I
  if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
  if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
  if 46 - 46: OoOoOO00
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 75 - 75: I1IiiI
  if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 14 - 14: i1IIi / ooOoO0o
  if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 16 - 16: O0
  if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
  return ( False )
  if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
  if 19 - 19: o0oOOo0O0Ooo % I1Ii111 % I11i
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 1 - 1: I1IiiI / o0oOOo0O0Ooo - I1Ii111
  if 50 - 50: I11i - OoOoOO00 + I1IiiI % Oo0Ooo / OoooooooOO - I1ii11iIi11i
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 26 - 26: IiII . Ii1I
  if 35 - 35: I1ii11iIi11i + OOooOOo
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 88 - 88: O0
  if 4 - 4: OoOoOO00 % iIii1I11I1II1 % OoooooooOO . oO0o
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 27 - 27: II111iiii - OoOoOO00
  if 81 - 81: o0oOOo0O0Ooo - Oo0Ooo % IiII - ooOoO0o / O0
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 27 - 27: Oo0Ooo
  if 15 - 15: iIii1I11I1II1 . OoOoOO00 % Ii1I / i1IIi . o0oOOo0O0Ooo
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 45 - 45: iIii1I11I1II1 - i1IIi % I1IiiI - I1Ii111 + oO0o
  if 15 - 15: iIii1I11I1II1 - OoooooooOO / ooOoO0o
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 83 - 83: IiII + I1Ii111 / OoOoOO00 * IiII . oO0o
  if 22 - 22: O0 + ooOoO0o + I1Ii111
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
  if 85 - 85: I1IiiI * OoO0O00
  if 63 - 63: I1IiiI - i11iIiiIii
  if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
  OoOOoO0oOo = addr_str . find ( "[" )
  IiIii1Ii = addr_str . find ( "]" )
  if ( OoOOoO0oOo != - 1 and IiIii1Ii != - 1 ) :
   self . instance_id = int ( addr_str [ OoOOoO0oOo + 1 : IiIii1Ii ] )
   addr_str = addr_str [ IiIii1Ii + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 64 - 64: OoOoOO00
    if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
    if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
    if 27 - 27: i11iIiiIii + iIii1I11I1II1
    if 15 - 15: oO0o
    if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
  if ( self . is_ipv4 ( ) ) :
   I1iIi1ii = addr_str . split ( "." )
   iiIiII11i1 = int ( I1iIi1ii [ 0 ] ) << 24
   iiIiII11i1 += int ( I1iIi1ii [ 1 ] ) << 16
   iiIiII11i1 += int ( I1iIi1ii [ 2 ] ) << 8
   iiIiII11i1 += int ( I1iIi1ii [ 3 ] )
   self . address = iiIiII11i1
  elif ( self . is_ipv6 ( ) ) :
   if 72 - 72: iII111i * I1Ii111 + i11iIiiIii - iII111i % o0oOOo0O0Ooo + OOooOOo
   if 16 - 16: I11i
   if 45 - 45: I1Ii111
   if 67 - 67: OoOoOO00 * OOooOOo / OOooOOo / OoooooooOO
   if 67 - 67: I11i - i1IIi . OoooooooOO / iIii1I11I1II1
   if 34 - 34: OoO0O00 * II111iiii
   if 43 - 43: OoOoOO00 . I1IiiI
   if 44 - 44: O0 / o0oOOo0O0Ooo
   if 19 - 19: I11i
   if 91 - 91: OOooOOo * OoooooooOO
   if 89 - 89: i1IIi / iII111i . I1Ii111
   if 74 - 74: I1ii11iIi11i % iII111i / OoooooooOO / I1ii11iIi11i % i11iIiiIii % ooOoO0o
   if 82 - 82: OoooooooOO . o0oOOo0O0Ooo * I1ii11iIi11i % I1ii11iIi11i * Ii1I
   if 83 - 83: I11i - Oo0Ooo + i11iIiiIii - i11iIiiIii
   if 64 - 64: IiII % I1IiiI / ooOoO0o
   if 74 - 74: OoooooooOO
   if 22 - 22: II111iiii . O0 * I1Ii111 % OoO0O00 / OoooooooOO + I1Ii111
   O0OoO0o0 = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 58 - 58: OoO0O00 - o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i - Ii1I * i11iIiiIii
   addr_str = binascii . hexlify ( addr_str )
   if 36 - 36: II111iiii * Ii1I
   if ( O0OoO0o0 ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 53 - 53: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo . Ii1I
   self . address = int ( addr_str , 16 )
   if 79 - 79: Ii1I % O0 * OOooOOo
  elif ( self . is_geo_prefix ( ) ) :
   o00OOOoooo00 = lisp_geo ( None )
   o00OOOoooo00 . name = "geo-prefix-{}" . format ( o00OOOoooo00 )
   o00OOOoooo00 . parse_geo_string ( addr_str )
   self . address = o00OOOoooo00
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
   if 41 - 41: I1ii11iIi11i . OoooooooOO * I1ii11iIi11i - oO0o
  self . mask_len = self . host_mask_len ( )
  if 40 - 40: I1IiiI % OoO0O00 + i11iIiiIii / oO0o
  if 98 - 98: oO0o + iIii1I11I1II1 . ooOoO0o / I1ii11iIi11i
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   OOOooo0OooOoO = prefix_str . find ( "]" )
   I1iIii11iIi1I = len ( prefix_str [ OOOooo0OooOoO + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , I1iIii11iIi1I = prefix_str . split ( "/" )
  else :
   Oo = prefix_str . find ( "'" )
   if ( Oo == - 1 ) : return
   o0 = prefix_str . find ( "'" , Oo + 1 )
   if ( o0 == - 1 ) : return
   I1iIii11iIi1I = len ( prefix_str [ Oo + 1 : o0 ] ) * 8
   if 77 - 77: OoOoOO00 / Oo0Ooo * OoOoOO00 % I1IiiI . II111iiii % OoO0O00
   if 38 - 38: iII111i - OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( I1iIii11iIi1I )
  if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
  if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  iiii1iiIii = ( 2 ** self . mask_len ) - 1
  OOoO00oOoo = self . addr_length ( ) * 8 - self . mask_len
  iiii1iiIii <<= OOoO00oOoo
  self . address &= iiii1iiIii
  if 26 - 26: II111iiii - I11i % i11iIiiIii - I1ii11iIi11i + OoOoOO00
  if 65 - 65: OoooooooOO / OoooooooOO % II111iiii
 def is_geo_string ( self , addr_str ) :
  OOOooo0OooOoO = addr_str . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : addr_str = addr_str [ OOOooo0OooOoO + 1 : : ]
  if 68 - 68: OoooooooOO . iIii1I11I1II1 - Ii1I / OoO0O00 / oO0o
  o00OOOoooo00 = addr_str . split ( "/" )
  if ( len ( o00OOOoooo00 ) == 2 ) :
   if ( o00OOOoooo00 [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 14 - 14: OOooOOo + iIii1I11I1II1 - Ii1I % I11i % OoO0O00 - i11iIiiIii
  o00OOOoooo00 = o00OOOoooo00 [ 0 ]
  o00OOOoooo00 = o00OOOoooo00 . split ( "-" )
  O0o0 = len ( o00OOOoooo00 )
  if ( O0o0 < 8 or O0o0 > 9 ) : return ( False )
  if 36 - 36: IiII * OoooooooOO . i11iIiiIii * i1IIi
  for O0O0Oo in range ( 0 , O0o0 ) :
   if ( O0O0Oo == 3 ) :
    if ( o00OOOoooo00 [ O0O0Oo ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 94 - 94: o0oOOo0O0Ooo
   if ( O0O0Oo == 7 ) :
    if ( o00OOOoooo00 [ O0O0Oo ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 42 - 42: Oo0Ooo
   if ( o00OOOoooo00 [ O0O0Oo ] . isdigit ( ) == False ) : return ( False )
   if 97 - 97: IiII / IiII . iII111i * O0 + II111iiii
  return ( True )
  if 33 - 33: oO0o * IiII / i11iIiiIii
  if 76 - 76: o0oOOo0O0Ooo
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 80 - 80: OOooOOo
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 15 - 15: OOooOOo . OoOoOO00 / oO0o . I1ii11iIi11i % OoO0O00 - oO0o
  if 21 - 21: ooOoO0o . o0oOOo0O0Ooo . oO0o . i1IIi
 def print_address ( self ) :
  oOOOo0o = self . print_address_no_iid ( )
  i1oO00O = "[" + str ( self . instance_id )
  for OoOOoO0oOo in self . iid_list : i1oO00O += "," + str ( OoOOoO0oOo )
  i1oO00O += "]"
  oOOOo0o = "{}{}" . format ( i1oO00O , oOOOo0o )
  return ( oOOOo0o )
  if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
  if 8 - 8: O0 + o0oOOo0O0Ooo / O0 - I1ii11iIi11i % I1ii11iIi11i
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   oOOOo0o = self . address
   Oo0oo0o00oOOo = oOOOo0o >> 24
   Oo0oOO = ( oOOOo0o >> 16 ) & 0xff
   o0ooO0ooO0000 = ( oOOOo0o >> 8 ) & 0xff
   O00ooO0OoOO0O = oOOOo0o & 0xff
   return ( "{}.{}.{}.{}" . format ( Oo0oo0o00oOOo , Oo0oOO , o0ooO0ooO0000 , O00ooO0OoOO0O ) )
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
   if 53 - 53: II111iiii + I11i / IiII % OoO0O00 * i11iIiiIii
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 65 - 65: ooOoO0o . ooOoO0o + Oo0Ooo % Ii1I
  if 96 - 96: I1Ii111 - I11i * I1Ii111
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   Iiii = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , Iiii ) )
   if 77 - 77: i1IIi . ooOoO0o % ooOoO0o - Ii1I
  oOOOo0o = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( oOOOo0o )
  if ( self . is_geo_prefix ( ) ) : return ( oOOOo0o )
  if 6 - 6: OOooOOo % Ii1I + ooOoO0o
  OOOooo0OooOoO = oOOOo0o . find ( "no-address" )
  if ( OOOooo0OooOoO == - 1 ) :
   oOOOo0o = "{}/{}" . format ( oOOOo0o , str ( self . mask_len ) )
  else :
   oOOOo0o = oOOOo0o [ 0 : OOOooo0OooOoO ]
   if 17 - 17: iIii1I11I1II1 * I1Ii111 % oO0o + o0oOOo0O0Ooo . Ii1I * Oo0Ooo
  return ( oOOOo0o )
  if 16 - 16: I1IiiI % OoO0O00 . ooOoO0o / OoooooooOO
  if 8 - 8: I1Ii111 % OoO0O00 . I1IiiI - OoOoOO00 + i1IIi / iIii1I11I1II1
 def print_prefix_no_iid ( self ) :
  oOOOo0o = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( oOOOo0o )
  if ( self . is_geo_prefix ( ) ) : return ( oOOOo0o )
  return ( "{}/{}" . format ( oOOOo0o , str ( self . mask_len ) ) )
  if 89 - 89: II111iiii / Ii1I % Ii1I
  if 57 - 57: I11i
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  oOOOo0o = self . print_address ( )
  OOOooo0OooOoO = oOOOo0o . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : oOOOo0o = oOOOo0o [ OOOooo0OooOoO + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   oOOOo0o = oOOOo0o . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , oOOOo0o ) )
   if 95 - 95: OoOoOO00 + I11i * i1IIi - ooOoO0o % ooOoO0o
  return ( "{}-{}-{}" . format ( self . instance_id , oOOOo0o , self . mask_len ) )
  if 58 - 58: OOooOOo
  if 74 - 74: i1IIi . IiII / ooOoO0o + I11i % i11iIiiIii % iII111i
 def print_sg ( self , g ) :
  I1iiIi111I = self . print_prefix ( )
  oo00oOo0o0o = I1iiIi111I . find ( "]" ) + 1
  g = g . print_prefix ( )
  Oo0OO00O0O0 = g . find ( "]" ) + 1
  i111i1iIi1 = "[{}]({}, {})" . format ( self . instance_id , I1iiIi111I [ oo00oOo0o0o : : ] , g [ Oo0OO00O0O0 : : ] )
  return ( i111i1iIi1 )
  if 57 - 57: iIii1I11I1II1 + I1ii11iIi11i / OoOoOO00 * I1ii11iIi11i . i1IIi * iII111i
  if 67 - 67: IiII + i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i11iIiiIii
 def hash_address ( self , addr ) :
  I11iI1 = self . address
  oOo00OO0o0 = addr . address
  if 23 - 23: Oo0Ooo
  if ( self . is_geo_prefix ( ) ) : I11iI1 = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : oOo00OO0o0 = addr . address . print_geo ( )
  if 7 - 7: Oo0Ooo / oO0o . I1Ii111 % I11i
  if ( type ( I11iI1 ) == str ) :
   I11iI1 = int ( binascii . hexlify ( I11iI1 [ 0 : 1 ] ) )
   if 85 - 85: II111iiii / o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO / Ii1I
  if ( type ( oOo00OO0o0 ) == str ) :
   oOo00OO0o0 = int ( binascii . hexlify ( oOo00OO0o0 [ 0 : 1 ] ) )
   if 18 - 18: i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
  return ( I11iI1 ^ oOo00OO0o0 )
  if 50 - 50: IiII / OoooooooOO . I11i
  if 93 - 93: OOooOOo / OoooooooOO % iII111i % Ii1I / I1Ii111 % OOooOOo
  if 25 - 25: i1IIi % Oo0Ooo . i1IIi * OoOoOO00 . Ii1I % OoO0O00
  if 47 - 47: o0oOOo0O0Ooo - i11iIiiIii / OoooooooOO
  if 93 - 93: I1IiiI * II111iiii * O0 % o0oOOo0O0Ooo + oO0o / ooOoO0o
  if 79 - 79: OoO0O00 + ooOoO0o / oO0o % I1ii11iIi11i
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 77 - 77: Ii1I / Ii1I / I1ii11iIi11i
  I1iIii11iIi1I = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   Oooo0Oo00O00 = 2 ** ( 32 - I1iIii11iIi1I )
   IIoooOOo0o0ooO = prefix . instance_id
   Iiii = IIoooOOo0o0ooO + Oooo0Oo00O00
   return ( self . instance_id in range ( IIoooOOo0o0ooO , Iiii ) )
   if 66 - 66: Ii1I * I1Ii111 * OoO0O00
   if 92 - 92: II111iiii * iII111i % OoOoOO00 % OoOoOO00 % i11iIiiIii
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 93 - 93: Ii1I + iIii1I11I1II1 % Ii1I . iIii1I11I1II1
   if 48 - 48: OoooooooOO - O0 + I1IiiI - I11i
   if 86 - 86: i11iIiiIii / IiII + i11iIiiIii + o0oOOo0O0Ooo . I1Ii111 . I1Ii111
   if 90 - 90: ooOoO0o % Ii1I
   if 12 - 12: OoooooooOO . OoooooooOO * I11i
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   oOOOo0o = self . address
   OoO000oOo = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    oOOOo0o = self . address . print_geo ( )
    OoO000oOo = prefix . address . print_geo ( )
    if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
   if ( len ( oOOOo0o ) < len ( OoO000oOo ) ) : return ( False )
   return ( oOOOo0o . find ( OoO000oOo ) == 0 )
   if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
   if 98 - 98: II111iiii - i1IIi - ooOoO0o
   if 36 - 36: IiII + o0oOOo0O0Ooo
   if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
   if 10 - 10: oO0o / i11iIiiIii
  if ( self . mask_len < I1iIii11iIi1I ) : return ( False )
  if 73 - 73: OoO0O00 - i1IIi
  OOoO00oOoo = ( prefix . addr_length ( ) * 8 ) - I1iIii11iIi1I
  iiii1iiIii = ( 2 ** I1iIii11iIi1I - 1 ) << OOoO00oOoo
  return ( ( self . address & iiii1iiIii ) == prefix . address )
  if 52 - 52: I1ii11iIi11i
  if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
 def mask_address ( self , mask_len ) :
  OOoO00oOoo = ( self . addr_length ( ) * 8 ) - mask_len
  iiii1iiIii = ( 2 ** mask_len - 1 ) << OOoO00oOoo
  self . address &= iiii1iiIii
  if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
  if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  i11IIi = self . print_prefix ( )
  IiiiI1i = prefix . print_prefix ( ) if prefix else ""
  return ( i11IIi == IiiiI1i )
  if 62 - 62: OoooooooOO + OoO0O00 . IiII
  if 41 - 41: OoooooooOO + oO0o % oO0o / I1ii11iIi11i
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   o0o0iiiI1ii1 = lisp_myrlocs [ 0 ]
   if ( o0o0iiiI1ii1 == None ) : return ( False )
   o0o0iiiI1ii1 = o0o0iiiI1ii1 . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == o0o0iiiI1ii1 )
   if 60 - 60: Oo0Ooo - iII111i . II111iiii % ooOoO0o / OoooooooOO / iIii1I11I1II1
  if ( self . is_ipv6 ( ) ) :
   o0o0iiiI1ii1 = lisp_myrlocs [ 1 ]
   if ( o0o0iiiI1ii1 == None ) : return ( False )
   o0o0iiiI1ii1 = o0o0iiiI1ii1 . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == o0o0iiiI1ii1 )
   if 23 - 23: I11i + iIii1I11I1II1
  return ( False )
  if 60 - 60: O0 * I1IiiI + o0oOOo0O0Ooo * OoO0O00 + o0oOOo0O0Ooo / i11iIiiIii
  if 54 - 54: i11iIiiIii . iII111i * i1IIi
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 68 - 68: Oo0Ooo
  self . instance_id = iid
  self . mask_len = mask_len
  if 20 - 20: IiII + i11iIiiIii * OOooOOo
  if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
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
  if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
  if 3 - 3: i11iIiiIii * IiII . Oo0Ooo % OoOoOO00 * I11i . iII111i
  if 80 - 80: I11i - IiII
 def lcaf_encode_iid ( self ) :
  oo0OoOOO = LISP_LCAF_INSTANCE_ID_TYPE
  Ooo00OoO0O00 = socket . htons ( self . lcaf_length ( oo0OoOOO ) )
  i1oO00O = self . instance_id
  ii11IiI = self . afi
  Iii1iii1II = 0
  if ( ii11IiI < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    ii11IiI = LISP_AFI_LCAF
    Iii1iii1II = 0
   else :
    ii11IiI = 0
    Iii1iii1II = self . mask_len
    if 40 - 40: OOooOOo * I1IiiI % I11i . I1Ii111 % O0 . O0
    if 14 - 14: ooOoO0o . OoOoOO00 + ooOoO0o * OoOoOO00 . OoOoOO00 * Oo0Ooo
    if 40 - 40: OoooooooOO
  IIi1 = struct . pack ( "BBBBH" , 0 , 0 , oo0OoOOO , Iii1iii1II , Ooo00OoO0O00 )
  IIi1 += struct . pack ( "IH" , socket . htonl ( i1oO00O ) , socket . htons ( ii11IiI ) )
  if ( ii11IiI == 0 ) : return ( IIi1 )
  if 77 - 77: iIii1I11I1II1 % I1Ii111 + II111iiii
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   IIi1 = IIi1 [ 0 : - 2 ]
   IIi1 += self . address . encode_geo ( )
   return ( IIi1 )
   if 40 - 40: I1ii11iIi11i / I1ii11iIi11i + I1IiiI + OoOoOO00
   if 76 - 76: iIii1I11I1II1 . iIii1I11I1II1 / OOooOOo / OoOoOO00 / iII111i / II111iiii
  IIi1 += self . pack_address ( )
  return ( IIi1 )
  if 64 - 64: i1IIi * II111iiii + I1ii11iIi11i + OOooOOo % I1ii11iIi11i - OoooooooOO
  if 96 - 96: IiII + oO0o / Oo0Ooo + OoooooooOO
 def lcaf_decode_iid ( self , packet ) :
  O0oOO0o00OO = "BBBBH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 53 - 53: Ii1I * IiII + Oo0Ooo + i11iIiiIii - iIii1I11I1II1
  I1iIiiI1IIi1 , i1iIi1II1 , oo0OoOOO , Oo0OOoo0 , i1iIii = struct . unpack ( O0oOO0o00OO ,
 packet [ : Ii1i1iiiIiIIiIiiii ] )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 58 - 58: Ii1I . Oo0Ooo
  if ( oo0OoOOO != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 28 - 28: Ii1I . II111iiii - OOooOOo / iIii1I11I1II1 - I1IiiI
  O0oOO0o00OO = "IH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 78 - 78: iIii1I11I1II1
  i1oO00O , ii11IiI = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 64 - 64: OoOoOO00 - oO0o
  i1iIii = socket . ntohs ( i1iIii )
  self . instance_id = socket . ntohl ( i1oO00O )
  ii11IiI = socket . ntohs ( ii11IiI )
  self . afi = ii11IiI
  if ( Oo0OOoo0 != 0 and ii11IiI == 0 ) : self . mask_len = Oo0OOoo0
  if ( ii11IiI == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if Oo0OOoo0 else LISP_AFI_ULTIMATE_ROOT
   if 8 - 8: i11iIiiIii - iIii1I11I1II1 / I1Ii111 . i11iIiiIii % o0oOOo0O0Ooo / oO0o
   if 36 - 36: IiII
   if 53 - 53: OoooooooOO / I1IiiI % I11i + Oo0Ooo
   if 15 - 15: O0
   if 75 - 75: iII111i / OoOoOO00
  if ( ii11IiI == 0 ) : return ( packet )
  if 2 - 2: i1IIi + oO0o % iII111i % I1ii11iIi11i + ooOoO0o . iII111i
  if 26 - 26: I11i + o0oOOo0O0Ooo + Ii1I % I11i
  if 95 - 95: IiII - O0 * oO0o * O0
  if 47 - 47: I1IiiI
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 20 - 20: I1Ii111
   if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
   if 73 - 73: OOooOOo / Oo0Ooo
   if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
   if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
  if ( ii11IiI == LISP_AFI_LCAF ) :
   O0oOO0o00OO = "BBBBH"
   Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
   if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
   if 70 - 70: I1ii11iIi11i
   Oo0OoooOoO0O0 , iIi1i , oo0OoOOO , OooIiii1ii , I1ii = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
   if 11 - 11: I1Ii111
   if 70 - 70: Ii1I
   if ( oo0OoOOO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 22 - 22: Ii1I
   I1ii = socket . ntohs ( I1ii )
   packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
   if ( I1ii > len ( packet ) ) : return ( None )
   if 59 - 59: I1ii11iIi11i
   o00OOOoooo00 = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = o00OOOoooo00
   packet = o00OOOoooo00 . decode_geo ( packet , I1ii , OooIiii1ii )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 90 - 90: OOooOOo / iII111i
   if 70 - 70: o0oOOo0O0Ooo
  Ooo00OoO0O00 = self . addr_length ( )
  if ( len ( packet ) < Ooo00OoO0O00 ) : return ( None )
  if 49 - 49: OOooOOo - I1IiiI + OoooooooOO % iII111i + o0oOOo0O0Ooo + OoOoOO00
  packet = self . unpack_address ( packet )
  return ( packet )
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
  if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
  if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
  if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
  if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
 def lcaf_encode_sg ( self , group ) :
  oo0OoOOO = LISP_LCAF_MCAST_INFO_TYPE
  i1oO00O = socket . htonl ( self . instance_id )
  Ooo00OoO0O00 = socket . htons ( self . lcaf_length ( oo0OoOOO ) )
  IIi1 = struct . pack ( "BBBBHIHBB" , 0 , 0 , oo0OoOOO , 0 , Ooo00OoO0O00 , i1oO00O ,
 0 , self . mask_len , group . mask_len )
  if 8 - 8: OOooOOo
  IIi1 += struct . pack ( "H" , socket . htons ( self . afi ) )
  IIi1 += self . pack_address ( )
  IIi1 += struct . pack ( "H" , socket . htons ( group . afi ) )
  IIi1 += group . pack_address ( )
  return ( IIi1 )
  if 85 - 85: O0 % OOooOOo . Ii1I
  if 74 - 74: I1ii11iIi11i - I1Ii111 + i11iIiiIii / I1Ii111 / OoooooooOO + o0oOOo0O0Ooo
 def lcaf_decode_sg ( self , packet ) :
  O0oOO0o00OO = "BBBBHIHBB"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( [ None , None ] )
  if 23 - 23: Oo0Ooo
  I1iIiiI1IIi1 , i1iIi1II1 , oo0OoOOO , Iii1i1 , i1iIii , i1oO00O , oOo0oO00oo0O0 , IIiIiIii1111 , I111IIi1IIi = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 31 - 31: I11i . ooOoO0o
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 69 - 69: I1ii11iIi11i
  if ( oo0OoOOO != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 6 - 6: iIii1I11I1II1 * I1ii11iIi11i / I11i % I1Ii111 / Oo0Ooo
  self . instance_id = socket . ntohl ( i1oO00O )
  i1iIii = socket . ntohs ( i1iIii ) - 8
  if 94 - 94: OoO0O00 - oO0o + iII111i . ooOoO0o * OoooooooOO
  if 42 - 42: iII111i / i11iIiiIii + II111iiii % IiII / ooOoO0o
  if 100 - 100: ooOoO0o / I1IiiI
  if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
  if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
  O0oOO0o00OO = "H"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( [ None , None ] )
  if ( i1iIii < Ii1i1iiiIiIIiIiiii ) : return ( [ None , None ] )
  if 64 - 64: i1IIi
  ii11IiI = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  i1iIii -= Ii1i1iiiIiIIiIiiii
  self . afi = socket . ntohs ( ii11IiI )
  self . mask_len = IIiIiIii1111
  Ooo00OoO0O00 = self . addr_length ( )
  if ( i1iIii < Ooo00OoO0O00 ) : return ( [ None , None ] )
  if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
  i1iIii -= Ooo00OoO0O00
  if 5 - 5: OoOoOO00 % i1IIi
  if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
  if 76 - 76: Oo0Ooo + I1IiiI - O0
  if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
  if 73 - 73: Oo0Ooo . OoOoOO00
  O0oOO0o00OO = "H"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( [ None , None ] )
  if ( i1iIii < Ii1i1iiiIiIIiIiiii ) : return ( [ None , None ] )
  if 50 - 50: IiII / o0oOOo0O0Ooo
  ii11IiI = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  i1iIii -= Ii1i1iiiIiIIiIiiii
  iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  iiI . afi = socket . ntohs ( ii11IiI )
  iiI . mask_len = I111IIi1IIi
  iiI . instance_id = self . instance_id
  Ooo00OoO0O00 = self . addr_length ( )
  if ( i1iIii < Ooo00OoO0O00 ) : return ( [ None , None ] )
  if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
  packet = iiI . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 52 - 52: O0
  return ( [ packet , iiI ] )
  if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
 def lcaf_decode_eid ( self , packet ) :
  O0oOO0o00OO = "BBB"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( [ None , None ] )
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
  if 83 - 83: oO0o / OoO0O00
  if 34 - 34: OoooooooOO - i1IIi * O0
  if 83 - 83: I1IiiI + OoO0O00
  if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
  Iii1i1 , iIi1i , oo0OoOOO = struct . unpack ( O0oOO0o00OO ,
 packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
  if ( oo0OoOOO == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( oo0OoOOO == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , iiI = self . lcaf_decode_sg ( packet )
   return ( [ packet , iiI ] )
  elif ( oo0OoOOO == LISP_LCAF_GEO_COORD_TYPE ) :
   O0oOO0o00OO = "BBBBH"
   Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
   if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( None )
   if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
   Oo0OoooOoO0O0 , iIi1i , oo0OoOOO , OooIiii1ii , I1ii = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] )
   if 62 - 62: Ii1I / Oo0Ooo . OoO0O00 - OOooOOo
   if 89 - 89: o0oOOo0O0Ooo % OoO0O00
   if ( oo0OoOOO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 53 - 53: OoOoOO00 . ooOoO0o - OoO0O00
   I1ii = socket . ntohs ( I1ii )
   packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
   if ( I1ii > len ( packet ) ) : return ( None )
   if 26 - 26: ooOoO0o - oO0o + OOooOOo * Ii1I - I11i % I1IiiI
   o00OOOoooo00 = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = o00OOOoooo00
   packet = o00OOOoooo00 . decode_geo ( packet , I1ii , OooIiii1ii )
   self . mask_len = self . host_mask_len ( )
   if 73 - 73: ooOoO0o + Ii1I . O0 . iII111i
  return ( [ packet , None ] )
  if 77 - 77: OOooOOo % I1IiiI - iII111i % I1Ii111
  if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
  if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
  if 46 - 46: I1ii11iIi11i * ooOoO0o
  if 4 - 4: I1Ii111 * II111iiii
  if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
class lisp_elp_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
  if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
 def copy_elp_node ( self ) :
  o00Oo0 = lisp_elp_node ( )
  o00Oo0 . copy_address ( self . address )
  o00Oo0 . probe = self . probe
  o00Oo0 . strict = self . strict
  o00Oo0 . eid = self . eid
  o00Oo0 . we_are_last = self . we_are_last
  return ( o00Oo0 )
  if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
  if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
  if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
class lisp_elp ( object ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
  if 84 - 84: Oo0Ooo + OoOoOO00 / iII111i . I1ii11iIi11i
 def copy_elp ( self ) :
  o0ooO0o0 = lisp_elp ( self . elp_name )
  o0ooO0o0 . use_elp_node = self . use_elp_node
  o0ooO0o0 . we_are_last = self . we_are_last
  for o00Oo0 in self . elp_nodes :
   o0ooO0o0 . elp_nodes . append ( o00Oo0 . copy_elp_node ( ) )
   if 26 - 26: Oo0Ooo
  return ( o0ooO0o0 )
  if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
  if 43 - 43: OoO0O00 * OoO0O00 * oO0o
 def print_elp ( self , want_marker ) :
  iiii1IIiIiI = ""
  for o00Oo0 in self . elp_nodes :
   i11IiI11I = ""
   if ( want_marker ) :
    if ( o00Oo0 == self . use_elp_node ) :
     i11IiI11I = "*"
    elif ( o00Oo0 . we_are_last ) :
     i11IiI11I = "x"
     if 21 - 21: Ii1I . OOooOOo * Oo0Ooo
     if 12 - 12: oO0o + ooOoO0o * IiII
   iiii1IIiIiI += "{}{}({}{}{}), " . format ( i11IiI11I ,
 o00Oo0 . address . print_address_no_iid ( ) ,
 "r" if o00Oo0 . eid else "R" , "P" if o00Oo0 . probe else "p" ,
 "S" if o00Oo0 . strict else "s" )
   if 84 - 84: o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo + I1IiiI
  return ( iiii1IIiIiI [ 0 : - 2 ] if iiii1IIiIiI != "" else "" )
  if 89 - 89: II111iiii
  if 41 - 41: iIii1I11I1II1
 def select_elp_node ( self ) :
  iIIiI , oO0oO000ooo0o , iIIiI1111 = lisp_myrlocs
  OOOooo0OooOoO = None
  if 24 - 24: I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo / I1ii11iIi11i
  for o00Oo0 in self . elp_nodes :
   if ( iIIiI and o00Oo0 . address . is_exact_match ( iIIiI ) ) :
    OOOooo0OooOoO = self . elp_nodes . index ( o00Oo0 )
    break
    if 72 - 72: I1Ii111 % O0
   if ( oO0oO000ooo0o and o00Oo0 . address . is_exact_match ( oO0oO000ooo0o ) ) :
    OOOooo0OooOoO = self . elp_nodes . index ( o00Oo0 )
    break
    if 24 - 24: I11i + I11i % I11i
    if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
    if 21 - 21: II111iiii
    if 89 - 89: OOooOOo % i11iIiiIii * OoOoOO00 % oO0o / O0 * i1IIi
    if 16 - 16: IiII
    if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
    if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
  if ( OOOooo0OooOoO == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   o00Oo0 . we_are_last = False
   return
   if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
   if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
   if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
   if 99 - 99: i11iIiiIii - I1Ii111
   if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
   if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ OOOooo0OooOoO ] ) :
   self . use_elp_node = None
   o00Oo0 . we_are_last = True
   return
   if 54 - 54: II111iiii * I1IiiI
   if 49 - 49: I1ii11iIi11i
   if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
   if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
   if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  self . use_elp_node = self . elp_nodes [ OOOooo0OooOoO + 1 ]
  return
  if 15 - 15: oO0o
  if 40 - 40: I1Ii111
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
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
  if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
  if 64 - 64: ooOoO0o / IiII . I1IiiI
 def copy_geo ( self ) :
  o00OOOoooo00 = lisp_geo ( self . geo_name )
  o00OOOoooo00 . latitude = self . latitude
  o00OOOoooo00 . lat_mins = self . lat_mins
  o00OOOoooo00 . lat_secs = self . lat_secs
  o00OOOoooo00 . longitude = self . longitude
  o00OOOoooo00 . long_mins = self . long_mins
  o00OOOoooo00 . long_secs = self . long_secs
  o00OOOoooo00 . altitude = self . altitude
  o00OOOoooo00 . radius = self . radius
  return ( o00OOOoooo00 )
  if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
  if 90 - 90: I11i
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
  if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
 def parse_geo_string ( self , geo_str ) :
  OOOooo0OooOoO = geo_str . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : geo_str = geo_str [ OOOooo0OooOoO + 1 : : ]
  if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
  if 13 - 13: II111iiii
  if 22 - 22: o0oOOo0O0Ooo
  if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
  if 12 - 12: I1ii11iIi11i / O0
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , IIiiIi = geo_str . split ( "/" )
   self . radius = int ( IIiiIi )
   if 81 - 81: OoOoOO00 + I11i % Oo0Ooo % IiII * IiII * o0oOOo0O0Ooo
   if 17 - 17: II111iiii * I1IiiI + II111iiii + I1IiiI % I11i * oO0o
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 51 - 51: I1IiiI
  iII1iiii1i = geo_str [ 0 : 4 ]
  O0OOOO = geo_str [ 4 : 8 ]
  if 35 - 35: oO0o + iII111i + I11i - I1ii11iIi11i - ooOoO0o - OOooOOo
  if 77 - 77: OoooooooOO + OoooooooOO / oO0o * o0oOOo0O0Ooo / I11i
  if 86 - 86: I1IiiI % IiII - IiII
  if 1 - 1: o0oOOo0O0Ooo + OoOoOO00 / OOooOOo % IiII
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 16 - 16: IiII . I11i * O0 + OoooooooOO
  if 37 - 37: OoO0O00 . i11iIiiIii - i11iIiiIii % I1Ii111 + II111iiii * i11iIiiIii
  if 83 - 83: OOooOOo % O0 - I11i . Ii1I % IiII
  if 45 - 45: I11i % OoO0O00
  self . latitude = int ( iII1iiii1i [ 0 ] )
  self . lat_mins = int ( iII1iiii1i [ 1 ] )
  self . lat_secs = int ( iII1iiii1i [ 2 ] )
  if ( iII1iiii1i [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 18 - 18: Ii1I / Ii1I * IiII
  if 33 - 33: ooOoO0o
  if 14 - 14: Oo0Ooo % I1Ii111 % ooOoO0o . oO0o * iIii1I11I1II1 . I1ii11iIi11i
  if 50 - 50: O0 * i11iIiiIii / iIii1I11I1II1 . I11i + i11iIiiIii
  self . longitude = int ( O0OOOO [ 0 ] )
  self . long_mins = int ( O0OOOO [ 1 ] )
  self . long_secs = int ( O0OOOO [ 2 ] )
  if ( O0OOOO [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 68 - 68: oO0o + o0oOOo0O0Ooo * iIii1I11I1II1 / i1IIi
  if 9 - 9: I11i % OoO0O00 . oO0o / I1ii11iIi11i
 def print_geo ( self ) :
  OOo0o = "N" if self . latitude < 0 else "S"
  iiII111I1 = "E" if self . longitude < 0 else "W"
  if 16 - 16: iII111i % I11i % OoOoOO00
  OooO0OO0o = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , OOo0o , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , iiII111I1 )
  if 80 - 80: OoooooooOO * i11iIiiIii % oO0o / Oo0Ooo - I1ii11iIi11i
  if ( self . no_geo_altitude ( ) == False ) :
   OooO0OO0o += "-" + str ( self . altitude )
   if 92 - 92: o0oOOo0O0Ooo % i1IIi / I1Ii111 % ooOoO0o / oO0o
   if 2 - 2: i11iIiiIii / Ii1I - i1IIi % O0
   if 12 - 12: Oo0Ooo + I1ii11iIi11i
   if 54 - 54: OoO0O00 . o0oOOo0O0Ooo / I11i
   if 95 - 95: i1IIi . I1Ii111
  if ( self . radius != 0 ) : OooO0OO0o += "/{}" . format ( self . radius )
  return ( OooO0OO0o )
  if 94 - 94: I1IiiI + Ii1I + i1IIi . iIii1I11I1II1
  if 64 - 64: O0 * OOooOOo * I1IiiI - o0oOOo0O0Ooo
 def geo_url ( self ) :
  o0oOiii11i = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  o0oOiii11i = "10" if ( o0oOiii11i == "" or o0oOiii11i . isdigit ( ) == False ) else o0oOiii11i
  OOoo0oooooO , I1iIIii = self . dms_to_decimal ( )
  I1iiiIii1 = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( OOoo0oooooO , I1iIIii , OOoo0oooooO , I1iIIii ,
  # i1IIi
  # OoOoOO00 % Ii1I + I1ii11iIi11i / I1ii11iIi11i
 o0oOiii11i )
  return ( I1iiiIii1 )
  if 26 - 26: o0oOOo0O0Ooo * I1Ii111
  if 65 - 65: I11i * iIii1I11I1II1 % OoO0O00 % I11i * O0 * i1IIi
 def print_geo_url ( self ) :
  o00OOOoooo00 = self . print_geo ( )
  if ( self . radius == 0 ) :
   I1iiiIii1 = self . geo_url ( )
   i1IIIII1 = "<a href='{}'>{}</a>" . format ( I1iiiIii1 , o00OOOoooo00 )
  else :
   I1iiiIii1 = o00OOOoooo00 . replace ( "/" , "-" )
   i1IIIII1 = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( I1iiiIii1 , o00OOOoooo00 )
   if 27 - 27: OoOoOO00 % OoooooooOO
  return ( i1IIIII1 )
  if 77 - 77: Ii1I % Oo0Ooo
  if 30 - 30: iIii1I11I1II1 * Oo0Ooo * OOooOOo * ooOoO0o
 def dms_to_decimal ( self ) :
  ii1I1 , IiI1Ii , I1IiIII1II1iI = self . latitude , self . lat_mins , self . lat_secs
  i1I1i1iiiIi = float ( abs ( ii1I1 ) )
  i1I1i1iiiIi += float ( IiI1Ii * 60 + I1IiIII1II1iI ) / 3600
  if ( ii1I1 > 0 ) : i1I1i1iiiIi = - i1I1i1iiiIi
  Iiiii1I1i = i1I1i1iiiIi
  if 24 - 24: OoO0O00
  ii1I1 , IiI1Ii , I1IiIII1II1iI = self . longitude , self . long_mins , self . long_secs
  i1I1i1iiiIi = float ( abs ( ii1I1 ) )
  i1I1i1iiiIi += float ( IiI1Ii * 60 + I1IiIII1II1iI ) / 3600
  if ( ii1I1 > 0 ) : i1I1i1iiiIi = - i1I1i1iiiIi
  OO0OOOo = i1I1i1iiiIi
  return ( ( Iiiii1I1i , OO0OOOo ) )
  if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
 def get_distance ( self , geo_point ) :
  OO0OO0 = self . dms_to_decimal ( )
  oO0OoOOOoO = geo_point . dms_to_decimal ( )
  iIIIii1 = geopy . distance . distance ( OO0OO0 , oO0OoOOOoO )
  return ( iIIIii1 . km )
  if 65 - 65: ooOoO0o * iII111i - OoOoOO00 / I11i
  if 3 - 3: i1IIi / ooOoO0o
 def point_in_circle ( self , geo_point ) :
  oOoOOo0oO00 = self . get_distance ( geo_point )
  return ( oOoOOo0oO00 <= self . radius )
  if 23 - 23: OoOoOO00
  if 54 - 54: i1IIi / I11i % O0 - Ii1I - Oo0Ooo - OoO0O00
 def encode_geo ( self ) :
  ooOOooooo0Oo = socket . htons ( LISP_AFI_LCAF )
  O0o0 = socket . htons ( 20 + 2 )
  iIi1i = 0
  if 63 - 63: o0oOOo0O0Ooo
  OOoo0oooooO = abs ( self . latitude )
  IIIOo0oo00 = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : iIi1i |= 0x40
  if 64 - 64: Ii1I / I1IiiI + ooOoO0o
  I1iIIii = abs ( self . longitude )
  ii11II1I1 = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : iIi1i |= 0x20
  if 85 - 85: IiII
  OOoO0oO0OO = 0
  if ( self . no_geo_altitude ( ) == False ) :
   OOoO0oO0OO = socket . htonl ( self . altitude )
   iIi1i |= 0x10
   if 89 - 89: iII111i + Oo0Ooo / Oo0Ooo / OoO0O00 + i11iIiiIii
  IIiiIi = socket . htons ( self . radius )
  if ( IIiiIi != 0 ) : iIi1i |= 0x06
  if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
  OoO00Oo0 = struct . pack ( "HBBBBH" , ooOOooooo0Oo , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , O0o0 )
  OoO00Oo0 += struct . pack ( "BBHBBHBBHIHHH" , iIi1i , 0 , 0 , OOoo0oooooO , IIIOo0oo00 >> 16 ,
 socket . htons ( IIIOo0oo00 & 0x0ffff ) , I1iIIii , ii11II1I1 >> 16 ,
 socket . htons ( ii11II1I1 & 0xffff ) , OOoO0oO0OO , IIiiIi , 0 , 0 )
  if 65 - 65: OoOoOO00 * I1ii11iIi11i - I11i - OOooOOo
  return ( OoO00Oo0 )
  if 13 - 13: I11i + II111iiii + I1ii11iIi11i * i11iIiiIii
  if 90 - 90: I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  O0oOO0o00OO = "BBHBBHBBHIHHH"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( lcaf_len < Ii1i1iiiIiIIiIiiii ) : return ( None )
  if 42 - 42: OOooOOo
  iIi1i , iiI11i , I1i1OO , OOoo0oooooO , IiIiII1iI1I1 , IIIOo0oo00 , I1iIIii , O0o0oOoOO0 , ii11II1I1 , OOoO0oO0OO , IIiiIi , i1IoO0oOOO , ii11IiI = struct . unpack ( O0oOO0o00OO ,
  # I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
 packet [ : Ii1i1iiiIiIIiIiiii ] )
  if 65 - 65: I1IiiI % iIii1I11I1II1
  if 52 - 52: I1IiiI
  if 19 - 19: I1IiiI
  if 17 - 17: I11i + OoooooooOO
  ii11IiI = socket . ntohs ( ii11IiI )
  if ( ii11IiI == LISP_AFI_LCAF ) : return ( None )
  if 63 - 63: IiII
  if ( iIi1i & 0x40 ) : OOoo0oooooO = - OOoo0oooooO
  self . latitude = OOoo0oooooO
  iIiiii1iIiiII = old_div ( ( ( IiIiII1iI1I1 << 16 ) | socket . ntohs ( IIIOo0oo00 ) ) , 1000 )
  self . lat_mins = old_div ( iIiiii1iIiiII , 60 )
  self . lat_secs = iIiiii1iIiiII % 60
  if 42 - 42: I1IiiI / I1IiiI - OOooOOo % OoooooooOO
  if ( iIi1i & 0x20 ) : I1iIIii = - I1iIIii
  self . longitude = I1iIIii
  II1i1Ii1iii = old_div ( ( ( O0o0oOoOO0 << 16 ) | socket . ntohs ( ii11II1I1 ) ) , 1000 )
  self . long_mins = old_div ( II1i1Ii1iii , 60 )
  self . long_secs = II1i1Ii1iii % 60
  if 11 - 11: o0oOOo0O0Ooo / Oo0Ooo
  self . altitude = socket . ntohl ( OOoO0oO0OO ) if ( iIi1i & 0x10 ) else - 1
  IIiiIi = socket . ntohs ( IIiiIi )
  self . radius = IIiiIi if ( iIi1i & 0x02 ) else IIiiIi * 1000
  if 53 - 53: I1ii11iIi11i + ooOoO0o - I1ii11iIi11i + I11i
  self . geo_name = None
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 12 - 12: iII111i / II111iiii . OoOoOO00 - OOooOOo
  if ( ii11IiI != 0 ) :
   self . rloc . afi = ii11IiI
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 23 - 23: ooOoO0o + ooOoO0o . I11i
  return ( packet )
  if 90 - 90: I1Ii111 / iIii1I11I1II1 / oO0o
  if 47 - 47: i11iIiiIii - OOooOOo / I1IiiI % o0oOOo0O0Ooo % I1IiiI % I11i
  if 26 - 26: OoOoOO00 * ooOoO0o
  if 23 - 23: Ii1I + i1IIi + IiII - O0 / OOooOOo
  if 82 - 82: I1Ii111
  if 78 - 78: I1Ii111 % oO0o * iIii1I11I1II1
class lisp_rle_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 1 - 1: i1IIi . iIii1I11I1II1
  if 2 - 2: OOooOOo % Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
 def copy_rle_node ( self ) :
  oO0oOOOO0oO0o0 = lisp_rle_node ( )
  oO0oOOOO0oO0o0 . address . copy_address ( self . address )
  oO0oOOOO0oO0o0 . level = self . level
  oO0oOOOO0oO0o0 . translated_port = self . translated_port
  oO0oOOOO0oO0o0 . rloc_name = self . rloc_name
  return ( oO0oOOOO0oO0o0 )
  if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
  if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
  if 49 - 49: iII111i + OoOoOO00
 def get_encap_keys ( self ) :
  IiO0o = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 33 - 33: ooOoO0o
  Oo0o = self . address . print_address_no_iid ( ) + ":" + IiO0o
  if 19 - 19: I1Ii111 % IiII
  try :
   Oo0Oo = lisp_crypto_keys_by_rloc_encap [ Oo0o ]
   if ( Oo0Oo [ 1 ] ) : return ( Oo0Oo [ 1 ] . encrypt_key , Oo0Oo [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
   if 16 - 16: i1IIi
   if 88 - 88: OOooOOo
   if 79 - 79: oO0o
class lisp_rle ( object ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
  if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
 def copy_rle ( self ) :
  IIii1i = lisp_rle ( self . rle_name )
  for oO0oOOOO0oO0o0 in self . rle_nodes :
   IIii1i . rle_nodes . append ( oO0oOOOO0oO0o0 . copy_rle_node ( ) )
   if 97 - 97: OoO0O00 - IiII + ooOoO0o % iIii1I11I1II1 % iII111i
  IIii1i . build_forwarding_list ( )
  return ( IIii1i )
  if 100 - 100: IiII - Ii1I * iIii1I11I1II1 . iII111i . i1IIi % Oo0Ooo
  if 11 - 11: I11i + oO0o % Ii1I
 def print_rle ( self , html , do_formatting ) :
  iIi111Ii1 = ""
  for oO0oOOOO0oO0o0 in self . rle_nodes :
   IiO0o = oO0oOOOO0oO0o0 . translated_port
   if 22 - 22: ooOoO0o
   O0OoooOoo = ""
   if ( oO0oOOOO0oO0o0 . rloc_name != None ) :
    O0OoooOoo = oO0oOOOO0oO0o0 . rloc_name
    if ( do_formatting ) : O0OoooOoo = blue ( O0OoooOoo , html )
    O0OoooOoo = "({})" . format ( O0OoooOoo )
    if 46 - 46: Oo0Ooo % i11iIiiIii * o0oOOo0O0Ooo
    if 33 - 33: oO0o * ooOoO0o * Ii1I * IiII
   Oo0o = oO0oOOOO0oO0o0 . address . print_address_no_iid ( )
   if ( oO0oOOOO0oO0o0 . address . is_local ( ) ) : Oo0o = red ( Oo0o , html )
   iIi111Ii1 += "{}{}{}, " . format ( Oo0o , "" if IiO0o == 0 else ":" + str ( IiO0o ) , O0OoooOoo )
   if 39 - 39: i1IIi
   if 79 - 79: ooOoO0o - II111iiii - oO0o
  return ( iIi111Ii1 [ 0 : - 2 ] if iIi111Ii1 != "" else "" )
  if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
  if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
 def build_forwarding_list ( self ) :
  i11IiIi1Ii1 = - 1
  for oO0oOOOO0oO0o0 in self . rle_nodes :
   if ( i11IiIi1Ii1 == - 1 ) :
    if ( oO0oOOOO0oO0o0 . address . is_local ( ) ) : i11IiIi1Ii1 = oO0oOOOO0oO0o0 . level
   else :
    if ( oO0oOOOO0oO0o0 . level > i11IiIi1Ii1 ) : break
    if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
    if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
  i11IiIi1Ii1 = 0 if i11IiIi1Ii1 == - 1 else oO0oOOOO0oO0o0 . level
  if 65 - 65: Ii1I . OoOoOO00 + O0 / iIii1I11I1II1 % Ii1I % I1Ii111
  self . rle_forwarding_list = [ ]
  for oO0oOOOO0oO0o0 in self . rle_nodes :
   if ( oO0oOOOO0oO0o0 . level == i11IiIi1Ii1 or ( i11IiIi1Ii1 == 0 and
 oO0oOOOO0oO0o0 . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and oO0oOOOO0oO0o0 . address . is_local ( ) ) :
     Oo0o = oO0oOOOO0oO0o0 . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( Oo0o ) )
     continue
     if 31 - 31: o0oOOo0O0Ooo - Oo0Ooo
    self . rle_forwarding_list . append ( oO0oOOOO0oO0o0 )
    if 15 - 15: O0 + OOooOOo
    if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
    if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
    if 87 - 87: i1IIi / OoooooooOO
    if 68 - 68: I1Ii111 / iIii1I11I1II1
class lisp_json ( object ) :
 def __init__ ( self , name , string , encrypted = False , ms_encrypt = False ) :
  self . json_name = name
  self . json_encrypted = False
  try :
   json . loads ( string )
  except :
   lprint ( "Invalid JSON string: '{}'" . format ( string ) )
   string = '{ "?" : "?" }'
   if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
  self . json_string = string
  if 40 - 40: i11iIiiIii + OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo * OoO0O00
  if 88 - 88: Oo0Ooo + oO0o + iII111i
  if 51 - 51: i1IIi + i11iIiiIii * I11i / iII111i + OoooooooOO
  if 89 - 89: i11iIiiIii - I1Ii111 - O0 % iIii1I11I1II1 / IiII - O0
  if 63 - 63: OOooOOo
  if 23 - 23: Oo0Ooo / i1IIi - OOooOOo / Oo0Ooo
  if 16 - 16: o0oOOo0O0Ooo - iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i + IiII
  if 73 - 73: OOooOOo % I1Ii111 + OoooooooOO / I1ii11iIi11i * oO0o % oO0o
  if 25 - 25: I1Ii111
  if ( len ( lisp_ms_json_keys ) != 0 ) :
   if ( ms_encrypt == False ) : return
   self . json_key_id = list ( lisp_ms_json_keys . keys ( ) ) [ 0 ]
   self . json_key = lisp_ms_json_keys [ self . json_key_id ]
   self . encrypt_json ( )
   if 93 - 93: OoO0O00
   if 62 - 62: Oo0Ooo . iII111i
  if ( lisp_log_id == "lig" and encrypted ) :
   IIIOoo = os . getenv ( "LISP_JSON_KEY" )
   if ( IIIOoo != None ) :
    OOOooo0OooOoO = - 1
    if ( IIIOoo [ 0 ] == "[" and "]" in IIIOoo ) :
     OOOooo0OooOoO = IIIOoo . find ( "]" )
     self . json_key_id = int ( IIIOoo [ 1 : OOOooo0OooOoO ] )
     if 15 - 15: i11iIiiIii * I11i + oO0o
    self . json_key = IIIOoo [ OOOooo0OooOoO + 1 : : ]
    if 67 - 67: IiII . OoO0O00
    self . decrypt_json ( )
    if 59 - 59: oO0o * o0oOOo0O0Ooo
    if 76 - 76: I1IiiI
    if 94 - 94: OoooooooOO * I1ii11iIi11i
    if 28 - 28: II111iiii / II111iiii / II111iiii
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 70 - 70: OoO0O00 + O0 * OoO0O00
  if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
 def delete ( self ) :
  if ( self . json_name in lisp_json_list ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
   if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
   if 97 - 97: Ii1I
 def print_json ( self , html ) :
  oo0OOOo00o = self . json_string
  ii111i1iI = "***"
  if ( html ) : ii111i1iI = red ( ii111i1iI , html )
  IIiIIi = ii111i1iI + self . json_string + ii111i1iI
  if ( self . valid_json ( ) ) : return ( oo0OOOo00o )
  return ( IIiIIi )
  if 2 - 2: OoOoOO00 - iIii1I11I1II1 * I1Ii111 % II111iiii - Oo0Ooo . OoooooooOO
  if 47 - 47: I1Ii111 + oO0o - Ii1I % OoO0O00 - I1Ii111 / i11iIiiIii
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 27 - 27: i11iIiiIii . OoO0O00 + Ii1I
  return ( True )
  if 47 - 47: I1Ii111 . iIii1I11I1II1 + i11iIiiIii
  if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
 def encrypt_json ( self ) :
  OoooooOoOOO = self . json_key . zfill ( 32 )
  OoOooO = "0" * 8
  if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
  IIOO00 = json . loads ( self . json_string )
  for IIIOoo in IIOO00 :
   iiIiII11i1 = IIOO00 [ IIIOoo ]
   if ( type ( iiIiII11i1 ) != str ) : iiIiII11i1 = str ( iiIiII11i1 )
   iiIiII11i1 = chacha . ChaCha ( OoooooOoOOO , OoOooO ) . encrypt ( iiIiII11i1 )
   IIOO00 [ IIIOoo ] = binascii . hexlify ( iiIiII11i1 )
   if 14 - 14: iII111i . iII111i . I11i % I11i * oO0o
  self . json_string = json . dumps ( IIOO00 )
  self . json_encrypted = True
  if 77 - 77: I1ii11iIi11i
  if 5 - 5: II111iiii . I1ii11iIi11i
 def decrypt_json ( self ) :
  OoooooOoOOO = self . json_key . zfill ( 32 )
  OoOooO = "0" * 8
  if 96 - 96: o0oOOo0O0Ooo + OoooooooOO - iII111i * O0
  IIOO00 = json . loads ( self . json_string )
  for IIIOoo in IIOO00 :
   iiIiII11i1 = binascii . unhexlify ( IIOO00 [ IIIOoo ] )
   IIOO00 [ IIIOoo ] = chacha . ChaCha ( OoooooOoOOO , OoOooO ) . encrypt ( iiIiII11i1 )
   if 12 - 12: OoO0O00 % i11iIiiIii - iII111i
  try :
   self . json_string = json . dumps ( IIOO00 )
   self . json_encrypted = False
  except :
   pass
   if 61 - 61: IiII / oO0o . I1Ii111 - IiII * IiII - iII111i
   if 49 - 49: Ii1I
   if 91 - 91: Ii1I / ooOoO0o % iII111i
   if 75 - 75: i1IIi
   if 23 - 23: oO0o + II111iiii % OoOoOO00 / O0 / iIii1I11I1II1 / I1Ii111
   if 47 - 47: I1IiiI / I11i + iIii1I11I1II1 * Oo0Ooo / I1ii11iIi11i
   if 8 - 8: ooOoO0o . O0 / OoO0O00
class lisp_stats ( object ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
  if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 72 - 72: I1ii11iIi11i
  if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  Ii1i1 = time . time ( ) - self . last_increment
  return ( Ii1i1 <= 1 )
  if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
  if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  Ii1i1 = time . time ( ) - self . last_increment
  return ( Ii1i1 <= 60 )
  if 89 - 89: Oo0Ooo % IiII
  if 36 - 36: IiII % OoOoOO00 % I1ii11iIi11i
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 9 - 9: Ii1I . OoooooooOO / ooOoO0o + i1IIi
  return ( c1 , c2 )
  if 90 - 90: oO0o - OoOoOO00 % ooOoO0o
  if 83 - 83: OOooOOo - I1ii11iIi11i + OoO0O00
 def normalize ( self , count ) :
  count = str ( count )
  o00O0oOo = len ( count )
  if ( o00O0oOo > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 64 - 64: Ii1I - iIii1I11I1II1 * I1IiiI % iII111i * II111iiii / OoO0O00
  if ( o00O0oOo > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 16 - 16: iIii1I11I1II1
  if ( o00O0oOo > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 39 - 39: oO0o / OoO0O00 - Ii1I + ooOoO0o + OOooOOo
  return ( count )
  if 84 - 84: iII111i / Oo0Ooo
  if 21 - 21: OoO0O00 . I1IiiI - OoO0O00
 def get_stats ( self , summary , html ) :
  ooOOO0 = self . last_rate_check
  O0O0oO0o0 = self . last_packet_count
  Oo0OOOooO0 = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 40 - 40: I1Ii111 - II111iiii . OOooOOo + OoO0O00 - I1IiiI * OoooooooOO
  ii11I11Iii = self . last_rate_check - ooOOO0
  if ( ii11I11Iii == 0 ) :
   IIIiI1I1i1i1III = 0
   O0O0OooOooo = 0
  else :
   IIIiI1I1i1i1III = int ( old_div ( ( self . packet_count - O0O0oO0o0 ) ,
 ii11I11Iii ) )
   O0O0OooOooo = old_div ( ( self . byte_count - Oo0OOOooO0 ) , ii11I11Iii )
   O0O0OooOooo = old_div ( ( O0O0OooOooo * 8 ) , 1000000 )
   O0O0OooOooo = round ( O0O0OooOooo , 2 )
   if 70 - 70: Oo0Ooo * oO0o + I11i . oO0o
   if 10 - 10: iII111i + i1IIi . I11i % ooOoO0o / ooOoO0o
   if 86 - 86: Oo0Ooo
   if 7 - 7: iIii1I11I1II1
   if 86 - 86: IiII + iII111i * II111iiii - IiII - o0oOOo0O0Ooo
  i1oo0O0ooo00 = self . normalize ( self . packet_count )
  iI1Iii1 = self . normalize ( self . byte_count )
  if 24 - 24: i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1 . I1IiiI
  if 81 - 81: OoOoOO00 * OoOoOO00 + OOooOOo . I11i - oO0o
  if 85 - 85: O0 * I1IiiI . Oo0Ooo - IiII
  if 84 - 84: I1Ii111 . iIii1I11I1II1 . O0 * I1ii11iIi11i
  if 59 - 59: i1IIi . o0oOOo0O0Ooo . Oo0Ooo * I1Ii111 + OoooooooOO
  if ( summary ) :
   I111Iii1I11Ii = "<br>" if html else ""
   i1oo0O0ooo00 , iI1Iii1 = self . stat_colors ( i1oo0O0ooo00 , iI1Iii1 , html )
   Ii1i1I111I = "packet-count: {}{}byte-count: {}" . format ( i1oo0O0ooo00 , I111Iii1I11Ii , iI1Iii1 )
   OOo = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( IIIiI1I1i1i1III , O0O0OooOooo )
   if 18 - 18: O0
   if ( html != "" ) : OOo = lisp_span ( Ii1i1I111I , OOo )
  else :
   OoOoo0o0OO = str ( IIIiI1I1i1i1III )
   iiiiIIiI = str ( O0O0OooOooo )
   if ( html ) :
    i1oo0O0ooo00 = lisp_print_cour ( i1oo0O0ooo00 )
    OoOoo0o0OO = lisp_print_cour ( OoOoo0o0OO )
    iI1Iii1 = lisp_print_cour ( iI1Iii1 )
    iiiiIIiI = lisp_print_cour ( iiiiIIiI )
    if 56 - 56: ooOoO0o
   I111Iii1I11Ii = "<br>" if html else ", "
   if 94 - 94: OoOoOO00
   OOo = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( i1oo0O0ooo00 , I111Iii1I11Ii , OoOoo0o0OO , I111Iii1I11Ii , iI1Iii1 , I111Iii1I11Ii ,
   # I1IiiI
 iiiiIIiI )
   if 97 - 97: OoooooooOO + OoooooooOO * IiII . OoOoOO00 * I11i
  return ( OOo )
  if 44 - 44: OoooooooOO + OoOoOO00 + IiII / iII111i
  if 75 - 75: i11iIiiIii
  if 27 - 27: I11i - IiII - I1Ii111
  if 90 - 90: OoO0O00 . oO0o * O0 / I11i % O0 + I1Ii111
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  if 84 - 84: Ii1I
  if 92 - 92: I11i
  if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
if 82 - 82: O0 * ooOoO0o * iIii1I11I1II1 . i1IIi
if 47 - 47: I11i * I11i . OoOoOO00
if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
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
  if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
  if ( recurse == False ) : return
  if 33 - 33: iIii1I11I1II1 . I11i
  if 63 - 63: oO0o - iII111i
  if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
  if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
  if 33 - 33: oO0o
  if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
  iiI1iII = lisp_get_default_route_next_hops ( )
  if ( iiI1iII == [ ] or len ( iiI1iII ) == 1 ) : return
  if 23 - 23: o0oOOo0O0Ooo / iII111i
  self . rloc_next_hop = iiI1iII [ 0 ]
  oo0o0o0o0O = self
  for o00o0O0O0oO0o in iiI1iII [ 1 : : ] :
   o000oooOOO0OO = lisp_rloc ( False )
   o000oooOOO0OO = copy . deepcopy ( self )
   o000oooOOO0OO . rloc_next_hop = o00o0O0O0oO0o
   oo0o0o0o0O . next_rloc = o000oooOOO0OO
   oo0o0o0o0O = o000oooOOO0OO
   if 38 - 38: i1IIi * OOooOOo . IiII + i11iIiiIii * OoOoOO00
   if 28 - 28: ooOoO0o * I1IiiI . OoO0O00 / I1Ii111
   if 47 - 47: I11i . iII111i * OoOoOO00 % OoooooooOO
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 59 - 59: OoooooooOO + I1ii11iIi11i - I11i / I1IiiI * oO0o
  if 90 - 90: I1Ii111 + i1IIi * I1Ii111 / I11i * Oo0Ooo
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 27 - 27: OoooooooOO
  if 42 - 42: OoO0O00 + OoOoOO00
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 52 - 52: iII111i * OoOoOO00
  if 80 - 80: I1Ii111 / IiII * o0oOOo0O0Ooo - OoOoOO00 / iIii1I11I1II1
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 38 - 38: II111iiii / I11i + IiII % OoooooooOO
  if 27 - 27: OoOoOO00 * OoO0O00 * OOooOOo % I1IiiI * o0oOOo0O0Ooo + I1ii11iIi11i
  if 73 - 73: i1IIi
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
  if 52 - 52: IiII / i11iIiiIii * O0
  if 67 - 67: OOooOOo / I11i - I1Ii111 % i11iIiiIii
 def print_rloc ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , i1 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 3 - 3: oO0o + iII111i + OOooOOo
  if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  i1Ii1iiI = self . rloc_name
  if ( cour ) : i1Ii1iiI = lisp_print_cour ( i1Ii1iiI )
  return ( 'rloc-name: {}' . format ( blue ( i1Ii1iiI , cour ) ) )
  if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
  if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  IiO0o = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 84 - 84: i1IIi
  if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
  if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
  if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
  IIIi1iI1 = self . rloc
  if ( IIIi1iI1 . is_null ( ) == False ) :
   o0O00Oo = lisp_get_nat_info ( IIIi1iI1 , self . rloc_name )
   if ( o0O00Oo ) :
    IiO0o = o0O00Oo . port
    oO00O = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    Oo0o = IIIi1iI1 . print_address_no_iid ( )
    iiIIii = red ( Oo0o , False )
    ooO00 = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 33 - 33: I1IiiI
    if 41 - 41: OoOoOO00 * i1IIi
    if 94 - 94: I11i
    if 28 - 28: OOooOOo
    if 82 - 82: II111iiii
    if 66 - 66: iII111i % I1Ii111 * oO0o
    if ( o0O00Oo . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( iiIIii , IiO0o , ooO00 ) )
     if 81 - 81: i11iIiiIii - O0 . iIii1I11I1II1 - I11i + iIii1I11I1II1
     if 50 - 50: Oo0Ooo . OoO0O00 + i11iIiiIii / i11iIiiIii
     o0O00Oo = None if ( o0O00Oo == oO00O ) else oO00O
     if ( o0O00Oo and o0O00Oo . timed_out ( ) ) :
      IiO0o = o0O00Oo . port
      iiIIii = red ( o0O00Oo . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( iiIIii , IiO0o ,
      # oO0o % OoOoOO00
 ooO00 ) )
      o0O00Oo = None
      if 77 - 77: II111iiii + i1IIi + I1IiiI
      if 75 - 75: OoooooooOO . I11i - OoOoOO00
      if 93 - 93: OoOoOO00 . I1Ii111 % I1ii11iIi11i
      if 58 - 58: OoooooooOO . i1IIi . Oo0Ooo - o0oOOo0O0Ooo / oO0o * I1Ii111
      if 6 - 6: oO0o - OoO0O00
      if 44 - 44: Oo0Ooo + I1ii11iIi11i % Oo0Ooo / I11i
      if 57 - 57: Oo0Ooo + Ii1I * OoooooooOO
    if ( o0O00Oo ) :
     if ( o0O00Oo . address != Oo0o ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( iiIIii , red ( o0O00Oo . address , False ) ) )
      if 30 - 30: O0
      self . rloc . store_address ( o0O00Oo . address )
      if 70 - 70: oO0o
     iiIIii = red ( o0O00Oo . address , False )
     IiO0o = o0O00Oo . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( iiIIii , IiO0o , ooO00 ) )
     if 89 - 89: O0
     self . store_translated_rloc ( IIIi1iI1 , IiO0o )
     if 3 - 3: iII111i - O0 / I11i
     if 46 - 46: I1IiiI . OoooooooOO / iIii1I11I1II1 - ooOoO0o * OOooOOo
     if 55 - 55: o0oOOo0O0Ooo + iIii1I11I1II1 / I11i
     if 97 - 97: i11iIiiIii
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 71 - 71: oO0o + Oo0Ooo
  if 7 - 7: OoOoOO00 / I1ii11iIi11i * i1IIi
  if 87 - 87: OoooooooOO * IiII - I1IiiI % I1ii11iIi11i % iIii1I11I1II1
  if 28 - 28: I1Ii111 / o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo . Ii1I / I11i
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for oO0oOOOO0oO0o0 in self . rle . rle_nodes :
    i1Ii1iiI = oO0oOOOO0oO0o0 . rloc_name
    o0O00Oo = lisp_get_nat_info ( oO0oOOOO0oO0o0 . address , i1Ii1iiI )
    if ( o0O00Oo == None ) : continue
    if 43 - 43: I1Ii111 . I1IiiI
    IiO0o = o0O00Oo . port
    IIi1Ii = i1Ii1iiI
    if ( IIi1Ii ) : IIi1Ii = blue ( i1Ii1iiI , False )
    if 16 - 16: i11iIiiIii * Oo0Ooo * Ii1I / OoOoOO00 / OOooOOo
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( IiO0o ,
    # ooOoO0o
 oO0oOOOO0oO0o0 . address . print_address_no_iid ( ) , IIi1Ii ) )
    oO0oOOOO0oO0o0 . translated_port = IiO0o
    if 96 - 96: OoO0O00 . o0oOOo0O0Ooo - I1IiiI / oO0o
    if 90 - 90: I1Ii111 / i1IIi + IiII . II111iiii
    if 42 - 42: I1ii11iIi11i . Oo0Ooo * I1IiiI / Oo0Ooo
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 83 - 83: i11iIiiIii / OoOoOO00
  if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
  if 43 - 43: II111iiii - OoooooooOO
  if 11 - 11: I1IiiI
  O00ooO0Oo = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 63 - 63: I1Ii111 + iIii1I11I1II1 / Oo0Ooo
  if ( rloc_record . keys != None and O00ooO0Oo ) :
   IIIOoo = rloc_record . keys [ 1 ]
   if ( IIIOoo != None ) :
    Oo0o = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( IiO0o )
    if 6 - 6: ooOoO0o + I1ii11iIi11i * I1IiiI / OoO0O00 / OoooooooOO
    IIIOoo . add_key_by_rloc ( Oo0o , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( Oo0o , False ) ) )
    if 23 - 23: ooOoO0o
    if 99 - 99: OOooOOo % I11i
    if 56 - 56: ooOoO0o
  return ( IiO0o )
  if 5 - 5: I1Ii111 + I1Ii111 * i11iIiiIii . OoO0O00
  if 50 - 50: iII111i - I1ii11iIi11i . Ii1I + i11iIiiIii + IiII * I1Ii111
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 51 - 51: iII111i * OoO0O00 * o0oOOo0O0Ooo . i1IIi
  if 54 - 54: Ii1I + i11iIiiIii - II111iiii * Oo0Ooo
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 20 - 20: ooOoO0o / o0oOOo0O0Ooo - i1IIi + IiII
  if 25 - 25: OoOoOO00 / ooOoO0o
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 73 - 73: iII111i
  return ( True )
  if 34 - 34: o0oOOo0O0Ooo * I1ii11iIi11i
  if 16 - 16: i1IIi
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 84 - 84: i11iIiiIii
  if 92 - 92: o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
  if 33 - 33: I1IiiI + O0 - I11i
 def print_state_change ( self , new_state ) :
  O0oo0ooOO00O0 = self . print_state ( )
  i1IIIII1 = "{} -> {}" . format ( O0oo0ooOO00O0 , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   i1IIIII1 = bold ( i1IIIII1 , False )
   if 9 - 9: IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
  return ( i1IIIII1 )
  if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
  if 38 - 38: O0 % I1ii11iIi11i + O0
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 37 - 37: Oo0Ooo / I1IiiI
  if 23 - 23: II111iiii / iII111i
 def print_recent_rloc_probe_rtts ( self ) :
  Oo000oo0o = str ( self . recent_rloc_probe_rtts )
  Oo000oo0o = Oo000oo0o . replace ( "-1" , "?" )
  return ( Oo000oo0o )
  if 14 - 14: Oo0Ooo % IiII + Oo0Ooo
  if 59 - 59: OoOoOO00 + O0 / I1IiiI % O0 / OoooooooOO * Ii1I
 def compute_rloc_probe_rtt ( self ) :
  oo0o0o0o0O = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  Ii1iI11I1 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ oo0o0o0o0O ] + Ii1iI11I1 [ 0 : - 1 ]
  if 85 - 85: OoOoOO00 / oO0o + II111iiii - iII111i - oO0o
  if 91 - 91: OoooooooOO . OOooOOo * iIii1I11I1II1 % IiII
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 31 - 31: Ii1I - i11iIiiIii
  if 47 - 47: IiII / o0oOOo0O0Ooo - IiII . I11i - I1Ii111 * o0oOOo0O0Ooo
 def print_recent_rloc_probe_hops ( self ) :
  oOOo0 = str ( self . recent_rloc_probe_hops )
  return ( oOOo0 )
  if 95 - 95: OOooOOo / OoOoOO00 + I1ii11iIi11i
  if 86 - 86: O0 / Ii1I . OoooooooOO . O0
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 87 - 87: Ii1I + o0oOOo0O0Ooo + OoooooooOO . Ii1I
  if ( from_ttl < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   OOOoo0 = "!"
  else :
   OOOoo0 = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 11 - 11: I11i - OoooooooOO
   if 73 - 73: Oo0Ooo % O0 . OOooOOo + O0
  oo0o0o0o0O = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + OOOoo0
  Ii1iI11I1 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ oo0o0o0o0O ] + Ii1iI11I1 [ 0 : - 1 ]
  if 84 - 84: Ii1I
  if 22 - 22: OoOoOO00
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  ooo0OOoO = lisp_decode_telemetry ( json_telemetry )
  if 28 - 28: OOooOOo + OoO0O00 * Ii1I * O0 / I1IiiI
  OOO0OOO = round ( float ( ooo0OOoO [ "etr-in" ] ) - float ( ooo0OOoO [ "itr-out" ] ) , 3 )
  OO0oO0Oo0O0 = round ( float ( ooo0OOoO [ "itr-in" ] ) - float ( ooo0OOoO [ "etr-out" ] ) , 3 )
  if 49 - 49: I1Ii111
  oo0o0o0o0O = self . rloc_probe_latency
  self . rloc_probe_latency = str ( OOO0OOO ) + "/" + str ( OO0oO0Oo0O0 )
  Ii1iI11I1 = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ oo0o0o0o0O ] + Ii1iI11I1 [ 0 : - 1 ]
  if 92 - 92: ooOoO0o
  if 82 - 82: ooOoO0o
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 80 - 80: I1Ii111 / I11i - Oo0Ooo / IiII % O0
  if 67 - 67: i11iIiiIii / I11i - iII111i - OOooOOo . II111iiii
 def print_recent_rloc_probe_latencies ( self ) :
  I1IiIiIIIIiI = str ( self . recent_rloc_probe_latencies )
  return ( I1IiIiIIIIiI )
  if 8 - 8: I1ii11iIi11i
  if 50 - 50: o0oOOo0O0Ooo - O0 - II111iiii + OOooOOo - OoOoOO00 + OoO0O00
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  IIIi1iI1 = self
  while ( True ) :
   if ( IIIi1iI1 . last_rloc_probe_nonce == nonce ) : break
   IIIi1iI1 = IIIi1iI1 . next_rloc
   if ( IIIi1iI1 == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 33 - 33: o0oOOo0O0Ooo % OoOoOO00 + iII111i
    return
    if 54 - 54: OoO0O00
    if 18 - 18: I1Ii111 - Oo0Ooo
    if 66 - 66: iII111i - IiII . I1Ii111
    if 29 - 29: I1Ii111 - Ii1I + O0 - oO0o - O0
    if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
    if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
  IIIi1iI1 . last_rloc_probe_reply = ts
  IIIi1iI1 . compute_rloc_probe_rtt ( )
  i11iiIiI1IIii = IIIi1iI1 . print_state_change ( "up" )
  if ( IIIi1iI1 . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( IIIi1iI1 . rloc , True )
   IIIi1iI1 . state = LISP_RLOC_UP_STATE
   IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
   I111I1iI1 = lisp_map_cache . lookup_cache ( eid , True )
   if ( I111I1iI1 ) : lisp_write_ipc_map_cache ( True , I111I1iI1 )
   if 90 - 90: OoOoOO00 % OoO0O00 . I1IiiI * oO0o
   if 17 - 17: O0 - i1IIi
   if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
   if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
   if 17 - 17: Ii1I * i1IIi % OoO0O00
  IIIi1iI1 . store_rloc_probe_hops ( hc , ttl )
  if 12 - 12: I1ii11iIi11i
  if 86 - 86: iIii1I11I1II1 % iII111i
  if 80 - 80: Oo0Ooo
  if 37 - 37: i11iIiiIii - I1Ii111
  if ( jt ) : IIIi1iI1 . store_rloc_probe_latencies ( jt )
  if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
  iII11 = bold ( "RLOC-probe reply" , False )
  Oo0o = IIIi1iI1 . rloc . print_address_no_iid ( )
  OooIIIii = bold ( str ( IIIi1iI1 . print_rloc_probe_rtt ( ) ) , False )
  IiIiIII11i1i = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 45 - 45: I1ii11iIi11i . I1Ii111 . i1IIi * OOooOOo
  o00o0O0O0oO0o = ""
  if ( IIIi1iI1 . rloc_next_hop != None ) :
   iiIi , O0iII11II1I1 = IIIi1iI1 . rloc_next_hop
   o00o0O0O0oO0o = ", nh {}({})" . format ( O0iII11II1I1 , iiIi )
   if 95 - 95: O0 . IiII % I1IiiI
   if 18 - 18: i11iIiiIii / ooOoO0o
  OOoo0oooooO = bold ( IIIi1iI1 . print_rloc_probe_latency ( ) , False )
  OOoo0oooooO = ", latency {}" . format ( OOoo0oooooO ) if jt else ""
  if 63 - 63: i11iIiiIii . i1IIi
  I1i = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( iII11 , red ( Oo0o , False ) , IiIiIII11i1i , I1i ,
  # i11iIiiIii
 i11iiIiI1IIii , OooIIIii , o00o0O0O0oO0o , str ( hc ) + "/" + str ( ttl ) , OOoo0oooooO ) )
  if 59 - 59: o0oOOo0O0Ooo % iIii1I11I1II1
  if ( IIIi1iI1 . rloc_next_hop == None ) : return
  if 55 - 55: i11iIiiIii / OoOoOO00
  if 31 - 31: i1IIi - I1IiiI . I1IiiI * Ii1I
  if 80 - 80: OoOoOO00
  if 36 - 36: I11i - ooOoO0o - ooOoO0o . I1ii11iIi11i / II111iiii % OOooOOo
  IIIi1iI1 = None
  IiI1 = None
  while ( True ) :
   IIIi1iI1 = self if IIIi1iI1 == None else IIIi1iI1 . next_rloc
   if ( IIIi1iI1 == None ) : break
   if ( IIIi1iI1 . up_state ( ) == False ) : continue
   if ( IIIi1iI1 . rloc_probe_rtt == - 1 ) : continue
   if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
   if ( IiI1 == None ) : IiI1 = IIIi1iI1
   if ( IIIi1iI1 . rloc_probe_rtt < IiI1 . rloc_probe_rtt ) : IiI1 = IIIi1iI1
   if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
   if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
  if ( IiI1 != None ) :
   iiIi , O0iII11II1I1 = IiI1 . rloc_next_hop
   o00o0O0O0oO0o = bold ( "nh {}({})" . format ( O0iII11II1I1 , iiIi ) , False )
   lprint ( "    Install host-route via best {}" . format ( o00o0O0O0oO0o ) )
   lisp_install_host_route ( Oo0o , None , False )
   lisp_install_host_route ( Oo0o , O0iII11II1I1 , True )
   if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
   if 19 - 19: i11iIiiIii
   if 20 - 20: i11iIiiIii . II111iiii - I1ii11iIi11i / ooOoO0o % i11iIiiIii
 def add_to_rloc_probe_list ( self , eid , group ) :
  Oo0o = self . rloc . print_address_no_iid ( )
  IiO0o = self . translated_port
  if ( IiO0o != 0 ) : Oo0o += ":" + str ( IiO0o )
  if 35 - 35: Oo0Ooo - I1ii11iIi11i . Oo0Ooo
  if ( Oo0o not in lisp_rloc_probe_list ) :
   lisp_rloc_probe_list [ Oo0o ] = [ ]
   if 13 - 13: II111iiii / OoOoOO00 * iII111i % O0 % I1ii11iIi11i * i11iIiiIii
   if 92 - 92: i11iIiiIii + OoO0O00
  if ( group . is_null ( ) ) : group . instance_id = 0
  for OOoooo , I1i , o0O0Ooo in lisp_rloc_probe_list [ Oo0o ] :
   if ( I1i . is_exact_match ( eid ) and o0O0Ooo . is_exact_match ( group ) ) :
    if ( OOoooo == self ) :
     if ( lisp_rloc_probe_list [ Oo0o ] == [ ] ) :
      lisp_rloc_probe_list . pop ( Oo0o )
      if 94 - 94: I1ii11iIi11i + OoO0O00 . II111iiii + oO0o . II111iiii
     return
     if 96 - 96: i11iIiiIii
    lisp_rloc_probe_list [ Oo0o ] . remove ( [ OOoooo , I1i , o0O0Ooo ] )
    break
    if 66 - 66: ooOoO0o * iII111i - iII111i - O0 . o0oOOo0O0Ooo
    if 23 - 23: iIii1I11I1II1 / I11i % OoOoOO00 . OoO0O00
  lisp_rloc_probe_list [ Oo0o ] . append ( [ self , eid , group ] )
  if 90 - 90: iIii1I11I1II1 - OOooOOo . Ii1I % OoO0O00
  if 89 - 89: i11iIiiIii
  if 86 - 86: Oo0Ooo % iIii1I11I1II1 . II111iiii / I11i % OoO0O00 % OoO0O00
  if 40 - 40: o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo * i1IIi
  if 94 - 94: oO0o - II111iiii + OoOoOO00
  IIIi1iI1 = lisp_rloc_probe_list [ Oo0o ] [ 0 ] [ 0 ]
  if ( IIIi1iI1 . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 90 - 90: Oo0Ooo + Oo0Ooo + I1Ii111
   if 81 - 81: i1IIi % iIii1I11I1II1 % Ii1I * ooOoO0o % i1IIi * I1IiiI
   if 15 - 15: ooOoO0o
 def delete_from_rloc_probe_list ( self , eid , group ) :
  Oo0o = self . rloc . print_address_no_iid ( )
  IiO0o = self . translated_port
  if ( IiO0o != 0 ) : Oo0o += ":" + str ( IiO0o )
  if ( Oo0o not in lisp_rloc_probe_list ) : return
  if 26 - 26: IiII % ooOoO0o / OOooOOo
  iiIIioOOooOoOO = [ ]
  for oO00Oo in lisp_rloc_probe_list [ Oo0o ] :
   if ( oO00Oo [ 0 ] != self ) : continue
   if ( oO00Oo [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( oO00Oo [ 2 ] . is_exact_match ( group ) == False ) : continue
   iiIIioOOooOoOO = oO00Oo
   break
   if 23 - 23: OoOoOO00 / i11iIiiIii % OoOoOO00
  if ( iiIIioOOooOoOO == [ ] ) : return
  if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
  try :
   lisp_rloc_probe_list [ Oo0o ] . remove ( iiIIioOOooOoOO )
   if ( lisp_rloc_probe_list [ Oo0o ] == [ ] ) :
    lisp_rloc_probe_list . pop ( Oo0o )
    if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
  except :
   return
   if 57 - 57: OoooooooOO . iIii1I11I1II1 % iII111i % Oo0Ooo
   if 92 - 92: I1Ii111 - Ii1I + I1Ii111
   if 8 - 8: Oo0Ooo . iII111i / i11iIiiIii + iIii1I11I1II1 - OoOoOO00
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  OoiIIIiIi1I1i = ""
  IIIi1iI1 = self
  while ( True ) :
   iiooo0 = IIIi1iI1 . last_rloc_probe
   if ( iiooo0 == None ) : iiooo0 = 0
   OooOo00 = IIIi1iI1 . last_rloc_probe_reply
   if ( OooOo00 == None ) : OooOo00 = 0
   OooIIIii = IIIi1iI1 . print_rloc_probe_rtt ( )
   I1iiIi111I = space ( 4 )
   if 13 - 13: IiII
   if ( IIIi1iI1 . rloc_next_hop == None ) :
    OoiIIIiIi1I1i += "RLOC-Probing:\n"
   else :
    iiIi , O0iII11II1I1 = IIIi1iI1 . rloc_next_hop
    OoiIIIiIi1I1i += "RLOC-Probing for nh {}({}):\n" . format ( O0iII11II1I1 , iiIi )
    if 86 - 86: OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / Ii1I - II111iiii
    if 5 - 5: I1ii11iIi11i / Oo0Ooo
   OoiIIIiIi1I1i += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( I1iiIi111I , lisp_print_elapsed ( iiooo0 ) ,
   # OOooOOo . i1IIi . IiII
 I1iiIi111I , lisp_print_elapsed ( OooOo00 ) , OooIIIii )
   if 78 - 78: OoooooooOO * I11i / OOooOOo + oO0o . I1Ii111 * iII111i
   if ( trailing_linefeed ) : OoiIIIiIi1I1i += "\n"
   if 98 - 98: i1IIi
   IIIi1iI1 = IIIi1iI1 . next_rloc
   if ( IIIi1iI1 == None ) : break
   OoiIIIiIi1I1i += "\n"
   if 28 - 28: Oo0Ooo . I1Ii111 . iIii1I11I1II1 + I1IiiI . II111iiii * I1ii11iIi11i
  return ( OoiIIIiIi1I1i )
  if 26 - 26: i1IIi / i11iIiiIii * II111iiii
  if 11 - 11: Oo0Ooo % i1IIi
 def get_encap_keys ( self ) :
  IiO0o = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
  Oo0o = self . rloc . print_address_no_iid ( ) + ":" + IiO0o
  if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
  try :
   Oo0Oo = lisp_crypto_keys_by_rloc_encap [ Oo0o ]
   if ( Oo0Oo [ 1 ] ) : return ( Oo0Oo [ 1 ] . encrypt_key , Oo0Oo [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
   if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
   if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
 def rloc_recent_rekey ( self ) :
  IiO0o = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 8 - 8: OoooooooOO
  Oo0o = self . rloc . print_address_no_iid ( ) + ":" + IiO0o
  if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
  try :
   IIIOoo = lisp_crypto_keys_by_rloc_encap [ Oo0o ] [ 1 ]
   if ( IIIOoo == None ) : return ( False )
   if ( IIIOoo . last_rekey == None ) : return ( True )
   return ( time . time ( ) - IIIOoo . last_rekey < 1 )
  except :
   return ( False )
   if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
   if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
   if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
   if 76 - 76: OOooOOo % iII111i
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
  if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
  if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
 def print_mapping ( self , eid_indent , rloc_indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  iiI = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 81 - 81: iII111i % OOooOOo * oO0o
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , iiI , i1 ,
 len ( self . rloc_set ) ) )
  for IIIi1iI1 in self . rloc_set : IIIi1iI1 . print_rloc ( rloc_indent )
  if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
  if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
  if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
 def print_ttl ( self ) :
  IiIIi = self . map_cache_ttl
  if ( IiIIi == None ) : return ( "forever" )
  if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
  if ( IiIIi >= 3600 ) :
   if ( ( IiIIi % 3600 ) == 0 ) :
    IiIIi = str ( old_div ( IiIIi , 3600 ) ) + " hours"
   else :
    IiIIi = str ( IiIIi * 60 ) + " mins"
    if 15 - 15: OOooOOo - OOooOOo - OoooooooOO * OoO0O00
  elif ( IiIIi >= 60 ) :
   if ( ( IiIIi % 60 ) == 0 ) :
    IiIIi = str ( old_div ( IiIIi , 60 ) ) + " mins"
   else :
    IiIIi = str ( IiIIi ) + " secs"
    if 12 - 12: II111iiii * I1Ii111 / I1Ii111 * oO0o * Oo0Ooo
  else :
   IiIIi = str ( IiIIi ) + " secs"
   if 17 - 17: OoOoOO00 % I1Ii111 / iII111i * I1Ii111
  return ( IiIIi )
  if 96 - 96: Oo0Ooo % o0oOOo0O0Ooo . OoOoOO00 % i11iIiiIii / OoooooooOO
  if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 86 - 86: i1IIi . oO0o % OOooOOo
  if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
  if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
 def refresh_multicast ( self ) :
  if 17 - 17: OoO0O00
  if 79 - 79: Ii1I - II111iiii
  if 57 - 57: II111iiii / OoooooooOO
  if 4 - 4: I11i * OoOoOO00
  if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
  Ii1i1 = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  oOoOII11IIi1Ii1i = ( Ii1i1 in [ 0 , 1 , 2 ] )
  if ( oOoOII11IIi1Ii1i == False ) : return ( False )
  if 88 - 88: iII111i - I1ii11iIi11i / OoOoOO00 + O0 % oO0o
  if 22 - 22: o0oOOo0O0Ooo * O0 % Oo0Ooo
  if 52 - 52: I1IiiI % I1Ii111 - i1IIi . o0oOOo0O0Ooo % I1ii11iIi11i
  if 34 - 34: o0oOOo0O0Ooo / OoOoOO00
  o0ooooO = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( o0ooooO ) : return ( False )
  if 57 - 57: o0oOOo0O0Ooo / i1IIi . O0 . OOooOOo - OOooOOo
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 45 - 45: ooOoO0o * i11iIiiIii - II111iiii
  if 67 - 67: OOooOOo % OOooOOo
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  Ii1i1 = time . time ( ) - self . last_refresh_time
  if ( Ii1i1 >= self . map_cache_ttl ) : return ( True )
  if 8 - 8: Ii1I / ooOoO0o
  if 11 - 11: oO0o * OoooooooOO
  if 88 - 88: I1Ii111 % OOooOOo - iIii1I11I1II1 / I1ii11iIi11i
  if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
  if 81 - 81: Ii1I
  oo0Oo0Oo0o0 = self . map_cache_ttl - ( old_div ( self . map_cache_ttl , 10 ) )
  if ( Ii1i1 >= oo0Oo0Oo0o0 ) : return ( True )
  return ( False )
  if 77 - 77: OOooOOo + O0 - Ii1I
  if 43 - 43: O0 % i11iIiiIii + o0oOOo0O0Ooo . I11i / OOooOOo . O0
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  Ii1i1 = time . time ( ) - self . stats . last_increment
  return ( Ii1i1 <= 60 )
  if 30 - 30: i11iIiiIii + i1IIi
  if 52 - 52: OoooooooOO % OoOoOO00 / IiII % OoO0O00
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 36 - 36: II111iiii . O0 % O0 * iII111i * iIii1I11I1II1
  if 42 - 42: iII111i . OOooOOo + oO0o / OoOoOO00
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 54 - 54: ooOoO0o % o0oOOo0O0Ooo + i11iIiiIii / ooOoO0o * II111iiii * Ii1I
  if 52 - 52: ooOoO0o + IiII * OoOoOO00 - OoO0O00 - OoooooooOO - oO0o
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for IIIi1iI1 in self . best_rloc_set :
   IIIi1iI1 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 60 - 60: iII111i / oO0o
   if 98 - 98: OoOoOO00 / OOooOOo
   if 31 - 31: II111iiii % I11i - I11i
 def build_best_rloc_set ( self ) :
  I1II11i11Iiii = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 25 - 25: O0 - Ii1I - IiII
  if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
  if 66 - 66: II111iiii % I1IiiI
  if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
  oO00O0O0 = 256
  for IIIi1iI1 in self . rloc_set :
   if ( IIIi1iI1 . up_state ( ) ) : oO00O0O0 = min ( IIIi1iI1 . priority , oO00O0O0 )
   if 8 - 8: iII111i . IiII / i11iIiiIii
   if 1 - 1: I11i - I1Ii111 - II111iiii - Ii1I
   if 31 - 31: OoooooooOO + I1IiiI - ooOoO0o
   if 79 - 79: O0 % I1ii11iIi11i % o0oOOo0O0Ooo + i11iIiiIii . i1IIi * OoOoOO00
   if 87 - 87: I1ii11iIi11i * I11i * ooOoO0o / O0 + OoooooooOO . iII111i
   if 70 - 70: OOooOOo + IiII
   if 59 - 59: I1IiiI * OOooOOo
   if 35 - 35: II111iiii
   if 28 - 28: I1Ii111 + IiII + I1ii11iIi11i . Ii1I
   if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
  for IIIi1iI1 in self . rloc_set :
   if ( IIIi1iI1 . priority <= oO00O0O0 ) :
    if ( IIIi1iI1 . unreach_state ( ) and IIIi1iI1 . last_rloc_probe == None ) :
     IIIi1iI1 . last_rloc_probe = lisp_get_timestamp ( )
     if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
    self . best_rloc_set . append ( IIIi1iI1 )
    if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
    if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
    if 98 - 98: IiII
    if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
    if 57 - 57: iII111i
    if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
    if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
    if 68 - 68: I11i / II111iiii * oO0o . II111iiii * OOooOOo
  for IIIi1iI1 in I1II11i11Iiii :
   if ( IIIi1iI1 . priority < oO00O0O0 ) : continue
   IIIi1iI1 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 78 - 78: I11i * OoO0O00 / II111iiii
  for IIIi1iI1 in self . best_rloc_set :
   if ( IIIi1iI1 . rloc . is_null ( ) ) : continue
   IIIi1iI1 . add_to_rloc_probe_list ( self . eid , self . group )
   if 86 - 86: I1Ii111 % II111iiii
   if 90 - 90: OoO0O00 / I11i - Oo0Ooo
   if 76 - 76: O0 + OoO0O00 / ooOoO0o . II111iiii * iIii1I11I1II1 . I1Ii111
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  OO0 = lisp_packet . packet
  II1I1I = lisp_packet . inner_version
  i1iIii = len ( self . best_rloc_set )
  if ( i1iIii == 0 ) :
   self . stats . increment ( len ( OO0 ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 33 - 33: iIii1I11I1II1 . I1ii11iIi11i - O0 - IiII
   if 51 - 51: OoooooooOO . I1IiiI . i11iIiiIii
  OOo0O0O = 4 if lisp_load_split_pings else 0
  O0o0oo0 = lisp_packet . hash_ports ( )
  if ( II1I1I == 4 ) :
   for OoOOoO0oOo in range ( 8 + OOo0O0O ) :
    O0o0oo0 = O0o0oo0 ^ struct . unpack ( "B" , OO0 [ OoOOoO0oOo + 12 ] ) [ 0 ]
    if 45 - 45: IiII / OOooOOo
  elif ( II1I1I == 6 ) :
   for OoOOoO0oOo in range ( 0 , 32 + OOo0O0O , 4 ) :
    O0o0oo0 = O0o0oo0 ^ struct . unpack ( "I" , OO0 [ OoOOoO0oOo + 8 : OoOOoO0oOo + 12 ] ) [ 0 ]
    if 79 - 79: I1IiiI . o0oOOo0O0Ooo . I1IiiI % O0 / Oo0Ooo / O0
   O0o0oo0 = ( O0o0oo0 >> 16 ) + ( O0o0oo0 & 0xffff )
   O0o0oo0 = ( O0o0oo0 >> 8 ) + ( O0o0oo0 & 0xff )
  else :
   for OoOOoO0oOo in range ( 0 , 12 + OOo0O0O , 4 ) :
    O0o0oo0 = O0o0oo0 ^ struct . unpack ( "I" , OO0 [ OoOOoO0oOo : OoOOoO0oOo + 4 ] ) [ 0 ]
    if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
    if 42 - 42: I1ii11iIi11i
    if 51 - 51: iII111i % i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
  if ( lisp_data_plane_logging ) :
   iII = [ ]
   for OOoooo in self . best_rloc_set :
    if ( OOoooo . rloc . is_null ( ) ) : continue
    iII . append ( [ OOoooo . rloc . print_address_no_iid ( ) , OOoooo . print_state ( ) ] )
    if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( O0o0oo0 ) , O0o0oo0 % i1iIii , red ( str ( iII ) , False ) ) )
   if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
   if 29 - 29: O0 + iII111i
   if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
   if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
   if 76 - 76: OoooooooOO - O0
   if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
  IIIi1iI1 = self . best_rloc_set [ O0o0oo0 % i1iIii ]
  if 32 - 32: O0 % O0
  if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
  if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
  if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
  if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
  I1 = lisp_get_echo_nonce ( IIIi1iI1 . rloc , None )
  if ( I1 ) :
   I1 . change_state ( IIIi1iI1 )
   if ( IIIi1iI1 . no_echoed_nonce_state ( ) ) :
    I1 . request_nonce_sent = None
    if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
    if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
    if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
    if 11 - 11: OOooOOo
    if 25 - 25: i1IIi
    if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
  if ( IIIi1iI1 . up_state ( ) == False ) :
   ooOoOo0OOoo = O0o0oo0 % i1iIii
   OOOooo0OooOoO = ( ooOoOo0OOoo + 1 ) % i1iIii
   while ( OOOooo0OooOoO != ooOoOo0OOoo ) :
    IIIi1iI1 = self . best_rloc_set [ OOOooo0OooOoO ]
    if ( IIIi1iI1 . up_state ( ) ) : break
    OOOooo0OooOoO = ( OOOooo0OooOoO + 1 ) % i1iIii
    if 5 - 5: o0oOOo0O0Ooo . O0 - I1ii11iIi11i - ooOoO0o
   if ( OOOooo0OooOoO == ooOoOo0OOoo ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 43 - 43: IiII . o0oOOo0O0Ooo % OoO0O00 - I11i * o0oOOo0O0Ooo - II111iiii
    if 21 - 21: iII111i * I1Ii111
    if 43 - 43: I1Ii111 / I1ii11iIi11i - o0oOOo0O0Ooo + OoOoOO00 * iII111i - OoO0O00
    if 4 - 4: O0 + OoO0O00 / II111iiii
    if 93 - 93: o0oOOo0O0Ooo * I11i * II111iiii / OOooOOo
    if 95 - 95: OoOoOO00 % I1ii11iIi11i * I1Ii111 % II111iiii
  IIIi1iI1 . stats . increment ( len ( OO0 ) )
  if 15 - 15: IiII . I1ii11iIi11i / I1IiiI . I1ii11iIi11i + Ii1I
  if 82 - 82: OOooOOo / I1IiiI % Oo0Ooo - OoO0O00 - o0oOOo0O0Ooo
  if 95 - 95: iII111i % o0oOOo0O0Ooo
  if 26 - 26: i1IIi / iII111i + iII111i
  if ( IIIi1iI1 . rle_name and IIIi1iI1 . rle == None ) :
   if ( IIIi1iI1 . rle_name in lisp_rle_list ) :
    IIIi1iI1 . rle = lisp_rle_list [ IIIi1iI1 . rle_name ]
    if 66 - 66: i1IIi + I1IiiI
    if 45 - 45: I1Ii111 . iII111i + OoO0O00 - O0
  if ( IIIi1iI1 . rle ) : return ( [ None , None , None , None , IIIi1iI1 . rle , None ] )
  if 71 - 71: Oo0Ooo + OOooOOo
  if 94 - 94: OOooOOo
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
  if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
  if ( IIIi1iI1 . elp and IIIi1iI1 . elp . use_elp_node ) :
   return ( [ IIIi1iI1 . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 31 - 31: I11i . o0oOOo0O0Ooo
   if 82 - 82: I11i - Oo0Ooo
   if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
   if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
   if 79 - 79: oO0o + IiII
  i1ii1I1 = None if ( IIIi1iI1 . rloc . is_null ( ) ) else IIIi1iI1 . rloc
  IiO0o = IIIi1iI1 . translated_port
  Oo0Oo00O000O = self . action if ( i1ii1I1 == None ) else None
  if 6 - 6: iIii1I11I1II1 % iII111i * i1IIi
  if 82 - 82: IiII / O0 / I11i % OoOoOO00 * I1Ii111 / OOooOOo
  if 10 - 10: I11i + iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
  if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
  if 97 - 97: i11iIiiIii / O0 % OoO0O00
  o00oO0O000 = None
  if ( I1 and I1 . request_nonce_timeout ( ) == False ) :
   o00oO0O000 = I1 . get_request_or_echo_nonce ( ipc_socket , i1ii1I1 )
   if 88 - 88: i1IIi . I1IiiI
   if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
   if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
   if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
   if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
  return ( [ i1ii1I1 , IiO0o , o00oO0O000 , Oo0Oo00O000O , None , IIIi1iI1 ] )
  if 84 - 84: I1IiiI + OOooOOo
  if 80 - 80: OOooOOo / OoOoOO00
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 93 - 93: OOooOOo
  if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
  if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
  if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
  if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
  for O0O0OOo0O in self . rloc_set :
   for IIIi1iI1 in rloc_address_set :
    if ( IIIi1iI1 . is_exact_match ( O0O0OOo0O . rloc ) == False ) : continue
    IIIi1iI1 = None
    break
    if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
   if ( IIIi1iI1 == rloc_address_set [ - 1 ] ) : return ( False )
   if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
  return ( True )
  if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
 def get_rloc ( self , rloc ) :
  for O0O0OOo0O in self . rloc_set :
   OOoooo = O0O0OOo0O . rloc
   if ( rloc . is_exact_match ( OOoooo ) ) : return ( O0O0OOo0O )
   if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
  return ( None )
  if 91 - 91: II111iiii * o0oOOo0O0Ooo
  if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
 def get_rloc_by_interface ( self , interface ) :
  for O0O0OOo0O in self . rloc_set :
   if ( O0O0OOo0O . interface == interface ) : return ( O0O0OOo0O )
   if 93 - 93: I11i * iIii1I11I1II1 * oO0o
  return ( None )
  if 74 - 74: I1IiiI
  if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   iIiI1ii = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( iIiI1ii == None ) :
    iIiI1ii = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , iIiI1ii )
    if 27 - 27: iIii1I11I1II1 . ooOoO0o
   iIiI1ii . add_source_entry ( self )
   if 74 - 74: i1IIi % OoOoOO00
   if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
   if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   I111I1iI1 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( I111I1iI1 == None ) :
    I111I1iI1 = lisp_mapping ( self . group , self . group , [ ] )
    I111I1iI1 . eid . copy_address ( self . group )
    I111I1iI1 . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , I111I1iI1 )
    if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( I111I1iI1 . group )
   I111I1iI1 . add_source_entry ( self )
   if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 100 - 100: Ii1I
  if 73 - 73: IiII - O0
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 54 - 54: OOooOOo
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    Ii1IIIIi = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( Ii1IIIIi ) )
    if 100 - 100: I11i . OOooOOo - II111iiii % I11i % iIii1I11I1II1
  else :
   I111I1iI1 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( I111I1iI1 == None ) : return
   if 4 - 4: o0oOOo0O0Ooo . iII111i / O0
   i11ii = I111I1iI1 . lookup_source_cache ( self . eid , True )
   if ( i11ii == None ) : return
   if 85 - 85: iIii1I11I1II1 . iIii1I11I1II1 / IiII % I1ii11iIi11i % i11iIiiIii . i1IIi
   I111I1iI1 . source_cache . delete_cache ( self . eid )
   if ( I111I1iI1 . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 20 - 20: Ii1I % I1ii11iIi11i . iIii1I11I1II1 - I1IiiI % IiII
    if 51 - 51: ooOoO0o
    if 50 - 50: O0 / II111iiii
    if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 15 - 15: I1IiiI
  if 48 - 48: Ii1I * IiII % O0 - II111iiii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 66 - 66: iIii1I11I1II1 / OOooOOo
  if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
  if 67 - 67: I1Ii111
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  i1oO00O = "," + str ( self . secondary_iid )
  return ( prefix . replace ( i1oO00O , i1oO00O + "*" ) )
  if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
  if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
 def increment_decap_stats ( self , packet ) :
  IiO0o = packet . udp_dport
  if ( IiO0o == LISP_DATA_PORT ) :
   IIIi1iI1 = self . get_rloc ( packet . outer_dest )
  else :
   if 46 - 46: I11i - ooOoO0o . I1IiiI
   if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
   if 90 - 90: i11iIiiIii / i1IIi
   if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
   for IIIi1iI1 in self . rloc_set :
    if ( IIIi1iI1 . translated_port != 0 ) : break
    if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
    if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
  if ( IIIi1iI1 != None ) : IIIi1iI1 . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 87 - 87: II111iiii - iIii1I11I1II1 % I11i % I1IiiI . o0oOOo0O0Ooo
  if 52 - 52: i11iIiiIii . oO0o / OoooooooOO - OoO0O00
 def rtrs_in_rloc_set ( self ) :
  for IIIi1iI1 in self . rloc_set :
   if ( IIIi1iI1 . is_rtr ( ) ) : return ( True )
   if 7 - 7: I1IiiI * I1IiiI % OOooOOo % iIii1I11I1II1 * OoO0O00 . o0oOOo0O0Ooo
  return ( False )
  if 32 - 32: ooOoO0o / i1IIi
  if 55 - 55: oO0o . OoOoOO00 + OoooooooOO - ooOoO0o . OoooooooOO
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 77 - 77: I1IiiI
  if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
  if 36 - 36: Oo0Ooo - OoOoOO00 - II111iiii
class lisp_dynamic_eid ( object ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
  if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
 def get_timeout ( self , interface ) :
  try :
   IiI1I11iIiIIII = lisp_myinterfaces [ interface ]
   self . timeout = IiI1I11iIiIIII . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 88 - 88: ooOoO0o
   if 91 - 91: OoO0O00 % IiII / I1IiiI - i11iIiiIii - IiII * ooOoO0o
   if 54 - 54: O0 % o0oOOo0O0Ooo + o0oOOo0O0Ooo % i11iIiiIii * I11i
   if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
class lisp_group_mapping ( object ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 98 - 98: iII111i % IiII + OoO0O00
  if 23 - 23: OOooOOo
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
  if 99 - 99: II111iiii + O0
  if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
  if 88 - 88: Oo0Ooo . iII111i
  if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
  if 9 - 9: OoOoOO00 % i1IIi + IiII
  if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
  if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
  if 95 - 95: ooOoO0o
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 i1oO00O = group_mapping . group_prefix . instance_id
 I1iIii11iIi1I = group_mapping . group_prefix . mask_len
 iiI = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , i1oO00O )
 if ( iiI . is_more_specific ( group_mapping . group_prefix ) ) : return ( I1iIii11iIi1I )
 return ( - 1 )
 if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 if 32 - 32: OoOoOO00 % i11iIiiIii
 if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 if 44 - 44: I1Ii111 + ooOoO0o
 if 15 - 15: I11i + OoO0O00 + OoOoOO00
 if 100 - 100: I1Ii111
 if 78 - 78: OoOoOO00
def lisp_lookup_group ( group ) :
 iII = None
 for I1II1I1III1 in list ( lisp_group_mapping_list . values ( ) ) :
  I1iIii11iIi1I = lisp_is_group_more_specific ( group , I1II1I1III1 )
  if ( I1iIii11iIi1I == - 1 ) : continue
  if ( iII == None or I1iIii11iIi1I > iII . group_prefix . mask_len ) : iII = I1II1I1III1
  if 99 - 99: II111iiii . OoooooooOO * iIii1I11I1II1
 return ( iII )
 if 72 - 72: OoooooooOO . I1ii11iIi11i * I1Ii111 / OoooooooOO % OOooOOo
 if 60 - 60: OoO0O00
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 54 - 54: I1IiiI + O0 - I1Ii111 - oO0o + O0 - I1ii11iIi11i
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
  if 21 - 21: ooOoO0o . i1IIi / Oo0Ooo . OoO0O00
  if 49 - 49: oO0o % i11iIiiIii * Ii1I
  if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
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
  if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
  if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
  if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
 def print_flags ( self , html ) :
  if ( html == False ) :
   OoiIIIiIi1I1i = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # I1ii11iIi11i . iII111i . II111iiii + IiII
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   II1iIIii1I111 = self . print_flags ( False )
   II1iIIii1I111 = II1iIIii1I111 . split ( "-" )
   OoiIIIiIi1I1i = ""
   for OO000o0 in II1iIIii1I111 :
    iIIiIi1111I = lisp_site_flags [ OO000o0 . upper ( ) ]
    iIIiIi1111I = iIIiIi1111I . format ( "" if OO000o0 . isupper ( ) else "not " )
    OoiIIIiIi1I1i += lisp_span ( OO000o0 , iIIiIi1111I )
    if ( OO000o0 . lower ( ) != "n" ) : OoiIIIiIi1I1i += "-"
    if 92 - 92: oO0o * I11i + i1IIi * iIii1I11I1II1 . I1IiiI % Oo0Ooo
    if 77 - 77: OoO0O00 % iII111i - oO0o + OoO0O00 + i11iIiiIii
  return ( OoiIIIiIi1I1i )
  if 12 - 12: OoooooooOO . I1ii11iIi11i + O0 / OoOoOO00
  if 20 - 20: I1ii11iIi11i * I1ii11iIi11i + I1ii11iIi11i / OoO0O00 - oO0o % O0
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 86 - 86: Oo0Ooo / OoO0O00
  if 78 - 78: I1IiiI * I1IiiI
 def build_sort_key ( self ) :
  iIIiI11II = lisp_cache ( )
  Iii1iii1II , IIIOoo = iIIiI11II . build_key ( self . eid )
  i1i111 = ""
  if ( self . group . is_null ( ) == False ) :
   I111IIi1IIi , i1i111 = iIIiI11II . build_key ( self . group )
   i1i111 = "-" + i1i111 [ 0 : 12 ] + "-" + str ( I111IIi1IIi ) + "-" + i1i111 [ 12 : : ]
   if 6 - 6: O0 - Ii1I . OOooOOo
  IIIOoo = IIIOoo [ 0 : 12 ] + "-" + str ( Iii1iii1II ) + "-" + IIIOoo [ 12 : : ] + i1i111
  del ( iIIiI11II )
  return ( IIIOoo )
  if 39 - 39: I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
  if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
 def merge_in_site_eid ( self , child ) :
  i1I11iii1IIi = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   i1I11iii1IIi = self . merge_rles_in_site_eid ( )
   if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
   if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
   if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
   if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
   if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
   if 85 - 85: I1IiiI - o0oOOo0O0Ooo
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 86 - 86: II111iiii + Ii1I * Ii1I
  return ( i1I11iii1IIi )
  if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
  if 86 - 86: Ii1I
 def copy_rloc_records ( self ) :
  oOoOOoo0OoO = [ ]
  for O0O0OOo0O in self . registered_rlocs :
   oOoOOoo0OoO . append ( copy . deepcopy ( O0O0OOo0O ) )
   if 78 - 78: I1Ii111 % i1IIi * I11i
  return ( oOoOOoo0OoO )
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for IiiiiiIiI in list ( self . individual_registrations . values ( ) ) :
   if ( self . site_id != IiiiiiIiI . site_id ) : continue
   if ( IiiiiiIiI . registered == False ) : continue
   self . registered_rlocs += IiiiiiIiI . copy_rloc_records ( )
   if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
   if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
   if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
   if 29 - 29: OoO0O00
   if 33 - 33: I1ii11iIi11i - O0
   if 72 - 72: Oo0Ooo * iII111i - I11i
  oOoOOoo0OoO = [ ]
  for O0O0OOo0O in self . registered_rlocs :
   if ( O0O0OOo0O . rloc . is_null ( ) or len ( oOoOOoo0OoO ) == 0 ) :
    oOoOOoo0OoO . append ( O0O0OOo0O )
    continue
    if 81 - 81: I1Ii111
   for oooOOOo00o in oOoOOoo0OoO :
    if ( oooOOOo00o . rloc . is_null ( ) ) : continue
    if ( O0O0OOo0O . rloc . is_exact_match ( oooOOOo00o . rloc ) ) : break
    if 33 - 33: OoO0O00 * II111iiii / i1IIi
   if ( oooOOOo00o == oOoOOoo0OoO [ - 1 ] ) : oOoOOoo0OoO . append ( O0O0OOo0O )
   if 93 - 93: I1Ii111 % I11i
  self . registered_rlocs = oOoOOoo0OoO
  if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
  if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
  if 49 - 49: IiII - OOooOOo * OOooOOo . O0
  if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
  if 61 - 61: OoO0O00
 def merge_rles_in_site_eid ( self ) :
  if 100 - 100: OoOoOO00
  if 97 - 97: OoooooooOO
  if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
  if 35 - 35: iII111i % OoO0O00 * O0
  i1I1Iii1II = { }
  for O0O0OOo0O in self . registered_rlocs :
   if ( O0O0OOo0O . rle == None ) : continue
   for oO0oOOOO0oO0o0 in O0O0OOo0O . rle . rle_nodes :
    oOOOo0o = oO0oOOOO0oO0o0 . address . print_address_no_iid ( )
    i1I1Iii1II [ oOOOo0o ] = oO0oOOOO0oO0o0 . address
    if 41 - 41: o0oOOo0O0Ooo * Ii1I + I11i . O0
   break
   if 17 - 17: Ii1I % I1Ii111
   if 69 - 69: iIii1I11I1II1
   if 65 - 65: IiII % OOooOOo / o0oOOo0O0Ooo * II111iiii - oO0o
   if 38 - 38: I1Ii111 * o0oOOo0O0Ooo
   if 32 - 32: iII111i / Ii1I / I1Ii111 - OoOoOO00 / OOooOOo * OoO0O00
  self . merge_rlocs_in_site_eid ( )
  if 32 - 32: I1ii11iIi11i + ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
  if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
  if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
  if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
  if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
  if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
  if 100 - 100: OoO0O00
  if 36 - 36: oO0o + Ii1I - O0
  Iii1111 = [ ]
  for O0O0OOo0O in self . registered_rlocs :
   if ( self . registered_rlocs . index ( O0O0OOo0O ) == 0 ) :
    Iii1111 . append ( O0O0OOo0O )
    continue
    if 88 - 88: i1IIi * o0oOOo0O0Ooo - I11i
   if ( O0O0OOo0O . rle == None ) : Iii1111 . append ( O0O0OOo0O )
   if 99 - 99: II111iiii + O0 / oO0o . OOooOOo . IiII
  self . registered_rlocs = Iii1111
  if 56 - 56: OoO0O00 % O0 . iII111i % o0oOOo0O0Ooo - I1IiiI + Ii1I
  if 77 - 77: iIii1I11I1II1 - OoO0O00 - i1IIi
  if 21 - 21: oO0o . Oo0Ooo . IiII . ooOoO0o
  if 88 - 88: i11iIiiIii . I1Ii111 . O0 % II111iiii - OoO0O00
  if 33 - 33: I1ii11iIi11i + OoooooooOO % OoO0O00
  if 1 - 1: I1Ii111 + ooOoO0o . i1IIi + O0
  if 15 - 15: OoooooooOO - ooOoO0o + ooOoO0o / I1Ii111 + IiII . II111iiii
  IIii1i = lisp_rle ( "" )
  i11O00oOooo00 = { }
  i1Ii1iiI = None
  for IiiiiiIiI in list ( self . individual_registrations . values ( ) ) :
   if ( IiiiiiIiI . registered == False ) : continue
   i11iI11iIiI1I = IiiiiiIiI . registered_rlocs [ 0 ] . rle
   if ( i11iI11iIiI1I == None ) : continue
   if 20 - 20: I1IiiI / OOooOOo - I1Ii111 / I11i
   i1Ii1iiI = IiiiiiIiI . registered_rlocs [ 0 ] . rloc_name
   for IIiiIiII1iiI in i11iI11iIiI1I . rle_nodes :
    oOOOo0o = IIiiIiII1iiI . address . print_address_no_iid ( )
    if ( oOOOo0o in i11O00oOooo00 ) : break
    if 20 - 20: o0oOOo0O0Ooo
    oO0oOOOO0oO0o0 = lisp_rle_node ( )
    oO0oOOOO0oO0o0 . address . copy_address ( IIiiIiII1iiI . address )
    oO0oOOOO0oO0o0 . level = IIiiIiII1iiI . level
    oO0oOOOO0oO0o0 . rloc_name = i1Ii1iiI
    IIii1i . rle_nodes . append ( oO0oOOOO0oO0o0 )
    i11O00oOooo00 [ oOOOo0o ] = IIiiIiII1iiI . address
    if 65 - 65: OOooOOo / OoOoOO00
    if 31 - 31: OoOoOO00 * I1IiiI + i11iIiiIii % OOooOOo * OoOoOO00
    if 36 - 36: I1Ii111 * OoO0O00
    if 84 - 84: OoOoOO00
    if 80 - 80: oO0o
    if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
  if ( len ( IIii1i . rle_nodes ) == 0 ) : IIii1i = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = IIii1i
   if ( i1Ii1iiI ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 92 - 92: iII111i
   if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
   if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
   if 92 - 92: I1Ii111 - IiII / IiII
   if 42 - 42: IiII
  if ( list ( i1I1Iii1II . keys ( ) ) == list ( i11O00oOooo00 . keys ( ) ) ) : return ( False )
  if 7 - 7: iIii1I11I1II1
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # Oo0Ooo % I11i * O0
 list ( i1I1Iii1II . keys ( ) ) , list ( i11O00oOooo00 . keys ( ) ) ) )
  if 61 - 61: I1ii11iIi11i - ooOoO0o / OoOoOO00 % OOooOOo * i1IIi . IiII
  return ( True )
  if 27 - 27: I1ii11iIi11i % iII111i . Oo0Ooo * iIii1I11I1II1
  if 40 - 40: I11i
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   i1I1I11II = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( i1I1I11II == None ) :
    i1I1I11II = lisp_site_eid ( self . site )
    i1I1I11II . eid . copy_address ( self . group )
    i1I1I11II . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , i1I1I11II )
    if 58 - 58: o0oOOo0O0Ooo / OOooOOo . oO0o % ooOoO0o
    if 33 - 33: I1IiiI * I1ii11iIi11i . OoO0O00 - I1Ii111 . OoO0O00
    if 79 - 79: ooOoO0o
    if 90 - 90: OOooOOo
    if 4 - 4: OoOoOO00 - I1Ii111 . i1IIi - IiII . ooOoO0o + II111iiii
    i1I1I11II . parent_for_more_specifics = self . parent_for_more_specifics
    if 56 - 56: I1ii11iIi11i / i1IIi + I11i % Oo0Ooo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( i1I1I11II . group )
   i1I1I11II . add_source_entry ( self )
   if 86 - 86: O0 * II111iiii
   if 75 - 75: iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % I1ii11iIi11i . II111iiii
   if 11 - 11: I1ii11iIi11i - I1ii11iIi11i . ooOoO0o * Oo0Ooo + I1Ii111
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   i1I1I11II = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( i1I1I11II == None ) : return
   if 59 - 59: iII111i - OOooOOo - OoO0O00 . I1IiiI % o0oOOo0O0Ooo + iII111i
   IiiiiiIiI = i1I1I11II . lookup_source_cache ( self . eid , True )
   if ( IiiiiiIiI == None ) : return
   if 10 - 10: iIii1I11I1II1 - Ii1I
   if ( i1I1I11II . source_cache == None ) : return
   if 84 - 84: iII111i
   i1I1I11II . source_cache . delete_cache ( self . eid )
   if ( i1I1I11II . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 21 - 21: i11iIiiIii
    if 30 - 30: OoO0O00 + OoooooooOO
    if 98 - 98: I1ii11iIi11i % I1IiiI
    if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 66 - 66: IiII
  if 56 - 56: oO0o + OoooooooOO
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 75 - 75: O0 % Ii1I
  if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 23 - 23: iII111i / iIii1I11I1II1
  if 5 - 5: O0
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
  if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
 def inherit_from_ams_parent ( self ) :
  OO0o0OoO0O = self . parent_for_more_specifics
  if ( OO0o0OoO0O == None ) : return
  self . force_proxy_reply = OO0o0OoO0O . force_proxy_reply
  self . force_nat_proxy_reply = OO0o0OoO0O . force_nat_proxy_reply
  self . force_ttl = OO0o0OoO0O . force_ttl
  self . pitr_proxy_reply_drop = OO0o0OoO0O . pitr_proxy_reply_drop
  self . proxy_reply_action = OO0o0OoO0O . proxy_reply_action
  self . echo_nonce_capable = OO0o0OoO0O . echo_nonce_capable
  self . policy = OO0o0OoO0O . policy
  self . require_signature = OO0o0OoO0O . require_signature
  self . encrypt_json = OO0o0OoO0O . encrypt_json
  if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
  if 6 - 6: O0 - OoOoOO00 - i11iIiiIii / iII111i
 def rtrs_in_rloc_set ( self ) :
  for O0O0OOo0O in self . registered_rlocs :
   if ( O0O0OOo0O . is_rtr ( ) ) : return ( True )
   if 63 - 63: OOooOOo
  return ( False )
  if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
  if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for O0O0OOo0O in self . registered_rlocs :
   if ( O0O0OOo0O . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( O0O0OOo0O . is_rtr ( ) ) : return ( True )
   if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
  return ( False )
  if 13 - 13: Ii1I - OoOoOO00 . Ii1I
  if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
 def is_rloc_in_rloc_set ( self , rloc ) :
  for O0O0OOo0O in self . registered_rlocs :
   if ( O0O0OOo0O . rle ) :
    for IIii1i in O0O0OOo0O . rle . rle_nodes :
     if ( IIii1i . address . is_exact_match ( rloc ) ) : return ( True )
     if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
     if 73 - 73: Ii1I . IiII % IiII
   if ( O0O0OOo0O . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 56 - 56: I1Ii111 + iII111i + iII111i
  return ( False )
  if 99 - 99: o0oOOo0O0Ooo % I1ii11iIi11i / Oo0Ooo . O0 + OoO0O00 * OoOoOO00
  if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
  for O0O0OOo0O in prev_rloc_set :
   O00Oo0o00 = O0O0OOo0O . rloc
   if ( self . is_rloc_in_rloc_set ( O00Oo0o00 ) == False ) : return ( False )
   if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
  return ( True )
  if 47 - 47: II111iiii % o0oOOo0O0Ooo
  if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
  if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
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
   if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
  if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
  try :
   O00Oo = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   oo0Oo00OO0000 = O00Oo [ 2 ]
  except :
   return
   if 74 - 74: Ii1I - OoOoOO00 + i11iIiiIii - II111iiii - i11iIiiIii . ooOoO0o
   if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
   if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
   if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
   if 78 - 78: i1IIi
   if 25 - 25: Ii1I * II111iiii / OoOoOO00
  if ( len ( oo0Oo00OO0000 ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
   if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
  oOOOo0o = oo0Oo00OO0000 [ self . a_record_index ]
  if ( oOOOo0o != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( oOOOo0o )
   self . insert_mr ( )
   if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
   if 15 - 15: i11iIiiIii
   if 85 - 85: I1Ii111 + iII111i - oO0o
   if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
   if 64 - 64: OoOoOO00
   if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
  for oOOOo0o in oo0Oo00OO0000 [ 1 : : ] :
   OoOOOO = lisp_address ( LISP_AFI_NONE , oOOOo0o , 0 , 0 )
   oooO = lisp_get_map_resolver ( OoOOOO , None )
   if ( oooO != None and oooO . a_record_index == oo0Oo00OO0000 . index ( oOOOo0o ) ) :
    continue
    if 71 - 71: ooOoO0o
   oooO = lisp_mr ( oOOOo0o , None , None )
   oooO . a_record_index = oo0Oo00OO0000 . index ( oOOOo0o )
   oooO . dns_name = self . dns_name
   oooO . last_dns_resolve = lisp_get_timestamp ( )
   if 35 - 35: OoOoOO00
   if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
   if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
   if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
   if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
  ooOOOoo0O00 = [ ]
  for oooO in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( self . dns_name != oooO . dns_name ) : continue
   OoOOOO = oooO . map_resolver . print_address_no_iid ( )
   if ( OoOOOO in oo0Oo00OO0000 ) : continue
   ooOOOoo0O00 . append ( oooO )
   if 22 - 22: oO0o + O0 + I11i . OoO0O00 - II111iiii
  for oooO in ooOOOoo0O00 : oooO . delete_mr ( )
  if 20 - 20: Ii1I * I1Ii111 . I1IiiI % OoOoOO00 / OoO0O00 % II111iiii
  if 43 - 43: IiII + II111iiii + oO0o / I1ii11iIi11i % i1IIi - OoO0O00
 def insert_mr ( self ) :
  IIIOoo = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ IIIOoo ] = self
  if 59 - 59: Oo0Ooo + O0 + iII111i
  if 71 - 71: IiII - OoO0O00
 def delete_mr ( self ) :
  IIIOoo = self . mr_name + self . map_resolver . print_address ( )
  if ( IIIOoo not in lisp_map_resolvers_list ) : return
  lisp_map_resolvers_list . pop ( IIIOoo )
  if 90 - 90: Oo0Ooo
  if 83 - 83: iIii1I11I1II1 % ooOoO0o % OOooOOo * i1IIi - o0oOOo0O0Ooo * i1IIi
  if 60 - 60: Ii1I . I1ii11iIi11i - I11i + i11iIiiIii / iII111i
class lisp_ddt_root ( object ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 9 - 9: I1Ii111 . oO0o . OoO0O00 / IiII - oO0o / oO0o
  if 50 - 50: II111iiii + OoOoOO00
  if 17 - 17: ooOoO0o + I1ii11iIi11i
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
  if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
  if 48 - 48: O0
 def print_referral ( self , eid_indent , referral_indent ) :
  OooOOOo0oooo = lisp_print_elapsed ( self . uptime )
  O00o00ooo0Ooo = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , OooOOOo0oooo ,
  # iIii1I11I1II1 / oO0o - Oo0Ooo - I1IiiI + iIii1I11I1II1
 O00o00ooo0Ooo , len ( self . referral_set ) ) )
  if 63 - 63: iIii1I11I1II1 / ooOoO0o + O0 - o0oOOo0O0Ooo
  for o00o0 in list ( self . referral_set . values ( ) ) :
   o00o0 . print_ref_node ( referral_indent )
   if 31 - 31: Ii1I
   if 76 - 76: OoO0O00 / II111iiii
   if 92 - 92: o0oOOo0O0Ooo . i1IIi . OoOoOO00 / OoO0O00 % Ii1I
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 61 - 61: i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 69 - 69: i11iIiiIii - iIii1I11I1II1
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 40 - 40: I1IiiI / oO0o + ooOoO0o
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
  if 37 - 37: I1ii11iIi11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 24 - 24: O0 . I1Ii111 * i11iIiiIii
  if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
 def print_ttl ( self ) :
  IiIIi = self . referral_ttl
  if ( IiIIi < 60 ) : return ( str ( IiIIi ) + " secs" )
  if 16 - 16: I11i % O0
  if ( ( IiIIi % 60 ) == 0 ) :
   IiIIi = str ( old_div ( IiIIi , 60 ) ) + " mins"
  else :
   IiIIi = str ( IiIIi ) + " secs"
   if 56 - 56: Ii1I * OoOoOO00 . i1IIi
  return ( IiIIi )
  if 15 - 15: I1Ii111
  if 64 - 64: OOooOOo * Oo0Ooo
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # i1IIi - ooOoO0o + II111iiii - iII111i . iIii1I11I1II1 / I1Ii111
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 29 - 29: i1IIi - I1IiiI / i1IIi
  if 64 - 64: IiII
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   oOo0 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( oOo0 == None ) :
    oOo0 = lisp_referral ( )
    oOo0 . eid . copy_address ( self . group )
    oOo0 . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , oOo0 )
    if 69 - 69: OOooOOo . I1IiiI
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( oOo0 . group )
   oOo0 . add_source_entry ( self )
   if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
   if 22 - 22: iII111i % I11i % O0 - I11i
   if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   oOo0 = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( oOo0 == None ) : return
   if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
   IIIIIIi1i1I = oOo0 . lookup_source_cache ( self . eid , True )
   if ( IIIIIIi1i1I == None ) : return
   if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
   oOo0 . source_cache . delete_cache ( self . eid )
   if ( oOo0 . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
    if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
    if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
    if 97 - 97: iIii1I11I1II1 * I1Ii111
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 39 - 39: I1Ii111 . II111iiii
  if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
  if 34 - 34: I1IiiI
  if 56 - 56: Ii1I
class lisp_referral_node ( object ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 71 - 71: O0 / i1IIi
  if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
 def print_ref_node ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , i1 ,
  # IiII * Ii1I - Ii1I . oO0o - IiII
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 56 - 56: i1IIi + i11iIiiIii % OoO0O00 - ooOoO0o / OoO0O00
  if 23 - 23: IiII - OoO0O00 / I1ii11iIi11i * oO0o
  if 77 - 77: O0 * oO0o . I1ii11iIi11i - i1IIi
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
   if 87 - 87: i1IIi % I1Ii111
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
   if 37 - 37: I11i
   if 61 - 61: OoooooooOO % iIii1I11I1II1 % O0 % I1Ii111 / Oo0Ooo . I1IiiI
   if 20 - 20: ooOoO0o - I1Ii111
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 97 - 97: O0
  try :
   O00Oo = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   oo0Oo00OO0000 = O00Oo [ 2 ]
  except :
   return
   if 56 - 56: Ii1I * I1IiiI * ooOoO0o
   if 39 - 39: iII111i % Ii1I * iIii1I11I1II1 - Ii1I - I1Ii111
   if 60 - 60: i11iIiiIii + i11iIiiIii - OoooooooOO + OoooooooOO
   if 5 - 5: o0oOOo0O0Ooo
   if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
   if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
  if ( len ( oo0Oo00OO0000 ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
   if 64 - 64: O0 - iII111i
  oOOOo0o = oo0Oo00OO0000 [ self . a_record_index ]
  if ( oOOOo0o != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( oOOOo0o )
   self . insert_ms ( )
   if 82 - 82: O0
   if 37 - 37: I1Ii111
   if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
   if 84 - 84: OOooOOo * ooOoO0o / O0
   if 96 - 96: I11i . I11i % II111iiii
   if 14 - 14: iII111i / OoooooooOO
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
  for oOOOo0o in oo0Oo00OO0000 [ 1 : : ] :
   OoOOOO = lisp_address ( LISP_AFI_NONE , oOOOo0o , 0 , 0 )
   IIo0o0oo0 = lisp_get_map_server ( OoOOOO )
   if ( IIo0o0oo0 != None and IIo0o0oo0 . a_record_index == oo0Oo00OO0000 . index ( oOOOo0o ) ) :
    continue
    if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
   IIo0o0oo0 = copy . deepcopy ( self )
   IIo0o0oo0 . map_server . store_address ( oOOOo0o )
   IIo0o0oo0 . a_record_index = oo0Oo00OO0000 . index ( oOOOo0o )
   IIo0o0oo0 . last_dns_resolve = lisp_get_timestamp ( )
   IIo0o0oo0 . insert_ms ( )
   if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
   if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
   if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
   if 11 - 11: I1IiiI
   if 45 - 45: OOooOOo / i1IIi * IiII * I1Ii111
  ooOOOoo0O00 = [ ]
  for IIo0o0oo0 in list ( lisp_map_servers_list . values ( ) ) :
   if ( self . dns_name != IIo0o0oo0 . dns_name ) : continue
   OoOOOO = IIo0o0oo0 . map_server . print_address_no_iid ( )
   if ( OoOOOO in oo0Oo00OO0000 ) : continue
   ooOOOoo0O00 . append ( IIo0o0oo0 )
   if 34 - 34: ooOoO0o / iIii1I11I1II1 . iII111i
  for IIo0o0oo0 in ooOOOoo0O00 : IIo0o0oo0 . delete_ms ( )
  if 91 - 91: OoO0O00
  if 8 - 8: oO0o
 def insert_ms ( self ) :
  IIIOoo = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ IIIOoo ] = self
  if 96 - 96: IiII
  if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
 def delete_ms ( self ) :
  IIIOoo = self . ms_name + self . map_server . print_address ( )
  if ( IIIOoo not in lisp_map_servers_list ) : return
  lisp_map_servers_list . pop ( IIIOoo )
  if 26 - 26: o0oOOo0O0Ooo . i1IIi
  if 62 - 62: IiII * I1ii11iIi11i % iIii1I11I1II1 / II111iiii - OoO0O00
  if 52 - 52: iII111i . I11i - I11i + oO0o + iIii1I11I1II1
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
  if 83 - 83: I11i * iIii1I11I1II1 + OoOoOO00
  if 81 - 81: ooOoO0o * OOooOOo / OoO0O00 + I1ii11iIi11i % I1Ii111
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 37 - 37: i11iIiiIii - OoooooooOO - OoOoOO00 * oO0o / Ii1I
  if 100 - 100: II111iiii / Oo0Ooo / iII111i / OOooOOo
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 100 - 100: iIii1I11I1II1
  if 50 - 50: I1Ii111 / ooOoO0o * I11i
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 53 - 53: II111iiii . IiII
  if 5 - 5: i1IIi % IiII
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 16 - 16: ooOoO0o - iII111i % Ii1I . OoOoOO00
  if 56 - 56: i11iIiiIii % i11iIiiIii % OoooooooOO . Ii1I . iII111i + I11i
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 64 - 64: O0
  if 37 - 37: o0oOOo0O0Ooo / O0
 def set_socket ( self , device ) :
  I1iiIi111I = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  I1iiIi111I . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   I1iiIi111I . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   I1iiIi111I . close ( )
   I1iiIi111I = None
   if 58 - 58: I1Ii111 + OoooooooOO + iIii1I11I1II1
  self . raw_socket = I1iiIi111I
  if 13 - 13: o0oOOo0O0Ooo . I11i / O0
  if 39 - 39: I11i + oO0o + ooOoO0o % ooOoO0o - I1IiiI % Oo0Ooo
 def set_bridge_socket ( self , device ) :
  I1iiIi111I = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   I1iiIi111I = I1iiIi111I . bind ( ( device , 0 ) )
   self . bridge_socket = I1iiIi111I
  except :
   return
   if 9 - 9: IiII / iII111i * II111iiii + O0 % Oo0Ooo / i1IIi
   if 45 - 45: OoOoOO00 % i11iIiiIii . I1IiiI - O0 * i1IIi - I1IiiI
   if 48 - 48: IiII / iIii1I11I1II1
   if 20 - 20: oO0o / OoooooooOO
class lisp_datetime ( object ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 95 - 95: Oo0Ooo . i11iIiiIii
  if 50 - 50: iII111i . i11iIiiIii - i1IIi
 def valid_datetime ( self ) :
  iii1IIIIiII = self . datetime_name
  if ( iii1IIIIiII . find ( ":" ) == - 1 ) : return ( False )
  if ( iii1IIIIiII . find ( "-" ) == - 1 ) : return ( False )
  i1Ii11i1iIi , oOOoOoo0 , iIiII1I1iIi , time = iii1IIIIiII [ 0 : 4 ] , iii1IIIIiII [ 5 : 7 ] , iii1IIIIiII [ 8 : 10 ] , iii1IIIIiII [ 11 : : ]
  if 24 - 24: oO0o
  if ( ( i1Ii11i1iIi + oOOoOoo0 + iIiII1I1iIi ) . isdigit ( ) == False ) : return ( False )
  if ( oOOoOoo0 < "01" and oOOoOoo0 > "12" ) : return ( False )
  if ( iIiII1I1iIi < "01" and iIiII1I1iIi > "31" ) : return ( False )
  if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
  oo0O , i1iiIIi111 , o0OiiI1iiI11 = time . split ( ":" )
  if 3 - 3: I11i
  if ( ( oo0O + i1iiIIi111 + o0OiiI1iiI11 ) . isdigit ( ) == False ) : return ( False )
  if ( oo0O < "00" and oo0O > "23" ) : return ( False )
  if ( i1iiIIi111 < "00" and i1iiIIi111 > "59" ) : return ( False )
  if ( o0OiiI1iiI11 < "00" and o0OiiI1iiI11 > "59" ) : return ( False )
  return ( True )
  if 55 - 55: OoO0O00 . i11iIiiIii . o0oOOo0O0Ooo % iIii1I11I1II1 . I1ii11iIi11i * I11i
  if 7 - 7: OoOoOO00 * iII111i - i11iIiiIii
 def parse_datetime ( self ) :
  oo000O00O0 = self . datetime_name
  oo000O00O0 = oo000O00O0 . replace ( "-" , "" )
  oo000O00O0 = oo000O00O0 . replace ( ":" , "" )
  self . datetime = int ( oo000O00O0 )
  if 45 - 45: OoO0O00 % OoO0O00 . iIii1I11I1II1 + OoO0O00
  if 14 - 14: O0 - O0 * Ii1I
 def now ( self ) :
  i1 = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  i1 = lisp_datetime ( i1 )
  return ( i1 )
  if 87 - 87: OoooooooOO - Ii1I * II111iiii % I1Ii111
  if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 65 - 65: I1Ii111 + OOooOOo
  if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
  if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 def past ( self ) :
  return ( self . future ( ) == False )
  if 77 - 77: ooOoO0o % I1IiiI
  if 26 - 26: o0oOOo0O0Ooo
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 72 - 72: I1IiiI
  if 90 - 90: ooOoO0o
 def this_year ( self ) :
  Oo0o0o = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  i1 = str ( self . datetime ) [ 0 : 4 ]
  return ( i1 == Oo0o0o )
  if 19 - 19: IiII . I1IiiI
  if 82 - 82: I11i + II111iiii % oO0o - I1ii11iIi11i
 def this_month ( self ) :
  Oo0o0o = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  i1 = str ( self . datetime ) [ 0 : 6 ]
  return ( i1 == Oo0o0o )
  if 54 - 54: i1IIi - I11i % Oo0Ooo / i11iIiiIii
  if 83 - 83: I1IiiI * OoooooooOO % I1IiiI - oO0o
 def today ( self ) :
  Oo0o0o = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  i1 = str ( self . datetime ) [ 0 : 8 ]
  return ( i1 == Oo0o0o )
  if 93 - 93: I1ii11iIi11i - OOooOOo - II111iiii * OoO0O00 . O0 - ooOoO0o
  if 53 - 53: OoO0O00 / i11iIiiIii . OoooooooOO
  if 84 - 84: I1ii11iIi11i
  if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
  if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
  if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
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
  if 67 - 67: i1IIi * I1Ii111 * O0
  if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
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
  if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
  if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
 def match_policy_map_request ( self , mr , srloc ) :
  for oOooOO00OooO in self . match_clauses :
   IiIiIII11i1i = oOooOO00OooO . source_eid
   I1oo0O0Ooo0O00 = mr . source_eid
   if ( IiIiIII11i1i and I1oo0O0Ooo0O00 and I1oo0O0Ooo0O00 . is_more_specific ( IiIiIII11i1i ) == False ) : continue
   if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
   IiIiIII11i1i = oOooOO00OooO . dest_eid
   I1oo0O0Ooo0O00 = mr . target_eid
   if ( IiIiIII11i1i and I1oo0O0Ooo0O00 and I1oo0O0Ooo0O00 . is_more_specific ( IiIiIII11i1i ) == False ) : continue
   if 75 - 75: i11iIiiIii
   IiIiIII11i1i = oOooOO00OooO . source_rloc
   I1oo0O0Ooo0O00 = srloc
   if ( IiIiIII11i1i and I1oo0O0Ooo0O00 and I1oo0O0Ooo0O00 . is_more_specific ( IiIiIII11i1i ) == False ) : continue
   OOoOo0O0 = oOooOO00OooO . datetime_lower
   oOO0Oo000O0o = oOooOO00OooO . datetime_upper
   if ( OOoOo0O0 and oOO0Oo000O0o and OOoOo0O0 . now_in_range ( oOO0Oo000O0o ) == False ) : continue
   return ( True )
   if 17 - 17: II111iiii
  return ( False )
  if 66 - 66: O0 % OoOoOO00 + IiII % I1Ii111
  if 94 - 94: OoOoOO00 / OoooooooOO % Ii1I * i11iIiiIii
 def set_policy_map_reply ( self ) :
  oo00o0oOOo = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( oo00o0oOOo ) : return ( None )
  if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
  IIIi1iI1 = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   IIIi1iI1 . rloc . copy_address ( self . set_rloc_address )
   oOOOo0o = IIIi1iI1 . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( oOOOo0o ) )
   if 20 - 20: OoOoOO00 - IiII
  if ( self . set_rloc_record_name ) :
   IIIi1iI1 . rloc_name = self . set_rloc_record_name
   iii1IiII1ii = blue ( IIIi1iI1 . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( iii1IiII1ii ) )
   if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
  if ( self . set_geo_name ) :
   IIIi1iI1 . geo_name = self . set_geo_name
   iii1IiII1ii = IIIi1iI1 . geo_name
   ooO0OI1iiIII11I11 = "" if ( iii1IiII1ii in lisp_geo_list ) else "(not configured)"
   if 52 - 52: iII111i % I11i
   lprint ( "Policy set-geo-name '{}' {}" . format ( iii1IiII1ii , ooO0OI1iiIII11I11 ) )
   if 95 - 95: IiII + Ii1I / OoO0O00 - iII111i / I1IiiI
  if ( self . set_elp_name ) :
   IIIi1iI1 . elp_name = self . set_elp_name
   iii1IiII1ii = IIIi1iI1 . elp_name
   ooO0OI1iiIII11I11 = "" if ( iii1IiII1ii in lisp_elp_list ) else "(not configured)"
   if 27 - 27: Oo0Ooo + i1IIi + i11iIiiIii . OoO0O00 . OoO0O00
   lprint ( "Policy set-elp-name '{}' {}" . format ( iii1IiII1ii , ooO0OI1iiIII11I11 ) )
   if 56 - 56: I1Ii111 / OoO0O00 + o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
  if ( self . set_rle_name ) :
   IIIi1iI1 . rle_name = self . set_rle_name
   iii1IiII1ii = IIIi1iI1 . rle_name
   ooO0OI1iiIII11I11 = "" if ( iii1IiII1ii in lisp_rle_list ) else "(not configured)"
   if 14 - 14: OoO0O00
   lprint ( "Policy set-rle-name '{}' {}" . format ( iii1IiII1ii , ooO0OI1iiIII11I11 ) )
   if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
  if ( self . set_json_name ) :
   IIIi1iI1 . json_name = self . set_json_name
   iii1IiII1ii = IIIi1iI1 . json_name
   ooO0OI1iiIII11I11 = "" if ( iii1IiII1ii in lisp_json_list ) else "(not configured)"
   if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
   lprint ( "Policy set-json-name '{}' {}" . format ( iii1IiII1ii , ooO0OI1iiIII11I11 ) )
   if 88 - 88: IiII % iIii1I11I1II1
  return ( IIIi1iI1 )
  if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
  if 75 - 75: i11iIiiIii . iII111i
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 68 - 68: OOooOOo . I1ii11iIi11i % I1ii11iIi11i . i11iIiiIii
  if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
  if 21 - 21: O0 + i11iIiiIii
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
  if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
  if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
 def add ( self , eid_prefix ) :
  self . eid_prefix = eid_prefix
  IiIIi = self . ttl
  oo0oO = eid_prefix . print_prefix ( )
  if ( oo0oO not in lisp_pubsub_cache ) :
   lisp_pubsub_cache [ oo0oO ] = { }
   if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
  iIiii11 = lisp_pubsub_cache [ oo0oO ]
  if 52 - 52: II111iiii * o0oOOo0O0Ooo
  o0o0O0oo0 = "Add"
  if ( self . xtr_id in iIiii11 ) :
   o0o0O0oo0 = "Replace"
   del ( iIiii11 [ self . xtr_id ] )
   if 37 - 37: I1ii11iIi11i / I1IiiI + I1Ii111 % i1IIi / i1IIi
  iIiii11 [ self . xtr_id ] = self
  if 91 - 91: I11i
  oo0oO = green ( oo0oO , False )
  i11iII = red ( self . itr . print_address_no_iid ( ) , False )
  ooOOoOO000 = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( o0o0O0oo0 , oo0oO ,
 i11iII , ooOOoOO000 , IiIIi ) )
  if 94 - 94: OoO0O00
  if 19 - 19: I11i * i11iIiiIii - OoO0O00 / ooOoO0o * I1Ii111 + OoO0O00
 def delete ( self , eid_prefix ) :
  oo0oO = eid_prefix . print_prefix ( )
  i11iII = red ( self . itr . print_address_no_iid ( ) , False )
  ooOOoOO000 = "0x" + lisp_hex_string ( self . xtr_id )
  if ( oo0oO in lisp_pubsub_cache ) :
   iIiii11 = lisp_pubsub_cache [ oo0oO ]
   if ( self . xtr_id in iIiii11 ) :
    iIiii11 . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( oo0oO ,
 i11iII , ooOOoOO000 ) )
    if 30 - 30: Ii1I / iII111i * Ii1I
    if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
    if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
    if 71 - 71: i1IIi % O0 % ooOoO0o
    if 24 - 24: O0
    if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
    if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
    if 79 - 79: ooOoO0o + Oo0Ooo
    if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
    if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
    if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
    if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
    if 46 - 46: OoO0O00
    if 21 - 21: iIii1I11I1II1 - iII111i
    if 15 - 15: O0 + iII111i + i11iIiiIii
    if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
    if 52 - 52: i11iIiiIii / oO0o / IiII
    if 84 - 84: I11i . oO0o + ooOoO0o
    if 75 - 75: I1Ii111
    if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
    if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
    if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
class lisp_trace ( object ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
  if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
 def print_trace ( self ) :
  IIOO00 = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( IIOO00 ) )
  if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
  if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
 def encode ( self ) :
  II = socket . htonl ( 0x90000000 )
  OO0 = struct . pack ( "II" , II , 0 )
  OO0 += struct . pack ( "Q" , self . nonce )
  OO0 += json . dumps ( self . packet_json )
  return ( OO0 )
  if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
  if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
 def decode ( self , packet ) :
  O0oOO0o00OO = "I"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( False )
  II = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  II = socket . ntohl ( II )
  if ( ( II & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 61 - 61: OOooOOo
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( False )
  oOOOo0o = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if 80 - 80: I1ii11iIi11i
  oOOOo0o = socket . ntohl ( oOOOo0o )
  iI111I = oOOOo0o >> 24
  OooiIi11iiI11 = ( oOOOo0o >> 16 ) & 0xff
  o0OO00O0oo0O0 = ( oOOOo0o >> 8 ) & 0xff
  iIIiI = oOOOo0o & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( iI111I , OooiIi11iiI11 , o0OO00O0oo0O0 , iIIiI )
  self . local_port = str ( II & 0xffff )
  if 5 - 5: I11i / OoO0O00
  O0oOO0o00OO = "Q"
  Ii1i1iiiIiIIiIiiii = struct . calcsize ( O0oOO0o00OO )
  if ( len ( packet ) < Ii1i1iiiIiIIiIiiii ) : return ( False )
  self . nonce = struct . unpack ( O0oOO0o00OO , packet [ : Ii1i1iiiIiIIiIiiii ] ) [ 0 ]
  packet = packet [ Ii1i1iiiIiIIiIiiii : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 95 - 95: o0oOOo0O0Ooo
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 50 - 50: I11i . oO0o
  return ( True )
  if 50 - 50: Ii1I . OOooOOo
  if 84 - 84: OoOoOO00 * OoO0O00 + I1IiiI
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 38 - 38: OoooooooOO % I1IiiI
  if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  IIIi1iI1 , IiO0o = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( IIIi1iI1 == None ) :
   IIIi1iI1 , IiO0o = rts_rloc . split ( ":" )
   IiO0o = int ( IiO0o )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( IIIi1iI1 , IiO0o ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( IIIi1iI1 ,
 IiO0o ) )
   if 75 - 75: ooOoO0o
   if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
  if ( lisp_socket == None ) :
   I1iiIi111I = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   I1iiIi111I . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   I1iiIi111I . sendto ( packet , ( IIIi1iI1 , IiO0o ) )
   I1iiIi111I . close ( )
  else :
   lisp_socket . sendto ( packet , ( IIIi1iI1 , IiO0o ) )
   if 14 - 14: I11i / I11i
   if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
   if 93 - 93: oO0o / ooOoO0o - I1Ii111
 def packet_length ( self ) :
  Ii1iiI1 = 8 ; O0O0 = 4 + 4 + 8
  return ( Ii1iiI1 + O0O0 + len ( json . dumps ( self . packet_json ) ) )
  if 48 - 48: OoooooooOO / OoO0O00 - II111iiii . OoOoOO00 / Oo0Ooo . II111iiii
  if 7 - 7: i11iIiiIii . I1Ii111 . I11i . I11i % I11i / oO0o
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  IIIOoo = self . local_rloc + ":" + self . local_port
  iiIiII11i1 = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ IIIOoo ] = iiIiII11i1
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( IIIOoo , iiIiII11i1 ) )
  if 11 - 11: i1IIi . O0
  if 9 - 9: OoooooooOO % Ii1I
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  IIIOoo = local_rloc_and_port
  try : iiIiII11i1 = lisp_rtr_nat_trace_cache [ IIIOoo ]
  except : iiIiII11i1 = ( None , None )
  return ( iiIiII11i1 )
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
def lisp_get_map_server ( address ) :
 for IIo0o0oo0 in list ( lisp_map_servers_list . values ( ) ) :
  if ( IIo0o0oo0 . map_server . is_exact_match ( address ) ) : return ( IIo0o0oo0 )
  if 80 - 80: I1Ii111 . I11i - I11i + I1ii11iIi11i
 return ( None )
 if 42 - 42: I11i / IiII % O0 - Oo0Ooo
 if 33 - 33: I1Ii111
 if 1 - 1: IiII - iIii1I11I1II1 % OoooooooOO
 if 1 - 1: o0oOOo0O0Ooo - i11iIiiIii + I11i
 if 47 - 47: O0 + IiII + ooOoO0o + OOooOOo / OoOoOO00
 if 31 - 31: oO0o * iII111i % OoOoOO00
 if 80 - 80: ooOoO0o % I1ii11iIi11i % I11i . I1Ii111
def lisp_get_any_map_server ( ) :
 for IIo0o0oo0 in list ( lisp_map_servers_list . values ( ) ) : return ( IIo0o0oo0 )
 return ( None )
 if 3 - 3: ooOoO0o - Oo0Ooo
 if 2 - 2: iII111i . iII111i
 if 77 - 77: OOooOOo
 if 74 - 74: O0
 if 86 - 86: OoOoOO00
 if 4 - 4: OoooooooOO * OoO0O00
 if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
 if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
 if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
 if 6 - 6: I1IiiI - OoOoOO00
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  oOOOo0o = address . print_address ( )
  oooO = None
  for IIIOoo in lisp_map_resolvers_list :
   if ( IIIOoo . find ( oOOOo0o ) == - 1 ) : continue
   oooO = lisp_map_resolvers_list [ IIIOoo ]
   if 63 - 63: OOooOOo - oO0o * I1IiiI
  return ( oooO )
  if 60 - 60: II111iiii - Oo0Ooo
  if 43 - 43: I1IiiI - IiII - OOooOOo
  if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
  if 99 - 99: O0
  if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
  if 85 - 85: ooOoO0o / I1IiiI
  if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
 if ( eid == "" ) :
  ooOO0o0oO = ""
 elif ( eid == None ) :
  ooOO0o0oO = "all"
 else :
  iIiI1ii = lisp_db_for_lookups . lookup_cache ( eid , False )
  ooOO0o0oO = "all" if iIiI1ii == None else iIiI1ii . use_mr_name
  if 12 - 12: I1Ii111 / I11i / Ii1I
  if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
 II1IIii = None
 for oooO in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( ooOO0o0oO == "" ) : return ( oooO )
  if ( oooO . mr_name != ooOO0o0oO ) : continue
  if ( II1IIii == None or oooO . last_used < II1IIii . last_used ) : II1IIii = oooO
  if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
 return ( II1IIii )
 if 76 - 76: I1Ii111 / OoOoOO00
 if 61 - 61: Oo0Ooo . i1IIi
 if 78 - 78: i11iIiiIii
 if 20 - 20: Ii1I
 if 100 - 100: OoooooooOO . I1Ii111
 if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
 if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
 if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
def lisp_get_decent_map_resolver ( eid ) :
 OOOooo0OooOoO = lisp_get_decent_index ( eid )
 OOo0oOoOo = str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix
 if 87 - 87: ooOoO0o * II111iiii * O0 % I1IiiI
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( OOo0oOoOo , False ) , eid . print_prefix ( ) ) )
 if 69 - 69: ooOoO0o . OoooooooOO
 if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
 II1IIii = None
 for oooO in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( OOo0oOoOo != oooO . dns_name ) : continue
  if ( II1IIii == None or oooO . last_used < II1IIii . last_used ) : II1IIii = oooO
  if 88 - 88: i1IIi - OoOoOO00
 return ( II1IIii )
 if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 if 7 - 7: Ii1I / iIii1I11I1II1
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
 if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
def lisp_ipv4_input ( packet ) :
 if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
 if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
 if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
 if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
 if ( ord ( packet [ 9 ] ) == 2 ) : return ( [ True , packet ] )
 if 38 - 38: IiII
 if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
 if 2 - 2: Oo0Ooo - OoOoOO00
 if 22 - 22: OoO0O00 - oO0o - O0
 OOOoOOo0o = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( OOOoOOo0o == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  OOOoOOo0o = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( OOOoOOo0o != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( [ False , None ] )
   if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
   if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
   if 2 - 2: i11iIiiIii
   if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
   if 17 - 17: iIii1I11I1II1
   if 32 - 32: IiII - OoOoOO00
   if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
 IiIIi = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( IiIIi == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( IiIIi == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
  return ( [ False , None ] )
  if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
  if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 IiIIi -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , IiIIi ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
 if 16 - 16: Oo0Ooo
 if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 if 96 - 96: I1IiiI . oO0o % O0
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
def lisp_ipv6_input ( packet ) :
 OO0oooOO = packet . inner_dest
 packet = packet . packet
 if 87 - 87: OoooooooOO
 if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
 if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
 if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 IiIIi = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( IiIIi == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( IiIIi == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
  return ( None )
  if 45 - 45: II111iiii . iII111i
  if 55 - 55: ooOoO0o / iII111i / O0
  if 98 - 98: O0 % iII111i + II111iiii
  if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
  if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
 if ( OO0oooOO . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
  if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
 IiIIi -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , IiIIi ) + packet [ 8 : : ]
 return ( packet )
 if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 if 36 - 36: O0
 if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
 if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
 if 21 - 21: i1IIi * iII111i + OoO0O00
 if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if 85 - 85: OoooooooOO
 if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
def lisp_mac_input ( packet ) :
 return ( packet )
 if 8 - 8: I1Ii111
 if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
 if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
 if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
 if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
 if 7 - 7: i1IIi . I1IiiI
 if 68 - 68: OoooooooOO
 if 91 - 91: IiII . ooOoO0o * I11i
 if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
def lisp_rate_limit_map_request ( dest ) :
 Oo0o0o = lisp_get_timestamp ( )
 if 69 - 69: iIii1I11I1II1 . II111iiii
 if 36 - 36: I1IiiI * i1IIi + OoOoOO00
 if 63 - 63: OoOoOO00 - iII111i
 if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 Ii1i1 = Oo0o0o - lisp_no_map_request_rate_limit
 if ( Ii1i1 < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  Oo = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - Ii1i1 )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( Oo ) )
  return ( False )
  if 82 - 82: iIii1I11I1II1 / OOooOOo
  if 7 - 7: OoooooooOO
  if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
  if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
  if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
 if ( lisp_last_map_request_sent == None ) : return ( False )
 Ii1i1 = Oo0o0o - lisp_last_map_request_sent
 o0ooooO = ( Ii1i1 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
 if ( o0ooooO ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( Ii1i1 , 3 ) ) )
  if 52 - 52: OoooooooOO - OoO0O00
  if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
 return ( o0ooooO )
 if 44 - 44: OoOoOO00 + I1IiiI . I1ii11iIi11i / i1IIi + II111iiii . Oo0Ooo
 if 39 - 39: o0oOOo0O0Ooo
 if 64 - 64: oO0o - i11iIiiIii
 if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
 if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
 if 21 - 21: OoOoOO00 / OoooooooOO + I1Ii111 - IiII
 if 62 - 62: Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % iII111i % iIii1I11I1II1
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ,
 pubsub = False ) :
 global lisp_last_map_request_sent
 if 54 - 54: IiII + OoOoOO00 / II111iiii % i11iIiiIii . I1Ii111
 if 69 - 69: i1IIi + ooOoO0o + Ii1I
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
 if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
 if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 iiIii1Ii1I1 = ii11I1IiiiiI1 = None
 if ( rloc ) :
  iiIii1Ii1I1 = rloc . rloc
  ii11I1IiiiiI1 = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 36 - 36: iII111i + oO0o / I1Ii111
  if 94 - 94: iIii1I11I1II1 - IiII . i11iIiiIii
  if 88 - 88: I1IiiI / i11iIiiIii * OOooOOo
  if 3 - 3: oO0o / o0oOOo0O0Ooo - OOooOOo . OoOoOO00 * I1Ii111
  if 61 - 61: OOooOOo + OoooooooOO
 I1i1I , III1IIIii111 , iIIiI1111 = lisp_myrlocs
 if ( I1i1I == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 77 - 77: I1Ii111 - OoOoOO00
 if ( III1IIIii111 == None and iiIii1Ii1I1 != None and iiIii1Ii1I1 . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 70 - 70: I1ii11iIi11i
  if 6 - 6: Ii1I - IiII
 i1ioo = lisp_map_request ( )
 i1ioo . record_count = 1
 i1ioo . nonce = lisp_get_control_nonce ( )
 i1ioo . rloc_probe = ( iiIii1Ii1I1 != None )
 i1ioo . subscribe_bit = pubsub
 i1ioo . xtr_id_present = pubsub
 if 56 - 56: II111iiii % ooOoO0o - OoooooooOO . iIii1I11I1II1
 if 66 - 66: OoooooooOO / iIii1I11I1II1
 if 92 - 92: OoO0O00
 if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
 if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
 if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
 if 34 - 34: II111iiii + iII111i / IiII
 if ( rloc ) : rloc . last_rloc_probe_nonce = i1ioo . nonce
 if 47 - 47: OoO0O00
 OoO0o0 = deid . is_multicast_address ( )
 if ( OoO0o0 ) :
  i1ioo . target_eid = seid
  i1ioo . target_group = deid
 else :
  i1ioo . target_eid = deid
  if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
  if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
  if 100 - 100: II111iiii . IiII . I11i
  if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
  if 3 - 3: OoooooooOO
  if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
  if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
  if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
 if ( i1ioo . rloc_probe == False ) :
  iIiI1ii = lisp_get_signature_eid ( )
  if ( iIiI1ii ) :
   i1ioo . signature_eid . copy_address ( iIiI1ii . eid )
   i1ioo . privkey_filename = "./lisp-sig.pem"
   if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
   if 37 - 37: I1ii11iIi11i * IiII
   if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
   if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
   if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
   if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
 if ( seid == None or OoO0o0 ) :
  i1ioo . source_eid . afi = LISP_AFI_NONE
 else :
  i1ioo . source_eid = seid
  if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
  if 78 - 78: oO0o
  if 33 - 33: oO0o + i1IIi
  if 32 - 32: iIii1I11I1II1
  if 71 - 71: Ii1I * I1IiiI
  if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
  if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
  if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
  if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
  if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
  if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
  if 89 - 89: I1ii11iIi11i . OoooooooOO
 if ( iiIii1Ii1I1 != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( iiIii1Ii1I1 . is_private_address ( ) == False ) :
   I1i1I = lisp_get_any_translated_rloc ( )
   if 61 - 61: i1IIi + i11iIiiIii
  if ( I1i1I == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
   if 97 - 97: OoO0O00 - I11i . OoooooooOO
   if 58 - 58: I1ii11iIi11i / II111iiii / i11iIiiIii
   if 27 - 27: iIii1I11I1II1 - O0 + OoOoOO00
   if 28 - 28: oO0o . IiII * iII111i % Oo0Ooo - OoO0O00 / I11i
   if 67 - 67: i11iIiiIii + i11iIiiIii / ooOoO0o - o0oOOo0O0Ooo
   if 94 - 94: O0 + OoO0O00 / I1IiiI * II111iiii * i11iIiiIii
   if 55 - 55: OoooooooOO * O0 + i1IIi % I1IiiI
 if ( iiIii1Ii1I1 == None or iiIii1Ii1I1 . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and iiIii1Ii1I1 == None ) :
   Iii1i1Ii = lisp_get_any_translated_rloc ( )
   if ( Iii1i1Ii != None ) : I1i1I = Iii1i1Ii
   if 79 - 79: I1IiiI * O0 . Ii1I
  i1ioo . itr_rlocs . append ( I1i1I )
  if 24 - 24: ooOoO0o * OoOoOO00 * iIii1I11I1II1 * iII111i + I1IiiI - II111iiii
 if ( iiIii1Ii1I1 == None or iiIii1Ii1I1 . is_ipv6 ( ) ) :
  if ( III1IIIii111 == None or III1IIIii111 . is_ipv6_link_local ( ) ) :
   III1IIIii111 = None
  else :
   i1ioo . itr_rloc_count = 1 if ( iiIii1Ii1I1 == None ) else 0
   i1ioo . itr_rlocs . append ( III1IIIii111 )
   if 31 - 31: oO0o / I1ii11iIi11i
   if 96 - 96: i1IIi + i1IIi * I1Ii111 . II111iiii % OoooooooOO
   if 58 - 58: IiII
   if 64 - 64: iIii1I11I1II1 / OoOoOO00
   if 14 - 14: Ii1I / OoooooooOO . i1IIi % IiII % i11iIiiIii
   if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
   if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
   if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
   if 19 - 19: o0oOOo0O0Ooo
 if ( iiIii1Ii1I1 != None and i1ioo . itr_rlocs != [ ] ) :
  oo00O0OO0Ooo0 = i1ioo . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   oo00O0OO0Ooo0 = I1i1I
  elif ( deid . is_ipv6 ( ) ) :
   oo00O0OO0Ooo0 = III1IIIii111
  else :
   oo00O0OO0Ooo0 = I1i1I
   if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
   if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
   if 71 - 71: OoO0O00 - I11i
   if 96 - 96: I1Ii111 / Ii1I
   if 65 - 65: I1ii11iIi11i * O0 . IiII
   if 11 - 11: I11i / Ii1I % oO0o
 OO0 = i1ioo . encode ( iiIii1Ii1I1 , ii11I1IiiiiI1 )
 i1ioo . print_map_request ( )
 if 50 - 50: i11iIiiIii
 if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
 if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
 if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 if 4 - 4: I1IiiI
 if 36 - 36: Ii1I
 if ( iiIii1Ii1I1 != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   o0O00Oo = lisp_get_nat_info ( iiIii1Ii1I1 , rloc . rloc_name )
   if 76 - 76: i11iIiiIii + i1IIi
   if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
   if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
   if 76 - 76: Ii1I * iII111i . OoooooooOO
   if ( o0O00Oo == None ) :
    OOoooo = rloc . rloc . print_address_no_iid ( )
    o0O0Ooo = "gleaned-{}" . format ( OOoooo )
    IiIiIII11i1i = rloc . translated_port
    o0O00Oo = lisp_nat_info ( OOoooo , o0O0Ooo , IiIiIII11i1i )
    if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
   lisp_encapsulate_rloc_probe ( lisp_sockets , iiIii1Ii1I1 , o0O00Oo ,
 OO0 )
   return
   if 44 - 44: I1Ii111 - II111iiii / OOooOOo
   if 50 - 50: I11i / I1ii11iIi11i
  Oo0o = iiIii1Ii1I1 . print_address_no_iid ( )
  OO0oooOO = lisp_convert_4to6 ( Oo0o )
  lisp_send ( lisp_sockets , OO0oooOO , LISP_CTRL_PORT , OO0 )
  return
  if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
  if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
  if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
  if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
  if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
  if 48 - 48: O0
 OooOOOOOOO0 = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  oooO = lisp_get_decent_map_resolver ( deid )
 else :
  oooO = lisp_get_map_resolver ( None , OooOOOOOOO0 )
  if 30 - 30: OoOoOO00 % iII111i * OoooooooOO + OOooOOo + Oo0Ooo
 if ( oooO == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 68 - 68: OoO0O00 * ooOoO0o / iII111i
  return
  if 96 - 96: Ii1I + I11i + II111iiii * I1IiiI / Oo0Ooo % I1Ii111
 oooO . last_used = lisp_get_timestamp ( )
 oooO . map_requests_sent += 1
 if ( oooO . last_nonce == 0 ) : oooO . last_nonce = i1ioo . nonce
 if 65 - 65: iII111i
 if 75 - 75: iIii1I11I1II1 - Oo0Ooo + Ii1I + ooOoO0o
 if 62 - 62: OOooOOo
 if 13 - 13: OOooOOo . i11iIiiIii
 if ( seid == None ) : seid = oo00O0OO0Ooo0
 lisp_send_ecm ( lisp_sockets , OO0 , seid , lisp_ephem_port , deid ,
 oooO . map_resolver )
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 if 79 - 79: oO0o
 if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
 if 8 - 8: iII111i
 if 10 - 10: OoOoOO00 % I11i
 oooO . resolve_dns_name ( )
 return
 if 49 - 49: oO0o % ooOoO0o + II111iiii
 if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
 if 99 - 99: OoOoOO00
 if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
 if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
 if 8 - 8: oO0o
 if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
 if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 1 - 1: OoooooooOO . Ii1I
 if 68 - 68: Ii1I
 if 98 - 98: iII111i
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 iiIIiIII11IIii = lisp_info ( )
 iiIIiIII11IIii . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : iiIIiIII11IIii . hostname += "-" + device_name
 if 13 - 13: O0 - I1Ii111
 Oo0o = dest . print_address_no_iid ( )
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
 if 100 - 100: O0 . iII111i / iIii1I11I1II1
 i1I1II = False
 if ( device_name ) :
  OOo00o0O = lisp_get_host_route_next_hop ( Oo0o )
  if 25 - 25: i1IIi - iIii1I11I1II1
  if 79 - 79: OoooooooOO . ooOoO0o % ooOoO0o % iII111i * IiII - OoO0O00
  if 14 - 14: o0oOOo0O0Ooo / O0 - iIii1I11I1II1
  if 88 - 88: OoooooooOO
  if 23 - 23: iII111i - IiII % i11iIiiIii
  if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
  if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
  if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
  if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
  if ( port == LISP_CTRL_PORT and OOo00o0O != None ) :
   while ( True ) :
    time . sleep ( .01 )
    OOo00o0O = lisp_get_host_route_next_hop ( Oo0o )
    if ( OOo00o0O == None ) : break
    if 11 - 11: II111iiii + i1IIi
    if 1 - 1: OOooOOo
    if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
  oOOO = lisp_get_default_route_next_hops ( )
  for iIIiI1111 , o00o0O0O0oO0o in oOOO :
   if ( iIIiI1111 != device_name ) : continue
   if 54 - 54: I1IiiI + IiII
   if 7 - 7: Ii1I % I1Ii111 + I1ii11iIi11i * IiII . OoO0O00 / I11i
   if 39 - 39: Oo0Ooo + OOooOOo . I1IiiI + OoO0O00 . OoooooooOO
   if 31 - 31: OoO0O00
   if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
   if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
   if ( OOo00o0O != o00o0O0O0oO0o ) :
    if ( OOo00o0O != None ) :
     lisp_install_host_route ( Oo0o , OOo00o0O , False )
     if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
    lisp_install_host_route ( Oo0o , o00o0O0O0oO0o , True )
    i1I1II = True
    if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
   break
   if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
   if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
   if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
   if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
   if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
   if 74 - 74: OoooooooOO + Ii1I
 OO0 = iiIIiIII11IIii . encode ( )
 iiIIiIII11IIii . print_info ( )
 if 100 - 100: I1IiiI
 if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 II1i11i1 = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 II1i11i1 = bold ( II1i11i1 , False )
 IiIiIII11i1i = bold ( "{}" . format ( port ) , False )
 OoOOOO = red ( Oo0o , False )
 IiIi1I1i1iIiI = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( IiIi1I1i1iIiI , OoOOOO , IiIiIII11i1i , II1i11i1 ) )
 if 70 - 70: iIii1I11I1II1 - i11iIiiIii * OOooOOo
 if 17 - 17: ooOoO0o / IiII
 if 4 - 4: i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoO0O00 . OOooOOo
 if 5 - 5: I1IiiI / OoOoOO00 / i11iIiiIii
 if 59 - 59: I11i - Ii1I - O0
 if 7 - 7: OoooooooOO
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , OO0 )
 else :
  o0O0OOooO = lisp_data_header ( )
  o0O0OOooO . instance_id ( 0xffffff )
  o0O0OOooO = o0O0OOooO . encode ( )
  if ( o0O0OOooO ) :
   OO0 = o0O0OOooO + OO0
   if 13 - 13: I11i - o0oOOo0O0Ooo - O0 % Oo0Ooo - oO0o * OoOoOO00
   if 76 - 76: IiII
   if 88 - 88: o0oOOo0O0Ooo * II111iiii % Oo0Ooo * I1ii11iIi11i . I1IiiI % I1ii11iIi11i
   if 37 - 37: OOooOOo % OoO0O00 % oO0o . I11i / OOooOOo
   if 8 - 8: iIii1I11I1II1 + O0 + IiII - IiII * I1Ii111 / i1IIi
   if 10 - 10: Oo0Ooo . i11iIiiIii + iIii1I11I1II1 % iII111i + i11iIiiIii
   if 6 - 6: OoOoOO00 + OOooOOo + Oo0Ooo
   if 43 - 43: IiII * iII111i . ooOoO0o / I1ii11iIi11i . ooOoO0o * II111iiii
   if 30 - 30: iII111i
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , OO0 )
   if 51 - 51: ooOoO0o + oO0o
   if 80 - 80: O0 - I1Ii111 * Ii1I + I1ii11iIi11i % II111iiii . I11i
   if 80 - 80: OoOoOO00 - OOooOOo
   if 37 - 37: ooOoO0o
   if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
   if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
   if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if ( i1I1II ) :
  lisp_install_host_route ( Oo0o , None , False )
  if ( OOo00o0O != None ) : lisp_install_host_route ( Oo0o , OOo00o0O , True )
  if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 return
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
 if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
 if 44 - 44: O0
 if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
 if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
 if 79 - 79: II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 iiIIiIII11IIii = lisp_info ( )
 packet = iiIIiIII11IIii . decode ( packet )
 if ( packet == None ) : return
 iiIIiIII11IIii . print_info ( )
 if 32 - 32: O0 + IiII
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 17 - 17: OOooOOo
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 iiIIiIII11IIii . info_reply = True
 iiIIiIII11IIii . global_etr_rloc . store_address ( addr_str )
 iiIIiIII11IIii . etr_port = sport
 if 46 - 46: II111iiii * OoO0O00
 if 77 - 77: ooOoO0o * I11i
 if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
 if 76 - 76: iII111i * OoooooooOO
 if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
 if ( iiIIiIII11IIii . hostname != None ) :
  iiIIiIII11IIii . private_etr_rloc . afi = LISP_AFI_NAME
  iiIIiIII11IIii . private_etr_rloc . store_address ( iiIIiIII11IIii . hostname )
  if 51 - 51: i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
 if ( rtr_list != None ) : iiIIiIII11IIii . rtr_list = rtr_list
 packet = iiIIiIII11IIii . encode ( )
 iiIIiIII11IIii . print_info ( )
 if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 if 63 - 63: II111iiii - Oo0Ooo
 if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
 if 78 - 78: IiII - I1IiiI
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 OO0oooOO = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , OO0oooOO , sport , packet )
 if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
 if 71 - 71: OoO0O00
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 if 54 - 54: Ii1I / I1IiiI
 IiiI = lisp_info_source ( iiIIiIII11IIii . hostname , addr_str , sport )
 IiiI . cache_address_for_info_source ( )
 return
 if 87 - 87: i1IIi + O0 % iII111i * iIii1I11I1II1 + II111iiii
 if 59 - 59: OoooooooOO . ooOoO0o / OOooOOo - OOooOOo / iIii1I11I1II1 / oO0o
 if 58 - 58: iIii1I11I1II1 - OoO0O00
 if 74 - 74: o0oOOo0O0Ooo . OOooOOo
 if 96 - 96: OoooooooOO
 if 19 - 19: Ii1I / OoooooooOO
 if 67 - 67: I1ii11iIi11i - OoooooooOO + OoooooooOO * o0oOOo0O0Ooo * iII111i
 if 30 - 30: I1ii11iIi11i % Ii1I
def lisp_get_signature_eid ( ) :
 for iIiI1ii in lisp_db_list :
  if ( iIiI1ii . signature_eid ) : return ( iIiI1ii )
  if 2 - 2: I1IiiI . IiII . iIii1I11I1II1 - OOooOOo
 return ( None )
 if 56 - 56: OoooooooOO + I1IiiI / I11i % i11iIiiIii / o0oOOo0O0Ooo / Ii1I
 if 27 - 27: oO0o
 if 98 - 98: OoOoOO00 . oO0o + I1ii11iIi11i
 if 14 - 14: OoooooooOO
 if 73 - 73: OoOoOO00 % o0oOOo0O0Ooo
 if 28 - 28: OoO0O00
 if 15 - 15: OoO0O00 . I11i
 if 64 - 64: OOooOOo + I1Ii111 - o0oOOo0O0Ooo . II111iiii * Ii1I
def lisp_get_any_translated_port ( ) :
 for iIiI1ii in lisp_db_list :
  for O0O0OOo0O in iIiI1ii . rloc_set :
   if ( O0O0OOo0O . translated_rloc . is_null ( ) ) : continue
   return ( O0O0OOo0O . translated_port )
   if 88 - 88: I1ii11iIi11i + OoooooooOO % I1ii11iIi11i
   if 3 - 3: I1Ii111 . O0 * OOooOOo * I11i + Ii1I * I1IiiI
 return ( None )
 if 18 - 18: iIii1I11I1II1 % ooOoO0o . o0oOOo0O0Ooo * iII111i % iII111i
 if 64 - 64: I1Ii111 . I11i
 if 32 - 32: I1ii11iIi11i + IiII % OoOoOO00 . O0
 if 70 - 70: IiII + iII111i . i11iIiiIii + OoO0O00
 if 45 - 45: o0oOOo0O0Ooo - ooOoO0o
 if 2 - 2: OOooOOo + iII111i * ooOoO0o + II111iiii
 if 88 - 88: ooOoO0o * OoO0O00 * I1ii11iIi11i - I1IiiI * IiII * I11i
 if 37 - 37: iIii1I11I1II1
 if 50 - 50: o0oOOo0O0Ooo - OOooOOo * IiII % Oo0Ooo
def lisp_get_any_translated_rloc ( ) :
 for iIiI1ii in lisp_db_list :
  for O0O0OOo0O in iIiI1ii . rloc_set :
   if ( O0O0OOo0O . translated_rloc . is_null ( ) ) : continue
   return ( O0O0OOo0O . translated_rloc )
   if 81 - 81: OoooooooOO - OoOoOO00 % I1ii11iIi11i % I1ii11iIi11i + OoOoOO00
   if 49 - 49: Ii1I + iIii1I11I1II1 . O0 * OOooOOo * OoooooooOO - OOooOOo
 return ( None )
 if 23 - 23: iIii1I11I1II1 % I11i . OoO0O00 / i11iIiiIii % O0 * Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
def lisp_get_all_translated_rlocs ( ) :
 IIiIIiiI11 = [ ]
 for iIiI1ii in lisp_db_list :
  for O0O0OOo0O in iIiI1ii . rloc_set :
   if ( O0O0OOo0O . is_rloc_translated ( ) == False ) : continue
   oOOOo0o = O0O0OOo0O . translated_rloc . print_address_no_iid ( )
   IIiIIiiI11 . append ( oOOOo0o )
   if 92 - 92: I1IiiI + oO0o % iII111i
   if 47 - 47: ooOoO0o . OOooOOo . oO0o + oO0o + i1IIi + iIii1I11I1II1
 return ( IIiIIiiI11 )
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 if 89 - 89: I11i % II111iiii
 if 35 - 35: oO0o
 if 65 - 65: II111iiii
 if 87 - 87: oO0o / OoO0O00 - oO0o
 if 69 - 69: i11iIiiIii
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 IiI1iiIIiIiii = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
 IIII1IiI = { }
 for IIIi1iI1 in rtr_list :
  if ( IIIi1iI1 == None ) : continue
  oOOOo0o = rtr_list [ IIIi1iI1 ]
  if ( IiI1iiIIiIiii and oOOOo0o . is_private_address ( ) ) : continue
  IIII1IiI [ IIIi1iI1 ] = oOOOo0o
  if 92 - 92: I1ii11iIi11i + iII111i
 rtr_list = IIII1IiI
 if 55 - 55: ooOoO0o
 ooO00O = [ ]
 for ii11IiI in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( ii11IiI == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 80 - 80: OoO0O00 / Ii1I . IiII % o0oOOo0O0Ooo
  if 92 - 92: i1IIi + IiII - iIii1I11I1II1 + i1IIi * ooOoO0o - i11iIiiIii
  if 68 - 68: o0oOOo0O0Ooo + IiII / iII111i - i11iIiiIii / OOooOOo
  if 62 - 62: I1IiiI
  if 42 - 42: II111iiii
  Ii1IIIIi = lisp_address ( ii11IiI , "" , 0 , iid )
  Ii1IIIIi . make_default_route ( Ii1IIIIi )
  I111I1iI1 = lisp_map_cache . lookup_cache ( Ii1IIIIi , True )
  if ( I111I1iI1 ) :
   if ( I111I1iI1 . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( I111I1iI1 . print_eid_tuple ( ) , False ) ) )
    if 49 - 49: OoooooooOO
   elif ( I111I1iI1 . do_rloc_sets_match ( list ( rtr_list . values ( ) ) ) ) :
    continue
    if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
   I111I1iI1 . delete_cache ( )
   if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
   if 6 - 6: oO0o / II111iiii
  ooO00O . append ( [ Ii1IIIIi , "" ] )
  if 23 - 23: IiII - OoooooooOO / oO0o
  if 69 - 69: O0 - OoooooooOO
  if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
  if 50 - 50: IiII - OOooOOo % OoOoOO00
  iiI = lisp_address ( ii11IiI , "" , 0 , iid )
  iiI . make_default_multicast_route ( iiI )
  o0oOOoo000o0 = lisp_map_cache . lookup_cache ( iiI , True )
  if ( o0oOOoo000o0 ) : o0oOOoo000o0 = o0oOOoo000o0 . source_cache . lookup_cache ( Ii1IIIIi , True )
  if ( o0oOOoo000o0 ) : o0oOOoo000o0 . delete_cache ( )
  if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
  ooO00O . append ( [ Ii1IIIIi , iiI ] )
  if 64 - 64: OOooOOo / OoOoOO00
 if ( len ( ooO00O ) == 0 ) : return
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 IIiii11iiI111 = [ ]
 for IiIi1I1i1iIiI in rtr_list :
  IIi1iIiiIIi = rtr_list [ IiIi1I1i1iIiI ]
  O0O0OOo0O = lisp_rloc ( )
  O0O0OOo0O . rloc . copy_address ( IIi1iIiiIIi )
  O0O0OOo0O . priority = 254
  O0O0OOo0O . mpriority = 255
  O0O0OOo0O . rloc_name = "RTR"
  IIiii11iiI111 . append ( O0O0OOo0O )
  if 90 - 90: OoooooooOO
  if 24 - 24: ooOoO0o % Ii1I - OoO0O00 + IiII
 for Ii1IIIIi in ooO00O :
  I111I1iI1 = lisp_mapping ( Ii1IIIIi [ 0 ] , Ii1IIIIi [ 1 ] , IIiii11iiI111 )
  I111I1iI1 . mapping_source = map_resolver
  I111I1iI1 . map_cache_ttl = LISP_MR_TTL * 60
  I111I1iI1 . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( I111I1iI1 . print_eid_tuple ( ) , False ) , list ( rtr_list . keys ( ) ) ) )
  if 56 - 56: II111iiii - oO0o % o0oOOo0O0Ooo % iII111i . IiII . i11iIiiIii
  IIiii11iiI111 = copy . deepcopy ( IIiii11iiI111 )
  if 17 - 17: II111iiii % OoooooooOO / II111iiii / i1IIi
 return
 if 13 - 13: i1IIi * O0 . I11i . I1IiiI . i11iIiiIii
 if 3 - 3: OoooooooOO
 if 1 - 1: oO0o - i11iIiiIii . OoOoOO00
 if 16 - 16: OOooOOo
 if 33 - 33: o0oOOo0O0Ooo / OoO0O00 + OoooooooOO
 if 82 - 82: o0oOOo0O0Ooo / i1IIi / i11iIiiIii * Oo0Ooo / OoO0O00
 if 95 - 95: I11i . OoOoOO00 * Ii1I
 if 94 - 94: OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
 if 55 - 55: II111iiii - IiII
 if 24 - 24: oO0o % Ii1I / i1IIi
def lisp_process_info_reply ( source , packet , store ) :
 if 84 - 84: i1IIi
 if 53 - 53: OoooooooOO - i1IIi - Ii1I
 if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
 if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
 iiIIiIII11IIii = lisp_info ( )
 packet = iiIIiIII11IIii . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 34 - 34: Ii1I
 iiIIiIII11IIii . print_info ( )
 if 5 - 5: II111iiii . I1ii11iIi11i
 if 85 - 85: I1Ii111 . IiII + II111iiii
 if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
 if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
 IIi111i1 = False
 for IiIi1I1i1iIiI in iiIIiIII11IIii . rtr_list :
  Oo0o = IiIi1I1i1iIiI . print_address_no_iid ( )
  if ( Oo0o in lisp_rtr_list ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ Oo0o ] != None ) : continue
   if 44 - 44: Oo0Ooo + iIii1I11I1II1
  IIi111i1 = True
  lisp_rtr_list [ Oo0o ] = IiIi1I1i1iIiI
  if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
  if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
  if 10 - 10: O0 / I11i
  if 29 - 29: i11iIiiIii % I11i
  if 49 - 49: I11i
 if ( lisp_i_am_itr and IIi111i1 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for i1oO00O in list ( lisp_iid_to_interface . keys ( ) ) :
    lisp_update_default_routes ( source , int ( i1oO00O ) , lisp_rtr_list )
    if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
    if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
    if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
    if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
    if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
    if 32 - 32: O0
    if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
 if ( store == False ) :
  return ( [ iiIIiIII11IIii . global_etr_rloc , iiIIiIII11IIii . etr_port , IIi111i1 ] )
  if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
  if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
  if 70 - 70: iIii1I11I1II1 - I11i
  if 2 - 2: oO0o / II111iiii * OoO0O00
  if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
  if 40 - 40: OOooOOo
 for iIiI1ii in lisp_db_list :
  for O0O0OOo0O in iIiI1ii . rloc_set :
   IIIi1iI1 = O0O0OOo0O . rloc
   OooOO = O0O0OOo0O . interface
   if ( OooOO == None ) :
    if ( IIIi1iI1 . is_null ( ) ) : continue
    if ( IIIi1iI1 . is_local ( ) == False ) : continue
    if ( iiIIiIII11IIii . private_etr_rloc . is_null ( ) == False and
 IIIi1iI1 . is_exact_match ( iiIIiIII11IIii . private_etr_rloc ) == False ) :
     continue
     if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
   elif ( iiIIiIII11IIii . private_etr_rloc . is_dist_name ( ) ) :
    i1Ii1iiI = iiIIiIII11IIii . private_etr_rloc . address
    if ( i1Ii1iiI != O0O0OOo0O . rloc_name ) : continue
    if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
    if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
   iIiI1I1ii1I1 = green ( iIiI1ii . eid . print_prefix ( ) , False )
   iiIIii = red ( IIIi1iI1 . print_address_no_iid ( ) , False )
   if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
   II1Iii1Ii11I = iiIIiIII11IIii . global_etr_rloc . is_exact_match ( IIIi1iI1 )
   if ( O0O0OOo0O . translated_port == 0 and II1Iii1Ii11I ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( iiIIii ,
 OooOO , iIiI1I1ii1I1 ) )
    continue
    if 14 - 14: I1ii11iIi11i / i1IIi . ooOoO0o % OoO0O00 * OoO0O00 + oO0o
    if 65 - 65: Oo0Ooo % iIii1I11I1II1
    if 40 - 40: iII111i + Ii1I . OoooooooOO . i1IIi
    if 7 - 7: I1ii11iIi11i - Ii1I % Ii1I
    if 75 - 75: O0 . II111iiii + Oo0Ooo * O0 - IiII % OoOoOO00
   O0o0OOoo = iiIIiIII11IIii . global_etr_rloc
   i1IIIIIi111 = O0O0OOo0O . translated_rloc
   if ( i1IIIIIi111 . is_exact_match ( O0o0OOoo ) and
 iiIIiIII11IIii . etr_port == O0O0OOo0O . translated_port ) : continue
   if 10 - 10: o0oOOo0O0Ooo + ooOoO0o + Oo0Ooo
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( iiIIiIII11IIii . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # II111iiii - I1ii11iIi11i / I11i . I1Ii111
 iiIIiIII11IIii . etr_port , iiIIii , OooOO , iIiI1I1ii1I1 ) )
   if 17 - 17: iII111i + I11i - iII111i
   O0O0OOo0O . store_translated_rloc ( iiIIiIII11IIii . global_etr_rloc ,
 iiIIiIII11IIii . etr_port )
   if 61 - 61: o0oOOo0O0Ooo % OoOoOO00 * Ii1I . iII111i
   if 21 - 21: Ii1I / iIii1I11I1II1 / iIii1I11I1II1 / OOooOOo % OoOoOO00
 return ( [ iiIIiIII11IIii . global_etr_rloc , iiIIiIII11IIii . etr_port , IIi111i1 ] )
 if 6 - 6: I1IiiI / o0oOOo0O0Ooo * IiII * OOooOOo - iII111i
 if 28 - 28: O0 - I11i / OoOoOO00 / oO0o
 if 41 - 41: i11iIiiIii + Oo0Ooo - OoO0O00 . i11iIiiIii / i11iIiiIii / Ii1I
 if 49 - 49: O0 % Oo0Ooo * I11i
 if 40 - 40: II111iiii
 if 56 - 56: II111iiii * iII111i
 if 51 - 51: I1IiiI . ooOoO0o / Ii1I / I1Ii111
 if 84 - 84: I11i - Ii1I
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 36 - 36: i1IIi
 oo0oO = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 I1oOo0o00oo = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 1 - 1: iII111i - OoOoOO00 + II111iiii + o0oOOo0O0Ooo % iIii1I11I1II1 - OOooOOo
 if 60 - 60: ooOoO0o % iIii1I11I1II1 / iIii1I11I1II1
 if 61 - 61: oO0o
 if 12 - 12: iIii1I11I1II1 - I1ii11iIi11i % I1ii11iIi11i * I1Ii111
 oo0oO . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , oo0oO , None )
 oo0oO . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , oo0oO , None )
 if 98 - 98: oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o - OoO0O00
 if 12 - 12: IiII . OoooooooOO - iIii1I11I1II1 % iII111i
 if 56 - 56: Oo0Ooo / I1IiiI + iIii1I11I1II1 + I1IiiI % iIii1I11I1II1
 if 64 - 64: O0
 I1oOo0o00oo . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , I1oOo0o00oo , None )
 I1oOo0o00oo . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , I1oOo0o00oo , None )
 if 55 - 55: OoO0O00 * oO0o . Ii1I + OoOoOO00 % I11i + IiII
 if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
 if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
 if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
 I1iii1iiiI = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 I1iii1iiiI . start ( )
 return
 if 1 - 1: Oo0Ooo / i11iIiiIii * Oo0Ooo
 if 54 - 54: OOooOOo / IiII / II111iiii
 if 19 - 19: I1Ii111 . I1Ii111
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
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
 oOOOo0o = lisp_get_interface_address ( rloc . interface )
 if ( oOOOo0o == None ) : return
 if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
 o0Oo0000o00 = rloc . rloc . print_address_no_iid ( )
 o000ooOo0o0Oo = oOOOo0o . print_address_no_iid ( )
 if 95 - 95: iII111i + OoooooooOO + O0 . OoOoOO00 + I1ii11iIi11i
 if ( o0Oo0000o00 == o000ooOo0o0Oo ) : return
 if 79 - 79: OoooooooOO / iII111i / IiII . OoooooooOO
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , o0Oo0000o00 , o000ooOo0o0Oo ) )
 if 92 - 92: I11i + O0 % II111iiii - I1ii11iIi11i + OoooooooOO . iIii1I11I1II1
 if 85 - 85: O0 - ooOoO0o
 rloc . rloc . copy_address ( oOOOo0o )
 lisp_myrlocs [ 0 ] = oOOOo0o
 return
 if 35 - 35: o0oOOo0O0Ooo - I1IiiI
 if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
 if 65 - 65: Ii1I % i11iIiiIii
 if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
 if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
 if 88 - 88: iII111i
 if 94 - 94: OoooooooOO
def lisp_update_encap_port ( mc ) :
 for IIIi1iI1 in mc . rloc_set :
  o0O00Oo = lisp_get_nat_info ( IIIi1iI1 . rloc , IIIi1iI1 . rloc_name )
  if ( o0O00Oo == None ) : continue
  if ( IIIi1iI1 . translated_port == o0O00Oo . port ) : continue
  if 32 - 32: I1ii11iIi11i
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( IIIi1iI1 . translated_port , o0O00Oo . port ,
  # OoOoOO00
 red ( IIIi1iI1 . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 93 - 93: i11iIiiIii - OoOoOO00 * i11iIiiIii % OoooooooOO * I1IiiI
  IIIi1iI1 . store_translated_rloc ( IIIi1iI1 . rloc , o0O00Oo . port )
  if 84 - 84: I1Ii111
 return
 if 82 - 82: OOooOOo . iII111i
 if 65 - 65: oO0o
 if 18 - 18: i1IIi % I11i * OoOoOO00 - I11i + OoO0O00 - O0
 if 36 - 36: iIii1I11I1II1 * iII111i / IiII % i1IIi
 if 8 - 8: I11i
 if 33 - 33: I1Ii111 . I11i . Ii1I - iIii1I11I1II1
 if 96 - 96: II111iiii % oO0o . i1IIi + II111iiii . iII111i
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 if 64 - 64: oO0o / IiII
 if 86 - 86: I11i
 if 36 - 36: o0oOOo0O0Ooo / OoO0O00
 if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
  if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 Oo0o0o = lisp_get_timestamp ( )
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
 if 86 - 86: i11iIiiIii
 if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if ( mc . last_refresh_time + mc . map_cache_ttl > Oo0o0o ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 79 - 79: I11i - II111iiii
  if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
  if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
  if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
  if 44 - 44: I1IiiI * IiII . OoooooooOO
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
  if 10 - 10: i1IIi + o0oOOo0O0Ooo
  if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
  if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
  if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 Ii1i1 = lisp_print_elapsed ( mc . last_refresh_time )
 oOo00OO0ooo = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( oOo00OO0ooo , False ) , bold ( "timed out" , False ) , Ii1i1 ) )
 if 2 - 2: I11i
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
 if 16 - 16: i11iIiiIii * Oo0Ooo
 if 76 - 76: iII111i . oO0o - i1IIi
 if 94 - 94: O0 % iII111i
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
def lisp_timeout_map_cache_walk ( mc , parms ) :
 ooOOOoo0O00 = parms [ 0 ]
 iiIIIii = parms [ 1 ]
 if 46 - 46: ooOoO0o % iIii1I11I1II1 / Oo0Ooo * I1Ii111 / iII111i
 if 89 - 89: ooOoO0o + OoooooooOO - O0 * o0oOOo0O0Ooo . o0oOOo0O0Ooo * i11iIiiIii
 if 10 - 10: Oo0Ooo % II111iiii
 if 28 - 28: OoooooooOO / iII111i / iIii1I11I1II1
 if ( mc . group . is_null ( ) ) :
  iiI1i , ooOOOoo0O00 = lisp_timeout_map_cache_entry ( mc , ooOOOoo0O00 )
  if ( ooOOOoo0O00 == [ ] or mc != ooOOOoo0O00 [ - 1 ] ) :
   iiIIIii = lisp_write_checkpoint_entry ( iiIIIii , mc )
   if 72 - 72: I1ii11iIi11i - OoooooooOO
  return ( [ iiI1i , parms ] )
  if 5 - 5: iIii1I11I1II1 % ooOoO0o / II111iiii
  if 44 - 44: O0 % OoooooooOO
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 6 - 6: I1IiiI / I1ii11iIi11i . I1ii11iIi11i + iIii1I11I1II1
 if 78 - 78: OOooOOo . I1Ii111
 if 60 - 60: i1IIi
 if 69 - 69: O0 * iII111i % I11i . O0 * Ii1I - I1IiiI
 if 9 - 9: IiII - I1Ii111 % iIii1I11I1II1 . i1IIi / OOooOOo . i1IIi
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 63 - 63: II111iiii . oO0o * IiII
 if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
 if 47 - 47: I11i
 if 88 - 88: OoO0O00 - OoooooooOO
 if 93 - 93: Oo0Ooo * I1IiiI
 if 60 - 60: I1Ii111 + OOooOOo % iII111i
 if 40 - 40: I11i + oO0o . O0 % oO0o
def lisp_timeout_map_cache ( lisp_map_cache ) :
 i1iiI = [ [ ] , [ ] ]
 i1iiI = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , i1iiI )
 if 12 - 12: iIii1I11I1II1
 if 9 - 9: OoOoOO00 * II111iiii / o0oOOo0O0Ooo * iII111i - II111iiii / i11iIiiIii
 if 14 - 14: i11iIiiIii + I1Ii111 . OoOoOO00 - oO0o * OoO0O00
 if 23 - 23: iIii1I11I1II1
 if 32 - 32: iII111i * iIii1I11I1II1 + I1Ii111 + IiII + O0 * OoO0O00
 ooOOOoo0O00 = i1iiI [ 0 ]
 for I111I1iI1 in ooOOOoo0O00 : I111I1iI1 . delete_cache ( )
 if 100 - 100: II111iiii
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
 if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
 iiIIIii = i1iiI [ 1 ]
 lisp_checkpoint ( iiIIIii )
 return
 if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
 if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
 if 40 - 40: o0oOOo0O0Ooo * I1IiiI
 if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
 if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
 if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
 if 16 - 16: oO0o
 if 32 - 32: OoooooooOO
 if 77 - 77: Oo0Ooo . i1IIi - I11i
 if 98 - 98: O0
 if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
 if 54 - 54: i1IIi % iII111i
 if 16 - 16: II111iiii - Oo0Ooo
 if 44 - 44: OOooOOo / Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if 85 - 85: iIii1I11I1II1 / Ii1I
def lisp_store_nat_info ( hostname , rloc , port ) :
 Oo0o = rloc . print_address_no_iid ( )
 IiI1iIiii1i = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( Oo0o , False ) , port )
 if 38 - 38: i1IIi - I1IiiI % I1Ii111 . I11i - iII111i / IiII
 O0iI1ii1II1i111 = lisp_nat_info ( Oo0o , hostname , port )
 if 80 - 80: OoOoOO00 . ooOoO0o - iIii1I11I1II1 / o0oOOo0O0Ooo * I1IiiI + II111iiii
 if ( hostname not in lisp_nat_state_info ) :
  lisp_nat_state_info [ hostname ] = [ O0iI1ii1II1i111 ]
  lprint ( IiI1iIiii1i . format ( "Store initial" ) )
  return ( True )
  if 37 - 37: IiII + OOooOOo - iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % oO0o
  if 26 - 26: iIii1I11I1II1 - I1Ii111 % iIii1I11I1II1 - iII111i
  if 37 - 37: i1IIi % iIii1I11I1II1 / OoOoOO00 * o0oOOo0O0Ooo - ooOoO0o . I1Ii111
  if 91 - 91: OoOoOO00
  if 89 - 89: Ii1I . I1Ii111 * OOooOOo + I1ii11iIi11i
  if 24 - 24: oO0o % iII111i
 o0O00Oo = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( o0O00Oo . address == Oo0o and o0O00Oo . port == port ) :
  o0O00Oo . uptime = lisp_get_timestamp ( )
  lprint ( IiI1iIiii1i . format ( "Refresh existing" ) )
  return ( False )
  if 70 - 70: IiII * I1Ii111 - II111iiii / Oo0Ooo / OOooOOo
  if 6 - 6: O0 + i11iIiiIii
  if 59 - 59: ooOoO0o . iII111i - II111iiii
  if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
  if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
  if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
  if 55 - 55: OoooooooOO
 IIi1II1 = None
 for o0O00Oo in lisp_nat_state_info [ hostname ] :
  if ( o0O00Oo . address == Oo0o and o0O00Oo . port == port ) :
   IIi1II1 = o0O00Oo
   break
   if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
   if 90 - 90: OOooOOo
   if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
 if ( IIi1II1 == None ) :
  lprint ( IiI1iIiii1i . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( IIi1II1 )
  lprint ( IiI1iIiii1i . format ( "Use previous" ) )
  if 65 - 65: oO0o
  if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 iIiiiiIiiII = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ O0iI1ii1II1i111 ] + iIiiiiIiiII
 return ( True )
 if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
 if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
 if 77 - 77: O0
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
 if 36 - 36: II111iiii
 if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
 if 7 - 7: i11iIiiIii
 if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
def lisp_get_nat_info ( rloc , hostname ) :
 if ( hostname not in lisp_nat_state_info ) : return ( None )
 if 41 - 41: IiII % II111iiii
 Oo0o = rloc . print_address_no_iid ( )
 for o0O00Oo in lisp_nat_state_info [ hostname ] :
  if ( o0O00Oo . address == Oo0o ) : return ( o0O00Oo )
  if 99 - 99: IiII - O0
 return ( None )
 if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
 if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
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
 if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
 if 47 - 47: I1Ii111 * iII111i
 if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
 if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
 if 51 - 51: I1IiiI
 if 52 - 52: I1Ii111
 if 82 - 82: iII111i + II111iiii
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 if 83 - 83: oO0o
 if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
 if 85 - 85: iIii1I11I1II1 / I11i
 if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
 if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
 I11ii1i1i1 = [ ]
 O0O00OOoo00 = [ ]
 if ( dest == None ) :
  for oooO in list ( lisp_map_resolvers_list . values ( ) ) :
   O0O00OOoo00 . append ( oooO . map_resolver )
   if 32 - 32: ooOoO0o - i1IIi
  I11ii1i1i1 = O0O00OOoo00
  if ( I11ii1i1i1 == [ ] ) :
   for IIo0o0oo0 in list ( lisp_map_servers_list . values ( ) ) :
    I11ii1i1i1 . append ( IIo0o0oo0 . map_server )
    if 39 - 39: II111iiii + OoooooooOO / I11i . i11iIiiIii + I1Ii111
    if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
  if ( I11ii1i1i1 == [ ] ) : return
 else :
  I11ii1i1i1 . append ( dest )
  if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
  if 41 - 41: O0 / OoooooooOO - i1IIi
  if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
  if 32 - 32: oO0o / IiII - I11i . ooOoO0o
  if 69 - 69: i11iIiiIii * i11iIiiIii
 IIiIIiiI11 = { }
 for iIiI1ii in lisp_db_list :
  for O0O0OOo0O in iIiI1ii . rloc_set :
   lisp_update_local_rloc ( O0O0OOo0O )
   if ( O0O0OOo0O . rloc . is_null ( ) ) : continue
   if ( O0O0OOo0O . interface == None ) : continue
   if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
   oOOOo0o = O0O0OOo0O . rloc . print_address_no_iid ( )
   if ( oOOOo0o in IIiIIiiI11 ) : continue
   IIiIIiiI11 [ oOOOo0o ] = O0O0OOo0O . interface
   if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
   if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
 if ( IIiIIiiI11 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
  return
  if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
  if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
  if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
  if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
  if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
  if 89 - 89: I1Ii111
 for oOOOo0o in IIiIIiiI11 :
  OooOO = IIiIIiiI11 [ oOOOo0o ]
  OoOOOO = red ( oOOOo0o , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OoOOOO ,
 OooOO ) )
  iIIiI1111 = OooOO if len ( IIiIIiiI11 ) > 1 else None
  for dest in I11ii1i1i1 :
   lisp_send_info_request ( lisp_sockets , dest , port , iIIiI1111 )
   if 29 - 29: I11i * ooOoO0o - OoooooooOO
   if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
   if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
   if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
   if 73 - 73: OoooooooOO
   if 25 - 25: i1IIi . II111iiii . I1Ii111
 if ( O0O00OOoo00 != [ ] ) :
  for oooO in list ( lisp_map_resolvers_list . values ( ) ) :
   oooO . resolve_dns_name ( )
   if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
   if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 return
 if 61 - 61: I1ii11iIi11i
 if 12 - 12: OoO0O00
 if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if 7 - 7: Oo0Ooo
 if 38 - 38: Oo0Ooo - I1ii11iIi11i
 if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
 if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
 if 3 - 3: Ii1I
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
 if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
 if 86 - 86: Oo0Ooo
 if 97 - 97: I1IiiI
 if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
 if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
 if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
 if 64 - 64: I1IiiI % ooOoO0o
 if ( value . find ( "." ) != - 1 ) :
  oOOOo0o = value . split ( "." )
  if ( len ( oOOOo0o ) != 4 ) : return ( False )
  if 72 - 72: O0 * II111iiii % OoO0O00 - I1IiiI * OOooOOo
  for O0o0O0OoOOoO in oOOOo0o :
   if ( O0o0O0OoOOoO . isdigit ( ) == False ) : return ( False )
   if ( int ( O0o0O0OoOOoO ) > 255 ) : return ( False )
   if 66 - 66: iIii1I11I1II1 - Oo0Ooo % OoooooooOO % O0
  return ( True )
  if 33 - 33: I1Ii111 / II111iiii / II111iiii
  if 15 - 15: O0 * OoooooooOO - O0 + OoooooooOO
  if 40 - 40: O0 * OoooooooOO - oO0o + iIii1I11I1II1 * OOooOOo + I1ii11iIi11i
  if 43 - 43: OoO0O00 . O0
  if 36 - 36: I11i
 if ( value . find ( "-" ) != - 1 ) :
  oOOOo0o = value . split ( "-" )
  for OoOOoO0oOo in [ "N" , "S" , "W" , "E" ] :
   if ( OoOOoO0oOo in oOOOo0o ) :
    if ( len ( oOOOo0o ) < 8 ) : return ( False )
    return ( True )
    if 28 - 28: ooOoO0o
    if 1 - 1: IiII / OoO0O00 * oO0o - I1Ii111 . OoOoOO00
    if 85 - 85: i11iIiiIii + OoOoOO00
    if 4 - 4: OOooOOo . OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
    if 60 - 60: OOooOOo . Ii1I
    if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
    if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
 if ( value . find ( "-" ) != - 1 ) :
  oOOOo0o = value . split ( "-" )
  if ( len ( oOOOo0o ) != 3 ) : return ( False )
  if 38 - 38: IiII / I11i / IiII * iII111i
  for iiii1I11i in oOOOo0o :
   try : int ( iiii1I11i , 16 )
   except : return ( False )
   if 65 - 65: OoOoOO00
  return ( True )
  if 31 - 31: iIii1I11I1II1 . iIii1I11I1II1 / IiII + I1ii11iIi11i * iIii1I11I1II1 / iIii1I11I1II1
  if 100 - 100: Ii1I / I1Ii111 + I1Ii111
  if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
  if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
  if 54 - 54: OoOoOO00 / i1IIi + OOooOOo - I1ii11iIi11i - I1IiiI * I1Ii111
 if ( value . find ( ":" ) != - 1 ) :
  oOOOo0o = value . split ( ":" )
  if ( len ( oOOOo0o ) < 2 ) : return ( False )
  if 91 - 91: OoooooooOO * OoooooooOO
  I11iIiiiIiii = False
  Ooo0oOOoo0O = 0
  for iiii1I11i in oOOOo0o :
   Ooo0oOOoo0O += 1
   if ( iiii1I11i == "" ) :
    if ( I11iIiiiIiii ) :
     if ( len ( oOOOo0o ) == Ooo0oOOoo0O ) : break
     if ( Ooo0oOOoo0O > 2 ) : return ( False )
     if 75 - 75: ooOoO0o / Ii1I . Ii1I + I1ii11iIi11i
    I11iIiiiIiii = True
    continue
    if 99 - 99: Ii1I % Oo0Ooo % Oo0Ooo - Oo0Ooo * iIii1I11I1II1 / Ii1I
   try : int ( iiii1I11i , 16 )
   except : return ( False )
   if 6 - 6: o0oOOo0O0Ooo
  return ( True )
  if 21 - 21: ooOoO0o
  if 97 - 97: I11i * OOooOOo . I1IiiI * OoO0O00 / I1IiiI
  if 34 - 34: OoooooooOO * ooOoO0o / ooOoO0o + I1IiiI
  if 61 - 61: oO0o
  if 56 - 56: Oo0Ooo
 if ( value [ 0 ] == "+" ) :
  oOOOo0o = value [ 1 : : ]
  for oOOOO000oo in oOOOo0o :
   if ( oOOOO000oo . isdigit ( ) == False ) : return ( False )
   if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
  return ( True )
  if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 return ( False )
 if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
 if 59 - 59: i11iIiiIii
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
 if 59 - 59: I1ii11iIi11i
 if 47 - 47: I1IiiI + Oo0Ooo
 if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
 if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
def lisp_process_api ( process , lisp_socket , data_structure ) :
 o0Oo0OoO , i1iiI = data_structure . split ( "%" )
 if 2 - 2: i11iIiiIii % I11i + OoOoOO00 / OOooOOo * iIii1I11I1II1 * OoOoOO00
 lprint ( "Process API request '{}', parameters: '{}'" . format ( o0Oo0OoO ,
 i1iiI ) )
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 O0oo = [ ]
 if ( o0Oo0OoO == "map-cache" ) :
  if ( i1iiI == "" ) :
   O0oo = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , O0oo )
  else :
   O0oo = lisp_process_api_map_cache_entry ( json . loads ( i1iiI ) )
   if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
   if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if ( o0Oo0OoO == "site-cache" ) :
  if ( i1iiI == "" ) :
   O0oo = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 O0oo )
  else :
   O0oo = lisp_process_api_site_cache_entry ( json . loads ( i1iiI ) )
   if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
   if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 if ( o0Oo0OoO == "site-cache-summary" ) :
  O0oo = lisp_process_api_site_cache_summary ( lisp_sites_by_eid )
  if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 if ( o0Oo0OoO == "map-server" ) :
  i1iiI = { } if ( i1iiI == "" ) else json . loads ( i1iiI )
  O0oo = lisp_process_api_ms_or_mr ( True , i1iiI )
  if 54 - 54: oO0o * II111iiii
 if ( o0Oo0OoO == "map-resolver" ) :
  i1iiI = { } if ( i1iiI == "" ) else json . loads ( i1iiI )
  O0oo = lisp_process_api_ms_or_mr ( False , i1iiI )
  if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
 if ( o0Oo0OoO == "database-mapping" ) :
  O0oo = lisp_process_api_database_mapping ( )
  if 98 - 98: ooOoO0o
  if 73 - 73: I1Ii111
  if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
  if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
  if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
 O0oo = json . dumps ( O0oo )
 Iii1 = lisp_api_ipc ( process , O0oo )
 lisp_ipc ( Iii1 , lisp_socket , "lisp-core" )
 return
 if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
 if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
 if 76 - 76: iII111i * OOooOOo
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if 40 - 40: iII111i
def lisp_process_api_map_cache ( mc , data ) :
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
 if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 5 - 5: Oo0Ooo . I1Ii111
 if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
 if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
 if 23 - 23: iIii1I11I1II1 - I1IiiI
 if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
 if 25 - 25: ooOoO0o * I1Ii111 * oO0o
 if 64 - 64: Ii1I / I1ii11iIi11i
 if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
 if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
 if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
 if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
def lisp_gather_map_cache_data ( mc , data ) :
 oO00Oo = { }
 oO00Oo [ "instance-id" ] = str ( mc . eid . instance_id )
 oO00Oo [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  oO00Oo [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
 oO00Oo [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 oO00Oo [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 oO00Oo [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 oO00Oo [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 55 - 55: OoO0O00
 if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
 if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 if 43 - 43: Oo0Ooo
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 IIiii11iiI111 = [ ]
 for IIIi1iI1 in mc . rloc_set :
  OOoooo = lisp_fill_rloc_in_json ( IIIi1iI1 )
  if 76 - 76: OOooOOo
  if 54 - 54: O0 * II111iiii * OOooOOo
  if 44 - 44: I1IiiI
  if 66 - 66: o0oOOo0O0Ooo
  if 40 - 40: OOooOOo * Ii1I
  if ( IIIi1iI1 . rloc . is_multicast_address ( ) ) :
   OOoooo [ "multicast-rloc-set" ] = [ ]
   for iII1II1I in list ( IIIi1iI1 . multicast_rloc_probe_list . values ( ) ) :
    oooO = lisp_fill_rloc_in_json ( iII1II1I )
    OOoooo [ "multicast-rloc-set" ] . append ( oooO )
    if 38 - 38: ooOoO0o
    if 5 - 5: OoooooooOO + iII111i - I11i
    if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
  IIiii11iiI111 . append ( OOoooo )
  if 7 - 7: I1ii11iIi11i
 oO00Oo [ "rloc-set" ] = IIiii11iiI111
 if 37 - 37: O0 . II111iiii
 data . append ( oO00Oo )
 return ( [ True , data ] )
 if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
 if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
 if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
 if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
 if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
 if 27 - 27: iII111i
 if 64 - 64: iIii1I11I1II1 - OOooOOo . iII111i % o0oOOo0O0Ooo / II111iiii % OoooooooOO
def lisp_fill_rloc_in_json ( rloc ) :
 OOoooo = { }
 if ( rloc . rloc_exists ( ) ) :
  OOoooo [ "address" ] = rloc . rloc . print_address_no_iid ( )
  if 87 - 87: OoooooooOO
  if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
 if ( rloc . translated_port != 0 ) :
  OOoooo [ "encap-port" ] = str ( rloc . translated_port )
  if 92 - 92: I1IiiI . I11i
 OOoooo [ "state" ] = rloc . print_state ( )
 if ( rloc . geo ) : OOoooo [ "geo" ] = rloc . geo . print_geo ( )
 if ( rloc . elp ) : OOoooo [ "elp" ] = rloc . elp . print_elp ( False )
 if ( rloc . rle ) : OOoooo [ "rle" ] = rloc . rle . print_rle ( False , False )
 if ( rloc . json ) : OOoooo [ "json" ] = rloc . json . print_json ( False )
 if ( rloc . rloc_name ) : OOoooo [ "rloc-name" ] = rloc . rloc_name
 OOo = rloc . stats . get_stats ( False , False )
 if ( OOo ) : OOoooo [ "stats" ] = OOo
 OOoooo [ "uptime" ] = lisp_print_elapsed ( rloc . uptime )
 OOoooo [ "upriority" ] = str ( rloc . priority )
 OOoooo [ "uweight" ] = str ( rloc . weight )
 OOoooo [ "mpriority" ] = str ( rloc . mpriority )
 OOoooo [ "mweight" ] = str ( rloc . mweight )
 O0o0oO = rloc . last_rloc_probe_reply
 if ( O0o0oO ) :
  OOoooo [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( O0o0oO )
  OOoooo [ "rloc-probe-rtt" ] = str ( rloc . rloc_probe_rtt )
  if 98 - 98: I1IiiI % iII111i * OOooOOo - I1ii11iIi11i
 OOoooo [ "rloc-hop-count" ] = rloc . rloc_probe_hops
 OOoooo [ "recent-rloc-hop-counts" ] = rloc . recent_rloc_probe_hops
 if 27 - 27: OOooOOo % oO0o . i1IIi + i1IIi % I1ii11iIi11i
 OOoooo [ "rloc-probe-latency" ] = rloc . rloc_probe_latency
 OOoooo [ "recent-rloc-probe-latencies" ] = rloc . recent_rloc_probe_latencies
 if 38 - 38: i1IIi . I1IiiI + II111iiii * OoO0O00 / IiII
 o00ooiI1i = [ ]
 for OooIIIii in rloc . recent_rloc_probe_rtts : o00ooiI1i . append ( str ( OooIIIii ) )
 OOoooo [ "recent-rloc-probe-rtts" ] = o00ooiI1i
 return ( OOoooo )
 if 49 - 49: I1IiiI
 if 23 - 23: OoooooooOO . OoO0O00 . OoooooooOO * I1ii11iIi11i - Oo0Ooo - iIii1I11I1II1
 if 91 - 91: iIii1I11I1II1 * Ii1I
 if 37 - 37: I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
def lisp_process_api_map_cache_entry ( parms ) :
 i1oO00O = parms [ "instance-id" ]
 i1oO00O = 0 if ( i1oO00O == "" ) else int ( i1oO00O )
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
 if 2 - 2: I11i - II111iiii / I1Ii111
 oo0oO = lisp_address ( LISP_AFI_NONE , "" , 0 , i1oO00O )
 oo0oO . store_prefix ( parms [ "eid-prefix" ] )
 OO0oooOO = oo0oO
 II11IIII1 = oo0oO
 if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
 if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
 if 76 - 76: ooOoO0o . I11i * OoO0O00
 if 53 - 53: II111iiii / OoOoOO00 / IiII * oO0o
 if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
 iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , i1oO00O )
 if ( "group-prefix" in parms ) :
  iiI . store_prefix ( parms [ "group-prefix" ] )
  OO0oooOO = iiI
  if 93 - 93: iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1 . oO0o % Oo0Ooo
  if 92 - 92: OoO0O00
 O0oo = [ ]
 I111I1iI1 = lisp_map_cache_lookup ( II11IIII1 , OO0oooOO )
 if ( I111I1iI1 ) : iiI1i , O0oo = lisp_process_api_map_cache ( I111I1iI1 , O0oo )
 return ( O0oo )
 if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 % ooOoO0o
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
def lisp_process_api_site_cache_summary ( site_cache ) :
 ii1iI11I = { "site" : "" , "registrations" : [ ] }
 oO00Oo = { "eid-prefix" : "" , "count" : 0 , "registered-count" : 0 }
 if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
 IIIIii1i111 = { }
 for Iii1iii1II in site_cache . cache_sorted :
  for i1I1I11II in list ( site_cache . cache [ Iii1iii1II ] . entries . values ( ) ) :
   if ( i1I1I11II . accept_more_specifics == False ) : continue
   if ( i1I1I11II . site . site_name not in IIIIii1i111 ) :
    IIIIii1i111 [ i1I1I11II . site . site_name ] = [ ]
    if 63 - 63: o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
   I1i = copy . deepcopy ( oO00Oo )
   I1i [ "eid-prefix" ] = i1I1I11II . eid . print_prefix ( )
   I1i [ "count" ] = len ( i1I1I11II . more_specific_registrations )
   for IIii1I in i1I1I11II . more_specific_registrations :
    if ( IIii1I . registered ) : I1i [ "registered-count" ] += 1
    if 93 - 93: OoOoOO00 + I1ii11iIi11i / OoooooooOO + o0oOOo0O0Ooo
   IIIIii1i111 [ i1I1I11II . site . site_name ] . append ( I1i )
   if 57 - 57: Ii1I + I1IiiI / O0
   if 44 - 44: i1IIi - ooOoO0o / I1ii11iIi11i
   if 60 - 60: o0oOOo0O0Ooo . i1IIi * IiII
 O0oo = [ ]
 for O00O0o in IIIIii1i111 :
  I1iiIi111I = copy . deepcopy ( ii1iI11I )
  I1iiIi111I [ "site" ] = O00O0o
  I1iiIi111I [ "registrations" ] = IIIIii1i111 [ O00O0o ]
  O0oo . append ( I1iiIi111I )
  if 100 - 100: I1IiiI / I1Ii111 - Oo0Ooo % iII111i - I1ii11iIi11i % OoO0O00
 return ( O0oo )
 if 11 - 11: II111iiii
 if 37 - 37: IiII
 if 43 - 43: OoO0O00 / IiII % iIii1I11I1II1
 if 89 - 89: I11i + iII111i / i11iIiiIii
 if 46 - 46: ooOoO0o + ooOoO0o / IiII
 if 57 - 57: OOooOOo + I1ii11iIi11i
 if 82 - 82: i11iIiiIii
def lisp_process_api_site_cache ( se , data ) :
 if 31 - 31: iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 45 - 45: OOooOOo / Ii1I % O0
 if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
 if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
 if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
 if 96 - 96: oO0o
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
 if 64 - 64: I1IiiI % i11iIiiIii / oO0o
 if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
 if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
 if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 if 31 - 31: OoO0O00
 if 89 - 89: II111iiii
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 I1IIIi = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 OOo0oOoOo = data [ "dns-name" ] if ( "dns-name" in data ) else None
 if ( "address" in data ) :
  I1IIIi . store_address ( data [ "address" ] )
  if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
  if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
 iiIiII11i1 = { }
 if ( ms_or_mr ) :
  for IIo0o0oo0 in list ( lisp_map_servers_list . values ( ) ) :
   if ( OOo0oOoOo ) :
    if ( OOo0oOoOo != IIo0o0oo0 . dns_name ) : continue
   else :
    if ( I1IIIi . is_exact_match ( IIo0o0oo0 . map_server ) == False ) : continue
    if 85 - 85: O0 * OOooOOo % I1Ii111
    if 33 - 33: O0
   iiIiII11i1 [ "dns-name" ] = IIo0o0oo0 . dns_name
   iiIiII11i1 [ "address" ] = IIo0o0oo0 . map_server . print_address_no_iid ( )
   iiIiII11i1 [ "ms-name" ] = "" if IIo0o0oo0 . ms_name == None else IIo0o0oo0 . ms_name
   return ( [ iiIiII11i1 ] )
   if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
 else :
  for oooO in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( OOo0oOoOo ) :
    if ( OOo0oOoOo != oooO . dns_name ) : continue
   else :
    if ( I1IIIi . is_exact_match ( oooO . map_resolver ) == False ) : continue
    if 43 - 43: iIii1I11I1II1
    if 88 - 88: I1IiiI - OoO0O00 . O0 . oO0o
   iiIiII11i1 [ "dns-name" ] = oooO . dns_name
   iiIiII11i1 [ "address" ] = oooO . map_resolver . print_address_no_iid ( )
   iiIiII11i1 [ "mr-name" ] = "" if oooO . mr_name == None else oooO . mr_name
   return ( [ iiIiII11i1 ] )
   if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
   if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
 return ( [ ] )
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo
 if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
 if 51 - 51: ooOoO0o % iII111i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 20 - 20: i1IIi - ooOoO0o % OoooooooOO * I1ii11iIi11i + II111iiii % i1IIi
 if 30 - 30: i11iIiiIii - I1IiiI + o0oOOo0O0Ooo + IiII
 if 16 - 16: I1ii11iIi11i / Ii1I + I1ii11iIi11i * I1Ii111
 if 49 - 49: ooOoO0o * OoOoOO00 . OoooooooOO . ooOoO0o + Oo0Ooo * IiII
 if 47 - 47: iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
def lisp_process_api_database_mapping ( ) :
 O0oo = [ ]
 if 84 - 84: o0oOOo0O0Ooo * I11i
 for iIiI1ii in lisp_db_list :
  oO00Oo = { }
  oO00Oo [ "eid-prefix" ] = iIiI1ii . eid . print_prefix ( )
  if ( iIiI1ii . group . is_null ( ) == False ) :
   oO00Oo [ "group-prefix" ] = iIiI1ii . group . print_prefix ( )
   if 22 - 22: i1IIi + OOooOOo % OoooooooOO
   if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
  o0o = [ ]
  for OOoooo in iIiI1ii . rloc_set :
   IIIi1iI1 = { }
   if ( OOoooo . rloc . is_null ( ) == False ) :
    IIIi1iI1 [ "rloc" ] = OOoooo . rloc . print_address_no_iid ( )
    if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
   if ( OOoooo . rloc_name != None ) : IIIi1iI1 [ "rloc-name" ] = OOoooo . rloc_name
   if ( OOoooo . interface != None ) : IIIi1iI1 [ "interface" ] = OOoooo . interface
   iIiIii1iI1I1IiI = OOoooo . translated_rloc
   if ( iIiIii1iI1I1IiI . is_null ( ) == False ) :
    IIIi1iI1 [ "translated-rloc" ] = iIiIii1iI1I1IiI . print_address_no_iid ( )
    if 13 - 13: I1ii11iIi11i % OOooOOo * IiII * OoO0O00
   if ( IIIi1iI1 != { } ) : o0o . append ( IIIi1iI1 )
   if 76 - 76: OOooOOo
   if 90 - 90: oO0o / Oo0Ooo + iII111i - O0
   if 76 - 76: ooOoO0o + IiII / I1ii11iIi11i . iIii1I11I1II1
   if 52 - 52: iIii1I11I1II1 * OOooOOo % i1IIi
   if 1 - 1: o0oOOo0O0Ooo + Ii1I - o0oOOo0O0Ooo % I1ii11iIi11i
  oO00Oo [ "rlocs" ] = o0o
  if 61 - 61: OoooooooOO
  if 93 - 93: OoO0O00
  if 18 - 18: OoOoOO00 - OoOoOO00 . iII111i / Oo0Ooo % Ii1I / iIii1I11I1II1
  if 97 - 97: ooOoO0o * ooOoO0o / IiII / iII111i . i11iIiiIii
  O0oo . append ( oO00Oo )
  if 29 - 29: Oo0Ooo % i1IIi - I11i * OoooooooOO + iII111i
 return ( O0oo )
 if 82 - 82: IiII - I1Ii111 - I1ii11iIi11i
 if 35 - 35: oO0o % OoOoOO00 + iII111i . I1Ii111 . IiII - OoooooooOO
 if 69 - 69: O0 . Ii1I / O0
 if 61 - 61: OoooooooOO / OOooOOo / iII111i % II111iiii
 if 97 - 97: I1Ii111 / iIii1I11I1II1 * OOooOOo + i11iIiiIii
 if 86 - 86: OoO0O00 - I1Ii111 * OoO0O00
 if 29 - 29: I1Ii111 % OoOoOO00 . oO0o / oO0o % I11i
def lisp_gather_site_cache_data ( se , data ) :
 oO00Oo = { }
 oO00Oo [ "site-name" ] = se . site . site_name
 oO00Oo [ "instance-id" ] = str ( se . eid . instance_id )
 oO00Oo [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  oO00Oo [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 91 - 91: o0oOOo0O0Ooo
 oO00Oo [ "registered" ] = "yes" if se . registered else "no"
 oO00Oo [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 oO00Oo [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 59 - 59: I11i . I11i
 oOOOo0o = se . last_registerer
 oOOOo0o = "none" if oOOOo0o . is_null ( ) else oOOOo0o . print_address ( )
 oO00Oo [ "last-registerer" ] = oOOOo0o
 oO00Oo [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 oO00Oo [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 oO00Oo [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  oO00Oo [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 98 - 98: II111iiii
  if 20 - 20: iIii1I11I1II1
  if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
  if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
  if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
 IIiii11iiI111 = [ ]
 for IIIi1iI1 in se . registered_rlocs :
  OOoooo = { }
  OOoooo [ "address" ] = IIIi1iI1 . rloc . print_address_no_iid ( ) if IIIi1iI1 . rloc_exists ( ) else "none"
  if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
  if 16 - 16: o0oOOo0O0Ooo
  if ( IIIi1iI1 . geo ) : OOoooo [ "geo" ] = IIIi1iI1 . geo . print_geo ( )
  if ( IIIi1iI1 . elp ) : OOoooo [ "elp" ] = IIIi1iI1 . elp . print_elp ( False )
  if ( IIIi1iI1 . rle ) : OOoooo [ "rle" ] = IIIi1iI1 . rle . print_rle ( False , True )
  if ( IIIi1iI1 . json ) : OOoooo [ "json" ] = IIIi1iI1 . json . print_json ( False )
  if ( IIIi1iI1 . rloc_name ) : OOoooo [ "rloc-name" ] = IIIi1iI1 . rloc_name
  OOoooo [ "uptime" ] = lisp_print_elapsed ( IIIi1iI1 . uptime )
  OOoooo [ "upriority" ] = str ( IIIi1iI1 . priority )
  OOoooo [ "uweight" ] = str ( IIIi1iI1 . weight )
  OOoooo [ "mpriority" ] = str ( IIIi1iI1 . mpriority )
  OOoooo [ "mweight" ] = str ( IIIi1iI1 . mweight )
  if 3 - 3: i11iIiiIii . I1ii11iIi11i
  IIiii11iiI111 . append ( OOoooo )
  if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 oO00Oo [ "registered-rlocs" ] = IIiii11iiI111
 if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
 data . append ( oO00Oo )
 return ( [ True , data ] )
 if 100 - 100: o0oOOo0O0Ooo
 if 95 - 95: iII111i * oO0o * i1IIi
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
def lisp_process_api_site_cache_entry ( parms ) :
 i1oO00O = parms [ "instance-id" ]
 i1oO00O = 0 if ( i1oO00O == "" ) else int ( i1oO00O )
 if 76 - 76: OoO0O00
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 if 92 - 92: OoOoOO00 + oO0o
 if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
 oo0oO = lisp_address ( LISP_AFI_NONE , "" , 0 , i1oO00O )
 oo0oO . store_prefix ( parms [ "eid-prefix" ] )
 if 28 - 28: I1IiiI . iIii1I11I1II1
 if 12 - 12: I1Ii111 * OOooOOo
 if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
 if 45 - 45: OoooooooOO * oO0o
 if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
 iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , i1oO00O )
 if ( "group-prefix" in parms ) :
  iiI . store_prefix ( parms [ "group-prefix" ] )
  if 16 - 16: Oo0Ooo
  if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
 O0oo = [ ]
 i1I1I11II = lisp_site_eid_lookup ( oo0oO , iiI , False )
 if ( i1I1I11II ) : lisp_gather_site_cache_data ( i1I1I11II , O0oo )
 return ( O0oo )
 if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 if 33 - 33: OOooOOo - OoooooooOO . iII111i
 if 2 - 2: I11i + i1IIi
 if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
def lisp_get_interface_instance_id ( device , source_eid ) :
 OooOO = None
 if ( device in lisp_myinterfaces ) :
  OooOO = lisp_myinterfaces [ device ]
  if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
  if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
  if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
  if 12 - 12: II111iiii * O0 - Oo0Ooo + o0oOOo0O0Ooo . Oo0Ooo + iIii1I11I1II1
  if 4 - 4: I1Ii111 - I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / oO0o
  if 18 - 18: iIii1I11I1II1 . ooOoO0o
 if ( OooOO == None or OooOO . instance_id == None ) :
  return ( lisp_default_iid )
  if 68 - 68: o0oOOo0O0Ooo
  if 36 - 36: Oo0Ooo . I11i + I1IiiI * i1IIi % Ii1I + OOooOOo
  if 5 - 5: o0oOOo0O0Ooo % oO0o / OoO0O00
  if 17 - 17: OoooooooOO - I1ii11iIi11i / OoO0O00 - I1Ii111 + i1IIi
  if 6 - 6: Oo0Ooo - II111iiii
  if 33 - 33: I1Ii111 - I1IiiI + iII111i . OoOoOO00
  if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
  if 68 - 68: I11i
  if 91 - 91: I11i
 i1oO00O = OooOO . get_instance_id ( )
 if ( source_eid == None ) : return ( i1oO00O )
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
 ooooooO = source_eid . instance_id
 iII = None
 for OooOO in lisp_multi_tenant_interfaces :
  if ( OooOO . device != device ) : continue
  Ii1IIIIi = OooOO . multi_tenant_eid
  source_eid . instance_id = Ii1IIIIi . instance_id
  if ( source_eid . is_more_specific ( Ii1IIIIi ) == False ) : continue
  if ( iII == None or iII . multi_tenant_eid . mask_len < Ii1IIIIi . mask_len ) :
   iII = OooOO
   if 13 - 13: iIii1I11I1II1 - OoooooooOO . OoooooooOO + iII111i - OoOoOO00 % oO0o
   if 11 - 11: ooOoO0o * iIii1I11I1II1 + OoooooooOO + OoO0O00
 source_eid . instance_id = ooooooO
 if 24 - 24: iII111i . OoO0O00 * Ii1I - OOooOOo . I11i
 if ( iII == None ) : return ( i1oO00O )
 return ( iII . get_instance_id ( ) )
 if 90 - 90: I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - i1IIi
 if 94 - 94: OoooooooOO
 if 80 - 80: O0 * OOooOOo + i1IIi + i11iIiiIii * o0oOOo0O0Ooo
 if 14 - 14: II111iiii * OOooOOo - O0 / I1ii11iIi11i . OoO0O00 . ooOoO0o
 if 98 - 98: o0oOOo0O0Ooo . i1IIi
 if 83 - 83: i11iIiiIii + OOooOOo % iII111i
 if 59 - 59: I11i
 if 23 - 23: OoOoOO00 * I1Ii111
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( device not in lisp_myinterfaces ) : return ( None )
 if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 OooOO = lisp_myinterfaces [ device ]
 IIi1i111ii1I = device if OooOO . dynamic_eid_device == None else OooOO . dynamic_eid_device
 if 8 - 8: Oo0Ooo % O0 . II111iiii
 if 45 - 45: i1IIi % ooOoO0o / oO0o + oO0o / OOooOOo - oO0o
 if ( OooOO . does_dynamic_eid_match ( eid ) ) : return ( IIi1i111ii1I )
 return ( None )
 if 91 - 91: i1IIi . Oo0Ooo . i11iIiiIii % iIii1I11I1II1 * OOooOOo
 if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
 if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 if 73 - 73: Oo0Ooo + II111iiii - IiII
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
 if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 94 - 94: OoO0O00
 IIII1iiiI11 = lisp_process_rloc_probe_timer
 I1ooo0o00o0Oooo = threading . Timer ( interval , IIII1iiiI11 , [ lisp_sockets ] )
 lisp_rloc_probe_timer = I1ooo0o00o0Oooo
 I1ooo0o00o0Oooo . start ( )
 return
 if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
 if 48 - 48: IiII . I1Ii111 + OoooooooOO - I1Ii111 . Ii1I . I1Ii111
 if 24 - 24: ooOoO0o * iIii1I11I1II1
 if 1 - 1: I1ii11iIi11i . O0
 if 3 - 3: iIii1I11I1II1 * ooOoO0o - OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoooooooOO
 if 42 - 42: I1Ii111 - i1IIi
 if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for IIIOoo in lisp_rloc_probe_list :
  IIO0o0OO0O = lisp_rloc_probe_list [ IIIOoo ]
  lprint ( "RLOC {}:" . format ( IIIOoo ) )
  for OOoooo , I1i , o0O0Ooo in IIO0o0OO0O :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( OOoooo ) ) , I1i . print_prefix ( ) ,
 o0O0Ooo . print_prefix ( ) , OOoooo . translated_port ) )
   if 87 - 87: I11i + I1ii11iIi11i
   if 83 - 83: i11iIiiIii * OoooooooOO * I1Ii111 * Ii1I % I11i
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 100 - 100: I1ii11iIi11i
 if 83 - 83: I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if 76 - 76: I1Ii111
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
 if 14 - 14: O0 * Oo0Ooo / i1IIi
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 if 78 - 78: II111iiii % OOooOOo
 if 6 - 6: OOooOOo
 if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
 IIIi1iI1 , I1i , o0O0Ooo = eid_list [ 0 ]
 oOOOoo = [ lisp_print_eid_tuple ( I1i , o0O0Ooo ) ]
 if 82 - 82: i11iIiiIii % I11i . OoOoOO00 + Ii1I * iIii1I11I1II1 - OoOoOO00
 for IIIi1iI1 , I1i , o0O0Ooo in eid_list [ 1 : : ] :
  IIIi1iI1 . state = LISP_RLOC_UNREACH_STATE
  IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
  oOOOoo . append ( lisp_print_eid_tuple ( I1i , o0O0Ooo ) )
  if 96 - 96: I1IiiI
  if 3 - 3: OoooooooOO
 I11ii1iIi111i = bold ( "unreachable" , False )
 iiIIii = red ( IIIi1iI1 . rloc . print_address_no_iid ( ) , False )
 if 96 - 96: IiII
 for oo0oO in oOOOoo :
  I1i = green ( oo0oO , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( iiIIii , I11ii1iIi111i , I1i ) )
  if 55 - 55: iIii1I11I1II1 + II111iiii . I1ii11iIi11i + Oo0Ooo . Ii1I * IiII
  if 91 - 91: iIii1I11I1II1 / Oo0Ooo
  if 68 - 68: o0oOOo0O0Ooo * OoOoOO00 . I1ii11iIi11i
  if 32 - 32: OoooooooOO * I11i
  if 86 - 86: I1Ii111 - i1IIi % O0
  if 38 - 38: I1IiiI + OoO0O00 % iII111i / ooOoO0o
 for IIIi1iI1 , I1i , o0O0Ooo in eid_list :
  I111I1iI1 = lisp_map_cache . lookup_cache ( I1i , True )
  if ( I111I1iI1 ) : lisp_write_ipc_map_cache ( True , I111I1iI1 )
  if 93 - 93: OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
 return
 if 90 - 90: iIii1I11I1II1 . Ii1I / i11iIiiIii . oO0o . I11i - I11i
 if 46 - 46: I11i
 if 2 - 2: I1Ii111 * oO0o
 if 93 - 93: I11i
 if 2 - 2: i1IIi / I1IiiI
 if 29 - 29: Ii1I * iIii1I11I1II1 * i1IIi
 if 83 - 83: oO0o % O0 . I11i / I11i / I1IiiI - OoOoOO00
 if 91 - 91: iIii1I11I1II1 - IiII + iIii1I11I1II1 % Oo0Ooo % I1IiiI
 if 84 - 84: iIii1I11I1II1 . Oo0Ooo - OoooooooOO % Oo0Ooo
 if 27 - 27: I1ii11iIi11i - ooOoO0o + I11i - I1ii11iIi11i
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 57 - 57: Oo0Ooo
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 31 - 31: I1IiiI % Ii1I / OOooOOo + OoooooooOO . i11iIiiIii
 if 87 - 87: iII111i + IiII * I1ii11iIi11i . iII111i + Ii1I - II111iiii
 if 87 - 87: OoOoOO00 . o0oOOo0O0Ooo + I1ii11iIi11i
 if 53 - 53: o0oOOo0O0Ooo * II111iiii + i1IIi
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 83 - 83: I11i * o0oOOo0O0Ooo * Ii1I + OoooooooOO
 if 76 - 76: I1ii11iIi11i . OoooooooOO + ooOoO0o / I1IiiI
 if 56 - 56: Ii1I % I11i / O0 % O0 % iIii1I11I1II1 + I1IiiI
 if 51 - 51: O0 * Ii1I / oO0o * OoooooooOO
 oOIiII = lisp_get_default_route_next_hops ( )
 if 37 - 37: OOooOOo * I11i
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 1 - 1: OOooOOo
 if 99 - 99: IiII * OoO0O00 . iII111i - OOooOOo + I1Ii111
 if 36 - 36: I1Ii111 - ooOoO0o . ooOoO0o % ooOoO0o
 if 5 - 5: O0 / Ii1I * i11iIiiIii - iII111i
 if 2 - 2: OoOoOO00 + I1IiiI . ooOoO0o - oO0o . iIii1I11I1II1
 Ooo0oOOoo0O = 0
 iII11 = bold ( "RLOC-probe" , False )
 for ooo00ooOOO0 in list ( lisp_rloc_probe_list . values ( ) ) :
  if 44 - 44: I11i
  if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
  if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
  if 27 - 27: O0 / Oo0Ooo . oO0o
  if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
  Ii1ii1II11I1 = None
  for iiIII1ii1 , oo0oO , iiI in ooo00ooOOO0 :
   Oo0o = iiIII1ii1 . rloc . print_address_no_iid ( )
   if 16 - 16: OoOoOO00 % iIii1I11I1II1 . iIii1I11I1II1 . I1ii11iIi11i - Ii1I . I11i
   if 20 - 20: Ii1I
   if 90 - 90: oO0o . I1IiiI . I1IiiI + OoooooooOO
   if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
   iiiI1iI11i1i1 , ii1I1iiiiiii1I1iii , i1iIi1II1 = lisp_allow_gleaning ( oo0oO , None , iiIII1ii1 )
   if ( iiiI1iI11i1i1 and ii1I1iiiiiii1I1iii == False ) :
    I1i = green ( oo0oO . print_address ( ) , False )
    Oo0o += ":{}" . format ( iiIII1ii1 . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( Oo0o , False ) , I1i ) )
    if 63 - 63: I11i * oO0o
    continue
    if 55 - 55: I1ii11iIi11i . Oo0Ooo / OoO0O00
    if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
    if 51 - 51: OoO0O00 - OoO0O00 * IiII
    if 24 - 24: OoooooooOO . II111iiii
    if 97 - 97: II111iiii . O0
    if 18 - 18: iII111i
    if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
   if ( iiIII1ii1 . down_state ( ) ) : continue
   if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
   if 25 - 25: OoO0O00
   if 54 - 54: O0
   if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
   if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
   if 92 - 92: ooOoO0o - iII111i
   if 69 - 69: iII111i
   if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
   if 63 - 63: oO0o * OoO0O00 * oO0o
   if 31 - 31: Oo0Ooo
   if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
   if ( Ii1ii1II11I1 ) :
    iiIII1ii1 . last_rloc_probe_nonce = Ii1ii1II11I1 . last_rloc_probe_nonce
    if 67 - 67: I1Ii111 . I1ii11iIi11i
    if ( Ii1ii1II11I1 . translated_port == iiIII1ii1 . translated_port and Ii1ii1II11I1 . rloc_name == iiIII1ii1 . rloc_name ) :
     if 2 - 2: O0 + I1Ii111
     I1i = green ( lisp_print_eid_tuple ( oo0oO , iiI ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( Oo0o , False ) , I1i ) )
     if 82 - 82: Ii1I / iII111i
     if 13 - 13: I11i + iII111i
     if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
     if 59 - 59: Oo0Ooo + I1ii11iIi11i
     if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
     if 70 - 70: i1IIi . Ii1I / Ii1I
     iiIII1ii1 . last_rloc_probe = Ii1ii1II11I1 . last_rloc_probe
     continue
     if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
     if 45 - 45: i1IIi + I1ii11iIi11i
     if 49 - 49: i11iIiiIii . I1ii11iIi11i
   o00o0O0O0oO0o = None
   IIIi1iI1 = None
   while ( True ) :
    IIIi1iI1 = iiIII1ii1 if IIIi1iI1 == None else IIIi1iI1 . next_rloc
    if ( IIIi1iI1 == None ) : break
    if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
    if 33 - 33: II111iiii
    if 39 - 39: ooOoO0o + I11i
    if 24 - 24: o0oOOo0O0Ooo
    if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
    if ( IIIi1iI1 . rloc_next_hop != None ) :
     if ( IIIi1iI1 . rloc_next_hop not in oOIiII ) :
      if ( IIIi1iI1 . up_state ( ) ) :
       iiIi , O0iII11II1I1 = IIIi1iI1 . rloc_next_hop
       IIIi1iI1 . state = LISP_RLOC_UNREACH_STATE
       IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( IIIi1iI1 . rloc , False )
       if 63 - 63: oO0o
      I11ii1iIi111i = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( O0iII11II1I1 , iiIi ,
 red ( Oo0o , False ) , I11ii1iIi111i ) )
      continue
      if 7 - 7: IiII / i11iIiiIii - OOooOOo
      if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
      if 55 - 55: I1Ii111 + ooOoO0o
      if 58 - 58: iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
      if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
      if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
    oo0o0o0o0O = IIIi1iI1 . last_rloc_probe
    OoOo = 0 if oo0o0o0o0O == None else time . time ( ) - oo0o0o0o0O
    if ( IIIi1iI1 . unreach_state ( ) and OoOo < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( Oo0o , False ) ) )
     if 67 - 67: oO0o % i11iIiiIii - I1IiiI % iIii1I11I1II1 . iIii1I11I1II1
     continue
     if 73 - 73: OOooOOo % OoO0O00 + IiII . Ii1I * I1Ii111
     if 26 - 26: iII111i - I11i
     if 5 - 5: OoO0O00 % iII111i + i1IIi - OoooooooOO
     if 16 - 16: i1IIi
     if 86 - 86: OoOoOO00 - iII111i - Oo0Ooo
     if 33 - 33: Ii1I - OoO0O00
    I1 = lisp_get_echo_nonce ( None , Oo0o )
    if ( I1 and I1 . request_nonce_timeout ( ) ) :
     IIIi1iI1 . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
     I11ii1iIi111i = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( Oo0o , False ) , I11ii1iIi111i ) )
     if 15 - 15: O0 . iIii1I11I1II1 - I1Ii111 + O0 + ooOoO0o / I1IiiI
     lisp_update_rtr_updown ( IIIi1iI1 . rloc , False )
     continue
     if 8 - 8: iII111i % O0 - OoOoOO00
     if 49 - 49: oO0o - OOooOOo / Ii1I / I1Ii111 . o0oOOo0O0Ooo . iII111i
     if 58 - 58: IiII + Ii1I
     if 89 - 89: Ii1I / Oo0Ooo * o0oOOo0O0Ooo / OoO0O00 + I11i
     if 4 - 4: I11i
     if 59 - 59: OoOoOO00 * I1ii11iIi11i / I1IiiI * II111iiii + OoOoOO00
    if ( I1 and I1 . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( Oo0o , False ) ) )
     if 6 - 6: OoOoOO00 % oO0o + I11i * Ii1I
     continue
     if 13 - 13: I1ii11iIi11i / Oo0Ooo - I1Ii111 * OoOoOO00
     if 47 - 47: IiII
     if 76 - 76: iII111i / II111iiii / I11i
     if 62 - 62: I1ii11iIi11i
     if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
     if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
    if ( IIIi1iI1 . last_rloc_probe != None ) :
     oo0o0o0o0O = IIIi1iI1 . last_rloc_probe_reply
     if ( oo0o0o0o0O == None ) : oo0o0o0o0O = 0
     OoOo = time . time ( ) - oo0o0o0o0O
     if ( IIIi1iI1 . up_state ( ) and OoOo >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
      IIIi1iI1 . state = LISP_RLOC_UNREACH_STATE
      IIIi1iI1 . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( IIIi1iI1 . rloc , False )
      I11ii1iIi111i = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( Oo0o , False ) , I11ii1iIi111i ) )
      if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
      if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
      lisp_mark_rlocs_for_other_eids ( ooo00ooOOO0 )
      if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
      if 71 - 71: i1IIi
      if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
    IIIi1iI1 . last_rloc_probe = lisp_get_timestamp ( )
    if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
    O0o = "" if IIIi1iI1 . unreach_state ( ) == False else " unreachable"
    if 56 - 56: IiII % o0oOOo0O0Ooo % I1ii11iIi11i
    if 88 - 88: iIii1I11I1II1 - o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i / i11iIiiIii / Ii1I
    if 10 - 10: I1Ii111 / Ii1I * I1Ii111 / OoO0O00 - I1ii11iIi11i
    if 7 - 7: I1IiiI . OoO0O00 . OoOoOO00 . I1ii11iIi11i * OoO0O00 - IiII
    if 6 - 6: OoO0O00 + II111iiii - oO0o
    if 90 - 90: Oo0Ooo % Oo0Ooo + oO0o - OoooooooOO + OOooOOo % I11i
    if 61 - 61: I1IiiI % oO0o + OOooOOo - I1Ii111
    i1i1 = ""
    O0iII11II1I1 = None
    if ( IIIi1iI1 . rloc_next_hop != None ) :
     iiIi , O0iII11II1I1 = IIIi1iI1 . rloc_next_hop
     lisp_install_host_route ( Oo0o , O0iII11II1I1 , True )
     i1i1 = ", send on nh {}({})" . format ( O0iII11II1I1 , iiIi )
     if 87 - 87: IiII / II111iiii
     if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
     if 84 - 84: OOooOOo . OOooOOo . oO0o % iII111i * Oo0Ooo - iIii1I11I1II1
     if 4 - 4: iII111i
     if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
    OooIIIii = IIIi1iI1 . print_rloc_probe_rtt ( )
    O0O0o00 = Oo0o
    if ( IIIi1iI1 . translated_port != 0 ) :
     O0O0o00 += ":{}" . format ( IIIi1iI1 . translated_port )
     if 91 - 91: OoooooooOO
    O0O0o00 = red ( O0O0o00 , False )
    if ( IIIi1iI1 . rloc_name != None ) :
     O0O0o00 += " (" + blue ( IIIi1iI1 . rloc_name , False ) + ")"
     if 50 - 50: Ii1I - II111iiii - IiII / I1Ii111 . Ii1I . I1IiiI
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( iII11 , O0o ,
 O0O0o00 , OooIIIii , i1i1 ) )
    if 39 - 39: i1IIi - I1ii11iIi11i / iIii1I11I1II1 + I11i / iIii1I11I1II1 % o0oOOo0O0Ooo
    if 67 - 67: I1Ii111 % Ii1I * ooOoO0o / OoO0O00 - oO0o % o0oOOo0O0Ooo
    if 5 - 5: IiII / Ii1I * o0oOOo0O0Ooo % o0oOOo0O0Ooo - i11iIiiIii
    if 35 - 35: OoOoOO00
    if 86 - 86: OoooooooOO * OoO0O00 . II111iiii + OoO0O00 . iII111i + o0oOOo0O0Ooo
    if 6 - 6: O0 - iII111i % IiII + IiII - I11i
    if 7 - 7: iIii1I11I1II1
    if 14 - 14: I1IiiI * Ii1I % OoOoOO00 / I1IiiI
    if ( IIIi1iI1 . rloc_next_hop != None ) :
     o00o0O0O0oO0o = lisp_get_host_route_next_hop ( Oo0o )
     if ( o00o0O0O0oO0o ) : lisp_install_host_route ( Oo0o , o00o0O0O0oO0o , False )
     if 87 - 87: OOooOOo - i1IIi
     if 65 - 65: I11i - ooOoO0o / i1IIi - OOooOOo
     if 74 - 74: O0 - II111iiii + iIii1I11I1II1 % I1IiiI % OoOoOO00
     if 57 - 57: O0 * Ii1I / I1IiiI
     if 54 - 54: iIii1I11I1II1 + iII111i % OoOoOO00 % OOooOOo
     if 67 - 67: iII111i . II111iiii - I1IiiI / iII111i . Ii1I
    if ( IIIi1iI1 . rloc . is_null ( ) ) :
     IIIi1iI1 . rloc . copy_address ( iiIII1ii1 . rloc )
     if 42 - 42: I1IiiI % I1Ii111 % iII111i + iII111i
     if 71 - 71: Oo0Ooo / OoOoOO00 - I1ii11iIi11i
     if 32 - 32: iII111i
     if 99 - 99: o0oOOo0O0Ooo . oO0o
     if 9 - 9: oO0o % OoooooooOO
    o0ooO = None if ( iiI . is_null ( ) ) else oo0oO
    OOoO = oo0oO if ( iiI . is_null ( ) ) else iiI
    lisp_send_map_request ( lisp_sockets , 0 , o0ooO , OOoO , IIIi1iI1 )
    Ii1ii1II11I1 = iiIII1ii1
    if 37 - 37: Oo0Ooo - I11i % OoOoOO00 - I1IiiI + iII111i % iII111i
    if 67 - 67: i1IIi
    if 79 - 79: I1Ii111 - Oo0Ooo - o0oOOo0O0Ooo + OoooooooOO
    if 40 - 40: o0oOOo0O0Ooo
    if ( O0iII11II1I1 ) : lisp_install_host_route ( Oo0o , O0iII11II1I1 , False )
    if 88 - 88: i11iIiiIii . iIii1I11I1II1
    if 57 - 57: Ii1I * iIii1I11I1II1
    if 92 - 92: Ii1I % Ii1I . I11i / i1IIi % Oo0Ooo
    if 25 - 25: o0oOOo0O0Ooo - OoO0O00 - OoOoOO00 - ooOoO0o
    if 28 - 28: OOooOOo * ooOoO0o * OoooooooOO % IiII
   if ( o00o0O0O0oO0o ) : lisp_install_host_route ( Oo0o , o00o0O0O0oO0o , True )
   if 9 - 9: OoooooooOO
   if 92 - 92: I1Ii111 + O0 + OoO0O00 % IiII
   if 31 - 31: Ii1I / Oo0Ooo - I1IiiI - I11i - i11iIiiIii
   if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
   Ooo0oOOoo0O += 1
   if ( ( Ooo0oOOoo0O % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
   if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
   if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
 if 57 - 57: I1Ii111 - IiII
 if 89 - 89: oO0o + iII111i
 if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
 if 7 - 7: II111iiii
 if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
 if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
 if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
 if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
 if ( lisp_i_am_itr == False ) : return
 if 67 - 67: I1Ii111
 if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
 if 77 - 77: ooOoO0o
 if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
 if 6 - 6: iII111i / iII111i . i11iIiiIii
 if ( lisp_register_all_rtrs ) : return
 if 12 - 12: I11i - OoO0O00
 o0Ooooo0 = rtr . print_address_no_iid ( )
 if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
 if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
 if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
 if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
 if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
 if ( o0Ooooo0 not in lisp_rtr_list ) : return
 if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( o0Ooooo0 , False ) , bold ( updown , False ) ) )
 if 42 - 42: i1IIi . OoO0O00 % iII111i
 if 57 - 57: I1ii11iIi11i / I1IiiI
 if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
 if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 Iii1 = "rtr%{}%{}" . format ( o0Ooooo0 , updown )
 Iii1 = lisp_command_ipc ( Iii1 , "lisp-itr" )
 lisp_ipc ( Iii1 , lisp_ipc_socket , "lisp-etr" )
 return
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 if 39 - 39: OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
 if 41 - 41: II111iiii . o0oOOo0O0Ooo
 if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl ,
 mrloc ) :
 IIIi1iI1 = rloc_entry . rloc
 o00oO0O000 = map_reply . nonce
 O0O0OooooooOO = map_reply . hop_count
 iII11 = bold ( "RLOC-probe reply" , False )
 iIi1iI = IIIi1iI1 . print_address_no_iid ( )
 IiiIOooo = source . print_address_no_iid ( )
 iIi1Iiii11Ii1 = lisp_rloc_probe_list
 oOoOOO = rloc_entry . json . json_string if rloc_entry . json else None
 i1 = lisp_get_timestamp ( )
 if 27 - 27: II111iiii - i1IIi
 if 4 - 4: I1IiiI
 if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if ( mrloc != None ) :
  OooO = mrloc . rloc . print_address_no_iid ( )
  if ( iIi1iI not in mrloc . multicast_rloc_probe_list ) :
   I11iIii1ii1Ii = lisp_rloc ( )
   I11iIii1ii1Ii = copy . deepcopy ( mrloc )
   I11iIii1ii1Ii . rloc . copy_address ( IIIi1iI1 )
   I11iIii1ii1Ii . multicast_rloc_probe_list = { }
   mrloc . multicast_rloc_probe_list [ iIi1iI ] = I11iIii1ii1Ii
   if 49 - 49: O0 . i11iIiiIii / I11i + OOooOOo * OOooOOo + II111iiii
  I11iIii1ii1Ii = mrloc . multicast_rloc_probe_list [ iIi1iI ]
  I11iIii1ii1Ii . last_rloc_probe_nonce = mrloc . last_rloc_probe_nonce
  I11iIii1ii1Ii . last_rloc_probe = mrloc . last_rloc_probe
  OOoooo , oo0oO , iiI = lisp_rloc_probe_list [ OooO ] [ 0 ]
  I11iIii1ii1Ii . process_rloc_probe_reply ( i1 , o00oO0O000 , oo0oO , iiI , O0O0OooooooOO , ttl , oOoOOO )
  mrloc . process_rloc_probe_reply ( i1 , o00oO0O000 , oo0oO , iiI , O0O0OooooooOO , ttl , oOoOOO )
  return
  if 55 - 55: I11i / I1ii11iIi11i . I1ii11iIi11i - Oo0Ooo
  if 4 - 4: I1IiiI
  if 40 - 40: Oo0Ooo % oO0o
  if 40 - 40: IiII * o0oOOo0O0Ooo . I1Ii111 - O0 % OoooooooOO + I1Ii111
  if 1 - 1: I1Ii111 % OoooooooOO + OoooooooOO - I1IiiI % I1IiiI
  if 51 - 51: iIii1I11I1II1 / I1IiiI
  if 27 - 27: O0 . o0oOOo0O0Ooo / ooOoO0o / OoooooooOO % Ii1I
 oOOOo0o = iIi1iI
 if ( oOOOo0o not in iIi1Iiii11Ii1 ) :
  oOOOo0o += ":" + str ( port )
  if ( oOOOo0o not in iIi1Iiii11Ii1 ) :
   oOOOo0o = IiiIOooo
   if ( oOOOo0o not in iIi1Iiii11Ii1 ) :
    oOOOo0o += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( iII11 , red ( iIi1iI , False ) , red ( IiiIOooo ,
    # I1IiiI % ooOoO0o
 False ) , port ) )
    return
    if 50 - 50: OoO0O00 + Ii1I % IiII * iII111i * oO0o . i11iIiiIii
    if 100 - 100: oO0o % OOooOOo * IiII / II111iiii . o0oOOo0O0Ooo
    if 35 - 35: OoooooooOO + I1Ii111 . OOooOOo * ooOoO0o + I1IiiI * Oo0Ooo
    if 65 - 65: OoooooooOO / i11iIiiIii + Ii1I * I11i + I11i * I11i
    if 64 - 64: ooOoO0o % II111iiii / OOooOOo . Ii1I % IiII + OOooOOo
    if 10 - 10: i11iIiiIii
    if 78 - 78: ooOoO0o * I11i / I1IiiI * O0
    if 78 - 78: OOooOOo / Oo0Ooo % Oo0Ooo % iII111i
 for IIIi1iI1 , oo0oO , iiI in lisp_rloc_probe_list [ oOOOo0o ] :
  if ( lisp_i_am_rtr ) :
   if ( IIIi1iI1 . translated_port != 0 and IIIi1iI1 . translated_port != port ) :
    continue
    if 15 - 15: OoO0O00 * IiII % ooOoO0o * Ii1I / I1ii11iIi11i * OoO0O00
    if 18 - 18: OoooooooOO
  IIIi1iI1 . process_rloc_probe_reply ( i1 , o00oO0O000 , oo0oO , iiI , O0O0OooooooOO , ttl , oOoOOO )
  if 19 - 19: Ii1I / o0oOOo0O0Ooo / i11iIiiIii
 return
 if 3 - 3: II111iiii / Oo0Ooo
 if 94 - 94: I11i + iII111i % OoOoOO00 - II111iiii + i1IIi
 if 27 - 27: II111iiii % Ii1I * II111iiii
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 if 11 - 11: I11i * iII111i
def lisp_db_list_length ( ) :
 Ooo0oOOoo0O = 0
 for iIiI1ii in lisp_db_list :
  Ooo0oOOoo0O += len ( iIiI1ii . dynamic_eids ) if iIiI1ii . dynamic_eid_configured ( ) else 1
  Ooo0oOOoo0O += len ( iIiI1ii . eid . iid_list )
  if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 return ( Ooo0oOOoo0O )
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
 if 47 - 47: iII111i % iII111i
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 if 74 - 74: I11i % OOooOOo
 if 57 - 57: O0 + I1IiiI + i11iIiiIii
 if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
def lisp_is_myeid ( eid ) :
 for iIiI1ii in lisp_db_list :
  if ( eid . is_more_specific ( iIiI1ii . eid ) ) : return ( True )
  if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
 return ( False )
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
 if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
 if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
 if 21 - 21: O0
 if 14 - 14: IiII / I1ii11iIi11i + Ii1I
 if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
 if 38 - 38: I1IiiI * Ii1I + Oo0Ooo - OoooooooOO
 if 63 - 63: I1ii11iIi11i
 if 99 - 99: I1Ii111 % oO0o - II111iiii . ooOoO0o
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 26 - 26: I1ii11iIi11i * iII111i . OoooooooOO - Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 I1 = None
 if ( rloc_str in lisp_nonce_echo_list ) :
  I1 = lisp_nonce_echo_list [ rloc_str ]
  if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 return ( I1 )
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
def lisp_decode_dist_name ( packet ) :
 Ooo0oOOoo0O = 0
 OO0oOOOoO00 = ""
 if 43 - 43: II111iiii % II111iiii - OoooooooOO
 while ( packet [ 0 : 1 ] != "\0" ) :
  if ( Ooo0oOOoo0O == 255 ) : return ( [ None , None ] )
  OO0oOOOoO00 += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  Ooo0oOOoo0O += 1
  if 4 - 4: iIii1I11I1II1 / OoooooooOO * OoooooooOO
  if 88 - 88: Ii1I % OoOoOO00
 packet = packet [ 1 : : ]
 return ( packet , OO0oOOOoO00 )
 if 66 - 66: OoooooooOO . I1Ii111 + II111iiii / I1Ii111 / I1Ii111
 if 10 - 10: i1IIi / ooOoO0o * o0oOOo0O0Ooo % i11iIiiIii - oO0o % i11iIiiIii
 if 27 - 27: I1Ii111
 if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
 if 63 - 63: o0oOOo0O0Ooo . iIii1I11I1II1 % IiII * i11iIiiIii
 if 70 - 70: iIii1I11I1II1
 if 12 - 12: OoOoOO00 / o0oOOo0O0Ooo - I1ii11iIi11i + oO0o + O0
 if 9 - 9: I1ii11iIi11i * OoooooooOO . O0 . ooOoO0o * i11iIiiIii / i1IIi
def lisp_write_flow_log ( flow_log ) :
 I1Ii = open ( "./logs/lisp-flow.log" , "a" )
 if 38 - 38: OoOoOO00 . OoooooooOO % I1ii11iIi11i . oO0o % oO0o
 Ooo0oOOoo0O = 0
 for Ooooo in flow_log :
  OO0 = Ooooo [ 3 ]
  OooOI1I = OO0 . print_flow ( Ooooo [ 0 ] , Ooooo [ 1 ] , Ooooo [ 2 ] )
  I1Ii . write ( OooOI1I )
  Ooo0oOOoo0O += 1
  if 94 - 94: OoO0O00 . o0oOOo0O0Ooo . oO0o / iII111i
 I1Ii . close ( )
 del ( flow_log )
 if 10 - 10: I1ii11iIi11i / ooOoO0o % O0
 Ooo0oOOoo0O = bold ( str ( Ooo0oOOoo0O ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( Ooo0oOOoo0O ) )
 return
 if 65 - 65: iII111i
 if 77 - 77: II111iiii
 if 100 - 100: O0 / iII111i + ooOoO0o / IiII
 if 12 - 12: oO0o + Oo0Ooo + I1ii11iIi11i / O0
 if 94 - 94: I1ii11iIi11i * OoOoOO00 * iIii1I11I1II1 / I11i
 if 19 - 19: II111iiii * oO0o
 if 70 - 70: ooOoO0o - II111iiii . I11i
def lisp_policy_command ( kv_pair ) :
 IiIiIII11i1i = lisp_policy ( "" )
 O0O0OO000ooo = None
 if 9 - 9: OoOoOO00 * ooOoO0o * iII111i . IiII
 oO00OO00 = [ ]
 for OoOOoO0oOo in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  oO00OO00 . append ( lisp_policy_match ( ) )
  if 35 - 35: oO0o
  if 8 - 8: IiII / o0oOOo0O0Ooo
 for ooOOOoo in list ( kv_pair . keys ( ) ) :
  iiIiII11i1 = kv_pair [ ooOOOoo ]
  if 22 - 22: O0 . I1IiiI
  if 35 - 35: I1Ii111
  if 80 - 80: I1Ii111 * I11i + O0 - OOooOOo . ooOoO0o - i11iIiiIii
  if 49 - 49: iIii1I11I1II1 + iIii1I11I1II1 - I1ii11iIi11i % o0oOOo0O0Ooo - i11iIiiIii
  if ( ooOOOoo == "instance-id" ) :
   for OoOOoO0oOo in range ( len ( oO00OO00 ) ) :
    O0Ii1i1iiIi = iiIiII11i1 [ OoOOoO0oOo ]
    if ( O0Ii1i1iiIi == "" ) : continue
    IiiIii = oO00OO00 [ OoOOoO0oOo ]
    if ( IiiIii . source_eid == None ) :
     IiiIii . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 73 - 73: OoOoOO00
    if ( IiiIii . dest_eid == None ) :
     IiiIii . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 25 - 25: iII111i / oO0o
    IiiIii . source_eid . instance_id = int ( O0Ii1i1iiIi )
    IiiIii . dest_eid . instance_id = int ( O0Ii1i1iiIi )
    if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
    if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
  if ( ooOOOoo == "source-eid" ) :
   for OoOOoO0oOo in range ( len ( oO00OO00 ) ) :
    O0Ii1i1iiIi = iiIiII11i1 [ OoOOoO0oOo ]
    if ( O0Ii1i1iiIi == "" ) : continue
    IiiIii = oO00OO00 [ OoOOoO0oOo ]
    if ( IiiIii . source_eid == None ) :
     IiiIii . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 61 - 61: I1IiiI / OOooOOo
    i1oO00O = IiiIii . source_eid . instance_id
    IiiIii . source_eid . store_prefix ( O0Ii1i1iiIi )
    IiiIii . source_eid . instance_id = i1oO00O
    if 67 - 67: OoOoOO00
    if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
  if ( ooOOOoo == "destination-eid" ) :
   for OoOOoO0oOo in range ( len ( oO00OO00 ) ) :
    O0Ii1i1iiIi = iiIiII11i1 [ OoOOoO0oOo ]
    if ( O0Ii1i1iiIi == "" ) : continue
    IiiIii = oO00OO00 [ OoOOoO0oOo ]
    if ( IiiIii . dest_eid == None ) :
     IiiIii . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
    i1oO00O = IiiIii . dest_eid . instance_id
    IiiIii . dest_eid . store_prefix ( O0Ii1i1iiIi )
    IiiIii . dest_eid . instance_id = i1oO00O
    if 95 - 95: ooOoO0o % OOooOOo
    if 17 - 17: i1IIi + Ii1I
  if ( ooOOOoo == "source-rloc" ) :
   for OoOOoO0oOo in range ( len ( oO00OO00 ) ) :
    O0Ii1i1iiIi = iiIiII11i1 [ OoOOoO0oOo ]
    if ( O0Ii1i1iiIi == "" ) : continue
    IiiIii = oO00OO00 [ OoOOoO0oOo ]
    IiiIii . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    IiiIii . source_rloc . store_prefix ( O0Ii1i1iiIi )
    if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
    if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
  if ( ooOOOoo == "destination-rloc" ) :
   for OoOOoO0oOo in range ( len ( oO00OO00 ) ) :
    O0Ii1i1iiIi = iiIiII11i1 [ OoOOoO0oOo ]
    if ( O0Ii1i1iiIi == "" ) : continue
    IiiIii = oO00OO00 [ OoOOoO0oOo ]
    IiiIii . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    IiiIii . dest_rloc . store_prefix ( O0Ii1i1iiIi )
    if 26 - 26: oO0o / I1ii11iIi11i - oO0o
    if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
  if ( ooOOOoo == "rloc-record-name" ) :
   for OoOOoO0oOo in range ( len ( oO00OO00 ) ) :
    O0Ii1i1iiIi = iiIiII11i1 [ OoOOoO0oOo ]
    if ( O0Ii1i1iiIi == "" ) : continue
    IiiIii = oO00OO00 [ OoOOoO0oOo ]
    IiiIii . rloc_record_name = O0Ii1i1iiIi
    if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
    if 96 - 96: Ii1I
  if ( ooOOOoo == "geo-name" ) :
   for OoOOoO0oOo in range ( len ( oO00OO00 ) ) :
    O0Ii1i1iiIi = iiIiII11i1 [ OoOOoO0oOo ]
    if ( O0Ii1i1iiIi == "" ) : continue
    IiiIii = oO00OO00 [ OoOOoO0oOo ]
    IiiIii . geo_name = O0Ii1i1iiIi
    if 90 - 90: II111iiii
    if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
  if ( ooOOOoo == "elp-name" ) :
   for OoOOoO0oOo in range ( len ( oO00OO00 ) ) :
    O0Ii1i1iiIi = iiIiII11i1 [ OoOOoO0oOo ]
    if ( O0Ii1i1iiIi == "" ) : continue
    IiiIii = oO00OO00 [ OoOOoO0oOo ]
    IiiIii . elp_name = O0Ii1i1iiIi
    if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
    if 52 - 52: i11iIiiIii * ooOoO0o
  if ( ooOOOoo == "rle-name" ) :
   for OoOOoO0oOo in range ( len ( oO00OO00 ) ) :
    O0Ii1i1iiIi = iiIiII11i1 [ OoOOoO0oOo ]
    if ( O0Ii1i1iiIi == "" ) : continue
    IiiIii = oO00OO00 [ OoOOoO0oOo ]
    IiiIii . rle_name = O0Ii1i1iiIi
    if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
    if 91 - 91: ooOoO0o
  if ( ooOOOoo == "json-name" ) :
   for OoOOoO0oOo in range ( len ( oO00OO00 ) ) :
    O0Ii1i1iiIi = iiIiII11i1 [ OoOOoO0oOo ]
    if ( O0Ii1i1iiIi == "" ) : continue
    IiiIii = oO00OO00 [ OoOOoO0oOo ]
    IiiIii . json_name = O0Ii1i1iiIi
    if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
    if 9 - 9: O0 + IiII
  if ( ooOOOoo == "datetime-range" ) :
   for OoOOoO0oOo in range ( len ( oO00OO00 ) ) :
    O0Ii1i1iiIi = iiIiII11i1 [ OoOOoO0oOo ]
    IiiIii = oO00OO00 [ OoOOoO0oOo ]
    if ( O0Ii1i1iiIi == "" ) : continue
    OOoOo0O0 = lisp_datetime ( O0Ii1i1iiIi [ 0 : 19 ] )
    oOO0Oo000O0o = lisp_datetime ( O0Ii1i1iiIi [ 19 : : ] )
    if ( OOoOo0O0 . valid_datetime ( ) and oOO0Oo000O0o . valid_datetime ( ) ) :
     IiiIii . datetime_lower = OOoOo0O0
     IiiIii . datetime_upper = oOO0Oo000O0o
     if 69 - 69: I1IiiI
     if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
     if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
     if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
     if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
     if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
     if 19 - 19: I1ii11iIi11i
  if ( ooOOOoo == "set-action" ) :
   IiIiIII11i1i . set_action = iiIiII11i1
   if 42 - 42: OoOoOO00 / IiII
  if ( ooOOOoo == "set-record-ttl" ) :
   IiIiIII11i1i . set_record_ttl = int ( iiIiII11i1 )
   if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
  if ( ooOOOoo == "set-instance-id" ) :
   if ( IiIiIII11i1i . set_source_eid == None ) :
    IiIiIII11i1i . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 99 - 99: I11i % ooOoO0o . I1Ii111
   if ( IiIiIII11i1i . set_dest_eid == None ) :
    IiIiIII11i1i . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 34 - 34: ooOoO0o + oO0o + II111iiii . I1Ii111 . i1IIi
   O0O0OO000ooo = int ( iiIiII11i1 )
   IiIiIII11i1i . set_source_eid . instance_id = O0O0OO000ooo
   IiIiIII11i1i . set_dest_eid . instance_id = O0O0OO000ooo
   if 14 - 14: OoO0O00 . ooOoO0o - i1IIi * I1IiiI
  if ( ooOOOoo == "set-source-eid" ) :
   if ( IiIiIII11i1i . set_source_eid == None ) :
    IiIiIII11i1i . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 24 - 24: iIii1I11I1II1 / I1Ii111
   IiIiIII11i1i . set_source_eid . store_prefix ( iiIiII11i1 )
   if ( O0O0OO000ooo != None ) : IiIiIII11i1i . set_source_eid . instance_id = O0O0OO000ooo
   if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
  if ( ooOOOoo == "set-destination-eid" ) :
   if ( IiIiIII11i1i . set_dest_eid == None ) :
    IiIiIII11i1i . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 64 - 64: I1ii11iIi11i . i1IIi % II111iiii % Oo0Ooo + oO0o - I1IiiI
   IiIiIII11i1i . set_dest_eid . store_prefix ( iiIiII11i1 )
   if ( O0O0OO000ooo != None ) : IiIiIII11i1i . set_dest_eid . instance_id = O0O0OO000ooo
   if 24 - 24: IiII . II111iiii . II111iiii . OoOoOO00 . i11iIiiIii
  if ( ooOOOoo == "set-rloc-address" ) :
   IiIiIII11i1i . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   IiIiIII11i1i . set_rloc_address . store_address ( iiIiII11i1 )
   if 11 - 11: Ii1I
  if ( ooOOOoo == "set-rloc-record-name" ) :
   IiIiIII11i1i . set_rloc_record_name = iiIiII11i1
   if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
  if ( ooOOOoo == "set-elp-name" ) :
   IiIiIII11i1i . set_elp_name = iiIiII11i1
   if 44 - 44: iII111i
  if ( ooOOOoo == "set-geo-name" ) :
   IiIiIII11i1i . set_geo_name = iiIiII11i1
   if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
  if ( ooOOOoo == "set-rle-name" ) :
   IiIiIII11i1i . set_rle_name = iiIiII11i1
   if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
  if ( ooOOOoo == "set-json-name" ) :
   IiIiIII11i1i . set_json_name = iiIiII11i1
   if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
  if ( ooOOOoo == "policy-name" ) :
   IiIiIII11i1i . policy_name = iiIiII11i1
   if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
   if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
   if 14 - 14: IiII . i11iIiiIii
   if 17 - 17: ooOoO0o % ooOoO0o * oO0o
   if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
   if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
 IiIiIII11i1i . match_clauses = oO00OO00
 IiIiIII11i1i . save_policy ( )
 return
 if 53 - 53: I1Ii111 % i11iIiiIii
 if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
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
if 80 - 80: o0oOOo0O0Ooo . I11i % iIii1I11I1II1 + OoOoOO00
if 87 - 87: I1Ii111 + II111iiii / I1ii11iIi11i + OoOoOO00
if 71 - 71: I1IiiI + iIii1I11I1II1 + O0 * iII111i % IiII
if 42 - 42: OOooOOo - I1ii11iIi11i
if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
if 12 - 12: i11iIiiIii
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 62 - 62: oO0o + OOooOOo + oO0o + I1IiiI
 i11I1I11I = command
 if ( interface != "" ) : i11I1I11I = interface + ": " + i11I1I11I
 lprint ( "Send CLI command '{}' to hardware" . format ( i11I1I11I ) )
 if 8 - 8: I11i % II111iiii / I11i % Ii1I
 Ii1iI = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 30 - 30: OoOoOO00 + I1Ii111 . OoOoOO00 - I11i
 os . system ( "FastCli -c '{}'" . format ( Ii1iI ) )
 return
 if 42 - 42: OoOoOO00
 if 77 - 77: Oo0Ooo * IiII * I1ii11iIi11i + IiII
 if 37 - 37: IiII . OoooooooOO - i11iIiiIii * I1ii11iIi11i - OOooOOo
 if 74 - 74: Ii1I + i11iIiiIii * iII111i / o0oOOo0O0Ooo . i11iIiiIii
 if 99 - 99: OOooOOo - OoooooooOO + OoooooooOO . OOooOOo
 if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
 if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
def lisp_arista_is_alive ( prefix ) :
 i1i1I11I = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 OoiIIIiIi1I1i = getoutput ( "FastCli -c '{}'" . format ( i1i1I11I ) )
 if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
 if 78 - 78: OoO0O00 - i1IIi % I1Ii111
 if 87 - 87: I11i
 if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
 OoiIIIiIi1I1i = OoiIIIiIi1I1i . split ( "\n" ) [ 1 ]
 O0Ooo0Ooooo = OoiIIIiIi1I1i . split ( " " )
 O0Ooo0Ooooo = O0Ooo0Ooooo [ - 1 ] . replace ( "\r" , "" )
 if 34 - 34: i11iIiiIii / I1Ii111 - o0oOOo0O0Ooo / i1IIi * I11i
 if 87 - 87: IiII / I1IiiI . OoOoOO00
 if 80 - 80: i1IIi + OOooOOo % i11iIiiIii * I1ii11iIi11i
 if 49 - 49: iIii1I11I1II1
 return ( O0Ooo0Ooooo == "Y" )
 if 2 - 2: OOooOOo * o0oOOo0O0Ooo - OOooOOo . I11i
 if 32 - 32: OoO0O00
 if 34 - 34: O0 * iIii1I11I1II1 . o0oOOo0O0Ooo . I1Ii111 . iIii1I11I1II1 * iIii1I11I1II1
 if 38 - 38: iIii1I11I1II1
 if 83 - 83: iII111i - Ii1I . oO0o - I1Ii111 * o0oOOo0O0Ooo
 if 70 - 70: i11iIiiIii - OoO0O00 / i11iIiiIii
 if 46 - 46: II111iiii + O0 * OoooooooOO
 if 39 - 39: OoooooooOO % II111iiii . o0oOOo0O0Ooo
 if 29 - 29: I11i . o0oOOo0O0Ooo . i1IIi . o0oOOo0O0Ooo
 if 77 - 77: iIii1I11I1II1 + iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i - IiII % I1IiiI % i1IIi
 if 98 - 98: I1Ii111 + II111iiii % OoO0O00 % iII111i
 if 54 - 54: II111iiii . ooOoO0o . iII111i - I1IiiI
 if 97 - 97: oO0o - O0 / II111iiii * II111iiii - oO0o * IiII
 if 97 - 97: IiII % OoO0O00 . OoOoOO00 - Ii1I
 if 28 - 28: O0 . I11i . I1IiiI - Ii1I - iII111i - iIii1I11I1II1
 if 14 - 14: OOooOOo + ooOoO0o
 if 56 - 56: o0oOOo0O0Ooo - OoOoOO00 - Ii1I
 if 50 - 50: I1ii11iIi11i
 if 24 - 24: ooOoO0o
 if 19 - 19: oO0o
 if 97 - 97: IiII
 if 36 - 36: II111iiii
 if 83 - 83: I11i . ooOoO0o
 if 57 - 57: IiII
 if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
 if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
 if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
 if 79 - 79: I1ii11iIi11i % I11i
 if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
 if 66 - 66: I1IiiI - o0oOOo0O0Ooo
 if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
 if 98 - 98: OoOoOO00 * OoO0O00 . Oo0Ooo
 if 6 - 6: I11i % iIii1I11I1II1 + I1Ii111
 if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
 if 90 - 90: OOooOOo
 if 43 - 43: IiII + ooOoO0o
 if 4 - 4: i1IIi
 if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
 if 6 - 6: Ii1I / iII111i
 if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
 if 70 - 70: oO0o - I1IiiI + Ii1I
 if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
 if 37 - 37: o0oOOo0O0Ooo
def lisp_program_vxlan_hardware ( mc ) :
 if 57 - 57: iII111i / i1IIi / i1IIi + IiII
 if 75 - 75: IiII / O0
 if 72 - 72: I11i
 if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
 if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 if 23 - 23: OoOoOO00 . oO0o - iII111i
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
 if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 88 - 88: I1Ii111
 if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
 if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
 if 83 - 83: oO0o
 i1IIiiIiiI1ii = mc . eid . print_prefix_no_iid ( )
 IIIi1iI1 = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
 if 71 - 71: II111iiii + iII111i + O0 % Oo0Ooo / I1IiiI
 if 52 - 52: Oo0Ooo . I1Ii111 * i1IIi / Oo0Ooo / OoO0O00
 if 29 - 29: iII111i
 oO0OOo0O0 = getoutput ( "ip route get {} | egrep vlan4094" . format ( i1IIiiIiiI1ii ) )
 if 81 - 81: i11iIiiIii / I1ii11iIi11i + i1IIi / I11i * I1IiiI
 if ( oO0OOo0O0 != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( i1IIiiIiiI1ii , False ) , oO0OOo0O0 ) )
  if 42 - 42: i1IIi . I1Ii111 - ooOoO0o + I11i / oO0o
  return
  if 60 - 60: i1IIi + OoooooooOO % i11iIiiIii / IiII % Oo0Ooo + I1IiiI
  if 87 - 87: Ii1I % OoooooooOO % I1Ii111 * i11iIiiIii * OoOoOO00
  if 78 - 78: I11i
  if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
  if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
  if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
  if 53 - 53: I1IiiI % I1IiiI
 OOoo00oOO = getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( OOoo00oOO . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 33 - 33: O0 * I11i * ooOoO0o / OoOoOO00 % IiII - I1IiiI
 if ( OOoo00oOO . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 15 - 15: II111iiii . O0 . iIii1I11I1II1 / O0 - oO0o
 IiIIi1 = getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( IiIIi1 == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 35 - 35: oO0o * i1IIi / IiII / iII111i
 IiIIi1 = IiIIi1 . split ( "inet " ) [ 1 ]
 IiIIi1 = IiIIi1 . split ( "/" ) [ 0 ]
 if 19 - 19: I1IiiI + iIii1I11I1II1 * O0 - OOooOOo
 if 32 - 32: O0 - II111iiii - i1IIi + O0 + OOooOOo
 if 44 - 44: I11i * oO0o % OoooooooOO % OoO0O00 / o0oOOo0O0Ooo
 if 37 - 37: OoO0O00 + OoOoOO00 - I1IiiI
 if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
 if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
 if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
 IiI11i = [ ]
 iI1i1iI1i = getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for IiiiI1 in iI1i1iI1i :
  if ( IiiiI1 . find ( "vlan4094" ) == - 1 ) : continue
  if ( IiiiI1 . find ( "(incomplete)" ) == - 1 ) : continue
  o00o0O0O0oO0o = IiiiI1 . split ( " " ) [ 0 ]
  IiI11i . append ( o00o0O0O0oO0o )
  if 12 - 12: iII111i * OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + oO0o
  if 100 - 100: OoOoOO00 / ooOoO0o + OOooOOo
 o00o0O0O0oO0o = None
 o0o0iiiI1ii1 = IiIIi1
 IiIIi1 = IiIIi1 . split ( "." )
 for OoOOoO0oOo in range ( 1 , 255 ) :
  IiIIi1 [ 3 ] = str ( OoOOoO0oOo )
  oOOOo0o = "." . join ( IiIIi1 )
  if ( oOOOo0o in IiI11i ) : continue
  if ( oOOOo0o == o0o0iiiI1ii1 ) : continue
  o00o0O0O0oO0o = oOOOo0o
  break
  if 56 - 56: oO0o / I11i * i1IIi + iIii1I11I1II1 % OoO0O00 / o0oOOo0O0Ooo
 if ( o00o0O0O0oO0o == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 46 - 46: I1IiiI . Ii1I % ooOoO0o + O0 . o0oOOo0O0Ooo * I11i
  return
  if 44 - 44: IiII % I1IiiI
  if 19 - 19: iIii1I11I1II1 . oO0o
  if 53 - 53: i1IIi - iIii1I11I1II1 * o0oOOo0O0Ooo / OoooooooOO
  if 30 - 30: OOooOOo . iIii1I11I1II1 * ooOoO0o * OoooooooOO / I1IiiI
  if 67 - 67: OoOoOO00 % iII111i . o0oOOo0O0Ooo / II111iiii * O0 / I1IiiI
  if 20 - 20: oO0o * O0 - Ii1I + i11iIiiIii - OoOoOO00
  if 18 - 18: I1ii11iIi11i . iII111i
 i1Iii11iiiII1 = IIIi1iI1 . split ( "." )
 ooOOOOo0oOOOO0 = lisp_hex_string ( i1Iii11iiiII1 [ 1 ] ) . zfill ( 2 )
 IiIii1ii = lisp_hex_string ( i1Iii11iiiII1 [ 2 ] ) . zfill ( 2 )
 oo0oO0O00OOO = lisp_hex_string ( i1Iii11iiiII1 [ 3 ] ) . zfill ( 2 )
 O0o0oo0oOO0oO = "00:00:00:{}:{}:{}" . format ( ooOOOOo0oOOOO0 , IiIii1ii , oo0oO0O00OOO )
 i1Ii11IIIi = "0000.00{}.{}{}" . format ( ooOOOOo0oOOOO0 , IiIii1ii , oo0oO0O00OOO )
 ooO0 = "arp -i vlan4094 -s {} {}" . format ( o00o0O0O0oO0o , O0o0oo0oOO0oO )
 os . system ( ooO0 )
 if 43 - 43: I1ii11iIi11i - Oo0Ooo . oO0o
 if 2 - 2: OoOoOO00 . I1IiiI
 if 88 - 88: I1IiiI
 if 34 - 34: ooOoO0o + I1Ii111 / iIii1I11I1II1 + Ii1I . o0oOOo0O0Ooo * OoO0O00
 ooooO0000o000o = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( i1Ii11IIIi , IIIi1iI1 )
 if 21 - 21: o0oOOo0O0Ooo * o0oOOo0O0Ooo - OoOoOO00 % OoOoOO00
 lisp_send_to_arista ( ooooO0000o000o , None )
 if 8 - 8: I1ii11iIi11i
 if 5 - 5: OOooOOo * i11iIiiIii % oO0o * ooOoO0o
 if 37 - 37: oO0o . IiII + I1ii11iIi11i
 if 57 - 57: ooOoO0o * o0oOOo0O0Ooo . i11iIiiIii . I1Ii111 . i1IIi
 if 95 - 95: I1Ii111 % o0oOOo0O0Ooo . I1Ii111
 i1I1II1iI = "ip route add {} via {}" . format ( i1IIiiIiiI1ii , o00o0O0O0oO0o )
 os . system ( i1I1II1iI )
 if 53 - 53: I1IiiI / o0oOOo0O0Ooo / o0oOOo0O0Ooo - o0oOOo0O0Ooo
 lprint ( "Hardware programmed with commands:" )
 i1I1II1iI = i1I1II1iI . replace ( i1IIiiIiiI1ii , green ( i1IIiiIiiI1ii , False ) )
 lprint ( "  " + i1I1II1iI )
 lprint ( "  " + ooO0 )
 ooooO0000o000o = ooooO0000o000o . replace ( IIIi1iI1 , red ( IIIi1iI1 , False ) )
 lprint ( "  " + ooooO0000o000o )
 return
 if 48 - 48: OoOoOO00 / IiII
 if 24 - 24: IiII + OoooooooOO * Ii1I % iIii1I11I1II1
 if 22 - 22: I1Ii111 - I1ii11iIi11i . Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: oO0o + OoOoOO00
 if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 if 59 - 59: O0
def lisp_clear_hardware_walk ( mc , parms ) :
 Ii1IIIIi = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( Ii1IIIIi ) )
 return ( [ True , None ] )
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 72 - 72: IiII / II111iiii
 IiIIIIi = bold ( "User cleared" , False )
 Ooo0oOOoo0O = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( IiIIIIi , Ooo0oOOoo0O ) )
 if 21 - 21: I1ii11iIi11i
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 60 - 60: i1IIi / OoO0O00 . Ii1I
 lisp_map_cache = lisp_cache ( )
 if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
 if 26 - 26: iII111i
 if 31 - 31: iII111i
 if 45 - 45: OoO0O00
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 55 - 55: iIii1I11I1II1 % iIii1I11I1II1 + I11i - ooOoO0o + I1IiiI * O0
 if 47 - 47: ooOoO0o + iIii1I11I1II1 * OOooOOo . I1IiiI . o0oOOo0O0Ooo
 if 49 - 49: Oo0Ooo . OoOoOO00 * OOooOOo
 if 86 - 86: IiII * OOooOOo + Ii1I
 if 62 - 62: I11i
 lisp_rloc_probe_list = { }
 if 86 - 86: Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
 if 15 - 15: I1IiiI / I1Ii111 % iII111i
 if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
 if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 43 - 43: oO0o . OoO0O00 * i1IIi
 if 1 - 1: ooOoO0o / i1IIi
 if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
 if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
 if 75 - 75: I11i * IiII * ooOoO0o
 lisp_rtr_list = { }
 if 31 - 31: Ii1I
 if 72 - 72: OOooOOo * Ii1I % OoO0O00
 if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
 if 42 - 42: oO0o / i1IIi . IiII
 lisp_gleaned_groups = { }
 if 12 - 12: i11iIiiIii . ooOoO0o
 if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if 88 - 88: OoooooooOO . I1IiiI
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 lisp_process_data_plane_restart ( True )
 return
 if 7 - 7: i1IIi
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 if 29 - 29: II111iiii % i11iIiiIii % O0
 if 38 - 38: o0oOOo0O0Ooo * IiII
 if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
 if 19 - 19: OoooooooOO
 if 34 - 34: OoOoOO00 . oO0o
 if 53 - 53: oO0o + OoooooooOO * ooOoO0o
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 I1I1I1I = lisp_myrlocs [ 0 ]
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 if 80 - 80: II111iiii . i11iIiiIii
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 52 - 52: iIii1I11I1II1 + O0
 i1iIii = len ( packet ) + 28
 o0OO00oo0O = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( i1iIii ) , 0 , 64 ,
 17 , 0 , socket . htonl ( I1I1I1I . address ) , socket . htonl ( rloc . address ) )
 o0OO00oo0O = lisp_ip_checksum ( o0OO00oo0O )
 if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 Ii1iiI1 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( i1iIii - 20 ) , 0 )
 if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
 if 29 - 29: iII111i % I1Ii111
 if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
 if 63 - 63: ooOoO0o
 packet = lisp_packet ( o0OO00oo0O + Ii1iiI1 + packet )
 if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
 if 90 - 90: IiII
 if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( I1I1I1I )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( I1I1I1I )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 iiIIii = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  III11iI1 = " {}" . format ( blue ( nat_info . hostname , False ) )
  iII11 = bold ( "RLOC-probe request" , False )
 else :
  III11iI1 = ""
  iII11 = bold ( "RLOC-probe reply" , False )
  if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
  if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( iII11 , iiIIii , III11iI1 , packet . encap_port ) )
 if 98 - 98: OOooOOo
 if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
 if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
 if 75 - 75: II111iiii . O0 . I1Ii111 * O0 / OoooooooOO
 if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
 IiiII11iIi = lisp_sockets [ 3 ]
 packet . send_packet ( IiiII11iIi , packet . outer_dest )
 del ( packet )
 return
 if 4 - 4: Oo0Ooo / I1IiiI * i1IIi . II111iiii
 if 13 - 13: i1IIi
 if 39 - 39: OOooOOo
 if 73 - 73: OoO0O00 . ooOoO0o
 if 13 - 13: o0oOOo0O0Ooo - OoOoOO00
 if 60 - 60: OoO0O00
 if 17 - 17: i11iIiiIii % i1IIi % I1IiiI % ooOoO0o + I1Ii111 + Oo0Ooo
 if 16 - 16: iII111i . I1ii11iIi11i . oO0o . OoO0O00
def lisp_get_default_route_next_hops ( ) :
 if 90 - 90: i1IIi . ooOoO0o + i11iIiiIii * OoooooooOO
 if 30 - 30: iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
 if 38 - 38: IiII + II111iiii
 if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
 if ( lisp_is_macos ( ) ) :
  i1i1I11I = "route -n get default"
  iiiiIIII1ii1 = getoutput ( i1i1I11I ) . split ( "\n" )
  iiIOooo0000O0O00 = OooOO = None
  for I1Ii in iiiiIIII1ii1 :
   if ( I1Ii . find ( "gateway: " ) != - 1 ) : iiIOooo0000O0O00 = I1Ii . split ( ": " ) [ 1 ]
   if ( I1Ii . find ( "interface: " ) != - 1 ) : OooOO = I1Ii . split ( ": " ) [ 1 ]
   if 79 - 79: OoOoOO00 . IiII * iII111i % OoooooooOO % i1IIi % iIii1I11I1II1
  return ( [ [ OooOO , iiIOooo0000O0O00 ] ] )
  if 20 - 20: I1Ii111 % oO0o * iIii1I11I1II1 % oO0o . IiII % OoooooooOO
  if 11 - 11: Oo0Ooo / Oo0Ooo / OoO0O00 / oO0o . iIii1I11I1II1 + I1Ii111
  if 23 - 23: Oo0Ooo * IiII - I1Ii111 . OoooooooOO
  if 78 - 78: OoOoOO00 - iIii1I11I1II1
  if 20 - 20: i1IIi
 i1i1I11I = "ip route | egrep 'default via'"
 oOOO = getoutput ( i1i1I11I ) . split ( "\n" )
 if 72 - 72: ooOoO0o . II111iiii
 iiI1iII = [ ]
 for oO0OOo0O0 in oOOO :
  if ( oO0OOo0O0 . find ( " metric " ) != - 1 ) : continue
  OOoooo = oO0OOo0O0 . split ( " " )
  try :
   I1IIiiII = OOoooo . index ( "via" ) + 1
   if ( I1IIiiII >= len ( OOoooo ) ) : continue
   ii1I = OOoooo . index ( "dev" ) + 1
   if ( ii1I >= len ( OOoooo ) ) : continue
  except :
   continue
   if 31 - 31: O0 / oO0o + O0 * OoOoOO00 / Oo0Ooo
   if 98 - 98: Oo0Ooo + iII111i . i11iIiiIii + IiII % Ii1I
  iiI1iII . append ( [ OOoooo [ ii1I ] , OOoooo [ I1IIiiII ] ] )
  if 42 - 42: i1IIi / o0oOOo0O0Ooo
 return ( iiI1iII )
 if 66 - 66: I1IiiI * O0
 if 59 - 59: oO0o % I1ii11iIi11i % O0 . ooOoO0o + iIii1I11I1II1
 if 8 - 8: I1Ii111 * Ii1I
 if 89 - 89: o0oOOo0O0Ooo
 if 39 - 39: I1ii11iIi11i . OOooOOo . OoO0O00 * O0 . iIii1I11I1II1 . I1ii11iIi11i
 if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 if 38 - 38: Ii1I
def lisp_get_host_route_next_hop ( rloc ) :
 i1i1I11I = "ip route | egrep '{} via'" . format ( rloc )
 oO0OOo0O0 = getoutput ( i1i1I11I ) . split ( " " )
 if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 try : OOOooo0OooOoO = oO0OOo0O0 . index ( "via" ) + 1
 except : return ( None )
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 if ( OOOooo0OooOoO >= len ( oO0OOo0O0 ) ) : return ( None )
 return ( oO0OOo0O0 [ OOOooo0OooOoO ] )
 if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
 if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
 if 59 - 59: i11iIiiIii / I1IiiI * iII111i
 if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
 if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
 if 89 - 89: O0 * ooOoO0o
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 i1i1 = "none" if nh == None else nh
 if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , i1i1 ) )
 if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
 if ( nh == None ) :
  o0o0O0oo0 = "ip route {} {}/32" . format ( install , dest )
 else :
  o0o0O0oo0 = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 82 - 82: iII111i * iII111i . IiII * II111iiii
 os . system ( o0o0O0oo0 )
 return
 if 17 - 17: OoooooooOO % I1Ii111 * I1Ii111 / II111iiii . OoOoOO00 * iII111i
 if 80 - 80: IiII % i11iIiiIii
 if 6 - 6: II111iiii + i11iIiiIii - Oo0Ooo % OOooOOo + Oo0Ooo
 if 46 - 46: iII111i
 if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
 if 11 - 11: ooOoO0o - OoOoOO00
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 4 - 4: OoO0O00 - OOooOOo
 I1Ii = open ( lisp_checkpoint_filename , "w" )
 for oO00Oo in checkpoint_list :
  I1Ii . write ( oO00Oo + "\n" )
  if 21 - 21: I1Ii111 * i11iIiiIii
 I1Ii . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 63 - 63: oO0o + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
 if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
 if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
 if 20 - 20: Ii1I * iII111i / ooOoO0o
 if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
 if 23 - 23: I1IiiI - I1ii11iIi11i . O0 . OoOoOO00 . OoO0O00
 if 81 - 81: IiII * I11i - iIii1I11I1II1
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 41 - 41: oO0o * I11i + I1IiiI - OoO0O00
 I1Ii = open ( lisp_checkpoint_filename , "r" )
 if 63 - 63: Oo0Ooo * Ii1I - Ii1I
 Ooo0oOOoo0O = 0
 for oO00Oo in I1Ii :
  Ooo0oOOoo0O += 1
  I1i = oO00Oo . split ( " rloc " )
  o0o = [ ] if ( I1i [ 1 ] in [ "native-forward\n" , "\n" ] ) else I1i [ 1 ] . split ( ", " )
  if 76 - 76: OoO0O00 . IiII % iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1IiiI
  if 57 - 57: IiII - i1IIi * ooOoO0o
  IIiii11iiI111 = [ ]
  for IIIi1iI1 in o0o :
   O0O0OOo0O = lisp_rloc ( False )
   OOoooo = IIIi1iI1 . split ( " " )
   O0O0OOo0O . rloc . store_address ( OOoooo [ 0 ] )
   O0O0OOo0O . priority = int ( OOoooo [ 1 ] )
   O0O0OOo0O . weight = int ( OOoooo [ 2 ] )
   IIiii11iiI111 . append ( O0O0OOo0O )
   if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
   if 75 - 75: OOooOOo * OoOoOO00
  I111I1iI1 = lisp_mapping ( "" , "" , IIiii11iiI111 )
  if ( I111I1iI1 != None ) :
   I111I1iI1 . eid . store_prefix ( I1i [ 0 ] )
   I111I1iI1 . checkpoint_entry = True
   I111I1iI1 . map_cache_ttl = LISP_NMR_TTL * 60
   if ( IIiii11iiI111 == [ ] ) : I111I1iI1 . action = LISP_NATIVE_FORWARD_ACTION
   I111I1iI1 . add_cache ( )
   continue
   if 82 - 82: Ii1I
   if 83 - 83: I1IiiI
  Ooo0oOOoo0O -= 1
  if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
  if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
 I1Ii . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , Ooo0oOOoo0O , lisp_checkpoint_filename ) )
 return
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
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 oO00Oo = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 9 - 9: i1IIi % iII111i / Ii1I
 for O0O0OOo0O in mc . rloc_set :
  if ( O0O0OOo0O . rloc . is_null ( ) ) : continue
  oO00Oo += "{} {} {}, " . format ( O0O0OOo0O . rloc . print_address_no_iid ( ) ,
 O0O0OOo0O . priority , O0O0OOo0O . weight )
  if 83 - 83: oO0o
  if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if ( mc . rloc_set != [ ] ) :
  oO00Oo = oO00Oo [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  oO00Oo += "native-forward"
  if 29 - 29: OoooooooOO
  if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
 checkpoint_list . append ( oO00Oo )
 return
 if 83 - 83: iIii1I11I1II1
 if 92 - 92: OoO0O00 - iII111i
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 if 74 - 74: i1IIi % i11iIiiIii + oO0o
def lisp_check_dp_socket ( ) :
 OOoOOoo0oOooO = lisp_ipc_dp_socket_name
 if ( os . path . exists ( OOoOOoo0oOooO ) == False ) :
  I1o0oOOoo0OO0 = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( OOoOOoo0oOooO , I1o0oOOoo0OO0 ) )
  return ( False )
  if 52 - 52: iII111i - II111iiii % i1IIi / iII111i
 return ( True )
 if 14 - 14: oO0o / I1Ii111 / IiII - i1IIi * Ii1I
 if 90 - 90: ooOoO0o
 if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
 if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
 if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
 if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
 if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
def lisp_write_to_dp_socket ( entry ) :
 try :
  oOO0oOoOO = json . dumps ( entry )
  o0000O0ooO = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( o0000O0ooO , oOO0oOoOO ) )
  lisp_ipc_dp_socket . sendto ( oOO0oOoOO , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( oOO0oOoOO ) )
  if 35 - 35: II111iiii
 return
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if 96 - 96: O0
 if 15 - 15: i1IIi . iIii1I11I1II1
 if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
 if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
 if 61 - 61: I1Ii111 + I11i + I1IiiI
 if 48 - 48: I11i
 if 67 - 67: o0oOOo0O0Ooo
 if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
def lisp_write_ipc_keys ( rloc ) :
 Oo0o = rloc . rloc . print_address_no_iid ( )
 IiO0o = rloc . translated_port
 if ( IiO0o != 0 ) : Oo0o += ":" + str ( IiO0o )
 if ( Oo0o not in lisp_rloc_probe_list ) : return
 if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
 for OOoooo , I1i , o0O0Ooo in lisp_rloc_probe_list [ Oo0o ] :
  I111I1iI1 = lisp_map_cache . lookup_cache ( I1i , True )
  if ( I111I1iI1 == None ) : continue
  lisp_write_ipc_map_cache ( True , I111I1iI1 )
  if 89 - 89: ooOoO0o % i11iIiiIii
 return
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 if 75 - 75: Ii1I
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
 o0ooOOoO0oO0 = "add" if add_or_delete else "delete"
 oO00Oo = { "type" : "map-cache" , "opcode" : o0ooOOoO0oO0 }
 if 82 - 82: II111iiii
 o0OooO = ( mc . group . is_null ( ) == False )
 if ( o0OooO ) :
  oO00Oo [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  oO00Oo [ "rles" ] = [ ]
 else :
  oO00Oo [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  oO00Oo [ "rlocs" ] = [ ]
  if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 oO00Oo [ "instance-id" ] = str ( mc . eid . instance_id )
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if ( o0OooO ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for oO0oOOOO0oO0o0 in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    oOOOo0o = oO0oOOOO0oO0o0 . address . print_address_no_iid ( )
    IiO0o = str ( 4341 ) if oO0oOOOO0oO0o0 . translated_port == 0 else str ( oO0oOOOO0oO0o0 . translated_port )
    if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
    OOoooo = { "rle" : oOOOo0o , "port" : IiO0o }
    OoooooOoOOO , oOo00OO0oooI111 = oO0oOOOO0oO0o0 . get_encap_keys ( )
    OOoooo = lisp_build_json_keys ( OOoooo , OoooooOoOOO , oOo00OO0oooI111 , "encrypt-key" )
    oO00Oo [ "rles" ] . append ( OOoooo )
    if 52 - 52: I11i + iII111i
    if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
 else :
  for IIIi1iI1 in mc . rloc_set :
   if ( IIIi1iI1 . rloc . is_ipv4 ( ) == False and IIIi1iI1 . rloc . is_ipv6 ( ) == False ) :
    continue
    if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
   if ( IIIi1iI1 . up_state ( ) == False ) : continue
   if 62 - 62: IiII . O0
   IiO0o = str ( 4341 ) if IIIi1iI1 . translated_port == 0 else str ( IIIi1iI1 . translated_port )
   if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
   OOoooo = { "rloc" : IIIi1iI1 . rloc . print_address_no_iid ( ) , "priority" :
 str ( IIIi1iI1 . priority ) , "weight" : str ( IIIi1iI1 . weight ) , "port" :
 IiO0o }
   OoooooOoOOO , oOo00OO0oooI111 = IIIi1iI1 . get_encap_keys ( )
   OOoooo = lisp_build_json_keys ( OOoooo , OoooooOoOOO , oOo00OO0oooI111 , "encrypt-key" )
   oO00Oo [ "rlocs" ] . append ( OOoooo )
   if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
   if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
   if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
 if ( dont_send == False ) : lisp_write_to_dp_socket ( oO00Oo )
 return ( oO00Oo )
 if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
 if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
 if 24 - 24: OoOoOO00
 if 87 - 87: I1ii11iIi11i / ooOoO0o * i1IIi
 if 71 - 71: OoOoOO00 - I11i
 if 83 - 83: oO0o + oO0o - Oo0Ooo . Oo0Ooo - iII111i . OOooOOo
 if 56 - 56: OoOoOO00 * IiII + i1IIi
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 40 - 40: I1ii11iIi11i / O0
 if 87 - 87: ooOoO0o
 if 100 - 100: iII111i + II111iiii * Oo0Ooo * OOooOOo
 if 6 - 6: IiII % OOooOOo
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
 OoooooOoOOO = keys [ 1 ] . encrypt_key
 oOo00OO0oooI111 = keys [ 1 ] . icv_key
 if 41 - 41: oO0o
 if 12 - 12: I1IiiI + I1Ii111
 if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
 o00o00 = rloc_addr . split ( ":" )
 if ( len ( o00o00 ) == 1 ) :
  oO00Oo = { "type" : "decap-keys" , "rloc" : o00o00 [ 0 ] }
 else :
  oO00Oo = { "type" : "decap-keys" , "rloc" : o00o00 [ 0 ] , "port" : o00o00 [ 1 ] }
  if 52 - 52: iII111i % iIii1I11I1II1 - Oo0Ooo - iIii1I11I1II1 * I1ii11iIi11i - OoO0O00
 oO00Oo = lisp_build_json_keys ( oO00Oo , OoooooOoOOO , oOo00OO0oooI111 , "decrypt-key" )
 if 26 - 26: i11iIiiIii % I11i % o0oOOo0O0Ooo % OoOoOO00 / iII111i - OOooOOo
 lisp_write_to_dp_socket ( oO00Oo )
 return
 if 17 - 17: i1IIi - Ii1I . ooOoO0o % I1Ii111 . OoooooooOO / oO0o
 if 91 - 91: ooOoO0o % I1ii11iIi11i
 if 60 - 60: O0 * Oo0Ooo * IiII % OoOoOO00 . OoOoOO00
 if 4 - 4: I1Ii111 % I1Ii111 * O0
 if 54 - 54: I1ii11iIi11i - IiII . OoO0O00 + I1ii11iIi11i / I1IiiI
 if 91 - 91: OOooOOo % Oo0Ooo
 if 44 - 44: iIii1I11I1II1 . OOooOOo
 if 57 - 57: II111iiii + I1Ii111
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 42 - 42: OoOoOO00 % O0
 entry [ "keys" ] = [ ]
 IIIOoo = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( IIIOoo )
 return ( entry )
 if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
 if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
 if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
 if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
 if 26 - 26: Ii1I * I11i / I11i
 if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
 oO00Oo = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 16 - 16: I11i
 if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
 if 61 - 61: O0 % iII111i
 if 41 - 41: I1Ii111 * OoooooooOO
 for iIiI1ii in lisp_db_list :
  if ( iIiI1ii . eid . is_ipv4 ( ) == False and iIiI1ii . eid . is_ipv6 ( ) == False ) : continue
  OoooooOO0O0oo = { "instance-id" : str ( iIiI1ii . eid . instance_id ) ,
 "eid-prefix" : iIiI1ii . eid . print_prefix_no_iid ( ) }
  oO00Oo [ "database-mappings" ] . append ( OoooooOO0O0oo )
  if 14 - 14: OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
 lisp_write_to_dp_socket ( oO00Oo )
 if 19 - 19: iIii1I11I1II1
 if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
 if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
 oO00Oo = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( oO00Oo )
 return
 if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
 if 57 - 57: i1IIi
 if 41 - 41: I11i / Ii1I
 if 1 - 1: II111iiii / iII111i
 if 83 - 83: OoO0O00 / iII111i
 if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
 if 96 - 96: OoO0O00
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 53 - 53: oO0o + OoO0O00
 if 58 - 58: iIii1I11I1II1 + OoOoOO00
 if 65 - 65: iII111i % Oo0Ooo * iIii1I11I1II1 + I1IiiI + II111iiii
 if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
 oO00Oo = { "type" : "interfaces" , "interfaces" : [ ] }
 if 15 - 15: OoOoOO00
 for OooOO in list ( lisp_myinterfaces . values ( ) ) :
  if ( OooOO . instance_id == None ) : continue
  OoooooOO0O0oo = { "interface" : OooOO . device ,
 "instance-id" : str ( OooOO . instance_id ) }
  oO00Oo [ "interfaces" ] . append ( OoooooOO0O0oo )
  if 13 - 13: I1ii11iIi11i - OOooOOo - i11iIiiIii / IiII
  if 65 - 65: IiII
 lisp_write_to_dp_socket ( oO00Oo )
 return
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
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
def lisp_parse_auth_key ( value ) :
 ooo00ooOOO0 = value . split ( "[" )
 O0O000oOO00o = { }
 if ( len ( ooo00ooOOO0 ) == 1 ) :
  O0O000oOO00o [ 0 ] = value
  return ( O0O000oOO00o )
  if 82 - 82: I1ii11iIi11i * I1Ii111 . O0
  if 19 - 19: iII111i
 for O0Ii1i1iiIi in ooo00ooOOO0 :
  if ( O0Ii1i1iiIi == "" ) : continue
  OOOooo0OooOoO = O0Ii1i1iiIi . find ( "]" )
  IiII11iI1 = O0Ii1i1iiIi [ 0 : OOOooo0OooOoO ]
  try : IiII11iI1 = int ( IiII11iI1 )
  except : return
  if 4 - 4: iII111i
  O0O000oOO00o [ IiII11iI1 ] = O0Ii1i1iiIi [ OOOooo0OooOoO + 1 : : ]
  if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
 return ( O0O000oOO00o )
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
def lisp_reassemble ( packet ) :
 OoooOO0 = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
 if 8 - 8: IiII * iIii1I11I1II1
 if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
 if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
 if ( OoooOO0 == 0 or OoooOO0 == 0x4000 ) : return ( packet )
 if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
 if 84 - 84: OoooooooOO
 if 95 - 95: o0oOOo0O0Ooo
 if 22 - 22: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
 OOoo0 = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 OOO0OOO = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 41 - 41: oO0o . II111iiii
 iiiIiIii = ( OoooOO0 & 0x2000 == 0 and ( OoooOO0 & 0x1fff ) != 0 )
 oO00Oo = [ ( OoooOO0 & 0x1fff ) * 8 , OOO0OOO - 20 , packet , iiiIiIii ]
 if 41 - 41: i1IIi % ooOoO0o * Oo0Ooo . OoO0O00 . OoOoOO00
 if 35 - 35: II111iiii * Oo0Ooo / iIii1I11I1II1 + O0 + II111iiii / I1IiiI
 if 49 - 49: i11iIiiIii % I1ii11iIi11i * O0 . o0oOOo0O0Ooo . I1ii11iIi11i / o0oOOo0O0Ooo
 if 99 - 99: I1ii11iIi11i * O0 / OoO0O00 % i1IIi + ooOoO0o
 if 85 - 85: OOooOOo / O0 - iIii1I11I1II1 . I11i . ooOoO0o - I1IiiI
 if 97 - 97: iIii1I11I1II1 * Oo0Ooo
 if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
 if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
 if ( OoooOO0 == 0x2000 ) :
  IiiIiiIIII , oOo = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  IiiIiiIIII = socket . ntohs ( IiiIiiIIII )
  oOo = socket . ntohs ( oOo )
  if ( oOo not in [ 4341 , 8472 , 4789 ] and IiiIiiIIII != 4341 ) :
   lisp_reassembly_queue [ OOoo0 ] = [ ]
   oO00Oo [ 2 ] = None
   if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
   if 47 - 47: OOooOOo * oO0o
   if 41 - 41: OoooooooOO * I1IiiI
   if 3 - 3: IiII
   if 96 - 96: I11i - OOooOOo + I11i
   if 71 - 71: Oo0Ooo
 if ( OOoo0 not in lisp_reassembly_queue ) :
  lisp_reassembly_queue [ OOoo0 ] = [ ]
  if 48 - 48: o0oOOo0O0Ooo / II111iiii / OoOoOO00 * o0oOOo0O0Ooo + I1IiiI . OoOoOO00
  if 52 - 52: Ii1I / OoOoOO00 . OOooOOo * IiII . OoooooooOO
  if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
  if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
  if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
 queue = lisp_reassembly_queue [ OOoo0 ]
 if 75 - 75: IiII
 if 74 - 74: o0oOOo0O0Ooo - iIii1I11I1II1
 if 92 - 92: i11iIiiIii * iIii1I11I1II1 - I1Ii111 . i1IIi
 if 23 - 23: O0 - O0 . I1Ii111 . I1IiiI - I1IiiI * i1IIi
 if 8 - 8: I1IiiI . I1ii11iIi11i + oO0o % oO0o * oO0o
 if ( len ( queue ) == 1 and queue [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( OOoo0 ) . zfill ( 4 ) ) )
  if 70 - 70: II111iiii + IiII + O0 / Ii1I - i11iIiiIii
  return ( None )
  if 72 - 72: II111iiii - II111iiii
  if 44 - 44: o0oOOo0O0Ooo + OoooooooOO
  if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
  if 87 - 87: OOooOOo * OoO0O00
  if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 queue . append ( oO00Oo )
 queue = sorted ( queue )
 if 86 - 86: II111iiii
 if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
 if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
 if 91 - 91: Ii1I
 oOOOo0o = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oOOOo0o . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 iII1iIi = oOOOo0o . print_address_no_iid ( )
 oOOOo0o . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 i1I1I = oOOOo0o . print_address_no_iid ( )
 oOOOo0o = red ( "{} -> {}" . format ( iII1iIi , i1I1I ) , False )
 if 17 - 17: OoOoOO00 - OoooooooOO
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if oO00Oo [ 2 ] == None else "" , oOOOo0o , lisp_hex_string ( OOoo0 ) . zfill ( 4 ) ,
 # o0oOOo0O0Ooo * o0oOOo0O0Ooo * I1ii11iIi11i % IiII
 # Oo0Ooo * I11i
 lisp_hex_string ( OoooOO0 ) . zfill ( 4 ) ) )
 if 87 - 87: OoooooooOO / oO0o * ooOoO0o
 if 72 - 72: oO0o + OoooooooOO - ooOoO0o . OoOoOO00
 if 67 - 67: O0 - o0oOOo0O0Ooo - OOooOOo
 if 17 - 17: i1IIi - ooOoO0o + O0 + I1IiiI / I11i / OoO0O00
 if 94 - 94: i1IIi - oO0o - O0 . I1Ii111
 if ( queue [ 0 ] [ 0 ] != 0 or queue [ - 1 ] [ 3 ] == False ) : return ( None )
 OoOi1IiIiiIIiii = queue [ 0 ]
 for Ii in queue [ 1 : : ] :
  OoooOO0 = Ii [ 0 ]
  Ooo0Oooo , IIIiiIii1Ii11 = OoOi1IiIiiIIiii [ 0 ] , OoOi1IiIiiIIiii [ 1 ]
  if ( Ooo0Oooo + IIIiiIii1Ii11 != OoooOO0 ) : return ( None )
  OoOi1IiIiiIIiii = Ii
  if 71 - 71: IiII % oO0o - i11iIiiIii % o0oOOo0O0Ooo * I1ii11iIi11i
 lisp_reassembly_queue . pop ( OOoo0 )
 if 61 - 61: ooOoO0o + I1Ii111 . iIii1I11I1II1 % iII111i
 if 44 - 44: ooOoO0o + o0oOOo0O0Ooo % OoOoOO00 + I1IiiI
 if 96 - 96: O0 % Ii1I / I1ii11iIi11i + I1ii11iIi11i - OoO0O00 / oO0o
 if 41 - 41: Ii1I
 if 78 - 78: OOooOOo
 packet = queue [ 0 ] [ 2 ]
 for Ii in queue [ 1 : : ] : packet += Ii [ 2 ] [ 20 : : ]
 if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( OOoo0 ) . zfill ( 4 ) , len ( packet ) ) )
 if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
 if 81 - 81: IiII
 if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
 if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
 if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
 i1iIii = socket . htons ( len ( packet ) )
 o0O0OOooO = packet [ 0 : 2 ] + struct . pack ( "H" , i1iIii ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
 o0O0OOooO = lisp_ip_checksum ( o0O0OOooO )
 return ( o0O0OOooO + packet [ 20 : : ] )
 if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
 if 79 - 79: IiII + I1Ii111
 if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
 if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
 if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if 44 - 44: Oo0Ooo / oO0o
 if 9 - 9: i1IIi % I1IiiI + OoO0O00 * ooOoO0o / iIii1I11I1II1 / iII111i
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 Oo0o = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( Oo0o in lisp_crypto_keys_by_rloc_decap ) : return ( Oo0o )
 if 80 - 80: OOooOOo / O0 % IiII * OoOoOO00
 Oo0o = addr . print_address_no_iid ( )
 if ( Oo0o in lisp_crypto_keys_by_rloc_decap ) : return ( Oo0o )
 if 53 - 53: OOooOOo + i11iIiiIii
 if 25 - 25: i11iIiiIii
 if 51 - 51: iII111i . ooOoO0o
 if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
 if 6 - 6: I11i + II111iiii - I1Ii111
 for IiI1o0o0oOo in lisp_crypto_keys_by_rloc_decap :
  OoOOOO = IiI1o0o0oOo . split ( ":" )
  if ( len ( OoOOOO ) == 1 ) : continue
  OoOOOO = OoOOOO [ 0 ] if len ( OoOOOO ) == 2 else ":" . join ( OoOOOO [ 0 : - 1 ] )
  if ( OoOOOO == Oo0o ) :
   Oo0Oo = lisp_crypto_keys_by_rloc_decap [ IiI1o0o0oOo ]
   lisp_crypto_keys_by_rloc_decap [ Oo0o ] = Oo0Oo
   return ( Oo0o )
   if 39 - 39: Ii1I * iIii1I11I1II1 * Oo0Ooo / i1IIi % o0oOOo0O0Ooo
   if 24 - 24: OoO0O00 + iIii1I11I1II1
 return ( None )
 if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
 if 64 - 64: O0 / OoooooooOO
 if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
 if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
 if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
 if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
 if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
 if 77 - 77: OoO0O00
 if 95 - 95: II111iiii
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 Ooo00O000o = addr + ":" + str ( port )
 if 7 - 7: ooOoO0o * I1Ii111 + I1IiiI
 if ( lisp_i_am_rtr ) :
  if ( addr in lisp_rloc_probe_list ) : return ( addr )
  if 88 - 88: O0 - O0 / Ii1I - OOooOOo % I11i
  if 13 - 13: IiII % OoooooooOO * IiII - OoO0O00 % OoooooooOO * IiII
  if 91 - 91: ooOoO0o * ooOoO0o % I1Ii111 . I1ii11iIi11i + iII111i / oO0o
  if 60 - 60: Ii1I
  if 27 - 27: I1ii11iIi11i - I11i . OoO0O00 / o0oOOo0O0Ooo
  if 87 - 87: iIii1I11I1II1 - OOooOOo - OOooOOo
  for o0O00Oo in list ( lisp_nat_state_info . values ( ) ) :
   for IiII11I1I1II in o0O00Oo :
    if ( addr == IiII11I1I1II . address ) : return ( Ooo00O000o )
    if 55 - 55: Oo0Ooo + OoooooooOO . IiII / O0 + I11i
    if 58 - 58: Ii1I
  return ( addr )
  if 35 - 35: OoO0O00 + OoOoOO00
 return ( Ooo00O000o )
 if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
 if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
 if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
 if 37 - 37: O0 + IiII + I1IiiI
 if 50 - 50: OoooooooOO . I1Ii111
 if 100 - 100: ooOoO0o * ooOoO0o - Ii1I
 if 13 - 13: iII111i . I11i * OoO0O00 . i1IIi . iIii1I11I1II1 - o0oOOo0O0Ooo
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_MULTICAST_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
 return
 if 79 - 79: II111iiii / IiII
 if 4 - 4: O0 - i11iIiiIii % ooOoO0o * O0 - ooOoO0o
 if 96 - 96: oO0o % II111iiii . Ii1I % OoO0O00 . iIii1I11I1II1 / IiII
 if 96 - 96: o0oOOo0O0Ooo / O0 . iIii1I11I1II1 . Ii1I % OOooOOo % II111iiii
 if 5 - 5: OoooooooOO / I1Ii111 % I1Ii111 / I1IiiI
 if 19 - 19: I1IiiI - ooOoO0o % IiII - o0oOOo0O0Ooo * OOooOOo + I1ii11iIi11i
 if 44 - 44: i1IIi
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 85 - 85: I1ii11iIi11i / IiII + oO0o
 if 95 - 95: IiII . OoO0O00
 if 36 - 36: IiII % Ii1I - OoOoOO00 + OoO0O00 + IiII * Ii1I
 if 15 - 15: I1IiiI / O0 % I1ii11iIi11i % OoOoOO00 . OoOoOO00 + iII111i
 if 79 - 79: OOooOOo + Ii1I . I1Ii111 / Oo0Ooo / i11iIiiIii / O0
 if 28 - 28: i1IIi % OoO0O00 / i1IIi - o0oOOo0O0Ooo
 if 97 - 97: II111iiii + O0 . Ii1I + OoooooooOO
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 39 - 39: i11iIiiIii + OoO0O00 + I11i * oO0o + iIii1I11I1II1 % o0oOOo0O0Ooo
 if 25 - 25: OoooooooOO
 if 78 - 78: oO0o / i11iIiiIii * O0 / OOooOOo % i11iIiiIii % O0
 if 86 - 86: IiII
 if 26 - 26: IiII - I1Ii111 + i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo
 if 39 - 39: Ii1I - i1IIi + i11iIiiIii
 if 21 - 21: IiII
 if 76 - 76: o0oOOo0O0Ooo % Oo0Ooo + OoO0O00
 if 36 - 36: OOooOOo . oO0o
 if 15 - 15: I1IiiI + ooOoO0o - o0oOOo0O0Ooo
 if 62 - 62: Ii1I - OOooOOo
 if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
 if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
 if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
 if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
 if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
 if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
 if 2 - 2: I1ii11iIi11i
 if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
def lisp_is_rloc_probe ( packet , rr ) :
 Ii1iiI1 = ( struct . unpack ( "B" , packet [ 9 ] ) [ 0 ] == 17 )
 if ( Ii1iiI1 == False ) : return ( [ packet , None , None , None ] )
 if 54 - 54: ooOoO0o
 IiiIiiIIII = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 oOo = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 i1iII11i11IIi = ( socket . htons ( LISP_CTRL_PORT ) in [ IiiIiiIIII , oOo ] )
 if ( i1iII11i11IIi == False ) : return ( [ packet , None , None , None ] )
 if 63 - 63: I1Ii111 + i11iIiiIii % i1IIi . Oo0Ooo + oO0o * oO0o
 if ( rr == 0 ) :
  iII11 = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( iII11 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  iII11 = lisp_is_rloc_probe_reply ( packet [ 28 ] )
  if ( iII11 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  iII11 = lisp_is_rloc_probe_request ( packet [ 28 ] )
  if ( iII11 == False ) :
   iII11 = lisp_is_rloc_probe_reply ( packet [ 28 ] )
   if ( iII11 == False ) : return ( [ packet , None , None , None ] )
   if 97 - 97: i1IIi % oO0o / iIii1I11I1II1 % OOooOOo + iIii1I11I1II1
   if 68 - 68: OoooooooOO . iII111i . Oo0Ooo + iIii1I11I1II1 - II111iiii % i1IIi
   if 48 - 48: O0
   if 60 - 60: ooOoO0o - IiII % i1IIi
   if 5 - 5: oO0o
   if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
 II11IIII1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 II11IIII1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
 if 58 - 58: oO0o . OoO0O00 / ooOoO0o
 if 61 - 61: I11i + I1Ii111
 if 27 - 27: ooOoO0o / i1IIi . oO0o - OoooooooOO
 if ( II11IIII1 . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 48 - 48: ooOoO0o % ooOoO0o / OoooooooOO + i1IIi * oO0o + ooOoO0o
 if 69 - 69: iII111i . iII111i
 if 46 - 46: IiII * Oo0Ooo + I1Ii111
 if 79 - 79: IiII
 II11IIII1 = II11IIII1 . print_address_no_iid ( )
 IiO0o = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 IiIIi = struct . unpack ( "B" , packet [ 8 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 89 - 89: IiII * I11i + I1ii11iIi11i * oO0o - II111iiii
 OOoooo = bold ( "Receive(pcap)" , False )
 I1Ii = bold ( "from " + II11IIII1 , False )
 IiIiIII11i1i = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( OOoooo , len ( packet ) , I1Ii , IiO0o , IiIiIII11i1i ) )
 if 58 - 58: ooOoO0o . I1Ii111 / i1IIi % I1ii11iIi11i + o0oOOo0O0Ooo
 return ( [ packet , II11IIII1 , IiO0o , IiIIi ] )
 if 94 - 94: i11iIiiIii + I1Ii111 . iII111i - ooOoO0o % I1Ii111
 if 94 - 94: i11iIiiIii - OOooOOo - O0 * OoooooooOO - ooOoO0o
 if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
 if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
 if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
 if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
 if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
 if 79 - 79: I11i . I11i - OoOoOO00
 if 86 - 86: OoO0O00 * Oo0Ooo . iIii1I11I1II1 * O0
 if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
 Iii1 = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
 lisp_write_to_dp_socket ( Iii1 )
 return
 if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
 if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
 if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
 if 93 - 93: oO0o
 if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
 if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
 if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
def lisp_external_data_plane ( ) :
 i1i1I11I = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( getoutput ( i1i1I11I ) != "" ) : return ( True )
 if 54 - 54: OoOoOO00 - I1IiiI - iII111i
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 49 - 49: i11iIiiIii * Oo0Ooo
 if 100 - 100: Oo0Ooo * oO0o
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
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
 OoO00Oo0O0 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 72 - 72: o0oOOo0O0Ooo / II111iiii * I11i % iIii1I11I1II1 - I1ii11iIi11i * I1Ii111
 if ( do_clear == False ) :
  ooOoOOoO0OOo = OoO00Oo0O0 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , ooOoOOoO0OOo )
  if 64 - 64: O0 * iII111i
  if 68 - 68: II111iiii
 lisp_write_to_dp_socket ( OoO00Oo0O0 )
 return
 if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
 if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
 if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
 if 65 - 65: ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . I1IiiI % O0
 if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
 if 1 - 1: I1ii11iIi11i % O0 - I1ii11iIi11i / OoooooooOO / OoO0O00
 if 82 - 82: i1IIi % Ii1I
 if 85 - 85: I1Ii111 * i11iIiiIii * iIii1I11I1II1 % iIii1I11I1II1
 if 64 - 64: OoO0O00 / Ii1I
 if 79 - 79: Ii1I % OOooOOo
 if 39 - 39: I1ii11iIi11i / Ii1I - II111iiii . i1IIi
 if 59 - 59: II111iiii
 if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
 if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( "entries" not in msg ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
  if 61 - 61: i1IIi
 for msg in msg [ "entries" ] :
  if ( "eid-prefix" not in msg ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 56 - 56: iIii1I11I1II1 / I11i * iII111i * I11i * OoooooooOO
  iIiI1I1ii1I1 = msg [ "eid-prefix" ]
  if 44 - 44: I1ii11iIi11i - OOooOOo % I11i - I1Ii111 / iIii1I11I1II1 - OOooOOo
  if ( "instance-id" not in msg ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 38 - 38: iIii1I11I1II1 - OoooooooOO * II111iiii . OoooooooOO + OOooOOo
  i1oO00O = int ( msg [ "instance-id" ] )
  if 59 - 59: OoooooooOO
  if 22 - 22: II111iiii
  if 85 - 85: I1Ii111 + I1ii11iIi11i * I11i % o0oOOo0O0Ooo + Ii1I
  if 23 - 23: IiII * OoO0O00
  oo0oO = lisp_address ( LISP_AFI_NONE , "" , 0 , i1oO00O )
  oo0oO . store_prefix ( iIiI1I1ii1I1 )
  I111I1iI1 = lisp_map_cache_lookup ( None , oo0oO )
  if ( I111I1iI1 == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( iIiI1I1ii1I1 ) )
   if 42 - 42: IiII
   continue
   if 83 - 83: i1IIi * o0oOOo0O0Ooo / OoO0O00 / o0oOOo0O0Ooo
   if 55 - 55: Oo0Ooo % O0 - OoO0O00
  if ( "rlocs" not in msg ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( iIiI1I1ii1I1 ) )
   if 42 - 42: OoooooooOO * OOooOOo
   continue
   if 93 - 93: OOooOOo + II111iiii . oO0o * Oo0Ooo - O0 + I1Ii111
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 99 - 99: OoO0O00 * o0oOOo0O0Ooo + OoOoOO00 * iIii1I11I1II1
  II1IIiI1 = msg [ "rlocs" ]
  if 55 - 55: OoO0O00
  if 11 - 11: OoooooooOO - I1IiiI . I1IiiI % o0oOOo0O0Ooo
  if 56 - 56: I1Ii111
  if 23 - 23: ooOoO0o . I11i - OOooOOo
  for iI1IiII in II1IIiI1 :
   if ( "rloc" not in iI1IiII ) : continue
   if 48 - 48: iIii1I11I1II1 / i11iIiiIii * OoOoOO00 * Oo0Ooo . IiII
   iiIIii = iI1IiII [ "rloc" ]
   if ( iiIIii == "no-address" ) : continue
   if 87 - 87: II111iiii * I1IiiI % IiII
   IIIi1iI1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   IIIi1iI1 . store_address ( iiIIii )
   if 95 - 95: OoooooooOO / OoO0O00 % O0 / I1Ii111 * Ii1I + I1ii11iIi11i
   O0O0OOo0O = I111I1iI1 . get_rloc ( IIIi1iI1 )
   if ( O0O0OOo0O == None ) : continue
   if 7 - 7: ooOoO0o
   if 83 - 83: oO0o / I1Ii111 + I1Ii111 * I1ii11iIi11i
   if 8 - 8: I11i . I1ii11iIi11i % i1IIi + Ii1I
   if 63 - 63: I1IiiI / OoooooooOO
   iIiii1I = 0 if ( "packet-count" not in iI1IiII ) else iI1IiII [ "packet-count" ]
   if 85 - 85: ooOoO0o + I1Ii111 - O0 * I11i / i1IIi
   iI1Iii1 = 0 if ( "byte-count" not in iI1IiII ) else iI1IiII [ "byte-count" ]
   if 66 - 66: ooOoO0o % I1Ii111 - O0 + I1Ii111 - i1IIi % OoOoOO00
   i1 = 0 if ( "seconds-last-packet" not in iI1IiII ) else iI1IiII [ "seconds-last-packet" ]
   if 13 - 13: O0 + iIii1I11I1II1 % I1IiiI * O0 + ooOoO0o
   if 60 - 60: iIii1I11I1II1 + OoooooooOO - OoO0O00
   O0O0OOo0O . stats . packet_count += iIiii1I
   O0O0OOo0O . stats . byte_count += iI1Iii1
   O0O0OOo0O . stats . last_increment = lisp_get_timestamp ( ) - i1
   if 44 - 44: O0 . OOooOOo . o0oOOo0O0Ooo . I1ii11iIi11i - II111iiii
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( iIiii1I , iI1Iii1 ,
 i1 , iIiI1I1ii1I1 , iiIIii ) )
   if 71 - 71: I1ii11iIi11i + o0oOOo0O0Ooo . i11iIiiIii * oO0o . i1IIi
   if 40 - 40: OoO0O00 - IiII
   if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
   if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
   if 38 - 38: iII111i - I1IiiI / ooOoO0o
  if ( I111I1iI1 . group . is_null ( ) and I111I1iI1 . has_ttl_elapsed ( ) ) :
   iIiI1I1ii1I1 = green ( I111I1iI1 . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( iIiI1I1ii1I1 ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , I111I1iI1 . eid , None )
   if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
   if 19 - 19: I11i / Oo0Ooo + I1Ii111
 return
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
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 97 - 97: i11iIiiIii % iIii1I11I1II1 + II111iiii
 if 90 - 90: OOooOOo / I1IiiI
 if 28 - 28: OoooooooOO + i1IIi
 if 29 - 29: Oo0Ooo
 if 98 - 98: OOooOOo / Oo0Ooo % Ii1I * OoooooooOO - oO0o
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  Iii1 = "stats%{}" . format ( json . dumps ( msg ) )
  Iii1 = lisp_command_ipc ( Iii1 , "lisp-itr" )
  lisp_ipc ( Iii1 , lisp_ipc_socket , "lisp-etr" )
  return
  if 64 - 64: I1IiiI - I1IiiI
  if 90 - 90: iII111i - I1IiiI - II111iiii / OOooOOo + Ii1I
  if 34 - 34: i11iIiiIii + I1Ii111 / O0 / iIii1I11I1II1 * OoooooooOO % Ii1I
  if 32 - 32: i11iIiiIii - OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI + O0
  if 36 - 36: I1ii11iIi11i + I1ii11iIi11i % I1Ii111 * ooOoO0o * OoOoOO00
  if 54 - 54: Oo0Ooo - I1IiiI % OOooOOo . I1ii11iIi11i / I1IiiI
  if 75 - 75: OOooOOo - O0 % iII111i . Ii1I % I1ii11iIi11i + I1ii11iIi11i
  if 32 - 32: Ii1I + II111iiii * IiII
 Iii1 = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( Iii1 , msg ) )
 if 9 - 9: I1Ii111
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 96 - 96: I1Ii111 / iIii1I11I1II1
 i1I1iIiii1ii = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 62 - 62: ooOoO0o - OoO0O00
 for OoOOO0O in i1I1iIiii1ii :
  iIiii1I = 0 if ( OoOOO0O not in msg ) else msg [ OoOOO0O ] [ "packet-count" ]
  lisp_decap_stats [ OoOOO0O ] . packet_count += iIiii1I
  if 13 - 13: iIii1I11I1II1 - iIii1I11I1II1 + I1IiiI - IiII * iIii1I11I1II1
  iI1Iii1 = 0 if ( OoOOO0O not in msg ) else msg [ OoOOO0O ] [ "byte-count" ]
  lisp_decap_stats [ OoOOO0O ] . byte_count += iI1Iii1
  if 86 - 86: Oo0Ooo
  i1 = 0 if ( OoOOO0O not in msg ) else msg [ OoOOO0O ] [ "seconds-last-packet" ]
  if 66 - 66: OoooooooOO % OoO0O00 + i11iIiiIii + I1Ii111 % OoO0O00
  lisp_decap_stats [ OoOOO0O ] . last_increment = lisp_get_timestamp ( ) - i1
  if 80 - 80: Oo0Ooo - Ii1I
 return
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
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 IiI , II11IIII1 = punt_socket . recvfrom ( 4000 )
 if 66 - 66: i11iIiiIii % Ii1I / iII111i * I1ii11iIi11i
 IiI1iIiii1i = json . loads ( IiI )
 if ( type ( IiI1iIiii1i ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( II11IIII1 ) )
  if 81 - 81: O0 + o0oOOo0O0Ooo - oO0o - I1ii11iIi11i * o0oOOo0O0Ooo
  return
  if 99 - 99: I1IiiI / ooOoO0o - I1ii11iIi11i . o0oOOo0O0Ooo
 oOOoOO0oOO = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( oOOoOO0oOO , II11IIII1 , IiI1iIiii1i ) )
 if 35 - 35: iIii1I11I1II1 * o0oOOo0O0Ooo * I1ii11iIi11i - Ii1I
 if ( "type" not in IiI1iIiii1i ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 53 - 53: II111iiii % iIii1I11I1II1 % i11iIiiIii % OOooOOo + OoooooooOO - OoooooooOO
  if 40 - 40: I1ii11iIi11i
  if 90 - 90: i11iIiiIii % i1IIi % OoO0O00 / iII111i * I1ii11iIi11i + I11i
  if 51 - 51: Ii1I * Oo0Ooo - OOooOOo % I1IiiI
  if 42 - 42: I11i - O0
 if ( IiI1iIiii1i [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( IiI1iIiii1i , lisp_send_sockets , lisp_ephem_port )
  return
  if 70 - 70: Ii1I / oO0o + i11iIiiIii - oO0o
 if ( IiI1iIiii1i [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( IiI1iIiii1i , punt_socket )
  return
  if 26 - 26: OoO0O00 % I1ii11iIi11i * O0 % OoO0O00
  if 98 - 98: OoO0O00 . ooOoO0o * I11i / i1IIi
  if 57 - 57: i11iIiiIii % OOooOOo
  if 67 - 67: oO0o - OOooOOo + II111iiii
  if 19 - 19: iIii1I11I1II1 * OoooooooOO - i11iIiiIii . I1Ii111 * OoO0O00
 if ( IiI1iIiii1i [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 30 - 30: iII111i + I1IiiI * ooOoO0o
  if 53 - 53: iII111i + IiII
  if 52 - 52: II111iiii * i11iIiiIii - IiII * IiII / OoooooooOO
  if 18 - 18: IiII / O0 / I1ii11iIi11i
  if 47 - 47: oO0o / iIii1I11I1II1
 if ( IiI1iIiii1i [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 45 - 45: OoOoOO00 * o0oOOo0O0Ooo / I1ii11iIi11i * iII111i - I1ii11iIi11i
 if ( "interface" not in IiI1iIiii1i ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( II11IIII1 ) )
  if 48 - 48: Ii1I / OoO0O00
  return
  if 45 - 45: O0 * OoO0O00 / I11i . II111iiii
  if 20 - 20: I11i - IiII
  if 75 - 75: i11iIiiIii + I11i % I11i . I1Ii111
  if 58 - 58: o0oOOo0O0Ooo * II111iiii + o0oOOo0O0Ooo . I1IiiI
  if 25 - 25: o0oOOo0O0Ooo * I11i
 iIIiI1111 = IiI1iIiii1i [ "interface" ]
 if ( iIIiI1111 == "" ) :
  i1oO00O = int ( IiI1iIiii1i [ "instance-id" ] )
  if ( i1oO00O == - 1 ) : return
 else :
  i1oO00O = lisp_get_interface_instance_id ( iIIiI1111 , None )
  if 70 - 70: OOooOOo
  if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
  if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
  if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
  if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
 o0ooO = None
 if ( "source-eid" in IiI1iIiii1i ) :
  o0O = IiI1iIiii1i [ "source-eid" ]
  o0ooO = lisp_address ( LISP_AFI_NONE , o0O , 0 , i1oO00O )
  if ( o0ooO . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( o0O ) )
   return
   if 63 - 63: I1IiiI
   if 20 - 20: oO0o + OoOoOO00
 OOoO = None
 if ( "dest-eid" in IiI1iIiii1i ) :
  II1I1iiii1 = IiI1iIiii1i [ "dest-eid" ]
  OOoO = lisp_address ( LISP_AFI_NONE , II1I1iiii1 , 0 , i1oO00O )
  if ( OOoO . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( II1I1iiii1 ) )
   return
   if 67 - 67: i1IIi / Ii1I * iIii1I11I1II1 % I1Ii111
   if 4 - 4: ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - o0oOOo0O0Ooo * OOooOOo
   if 91 - 91: OoOoOO00 * II111iiii % I1ii11iIi11i
   if 89 - 89: OOooOOo - Oo0Ooo . I1ii11iIi11i - I1IiiI
   if 1 - 1: iIii1I11I1II1
   if 100 - 100: Oo0Ooo % OoooooooOO
   if 28 - 28: oO0o . o0oOOo0O0Ooo
   if 14 - 14: Oo0Ooo - I1Ii111 + Oo0Ooo / iII111i
 if ( o0ooO ) :
  I1i = green ( o0ooO . print_address ( ) , False )
  iIiI1ii = lisp_db_for_lookups . lookup_cache ( o0ooO , False )
  if ( iIiI1ii != None ) :
   if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
   if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
   if 66 - 66: I1IiiI . Oo0Ooo - oO0o
   if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
   if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
   if ( iIiI1ii . dynamic_eid_configured ( ) ) :
    OooOO = lisp_allow_dynamic_eid ( iIIiI1111 , o0ooO )
    if ( OooOO != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( iIiI1ii , o0ooO , iIIiI1111 , OooOO )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( I1i , iIIiI1111 ) )
     if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
     if 68 - 68: OoOoOO00 - iII111i - I1IiiI
     if 37 - 37: iII111i - I1Ii111 + i1IIi / o0oOOo0O0Ooo % iII111i / iII111i
  else :
   lprint ( "Punt from non-EID source {}" . format ( I1i ) )
   if 8 - 8: i1IIi % I11i
   if 12 - 12: ooOoO0o / II111iiii + ooOoO0o * I1ii11iIi11i / i1IIi - iIii1I11I1II1
   if 71 - 71: IiII - i11iIiiIii
   if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
   if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
   if 80 - 80: I11i
 if ( OOoO ) :
  I111I1iI1 = lisp_map_cache_lookup ( o0ooO , OOoO )
  if ( I111I1iI1 == None or lisp_mr_or_pubsub ( I111I1iI1 . action ) ) :
   if 98 - 98: iII111i / I1ii11iIi11i
   if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
   if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
   if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
   if 56 - 56: IiII * II111iiii + Oo0Ooo - O0 - OoO0O00 . I1Ii111
   if ( lisp_rate_limit_map_request ( OOoO ) ) : return
   if 53 - 53: i1IIi + IiII
   iIiii11 = ( I111I1iI1 and I111I1iI1 . action == LISP_SEND_PUBSUB_ACTION )
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 o0ooO , OOoO , None , iIiii11 )
  else :
   I1i = green ( OOoO . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( I1i ) )
   if 90 - 90: II111iiii / oO0o / oO0o . OoOoOO00 / OoO0O00 / iIii1I11I1II1
   if 96 - 96: iIii1I11I1II1 % I1ii11iIi11i
 return
 if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
 if 72 - 72: I1Ii111 / OoO0O00 + II111iiii
 if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
 if 25 - 25: IiII * IiII
 if 54 - 54: I1Ii111
 if 90 - 90: Oo0Ooo / Ii1I
 if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 oO00Oo = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( oO00Oo )
 return ( [ True , jdata ] )
 if 77 - 77: OoO0O00 / OOooOOo
 if 97 - 97: OoOoOO00 / Ii1I * I1IiiI - Oo0Ooo % O0
 if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
 if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
 if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
 if 93 - 93: O0
 if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
 if 73 - 73: OoooooooOO
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
 if 100 - 100: II111iiii + oO0o
 if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
 if 42 - 42: oO0o + OoO0O00
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 16 - 16: Ii1I
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
 if 84 - 84: OOooOOo
 if 78 - 78: O0 % O0
 if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
 if 41 - 41: iII111i / Ii1I
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 if 24 - 24: IiII / Oo0Ooo
 if 90 - 90: ooOoO0o . OOooOOo - Ii1I
 if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
 if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
 if 55 - 55: ooOoO0o - II111iiii . ooOoO0o . iII111i / OoooooooOO
 if 51 - 51: I1IiiI * I1Ii111 - ooOoO0o + IiII
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 iIiI1I1ii1I1 = eid . print_address ( )
 if ( iIiI1I1ii1I1 in db . dynamic_eids ) :
  db . dynamic_eids [ iIiI1I1ii1I1 ] . last_packet = lisp_get_timestamp ( )
  return
  if 22 - 22: OoOoOO00 % Ii1I + iII111i
  if 64 - 64: ooOoO0o
  if 87 - 87: IiII - Ii1I / Oo0Ooo / I1ii11iIi11i . iII111i
  if 49 - 49: IiII * OoooooooOO * iIii1I11I1II1 * Oo0Ooo / iII111i % oO0o
  if 88 - 88: I1Ii111 * OOooOOo
 ooOoo000 = lisp_dynamic_eid ( )
 ooOoo000 . dynamic_eid . copy_address ( eid )
 ooOoo000 . interface = routed_interface
 ooOoo000 . last_packet = lisp_get_timestamp ( )
 ooOoo000 . get_timeout ( routed_interface )
 db . dynamic_eids [ iIiI1I1ii1I1 ] = ooOoo000
 if 38 - 38: Oo0Ooo - OoooooooOO - OoooooooOO / II111iiii
 IiiI1iI1I = ""
 if ( input_interface != routed_interface ) :
  IiiI1iI1I = ", routed-interface " + routed_interface
  if 90 - 90: I11i + II111iiii - oO0o - ooOoO0o / ooOoO0o / i11iIiiIii
  if 80 - 80: I1ii11iIi11i % O0 / II111iiii + iII111i
 IIi111iI1i1II11IIi = green ( iIiI1I1ii1I1 , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( IIi111iI1i1II11IIi , input_interface , IiiI1iI1I , ooOoo000 . timeout ) )
 if 99 - 99: I1IiiI + O0 + OoOoOO00 + I1ii11iIi11i
 if 80 - 80: OoOoOO00
 if 46 - 46: iIii1I11I1II1 % OoooooooOO - I1Ii111 % Oo0Ooo % i11iIiiIii % OOooOOo
 if 2 - 2: i11iIiiIii
 if 93 - 93: OoOoOO00
 Iii1 = "learn%{}%{}" . format ( iIiI1I1ii1I1 , routed_interface )
 Iii1 = lisp_command_ipc ( Iii1 , "lisp-itr" )
 lisp_ipc ( Iii1 , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 14 - 14: II111iiii
 if 68 - 68: Ii1I % Oo0Ooo + I1ii11iIi11i + I1ii11iIi11i + oO0o % Oo0Ooo
 if 22 - 22: OoO0O00
 if 40 - 40: I1ii11iIi11i * I1Ii111
 if 6 - 6: i11iIiiIii . o0oOOo0O0Ooo * iIii1I11I1II1 . OoOoOO00 . II111iiii
 if 67 - 67: OoO0O00 - Oo0Ooo + OOooOOo / OoOoOO00 + OOooOOo
 if 18 - 18: Oo0Ooo % OoOoOO00 % i1IIi
 if 66 - 66: OoOoOO00 % II111iiii
 if 16 - 16: i11iIiiIii - I1IiiI + ooOoO0o * oO0o
 if 30 - 30: II111iiii / o0oOOo0O0Ooo
 if 57 - 57: I11i / I1ii11iIi11i . I11i
 if 68 - 68: OoOoOO00 + O0 . I1IiiI
 if 26 - 26: I1ii11iIi11i
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 98 - 98: Oo0Ooo
 if 72 - 72: oO0o + OoooooooOO . O0 + IiII
 if 49 - 49: i1IIi - i11iIiiIii + II111iiii + Ii1I / OoO0O00
 if 34 - 34: I1ii11iIi11i * i11iIiiIii
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 6 - 6: I1ii11iIi11i + I1IiiI / OoooooooOO % I11i * Oo0Ooo
 OO0o0OoO0O = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 20 - 20: Oo0Ooo
 for IIIOoo in lisp_crypto_keys_by_rloc_decap :
  if 85 - 85: I1Ii111
  if 98 - 98: OoO0O00 - IiII % iIii1I11I1II1 . OoOoOO00 + i1IIi + OoooooooOO
  if 29 - 29: I1ii11iIi11i * I1Ii111 - i1IIi * i11iIiiIii * iIii1I11I1II1 % I11i
  if 73 - 73: OoO0O00 . I1IiiI / o0oOOo0O0Ooo
  if ( IIIOoo . find ( addr_str ) == - 1 ) : continue
  if 12 - 12: I11i * i11iIiiIii - O0 * o0oOOo0O0Ooo - IiII + I1IiiI
  if 7 - 7: oO0o + I1Ii111 . o0oOOo0O0Ooo / IiII + iIii1I11I1II1 % I1Ii111
  if 24 - 24: i11iIiiIii + iIii1I11I1II1
  if 22 - 22: i11iIiiIii . II111iiii / o0oOOo0O0Ooo / Ii1I . O0 . OoOoOO00
  if ( IIIOoo == addr_str ) : continue
  if 89 - 89: O0 * Oo0Ooo + I1Ii111 + ooOoO0o * OoOoOO00
  if 20 - 20: OoO0O00 - OoOoOO00
  if 84 - 84: iIii1I11I1II1 + ooOoO0o . o0oOOo0O0Ooo % iII111i
  if 35 - 35: I11i - oO0o * oO0o / OoooooooOO + iII111i + OoOoOO00
  oO00Oo = lisp_crypto_keys_by_rloc_decap [ IIIOoo ]
  if ( oO00Oo == OO0o0OoO0O ) : continue
  if 48 - 48: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / o0oOOo0O0Ooo % O0
  if 38 - 38: OoO0O00 + o0oOOo0O0Ooo / OoO0O00
  if 74 - 74: oO0o - i1IIi . Oo0Ooo / I1IiiI + o0oOOo0O0Ooo . OoOoOO00
  if 35 - 35: iII111i / Ii1I
  o0o0OO000O00 = oO00Oo [ 1 ]
  if ( packet_icv != o0o0OO000O00 . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( IIIOoo , False ) ) )
   continue
   if 29 - 29: oO0o - ooOoO0o * iIii1I11I1II1 / OoOoOO00
   if 34 - 34: I1IiiI . Oo0Ooo
  lprint ( "Changing decap crypto key to {}" . format ( red ( IIIOoo , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = oO00Oo
  if 4 - 4: Ii1I - II111iiii * iII111i / oO0o - I1IiiI
 return
 if 32 - 32: iIii1I11I1II1 - I11i
 if 49 - 49: I11i * I1Ii111 - iIii1I11I1II1 * O0
 if 72 - 72: I1IiiI * iII111i
 if 61 - 61: Ii1I * Oo0Ooo * I1Ii111 % I11i + iII111i % oO0o
 if 67 - 67: IiII
 if 90 - 90: o0oOOo0O0Ooo
 if 5 - 5: i1IIi
 if 55 - 55: Ii1I
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 46 - 46: OOooOOo / iII111i . i1IIi . i11iIiiIii . iIii1I11I1II1 % I11i
 if 62 - 62: I11i % II111iiii % OoooooooOO * ooOoO0o / oO0o
 if 29 - 29: o0oOOo0O0Ooo / O0 / OoO0O00
 if 23 - 23: Ii1I + i11iIiiIii % IiII
 if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
 if 49 - 49: O0
 if 72 - 72: I1Ii111
 if 96 - 96: II111iiii / OOooOOo % i1IIi / Oo0Ooo
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 iii1IiII1ii = dns_name . split ( "." )
 iii1IiII1ii = "." . join ( iii1IiII1ii [ 1 : : ] )
 return ( iii1IiII1ii == lisp_decent_dns_suffix )
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
def lisp_get_decent_index ( eid ) :
 iIiI1I1ii1I1 = eid . print_prefix ( )
 i1i11111iiII1 = hmac . new ( "lisp-decent" , iIiI1I1ii1I1 , hashlib . sha256 ) . hexdigest ( )
 if 30 - 30: O0 - I11i
 if 98 - 98: OoOoOO00 . II111iiii . II111iiii * i1IIi + OoOoOO00 / I1ii11iIi11i
 if 71 - 71: Ii1I / I1IiiI / OOooOOo + Oo0Ooo - I11i
 if 16 - 16: II111iiii * Ii1I - I1ii11iIi11i
 o0o0OoOo0oO00 = os . getenv ( "LISP_DECENT_HASH_WIDTH" )
 if ( o0o0OoOo0oO00 in [ "" , None ] ) :
  o0o0OoOo0oO00 = 12
 else :
  o0o0OoOo0oO00 = int ( o0o0OoOo0oO00 )
  if ( o0o0OoOo0oO00 > 32 ) :
   o0o0OoOo0oO00 = 12
  else :
   o0o0OoOo0oO00 *= 2
   if 46 - 46: I1Ii111
   if 30 - 30: O0 * I1IiiI . I1Ii111
   if 99 - 99: I1Ii111 / Oo0Ooo - oO0o
 i11IIIiIiII1 = i1i11111iiII1 [ 0 : o0o0OoOo0oO00 ]
 OOOooo0OooOoO = int ( i11IIIiIiII1 , 16 ) % lisp_decent_modulus
 if 24 - 24: OoooooooOO . i1IIi - O0 * i1IIi - OOooOOo
 lprint ( "LISP-Decent modulus {}, hash-width {}, mod-value {}, index {}" . format ( lisp_decent_modulus , old_div ( o0o0OoOo0oO00 , 2 ) , i11IIIiIiII1 , OOOooo0OooOoO ) )
 if 73 - 73: Oo0Ooo % ooOoO0o - O0 + OOooOOo / Ii1I
 if 24 - 24: I1IiiI - IiII + I1ii11iIi11i
 return ( OOOooo0OooOoO )
 if 82 - 82: o0oOOo0O0Ooo . IiII . Ii1I . IiII % iIii1I11I1II1 + oO0o
 if 35 - 35: O0 / O0 . i1IIi
 if 58 - 58: IiII . iII111i % O0 . Ii1I * Oo0Ooo
 if 54 - 54: OoO0O00 % OOooOOo - OoO0O00 . Oo0Ooo % i1IIi
 if 95 - 95: iII111i . OoooooooOO . o0oOOo0O0Ooo / II111iiii - OoooooooOO / I1Ii111
 if 11 - 11: II111iiii / iII111i . oO0o / ooOoO0o / OOooOOo + OoO0O00
 if 37 - 37: iIii1I11I1II1 * O0
def lisp_get_decent_dns_name ( eid ) :
 OOOooo0OooOoO = lisp_get_decent_index ( eid )
 return ( str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix )
 if 64 - 64: I1Ii111 - II111iiii + oO0o % ooOoO0o * oO0o
 if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
 if 27 - 27: OoOoOO00 . I11i / OoOoOO00
 if 96 - 96: OoO0O00 - I1IiiI
 if 73 - 73: I1IiiI - o0oOOo0O0Ooo - I1Ii111
 if 34 - 34: iIii1I11I1II1 - i1IIi + OoO0O00 % Oo0Ooo + i1IIi
 if 46 - 46: I1IiiI
 if 82 - 82: iII111i . i1IIi
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 oo0oO = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 OOOooo0OooOoO = lisp_get_decent_index ( oo0oO )
 return ( str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix )
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
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 13 - 13: O0
 IiI1ii1Ii = 28 if packet . inner_version == 4 else 48
 oO0Oo0OoO0oo = packet . packet [ IiI1ii1Ii : : ]
 O0O0 = lisp_trace ( )
 if ( O0O0 . decode ( oO0Oo0OoO0oo ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 22 - 22: i1IIi * OoOoOO00 + Ii1I
  if 48 - 48: Ii1I % IiII + OoO0O00 . IiII
 i1i11iiIIii = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 52 - 52: oO0o
 if 42 - 42: Oo0Ooo . i11iIiiIii + i11iIiiIii / OoOoOO00 . OOooOOo + I11i
 if 65 - 65: i1IIi % i1IIi + O0 . O0 . I11i / o0oOOo0O0Ooo
 if 59 - 59: iIii1I11I1II1 . iII111i
 if 33 - 33: I1Ii111 - Ii1I / I11i
 if 17 - 17: OoO0O00
 if ( i1i11iiIIii != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : i1i11iiIIii += ":{}" . format ( packet . encap_port )
  if 85 - 85: IiII
  if 3 - 3: I11i % OOooOOo % OoO0O00
  if 93 - 93: i11iIiiIii % I1IiiI
  if 81 - 81: iIii1I11I1II1 / Oo0Ooo - i11iIiiIii / I1IiiI * iII111i
  if 32 - 32: i1IIi - Oo0Ooo
 oO00Oo = { }
 oO00Oo [ "n" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 44 - 44: o0oOOo0O0Ooo + oO0o * II111iiii % Ii1I
 iiI1iIIii = packet . outer_source
 if ( iiI1iIIii . is_null ( ) ) : iiI1iIIii = lisp_myrlocs [ 0 ]
 oO00Oo [ "sr" ] = iiI1iIIii . print_address_no_iid ( )
 if 38 - 38: o0oOOo0O0Ooo
 if 78 - 78: OoO0O00 % o0oOOo0O0Ooo * IiII
 if 35 - 35: Ii1I
 if 93 - 93: II111iiii / I1Ii111 + iII111i + I1ii11iIi11i . I11i
 if 21 - 21: IiII / OoO0O00 % IiII - OoO0O00
 if ( oO00Oo [ "n" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  oO00Oo [ "sr" ] += ":{}" . format ( packet . inner_sport )
  if 87 - 87: II111iiii
  if 38 - 38: I1IiiI / O0
 oO00Oo [ "hn" ] = lisp_hostname
 IIIOoo = ed [ 0 ] + "ts"
 oO00Oo [ IIIOoo ] = lisp_get_timestamp ( )
 if 92 - 92: o0oOOo0O0Ooo + OoooooooOO / ooOoO0o % oO0o
 if 28 - 28: i1IIi . II111iiii + O0 / O0 % OoOoOO00 + OOooOOo
 if 24 - 24: OoooooooOO
 if 11 - 11: i11iIiiIii / iIii1I11I1II1 % ooOoO0o + OOooOOo
 if 73 - 73: OoOoOO00 + OoooooooOO + iIii1I11I1II1 + II111iiii * iIii1I11I1II1 - OoOoOO00
 if 71 - 71: O0 * OOooOOo . I1IiiI . I1Ii111 * I11i
 if ( i1i11iiIIii == "?" and oO00Oo [ "n" ] == "ETR" ) :
  iIiI1ii = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( iIiI1ii != None and len ( iIiI1ii . rloc_set ) >= 1 ) :
   i1i11iiIIii = iIiI1ii . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 45 - 45: O0 . O0 . II111iiii * ooOoO0o
   if 2 - 2: OoO0O00 . o0oOOo0O0Ooo
 oO00Oo [ "dr" ] = i1i11iiIIii
 if 48 - 48: Ii1I
 if 45 - 45: I1ii11iIi11i - I11i + Ii1I
 if 82 - 82: iII111i
 if 81 - 81: i1IIi % OOooOOo - OoO0O00 - Oo0Ooo
 if ( i1i11iiIIii == "?" and reason != None ) :
  oO00Oo [ "dr" ] += " ({})" . format ( reason )
  if 19 - 19: i1IIi
  if 97 - 97: OoO0O00 + i11iIiiIii % I1IiiI * Ii1I
  if 89 - 89: IiII % i11iIiiIii + OoO0O00 . oO0o / I1IiiI . Ii1I
  if 11 - 11: ooOoO0o - I1Ii111 - I11i + OoOoOO00
  if 20 - 20: I11i + O0
 if ( rloc_entry != None ) :
  oO00Oo [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  oO00Oo [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  oO00Oo [ "lats" ] = rloc_entry . recent_rloc_probe_latencies
  if 27 - 27: Oo0Ooo
  if 12 - 12: I1ii11iIi11i . iII111i - iII111i - OOooOOo - iIii1I11I1II1
  if 50 - 50: I1IiiI - iIii1I11I1II1 . iII111i - Ii1I / I1Ii111 + iII111i
  if 46 - 46: OOooOOo + iII111i % Oo0Ooo * iII111i % OoooooooOO * IiII
  if 27 - 27: I1IiiI + I1IiiI + I1ii11iIi11i - oO0o * OOooOOo
  if 53 - 53: I1ii11iIi11i / OoooooooOO * iIii1I11I1II1
 o0ooO = packet . inner_source . print_address ( )
 OOoO = packet . inner_dest . print_address ( )
 if ( O0O0 . packet_json == [ ] ) :
  oOO0oOoOO = { }
  oOO0oOoOO [ "se" ] = o0ooO
  oOO0oOoOO [ "de" ] = OOoO
  oOO0oOoOO [ "paths" ] = [ ]
  O0O0 . packet_json . append ( oOO0oOoOO )
  if 4 - 4: I1IiiI . iIii1I11I1II1 + OOooOOo / IiII . o0oOOo0O0Ooo . I11i
  if 52 - 52: ooOoO0o % i11iIiiIii . IiII + OoO0O00
  if 66 - 66: II111iiii . Ii1I
  if 42 - 42: iIii1I11I1II1 * iII111i * I1IiiI
  if 66 - 66: Oo0Ooo * i1IIi / I1ii11iIi11i / OoO0O00
  if 12 - 12: OOooOOo + iIii1I11I1II1 % I1Ii111 + OOooOOo
 for oOO0oOoOO in O0O0 . packet_json :
  if ( oOO0oOoOO [ "de" ] != OOoO ) : continue
  oOO0oOoOO [ "paths" ] . append ( oO00Oo )
  break
  if 19 - 19: OoO0O00 / I1IiiI - o0oOOo0O0Ooo - i1IIi + I1ii11iIi11i * OoooooooOO
  if 74 - 74: I1Ii111 . I11i / Oo0Ooo
  if 88 - 88: oO0o % OoO0O00 - i11iIiiIii % I1Ii111 / O0 * IiII
  if 99 - 99: o0oOOo0O0Ooo . ooOoO0o / i11iIiiIii
  if 44 - 44: IiII + OOooOOo % OoO0O00 . OoooooooOO * O0
  if 72 - 72: i1IIi - iII111i * I1IiiI % O0 - I11i * O0
  if 78 - 78: I1IiiI - OoO0O00 / Ii1I . i1IIi
  if 30 - 30: IiII
 iiOoOo0O = False
 if ( len ( O0O0 . packet_json ) == 1 and oO00Oo [ "n" ] == "ETR" and
 O0O0 . myeid ( packet . inner_dest ) ) :
  oOO0oOoOO = { }
  oOO0oOoOO [ "se" ] = OOoO
  oOO0oOoOO [ "de" ] = o0ooO
  oOO0oOoOO [ "paths" ] = [ ]
  O0O0 . packet_json . append ( oOO0oOoOO )
  iiOoOo0O = True
  if 77 - 77: OoOoOO00 / OoO0O00 - o0oOOo0O0Ooo * I1IiiI
  if 42 - 42: ooOoO0o % OoooooooOO - Oo0Ooo - II111iiii
  if 49 - 49: O0 % O0
  if 4 - 4: IiII / I1Ii111
  if 6 - 6: Ii1I
  if 63 - 63: Oo0Ooo - II111iiii
 O0O0 . print_trace ( )
 oO0Oo0OoO0oo = O0O0 . encode ( )
 if 3 - 3: iIii1I11I1II1
 if 21 - 21: Ii1I
 if 37 - 37: II111iiii - I11i / oO0o / I11i % Oo0Ooo
 if 81 - 81: I1Ii111 . ooOoO0o + OoooooooOO + II111iiii / iIii1I11I1II1 * I1Ii111
 if 23 - 23: Ii1I
 if 74 - 74: OoooooooOO % I1Ii111 + OoO0O00 * i11iIiiIii - I11i - I1ii11iIi11i
 if 98 - 98: Ii1I - Oo0Ooo - o0oOOo0O0Ooo
 if 7 - 7: II111iiii + OoO0O00 . I1IiiI - iII111i . o0oOOo0O0Ooo
 o0oooO = O0O0 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "sr" ]
 if ( i1i11iiIIii == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( o0oooO ) )
  O0O0 . return_to_sender ( lisp_socket , o0oooO , oO0Oo0OoO0oo )
  return ( False )
  if 86 - 86: II111iiii % I1ii11iIi11i
  if 88 - 88: Oo0Ooo . oO0o + OoOoOO00 % OoooooooOO
  if 81 - 81: OoooooooOO . I1Ii111 + OoO0O00 % I1Ii111
  if 49 - 49: oO0o . oO0o % oO0o / Oo0Ooo
  if 62 - 62: ooOoO0o . i1IIi % OoO0O00 - I1ii11iIi11i - IiII
  if 57 - 57: i1IIi - II111iiii - O0 . iII111i + OoO0O00
 OooooOo = O0O0 . packet_length ( )
 if 67 - 67: OOooOOo * iII111i / iIii1I11I1II1 / I1ii11iIi11i
 if 10 - 10: OoooooooOO % I1ii11iIi11i * i1IIi . iII111i
 if 96 - 96: II111iiii % i11iIiiIii - Oo0Ooo
 if 70 - 70: O0 * iIii1I11I1II1 - IiII * I11i / Ii1I + i11iIiiIii
 if 26 - 26: II111iiii - I11i % I11i / ooOoO0o + Oo0Ooo
 if 91 - 91: I1IiiI % Ii1I - OOooOOo - Oo0Ooo / I1IiiI / OoO0O00
 i1iOoO = packet . packet [ 0 : IiI1ii1Ii ]
 IiIiIII11i1i = struct . pack ( "HH" , socket . htons ( OooooOo ) , 0 )
 i1iOoO = i1iOoO [ 0 : IiI1ii1Ii - 4 ] + IiIiIII11i1i
 if ( packet . inner_version == 6 and oO00Oo [ "n" ] == "ETR" and
 len ( O0O0 . packet_json ) == 2 ) :
  Ii1iiI1 = i1iOoO [ IiI1ii1Ii - 8 : : ] + oO0Oo0OoO0oo
  Ii1iiI1 = lisp_udp_checksum ( o0ooO , OOoO , Ii1iiI1 )
  i1iOoO = i1iOoO [ 0 : IiI1ii1Ii - 8 ] + Ii1iiI1 [ 0 : 8 ]
  if 98 - 98: i1IIi / OoOoOO00 * OOooOOo + ooOoO0o
  if 56 - 56: o0oOOo0O0Ooo % OoooooooOO . i1IIi + i1IIi - oO0o
  if 41 - 41: I11i
  if 92 - 92: i11iIiiIii
  if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
  if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
  if 77 - 77: i1IIi
  if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
  if 65 - 65: O0 / OoOoOO00
 if ( iiOoOo0O ) :
  if ( packet . inner_version == 4 ) :
   i1iOoO = i1iOoO [ 0 : 12 ] + i1iOoO [ 16 : 20 ] + i1iOoO [ 12 : 16 ] + i1iOoO [ 22 : 24 ] + i1iOoO [ 20 : 22 ] + i1iOoO [ 24 : : ]
   if 77 - 77: OoO0O00
  else :
   i1iOoO = i1iOoO [ 0 : 8 ] + i1iOoO [ 24 : 40 ] + i1iOoO [ 8 : 24 ] + i1iOoO [ 42 : 44 ] + i1iOoO [ 40 : 42 ] + i1iOoO [ 44 : : ]
   if 17 - 17: i1IIi
   if 35 - 35: OoOoOO00
  iiIi = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = iiIi
  if 61 - 61: I1Ii111
  if 78 - 78: I1Ii111 * Ii1I % Ii1I + I1IiiI
  if 83 - 83: iIii1I11I1II1 + O0 / IiII . iIii1I11I1II1
  if 74 - 74: Oo0Ooo
  if 60 - 60: OoooooooOO
  if 16 - 16: iIii1I11I1II1 - OoOoOO00 / I1ii11iIi11i % O0 % o0oOOo0O0Ooo
  if 99 - 99: ooOoO0o . o0oOOo0O0Ooo - O0 * I1Ii111 . i11iIiiIii / iIii1I11I1II1
 IiI1ii1Ii = 2 if packet . inner_version == 4 else 4
 IiiIIi = 20 + OooooOo if packet . inner_version == 4 else OooooOo
 I111Iii1I11Ii = struct . pack ( "H" , socket . htons ( IiiIIi ) )
 i1iOoO = i1iOoO [ 0 : IiI1ii1Ii ] + I111Iii1I11Ii + i1iOoO [ IiI1ii1Ii + 2 : : ]
 if 69 - 69: i1IIi + O0
 if 67 - 67: I1ii11iIi11i * iIii1I11I1II1 / O0 - I1Ii111
 if 82 - 82: I1ii11iIi11i % i11iIiiIii - OoOoOO00 / I1Ii111 * o0oOOo0O0Ooo * OoO0O00
 if 85 - 85: Oo0Ooo + Ii1I - OoooooooOO . O0
 if ( packet . inner_version == 4 ) :
  iIiIII = struct . pack ( "H" , 0 )
  i1iOoO = i1iOoO [ 0 : 10 ] + iIiIII + i1iOoO [ 12 : : ]
  I111Iii1I11Ii = lisp_ip_checksum ( i1iOoO [ 0 : 20 ] )
  i1iOoO = I111Iii1I11Ii + i1iOoO [ 20 : : ]
  if 10 - 10: OOooOOo / Oo0Ooo . O0 / i1IIi - OoOoOO00
  if 41 - 41: II111iiii - I1ii11iIi11i - I1Ii111
  if 82 - 82: I1IiiI * I1IiiI / iIii1I11I1II1
  if 14 - 14: I11i + Ii1I - OOooOOo % Ii1I / Ii1I
  if 86 - 86: I1Ii111 - i11iIiiIii + Ii1I + I11i
 packet . packet = i1iOoO + oO0Oo0OoO0oo
 return ( True )
 if 96 - 96: Ii1I
 if 28 - 28: i1IIi . oO0o . IiII + Oo0Ooo . Oo0Ooo . i1IIi
 if 34 - 34: Oo0Ooo + IiII / i1IIi
 if 33 - 33: i1IIi
 if 26 - 26: ooOoO0o - Oo0Ooo * II111iiii - Oo0Ooo
 if 15 - 15: OoO0O00 - oO0o . OoOoOO00 / O0 * oO0o
 if 45 - 45: O0
 if 89 - 89: IiII - IiII % o0oOOo0O0Ooo * Oo0Ooo % ooOoO0o
 if 4 - 4: OoO0O00 % II111iiii / I11i
 if 95 - 95: I1Ii111 - I1Ii111 - iII111i + IiII . OoO0O00
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 5 - 5: i11iIiiIii - O0 % ooOoO0o
 for oO00Oo in lisp_glean_mappings :
  if ( "instance-id" in oO00Oo ) :
   i1oO00O = eid . instance_id
   I1i1 , IiIiI1IIi1Ii = oO00Oo [ "instance-id" ]
   if ( i1oO00O < I1i1 or i1oO00O > IiIiI1IIi1Ii ) : continue
   if 55 - 55: II111iiii
  if ( "eid-prefix" in oO00Oo ) :
   I1i = copy . deepcopy ( oO00Oo [ "eid-prefix" ] )
   I1i . instance_id = eid . instance_id
   if ( eid . is_more_specific ( I1i ) == False ) : continue
   if 7 - 7: I1Ii111 % o0oOOo0O0Ooo . oO0o . ooOoO0o % i1IIi / I1IiiI
  if ( "group-prefix" in oO00Oo ) :
   if ( group == None ) : continue
   o0O0Ooo = copy . deepcopy ( oO00Oo [ "group-prefix" ] )
   o0O0Ooo . instance_id = group . instance_id
   if ( group . is_more_specific ( o0O0Ooo ) == False ) : continue
   if 88 - 88: i11iIiiIii / oO0o - i1IIi / I1IiiI
  if ( "rloc-prefix" in oO00Oo ) :
   if ( rloc != None and rloc . is_more_specific ( oO00Oo [ "rloc-prefix" ] )
 == False ) : continue
   if 57 - 57: oO0o + O0 * I11i
  return ( True , oO00Oo [ "rloc-probe" ] , oO00Oo [ "igmp-query" ] )
  if 87 - 87: o0oOOo0O0Ooo % Oo0Ooo * I1ii11iIi11i / OoooooooOO / o0oOOo0O0Ooo
 return ( False , False , False )
 if 78 - 78: Ii1I
 if 5 - 5: i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
 if 57 - 57: IiII
 if 89 - 89: I1ii11iIi11i - I1Ii111 + o0oOOo0O0Ooo
 if 62 - 62: I1ii11iIi11i + OoooooooOO * OOooOOo
 if 49 - 49: i1IIi - I11i * II111iiii
 if 4 - 4: o0oOOo0O0Ooo + o0oOOo0O0Ooo
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 iiiii1I1III1 = geid . print_address ( )
 Ooo00oOOOOoo = seid . print_address_no_iid ( )
 I1iiIi111I = green ( "{}" . format ( Ooo00oOOOOoo ) , False )
 I1i = green ( "(*, {})" . format ( iiiii1I1III1 ) , False )
 OOoooo = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 65 - 65: Oo0Ooo
 if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * OoooooooOO . o0oOOo0O0Ooo
 if 90 - 90: i11iIiiIii . I1IiiI + ooOoO0o * OoooooooOO * OoooooooOO + oO0o
 if 77 - 77: OOooOOo * OoOoOO00
 I111I1iI1 = lisp_map_cache_lookup ( seid , geid )
 if ( I111I1iI1 == None ) :
  I111I1iI1 = lisp_mapping ( "" , "" , [ ] )
  I111I1iI1 . group . copy_address ( geid )
  I111I1iI1 . eid . copy_address ( geid )
  I111I1iI1 . eid . address = 0
  I111I1iI1 . eid . mask_len = 0
  I111I1iI1 . mapping_source . copy_address ( rloc )
  I111I1iI1 . map_cache_ttl = LISP_IGMP_TTL
  I111I1iI1 . gleaned = True
  I111I1iI1 . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( I1i ) )
  if 75 - 75: Oo0Ooo * Oo0Ooo - IiII - OoOoOO00 / i11iIiiIii + I1Ii111
  if 57 - 57: i11iIiiIii / oO0o
  if 37 - 37: o0oOOo0O0Ooo + OoOoOO00 - i1IIi . Oo0Ooo
  if 3 - 3: ooOoO0o % OoooooooOO / I1Ii111 + oO0o - O0
  if 72 - 72: oO0o * OoO0O00
  if 89 - 89: OoooooooOO . OOooOOo
 O0O0OOo0O = OOoOOo0 = oO0oOOOO0oO0o0 = None
 if ( I111I1iI1 . rloc_set != [ ] ) :
  O0O0OOo0O = I111I1iI1 . rloc_set [ 0 ]
  if ( O0O0OOo0O . rle ) :
   OOoOOo0 = O0O0OOo0O . rle
   for o0I1i11 in OOoOOo0 . rle_nodes :
    if ( o0I1i11 . rloc_name != Ooo00oOOOOoo ) : continue
    oO0oOOOO0oO0o0 = o0I1i11
    break
    if 26 - 26: Oo0Ooo / I1ii11iIi11i / Oo0Ooo % Oo0Ooo . IiII
    if 52 - 52: I1Ii111 - IiII / Ii1I
    if 64 - 64: I1Ii111 / Ii1I
    if 78 - 78: I11i % ooOoO0o - iIii1I11I1II1 / iIii1I11I1II1
    if 65 - 65: Ii1I . i1IIi + i11iIiiIii % I1Ii111 . OoO0O00 + Oo0Ooo
    if 82 - 82: O0 % I1IiiI / II111iiii * iII111i - OoO0O00 - II111iiii
    if 51 - 51: I1Ii111 % IiII / iIii1I11I1II1 % I1IiiI * i11iIiiIii
 if ( O0O0OOo0O == None ) :
  O0O0OOo0O = lisp_rloc ( )
  I111I1iI1 . rloc_set = [ O0O0OOo0O ]
  O0O0OOo0O . priority = 253
  O0O0OOo0O . mpriority = 255
  I111I1iI1 . build_best_rloc_set ( )
  if 26 - 26: II111iiii
 if ( OOoOOo0 == None ) :
  OOoOOo0 = lisp_rle ( geid . print_address ( ) )
  O0O0OOo0O . rle = OOoOOo0
  if 19 - 19: IiII - II111iiii / o0oOOo0O0Ooo . oO0o % OoooooooOO % I1IiiI
 if ( oO0oOOOO0oO0o0 == None ) :
  oO0oOOOO0oO0o0 = lisp_rle_node ( )
  oO0oOOOO0oO0o0 . rloc_name = Ooo00oOOOOoo
  OOoOOo0 . rle_nodes . append ( oO0oOOOO0oO0o0 )
  OOoOOo0 . build_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( OOoooo , I1iiIi111I , I1i ) )
 elif ( rloc . is_exact_match ( oO0oOOOO0oO0o0 . address ) == False or
 port != oO0oOOOO0oO0o0 . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( OOoooo , I1iiIi111I , I1i ) )
  if 76 - 76: oO0o * I1ii11iIi11i
  if 42 - 42: II111iiii . O0
  if 32 - 32: i1IIi % O0 / II111iiii - OoO0O00 + IiII * i11iIiiIii
  if 55 - 55: II111iiii
  if 93 - 93: i11iIiiIii / OoooooooOO % I1ii11iIi11i % I1ii11iIi11i
 oO0oOOOO0oO0o0 . store_translated_rloc ( rloc , port )
 if 37 - 37: OoO0O00 . I11i / I1ii11iIi11i . OoO0O00 - I1Ii111 + Oo0Ooo
 if 42 - 42: I1ii11iIi11i . I11i
 if 95 - 95: I1IiiI - I11i * I1Ii111 - I11i
 if 92 - 92: oO0o % iIii1I11I1II1 * o0oOOo0O0Ooo * OoooooooOO - iIii1I11I1II1
 if 51 - 51: Ii1I - OoO0O00 + i1IIi
 if ( igmp ) :
  iI11iI11i11ii = seid . print_address ( )
  if ( iI11iI11i11ii not in lisp_gleaned_groups ) :
   lisp_gleaned_groups [ iI11iI11i11ii ] = { }
   if 11 - 11: II111iiii - iII111i + oO0o % Oo0Ooo
  lisp_gleaned_groups [ iI11iI11i11ii ] [ iiiii1I1III1 ] = lisp_get_timestamp ( )
  if 56 - 56: IiII
  if 72 - 72: Oo0Ooo
  if 37 - 37: i11iIiiIii * I1IiiI % ooOoO0o
  if 23 - 23: OoO0O00 + o0oOOo0O0Ooo * I1IiiI
  if 76 - 76: i1IIi . OOooOOo
  if 78 - 78: OoooooooOO % OoOoOO00 * oO0o . I1ii11iIi11i
  if 79 - 79: OoooooooOO
  if 6 - 6: i11iIiiIii / II111iiii + II111iiii + I1ii11iIi11i % IiII - I1ii11iIi11i
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 92 - 92: IiII
 if 49 - 49: O0 . OoOoOO00
 if 7 - 7: i1IIi + II111iiii
 if 96 - 96: I1Ii111 / OoO0O00
 I111I1iI1 = lisp_map_cache_lookup ( seid , geid )
 if ( I111I1iI1 == None ) : return
 if 27 - 27: Ii1I
 IIii1i = I111I1iI1 . rloc_set [ 0 ] . rle
 if ( IIii1i == None ) : return
 if 90 - 90: I1ii11iIi11i
 i1Ii1iiI = seid . print_address_no_iid ( )
 iIIiOOOO0 = False
 for oO0oOOOO0oO0o0 in IIii1i . rle_nodes :
  if ( oO0oOOOO0oO0o0 . rloc_name == i1Ii1iiI ) :
   iIIiOOOO0 = True
   break
   if 43 - 43: OoO0O00 . I1IiiI . oO0o + Ii1I
   if 7 - 7: iII111i / Oo0Ooo - OoO0O00 + I1Ii111 * II111iiii * ooOoO0o
 if ( iIIiOOOO0 == False ) : return
 if 80 - 80: oO0o - i1IIi / I11i . II111iiii % O0 % I11i
 if 70 - 70: iIii1I11I1II1 * i1IIi * OOooOOo - Oo0Ooo % i1IIi
 if 60 - 60: o0oOOo0O0Ooo . OOooOOo % II111iiii - I1ii11iIi11i
 if 4 - 4: OOooOOo % ooOoO0o
 IIii1i . rle_nodes . remove ( oO0oOOOO0oO0o0 )
 IIii1i . build_forwarding_list ( )
 if 39 - 39: Ii1I
 iiiii1I1III1 = geid . print_address ( )
 iI11iI11i11ii = seid . print_address ( )
 I1iiIi111I = green ( "{}" . format ( iI11iI11i11ii ) , False )
 I1i = green ( "(*, {})" . format ( iiiii1I1III1 ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( I1i , I1iiIi111I ) )
 if 67 - 67: iIii1I11I1II1 - OOooOOo
 if 47 - 47: OOooOOo - OOooOOo * I1Ii111
 if 24 - 24: I1ii11iIi11i
 if 37 - 37: II111iiii - iIii1I11I1II1 / o0oOOo0O0Ooo . O0 + II111iiii
 if ( iI11iI11i11ii in lisp_gleaned_groups ) :
  if ( iiiii1I1III1 in lisp_gleaned_groups [ iI11iI11i11ii ] ) :
   lisp_gleaned_groups [ iI11iI11i11ii ] . pop ( iiiii1I1III1 )
   if 9 - 9: o0oOOo0O0Ooo
   if 47 - 47: Ii1I * I1Ii111 / II111iiii
   if 73 - 73: ooOoO0o
   if 53 - 53: IiII . Oo0Ooo
   if 54 - 54: i11iIiiIii % ooOoO0o % I1Ii111 + o0oOOo0O0Ooo
   if 2 - 2: IiII
 if ( IIii1i . rle_nodes == [ ] ) :
  I111I1iI1 . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( I1i ) )
  if 25 - 25: OoOoOO00 . OoO0O00 * o0oOOo0O0Ooo . OoooooooOO - Oo0Ooo + I1IiiI
  if 82 - 82: OoO0O00 - Ii1I * I11i * o0oOOo0O0Ooo
  if 17 - 17: OoooooooOO + I1Ii111
  if 91 - 91: iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo
  if 98 - 98: o0oOOo0O0Ooo % II111iiii * IiII - i11iIiiIii * oO0o
  if 15 - 15: O0 - II111iiii - Oo0Ooo . I1ii11iIi11i % OoO0O00
  if 63 - 63: o0oOOo0O0Ooo / OoOoOO00 % I1ii11iIi11i % I11i
  if 58 - 58: O0 + iII111i
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 iI11iI11i11ii = seid . print_address ( )
 if ( iI11iI11i11ii not in lisp_gleaned_groups ) : return
 if 66 - 66: i1IIi . O0 . i1IIi - iIii1I11I1II1 - ooOoO0o % I1ii11iIi11i
 for iiI in lisp_gleaned_groups [ iI11iI11i11ii ] :
  lisp_geid . store_address ( iiI )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
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
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 57 - 57: I1Ii111 * o0oOOo0O0Ooo - o0oOOo0O0Ooo * I11i
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 89 - 89: Ii1I % O0
def lisp_process_igmp_packet ( packet ) :
 II11IIII1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 II11IIII1 . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 II11IIII1 = bold ( "from {}" . format ( II11IIII1 . print_address_no_iid ( ) ) , False )
 if 81 - 81: OoooooooOO / II111iiii - ooOoO0o
 OOoooo = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( OOoooo , len ( packet ) , II11IIII1 ,
 lisp_format_packet ( packet ) ) )
 if 14 - 14: O0
 if 59 - 59: I11i % II111iiii . iIii1I11I1II1 * oO0o % Ii1I
 if 79 - 79: OoooooooOO . II111iiii
 if 55 - 55: II111iiii
 IIIii11IiIiI1 = ( struct . unpack ( "B" , packet [ 0 ] ) [ 0 ] & 0x0f ) * 4
 if 57 - 57: i11iIiiIii - I1Ii111
 if 90 - 90: ooOoO0o . Ii1I % i11iIiiIii + iII111i * iII111i / Oo0Ooo
 if 68 - 68: oO0o
 if 42 - 42: OoOoOO00
 I11IiII11iI = packet [ IIIii11IiIiI1 : : ]
 II11i1iii1 = struct . unpack ( "B" , I11IiII11iI [ 0 ] ) [ 0 ]
 if 7 - 7: i11iIiiIii % I1Ii111
 if 96 - 96: I1Ii111 % OoooooooOO + O0 % o0oOOo0O0Ooo + OOooOOo - iIii1I11I1II1
 if 29 - 29: II111iiii - I1Ii111 + o0oOOo0O0Ooo
 if 23 - 23: OOooOOo * OOooOOo * I1Ii111 . II111iiii
 if 34 - 34: IiII * Oo0Ooo % II111iiii . Ii1I . I1ii11iIi11i
 iiI = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iiI . address = socket . ntohl ( struct . unpack ( "II" , I11IiII11iI [ : 8 ] ) [ 1 ] )
 iiiii1I1III1 = iiI . print_address_no_iid ( )
 if 28 - 28: iII111i
 if ( II11i1iii1 == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( iiiii1I1III1 ) )
  return ( True )
  if 74 - 74: Ii1I + I1IiiI * iII111i / i11iIiiIii - ooOoO0o * OoooooooOO
  if 98 - 98: I1IiiI
 Oo0o0ooo0oo0 = ( II11i1iii1 in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( Oo0o0ooo0oo0 == False ) :
  III111I = "{} ({})" . format ( II11i1iii1 , igmp_types [ II11i1iii1 ] ) if ( II11i1iii1 in igmp_types ) else II11i1iii1
  if 56 - 56: I1Ii111 . i11iIiiIii
  lprint ( "IGMP type {} not supported" . format ( III111I ) )
  return ( [ ] )
  if 58 - 58: ooOoO0o - II111iiii - I11i
  if 37 - 37: I11i % i11iIiiIii
 if ( len ( I11IiII11iI ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 52 - 52: oO0o / o0oOOo0O0Ooo % O0
  if 53 - 53: iIii1I11I1II1 * I1ii11iIi11i
  if 46 - 46: OOooOOo % OoOoOO00 * iII111i
  if 55 - 55: I1IiiI * iIii1I11I1II1 . OoOoOO00
  if 82 - 82: iIii1I11I1II1 - iII111i % I1IiiI + I1IiiI * i1IIi % O0
 if ( II11i1iii1 == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( iiiii1I1III1 , False ) ) )
  return ( [ [ None , iiiii1I1III1 , False ] ] )
  if 63 - 63: I1IiiI + OoOoOO00
 if ( II11i1iii1 in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( II11i1iii1 == 0x12 ) else 2 , bold ( iiiii1I1III1 , False ) ) )
  if 55 - 55: o0oOOo0O0Ooo
  if 95 - 95: OoO0O00 * ooOoO0o * oO0o % Oo0Ooo
  if 36 - 36: I1IiiI - Ii1I + oO0o . iIii1I11I1II1
  if 47 - 47: Ii1I
  if 12 - 12: I1IiiI / IiII + OoOoOO00 . I1Ii111 / I1Ii111
  if ( iiiii1I1III1 . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
  else :
   return ( [ [ None , iiiii1I1III1 , True ] ] )
   if 97 - 97: OOooOOo - iII111i . I1IiiI * oO0o . OoOoOO00 * IiII
   if 29 - 29: iIii1I11I1II1
   if 94 - 94: Ii1I - i11iIiiIii % O0 + Ii1I / O0 % I11i
   if 42 - 42: I1ii11iIi11i . iIii1I11I1II1 % I11i
   if 54 - 54: OoOoOO00 / Ii1I
  return ( [ ] )
  if 84 - 84: Oo0Ooo / OoO0O00 . o0oOOo0O0Ooo - iII111i . iII111i - II111iiii
  if 99 - 99: I1Ii111 % Oo0Ooo
  if 61 - 61: OoooooooOO % i11iIiiIii + OOooOOo
  if 53 - 53: iII111i . iIii1I11I1II1
  if 59 - 59: II111iiii . II111iiii - iII111i
 iIiI1IIi1Ii1i = iiI . address
 I11IiII11iI = I11IiII11iI [ 8 : : ]
 if 46 - 46: oO0o / iIii1I11I1II1 + OoO0O00
 I1iiiIiIi1i1ii = "BBHI"
 I1iiI = struct . calcsize ( I1iiiIiIi1i1ii )
 i1111iiiIIiIiIIii1 = "I"
 IIiIi11 = struct . calcsize ( i1111iiiIIiIiIIii1 )
 II11IIII1 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 18 - 18: I1IiiI / o0oOOo0O0Ooo % I1Ii111 * I1Ii111
 if 98 - 98: i11iIiiIii / o0oOOo0O0Ooo * oO0o - o0oOOo0O0Ooo * i11iIiiIii % OoO0O00
 if 62 - 62: OoOoOO00 / iII111i
 if 70 - 70: IiII / O0 - i1IIi
 ii11iiI = [ ]
 for OoOOoO0oOo in range ( iIiI1IIi1Ii1i ) :
  if ( len ( I11IiII11iI ) < I1iiI ) : return
  i1IOooOOOOoo , I1iIiiI1IIi1 , OoOOOo , I1IIIi = struct . unpack ( I1iiiIiIi1i1ii ,
 I11IiII11iI [ : I1iiI ] )
  if 21 - 21: ooOoO0o * OoO0O00 % Oo0Ooo
  I11IiII11iI = I11IiII11iI [ I1iiI : : ]
  if 81 - 81: OoO0O00 + I1Ii111 . OoOoOO00 * I11i * O0
  if ( i1IOooOOOOoo not in lisp_igmp_record_types ) :
   lprint ( "Invalid record type {}" . format ( i1IOooOOOOoo ) )
   continue
   if 9 - 9: Ii1I . i1IIi % iIii1I11I1II1
   if 72 - 72: i11iIiiIii + OOooOOo . I1Ii111 + Ii1I + OOooOOo
  OoO000O0ooOO = lisp_igmp_record_types [ i1IOooOOOOoo ]
  OoOOOo = socket . ntohs ( OoOOOo )
  iiI . address = socket . ntohl ( I1IIIi )
  iiiii1I1III1 = iiI . print_address_no_iid ( )
  if 81 - 81: IiII % oO0o + IiII * OoO0O00 % I1IiiI
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( OoO000O0ooOO , iiiii1I1III1 , OoOOOo ) )
  if 72 - 72: OoooooooOO
  if 40 - 40: IiII + o0oOOo0O0Ooo + O0 . oO0o * iIii1I11I1II1 / OOooOOo
  if 60 - 60: iII111i - I11i
  if 12 - 12: o0oOOo0O0Ooo % i1IIi
  if 29 - 29: OOooOOo . OoooooooOO . iII111i % i1IIi + i11iIiiIii
  if 9 - 9: IiII
  if 29 - 29: I11i * II111iiii / I1ii11iIi11i
  IiI1i1 = False
  if ( i1IOooOOOOoo in ( 1 , 5 ) ) : IiI1i1 = True
  if ( i1IOooOOOOoo in ( 2 , 4 ) and OoOOOo == 0 ) : IiI1i1 = True
  iI1iIi = "join" if ( IiI1i1 ) else "leave"
  if 12 - 12: II111iiii % Oo0Ooo / Oo0Ooo . i1IIi % Ii1I
  if 21 - 21: II111iiii - o0oOOo0O0Ooo * OoO0O00 . OOooOOo
  if 65 - 65: o0oOOo0O0Ooo + I1IiiI
  if 21 - 21: I1Ii111
  if ( iiiii1I1III1 . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 74 - 74: iII111i
   if 51 - 51: O0 . II111iiii - OoooooooOO + ooOoO0o - o0oOOo0O0Ooo
   if 86 - 86: OOooOOo % i11iIiiIii / OoOoOO00
   if 72 - 72: I1IiiI . oO0o
   if 76 - 76: Ii1I - Oo0Ooo * II111iiii
   if 17 - 17: I1Ii111 * O0
   if 8 - 8: i11iIiiIii / OoO0O00 / OOooOOo
   if 26 - 26: I1ii11iIi11i . Ii1I - iIii1I11I1II1 . Ii1I / Ii1I % I11i
  if ( OoOOOo == 0 ) :
   ii11iiI . append ( [ None , iiiii1I1III1 , IiI1i1 ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( iI1iIi , False ) ,
 bold ( iiiii1I1III1 , False ) ) )
   if 56 - 56: OOooOOo . I11i + O0 * oO0o - i11iIiiIii / i11iIiiIii
   if 73 - 73: I1ii11iIi11i
   if 59 - 59: iII111i % iIii1I11I1II1 * OoOoOO00
   if 41 - 41: i1IIi * IiII - i11iIiiIii / O0 + Oo0Ooo + ooOoO0o
   if 94 - 94: OoO0O00 . O0 + iIii1I11I1II1 . oO0o % oO0o
  for IiIii1Ii in range ( OoOOOo ) :
   if ( len ( I11IiII11iI ) < IIiIi11 ) : return
   I1IIIi = struct . unpack ( i1111iiiIIiIiIIii1 , I11IiII11iI [ : IIiIi11 ] ) [ 0 ]
   II11IIII1 . address = socket . ntohl ( I1IIIi )
   iIiII11iI1II1 = II11IIII1 . print_address_no_iid ( )
   ii11iiI . append ( [ iIiII11iI1II1 , iiiii1I1III1 , IiI1i1 ] )
   lprint ( "{} ({}, {})" . format ( iI1iIi ,
 green ( iIiII11iI1II1 , False ) , bold ( iiiii1I1III1 , False ) ) )
   I11IiII11iI = I11IiII11iI [ IIiIi11 : : ]
   if 1 - 1: OoOoOO00 - i11iIiiIii . Ii1I * i1IIi
   if 4 - 4: OoooooooOO - OoOoOO00
   if 96 - 96: I1ii11iIi11i
   if 72 - 72: ooOoO0o - I1Ii111 - iIii1I11I1II1 . I1IiiI
   if 77 - 77: Oo0Ooo * OoO0O00
   if 67 - 67: OoOoOO00 . I1Ii111 / I1IiiI * II111iiii
   if 45 - 45: I1ii11iIi11i * o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo
   if 58 - 58: OOooOOo + O0
 return ( ii11iiI )
 if 19 - 19: o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * OOooOOo - Ii1I * OoOoOO00 % OoO0O00 * O0
 if 70 - 70: I1IiiI
 if 17 - 17: I11i % OOooOOo - i11iIiiIii . OoooooooOO % OoO0O00 + OoO0O00
 if 24 - 24: Ii1I . OOooOOo . IiII / Oo0Ooo . Oo0Ooo . II111iiii
 if 63 - 63: ooOoO0o . I11i
 if 39 - 39: II111iiii % oO0o % I1IiiI - iIii1I11I1II1 / I1IiiI
 if 94 - 94: iII111i + oO0o
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 43 - 43: iIii1I11I1II1 + iIii1I11I1II1
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 8 - 8: iIii1I11I1II1
 if 30 - 30: OOooOOo - I1ii11iIi11i * iIii1I11I1II1 + Oo0Ooo
 if 25 - 25: IiII
 if 78 - 78: OoOoOO00 * iIii1I11I1II1 * ooOoO0o - OoooooooOO - IiII
 if 40 - 40: OoO0O00 . i11iIiiIii + ooOoO0o
 if 30 - 30: OOooOOo . OoO0O00 % iII111i - OoO0O00 % i11iIiiIii
 i1iIiIi = True
 I111I1iI1 = lisp_map_cache . lookup_cache ( seid , True )
 if ( I111I1iI1 and len ( I111I1iI1 . rloc_set ) != 0 ) :
  I111I1iI1 . last_refresh_time = lisp_get_timestamp ( )
  if 51 - 51: II111iiii . IiII
  o0oOoOOoooOOOo0 = I111I1iI1 . rloc_set [ 0 ]
  oOoOOooO = o0oOoOOoooOOOo0 . rloc
  OooOOOOO0OOO = o0oOoOOoooOOOo0 . translated_port
  i1iIiIi = ( oOoOOooO . is_exact_match ( rloc ) == False or
 OooOOOOO0OOO != encap_port )
  if 75 - 75: o0oOOo0O0Ooo + i11iIiiIii % I1ii11iIi11i
  if ( i1iIiIi ) :
   I1i = green ( seid . print_address ( ) , False )
   OOoooo = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( I1i , OOoooo ) )
   o0oOoOOoooOOOo0 . delete_from_rloc_probe_list ( I111I1iI1 . eid , I111I1iI1 . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 45 - 45: I1Ii111 % Ii1I . ooOoO0o
 else :
  I111I1iI1 = lisp_mapping ( "" , "" , [ ] )
  I111I1iI1 . eid . copy_address ( seid )
  I111I1iI1 . mapping_source . copy_address ( rloc )
  I111I1iI1 . map_cache_ttl = LISP_GLEAN_TTL
  I111I1iI1 . gleaned = True
  I1i = green ( seid . print_address ( ) , False )
  OOoooo = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( I1i , OOoooo ) )
  I111I1iI1 . add_cache ( )
  if 99 - 99: I11i - OoOoOO00 % I11i / i1IIi
  if 55 - 55: o0oOOo0O0Ooo / ooOoO0o % I1IiiI / I1Ii111
  if 30 - 30: I11i % OoOoOO00 * O0
  if 32 - 32: iII111i - Oo0Ooo / Oo0Ooo + o0oOOo0O0Ooo + Ii1I + IiII
  if 100 - 100: Oo0Ooo + o0oOOo0O0Ooo % Oo0Ooo
 if ( i1iIiIi ) :
  O0O0OOo0O = lisp_rloc ( )
  O0O0OOo0O . store_translated_rloc ( rloc , encap_port )
  O0O0OOo0O . add_to_rloc_probe_list ( I111I1iI1 . eid , I111I1iI1 . group )
  O0O0OOo0O . priority = 253
  O0O0OOo0O . mpriority = 255
  IIiii11iiI111 = [ O0O0OOo0O ]
  I111I1iI1 . rloc_set = IIiii11iiI111
  I111I1iI1 . build_best_rloc_set ( )
  if 73 - 73: o0oOOo0O0Ooo + Ii1I
  if 62 - 62: OOooOOo
  if 91 - 91: iII111i . Ii1I - OoooooooOO / Ii1I / II111iiii - O0
  if 67 - 67: oO0o * i11iIiiIii / I1ii11iIi11i . I11i % OOooOOo
  if 75 - 75: ooOoO0o - OOooOOo
 if ( igmp == None ) : return
 if 97 - 97: i11iIiiIii / I11i % II111iiii
 if 20 - 20: I1Ii111 + OoooooooOO . o0oOOo0O0Ooo - ooOoO0o
 if 61 - 61: i11iIiiIii + OoooooooOO
 if 7 - 7: I1IiiI * OoO0O00 * I1IiiI
 if 50 - 50: I1ii11iIi11i
 lisp_geid . instance_id = seid . instance_id
 if 88 - 88: IiII
 if 55 - 55: Oo0Ooo + OOooOOo + IiII
 if 55 - 55: O0 . I1Ii111 * I1ii11iIi11i * o0oOOo0O0Ooo - ooOoO0o
 if 17 - 17: OOooOOo
 if 66 - 66: O0 - i11iIiiIii * O0 / iII111i . I1Ii111 / IiII
 ooOoOOoO0OOo = lisp_process_igmp_packet ( igmp )
 if ( type ( ooOoOOoO0OOo ) == bool ) : return
 if 96 - 96: OoOoOO00 / i11iIiiIii - OoooooooOO / II111iiii * i1IIi
 for II11IIII1 , iiI , IiI1i1 in ooOoOOoO0OOo :
  if ( II11IIII1 != None ) : continue
  if 82 - 82: iII111i
  if 55 - 55: OoOoOO00 + I1ii11iIi11i % ooOoO0o % I1Ii111 . i1IIi % OOooOOo
  if 21 - 21: OoO0O00 / Ii1I . IiII
  if 35 - 35: i1IIi
  lisp_geid . store_address ( iiI )
  i1I , I1iIiiI1IIi1 , i1iIi1II1 = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( i1I == False ) : continue
  if 58 - 58: Ii1I - IiII / ooOoO0o % o0oOOo0O0Ooo + I1ii11iIi11i
  if ( IiI1i1 ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
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
   if 91 - 91: I11i - iII111i
def lisp_is_json_telemetry ( json_string ) :
 try :
  ooo0OOoO = json . loads ( json_string )
  if ( type ( ooo0OOoO ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 35 - 35: I1IiiI * I11i + I11i
  if 67 - 67: I1ii11iIi11i - I1IiiI + Ii1I * Ii1I + Oo0Ooo
 if ( "type" not in ooo0OOoO ) : return ( None )
 if ( "sub-type" not in ooo0OOoO ) : return ( None )
 if ( ooo0OOoO [ "type" ] != "telemetry" ) : return ( None )
 if ( ooo0OOoO [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( ooo0OOoO )
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
 if 26 - 26: I1IiiI % OOooOOo * OoOoOO00
 if 14 - 14: I11i * Oo0Ooo . I1Ii111 * Ii1I . i11iIiiIii * I1ii11iIi11i
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 ooo0OOoO = lisp_is_json_telemetry ( json_string )
 if ( ooo0OOoO == None ) : return ( json_string )
 if 11 - 11: oO0o + oO0o + o0oOOo0O0Ooo / iIii1I11I1II1 / I11i
 if ( ooo0OOoO [ "itr-in" ] == "?" ) : ooo0OOoO [ "itr-in" ] = ii
 if ( ooo0OOoO [ "itr-out" ] == "?" ) : ooo0OOoO [ "itr-out" ] = io
 if ( ooo0OOoO [ "etr-in" ] == "?" ) : ooo0OOoO [ "etr-in" ] = ei
 if ( ooo0OOoO [ "etr-out" ] == "?" ) : ooo0OOoO [ "etr-out" ] = eo
 json_string = json . dumps ( ooo0OOoO )
 return ( json_string )
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
def lisp_decode_telemetry ( json_string ) :
 ooo0OOoO = lisp_is_json_telemetry ( json_string )
 if ( ooo0OOoO == None ) : return ( { } )
 return ( ooo0OOoO )
 if 10 - 10: I11i . OoO0O00 / O0 / oO0o / o0oOOo0O0Ooo / ooOoO0o
 if 30 - 30: Oo0Ooo
 if 93 - 93: II111iiii - I1IiiI
 if 80 - 80: I11i . o0oOOo0O0Ooo % IiII - OoOoOO00 % OOooOOo / OoooooooOO
 if 57 - 57: OoooooooOO % o0oOOo0O0Ooo - iIii1I11I1II1 . OoooooooOO
 if 42 - 42: o0oOOo0O0Ooo % OoooooooOO * OoO0O00 - o0oOOo0O0Ooo
 if 83 - 83: i1IIi . i1IIi * ooOoO0o
 if 26 - 26: I1IiiI - IiII
 if 99 - 99: IiII * iII111i + i1IIi * I1Ii111
def lisp_telemetry_configured ( ) :
 if ( "telemetry" not in lisp_json_list ) : return ( None )
 if 88 - 88: o0oOOo0O0Ooo . IiII - Oo0Ooo
 o00O = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( o00O ) == None ) : return ( None )
 if 24 - 24: Oo0Ooo - OOooOOo / Ii1I / II111iiii . Oo0Ooo - Ii1I
 return ( o00O )
 if 5 - 5: IiII
 if 66 - 66: OoO0O00 . I1ii11iIi11i . OoooooooOO
 if 21 - 21: I11i / IiII + i1IIi . Oo0Ooo % II111iiii
 if 8 - 8: oO0o / iIii1I11I1II1 + OoooooooOO
 if 11 - 11: OOooOOo . O0 + IiII . i1IIi
 if 81 - 81: OoO0O00 - I11i - OoO0O00 + oO0o
 if 20 - 20: OoooooooOO - Oo0Ooo + I1Ii111 + OoooooooOO
def lisp_mr_or_pubsub ( action ) :
 return ( action in [ LISP_SEND_MAP_REQUEST_ACTION , LISP_SEND_PUBSUB_ACTION ] )
 if 66 - 66: I1ii11iIi11i / oO0o % IiII + II111iiii % iII111i
 if 54 - 54: iII111i * O0 / I1IiiI % Ii1I
 if 12 - 12: IiII % I1IiiI - o0oOOo0O0Ooo - I1ii11iIi11i - i11iIiiIii * i1IIi
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
