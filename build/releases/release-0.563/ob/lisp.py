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
 o00oo = lisp_format_packet ( packet [ 0 : 12 ] ) . decode ( )
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
 for oOOOo0o in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( oOOOo0o [ "peer" ] == "127.0.0.1" ) : continue
  return ( oOOOo0o [ "peer" ] )
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
 O0o0oo0oOO0oO = mac_str . split ( "/" )
 if ( len ( O0o0oo0oOO0oO ) == 2 ) : mac_str = O0o0oo0oOO0oO [ 0 ]
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
  O0o0oo0oOO0oO = I1iI1i11IiI11 [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  O0o0oo0oOO0oO = O0o0oo0oOO0oO . replace ( ":" , "" )
  if 32 - 32: O0
  if 73 - 73: O0 . I1ii11iIi11i % IiII + OoO0O00 * I11i - OoOoOO00
  if 52 - 52: OOooOOo * oO0o + I11i * I11i % i1IIi % I11i
  if 96 - 96: o0oOOo0O0Ooo * oO0o - OOooOOo * o0oOOo0O0Ooo * i1IIi
  if 8 - 8: ooOoO0o - Oo0Ooo + iIii1I11I1II1 + i1IIi * Ii1I - iIii1I11I1II1
  if ( len ( O0o0oo0oOO0oO ) < 12 ) : continue
  if 30 - 30: I11i / I1ii11iIi11i
  if ( O0o0oo0oOO0oO not in lisp_mymacs ) : lisp_mymacs [ O0o0oo0oOO0oO ] = [ ]
  lisp_mymacs [ O0o0oo0oOO0oO ] . append ( OoO0 )
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
 oOOOo0o = ""
 ooOOo = lisp_is_macos ( )
 if ( ooOOo ) :
  O0O0 = getoutput ( "ifconfig {} | egrep 'inet '" . format ( OoO0 ) )
  if ( O0O0 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  i1iii1IiiiI1i1 = 'ip addr show | egrep "inet " | egrep "{}"' . format ( OoO0 )
  O0O0 = getoutput ( i1iii1IiiiI1i1 )
  if ( O0O0 == "" ) :
   i1iii1IiiiI1i1 = 'ip addr show | egrep "inet " | egrep "global lo"'
   O0O0 = getoutput ( i1iii1IiiiI1i1 )
   if 37 - 37: Oo0Ooo - i1IIi - IiII + I11i . iIii1I11I1II1
  if ( O0O0 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 59 - 59: OoooooooOO - I1Ii111 % o0oOOo0O0Ooo . I11i + i1IIi * I11i
  if 5 - 5: II111iiii - IiII
  if 86 - 86: IiII * I11i + O0 * I1Ii111 + i11iIiiIii - I1ii11iIi11i
  if 70 - 70: i11iIiiIii
  if 57 - 57: I11i % OOooOOo + ooOoO0o * Ii1I . Oo0Ooo
  if 78 - 78: OoooooooOO / i1IIi . OOooOOo
 oOOOo0o = ""
 O0O0 = O0O0 . split ( "\n" )
 if 88 - 88: I11i + I1IiiI - I11i / OoooooooOO - i11iIiiIii
 for i11 in O0O0 :
  OoOOOO = i11 . split ( ) [ 1 ]
  if ( ooOOo == False ) : OoOOOO = OoOOOO . split ( "/" ) [ 0 ]
  Ii1IiIIIi = lisp_address ( LISP_AFI_IPV4 , OoOOOO , 32 , 0 )
  return ( Ii1IiIIIi )
  if 71 - 71: OoO0O00 % I1IiiI - iII111i . iII111i
 return ( lisp_address ( LISP_AFI_IPV4 , oOOOo0o , 32 , 0 ) )
 if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
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
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 89 - 89: OoooooooOO . iIii1I11I1II1 . Oo0Ooo * iIii1I11I1II1 - I1Ii111
 if 92 - 92: OoooooooOO - I1ii11iIi11i - OoooooooOO % I1IiiI % I1IiiI % iIii1I11I1II1
 if 92 - 92: iII111i * O0 % I1Ii111 . iIii1I11I1II1
 if 66 - 66: I11i + Ii1I
 if 48 - 48: I1ii11iIi11i
 if 96 - 96: ooOoO0o . OoooooooOO
 if 39 - 39: OOooOOo + OoO0O00
 if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
 if 71 - 71: ooOoO0o . i11iIiiIii
 OoO000oo000o0 = None
 OOOooo0OooOoO = 1
 i1Ii1I1Ii11iI = os . getenv ( "LISP_ADDR_SELECT" )
 if ( i1Ii1I1Ii11iI != None and i1Ii1I1Ii11iI != "" ) :
  i1Ii1I1Ii11iI = i1Ii1I1Ii11iI . split ( ":" )
  if ( len ( i1Ii1I1Ii11iI ) == 2 ) :
   OoO000oo000o0 = i1Ii1I1Ii11iI [ 0 ]
   OOOooo0OooOoO = i1Ii1I1Ii11iI [ 1 ]
  else :
   if ( i1Ii1I1Ii11iI [ 0 ] . isdigit ( ) ) :
    OOOooo0OooOoO = i1Ii1I1Ii11iI [ 0 ]
   else :
    OoO000oo000o0 = i1Ii1I1Ii11iI [ 0 ]
    if 8 - 8: I1ii11iIi11i
    if 82 - 82: OoooooooOO
  OOOooo0OooOoO = 1 if ( OOOooo0OooOoO == "" ) else int ( OOOooo0OooOoO )
  if 75 - 75: II111iiii % I1IiiI + OOooOOo % OoooooooOO / IiII
  if 4 - 4: i11iIiiIii - OOooOOo % I1ii11iIi11i * I1Ii111 % o0oOOo0O0Ooo
 o0O = [ None , None , None ]
 oOoo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 O0OoO0o0Oooo = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 Ooo0oOOoo0O = None
 if 57 - 57: I1IiiI . i11iIiiIii * II111iiii + OoooooooOO + Ii1I
 for OoO0 in netifaces . interfaces ( ) :
  if ( OoO000oo000o0 != None and OoO000oo000o0 != OoO0 ) : continue
  O00Oo = netifaces . ifaddresses ( OoO0 )
  if ( O00Oo == { } ) : continue
  if 73 - 73: O0 % I11i + iII111i . I1ii11iIi11i . I1ii11iIi11i + IiII
  if 30 - 30: OoOoOO00
  if 89 - 89: I11i
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  Ooo0oOOoo0O = lisp_get_interface_instance_id ( OoO0 , None )
  if 79 - 79: IiII + IiII + Ii1I
  if 39 - 39: O0 - OoooooooOO
  if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
  if 79 - 79: O0
  if ( netifaces . AF_INET in O00Oo ) :
   ooooo0Oo0 = O00Oo [ netifaces . AF_INET ]
   IiI = 0
   for oOOOo0o in ooooo0Oo0 :
    oOoo . store_address ( oOOOo0o [ "addr" ] )
    if ( oOoo . is_ipv4_loopback ( ) ) : continue
    if ( oOoo . is_ipv4_link_local ( ) ) : continue
    if ( oOoo . address == 0 ) : continue
    IiI += 1
    oOoo . instance_id = Ooo0oOOoo0O
    if ( OoO000oo000o0 == None and
 lisp_db_for_lookups . lookup_cache ( oOoo , False ) ) : continue
    o0O [ 0 ] = oOoo
    if ( IiI == OOOooo0OooOoO ) : break
    if 9 - 9: II111iiii % OoOoOO00
    if 26 - 26: iIii1I11I1II1 - I1ii11iIi11i . IiII . IiII + iIii1I11I1II1 * Oo0Ooo
  if ( netifaces . AF_INET6 in O00Oo ) :
   o0I1IIIi11ii11 = O00Oo [ netifaces . AF_INET6 ]
   IiI = 0
   for oOOOo0o in o0I1IIIi11ii11 :
    Oo0o = oOOOo0o [ "addr" ]
    O0OoO0o0Oooo . store_address ( Oo0o )
    if ( O0OoO0o0Oooo . is_ipv6_string_link_local ( Oo0o ) ) : continue
    if ( O0OoO0o0Oooo . is_ipv6_loopback ( ) ) : continue
    IiI += 1
    O0OoO0o0Oooo . instance_id = Ooo0oOOoo0O
    if ( OoO000oo000o0 == None and
 lisp_db_for_lookups . lookup_cache ( O0OoO0o0Oooo , False ) ) : continue
    o0O [ 1 ] = O0OoO0o0Oooo
    if ( IiI == OOOooo0OooOoO ) : break
    if 85 - 85: OOooOOo + II111iiii - OOooOOo * oO0o - i1IIi % iII111i
    if 1 - 1: OoooooooOO / O0 + OoOoOO00 + OoOoOO00 . I1Ii111 - OoOoOO00
    if 9 - 9: I1Ii111 * OoooooooOO % I1IiiI / OoOoOO00 * I11i
    if 48 - 48: OoooooooOO . OoOoOO00
    if 65 - 65: oO0o . Oo0Ooo
    if 94 - 94: OoOoOO00 + IiII . ooOoO0o
  if ( o0O [ 0 ] == None ) : continue
  if 69 - 69: O0 - O0
  o0O [ 2 ] = OoO0
  break
  if 41 - 41: IiII % o0oOOo0O0Ooo
  if 67 - 67: O0 % I1Ii111
 III = o0O [ 0 ] . print_address_no_iid ( ) if o0O [ 0 ] else "none"
 I1I = o0O [ 1 ] . print_address_no_iid ( ) if o0O [ 1 ] else "none"
 OoO0 = o0O [ 2 ] if o0O [ 2 ] else "none"
 if 70 - 70: Ii1I . O0 - OOooOOo
 OoO000oo000o0 = " (user selected)" if OoO000oo000o0 != None else ""
 if 62 - 62: I1Ii111 * I11i
 III = red ( III , False )
 I1I = red ( I1I , False )
 OoO0 = bold ( OoO0 , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( III , I1I , OoO0 , OoO000oo000o0 , Ooo0oOOoo0O ) )
 if 74 - 74: OoOoOO00 . iIii1I11I1II1
 if 87 - 87: ooOoO0o
 lisp_myrlocs = o0O
 return ( ( o0O [ 0 ] != None ) )
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
   for oOOOo0o in iIiiI11II11i [ netifaces . AF_INET ] :
    OoOOOO = oOOOo0o [ "addr" ]
    if ( OoOOOO . find ( "127.0.0.1" ) != - 1 ) : continue
    o00oOoo0o00 . append ( OoOOOO )
    if 58 - 58: oO0o
    if 98 - 98: o0oOOo0O0Ooo * OoO0O00
  if ( netifaces . AF_INET6 in iIiiI11II11i ) :
   for oOOOo0o in iIiiI11II11i [ netifaces . AF_INET6 ] :
    OoOOOO = oOOOo0o [ "addr" ]
    if ( OoOOOO == "::1" ) : continue
    if ( OoOOOO [ 0 : 5 ] == "fe80:" ) : continue
    o00oOoo0o00 . append ( OoOOOO )
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
 for i11 in Ii11I1I11II :
  if ( i11 [ 0 ] == "#" ) : continue
  IIiiiI = i11 . split ( "rle-address = " ) [ 1 ]
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
  iI = len ( packet )
  if ( ( iI % 16 ) != 0 ) :
   o00ooO000Oo00 = ( old_div ( iI , 16 ) + 1 ) * 16
   packet = packet . ljust ( o00ooO000Oo00 )
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
  i1 = lisp_get_timestamp ( )
  iIIiI = None
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   O0O0O0OO00oo = chacha . ChaCha ( key . encrypt_key , iI1ii ) . encrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   I11IIIIiI1 = binascii . unhexlify ( key . encrypt_key )
   try :
    o0oOOO = AES . new ( I11IIIIiI1 , AES . MODE_GCM , iI1ii )
    O0O0O0OO00oo = o0oOOO . encrypt
    iIIiI = o0oOOO . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 62 - 62: Ii1I - oO0o % iIii1I11I1II1
  else :
   I11IIIIiI1 = binascii . unhexlify ( key . encrypt_key )
   O0O0O0OO00oo = AES . new ( I11IIIIiI1 , AES . MODE_CBC , iI1ii ) . encrypt
   if 57 - 57: OoooooooOO / OoOoOO00
   if 44 - 44: OoOoOO00 * i1IIi * O0
  oooo0o0oO = O0O0O0OO00oo ( OO0Oo00OO0oo )
  if 15 - 15: iIii1I11I1II1 . OOooOOo . I1ii11iIi11i * i11iIiiIii
  if ( oooo0o0oO == None ) : return ( [ self . packet , False ] )
  i1 = int ( str ( time . time ( ) - i1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 72 - 72: I11i
  if 26 - 26: IiII % Oo0Ooo
  if 72 - 72: O0 + o0oOOo0O0Ooo + I1IiiI / Oo0Ooo
  if 83 - 83: IiII - I1IiiI . Ii1I
  if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
  if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
  if ( iIIiI != None ) : oooo0o0oO += iIIiI ( )
  if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
  if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
  if 25 - 25: Oo0Ooo % OoOoOO00
  if 75 - 75: i1IIi
  if 74 - 74: Oo0Ooo + I1Ii111 - oO0o - OoO0O00 + iII111i - iIii1I11I1II1
  self . lisp_header . key_id ( key . key_id )
  oOoOO0O00o = self . lisp_header . encode ( )
  if 54 - 54: I1ii11iIi11i + II111iiii . I1IiiI / OoO0O00 . ooOoO0o
  O00oooO00oo = key . do_icv ( oOoOO0O00o + iI1ii + oooo0o0oO , iI1ii )
  if 44 - 44: iIii1I11I1II1 * I1Ii111 * Oo0Ooo * I1ii11iIi11i + I11i
  III1i1IIII1i = 4 if ( key . do_poly ) else 8
  if 48 - 48: OoooooooOO
  Oo0OOOOOOO0oo = bold ( "Encrypt" , False )
  II1Iiiii111i = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  OooooO0o0 = "poly" if key . do_poly else "sha256"
  OooooO0o0 = bold ( OooooO0o0 , False )
  OOoo00o00O0o0 = "ICV({}): 0x{}...{}" . format ( OooooO0o0 , O00oooO00oo [ 0 : III1i1IIII1i ] , O00oooO00oo [ - III1i1IIII1i : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( Oo0OOOOOOO0oo , key . key_id , addr_str , OOoo00o00O0o0 , II1Iiiii111i , i1 ) )
  if 3 - 3: I1ii11iIi11i * I11i
  if 53 - 53: iIii1I11I1II1 / iII111i % OoO0O00 + IiII / ooOoO0o
  O00oooO00oo = int ( O00oooO00oo , 16 )
  if ( key . do_poly ) :
   oo00oO = byte_swap_64 ( ( O00oooO00oo >> 64 ) & LISP_8_64_MASK )
   I11i1I11 = byte_swap_64 ( O00oooO00oo & LISP_8_64_MASK )
   O00oooO00oo = struct . pack ( "QQ" , oo00oO , I11i1I11 )
  else :
   oo00oO = byte_swap_64 ( ( O00oooO00oo >> 96 ) & LISP_8_64_MASK )
   I11i1I11 = byte_swap_64 ( ( O00oooO00oo >> 32 ) & LISP_8_64_MASK )
   I1iIiiI11 = socket . htonl ( O00oooO00oo & 0xffffffff )
   O00oooO00oo = struct . pack ( "QQI" , oo00oO , I11i1I11 , I1iIiiI11 )
   if 27 - 27: iII111i
   if 74 - 74: IiII / ooOoO0o
  return ( [ iI1ii + oooo0o0oO + O00oooO00oo , True ] )
  if 86 - 86: O0 . i1IIi - OoO0O00 / Oo0Ooo / I1ii11iIi11i
  if 64 - 64: OoooooooOO - i1IIi / II111iiii
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 49 - 49: Oo0Ooo + O0 + IiII . II111iiii % ooOoO0o
  if 33 - 33: OoOoOO00 . iIii1I11I1II1 / I11i % Ii1I
  if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
  if 27 - 27: OoO0O00 + Oo0Ooo
  if 92 - 92: I1IiiI % iII111i
  if 31 - 31: OoooooooOO - oO0o / I1Ii111
  if ( key . do_poly ) :
   oo00oO , I11i1I11 = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   oo00o000O = byte_swap_64 ( oo00oO ) << 64
   oo00o000O |= byte_swap_64 ( I11i1I11 )
   oo00o000O = lisp_hex_string ( oo00o000O ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   III1i1IIII1i = 4
   OooO0o = bold ( "poly" , False )
  else :
   oo00oO , I11i1I11 , I1iIiiI11 = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   oo00o000O = byte_swap_64 ( oo00oO ) << 96
   oo00o000O |= byte_swap_64 ( I11i1I11 ) << 32
   oo00o000O |= socket . htonl ( I1iIiiI11 )
   oo00o000O = lisp_hex_string ( oo00o000O ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   III1i1IIII1i = 8
   OooO0o = bold ( "sha" , False )
   if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
  oOoOO0O00o = self . lisp_header . encode ( )
  if 31 - 31: i1IIi % II111iiii
  if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
  if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
  if 3 - 3: II111iiii / OOooOOo
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   i1I = 8
   II1Iiiii111i = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   i1I = 12
   II1Iiiii111i = bold ( "aes-gcm" , False )
  else :
   i1I = 16
   II1Iiiii111i = bold ( "aes-cbc" , False )
   if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
  iI1ii = packet [ 0 : i1I ]
  if 24 - 24: oO0o - iII111i / ooOoO0o
  if 10 - 10: OoOoOO00 * i1IIi
  if 15 - 15: I11i + i1IIi - II111iiii % I1IiiI
  if 34 - 34: I1IiiI
  o0OoOo0O00 = key . do_icv ( oOoOO0O00o + packet , iI1ii )
  if 9 - 9: OOooOOo
  I1iII = "0x{}...{}" . format ( oo00o000O [ 0 : III1i1IIII1i ] , oo00o000O [ - III1i1IIII1i : : ] )
  I1IIiIi = "0x{}...{}" . format ( o0OoOo0O00 [ 0 : III1i1IIII1i ] , o0OoOo0O00 [ - III1i1IIII1i : : ] )
  if 93 - 93: oO0o - OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  if ( o0OoOo0O00 != oo00o000O ) :
   self . packet_error = "ICV-error"
   o0000oO = II1Iiiii111i + "/" + OooO0o
   ooo0oo = bold ( "ICV failed ({})" . format ( o0000oO ) , False )
   OOoo00o00O0o0 = "packet-ICV {} != computed-ICV {}" . format ( I1iII , I1IIiIi )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( ooo0oo , red ( addr_str , False ) ,
   # I1IiiI - OoOoOO00 . Oo0Ooo . i1IIi - oO0o
 self . udp_sport , key . key_id , OOoo00o00O0o0 ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 93 - 93: IiII % I1ii11iIi11i
   if 31 - 31: II111iiii + OOooOOo - OoooooooOO . I11i
   if 28 - 28: Ii1I . I1ii11iIi11i
   if 77 - 77: I1ii11iIi11i % II111iiii
   if 81 - 81: OoOoOO00 % Ii1I / O0 * iIii1I11I1II1 % IiII . I1IiiI
   if 90 - 90: o0oOOo0O0Ooo
   lisp_retry_decap_keys ( addr_str , oOoOO0O00o + packet , iI1ii , oo00o000O )
   return ( [ None , False ] )
   if 44 - 44: o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo + OoOoOO00
   if 32 - 32: IiII - ooOoO0o * iII111i * I11i
   if 84 - 84: Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
   if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
   if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
  packet = packet [ i1I : : ]
  if 1 - 1: Oo0Ooo . II111iiii
  if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
  if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
  if 4 - 4: IiII
  i1 = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   IiI1iIiiI1iI = chacha . ChaCha ( key . encrypt_key , iI1ii ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   I11IIIIiI1 = binascii . unhexlify ( key . encrypt_key )
   try :
    IiI1iIiiI1iI = AES . new ( I11IIIIiI1 , AES . MODE_GCM , iI1ii ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 2 - 2: I1IiiI * I1Ii111 % I1Ii111 - I1Ii111 - iII111i + OOooOOo
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 7 - 7: I11i - OoO0O00 . OoooooooOO / OoooooooOO - I11i
   I11IIIIiI1 = binascii . unhexlify ( key . encrypt_key )
   IiI1iIiiI1iI = AES . new ( I11IIIIiI1 , AES . MODE_CBC , iI1ii ) . decrypt
   if 84 - 84: II111iiii
   if 36 - 36: OOooOOo - OoOoOO00 - iIii1I11I1II1
  II11 = IiI1iIiiI1iI ( packet )
  i1 = int ( str ( time . time ( ) - i1 ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 79 - 79: O0 + I11i
  if 25 - 25: I1Ii111 - Ii1I / O0 . OoooooooOO % I1IiiI . i1IIi
  if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
  if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
  Oo0OOOOOOO0oo = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  OooooO0o0 = "poly" if key . do_poly else "sha256"
  OooooO0o0 = bold ( OooooO0o0 , False )
  OOoo00o00O0o0 = "ICV({}): {}" . format ( OooooO0o0 , I1iII )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( Oo0OOOOOOO0oo , key . key_id , addr_str , OOoo00o00O0o0 , II1Iiiii111i , i1 ) )
  if 80 - 80: Ii1I
  if 26 - 26: iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
  if 59 - 59: I1ii11iIi11i + I11i . oO0o
  if 87 - 87: OoO0O00
  if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  self . packet = self . packet [ 0 : header_length ]
  return ( [ II11 , True ] )
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
  if 46 - 46: i11iIiiIii
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  Iiiii = 1000
  if 25 - 25: Oo0Ooo * I1IiiI + OOooOOo + I1Ii111 % OOooOOo
  if 84 - 84: O0 % Ii1I . Ii1I . iII111i * I11i
  if 43 - 43: OoOoOO00 . I1ii11iIi11i % i1IIi
  if 61 - 61: I1IiiI + oO0o % I1Ii111 % iIii1I11I1II1 - OoooooooOO
  if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
  oOo00Oo0o00oo = [ ]
  IiI1ii1Ii = 0
  iI = len ( inner_packet )
  while ( IiI1ii1Ii < iI ) :
   oo0O00o0O0Oo = inner_packet [ IiI1ii1Ii : : ]
   if ( len ( oo0O00o0O0Oo ) > Iiiii ) : oo0O00o0O0Oo = oo0O00o0O0Oo [ 0 : Iiiii ]
   oOo00Oo0o00oo . append ( oo0O00o0O0Oo )
   IiI1ii1Ii += len ( oo0O00o0O0Oo )
   if 58 - 58: OoOoOO00 + OoO0O00 * Ii1I
   if 31 - 31: oO0o - iII111i
   if 46 - 46: I1IiiI + Oo0Ooo - Ii1I
   if 99 - 99: OOooOOo + I1IiiI . I1ii11iIi11i * OoooooooOO
   if 82 - 82: i11iIiiIii + iIii1I11I1II1 / Oo0Ooo + OOooOOo * II111iiii
   if 34 - 34: o0oOOo0O0Ooo % OoooooooOO
  iIIIi = [ ]
  IiI1ii1Ii = 0
  for oo0O00o0O0Oo in oOo00Oo0o00oo :
   if 74 - 74: O0 . I11i
   if 64 - 64: ooOoO0o / i1IIi % iII111i
   if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
   if 99 - 99: I1Ii111
   o0I1IiiiiI1i1I = IiI1ii1Ii if ( oo0O00o0O0Oo == oOo00Oo0o00oo [ - 1 ] ) else 0x2000 + IiI1ii1Ii
   o0I1IiiiiI1i1I = socket . htons ( o0I1IiiiiI1i1I )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , o0I1IiiiiI1i1I ) + outer_hdr [ 8 : : ]
   if 48 - 48: I11i + II111iiii % oO0o % OOooOOo * II111iiii
   if 41 - 41: OoO0O00
   if 13 - 13: ooOoO0o - I1IiiI
   if 23 - 23: I1IiiI
   i1IIiI1iII = socket . htons ( len ( oo0O00o0O0Oo ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , i1IIiI1iII ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   iIIIi . append ( outer_hdr + oo0O00o0O0Oo )
   IiI1ii1Ii += len ( oo0O00o0O0Oo ) / 8
   if 45 - 45: i1IIi % OOooOOo % II111iiii
  return ( iIIIi )
  if 4 - 4: oO0o * I1IiiI - ooOoO0o / II111iiii + OOooOOo / i11iIiiIii
  if 63 - 63: OoO0O00 + ooOoO0o
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 3 - 3: OoOoOO00 - I1Ii111 / oO0o . O0 * ooOoO0o / I1ii11iIi11i
  Ii1i1 = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( Ii1i1 < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 18 - 18: Ii1I
   return ( False )
   if 74 - 74: Ii1I + I1ii11iIi11i + I1IiiI
   if 37 - 37: IiII
   if 97 - 97: o0oOOo0O0Ooo / IiII + OoOoOO00 + OoO0O00 % I1Ii111
   if 18 - 18: I1IiiI - OoOoOO00
   if 18 - 18: OOooOOo + OoO0O00 * oO0o - oO0o . I1ii11iIi11i * I11i
   if 95 - 95: I1ii11iIi11i / OoOoOO00
   if 10 - 10: IiII % I1ii11iIi11i - IiII
   if 86 - 86: Oo0Ooo
   if 88 - 88: I1Ii111 * I1IiiI
   if 30 - 30: OoOoOO00 / oO0o / Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
   if 93 - 93: OoOoOO00
   if 97 - 97: i11iIiiIii
   if 68 - 68: IiII * OoO0O00 . I11i / Ii1I . o0oOOo0O0Ooo - i11iIiiIii
   if 49 - 49: Oo0Ooo / Ii1I % I11i + oO0o - OoO0O00
   if 13 - 13: II111iiii
  OoO = socket . htons ( 1400 )
  O0OO0ooO00 = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , OoO )
  O0OO0ooO00 += inner_packet [ 0 : 20 + 8 ]
  O0OO0ooO00 = lisp_icmp_checksum ( O0OO0ooO00 )
  if 34 - 34: i1IIi % oO0o . IiII . i1IIi + II111iiii / OoO0O00
  if 79 - 79: I1ii11iIi11i - iIii1I11I1II1 % i1IIi / Oo0Ooo + II111iiii
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
  o0OO00oo0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , o000o0o00Oo , 0 , 0 , 32 , 1 , 0 ) + O00oOoo00O + oOooo00OOO000
  o0OO00oo0O = lisp_ip_checksum ( o0OO00oo0O )
  o0OO00oo0O = self . fix_outer_header ( o0OO00oo0O )
  o0OO00oo0O += O0OO0ooO00
  IIi1IiiIi1III = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( IIi1IiiIi1III , OooOOooo ,
 lisp_format_packet ( o0OO00oo0O ) ) )
  if 19 - 19: i1IIi % I1IiiI - iIii1I11I1II1 - oO0o / I1ii11iIi11i
  try :
   lisp_icmp_raw_socket . sendto ( o0OO00oo0O , ( OooOOooo , 0 ) )
  except socket . error as I1i :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( I1i ) )
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
  iI = len ( OO0Oo00OO0oo )
  if ( iI <= 1500 ) : return ( [ OO0Oo00OO0oo ] , "Fragment-None" )
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
   iIIIi = self . fragment_outer ( i1iIi , oOO00OOOoO0o )
   return ( iIIIi , "Fragment-Outer" )
   if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
   if 36 - 36: OoOoOO00 . i11iIiiIii
   if 81 - 81: Oo0Ooo * iII111i * OoO0O00
   if 85 - 85: O0 * oO0o
   if 39 - 39: II111iiii * I1IiiI - iIii1I11I1II1
  Ii1o0OOOoo0000 = 56 if ( self . outer_version == 6 ) else 36
  i1iIi = OO0Oo00OO0oo [ 0 : Ii1o0OOOoo0000 ]
  IiIIii1i1i11iII = OO0Oo00OO0oo [ Ii1o0OOOoo0000 : Ii1o0OOOoo0000 + 20 ]
  oOO00OOOoO0o = OO0Oo00OO0oo [ Ii1o0OOOoo0000 + 20 : : ]
  if 53 - 53: i11iIiiIii
  if 90 - 90: ooOoO0o
  if 12 - 12: IiII * iIii1I11I1II1 - oO0o
  if 64 - 64: I1Ii111 + iIii1I11I1II1
  if 66 - 66: I11i - I11i + IiII
  i1i = struct . unpack ( "H" , IiIIii1i1i11iII [ 6 : 8 ] ) [ 0 ]
  i1i = socket . ntohs ( i1i )
  if ( i1i & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    i1iiiI = OO0Oo00OO0oo [ Ii1o0OOOoo0000 : : ]
    if ( self . send_icmp_too_big ( i1iiiI ) ) : return ( [ ] , None )
    if 33 - 33: o0oOOo0O0Ooo % IiII - iIii1I11I1II1 % OOooOOo + I1Ii111 - i11iIiiIii
   if ( lisp_ignore_df_bit ) :
    i1i &= ~ 0x4000
   else :
    ooi1 = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( ooi1 ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 17 - 17: OoOoOO00 - I1IiiI
    if 63 - 63: OoOoOO00 - oO0o / iIii1I11I1II1 - Ii1I / I1Ii111
    if 34 - 34: iII111i / o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
  IiI1ii1Ii = 0
  iI = len ( oOO00OOOoO0o )
  iIIIi = [ ]
  while ( IiI1ii1Ii < iI ) :
   iIIIi . append ( oOO00OOOoO0o [ IiI1ii1Ii : IiI1ii1Ii + 1400 ] )
   IiI1ii1Ii += 1400
   if 97 - 97: i1IIi
   if 46 - 46: I1ii11iIi11i
   if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
   if 23 - 23: I11i
   if 36 - 36: IiII . iII111i - i1IIi + I1Ii111
  oOo00Oo0o00oo = iIIIi
  iIIIi = [ ]
  ooOOo0O0o00o00 = True if i1i & 0x2000 else False
  i1i = ( i1i & 0x1fff ) * 8
  for oo0O00o0O0Oo in oOo00Oo0o00oo :
   if 90 - 90: I1Ii111 . II111iiii . I1ii11iIi11i
   if 32 - 32: ooOoO0o - OoO0O00 . iII111i . iII111i % i1IIi * Ii1I
   if 65 - 65: iII111i / ooOoO0o . II111iiii
   if 90 - 90: I11i
   o00oooo = old_div ( i1i , 8 )
   if ( ooOOo0O0o00o00 ) :
    o00oooo |= 0x2000
   elif ( oo0O00o0O0Oo != oOo00Oo0o00oo [ - 1 ] ) :
    o00oooo |= 0x2000
    if 63 - 63: II111iiii - I11i . OoOoOO00
   o00oooo = socket . htons ( o00oooo )
   IiIIii1i1i11iII = IiIIii1i1i11iII [ 0 : 6 ] + struct . pack ( "H" , o00oooo ) + IiIIii1i1i11iII [ 8 : : ]
   if 8 - 8: I1IiiI * ooOoO0o / IiII + OoOoOO00 . IiII - OOooOOo
   if 80 - 80: iIii1I11I1II1 / oO0o * Oo0Ooo - OOooOOo * iII111i
   if 97 - 97: IiII - I11i / II111iiii
   if 26 - 26: iII111i + O0 * iII111i . i1IIi
   if 50 - 50: iIii1I11I1II1 - I11i % iII111i - Oo0Ooo
   if 52 - 52: oO0o + Ii1I - I1ii11iIi11i * Ii1I . OOooOOo + I1Ii111
   iI = len ( oo0O00o0O0Oo )
   i1i += iI
   i1IIiI1iII = socket . htons ( iI + 20 )
   IiIIii1i1i11iII = IiIIii1i1i11iII [ 0 : 2 ] + struct . pack ( "H" , i1IIiI1iII ) + IiIIii1i1i11iII [ 4 : 10 ] + struct . pack ( "H" , 0 ) + IiIIii1i1i11iII [ 12 : : ]
   if 43 - 43: I1IiiI % IiII % I1ii11iIi11i
   IiIIii1i1i11iII = lisp_ip_checksum ( IiIIii1i1i11iII )
   OO00oOo0o00 = IiIIii1i1i11iII + oo0O00o0O0Oo
   if 73 - 73: iII111i / ooOoO0o + OoO0O00 / OoOoOO00 . II111iiii * Ii1I
   if 21 - 21: I1IiiI - I1IiiI + iII111i % I1IiiI * oO0o
   if 74 - 74: iII111i / I11i . I1IiiI - OoooooooOO + II111iiii + I11i
   if 36 - 36: Ii1I * I1IiiI * I1ii11iIi11i . I11i * I1ii11iIi11i
   if 76 - 76: OOooOOo + O0 / IiII - OoO0O00
   iI = len ( OO00oOo0o00 )
   if ( self . outer_version == 4 ) :
    i1IIiI1iII = iI + Ii1o0OOOoo0000
    iI += 16
    i1iIi = i1iIi [ 0 : 2 ] + struct . pack ( "H" , i1IIiI1iII ) + i1iIi [ 4 : : ]
    if 27 - 27: Oo0Ooo - iIii1I11I1II1 * iII111i * II111iiii * I1ii11iIi11i
    i1iIi = lisp_ip_checksum ( i1iIi )
    OO00oOo0o00 = i1iIi + OO00oOo0o00
    OO00oOo0o00 = self . fix_outer_header ( OO00oOo0o00 )
    if 9 - 9: i11iIiiIii + OOooOOo - OoOoOO00 / ooOoO0o % i1IIi / oO0o
    if 22 - 22: i1IIi
    if 3 - 3: OoO0O00 * I1ii11iIi11i - iII111i + I1ii11iIi11i
    if 63 - 63: I11i * ooOoO0o % II111iiii % I1Ii111 + I1IiiI * Oo0Ooo
    if 96 - 96: IiII
   oo00OOo0 = Ii1o0OOOoo0000 - 12
   i1IIiI1iII = socket . htons ( iI )
   OO00oOo0o00 = OO00oOo0o00 [ 0 : oo00OOo0 ] + struct . pack ( "H" , i1IIiI1iII ) + OO00oOo0o00 [ oo00OOo0 + 2 : : ]
   if 61 - 61: oO0o % ooOoO0o - I1ii11iIi11i + oO0o . OoOoOO00
   iIIIi . append ( OO00oOo0o00 )
   if 44 - 44: I1ii11iIi11i / O0 - IiII + OOooOOo . I11i . I1ii11iIi11i
  return ( iIIIi , "Fragment-Inner" )
  if 95 - 95: OoOoOO00 % I1Ii111 % i1IIi * o0oOOo0O0Ooo + OOooOOo
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
  iIIIi , ii1IIii = self . fragment ( )
  if 11 - 11: I1IiiI - Ii1I * OOooOOo % o0oOOo0O0Ooo
  for OO00oOo0o00 in iIIIi :
   if ( len ( iIIIi ) != 1 ) :
    self . packet = OO00oOo0o00
    self . print_packet ( ii1IIii , True )
    if 5 - 5: I1ii11iIi11i / o0oOOo0O0Ooo * I11i - i11iIiiIii - OoooooooOO / ooOoO0o
    if 6 - 6: I11i * OoooooooOO - OOooOOo + O0 * I1Ii111
   try : lisp_raw_socket . sendto ( OO00oOo0o00 , ( dest , 0 ) )
   except socket . error as I1i :
    lprint ( "socket.sendto() failed: {}" . format ( I1i ) )
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
  except socket . error as I1i :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( I1i ) )
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
  oO = 0
  i1oO00O = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   I1iI1Ii11 = struct . unpack ( "B" , OO0Oo00OO0oo [ 0 : 1 ] ) [ 0 ]
   self . outer_version = I1iI1Ii11 >> 4
   if ( self . outer_version == 4 ) :
    if 34 - 34: Ii1I * I1IiiI + I11i * OoOoOO00 - II111iiii
    if 92 - 92: OOooOOo . o0oOOo0O0Ooo / iII111i . iIii1I11I1II1 % Oo0Ooo . OoooooooOO
    if 81 - 81: i11iIiiIii * iII111i . oO0o * oO0o . IiII
    if 47 - 47: iIii1I11I1II1 % I11i . I11i / O0 . i11iIiiIii * Ii1I
    if 24 - 24: O0
    Ii1Iii1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 10 : 12 ] ) [ 0 ]
    OO0Oo00OO0oo = lisp_ip_checksum ( OO0Oo00OO0oo )
    OOOoOOo0o = struct . unpack ( "H" , OO0Oo00OO0oo [ 10 : 12 ] ) [ 0 ]
    if ( OOOoOOo0o != 0 ) :
     if ( Ii1Iii1 != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( OO0 )
       if 87 - 87: OoooooooOO
       if 1 - 1: iIii1I11I1II1 / o0oOOo0O0Ooo
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 98 - 98: O0 % I1IiiI / OoooooooOO * I1ii11iIi11i - oO0o
      if 51 - 51: iII111i + I11i
      if 54 - 54: II111iiii * O0 % I1IiiI . I11i
    O0ooO0O00oo0 = LISP_AFI_IPV4
    IiI1ii1Ii = 12
    self . outer_tos = struct . unpack ( "B" , OO0Oo00OO0oo [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , OO0Oo00OO0oo [ 8 : 9 ] ) [ 0 ]
    oO = 20
   elif ( self . outer_version == 6 ) :
    O0ooO0O00oo0 = LISP_AFI_IPV6
    IiI1ii1Ii = 8
    II1i1iI = struct . unpack ( "H" , OO0Oo00OO0oo [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( II1i1iI ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , OO0Oo00OO0oo [ 7 : 8 ] ) [ 0 ]
    oO = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( OO0 )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 5 - 5: OoOoOO00 + iII111i * ooOoO0o
    if 47 - 47: iIii1I11I1II1 + OoO0O00 % iIii1I11I1II1 . ooOoO0o / Oo0Ooo - i11iIiiIii
   self . outer_source . afi = O0ooO0O00oo0
   self . outer_dest . afi = O0ooO0O00oo0
   OOoo = self . outer_source . addr_length ( )
   if 40 - 40: I1IiiI
   self . outer_source . unpack_address ( OO0Oo00OO0oo [ IiI1ii1Ii : IiI1ii1Ii + OOoo ] )
   IiI1ii1Ii += OOoo
   self . outer_dest . unpack_address ( OO0Oo00OO0oo [ IiI1ii1Ii : IiI1ii1Ii + OOoo ] )
   OO0Oo00OO0oo = OO0Oo00OO0oo [ oO : : ]
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
   i1oO00O = self . lisp_header . get_instance_id ( )
   oO += 16
   if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
  if ( i1oO00O == 0xffffff ) : i1oO00O = 0
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
   OO0Oo00OO0oo , ooiIi11i1I11Ii = self . decrypt ( OO0Oo00OO0oo , oO , III11II111 ,
 Oo0o )
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
  I1iI1Ii11 = struct . unpack ( "B" , OO0Oo00OO0oo [ 0 : 1 ] ) [ 0 ]
  self . inner_version = I1iI1Ii11 >> 4
  if ( iii111 and self . inner_version == 4 and I1iI1Ii11 >= 0x45 ) :
   o0oOO00O000O0 = socket . ntohs ( struct . unpack ( "H" , OO0Oo00OO0oo [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , OO0Oo00OO0oo [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , OO0Oo00OO0oo [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , OO0Oo00OO0oo [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( OO0Oo00OO0oo [ 12 : 16 ] )
   self . inner_dest . unpack_address ( OO0Oo00OO0oo [ 16 : 20 ] )
   i1i = socket . ntohs ( struct . unpack ( "H" , OO0Oo00OO0oo [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( i1i & 0x2000 or i1i != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , OO0Oo00OO0oo [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , OO0Oo00OO0oo [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 89 - 89: o0oOOo0O0Ooo - II111iiii - I1Ii111 - OOooOOo % OoOoOO00 % I1IiiI
  elif ( iii111 and self . inner_version == 6 and I1iI1Ii11 >= 0x60 ) :
   o0oOO00O000O0 = socket . ntohs ( struct . unpack ( "H" , OO0Oo00OO0oo [ 4 : 6 ] ) [ 0 ] ) + 40
   II1i1iI = struct . unpack ( "H" , OO0Oo00OO0oo [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( II1i1iI ) >> 4 ) & 0xff
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
    if 84 - 84: o0oOOo0O0Ooo * i1IIi % Oo0Ooo
  elif ( o00O000oooOo ) :
   o0oOO00O000O0 = len ( OO0Oo00OO0oo )
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
   if 41 - 41: oO0o . iII111i + OoooooooOO * Ii1I . o0oOOo0O0Ooo
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( I1iI1Ii11 ) ) )
   if 11 - 11: O0
   OO0Oo00OO0oo = lisp_format_packet ( OO0Oo00OO0oo [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( OO0Oo00OO0oo ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 96 - 96: iII111i + o0oOOo0O0Ooo
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = i1oO00O
  self . inner_dest . instance_id = i1oO00O
  if 10 - 10: i11iIiiIii . OoooooooOO . O0 % ooOoO0o / OoO0O00
  if 36 - 36: I1IiiI % i1IIi + OoO0O00
  if 59 - 59: i11iIiiIii - i11iIiiIii + I1IiiI
  if 4 - 4: Oo0Ooo * O0 - oO0o % ooOoO0o + OoOoOO00
  if 3 - 3: OoOoOO00
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   oo000O0o = lisp_get_echo_nonce ( self . outer_source , None )
   if ( oo000O0o == None ) :
    o00oO = self . outer_source . print_address_no_iid ( )
    oo000O0o = lisp_echo_nonce ( o00oO )
    if 2 - 2: IiII
   OOO0O0O = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    oo000O0o . receive_request ( lisp_ipc_socket , OOO0O0O )
   elif ( oo000O0o . request_nonce_sent ) :
    oo000O0o . receive_echo ( lisp_ipc_socket , OOO0O0O )
    if 5 - 5: OoOoOO00 % II111iiii * II111iiii . I1IiiI
    if 11 - 11: iII111i
    if 20 - 20: Ii1I . I1Ii111 % Ii1I
    if 5 - 5: OOooOOo + iII111i
    if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
    if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
    if 11 - 11: I1ii11iIi11i / O0 + II111iiii
  if ( ooiIi11i1I11Ii ) : self . packet += OO0Oo00OO0oo [ : o0oOO00O000O0 ]
  if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
  if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
  if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
  if 2 - 2: Ii1I
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
  if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 81 - 81: iIii1I11I1II1
  if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
 def strip_outer_headers ( self ) :
  IiI1ii1Ii = 16
  IiI1ii1Ii += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ IiI1ii1Ii : : ]
  return ( self )
  if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
  if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
 def hash_ports ( self ) :
  OO0Oo00OO0oo = self . packet
  I1iI1Ii11 = self . inner_version
  iiIIII11iIii = 0
  if ( I1iI1Ii11 == 4 ) :
   O0000O = struct . unpack ( "B" , OO0Oo00OO0oo [ 9 : 10 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( O0000O )
   if ( O0000O in [ 6 , 17 ] ) :
    iiIIII11iIii = O0000O
    iiIIII11iIii += struct . unpack ( "I" , OO0Oo00OO0oo [ 20 : 24 ] ) [ 0 ]
    iiIIII11iIii = ( iiIIII11iIii >> 16 ) ^ ( iiIIII11iIii & 0xffff )
    if 67 - 67: O0 + I1IiiI + oO0o - II111iiii
    if 27 - 27: o0oOOo0O0Ooo / I1IiiI
  if ( I1iI1Ii11 == 6 ) :
   O0000O = struct . unpack ( "B" , OO0Oo00OO0oo [ 6 : 7 ] ) [ 0 ]
   if ( O0000O in [ 6 , 17 ] ) :
    iiIIII11iIii = O0000O
    iiIIII11iIii += struct . unpack ( "I" , OO0Oo00OO0oo [ 40 : 44 ] ) [ 0 ]
    iiIIII11iIii = ( iiIIII11iIii >> 16 ) ^ ( iiIIII11iIii & 0xffff )
    if 91 - 91: I1IiiI - iII111i / OoO0O00 - OoO0O00 / Ii1I - IiII
    if 14 - 14: OOooOOo / o0oOOo0O0Ooo + Ii1I / OoooooooOO - I11i
  return ( iiIIII11iIii )
  if 88 - 88: Ii1I / OoooooooOO % OoOoOO00 - i1IIi
  if 49 - 49: o0oOOo0O0Ooo - iIii1I11I1II1
 def hash_packet ( self ) :
  iiIIII11iIii = self . inner_source . address ^ self . inner_dest . address
  iiIIII11iIii += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   iiIIII11iIii = ( iiIIII11iIii >> 16 ) ^ ( iiIIII11iIii & 0xffff )
  elif ( self . inner_version == 6 ) :
   iiIIII11iIii = ( iiIIII11iIii >> 64 ) ^ ( iiIIII11iIii & 0xffffffffffffffff )
   iiIIII11iIii = ( iiIIII11iIii >> 32 ) ^ ( iiIIII11iIii & 0xffffffff )
   iiIIII11iIii = ( iiIIII11iIii >> 16 ) ^ ( iiIIII11iIii & 0xffff )
   if 61 - 61: iII111i * ooOoO0o
  self . udp_sport = 0xf000 | ( iiIIII11iIii & 0xfff )
  if 1 - 1: I1Ii111 * OoOoOO00
  if 100 - 100: I1ii11iIi11i / O0 / ooOoO0o + I1ii11iIi11i
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   iiI = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # iII111i . o0oOOo0O0Ooo / Ii1I / OOooOOo * i1IIi
 green ( iiI , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 90 - 90: I1IiiI . II111iiii - i1IIi + oO0o
   if 58 - 58: iII111i - OoooooooOO
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   o00o = "decap"
   o00o += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   o00o = s_or_r
   if ( o00o in [ "Send" , "Replicate" ] or o00o . find ( "Fragment" ) != - 1 ) :
    o00o = "encap"
    if 62 - 62: I11i . II111iiii * O0 + i1IIi * OoooooooOO + OoooooooOO
    if 23 - 23: i1IIi
  IIiii1I1I = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 62 - 62: II111iiii - OoOoOO00 * Ii1I
  if 53 - 53: oO0o + iII111i
  if 61 - 61: oO0o % Oo0Ooo % Ii1I
  if 21 - 21: i1IIi + II111iiii
  if 24 - 24: i11iIiiIii + i1IIi * OoOoOO00 % iII111i
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   i11 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 39 - 39: OoOoOO00 + I1Ii111 % O0
   i11 += bold ( "control-packet" , False ) + ": {} ..."
   if 26 - 26: ooOoO0o + OoOoOO00
   dprint ( i11 . format ( bold ( s_or_r , False ) , red ( IIiii1I1I , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   i11 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
   if 6 - 6: I1Ii111
   if 46 - 46: II111iiii * I1Ii111
   if 23 - 23: i1IIi - O0
  if ( self . lisp_header . k_bits ) :
   if ( o00o == "encap" ) : o00o = "encrypt/encap"
   if ( o00o == "decap" ) : o00o = "decap/decrypt"
   if 6 - 6: ooOoO0o % OoooooooOO * I1Ii111 - IiII
   if 24 - 24: I11i / iIii1I11I1II1 . OoooooooOO % OoOoOO00 . Ii1I
  iiI = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 73 - 73: I1Ii111
  dprint ( i11 . format ( bold ( s_or_r , False ) , red ( IIiii1I1I , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( iiI , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( o00o ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 25 - 25: IiII
  if 77 - 77: o0oOOo0O0Ooo . iIii1I11I1II1 . OoooooooOO . iIii1I11I1II1
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 87 - 87: II111iiii - OoooooooOO / i1IIi . Ii1I - Oo0Ooo . i11iIiiIii
  if 47 - 47: Oo0Ooo % OoO0O00 - ooOoO0o - Oo0Ooo * oO0o
 def get_raw_socket ( self ) :
  i1oO00O = str ( self . lisp_header . get_instance_id ( ) )
  if ( i1oO00O == "0" ) : return ( None )
  if ( i1oO00O not in lisp_iid_to_interface ) : return ( None )
  if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
  i1i1111I = lisp_iid_to_interface [ i1oO00O ]
  I1iiIi111I = i1i1111I . get_socket ( )
  if ( I1iiIi111I == None ) :
   Oo0OOOOOOO0oo = bold ( "SO_BINDTODEVICE" , False )
   IIIiii = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( Oo0OOOOOOO0oo , "drop" if IIIiii else "forward" ) )
   if 44 - 44: IiII . I11i % I1IiiI - i1IIi
   if ( IIIiii ) : return ( None )
   if 2 - 2: OoOoOO00 + OoOoOO00
   if 47 - 47: OoO0O00 + I1Ii111 . I1Ii111 * O0 / Oo0Ooo + OOooOOo
  i1oO00O = bold ( i1oO00O , False )
  iiIi = bold ( i1i1111I . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( i1oO00O , iiIi ) )
  return ( I1iiIi111I )
  if 44 - 44: o0oOOo0O0Ooo + I1Ii111 + OoOoOO00 * Oo0Ooo
  if 20 - 20: ooOoO0o . I11i . i11iIiiIii / o0oOOo0O0Ooo / OoO0O00 . Ii1I
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 47 - 47: O0 / iIii1I11I1II1 - OoOoOO00 + Ii1I
  IIi11III1i = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or IIi11III1i ) :
   IIIiiII1iIi1ii1i = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = IIIiiII1iIi1ii1i ) . start ( )
   if ( IIi11III1i ) : os . system ( "rm ./log-flows" )
   return
   if 49 - 49: OoOoOO00
   if 99 - 99: O0 + IiII + ooOoO0o - ooOoO0o * I1ii11iIi11i / IiII
  i1 = datetime . datetime . now ( )
  lisp_flow_log . append ( [ i1 , encap , self . packet , self ] )
  if 82 - 82: o0oOOo0O0Ooo - OOooOOo
  if 84 - 84: iII111i % i1IIi % OoO0O00 % II111iiii
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  o0oO0o0O0o0Oo = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 10 - 10: I11i + I1IiiI + OoooooooOO . OoOoOO00
  o0O0o = red ( self . outer_source . print_address_no_iid ( ) , False )
  iii1I1II1iIii = red ( self . outer_dest . print_address_no_iid ( ) , False )
  ii = green ( self . inner_source . print_address ( ) , False )
  oOo00O0o = green ( self . inner_dest . print_address ( ) , False )
  if 18 - 18: ooOoO0o
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   o0oO0o0O0o0Oo += " {}:{} -> {}:{}, LISP control message type {}\n"
   o0oO0o0O0o0Oo = o0oO0o0O0o0Oo . format ( o0O0o , self . udp_sport , iii1I1II1iIii , self . udp_dport ,
 self . inner_version )
   return ( o0oO0o0O0o0Oo )
   if 37 - 37: Oo0Ooo % i11iIiiIii - I1IiiI * I1ii11iIi11i . ooOoO0o
   if 62 - 62: OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
  if ( self . outer_dest . is_null ( ) == False ) :
   o0oO0o0O0o0Oo += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   o0oO0o0O0o0Oo = o0oO0o0O0o0Oo . format ( o0O0o , self . udp_sport , iii1I1II1iIii , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 29 - 29: oO0o
   if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
   if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
   if 33 - 33: OoooooooOO . O0
   if 59 - 59: iIii1I11I1II1
  if ( self . lisp_header . k_bits != 0 ) :
   i1OOoO0OO0oO = "\n"
   if ( self . packet_error != "" ) :
    i1OOoO0OO0oO = " ({})" . format ( self . packet_error ) + i1OOoO0OO0oO
    if 4 - 4: OoooooooOO
   o0oO0o0O0o0Oo += ", encrypted" + i1OOoO0OO0oO
   return ( o0oO0o0O0o0Oo )
   if 7 - 7: IiII
   if 26 - 26: OOooOOo + Oo0Ooo
   if 71 - 71: I1IiiI . ooOoO0o
   if 43 - 43: I1ii11iIi11i * OOooOOo
   if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 91 - 91: Ii1I + I11i - Oo0Ooo % OoOoOO00 . iII111i
   if 51 - 51: OOooOOo / I11i
  O0000O = packet [ 9 : 10 ] if self . inner_version == 4 else packet [ 6 : 7 ]
  O0000O = struct . unpack ( "B" , O0000O ) [ 0 ]
  if 51 - 51: ooOoO0o * oO0o - I1Ii111 + iII111i
  o0oO0o0O0o0Oo += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  o0oO0o0O0o0Oo = o0oO0o0O0o0Oo . format ( ii , oOo00O0o , len ( packet ) , self . inner_tos ,
 self . inner_ttl , O0000O )
  if 46 - 46: o0oOOo0O0Ooo - i11iIiiIii % OoO0O00 / Ii1I - OoOoOO00
  if 88 - 88: oO0o * I1IiiI / OoO0O00 - OOooOOo / i1IIi . I1Ii111
  if 26 - 26: i11iIiiIii - ooOoO0o
  if 45 - 45: ooOoO0o + II111iiii % iII111i
  if ( O0000O in [ 6 , 17 ] ) :
   o00OoOo0 = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( o00OoOo0 ) == 4 ) :
    o00OoOo0 = socket . ntohl ( struct . unpack ( "I" , o00OoOo0 ) [ 0 ] )
    o0oO0o0O0o0Oo += ", ports {} -> {}" . format ( o00OoOo0 >> 16 , o00OoOo0 & 0xffff )
    if 22 - 22: iIii1I11I1II1 / ooOoO0o / I1IiiI - o0oOOo0O0Ooo
  elif ( O0000O == 1 ) :
   II = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( II ) == 2 ) :
    II = socket . ntohs ( struct . unpack ( "H" , II ) [ 0 ] )
    o0oO0o0O0o0Oo += ", icmp-seq {}" . format ( II )
    if 95 - 95: iIii1I11I1II1
    if 75 - 75: OOooOOo - OoO0O00
  if ( self . packet_error != "" ) :
   o0oO0o0O0o0Oo += " ({})" . format ( self . packet_error )
   if 91 - 91: O0 . I1Ii111
  o0oO0o0O0o0Oo += "\n"
  return ( o0oO0o0O0o0Oo )
  if 31 - 31: O0 - IiII * i11iIiiIii * i1IIi
  if 78 - 78: ooOoO0o * OoOoOO00 . Ii1I . OoOoOO00 % iIii1I11I1II1
 def is_trace ( self ) :
  o00OoOo0 = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in o00OoOo0 )
  if 67 - 67: Ii1I . Oo0Ooo
  if 39 - 39: I11i * I1Ii111
  if 63 - 63: ooOoO0o % I1IiiI . OOooOOo - ooOoO0o / Oo0Ooo % I1IiiI
  if 39 - 39: o0oOOo0O0Ooo . i1IIi % oO0o / I11i % O0
  if 100 - 100: I1Ii111 - OoOoOO00
  if 78 - 78: OoooooooOO - OoOoOO00 . i11iIiiIii
  if 36 - 36: oO0o * iII111i + IiII * iII111i . I1ii11iIi11i - iIii1I11I1II1
  if 14 - 14: I11i * oO0o + i11iIiiIii
  if 84 - 84: iII111i / II111iiii
  if 86 - 86: I1IiiI
  if 97 - 97: II111iiii
  if 38 - 38: I1IiiI
  if 42 - 42: o0oOOo0O0Ooo
  if 8 - 8: i11iIiiIii / ooOoO0o
  if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
  if 19 - 19: i1IIi % II111iiii
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
class lisp_data_header ( object ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 56 - 56: Ii1I * i11iIiiIii
  if 92 - 92: II111iiii - O0 . I1Ii111
 def print_header ( self , e_or_d ) :
  oOOOoOO = lisp_hex_string ( self . first_long & 0xffffff )
  oOO0 = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 64 - 64: i1IIi
  i11 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 71 - 71: IiII * o0oOOo0O0Ooo
  return ( i11 . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 oOOOoOO , oOO0 ) )
  if 99 - 99: o0oOOo0O0Ooo
  if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
 def encode ( self ) :
  Iii1iIII1Iii = "II"
  oOOOoOO = socket . htonl ( self . first_long )
  oOO0 = socket . htonl ( self . second_long )
  if 13 - 13: iIii1I11I1II1 - OOooOOo
  i111ii1II11ii = struct . pack ( Iii1iIII1Iii , oOOOoOO , oOO0 )
  return ( i111ii1II11ii )
  if 21 - 21: I11i
  if 79 - 79: OoO0O00 / OOooOOo - i1IIi + i1IIi - IiII + IiII
 def decode ( self , packet ) :
  Iii1iIII1Iii = "II"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( False )
  if 18 - 18: Ii1I + OoOoOO00 . i1IIi / IiII / iII111i
  oOOOoOO , oOO0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 97 - 97: OoO0O00 + iIii1I11I1II1
  if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
  self . first_long = socket . ntohl ( oOOOoOO )
  self . second_long = socket . ntohl ( oOO0 )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 26 - 26: IiII
  if 52 - 52: O0 + ooOoO0o
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
  if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 1 - 1: I1IiiI . Ii1I
  if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  if 21 - 21: O0 * ooOoO0o % OoO0O00
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
  if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
  if 76 - 76: I11i . I1ii11iIi11i * OoooooooOO % iII111i
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 24 - 24: OoooooooOO
  if 83 - 83: O0 / OoO0O00
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 62 - 62: I11i
  if 73 - 73: Ii1I % OoO0O00 * OOooOOo
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 84 - 84: Oo0Ooo
  if 18 - 18: OoooooooOO
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 85 - 85: OoooooooOO . OoO0O00 . OoO0O00
  if 70 - 70: I11i
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 72 - 72: I1Ii111 - ooOoO0o - I1IiiI - iII111i + OOooOOo - i1IIi
  if 45 - 45: OoO0O00 * I1IiiI
  if 61 - 61: iII111i % II111iiii / OoOoOO00 % I1ii11iIi11i . iIii1I11I1II1 % O0
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
  if 74 - 74: I1ii11iIi11i * oO0o + iII111i % O0
  if 18 - 18: i1IIi % IiII . O0 - O0 - O0 - II111iiii
 def send_ipc ( self , ipc_socket , ipc ) :
  OO = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  OooOOooo = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , OO )
  lisp_ipc ( ipc , ipc_socket , OooOOooo )
  if 84 - 84: Ii1I
  if 70 - 70: iIii1I11I1II1
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  ii1I11Iii = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , ii1I11Iii )
  if 3 - 3: iII111i . I1IiiI . iII111i % I1ii11iIi11i
  if 9 - 9: O0 * Ii1I
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  ii1I11Iii = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , ii1I11Iii )
  if 54 - 54: I11i % I11i - ooOoO0o
  if 32 - 32: o0oOOo0O0Ooo % II111iiii / o0oOOo0O0Ooo . OOooOOo . o0oOOo0O0Ooo
 def receive_request ( self , ipc_socket , nonce ) :
  Ii1iIiIiIiI = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( Ii1iIiIiIiI != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 1 - 1: I1IiiI / I1IiiI
  if 37 - 37: OoO0O00 - i1IIi - II111iiii . i1IIi
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 6 - 6: IiII + I1ii11iIi11i
  if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 13 - 13: iIii1I11I1II1 * o0oOOo0O0Ooo - i11iIiiIii
  if 63 - 63: OoooooooOO * I1Ii111
  if 50 - 50: Oo0Ooo - o0oOOo0O0Ooo % II111iiii . O0 . oO0o % II111iiii
  if 18 - 18: I11i % OoooooooOO + OoO0O00 / I11i
  if 37 - 37: i1IIi - Ii1I / IiII . II111iiii % ooOoO0o
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   i11iIi1I1i1 = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 92 - 92: O0
   if 38 - 38: II111iiii / iII111i - o0oOOo0O0Ooo
   if ( remote_rloc . address > i11iIi1I1i1 . address ) :
    OoOOOO = "exit"
    self . request_nonce_sent = None
   else :
    OoOOOO = "stay in"
    self . echo_nonce_sent = None
    if 92 - 92: Oo0Ooo % o0oOOo0O0Ooo - ooOoO0o / ooOoO0o / OoOoOO00
    if 84 - 84: OOooOOo
   I1 = bold ( "collision" , False )
   i1IIiI1iII = red ( i11iIi1I1i1 . print_address_no_iid ( ) , False )
   I1I1iIiiiiII11 = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( I1 ,
 i1IIiI1iII , I1I1iIiiiiII11 , OoOOOO ) )
   if 55 - 55: I1ii11iIi11i / OoooooooOO - OoO0O00 / I1IiiI
   if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
   if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
   if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
   if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
  if ( self . echo_nonce_sent != None ) :
   OOO0O0O = self . echo_nonce_sent
   I1i = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( I1i ,
 lisp_hex_string ( OOO0O0O ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( OOO0O0O )
   if 8 - 8: o0oOOo0O0Ooo
   if 78 - 78: i1IIi - Oo0Ooo
   if 48 - 48: Ii1I - OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
   if 42 - 42: I1Ii111
   if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
   if 80 - 80: OOooOOo
   if 12 - 12: Ii1I
  OOO0O0O = self . request_nonce_sent
  i1Ii = self . last_request_nonce_sent
  if ( OOO0O0O and i1Ii != None ) :
   if ( time . time ( ) - i1Ii >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OOO0O0O ) ) )
    if 40 - 40: IiII . OoooooooOO . I1IiiI + O0 % i1IIi / IiII
    return ( None )
    if 36 - 36: OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
    if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
    if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
    if 2 - 2: ooOoO0o - O0 - I1ii11iIi11i / I11i * OoOoOO00
    if 26 - 26: I1ii11iIi11i + I1Ii111 - oO0o + IiII % OOooOOo
    if 84 - 84: I11i % Ii1I % O0 * o0oOOo0O0Ooo
    if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
    if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
    if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
  if ( OOO0O0O == None ) :
   OOO0O0O = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( OOO0O0O )
   if 65 - 65: I1ii11iIi11i / ooOoO0o
   self . request_nonce_sent = OOO0O0O
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OOO0O0O ) ) )
   if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 57 - 57: iII111i
   if 29 - 29: I1IiiI
   if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
   if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
   if 22 - 22: O0 % IiII % iII111i % I1IiiI
   if ( lisp_i_am_itr == False ) : return ( OOO0O0O | 0x80000000 )
   self . send_request_ipc ( ipc_socket , OOO0O0O )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OOO0O0O ) ) )
   if 34 - 34: iII111i . Oo0Ooo % I1ii11iIi11i . iII111i % IiII / IiII
   if 84 - 84: Ii1I
   if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
   if 9 - 9: iII111i - iII111i
   if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
   if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
   if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( OOO0O0O | 0x80000000 )
  if 41 - 41: I1ii11iIi11i % I1ii11iIi11i + IiII . iII111i % I1Ii111 * ooOoO0o
  if 57 - 57: Ii1I . I1Ii111 . II111iiii % OoooooooOO * O0 + iIii1I11I1II1
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
  Ii1i1 = time . time ( ) - self . last_request_nonce_sent
  o000 = self . last_echo_nonce_rcvd
  return ( Ii1i1 >= LISP_NONCE_ECHO_INTERVAL and o000 == None )
  if 8 - 8: Oo0Ooo
  if 22 - 22: ooOoO0o % OoOoOO00 / o0oOOo0O0Ooo
 def recently_requested ( self ) :
  o000 = self . last_request_nonce_sent
  if ( o000 == None ) : return ( False )
  if 98 - 98: OoO0O00 / o0oOOo0O0Ooo * I1IiiI
  Ii1i1 = time . time ( ) - o000
  return ( Ii1i1 <= LISP_NONCE_ECHO_INTERVAL )
  if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
  if 6 - 6: iII111i % o0oOOo0O0Ooo + I1Ii111
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 91 - 91: o0oOOo0O0Ooo + O0 * oO0o * IiII * I1ii11iIi11i
  if 83 - 83: OoooooooOO
  if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
  if 88 - 88: OOooOOo / i11iIiiIii / Ii1I / i11iIiiIii * I1ii11iIi11i % I11i
  o000 = self . last_good_echo_nonce_rcvd
  if ( o000 == None ) : o000 = 0
  Ii1i1 = time . time ( ) - o000
  if ( Ii1i1 <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 43 - 43: OoOoOO00 * OoO0O00 % i1IIi * Ii1I + iIii1I11I1II1
  if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
  if 63 - 63: ooOoO0o . OOooOOo
  if 66 - 66: I1IiiI
  if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
  if 60 - 60: I1ii11iIi11i
  o000 = self . last_new_request_nonce_sent
  if ( o000 == None ) : o000 = 0
  Ii1i1 = time . time ( ) - o000
  return ( Ii1i1 <= LISP_NONCE_ECHO_INTERVAL )
  if 78 - 78: oO0o + II111iiii
  if 55 - 55: OoooooooOO
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   ooO0O = bold ( "down" , False )
   O0Ooo0O0O = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , ooO0O , O0Ooo0O0O ) )
   if 63 - 63: OoOoOO00 / OoOoOO00 - I1Ii111 % OOooOOo
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 45 - 45: IiII / Oo0Ooo + OoooooooOO
   if 77 - 77: oO0o . Ii1I / O0 * oO0o
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 98 - 98: Oo0Ooo - oO0o . I1Ii111
  if ( self . recently_requested ( ) == False ) :
   O0o = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , O0o ) )
   if 58 - 58: Ii1I % OOooOOo - i11iIiiIii
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 65 - 65: Oo0Ooo % IiII % IiII - Oo0Ooo % I11i
   if 34 - 34: OOooOOo . IiII / OoooooooOO
   if 75 - 75: OoooooooOO / OoOoOO00 - iIii1I11I1II1 + oO0o % i1IIi / ooOoO0o
 def print_echo_nonce ( self ) :
  O00o0O0OoOo0 = lisp_print_elapsed ( self . last_request_nonce_sent )
  o00o0O0o0o0 = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 35 - 35: iIii1I11I1II1 % I1Ii111 * I11i . Oo0Ooo
  I11IiiI1 = lisp_print_elapsed ( self . last_echo_nonce_sent )
  oOo0 = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  I1iiIi111I = space ( 4 )
  if 52 - 52: iIii1I11I1II1 * OoOoOO00 + o0oOOo0O0Ooo . I11i
  OoiIIIiIi1I1i = "Nonce-Echoing:\n"
  OoiIIIiIi1I1i += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( I1iiIi111I , O00o0O0OoOo0 , I1iiIi111I , o00o0O0o0o0 )
  if 59 - 59: iII111i . i1IIi
  OoiIIIiIi1I1i += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( I1iiIi111I , oOo0 , I1iiIi111I , I11IiiI1 )
  if 31 - 31: I1IiiI + I1IiiI
  if 11 - 11: IiII + OoOoOO00 % o0oOOo0O0Ooo * OoO0O00 / IiII
  return ( OoiIIIiIi1I1i )
  if 5 - 5: iII111i / oO0o % ooOoO0o . i11iIiiIii % OoOoOO00 + oO0o
  if 95 - 95: I1ii11iIi11i
  if 48 - 48: I11i
  if 14 - 14: iIii1I11I1II1 / o0oOOo0O0Ooo * IiII
  if 35 - 35: iIii1I11I1II1
  if 34 - 34: OoO0O00 % I1IiiI . o0oOOo0O0Ooo % OoO0O00 % OoO0O00
  if 30 - 30: I1IiiI + I1IiiI
  if 75 - 75: I1IiiI - ooOoO0o - I1IiiI % oO0o % OoooooooOO
  if 13 - 13: ooOoO0o * OoO0O00 % iIii1I11I1II1 / IiII * iII111i . Oo0Ooo
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
    if 23 - 23: ooOoO0o / IiII . iII111i * Ii1I
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   III11II111 = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( III11II111 )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 87 - 87: i11iIiiIii
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 34 - 34: i1IIi
  if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 100 - 100: IiII + i1IIi * OoO0O00
  if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
  iI1ii = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   iI1ii = struct . pack ( "Q" , iI1ii & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   ooIi = struct . pack ( "I" , ( iI1ii >> 64 ) & LISP_4_32_MASK )
   iii1I = struct . pack ( "Q" , iI1ii & LISP_8_64_MASK )
   iI1ii = ooIi + iii1I
  else :
   iI1ii = struct . pack ( "QQ" , iI1ii >> 64 , iI1ii & LISP_8_64_MASK )
  return ( iI1ii )
  if 3 - 3: OoOoOO00
  if 52 - 52: OoOoOO00
 def key_length ( self , key ) :
  if ( type ( key ) != str ) : key = self . normalize_pub_key ( key )
  return ( old_div ( len ( key ) , 2 ) )
  if 79 - 79: I1IiiI + Oo0Ooo % OoOoOO00 - IiII + I1IiiI * oO0o
  if 52 - 52: OoOoOO00 % I1ii11iIi11i * Oo0Ooo % OoooooooOO - OoO0O00
 def print_key ( self , key ) :
  I11IIIIiI1 = self . normalize_pub_key ( key )
  return ( "0x{}...{}({})" . format ( I11IIIIiI1 [ 0 : 4 ] , I11IIIIiI1 [ - 4 : : ] , self . key_length ( I11IIIIiI1 ) ) )
  if 13 - 13: OOooOOo . Ii1I / I11i
  if 93 - 93: ooOoO0o * I1IiiI * I1ii11iIi11i / I1ii11iIi11i
 def normalize_pub_key ( self , key ) :
  if ( type ( key ) == str ) :
   if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
   return ( key )
   if 62 - 62: ooOoO0o * Ii1I % I1ii11iIi11i - i1IIi - I1ii11iIi11i
  key = lisp_hex_string ( key ) . zfill ( 256 )
  return ( key )
  if 24 - 24: OOooOOo
  if 71 - 71: IiII - i1IIi
 def print_keys ( self , do_bold = True ) :
  i1IIiI1iII = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   i1IIiI1iII += "none"
  else :
   i1IIiI1iII += self . print_key ( self . local_public_key )
   if 56 - 56: OoOoOO00 + oO0o
  I1I1iIiiiiII11 = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   I1I1iIiiiiII11 += "none"
  else :
   I1I1iIiiiiII11 += self . print_key ( self . remote_public_key )
   if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
  i1Iiiiii1II = "ECDH" if ( self . curve25519 ) else "DH"
  i1iII1i = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( i1Iiiiii1II , i1iII1i , i1IIiI1iII , I1I1iIiiiiII11 ) )
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
  III11II111 = self . local_private_key
  o0O0Ooo = self . dh_g_value
  o00oo = self . dh_p_value
  return ( int ( ( o0O0Ooo ** III11II111 ) % o00oo ) )
  if 35 - 35: I1IiiI
  if 48 - 48: OoooooooOO % OoooooooOO - OoO0O00 . OoOoOO00
 def compute_shared_key ( self , ed , print_shared = False ) :
  III11II111 = self . local_private_key
  I1iiii = self . remote_public_key
  if 69 - 69: OoOoOO00 + O0 - I11i - iIii1I11I1II1 . OoO0O00
  i1IO00oO0oOOOOOO = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( i1IO00oO0oOOOOOO , self . print_keys ( ) ) )
  if 88 - 88: iIii1I11I1II1 % II111iiii % II111iiii . OOooOOo % oO0o
  if ( self . curve25519 ) :
   iIoo0O0 = curve25519 . Public ( I1iiii )
   self . shared_key = self . curve25519 . get_shared_key ( iIoo0O0 )
  else :
   o00oo = self . dh_p_value
   self . shared_key = ( I1iiii ** III11II111 ) % o00oo
   if 37 - 37: iII111i % I11i . iII111i - OOooOOo / iIii1I11I1II1 - OOooOOo
   if 50 - 50: O0
   if 97 - 97: II111iiii
   if 43 - 43: Oo0Ooo / I1Ii111 / i1IIi
   if 3 - 3: Ii1I * ooOoO0o . OoO0O00 * OoooooooOO + OoOoOO00 / O0
   if 60 - 60: I11i
   if 97 - 97: i11iIiiIii * iIii1I11I1II1 / II111iiii
  if ( print_shared ) :
   I11IIIIiI1 = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( I11IIIIiI1 ) )
   if 66 - 66: II111iiii + iII111i * oO0o % I11i / i1IIi / iIii1I11I1II1
   if 62 - 62: OoOoOO00 + oO0o * IiII + O0 / OOooOOo + ooOoO0o
   if 38 - 38: i1IIi / iIii1I11I1II1 + iII111i
   if 26 - 26: I1ii11iIi11i . Ii1I % o0oOOo0O0Ooo
   if 4 - 4: I1Ii111
  self . compute_encrypt_icv_keys ( )
  if 80 - 80: Oo0Ooo . O0 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 52 - 52: OoO0O00 % i11iIiiIii . ooOoO0o % OoOoOO00 % OoooooooOO
  if 5 - 5: OoOoOO00 / O0 / i11iIiiIii
  if 88 - 88: II111iiii - iII111i / OoooooooOO
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 71 - 71: I1ii11iIi11i
  if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
 def compute_encrypt_icv_keys ( self ) :
  i1iI11IiII = hashlib . sha256
  if ( self . curve25519 ) :
   oO00Oo0OO = self . shared_key
  else :
   oO00Oo0OO = lisp_hex_string ( self . shared_key )
   if 32 - 32: Ii1I - Ii1I
   if 6 - 6: iIii1I11I1II1 - i11iIiiIii / I1ii11iIi11i - o0oOOo0O0Ooo
   if 95 - 95: I11i
   if 76 - 76: II111iiii - i1IIi . O0 * i11iIiiIii % o0oOOo0O0Ooo - iII111i
   if 30 - 30: I1Ii111 % oO0o + oO0o * OoooooooOO - I1ii11iIi11i
  i1IIiI1iII = self . local_public_key
  if ( type ( i1IIiI1iII ) != int ) : i1IIiI1iII = int ( binascii . hexlify ( i1IIiI1iII ) , 16 )
  I1I1iIiiiiII11 = self . remote_public_key
  if ( type ( I1I1iIiiiiII11 ) != int ) : I1I1iIiiiiII11 = int ( binascii . hexlify ( I1I1iIiiiiII11 ) , 16 )
  OOoOOo = "0001" + "lisp-crypto" + lisp_hex_string ( i1IIiI1iII ^ I1I1iIiiiiII11 ) + "0100"
  if 22 - 22: OoOoOO00 . II111iiii
  ii111 = hmac . new ( OOoOOo . encode ( ) , oO00Oo0OO , i1iI11IiII ) . hexdigest ( )
  ii111 = int ( ii111 , 16 )
  if 60 - 60: ooOoO0o * i11iIiiIii + I1Ii111 % OoooooooOO
  if 44 - 44: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo % O0 / OoooooooOO . OOooOOo
  if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
  if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
  O00O00000 = ( ii111 >> 128 ) & LISP_16_128_MASK
  iI1II1IIIIi = ii111 & LISP_16_128_MASK
  self . encrypt_key = lisp_hex_string ( O00O00000 ) . zfill ( 32 )
  IiIIi = 32 if self . do_poly else 40
  self . icv_key = lisp_hex_string ( iI1II1IIIIi ) . zfill ( IiIIi )
  if 85 - 85: O0 + O0 - O0 - IiII . I1ii11iIi11i % Ii1I
  if 60 - 60: OoooooooOO * Oo0Ooo % I1Ii111
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   OooO0o00O = self . icv . poly1305aes
   iIii11IiIi1I = self . icv . binascii . hexlify
   nonce = iIii11IiIi1I ( nonce )
   OoO000oOO = OooO0o00O ( self . encrypt_key , self . icv_key , nonce , packet )
   OoO000oOO = iIii11IiIi1I ( OoO000oOO )
  else :
   III11II111 = binascii . unhexlify ( self . icv_key )
   OoO000oOO = hmac . new ( III11II111 , packet , self . icv ) . hexdigest ( )
   OoO000oOO = OoO000oOO [ 0 : 40 ]
   if 25 - 25: i11iIiiIii - OoOoOO00
  return ( OoO000oOO )
  if 32 - 32: i11iIiiIii
  if 57 - 57: iIii1I11I1II1
 def add_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 99 - 99: iII111i % o0oOOo0O0Ooo + iIii1I11I1II1
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 51 - 51: i1IIi % o0oOOo0O0Ooo - oO0o - IiII
  if 14 - 14: ooOoO0o + Ii1I
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
  OO0Oo00OO0oo = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( i1iiII1I1I1ii ) , 1 , 0 )
  if 19 - 19: O0 % I1IiiI + oO0o
  if 23 - 23: OOooOOo
  if 68 - 68: OoooooooOO
  if 18 - 18: Ii1I * OoO0O00
  if 89 - 89: OoO0O00 + oO0o % iIii1I11I1II1 + I11i / O0
  if 38 - 38: ooOoO0o - o0oOOo0O0Ooo - O0 + ooOoO0o % OoOoOO00 . o0oOOo0O0Ooo
  i1iII1i = self . cipher_suite
  OO0Oo00OO0oo += struct . pack ( "BBH" , i1iII1i , 0 , socket . htons ( iI111I ) )
  if 40 - 40: iIii1I11I1II1 * OoooooooOO * I1Ii111 - Ii1I + i11iIiiIii
  if 81 - 81: OoO0O00 * OoooooooOO / iII111i
  if 8 - 8: O0 * i1IIi - OoOoOO00 % I1IiiI / I1ii11iIi11i
  if 39 - 39: I1ii11iIi11i . oO0o * II111iiii + I1IiiI - iIii1I11I1II1
  for OoOOoO0oOo in range ( 0 , iI111I * 2 , 16 ) :
   III11II111 = int ( oOO [ OoOOoO0oOo : OoOOoO0oOo + 16 ] , 16 )
   OO0Oo00OO0oo += struct . pack ( "Q" , byte_swap_64 ( III11II111 ) )
   if 56 - 56: IiII - Ii1I + i11iIiiIii * OoO0O00 % I1IiiI
   if 37 - 37: iIii1I11I1II1 + IiII / I1Ii111 . OoooooooOO
   if 72 - 72: oO0o % ooOoO0o % OOooOOo
   if 63 - 63: OoO0O00 . Ii1I % II111iiii / I11i - OoOoOO00
   if 4 - 4: Oo0Ooo - O0 / I11i + O0 - oO0o * Oo0Ooo
  if ( rloc_addr ) :
   OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   OO0Oo00OO0oo += rloc_addr . pack_address ( )
   if 25 - 25: I1IiiI
  return ( OO0Oo00OO0oo )
  if 64 - 64: oO0o
  if 80 - 80: o0oOOo0O0Ooo % iIii1I11I1II1
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 63 - 63: IiII * i11iIiiIii
  if 86 - 86: I11i % I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
  if 26 - 26: II111iiii * iII111i + o0oOOo0O0Ooo / O0 + i1IIi - I11i
  if 56 - 56: OOooOOo
  if ( lcaf_len == 0 ) :
   Iii1iIII1Iii = "HHBBH"
   oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
   if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
   if 76 - 76: i1IIi % iIii1I11I1II1 - o0oOOo0O0Ooo + IiII - I11i
   O0ooO0O00oo0 , OOOo00o , ooOoOoOo , OOOo00o , lcaf_len = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
   if 9 - 9: I11i - II111iiii + I1Ii111 / oO0o % I1ii11iIi11i
   if 17 - 17: iIii1I11I1II1 - ooOoO0o
   if ( ooOoOoOo != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ oOoOo000Ooooo : : ]
   if 52 - 52: I1ii11iIi11i
   if 93 - 93: iII111i . i11iIiiIii
   if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
   if 49 - 49: O0 . Oo0Ooo / Ii1I
   if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
   if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
  ooOoOoOo = LISP_LCAF_SECURITY_TYPE
  Iii1iIII1Iii = "BBBBH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  i1IIiiI1iii1 , OOOo00o , i1iII1i , OOOo00o , iI111I = struct . unpack ( Iii1iIII1Iii ,
 packet [ : oOoOo000Ooooo ] )
  if 100 - 100: iII111i / o0oOOo0O0Ooo
  if 11 - 11: I1ii11iIi11i * OoOoOO00 % i11iIiiIii - Ii1I
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . I1ii11iIi11i
  if 63 - 63: oO0o
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
  packet = packet [ oOoOo000Ooooo : : ]
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
  for OoOOoO0oOo in range ( 0 , iI111I , 8 ) :
   III11II111 = byte_swap_64 ( struct . unpack ( "Q" , packet [ OoOOoO0oOo : OoOOoO0oOo + 8 ] ) [ 0 ] )
   oOO <<= 64
   oOO |= III11II111
   if 95 - 95: I1ii11iIi11i
  self . remote_public_key = oOO
  if 98 - 98: IiII * iII111i . OoooooooOO . O0
  if 89 - 89: iII111i / O0 % OoooooooOO - O0 . OoO0O00
  if 32 - 32: ooOoO0o
  if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
  if 57 - 57: I1ii11iIi11i - OoO0O00 * iIii1I11I1II1
  if ( self . curve25519 ) :
   III11II111 = lisp_hex_string ( self . remote_public_key )
   III11II111 = III11II111 . zfill ( 64 )
   II111IiI11i = ""
   for OoOOoO0oOo in range ( 0 , len ( III11II111 ) , 2 ) :
    II111IiI11i += chr ( int ( III11II111 [ OoOOoO0oOo : OoOOoO0oOo + 2 ] , 16 ) )
    if 91 - 91: II111iiii . Oo0Ooo . oO0o - OoooooooOO / OoOoOO00
   self . remote_public_key = II111IiI11i
   if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
   if 55 - 55: OoO0O00
  packet = packet [ iI111I : : ]
  return ( packet )
  if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
  if 32 - 32: Ii1I * oO0o
  if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
  if 28 - 28: Oo0Ooo
  if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
  if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
  if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
  if 69 - 69: I11i
class lisp_thread ( object ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
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
  if 38 - 38: OoooooooOO * iIii1I11I1II1
  if 54 - 54: OoooooooOO . I1Ii111
 def decode ( self , packet ) :
  Iii1iIII1Iii = "BBBBQ"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( False )
  if 71 - 71: Ii1I
  I1iI1Ii1I1Iii1 , ii1i , OO00O0O00oOOO , self . record_count , self . nonce = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 17 - 17: ooOoO0o
  if 25 - 25: Ii1I * iIii1I11I1II1 * o0oOOo0O0Ooo + OoOoOO00 . OoOoOO00
  self . type = I1iI1Ii1I1Iii1 >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( I1iI1Ii1I1Iii1 & 0x01 ) else False
   self . rloc_probe = True if ( I1iI1Ii1I1Iii1 & 0x02 ) else False
   self . smr_invoked_bit = True if ( ii1i & 0x40 ) else False
   if 3 - 3: OoO0O00 . I1IiiI . I11i . I1ii11iIi11i
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( I1iI1Ii1I1Iii1 & 0x04 ) else False
   self . to_etr = True if ( I1iI1Ii1I1Iii1 & 0x02 ) else False
   self . to_ms = True if ( I1iI1Ii1I1Iii1 & 0x01 ) else False
   if 19 - 19: O0 * I11i % OoooooooOO
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( I1iI1Ii1I1Iii1 & 0x08 ) else False
   if 36 - 36: o0oOOo0O0Ooo % I11i * I1ii11iIi11i % Ii1I + i1IIi - Oo0Ooo
  return ( True )
  if 56 - 56: I1ii11iIi11i
  if 32 - 32: OoOoOO00 % O0 % i11iIiiIii - ooOoO0o . I1IiiI
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 24 - 24: oO0o % o0oOOo0O0Ooo / I1Ii111 + o0oOOo0O0Ooo
  if 59 - 59: II111iiii % I1IiiI * O0 . OoooooooOO - OoooooooOO % O0
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
  if 28 - 28: i1IIi / I11i . o0oOOo0O0Ooo
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
  if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
  if 10 - 10: II111iiii . OOooOOo / iII111i
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 35 - 35: iII111i / Oo0Ooo + O0 * iIii1I11I1II1 - O0
  if 3 - 3: I1ii11iIi11i
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 42 - 42: I11i % Oo0Ooo + IiII - I11i . iIii1I11I1II1 - Ii1I
  if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
  if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
  if 87 - 87: OoO0O00 * Oo0Ooo
  if 83 - 83: i1IIi * I1Ii111 - IiII / Ii1I
  if 48 - 48: oO0o . II111iiii - OoOoOO00 % i1IIi . OoOoOO00
  if 32 - 32: Ii1I * I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
  if 67 - 67: OoOoOO00 % Oo0Ooo
  if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
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
  if 73 - 73: I1ii11iIi11i
  if 92 - 92: i11iIiiIii + O0 * I11i
 def print_map_register ( self ) :
  oOOoO = lisp_hex_string ( self . xtr_id )
  if 1 - 1: II111iiii
  i11 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 44 - 44: i11iIiiIii
  lprint ( i11 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # O0 - O0 % I1Ii111 / I1ii11iIi11i
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , oOOoO , self . site_id ) )
  if 76 - 76: OoO0O00 * oO0o - OoO0O00
  if 57 - 57: OoooooooOO / OoOoOO00 + oO0o . Ii1I
  if 14 - 14: i11iIiiIii % OOooOOo * o0oOOo0O0Ooo * OoOoOO00
  if 55 - 55: I1Ii111 * OOooOOo * I1Ii111
 def encode ( self ) :
  oOOOoOO = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : oOOOoOO |= 0x08000000
  if ( self . lisp_sec_present ) : oOOOoOO |= 0x04000000
  if ( self . xtr_id_present ) : oOOOoOO |= 0x02000000
  if ( self . map_register_refresh ) : oOOOoOO |= 0x1000
  if ( self . use_ttl_for_timeout ) : oOOOoOO |= 0x800
  if ( self . merge_register_requested ) : oOOOoOO |= 0x400
  if ( self . mobile_node ) : oOOOoOO |= 0x200
  if ( self . map_notify_requested ) : oOOOoOO |= 0x100
  if ( self . encryption_key_id != None ) :
   oOOOoOO |= 0x2000
   oOOOoOO |= self . encryption_key_id << 14
   if 70 - 70: O0 . Ii1I
   if 33 - 33: OOooOOo * Ii1I
   if 64 - 64: i11iIiiIii . iIii1I11I1II1
   if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
   if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 70 - 70: I11i . I1ii11iIi11i * oO0o
    if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
    if 23 - 23: I1ii11iIi11i % I11i
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  OO0Oo00OO0oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 18 - 18: OoooooooOO . i1IIi + II111iiii
  OO0Oo00OO0oo = self . zero_auth ( OO0Oo00OO0oo )
  return ( OO0Oo00OO0oo )
  if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
  if 34 - 34: I1Ii111 * I11i
 def zero_auth ( self , packet ) :
  IiI1ii1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  i1oO0o00oOo00oO = b""
  OoooOOO0 = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   i1oO0o00oOo00oO = struct . pack ( "QQI" , 0 , 0 , 0 )
   OoooOOO0 = struct . calcsize ( "QQI" )
   if 99 - 99: Ii1I - IiII - i1IIi / i11iIiiIii . IiII
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   i1oO0o00oOo00oO = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   OoooOOO0 = struct . calcsize ( "QQQQ" )
   if 58 - 58: OOooOOo
  packet = packet [ 0 : IiI1ii1Ii ] + i1oO0o00oOo00oO + packet [ IiI1ii1Ii + OoooOOO0 : : ]
  return ( packet )
  if 12 - 12: I1IiiI . o0oOOo0O0Ooo * OoooooooOO
  if 64 - 64: OoOoOO00 + IiII - i1IIi . II111iiii . OoO0O00
 def encode_auth ( self , packet ) :
  IiI1ii1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  OoooOOO0 = self . auth_len
  i1oO0o00oOo00oO = self . auth_data
  packet = packet [ 0 : IiI1ii1Ii ] + i1oO0o00oOo00oO + packet [ IiI1ii1Ii + OoooOOO0 : : ]
  return ( packet )
  if 31 - 31: oO0o . iII111i - I11i . iIii1I11I1II1 + I11i . OoOoOO00
  if 86 - 86: I1ii11iIi11i - I1ii11iIi11i / iII111i - I1ii11iIi11i * iII111i + I1Ii111
 def decode ( self , packet ) :
  OOooo = packet
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  if 39 - 39: i1IIi
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  oOOOoOO = socket . ntohl ( oOOOoOO [ 0 ] )
  packet = packet [ oOoOo000Ooooo : : ]
  if 55 - 55: II111iiii * iII111i / OoooooooOO
  Iii1iIII1Iii = "QBBH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  if 68 - 68: IiII
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 20 - 20: OoO0O00 / i11iIiiIii - i1IIi
  if 46 - 46: OOooOOo - Oo0Ooo % iII111i % i11iIiiIii
  self . nonce = byte_swap_64 ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( oOOOoOO & 0x08000000 ) else False
  if 80 - 80: I11i - I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  self . lisp_sec_present = True if ( oOOOoOO & 0x04000000 ) else False
  self . xtr_id_present = True if ( oOOOoOO & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( oOOOoOO & 0x800 ) else False
  self . map_register_refresh = True if ( oOOOoOO & 0x1000 ) else False
  self . merge_register_requested = True if ( oOOOoOO & 0x400 ) else False
  self . mobile_node = True if ( oOOOoOO & 0x200 ) else False
  self . map_notify_requested = True if ( oOOOoOO & 0x100 ) else False
  self . record_count = oOOOoOO & 0xff
  if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
  if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
  if 20 - 20: ooOoO0o
  if 63 - 63: iIii1I11I1II1 . OoO0O00
  self . encrypt_bit = True if oOOOoOO & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( oOOOoOO >> 14 ) & 0x7
   if 100 - 100: i1IIi * i1IIi
   if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
   if 94 - 94: IiII
   if 15 - 15: Ii1I - IiII / O0
   if 28 - 28: I1Ii111 . i1IIi / I1ii11iIi11i
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( OOooo ) == False ) : return ( [ None , None ] )
   if 77 - 77: i11iIiiIii / I1Ii111 / i11iIiiIii % OoOoOO00 - I1Ii111
   if 80 - 80: I1Ii111 % OoOoOO00 . OoooooooOO . II111iiii % IiII
  packet = packet [ oOoOo000Ooooo : : ]
  if 6 - 6: I1Ii111 % IiII / Ii1I + I1Ii111 . oO0o
  if 70 - 70: iIii1I11I1II1 / Ii1I
  if 61 - 61: O0 * o0oOOo0O0Ooo + I1Ii111 - OOooOOo . I1IiiI - IiII
  if 7 - 7: I1ii11iIi11i
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 81 - 81: Oo0Ooo % II111iiii % o0oOOo0O0Ooo / I11i
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 95 - 95: OoOoOO00 - O0 % OoooooooOO
    if 13 - 13: i11iIiiIii
   OoooOOO0 = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    oOoOo000Ooooo = struct . calcsize ( "QQI" )
    if ( OoooOOO0 < oOoOo000Ooooo ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
    o00OOOOoOO , Ooo , OoOoo0ooo0 = struct . unpack ( "QQI" , packet [ : OoooOOO0 ] )
    oO000oOo0oO0 = b""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    oOoOo000Ooooo = struct . calcsize ( "QQQQ" )
    if ( OoooOOO0 < oOoOo000Ooooo ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 2 - 2: o0oOOo0O0Ooo - I1IiiI - i11iIiiIii / OoooooooOO
    o00OOOOoOO , Ooo , OoOoo0ooo0 , oO000oOo0oO0 = struct . unpack ( "QQQQ" ,
 packet [ : OoooOOO0 ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 87 - 87: o0oOOo0O0Ooo + oO0o + OoooooooOO * OOooOOo
    return ( [ None , None ] )
    if 50 - 50: Oo0Ooo * i1IIi - I1ii11iIi11i * I1IiiI
   self . auth_data = lisp_concat_auth_data ( self . alg_id , o00OOOOoOO , Ooo ,
 OoOoo0ooo0 , oO000oOo0oO0 )
   OOooo = self . zero_auth ( OOooo )
   packet = packet [ self . auth_len : : ]
   if 24 - 24: OoOoOO00 * Ii1I
  return ( [ OOooo , packet ] )
  if 17 - 17: OoO0O00 . I1IiiI * O0
  if 81 - 81: OOooOOo
 def encode_xtr_id ( self , packet ) :
  OooOooo00OOO0o = self . xtr_id >> 64
  II1iIIiIII = self . xtr_id & 0xffffffffffffffff
  OooOooo00OOO0o = byte_swap_64 ( OooOooo00OOO0o )
  II1iIIiIII = byte_swap_64 ( II1iIIiIII )
  iI1 = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , OooOooo00OOO0o , II1iIIiIII , iI1 )
  return ( packet )
  if 5 - 5: IiII - I11i
  if 16 - 16: IiII . iII111i . Oo0Ooo % OOooOOo / IiII
 def decode_xtr_id ( self , packet ) :
  oOoOo000Ooooo = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - oOoOo000Ooooo : : ]
  OooOooo00OOO0o , II1iIIiIII , iI1 = struct . unpack ( "QQQ" ,
 packet [ : oOoOo000Ooooo ] )
  OooOooo00OOO0o = byte_swap_64 ( OooOooo00OOO0o )
  II1iIIiIII = byte_swap_64 ( II1iIIiIII )
  self . xtr_id = ( OooOooo00OOO0o << 64 ) | II1iIIiIII
  self . site_id = byte_swap_64 ( iI1 )
  return ( True )
  if 72 - 72: o0oOOo0O0Ooo * ooOoO0o - i11iIiiIii / Ii1I
  if 11 - 11: O0 - I1IiiI
  if 31 - 31: iII111i
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
  if 47 - 47: I1Ii111 + I1IiiI
  if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
 def print_notify ( self ) :
  i1oO0o00oOo00oO = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( i1oO0o00oOo00oO ) != 40 ) :
   i1oO0o00oOo00oO = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( i1oO0o00oOo00oO ) != 64 ) :
   i1oO0o00oOo00oO = self . auth_data
   if 80 - 80: oO0o
  i11 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( i11 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # I1IiiI * iII111i / OoooooooOO * OoOoOO00 . Oo0Ooo
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , i1oO0o00oOo00oO ) )
  if 29 - 29: iII111i . o0oOOo0O0Ooo / o0oOOo0O0Ooo / Ii1I
  if 1 - 1: OoooooooOO - i11iIiiIii - OOooOOo + i1IIi - OoOoOO00 - iII111i
  if 75 - 75: I1IiiI
  if 99 - 99: ooOoO0o . Ii1I
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   i1oO0o00oOo00oO = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 92 - 92: i1IIi
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   i1oO0o00oOo00oO = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
  packet += i1oO0o00oOo00oO
  return ( packet )
  if 30 - 30: OoooooooOO % o0oOOo0O0Ooo + ooOoO0o * OoO0O00
  if 57 - 57: I11i + iIii1I11I1II1 . OoO0O00 + oO0o
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   oOOOoOO = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   oOOOoOO = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 4 - 4: Ii1I
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  OO0Oo00OO0oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 43 - 43: i1IIi . I1IiiI * iIii1I11I1II1 * i11iIiiIii - OOooOOo + ooOoO0o
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = OO0Oo00OO0oo + eid_records
   return ( self . packet )
   if 56 - 56: Oo0Ooo % i11iIiiIii / Ii1I . I1Ii111 . OoO0O00 - OoOoOO00
   if 32 - 32: I1Ii111 / oO0o / I1IiiI
   if 22 - 22: OoO0O00 - OoOoOO00 . Oo0Ooo + o0oOOo0O0Ooo
   if 69 - 69: oO0o - I1IiiI
   if 10 - 10: i1IIi / iII111i . II111iiii * i1IIi % OoooooooOO
  OO0Oo00OO0oo = self . zero_auth ( OO0Oo00OO0oo )
  OO0Oo00OO0oo += eid_records
  if 83 - 83: I11i . OOooOOo + I1Ii111 * I11i . I1Ii111 + oO0o
  iiIIII11iIii = lisp_hash_me ( OO0Oo00OO0oo , self . alg_id , password , False )
  if 64 - 64: Ii1I . o0oOOo0O0Ooo - i1IIi
  IiI1ii1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  OoooOOO0 = self . auth_len
  self . auth_data = iiIIII11iIii
  OO0Oo00OO0oo = OO0Oo00OO0oo [ 0 : IiI1ii1Ii ] + iiIIII11iIii + OO0Oo00OO0oo [ IiI1ii1Ii + OoooOOO0 : : ]
  self . packet = OO0Oo00OO0oo
  return ( OO0Oo00OO0oo )
  if 35 - 35: I1ii11iIi11i % OoooooooOO
  if 59 - 59: I1IiiI % I11i
 def decode ( self , packet ) :
  OOooo = packet
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 32 - 32: I1IiiI * O0 + O0
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  oOOOoOO = socket . ntohl ( oOOOoOO [ 0 ] )
  self . map_notify_ack = ( ( oOOOoOO >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = oOOOoOO & 0xff
  packet = packet [ oOoOo000Ooooo : : ]
  if 34 - 34: IiII
  Iii1iIII1Iii = "QBBH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 5 - 5: OoO0O00 . I1IiiI
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 48 - 48: Oo0Ooo - OoO0O00 . I11i - iIii1I11I1II1 % Ii1I
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ oOoOo000Ooooo : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 47 - 47: iII111i / OoooooooOO - II111iiii
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
  if 23 - 23: i1IIi
  if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
  if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 31 - 31: I1Ii111 - I11i
  OoooOOO0 = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   o00OOOOoOO , Ooo , OoOoo0ooo0 = struct . unpack ( "QQI" , packet [ : OoooOOO0 ] )
   oO000oOo0oO0 = ""
   if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   o00OOOOoOO , Ooo , OoOoo0ooo0 , oO000oOo0oO0 = struct . unpack ( "QQQQ" ,
 packet [ : OoooOOO0 ] )
   if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
  self . auth_data = lisp_concat_auth_data ( self . alg_id , o00OOOOoOO , Ooo ,
 OoOoo0ooo0 , oO000oOo0oO0 )
  if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
  oOoOo000Ooooo = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( OOooo [ : oOoOo000Ooooo ] )
  oOoOo000Ooooo += OoooOOO0
  packet += OOooo [ oOoOo000Ooooo : : ]
  return ( packet )
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
  if 73 - 73: i11iIiiIii + O0 % O0
  if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
  if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
  if 18 - 18: OoOoOO00
  if 30 - 30: II111iiii
  if 27 - 27: i1IIi - iIii1I11I1II1 + O0 % Oo0Ooo / OOooOOo + i1IIi
  if 48 - 48: Oo0Ooo
  if 70 - 70: OoooooooOO * i11iIiiIii
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
  if 60 - 60: IiII / iIii1I11I1II1 + OoooooooOO - I1ii11iIi11i * i11iIiiIii
  if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 47 - 47: Ii1I . OoOoOO00 . iIii1I11I1II1 . o0oOOo0O0Ooo
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 39 - 39: o0oOOo0O0Ooo
  if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
 def print_map_request ( self ) :
  oOOoO = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   oOOoO = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
   if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
   if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
  i11 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
  lprint ( i11 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # OoOoOO00
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , oOOoO ) )
  if 82 - 82: ooOoO0o . I1Ii111 . Oo0Ooo % iIii1I11I1II1 - i11iIiiIii
  O0o0O0 = self . keys
  for I1IoOO0oOOOOO0 in self . itr_rlocs :
   if ( I1IoOO0oOOOOO0 . afi == LISP_AFI_LCAF and self . json_telemetry != None ) :
    continue
    if 99 - 99: OoOoOO00 . I1Ii111 * II111iiii - i11iIiiIii + I11i
   I1iii1iIiI111 = red ( I1IoOO0oOOOOO0 . print_address_no_iid ( ) , False )
   lprint ( "  itr-rloc: afi {} {}{}" . format ( I1IoOO0oOOOOO0 . afi , I1iii1iIiI111 ,
 "" if ( O0o0O0 == None ) else ", " + O0o0O0 [ 1 ] . print_keys ( ) ) )
   O0o0O0 = None
   if 77 - 77: oO0o / iIii1I11I1II1 % I1IiiI / o0oOOo0O0Ooo / II111iiii - I1Ii111
  if ( self . json_telemetry != None ) :
   lprint ( "  itr-rloc: afi {} telemetry: {}" . format ( LISP_AFI_LCAF ,
 self . json_telemetry ) )
   if 4 - 4: i1IIi
   if 97 - 97: OoooooooOO / i11iIiiIii % O0
   if 17 - 17: I1Ii111 + i11iIiiIii . i11iIiiIii * i1IIi / O0
 def sign_map_request ( self , privkey ) :
  Ii1IiI = self . signature_eid . print_address ( )
  Ooo0o00O0O0oO = self . source_eid . print_address ( )
  OO000OOO = self . target_eid . print_address ( )
  o000OOooo000O = lisp_hex_string ( self . nonce ) + Ooo0o00O0O0oO + OO000OOO
  self . map_request_signature = privkey . sign ( o000OOooo000O )
  oo0 = binascii . b2a_base64 ( self . map_request_signature )
  oo0 = { "source-eid" : Ooo0o00O0O0oO , "signature-eid" : Ii1IiI ,
 "signature" : oo0 }
  return ( json . dumps ( oo0 ) )
  if 96 - 96: O0
  if 89 - 89: I1ii11iIi11i - Oo0Ooo
 def verify_map_request_sig ( self , pubkey ) :
  I1i1ii1iIii = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( I1i1ii1iIii ) )
   return ( False )
   if 42 - 42: I1IiiI
   if 95 - 95: I1ii11iIi11i / IiII % iIii1I11I1II1 + O0
  Ooo0o00O0O0oO = self . source_eid . print_address ( )
  OO000OOO = self . target_eid . print_address ( )
  o000OOooo000O = lisp_hex_string ( self . nonce ) + Ooo0o00O0O0oO + OO000OOO
  pubkey = binascii . a2b_base64 ( pubkey )
  if 6 - 6: IiII
  OOoO0OOO00 = True
  try :
   III11II111 = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 15 - 15: o0oOOo0O0Ooo . O0 - I1IiiI / i1IIi . oO0o * OoooooooOO
   OOoO0OOO00 = False
   if 32 - 32: ooOoO0o / II111iiii . O0 . ooOoO0o % I1IiiI - o0oOOo0O0Ooo
   if 69 - 69: Ii1I - I1IiiI * OOooOOo . iIii1I11I1II1 * OoOoOO00 . OoooooooOO
  if ( OOoO0OOO00 ) :
   try :
    OOoO0OOO00 = III11II111 . verify ( self . map_request_signature , o000OOooo000O )
   except :
    OOoO0OOO00 = False
    if 6 - 6: O0 . o0oOOo0O0Ooo - OoOoOO00
    if 3 - 3: OoooooooOO % iIii1I11I1II1 * I1Ii111 % Oo0Ooo + iIii1I11I1II1
    if 66 - 66: Oo0Ooo - OoOoOO00
  I111 = bold ( "passed" if OOoO0OOO00 else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( I111 , I1i1ii1iIii ) )
  return ( OOoO0OOO00 )
  if 76 - 76: ooOoO0o % I1IiiI
  if 18 - 18: OoO0O00
 def encode_json ( self , json_string ) :
  ooOoOoOo = LISP_LCAF_JSON_TYPE
  O0oOo = socket . htons ( LISP_AFI_LCAF )
  iIi1IiiIII = socket . htons ( len ( json_string ) + 4 )
  i11iI1I1I11II = socket . htons ( len ( json_string ) )
  OO0Oo00OO0oo = struct . pack ( "HBBBBHH" , O0oOo , 0 , 0 , ooOoOoOo , 0 , iIi1IiiIII ,
 i11iI1I1I11II )
  OO0Oo00OO0oo += json_string . encode ( )
  OO0Oo00OO0oo += struct . pack ( "H" , 0 )
  return ( OO0Oo00OO0oo )
  if 70 - 70: iIii1I11I1II1 . ooOoO0o * oO0o
  if 45 - 45: OoO0O00 * II111iiii * OoOoOO00 - OOooOOo % oO0o - Oo0Ooo
 def encode ( self , probe_dest , probe_port ) :
  oOOOoOO = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  if 4 - 4: o0oOOo0O0Ooo . OoOoOO00 - iIii1I11I1II1 / IiII / I1IiiI % I1IiiI
  Iiii1I = lisp_telemetry_configured ( ) if ( self . rloc_probe ) else None
  if ( Iiii1I != None ) : self . itr_rloc_count += 1
  oOOOoOO = oOOOoOO | ( self . itr_rloc_count << 8 )
  if 26 - 26: Oo0Ooo + OoooooooOO - OOooOOo * II111iiii / iII111i
  if ( self . auth_bit ) : oOOOoOO |= 0x08000000
  if ( self . map_data_present ) : oOOOoOO |= 0x04000000
  if ( self . rloc_probe ) : oOOOoOO |= 0x02000000
  if ( self . smr_bit ) : oOOOoOO |= 0x01000000
  if ( self . pitr_bit ) : oOOOoOO |= 0x00800000
  if ( self . smr_invoked_bit ) : oOOOoOO |= 0x00400000
  if ( self . mobile_node ) : oOOOoOO |= 0x00200000
  if ( self . xtr_id_present ) : oOOOoOO |= 0x00100000
  if ( self . local_xtr ) : oOOOoOO |= 0x00004000
  if ( self . dont_reply_bit ) : oOOOoOO |= 0x00002000
  if 77 - 77: I11i
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  if 50 - 50: o0oOOo0O0Ooo - OoOoOO00
  if 1 - 1: i1IIi / Ii1I % IiII - I11i % o0oOOo0O0Ooo
  if 28 - 28: ooOoO0o - IiII + iII111i . ooOoO0o % OoooooooOO
  if 17 - 17: OOooOOo / iII111i / IiII / OoO0O00 . I11i / o0oOOo0O0Ooo
  if 1 - 1: iIii1I11I1II1 + IiII % ooOoO0o + O0 / iIii1I11I1II1 % OoO0O00
  if 83 - 83: i11iIiiIii * II111iiii . i1IIi * I1Ii111
  i11oO0oOO000 = False
  OoOoO0O0oOo = self . privkey_filename
  if ( OoOoO0O0oOo != None and os . path . exists ( OoOoO0O0oOo ) ) :
   iiI1i1I = open ( OoOoO0O0oOo , "r" ) ; III11II111 = iiI1i1I . read ( ) ; iiI1i1I . close ( )
   try :
    III11II111 = ecdsa . SigningKey . from_pem ( III11II111 )
   except :
    return ( None )
    if 68 - 68: i11iIiiIii - OoOoOO00 . I11i % I1Ii111 + i11iIiiIii . OOooOOo
   Ii111I1iIiiIi = self . sign_map_request ( III11II111 )
   i11oO0oOO000 = True
  elif ( self . map_request_signature != None ) :
   oo0 = binascii . b2a_base64 ( self . map_request_signature )
   Ii111I1iIiiIi = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : oo0 }
   Ii111I1iIiiIi = json . dumps ( Ii111I1iIiiIi )
   i11oO0oOO000 = True
   if 45 - 45: IiII * Ii1I . o0oOOo0O0Ooo
  if ( i11oO0oOO000 ) :
   OO0Oo00OO0oo += self . encode_json ( Ii111I1iIiiIi )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    OO0Oo00OO0oo += self . source_eid . lcaf_encode_iid ( )
   else :
    OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    OO0Oo00OO0oo += self . source_eid . pack_address ( )
    if 68 - 68: Oo0Ooo + o0oOOo0O0Ooo * OOooOOo . II111iiii % Ii1I
    if 14 - 14: OoooooooOO * Oo0Ooo % ooOoO0o . Ii1I - iII111i - II111iiii
    if 67 - 67: iII111i
    if 69 - 69: OOooOOo + iII111i / I1Ii111
    if 37 - 37: iIii1I11I1II1 * I11i / IiII * Oo0Ooo % i11iIiiIii
    if 93 - 93: ooOoO0o + ooOoO0o
    if 65 - 65: OoooooooOO * I11i * oO0o % I1ii11iIi11i * II111iiii
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   Oo0o = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 86 - 86: i11iIiiIii / I11i * iII111i - iII111i
   if ( Oo0o in lisp_crypto_keys_by_rloc_encap ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ Oo0o ]
    if 32 - 32: Oo0Ooo . O0
    if 48 - 48: I1ii11iIi11i % II111iiii + I11i
    if 25 - 25: IiII * o0oOOo0O0Ooo / I1IiiI . IiII % II111iiii
    if 50 - 50: OoOoOO00 * iII111i
    if 59 - 59: I1IiiI * I1IiiI / I11i
    if 92 - 92: o0oOOo0O0Ooo
    if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
  for I1IoOO0oOOOOO0 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( I1IoOO0oOOOOO0 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     O0o0O0 = lisp_keys ( 1 )
     self . keys = [ None , O0o0O0 , None , None ]
     if 50 - 50: Oo0Ooo
    O0o0O0 = self . keys [ 1 ]
    O0o0O0 . add_key_by_nonce ( self . nonce )
    OO0Oo00OO0oo += O0o0O0 . encode_lcaf ( I1IoOO0oOOOOO0 )
   else :
    OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( I1IoOO0oOOOOO0 . afi ) )
    OO0Oo00OO0oo += I1IoOO0oOOOOO0 . pack_address ( )
    if 16 - 16: Ii1I - OoOoOO00 % Oo0Ooo / Ii1I . I11i + ooOoO0o
    if 78 - 78: iIii1I11I1II1 + OoO0O00 + i11iIiiIii
    if 21 - 21: Oo0Ooo + Ii1I % ooOoO0o + OoOoOO00 % I11i
    if 22 - 22: i1IIi / OoooooooOO . OoO0O00
    if 83 - 83: I1IiiI - OoooooooOO + I1ii11iIi11i . Ii1I / o0oOOo0O0Ooo + ooOoO0o
    if 90 - 90: I1IiiI - i11iIiiIii
  if ( Iiii1I != None ) :
   i1 = str ( time . time ( ) )
   Iiii1I = lisp_encode_telemetry ( Iiii1I , io = i1 )
   self . json_telemetry = Iiii1I
   OO0Oo00OO0oo += self . encode_json ( Iiii1I )
   if 42 - 42: OOooOOo . Oo0Ooo
   if 21 - 21: iII111i . I1IiiI / I11i
  ooOoO00 = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 61 - 61: i11iIiiIii % I1Ii111 / o0oOOo0O0Ooo
  if 40 - 40: OOooOOo / Ii1I % I1IiiI / o0oOOo0O0Ooo . iII111i
  o00o0Ooo = 0
  if ( self . subscribe_bit ) :
   o00o0Ooo = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 20 - 20: OoOoOO00 / o0oOOo0O0Ooo % OoOoOO00 * I1IiiI
    if 26 - 26: I11i . iII111i . o0oOOo0O0Ooo
    if 15 - 15: OoO0O00 / iII111i
  Iii1iIII1Iii = "BB"
  OO0Oo00OO0oo += struct . pack ( Iii1iIII1Iii , o00o0Ooo , ooOoO00 )
  if 46 - 46: OoooooooOO . I1Ii111
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
   if 15 - 15: Ii1I
   if 84 - 84: OoOoOO00 - ooOoO0o - OoooooooOO . OoooooooOO % IiII
   if 38 - 38: OoO0O00 * I1ii11iIi11i
   if 4 - 4: OoO0O00 . I1ii11iIi11i
   if 21 - 21: i11iIiiIii / OoO0O00 / I1ii11iIi11i * O0 - II111iiii * OOooOOo
  if ( self . subscribe_bit ) : OO0Oo00OO0oo = self . encode_xtr_id ( OO0Oo00OO0oo )
  return ( OO0Oo00OO0oo )
  if 27 - 27: o0oOOo0O0Ooo . OoOoOO00 * Ii1I * iII111i * O0
  if 93 - 93: IiII % I1Ii111 % II111iiii
 def lcaf_decode_json ( self , packet ) :
  Iii1iIII1Iii = "BBBBHH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 20 - 20: OoooooooOO * I1Ii111
  i1ii1iiI11ii1II1 , IIi1 , ooOoOoOo , oo0oOOo0 , iIi1IiiIII , i11iI1I1I11II = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  if 18 - 18: I1IiiI - I1ii11iIi11i * I11i / i11iIiiIii - o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if ( ooOoOoOo != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 31 - 31: I11i
  if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
  if 17 - 17: Ii1I * IiII * i11iIiiIii / I1ii11iIi11i / i11iIiiIii
  if 23 - 23: OoooooooOO + i11iIiiIii / Oo0Ooo / iII111i . iII111i * I1IiiI
  iIi1IiiIII = socket . ntohs ( iIi1IiiIII )
  i11iI1I1I11II = socket . ntohs ( i11iI1I1I11II )
  packet = packet [ oOoOo000Ooooo : : ]
  if ( len ( packet ) < iIi1IiiIII ) : return ( None )
  if ( iIi1IiiIII != i11iI1I1I11II + 4 ) : return ( None )
  if 98 - 98: IiII
  if 23 - 23: I11i / i1IIi * OoO0O00
  if 51 - 51: OOooOOo - OoooooooOO / OoooooooOO % OoooooooOO
  if 85 - 85: OoO0O00 . o0oOOo0O0Ooo . I1IiiI
  Ii111I1iIiiIi = packet [ 0 : i11iI1I1I11II ]
  packet = packet [ i11iI1I1I11II : : ]
  if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
  if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
  if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
  if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
  if ( lisp_is_json_telemetry ( Ii111I1iIiiIi ) != None ) :
   self . json_telemetry = Ii111I1iIiiIi
   if 24 - 24: IiII * I1IiiI / OOooOOo
   if 51 - 51: iIii1I11I1II1 / I11i * OoO0O00 * Ii1I + I1ii11iIi11i . OoooooooOO
   if 75 - 75: IiII / OoooooooOO / O0 % OOooOOo
   if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
   if 11 - 11: o0oOOo0O0Ooo * OoO0O00
  Iii1iIII1Iii = "H"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  O0ooO0O00oo0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if ( O0ooO0O00oo0 != 0 ) : return ( packet )
  if 92 - 92: OoOoOO00 . Oo0Ooo * I11i
  if ( self . json_telemetry != None ) : return ( packet )
  if 86 - 86: O0
  if 55 - 55: Ii1I / I1Ii111 / I1ii11iIi11i % ooOoO0o % I1IiiI
  if 55 - 55: oO0o + OoooooooOO % i1IIi
  if 24 - 24: I1ii11iIi11i - Oo0Ooo
  try :
   Ii111I1iIiiIi = json . loads ( Ii111I1iIiiIi )
  except :
   return ( None )
   if 36 - 36: I1IiiI . OOooOOo % II111iiii * IiII
   if 34 - 34: I11i % iII111i - ooOoO0o - I1IiiI
   if 44 - 44: Ii1I . o0oOOo0O0Ooo . iIii1I11I1II1 + OoooooooOO - I1IiiI
   if 22 - 22: I11i * I1ii11iIi11i . OoooooooOO / Oo0Ooo / Ii1I
   if 54 - 54: I1Ii111 % Ii1I + ooOoO0o
  if ( "source-eid" not in Ii111I1iIiiIi ) : return ( packet )
  I11I = Ii111I1iIiiIi [ "source-eid" ]
  O0ooO0O00oo0 = LISP_AFI_IPV4 if I11I . count ( "." ) == 3 else LISP_AFI_IPV6 if I11I . count ( ":" ) == 7 else None
  if 10 - 10: i1IIi % II111iiii / I1ii11iIi11i - oO0o % Oo0Ooo - iII111i
  if ( O0ooO0O00oo0 == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( I11I ) )
   return ( None )
   if 45 - 45: Oo0Ooo
   if 27 - 27: iII111i + Oo0Ooo * O0 / oO0o * i11iIiiIii
  self . source_eid . afi = O0ooO0O00oo0
  self . source_eid . store_address ( I11I )
  if 24 - 24: I11i
  if ( "signature-eid" not in Ii111I1iIiiIi ) : return ( packet )
  I11I = Ii111I1iIiiIi [ "signature-eid" ]
  if ( I11I . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( I11I ) )
   return ( None )
   if 9 - 9: i1IIi + oO0o
   if 14 - 14: O0 + I1ii11iIi11i
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( I11I )
  if 39 - 39: i11iIiiIii
  if ( "signature" not in Ii111I1iIiiIi ) : return ( packet )
  oo0 = binascii . a2b_base64 ( Ii111I1iIiiIi [ "signature" ] )
  self . map_request_signature = oo0
  return ( packet )
  if 97 - 97: OoOoOO00 . Oo0Ooo . I1Ii111 + iII111i % ooOoO0o . IiII
  if 40 - 40: I1Ii111 - i11iIiiIii
 def decode ( self , packet , source , port ) :
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 58 - 58: II111iiii / O0
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  oOOOoOO = oOOOoOO [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if 83 - 83: OOooOOo * IiII / OoO0O00 / i11iIiiIii
  Iii1iIII1Iii = "Q"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 94 - 94: O0 / iIii1I11I1II1 + O0 / I1IiiI
  OOO0O0O = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  packet = packet [ oOoOo000Ooooo : : ]
  if 90 - 90: OoooooooOO * OoooooooOO
  oOOOoOO = socket . ntohl ( oOOOoOO )
  self . auth_bit = True if ( oOOOoOO & 0x08000000 ) else False
  self . map_data_present = True if ( oOOOoOO & 0x04000000 ) else False
  self . rloc_probe = True if ( oOOOoOO & 0x02000000 ) else False
  self . smr_bit = True if ( oOOOoOO & 0x01000000 ) else False
  self . pitr_bit = True if ( oOOOoOO & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( oOOOoOO & 0x00400000 ) else False
  self . mobile_node = True if ( oOOOoOO & 0x00200000 ) else False
  self . xtr_id_present = True if ( oOOOoOO & 0x00100000 ) else False
  self . local_xtr = True if ( oOOOoOO & 0x00004000 ) else False
  self . dont_reply_bit = True if ( oOOOoOO & 0x00002000 ) else False
  self . itr_rloc_count = ( ( oOOOoOO >> 8 ) & 0x1f )
  self . record_count = oOOOoOO & 0xff
  self . nonce = OOO0O0O [ 0 ]
  if 47 - 47: OoOoOO00 - I1Ii111 + IiII . II111iiii / oO0o / i11iIiiIii
  if 28 - 28: I1IiiI . o0oOOo0O0Ooo + OoO0O00
  if 100 - 100: oO0o + II111iiii / IiII / i1IIi / Ii1I / O0
  if 50 - 50: Ii1I + Ii1I
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 51 - 51: I1ii11iIi11i / OoooooooOO * IiII
   if 78 - 78: iII111i / I1ii11iIi11i . i11iIiiIii
  oOoOo000Ooooo = struct . calcsize ( "H" )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 69 - 69: I11i - II111iiii
  O0ooO0O00oo0 = struct . unpack ( "H" , packet [ : oOoOo000Ooooo ] )
  self . source_eid . afi = socket . ntohs ( O0ooO0O00oo0 [ 0 ] )
  packet = packet [ oOoOo000Ooooo : : ]
  if 66 - 66: I1IiiI . I1IiiI - OoOoOO00 * OoooooooOO * II111iiii + I1IiiI
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   oOoOoOo0O0o = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( oOoOoOo0O0o )
    if ( packet == None ) : return ( None )
    if 46 - 46: II111iiii - Oo0Ooo + o0oOOo0O0Ooo + OOooOOo + IiII * II111iiii
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 42 - 42: Oo0Ooo % I1ii11iIi11i / iII111i
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 97 - 97: OOooOOo
  oOOooO = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  ooOO0O0OooO0 = self . itr_rloc_count + 1
  if 4 - 4: i1IIi / OoO0O00 / i1IIi - oO0o + i11iIiiIii - OoO0O00
  while ( ooOO0O0OooO0 != 0 ) :
   oOoOo000Ooooo = struct . calcsize ( "H" )
   if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
   if 71 - 71: I1Ii111 . OoooooooOO / IiII + oO0o * oO0o % Ii1I
   O0ooO0O00oo0 = socket . ntohs ( struct . unpack ( "H" , packet [ : oOoOo000Ooooo ] ) [ 0 ] )
   I1IoOO0oOOOOO0 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   I1IoOO0oOOOOO0 . afi = O0ooO0O00oo0
   if 46 - 46: i1IIi + OOooOOo % i11iIiiIii % OoOoOO00
   if 21 - 21: iII111i / OOooOOo % IiII
   if 51 - 51: I11i + ooOoO0o / I1IiiI
   if 3 - 3: iIii1I11I1II1 / OOooOOo % oO0o . Ii1I - Ii1I
   if 55 - 55: i11iIiiIii % OoooooooOO + O0
   if ( I1IoOO0oOOOOO0 . afi == LISP_AFI_LCAF ) :
    OOooo = packet
    I11ii1I1 = packet [ oOoOo000Ooooo : : ]
    packet = self . lcaf_decode_json ( I11ii1I1 )
    if ( packet == None ) : return ( None )
    if ( packet == I11ii1I1 ) : packet = OOooo
    if 51 - 51: I1ii11iIi11i % OoooooooOO - OoooooooOO . I11i
    if 97 - 97: i1IIi % I11i . o0oOOo0O0Ooo * I1IiiI % II111iiii
    if 41 - 41: I11i . I1ii11iIi11i
    if 69 - 69: O0 * ooOoO0o % ooOoO0o / oO0o
    if 2 - 2: oO0o % OoO0O00
    if 3 - 3: oO0o / OoO0O00 % i11iIiiIii
   if ( I1IoOO0oOOOOO0 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < I1IoOO0oOOOOO0 . addr_length ( ) ) : return ( None )
    packet = I1IoOO0oOOOOO0 . unpack_address ( packet [ oOoOo000Ooooo : : ] )
    if ( packet == None ) : return ( None )
    if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
    if ( oOOooO ) :
     self . itr_rlocs . append ( I1IoOO0oOOOOO0 )
     ooOO0O0OooO0 -= 1
     continue
     if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
     if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
    Oo0o = lisp_build_crypto_decap_lookup_key ( I1IoOO0oOOOOO0 , port )
    if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
    if 64 - 64: IiII
    if 21 - 21: o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO
    if 17 - 17: OOooOOo - iII111i % I1IiiI * OOooOOo * iIii1I11I1II1 . o0oOOo0O0Ooo
    if 58 - 58: oO0o - II111iiii + O0
    if ( lisp_nat_traversal and I1IoOO0oOOOOO0 . is_private_address ( ) and source ) : I1IoOO0oOOOOO0 = source
    if 54 - 54: iIii1I11I1II1 - IiII - IiII
    iiiiiI = lisp_crypto_keys_by_rloc_decap
    if ( Oo0o in iiiiiI ) : iiiiiI . pop ( Oo0o )
    if 46 - 46: ooOoO0o % OOooOOo + II111iiii * i1IIi
    if 81 - 81: oO0o - o0oOOo0O0Ooo + iII111i
    if 49 - 49: OoooooooOO
    if 74 - 74: OOooOOo - II111iiii
    if 66 - 66: i11iIiiIii + I1Ii111 . ooOoO0o
    if 46 - 46: I1Ii111 / I1ii11iIi11i
    lisp_write_ipc_decap_key ( Oo0o , None )
    if 41 - 41: i1IIi % Ii1I + I1Ii111 . Oo0Ooo / iIii1I11I1II1
   elif ( self . json_telemetry == None ) :
    if 77 - 77: Oo0Ooo . OoO0O00 % O0 - OoO0O00 - Oo0Ooo
    if 95 - 95: IiII * II111iiii % o0oOOo0O0Ooo * Oo0Ooo . I11i
    if 46 - 46: II111iiii - OoO0O00 % ooOoO0o
    if 97 - 97: OoO0O00 . OoOoOO00
    OOooo = packet
    OOoOOO = lisp_keys ( 1 )
    packet = OOoOOO . decode_lcaf ( OOooo , 0 )
    if 92 - 92: iIii1I11I1II1 * II111iiii . Oo0Ooo - OoO0O00 . i11iIiiIii - OoO0O00
    if ( packet == None ) : return ( None )
    if 8 - 8: I1ii11iIi11i * IiII / Oo0Ooo
    if 99 - 99: OOooOOo * I1Ii111 . ooOoO0o - i1IIi - I11i % IiII
    if 40 - 40: OoOoOO00 % I1Ii111 / I1IiiI + i1IIi
    if 53 - 53: I1Ii111
    OoOO0Ooo = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( OOoOOO . cipher_suite in OoOO0Ooo ) :
     if ( OOoOOO . cipher_suite == LISP_CS_25519_CBC or
 OOoOOO . cipher_suite == LISP_CS_25519_GCM ) :
      III11II111 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 81 - 81: O0 % o0oOOo0O0Ooo / Ii1I / ooOoO0o . i11iIiiIii + IiII
     if ( OOoOOO . cipher_suite == LISP_CS_25519_CHACHA ) :
      III11II111 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 29 - 29: ooOoO0o
    else :
     III11II111 = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 70 - 70: oO0o . O0 % I11i % IiII - I11i * I1ii11iIi11i
    packet = III11II111 . decode_lcaf ( OOooo , 0 )
    if ( packet == None ) : return ( None )
    if 22 - 22: i1IIi
    if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
    O0ooO0O00oo0 = struct . unpack ( "H" , packet [ : oOoOo000Ooooo ] ) [ 0 ]
    I1IoOO0oOOOOO0 . afi = socket . ntohs ( O0ooO0O00oo0 )
    if ( len ( packet ) < I1IoOO0oOOOOO0 . addr_length ( ) ) : return ( None )
    if 82 - 82: oO0o . iIii1I11I1II1 - I1ii11iIi11i
    packet = I1IoOO0oOOOOO0 . unpack_address ( packet [ oOoOo000Ooooo : : ] )
    if ( packet == None ) : return ( None )
    if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
    if ( oOOooO ) :
     self . itr_rlocs . append ( I1IoOO0oOOOOO0 )
     ooOO0O0OooO0 -= 1
     continue
     if 33 - 33: O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + iII111i - oO0o
     if 27 - 27: I1Ii111 + ooOoO0o - I1Ii111 % i11iIiiIii * Oo0Ooo * o0oOOo0O0Ooo
    Oo0o = lisp_build_crypto_decap_lookup_key ( I1IoOO0oOOOOO0 , port )
    if 88 - 88: OOooOOo
    IIiII1i = None
    if ( lisp_nat_traversal and I1IoOO0oOOOOO0 . is_private_address ( ) and source ) : I1IoOO0oOOOOO0 = source
    if 77 - 77: Ii1I - i11iIiiIii * I1Ii111 / iIii1I11I1II1 + i1IIi . O0
    if 20 - 20: OoO0O00 / OoOoOO00 . oO0o + O0
    if ( Oo0o in lisp_crypto_keys_by_rloc_decap ) :
     O0o0O0 = lisp_crypto_keys_by_rloc_decap [ Oo0o ]
     IIiII1i = O0o0O0 [ 1 ] if O0o0O0 and O0o0O0 [ 1 ] else None
     if 100 - 100: O0 / OOooOOo - ooOoO0o
     if 15 - 15: iII111i - O0 - OoooooooOO
    iiiiIIiiII1Iii1 = True
    if ( IIiII1i ) :
     if ( IIiII1i . compare_keys ( III11II111 ) ) :
      self . keys = [ None , IIiII1i , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( Oo0o , False ) ) )
      if 93 - 93: OoOoOO00 % Ii1I / Ii1I - ooOoO0o - IiII % ooOoO0o
     else :
      iiiiIIiiII1Iii1 = False
      IiIIiI1i1IIiI = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( IiIIiI1i1IIiI , red ( Oo0o ,
 False ) ) )
      III11II111 . copy_keypair ( IIiII1i )
      III11II111 . uptime = IIiII1i . uptime
      IIiII1i = None
      if 75 - 75: I1IiiI % II111iiii * oO0o % i1IIi % OOooOOo
      if 93 - 93: OoOoOO00
      if 48 - 48: i11iIiiIii
    if ( IIiII1i == None ) :
     self . keys = [ None , III11II111 , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      III11II111 . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( Oo0o , False ) ) )
     elif ( III11II111 . remote_public_key != None ) :
      if ( iiiiIIiiII1Iii1 ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # i11iIiiIii % I1IiiI
 red ( Oo0o , False ) ) )
       if 90 - 90: II111iiii
      III11II111 . compute_shared_key ( "decap" )
      III11II111 . add_key_by_rloc ( Oo0o , False )
      if 2 - 2: Ii1I - OoooooooOO - i11iIiiIii % Oo0Ooo / Ii1I
      if 77 - 77: o0oOOo0O0Ooo . o0oOOo0O0Ooo * I1Ii111 + OOooOOo - i11iIiiIii
      if 45 - 45: I1IiiI . I1IiiI - Oo0Ooo * OOooOOo
      if 71 - 71: i1IIi / I11i
   self . itr_rlocs . append ( I1IoOO0oOOOOO0 )
   ooOO0O0OooO0 -= 1
   if 14 - 14: OoooooooOO
   if 99 - 99: o0oOOo0O0Ooo * o0oOOo0O0Ooo
  oOoOo000Ooooo = struct . calcsize ( "BBH" )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 6 - 6: i11iIiiIii + oO0o % ooOoO0o + i11iIiiIii - OOooOOo
  o00o0Ooo , ooOoO00 , O0ooO0O00oo0 = struct . unpack ( "BBH" , packet [ : oOoOo000Ooooo ] )
  self . subscribe_bit = ( o00o0Ooo & 0x80 )
  self . target_eid . afi = socket . ntohs ( O0ooO0O00oo0 )
  packet = packet [ oOoOo000Ooooo : : ]
  if 12 - 12: iII111i . oO0o % IiII * OoooooooOO . IiII
  self . target_eid . mask_len = ooOoO00
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , iIi = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( iIi ) : self . target_group = iIi
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ oOoOo000Ooooo : : ]
   if 34 - 34: OoooooooOO
  return ( packet )
  if 40 - 40: I1ii11iIi11i . OoO0O00
  if 30 - 30: ooOoO0o % I1IiiI . oO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 48 - 48: OoOoOO00
  if 28 - 28: I11i / O0 * IiII - I1Ii111 % IiII
 def encode_xtr_id ( self , packet ) :
  OooOooo00OOO0o = self . xtr_id >> 64
  II1iIIiIII = self . xtr_id & 0xffffffffffffffff
  OooOooo00OOO0o = byte_swap_64 ( OooOooo00OOO0o )
  II1iIIiIII = byte_swap_64 ( II1iIIiIII )
  packet += struct . pack ( "QQ" , OooOooo00OOO0o , II1iIIiIII )
  return ( packet )
  if 8 - 8: I11i / I1ii11iIi11i % I1ii11iIi11i % Ii1I + iII111i
  if 100 - 100: OoO0O00
 def decode_xtr_id ( self , packet ) :
  oOoOo000Ooooo = struct . calcsize ( "QQ" )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  packet = packet [ len ( packet ) - oOoOo000Ooooo : : ]
  OooOooo00OOO0o , II1iIIiIII = struct . unpack ( "QQ" , packet [ : oOoOo000Ooooo ] )
  OooOooo00OOO0o = byte_swap_64 ( OooOooo00OOO0o )
  II1iIIiIII = byte_swap_64 ( II1iIIiIII )
  self . xtr_id = ( OooOooo00OOO0o << 64 ) | II1iIIiIII
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
  i11 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 89 - 89: OOooOOo
  lprint ( i11 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # O0 / iII111i
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 70 - 70: Oo0Ooo
  if 92 - 92: OOooOOo + i1IIi - ooOoO0o
 def encode ( self ) :
  oOOOoOO = ( LISP_MAP_REPLY << 28 ) | self . record_count
  oOOOoOO |= self . hop_count << 8
  if ( self . rloc_probe ) : oOOOoOO |= 0x08000000
  if ( self . echo_nonce_capable ) : oOOOoOO |= 0x04000000
  if ( self . security ) : oOOOoOO |= 0x02000000
  if 13 - 13: iII111i
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  return ( OO0Oo00OO0oo )
  if 79 - 79: OoooooooOO / OoO0O00 % Ii1I - OoOoOO00 * i1IIi + I1Ii111
  if 42 - 42: i11iIiiIii % I1Ii111 + i11iIiiIii % i11iIiiIii % I1ii11iIi11i
 def decode ( self , packet ) :
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 6 - 6: oO0o . o0oOOo0O0Ooo / I1IiiI
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  oOOOoOO = oOOOoOO [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if 64 - 64: iII111i
  Iii1iIII1Iii = "Q"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 65 - 65: O0 / II111iiii * IiII % Ii1I + o0oOOo0O0Ooo
  OOO0O0O = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  packet = packet [ oOoOo000Ooooo : : ]
  if 43 - 43: I1Ii111 + OoO0O00 * OoooooooOO
  oOOOoOO = socket . ntohl ( oOOOoOO )
  self . rloc_probe = True if ( oOOOoOO & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( oOOOoOO & 0x04000000 ) else False
  self . security = True if ( oOOOoOO & 0x02000000 ) else False
  self . hop_count = ( oOOOoOO >> 8 ) & 0xff
  self . record_count = oOOOoOO & 0xff
  self . nonce = OOO0O0O [ 0 ]
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
  O0ooO0O00oo0 = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  i11 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
  lprint ( i11 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 IIi1iiIII11 , "auth" if ( self . authoritative is True ) else "non-auth" ,
 oO00O0o0Oo , I1IIiIiIIiIiI , self . map_version , O0ooO0O00oo0 ,
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
  O0ooO0O00oo0 = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( O0ooO0O00oo0 < 0 ) : O0ooO0O00oo0 = LISP_AFI_LCAF
  I1iiIiI1II1ii = ( self . group . is_null ( ) == False )
  if ( I1iiIiI1II1ii ) : O0ooO0O00oo0 = LISP_AFI_LCAF
  if 10 - 10: O0 % I11i + I1ii11iIi11i - i11iIiiIii % i1IIi + II111iiii
  iii1IOO00OOOO00oOO = ( self . signature_count << 12 ) | self . map_version
  ooOoO00 = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 56 - 56: IiII * Ii1I . II111iiii / OoOoOO00
  OO0Oo00OO0oo = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , ooOoO00 , socket . htons ( oOoO0OooO0O ) ,
 socket . htons ( iii1IOO00OOOO00oOO ) , socket . htons ( O0ooO0O00oo0 ) )
  if 70 - 70: I1ii11iIi11i
  if 82 - 82: OoO0O00 + i11iIiiIii
  if 100 - 100: iIii1I11I1II1 % OOooOOo + ooOoO0o * Ii1I
  if 3 - 3: ooOoO0o
  if ( I1iiIiI1II1ii ) :
   OO0Oo00OO0oo += self . eid . lcaf_encode_sg ( self . group )
   return ( OO0Oo00OO0oo )
   if 64 - 64: I1ii11iIi11i % Oo0Ooo - iIii1I11I1II1 % OoO0O00 * iIii1I11I1II1 + I11i
   if 99 - 99: i11iIiiIii * I11i * I1Ii111
   if 28 - 28: iIii1I11I1II1 * iIii1I11I1II1 * ooOoO0o % I1ii11iIi11i / i11iIiiIii
   if 90 - 90: OoO0O00 + i1IIi
   if 43 - 43: O0 % oO0o * I1IiiI
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   OO0Oo00OO0oo = OO0Oo00OO0oo [ 0 : - 2 ]
   OO0Oo00OO0oo += self . eid . address . encode_geo ( )
   return ( OO0Oo00OO0oo )
   if 64 - 64: II111iiii + i11iIiiIii
   if 17 - 17: O0 * I1IiiI
   if 40 - 40: iIii1I11I1II1 * iII111i % iIii1I11I1II1
   if 39 - 39: i1IIi . Ii1I - Oo0Ooo
   if 91 - 91: I1IiiI - OoooooooOO - OoooooooOO
  if ( O0ooO0O00oo0 == LISP_AFI_LCAF ) :
   OO0Oo00OO0oo += self . eid . lcaf_encode_iid ( )
   return ( OO0Oo00OO0oo )
   if 69 - 69: iII111i * i11iIiiIii / i1IIi
   if 86 - 86: I1IiiI % I11i * O0 + i1IIi % I1Ii111
   if 97 - 97: II111iiii * OoOoOO00 - I1Ii111 / i11iIiiIii / OoOoOO00
   if 25 - 25: Oo0Ooo / Oo0Ooo
   if 74 - 74: OOooOOo
  OO0Oo00OO0oo += self . eid . pack_address ( )
  return ( OO0Oo00OO0oo )
  if 30 - 30: O0 . Ii1I / o0oOOo0O0Ooo + I1IiiI - O0
  if 88 - 88: i11iIiiIii
 def decode ( self , packet ) :
  Iii1iIII1Iii = "IBBHHH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 33 - 33: OoO0O00 + O0
  self . record_ttl , self . rloc_count , self . eid . mask_len , oOoO0OooO0O , self . map_version , self . eid . afi = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 20 - 20: o0oOOo0O0Ooo % I11i . ooOoO0o - i1IIi . O0
  if 10 - 10: i1IIi
  if 49 - 49: I1Ii111 - Ii1I . O0
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
  packet = packet [ oOoOo000Ooooo : : ]
  if 46 - 46: OOooOOo
  if 64 - 64: I1IiiI / OoOoOO00
  if 6 - 6: i11iIiiIii - iII111i * i1IIi - iII111i
  if 8 - 8: I11i / i11iIiiIii . O0 / OoO0O00 * oO0o + I1Ii111
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , o0o0o = self . eid . lcaf_decode_eid ( packet )
   if ( o0o0o ) : self . group = o0o0o
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 79 - 79: OoO0O00
   if 4 - 4: I11i / I1ii11iIi11i
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
  if 14 - 14: Oo0Ooo . O0 - oO0o - i11iIiiIii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 16 - 16: IiII * OoO0O00 * i11iIiiIii - ooOoO0o
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
  if 88 - 88: iIii1I11I1II1 / Ii1I * IiII / I1Ii111
  if 31 - 31: O0 . I1IiiI
 def print_ecm ( self ) :
  i11 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 8 - 8: OoOoOO00
  lprint ( i11 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 99 - 99: iII111i
  if 93 - 93: I1Ii111
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 39 - 39: Ii1I
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 10 - 10: OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i % iII111i / i11iIiiIii
   if 14 - 14: i11iIiiIii % o0oOOo0O0Ooo * O0 % iIii1I11I1II1 . IiII - II111iiii
   if 14 - 14: Ii1I % ooOoO0o - OoOoOO00
   if 52 - 52: OoO0O00 / i1IIi - Ii1I
   if 8 - 8: oO0o + ooOoO0o . I1ii11iIi11i . i1IIi / I1IiiI . IiII
   if 8 - 8: i1IIi * O0
  oOOOoOO = ( LISP_ECM << 28 )
  if ( self . security ) : oOOOoOO |= 0x08000000
  if ( self . ddt ) : oOOOoOO |= 0x04000000
  if ( self . to_etr ) : oOOOoOO |= 0x02000000
  if ( self . to_ms ) : oOOOoOO |= 0x01000000
  if 60 - 60: Oo0Ooo - II111iiii + I1IiiI
  iIiiiII11II = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  if 71 - 71: I1Ii111 - OoO0O00
  o0OO00oo0O = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   o0OO00oo0O = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   o0OO00oo0O += self . source . pack_address ( )
   o0OO00oo0O += self . dest . pack_address ( )
   o0OO00oo0O = lisp_ip_checksum ( o0OO00oo0O )
   if 61 - 61: I1ii11iIi11i * i11iIiiIii * ooOoO0o . I11i
  if ( self . afi == LISP_AFI_IPV6 ) :
   o0OO00oo0O = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   o0OO00oo0O += self . source . pack_address ( )
   o0OO00oo0O += self . dest . pack_address ( )
   if 35 - 35: I1Ii111 * Oo0Ooo / o0oOOo0O0Ooo
   if 89 - 89: oO0o / OoooooooOO . Ii1I + Oo0Ooo + IiII / OoOoOO00
  I1iiIi111I = socket . htons ( self . udp_sport )
  iiIi = socket . htons ( self . udp_dport )
  i1IIiI1iII = socket . htons ( self . udp_length )
  I1 = socket . htons ( self . udp_checksum )
  Ii1iiI1 = struct . pack ( "HHHH" , I1iiIi111I , iiIi , i1IIiI1iII , I1 )
  return ( iIiiiII11II + o0OO00oo0O + Ii1iiI1 )
  if 67 - 67: IiII
  if 66 - 66: i11iIiiIii * iII111i
 def decode ( self , packet ) :
  if 51 - 51: OoooooooOO + I11i . iII111i + i11iIiiIii * iII111i - OoO0O00
  if 60 - 60: iII111i * iIii1I11I1II1 . OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
  if 36 - 36: i1IIi . OoooooooOO - II111iiii - OoOoOO00 - IiII
  if 53 - 53: I1ii11iIi11i - II111iiii . i11iIiiIii
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 76 - 76: iIii1I11I1II1 - Oo0Ooo
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 79 - 79: I1IiiI * IiII . OoooooooOO % I1Ii111 * I1Ii111
  oOOOoOO = socket . ntohl ( oOOOoOO [ 0 ] )
  self . security = True if ( oOOOoOO & 0x08000000 ) else False
  self . ddt = True if ( oOOOoOO & 0x04000000 ) else False
  self . to_etr = True if ( oOOOoOO & 0x02000000 ) else False
  self . to_ms = True if ( oOOOoOO & 0x01000000 ) else False
  packet = packet [ oOoOo000Ooooo : : ]
  if 17 - 17: I1Ii111 - I1Ii111 . oO0o / I1Ii111
  if 36 - 36: I1ii11iIi11i * i1IIi + iIii1I11I1II1
  if 55 - 55: I1IiiI . I1Ii111 - I1IiiI % oO0o / iIii1I11I1II1 * Ii1I
  if 77 - 77: OOooOOo
  if ( len ( packet ) < 1 ) : return ( None )
  I1iI1Ii11 = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  I1iI1Ii11 = I1iI1Ii11 >> 4
  if 29 - 29: II111iiii % iIii1I11I1II1 * O0 . o0oOOo0O0Ooo
  if ( I1iI1Ii11 == 4 ) :
   oOoOo000Ooooo = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
   if 56 - 56: i1IIi . ooOoO0o + I11i - i11iIiiIii
   ooooO00o0 , i1IIiI1iII , ooooO00o0 , Ii1I111Ii , o00oo , I1 = struct . unpack ( "HHIBBH" , packet [ : oOoOo000Ooooo ] )
   self . length = socket . ntohs ( i1IIiI1iII )
   self . ttl = Ii1I111Ii
   self . protocol = o00oo
   self . ip_checksum = socket . ntohs ( I1 )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 77 - 77: I1ii11iIi11i / iII111i % OoO0O00 - oO0o
   if 69 - 69: oO0o . i11iIiiIii - O0
   if 5 - 5: i1IIi + Ii1I
   if 38 - 38: I1IiiI . O0 + OOooOOo / I1ii11iIi11i . iIii1I11I1II1 - i1IIi
   o00oo = struct . pack ( "H" , 0 )
   iIII1ii = struct . calcsize ( "HHIBB" )
   oo0ooo00oooo = struct . calcsize ( "H" )
   packet = packet [ : iIII1ii ] + o00oo + packet [ iIII1ii + oo0ooo00oooo : ]
   if 9 - 9: I11i / I1Ii111 + iIii1I11I1II1 + I1IiiI - II111iiii
   packet = packet [ oOoOo000Ooooo : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 96 - 96: iII111i + Oo0Ooo - OoooooooOO . i1IIi + i1IIi % iIii1I11I1II1
   if 80 - 80: OoooooooOO / O0 / I1Ii111 - Oo0Ooo . i11iIiiIii
  if ( I1iI1Ii11 == 6 ) :
   oOoOo000Ooooo = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
   if 3 - 3: Oo0Ooo - OOooOOo * OoO0O00 - II111iiii . OoooooooOO
   ooooO00o0 , i1IIiI1iII , o00oo , Ii1I111Ii = struct . unpack ( "IHBB" , packet [ : oOoOo000Ooooo ] )
   self . length = socket . ntohs ( i1IIiI1iII )
   self . protocol = o00oo
   self . ttl = Ii1I111Ii
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 14 - 14: I1IiiI
   packet = packet [ oOoOo000Ooooo : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 41 - 41: I1Ii111 % i1IIi + OoO0O00 / oO0o
   if 48 - 48: i1IIi . Oo0Ooo . i1IIi . I1ii11iIi11i * I1IiiI - Ii1I
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 83 - 83: OoooooooOO
  oOoOo000Ooooo = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 42 - 42: I1ii11iIi11i . i1IIi - OoOoOO00 - oO0o + i11iIiiIii
  I1iiIi111I , iiIi , i1IIiI1iII , I1 = struct . unpack ( "HHHH" , packet [ : oOoOo000Ooooo ] )
  self . udp_sport = socket . ntohs ( I1iiIi111I )
  self . udp_dport = socket . ntohs ( iiIi )
  self . udp_length = socket . ntohs ( i1IIiI1iII )
  self . udp_checksum = socket . ntohs ( I1 )
  packet = packet [ oOoOo000Ooooo : : ]
  return ( packet )
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
  o00oO = self . print_rloc_name ( )
  if ( o00oO != "" ) : o00oO = ", " + o00oO
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
  ooOo = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   ooOo = ", " + self . keys [ 1 ] . print_keys ( )
   if 74 - 74: o0oOOo0O0Ooo % oO0o % iII111i / I1ii11iIi11i / O0 % I1Ii111
   if 48 - 48: i11iIiiIii + I11i
  i11 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( i11 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , o00oO , oOIIi ,
 iIII1Iiii , IIIi1iI1 , IiiiIiii , ooOo ) )
  if 60 - 60: OoOoOO00 + i11iIiiIii
  if 3 - 3: II111iiii
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 72 - 72: I1Ii111 * OoO0O00 + Oo0Ooo / Ii1I % OOooOOo
  if 84 - 84: OoOoOO00 / o0oOOo0O0Ooo
  if 9 - 9: Ii1I
 def store_rloc_entry ( self , rloc_entry ) :
  OooOOoOO0OO = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 50 - 50: OOooOOo + iIii1I11I1II1
  self . rloc . copy_address ( OooOOoOO0OO )
  if 76 - 76: iIii1I11I1II1 + I1ii11iIi11i + iIii1I11I1II1 + OoO0O00
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 83 - 83: i1IIi + Oo0Ooo . O0 / IiII - II111iiii + ooOoO0o
   if 17 - 17: OOooOOo
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   ooO0o = rloc_entry . geo_name
   if ( ooO0o and ooO0o in lisp_geo_list ) :
    self . geo = lisp_geo_list [ ooO0o ]
    if 93 - 93: Oo0Ooo / II111iiii . Oo0Ooo + i1IIi + i1IIi
    if 30 - 30: OoOoOO00 . OOooOOo % OOooOOo / II111iiii + i1IIi
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   ooO0o = rloc_entry . elp_name
   if ( ooO0o and ooO0o in lisp_elp_list ) :
    self . elp = lisp_elp_list [ ooO0o ]
    if 61 - 61: i1IIi % II111iiii * II111iiii . o0oOOo0O0Ooo / I1ii11iIi11i - I1Ii111
    if 93 - 93: Ii1I - i1IIi
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   ooO0o = rloc_entry . rle_name
   if ( ooO0o and ooO0o in lisp_rle_list ) :
    self . rle = lisp_rle_list [ ooO0o ]
    if 3 - 3: oO0o + OoO0O00 - iII111i / Ii1I
    if 58 - 58: Ii1I * I11i
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   ooO0o = rloc_entry . json_name
   if ( ooO0o and ooO0o in lisp_json_list ) :
    self . json = lisp_json_list [ ooO0o ]
    if 95 - 95: oO0o
    if 49 - 49: I1IiiI
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 23 - 23: I1Ii111
  if 5 - 5: I1ii11iIi11i % OoOoOO00 . OoooooooOO . o0oOOo0O0Ooo + i11iIiiIii
 def encode_json ( self , lisp_json ) :
  Ii111I1iIiiIi = lisp_json . json_string
  o0Oo0OOO0 = 0
  if ( lisp_json . json_encrypted ) :
   o0Oo0OOO0 = ( lisp_json . json_key_id << 5 ) | 0x02
   if 73 - 73: OoOoOO00 % oO0o / O0 - OoooooooOO
   if 87 - 87: iIii1I11I1II1
  ooOoOoOo = LISP_LCAF_JSON_TYPE
  O0oOo = socket . htons ( LISP_AFI_LCAF )
  I1I1IIi11II = self . rloc . addr_length ( ) + 2
  if 64 - 64: I11i * i1IIi + i1IIi * I1ii11iIi11i . ooOoO0o
  iIi1IiiIII = socket . htons ( len ( Ii111I1iIiiIi ) + I1I1IIi11II )
  if 37 - 37: I11i % iIii1I11I1II1 % I1ii11iIi11i
  i11iI1I1I11II = socket . htons ( len ( Ii111I1iIiiIi ) )
  OO0Oo00OO0oo = struct . pack ( "HBBBBHH" , O0oOo , 0 , 0 , ooOoOoOo , o0Oo0OOO0 ,
 iIi1IiiIII , i11iI1I1I11II )
  OO0Oo00OO0oo += Ii111I1iIiiIi
  if 61 - 61: o0oOOo0O0Ooo * O0
  if 84 - 84: I11i * oO0o
  if 89 - 89: o0oOOo0O0Ooo
  if 95 - 95: i1IIi . OoOoOO00 % OoOoOO00 + OOooOOo / OoooooooOO
  if ( lisp_is_json_telemetry ( Ii111I1iIiiIi ) ) :
   OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   OO0Oo00OO0oo += self . rloc . pack_address ( )
  else :
   OO0Oo00OO0oo += struct . pack ( "H" , 0 )
   if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
  return ( OO0Oo00OO0oo )
  if 85 - 85: O0 - OoOoOO00
  if 17 - 17: o0oOOo0O0Ooo / i1IIi / OOooOOo
 def encode_lcaf ( self ) :
  O0oOo = socket . htons ( LISP_AFI_LCAF )
  OOO0 = b""
  if ( self . geo ) :
   OOO0 = self . geo . encode_geo ( )
   if 13 - 13: I11i / OoooooooOO - I1Ii111
   if 78 - 78: iII111i . oO0o . I1IiiI % O0 * ooOoO0o % I1Ii111
  ii1111I = b""
  if ( self . elp ) :
   IIii11 = ""
   for oO0 in self . elp . elp_nodes :
    O0ooO0O00oo0 = socket . htons ( oO0 . address . afi )
    IIi1 = 0
    if ( oO0 . eid ) : IIi1 |= 0x4
    if ( oO0 . probe ) : IIi1 |= 0x2
    if ( oO0 . strict ) : IIi1 |= 0x1
    IIi1 = socket . htons ( IIi1 )
    IIii11 += struct . pack ( "HH" , IIi1 , O0ooO0O00oo0 )
    IIii11 += oO0 . address . pack_address ( )
    if 61 - 61: Ii1I
    if 48 - 48: I1IiiI - i11iIiiIii * I1ii11iIi11i
   oOOO0o0O00OO = socket . htons ( len ( IIii11 ) )
   ii1111I = struct . pack ( "HBBBBH" , O0oOo , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , oOOO0o0O00OO )
   ii1111I += IIii11
   if 90 - 90: I1Ii111 * OoO0O00
   if 51 - 51: i1IIi
  oOOoOooo0oOO0 = b""
  if ( self . rle ) :
   o00o0O0oo = ""
   for IIIi11i1 in self . rle . rle_nodes :
    O0ooO0O00oo0 = socket . htons ( IIIi11i1 . address . afi )
    o00o0O0oo += struct . pack ( "HBBH" , 0 , 0 , IIIi11i1 . level , O0ooO0O00oo0 )
    o00o0O0oo += IIIi11i1 . address . pack_address ( )
    if ( IIIi11i1 . rloc_name ) :
     o00o0O0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     o00o0O0oo += ( IIIi11i1 . rloc_name + "\0" ) . encode ( )
     if 67 - 67: II111iiii
     if 81 - 81: oO0o . Oo0Ooo + O0 * o0oOOo0O0Ooo % OOooOOo
     if 98 - 98: oO0o / iIii1I11I1II1 - OoOoOO00
   I1Ii1i111I = socket . htons ( len ( o00o0O0oo ) )
   oOOoOooo0oOO0 = struct . pack ( "HBBBBH" , O0oOo , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , I1Ii1i111I )
   oOOoOooo0oOO0 += o00o0O0oo
   if 51 - 51: O0 + Ii1I * OoooooooOO . oO0o + OoooooooOO
   if 58 - 58: ooOoO0o . Oo0Ooo / I1ii11iIi11i + OoO0O00 * OoooooooOO / I1IiiI
  iii11i11 = b""
  if ( self . json ) :
   iii11i11 = self . encode_json ( self . json )
   if 80 - 80: II111iiii / iIii1I11I1II1 - OoO0O00 . I11i / II111iiii
   if 20 - 20: o0oOOo0O0Ooo % i1IIi / Oo0Ooo / I11i * Oo0Ooo
  oOOoOO = b""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   oOOoOO = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 63 - 63: I1IiiI
   if 3 - 3: iII111i + I1ii11iIi11i
  II111I1111iI = b""
  if ( self . rloc_name ) :
   II111I1111iI += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   II111I1111iI += ( self . rloc_name + "\0" ) . encode ( )
   if 91 - 91: I1IiiI + O0 / OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
   if 77 - 77: iIii1I11I1II1 + OoOoOO00 - ooOoO0o * oO0o % OoO0O00
  IIIii1I = len ( OOO0 ) + len ( ii1111I ) + len ( oOOoOooo0oOO0 ) + len ( oOOoOO ) + 2 + len ( iii11i11 ) + self . rloc . addr_length ( ) + len ( II111I1111iI )
  if 86 - 86: IiII * O0 + oO0o * I1Ii111
  IIIii1I = socket . htons ( IIIii1I )
  II11oOOOoO = struct . pack ( "HBBBBHH" , O0oOo , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , IIIii1I , socket . htons ( self . rloc . afi ) )
  II11oOOOoO += self . rloc . pack_address ( )
  return ( II11oOOOoO + II111I1111iI + OOO0 + ii1111I + oOOoOooo0oOO0 + oOOoOO + iii11i11 )
  if 8 - 8: i11iIiiIii + OoOoOO00 . I1ii11iIi11i / OoooooooOO % II111iiii
  if 21 - 21: oO0o - o0oOOo0O0Ooo + ooOoO0o . I1IiiI * oO0o * Ii1I
 def encode ( self ) :
  IIi1 = 0
  if ( self . local_bit ) : IIi1 |= 0x0004
  if ( self . probe_bit ) : IIi1 |= 0x0002
  if ( self . reach_bit ) : IIi1 |= 0x0001
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
  OO0Oo00OO0oo = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( IIi1 ) ,
 socket . htons ( self . rloc . afi ) )
  if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
   OO0Oo00OO0oo = OO0Oo00OO0oo [ 0 : - 2 ] + self . encode_lcaf ( )
  else :
   OO0Oo00OO0oo += self . rloc . pack_address ( )
   if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
  return ( OO0Oo00OO0oo )
  if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
  if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
 def decode_lcaf ( self , packet , nonce , ms_json_encrypt ) :
  Iii1iIII1Iii = "HBBBBH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 86 - 86: IiII
  O0ooO0O00oo0 , i1ii1iiI11ii1II1 , IIi1 , ooOoOoOo , oo0oOOo0 , iIi1IiiIII = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 71 - 71: Ii1I - i1IIi . I1IiiI
  if 15 - 15: i1IIi % II111iiii / II111iiii - I1ii11iIi11i - I11i % i1IIi
  iIi1IiiIII = socket . ntohs ( iIi1IiiIII )
  packet = packet [ oOoOo000Ooooo : : ]
  if ( iIi1IiiIII > len ( packet ) ) : return ( None )
  if 54 - 54: i1IIi . OoO0O00 + iII111i + OoO0O00 * i1IIi
  if 13 - 13: Oo0Ooo / OoO0O00 + OOooOOo
  if 90 - 90: OoO0O00 * i11iIiiIii / oO0o
  if 91 - 91: iII111i - OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
  if ( ooOoOoOo == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( iIi1IiiIII > 0 ) :
    Iii1iIII1Iii = "H"
    oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
    if ( iIi1IiiIII < oOoOo000Ooooo ) : return ( None )
    if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
    o0oOO00O000O0 = len ( packet )
    O0ooO0O00oo0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
    O0ooO0O00oo0 = socket . ntohs ( O0ooO0O00oo0 )
    if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
    if ( O0ooO0O00oo0 == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ oOoOo000Ooooo : : ]
     self . rloc_name = None
     if ( O0ooO0O00oo0 == LISP_AFI_NAME ) :
      packet , oOo = lisp_decode_dist_name ( packet )
      self . rloc_name = oOo
     else :
      self . rloc . afi = O0ooO0O00oo0
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 87 - 87: I1IiiI + OoooooooOO + O0
      if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
      if 65 - 65: IiII
    iIi1IiiIII -= o0oOO00O000O0 - len ( packet )
    if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
    if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
  elif ( ooOoOoOo == LISP_LCAF_GEO_COORD_TYPE ) :
   if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
   if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
   if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
   if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
   iII1I11iI = lisp_geo ( "" )
   packet = iII1I11iI . decode_geo ( packet , iIi1IiiIII , oo0oOOo0 )
   if ( packet == None ) : return ( None )
   self . geo = iII1I11iI
   if 14 - 14: I1ii11iIi11i * oO0o . O0
  elif ( ooOoOoOo == LISP_LCAF_JSON_TYPE ) :
   Ooo0O00o00 = oo0oOOo0 & 0x02
   if 63 - 63: O0 * O0 . IiII
   if 54 - 54: I1IiiI / i1IIi * I1ii11iIi11i
   if 10 - 10: I1IiiI % II111iiii / I1IiiI
   if 13 - 13: II111iiii - i11iIiiIii
   Iii1iIII1Iii = "H"
   oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
   if ( iIi1IiiIII < oOoOo000Ooooo ) : return ( None )
   if 90 - 90: I11i . OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
   i11iI1I1I11II = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
   i11iI1I1I11II = socket . ntohs ( i11iI1I1I11II )
   if ( iIi1IiiIII < oOoOo000Ooooo + i11iI1I1I11II ) : return ( None )
   if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
   packet = packet [ oOoOo000Ooooo : : ]
   self . json = lisp_json ( "" , packet [ 0 : i11iI1I1I11II ] , Ooo0O00o00 ,
 ms_json_encrypt )
   packet = packet [ i11iI1I1I11II : : ]
   if 95 - 95: iII111i / ooOoO0o + I1Ii111
   if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
   if 81 - 81: I1ii11iIi11i
   if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
   O0ooO0O00oo0 = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 76 - 76: I1Ii111 - O0
   if ( O0ooO0O00oo0 != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = O0ooO0O00oo0
    packet = self . rloc . unpack_address ( packet )
    if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
    if 7 - 7: II111iiii + I11i
  elif ( ooOoOoOo == LISP_LCAF_ELP_TYPE ) :
   if 99 - 99: iIii1I11I1II1 * oO0o
   if 37 - 37: ooOoO0o * iII111i * I11i
   if 11 - 11: I1IiiI
   if 48 - 48: O0 . I11i
   iII11 = lisp_elp ( None )
   iII11 . elp_nodes = [ ]
   while ( iIi1IiiIII > 0 ) :
    IIi1 , O0ooO0O00oo0 = struct . unpack ( "HH" , packet [ : 4 ] )
    if 33 - 33: O0
    O0ooO0O00oo0 = socket . ntohs ( O0ooO0O00oo0 )
    if ( O0ooO0O00oo0 == LISP_AFI_LCAF ) : return ( None )
    if 31 - 31: OoO0O00
    oO0 = lisp_elp_node ( )
    iII11 . elp_nodes . append ( oO0 )
    if 9 - 9: oO0o * OoO0O00 * I1IiiI - I1IiiI % OoO0O00
    IIi1 = socket . ntohs ( IIi1 )
    oO0 . eid = ( IIi1 & 0x4 )
    oO0 . probe = ( IIi1 & 0x2 )
    oO0 . strict = ( IIi1 & 0x1 )
    oO0 . address . afi = O0ooO0O00oo0
    oO0 . address . mask_len = oO0 . address . host_mask_len ( )
    packet = oO0 . address . unpack_address ( packet [ 4 : : ] )
    iIi1IiiIII -= oO0 . address . addr_length ( ) + 4
    if 84 - 84: I1IiiI % I1IiiI * Ii1I
   iII11 . select_elp_node ( )
   self . elp = iII11
   if 75 - 75: iIii1I11I1II1 - I1Ii111
  elif ( ooOoOoOo == LISP_LCAF_RLE_TYPE ) :
   if 86 - 86: O0 + O0 / I11i - iIii1I11I1II1
   if 42 - 42: OOooOOo
   if 39 - 39: O0 % Ii1I . I11i * o0oOOo0O0Ooo
   if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
   IIiiiI = lisp_rle ( None )
   IIiiiI . rle_nodes = [ ]
   while ( iIi1IiiIII > 0 ) :
    ooooO00o0 , IIi11I , iII111iI , O0ooO0O00oo0 = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
    O0ooO0O00oo0 = socket . ntohs ( O0ooO0O00oo0 )
    if ( O0ooO0O00oo0 == LISP_AFI_LCAF ) : return ( None )
    if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
    IIIi11i1 = lisp_rle_node ( )
    IIiiiI . rle_nodes . append ( IIIi11i1 )
    if 30 - 30: i11iIiiIii % OOooOOo
    IIIi11i1 . level = iII111iI
    IIIi11i1 . address . afi = O0ooO0O00oo0
    IIIi11i1 . address . mask_len = IIIi11i1 . address . host_mask_len ( )
    packet = IIIi11i1 . address . unpack_address ( packet [ 6 : : ] )
    if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
    iIi1IiiIII -= IIIi11i1 . address . addr_length ( ) + 6
    if ( iIi1IiiIII >= 2 ) :
     O0ooO0O00oo0 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( O0ooO0O00oo0 ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , IIIi11i1 . rloc_name = lisp_decode_dist_name ( packet )
      if 27 - 27: I1IiiI + OoOoOO00 + iII111i
      if ( packet == None ) : return ( None )
      iIi1IiiIII -= len ( IIIi11i1 . rloc_name ) + 1 + 2
      if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
      if 34 - 34: i1IIi % Oo0Ooo . oO0o
      if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
   self . rle = IIiiiI
   self . rle . build_forwarding_list ( )
   if 62 - 62: Oo0Ooo . OoO0O00 * I1Ii111 . i11iIiiIii * O0
  elif ( ooOoOoOo == LISP_LCAF_SECURITY_TYPE ) :
   if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
   if 62 - 62: I1IiiI . Ii1I
   if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
   if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
   if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
   OOooo = packet
   OOoOOO = lisp_keys ( 1 )
   packet = OOoOOO . decode_lcaf ( OOooo , iIi1IiiIII , False )
   if ( packet == None ) : return ( None )
   if 52 - 52: Ii1I - I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo
   if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
   if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
   if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
   OoOO0Ooo = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( OOoOOO . cipher_suite in OoOO0Ooo ) :
    if ( OOoOOO . cipher_suite == LISP_CS_25519_CBC ) :
     III11II111 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 40 - 40: OoOoOO00 - II111iiii
    if ( OOoOOO . cipher_suite == LISP_CS_25519_CHACHA ) :
     III11II111 = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 29 - 29: I1IiiI - O0
   else :
    III11II111 = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 36 - 36: I1IiiI * I1IiiI
   packet = III11II111 . decode_lcaf ( OOooo , iIi1IiiIII , False )
   if ( packet == None ) : return ( None )
   if 79 - 79: I1Ii111 - I11i
   if ( len ( packet ) < 2 ) : return ( None )
   O0ooO0O00oo0 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( O0ooO0O00oo0 )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 49 - 49: II111iiii + O0 * ooOoO0o - Oo0Ooo
   if 89 - 89: I1IiiI + I11i . oO0o . II111iiii + oO0o / Oo0Ooo
   if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
   if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
   if 18 - 18: II111iiii . o0oOOo0O0Ooo
   if 75 - 75: OoooooooOO - Oo0Ooo
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 56 - 56: II111iiii - i11iIiiIii - oO0o . o0oOOo0O0Ooo
   i1IiOo0OO0o = self . rloc_name
   if ( i1IiOo0OO0o ) : i1IiOo0OO0o = blue ( self . rloc_name , False )
   if 35 - 35: i11iIiiIii + i1IIi
   if 16 - 16: OoO0O00 - I1Ii111 * iII111i
   if 41 - 41: i11iIiiIii + i1IIi / IiII * I1ii11iIi11i / iIii1I11I1II1
   if 70 - 70: I1IiiI % oO0o + iII111i % i11iIiiIii + ooOoO0o
   if 88 - 88: I11i * oO0o * I1ii11iIi11i - OOooOOo * IiII + o0oOOo0O0Ooo
   if 9 - 9: OoooooooOO
   IIiII1i = self . keys [ 1 ] if self . keys else None
   if ( IIiII1i == None ) :
    if ( III11II111 . remote_public_key == None ) :
     Oo0OOOOOOO0oo = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( Oo0OOOOOOO0oo , i1IiOo0OO0o ) )
     III11II111 = None
    else :
     Oo0OOOOOOO0oo = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( Oo0OOOOOOO0oo , i1IiOo0OO0o ) )
     III11II111 . compute_shared_key ( "encap" )
     if 26 - 26: OoOoOO00 + II111iiii - OoO0O00 + iII111i - iII111i % O0
     if 79 - 79: iIii1I11I1II1 - OoOoOO00 - O0 + I1ii11iIi11i
     if 69 - 69: oO0o % OoooooooOO
     if 21 - 21: I1Ii111
     if 62 - 62: Ii1I % o0oOOo0O0Ooo
     if 65 - 65: OoO0O00 + Oo0Ooo + IiII / OoOoOO00
     if 37 - 37: oO0o - I11i
     if 64 - 64: OoO0O00 * OoOoOO00
     if 50 - 50: I1ii11iIi11i + I11i * iII111i
     if 27 - 27: OoOoOO00 * OOooOOo * iIii1I11I1II1 / i1IIi
   if ( IIiII1i ) :
    if ( III11II111 . remote_public_key == None ) :
     III11II111 = None
     IiIIiI1i1IIiI = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( IiIIiI1i1IIiI , i1IiOo0OO0o ) )
    elif ( IIiII1i . compare_keys ( III11II111 ) ) :
     III11II111 = IIiII1i
     lprint ( "    Maintain stored encap-keys for {}" . format ( i1IiOo0OO0o ) )
     if 60 - 60: OOooOOo * I1Ii111 . oO0o
    else :
     if ( IIiII1i . remote_public_key == None ) :
      Oo0OOOOOOO0oo = "New encap-keying for existing state"
     else :
      Oo0OOOOOOO0oo = "Remote encap-rekeying"
      if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
     lprint ( "    {} for {}" . format ( bold ( Oo0OOOOOOO0oo , False ) ,
 i1IiOo0OO0o ) )
     IIiII1i . remote_public_key = III11II111 . remote_public_key
     IIiII1i . compute_shared_key ( "encap" )
     III11II111 = IIiII1i
     if 51 - 51: I1IiiI . I11i - OoOoOO00
     if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
   self . keys = [ None , III11II111 , None , None ]
   if 97 - 97: Ii1I . Ii1I % iII111i
  else :
   if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
   if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
   if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
   if 25 - 25: I11i - I1ii11iIi11i
   packet = packet [ iIi1IiiIII : : ]
   if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
  return ( packet )
  if 83 - 83: O0
  if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
 def decode ( self , packet , nonce , ms_json_encrypt = False ) :
  Iii1iIII1Iii = "BBBBHH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
  self . priority , self . weight , self . mpriority , self . mweight , IIi1 , O0ooO0O00oo0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
  if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
  IIi1 = socket . ntohs ( IIi1 )
  O0ooO0O00oo0 = socket . ntohs ( O0ooO0O00oo0 )
  self . local_bit = True if ( IIi1 & 0x0004 ) else False
  self . probe_bit = True if ( IIi1 & 0x0002 ) else False
  self . reach_bit = True if ( IIi1 & 0x0001 ) else False
  if 46 - 46: o0oOOo0O0Ooo
  if ( O0ooO0O00oo0 == LISP_AFI_LCAF ) :
   packet = packet [ oOoOo000Ooooo - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
  else :
   self . rloc . afi = O0ooO0O00oo0
   packet = packet [ oOoOo000Ooooo : : ]
   packet = self . rloc . unpack_address ( packet )
   if 28 - 28: i1IIi
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
  if 62 - 62: I1Ii111 * I11i / I11i
 def end_of_rlocs ( self , packet , rloc_count ) :
  for OoOOoO0oOo in range ( rloc_count ) :
   packet = self . decode ( packet , None , False )
   if ( packet == None ) : return ( None )
   if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
  return ( packet )
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
class lisp_map_referral ( object ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 41 - 41: I1IiiI * I1IiiI . I1Ii111
  if 38 - 38: I1IiiI % i11iIiiIii
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # O0
 lisp_hex_string ( self . nonce ) ) )
  if 5 - 5: I1Ii111 . O0 / o0oOOo0O0Ooo / I11i - I1ii11iIi11i
  if 2 - 2: IiII % OoOoOO00
 def encode ( self ) :
  oOOOoOO = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  return ( OO0Oo00OO0oo )
  if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
  if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
 def decode ( self , packet ) :
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 33 - 33: II111iiii + Ii1I
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  oOOOoOO = socket . ntohl ( oOOOoOO [ 0 ] )
  self . record_count = oOOOoOO & 0xff
  packet = packet [ oOoOo000Ooooo : : ]
  if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
  Iii1iIII1Iii = "Q"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
  self . nonce = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  return ( packet )
  if 59 - 59: I11i % Ii1I / OoOoOO00
  if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
  if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
  if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
  if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
  if 80 - 80: Oo0Ooo
  if 58 - 58: I1Ii111 + OOooOOo
  if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
class lisp_ddt_entry ( object ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
  if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 76 - 76: iII111i - iIii1I11I1II1
  if 23 - 23: I11i / OoO0O00 % OOooOOo
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
  if 21 - 21: Ii1I % O0
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  IiI11111I1ii1 = self . delegation_set [ 0 ]
  return ( IiI11111I1ii1 . print_node_type ( ) )
  if 40 - 40: I1IiiI . Oo0Ooo - Ii1I
  if 60 - 60: o0oOOo0O0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 25 - 25: Ii1I . II111iiii * iII111i - o0oOOo0O0Ooo + Ii1I
  if 35 - 35: ooOoO0o
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   OooOoo0o = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( OooOoo0o == None ) :
    OooOoo0o = lisp_ddt_entry ( )
    OooOoo0o . eid . copy_address ( self . group )
    OooOoo0o . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , OooOoo0o )
    if 98 - 98: ooOoO0o * iII111i + OoOoOO00
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OooOoo0o . group )
   OooOoo0o . add_source_entry ( self )
   if 86 - 86: oO0o - Oo0Ooo + i11iIiiIii % ooOoO0o % i1IIi / O0
   if 49 - 49: ooOoO0o . I1ii11iIi11i * I1Ii111 * Ii1I * o0oOOo0O0Ooo - OoOoOO00
   if 53 - 53: o0oOOo0O0Ooo * Ii1I / O0
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 81 - 81: Ii1I - iII111i / OOooOOo + I1IiiI + OoO0O00
  if 24 - 24: o0oOOo0O0Ooo - i11iIiiIii + i11iIiiIii . I1IiiI - OOooOOo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 16 - 16: OOooOOo
  if 74 - 74: I11i . II111iiii + O0 * II111iiii
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 50 - 50: IiII
  if 7 - 7: OoO0O00 / I1IiiI * Ii1I % OoO0O00 + OoO0O00 % II111iiii
  if 83 - 83: O0 % o0oOOo0O0Ooo
class lisp_ddt_node ( object ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 77 - 77: I1Ii111 - OoooooooOO
  if 2 - 2: OoOoOO00 - OOooOOo * o0oOOo0O0Ooo / OoO0O00 - IiII % I1IiiI
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 98 - 98: iIii1I11I1II1
  if 49 - 49: I1IiiI - I11i
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 63 - 63: i11iIiiIii . OoO0O00 . oO0o
  if 85 - 85: oO0o . I1ii11iIi11i + i11iIiiIii
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 85 - 85: I11i
  if 36 - 36: ooOoO0o % OoO0O00
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 1 - 1: OoooooooOO - OoOoOO00
  if 35 - 35: I1Ii111
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
  if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
  if 92 - 92: iII111i % I1ii11iIi11i
  if 16 - 16: oO0o
  if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
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
  if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
  if 52 - 52: ooOoO0o
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # I1IiiI + I11i + I1IiiI
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 90 - 90: iII111i - I1ii11iIi11i - i1IIi % oO0o * iIii1I11I1II1 - OoOoOO00
  if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
  if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( self . nonce in lisp_ddt_map_requestQ ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 97 - 97: Ii1I - IiII
   if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
   if 81 - 81: I1ii11iIi11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
  if 81 - 81: OoOoOO00
  if 52 - 52: iII111i * IiII % I1IiiI * I11i
  if 73 - 73: I1Ii111 * ooOoO0o
  if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 14 - 14: iII111i / OoO0O00
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 28 - 28: I1Ii111
if 27 - 27: iII111i * I1IiiI
if 60 - 60: i1IIi / I1IiiI - I1ii11iIi11i
if 41 - 41: I1Ii111 + ooOoO0o / OOooOOo + I11i % Oo0Ooo
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
  if 91 - 91: I1IiiI % I1ii11iIi11i % oO0o / i1IIi * iIii1I11I1II1 + I11i
  if 48 - 48: ooOoO0o / I1ii11iIi11i / OoO0O00 / II111iiii * OoOoOO00
 def print_info ( self ) :
  if ( self . info_reply ) :
   O0OO = "Info-Reply"
   OooOOoOO0OO = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # ooOoO0o * oO0o / OOooOOo * Oo0Ooo
   # I11i . ooOoO0o * II111iiii
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : OooOOoOO0OO += "empty, "
   for i1I1IIIi11I in self . rtr_list :
    OooOOoOO0OO += red ( i1I1IIIi11I . print_address_no_iid ( ) , False ) + ", "
    if 13 - 13: iIii1I11I1II1 . OOooOOo . oO0o - Oo0Ooo * I1IiiI / i1IIi
   OooOOoOO0OO = OooOOoOO0OO [ 0 : - 2 ]
  else :
   O0OO = "Info-Request"
   Ooo0OOo = "<none>" if self . hostname == None else self . hostname
   OooOOoOO0OO = ", hostname: {}" . format ( blue ( Ooo0OOo , False ) )
   if 88 - 88: OOooOOo / iII111i + o0oOOo0O0Ooo . Oo0Ooo
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( O0OO , False ) ,
 lisp_hex_string ( self . nonce ) , OooOOoOO0OO ) )
  if 96 - 96: I1IiiI . IiII - i11iIiiIii . I1Ii111
  if 39 - 39: i11iIiiIii
 def encode ( self ) :
  oOOOoOO = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : oOOOoOO |= ( 1 << 27 )
  if 9 - 9: OOooOOo % O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
  if 78 - 78: iIii1I11I1II1 - i1IIi . I11i . o0oOOo0O0Ooo
  if 66 - 66: OOooOOo * Oo0Ooo
  if 58 - 58: OOooOOo
  if 96 - 96: IiII % OoooooooOO + O0 * II111iiii / OOooOOo . I1Ii111
  if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
  if 13 - 13: ooOoO0o
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  OO0Oo00OO0oo += struct . pack ( "III" , 0 , 0 , 0 )
  if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
  if 3 - 3: iIii1I11I1II1 / oO0o
  if 61 - 61: I1Ii111 / O0 - iII111i
  if 44 - 44: i1IIi
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    OO0Oo00OO0oo += struct . pack ( "H" , 0 )
   else :
    OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    OO0Oo00OO0oo += ( self . hostname + "\0" ) . encode ( )
    if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
   return ( OO0Oo00OO0oo )
   if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
   if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
   if 69 - 69: iII111i * I11i
   if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
   if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
  O0ooO0O00oo0 = socket . htons ( LISP_AFI_LCAF )
  ooOoOoOo = LISP_LCAF_NAT_TYPE
  iIi1IiiIII = socket . htons ( 16 )
  O0oOOOoOoo0o = socket . htons ( self . ms_port )
  iI11 = socket . htons ( self . etr_port )
  OO0Oo00OO0oo += struct . pack ( "HHBBHHHH" , O0ooO0O00oo0 , 0 , ooOoOoOo , 0 , iIi1IiiIII ,
 O0oOOOoOoo0o , iI11 , socket . htons ( self . global_etr_rloc . afi ) )
  OO0Oo00OO0oo += self . global_etr_rloc . pack_address ( )
  OO0Oo00OO0oo += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  OO0Oo00OO0oo += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : OO0Oo00OO0oo += struct . pack ( "H" , 0 )
  if 40 - 40: iIii1I11I1II1
  if 33 - 33: i11iIiiIii - oO0o
  if 35 - 35: OoOoOO00 - I11i % Ii1I * OoooooooOO
  if 84 - 84: I1IiiI * I1ii11iIi11i + iIii1I11I1II1 - II111iiii % O0 . OOooOOo
  for i1I1IIIi11I in self . rtr_list :
   OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( i1I1IIIi11I . afi ) )
   OO0Oo00OO0oo += i1I1IIIi11I . pack_address ( )
   if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
  return ( OO0Oo00OO0oo )
  if 74 - 74: i1IIi
  if 80 - 80: ooOoO0o + I1Ii111 . I1ii11iIi11i % OoooooooOO
 def decode ( self , packet ) :
  OOooo = packet
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 26 - 26: OoOoOO00 . iII111i * iIii1I11I1II1 / IiII
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  oOOOoOO = oOOOoOO [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if 69 - 69: OoooooooOO / I11i + Ii1I * II111iiii
  Iii1iIII1Iii = "Q"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 35 - 35: i11iIiiIii + oO0o
  OOO0O0O = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 85 - 85: OoOoOO00 . O0 % OoooooooOO % oO0o
  oOOOoOO = socket . ntohl ( oOOOoOO )
  self . nonce = OOO0O0O [ 0 ]
  self . info_reply = oOOOoOO & 0x08000000
  self . hostname = None
  packet = packet [ oOoOo000Ooooo : : ]
  if 43 - 43: I1IiiI - I11i . I1IiiI / i11iIiiIii % IiII * i11iIiiIii
  if 12 - 12: II111iiii - iIii1I11I1II1
  if 43 - 43: i11iIiiIii % OoO0O00
  if 100 - 100: i1IIi
  if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
  Iii1iIII1Iii = "HH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
  if 71 - 71: IiII + OoO0O00
  if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
  if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
  if 30 - 30: O0 - O0 % iIii1I11I1II1 + iII111i * OoooooooOO
  oo0OO0oo , OoooOOO0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if ( OoooOOO0 != 0 ) : return ( None )
  if 1 - 1: O0
  packet = packet [ oOoOo000Ooooo : : ]
  Iii1iIII1Iii = "IBBH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 36 - 36: oO0o . iII111i
  O0O00O , OOOo00o , O00o00 , Ii1IiII1II = struct . unpack ( Iii1iIII1Iii ,
 packet [ : oOoOo000Ooooo ] )
  if 24 - 24: ooOoO0o % I1IiiI * OoooooooOO * IiII + Oo0Ooo / Ii1I
  if ( Ii1IiII1II != 0 ) : return ( None )
  packet = packet [ oOoOo000Ooooo : : ]
  if 9 - 9: iII111i % OOooOOo / OoOoOO00 * I1ii11iIi11i % i11iIiiIii / O0
  if 45 - 45: i1IIi . ooOoO0o / o0oOOo0O0Ooo % Ii1I
  if 1 - 1: iII111i + Ii1I + I1IiiI * OoooooooOO * ooOoO0o
  if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
  if ( self . info_reply == False ) :
   Iii1iIII1Iii = "H"
   oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
   if ( len ( packet ) >= oOoOo000Ooooo ) :
    O0ooO0O00oo0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
    if ( socket . ntohs ( O0ooO0O00oo0 ) == LISP_AFI_NAME ) :
     packet = packet [ oOoOo000Ooooo : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 60 - 60: OOooOOo . ooOoO0o % i1IIi % Ii1I % ooOoO0o + OoO0O00
     if 26 - 26: O0 % o0oOOo0O0Ooo + iII111i * I1ii11iIi11i * I1Ii111
   return ( OOooo )
   if 4 - 4: OOooOOo * OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
   if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
   if 62 - 62: I1Ii111 % II111iiii
   if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
   if 91 - 91: i11iIiiIii + Ii1I
  Iii1iIII1Iii = "HHBBHHH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 85 - 85: I11i % IiII
  O0ooO0O00oo0 , ooooO00o0 , ooOoOoOo , OOOo00o , iIi1IiiIII , O0oOOOoOoo0o , iI11 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
  if ( socket . ntohs ( O0ooO0O00oo0 ) != LISP_AFI_LCAF ) : return ( None )
  if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
  self . ms_port = socket . ntohs ( O0oOOOoOoo0o )
  self . etr_port = socket . ntohs ( iI11 )
  packet = packet [ oOoOo000Ooooo : : ]
  if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
  if 93 - 93: Ii1I / iII111i
  if 100 - 100: Oo0Ooo
  if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
  Iii1iIII1Iii = "H"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
  if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
  if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
  if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
  O0ooO0O00oo0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if ( O0ooO0O00oo0 != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( O0ooO0O00oo0 )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 72 - 72: I1Ii111 . OoO0O00
   if 59 - 59: I1IiiI * I11i % i1IIi
   if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
   if 60 - 60: iIii1I11I1II1
   if 13 - 13: II111iiii + Ii1I
   if 33 - 33: i1IIi
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( OOooo )
  if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
  O0ooO0O00oo0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if ( O0ooO0O00oo0 != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( O0ooO0O00oo0 )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OOooo )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
   if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
   if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
   if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
   if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( OOooo )
  if 81 - 81: i1IIi % iIii1I11I1II1
  O0ooO0O00oo0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if ( O0ooO0O00oo0 != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( O0ooO0O00oo0 )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OOooo )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
   if 82 - 82: ooOoO0o
   if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
   if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
   if 59 - 59: i11iIiiIii / OoO0O00
   if 48 - 48: iIii1I11I1II1
  while ( len ( packet ) >= oOoOo000Ooooo ) :
   O0ooO0O00oo0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
   packet = packet [ oOoOo000Ooooo : : ]
   if ( O0ooO0O00oo0 == 0 ) : continue
   i1I1IIIi11I = lisp_address ( socket . ntohs ( O0ooO0O00oo0 ) , "" , 0 , 0 )
   packet = i1I1IIIi11I . unpack_address ( packet )
   if ( packet == None ) : return ( OOooo )
   i1I1IIIi11I . mask_len = i1I1IIIi11I . host_mask_len ( )
   self . rtr_list . append ( i1I1IIIi11I )
   if 19 - 19: oO0o
  return ( OOooo )
  if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
  if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
  if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
class lisp_nat_info ( object ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
  if 8 - 8: I1ii11iIi11i + II111iiii . OoO0O00 + I1IiiI - II111iiii % OoO0O00
 def timed_out ( self ) :
  Ii1i1 = time . time ( ) - self . uptime
  return ( Ii1i1 >= ( LISP_INFO_INTERVAL * 2 ) )
  if 85 - 85: i11iIiiIii % iII111i + II111iiii
  if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
  if 50 - 50: OoO0O00 / OOooOOo % I1IiiI / Ii1I + OoO0O00 . iIii1I11I1II1
class lisp_info_source ( object ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 62 - 62: I1Ii111 + OoooooooOO - Ii1I - iIii1I11I1II1
  if 80 - 80: OoO0O00
 def cache_address_for_info_source ( self ) :
  III11II111 = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ III11II111 ] = self
  if 72 - 72: II111iiii % i11iIiiIii + OoOoOO00 / I1Ii111 - i11iIiiIii
  if 39 - 39: i11iIiiIii - OOooOOo / OoO0O00 * OoOoOO00 / IiII
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 / Ii1I / II111iiii
  if 56 - 56: OOooOOo * iII111i / Ii1I
  if 9 - 9: I1ii11iIi11i * i11iIiiIii / I1Ii111 + iIii1I11I1II1
  if 1 - 1: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / oO0o
  if 73 - 73: iII111i
  if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo
  if 45 - 45: oO0o % O0 / O0
  if 98 - 98: I1Ii111
  if 58 - 58: OOooOOo
  if 6 - 6: I1ii11iIi11i
  if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 18 - 18: ooOoO0o
 if ( lisp_is_x86 ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
  if 29 - 29: Ii1I . II111iiii / I1Ii111
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  i1oO0o00oOo00oO = auth1 + auth2 + auth3
  if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  i1oO0o00oOo00oO = auth1 + auth2 + auth3 + auth4
  if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
 return ( i1oO0o00oOo00oO )
 if 81 - 81: i11iIiiIii - II111iiii + I11i
 if 52 - 52: II111iiii
 if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
 if 26 - 26: I1ii11iIi11i - OoO0O00
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
 if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
 if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
 if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
 if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
 if 15 - 15: Ii1I
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   I1iii = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 18 - 18: iIii1I11I1II1 + I11i
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   I1iii = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 92 - 92: IiII * OoO0O00 . OoOoOO00 + iII111i - I1IiiI
  I1iii . bind ( ( local_addr , int ( port ) ) )
 else :
  ooO0o = port
  if ( os . path . exists ( ooO0o ) ) :
   os . system ( "rm " + ooO0o )
   time . sleep ( 1 )
   if 15 - 15: OoO0O00 / OoO0O00 * o0oOOo0O0Ooo * I1ii11iIi11i - o0oOOo0O0Ooo
  I1iii = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  I1iii . bind ( ooO0o )
  if 47 - 47: I1IiiI / OoOoOO00 / II111iiii
 return ( I1iii )
 if 7 - 7: oO0o . ooOoO0o
 if 73 - 73: i1IIi % I1Ii111 * ooOoO0o % OoO0O00
 if 70 - 70: ooOoO0o * I1ii11iIi11i
 if 26 - 26: i11iIiiIii - II111iiii . II111iiii * oO0o / Ii1I + I1IiiI
 if 12 - 12: OoO0O00 * iIii1I11I1II1 % I1Ii111 . O0 * OoOoOO00 * OOooOOo
 if 34 - 34: I1IiiI . i1IIi
 if 38 - 38: iIii1I11I1II1
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   I1iii = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 64 - 64: i1IIi / OoO0O00
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   I1iii = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 68 - 68: I11i * O0 * oO0o + OoOoOO00 / IiII
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  I1iii = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  I1iii . bind ( internal_name )
  if 42 - 42: iIii1I11I1II1 % i1IIi - OoOoOO00 % I1ii11iIi11i * Ii1I + i11iIiiIii
 return ( I1iii )
 if 40 - 40: OOooOOo
 if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
 if 94 - 94: IiII
 if 69 - 69: I1Ii111 . I1Ii111
 if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
 if 8 - 8: iII111i % o0oOOo0O0Ooo
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 87 - 87: Ii1I % I11i / I1Ii111
 if 21 - 21: OoO0O00 + Ii1I / I1Ii111
 if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
 if 38 - 38: i1IIi
 if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
 if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
 if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
 if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 if 73 - 73: I1ii11iIi11i / I1Ii111 + i11iIiiIii + OoO0O00 . ooOoO0o
 if 54 - 54: I1ii11iIi11i + IiII - oO0o + Oo0Ooo / IiII % Oo0Ooo
 if 2 - 2: OOooOOo / I11i * I11i + I11i / O0 - OOooOOo
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
 if 49 - 49: I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
def lisp_packet_ipc ( packet , source , sport ) :
 return ( ( "packet@" + str ( len ( packet ) ) + "@" + source + "@" + str ( sport ) + "@" + packet ) )
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
 if 45 - 45: Ii1I
 if 8 - 8: oO0o + OOooOOo
 if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
 if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
 if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
 if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 return ( "control-packet@" + dest + "@" + str ( dport ) + "@" + packet )
 if 30 - 30: I11i + O0 / Ii1I / OoOoOO00 - oO0o + II111iiii
 if 21 - 21: iIii1I11I1II1 % OoooooooOO * OOooOOo % i1IIi
 if 73 - 73: OoooooooOO
 if 100 - 100: I11i / i1IIi / i1IIi % Ii1I - II111iiii . OoooooooOO
 if 72 - 72: Oo0Ooo * OoooooooOO % I1IiiI + I11i - II111iiii
 if 82 - 82: iIii1I11I1II1 / i1IIi * I1IiiI . i11iIiiIii
 if 56 - 56: Ii1I * I1IiiI / ooOoO0o * II111iiii
def lisp_data_packet_ipc ( packet , source ) :
 return ( "data-packet@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 51 - 51: i1IIi . oO0o % OOooOOo
 if 90 - 90: OoooooooOO + iII111i / iIii1I11I1II1
 if 12 - 12: OoooooooOO
 if 9 - 9: O0 / O0 / I1IiiI - oO0o . ooOoO0o
 if 6 - 6: O0 - OoO0O00 + OoooooooOO % iIii1I11I1II1
 if 58 - 58: i11iIiiIii * OOooOOo . Oo0Ooo / iII111i - i1IIi
 if 45 - 45: Ii1I
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
def lisp_command_ipc ( packet , source ) :
 return ( "command@" + str ( len ( packet ) ) + "@" + source + "@@" + packet )
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
 if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
 if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
 if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
 if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 if 92 - 92: OoO0O00 . i1IIi
 if 22 - 22: Ii1I . I1IiiI
def lisp_api_ipc ( source , data ) :
 return ( "api@" + str ( len ( data ) ) + "@" + source + "@@" + data )
 if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
 if 66 - 66: I11i + iII111i
 if 50 - 50: IiII
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
def lisp_ipc ( packet , send_socket , node ) :
 if 8 - 8: I11i - I11i % IiII
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 81 - 81: OOooOOo * oO0o
  if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
 iI1I = 1500 if ( packet . find ( "control-packet" ) == - 1 ) else 9000
 if 27 - 27: O0
 IiI1ii1Ii = 0
 iI = len ( packet )
 O0o0oO0 = 0
 IIi1ii1II1II = .001
 while ( iI > 0 ) :
  ii11iiIii1 = min ( iI , iI1I )
  O0i1I1i1II = packet [ IiI1ii1Ii : ii11iiIii1 + IiI1ii1Ii ]
  if 29 - 29: I1IiiI + O0 . OOooOOo % OOooOOo * Oo0Ooo
  try :
   send_socket . sendto ( O0i1I1i1II . encode ( ) , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( O0i1I1i1II ) , len ( packet ) , node ) )
   if 44 - 44: i11iIiiIii / OoO0O00 . I1Ii111
   O0o0oO0 = 0
   IIi1ii1II1II = .001
   if 89 - 89: O0 % i1IIi * I1ii11iIi11i / OOooOOo % OoooooooOO / I1IiiI
  except socket . error as I1i :
   if ( O0o0oO0 == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 12 - 12: i1IIi / II111iiii . I11i
    if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( O0i1I1i1II ) , len ( packet ) , node , I1i ) )
   if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
   if 94 - 94: OOooOOo / IiII
   O0o0oO0 += 1
   time . sleep ( IIi1ii1II1II )
   if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
   lprint ( "Retrying after {} ms ..." . format ( IIi1ii1II1II * 1000 ) )
   IIi1ii1II1II *= 2
   continue
   if 22 - 22: OoOoOO00 - Oo0Ooo
   if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
  IiI1ii1Ii += ii11iiIii1
  iI -= ii11iiIii1
  if 33 - 33: I11i + O0
 return
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
 if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
 if 12 - 12: II111iiii + I11i
 if 9 - 9: I1ii11iIi11i
 if 51 - 51: I1ii11iIi11i
 if 37 - 37: I1IiiI % I1Ii111
 if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 IiI1ii1Ii = 0
 iiiiIIiiII1Iii1 = b""
 iI = len ( packet ) * 2
 while ( IiI1ii1Ii < iI ) :
  iiiiIIiiII1Iii1 += packet [ IiI1ii1Ii : IiI1ii1Ii + 8 ] + b" "
  IiI1ii1Ii += 8
  iI -= 4
  if 98 - 98: I11i * O0 + IiII - oO0o
 return ( iiiiIIiiII1Iii1 )
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
 Ii1IiIIIi = dest . print_address_no_iid ( )
 if ( Ii1IiIIIi . find ( "::ffff:" ) != - 1 and Ii1IiIIIi . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : OOooo0O0O00o = lisp_sockets [ 0 ]
  if ( OOooo0O0O00o == None ) :
   OOooo0O0O00o = lisp_sockets [ 0 ]
   Ii1IiIIIi = Ii1IiIIIi . split ( "::ffff:" ) [ - 1 ]
   if 21 - 21: iII111i
   if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
   if 75 - 75: OoooooooOO
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + Ii1IiIIIi , False ) , port ,
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
 try : OOooo0O0O00o . sendto ( packet , ( Ii1IiIIIi , port ) )
 except socket . error as I1i :
  lprint ( "socket.sendto() failed: {}" . format ( I1i ) )
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
 ii11iiIii1 = total_length - len ( packet )
 if ( ii11iiIii1 == 0 ) : return ( [ True , packet ] )
 if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 75 - 75: I1Ii111 - i1IIi - OoO0O00
 if 25 - 25: iII111i . o0oOOo0O0Ooo
 if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
 if 68 - 68: ooOoO0o % OoooooooOO
 if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
 iI = ii11iiIii1
 while ( iI > 0 ) :
  try : O0i1I1i1II = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 60 - 60: iII111i . OOooOOo
  O0i1I1i1II = O0i1I1i1II [ 0 ] . decode ( )
  if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
  if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
  if 19 - 19: I1IiiI
  if 99 - 99: OOooOOo - OOooOOo
  if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
  if ( O0i1I1i1II . find ( "packet@" ) == 0 ) :
   ooooO0Oo = O0i1I1i1II . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( O0i1I1i1II ) ,
   # I1IiiI - IiII . I1IiiI / OoooooooOO * o0oOOo0O0Ooo
 ooooO0Oo [ 1 ] if len ( ooooO0Oo ) > 2 else "?" )
   return ( [ False , O0i1I1i1II ] )
   if 11 - 11: OoooooooOO . Oo0Ooo / ooOoO0o + Oo0Ooo . I11i . OOooOOo
   if 10 - 10: I1ii11iIi11i - OoooooooOO
  iI -= len ( O0i1I1i1II )
  packet += O0i1I1i1II
  if 41 - 41: IiII + I1ii11iIi11i + I11i % iII111i - I1ii11iIi11i
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( O0i1I1i1II ) , total_length , source ) )
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
 OO0Oo00OO0oo = ""
 for O0i1I1i1II in payload : OO0Oo00OO0oo += O0i1I1i1II + "\x40"
 return ( OO0Oo00OO0oo [ : - 1 ] )
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
   OO0Oo00OO0oo = oo0Ooo [ 0 ]
   OO = lisp_convert_6to4 ( oo0Ooo [ 1 ] [ 0 ] )
   O00oo0o0o0oo = oo0Ooo [ 1 ] [ 1 ]
   if 35 - 35: Ii1I % i1IIi + I1IiiI
   if ( O00oo0o0o0oo == LISP_DATA_PORT ) :
    o0Ooo = lisp_data_plane_logging
    Oo000oo0ooooO = lisp_format_packet ( OO0Oo00OO0oo [ 0 : 60 ] ) + b" ..."
   else :
    o0Ooo = True
    Oo000oo0ooooO = lisp_format_packet ( OO0Oo00OO0oo )
    if 53 - 53: i11iIiiIii / i1IIi . i1IIi + I11i
    if 19 - 19: ooOoO0o . OoOoOO00 + Oo0Ooo + iIii1I11I1II1 . OoOoOO00 - I1IiiI
   if ( o0Ooo ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( OO0Oo00OO0oo ) , bold ( "from " + OO , False ) , O00oo0o0o0oo ,
 Oo000oo0ooooO ) )
    if 70 - 70: OOooOOo . OoOoOO00 . OOooOOo / iII111i
   return ( [ "packet" , OO , O00oo0o0o0oo , OO0Oo00OO0oo ] )
   if 72 - 72: OoooooooOO + Ii1I + iIii1I11I1II1
   if 13 - 13: iII111i . I1Ii111 % ooOoO0o / i1IIi
   if 64 - 64: iII111i
   if 9 - 9: I1ii11iIi11i + Oo0Ooo * I11i / I1Ii111 / I1ii11iIi11i / oO0o
   if 48 - 48: Oo0Ooo % i1IIi / I1ii11iIi11i / oO0o + iII111i
   if 47 - 47: Ii1I
  OoOO0 = False
  oO00Oo0OO = oo0Ooo [ 0 ] . decode ( )
  oOoOO0OO = False
  if 95 - 95: iIii1I11I1II1 % I1ii11iIi11i + II111iiii + ooOoO0o + iIii1I11I1II1 / I1Ii111
  while ( OoOO0 == False ) :
   oO00Oo0OO = oO00Oo0OO . split ( "@" )
   if 59 - 59: I1Ii111
   if ( len ( oO00Oo0OO ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( oO00Oo0OO [ 0 ] ) )
    if 22 - 22: OoooooooOO
    oOoOO0OO = True
    break
    if 88 - 88: I1Ii111 - OoO0O00
    if 29 - 29: I1IiiI . I1Ii111
   OOOO = oO00Oo0OO [ 0 ]
   try :
    ooi1Ii1I1i11i11 = int ( oO00Oo0OO [ 1 ] )
   except :
    o00O0OO0 = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( o00O0OO0 , oo0Ooo ) )
    oOoOO0OO = True
    break
    if 77 - 77: II111iiii
   OO = oO00Oo0OO [ 2 ]
   O00oo0o0o0oo = oO00Oo0OO [ 3 ]
   if 80 - 80: i11iIiiIii / Ii1I / ooOoO0o - OoO0O00
   if 17 - 17: OoO0O00 * i11iIiiIii * Oo0Ooo / OoooooooOO / II111iiii
   if 92 - 92: iII111i + II111iiii
   if 88 - 88: o0oOOo0O0Ooo . IiII / O0 + ooOoO0o
   if 19 - 19: Oo0Ooo
   if 24 - 24: Ii1I . I1ii11iIi11i . i1IIi % Oo0Ooo
   if 63 - 63: OoO0O00 . I1IiiI + ooOoO0o + I1ii11iIi11i
   if 63 - 63: OoooooooOO * OoOoOO00 - Ii1I
   if ( len ( oO00Oo0OO ) > 5 ) :
    OO0Oo00OO0oo = lisp_bit_stuff ( oO00Oo0OO [ 4 : : ] )
   else :
    OO0Oo00OO0oo = oO00Oo0OO [ 4 ]
    if 93 - 93: OoooooooOO * OOooOOo
    if 34 - 34: OoOoOO00 + OoOoOO00 - Oo0Ooo
    if 21 - 21: i1IIi + O0 % I1ii11iIi11i / i1IIi - iII111i
    if 56 - 56: Ii1I - Ii1I / OoooooooOO * i11iIiiIii - iII111i % iIii1I11I1II1
    if 87 - 87: O0
    if 23 - 23: I1IiiI
   OoOO0 , OO0Oo00OO0oo = lisp_receive_segments ( lisp_socket , OO0Oo00OO0oo ,
 OO , ooi1Ii1I1i11i11 )
   if ( OO0Oo00OO0oo == None ) : return ( [ "" , "" , "" , "" ] )
   if 97 - 97: OoooooooOO / ooOoO0o
   if 50 - 50: O0
   if 100 - 100: IiII . Oo0Ooo - Oo0Ooo % iII111i
   if 83 - 83: i11iIiiIii % ooOoO0o * I1ii11iIi11i - ooOoO0o . OoOoOO00
   if 54 - 54: oO0o + OoOoOO00 - OoOoOO00 / I1ii11iIi11i * i11iIiiIii + OoooooooOO
   if ( OoOO0 == False ) :
    oO00Oo0OO = OO0Oo00OO0oo
    continue
    if 20 - 20: OOooOOo / O0
    if 51 - 51: ooOoO0o - I1Ii111 * oO0o
   if ( O00oo0o0o0oo == "" ) : O00oo0o0o0oo = "no-port"
   if ( OOOO == "command" and lisp_i_am_core == False ) :
    OOOooo0OooOoO = OO0Oo00OO0oo . find ( " {" )
    II1Ii1IiiI1 = OO0Oo00OO0oo if OOOooo0OooOoO == - 1 else OO0Oo00OO0oo [ : OOOooo0OooOoO ]
    II1Ii1IiiI1 = ": '" + II1Ii1IiiI1 + "'"
   else :
    II1Ii1IiiI1 = ""
    if 10 - 10: i1IIi % I11i % i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo + OOooOOo
    if 87 - 87: O0 + o0oOOo0O0Ooo * OoOoOO00 % o0oOOo0O0Ooo * ooOoO0o
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( OO0Oo00OO0oo ) , bold ( "from " + OO , False ) , O00oo0o0o0oo , OOOO ,
 II1Ii1IiiI1 if ( OOOO in [ "command" , "api" ] ) else ": ... " if ( OOOO == "data-packet" ) else ": " + lisp_format_packet ( OO0Oo00OO0oo ) ) )
   if 48 - 48: I1ii11iIi11i * I1Ii111 % ooOoO0o * II111iiii + OoOoOO00
   if 17 - 17: iII111i + OOooOOo
   if 89 - 89: Oo0Ooo + II111iiii * OoO0O00 + Oo0Ooo % II111iiii
   if 59 - 59: O0 + Oo0Ooo
   if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
  if ( oOoOO0OO ) : continue
  return ( [ OOOO , OO , O00oo0o0o0oo , OO0Oo00OO0oo ] )
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
 ooOI1i = time . time ( )
 if 40 - 40: IiII / oO0o + OoooooooOO / iII111i / II111iiii + i1IIi
 i111ii1II11ii = lisp_control_header ( )
 if ( i111ii1II11ii . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( OoO000o )
  if 33 - 33: I11i + I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
  if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
  if 69 - 69: OoooooooOO
  if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
  if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
 oooOooOoO = source
 if ( source . find ( "lisp" ) == - 1 ) :
  I1iiIi111I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  I1iiIi111I . string_to_afi ( source )
  I1iiIi111I . store_address ( source )
  source = I1iiIi111I
  if 65 - 65: o0oOOo0O0Ooo % i11iIiiIii / II111iiii
  if 85 - 85: I1Ii111 / II111iiii / OOooOOo
 if ( i111ii1II11ii . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , ooOI1i )
  if 87 - 87: OoOoOO00 - oO0o - IiII / iII111i - OOooOOo / Oo0Ooo
 elif ( i111ii1II11ii . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , ooOI1i )
  if 99 - 99: OoO0O00 * I11i
 elif ( i111ii1II11ii . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 33 - 33: I1Ii111 % IiII * OOooOOo - I1Ii111
 elif ( i111ii1II11ii . type == LISP_MAP_NOTIFY ) :
  if ( oooOooOoO == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-rtr" ) ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-itr" ) ) :
   lisp_process_unicast_map_notify ( lisp_sockets , packet , source )
   if 100 - 100: ooOoO0o . i11iIiiIii * Oo0Ooo - i11iIiiIii
   if 72 - 72: oO0o + I11i . OoooooooOO
 elif ( i111ii1II11ii . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 84 - 84: oO0o * oO0o - i1IIi + ooOoO0o
 elif ( i111ii1II11ii . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 83 - 83: i1IIi
 elif ( i111ii1II11ii . type == LISP_NAT_INFO and i111ii1II11ii . is_info_reply ( ) ) :
  ooooO00o0 , IIi11I , OoO000o = lisp_process_info_reply ( source , packet , True )
  if 85 - 85: i11iIiiIii / OoO0O00 / oO0o
 elif ( i111ii1II11ii . type == LISP_NAT_INFO and i111ii1II11ii . is_info_reply ( ) == False ) :
  Oo0o = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , Oo0o , udp_sport ,
 None )
  if 12 - 12: iII111i % OOooOOo % i1IIi
 elif ( i111ii1II11ii . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 17 - 17: IiII
 else :
  lprint ( "Invalid LISP control packet type {}" . format ( i111ii1II11ii . type ) )
  if 63 - 63: ooOoO0o . i11iIiiIii / iIii1I11I1II1
 return ( OoO000o )
 if 8 - 8: i11iIiiIii . IiII * iIii1I11I1II1 * I1IiiI * Ii1I * i11iIiiIii
 if 24 - 24: I1IiiI * I11i - o0oOOo0O0Ooo / iII111i + IiII - I1ii11iIi11i
 if 53 - 53: I11i / I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * OoOoOO00
 if 86 - 86: iIii1I11I1II1 - I1Ii111
 if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
 if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
 if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp ) :
 if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
 o00oo = bold ( "RLOC-probe" , False )
 if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( o00oo ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
  if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( o00oo ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 88 - 88: i1IIi
  if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( o00oo ) )
 return
 if 55 - 55: OoO0O00 % IiII
 if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
 if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
 if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
 if 63 - 63: I1Ii111 + iII111i
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 6 - 6: I1ii11iIi11i + Ii1I
 if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
 if 97 - 97: ooOoO0o + OOooOOo
 if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
 if 6 - 6: Oo0Ooo + I1IiiI
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 48 - 48: oO0o . I1ii11iIi11i
 if 59 - 59: IiII - Ii1I
 if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
 if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
 if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
 if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
 if 53 - 53: o0oOOo0O0Ooo * Ii1I
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , map_request ,
 keys , enc , auth , mr_ttl = - 1 ) :
 if 42 - 42: I11i + iII111i / iIii1I11I1II1
 iii1Iii1 = map_request . rloc_probe if ( map_request != None ) else False
 iIO0OOoOOO0OO = map_request . json_telemetry if ( map_request != None ) else None
 if 86 - 86: I1IiiI - o0oOOo0O0Ooo
 if 67 - 67: Oo0Ooo * oO0o
 Oo0oOooOoo = lisp_map_reply ( )
 Oo0oOooOoo . rloc_probe = iii1Iii1
 Oo0oOooOoo . echo_nonce_capable = enc
 Oo0oOooOoo . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 Oo0oOooOoo . record_count = 1
 Oo0oOooOoo . nonce = nonce
 OO0Oo00OO0oo = Oo0oOooOoo . encode ( )
 Oo0oOooOoo . print_map_reply ( )
 if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
 O0oIII = lisp_eid_record ( )
 O0oIII . rloc_count = len ( rloc_set )
 if ( iIO0OOoOOO0OO != None ) : O0oIII . rloc_count += 1
 O0oIII . authoritative = auth
 O0oIII . record_ttl = ttl
 O0oIII . action = action
 O0oIII . eid = eid
 O0oIII . group = group
 if 98 - 98: I1ii11iIi11i / I1Ii111 . i1IIi / OoOoOO00
 OO0Oo00OO0oo += O0oIII . encode ( )
 O0oIII . print_record ( "  " , False )
 if 56 - 56: OOooOOo * O0
 o0OoO = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 6 - 6: I1ii11iIi11i / OOooOOo
 oOOO0O0OOo0 = None
 for II1 in rloc_set :
  oOoOo = II1 . rloc . is_multicast_address ( )
  i1IOoo0 = lisp_rloc_record ( )
  ooOooOo = iii1Iii1 and ( oOoOo or iIO0OOoOOO0OO == None )
  Oo0o = II1 . rloc . print_address_no_iid ( )
  if ( Oo0o in o0OoO or oOoOo ) :
   i1IOoo0 . local_bit = True
   i1IOoo0 . probe_bit = ooOooOo
   i1IOoo0 . keys = keys
   if ( II1 . priority == 254 and lisp_i_am_rtr ) :
    i1IOoo0 . rloc_name = "RTR"
    if 98 - 98: i11iIiiIii * Oo0Ooo + iIii1I11I1II1
   if ( oOOO0O0OOo0 == None ) : oOOO0O0OOo0 = II1 . rloc
   if 23 - 23: i11iIiiIii - II111iiii . OoooooooOO / I1ii11iIi11i / OoOoOO00 * OoO0O00
  i1IOoo0 . store_rloc_entry ( II1 )
  i1IOoo0 . reach_bit = True
  i1IOoo0 . print_record ( "    " )
  OO0Oo00OO0oo += i1IOoo0 . encode ( )
  if 72 - 72: OOooOOo * OOooOOo
  if 5 - 5: o0oOOo0O0Ooo / i11iIiiIii
  if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
  if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
  if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
 if ( iIO0OOoOOO0OO != None ) :
  i1IOoo0 = lisp_rloc_record ( )
  if ( oOOO0O0OOo0 ) : i1IOoo0 . rloc . copy_address ( oOOO0O0OOo0 )
  i1IOoo0 . local_bit = True
  i1IOoo0 . probe_bit = True
  i1IOoo0 . reach_bit = True
  if ( lisp_i_am_rtr ) :
   i1IOoo0 . priority = 254
   i1IOoo0 . rloc_name = "RTR"
   if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
  I1iIi = lisp_encode_telemetry ( iIO0OOoOOO0OO , eo = str ( time . time ( ) ) )
  i1IOoo0 . json = lisp_json ( "telemetry" , I1iIi )
  i1IOoo0 . print_record ( "    " )
  OO0Oo00OO0oo += i1IOoo0 . encode ( )
  if 45 - 45: II111iiii . iIii1I11I1II1 . Ii1I / OoO0O00 / IiII + OoooooooOO
 return ( OO0Oo00OO0oo )
 if 21 - 21: OoO0O00
 if 36 - 36: iIii1I11I1II1 + I1IiiI + OoOoOO00 . iIii1I11I1II1
 if 6 - 6: OoOoOO00 - O0
 if 46 - 46: IiII . Oo0Ooo
 if 75 - 75: OoO0O00 % OoO0O00 + OoOoOO00 . O0 . OOooOOo / O0
 if 39 - 39: iII111i - Oo0Ooo * I1ii11iIi11i % OOooOOo / oO0o / Oo0Ooo
 if 53 - 53: ooOoO0o % OoO0O00 * O0 + II111iiii + iIii1I11I1II1
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 Ii = lisp_map_referral ( )
 Ii . record_count = 1
 Ii . nonce = nonce
 OO0Oo00OO0oo = Ii . encode ( )
 Ii . print_map_referral ( )
 if 40 - 40: Ii1I % oO0o
 O0oIII = lisp_eid_record ( )
 if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 ooOOo0ooo = 0
 if ( ddt_entry == None ) :
  O0oIII . eid = eid
  O0oIII . group = group
 else :
  ooOOo0ooo = len ( ddt_entry . delegation_set )
  O0oIII . eid = ddt_entry . eid
  O0oIII . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 71 - 71: OoOoOO00 / i11iIiiIii * iII111i
 O0oIII . rloc_count = ooOOo0ooo
 O0oIII . authoritative = True
 if 90 - 90: Ii1I
 if 27 - 27: oO0o + Ii1I . i11iIiiIii
 if 97 - 97: iII111i . I1IiiI
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
 oO00O0o0Oo = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( ooOOo0ooo == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   IiI11111I1ii1 = ddt_entry . delegation_set [ 0 ]
   if ( IiI11111I1ii1 . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 45 - 45: oO0o
   if ( IiI11111I1ii1 . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
    if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
    if 100 - 100: i11iIiiIii - iII111i - I11i
    if 5 - 5: oO0o % IiII * iII111i
    if 98 - 98: iII111i / OOooOOo + IiII
    if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
    if 82 - 82: ooOoO0o % OOooOOo % Ii1I
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : oO00O0o0Oo = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  oO00O0o0Oo = ( lisp_i_am_ms and IiI11111I1ii1 . is_ms_peer ( ) == False )
  if 82 - 82: I1ii11iIi11i
  if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 O0oIII . action = action
 O0oIII . ddt_incomplete = oO00O0o0Oo
 O0oIII . record_ttl = ttl
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 OO0Oo00OO0oo += O0oIII . encode ( )
 O0oIII . print_record ( "  " , True )
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 if ( ooOOo0ooo == 0 ) : return ( OO0Oo00OO0oo )
 if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 for IiI11111I1ii1 in ddt_entry . delegation_set :
  i1IOoo0 = lisp_rloc_record ( )
  i1IOoo0 . rloc = IiI11111I1ii1 . delegate_address
  i1IOoo0 . priority = IiI11111I1ii1 . priority
  i1IOoo0 . weight = IiI11111I1ii1 . weight
  i1IOoo0 . mpriority = 255
  i1IOoo0 . mweight = 0
  i1IOoo0 . reach_bit = True
  OO0Oo00OO0oo += i1IOoo0 . encode ( )
  i1IOoo0 . print_record ( "    " )
  if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
 return ( OO0Oo00OO0oo )
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
 OOO0O0O = map_request . nonce
 iI11ii1IiIi11 = lisp_nonce_echoing
 O0o0O0 = map_request . keys
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
 OO0Oo00OO0oo = lisp_build_map_reply ( iIiI1ii . eid , iIiI1ii . group , iIiI1ii . rloc_set , OOO0O0O ,
 LISP_NO_ACTION , 1440 , map_request , O0o0O0 , iI11ii1IiIi11 , True , ttl )
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
  iIoo0O0 = ( oo00O0OO0Ooo0 . is_private_address ( ) == False )
  i1I1IIIi11I = oo00O0OO0Ooo0 . print_address_no_iid ( )
  if ( iIoo0O0 and i1I1IIIi11I in lisp_rtr_list or sport == 0 ) :
   lisp_encapsulate_rloc_probe ( lisp_sockets , oo00O0OO0Ooo0 , None , OO0Oo00OO0oo )
   return
   if 18 - 18: i11iIiiIii % iII111i
   if 70 - 70: O0 + iII111i % I11i % I1Ii111 + OoOoOO00 / ooOoO0o
   if 35 - 35: IiII + OoO0O00
   if 82 - 82: i1IIi - ooOoO0o / I11i + I11i % I1IiiI - OoooooooOO
   if 56 - 56: I1ii11iIi11i
   if 80 - 80: Oo0Ooo / OOooOOo / iII111i . o0oOOo0O0Ooo
 lisp_send_map_reply ( lisp_sockets , OO0Oo00OO0oo , oo00O0OO0Ooo0 , sport )
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
 OOO0O0O = map_request . nonce
 if 93 - 93: I1ii11iIi11i
 I11I = map_request . target_eid
 o0o0o = map_request . target_group
 if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
 IIiii11iiI111 = [ ]
 for I1OOOo in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( I1OOOo == None ) : continue
  OooOOoOO0OO = lisp_rloc ( )
  OooOOoOO0OO . rloc . copy_address ( I1OOOo )
  OooOOoOO0OO . priority = 254
  IIiii11iiI111 . append ( OooOOoOO0OO )
  if 9 - 9: Ii1I
  if 53 - 53: Ii1I % IiII + I11i % IiII
 iI11ii1IiIi11 = lisp_nonce_echoing
 O0o0O0 = map_request . keys
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
 OO0Oo00OO0oo = lisp_build_map_reply ( I11I , o0o0o , IIiii11iiI111 , OOO0O0O , LISP_NO_ACTION ,
 1440 , map_request , O0o0O0 , iI11ii1IiIi11 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , OO0Oo00OO0oo , oo00O0OO0Ooo0 , sport )
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
 for II1 in IIiii11iiI111 :
  if ( II1 . is_rtr ( ) ) : continue
  if ( II1 . rloc . is_private_address ( ) ) :
   I11I1II1I1I1i = copy . deepcopy ( II1 )
   iii1 . append ( I11I1II1I1I1i )
   continue
   if 98 - 98: I1Ii111
  OOI1I1 = II1
  break
  if 75 - 75: OOooOOo . i11iIiiIii * Ii1I
 if ( OOI1I1 == None ) : return ( IIiii11iiI111 )
 OOI1I1 = OOI1I1 . rloc . print_address_no_iid ( )
 if 32 - 32: iIii1I11I1II1 . OoO0O00 / Oo0Ooo % OOooOOo + IiII
 if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
 if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
 if 47 - 47: II111iiii
 IiiI11Ii1 = None
 for II1 in O0ooO0O0O00 . registered_rlocs :
  if ( II1 . is_rtr ( ) ) : continue
  if ( II1 . rloc . is_private_address ( ) ) : continue
  IiiI11Ii1 = II1
  break
  if 68 - 68: O0 - i1IIi % iII111i * I1ii11iIi11i + I11i
 if ( IiiI11Ii1 == None ) : return ( IIiii11iiI111 )
 IiiI11Ii1 = IiiI11Ii1 . rloc . print_address_no_iid ( )
 if 94 - 94: iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
 if 94 - 94: OoO0O00 . ooOoO0o
 if 25 - 25: I1Ii111 % OOooOOo
 if 82 - 82: Ii1I
 iI1 = target_site_eid . site_id
 if ( iI1 == 0 ) :
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
 if ( iI1 == O0ooO0O0O00 . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( iI1 ) )
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
 for II1 in registered_rloc_set :
  if ( II1 . priority != 254 ) : continue
  OOOo0O0O0O0O0 |= True
  if ( II1 . rloc . is_exact_match ( mr_source ) == False ) : continue
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
 for II1 in registered_rloc_set :
  if ( IiI1iiIIiIiii and II1 . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and II1 . priority == 255 ) : continue
  if ( multicast and II1 . mpriority == 255 ) : continue
  if ( II1 . priority == 254 ) :
   OOOo0O00OO00O . append ( II1 )
  else :
   IIiii11iiI111 . append ( II1 )
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
 for II1 in registered_rloc_set :
  if ( II1 . rloc . is_ipv6 ( ) ) : IIiii11iiI111 . append ( II1 )
  if ( II1 . rloc . is_private_address ( ) ) : IIiii11iiI111 . append ( II1 )
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
 OOO0O0O = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 28 - 28: I1IiiI - I1Ii111
 if 60 - 60: OOooOOo / O0 * o0oOOo0O0Ooo * OoooooooOO
 if 95 - 95: II111iiii
 if 2 - 2: I11i - OoooooooOO / I1ii11iIi11i . I1ii11iIi11i * i11iIiiIii % II111iiii
 oOOOoOO = ( LISP_MAP_NOTIFY << 28 ) | iIiI1IIi1Ii1i
 i111ii1II11ii = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
 OooooO0o0 = struct . pack ( "I" , 0 )
 if 1 - 1: i11iIiiIii / OoOoOO00 - I1ii11iIi11i . I1IiiI / I1Ii111 % iIii1I11I1II1
 if 87 - 87: OoOoOO00 - II111iiii + Oo0Ooo
 if 44 - 44: i1IIi + I1ii11iIi11i / iIii1I11I1II1
 if 47 - 47: I1Ii111
 packet = i111ii1II11ii + OOO0O0O + OooooO0o0 + packet
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
  for iIiii11 in list ( lisp_pubsub_cache [ Ooooo ] . values ( ) ) :
   I1i = iIiii11 . eid_prefix
   if ( I1i . is_more_specific ( registered_eid ) == False ) : continue
   if 40 - 40: II111iiii + OoooooooOO / iII111i % O0 + OOooOOo . ooOoO0o
   I1IoOO0oOOOOO0 = iIiii11 . itr
   O00oo0o0o0oo = iIiii11 . port
   I1iii1iIiI111 = red ( I1IoOO0oOOOOO0 . print_address_no_iid ( ) , False )
   Oo00OOo = bold ( "subscriber" , False )
   oOOoO = "0x" + lisp_hex_string ( iIiii11 . xtr_id )
   OOO0O0O = "0x" + lisp_hex_string ( iIiii11 . nonce )
   if 47 - 47: oO0o
   lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( Oo00OOo , I1iii1iIiI111 , O00oo0o0o0oo , oOOoO , green ( Ooooo , False ) , OOO0O0O ) )
   if 91 - 91: I1IiiI * O0 + OoooooooOO * i1IIi % I1ii11iIi11i . IiII
   if 67 - 67: I1IiiI * I11i
   if 43 - 43: IiII * Oo0Ooo / OoOoOO00 + I1IiiI - i11iIiiIii + II111iiii
   if 81 - 81: I11i / Oo0Ooo % Ii1I % OoO0O00
   if 87 - 87: O0 % II111iiii
   if 42 - 42: I1IiiI . i1IIi
   OOo00O0O0OO = copy . deepcopy ( eid_record )
   OOo00O0O0OO . eid . copy_address ( I1i )
   OOo00O0O0OO = OOo00O0O0OO . encode ( ) + rloc_records
   lisp_build_map_notify ( lisp_sockets , OOo00O0O0OO , [ Ooooo ] , 1 , I1IoOO0oOOOOO0 ,
 O00oo0o0o0oo , iIiii11 . nonce , 0 , 0 , 0 , site , False )
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
 I11I = green ( reply_eid . print_prefix ( ) , False )
 I1IoOO0oOOOOO0 = red ( itr_rloc . print_address_no_iid ( ) , False )
 I1III11111Ii1 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( I1III11111Ii1 ,
 I11I , I1IoOO0oOOOOO0 , xtr_id ) )
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
 I11I = map_request . target_eid
 o0o0o = map_request . target_group
 iIiI1I1ii1I1 = lisp_print_eid_tuple ( I11I , o0o0o )
 oo00O0OO0Ooo0 = map_request . itr_rlocs [ 0 ]
 oOOoO = map_request . xtr_id
 OOO0O0O = map_request . nonce
 oOoO0OooO0O = LISP_NO_ACTION
 iIiii11 = map_request . subscribe_bit
 if 81 - 81: iII111i + I11i - i11iIiiIii * I1IiiI / IiII - Ii1I
 if 44 - 44: OoooooooOO . oO0o
 if 30 - 30: I1Ii111 % IiII / II111iiii
 if 68 - 68: oO0o / O0 / OOooOOo
 if 3 - 3: o0oOOo0O0Ooo / o0oOOo0O0Ooo
 iIiIiII1I11II = True
 OOo0oO = ( lisp_get_eid_hash ( I11I ) != None )
 if ( OOo0oO ) :
  oo0 = map_request . map_request_signature
  if ( oo0 == None ) :
   iIiIiII1I11II = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 17 - 17: ooOoO0o - i1IIi
  else :
   Ii1IiI = map_request . signature_eid
   Oo00oOoo , ooOo0OO , iIiIiII1I11II = lisp_lookup_public_key ( Ii1IiI )
   if ( iIiIiII1I11II ) :
    iIiIiII1I11II = map_request . verify_map_request_sig ( ooOo0OO )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Ii1IiI . print_address ( ) , Oo00oOoo . print_address ( ) ) )
    if 18 - 18: I1IiiI
    if 7 - 7: II111iiii % iII111i * I11i
   II1II = bold ( "passed" , False ) if iIiIiII1I11II else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( II1II ) )
   if 52 - 52: OOooOOo / ooOoO0o . Ii1I
   if 83 - 83: i11iIiiIii - o0oOOo0O0Ooo - O0
   if 25 - 25: I1ii11iIi11i - O0 * iII111i % I1IiiI % Ii1I + OoO0O00
 if ( iIiii11 and iIiIiII1I11II == False ) :
  iIiii11 = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
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
  if 6 - 6: O0 * Oo0Ooo
  if 20 - 20: OoooooooOO * i1IIi * IiII / OoooooooOO - Oo0Ooo / i11iIiiIii
  if 28 - 28: iIii1I11I1II1 % OOooOOo * I1IiiI
  if 28 - 28: O0 . OoOoOO00
 IIIi1 = oo00O0OO0Ooo0 if ( oo00O0OO0Ooo0 . afi == ecm_source . afi ) else ecm_source
 if 9 - 9: OoooooooOO % I1IiiI - iIii1I11I1II1 / Oo0Ooo
 iI1IiiIiIIIi1 = lisp_site_eid_lookup ( I11I , o0o0o , False )
 if 33 - 33: o0oOOo0O0Ooo - Ii1I + iIii1I11I1II1 - i1IIi
 if ( iI1IiiIiIIIi1 == None or iI1IiiIiIIIi1 . is_star_g ( ) ) :
  ii1I1ii1i1i = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( ii1I1ii1i1i ,
 green ( iIiI1I1ii1I1 , False ) ) )
  if 34 - 34: OoooooooOO * OoooooooOO / O0
  if 73 - 73: II111iiii
  if 98 - 98: OoOoOO00 / iII111i - OoooooooOO + i11iIiiIii / O0 % II111iiii
  if 42 - 42: I1ii11iIi11i % i11iIiiIii . iII111i
  lisp_send_negative_map_reply ( lisp_sockets , I11I , o0o0o , OOO0O0O , oo00O0OO0Ooo0 ,
 mr_sport , 15 , oOOoO , iIiii11 )
  if 60 - 60: I1Ii111 % IiII - iIii1I11I1II1
  return ( [ I11I , o0o0o , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 86 - 86: I1Ii111
  if 60 - 60: I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
 oOo00OO0ooo = iI1IiiIiIIIi1 . print_eid_tuple ( )
 iii11i1i1II11 = iI1IiiIiIIIi1 . site . site_name
 if 97 - 97: OoooooooOO . IiII - I11i / o0oOOo0O0Ooo
 if 15 - 15: OoOoOO00
 if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
 if 4 - 4: O0
 if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
 if ( OOo0oO == False and iI1IiiIiIIIi1 . require_signature ) :
  oo0 = map_request . map_request_signature
  Ii1IiI = map_request . signature_eid
  if ( oo0 == None or Ii1IiI . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( iii11i1i1II11 ) )
   iIiIiII1I11II = False
  else :
   Ii1IiI = map_request . signature_eid
   Oo00oOoo , ooOo0OO , iIiIiII1I11II = lisp_lookup_public_key ( Ii1IiI )
   if ( iIiIiII1I11II ) :
    iIiIiII1I11II = map_request . verify_map_request_sig ( ooOo0OO )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Ii1IiI . print_address ( ) , Oo00oOoo . print_address ( ) ) )
    if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
    if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
   II1II = bold ( "passed" , False ) if iIiIiII1I11II else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( II1II ) )
   if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
   if 22 - 22: iIii1I11I1II1 % i11iIiiIii
   if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
   if 43 - 43: oO0o
   if 22 - 22: I1Ii111 + i11iIiiIii
   if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
 if ( iIiIiII1I11II and iI1IiiIiIIIi1 . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( iii11i1i1II11 , green ( oOo00OO0ooo , False ) , green ( iIiI1I1ii1I1 , False ) ) )
  if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
  if 78 - 78: I1IiiI * I11i % OOooOOo + Ii1I + OoOoOO00
  if 23 - 23: iII111i / Oo0Ooo % OoooooooOO * OoooooooOO . iII111i / I1ii11iIi11i
  if 30 - 30: oO0o - OoOoOO00 . I1IiiI
  if 17 - 17: OoOoOO00
  if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
  if ( iI1IiiIiIIIi1 . accept_more_specifics == False ) :
   I11I = iI1IiiIiIIIi1 . eid
   o0o0o = iI1IiiIiIIIi1 . group
   if 57 - 57: O0
   if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
   if 13 - 13: I1ii11iIi11i
   if 32 - 32: OOooOOo / I11i + I1Ii111 / Oo0Ooo * OoooooooOO / II111iiii
   if 8 - 8: OoO0O00
  O0O00O = 1
  if ( iI1IiiIiIIIi1 . force_ttl != None ) :
   O0O00O = iI1IiiIiIIIi1 . force_ttl | 0x80000000
   if 17 - 17: iIii1I11I1II1 - Oo0Ooo
   if 25 - 25: O0 + I1ii11iIi11i
   if 53 - 53: OoooooooOO . Oo0Ooo
   if 35 - 35: OOooOOo % i11iIiiIii % ooOoO0o . O0
   if 9 - 9: ooOoO0o + iII111i / i1IIi % Oo0Ooo - o0oOOo0O0Ooo / I1IiiI
  lisp_send_negative_map_reply ( lisp_sockets , I11I , o0o0o , OOO0O0O , oo00O0OO0Ooo0 ,
 mr_sport , O0O00O , oOOoO , iIiii11 )
  if 42 - 42: OOooOOo + oO0o % O0 * I1ii11iIi11i + i11iIiiIii
  return ( [ I11I , o0o0o , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 16 - 16: i1IIi . I11i + OoO0O00 % Ii1I * IiII + I1IiiI
  if 96 - 96: II111iiii + O0 - II111iiii
  if 97 - 97: I1IiiI
  if 87 - 87: I11i + iIii1I11I1II1
  if 91 - 91: oO0o
 ooO0 = False
 i1i11iIi1 = ""
 iii1iI = False
 if ( iI1IiiIiIIIi1 . force_nat_proxy_reply ) :
  i1i11iIi1 = ", nat-forced"
  ooO0 = True
  iii1iI = True
 elif ( iI1IiiIiIIIi1 . force_proxy_reply ) :
  i1i11iIi1 = ", forced"
  iii1iI = True
 elif ( iI1IiiIiIIIi1 . proxy_reply_requested ) :
  i1i11iIi1 = ", requested"
  iii1iI = True
 elif ( map_request . pitr_bit and iI1IiiIiIIIi1 . pitr_proxy_reply_drop ) :
  i1i11iIi1 = ", drop-to-pitr"
  oOoO0OooO0O = LISP_DROP_ACTION
 elif ( iI1IiiIiIIIi1 . proxy_reply_action != "" ) :
  oOoO0OooO0O = iI1IiiIiIIIi1 . proxy_reply_action
  i1i11iIi1 = ", forced, action {}" . format ( oOoO0OooO0O )
  oOoO0OooO0O = LISP_DROP_ACTION if ( oOoO0OooO0O == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 72 - 72: I11i * II111iiii
  if 82 - 82: I1Ii111 . OoO0O00 * II111iiii
  if 99 - 99: iIii1I11I1II1 / iII111i % i1IIi - II111iiii / OoO0O00
  if 33 - 33: OoooooooOO / i1IIi . Ii1I
  if 96 - 96: OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
  if 56 - 56: IiII - ooOoO0o % oO0o / Oo0Ooo * oO0o % O0
  if 71 - 71: iII111i / II111iiii - II111iiii / I1IiiI
 Iii11 = False
 oo00OO = None
 if ( iii1iI and iI1IiiIiIIIi1 . policy in lisp_policies ) :
  o00oo = lisp_policies [ iI1IiiIiIIIi1 . policy ]
  if ( o00oo . match_policy_map_request ( map_request , mr_source ) ) : oo00OO = o00oo
  if 49 - 49: iIii1I11I1II1 % Oo0Ooo % I11i * Ii1I - OoO0O00
  if ( oo00OO ) :
   III1i1IIII1i = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( III1i1IIII1i ,
 o00oo . policy_name , o00oo . set_action ) )
  else :
   III1i1IIII1i = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( III1i1IIII1i ,
 o00oo . policy_name ) )
   Iii11 = True
   if 15 - 15: i11iIiiIii + o0oOOo0O0Ooo . Ii1I . I1IiiI
   if 8 - 8: iII111i % II111iiii + IiII
   if 5 - 5: i1IIi + II111iiii
 if ( i1i11iIi1 != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( iIiI1I1ii1I1 , False ) , iii11i1i1II11 , green ( oOo00OO0ooo , False ) ,
  # iIii1I11I1II1 - O0 % Oo0Ooo * OoooooooOO / I1IiiI
 i1i11iIi1 ) )
  if 65 - 65: OOooOOo % iIii1I11I1II1 / Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
  IIiii11iiI111 = iI1IiiIiIIIi1 . registered_rlocs
  O0O00O = 1440
  if ( ooO0 ) :
   if ( iI1IiiIiIIIi1 . site_id != 0 ) :
    O0OOO0o = map_request . source_eid
    IIiii11iiI111 = lisp_get_private_rloc_set ( iI1IiiIiIIIi1 , O0OOO0o , o0o0o )
    if 33 - 33: O0 % I1ii11iIi11i + I1IiiI - i1IIi . i1IIi * II111iiii
   if ( IIiii11iiI111 == iI1IiiIiIIIi1 . registered_rlocs ) :
    oo0o0oOOoo00 = ( iI1IiiIiIIIi1 . group . is_null ( ) == False )
    iii1 = lisp_get_partial_rloc_set ( IIiii11iiI111 , IIIi1 , oo0o0oOOoo00 )
    if ( iii1 != IIiii11iiI111 ) :
     O0O00O = 15
     IIiii11iiI111 = iii1
     if 52 - 52: O0 - I1Ii111 . oO0o
     if 43 - 43: IiII * Ii1I - I1ii11iIi11i * I1ii11iIi11i
     if 53 - 53: oO0o % I11i * OoO0O00 . i1IIi
     if 35 - 35: I11i . IiII + ooOoO0o
     if 19 - 19: O0 - i1IIi / I1Ii111
     if 14 - 14: I11i - i11iIiiIii
     if 49 - 49: oO0o . I1ii11iIi11i
     if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
  if ( iI1IiiIiIIIi1 . force_ttl != None ) :
   O0O00O = iI1IiiIiIIIi1 . force_ttl | 0x80000000
   if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
   if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
   if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
   if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
   if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
   if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
  if ( oo00OO ) :
   if ( oo00OO . set_record_ttl ) :
    O0O00O = oo00OO . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( O0O00O ) )
    if 72 - 72: I1Ii111
   if ( oo00OO . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    oOoO0OooO0O = LISP_POLICY_DENIED_ACTION
    IIiii11iiI111 = [ ]
   else :
    OooOOoOO0OO = oo00OO . set_policy_map_reply ( )
    if ( OooOOoOO0OO ) : IIiii11iiI111 = [ OooOOoOO0OO ]
    if 51 - 51: OoOoOO00
    if 61 - 61: Oo0Ooo / i1IIi + I1Ii111 - OoooooooOO / O0
    if 25 - 25: I1ii11iIi11i * i11iIiiIii / i1IIi
  if ( Iii11 ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   oOoO0OooO0O = LISP_POLICY_DENIED_ACTION
   IIiii11iiI111 = [ ]
   if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
   if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
  iI11ii1IiIi11 = iI1IiiIiIIIi1 . echo_nonce_capable
  if 46 - 46: oO0o
  if 5 - 5: i1IIi % o0oOOo0O0Ooo + OoOoOO00 - I11i . Ii1I
  if 33 - 33: II111iiii * o0oOOo0O0Ooo
  if 8 - 8: I1ii11iIi11i % o0oOOo0O0Ooo - IiII
  if ( iIiIiII1I11II ) :
   OooOo0OO = iI1IiiIiIIIi1 . eid
   i1111I1I = iI1IiiIiIIIi1 . group
  else :
   OooOo0OO = I11I
   i1111I1I = o0o0o
   oOoO0OooO0O = LISP_AUTH_FAILURE_ACTION
   IIiii11iiI111 = [ ]
   if 66 - 66: iII111i - ooOoO0o * I1ii11iIi11i - Ii1I / OoooooooOO
   if 86 - 86: I1IiiI % iII111i + Oo0Ooo + i1IIi % o0oOOo0O0Ooo
   if 85 - 85: Ii1I + I1Ii111 * I11i
   if 59 - 59: Oo0Ooo
   if 35 - 35: OoooooooOO + I1ii11iIi11i * OOooOOo
   if 75 - 75: Ii1I * Oo0Ooo % iIii1I11I1II1 . O0 % oO0o
  if ( iIiii11 ) :
   OooOo0OO = I11I
   i1111I1I = o0o0o
   if 4 - 4: I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
   if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
   if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
   if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
   if 66 - 66: iII111i % iII111i
   if 59 - 59: II111iiii . i1IIi % i1IIi
  packet = lisp_build_map_reply ( OooOo0OO , i1111I1I , IIiii11iiI111 ,
 OOO0O0O , oOoO0OooO0O , O0O00O , map_request , None , iI11ii1IiIi11 , False )
  if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
  if ( iIiii11 ) :
   lisp_process_pubsub ( lisp_sockets , packet , OooOo0OO , oo00O0OO0Ooo0 ,
 mr_sport , OOO0O0O , O0O00O , oOOoO )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , oo00O0OO0Ooo0 , mr_sport )
   if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
   if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
  return ( [ iI1IiiIiIIIi1 . eid , iI1IiiIiIIIi1 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 13 - 13: Ii1I % i11iIiiIii
  if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
  if 50 - 50: I1ii11iIi11i + iII111i
  if 64 - 64: oO0o
  if 11 - 11: o0oOOo0O0Ooo
 ooOOo0ooo = len ( iI1IiiIiIIIi1 . registered_rlocs )
 if ( ooOOo0ooo == 0 ) :
  lprint ( ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" ) . format ( green ( iIiI1I1ii1I1 , False ) , iii11i1i1II11 ,
  # O0 + iIii1I11I1II1 / Oo0Ooo * OOooOOo . OOooOOo - I11i
 green ( oOo00OO0ooo , False ) ) )
  return ( [ iI1IiiIiIIIi1 . eid , iI1IiiIiIIIi1 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 36 - 36: O0
  if 91 - 91: Oo0Ooo / I11i / OoooooooOO - I1ii11iIi11i
  if 7 - 7: oO0o - I11i
  if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
  if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
 IIIi1Iiiii1Ii = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 63 - 63: i11iIiiIii + Oo0Ooo + IiII - I1IiiI + I1IiiI
 iiIIII11iIii = map_request . target_eid . hash_address ( IIIi1Iiiii1Ii )
 iiIIII11iIii %= ooOOo0ooo
 i1i1 = iI1IiiIiIIIi1 . registered_rlocs [ iiIIII11iIii ]
 if 51 - 51: OoO0O00
 if ( i1i1 . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( iIiI1I1ii1I1 , False ) ,
  # OoOoOO00 * ooOoO0o - Ii1I
 iii11i1i1II11 , green ( oOo00OO0ooo , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( iIiI1I1ii1I1 , False ) ,
  # oO0o - IiII % OoooooooOO . ooOoO0o * I1IiiI
 red ( i1i1 . rloc . print_address ( ) , False ) , iii11i1i1II11 ,
 green ( oOo00OO0ooo , False ) ) )
  if 44 - 44: o0oOOo0O0Ooo
  if 76 - 76: i11iIiiIii % OoO0O00
  if 38 - 38: I1ii11iIi11i + II111iiii - I1ii11iIi11i
  if 67 - 67: Ii1I / OoOoOO00
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , i1i1 . rloc , to_etr = True )
  if 19 - 19: OoO0O00 - OOooOOo * O0
 return ( [ iI1IiiIiIIIi1 . eid , iI1IiiIiIIIi1 . group , LISP_DDT_ACTION_MS_ACK ] )
 if 75 - 75: Ii1I + Oo0Ooo
 if 72 - 72: iII111i / o0oOOo0O0Ooo % I1IiiI * OOooOOo % I1ii11iIi11i * i11iIiiIii
 if 12 - 12: Ii1I * iIii1I11I1II1 . OoOoOO00 % i1IIi
 if 24 - 24: OoOoOO00 . OoO0O00 / oO0o * OoO0O00 . ooOoO0o * i11iIiiIii
 if 61 - 61: ooOoO0o % IiII
 if 23 - 23: OoooooooOO % o0oOOo0O0Ooo + OoO0O00
 if 25 - 25: IiII % OOooOOo + Ii1I * I1ii11iIi11i
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 25 - 25: iIii1I11I1II1 * OoOoOO00 % I1IiiI + IiII
 if 34 - 34: ooOoO0o - OoooooooOO . o0oOOo0O0Ooo
 if 83 - 83: II111iiii . OOooOOo
 if 88 - 88: O0
 I11I = map_request . target_eid
 o0o0o = map_request . target_group
 iIiI1I1ii1I1 = lisp_print_eid_tuple ( I11I , o0o0o )
 OOO0O0O = map_request . nonce
 oOoO0OooO0O = LISP_DDT_ACTION_NULL
 if 12 - 12: Ii1I % OOooOOo % Oo0Ooo * I1Ii111
 if 96 - 96: iII111i + ooOoO0o
 if 100 - 100: OOooOOo . ooOoO0o + Ii1I + Ii1I
 if 70 - 70: ooOoO0o . iIii1I11I1II1 / oO0o
 if 18 - 18: Ii1I / OoooooooOO % i1IIi * o0oOOo0O0Ooo
 O0ooO0oOoOo = None
 if ( lisp_i_am_ms ) :
  iI1IiiIiIIIi1 = lisp_site_eid_lookup ( I11I , o0o0o , False )
  if ( iI1IiiIiIIIi1 == None ) : return
  if 54 - 54: o0oOOo0O0Ooo
  if ( iI1IiiIiIIIi1 . registered ) :
   oOoO0OooO0O = LISP_DDT_ACTION_MS_ACK
   O0O00O = 1440
  else :
   I11I , o0o0o , oOoO0OooO0O = lisp_ms_compute_neg_prefix ( I11I , o0o0o )
   oOoO0OooO0O = LISP_DDT_ACTION_MS_NOT_REG
   O0O00O = 1
   if 53 - 53: II111iiii / IiII . i1IIi + I1Ii111 / OoO0O00 - OoooooooOO
 else :
  O0ooO0oOoOo = lisp_ddt_cache_lookup ( I11I , o0o0o , False )
  if ( O0ooO0oOoOo == None ) :
   oOoO0OooO0O = LISP_DDT_ACTION_NOT_AUTH
   O0O00O = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( iIiI1I1ii1I1 , False ) ) )
   if 67 - 67: ooOoO0o . Ii1I - Oo0Ooo * iII111i . I11i - OOooOOo
  elif ( O0ooO0oOoOo . is_auth_prefix ( ) ) :
   if 10 - 10: I11i
   if 37 - 37: o0oOOo0O0Ooo / I1IiiI * oO0o / II111iiii
   if 39 - 39: IiII - i1IIi - IiII - OoooooooOO - I1ii11iIi11i
   if 66 - 66: IiII + i1IIi
   oOoO0OooO0O = LISP_DDT_ACTION_DELEGATION_HOLE
   O0O00O = 15
   i1ii = O0ooO0oOoOo . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( i1ii ,
   # ooOoO0o % Ii1I . i1IIi
 green ( iIiI1I1ii1I1 , False ) ) )
   if 21 - 21: i11iIiiIii / II111iiii % OoOoOO00 * oO0o - ooOoO0o + II111iiii
   if ( o0o0o . is_null ( ) ) :
    I11I = lisp_ddt_compute_neg_prefix ( I11I , O0ooO0oOoOo ,
 lisp_ddt_cache )
   else :
    o0o0o = lisp_ddt_compute_neg_prefix ( o0o0o , O0ooO0oOoOo ,
 lisp_ddt_cache )
    I11I = lisp_ddt_compute_neg_prefix ( I11I , O0ooO0oOoOo ,
 O0ooO0oOoOo . source_cache )
    if 66 - 66: i11iIiiIii * I1Ii111
   O0ooO0oOoOo = None
  else :
   i1ii = O0ooO0oOoOo . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( i1ii , green ( iIiI1I1ii1I1 , False ) ) )
   if 7 - 7: OoO0O00 . OoO0O00 % ooOoO0o * Oo0Ooo - O0 / Ii1I
   O0O00O = 1440
   if 54 - 54: I1Ii111 - ooOoO0o
   if 16 - 16: Ii1I + i11iIiiIii . OoO0O00 / I11i . I11i % I11i
   if 80 - 80: i11iIiiIii + OoO0O00
   if 2 - 2: II111iiii
   if 67 - 67: oO0o % I1Ii111
   if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
 OO0Oo00OO0oo = lisp_build_map_referral ( I11I , o0o0o , O0ooO0oOoOo , oOoO0OooO0O , O0O00O , OOO0O0O )
 OOO0O0O = map_request . nonce >> 32
 if ( map_request . nonce != 0 and OOO0O0O != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , OO0Oo00OO0oo , ecm_source , port )
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
 ooOoO00 = 0
 if 6 - 6: I1ii11iIi11i / i1IIi
 if 11 - 11: iIii1I11I1II1
 if 94 - 94: i1IIi . Oo0Ooo / o0oOOo0O0Ooo % I1Ii111 / OOooOOo + OoOoOO00
 if 21 - 21: Oo0Ooo / Oo0Ooo
 for ooOoO00 in range ( OOooO0Ooo ) :
  i1111i = 1 << ( OOooO0Ooo - ooOoO00 - 1 )
  if ( oo00o & i1111i ) : break
  if 15 - 15: OoooooooOO - i1IIi - Oo0Ooo - IiII
  if 80 - 80: II111iiii - I1ii11iIi11i / iIii1I11I1II1 % Oo0Ooo . Ii1I
 if ( ooOoO00 > neg_prefix . mask_len ) : neg_prefix . mask_len = ooOoO00
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
 I11I , o00 , IiI1i = parms
 if 11 - 11: o0oOOo0O0Ooo - iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
 if ( o00 == None ) :
  if ( entry . eid . instance_id != I11I . instance_id ) :
   return ( [ True , parms ] )
   if 51 - 51: I1IiiI + O0
  if ( entry . eid . afi != I11I . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( o00 ) == False ) :
   return ( [ True , parms ] )
   if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
   if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
   if 85 - 85: OoOoOO00
   if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
   if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
   if 72 - 72: Ii1I
 lisp_find_negative_mask_len ( I11I , entry . eid , IiI1i )
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
 oOoO0OooO0O = LISP_DDT_ACTION_DELEGATION_HOLE if ( o00 != None ) else LISP_DDT_ACTION_NOT_AUTH
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
 return ( [ IiI1i , I1Ii11I1 , oOoO0OooO0O ] )
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
 I11I = map_request . target_eid
 o0o0o = map_request . target_group
 OOO0O0O = map_request . nonce
 if 60 - 60: I1IiiI / I1IiiI / II111iiii
 if ( action == LISP_DDT_ACTION_MS_ACK ) : O0O00O = 1440
 if 59 - 59: OOooOOo . oO0o + ooOoO0o % o0oOOo0O0Ooo . i11iIiiIii
 if 27 - 27: OoOoOO00 - OoooooooOO / IiII / II111iiii * OOooOOo * ooOoO0o
 if 43 - 43: II111iiii . IiII - I1IiiI * I1ii11iIi11i + OoooooooOO
 if 34 - 34: I1Ii111 / i1IIi
 Ii = lisp_map_referral ( )
 Ii . record_count = 1
 Ii . nonce = OOO0O0O
 OO0Oo00OO0oo = Ii . encode ( )
 Ii . print_map_referral ( )
 if 95 - 95: OoOoOO00 * OOooOOo
 oO00O0o0Oo = False
 if 68 - 68: I1Ii111 / iIii1I11I1II1 % Ii1I
 if 77 - 77: i11iIiiIii + i11iIiiIii - I1ii11iIi11i % I1ii11iIi11i
 if 26 - 26: oO0o + OoooooooOO % o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
 if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
 if 77 - 77: OOooOOo + ooOoO0o / O0
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( I11I ,
 o0o0o )
  O0O00O = 15
  if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : O0O00O = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : O0O00O = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : O0O00O = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : O0O00O = 0
 if 49 - 49: ooOoO0o . Ii1I
 O0Oo = False
 ooOOo0ooo = 0
 O0ooO0oOoOo = lisp_ddt_cache_lookup ( I11I , o0o0o , False )
 if ( O0ooO0oOoOo != None ) :
  ooOOo0ooo = len ( O0ooO0oOoOo . delegation_set )
  O0Oo = O0ooO0oOoOo . is_ms_peer_entry ( )
  O0ooO0oOoOo . map_referrals_sent += 1
  if 47 - 47: OoO0O00 * I1Ii111 % OoooooooOO
  if 38 - 38: Ii1I % i1IIi
  if 41 - 41: I1ii11iIi11i . ooOoO0o / Oo0Ooo + i1IIi / i11iIiiIii * I1IiiI
  if 63 - 63: ooOoO0o + i11iIiiIii / i1IIi - I1Ii111 . O0 % OOooOOo
  if 39 - 39: o0oOOo0O0Ooo
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : oO00O0o0Oo = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  oO00O0o0Oo = ( O0Oo == False )
  if 88 - 88: iII111i % I1IiiI . iIii1I11I1II1 * OOooOOo / IiII % OoooooooOO
  if 94 - 94: ooOoO0o % oO0o - OoooooooOO + IiII * Ii1I
  if 60 - 60: OoO0O00 - O0 + o0oOOo0O0Ooo + I1ii11iIi11i
  if 78 - 78: OOooOOo * Oo0Ooo * Ii1I
  if 94 - 94: OoooooooOO % iII111i
 O0oIII = lisp_eid_record ( )
 O0oIII . rloc_count = ooOOo0ooo
 O0oIII . authoritative = True
 O0oIII . action = action
 O0oIII . ddt_incomplete = oO00O0o0Oo
 O0oIII . eid = eid_prefix
 O0oIII . group = group_prefix
 O0oIII . record_ttl = O0O00O
 if 48 - 48: iIii1I11I1II1
 OO0Oo00OO0oo += O0oIII . encode ( )
 O0oIII . print_record ( "  " , True )
 if 25 - 25: i1IIi % o0oOOo0O0Ooo . iII111i / OoooooooOO + i1IIi
 if 76 - 76: Oo0Ooo / OOooOOo + ooOoO0o % OoooooooOO - Oo0Ooo - I11i
 if 36 - 36: OoO0O00 . Oo0Ooo * I1ii11iIi11i
 if 16 - 16: IiII + OOooOOo
 if ( ooOOo0ooo != 0 ) :
  for IiI11111I1ii1 in O0ooO0oOoOo . delegation_set :
   i1IOoo0 = lisp_rloc_record ( )
   i1IOoo0 . rloc = IiI11111I1ii1 . delegate_address
   i1IOoo0 . priority = IiI11111I1ii1 . priority
   i1IOoo0 . weight = IiI11111I1ii1 . weight
   i1IOoo0 . mpriority = 255
   i1IOoo0 . mweight = 0
   i1IOoo0 . reach_bit = True
   OO0Oo00OO0oo += i1IOoo0 . encode ( )
   i1IOoo0 . print_record ( "    " )
   if 33 - 33: ooOoO0o . i11iIiiIii + OOooOOo
   if 77 - 77: OoooooooOO * Ii1I * iIii1I11I1II1 + IiII
   if 53 - 53: IiII + I1Ii111 + oO0o
   if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
   if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
   if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
   if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , OO0Oo00OO0oo , ecm_source , port )
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
 oOoO0OooO0O = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 48 - 48: oO0o / i1IIi . II111iiii
 if 46 - 46: O0 * oO0o * I1Ii111
 if 76 - 76: Oo0Ooo + OOooOOo - i1IIi * iII111i % i11iIiiIii
 if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 if ( lisp_get_eid_hash ( eid ) != None ) :
  oOoO0OooO0O = LISP_SEND_MAP_REQUEST_ACTION
  if 41 - 41: Ii1I + IiII
  if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
 OO0Oo00OO0oo = lisp_build_map_reply ( eid , group , [ ] , nonce , oOoO0OooO0O , ttl , None ,
 None , False , False )
 if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
 if 99 - 99: i1IIi * OoOoOO00 - i1IIi
 if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
 if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , OO0Oo00OO0oo , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , OO0Oo00OO0oo , dest , port )
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
 OOO0O0O = mr . nonce
 if 13 - 13: Oo0Ooo / OoO0O00 + I1Ii111
 if 48 - 48: I1ii11iIi11i * i1IIi + I1Ii111
 if 80 - 80: I1IiiI % I11i
 if 64 - 64: OOooOOo + i11iIiiIii + I1IiiI . I11i % I11i - o0oOOo0O0Ooo
 if 3 - 3: I1IiiI / i1IIi + II111iiii + Oo0Ooo
 if ( mr . last_request_sent_to ) :
  ii1iiI11 = mr . last_request_sent_to . print_address ( )
  oOo0III = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( oOo0III and ii1iiI11 in oOo0III . referral_set ) :
   oOo0III . referral_set [ ii1iiI11 ] . no_responses += 1
   if 39 - 39: II111iiii / OoO0O00 % OOooOOo
   if 5 - 5: iII111i
   if 34 - 34: I1ii11iIi11i * iIii1I11I1II1
   if 63 - 63: IiII
   if 58 - 58: Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
   if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
   if 10 - 10: I11i
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( i1OOOoO0O0O0O , False ) , lisp_hex_string ( OOO0O0O ) ) )
  if 24 - 24: Ii1I
  mr . dequeue_map_request ( )
  return
  if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
  if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
 mr . retry_count += 1
 if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
 I1iiIi111I = green ( iI11iI11i11ii , False )
 iiIi = green ( i1OOOoO0O0O0O , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # I1ii11iIi11i
 red ( mr . itr . print_address ( ) , False ) , I1iiIi111I , iiIi ,
 lisp_hex_string ( OOO0O0O ) ) )
 if 95 - 95: i11iIiiIii + I1ii11iIi11i
 if 97 - 97: ooOoO0o * iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - o0oOOo0O0Ooo
 if 37 - 37: II111iiii
 if 27 - 27: Oo0Ooo * OoooooooOO / I1IiiI
 lisp_send_ddt_map_request ( mr , False )
 if 43 - 43: OoO0O00
 if 51 - 51: OoooooooOO % IiII % Oo0Ooo
 if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
 if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 95 - 95: iII111i
 if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
 if 19 - 19: OOooOOo * o0oOOo0O0Ooo
 if 64 - 64: I11i % ooOoO0o / OOooOOo / iII111i
 if 80 - 80: i1IIi
 if 74 - 74: I1ii11iIi11i . OoO0O00 + i11iIiiIii
 if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
 if 68 - 68: iII111i
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
 if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
 if 9 - 9: IiII * O0 + OOooOOo . II111iiii
 if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
 oooo0oO = [ ]
 for IiIiiiII1I in list ( referral . referral_set . values ( ) ) :
  if ( IiIiiiII1I . updown == False ) : continue
  if ( len ( oooo0oO ) == 0 or oooo0oO [ 0 ] . priority == IiIiiiII1I . priority ) :
   oooo0oO . append ( IiIiiiII1I )
  elif ( oooo0oO [ 0 ] . priority > IiIiiiII1I . priority ) :
   oooo0oO = [ ]
   oooo0oO . append ( IiIiiiII1I )
   if 30 - 30: o0oOOo0O0Ooo + iIii1I11I1II1 - II111iiii - ooOoO0o + OoOoOO00 - II111iiii
   if 69 - 69: oO0o / O0 / I1IiiI + OoooooooOO * I11i * IiII
   if 41 - 41: ooOoO0o % i11iIiiIii
 o0OoooO00 = len ( oooo0oO )
 if ( o0OoooO00 == 0 ) : return ( None )
 if 21 - 21: OoOoOO00
 iiIIII11iIii = dest_eid . hash_address ( source_eid )
 iiIIII11iIii = iiIIII11iIii % o0OoooO00
 return ( oooo0oO [ iiIIII11iIii ] )
 if 2 - 2: i1IIi . OOooOOo
 if 23 - 23: Ii1I - OOooOOo
 if 89 - 89: i11iIiiIii
 if 40 - 40: OoooooooOO % OoO0O00
 if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
 if 90 - 90: O0 - II111iiii + I1IiiI . iII111i
 if 3 - 3: o0oOOo0O0Ooo + i1IIi * Oo0Ooo
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 iI1ii1IIi11i1 = mr . lisp_sockets
 OOO0O0O = mr . nonce
 I1IoOO0oOOOOO0 = mr . itr
 oOO00O0oooo00 = mr . mr_source
 iIiI1I1ii1I1 = mr . print_eid_tuple ( )
 if 90 - 90: Oo0Ooo - IiII % O0
 if 57 - 57: OoooooooOO - o0oOOo0O0Ooo * Oo0Ooo + ooOoO0o
 if 22 - 22: I1ii11iIi11i % I1Ii111 % i11iIiiIii . ooOoO0o
 if 48 - 48: ooOoO0o - O0
 if 29 - 29: oO0o . oO0o
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( iIiI1I1ii1I1 , False ) , lisp_hex_string ( OOO0O0O ) ) )
  if 96 - 96: O0
  mr . dequeue_map_request ( )
  return
  if 85 - 85: Oo0Ooo + i11iIiiIii . OOooOOo / II111iiii / iII111i
  if 90 - 90: o0oOOo0O0Ooo - OoooooooOO - i1IIi
  if 47 - 47: I1Ii111 * Ii1I . iIii1I11I1II1 / OoOoOO00
  if 68 - 68: i11iIiiIii / OOooOOo / I1ii11iIi11i % IiII * IiII + II111iiii
  if 65 - 65: I1IiiI + OoOoOO00 - OoOoOO00 . oO0o
  if 84 - 84: Ii1I * i1IIi
 if ( send_to_root ) :
  III1IIi1 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  Oo000O = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( iIiI1I1ii1I1 , False ) ) )
 else :
  III1IIi1 = mr . eid
  Oo000O = mr . group
  if 6 - 6: iIii1I11I1II1 + oO0o
  if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
  if 29 - 29: Ii1I . OOooOOo
  if 59 - 59: O0 . OoO0O00
  if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
 oo00oO0ooo = lisp_referral_cache_lookup ( III1IIi1 , Oo000O , False )
 if ( oo00oO0ooo == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( iI1ii1IIi11i1 , III1IIi1 , Oo000O ,
 OOO0O0O , I1IoOO0oOOOOO0 , mr . sport , 15 , None , False )
  return
  if 6 - 6: iIii1I11I1II1 . O0 . oO0o + I1ii11iIi11i
  if 32 - 32: I1IiiI / OOooOOo . i11iIiiIii - IiII . iII111i . Ii1I
 IiI11IIIIIi = oo00oO0ooo . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( IiI11IIIIIi ,
 oo00oO0ooo . print_referral_type ( ) ) )
 if 24 - 24: OoooooooOO . o0oOOo0O0Ooo * OoOoOO00 % Oo0Ooo . OoO0O00 / OoooooooOO
 IiIiiiII1I = lisp_get_referral_node ( oo00oO0ooo , oOO00O0oooo00 , mr . eid )
 if ( IiIiiiII1I == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( iI1ii1IIi11i1 , oo00oO0ooo . eid ,
 oo00oO0ooo . group , OOO0O0O , I1IoOO0oOOOOO0 , mr . sport , 1 , None , False )
  return
  if 59 - 59: OoO0O00 + O0 + i11iIiiIii / OoOoOO00 + iIii1I11I1II1 / OoOoOO00
  if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( IiIiiiII1I . referral_address . print_address ( ) ,
 # I11i - I11i + O0 * I1IiiI * O0 * II111iiii
 oo00oO0ooo . print_referral_type ( ) , green ( iIiI1I1ii1I1 , False ) ,
 lisp_hex_string ( OOO0O0O ) ) )
 if 73 - 73: II111iiii
 if 81 - 81: I1IiiI + OoO0O00
 if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
 if 32 - 32: o0oOOo0O0Ooo - iII111i + i11iIiiIii / ooOoO0o . OoOoOO00 . IiII
 iIiiii1 = ( oo00oO0ooo . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 oo00oO0ooo . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( iI1ii1IIi11i1 , mr . packet , oOO00O0oooo00 , mr . sport , mr . eid ,
 IiIiiiII1I . referral_address , to_ms = iIiiii1 , ddt = True )
 if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
 if 26 - 26: I1ii11iIi11i
 if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
 if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
 mr . last_request_sent_to = IiIiiiII1I . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 IiIiiiII1I . map_requests_sent += 1
 return
 if 40 - 40: Ii1I / i1IIi . iII111i
 if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
 if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
 if 85 - 85: I1IiiI + i1IIi % I1Ii111
 if 76 - 76: i11iIiiIii % i11iIiiIii
 if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
 if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
 if 69 - 69: O0 % I1ii11iIi11i
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 77 - 77: iIii1I11I1II1 . OOooOOo
 I11I = map_request . target_eid
 o0o0o = map_request . target_group
 i1OOOoO0O0O0O = map_request . print_eid_tuple ( )
 iI11iI11i11ii = mr_source . print_address ( )
 OOO0O0O = map_request . nonce
 if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 I1iiIi111I = green ( iI11iI11i11ii , False )
 iiIi = green ( i1OOOoO0O0O0O , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # OOooOOo . Oo0Ooo - Oo0Ooo * i1IIi
 red ( ecm_source . print_address ( ) , False ) , I1iiIi111I , iiIi ,
 lisp_hex_string ( OOO0O0O ) ) )
 if 67 - 67: IiII + ooOoO0o . i1IIi % I1Ii111 . I1IiiI . Oo0Ooo
 if 58 - 58: I11i - I1ii11iIi11i + I1IiiI
 if 79 - 79: Oo0Ooo . OoooooooOO * II111iiii . Oo0Ooo % Oo0Ooo - i1IIi
 if 88 - 88: II111iiii * oO0o + I1IiiI . II111iiii
 OO0O0O0OOO0OO = lisp_ddt_map_request ( lisp_sockets , packet , I11I , o0o0o , OOO0O0O )
 OO0O0O0OOO0OO . packet = packet
 OO0O0O0OOO0OO . itr = ecm_source
 OO0O0O0OOO0OO . mr_source = mr_source
 OO0O0O0OOO0OO . sport = sport
 OO0O0O0OOO0OO . from_pitr = map_request . pitr_bit
 OO0O0O0OOO0OO . queue_map_request ( )
 if 80 - 80: iIii1I11I1II1
 lisp_send_ddt_map_request ( OO0O0O0OOO0OO , False )
 return
 if 97 - 97: I1ii11iIi11i + IiII - iII111i . i1IIi . O0
 if 33 - 33: i11iIiiIii . iII111i % o0oOOo0O0Ooo
 if 35 - 35: OoO0O00 + OOooOOo % II111iiii * Ii1I / OoOoOO00
 if 71 - 71: OOooOOo / i1IIi
 if 50 - 50: iIii1I11I1II1 * IiII
 if 73 - 73: II111iiii
 if 4 - 4: II111iiii * o0oOOo0O0Ooo + I11i . II111iiii
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 35 - 35: ooOoO0o - ooOoO0o . i1IIi % oO0o * IiII * I1ii11iIi11i
 OOooo = packet
 III1II1iiI = lisp_map_request ( )
 packet = III1II1iiI . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 46 - 46: O0 % ooOoO0o
  if 79 - 79: I1ii11iIi11i
 III1II1iiI . print_map_request ( )
 if 9 - 9: IiII . O0
 if 66 - 66: i11iIiiIii
 if 33 - 33: i11iIiiIii % OoO0O00 * I1ii11iIi11i
 if 96 - 96: I11i % OoooooooOO * I11i . IiII / I1Ii111
 if ( III1II1iiI . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , III1II1iiI , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 56 - 56: I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
  if 84 - 84: OoOoOO00
  if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
  if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
  if 85 - 85: o0oOOo0O0Ooo % Ii1I
 if ( III1II1iiI . smr_bit ) :
  lisp_process_smr ( III1II1iiI )
  if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
  if 23 - 23: II111iiii . II111iiii
  if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
  if 21 - 21: OOooOOo % Ii1I
  if 3 - 3: OOooOOo / ooOoO0o / I1Ii111 . I11i
 if ( III1II1iiI . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( III1II1iiI )
  if 54 - 54: I1ii11iIi11i - I1IiiI . OoOoOO00
  if 36 - 36: OoO0O00 * I1IiiI / iII111i
  if 95 - 95: Ii1I . Oo0Ooo
  if 42 - 42: IiII . i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o
  if 99 - 99: i1IIi + OoOoOO00 - iII111i % II111iiii
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , III1II1iiI , mr_source ,
 mr_port , ttl , timestamp )
  if 6 - 6: ooOoO0o - I1Ii111 . OoOoOO00
  if 64 - 64: iII111i + I1ii11iIi11i
  if 88 - 88: I1Ii111 / i11iIiiIii - O0 . II111iiii / II111iiii * II111iiii
  if 56 - 56: Oo0Ooo / I1IiiI % I1Ii111 % I1ii11iIi11i * I1IiiI - IiII
  if 39 - 39: oO0o + iII111i . I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + OOooOOo
 if ( lisp_i_am_ms ) :
  packet = OOooo
  I11I , o0o0o , O0o0O = lisp_ms_process_map_request ( lisp_sockets ,
 OOooo , III1II1iiI , mr_source , mr_port , ecm_source )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , III1II1iiI , ecm_source ,
 ecm_port , O0o0O , I11I , o0o0o )
   if 57 - 57: iII111i % iII111i - II111iiii * I1IiiI / I11i
  return
  if 100 - 100: Ii1I % OoO0O00 % OoooooooOO / II111iiii * I1Ii111
  if 64 - 64: I1Ii111 * OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / Oo0Ooo
  if 50 - 50: OOooOOo % i11iIiiIii
  if 99 - 99: IiII
  if 87 - 87: IiII
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , OOooo , III1II1iiI ,
 ecm_source , mr_port , mr_source )
  if 35 - 35: oO0o . O0 . Ii1I / ooOoO0o
  if 36 - 36: i11iIiiIii . II111iiii . I11i . II111iiii
  if 36 - 36: Ii1I + ooOoO0o / Oo0Ooo % Oo0Ooo
  if 2 - 2: oO0o - Oo0Ooo * OoO0O00 . ooOoO0o . OOooOOo - oO0o
  if 74 - 74: o0oOOo0O0Ooo
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = OOooo
  lisp_ddt_process_map_request ( lisp_sockets , III1II1iiI , ecm_source ,
 ecm_port )
  if 18 - 18: Oo0Ooo % OOooOOo / OOooOOo . I1IiiI + i1IIi . I1IiiI
 return
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
 if 6 - 6: O0 * I1Ii111 - II111iiii
 if 60 - 60: oO0o % oO0o
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
 if 82 - 82: I1ii11iIi11i
 if 75 - 75: I11i - II111iiii
def lisp_store_mr_stats ( source , nonce ) :
 OO0O0O0OOO0OO = lisp_get_map_resolver ( source , None )
 if ( OO0O0O0OOO0OO == None ) : return
 if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
 if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
 if 76 - 76: OOooOOo - iII111i + IiII
 if 48 - 48: I1IiiI - II111iiii
 OO0O0O0OOO0OO . neg_map_replies_received += 1
 OO0O0O0OOO0OO . last_reply = lisp_get_timestamp ( )
 if 15 - 15: O0
 if 54 - 54: iIii1I11I1II1
 if 54 - 54: iII111i + OOooOOo + OoO0O00
 if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
 if ( ( OO0O0O0OOO0OO . neg_map_replies_received % 100 ) == 0 ) : OO0O0O0OOO0OO . total_rtt = 0
 if 65 - 65: IiII + OoOoOO00
 if 93 - 93: Ii1I
 if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
 if 5 - 5: OoO0O00 / ooOoO0o
 if ( OO0O0O0OOO0OO . last_nonce == nonce ) :
  OO0O0O0OOO0OO . total_rtt += ( time . time ( ) - OO0O0O0OOO0OO . last_used )
  OO0O0O0OOO0OO . last_nonce = 0
  if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
 if ( ( OO0O0O0OOO0OO . neg_map_replies_received % 10 ) == 0 ) : OO0O0O0OOO0OO . last_nonce = 0
 return
 if 97 - 97: oO0o / Ii1I
 if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
 if 91 - 91: IiII * Ii1I * OOooOOo
 if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
 if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
 if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
 Oo0oOooOoo = lisp_map_reply ( )
 packet = Oo0oOooOoo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
 Oo0oOooOoo . print_map_reply ( )
 if 95 - 95: IiII + iII111i % I1IiiI
 if 18 - 18: Oo0Ooo
 if 8 - 8: O0 + iIii1I11I1II1 - O0
 if 67 - 67: O0
 I1ii1 = None
 for OoOOoO0oOo in range ( Oo0oOooOoo . record_count ) :
  O0oIII = lisp_eid_record ( )
  packet = O0oIII . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 30 - 30: I1ii11iIi11i * I11i
  O0oIII . print_record ( "  " , False )
  if 76 - 76: I1ii11iIi11i / O0
  if 38 - 38: oO0o + oO0o . iII111i / OoO0O00
  if 27 - 27: o0oOOo0O0Ooo * I1ii11iIi11i
  if 100 - 100: I1Ii111 / O0 - iIii1I11I1II1 . iII111i % I1Ii111 - ooOoO0o
  if 100 - 100: OoO0O00 + I1ii11iIi11i + I1ii11iIi11i . I1Ii111
  if ( O0oIII . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , Oo0oOooOoo . nonce )
   if 83 - 83: OoOoOO00 / OOooOOo * II111iiii * OoooooooOO
   if 51 - 51: OoOoOO00 + o0oOOo0O0Ooo / Ii1I
  oOoOo = ( O0oIII . group . is_null ( ) == False )
  if 6 - 6: I11i % IiII
  if 48 - 48: Ii1I
  if 100 - 100: OoO0O00 % I1Ii111 + OoooooooOO / OoO0O00
  if 62 - 62: IiII
  if 66 - 66: o0oOOo0O0Ooo % OOooOOo
  if ( lisp_decent_push_configured ) :
   oOoO0OooO0O = O0oIII . action
   if ( oOoOo and oOoO0OooO0O == LISP_DROP_ACTION ) :
    if ( O0oIII . eid . is_local ( ) ) : continue
    if 15 - 15: Ii1I % IiII + IiII % iII111i - O0 * OoooooooOO
    if 53 - 53: OoOoOO00 . Ii1I / Oo0Ooo
    if 62 - 62: i11iIiiIii
    if 38 - 38: I1ii11iIi11i % ooOoO0o * OoooooooOO + iIii1I11I1II1 % i1IIi / OOooOOo
    if 6 - 6: i11iIiiIii
    if 8 - 8: iIii1I11I1II1 + I1ii11iIi11i . i1IIi % OoOoOO00 % OoooooooOO * Oo0Ooo
    if 53 - 53: oO0o
  if ( oOoOo == False and O0oIII . eid . is_null ( ) ) : continue
  if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
  if 4 - 4: I1IiiI
  if 31 - 31: ooOoO0o * i1IIi . O0
  if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
  if 100 - 100: I1Ii111
  if ( oOoOo ) :
   O0oo0OOo00o0o = lisp_map_cache_lookup ( O0oIII . eid , O0oIII . group )
  else :
   O0oo0OOo00o0o = lisp_map_cache . lookup_cache ( O0oIII . eid , True )
   if 18 - 18: iII111i
  O00 = ( O0oo0OOo00o0o == None )
  if 68 - 68: OoO0O00 * i1IIi
  if 39 - 39: OoO0O00 % OoO0O00
  if 18 - 18: ooOoO0o * I1IiiI / iII111i % iII111i
  if 9 - 9: i11iIiiIii % ooOoO0o % O0 + i1IIi / O0
  if 12 - 12: I1Ii111 - iII111i * iII111i + OoO0O00 . Ii1I % I11i
  if ( O0oo0OOo00o0o == None ) :
   I1II1iI1IiI , ooooO00o0 , IIi11I = lisp_allow_gleaning ( O0oIII . eid , O0oIII . group ,
 None )
   if ( I1II1iI1IiI ) : continue
  else :
   if ( O0oo0OOo00o0o . gleaned ) : continue
   if 84 - 84: IiII / Ii1I
   if 39 - 39: OOooOOo - iIii1I11I1II1 + OoOoOO00 % IiII * OoooooooOO % Ii1I
   if 11 - 11: I1ii11iIi11i
   if 83 - 83: O0
   if 97 - 97: O0
  IIiii11iiI111 = [ ]
  I1iiI = None
  for Oooo0 in range ( O0oIII . rloc_count ) :
   i1IOoo0 = lisp_rloc_record ( )
   i1IOoo0 . keys = Oo0oOooOoo . keys
   packet = i1IOoo0 . decode ( packet , Oo0oOooOoo . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 91 - 91: ooOoO0o . II111iiii
   i1IOoo0 . print_record ( "    " )
   if 15 - 15: i11iIiiIii % OOooOOo - iII111i
   I1I1oO0oo = None
   if ( O0oo0OOo00o0o ) : I1I1oO0oo = O0oo0OOo00o0o . get_rloc ( i1IOoo0 . rloc )
   if ( I1I1oO0oo ) :
    OooOOoOO0OO = I1I1oO0oo
   else :
    OooOOoOO0OO = lisp_rloc ( )
    if 7 - 7: iIii1I11I1II1 - I1Ii111 . ooOoO0o . O0 - OOooOOo
    if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
    if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
    if 9 - 9: Ii1I
    if 44 - 44: iII111i
    if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
    if 37 - 37: OoO0O00 - Ii1I + OoO0O00
   O00oo0o0o0oo = OooOOoOO0OO . store_rloc_from_record ( i1IOoo0 , Oo0oOooOoo . nonce ,
 source )
   OooOOoOO0OO . echo_nonce_capable = Oo0oOooOoo . echo_nonce_capable
   if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
   if ( OooOOoOO0OO . echo_nonce_capable ) :
    Oo0o = OooOOoOO0OO . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , Oo0o ) == None ) :
     lisp_echo_nonce ( Oo0o )
     if 60 - 60: Oo0Ooo
     if 46 - 46: OoOoOO00 + i1IIi
     if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
     if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
     if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
     if 4 - 4: OoO0O00
   if ( OooOOoOO0OO . json ) :
    if ( lisp_is_json_telemetry ( OooOOoOO0OO . json . json_string ) ) :
     I1iIi = OooOOoOO0OO . json . json_string
     I1iIi = lisp_encode_telemetry ( I1iIi , ii = itr_in_ts )
     OooOOoOO0OO . json . json_string = I1iIi
     if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
     if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
     if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
     if 38 - 38: iII111i * OoooooooOO - IiII
     if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
     if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
     if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
     if 76 - 76: I11i . I1IiiI
     if 66 - 66: oO0o % oO0o * IiII
     if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
   if ( Oo0oOooOoo . rloc_probe and i1IOoo0 . probe_bit ) :
    if ( OooOOoOO0OO . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( OooOOoOO0OO , source , O00oo0o0o0oo ,
 Oo0oOooOoo , ttl , I1iiI )
     if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
    if ( OooOOoOO0OO . rloc . is_multicast_address ( ) ) : I1iiI = OooOOoOO0OO
    if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
    if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
    if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
    if 23 - 23: OOooOOo
    if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
   IIiii11iiI111 . append ( OooOOoOO0OO )
   if 47 - 47: OoO0O00
   if 52 - 52: I1IiiI * iIii1I11I1II1 % oO0o * IiII % oO0o
   if 9 - 9: I11i
   if 83 - 83: i11iIiiIii
   if ( lisp_data_plane_security and OooOOoOO0OO . rloc_recent_rekey ( ) ) :
    I1ii1 = OooOOoOO0OO
    if 72 - 72: oO0o + II111iiii . O0 * oO0o + iII111i
    if 22 - 22: I11i + Ii1I . IiII - OoO0O00 - o0oOOo0O0Ooo
    if 84 - 84: OoooooooOO - Oo0Ooo
    if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
    if 82 - 82: OoOoOO00
    if 61 - 61: oO0o . o0oOOo0O0Ooo
    if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
    if 70 - 70: I1IiiI
    if 74 - 74: ooOoO0o * II111iiii
    if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
    if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
  if ( Oo0oOooOoo . rloc_probe == False and lisp_nat_traversal ) :
   iii1 = [ ]
   oOOo = [ ]
   for OooOOoOO0OO in IIiii11iiI111 :
    if 67 - 67: I1IiiI % I11i - OoooooooOO
    if 2 - 2: Ii1I
    if 25 - 25: I1Ii111 * I1IiiI + OoOoOO00 . i11iIiiIii . I1IiiI . I11i
    if 61 - 61: o0oOOo0O0Ooo / ooOoO0o + o0oOOo0O0Ooo + Ii1I * iIii1I11I1II1 * OoooooooOO
    if 86 - 86: oO0o . o0oOOo0O0Ooo * OoOoOO00 / oO0o
    if ( OooOOoOO0OO . rloc . is_private_address ( ) ) :
     OooOOoOO0OO . priority = 1
     OooOOoOO0OO . state = LISP_RLOC_UNREACH_STATE
     iii1 . append ( OooOOoOO0OO )
     oOOo . append ( OooOOoOO0OO . rloc . print_address_no_iid ( ) )
     continue
     if 47 - 47: OOooOOo
     if 40 - 40: I1ii11iIi11i
     if 67 - 67: I1Ii111 - OoO0O00 * ooOoO0o - oO0o / OoO0O00 . I1Ii111
     if 39 - 39: Ii1I
     if 90 - 90: I1Ii111 - I1Ii111 . i11iIiiIii + OoooooooOO % OOooOOo / Oo0Ooo
     if 51 - 51: o0oOOo0O0Ooo
    if ( OooOOoOO0OO . priority == 254 and lisp_i_am_rtr == False ) :
     iii1 . append ( OooOOoOO0OO )
     oOOo . append ( OooOOoOO0OO . rloc . print_address_no_iid ( ) )
     if 8 - 8: oO0o . oO0o . Ii1I
    if ( OooOOoOO0OO . priority != 254 and lisp_i_am_rtr ) :
     iii1 . append ( OooOOoOO0OO )
     oOOo . append ( OooOOoOO0OO . rloc . print_address_no_iid ( ) )
     if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
     if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
     if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
   if ( oOOo != [ ] ) :
    IIiii11iiI111 = iii1
    lprint ( "NAT-traversal optimized RLOC-set: {}" . format ( oOOo ) )
    if 10 - 10: ooOoO0o
    if 69 - 69: I11i + I1IiiI / oO0o
    if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
    if 85 - 85: I1Ii111 - oO0o
    if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
    if 96 - 96: oO0o
    if 44 - 44: OoooooooOO / iII111i * Oo0Ooo % OoOoOO00 . oO0o
  iii1 = [ ]
  for OooOOoOO0OO in IIiii11iiI111 :
   if ( OooOOoOO0OO . json != None ) : continue
   iii1 . append ( OooOOoOO0OO )
   if 97 - 97: iIii1I11I1II1 / ooOoO0o
  if ( iii1 != [ ] ) :
   IiI = len ( IIiii11iiI111 ) - len ( iii1 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( IiI ) )
   if 16 - 16: Oo0Ooo % IiII
   IIiii11iiI111 = iii1
   if 48 - 48: I1IiiI . I1Ii111 . o0oOOo0O0Ooo
   if 72 - 72: Ii1I * OoO0O00 / OoO0O00
   if 39 - 39: oO0o
   if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
   if 57 - 57: oO0o + O0 - OoOoOO00
   if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
   if 93 - 93: o0oOOo0O0Ooo + i1IIi
   if 24 - 24: i1IIi
  if ( Oo0oOooOoo . rloc_probe and O0oo0OOo00o0o != None ) : IIiii11iiI111 = O0oo0OOo00o0o . rloc_set
  if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
  if 99 - 99: Oo0Ooo
  if 38 - 38: I1ii11iIi11i - I1IiiI
  if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
  if 42 - 42: iII111i + I1ii11iIi11i
  iI1iIIII1i1 = O00
  if ( O0oo0OOo00o0o and IIiii11iiI111 != O0oo0OOo00o0o . rloc_set ) :
   O0oo0OOo00o0o . delete_rlocs_from_rloc_probe_list ( )
   iI1iIIII1i1 = True
   if 94 - 94: OoOoOO00 . o0oOOo0O0Ooo
   if 27 - 27: IiII - IiII % OOooOOo
   if 16 - 16: I1IiiI * iIii1I11I1II1 % o0oOOo0O0Ooo - IiII - OOooOOo
   if 83 - 83: Ii1I
   if 20 - 20: ooOoO0o
  I1iII1 = O0oo0OOo00o0o . uptime if ( O0oo0OOo00o0o ) else None
  if ( O0oo0OOo00o0o == None ) :
   O0oo0OOo00o0o = lisp_mapping ( O0oIII . eid , O0oIII . group , IIiii11iiI111 )
   O0oo0OOo00o0o . mapping_source = source
   if 41 - 41: iII111i * OOooOOo . oO0o / ooOoO0o + OoooooooOO + ooOoO0o
   if 100 - 100: I1IiiI / I1IiiI - I1IiiI % OOooOOo * O0 * I1IiiI
   if 20 - 20: iII111i + ooOoO0o . i11iIiiIii
   if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
   if 50 - 50: OoooooooOO * II111iiii
   if 7 - 7: ooOoO0o / I11i * iII111i
   if ( lisp_i_am_rtr and O0oIII . group . is_null ( ) == False ) :
    O0oo0OOo00o0o . map_cache_ttl = LISP_MCAST_TTL
   else :
    O0oo0OOo00o0o . map_cache_ttl = O0oIII . store_ttl ( )
    if 17 - 17: O0 % I1Ii111
   O0oo0OOo00o0o . action = O0oIII . action
   O0oo0OOo00o0o . add_cache ( iI1iIIII1i1 )
   if 28 - 28: i1IIi * ooOoO0o
   if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
  oo0o0OOoO = "Add"
  if ( I1iII1 ) :
   O0oo0OOo00o0o . uptime = I1iII1
   O0oo0OOo00o0o . refresh_time = lisp_get_timestamp ( )
   oo0o0OOoO = "Replace"
   if 40 - 40: OoooooooOO - IiII
   if 74 - 74: II111iiii - i11iIiiIii - IiII + OOooOOo
  lprint ( "{} {} map-cache with {} RLOCs" . format ( oo0o0OOoO ,
 green ( O0oo0OOo00o0o . print_eid_tuple ( ) , False ) , len ( IIiii11iiI111 ) ) )
  if 8 - 8: I1ii11iIi11i
  if 56 - 56: o0oOOo0O0Ooo / I1ii11iIi11i
  if 25 - 25: iIii1I11I1II1 / OoO0O00 - o0oOOo0O0Ooo
  if 97 - 97: ooOoO0o % OoooooooOO * o0oOOo0O0Ooo
  if 8 - 8: I1ii11iIi11i + Oo0Ooo - iII111i
  if ( lisp_ipc_dp_socket and I1ii1 != None ) :
   lisp_write_ipc_keys ( I1ii1 )
   if 53 - 53: ooOoO0o / IiII
   if 36 - 36: iIii1I11I1II1
   if 78 - 78: II111iiii * I11i
   if 47 - 47: Ii1I
   if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
   if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
   if 53 - 53: iIii1I11I1II1
  if ( O00 ) :
   iiIii11Ii = bold ( "RLOC-probe" , False )
   for OooOOoOO0OO in O0oo0OOo00o0o . best_rloc_set :
    Oo0o = red ( OooOOoOO0OO . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( iiIii11Ii , Oo0o ) )
    lisp_send_map_request ( lisp_sockets , 0 , O0oo0OOo00o0o . eid , O0oo0OOo00o0o . group , OooOOoOO0OO )
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
 iiIIII11iIii = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 13 - 13: I1IiiI
 if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
 if 84 - 84: OoooooooOO - oO0o - I1Ii111
 if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
 map_register . auth_data = iiIIII11iIii
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
  iiIIII11iIii = hmac . new ( password . encode ( ) , packet , o00oO0OOo0O ) . hexdigest ( )
 else :
  iiIIII11iIii = hmac . new ( password . encode ( ) , packet , o00oO0OOo0O ) . digest ( )
  if 48 - 48: I1IiiI % OoO0O00
 return ( iiIIII11iIii )
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
 iiIIII11iIii = lisp_hash_me ( packet , alg_id , password , True )
 Oo0OoO = ( iiIIII11iIii == auth_data )
 if 62 - 62: iIii1I11I1II1 * o0oOOo0O0Ooo * OOooOOo . o0oOOo0O0Ooo + I11i
 if 46 - 46: o0oOOo0O0Ooo - i1IIi / OoO0O00 + o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 * o0oOOo0O0Ooo / i1IIi * I1Ii111 * I1ii11iIi11i
 if 45 - 45: iII111i / Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
 if ( Oo0OoO == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( iiIIII11iIii , auth_data ) )
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
 OooOOooo = map_notify . etr
 O00oo0o0o0oo = map_notify . etr_port
 if 63 - 63: OOooOOo + iII111i - IiII - I1IiiI % IiII . OoO0O00
 if 73 - 73: OoOoOO00
 if 47 - 47: oO0o
 if 17 - 17: IiII
 if 47 - 47: I11i . I1IiiI % ooOoO0o . i11iIiiIii
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( OooOOooo . print_address ( ) , False ) ) )
  if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
  if 100 - 100: O0
  III11II111 = map_notify . nonce_key
  if ( III11II111 in lisp_map_notify_queue ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( III11II111 ) )
   if 9 - 9: Ii1I
   try :
    lisp_map_notify_queue . pop ( III11II111 )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 87 - 87: I1IiiI
    if 56 - 56: OOooOOo % oO0o - OoOoOO00
  return
  if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
  if 81 - 81: oO0o / iIii1I11I1II1
 iI1ii1IIi11i1 = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 15 - 15: Ii1I + I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # II111iiii % Ii1I
 red ( OooOOooo . print_address ( ) , False ) , map_notify . retry_count ) )
 if 10 - 10: iIii1I11I1II1 . I1IiiI - II111iiii + O0
 lisp_send_map_notify ( iI1ii1IIi11i1 , map_notify . packet , OooOOooo , O00oo0o0o0oo )
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
  i1IOoo0 = lisp_rloc_record ( )
  i1IOoo0 . store_rloc_entry ( OOOo )
  i1IOoo0 . local_bit = True
  i1IOoo0 . probe_bit = False
  i1IOoo0 . reach_bit = True
  IiI1I1 += i1IOoo0 . encode ( )
  i1IOoo0 . print_record ( "  " )
  del ( i1IOoo0 )
  if 39 - 39: I11i / O0 - I1ii11iIi11i . Oo0Ooo * OoooooooOO / o0oOOo0O0Ooo
  if 71 - 71: O0 . OoooooooOO + Oo0Ooo . ooOoO0o / Ii1I
  if 92 - 92: I1ii11iIi11i . oO0o
  if 8 - 8: o0oOOo0O0Ooo / oO0o
  if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 for OOOo in parent . registered_rlocs :
  OooOOooo = OOOo . rloc
  ii11i1IiI = lisp_map_notify ( lisp_sockets )
  ii11i1IiI . record_count = 1
  oo0OO0oo = map_register . key_id
  ii11i1IiI . key_id = oo0OO0oo
  ii11i1IiI . alg_id = map_register . alg_id
  ii11i1IiI . auth_len = map_register . auth_len
  ii11i1IiI . nonce = map_register . nonce
  ii11i1IiI . nonce_key = lisp_hex_string ( ii11i1IiI . nonce )
  ii11i1IiI . etr . copy_address ( OooOOooo )
  ii11i1IiI . etr_port = map_register . sport
  ii11i1IiI . site = parent . site
  OO0Oo00OO0oo = ii11i1IiI . encode ( IiI1I1 , parent . site . auth_key [ oo0OO0oo ] )
  ii11i1IiI . print_notify ( )
  if 99 - 99: Ii1I / iII111i / Ii1I + iII111i
  if 18 - 18: OoOoOO00 % OoO0O00 + Ii1I * I1Ii111 / O0 % I1Ii111
  if 6 - 6: II111iiii - i1IIi
  if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
  III11II111 = ii11i1IiI . nonce_key
  if ( III11II111 in lisp_map_notify_queue ) :
   oO00oo0 = lisp_map_notify_queue [ III11II111 ]
   oO00oo0 . retransmit_timer . cancel ( )
   del ( oO00oo0 )
   if 36 - 36: i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
  lisp_map_notify_queue [ III11II111 ] = ii11i1IiI
  if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
  if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
  if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
  if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( OooOOooo . print_address ( ) , False ) ) )
  if 32 - 32: I1Ii111
  lisp_send ( lisp_sockets , OooOOooo , LISP_CTRL_PORT , OO0Oo00OO0oo )
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
 III11II111 = lisp_hex_string ( nonce ) + source . print_address ( )
 if 47 - 47: II111iiii % Oo0Ooo . iIii1I11I1II1 . oO0o
 if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
 if 15 - 15: iII111i
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
 if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( III11II111 in lisp_map_notify_queue ) :
  ii11i1IiI = lisp_map_notify_queue [ III11II111 ]
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
  III11II111 = ii11i1IiI . nonce_key
  lisp_map_notify_queue [ III11II111 ] = ii11i1IiI
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
 OO0Oo00OO0oo = ii11i1IiI . encode ( eid_records , site . auth_key [ key_id ] )
 ii11i1IiI . print_notify ( )
 if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
 if ( map_register_ack == False ) :
  O0oIII = lisp_eid_record ( )
  O0oIII . decode ( eid_records )
  O0oIII . print_record ( "  " , False )
  if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
  if 69 - 69: IiII
  if 13 - 13: i11iIiiIii
  if 49 - 49: OoOoOO00
  if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
 lisp_send_map_notify ( lisp_sockets , OO0Oo00OO0oo , ii11i1IiI . etr , port )
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
 OO0Oo00OO0oo = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 9 - 9: I1ii11iIi11i + I11i
 if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
 if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
 if 4 - 4: OoOoOO00 / OoO0O00
 OooOOooo = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( OooOOooo . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , OooOOooo , LISP_CTRL_PORT , OO0Oo00OO0oo )
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
 III11II111 = ii11i1IiI . nonce_key
 if 4 - 4: I11i
 if 8 - 8: IiII
 if 1 - 1: ooOoO0o . IiII
 if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
 if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
 if 66 - 66: i1IIi . I1ii11iIi11i
 lisp_remove_eid_from_map_notify_queue ( ii11i1IiI . eid_list )
 if ( III11II111 in lisp_map_notify_queue ) :
  ii11i1IiI = lisp_map_notify_queue [ III11II111 ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( ii11i1IiI . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 86 - 86: Oo0Ooo
  return
  if 48 - 48: OoO0O00
  if 55 - 55: OoO0O00 * i1IIi * I11i / iII111i
  if 42 - 42: IiII
  if 28 - 28: OoOoOO00 + OoOoOO00
  if 53 - 53: II111iiii % i1IIi + ooOoO0o . I1Ii111
 lisp_map_notify_queue [ III11II111 ] = ii11i1IiI
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
 O0oIII = lisp_eid_record ( )
 O0oIII . record_ttl = 1440
 O0oIII . eid . copy_address ( site_eid . eid )
 O0oIII . group . copy_address ( site_eid . group )
 O0oIII . rloc_count = 0
 for II1 in site_eid . registered_rlocs :
  if ( ii111iII1I ^ II1 . is_rtr ( ) ) : continue
  O0oIII . rloc_count += 1
  if 63 - 63: O0 / Ii1I + I1Ii111 % OoO0O00 % OOooOOo * O0
 OO0Oo00OO0oo = O0oIII . encode ( )
 if 35 - 35: OoO0O00 + OoooooooOO % Oo0Ooo / I11i - O0 . i1IIi
 if 76 - 76: IiII % I1IiiI * Ii1I / Ii1I / OoooooooOO + Ii1I
 if 19 - 19: OoooooooOO
 if 88 - 88: I1IiiI % ooOoO0o % Oo0Ooo - O0
 ii11i1IiI . print_notify ( )
 O0oIII . print_record ( "  " , False )
 if 71 - 71: OOooOOo % Ii1I - i11iIiiIii - oO0o . ooOoO0o / I1Ii111
 if 53 - 53: iII111i . Oo0Ooo
 if 91 - 91: oO0o * OoooooooOO * oO0o % oO0o * II111iiii % I1Ii111
 if 8 - 8: Ii1I
 for II1 in site_eid . registered_rlocs :
  if ( ii111iII1I ^ II1 . is_rtr ( ) ) : continue
  i1IOoo0 = lisp_rloc_record ( )
  i1IOoo0 . store_rloc_entry ( II1 )
  i1IOoo0 . local_bit = True
  i1IOoo0 . probe_bit = False
  i1IOoo0 . reach_bit = True
  OO0Oo00OO0oo += i1IOoo0 . encode ( )
  i1IOoo0 . print_record ( "    " )
  if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
  if 94 - 94: oO0o
  if 95 - 95: ooOoO0o * O0 + OOooOOo
  if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
  if 21 - 21: ooOoO0o
 OO0Oo00OO0oo = ii11i1IiI . encode ( OO0Oo00OO0oo , "" )
 if ( OO0Oo00OO0oo == None ) : return
 if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
 if 81 - 81: oO0o
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
 if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
 lisp_send_map_notify ( lisp_sockets , OO0Oo00OO0oo , xtr , LISP_CTRL_PORT )
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
 for I1iiIiI1II1ii in rle_list :
  iIiiIi1I = lisp_site_eid_lookup ( I1iiIiI1II1ii [ 0 ] , I1iiIiI1II1ii [ 1 ] , True )
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
    for II1 in Ii1iIi1I1I1I . registered_rlocs :
     if ( II1 . is_rtr ( ) == False ) : continue
     o0OooO0oO [ II1 . rloc . print_address ( ) ] = II1
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
   Iiii1IoO0o = [ ]
   if ( len ( oo0000000oOoo ) != 0 and oo0000000oOoo [ 0 ] . rle != None ) :
    Iiii1IoO0o = oo0000000oOoo [ 0 ] . rle . rle_nodes
    if 90 - 90: Oo0Ooo % I1Ii111 + iII111i * I1IiiI * OoOoOO00
   for IIIi11i1 in Iiii1IoO0o :
    oo0oooo . append ( IIIi11i1 . address )
    ii11iI11I . append ( IIIi11i1 . address . print_address_no_iid ( ) )
    if 39 - 39: o0oOOo0O0Ooo * ooOoO0o / i1IIi
   lprint ( "Notify existing RLE-nodes {}" . format ( ii11iI11I ) )
  else :
   if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
   if 45 - 45: Ii1I * IiII - OOooOOo
   if 57 - 57: iII111i % OoO0O00 / OoooooooOO
   if 69 - 69: oO0o
   if 44 - 44: IiII - II111iiii % Ii1I
   for II1 in oo0000000oOoo :
    if ( II1 . is_rtr ( ) ) : oo0oooo . append ( II1 . rloc )
    if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
    if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
    if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
    if 59 - 59: OoOoOO00
    if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
   O00O0 = ( len ( oo0oooo ) != 0 )
   if ( O00O0 == False ) :
    iI1IiiIiIIIi1 = lisp_site_eid_lookup ( I1iiIiI1II1ii [ 0 ] , oo0OOooO0oO , False )
    if ( iI1IiiIiIIIi1 == None ) : continue
    if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
    for II1 in iI1IiiIiIIIi1 . registered_rlocs :
     if ( II1 . rloc . is_null ( ) ) : continue
     oo0oooo . append ( II1 . rloc )
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
 for OoOOoO0oOo in range ( rloc_count ) :
  i1IOoo0 = lisp_rloc_record ( )
  packet = i1IOoo0 . decode ( packet , None )
  iii = i1IOoo0 . json
  if ( iii == None ) : continue
  if 41 - 41: I1ii11iIi11i
  try :
   iii = json . loads ( iii . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 90 - 90: IiII * I1Ii111 * I1Ii111 * I1IiiI . OoOoOO00 * iII111i
   if 46 - 46: OoOoOO00
  if ( "signature" not in iii ) : continue
  return ( i1IOoo0 )
  if 1 - 1: oO0o + ooOoO0o / iII111i
 return ( None )
 if 11 - 11: IiII / OoO0O00 * I1ii11iIi11i
 if 20 - 20: I1IiiI * OoO0O00 / Oo0Ooo
 if 59 - 59: I11i % i1IIi % Oo0Ooo % Oo0Ooo
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
  i1oO00O = II1i1i . instance_id
  if ( i1oO00O == - 1 ) : II1i1i . instance_id = eid . instance_id
  if 33 - 33: oO0o . oO0o / IiII + II111iiii
  IIiiIiI = eid . is_more_specific ( II1i1i )
  II1i1i . instance_id = i1oO00O
  if ( IIiiIiI ) :
   O0OOo0oo = 128 - II1i1i . mask_len
   break
   if 5 - 5: Oo0Ooo / OoooooooOO / Ii1I * I1Ii111
   if 37 - 37: Ii1I * o0oOOo0O0Ooo
 if ( O0OOo0oo == None ) : return ( None )
 if 39 - 39: OoooooooOO
 Ii1IiIIIi = eid . address
 iI1ii1Ii = ""
 for OoOOoO0oOo in range ( 0 , old_div ( O0OOo0oo , 16 ) ) :
  oOOOo0o = Ii1IiIIIi & 0xffff
  oOOOo0o = hex ( oOOOo0o ) [ 2 : - 1 ]
  iI1ii1Ii = oOOOo0o . zfill ( 4 ) + ":" + iI1ii1Ii
  Ii1IiIIIi >>= 16
  if 10 - 10: i1IIi + OOooOOo - OoooooooOO . iII111i - i1IIi
 if ( O0OOo0oo % 16 != 0 ) :
  oOOOo0o = Ii1IiIIIi & 0xff
  oOOOo0o = hex ( oOOOo0o ) [ 2 : - 1 ]
  iI1ii1Ii = oOOOo0o . zfill ( 2 ) + ":" + iI1ii1Ii
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
 i1oO00O = eid . instance_id
 if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
 if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
 if 27 - 27: O0 - iIii1I11I1II1
 if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
 if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
 OoOOo0 = lisp_get_eid_hash ( eid )
 if ( OoOOo0 == None ) : return ( [ None , None , False ] )
 if 61 - 61: IiII * I1Ii111 * OoO0O00 / oO0o - OoooooooOO
 OoOOo0 = "hash-" + OoOOo0
 Oo00oOoo = lisp_address ( LISP_AFI_NAME , OoOOo0 , len ( OoOOo0 ) , i1oO00O )
 o0o0o = lisp_address ( LISP_AFI_NONE , "" , 0 , i1oO00O )
 if 5 - 5: o0oOOo0O0Ooo % OOooOOo % II111iiii
 if 86 - 86: O0 . ooOoO0o * OoooooooOO + Ii1I / I11i / II111iiii
 if 26 - 26: OoooooooOO - I1Ii111 / Oo0Ooo - iII111i % OoOoOO00 * OoooooooOO
 if 3 - 3: oO0o
 iI1IiiIiIIIi1 = lisp_site_eid_lookup ( Oo00oOoo , o0o0o , True )
 if ( iI1IiiIiIIIi1 == None ) : return ( [ Oo00oOoo , None , False ] )
 if 3 - 3: I1ii11iIi11i . IiII + ooOoO0o
 if 66 - 66: OOooOOo + oO0o - ooOoO0o / Ii1I * OoO0O00 * i11iIiiIii
 if 69 - 69: I11i % i11iIiiIii
 if 34 - 34: Ii1I . OoooooooOO + II111iiii % oO0o
 ooOo0OO = None
 for OooOOoOO0OO in iI1IiiIiIIIi1 . registered_rlocs :
  Oo0OOo0Oo0 = OooOOoOO0OO . json
  if ( Oo0OOo0Oo0 == None ) : continue
  try :
   Oo0OOo0Oo0 = json . loads ( Oo0OOo0Oo0 . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( OoOOo0 ) )
   if 79 - 79: I1Ii111
   return ( [ Oo00oOoo , None , False ] )
   if 81 - 81: OoooooooOO + OoOoOO00 / II111iiii
  if ( "public-key" not in Oo0OOo0Oo0 ) : continue
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
 oo0 = json . loads ( rloc_record . json . json_string )
 if 58 - 58: oO0o / ooOoO0o
 if ( lisp_get_eid_hash ( eid ) ) :
  Ii1IiI = eid
 elif ( "signature-eid" in oo0 ) :
  iII1II11II = oo0 [ "signature-eid" ]
  Ii1IiI = lisp_address ( LISP_AFI_IPV6 , iII1II11II , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 46 - 46: o0oOOo0O0Ooo % O0
  if 30 - 30: oO0o
  if 64 - 64: O0
  if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
  if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
 Oo00oOoo , ooOo0OO , IIi1II1i111i1i = lisp_lookup_public_key ( Ii1IiI )
 if ( Oo00oOoo == None ) :
  iIiI1I1ii1I1 = green ( Ii1IiI . print_address ( ) , False )
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
 OoO0OOOo0O0O0 = oo0 [ "signature" ]
 if 30 - 30: i11iIiiIii - I11i * ooOoO0o + iII111i % I1Ii111
 try :
  oo0 = binascii . a2b_base64 ( OoO0OOOo0O0O0 )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 1 - 1: iIii1I11I1II1 % i11iIiiIii - i11iIiiIii % II111iiii
  if 89 - 89: iII111i . OoO0O00 . iII111i
 iI1iIIII1 = len ( oo0 )
 if ( iI1iIIII1 & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( iI1iIIII1 ) )
  return ( False )
  if 75 - 75: OoooooooOO . II111iiii / Oo0Ooo . I1ii11iIi11i % IiII
  if 83 - 83: iII111i + i1IIi % I1IiiI % OOooOOo . iII111i % ooOoO0o
  if 15 - 15: iII111i
  if 55 - 55: iII111i
  if 22 - 22: I1Ii111 % II111iiii % iIii1I11I1II1 % II111iiii
 o000OOooo000O = Ii1IiI . print_address ( )
 if 33 - 33: II111iiii
 if 60 - 60: iIii1I11I1II1 / OOooOOo
 if 78 - 78: i11iIiiIii
 if 20 - 20: OoooooooOO * OoooooooOO - OOooOOo
 ooOo0OO = binascii . a2b_base64 ( ooOo0OO )
 try :
  III11II111 = ecdsa . VerifyingKey . from_pem ( ooOo0OO )
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
  OOoO0OOO00 = III11II111 . verify ( oo0 , o000OOooo000O , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( o000OOooo000O ) )
  if 71 - 71: I1IiiI % I1Ii111 / oO0o % oO0o / iIii1I11I1II1 + I1Ii111
  lprint ( "  Signature used '{}'" . format ( OoO0OOOo0O0O0 ) )
  return ( False )
  if 86 - 86: IiII % i1IIi * o0oOOo0O0Ooo - I1Ii111
 return ( OOoO0OOO00 )
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
 i111ii1II11ii = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 oo0O00O0O0O00Ooo = ( i111ii1II11ii >> 13 ) & 0x1
 if ( oo0O00O0O0O00Ooo == 0 ) : return ( packet )
 if 97 - 97: i1IIi . I1ii11iIi11i . OOooOOo - ooOoO0o
 iiIi1iIIII1 = ( i111ii1II11ii >> 14 ) & 0x7
 if 65 - 65: I11i . o0oOOo0O0Ooo + i11iIiiIii
 if 4 - 4: oO0o . i11iIiiIii - OoooooooOO - I11i . Ii1I
 if 83 - 83: Oo0Ooo * II111iiii + Ii1I
 if 59 - 59: iII111i % OoO0O00 / Oo0Ooo + I1ii11iIi11i % Ii1I
 try :
  OooOo0o = lisp_ms_encryption_keys [ iiIi1iIIII1 ]
  OooOo0o = OooOo0o . zfill ( 32 )
  iI1ii = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( iiIi1iIIII1 ) )
  return ( None )
  if 88 - 88: II111iiii + i11iIiiIii
  if 14 - 14: II111iiii + OOooOOo * Ii1I * I1IiiI + OOooOOo . OOooOOo
 iiIi = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( iiIi , iiIi1iIIII1 ) )
 if 5 - 5: oO0o + OoooooooOO
 if 88 - 88: oO0o + OOooOOo
 if 14 - 14: I11i / i1IIi
 if 56 - 56: OoooooooOO
 II11 = chacha . ChaCha ( OooOo0o , iI1ii , 20 ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + II11 )
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
 OOooo , packet = iiIio0o0 . decode ( packet )
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
 iIiI1IIi1Ii1i = iiIio0o0 . record_count
 for OoOOoO0oOo in range ( iIiI1IIi1Ii1i ) :
  O0oIII = lisp_eid_record ( )
  i1IOoo0 = lisp_rloc_record ( )
  packet = O0oIII . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 26 - 26: Oo0Ooo
  O0oIII . print_record ( "  " , False )
  if 3 - 3: I11i . OoO0O00 . i1IIi - I1IiiI * oO0o
  if 93 - 93: i1IIi + I1ii11iIi11i % Oo0Ooo + iIii1I11I1II1 / II111iiii
  if 100 - 100: iIii1I11I1II1 / II111iiii / Ii1I * Ii1I - OoO0O00
  if 36 - 36: ooOoO0o % i1IIi / OoOoOO00 % OoOoOO00 + Ii1I
  iI1IiiIiIIIi1 = lisp_site_eid_lookup ( O0oIII . eid , O0oIII . group ,
 False )
  if 35 - 35: Ii1I . ooOoO0o - ooOoO0o % OoO0O00 / oO0o
  i1iiI = iI1IiiIiIIIi1 . print_eid_tuple ( ) if iI1IiiIiIIIi1 else None
  if 44 - 44: OoOoOO00 * Oo0Ooo
  if 51 - 51: OOooOOo / IiII % I1Ii111 . OoOoOO00 % Ii1I
  if 88 - 88: OoO0O00
  if 28 - 28: I1Ii111 - iIii1I11I1II1
  if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
  if 65 - 65: iII111i . oO0o
  if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
  if ( iI1IiiIiIIIi1 and iI1IiiIiIIIi1 . accept_more_specifics == False ) :
   if ( iI1IiiIiIIIi1 . eid_record_matches ( O0oIII ) == False ) :
    i11I1Ii1 = iI1IiiIiIIIi1 . parent_for_more_specifics
    if ( i11I1Ii1 ) : iI1IiiIiIIIi1 = i11I1Ii1
    if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
    if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
    if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
    if 43 - 43: Oo0Ooo % I11i
    if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
    if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
    if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
    if 100 - 100: ooOoO0o . OoooooooOO % i1IIi % OoO0O00
  iI111Ii111I1i = ( iI1IiiIiIIIi1 and iI1IiiIiIIIi1 . accept_more_specifics )
  if ( iI111Ii111I1i ) :
   IIiII1I1ii11i = lisp_site_eid ( iI1IiiIiIIIi1 . site )
   IIiII1I1ii11i . dynamic = True
   IIiII1I1ii11i . eid . copy_address ( O0oIII . eid )
   IIiII1I1ii11i . group . copy_address ( O0oIII . group )
   IIiII1I1ii11i . parent_for_more_specifics = iI1IiiIiIIIi1
   IIiII1I1ii11i . add_cache ( )
   IIiII1I1ii11i . inherit_from_ams_parent ( )
   iI1IiiIiIIIi1 . more_specific_registrations . append ( IIiII1I1ii11i )
   iI1IiiIiIIIi1 = IIiII1I1ii11i
  else :
   iI1IiiIiIIIi1 = lisp_site_eid_lookup ( O0oIII . eid , O0oIII . group ,
 True )
   if 25 - 25: II111iiii + I1IiiI
   if 99 - 99: i1IIi * I11i % OoooooooOO % i11iIiiIii % I1Ii111 . OOooOOo
  iIiI1I1ii1I1 = O0oIII . print_eid_tuple ( )
  if 46 - 46: II111iiii - oO0o - Ii1I * OoOoOO00 % i1IIi
  if ( iI1IiiIiIIIi1 == None ) :
   ii1I1ii1i1i = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( ii1I1ii1i1i , green ( iIiI1I1ii1I1 , False ) ,
 ", matched non-ams {}" . format ( green ( i1iiI , False ) if i1iiI else "" ) ) )
   if 71 - 71: o0oOOo0O0Ooo + Oo0Ooo % OoooooooOO
   if 5 - 5: i1IIi % Oo0Ooo / OoooooooOO * OoOoOO00 + OOooOOo - ooOoO0o
   if 24 - 24: oO0o / ooOoO0o % I1IiiI / I1ii11iIi11i
   if 88 - 88: OoO0O00
   if 96 - 96: IiII % I1ii11iIi11i % Oo0Ooo - i11iIiiIii % iIii1I11I1II1
   packet = i1IOoo0 . end_of_rlocs ( packet , O0oIII . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 100 - 100: IiII - Ii1I
   continue
   if 9 - 9: II111iiii / Ii1I / O0 - OoOoOO00 - IiII
   if 6 - 6: OoOoOO00 / O0 * i1IIi * OoooooooOO
  i1iIiII1II11i = iI1IiiIiIIIi1 . site
  if 60 - 60: iII111i - iII111i - Oo0Ooo . i11iIiiIii
  if ( iI111Ii111I1i ) :
   I1i = iI1IiiIiIIIi1 . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( I1i , False ) , i1iIiII1II11i . site_name , green ( iIiI1I1ii1I1 , False ) ) )
   if 67 - 67: oO0o * OoOoOO00 * OoO0O00 + O0 * oO0o
  else :
   I1i = green ( iI1IiiIiIIIi1 . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( I1i , i1iIiII1II11i . site_name , green ( iIiI1I1ii1I1 , False ) ) )
   if 39 - 39: i1IIi
   if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
   if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
   if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
   if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
   if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
  if ( i1iIiII1II11i . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( i1iIiII1II11i . site_name ) )
   packet = i1IOoo0 . end_of_rlocs ( packet , O0oIII . rloc_count )
   continue
   if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
   if 22 - 22: ooOoO0o - OOooOOo
   if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
   if 20 - 20: ooOoO0o - i11iIiiIii
   if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
   if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
   if 33 - 33: OoO0O00 . OoooooooOO % iII111i / oO0o * Ii1I + ooOoO0o
   if 29 - 29: oO0o
  oo0OO0oo = iiIio0o0 . key_id
  if ( oo0OO0oo in i1iIiII1II11i . auth_key ) :
   iiIo0O0O0 = i1iIiII1II11i . auth_key [ oo0OO0oo ]
  else :
   iiIo0O0O0 = ""
   if 37 - 37: o0oOOo0O0Ooo
   if 84 - 84: Oo0Ooo * i11iIiiIii * OoooooooOO % I1ii11iIi11i / i11iIiiIii
  O0o0OOO0 = lisp_verify_auth ( OOooo , iiIio0o0 . alg_id ,
 iiIio0o0 . auth_data , iiIo0O0O0 )
  OooOooo0 = "dynamic " if iI1IiiIiIIIi1 . dynamic else ""
  if 80 - 80: I1IiiI - OOooOOo + OoOoOO00
  I111 = bold ( "passed" if O0o0OOO0 else "failed" , False )
  oo0OO0oo = "key-id {}" . format ( oo0OO0oo ) if oo0OO0oo == iiIio0o0 . key_id else "bad key-id {}" . format ( iiIio0o0 . key_id )
  if 53 - 53: OoooooooOO . I11i * OOooOOo + i11iIiiIii * O0 . iIii1I11I1II1
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( I111 , OooOooo0 , green ( iIiI1I1ii1I1 , False ) , oo0OO0oo ) )
  if 72 - 72: IiII . ooOoO0o . Oo0Ooo - iIii1I11I1II1 % IiII
  if 97 - 97: OoooooooOO
  if 26 - 26: I11i . I1IiiI / IiII / Oo0Ooo % Oo0Ooo / O0
  if 27 - 27: I11i - I11i % OoO0O00 - iII111i . OOooOOo - iIii1I11I1II1
  if 15 - 15: OoO0O00 + iIii1I11I1II1
  if 89 - 89: OoooooooOO * Ii1I
  i11Iii = True
  ooo0Ooo0o0 = ( lisp_get_eid_hash ( O0oIII . eid ) != None )
  if ( ooo0Ooo0o0 or iI1IiiIiIIIi1 . require_signature ) :
   iII1I1iII1i = "Required " if iI1IiiIiIIIi1 . require_signature else ""
   iIiI1I1ii1I1 = green ( iIiI1I1ii1I1 , False )
   OooOOoOO0OO = lisp_find_sig_in_rloc_set ( packet , O0oIII . rloc_count )
   if ( OooOOoOO0OO == None ) :
    i11Iii = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( iII1I1iII1i ,
    # i1IIi . IiII / o0oOOo0O0Ooo / I11i
 bold ( "failed" , False ) , iIiI1I1ii1I1 ) )
   else :
    i11Iii = lisp_verify_cga_sig ( O0oIII . eid , OooOOoOO0OO )
    I111 = bold ( "passed" if i11Iii else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( iII1I1iII1i , I111 , iIiI1I1ii1I1 ) )
    if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
    if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
    if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
    if 29 - 29: iII111i * O0 + I1IiiI * IiII + iII111i - IiII
  if ( O0o0OOO0 == False or i11Iii == False ) :
   packet = i1IOoo0 . end_of_rlocs ( packet , O0oIII . rloc_count )
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
   i11I1Ii1 = iI1IiiIiIIIi1
   i11I1Ii1 . inconsistent_registration = False
   if 87 - 87: Oo0Ooo
   if 7 - 7: iIii1I11I1II1
   if 85 - 85: iIii1I11I1II1 . O0
   if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
   if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
   if ( iI1IiiIiIIIi1 . group . is_null ( ) ) :
    if ( i11I1Ii1 . site_id != iiIio0o0 . site_id ) :
     i11I1Ii1 . site_id = iiIio0o0 . site_id
     i11I1Ii1 . registered = False
     i11I1Ii1 . individual_registrations = { }
     i11I1Ii1 . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
     if 8 - 8: OoO0O00 . OoO0O00
     if 29 - 29: I11i + OoooooooOO % o0oOOo0O0Ooo - I1Ii111
   III11II111 = iiIio0o0 . xtr_id
   if ( III11II111 in iI1IiiIiIIIi1 . individual_registrations ) :
    iI1IiiIiIIIi1 = iI1IiiIiIIIi1 . individual_registrations [ III11II111 ]
   else :
    iI1IiiIiIIIi1 = lisp_site_eid ( i1iIiII1II11i )
    iI1IiiIiIIIi1 . eid . copy_address ( i11I1Ii1 . eid )
    iI1IiiIiIIIi1 . group . copy_address ( i11I1Ii1 . group )
    iI1IiiIiIIIi1 . encrypt_json = i11I1Ii1 . encrypt_json
    i11I1Ii1 . individual_registrations [ III11II111 ] = iI1IiiIiIIIi1
    if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
  else :
   iI1IiiIiIIIi1 . inconsistent_registration = iI1IiiIiIIIi1 . merge_register_requested
   if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
   if 24 - 24: IiII
   if 95 - 95: IiII + OoOoOO00 * OOooOOo
  iI1IiiIiIIIi1 . map_registers_received += 1
  if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
  if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
  if 41 - 41: i1IIi / IiII
  if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
  if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
  II1iiiiIIIII = ( iI1IiiIiIIIi1 . is_rloc_in_rloc_set ( source ) == False )
  if ( O0oIII . record_ttl == 0 and II1iiiiIIIII ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
   continue
   if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
   if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
   if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
   if 90 - 90: oO0o / o0oOOo0O0Ooo . o0oOOo0O0Ooo % OoOoOO00 / IiII
   if 13 - 13: oO0o + IiII
   if 36 - 36: oO0o - OoOoOO00 . O0 % IiII
  OO0ooOo0o = iI1IiiIiIIIi1 . registered_rlocs
  iI1IiiIiIIIi1 . registered_rlocs = [ ]
  if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
  if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
  if 41 - 41: OoooooooOO + iII111i . OOooOOo
  OOOoooO = packet
  for Oooo0 in range ( O0oIII . rloc_count ) :
   i1IOoo0 = lisp_rloc_record ( )
   packet = i1IOoo0 . decode ( packet , None , iI1IiiIiIIIi1 . encrypt_json )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
   i1IOoo0 . print_record ( "    " )
   if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
   if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
   if 57 - 57: II111iiii % OoO0O00 * i1IIi
   if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
   if ( len ( i1iIiII1II11i . allowed_rlocs ) > 0 ) :
    Oo0o = i1IOoo0 . rloc . print_address ( )
    if ( Oo0o not in i1iIiII1II11i . allowed_rlocs ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( Oo0o , False ) ) )
     if 9 - 9: II111iiii % OoooooooOO
     if 4 - 4: i1IIi * i11iIiiIii % OoooooooOO + OoOoOO00 . oO0o
     iI1IiiIiIIIi1 . registered = False
     packet = i1IOoo0 . end_of_rlocs ( packet ,
 O0oIII . rloc_count - Oooo0 - 1 )
     break
     if 95 - 95: I1ii11iIi11i * OoOoOO00 % o0oOOo0O0Ooo / O0 + ooOoO0o % OOooOOo
     if 48 - 48: i1IIi + IiII - iIii1I11I1II1 . i11iIiiIii % OOooOOo + I1ii11iIi11i
     if 95 - 95: ooOoO0o + OoOoOO00 . II111iiii + Ii1I
     if 81 - 81: OoooooooOO / OOooOOo / Oo0Ooo
     if 26 - 26: iII111i
     if 93 - 93: Oo0Ooo + I1IiiI % OoOoOO00 / OOooOOo / I1ii11iIi11i
   OooOOoOO0OO = lisp_rloc ( )
   OooOOoOO0OO . store_rloc_from_record ( i1IOoo0 , None , source )
   if 6 - 6: IiII
   if 68 - 68: Oo0Ooo
   if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
   if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
   if 93 - 93: i11iIiiIii
   if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
   if ( source . is_exact_match ( OooOOoOO0OO . rloc ) ) :
    OooOOoOO0OO . map_notify_requested = iiIio0o0 . map_notify_requested
    if 40 - 40: IiII % IiII
    if 9 - 9: I1IiiI * i1IIi + OOooOOo * OoOoOO00
    if 8 - 8: iII111i
    if 51 - 51: I1IiiI
    if 72 - 72: ooOoO0o / I1ii11iIi11i . Ii1I * iII111i . iIii1I11I1II1
   iI1IiiIiIIIi1 . registered_rlocs . append ( OooOOoOO0OO )
   if 35 - 35: OoO0O00 . OoOoOO00 % O0 * OoO0O00
   if 68 - 68: OOooOOo
  O0O0oOOOoOoo = ( iI1IiiIiIIIi1 . do_rloc_sets_match ( OO0ooOo0o ) == False )
  if 82 - 82: Oo0Ooo - oO0o
  if 36 - 36: Oo0Ooo / Oo0Ooo - o0oOOo0O0Ooo - i11iIiiIii
  if 59 - 59: i11iIiiIii / iIii1I11I1II1 / ooOoO0o
  if 2 - 2: iII111i + II111iiii
  if 88 - 88: i1IIi - iII111i / OOooOOo / i1IIi
  if 48 - 48: iII111i / OoooooooOO / iIii1I11I1II1
  if ( iiIio0o0 . map_register_refresh and O0O0oOOOoOoo and
 iI1IiiIiIIIi1 . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   iI1IiiIiIIIi1 . registered_rlocs = OO0ooOo0o
   continue
   if 41 - 41: II111iiii - II111iiii - OoO0O00 + oO0o * I11i
   if 77 - 77: IiII % iIii1I11I1II1 - OOooOOo / I1Ii111 / ooOoO0o . iII111i
   if 62 - 62: I1Ii111
   if 42 - 42: o0oOOo0O0Ooo
   if 59 - 59: I1ii11iIi11i % O0 - i1IIi . Oo0Ooo
   if 18 - 18: II111iiii
  if ( iI1IiiIiIIIi1 . registered == False ) :
   iI1IiiIiIIIi1 . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 31 - 31: Oo0Ooo / Oo0Ooo / iIii1I11I1II1 / I11i % OoooooooOO
  iI1IiiIiIIIi1 . last_registered = lisp_get_timestamp ( )
  iI1IiiIiIIIi1 . registered = ( O0oIII . record_ttl != 0 )
  iI1IiiIiIIIi1 . last_registerer = source
  if 90 - 90: I1IiiI
  if 35 - 35: O0
  if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
  if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
  iI1IiiIiIIIi1 . auth_sha1_or_sha2 = i1IiIIi11I
  iI1IiiIiIIIi1 . proxy_reply_requested = iiIio0o0 . proxy_reply_requested
  iI1IiiIiIIIi1 . lisp_sec_present = iiIio0o0 . lisp_sec_present
  iI1IiiIiIIIi1 . map_notify_requested = iiIio0o0 . map_notify_requested
  iI1IiiIiIIIi1 . mobile_node_requested = iiIio0o0 . mobile_node
  iI1IiiIiIIIi1 . merge_register_requested = iiIio0o0 . merge_register_requested
  if 78 - 78: I1IiiI - iIii1I11I1II1
  iI1IiiIiIIIi1 . use_register_ttl_requested = iiIio0o0 . use_ttl_for_timeout
  if ( iI1IiiIiIIIi1 . use_register_ttl_requested ) :
   iI1IiiIiIIIi1 . register_ttl = O0oIII . store_ttl ( )
  else :
   iI1IiiIiIIIi1 . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 20 - 20: i11iIiiIii % I1IiiI % OoOoOO00
  iI1IiiIiIIIi1 . xtr_id_present = iiIio0o0 . xtr_id_present
  if ( iI1IiiIiIIIi1 . xtr_id_present ) :
   iI1IiiIiIIIi1 . xtr_id = iiIio0o0 . xtr_id
   iI1IiiIiIIIi1 . site_id = iiIio0o0 . site_id
   if 85 - 85: I11i + OoOoOO00 * O0 * O0
   if 92 - 92: i11iIiiIii
   if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
   if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
   if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
  if ( iiIio0o0 . merge_register_requested ) :
   if ( i11I1Ii1 . merge_in_site_eid ( iI1IiiIiIIIi1 ) ) :
    Oooo0o00oOO0o0 . append ( [ O0oIII . eid , O0oIII . group ] )
    if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
   if ( iiIio0o0 . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , i11I1Ii1 , iiIio0o0 ,
 O0oIII )
    if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
    if 42 - 42: OoOoOO00 . I11i % II111iiii
    if 19 - 19: OoooooooOO
  if ( O0O0oOOOoOoo == False ) : continue
  if ( len ( Oooo0o00oOO0o0 ) != 0 ) : continue
  if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
  oOII . append ( iI1IiiIiIIIi1 . print_eid_tuple ( ) )
  if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
  if 56 - 56: I11i
  if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
  if 32 - 32: OOooOOo / i1IIi / OOooOOo
  if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
  if 45 - 45: Oo0Ooo
  if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
  II1i11iI = copy . deepcopy ( O0oIII )
  O0oIII = O0oIII . encode ( )
  O0oIII += OOOoooO
  I1iI1iI1iIIi = [ iI1IiiIiIIIi1 . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 31 - 31: OoO0O00 % ooOoO0o * Ii1I
  for OooOOoOO0OO in OO0ooOo0o :
   if ( OooOOoOO0OO . map_notify_requested == False ) : continue
   if ( OooOOoOO0OO . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , O0oIII , I1iI1iI1iIIi , 1 , OooOOoOO0OO . rloc ,
 LISP_CTRL_PORT , iiIio0o0 . nonce , iiIio0o0 . key_id ,
 iiIio0o0 . alg_id , iiIio0o0 . auth_len , i1iIiII1II11i , False )
   if 67 - 67: I11i . II111iiii + iIii1I11I1II1 - I1IiiI
   if 25 - 25: i1IIi . OoO0O00 - Ii1I
   if 42 - 42: O0 * iII111i . i1IIi / i11iIiiIii + Ii1I
   if 80 - 80: O0 + II111iiii + oO0o . Oo0Ooo * i1IIi
   if 8 - 8: Ii1I
  lisp_notify_subscribers ( lisp_sockets , II1i11iI , OOOoooO ,
 iI1IiiIiIIIi1 . eid , i1iIiII1II11i )
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
 for OoOOoO0oOo in range ( ii11i1IiI . record_count ) :
  O0oIII = lisp_eid_record ( )
  I1i1IIiIIiIiIi = O0oIII . decode ( I1i1IIiIIiIiIi )
  if ( packet == None ) : return
  O0oIII . print_record ( "  " , False )
  iIiI1I1ii1I1 = O0oIII . print_eid_tuple ( )
  if 14 - 14: iII111i / IiII / oO0o
  if 55 - 55: OoO0O00 % O0
  if 92 - 92: OoooooooOO / O0
  if 14 - 14: i11iIiiIii
  if 43 - 43: OOooOOo
  O0oo0OOo00o0o = lisp_map_cache_lookup ( O0oIII . eid , O0oIII . eid )
  if ( O0oo0OOo00o0o == None ) :
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
  if ( O0oo0OOo00o0o . action != LISP_SEND_PUBSUB_ACTION ) :
   if ( O0oo0OOo00o0o . subscribed_eid == None ) :
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
  if ( O0oo0OOo00o0o . action == LISP_SEND_PUBSUB_ACTION ) :
   O0oo0OOo00o0o = lisp_mapping ( O0oIII . eid , O0oIII . group , [ ] )
   O0oo0OOo00o0o . add_cache ( )
   i11o0o0OoOo00O0O = copy . deepcopy ( O0oIII . eid )
   oo0ooOo0oo0Oo = copy . deepcopy ( O0oIII . group )
  else :
   i11o0o0OoOo00O0O = O0oo0OOo00o0o . subscribed_eid
   oo0ooOo0oo0Oo = O0oo0OOo00o0o . subscribed_group
   O0000oo0Oo = O0oo0OOo00o0o . rloc_set
   O0oo0OOo00o0o . delete_rlocs_from_rloc_probe_list ( )
   O0oo0OOo00o0o . rloc_set = [ ]
   if 35 - 35: Oo0Ooo / OoooooooOO * O0 / Ii1I . OoO0O00
   if 93 - 93: I11i / OoooooooOO % Oo0Ooo . OoO0O00
   if 54 - 54: OoooooooOO . OoooooooOO / i1IIi * Oo0Ooo
   if 90 - 90: oO0o / Oo0Ooo + Oo0Ooo
   if 16 - 16: I1Ii111 / I1ii11iIi11i / I11i - I1IiiI
  O0oo0OOo00o0o . mapping_source = None if source == "lisp-itr" else source
  O0oo0OOo00o0o . map_cache_ttl = O0oIII . store_ttl ( )
  O0oo0OOo00o0o . subscribed_eid = i11o0o0OoOo00O0O
  O0oo0OOo00o0o . subscribed_group = oo0ooOo0oo0Oo
  if 30 - 30: I1Ii111 + OoO0O00 % OoOoOO00 / I11i - iII111i
  if 35 - 35: o0oOOo0O0Ooo / I1Ii111 - ooOoO0o
  if 44 - 44: I1IiiI * I11i + I1ii11iIi11i / IiII
  if 95 - 95: OoOoOO00
  if 73 - 73: IiII * Oo0Ooo . I1IiiI - iIii1I11I1II1
  if ( len ( O0000oo0Oo ) != 0 and O0oIII . rloc_count == 0 ) :
   O0oo0OOo00o0o . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , O0oo0OOo00o0o )
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
  iiiiIIiiII1Iii1 = OOOOO0OO00OOO = 0
  for Oooo0 in range ( O0oIII . rloc_count ) :
   i1IOoo0 = lisp_rloc_record ( )
   I1i1IIiIIiIiIi = i1IOoo0 . decode ( I1i1IIiIIiIiIi , None )
   i1IOoo0 . print_record ( "    " )
   if 14 - 14: I1IiiI - i11iIiiIii . O0 % OOooOOo . Ii1I
   if 46 - 46: II111iiii . i1IIi - i11iIiiIii + I11i - I1Ii111
   if 6 - 6: ooOoO0o / Ii1I / iIii1I11I1II1 - IiII - ooOoO0o
   if 7 - 7: OoOoOO00 + i1IIi % ooOoO0o * I11i + i11iIiiIii / II111iiii
   Ii1iI11I1ii1i = False
   for I1I1iIiiiiII11 in O0000oo0Oo :
    if ( I1I1iIiiiiII11 . rloc . is_exact_match ( i1IOoo0 . rloc ) ) :
     Ii1iI11I1ii1i = True
     break
     if 2 - 2: O0 / o0oOOo0O0Ooo - OoO0O00 * II111iiii
     if 4 - 4: I1IiiI + Oo0Ooo . iIii1I11I1II1
   if ( Ii1iI11I1ii1i ) :
    OooOOoOO0OO = copy . deepcopy ( I1I1iIiiiiII11 )
    OOOOO0OO00OOO += 1
   else :
    OooOOoOO0OO = lisp_rloc ( )
    iiiiIIiiII1Iii1 += 1
    if 100 - 100: i11iIiiIii
    if 21 - 21: OoOoOO00 + iII111i . OoO0O00
    if 79 - 79: i11iIiiIii - OoO0O00 * OoO0O00 * i1IIi / iIii1I11I1II1 + iII111i
    if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
    if 62 - 62: iIii1I11I1II1
   OooOOoOO0OO . store_rloc_from_record ( i1IOoo0 , None , O0oo0OOo00o0o . mapping_source )
   O0oo0OOo00o0o . rloc_set . append ( OooOOoOO0OO )
   if 60 - 60: Oo0Ooo % IiII % OoO0O00 - i11iIiiIii
   if 53 - 53: i11iIiiIii + OoooooooOO
  lprint ( "Update {} map-cache entry with {}/{} new/replaced RLOCs" . format ( green ( iIiI1I1ii1I1 , False ) , iiiiIIiiII1Iii1 , OOOOO0OO00OOO ) )
  if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  if 79 - 79: II111iiii / OoooooooOO
  if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
  if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
  if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  O0oo0OOo00o0o . build_best_rloc_set ( )
  lisp_write_ipc_map_cache ( True , O0oo0OOo00o0o )
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
 for OoOOoO0oOo in range ( ii11i1IiI . record_count ) :
  O0oIII = lisp_eid_record ( )
  I1i1IIiIIiIiIi = O0oIII . decode ( I1i1IIiIIiIiIi )
  if ( packet == None ) : return
  O0oIII . print_record ( "  " , False )
  if 31 - 31: II111iiii
  if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
  if 67 - 67: IiII + oO0o * IiII
  if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
  O0oo0OOo00o0o = lisp_map_cache_lookup ( O0oIII . eid , O0oIII . group )
  if ( O0oo0OOo00o0o == None ) :
   o00000o , ooooO00o0 , IIi11I = lisp_allow_gleaning ( O0oIII . eid , O0oIII . group ,
 None )
   if ( o00000o == False ) : continue
   if 16 - 16: I1IiiI . Ii1I
   O0oo0OOo00o0o = lisp_mapping ( O0oIII . eid , O0oIII . group , [ ] )
   O0oo0OOo00o0o . add_cache ( )
   if 80 - 80: OOooOOo * O0 / iIii1I11I1II1 / IiII / OoOoOO00
   if 15 - 15: I1ii11iIi11i * iII111i + i11iIiiIii
   if 68 - 68: i1IIi / oO0o * I1ii11iIi11i - OoOoOO00 + Oo0Ooo / O0
   if 1 - 1: ooOoO0o - Oo0Ooo + I1Ii111
   if 90 - 90: I1Ii111 * O0 . iII111i - Oo0Ooo % iIii1I11I1II1
   if 7 - 7: I1ii11iIi11i % o0oOOo0O0Ooo % O0 % iIii1I11I1II1
   if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
  if ( O0oo0OOo00o0o . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( O0oo0OOo00o0o . print_eid_tuple ( ) , False ) ) )
   if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
   continue
   if 77 - 77: II111iiii - IiII % OOooOOo
   if 22 - 22: OoooooooOO / oO0o
  O0oo0OOo00o0o . mapping_source = None if source == "lisp-etr" else source
  O0oo0OOo00o0o . map_cache_ttl = O0oIII . store_ttl ( )
  if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
  if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
  if 12 - 12: I1Ii111
  if 17 - 17: I1Ii111 % oO0o + O0
  if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
  if ( len ( O0oo0OOo00o0o . rloc_set ) != 0 and O0oIII . rloc_count == 0 ) :
   O0oo0OOo00o0o . rloc_set = [ ]
   O0oo0OOo00o0o . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , O0oo0OOo00o0o )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( O0oo0OOo00o0o . print_eid_tuple ( ) , False ) ) )
   if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
   continue
   if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
   if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
  iIiI1III = O0oo0OOo00o0o . rtrs_in_rloc_set ( )
  if 86 - 86: Ii1I - o0oOOo0O0Ooo % iII111i
  if 37 - 37: Oo0Ooo
  if 87 - 87: I1ii11iIi11i . OoooooooOO . ooOoO0o + iIii1I11I1II1 + O0 % I1ii11iIi11i
  if 53 - 53: IiII
  if 96 - 96: Oo0Ooo . i11iIiiIii / Ii1I . I1ii11iIi11i % I1Ii111
  for Oooo0 in range ( O0oIII . rloc_count ) :
   i1IOoo0 = lisp_rloc_record ( )
   I1i1IIiIIiIiIi = i1IOoo0 . decode ( I1i1IIiIIiIiIi , None )
   i1IOoo0 . print_record ( "    " )
   if ( O0oIII . group . is_null ( ) ) : continue
   if ( i1IOoo0 . rle == None ) : continue
   if 68 - 68: ooOoO0o
   if 58 - 58: iII111i * I1IiiI
   if 82 - 82: Oo0Ooo / OoO0O00 % Oo0Ooo . ooOoO0o * O0
   if 39 - 39: I1Ii111 * IiII
   if 16 - 16: ooOoO0o + OoO0O00 / I11i * OoO0O00 . Oo0Ooo % OoOoOO00
   OO000 = O0oo0OOo00o0o . rloc_set [ 0 ] . stats if len ( O0oo0OOo00o0o . rloc_set ) != 0 else None
   if 30 - 30: Oo0Ooo % II111iiii % Oo0Ooo * o0oOOo0O0Ooo - Oo0Ooo
   if 23 - 23: iII111i
   if 96 - 96: oO0o . Ii1I / OoOoOO00 - O0 * iIii1I11I1II1 + Oo0Ooo
   if 35 - 35: Oo0Ooo - O0 * I11i % II111iiii % i11iIiiIii / I1IiiI
   OooOOoOO0OO = lisp_rloc ( )
   OooOOoOO0OO . store_rloc_from_record ( i1IOoo0 , None , O0oo0OOo00o0o . mapping_source )
   if ( OO000 != None ) : OooOOoOO0OO . stats = copy . deepcopy ( OO000 )
   if 68 - 68: OoOoOO00 * ooOoO0o
   if ( iIiI1III and OooOOoOO0OO . is_rtr ( ) == False ) : continue
   if 7 - 7: i11iIiiIii * i1IIi % I11i - IiII
   O0oo0OOo00o0o . rloc_set = [ OooOOoOO0OO ]
   O0oo0OOo00o0o . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , O0oo0OOo00o0o )
   if 99 - 99: OoO0O00 * oO0o / Ii1I + OoO0O00
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( O0oo0OOo00o0o . print_eid_tuple ( ) , False ) ,
   # OoOoOO00 % I11i . oO0o * oO0o
 OooOOoOO0OO . rle . print_rle ( False , True ) ) )
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
 OO0Oo00OO0oo = ii11i1IiI . decode ( orig_packet )
 if ( OO0Oo00OO0oo == None ) :
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
  IIiiIiI = None
  for III11II111 in lisp_map_servers_list :
   if ( III11II111 . find ( I1iiIi111I ) == - 1 ) : continue
   IIiiIiI = lisp_map_servers_list [ III11II111 ]
   if 75 - 75: ooOoO0o
  if ( IIiiIiI == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( I1iiIi111I ) )
   if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
   return
   if 85 - 85: ooOoO0o
   if 29 - 29: iII111i . Ii1I
  IIiiIiI . map_notifies_received += 1
  if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
  O0o0OOO0 = lisp_verify_auth ( OO0Oo00OO0oo , ii11i1IiI . alg_id ,
 ii11i1IiI . auth_data , IIiiIiI . password )
  if 45 - 45: IiII
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if O0o0OOO0 else "failed" ) )
  if 49 - 49: I1IiiI . Ii1I * I1IiiI - OoooooooOO . I11i / I1Ii111
  if ( O0o0OOO0 == False ) : return
 else :
  IIiiIiI = lisp_ms ( I1iiIi111I , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
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
 O0oIII = lisp_eid_record ( )
 OO0Oo00OO0oo = O0oIII . decode ( I1i1IIiIIiIiIi )
 if ( OO0Oo00OO0oo == None ) : return
 if 97 - 97: oO0o % iIii1I11I1II1
 O0oIII . print_record ( "  " , False )
 if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
 for Oooo0 in range ( O0oIII . rloc_count ) :
  i1IOoo0 = lisp_rloc_record ( )
  OO0Oo00OO0oo = i1IOoo0 . decode ( OO0Oo00OO0oo , None )
  if ( OO0Oo00OO0oo == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 16 - 16: I1IiiI
  i1IOoo0 . print_record ( "    " )
  if 39 - 39: ooOoO0o * II111iiii
  if 90 - 90: OoooooooOO * ooOoO0o
  if 14 - 14: I1IiiI % i1IIi
  if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
  if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
 if ( O0oIII . group . is_null ( ) == False ) :
  if 55 - 55: i1IIi
  if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
  if 88 - 88: O0
  if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
  if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( O0oIII . print_eid_tuple ( ) , False ) ) )
  if 90 - 90: i11iIiiIii - iII111i * oO0o
  if 79 - 79: IiII
  ii1I11Iii = lisp_control_packet_ipc ( orig_packet , I1iiIi111I , "lisp-itr" , 0 )
  lisp_ipc ( ii1I11Iii , lisp_sockets [ 2 ] , "lisp-core-pkt" )
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
 O0oIII = lisp_eid_record ( )
 if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
 if ( O0oIII . decode ( ii11i1IiI . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 94 - 94: IiII * i1IIi
 O0oIII . print_record ( "  " , False )
 if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 iIiI1I1ii1I1 = O0oIII . print_eid_tuple ( )
 if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
 if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
 if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
 if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
 if ( ii11i1IiI . alg_id != LISP_NONE_ALG_ID and ii11i1IiI . auth_len != 0 ) :
  iI1IiiIiIIIi1 = lisp_sites_by_eid . lookup_cache ( O0oIII . eid , True )
  if ( iI1IiiIiIIIi1 == None ) :
   ii1I1ii1i1i = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( ii1I1ii1i1i , green ( iIiI1I1ii1I1 , False ) ) )
   if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
   return
   if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
  i1iIiII1II11i = iI1IiiIiIIIi1 . site
  if 66 - 66: i1IIi
  if 98 - 98: Oo0Ooo / iIii1I11I1II1
  if 33 - 33: O0 - iII111i
  if 40 - 40: iII111i * I11i
  i1iIiII1II11i . map_notify_acks_received += 1
  if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  oo0OO0oo = ii11i1IiI . key_id
  if ( oo0OO0oo in i1iIiII1II11i . auth_key ) :
   iiIo0O0O0 = i1iIiII1II11i . auth_key [ oo0OO0oo ]
  else :
   iiIo0O0O0 = ""
   if 87 - 87: OoOoOO00
   if 30 - 30: IiII % OoOoOO00 + I1Ii111
  O0o0OOO0 = lisp_verify_auth ( packet , ii11i1IiI . alg_id ,
 ii11i1IiI . auth_data , iiIo0O0O0 )
  if 13 - 13: iII111i * Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
  oo0OO0oo = "key-id {}" . format ( oo0OO0oo ) if oo0OO0oo == ii11i1IiI . key_id else "bad key-id {}" . format ( ii11i1IiI . key_id )
  if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
  if 87 - 87: I11i
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if O0o0OOO0 else "failed" , oo0OO0oo ) )
  if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
  if ( O0o0OOO0 == False ) : return
  if 72 - 72: OoO0O00 * Oo0Ooo - IiII
  if 74 - 74: Ii1I
  if 26 - 26: I11i . O0
  if 68 - 68: Ii1I
  if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
 if ( ii11i1IiI . retransmit_timer ) : ii11i1IiI . retransmit_timer . cancel ( )
 if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
 i1i1 = source . print_address ( )
 III11II111 = ii11i1IiI . nonce_key
 if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
 if ( III11II111 in lisp_map_notify_queue ) :
  ii11i1IiI = lisp_map_notify_queue . pop ( III11II111 )
  if ( ii11i1IiI . retransmit_timer ) : ii11i1IiI . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( III11II111 ) )
  if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( ii11i1IiI . nonce_key , red ( i1i1 , False ) ) )
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
  oOo00OO0ooo = lisp_print_eid_tuple ( eid , group )
  O0o0O0Ooo000 = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 26 - 26: I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( oOo00OO0ooo , False ) , s ,
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
 Ii = lisp_map_referral ( )
 packet = Ii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 100 - 100: II111iiii * Ii1I . OoO0O00 . iII111i + i1IIi * I1IiiI
 Ii . print_map_referral ( )
 if 84 - 84: OoO0O00 + i1IIi
 I1iiIi111I = source . print_address ( )
 OOO0O0O = Ii . nonce
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo * I1Ii111 % OoooooooOO % I11i
 if 48 - 48: o0oOOo0O0Ooo / OoO0O00
 if 45 - 45: OOooOOo
 if 57 - 57: iIii1I11I1II1 + IiII - I1IiiI
 for OoOOoO0oOo in range ( Ii . record_count ) :
  O0oIII = lisp_eid_record ( )
  packet = O0oIII . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 64 - 64: II111iiii . IiII / I1IiiI
  O0oIII . print_record ( "  " , True )
  if 20 - 20: OoooooooOO - I1ii11iIi11i * I1ii11iIi11i * I1ii11iIi11i
  if 87 - 87: OoooooooOO * ooOoO0o
  if 6 - 6: I1Ii111 / ooOoO0o / OoooooooOO . iIii1I11I1II1
  if 68 - 68: OoO0O00
  III11II111 = str ( OOO0O0O )
  if ( III11II111 not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( OOO0O0O ) , I1iiIi111I ) )
   if 26 - 26: I11i % i1IIi / iIii1I11I1II1 % IiII . iII111i + I1ii11iIi11i
   if 49 - 49: O0 . IiII + I1Ii111 - I11i % II111iiii
   continue
   if 15 - 15: O0 - OoOoOO00 % II111iiii + O0 % O0 + OoOoOO00
  OO0O0O0OOO0OO = lisp_ddt_map_requestQ [ III11II111 ]
  if ( OO0O0O0OOO0OO == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( OOO0O0O ) , I1iiIi111I ) )
   if 34 - 34: I1Ii111
   continue
   if 69 - 69: iIii1I11I1II1 . OOooOOo % I11i
   if 28 - 28: I1Ii111 . ooOoO0o % I1IiiI
   if 62 - 62: II111iiii + ooOoO0o + I1IiiI
   if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
   if 13 - 13: I1ii11iIi11i
   if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
  if ( lisp_map_referral_loop ( OO0O0O0OOO0OO , O0oIII . eid , O0oIII . group ,
 O0oIII . action , I1iiIi111I ) ) :
   OO0O0O0OOO0OO . dequeue_map_request ( )
   continue
   if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
   if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
  OO0O0O0OOO0OO . last_cached_prefix [ 0 ] = O0oIII . eid
  OO0O0O0OOO0OO . last_cached_prefix [ 1 ] = O0oIII . group
  if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
  if 18 - 18: OoooooooOO - I1ii11iIi11i
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  if 79 - 79: OOooOOo + Oo0Ooo
  oo0o0OOoO = False
  oo00oO0ooo = lisp_referral_cache_lookup ( O0oIII . eid , O0oIII . group ,
 True )
  if ( oo00oO0ooo == None ) :
   oo0o0OOoO = True
   oo00oO0ooo = lisp_referral ( )
   oo00oO0ooo . eid = O0oIII . eid
   oo00oO0ooo . group = O0oIII . group
   if ( O0oIII . ddt_incomplete == False ) : oo00oO0ooo . add_cache ( )
  elif ( oo00oO0ooo . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( oo00oO0ooo . print_eid_tuple ( ) , False ) ) )
   if 33 - 33: iIii1I11I1II1
   OO0O0O0OOO0OO . dequeue_map_request ( )
   continue
   if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
   if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
  oOoO0OooO0O = O0oIII . action
  oo00oO0ooo . referral_source = source
  oo00oO0ooo . referral_type = oOoO0OooO0O
  O0O00O = O0oIII . store_ttl ( )
  oo00oO0ooo . referral_ttl = O0O00O
  oo00oO0ooo . expires = lisp_set_timestamp ( O0O00O )
  if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
  if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
  if 99 - 99: OOooOOo
  if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
  OOOoO = oo00oO0ooo . is_referral_negative ( )
  if ( I1iiIi111I in oo00oO0ooo . referral_set ) :
   IiIiiiII1I = oo00oO0ooo . referral_set [ I1iiIi111I ]
   if 39 - 39: IiII / oO0o % Ii1I
   if ( IiIiiiII1I . updown == False and OOOoO == False ) :
    IiIiiiII1I . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( I1iiIi111I ) )
    if 62 - 62: I11i - o0oOOo0O0Ooo
   elif ( IiIiiiII1I . updown == True and OOOoO == True ) :
    IiIiiiII1I . updown = False
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
  for III11II111 in oo00oO0ooo . referral_set : o0o0oo [ III11II111 ] = None
  if 39 - 39: i1IIi
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
  if 59 - 59: i1IIi
  if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
  for OoOOoO0oOo in range ( O0oIII . rloc_count ) :
   i1IOoo0 = lisp_rloc_record ( )
   packet = i1IOoo0 . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
   i1IOoo0 . print_record ( "    " )
   if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
   if 71 - 71: OOooOOo
   if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
   if 73 - 73: iII111i / I1IiiI * ooOoO0o
   Oo0o = i1IOoo0 . rloc . print_address ( )
   if ( Oo0o not in oo00oO0ooo . referral_set ) :
    IiIiiiII1I = lisp_referral_node ( )
    IiIiiiII1I . referral_address . copy_address ( i1IOoo0 . rloc )
    oo00oO0ooo . referral_set [ Oo0o ] = IiIiiiII1I
    if ( I1iiIi111I == Oo0o and OOOoO ) : IiIiiiII1I . updown = False
   else :
    IiIiiiII1I = oo00oO0ooo . referral_set [ Oo0o ]
    if ( Oo0o in o0o0oo ) : o0o0oo . pop ( Oo0o )
    if 85 - 85: I11i + I11i + oO0o - OoOoOO00
   IiIiiiII1I . priority = i1IOoo0 . priority
   IiIiiiII1I . weight = i1IOoo0 . weight
   if 15 - 15: OoO0O00
   if 88 - 88: Ii1I % i1IIi / I1Ii111
   if 2 - 2: Ii1I . IiII % OoOoOO00
   if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
   if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
  for III11II111 in o0o0oo : oo00oO0ooo . referral_set . pop ( III11II111 )
  if 35 - 35: i11iIiiIii
  iIiI1I1ii1I1 = oo00oO0ooo . print_eid_tuple ( )
  if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
  if ( oo0o0OOoO ) :
   if ( O0oIII . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( iIiI1I1ii1I1 , False ) ) )
    if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( iIiI1I1ii1I1 , False ) , O0oIII . rloc_count ) )
    if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
    if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( iIiI1I1ii1I1 , False ) , O0oIII . rloc_count ) )
   if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
   if 12 - 12: i11iIiiIii / Ii1I + i1IIi
   if 54 - 54: I1IiiI
   if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
   if 37 - 37: Oo0Ooo
   if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
  if ( oOoO0OooO0O == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( OO0O0O0OOO0OO . lisp_sockets , oo00oO0ooo . eid ,
 oo00oO0ooo . group , OO0O0O0OOO0OO . nonce , OO0O0O0OOO0OO . itr , OO0O0O0OOO0OO . sport , 15 , None , False )
   OO0O0O0OOO0OO . dequeue_map_request ( )
   if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
   if 19 - 19: O0 * II111iiii * OoOoOO00
  if ( oOoO0OooO0O == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( OO0O0O0OOO0OO . tried_root ) :
    lisp_send_negative_map_reply ( OO0O0O0OOO0OO . lisp_sockets , oo00oO0ooo . eid ,
 oo00oO0ooo . group , OO0O0O0OOO0OO . nonce , OO0O0O0OOO0OO . itr , OO0O0O0OOO0OO . sport , 0 , None , False )
    OO0O0O0OOO0OO . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( OO0O0O0OOO0OO , True )
    if 53 - 53: Oo0Ooo
    if 16 - 16: Ii1I
    if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
  if ( oOoO0OooO0O == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( I1iiIi111I in oo00oO0ooo . referral_set ) :
    IiIiiiII1I = oo00oO0ooo . referral_set [ I1iiIi111I ]
    IiIiiiII1I . updown = False
    if 78 - 78: OoO0O00 + oO0o
   if ( len ( oo00oO0ooo . referral_set ) == 0 ) :
    OO0O0O0OOO0OO . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( OO0O0O0OOO0OO , False )
    if 86 - 86: ooOoO0o . ooOoO0o + oO0o
    if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
    if 31 - 31: IiII + iII111i
  if ( oOoO0OooO0O in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( OO0O0O0OOO0OO . eid . is_exact_match ( O0oIII . eid ) ) :
    if ( not OO0O0O0OOO0OO . tried_root ) :
     lisp_send_ddt_map_request ( OO0O0O0OOO0OO , True )
    else :
     lisp_send_negative_map_reply ( OO0O0O0OOO0OO . lisp_sockets ,
 oo00oO0ooo . eid , oo00oO0ooo . group , OO0O0O0OOO0OO . nonce , OO0O0O0OOO0OO . itr ,
 OO0O0O0OOO0OO . sport , 15 , None , False )
     OO0O0O0OOO0OO . dequeue_map_request ( )
     if 5 - 5: O0 * Ii1I
   else :
    lisp_send_ddt_map_request ( OO0O0O0OOO0OO , False )
    if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
    if 77 - 77: OOooOOo / OoooooooOO
    if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
  if ( oOoO0OooO0O == LISP_DDT_ACTION_MS_ACK ) : OO0O0O0OOO0OO . dequeue_map_request ( )
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
 iIiiiII11II = lisp_ecm ( 0 )
 packet = iIiiiII11II . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
  if 86 - 86: Ii1I / oO0o
 iIiiiII11II . print_ecm ( )
 if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
 i111ii1II11ii = lisp_control_header ( )
 if ( i111ii1II11ii . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 60 - 60: II111iiii / Ii1I
  if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
 OoO0OOoo = i111ii1II11ii . type
 del ( i111ii1II11ii )
 if 68 - 68: iII111i + I1Ii111
 if ( OoO0OOoo != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 90 - 90: o0oOOo0O0Ooo
  if 48 - 48: iII111i + Ii1I
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
  if 67 - 67: oO0o
 OoOoo0oOOO = iIiiiII11II . udp_sport
 ooOI1i = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , source , ecm_port ,
 iIiiiII11II . source , OoOoo0oOOO , iIiiiII11II . ddt , - 1 , ooOI1i )
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
 OooOOooo = ms . map_server
 if ( lisp_decent_push_configured and OooOOooo . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  OooOOooo = copy . deepcopy ( OooOOooo )
  OooOOooo . address = 0x7f000001
  ooOo0O0O0oOO0 = bold ( "Bootstrap" , False )
  o0O0Ooo = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( ooOo0O0O0oOO0 , o0O0Ooo ) )
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
  iI1ii = "0" * 8
  oooo0o0oO = chacha . ChaCha ( OooOo0o , iI1ii , 20 ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + oooo0o0oO
  I1i = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( I1i , ms . ekey_id ) )
  if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
  if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
 Iii1IIi11ii1i = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  Iii1IIi11ii1i = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 80 - 80: I1IiiI % Ii1I
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( OooOOooo . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , Iii1IIi11ii1i ) )
 if 38 - 38: IiII . I1Ii111
 lisp_send ( lisp_sockets , OooOOooo , LISP_CTRL_PORT , packet )
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
 OO = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 69 - 69: iII111i % I1ii11iIi11i
 if 19 - 19: IiII
 packet = lisp_control_packet_ipc ( packet , OO , dest , port )
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
  iiI1iiIiiiI1I = lisp_get_any_translated_port ( )
  if ( iiI1iiIiiiI1I != None ) : inner_sport = iiI1iiIiiiI1I
  if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
 iIiiiII11II = lisp_ecm ( inner_sport )
 if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
 iIiiiII11II . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 iIiiiII11II . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 iIiiiII11II . ddt = ddt
 ooO0ooO0OO = iIiiiII11II . encode ( packet , inner_source , inner_dest )
 if ( ooO0ooO0OO == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 26 - 26: iIii1I11I1II1 % oO0o * I1Ii111 / OoooooooOO * I11i * OoooooooOO
 iIiiiII11II . print_ecm ( )
 if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
 packet = ooO0ooO0OO + packet
 if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
 Oo0o = outer_dest . print_address_no_iid ( )
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( Oo0o ) )
 OooOOooo = lisp_convert_4to6 ( Oo0o )
 lisp_send ( lisp_sockets , OooOOooo , LISP_CTRL_PORT , packet )
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
 oOOOo0o = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
 if 77 - 77: Ii1I
 if 9 - 9: OOooOOo / OoooooooOO + iII111i
 if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
 if 20 - 20: I1Ii111
 if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
 if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 return ( oOOOo0o )
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
   O00o00 = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   O00o00 = prefix . mask_len
  else :
   O00o00 = prefix . mask_len + 48
   if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
   if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
  i1oO00O = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  O0ooO0O00oo0 = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    iI = prefix . addr_length ( ) * 2
    oOOOo0o = lisp_hex_string ( prefix . address ) . zfill ( iI )
   else :
    oOOOo0o = prefix . address
    if 24 - 24: Ii1I % II111iiii - i11iIiiIii
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   O0ooO0O00oo0 = "8003"
   oOOOo0o = prefix . address . print_geo ( )
  else :
   O0ooO0O00oo0 = ""
   oOOOo0o = ""
   if 52 - 52: OoO0O00
   if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
  III11II111 = i1oO00O + O0ooO0O00oo0 + oOOOo0o
  return ( [ O00o00 , III11II111 ] )
  if 50 - 50: IiII . i11iIiiIii % I11i
  if 22 - 22: i1IIi - II111iiii - OoOoOO00 . iII111i
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  O00o00 , III11II111 = self . build_key ( prefix )
  if ( O00o00 not in self . cache ) :
   self . cache [ O00o00 ] = lisp_cache_entries ( )
   self . cache_sorted = self . sort_in_entry ( self . cache_sorted , O00o00 )
   if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
  if ( III11II111 not in self . cache [ O00o00 ] . entries ) :
   self . cache_count += 1
   if 34 - 34: iII111i . OoOoOO00
  self . cache [ O00o00 ] . entries [ III11II111 ] = entry
  if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
 def lookup_cache ( self , prefix , exact ) :
  IiI1 , III11II111 = self . build_key ( prefix )
  if ( exact ) :
   if ( IiI1 not in self . cache ) : return ( None )
   if ( III11II111 not in self . cache [ IiI1 ] . entries ) : return ( None )
   return ( self . cache [ IiI1 ] . entries [ III11II111 ] )
   if 8 - 8: OoO0O00 + IiII * I11i + I1ii11iIi11i / I11i
   if 69 - 69: Ii1I * oO0o % II111iiii + oO0o - I1Ii111
  Ii1iI11I1ii1i = None
  for O00o00 in self . cache_sorted :
   if ( IiI1 < O00o00 ) : return ( Ii1iI11I1ii1i )
   for iIiiI11II11i in list ( self . cache [ O00o00 ] . entries . values ( ) ) :
    if ( prefix . is_more_specific ( iIiiI11II11i . eid ) ) :
     if ( Ii1iI11I1ii1i == None or
 iIiiI11II11i . eid . is_more_specific ( Ii1iI11I1ii1i . eid ) ) : Ii1iI11I1ii1i = iIiiI11II11i
     if 55 - 55: oO0o
     if 10 - 10: I1IiiI
     if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
  return ( Ii1iI11I1ii1i )
  if 34 - 34: OoooooooOO / iII111i / O0
  if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
 def delete_cache ( self , prefix ) :
  O00o00 , III11II111 = self . build_key ( prefix )
  if ( O00o00 not in self . cache ) : return
  if ( III11II111 not in self . cache [ O00o00 ] . entries ) : return
  self . cache [ O00o00 ] . entries . pop ( III11II111 )
  self . cache_count -= 1
  if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
  if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
 def walk_cache ( self , function , parms ) :
  for O00o00 in self . cache_sorted :
   for iIiiI11II11i in list ( self . cache [ O00o00 ] . entries . values ( ) ) :
    i1iII1iI , parms = function ( iIiiI11II11i , parms )
    if ( i1iII1iI == False ) : return ( parms )
    if 49 - 49: OOooOOo . i11iIiiIii
    if 31 - 31: OOooOOo / I1Ii111 / OoooooooOO * I11i . ooOoO0o
  return ( parms )
  if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
  if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
 def sort_in_entry ( self , table , value ) :
  if ( table == [ ] ) : return ( [ value ] )
  if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
  Ii1I111Ii = table
  while ( True ) :
   if ( len ( Ii1I111Ii ) == 1 ) :
    if ( value == Ii1I111Ii [ 0 ] ) : return ( table )
    OOOooo0OooOoO = table . index ( Ii1I111Ii [ 0 ] )
    if ( value < Ii1I111Ii [ 0 ] ) :
     return ( table [ 0 : OOOooo0OooOoO ] + [ value ] + table [ OOOooo0OooOoO : : ] )
     if 76 - 76: OoO0O00 * ooOoO0o
    if ( value > Ii1I111Ii [ 0 ] ) :
     return ( table [ 0 : OOOooo0OooOoO + 1 ] + [ value ] + table [ OOOooo0OooOoO + 1 : : ] )
     if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
     if 98 - 98: iII111i . II111iiii % O0
   OOOooo0OooOoO = old_div ( len ( Ii1I111Ii ) , 2 )
   Ii1I111Ii = Ii1I111Ii [ 0 : OOOooo0OooOoO ] if ( value < Ii1I111Ii [ OOOooo0OooOoO ] ) else Ii1I111Ii [ OOOooo0OooOoO : : ]
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
  for O00o00 in self . cache_sorted :
   for III11II111 in self . cache [ O00o00 ] . entries :
    iIiiI11II11i = self . cache [ O00o00 ] . entries [ III11II111 ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( O00o00 , III11II111 ,
 iIiiI11II11i ) )
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
 oOoOo = dest . is_multicast_address ( )
 if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
 if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
 if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
 if 9 - 9: iIii1I11I1II1
 O0oo0OOo00o0o = lisp_map_cache . lookup_cache ( dest , False )
 if ( O0oo0OOo00o0o == None ) :
  iIiI1I1ii1I1 = source . print_sg ( dest ) if oOoOo else dest . print_address ( )
  iIiI1I1ii1I1 = green ( iIiI1I1ii1I1 , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( iIiI1I1ii1I1 ) )
  return ( None )
  if 75 - 75: I11i . II111iiii * I1IiiI * IiII
  if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
  if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
  if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
  if 34 - 34: iIii1I11I1II1
 if ( oOoOo == False ) :
  oo0o0oOOoo00 = green ( O0oo0OOo00o0o . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , oo0o0oOOoo00 ) )
  if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
  return ( O0oo0OOo00o0o )
  if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
  if 20 - 20: OoO0O00
  if 93 - 93: ooOoO0o + o0oOOo0O0Ooo - I1ii11iIi11i
  if 56 - 56: Ii1I / Oo0Ooo
  if 96 - 96: o0oOOo0O0Ooo . II111iiii
 O0oo0OOo00o0o = O0oo0OOo00o0o . lookup_source_cache ( source , False )
 if ( O0oo0OOo00o0o == None ) :
  iIiI1I1ii1I1 = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( iIiI1I1ii1I1 ) )
  return ( None )
  if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
  if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
  if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
  if 6 - 6: OoooooooOO
  if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
 oo0o0oOOoo00 = green ( O0oo0OOo00o0o . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , oo0o0oOOoo00 ) )
 if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
 return ( O0oo0OOo00o0o )
 if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
 if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
 if 14 - 14: OOooOOo * IiII
 if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
 if 33 - 33: OoO0O00
 if 91 - 91: I11i % I11i % iII111i
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  oOo0III = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( oOo0III )
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
 oOo0III = lisp_referral_cache . lookup_cache ( group , exact )
 if ( oOo0III == None ) : return ( None )
 if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
 iiiIIiIII111 = oOo0III . lookup_source_cache ( eid , exact )
 if ( iiiIIiIII111 ) : return ( iiiIIiIII111 )
 if 20 - 20: Oo0Ooo
 if ( exact ) : oOo0III = None
 return ( oOo0III )
 if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
 if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
 if 84 - 84: OOooOOo
 if 68 - 68: I1Ii111
 if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
 if 54 - 54: oO0o + I11i - OoO0O00
 if 86 - 86: OoooooooOO
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  OooOoo0o = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( OooOoo0o )
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
 OooOoo0o = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( OooOoo0o == None ) : return ( None )
 if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
 O0OoiI11Ii = OooOoo0o . lookup_source_cache ( eid , exact )
 if ( O0OoiI11Ii ) : return ( O0OoiI11Ii )
 if 58 - 58: i11iIiiIii
 if ( exact ) : OooOoo0o = None
 return ( OooOoo0o )
 if 16 - 16: OoOoOO00 - iII111i / I1Ii111
 if 60 - 60: OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
 if 87 - 87: iII111i
 if 86 - 86: IiII - I11i
 if 99 - 99: i1IIi + I1ii11iIi11i
 if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
 if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 44 - 44: II111iiii / I1ii11iIi11i
 if ( group . is_null ( ) ) :
  iI1IiiIiIIIi1 = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( iI1IiiIiIIIi1 )
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
 iI1IiiIiIIIi1 = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( iI1IiiIiIIIi1 == None ) : return ( None )
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
 O0OOO0o = iI1IiiIiIIIi1 . lookup_source_cache ( eid , exact )
 if ( O0OOO0o ) : return ( O0OOO0o )
 if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
 if ( exact ) :
  iI1IiiIiIIIi1 = None
 else :
  i11I1Ii1 = iI1IiiIiIIIi1 . parent_for_more_specifics
  if ( i11I1Ii1 and i11I1Ii1 . accept_more_specifics ) :
   if ( group . is_more_specific ( i11I1Ii1 . group ) ) : iI1IiiIiIIIi1 = i11I1Ii1
   if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
   if 11 - 11: Ii1I - ooOoO0o % i11iIiiIii / OoooooooOO - O0 - IiII
 return ( iI1IiiIiIIIi1 )
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
  oOOOo0o = self . address
  if ( ( ( oOOOo0o & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( oOOOo0o & 0xff000000 ) >> 24 ) == 172 ) :
   I1iiIii11Ii = ( oOOOo0o & 0x00ff0000 ) >> 16
   if ( I1iiIii11Ii >= 16 and I1iiIii11Ii <= 31 ) : return ( True )
   if 48 - 48: o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  if ( ( ( oOOOo0o & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
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
  oOOOo0o = self . address >> 96
  return ( oOOOo0o == 0x20010005 )
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
  Iii1iIII1Iii = self . packet_format ( )
  OO0Oo00OO0oo = b""
  if ( self . is_ipv4 ( ) ) :
   OO0Oo00OO0oo = struct . pack ( Iii1iIII1Iii , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   III = byte_swap_64 ( self . address >> 64 )
   I1I = byte_swap_64 ( self . address & 0xffffffffffffffff )
   OO0Oo00OO0oo = struct . pack ( Iii1iIII1Iii , III , I1I )
  elif ( self . is_mac ( ) ) :
   oOOOo0o = self . address
   III = ( oOOOo0o >> 32 ) & 0xffff
   I1I = ( oOOOo0o >> 16 ) & 0xffff
   iIi1 = oOOOo0o & 0xffff
   OO0Oo00OO0oo = struct . pack ( Iii1iIII1Iii , III , I1I , iIi1 )
  elif ( self . is_e164 ( ) ) :
   oOOOo0o = self . address
   III = ( oOOOo0o >> 32 ) & 0xffffffff
   I1I = ( oOOOo0o & 0xffffffff )
   OO0Oo00OO0oo = struct . pack ( Iii1iIII1Iii , III , I1I )
  elif ( self . is_dist_name ( ) ) :
   OO0Oo00OO0oo += self . address + "\0"
   if 75 - 75: O0 - iIii1I11I1II1 . i1IIi * II111iiii . II111iiii
  return ( OO0Oo00OO0oo )
  if 16 - 16: I1Ii111 / I1IiiI % OOooOOo
  if 61 - 61: I1ii11iIi11i . OOooOOo - O0 * OoOoOO00
 def unpack_address ( self , packet ) :
  Iii1iIII1Iii = self . packet_format ( )
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 12 - 12: I1ii11iIi11i / I1Ii111
  oOOOo0o = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 5 - 5: Oo0Ooo / o0oOOo0O0Ooo % i11iIiiIii - ooOoO0o
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( oOOOo0o [ 0 ] )
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
   if ( oOOOo0o [ 0 ] <= 0xffff and ( oOOOo0o [ 0 ] & 0xff ) == 0 ) :
    OO0I11iI = ( oOOOo0o [ 0 ] << 48 ) << 64
   else :
    OO0I11iI = byte_swap_64 ( oOOOo0o [ 0 ] ) << 64
    if 52 - 52: OoO0O00 % I11i - oO0o . I11i % IiII
   OooOOoO0o0 = byte_swap_64 ( oOOOo0o [ 1 ] )
   self . address = OO0I11iI | OooOOoO0o0
   if 13 - 13: I1IiiI / iIii1I11I1II1 - I11i - iIii1I11I1II1 - OoOoOO00 % O0
  elif ( self . is_mac ( ) ) :
   i1oO00o = oOOOo0o [ 0 ]
   I1IoOo = oOOOo0o [ 1 ]
   iI1IIiI1i11Ii = oOOOo0o [ 2 ]
   self . address = ( i1oO00o << 32 ) + ( I1IoOo << 16 ) + iI1IIiI1i11Ii
   if 70 - 70: I1IiiI . I1IiiI - OoooooooOO - I11i
  elif ( self . is_e164 ( ) ) :
   self . address = ( oOOOo0o [ 0 ] << 32 ) + oOOOo0o [ 1 ]
   if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   oOoOo000Ooooo = 0
   if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
  packet = packet [ oOoOo000Ooooo : : ]
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
  OoOOoO0oOo = addr_str . find ( "[" )
  Oooo0 = addr_str . find ( "]" )
  if ( OoOOoO0oOo != - 1 and Oooo0 != - 1 ) :
   self . instance_id = int ( addr_str [ OoOOoO0oOo + 1 : Oooo0 ] )
   addr_str = addr_str [ Oooo0 + 1 : : ]
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
   iiIiII11i1 = int ( i1i11i1Iii [ 0 ] ) << 24
   iiIiII11i1 += int ( i1i11i1Iii [ 1 ] ) << 16
   iiIiII11i1 += int ( i1i11i1Iii [ 2 ] ) << 8
   iiIiII11i1 += int ( i1i11i1Iii [ 3 ] )
   self . address = iiIiII11i1
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
   iII1I11iI = lisp_geo ( None )
   iII1I11iI . name = "geo-prefix-{}" . format ( iII1I11iI )
   iII1I11iI . parse_geo_string ( addr_str )
   self . address = iII1I11iI
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
   if 46 - 46: I1ii11iIi11i / ooOoO0o
  self . mask_len = self . host_mask_len ( )
  if 69 - 69: I1ii11iIi11i . IiII % o0oOOo0O0Ooo / OoooooooOO
  if 7 - 7: o0oOOo0O0Ooo % II111iiii
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   OOOooo0OooOoO = prefix_str . find ( "]" )
   ooOoO00 = len ( prefix_str [ OOOooo0OooOoO + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , ooOoO00 = prefix_str . split ( "/" )
  else :
   Oo = prefix_str . find ( "'" )
   if ( Oo == - 1 ) : return
   o0 = prefix_str . find ( "'" , Oo + 1 )
   if ( o0 == - 1 ) : return
   ooOoO00 = len ( prefix_str [ Oo + 1 : o0 ] ) * 8
   if 78 - 78: i11iIiiIii - I1ii11iIi11i + oO0o + II111iiii + OoooooooOO
   if 70 - 70: II111iiii
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( ooOoO00 )
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
  iII1I11iI = addr_str . split ( "/" )
  if ( len ( iII1I11iI ) == 2 ) :
   if ( iII1I11iI [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 33 - 33: oO0o * IiII / i11iIiiIii
  iII1I11iI = iII1I11iI [ 0 ]
  iII1I11iI = iII1I11iI . split ( "-" )
  o0o0o0o0 = len ( iII1I11iI )
  if ( o0o0o0o0 < 8 or o0o0o0o0 > 9 ) : return ( False )
  if 18 - 18: oO0o . I1ii11iIi11i % oO0o
  for IIi1IIi in range ( 0 , o0o0o0o0 ) :
   if ( IIi1IIi == 3 ) :
    if ( iII1I11iI [ IIi1IIi ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 96 - 96: Ii1I % I11i * OoooooooOO . I1IiiI . iIii1I11I1II1
   if ( IIi1IIi == 7 ) :
    if ( iII1I11iI [ IIi1IIi ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 8 - 8: O0 + o0oOOo0O0Ooo / O0 - I1ii11iIi11i % I1ii11iIi11i
   if ( iII1I11iI [ IIi1IIi ] . isdigit ( ) == False ) : return ( False )
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
  oOOOo0o = self . print_address_no_iid ( )
  i1oO00O = "[" + str ( self . instance_id )
  for OoOOoO0oOo in self . iid_list : i1oO00O += "," + str ( OoOOoO0oOo )
  i1oO00O += "]"
  oOOOo0o = "{}{}" . format ( i1oO00O , oOOOo0o )
  return ( oOOOo0o )
  if 89 - 89: i11iIiiIii + I1ii11iIi11i - ooOoO0o . ooOoO0o + Oo0Ooo % Ii1I
  if 96 - 96: I1Ii111 - I11i * I1Ii111
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   oOOOo0o = self . address
   Iiii = oOOOo0o >> 24
   OoO00oO00O0 = ( oOOOo0o >> 16 ) & 0xff
   o0o00OOoO00Oo = ( oOOOo0o >> 8 ) & 0xff
   OoOo0 = oOOOo0o & 0xff
   return ( "{}.{}.{}.{}" . format ( Iiii , OoO00oO00O0 , o0o00OOoO00Oo , OoOo0 ) )
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
  oOOOo0o = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( oOOOo0o )
  if ( self . is_geo_prefix ( ) ) : return ( oOOOo0o )
  if 78 - 78: i11iIiiIii % oO0o % Ii1I / I1Ii111 / I1Ii111
  OOOooo0OooOoO = oOOOo0o . find ( "no-address" )
  if ( OOOooo0OooOoO == - 1 ) :
   oOOOo0o = "{}/{}" . format ( oOOOo0o , str ( self . mask_len ) )
  else :
   oOOOo0o = oOOOo0o [ 0 : OOOooo0OooOoO ]
   if 20 - 20: iII111i / I11i / iIii1I11I1II1
  return ( oOOOo0o )
  if 94 - 94: i11iIiiIii % I1ii11iIi11i % IiII - I1Ii111
  if 55 - 55: I11i - ooOoO0o - iIii1I11I1II1 + I1ii11iIi11i / IiII
 def print_prefix_no_iid ( self ) :
  oOOOo0o = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( oOOOo0o )
  if ( self . is_geo_prefix ( ) ) : return ( oOOOo0o )
  return ( "{}/{}" . format ( oOOOo0o , str ( self . mask_len ) ) )
  if 49 - 49: I1ii11iIi11i
  if 91 - 91: OOooOOo % iII111i
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  oOOOo0o = self . print_address ( )
  OOOooo0OooOoO = oOOOo0o . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : oOOOo0o = oOOOo0o [ OOOooo0OooOoO + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   oOOOo0o = oOOOo0o . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , oOOOo0o ) )
   if 40 - 40: i11iIiiIii . II111iiii / OoOoOO00 + OoooooooOO + i1IIi . O0
  return ( "{}-{}-{}" . format ( self . instance_id , oOOOo0o , self . mask_len ) )
  if 39 - 39: I1ii11iIi11i
  if 26 - 26: oO0o . I1Ii111 % I11i
 def print_sg ( self , g ) :
  I1iiIi111I = self . print_prefix ( )
  OooOo = I1iiIi111I . find ( "]" ) + 1
  g = g . print_prefix ( )
  i1iii = g . find ( "]" ) + 1
  i111i1iIi1 = "[{}]({}, {})" . format ( self . instance_id , I1iiIi111I [ OooOo : : ] , g [ i1iii : : ] )
  return ( i111i1iIi1 )
  if 51 - 51: OoOoOO00
  if 34 - 34: i11iIiiIii * OoooooooOO
 def hash_address ( self , addr ) :
  III = self . address
  I1I = addr . address
  if 74 - 74: OoooooooOO * iII111i % OOooOOo . OoooooooOO * I11i % I1Ii111
  if ( self . is_geo_prefix ( ) ) : III = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : I1I = addr . address . print_geo ( )
  if 67 - 67: I11i * i1IIi
  if ( type ( III ) == str ) :
   III = int ( binascii . hexlify ( III [ 0 : 1 ] ) )
   if 7 - 7: i1IIi * OoOoOO00 . Ii1I
  if ( type ( I1I ) == str ) :
   I1I = int ( binascii . hexlify ( I1I [ 0 : 1 ] ) )
   if 80 - 80: OoOoOO00 + o0oOOo0O0Ooo - II111iiii
  return ( III ^ I1I )
  if 3 - 3: ooOoO0o * I1Ii111
  if 34 - 34: Ii1I / Oo0Ooo . II111iiii - ooOoO0o - I1ii11iIi11i % OoOoOO00
  if 43 - 43: Ii1I * oO0o
  if 57 - 57: OoooooooOO + I1IiiI % I1ii11iIi11i % ooOoO0o * I1Ii111
  if 9 - 9: i11iIiiIii
  if 85 - 85: IiII / o0oOOo0O0Ooo * ooOoO0o
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 74 - 74: O0 - o0oOOo0O0Ooo
  ooOoO00 = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   oooOOo0o0ooO = 2 ** ( 32 - ooOoO00 )
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
   oOOOo0o = self . address
   O000 = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    oOOOo0o = self . address . print_geo ( )
    O000 = prefix . address . print_geo ( )
    if 12 - 12: OoooooooOO . OoooooooOO * I11i
   if ( len ( oOOOo0o ) < len ( O000 ) ) : return ( False )
   return ( oOOOo0o . find ( O000 ) == 0 )
   if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
   if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
   if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
   if 98 - 98: II111iiii - i1IIi - ooOoO0o
   if 36 - 36: IiII + o0oOOo0O0Ooo
  if ( self . mask_len < ooOoO00 ) : return ( False )
  if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
  I1ii1iiI1I1I1 = ( prefix . addr_length ( ) * 8 ) - ooOoO00
  O0o0 = ( 2 ** ooOoO00 - 1 ) << I1ii1iiI1I1I1
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
   Ii1IiIOo = lisp_myrlocs [ 0 ]
   if ( Ii1IiIOo == None ) : return ( False )
   Ii1IiIOo = Ii1IiIOo . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == Ii1IiIOo )
   if 73 - 73: iIii1I11I1II1 * Oo0Ooo
  if ( self . is_ipv6 ( ) ) :
   Ii1IiIOo = lisp_myrlocs [ 1 ]
   if ( Ii1IiIOo == None ) : return ( False )
   Ii1IiIOo = Ii1IiIOo . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == Ii1IiIOo )
   if 54 - 54: oO0o . Ii1I
  return ( False )
  if 31 - 31: I11i
  if 60 - 60: Oo0Ooo - iII111i . II111iiii % ooOoO0o / OoooooooOO / iIii1I11I1II1
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 23 - 23: I11i + iIii1I11I1II1
  self . instance_id = iid
  self . mask_len = mask_len
  if 60 - 60: O0 * I1IiiI + o0oOOo0O0Ooo * OoO0O00 + o0oOOo0O0Ooo / i11iIiiIii
  if 54 - 54: i11iIiiIii . iII111i * i1IIi
 def lcaf_length ( self , lcaf_type ) :
  iI = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : iI += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : iI += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : iI += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : iI += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : iI += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : iI += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : iI += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : iI += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : iI = iI * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : iI += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : iI += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : iI += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : iI += 4
  return ( iI )
  if 68 - 68: Oo0Ooo
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
  ooOoOoOo = LISP_LCAF_INSTANCE_ID_TYPE
  OOoo = socket . htons ( self . lcaf_length ( ooOoOoOo ) )
  i1oO00O = self . instance_id
  O0ooO0O00oo0 = self . afi
  O00o00 = 0
  if ( O0ooO0O00oo0 < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    O0ooO0O00oo0 = LISP_AFI_LCAF
    O00o00 = 0
   else :
    O0ooO0O00oo0 = 0
    O00o00 = self . mask_len
    if 81 - 81: i11iIiiIii / Oo0Ooo * i1IIi + OoO0O00 + O0 % I1ii11iIi11i
    if 3 - 3: i11iIiiIii * IiII . Oo0Ooo % OoOoOO00 * I11i . iII111i
    if 80 - 80: I11i - IiII
  I11Ii111iiii1 = struct . pack ( "BBBBH" , 0 , 0 , ooOoOoOo , O00o00 , OOoo )
  I11Ii111iiii1 += struct . pack ( "IH" , socket . htonl ( i1oO00O ) , socket . htons ( O0ooO0O00oo0 ) )
  if ( O0ooO0O00oo0 == 0 ) : return ( I11Ii111iiii1 )
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
  Iii1iIII1Iii = "BBBBH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 92 - 92: iIii1I11I1II1
  ooooO00o0 , IIi11I , ooOoOoOo , i1iIio00oOoOO0 , iI = struct . unpack ( Iii1iIII1Iii ,
 packet [ : oOoOo000Ooooo ] )
  packet = packet [ oOoOo000Ooooo : : ]
  if 70 - 70: OoooooooOO - oO0o * IiII + OoooooooOO
  if ( ooOoOoOo != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 65 - 65: OoooooooOO + OOooOOo - I1Ii111
  Iii1iIII1Iii = "IH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 78 - 78: Oo0Ooo * OOooOOo + i11iIiiIii
  i1oO00O , O0ooO0O00oo0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  packet = packet [ oOoOo000Ooooo : : ]
  if 15 - 15: I1ii11iIi11i % I1Ii111 . I1ii11iIi11i - iIii1I11I1II1
  iI = socket . ntohs ( iI )
  self . instance_id = socket . ntohl ( i1oO00O )
  O0ooO0O00oo0 = socket . ntohs ( O0ooO0O00oo0 )
  self . afi = O0ooO0O00oo0
  if ( i1iIio00oOoOO0 != 0 and O0ooO0O00oo0 == 0 ) : self . mask_len = i1iIio00oOoOO0
  if ( O0ooO0O00oo0 == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if i1iIio00oOoOO0 else LISP_AFI_ULTIMATE_ROOT
   if 20 - 20: i1IIi - Ii1I . II111iiii + O0 % oO0o % II111iiii
   if 26 - 26: iIii1I11I1II1 - Ii1I / iIii1I11I1II1 . i1IIi - o0oOOo0O0Ooo
   if 48 - 48: iII111i . i11iIiiIii - iIii1I11I1II1 / iIii1I11I1II1
   if 92 - 92: II111iiii . oO0o - O0 + o0oOOo0O0Ooo * I1ii11iIi11i
   if 32 - 32: I1IiiI % OoO0O00
  if ( O0ooO0O00oo0 == 0 ) : return ( packet )
  if 71 - 71: OoooooooOO . I11i . I1IiiI
  if 27 - 27: i11iIiiIii + Oo0Ooo * I11i / OOooOOo - iII111i
  if 42 - 42: ooOoO0o . II111iiii % OoOoOO00 - I11i
  if 34 - 34: Ii1I % I1Ii111 % I1ii11iIi11i - IiII
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 89 - 89: IiII
   if 64 - 64: OoOoOO00
   if 3 - 3: i11iIiiIii / I1Ii111
   if 40 - 40: OoooooooOO / o0oOOo0O0Ooo + OoOoOO00
   if 73 - 73: OOooOOo / Oo0Ooo
  if ( O0ooO0O00oo0 == LISP_AFI_LCAF ) :
   Iii1iIII1Iii = "BBBBH"
   oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
   if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
   if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
   i1ii1iiI11ii1II1 , IIi1 , ooOoOoOo , oo0oOOo0 , iIi1IiiIII = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
   if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
   if 70 - 70: I1ii11iIi11i
   if ( ooOoOoOo != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 11 - 11: I1Ii111
   iIi1IiiIII = socket . ntohs ( iIi1IiiIII )
   packet = packet [ oOoOo000Ooooo : : ]
   if ( iIi1IiiIII > len ( packet ) ) : return ( None )
   if 70 - 70: Ii1I
   iII1I11iI = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = iII1I11iI
   packet = iII1I11iI . decode_geo ( packet , iIi1IiiIII , oo0oOOo0 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 22 - 22: Ii1I
   if 59 - 59: I1ii11iIi11i
  OOoo = self . addr_length ( )
  if ( len ( packet ) < OOoo ) : return ( None )
  if 90 - 90: OOooOOo / iII111i
  packet = self . unpack_address ( packet )
  return ( packet )
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
  if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
  if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
  if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
 def lcaf_encode_sg ( self , group ) :
  ooOoOoOo = LISP_LCAF_MCAST_INFO_TYPE
  i1oO00O = socket . htonl ( self . instance_id )
  OOoo = socket . htons ( self . lcaf_length ( ooOoOoOo ) )
  I11Ii111iiii1 = struct . pack ( "BBBBHIHBB" , 0 , 0 , ooOoOoOo , 0 , OOoo , i1oO00O ,
 0 , self . mask_len , group . mask_len )
  if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  I11Ii111iiii1 += struct . pack ( "H" , socket . htons ( self . afi ) )
  I11Ii111iiii1 += self . pack_address ( )
  I11Ii111iiii1 += struct . pack ( "H" , socket . htons ( group . afi ) )
  I11Ii111iiii1 += group . pack_address ( )
  return ( I11Ii111iiii1 )
  if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
  if 8 - 8: OOooOOo
 def lcaf_decode_sg ( self , packet ) :
  Iii1iIII1Iii = "BBBBHIHBB"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  if 85 - 85: O0 % OOooOOo . Ii1I
  ooooO00o0 , IIi11I , ooOoOoOo , OOOo00o , iI , i1oO00O , OOO0ooo0O , IiI1Ii1iI11i , I1II1I = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 13 - 13: o0oOOo0O0Ooo / O0 . I1Ii111 * I1Ii111
  packet = packet [ oOoOo000Ooooo : : ]
  if 76 - 76: Ii1I - iII111i
  if ( ooOoOoOo != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 79 - 79: o0oOOo0O0Ooo + IiII / o0oOOo0O0Ooo - I1IiiI / OoooooooOO
  self . instance_id = socket . ntohl ( i1oO00O )
  iI = socket . ntohs ( iI ) - 8
  if 17 - 17: OOooOOo * I1ii11iIi11i . Ii1I . iIii1I11I1II1 * OoooooooOO
  if 60 - 60: II111iiii % Oo0Ooo * I11i * OoO0O00 - OoOoOO00
  if 65 - 65: iII111i
  if 86 - 86: OoO0O00 / II111iiii % OoOoOO00 * OOooOOo . I1IiiI / IiII
  if 100 - 100: i1IIi / I1IiiI * I1ii11iIi11i % ooOoO0o + OoO0O00 * oO0o
  Iii1iIII1Iii = "H"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  if ( iI < oOoOo000Ooooo ) : return ( [ None , None ] )
  if 51 - 51: I1Ii111 - OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00
  O0ooO0O00oo0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  iI -= oOoOo000Ooooo
  self . afi = socket . ntohs ( O0ooO0O00oo0 )
  self . mask_len = IiI1Ii1iI11i
  OOoo = self . addr_length ( )
  if ( iI < OOoo ) : return ( [ None , None ] )
  if 45 - 45: i11iIiiIii - II111iiii / i1IIi * OoOoOO00
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 1 - 1: OOooOOo + I1IiiI + Ii1I . iII111i
  iI -= OOoo
  if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
  if 5 - 5: OoOoOO00 % i1IIi
  if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
  if 76 - 76: Oo0Ooo + I1IiiI - O0
  if 58 - 58: IiII * i1IIi . I1IiiI - iII111i
  Iii1iIII1Iii = "H"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  if ( iI < oOoOo000Ooooo ) : return ( [ None , None ] )
  if 73 - 73: Oo0Ooo . OoOoOO00
  O0ooO0O00oo0 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  iI -= oOoOo000Ooooo
  o0o0o = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  o0o0o . afi = socket . ntohs ( O0ooO0O00oo0 )
  o0o0o . mask_len = I1II1I
  o0o0o . instance_id = self . instance_id
  OOoo = self . addr_length ( )
  if ( iI < OOoo ) : return ( [ None , None ] )
  if 50 - 50: IiII / o0oOOo0O0Ooo
  packet = o0o0o . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
  return ( [ packet , o0o0o ] )
  if 52 - 52: O0
  if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
 def lcaf_decode_eid ( self , packet ) :
  Iii1iIII1Iii = "BBB"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
  if 83 - 83: oO0o / OoO0O00
  if 34 - 34: OoooooooOO - i1IIi * O0
  if 83 - 83: I1IiiI + OoO0O00
  OOOo00o , IIi1 , ooOoOoOo = struct . unpack ( Iii1iIII1Iii ,
 packet [ : oOoOo000Ooooo ] )
  if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
  if ( ooOoOoOo == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( ooOoOoOo == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , o0o0o = self . lcaf_decode_sg ( packet )
   return ( [ packet , o0o0o ] )
  elif ( ooOoOoOo == LISP_LCAF_GEO_COORD_TYPE ) :
   Iii1iIII1Iii = "BBBBH"
   oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
   if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
   if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
   i1ii1iiI11ii1II1 , IIi1 , ooOoOoOo , oo0oOOo0 , iIi1IiiIII = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
   if 15 - 15: iIii1I11I1II1 * I1ii11iIi11i / ooOoO0o * oO0o % OOooOOo
   if 62 - 62: Ii1I / Oo0Ooo . OoO0O00 - OOooOOo
   if ( ooOoOoOo != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 89 - 89: o0oOOo0O0Ooo % OoO0O00
   iIi1IiiIII = socket . ntohs ( iIi1IiiIII )
   packet = packet [ oOoOo000Ooooo : : ]
   if ( iIi1IiiIII > len ( packet ) ) : return ( None )
   if 53 - 53: OoOoOO00 . ooOoO0o - OoO0O00
   iII1I11iI = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = iII1I11iI
   packet = iII1I11iI . decode_geo ( packet , iIi1IiiIII , oo0oOOo0 )
   self . mask_len = self . host_mask_len ( )
   if 26 - 26: ooOoO0o - oO0o + OOooOOo * Ii1I - I11i % I1IiiI
  return ( [ packet , None ] )
  if 73 - 73: ooOoO0o + Ii1I . O0 . iII111i
  if 77 - 77: OOooOOo % I1IiiI - iII111i % I1Ii111
  if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
  if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
  if 46 - 46: I1ii11iIi11i * ooOoO0o
  if 4 - 4: I1Ii111 * II111iiii
class lisp_elp_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
  if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
 def copy_elp_node ( self ) :
  oO0 = lisp_elp_node ( )
  oO0 . copy_address ( self . address )
  oO0 . probe = self . probe
  oO0 . strict = self . strict
  oO0 . eid = self . eid
  oO0 . we_are_last = self . we_are_last
  return ( oO0 )
  if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
  if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
  if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
class lisp_elp ( object ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
  if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
 def copy_elp ( self ) :
  iII11 = lisp_elp ( self . elp_name )
  iII11 . use_elp_node = self . use_elp_node
  iII11 . we_are_last = self . we_are_last
  for oO0 in self . elp_nodes :
   iII11 . elp_nodes . append ( oO0 . copy_elp_node ( ) )
   if 84 - 84: Oo0Ooo + OoOoOO00 / iII111i . I1ii11iIi11i
  return ( iII11 )
  if 26 - 26: Oo0Ooo
  if 61 - 61: Ii1I * oO0o * i11iIiiIii + OoO0O00
 def print_elp ( self , want_marker ) :
  iIII1Iiii = ""
  for oO0 in self . elp_nodes :
   iI1IIiiI11IiI = ""
   if ( want_marker ) :
    if ( oO0 == self . use_elp_node ) :
     iI1IIiiI11IiI = "*"
    elif ( oO0 . we_are_last ) :
     iI1IIiiI11IiI = "x"
     if 94 - 94: i1IIi - i11iIiiIii + I1Ii111 % Oo0Ooo % Oo0Ooo . OoO0O00
     if 65 - 65: IiII * I11i * o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoOoOO00 % OoOoOO00
   iIII1Iiii += "{}{}({}{}{}), " . format ( iI1IIiiI11IiI ,
 oO0 . address . print_address_no_iid ( ) ,
 "r" if oO0 . eid else "R" , "P" if oO0 . probe else "p" ,
 "S" if oO0 . strict else "s" )
   if 55 - 55: i11iIiiIii * II111iiii
  return ( iIII1Iiii [ 0 : - 2 ] if iIII1Iiii != "" else "" )
  if 41 - 41: iIii1I11I1II1
  if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
 def select_elp_node ( self ) :
  oO0oO000ooo0o , II11iII1i11ii , OoO0 = lisp_myrlocs
  OOOooo0OooOoO = None
  if 34 - 34: iII111i % I11i % oO0o
  for oO0 in self . elp_nodes :
   if ( oO0oO000ooo0o and oO0 . address . is_exact_match ( oO0oO000ooo0o ) ) :
    OOOooo0OooOoO = self . elp_nodes . index ( oO0 )
    break
    if 71 - 71: OoooooooOO . iII111i . oO0o
   if ( II11iII1i11ii and oO0 . address . is_exact_match ( II11iII1i11ii ) ) :
    OOOooo0OooOoO = self . elp_nodes . index ( oO0 )
    break
    if 62 - 62: i1IIi . II111iiii . IiII * OOooOOo % i11iIiiIii * I11i
    if 48 - 48: I1Ii111 - O0
    if 23 - 23: iIii1I11I1II1
    if 88 - 88: I1IiiI + iII111i / Ii1I
    if 57 - 57: o0oOOo0O0Ooo
    if 69 - 69: i1IIi / i1IIi / OoOoOO00 + ooOoO0o % I1Ii111
    if 41 - 41: II111iiii * OOooOOo
  if ( OOOooo0OooOoO == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   oO0 . we_are_last = False
   return
   if 8 - 8: I1Ii111 + O0
   if 67 - 67: iIii1I11I1II1 . O0
   if 40 - 40: OOooOOo - ooOoO0o . OoooooooOO % O0 * I11i - I1ii11iIi11i
   if 92 - 92: ooOoO0o % oO0o / i11iIiiIii
   if 91 - 91: OOooOOo
   if 60 - 60: i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ OOOooo0OooOoO ] ) :
   self . use_elp_node = None
   oO0 . we_are_last = True
   return
   if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
   if 54 - 54: II111iiii * I1IiiI
   if 49 - 49: I1ii11iIi11i
   if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
   if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  self . use_elp_node = self . elp_nodes [ OOOooo0OooOoO + 1 ]
  return
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  if 15 - 15: oO0o
  if 40 - 40: I1Ii111
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
  if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
  if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
 def copy_geo ( self ) :
  iII1I11iI = lisp_geo ( self . geo_name )
  iII1I11iI . latitude = self . latitude
  iII1I11iI . lat_mins = self . lat_mins
  iII1I11iI . lat_secs = self . lat_secs
  iII1I11iI . longitude = self . longitude
  iII1I11iI . long_mins = self . long_mins
  iII1I11iI . long_secs = self . long_secs
  iII1I11iI . altitude = self . altitude
  iII1I11iI . radius = self . radius
  return ( iII1I11iI )
  if 64 - 64: ooOoO0o / IiII . I1IiiI
  if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 90 - 90: I11i
  if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
 def parse_geo_string ( self , geo_str ) :
  OOOooo0OooOoO = geo_str . find ( "]" )
  if ( OOOooo0OooOoO != - 1 ) : geo_str = geo_str [ OOOooo0OooOoO + 1 : : ]
  if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
  if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
  if 13 - 13: II111iiii
  if 22 - 22: o0oOOo0O0Ooo
  if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , iIii = geo_str . split ( "/" )
   self . radius = int ( iIii )
   if 93 - 93: OoOoOO00
   if 48 - 48: i1IIi
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 22 - 22: iII111i / OoO0O00 * OOooOOo + I11i
  o000Oo00oOoO = geo_str [ 0 : 4 ]
  I11II = geo_str [ 4 : 8 ]
  if 16 - 16: I1IiiI + I11i
  if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
  if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
  if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 78 - 78: i1IIi / ooOoO0o / oO0o
  if 21 - 21: IiII % Ii1I + OOooOOo + IiII
  if 90 - 90: o0oOOo0O0Ooo
  if 38 - 38: OoOoOO00 / OOooOOo % OoooooooOO * I1ii11iIi11i
  self . latitude = int ( o000Oo00oOoO [ 0 ] )
  self . lat_mins = int ( o000Oo00oOoO [ 1 ] )
  self . lat_secs = int ( o000Oo00oOoO [ 2 ] )
  if ( o000Oo00oOoO [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 7 - 7: I11i * O0 + Oo0Ooo / O0 * oO0o + i11iIiiIii
  if 74 - 74: OoOoOO00
  if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
  if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
  self . longitude = int ( I11II [ 0 ] )
  self . long_mins = int ( I11II [ 1 ] )
  self . long_secs = int ( I11II [ 2 ] )
  if ( I11II [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 87 - 87: ooOoO0o . iIii1I11I1II1
  if 99 - 99: Ii1I + OoooooooOO * IiII * i11iIiiIii - iIii1I11I1II1
 def print_geo ( self ) :
  o0oooooO0o = "N" if self . latitude < 0 else "S"
  OO0Ooo = "E" if self . longitude < 0 else "W"
  if 23 - 23: I1ii11iIi11i
  oOIIi = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , o0oooooO0o , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , OO0Ooo )
  if 68 - 68: OoO0O00 . oO0o / IiII - II111iiii % Oo0Ooo
  if ( self . no_geo_altitude ( ) == False ) :
   oOIIi += "-" + str ( self . altitude )
   if 24 - 24: II111iiii / I1ii11iIi11i + oO0o / Ii1I + IiII % oO0o
   if 86 - 86: I1IiiI
   if 83 - 83: I11i % Ii1I + IiII % I11i / i1IIi . oO0o
   if 56 - 56: I1Ii111 - OOooOOo % o0oOOo0O0Ooo
   if 30 - 30: I1Ii111 % i1IIi
  if ( self . radius != 0 ) : oOIIi += "/{}" . format ( self . radius )
  return ( oOIIi )
  if 98 - 98: oO0o . i11iIiiIii / Ii1I - Ii1I
  if 23 - 23: iIii1I11I1II1
 def geo_url ( self ) :
  iIIIiI = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  iIIIiI = "10" if ( iIIIiI == "" or iIIIiI . isdigit ( ) == False ) else iIIIiI
  I1iii11III , Iii = self . dms_to_decimal ( )
  Oo0OOoO0oo0oO = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( I1iii11III , Iii , I1iii11III , Iii ,
  # I1IiiI / iIii1I11I1II1
  # iII111i % i1IIi
 iIIIiI )
  return ( Oo0OOoO0oo0oO )
  if 92 - 92: o0oOOo0O0Ooo % i1IIi / OoooooooOO * OoooooooOO / iIii1I11I1II1
  if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
 def print_geo_url ( self ) :
  iII1I11iI = self . print_geo ( )
  if ( self . radius == 0 ) :
   Oo0OOoO0oo0oO = self . geo_url ( )
   Oo0OOOOOOO0oo = "<a href='{}'>{}</a>" . format ( Oo0OOoO0oo0oO , iII1I11iI )
  else :
   Oo0OOoO0oo0oO = iII1I11iI . replace ( "/" , "-" )
   Oo0OOOOOOO0oo = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( Oo0OOoO0oo0oO , iII1I11iI )
   if 33 - 33: I1Ii111 + OoooooooOO
  return ( Oo0OOOOOOO0oo )
  if 73 - 73: O0 . Oo0Ooo
  if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
 def dms_to_decimal ( self ) :
  iiIIii1I1I1 , Oo0O000oooo , o0o0 = self . latitude , self . lat_mins , self . lat_secs
  oO0o0 = float ( abs ( iiIIii1I1I1 ) )
  oO0o0 += float ( Oo0O000oooo * 60 + o0o0 ) / 3600
  if ( iiIIii1I1I1 > 0 ) : oO0o0 = - oO0o0
  I1iIii1I1 = oO0o0
  if 19 - 19: iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . Ii1I * OoO0O00
  iiIIii1I1I1 , Oo0O000oooo , o0o0 = self . longitude , self . long_mins , self . long_secs
  oO0o0 = float ( abs ( iiIIii1I1I1 ) )
  oO0o0 += float ( Oo0O000oooo * 60 + o0o0 ) / 3600
  if ( iiIIii1I1I1 > 0 ) : oO0o0 = - oO0o0
  iI1II1 = oO0o0
  return ( ( I1iIii1I1 , iI1II1 ) )
  if 2 - 2: i1IIi / Ii1I % OoO0O00
  if 85 - 85: i1IIi % iIii1I11I1II1
 def get_distance ( self , geo_point ) :
  iiOooo0 = self . dms_to_decimal ( )
  OooO = geo_point . dms_to_decimal ( )
  OO0OOOo = geopy . distance . distance ( iiOooo0 , OooO )
  return ( OO0OOOo . km )
  if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
 def point_in_circle ( self , geo_point ) :
  OO0OO0 = self . get_distance ( geo_point )
  return ( OO0OO0 <= self . radius )
  if 75 - 75: OoO0O00 % iII111i
  if 46 - 46: o0oOOo0O0Ooo
 def encode_geo ( self ) :
  O0oOo = socket . htons ( LISP_AFI_LCAF )
  o0o0o0o0 = socket . htons ( 20 + 2 )
  IIi1 = 0
  if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
  I1iii11III = abs ( self . latitude )
  i1IOO0oO0oooo00O = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : IIi1 |= 0x40
  if 79 - 79: OoO0O00 . OoooooooOO + iII111i
  Iii = abs ( self . longitude )
  i1iiII1ii11I = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : IIi1 |= 0x20
  if 8 - 8: OOooOOo % OoO0O00 + O0 - o0oOOo0O0Ooo
  IIIOo0oo00 = 0
  if ( self . no_geo_altitude ( ) == False ) :
   IIIOo0oo00 = socket . htonl ( self . altitude )
   IIi1 |= 0x10
   if 64 - 64: Ii1I / I1IiiI + ooOoO0o
  iIii = socket . htons ( self . radius )
  if ( iIii != 0 ) : IIi1 |= 0x06
  if 4 - 4: II111iiii - Ii1I
  O0O00o000 = struct . pack ( "HBBBBH" , O0oOo , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , o0o0o0o0 )
  O0O00o000 += struct . pack ( "BBHBBHBBHIHHH" , IIi1 , 0 , 0 , I1iii11III , i1IOO0oO0oooo00O >> 16 ,
 socket . htons ( i1IOO0oO0oooo00O & 0x0ffff ) , Iii , i1iiII1ii11I >> 16 ,
 socket . htons ( i1iiII1ii11I & 0xffff ) , IIIOo0oo00 , iIii , 0 , 0 )
  if 71 - 71: OoO0O00 . iIii1I11I1II1 * ooOoO0o + Oo0Ooo
  return ( O0O00o000 )
  if 65 - 65: OoOoOO00 % i1IIi % i1IIi + OoOoOO00 + i11iIiiIii + iII111i
  if 37 - 37: i11iIiiIii
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  Iii1iIII1Iii = "BBHBBHBBHIHHH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( lcaf_len < oOoOo000Ooooo ) : return ( None )
  if 56 - 56: OoooooooOO
  IIi1 , OoO00Oo0 , OOOOO00oOO0Oo , I1iii11III , O0ooo0O0Oo0OOO , i1IOO0oO0oooo00O , Iii , i1ii1i1i11IiI , i1iiII1ii11I , IIIOo0oo00 , iIii , IiIiII1iI1I1 , O0ooO0O00oo0 = struct . unpack ( Iii1iIII1Iii ,
  # OOooOOo % i11iIiiIii * I1IiiI % i11iIiiIii + OoO0O00 - iII111i
 packet [ : oOoOo000Ooooo ] )
  if 39 - 39: ooOoO0o . OoOoOO00
  if 60 - 60: o0oOOo0O0Ooo + iII111i
  if 8 - 8: OoOoOO00 - iIii1I11I1II1 * I1Ii111
  if 3 - 3: OoO0O00
  O0ooO0O00oo0 = socket . ntohs ( O0ooO0O00oo0 )
  if ( O0ooO0O00oo0 == LISP_AFI_LCAF ) : return ( None )
  if 48 - 48: i11iIiiIii * i11iIiiIii / oO0o
  if ( IIi1 & 0x40 ) : I1iii11III = - I1iii11III
  self . latitude = I1iii11III
  IiIiI = old_div ( ( ( O0ooo0O0Oo0OOO << 16 ) | socket . ntohs ( i1IOO0oO0oooo00O ) ) , 1000 )
  self . lat_mins = old_div ( IiIiI , 60 )
  self . lat_secs = IiIiI % 60
  if 19 - 19: I1IiiI
  if ( IIi1 & 0x20 ) : Iii = - Iii
  self . longitude = Iii
  i1iIi1 = old_div ( ( ( i1ii1i1i11IiI << 16 ) | socket . ntohs ( i1iiII1ii11I ) ) , 1000 )
  self . long_mins = old_div ( i1iIi1 , 60 )
  self . long_secs = i1iIi1 % 60
  if 3 - 3: oO0o * II111iiii . O0
  self . altitude = socket . ntohl ( IIIOo0oo00 ) if ( IIi1 & 0x10 ) else - 1
  iIii = socket . ntohs ( iIii )
  self . radius = iIii if ( IIi1 & 0x02 ) else iIii * 1000
  if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
  self . geo_name = None
  packet = packet [ oOoOo000Ooooo : : ]
  if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
  if ( O0ooO0O00oo0 != 0 ) :
   self . rloc . afi = O0ooO0O00oo0
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
  return ( packet )
  if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
  if 100 - 100: I11i - I1ii11iIi11i . i1IIi
  if 85 - 85: II111iiii
  if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
  if 4 - 4: I11i % I1IiiI
class lisp_rle_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . level = 0
  self . translated_port = 0
  self . rloc_name = None
  if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
  if 96 - 96: OoOoOO00 % Ii1I
 def copy_rle_node ( self ) :
  IIIi11i1 = lisp_rle_node ( )
  IIIi11i1 . address . copy_address ( self . address )
  IIIi11i1 . level = self . level
  IIIi11i1 . translated_port = self . translated_port
  IIIi11i1 . rloc_name = self . rloc_name
  return ( IIIi11i1 )
  if 50 - 50: IiII - II111iiii
  if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
 def store_translated_rloc ( self , rloc , port ) :
  self . address . copy_address ( rloc )
  self . translated_port = port
  if 13 - 13: II111iiii
  if 14 - 14: i11iIiiIii . IiII
 def get_encap_keys ( self ) :
  O00oo0o0o0oo = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 70 - 70: Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
  Oo0o = self . address . print_address_no_iid ( ) + ":" + O00oo0o0o0oo
  if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
  try :
   O0o0O0 = lisp_crypto_keys_by_rloc_encap [ Oo0o ]
   if ( O0o0O0 [ 1 ] ) : return ( O0o0O0 [ 1 ] . encrypt_key , O0o0O0 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
   if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
   if 49 - 49: iII111i + OoOoOO00
   if 33 - 33: ooOoO0o
class lisp_rle ( object ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 19 - 19: I1Ii111 % IiII
  if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
 def copy_rle ( self ) :
  IIiiiI = lisp_rle ( self . rle_name )
  for IIIi11i1 in self . rle_nodes :
   IIiiiI . rle_nodes . append ( IIIi11i1 . copy_rle_node ( ) )
   if 16 - 16: i1IIi
  IIiiiI . build_forwarding_list ( )
  return ( IIiiiI )
  if 88 - 88: OOooOOo
  if 79 - 79: oO0o
 def print_rle ( self , html , do_formatting ) :
  IIIi1iI1 = ""
  for IIIi11i1 in self . rle_nodes :
   O00oo0o0o0oo = IIIi11i1 . translated_port
   if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
   OOOO0o0o = ""
   if ( IIIi11i1 . rloc_name != None ) :
    OOOO0o0o = IIIi11i1 . rloc_name
    if ( do_formatting ) : OOOO0o0o = blue ( OOOO0o0o , html )
    OOOO0o0o = "({})" . format ( OOOO0o0o )
    if 95 - 95: ooOoO0o + o0oOOo0O0Ooo % OoO0O00
    if 42 - 42: ooOoO0o % iIii1I11I1II1 % ooOoO0o * oO0o * I1Ii111 * Ii1I
   Oo0o = IIIi11i1 . address . print_address_no_iid ( )
   if ( IIIi11i1 . address . is_local ( ) ) : Oo0o = red ( Oo0o , html )
   IIIi1iI1 += "{}{}{}, " . format ( Oo0o , "" if O00oo0o0o0oo == 0 else ":" + str ( O00oo0o0o0oo ) , OOOO0o0o )
   if 16 - 16: i11iIiiIii
   if 83 - 83: Oo0Ooo / Oo0Ooo . I11i + oO0o % Ii1I
  return ( IIIi1iI1 [ 0 : - 2 ] if IIIi1iI1 != "" else "" )
  if 22 - 22: ooOoO0o
  if 83 - 83: OOooOOo - i11iIiiIii - i1IIi / oO0o
 def build_forwarding_list ( self ) :
  iII111iI = - 1
  for IIIi11i1 in self . rle_nodes :
   if ( iII111iI == - 1 ) :
    if ( IIIi11i1 . address . is_local ( ) ) : iII111iI = IIIi11i1 . level
   else :
    if ( IIIi11i1 . level > iII111iI ) : break
    if 33 - 33: OoO0O00 + OOooOOo
    if 36 - 36: o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * ooOoO0o * Ii1I * IiII
  iII111iI = 0 if iII111iI == - 1 else IIIi11i1 . level
  if 39 - 39: i1IIi
  self . rle_forwarding_list = [ ]
  for IIIi11i1 in self . rle_nodes :
   if ( IIIi11i1 . level == iII111iI or ( iII111iI == 0 and
 IIIi11i1 . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and IIIi11i1 . address . is_local ( ) ) :
     Oo0o = IIIi11i1 . address . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( Oo0o ) )
     continue
     if 79 - 79: ooOoO0o - II111iiii - oO0o
    self . rle_forwarding_list . append ( IIIi11i1 )
    if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
    if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
    if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
    if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
    if 65 - 65: Ii1I . OoOoOO00 + O0 / iIii1I11I1II1 % Ii1I % I1Ii111
class lisp_json ( object ) :
 def __init__ ( self , name , string , encrypted = False , ms_encrypt = False ) :
  if 31 - 31: o0oOOo0O0Ooo - Oo0Ooo
  if 15 - 15: O0 + OOooOOo
  if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
  if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
  if ( type ( string ) == bytes ) : string = string . decode ( )
  if 87 - 87: i1IIi / OoooooooOO
  self . json_name = name
  self . json_encrypted = False
  try :
   json . loads ( string )
  except :
   lprint ( "Invalid JSON string: '{}'" . format ( string ) )
   string = '{ "?" : "?" }'
   if 68 - 68: I1Ii111 / iIii1I11I1II1
  self . json_string = string
  if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
  if 40 - 40: i11iIiiIii + OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo * OoO0O00
  if 88 - 88: Oo0Ooo + oO0o + iII111i
  if 51 - 51: i1IIi + i11iIiiIii * I11i / iII111i + OoooooooOO
  if 89 - 89: i11iIiiIii - I1Ii111 - O0 % iIii1I11I1II1 / IiII - O0
  if 63 - 63: OOooOOo
  if 23 - 23: Oo0Ooo / i1IIi - OOooOOo / Oo0Ooo
  if 16 - 16: o0oOOo0O0Ooo - iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i + IiII
  if 73 - 73: OOooOOo % I1Ii111 + OoooooooOO / I1ii11iIi11i * oO0o % oO0o
  if ( len ( lisp_ms_json_keys ) != 0 ) :
   if ( ms_encrypt == False ) : return
   self . json_key_id = list ( lisp_ms_json_keys . keys ( ) ) [ 0 ]
   self . json_key = lisp_ms_json_keys [ self . json_key_id ]
   self . encrypt_json ( )
   if 25 - 25: I1Ii111
   if 93 - 93: OoO0O00
  if ( lisp_log_id == "lig" and encrypted ) :
   III11II111 = os . getenv ( "LISP_JSON_KEY" )
   if ( III11II111 != None ) :
    OOOooo0OooOoO = - 1
    if ( III11II111 [ 0 ] == "[" and "]" in III11II111 ) :
     OOOooo0OooOoO = III11II111 . find ( "]" )
     self . json_key_id = int ( III11II111 [ 1 : OOOooo0OooOoO ] )
     if 62 - 62: Oo0Ooo . iII111i
    self . json_key = III11II111 [ OOOooo0OooOoO + 1 : : ]
    if 15 - 15: i11iIiiIii * I11i + oO0o
    self . decrypt_json ( )
    if 67 - 67: IiII . OoO0O00
    if 59 - 59: oO0o * o0oOOo0O0Ooo
    if 76 - 76: I1IiiI
    if 94 - 94: OoooooooOO * I1ii11iIi11i
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 28 - 28: II111iiii / II111iiii / II111iiii
  if 70 - 70: OoO0O00 + O0 * OoO0O00
 def delete ( self ) :
  if ( self . json_name in lisp_json_list ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
   if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
   if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
 def print_json ( self , html ) :
  oOOoo0O0OOO = self . json_string
  II1iiiiIIIII = "***"
  if ( html ) : II1iiiiIIIII = red ( II1iiiiIIIII , html )
  Iii1IIiIIii1 = II1iiiiIIIII + self . json_string + II1iiiiIIIII
  if ( self . valid_json ( ) ) : return ( oOOoo0O0OOO )
  return ( Iii1IIiIIii1 )
  if 56 - 56: iIii1I11I1II1 * I1Ii111 % o0oOOo0O0Ooo
  if 27 - 27: Oo0Ooo
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 16 - 16: Oo0Ooo * oO0o * oO0o
  return ( True )
  if 76 - 76: OoO0O00 - I1Ii111 / II111iiii . iIii1I11I1II1 + i11iIiiIii
  if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
 def encrypt_json ( self ) :
  OooOo0o = self . json_key . zfill ( 32 )
  iI1ii = "0" * 8
  if 38 - 38: i11iIiiIii
  Oo0O = json . loads ( self . json_string )
  for III11II111 in Oo0O :
   iiIiII11i1 = Oo0O [ III11II111 ]
   if ( type ( iiIiII11i1 ) != str ) : iiIiII11i1 = str ( iiIiII11i1 )
   iiIiII11i1 = chacha . ChaCha ( OooOo0o , iI1ii ) . encrypt ( iiIiII11i1 )
   Oo0O [ III11II111 ] = binascii . hexlify ( iiIiII11i1 )
   if 77 - 77: iII111i . I1IiiI - iIii1I11I1II1 + II111iiii / i1IIi
  self . json_string = json . dumps ( Oo0O )
  self . json_encrypted = True
  if 65 - 65: I1ii11iIi11i
  if 2 - 2: iII111i % I1ii11iIi11i / iII111i
 def decrypt_json ( self ) :
  OooOo0o = self . json_key . zfill ( 32 )
  iI1ii = "0" * 8
  if 93 - 93: iII111i
  Oo0O = json . loads ( self . json_string )
  for III11II111 in Oo0O :
   iiIiII11i1 = binascii . unhexlify ( Oo0O [ III11II111 ] )
   Oo0O [ III11II111 ] = chacha . ChaCha ( OooOo0o , iI1ii ) . encrypt ( iiIiII11i1 )
   if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
  try :
   self . json_string = json . dumps ( Oo0O )
   self . json_encrypted = False
  except :
   pass
   if 32 - 32: II111iiii
   if 58 - 58: I1IiiI - o0oOOo0O0Ooo - I1Ii111 . O0 % OoO0O00 . I11i
   if 41 - 41: iII111i . I1Ii111 - IiII / O0
   if 62 - 62: IiII * I1ii11iIi11i * iII111i * OoOoOO00
   if 12 - 12: Oo0Ooo * Ii1I / ooOoO0o % I11i % O0
   if 25 - 25: Oo0Ooo * oO0o
   if 78 - 78: OoOoOO00 / II111iiii
class lisp_stats ( object ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 6 - 6: I1Ii111 . OoOoOO00
  if 75 - 75: Oo0Ooo + I11i
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 87 - 87: I1IiiI
  if 36 - 36: OoO0O00 . ooOoO0o . O0 / OoO0O00
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  Ii1i1 = time . time ( ) - self . last_increment
  return ( Ii1i1 <= 1 )
  if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
  if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  Ii1i1 = time . time ( ) - self . last_increment
  return ( Ii1i1 <= 60 )
  if 72 - 72: I1ii11iIi11i
  if 74 - 74: I1Ii111 * iIii1I11I1II1 / oO0o - IiII - I1IiiI
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 84 - 84: iIii1I11I1II1 % Oo0Ooo / I1ii11iIi11i + o0oOOo0O0Ooo * II111iiii
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 81 - 81: I1IiiI / I1ii11iIi11i / OOooOOo
  return ( c1 , c2 )
  if 89 - 89: Oo0Ooo % IiII
  if 36 - 36: IiII % OoOoOO00 % I1ii11iIi11i
 def normalize ( self , count ) :
  count = str ( count )
  IIIIii1iIi = len ( count )
  if ( IIIIii1iIi > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 79 - 79: OoOoOO00 . ooOoO0o
  if ( IIIIii1iIi > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 22 - 22: oO0o + Ii1I - ooOoO0o + OoOoOO00 % OOooOOo - Oo0Ooo
  if ( IIIIii1iIi > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 59 - 59: OoOoOO00 * iII111i - OOooOOo
  return ( count )
  if 49 - 49: I1ii11iIi11i / oO0o . oO0o * iII111i % iII111i . I1IiiI
  if 96 - 96: II111iiii / OoooooooOO + iIii1I11I1II1 . Ii1I + OoooooooOO
 def get_stats ( self , summary , html ) :
  OO0O000 = self . last_rate_check
  iIiIiIIiIIi = self . last_packet_count
  iIIiI11 = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 59 - 59: OoOoOO00 % O0 * I1Ii111 - i1IIi
  O0o0OOOooO0 = self . last_rate_check - OO0O000
  if ( O0o0OOOooO0 == 0 ) :
   I1iiI1II = 0
   ooo0 = 0
  else :
   I1iiI1II = int ( old_div ( ( self . packet_count - iIiIiIIiIIi ) ,
 O0o0OOOooO0 ) )
   ooo0 = old_div ( ( self . byte_count - iIIiI11 ) , O0o0OOOooO0 )
   ooo0 = old_div ( ( ooo0 * 8 ) , 1000000 )
   ooo0 = round ( ooo0 , 2 )
   if 6 - 6: I1IiiI * I1Ii111 % I1IiiI - II111iiii . oO0o
   if 9 - 9: I1Ii111 . i11iIiiIii * I11i + o0oOOo0O0Ooo
   if 85 - 85: i11iIiiIii * iII111i
   if 43 - 43: Ii1I + iII111i * I1ii11iIi11i * Ii1I
   if 62 - 62: O0
  ii1I = self . normalize ( self . packet_count )
  oOo0Oo = self . normalize ( self . byte_count )
  if 68 - 68: iIii1I11I1II1 % Ii1I / I11i
  if 17 - 17: IiII * Oo0Ooo . i11iIiiIii . IiII . Oo0Ooo % IiII
  if 93 - 93: II111iiii - IiII - O0 - i11iIiiIii / OOooOOo
  if 76 - 76: OOooOOo
  if 31 - 31: OOooOOo + i1IIi / Ii1I / OoOoOO00 % OoO0O00 + Oo0Ooo
  if ( summary ) :
   Oo0oO0 = "<br>" if html else ""
   ii1I , oOo0Oo = self . stat_colors ( ii1I , oOo0Oo , html )
   Oo0ooO000OO = "packet-count: {}{}byte-count: {}" . format ( ii1I , Oo0oO0 , oOo0Oo )
   OO000 = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( I1iiI1II , ooo0 )
   if 48 - 48: OOooOOo
   if ( html != "" ) : OO000 = lisp_span ( Oo0ooO000OO , OO000 )
  else :
   O0O0ooOOO = str ( I1iiI1II )
   Oo0oo0oOO = str ( ooo0 )
   if ( html ) :
    ii1I = lisp_print_cour ( ii1I )
    O0O0ooOOO = lisp_print_cour ( O0O0ooOOO )
    oOo0Oo = lisp_print_cour ( oOo0Oo )
    Oo0oo0oOO = lisp_print_cour ( Oo0oo0oOO )
    if 78 - 78: i1IIi
   Oo0oO0 = "<br>" if html else ", "
   if 8 - 8: Oo0Ooo * I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
   OO000 = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( ii1I , Oo0oO0 , O0O0ooOOO , Oo0oO0 , oOo0Oo , Oo0oO0 ,
   # OOooOOo % o0oOOo0O0Ooo * O0 . Oo0Ooo % ooOoO0o * oO0o
 Oo0oo0oOO )
   if 19 - 19: OOooOOo - II111iiii
  return ( OO000 )
  if 80 - 80: Oo0Ooo % I1Ii111
  if 91 - 91: OoooooooOO - O0 . iII111i - II111iiii % O0 - OoooooooOO
  if 94 - 94: I1IiiI % I1ii11iIi11i
  if 30 - 30: iIii1I11I1II1 . OoOoOO00
  if 28 - 28: I1IiiI . O0 - oO0o
  if 56 - 56: ooOoO0o
  if 94 - 94: OoOoOO00
  if 12 - 12: I11i * OoooooooOO + ooOoO0o
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 16 - 16: IiII
if 100 - 100: OoO0O00 % Oo0Ooo - OoooooooOO
if 48 - 48: IiII / I11i * OoooooooOO
if 1 - 1: I1ii11iIi11i + I11i
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
  if 54 - 54: IiII * O0 * I1Ii111 + i1IIi - I11i . I11i
  if ( recurse == False ) : return
  if 39 - 39: I1Ii111
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  if 84 - 84: Ii1I
  if 92 - 92: I11i
  if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
  if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
  Oo00oooOO00o0 = lisp_get_default_route_next_hops ( )
  if ( Oo00oooOO00o0 == [ ] or len ( Oo00oooOO00o0 ) == 1 ) : return
  if 49 - 49: OoO0O00 + OoOoOO00 . i11iIiiIii + o0oOOo0O0Ooo * Oo0Ooo
  self . rloc_next_hop = Oo00oooOO00o0 [ 0 ]
  i1Ii = self
  for IIi1iiii1Ii in Oo00oooOO00o0 [ 1 : : ] :
   OoOo00ooo0O = lisp_rloc ( False )
   OoOo00ooo0O = copy . deepcopy ( self )
   OoOo00ooo0O . rloc_next_hop = IIi1iiii1Ii
   i1Ii . next_rloc = OoOo00ooo0O
   i1Ii = OoOo00ooo0O
   if 96 - 96: i11iIiiIii * OoooooooOO - OoO0O00 % IiII * OOooOOo
   if 28 - 28: oO0o . oO0o
   if 79 - 79: OOooOOo + i11iIiiIii + OOooOOo % I1IiiI % OoOoOO00
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 50 - 50: o0oOOo0O0Ooo / iIii1I11I1II1 * OoO0O00
  if 44 - 44: II111iiii / o0oOOo0O0Ooo
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
  if 79 - 79: ooOoO0o - O0
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 56 - 56: ooOoO0o
  if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 60 - 60: IiII % i11iIiiIii / OOooOOo
  if 43 - 43: i11iIiiIii * II111iiii + ooOoO0o - OoooooooOO * II111iiii / OoO0O00
  if 92 - 92: O0 - ooOoO0o % iII111i
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
  if 83 - 83: I1ii11iIi11i / OoOoOO00 % OoooooooOO
  if 54 - 54: I11i / I1IiiI * IiII - iII111i
 def print_rloc ( self , indent ) :
  i1 = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , i1 , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 37 - 37: i1IIi * I1Ii111 / I11i * II111iiii + OoooooooOO . OoO0O00
  if 22 - 22: OoOoOO00 + OoooooooOO - I1Ii111
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  oOo = self . rloc_name
  if ( cour ) : oOo = lisp_print_cour ( oOo )
  return ( 'rloc-name: {}' . format ( blue ( oOo , cour ) ) )
  if 82 - 82: Ii1I % I1Ii111 / ooOoO0o
  if 86 - 86: II111iiii - iIii1I11I1II1 + oO0o + I1IiiI
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  O00oo0o0o0oo = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . rloc_name = rloc_record . rloc_name
  if 29 - 29: Ii1I % OoooooooOO * II111iiii
  if 88 - 88: I1Ii111 + I11i + I1Ii111 % OoO0O00 / I1ii11iIi11i - I11i
  if 15 - 15: Oo0Ooo - i1IIi
  if 87 - 87: O0 . o0oOOo0O0Ooo % OOooOOo / I11i - I1Ii111 % i11iIiiIii
  OooOOoOO0OO = self . rloc
  if ( OooOOoOO0OO . is_null ( ) == False ) :
   iII1II1 = lisp_get_nat_info ( OooOOoOO0OO , self . rloc_name )
   if ( iII1II1 ) :
    O00oo0o0o0oo = iII1II1 . port
    iII1i111 = lisp_nat_state_info [ self . rloc_name ] [ 0 ]
    Oo0o = OooOOoOO0OO . print_address_no_iid ( )
    o00oO = red ( Oo0o , False )
    O00O0o00o0 = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
    if 84 - 84: i1IIi
    if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
    if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
    if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
    if 65 - 65: OoOoOO00
    if ( iII1II1 . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( o00oO , O00oo0o0o0oo , O00O0o00o0 ) )
     if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
     if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
     iII1II1 = None if ( iII1II1 == iII1i111 ) else iII1i111
     if ( iII1II1 and iII1II1 . timed_out ( ) ) :
      O00oo0o0o0oo = iII1II1 . port
      o00oO = red ( iII1II1 . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( o00oO , O00oo0o0o0oo ,
      # i1IIi + IiII
 O00O0o00o0 ) )
      iII1II1 = None
      if 48 - 48: i11iIiiIii * I11i
      if 28 - 28: OOooOOo
      if 82 - 82: II111iiii
      if 66 - 66: iII111i % I1Ii111 * oO0o
      if 81 - 81: i11iIiiIii - O0 . iIii1I11I1II1 - I11i + iIii1I11I1II1
      if 50 - 50: Oo0Ooo . OoO0O00 + i11iIiiIii / i11iIiiIii
      if 27 - 27: OoOoOO00 - OoOoOO00 % II111iiii + i1IIi + I1IiiI
    if ( iII1II1 ) :
     if ( iII1II1 . address != Oo0o ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( o00oO , red ( iII1II1 . address , False ) ) )
      if 75 - 75: OoooooooOO . I11i - OoOoOO00
      self . rloc . store_address ( iII1II1 . address )
      if 93 - 93: OoOoOO00 . I1Ii111 % I1ii11iIi11i
     o00oO = red ( iII1II1 . address , False )
     O00oo0o0o0oo = iII1II1 . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( o00oO , O00oo0o0o0oo , O00O0o00o0 ) )
     if 58 - 58: OoooooooOO . i1IIi . Oo0Ooo - o0oOOo0O0Ooo / oO0o * I1Ii111
     self . store_translated_rloc ( OooOOoOO0OO , O00oo0o0o0oo )
     if 6 - 6: oO0o - OoO0O00
     if 44 - 44: Oo0Ooo + I1ii11iIi11i % Oo0Ooo / I11i
     if 57 - 57: Oo0Ooo + Ii1I * OoooooooOO
     if 30 - 30: O0
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 70 - 70: oO0o
  if 89 - 89: O0
  if 3 - 3: iII111i - O0 / I11i
  if 46 - 46: I1IiiI . OoooooooOO / iIii1I11I1II1 - ooOoO0o * OOooOOo
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for IIIi11i1 in self . rle . rle_nodes :
    oOo = IIIi11i1 . rloc_name
    iII1II1 = lisp_get_nat_info ( IIIi11i1 . address , oOo )
    if ( iII1II1 == None ) : continue
    if 55 - 55: o0oOOo0O0Ooo + iIii1I11I1II1 / I11i
    O00oo0o0o0oo = iII1II1 . port
    i1IiOo0OO0o = oOo
    if ( i1IiOo0OO0o ) : i1IiOo0OO0o = blue ( oOo , False )
    if 97 - 97: i11iIiiIii
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( O00oo0o0o0oo ,
    # OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
 IIIi11i1 . address . print_address_no_iid ( ) , i1IiOo0OO0o ) )
    IIIi11i1 . translated_port = O00oo0o0o0oo
    if 60 - 60: OOooOOo * I1Ii111
    if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
    if 97 - 97: II111iiii * o0oOOo0O0Ooo
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) : self . state = LISP_RLOC_UP_STATE
  if 13 - 13: o0oOOo0O0Ooo . II111iiii
  if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
  if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
  if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
  Iii1iI = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 51 - 51: I1ii11iIi11i
  if ( rloc_record . keys != None and Iii1iI ) :
   III11II111 = rloc_record . keys [ 1 ]
   if ( III11II111 != None ) :
    Oo0o = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( O00oo0o0o0oo )
    if 95 - 95: I1IiiI / iII111i + i1IIi
    III11II111 . add_key_by_rloc ( Oo0o , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( Oo0o , False ) ) )
    if 31 - 31: OoOoOO00
    if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
    if 43 - 43: II111iiii - OoooooooOO
  return ( O00oo0o0o0oo )
  if 11 - 11: I1IiiI
  if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if 64 - 64: OoO0O00 - OoO0O00
  if 93 - 93: Oo0Ooo . O0
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 75 - 75: iII111i * II111iiii - I1IiiI
  if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
  return ( True )
  if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
  if 46 - 46: I1Ii111
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
  if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
  if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
 def print_state_change ( self , new_state ) :
  O0iIIiii1ii1III = self . print_state ( )
  Oo0OOOOOOO0oo = "{} -> {}" . format ( O0iIIiii1ii1III , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   Oo0OOOOOOO0oo = bold ( Oo0OOOOOOO0oo , False )
   if 91 - 91: OoOoOO00 * I1IiiI - Oo0Ooo
  return ( Oo0OOOOOOO0oo )
  if 36 - 36: O0 - IiII % iII111i
  if 93 - 93: OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + oO0o % OOooOOo
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 9 - 9: IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
  if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
 def print_recent_rloc_probe_rtts ( self ) :
  iiIIiIiiII = str ( self . recent_rloc_probe_rtts )
  iiIIiIiiII = iiIIiIiiII . replace ( "-1" , "?" )
  return ( iiIIiIiiII )
  if 23 - 23: II111iiii / iII111i
  if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
 def compute_rloc_probe_rtt ( self ) :
  i1Ii = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  oO0iII1IIii1iii = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ i1Ii ] + oO0iII1IIii1iii [ 0 : - 1 ]
  if 98 - 98: II111iiii % I1Ii111
  if 64 - 64: I11i
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 26 - 26: ooOoO0o * I11i + OOooOOo * i1IIi
  if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
 def print_recent_rloc_probe_hops ( self ) :
  Ooo000o0o = str ( self . recent_rloc_probe_hops )
  return ( Ooo000o0o )
  if 31 - 31: i11iIiiIii % IiII + IiII / oO0o
  if 53 - 53: IiII
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 52 - 52: I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
  if ( from_ttl < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   OoOOOOOoo0 = "!"
  else :
   OoOOOOOoo0 = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 13 - 13: O0
   if 87 - 87: Ii1I + o0oOOo0O0Ooo + OoooooooOO . Ii1I
  i1Ii = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + OoOOOOOoo0
  oO0iII1IIii1iii = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ i1Ii ] + oO0iII1IIii1iii [ 0 : - 1 ]
  if 73 - 73: o0oOOo0O0Ooo + OoooooooOO - I1Ii111 . iIii1I11I1II1
  if 25 - 25: OoooooooOO % I1ii11iIi11i % Oo0Ooo % i11iIiiIii
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  ii1i1iiI1 = lisp_decode_telemetry ( json_telemetry )
  if 19 - 19: II111iiii / OoO0O00 * II111iiii + I1IiiI
  II1I11 = round ( float ( ii1i1iiI1 [ "etr-in" ] ) - float ( ii1i1iiI1 [ "itr-out" ] ) , 3 )
  i11III = round ( float ( ii1i1iiI1 [ "itr-in" ] ) - float ( ii1i1iiI1 [ "etr-out" ] ) , 3 )
  if 96 - 96: OoO0O00 - ooOoO0o * Ii1I
  i1Ii = self . rloc_probe_latency
  self . rloc_probe_latency = str ( II1I11 ) + "/" + str ( i11III )
  oO0iII1IIii1iii = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ i1Ii ] + oO0iII1IIii1iii [ 0 : - 1 ]
  if 34 - 34: OoO0O00 . Oo0Ooo % Ii1I . IiII + OoOoOO00
  if 10 - 10: OoooooooOO * iII111i * ooOoO0o . Ii1I % I1Ii111 / I1ii11iIi11i
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 71 - 71: Ii1I + IiII
  if 10 - 10: II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % iII111i
 def print_recent_rloc_probe_latencies ( self ) :
  Ii111 = str ( self . recent_rloc_probe_latencies )
  return ( Ii111 )
  if 40 - 40: oO0o
  if 4 - 4: o0oOOo0O0Ooo + I1IiiI - O0 - iIii1I11I1II1
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  OooOOoOO0OO = self
  while ( True ) :
   if ( OooOOoOO0OO . last_rloc_probe_nonce == nonce ) : break
   OooOOoOO0OO = OooOOoOO0OO . next_rloc
   if ( OooOOoOO0OO == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 56 - 56: OOooOOo * o0oOOo0O0Ooo - O0
    return
    if 45 - 45: OOooOOo - OoO0O00
    if 49 - 49: OoOoOO00 / o0oOOo0O0Ooo % OoO0O00
    if 50 - 50: iIii1I11I1II1 - OoooooooOO + I1ii11iIi11i / Oo0Ooo * OOooOOo
    if 37 - 37: O0 % I1Ii111 * OOooOOo / OOooOOo
    if 95 - 95: I1ii11iIi11i % o0oOOo0O0Ooo . oO0o
    if 9 - 9: OoOoOO00 % OoOoOO00 * ooOoO0o / I1IiiI - OOooOOo
  OooOOoOO0OO . last_rloc_probe_reply = ts
  OooOOoOO0OO . compute_rloc_probe_rtt ( )
  oOO0Oo = OooOOoOO0OO . print_state_change ( "up" )
  if ( OooOOoOO0OO . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( OooOOoOO0OO . rloc , True )
   OooOOoOO0OO . state = LISP_RLOC_UP_STATE
   OooOOoOO0OO . last_state_change = lisp_get_timestamp ( )
   O0oo0OOo00o0o = lisp_map_cache . lookup_cache ( eid , True )
   if ( O0oo0OOo00o0o ) : lisp_write_ipc_map_cache ( True , O0oo0OOo00o0o )
   if 3 - 3: ooOoO0o * Ii1I
   if 29 - 29: OoooooooOO + OOooOOo
   if 68 - 68: O0 + IiII / iII111i - OoOoOO00
   if 5 - 5: I1IiiI * OoooooooOO - II111iiii
   if 64 - 64: i1IIi
  OooOOoOO0OO . store_rloc_probe_hops ( hc , ttl )
  if 77 - 77: OOooOOo - i1IIi / II111iiii . I1Ii111 + O0
  if 1 - 1: OoooooooOO % iIii1I11I1II1 * I1ii11iIi11i
  if 17 - 17: Ii1I * i1IIi % OoO0O00
  if 12 - 12: I1ii11iIi11i
  if ( jt ) : OooOOoOO0OO . store_rloc_probe_latencies ( jt )
  if 86 - 86: iIii1I11I1II1 % iII111i
  iiIii11Ii = bold ( "RLOC-probe reply" , False )
  Oo0o = OooOOoOO0OO . rloc . print_address_no_iid ( )
  oOoOo0 = bold ( str ( OooOOoOO0OO . print_rloc_probe_rtt ( ) ) , False )
  o00oo = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
  IIi1iiii1Ii = ""
  if ( OooOOoOO0OO . rloc_next_hop != None ) :
   iiIi , OooIIIii = OooOOoOO0OO . rloc_next_hop
   IIi1iiii1Ii = ", nh {}({})" . format ( OooIIIii , iiIi )
   if 45 - 45: I1ii11iIi11i . I1Ii111 . i1IIi * OOooOOo
   if 53 - 53: Ii1I . i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
  I1iii11III = bold ( OooOOoOO0OO . print_rloc_probe_latency ( ) , False )
  I1iii11III = ", latency {}" . format ( I1iii11III ) if jt else ""
  if 87 - 87: I1Ii111 % i11iIiiIii + O0
  I1i = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( iiIii11Ii , red ( Oo0o , False ) , o00oo , I1i ,
  # II111iiii - I1ii11iIi11i . ooOoO0o
 oOO0Oo , oOoOo0 , IIi1iiii1Ii , str ( hc ) + "/" + str ( ttl ) , I1iii11III ) )
  if 35 - 35: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / iIii1I11I1II1 - o0oOOo0O0Ooo
  if ( OooOOoOO0OO . rloc_next_hop == None ) : return
  if 24 - 24: OoOoOO00 . I1IiiI
  if 55 - 55: i11iIiiIii / ooOoO0o / Ii1I + Ii1I
  if 14 - 14: IiII + I11i - o0oOOo0O0Ooo
  if 100 - 100: ooOoO0o
  OooOOoOO0OO = None
  IiIi1iiI1i = None
  while ( True ) :
   OooOOoOO0OO = self if OooOOoOO0OO == None else OooOOoOO0OO . next_rloc
   if ( OooOOoOO0OO == None ) : break
   if ( OooOOoOO0OO . up_state ( ) == False ) : continue
   if ( OooOOoOO0OO . rloc_probe_rtt == - 1 ) : continue
   if 82 - 82: OoO0O00
   if ( IiIi1iiI1i == None ) : IiIi1iiI1i = OooOOoOO0OO
   if ( OooOOoOO0OO . rloc_probe_rtt < IiIi1iiI1i . rloc_probe_rtt ) : IiIi1iiI1i = OooOOoOO0OO
   if 96 - 96: OOooOOo
   if 85 - 85: iIii1I11I1II1 + iII111i + iII111i - ooOoO0o * OoO0O00
  if ( IiIi1iiI1i != None ) :
   iiIi , OooIIIii = IiIi1iiI1i . rloc_next_hop
   IIi1iiii1Ii = bold ( "nh {}({})" . format ( OooIIIii , iiIi ) , False )
   lprint ( "    Install host-route via best {}" . format ( IIi1iiii1Ii ) )
   lisp_install_host_route ( Oo0o , None , False )
   lisp_install_host_route ( Oo0o , OooIIIii , True )
   if 80 - 80: i11iIiiIii / OOooOOo . OoooooooOO % I11i - iII111i * iIii1I11I1II1
   if 70 - 70: Oo0Ooo
   if 75 - 75: I1Ii111
 def add_to_rloc_probe_list ( self , eid , group ) :
  Oo0o = self . rloc . print_address_no_iid ( )
  O00oo0o0o0oo = self . translated_port
  if ( O00oo0o0o0oo != 0 ) : Oo0o += ":" + str ( O00oo0o0o0oo )
  if 40 - 40: OoO0O00 % Oo0Ooo / OoooooooOO / i11iIiiIii
  if ( Oo0o not in lisp_rloc_probe_list ) :
   lisp_rloc_probe_list [ Oo0o ] = [ ]
   if 5 - 5: O0 % i11iIiiIii
   if 60 - 60: I1ii11iIi11i / I11i
  if ( group . is_null ( ) ) : group . instance_id = 0
  for I1I1iIiiiiII11 , I1i , o0O0Ooo in lisp_rloc_probe_list [ Oo0o ] :
   if ( I1i . is_exact_match ( eid ) and o0O0Ooo . is_exact_match ( group ) ) :
    if ( I1I1iIiiiiII11 == self ) :
     if ( lisp_rloc_probe_list [ Oo0o ] == [ ] ) :
      lisp_rloc_probe_list . pop ( Oo0o )
      if 100 - 100: I1IiiI
     return
     if 44 - 44: iIii1I11I1II1 + Oo0Ooo - I1Ii111 . OoooooooOO
    lisp_rloc_probe_list [ Oo0o ] . remove ( [ I1I1iIiiiiII11 , I1i , o0O0Ooo ] )
    break
    if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
    if 2 - 2: I11i * I1ii11iIi11i + O0
  lisp_rloc_probe_list [ Oo0o ] . append ( [ self , eid , group ] )
  if 44 - 44: iIii1I11I1II1 / II111iiii - ooOoO0o
  if 10 - 10: OOooOOo
  if 78 - 78: OOooOOo * I1ii11iIi11i % i11iIiiIii % o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO
  if 12 - 12: iIii1I11I1II1 % OoO0O00 + OOooOOo * iIii1I11I1II1 - iIii1I11I1II1
  if 70 - 70: OoO0O00 % i11iIiiIii * IiII . I11i * Oo0Ooo
  OooOOoOO0OO = lisp_rloc_probe_list [ Oo0o ] [ 0 ] [ 0 ]
  if ( OooOOoOO0OO . state == LISP_RLOC_UNREACH_STATE ) :
   self . state = LISP_RLOC_UNREACH_STATE
   self . last_state_change = lisp_get_timestamp ( )
   if 17 - 17: i1IIi
   if 29 - 29: OOooOOo % OoO0O00 + oO0o + o0oOOo0O0Ooo . iII111i
   if 14 - 14: i1IIi + OoOoOO00 * oO0o - II111iiii + IiII + OoOoOO00
 def delete_from_rloc_probe_list ( self , eid , group ) :
  Oo0o = self . rloc . print_address_no_iid ( )
  O00oo0o0o0oo = self . translated_port
  if ( O00oo0o0o0oo != 0 ) : Oo0o += ":" + str ( O00oo0o0o0oo )
  if ( Oo0o not in lisp_rloc_probe_list ) : return
  if 42 - 42: Oo0Ooo + iII111i * ooOoO0o
  oo00000ooo = [ ]
  for iIiiI11II11i in lisp_rloc_probe_list [ Oo0o ] :
   if ( iIiiI11II11i [ 0 ] != self ) : continue
   if ( iIiiI11II11i [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( iIiiI11II11i [ 2 ] . is_exact_match ( group ) == False ) : continue
   oo00000ooo = iIiiI11II11i
   break
   if 12 - 12: Oo0Ooo / IiII % ooOoO0o / iIii1I11I1II1 % O0 / i11iIiiIii
  if ( oo00000ooo == [ ] ) : return
  if 58 - 58: i11iIiiIii * O0
  try :
   lisp_rloc_probe_list [ Oo0o ] . remove ( oo00000ooo )
   if ( lisp_rloc_probe_list [ Oo0o ] == [ ] ) :
    lisp_rloc_probe_list . pop ( Oo0o )
    if 85 - 85: oO0o
  except :
   return
   if 57 - 57: II111iiii . I1IiiI - OOooOOo
   if 54 - 54: i1IIi + OoOoOO00
   if 76 - 76: OoOoOO00
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  OoiIIIiIi1I1i = ""
  OooOOoOO0OO = self
  while ( True ) :
   OOO = OooOOoOO0OO . last_rloc_probe
   if ( OOO == None ) : OOO = 0
   II11i = OooOOoOO0OO . last_rloc_probe_reply
   if ( II11i == None ) : II11i = 0
   oOoOo0 = OooOOoOO0OO . print_rloc_probe_rtt ( )
   I1iiIi111I = space ( 4 )
   if 97 - 97: I1Ii111
   if ( OooOOoOO0OO . rloc_next_hop == None ) :
    OoiIIIiIi1I1i += "RLOC-Probing:\n"
   else :
    iiIi , OooIIIii = OooOOoOO0OO . rloc_next_hop
    OoiIIIiIi1I1i += "RLOC-Probing for nh {}({}):\n" . format ( OooIIIii , iiIi )
    if 98 - 98: I11i
    if 61 - 61: iIii1I11I1II1 * iII111i
   OoiIIIiIi1I1i += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( I1iiIi111I , lisp_print_elapsed ( OOO ) ,
   # I1ii11iIi11i - OoooooooOO . iIii1I11I1II1 % Ii1I
 I1iiIi111I , lisp_print_elapsed ( II11i ) , oOoOo0 )
   if 84 - 84: Oo0Ooo * I1Ii111 - Oo0Ooo
   if ( trailing_linefeed ) : OoiIIIiIi1I1i += "\n"
   if 78 - 78: OOooOOo . Oo0Ooo . iII111i / i11iIiiIii + iIii1I11I1II1 - OoOoOO00
   OooOOoOO0OO = OooOOoOO0OO . next_rloc
   if ( OooOOoOO0OO == None ) : break
   OoiIIIiIi1I1i += "\n"
   if 1 - 1: i11iIiiIii
  return ( OoiIIIiIi1I1i )
  if 25 - 25: OoooooooOO / II111iiii . OOooOOo * OoOoOO00 - OoooooooOO
  if 8 - 8: iII111i . iIii1I11I1II1 * O0
 def get_encap_keys ( self ) :
  O00oo0o0o0oo = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 87 - 87: OoO0O00 * OoooooooOO + OoOoOO00 . OoooooooOO + o0oOOo0O0Ooo + Ii1I
  Oo0o = self . rloc . print_address_no_iid ( ) + ":" + O00oo0o0o0oo
  if 26 - 26: i1IIi
  try :
   O0o0O0 = lisp_crypto_keys_by_rloc_encap [ Oo0o ]
   if ( O0o0O0 [ 1 ] ) : return ( O0o0O0 [ 1 ] . encrypt_key , O0o0O0 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 33 - 33: OoOoOO00 + OOooOOo . i1IIi . IiII
   if 78 - 78: OoooooooOO * I11i / OOooOOo + oO0o . I1Ii111 * iII111i
   if 98 - 98: i1IIi
 def rloc_recent_rekey ( self ) :
  O00oo0o0o0oo = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 28 - 28: Oo0Ooo . I1Ii111 . iIii1I11I1II1 + I1IiiI . II111iiii * I1ii11iIi11i
  Oo0o = self . rloc . print_address_no_iid ( ) + ":" + O00oo0o0o0oo
  if 26 - 26: i1IIi / i11iIiiIii * II111iiii
  try :
   III11II111 = lisp_crypto_keys_by_rloc_encap [ Oo0o ] [ 1 ]
   if ( III11II111 == None ) : return ( False )
   if ( III11II111 . last_rekey == None ) : return ( True )
   return ( time . time ( ) - III11II111 . last_rekey < 1 )
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
  o0o0o = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 8 - 8: OoooooooOO
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , o0o0o , i1 ,
 len ( self . rloc_set ) ) )
  for OooOOoOO0OO in self . rloc_set : OooOOoOO0OO . print_rloc ( rloc_indent )
  if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
  if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
  if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
 def print_ttl ( self ) :
  O0O00O = self . map_cache_ttl
  if ( O0O00O == None ) : return ( "forever" )
  if 76 - 76: OOooOOo % iII111i
  if ( O0O00O >= 3600 ) :
   if ( ( O0O00O % 3600 ) == 0 ) :
    O0O00O = str ( old_div ( O0O00O , 3600 ) ) + " hours"
   else :
    O0O00O = str ( O0O00O * 60 ) + " mins"
    if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
  elif ( O0O00O >= 60 ) :
   if ( ( O0O00O % 60 ) == 0 ) :
    O0O00O = str ( old_div ( O0O00O , 60 ) ) + " mins"
   else :
    O0O00O = str ( O0O00O ) + " secs"
    if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
  else :
   O0O00O = str ( O0O00O ) + " secs"
   if 81 - 81: iII111i % OOooOOo * oO0o
  return ( O0O00O )
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
  Ii1i1 = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  OO000OoOOOo = ( Ii1i1 in [ 0 , 1 , 2 ] )
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
  Ii1i1 = time . time ( ) - self . last_refresh_time
  if ( Ii1i1 >= self . map_cache_ttl ) : return ( True )
  if 67 - 67: Oo0Ooo
  if 52 - 52: I1IiiI % I1Ii111 - i1IIi . o0oOOo0O0Ooo % I1ii11iIi11i
  if 34 - 34: o0oOOo0O0Ooo / OoOoOO00
  if 74 - 74: IiII + i1IIi . II111iiii
  if 1 - 1: Ii1I - o0oOOo0O0Ooo / i11iIiiIii
  iI1o00Ooo = self . map_cache_ttl - ( old_div ( self . map_cache_ttl , 10 ) )
  if ( Ii1i1 >= iI1o00Ooo ) : return ( True )
  return ( False )
  if 67 - 67: OOooOOo % OOooOOo
  if 8 - 8: Ii1I / ooOoO0o
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  Ii1i1 = time . time ( ) - self . stats . last_increment
  return ( Ii1i1 <= 60 )
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
  for OooOOoOO0OO in self . best_rloc_set :
   OooOOoOO0OO . delete_from_rloc_probe_list ( self . eid , self . group )
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
  for OooOOoOO0OO in self . rloc_set :
   if ( OooOOoOO0OO . up_state ( ) ) : OO000OOOOOoO = min ( OooOOoOO0OO . priority , OO000OOOOOoO )
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
  for OooOOoOO0OO in self . rloc_set :
   if ( OooOOoOO0OO . priority <= OO000OOOOOoO ) :
    if ( OooOOoOO0OO . unreach_state ( ) and OooOOoOO0OO . last_rloc_probe == None ) :
     OooOOoOO0OO . last_rloc_probe = lisp_get_timestamp ( )
     if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
    self . best_rloc_set . append ( OooOOoOO0OO )
    if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
    if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
    if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
    if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
    if 35 - 35: II111iiii
    if 28 - 28: I1Ii111 + IiII + I1ii11iIi11i . Ii1I
    if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
    if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
  for OooOOoOO0OO in oo0oooOooO :
   if ( OooOOoOO0OO . priority < OO000OOOOOoO ) : continue
   OooOOoOO0OO . delete_from_rloc_probe_list ( self . eid , self . group )
   if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
  for OooOOoOO0OO in self . best_rloc_set :
   if ( OooOOoOO0OO . rloc . is_null ( ) ) : continue
   OooOOoOO0OO . add_to_rloc_probe_list ( self . eid , self . group )
   if 1 - 1: ooOoO0o + iII111i % i11iIiiIii / OoOoOO00
   if 98 - 98: IiII
   if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  OO0Oo00OO0oo = lisp_packet . packet
  ooO0oOoO0O0 = lisp_packet . inner_version
  iI = len ( self . best_rloc_set )
  if ( iI == 0 ) :
   self . stats . increment ( len ( OO0Oo00OO0oo ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 53 - 53: oO0o - Ii1I
   if 24 - 24: oO0o
  O00o = 4 if lisp_load_split_pings else 0
  iiIIII11iIii = lisp_packet . hash_ports ( )
  if ( ooO0oOoO0O0 == 4 ) :
   for OoOOoO0oOo in range ( 8 + O00o ) :
    iiIIII11iIii = iiIIII11iIii ^ struct . unpack ( "B" , OO0Oo00OO0oo [ OoOOoO0oOo + 12 : OoOOoO0oOo + 13 ] ) [ 0 ]
    if 10 - 10: II111iiii * Ii1I % IiII + I11i
  elif ( ooO0oOoO0O0 == 6 ) :
   for OoOOoO0oOo in range ( 0 , 32 + O00o , 4 ) :
    iiIIII11iIii = iiIIII11iIii ^ struct . unpack ( "I" , OO0Oo00OO0oo [ OoOOoO0oOo + 8 : OoOOoO0oOo + 12 ] ) [ 0 ]
    if 29 - 29: IiII / Ii1I / I1Ii111
   iiIIII11iIii = ( iiIIII11iIii >> 16 ) + ( iiIIII11iIii & 0xffff )
   iiIIII11iIii = ( iiIIII11iIii >> 8 ) + ( iiIIII11iIii & 0xff )
  else :
   for OoOOoO0oOo in range ( 0 , 12 + O00o , 4 ) :
    iiIIII11iIii = iiIIII11iIii ^ struct . unpack ( "I" , OO0Oo00OO0oo [ OoOOoO0oOo : OoOOoO0oOo + 4 ] ) [ 0 ]
    if 30 - 30: i1IIi + OOooOOo + Oo0Ooo % iII111i % O0 + i1IIi
    if 45 - 45: ooOoO0o
    if 89 - 89: iIii1I11I1II1 . I1Ii111
  if ( lisp_data_plane_logging ) :
   II1I1I = [ ]
   for I1I1iIiiiiII11 in self . best_rloc_set :
    if ( I1I1iIiiiiII11 . rloc . is_null ( ) ) : continue
    II1I1I . append ( [ I1I1iIiiiiII11 . rloc . print_address_no_iid ( ) , I1I1iIiiiiII11 . print_state ( ) ] )
    if 33 - 33: iIii1I11I1II1 . I1ii11iIi11i - O0 - IiII
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( iiIIII11iIii ) , iiIIII11iIii % iI , red ( str ( II1I1I ) , False ) ) )
   if 51 - 51: OoooooooOO . I1IiiI . i11iIiiIii
   if 76 - 76: OoOoOO00 + iII111i . ooOoO0o + OoO0O00 + I1IiiI / IiII
   if 70 - 70: O0 * i11iIiiIii / Ii1I - II111iiii / O0
   if 30 - 30: IiII . I1ii11iIi11i % ooOoO0o
   if 15 - 15: oO0o
   if 86 - 86: O0
  OooOOoOO0OO = self . best_rloc_set [ iiIIII11iIii % iI ]
  if 13 - 13: I1ii11iIi11i . IiII - I11i
  if 81 - 81: i11iIiiIii
  if 7 - 7: IiII - OoOoOO00 * i1IIi
  if 14 - 14: I1ii11iIi11i . OoO0O00
  if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
  oo000O0o = lisp_get_echo_nonce ( OooOOoOO0OO . rloc , None )
  if ( oo000O0o ) :
   oo000O0o . change_state ( OooOOoOO0OO )
   if ( OooOOoOO0OO . no_echoed_nonce_state ( ) ) :
    oo000O0o . request_nonce_sent = None
    if 25 - 25: IiII % I1IiiI / O0 % OOooOOo - OoooooooOO
    if 29 - 29: O0 + iII111i
    if 4 - 4: I11i * I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
    if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
    if 76 - 76: OoooooooOO - O0
    if 17 - 17: Oo0Ooo % I1Ii111 . oO0o - O0
  if ( OooOOoOO0OO . up_state ( ) == False ) :
   iiiIIi1Iii = iiIIII11iIii % iI
   OOOooo0OooOoO = ( iiiIIi1Iii + 1 ) % iI
   while ( OOOooo0OooOoO != iiiIIi1Iii ) :
    OooOOoOO0OO = self . best_rloc_set [ OOOooo0OooOoO ]
    if ( OooOOoOO0OO . up_state ( ) ) : break
    OOOooo0OooOoO = ( OOOooo0OooOoO + 1 ) % iI
    if 39 - 39: iII111i - I1ii11iIi11i % ooOoO0o - OoOoOO00 + OoOoOO00
   if ( OOOooo0OooOoO == iiiIIi1Iii ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 97 - 97: I11i * I1Ii111 * oO0o
    if 3 - 3: iIii1I11I1II1 / ooOoO0o + ooOoO0o + I11i
    if 20 - 20: OOooOOo - i1IIi / i11iIiiIii
    if 60 - 60: I11i * I11i + Oo0Ooo . IiII / iII111i % OoooooooOO
    if 35 - 35: O0 . Oo0Ooo / Oo0Ooo / Ii1I / i1IIi * I11i
    if 93 - 93: O0 + IiII
  OooOOoOO0OO . stats . increment ( len ( OO0Oo00OO0oo ) )
  if 91 - 91: iIii1I11I1II1
  if 66 - 66: i1IIi . ooOoO0o
  if 84 - 84: O0 % ooOoO0o / I1Ii111
  if 75 - 75: I11i - iII111i . O0
  if ( OooOOoOO0OO . rle_name and OooOOoOO0OO . rle == None ) :
   if ( OooOOoOO0OO . rle_name in lisp_rle_list ) :
    OooOOoOO0OO . rle = lisp_rle_list [ OooOOoOO0OO . rle_name ]
    if 52 - 52: I1ii11iIi11i
    if 22 - 22: I1ii11iIi11i - i1IIi / OOooOOo . o0oOOo0O0Ooo . oO0o
  if ( OooOOoOO0OO . rle ) : return ( [ None , None , None , None , OooOOoOO0OO . rle , None ] )
  if 9 - 9: ooOoO0o - I1Ii111 + IiII . iII111i
  if 52 - 52: I1Ii111 + oO0o % II111iiii - i1IIi
  if 32 - 32: I1Ii111 % ooOoO0o + I1Ii111 / I1ii11iIi11i - o0oOOo0O0Ooo + ooOoO0o
  if 46 - 46: OoO0O00 % OoO0O00 . O0 + II111iiii
  if ( OooOOoOO0OO . elp and OooOOoOO0OO . elp . use_elp_node ) :
   return ( [ OooOOoOO0OO . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 42 - 42: OOooOOo * I1Ii111
   if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
   if 91 - 91: iII111i . OoooooooOO
   if 90 - 90: i11iIiiIii - I1IiiI
   if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
  oOO0o00O = None if ( OooOOoOO0OO . rloc . is_null ( ) ) else OooOOoOO0OO . rloc
  O00oo0o0o0oo = OooOOoOO0OO . translated_port
  oOoO0OooO0O = self . action if ( oOO0o00O == None ) else None
  if 26 - 26: i1IIi / iII111i + iII111i
  if 66 - 66: i1IIi + I1IiiI
  if 45 - 45: I1Ii111 . iII111i + OoO0O00 - O0
  if 71 - 71: Oo0Ooo + OOooOOo
  if 94 - 94: OOooOOo
  OOO0O0O = None
  if ( oo000O0o and oo000O0o . request_nonce_timeout ( ) == False ) :
   OOO0O0O = oo000O0o . get_request_or_echo_nonce ( ipc_socket , oOO0o00O )
   if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
   if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
   if 31 - 31: I11i . o0oOOo0O0Ooo
   if 82 - 82: I11i - Oo0Ooo
   if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
  return ( [ oOO0o00O , O00oo0o0o0oo , OOO0O0O , oOoO0OooO0O , None , OooOOoOO0OO ] )
  if 80 - 80: oO0o % I1ii11iIi11i * I1Ii111 + i1IIi
  if 79 - 79: oO0o + IiII
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 4 - 4: iII111i + OoooooooOO / I1Ii111
  if 57 - 57: I1IiiI . iIii1I11I1II1 % iII111i * iII111i / I1Ii111
  if 30 - 30: O0 / I11i % OoOoOO00 * I1Ii111 / O0 % ooOoO0o
  if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
  if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
  for II1 in self . rloc_set :
   for OooOOoOO0OO in rloc_address_set :
    if ( OooOOoOO0OO . is_exact_match ( II1 . rloc ) == False ) : continue
    OooOOoOO0OO = None
    break
    if 97 - 97: i11iIiiIii / O0 % OoO0O00
   if ( OooOOoOO0OO == rloc_address_set [ - 1 ] ) : return ( False )
   if 88 - 88: i1IIi . I1IiiI
  return ( True )
  if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
  if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
 def get_rloc ( self , rloc ) :
  for II1 in self . rloc_set :
   I1I1iIiiiiII11 = II1 . rloc
   if ( rloc . is_exact_match ( I1I1iIiiiiII11 ) ) : return ( II1 )
   if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
  return ( None )
  if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
  if 84 - 84: I1IiiI + OOooOOo
 def get_rloc_by_interface ( self , interface ) :
  for II1 in self . rloc_set :
   if ( II1 . interface == interface ) : return ( II1 )
   if 80 - 80: OOooOOo / OoOoOO00
  return ( None )
  if 93 - 93: OOooOOo
  if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   iIiI1ii = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( iIiI1ii == None ) :
    iIiI1ii = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , iIiI1ii )
    if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
   iIiI1ii . add_source_entry ( self )
   if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
   if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
   if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   O0oo0OOo00o0o = lisp_map_cache . lookup_cache ( self . group , True )
   if ( O0oo0OOo00o0o == None ) :
    O0oo0OOo00o0o = lisp_mapping ( self . group , self . group , [ ] )
    O0oo0OOo00o0o . eid . copy_address ( self . group )
    O0oo0OOo00o0o . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , O0oo0OOo00o0o )
    if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( O0oo0OOo00o0o . group )
   O0oo0OOo00o0o . add_source_entry ( self )
   if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 91 - 91: II111iiii * o0oOOo0O0Ooo
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    Ii1I1I11I11 = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( Ii1I1I11I11 ) )
    if 84 - 84: oO0o
  else :
   O0oo0OOo00o0o = lisp_map_cache . lookup_cache ( self . group , True )
   if ( O0oo0OOo00o0o == None ) : return
   if 74 - 74: I1IiiI
   I1i11111Iiii = O0oo0OOo00o0o . lookup_source_cache ( self . eid , True )
   if ( I1i11111Iiii == None ) : return
   if 13 - 13: i1IIi % i1IIi % ooOoO0o + IiII * II111iiii * OOooOOo
   O0oo0OOo00o0o . source_cache . delete_cache ( self . eid )
   if ( O0oo0OOo00o0o . source_cache . cache_size ( ) == 0 ) :
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
  i1oO00O = "," + str ( self . secondary_iid )
  return ( prefix . replace ( i1oO00O , i1oO00O + "*" ) )
  if 28 - 28: iII111i
  if 97 - 97: iIii1I11I1II1
 def increment_decap_stats ( self , packet ) :
  O00oo0o0o0oo = packet . udp_dport
  if ( O00oo0o0o0oo == LISP_DATA_PORT ) :
   OooOOoOO0OO = self . get_rloc ( packet . outer_dest )
  else :
   if 18 - 18: OOooOOo
   if 87 - 87: O0 - i1IIi . I11i / Ii1I % iIii1I11I1II1
   if 57 - 57: I11i . IiII / iIii1I11I1II1 - ooOoO0o
   if 50 - 50: O0 / II111iiii
   for OooOOoOO0OO in self . rloc_set :
    if ( OooOOoOO0OO . translated_port != 0 ) : break
    if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
    if 15 - 15: I1IiiI
  if ( OooOOoOO0OO != None ) : OooOOoOO0OO . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 48 - 48: Ii1I * IiII % O0 - II111iiii
  if 66 - 66: iIii1I11I1II1 / OOooOOo
 def rtrs_in_rloc_set ( self ) :
  for OooOOoOO0OO in self . rloc_set :
   if ( OooOOoOO0OO . is_rtr ( ) ) : return ( True )
   if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
  return ( False )
  if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
  if 67 - 67: I1Ii111
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
  if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
  if 46 - 46: I11i - ooOoO0o . I1IiiI
class lisp_dynamic_eid ( object ) :
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
class lisp_group_mapping ( object ) :
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
 i1oO00O = group_mapping . group_prefix . instance_id
 ooOoO00 = group_mapping . group_prefix . mask_len
 o0o0o = lisp_address ( LISP_AFI_IPV4 , group_str , 32 , i1oO00O )
 if ( o0o0o . is_more_specific ( group_mapping . group_prefix ) ) : return ( ooOoO00 )
 return ( - 1 )
 if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
 if 92 - 92: I11i
 if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
 if 98 - 98: iII111i % IiII + OoO0O00
 if 23 - 23: OOooOOo
 if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
 if 99 - 99: II111iiii + O0
def lisp_lookup_group ( group ) :
 II1I1I = None
 for O0O0oO00Oo00 in list ( lisp_group_mapping_list . values ( ) ) :
  ooOoO00 = lisp_is_group_more_specific ( group , O0O0oO00Oo00 )
  if ( ooOoO00 == - 1 ) : continue
  if ( II1I1I == None or ooOoO00 > II1I1I . group_prefix . mask_len ) : II1I1I = O0O0oO00Oo00
  if 27 - 27: Oo0Ooo
 return ( II1I1I )
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
  if 65 - 65: II111iiii / I1Ii111 + I1IiiI - OoooooooOO + ooOoO0o - I1ii11iIi11i
  if 29 - 29: OoOoOO00 / OOooOOo / OoO0O00
  if 95 - 95: ooOoO0o
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
   ii1i = self . print_flags ( False )
   ii1i = ii1i . split ( "-" )
   OoiIIIiIi1I1i = ""
   for iIII1i11iI in ii1i :
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
  O00o00 , III11II111 = oo0oO0OO . build_key ( self . eid )
  Iii11iIII = ""
  if ( self . group . is_null ( ) == False ) :
   I1II1I , Iii11iIII = oo0oO0OO . build_key ( self . group )
   Iii11iIII = "-" + Iii11iIII [ 0 : 12 ] + "-" + str ( I1II1I ) + "-" + Iii11iIII [ 12 : : ]
   if 99 - 99: Ii1I
  III11II111 = III11II111 [ 0 : 12 ] + "-" + str ( O00o00 ) + "-" + III11II111 [ 12 : : ] + Iii11iIII
  del ( oo0oO0OO )
  return ( III11II111 )
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
  for II1 in self . registered_rlocs :
   oOO0IiiiI . append ( copy . deepcopy ( II1 ) )
   if 43 - 43: oO0o / Ii1I % OOooOOo
  return ( oOO0IiiiI )
  if 45 - 45: II111iiii
  if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for iI1IiiIiIIIi1 in list ( self . individual_registrations . values ( ) ) :
   if ( self . site_id != iI1IiiIiIIIi1 . site_id ) : continue
   if ( iI1IiiIiIIIi1 . registered == False ) : continue
   self . registered_rlocs += iI1IiiIiIIIi1 . copy_rloc_records ( )
   if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
   if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
   if 43 - 43: OOooOOo . O0
   if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
   if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
   if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
  oOO0IiiiI = [ ]
  for II1 in self . registered_rlocs :
   if ( II1 . rloc . is_null ( ) or len ( oOO0IiiiI ) == 0 ) :
    oOO0IiiiI . append ( II1 )
    continue
    if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
   for I1I11I1IIi in oOO0IiiiI :
    if ( I1I11I1IIi . rloc . is_null ( ) ) : continue
    if ( II1 . rloc . is_exact_match ( I1I11I1IIi . rloc ) ) : break
    if 3 - 3: i1IIi + OoOoOO00 - OoOoOO00
   if ( I1I11I1IIi == oOO0IiiiI [ - 1 ] ) : oOO0IiiiI . append ( II1 )
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
  for II1 in self . registered_rlocs :
   if ( II1 . rle == None ) : continue
   for IIIi11i1 in II1 . rle . rle_nodes :
    oOOOo0o = IIIi11i1 . address . print_address_no_iid ( )
    iiIOoOoo [ oOOOo0o ] = IIIi11i1 . address
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
  for II1 in self . registered_rlocs :
   if ( self . registered_rlocs . index ( II1 ) == 0 ) :
    i11IiIi11I . append ( II1 )
    continue
    if 84 - 84: I1IiiI . o0oOOo0O0Ooo * I1ii11iIi11i
   if ( II1 . rle == None ) : i11IiIi11I . append ( II1 )
   if 41 - 41: o0oOOo0O0Ooo * Ii1I + I11i . O0
  self . registered_rlocs = i11IiIi11I
  if 17 - 17: Ii1I % I1Ii111
  if 69 - 69: iIii1I11I1II1
  if 65 - 65: IiII % OOooOOo / o0oOOo0O0Ooo * II111iiii - oO0o
  if 38 - 38: I1Ii111 * o0oOOo0O0Ooo
  if 32 - 32: iII111i / Ii1I / I1Ii111 - OoOoOO00 / OOooOOo * OoO0O00
  if 32 - 32: I1ii11iIi11i + ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
  if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
  IIiiiI = lisp_rle ( "" )
  I1iiIi1iI1I11 = { }
  oOo = None
  for iI1IiiIiIIIi1 in list ( self . individual_registrations . values ( ) ) :
   if ( iI1IiiIiIIIi1 . registered == False ) : continue
   O0oI1Iii = iI1IiiIiIIIi1 . registered_rlocs [ 0 ] . rle
   if ( O0oI1Iii == None ) : continue
   if 5 - 5: II111iiii
   oOo = iI1IiiIiIIIi1 . registered_rlocs [ 0 ] . rloc_name
   for ooOooOooOoOo in O0oI1Iii . rle_nodes :
    oOOOo0o = ooOooOooOoOo . address . print_address_no_iid ( )
    if ( oOOOo0o in I1iiIi1iI1I11 ) : break
    if 100 - 100: OoO0O00
    IIIi11i1 = lisp_rle_node ( )
    IIIi11i1 . address . copy_address ( ooOooOooOoOo . address )
    IIIi11i1 . level = ooOooOooOoOo . level
    IIIi11i1 . rloc_name = oOo
    IIiiiI . rle_nodes . append ( IIIi11i1 )
    I1iiIi1iI1I11 [ oOOOo0o ] = ooOooOooOoOo . address
    if 36 - 36: oO0o + Ii1I - O0
    if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
    if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
    if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
    if 11 - 11: I11i
    if 85 - 85: OoOoOO00 - Ii1I / Oo0Ooo % I1ii11iIi11i
  if ( len ( IIiiiI . rle_nodes ) == 0 ) : IIiiiI = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = IIiiiI
   if ( oOo ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 12 - 12: i1IIi + o0oOOo0O0Ooo / oO0o . O0
   if 37 - 37: IiII
   if 99 - 99: i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . OoO0O00 / I1IiiI
   if 44 - 44: iII111i - OoO0O00 / i11iIiiIii
   if 55 - 55: O0 * OoO0O00 * i1IIi
  if ( list ( iiIOoOoo . keys ( ) ) == list ( I1iiIi1iI1I11 . keys ( ) ) ) : return ( False )
  if 9 - 9: IiII
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # OoOoOO00 / OoooooooOO * OoO0O00 * I1Ii111
 list ( iiIOoOoo . keys ( ) ) , list ( I1iiIi1iI1I11 . keys ( ) ) ) )
  if 12 - 12: i11iIiiIii / iIii1I11I1II1 . I11i % I1Ii111 * ooOoO0o % ooOoO0o
  return ( True )
  if 13 - 13: i1IIi . ooOoO0o . ooOoO0o
  if 24 - 24: iIii1I11I1II1
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
    if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
    if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
    if 74 - 74: IiII * iIii1I11I1II1 - I1IiiI
    if 62 - 62: o0oOOo0O0Ooo
    if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
    Ii1iIi1I1I1I . parent_for_more_specifics = self . parent_for_more_specifics
    if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( Ii1iIi1I1I1I . group )
   Ii1iIi1I1I1I . add_source_entry ( self )
   if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
   if 84 - 84: OoOoOO00
   if 80 - 80: oO0o
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   Ii1iIi1I1I1I = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( Ii1iIi1I1I1I == None ) : return
   if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
   iI1IiiIiIIIi1 = Ii1iIi1I1I1I . lookup_source_cache ( self . eid , True )
   if ( iI1IiiIiIIIi1 == None ) : return
   if 92 - 92: iII111i
   if ( Ii1iIi1I1I1I . source_cache == None ) : return
   if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
   Ii1iIi1I1I1I . source_cache . delete_cache ( self . eid )
   if ( Ii1iIi1I1I1I . source_cache . cache_size ( ) == 0 ) :
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
  if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
  if 58 - 58: Ii1I / Oo0Ooo % IiII
 def rtrs_in_rloc_set ( self ) :
  for II1 in self . registered_rlocs :
   if ( II1 . is_rtr ( ) ) : return ( True )
   if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
  return ( False )
  if 60 - 60: iII111i . o0oOOo0O0Ooo
  if 56 - 56: I1ii11iIi11i
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for II1 in self . registered_rlocs :
   if ( II1 . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( II1 . is_rtr ( ) ) : return ( True )
   if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
  return ( False )
  if 70 - 70: o0oOOo0O0Ooo + O0 % I1IiiI
  if 56 - 56: Ii1I
 def is_rloc_in_rloc_set ( self , rloc ) :
  for II1 in self . registered_rlocs :
   if ( II1 . rle ) :
    for IIiiiI in II1 . rle . rle_nodes :
     if ( IIiiiI . address . is_exact_match ( rloc ) ) : return ( True )
     if 84 - 84: iII111i
     if 21 - 21: i11iIiiIii
   if ( II1 . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 30 - 30: OoO0O00 + OoooooooOO
  return ( False )
  if 98 - 98: I1ii11iIi11i % I1IiiI
  if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 66 - 66: IiII
  for II1 in prev_rloc_set :
   I1I1oO0oo = II1 . rloc
   if ( self . is_rloc_in_rloc_set ( I1I1oO0oo ) == False ) : return ( False )
   if 56 - 56: oO0o + OoooooooOO
  return ( True )
  if 75 - 75: O0 % Ii1I
  if 47 - 47: OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
  if 23 - 23: iII111i / iIii1I11I1II1
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
   O00Oo = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   IiIIii1I = O00Oo [ 2 ]
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
  oOOOo0o = IiIIii1I [ self . a_record_index ]
  if ( oOOOo0o != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( oOOOo0o )
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
  for oOOOo0o in IiIIii1I [ 1 : : ] :
   OoOOOO = lisp_address ( LISP_AFI_NONE , oOOOo0o , 0 , 0 )
   OO0O0O0OOO0OO = lisp_get_map_resolver ( OoOOOO , None )
   if ( OO0O0O0OOO0OO != None and OO0O0O0OOO0OO . a_record_index == IiIIii1I . index ( oOOOo0o ) ) :
    continue
    if 24 - 24: I11i / Oo0Ooo / i1IIi + IiII
   OO0O0O0OOO0OO = lisp_mr ( oOOOo0o , None , None )
   OO0O0O0OOO0OO . a_record_index = IiIIii1I . index ( oOOOo0o )
   OO0O0O0OOO0OO . dns_name = self . dns_name
   OO0O0O0OOO0OO . last_dns_resolve = lisp_get_timestamp ( )
   if 10 - 10: I11i - IiII / II111iiii / oO0o % O0 / I1Ii111
   if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
   if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
   if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
   if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
  oo0Oo00OO0000 = [ ]
  for OO0O0O0OOO0OO in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( self . dns_name != OO0O0O0OOO0OO . dns_name ) : continue
   OoOOOO = OO0O0O0OOO0OO . map_resolver . print_address_no_iid ( )
   if ( OoOOOO in IiIIii1I ) : continue
   oo0Oo00OO0000 . append ( OO0O0O0OOO0OO )
   if 74 - 74: Ii1I - OoOoOO00 + i11iIiiIii - II111iiii - i11iIiiIii . ooOoO0o
  for OO0O0O0OOO0OO in oo0Oo00OO0000 : OO0O0O0OOO0OO . delete_mr ( )
  if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
  if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
 def insert_mr ( self ) :
  III11II111 = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ III11II111 ] = self
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
  if 78 - 78: i1IIi
 def delete_mr ( self ) :
  III11II111 = self . mr_name + self . map_resolver . print_address ( )
  if ( III11II111 not in lisp_map_resolvers_list ) : return
  lisp_map_resolvers_list . pop ( III11II111 )
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
  for IiIiiiII1I in list ( self . referral_set . values ( ) ) :
   IiIiiiII1I . print_ref_node ( referral_indent )
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
  O0O00O = self . referral_ttl
  if ( O0O00O < 60 ) : return ( str ( O0O00O ) + " secs" )
  if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
  if ( ( O0O00O % 60 ) == 0 ) :
   O0O00O = str ( old_div ( O0O00O , 60 ) ) + " mins"
  else :
   O0O00O = str ( O0O00O ) + " secs"
   if 65 - 65: I1ii11iIi11i + OoOoOO00
  return ( O0O00O )
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
   oOo0III = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( oOo0III == None ) :
    oOo0III = lisp_referral ( )
    oOo0III . eid . copy_address ( self . group )
    oOo0III . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , oOo0III )
    if 48 - 48: OoooooooOO + II111iiii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( oOo0III . group )
   oOo0III . add_source_entry ( self )
   if 46 - 46: I1IiiI - II111iiii * OoO0O00 % OoooooooOO / OoO0O00 + II111iiii
   if 92 - 92: OoOoOO00 - iIii1I11I1II1
   if 10 - 10: iII111i - I1IiiI / I1ii11iIi11i - i1IIi - II111iiii % i11iIiiIii
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   oOo0III = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( oOo0III == None ) : return
   if 2 - 2: ooOoO0o % ooOoO0o
   iiiIIiIII111 = oOo0III . lookup_source_cache ( self . eid , True )
   if ( iiiIIiIII111 == None ) : return
   if 94 - 94: ooOoO0o / OoooooooOO * i1IIi . Oo0Ooo * i11iIiiIii
   oOo0III . source_cache . delete_cache ( self . eid )
   if ( oOo0III . source_cache . cache_size ( ) == 0 ) :
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
   O00Oo = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   IiIIii1I = O00Oo [ 2 ]
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
  oOOOo0o = IiIIii1I [ self . a_record_index ]
  if ( oOOOo0o != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( oOOOo0o )
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
  for oOOOo0o in IiIIii1I [ 1 : : ] :
   OoOOOO = lisp_address ( LISP_AFI_NONE , oOOOo0o , 0 , 0 )
   IIiiIiI = lisp_get_map_server ( OoOOOO )
   if ( IIiiIiI != None and IIiiIiI . a_record_index == IiIIii1I . index ( oOOOo0o ) ) :
    continue
    if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
   IIiiIiI = copy . deepcopy ( self )
   IIiiIiI . map_server . store_address ( oOOOo0o )
   IIiiIiI . a_record_index = IiIIii1I . index ( oOOOo0o )
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
   OoOOOO = IIiiIiI . map_server . print_address_no_iid ( )
   if ( OoOOOO in IiIIii1I ) : continue
   oo0Oo00OO0000 . append ( IIiiIiI )
   if 69 - 69: OOooOOo
  for IIiiIiI in oo0Oo00OO0000 : IIiiIiI . delete_ms ( )
  if 9 - 9: i11iIiiIii * Oo0Ooo
  if 33 - 33: oO0o / ooOoO0o
 def insert_ms ( self ) :
  III11II111 = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ III11II111 ] = self
  if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
  if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
 def delete_ms ( self ) :
  III11II111 = self . ms_name + self . map_server . print_address ( )
  if ( III11II111 not in lisp_map_servers_list ) : return
  lisp_map_servers_list . pop ( III11II111 )
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
  for oo0o0oOOoo00 in self . match_clauses :
   o00oo = oo0o0oOOoo00 . source_eid
   Ii1I111Ii = mr . source_eid
   if ( o00oo and Ii1I111Ii and Ii1I111Ii . is_more_specific ( o00oo ) == False ) : continue
   if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
   o00oo = oo0o0oOOoo00 . dest_eid
   Ii1I111Ii = mr . target_eid
   if ( o00oo and Ii1I111Ii and Ii1I111Ii . is_more_specific ( o00oo ) == False ) : continue
   if 65 - 65: I1Ii111 + OOooOOo
   o00oo = oo0o0oOOoo00 . source_rloc
   Ii1I111Ii = srloc
   if ( o00oo and Ii1I111Ii and Ii1I111Ii . is_more_specific ( o00oo ) == False ) : continue
   i1IIiI1iII = oo0o0oOOoo00 . datetime_lower
   OO0O0OOooo = oo0o0oOOoo00 . datetime_upper
   if ( i1IIiI1iII and OO0O0OOooo and i1IIiI1iII . now_in_range ( OO0O0OOooo ) == False ) : continue
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
  OooOOoOO0OO = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   OooOOoOO0OO . rloc . copy_address ( self . set_rloc_address )
   oOOOo0o = OooOOoOO0OO . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( oOOOo0o ) )
   if 22 - 22: OoooooooOO / O0 / I1IiiI * I1ii11iIi11i % I11i + iII111i
  if ( self . set_rloc_record_name ) :
   OooOOoOO0OO . rloc_name = self . set_rloc_record_name
   ooO0o = blue ( OooOOoOO0OO . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( ooO0o ) )
   if 26 - 26: I1ii11iIi11i - o0oOOo0O0Ooo - i1IIi - Ii1I
  if ( self . set_geo_name ) :
   OooOOoOO0OO . geo_name = self . set_geo_name
   ooO0o = OooOOoOO0OO . geo_name
   oo0O0o = "" if ( ooO0o in lisp_geo_list ) else "(not configured)"
   if 76 - 76: I1IiiI - oO0o
   lprint ( "Policy set-geo-name '{}' {}" . format ( ooO0o , oo0O0o ) )
   if 93 - 93: I1ii11iIi11i - OOooOOo - II111iiii * OoO0O00 . O0 - ooOoO0o
  if ( self . set_elp_name ) :
   OooOOoOO0OO . elp_name = self . set_elp_name
   ooO0o = OooOOoOO0OO . elp_name
   oo0O0o = "" if ( ooO0o in lisp_elp_list ) else "(not configured)"
   if 53 - 53: OoO0O00 / i11iIiiIii . OoooooooOO
   lprint ( "Policy set-elp-name '{}' {}" . format ( ooO0o , oo0O0o ) )
   if 84 - 84: I1ii11iIi11i
  if ( self . set_rle_name ) :
   OooOOoOO0OO . rle_name = self . set_rle_name
   ooO0o = OooOOoOO0OO . rle_name
   oo0O0o = "" if ( ooO0o in lisp_rle_list ) else "(not configured)"
   if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
   lprint ( "Policy set-rle-name '{}' {}" . format ( ooO0o , oo0O0o ) )
   if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
  if ( self . set_json_name ) :
   OooOOoOO0OO . json_name = self . set_json_name
   ooO0o = OooOOoOO0OO . json_name
   oo0O0o = "" if ( ooO0o in lisp_json_list ) else "(not configured)"
   if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
   lprint ( "Policy set-json-name '{}' {}" . format ( ooO0o , oo0O0o ) )
   if 67 - 67: i1IIi * I1Ii111 * O0
  return ( OooOOoOO0OO )
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
  O0O00O = self . ttl
  I11I = eid_prefix . print_prefix ( )
  if ( I11I not in lisp_pubsub_cache ) :
   lisp_pubsub_cache [ I11I ] = { }
   if 90 - 90: I1IiiI * i11iIiiIii . OOooOOo / o0oOOo0O0Ooo
  iIiii11 = lisp_pubsub_cache [ I11I ]
  if 82 - 82: Oo0Ooo
  I11IiI1i11i1 = "Add"
  if ( self . xtr_id in iIiii11 ) :
   I11IiI1i11i1 = "Replace"
   del ( iIiii11 [ self . xtr_id ] )
   if 35 - 35: Ii1I . O0 % i11iIiiIii * oO0o - OoooooooOO
  iIiii11 [ self . xtr_id ] = self
  if 87 - 87: iII111i * ooOoO0o - OOooOOo . O0
  I11I = green ( I11I , False )
  I1IoOO0oOOOOO0 = red ( self . itr . print_address_no_iid ( ) , False )
  oOOoO = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( I11IiI1i11i1 , I11I ,
 I1IoOO0oOOOOO0 , oOOoO , O0O00O ) )
  if 20 - 20: OoOoOO00 - IiII
  if 9 - 9: O0 . I11i % I1ii11iIi11i * oO0o - I1Ii111 - i1IIi
 def delete ( self , eid_prefix ) :
  I11I = eid_prefix . print_prefix ( )
  I1IoOO0oOOOOO0 = red ( self . itr . print_address_no_iid ( ) , False )
  oOOoO = "0x" + lisp_hex_string ( self . xtr_id )
  if ( I11I in lisp_pubsub_cache ) :
   iIiii11 = lisp_pubsub_cache [ I11I ]
   if ( self . xtr_id in iIiii11 ) :
    iIiii11 . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( I11I ,
 I1IoOO0oOOOOO0 , oOOoO ) )
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
  Oo0O = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( Oo0O ) )
  if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
  if 30 - 30: Ii1I / iII111i * Ii1I
 def encode ( self ) :
  oOOOoOO = socket . htonl ( 0x90000000 )
  OO0Oo00OO0oo = struct . pack ( "II" , oOOOoOO , 0 )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  OO0Oo00OO0oo += json . dumps ( self . packet_json )
  return ( OO0Oo00OO0oo )
  if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
  if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
 def decode ( self , packet ) :
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( False )
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  oOOOoOO = socket . ntohl ( oOOOoOO )
  if ( ( oOOOoOO & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 71 - 71: i1IIi % O0 % ooOoO0o
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( False )
  oOOOo0o = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if 24 - 24: O0
  oOOOo0o = socket . ntohl ( oOOOo0o )
  oooO = oOOOo0o >> 24
  O000OO000 = ( oOOOo0o >> 16 ) & 0xff
  iI111IiI1I1Ii = ( oOOOo0o >> 8 ) & 0xff
  oO0oO000ooo0o = oOOOo0o & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( oooO , O000OO000 , iI111IiI1I1Ii , oO0oO000ooo0o )
  self . local_port = str ( oOOOoOO & 0xffff )
  if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
  Iii1iIII1Iii = "Q"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( False )
  self . nonce = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
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
  OooOOoOO0OO , O00oo0o0o0oo = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( OooOOoOO0OO == None ) :
   OooOOoOO0OO , O00oo0o0o0oo = rts_rloc . split ( ":" )
   O00oo0o0o0oo = int ( O00oo0o0o0oo )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( OooOOoOO0OO , O00oo0o0o0oo ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( OooOOoOO0OO ,
 O00oo0o0o0oo ) )
   if 52 - 52: i11iIiiIii / oO0o / IiII
   if 84 - 84: I11i . oO0o + ooOoO0o
  if ( lisp_socket == None ) :
   I1iiIi111I = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   I1iiIi111I . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   I1iiIi111I . sendto ( packet , ( OooOOoOO0OO , O00oo0o0o0oo ) )
   I1iiIi111I . close ( )
  else :
   lisp_socket . sendto ( packet , ( OooOOoOO0OO , O00oo0o0o0oo ) )
   if 75 - 75: I1Ii111
   if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
   if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 def packet_length ( self ) :
  Ii1iiI1 = 8 ; O0Ooo0 = 4 + 4 + 8
  return ( Ii1iiI1 + O0Ooo0 + len ( json . dumps ( self . packet_json ) ) )
  if 48 - 48: Oo0Ooo - oO0o
  if 80 - 80: OoO0O00 * OoOoOO00 - OoooooooOO * iII111i % ooOoO0o
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  III11II111 = self . local_rloc + ":" + self . local_port
  iiIiII11i1 = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ III11II111 ] = iiIiII11i1
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( III11II111 , iiIiII11i1 ) )
  if 17 - 17: OoO0O00 % II111iiii . i1IIi . OOooOOo
  if 49 - 49: II111iiii / OoOoOO00 * IiII % OoO0O00
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  III11II111 = local_rloc_and_port
  try : iiIiII11i1 = lisp_rtr_nat_trace_cache [ III11II111 ]
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
 for IIiiIiI in list ( lisp_map_servers_list . values ( ) ) :
  if ( IIiiIiI . map_server . is_exact_match ( address ) ) : return ( IIiiIiI )
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
 for IIiiIiI in list ( lisp_map_servers_list . values ( ) ) : return ( IIiiIiI )
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
  oOOOo0o = address . print_address ( )
  OO0O0O0OOO0OO = None
  for III11II111 in lisp_map_resolvers_list :
   if ( III11II111 . find ( oOOOo0o ) == - 1 ) : continue
   OO0O0O0OOO0OO = lisp_map_resolvers_list [ III11II111 ]
   if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
  return ( OO0O0O0OOO0OO )
  if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
  if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
  if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
  if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
  if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
  if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
  if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
 if ( eid == "" ) :
  o0o = ""
 elif ( eid == None ) :
  o0o = "all"
 else :
  iIiI1ii = lisp_db_for_lookups . lookup_cache ( eid , False )
  o0o = "all" if iIiI1ii == None else iIiI1ii . use_mr_name
  if 96 - 96: oO0o % I1Ii111 . I11i - I11i + OoO0O00 - oO0o
  if 25 - 25: IiII % O0 - I1IiiI + I1Ii111 . i11iIiiIii
 I1iiiIIIIi1I = None
 for OO0O0O0OOO0OO in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( o0o == "" ) : return ( OO0O0O0OOO0OO )
  if ( OO0O0O0OOO0OO . mr_name != o0o ) : continue
  if ( I1iiiIIIIi1I == None or OO0O0O0OOO0OO . last_used < I1iiiIIIIi1I . last_used ) : I1iiiIIIIi1I = OO0O0O0OOO0OO
  if 69 - 69: Oo0Ooo . Oo0Ooo * ooOoO0o
 return ( I1iiiIIIIi1I )
 if 19 - 19: I1IiiI + ooOoO0o + I11i - OoOoOO00 * Ii1I
 if 62 - 62: I11i * iIii1I11I1II1 - I1Ii111 % I1IiiI . oO0o
 if 99 - 99: i1IIi . iII111i . iII111i
 if 77 - 77: OOooOOo
 if 74 - 74: O0
 if 86 - 86: OoOoOO00
 if 4 - 4: OoooooooOO * OoO0O00
 if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
def lisp_get_decent_map_resolver ( eid ) :
 OOOooo0OooOoO = lisp_get_decent_index ( eid )
 II1OO = str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix
 if 90 - 90: OoooooooOO + ooOoO0o / iIii1I11I1II1 + iII111i
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( II1OO , False ) , eid . print_prefix ( ) ) )
 if 45 - 45: ooOoO0o / O0 % O0 % i1IIi . I1IiiI - OoOoOO00
 if 63 - 63: OOooOOo - oO0o * I1IiiI
 I1iiiIIIIi1I = None
 for OO0O0O0OOO0OO in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( II1OO != OO0O0O0OOO0OO . dns_name ) : continue
  if ( I1iiiIIIIi1I == None or OO0O0O0OOO0OO . last_used < I1iiiIIIIi1I . last_used ) : I1iiiIIIIi1I = OO0O0O0OOO0OO
  if 60 - 60: II111iiii - Oo0Ooo
 return ( I1iiiIIIIi1I )
 if 43 - 43: I1IiiI - IiII - OOooOOo
 if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
 if 99 - 99: O0
 if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
 if 85 - 85: ooOoO0o / I1IiiI
 if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
 if 99 - 99: i11iIiiIii - I1ii11iIi11i
def lisp_ipv4_input ( packet ) :
 if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
 if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
 if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
 if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
 if ( ord ( packet [ 9 : 10 ] ) == 2 ) : return ( [ True , packet ] )
 if 76 - 76: I1Ii111 / OoOoOO00
 if 61 - 61: Oo0Ooo . i1IIi
 if 78 - 78: i11iIiiIii
 if 20 - 20: Ii1I
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
   if 100 - 100: OoooooooOO . I1Ii111
   if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
   if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
   if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
   if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
   if 37 - 37: IiII
   if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
 O0O00O = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( O0O00O == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( O0O00O == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
  return ( [ False , None ] )
  if 88 - 88: i1IIi - OoOoOO00
  if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
 O0O00O -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , O0O00O ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 7 - 7: Ii1I / iIii1I11I1II1
 if 36 - 36: iIii1I11I1II1 % i11iIiiIii
 if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
 if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
 if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
 if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
def lisp_ipv6_input ( packet ) :
 OooOOooo = packet . inner_dest
 packet = packet . packet
 if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
 if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
 if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
 if 38 - 38: IiII
 if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
 O0O00O = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( O0O00O == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( O0O00O == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 2 - 2: Oo0Ooo - OoOoOO00
  return ( None )
  if 22 - 22: OoO0O00 - oO0o - O0
  if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
  if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
  if 2 - 2: i11iIiiIii
  if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
 if ( OooOOooo . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 17 - 17: iIii1I11I1II1
  if 32 - 32: IiII - OoOoOO00
 O0O00O -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , O0O00O ) + packet [ 8 : : ]
 return ( packet )
 if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
 if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
 if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
 if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
 if 16 - 16: Oo0Ooo
 if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
 if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
def lisp_mac_input ( packet ) :
 return ( packet )
 if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
 if 96 - 96: I1IiiI . oO0o % O0
 if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
 if 87 - 87: OoooooooOO
 if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
 if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
 if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
 if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
def lisp_rate_limit_map_request ( dest ) :
 iiI1 = lisp_get_timestamp ( )
 if 45 - 45: II111iiii . iII111i
 if 55 - 55: ooOoO0o / iII111i / O0
 if 98 - 98: O0 % iII111i + II111iiii
 if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
 Ii1i1 = iiI1 - lisp_no_map_request_rate_limit
 if ( Ii1i1 < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  Oo = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - Ii1i1 )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( Oo ) )
  return ( False )
  if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
  if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
  if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
  if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
  if 36 - 36: O0
 if ( lisp_last_map_request_sent == None ) : return ( False )
 Ii1i1 = iiI1 - lisp_last_map_request_sent
 IiII1IIiI1i = ( Ii1i1 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
 if ( IiII1IIiI1i ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( Ii1i1 , 3 ) ) )
  if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
  if 21 - 21: i1IIi * iII111i + OoO0O00
 return ( IiII1IIiI1i )
 if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 if 85 - 85: OoooooooOO
 if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
 if 8 - 8: I1Ii111
 if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
 if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
 if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ,
 pubsub = False ) :
 global lisp_last_map_request_sent
 if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
 if 7 - 7: i1IIi . I1IiiI
 if 68 - 68: OoooooooOO
 if 91 - 91: IiII . ooOoO0o * I11i
 if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
 if 69 - 69: iIii1I11I1II1 . II111iiii
 iiIiIIiII111i = I11IiI1iii1i = None
 if ( rloc ) :
  iiIiIIiII111i = rloc . rloc
  I11IiI1iii1i = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 7 - 7: o0oOOo0O0Ooo % IiII
  if 68 - 68: Oo0Ooo
  if 76 - 76: I1ii11iIi11i . IiII - IiII
  if 51 - 51: i11iIiiIii
  if 11 - 11: I1ii11iIi11i
 o0o00oooO0o0o , OOoO0OOoOoO , OoO0 = lisp_myrlocs
 if ( o0o00oooO0o0o == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
 if ( OOoO0OOoOoO == None and iiIiIIiII111i != None and iiIiIIiII111i . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 44 - 44: OoOoOO00 + I1IiiI . I1ii11iIi11i / i1IIi + II111iiii . Oo0Ooo
  if 39 - 39: o0oOOo0O0Ooo
 III1II1iiI = lisp_map_request ( )
 III1II1iiI . record_count = 1
 III1II1iiI . nonce = lisp_get_control_nonce ( )
 III1II1iiI . rloc_probe = ( iiIiIIiII111i != None )
 III1II1iiI . subscribe_bit = pubsub
 III1II1iiI . xtr_id_present = pubsub
 if 64 - 64: oO0o - i11iIiiIii
 if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
 if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
 if 21 - 21: OoOoOO00 / OoooooooOO + I1Ii111 - IiII
 if 62 - 62: Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % iII111i % iIii1I11I1II1
 if 54 - 54: IiII + OoOoOO00 / II111iiii % i11iIiiIii . I1Ii111
 if 69 - 69: i1IIi + ooOoO0o + Ii1I
 if ( rloc ) : rloc . last_rloc_probe_nonce = III1II1iiI . nonce
 if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 I1iiIiI1II1ii = deid . is_multicast_address ( )
 if ( I1iiIiI1II1ii ) :
  III1II1iiI . target_eid = seid
  III1II1iiI . target_group = deid
 else :
  III1II1iiI . target_eid = deid
  if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
  if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
  if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
  if 8 - 8: i1IIi
  if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
  if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
  if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
  if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
  if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
 if ( III1II1iiI . rloc_probe == False ) :
  iIiI1ii = lisp_get_signature_eid ( )
  if ( iIiI1ii ) :
   III1II1iiI . signature_eid . copy_address ( iIiI1ii . eid )
   III1II1iiI . privkey_filename = "./lisp-sig.pem"
   if 54 - 54: OOooOOo
   if 86 - 86: oO0o * Oo0Ooo / OOooOOo
   if 18 - 18: II111iiii - I1Ii111
   if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
   if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
   if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
 if ( seid == None or I1iiIiI1II1ii ) :
  III1II1iiI . source_eid . afi = LISP_AFI_NONE
 else :
  III1II1iiI . source_eid = seid
  if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
  if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
  if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
  if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
  if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
  if 34 - 34: II111iiii + iII111i / IiII
  if 47 - 47: OoO0O00
  if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
  if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
  if 100 - 100: II111iiii . IiII . I11i
  if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
 if ( iiIiIIiII111i != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( iiIiIIiII111i . is_private_address ( ) == False ) :
   o0o00oooO0o0o = lisp_get_any_translated_rloc ( )
   if 3 - 3: OoooooooOO
  if ( o0o00oooO0o0o == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
   if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
   if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
   if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
   if 37 - 37: I1ii11iIi11i * IiII
   if 65 - 65: OOooOOo / O0 . I1ii11iIi11i % i1IIi % Oo0Ooo
   if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
   if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
 if ( iiIiIIiII111i == None or iiIiIIiII111i . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and iiIiIIiII111i == None ) :
   iiiI111i1iIi = lisp_get_any_translated_rloc ( )
   if ( iiiI111i1iIi != None ) : o0o00oooO0o0o = iiiI111i1iIi
   if 99 - 99: iIii1I11I1II1 + O0 + OoooooooOO % I1IiiI - OoOoOO00 / oO0o
  III1II1iiI . itr_rlocs . append ( o0o00oooO0o0o )
  if 22 - 22: iIii1I11I1II1 . I11i
 if ( iiIiIIiII111i == None or iiIiIIiII111i . is_ipv6 ( ) ) :
  if ( OOoO0OOoOoO == None or OOoO0OOoOoO . is_ipv6_link_local ( ) ) :
   OOoO0OOoOoO = None
  else :
   III1II1iiI . itr_rloc_count = 1 if ( iiIiIIiII111i == None ) else 0
   III1II1iiI . itr_rlocs . append ( OOoO0OOoOoO )
   if 21 - 21: I1IiiI % Oo0Ooo - II111iiii / I1IiiI . OoOoOO00 - o0oOOo0O0Ooo
   if 23 - 23: OoOoOO00 / O0 * OoOoOO00 . I1IiiI + Oo0Ooo . iII111i
   if 1 - 1: i11iIiiIii * OoO0O00 - OoooooooOO + OoooooooOO
   if 31 - 31: OoooooooOO - OoOoOO00 * II111iiii % ooOoO0o - ooOoO0o / i11iIiiIii
   if 8 - 8: I1IiiI . i1IIi - I11i
   if 85 - 85: OOooOOo * IiII % O0 / I1ii11iIi11i
   if 17 - 17: Oo0Ooo / i11iIiiIii / I11i - I1Ii111
   if 3 - 3: I1Ii111 - Oo0Ooo / iIii1I11I1II1
   if 71 - 71: o0oOOo0O0Ooo + i11iIiiIii + OoooooooOO % OoOoOO00 - I1ii11iIi11i / OoooooooOO
 if ( iiIiIIiII111i != None and III1II1iiI . itr_rlocs != [ ] ) :
  oo00O0OO0Ooo0 = III1II1iiI . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   oo00O0OO0Ooo0 = o0o00oooO0o0o
  elif ( deid . is_ipv6 ( ) ) :
   oo00O0OO0Ooo0 = OOoO0OOoOoO
  else :
   oo00O0OO0Ooo0 = o0o00oooO0o0o
   if 26 - 26: II111iiii
   if 41 - 41: Oo0Ooo . OoOoOO00 . iII111i / i11iIiiIii
   if 65 - 65: iII111i * o0oOOo0O0Ooo * OoooooooOO + I11i + oO0o % OoO0O00
   if 1 - 1: I1ii11iIi11i . ooOoO0o
   if 54 - 54: OoOoOO00 % I1IiiI . ooOoO0o + IiII / i11iIiiIii / o0oOOo0O0Ooo
   if 51 - 51: OoOoOO00 / Ii1I . I1IiiI / Ii1I . II111iiii - iIii1I11I1II1
 OO0Oo00OO0oo = III1II1iiI . encode ( iiIiIIiII111i , I11IiI1iii1i )
 III1II1iiI . print_map_request ( )
 if 78 - 78: I11i
 if 42 - 42: Ii1I
 if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
 if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
 if 21 - 21: I1ii11iIi11i - ooOoO0o
 if 81 - 81: iII111i / i11iIiiIii / I1Ii111
 if ( iiIiIIiII111i != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   iII1II1 = lisp_get_nat_info ( iiIiIIiII111i , rloc . rloc_name )
   if 70 - 70: I1ii11iIi11i / i11iIiiIii
   if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
   if 76 - 76: OoooooooOO
   if 78 - 78: IiII % i11iIiiIii
   if ( iII1II1 == None ) :
    I1I1iIiiiiII11 = rloc . rloc . print_address_no_iid ( )
    o0O0Ooo = "gleaned-{}" . format ( I1I1iIiiiiII11 )
    o00oo = rloc . translated_port
    iII1II1 = lisp_nat_info ( I1I1iIiiiiII11 , o0O0Ooo , o00oo )
    if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
   lisp_encapsulate_rloc_probe ( lisp_sockets , iiIiIIiII111i , iII1II1 ,
 OO0Oo00OO0oo )
   return
   if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
   if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
  Oo0o = iiIiIIiII111i . print_address_no_iid ( )
  OooOOooo = lisp_convert_4to6 ( Oo0o )
  lisp_send ( lisp_sockets , OooOOooo , LISP_CTRL_PORT , OO0Oo00OO0oo )
  return
  if 19 - 19: o0oOOo0O0Ooo
  if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
  if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
  if 71 - 71: OoO0O00 - I11i
  if 96 - 96: I1Ii111 / Ii1I
  if 65 - 65: I1ii11iIi11i * O0 . IiII
 i111I = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  OO0O0O0OOO0OO = lisp_get_decent_map_resolver ( deid )
 else :
  OO0O0O0OOO0OO = lisp_get_map_resolver ( None , i111I )
  if 50 - 50: i11iIiiIii
 if ( OO0O0O0OOO0OO == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
  return
  if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
 OO0O0O0OOO0OO . last_used = lisp_get_timestamp ( )
 OO0O0O0OOO0OO . map_requests_sent += 1
 if ( OO0O0O0OOO0OO . last_nonce == 0 ) : OO0O0O0OOO0OO . last_nonce = III1II1iiI . nonce
 if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 if 4 - 4: I1IiiI
 if 36 - 36: Ii1I
 if 76 - 76: i11iIiiIii + i1IIi
 if ( seid == None ) : seid = oo00O0OO0Ooo0
 lisp_send_ecm ( lisp_sockets , OO0Oo00OO0oo , seid , lisp_ephem_port , deid ,
 OO0O0O0OOO0OO . map_resolver )
 if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
 if 15 - 15: OoOoOO00 / OoooooooOO + OOooOOo
 if 76 - 76: Ii1I * iII111i . OoooooooOO
 if 92 - 92: iIii1I11I1II1 - Oo0Ooo - I1IiiI - OOooOOo * I1Ii111
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 44 - 44: I1Ii111 - II111iiii / OOooOOo
 if 50 - 50: I11i / I1ii11iIi11i
 if 60 - 60: II111iiii / Ii1I + OoO0O00 % I1IiiI * i1IIi / II111iiii
 if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
 OO0O0O0OOO0OO . resolve_dns_name ( )
 return
 if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
 if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
 if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 if 48 - 48: O0
 if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
 if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
 if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
 if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
 if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 if 79 - 79: oO0o
 ii1i1i1i1 = lisp_info ( )
 ii1i1i1i1 . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : ii1i1i1i1 . hostname += "-" + device_name
 if 4 - 4: o0oOOo0O0Ooo - O0 * OoooooooOO % O0 * Ii1I
 Oo0o = dest . print_address_no_iid ( )
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
 iiIIiI = False
 if ( device_name ) :
  II11IIii = lisp_get_host_route_next_hop ( Oo0o )
  if 13 - 13: O0 - I1Ii111
  if 56 - 56: I1ii11iIi11i - OoooooooOO
  if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
  if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
  if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
  if 31 - 31: Oo0Ooo * IiII / IiII
  if 3 - 3: I1Ii111
  if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
  if 82 - 82: o0oOOo0O0Ooo
  if ( port == LISP_CTRL_PORT and II11IIii != None ) :
   while ( True ) :
    time . sleep ( .01 )
    II11IIii = lisp_get_host_route_next_hop ( Oo0o )
    if ( II11IIii == None ) : break
    if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
    if 92 - 92: iII111i + OoO0O00
    if 70 - 70: iIii1I11I1II1
  O0O0o0O0OoOoOO = lisp_get_default_route_next_hops ( )
  for OoO0 , IIi1iiii1Ii in O0O0o0O0OoOoOO :
   if ( OoO0 != device_name ) : continue
   if 24 - 24: OoooooooOO . OoOoOO00
   if 93 - 93: II111iiii + i11iIiiIii * Ii1I
   if 100 - 100: O0 . iII111i / iIii1I11I1II1
   if 47 - 47: ooOoO0o + OoOoOO00
   if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
   if 91 - 91: I11i
   if ( II11IIii != IIi1iiii1Ii ) :
    if ( II11IIii != None ) :
     lisp_install_host_route ( Oo0o , II11IIii , False )
     if 54 - 54: I1ii11iIi11i / i1IIi
    lisp_install_host_route ( Oo0o , IIi1iiii1Ii , True )
    iiIIiI = True
    if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
   break
   if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
   if 23 - 23: iII111i - IiII % i11iIiiIii
   if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
   if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
   if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
   if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
 OO0Oo00OO0oo = ii1i1i1i1 . encode ( )
 ii1i1i1i1 . print_info ( )
 if 11 - 11: II111iiii + i1IIi
 if 1 - 1: OOooOOo
 if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
 if 83 - 83: OoooooooOO
 OOoOO0o00 = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 OOoOO0o00 = bold ( OOoOO0o00 , False )
 o00oo = bold ( "{}" . format ( port ) , False )
 OoOOOO = red ( Oo0o , False )
 i1I1IIIi11I = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( i1I1IIIi11I , OoOOOO , o00oo , OOoOO0o00 ) )
 if 77 - 77: I1Ii111 * O0 - IiII
 if 21 - 21: Oo0Ooo % Oo0Ooo % Oo0Ooo
 if 15 - 15: I1IiiI + OoO0O00 . I1IiiI / OoO0O00 . o0oOOo0O0Ooo
 if 72 - 72: IiII + oO0o * o0oOOo0O0Ooo
 if 39 - 39: O0 + iII111i + ooOoO0o / iIii1I11I1II1
 if 91 - 91: Ii1I
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , OO0Oo00OO0oo )
 else :
  i111ii1II11ii = lisp_data_header ( )
  i111ii1II11ii . instance_id ( 0xffffff )
  i111ii1II11ii = i111ii1II11ii . encode ( )
  if ( i111ii1II11ii ) :
   OO0Oo00OO0oo = i111ii1II11ii + OO0Oo00OO0oo
   if 62 - 62: I1Ii111 . iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I11i % i1IIi
   if 72 - 72: oO0o
   if 3 - 3: ooOoO0o - Oo0Ooo / iII111i
   if 40 - 40: IiII + oO0o
   if 95 - 95: I1Ii111 % OOooOOo + Ii1I * i11iIiiIii + i11iIiiIii
   if 27 - 27: i11iIiiIii - iIii1I11I1II1 % I1Ii111
   if 10 - 10: i11iIiiIii - Ii1I - OoooooooOO % II111iiii
   if 42 - 42: OoOoOO00 + iII111i % Oo0Ooo
   if 25 - 25: IiII % O0 * I11i * OoOoOO00 / OoooooooOO
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , OO0Oo00OO0oo )
   if 80 - 80: I1IiiI . oO0o - I1IiiI - OoOoOO00 * ooOoO0o / O0
   if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
   if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
   if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
   if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
   if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
   if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
 if ( iiIIiI ) :
  lisp_install_host_route ( Oo0o , None , False )
  if ( II11IIii != None ) : lisp_install_host_route ( Oo0o , II11IIii , True )
  if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 return
 if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
 if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
 if 40 - 40: I1ii11iIi11i
 if 76 - 76: Oo0Ooo - I11i
 if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
 if 39 - 39: I1IiiI
 if 8 - 8: IiII * i1IIi * i1IIi * O0
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 69 - 69: Oo0Ooo
 if 48 - 48: iII111i
 if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
 if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
 ii1i1i1i1 = lisp_info ( )
 packet = ii1i1i1i1 . decode ( packet )
 if ( packet == None ) : return
 ii1i1i1i1 . print_info ( )
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 if 37 - 37: ooOoO0o
 ii1i1i1i1 . info_reply = True
 ii1i1i1i1 . global_etr_rloc . store_address ( addr_str )
 ii1i1i1i1 . etr_port = sport
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if ( ii1i1i1i1 . hostname != None ) :
  ii1i1i1i1 . private_etr_rloc . afi = LISP_AFI_NAME
  ii1i1i1i1 . private_etr_rloc . store_address ( ii1i1i1i1 . hostname )
  if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
  if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
 if ( rtr_list != None ) : ii1i1i1i1 . rtr_list = rtr_list
 packet = ii1i1i1i1 . encode ( )
 ii1i1i1i1 . print_info ( )
 if 44 - 44: O0
 if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
 if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 OooOOooo = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , OooOOooo , sport , packet )
 if 79 - 79: II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 if 32 - 32: O0 + IiII
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 i1IiI = lisp_info_source ( ii1i1i1i1 . hostname , addr_str , sport )
 i1IiI . cache_address_for_info_source ( )
 return
 if 17 - 17: OOooOOo
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 if 46 - 46: II111iiii * OoO0O00
 if 77 - 77: ooOoO0o * I11i
 if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
 if 76 - 76: iII111i * OoooooooOO
 if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
 if 51 - 51: i11iIiiIii
def lisp_get_signature_eid ( ) :
 for iIiI1ii in lisp_db_list :
  if ( iIiI1ii . signature_eid ) : return ( iIiI1ii )
  if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
 return ( None )
 if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 if 63 - 63: II111iiii - Oo0Ooo
 if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
 if 78 - 78: IiII - I1IiiI
 if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
 if 71 - 71: OoO0O00
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
def lisp_get_any_translated_port ( ) :
 for iIiI1ii in lisp_db_list :
  for II1 in iIiI1ii . rloc_set :
   if ( II1 . translated_rloc . is_null ( ) ) : continue
   return ( II1 . translated_port )
   if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
   if 54 - 54: Ii1I / I1IiiI
 return ( None )
 if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
 if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
 if 18 - 18: oO0o * OOooOOo
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
 if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
 if 63 - 63: I1IiiI
 if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
def lisp_get_any_translated_rloc ( ) :
 for iIiI1ii in lisp_db_list :
  for II1 in iIiI1ii . rloc_set :
   if ( II1 . translated_rloc . is_null ( ) ) : continue
   return ( II1 . translated_rloc )
   if 23 - 23: I1IiiI
   if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
 return ( None )
 if 57 - 57: iIii1I11I1II1
 if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
 if 3 - 3: oO0o % OoO0O00 % OOooOOo
 if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
 if 58 - 58: ooOoO0o
 if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
 if 77 - 77: O0
def lisp_get_all_translated_rlocs ( ) :
 O000Ooo0 = [ ]
 for iIiI1ii in lisp_db_list :
  for II1 in iIiI1ii . rloc_set :
   if ( II1 . is_rloc_translated ( ) == False ) : continue
   oOOOo0o = II1 . translated_rloc . print_address_no_iid ( )
   O000Ooo0 . append ( oOOOo0o )
   if 72 - 72: Oo0Ooo - I1ii11iIi11i
   if 75 - 75: OoOoOO00 . OOooOOo . I1IiiI - iIii1I11I1II1 * OoOoOO00 % i11iIiiIii
 return ( O000Ooo0 )
 if 41 - 41: o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
 if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
 if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
 if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
 if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
 if 60 - 60: OoOoOO00 - IiII + OoO0O00
 if 77 - 77: iIii1I11I1II1
 if 92 - 92: IiII
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 IiI1iiIIiIiii = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
 o0o0o0O = { }
 for OooOOoOO0OO in rtr_list :
  if ( OooOOoOO0OO == None ) : continue
  oOOOo0o = rtr_list [ OooOOoOO0OO ]
  if ( IiI1iiIIiIiii and oOOOo0o . is_private_address ( ) ) : continue
  o0o0o0O [ OooOOoOO0OO ] = oOOOo0o
  if 75 - 75: I1ii11iIi11i
 rtr_list = o0o0o0O
 if 50 - 50: OoO0O00 % OoOoOO00
 i111 = [ ]
 for O0ooO0O00oo0 in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( O0ooO0O00oo0 == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 25 - 25: OoooooooOO % ooOoO0o / i1IIi . o0oOOo0O0Ooo
  if 62 - 62: i11iIiiIii / i11iIiiIii * I1Ii111
  if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
  if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
  if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
  Ii1I1I11I11 = lisp_address ( O0ooO0O00oo0 , "" , 0 , iid )
  Ii1I1I11I11 . make_default_route ( Ii1I1I11I11 )
  O0oo0OOo00o0o = lisp_map_cache . lookup_cache ( Ii1I1I11I11 , True )
  if ( O0oo0OOo00o0o ) :
   if ( O0oo0OOo00o0o . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( O0oo0OOo00o0o . print_eid_tuple ( ) , False ) ) )
    if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
   elif ( O0oo0OOo00o0o . do_rloc_sets_match ( list ( rtr_list . values ( ) ) ) ) :
    continue
    if 49 - 49: iII111i / iII111i - OoOoOO00
   O0oo0OOo00o0o . delete_cache ( )
   if 89 - 89: ooOoO0o
   if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
  i111 . append ( [ Ii1I1I11I11 , "" ] )
  if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
  if 11 - 11: iII111i
  if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
  if 89 - 89: I11i % II111iiii
  o0o0o = lisp_address ( O0ooO0O00oo0 , "" , 0 , iid )
  o0o0o . make_default_multicast_route ( o0o0o )
  iIii1IiII = lisp_map_cache . lookup_cache ( o0o0o , True )
  if ( iIii1IiII ) : iIii1IiII = iIii1IiII . source_cache . lookup_cache ( Ii1I1I11I11 , True )
  if ( iIii1IiII ) : iIii1IiII . delete_cache ( )
  if 45 - 45: iIii1I11I1II1 % II111iiii . iIii1I11I1II1 * IiII
  i111 . append ( [ Ii1I1I11I11 , o0o0o ] )
  if 17 - 17: iII111i - OOooOOo / OOooOOo % OoO0O00 + i11iIiiIii % OoO0O00
 if ( len ( i111 ) == 0 ) : return
 if 13 - 13: I1IiiI + Oo0Ooo * I1IiiI . i1IIi * I1ii11iIi11i + iII111i
 if 55 - 55: ooOoO0o
 if 68 - 68: Oo0Ooo
 if 3 - 3: Ii1I % Ii1I + oO0o
 IIiii11iiI111 = [ ]
 for i1I1IIIi11I in rtr_list :
  i1O00OoO0O = rtr_list [ i1I1IIIi11I ]
  II1 = lisp_rloc ( )
  II1 . rloc . copy_address ( i1O00OoO0O )
  II1 . priority = 254
  II1 . mpriority = 255
  II1 . rloc_name = "RTR"
  IIiii11iiI111 . append ( II1 )
  if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
  if 82 - 82: OOooOOo . oO0o
 for Ii1I1I11I11 in i111 :
  O0oo0OOo00o0o = lisp_mapping ( Ii1I1I11I11 [ 0 ] , Ii1I1I11I11 [ 1 ] , IIiii11iiI111 )
  O0oo0OOo00o0o . mapping_source = map_resolver
  O0oo0OOo00o0o . map_cache_ttl = LISP_MR_TTL * 60
  O0oo0OOo00o0o . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( O0oo0OOo00o0o . print_eid_tuple ( ) , False ) , list ( rtr_list . keys ( ) ) ) )
  if 12 - 12: i11iIiiIii + II111iiii
  IIiii11iiI111 = copy . deepcopy ( IIiii11iiI111 )
  if 49 - 49: OoooooooOO
 return
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
def lisp_process_info_reply ( source , packet , store ) :
 if 64 - 64: OOooOOo / OoOoOO00
 if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
 if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
 if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
 ii1i1i1i1 = lisp_info ( )
 packet = ii1i1i1i1 . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
 ii1i1i1i1 . print_info ( )
 if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
 if 49 - 49: IiII
 if 1 - 1: oO0o / I11i
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 I1Ii1i1ii = False
 for i1I1IIIi11I in ii1i1i1i1 . rtr_list :
  Oo0o = i1I1IIIi11I . print_address_no_iid ( )
  if ( Oo0o in lisp_rtr_list ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ Oo0o ] != None ) : continue
   if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
  I1Ii1i1ii = True
  lisp_rtr_list [ Oo0o ] = i1I1IIIi11I
  if 24 - 24: O0
  if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
  if 65 - 65: i11iIiiIii
  if 46 - 46: i11iIiiIii
  if 70 - 70: i1IIi + o0oOOo0O0Ooo
 if ( lisp_i_am_itr and I1Ii1i1ii ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for i1oO00O in list ( lisp_iid_to_interface . keys ( ) ) :
    lisp_update_default_routes ( source , int ( i1oO00O ) , lisp_rtr_list )
    if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
    if 29 - 29: i11iIiiIii * i1IIi
    if 36 - 36: OoO0O00 * I11i . ooOoO0o
    if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
    if 55 - 55: II111iiii - IiII
    if 24 - 24: oO0o % Ii1I / i1IIi
    if 84 - 84: i1IIi
 if ( store == False ) :
  return ( [ ii1i1i1i1 . global_etr_rloc , ii1i1i1i1 . etr_port , I1Ii1i1ii ] )
  if 53 - 53: OoooooooOO - i1IIi - Ii1I
  if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
  if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
  if 34 - 34: Ii1I
  if 5 - 5: II111iiii . I1ii11iIi11i
  if 85 - 85: I1Ii111 . IiII + II111iiii
 for iIiI1ii in lisp_db_list :
  for II1 in iIiI1ii . rloc_set :
   OooOOoOO0OO = II1 . rloc
   i1i1111I = II1 . interface
   if ( i1i1111I == None ) :
    if ( OooOOoOO0OO . is_null ( ) ) : continue
    if ( OooOOoOO0OO . is_local ( ) == False ) : continue
    if ( ii1i1i1i1 . private_etr_rloc . is_null ( ) == False and
 OooOOoOO0OO . is_exact_match ( ii1i1i1i1 . private_etr_rloc ) == False ) :
     continue
     if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
   elif ( ii1i1i1i1 . private_etr_rloc . is_dist_name ( ) ) :
    oOo = ii1i1i1i1 . private_etr_rloc . address
    if ( oOo != II1 . rloc_name ) : continue
    if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
    if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
   iIiI1I1ii1I1 = green ( iIiI1ii . eid . print_prefix ( ) , False )
   o00oO = red ( OooOOoOO0OO . print_address_no_iid ( ) , False )
   if 87 - 87: OOooOOo
   iIiIIi1 = ii1i1i1i1 . global_etr_rloc . is_exact_match ( OooOOoOO0OO )
   if ( II1 . translated_port == 0 and iIiIIi1 ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( o00oO ,
 i1i1111I , iIiI1I1ii1I1 ) )
    continue
    if 23 - 23: ooOoO0o * II111iiii . II111iiii % I1Ii111
    if 69 - 69: I1ii11iIi11i * IiII / II111iiii
    if 10 - 10: O0 / I11i
    if 29 - 29: i11iIiiIii % I11i
    if 49 - 49: I11i
   oO0I1iIii11iI1I = ii1i1i1i1 . global_etr_rloc
   Oo0O0oOO = II1 . translated_rloc
   if ( Oo0O0oOO . is_exact_match ( oO0I1iIii11iI1I ) and
 ii1i1i1i1 . etr_port == II1 . translated_port ) : continue
   if 61 - 61: I1IiiI * O0 . II111iiii
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( ii1i1i1i1 . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # I1ii11iIi11i * O0 * O0 % OoooooooOO % I11i
 ii1i1i1i1 . etr_port , o00oO , i1i1111I , iIiI1I1ii1I1 ) )
   if 48 - 48: Ii1I
   II1 . store_translated_rloc ( ii1i1i1i1 . global_etr_rloc ,
 ii1i1i1i1 . etr_port )
   if 32 - 32: O0
   if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
 return ( [ ii1i1i1i1 . global_etr_rloc , ii1i1i1i1 . etr_port , I1Ii1i1ii ] )
 if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
 if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
 if 70 - 70: iIii1I11I1II1 - I11i
 if 2 - 2: oO0o / II111iiii * OoO0O00
 if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
 if 40 - 40: OOooOOo
 if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
 if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
 I11I = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 I1iii1Ii1I = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 68 - 68: ooOoO0o - O0 + Ii1I / I1IiiI + Ii1I * OOooOOo
 if 14 - 14: I1ii11iIi11i / i1IIi . ooOoO0o % OoO0O00 * OoO0O00 + oO0o
 if 65 - 65: Oo0Ooo % iIii1I11I1II1
 if 40 - 40: iII111i + Ii1I . OoooooooOO . i1IIi
 I11I . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , I11I , None )
 I11I . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , I11I , None )
 if 7 - 7: I1ii11iIi11i - Ii1I % Ii1I
 if 75 - 75: O0 . II111iiii + Oo0Ooo * O0 - IiII % OoOoOO00
 if 85 - 85: I1Ii111 - Ii1I . I1ii11iIi11i - OoooooooOO
 if 10 - 10: Ii1I . iII111i
 I1iii1Ii1I . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , I1iii1Ii1I , None )
 I1iii1Ii1I . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , I1iii1Ii1I , None )
 if 62 - 62: o0oOOo0O0Ooo + OoooooooOO + IiII
 if 98 - 98: OoO0O00 . o0oOOo0O0Ooo + ooOoO0o + OOooOOo + oO0o
 if 29 - 29: i11iIiiIii - I11i
 if 94 - 94: Oo0Ooo
 I11II1I1I = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 I11II1I1I . start ( )
 return
 if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
 if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
 if 58 - 58: II111iiii * oO0o - i1IIi . I11i
 if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
 if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
 if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
 if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
 if 31 - 31: i1IIi * Ii1I
 if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
 if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
 if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
 if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
 if 15 - 15: oO0o
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
 oOOOo0o = lisp_get_interface_address ( rloc . interface )
 if ( oOOOo0o == None ) : return
 if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
 oOoO0o = rloc . rloc . print_address_no_iid ( )
 iiiiIIiiII1Iii1 = oOOOo0o . print_address_no_iid ( )
 if 85 - 85: OoooooooOO % OoOoOO00 + OoOoOO00 / iIii1I11I1II1
 if ( oOoO0o == iiiiIIiiII1Iii1 ) : return
 if 70 - 70: oO0o . i11iIiiIii
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , oOoO0o , iiiiIIiiII1Iii1 ) )
 if 7 - 7: iII111i * i11iIiiIii + Oo0Ooo - Ii1I
 if 80 - 80: I11i + o0oOOo0O0Ooo * Ii1I
 rloc . rloc . copy_address ( oOOOo0o )
 lisp_myrlocs [ 0 ] = oOOOo0o
 return
 if 48 - 48: oO0o . iII111i
 if 51 - 51: I1Ii111 . OoO0O00 + I1IiiI . o0oOOo0O0Ooo
 if 55 - 55: o0oOOo0O0Ooo + Ii1I % ooOoO0o
 if 41 - 41: OoO0O00 - I11i . I1Ii111 % i1IIi . I11i . II111iiii
 if 6 - 6: i11iIiiIii - Oo0Ooo
 if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
 if 20 - 20: IiII / OoooooooOO / O0 / I1Ii111 * ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
def lisp_update_encap_port ( mc ) :
 for OooOOoOO0OO in mc . rloc_set :
  iII1II1 = lisp_get_nat_info ( OooOOoOO0OO . rloc , OooOOoOO0OO . rloc_name )
  if ( iII1II1 == None ) : continue
  if ( OooOOoOO0OO . translated_port == iII1II1 . port ) : continue
  if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( OooOOoOO0OO . translated_port , iII1II1 . port ,
  # oO0o % II111iiii + Ii1I % Ii1I - OoO0O00
 red ( OooOOoOO0OO . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 27 - 27: I1Ii111 / I11i . I11i % I1Ii111 . I1Ii111
  OooOOoOO0OO . store_translated_rloc ( OooOOoOO0OO . rloc , iII1II1 . port )
  if 80 - 80: o0oOOo0O0Ooo - o0oOOo0O0Ooo % I11i / ooOoO0o / IiII
 return
 if 37 - 37: I1IiiI % I1ii11iIi11i / OoooooooOO - OoO0O00 . I1ii11iIi11i
 if 15 - 15: I11i / oO0o * ooOoO0o . o0oOOo0O0Ooo + I1ii11iIi11i
 if 35 - 35: i11iIiiIii
 if 71 - 71: O0 - OoooooooOO
 if 82 - 82: i11iIiiIii * II111iiii % IiII
 if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
 if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
 if 67 - 67: iII111i
 if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
 if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
 if 60 - 60: i1IIi / iII111i
 if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 2 - 2: iIii1I11I1II1
  if 85 - 85: O0 - ooOoO0o
 iiI1 = lisp_get_timestamp ( )
 if 35 - 35: o0oOOo0O0Ooo - I1IiiI
 if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
 if 65 - 65: Ii1I % i11iIiiIii
 if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
 if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
 if ( mc . last_refresh_time + mc . map_cache_ttl > iiI1 ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 88 - 88: iII111i
  if 94 - 94: OoooooooOO
  if 32 - 32: I1ii11iIi11i
  if 8 - 8: I11i * i11iIiiIii - ooOoO0o
  if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
  if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
  if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
  if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
  if 42 - 42: II111iiii . iII111i
 Ii1i1 = lisp_print_elapsed ( mc . last_refresh_time )
 oOo00OO0ooo = mc . print_eid_tuple ( )
 lprint ( "Map-cache entry for EID-prefix {} has {}, had uptime of {}" . format ( green ( oOo00OO0ooo , False ) , bold ( "timed out" , False ) , Ii1i1 ) )
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 if 64 - 64: oO0o / IiII
 if 86 - 86: I11i
 if 36 - 36: o0oOOo0O0Ooo / OoO0O00
 if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
 if 86 - 86: i11iIiiIii
 if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
def lisp_timeout_map_cache_walk ( mc , parms ) :
 oo0Oo00OO0000 = parms [ 0 ]
 o0ooOOo0O = parms [ 1 ]
 if 84 - 84: OOooOOo / Oo0Ooo - O0 + IiII
 if 11 - 11: IiII * OoO0O00 * Ii1I - oO0o
 if 2 - 2: OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 if ( mc . group . is_null ( ) ) :
  i1iII1iI , oo0Oo00OO0000 = lisp_timeout_map_cache_entry ( mc , oo0Oo00OO0000 )
  if ( oo0Oo00OO0000 == [ ] or mc != oo0Oo00OO0000 [ - 1 ] ) :
   o0ooOOo0O = lisp_write_checkpoint_entry ( o0ooOOo0O , mc )
   if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
  return ( [ i1iII1iI , parms ] )
  if 10 - 10: i1IIi + o0oOOo0O0Ooo
  if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 parms = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , parms )
 return ( [ True , parms ] )
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
 if 16 - 16: i11iIiiIii * Oo0Ooo
 if 76 - 76: iII111i . oO0o - i1IIi
def lisp_timeout_map_cache ( lisp_map_cache ) :
 I1iI1i11IiI11 = [ [ ] , [ ] ]
 I1iI1i11IiI11 = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , I1iI1i11IiI11 )
 if 94 - 94: O0 % iII111i
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 oo0Oo00OO0000 = I1iI1i11IiI11 [ 0 ]
 for O0oo0OOo00o0o in oo0Oo00OO0000 : O0oo0OOo00o0o . delete_cache ( )
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
 if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
 if 28 - 28: OoooooooOO + OoooooooOO
 o0ooOOo0O = I1iI1i11IiI11 [ 1 ]
 lisp_checkpoint ( o0ooOOo0O )
 return
 if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
 if 15 - 15: II111iiii * OoO0O00
 if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
 if 58 - 58: Ii1I
 if 20 - 20: OOooOOo
 if 93 - 93: i1IIi . IiII % O0 * iII111i
 if 84 - 84: I11i
 if 99 - 99: I1ii11iIi11i
 if 78 - 78: I1Ii111 . IiII - OOooOOo
 if 93 - 93: iIii1I11I1II1
 if 33 - 33: OOooOOo . i1IIi
 if 63 - 63: II111iiii . oO0o * IiII
 if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
 if 47 - 47: I11i
 if 88 - 88: OoO0O00 - OoooooooOO
 if 93 - 93: Oo0Ooo * I1IiiI
def lisp_store_nat_info ( hostname , rloc , port ) :
 Oo0o = rloc . print_address_no_iid ( )
 o0000OO = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( Oo0o , False ) , port )
 if 46 - 46: oO0o . O0 % iIii1I11I1II1 - iIii1I11I1II1 . O0
 Ooo0OO0 = lisp_nat_info ( Oo0o , hostname , port )
 if 24 - 24: iIii1I11I1II1 . I11i
 if ( hostname not in lisp_nat_state_info ) :
  lisp_nat_state_info [ hostname ] = [ Ooo0OO0 ]
  lprint ( o0000OO . format ( "Store initial" ) )
  return ( True )
  if 47 - 47: i11iIiiIii
  if 92 - 92: I1Ii111 + OoO0O00 - iIii1I11I1II1 / iIii1I11I1II1
  if 32 - 32: iII111i * iIii1I11I1II1 + I1Ii111 + IiII + O0 * OoO0O00
  if 100 - 100: II111iiii
  if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
  if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 iII1II1 = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( iII1II1 . address == Oo0o and iII1II1 . port == port ) :
  iII1II1 . uptime = lisp_get_timestamp ( )
  lprint ( o0000OO . format ( "Refresh existing" ) )
  return ( False )
  if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
  if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
  if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
  if 40 - 40: o0oOOo0O0Ooo * I1IiiI
  if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
  if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
  if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
 IIi = None
 for iII1II1 in lisp_nat_state_info [ hostname ] :
  if ( iII1II1 . address == Oo0o and iII1II1 . port == port ) :
   IIi = iII1II1
   break
   if 55 - 55: OoOoOO00 % iIii1I11I1II1 . I1IiiI - OoooooooOO . Oo0Ooo % iIii1I11I1II1
   if 38 - 38: I11i / i11iIiiIii * IiII . OOooOOo
   if 79 - 79: I1Ii111 - OOooOOo - OoOoOO00
 if ( IIi == None ) :
  lprint ( o0000OO . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( IIi )
  lprint ( o0000OO . format ( "Use previous" ) )
  if 29 - 29: OoooooooOO - i1IIi % OoooooooOO * o0oOOo0O0Ooo / II111iiii
  if 38 - 38: i1IIi % o0oOOo0O0Ooo - Oo0Ooo
 I1Ooo0O = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ Ooo0OO0 ] + I1Ooo0O
 return ( True )
 if 70 - 70: oO0o / iIii1I11I1II1 * II111iiii - iIii1I11I1II1 / ooOoO0o
 if 26 - 26: I1ii11iIi11i * Ii1I / I1IiiI
 if 10 - 10: I11i - iII111i / I1ii11iIi11i * i11iIiiIii % II111iiii % OoOoOO00
 if 98 - 98: OoooooooOO * IiII . OoOoOO00
 if 46 - 46: ooOoO0o / OOooOOo * I1Ii111 % OoOoOO00 . ooOoO0o - i1IIi
 if 11 - 11: OoOoOO00 - II111iiii + I1Ii111 + IiII + OOooOOo - ooOoO0o
 if 12 - 12: Ii1I - oO0o % I1ii11iIi11i / oO0o
 if 14 - 14: OOooOOo * iII111i . IiII + i1IIi % i1IIi
def lisp_get_nat_info ( rloc , hostname ) :
 if ( hostname not in lisp_nat_state_info ) : return ( None )
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 Oo0o = rloc . print_address_no_iid ( )
 for iII1II1 in lisp_nat_state_info [ hostname ] :
  if ( iII1II1 . address == Oo0o ) : return ( iII1II1 )
  if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
 return ( None )
 if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 if 70 - 70: I1IiiI
 if 35 - 35: i11iIiiIii
 if 59 - 59: ooOoO0o . iII111i - II111iiii
 if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
 if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
 if 55 - 55: OoooooooOO
 if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
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
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
 if 36 - 36: II111iiii
 if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
 if 7 - 7: i11iIiiIii
 if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
 if 41 - 41: IiII % II111iiii
 o0oOO00O = [ ]
 I1iI111iIi = [ ]
 if ( dest == None ) :
  for OO0O0O0OOO0OO in list ( lisp_map_resolvers_list . values ( ) ) :
   I1iI111iIi . append ( OO0O0O0OOO0OO . map_resolver )
   if 57 - 57: I1ii11iIi11i + o0oOOo0O0Ooo
  o0oOO00O = I1iI111iIi
  if ( o0oOO00O == [ ] ) :
   for IIiiIiI in list ( lisp_map_servers_list . values ( ) ) :
    o0oOO00O . append ( IIiiIiI . map_server )
    if 23 - 23: iIii1I11I1II1 + I1ii11iIi11i * ooOoO0o - OOooOOo % O0
    if 47 - 47: O0 - II111iiii
  if ( o0oOO00O == [ ] ) : return
 else :
  o0oOO00O . append ( dest )
  if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
  if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
  if 74 - 74: I11i . I11i
  if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
  if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
 O000Ooo0 = { }
 for iIiI1ii in lisp_db_list :
  for II1 in iIiI1ii . rloc_set :
   lisp_update_local_rloc ( II1 )
   if ( II1 . rloc . is_null ( ) ) : continue
   if ( II1 . interface == None ) : continue
   if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
   oOOOo0o = II1 . rloc . print_address_no_iid ( )
   if ( oOOOo0o in O000Ooo0 ) : continue
   O000Ooo0 [ oOOOo0o ] = II1 . interface
   if 13 - 13: O0 * iII111i
   if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
 if ( O000Ooo0 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
  return
  if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
  if 47 - 47: I1Ii111 * iII111i
  if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
  if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
  if 51 - 51: I1IiiI
  if 52 - 52: I1Ii111
 for oOOOo0o in O000Ooo0 :
  i1i1111I = O000Ooo0 [ oOOOo0o ]
  OoOOOO = red ( oOOOo0o , False )
  lprint ( "Build Info-Request for private address {} ({})" . format ( OoOOOO ,
 i1i1111I ) )
  OoO0 = i1i1111I if len ( O000Ooo0 ) > 1 else None
  for dest in o0oOO00O :
   lisp_send_info_request ( lisp_sockets , dest , port , OoO0 )
   if 82 - 82: iII111i + II111iiii
   if 29 - 29: O0 % Ii1I * ooOoO0o % O0
   if 83 - 83: oO0o
   if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
   if 85 - 85: iIii1I11I1II1 / I11i
   if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
 if ( I1iI111iIi != [ ] ) :
  for OO0O0O0OOO0OO in list ( lisp_map_resolvers_list . values ( ) ) :
   OO0O0O0OOO0OO . resolve_dns_name ( )
   if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
   if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
 return
 if 89 - 89: ooOoO0o
 if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
 if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
 if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
 if 20 - 20: I11i
 if 37 - 37: I1Ii111
 if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
 if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 41 - 41: O0 / OoooooooOO - i1IIi
 if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 if 32 - 32: oO0o / IiII - I11i . ooOoO0o
 if 69 - 69: i11iIiiIii * i11iIiiIii
 if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
 if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
 if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
 if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
 if ( value . find ( "." ) != - 1 ) :
  oOOOo0o = value . split ( "." )
  if ( len ( oOOOo0o ) != 4 ) : return ( False )
  if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
  for Oo0 in oOOOo0o :
   if ( Oo0 . isdigit ( ) == False ) : return ( False )
   if ( int ( Oo0 ) > 255 ) : return ( False )
   if 17 - 17: oO0o + I1Ii111 . IiII % OoOoOO00 % Ii1I % Ii1I
  return ( True )
  if 67 - 67: O0 + Ii1I % Oo0Ooo % OoooooooOO / iIii1I11I1II1
  if 25 - 25: IiII
  if 10 - 10: Oo0Ooo / I11i * ooOoO0o - I1Ii111 / iII111i - O0
  if 28 - 28: OOooOOo - oO0o
  if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
 if ( value . find ( "-" ) != - 1 ) :
  oOOOo0o = value . split ( "-" )
  for OoOOoO0oOo in [ "N" , "S" , "W" , "E" ] :
   if ( OoOOoO0oOo in oOOOo0o ) :
    if ( len ( oOOOo0o ) < 8 ) : return ( False )
    return ( True )
    if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
    if 73 - 73: OoooooooOO
    if 25 - 25: i1IIi . II111iiii . I1Ii111
    if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
    if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
    if 61 - 61: I1ii11iIi11i
    if 12 - 12: OoO0O00
 if ( value . find ( "-" ) != - 1 ) :
  oOOOo0o = value . split ( "-" )
  if ( len ( oOOOo0o ) != 3 ) : return ( False )
  if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
  for iIiIII in oOOOo0o :
   try : int ( iIiIII , 16 )
   except : return ( False )
   if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
  return ( True )
  if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
  if 3 - 3: Ii1I
  if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
  if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
  if 86 - 86: Oo0Ooo
 if ( value . find ( ":" ) != - 1 ) :
  oOOOo0o = value . split ( ":" )
  if ( len ( oOOOo0o ) < 2 ) : return ( False )
  if 97 - 97: I1IiiI
  O00O = False
  IiI = 0
  for iIiIII in oOOOo0o :
   IiI += 1
   if ( iIiIII == "" ) :
    if ( O00O ) :
     if ( len ( oOOOo0o ) == IiI ) : break
     if ( IiI > 2 ) : return ( False )
     if 15 - 15: II111iiii - I11i - i11iIiiIii % Oo0Ooo * O0
    O00O = True
    continue
    if 46 - 46: i11iIiiIii * ooOoO0o
   try : int ( iIiIII , 16 )
   except : return ( False )
   if 36 - 36: OoOoOO00
  return ( True )
  if 63 - 63: ooOoO0o
  if 83 - 83: Oo0Ooo % I1IiiI % I11i
  if 54 - 54: Oo0Ooo . oO0o * I11i . i1IIi / Oo0Ooo
  if 28 - 28: I1IiiI - I1IiiI % I11i * OOooOOo
  if 97 - 97: iII111i
 if ( value [ 0 ] == "+" ) :
  oOOOo0o = value [ 1 : : ]
  for I1iI1I in oOOOo0o :
   if ( I1iI1I . isdigit ( ) == False ) : return ( False )
   if 91 - 91: I11i / OOooOOo - OoooooooOO - I1ii11iIi11i - i1IIi
  return ( True )
  if 53 - 53: o0oOOo0O0Ooo - I11i . I11i + OoooooooOO
 return ( False )
 if 6 - 6: II111iiii + I1Ii111
 if 17 - 17: iIii1I11I1II1 / I1ii11iIi11i
 if 85 - 85: o0oOOo0O0Ooo
 if 20 - 20: OoooooooOO . ooOoO0o + ooOoO0o
 if 7 - 7: OoO0O00 / IiII - OoO0O00 . OOooOOo
 if 56 - 56: iIii1I11I1II1 / O0 + Oo0Ooo
 if 5 - 5: O0 / i11iIiiIii * I1IiiI % IiII * OoO0O00
 if 67 - 67: I1Ii111 . iII111i + Oo0Ooo / i11iIiiIii
 if 47 - 47: iII111i
 if 16 - 16: OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
 if 60 - 60: OOooOOo . Ii1I
 if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
def lisp_process_api ( process , lisp_socket , data_structure ) :
 OO00oOoOOo0 , I1iI1i11IiI11 = data_structure . split ( "%" )
 if 28 - 28: IiII * II111iiii * oO0o . OoooooooOO / i1IIi
 lprint ( "Process API request '{}', parameters: '{}'" . format ( OO00oOoOOo0 ,
 I1iI1i11IiI11 ) )
 if 89 - 89: iII111i * oO0o . iIii1I11I1II1
 oO00Oo0OO = [ ]
 if ( OO00oOoOOo0 == "map-cache" ) :
  if ( I1iI1i11IiI11 == "" ) :
   oO00Oo0OO = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , oO00Oo0OO )
  else :
   oO00Oo0OO = lisp_process_api_map_cache_entry ( json . loads ( I1iI1i11IiI11 ) )
   if 50 - 50: iIii1I11I1II1 * iIii1I11I1II1
   if 20 - 20: OoOoOO00
 if ( OO00oOoOOo0 == "site-cache" ) :
  if ( I1iI1i11IiI11 == "" ) :
   oO00Oo0OO = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 oO00Oo0OO )
  else :
   oO00Oo0OO = lisp_process_api_site_cache_entry ( json . loads ( I1iI1i11IiI11 ) )
   if 86 - 86: OoooooooOO - iIii1I11I1II1 . OoO0O00 * Ii1I / I1Ii111 + I1Ii111
   if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
 if ( OO00oOoOOo0 == "site-cache-summary" ) :
  oO00Oo0OO = lisp_process_api_site_cache_summary ( lisp_sites_by_eid )
  if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
 if ( OO00oOoOOo0 == "map-server" ) :
  I1iI1i11IiI11 = { } if ( I1iI1i11IiI11 == "" ) else json . loads ( I1iI1i11IiI11 )
  oO00Oo0OO = lisp_process_api_ms_or_mr ( True , I1iI1i11IiI11 )
  if 54 - 54: OoOoOO00 / i1IIi + OOooOOo - I1ii11iIi11i - I1IiiI * I1Ii111
 if ( OO00oOoOOo0 == "map-resolver" ) :
  I1iI1i11IiI11 = { } if ( I1iI1i11IiI11 == "" ) else json . loads ( I1iI1i11IiI11 )
  oO00Oo0OO = lisp_process_api_ms_or_mr ( False , I1iI1i11IiI11 )
  if 91 - 91: OoooooooOO * OoooooooOO
 if ( OO00oOoOOo0 == "database-mapping" ) :
  oO00Oo0OO = lisp_process_api_database_mapping ( )
  if 27 - 27: ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
  if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
  if 33 - 33: OOooOOo % OoooooooOO
  if 98 - 98: Ii1I
  if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
 oO00Oo0OO = json . dumps ( oO00Oo0OO )
 ii1I11Iii = lisp_api_ipc ( process , oO00Oo0OO )
 lisp_ipc ( ii1I11Iii , lisp_socket , "lisp-core" )
 return
 if 95 - 95: iIii1I11I1II1 / O0 % O0
 if 53 - 53: ooOoO0o . ooOoO0o
 if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
 if 18 - 18: OoO0O00 * ooOoO0o
 if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
 if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
 if 67 - 67: I1IiiI
def lisp_process_api_map_cache ( mc , data ) :
 if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
 if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
 if 59 - 59: i11iIiiIii
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 59 - 59: I1ii11iIi11i
 if 47 - 47: I1IiiI + Oo0Ooo
 if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 if 98 - 98: IiII / o0oOOo0O0Ooo - i1IIi - OOooOOo
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 65 - 65: Ii1I + OoOoOO00 * Oo0Ooo . O0 . IiII
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
 if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
 if 58 - 58: IiII . Ii1I + II111iiii
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
def lisp_gather_map_cache_data ( mc , data ) :
 iIiiI11II11i = { }
 iIiiI11II11i [ "instance-id" ] = str ( mc . eid . instance_id )
 iIiiI11II11i [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  iIiiI11II11i [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 iIiiI11II11i [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 iIiiI11II11i [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 iIiiI11II11i [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 iIiiI11II11i [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 IIiii11iiI111 = [ ]
 for OooOOoOO0OO in mc . rloc_set :
  I1I1iIiiiiII11 = lisp_fill_rloc_in_json ( OooOOoOO0OO )
  if 54 - 54: oO0o * II111iiii
  if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
  if 98 - 98: ooOoO0o
  if 73 - 73: I1Ii111
  if 97 - 97: OoO0O00 * Ii1I + Oo0Ooo
  if ( OooOOoOO0OO . rloc . is_multicast_address ( ) ) :
   I1I1iIiiiiII11 [ "multicast-rloc-set" ] = [ ]
   for I1iiI in list ( OooOOoOO0OO . multicast_rloc_probe_list . values ( ) ) :
    OO0O0O0OOO0OO = lisp_fill_rloc_in_json ( I1iiI )
    I1I1iIiiiiII11 [ "multicast-rloc-set" ] . append ( OO0O0O0OOO0OO )
    if 83 - 83: II111iiii - Oo0Ooo % II111iiii * o0oOOo0O0Ooo
    if 51 - 51: iII111i * iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . OoooooooOO
    if 54 - 54: i11iIiiIii . iIii1I11I1II1 * iIii1I11I1II1 + Ii1I % I11i - OoO0O00
  IIiii11iiI111 . append ( I1I1iIiiiiII11 )
  if 16 - 16: IiII % iIii1I11I1II1 * i11iIiiIii + O0
 iIiiI11II11i [ "rloc-set" ] = IIiii11iiI111
 if 76 - 76: iII111i * OOooOOo
 data . append ( iIiiI11II11i )
 return ( [ True , data ] )
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if 40 - 40: iII111i
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
 if 59 - 59: i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
 if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
def lisp_fill_rloc_in_json ( rloc ) :
 I1I1iIiiiiII11 = { }
 if ( rloc . rloc_exists ( ) ) :
  I1I1iIiiiiII11 [ "address" ] = rloc . rloc . print_address_no_iid ( )
  if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
  if 5 - 5: Oo0Ooo . I1Ii111
 if ( rloc . translated_port != 0 ) :
  I1I1iIiiiiII11 [ "encap-port" ] = str ( rloc . translated_port )
  if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
 I1I1iIiiiiII11 [ "state" ] = rloc . print_state ( )
 if ( rloc . geo ) : I1I1iIiiiiII11 [ "geo" ] = rloc . geo . print_geo ( )
 if ( rloc . elp ) : I1I1iIiiiiII11 [ "elp" ] = rloc . elp . print_elp ( False )
 if ( rloc . rle ) : I1I1iIiiiiII11 [ "rle" ] = rloc . rle . print_rle ( False , False )
 if ( rloc . json ) : I1I1iIiiiiII11 [ "json" ] = rloc . json . print_json ( False )
 if ( rloc . rloc_name ) : I1I1iIiiiiII11 [ "rloc-name" ] = rloc . rloc_name
 OO000 = rloc . stats . get_stats ( False , False )
 if ( OO000 ) : I1I1iIiiiiII11 [ "stats" ] = OO000
 I1I1iIiiiiII11 [ "uptime" ] = lisp_print_elapsed ( rloc . uptime )
 I1I1iIiiiiII11 [ "upriority" ] = str ( rloc . priority )
 I1I1iIiiiiII11 [ "uweight" ] = str ( rloc . weight )
 I1I1iIiiiiII11 [ "mpriority" ] = str ( rloc . mpriority )
 I1I1iIiiiiII11 [ "mweight" ] = str ( rloc . mweight )
 O0ooOO0ooOo = rloc . last_rloc_probe_reply
 if ( O0ooOO0ooOo ) :
  I1I1iIiiiiII11 [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( O0ooOO0ooOo )
  I1I1iIiiiiII11 [ "rloc-probe-rtt" ] = str ( rloc . rloc_probe_rtt )
  if 33 - 33: OoooooooOO * i1IIi / O0 * I1ii11iIi11i
 I1I1iIiiiiII11 [ "rloc-hop-count" ] = rloc . rloc_probe_hops
 I1I1iIiiiiII11 [ "recent-rloc-hop-counts" ] = rloc . recent_rloc_probe_hops
 if 55 - 55: o0oOOo0O0Ooo * Oo0Ooo . ooOoO0o
 I1I1iIiiiiII11 [ "rloc-probe-latency" ] = rloc . rloc_probe_latency
 I1I1iIiiiiII11 [ "recent-rloc-probe-latencies" ] = rloc . recent_rloc_probe_latencies
 if 25 - 25: IiII . O0 / OoOoOO00
 iIiI111 = [ ]
 for oOoOo0 in rloc . recent_rloc_probe_rtts : iIiI111 . append ( str ( oOoOo0 ) )
 I1I1iIiiiiII11 [ "recent-rloc-probe-rtts" ] = iIiI111
 return ( I1I1iIiiiiII11 )
 if 94 - 94: II111iiii - Ii1I / II111iiii - o0oOOo0O0Ooo
 if 34 - 34: O0 / I1Ii111
 if 56 - 56: iII111i . O0 + OoO0O00 - I1ii11iIi11i
 if 37 - 37: Oo0Ooo
 if 3 - 3: Oo0Ooo
 if 73 - 73: i11iIiiIii / iII111i + O0 * I1IiiI * i1IIi
 if 75 - 75: iIii1I11I1II1 / II111iiii / I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
def lisp_process_api_map_cache_entry ( parms ) :
 i1oO00O = parms [ "instance-id" ]
 i1oO00O = 0 if ( i1oO00O == "" ) else int ( i1oO00O )
 if 16 - 16: I11i
 if 55 - 55: OoO0O00
 if 87 - 87: Ii1I - iII111i / O0 - o0oOOo0O0Ooo - iIii1I11I1II1 % Ii1I
 if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 I11I = lisp_address ( LISP_AFI_NONE , "" , 0 , i1oO00O )
 I11I . store_prefix ( parms [ "eid-prefix" ] )
 OooOOooo = I11I
 OO = I11I
 if 43 - 43: Oo0Ooo
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
 o0o0o = lisp_address ( LISP_AFI_NONE , "" , 0 , i1oO00O )
 if ( "group-prefix" in parms ) :
  o0o0o . store_prefix ( parms [ "group-prefix" ] )
  OooOOooo = o0o0o
  if 66 - 66: o0oOOo0O0Ooo
  if 40 - 40: OOooOOo * Ii1I
 oO00Oo0OO = [ ]
 O0oo0OOo00o0o = lisp_map_cache_lookup ( OO , OooOOooo )
 if ( O0oo0OOo00o0o ) : i1iII1iI , oO00Oo0OO = lisp_process_api_map_cache ( O0oo0OOo00o0o , oO00Oo0OO )
 return ( oO00Oo0OO )
 if 38 - 38: ooOoO0o
 if 5 - 5: OoooooooOO + iII111i - I11i
 if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
 if 7 - 7: I1ii11iIi11i
 if 37 - 37: O0 . II111iiii
 if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
 if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
 if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
 if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
 if 74 - 74: I1ii11iIi11i * OoooooooOO . iII111i
 if 45 - 45: I1IiiI - IiII % ooOoO0o - IiII . Oo0Ooo - o0oOOo0O0Ooo
def lisp_process_api_site_cache_summary ( site_cache ) :
 i1iIiII1II11i = { "site" : "" , "registrations" : [ ] }
 iIiiI11II11i = { "eid-prefix" : "" , "count" : 0 , "registered-count" : 0 }
 if 27 - 27: iII111i
 Ooo000oO0 = { }
 for O00o00 in site_cache . cache_sorted :
  for Ii1iIi1I1I1I in list ( site_cache . cache [ O00o00 ] . entries . values ( ) ) :
   if ( Ii1iIi1I1I1I . accept_more_specifics == False ) : continue
   if ( Ii1iIi1I1I1I . site . site_name not in Ooo000oO0 ) :
    Ooo000oO0 [ Ii1iIi1I1I1I . site . site_name ] = [ ]
    if 28 - 28: iIii1I11I1II1 * OoooooooOO
   I1i = copy . deepcopy ( iIiiI11II11i )
   I1i [ "eid-prefix" ] = Ii1iIi1I1I1I . eid . print_prefix ( )
   I1i [ "count" ] = len ( Ii1iIi1I1I1I . more_specific_registrations )
   for OO0ooO0OOo in Ii1iIi1I1I1I . more_specific_registrations :
    if ( OO0ooO0OOo . registered ) : I1i [ "registered-count" ] += 1
    if 96 - 96: O0 / I11i / IiII - I1Ii111 / I11i / I11i
   Ooo000oO0 [ Ii1iIi1I1I1I . site . site_name ] . append ( I1i )
   if 19 - 19: OoOoOO00
   if 98 - 98: I1IiiI % iII111i * OOooOOo - I1ii11iIi11i
   if 27 - 27: OOooOOo % oO0o . i1IIi + i1IIi % I1ii11iIi11i
 oO00Oo0OO = [ ]
 for iii11i1i1II11 in Ooo000oO0 :
  I1iiIi111I = copy . deepcopy ( i1iIiII1II11i )
  I1iiIi111I [ "site" ] = iii11i1i1II11
  I1iiIi111I [ "registrations" ] = Ooo000oO0 [ iii11i1i1II11 ]
  oO00Oo0OO . append ( I1iiIi111I )
  if 38 - 38: i1IIi . I1IiiI + II111iiii * OoO0O00 / IiII
 return ( oO00Oo0OO )
 if 60 - 60: II111iiii
 if 68 - 68: O0 / I1IiiI / OoOoOO00 / iIii1I11I1II1 % O0 + I1IiiI
 if 23 - 23: OoooooooOO . OoO0O00 . OoooooooOO * I1ii11iIi11i - Oo0Ooo - iIii1I11I1II1
 if 91 - 91: iIii1I11I1II1 * Ii1I
 if 37 - 37: I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
def lisp_process_api_site_cache ( se , data ) :
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 2 - 2: I11i - II111iiii / I1Ii111
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
 if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
 if 76 - 76: ooOoO0o . I11i * OoO0O00
 if 53 - 53: II111iiii / OoOoOO00 / IiII * oO0o
 if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 93 - 93: iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1 . oO0o % Oo0Ooo
 if 92 - 92: OoO0O00
 if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 % ooOoO0o
 if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
 if 38 - 38: o0oOOo0O0Ooo . O0 - OoO0O00 % I11i
 if 80 - 80: o0oOOo0O0Ooo
 if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 Ii1IiIIIi = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 II1OO = data [ "dns-name" ] if ( "dns-name" in data ) else None
 if ( "address" in data ) :
  Ii1IiIIIi . store_address ( data [ "address" ] )
  if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
  if 15 - 15: I1Ii111
 iiIiII11i1 = { }
 if ( ms_or_mr ) :
  for IIiiIiI in list ( lisp_map_servers_list . values ( ) ) :
   if ( II1OO ) :
    if ( II1OO != IIiiIiI . dns_name ) : continue
   else :
    if ( Ii1IiIIIi . is_exact_match ( IIiiIiI . map_server ) == False ) : continue
    if 38 - 38: O0
    if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
   iiIiII11i1 [ "dns-name" ] = IIiiIiI . dns_name
   iiIiII11i1 [ "address" ] = IIiiIiI . map_server . print_address_no_iid ( )
   iiIiII11i1 [ "ms-name" ] = "" if IIiiIiI . ms_name == None else IIiiIiI . ms_name
   return ( [ iiIiII11i1 ] )
   if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
 else :
  for OO0O0O0OOO0OO in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( II1OO ) :
    if ( II1OO != OO0O0O0OOO0OO . dns_name ) : continue
   else :
    if ( Ii1IiIIIi . is_exact_match ( OO0O0O0OOO0OO . map_resolver ) == False ) : continue
    if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
    if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
   iiIiII11i1 [ "dns-name" ] = OO0O0O0OOO0OO . dns_name
   iiIiII11i1 [ "address" ] = OO0O0O0OOO0OO . map_resolver . print_address_no_iid ( )
   iiIiII11i1 [ "mr-name" ] = "" if OO0O0O0OOO0OO . mr_name == None else OO0O0O0OOO0OO . mr_name
   return ( [ iiIiII11i1 ] )
   if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
   if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
 return ( [ ] )
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
def lisp_process_api_database_mapping ( ) :
 oO00Oo0OO = [ ]
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 for iIiI1ii in lisp_db_list :
  iIiiI11II11i = { }
  iIiiI11II11i [ "eid-prefix" ] = iIiI1ii . eid . print_prefix ( )
  if ( iIiI1ii . group . is_null ( ) == False ) :
   iIiiI11II11i [ "group-prefix" ] = iIiI1ii . group . print_prefix ( )
   if 64 - 64: Ii1I
   if 4 - 4: OoOoOO00
  o0O = [ ]
  for I1I1iIiiiiII11 in iIiI1ii . rloc_set :
   OooOOoOO0OO = { }
   if ( I1I1iIiiiiII11 . rloc . is_null ( ) == False ) :
    OooOOoOO0OO [ "rloc" ] = I1I1iIiiiiII11 . rloc . print_address_no_iid ( )
    if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
   if ( I1I1iIiiiiII11 . rloc_name != None ) : OooOOoOO0OO [ "rloc-name" ] = I1I1iIiiiiII11 . rloc_name
   if ( I1I1iIiiiiII11 . interface != None ) : OooOOoOO0OO [ "interface" ] = I1I1iIiiiiII11 . interface
   I11iI1i1 = I1I1iIiiiiII11 . translated_rloc
   if ( I11iI1i1 . is_null ( ) == False ) :
    OooOOoOO0OO [ "translated-rloc" ] = I11iI1i1 . print_address_no_iid ( )
    if 48 - 48: i1IIi + iII111i - Ii1I
   if ( OooOOoOO0OO != { } ) : o0O . append ( OooOOoOO0OO )
   if 9 - 9: o0oOOo0O0Ooo
   if 92 - 92: i11iIiiIii + OoooooooOO + O0 % oO0o
   if 90 - 90: Oo0Ooo * i11iIiiIii
   if 95 - 95: I1Ii111 % i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - I1Ii111
   if 69 - 69: iIii1I11I1II1 * oO0o
  iIiiI11II11i [ "rlocs" ] = o0O
  if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
  if 64 - 64: I1IiiI % i11iIiiIii / oO0o
  if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
  if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
  oO00Oo0OO . append ( iIiiI11II11i )
  if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 return ( oO00Oo0OO )
 if 31 - 31: OoO0O00
 if 89 - 89: II111iiii
 if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
 if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
 if 85 - 85: O0 * OOooOOo % I1Ii111
 if 33 - 33: O0
 if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
def lisp_gather_site_cache_data ( se , data ) :
 iIiiI11II11i = { }
 iIiiI11II11i [ "site-name" ] = se . site . site_name
 iIiiI11II11i [ "instance-id" ] = str ( se . eid . instance_id )
 iIiiI11II11i [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  iIiiI11II11i [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 43 - 43: iIii1I11I1II1
 iIiiI11II11i [ "registered" ] = "yes" if se . registered else "no"
 iIiiI11II11i [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 iIiiI11II11i [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 88 - 88: I1IiiI - OoO0O00 . O0 . oO0o
 oOOOo0o = se . last_registerer
 oOOOo0o = "none" if oOOOo0o . is_null ( ) else oOOOo0o . print_address ( )
 iIiiI11II11i [ "last-registerer" ] = oOOOo0o
 iIiiI11II11i [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 iIiiI11II11i [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 iIiiI11II11i [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  iIiiI11II11i [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
  if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
  if 59 - 59: OOooOOo - o0oOOo0O0Ooo
  if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
  if 51 - 51: ooOoO0o % iII111i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 IIiii11iiI111 = [ ]
 for OooOOoOO0OO in se . registered_rlocs :
  I1I1iIiiiiII11 = { }
  I1I1iIiiiiII11 [ "address" ] = OooOOoOO0OO . rloc . print_address_no_iid ( ) if OooOOoOO0OO . rloc_exists ( ) else "none"
  if 20 - 20: i1IIi - ooOoO0o % OoooooooOO * I1ii11iIi11i + II111iiii % i1IIi
  if 30 - 30: i11iIiiIii - I1IiiI + o0oOOo0O0Ooo + IiII
  if ( OooOOoOO0OO . geo ) : I1I1iIiiiiII11 [ "geo" ] = OooOOoOO0OO . geo . print_geo ( )
  if ( OooOOoOO0OO . elp ) : I1I1iIiiiiII11 [ "elp" ] = OooOOoOO0OO . elp . print_elp ( False )
  if ( OooOOoOO0OO . rle ) : I1I1iIiiiiII11 [ "rle" ] = OooOOoOO0OO . rle . print_rle ( False , True )
  if ( OooOOoOO0OO . json ) : I1I1iIiiiiII11 [ "json" ] = OooOOoOO0OO . json . print_json ( False )
  if ( OooOOoOO0OO . rloc_name ) : I1I1iIiiiiII11 [ "rloc-name" ] = OooOOoOO0OO . rloc_name
  I1I1iIiiiiII11 [ "uptime" ] = lisp_print_elapsed ( OooOOoOO0OO . uptime )
  I1I1iIiiiiII11 [ "upriority" ] = str ( OooOOoOO0OO . priority )
  I1I1iIiiiiII11 [ "uweight" ] = str ( OooOOoOO0OO . weight )
  I1I1iIiiiiII11 [ "mpriority" ] = str ( OooOOoOO0OO . mpriority )
  I1I1iIiiiiII11 [ "mweight" ] = str ( OooOOoOO0OO . mweight )
  if 16 - 16: I1ii11iIi11i / Ii1I + I1ii11iIi11i * I1Ii111
  IIiii11iiI111 . append ( I1I1iIiiiiII11 )
  if 49 - 49: ooOoO0o * OoOoOO00 . OoooooooOO . ooOoO0o + Oo0Ooo * IiII
 iIiiI11II11i [ "registered-rlocs" ] = IIiii11iiI111
 if 47 - 47: iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
 data . append ( iIiiI11II11i )
 return ( [ True , data ] )
 if 84 - 84: o0oOOo0O0Ooo * I11i
 if 22 - 22: i1IIi + OOooOOo % OoooooooOO
 if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
 if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 if 66 - 66: OoooooooOO
 if 90 - 90: IiII - OoOoOO00
def lisp_process_api_site_cache_entry ( parms ) :
 i1oO00O = parms [ "instance-id" ]
 i1oO00O = 0 if ( i1oO00O == "" ) else int ( i1oO00O )
 if 98 - 98: Oo0Ooo / oO0o . Ii1I
 if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
 if 37 - 37: iII111i - Ii1I . oO0o
 if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
 I11I = lisp_address ( LISP_AFI_NONE , "" , 0 , i1oO00O )
 I11I . store_prefix ( parms [ "eid-prefix" ] )
 if 25 - 25: oO0o
 if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
 if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
 if 39 - 39: iIii1I11I1II1 % ooOoO0o
 if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
 o0o0o = lisp_address ( LISP_AFI_NONE , "" , 0 , i1oO00O )
 if ( "group-prefix" in parms ) :
  o0o0o . store_prefix ( parms [ "group-prefix" ] )
  if 36 - 36: IiII / I1IiiI % iII111i / iII111i
  if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
 oO00Oo0OO = [ ]
 Ii1iIi1I1I1I = lisp_site_eid_lookup ( I11I , o0o0o , False )
 if ( Ii1iIi1I1I1I ) : lisp_gather_site_cache_data ( Ii1iIi1I1I1I , oO00Oo0OO )
 return ( oO00Oo0OO )
 if 65 - 65: O0 + O0 * I1Ii111
 if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
 if 16 - 16: I11i % iII111i
 if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
 if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
 if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
 if 1 - 1: O0 / iIii1I11I1II1
def lisp_get_interface_instance_id ( device , source_eid ) :
 i1i1111I = None
 if ( device in lisp_myinterfaces ) :
  i1i1111I = lisp_myinterfaces [ device ]
  if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
  if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
  if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
  if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
  if 16 - 16: o0oOOo0O0Ooo
  if 3 - 3: i11iIiiIii . I1ii11iIi11i
 if ( i1i1111I == None or i1i1111I . instance_id == None ) :
  return ( lisp_default_iid )
  if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
  if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
  if 100 - 100: o0oOOo0O0Ooo
  if 95 - 95: iII111i * oO0o * i1IIi
  if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
  if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
  if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
  if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
  if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 i1oO00O = i1i1111I . get_instance_id ( )
 if ( source_eid == None ) : return ( i1oO00O )
 if 76 - 76: OoO0O00
 oo0o00oOOO000 = source_eid . instance_id
 II1I1I = None
 for i1i1111I in lisp_multi_tenant_interfaces :
  if ( i1i1111I . device != device ) : continue
  Ii1I1I11I11 = i1i1111I . multi_tenant_eid
  source_eid . instance_id = Ii1I1I11I11 . instance_id
  if ( source_eid . is_more_specific ( Ii1I1I11I11 ) == False ) : continue
  if ( II1I1I == None or II1I1I . multi_tenant_eid . mask_len < Ii1I1I11I11 . mask_len ) :
   II1I1I = i1i1111I
   if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1
   if 2 - 2: Oo0Ooo + II111iiii * O0 / iIii1I11I1II1 / iIii1I11I1II1
 source_eid . instance_id = oo0o00oOOO000
 if 33 - 33: OOooOOo * OOooOOo . II111iiii % O0 % O0 % o0oOOo0O0Ooo
 if ( II1I1I == None ) : return ( i1oO00O )
 return ( II1I1I . get_instance_id ( ) )
 if 45 - 45: OoooooooOO * oO0o
 if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
 if 16 - 16: Oo0Ooo
 if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
 if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 if 33 - 33: OOooOOo - OoooooooOO . iII111i
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( device not in lisp_myinterfaces ) : return ( None )
 if 2 - 2: I11i + i1IIi
 i1i1111I = lisp_myinterfaces [ device ]
 O00Oo000 = device if i1i1111I . dynamic_eid_device == None else i1i1111I . dynamic_eid_device
 if 96 - 96: I1IiiI . IiII + I11i / iIii1I11I1II1
 if 27 - 27: I11i - Ii1I * OoOoOO00 % iIii1I11I1II1
 if ( i1i1111I . does_dynamic_eid_match ( eid ) ) : return ( O00Oo000 )
 return ( None )
 if 69 - 69: Ii1I . II111iiii + o0oOOo0O0Ooo * iII111i
 if 95 - 95: II111iiii / iII111i + i1IIi
 if 70 - 70: IiII . I1Ii111
 if 29 - 29: Oo0Ooo . i11iIiiIii + OoOoOO00 - Oo0Ooo
 if 13 - 13: ooOoO0o
 if 56 - 56: I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / OoooooooOO - I1IiiI
 if 3 - 3: ooOoO0o
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 68 - 68: o0oOOo0O0Ooo
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 36 - 36: Oo0Ooo . I11i + I1IiiI * i1IIi % Ii1I + OOooOOo
 iIiIIi1IiiI = lisp_process_rloc_probe_timer
 i1i1I1Iii = threading . Timer ( interval , iIiIIi1IiiI , [ lisp_sockets ] )
 lisp_rloc_probe_timer = i1i1I1Iii
 i1i1I1Iii . start ( )
 return
 if 59 - 59: I1Ii111 + O0 / OoooooooOO
 if 63 - 63: I1IiiI / o0oOOo0O0Ooo - I1Ii111
 if 49 - 49: iII111i . OoOoOO00
 if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
 if 68 - 68: I11i
 if 91 - 91: I11i
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for III11II111 in lisp_rloc_probe_list :
  ooooooO = lisp_rloc_probe_list [ III11II111 ]
  lprint ( "RLOC {}:" . format ( III11II111 ) )
  for I1I1iIiiiiII11 , I1i , o0O0Ooo in ooooooO :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( I1I1iIiiiiII11 ) ) , I1i . print_prefix ( ) ,
 o0O0Ooo . print_prefix ( ) , I1I1iIiiiiII11 . translated_port ) )
   if 13 - 13: iIii1I11I1II1 - OoooooooOO . OoooooooOO + iII111i - OoOoOO00 % oO0o
   if 11 - 11: ooOoO0o * iIii1I11I1II1 + OoooooooOO + OoO0O00
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 24 - 24: iII111i . OoO0O00 * Ii1I - OOooOOo . I11i
 if 90 - 90: I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - i1IIi
 if 94 - 94: OoooooooOO
 if 80 - 80: O0 * OOooOOo + i1IIi + i11iIiiIii * o0oOOo0O0Ooo
 if 14 - 14: II111iiii * OOooOOo - O0 / I1ii11iIi11i . OoO0O00 . ooOoO0o
 if 98 - 98: o0oOOo0O0Ooo . i1IIi
 if 83 - 83: i11iIiiIii + OOooOOo % iII111i
 if 59 - 59: I11i
 if 23 - 23: OoOoOO00 * I1Ii111
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
 if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
 if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
 OooOOoOO0OO , I1i , o0O0Ooo = eid_list [ 0 ]
 iIIiIIII11iii = [ lisp_print_eid_tuple ( I1i , o0O0Ooo ) ]
 if 39 - 39: ooOoO0o . OOooOOo . ooOoO0o + oO0o + Oo0Ooo
 for OooOOoOO0OO , I1i , o0O0Ooo in eid_list [ 1 : : ] :
  OooOOoOO0OO . state = LISP_RLOC_UNREACH_STATE
  OooOOoOO0OO . last_state_change = lisp_get_timestamp ( )
  iIIiIIII11iii . append ( lisp_print_eid_tuple ( I1i , o0O0Ooo ) )
  if 25 - 25: IiII * OoO0O00 - OOooOOo
  if 100 - 100: oO0o % i1IIi + iII111i * oO0o / iIii1I11I1II1
 IIIIi1 = bold ( "unreachable" , False )
 o00oO = red ( OooOOoOO0OO . rloc . print_address_no_iid ( ) , False )
 if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
 for I11I in iIIiIIII11iii :
  I1i = green ( I11I , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( o00oO , IIIIi1 , I1i ) )
  if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
  if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
  if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
  if 94 - 94: OoO0O00
  if 35 - 35: I1ii11iIi11i % OoO0O00 + II111iiii % II111iiii / IiII - iII111i
  if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
 for OooOOoOO0OO , I1i , o0O0Ooo in eid_list :
  O0oo0OOo00o0o = lisp_map_cache . lookup_cache ( I1i , True )
  if ( O0oo0OOo00o0o ) : lisp_write_ipc_map_cache ( True , O0oo0OOo00o0o )
  if 48 - 48: IiII . I1Ii111 + OoooooooOO - I1Ii111 . Ii1I . I1Ii111
 return
 if 24 - 24: ooOoO0o * iIii1I11I1II1
 if 1 - 1: I1ii11iIi11i . O0
 if 3 - 3: iIii1I11I1II1 * ooOoO0o - OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoooooooOO
 if 42 - 42: I1Ii111 - i1IIi
 if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
 if 31 - 31: OoO0O00 . I1ii11iIi11i % I11i - II111iiii
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 76 - 76: I1Ii111
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 if 78 - 78: II111iiii % OOooOOo
 if 6 - 6: OOooOOo
 I1I11iII = lisp_get_default_route_next_hops ( )
 if 48 - 48: OOooOOo - II111iiii - i11iIiiIii
 lprint ( "---------- Start RLOC Probing for {} entries ----------" . format ( len ( lisp_rloc_probe_list ) ) )
 if 82 - 82: i11iIiiIii % I11i . OoOoOO00 + Ii1I * iIii1I11I1II1 - OoOoOO00
 if 96 - 96: I1IiiI
 if 3 - 3: OoooooooOO
 if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
 if 56 - 56: ooOoO0o
 IiI = 0
 iiIii11Ii = bold ( "RLOC-probe" , False )
 for O0oOOoooOOoO0000 in list ( lisp_rloc_probe_list . values ( ) ) :
  if 18 - 18: Oo0Ooo . OOooOOo
  if 37 - 37: i11iIiiIii - I1ii11iIi11i + I1IiiI / OoooooooOO * IiII % Oo0Ooo
  if 67 - 67: i1IIi % Oo0Ooo . OoOoOO00 - Ii1I / OoooooooOO + iII111i
  if 100 - 100: O0 + I1ii11iIi11i + OoooooooOO - iII111i * iIii1I11I1II1 . II111iiii
  if 79 - 79: i11iIiiIii
  I11Ii1ii1 = None
  for Oo0ooooOoO000 , I11I , o0o0o in O0oOOoooOOoO0000 :
   Oo0o = Oo0ooooOoO000 . rloc . print_address_no_iid ( )
   if 13 - 13: ooOoO0o % OOooOOo
   if 64 - 64: O0
   if 28 - 28: I11i / I1IiiI - I1Ii111 + I1ii11iIi11i % iIii1I11I1II1
   if 35 - 35: iIii1I11I1II1 % Oo0Ooo % iII111i / iIii1I11I1II1 - I1ii11iIi11i . Oo0Ooo
   I1II1iI1IiI , ooOOOO , IIi11I = lisp_allow_gleaning ( I11I , None , Oo0ooooOoO000 )
   if ( I1II1iI1IiI and ooOOOO == False ) :
    I1i = green ( I11I . print_address ( ) , False )
    Oo0o += ":{}" . format ( Oo0ooooOoO000 . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( Oo0o , False ) , I1i ) )
    if 98 - 98: I1ii11iIi11i % OoooooooOO - I1IiiI + I11i
    continue
    if 74 - 74: Ii1I / OOooOOo + O0
    if 19 - 19: IiII
    if 87 - 87: IiII % iIii1I11I1II1 * I1ii11iIi11i
    if 43 - 43: Ii1I - IiII / i11iIiiIii + OoOoOO00 + I1ii11iIi11i - o0oOOo0O0Ooo
    if 39 - 39: OoOoOO00 - i1IIi / oO0o % I11i * o0oOOo0O0Ooo * I1IiiI
    if 79 - 79: Ii1I
    if 56 - 56: I1ii11iIi11i
   if ( Oo0ooooOoO000 . down_state ( ) ) : continue
   if 40 - 40: OoooooooOO
   if 100 - 100: IiII - I11i
   if 79 - 79: iII111i % O0
   if 73 - 73: Oo0Ooo
   if 13 - 13: OOooOOo - ooOoO0o
   if 8 - 8: I1Ii111 % oO0o
   if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
   if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
   if 90 - 90: OoO0O00
   if 54 - 54: OOooOOo + Oo0Ooo * o0oOOo0O0Ooo - iIii1I11I1II1 * ooOoO0o
   if 76 - 76: i11iIiiIii * I1IiiI - IiII . o0oOOo0O0Ooo % iII111i . i11iIiiIii
   if ( I11Ii1ii1 ) :
    Oo0ooooOoO000 . last_rloc_probe_nonce = I11Ii1ii1 . last_rloc_probe_nonce
    if 69 - 69: O0 + o0oOOo0O0Ooo / ooOoO0o
    if ( I11Ii1ii1 . translated_port == Oo0ooooOoO000 . translated_port and I11Ii1ii1 . rloc_name == Oo0ooooOoO000 . rloc_name ) :
     if 7 - 7: Ii1I . Ii1I . iIii1I11I1II1 / ooOoO0o
     I1i = green ( lisp_print_eid_tuple ( I11I , o0o0o ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( Oo0o , False ) , I1i ) )
     if 70 - 70: O0
     if 42 - 42: I1Ii111 + OoooooooOO + I11i
     if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
     if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
     if 27 - 27: O0 / Oo0Ooo . oO0o
     if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
     Oo0ooooOoO000 . last_rloc_probe = I11Ii1ii1 . last_rloc_probe
     continue
     if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
     if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
     if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
   IIi1iiii1Ii = None
   OooOOoOO0OO = None
   while ( True ) :
    OooOOoOO0OO = Oo0ooooOoO000 if OooOOoOO0OO == None else OooOOoOO0OO . next_rloc
    if ( OooOOoOO0OO == None ) : break
    if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
    if 67 - 67: oO0o
    if 12 - 12: I1IiiI + OoooooooOO
    if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
    if 19 - 19: OoooooooOO / IiII
    if ( OooOOoOO0OO . rloc_next_hop != None ) :
     if ( OooOOoOO0OO . rloc_next_hop not in I1I11iII ) :
      if ( OooOOoOO0OO . up_state ( ) ) :
       iiIi , OooIIIii = OooOOoOO0OO . rloc_next_hop
       OooOOoOO0OO . state = LISP_RLOC_UNREACH_STATE
       OooOOoOO0OO . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( OooOOoOO0OO . rloc , False )
       if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
      IIIIi1 = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( OooIIIii , iiIi ,
 red ( Oo0o , False ) , IIIIi1 ) )
      continue
      if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
      if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
      if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
      if 51 - 51: OoO0O00 - OoO0O00 * IiII
      if 24 - 24: OoooooooOO . II111iiii
      if 97 - 97: II111iiii . O0
    i1Ii = OooOOoOO0OO . last_rloc_probe
    iI1i1iiIiIi = 0 if i1Ii == None else time . time ( ) - i1Ii
    if ( OooOOoOO0OO . unreach_state ( ) and iI1i1iiIiIi < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( Oo0o , False ) ) )
     if 74 - 74: o0oOOo0O0Ooo
     continue
     if 15 - 15: oO0o % Oo0Ooo * i1IIi / OoO0O00 . iIii1I11I1II1 - O0
     if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
     if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
     if 92 - 92: ooOoO0o - iII111i
     if 69 - 69: iII111i
     if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
    oo000O0o = lisp_get_echo_nonce ( None , Oo0o )
    if ( oo000O0o and oo000O0o . request_nonce_timeout ( ) ) :
     OooOOoOO0OO . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     OooOOoOO0OO . last_state_change = lisp_get_timestamp ( )
     IIIIi1 = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( Oo0o , False ) , IIIIi1 ) )
     if 63 - 63: oO0o * OoO0O00 * oO0o
     lisp_update_rtr_updown ( OooOOoOO0OO . rloc , False )
     continue
     if 31 - 31: Oo0Ooo
     if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
     if 67 - 67: I1Ii111 . I1ii11iIi11i
     if 2 - 2: O0 + I1Ii111
     if 82 - 82: Ii1I / iII111i
     if 13 - 13: I11i + iII111i
    if ( oo000O0o and oo000O0o . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( Oo0o , False ) ) )
     if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
     continue
     if 59 - 59: Oo0Ooo + I1ii11iIi11i
     if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
     if 70 - 70: i1IIi . Ii1I / Ii1I
     if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
     if 45 - 45: i1IIi + I1ii11iIi11i
     if 49 - 49: i11iIiiIii . I1ii11iIi11i
    if ( OooOOoOO0OO . last_rloc_probe != None ) :
     i1Ii = OooOOoOO0OO . last_rloc_probe_reply
     if ( i1Ii == None ) : i1Ii = 0
     iI1i1iiIiIi = time . time ( ) - i1Ii
     if ( OooOOoOO0OO . up_state ( ) and iI1i1iiIiIi >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
      OooOOoOO0OO . state = LISP_RLOC_UNREACH_STATE
      OooOOoOO0OO . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( OooOOoOO0OO . rloc , False )
      IIIIi1 = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( Oo0o , False ) , IIIIi1 ) )
      if 33 - 33: II111iiii
      if 39 - 39: ooOoO0o + I11i
      lisp_mark_rlocs_for_other_eids ( O0oOOoooOOoO0000 )
      if 24 - 24: o0oOOo0O0Ooo
      if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
      if 63 - 63: oO0o
    OooOOoOO0OO . last_rloc_probe = lisp_get_timestamp ( )
    if 7 - 7: IiII / i11iIiiIii - OOooOOo
    Ii1iI11 = "" if OooOOoOO0OO . unreach_state ( ) == False else " unreachable"
    if 40 - 40: II111iiii - I1Ii111 + I1ii11iIi11i * Ii1I
    if 6 - 6: I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1ii11iIi11i * IiII
    if 10 - 10: ooOoO0o . I1IiiI . Oo0Ooo * I1ii11iIi11i
    if 11 - 11: OoOoOO00 * OOooOOo % o0oOOo0O0Ooo / I1ii11iIi11i . o0oOOo0O0Ooo
    if 23 - 23: iIii1I11I1II1 + OOooOOo
    if 74 - 74: oO0o - I11i . i11iIiiIii / iIii1I11I1II1 . I11i
    if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
    I1iI1II1Iii = ""
    OooIIIii = None
    if ( OooOOoOO0OO . rloc_next_hop != None ) :
     iiIi , OooIIIii = OooOOoOO0OO . rloc_next_hop
     lisp_install_host_route ( Oo0o , OooIIIii , True )
     I1iI1II1Iii = ", send on nh {}({})" . format ( OooIIIii , iiIi )
     if 16 - 16: i1IIi
     if 86 - 86: OoOoOO00 - iII111i - Oo0Ooo
     if 33 - 33: Ii1I - OoO0O00
     if 15 - 15: O0 . iIii1I11I1II1 - I1Ii111 + O0 + ooOoO0o / I1IiiI
     if 8 - 8: iII111i % O0 - OoOoOO00
    oOoOo0 = OooOOoOO0OO . print_rloc_probe_rtt ( )
    IIi1i1i1 = Oo0o
    if ( OooOOoOO0OO . translated_port != 0 ) :
     IIi1i1i1 += ":{}" . format ( OooOOoOO0OO . translated_port )
     if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
    IIi1i1i1 = red ( IIi1i1i1 , False )
    if ( OooOOoOO0OO . rloc_name != None ) :
     IIi1i1i1 += " (" + blue ( OooOOoOO0OO . rloc_name , False ) + ")"
     if 82 - 82: ooOoO0o % Oo0Ooo
    lprint ( "Send {}{} {}, last rtt: {}{}" . format ( iiIii11Ii , Ii1iI11 ,
 IIi1i1i1 , oOoOo0 , I1iI1II1Iii ) )
    if 26 - 26: OoO0O00 + i11iIiiIii % I11i . I1ii11iIi11i
    if 76 - 76: i1IIi + ooOoO0o - Oo0Ooo + OoOoOO00 / I1ii11iIi11i . OOooOOo
    if 50 - 50: IiII - Ii1I % iIii1I11I1II1
    if 60 - 60: o0oOOo0O0Ooo - Oo0Ooo
    if 92 - 92: OoOoOO00 + IiII . OoO0O00 % iII111i / II111iiii / I11i
    if 62 - 62: I1ii11iIi11i
    if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
    if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
    if ( OooOOoOO0OO . rloc_next_hop != None ) :
     IIi1iiii1Ii = lisp_get_host_route_next_hop ( Oo0o )
     if ( IIi1iiii1Ii ) : lisp_install_host_route ( Oo0o , IIi1iiii1Ii , False )
     if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
     if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
     if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
     if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
     if 71 - 71: i1IIi
     if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
    if ( OooOOoOO0OO . rloc . is_null ( ) ) :
     OooOOoOO0OO . rloc . copy_address ( Oo0ooooOoO000 . rloc )
     if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
     if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
     if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
     if 79 - 79: iII111i
     if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
    O0OOO0o = None if ( o0o0o . is_null ( ) ) else I11I
    iI1O0oOOO = I11I if ( o0o0o . is_null ( ) ) else o0o0o
    lisp_send_map_request ( lisp_sockets , 0 , O0OOO0o , iI1O0oOOO , OooOOoOO0OO )
    I11Ii1ii1 = Oo0ooooOoO000
    if 62 - 62: IiII - I1Ii111
    if 68 - 68: Oo0Ooo + oO0o - OoO0O00
    if 17 - 17: I11i % I1ii11iIi11i - I1IiiI % oO0o + I1ii11iIi11i
    if 68 - 68: i1IIi . ooOoO0o . Oo0Ooo + iII111i . I1IiiI * i1IIi
    if ( OooIIIii ) : lisp_install_host_route ( Oo0o , OooIIIii , False )
    if 88 - 88: iII111i + i11iIiiIii
    if 42 - 42: I1Ii111 * O0 / OoO0O00 + iII111i
    if 86 - 86: OOooOOo
    if 6 - 6: oO0o % iII111i * Oo0Ooo - i11iIiiIii . OoooooooOO
    if 85 - 85: O0 * i1IIi
   if ( IIi1iiii1Ii ) : lisp_install_host_route ( Oo0o , IIi1iiii1Ii , True )
   if 29 - 29: i11iIiiIii
   if 34 - 34: OoOoOO00
   if 17 - 17: oO0o * OoOoOO00 % OoO0O00 % I1IiiI * I11i
   if 78 - 78: OoooooooOO . I1Ii111 + Ii1I - II111iiii - IiII / iIii1I11I1II1
   IiI += 1
   if ( ( IiI % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 92 - 92: Ii1I
   if 34 - 34: OOooOOo * OoooooooOO / I1ii11iIi11i
   if 41 - 41: i1IIi
 lprint ( "---------- End RLOC Probing ----------" )
 return
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
 if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
 if 100 - 100: OoO0O00 . Oo0Ooo
 if 29 - 29: OoO0O00
 if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
 if 47 - 47: II111iiii * I1ii11iIi11i
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
 if 71 - 71: I1ii11iIi11i * i1IIi
 if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
 if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
 if ( lisp_i_am_itr == False ) : return
 if 57 - 57: OOooOOo . I11i % OoOoOO00
 if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
 if 78 - 78: iII111i - OOooOOo / I1Ii111
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
 if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
 if ( lisp_register_all_rtrs ) : return
 if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 o0OOOo000Oo = rtr . print_address_no_iid ( )
 if 25 - 25: OOooOOo - I1ii11iIi11i * OoOoOO00 + OoooooooOO - Oo0Ooo
 if 8 - 8: I1IiiI * i11iIiiIii . I1ii11iIi11i . I1IiiI
 if 87 - 87: I1Ii111 . I11i % i11iIiiIii % OoooooooOO % I11i
 if 80 - 80: i1IIi + I1ii11iIi11i
 if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
 if ( o0OOOo000Oo not in lisp_rtr_list ) : return
 if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( o0OOOo000Oo , False ) , bold ( updown , False ) ) )
 if 66 - 66: OoO0O00 * Ii1I . OoO0O00
 if 90 - 90: II111iiii % Ii1I
 if 67 - 67: I1IiiI - I11i - i11iIiiIii
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 ii1I11Iii = "rtr%{}%{}" . format ( o0OOOo000Oo , updown )
 ii1I11Iii = lisp_command_ipc ( ii1I11Iii , "lisp-itr" )
 lisp_ipc ( ii1I11Iii , lisp_ipc_socket , "lisp-etr" )
 return
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
 if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
 if 57 - 57: I1Ii111 - IiII
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl ,
 mrloc ) :
 OooOOoOO0OO = rloc_entry . rloc
 OOO0O0O = map_reply . nonce
 oO0O00 = map_reply . hop_count
 iiIii11Ii = bold ( "RLOC-probe reply" , False )
 OoOIiiii1iiIi11 = OooOOoOO0OO . print_address_no_iid ( )
 ooOo00 = source . print_address_no_iid ( )
 I1I1i1iIi1I = lisp_rloc_probe_list
 oOoOOO = rloc_entry . json . json_string if rloc_entry . json else None
 i1 = lisp_get_timestamp ( )
 if 54 - 54: I1IiiI . I1ii11iIi11i . iII111i . iII111i % O0 % o0oOOo0O0Ooo
 if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
 if 67 - 67: I1Ii111
 if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
 if 77 - 77: ooOoO0o
 if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
 if ( mrloc != None ) :
  i1i1iI1I = mrloc . rloc . print_address_no_iid ( )
  if ( OoOIiiii1iiIi11 not in mrloc . multicast_rloc_probe_list ) :
   o0Ooooo0 = lisp_rloc ( )
   o0Ooooo0 = copy . deepcopy ( mrloc )
   o0Ooooo0 . rloc . copy_address ( OooOOoOO0OO )
   o0Ooooo0 . multicast_rloc_probe_list = { }
   mrloc . multicast_rloc_probe_list [ OoOIiiii1iiIi11 ] = o0Ooooo0
   if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
  o0Ooooo0 = mrloc . multicast_rloc_probe_list [ OoOIiiii1iiIi11 ]
  o0Ooooo0 . last_rloc_probe_nonce = mrloc . last_rloc_probe_nonce
  o0Ooooo0 . last_rloc_probe = mrloc . last_rloc_probe
  I1I1iIiiiiII11 , I11I , o0o0o = lisp_rloc_probe_list [ i1i1iI1I ] [ 0 ]
  o0Ooooo0 . process_rloc_probe_reply ( i1 , OOO0O0O , I11I , o0o0o , oO0O00 , ttl , oOoOOO )
  mrloc . process_rloc_probe_reply ( i1 , OOO0O0O , I11I , o0o0o , oO0O00 , ttl , oOoOOO )
  return
  if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
  if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
  if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
  if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
  if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
  if 42 - 42: i1IIi . OoO0O00 % iII111i
  if 57 - 57: I1ii11iIi11i / I1IiiI
 oOOOo0o = OoOIiiii1iiIi11
 if ( oOOOo0o not in I1I1i1iIi1I ) :
  oOOOo0o += ":" + str ( port )
  if ( oOOOo0o not in I1I1i1iIi1I ) :
   oOOOo0o = ooOo00
   if ( oOOOo0o not in I1I1i1iIi1I ) :
    oOOOo0o += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( iiIii11Ii , red ( OoOIiiii1iiIi11 , False ) , red ( ooOo00 ,
    # I1ii11iIi11i * i11iIiiIii * i1IIi * I1ii11iIi11i + oO0o
 False ) , port ) )
    return
    if 41 - 41: ooOoO0o * O0 * iII111i
    if 61 - 61: O0 % I1IiiI . I1ii11iIi11i / i1IIi
    if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
    if 83 - 83: O0 / I1Ii111 - OoooooooOO
    if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
    if 39 - 39: OoooooooOO
    if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
    if 41 - 41: II111iiii . o0oOOo0O0Ooo
 for OooOOoOO0OO , I11I , o0o0o in lisp_rloc_probe_list [ oOOOo0o ] :
  if ( lisp_i_am_rtr ) :
   if ( OooOOoOO0OO . translated_port != 0 and OooOOoOO0OO . translated_port != port ) :
    continue
    if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
    if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
  OooOOoOO0OO . process_rloc_probe_reply ( i1 , OOO0O0O , I11I , o0o0o , oO0O00 , ttl , oOoOOO )
  if 15 - 15: OoO0O00
 return
 if 37 - 37: OoO0O00 . OoooooooOO - OOooOOo
 if 34 - 34: o0oOOo0O0Ooo + iIii1I11I1II1 / o0oOOo0O0Ooo / ooOoO0o
 if 53 - 53: II111iiii / iIii1I11I1II1
 if 25 - 25: I1Ii111
 if 58 - 58: OoOoOO00 * i1IIi
 if 20 - 20: IiII
 if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
 if 30 - 30: i11iIiiIii . I1IiiI
def lisp_db_list_length ( ) :
 IiI = 0
 for iIiI1ii in lisp_db_list :
  IiI += len ( iIiI1ii . dynamic_eids ) if iIiI1ii . dynamic_eid_configured ( ) else 1
  IiI += len ( iIiI1ii . eid . iid_list )
  if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 return ( IiI )
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
def lisp_is_myeid ( eid ) :
 for iIiI1ii in lisp_db_list :
  if ( eid . is_more_specific ( iIiI1ii . eid ) ) : return ( True )
  if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
 return ( False )
 if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
 if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
 if 13 - 13: OOooOOo / OoooooooOO
 if 7 - 7: II111iiii - ooOoO0o
 if 72 - 72: Ii1I
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
 if 24 - 24: i11iIiiIii + ooOoO0o
 if 80 - 80: IiII % I11i % oO0o
 if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 if 70 - 70: iIii1I11I1II1
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 if 64 - 64: iII111i - Oo0Ooo
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 oo000O0o = None
 if ( rloc_str in lisp_nonce_echo_list ) :
  oo000O0o = lisp_nonce_echo_list [ rloc_str ]
  if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
 return ( oo000O0o )
 if 50 - 50: I1IiiI % o0oOOo0O0Ooo
 if 1 - 1: II111iiii
 if 22 - 22: I1Ii111 + iII111i
 if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
def lisp_decode_dist_name ( packet ) :
 IiI = 0
 i1II = b""
 if 22 - 22: OoooooooOO
 while ( packet [ 0 : 1 ] != b"\x00" ) :
  if ( IiI == 255 ) : return ( [ None , None ] )
  i1II += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  IiI += 1
  if 86 - 86: II111iiii % Oo0Ooo % I1IiiI / IiII * Oo0Ooo
  if 67 - 67: i11iIiiIii % OoOoOO00 - oO0o
 packet = packet [ 1 : : ]
 return ( packet , i1II . decode ( ) )
 if 28 - 28: I1Ii111 . I1ii11iIi11i % Ii1I . i1IIi + I11i
 if 84 - 84: Ii1I % oO0o / I1ii11iIi11i . OoooooooOO % I1IiiI
 if 28 - 28: I1Ii111 / IiII + oO0o + O0
 if 52 - 52: I1IiiI - i11iIiiIii
 if 15 - 15: I11i / OOooOOo % OoO0O00 - O0 + Oo0Ooo
 if 32 - 32: IiII
 if 53 - 53: I1ii11iIi11i
 if 85 - 85: iIii1I11I1II1 - II111iiii + Ii1I
def lisp_write_flow_log ( flow_log ) :
 iiI1i1I = open ( "./logs/lisp-flow.log" , "a" )
 if 3 - 3: ooOoO0o - I1Ii111
 IiI = 0
 for o0oO0o0O0o0Oo in flow_log :
  OO0Oo00OO0oo = o0oO0o0O0o0Oo [ 3 ]
  o0o00ooo0 = OO0Oo00OO0oo . print_flow ( o0oO0o0O0o0Oo [ 0 ] , o0oO0o0O0o0Oo [ 1 ] , o0oO0o0O0o0Oo [ 2 ] )
  iiI1i1I . write ( o0o00ooo0 )
  IiI += 1
  if 78 - 78: iII111i . II111iiii
 iiI1i1I . close ( )
 del ( flow_log )
 if 61 - 61: I1IiiI / Ii1I . O0 + iII111i + oO0o / I11i
 IiI = bold ( str ( IiI ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( IiI ) )
 return
 if 14 - 14: I11i % iII111i * i11iIiiIii % i1IIi
 if 10 - 10: iIii1I11I1II1
 if 42 - 42: Oo0Ooo * I1ii11iIi11i
 if 77 - 77: ooOoO0o % I1IiiI * oO0o
 if 91 - 91: OoOoOO00 * Oo0Ooo * IiII - I1IiiI
 if 37 - 37: Oo0Ooo - oO0o / I1ii11iIi11i . o0oOOo0O0Ooo * Ii1I
 if 95 - 95: i11iIiiIii - ooOoO0o / I11i / I1Ii111
def lisp_policy_command ( kv_pair ) :
 o00oo = lisp_policy ( "" )
 oOoOO0oOO0oo = None
 if 87 - 87: II111iiii . iIii1I11I1II1 . OoOoOO00
 II1i1OoOOo0o0o00 = [ ]
 for OoOOoO0oOo in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  II1i1OoOOo0o0o00 . append ( lisp_policy_match ( ) )
  if 28 - 28: Oo0Ooo % iIii1I11I1II1 % iII111i . iIii1I11I1II1 * oO0o - OoooooooOO
  if 12 - 12: O0
 for I111iIiI in list ( kv_pair . keys ( ) ) :
  iiIiII11i1 = kv_pair [ I111iIiI ]
  if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
  if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
  if 93 - 93: iIii1I11I1II1 / IiII
  if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
  if ( I111iIiI == "instance-id" ) :
   for OoOOoO0oOo in range ( len ( II1i1OoOOo0o0o00 ) ) :
    I11iII = iiIiII11i1 [ OoOOoO0oOo ]
    if ( I11iII == "" ) : continue
    O0O0iIIi11Ii = II1i1OoOOo0o0o00 [ OoOOoO0oOo ]
    if ( O0O0iIIi11Ii . source_eid == None ) :
     O0O0iIIi11Ii . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 41 - 41: OoO0O00 % Oo0Ooo - oO0o + OoO0O00 / OOooOOo
    if ( O0O0iIIi11Ii . dest_eid == None ) :
     O0O0iIIi11Ii . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 74 - 74: ooOoO0o . oO0o - Oo0Ooo % OOooOOo
    O0O0iIIi11Ii . source_eid . instance_id = int ( I11iII )
    O0O0iIIi11Ii . dest_eid . instance_id = int ( I11iII )
    if 15 - 15: o0oOOo0O0Ooo - Oo0Ooo / IiII
    if 94 - 94: Ii1I + o0oOOo0O0Ooo / II111iiii
  if ( I111iIiI == "source-eid" ) :
   for OoOOoO0oOo in range ( len ( II1i1OoOOo0o0o00 ) ) :
    I11iII = iiIiII11i1 [ OoOOoO0oOo ]
    if ( I11iII == "" ) : continue
    O0O0iIIi11Ii = II1i1OoOOo0o0o00 [ OoOOoO0oOo ]
    if ( O0O0iIIi11Ii . source_eid == None ) :
     O0O0iIIi11Ii . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 18 - 18: I1IiiI
    i1oO00O = O0O0iIIi11Ii . source_eid . instance_id
    O0O0iIIi11Ii . source_eid . store_prefix ( I11iII )
    O0O0iIIi11Ii . source_eid . instance_id = i1oO00O
    if 27 - 27: ooOoO0o
    if 20 - 20: OoooooooOO * OOooOOo
  if ( I111iIiI == "destination-eid" ) :
   for OoOOoO0oOo in range ( len ( II1i1OoOOo0o0o00 ) ) :
    I11iII = iiIiII11i1 [ OoOOoO0oOo ]
    if ( I11iII == "" ) : continue
    O0O0iIIi11Ii = II1i1OoOOo0o0o00 [ OoOOoO0oOo ]
    if ( O0O0iIIi11Ii . dest_eid == None ) :
     O0O0iIIi11Ii . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
    i1oO00O = O0O0iIIi11Ii . dest_eid . instance_id
    O0O0iIIi11Ii . dest_eid . store_prefix ( I11iII )
    O0O0iIIi11Ii . dest_eid . instance_id = i1oO00O
    if 93 - 93: OoooooooOO / I1Ii111
    if 91 - 91: I1Ii111
  if ( I111iIiI == "source-rloc" ) :
   for OoOOoO0oOo in range ( len ( II1i1OoOOo0o0o00 ) ) :
    I11iII = iiIiII11i1 [ OoOOoO0oOo ]
    if ( I11iII == "" ) : continue
    O0O0iIIi11Ii = II1i1OoOOo0o0o00 [ OoOOoO0oOo ]
    O0O0iIIi11Ii . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    O0O0iIIi11Ii . source_rloc . store_prefix ( I11iII )
    if 18 - 18: ooOoO0o * I11i
    if 53 - 53: I11i . i11iIiiIii - iIii1I11I1II1 / I1Ii111
  if ( I111iIiI == "destination-rloc" ) :
   for OoOOoO0oOo in range ( len ( II1i1OoOOo0o0o00 ) ) :
    I11iII = iiIiII11i1 [ OoOOoO0oOo ]
    if ( I11iII == "" ) : continue
    O0O0iIIi11Ii = II1i1OoOOo0o0o00 [ OoOOoO0oOo ]
    O0O0iIIi11Ii . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    O0O0iIIi11Ii . dest_rloc . store_prefix ( I11iII )
    if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
    if 63 - 63: o0oOOo0O0Ooo . iIii1I11I1II1 % IiII * i11iIiiIii
  if ( I111iIiI == "rloc-record-name" ) :
   for OoOOoO0oOo in range ( len ( II1i1OoOOo0o0o00 ) ) :
    I11iII = iiIiII11i1 [ OoOOoO0oOo ]
    if ( I11iII == "" ) : continue
    O0O0iIIi11Ii = II1i1OoOOo0o0o00 [ OoOOoO0oOo ]
    O0O0iIIi11Ii . rloc_record_name = I11iII
    if 70 - 70: iIii1I11I1II1
    if 12 - 12: OoOoOO00 / o0oOOo0O0Ooo - I1ii11iIi11i + oO0o + O0
  if ( I111iIiI == "geo-name" ) :
   for OoOOoO0oOo in range ( len ( II1i1OoOOo0o0o00 ) ) :
    I11iII = iiIiII11i1 [ OoOOoO0oOo ]
    if ( I11iII == "" ) : continue
    O0O0iIIi11Ii = II1i1OoOOo0o0o00 [ OoOOoO0oOo ]
    O0O0iIIi11Ii . geo_name = I11iII
    if 9 - 9: I1ii11iIi11i * OoooooooOO . O0 . ooOoO0o * i11iIiiIii / i1IIi
    if 38 - 38: OoOoOO00 . OoooooooOO % I1ii11iIi11i . oO0o % oO0o
  if ( I111iIiI == "elp-name" ) :
   for OoOOoO0oOo in range ( len ( II1i1OoOOo0o0o00 ) ) :
    I11iII = iiIiII11i1 [ OoOOoO0oOo ]
    if ( I11iII == "" ) : continue
    O0O0iIIi11Ii = II1i1OoOOo0o0o00 [ OoOOoO0oOo ]
    O0O0iIIi11Ii . elp_name = I11iII
    if 80 - 80: i11iIiiIii / OoOoOO00 . OOooOOo . iIii1I11I1II1
    if 81 - 81: I1ii11iIi11i * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO
  if ( I111iIiI == "rle-name" ) :
   for OoOOoO0oOo in range ( len ( II1i1OoOOo0o0o00 ) ) :
    I11iII = iiIiII11i1 [ OoOOoO0oOo ]
    if ( I11iII == "" ) : continue
    O0O0iIIi11Ii = II1i1OoOOo0o0o00 [ OoOOoO0oOo ]
    O0O0iIIi11Ii . rle_name = I11iII
    if 64 - 64: Oo0Ooo . I1ii11iIi11i / ooOoO0o % oO0o . iIii1I11I1II1
    if 84 - 84: II111iiii . oO0o * O0 / iII111i + OoooooooOO
  if ( I111iIiI == "json-name" ) :
   for OoOOoO0oOo in range ( len ( II1i1OoOOo0o0o00 ) ) :
    I11iII = iiIiII11i1 [ OoOOoO0oOo ]
    if ( I11iII == "" ) : continue
    O0O0iIIi11Ii = II1i1OoOOo0o0o00 [ OoOOoO0oOo ]
    O0O0iIIi11Ii . json_name = I11iII
    if 99 - 99: I1ii11iIi11i . oO0o + Oo0Ooo + I1ii11iIi11i / I1Ii111 . I1ii11iIi11i
    if 95 - 95: OoOoOO00 * iIii1I11I1II1 / OoooooooOO % i1IIi
  if ( I111iIiI == "datetime-range" ) :
   for OoOOoO0oOo in range ( len ( II1i1OoOOo0o0o00 ) ) :
    I11iII = iiIiII11i1 [ OoOOoO0oOo ]
    O0O0iIIi11Ii = II1i1OoOOo0o0o00 [ OoOOoO0oOo ]
    if ( I11iII == "" ) : continue
    i1IIiI1iII = lisp_datetime ( I11iII [ 0 : 19 ] )
    OO0O0OOooo = lisp_datetime ( I11iII [ 19 : : ] )
    if ( i1IIiI1iII . valid_datetime ( ) and OO0O0OOooo . valid_datetime ( ) ) :
     O0O0iIIi11Ii . datetime_lower = i1IIiI1iII
     O0O0iIIi11Ii . datetime_upper = OO0O0OOooo
     if 91 - 91: OOooOOo - OoOoOO00
     if 58 - 58: II111iiii . OOooOOo % II111iiii * oO0o % OoO0O00 % I11i
     if 71 - 71: Ii1I * II111iiii * I1IiiI
     if 22 - 22: oO0o
     if 96 - 96: ooOoO0o * iII111i . IiII
     if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
     if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
  if ( I111iIiI == "set-action" ) :
   o00oo . set_action = iiIiII11i1
   if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
  if ( I111iIiI == "set-record-ttl" ) :
   o00oo . set_record_ttl = int ( iiIiII11i1 )
   if 22 - 22: i1IIi
  if ( I111iIiI == "set-instance-id" ) :
   if ( o00oo . set_source_eid == None ) :
    o00oo . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 33 - 33: O0
   if ( o00oo . set_dest_eid == None ) :
    o00oo . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 34 - 34: I1Ii111 . IiII % iII111i
   oOoOO0oOO0oo = int ( iiIiII11i1 )
   o00oo . set_source_eid . instance_id = oOoOO0oOO0oo
   o00oo . set_dest_eid . instance_id = oOoOO0oOO0oo
   if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
  if ( I111iIiI == "set-source-eid" ) :
   if ( o00oo . set_source_eid == None ) :
    o00oo . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
   o00oo . set_source_eid . store_prefix ( iiIiII11i1 )
   if ( oOoOO0oOO0oo != None ) : o00oo . set_source_eid . instance_id = oOoOO0oOO0oo
   if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
  if ( I111iIiI == "set-destination-eid" ) :
   if ( o00oo . set_dest_eid == None ) :
    o00oo . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 75 - 75: i1IIi * i11iIiiIii
   o00oo . set_dest_eid . store_prefix ( iiIiII11i1 )
   if ( oOoOO0oOO0oo != None ) : o00oo . set_dest_eid . instance_id = oOoOO0oOO0oo
   if 40 - 40: I1ii11iIi11i + OoO0O00
  if ( I111iIiI == "set-rloc-address" ) :
   o00oo . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   o00oo . set_rloc_address . store_address ( iiIiII11i1 )
   if 8 - 8: i11iIiiIii - iIii1I11I1II1
  if ( I111iIiI == "set-rloc-record-name" ) :
   o00oo . set_rloc_record_name = iiIiII11i1
   if 73 - 73: OoOoOO00
  if ( I111iIiI == "set-elp-name" ) :
   o00oo . set_elp_name = iiIiII11i1
   if 25 - 25: iII111i / oO0o
  if ( I111iIiI == "set-geo-name" ) :
   o00oo . set_geo_name = iiIiII11i1
   if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
  if ( I111iIiI == "set-rle-name" ) :
   o00oo . set_rle_name = iiIiII11i1
   if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
  if ( I111iIiI == "set-json-name" ) :
   o00oo . set_json_name = iiIiII11i1
   if 61 - 61: I1IiiI / OOooOOo
  if ( I111iIiI == "policy-name" ) :
   o00oo . policy_name = iiIiII11i1
   if 67 - 67: OoOoOO00
   if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
   if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
   if 95 - 95: ooOoO0o % OOooOOo
   if 17 - 17: i1IIi + Ii1I
   if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
 o00oo . match_clauses = II1i1OoOOo0o0o00
 o00oo . save_policy ( )
 return
 if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
 if 26 - 26: oO0o / I1ii11iIi11i - oO0o
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
if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
if 96 - 96: Ii1I
if 90 - 90: II111iiii
if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
if 52 - 52: i11iIiiIii * ooOoO0o
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 oO0OoO000oO0o = command
 if ( interface != "" ) : oO0OoO000oO0o = interface + ": " + oO0OoO000oO0o
 lprint ( "Send CLI command '{}' to hardware" . format ( oO0OoO000oO0o ) )
 if 18 - 18: IiII . i11iIiiIii % I1IiiI
 I1I1iii11I1 = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
 os . system ( "FastCli -c '{}'" . format ( I1I1iii11I1 ) )
 return
 if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
 if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
 if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
 if 19 - 19: I1ii11iIi11i
 if 42 - 42: OoOoOO00 / IiII
 if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
 if 99 - 99: I11i % ooOoO0o . I1Ii111
def lisp_arista_is_alive ( prefix ) :
 i1iii1IiiiI1i1 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 OoiIIIiIi1I1i = getoutput ( "FastCli -c '{}'" . format ( i1iii1IiiiI1i1 ) )
 if 34 - 34: ooOoO0o + oO0o + II111iiii . I1Ii111 . i1IIi
 if 14 - 14: OoO0O00 . ooOoO0o - i1IIi * I1IiiI
 if 24 - 24: iIii1I11I1II1 / I1Ii111
 if 16 - 16: OoOoOO00 * I1Ii111 - I1IiiI / I1Ii111
 OoiIIIiIi1I1i = OoiIIIiIi1I1i . split ( "\n" ) [ 1 ]
 OOooOOOOoo0o0 = OoiIIIiIi1I1i . split ( " " )
 OOooOOOOoo0o0 = OOooOOOOoo0o0 [ - 1 ] . replace ( "\r" , "" )
 if 10 - 10: II111iiii . O0
 if 46 - 46: iIii1I11I1II1
 if 8 - 8: I1ii11iIi11i % I11i - i1IIi . Oo0Ooo * I1Ii111
 if 44 - 44: iII111i
 return ( OOooOOOOoo0o0 == "Y" )
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
 if 42 - 42: OOooOOo - I1ii11iIi11i
 if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
 if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
 if 12 - 12: i11iIiiIii
 if 62 - 62: oO0o + OOooOOo + oO0o + I1IiiI
 if 10 - 10: IiII - Oo0Ooo % ooOoO0o
 if 38 - 38: oO0o * o0oOOo0O0Ooo . I11i % II111iiii / I11i % Ii1I
 if 19 - 19: II111iiii / i11iIiiIii * II111iiii + OoOoOO00 - OoOoOO00
 if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
 if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
 if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
 if 76 - 76: IiII % I1IiiI . iII111i
 if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
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
 if 91 - 91: O0
 if 13 - 13: o0oOOo0O0Ooo
 if 15 - 15: iIii1I11I1II1 * Oo0Ooo . iIii1I11I1II1 . Ii1I % iII111i - i11iIiiIii
def lisp_program_vxlan_hardware ( mc ) :
 if 77 - 77: ooOoO0o - o0oOOo0O0Ooo * OoOoOO00 % oO0o
 if 4 - 4: i11iIiiIii + OoOoOO00
 if 45 - 45: ooOoO0o / OoooooooOO . Oo0Ooo
 if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
 if 53 - 53: i1IIi
 if 51 - 51: OoOoOO00 / iIii1I11I1II1 . oO0o - I1ii11iIi11i - OOooOOo
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 90 - 90: i1IIi / oO0o * I1Ii111 + II111iiii % I11i
 if 41 - 41: o0oOOo0O0Ooo - II111iiii . ooOoO0o . iII111i - ooOoO0o / iII111i
 if 59 - 59: O0 / II111iiii * II111iiii - ooOoO0o
 if 63 - 63: I1ii11iIi11i * IiII % OoO0O00 . OoOoOO00 - II111iiii % IiII
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 8 - 8: iIii1I11I1II1
 if 71 - 71: oO0o / o0oOOo0O0Ooo % iIii1I11I1II1 * iIii1I11I1II1
 if 29 - 29: ooOoO0o - OoOoOO00 - o0oOOo0O0Ooo
 if 54 - 54: Ii1I + i11iIiiIii + i1IIi - OoooooooOO
 II1i1i = mc . eid . print_prefix_no_iid ( )
 OooOOoOO0OO = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 100 - 100: oO0o . ooOoO0o
 if 14 - 14: OoooooooOO + iII111i / iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1 - IiII
 if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
 if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
 OO00oo = getoutput ( "ip route get {} | egrep vlan4094" . format ( II1i1i ) )
 if 71 - 71: I1Ii111 % Ii1I - I11i / I11i - Ii1I
 if ( OO00oo != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( II1i1i , False ) , OO00oo ) )
  if 54 - 54: Oo0Ooo . OoO0O00 * iII111i . i1IIi - o0oOOo0O0Ooo
  return
  if 33 - 33: Ii1I - oO0o . iII111i * I1ii11iIi11i
  if 78 - 78: oO0o % ooOoO0o
  if 37 - 37: iIii1I11I1II1 + Oo0Ooo + OoO0O00 . I11i % iIii1I11I1II1 + I1Ii111
  if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
  if 90 - 90: OOooOOo
  if 43 - 43: IiII + ooOoO0o
  if 4 - 4: i1IIi
 oOooii111 = getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( oOooii111 . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 90 - 90: iII111i . Oo0Ooo * o0oOOo0O0Ooo % I11i . OoOoOO00
 if ( oOooii111 . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 63 - 63: I1ii11iIi11i + OoOoOO00 - Ii1I + OoO0O00 - II111iiii
 IiIiIIIi1iiIi = getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( IiIiIIIi1iiIi == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 88 - 88: II111iiii / O0 * O0 % I1IiiI % I11i
 IiIiIIIi1iiIi = IiIiIIIi1iiIi . split ( "inet " ) [ 1 ]
 IiIiIIIi1iiIi = IiIiIIIi1iiIi . split ( "/" ) [ 0 ]
 if 74 - 74: OoooooooOO / i1IIi * i1IIi / OoO0O00 / I1Ii111
 if 51 - 51: i1IIi - oO0o / I11i + Ii1I + ooOoO0o
 if 23 - 23: OoOoOO00 . oO0o - iII111i
 if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
 if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
 if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
 if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
 oo0oOo0oOoO0o = [ ]
 iIii1iiI111 = getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for i11 in iIii1iiI111 :
  if ( i11 . find ( "vlan4094" ) == - 1 ) : continue
  if ( i11 . find ( "(incomplete)" ) == - 1 ) : continue
  IIi1iiii1Ii = i11 . split ( " " ) [ 0 ]
  oo0oOo0oOoO0o . append ( IIi1iiii1Ii )
  if 8 - 8: ooOoO0o * I1Ii111 + o0oOOo0O0Ooo * II111iiii
  if 61 - 61: oO0o
 IIi1iiii1Ii = None
 Ii1IiIOo = IiIiIIIi1iiIi
 IiIiIIIi1iiIi = IiIiIIIi1iiIi . split ( "." )
 for OoOOoO0oOo in range ( 1 , 255 ) :
  IiIiIIIi1iiIi [ 3 ] = str ( OoOOoO0oOo )
  oOOOo0o = "." . join ( IiIiIIIi1iiIi )
  if ( oOOOo0o in oo0oOo0oOoO0o ) : continue
  if ( oOOOo0o == Ii1IiIOo ) : continue
  IIi1iiii1Ii = oOOOo0o
  break
  if 45 - 45: I11i * OoOoOO00 % Oo0Ooo / iII111i
 if ( IIi1iiii1Ii == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 78 - 78: II111iiii
  return
  if 38 - 38: I11i - i11iIiiIii
  if 38 - 38: I1IiiI * i1IIi / OoO0O00 + iIii1I11I1II1 / I1Ii111 % II111iiii
  if 62 - 62: OoOoOO00 * i1IIi + iII111i
  if 43 - 43: OOooOOo % i11iIiiIii / I1ii11iIi11i + i1IIi / ooOoO0o
  if 74 - 74: Ii1I + iIii1I11I1II1
  if 23 - 23: OoO0O00 * i1IIi * oO0o % I1ii11iIi11i
  if 92 - 92: iII111i / I1IiiI / i11iIiiIii
 OOo0000 = OooOOoOO0OO . split ( "." )
 o00oO0o0O0oo = lisp_hex_string ( OOo0000 [ 1 ] ) . zfill ( 2 )
 I11I1iIIIi = lisp_hex_string ( OOo0000 [ 2 ] ) . zfill ( 2 )
 II1I111I11II = lisp_hex_string ( OOo0000 [ 3 ] ) . zfill ( 2 )
 O0o0oo0oOO0oO = "00:00:00:{}:{}:{}" . format ( o00oO0o0O0oo , I11I1iIIIi , II1I111I11II )
 Ii11I = "0000.00{}.{}{}" . format ( o00oO0o0O0oo , I11I1iIIIi , II1I111I11II )
 i1oOo00o00o = "arp -i vlan4094 -s {} {}" . format ( IIi1iiii1Ii , O0o0oo0oOO0oO )
 os . system ( i1oOo00o00o )
 if 98 - 98: oO0o + I1IiiI * I11i . II111iiii . O0
 if 7 - 7: OOooOOo . O0
 if 65 - 65: I11i
 if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
 o0Oooo00o = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( Ii11I , OooOOoOO0OO )
 if 67 - 67: IiII / oO0o . O0
 lisp_send_to_arista ( o0Oooo00o , None )
 if 70 - 70: I1ii11iIi11i % O0
 if 57 - 57: i1IIi + OoOoOO00
 if 8 - 8: Ii1I + I11i * oO0o % I11i
 if 17 - 17: o0oOOo0O0Ooo + Oo0Ooo
 if 38 - 38: oO0o + I1IiiI + OOooOOo
 ooooo0 = "ip route add {} via {}" . format ( II1i1i , IIi1iiii1Ii )
 os . system ( ooooo0 )
 if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
 lprint ( "Hardware programmed with commands:" )
 ooooo0 = ooooo0 . replace ( II1i1i , green ( II1i1i , False ) )
 lprint ( "  " + ooooo0 )
 lprint ( "  " + i1oOo00o00o )
 o0Oooo00o = o0Oooo00o . replace ( OooOOoOO0OO , red ( OooOOoOO0OO , False ) )
 lprint ( "  " + o0Oooo00o )
 return
 if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
 if 20 - 20: I1IiiI + iII111i + O0 * O0
 if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
 if 31 - 31: ooOoO0o
 if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
 if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
 if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
def lisp_clear_hardware_walk ( mc , parms ) :
 Ii1I1I11I11 = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( Ii1I1I11I11 ) )
 return ( [ True , None ] )
 if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
 if 97 - 97: O0
 if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
 if 31 - 31: iIii1I11I1II1
 if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
 if 20 - 20: iIii1I11I1II1 % OOooOOo
 if 91 - 91: ooOoO0o
 if 96 - 96: I1IiiI . OOooOOo
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
 i1IIiI1IiIi = bold ( "User cleared" , False )
 IiI = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( i1IIiI1IiIi , IiI ) )
 if 33 - 33: I1ii11iIi11i
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 85 - 85: ooOoO0o / I11i
 lisp_map_cache = lisp_cache ( )
 if 52 - 52: OoooooooOO
 if 84 - 84: O0 . OOooOOo / IiII - i1IIi % OoooooooOO
 if 5 - 5: ooOoO0o % Oo0Ooo % II111iiii + ooOoO0o
 if 6 - 6: OoO0O00 + I1Ii111 - Ii1I / I1ii11iIi11i
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 31 - 31: O0 . OoooooooOO % oO0o / i11iIiiIii
 if 85 - 85: I11i
 if 23 - 23: oO0o % I11i * Oo0Ooo + Oo0Ooo
 if 23 - 23: Ii1I % i1IIi - I1Ii111
 if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 lisp_rloc_probe_list = { }
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
 if 11 - 11: IiII / I1IiiI . I1IiiI
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
 if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
 if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
 if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
 if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
 lisp_rtr_list = { }
 if 3 - 3: I1Ii111
 if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
 if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
 if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
 lisp_gleaned_groups = { }
 if 55 - 55: OoooooooOO / IiII + i1IIi
 if 54 - 54: ooOoO0o * Ii1I / Ii1I
 if 15 - 15: oO0o * I1Ii111
 if 11 - 11: Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 lisp_process_data_plane_restart ( True )
 return
 if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: oO0o + OoOoOO00
 if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 if 59 - 59: O0
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 if 15 - 15: I11i - OOooOOo . II111iiii . iIii1I11I1II1
def lisp_encapsulate_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 93 - 93: I11i + o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 o0oo = lisp_myrlocs [ 0 ]
 if 64 - 64: OoOoOO00 / OoO0O00 + oO0o
 if 16 - 16: I1ii11iIi11i . I1ii11iIi11i
 if 38 - 38: O0 / OoO0O00
 if 80 - 80: ooOoO0o
 if 46 - 46: Ii1I
 iI = len ( packet ) + 28
 o0OO00oo0O = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( iI ) , 0 , 64 ,
 17 , 0 , socket . htonl ( o0oo . address ) , socket . htonl ( rloc . address ) )
 o0OO00oo0O = lisp_ip_checksum ( o0OO00oo0O )
 if 48 - 48: I1Ii111 + i1IIi - Ii1I
 Ii1iiI1 = struct . pack ( "HHHH" , 0 , socket . htons ( LISP_CTRL_PORT ) ,
 socket . htons ( iI - 20 ) , 0 )
 if 94 - 94: iII111i . I1IiiI
 if 5 - 5: OoooooooOO + o0oOOo0O0Ooo + OOooOOo * OoO0O00 . OOooOOo . I11i
 if 49 - 49: I1IiiI * OoOoOO00 . OoOoOO00 % I1Ii111 * iIii1I11I1II1 . OOooOOo
 if 9 - 9: OoOoOO00 - O0 + Oo0Ooo
 packet = lisp_packet ( o0OO00oo0O + Ii1iiI1 + packet )
 if 89 - 89: IiII - iII111i + IiII
 if 39 - 39: oO0o % I11i . oO0o * I11i
 if 36 - 36: i1IIi / I1ii11iIi11i * iIii1I11I1II1
 if 44 - 44: Ii1I / I1Ii111
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( o0oo )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( o0oo )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 81 - 81: OoooooooOO * I1IiiI * II111iiii . Oo0Ooo
 o00oO = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  Ooo0OOo = " {}" . format ( blue ( nat_info . hostname , False ) )
  iiIii11Ii = bold ( "RLOC-probe request" , False )
 else :
  Ooo0OOo = ""
  iiIii11Ii = bold ( "RLOC-probe reply" , False )
  if 28 - 28: iII111i * I1IiiI + Oo0Ooo % I1ii11iIi11i / OoooooooOO * ooOoO0o
  if 45 - 45: OoO0O00 + iIii1I11I1II1 + ooOoO0o - OoO0O00
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( iiIii11Ii , o00oO , Ooo0OOo , packet . encap_port ) )
 if 22 - 22: I1IiiI
 if 28 - 28: OoO0O00 / ooOoO0o % OoOoOO00 - Ii1I * i11iIiiIii + I1ii11iIi11i
 if 90 - 90: ooOoO0o * o0oOOo0O0Ooo + Ii1I / I11i % II111iiii
 if 59 - 59: I11i + iII111i + I11i
 if 84 - 84: I1IiiI * Ii1I . I1IiiI % OOooOOo * Ii1I % OoO0O00
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
 iIiiooo0 = lisp_sockets [ 3 ]
 packet . send_packet ( iIiiooo0 , packet . outer_dest )
 del ( packet )
 return
 if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if 88 - 88: OoooooooOO . I1IiiI
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 if 7 - 7: i1IIi
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
 if 29 - 29: II111iiii % i11iIiiIii % O0
def lisp_get_default_route_next_hops ( ) :
 if 38 - 38: o0oOOo0O0Ooo * IiII
 if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
 if 19 - 19: OoooooooOO
 if ( lisp_is_macos ( ) ) :
  i1iii1IiiiI1i1 = "route -n get default"
  iII = getoutput ( i1iii1IiiiI1i1 ) . split ( "\n" )
  oO0o000 = i1i1111I = None
  for iiI1i1I in iII :
   if ( iiI1i1I . find ( "gateway: " ) != - 1 ) : oO0o000 = iiI1i1I . split ( ": " ) [ 1 ]
   if ( iiI1i1I . find ( "interface: " ) != - 1 ) : i1i1111I = iiI1i1I . split ( ": " ) [ 1 ]
   if 57 - 57: o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
  return ( [ [ i1i1111I , oO0o000 ] ] )
  if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
  if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
  if 80 - 80: II111iiii . i11iIiiIii
  if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
  if 33 - 33: iIii1I11I1II1
 i1iii1IiiiI1i1 = "ip route | egrep 'default via'"
 O0O0o0O0OoOoOO = getoutput ( i1iii1IiiiI1i1 ) . split ( "\n" )
 if 52 - 52: iIii1I11I1II1 + O0
 Oo00oooOO00o0 = [ ]
 for OO00oo in O0O0o0O0OoOoOO :
  if ( OO00oo . find ( " metric " ) != - 1 ) : continue
  I1I1iIiiiiII11 = OO00oo . split ( " " )
  try :
   O0o0o = I1I1iIiiiiII11 . index ( "via" ) + 1
   if ( O0o0o >= len ( I1I1iIiiiiII11 ) ) : continue
   IiOOOO0 = I1I1iIiiiiII11 . index ( "dev" ) + 1
   if ( IiOOOO0 >= len ( I1I1iIiiiiII11 ) ) : continue
  except :
   continue
   if 42 - 42: O0 - II111iiii
   if 33 - 33: I1Ii111 * IiII * OOooOOo - ooOoO0o % II111iiii
  Oo00oooOO00o0 . append ( [ I1I1iIiiiiII11 [ IiOOOO0 ] , I1I1iIiiiiII11 [ O0o0o ] ] )
  if 24 - 24: O0 . IiII % i11iIiiIii - i1IIi * I1Ii111
 return ( Oo00oooOO00o0 )
 if 9 - 9: i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
 if 90 - 90: IiII
 if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
 if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
 if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
def lisp_get_host_route_next_hop ( rloc ) :
 i1iii1IiiiI1i1 = "ip route | egrep '{} via'" . format ( rloc )
 OO00oo = getoutput ( i1iii1IiiiI1i1 ) . split ( " " )
 if 98 - 98: OOooOOo
 try : OOOooo0OooOoO = OO00oo . index ( "via" ) + 1
 except : return ( None )
 if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
 if ( OOOooo0OooOoO >= len ( OO00oo ) ) : return ( None )
 return ( OO00oo [ OOOooo0OooOoO ] )
 if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
 if 75 - 75: II111iiii . O0 . I1Ii111 * O0 / OoooooooOO
 if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
 if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
 if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i . Ii1I + I1IiiI % i11iIiiIii - i11iIiiIii
 if 62 - 62: I1Ii111 + I1IiiI
 if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 I1iI1II1Iii = "none" if nh == None else nh
 if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
 lprint ( "{} host-route {}, nh {}" . format ( install . title ( ) , dest , I1iI1II1Iii ) )
 if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
 if ( nh == None ) :
  I11IiI1i11i1 = "ip route {} {}/32" . format ( install , dest )
 else :
  I11IiI1i11i1 = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
 os . system ( I11IiI1i11i1 )
 return
 if 59 - 59: iII111i
 if 14 - 14: oO0o . IiII + iIii1I11I1II1 - i1IIi
 if 46 - 46: i11iIiiIii * II111iiii / i11iIiiIii % i11iIiiIii * II111iiii + i11iIiiIii
 if 87 - 87: Oo0Ooo + OoO0O00 / II111iiii * OoooooooOO
 if 95 - 95: I1Ii111 * o0oOOo0O0Ooo + OoO0O00 % OoOoOO00 - ooOoO0o / OoOoOO00
 if 45 - 45: OoooooooOO / oO0o / o0oOOo0O0Ooo + Ii1I + O0 . iII111i
 if 34 - 34: iIii1I11I1II1 . o0oOOo0O0Ooo + ooOoO0o
 if 96 - 96: O0 / ooOoO0o
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 82 - 82: OoO0O00 * OOooOOo * I11i * I1Ii111 % iIii1I11I1II1
 iiI1i1I = open ( lisp_checkpoint_filename , "w" )
 for iIiiI11II11i in checkpoint_list :
  iiI1i1I . write ( iIiiI11II11i + "\n" )
  if 50 - 50: Ii1I * Ii1I % I11i / iIii1I11I1II1 / ooOoO0o / iII111i
 iiI1i1I . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 91 - 91: Ii1I - O0 . I11i - OoooooooOO * IiII . II111iiii
 if 38 - 38: I1IiiI + OoO0O00
 if 11 - 11: iIii1I11I1II1 + i1IIi * IiII - Oo0Ooo
 if 66 - 66: I1Ii111 . Ii1I / I1ii11iIi11i / iIii1I11I1II1 + O0 / i1IIi
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 iiI1i1I = open ( lisp_checkpoint_filename , "r" )
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 IiI = 0
 for iIiiI11II11i in iiI1i1I :
  IiI += 1
  I1i = iIiiI11II11i . split ( " rloc " )
  o0O = [ ] if ( I1i [ 1 ] in [ "native-forward\n" , "\n" ] ) else I1i [ 1 ] . split ( ", " )
  if 100 - 100: O0
  if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
  IIiii11iiI111 = [ ]
  for OooOOoOO0OO in o0O :
   II1 = lisp_rloc ( False )
   I1I1iIiiiiII11 = OooOOoOO0OO . split ( " " )
   II1 . rloc . store_address ( I1I1iIiiiiII11 [ 0 ] )
   II1 . priority = int ( I1I1iIiiiiII11 [ 1 ] )
   II1 . weight = int ( I1I1iIiiiiII11 [ 2 ] )
   IIiii11iiI111 . append ( II1 )
   if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
   if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
  O0oo0OOo00o0o = lisp_mapping ( "" , "" , IIiii11iiI111 )
  if ( O0oo0OOo00o0o != None ) :
   O0oo0OOo00o0o . eid . store_prefix ( I1i [ 0 ] )
   O0oo0OOo00o0o . checkpoint_entry = True
   O0oo0OOo00o0o . map_cache_ttl = LISP_NMR_TTL * 60
   if ( IIiii11iiI111 == [ ] ) : O0oo0OOo00o0o . action = LISP_NATIVE_FORWARD_ACTION
   O0oo0OOo00o0o . add_cache ( )
   continue
   if 38 - 38: Ii1I
   if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
  IiI -= 1
  if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
  if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 iiI1i1I . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , IiI , lisp_checkpoint_filename ) )
 return
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
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 11 - 11: ooOoO0o - OoOoOO00
 iIiiI11II11i = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 for II1 in mc . rloc_set :
  if ( II1 . rloc . is_null ( ) ) : continue
  iIiiI11II11i += "{} {} {}, " . format ( II1 . rloc . print_address_no_iid ( ) ,
 II1 . priority , II1 . weight )
  if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
  if 4 - 4: OoO0O00 - OOooOOo
 if ( mc . rloc_set != [ ] ) :
  iIiiI11II11i = iIiiI11II11i [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  iIiiI11II11i += "native-forward"
  if 21 - 21: I1Ii111 * i11iIiiIii
  if 63 - 63: oO0o + OoOoOO00
 checkpoint_list . append ( iIiiI11II11i )
 return
 if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
 if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
 if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
 if 20 - 20: Ii1I * iII111i / ooOoO0o
 if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
 if 23 - 23: I1IiiI - I1ii11iIi11i . O0 . OoOoOO00 . OoO0O00
 if 81 - 81: IiII * I11i - iIii1I11I1II1
def lisp_check_dp_socket ( ) :
 III1IIIII1II = lisp_ipc_dp_socket_name
 if ( os . path . exists ( III1IIIII1II ) == False ) :
  O0oO00ooOoo = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( III1IIIII1II , O0oO00ooOoo ) )
  return ( False )
  if 14 - 14: OoOoOO00 - I1ii11iIi11i
 return ( True )
 if 88 - 88: ooOoO0o / iII111i . oO0o . O0 * IiII / OoO0O00
 if 79 - 79: II111iiii % OOooOOo * OoOoOO00
 if 82 - 82: Ii1I
 if 83 - 83: I1IiiI
 if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
 if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
 if 45 - 45: I11i - iIii1I11I1II1
def lisp_write_to_dp_socket ( entry ) :
 try :
  i1iIIIi = json . dumps ( entry )
  oooOooO000o0O = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( oooOooO000o0O , i1iIIIi ) )
  lisp_ipc_dp_socket . sendto ( i1iIIIi , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( i1iIIIi ) )
  if 96 - 96: O0
 return
 if 49 - 49: OOooOOo . iIii1I11I1II1 * OoO0O00 . I1IiiI * OoOoOO00 / II111iiii
 if 72 - 72: I11i
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
 if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
 if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
def lisp_write_ipc_keys ( rloc ) :
 Oo0o = rloc . rloc . print_address_no_iid ( )
 O00oo0o0o0oo = rloc . translated_port
 if ( O00oo0o0o0oo != 0 ) : Oo0o += ":" + str ( O00oo0o0o0oo )
 if ( Oo0o not in lisp_rloc_probe_list ) : return
 if 9 - 9: i1IIi % iII111i / Ii1I
 for I1I1iIiiiiII11 , I1i , o0O0Ooo in lisp_rloc_probe_list [ Oo0o ] :
  O0oo0OOo00o0o = lisp_map_cache . lookup_cache ( I1i , True )
  if ( O0oo0OOo00o0o == None ) : continue
  lisp_write_ipc_map_cache ( True , O0oo0OOo00o0o )
  if 83 - 83: oO0o
 return
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if 29 - 29: OoooooooOO
 if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
 if 83 - 83: iIii1I11I1II1
 if 92 - 92: OoO0O00 - iII111i
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 if 74 - 74: i1IIi % i11iIiiIii + oO0o
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 o0ooOOoO0oO0 = "add" if add_or_delete else "delete"
 iIiiI11II11i = { "type" : "map-cache" , "opcode" : o0ooOOoO0oO0 }
 if 34 - 34: Oo0Ooo . i1IIi
 oOoOo = ( mc . group . is_null ( ) == False )
 if ( oOoOo ) :
  iIiiI11II11i [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  iIiiI11II11i [ "rles" ] = [ ]
 else :
  iIiiI11II11i [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  iIiiI11II11i [ "rlocs" ] = [ ]
  if 97 - 97: I11i
 iIiiI11II11i [ "instance-id" ] = str ( mc . eid . instance_id )
 if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
 if ( oOoOo ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for IIIi11i1 in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    oOOOo0o = IIIi11i1 . address . print_address_no_iid ( )
    O00oo0o0o0oo = str ( 4341 ) if IIIi11i1 . translated_port == 0 else str ( IIIi11i1 . translated_port )
    if 20 - 20: oO0o % OoOoOO00
    I1I1iIiiiiII11 = { "rle" : oOOOo0o , "port" : O00oo0o0o0oo }
    OooOo0o , OO00ooo0 = IIIi11i1 . get_encap_keys ( )
    I1I1iIiiiiII11 = lisp_build_json_keys ( I1I1iIiiiiII11 , OooOo0o , OO00ooo0 , "encrypt-key" )
    iIiiI11II11i [ "rles" ] . append ( I1I1iIiiiiII11 )
    if 14 - 14: oO0o / I1Ii111 / IiII - i1IIi * Ii1I
    if 90 - 90: ooOoO0o
 else :
  for OooOOoOO0OO in mc . rloc_set :
   if ( OooOOoOO0OO . rloc . is_ipv4 ( ) == False and OooOOoOO0OO . rloc . is_ipv6 ( ) == False ) :
    continue
    if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
   if ( OooOOoOO0OO . up_state ( ) == False ) : continue
   if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
   O00oo0o0o0oo = str ( 4341 ) if OooOOoOO0OO . translated_port == 0 else str ( OooOOoOO0OO . translated_port )
   if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
   I1I1iIiiiiII11 = { "rloc" : OooOOoOO0OO . rloc . print_address_no_iid ( ) , "priority" :
 str ( OooOOoOO0OO . priority ) , "weight" : str ( OooOOoOO0OO . weight ) , "port" :
 O00oo0o0o0oo }
   OooOo0o , OO00ooo0 = OooOOoOO0OO . get_encap_keys ( )
   I1I1iIiiiiII11 = lisp_build_json_keys ( I1I1iIiiiiII11 , OooOo0o , OO00ooo0 , "encrypt-key" )
   iIiiI11II11i [ "rlocs" ] . append ( I1I1iIiiiiII11 )
   if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
   if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
   if 55 - 55: Oo0Ooo - OOooOOo - O0
 if ( dont_send == False ) : lisp_write_to_dp_socket ( iIiiI11II11i )
 return ( iIiiI11II11i )
 if 40 - 40: OoOoOO00 - OOooOOo
 if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 if 35 - 35: II111iiii
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if 96 - 96: O0
 if 15 - 15: i1IIi . iIii1I11I1II1
 if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
 if 61 - 61: I1Ii111 + I11i + I1IiiI
 if 48 - 48: I11i
 if 67 - 67: o0oOOo0O0Ooo
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
 OooOo0o = keys [ 1 ] . encrypt_key
 OO00ooo0 = keys [ 1 ] . icv_key
 if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
 if 89 - 89: ooOoO0o % i11iIiiIii
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 o00oo0OoOo0 = rloc_addr . split ( ":" )
 if ( len ( o00oo0OoOo0 ) == 1 ) :
  iIiiI11II11i = { "type" : "decap-keys" , "rloc" : o00oo0OoOo0 [ 0 ] }
 else :
  iIiiI11II11i = { "type" : "decap-keys" , "rloc" : o00oo0OoOo0 [ 0 ] , "port" : o00oo0OoOo0 [ 1 ] }
  if 32 - 32: ooOoO0o * OoO0O00 - I11i - OoooooooOO % i1IIi
 iIiiI11II11i = lisp_build_json_keys ( iIiiI11II11i , OooOo0o , OO00ooo0 , "decrypt-key" )
 if 81 - 81: OOooOOo * O0 + II111iiii . Oo0Ooo
 lisp_write_to_dp_socket ( iIiiI11II11i )
 return
 if 52 - 52: I1IiiI . oO0o % O0
 if 42 - 42: I1Ii111
 if 81 - 81: I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - O0 * iII111i
 if 35 - 35: OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111 * OoO0O00
 if 78 - 78: iIii1I11I1II1 + I11i - OoOoOO00 / I1ii11iIi11i + iIii1I11I1II1 % II111iiii
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 53 - 53: Ii1I
 entry [ "keys" ] = [ ]
 III11II111 = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( III11II111 )
 return ( entry )
 if 63 - 63: I11i % OoOoOO00
 if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
 if 52 - 52: I11i + iII111i
 if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
 if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
 if 62 - 62: IiII . O0
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
 if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
 if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
 if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
 iIiiI11II11i = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
 if 24 - 24: OoOoOO00
 if 87 - 87: I1ii11iIi11i / ooOoO0o * i1IIi
 if 71 - 71: OoOoOO00 - I11i
 for iIiI1ii in lisp_db_list :
  if ( iIiI1ii . eid . is_ipv4 ( ) == False and iIiI1ii . eid . is_ipv6 ( ) == False ) : continue
  OOOOoOO = { "instance-id" : str ( iIiI1ii . eid . instance_id ) ,
 "eid-prefix" : iIiI1ii . eid . print_prefix_no_iid ( ) }
  iIiiI11II11i [ "database-mappings" ] . append ( OOOOoOO )
  if 38 - 38: iII111i
 lisp_write_to_dp_socket ( iIiiI11II11i )
 if 66 - 66: iII111i + Oo0Ooo + i1IIi * Oo0Ooo
 if 18 - 18: O0 - IiII
 if 5 - 5: I1ii11iIi11i * iII111i + II111iiii * Oo0Ooo * O0 - I1IiiI
 if 71 - 71: i11iIiiIii % I1IiiI + I1ii11iIi11i + II111iiii + OoooooooOO + oO0o
 if 12 - 12: I1IiiI + I1Ii111
 iIiiI11II11i = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( iIiiI11II11i )
 return
 if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
 if 79 - 79: Ii1I + IiII
 if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
 if 98 - 98: I1ii11iIi11i
 if 58 - 58: IiII / i11iIiiIii % I11i
 if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 21 - 21: Ii1I
 if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
 if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
 if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
 iIiiI11II11i = { "type" : "interfaces" , "interfaces" : [ ] }
 if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
 for i1i1111I in list ( lisp_myinterfaces . values ( ) ) :
  if ( i1i1111I . instance_id == None ) : continue
  OOOOoOO = { "interface" : i1i1111I . device ,
 "instance-id" : str ( i1i1111I . instance_id ) }
  iIiiI11II11i [ "interfaces" ] . append ( OOOOoOO )
  if 44 - 44: iIii1I11I1II1 . OOooOOo
  if 57 - 57: II111iiii + I1Ii111
 lisp_write_to_dp_socket ( iIiiI11II11i )
 return
 if 42 - 42: OoOoOO00 % O0
 if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
 if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
 if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
 if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
 if 26 - 26: Ii1I * I11i / I11i
 if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
 if 16 - 16: I11i
 if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
def lisp_parse_auth_key ( value ) :
 O0oOOoooOOoO0000 = value . split ( "[" )
 oo0Oo00o000 = { }
 if ( len ( O0oOOoooOOoO0000 ) == 1 ) :
  oo0Oo00o000 [ 0 ] = value
  return ( oo0Oo00o000 )
  if 17 - 17: II111iiii
  if 29 - 29: o0oOOo0O0Ooo - iII111i
 for I11iII in O0oOOoooOOoO0000 :
  if ( I11iII == "" ) : continue
  OOOooo0OooOoO = I11iII . find ( "]" )
  oo0OO0oo = I11iII [ 0 : OOOooo0OooOoO ]
  try : oo0OO0oo = int ( oo0OO0oo )
  except : return
  if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
  oo0Oo00o000 [ oo0OO0oo ] = I11iII [ OOOooo0OooOoO + 1 : : ]
  if 19 - 19: iIii1I11I1II1
 return ( oo0Oo00o000 )
 if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
 if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
 if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
 if 57 - 57: i1IIi
 if 41 - 41: I11i / Ii1I
 if 1 - 1: II111iiii / iII111i
 if 83 - 83: OoO0O00 / iII111i
 if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
 if 96 - 96: OoO0O00
 if 53 - 53: oO0o + OoO0O00
 if 58 - 58: iIii1I11I1II1 + OoOoOO00
 if 65 - 65: iII111i % Oo0Ooo * iIii1I11I1II1 + I1IiiI + II111iiii
 if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
 if 15 - 15: OoOoOO00
def lisp_reassemble ( packet ) :
 o0I1IiiiiI1i1I = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 13 - 13: I1ii11iIi11i - OOooOOo - i11iIiiIii / IiII
 if 65 - 65: IiII
 if 76 - 76: I1Ii111 % I1ii11iIi11i + ooOoO0o / I1IiiI
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo - o0oOOo0O0Ooo % I1IiiI
 if ( o0I1IiiiiI1i1I == 0 or o0I1IiiiiI1i1I == 0x4000 ) : return ( packet )
 if 55 - 55: o0oOOo0O0Ooo % I1ii11iIi11i - IiII + OoooooooOO
 if 44 - 44: iII111i * I1Ii111 - I1IiiI % i1IIi
 if 35 - 35: iII111i . OoOoOO00 + i1IIi . I1Ii111 - oO0o
 if 92 - 92: o0oOOo0O0Ooo
 i11I1iiii = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 II1I11 = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 8 - 8: i1IIi / IiII . O0
 ooOOo0O0OO = ( o0I1IiiiiI1i1I & 0x2000 == 0 and ( o0I1IiiiiI1i1I & 0x1fff ) != 0 )
 iIiiI11II11i = [ ( o0I1IiiiiI1i1I & 0x1fff ) * 8 , II1I11 - 20 , packet , ooOOo0O0OO ]
 if 66 - 66: I1ii11iIi11i + iII111i / Ii1I / I1IiiI * i11iIiiIii
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if 4 - 4: iII111i
 if ( o0I1IiiiiI1i1I == 0x2000 ) :
  iiI1iiIiiiI1I , i111I1 = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  iiI1iiIiiiI1I = socket . ntohs ( iiI1iiIiiiI1I )
  i111I1 = socket . ntohs ( i111I1 )
  if ( i111I1 not in [ 4341 , 8472 , 4789 ] and iiI1iiIiiiI1I != 4341 ) :
   lisp_reassembly_queue [ i11I1iiii ] = [ ]
   iIiiI11II11i [ 2 ] = None
   if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
   if 32 - 32: iII111i
   if 59 - 59: OoOoOO00 - I1Ii111
   if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
   if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
   if 33 - 33: Ii1I
 if ( i11I1iiii not in lisp_reassembly_queue ) :
  lisp_reassembly_queue [ i11I1iiii ] = [ ]
  if 20 - 20: Ii1I + I11i
  if 98 - 98: OOooOOo
  if 58 - 58: i11iIiiIii / OoOoOO00
  if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
  if 83 - 83: OoO0O00 - Oo0Ooo * I1IiiI % Oo0Ooo % oO0o
 queue = lisp_reassembly_queue [ i11I1iiii ]
 if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
 if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
 if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
 if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
 if 21 - 21: IiII
 if ( len ( queue ) == 1 and queue [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( i11I1iiii ) . zfill ( 4 ) ) )
  if 43 - 43: IiII
  return ( None )
  if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
  if 8 - 8: IiII * iIii1I11I1II1
  if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
  if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
  if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
 queue . append ( iIiiI11II11i )
 queue = sorted ( queue )
 if 84 - 84: OoooooooOO
 if 95 - 95: o0oOOo0O0Ooo
 if 22 - 22: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
 if 41 - 41: oO0o . II111iiii
 oOOOo0o = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oOOOo0o . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 iiiIiIii = oOOOo0o . print_address_no_iid ( )
 oOOOo0o . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 Ii11iIiIII1 = oOOOo0o . print_address_no_iid ( )
 oOOOo0o = red ( "{} -> {}" . format ( iiiIiIii , Ii11iIiIII1 ) , False )
 if 96 - 96: Oo0Ooo / I1IiiI
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if iIiiI11II11i [ 2 ] == None else "" , oOOOo0o , lisp_hex_string ( i11I1iiii ) . zfill ( 4 ) ,
 # OoO0O00
 # i1IIi
 lisp_hex_string ( o0I1IiiiiI1i1I ) . zfill ( 4 ) ) )
 if 28 - 28: IiII + I11i
 if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
 if 56 - 56: Ii1I . OoO0O00
 if 43 - 43: iII111i * iII111i
 if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
 if ( queue [ 0 ] [ 0 ] != 0 or queue [ - 1 ] [ 3 ] == False ) : return ( None )
 oo0oO00oO0o00 = queue [ 0 ]
 for oo0O00o0O0Oo in queue [ 1 : : ] :
  o0I1IiiiiI1i1I = oo0O00o0O0Oo [ 0 ]
  O00o0o00 , iIi1iIi = oo0oO00oO0o00 [ 0 ] , oo0oO00oO0o00 [ 1 ]
  if ( O00o0o00 + iIi1iIi != o0I1IiiiiI1i1I ) : return ( None )
  oo0oO00oO0o00 = oo0O00o0O0Oo
  if 28 - 28: iII111i % Oo0Ooo % I1IiiI + iII111i
 lisp_reassembly_queue . pop ( i11I1iiii )
 if 67 - 67: i1IIi + OoooooooOO * i11iIiiIii / iIii1I11I1II1
 if 86 - 86: o0oOOo0O0Ooo + OoOoOO00 % I11i - iIii1I11I1II1 % OoOoOO00 + ooOoO0o
 if 30 - 30: II111iiii / OoOoOO00 * o0oOOo0O0Ooo + OoooooooOO
 if 32 - 32: Ii1I - Ii1I / i11iIiiIii
 if 48 - 48: iIii1I11I1II1 % OoooooooOO * Ii1I . i1IIi . oO0o % iIii1I11I1II1
 packet = queue [ 0 ] [ 2 ]
 for oo0O00o0O0Oo in queue [ 1 : : ] : packet += oo0O00o0O0Oo [ 2 ] [ 20 : : ]
 if 89 - 89: I11i + I11i * OoooooooOO + IiII % iIii1I11I1II1
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( i11I1iiii ) . zfill ( 4 ) , len ( packet ) ) )
 if 52 - 52: i1IIi
 if 85 - 85: I1Ii111 - iII111i
 if 44 - 44: I11i - I11i - IiII . I11i
 if 34 - 34: iIii1I11I1II1 - oO0o * i11iIiiIii * o0oOOo0O0Ooo
 if 15 - 15: I1Ii111
 iI = socket . htons ( len ( packet ) )
 i111ii1II11ii = packet [ 0 : 2 ] + struct . pack ( "H" , iI ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 25 - 25: I1ii11iIi11i * O0
 if 8 - 8: i11iIiiIii
 i111ii1II11ii = lisp_ip_checksum ( i111ii1II11ii )
 return ( i111ii1II11ii + packet [ 20 : : ] )
 if 95 - 95: ooOoO0o + i1IIi / OOooOOo . i11iIiiIii
 if 31 - 31: iII111i - iII111i - oO0o
 if 62 - 62: Oo0Ooo % Oo0Ooo / OoooooooOO * o0oOOo0O0Ooo . Ii1I
 if 1 - 1: I1ii11iIi11i / II111iiii / II111iiii + o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
 if 87 - 87: OOooOOo * OoO0O00
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 if 86 - 86: II111iiii
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 Oo0o = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( Oo0o in lisp_crypto_keys_by_rloc_decap ) : return ( Oo0o )
 if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
 Oo0o = addr . print_address_no_iid ( )
 if ( Oo0o in lisp_crypto_keys_by_rloc_decap ) : return ( Oo0o )
 if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
 if 91 - 91: Ii1I
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 72 - 72: I1ii11iIi11i
 if 5 - 5: i1IIi
 for I1IiiIIi in lisp_crypto_keys_by_rloc_decap :
  OoOOOO = I1IiiIIi . split ( ":" )
  if ( len ( OoOOOO ) == 1 ) : continue
  OoOOOO = OoOOOO [ 0 ] if len ( OoOOOO ) == 2 else ":" . join ( OoOOOO [ 0 : - 1 ] )
  if ( OoOOOO == Oo0o ) :
   O0o0O0 = lisp_crypto_keys_by_rloc_decap [ I1IiiIIi ]
   lisp_crypto_keys_by_rloc_decap [ Oo0o ] = O0o0O0
   return ( Oo0o )
   if 57 - 57: I1Ii111 - iII111i - IiII - ooOoO0o / I11i + IiII
   if 45 - 45: I1Ii111 . oO0o
 return ( None )
 if 96 - 96: OoO0O00 - oO0o - i11iIiiIii . OoOoOO00 * OOooOOo
 if 46 - 46: o0oOOo0O0Ooo . OOooOOo - ooOoO0o . I1ii11iIi11i
 if 21 - 21: Oo0Ooo * I1IiiI . I1IiiI
 if 27 - 27: I1Ii111 + OOooOOo - oO0o / O0 - O0
 if 95 - 95: O0 % I1ii11iIi11i . O0 . OOooOOo * i11iIiiIii - oO0o
 if 2 - 2: OOooOOo + II111iiii
 if 30 - 30: IiII
 if 99 - 99: O0 / OoO0O00 * II111iiii . II111iiii
 if 14 - 14: OoOoOO00 * i1IIi - OoOoOO00 . OoooooooOO
 if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
 if 64 - 64: IiII . I1ii11iIi11i - o0oOOo0O0Ooo - ooOoO0o + OoooooooOO
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 O0O = addr + ":" + str ( port )
 if 59 - 59: I11i * OoO0O00 - OoOoOO00
 if ( lisp_i_am_rtr ) :
  if ( addr in lisp_rloc_probe_list ) : return ( addr )
  if 35 - 35: I11i * II111iiii . Oo0Ooo % OOooOOo - II111iiii - OoO0O00
  if 62 - 62: Ii1I . i11iIiiIii % OOooOOo
  if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
  if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
  if 81 - 81: IiII
  if 54 - 54: I1IiiI % OoO0O00 % OoOoOO00
  for iII1II1 in list ( lisp_nat_state_info . values ( ) ) :
   for ooO0 in iII1II1 :
    if ( addr == ooO0 . address ) : return ( O0O )
    if 12 - 12: II111iiii . O0 * i11iIiiIii . I11i
    if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
  return ( addr )
  if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 return ( O0O )
 if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
 if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
 if 79 - 79: IiII + I1Ii111
 if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
 if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
 if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
 if 73 - 73: OoOoOO00
def lisp_set_ttl ( lisp_socket , ttl ) :
 try :
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_TTL , ttl )
  lisp_socket . setsockopt ( socket . SOL_IP , socket . IP_MULTICAST_TTL , ttl )
 except :
  lprint ( "socket.setsockopt(IP_TTL) not supported" )
  pass
  if 44 - 44: Oo0Ooo / oO0o
 return
 if 9 - 9: i1IIi % I1IiiI + OoO0O00 * ooOoO0o / iIii1I11I1II1 / iII111i
 if 80 - 80: OOooOOo / O0 % IiII * OoOoOO00
 if 53 - 53: OOooOOo + i11iIiiIii
 if 25 - 25: i11iIiiIii
 if 51 - 51: iII111i . ooOoO0o
 if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
 if 6 - 6: I11i + II111iiii - I1Ii111
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
 if 56 - 56: I11i + I1Ii111
 if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
 if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
 if 64 - 64: O0 / OoooooooOO
 if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
 if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
 if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
 if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
 if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
 if 77 - 77: OoO0O00
 if 95 - 95: II111iiii
 if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
 if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
 if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
 if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
 if 97 - 97: I1Ii111
 if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
 if 56 - 56: O0 - i1IIi % o0oOOo0O0Ooo + IiII
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo % I11i - OoOoOO00
 if 38 - 38: OoooooooOO
 if 27 - 27: O0 + I1ii11iIi11i % Ii1I . i1IIi + OoO0O00 + OoOoOO00
 if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
 if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
def lisp_is_rloc_probe ( packet , rr ) :
 Ii1iiI1 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == 17 )
 if ( Ii1iiI1 == False ) : return ( [ packet , None , None , None ] )
 if 36 - 36: o0oOOo0O0Ooo - i11iIiiIii
 iiI1iiIiiiI1I = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 i111I1 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 iiI1iIi = ( socket . htons ( LISP_CTRL_PORT ) in [ iiI1iiIiiiI1I , i111I1 ] )
 if ( iiI1iIi == False ) : return ( [ packet , None , None , None ] )
 if 17 - 17: ooOoO0o * Oo0Ooo
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
   if 91 - 91: ooOoO0o - iIii1I11I1II1 % O0 * ooOoO0o % O0 % OoO0O00
   if 8 - 8: iIii1I11I1II1 - o0oOOo0O0Ooo
   if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
   if 79 - 79: II111iiii / IiII
   if 4 - 4: O0 - i11iIiiIii % ooOoO0o * O0 - ooOoO0o
   if 96 - 96: oO0o % II111iiii . Ii1I % OoO0O00 . iIii1I11I1II1 / IiII
 OO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 OO . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 96 - 96: o0oOOo0O0Ooo / O0 . iIii1I11I1II1 . Ii1I % OOooOOo % II111iiii
 if 5 - 5: OoooooooOO / I1Ii111 % I1Ii111 / I1IiiI
 if 19 - 19: I1IiiI - ooOoO0o % IiII - o0oOOo0O0Ooo * OOooOOo + I1ii11iIi11i
 if 44 - 44: i1IIi
 if ( OO . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 85 - 85: I1ii11iIi11i / IiII + oO0o
 if 95 - 95: IiII . OoO0O00
 if 36 - 36: IiII % Ii1I - OoOoOO00 + OoO0O00 + IiII * Ii1I
 if 15 - 15: I1IiiI / O0 % I1ii11iIi11i % OoOoOO00 . OoOoOO00 + iII111i
 OO = OO . print_address_no_iid ( )
 O00oo0o0o0oo = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 O0O00O = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 79 - 79: OOooOOo + Ii1I . I1Ii111 / Oo0Ooo / i11iIiiIii / O0
 I1I1iIiiiiII11 = bold ( "Receive(pcap)" , False )
 iiI1i1I = bold ( "from " + OO , False )
 o00oo = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( I1I1iIiiiiII11 , len ( packet ) , iiI1i1I , O00oo0o0o0oo , o00oo ) )
 if 28 - 28: i1IIi % OoO0O00 / i1IIi - o0oOOo0O0Ooo
 return ( [ packet , OO , O00oo0o0o0oo , O0O00O ] )
 if 97 - 97: II111iiii + O0 . Ii1I + OoooooooOO
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
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 62 - 62: Ii1I - OOooOOo
 ii1I11Iii = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
 lisp_write_to_dp_socket ( ii1I11Iii )
 return
 if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
 if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
 if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
 if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
 if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
 if 2 - 2: I1ii11iIi11i
 if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
 if 54 - 54: ooOoO0o
def lisp_external_data_plane ( ) :
 i1iii1IiiiI1i1 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( getoutput ( i1iii1IiiiI1i1 ) != "" ) : return ( True )
 if 47 - 47: I11i * I1IiiI / oO0o
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
 if 4 - 4: i1IIi
 if 43 - 43: oO0o * ooOoO0o - I11i
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
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 27 - 27: ooOoO0o / i1IIi . oO0o - OoooooooOO
 I1i1Ii1iII = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 98 - 98: iIii1I11I1II1 / iII111i % OoOoOO00 + IiII * OoOoOO00
 if ( do_clear == False ) :
  Ii11111I11I = I1i1Ii1iII [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , Ii11111I11I )
  if 64 - 64: I1ii11iIi11i / O0 % II111iiii * I1Ii111
  if 76 - 76: I1ii11iIi11i + o0oOOo0O0Ooo
 lisp_write_to_dp_socket ( I1i1Ii1iII )
 return
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
 if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
 if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
 if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( "entries" not in msg ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
  if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
 for msg in msg [ "entries" ] :
  if ( "eid-prefix" not in msg ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 93 - 93: oO0o
  iIiI1I1ii1I1 = msg [ "eid-prefix" ]
  if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
  if ( "instance-id" not in msg ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
  i1oO00O = int ( msg [ "instance-id" ] )
  if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
  if 54 - 54: OoOoOO00 - I1IiiI - iII111i
  if 49 - 49: i11iIiiIii * Oo0Ooo
  if 100 - 100: Oo0Ooo * oO0o
  I11I = lisp_address ( LISP_AFI_NONE , "" , 0 , i1oO00O )
  I11I . store_prefix ( iIiI1I1ii1I1 )
  O0oo0OOo00o0o = lisp_map_cache_lookup ( None , I11I )
  if ( O0oo0OOo00o0o == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( iIiI1I1ii1I1 ) )
   if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
   continue
   if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
   if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
  if ( "rlocs" not in msg ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( iIiI1I1ii1I1 ) )
   if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
   continue
   if 85 - 85: OoO0O00 - Ii1I / O0
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 45 - 45: IiII + I1Ii111 / I11i
  o0o0000oo0o = msg [ "rlocs" ]
  if 58 - 58: O0 * o0oOOo0O0Ooo - I1Ii111 % OOooOOo
  if 47 - 47: i1IIi % Oo0Ooo + I1IiiI / I11i
  if 79 - 79: iII111i / IiII . IiII + i11iIiiIii
  if 68 - 68: O0 % oO0o * IiII % O0
  for oo0ooo0Oo0O in o0o0000oo0o :
   if ( "rloc" not in oo0ooo0Oo0O ) : continue
   if 73 - 73: Ii1I - IiII + I11i % I1ii11iIi11i . ooOoO0o % OoOoOO00
   o00oO = oo0ooo0Oo0O [ "rloc" ]
   if ( o00oO == "no-address" ) : continue
   if 27 - 27: I11i + IiII % o0oOOo0O0Ooo / II111iiii * I11i % I1ii11iIi11i
   OooOOoOO0OO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   OooOOoOO0OO . store_address ( o00oO )
   if 12 - 12: I1Ii111 - I1IiiI % i11iIiiIii * iIii1I11I1II1 + OoOoOO00 + i11iIiiIii
   II1 = O0oo0OOo00o0o . get_rloc ( OooOOoOO0OO )
   if ( II1 == None ) : continue
   if 36 - 36: Oo0Ooo + oO0o / I1Ii111 / iII111i . O0 % II111iiii
   if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
   if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
   if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
   O0O000o00oo = 0 if ( "packet-count" not in oo0ooo0Oo0O ) else oo0ooo0Oo0O [ "packet-count" ]
   if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
   oOo0Oo = 0 if ( "byte-count" not in oo0ooo0Oo0O ) else oo0ooo0Oo0O [ "byte-count" ]
   if 1 - 1: I1ii11iIi11i % O0 - I1ii11iIi11i / OoooooooOO / OoO0O00
   i1 = 0 if ( "seconds-last-packet" not in oo0ooo0Oo0O ) else oo0ooo0Oo0O [ "seconds-last-packet" ]
   if 82 - 82: i1IIi % Ii1I
   if 85 - 85: I1Ii111 * i11iIiiIii * iIii1I11I1II1 % iIii1I11I1II1
   II1 . stats . packet_count += O0O000o00oo
   II1 . stats . byte_count += oOo0Oo
   II1 . stats . last_increment = lisp_get_timestamp ( ) - i1
   if 64 - 64: OoO0O00 / Ii1I
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( O0O000o00oo , oOo0Oo ,
 i1 , iIiI1I1ii1I1 , o00oO ) )
   if 79 - 79: Ii1I % OOooOOo
   if 39 - 39: I1ii11iIi11i / Ii1I - II111iiii . i1IIi
   if 59 - 59: II111iiii
   if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
   if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
  if ( O0oo0OOo00o0o . group . is_null ( ) and O0oo0OOo00o0o . has_ttl_elapsed ( ) ) :
   iIiI1I1ii1I1 = green ( O0oo0OOo00o0o . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( iIiI1I1ii1I1 ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , O0oo0OOo00o0o . eid , None )
   if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
   if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
 return
 if 61 - 61: i1IIi
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
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 83 - 83: oO0o / I1Ii111 + I1Ii111 * I1ii11iIi11i
 if 8 - 8: I11i . I1ii11iIi11i % i1IIi + Ii1I
 if 63 - 63: I1IiiI / OoooooooOO
 if 16 - 16: OoOoOO00
 if 67 - 67: O0 . I1Ii111
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  ii1I11Iii = "stats%{}" . format ( json . dumps ( msg ) )
  ii1I11Iii = lisp_command_ipc ( ii1I11Iii , "lisp-itr" )
  lisp_ipc ( ii1I11Iii , lisp_ipc_socket , "lisp-etr" )
  return
  if 42 - 42: OoOoOO00 % I1ii11iIi11i * I1Ii111 * i1IIi . i1IIi % OOooOOo
  if 90 - 90: oO0o * Oo0Ooo * oO0o . Ii1I * i1IIi
  if 47 - 47: OOooOOo
  if 38 - 38: I11i
  if 15 - 15: OoO0O00 / ooOoO0o . OoO0O00 - iIii1I11I1II1 + OoooooooOO - OoO0O00
  if 44 - 44: O0 . OOooOOo . o0oOOo0O0Ooo . I1ii11iIi11i - II111iiii
  if 71 - 71: I1ii11iIi11i + o0oOOo0O0Ooo . i11iIiiIii * oO0o . i1IIi
  if 40 - 40: OoO0O00 - IiII
 ii1I11Iii = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( ii1I11Iii , msg ) )
 if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
 i1ii1IIi = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 66 - 66: O0 . i11iIiiIii
 for oo0OO0 in i1ii1IIi :
  O0O000o00oo = 0 if ( oo0OO0 not in msg ) else msg [ oo0OO0 ] [ "packet-count" ]
  lisp_decap_stats [ oo0OO0 ] . packet_count += O0O000o00oo
  if 43 - 43: I1ii11iIi11i
  oOo0Oo = 0 if ( oo0OO0 not in msg ) else msg [ oo0OO0 ] [ "byte-count" ]
  lisp_decap_stats [ oo0OO0 ] . byte_count += oOo0Oo
  if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
  i1 = 0 if ( oo0OO0 not in msg ) else msg [ oo0OO0 ] [ "seconds-last-packet" ]
  if 22 - 22: iII111i
  lisp_decap_stats [ oo0OO0 ] . last_increment = lisp_get_timestamp ( ) - i1
  if 88 - 88: I11i + OoOoOO00 % IiII % OoO0O00 * O0 / OoooooooOO
 return
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
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 o0OO0 , OO = punt_socket . recvfrom ( 4000 )
 if 18 - 18: ooOoO0o + I11i + Oo0Ooo . iIii1I11I1II1
 o0000OO = json . loads ( o0OO0 )
 if ( type ( o0000OO ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( OO ) )
  if 28 - 28: II111iiii / I1IiiI - II111iiii / OoooooooOO + II111iiii / i11iIiiIii
  return
  if 36 - 36: i1IIi % Ii1I - ooOoO0o + o0oOOo0O0Ooo % oO0o / oO0o
 II11I = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( II11I , OO , o0000OO ) )
 if 84 - 84: OoooooooOO + I1IiiI / Ii1I % I1IiiI
 if ( "type" not in o0000OO ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 86 - 86: OoooooooOO . II111iiii * O0
  if 100 - 100: Ii1I
  if 20 - 20: ooOoO0o / i11iIiiIii - OoOoOO00 / iIii1I11I1II1 * iII111i
  if 53 - 53: O0 / I11i + Oo0Ooo
  if 56 - 56: I1Ii111 - I1Ii111 * OoOoOO00 * iII111i - I1ii11iIi11i
 if ( o0000OO [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( o0000OO , lisp_send_sockets , lisp_ephem_port )
  return
  if 38 - 38: iIii1I11I1II1 + i1IIi % I1IiiI - I1Ii111 % oO0o
 if ( o0000OO [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( o0000OO , punt_socket )
  return
  if 69 - 69: OoooooooOO . OOooOOo * Oo0Ooo % I1ii11iIi11i - I1IiiI
  if 35 - 35: I1Ii111 % IiII / O0
  if 11 - 11: i1IIi * I1Ii111 / OoOoOO00 . I1Ii111 + OoOoOO00 % IiII
  if 18 - 18: OoooooooOO / Ii1I / i1IIi / oO0o
  if 24 - 24: OoO0O00 * iII111i - i11iIiiIii + oO0o
 if ( o0000OO [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 66 - 66: Oo0Ooo * I11i . iIii1I11I1II1 - OoO0O00
  if 11 - 11: I1Ii111 + iIii1I11I1II1 * O0 * Oo0Ooo
  if 66 - 66: OoooooooOO % OoO0O00 + i11iIiiIii + I1Ii111 % OoO0O00
  if 80 - 80: Oo0Ooo - Ii1I
  if 54 - 54: O0 - iIii1I11I1II1 . OoO0O00 . IiII % OoO0O00
 if ( o0000OO [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 28 - 28: O0 % i1IIi % OoO0O00 / o0oOOo0O0Ooo . iIii1I11I1II1 - iII111i
 if ( "interface" not in o0000OO ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( OO ) )
  if 50 - 50: o0oOOo0O0Ooo + iII111i / i1IIi % II111iiii
  return
  if 61 - 61: IiII
  if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
  if 48 - 48: IiII * oO0o
  if 53 - 53: i1IIi * iIii1I11I1II1 . OOooOOo
  if 68 - 68: IiII % IiII - iII111i . IiII + OoooooooOO
 OoO0 = o0000OO [ "interface" ]
 if ( OoO0 == "" ) :
  i1oO00O = int ( o0000OO [ "instance-id" ] )
  if ( i1oO00O == - 1 ) : return
 else :
  i1oO00O = lisp_get_interface_instance_id ( OoO0 , None )
  if 82 - 82: Ii1I . II111iiii / i1IIi * OoO0O00
  if 80 - 80: I11i
  if 96 - 96: i1IIi - I1ii11iIi11i * iII111i . OOooOOo . OoO0O00
  if 93 - 93: oO0o * Oo0Ooo * IiII
  if 26 - 26: o0oOOo0O0Ooo + O0 % i11iIiiIii . ooOoO0o . I1IiiI + Oo0Ooo
 O0OOO0o = None
 if ( "source-eid" in o0000OO ) :
  Ooo0o00O0O0oO = o0000OO [ "source-eid" ]
  O0OOO0o = lisp_address ( LISP_AFI_NONE , Ooo0o00O0O0oO , 0 , i1oO00O )
  if ( O0OOO0o . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( Ooo0o00O0O0oO ) )
   return
   if 90 - 90: IiII * OoooooooOO + II111iiii / iII111i + i11iIiiIii / ooOoO0o
   if 20 - 20: II111iiii % I1ii11iIi11i - OoooooooOO * Ii1I / I11i - OoooooooOO
 iI1O0oOOO = None
 if ( "dest-eid" in o0000OO ) :
  IiI11iI = o0000OO [ "dest-eid" ]
  iI1O0oOOO = lisp_address ( LISP_AFI_NONE , IiI11iI , 0 , i1oO00O )
  if ( iI1O0oOOO . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( IiI11iI ) )
   return
   if 56 - 56: i1IIi + OoooooooOO - i11iIiiIii + o0oOOo0O0Ooo
   if 10 - 10: OOooOOo - o0oOOo0O0Ooo
   if 80 - 80: II111iiii
   if 79 - 79: I1ii11iIi11i % iII111i % O0 + o0oOOo0O0Ooo - oO0o - I1Ii111
   if 60 - 60: oO0o * I1IiiI / ooOoO0o - i11iIiiIii
   if 57 - 57: I1IiiI * I1IiiI % O0 + OOooOOo
   if 58 - 58: Oo0Ooo . I1IiiI + I1Ii111 - ooOoO0o . o0oOOo0O0Ooo
   if 52 - 52: o0oOOo0O0Ooo % I11i * I11i / iIii1I11I1II1
 if ( O0OOO0o ) :
  I1i = green ( O0OOO0o . print_address ( ) , False )
  iIiI1ii = lisp_db_for_lookups . lookup_cache ( O0OOO0o , False )
  if ( iIiI1ii != None ) :
   if 77 - 77: OoOoOO00
   if 67 - 67: OoooooooOO / OoooooooOO + IiII - ooOoO0o
   if 72 - 72: Ii1I
   if 21 - 21: ooOoO0o + iII111i
   if 39 - 39: o0oOOo0O0Ooo % I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo
   if ( iIiI1ii . dynamic_eid_configured ( ) ) :
    i1i1111I = lisp_allow_dynamic_eid ( OoO0 , O0OOO0o )
    if ( i1i1111I != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( iIiI1ii , O0OOO0o , OoO0 , i1i1111I )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( I1i , OoO0 ) )
     if 78 - 78: OoO0O00 / o0oOOo0O0Ooo / O0 % OOooOOo % i1IIi
     if 78 - 78: o0oOOo0O0Ooo - oO0o . II111iiii
     if 67 - 67: iII111i + I11i - OoO0O00 . OOooOOo * iIii1I11I1II1
  else :
   lprint ( "Punt from non-EID source {}" . format ( I1i ) )
   if 44 - 44: OoooooooOO * i1IIi % i1IIi - i11iIiiIii % OOooOOo - OoO0O00
   if 62 - 62: OOooOOo + OoooooooOO / I1Ii111 % iIii1I11I1II1
   if 59 - 59: i11iIiiIii . IiII
   if 91 - 91: Oo0Ooo / iII111i + I1Ii111
   if 32 - 32: i1IIi - iII111i + o0oOOo0O0Ooo * I1Ii111 % I1ii11iIi11i / i11iIiiIii
   if 91 - 91: IiII / OoooooooOO . OoooooooOO + OoooooooOO * I1ii11iIi11i . OoOoOO00
 if ( iI1O0oOOO ) :
  O0oo0OOo00o0o = lisp_map_cache_lookup ( O0OOO0o , iI1O0oOOO )
  if ( O0oo0OOo00o0o == None or lisp_mr_or_pubsub ( O0oo0OOo00o0o . action ) ) :
   if 22 - 22: iIii1I11I1II1 - OoO0O00
   if 77 - 77: I1IiiI + IiII - oO0o - I1ii11iIi11i * II111iiii + i1IIi
   if 79 - 79: I1ii11iIi11i + O0 * OoooooooOO
   if 43 - 43: I11i
   if 29 - 29: o0oOOo0O0Ooo / I11i
   if ( lisp_rate_limit_map_request ( iI1O0oOOO ) ) : return
   if 88 - 88: OoOoOO00 - Ii1I . O0 % I1Ii111 % I1ii11iIi11i
   iIiii11 = ( O0oo0OOo00o0o and O0oo0OOo00o0o . action == LISP_SEND_PUBSUB_ACTION )
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 O0OOO0o , iI1O0oOOO , None , iIiii11 )
  else :
   I1i = green ( iI1O0oOOO . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( I1i ) )
   if 56 - 56: OoOoOO00 - iIii1I11I1II1 / I1IiiI - i1IIi / o0oOOo0O0Ooo * I11i
   if 70 - 70: OOooOOo
 return
 if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
 if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
 if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
 if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
 if 63 - 63: I1IiiI
 if 20 - 20: oO0o + OoOoOO00
 if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 iIiiI11II11i = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( iIiiI11II11i )
 return ( [ True , jdata ] )
 if 4 - 4: OOooOOo % oO0o
 if 18 - 18: Ii1I * I11i
 if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
 if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
 if 56 - 56: Oo0Ooo . I1ii11iIi11i - i11iIiiIii / iIii1I11I1II1 . ooOoO0o
 if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
 if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
 if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 66 - 66: I1IiiI . Oo0Ooo - oO0o
 if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
 if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 68 - 68: OoOoOO00 - iII111i - I1IiiI
 if 37 - 37: iII111i - I1Ii111 + i1IIi / o0oOOo0O0Ooo % iII111i / iII111i
 if 8 - 8: i1IIi % I11i
 if 12 - 12: ooOoO0o / II111iiii + ooOoO0o * I1ii11iIi11i / i1IIi - iIii1I11I1II1
 if 71 - 71: IiII - i11iIiiIii
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
 if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
 if 80 - 80: I11i
 if 98 - 98: iII111i / I1ii11iIi11i
 if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
 if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 iIiI1I1ii1I1 = eid . print_address ( )
 if ( iIiI1I1ii1I1 in db . dynamic_eids ) :
  db . dynamic_eids [ iIiI1I1ii1I1 ] . last_packet = lisp_get_timestamp ( )
  return
  if 56 - 56: IiII * II111iiii + Oo0Ooo - O0 - OoO0O00 . I1Ii111
  if 53 - 53: i1IIi + IiII
  if 90 - 90: II111iiii / oO0o / oO0o . OoOoOO00 / OoO0O00 / iIii1I11I1II1
  if 96 - 96: iIii1I11I1II1 % I1ii11iIi11i
  if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
 iiI1IiI1I1I = lisp_dynamic_eid ( )
 iiI1IiI1I1I . dynamic_eid . copy_address ( eid )
 iiI1IiI1I1I . interface = routed_interface
 iiI1IiI1I1I . last_packet = lisp_get_timestamp ( )
 iiI1IiI1I1I . get_timeout ( routed_interface )
 db . dynamic_eids [ iIiI1I1ii1I1 ] = iiI1IiI1I1I
 if 72 - 72: I1Ii111 / OoO0O00 + II111iiii
 I1ii1i = ""
 if ( input_interface != routed_interface ) :
  I1ii1i = ", routed-interface " + routed_interface
  if 23 - 23: i1IIi + I1Ii111 / IiII * O0 - I1Ii111
  if 90 - 90: Oo0Ooo / Ii1I
 OoO0oOo0o = green ( iIiI1I1ii1I1 , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( OoO0oOo0o , input_interface , I1ii1i , iiI1IiI1I1I . timeout ) )
 if 22 - 22: ooOoO0o % i1IIi % OoOoOO00
 if 90 - 90: I1IiiI - Oo0Ooo % OOooOOo . OoOoOO00 * O0
 if 75 - 75: iIii1I11I1II1 . i1IIi % o0oOOo0O0Ooo
 if 26 - 26: I11i * OoO0O00
 if 8 - 8: OOooOOo / Ii1I * I1ii11iIi11i - I1Ii111 + OOooOOo
 ii1I11Iii = "learn%{}%{}" . format ( iIiI1I1ii1I1 , routed_interface )
 ii1I11Iii = lisp_command_ipc ( ii1I11Iii , "lisp-itr" )
 lisp_ipc ( ii1I11Iii , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 33 - 33: OoOoOO00 - Ii1I + o0oOOo0O0Ooo - i11iIiiIii * O0 * O0
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
 if 41 - 41: iII111i / Ii1I
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 if 24 - 24: IiII / Oo0Ooo
 if 90 - 90: ooOoO0o . OOooOOo - Ii1I
 if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
 i11I1Ii1 = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 55 - 55: ooOoO0o - II111iiii . ooOoO0o . iII111i / OoooooooOO
 for III11II111 in lisp_crypto_keys_by_rloc_decap :
  if 51 - 51: I1IiiI * I1Ii111 - ooOoO0o + IiII
  if 22 - 22: OoOoOO00 % Ii1I + iII111i
  if 64 - 64: ooOoO0o
  if 87 - 87: IiII - Ii1I / Oo0Ooo / I1ii11iIi11i . iII111i
  if ( III11II111 . find ( addr_str ) == - 1 ) : continue
  if 49 - 49: IiII * OoooooooOO * iIii1I11I1II1 * Oo0Ooo / iII111i % oO0o
  if 88 - 88: I1Ii111 * OOooOOo
  if 38 - 38: Oo0Ooo - OoooooooOO - OoooooooOO / II111iiii
  if 10 - 10: II111iiii - OoO0O00 / II111iiii % Ii1I - OoOoOO00
  if ( III11II111 == addr_str ) : continue
  if 90 - 90: I11i + II111iiii - oO0o - ooOoO0o / ooOoO0o / i11iIiiIii
  if 80 - 80: I1ii11iIi11i % O0 / II111iiii + iII111i
  if 22 - 22: Oo0Ooo + ooOoO0o . OOooOOo % Oo0Ooo . IiII
  if 34 - 34: Ii1I . OoOoOO00 - OOooOOo * Oo0Ooo - ooOoO0o . oO0o
  iIiiI11II11i = lisp_crypto_keys_by_rloc_decap [ III11II111 ]
  if ( iIiiI11II11i == i11I1Ii1 ) : continue
  if 42 - 42: O0 + OoO0O00
  if 47 - 47: O0 % OoOoOO00 + Ii1I * iIii1I11I1II1
  if 55 - 55: Ii1I
  if 93 - 93: iII111i + OOooOOo . OoooooooOO . I1Ii111 . O0
  iiO0OOOOOO0O = iIiiI11II11i [ 1 ]
  if ( packet_icv != iiO0OOOOOO0O . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( III11II111 , False ) ) )
   continue
   if 37 - 37: OoO0O00 . Oo0Ooo
   if 29 - 29: I1Ii111 - Ii1I . i11iIiiIii . o0oOOo0O0Ooo * iIii1I11I1II1 . iIii1I11I1II1
  lprint ( "Changing decap crypto key to {}" . format ( red ( III11II111 , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = iIiiI11II11i
  if 48 - 48: iII111i - I1ii11iIi11i
 return
 if 44 - 44: II111iiii + Oo0Ooo % OoOoOO00
 if 66 - 66: iII111i + Oo0Ooo
 if 74 - 74: OOooOOo / Ii1I / OoOoOO00
 if 26 - 26: o0oOOo0O0Ooo
 if 59 - 59: Oo0Ooo
 if 31 - 31: oO0o * i1IIi / II111iiii / I1ii11iIi11i - OoooooooOO + I11i
 if 5 - 5: OOooOOo % OoOoOO00 + O0 + O0
 if 32 - 32: I1ii11iIi11i . ooOoO0o
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 15 - 15: oO0o % oO0o + iIii1I11I1II1
 if 19 - 19: IiII . I11i + oO0o
 if 24 - 24: OoOoOO00 . I1IiiI / Ii1I
 if 42 - 42: I1Ii111 / I1ii11iIi11i
 if 1 - 1: OOooOOo
 if 48 - 48: I1IiiI / OoooooooOO % I11i * Oo0Ooo
 if 20 - 20: Oo0Ooo
 if 85 - 85: I1Ii111
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 ooO0o = dns_name . split ( "." )
 ooO0o = "." . join ( ooO0o [ 1 : : ] )
 return ( ooO0o == lisp_decent_dns_suffix )
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
def lisp_get_decent_index ( eid ) :
 iIiI1I1ii1I1 = eid . print_prefix ( )
 I1II = hmac . new ( b"lisp-decent" , iIiI1I1ii1I1 , hashlib . sha256 ) . hexdigest ( )
 if 25 - 25: o0oOOo0O0Ooo % Oo0Ooo . Oo0Ooo + OoO0O00
 if 23 - 23: I11i + I1ii11iIi11i * iIii1I11I1II1 - i1IIi
 if 33 - 33: I1IiiI + o0oOOo0O0Ooo . OoOoOO00
 if 35 - 35: iII111i / Ii1I
 o0o0OO000O00 = os . getenv ( "LISP_DECENT_HASH_WIDTH" )
 if ( o0o0OO000O00 in [ "" , None ] ) :
  o0o0OO000O00 = 12
 else :
  o0o0OO000O00 = int ( o0o0OO000O00 )
  if ( o0o0OO000O00 > 32 ) :
   o0o0OO000O00 = 12
  else :
   o0o0OO000O00 *= 2
   if 29 - 29: oO0o - ooOoO0o * iIii1I11I1II1 / OoOoOO00
   if 34 - 34: I1IiiI . Oo0Ooo
   if 4 - 4: Ii1I - II111iiii * iII111i / oO0o - I1IiiI
 ii1II11I = I1II [ 0 : o0o0OO000O00 ]
 OOOooo0OooOoO = int ( ii1II11I , 16 ) % lisp_decent_modulus
 if 93 - 93: O0 . I1IiiI % I1IiiI * oO0o % I1Ii111 * Ii1I
 lprint ( "LISP-Decent modulus {}, hash-width {}, mod-value {}, index {}" . format ( lisp_decent_modulus , old_div ( o0o0OO000O00 , 2 ) , ii1II11I , OOOooo0OooOoO ) )
 if 85 - 85: I1Ii111 % I11i + iII111i
 if 83 - 83: iIii1I11I1II1 - IiII * o0oOOo0O0Ooo . i11iIiiIii
 return ( OOOooo0OooOoO )
 if 4 - 4: iIii1I11I1II1 - Ii1I
 if 46 - 46: OOooOOo / iII111i . i1IIi . i11iIiiIii . iIii1I11I1II1 % I11i
 if 62 - 62: I11i % II111iiii % OoooooooOO * ooOoO0o / oO0o
 if 29 - 29: o0oOOo0O0Ooo / O0 / OoO0O00
 if 23 - 23: Ii1I + i11iIiiIii % IiII
 if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
 if 49 - 49: O0
def lisp_get_decent_dns_name ( eid ) :
 OOOooo0OooOoO = lisp_get_decent_index ( eid )
 return ( str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix )
 if 72 - 72: I1Ii111
 if 96 - 96: II111iiii / OOooOOo % i1IIi / Oo0Ooo
 if 22 - 22: I1IiiI % iIii1I11I1II1 % I1ii11iIi11i
 if 68 - 68: iII111i + I11i
 if 61 - 61: oO0o . I1Ii111
 if 74 - 74: O0 . Ii1I - iII111i % IiII + II111iiii
 if 71 - 71: oO0o + Ii1I % oO0o
 if 17 - 17: I1Ii111 % I1Ii111 * o0oOOo0O0Ooo
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 I11I = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 OOOooo0OooOoO = lisp_get_decent_index ( I11I )
 return ( str ( OOOooo0OooOoO ) + "." + lisp_decent_dns_suffix )
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
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 44 - 44: Oo0Ooo - OoooooooOO % ooOoO0o + II111iiii
 IiI1ii1Ii = 28 if packet . inner_version == 4 else 48
 OOO00o0O = packet . packet [ IiI1ii1Ii : : ]
 O0Ooo0 = lisp_trace ( )
 if ( O0Ooo0 . decode ( OOO00o0O ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 26 - 26: Ii1I . OOooOOo / iII111i % OoOoOO00
  if 8 - 8: I1IiiI / O0 * I1IiiI . ooOoO0o * I1IiiI + I1Ii111
 ooO000OOO = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 6 - 6: oO0o . Ii1I + Ii1I / OoooooooOO
 if 19 - 19: IiII / oO0o . OOooOOo / I11i
 if 68 - 68: I1ii11iIi11i + OoO0O00 * i1IIi . Ii1I - i1IIi
 if 43 - 43: OoO0O00 + I1ii11iIi11i * iII111i % i11iIiiIii
 if 55 - 55: IiII
 if 6 - 6: IiII % iIii1I11I1II1 + I1IiiI - II111iiii + O0
 if ( ooO000OOO != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : ooO000OOO += ":{}" . format ( packet . encap_port )
  if 9 - 9: i1IIi
  if 58 - 58: IiII . iII111i % O0 . Ii1I * Oo0Ooo
  if 54 - 54: OoO0O00 % OOooOOo - OoO0O00 . Oo0Ooo % i1IIi
  if 95 - 95: iII111i . OoooooooOO . o0oOOo0O0Ooo / II111iiii - OoooooooOO / I1Ii111
  if 11 - 11: II111iiii / iII111i . oO0o / ooOoO0o / OOooOOo + OoO0O00
 iIiiI11II11i = { }
 iIiiI11II11i [ "n" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 37 - 37: iIii1I11I1II1 * O0
 O0Oo0O00O = packet . outer_source
 if ( O0Oo0O00O . is_null ( ) ) : O0Oo0O00O = lisp_myrlocs [ 0 ]
 iIiiI11II11i [ "sr" ] = O0Oo0O00O . print_address_no_iid ( )
 if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
 if 27 - 27: OoOoOO00 . I11i / OoOoOO00
 if 96 - 96: OoO0O00 - I1IiiI
 if 73 - 73: I1IiiI - o0oOOo0O0Ooo - I1Ii111
 if 34 - 34: iIii1I11I1II1 - i1IIi + OoO0O00 % Oo0Ooo + i1IIi
 if ( iIiiI11II11i [ "n" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  iIiiI11II11i [ "sr" ] += ":{}" . format ( packet . inner_sport )
  if 46 - 46: I1IiiI
  if 82 - 82: iII111i . i1IIi
 iIiiI11II11i [ "hn" ] = lisp_hostname
 III11II111 = ed [ 0 ] + "ts"
 iIiiI11II11i [ III11II111 ] = lisp_get_timestamp ( )
 if 38 - 38: Ii1I . I1IiiI . I1ii11iIi11i
 if 26 - 26: O0 - II111iiii * I1Ii111 - OoOoOO00
 if 96 - 96: I11i * Oo0Ooo / OOooOOo - IiII
 if 75 - 75: OoooooooOO - O0
 if 39 - 39: i11iIiiIii / Ii1I / ooOoO0o
 if 93 - 93: o0oOOo0O0Ooo - Oo0Ooo / oO0o / OoOoOO00
 if ( ooO000OOO == "?" and iIiiI11II11i [ "n" ] == "ETR" ) :
  iIiI1ii = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( iIiI1ii != None and len ( iIiI1ii . rloc_set ) >= 1 ) :
   ooO000OOO = iIiI1ii . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 75 - 75: o0oOOo0O0Ooo * ooOoO0o % Ii1I
   if 94 - 94: OoooooooOO + II111iiii / iIii1I11I1II1 * ooOoO0o
 iIiiI11II11i [ "dr" ] = ooO000OOO
 if 85 - 85: ooOoO0o / IiII
 if 28 - 28: i11iIiiIii - OoOoOO00
 if 13 - 13: O0
 if 82 - 82: OoooooooOO
 if ( ooO000OOO == "?" and reason != None ) :
  iIiiI11II11i [ "dr" ] += " ({})" . format ( reason )
  if 59 - 59: I1Ii111 + I1ii11iIi11i + OoO0O00 % oO0o . i1IIi % O0
  if 22 - 22: i1IIi * OoOoOO00 + Ii1I
  if 48 - 48: Ii1I % IiII + OoO0O00 . IiII
  if 42 - 42: Ii1I
  if 70 - 70: I11i
 if ( rloc_entry != None ) :
  iIiiI11II11i [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  iIiiI11II11i [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  iIiiI11II11i [ "lats" ] = rloc_entry . recent_rloc_probe_latencies
  if 82 - 82: O0
  if 58 - 58: II111iiii . O0 - OoO0O00 - IiII
  if 4 - 4: i11iIiiIii + i11iIiiIii / O0
  if 46 - 46: I11i % ooOoO0o - Ii1I
  if 25 - 25: O0 / i11iIiiIii . O0
  if 24 - 24: I1ii11iIi11i - i11iIiiIii / iII111i . Oo0Ooo / I1ii11iIi11i
 O0OOO0o = packet . inner_source . print_address ( )
 iI1O0oOOO = packet . inner_dest . print_address ( )
 if ( O0Ooo0 . packet_json == [ ] ) :
  i1iIIIi = { }
  i1iIIIi [ "se" ] = O0OOO0o
  i1iIIIi [ "de" ] = iI1O0oOOO
  i1iIIIi [ "paths" ] = [ ]
  O0Ooo0 . packet_json . append ( i1iIIIi )
  if 92 - 92: I11i % OoooooooOO
  if 14 - 14: i11iIiiIii * i11iIiiIii * OoOoOO00
  if 84 - 84: OOooOOo % I1Ii111 + I11i / I1IiiI . iII111i
  if 78 - 78: oO0o . Oo0Ooo
  if 18 - 18: IiII
  if 35 - 35: OoooooooOO / i1IIi - OoO0O00 + Oo0Ooo - o0oOOo0O0Ooo
 for i1iIIIi in O0Ooo0 . packet_json :
  if ( i1iIIIi [ "de" ] != iI1O0oOOO ) : continue
  i1iIIIi [ "paths" ] . append ( iIiiI11II11i )
  break
  if 100 - 100: II111iiii % i11iIiiIii % oO0o + O0
  if 46 - 46: OoO0O00 / I1IiiI - Oo0Ooo . o0oOOo0O0Ooo . Oo0Ooo % I11i
  if 43 - 43: IiII - O0 + I1Ii111 % OoooooooOO % OoO0O00 / I1Ii111
  if 48 - 48: I1ii11iIi11i . i1IIi % i1IIi - iII111i * o0oOOo0O0Ooo + IiII
  if 45 - 45: II111iiii . II111iiii + I1IiiI / I1Ii111 . OoO0O00 - o0oOOo0O0Ooo
  if 20 - 20: ooOoO0o % oO0o
  if 28 - 28: i1IIi . II111iiii + O0 / O0 % OoOoOO00 + OOooOOo
  if 24 - 24: OoooooooOO
 Ii1iI = False
 if ( len ( O0Ooo0 . packet_json ) == 1 and iIiiI11II11i [ "n" ] == "ETR" and
 O0Ooo0 . myeid ( packet . inner_dest ) ) :
  i1iIIIi = { }
  i1iIIIi [ "se" ] = iI1O0oOOO
  i1iIIIi [ "de" ] = O0OOO0o
  i1iIIIi [ "paths" ] = [ ]
  O0Ooo0 . packet_json . append ( i1iIIIi )
  Ii1iI = True
  if 96 - 96: I1Ii111 % OoOoOO00 + OoooooooOO + iIii1I11I1II1 + iII111i
  if 30 - 30: OoOoOO00 . Ii1I % O0 * iIii1I11I1II1
  if 68 - 68: I1IiiI
  if 85 - 85: OoO0O00 % O0 - i11iIiiIii . iII111i . ooOoO0o / i11iIiiIii
  if 19 - 19: OoO0O00
  if 54 - 54: Ii1I . Oo0Ooo + o0oOOo0O0Ooo
 O0Ooo0 . print_trace ( )
 OOO00o0O = O0Ooo0 . encode ( )
 if 59 - 59: Ii1I % OoooooooOO % iII111i
 if 81 - 81: i1IIi % OOooOOo - OoO0O00 - Oo0Ooo
 if 19 - 19: i1IIi
 if 97 - 97: OoO0O00 + i11iIiiIii % I1IiiI * Ii1I
 if 89 - 89: IiII % i11iIiiIii + OoO0O00 . oO0o / I1IiiI . Ii1I
 if 11 - 11: ooOoO0o - I1Ii111 - I11i + OoOoOO00
 if 20 - 20: I11i + O0
 if 27 - 27: Oo0Ooo
 IIIOO0oO0OoooO0 = O0Ooo0 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "sr" ]
 if ( ooO000OOO == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( IIIOO0oO0OoooO0 ) )
  O0Ooo0 . return_to_sender ( lisp_socket , IIIOO0oO0OoooO0 , OOO00o0O )
  return ( False )
  if 30 - 30: I1Ii111 + OoOoOO00 * Oo0Ooo * iII111i % iII111i
  if 95 - 95: iII111i % OoooooooOO * IiII
  if 27 - 27: I1IiiI + I1IiiI + I1ii11iIi11i - oO0o * OOooOOo
  if 53 - 53: I1ii11iIi11i / OoooooooOO * iIii1I11I1II1
  if 4 - 4: I1IiiI . iIii1I11I1II1 + OOooOOo / IiII . o0oOOo0O0Ooo . I11i
  if 52 - 52: ooOoO0o % i11iIiiIii . IiII + OoO0O00
 OooooOo = O0Ooo0 . packet_length ( )
 if 66 - 66: II111iiii . Ii1I
 if 42 - 42: iIii1I11I1II1 * iII111i * I1IiiI
 if 66 - 66: Oo0Ooo * i1IIi / I1ii11iIi11i / OoO0O00
 if 12 - 12: OOooOOo + iIii1I11I1II1 % I1Ii111 + OOooOOo
 if 19 - 19: OoO0O00 / I1IiiI - o0oOOo0O0Ooo - i1IIi + I1ii11iIi11i * OoooooooOO
 if 74 - 74: I1Ii111 . I11i / Oo0Ooo
 OOOO0oo00o = packet . packet [ 0 : IiI1ii1Ii ]
 o00oo = struct . pack ( "HH" , socket . htons ( OooooOo ) , 0 )
 OOOO0oo00o = OOOO0oo00o [ 0 : IiI1ii1Ii - 4 ] + o00oo
 if ( packet . inner_version == 6 and iIiiI11II11i [ "n" ] == "ETR" and
 len ( O0Ooo0 . packet_json ) == 2 ) :
  Ii1iiI1 = OOOO0oo00o [ IiI1ii1Ii - 8 : : ] + OOO00o0O
  Ii1iiI1 = lisp_udp_checksum ( O0OOO0o , iI1O0oOOO , Ii1iiI1 )
  OOOO0oo00o = OOOO0oo00o [ 0 : IiI1ii1Ii - 8 ] + Ii1iiI1 [ 0 : 8 ]
  if 90 - 90: OoooooooOO + II111iiii - i11iIiiIii * I11i + IiII + OOooOOo
  if 66 - 66: OoO0O00
  if 94 - 94: O0
  if 72 - 72: i1IIi - iII111i * I1IiiI % O0 - I11i * O0
  if 78 - 78: I1IiiI - OoO0O00 / Ii1I . i1IIi
  if 30 - 30: IiII
  if 21 - 21: i1IIi . iII111i - I1IiiI
  if 28 - 28: IiII / Ii1I - i1IIi - OoOoOO00
  if 65 - 65: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo
 if ( Ii1iI ) :
  if ( packet . inner_version == 4 ) :
   OOOO0oo00o = OOOO0oo00o [ 0 : 12 ] + OOOO0oo00o [ 16 : 20 ] + OOOO0oo00o [ 12 : 16 ] + OOOO0oo00o [ 22 : 24 ] + OOOO0oo00o [ 20 : 22 ] + OOOO0oo00o [ 24 : : ]
   if 77 - 77: OoooooooOO - Oo0Ooo - OoOoOO00 / I11i / O0 . i11iIiiIii
  else :
   OOOO0oo00o = OOOO0oo00o [ 0 : 8 ] + OOOO0oo00o [ 24 : 40 ] + OOOO0oo00o [ 8 : 24 ] + OOOO0oo00o [ 42 : 44 ] + OOOO0oo00o [ 40 : 42 ] + OOOO0oo00o [ 44 : : ]
   if 27 - 27: I1Ii111 * O0
   if 9 - 9: i1IIi - Oo0Ooo - i11iIiiIii / iIii1I11I1II1 . i1IIi
  iiIi = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = iiIi
  if 2 - 2: I11i + II111iiii - I11i / oO0o / I11i
  if 73 - 73: IiII % I1Ii111 . OoOoOO00
  if 96 - 96: I1IiiI / ooOoO0o / iIii1I11I1II1
  if 91 - 91: Ii1I . I11i
  if 87 - 87: Oo0Ooo / IiII * OOooOOo + I1ii11iIi11i . I11i
  if 56 - 56: oO0o + oO0o % o0oOOo0O0Ooo + OOooOOo . II111iiii + i11iIiiIii
  if 45 - 45: iIii1I11I1II1 / o0oOOo0O0Ooo * OoooooooOO - Oo0Ooo
 IiI1ii1Ii = 2 if packet . inner_version == 4 else 4
 ooO0oo0OoOOO0 = 20 + OooooOo if packet . inner_version == 4 else OooooOo
 Oo0oO0 = struct . pack ( "H" , socket . htons ( ooO0oo0OoOOO0 ) )
 OOOO0oo00o = OOOO0oo00o [ 0 : IiI1ii1Ii ] + Oo0oO0 + OOOO0oo00o [ IiI1ii1Ii + 2 : : ]
 if 50 - 50: I1ii11iIi11i % O0
 if 20 - 20: OOooOOo * I1Ii111 + OoOoOO00
 if 64 - 64: oO0o
 if 77 - 77: oO0o / oO0o + O0 % ooOoO0o
 if ( packet . inner_version == 4 ) :
  I1 = struct . pack ( "H" , 0 )
  OOOO0oo00o = OOOO0oo00o [ 0 : 10 ] + I1 + OOOO0oo00o [ 12 : : ]
  Oo0oO0 = lisp_ip_checksum ( OOOO0oo00o [ 0 : 20 ] )
  OOOO0oo00o = Oo0oO0 + OOOO0oo00o [ 20 : : ]
  if 84 - 84: OoO0O00 - o0oOOo0O0Ooo
  if 57 - 57: I11i - i1IIi - II111iiii - O0 . iII111i + OoO0O00
  if 67 - 67: OOooOOo * iII111i / iIii1I11I1II1 / I1ii11iIi11i
  if 10 - 10: OoooooooOO % I1ii11iIi11i * i1IIi . iII111i
  if 96 - 96: II111iiii % i11iIiiIii - Oo0Ooo
 packet . packet = OOOO0oo00o + OOO00o0O
 return ( True )
 if 70 - 70: O0 * iIii1I11I1II1 - IiII * I11i / Ii1I + i11iIiiIii
 if 26 - 26: II111iiii - I11i % I11i / ooOoO0o + Oo0Ooo
 if 91 - 91: I1IiiI % Ii1I - OOooOOo - Oo0Ooo / I1IiiI / OoO0O00
 if 40 - 40: OoooooooOO
 if 71 - 71: OOooOOo
 if 88 - 88: O0
 if 44 - 44: II111iiii - IiII / I1IiiI + ooOoO0o % iII111i - iII111i
 if 53 - 53: OoooooooOO
 if 41 - 41: i1IIi - oO0o
 if 41 - 41: I11i
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 92 - 92: i11iIiiIii
 for iIiiI11II11i in lisp_glean_mappings :
  if ( "instance-id" in iIiiI11II11i ) :
   i1oO00O = eid . instance_id
   OooOOoO0o0 , OO0I11iI = iIiiI11II11i [ "instance-id" ]
   if ( i1oO00O < OooOOoO0o0 or i1oO00O > OO0I11iI ) : continue
   if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
  if ( "eid-prefix" in iIiiI11II11i ) :
   I1i = copy . deepcopy ( iIiiI11II11i [ "eid-prefix" ] )
   I1i . instance_id = eid . instance_id
   if ( eid . is_more_specific ( I1i ) == False ) : continue
   if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
  if ( "group-prefix" in iIiiI11II11i ) :
   if ( group == None ) : continue
   o0O0Ooo = copy . deepcopy ( iIiiI11II11i [ "group-prefix" ] )
   o0O0Ooo . instance_id = group . instance_id
   if ( group . is_more_specific ( o0O0Ooo ) == False ) : continue
   if 77 - 77: i1IIi
  if ( "rloc-prefix" in iIiiI11II11i ) :
   if ( rloc != None and rloc . is_more_specific ( iIiiI11II11i [ "rloc-prefix" ] )
 == False ) : continue
   if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
  return ( True , iIiiI11II11i [ "rloc-probe" ] , iIiiI11II11i [ "igmp-query" ] )
  if 65 - 65: O0 / OoOoOO00
 return ( False , False , False )
 if 77 - 77: OoO0O00
 if 17 - 17: i1IIi
 if 35 - 35: OoOoOO00
 if 61 - 61: I1Ii111
 if 78 - 78: I1Ii111 * Ii1I % Ii1I + I1IiiI
 if 83 - 83: iIii1I11I1II1 + O0 / IiII . iIii1I11I1II1
 if 74 - 74: Oo0Ooo
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 iiiii1I1III1 = geid . print_address ( )
 oo0O = seid . print_address_no_iid ( )
 I1iiIi111I = green ( "{}" . format ( oo0O ) , False )
 I1i = green ( "(*, {})" . format ( iiiii1I1III1 ) , False )
 I1I1iIiiiiII11 = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 11 - 11: I11i + I1ii11iIi11i
 if 82 - 82: o0oOOo0O0Ooo
 if 99 - 99: ooOoO0o . o0oOOo0O0Ooo - O0 * I1Ii111 . i11iIiiIii / iIii1I11I1II1
 if 40 - 40: iIii1I11I1II1 + oO0o / iIii1I11I1II1 - i1IIi % OoO0O00
 O0oo0OOo00o0o = lisp_map_cache_lookup ( seid , geid )
 if ( O0oo0OOo00o0o == None ) :
  O0oo0OOo00o0o = lisp_mapping ( "" , "" , [ ] )
  O0oo0OOo00o0o . group . copy_address ( geid )
  O0oo0OOo00o0o . eid . copy_address ( geid )
  O0oo0OOo00o0o . eid . address = 0
  O0oo0OOo00o0o . eid . mask_len = 0
  O0oo0OOo00o0o . mapping_source . copy_address ( rloc )
  O0oo0OOo00o0o . map_cache_ttl = LISP_IGMP_TTL
  O0oo0OOo00o0o . gleaned = True
  O0oo0OOo00o0o . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( I1i ) )
  if 22 - 22: OOooOOo
  if 65 - 65: i1IIi - oO0o . I1Ii111 . ooOoO0o % I1ii11iIi11i % I1ii11iIi11i
  if 1 - 1: I1Ii111 + I1Ii111
  if 96 - 96: iII111i + OoOoOO00 - o0oOOo0O0Ooo + Ii1I
  if 6 - 6: O0 . I11i
  if 22 - 22: Oo0Ooo . O0 / i1IIi - OoOoOO00
 II1 = iiII11I1 = IIIi11i1 = None
 if ( O0oo0OOo00o0o . rloc_set != [ ] ) :
  II1 = O0oo0OOo00o0o . rloc_set [ 0 ]
  if ( II1 . rle ) :
   iiII11I1 = II1 . rle
   for iii1I1 in iiII11I1 . rle_nodes :
    if ( iii1I1 . rloc_name != oo0O ) : continue
    IIIi11i1 = iii1I1
    break
    if 62 - 62: OOooOOo % Ii1I / IiII % oO0o - I1Ii111
    if 47 - 47: OoO0O00
    if 78 - 78: O0 * II111iiii % O0 * O0 / oO0o
    if 47 - 47: Oo0Ooo . Oo0Ooo . I1IiiI / OoO0O00 + II111iiii + IiII
    if 23 - 23: i1IIi . II111iiii
    if 60 - 60: ooOoO0o * oO0o + Oo0Ooo / iIii1I11I1II1
    if 74 - 74: OoooooooOO + II111iiii - IiII + O0
 if ( II1 == None ) :
  II1 = lisp_rloc ( )
  O0oo0OOo00o0o . rloc_set = [ II1 ]
  II1 . priority = 253
  II1 . mpriority = 255
  O0oo0OOo00o0o . build_best_rloc_set ( )
  if 62 - 62: O0 . I11i * oO0o
 if ( iiII11I1 == None ) :
  iiII11I1 = lisp_rle ( geid . print_address ( ) )
  II1 . rle = iiII11I1
  if 88 - 88: iII111i * iII111i - ooOoO0o + OoO0O00 . iII111i
 if ( IIIi11i1 == None ) :
  IIIi11i1 = lisp_rle_node ( )
  IIIi11i1 . rloc_name = oo0O
  iiII11I1 . rle_nodes . append ( IIIi11i1 )
  iiII11I1 . build_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( I1I1iIiiiiII11 , I1iiIi111I , I1i ) )
 elif ( rloc . is_exact_match ( IIIi11i1 . address ) == False or
 port != IIIi11i1 . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( I1I1iIiiiiII11 , I1iiIi111I , I1i ) )
  if 44 - 44: I11i / I1Ii111
  if 77 - 77: oO0o * OoOoOO00 * O0 % IiII
  if 45 - 45: OoOoOO00
  if 66 - 66: I11i
  if 10 - 10: i11iIiiIii - O0 / iII111i * i11iIiiIii * OoooooooOO - oO0o
 IIIi11i1 . store_translated_rloc ( rloc , port )
 if 70 - 70: i1IIi / IiII + II111iiii - I1ii11iIi11i . OoooooooOO - i1IIi
 if 34 - 34: OoOoOO00 + iII111i - I11i . IiII
 if 79 - 79: ooOoO0o - II111iiii + I1IiiI - o0oOOo0O0Ooo . Ii1I
 if 16 - 16: o0oOOo0O0Ooo . i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
 if 57 - 57: IiII
 if ( igmp ) :
  iI11iI11i11ii = seid . print_address ( )
  if ( iI11iI11i11ii not in lisp_gleaned_groups ) :
   lisp_gleaned_groups [ iI11iI11i11ii ] = { }
   if 89 - 89: I1ii11iIi11i - I1Ii111 + o0oOOo0O0Ooo
  lisp_gleaned_groups [ iI11iI11i11ii ] [ iiiii1I1III1 ] = lisp_get_timestamp ( )
  if 62 - 62: I1ii11iIi11i + OoooooooOO * OOooOOo
  if 49 - 49: i1IIi - I11i * II111iiii
  if 4 - 4: o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 57 - 57: I1IiiI * OOooOOo . i11iIiiIii * oO0o - OoOoOO00
  if 35 - 35: O0
  if 65 - 65: Oo0Ooo
  if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * OoooooooOO . o0oOOo0O0Ooo
  if 90 - 90: i11iIiiIii . I1IiiI + ooOoO0o * OoooooooOO * OoooooooOO + oO0o
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 77 - 77: OOooOOo * OoOoOO00
 if 75 - 75: Oo0Ooo * Oo0Ooo - IiII - OoOoOO00 / i11iIiiIii + I1Ii111
 if 57 - 57: i11iIiiIii / oO0o
 if 37 - 37: o0oOOo0O0Ooo + OoOoOO00 - i1IIi . Oo0Ooo
 O0oo0OOo00o0o = lisp_map_cache_lookup ( seid , geid )
 if ( O0oo0OOo00o0o == None ) : return
 if 3 - 3: ooOoO0o % OoooooooOO / I1Ii111 + oO0o - O0
 IIiiiI = O0oo0OOo00o0o . rloc_set [ 0 ] . rle
 if ( IIiiiI == None ) : return
 if 72 - 72: oO0o * OoO0O00
 oOo = seid . print_address_no_iid ( )
 Ii1iI11I1ii1i = False
 for IIIi11i1 in IIiiiI . rle_nodes :
  if ( IIIi11i1 . rloc_name == oOo ) :
   Ii1iI11I1ii1i = True
   break
   if 89 - 89: OoooooooOO . OOooOOo
   if 96 - 96: o0oOOo0O0Ooo + OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo * i11iIiiIii + OOooOOo
 if ( Ii1iI11I1ii1i == False ) : return
 if 16 - 16: IiII / I1Ii111 . II111iiii * I11i
 if 33 - 33: I1ii11iIi11i / Oo0Ooo % i11iIiiIii
 if 37 - 37: Oo0Ooo - I1Ii111 - IiII / oO0o % I1IiiI / I1Ii111
 if 80 - 80: iII111i - oO0o % i1IIi * iIii1I11I1II1 . oO0o
 IIiiiI . rle_nodes . remove ( IIIi11i1 )
 IIiiiI . build_forwarding_list ( )
 if 86 - 86: Ii1I
 iiiii1I1III1 = geid . print_address ( )
 iI11iI11i11ii = seid . print_address ( )
 I1iiIi111I = green ( "{}" . format ( iI11iI11i11ii ) , False )
 I1i = green ( "(*, {})" . format ( iiiii1I1III1 ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( I1i , I1iiIi111I ) )
 if 36 - 36: i11iIiiIii % i11iIiiIii
 if 91 - 91: Oo0Ooo + I1Ii111 % iII111i
 if 7 - 7: I1Ii111 + II111iiii
 if 63 - 63: OoO0O00 - o0oOOo0O0Ooo / iII111i % II111iiii * IiII
 if ( iI11iI11i11ii in lisp_gleaned_groups ) :
  if ( iiiii1I1III1 in lisp_gleaned_groups [ iI11iI11i11ii ] ) :
   lisp_gleaned_groups [ iI11iI11i11ii ] . pop ( iiiii1I1III1 )
   if 71 - 71: IiII
   if 34 - 34: II111iiii
   if 7 - 7: IiII / I1ii11iIi11i
   if 88 - 88: iIii1I11I1II1 / o0oOOo0O0Ooo
   if 68 - 68: OoooooooOO % Ii1I + ooOoO0o / oO0o
   if 60 - 60: i11iIiiIii / O0 / I1IiiI
 if ( IIiiiI . rle_nodes == [ ] ) :
  O0oo0OOo00o0o . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( I1i ) )
  if 99 - 99: I1IiiI / oO0o . OoO0O00 / ooOoO0o + IiII
  if 3 - 3: II111iiii . OOooOOo * i11iIiiIii / I11i
  if 16 - 16: I1ii11iIi11i - ooOoO0o + OoO0O00 . I11i / O0
  if 56 - 56: I1IiiI + Oo0Ooo * II111iiii + iIii1I11I1II1
  if 56 - 56: o0oOOo0O0Ooo * I1IiiI - I11i * I1Ii111 - I11i
  if 92 - 92: oO0o % iIii1I11I1II1 * o0oOOo0O0Ooo * OoooooooOO - iIii1I11I1II1
  if 51 - 51: Ii1I - OoO0O00 + i1IIi
  if 11 - 11: II111iiii - iII111i + oO0o % Oo0Ooo
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 iI11iI11i11ii = seid . print_address ( )
 if ( iI11iI11i11ii not in lisp_gleaned_groups ) : return
 if 56 - 56: IiII
 for o0o0o in lisp_gleaned_groups [ iI11iI11i11ii ] :
  lisp_geid . store_address ( o0o0o )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
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
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 91 - 91: OoooooooOO
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 86 - 86: iII111i / OoooooooOO - I1ii11iIi11i
def lisp_process_igmp_packet ( packet ) :
 OO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 OO . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 OO = bold ( "from {}" . format ( OO . print_address_no_iid ( ) ) , False )
 if 63 - 63: ooOoO0o % Ii1I * I1IiiI
 I1I1iIiiiiII11 = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( I1I1iIiiiiII11 , len ( packet ) , OO ,
 lisp_format_packet ( packet ) ) )
 if 48 - 48: iII111i - iII111i - o0oOOo0O0Ooo + ooOoO0o - o0oOOo0O0Ooo / Ii1I
 if 43 - 43: I1IiiI + Ii1I
 if 37 - 37: OoOoOO00 - OoooooooOO . ooOoO0o - IiII % iIii1I11I1II1 . iIii1I11I1II1
 if 64 - 64: OoOoOO00 + iII111i % I1Ii111 - OOooOOo + O0
 o00O00O = ( struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ] & 0x0f ) * 4
 if 92 - 92: Ii1I . I11i
 if 12 - 12: o0oOOo0O0Ooo * I1IiiI . i1IIi * OoooooooOO
 if 46 - 46: i1IIi + II111iiii . I1ii11iIi11i + O0 / I11i
 if 15 - 15: II111iiii / I1IiiI / i11iIiiIii
 iII1iIIiII1i = packet [ o00O00O : : ]
 OOOOO0OoOoo = struct . unpack ( "B" , iII1iIIiII1i [ 0 : 1 ] ) [ 0 ]
 if 49 - 49: O0 * Ii1I * i1IIi % IiII % OoooooooOO / I1Ii111
 if 11 - 11: OoO0O00 * ooOoO0o * II111iiii - iII111i
 if 18 - 18: I1ii11iIi11i + I1IiiI * iIii1I11I1II1 - I11i - o0oOOo0O0Ooo
 if 47 - 47: IiII + OoO0O00 % ooOoO0o - iII111i - IiII - oO0o
 if 63 - 63: OoooooooOO / I1Ii111
 o0o0o = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 o0o0o . address = socket . ntohl ( struct . unpack ( "II" , iII1iIIiII1i [ : 8 ] ) [ 1 ] )
 iiiii1I1III1 = o0o0o . print_address_no_iid ( )
 if 90 - 90: I1Ii111 . i11iIiiIii - iIii1I11I1II1 + I1Ii111
 if ( OOOOO0OoOoo == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( iiiii1I1III1 ) )
  return ( True )
  if 67 - 67: IiII - I1ii11iIi11i + ooOoO0o . iIii1I11I1II1 . IiII
  if 13 - 13: I1IiiI / i11iIiiIii % iIii1I11I1II1 - Oo0Ooo . i11iIiiIii + I1IiiI
 OOOoo0o = ( OOOOO0OoOoo in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( OOOoo0o == False ) :
  O0OOiii11i = "{} ({})" . format ( OOOOO0OoOoo , igmp_types [ OOOOO0OoOoo ] ) if ( OOOOO0OoOoo in igmp_types ) else OOOOO0OoOoo
  if 46 - 46: iIii1I11I1II1 - OoooooooOO . oO0o % iIii1I11I1II1 / i1IIi + Ii1I
  lprint ( "IGMP type {} not supported" . format ( O0OOiii11i ) )
  return ( [ ] )
  if 5 - 5: I1ii11iIi11i % II111iiii
  if 17 - 17: i11iIiiIii - II111iiii / O0 % OoO0O00 . Oo0Ooo + IiII
 if ( len ( iII1iIIiII1i ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 60 - 60: I11i % I1IiiI
  if 99 - 99: oO0o . OOooOOo % iII111i * Ii1I
  if 98 - 98: Oo0Ooo * O0 + i1IIi
  if 41 - 41: i1IIi % OoO0O00 * iIii1I11I1II1
  if 2 - 2: I1ii11iIi11i * iII111i . iIii1I11I1II1 * Oo0Ooo
 if ( OOOOO0OoOoo == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( iiiii1I1III1 , False ) ) )
  return ( [ [ None , iiiii1I1III1 , False ] ] )
  if 34 - 34: i11iIiiIii % O0 . I1IiiI / ooOoO0o + OoO0O00
 if ( OOOOO0OoOoo in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( OOOOO0OoOoo == 0x12 ) else 2 , bold ( iiiii1I1III1 , False ) ) )
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
 iIiI1IIi1Ii1i = o0o0o . address
 iII1iIIiII1i = iII1iIIiII1i [ 8 : : ]
 if 27 - 27: Ii1I / o0oOOo0O0Ooo % I11i
 oooo0oo0o00 = "BBHI"
 OOo0oOOO0ooO = struct . calcsize ( oooo0oo0o00 )
 o0OoO0 = "I"
 Oo0oo0000O = struct . calcsize ( o0OoO0 )
 OO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 16 - 16: Ii1I . I1ii11iIi11i
 if 28 - 28: iII111i
 if 74 - 74: Ii1I + I1IiiI * iII111i / i11iIiiIii - ooOoO0o * OoooooooOO
 if 98 - 98: I1IiiI
 Oo0o0ooo0oo0 = [ ]
 for OoOOoO0oOo in range ( iIiI1IIi1Ii1i ) :
  if ( len ( iII1iIIiII1i ) < OOo0oOOO0ooO ) : return
  III111I , ooooO00o0 , o0oo0Oo0Oo00 , Ii1IiIIIi = struct . unpack ( oooo0oo0o00 ,
 iII1iIIiII1i [ : OOo0oOOO0ooO ] )
  if 1 - 1: i1IIi + iII111i - O0 - o0oOOo0O0Ooo
  iII1iIIiII1i = iII1iIIiII1i [ OOo0oOOO0ooO : : ]
  if 23 - 23: I1ii11iIi11i . OoO0O00 + OOooOOo % OoOoOO00 * o0oOOo0O0Ooo % OoOoOO00
  if ( III111I not in lisp_igmp_record_types ) :
   lprint ( "Invalid record type {}" . format ( III111I ) )
   continue
   if 96 - 96: iIii1I11I1II1 . iII111i + IiII
   if 51 - 51: Ii1I
  o0O0oo = lisp_igmp_record_types [ III111I ]
  o0oo0Oo0Oo00 = socket . ntohs ( o0oo0Oo0Oo00 )
  o0o0o . address = socket . ntohl ( Ii1IiIIIi )
  iiiii1I1III1 = o0o0o . print_address_no_iid ( )
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
  for Oooo0 in range ( o0oo0Oo0Oo00 ) :
   if ( len ( iII1iIIiII1i ) < Oo0oo0000O ) : return
   Ii1IiIIIi = struct . unpack ( o0OoO0 , iII1iIIiII1i [ : Oo0oo0000O ] ) [ 0 ]
   OO . address = socket . ntohl ( Ii1IiIIIi )
   iiiI11Ii1 = OO . print_address_no_iid ( )
   Oo0o0ooo0oo0 . append ( [ iiiI11Ii1 , iiiii1I1III1 , O00oOoo00 ] )
   lprint ( "{} ({}, {})" . format ( IIiI1i1 ,
 green ( iiiI11Ii1 , False ) , bold ( iiiii1I1III1 , False ) ) )
   iII1iIIiII1i = iII1iIIiII1i [ Oo0oo0000O : : ]
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
 O0oo0OOo00o0o = lisp_map_cache . lookup_cache ( seid , True )
 if ( O0oo0OOo00o0o and len ( O0oo0OOo00o0o . rloc_set ) != 0 ) :
  O0oo0OOo00o0o . last_refresh_time = lisp_get_timestamp ( )
  if 95 - 95: iII111i . OOooOOo - O0 . II111iiii - Oo0Ooo
  II1I11iiI1iii = O0oo0OOo00o0o . rloc_set [ 0 ]
  OO00Ooo = II1I11iiI1iii . rloc
  IiiIiiiI1i1iI = II1I11iiI1iii . translated_port
  oOoO0OoOOooo = ( OO00Ooo . is_exact_match ( rloc ) == False or
 IiiIiiiI1i1iI != encap_port )
  if 53 - 53: iIii1I11I1II1 . Ii1I / Ii1I % I1ii11iIi11i % I1Ii111
  if ( oOoO0OoOOooo ) :
   I1i = green ( seid . print_address ( ) , False )
   I1I1iIiiiiII11 = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( I1i , I1I1iIiiiiII11 ) )
   II1I11iiI1iii . delete_from_rloc_probe_list ( O0oo0OOo00o0o . eid , O0oo0OOo00o0o . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 13 - 13: I11i + O0 * oO0o - II111iiii
 else :
  O0oo0OOo00o0o = lisp_mapping ( "" , "" , [ ] )
  O0oo0OOo00o0o . eid . copy_address ( seid )
  O0oo0OOo00o0o . mapping_source . copy_address ( rloc )
  O0oo0OOo00o0o . map_cache_ttl = LISP_GLEAN_TTL
  O0oo0OOo00o0o . gleaned = True
  I1i = green ( seid . print_address ( ) , False )
  I1I1iIiiiiII11 = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( I1i , I1I1iIiiiiII11 ) )
  O0oo0OOo00o0o . add_cache ( )
  if 4 - 4: I11i
  if 5 - 5: Oo0Ooo - iII111i % iIii1I11I1II1 * OoOoOO00
  if 41 - 41: i1IIi * IiII - i11iIiiIii / O0 + Oo0Ooo + ooOoO0o
  if 94 - 94: OoO0O00 . O0 + iIii1I11I1II1 . oO0o % oO0o
  if 7 - 7: I1ii11iIi11i * oO0o / OoOoOO00
 if ( oOoO0OoOOooo ) :
  II1 = lisp_rloc ( )
  II1 . store_translated_rloc ( rloc , encap_port )
  II1 . add_to_rloc_probe_list ( O0oo0OOo00o0o . eid , O0oo0OOo00o0o . group )
  II1 . priority = 253
  II1 . mpriority = 255
  IIiii11iiI111 = [ II1 ]
  O0oo0OOo00o0o . rloc_set = IIiii11iiI111
  O0oo0OOo00o0o . build_best_rloc_set ( )
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
 Ii11111I11I = lisp_process_igmp_packet ( igmp )
 if ( type ( Ii11111I11I ) == bool ) : return
 if 94 - 94: iII111i + oO0o
 for OO , o0o0o , O00oOoo00 in Ii11111I11I :
  if ( OO != None ) : continue
  if 43 - 43: iIii1I11I1II1 + iIii1I11I1II1
  if 8 - 8: iIii1I11I1II1
  if 30 - 30: OOooOOo - I1ii11iIi11i * iIii1I11I1II1 + Oo0Ooo
  if 25 - 25: IiII
  lisp_geid . store_address ( o0o0o )
  o00000o , ooooO00o0 , IIi11I = lisp_allow_gleaning ( seid , lisp_geid , rloc )
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
  ii1i1iiI1 = json . loads ( json_string )
  if ( type ( ii1i1iiI1 ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 7 - 7: ooOoO0o * I1ii11iIi11i - Ii1I % i1IIi + I11i
  if 22 - 22: I1IiiI - OOooOOo - II111iiii * I1IiiI
 if ( "type" not in ii1i1iiI1 ) : return ( None )
 if ( "sub-type" not in ii1i1iiI1 ) : return ( None )
 if ( ii1i1iiI1 [ "type" ] != "telemetry" ) : return ( None )
 if ( ii1i1iiI1 [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( ii1i1iiI1 )
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
 ii1i1iiI1 = lisp_is_json_telemetry ( json_string )
 if ( ii1i1iiI1 == None ) : return ( json_string )
 if 7 - 7: I1IiiI * OoO0O00 * I1IiiI
 if ( ii1i1iiI1 [ "itr-in" ] == "?" ) : ii1i1iiI1 [ "itr-in" ] = ii
 if ( ii1i1iiI1 [ "itr-out" ] == "?" ) : ii1i1iiI1 [ "itr-out" ] = io
 if ( ii1i1iiI1 [ "etr-in" ] == "?" ) : ii1i1iiI1 [ "etr-in" ] = ei
 if ( ii1i1iiI1 [ "etr-out" ] == "?" ) : ii1i1iiI1 [ "etr-out" ] = eo
 json_string = json . dumps ( ii1i1iiI1 )
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
 ii1i1iiI1 = lisp_is_json_telemetry ( json_string )
 if ( ii1i1iiI1 == None ) : return ( { } )
 return ( ii1i1iiI1 )
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
 if ( "telemetry" not in lisp_json_list ) : return ( None )
 if 44 - 44: O0 - o0oOOo0O0Ooo - I1Ii111 % O0
 Ii111I1iIiiIi = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( Ii111I1iIiiIi ) == None ) : return ( None )
 if 31 - 31: i11iIiiIii - I11i
 return ( Ii111I1iIiiIi )
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
