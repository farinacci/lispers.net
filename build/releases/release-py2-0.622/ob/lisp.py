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
if 55 - 55: OOooOOo . I1IiiI
lisp_decent_lookup_prefixes = { }
if 61 - 61: Oo0Ooo % IiII . Oo0Ooo
if 100 - 100: I1Ii111 * O0
if 64 - 64: OOooOOo % iIii1I11I1II1 * oO0o
if 79 - 79: O0
if 78 - 78: I1ii11iIi11i + OOooOOo - I1Ii111
if 38 - 38: o0oOOo0O0Ooo - oO0o + iIii1I11I1II1 / OoOoOO00 % Oo0Ooo
lisp_ipc_socket = None
if 57 - 57: OoO0O00 / ooOoO0o
if 29 - 29: iIii1I11I1II1 + OoOoOO00 * OoO0O00 * OOooOOo . I1IiiI * I1IiiI
if 7 - 7: IiII * I1Ii111 % Ii1I - o0oOOo0O0Ooo
if 13 - 13: Ii1I . i11iIiiIii
lisp_ms_encryption_keys = { }
lisp_ms_json_keys = { }
if 56 - 56: I1ii11iIi11i % O0 - I1IiiI
if 100 - 100: Ii1I - O0 % oO0o * OOooOOo + I1IiiI
if 88 - 88: OoooooooOO - OoO0O00 * O0 * OoooooooOO . OoooooooOO
if 33 - 33: I1Ii111 + iII111i * oO0o / iIii1I11I1II1 - I1IiiI
if 54 - 54: I1Ii111 / OOooOOo . oO0o % iII111i
if 57 - 57: i11iIiiIii . I1ii11iIi11i - Ii1I - oO0o + OoOoOO00
if 63 - 63: OoOoOO00 * iII111i
if 69 - 69: O0 . OoO0O00
if 49 - 49: I1IiiI - I11i
if 74 - 74: iIii1I11I1II1 * I1ii11iIi11i + OoOoOO00 / i1IIi / II111iiii . Oo0Ooo
if 62 - 62: OoooooooOO * I1IiiI
if 58 - 58: OoOoOO00 % o0oOOo0O0Ooo
if 50 - 50: I1Ii111 . o0oOOo0O0Ooo
if 97 - 97: O0 + OoOoOO00
lisp_rtr_nat_trace_cache = { }
if 89 - 89: o0oOOo0O0Ooo + OoO0O00 * I11i * Ii1I
if 37 - 37: OoooooooOO - O0 - o0oOOo0O0Ooo
if 77 - 77: OOooOOo * iIii1I11I1II1
if 98 - 98: I1IiiI % Ii1I * OoooooooOO
if 51 - 51: iIii1I11I1II1 . OoOoOO00 / oO0o + o0oOOo0O0Ooo
if 33 - 33: ooOoO0o . II111iiii % iII111i + o0oOOo0O0Ooo
if 71 - 71: Oo0Ooo % OOooOOo
if 98 - 98: I11i % i11iIiiIii % ooOoO0o + Ii1I
if 78 - 78: I1ii11iIi11i % oO0o / iII111i - iIii1I11I1II1
if 69 - 69: I1Ii111
lisp_glean_mappings = [ ]
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
if 52 - 52: OOooOOo
if 19 - 19: I1IiiI
if 25 - 25: Ii1I / ooOoO0o
if 31 - 31: OOooOOo . O0 % I1IiiI . o0oOOo0O0Ooo + IiII
if 71 - 71: I1Ii111 . II111iiii
lisp_gleaned_groups = { }
if 62 - 62: OoooooooOO . I11i
if 61 - 61: OoOoOO00 - OOooOOo - i1IIi
if 25 - 25: O0 * I11i + I1ii11iIi11i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
if 58 - 58: I1IiiI
if 53 - 53: i1IIi
lisp_icmp_raw_socket = None
if ( os . getenv ( "LISP_SEND_ICMP_TOO_BIG" ) != None ) :
 lisp_icmp_raw_socket = socket . socket ( socket . AF_INET , socket . SOCK_RAW ,
 socket . IPPROTO_ICMP )
 lisp_icmp_raw_socket . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
 if 59 - 59: o0oOOo0O0Ooo
 if 81 - 81: OoOoOO00 - OoOoOO00 . iII111i
lisp_ignore_df_bit = ( os . getenv ( "LISP_IGNORE_DF_BIT" ) != None )
if 73 - 73: I11i % i11iIiiIii - I1IiiI
if 7 - 7: O0 * i11iIiiIii * Ii1I + ooOoO0o % OoO0O00 - ooOoO0o
if 39 - 39: Oo0Ooo * OOooOOo % OOooOOo - OoooooooOO + o0oOOo0O0Ooo - I11i
if 23 - 23: i11iIiiIii
if 30 - 30: o0oOOo0O0Ooo - i1IIi % II111iiii + I11i * iIii1I11I1II1
if 81 - 81: IiII % i1IIi . iIii1I11I1II1
LISP_DATA_PORT = 4341
LISP_CTRL_PORT = 4342
LISP_L2_DATA_PORT = 8472
LISP_VXLAN_DATA_PORT = 4789
LISP_VXLAN_GPE_PORT = 4790
LISP_TRACE_PORT = 2434
if 4 - 4: i11iIiiIii % OoO0O00 % i1IIi / IiII
if 6 - 6: iII111i / I1IiiI % OOooOOo - I1IiiI
if 31 - 31: OOooOOo
if 23 - 23: I1Ii111 . IiII
LISP_MAP_REQUEST = 1
LISP_MAP_REPLY = 2
LISP_MAP_REGISTER = 3
LISP_MAP_NOTIFY = 4
LISP_MAP_NOTIFY_ACK = 5
LISP_MAP_REFERRAL = 6
LISP_NAT_INFO = 7
LISP_ECM = 8
LISP_TRACE = 9
if 92 - 92: OoOoOO00 + I1Ii111 * Ii1I % I1IiiI
if 42 - 42: Oo0Ooo
if 76 - 76: I1IiiI * iII111i % I1Ii111
if 57 - 57: iIii1I11I1II1 - i1IIi / I1Ii111 - O0 * OoooooooOO % II111iiii
LISP_NO_ACTION = 0
LISP_NATIVE_FORWARD_ACTION = 1
LISP_SEND_MAP_REQUEST_ACTION = 2
LISP_DROP_ACTION = 3
LISP_POLICY_DENIED_ACTION = 4
LISP_AUTH_FAILURE_ACTION = 5
LISP_SEND_PUBSUB_ACTION = 6
LISP_NOT_REGISTERED_YET_ACTION = 7
if 68 - 68: OoooooooOO * I11i % OoOoOO00 - IiII
lisp_map_reply_action_string = [ "no-action" , "native-forward" ,
 "send-map-request" , "drop-action" , "policy-denied" ,
 "auth-failure" , "send-subscribe" , "not-registered-yet" ]
if 34 - 34: I1Ii111 . iIii1I11I1II1 * OoOoOO00 * oO0o / I1Ii111 / I1ii11iIi11i
if 78 - 78: Oo0Ooo - o0oOOo0O0Ooo / OoOoOO00
if 10 - 10: iII111i + Oo0Ooo * I1ii11iIi11i + iIii1I11I1II1 / I1Ii111 / I1ii11iIi11i
if 42 - 42: I1IiiI
LISP_NONE_ALG_ID = 0
LISP_SHA_1_96_ALG_ID = 1
LISP_SHA_256_128_ALG_ID = 2
LISP_MD5_AUTH_DATA_LEN = 16
LISP_SHA1_160_AUTH_DATA_LEN = 20
LISP_SHA2_256_AUTH_DATA_LEN = 32
if 38 - 38: OOooOOo + II111iiii % ooOoO0o % OoOoOO00 - Ii1I / OoooooooOO
if 73 - 73: o0oOOo0O0Ooo * O0 - i11iIiiIii
if 85 - 85: Ii1I % iII111i + I11i / o0oOOo0O0Ooo . oO0o + OOooOOo
if 62 - 62: i11iIiiIii + i11iIiiIii - o0oOOo0O0Ooo
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
if 28 - 28: iII111i . iII111i % iIii1I11I1II1 * iIii1I11I1II1 . o0oOOo0O0Ooo / iII111i
if 27 - 27: OoO0O00 + ooOoO0o - i1IIi
if 69 - 69: IiII - O0 % I1ii11iIi11i + i11iIiiIii . OoOoOO00 / OoO0O00
if 79 - 79: O0 * i11iIiiIii - IiII / IiII
LISP_MR_TTL = ( 24 * 60 )
LISP_REGISTER_TTL = 3
LISP_SHORT_TTL = 1
LISP_NMR_TTL = 15
LISP_GLEAN_TTL = 15
LISP_MCAST_TTL = 15
LISP_IGMP_TTL = 240
if 48 - 48: O0
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
if 5 - 5: Ii1I
if 46 - 46: IiII
if 45 - 45: ooOoO0o
if 21 - 21: oO0o . I1Ii111 . OOooOOo / Oo0Ooo / I1Ii111
LISP_CS_1024 = 0
LISP_CS_1024_G = 2
LISP_CS_1024_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 17 - 17: OOooOOo / OOooOOo / I11i
LISP_CS_2048_CBC = 1
LISP_CS_2048_CBC_G = 2
LISP_CS_2048_CBC_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
if 1 - 1: i1IIi . i11iIiiIii % OOooOOo
LISP_CS_25519_CBC = 2
LISP_CS_2048_GCM = 3
if 82 - 82: iIii1I11I1II1 + Oo0Ooo . iIii1I11I1II1 % IiII / Ii1I . Ii1I
LISP_CS_3072 = 4
LISP_CS_3072_G = 2
LISP_CS_3072_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
if 14 - 14: o0oOOo0O0Ooo . OOooOOo . I11i + OoooooooOO - OOooOOo + IiII
LISP_CS_25519_GCM = 5
LISP_CS_25519_CHACHA = 6
if 9 - 9: Ii1I
LISP_4_32_MASK = 0xFFFFFFFF
LISP_8_64_MASK = 0xFFFFFFFFFFFFFFFF
LISP_16_128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
if 59 - 59: I1IiiI * II111iiii . O0
use_chacha = ( os . getenv ( "LISP_USE_CHACHA" ) != None )
use_poly = ( os . getenv ( "LISP_USE_POLY" ) != None )
if 56 - 56: Ii1I - iII111i % I1IiiI - o0oOOo0O0Ooo
if 51 - 51: O0 / ooOoO0o * iIii1I11I1II1 + I1ii11iIi11i + o0oOOo0O0Ooo
if 98 - 98: iIii1I11I1II1 * I1ii11iIi11i * OOooOOo + ooOoO0o % i11iIiiIii % O0
if 27 - 27: O0
if 79 - 79: o0oOOo0O0Ooo - I11i + o0oOOo0O0Ooo . oO0o
if 28 - 28: i1IIi - iII111i
if 54 - 54: iII111i - O0 % OOooOOo
if 73 - 73: O0 . OoOoOO00 + I1IiiI - I11i % I11i . I11i
def lisp_record_traceback ( * args ) :
 if 17 - 17: Ii1I - OoooooooOO % Ii1I . IiII / i11iIiiIii % iII111i
 iIiIIIIIii = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
 OOo0 = open ( "./logs/lisp-traceback.log" , "a" )
 OOo0 . write ( "---------- Exception occurred: {} ----------\n" . format ( iIiIIIIIii ) )
 try :
  traceback . print_last ( file = OOo0 )
 except :
  OOo0 . write ( "traceback.print_last(file=fd) failed" )
  if 25 - 25: OoooooooOO + IiII * I1ii11iIi11i
 try :
  traceback . print_last ( )
 except :
  print ( "traceback.print_last() failed" )
  if 92 - 92: I1IiiI + I11i + O0 / o0oOOo0O0Ooo + I1Ii111
 OOo0 . close ( )
 return
 if 18 - 18: ooOoO0o * OoOoOO00 . iII111i / I1ii11iIi11i / i11iIiiIii
 if 21 - 21: oO0o / I1ii11iIi11i + Ii1I + OoooooooOO
 if 91 - 91: i11iIiiIii / i1IIi + iII111i + ooOoO0o * i11iIiiIii
 if 66 - 66: iIii1I11I1II1 % i1IIi - O0 + I11i * I1Ii111 . IiII
 if 52 - 52: ooOoO0o + O0 . iII111i . I1ii11iIi11i . OoO0O00
 if 97 - 97: I1IiiI / iII111i
 if 71 - 71: II111iiii / i1IIi . I1ii11iIi11i % OoooooooOO . OoOoOO00
def lisp_set_exception ( ) :
 sys . excepthook = lisp_record_traceback
 return
 if 41 - 41: i1IIi * II111iiii / OoooooooOO . OOooOOo
 if 83 - 83: iII111i . O0 / Oo0Ooo / OOooOOo - II111iiii
 if 100 - 100: OoO0O00
 if 46 - 46: OoOoOO00 / iIii1I11I1II1 % iII111i . iIii1I11I1II1 * iII111i
 if 38 - 38: I1ii11iIi11i - iII111i / O0 . I1Ii111
 if 45 - 45: I1Ii111
 if 83 - 83: OoOoOO00 . OoooooooOO
def lisp_is_raspbian ( ) :
 if ( distro . linux_distribution ( ) [ 0 ] != "debian" ) : return ( False )
 return ( platform . machine ( ) in [ "armv6l" , "armv7l" ] )
 if 58 - 58: i11iIiiIii + OoooooooOO % OoooooooOO / IiII / i11iIiiIii
 if 62 - 62: OoO0O00 / I1ii11iIi11i
 if 7 - 7: OoooooooOO . IiII
 if 53 - 53: Ii1I % Ii1I * o0oOOo0O0Ooo + OoOoOO00
 if 92 - 92: OoooooooOO + i1IIi / Ii1I * O0
 if 100 - 100: ooOoO0o % iIii1I11I1II1 * II111iiii - iII111i
 if 92 - 92: ooOoO0o
def lisp_is_ubuntu ( ) :
 return ( distro . linux_distribution ( ) [ 0 ] == "Ubuntu" )
 if 22 - 22: Oo0Ooo % iII111i * I1ii11iIi11i / OOooOOo % i11iIiiIii * I11i
 if 95 - 95: OoooooooOO - IiII * I1IiiI + OoOoOO00
 if 10 - 10: o0oOOo0O0Ooo / i11iIiiIii
 if 92 - 92: I11i . I1Ii111
 if 85 - 85: I1ii11iIi11i . I1Ii111
 if 78 - 78: ooOoO0o * I1Ii111 + iIii1I11I1II1 + iIii1I11I1II1 / I1Ii111 . Ii1I
 if 97 - 97: ooOoO0o / I1Ii111 % i1IIi % I1ii11iIi11i
def lisp_is_fedora ( ) :
 return ( distro . linux_distribution ( ) [ 0 ] == "fedora" )
 if 18 - 18: iIii1I11I1II1 % I11i
 if 95 - 95: ooOoO0o + i11iIiiIii * I1Ii111 - i1IIi * I1Ii111 - iIii1I11I1II1
 if 75 - 75: OoooooooOO * IiII
 if 9 - 9: IiII - II111iiii + O0 / iIii1I11I1II1 / i11iIiiIii
 if 39 - 39: IiII * Oo0Ooo + iIii1I11I1II1 - IiII + OOooOOo
 if 69 - 69: O0
 if 85 - 85: ooOoO0o / O0
def lisp_is_centos ( ) :
 return ( distro . linux_distribution ( ) [ 0 ] == "centos" )
 if 18 - 18: o0oOOo0O0Ooo % O0 * I1ii11iIi11i
 if 62 - 62: I1Ii111 . IiII . OoooooooOO
 if 11 - 11: OOooOOo / I11i
 if 73 - 73: i1IIi / i11iIiiIii
 if 58 - 58: Oo0Ooo . II111iiii + oO0o - i11iIiiIii / II111iiii / O0
 if 85 - 85: OoOoOO00 + OOooOOo
 if 10 - 10: IiII / OoO0O00 + OoOoOO00 / i1IIi
def lisp_is_debian ( ) :
 return ( distro . linux_distribution ( ) [ 0 ] == "debian" )
 if 27 - 27: Ii1I
 if 67 - 67: I1IiiI
 if 55 - 55: I1ii11iIi11i - iII111i * o0oOOo0O0Ooo + OoOoOO00 * OoOoOO00 * O0
 if 91 - 91: I1Ii111 - OOooOOo % iIii1I11I1II1 - OoooooooOO % ooOoO0o
 if 98 - 98: OoO0O00 . OoO0O00 * oO0o * II111iiii * I1Ii111
 if 92 - 92: Oo0Ooo
 if 40 - 40: OoOoOO00 / IiII
def lisp_is_debian_kali ( ) :
 return ( distro . linux_distribution ( ) [ 0 ] == "Kali" )
 if 79 - 79: OoO0O00 - iIii1I11I1II1 + Ii1I - I1Ii111
 if 93 - 93: II111iiii . I1IiiI - Oo0Ooo + OoOoOO00
 if 61 - 61: II111iiii
 if 15 - 15: i11iIiiIii % I1IiiI * I11i / I1Ii111
 if 90 - 90: iII111i
 if 31 - 31: OOooOOo + O0
 if 87 - 87: ooOoO0o
def lisp_is_macos ( ) :
 return ( distro . linux_distribution ( ) [ 0 ] == "Darwin" )
 if 45 - 45: OoO0O00 / OoooooooOO - iII111i / Ii1I % IiII
 if 83 - 83: I1IiiI . iIii1I11I1II1 - IiII * i11iIiiIii
 if 20 - 20: i1IIi * I1Ii111 + II111iiii % o0oOOo0O0Ooo % oO0o
 if 13 - 13: Oo0Ooo
 if 60 - 60: I1ii11iIi11i * I1IiiI
 if 17 - 17: OOooOOo % Oo0Ooo / I1ii11iIi11i . IiII * OOooOOo - II111iiii
 if 41 - 41: Ii1I
def lisp_is_alpine ( ) :
 return ( os . path . exists ( "/etc/alpine-release" ) )
 if 77 - 77: I1Ii111
 if 65 - 65: II111iiii . I1IiiI % oO0o * OoO0O00
 if 38 - 38: OoOoOO00 / iII111i % Oo0Ooo
 if 11 - 11: iII111i - oO0o + II111iiii - iIii1I11I1II1
 if 7 - 7: IiII - I11i / II111iiii * Ii1I . iII111i * iII111i
 if 61 - 61: I11i % ooOoO0o - OoO0O00 / Oo0Ooo
 if 4 - 4: OoooooooOO - i1IIi % Ii1I - OOooOOo * o0oOOo0O0Ooo
def lisp_is_x86 ( ) :
 Ooooo00o0OoO = platform . machine ( )
 return ( Ooooo00o0OoO in ( "x86" , "i686" , "x86_64" ) )
 if 75 - 75: I1IiiI % II111iiii
 if 30 - 30: IiII + I1Ii111 - IiII . IiII - II111iiii + O0
 if 86 - 86: i1IIi
 if 41 - 41: OoOoOO00 * I11i / OoOoOO00 % oO0o
 if 18 - 18: II111iiii . OoooooooOO % OoOoOO00 % Ii1I
 if 9 - 9: OoO0O00 - Oo0Ooo * OoooooooOO . Oo0Ooo
 if 2 - 2: OoooooooOO % OOooOOo
def lisp_is_apple_m ( ) :
 Ooooo00o0OoO = platform . machine ( )
 return ( Ooooo00o0OoO == "aarch64" )
 if 63 - 63: I1IiiI % iIii1I11I1II1
 if 39 - 39: iII111i / II111iiii / I1ii11iIi11i % I1IiiI
 if 89 - 89: I1Ii111 + OoooooooOO + I1Ii111 * i1IIi + iIii1I11I1II1 % I11i
 if 59 - 59: OOooOOo + i11iIiiIii
 if 88 - 88: i11iIiiIii - ooOoO0o
 if 67 - 67: OOooOOo . Oo0Ooo + OoOoOO00 - OoooooooOO
 if 70 - 70: OOooOOo / II111iiii - iIii1I11I1II1 - iII111i
def lisp_is_linux ( ) :
 return ( platform . uname ( ) [ 0 ] == "Linux" )
 if 11 - 11: iIii1I11I1II1 . OoooooooOO . II111iiii / i1IIi - I11i
 if 30 - 30: OoOoOO00
 if 21 - 21: i11iIiiIii / I1Ii111 % OOooOOo * O0 . I11i - iIii1I11I1II1
 if 26 - 26: II111iiii * OoOoOO00
 if 10 - 10: II111iiii . iII111i
 if 32 - 32: Ii1I . IiII . OoooooooOO - OoO0O00 + oO0o
 if 88 - 88: iII111i
def lisp_is_python2 ( ) :
 iiI11I1i1i1iI = sys . version . split ( ) [ 0 ]
 return ( iiI11I1i1i1iI [ 0 : 3 ] == "2.7" )
 if 60 - 60: OoooooooOO % Oo0Ooo + OOooOOo . ooOoO0o * iIii1I11I1II1
 if 93 - 93: OoO0O00
 if 5 - 5: I11i / OOooOOo
 if 77 - 77: ooOoO0o - I1IiiI % I11i - O0
 if 67 - 67: OOooOOo + Oo0Ooo
 if 84 - 84: O0 * OoooooooOO - IiII * IiII
 if 8 - 8: ooOoO0o / i1IIi . oO0o
def lisp_is_python3 ( ) :
 iiI11I1i1i1iI = sys . version . split ( ) [ 0 ]
 return ( iiI11I1i1i1iI [ 0 : 2 ] == "3." )
 if 41 - 41: iII111i + OoO0O00
 if 86 - 86: OoOoOO00 . iIii1I11I1II1 - OoO0O00
 if 56 - 56: O0
 if 61 - 61: o0oOOo0O0Ooo / OOooOOo / Oo0Ooo * O0
 if 23 - 23: oO0o - OOooOOo + I11i
 if 12 - 12: I1IiiI / ooOoO0o % o0oOOo0O0Ooo / i11iIiiIii % OoooooooOO
 if 15 - 15: iIii1I11I1II1 % OoooooooOO - Oo0Ooo * Ii1I + I11i
def lisp_on_aws ( ) :
 i1I1II1iIIi11 = getoutput ( "sudo dmidecode | grep -i amazon" )
 if ( i1I1II1iIIi11 . find ( "command not found" ) != - 1 and lisp_on_docker ( ) ) :
  IiI1iII1II111 = bold ( "AWS check" , False )
  lprint ( "{} - dmidecode not installed in docker container" . format ( IiI1iII1II111 ) )
  if 28 - 28: OoOoOO00 * OoO0O00 . I11i % I11i / I11i * I1Ii111
 return ( i1I1II1iIIi11 . lower ( ) . find ( "amazon" ) != - 1 )
 if 64 - 64: II111iiii - I1IiiI
 if 68 - 68: ooOoO0o - OOooOOo - iIii1I11I1II1 / OoOoOO00 + OOooOOo - OoO0O00
 if 75 - 75: iII111i / o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO % OoooooooOO % II111iiii
 if 26 - 26: II111iiii % i11iIiiIii % iIii1I11I1II1 % I11i * I11i * I1ii11iIi11i
 if 24 - 24: II111iiii % I1Ii111 - ooOoO0o + I1IiiI * I1ii11iIi11i
 if 2 - 2: Ii1I - IiII
 if 83 - 83: oO0o % o0oOOo0O0Ooo % Ii1I - II111iiii * OOooOOo / OoooooooOO
def lisp_on_gcp ( ) :
 i1I1II1iIIi11 = getoutput ( "sudo dmidecode -s bios-version" )
 if ( i1I1II1iIIi11 . find ( "command not found" ) != - 1 and lisp_on_docker ( ) ) :
  IiI1iII1II111 = bold ( "GCP check" , False )
  lprint ( "{} - dmidecode not installed in docker container" . format ( IiI1iII1II111 ) )
  if 18 - 18: OoO0O00 + iIii1I11I1II1 - II111iiii - I1IiiI
 return ( i1I1II1iIIi11 . lower ( ) . find ( "google" ) != - 1 )
 if 71 - 71: OoooooooOO
 if 33 - 33: I1Ii111
 if 62 - 62: I1ii11iIi11i + Ii1I + i1IIi / OoooooooOO
 if 7 - 7: o0oOOo0O0Ooo + i1IIi . I1IiiI / Oo0Ooo
 if 22 - 22: ooOoO0o - ooOoO0o % OOooOOo . I1Ii111 + oO0o
 if 63 - 63: I1IiiI % I1Ii111 * o0oOOo0O0Ooo + I1Ii111 / Oo0Ooo % iII111i
 if 45 - 45: IiII
def lisp_on_docker ( ) :
 return ( os . path . exists ( "/.dockerenv" ) )
 if 20 - 20: OoooooooOO * o0oOOo0O0Ooo * O0 . OOooOOo
 if 78 - 78: iIii1I11I1II1 + I11i - Ii1I * I1Ii111 - OoooooooOO % OoOoOO00
 if 34 - 34: O0
 if 80 - 80: i1IIi - Oo0Ooo / OoO0O00 - i11iIiiIii
 if 68 - 68: oO0o - I1ii11iIi11i % O0 % I1Ii111
 if 11 - 11: O0 / OoO0O00 % OOooOOo + o0oOOo0O0Ooo + iIii1I11I1II1
 if 40 - 40: ooOoO0o - OOooOOo . Ii1I * Oo0Ooo % I1Ii111
 if 56 - 56: i11iIiiIii . o0oOOo0O0Ooo - I1IiiI * I11i
def lisp_process_logfile ( ) :
 oOOoo0 = "./logs/lisp-{}.log" . format ( lisp_log_id )
 if ( os . path . exists ( oOOoo0 ) ) : return
 if 20 - 20: IiII % IiII
 sys . stdout . close ( )
 sys . stdout = open ( oOOoo0 , "a" )
 if 94 - 94: o0oOOo0O0Ooo + O0 / I11i . I1IiiI + OOooOOo . iIii1I11I1II1
 lisp_print_banner ( bold ( "logfile rotation" , False ) )
 return
 if 62 - 62: OoOoOO00 / I1IiiI - I1ii11iIi11i - I1IiiI + i11iIiiIii + i1IIi
 if 23 - 23: iII111i + I11i . OoOoOO00 * I1IiiI + I1ii11iIi11i
 if 18 - 18: IiII * o0oOOo0O0Ooo . IiII / O0
 if 8 - 8: o0oOOo0O0Ooo
 if 4 - 4: I1ii11iIi11i + I1ii11iIi11i * ooOoO0o - OoOoOO00
 if 78 - 78: Ii1I / II111iiii % OoOoOO00
 if 52 - 52: OOooOOo - iII111i * oO0o
 if 17 - 17: OoooooooOO + OOooOOo * I11i * OoOoOO00
def lisp_i_am ( name ) :
 global lisp_log_id , lisp_i_am_itr , lisp_i_am_etr , lisp_i_am_rtr
 global lisp_i_am_mr , lisp_i_am_ms , lisp_i_am_ddt , lisp_i_am_core
 global lisp_hostname
 if 36 - 36: O0 + Oo0Ooo
 lisp_log_id = name
 if ( name == "itr" ) : lisp_i_am_itr = True
 if ( name == "etr" ) : lisp_i_am_etr = True
 if ( name == "rtr" ) : lisp_i_am_rtr = True
 if ( name == "mr" ) : lisp_i_am_mr = True
 if ( name == "ms" ) : lisp_i_am_ms = True
 if ( name == "ddt" ) : lisp_i_am_ddt = True
 if ( name == "core" ) : lisp_i_am_core = True
 if 5 - 5: Oo0Ooo * OoOoOO00
 if 46 - 46: ooOoO0o
 if 33 - 33: iII111i - II111iiii * OoooooooOO - Oo0Ooo - OOooOOo
 if 84 - 84: I1Ii111 + Oo0Ooo - OoOoOO00 * OoOoOO00
 if 61 - 61: OoooooooOO . oO0o . OoooooooOO / Oo0Ooo
 lisp_hostname = socket . gethostname ( )
 o00O = lisp_hostname . find ( "." )
 if ( o00O != - 1 ) : lisp_hostname = lisp_hostname [ 0 : o00O ]
 return
 if 48 - 48: iII111i . i11iIiiIii
 if 5 - 5: oO0o . I1ii11iIi11i . II111iiii . OoooooooOO
 if 96 - 96: i11iIiiIii - OOooOOo % O0 / OoO0O00
 if 100 - 100: iII111i / Ii1I - OoooooooOO % II111iiii - I1IiiI % OoOoOO00
 if 60 - 60: iIii1I11I1II1 + i1IIi
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 . i11iIiiIii - Ii1I
 if 51 - 51: OoOoOO00
 if 14 - 14: IiII % oO0o % Oo0Ooo - i11iIiiIii
 if 53 - 53: Ii1I % Oo0Ooo
def lprint ( * args ) :
 O0ooOo0o0Oo = ( "force" in args )
 if ( lisp_debug_logging == False and O0ooOo0o0Oo == False ) : return
 if 71 - 71: iIii1I11I1II1 - OOooOOo . I1IiiI % OoooooooOO + OOooOOo
 lisp_process_logfile ( )
 iIiIIIIIii = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 iIiIIIIIii = iIiIIIIIii [ : - 3 ]
 print ( "{}: {}:" . format ( iIiIIIIIii , lisp_log_id ) , end = " " )
 if 26 - 26: Oo0Ooo + OOooOOo / OoO0O00 % OoOoOO00 % I1ii11iIi11i + II111iiii
 for i11I1I1iiI in args :
  if ( i11I1I1iiI == "force" ) : continue
  print ( i11I1I1iiI , end = " " )
  if 34 - 34: I11i % ooOoO0o . O0 . iIii1I11I1II1
 print ( )
 if 93 - 93: i1IIi . i11iIiiIii . Oo0Ooo
 try : sys . stdout . flush ( )
 except : pass
 return
 if 99 - 99: I11i - I1Ii111 - oO0o % OoO0O00
 if 21 - 21: II111iiii % I1ii11iIi11i . i1IIi - OoooooooOO
 if 4 - 4: OoooooooOO . ooOoO0o
 if 78 - 78: I1ii11iIi11i + I11i - O0
 if 10 - 10: I1Ii111 % I1IiiI
 if 97 - 97: OoooooooOO - I1Ii111
 if 58 - 58: iIii1I11I1II1 + O0
 if 30 - 30: ooOoO0o % iII111i * OOooOOo - I1ii11iIi11i * Ii1I % ooOoO0o
def fprint ( * args ) :
 iiiiI11ii = args + ( "force" , )
 lprint ( * iiiiI11ii )
 return
 if 96 - 96: iII111i . O0 / iII111i % O0
 if 94 - 94: IiII + I1Ii111 / OOooOOo
 if 91 - 91: I11i / i1IIi * i1IIi
 if 25 - 25: iIii1I11I1II1 . OOooOOo * oO0o - Ii1I
 if 55 - 55: OoOoOO00
 if 63 - 63: IiII * OoOoOO00 * ooOoO0o
 if 92 - 92: I1ii11iIi11i / O0
 if 80 - 80: o0oOOo0O0Ooo - OOooOOo + OoooooooOO
def dprint ( * args ) :
 if ( lisp_data_plane_logging ) : lprint ( * args )
 return
 if 98 - 98: OOooOOo + i1IIi . I1IiiI - II111iiii - o0oOOo0O0Ooo
 if 24 - 24: Oo0Ooo - i1IIi + I11i
 if 38 - 38: OoooooooOO / I1ii11iIi11i . O0 / i1IIi / Oo0Ooo + iIii1I11I1II1
 if 96 - 96: iII111i
 if 18 - 18: iII111i * I11i - Ii1I
 if 31 - 31: Oo0Ooo - O0 % OoOoOO00 % oO0o
 if 45 - 45: I1ii11iIi11i + II111iiii * i11iIiiIii
def cprint ( instance ) :
 print ( "{}:" . format ( instance ) )
 pprint . pprint ( instance . __dict__ )
 if 13 - 13: OoooooooOO * oO0o - Ii1I / OOooOOo + I11i + IiII
 if 39 - 39: iIii1I11I1II1 - OoooooooOO
 if 81 - 81: I1ii11iIi11i - O0 * OoooooooOO
 if 23 - 23: II111iiii / oO0o
 if 28 - 28: Oo0Ooo * ooOoO0o - OoO0O00
 if 19 - 19: I11i
 if 67 - 67: O0 % iIii1I11I1II1 / IiII . i11iIiiIii - Ii1I + O0
 if 27 - 27: OOooOOo
def debug ( * args ) :
 lisp_process_logfile ( )
 if 89 - 89: II111iiii / oO0o
 iIiIIIIIii = datetime . datetime . now ( ) . strftime ( "%m/%d/%y %H:%M:%S.%f" )
 iIiIIIIIii = iIiIIIIIii [ : - 3 ]
 if 14 - 14: OOooOOo . I1IiiI * ooOoO0o + II111iiii - ooOoO0o + OOooOOo
 print ( red ( ">>>" , False ) , end = " " )
 print ( "{}:" . format ( iIiIIIIIii ) , end = " " )
 for i11I1I1iiI in args : print ( i11I1I1iiI , end = " " )
 print ( red ( "<<<\n" , False ) )
 try : sys . stdout . flush ( )
 except : pass
 return
 if 18 - 18: oO0o - o0oOOo0O0Ooo - I1IiiI - I1IiiI
 if 54 - 54: Oo0Ooo + I1IiiI / iII111i . I1IiiI * OoOoOO00
 if 1 - 1: OoOoOO00 * OoO0O00 . i1IIi / Oo0Ooo . I1ii11iIi11i + Oo0Ooo
 if 17 - 17: Oo0Ooo + OoO0O00 / Ii1I / iII111i * OOooOOo
 if 29 - 29: OoO0O00 % OoooooooOO * oO0o / II111iiii - oO0o
 if 19 - 19: i11iIiiIii
 if 54 - 54: II111iiii . I11i
def lisp_print_caller ( ) :
 fprint ( traceback . print_last ( ) )
 if 73 - 73: OoOoOO00 . I1IiiI
 if 32 - 32: OoOoOO00 * I1IiiI % ooOoO0o * Ii1I . O0
 if 48 - 48: iII111i * iII111i
 if 13 - 13: Ii1I / I11i + OoOoOO00 . o0oOOo0O0Ooo % ooOoO0o
 if 48 - 48: I1IiiI / i11iIiiIii - o0oOOo0O0Ooo * oO0o / OoooooooOO
 if 89 - 89: iIii1I11I1II1 / I1IiiI - II111iiii / Ii1I . i11iIiiIii . Ii1I
 if 48 - 48: O0 + O0 . I1Ii111 - ooOoO0o
def lisp_print_banner ( string ) :
 global lisp_version , lisp_hostname
 if 63 - 63: oO0o
 if ( lisp_version == "" ) :
  lisp_version = getoutput ( "cat lisp-version.txt" )
  if 71 - 71: i1IIi . Ii1I * iII111i % OoooooooOO + OOooOOo
 iIIi1iiI1i11 = bold ( lisp_hostname , False )
 lprint ( "lispers.net LISP {} {}, version {}, hostname {}" . format ( string ,
 datetime . datetime . now ( ) , lisp_version , iIIi1iiI1i11 ) )
 return
 if 56 - 56: OoooooooOO
 if 30 - 30: i11iIiiIii + oO0o
 if 38 - 38: IiII . Ii1I
 if 24 - 24: o0oOOo0O0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI - oO0o
 if 12 - 12: iII111i . IiII . OoOoOO00 / O0
 if 58 - 58: o0oOOo0O0Ooo - II111iiii % oO0o + I1Ii111 . OoOoOO00 / IiII
 if 8 - 8: I1ii11iIi11i . OoO0O00 * I11i + II111iiii % i11iIiiIii
def green ( string , html ) :
 if ( html ) : return ( '<font color="green"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[92m" + string + "\033[0m" , html ) )
 if 8 - 8: ooOoO0o * O0
 if 73 - 73: o0oOOo0O0Ooo / oO0o / I11i / OoO0O00
 if 11 - 11: OoOoOO00 + IiII - OoooooooOO / OoO0O00
 if 34 - 34: ooOoO0o
 if 45 - 45: ooOoO0o / Oo0Ooo / Ii1I
 if 44 - 44: I1ii11iIi11i - Ii1I / II111iiii * OoO0O00 * Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo - I1IiiI * i1IIi / i11iIiiIii * OOooOOo % II111iiii
def green_last_sec ( string ) :
 return ( green ( string , True ) )
 if 56 - 56: OoooooooOO * Oo0Ooo . Oo0Ooo . I1ii11iIi11i
 if 24 - 24: Oo0Ooo . I11i * Ii1I % iII111i / OOooOOo
 if 58 - 58: I1IiiI - I1ii11iIi11i % O0 . I1IiiI % OoO0O00 % IiII
 if 87 - 87: oO0o - i11iIiiIii
 if 78 - 78: i11iIiiIii / iIii1I11I1II1 - o0oOOo0O0Ooo
 if 23 - 23: I11i
 if 40 - 40: o0oOOo0O0Ooo - II111iiii / Oo0Ooo
def green_last_min ( string ) :
 return ( '<font color="#58D68D"><b>{}</b></font>' . format ( string ) )
 if 14 - 14: I1ii11iIi11i
 if 5 - 5: o0oOOo0O0Ooo . iIii1I11I1II1 % iIii1I11I1II1
 if 56 - 56: OoooooooOO - I11i - i1IIi
 if 8 - 8: I1Ii111 / OOooOOo . I1IiiI + I1ii11iIi11i / i11iIiiIii
 if 31 - 31: ooOoO0o - iIii1I11I1II1 + iII111i . Oo0Ooo / IiII % iIii1I11I1II1
 if 6 - 6: IiII * i11iIiiIii % iIii1I11I1II1 % i11iIiiIii + o0oOOo0O0Ooo / i1IIi
 if 53 - 53: I11i + iIii1I11I1II1
def red ( string , html ) :
 if ( html ) : return ( '<font color="red"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[91m" + string + "\033[0m" , html ) )
 if 70 - 70: I1ii11iIi11i
 if 67 - 67: OoooooooOO
 if 29 - 29: O0 - i11iIiiIii - II111iiii + OOooOOo * IiII
 if 2 - 2: i1IIi - ooOoO0o + I1IiiI . o0oOOo0O0Ooo * o0oOOo0O0Ooo / OoOoOO00
 if 93 - 93: i1IIi
 if 53 - 53: OoooooooOO + Oo0Ooo + oO0o
 if 24 - 24: iII111i - IiII - iII111i * I1ii11iIi11i . OoooooooOO / IiII
def blue ( string , html ) :
 if ( html ) : return ( '<font color="blue"><b>{}</b></font>' . format ( string ) )
 return ( bold ( "\033[94m" + string + "\033[0m" , html ) )
 if 66 - 66: Oo0Ooo
 if 97 - 97: i1IIi - OoooooooOO / I1Ii111 * I1IiiI
 if 55 - 55: o0oOOo0O0Ooo . iII111i
 if 87 - 87: o0oOOo0O0Ooo % iIii1I11I1II1
 if 100 - 100: I1Ii111 . I1IiiI * I1Ii111 - I1IiiI . I11i * Ii1I
 if 89 - 89: OoO0O00 + IiII * I1Ii111
 if 28 - 28: OoooooooOO . oO0o % I1ii11iIi11i / i1IIi / OOooOOo
def bold ( string , html ) :
 if ( html ) : return ( "<b>{}</b>" . format ( string ) )
 return ( "\033[1m" + string + "\033[0m" )
 if 36 - 36: o0oOOo0O0Ooo + I11i - IiII + iIii1I11I1II1 + OoooooooOO
 if 4 - 4: II111iiii . I11i + Ii1I * I1Ii111 . ooOoO0o
 if 87 - 87: OoOoOO00 / OoO0O00 / i11iIiiIii
 if 74 - 74: oO0o / I1ii11iIi11i % o0oOOo0O0Ooo
 if 88 - 88: OoOoOO00 - i11iIiiIii % o0oOOo0O0Ooo * I11i + I1ii11iIi11i
 if 52 - 52: II111iiii . I1IiiI + OoOoOO00 % OoO0O00
 if 62 - 62: o0oOOo0O0Ooo
def convert_font ( string ) :
 I1i111i = [ [ "[91m" , red ] , [ "[92m" , green ] , [ "[94m" , blue ] , [ "[1m" , bold ] ]
 iI1i = "[0m"
 if 46 - 46: I1Ii111 % Ii1I
 for oOO in I1i111i :
  oO0OO00OOo0 = oOO [ 0 ]
  Ii1IIii = oOO [ 1 ]
  II1Ii = len ( oO0OO00OOo0 )
  o00O = string . find ( oO0OO00OOo0 )
  if ( o00O != - 1 ) : break
  if 89 - 89: OoOoOO00 - OoO0O00
  if 8 - 8: o0oOOo0O0Ooo / I1ii11iIi11i - i11iIiiIii % iIii1I11I1II1
 while ( o00O != - 1 ) :
  o00o0oOo0O0O = string [ o00O : : ] . find ( iI1i )
  oO0ooOO = string [ o00O + II1Ii : o00O + o00o0oOo0O0O ]
  string = string [ : o00O ] + Ii1IIii ( oO0ooOO , True ) + string [ o00O + o00o0oOo0O0O + II1Ii : : ]
  if 7 - 7: II111iiii - OOooOOo . II111iiii
  o00O = string . find ( oO0OO00OOo0 )
  if 53 - 53: oO0o % I11i . ooOoO0o - OoOoOO00
  if 69 - 69: II111iiii * I1IiiI - ooOoO0o - iIii1I11I1II1 + o0oOOo0O0Ooo - oO0o
  if 50 - 50: I11i - ooOoO0o
  if 1 - 1: oO0o
  if 12 - 12: ooOoO0o % I1IiiI + oO0o - i1IIi . Ii1I / I1IiiI
 if ( string . find ( "[1m" ) != - 1 ) : string = convert_font ( string )
 return ( string )
 if 51 - 51: OOooOOo . I1IiiI
 if 73 - 73: OoooooooOO . I1IiiI / I1Ii111 % Ii1I
 if 65 - 65: IiII - I1IiiI - Ii1I
 if 42 - 42: II111iiii * I1IiiI % i1IIi - Ii1I % IiII
 if 36 - 36: i11iIiiIii / oO0o * I1ii11iIi11i * I1ii11iIi11i + Ii1I * I11i
 if 32 - 32: OoO0O00
 if 50 - 50: ooOoO0o + i1IIi
def lisp_space ( num ) :
 i11IiIIi11I = ""
 for o000o0O0Oo00 in range ( num ) : i11IiIIi11I += "&#160;"
 return ( i11IiIIi11I )
 if 60 - 60: OoOoOO00
 if 5 - 5: I1IiiI - I1IiiI - I1IiiI * OoooooooOO
 if 28 - 28: iIii1I11I1II1 + iIii1I11I1II1
 if 28 - 28: oO0o
 if 52 - 52: I1IiiI + iIii1I11I1II1
 if 71 - 71: O0 / oO0o
 if 34 - 34: OoOoOO00 . iIii1I11I1II1 % O0
def lisp_button ( string , url ) :
 iI11Ii111 = '<button style="background-color:transparent;border-radius:10px; ' + 'type="button">'
 if 54 - 54: OoOoOO00 % iII111i . OoOoOO00 * OOooOOo + OoOoOO00 % i1IIi
 if 23 - 23: I1Ii111 - OOooOOo + Ii1I - OoOoOO00 * OoOoOO00 . Oo0Ooo
 if ( url == None ) :
  iIii11iI1II = iI11Ii111 + string + "</button>"
 else :
  I1II1I1I = '<a href="{}">' . format ( url )
  OOo0oOO0o0oo0 = lisp_space ( 2 )
  iIii11iI1II = OOo0oOO0o0oo0 + I1II1I1I + iI11Ii111 + string + "</button></a>" + OOo0oOO0o0oo0
  if 78 - 78: OOooOOo + iII111i . IiII
 return ( iIii11iI1II )
 if 91 - 91: iIii1I11I1II1 . o0oOOo0O0Ooo . I1ii11iIi11i + OoooooooOO
 if 69 - 69: I1Ii111 - I1IiiI
 if 95 - 95: I1IiiI * i11iIiiIii . ooOoO0o
 if 41 - 41: II111iiii
 if 37 - 37: I11i . Oo0Ooo % IiII * i1IIi
 if 71 - 71: Oo0Ooo / o0oOOo0O0Ooo + OOooOOo
 if 48 - 48: I1Ii111 + iII111i
def lisp_print_cour ( string ) :
 i11IiIIi11I = '<font face="Courier New">{}</font>' . format ( string )
 return ( i11IiIIi11I )
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii . OoOoOO00 % ooOoO0o + oO0o . OoO0O00
 if 46 - 46: OoO0O00 - o0oOOo0O0Ooo / OoOoOO00 - OoooooooOO + oO0o
 if 58 - 58: o0oOOo0O0Ooo / o0oOOo0O0Ooo + ooOoO0o + I11i - OoOoOO00 . OOooOOo
 if 15 - 15: ooOoO0o * OoOoOO00 % IiII . OoOoOO00 . I11i
 if 97 - 97: oO0o
 if 80 - 80: I1IiiI . Ii1I
 if 47 - 47: I11i + ooOoO0o + II111iiii % i11iIiiIii
def lisp_print_sans ( string ) :
 i11IiIIi11I = '<font face="Sans-Serif">{}</font>' . format ( string )
 return ( i11IiIIi11I )
 if 93 - 93: I1ii11iIi11i % OoOoOO00 . O0 / iII111i * oO0o
 if 29 - 29: o0oOOo0O0Ooo
 if 86 - 86: II111iiii . IiII
 if 2 - 2: OoooooooOO
 if 60 - 60: OoO0O00
 if 81 - 81: OoOoOO00 % Ii1I
 if 87 - 87: iIii1I11I1II1 . OoooooooOO * OoOoOO00
def lisp_span ( string , hover_string ) :
 i11IiIIi11I = '<span title="{}">{}</span>' . format ( hover_string , string )
 return ( i11IiIIi11I )
 if 100 - 100: OoO0O00 / i1IIi - I1IiiI % Ii1I - iIii1I11I1II1
 if 17 - 17: I11i / o0oOOo0O0Ooo % Oo0Ooo
 if 71 - 71: IiII . I1Ii111 . OoO0O00
 if 68 - 68: i11iIiiIii % oO0o * OoO0O00 * IiII * II111iiii + O0
 if 66 - 66: I11i % I1ii11iIi11i % OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / iII111i % O0 . OoO0O00 . i1IIi
 if 29 - 29: O0 . I1Ii111
def lisp_eid_help_hover ( output ) :
 OO0o0oO0O000o = '''Unicast EID format:
  For longest match lookups:
    <address> or [<iid>]<address>
  For exact match lookups:
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''
 if 47 - 47: I1Ii111 - OoO0O00 / Ii1I * OoooooooOO / Ii1I . Oo0Ooo
 if 34 - 34: ooOoO0o
 i1IiIi1 = lisp_span ( output , OO0o0oO0O000o )
 return ( i1IiIi1 )
 if 22 - 22: I11i * O0 . II111iiii - OoO0O00
 if 90 - 90: oO0o
 if 94 - 94: I11i / I1ii11iIi11i * I1Ii111 - OoOoOO00
 if 44 - 44: Ii1I % i11iIiiIii - iII111i * I1ii11iIi11i + Oo0Ooo * OOooOOo
 if 41 - 41: O0 * ooOoO0o - OoOoOO00 . Ii1I
 if 65 - 65: Oo0Ooo . OoooooooOO
 if 70 - 70: Oo0Ooo - oO0o . iIii1I11I1II1 % I11i / OoOoOO00 - O0
def lisp_geo_help_hover ( output ) :
 OO0o0oO0O000o = '''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''
 if 55 - 55: iII111i - OoO0O00
 if 100 - 100: O0
 i1IiIi1 = lisp_span ( output , OO0o0oO0O000o )
 return ( i1IiIi1 )
 if 79 - 79: iIii1I11I1II1
 if 81 - 81: OOooOOo + iIii1I11I1II1 * I1Ii111 - iIii1I11I1II1 . OOooOOo
 if 48 - 48: I11i . OoooooooOO . I1IiiI . OoOoOO00 % I1ii11iIi11i / iII111i
 if 11 - 11: i1IIi % OoO0O00 % iII111i
 if 99 - 99: ooOoO0o / iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I1IiiI
 if 13 - 13: OoO0O00
 if 70 - 70: I1Ii111 + O0 . oO0o * Ii1I
def space ( num ) :
 i11IiIIi11I = ""
 for o000o0O0Oo00 in range ( num ) : i11IiIIi11I += "&#160;"
 return ( i11IiIIi11I )
 if 2 - 2: OoooooooOO . OOooOOo . IiII
 if 42 - 42: OOooOOo % oO0o / OoO0O00 - oO0o * i11iIiiIii
 if 19 - 19: oO0o * I1IiiI % i11iIiiIii
 if 24 - 24: o0oOOo0O0Ooo
 if 10 - 10: o0oOOo0O0Ooo % Ii1I / OOooOOo
 if 28 - 28: OOooOOo % ooOoO0o
 if 48 - 48: i11iIiiIii % oO0o
 if 29 - 29: iII111i + i11iIiiIii % I11i
def lisp_get_ephemeral_port ( ) :
 return ( random . randrange ( 32768 , 65535 ) )
 if 93 - 93: OoOoOO00 % iIii1I11I1II1
 if 90 - 90: I1IiiI - OOooOOo / Ii1I / O0 / I11i
 if 87 - 87: OoOoOO00 / IiII + iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 + oO0o % ooOoO0o
 if 21 - 21: OOooOOo
 if 6 - 6: IiII
 if 46 - 46: IiII + oO0o
def lisp_get_data_nonce ( ) :
 return ( random . randint ( 0 , 0xffffff ) )
 if 79 - 79: OoooooooOO - IiII * IiII . OoOoOO00
 if 100 - 100: II111iiii * I11i % I1IiiI / I1ii11iIi11i
 if 90 - 90: I1ii11iIi11i . ooOoO0o . OoOoOO00 . Ii1I
 if 4 - 4: Ii1I + OoOoOO00 % I1ii11iIi11i / i11iIiiIii
 if 74 - 74: II111iiii . O0 - I1IiiI + IiII % i11iIiiIii % OoOoOO00
 if 78 - 78: Ii1I + OoOoOO00 + IiII - IiII . i11iIiiIii / OoO0O00
 if 27 - 27: Ii1I - O0 % I11i * I1Ii111 . IiII % iIii1I11I1II1
def lisp_get_control_nonce ( ) :
 return ( random . randint ( 0 , ( 2 ** 64 ) - 1 ) )
 if 37 - 37: OoooooooOO + O0 - i1IIi % ooOoO0o
 if 24 - 24: OoOoOO00
 if 94 - 94: i1IIi * i1IIi % II111iiii + OOooOOo
 if 28 - 28: I1IiiI
 if 49 - 49: I11i . o0oOOo0O0Ooo % oO0o / Ii1I
 if 95 - 95: O0 * OoOoOO00 * IiII . ooOoO0o / iIii1I11I1II1
 if 28 - 28: IiII + oO0o - ooOoO0o / iIii1I11I1II1 - I1IiiI
 if 45 - 45: O0 / i1IIi * oO0o * OoO0O00
 if 35 - 35: I1ii11iIi11i / iII111i % I1IiiI + iIii1I11I1II1
def lisp_hex_string ( integer_value ) :
 oO00o = hex ( integer_value ) [ 2 : : ]
 if ( oO00o [ - 1 ] == "L" ) : oO00o = oO00o [ 0 : - 1 ]
 return ( oO00o )
 if 36 - 36: I1Ii111 . II111iiii % ooOoO0o
 if 84 - 84: OoooooooOO - i11iIiiIii / iIii1I11I1II1 / OoooooooOO / I1ii11iIi11i
 if 4 - 4: Oo0Ooo + o0oOOo0O0Ooo
 if 17 - 17: OoO0O00 * OoOoOO00
 if 15 - 15: i11iIiiIii / ooOoO0o % I1IiiI
 if 71 - 71: I1Ii111 / I1ii11iIi11i * iIii1I11I1II1
 if 57 - 57: OOooOOo + I1Ii111 % I1ii11iIi11i . OoO0O00 / OoO0O00 * O0
def lisp_get_timestamp ( ) :
 return ( time . time ( ) )
 if 6 - 6: i1IIi - II111iiii * o0oOOo0O0Ooo . OoO0O00
lisp_uptime = lisp_get_timestamp ( )
if 68 - 68: o0oOOo0O0Ooo
if 20 - 20: I1Ii111 - I1Ii111
if 37 - 37: IiII
if 37 - 37: Oo0Ooo / IiII * O0
if 73 - 73: iII111i * iII111i / ooOoO0o
if 43 - 43: I1ii11iIi11i . i1IIi . IiII + O0 * Ii1I * O0
def lisp_set_timestamp ( seconds ) :
 return ( time . time ( ) + seconds )
 if 41 - 41: I1ii11iIi11i + Ii1I % OoooooooOO . I1ii11iIi11i + iII111i . iII111i
 if 31 - 31: i11iIiiIii + II111iiii . iII111i * OoOoOO00
 if 66 - 66: OoOoOO00 + i1IIi % II111iiii . O0 * I1ii11iIi11i % I1ii11iIi11i
 if 87 - 87: OOooOOo + o0oOOo0O0Ooo . iII111i - OoooooooOO
 if 6 - 6: iIii1I11I1II1 * OoooooooOO
 if 28 - 28: Oo0Ooo * o0oOOo0O0Ooo / I1Ii111
 if 52 - 52: O0 / o0oOOo0O0Ooo % iII111i * I1IiiI % OOooOOo
def lisp_print_elapsed ( ts ) :
 if ( ts == 0 or ts == None ) : return ( "never" )
 o0oOOOO0 = time . time ( ) - ts
 o0oOOOO0 = round ( o0oOOOO0 , 0 )
 return ( str ( datetime . timedelta ( seconds = o0oOOOO0 ) ) )
 if 11 - 11: i1IIi
 if 19 - 19: iII111i - o0oOOo0O0Ooo - Ii1I - OoOoOO00 . iII111i . I1Ii111
 if 48 - 48: iII111i + IiII
 if 60 - 60: I11i + iII111i . IiII / i1IIi . iIii1I11I1II1
 if 14 - 14: OOooOOo
 if 79 - 79: Ii1I
 if 76 - 76: iIii1I11I1II1
def lisp_print_future ( ts ) :
 if ( ts == 0 ) : return ( "never" )
 Oo = ts - time . time ( )
 if ( Oo < 0 ) : return ( "expired" )
 Oo = round ( Oo , 0 )
 return ( str ( datetime . timedelta ( seconds = Oo ) ) )
 if 26 - 26: OOooOOo
 if 76 - 76: i1IIi * OoooooooOO * O0 + I1Ii111 * I1Ii111
 if 35 - 35: o0oOOo0O0Ooo
 if 73 - 73: O0 - I1ii11iIi11i
 if 2 - 2: II111iiii / I1Ii111
 if 54 - 54: i1IIi . I11i - I1ii11iIi11i + ooOoO0o + Oo0Ooo / Oo0Ooo
 if 22 - 22: ooOoO0o . iIii1I11I1II1
 if 12 - 12: Ii1I
 if 71 - 71: I1IiiI . II111iiii . I1IiiI - ooOoO0o
 if 45 - 45: IiII / O0 / OoOoOO00 * OOooOOo
 if 18 - 18: iIii1I11I1II1 + OOooOOo + iIii1I11I1II1 . I1ii11iIi11i + I1Ii111 . ooOoO0o
 if 7 - 7: I1ii11iIi11i + iIii1I11I1II1 * I11i * I11i / II111iiii - Ii1I
 if 65 - 65: oO0o + OoOoOO00 + II111iiii
def lisp_print_eid_tuple ( eid , group ) :
 oOOoo = eid . print_prefix ( )
 if ( group . is_null ( ) ) : return ( oOOoo )
 if 6 - 6: OOooOOo
 ooOoo000oO = group . print_prefix ( )
 i1I1iI = group . instance_id
 if 92 - 92: Oo0Ooo / i11iIiiIii + I1ii11iIi11i
 if ( eid . is_null ( ) or eid . is_exact_match ( group ) ) :
  o00O = ooOoo000oO . find ( "]" ) + 1
  return ( "[{}](*, {})" . format ( i1I1iI , ooOoo000oO [ o00O : : ] ) )
  if 87 - 87: OoOoOO00 % iIii1I11I1II1
  if 72 - 72: OOooOOo . OOooOOo - I1ii11iIi11i
 III1II1i = eid . print_sg ( group )
 return ( III1II1i )
 if 3 - 3: iII111i
 if 35 - 35: IiII . O0 + Oo0Ooo + OOooOOo + i1IIi
 if 65 - 65: O0 * I1IiiI / I1IiiI . OoOoOO00
 if 87 - 87: II111iiii * I1ii11iIi11i % Oo0Ooo * Oo0Ooo
 if 58 - 58: OOooOOo . o0oOOo0O0Ooo + I1IiiI % Oo0Ooo - OoO0O00
 if 50 - 50: iII111i % II111iiii - ooOoO0o . i1IIi + O0 % iII111i
 if 10 - 10: iII111i . i1IIi + Ii1I
 if 66 - 66: OoO0O00 % o0oOOo0O0Ooo
def lisp_convert_6to4 ( addr_str ) :
 if ( addr_str . find ( "::ffff:" ) == - 1 ) : return ( addr_str )
 iI1ii11Ii = addr_str . split ( ":" )
 return ( iI1ii11Ii [ - 1 ] )
 if 97 - 97: I1Ii111 + oO0o - OoO0O00 % oO0o - o0oOOo0O0Ooo
 if 37 - 37: OoooooooOO
 if 69 - 69: I1IiiI + iII111i
 if 7 - 7: iII111i + oO0o
 if 26 - 26: iIii1I11I1II1 + i1IIi / OoOoOO00 % I1ii11iIi11i
 if 44 - 44: OoooooooOO . II111iiii . OOooOOo % OoooooooOO
 if 86 - 86: i11iIiiIii + O0 * IiII - OoO0O00 * OOooOOo + O0
 if 95 - 95: iIii1I11I1II1 . I1Ii111 % iII111i - I1Ii111 * II111iiii
 if 89 - 89: iII111i . I1IiiI
 if 59 - 59: i1IIi % iIii1I11I1II1 + OoooooooOO
 if 97 - 97: I1ii11iIi11i / Oo0Ooo + I1Ii111
def lisp_convert_4to6 ( addr_str ) :
 iI1ii11Ii = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 if ( iI1ii11Ii . is_ipv4_string ( addr_str ) ) : addr_str = "::ffff:" + addr_str
 iI1ii11Ii . store_address ( addr_str )
 return ( iI1ii11Ii )
 if 32 - 32: ooOoO0o % I1Ii111 * Oo0Ooo
 if 72 - 72: ooOoO0o . iII111i - I1Ii111 - Ii1I % i1IIi
 if 56 - 56: Oo0Ooo * iII111i
 if 13 - 13: Oo0Ooo * Oo0Ooo * II111iiii * iII111i . i1IIi / IiII
 if 92 - 92: Ii1I * i11iIiiIii + iII111i * I1Ii111
 if 48 - 48: I11i * iII111i * iII111i
 if 70 - 70: oO0o + I11i % i11iIiiIii + O0
 if 65 - 65: iIii1I11I1II1 % oO0o + O0 / OoooooooOO
 if 52 - 52: Ii1I % OOooOOo * I1IiiI % I11i + OOooOOo / iII111i
def lisp_gethostbyname ( string ) :
 oo000o = string . split ( "." )
 OO00o0oOO = string . split ( ":" )
 i1i1I1 = string . split ( "-" )
 if 46 - 46: I11i . IiII / II111iiii % iIii1I11I1II1 + IiII
 if ( len ( oo000o ) == 4 ) :
  if ( oo000o [ 0 ] . isdigit ( ) and oo000o [ 1 ] . isdigit ( ) and oo000o [ 2 ] . isdigit ( ) and
 oo000o [ 3 ] . isdigit ( ) ) : return ( string )
  if 61 - 61: OOooOOo / OoO0O00 + II111iiii . oO0o / Oo0Ooo * OOooOOo
 if ( len ( OO00o0oOO ) > 1 ) :
  try :
   int ( OO00o0oOO [ 0 ] , 16 )
   return ( string )
  except :
   pass
   if 46 - 46: iIii1I11I1II1
   if 33 - 33: I11i % I11i % O0 / I1IiiI . i1IIi
   if 91 - 91: ooOoO0o * I11i - II111iiii . I1IiiI - Oo0Ooo + ooOoO0o
   if 56 - 56: o0oOOo0O0Ooo / IiII * I1IiiI . o0oOOo0O0Ooo
   if 15 - 15: i11iIiiIii
   if 13 - 13: I11i * II111iiii * oO0o * II111iiii % IiII / I1IiiI
   if 100 - 100: IiII . Ii1I - iIii1I11I1II1 . i11iIiiIii / II111iiii
 if ( len ( i1i1I1 ) == 3 ) :
  for o000o0O0Oo00 in range ( 3 ) :
   try : int ( i1i1I1 [ o000o0O0Oo00 ] , 16 )
   except : break
   if 71 - 71: I1Ii111 * Oo0Ooo . I11i
   if 49 - 49: IiII * O0 . IiII
   if 19 - 19: II111iiii - IiII
 try :
  iI1ii11Ii = socket . gethostbyname ( string )
  return ( iI1ii11Ii )
 except :
  if ( lisp_is_alpine ( ) == False ) : return ( "" )
  if 59 - 59: o0oOOo0O0Ooo * OoO0O00 - Ii1I . OOooOOo
  if 89 - 89: OOooOOo
  if 69 - 69: ooOoO0o - OoooooooOO * O0
  if 84 - 84: ooOoO0o + i11iIiiIii - OOooOOo * ooOoO0o
  if 33 - 33: ooOoO0o % i1IIi - oO0o . O0 / O0
 try :
  iI1ii11Ii = socket . getaddrinfo ( string , 0 ) [ 0 ]
  if ( iI1ii11Ii [ 3 ] != string ) : return ( "" )
  iI1ii11Ii = iI1ii11Ii [ 4 ] [ 0 ]
 except :
  iI1ii11Ii = ""
  if 96 - 96: OoooooooOO + IiII * O0
 return ( iI1ii11Ii )
 if 86 - 86: Ii1I
 if 29 - 29: iIii1I11I1II1 - OoO0O00 + I1IiiI % iIii1I11I1II1 % OOooOOo
 if 84 - 84: IiII + I1ii11iIi11i + Ii1I + iII111i
 if 62 - 62: i11iIiiIii + OoOoOO00 + i1IIi
 if 69 - 69: OoOoOO00
 if 63 - 63: OoO0O00 / OoOoOO00 * iIii1I11I1II1 . I1Ii111
 if 85 - 85: i11iIiiIii / i11iIiiIii . OoO0O00 . O0
 if 67 - 67: II111iiii / o0oOOo0O0Ooo . OOooOOo . OoooooooOO
def lisp_ip_checksum ( data , hdrlen = 20 ) :
 if ( len ( data ) < hdrlen ) :
  lprint ( "IPv4 packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 19 - 19: IiII . I1ii11iIi11i / OoOoOO00
  if 68 - 68: ooOoO0o / OoooooooOO * I11i / oO0o
 ooooO000 = binascii . hexlify ( data )
 if 61 - 61: ooOoO0o - OOooOOo + OOooOOo
 if 40 - 40: i11iIiiIii . iIii1I11I1II1
 if 2 - 2: i1IIi * oO0o - oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
 if 3 - 3: OoooooooOO
 O0OoO0o = 0
 for o000o0O0Oo00 in range ( 0 , hdrlen * 2 , 4 ) :
  O0OoO0o += int ( ooooO000 [ o000o0O0Oo00 : o000o0O0Oo00 + 4 ] , 16 )
  if 1 - 1: ooOoO0o % I11i * I1ii11iIi11i - II111iiii
  if 49 - 49: oO0o - iII111i % OoOoOO00
  if 72 - 72: I1IiiI + IiII . OoOoOO00 + OoOoOO00
  if 94 - 94: i11iIiiIii % OoooooooOO / I1IiiI
  if 24 - 24: I1IiiI * oO0o
 O0OoO0o = ( O0OoO0o >> 16 ) + ( O0OoO0o & 0xffff )
 O0OoO0o += O0OoO0o >> 16
 O0OoO0o = socket . htons ( ~ O0OoO0o & 0xffff )
 if 85 - 85: II111iiii . ooOoO0o % OOooOOo % I11i
 if 80 - 80: oO0o * I11i / iIii1I11I1II1 % oO0o / iIii1I11I1II1
 if 42 - 42: i1IIi / i11iIiiIii . Oo0Ooo * iII111i . i11iIiiIii * O0
 if 44 - 44: i1IIi . I1IiiI / i11iIiiIii + IiII
 O0OoO0o = struct . pack ( "H" , O0OoO0o )
 ooooO000 = data [ 0 : 10 ] + O0OoO0o + data [ 12 : : ]
 return ( ooooO000 )
 if 27 - 27: OOooOOo
 if 52 - 52: I1Ii111 % OoOoOO00 + iIii1I11I1II1 * oO0o . Ii1I
 if 95 - 95: iIii1I11I1II1 . IiII - OoooooooOO * OoO0O00 / o0oOOo0O0Ooo
 if 74 - 74: oO0o
 if 34 - 34: iII111i
 if 44 - 44: i1IIi % I1IiiI % o0oOOo0O0Ooo
 if 9 - 9: Oo0Ooo % OoooooooOO - Ii1I
 if 43 - 43: OoO0O00 % OoO0O00
def lisp_icmp_checksum ( data ) :
 if ( len ( data ) < 36 ) :
  lprint ( "ICMP packet too short, length {}" . format ( len ( data ) ) )
  return ( data )
  if 46 - 46: Oo0Ooo % iIii1I11I1II1 . iII111i . O0 * ooOoO0o / OoooooooOO
  if 7 - 7: oO0o - O0 * I11i - o0oOOo0O0Ooo - II111iiii
 Ii11iiI1 = binascii . hexlify ( data )
 if 71 - 71: o0oOOo0O0Ooo / OOooOOo % OOooOOo
 if 89 - 89: OoooooooOO + i11iIiiIii / I11i + iIii1I11I1II1 % ooOoO0o
 if 29 - 29: I1ii11iIi11i
 if 53 - 53: i11iIiiIii . I1ii11iIi11i % Ii1I / ooOoO0o % iIii1I11I1II1
 O0OoO0o = 0
 for o000o0O0Oo00 in range ( 0 , 36 , 4 ) :
  O0OoO0o += int ( Ii11iiI1 [ o000o0O0Oo00 : o000o0O0Oo00 + 4 ] , 16 )
  if 6 - 6: Oo0Ooo - OOooOOo . iIii1I11I1II1
  if 30 - 30: ooOoO0o + ooOoO0o % IiII - o0oOOo0O0Ooo - I1ii11iIi11i
  if 36 - 36: I11i % OOooOOo
  if 72 - 72: I1IiiI / iII111i - O0 + I11i
  if 83 - 83: O0
 O0OoO0o = ( O0OoO0o >> 16 ) + ( O0OoO0o & 0xffff )
 O0OoO0o += O0OoO0o >> 16
 O0OoO0o = socket . htons ( ~ O0OoO0o & 0xffff )
 if 89 - 89: Oo0Ooo + I1ii11iIi11i - o0oOOo0O0Ooo
 if 40 - 40: OoO0O00 + OoO0O00
 if 94 - 94: iII111i * iIii1I11I1II1 . I11i
 if 13 - 13: iIii1I11I1II1 * OoOoOO00 / I1Ii111 % ooOoO0o + oO0o
 O0OoO0o = struct . pack ( "H" , O0OoO0o )
 Ii11iiI1 = data [ 0 : 2 ] + O0OoO0o + data [ 4 : : ]
 return ( Ii11iiI1 )
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
 if 83 - 83: I1ii11iIi11i * I1ii11iIi11i + OOooOOo
 if 57 - 57: O0 - O0 . I1ii11iIi11i / o0oOOo0O0Ooo / Ii1I
 if 20 - 20: OOooOOo * II111iiii - OoOoOO00 - oO0o * I1Ii111
 if 6 - 6: ooOoO0o + OOooOOo / Oo0Ooo + IiII % II111iiii / OoO0O00
 if 45 - 45: OoooooooOO
 if 9 - 9: I11i . OoO0O00 * i1IIi . OoooooooOO
 if 32 - 32: OoOoOO00 . I1ii11iIi11i % I1IiiI - II111iiii
def lisp_udp_checksum ( source , dest , data ) :
 if 11 - 11: O0 + I1IiiI
 if 80 - 80: oO0o % oO0o % O0 - i11iIiiIii . iII111i / O0
 if 13 - 13: I1IiiI + O0 - I1ii11iIi11i % Oo0Ooo / Ii1I . i1IIi
 if 60 - 60: Oo0Ooo . IiII % I1IiiI - I1Ii111
 OOo0oOO0o0oo0 = lisp_address ( LISP_AFI_IPV6 , source , LISP_IPV6_HOST_MASK_LEN , 0 )
 oooOo = lisp_address ( LISP_AFI_IPV6 , dest , LISP_IPV6_HOST_MASK_LEN , 0 )
 oOoO0Oo0 = socket . htonl ( len ( data ) )
 i11i11i = socket . htonl ( LISP_UDP_PROTOCOL )
 iiI1iI = OOo0oOO0o0oo0 . pack_address ( )
 iiI1iI += oooOo . pack_address ( )
 iiI1iI += struct . pack ( "II" , oOoO0Oo0 , i11i11i )
 if 84 - 84: OoooooooOO + I1Ii111 / I1IiiI % OOooOOo % I1ii11iIi11i * I1IiiI
 if 58 - 58: OoO0O00 - OoOoOO00 . i11iIiiIii % i11iIiiIii / i1IIi / oO0o
 if 24 - 24: I1IiiI * i1IIi % ooOoO0o / O0 + i11iIiiIii
 if 12 - 12: I1ii11iIi11i / Ii1I
 ii11 = binascii . hexlify ( iiI1iI + data )
 Ii11 = len ( ii11 ) % 4
 for o000o0O0Oo00 in range ( 0 , Ii11 ) : ii11 += "0"
 if 3 - 3: Ii1I + I1Ii111 . i1IIi / OOooOOo % I1Ii111
 if 98 - 98: IiII * iIii1I11I1II1 . Ii1I * Oo0Ooo / I1ii11iIi11i + ooOoO0o
 if 25 - 25: oO0o
 if 19 - 19: I1IiiI % Ii1I . IiII * ooOoO0o
 O0OoO0o = 0
 for o000o0O0Oo00 in range ( 0 , len ( ii11 ) , 4 ) :
  O0OoO0o += int ( ii11 [ o000o0O0Oo00 : o000o0O0Oo00 + 4 ] , 16 )
  if 89 - 89: OoOoOO00 . OOooOOo
  if 7 - 7: oO0o % OoOoOO00 - I1IiiI + Oo0Ooo
  if 70 - 70: II111iiii + I1Ii111 + i11iIiiIii - i1IIi / IiII
  if 40 - 40: I1ii11iIi11i * I1Ii111
  if 38 - 38: O0 . Oo0Ooo + OoOoOO00 - oO0o
 O0OoO0o = ( O0OoO0o >> 16 ) + ( O0OoO0o & 0xffff )
 O0OoO0o += O0OoO0o >> 16
 O0OoO0o = socket . htons ( ~ O0OoO0o & 0xffff )
 if 43 - 43: iII111i + Oo0Ooo / OoooooooOO
 if 24 - 24: O0 + o0oOOo0O0Ooo * Ii1I - I1Ii111
 if 10 - 10: i11iIiiIii
 if 21 - 21: I1IiiI / iII111i
 O0OoO0o = struct . pack ( "H" , O0OoO0o )
 ii11 = data [ 0 : 6 ] + O0OoO0o + data [ 8 : : ]
 return ( ii11 )
 if 69 - 69: ooOoO0o % ooOoO0o
 if 76 - 76: i11iIiiIii * iII111i / OoO0O00 % I1ii11iIi11i + OOooOOo
 if 48 - 48: iIii1I11I1II1 % i1IIi + OoOoOO00 % o0oOOo0O0Ooo
 if 79 - 79: OoOoOO00 % I1IiiI % Ii1I / i1IIi % OoO0O00
 if 56 - 56: iIii1I11I1II1 - i11iIiiIii * iII111i
 if 84 - 84: OOooOOo + Ii1I + o0oOOo0O0Ooo
 if 33 - 33: Ii1I
 if 93 - 93: ooOoO0o
def lisp_igmp_checksum ( igmp ) :
 II11iIIii = binascii . hexlify ( igmp )
 if 57 - 57: O0 * I1ii11iIi11i . i11iIiiIii
 if 69 - 69: O0 / II111iiii * i1IIi
 if 66 - 66: O0
 if 52 - 52: OoO0O00 * OoooooooOO
 O0OoO0o = 0
 for o000o0O0Oo00 in range ( 0 , 24 , 4 ) :
  O0OoO0o += int ( II11iIIii [ o000o0O0Oo00 : o000o0O0Oo00 + 4 ] , 16 )
  if 12 - 12: O0 + IiII * i1IIi . OoO0O00
  if 71 - 71: I1Ii111 - o0oOOo0O0Ooo - OOooOOo
  if 28 - 28: iIii1I11I1II1
  if 7 - 7: o0oOOo0O0Ooo % IiII * OoOoOO00
  if 58 - 58: IiII / I11i + II111iiii % iII111i - OoooooooOO
 O0OoO0o = ( O0OoO0o >> 16 ) + ( O0OoO0o & 0xffff )
 O0OoO0o += O0OoO0o >> 16
 O0OoO0o = socket . htons ( ~ O0OoO0o & 0xffff )
 if 25 - 25: OoOoOO00 % OoooooooOO * Oo0Ooo - i1IIi * II111iiii * oO0o
 if 30 - 30: I11i % OoOoOO00 / I1ii11iIi11i * O0 * Ii1I . I1IiiI
 if 46 - 46: OoOoOO00 - O0
 if 70 - 70: I11i + Oo0Ooo * iIii1I11I1II1 . I1IiiI * I11i
 O0OoO0o = struct . pack ( "H" , O0OoO0o )
 igmp = igmp [ 0 : 2 ] + O0OoO0o + igmp [ 4 : : ]
 return ( igmp )
 if 49 - 49: o0oOOo0O0Ooo
 if 25 - 25: iII111i . OoooooooOO * iIii1I11I1II1 . o0oOOo0O0Ooo / O0 + Ii1I
 if 68 - 68: Oo0Ooo
 if 22 - 22: OOooOOo
 if 22 - 22: iII111i * I11i - Oo0Ooo * O0 / i11iIiiIii
 if 78 - 78: Oo0Ooo * O0 / ooOoO0o + OoooooooOO + OOooOOo
 if 23 - 23: iII111i % OoooooooOO / iIii1I11I1II1 + I1ii11iIi11i / i1IIi / o0oOOo0O0Ooo
def lisp_get_interface_address ( device ) :
 if 94 - 94: i1IIi
 if 36 - 36: I1IiiI + Oo0Ooo
 if 46 - 46: iII111i
 if 65 - 65: i1IIi . I1ii11iIi11i / ooOoO0o
 if ( device not in netifaces . interfaces ( ) ) : return ( None )
 if 11 - 11: IiII * ooOoO0o / ooOoO0o - OOooOOo
 if 68 - 68: I1IiiI % IiII - IiII / I1IiiI + I1ii11iIi11i - Oo0Ooo
 if 65 - 65: ooOoO0o - i1IIi
 if 62 - 62: I11i / oO0o % Oo0Ooo . OoooooooOO / i11iIiiIii / I1Ii111
 OooO0O0Ooo = netifaces . ifaddresses ( device )
 if ( netifaces . AF_INET not in OooO0O0Ooo ) : return ( None )
 if 85 - 85: o0oOOo0O0Ooo / I1Ii111
 if 67 - 67: I11i % oO0o
 if 39 - 39: i11iIiiIii + IiII
 if 7 - 7: iIii1I11I1II1 - i1IIi
 I1ii1i1iiii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 45 - 45: Ii1I / ooOoO0o . OoooooooOO + OoO0O00
 for iI1ii11Ii in OooO0O0Ooo [ netifaces . AF_INET ] :
  O00oO000Oo0 = iI1ii11Ii [ "addr" ]
  I1ii1i1iiii . store_address ( O00oO000Oo0 )
  return ( I1ii1i1iiii )
  if 26 - 26: Oo0Ooo + O0 - iIii1I11I1II1
 return ( None )
 if 47 - 47: OoooooooOO
 if 2 - 2: OoOoOO00 % I1Ii111 * Oo0Ooo * OoOoOO00
 if 65 - 65: i11iIiiIii + Oo0Ooo * OoooooooOO - OoO0O00
 if 26 - 26: o0oOOo0O0Ooo % OOooOOo + OOooOOo % I11i * i11iIiiIii / iII111i
 if 64 - 64: oO0o % OoOoOO00 / II111iiii % ooOoO0o - iII111i
 if 2 - 2: I1Ii111 - I1ii11iIi11i + o0oOOo0O0Ooo * OoO0O00 / iII111i
 if 26 - 26: OOooOOo * Oo0Ooo
 if 31 - 31: I11i * oO0o . Ii1I
 if 35 - 35: I11i
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
def lisp_get_input_interface ( packet ) :
 III1ii = lisp_format_packet ( packet [ 0 : 12 ] )
 iII1ii = III1ii . replace ( " " , "" )
 o0oOoO00 = iII1ii [ 0 : 12 ]
 oOO000 = iII1ii [ 12 : : ]
 if 95 - 95: O0 + I1IiiI + OoOoOO00 . OOooOOo
 try : OO0 = ( oOO000 in lisp_mymacs )
 except : OO0 = False
 if 28 - 28: Oo0Ooo % OOooOOo - OoO0O00 + ooOoO0o / ooOoO0o
 if ( o0oOoO00 in lisp_mymacs ) : return ( lisp_mymacs [ o0oOoO00 ] , oOO000 , o0oOoO00 , OO0 )
 if ( OO0 ) : return ( lisp_mymacs [ oOO000 ] , oOO000 , o0oOoO00 , OO0 )
 return ( [ "?" ] , oOO000 , o0oOoO00 , OO0 )
 if 82 - 82: Oo0Ooo
 if 5 - 5: OoO0O00 / OoO0O00 - O0 - I1Ii111 + I1Ii111
 if 99 - 99: I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - iIii1I11I1II1 - Ii1I
 if 31 - 31: IiII - OoO0O00 / OOooOOo . i1IIi / Ii1I
 if 66 - 66: OoO0O00
 if 72 - 72: I1Ii111
 if 91 - 91: II111iiii / IiII + iIii1I11I1II1 . I11i - O0
 if 70 - 70: Ii1I * oO0o - I11i + Oo0Ooo % I1ii11iIi11i - IiII
def lisp_get_local_interfaces ( ) :
 for ooo in netifaces . interfaces ( ) :
  OoO00OooO0 = lisp_interface ( ooo )
  OoO00OooO0 . add_interface ( )
  if 98 - 98: OOooOOo + Ii1I
 return
 if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
 if 50 - 50: iIii1I11I1II1 - iII111i - I11i
 if 60 - 60: iIii1I11I1II1 * ooOoO0o
 if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
 if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
 if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
 if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
def lisp_get_loopback_address ( ) :
 for iI1ii11Ii in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( iI1ii11Ii [ "peer" ] == "127.0.0.1" ) : continue
  return ( iI1ii11Ii [ "peer" ] )
  if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
 return ( None )
 if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
 if 93 - 93: ooOoO0o
 if 18 - 18: ooOoO0o
 if 66 - 66: oO0o * i11iIiiIii + OoOoOO00 / OOooOOo
 if 96 - 96: OOooOOo + OOooOOo % IiII % OOooOOo
 if 28 - 28: iIii1I11I1II1 + OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
 if 58 - 58: I11i / OoooooooOO % oO0o + OoO0O00
 if 58 - 58: O0
def lisp_is_mac_string ( mac_str ) :
 i1i1I1 = mac_str . split ( "/" )
 if ( len ( i1i1I1 ) == 2 ) : mac_str = i1i1I1 [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 91 - 91: iII111i / I1ii11iIi11i . iII111i - o0oOOo0O0Ooo + I1ii11iIi11i
 if 72 - 72: Ii1I . IiII * I1ii11iIi11i / I1ii11iIi11i / iII111i
 if 13 - 13: i1IIi
 if 17 - 17: i11iIiiIii * o0oOOo0O0Ooo * o0oOOo0O0Ooo + OoO0O00
 if 95 - 95: I1IiiI
 if 95 - 95: OOooOOo % I1ii11iIi11i + o0oOOo0O0Ooo % ooOoO0o
 if 36 - 36: O0 / i1IIi % II111iiii / iII111i
 if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
def lisp_get_local_macs ( ) :
 for ooo in netifaces . interfaces ( ) :
  if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
  if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
  if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
  if 55 - 55: oO0o
  if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
  oooOo = ooo . replace ( ":" , "" )
  oooOo = ooo . replace ( "-" , "" )
  if ( oooOo . isalnum ( ) == False ) : continue
  if 97 - 97: I1Ii111 . I11i / I1IiiI
  if 83 - 83: I11i - I1ii11iIi11i * oO0o
  if 90 - 90: Oo0Ooo * I1IiiI
  if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
  if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
  try :
   i11i11Iiii11i = netifaces . ifaddresses ( ooo )
  except :
   continue
   if 6 - 6: OoOoOO00 - ooOoO0o * o0oOOo0O0Ooo + OoOoOO00 % o0oOOo0O0Ooo
  if ( netifaces . AF_LINK not in i11i11Iiii11i ) : continue
  i1i1I1 = i11i11Iiii11i [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  i1i1I1 = i1i1I1 . replace ( ":" , "" )
  if 100 - 100: OoO0O00 % I1Ii111 - I11i % I11i % I11i / ooOoO0o
  if 83 - 83: oO0o - ooOoO0o - IiII % i1IIi - iII111i . o0oOOo0O0Ooo
  if 96 - 96: Oo0Ooo + I1Ii111 . i1IIi
  if 54 - 54: II111iiii . i1IIi / I1ii11iIi11i % I1IiiI / I1Ii111
  if 65 - 65: OoOoOO00 . OoOoOO00 - oO0o + Oo0Ooo / i11iIiiIii
  if ( len ( i1i1I1 ) < 12 ) : continue
  if 90 - 90: iIii1I11I1II1 + OoOoOO00
  if ( i1i1I1 not in lisp_mymacs ) : lisp_mymacs [ i1i1I1 ] = [ ]
  lisp_mymacs [ i1i1I1 ] . append ( ooo )
  if 9 - 9: iIii1I11I1II1 . OoooooooOO + i1IIi - Oo0Ooo
  if 30 - 30: iII111i / OoO0O00 . iII111i
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 17 - 17: Oo0Ooo + OoooooooOO * OoooooooOO
 if 5 - 5: I1Ii111 % OoooooooOO . OoOoOO00
 if 67 - 67: I1ii11iIi11i + Ii1I
 if 72 - 72: IiII % o0oOOo0O0Ooo
 if 93 - 93: iIii1I11I1II1 + i11iIiiIii . o0oOOo0O0Ooo . i1IIi % I1IiiI % ooOoO0o
 if 74 - 74: OoOoOO00 / i1IIi % OoooooooOO
 if 52 - 52: IiII % ooOoO0o
 if 25 - 25: I11i / I11i % OoooooooOO - I1ii11iIi11i * oO0o
def lisp_get_local_rloc ( ) :
 i1 = getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( i1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 93 - 93: O0 - OoO0O00 . I1IiiI
 if 64 - 64: OoOoOO00 + o0oOOo0O0Ooo
 if 65 - 65: II111iiii / Oo0Ooo
 if 42 - 42: i11iIiiIii . O0
 i1 = i1 . split ( "\n" ) [ 0 ]
 ooo = i1 . split ( ) [ - 1 ]
 if 75 - 75: I1Ii111 + iIii1I11I1II1
 iI1ii11Ii = ""
 IiiiI1 = lisp_is_macos ( )
 if ( IiiiI1 ) :
  i1 = getoutput ( "ifconfig {} | egrep 'inet '" . format ( ooo ) )
  if ( i1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  I1IIIi = 'ip addr show | egrep "inet " | egrep "{}"' . format ( ooo )
  i1 = getoutput ( I1IIIi )
  if ( i1 == "" ) :
   I1IIIi = 'ip addr show | egrep "inet " | egrep "global lo"'
   i1 = getoutput ( I1IIIi )
   if 39 - 39: I11i . I1ii11iIi11i . OOooOOo * I11i / O0 * o0oOOo0O0Ooo
  if ( i1 == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 35 - 35: i1IIi * i11iIiiIii % I1ii11iIi11i / IiII / IiII
  if 91 - 91: OoO0O00 * I1Ii111 % OoO0O00 . o0oOOo0O0Ooo * I1ii11iIi11i . OOooOOo
  if 13 - 13: I1ii11iIi11i
  if 80 - 80: Oo0Ooo % IiII % OoooooooOO * Oo0Ooo % Ii1I
  if 41 - 41: OoooooooOO / i1IIi
  if 70 - 70: OoOoOO00 % o0oOOo0O0Ooo % i1IIi / I1ii11iIi11i % i11iIiiIii / i1IIi
 iI1ii11Ii = ""
 i1 = i1 . split ( "\n" )
 if 4 - 4: IiII
 for oOo0OoOOOo0 in i1 :
  I1II1I1I = oOo0OoOOOo0 . split ( ) [ 1 ]
  if ( IiiiI1 == False ) : I1II1I1I = I1II1I1I . split ( "/" ) [ 0 ]
  OOoo00 = lisp_address ( LISP_AFI_IPV4 , I1II1I1I , 32 , 0 )
  return ( OOoo00 )
  if 22 - 22: ooOoO0o / ooOoO0o - Ii1I % I11i . OOooOOo + IiII
 return ( lisp_address ( LISP_AFI_IPV4 , iI1ii11Ii , 32 , 0 ) )
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
 if 89 - 89: OoooooooOO . iIii1I11I1II1 . Oo0Ooo * iIii1I11I1II1 - I1Ii111
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 92 - 92: OoooooooOO - I1ii11iIi11i - OoooooooOO % I1IiiI % I1IiiI % iIii1I11I1II1
 if 92 - 92: iII111i * O0 % I1Ii111 . iIii1I11I1II1
 if 66 - 66: I11i + Ii1I
 if 48 - 48: I1ii11iIi11i
 if 96 - 96: ooOoO0o . OoooooooOO
 if 39 - 39: OOooOOo + OoO0O00
 if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
 if 71 - 71: ooOoO0o . i11iIiiIii
 if 56 - 56: O0 * iII111i + iII111i * iIii1I11I1II1 / ooOoO0o * I1Ii111
 Ii = None
 o00O = 1
 Oo0O0O = os . getenv ( "LISP_ADDR_SELECT" )
 if ( Oo0O0O != None and Oo0O0O != "" ) :
  Oo0O0O = Oo0O0O . split ( ":" )
  if ( len ( Oo0O0O ) == 2 ) :
   Ii = Oo0O0O [ 0 ]
   o00O = Oo0O0O [ 1 ]
  else :
   if ( Oo0O0O [ 0 ] . isdigit ( ) ) :
    o00O = Oo0O0O [ 0 ]
   else :
    Ii = Oo0O0O [ 0 ]
    if 8 - 8: i11iIiiIii * O0 + I1ii11iIi11i . iIii1I11I1II1 % I11i / I11i
    if 70 - 70: I1IiiI + Ii1I
  o00O = 1 if ( o00O == "" ) else int ( o00O )
  if 70 - 70: IiII . i11iIiiIii
  if 76 - 76: iII111i . IiII % iII111i - I1Ii111
 Oo0O0oo = [ None , None , None ]
 o0O0 = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oO0o0 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 ooO = None
 if 85 - 85: II111iiii
 for ooo in netifaces . interfaces ( ) :
  if ( Ii != None and Ii != ooo ) : continue
  OooO0O0Ooo = netifaces . ifaddresses ( ooo )
  if ( OooO0O0Ooo == { } ) : continue
  if 55 - 55: I1ii11iIi11i
  if 76 - 76: oO0o - i11iIiiIii
  if 27 - 27: I1ii11iIi11i - i11iIiiIii % I1Ii111 / Oo0Ooo . Oo0Ooo / OoooooooOO
  if 76 - 76: I11i * OoO0O00 . iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
  ooO = lisp_get_interface_instance_id ( ooo , None )
  if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
  if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
  if 79 - 79: IiII + IiII + Ii1I
  if 39 - 39: O0 - OoooooooOO
  if ( netifaces . AF_INET in OooO0O0Ooo ) :
   oo000o = OooO0O0Ooo [ netifaces . AF_INET ]
   oo0O00ooo0o = 0
   for iI1ii11Ii in oo000o :
    o0O0 . store_address ( iI1ii11Ii [ "addr" ] )
    if ( o0O0 . is_ipv4_loopback ( ) ) : continue
    if ( o0O0 . is_ipv4_link_local ( ) ) : continue
    if ( o0O0 . address == 0 ) : continue
    oo0O00ooo0o += 1
    o0O0 . instance_id = ooO
    if ( Ii == None and
 lisp_db_for_lookups . lookup_cache ( o0O0 , False ) ) : continue
    Oo0O0oo [ 0 ] = o0O0
    if ( oo0O00ooo0o == o00O ) : break
    if 29 - 29: OoooooooOO . II111iiii % OoOoOO00
    if 26 - 26: iIii1I11I1II1 - I1ii11iIi11i . IiII . IiII + iIii1I11I1II1 * Oo0Ooo
  if ( netifaces . AF_INET6 in OooO0O0Ooo ) :
   OO00o0oOO = OooO0O0Ooo [ netifaces . AF_INET6 ]
   oo0O00ooo0o = 0
   for iI1ii11Ii in OO00o0oOO :
    O00oO000Oo0 = iI1ii11Ii [ "addr" ]
    oO0o0 . store_address ( O00oO000Oo0 )
    if ( oO0o0 . is_ipv6_string_link_local ( O00oO000Oo0 ) ) : continue
    if ( oO0o0 . is_ipv6_loopback ( ) ) : continue
    oo0O00ooo0o += 1
    oO0o0 . instance_id = ooO
    if ( Ii == None and
 lisp_db_for_lookups . lookup_cache ( oO0o0 , False ) ) : continue
    Oo0O0oo [ 1 ] = oO0o0
    if ( oo0O00ooo0o == o00O ) : break
    if 85 - 85: OOooOOo + II111iiii - OOooOOo * oO0o - i1IIi % iII111i
    if 1 - 1: OoooooooOO / O0 + OoOoOO00 + OoOoOO00 . I1Ii111 - OoOoOO00
    if 9 - 9: I1Ii111 * OoooooooOO % I1IiiI / OoOoOO00 * I11i
    if 48 - 48: OoooooooOO . OoOoOO00
    if 65 - 65: oO0o . Oo0Ooo
    if 94 - 94: OoOoOO00 + IiII . ooOoO0o
  if ( Oo0O0oo [ 0 ] == None ) : continue
  if 69 - 69: O0 - O0
  Oo0O0oo [ 2 ] = ooo
  break
  if 41 - 41: IiII % o0oOOo0O0Ooo
  if 67 - 67: O0 % I1Ii111
 III = Oo0O0oo [ 0 ] . print_address_no_iid ( ) if Oo0O0oo [ 0 ] else "none"
 I1I = Oo0O0oo [ 1 ] . print_address_no_iid ( ) if Oo0O0oo [ 1 ] else "none"
 ooo = Oo0O0oo [ 2 ] if Oo0O0oo [ 2 ] else "none"
 if 70 - 70: Ii1I . O0 - OOooOOo
 Ii = " (user selected)" if Ii != None else ""
 if 62 - 62: I1Ii111 * I11i
 III = red ( III , False )
 I1I = red ( I1I , False )
 ooo = bold ( ooo , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( III , I1I , ooo , Ii , ooO ) )
 if 74 - 74: OoOoOO00 . iIii1I11I1II1
 if 87 - 87: ooOoO0o
 lisp_myrlocs = Oo0O0oo
 return ( ( Oo0O0oo [ 0 ] != None ) )
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
 for OoO00OooO0 in netifaces . interfaces ( ) :
  try : iIiiI11II11i = netifaces . ifaddresses ( OoO00OooO0 )
  except : continue
  if 98 - 98: iII111i - iII111i
  if ( netifaces . AF_INET in iIiiI11II11i ) :
   for iI1ii11Ii in iIiiI11II11i [ netifaces . AF_INET ] :
    I1II1I1I = iI1ii11Ii [ "addr" ]
    if ( I1II1I1I . find ( "127.0.0.1" ) != - 1 ) : continue
    o00oOoo0o00 . append ( I1II1I1I )
    if 58 - 58: oO0o
    if 98 - 98: o0oOOo0O0Ooo * OoO0O00
  if ( netifaces . AF_INET6 in iIiiI11II11i ) :
   for iI1ii11Ii in iIiiI11II11i [ netifaces . AF_INET6 ] :
    I1II1I1I = iI1ii11Ii [ "addr" ]
    if ( I1II1I1I == "::1" ) : continue
    if ( I1II1I1I [ 0 : 5 ] == "fe80:" ) : continue
    o00oOoo0o00 . append ( I1II1I1I )
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
 i1 = getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( i1 == "" ) : return ( o0OOo0O )
 if 52 - 52: OoooooooOO / IiII % II111iiii
 Ii11I1I11II = i1 . split ( "\n" )
 for oOo0OoOOOo0 in Ii11I1I11II :
  if ( oOo0OoOOOo0 [ 0 ] == "#" ) : continue
  IIiiiI = oOo0OoOOOo0 . split ( "rle-address = " ) [ 1 ]
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
   O00oO000Oo0 = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 86 - 86: iIii1I11I1II1 - I11i % ooOoO0o . OOooOOo * OoOoOO00 . i1IIi
   if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_encap ) :
    O0o0O0 = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ]
    if ( O0o0O0 [ 1 ] ) :
     O0o0O0 [ 1 ] . use_count += 1
     OO0Oo00OO0oo , oOO00o0O0 = self . encrypt ( O0o0O0 [ 1 ] , O00oO000Oo0 )
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
  ii11 = struct . pack ( "HHHH" , iiI1iiIiiiI1I , i111I1 , OOOo0Oo0O , self . udp_checksum )
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
  self . packet = iii11 + ii11 + oOoOO0O00o + self . packet
  return ( self )
  if 34 - 34: o0oOOo0O0Ooo . I1Ii111 % IiII - O0 / I1Ii111
  if 91 - 91: i11iIiiIii % I1Ii111 * oO0o - I1ii11iIi11i . I1Ii111
 def cipher_pad ( self , packet ) :
  iI = len ( packet )
  if ( ( iI % 16 ) != 0 ) :
   o00oo = ( old_div ( iI , 16 ) + 1 ) * 16
   packet = packet . ljust ( o00oo )
   if 78 - 78: IiII - I11i % O0 - OOooOOo % OoO0O00
  return ( packet )
  if 43 - 43: OoO0O00
  if 90 - 90: OoooooooOO + O0 + I1ii11iIi11i / I11i / Ii1I * I1ii11iIi11i
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 100 - 100: I11i
   if 82 - 82: iIii1I11I1II1
   if 19 - 19: I1IiiI
   if 66 - 66: oO0o / OoOoOO00
   if 13 - 13: II111iiii
  OO0Oo00OO0oo = self . cipher_pad ( self . packet )
  oO0o000oOO = key . get_iv ( )
  if 27 - 27: O0 - I11i * II111iiii - iIii1I11I1II1 / ooOoO0o
  iIiIIIIIii = lisp_get_timestamp ( )
  II1i = None
  OOoOooO0o = False
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   I1IiiiI = chacha . ChaCha ( key . encrypt_key , oO0o000oOO ) . encrypt
   OOoOooO0o = True
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   iIiI1111 = binascii . unhexlify ( key . encrypt_key )
   try :
    O0OO00 = AES . new ( iIiI1111 , AES . MODE_GCM , oO0o000oOO )
    I1IiiiI = O0OO00 . encrypt
    II1i = O0OO00 . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 6 - 6: Oo0Ooo
  else :
   iIiI1111 = binascii . unhexlify ( key . encrypt_key )
   I1IiiiI = AES . new ( iIiI1111 , AES . MODE_CBC , oO0o000oOO ) . encrypt
   if 73 - 73: I1Ii111 * I1ii11iIi11i + o0oOOo0O0Ooo - Oo0Ooo . I11i
   if 93 - 93: i11iIiiIii
  OoO = I1IiiiI ( OO0Oo00OO0oo )
  if 34 - 34: Oo0Ooo - Ii1I - iII111i
  if ( OoO == None ) : return ( [ self . packet , False ] )
  iIiIIIIIii = int ( str ( time . time ( ) - iIiIIIIIii ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 61 - 61: I1ii11iIi11i
  if 33 - 33: OoOoOO00 / OoO0O00
  if 47 - 47: iII111i + O0 / II111iiii * I1IiiI - OoooooooOO . Ii1I
  if 28 - 28: oO0o . oO0o . iIii1I11I1II1 . OOooOOo . I1ii11iIi11i * i11iIiiIii
  if 72 - 72: I11i
  if 26 - 26: IiII % Oo0Ooo
  if ( OOoOooO0o ) :
   OoO = OoO . encode ( "raw_unicode_escape" )
   if 72 - 72: O0 + o0oOOo0O0Ooo + I1IiiI / Oo0Ooo
   if 83 - 83: IiII - I1IiiI . Ii1I
   if 34 - 34: OoOoOO00 - oO0o * OoooooooOO
   if 5 - 5: i11iIiiIii * iII111i - Ii1I - I1ii11iIi11i - i1IIi + iII111i
   if 4 - 4: ooOoO0o + O0 . i1IIi * I1ii11iIi11i - o0oOOo0O0Ooo
   if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
   if 25 - 25: Oo0Ooo % OoOoOO00
  if ( II1i != None ) : OoO += II1i ( )
  if 75 - 75: i1IIi
  if 74 - 74: Oo0Ooo + I1Ii111 - oO0o - OoO0O00 + iII111i - iIii1I11I1II1
  if 54 - 54: I1ii11iIi11i + II111iiii . I1IiiI / OoO0O00 . ooOoO0o
  if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
  if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
  self . lisp_header . key_id ( key . key_id )
  oOoOO0O00o = self . lisp_header . encode ( )
  if 36 - 36: I11i - IiII . IiII
  Oo0OOOO0oOoo0 = key . do_icv ( oOoOO0O00o + oO0o000oOO + OoO , oO0o000oOO )
  if 92 - 92: IiII . Oo0Ooo - Oo0Ooo - o0oOOo0O0Ooo + I1Ii111 - O0
  i1I1Iiii = 4 if ( key . do_poly ) else 8
  if 15 - 15: ooOoO0o % o0oOOo0O0Ooo / oO0o - II111iiii . iIii1I11I1II1
  ii1111Iii11i = bold ( "Encrypt" , False )
  O0o0oo0O = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  Ooo00OOo000 = "poly" if key . do_poly else "sha256"
  Ooo00OOo000 = bold ( Ooo00OOo000 , False )
  i1ooOO00o0 = "ICV({}): 0x{}...{}" . format ( Ooo00OOo000 , Oo0OOOO0oOoo0 [ 0 : i1I1Iiii ] , Oo0OOOO0oOoo0 [ - i1I1Iiii : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( ii1111Iii11i , key . key_id , addr_str , i1ooOO00o0 , O0o0oo0O , iIiIIIIIii ) )
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
  return ( [ oO0o000oOO + OoO + Oo0OOOO0oOoo0 , True ] )
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
  oOoOO0O00o = self . lisp_header . encode ( )
  if 38 - 38: i1IIi . Oo0Ooo * Oo0Ooo / I1ii11iIi11i
  if 65 - 65: ooOoO0o % O0
  if 17 - 17: i1IIi + oO0o . I11i + i1IIi - II111iiii % I1IiiI
  if 34 - 34: I1IiiI
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   o0 = 8
   O0o0oo0O = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o0 = 12
   O0o0oo0O = bold ( "aes-gcm" , False )
  else :
   o0 = 16
   O0o0oo0O = bold ( "aes-cbc" , False )
   if 76 - 76: I1IiiI - I1IiiI - o0oOOo0O0Ooo % ooOoO0o * O0
  oO0o000oOO = packet [ 0 : o0 ]
  if 11 - 11: Ii1I + I11i . OoO0O00 . i11iIiiIii * OoO0O00
  if 18 - 18: I11i + Oo0Ooo - OoO0O00 / I1Ii111 / OOooOOo
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo . oO0o / I11i
  if 52 - 52: I1Ii111 + I1Ii111
  OO0ii1 = key . do_icv ( oOoOO0O00o + packet , oO0o000oOO )
  if 32 - 32: o0oOOo0O0Ooo % I1IiiI
  iII = "0x{}...{}" . format ( oOooo [ 0 : i1I1Iiii ] , oOooo [ - i1I1Iiii : : ] )
  Ii11IiIIiIIii = "0x{}...{}" . format ( OO0ii1 [ 0 : i1I1Iiii ] , OO0ii1 [ - i1I1Iiii : : ] )
  if 74 - 74: iIii1I11I1II1 / Ii1I
  if ( OO0ii1 != oOooo ) :
   self . packet_error = "ICV-error"
   O0Oo0 = O0o0oo0O + "/" + Iii1II1
   Oo00o0o = bold ( "ICV failed ({})" . format ( O0Oo0 ) , False )
   i1ooOO00o0 = "packet-ICV {} != computed-ICV {}" . format ( iII , Ii11IiIIiIIii )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( Oo00o0o , red ( addr_str , False ) ,
   # IiII
 self . udp_sport , key . key_id , i1ooOO00o0 ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 33 - 33: o0oOOo0O0Ooo . OOooOOo + o0oOOo0O0Ooo / I1ii11iIi11i . Oo0Ooo + OoOoOO00
   if 32 - 32: IiII - ooOoO0o * iII111i * I11i
   if 84 - 84: Ii1I + I1ii11iIi11i % I1IiiI + i11iIiiIii
   if 37 - 37: I11i % I1ii11iIi11i / ooOoO0o
   if 94 - 94: I11i / OoO0O00 . o0oOOo0O0Ooo
   if 1 - 1: Oo0Ooo . II111iiii
   lisp_retry_decap_keys ( addr_str , oOoOO0O00o + packet , oO0o000oOO , oOooo )
   return ( [ None , False ] )
   if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
   if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
   if 4 - 4: IiII
   if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
   if 99 - 99: i11iIiiIii - iII111i
  packet = packet [ o0 : : ]
  if 85 - 85: I1Ii111 % I1ii11iIi11i
  if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
  if 73 - 73: OoO0O00
  if 28 - 28: OoooooooOO - I11i
  iIiIIIIIii = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   oOOO0 = chacha . ChaCha ( key . encrypt_key , oO0o000oOO ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   iIiI1111 = binascii . unhexlify ( key . encrypt_key )
   try :
    oOOO0 = AES . new ( iIiI1111 , AES . MODE_GCM , oO0o000oOO ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 57 - 57: O0 . OoooooooOO % I1ii11iIi11i
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 97 - 97: i1IIi % O0 + i1IIi % oO0o * I1Ii111
   iIiI1111 = binascii . unhexlify ( key . encrypt_key )
   oOOO0 = AES . new ( iIiI1111 , AES . MODE_CBC , oO0o000oOO ) . decrypt
   if 20 - 20: O0 . OoooooooOO % I1IiiI . OoooooooOO / IiII
   if 18 - 18: II111iiii % OoOoOO00
  oOO0o0OOo = oOOO0 ( packet )
  iIiIIIIIii = int ( str ( time . time ( ) - iIiIIIIIii ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 71 - 71: Ii1I % OOooOOo / o0oOOo0O0Ooo
  if 83 - 83: Ii1I . OoOoOO00 / iIii1I11I1II1 . OoooooooOO - iIii1I11I1II1
  if 59 - 59: I1ii11iIi11i + I11i . oO0o
  if 87 - 87: OoO0O00
  ii1111Iii11i = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  Ooo00OOo000 = "poly" if key . do_poly else "sha256"
  Ooo00OOo000 = bold ( Ooo00OOo000 , False )
  i1ooOO00o0 = "ICV({}): {}" . format ( Ooo00OOo000 , iII )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( ii1111Iii11i , key . key_id , addr_str , i1ooOO00o0 , O0o0oo0O , iIiIIIIIii ) )
  if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  if 46 - 46: Oo0Ooo + II111iiii * I1IiiI + OOooOOo
  if 31 - 31: Ii1I * o0oOOo0O0Ooo * Ii1I + OoO0O00 * o0oOOo0O0Ooo . I1Ii111
  if 89 - 89: OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
  if 46 - 46: i11iIiiIii
  if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
  if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
  self . packet = self . packet [ 0 : header_length ]
  return ( [ oOO0o0OOo , True ] )
  if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
  if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  ooOO = 1000
  if 66 - 66: Oo0Ooo / i11iIiiIii % ooOoO0o
  if 43 - 43: OOooOOo
  if 84 - 84: OOooOOo . IiII . iII111i
  if 2 - 2: Oo0Ooo - OoOoOO00
  if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
  o0OO0oO0Oo0 = [ ]
  II1Ii = 0
  iI = len ( inner_packet )
  while ( II1Ii < iI ) :
   oo0O00o0O0Oo = inner_packet [ II1Ii : : ]
   if ( len ( oo0O00o0O0Oo ) > ooOO ) : oo0O00o0O0Oo = oo0O00o0O0Oo [ 0 : ooOO ]
   o0OO0oO0Oo0 . append ( oo0O00o0O0Oo )
   II1Ii += len ( oo0O00o0O0Oo )
   if 73 - 73: II111iiii . OoOoOO00 . Oo0Ooo
   if 89 - 89: I1IiiI / iII111i / OoooooooOO - i11iIiiIii + I1IiiI
   if 64 - 64: i11iIiiIii + i1IIi % O0 . I11i
   if 64 - 64: ooOoO0o / i1IIi % iII111i
   if 84 - 84: OoOoOO00 - Oo0Ooo . ooOoO0o . IiII - Oo0Ooo
   if 99 - 99: I1Ii111
  o0I1IiiiiI1i1I = [ ]
  II1Ii = 0
  for oo0O00o0O0Oo in o0OO0oO0Oo0 :
   if 48 - 48: I11i + II111iiii % oO0o % OOooOOo * II111iiii
   if 41 - 41: OoO0O00
   if 13 - 13: ooOoO0o - I1IiiI
   if 23 - 23: I1IiiI
   i1IIiI1iII = II1Ii if ( oo0O00o0O0Oo == o0OO0oO0Oo0 [ - 1 ] ) else 0x2000 + II1Ii
   i1IIiI1iII = socket . htons ( i1IIiI1iII )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , i1IIiI1iII ) + outer_hdr [ 8 : : ]
   if 45 - 45: i1IIi % OOooOOo % II111iiii
   if 4 - 4: oO0o * I1IiiI - ooOoO0o / II111iiii + OOooOOo / i11iIiiIii
   if 63 - 63: OoO0O00 + ooOoO0o
   if 3 - 3: OoOoOO00 - I1Ii111 / oO0o . O0 * ooOoO0o / I1ii11iIi11i
   i1II1IIiIi1 = socket . htons ( len ( oo0O00o0O0Oo ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , i1II1IIiIi1 ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   o0I1IiiiiI1i1I . append ( outer_hdr + oo0O00o0O0Oo )
   II1Ii += len ( oo0O00o0O0Oo ) / 8
   if 97 - 97: o0oOOo0O0Ooo / IiII + OoOoOO00 + OoO0O00 % I1Ii111
  return ( o0I1IiiiiI1i1I )
  if 18 - 18: I1IiiI - OoOoOO00
  if 18 - 18: OOooOOo + OoO0O00 * oO0o - oO0o . I1ii11iIi11i * I11i
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 95 - 95: I1ii11iIi11i / OoOoOO00
  o0oOOOO0 = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( o0oOOOO0 < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 10 - 10: IiII % I1ii11iIi11i - IiII
   return ( False )
   if 86 - 86: Oo0Ooo
   if 88 - 88: I1Ii111 * I1IiiI
   if 30 - 30: OoOoOO00 / oO0o / Ii1I * o0oOOo0O0Ooo * oO0o . I1IiiI
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
  iIiIi1i1Iiii = socket . htons ( 1400 )
  Ii11iiI1 = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , iIiIi1i1Iiii )
  Ii11iiI1 += inner_packet [ 0 : 20 + 8 ]
  Ii11iiI1 = lisp_icmp_checksum ( Ii11iiI1 )
  if 78 - 78: Oo0Ooo - I1Ii111 + iII111i * Ii1I * o0oOOo0O0Ooo
  if 23 - 23: Oo0Ooo - O0
  if 33 - 33: I1ii11iIi11i
  if 54 - 54: ooOoO0o * I1ii11iIi11i . II111iiii / OOooOOo % OOooOOo
  if 25 - 25: i11iIiiIii + I1ii11iIi11i - OoooooooOO . O0 % I1Ii111
  if 53 - 53: i1IIi
  if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
  iiIII1i1 = inner_packet [ 12 : 16 ]
  oOOo0OOoOO0 = self . inner_source . print_address_no_iid ( )
  IiIi = self . outer_source . pack_address ( )
  if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
  if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
  if 11 - 11: I1ii11iIi11i - OoooooooOO
  if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
  if 27 - 27: IiII + iIii1I11I1II1 / Oo0Ooo + OoO0O00 % Oo0Ooo + OoO0O00
  if 77 - 77: Oo0Ooo * ooOoO0o % Ii1I
  if 2 - 2: I11i / Oo0Ooo / Ii1I / I1ii11iIi11i / OoooooooOO
  if 22 - 22: iIii1I11I1II1 * I1IiiI / I11i + OoOoOO00
  o000o0o00Oo = socket . htons ( 20 + 36 )
  ooooO000 = struct . pack ( "BBHHHBBH" , 0x45 , 0 , o000o0o00Oo , 0 , 0 , 32 , 1 , 0 ) + IiIi + iiIII1i1
  ooooO000 = lisp_ip_checksum ( ooooO000 )
  ooooO000 = self . fix_outer_header ( ooooO000 )
  ooooO000 += Ii11iiI1
  o00OoOOoO = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( o00OoOOoO , oOOo0OOoOO0 ,
 lisp_format_packet ( ooooO000 ) ) )
  if 28 - 28: iIii1I11I1II1 * I11i . I1IiiI
  try :
   lisp_icmp_raw_socket . sendto ( ooooO000 , ( oOOo0OOoOO0 , 0 ) )
  except socket . error as oOO :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( oOO ) )
   return ( False )
   if 78 - 78: OoooooooOO . OoooooooOO / O0
   if 25 - 25: II111iiii % II111iiii - Ii1I . O0
   if 79 - 79: IiII / OoO0O00 * OoooooooOO * OoOoOO00 + I1IiiI
   if 68 - 68: I11i / iIii1I11I1II1 . Oo0Ooo + i11iIiiIii + o0oOOo0O0Ooo
   if 92 - 92: OoO0O00 . o0oOOo0O0Ooo . Ii1I % OoOoOO00
   if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
  lisp_last_icmp_too_big_sent = lisp_get_timestamp ( )
  return ( True )
  if 9 - 9: ooOoO0o - Ii1I % II111iiii + IiII + OOooOOo % O0
 def fragment ( self ) :
  global lisp_icmp_raw_socket
  global lisp_ignore_df_bit
  if 65 - 65: OOooOOo - OoO0O00 % i11iIiiIii
  OO0Oo00OO0oo = self . fix_outer_header ( self . packet )
  if 58 - 58: iII111i
  if 2 - 2: II111iiii + i1IIi
  if 68 - 68: OOooOOo + Ii1I
  if 58 - 58: IiII * Ii1I . i1IIi
  if 19 - 19: oO0o
  if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
  iI = len ( OO0Oo00OO0oo )
  if ( iI <= 1500 ) : return ( [ OO0Oo00OO0oo ] , "Fragment-None" )
  if 94 - 94: iIii1I11I1II1 + IiII
  OO0Oo00OO0oo = self . packet
  if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
  if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
  if 36 - 36: OoOoOO00 . i11iIiiIii
  if 81 - 81: Oo0Ooo * iII111i * OoO0O00
  if 85 - 85: O0 * oO0o
  if ( self . inner_version != 4 ) :
   iiIiiiIii11i1 = random . randint ( 0 , 0xffff )
   OOoo00O0oo = OO0Oo00OO0oo [ 0 : 4 ] + struct . pack ( "H" , iiIiiiIii11i1 ) + OO0Oo00OO0oo [ 6 : 20 ]
   i1ii1i1i1 = OO0Oo00OO0oo [ 20 : : ]
   o0I1IiiiiI1i1I = self . fragment_outer ( OOoo00O0oo , i1ii1i1i1 )
   return ( o0I1IiiiiI1i1I , "Fragment-Outer" )
   if 92 - 92: Oo0Ooo
   if 60 - 60: i11iIiiIii . O0 * iIii1I11I1II1 * OoOoOO00
   if 99 - 99: iIii1I11I1II1 - oO0o - OoOoOO00 / iIii1I11I1II1 * Oo0Ooo - oO0o
   if 72 - 72: IiII % i1IIi / iIii1I11I1II1
   if 95 - 95: O0 . OoO0O00
  ooOo = 56 if ( self . outer_version == 6 ) else 36
  OOoo00O0oo = OO0Oo00OO0oo [ 0 : ooOo ]
  OO00oOOO = OO0Oo00OO0oo [ ooOo : ooOo + 20 ]
  i1ii1i1i1 = OO0Oo00OO0oo [ ooOo + 20 : : ]
  if 94 - 94: I1Ii111
  if 39 - 39: OoooooooOO
  if 19 - 19: i11iIiiIii
  if 80 - 80: I1IiiI
  if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
  Iii11I1i = struct . unpack ( "H" , OO00oOOO [ 6 : 8 ] ) [ 0 ]
  Iii11I1i = socket . ntohs ( Iii11I1i )
  if ( Iii11I1i & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    oO0OOoOO = OO0Oo00OO0oo [ ooOo : : ]
    if ( self . send_icmp_too_big ( oO0OOoOO ) ) : return ( [ ] , None )
    if 97 - 97: i1IIi
   if ( lisp_ignore_df_bit ) :
    Iii11I1i &= ~ 0x4000
   else :
    ii1iI1i1 = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( ii1iI1i1 ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 51 - 51: ooOoO0o * iII111i / i1IIi
    if 2 - 2: oO0o + IiII . iII111i - i1IIi + I1Ii111
    if 54 - 54: OoooooooOO . oO0o - iII111i
  II1Ii = 0
  iI = len ( i1ii1i1i1 )
  o0I1IiiiiI1i1I = [ ]
  while ( II1Ii < iI ) :
   o0I1IiiiiI1i1I . append ( i1ii1i1i1 [ II1Ii : II1Ii + 1400 ] )
   II1Ii += 1400
   if 76 - 76: I1Ii111
   if 61 - 61: ooOoO0o / II111iiii * ooOoO0o * OoOoOO00 * I1Ii111 . i11iIiiIii
   if 26 - 26: I1Ii111 / ooOoO0o - OoO0O00 . iIii1I11I1II1
   if 83 - 83: ooOoO0o % Ii1I / Oo0Ooo - iII111i / O0
   if 97 - 97: iIii1I11I1II1 * I11i
  o0OO0oO0Oo0 = o0I1IiiiiI1i1I
  o0I1IiiiiI1i1I = [ ]
  o00oooo = True if Iii11I1i & 0x2000 else False
  Iii11I1i = ( Iii11I1i & 0x1fff ) * 8
  for oo0O00o0O0Oo in o0OO0oO0Oo0 :
   if 63 - 63: II111iiii - I11i . OoOoOO00
   if 8 - 8: I1IiiI * ooOoO0o / IiII + OoOoOO00 . IiII - OOooOOo
   if 80 - 80: iIii1I11I1II1 / oO0o * Oo0Ooo - OOooOOo * iII111i
   if 97 - 97: IiII - I11i / II111iiii
   I11ii1i = old_div ( Iii11I1i , 8 )
   if ( o00oooo ) :
    I11ii1i |= 0x2000
   elif ( oo0O00o0O0Oo != o0OO0oO0Oo0 [ - 1 ] ) :
    I11ii1i |= 0x2000
    if 50 - 50: iIii1I11I1II1 - I11i % iII111i - Oo0Ooo
   I11ii1i = socket . htons ( I11ii1i )
   OO00oOOO = OO00oOOO [ 0 : 6 ] + struct . pack ( "H" , I11ii1i ) + OO00oOOO [ 8 : : ]
   if 52 - 52: oO0o + Ii1I - I1ii11iIi11i * Ii1I . OOooOOo + I1Ii111
   if 43 - 43: I1IiiI % IiII % I1ii11iIi11i
   if 53 - 53: oO0o % OOooOOo % I1ii11iIi11i . I1Ii111 . I1Ii111 . iII111i
   if 73 - 73: iII111i / ooOoO0o + OoO0O00 / OoOoOO00 . II111iiii * Ii1I
   if 21 - 21: I1IiiI - I1IiiI + iII111i % I1IiiI * oO0o
   if 74 - 74: iII111i / I11i . I1IiiI - OoooooooOO + II111iiii + I11i
   iI = len ( oo0O00o0O0Oo )
   Iii11I1i += iI
   i1II1IIiIi1 = socket . htons ( iI + 20 )
   OO00oOOO = OO00oOOO [ 0 : 2 ] + struct . pack ( "H" , i1II1IIiIi1 ) + OO00oOOO [ 4 : 10 ] + struct . pack ( "H" , 0 ) + OO00oOOO [ 12 : : ]
   if 36 - 36: Ii1I * I1IiiI * I1ii11iIi11i . I11i * I1ii11iIi11i
   OO00oOOO = lisp_ip_checksum ( OO00oOOO )
   O0ooO0 = OO00oOOO + oo0O00o0O0Oo
   if 41 - 41: o0oOOo0O0Ooo % Oo0Ooo
   if 93 - 93: ooOoO0o
   if 82 - 82: I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - OoOoOO00 / iII111i
   if 99 - 99: oO0o / i1IIi
   if 2 - 2: oO0o . iII111i
   iI = len ( O0ooO0 )
   if ( self . outer_version == 4 ) :
    i1II1IIiIi1 = iI + ooOo
    iI += 16
    OOoo00O0oo = OOoo00O0oo [ 0 : 2 ] + struct . pack ( "H" , i1II1IIiIi1 ) + OOoo00O0oo [ 4 : : ]
    if 42 - 42: OoO0O00 - I1ii11iIi11i * IiII - ooOoO0o
    OOoo00O0oo = lisp_ip_checksum ( OOoo00O0oo )
    O0ooO0 = OOoo00O0oo + O0ooO0
    O0ooO0 = self . fix_outer_header ( O0ooO0 )
    if 75 - 75: iII111i * Oo0Ooo / I1Ii111 * Oo0Ooo / ooOoO0o
    if 14 - 14: i1IIi * iIii1I11I1II1 - Ii1I * OoOoOO00 - iII111i / oO0o
    if 73 - 73: I1ii11iIi11i - OoOoOO00 * O0 - OoOoOO00 - OoO0O00
    if 96 - 96: I1ii11iIi11i - O0
    if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
   oO0oO00 = ooOo - 12
   i1II1IIiIi1 = socket . htons ( iI )
   O0ooO0 = O0ooO0 [ 0 : oO0oO00 ] + struct . pack ( "H" , i1II1IIiIi1 ) + O0ooO0 [ oO0oO00 + 2 : : ]
   if 15 - 15: I1IiiI % oO0o . Oo0Ooo % iIii1I11I1II1
   o0I1IiiiiI1i1I . append ( O0ooO0 )
   if 98 - 98: I11i - i1IIi % Ii1I - OoooooooOO
  return ( o0I1IiiiiI1i1I , "Fragment-Inner" )
  if 19 - 19: iIii1I11I1II1 + I1Ii111 . I1Ii111 - Oo0Ooo
  if 41 - 41: I1IiiI . Oo0Ooo . IiII % OoooooooOO + OoO0O00
 def fix_outer_header ( self , packet ) :
  if 23 - 23: I1IiiI - o0oOOo0O0Ooo % oO0o . O0 * OoooooooOO + ooOoO0o
  if 53 - 53: Oo0Ooo
  if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
  if 58 - 58: IiII % iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * iII111i
  if 32 - 32: OoooooooOO + o0oOOo0O0Ooo
  if 91 - 91: ooOoO0o - I1Ii111 * I1Ii111
  if 55 - 55: iIii1I11I1II1 + I1IiiI - Oo0Ooo
  if 24 - 24: OoO0O00 / I1Ii111 + iII111i * I11i * iII111i
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 : 4 ] + packet [ 2 : 3 ] + packet [ 4 : 6 ] + packet [ 7 : 8 ] + packet [ 6 : 7 ] + packet [ 8 : : ]
    if 10 - 10: I1IiiI - I1ii11iIi11i - Oo0Ooo - o0oOOo0O0Ooo
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 : 4 ] + packet [ 2 : 3 ] + packet [ 4 : : ]
    if 21 - 21: OoooooooOO + I1Ii111
    if 43 - 43: i11iIiiIii . I1ii11iIi11i . oO0o
  return ( packet )
  if 31 - 31: Ii1I % o0oOOo0O0Ooo % I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
  if 74 - 74: I1IiiI . ooOoO0o / iII111i . IiII
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
  dest = dest . print_address_no_iid ( )
  o0I1IiiiiI1i1I , ooOoo0oo00000O = self . fragment ( )
  if 84 - 84: iIii1I11I1II1
  for O0ooO0 in o0I1IiiiiI1i1I :
   if ( len ( o0I1IiiiiI1i1I ) != 1 ) :
    self . packet = O0ooO0
    self . print_packet ( ooOoo0oo00000O , True )
    if 25 - 25: OoO0O00 * IiII - i1IIi - I11i * II111iiii
    if 70 - 70: II111iiii + iII111i * OoOoOO00
   try : lisp_raw_socket . sendto ( O0ooO0 , ( dest , 0 ) )
   except socket . error as oOO :
    lprint ( "socket.sendto() failed: {}" . format ( oOO ) )
    if 61 - 61: OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
    if 91 - 91: I1IiiI / II111iiii * OOooOOo
    if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
    if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 81 - 81: OoO0O00 - iIii1I11I1II1
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 60 - 60: I1Ii111
   if 77 - 77: I1IiiI / I1ii11iIi11i
  OO0Oo00OO0oo = mac_header + self . packet
  if 95 - 95: I1Ii111 * i1IIi + oO0o
  if 40 - 40: II111iiii
  if 7 - 7: OOooOOo / OoO0O00
  if 88 - 88: i1IIi
  if 53 - 53: ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
  if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
  if 57 - 57: oO0o
  if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
  if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
  if 37 - 37: iII111i
  if 15 - 15: o0oOOo0O0Ooo % OoO0O00 / iII111i
  l2_socket . write ( OO0Oo00OO0oo )
  return
  if 36 - 36: OoO0O00 + OoO0O00 % Oo0Ooo + Oo0Ooo / i1IIi % i1IIi
  if 20 - 20: OOooOOo * oO0o
 def bridge_l2_packet ( self , eid , db ) :
  try : OOOoooOo00O = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : OoO00OooO0 = lisp_myinterfaces [ OOOoooOo00O . interface ]
  except : return
  try :
   socket = OoO00OooO0 . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 6 - 6: OoooooooOO - Oo0Ooo
  try : socket . send ( self . packet )
  except socket . error as oOO :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( oOO ) )
   if 52 - 52: OOooOOo + Oo0Ooo
   if 67 - 67: I1ii11iIi11i % OoooooooOO
   if 41 - 41: OoO0O00 / IiII + I1Ii111 . I1Ii111 / oO0o
 def is_lisp_packet ( self , packet ) :
  ii11 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( ii11 == False ) : return ( False )
  if 74 - 74: Ii1I % i11iIiiIii . O0 * I1IiiI * i1IIi * OoooooooOO
  I1I1I1 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( I1I1I1 ) == LISP_DATA_PORT ) : return ( True )
  I1I1I1 = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( I1I1I1 ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 29 - 29: I1ii11iIi11i
  if 91 - 91: OoO0O00
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  OO0Oo00OO0oo = self . packet
  OOO = len ( OO0Oo00OO0oo )
  O0OoO0oOOoo0 = Oo000O000 = True
  if 7 - 7: I1IiiI
  if 40 - 40: ooOoO0o
  if 80 - 80: I1IiiI * I1Ii111 % oO0o . i11iIiiIii % IiII
  if 42 - 42: OoooooooOO * II111iiii
  O0oooOO = 0
  i1I1iI = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   IIiIi1I1iI1 = struct . unpack ( "B" , OO0Oo00OO0oo [ 0 : 1 ] ) [ 0 ]
   self . outer_version = IIiIi1I1iI1 >> 4
   if ( self . outer_version == 4 ) :
    if 39 - 39: OOooOOo
    if 70 - 70: IiII % OoO0O00 % I1IiiI
    if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
    if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
    if 2 - 2: oO0o * oO0o . OoOoOO00 * Ii1I * iIii1I11I1II1
    I1ii = struct . unpack ( "H" , OO0Oo00OO0oo [ 10 : 12 ] ) [ 0 ]
    OO0Oo00OO0oo = lisp_ip_checksum ( OO0Oo00OO0oo )
    O0OoO0o = struct . unpack ( "H" , OO0Oo00OO0oo [ 10 : 12 ] ) [ 0 ]
    if ( O0OoO0o != 0 ) :
     if ( I1ii != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( OOO )
       if 96 - 96: Ii1I
       if 24 - 24: O0
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 33 - 33: OoooooooOO + oO0o * II111iiii / OOooOOo
      if 87 - 87: OoooooooOO
      if 1 - 1: iIii1I11I1II1 / o0oOOo0O0Ooo
    Oooo0oOOOO = LISP_AFI_IPV4
    II1Ii = 12
    self . outer_tos = struct . unpack ( "B" , OO0Oo00OO0oo [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , OO0Oo00OO0oo [ 8 : 9 ] ) [ 0 ]
    O0oooOO = 20
   elif ( self . outer_version == 6 ) :
    Oooo0oOOOO = LISP_AFI_IPV6
    II1Ii = 8
    i1II1i1iiI1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( i1II1i1iiI1 ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , OO0Oo00OO0oo [ 7 : 8 ] ) [ 0 ]
    O0oooOO = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( OOO )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 62 - 62: Ii1I . i11iIiiIii % O0 % I1Ii111 - Oo0Ooo
    if 69 - 69: II111iiii . OoOoOO00 * OoOoOO00 % Ii1I + I1IiiI
   self . outer_source . afi = Oooo0oOOOO
   self . outer_dest . afi = Oooo0oOOOO
   ooOOO000O = self . outer_source . addr_length ( )
   if 90 - 90: Ii1I . i11iIiiIii + iIii1I11I1II1
   self . outer_source . unpack_address ( OO0Oo00OO0oo [ II1Ii : II1Ii + ooOOO000O ] )
   II1Ii += ooOOO000O
   self . outer_dest . unpack_address ( OO0Oo00OO0oo [ II1Ii : II1Ii + ooOOO000O ] )
   OO0Oo00OO0oo = OO0Oo00OO0oo [ O0oooOO : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 32 - 32: Oo0Ooo - Ii1I . OoooooooOO - OoooooooOO - Oo0Ooo . iIii1I11I1II1
   if 34 - 34: Oo0Ooo
   if 31 - 31: i1IIi - I11i + I1Ii111 + ooOoO0o . ooOoO0o . O0
   if 33 - 33: i1IIi / iII111i * OoO0O00
   iI1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( iI1 )
   iI1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( iI1 )
   iI1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( iI1 )
   iI1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( iI1 )
   OO0Oo00OO0oo = OO0Oo00OO0oo [ 8 : : ]
   if 43 - 43: iIii1I11I1II1
   if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
   if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
   if 98 - 98: i1IIi - iII111i
   O0OoO0oOOoo0 = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   Oo000O000 = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 49 - 49: o0oOOo0O0Ooo . Ii1I . oO0o
   if 9 - 9: IiII - II111iiii * OoO0O00
   if 78 - 78: iIii1I11I1II1 / O0 * oO0o / iII111i / OoOoOO00
   if 15 - 15: ooOoO0o / oO0o
   if ( self . lisp_header . decode ( OO0Oo00OO0oo ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( OOO )
    if 54 - 54: ooOoO0o - iIii1I11I1II1 - I11i % Ii1I / II111iiii
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 80 - 80: i11iIiiIii % iIii1I11I1II1 / i11iIiiIii
   OO0Oo00OO0oo = OO0Oo00OO0oo [ 8 : : ]
   i1I1iI = self . lisp_header . get_instance_id ( )
   O0oooOO += 16
   if 66 - 66: OoOoOO00 . iIii1I11I1II1 * I1ii11iIi11i - Ii1I - iIii1I11I1II1
  if ( i1I1iI == 0xffffff ) : i1I1iI = 0
  if 28 - 28: OoOoOO00 % OoooooooOO
  if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
  if 84 - 84: II111iiii
  if 57 - 57: O0 * iIii1I11I1II1 % O0 . OoooooooOO
  O00O = False
  IIIIIi1 = self . lisp_header . k_bits
  if ( IIIIIi1 ) :
   O00oO000Oo0 = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( O00oO000Oo0 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( OOO )
    if 82 - 82: I1Ii111 . i1IIi / oO0o
    self . print_packet ( "Receive" , is_lisp_packet )
    oooooo0Oo00o = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( oooooo0Oo00o , IIIIIi1 ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 77 - 77: OOooOOo % i11iIiiIii - I1ii11iIi11i
    if 21 - 21: I11i . Oo0Ooo - OoooooooOO * i1IIi
   OoOOooOOoo = lisp_crypto_keys_by_rloc_decap [ O00oO000Oo0 ] [ IIIIIi1 ]
   if ( OoOOooOOoo == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( OOO )
    if 12 - 12: oO0o . OOooOOo
    self . print_packet ( "Receive" , is_lisp_packet )
    oooooo0Oo00o = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( oooooo0Oo00o ,
 red ( O00oO000Oo0 , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 52 - 52: i11iIiiIii / I11i % IiII
    if 21 - 21: iII111i % IiII % Oo0Ooo % O0
    if 63 - 63: II111iiii * I1IiiI - OoooooooOO / I1IiiI
    if 50 - 50: OoOoOO00 % Ii1I + OoOoOO00 * Ii1I - OOooOOo
    if 94 - 94: iIii1I11I1II1
   OoOOooOOoo . use_count += 1
   OO0Oo00OO0oo , O00O = self . decrypt ( OO0Oo00OO0oo , O0oooOO , OoOOooOOoo , O00oO000Oo0 )
   if ( O00O == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( OOO )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 1 - 1: O0
    if 2 - 2: OoO0O00 . I11i
    if 97 - 97: Oo0Ooo
    if 65 - 65: Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1 . I1Ii111 + ooOoO0o
    if 92 - 92: oO0o
    if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
   if ( OoOOooOOoo . cipher_suite == LISP_CS_25519_CHACHA ) :
    OO0Oo00OO0oo = OO0Oo00OO0oo . encode ( "raw_unicode_escape" )
    if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
    if 47 - 47: IiII . OOooOOo
    if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
    if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
    if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
    if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
  IIiIi1I1iI1 = struct . unpack ( "B" , OO0Oo00OO0oo [ 0 : 1 ] ) [ 0 ]
  self . inner_version = IIiIi1I1iI1 >> 4
  if ( O0OoO0oOOoo0 and self . inner_version == 4 and IIiIi1I1iI1 >= 0x45 ) :
   o0oOO00O000O0 = socket . ntohs ( struct . unpack ( "H" , OO0Oo00OO0oo [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , OO0Oo00OO0oo [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , OO0Oo00OO0oo [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , OO0Oo00OO0oo [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( OO0Oo00OO0oo [ 12 : 16 ] )
   self . inner_dest . unpack_address ( OO0Oo00OO0oo [ 16 : 20 ] )
   Iii11I1i = socket . ntohs ( struct . unpack ( "H" , OO0Oo00OO0oo [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( Iii11I1i & 0x2000 or Iii11I1i != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , OO0Oo00OO0oo [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , OO0Oo00OO0oo [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 89 - 89: o0oOOo0O0Ooo - II111iiii - I1Ii111 - OOooOOo % OoOoOO00 % I1IiiI
  elif ( O0OoO0oOOoo0 and self . inner_version == 6 and IIiIi1I1iI1 >= 0x60 ) :
   o0oOO00O000O0 = socket . ntohs ( struct . unpack ( "H" , OO0Oo00OO0oo [ 4 : 6 ] ) [ 0 ] ) + 40
   i1II1i1iiI1 = struct . unpack ( "H" , OO0Oo00OO0oo [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( i1II1i1iiI1 ) >> 4 ) & 0xff
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
  elif ( Oo000O000 ) :
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
   if ( stats ) : stats [ self . packet_error ] . increment ( OOO )
   if 41 - 41: oO0o . iII111i + OoooooooOO * Ii1I . o0oOOo0O0Ooo
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( IIiIi1I1iI1 ) ) )
   if 11 - 11: O0
   OO0Oo00OO0oo = lisp_format_packet ( OO0Oo00OO0oo [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( OO0Oo00OO0oo ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 96 - 96: iII111i + o0oOOo0O0Ooo
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = i1I1iI
  self . inner_dest . instance_id = i1I1iI
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
  if ( O00O ) : self . packet += OO0Oo00OO0oo [ : o0oOO00O000O0 ]
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
  II1Ii = 16
  II1Ii += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ II1Ii : : ]
  return ( self )
  if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
  if 89 - 89: OoooooooOO % II111iiii - OoO0O00 % i11iIiiIii
 def hash_ports ( self ) :
  OO0Oo00OO0oo = self . packet
  IIiIi1I1iI1 = self . inner_version
  iiIIII11iIii = 0
  if ( IIiIi1I1iI1 == 4 ) :
   O0000O = struct . unpack ( "B" , OO0Oo00OO0oo [ 9 : 10 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( O0000O )
   if ( O0000O in [ 6 , 17 ] ) :
    iiIIII11iIii = O0000O
    iiIIII11iIii += struct . unpack ( "I" , OO0Oo00OO0oo [ 20 : 24 ] ) [ 0 ]
    iiIIII11iIii = ( iiIIII11iIii >> 16 ) ^ ( iiIIII11iIii & 0xffff )
    if 67 - 67: O0 + I1IiiI + oO0o - II111iiii
    if 27 - 27: o0oOOo0O0Ooo / I1IiiI
  if ( IIiIi1I1iI1 == 6 ) :
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
   oOo0OoOOOo0 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 39 - 39: OoOoOO00 + I1Ii111 % O0
   oOo0OoOOOo0 += bold ( "control-packet" , False ) + ": {} ..."
   if 26 - 26: ooOoO0o + OoOoOO00
   dprint ( oOo0OoOOOo0 . format ( bold ( s_or_r , False ) , red ( IIiii1I1I , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   oOo0OoOOOo0 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
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
  dprint ( oOo0OoOOOo0 . format ( bold ( s_or_r , False ) , red ( IIiii1I1I , False ) ,
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
  i1I1iI = str ( self . lisp_header . get_instance_id ( ) )
  if ( i1I1iI == "0" ) : return ( None )
  if ( i1I1iI not in lisp_iid_to_interface ) : return ( None )
  if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
  OoO00OooO0 = lisp_iid_to_interface [ i1I1iI ]
  OOo0oOO0o0oo0 = OoO00OooO0 . get_socket ( )
  if ( OOo0oOO0o0oo0 == None ) :
   ii1111Iii11i = bold ( "SO_BINDTODEVICE" , False )
   IIIiii = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( ii1111Iii11i , "drop" if IIIiii else "forward" ) )
   if 44 - 44: IiII . I11i % I1IiiI - i1IIi
   if ( IIIiii ) : return ( None )
   if 2 - 2: OoOoOO00 + OoOoOO00
   if 47 - 47: OoO0O00 + I1Ii111 . I1Ii111 * O0 / Oo0Ooo + OOooOOo
  i1I1iI = bold ( i1I1iI , False )
  oooOo = bold ( OoO00OooO0 . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( i1I1iI , oooOo ) )
  return ( OOo0oOO0o0oo0 )
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
  iIiIIIIIii = datetime . datetime . now ( )
  lisp_flow_log . append ( [ iIiIIIIIii , encap , self . packet , self ] )
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
  oOo0OoOOOo0 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 71 - 71: IiII * o0oOOo0O0Ooo
  return ( oOo0OoOOOo0 . format ( bold ( e_or_d , False ) ,
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
  oOOo0OOoOO0 = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , OO )
  lisp_ipc ( ipc , ipc_socket , oOOo0OOoOO0 )
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
    I1II1I1I = "exit"
    self . request_nonce_sent = None
   else :
    I1II1I1I = "stay in"
    self . echo_nonce_sent = None
    if 92 - 92: Oo0Ooo % o0oOOo0O0Ooo - ooOoO0o / ooOoO0o / OoOoOO00
    if 84 - 84: OOooOOo
   I1 = bold ( "collision" , False )
   i1II1IIiIi1 = red ( i11iIi1I1i1 . print_address_no_iid ( ) , False )
   I1I1 = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( I1 ,
 i1II1IIiIi1 , I1I1 , I1II1I1I ) )
   if 26 - 26: Oo0Ooo % i1IIi
   if 15 - 15: O0
   if 60 - 60: Ii1I % oO0o - I1ii11iIi11i / oO0o
   if 20 - 20: I1IiiI + i1IIi
   if 89 - 89: ooOoO0o % oO0o * Ii1I - Oo0Ooo / o0oOOo0O0Ooo + OoO0O00
  if ( self . echo_nonce_sent != None ) :
   OOO0O0O = self . echo_nonce_sent
   oOO = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( oOO ,
 lisp_hex_string ( OOO0O0O ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( OOO0O0O )
   if 56 - 56: i11iIiiIii * iII111i / i11iIiiIii * Ii1I . iIii1I11I1II1 . I1ii11iIi11i
   if 93 - 93: OoOoOO00 + I11i
   if 27 - 27: iIii1I11I1II1 * I11i
   if 42 - 42: oO0o
   if 22 - 22: iIii1I11I1II1 % I1IiiI . O0
   if 13 - 13: II111iiii % i1IIi - OoOoOO00 + iII111i
   if 59 - 59: OoooooooOO + I1Ii111 % o0oOOo0O0Ooo - OoOoOO00 . I1IiiI
  OOO0O0O = self . request_nonce_sent
  i11iII11I1III = self . last_request_nonce_sent
  if ( OOO0O0O and i11iII11I1III != None ) :
   if ( time . time ( ) - i11iII11I1III >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OOO0O0O ) ) )
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
  if ( OOO0O0O == None ) :
   OOO0O0O = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( OOO0O0O )
   if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
   self . request_nonce_sent = OOO0O0O
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OOO0O0O ) ) )
   if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
   if 65 - 65: I1ii11iIi11i / ooOoO0o
   if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
   if 57 - 57: iII111i
   if 29 - 29: I1IiiI
   if ( lisp_i_am_itr == False ) : return ( OOO0O0O | 0x80000000 )
   self . send_request_ipc ( ipc_socket , OOO0O0O )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OOO0O0O ) ) )
   if 41 - 41: I1Ii111 * OoO0O00 - iII111i . Ii1I
   if 41 - 41: iIii1I11I1II1 - O0 - I1ii11iIi11i - oO0o + I1Ii111
   if 22 - 22: O0 % IiII % iII111i % I1IiiI
   if 34 - 34: iII111i . Oo0Ooo % I1ii11iIi11i . iII111i % IiII / IiII
   if 84 - 84: Ii1I
   if 1 - 1: oO0o - Oo0Ooo * iIii1I11I1II1 * Oo0Ooo * i1IIi
   if 9 - 9: iII111i - iII111i
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( OOO0O0O | 0x80000000 )
  if 3 - 3: O0 + O0 - O0 - O0 % OoooooooOO + oO0o
  if 20 - 20: OoO0O00 + I11i . II111iiii / i11iIiiIii
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
  o0oOOOO0 = time . time ( ) - self . last_request_nonce_sent
  IIIIi11111 = self . last_echo_nonce_rcvd
  return ( o0oOOOO0 >= LISP_NONCE_ECHO_INTERVAL and IIIIi11111 == None )
  if 99 - 99: O0 * i11iIiiIii % OOooOOo * II111iiii
  if 98 - 98: O0 + iIii1I11I1II1
 def recently_requested ( self ) :
  IIIIi11111 = self . last_request_nonce_sent
  if ( IIIIi11111 == None ) : return ( False )
  if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
  o0oOOOO0 = time . time ( ) - IIIIi11111
  return ( o0oOOOO0 <= LISP_NONCE_ECHO_INTERVAL )
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
  o0oOOOO0 = time . time ( ) - IIIIi11111
  if ( o0oOOOO0 <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 83 - 83: OoooooooOO
  if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
  if 88 - 88: OOooOOo / i11iIiiIii / Ii1I / i11iIiiIii * I1ii11iIi11i % I11i
  if 43 - 43: OoOoOO00 * OoO0O00 % i1IIi * Ii1I + iIii1I11I1II1
  if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
  if 63 - 63: ooOoO0o . OOooOOo
  IIIIi11111 = self . last_new_request_nonce_sent
  if ( IIIIi11111 == None ) : IIIIi11111 = 0
  o0oOOOO0 = time . time ( ) - IIIIi11111
  return ( o0oOOOO0 <= LISP_NONCE_ECHO_INTERVAL )
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
  OOo0oOO0o0oo0 = space ( 4 )
  if 56 - 56: I1IiiI
  i11IiIIi11I = "Nonce-Echoing:\n"
  i11IiIIi11I += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( OOo0oOO0o0oo0 , oOOO , OOo0oOO0o0oo0 , Iii111111 )
  if 49 - 49: i1IIi % oO0o / OOooOOo . I1ii11iIi11i - I1Ii111
  i11IiIIi11I += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( OOo0oOO0o0oo0 , IiII11 , OOo0oOO0o0oo0 , oO0o0o0OO0o00 )
  if 12 - 12: i11iIiiIii + I11i - I1ii11iIi11i
  if 27 - 27: iII111i
  return ( i11IiIIi11I )
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
   OoOOooOOoo = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( OoOOooOOoo . encode ( ) )
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
  oO0o000oOO = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   oO0o000oOO = struct . pack ( "Q" , oO0o000oOO & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   o00oOOO = struct . pack ( "I" , ( oO0o000oOO >> 64 ) & LISP_4_32_MASK )
   OoOOOo0 = struct . pack ( "Q" , oO0o000oOO & LISP_8_64_MASK )
   oO0o000oOO = o00oOOO + OoOOOo0
  else :
   oO0o000oOO = struct . pack ( "QQ" , oO0o000oOO >> 64 , oO0o000oOO & LISP_8_64_MASK )
  return ( oO0o000oOO )
  if 53 - 53: o0oOOo0O0Ooo / I11i % O0 / iIii1I11I1II1 / iII111i
  if 1 - 1: Oo0Ooo . i11iIiiIii
 def key_length ( self , key ) :
  if ( isinstance ( key , int ) ) : key = self . normalize_pub_key ( key )
  return ( old_div ( len ( key ) , 2 ) )
  if 9 - 9: OoooooooOO / I11i
  if 47 - 47: OoooooooOO
 def print_key ( self , key ) :
  iIiI1111 = self . normalize_pub_key ( key )
  II1 = iIiI1111 [ 0 : 4 ] . decode ( )
  o0OOO = iIiI1111 [ - 4 : : ] . decode ( )
  return ( "0x{}...{}({})" . format ( II1 , o0OOO , self . key_length ( iIiI1111 ) ) )
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
  i1II1IIiIi1 = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   i1II1IIiIi1 += "none"
  else :
   i1II1IIiIi1 += self . print_key ( self . local_public_key )
   if 25 - 25: i1IIi * I1IiiI - OoOoOO00 + oO0o
  I1I1 = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   I1I1 += "none"
  else :
   I1I1 += self . print_key ( self . remote_public_key )
   if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
  i1Iiiiii1II = "ECDH" if ( self . curve25519 ) else "DH"
  i1iII1i = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( i1Iiiiii1II , i1iII1i , i1II1IIiIi1 , I1I1 ) )
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
  OoOOooOOoo = self . local_private_key
  II11iIIii = self . dh_g_value
  III1ii = self . dh_p_value
  return ( int ( ( II11iIIii ** OoOOooOOoo ) % III1ii ) )
  if 35 - 35: I1IiiI
  if 48 - 48: OoooooooOO % OoooooooOO - OoO0O00 . OoOoOO00
 def compute_shared_key ( self , ed , print_shared = False ) :
  OoOOooOOoo = self . local_private_key
  I1i = self . remote_public_key
  if 5 - 5: OoooooooOO
  i1IIIiI1ii = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( i1IIIiI1ii , self . print_keys ( ) ) )
  if 41 - 41: OoooooooOO
  if ( self . curve25519 ) :
   I1I111i = curve25519 . Public ( I1i )
   self . shared_key = self . curve25519 . get_shared_key ( I1I111i )
  else :
   III1ii = self . dh_p_value
   self . shared_key = ( I1i ** OoOOooOOoo ) % III1ii
   if 63 - 63: I1ii11iIi11i . I1IiiI + OOooOOo - IiII + iII111i
   if 78 - 78: Ii1I
   if 29 - 29: II111iiii
   if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
   if 84 - 84: Oo0Ooo % I11i * O0 * I11i
   if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
   if 12 - 12: Oo0Ooo + I1IiiI
  if ( print_shared ) :
   iIiI1111 = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( iIiI1111 ) )
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
  ooOoii = hashlib . sha256
  if ( self . curve25519 ) :
   ooo0o0oO = self . shared_key
  else :
   ooo0o0oO = lisp_hex_string ( self . shared_key )
   if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
   if 1 - 1: IiII % i1IIi
   if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
   if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
   if 80 - 80: I1ii11iIi11i
  i1II1IIiIi1 = self . local_public_key
  if ( type ( i1II1IIiIi1 ) != int ) : i1II1IIiIi1 = int ( binascii . hexlify ( i1II1IIiIi1 ) , 16 )
  I1I1 = self . remote_public_key
  if ( type ( I1I1 ) != int ) : I1I1 = int ( binascii . hexlify ( I1I1 ) , 16 )
  ooOOO = "0001" + "lisp-crypto" + lisp_hex_string ( i1II1IIiIi1 ^ I1I1 ) + "0100"
  if 95 - 95: I11i
  Oooo0o0oO = hmac . new ( ooOOO . encode ( ) , ooo0o0oO , ooOoii ) . hexdigest ( )
  Oooo0o0oO = int ( Oooo0o0oO , 16 )
  if 51 - 51: iII111i / I1Ii111 % oO0o + oO0o * oO0o
  if 20 - 20: iII111i % I1ii11iIi11i + OoO0O00 / Oo0Ooo
  if 10 - 10: i11iIiiIii / OoOoOO00
  if 27 - 27: I1IiiI / OoooooooOO
  OOO00Oo00o = ( Oooo0o0oO >> 128 ) & LISP_16_128_MASK
  IiII1Iiii = Oooo0o0oO & LISP_16_128_MASK
  OOO00Oo00o = lisp_hex_string ( OOO00Oo00o ) . zfill ( 32 )
  self . encrypt_key = OOO00Oo00o . encode ( )
  I1o000o00OO00Oo = 32 if self . do_poly else 40
  IiII1Iiii = lisp_hex_string ( IiII1Iiii ) . zfill ( I1o000o00OO00Oo )
  self . icv_key = IiII1Iiii . encode ( )
  if 12 - 12: I11i * oO0o - I1Ii111 * iII111i - ooOoO0o * I1Ii111
  if 90 - 90: Ii1I . OoOoOO00
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   o0OOOOoo = self . icv . poly1305aes
   oO = self . icv . binascii . hexlify
   nonce = oO ( nonce )
   i1IiIiIii11I = o0OOOOoo ( self . encrypt_key , self . icv_key , nonce , packet )
   if ( lisp_is_python2 ( ) ) :
    i1IiIiIii11I = oO ( i1IiIiIii11I . encode ( "raw_unicode_escape" ) )
   else :
    i1IiIiIii11I = oO ( i1IiIiIii11I ) . decode ( )
    if 80 - 80: I1Ii111 + I11i . I1Ii111 + OOooOOo
  else :
   OoOOooOOoo = binascii . unhexlify ( self . icv_key )
   i1IiIiIii11I = hmac . new ( OoOOooOOoo , packet , self . icv ) . hexdigest ( )
   i1IiIiIii11I = i1IiIiIii11I [ 0 : 40 ]
   if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
  return ( i1IiIiIii11I )
  if 43 - 43: IiII . OoooooooOO - II111iiii
  if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
 def add_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
  if 15 - 15: Ii1I + OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
 def delete_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
  if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
 def add_key_by_rloc ( self , addr_str , encap ) :
  O0O000 = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 72 - 72: i1IIi
  if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
  if ( addr_str not in O0O000 ) :
   O0O000 [ addr_str ] = [ None , None , None , None ]
   if 28 - 28: iIii1I11I1II1 . O0
  O0O000 [ addr_str ] [ self . key_id ] = self
  if 32 - 32: OoooooooOO
  if 29 - 29: I1ii11iIi11i
  if 41 - 41: Ii1I
  if 49 - 49: Ii1I % II111iiii . Ii1I - o0oOOo0O0Ooo - I11i * IiII
  if 47 - 47: O0 . o0oOOo0O0Ooo / Ii1I * iII111i
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , O0O000 [ addr_str ] )
   if 63 - 63: I1Ii111 - oO0o - iII111i - ooOoO0o / oO0o + OoO0O00
   if 94 - 94: IiII / I1IiiI . II111iiii
   if 32 - 32: oO0o . OOooOOo % OOooOOo . OoOoOO00
 def encode_lcaf ( self , rloc_addr ) :
  I1Iii1 = self . normalize_pub_key ( self . local_public_key )
  I11iiI1i = self . key_length ( I1Iii1 )
  ooOoOO = ( 6 + I11iiI1i + 2 )
  if ( rloc_addr != None ) : ooOoOO += rloc_addr . addr_length ( )
  if 31 - 31: o0oOOo0O0Ooo
  OO0Oo00OO0oo = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( ooOoOO ) , 1 , 0 )
  if 59 - 59: Oo0Ooo / Oo0Ooo
  if 87 - 87: I1ii11iIi11i % OoOoOO00 + Ii1I . i11iIiiIii / Ii1I
  if 32 - 32: Ii1I + IiII + I1ii11iIi11i
  if 79 - 79: i1IIi / Ii1I
  if 81 - 81: iIii1I11I1II1
  if 86 - 86: IiII % IiII % OoooooooOO
  i1iII1i = self . cipher_suite
  OO0Oo00OO0oo += struct . pack ( "BBH" , i1iII1i , 0 , socket . htons ( I11iiI1i ) )
  if 42 - 42: Oo0Ooo . oO0o + O0 / OOooOOo % OoooooooOO
  if 19 - 19: ooOoO0o / Ii1I
  if 43 - 43: OoOoOO00 % Ii1I + Oo0Ooo - OoooooooOO . O0 % Oo0Ooo
  if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
  for o000o0O0Oo00 in range ( 0 , I11iiI1i * 2 , 16 ) :
   OoOOooOOoo = int ( I1Iii1 [ o000o0O0Oo00 : o000o0O0Oo00 + 16 ] , 16 )
   OO0Oo00OO0oo += struct . pack ( "Q" , byte_swap_64 ( OoOOooOOoo ) )
   if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
   if 88 - 88: I1Ii111 - OoO0O00
   if 79 - 79: iII111i
   if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
   if 48 - 48: I1ii11iIi11i + Oo0Ooo
  if ( rloc_addr ) :
   OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   OO0Oo00OO0oo += rloc_addr . pack_address ( )
   if 76 - 76: I1ii11iIi11i
  return ( OO0Oo00OO0oo )
  if 98 - 98: II111iiii + I1IiiI - I1ii11iIi11i . Ii1I
  if 51 - 51: Ii1I + i11iIiiIii * OoO0O00 % Oo0Ooo / I1IiiI - iIii1I11I1II1
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 20 - 20: I1Ii111 . I11i . Ii1I + I11i - OOooOOo * oO0o
  if 82 - 82: OoO0O00
  if 78 - 78: II111iiii / I11i - i11iIiiIii + I1ii11iIi11i * Oo0Ooo
  if 17 - 17: OoOoOO00
  if ( lcaf_len == 0 ) :
   Iii1iIII1Iii = "HHBBH"
   oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
   if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
   if 72 - 72: iII111i . Oo0Ooo - i11iIiiIii / I1IiiI
   Oooo0oOOOO , o0o0OoOo0 , o000O0OOo00O , o0o0OoOo0 , lcaf_len = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
   if 18 - 18: ooOoO0o * II111iiii
   if 43 - 43: o0oOOo0O0Ooo / O0 + i1IIi - I1ii11iIi11i % i11iIiiIii
   if ( o000O0OOo00O != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 69 - 69: OOooOOo % I1ii11iIi11i / OoOoOO00 . OOooOOo - IiII
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ oOoOo000Ooooo : : ]
   if 74 - 74: OoO0O00 - o0oOOo0O0Ooo - IiII . O0 % ooOoO0o
   if 32 - 32: OoOoOO00 . OoO0O00 / Oo0Ooo . i11iIiiIii
   if 9 - 9: I11i - II111iiii + I1Ii111 / oO0o % I1ii11iIi11i
   if 17 - 17: iIii1I11I1II1 - ooOoO0o
   if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
   if 52 - 52: I1ii11iIi11i
  o000O0OOo00O = LISP_LCAF_SECURITY_TYPE
  Iii1iIII1Iii = "BBBBH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 93 - 93: iII111i . i11iIiiIii
  I1i1I , o0o0OoOo0 , i1iII1i , o0o0OoOo0 , I11iiI1i = struct . unpack ( Iii1iIII1Iii ,
 packet [ : oOoOo000Ooooo ] )
  if 64 - 64: iII111i - Oo0Ooo + O0 . Oo0Ooo / Ii1I
  if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
  if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
  if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  if 44 - 44: i11iIiiIii
  if 69 - 69: OOooOOo * O0 + i11iIiiIii
  packet = packet [ oOoOo000Ooooo : : ]
  I11iiI1i = socket . ntohs ( I11iiI1i )
  if ( len ( packet ) < I11iiI1i ) : return ( None )
  if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
  if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
  if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
  if 63 - 63: oO0o
  OOOOoO0O = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( i1iII1i not in OOOOoO0O ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( OOOOoO0O ,
 i1iII1i ) )
   packet = packet [ I11iiI1i : : ]
   return ( packet )
   if 79 - 79: i11iIiiIii
   if 81 - 81: iII111i + IiII - i11iIiiIii
  self . cipher_suite = i1iII1i
  if 60 - 60: I1Ii111
  if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
  if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
  if 14 - 14: Ii1I - O0
  if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
  I1Iii1 = 0
  for o000o0O0Oo00 in range ( 0 , I11iiI1i , 8 ) :
   OoOOooOOoo = byte_swap_64 ( struct . unpack ( "Q" , packet [ o000o0O0Oo00 : o000o0O0Oo00 + 8 ] ) [ 0 ] )
   I1Iii1 <<= 64
   I1Iii1 |= OoOOooOOoo
   if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
  self . remote_public_key = I1Iii1
  if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
  if 7 - 7: IiII * ooOoO0o + OoOoOO00
  if 22 - 22: iII111i
  if 48 - 48: I1ii11iIi11i . I1IiiI
  if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
  if ( self . curve25519 ) :
   OoOOooOOoo = lisp_hex_string ( self . remote_public_key )
   OoOOooOOoo = OoOOooOOoo . zfill ( 64 )
   i111II = b""
   for o000o0O0Oo00 in range ( 0 , len ( OoOOooOOoo ) , 2 ) :
    i11iI1I1 = int ( OoOOooOOoo [ o000o0O0Oo00 : o000o0O0Oo00 + 2 ] , 16 )
    i111II += lisp_store_byte ( i11iI1I1 )
    if 89 - 89: iII111i
   self . remote_public_key = i111II
   if 9 - 9: IiII . I11i
   if 23 - 23: O0 % OoooooooOO - O0 . I1IiiI + i11iIiiIii
  packet = packet [ I11iiI1i : : ]
  return ( packet )
  if 96 - 96: ooOoO0o % O0
  if 51 - 51: I1IiiI - iII111i / I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i
  if 87 - 87: II111iiii . Ii1I * OoO0O00
  if 74 - 74: o0oOOo0O0Ooo % OoOoOO00 . iII111i % I1Ii111 . O0 % II111iiii
  if 5 - 5: oO0o - OoooooooOO / OoOoOO00
  if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
  if 55 - 55: OoO0O00
  if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
  if 32 - 32: Ii1I * oO0o
def lisp_store_byte_py2 ( byte ) :
 return ( chr ( byte ) )
 if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
def lisp_store_byte_py3 ( byte ) :
 return ( bytes ( [ byte ] ) )
 if 28 - 28: Oo0Ooo
 if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
lisp_store_byte = lisp_store_byte_py2
if ( lisp_is_python3 ( ) ) : lisp_store_byte = lisp_store_byte_py3
if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
if 69 - 69: I11i
if 17 - 17: I11i
if 38 - 38: I1Ii111 % OOooOOo
if 9 - 9: O0 . iIii1I11I1II1
class lisp_thread ( object ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
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
  if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
  if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
 def decode ( self , packet ) :
  Iii1iIII1Iii = "BBBBQ"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( False )
  if 93 - 93: ooOoO0o % I1Ii111
  II1I11iIIIii1 , I11iIIiIIiIi , ii1IiI , self . record_count , self . nonce = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 96 - 96: Ii1I
  if 73 - 73: I1Ii111 + Ii1I
  self . type = II1I11iIIIii1 >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( II1I11iIIIii1 & 0x01 ) else False
   self . rloc_probe = True if ( II1I11iIIIii1 & 0x02 ) else False
   self . smr_invoked_bit = True if ( I11iIIiIIiIi & 0x40 ) else False
   if 53 - 53: OOooOOo % OoO0O00 - o0oOOo0O0Ooo % Oo0Ooo / O0 - I1ii11iIi11i
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( II1I11iIIIii1 & 0x04 ) else False
   self . to_etr = True if ( II1I11iIIIii1 & 0x02 ) else False
   self . to_ms = True if ( II1I11iIIIii1 & 0x01 ) else False
   if 32 - 32: OoOoOO00 % O0 % i11iIiiIii - ooOoO0o . I1IiiI
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( II1I11iIIIii1 & 0x08 ) else False
   if 24 - 24: oO0o % o0oOOo0O0Ooo / I1Ii111 + o0oOOo0O0Ooo
  return ( True )
  if 59 - 59: II111iiii % I1IiiI * O0 . OoooooooOO - OoooooooOO % O0
  if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 28 - 28: i1IIi / I11i . o0oOOo0O0Ooo
  if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
  if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 10 - 10: II111iiii . OOooOOo / iII111i
  if 35 - 35: iII111i / Oo0Ooo + O0 * iIii1I11I1II1 - O0
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 3 - 3: I1ii11iIi11i
  if 42 - 42: I11i % Oo0Ooo + IiII - I11i . iIii1I11I1II1 - Ii1I
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
  if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
  if 66 - 66: ooOoO0o + oO0o % OoooooooOO
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
  if 17 - 17: IiII
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 73 - 73: I1ii11iIi11i
  if 92 - 92: i11iIiiIii + O0 * I11i
  if 60 - 60: o0oOOo0O0Ooo / Oo0Ooo
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
  if 19 - 19: iIii1I11I1II1 . OoO0O00 / OoooooooOO
  if 2 - 2: O0 - O0 % I1Ii111 / I1ii11iIi11i
 def print_map_register ( self ) :
  oOOOOOOooOOoO = lisp_hex_string ( self . xtr_id )
  if 78 - 78: OOooOOo
  oOo0OoOOOo0 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 68 - 68: ooOoO0o
  lprint ( oOo0OoOOOo0 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # o0oOOo0O0Ooo * o0oOOo0O0Ooo + iII111i + I1Ii111 * OOooOOo
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , oOOOOOOooOOoO , self . site_id ) )
  if 91 - 91: iIii1I11I1II1 / Ii1I . OoooooooOO / OOooOOo * Ii1I
  if 64 - 64: i11iIiiIii . iIii1I11I1II1
  if 7 - 7: OoOoOO00 % ooOoO0o + OoOoOO00 - OoOoOO00 * i11iIiiIii % OoO0O00
  if 57 - 57: OOooOOo / OoO0O00 + I1ii11iIi11i
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
   if 60 - 60: O0 * Oo0Ooo % OOooOOo + IiII . OoO0O00 . Oo0Ooo
   if 70 - 70: I11i . I1ii11iIi11i * oO0o
   if 97 - 97: oO0o . iIii1I11I1II1 - OOooOOo
   if 23 - 23: I1ii11iIi11i % I11i
   if 18 - 18: OoooooooOO . i1IIi + II111iiii
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 99 - 99: I1Ii111 - I1ii11iIi11i - I1IiiI - I1Ii111 + OoO0O00 + II111iiii
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 34 - 34: I1Ii111 * I11i
    if 31 - 31: IiII . oO0o
    if 40 - 40: Ii1I - I11i / II111iiii * i1IIi + IiII * II111iiii
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  OO0Oo00OO0oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 53 - 53: I1ii11iIi11i - i11iIiiIii . OoO0O00 / OoOoOO00 - I1Ii111
  OO0Oo00OO0oo = self . zero_auth ( OO0Oo00OO0oo )
  return ( OO0Oo00OO0oo )
  if 99 - 99: Ii1I - IiII - i1IIi / i11iIiiIii . IiII
  if 58 - 58: OOooOOo
 def zero_auth ( self , packet ) :
  II1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  iiOO0O = b""
  IiiiiIi1iII1 = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   iiOO0O = struct . pack ( "QQI" , 0 , 0 , 0 )
   IiiiiIi1iII1 = struct . calcsize ( "QQI" )
   if 15 - 15: iIii1I11I1II1 + I11i . IiII + o0oOOo0O0Ooo * I1ii11iIi11i
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   iiOO0O = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   IiiiiIi1iII1 = struct . calcsize ( "QQQQ" )
   if 20 - 20: iII111i - I1ii11iIi11i * iII111i + I1Ii111
  packet = packet [ 0 : II1Ii ] + iiOO0O + packet [ II1Ii + IiiiiIi1iII1 : : ]
  return ( packet )
  if 61 - 61: Oo0Ooo / II111iiii / Oo0Ooo / i1IIi . Oo0Ooo - IiII
  if 30 - 30: OoooooooOO % OOooOOo
 def encode_auth ( self , packet ) :
  II1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  IiiiiIi1iII1 = self . auth_len
  iiOO0O = self . auth_data
  packet = packet [ 0 : II1Ii ] + iiOO0O + packet [ II1Ii + IiiiiIi1iII1 : : ]
  return ( packet )
  if 14 - 14: OoOoOO00 / OoO0O00 / i11iIiiIii - OoOoOO00 / o0oOOo0O0Ooo - OOooOOo
  if 81 - 81: iII111i % Ii1I . ooOoO0o
 def decode ( self , packet ) :
  OOo00o0oOO0o = packet
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  if 27 - 27: iII111i / i1IIi . iII111i % OoooooooOO * oO0o % II111iiii
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  oOOOoOO = socket . ntohl ( oOOOoOO [ 0 ] )
  packet = packet [ oOoOo000Ooooo : : ]
  if 40 - 40: I11i % Ii1I
  Iii1iIII1Iii = "QBBH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  if 76 - 76: ooOoO0o . oO0o
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 24 - 24: iIii1I11I1II1
  if 41 - 41: IiII / i1IIi / OoOoOO00 / OOooOOo . OoO0O00 % OoOoOO00
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( oOOOoOO & 0x08000000 ) else False
  if 94 - 94: IiII
  self . lisp_sec_present = True if ( oOOOoOO & 0x04000000 ) else False
  self . xtr_id_present = True if ( oOOOoOO & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( oOOOoOO & 0x800 ) else False
  self . map_register_refresh = True if ( oOOOoOO & 0x1000 ) else False
  self . merge_register_requested = True if ( oOOOoOO & 0x400 ) else False
  self . mobile_node = True if ( oOOOoOO & 0x200 ) else False
  self . map_notify_requested = True if ( oOOOoOO & 0x100 ) else False
  self . record_count = oOOOoOO & 0xff
  if 15 - 15: Ii1I - IiII / O0
  if 28 - 28: I1Ii111 . i1IIi / I1ii11iIi11i
  if 77 - 77: i11iIiiIii / I1Ii111 / i11iIiiIii % OoOoOO00 - I1Ii111
  if 80 - 80: I1Ii111 % OoOoOO00 . OoooooooOO . II111iiii % IiII
  self . encrypt_bit = True if oOOOoOO & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( oOOOoOO >> 14 ) & 0x7
   if 6 - 6: I1Ii111 % IiII / Ii1I + I1Ii111 . oO0o
   if 70 - 70: iIii1I11I1II1 / Ii1I
   if 61 - 61: O0 * o0oOOo0O0Ooo + I1Ii111 - OOooOOo . I1IiiI - IiII
   if 7 - 7: I1ii11iIi11i
   if 81 - 81: Oo0Ooo % II111iiii % o0oOOo0O0Ooo / I11i
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( OOo00o0oOO0o ) == False ) : return ( [ None , None ] )
   if 95 - 95: OoOoOO00 - O0 % OoooooooOO
   if 13 - 13: i11iIiiIii
  packet = packet [ oOoOo000Ooooo : : ]
  if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
  if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
  if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
  if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 69 - 69: Oo0Ooo * ooOoO0o
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
    if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
   IiiiiIi1iII1 = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    oOoOo000Ooooo = struct . calcsize ( "QQI" )
    if ( IiiiiIi1iII1 < oOoOo000Ooooo ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
    oo0Oooo0O , ooO0Oo , oO0ooo000 = struct . unpack ( "QQI" , packet [ : IiiiiIi1iII1 ] )
    i11II = b""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    oOoOo000Ooooo = struct . calcsize ( "QQQQ" )
    if ( IiiiiIi1iII1 < oOoOo000Ooooo ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 47 - 47: OoO0O00 . I11i % ooOoO0o - Oo0Ooo . I1IiiI
    oo0Oooo0O , ooO0Oo , oO0ooo000 , i11II = struct . unpack ( "QQQQ" ,
 packet [ : IiiiiIi1iII1 ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 26 - 26: I1ii11iIi11i - i1IIi . OOooOOo . Ii1I
    return ( [ None , None ] )
    if 5 - 5: IiII - I11i
   self . auth_data = lisp_concat_auth_data ( self . alg_id , oo0Oooo0O , ooO0Oo ,
 oO0ooo000 , i11II )
   OOo00o0oOO0o = self . zero_auth ( OOo00o0oOO0o )
   packet = packet [ self . auth_len : : ]
   if 16 - 16: IiII . iII111i . Oo0Ooo % OOooOOo / IiII
  return ( [ OOo00o0oOO0o , packet ] )
  if 72 - 72: o0oOOo0O0Ooo * ooOoO0o - i11iIiiIii / Ii1I
  if 11 - 11: O0 - I1IiiI
 def encode_xtr_id ( self , packet ) :
  ii1i11III1I1 = self . xtr_id >> 64
  O000o = self . xtr_id & 0xffffffffffffffff
  ii1i11III1I1 = byte_swap_64 ( ii1i11III1I1 )
  O000o = byte_swap_64 ( O000o )
  iiI1I = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , ii1i11III1I1 , O000o , iiI1I )
  return ( packet )
  if 15 - 15: OoooooooOO
  if 31 - 31: II111iiii
 def decode_xtr_id ( self , packet ) :
  oOoOo000Ooooo = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - oOoOo000Ooooo : : ]
  ii1i11III1I1 , O000o , iiI1I = struct . unpack ( "QQQ" ,
 packet [ : oOoOo000Ooooo ] )
  ii1i11III1I1 = byte_swap_64 ( ii1i11III1I1 )
  O000o = byte_swap_64 ( O000o )
  self . xtr_id = ( ii1i11III1I1 << 64 ) | O000o
  self . site_id = byte_swap_64 ( iiI1I )
  return ( True )
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
  if 99 - 99: ooOoO0o . Ii1I
  if 92 - 92: i1IIi
 def print_notify ( self ) :
  iiOO0O = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( iiOO0O ) != 40 ) :
   iiOO0O = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( iiOO0O ) != 64 ) :
   iiOO0O = self . auth_data
   if 68 - 68: OoO0O00 % IiII - oO0o - ooOoO0o . Oo0Ooo
  oOo0OoOOOo0 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( oOo0OoOOOo0 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # Ii1I - OoooooooOO
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , iiOO0O ) )
  if 44 - 44: ooOoO0o * I1ii11iIi11i + OoOoOO00 - I11i
  if 2 - 2: OoOoOO00
  if 42 - 42: iIii1I11I1II1 . OoO0O00 % iIii1I11I1II1 * i1IIi
  if 92 - 92: iIii1I11I1II1 * I1ii11iIi11i
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   iiOO0O = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 5 - 5: ooOoO0o - I1Ii111 - iII111i
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   iiOO0O = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 38 - 38: iIii1I11I1II1 . Ii1I
  packet += iiOO0O
  return ( packet )
  if 12 - 12: OoO0O00 - I1IiiI + OoooooooOO + OoooooooOO * I1IiiI - i1IIi
  if 64 - 64: i11iIiiIii + OoOoOO00 + o0oOOo0O0Ooo + OOooOOo
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   oOOOoOO = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   oOOOoOO = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 33 - 33: I1IiiI - iII111i . i1IIi / i11iIiiIii
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  OO0Oo00OO0oo += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 84 - 84: I11i / OoooooooOO / IiII % I11i . OOooOOo + I1Ii111
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = OO0Oo00OO0oo + eid_records
   return ( self . packet )
   if 94 - 94: I11i
   if 48 - 48: oO0o - OoooooooOO + o0oOOo0O0Ooo % i1IIi - I1IiiI + OOooOOo
   if 56 - 56: I1IiiI - OOooOOo
   if 35 - 35: OoO0O00 / I1IiiI * O0 + I1IiiI . O0
   if 86 - 86: I1IiiI
  OO0Oo00OO0oo = self . zero_auth ( OO0Oo00OO0oo )
  OO0Oo00OO0oo += eid_records
  if 10 - 10: OoOoOO00 / oO0o % Oo0Ooo
  iiIIII11iIii = lisp_hash_me ( OO0Oo00OO0oo , self . alg_id , password , False )
  if 15 - 15: I11i - iIii1I11I1II1 % Ii1I
  II1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  IiiiiIi1iII1 = self . auth_len
  self . auth_data = iiIIII11iIii
  OO0Oo00OO0oo = OO0Oo00OO0oo [ 0 : II1Ii ] + iiIIII11iIii + OO0Oo00OO0oo [ II1Ii + IiiiiIi1iII1 : : ]
  self . packet = OO0Oo00OO0oo
  return ( OO0Oo00OO0oo )
  if 47 - 47: iII111i / OoooooooOO - II111iiii
  if 91 - 91: OoOoOO00 + o0oOOo0O0Ooo
 def decode ( self , packet ) :
  OOo00o0oOO0o = packet
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 23 - 23: i1IIi
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  oOOOoOO = socket . ntohl ( oOOOoOO [ 0 ] )
  self . map_notify_ack = ( ( oOOOoOO >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = oOOOoOO & 0xff
  packet = packet [ oOoOo000Ooooo : : ]
  if 9 - 9: i1IIi % I1Ii111 - OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo
  Iii1iIII1Iii = "QBBH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 18 - 18: Ii1I . OoOoOO00 + iII111i . I1IiiI + OoooooooOO . OoO0O00
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 31 - 31: I1Ii111 - I11i
  if 49 - 49: iIii1I11I1II1 - iIii1I11I1II1 - OoOoOO00 + IiII / OoOoOO00
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ oOoOo000Ooooo : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 74 - 74: OoooooooOO + I1ii11iIi11i % O0
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 32 - 32: I1ii11iIi11i + I1ii11iIi11i
  if 89 - 89: ooOoO0o + oO0o + Ii1I - OOooOOo
  if 12 - 12: OoOoOO00 - o0oOOo0O0Ooo - I1Ii111 / I11i
  if 17 - 17: OoO0O00 - I1Ii111 - II111iiii / I1Ii111 / Ii1I
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 30 - 30: OOooOOo * I1ii11iIi11i % I1ii11iIi11i + iII111i * IiII
  IiiiiIi1iII1 = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oo0Oooo0O , ooO0Oo , oO0ooo000 = struct . unpack ( "QQI" , packet [ : IiiiiIi1iII1 ] )
   i11II = ""
   if 33 - 33: o0oOOo0O0Ooo + I11i * O0 * OoO0O00 . I1ii11iIi11i
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oo0Oooo0O , ooO0Oo , oO0ooo000 , i11II = struct . unpack ( "QQQQ" ,
 packet [ : IiiiiIi1iII1 ] )
   if 74 - 74: iII111i * iII111i * o0oOOo0O0Ooo / oO0o
  self . auth_data = lisp_concat_auth_data ( self . alg_id , oo0Oooo0O , ooO0Oo ,
 oO0ooo000 , i11II )
  if 91 - 91: i11iIiiIii . I1ii11iIi11i / II111iiii
  oOoOo000Ooooo = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( OOo00o0oOO0o [ : oOoOo000Ooooo ] )
  oOoOo000Ooooo += IiiiiIi1iII1
  packet += OOo00o0oOO0o [ oOoOo000Ooooo : : ]
  return ( packet )
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
  if 60 - 60: IiII / iIii1I11I1II1 + OoooooooOO - I1ii11iIi11i * i11iIiiIii
  if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
  if 47 - 47: Ii1I . OoOoOO00 . iIii1I11I1II1 . o0oOOo0O0Ooo
  if 39 - 39: o0oOOo0O0Ooo
  if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
  if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
  if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
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
  if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
  if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 8 - 8: I11i % ooOoO0o . iIii1I11I1II1
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 95 - 95: o0oOOo0O0Ooo + i11iIiiIii . I1ii11iIi11i . ooOoO0o . o0oOOo0O0Ooo
  if 93 - 93: iII111i
 def print_map_request ( self ) :
  oOOOOOOooOOoO = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   oOOOOOOooOOoO = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 55 - 55: II111iiii % o0oOOo0O0Ooo - OoO0O00
   if 48 - 48: ooOoO0o * iIii1I11I1II1 % OoOoOO00
   if 100 - 100: II111iiii - i11iIiiIii + OoO0O00 % ooOoO0o - iIii1I11I1II1 * i11iIiiIii
  oOo0OoOOOo0 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 30 - 30: OoO0O00 . OoO0O00 . Ii1I % Ii1I * i1IIi * oO0o
  lprint ( oOo0OoOOOo0 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # OoooooooOO . i1IIi / o0oOOo0O0Ooo - I1Ii111 / i11iIiiIii
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , oOOOOOOooOOoO ) )
  if 16 - 16: OoO0O00 * II111iiii
  O0o0O0 = self . keys
  for IiI1ii1ii in self . itr_rlocs :
   if ( IiI1ii1ii . afi == LISP_AFI_LCAF and self . json_telemetry != None ) :
    continue
    if 22 - 22: i11iIiiIii
   o0Ooo = red ( IiI1ii1ii . print_address_no_iid ( ) , False )
   lprint ( "  itr-rloc: afi {} {}{}" . format ( IiI1ii1ii . afi , o0Ooo ,
 "" if ( O0o0O0 == None ) else ", " + O0o0O0 [ 1 ] . print_keys ( ) ) )
   O0o0O0 = None
   if 1 - 1: Ii1I - iIii1I11I1II1 * Ii1I . i11iIiiIii
  if ( self . json_telemetry != None ) :
   lprint ( "  itr-rloc: afi {} telemetry: {}" . format ( LISP_AFI_LCAF ,
 self . json_telemetry ) )
   if 96 - 96: Ii1I + iII111i - OoOoOO00 . I11i * o0oOOo0O0Ooo - Ii1I
   if 73 - 73: Oo0Ooo - I11i - ooOoO0o / I1Ii111 * IiII
   if 55 - 55: i1IIi / I1Ii111 . iII111i
 def sign_map_request ( self , privkey ) :
  Oooo00oo0o = self . signature_eid . print_address ( )
  OoO00o = self . source_eid . print_address ( )
  o0oOo = self . target_eid . print_address ( )
  iiOO00O = lisp_hex_string ( self . nonce ) + OoO00o + o0oOo
  self . map_request_signature = privkey . sign ( iiOO00O . encode ( ) )
  iiO0OoO0OOO00 = binascii . b2a_base64 ( self . map_request_signature )
  iiO0OoO0OOO00 = { "source-eid" : OoO00o , "signature-eid" : Oooo00oo0o ,
 "signature" : iiO0OoO0OOO00 . decode ( ) }
  return ( json . dumps ( iiO0OoO0OOO00 ) )
  if 15 - 15: o0oOOo0O0Ooo . O0 - I1IiiI / i1IIi . oO0o * OoooooooOO
  if 32 - 32: ooOoO0o / II111iiii . O0 . ooOoO0o % I1IiiI - o0oOOo0O0Ooo
 def verify_map_request_sig ( self , pubkey ) :
  O00OoO0oo = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( O00OoO0oo ) )
   return ( False )
   if 47 - 47: OoO0O00 . i11iIiiIii
   if 9 - 9: OoOoOO00 - I11i . OoooooooOO % ooOoO0o
  OoO00o = self . source_eid . print_address ( )
  o0oOo = self . target_eid . print_address ( )
  iiOO00O = lisp_hex_string ( self . nonce ) + OoO00o + o0oOo
  pubkey = binascii . a2b_base64 ( pubkey )
  if 13 - 13: OoO0O00 * iIii1I11I1II1 + II111iiii - Oo0Ooo - OoOoOO00
  I111 = True
  try :
   OoOOooOOoo = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 76 - 76: ooOoO0o % I1IiiI
   I111 = False
   if 18 - 18: OoO0O00
   if 99 - 99: iII111i / oO0o . i11iIiiIii / I11i + i1IIi - I11i
  if ( I111 ) :
   try :
    iiOO00O = iiOO00O . encode ( )
    I111 = OoOOooOOoo . verify ( self . map_request_signature , iiOO00O )
   except :
    I111 = False
    if 50 - 50: i1IIi
    if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
    if 75 - 75: OoOoOO00
  oO00OO0Ooo00O = bold ( "passed" if I111 else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( oO00OO0Ooo00O , O00OoO0oo ) )
  return ( I111 )
  if 45 - 45: OoO0O00 * II111iiii * OoOoOO00 - OOooOOo % oO0o - Oo0Ooo
  if 4 - 4: o0oOOo0O0Ooo . OoOoOO00 - iIii1I11I1II1 / IiII / I1IiiI % I1IiiI
 def encode_json ( self , json_string ) :
  o000O0OOo00O = LISP_LCAF_JSON_TYPE
  Iiii1I = socket . htons ( LISP_AFI_LCAF )
  IIIi1I = socket . htons ( len ( json_string ) + 4 )
  i1i1IiIIIi1 = socket . htons ( len ( json_string ) )
  OO0Oo00OO0oo = struct . pack ( "HBBBBHH" , Iiii1I , 0 , 0 , o000O0OOo00O , 0 , IIIi1I ,
 i1i1IiIIIi1 )
  OO0Oo00OO0oo += json_string . encode ( )
  OO0Oo00OO0oo += struct . pack ( "H" , 0 )
  return ( OO0Oo00OO0oo )
  if 24 - 24: Ii1I % o0oOOo0O0Ooo
  if 87 - 87: o0oOOo0O0Ooo % iII111i / ooOoO0o - IiII + i11iIiiIii
 def encode ( self , probe_dest , probe_port ) :
  oOOOoOO = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  if 85 - 85: OoooooooOO * IiII . OOooOOo / iII111i / OoooooooOO
  oo0Oo0 = lisp_telemetry_configured ( ) if ( self . rloc_probe ) else None
  if ( oo0Oo0 != None ) : self . itr_rloc_count += 1
  oOOOoOO = oOOOoOO | ( self . itr_rloc_count << 8 )
  if 50 - 50: I11i
  if ( self . auth_bit ) : oOOOoOO |= 0x08000000
  if ( self . map_data_present ) : oOOOoOO |= 0x04000000
  if ( self . rloc_probe ) : oOOOoOO |= 0x02000000
  if ( self . smr_bit ) : oOOOoOO |= 0x01000000
  if ( self . pitr_bit ) : oOOOoOO |= 0x00800000
  if ( self . smr_invoked_bit ) : oOOOoOO |= 0x00400000
  if ( self . mobile_node ) : oOOOoOO |= 0x00200000
  if ( self . xtr_id_present ) : oOOOoOO |= 0x00100000
  if ( self . decent_nat_xtr ) : oOOOoOO |= 0x00008000
  if ( self . local_xtr ) : oOOOoOO |= 0x00004000
  if ( self . dont_reply_bit ) : oOOOoOO |= 0x00002000
  if 88 - 88: i1IIi * OOooOOo . iIii1I11I1II1
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  if 45 - 45: I1Ii111 - O0 . I1Ii111 / I1Ii111 / OoOoOO00
  if 12 - 12: OOooOOo
  if 75 - 75: OOooOOo + Ii1I + oO0o . Oo0Ooo
  if 93 - 93: OOooOOo * Ii1I - o0oOOo0O0Ooo . oO0o . iII111i
  if 64 - 64: Oo0Ooo / iIii1I11I1II1 . OoO0O00 / o0oOOo0O0Ooo / I11i
  if 3 - 3: OOooOOo - o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
  iiI1i111I1 = False
  iiIi11i1I1 = self . privkey_filename
  if ( iiIi11i1I1 != None and os . path . exists ( iiIi11i1I1 ) ) :
   o0OoO0 = open ( iiIi11i1I1 , "r" ) ; OoOOooOOoo = o0OoO0 . read ( ) ; o0OoO0 . close ( )
   try :
    OoOOooOOoo = ecdsa . SigningKey . from_pem ( OoOOooOOoo )
   except :
    return ( None )
    if 30 - 30: IiII . OoooooooOO * Oo0Ooo % ooOoO0o . oO0o
   OoOo00OO0o00 = self . sign_map_request ( OoOOooOOoo )
   iiI1i111I1 = True
  elif ( self . map_request_signature != None ) :
   iiO0OoO0OOO00 = binascii . b2a_base64 ( self . map_request_signature )
   OoOo00OO0o00 = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : iiO0OoO0OOO00 }
   OoOo00OO0o00 = json . dumps ( OoOo00OO0o00 )
   iiI1i111I1 = True
   if 37 - 37: iIii1I11I1II1 * I11i / IiII * Oo0Ooo % i11iIiiIii
  if ( iiI1i111I1 ) :
   OO0Oo00OO0oo += self . encode_json ( OoOo00OO0o00 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    OO0Oo00OO0oo += self . source_eid . lcaf_encode_iid ( )
   else :
    OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    OO0Oo00OO0oo += self . source_eid . pack_address ( )
    if 93 - 93: ooOoO0o + ooOoO0o
    if 65 - 65: OoooooooOO * I11i * oO0o % I1ii11iIi11i * II111iiii
    if 86 - 86: i11iIiiIii / I11i * iII111i - iII111i
    if 32 - 32: Oo0Ooo . O0
    if 48 - 48: I1ii11iIi11i % II111iiii + I11i
    if 25 - 25: IiII * o0oOOo0O0Ooo / I1IiiI . IiII % II111iiii
    if 50 - 50: OoOoOO00 * iII111i
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   O00oO000Oo0 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 59 - 59: I1IiiI * I1IiiI / I11i
   if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_encap ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ]
    if 92 - 92: o0oOOo0O0Ooo
    if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
    if 50 - 50: Oo0Ooo
    if 16 - 16: Ii1I - OoOoOO00 % Oo0Ooo / Ii1I . I11i + ooOoO0o
    if 78 - 78: iIii1I11I1II1 + OoO0O00 + i11iIiiIii
    if 21 - 21: Oo0Ooo + Ii1I % ooOoO0o + OoOoOO00 % I11i
    if 22 - 22: i1IIi / OoooooooOO . OoO0O00
  for IiI1ii1ii in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( IiI1ii1ii ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     O0o0O0 = lisp_keys ( 1 )
     self . keys = [ None , O0o0O0 , None , None ]
     if 83 - 83: I1IiiI - OoooooooOO + I1ii11iIi11i . Ii1I / o0oOOo0O0Ooo + ooOoO0o
    O0o0O0 = self . keys [ 1 ]
    O0o0O0 . add_key_by_nonce ( self . nonce )
    OO0Oo00OO0oo += O0o0O0 . encode_lcaf ( IiI1ii1ii )
   else :
    OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( IiI1ii1ii . afi ) )
    OO0Oo00OO0oo += IiI1ii1ii . pack_address ( )
    if 90 - 90: I1IiiI - i11iIiiIii
    if 42 - 42: OOooOOo . Oo0Ooo
    if 21 - 21: iII111i . I1IiiI / I11i
    if 97 - 97: iIii1I11I1II1 + i1IIi - o0oOOo0O0Ooo
    if 73 - 73: OoO0O00 - i11iIiiIii % I1Ii111 / Oo0Ooo - OoooooooOO % OOooOOo
    if 79 - 79: I1IiiI / o0oOOo0O0Ooo . Ii1I * I1ii11iIi11i + I11i
  if ( oo0Oo0 != None ) :
   iIiIIIIIii = str ( time . time ( ) )
   oo0Oo0 = lisp_encode_telemetry ( oo0Oo0 , io = iIiIIIIIii )
   self . json_telemetry = oo0Oo0
   OO0Oo00OO0oo += self . encode_json ( oo0Oo0 )
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
  Iii1iIII1Iii = "BB"
  OO0Oo00OO0oo += struct . pack ( Iii1iIII1Iii , OOOO0oo0o0O , OOOoOo0o0Ooo )
  if 81 - 81: I1Ii111
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
   if 45 - 45: OOooOOo * II111iiii * OoooooooOO / OoooooooOO * I1Ii111
   if 38 - 38: iII111i . OoooooooOO
   if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
   if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
   if 61 - 61: I11i
  if ( self . subscribe_bit ) : OO0Oo00OO0oo = self . encode_xtr_id ( OO0Oo00OO0oo )
  return ( OO0Oo00OO0oo )
  if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
  if 35 - 35: ooOoO0o
 def lcaf_decode_json ( self , packet ) :
  Iii1iIII1Iii = "BBBBHH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  Ii1Ii1Ii , Ooo0000o , o000O0OOo00O , ii11Ii1111 , IIIi1I , i1i1IiIIIi1 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 89 - 89: II111iiii . I1ii11iIi11i
  if 4 - 4: I1IiiI * OoooooooOO
  if ( o000O0OOo00O != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 21 - 21: OoooooooOO
  if 36 - 36: iII111i
  if 91 - 91: ooOoO0o + IiII . I1IiiI / I11i / IiII
  if 23 - 23: I1ii11iIi11i - OOooOOo - i1IIi
  IIIi1I = socket . ntohs ( IIIi1I )
  i1i1IiIIIi1 = socket . ntohs ( i1i1IiIIIi1 )
  packet = packet [ oOoOo000Ooooo : : ]
  if ( len ( packet ) < IIIi1I ) : return ( None )
  if ( IIIi1I != i1i1IiIIIi1 + 4 ) : return ( None )
  if 20 - 20: OoooooooOO / Oo0Ooo * OoO0O00 . o0oOOo0O0Ooo . I1IiiI
  if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
  if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
  if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
  OoOo00OO0o00 = packet [ 0 : i1i1IiIIIi1 ]
  packet = packet [ i1i1IiIIIi1 : : ]
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
  Iii1iIII1Iii = "H"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  Oooo0oOOOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if ( Oooo0oOOOO != 0 ) : return ( packet )
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
  Oooo0oOOOO = LISP_AFI_IPV4 if o0Ooo0Oooo0o . count ( "." ) == 3 else LISP_AFI_IPV6 if o0Ooo0Oooo0o . count ( ":" ) == 7 else None
  if 22 - 22: oO0o / II111iiii . OoOoOO00
  if ( Oooo0oOOOO == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( o0Ooo0Oooo0o ) )
   return ( None )
   if 9 - 9: i11iIiiIii + ooOoO0o . iIii1I11I1II1 * OoOoOO00
   if 4 - 4: I1Ii111 + iII111i % O0
  self . source_eid . afi = Oooo0oOOOO
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
  iiO0OoO0OOO00 = binascii . a2b_base64 ( OoOo00OO0o00 [ "signature" ] )
  self . map_request_signature = iiO0OoO0OOO00
  return ( packet )
  if 26 - 26: i11iIiiIii - II111iiii
  if 43 - 43: I1IiiI
 def decode ( self , packet , source , port ) :
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 35 - 35: ooOoO0o + OoOoOO00 * OoooooooOO - II111iiii
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  oOOOoOO = oOOOoOO [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if 19 - 19: i1IIi / Ii1I / OoOoOO00 . I1IiiI / Ii1I % o0oOOo0O0Ooo
  Iii1iIII1Iii = "Q"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 39 - 39: ooOoO0o - OoooooooOO
  OOO0O0O = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  packet = packet [ oOoOo000Ooooo : : ]
  if 88 - 88: i1IIi + iIii1I11I1II1 * i11iIiiIii - OoooooooOO % o0oOOo0O0Ooo
  oOOOoOO = socket . ntohl ( oOOOoOO )
  self . auth_bit = True if ( oOOOoOO & 0x08000000 ) else False
  self . map_data_present = True if ( oOOOoOO & 0x04000000 ) else False
  self . rloc_probe = True if ( oOOOoOO & 0x02000000 ) else False
  self . smr_bit = True if ( oOOOoOO & 0x01000000 ) else False
  self . pitr_bit = True if ( oOOOoOO & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( oOOOoOO & 0x00400000 ) else False
  self . mobile_node = True if ( oOOOoOO & 0x00200000 ) else False
  self . xtr_id_present = True if ( oOOOoOO & 0x00100000 ) else False
  self . decent_nat_xtr = True if ( oOOOoOO & 0x00008000 ) else False
  self . local_xtr = True if ( oOOOoOO & 0x00004000 ) else False
  self . dont_reply_bit = True if ( oOOOoOO & 0x00002000 ) else False
  self . itr_rloc_count = ( ( oOOOoOO >> 8 ) & 0x1f )
  self . record_count = oOOOoOO & 0xff
  self . nonce = OOO0O0O [ 0 ]
  if 74 - 74: ooOoO0o - i11iIiiIii
  if 34 - 34: IiII + I1Ii111 + Oo0Ooo / II111iiii
  if 33 - 33: Ii1I . i1IIi - II111iiii - OoO0O00
  if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
   if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
  oOoOo000Ooooo = struct . calcsize ( "H" )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 52 - 52: O0 . I1Ii111 + iII111i / i11iIiiIii
  Oooo0oOOOO = struct . unpack ( "H" , packet [ : oOoOo000Ooooo ] )
  self . source_eid . afi = socket . ntohs ( Oooo0oOOOO [ 0 ] )
  packet = packet [ oOoOo000Ooooo : : ]
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
   oOoOo000Ooooo = struct . calcsize ( "H" )
   if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
   if 6 - 6: Ii1I - o0oOOo0O0Ooo % I11i + i11iIiiIii
   Oooo0oOOOO = socket . ntohs ( struct . unpack ( "H" , packet [ : oOoOo000Ooooo ] ) [ 0 ] )
   IiI1ii1ii = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   IiI1ii1ii . afi = Oooo0oOOOO
   if 40 - 40: O0 . Ii1I
   if 58 - 58: i11iIiiIii * iII111i / Ii1I - oO0o - I1ii11iIi11i % o0oOOo0O0Ooo
   if 16 - 16: OoooooooOO
   if 71 - 71: Ii1I % O0 / I1Ii111 % iII111i - II111iiii / OoO0O00
   if 30 - 30: I11i
   if ( IiI1ii1ii . afi == LISP_AFI_LCAF ) :
    OOo00o0oOO0o = packet
    O0o00o0Oo = packet [ oOoOo000Ooooo : : ]
    packet = self . lcaf_decode_json ( O0o00o0Oo )
    if ( packet == None ) : return ( None )
    if ( packet == O0o00o0Oo ) : packet = OOo00o0oOO0o
    if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
    if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
    if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
    if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
    if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
    if 64 - 64: IiII
   if ( IiI1ii1ii . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < IiI1ii1ii . addr_length ( ) ) : return ( None )
    packet = IiI1ii1ii . unpack_address ( packet [ oOoOo000Ooooo : : ] )
    if ( packet == None ) : return ( None )
    if 21 - 21: o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO
    if ( ooOo000 ) :
     self . itr_rlocs . append ( IiI1ii1ii )
     OO0o0oo -= 1
     continue
     if 17 - 17: OOooOOo - iII111i % I1IiiI * OOooOOo * iIii1I11I1II1 . o0oOOo0O0Ooo
     if 58 - 58: oO0o - II111iiii + O0
    O00oO000Oo0 = lisp_build_crypto_decap_lookup_key ( IiI1ii1ii , port )
    if 54 - 54: iIii1I11I1II1 - IiII - IiII
    if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
    if 63 - 63: iII111i - OoO0O00 * OOooOOo
    if 89 - 89: iII111i / Oo0Ooo
    if 66 - 66: o0oOOo0O0Ooo + OoOoOO00 % OoooooooOO . I11i
    if ( lisp_nat_traversal and IiI1ii1ii . is_private_address ( ) and source ) : IiI1ii1ii = source
    if 30 - 30: II111iiii - Oo0Ooo - i11iIiiIii + O0
    Ooo0OO0 = lisp_crypto_keys_by_rloc_decap
    if ( O00oO000Oo0 in Ooo0OO0 ) : Ooo0OO0 . pop ( O00oO000Oo0 )
    if 71 - 71: Ii1I + i11iIiiIii
    if 92 - 92: iIii1I11I1II1 + Ii1I
    if 69 - 69: Oo0Ooo
    if 70 - 70: O0 - OoO0O00 - Oo0Ooo
    if 95 - 95: IiII * II111iiii % o0oOOo0O0Ooo * Oo0Ooo . I11i
    if 46 - 46: II111iiii - OoO0O00 % ooOoO0o
    lisp_write_ipc_decap_key ( O00oO000Oo0 , None )
    if 97 - 97: OoO0O00 . OoOoOO00
   elif ( self . json_telemetry == None ) :
    if 78 - 78: I1ii11iIi11i + I1ii11iIi11i . OoOoOO00 - IiII * iIii1I11I1II1 * O0
    if 26 - 26: OoooooooOO + oO0o + OoO0O00 . O0
    if 46 - 46: OoooooooOO - Oo0Ooo * I1Ii111 * OOooOOo * I1Ii111 . oO0o
    if 96 - 96: Ii1I / IiII % o0oOOo0O0Ooo + I11i
    OOo00o0oOO0o = packet
    iIiiIi1111ii = lisp_keys ( 1 )
    packet = iIiiIi1111ii . decode_lcaf ( OOo00o0oOO0o , 0 )
    if 53 - 53: O0 % ooOoO0o
    if ( packet == None ) : return ( None )
    if 41 - 41: IiII
    if 29 - 29: ooOoO0o
    if 70 - 70: oO0o . O0 % I11i % IiII - I11i * I1ii11iIi11i
    if 22 - 22: i1IIi
    OOOOoO0O = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( iIiiIi1111ii . cipher_suite in OOOOoO0O ) :
     if ( iIiiIi1111ii . cipher_suite == LISP_CS_25519_CBC or
 iIiiIi1111ii . cipher_suite == LISP_CS_25519_GCM ) :
      OoOOooOOoo = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 82 - 82: oO0o . iIii1I11I1II1 - I1ii11iIi11i
     if ( iIiiIi1111ii . cipher_suite == LISP_CS_25519_CHACHA ) :
      OoOOooOOoo = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
    else :
     OoOOooOOoo = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 33 - 33: O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + iII111i - oO0o
    packet = OoOOooOOoo . decode_lcaf ( OOo00o0oOO0o , 0 )
    if ( packet == None ) : return ( None )
    if 27 - 27: I1Ii111 + ooOoO0o - I1Ii111 % i11iIiiIii * Oo0Ooo * o0oOOo0O0Ooo
    if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
    Oooo0oOOOO = struct . unpack ( "H" , packet [ : oOoOo000Ooooo ] ) [ 0 ]
    IiI1ii1ii . afi = socket . ntohs ( Oooo0oOOOO )
    if ( len ( packet ) < IiI1ii1ii . addr_length ( ) ) : return ( None )
    if 88 - 88: OOooOOo
    packet = IiI1ii1ii . unpack_address ( packet [ oOoOo000Ooooo : : ] )
    if ( packet == None ) : return ( None )
    if 25 - 25: OoO0O00 + o0oOOo0O0Ooo . ooOoO0o - Ii1I . oO0o * Ii1I
    if ( ooOo000 ) :
     self . itr_rlocs . append ( IiI1ii1ii )
     OO0o0oo -= 1
     continue
     if 85 - 85: i1IIi
     if 94 - 94: OoooooooOO . O0 / OoooooooOO
    O00oO000Oo0 = lisp_build_crypto_decap_lookup_key ( IiI1ii1ii , port )
    if 67 - 67: i11iIiiIii + OoOoOO00
    I1iII = None
    if ( lisp_nat_traversal and IiI1ii1ii . is_private_address ( ) and source ) : IiI1ii1ii = source
    if 97 - 97: I1IiiI
    if 63 - 63: O0 - OoOoOO00 / i11iIiiIii / OoooooooOO / ooOoO0o / II111iiii
    if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_decap ) :
     O0o0O0 = lisp_crypto_keys_by_rloc_decap [ O00oO000Oo0 ]
     I1iII = O0o0O0 [ 1 ] if O0o0O0 and O0o0O0 [ 1 ] else None
     if 45 - 45: II111iiii . OoO0O00 + OoO0O00 * iIii1I11I1II1
     if 23 - 23: IiII * OoOoOO00 % Ii1I / Ii1I - ooOoO0o - OOooOOo
    O00 = True
    if ( I1iII ) :
     if ( I1iII . compare_keys ( OoOOooOOoo ) ) :
      self . keys = [ None , I1iII , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( O00oO000Oo0 , False ) ) )
      if 17 - 17: II111iiii + ooOoO0o + iII111i . I1ii11iIi11i
     else :
      O00 = False
      i111i1 = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( i111i1 , red ( O00oO000Oo0 ,
 False ) ) )
      OoOOooOOoo . copy_keypair ( I1iII )
      OoOOooOOoo . uptime = I1iII . uptime
      I1iII = None
      if 27 - 27: OOooOOo - OOooOOo / i11iIiiIii * OoOoOO00 + O0
      if 2 - 2: i11iIiiIii % I1IiiI
      if 90 - 90: II111iiii
    if ( I1iII == None ) :
     self . keys = [ None , OoOOooOOoo , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      OoOOooOOoo . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( O00oO000Oo0 , False ) ) )
     elif ( OoOOooOOoo . remote_public_key != None ) :
      if ( O00 ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # Ii1I
 red ( O00oO000Oo0 , False ) ) )
       if 61 - 61: OoooooooOO - i11iIiiIii % Oo0Ooo / Ii1I % I11i
      OoOOooOOoo . compute_shared_key ( "decap" )
      OoOOooOOoo . add_key_by_rloc ( O00oO000Oo0 , False )
      if 4 - 4: o0oOOo0O0Ooo * I1Ii111 + OOooOOo - i11iIiiIii
      if 45 - 45: I1IiiI . I1IiiI - Oo0Ooo * OOooOOo
      if 71 - 71: i1IIi / I11i
      if 14 - 14: OoooooooOO
   self . itr_rlocs . append ( IiI1ii1ii )
   OO0o0oo -= 1
   if 99 - 99: o0oOOo0O0Ooo * o0oOOo0O0Ooo
   if 6 - 6: i11iIiiIii + oO0o % ooOoO0o + i11iIiiIii - OOooOOo
  oOoOo000Ooooo = struct . calcsize ( "BBH" )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 12 - 12: iII111i . oO0o % IiII * OoooooooOO . IiII
  OOOO0oo0o0O , OOOoOo0o0Ooo , Oooo0oOOOO = struct . unpack ( "BBH" , packet [ : oOoOo000Ooooo ] )
  self . subscribe_bit = ( OOOO0oo0o0O & 0x80 )
  self . target_eid . afi = socket . ntohs ( Oooo0oOOOO )
  packet = packet [ oOoOo000Ooooo : : ]
  if 15 - 15: I1IiiI . I1IiiI / i11iIiiIii
  self . target_eid . mask_len = OOOoOo0o0Ooo
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , iiII = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( iiII ) : self . target_group = iiII
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ oOoOo000Ooooo : : ]
   if 30 - 30: ooOoO0o % I1IiiI . oO0o
  return ( packet )
  if 48 - 48: OoOoOO00
  if 28 - 28: I11i / O0 * IiII - I1Ii111 % IiII
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 8 - 8: I11i / I1ii11iIi11i % I1ii11iIi11i % Ii1I + iII111i
  if 100 - 100: OoO0O00
 def encode_xtr_id ( self , packet ) :
  ii1i11III1I1 = self . xtr_id >> 64
  O000o = self . xtr_id & 0xffffffffffffffff
  ii1i11III1I1 = byte_swap_64 ( ii1i11III1I1 )
  O000o = byte_swap_64 ( O000o )
  packet += struct . pack ( "QQ" , ii1i11III1I1 , O000o )
  return ( packet )
  if 25 - 25: I1Ii111 - ooOoO0o + Oo0Ooo . I1IiiI % iIii1I11I1II1
  if 49 - 49: i1IIi + OoO0O00 + iII111i / Oo0Ooo
 def decode_xtr_id ( self , packet ) :
  oOoOo000Ooooo = struct . calcsize ( "QQ" )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  packet = packet [ len ( packet ) - oOoOo000Ooooo : : ]
  ii1i11III1I1 , O000o = struct . unpack ( "QQ" , packet [ : oOoOo000Ooooo ] )
  ii1i11III1I1 = byte_swap_64 ( ii1i11III1I1 )
  O000o = byte_swap_64 ( O000o )
  self . xtr_id = ( ii1i11III1I1 << 64 ) | O000o
  return ( True )
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
  if 62 - 62: o0oOOo0O0Ooo % II111iiii
  if 22 - 22: oO0o - o0oOOo0O0Ooo
class lisp_map_reply ( object ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 89 - 89: OOooOOo
  if 34 - 34: iII111i . OOooOOo
 def print_map_reply ( self ) :
  oOo0OoOOOo0 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 13 - 13: OoO0O00 * OOooOOo + oO0o
  lprint ( oOo0OoOOOo0 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # iIii1I11I1II1 * i11iIiiIii
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 84 - 84: i1IIi * Ii1I . oO0o + I1Ii111 % OoOoOO00
  if 47 - 47: OoO0O00 * I11i
 def encode ( self ) :
  oOOOoOO = ( LISP_MAP_REPLY << 28 ) | self . record_count
  oOOOoOO |= self . hop_count << 8
  if ( self . rloc_probe ) : oOOOoOO |= 0x08000000
  if ( self . echo_nonce_capable ) : oOOOoOO |= 0x04000000
  if ( self . security ) : oOOOoOO |= 0x02000000
  if 70 - 70: Oo0Ooo
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  return ( OO0Oo00OO0oo )
  if 93 - 93: iII111i . I1ii11iIi11i . Oo0Ooo . oO0o . OoooooooOO
  if 51 - 51: O0 - iII111i
 def decode ( self , packet ) :
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 65 - 65: O0 / II111iiii * IiII % Ii1I + o0oOOo0O0Ooo
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  oOOOoOO = oOOOoOO [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if 43 - 43: I1Ii111 + OoO0O00 * OoooooooOO
  Iii1iIII1Iii = "Q"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 85 - 85: iII111i + OOooOOo
  OOO0O0O = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  packet = packet [ oOoOo000Ooooo : : ]
  if 36 - 36: OoO0O00 % II111iiii * O0 + II111iiii - oO0o - i1IIi
  oOOOoOO = socket . ntohl ( oOOOoOO )
  self . rloc_probe = True if ( oOOOoOO & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( oOOOoOO & 0x04000000 ) else False
  self . security = True if ( oOOOoOO & 0x02000000 ) else False
  self . hop_count = ( oOOOoOO >> 8 ) & 0xff
  self . record_count = oOOOoOO & 0xff
  self . nonce = OOO0O0O [ 0 ]
  if 53 - 53: Ii1I - OOooOOo
  if ( self . nonce in lisp_crypto_keys_by_nonce ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 75 - 75: iII111i % O0 - I11i - I1ii11iIi11i + I1IiiI - I1IiiI
  return ( packet )
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
  if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
  if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
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
  if 73 - 73: oO0o / OOooOOo * II111iiii % OoooooooOO - i1IIi - ooOoO0o
  if 43 - 43: o0oOOo0O0Ooo + Ii1I % OoO0O00 . I1Ii111 + i1IIi
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 65 - 65: ooOoO0o + IiII - OoOoOO00 % II111iiii - iIii1I11I1II1
  if 39 - 39: I1IiiI + I1ii11iIi11i - i11iIiiIii
 def print_ttl ( self ) :
  i1i = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   i1i = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( i1i % 60 ) == 0 ) :
   i1i = str ( old_div ( i1i , 60 ) ) + " hours"
  else :
   i1i = str ( i1i ) + " mins"
   if 48 - 48: I1ii11iIi11i - IiII * i1IIi
  return ( i1i )
  if 68 - 68: iII111i . OoO0O00 % IiII % I11i
  if 63 - 63: I1ii11iIi11i % ooOoO0o % I1ii11iIi11i
 def store_ttl ( self ) :
  i1i = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : i1i = self . record_ttl & 0x7fffffff
  return ( i1i )
  if 71 - 71: Ii1I
  if 43 - 43: o0oOOo0O0Ooo / ooOoO0o
 def print_record ( self , indent , ddt ) :
  OoOoOOoOo = ""
  o0Oo0ooOOO000 = ""
  i1i11IIIi = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    i1i11IIIi = lisp_map_referral_action_string [ self . action ]
    i1i11IIIi = bold ( i1i11IIIi , False )
    OoOoOOoOo = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 88 - 88: I1ii11iIi11i . o0oOOo0O0Ooo % OOooOOo + Ii1I
    o0Oo0ooOOO000 = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 52 - 52: iII111i
    if 65 - 65: Oo0Ooo * ooOoO0o % i11iIiiIii
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    i1i11IIIi = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     i1i11IIIi = bold ( i1i11IIIi , False )
     if 12 - 12: OoOoOO00 . I1ii11iIi11i . Oo0Ooo
     if 61 - 61: I11i / OOooOOo
     if 85 - 85: OoOoOO00 - I11i . OoOoOO00 . OoOoOO00
     if 62 - 62: IiII % OoooooooOO * OoO0O00 + OoO0O00 % Ii1I % iII111i
  Oooo0oOOOO = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  oOo0OoOOOo0 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 66 - 66: I1IiiI . OOooOOo - OoO0O00 % Oo0Ooo * o0oOOo0O0Ooo - oO0o
  lprint ( oOo0OoOOOo0 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 i1i11IIIi , "auth" if ( self . authoritative is True ) else "non-auth" ,
 OoOoOOoOo , o0Oo0ooOOO000 , self . map_version , Oooo0oOOOO ,
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
  Oooo0oOOOO = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( Oooo0oOOOO < 0 ) : Oooo0oOOOO = LISP_AFI_LCAF
  I1iiIiI1II1ii = ( self . group . is_null ( ) == False )
  if ( I1iiIiI1II1ii ) : Oooo0oOOOO = LISP_AFI_LCAF
  if 10 - 10: O0 % I11i + I1ii11iIi11i - i11iIiiIii % i1IIi + II111iiii
  iii1I = ( self . signature_count << 12 ) | self . map_version
  OOOoOo0o0Ooo = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 55 - 55: OoOoOO00 * I1Ii111 % OoO0O00 - OoO0O00
  OO0Oo00OO0oo = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , OOOoOo0o0Ooo , socket . htons ( oOoO0OooO0O ) ,
 socket . htons ( iii1I ) , socket . htons ( Oooo0oOOOO ) )
  if 34 - 34: O0 * OoO0O00 - oO0o - IiII * Ii1I . II111iiii
  if 28 - 28: O0 % iII111i - i1IIi
  if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
  if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
  if ( I1iiIiI1II1ii ) :
   OO0Oo00OO0oo += self . eid . lcaf_encode_sg ( self . group )
   return ( OO0Oo00OO0oo )
   if 97 - 97: oO0o - iII111i + IiII . OoOoOO00 + iIii1I11I1II1
   if 75 - 75: ooOoO0o + ooOoO0o . I1Ii111 % iII111i / iIii1I11I1II1 * iII111i
   if 13 - 13: II111iiii * i11iIiiIii - i1IIi * OoO0O00 + i1IIi
   if 43 - 43: O0 % oO0o * I1IiiI
   if 64 - 64: II111iiii + i11iIiiIii
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   OO0Oo00OO0oo = OO0Oo00OO0oo [ 0 : - 2 ]
   OO0Oo00OO0oo += self . eid . address . encode_geo ( )
   return ( OO0Oo00OO0oo )
   if 17 - 17: O0 * I1IiiI
   if 40 - 40: iIii1I11I1II1 * iII111i % iIii1I11I1II1
   if 39 - 39: i1IIi . Ii1I - Oo0Ooo
   if 91 - 91: I1IiiI - OoooooooOO - OoooooooOO
   if 69 - 69: iII111i * i11iIiiIii / i1IIi
  if ( Oooo0oOOOO == LISP_AFI_LCAF ) :
   OO0Oo00OO0oo += self . eid . lcaf_encode_iid ( )
   return ( OO0Oo00OO0oo )
   if 86 - 86: I1IiiI % I11i * O0 + i1IIi % I1Ii111
   if 97 - 97: II111iiii * OoOoOO00 - I1Ii111 / i11iIiiIii / OoOoOO00
   if 25 - 25: Oo0Ooo / Oo0Ooo
   if 74 - 74: OOooOOo
   if 30 - 30: O0 . Ii1I / o0oOOo0O0Ooo + I1IiiI - O0
  OO0Oo00OO0oo += self . eid . pack_address ( )
  return ( OO0Oo00OO0oo )
  if 88 - 88: i11iIiiIii
  if 33 - 33: OoO0O00 + O0
 def decode ( self , packet ) :
  Iii1iIII1Iii = "IBBHHH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 20 - 20: o0oOOo0O0Ooo % I11i . ooOoO0o - i1IIi . O0
  self . record_ttl , self . rloc_count , self . eid . mask_len , oOoO0OooO0O , self . map_version , self . eid . afi = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
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
  packet = packet [ oOoOo000Ooooo : : ]
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
  oOo0OoOOOo0 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 93 - 93: I1Ii111
  lprint ( oOo0OoOOOo0 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
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
  oOOOoOO = ( LISP_ECM << 28 )
  if ( self . security ) : oOOOoOO |= 0x08000000
  if ( self . ddt ) : oOOOoOO |= 0x04000000
  if ( self . to_etr ) : oOOOoOO |= 0x02000000
  if ( self . to_ms ) : oOOOoOO |= 0x01000000
  if 8 - 8: Oo0Ooo
  III1iI1III1I1 = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  if 4 - 4: ooOoO0o
  ooooO000 = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   ooooO000 = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   ooooO000 += self . source . pack_address ( )
   ooooO000 += self . dest . pack_address ( )
   ooooO000 = lisp_ip_checksum ( ooooO000 )
   if 71 - 71: I1Ii111 + i1IIi * Oo0Ooo
  if ( self . afi == LISP_AFI_IPV6 ) :
   ooooO000 = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   ooooO000 += self . source . pack_address ( )
   ooooO000 += self . dest . pack_address ( )
   if 51 - 51: OoooooooOO * O0 - OoO0O00 . Oo0Ooo % II111iiii + IiII
   if 48 - 48: IiII . II111iiii - i11iIiiIii * iII111i
  OOo0oOO0o0oo0 = socket . htons ( self . udp_sport )
  oooOo = socket . htons ( self . udp_dport )
  i1II1IIiIi1 = socket . htons ( self . udp_length )
  I1 = socket . htons ( self . udp_checksum )
  ii11 = struct . pack ( "HHHH" , OOo0oOO0o0oo0 , oooOo , i1II1IIiIi1 , I1 )
  return ( III1iI1III1I1 + ooooO000 + ii11 )
  if 51 - 51: OoooooooOO + I11i . iII111i + i11iIiiIii * iII111i - OoO0O00
  if 60 - 60: iII111i * iIii1I11I1II1 . OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
 def decode ( self , packet ) :
  if 36 - 36: i1IIi . OoooooooOO - II111iiii - OoOoOO00 - IiII
  if 53 - 53: I1ii11iIi11i - II111iiii . i11iIiiIii
  if 76 - 76: iIii1I11I1II1 - Oo0Ooo
  if 79 - 79: I1IiiI * IiII . OoooooooOO % I1Ii111 * I1Ii111
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 17 - 17: I1Ii111 - I1Ii111 . oO0o / I1Ii111
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 36 - 36: I1ii11iIi11i * i1IIi + iIii1I11I1II1
  oOOOoOO = socket . ntohl ( oOOOoOO [ 0 ] )
  self . security = True if ( oOOOoOO & 0x08000000 ) else False
  self . ddt = True if ( oOOOoOO & 0x04000000 ) else False
  self . to_etr = True if ( oOOOoOO & 0x02000000 ) else False
  self . to_ms = True if ( oOOOoOO & 0x01000000 ) else False
  packet = packet [ oOoOo000Ooooo : : ]
  if 55 - 55: I1IiiI . I1Ii111 - I1IiiI % oO0o / iIii1I11I1II1 * Ii1I
  if 77 - 77: OOooOOo
  if 29 - 29: II111iiii % iIii1I11I1II1 * O0 . o0oOOo0O0Ooo
  if 56 - 56: i1IIi . ooOoO0o + I11i - i11iIiiIii
  if ( len ( packet ) < 1 ) : return ( None )
  IIiIi1I1iI1 = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  IIiIi1I1iI1 = IIiIi1I1iI1 >> 4
  if 100 - 100: iIii1I11I1II1 - i1IIi . OOooOOo
  if ( IIiIi1I1iI1 == 4 ) :
   oOoOo000Ooooo = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
   if 73 - 73: I1Ii111 / I11i / i11iIiiIii - I1ii11iIi11i % ooOoO0o
   Oo0OoO00O , i1II1IIiIi1 , Oo0OoO00O , IIiIIiiiiI , III1ii , I1 = struct . unpack ( "HHIBBH" , packet [ : oOoOo000Ooooo ] )
   self . length = socket . ntohs ( i1II1IIiIi1 )
   self . ttl = IIiIIiiiiI
   self . protocol = III1ii
   self . ip_checksum = socket . ntohs ( I1 )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 24 - 24: IiII + I1IiiI . O0 + OOooOOo / O0
   if 59 - 59: i1IIi . II111iiii . Oo0Ooo + oO0o
   if 65 - 65: I1IiiI / OoOoOO00 % I1IiiI * i11iIiiIii * OoooooooOO / I11i
   if 91 - 91: i11iIiiIii / i11iIiiIii
   III1ii = struct . pack ( "H" , 0 )
   I1I1I = struct . calcsize ( "HHIBB" )
   Ii11I = struct . calcsize ( "H" )
   packet = packet [ : I1I1I ] + III1ii + packet [ I1I1I + Ii11I : ]
   if 84 - 84: OoooooooOO + OoOoOO00 . Ii1I / i1IIi
   packet = packet [ oOoOo000Ooooo : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 15 - 15: II111iiii % i1IIi / oO0o . iIii1I11I1II1 * Oo0Ooo
   if 5 - 5: iII111i
  if ( IIiIi1I1iI1 == 6 ) :
   oOoOo000Ooooo = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
   if 61 - 61: OOooOOo * OoO0O00 - O0
   Oo0OoO00O , i1II1IIiIi1 , III1ii , IIiIIiiiiI = struct . unpack ( "IHBB" , packet [ : oOoOo000Ooooo ] )
   self . length = socket . ntohs ( i1II1IIiIi1 )
   self . protocol = III1ii
   self . ttl = IIiIIiiiiI
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 30 - 30: iIii1I11I1II1
   packet = packet [ oOoOo000Ooooo : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 14 - 14: o0oOOo0O0Ooo + Ii1I
   if 91 - 91: OoooooooOO / oO0o + OoOoOO00
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 100 - 100: i1IIi
  oOoOo000Ooooo = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 13 - 13: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo
  OOo0oOO0o0oo0 , oooOo , i1II1IIiIi1 , I1 = struct . unpack ( "HHHH" , packet [ : oOoOo000Ooooo ] )
  self . udp_sport = socket . ntohs ( OOo0oOO0o0oo0 )
  self . udp_dport = socket . ntohs ( oooOo )
  self . udp_length = socket . ntohs ( i1II1IIiIi1 )
  self . udp_checksum = socket . ntohs ( I1 )
  packet = packet [ oOoOo000Ooooo : : ]
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
  ooOoOO0Oo0oO0o = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   ooOoOO0Oo0oO0o = ", " + self . keys [ 1 ] . print_keys ( )
   if 94 - 94: Oo0Ooo / I11i . I1ii11iIi11i
   if 31 - 31: i11iIiiIii + iIii1I11I1II1 . II111iiii
  oOo0OoOOOo0 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( oOo0OoOOOo0 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , o00oO , oOIIi ,
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
  o000O0OOo00O = LISP_LCAF_JSON_TYPE
  Iiii1I = socket . htons ( LISP_AFI_LCAF )
  OoOOo0Oo0o0 = self . rloc . addr_length ( ) + 2
  if 72 - 72: O0 * I1Ii111 - iIii1I11I1II1 % i1IIi
  IIIi1I = socket . htons ( len ( OoOo00OO0o00 ) + OoOOo0Oo0o0 )
  if 83 - 83: OoOoOO00 + OOooOOo / OoooooooOO
  i1i1IiIIIi1 = socket . htons ( len ( OoOo00OO0o00 ) )
  OO0Oo00OO0oo = struct . pack ( "HBBBBHH" , Iiii1I , 0 , 0 , o000O0OOo00O , iIii1iii1 ,
 IIIi1I , i1i1IiIIIi1 )
  OO0Oo00OO0oo += OoOo00OO0o00 . encode ( )
  if 39 - 39: OoO0O00 % iII111i . oO0o . II111iiii - i11iIiiIii
  if 85 - 85: O0 - OoOoOO00
  if 17 - 17: o0oOOo0O0Ooo / i1IIi / OOooOOo
  if 91 - 91: I1ii11iIi11i / Ii1I - OoOoOO00 . I11i / oO0o
  if ( lisp_is_json_telemetry ( OoOo00OO0o00 ) ) :
   OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   OO0Oo00OO0oo += self . rloc . pack_address ( )
  else :
   OO0Oo00OO0oo += struct . pack ( "H" , 0 )
   if 16 - 16: IiII % iII111i . oO0o . I1IiiI % O0 * I11i
  return ( OO0Oo00OO0oo )
  if 99 - 99: OoOoOO00 / OoooooooOO + iII111i * I11i * i11iIiiIii + OOooOOo
  if 40 - 40: II111iiii / I11i % I1IiiI - O0
 def encode_lcaf ( self ) :
  Iiii1I = socket . htons ( LISP_AFI_LCAF )
  Ii1IIII1i = b""
  if ( self . geo ) :
   Ii1IIII1i = self . geo . encode_geo ( )
   if 59 - 59: IiII / OoOoOO00 - I1Ii111 - ooOoO0o . oO0o
   if 87 - 87: oO0o + I1IiiI * I1Ii111 * o0oOOo0O0Ooo + O0
  I1IIiIi = b""
  if ( self . elp ) :
   iiII11iI11i1I = b""
   for oo0o in self . elp . elp_nodes :
    Oooo0oOOOO = socket . htons ( oo0o . address . afi )
    Ooo0000o = 0
    if ( oo0o . eid ) : Ooo0000o |= 0x4
    if ( oo0o . probe ) : Ooo0000o |= 0x2
    if ( oo0o . strict ) : Ooo0000o |= 0x1
    Ooo0000o = socket . htons ( Ooo0000o )
    iiII11iI11i1I += struct . pack ( "HH" , Ooo0000o , Oooo0oOOOO )
    iiII11iI11i1I += oo0o . address . pack_address ( )
    if 55 - 55: II111iiii / ooOoO0o / II111iiii * OOooOOo
    if 67 - 67: II111iiii
   OOii1II1IiIIiI = socket . htons ( len ( iiII11iI11i1I ) )
   I1IIiIi = struct . pack ( "HBBBBH" , Iiii1I , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , OOii1II1IiIIiI )
   I1IIiIi += iiII11iI11i1I
   if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
   if 100 - 100: o0oOOo0O0Ooo - Oo0Ooo % I1Ii111 . i11iIiiIii % OoooooooOO
  II1ioOO0Oo = b""
  if ( self . rle ) :
   iIIi = b""
   for Ii1111iiIii in self . rle . rle_nodes :
    Oooo0oOOOO = socket . htons ( Ii1111iiIii . rloc . rloc . afi )
    iIIi += struct . pack ( "HBBH" , 0 , 0 , Ii1111iiIii . level , Oooo0oOOOO )
    iIIi += Ii1111iiIii . rloc . rloc . pack_address ( )
    if ( Ii1111iiIii . rloc . rloc_name ) :
     iIIi += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     iIIi += ( Ii1111iiIii . rloc . rloc_name + "\0" ) . encode ( )
     if 43 - 43: II111iiii % OoooooooOO
     if 81 - 81: i1IIi - i1IIi / I1Ii111 + Oo0Ooo % I1Ii111
     if 26 - 26: OoO0O00
   OoOO = socket . htons ( len ( iIIi ) )
   II1ioOO0Oo = struct . pack ( "HBBBBH" , Iiii1I , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , OoOO )
   II1ioOO0Oo += iIIi
   if 63 - 63: I1IiiI
   if 3 - 3: iII111i + I1ii11iIi11i
  II111I1111iI = b""
  if ( self . json ) :
   II111I1111iI = self . encode_json ( self . json )
   if 91 - 91: I1IiiI + O0 / OoO0O00 * OoOoOO00 . o0oOOo0O0Ooo % i11iIiiIii
   if 77 - 77: iIii1I11I1II1 + OoOoOO00 - ooOoO0o * oO0o % OoO0O00
  IIIii1I = b""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   IIIii1I = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 86 - 86: IiII * O0 + oO0o * I1Ii111
   if 9 - 9: o0oOOo0O0Ooo / ooOoO0o % OoO0O00 * OoOoOO00 + OoO0O00 + I1IiiI
  oOooOoO0oo = b""
  if ( self . rloc_name ) :
   oOooOoO0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   oOooOoO0oo += ( self . rloc_name + "\0" ) . encode ( )
   if 21 - 21: oO0o - o0oOOo0O0Ooo + ooOoO0o . I1IiiI * oO0o * Ii1I
   if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
  IiiIiiii = len ( Ii1IIII1i ) + len ( I1IIiIi ) + len ( II1ioOO0Oo ) + len ( IIIii1I ) + 2 + len ( II111I1111iI ) + self . rloc . addr_length ( ) + len ( oOooOoO0oo )
  if 87 - 87: IiII - OoO0O00 * Oo0Ooo / o0oOOo0O0Ooo % oO0o % Ii1I
  IiiIiiii = socket . htons ( IiiIiiii )
  I1IIiIiI = struct . pack ( "HBBBBHH" , Iiii1I , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , IiiIiiii , socket . htons ( self . rloc . afi ) )
  I1IIiIiI += self . rloc . pack_address ( )
  return ( I1IIiIiI + oOooOoO0oo + Ii1IIII1i + I1IIiIi + II1ioOO0Oo + IIIii1I + II111I1111iI )
  if 2 - 2: O0 . OoO0O00 % oO0o - iII111i . i11iIiiIii - II111iiii
  if 93 - 93: IiII . OoOoOO00 % Ii1I - i1IIi . iIii1I11I1II1 / I1Ii111
 def encode ( self ) :
  Ooo0000o = 0
  if ( self . local_bit ) : Ooo0000o |= 0x0004
  if ( self . probe_bit ) : Ooo0000o |= 0x0002
  if ( self . reach_bit ) : Ooo0000o |= 0x0001
  if 75 - 75: II111iiii / oO0o
  OO0Oo00OO0oo = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( Ooo0000o ) ,
 socket . htons ( self . rloc . afi ) )
  if 26 - 26: I11i - i1IIi % OOooOOo - OoooooooOO
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 23 - 23: OoOoOO00 + I1Ii111 * OoO0O00
   try :
    OO0Oo00OO0oo = OO0Oo00OO0oo [ 0 : - 2 ] + self . encode_lcaf ( )
   except :
    lprint ( "Could not encode LCAF for RLOC-record" )
    if 22 - 22: OoO0O00
  else :
   OO0Oo00OO0oo += self . rloc . pack_address ( )
   if 28 - 28: OoO0O00 + IiII % Oo0Ooo
  return ( OO0Oo00OO0oo )
  if 95 - 95: i11iIiiIii / I1Ii111 - I1Ii111
  if 61 - 61: OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
 def decode_lcaf ( self , packet , nonce , ms_json_encrypt ) :
  Iii1iIII1Iii = "HBBBBH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
  Oooo0oOOOO , Ii1Ii1Ii , Ooo0000o , o000O0OOo00O , ii11Ii1111 , IIIi1I = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 25 - 25: OoOoOO00 + IiII . i11iIiiIii
  if 87 - 87: I1IiiI + OoooooooOO + O0
  IIIi1I = socket . ntohs ( IIIi1I )
  packet = packet [ oOoOo000Ooooo : : ]
  if ( IIIi1I > len ( packet ) ) : return ( None )
  if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
  if 65 - 65: IiII
  if 74 - 74: Oo0Ooo + i1IIi - II111iiii / ooOoO0o / iII111i
  if 66 - 66: ooOoO0o / IiII * iIii1I11I1II1
  if ( o000O0OOo00O == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( IIIi1I > 0 ) :
    Iii1iIII1Iii = "H"
    oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
    if ( IIIi1I < oOoOo000Ooooo ) : return ( None )
    if 42 - 42: I1Ii111 - i11iIiiIii % II111iiii * ooOoO0o . O0 % I11i
    o0oOO00O000O0 = len ( packet )
    Oooo0oOOOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
    Oooo0oOOOO = socket . ntohs ( Oooo0oOOOO )
    if 82 - 82: Oo0Ooo % O0 + I1ii11iIi11i % I1ii11iIi11i
    if ( Oooo0oOOOO == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ oOoOo000Ooooo : : ]
     self . rloc_name = None
     if ( Oooo0oOOOO == LISP_AFI_NAME ) :
      packet , oOo = lisp_decode_dist_name ( packet )
      self . rloc_name = oOo
     else :
      self . rloc . afi = Oooo0oOOOO
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
      if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
      if 29 - 29: Oo0Ooo - Ii1I - Oo0Ooo
    IIIi1I -= o0oOO00O000O0 - len ( packet )
    if 89 - 89: Oo0Ooo . OoO0O00 . I1ii11iIi11i * oO0o . O0
    if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
  elif ( o000O0OOo00O == LISP_LCAF_GEO_COORD_TYPE ) :
   if 69 - 69: I1Ii111 + O0 . IiII . o0oOOo0O0Ooo
   if 38 - 38: IiII / i1IIi
   if 60 - 60: OoOoOO00
   if 75 - 75: II111iiii / iIii1I11I1II1 / OoooooooOO
   o0o0OoOo000O = lisp_geo ( "" )
   packet = o0o0OoOo000O . decode_geo ( packet , IIIi1I , ii11Ii1111 )
   if ( packet == None ) : return ( None )
   self . geo = o0o0OoOo000O
   if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
  elif ( o000O0OOo00O == LISP_LCAF_JSON_TYPE ) :
   o0O00 = ii11Ii1111 & 0x02
   if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
   if 81 - 81: I1ii11iIi11i
   if 31 - 31: O0 % ooOoO0o / I1IiiI * iII111i % iIii1I11I1II1 * OoOoOO00
   if 76 - 76: I1Ii111 - O0
   Iii1iIII1Iii = "H"
   oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
   if ( IIIi1I < oOoOo000Ooooo ) : return ( None )
   if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
   i1i1IiIIIi1 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
   i1i1IiIIIi1 = socket . ntohs ( i1i1IiIIIi1 )
   if ( IIIi1I < oOoOo000Ooooo + i1i1IiIIIi1 ) : return ( None )
   if 7 - 7: II111iiii + I11i
   packet = packet [ oOoOo000Ooooo : : ]
   self . json = lisp_json ( "" , packet [ 0 : i1i1IiIIIi1 ] , o0O00 ,
 ms_json_encrypt )
   packet = packet [ i1i1IiIIIi1 : : ]
   if 99 - 99: iIii1I11I1II1 * oO0o
   if 37 - 37: ooOoO0o * iII111i * I11i
   if 11 - 11: I1IiiI
   if 48 - 48: O0 . I11i
   Oooo0oOOOO = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 9 - 9: oO0o / Oo0Ooo
   if ( Oooo0oOOOO != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = Oooo0oOOOO
    packet = self . rloc . unpack_address ( packet )
    if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
    if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
  elif ( o000O0OOo00O == LISP_LCAF_ELP_TYPE ) :
   if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
   if 31 - 31: oO0o
   if 74 - 74: OoO0O00
   if 11 - 11: oO0o + O0 % Ii1I . I11i * o0oOOo0O0Ooo
   I1IIii1IIi11IIiI = lisp_elp ( None )
   I1IIii1IIi11IIiI . elp_nodes = [ ]
   while ( IIIi1I > 0 ) :
    Ooo0000o , Oooo0oOOOO = struct . unpack ( "HH" , packet [ : 4 ] )
    if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
    Oooo0oOOOO = socket . ntohs ( Oooo0oOOOO )
    if ( Oooo0oOOOO == LISP_AFI_LCAF ) : return ( None )
    if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
    oo0o = lisp_elp_node ( )
    I1IIii1IIi11IIiI . elp_nodes . append ( oo0o )
    if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
    Ooo0000o = socket . ntohs ( Ooo0000o )
    oo0o . eid = ( Ooo0000o & 0x4 )
    oo0o . probe = ( Ooo0000o & 0x2 )
    oo0o . strict = ( Ooo0000o & 0x1 )
    oo0o . address . afi = Oooo0oOOOO
    oo0o . address . mask_len = oo0o . address . host_mask_len ( )
    packet = oo0o . address . unpack_address ( packet [ 4 : : ] )
    IIIi1I -= oo0o . address . addr_length ( ) + 4
    if 30 - 30: i11iIiiIii % OOooOOo
   I1IIii1IIi11IIiI . select_elp_node ( )
   self . elp = I1IIii1IIi11IIiI
   if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
  elif ( o000O0OOo00O == LISP_LCAF_RLE_TYPE ) :
   if 27 - 27: I1IiiI + OoOoOO00 + iII111i
   if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
   if 34 - 34: i1IIi % Oo0Ooo . oO0o
   if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
   IIiiiI = lisp_rle ( "" )
   IIiiiI . rle_nodes = [ ]
   while ( IIIi1I > 0 ) :
    Oo0OoO00O , OOo00 , i1iIIII11I , Oooo0oOOOO = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 22 - 22: I1IiiI
    Oooo0oOOOO = socket . ntohs ( Oooo0oOOOO )
    if ( Oooo0oOOOO == LISP_AFI_LCAF ) : return ( None )
    if 76 - 76: o0oOOo0O0Ooo * Ii1I % I1ii11iIi11i % I1ii11iIi11i * I1IiiI
    Ii1111iiIii = lisp_rle_node ( )
    IIiiiI . rle_nodes . append ( Ii1111iiIii )
    if 59 - 59: iII111i / ooOoO0o % OoO0O00 / I1ii11iIi11i - IiII
    Ii1111iiIii . level = i1iIIII11I
    Ii1111iiIii . rloc . rloc . afi = Oooo0oOOOO
    Ii1111iiIii . rloc . rloc . mask_len = Ii1111iiIii . rloc . rloc . host_mask_len ( )
    packet = Ii1111iiIii . rloc . rloc . unpack_address ( packet [ 6 : : ] )
    if 96 - 96: O0 / I11i - iIii1I11I1II1
    IIIi1I -= Ii1111iiIii . rloc . rloc . addr_length ( ) + 6
    if ( IIIi1I >= 2 ) :
     Oooo0oOOOO = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( Oooo0oOOOO ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , Ii1111iiIii . rloc . rloc_name = lisp_decode_dist_name ( packet )
      if 74 - 74: II111iiii % o0oOOo0O0Ooo - iII111i
      if ( packet == None ) : return ( None )
      IIIi1I -= len ( Ii1111iiIii . rloc . rloc_name ) + 1 + 2
      if 53 - 53: I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo - OOooOOo
      if 88 - 88: I1Ii111
      if 72 - 72: iIii1I11I1II1 % i1IIi / OoO0O00 / I1IiiI - II111iiii - I1Ii111
   self . rle = IIiiiI
   self . rle . build_rle_forwarding_list ( )
   if 43 - 43: o0oOOo0O0Ooo - Oo0Ooo - I1ii11iIi11i / II111iiii + I1IiiI / I1ii11iIi11i
  elif ( o000O0OOo00O == LISP_LCAF_SECURITY_TYPE ) :
   if 34 - 34: Oo0Ooo
   if 21 - 21: I1IiiI / I1IiiI % I1Ii111 - OoOoOO00 % OoOoOO00 - II111iiii
   if 97 - 97: oO0o
   if 98 - 98: I1Ii111 * I1IiiI + iIii1I11I1II1
   if 75 - 75: oO0o
   OOo00o0oOO0o = packet
   iIiiIi1111ii = lisp_keys ( 1 )
   packet = iIiiIi1111ii . decode_lcaf ( OOo00o0oOO0o , IIIi1I )
   if ( packet == None ) : return ( None )
   if 50 - 50: oO0o / Oo0Ooo
   if 32 - 32: OoO0O00 % oO0o * I1ii11iIi11i + I11i / I1Ii111
   if 5 - 5: o0oOOo0O0Ooo + iII111i / OoooooooOO + Ii1I . OoOoOO00 / oO0o
   if 18 - 18: II111iiii . o0oOOo0O0Ooo
   OOOOoO0O = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( iIiiIi1111ii . cipher_suite in OOOOoO0O ) :
    if ( iIiiIi1111ii . cipher_suite == LISP_CS_25519_CBC ) :
     OoOOooOOoo = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 75 - 75: OoooooooOO - Oo0Ooo
    if ( iIiiIi1111ii . cipher_suite == LISP_CS_25519_CHACHA ) :
     OoOOooOOoo = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 56 - 56: II111iiii - i11iIiiIii - oO0o . o0oOOo0O0Ooo
   else :
    OoOOooOOoo = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 4 - 4: i1IIi
   packet = OoOOooOOoo . decode_lcaf ( OOo00o0oOO0o , IIIi1I )
   if ( packet == None ) : return ( None )
   if 91 - 91: IiII . OoO0O00 * Ii1I / o0oOOo0O0Ooo
   if ( len ( packet ) < 2 ) : return ( None )
   Oooo0oOOOO = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( Oooo0oOOOO )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 41 - 41: I1IiiI . OoO0O00 / i1IIi . Oo0Ooo . oO0o
   if 44 - 44: iII111i * I11i + i11iIiiIii + i1IIi / IiII * II111iiii
   if 58 - 58: OOooOOo
   if 72 - 72: OoO0O00 + OOooOOo - Oo0Ooo % ooOoO0o . IiII
   if 95 - 95: iII111i % OOooOOo - IiII - OoOoOO00 % o0oOOo0O0Ooo * O0
   if 16 - 16: I1Ii111 / Oo0Ooo
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 48 - 48: Oo0Ooo / oO0o + iII111i % iII111i
   IIiIIIiI = self . rloc_name
   if ( IIiIIIiI ) : IIiIIIiI = blue ( self . rloc_name , False )
   if 69 - 69: oO0o % OoooooooOO
   if 21 - 21: I1Ii111
   if 62 - 62: Ii1I % o0oOOo0O0Ooo
   if 65 - 65: OoO0O00 + Oo0Ooo + IiII / OoOoOO00
   if 37 - 37: oO0o - I11i
   if 64 - 64: OoO0O00 * OoOoOO00
   I1iII = self . keys [ 1 ] if self . keys else None
   if ( I1iII == None ) :
    if ( OoOOooOOoo . remote_public_key == None ) :
     ii1111Iii11i = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( ii1111Iii11i , IIiIIIiI ) )
     OoOOooOOoo = None
    else :
     ii1111Iii11i = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( ii1111Iii11i , IIiIIIiI ) )
     OoOOooOOoo . compute_shared_key ( "encap" )
     if 50 - 50: I1ii11iIi11i + I11i * iII111i
     if 27 - 27: OoOoOO00 * OOooOOo * iIii1I11I1II1 / i1IIi
     if 60 - 60: OOooOOo * I1Ii111 . oO0o
     if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
     if 51 - 51: I1IiiI . I11i - OoOoOO00
     if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
     if 97 - 97: Ii1I . Ii1I % iII111i
     if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
     if 54 - 54: iIii1I11I1II1 - OoooooooOO / I11i / oO0o % I1IiiI + OoOoOO00
     if 26 - 26: OoO0O00 * II111iiii % OOooOOo * iII111i + iII111i
   if ( I1iII ) :
    if ( OoOOooOOoo . remote_public_key == None ) :
     OoOOooOOoo = None
     i111i1 = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( i111i1 , IIiIIIiI ) )
    elif ( I1iII . compare_keys ( OoOOooOOoo ) ) :
     OoOOooOOoo = I1iII
     lprint ( "    Maintain stored encap-keys for {}" . format ( IIiIIIiI ) )
     if 25 - 25: I11i - I1ii11iIi11i
    else :
     if ( I1iII . remote_public_key == None ) :
      ii1111Iii11i = "New encap-keying for existing state"
     else :
      ii1111Iii11i = "Remote encap-rekeying"
      if 100 - 100: I1Ii111 / Ii1I + OoOoOO00 . OoooooooOO
     lprint ( "    {} for {}" . format ( bold ( ii1111Iii11i , False ) ,
 IIiIIIiI ) )
     I1iII . remote_public_key = OoOOooOOoo . remote_public_key
     I1iII . compute_shared_key ( "encap" )
     OoOOooOOoo = I1iII
     if 83 - 83: O0
     if 35 - 35: i11iIiiIii - I11i . OoOoOO00 * II111iiii % i11iIiiIii
   self . keys = [ None , OoOOooOOoo , None , None ]
   if 55 - 55: o0oOOo0O0Ooo / O0 / OoooooooOO * Oo0Ooo % iII111i
  else :
   if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
   if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
   if 46 - 46: o0oOOo0O0Ooo
   if 28 - 28: i1IIi
   packet = packet [ IIIi1I : : ]
   if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
  return ( packet )
  if 62 - 62: I1Ii111 * I11i / I11i
  if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
 def decode ( self , packet , nonce , ms_json_encrypt = False ) :
  Iii1iIII1Iii = "BBBBHH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
  self . priority , self . weight , self . mpriority , self . mweight , Ooo0000o , Oooo0oOOOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
  if 94 - 94: iII111i
  Ooo0000o = socket . ntohs ( Ooo0000o )
  Oooo0oOOOO = socket . ntohs ( Oooo0oOOOO )
  self . local_bit = True if ( Ooo0000o & 0x0004 ) else False
  self . probe_bit = True if ( Ooo0000o & 0x0002 ) else False
  self . reach_bit = True if ( Ooo0000o & 0x0001 ) else False
  if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
  if ( Oooo0oOOOO == LISP_AFI_LCAF ) :
   packet = packet [ oOoOo000Ooooo - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
  else :
   self . rloc . afi = Oooo0oOOOO
   packet = packet [ oOoOo000Ooooo : : ]
   packet = self . rloc . unpack_address ( packet )
   if 81 - 81: I1IiiI
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 62 - 62: Ii1I * OoOoOO00
  if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
 def end_of_rlocs ( self , packet , rloc_count ) :
  for o000o0O0Oo00 in range ( rloc_count ) :
   packet = self . decode ( packet , None , False )
   if ( packet == None ) : return ( None )
   if 11 - 11: Ii1I
  return ( packet )
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
class lisp_map_referral ( object ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 33 - 33: II111iiii + Ii1I
  if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # OoOoOO00 % iII111i - oO0o * i1IIi + OoooooooOO / I1ii11iIi11i
 lisp_hex_string ( self . nonce ) ) )
  if 43 - 43: I1IiiI % OoOoOO00 % ooOoO0o * Ii1I + I1IiiI
  if 29 - 29: I1IiiI . OoO0O00 * iII111i % o0oOOo0O0Ooo
 def encode ( self ) :
  oOOOoOO = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  return ( OO0Oo00OO0oo )
  if 100 - 100: iII111i * O0 . I1ii11iIi11i
  if 85 - 85: I1ii11iIi11i + iII111i * iIii1I11I1II1 + OoOoOO00 . OoOoOO00 * I1IiiI
 def decode ( self , packet ) :
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 45 - 45: OoO0O00 % OoOoOO00
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  oOOOoOO = socket . ntohl ( oOOOoOO [ 0 ] )
  self . record_count = oOOOoOO & 0xff
  packet = packet [ oOoOo000Ooooo : : ]
  if 52 - 52: Oo0Ooo . II111iiii - I1Ii111 + Ii1I % I1ii11iIi11i
  Iii1iIII1Iii = "Q"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 61 - 61: o0oOOo0O0Ooo % I1IiiI
  self . nonce = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  return ( packet )
  if 42 - 42: I1ii11iIi11i + I1Ii111 - I11i * i1IIi + OoO0O00 . o0oOOo0O0Ooo
  if 4 - 4: OoO0O00 + I1ii11iIi11i + Ii1I + I1ii11iIi11i / iII111i
  if 15 - 15: OoooooooOO + I11i
  if 76 - 76: O0 % Ii1I * ooOoO0o
  if 13 - 13: OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
  if 21 - 21: Ii1I % O0
  if 15 - 15: II111iiii * Ii1I + IiII % iII111i
  if 96 - 96: II111iiii * I1Ii111 / Oo0Ooo
class lisp_ddt_entry ( object ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 35 - 35: I1IiiI
  if 54 - 54: I1ii11iIi11i % o0oOOo0O0Ooo . i1IIi
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 72 - 72: Ii1I
  if 87 - 87: iII111i - I1IiiI
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 54 - 54: iIii1I11I1II1 + oO0o * o0oOOo0O0Ooo % OoooooooOO . Oo0Ooo
  if 32 - 32: iII111i
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  I11I1I = self . delegation_set [ 0 ]
  return ( I11I1I . print_node_type ( ) )
  if 86 - 86: oO0o - Oo0Ooo + i11iIiiIii % ooOoO0o % i1IIi / O0
  if 49 - 49: ooOoO0o . I1ii11iIi11i * I1Ii111 * Ii1I * o0oOOo0O0Ooo - OoOoOO00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 53 - 53: o0oOOo0O0Ooo * Ii1I / O0
  if 81 - 81: Ii1I - iII111i / OOooOOo + I1IiiI + OoO0O00
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   IIIiiiIi = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( IIIiiiIi == None ) :
    IIIiiiIi = lisp_ddt_entry ( )
    IIIiiiIi . eid . copy_address ( self . group )
    IIIiiiIi . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , IIIiiiIi )
    if 69 - 69: i11iIiiIii
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IIIiiiIi . group )
   IIIiiiIi . add_source_entry ( self )
   if 69 - 69: i11iIiiIii - OoOoOO00 % I1Ii111 / II111iiii . OoOoOO00
   if 14 - 14: IiII . OoO0O00 / I1IiiI * Ii1I % OoO0O00 + OOooOOo
   if 45 - 45: i1IIi % I11i
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 6 - 6: II111iiii % I1Ii111 - i11iIiiIii / ooOoO0o
  if 51 - 51: OOooOOo * o0oOOo0O0Ooo / oO0o
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 43 - 43: I1IiiI * OoooooooOO * OoOoOO00 . OOooOOo / I1IiiI
  if 71 - 71: O0 + iIii1I11I1II1 . oO0o + iII111i
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 49 - 49: oO0o
  if 36 - 36: iII111i . I11i . i1IIi + I11i
  if 97 - 97: II111iiii . OoooooooOO - OoOoOO00
class lisp_ddt_node ( object ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 35 - 35: I1Ii111
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 / i1IIi + OoO0O00 - OoooooooOO / i11iIiiIii
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 79 - 79: I1IiiI * ooOoO0o * ooOoO0o
  if 92 - 92: iII111i % I1ii11iIi11i
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 16 - 16: oO0o
  if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 24 - 24: Ii1I + IiII + OoooooooOO / oO0o / I1IiiI + IiII
  if 52 - 52: ooOoO0o
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 38 - 38: OoO0O00 + I1IiiI % IiII
  if 87 - 87: oO0o * Ii1I - I1Ii111 / oO0o
  if 65 - 65: OoOoOO00
  if 87 - 87: I11i - i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
  if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
  if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
  if 97 - 97: Ii1I - IiII
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
  if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
  if 81 - 81: I1ii11iIi11i
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # ooOoO0o * I1IiiI - OoO0O00 + OOooOOo
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 79 - 79: Oo0Ooo . i11iIiiIii * OoO0O00 / I11i * OoOoOO00
  if 78 - 78: I11i . I1ii11iIi11i . I1ii11iIi11i
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 71 - 71: iII111i + IiII + I1IiiI - OoOoOO00
  if 49 - 49: I1IiiI % O0 - OoooooooOO * OoO0O00 / iIii1I11I1II1 + I11i
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( self . nonce in lisp_ddt_map_requestQ ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 7 - 7: iII111i * I1ii11iIi11i / oO0o
   if 31 - 31: I1ii11iIi11i - II111iiii
   if 86 - 86: IiII % OOooOOo % OoOoOO00 / I1IiiI % OoooooooOO
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 83 - 83: i1IIi . OoOoOO00 . i1IIi / OOooOOo * O0
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
  if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
  if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 94 - 94: I1IiiI / I1ii11iIi11i / OOooOOo
if 45 - 45: II111iiii
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
  if 98 - 98: i11iIiiIii + I1ii11iIi11i * OOooOOo / OoOoOO00
  if 84 - 84: o0oOOo0O0Ooo
 def print_info ( self ) :
  if ( self . info_reply ) :
   IiiI1ii1 = "Info-Reply"
   iIIiI11 = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # i11iIiiIii . ooOoO0o . iII111i
   # O0 % O0 / I1ii11iIi11i . II111iiii / II111iiii
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : iIIiI11 += "empty, "
   for Ooooo0OO in self . rtr_list :
    iIIiI11 += red ( Ooooo0OO . print_address_no_iid ( ) , False ) + ", "
    if 20 - 20: Oo0Ooo - O0 - ooOoO0o % iII111i * OoOoOO00 * OoooooooOO
   iIIiI11 = iIIiI11 [ 0 : - 2 ]
  else :
   IiiI1ii1 = "Info-Request"
   ooo00 = "<none>" if self . hostname == None else self . hostname
   iIIiI11 = ", hostname: {}" . format ( blue ( ooo00 , False ) )
   if 47 - 47: OoO0O00 - Oo0Ooo * OoO0O00 / oO0o
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( IiiI1ii1 , False ) ,
 lisp_hex_string ( self . nonce ) , iIIiI11 ) )
  if 13 - 13: ooOoO0o
  if 55 - 55: i1IIi . I11i . II111iiii + O0 + ooOoO0o - i1IIi
 def encode ( self ) :
  oOOOoOO = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : oOOOoOO |= ( 1 << 27 )
  if 3 - 3: iIii1I11I1II1 / oO0o
  if 61 - 61: I1Ii111 / O0 - iII111i
  if 44 - 44: i1IIi
  if 23 - 23: I1ii11iIi11i . OoooooooOO / Ii1I + o0oOOo0O0Ooo
  if 89 - 89: OoOoOO00 + Oo0Ooo . OoOoOO00 - II111iiii
  if 85 - 85: OoooooooOO * OoooooooOO / Ii1I - II111iiii
  if 69 - 69: iII111i * I11i
  OO0Oo00OO0oo = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  OO0Oo00OO0oo += struct . pack ( "III" , 0 , 0 , 0 )
  if 43 - 43: o0oOOo0O0Ooo - IiII * Ii1I . i11iIiiIii / II111iiii
  if 61 - 61: OoOoOO00 / I1IiiI . I1ii11iIi11i % OOooOOo
  if 70 - 70: OOooOOo * OoOoOO00 / oO0o + Oo0Ooo / O0
  if 16 - 16: Oo0Ooo / OoooooooOO / IiII + Oo0Ooo * i11iIiiIii
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    OO0Oo00OO0oo += struct . pack ( "H" , 0 )
   else :
    OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    OO0Oo00OO0oo += ( self . hostname + "\0" ) . encode ( )
    if 15 - 15: o0oOOo0O0Ooo / i11iIiiIii
   return ( OO0Oo00OO0oo )
   if 63 - 63: I1ii11iIi11i - Ii1I + I11i
   if 98 - 98: iII111i / IiII * I1IiiI / oO0o - iIii1I11I1II1
   if 72 - 72: O0 . OOooOOo
   if 99 - 99: i1IIi + iIii1I11I1II1 - ooOoO0o + OoO0O00 + Oo0Ooo . I1ii11iIi11i
   if 74 - 74: i1IIi
  Oooo0oOOOO = socket . htons ( LISP_AFI_LCAF )
  o000O0OOo00O = LISP_LCAF_NAT_TYPE
  IIIi1I = socket . htons ( 16 )
  O0o00O = socket . htons ( self . ms_port )
  iiI11ii11 = socket . htons ( self . etr_port )
  OO0Oo00OO0oo += struct . pack ( "HHBBHHHH" , Oooo0oOOOO , 0 , o000O0OOo00O , 0 , IIIi1I ,
 O0o00O , iiI11ii11 , socket . htons ( self . global_etr_rloc . afi ) )
  OO0Oo00OO0oo += self . global_etr_rloc . pack_address ( )
  OO0Oo00OO0oo += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  OO0Oo00OO0oo += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : OO0Oo00OO0oo += struct . pack ( "H" , 0 )
  if 53 - 53: OoO0O00 / I11i
  if 99 - 99: I1IiiI / OoOoOO00 / oO0o . I1ii11iIi11i * iIii1I11I1II1
  if 47 - 47: OOooOOo . oO0o . IiII + I1IiiI - OoooooooOO
  if 74 - 74: OOooOOo / i11iIiiIii
  for Ooooo0OO in self . rtr_list :
   OO0Oo00OO0oo += struct . pack ( "H" , socket . htons ( Ooooo0OO . afi ) )
   OO0Oo00OO0oo += Ooooo0OO . pack_address ( )
   if 96 - 96: iIii1I11I1II1 . o0oOOo0O0Ooo / iIii1I11I1II1 / OoooooooOO + i11iIiiIii % OoO0O00
  return ( OO0Oo00OO0oo )
  if 100 - 100: i1IIi
  if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
 def decode ( self , packet ) :
  OOo00o0oOO0o = packet
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  oOOOoOO = oOOOoOO [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if 71 - 71: IiII + OoO0O00
  Iii1iIII1Iii = "Q"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
  OOO0O0O = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
  oOOOoOO = socket . ntohl ( oOOOoOO )
  self . nonce = OOO0O0O [ 0 ]
  self . info_reply = oOOOoOO & 0x08000000
  self . hostname = None
  packet = packet [ oOoOo000Ooooo : : ]
  if 30 - 30: O0 - O0 % iIii1I11I1II1 + iII111i * OoooooooOO
  if 1 - 1: O0
  if 36 - 36: oO0o . iII111i
  if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
  if 56 - 56: o0oOOo0O0Ooo
  Iii1iIII1Iii = "HH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
  if 88 - 88: Ii1I + O0
  if 92 - 92: I1IiiI % iII111i % I11i + OoooooooOO - i11iIiiIii
  if 9 - 9: i11iIiiIii - II111iiii / ooOoO0o
  if 81 - 81: i11iIiiIii % OoOoOO00 % OoO0O00 * Ii1I
  IIIIIi1 , IiiiiIi1iII1 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if ( IiiiiIi1iII1 != 0 ) : return ( None )
  if 85 - 85: OoooooooOO * ooOoO0o
  packet = packet [ oOoOo000Ooooo : : ]
  Iii1iIII1Iii = "IBBH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
  i1i , o0o0OoOo0 , O00O00O , o00oOO0O0o00O0o0o = struct . unpack ( Iii1iIII1Iii ,
 packet [ : oOoOo000Ooooo ] )
  if 71 - 71: i11iIiiIii + II111iiii - I11i + iIii1I11I1II1
  if ( o00oOO0O0o00O0o0o != 0 ) : return ( None )
  packet = packet [ oOoOo000Ooooo : : ]
  if 51 - 51: oO0o - OOooOOo / II111iiii * I1Ii111
  if 75 - 75: I1ii11iIi11i % OoOoOO00 % iII111i * iIii1I11I1II1 . I1Ii111
  if 33 - 33: Ii1I . i1IIi * OOooOOo
  if 75 - 75: IiII % Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - Ii1I
  if ( self . info_reply == False ) :
   Iii1iIII1Iii = "H"
   oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
   if ( len ( packet ) >= oOoOo000Ooooo ) :
    Oooo0oOOOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
    if ( socket . ntohs ( Oooo0oOOOO ) == LISP_AFI_NAME ) :
     packet = packet [ oOoOo000Ooooo : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 26 - 26: Oo0Ooo - i1IIi
     if 72 - 72: i11iIiiIii . I1ii11iIi11i / ooOoO0o - I1Ii111 * II111iiii - II111iiii
   return ( OOo00o0oOO0o )
   if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
   if 93 - 93: Ii1I / iII111i
   if 100 - 100: Oo0Ooo
   if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
   if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
  Iii1iIII1Iii = "HHBBHHH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
  Oooo0oOOOO , Oo0OoO00O , o000O0OOo00O , o0o0OoOo0 , IIIi1I , O0o00O , iiI11ii11 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
  if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
  if ( socket . ntohs ( Oooo0oOOOO ) != LISP_AFI_LCAF ) : return ( None )
  if 72 - 72: I1Ii111 . OoO0O00
  self . ms_port = socket . ntohs ( O0o00O )
  self . etr_port = socket . ntohs ( iiI11ii11 )
  packet = packet [ oOoOo000Ooooo : : ]
  if 59 - 59: I1IiiI * I11i % i1IIi
  if 77 - 77: OOooOOo * OoooooooOO + I1IiiI + I1IiiI % oO0o . OoooooooOO
  if 60 - 60: iIii1I11I1II1
  if 13 - 13: II111iiii + Ii1I
  Iii1iIII1Iii = "H"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 33 - 33: i1IIi
  if 36 - 36: ooOoO0o % ooOoO0o . i11iIiiIii
  if 42 - 42: OoO0O00 . I1Ii111 / Ii1I
  if 57 - 57: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / oO0o . OoOoOO00
  Oooo0oOOOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if ( Oooo0oOOOO != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( Oooo0oOOOO )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 74 - 74: I1IiiI * OoO0O00 + OoooooooOO * ooOoO0o . oO0o
   if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
   if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
   if 81 - 81: i1IIi % iIii1I11I1II1
   if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
   if 82 - 82: ooOoO0o
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( OOo00o0oOO0o )
  if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
  Oooo0oOOOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if ( Oooo0oOOOO != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( Oooo0oOOOO )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OOo00o0oOO0o )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
   if 59 - 59: i11iIiiIii / OoO0O00
   if 48 - 48: iIii1I11I1II1
   if 19 - 19: oO0o
   if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( OOo00o0oOO0o )
  if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
  Oooo0oOOOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if ( Oooo0oOOOO != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( Oooo0oOOOO )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( OOo00o0oOO0o )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
   if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
   if 8 - 8: I1ii11iIi11i + II111iiii . OoO0O00 + I1IiiI - II111iiii % OoO0O00
   if 85 - 85: i11iIiiIii % iII111i + II111iiii
   if 16 - 16: ooOoO0o * OoOoOO00 / OoOoOO00 + II111iiii
   if 50 - 50: OoO0O00 / OOooOOo % I1IiiI / Ii1I + OoO0O00 . iIii1I11I1II1
  while ( len ( packet ) >= oOoOo000Ooooo ) :
   Oooo0oOOOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
   packet = packet [ oOoOo000Ooooo : : ]
   if ( Oooo0oOOOO == 0 ) : continue
   Ooooo0OO = lisp_address ( socket . ntohs ( Oooo0oOOOO ) , "" , 0 , 0 )
   packet = Ooooo0OO . unpack_address ( packet )
   if ( packet == None ) : return ( OOo00o0oOO0o )
   Ooooo0OO . mask_len = Ooooo0OO . host_mask_len ( )
   self . rtr_list . append ( Ooooo0OO )
   if 62 - 62: I1Ii111 + OoooooooOO - Ii1I - iIii1I11I1II1
  return ( OOo00o0oOO0o )
  if 80 - 80: OoO0O00
  if 72 - 72: II111iiii % i11iIiiIii + OoOoOO00 / I1Ii111 - i11iIiiIii
  if 39 - 39: i11iIiiIii - OOooOOo / OoO0O00 * OoOoOO00 / IiII
class lisp_nat_info ( object ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 / Ii1I / II111iiii
  if 56 - 56: OOooOOo * iII111i / Ii1I
 def timed_out ( self ) :
  o0oOOOO0 = time . time ( ) - self . uptime
  return ( o0oOOOO0 >= ( LISP_INFO_INTERVAL * 2 ) )
  if 9 - 9: I1ii11iIi11i * i11iIiiIii / I1Ii111 + iIii1I11I1II1
  if 1 - 1: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / oO0o
  if 73 - 73: iII111i
class lisp_info_source ( object ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 6 - 6: o0oOOo0O0Ooo + Oo0Ooo
  if 45 - 45: oO0o % O0 / O0
 def cache_address_for_info_source ( self ) :
  OoOOooOOoo = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ OoOOooOOoo ] = self
  if 98 - 98: I1Ii111
  if 58 - 58: OOooOOo
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
  if 6 - 6: I1ii11iIi11i
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
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 26 - 26: I1ii11iIi11i - OoO0O00
 if ( lisp_is_x86 ( ) or lisp_is_apple_m ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
  if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  iiOO0O = auth1 + auth2 + auth3
  if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  iiOO0O = auth1 + auth2 + auth3 + auth4
  if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
 return ( iiOO0O )
 if 15 - 15: Ii1I
 if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
 if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
 if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
 if 46 - 46: II111iiii . iIii1I11I1II1
 if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
 if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
 if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
 if 87 - 87: I1Ii111
 if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   IiiI1 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 81 - 81: I1Ii111 % OoO0O00 . II111iiii - IiII + IiII + Ii1I
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   IiiI1 = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 11 - 11: OOooOOo / iII111i + OoOoOO00 - Ii1I
  IiiI1 . bind ( ( local_addr , int ( port ) ) )
 else :
  ooO0o = port
  if ( os . path . exists ( ooO0o ) ) :
   os . system ( "rm " + ooO0o )
   time . sleep ( 1 )
   if 5 - 5: OOooOOo . oO0o / o0oOOo0O0Ooo
  IiiI1 = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  IiiI1 . bind ( ooO0o )
  if 52 - 52: I1IiiI + O0 * I1Ii111
 return ( IiiI1 )
 if 17 - 17: OoooooooOO % I1Ii111 . o0oOOo0O0Ooo * OoO0O00 - I1Ii111 . iII111i
 if 62 - 62: oO0o * OoooooooOO % o0oOOo0O0Ooo
 if 16 - 16: II111iiii - I1IiiI * O0 . OOooOOo / iII111i
 if 55 - 55: Ii1I + OoooooooOO % I1Ii111 % OoO0O00 / OoO0O00 + II111iiii
 if 79 - 79: o0oOOo0O0Ooo % I1Ii111 . Ii1I % iIii1I11I1II1 / Oo0Ooo + i11iIiiIii
 if 25 - 25: ooOoO0o
 if 49 - 49: OoO0O00 % I11i . OOooOOo + i1IIi
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   IiiI1 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 23 - 23: IiII + ooOoO0o % OoOoOO00 % I1IiiI
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   IiiI1 = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 43 - 43: IiII - IiII
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  IiiI1 = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  IiiI1 . bind ( internal_name )
  if 46 - 46: O0 % I1IiiI / I1ii11iIi11i + i1IIi
 return ( IiiI1 )
 if 95 - 95: oO0o / OoooooooOO % I1Ii111 + I1Ii111 + I1IiiI
 if 17 - 17: ooOoO0o % I1IiiI
 if 34 - 34: I11i - i1IIi % OoO0O00 - OoOoOO00 * iIii1I11I1II1 . OoO0O00
 if 98 - 98: Oo0Ooo * oO0o - Oo0Ooo * oO0o
 if 24 - 24: IiII % i11iIiiIii + ooOoO0o
 if 28 - 28: I11i * I11i + I11i / O0 - OOooOOo
 if 29 - 29: OoOoOO00 + i11iIiiIii % OoO0O00 - OoooooooOO
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 68 - 68: iII111i / OOooOOo
 if 28 - 28: II111iiii
 if 49 - 49: I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i * i11iIiiIii
 if 12 - 12: O0 - iIii1I11I1II1 % Oo0Ooo / O0 - IiII
 if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
 if 45 - 45: Ii1I
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
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
def lisp_packet_ipc ( packet , source , sport ) :
 i111ii1II11ii = "packet@{}@{}@{}@" . format ( str ( len ( packet ) ) , source , str ( sport ) )
 return ( i111ii1II11ii . encode ( ) + packet )
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
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 i111ii1II11ii = "control-packet@{}@{}@" . format ( dest , str ( dport ) )
 return ( i111ii1II11ii . encode ( ) + packet )
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
 if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
 if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
 if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
 if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 if 92 - 92: OoO0O00 . i1IIi
 if 22 - 22: Ii1I . I1IiiI
def lisp_data_packet_ipc ( packet , source ) :
 i111ii1II11ii = "data-packet@{}@{}@@" . format ( str ( len ( packet ) ) , source )
 return ( i111ii1II11ii . encode ( ) + packet )
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
def lisp_command_ipc ( ipc , source ) :
 OO0Oo00OO0oo = "command@{}@{}@@" . format ( len ( ipc ) , source ) + ipc
 return ( OO0Oo00OO0oo . encode ( ) )
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 if 81 - 81: OOooOOo * oO0o
 if 32 - 32: Oo0Ooo * OoO0O00 + ooOoO0o . O0 * oO0o * iIii1I11I1II1
 if 50 - 50: i1IIi
 if 53 - 53: II111iiii + O0 . ooOoO0o * IiII + i1IIi
 if 80 - 80: Ii1I + O0
 if 59 - 59: i11iIiiIii - OoooooooOO % I11i . OoO0O00 - Oo0Ooo * o0oOOo0O0Ooo
 if 7 - 7: II111iiii % Ii1I * i11iIiiIii
 if 28 - 28: II111iiii / ooOoO0o * i11iIiiIii % OOooOOo
 if 18 - 18: I11i - IiII - iIii1I11I1II1
def lisp_api_ipc ( source , data ) :
 OO0Oo00OO0oo = "api@" + str ( len ( data ) ) + "@" + source + "@@" + data
 return ( OO0Oo00OO0oo . encode ( ) )
 if 82 - 82: II111iiii + OoO0O00 % iIii1I11I1II1 / O0
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
def lisp_ipc ( packet , send_socket , node ) :
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
 if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
 if 12 - 12: II111iiii + I11i
 if 9 - 9: I1ii11iIi11i
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 51 - 51: I1ii11iIi11i
  if 37 - 37: I1IiiI % I1Ii111
 IIIII1i111I = 1500 if ( packet . find ( b"control-packet" ) == - 1 ) else 9000
 if 84 - 84: O0 + IiII - I1IiiI - I1Ii111 / OoooooooOO
 II1Ii = 0
 iI = len ( packet )
 Oo00OOOO = 0
 oOI11I = .001
 while ( iI > 0 ) :
  i11ii = min ( iI , IIIII1i111I )
  O0O0 = packet [ II1Ii : i11ii + II1Ii ]
  if 75 - 75: i11iIiiIii . o0oOOo0O0Ooo / oO0o . OoO0O00 % Ii1I % Ii1I
  try :
   if ( type ( O0O0 ) == str ) : O0O0 = O0O0 . encode ( )
   send_socket . sendto ( O0O0 , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( O0O0 ) , len ( packet ) , node ) )
   if 94 - 94: iII111i . Ii1I
   Oo00OOOO = 0
   oOI11I = .001
   if 71 - 71: o0oOOo0O0Ooo * II111iiii / OOooOOo . OoO0O00
  except socket . error as oOO :
   if ( Oo00OOOO == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 73 - 73: I1Ii111 * OoO0O00 / OoOoOO00 . II111iiii
    if 87 - 87: OoO0O00 + Oo0Ooo + O0 % OoooooooOO - iIii1I11I1II1
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( O0O0 ) , len ( packet ) , node , oOO ) )
   if 100 - 100: Oo0Ooo + IiII
   if 81 - 81: iIii1I11I1II1 + iIii1I11I1II1
   Oo00OOOO += 1
   time . sleep ( oOI11I )
   if 19 - 19: ooOoO0o + i1IIi / Oo0Ooo * II111iiii * I1Ii111 / ooOoO0o
   lprint ( "Retrying after {} ms ..." . format ( oOI11I * 1000 ) )
   oOI11I *= 2
   continue
   if 23 - 23: I1Ii111
   if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
  II1Ii += i11ii
  iI -= i11ii
  if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 return
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if 21 - 21: iII111i
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 if 75 - 75: OoooooooOO
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 II1Ii = 0
 O00 = b""
 iI = len ( packet ) * 2
 while ( II1Ii < iI ) :
  O00 += packet [ II1Ii : II1Ii + 8 ] + b" "
  II1Ii += 8
  iI -= 4
  if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 return ( O00 . decode ( ) )
 if 63 - 63: Oo0Ooo * I1IiiI
 if 84 - 84: Oo0Ooo
 if 67 - 67: oO0o / II111iiii . I11i / oO0o
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 if 100 - 100: i11iIiiIii % oO0o
 if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
 if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
def lisp_send ( lisp_sockets , dest , port , packet ) :
 if 73 - 73: i11iIiiIii
 III1II1II1 = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 83 - 83: i1IIi - Oo0Ooo - IiII - i11iIiiIii
 if 53 - 53: OoOoOO00 . OoooooooOO
 if 11 - 11: i1IIi % II111iiii % I1ii11iIi11i
 if 99 - 99: oO0o - I1Ii111
 if 29 - 29: I1IiiI - I11i
 if 42 - 42: Oo0Ooo - O0 . OoOoOO00
 if 4 - 4: IiII
 if 2 - 2: iII111i
 if 47 - 47: i1IIi % I11i
 if 17 - 17: OoOoOO00 - iII111i % I11i / o0oOOo0O0Ooo / II111iiii
 if 22 - 22: Oo0Ooo + I1ii11iIi11i % i11iIiiIii . OoO0O00 - I11i % I11i
 if 21 - 21: I1IiiI . OoO0O00 * IiII % OoooooooOO - Oo0Ooo + Oo0Ooo
 OOoo00 = dest . print_address_no_iid ( )
 if ( OOoo00 . find ( "::ffff:" ) != - 1 and OOoo00 . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : III1II1II1 = lisp_sockets [ 0 ]
  if ( III1II1II1 == None ) :
   III1II1II1 = lisp_sockets [ 0 ]
   OOoo00 = OOoo00 . split ( "::ffff:" ) [ - 1 ]
   if 94 - 94: ooOoO0o
   if 80 - 80: i11iIiiIii - O0 / I1Ii111 + OOooOOo % Oo0Ooo
   if 95 - 95: II111iiii
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + OOoo00 , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 76 - 76: OoO0O00 % iII111i * OoOoOO00 / ooOoO0o / i1IIi
 if 45 - 45: Ii1I . I11i * I1Ii111 . i11iIiiIii
 if 34 - 34: O0 * o0oOOo0O0Ooo / IiII
 if 75 - 75: I1Ii111 - i1IIi - OoO0O00
 try :
  III1II1II1 . sendto ( packet , ( OOoo00 , port ) )
 except socket . error as oOO :
  lprint ( "socket.sendto() failed: {}" . format ( oOO ) )
  if 25 - 25: iII111i . o0oOOo0O0Ooo
 return
 if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
 if 68 - 68: ooOoO0o % OoooooooOO
 if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
 if 60 - 60: iII111i . OOooOOo
 if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
 if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
 if 19 - 19: I1IiiI
 if 99 - 99: OOooOOo - OOooOOo
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo . I11i
 if 67 - 67: iII111i
 if 52 - 52: IiII . OoooooooOO
 i11ii = total_length - len ( packet )
 if ( i11ii == 0 ) : return ( [ True , packet ] )
 if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 38 - 38: I11i
 if 66 - 66: II111iiii
 if 57 - 57: OoO0O00 / Oo0Ooo % I1IiiI * I1ii11iIi11i
 if 68 - 68: iII111i - o0oOOo0O0Ooo - OoO0O00 . O0 - i11iIiiIii
 if 2 - 2: I1ii11iIi11i * i1IIi
 iI = i11ii
 while ( iI > 0 ) :
  try : O0O0 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 17 - 17: I1ii11iIi11i * Ii1I % Oo0Ooo * I1Ii111 + OoO0O00 . OoooooooOO
  O0O0 = O0O0 [ 0 ]
  if 60 - 60: Ii1I . II111iiii
  if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
  if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
  if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
  if 50 - 50: iIii1I11I1II1
  oO00o0Oo0 = O0O0 . decode ( )
  if ( oO00o0Oo0 . find ( "packet@" ) == 0 ) :
   oO00o0Oo0 = oO00o0Oo0 . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( O0O0 ) ,
   # OoooooooOO * Oo0Ooo / o0oOOo0O0Ooo * I11i + OoO0O00 . OoooooooOO
 oO00o0Oo0 [ 1 ] if len ( oO00o0Oo0 ) > 2 else "?" )
   return ( [ False , O0O0 ] )
   if 12 - 12: oO0o - I1ii11iIi11i
   if 69 - 69: iII111i * IiII * oO0o % OoO0O00 - o0oOOo0O0Ooo
  iI -= len ( O0O0 )
  packet += O0O0
  if 97 - 97: O0 + i11iIiiIii . i1IIi
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( O0O0 ) , total_length , source ) )
  if 43 - 43: II111iiii + OOooOOo . i11iIiiIii - II111iiii
  if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 return ( [ True , packet ] )
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
 if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
 if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
 if 15 - 15: oO0o . IiII + I1Ii111 - OoooooooOO
 if 85 - 85: II111iiii - Oo0Ooo + oO0o . i11iIiiIii + Oo0Ooo
 if 86 - 86: ooOoO0o . OoO0O00
 if 47 - 47: IiII % I1IiiI
 if 91 - 91: Ii1I
 if 69 - 69: iII111i
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 OO0Oo00OO0oo = b""
 for O0O0 in payload : OO0Oo00OO0oo += O0O0 + b"\x40"
 return ( OO0Oo00OO0oo [ : - 1 ] )
 if 96 - 96: Ii1I
 if 39 - 39: OoO0O00 - I1IiiI % II111iiii - IiII * I1ii11iIi11i
 if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
 if 7 - 7: ooOoO0o * I11i / iIii1I11I1II1
 if 15 - 15: OoooooooOO / iII111i
 if 40 - 40: o0oOOo0O0Ooo
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
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 74 - 74: OoooooooOO * ooOoO0o
  if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
  if 50 - 50: o0oOOo0O0Ooo % O0
  if 67 - 67: OoOoOO00
  try : I1IIiI1iiIi = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 85 - 85: II111iiii * i1IIi * iIii1I11I1II1 - O0 % I1Ii111
  if 36 - 36: Oo0Ooo * I11i / I1Ii111 / i1IIi
  if 60 - 60: iII111i + Oo0Ooo % i1IIi / II111iiii
  if 59 - 59: iII111i - O0 + Ii1I
  if 75 - 75: II111iiii / OoOoOO00 - o0oOOo0O0Ooo % I1ii11iIi11i + OoO0O00
  if 7 - 7: iII111i - OoO0O00 + ooOoO0o * iII111i
  if ( internal == False ) :
   OO0Oo00OO0oo = I1IIiI1iiIi [ 0 ]
   OO = lisp_convert_6to4 ( I1IIiI1iiIi [ 1 ] [ 0 ] )
   I1I1I1 = I1IIiI1iiIi [ 1 ] [ 1 ]
   if 14 - 14: OoOoOO00 - OoOoOO00 / ooOoO0o
   if ( I1I1I1 == LISP_DATA_PORT ) :
    iIi1iii1iI1I = lisp_data_plane_logging
    ii1 = lisp_format_packet ( OO0Oo00OO0oo [ 0 : 60 ] ) + " ..."
   else :
    iIi1iii1iI1I = True
    ii1 = lisp_format_packet ( OO0Oo00OO0oo )
    if 74 - 74: Oo0Ooo / OoOoOO00 + OoOoOO00 % i11iIiiIii . OoO0O00 + ooOoO0o
    if 77 - 77: ooOoO0o . I11i + OoooooooOO
   if ( iIi1iii1iI1I ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( OO0Oo00OO0oo ) , bold ( "from " + OO , False ) , I1I1I1 ,
 ii1 ) )
    if 100 - 100: ooOoO0o . oO0o % I1ii11iIi11i . IiII * IiII - o0oOOo0O0Ooo
   return ( [ "packet" , OO , I1I1I1 , OO0Oo00OO0oo ] )
   if 49 - 49: iIii1I11I1II1 % Ii1I / OoooooooOO - II111iiii . Ii1I
   if 65 - 65: OoooooooOO + I1Ii111 % ooOoO0o + II111iiii . i1IIi + OoooooooOO
   if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
   if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
   if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
   if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
  I1II = False
  ooo0o0oO = I1IIiI1iiIi [ 0 ]
  if ( type ( ooo0o0oO ) == str ) : ooo0o0oO = ooo0o0oO . encode ( )
  iIIi1Ii1 = False
  if 9 - 9: I1ii11iIi11i - i1IIi
  while ( I1II == False ) :
   ooo0o0oO = ooo0o0oO . split ( b"@" )
   if 82 - 82: OOooOOo * OoooooooOO % IiII % OoooooooOO
   if ( len ( ooo0o0oO ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( ooo0o0oO [ 0 ] ) )
    if 61 - 61: iII111i
    iIIi1Ii1 = True
    break
    if 85 - 85: IiII
    if 4 - 4: i1IIi
   iiii1Iii1Ii1I = ooo0o0oO [ 0 ] . decode ( )
   try :
    I1111i = int ( ooo0o0oO [ 1 ] )
   except :
    OOo0OO0OO = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( OOo0OO0OO , I1IIiI1iiIi ) )
    iIIi1Ii1 = True
    break
    if 58 - 58: OoOoOO00 / I1ii11iIi11i * Oo0Ooo
   OO = ooo0o0oO [ 2 ] . decode ( )
   I1I1I1 = ooo0o0oO [ 3 ] . decode ( )
   if 5 - 5: OoooooooOO / I1IiiI
   if 68 - 68: o0oOOo0O0Ooo
   if 39 - 39: IiII * oO0o * OOooOOo + Ii1I
   if 37 - 37: OoooooooOO + OoOoOO00 % iIii1I11I1II1 . OOooOOo + ooOoO0o . OOooOOo
   if 21 - 21: IiII % ooOoO0o . I1IiiI + OOooOOo - IiII
   if 69 - 69: I1Ii111 . OOooOOo - OoOoOO00
   if 95 - 95: OoOoOO00 * I1Ii111 % iII111i - I1Ii111
   if 92 - 92: II111iiii + OoooooooOO + OoOoOO00 / OOooOOo * Ii1I * Oo0Ooo
   if ( len ( ooo0o0oO ) > 5 ) :
    OO0Oo00OO0oo = lisp_bit_stuff ( ooo0o0oO [ 4 : : ] )
   else :
    OO0Oo00OO0oo = ooo0o0oO [ 4 ]
    if 40 - 40: I1IiiI / I11i + II111iiii + II111iiii - O0 + Oo0Ooo
    if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
    if 50 - 50: I11i . I11i % I1IiiI - i1IIi
    if 63 - 63: OoO0O00 . iII111i
    if 28 - 28: ooOoO0o . Oo0Ooo - OoooooooOO - I1Ii111 - OoooooooOO - oO0o
    if 25 - 25: I11i / I1Ii111 . i11iIiiIii % i1IIi
   I1II , OO0Oo00OO0oo = lisp_receive_segments ( lisp_socket , OO0Oo00OO0oo ,
 OO , I1111i )
   if ( OO0Oo00OO0oo == None ) : return ( [ "" , "" , "" , "" ] )
   if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
   if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
   if 30 - 30: OoO0O00 / ooOoO0o % ooOoO0o
   if 40 - 40: i1IIi . iIii1I11I1II1 * OoOoOO00
   if 83 - 83: iIii1I11I1II1 + Ii1I - Ii1I % II111iiii
   if ( I1II == False ) :
    ooo0o0oO = OO0Oo00OO0oo
    continue
    if 82 - 82: O0
    if 18 - 18: iII111i . IiII . I1IiiI
   if ( I1I1I1 == "" ) : I1I1I1 = "no-port"
   if ( iiii1Iii1Ii1I == "command" and lisp_i_am_core == False ) :
    o00O = OO0Oo00OO0oo . find ( b" {" )
    I1IIi = OO0Oo00OO0oo if o00O == - 1 else OO0Oo00OO0oo [ : o00O ]
    I1IIi = ": '" + I1IIi . decode ( ) + "'"
   else :
    I1IIi = ""
    if 20 - 20: OoO0O00 * II111iiii
    if 22 - 22: Oo0Ooo * I11i
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( OO0Oo00OO0oo ) , bold ( "from " + OO , False ) , I1I1I1 , iiii1Iii1Ii1I ,
 I1IIi if ( iiii1Iii1Ii1I in [ "command" , "api" ] ) else ": ... " if ( iiii1Iii1Ii1I == "data-packet" ) else ": " + lisp_format_packet ( OO0Oo00OO0oo ) ) )
   if 48 - 48: i11iIiiIii * I1IiiI % oO0o % OoooooooOO
   if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
   if 69 - 69: OoooooooOO
   if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
   if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
  if ( iIIi1Ii1 ) : continue
  return ( [ iiii1Iii1Ii1I , OO , I1I1I1 , OO0Oo00OO0oo ] )
  if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
  if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
  if 52 - 52: II111iiii . iII111i
  if 36 - 36: I1IiiI * II111iiii
  if 68 - 68: oO0o * o0oOOo0O0Ooo + OoooooooOO - I1ii11iIi11i * i1IIi % OOooOOo
  if 39 - 39: I1Ii111 / I11i + oO0o / I1Ii111 % IiII * I1ii11iIi11i
  if 66 - 66: I1ii11iIi11i * ooOoO0o . i11iIiiIii * Oo0Ooo - I11i . I1IiiI
  if 43 - 43: I11i . iII111i . IiII - oO0o
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 Oo00oo = False
 oooOO = time . time ( )
 if 12 - 12: iII111i % OOooOOo % i1IIi
 i111ii1II11ii = lisp_control_header ( )
 if ( i111ii1II11ii . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( Oo00oo )
  if 17 - 17: IiII
  if 63 - 63: ooOoO0o . i11iIiiIii / iIii1I11I1II1
  if 8 - 8: i11iIiiIii . IiII * iIii1I11I1II1 * I1IiiI * Ii1I * i11iIiiIii
  if 24 - 24: I1IiiI * I11i - o0oOOo0O0Ooo / iII111i + IiII - I1ii11iIi11i
  if 53 - 53: I11i / I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * OoOoOO00
 oo00O0oO = source
 if ( source . find ( "lisp" ) == - 1 ) :
  OOo0oOO0o0oo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  OOo0oOO0o0oo0 . string_to_afi ( source )
  OOo0oOO0o0oo0 . store_address ( source )
  source = OOo0oOO0o0oo0
  if 88 - 88: OoO0O00 + o0oOOo0O0Ooo - I11i
  if 34 - 34: O0 . I1ii11iIi11i - I11i
 if ( i111ii1II11ii . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , oooOO )
  if 86 - 86: II111iiii * Oo0Ooo - I1IiiI % iII111i
 elif ( i111ii1II11ii . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , oooOO )
  if 77 - 77: I11i / iII111i * o0oOOo0O0Ooo % iIii1I11I1II1
 elif ( i111ii1II11ii . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 26 - 26: i1IIi / OoO0O00 / IiII
 elif ( i111ii1II11ii . type == LISP_MAP_NOTIFY ) :
  if ( oo00O0oO == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-rtr" ) ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-itr" ) ) :
   lisp_process_unicast_map_notify ( lisp_sockets , packet , source )
   if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
   if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
 elif ( i111ii1II11ii . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
 elif ( i111ii1II11ii . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 88 - 88: i1IIi
 elif ( i111ii1II11ii . type == LISP_NAT_INFO and i111ii1II11ii . is_info_reply ( ) ) :
  Oo0OoO00O , OOo00 , Oo00oo = lisp_process_info_reply ( source , packet , True )
  if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
 elif ( i111ii1II11ii . type == LISP_NAT_INFO and i111ii1II11ii . is_info_reply ( ) == False ) :
  O00oO000Oo0 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , O00oO000Oo0 , udp_sport ,
 None )
  if 55 - 55: OoO0O00 % IiII
 elif ( i111ii1II11ii . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
 else :
  lprint ( "Invalid LISP control packet type {}:" . format ( i111ii1II11ii . type ) )
  lprint ( lisp_format_packet ( packet ) )
  if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
  if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
 return ( Oo00oo )
 if 63 - 63: I1Ii111 + iII111i
 if 6 - 6: I1ii11iIi11i + Ii1I
 if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
 if 97 - 97: ooOoO0o + OOooOOo
 if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
 if 6 - 6: Oo0Ooo + I1IiiI
 if 48 - 48: oO0o . I1ii11iIi11i
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp ) :
 if 59 - 59: IiII - Ii1I
 III1ii = bold ( "RLOC-probe" , False )
 if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( III1ii ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
  if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( III1ii ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
  if 53 - 53: o0oOOo0O0Ooo * Ii1I
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( III1ii ) )
 return
 if 42 - 42: I11i + iII111i / iIii1I11I1II1
 if 1 - 1: O0 - II111iiii
 if 75 - 75: II111iiii / OoO0O00 % II111iiii
 if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
 if 44 - 44: OOooOOo - o0oOOo0O0Ooo
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
 if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
 if 62 - 62: OoooooooOO
 if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
 if 52 - 52: ooOoO0o . iIii1I11I1II1 / iIii1I11I1II1 % oO0o - oO0o * II111iiii
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 57 - 57: I1Ii111
 if 23 - 23: I1ii11iIi11i + II111iiii
 if 99 - 99: o0oOOo0O0Ooo . I1IiiI + o0oOOo0O0Ooo * o0oOOo0O0Ooo / O0
 if 27 - 27: OOooOOo - I1Ii111
 if 33 - 33: OOooOOo - Ii1I - iII111i + I1ii11iIi11i - i11iIiiIii
 if 89 - 89: iIii1I11I1II1 * I11i + OOooOOo
 if 27 - 27: i1IIi - OoO0O00
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , map_request ,
 keys , enc , auth , mr_ttl = - 1 ) :
 if 23 - 23: iIii1I11I1II1 + Oo0Ooo * IiII
 oo = map_request . rloc_probe if ( map_request != None ) else False
 OOoOooO = map_request . json_telemetry if ( map_request != None ) else None
 if 10 - 10: I1Ii111 + I1IiiI . iIii1I11I1II1 + IiII / i11iIiiIii - O0
 if 27 - 27: OoooooooOO / I1ii11iIi11i
 o0o000o = lisp_map_reply ( )
 o0o000o . rloc_probe = oo
 o0o000o . echo_nonce_capable = enc
 o0o000o . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 o0o000o . record_count = 1
 o0o000o . nonce = nonce
 OO0Oo00OO0oo = o0o000o . encode ( )
 o0o000o . print_map_reply ( )
 if 28 - 28: i11iIiiIii - i11iIiiIii
 Oo0oOoooO = lisp_eid_record ( )
 Oo0oOoooO . rloc_count = len ( rloc_set )
 if ( OOoOooO != None ) : Oo0oOoooO . rloc_count += 1
 Oo0oOoooO . authoritative = auth
 Oo0oOoooO . record_ttl = ttl
 Oo0oOoooO . action = action
 Oo0oOoooO . eid = eid
 Oo0oOoooO . group = group
 if 84 - 84: I1ii11iIi11i * Oo0Ooo % I1IiiI - i11iIiiIii . OoooooooOO
 OO0Oo00OO0oo += Oo0oOoooO . encode ( )
 Oo0oOoooO . print_record ( "  " , False )
 if 62 - 62: iII111i * I1Ii111 / o0oOOo0O0Ooo
 iII11iiiIi1i = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
 iiIII1 = None
 for iIIoOo in rloc_set :
  iii = iIIoOo . rloc . is_multicast_address ( )
  oOiI111IIIiIii = lisp_rloc_record ( )
  II1OO0Oo0oOOO000 = oo and ( iii or OOoOooO == None )
  O00oO000Oo0 = iIIoOo . rloc . print_address_no_iid ( )
  if ( O00oO000Oo0 in iII11iiiIi1i or iii ) :
   oOiI111IIIiIii . local_bit = True
   oOiI111IIIiIii . probe_bit = II1OO0Oo0oOOO000
   oOiI111IIIiIii . keys = keys
   if ( iIIoOo . priority == 254 and lisp_i_am_rtr ) :
    oOiI111IIIiIii . rloc_name = "RTR"
    if 88 - 88: O0 + II111iiii + iIii1I11I1II1
   if ( iiIII1 == None ) :
    if ( iIIoOo . translated_rloc . is_null ( ) ) :
     iiIII1 = iIIoOo . rloc
    else :
     iiIII1 = iIIoOo . translated_rloc
     if 11 - 11: II111iiii . II111iiii + Ii1I % oO0o
     if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
     if 78 - 78: oO0o
  oOiI111IIIiIii . store_rloc_entry ( iIIoOo )
  oOiI111IIIiIii . reach_bit = True
  oOiI111IIIiIii . print_record ( "    " )
  OO0Oo00OO0oo += oOiI111IIIiIii . encode ( )
  if 20 - 20: i1IIi + i1IIi * i1IIi
  if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
  if 27 - 27: oO0o + Ii1I . i11iIiiIii
  if 97 - 97: iII111i . I1IiiI
  if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 if ( OOoOooO != None ) :
  oOiI111IIIiIii = lisp_rloc_record ( )
  if ( iiIII1 ) : oOiI111IIIiIii . rloc . copy_address ( iiIII1 )
  oOiI111IIIiIii . local_bit = True
  oOiI111IIIiIii . probe_bit = True
  oOiI111IIIiIii . reach_bit = True
  if ( lisp_i_am_rtr ) :
   oOiI111IIIiIii . priority = 254
   oOiI111IIIiIii . rloc_name = "RTR"
   if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
  iI111i1ii = lisp_encode_telemetry ( OOoOooO , eo = str ( time . time ( ) ) )
  oOiI111IIIiIii . json = lisp_json ( "telemetry" , iI111i1ii )
  oOiI111IIIiIii . print_record ( "    " )
  OO0Oo00OO0oo += oOiI111IIIiIii . encode ( )
  if 35 - 35: O0 % Ii1I + OoooooooOO
 return ( OO0Oo00OO0oo )
 if 72 - 72: I1ii11iIi11i
 if 100 - 100: i11iIiiIii - iII111i - I11i
 if 5 - 5: oO0o % IiII * iII111i
 if 98 - 98: iII111i / OOooOOo + IiII
 if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 if 82 - 82: ooOoO0o % OOooOOo % Ii1I
 if 82 - 82: I1ii11iIi11i
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 OoO0o0OooO = lisp_map_referral ( )
 OoO0o0OooO . record_count = 1
 OoO0o0OooO . nonce = nonce
 OO0Oo00OO0oo = OoO0o0OooO . encode ( )
 OoO0o0OooO . print_map_referral ( )
 if 82 - 82: OoOoOO00
 Oo0oOoooO = lisp_eid_record ( )
 if 5 - 5: OOooOOo . OOooOOo
 o00O000o0O0O = 0
 if ( ddt_entry == None ) :
  Oo0oOoooO . eid = eid
  Oo0oOoooO . group = group
 else :
  o00O000o0O0O = len ( ddt_entry . delegation_set )
  Oo0oOoooO . eid = ddt_entry . eid
  Oo0oOoooO . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 89 - 89: I1ii11iIi11i
 Oo0oOoooO . rloc_count = o00O000o0O0O
 Oo0oOoooO . authoritative = True
 if 43 - 43: I1Ii111 % i11iIiiIii / i1IIi + I1IiiI
 if 60 - 60: OOooOOo % iII111i * iIii1I11I1II1
 if 36 - 36: ooOoO0o * i1IIi + iII111i * OOooOOo * Ii1I
 if 74 - 74: Oo0Ooo - Oo0Ooo . I11i + I11i * OoO0O00
 if 48 - 48: iIii1I11I1II1 . I11i . II111iiii
 OoOoOOoOo = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( o00O000o0O0O == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   I11I1I = ddt_entry . delegation_set [ 0 ]
   if ( I11I1I . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 45 - 45: oO0o + ooOoO0o + OOooOOo * OOooOOo * o0oOOo0O0Ooo / Oo0Ooo
   if ( I11I1I . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 61 - 61: OoooooooOO % i11iIiiIii . i1IIi . OOooOOo
    if 90 - 90: iIii1I11I1II1 - iIii1I11I1II1 % O0
    if 43 - 43: Oo0Ooo / i1IIi % Ii1I . OoOoOO00
    if 22 - 22: iIii1I11I1II1 + Ii1I
    if 73 - 73: I1IiiI / OoO0O00 / OoooooooOO
    if 14 - 14: ooOoO0o % o0oOOo0O0Ooo / I1ii11iIi11i . IiII + I1ii11iIi11i
    if 30 - 30: I1ii11iIi11i + iIii1I11I1II1 . I1ii11iIi11i
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : OoOoOOoOo = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  OoOoOOoOo = ( lisp_i_am_ms and I11I1I . is_ms_peer ( ) == False )
  if 9 - 9: I1IiiI - Ii1I * II111iiii - I11i
  if 85 - 85: oO0o % ooOoO0o / OOooOOo
 Oo0oOoooO . action = action
 Oo0oOoooO . ddt_incomplete = OoOoOOoOo
 Oo0oOoooO . record_ttl = ttl
 if 50 - 50: O0 * O0 / iIii1I11I1II1
 OO0Oo00OO0oo += Oo0oOoooO . encode ( )
 Oo0oOoooO . print_record ( "  " , True )
 if 31 - 31: I1IiiI / o0oOOo0O0Ooo
 if ( o00O000o0O0O == 0 ) : return ( OO0Oo00OO0oo )
 if 70 - 70: I1IiiI
 for I11I1I in ddt_entry . delegation_set :
  oOiI111IIIiIii = lisp_rloc_record ( )
  oOiI111IIIiIii . rloc = I11I1I . delegate_address
  oOiI111IIIiIii . priority = I11I1I . priority
  oOiI111IIIiIii . weight = I11I1I . weight
  oOiI111IIIiIii . mpriority = 255
  oOiI111IIIiIii . mweight = 0
  oOiI111IIIiIii . reach_bit = True
  OO0Oo00OO0oo += oOiI111IIIiIii . encode ( )
  oOiI111IIIiIii . print_record ( "    " )
  if 36 - 36: ooOoO0o . oO0o . I11i - I1ii11iIi11i / OoOoOO00 * Oo0Ooo
 return ( OO0Oo00OO0oo )
 if 42 - 42: OoooooooOO / o0oOOo0O0Ooo . Ii1I * iII111i * I1IiiI - Oo0Ooo
 if 76 - 76: oO0o * II111iiii
 if 81 - 81: I11i
 if 2 - 2: OoOoOO00
 if 75 - 75: I1IiiI - OoooooooOO * I1Ii111
 if 1 - 1: o0oOOo0O0Ooo % oO0o * I1Ii111 - i1IIi - iII111i . oO0o
 if 25 - 25: i1IIi * o0oOOo0O0Ooo / oO0o
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 11 - 11: IiII + II111iiii
 if ( map_request . target_group . is_null ( ) ) :
  i1I = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  i1I = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( i1I ) : i1I = i1I . lookup_source_cache ( map_request . target_eid , False )
  if 85 - 85: OoooooooOO . I1IiiI % OoO0O00 / I1Ii111 . iII111i * I1IiiI
 oOOoo = map_request . print_prefix ( )
 if 26 - 26: OoooooooOO % I1ii11iIi11i - i11iIiiIii
 if ( i1I == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( oOOoo , False ) ) )
  if 84 - 84: OoO0O00
  return
  if 67 - 67: I1Ii111 + I1Ii111
  if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
 Ooo = i1I . print_eid_tuple ( )
 if 26 - 26: OoooooooOO . OoooooooOO * OoOoOO00 - Oo0Ooo + i11iIiiIii
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( Ooo , False ) , green ( oOOoo , False ) ) )
 if 61 - 61: O0 - I1Ii111 % II111iiii
 if 20 - 20: Oo0Ooo + iIii1I11I1II1 % I1Ii111 + O0 % I1Ii111
 if 70 - 70: OoO0O00 - OOooOOo - o0oOOo0O0Ooo % I11i - iII111i / I1ii11iIi11i
 if 18 - 18: oO0o * II111iiii . I1Ii111 - iIii1I11I1II1 / iIii1I11I1II1
 if 1 - 1: iII111i
 OOoo0O = map_request . itr_rlocs [ 0 ]
 if ( OOoo0O . is_private_address ( ) and lisp_nat_traversal ) :
  OOoo0O = source
  if 16 - 16: iII111i % OoOoOO00 . OoooooooOO * o0oOOo0O0Ooo - I1IiiI / oO0o
  if 51 - 51: Oo0Ooo + O0 / OoOoOO00 - I1ii11iIi11i * Oo0Ooo / IiII
 OOO0O0O = map_request . nonce
 II1O0oooO0oooooO = lisp_nonce_echoing
 O0o0O0 = map_request . keys
 if 88 - 88: i1IIi * II111iiii / i11iIiiIii % IiII . IiII
 if 93 - 93: OoOoOO00 * i1IIi . Ii1I
 if 2 - 2: i1IIi
 if 84 - 84: i1IIi / Ii1I + OoOoOO00 % Ii1I . oO0o
 if 74 - 74: OOooOOo - o0oOOo0O0Ooo - I1Ii111 - OoO0O00
 iIOooOoo0 = map_request . json_telemetry
 if ( iIOooOoo0 != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( iIOooOoo0 , ei = etr_in_ts )
  if 3 - 3: IiII % O0 + iII111i % I11i % OoOoOO00
  if 92 - 92: ooOoO0o + I1IiiI
 i1I . map_replies_sent += 1
 if 19 - 19: OoO0O00 * ooOoO0o % I1ii11iIi11i
 OO0Oo00OO0oo = lisp_build_map_reply ( i1I . eid , i1I . group , i1I . rloc_set , OOO0O0O ,
 LISP_NO_ACTION , 1440 , map_request , O0o0O0 , II1O0oooO0oooooO , True , ttl )
 if 21 - 21: OoO0O00 * I11i
 if 76 - 76: I1IiiI - I1ii11iIi11i / I1ii11iIi11i . o0oOOo0O0Ooo % OoooooooOO
 if 39 - 39: OoooooooOO % iII111i
 if 55 - 55: IiII . i11iIiiIii % OoooooooOO
 if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
 if 58 - 58: O0
 if 43 - 43: O0 / i1IIi / I11i % I1IiiI
 if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
 if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
 if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
 if 34 - 34: OoooooooOO * i11iIiiIii
 if 33 - 33: II111iiii
 if 59 - 59: iIii1I11I1II1 % I11i
 if 93 - 93: I1ii11iIi11i
 if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
 if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  if 15 - 15: I11i + iII111i
  I1I111i = ( OOoo0O . is_private_address ( ) == False )
  Ooooo0OO = OOoo0O . print_address_no_iid ( )
  if ( I1I111i and Ooooo0OO in lisp_rtr_list and sport == 0 ) :
   lisp_encap_rloc_probe ( lisp_sockets , OOoo0O , None , OO0Oo00OO0oo )
   return
   if 79 - 79: i11iIiiIii * IiII % iII111i
   if 18 - 18: iIii1I11I1II1 - O0 . o0oOOo0O0Ooo % oO0o
   if 73 - 73: IiII + I11i % I1IiiI * iII111i . O0
   if 17 - 17: OoO0O00 * OoOoOO00 % O0 % iII111i / i1IIi
   if 100 - 100: i11iIiiIii
   if 54 - 54: O0 * Ii1I + Ii1I
   if 59 - 59: i11iIiiIii % iII111i
   if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
   if 13 - 13: I11i / O0 . o0oOOo0O0Ooo . ooOoO0o
   if 7 - 7: OoO0O00 + OoooooooOO % II111iiii % oO0o
  IIoOo0oooO0 = OOoo0O . print_address_no_iid ( )
  if ( lisp_decent_nat and IIoOo0oooO0 not in lisp_rtr_list ) :
   ooOooO = lisp_get_nat_info ( OOoo0O , None )
   if ( ooOooO == None ) :
    lprint ( "Could not find NAT-info state for {}" . format ( IIoOo0oooO0 ) )
    return
    if 34 - 34: iIii1I11I1II1 - Ii1I % OOooOOo * i1IIi . ooOoO0o
    if 43 - 43: iIii1I11I1II1 % Oo0Ooo . I11i % I1ii11iIi11i % I1Ii111 % I1ii11iIi11i
    if 72 - 72: OoOoOO00 % OoO0O00 + O0 + OoOoOO00 - Ii1I . oO0o
    if 9 - 9: OoOoOO00 / OoooooooOO - OoOoOO00 / Oo0Ooo . I1IiiI - I11i
    if 41 - 41: oO0o % iII111i % iIii1I11I1II1 / I1ii11iIi11i
   lisp_encap_rloc_probe ( lisp_sockets , OOoo0O , ooOooO , OO0Oo00OO0oo )
   return
   if 69 - 69: OOooOOo * I11i % i11iIiiIii
   if 63 - 63: OoOoOO00 + I1IiiI / I1ii11iIi11i / o0oOOo0O0Ooo % I1IiiI
   if 67 - 67: I1Ii111 . oO0o % I1ii11iIi11i % OOooOOo + I1IiiI
   if 4 - 4: iII111i - i11iIiiIii * ooOoO0o
   if 74 - 74: Oo0Ooo . OOooOOo + OOooOOo / OOooOOo + I1IiiI + i1IIi
   if 32 - 32: i11iIiiIii % Ii1I
 lisp_send_map_reply ( lisp_sockets , OO0Oo00OO0oo , OOoo0O , sport )
 return
 if 92 - 92: OoOoOO00 % o0oOOo0O0Ooo % ooOoO0o - IiII - oO0o
 if 90 - 90: ooOoO0o
 if 11 - 11: OoOoOO00 % OOooOOo . i11iIiiIii * I1IiiI % O0 % iIii1I11I1II1
 if 18 - 18: Oo0Ooo % OOooOOo + IiII
 if 28 - 28: OOooOOo . OoO0O00 / o0oOOo0O0Ooo + II111iiii / iIii1I11I1II1 * II111iiii
 if 83 - 83: II111iiii . OoOoOO00 - i11iIiiIii . OoOoOO00 . i1IIi % OoooooooOO
 if 47 - 47: II111iiii
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 30 - 30: i1IIi . Oo0Ooo / o0oOOo0O0Ooo + IiII * OOooOOo
 if 26 - 26: Ii1I % O0 - i1IIi % iII111i * OoO0O00
 if 60 - 60: I1ii11iIi11i * iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
 if 94 - 94: OoO0O00 . ooOoO0o
 OOoo0O = map_request . itr_rlocs [ 0 ]
 if ( OOoo0O . is_private_address ( ) ) : OOoo0O = source
 OOO0O0O = map_request . nonce
 if 25 - 25: I1Ii111 % OOooOOo
 o0Ooo0Oooo0o = map_request . target_eid
 oo0oOooo0O = map_request . target_group
 if 82 - 82: Ii1I
 i1i1i1 = [ ]
 for IIi111iiiIi in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( IIi111iiiIi == None ) : continue
  iIIiI11 = lisp_rloc ( )
  iIIiI11 . rloc . copy_address ( IIi111iiiIi )
  iIIiI11 . priority = 254
  i1i1i1 . append ( iIIiI11 )
  if 13 - 13: oO0o / iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
  if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
 II1O0oooO0oooooO = lisp_nonce_echoing
 O0o0O0 = map_request . keys
 if 65 - 65: OOooOOo * I11i * Oo0Ooo
 if 21 - 21: Ii1I . iIii1I11I1II1
 if 84 - 84: OOooOOo
 if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
 if 33 - 33: ooOoO0o % I1IiiI
 iIOooOoo0 = map_request . json_telemetry
 if ( iIOooOoo0 != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( iIOooOoo0 , ei = etr_in_ts )
  if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
  if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
 OO0Oo00OO0oo = lisp_build_map_reply ( o0Ooo0Oooo0o , oo0oOooo0O , i1i1i1 , OOO0O0O , LISP_NO_ACTION ,
 1440 , map_request , O0o0O0 , II1O0oooO0oooooO , True , ttl )
 lisp_send_map_reply ( lisp_sockets , OO0Oo00OO0oo , OOoo0O , sport )
 return
 if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
 if 9 - 9: iII111i * Oo0Ooo % iII111i % Oo0Ooo * II111iiii
 if 71 - 71: II111iiii + I1ii11iIi11i * II111iiii
 if 59 - 59: OoO0O00
 if 81 - 81: i11iIiiIii
 if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
 if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
 if 85 - 85: OoooooooOO
 if 37 - 37: OoooooooOO + O0 + I1ii11iIi11i + IiII * iII111i
 if 15 - 15: i11iIiiIii / Oo0Ooo - OOooOOo . IiII
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 i1i1i1 = target_site_eid . registered_rlocs
 if 11 - 11: OOooOOo / i1IIi % Oo0Ooo
 o0OoOOO00O = lisp_site_eid_lookup ( seid , group , False )
 if ( o0OoOOO00O == None ) : return ( i1i1i1 )
 if 58 - 58: I1Ii111
 if 43 - 43: I1Ii111 + I11i - Ii1I + I11i - Oo0Ooo
 if 63 - 63: IiII % I11i / OoOoOO00 % OOooOOo * iII111i * OoO0O00
 if 11 - 11: I1Ii111 * II111iiii
 iIIiII1iiI1i1 = None
 iIiii = [ ]
 for iIIoOo in i1i1i1 :
  if ( iIIoOo . is_rtr ( ) ) : continue
  if ( iIIoOo . rloc . is_private_address ( ) ) :
   I1iIII1111I1I = copy . deepcopy ( iIIoOo )
   iIiii . append ( I1iIII1111I1I )
   continue
   if 49 - 49: i1IIi / OOooOOo
  iIIiII1iiI1i1 = iIIoOo
  break
  if 22 - 22: ooOoO0o % I11i + OoO0O00 . oO0o * Ii1I
 if ( iIIiII1iiI1i1 == None ) : return ( i1i1i1 )
 iIIiII1iiI1i1 = iIIiII1iiI1i1 . rloc . print_address_no_iid ( )
 if 58 - 58: ooOoO0o
 if 12 - 12: Oo0Ooo
 if 49 - 49: OoooooooOO . II111iiii - o0oOOo0O0Ooo * I1ii11iIi11i * Ii1I
 if 98 - 98: IiII + I1Ii111 . iIii1I11I1II1 + OoooooooOO . I1ii11iIi11i - O0
 i1iI1I11iiI = None
 for iIIoOo in o0OoOOO00O . registered_rlocs :
  if ( iIIoOo . is_rtr ( ) ) : continue
  if ( iIIoOo . rloc . is_private_address ( ) ) : continue
  i1iI1I11iiI = iIIoOo
  break
  if 20 - 20: I11i * O0 - OoooooooOO * OOooOOo % oO0o * iII111i
 if ( i1iI1I11iiI == None ) : return ( i1i1i1 )
 i1iI1I11iiI = i1iI1I11iiI . rloc . print_address_no_iid ( )
 if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
 if 48 - 48: iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
 if 24 - 24: I1IiiI
 if 63 - 63: I11i - iIii1I11I1II1 * Ii1I + OoooooooOO . i11iIiiIii
 iiI1I = target_site_eid . site_id
 if ( iiI1I == 0 ) :
  if ( i1iI1I11iiI == iIIiII1iiI1i1 ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( iIIiII1iiI1i1 ) )
   if 94 - 94: OoO0O00 . oO0o . OoOoOO00 * i11iIiiIii
   return ( iIiii )
   if 96 - 96: i1IIi . OoO0O00 . OoO0O00 - o0oOOo0O0Ooo - Ii1I
  return ( i1i1i1 )
  if 33 - 33: ooOoO0o + I1ii11iIi11i - I1IiiI . iII111i / OoO0O00
  if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
  if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
  if 77 - 77: ooOoO0o . II111iiii
  if 41 - 41: IiII
  if 27 - 27: IiII / IiII
  if 91 - 91: Ii1I
 if ( iiI1I == o0OoOOO00O . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( iiI1I ) )
  return ( iIiii )
  if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
 return ( i1i1i1 )
 if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
 if 98 - 98: OoO0O00 . i1IIi
 if 58 - 58: i1IIi * O0 + I1ii11iIi11i . IiII
 if 11 - 11: OOooOOo + iIii1I11I1II1 - ooOoO0o * OoO0O00 * i11iIiiIii
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 7 - 7: Oo0Ooo + ooOoO0o - I1Ii111 * iIii1I11I1II1
 if 6 - 6: ooOoO0o % I1Ii111 % ooOoO0o . Ii1I * Oo0Ooo . IiII
 if 100 - 100: i1IIi . Ii1I . o0oOOo0O0Ooo + Ii1I - i1IIi . I11i
 if 19 - 19: i11iIiiIii + I11i - IiII . iII111i * i1IIi
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 oo0o000OOoOO0 = [ ]
 i1i1i1 = [ ]
 if 27 - 27: IiII - iII111i * i11iIiiIii % i11iIiiIii + OoOoOO00 . I1Ii111
 if 10 - 10: IiII / i11iIiiIii
 if 6 - 6: I11i - OOooOOo
 if 100 - 100: Oo0Ooo / OOooOOo + iII111i - o0oOOo0O0Ooo + OoO0O00 % IiII
 if 91 - 91: Ii1I % I11i % Oo0Ooo / OoO0O00 - II111iiii - o0oOOo0O0Ooo
 if 50 - 50: OoooooooOO
 Oo0OOoooO = False
 ii11OoOoO0o0Oo00o = False
 for iIIoOo in registered_rloc_set :
  if ( iIIoOo . priority != 254 ) : continue
  ii11OoOoO0o0Oo00o |= True
  if ( iIIoOo . rloc . is_exact_match ( mr_source ) == False ) : continue
  Oo0OOoooO = True
  break
  if 79 - 79: OoOoOO00 * iII111i + II111iiii
  if 74 - 74: Oo0Ooo % OoO0O00 / I1ii11iIi11i
  if 24 - 24: O0
  if 69 - 69: OOooOOo + Ii1I + OoOoOO00 % I1Ii111 % iII111i
  if 72 - 72: OoOoOO00 * I1ii11iIi11i + iIii1I11I1II1
  if 51 - 51: oO0o + I1IiiI - I1Ii111 * Oo0Ooo . II111iiii
  if 63 - 63: I1ii11iIi11i - ooOoO0o - II111iiii + II111iiii
 if ( ii11OoOoO0o0Oo00o == False ) : return ( registered_rloc_set )
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
 Ii11iI1ii1 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 69 - 69: o0oOOo0O0Ooo . iIii1I11I1II1 + OoOoOO00 * OoO0O00
 if 57 - 57: i11iIiiIii * i11iIiiIii % I1Ii111 - iII111i * O0 - Ii1I
 if 63 - 63: IiII % OoooooooOO * OoOoOO00 * iIii1I11I1II1 . iII111i % oO0o
 if 58 - 58: I11i * iII111i + I11i % OoO0O00
 if 19 - 19: Oo0Ooo
 for iIIoOo in registered_rloc_set :
  if ( Ii11iI1ii1 and iIIoOo . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and iIIoOo . priority == 255 ) : continue
  if ( multicast and iIIoOo . mpriority == 255 ) : continue
  if ( iIIoOo . priority == 254 ) :
   oo0o000OOoOO0 . append ( iIIoOo )
  else :
   i1i1i1 . append ( iIIoOo )
   if 43 - 43: oO0o % ooOoO0o
   if 36 - 36: I11i / I1IiiI + O0 % II111iiii
   if 24 - 24: I1Ii111 / o0oOOo0O0Ooo - OOooOOo / IiII
   if 7 - 7: OoooooooOO - i11iIiiIii * i11iIiiIii / oO0o * i1IIi % OoooooooOO
   if 6 - 6: I1ii11iIi11i * i11iIiiIii % i11iIiiIii / I1Ii111
   if 21 - 21: oO0o
 if ( Oo0OOoooO ) : return ( i1i1i1 )
 if 47 - 47: I1ii11iIi11i
 if 24 - 24: I1Ii111 % iIii1I11I1II1
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
 i1i1i1 = [ ]
 for iIIoOo in registered_rloc_set :
  if ( iIIoOo . rloc . is_ipv6 ( ) ) : i1i1i1 . append ( iIIoOo )
  if ( iIIoOo . rloc . is_private_address ( ) ) : i1i1i1 . append ( iIIoOo )
  if 9 - 9: Ii1I / O0
 i1i1i1 += oo0o000OOoOO0
 return ( i1i1i1 )
 if 95 - 95: iII111i / I11i
 if 86 - 86: O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
 if 22 - 22: Ii1I
 if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
 if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
 if 32 - 32: oO0o . I1Ii111 * I1Ii111
 if 32 - 32: I1Ii111 . Ii1I / i1IIi
 if 2 - 2: OOooOOo * ooOoO0o / I11i + OoO0O00
 if 96 - 96: II111iiii * OoO0O00 + I1ii11iIi11i + OoOoOO00 / II111iiii . iII111i
 if 64 - 64: iII111i % Oo0Ooo
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 O0o0oo = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 O0o0oo . add ( reply_eid )
 return ( O0o0oo )
 if 42 - 42: I1IiiI . i1IIi
 if 98 - 98: o0oOOo0O0Ooo % I11i . Oo0Ooo * Oo0Ooo % iII111i
 if 37 - 37: OoO0O00 / I1Ii111 . I1Ii111 * i1IIi
 if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
 if 13 - 13: II111iiii
 if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 if 98 - 98: oO0o . Oo0Ooo
 if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
 if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
 if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
 if 64 - 64: OoooooooOO + OOooOOo
 if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
 if 86 - 86: iIii1I11I1II1 * OoO0O00
 if 82 - 82: I1IiiI - OoO0O00 % o0oOOo0O0Ooo
def lisp_convert_reply_to_notify ( packet ) :
 if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
 if 98 - 98: Oo0Ooo . II111iiii * I11i
 if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
 if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
 oO0Oo0o0 = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 oO0Oo0o0 = socket . ntohl ( oO0Oo0o0 ) & 0xff
 OOO0O0O = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 98 - 98: IiII - o0oOOo0O0Ooo
 if 55 - 55: I1ii11iIi11i
 if 20 - 20: iII111i - Ii1I - i1IIi
 if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
 oOOOoOO = ( LISP_MAP_NOTIFY << 28 ) | oO0Oo0o0
 i111ii1II11ii = struct . pack ( "I" , socket . htonl ( oOOOoOO ) )
 Ooo00OOo000 = struct . pack ( "I" , 0 )
 if 94 - 94: Oo0Ooo
 if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
 if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
 if 43 - 43: OoooooooOO * I1IiiI
 packet = i111ii1II11ii + OOO0O0O + Ooo00OOo000 + packet
 return ( packet )
 if 2 - 2: OOooOOo / oO0o + I1ii11iIi11i + i11iIiiIii % iIii1I11I1II1 . I1ii11iIi11i
 if 100 - 100: Oo0Ooo * ooOoO0o + Ii1I / iII111i * o0oOOo0O0Ooo
 if 26 - 26: I1Ii111 * OoOoOO00
 if 38 - 38: II111iiii
 if 50 - 50: OoOoOO00 . IiII - OOooOOo
 if 46 - 46: iIii1I11I1II1
 if 97 - 97: O0 * OOooOOo - o0oOOo0O0Ooo % o0oOOo0O0Ooo * II111iiii % I11i
 if 65 - 65: iIii1I11I1II1 / OOooOOo
def lisp_notify_subscribers ( lisp_sockets , eid_record , rloc_records ,
 registered_eid , site ) :
 if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
 for I1IIIiiII in lisp_pubsub_cache :
  for O0o0oo in list ( lisp_pubsub_cache [ I1IIIiiII ] . values ( ) ) :
   oOO = O0o0oo . eid_prefix
   if ( oOO . is_more_specific ( registered_eid ) == False ) : continue
   if 30 - 30: i1IIi * OoOoOO00 * I11i . O0
   IiI1ii1ii = O0o0oo . itr
   I1I1I1 = O0o0oo . port
   o0Ooo = red ( IiI1ii1ii . print_address_no_iid ( ) , False )
   i1I1I11iiiI = bold ( "subscriber" , False )
   oOOOOOOooOOoO = "0x" + lisp_hex_string ( O0o0oo . xtr_id )
   OOO0O0O = "0x" + lisp_hex_string ( O0o0oo . nonce )
   if 88 - 88: i1IIi + OoooooooOO . II111iiii - iII111i + I1Ii111
   lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( i1I1I11iiiI , o0Ooo , I1I1I1 , oOOOOOOooOOoO , green ( I1IIIiiII , False ) , OOO0O0O ) )
   if 21 - 21: OOooOOo / OoooooooOO + II111iiii - OOooOOo . I1IiiI . I1IiiI
   if 53 - 53: II111iiii . OoO0O00 * OoOoOO00 / II111iiii
   if 46 - 46: I1ii11iIi11i % ooOoO0o % OOooOOo
   if 40 - 40: I1IiiI % I1IiiI - i11iIiiIii % OoOoOO00
   if 17 - 17: ooOoO0o - i1IIi
   if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
   IIiIi = copy . deepcopy ( eid_record )
   IIiIi . eid . copy_address ( oOO )
   IIiIi = IIiIi . encode ( ) + rloc_records
   lisp_build_map_notify ( lisp_sockets , IIiIi , [ I1IIIiiII ] , 1 , IiI1ii1ii ,
 I1I1I1 , O0o0oo . nonce , 0 , 0 , 0 , site , False )
   if 89 - 89: OoooooooOO + I1IiiI . OoOoOO00 . I11i
   O0o0oo . map_notify_count += 1
   if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
   if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
 return
 if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
 if 3 - 3: Ii1I - I1IiiI + O0
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
 if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
 if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 67 - 67: o0oOOo0O0Ooo - Ii1I
 if 29 - 29: OoOoOO00 . I1ii11iIi11i
 if 24 - 24: OOooOOo + i1IIi . I11i . OoOoOO00 + OoooooooOO
 if 98 - 98: ooOoO0o + i1IIi / I1IiiI
 O0o0oo = lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl ,
 xtr_id )
 if 1 - 1: IiII . OoooooooOO + II111iiii
 o0Ooo0Oooo0o = green ( reply_eid . print_prefix ( ) , False )
 IiI1ii1ii = red ( itr_rloc . print_address_no_iid ( ) , False )
 iiIi11i1ii1I = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( iiIi11i1ii1I ,
 o0Ooo0Oooo0o , IiI1ii1ii , xtr_id ) )
 if 19 - 19: i11iIiiIii + II111iiii
 if 37 - 37: I1Ii111 . I1IiiI - II111iiii / O0 . OoOoOO00
 if 27 - 27: I1ii11iIi11i / II111iiii + O0 % I1ii11iIi11i
 if 72 - 72: I1IiiI - i1IIi
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 O0o0oo . map_notify_count += 1
 return
 if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
 if 65 - 65: Oo0Ooo / OoooooooOO
 if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
 if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
 if 80 - 80: IiII / OoooooooOO
 if 69 - 69: OoOoOO00 + IiII
 if 18 - 18: O0 / I11i
 if 10 - 10: I1Ii111 * i1IIi
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source , ecm_sport ) :
 if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 mr_sport = ecm_sport
 if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
 if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
 if 7 - 7: I11i - I1IiiI . iII111i + O0 / iIii1I11I1II1 - I1Ii111
 if 32 - 32: ooOoO0o
 if 9 - 9: I1Ii111
 if 77 - 77: OoooooooOO * I1Ii111
 o0Ooo0Oooo0o = map_request . target_eid
 oo0oOooo0O = map_request . target_group
 oOOoo = lisp_print_eid_tuple ( o0Ooo0Oooo0o , oo0oOooo0O )
 OOoo0O = map_request . itr_rlocs [ 0 ]
 oOOOOOOooOOoO = map_request . xtr_id
 OOO0O0O = map_request . nonce
 oOoO0OooO0O = LISP_NO_ACTION
 O0o0oo = map_request . subscribe_bit
 o00OooO0o0Ooo = map_request . decent_nat_xtr
 if 47 - 47: oO0o + ooOoO0o - o0oOOo0O0Ooo
 if 27 - 27: O0
 if 7 - 7: iII111i
 if 14 - 14: i1IIi - i1IIi + iII111i
 if 92 - 92: ooOoO0o
 o000OOoOO0 = True
 OooOOOOOO = ( lisp_get_eid_hash ( o0Ooo0Oooo0o ) != None )
 if ( OooOOOOOO ) :
  iiO0OoO0OOO00 = map_request . map_request_signature
  if ( iiO0OoO0OOO00 == None ) :
   o000OOoOO0 = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
  else :
   Oooo00oo0o = map_request . signature_eid
   iiii1I1I11 , OOO0OoOooO0 , o000OOoOO0 = lisp_lookup_public_key ( Oooo00oo0o )
   if ( o000OOoOO0 ) :
    o000OOoOO0 = map_request . verify_map_request_sig ( OOO0OoOooO0 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Oooo00oo0o . print_address ( ) , iiii1I1I11 . print_address ( ) ) )
    if 2 - 2: Ii1I * O0 . II111iiii
    if 39 - 39: iII111i + iIii1I11I1II1 / Ii1I . IiII
   i1IiIiii = bold ( "passed" , False ) if o000OOoOO0 else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( i1IiIiii ) )
   if 25 - 25: I1Ii111 % iII111i / OoO0O00 % Oo0Ooo % Ii1I
   if 46 - 46: II111iiii * iII111i
   if 80 - 80: OoooooooOO * OoooooooOO . I1IiiI
 if ( O0o0oo and o000OOoOO0 == False ) :
  O0o0oo = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 82 - 82: OoOoOO00 / oO0o - OoOoOO00 . I1IiiI
  if 17 - 17: OoOoOO00
  if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
  if 57 - 57: O0
  if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
  if 13 - 13: I1ii11iIi11i
  if 32 - 32: OOooOOo / I11i + I1Ii111 / Oo0Ooo * OoooooooOO / II111iiii
  if 8 - 8: OoO0O00
  if 17 - 17: iIii1I11I1II1 - Oo0Ooo
  if 25 - 25: O0 + I1ii11iIi11i
  if 53 - 53: OoooooooOO . Oo0Ooo
  if 35 - 35: OOooOOo % i11iIiiIii % ooOoO0o . O0
  if 9 - 9: ooOoO0o + iII111i / i1IIi % Oo0Ooo - o0oOOo0O0Ooo / I1IiiI
  if 42 - 42: OOooOOo + oO0o % O0 * I1ii11iIi11i + i11iIiiIii
 IiII11I1I1II = OOoo0O if ( OOoo0O . afi == ecm_source . afi ) else ecm_source
 if 30 - 30: II111iiii . iIii1I11I1II1 * IiII / II111iiii
 I1iOooO0o = lisp_site_eid_lookup ( o0Ooo0Oooo0o , oo0oOooo0O , False )
 if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
 if ( I1iOooO0o == None or I1iOooO0o . is_star_g ( ) ) :
  oOiiI1i11i1Ii = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( oOiiI1i11i1Ii ,
 green ( oOOoo , False ) ) )
  if 94 - 94: II111iiii + I11i * iIii1I11I1II1 / iII111i % i1IIi - OoooooooOO
  if 29 - 29: OoOoOO00 / OoooooooOO / i11iIiiIii
  if 23 - 23: o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo . II111iiii / ooOoO0o
  if 56 - 56: IiII - ooOoO0o % oO0o / Oo0Ooo * oO0o % O0
  lisp_send_negative_map_reply ( lisp_sockets , o0Ooo0Oooo0o , oo0oOooo0O , OOO0O0O , OOoo0O ,
 mr_sport , 15 , oOOOOOOooOOoO , O0o0oo )
  if 71 - 71: iII111i / II111iiii - II111iiii / I1IiiI
  return ( [ o0Ooo0Oooo0o , oo0oOooo0O , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 24 - 24: O0 . I1IiiI + IiII . IiII
  if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
 Ooo = I1iOooO0o . print_eid_tuple ( )
 i1i1I11I1I = I1iOooO0o . site . site_name
 if 15 - 15: i11iIiiIii + o0oOOo0O0Ooo . Ii1I . I1IiiI
 if 8 - 8: iII111i % II111iiii + IiII
 if 5 - 5: i1IIi + II111iiii
 if 75 - 75: OOooOOo . IiII . I1IiiI + OoooooooOO
 if 35 - 35: I11i % i1IIi - I1ii11iIi11i . Oo0Ooo
 if ( OooOOOOOO == False and I1iOooO0o . require_signature ) :
  iiO0OoO0OOO00 = map_request . map_request_signature
  Oooo00oo0o = map_request . signature_eid
  if ( iiO0OoO0OOO00 == None or Oooo00oo0o . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( i1i1I11I1I ) )
   o000OOoOO0 = False
  else :
   Oooo00oo0o = map_request . signature_eid
   iiii1I1I11 , OOO0OoOooO0 , o000OOoOO0 = lisp_lookup_public_key ( Oooo00oo0o )
   if ( o000OOoOO0 ) :
    o000OOoOO0 = map_request . verify_map_request_sig ( OOO0OoOooO0 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( Oooo00oo0o . print_address ( ) , iiii1I1I11 . print_address ( ) ) )
    if 69 - 69: ooOoO0o * OoO0O00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
    if 35 - 35: I1IiiI . OOooOOo * OoO0O00 . I1ii11iIi11i - I1IiiI
   i1IiIiii = bold ( "passed" , False ) if o000OOoOO0 else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( i1IiIiii ) )
   if 5 - 5: i1IIi * II111iiii
   if 64 - 64: I1IiiI * iIii1I11I1II1 % I1Ii111
   if 22 - 22: OoooooooOO + I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo
   if 61 - 61: iIii1I11I1II1
   if 95 - 95: I1ii11iIi11i + IiII * Ii1I - IiII
   if 58 - 58: I1ii11iIi11i - oO0o % I11i * O0
 if ( o000OOoOO0 and I1iOooO0o . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( i1i1I11I1I , green ( Ooo , False ) , green ( oOOoo , False ) ) )
  if 43 - 43: OoOoOO00 + O0
  if 71 - 71: ooOoO0o * I1IiiI / I1ii11iIi11i
  if 8 - 8: I1Ii111 / iIii1I11I1II1
  if 29 - 29: i11iIiiIii % i1IIi + oO0o . I1ii11iIi11i
  if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
  if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
  if ( I1iOooO0o . accept_more_specifics == False ) :
   o0Ooo0Oooo0o = I1iOooO0o . eid
   oo0oOooo0O = I1iOooO0o . group
   if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
   if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
   if 53 - 53: OOooOOo / I11i + OOooOOo / I1IiiI / OoO0O00
   if 12 - 12: i11iIiiIii % ooOoO0o / iII111i . IiII
   if 68 - 68: OOooOOo / iIii1I11I1II1 + I1IiiI . ooOoO0o * IiII
  i1i = 1
  if ( I1iOooO0o . force_ttl != None ) :
   i1i = I1iOooO0o . force_ttl | 0x80000000
   if 72 - 72: I1Ii111
  oO0oOOo = ( I1iOooO0o . proxy_reply_action == "not-registered-yet" )
  if 66 - 66: OoooooooOO / i1IIi . iII111i + II111iiii - i1IIi . OOooOOo
  if 62 - 62: oO0o % i11iIiiIii * Oo0Ooo / OOooOOo + OOooOOo
  if 11 - 11: I11i % iIii1I11I1II1
  if 69 - 69: OoOoOO00 / oO0o . iII111i . i1IIi % o0oOOo0O0Ooo + I1ii11iIi11i
  lisp_send_negative_map_reply ( lisp_sockets , o0Ooo0Oooo0o , oo0oOooo0O , OOO0O0O , OOoo0O ,
 mr_sport , i1i , oOOOOOOooOOoO , O0o0oo , not_reg_yet = oO0oOOo )
  if 46 - 46: I11i
  return ( [ o0Ooo0Oooo0o , oo0oOooo0O , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 78 - 78: IiII / II111iiii
  if 55 - 55: Oo0Ooo
  if 80 - 80: o0oOOo0O0Ooo - I1Ii111 * O0 * iIii1I11I1II1
  if 59 - 59: I1ii11iIi11i + I11i / OoO0O00
  if 36 - 36: o0oOOo0O0Ooo + ooOoO0o * I11i
 oOO0O000OOo0 = False
 I1iI1II1iI1 = ""
 i111IiIIIIi = False
 if ( I1iOooO0o . force_nat_proxy_reply ) :
  I1iI1II1iI1 = ", nat-forced"
  oOO0O000OOo0 = ( o00OooO0o0Ooo == False )
  i111IiIIIIi = True
 elif ( I1iOooO0o . force_proxy_reply ) :
  I1iI1II1iI1 = ", forced"
  i111IiIIIIi = True
 elif ( I1iOooO0o . proxy_reply_requested ) :
  I1iI1II1iI1 = ", requested"
  i111IiIIIIi = True
 elif ( map_request . pitr_bit and I1iOooO0o . pitr_proxy_reply_drop ) :
  I1iI1II1iI1 = ", drop-to-pitr"
  oOoO0OooO0O = LISP_DROP_ACTION
 elif ( I1iOooO0o . proxy_reply_action != "" ) :
  oOoO0OooO0O = I1iOooO0o . proxy_reply_action
  I1iI1II1iI1 = ", forced, action {}" . format ( oOoO0OooO0O )
  oOoO0OooO0O = LISP_DROP_ACTION if ( oOoO0OooO0O == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 95 - 95: I11i - ooOoO0o % Ii1I % Oo0Ooo
  if 2 - 2: Ii1I
  if 9 - 9: Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
  if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
  if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
  if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
  if 66 - 66: iII111i % iII111i
 oooO0o = False
 OOOO0 = None
 if ( i111IiIIIIi and I1iOooO0o . policy in lisp_policies ) :
  III1ii = lisp_policies [ I1iOooO0o . policy ]
  if ( III1ii . match_policy_map_request ( map_request , mr_source ) ) : OOOO0 = III1ii
  if 25 - 25: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoooooooOO . i1IIi
  if ( OOOO0 ) :
   i1I1Iiii = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( i1I1Iiii ,
 III1ii . policy_name , III1ii . set_action ) )
  else :
   i1I1Iiii = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( i1I1Iiii ,
 III1ii . policy_name ) )
   oooO0o = True
   if 10 - 10: OoO0O00 % iIii1I11I1II1 * OoOoOO00 / i11iIiiIii - I1IiiI . O0
   if 2 - 2: II111iiii
   if 13 - 13: Ii1I % i11iIiiIii
 if ( I1iI1II1iI1 != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( oOOoo , False ) , i1i1I11I1I , green ( Ooo , False ) ,
  # I1Ii111
 I1iI1II1iI1 ) )
  if 68 - 68: OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % OoOoOO00 / i1IIi
  i1i1i1 = I1iOooO0o . registered_rlocs
  i1i = 1440
  if ( oOO0O000OOo0 ) :
   if ( I1iOooO0o . site_id != 0 ) :
    IIiIiiI1Iii = map_request . source_eid
    i1i1i1 = lisp_get_private_rloc_set ( I1iOooO0o , IIiIiiI1Iii , oo0oOooo0O )
    if 11 - 11: iIii1I11I1II1 + oO0o - I11i - O0 + I1Ii111 . OOooOOo
   if ( i1i1i1 == I1iOooO0o . registered_rlocs ) :
    i1IiI = ( I1iOooO0o . group . is_null ( ) == False )
    iIiii = lisp_get_partial_rloc_set ( i1i1i1 , IiII11I1I1II , i1IiI )
    if ( iIiii != i1i1i1 ) :
     i1i = 15
     i1i1i1 = iIiii
     if 7 - 7: oO0o - I11i
     if 59 - 59: Ii1I / o0oOOo0O0Ooo / OoO0O00 + IiII + i11iIiiIii
     if 64 - 64: o0oOOo0O0Ooo * IiII * IiII * iII111i % i11iIiiIii
     if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
     if 10 - 10: OOooOOo / I1ii11iIi11i
     if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
     if 48 - 48: O0 / i1IIi / iII111i
     if 11 - 11: O0 - OoO0O00 + OoOoOO00 * ooOoO0o - Ii1I
  if ( I1iOooO0o . force_ttl != None ) :
   i1i = I1iOooO0o . force_ttl | 0x80000000
   if 82 - 82: Ii1I - O0 * ooOoO0o . ooOoO0o
   if 32 - 32: o0oOOo0O0Ooo . OoooooooOO % OOooOOo
   if 2 - 2: OoOoOO00 + I1ii11iIi11i + oO0o
   if 27 - 27: OoooooooOO - Ii1I / OoooooooOO + OoO0O00
   if 58 - 58: OOooOOo * I11i . I1IiiI
   if 46 - 46: I11i + II111iiii * iII111i % ooOoO0o - I1IiiI
  if ( OOOO0 ) :
   if ( OOOO0 . set_record_ttl ) :
    i1i = OOOO0 . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( i1i ) )
    if 73 - 73: I1ii11iIi11i * iIii1I11I1II1 . I1Ii111 - Ii1I
   if ( OOOO0 . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    oOoO0OooO0O = LISP_POLICY_DENIED_ACTION
    i1i1i1 = [ ]
   else :
    iIIiI11 = OOOO0 . set_policy_map_reply ( )
    if ( iIIiI11 ) : i1i1i1 = [ iIIiI11 ]
    if 11 - 11: I11i
    if 48 - 48: IiII / O0
    if 46 - 46: ooOoO0o + oO0o
  if ( oooO0o ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   oOoO0OooO0O = LISP_POLICY_DENIED_ACTION
   i1i1i1 = [ ]
   if 7 - 7: ooOoO0o * oO0o . i1IIi
   if 74 - 74: i1IIi * I11i + OoOoOO00 / OoO0O00 - oO0o / I11i
  II1O0oooO0oooooO = I1iOooO0o . echo_nonce_capable
  if 90 - 90: IiII % I1ii11iIi11i % i1IIi
  if 63 - 63: Ii1I . I1IiiI + IiII / OoOoOO00 + ooOoO0o - iIii1I11I1II1
  if 20 - 20: i1IIi % II111iiii . IiII % iIii1I11I1II1
  if 9 - 9: o0oOOo0O0Ooo
  if ( o000OOoOO0 ) :
   O00O00oO00 = I1iOooO0o . eid
   O0I111Ii1 = I1iOooO0o . group
  else :
   O00O00oO00 = o0Ooo0Oooo0o
   O0I111Ii1 = oo0oOooo0O
   oOoO0OooO0O = LISP_AUTH_FAILURE_ACTION
   i1i1i1 = [ ]
   if 19 - 19: oO0o
   if 18 - 18: Ii1I / OoooooooOO % i1IIi * o0oOOo0O0Ooo
   if 70 - 70: IiII % i1IIi / IiII - o0oOOo0O0Ooo . Oo0Ooo / O0
   if 54 - 54: o0oOOo0O0Ooo
   if 53 - 53: II111iiii / IiII . i1IIi + I1Ii111 / OoO0O00 - OoooooooOO
   if 67 - 67: ooOoO0o . Ii1I - Oo0Ooo * iII111i . I11i - OOooOOo
  if ( O0o0oo ) :
   O00O00oO00 = o0Ooo0Oooo0o
   O0I111Ii1 = oo0oOooo0O
   if 10 - 10: I11i
   if 37 - 37: o0oOOo0O0Ooo / I1IiiI * oO0o / II111iiii
   if 39 - 39: IiII - i1IIi - IiII - OoooooooOO - I1ii11iIi11i
   if 66 - 66: IiII + i1IIi
   if 21 - 21: IiII / i11iIiiIii / OoOoOO00
   if 75 - 75: Ii1I . i1IIi / I1IiiI * iII111i . IiII / OoOoOO00
  packet = lisp_build_map_reply ( O00O00oO00 , O0I111Ii1 , i1i1i1 ,
 OOO0O0O , oOoO0OooO0O , i1i , map_request , None , II1O0oooO0oooooO , False )
  if 58 - 58: ooOoO0o + OOooOOo / ooOoO0o / i11iIiiIii
  if ( O0o0oo ) :
   lisp_process_pubsub ( lisp_sockets , packet , O00O00oO00 , OOoo0O ,
 mr_sport , OOO0O0O , i1i , oOOOOOOooOOoO )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , OOoo0O , mr_sport )
   if 95 - 95: ooOoO0o
   if 10 - 10: OoO0O00 % ooOoO0o * o0oOOo0O0Ooo
  return ( [ I1iOooO0o . eid , I1iOooO0o . group , LISP_DDT_ACTION_MS_ACK ] )
  if 37 - 37: Ii1I . o0oOOo0O0Ooo
  if 34 - 34: ooOoO0o * IiII . Ii1I + iIii1I11I1II1
  if 1 - 1: i11iIiiIii + I11i
  if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
  if 67 - 67: oO0o % I1Ii111
 o00O000o0O0O = len ( I1iOooO0o . registered_rlocs )
 if ( o00O000o0O0O == 0 ) :
  lprint ( ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" ) . format ( green ( oOOoo , False ) , i1i1I11I1I ,
  # iIii1I11I1II1 * O0 / Oo0Ooo . o0oOOo0O0Ooo + I1IiiI
 green ( Ooo , False ) ) )
  return ( [ I1iOooO0o . eid , I1iOooO0o . group , LISP_DDT_ACTION_MS_ACK ] )
  if 48 - 48: iIii1I11I1II1 * I1IiiI . I1Ii111 * IiII / I1ii11iIi11i % I1IiiI
  if 75 - 75: O0 . I1Ii111 . Ii1I % Oo0Ooo - OOooOOo / i11iIiiIii
  if 35 - 35: OoO0O00 . II111iiii + I1Ii111 + Ii1I - O0 + OoOoOO00
  if 77 - 77: O0 % Ii1I - I1ii11iIi11i
  if 17 - 17: OoooooooOO - OoooooooOO % I1Ii111 * Ii1I . OoooooooOO
 Oo00Oo0OOO = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 5 - 5: I11i . ooOoO0o
 iiIIII11iIii = map_request . target_eid . hash_address ( Oo00Oo0OOO )
 iiIIII11iIii %= o00O000o0O0O
 IiIii11I1 = I1iOooO0o . registered_rlocs [ iiIIII11iIii ]
 if 17 - 17: OoooooooOO + ooOoO0o
 if ( IiIii11I1 . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( oOOoo , False ) ,
  # II111iiii - I1Ii111 . ooOoO0o * iII111i
 i1i1I11I1I , green ( Ooo , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( oOOoo , False ) ,
  # II111iiii + I1ii11iIi11i - OoooooooOO
 red ( IiIii11I1 . rloc . print_address ( ) , False ) , i1i1I11I1I ,
 green ( Ooo , False ) ) )
  if 74 - 74: i11iIiiIii % i11iIiiIii / II111iiii + I1ii11iIi11i . OOooOOo
  if 83 - 83: I1IiiI . ooOoO0o . II111iiii % OOooOOo
  if 86 - 86: i11iIiiIii + I1ii11iIi11i / OoOoOO00 * OoooooooOO
  if 6 - 6: II111iiii
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , IiIii11I1 . rloc , to_etr = True )
  if 26 - 26: iIii1I11I1II1 / iIii1I11I1II1 . IiII * i11iIiiIii
 return ( [ I1iOooO0o . eid , I1iOooO0o . group , LISP_DDT_ACTION_MS_ACK ] )
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
 o0Ooo0Oooo0o = map_request . target_eid
 oo0oOooo0O = map_request . target_group
 oOOoo = lisp_print_eid_tuple ( o0Ooo0Oooo0o , oo0oOooo0O )
 OOO0O0O = map_request . nonce
 oOoO0OooO0O = LISP_DDT_ACTION_NULL
 if 46 - 46: i1IIi % IiII
 if 45 - 45: I1ii11iIi11i / I1ii11iIi11i - OoO0O00
 if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
 if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
 if 75 - 75: OOooOOo . ooOoO0o
 IiI1i = None
 if ( lisp_i_am_ms ) :
  I1iOooO0o = lisp_site_eid_lookup ( o0Ooo0Oooo0o , oo0oOooo0O , False )
  if ( I1iOooO0o == None ) : return
  if 11 - 11: o0oOOo0O0Ooo - iII111i - OoO0O00 % I1ii11iIi11i * Oo0Ooo
  if ( I1iOooO0o . registered ) :
   oOoO0OooO0O = LISP_DDT_ACTION_MS_ACK
   i1i = 1440
  else :
   o0Ooo0Oooo0o , oo0oOooo0O , oOoO0OooO0O = lisp_ms_compute_neg_prefix ( o0Ooo0Oooo0o , oo0oOooo0O )
   oOoO0OooO0O = LISP_DDT_ACTION_MS_NOT_REG
   i1i = 1
   if 51 - 51: I1IiiI + O0
 else :
  IiI1i = lisp_ddt_cache_lookup ( o0Ooo0Oooo0o , oo0oOooo0O , False )
  if ( IiI1i == None ) :
   oOoO0OooO0O = LISP_DDT_ACTION_NOT_AUTH
   i1i = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( oOOoo , False ) ) )
   if 4 - 4: ooOoO0o / OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1
  elif ( IiI1i . is_auth_prefix ( ) ) :
   if 33 - 33: iII111i . iIii1I11I1II1 - Ii1I
   if 85 - 85: OoOoOO00
   if 57 - 57: Oo0Ooo - II111iiii - I1ii11iIi11i * oO0o
   if 41 - 41: I11i / ooOoO0o + IiII % OoooooooOO
   oOoO0OooO0O = LISP_DDT_ACTION_DELEGATION_HOLE
   i1i = 15
   oo0oOOOOOo0 = IiI1i . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( oo0oOOOOOo0 ,
   # I11i / II111iiii * i11iIiiIii / II111iiii % Oo0Ooo % i11iIiiIii
 green ( oOOoo , False ) ) )
   if 24 - 24: I11i . Ii1I / ooOoO0o + I1ii11iIi11i + OoooooooOO - I11i
   if ( oo0oOooo0O . is_null ( ) ) :
    o0Ooo0Oooo0o = lisp_ddt_compute_neg_prefix ( o0Ooo0Oooo0o , IiI1i ,
 lisp_ddt_cache )
   else :
    oo0oOooo0O = lisp_ddt_compute_neg_prefix ( oo0oOooo0O , IiI1i ,
 lisp_ddt_cache )
    o0Ooo0Oooo0o = lisp_ddt_compute_neg_prefix ( o0Ooo0Oooo0o , IiI1i ,
 IiI1i . source_cache )
    if 51 - 51: I1IiiI % i1IIi + ooOoO0o / I1ii11iIi11i % iIii1I11I1II1 % IiII
   IiI1i = None
  else :
   oo0oOOOOOo0 = IiI1i . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( oo0oOOOOOo0 , green ( oOOoo , False ) ) )
   if 12 - 12: OoOoOO00 * OoO0O00 / IiII - OoO0O00 * o0oOOo0O0Ooo * iII111i
   i1i = 1440
   if 84 - 84: ooOoO0o * OOooOOo / I1Ii111 * I1IiiI * ooOoO0o
   if 75 - 75: oO0o
   if 60 - 60: OoOoOO00 % I1IiiI . i11iIiiIii % OoOoOO00 - I1Ii111
   if 71 - 71: OoooooooOO * Oo0Ooo
   if 80 - 80: iIii1I11I1II1
   if 91 - 91: OoOoOO00 + OoOoOO00 + ooOoO0o
 OO0Oo00OO0oo = lisp_build_map_referral ( o0Ooo0Oooo0o , oo0oOooo0O , IiI1i , oOoO0OooO0O , i1i , OOO0O0O )
 OOO0O0O = map_request . nonce >> 32
 if ( map_request . nonce != 0 and OOO0O0O != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , OO0Oo00OO0oo , ecm_source , port )
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
 OOOoOo0o0Ooo = 0
 if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
 if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
 if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
 if 70 - 70: i1IIi * II111iiii * I1IiiI
 for OOOoOo0o0Ooo in range ( iIiii1 ) :
  Ii1i1Ii = 1 << ( iIiii1 - OOOoOo0o0Ooo - 1 )
  if ( i1111I & Ii1i1Ii ) : break
  if 7 - 7: OoooooooOO + II111iiii / Oo0Ooo % O0 % OOooOOo . I1Ii111
  if 78 - 78: iIii1I11I1II1 % OOooOOo
 if ( OOOoOo0o0Ooo > neg_prefix . mask_len ) : neg_prefix . mask_len = OOOoOo0o0Ooo
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
 o0Ooo0Oooo0o , O0OoO0O0 , o0O0O0ooo00O = parms
 if 97 - 97: IiII % Oo0Ooo % OoOoOO00
 if ( O0OoO0O0 == None ) :
  if ( entry . eid . instance_id != o0Ooo0Oooo0o . instance_id ) :
   return ( [ True , parms ] )
   if 87 - 87: i11iIiiIii . oO0o * I1IiiI * I1Ii111
  if ( entry . eid . afi != o0Ooo0Oooo0o . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( O0OoO0O0 ) == False ) :
   return ( [ True , parms ] )
   if 57 - 57: iIii1I11I1II1 / i11iIiiIii / IiII + I1ii11iIi11i % I1IiiI
   if 80 - 80: iIii1I11I1II1
   if 23 - 23: II111iiii . ooOoO0o % I1Ii111
   if 39 - 39: OoooooooOO
   if 10 - 10: Oo0Ooo * iII111i
   if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
 lisp_find_negative_mask_len ( o0Ooo0Oooo0o , entry . eid , o0O0O0ooo00O )
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
 I1i1 = lisp_address ( group . afi , "" , 0 , 0 )
 I1i1 . copy_address ( group )
 I1i1 . mask_len = 0
 O0OoO0O0 = None
 if 47 - 47: OoOoOO00 % I1Ii111 / iIii1I11I1II1 % Ii1I % o0oOOo0O0Ooo
 if 49 - 49: OOooOOo
 if 1 - 1: I1ii11iIi11i - OoOoOO00 / oO0o + OoooooooOO % o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
 if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
 if ( group . is_null ( ) ) :
  IiI1i = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( IiI1i == None ) :
   o0O0O0ooo00O . mask_len = o0O0O0ooo00O . host_mask_len ( )
   I1i1 . mask_len = I1i1 . host_mask_len ( )
   return ( [ o0O0O0ooo00O , I1i1 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 77 - 77: OOooOOo + ooOoO0o / O0
  I11IiI = lisp_sites_by_eid
  if ( IiI1i . is_auth_prefix ( ) ) : O0OoO0O0 = IiI1i . eid
 else :
  IiI1i = lisp_ddt_cache . lookup_cache ( group , False )
  if ( IiI1i == None ) :
   o0O0O0ooo00O . mask_len = o0O0O0ooo00O . host_mask_len ( )
   I1i1 . mask_len = I1i1 . host_mask_len ( )
   return ( [ o0O0O0ooo00O , I1i1 , LISP_DDT_ACTION_NOT_AUTH ] )
   if 54 - 54: OoOoOO00 * i11iIiiIii / Ii1I * OOooOOo % OoooooooOO
  if ( IiI1i . is_auth_prefix ( ) ) : O0OoO0O0 = IiI1i . group
  if 69 - 69: OoOoOO00 / I1Ii111 + OOooOOo + I1Ii111
  group , O0OoO0O0 , I1i1 = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , O0OoO0O0 , I1i1 ) )
  if 19 - 19: OOooOOo / i1IIi % OoO0O00
  if 94 - 94: I1ii11iIi11i
  I1i1 . mask_address ( I1i1 . mask_len )
  if 18 - 18: Oo0Ooo + i1IIi / i11iIiiIii * oO0o / Oo0Ooo * ooOoO0o
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , O0OoO0O0 . print_prefix ( ) if ( O0OoO0O0 != None ) else "'not found'" ,
  # OOooOOo . i1IIi
  # I1Ii111
  # OOooOOo . O0 + IiII - iII111i * iII111i
 I1i1 . print_prefix ( ) ) )
  if 6 - 6: iIii1I11I1II1 * i1IIi
  I11IiI = IiI1i . source_cache
  if 66 - 66: OoooooooOO * I11i * ooOoO0o % oO0o - Oo0Ooo
  if 17 - 17: Ii1I * I1ii11iIi11i - OoO0O00 - O0 + o0oOOo0O0Ooo + I1ii11iIi11i
  if 78 - 78: OOooOOo * Oo0Ooo * Ii1I
  if 94 - 94: OoooooooOO % iII111i
  if 48 - 48: iIii1I11I1II1
 oOoO0OooO0O = LISP_DDT_ACTION_DELEGATION_HOLE if ( O0OoO0O0 != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 25 - 25: i1IIi % o0oOOo0O0Ooo . iII111i / OoooooooOO + i1IIi
 if 76 - 76: Oo0Ooo / OOooOOo + ooOoO0o % OoooooooOO - Oo0Ooo - I11i
 if 36 - 36: OoO0O00 . Oo0Ooo * I1ii11iIi11i
 if 16 - 16: IiII + OOooOOo
 if 33 - 33: ooOoO0o . i11iIiiIii + OOooOOo
 if 77 - 77: OoooooooOO * Ii1I * iIii1I11I1II1 + IiII
 eid , O0OoO0O0 , o0O0O0ooo00O = I11IiI . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , O0OoO0O0 , o0O0O0ooo00O ) )
 if 53 - 53: IiII + I1Ii111 + oO0o
 if 31 - 31: OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
 if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
 if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
 o0O0O0ooo00O . mask_address ( o0O0O0ooo00O . mask_len )
 if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # Oo0Ooo - I1Ii111 / i1IIi
 # I11i + i1IIi + I1ii11iIi11i * OoooooooOO * IiII
 O0OoO0O0 . print_prefix ( ) if ( O0OoO0O0 != None ) else "'not found'" , o0O0O0ooo00O . print_prefix ( ) ) )
 if 70 - 70: iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / II111iiii + I1IiiI
 if 33 - 33: oO0o
 return ( [ o0O0O0ooo00O , I1i1 , oOoO0OooO0O ] )
 if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
 if 46 - 46: i11iIiiIii + I11i - iIii1I11I1II1 / OoO0O00 - ooOoO0o / i1IIi
 if 44 - 44: o0oOOo0O0Ooo + Oo0Ooo
 if 46 - 46: OOooOOo % I1IiiI
 if 66 - 66: iIii1I11I1II1 . o0oOOo0O0Ooo - ooOoO0o
 if 27 - 27: Oo0Ooo - i1IIi * OoooooooOO - OoOoOO00 + OoOoOO00
 if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
 if 86 - 86: Ii1I * OoOoOO00 % I1ii11iIi11i + OOooOOo
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 85 - 85: iII111i % i11iIiiIii
 o0Ooo0Oooo0o = map_request . target_eid
 oo0oOooo0O = map_request . target_group
 OOO0O0O = map_request . nonce
 if 78 - 78: i11iIiiIii / I11i / Oo0Ooo + II111iiii - I1ii11iIi11i / I1ii11iIi11i
 if ( action == LISP_DDT_ACTION_MS_ACK ) : i1i = 1440
 if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
 if 41 - 41: Ii1I + IiII
 if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
 if 53 - 53: I1IiiI % OOooOOo + Ii1I - Ii1I
 OoO0o0OooO = lisp_map_referral ( )
 OoO0o0OooO . record_count = 1
 OoO0o0OooO . nonce = OOO0O0O
 OO0Oo00OO0oo = OoO0o0OooO . encode ( )
 OoO0o0OooO . print_map_referral ( )
 if 99 - 99: i1IIi * OoOoOO00 - i1IIi
 OoOoOOoOo = False
 if 65 - 65: OoO0O00 / i11iIiiIii + I1ii11iIi11i + OoOoOO00
 if 82 - 82: Ii1I * OOooOOo % ooOoO0o / OoO0O00 - Oo0Ooo . I1Ii111
 if 90 - 90: I11i * i11iIiiIii % i1IIi + I1Ii111 / OoO0O00
 if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
 if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
 if 45 - 45: I1ii11iIi11i - I11i
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( o0Ooo0Oooo0o ,
 oo0oOooo0O )
  i1i = 15
  if 60 - 60: OOooOOo - OOooOOo * OoOoOO00 / Ii1I % iII111i % Oo0Ooo
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : i1i = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : i1i = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : i1i = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : i1i = 0
 if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
 iiiiiIIiii = False
 o00O000o0O0O = 0
 IiI1i = lisp_ddt_cache_lookup ( o0Ooo0Oooo0o , oo0oOooo0O , False )
 if ( IiI1i != None ) :
  o00O000o0O0O = len ( IiI1i . delegation_set )
  iiiiiIIiii = IiI1i . is_ms_peer_entry ( )
  IiI1i . map_referrals_sent += 1
  if 39 - 39: i11iIiiIii + I1Ii111
  if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
  if 48 - 48: IiII
  if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
  if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : OoOoOOoOo = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  OoOoOOoOo = ( iiiiiIIiii == False )
  if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
  if 57 - 57: I1Ii111 / II111iiii % iII111i
  if 32 - 32: IiII - OOooOOo + i11iIiiIii + I1IiiI . iII111i
  if 75 - 75: o0oOOo0O0Ooo % o0oOOo0O0Ooo . I1IiiI / OoO0O00
  if 22 - 22: Oo0Ooo / iIii1I11I1II1 + o0oOOo0O0Ooo
 Oo0oOoooO = lisp_eid_record ( )
 Oo0oOoooO . rloc_count = o00O000o0O0O
 Oo0oOoooO . authoritative = True
 Oo0oOoooO . action = action
 Oo0oOoooO . ddt_incomplete = OoOoOOoOo
 Oo0oOoooO . eid = eid_prefix
 Oo0oOoooO . group = group_prefix
 Oo0oOoooO . record_ttl = i1i
 if 16 - 16: II111iiii . Ii1I + I1Ii111 % i1IIi / i11iIiiIii + OOooOOo
 OO0Oo00OO0oo += Oo0oOoooO . encode ( )
 Oo0oOoooO . print_record ( "  " , True )
 if 43 - 43: I1IiiI . Oo0Ooo + i1IIi + I11i / OoO0O00
 if 66 - 66: i11iIiiIii
 if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
 if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
 if ( o00O000o0O0O != 0 ) :
  for I11I1I in IiI1i . delegation_set :
   oOiI111IIIiIii = lisp_rloc_record ( )
   oOiI111IIIiIii . rloc = I11I1I . delegate_address
   oOiI111IIIiIii . priority = I11I1I . priority
   oOiI111IIIiIii . weight = I11I1I . weight
   oOiI111IIIiIii . mpriority = 255
   oOiI111IIIiIii . mweight = 0
   oOiI111IIIiIii . reach_bit = True
   OO0Oo00OO0oo += oOiI111IIIiIii . encode ( )
   oOiI111IIIiIii . print_record ( "    " )
   if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
   if 10 - 10: I11i
   if 24 - 24: Ii1I
   if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
   if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
   if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
   if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , OO0Oo00OO0oo , ecm_source , port )
 return
 if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
 if 26 - 26: ooOoO0o + Oo0Ooo
 if 24 - 24: I1IiiI
 if 43 - 43: OoO0O00
 if 51 - 51: OoooooooOO % IiII % Oo0Ooo
 if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
 if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
 if 95 - 95: iII111i
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub , not_reg_yet = False ) :
 if 77 - 77: I1IiiI * II111iiii * iIii1I11I1II1
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # ooOoO0o / OOooOOo
 red ( dest . print_address ( ) , False ) ) )
 if 51 - 51: Ii1I - II111iiii % II111iiii * OOooOOo
 oOoO0OooO0O = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 84 - 84: i1IIi . OoOoOO00 % I1ii11iIi11i . OoO0O00 + i11iIiiIii
 if 19 - 19: i1IIi / I1IiiI + IiII . iII111i
 if 68 - 68: iII111i
 if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
 if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
 if ( lisp_get_eid_hash ( eid ) != None ) :
  oOoO0OooO0O = LISP_SEND_MAP_REQUEST_ACTION
  if 9 - 9: IiII * O0 + OOooOOo . II111iiii
 if ( not_reg_yet ) :
  oOoO0OooO0O = LISP_NOT_REGISTERED_YET_ACTION
  if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
  if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
  if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
 OO0Oo00OO0oo = lisp_build_map_reply ( eid , group , [ ] , nonce , oOoO0OooO0O , ttl , None ,
 None , False , False )
 if 16 - 16: I1Ii111 + II111iiii + IiII
 if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
 if 46 - 46: ooOoO0o % II111iiii
 if 61 - 61: OoO0O00 . I1IiiI
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , OO0Oo00OO0oo , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , OO0Oo00OO0oo , dest , port )
  if 89 - 89: IiII
 return
 if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
 if 19 - 19: I1Ii111 + I11i
 if 21 - 21: OoOoOO00
 if 2 - 2: i1IIi . OOooOOo
 if 23 - 23: Ii1I - OOooOOo
 if 89 - 89: i11iIiiIii
 if 40 - 40: OoooooooOO % OoO0O00
def lisp_retransmit_ddt_map_request ( mr ) :
 OoO00OOooo00 = mr . mr_source . print_address ( )
 OOo = mr . print_eid_tuple ( )
 OOO0O0O = mr . nonce
 if 9 - 9: i11iIiiIii % Oo0Ooo
 if 43 - 43: i1IIi * O0 + ooOoO0o + OoO0O00
 if 99 - 99: IiII . OoOoOO00
 if 64 - 64: I1Ii111
 if 96 - 96: Ii1I
 if ( mr . last_request_sent_to ) :
  oOO00O0oooo00 = mr . last_request_sent_to . print_address ( )
  oO00oOOOo = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( oO00oOOOo and oOO00O0oooo00 in oO00oOOOo . referral_set ) :
   oO00oOOOo . referral_set [ oOO00O0oooo00 ] . no_responses += 1
   if 96 - 96: Oo0Ooo + i1IIi * Ii1I - I1ii11iIi11i
   if 81 - 81: i11iIiiIii . OoOoOO00 * o0oOOo0O0Ooo / O0 * OoooooooOO / i11iIiiIii
   if 62 - 62: i11iIiiIii * iII111i . Oo0Ooo % Oo0Ooo
   if 4 - 4: OoooooooOO
   if 66 - 66: iII111i / IiII
   if 45 - 45: o0oOOo0O0Ooo - i1IIi / o0oOOo0O0Ooo + IiII
   if 94 - 94: Ii1I
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( OOo , False ) , lisp_hex_string ( OOO0O0O ) ) )
  if 21 - 21: OoOoOO00
  mr . dequeue_map_request ( )
  return
  if 68 - 68: i11iIiiIii / OOooOOo / I1ii11iIi11i % IiII * IiII + II111iiii
  if 65 - 65: I1IiiI + OoOoOO00 - OoOoOO00 . oO0o
 mr . retry_count += 1
 if 84 - 84: Ii1I * i1IIi
 OOo0oOO0o0oo0 = green ( OoO00OOooo00 , False )
 oooOo = green ( OOo , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # o0oOOo0O0Ooo - Oo0Ooo + ooOoO0o
 red ( mr . itr . print_address ( ) , False ) , OOo0oOO0o0oo0 , oooOo ,
 lisp_hex_string ( OOO0O0O ) ) )
 if 65 - 65: I1Ii111 / o0oOOo0O0Ooo - i11iIiiIii + I11i
 if 75 - 75: O0 - OoO0O00 / oO0o . i1IIi . I1ii11iIi11i + o0oOOo0O0Ooo
 if 29 - 29: Ii1I . OOooOOo
 if 59 - 59: O0 . OoO0O00
 lisp_send_ddt_map_request ( mr , False )
 if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
 if 81 - 81: i1IIi % I11i * iIii1I11I1II1
 if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
 if 59 - 59: II111iiii * I1IiiI
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
 if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
 if 37 - 37: I1Ii111 / OoooooooOO
 if 19 - 19: Ii1I - O0 + I1IiiI + OoooooooOO + ooOoO0o - Oo0Ooo
 if 45 - 45: I1IiiI . OoOoOO00 . OoOoOO00
 if 20 - 20: OoOoOO00
 if 69 - 69: OoOoOO00 * Ii1I % ooOoO0o . OoOoOO00 / oO0o * I1Ii111
 if 93 - 93: OoO0O00 % IiII % ooOoO0o . I1IiiI
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 96 - 96: II111iiii
 if 73 - 73: II111iiii
 if 81 - 81: I1IiiI + OoO0O00
 if 22 - 22: OoO0O00 * OoOoOO00 * I11i * IiII . OoO0O00 . I1ii11iIi11i
 III1iii1i = [ ]
 for Iii in list ( referral . referral_set . values ( ) ) :
  if ( Iii . updown == False ) : continue
  if ( len ( III1iii1i ) == 0 or III1iii1i [ 0 ] . priority == Iii . priority ) :
   III1iii1i . append ( Iii )
  elif ( III1iii1i [ 0 ] . priority > Iii . priority ) :
   III1iii1i = [ ]
   III1iii1i . append ( Iii )
   if 66 - 66: iIii1I11I1II1
   if 13 - 13: O0 / ooOoO0o
   if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
 iI111iiI = len ( III1iii1i )
 if ( iI111iiI == 0 ) : return ( None )
 if 6 - 6: iII111i + II111iiii . IiII . Ii1I / ooOoO0o / I11i
 iiIIII11iIii = dest_eid . hash_address ( source_eid )
 iiIIII11iIii = iiIIII11iIii % iI111iiI
 return ( III1iii1i [ iiIIII11iIii ] )
 if 85 - 85: ooOoO0o / II111iiii / OoO0O00 + Ii1I / i1IIi . iII111i
 if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
 if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
 if 85 - 85: I1IiiI + i1IIi % I1Ii111
 if 76 - 76: i11iIiiIii % i11iIiiIii
 if 33 - 33: OOooOOo . ooOoO0o / iIii1I11I1II1 * OOooOOo / oO0o
 if 75 - 75: Ii1I - OoOoOO00 . OOooOOo - o0oOOo0O0Ooo - I1ii11iIi11i
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 ooO0ooo0O0 = mr . lisp_sockets
 OOO0O0O = mr . nonce
 IiI1ii1ii = mr . itr
 oooo000OOOoO = mr . mr_source
 oOOoo = mr . print_eid_tuple ( )
 if 51 - 51: Oo0Ooo * OOooOOo / iII111i
 if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
 if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
 if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
 if 40 - 40: oO0o * IiII
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( oOOoo , False ) , lisp_hex_string ( OOO0O0O ) ) )
  if 29 - 29: O0 - II111iiii + iII111i
  mr . dequeue_map_request ( )
  return
  if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
  if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
  if 83 - 83: i1IIi
  if 9 - 9: iIii1I11I1II1 + i11iIiiIii
  if 70 - 70: I1IiiI - OoO0O00 % OOooOOo + ooOoO0o % II111iiii
  if 19 - 19: I11i + i1IIi / i1IIi - II111iiii + I1Ii111
 if ( send_to_root ) :
  IiiiI1iIIi = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  o0O0o0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( oOOoo , False ) ) )
 else :
  IiiiI1iIIi = mr . eid
  o0O0o0 = mr . group
  if 80 - 80: oO0o * I1Ii111
  if 87 - 87: iII111i + OoOoOO00 % ooOoO0o - oO0o
  if 40 - 40: i1IIi / OoOoOO00 - I11i / ooOoO0o . Ii1I
  if 8 - 8: I1IiiI . IiII . OOooOOo . O0
  if 3 - 3: Ii1I + i11iIiiIii
 o00000oo = lisp_referral_cache_lookup ( IiiiI1iIIi , o0O0o0 , False )
 if ( o00000oo == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( ooO0ooo0O0 , IiiiI1iIIi , o0O0o0 ,
 OOO0O0O , IiI1ii1ii , mr . sport , 15 , None , False )
  return
  if 73 - 73: I1Ii111 * I1ii11iIi11i
  if 79 - 79: I11i / O0 % Ii1I % I1ii11iIi11i
 II1OOOoo0O = o00000oo . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( II1OOOoo0O ,
 o00000oo . print_referral_type ( ) ) )
 if 95 - 95: oO0o . oO0o - i1IIi % O0
 Iii = lisp_get_referral_node ( o00000oo , oooo000OOOoO , mr . eid )
 if ( Iii == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( ooO0ooo0O0 , o00000oo . eid ,
 o00000oo . group , OOO0O0O , IiI1ii1ii , mr . sport , 1 , None , False )
  return
  if 11 - 11: iII111i * I1IiiI
  if 72 - 72: iII111i % OoooooooOO - ooOoO0o - OoO0O00
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( Iii . referral_address . print_address ( ) ,
 # iIii1I11I1II1 / i1IIi / II111iiii . OoooooooOO / iII111i
 o00000oo . print_referral_type ( ) , green ( oOOoo , False ) ,
 lisp_hex_string ( OOO0O0O ) ) )
 if 32 - 32: IiII
 if 89 - 89: I1IiiI
 if 24 - 24: o0oOOo0O0Ooo - i1IIi . II111iiii
 if 73 - 73: i11iIiiIii % OoooooooOO - i1IIi - O0 * I1Ii111
 OOOoOOO = ( o00000oo . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 o00000oo . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( ooO0ooo0O0 , mr . packet , oooo000OOOoO , mr . sport , mr . eid ,
 Iii . referral_address , to_ms = OOOoOOO , ddt = True )
 if 47 - 47: II111iiii + iII111i / i1IIi * Ii1I . OoO0O00 + IiII
 if 7 - 7: i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o * I1ii11iIi11i
 if 34 - 34: OoOoOO00 - I11i
 if 85 - 85: OoOoOO00 . oO0o
 mr . last_request_sent_to = Iii . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 Iii . map_requests_sent += 1
 return
 if 98 - 98: I1Ii111
 if 49 - 49: OoO0O00 / I1ii11iIi11i % IiII * II111iiii
 if 92 - 92: iIii1I11I1II1 . OoooooooOO . ooOoO0o / II111iiii
 if 30 - 30: i1IIi * Ii1I + Ii1I / I1Ii111
 if 84 - 84: I1IiiI - Oo0Ooo * OoO0O00 * oO0o
 if 13 - 13: I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + oO0o - iII111i
 if 32 - 32: I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
 if 33 - 33: ooOoO0o % I11i
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 72 - 72: OoO0O00 % OoooooooOO / II111iiii * oO0o * I1Ii111
 o0Ooo0Oooo0o = map_request . target_eid
 oo0oOooo0O = map_request . target_group
 OOo = map_request . print_eid_tuple ( )
 OoO00OOooo00 = mr_source . print_address ( )
 OOO0O0O = map_request . nonce
 if 98 - 98: OOooOOo * Ii1I + I1ii11iIi11i / iIii1I11I1II1 / OoOoOO00 + I1IiiI
 OOo0oOO0o0oo0 = green ( OoO00OOooo00 , False )
 oooOo = green ( OOo , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # i11iIiiIii % O0 * IiII * IiII . I1IiiI
 red ( ecm_source . print_address ( ) , False ) , OOo0oOO0o0oo0 , oooOo ,
 lisp_hex_string ( OOO0O0O ) ) )
 if 63 - 63: oO0o
 if 2 - 2: II111iiii
 if 79 - 79: o0oOOo0O0Ooo + i11iIiiIii . II111iiii . I11i . Oo0Ooo / oO0o
 if 39 - 39: ooOoO0o / Oo0Ooo % i11iIiiIii + I1ii11iIi11i * oO0o
 oOoOO0oOo00Oo = lisp_ddt_map_request ( lisp_sockets , packet , o0Ooo0Oooo0o , oo0oOooo0O , OOO0O0O )
 oOoOO0oOo00Oo . packet = packet
 oOoOO0oOo00Oo . itr = ecm_source
 oOoOO0oOo00Oo . mr_source = mr_source
 oOoOO0oOo00Oo . sport = sport
 oOoOO0oOo00Oo . from_pitr = map_request . pitr_bit
 oOoOO0oOo00Oo . queue_map_request ( )
 if 66 - 66: OOooOOo
 lisp_send_ddt_map_request ( oOoOO0oOo00Oo , False )
 return
 if 37 - 37: i1IIi . I1IiiI
 if 3 - 3: O0 * O0 + II111iiii + OoOoOO00 * I11i % Oo0Ooo
 if 19 - 19: oO0o % IiII % OoooooooOO % I1ii11iIi11i / OoO0O00
 if 6 - 6: O0 * I1Ii111 - II111iiii
 if 60 - 60: oO0o % oO0o
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 82 - 82: I1ii11iIi11i
 OOo00o0oOO0o = packet
 o0o000Oo = lisp_map_request ( )
 packet = o0o000Oo . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 89 - 89: I1IiiI / o0oOOo0O0Ooo % i1IIi * ooOoO0o
  if 59 - 59: I11i / OoOoOO00 % ooOoO0o . Ii1I
 o0o000Oo . print_map_request ( )
 if 48 - 48: OoOoOO00 % IiII % i1IIi + o0oOOo0O0Ooo
 if 33 - 33: iIii1I11I1II1 . O0
 if 54 - 54: iIii1I11I1II1
 if 54 - 54: iII111i + OOooOOo + OoO0O00
 if ( o0o000Oo . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , o0o000Oo , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
  if 65 - 65: IiII + OoOoOO00
  if 93 - 93: Ii1I
  if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
  if 5 - 5: OoO0O00 / ooOoO0o
 if ( o0o000Oo . smr_bit ) :
  lisp_process_smr ( o0o000Oo )
  if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
  if 97 - 97: oO0o / Ii1I
  if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
  if 34 - 34: I1Ii111 + OOooOOo * iII111i / ooOoO0o % i11iIiiIii
  if 91 - 91: IiII * Ii1I * OOooOOo
 if ( o0o000Oo . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( o0o000Oo )
  if 17 - 17: o0oOOo0O0Ooo + Ii1I % I1ii11iIi11i + IiII % I1Ii111 + I1ii11iIi11i
  if 100 - 100: I11i * OoO0O00 - i1IIi + iII111i * Ii1I - OoooooooOO
  if 47 - 47: o0oOOo0O0Ooo / Ii1I - iII111i * OOooOOo / i11iIiiIii
  if 97 - 97: iIii1I11I1II1 + OoOoOO00 + OoOoOO00 * o0oOOo0O0Ooo
  if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , o0o000Oo , mr_source ,
 mr_port , ttl , timestamp )
  if 95 - 95: IiII + iII111i % I1IiiI
  if 18 - 18: Oo0Ooo
  if 8 - 8: O0 + iIii1I11I1II1 - O0
  if 67 - 67: O0
  if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
 if ( lisp_i_am_ms ) :
  packet = OOo00o0oOO0o
  o0Ooo0Oooo0o , oo0oOooo0O , iiIIIIiI = lisp_ms_process_map_request ( lisp_sockets ,
 OOo00o0oOO0o , o0o000Oo , mr_source , mr_port , ecm_source , ecm_port )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , o0o000Oo , ecm_source ,
 ecm_port , iiIIIIiI , o0Ooo0Oooo0o , oo0oOooo0O )
   if 18 - 18: II111iiii + ooOoO0o / I1ii11iIi11i - I1Ii111 * I1Ii111 / I1ii11iIi11i
  return
  if 10 - 10: iIii1I11I1II1
  if 81 - 81: I1Ii111 - ooOoO0o * Oo0Ooo - OoO0O00 + I1ii11iIi11i
  if 16 - 16: iII111i * i1IIi - IiII + OOooOOo
  if 89 - 89: o0oOOo0O0Ooo . Oo0Ooo
  if 48 - 48: o0oOOo0O0Ooo / O0 % i1IIi
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , OOo00o0oOO0o , o0o000Oo ,
 ecm_source , mr_port , mr_source )
  if 82 - 82: OoOoOO00 * Ii1I . I1ii11iIi11i * OoO0O00 % Oo0Ooo
  if 95 - 95: OoO0O00 / oO0o
  if 15 - 15: I1IiiI - o0oOOo0O0Ooo % iIii1I11I1II1 % I11i * OoOoOO00 % IiII
  if 74 - 74: iII111i - O0 * o0oOOo0O0Ooo / OoooooooOO + II111iiii + Ii1I
  if 39 - 39: i11iIiiIii . IiII + I1ii11iIi11i % IiII
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = OOo00o0oOO0o
  lisp_ddt_process_map_request ( lisp_sockets , o0o000Oo , ecm_source ,
 ecm_port )
  if 96 - 96: I11i / I1IiiI . i1IIi
 return
 if 67 - 67: i11iIiiIii
 if 3 - 3: IiII
 if 47 - 47: O0
 if 60 - 60: OOooOOo / ooOoO0o + Oo0Ooo / O0 - oO0o
 if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
 if 4 - 4: I1IiiI
 if 31 - 31: ooOoO0o * i1IIi . O0
 if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
def lisp_store_mr_stats ( source , nonce ) :
 oOoOO0oOo00Oo = lisp_get_map_resolver ( source , None )
 if ( oOoOO0oOo00Oo == None ) : return
 if 100 - 100: I1Ii111
 if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
 if 88 - 88: IiII
 if 29 - 29: iII111i . ooOoO0o
 oOoOO0oOo00Oo . neg_map_replies_received += 1
 oOoOO0oOo00Oo . last_reply = lisp_get_timestamp ( )
 if 62 - 62: IiII
 if 95 - 95: ooOoO0o / i1IIi + II111iiii + OoO0O00 % OoO0O00
 if 18 - 18: ooOoO0o * I1IiiI / iII111i % iII111i
 if 9 - 9: i11iIiiIii % ooOoO0o % O0 + i1IIi / O0
 if ( ( oOoOO0oOo00Oo . neg_map_replies_received % 100 ) == 0 ) : oOoOO0oOo00Oo . total_rtt = 0
 if 12 - 12: I1Ii111 - iII111i * iII111i + OoO0O00 . Ii1I % I11i
 if 28 - 28: ooOoO0o % OoO0O00 - II111iiii * IiII - I1IiiI + I1IiiI
 if 84 - 84: IiII / Ii1I
 if 39 - 39: OOooOOo - iIii1I11I1II1 + OoOoOO00 % IiII * OoooooooOO % Ii1I
 if ( oOoOO0oOo00Oo . last_nonce == nonce ) :
  oOoOO0oOo00Oo . total_rtt += ( time . time ( ) - oOoOO0oOo00Oo . last_used )
  oOoOO0oOo00Oo . last_nonce = 0
  if 11 - 11: I1ii11iIi11i
 if ( ( oOoOO0oOo00Oo . neg_map_replies_received % 10 ) == 0 ) : oOoOO0oOo00Oo . last_nonce = 0
 return
 if 83 - 83: O0
 if 97 - 97: O0
 if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
 if 28 - 28: I1Ii111 * II111iiii
 if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
 if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
 if 15 - 15: I11i
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 67 - 67: iIii1I11I1II1
 o0o000o = lisp_map_reply ( )
 packet = o0o000o . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 91 - 91: ooOoO0o
 o0o000o . print_map_reply ( )
 if 66 - 66: OOooOOo
 if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
 if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
 if 9 - 9: Ii1I
 iI1i11iIIiI = None
 for o000o0O0Oo00 in range ( o0o000o . record_count ) :
  Oo0oOoooO = lisp_eid_record ( )
  packet = Oo0oOoooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 98 - 98: o0oOOo0O0Ooo + OoOoOO00 + Ii1I
  Oo0oOoooO . print_record ( "  " , False )
  if 44 - 44: oO0o % iII111i . I1ii11iIi11i
  if 24 - 24: i1IIi . I1ii11iIi11i * Oo0Ooo . OoOoOO00
  if 18 - 18: i1IIi + iII111i + I1Ii111
  if 29 - 29: OOooOOo * OOooOOo . I1ii11iIi11i . iII111i % OOooOOo
  if 63 - 63: iII111i - o0oOOo0O0Ooo * OOooOOo . Ii1I . Ii1I
  if ( Oo0oOoooO . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , o0o000o . nonce )
   if 7 - 7: i11iIiiIii . I1ii11iIi11i
   if 4 - 4: i11iIiiIii % OoO0O00 . oO0o
  iii = ( Oo0oOoooO . group . is_null ( ) == False )
  if 72 - 72: i1IIi + I1Ii111 . oO0o * oO0o * I1IiiI
  if 40 - 40: OoO0O00 % ooOoO0o + iII111i + IiII + I11i * Oo0Ooo
  if 99 - 99: Oo0Ooo
  if 99 - 99: I1Ii111 + oO0o % OoooooooOO
  if 88 - 88: ooOoO0o % Oo0Ooo * II111iiii
  if ( lisp_decent_push_configured ) :
   oOoO0OooO0O = Oo0oOoooO . action
   if ( iii and oOoO0OooO0O == LISP_DROP_ACTION ) :
    if ( Oo0oOoooO . eid . is_local ( ) ) : continue
    if 62 - 62: iII111i * I1Ii111 % OoOoOO00 * O0
    if 85 - 85: II111iiii - O0 . i11iIiiIii . o0oOOo0O0Ooo + ooOoO0o - ooOoO0o
    if 25 - 25: I1ii11iIi11i % Ii1I * O0 / I1IiiI % OOooOOo
    if 42 - 42: IiII - IiII - I1ii11iIi11i + i1IIi * Oo0Ooo
    if 80 - 80: oO0o + O0
    if 84 - 84: i1IIi - II111iiii
    if 2 - 2: i11iIiiIii - OoO0O00 * Oo0Ooo
  if ( iii == False and Oo0oOoooO . eid . is_null ( ) ) : continue
  if 100 - 100: I1Ii111
  if 5 - 5: IiII % oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / Ii1I
  if 55 - 55: Oo0Ooo / o0oOOo0O0Ooo
  if 51 - 51: I1IiiI + i11iIiiIii / ooOoO0o % I1IiiI + Oo0Ooo
  if 6 - 6: OoOoOO00 . O0
  if ( iii ) :
   I1I1i1I11I = lisp_map_cache . lookup_cache ( Oo0oOoooO . group , True )
   if ( I1I1i1I11I ) : I1I1i1I11I = I1I1i1I11I . lookup_source_cache ( Oo0oOoooO . eid , False )
  else :
   I1I1i1I11I = lisp_map_cache . lookup_cache ( Oo0oOoooO . eid , True )
   if 9 - 9: I11i
  o0ooo0oOO0o = ( I1I1i1I11I == None )
  if 78 - 78: iIii1I11I1II1 % I1ii11iIi11i % IiII
  if 59 - 59: iII111i - I1ii11iIi11i / OoooooooOO
  if 37 - 37: Oo0Ooo - OoO0O00 . i11iIiiIii + I1IiiI . iIii1I11I1II1 % OoOoOO00
  if 61 - 61: oO0o . o0oOOo0O0Ooo
  if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
  if ( I1I1i1I11I == None ) :
   o0o00 , Oo0OoO00O , OOo00 = lisp_allow_gleaning ( Oo0oOoooO . eid , Oo0oOoooO . group ,
 None )
   if ( o0o00 ) : continue
  else :
   if ( I1I1i1I11I . gleaned ) : continue
   if 28 - 28: iIii1I11I1II1 - o0oOOo0O0Ooo . iIii1I11I1II1 / I11i / I1Ii111 % iIii1I11I1II1
   if 45 - 45: OoO0O00 + ooOoO0o / iIii1I11I1II1 % i11iIiiIii
   if 16 - 16: i1IIi / oO0o - OOooOOo / Ii1I + I1IiiI
   if 62 - 62: i11iIiiIii . Ii1I . iII111i / I1Ii111 * OoO0O00
   if 31 - 31: OoOoOO00
  i1i1i1 = [ ]
  ii1OOO0 = None
  oOo = None
  for I11ii1IiI1Ii in range ( Oo0oOoooO . rloc_count ) :
   oOiI111IIIiIii = lisp_rloc_record ( )
   oOiI111IIIiIii . keys = o0o000o . keys
   packet = oOiI111IIIiIii . decode ( packet , o0o000o . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 50 - 50: O0 + Oo0Ooo % I1ii11iIi11i . OOooOOo
   oOiI111IIIiIii . print_record ( "    " )
   if 88 - 88: iII111i * o0oOOo0O0Ooo + OoooooooOO * oO0o
   if 7 - 7: Oo0Ooo * Ii1I . IiII
   if 86 - 86: O0 * OoOoOO00 * I11i . OoooooooOO
   if 18 - 18: o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoO0O00 . oO0o . iIii1I11I1II1
   OOooooOoO00o0 = None
   if ( I1I1i1I11I ) :
    OOooooOoO00o0 = I1I1i1I11I . get_rloc ( oOiI111IIIiIii . rloc )
    if ( OOooooOoO00o0 == None and iii and I1I1i1I11I . rloc_set != [ ] ) :
     oOOO = I1I1i1I11I . rloc_set [ 0 ]
     OOooooOoO00o0 = oOOO . get_rle ( oOiI111IIIiIii . rloc )
     if 99 - 99: iII111i . IiII * OoooooooOO - OoO0O00
     if 80 - 80: OoOoOO00 * iIii1I11I1II1 % O0 . O0
   if ( OOooooOoO00o0 ) :
    iIIiI11 = OOooooOoO00o0
   else :
    iIIiI11 = lisp_rloc ( )
    if 100 - 100: OoO0O00 + II111iiii % oO0o / OoOoOO00 * OOooOOo
    if 23 - 23: OoOoOO00
    if 56 - 56: o0oOOo0O0Ooo / oO0o * I1Ii111 + iIii1I11I1II1 / IiII + o0oOOo0O0Ooo
    if 50 - 50: I1IiiI * ooOoO0o
    if 49 - 49: oO0o . I11i + OoooooooOO / iII111i * Oo0Ooo % iIii1I11I1II1
    if 49 - 49: II111iiii * iIii1I11I1II1 / OoooooooOO * i1IIi
    if 81 - 81: OoOoOO00 * i11iIiiIii + I1IiiI
   I1I1I1 = iIIiI11 . store_rloc_from_record ( oOiI111IIIiIii , o0o000o . nonce , source )
   iIIiI11 . echo_nonce_capable = o0o000o . echo_nonce_capable
   if 2 - 2: I11i - IiII + I1IiiI % OoO0O00 + iIii1I11I1II1 + oO0o
   if ( iIIiI11 . echo_nonce_capable ) :
    O00oO000Oo0 = iIIiI11 . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , O00oO000Oo0 ) == None ) :
     lisp_echo_nonce ( O00oO000Oo0 )
     if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
     if 57 - 57: oO0o + O0 - OoOoOO00
     if 14 - 14: II111iiii + i11iIiiIii + Ii1I / o0oOOo0O0Ooo . OoO0O00
     if 93 - 93: o0oOOo0O0Ooo + i1IIi
     if 24 - 24: i1IIi
     if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
   if ( iIIiI11 . json ) :
    if ( lisp_is_json_telemetry ( iIIiI11 . json . json_string ) ) :
     iI111i1ii = iIIiI11 . json . json_string
     iI111i1ii = lisp_encode_telemetry ( iI111i1ii , ii = itr_in_ts )
     iIIiI11 . json . json_string = iI111i1ii
     if 99 - 99: Oo0Ooo
     if 38 - 38: I1ii11iIi11i - I1IiiI
     if 50 - 50: iII111i % OoO0O00 - oO0o + Oo0Ooo . O0 . iII111i
     if 42 - 42: iII111i + I1ii11iIi11i
     if 44 - 44: I1ii11iIi11i % IiII
     if 1 - 1: Oo0Ooo + IiII - I1Ii111 / I1Ii111
   if ( oOo == None ) : oOo = iIIiI11 . rloc_name
   if 25 - 25: OoOoOO00
   if 52 - 52: OOooOOo + IiII
   if 73 - 73: OoooooooOO - I1Ii111 % iII111i / OOooOOo . o0oOOo0O0Ooo - IiII
   if 69 - 69: Ii1I . iIii1I11I1II1 / Oo0Ooo * Oo0Ooo % IiII
   if 5 - 5: OOooOOo - I1Ii111 + IiII
   if 82 - 82: OOooOOo
   if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
   if 26 - 26: I1IiiI - OOooOOo
   if ( o0o000o . rloc_probe and oOiI111IIIiIii . probe_bit ) :
    if ( iIIiI11 . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( iIIiI11 , source , I1I1I1 ,
 o0o000o , ttl , ii1OOO0 , oOo )
     if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
    if ( iIIiI11 . rloc . is_multicast_address ( ) ) : ii1OOO0 = iIIiI11
    if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
    if 50 - 50: OoooooooOO * II111iiii
    if 7 - 7: ooOoO0o / I11i * iII111i
    if 17 - 17: O0 % I1Ii111
    if 28 - 28: i1IIi * ooOoO0o
   i1i1i1 . append ( iIIiI11 )
   if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
   if 92 - 92: II111iiii - II111iiii % IiII
   if 48 - 48: oO0o / II111iiii + oO0o
   if 16 - 16: o0oOOo0O0Ooo % II111iiii - i11iIiiIii - IiII + O0 - i11iIiiIii
   if ( lisp_data_plane_security and iIIiI11 . rloc_recent_rekey ( ) ) :
    iI1i11iIIiI = iIIiI11
    if 58 - 58: OoooooooOO / I1ii11iIi11i - Oo0Ooo / II111iiii
    if 13 - 13: o0oOOo0O0Ooo + OoOoOO00 * ooOoO0o % IiII
    if 18 - 18: I1IiiI . I1ii11iIi11i + Oo0Ooo - iII111i
    if 53 - 53: ooOoO0o / IiII
    if 36 - 36: iIii1I11I1II1
    if 78 - 78: II111iiii * I11i
    if 47 - 47: Ii1I
    if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
    if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
    if 53 - 53: iIii1I11I1II1
    if 8 - 8: O0 - O0 - II111iiii
  if ( o0o000o . rloc_probe == False and lisp_nat_traversal ) :
   iIiii = [ ]
   OoO0oo0O = [ ]
   for iIIiI11 in i1i1i1 :
    o00oO = iIIiI11 . rloc . print_address_no_iid ( )
    if 63 - 63: oO0o % Oo0Ooo * OoO0O00 / II111iiii / Ii1I - ooOoO0o
    if 14 - 14: ooOoO0o . o0oOOo0O0Ooo + II111iiii
    if 50 - 50: Ii1I - i1IIi * oO0o
    if 52 - 52: I11i / oO0o - oO0o
    if 84 - 84: iIii1I11I1II1 - o0oOOo0O0Ooo
    if ( iIIiI11 . rloc . is_private_address ( ) ) :
     iIIiI11 . priority = 1
     iIIiI11 . state = LISP_RLOC_UNREACH_STATE
     iIiii . append ( iIIiI11 )
     OoO0oo0O . append ( o00oO )
     continue
     if 37 - 37: iII111i * o0oOOo0O0Ooo
     if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
     if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
     if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
     if 34 - 34: O0 * oO0o
     if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
     if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
     if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
     if 88 - 88: i11iIiiIii
     if 13 - 13: I1IiiI
    if ( lisp_i_am_rtr ) :
     if ( iIIiI11 . priority != 254 ) :
      iIiii . append ( iIIiI11 )
      OoO0oo0O . append ( o00oO )
      if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
    elif ( lisp_decent_nat ) :
     iIiii . append ( iIIiI11 )
     OoO0oo0O . append ( o00oO )
    elif ( iIIiI11 . priority == 254 ) :
     iIiii . append ( iIIiI11 )
     OoO0oo0O . append ( o00oO )
     if 84 - 84: OoooooooOO - oO0o - I1Ii111
     if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
     if 20 - 20: IiII
   if ( OoO0oo0O != [ ] ) :
    i1i1i1 = iIiii
    iIiIIIii1iI = "NAT-decent" if ( lisp_decent_nat ) else "NAT-traversal"
    if 27 - 27: I11i . II111iiii + I1ii11iIi11i * Ii1I * Oo0Ooo
    lprint ( "{} optimized RLOC-set: {}" . format ( iIiIIIii1iI , OoO0oo0O ) )
    if 64 - 64: i11iIiiIii - I1Ii111 - Ii1I % OOooOOo + iII111i
    if 46 - 46: OoO0O00 - oO0o / OOooOOo . OoooooooOO * I1Ii111 . Ii1I
    if 94 - 94: o0oOOo0O0Ooo
    if 46 - 46: I1ii11iIi11i + iII111i / OoO0O00 + oO0o * I11i % OOooOOo
    if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
    if 47 - 47: Ii1I - Oo0Ooo * OoOoOO00
    if 20 - 20: oO0o
  iIiii = [ ]
  for iIIiI11 in i1i1i1 :
   if ( iIIiI11 . json != None ) : continue
   iIiii . append ( iIIiI11 )
   if 48 - 48: I1IiiI % OoO0O00
  if ( iIiii != [ ] ) :
   oo0O00ooo0o = len ( i1i1i1 ) - len ( iIiii )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( oo0O00ooo0o ) )
   if 33 - 33: Ii1I
   i1i1i1 = iIiii
   if 73 - 73: Ii1I . IiII
   if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
   if 90 - 90: i11iIiiIii * i1IIi
   if 88 - 88: i11iIiiIii - OoOoOO00
   if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
   if 6 - 6: iII111i
  if ( lisp_decent_nat ) :
   for iIIiI11 in i1i1i1 :
    if ( iIIiI11 . is_decent_nat_port ( ) == False ) : continue
    lisp_itr_nat_probe ( iIIiI11 . rloc , iIIiI11 . rloc_name , lisp_sockets [ 2 ] )
    if 44 - 44: oO0o
    if 23 - 23: I1IiiI + iIii1I11I1II1 . iII111i + OOooOOo - OoO0O00 + i1IIi
    if 60 - 60: i11iIiiIii + Oo0Ooo * OoOoOO00 . iII111i - iIii1I11I1II1 * IiII
    if 52 - 52: OOooOOo
    if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
    if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
    if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
    if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
    if 66 - 66: I1IiiI
  if ( o0o000o . rloc_probe and I1I1i1I11I != None ) : i1i1i1 = I1I1i1I11I . rloc_set
  if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
  if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
  if 22 - 22: I1Ii111
  if 41 - 41: O0 * i1IIi
  if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
  iIiI1 = o0ooo0oOO0o
  if ( I1I1i1I11I and i1i1i1 != I1I1i1I11I . rloc_set ) :
   I1I1i1I11I . delete_rlocs_from_rloc_probe_list ( )
   iIiI1 = True
   if 7 - 7: Ii1I
   if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
   if 63 - 63: OOooOOo + iII111i - IiII - I1IiiI % IiII . OoO0O00
   if 73 - 73: OoOoOO00
   if 47 - 47: oO0o
  iIIi11Ii1iII = I1I1i1I11I . uptime if ( I1I1i1I11I ) else None
  if ( I1I1i1I11I == None or iIiI1 ) :
   I1I1i1I11I = lisp_mapping ( Oo0oOoooO . eid , Oo0oOoooO . group , i1i1i1 )
   I1I1i1I11I . mapping_source = source
   if 72 - 72: I11i % ooOoO0o / O0 . O0
   if 7 - 7: O0 * I1ii11iIi11i + Ii1I + oO0o % oO0o
   if 47 - 47: oO0o * I1ii11iIi11i
   if 85 - 85: OoooooooOO * I1ii11iIi11i + i11iIiiIii . iII111i * II111iiii / oO0o
   if 14 - 14: I1Ii111
   if 49 - 49: I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
   if ( lisp_i_am_rtr and Oo0oOoooO . group . is_null ( ) == False ) :
    I1I1i1I11I . map_cache_ttl = LISP_MCAST_TTL
   else :
    I1I1i1I11I . map_cache_ttl = Oo0oOoooO . store_ttl ( )
    if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
   I1I1i1I11I . action = Oo0oOoooO . action
   I1I1i1I11I . add_cache ( iIiI1 )
   if 28 - 28: ooOoO0o
   if 88 - 88: oO0o
  o0o0Oo = "Add"
  if ( iIIi11Ii1iII ) :
   I1I1i1I11I . uptime = iIIi11Ii1iII
   I1I1i1I11I . refresh_time = lisp_get_timestamp ( )
   o0o0Oo = "Replace"
   if 76 - 76: OoOoOO00 / iII111i * ooOoO0o . i1IIi
   if 28 - 28: I11i . I1ii11iIi11i
  lprint ( "{} {} map-cache with {} RLOCs" . format ( o0o0Oo ,
 green ( I1I1i1I11I . print_eid_tuple ( ) , False ) , len ( i1i1i1 ) ) )
  if 80 - 80: OoO0O00 - OoooooooOO * i11iIiiIii
  if 20 - 20: OoO0O00 . II111iiii
  if 70 - 70: i11iIiiIii % Ii1I * IiII / IiII . o0oOOo0O0Ooo
  if 52 - 52: o0oOOo0O0Ooo % I11i
  if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
  if ( lisp_ipc_dp_socket and iI1i11iIIiI != None ) :
   lisp_write_ipc_keys ( iI1i11iIIiI )
   if 36 - 36: OOooOOo
   if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
   if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
   if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
   if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
   if 79 - 79: oO0o - iII111i
   if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
  if ( o0ooo0oOO0o ) :
   II1iii1I1 = bold ( "RLOC-probe" , False )
   for iIIiI11 in I1I1i1I11I . best_rloc_set :
    O00oO000Oo0 = red ( iIIiI11 . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( II1iii1I1 , O00oO000Oo0 ) )
    lisp_send_map_request ( lisp_sockets , 0 , I1I1i1I11I . eid , I1I1i1I11I . group , iIIiI11 )
    if 39 - 39: O0 . OOooOOo
    if 95 - 95: I11i
    if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
 return
 if 8 - 8: I1ii11iIi11i
 if 100 - 100: OoooooooOO / I11i - Ii1I
 if 11 - 11: OoO0O00
 if 20 - 20: Oo0Ooo
 if 34 - 34: I1Ii111 % i11iIiiIii / oO0o - i1IIi . o0oOOo0O0Ooo / oO0o
 if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
 if 1 - 1: I1ii11iIi11i
 if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 81 - 81: iII111i % IiII / I11i
 packet = map_register . zero_auth ( packet )
 iiIIII11iIii = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 50 - 50: IiII + i1IIi % I1Ii111
 if 72 - 72: I1Ii111
 if 6 - 6: II111iiii - i1IIi
 if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
 map_register . auth_data = iiIIII11iIii
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
 if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
 if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
 if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
 if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
 if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
 if 32 - 32: I1Ii111
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  I1III1 = hashlib . sha1
  if 21 - 21: i1IIi * Oo0Ooo * OoO0O00 . iIii1I11I1II1 / ooOoO0o
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  I1III1 = hashlib . sha256
  if 4 - 4: Oo0Ooo - i1IIi . Oo0Ooo * I11i . i1IIi + OOooOOo
  if 3 - 3: IiII / iII111i * iII111i
 if ( do_hex ) :
  iiIIII11iIii = hmac . new ( password . encode ( ) , packet , I1III1 ) . hexdigest ( )
 else :
  iiIIII11iIii = hmac . new ( password . encode ( ) , packet , I1III1 ) . digest ( )
  if 15 - 15: O0 + I1IiiI * OoO0O00 - i1IIi + Ii1I . i1IIi
 return ( iiIIII11iIii )
 if 99 - 99: II111iiii + iIii1I11I1II1 / o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 - iIii1I11I1II1
 if 38 - 38: I1IiiI . oO0o - II111iiii
 if 37 - 37: i1IIi % oO0o / IiII * I11i + ooOoO0o % Oo0Ooo
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 % i1IIi . i11iIiiIii
 if 38 - 38: o0oOOo0O0Ooo - OoO0O00 - i11iIiiIii
 if 60 - 60: i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i * iII111i . oO0o + iII111i
 if 29 - 29: Oo0Ooo
 if 16 - 16: oO0o
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
 iiIIII11iIii = lisp_hash_me ( packet , alg_id , password , True )
 i11iii1IiIii = ( iiIIII11iIii == auth_data )
 if 79 - 79: I11i % I1Ii111 . I1Ii111 * O0 + II111iiii
 if 59 - 59: ooOoO0o * oO0o . IiII
 if 99 - 99: OoOoOO00 + OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1 + II111iiii
 if 42 - 42: ooOoO0o
 if ( i11iii1IiIii == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( iiIIII11iIii , auth_data ) )
  if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
  if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
 return ( i11iii1IiIii )
 if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
 if 10 - 10: oO0o * Oo0Ooo
 if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
 if 91 - 91: I1Ii111
 if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
 if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
 if 100 - 100: ooOoO0o / I1ii11iIi11i * OoOoOO00 . I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
def lisp_retransmit_map_notify ( map_notify ) :
 oOOo0OOoOO0 = map_notify . etr
 I1I1I1 = map_notify . etr_port
 if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
 if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
 if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
 if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
 if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( oOOo0OOoOO0 . print_address ( ) , False ) ) )
  if 69 - 69: IiII
  if 13 - 13: i11iIiiIii
  OoOOooOOoo = map_notify . nonce_key
  if ( OoOOooOOoo in lisp_map_notify_queue ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( OoOOooOOoo ) )
   if 49 - 49: OoOoOO00
   try :
    lisp_map_notify_queue . pop ( OoOOooOOoo )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
    if 80 - 80: I1IiiI - OOooOOo . oO0o
  return
  if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
  if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
 ooO0ooo0O0 = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 8 - 8: OoO0O00 . OOooOOo % I1Ii111 * OOooOOo / I1IiiI
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # OoO0O00
 red ( oOOo0OOoOO0 . print_address ( ) , False ) , map_notify . retry_count ) )
 if 52 - 52: I1ii11iIi11i . Oo0Ooo - O0 % OoO0O00 - iII111i * oO0o
 lisp_send_map_notify ( ooO0ooo0O0 , map_notify . packet , oOOo0OOoOO0 , I1I1I1 )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 59 - 59: OOooOOo . i1IIi / I11i
 if 45 - 45: i1IIi / i1IIi . ooOoO0o . O0 / I1IiiI
 if 68 - 68: I11i % iIii1I11I1II1 . ooOoO0o . I1Ii111 + OoooooooOO
 if 45 - 45: IiII - Ii1I
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 74 - 74: ooOoO0o / I1Ii111
 if 80 - 80: I1Ii111 / O0 * O0
 if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
 if 89 - 89: i11iIiiIii - II111iiii
 if 67 - 67: IiII % I1Ii111 + i11iIiiIii
 if 53 - 53: OOooOOo
 if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
 if 52 - 52: Ii1I * I1ii11iIi11i
 if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
 if 9 - 9: I1ii11iIi11i + I11i
 eid_record . rloc_count = len ( parent . registered_rlocs )
 I1ii1I = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 89 - 89: OoOoOO00
 if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
 if 4 - 4: OoOoOO00 / OoO0O00
 if 66 - 66: I1Ii111 / OoOoOO00
 for oOOi1IiIiIIIiIi in parent . registered_rlocs :
  oOiI111IIIiIii = lisp_rloc_record ( )
  oOiI111IIIiIii . store_rloc_entry ( oOOi1IiIiIIIiIi )
  oOiI111IIIiIii . local_bit = True
  oOiI111IIIiIii . probe_bit = False
  oOiI111IIIiIii . reach_bit = True
  I1ii1I += oOiI111IIIiIii . encode ( )
  oOiI111IIIiIii . print_record ( "  " )
  del ( oOiI111IIIiIii )
  if 61 - 61: I1IiiI - oO0o
  if 23 - 23: I1ii11iIi11i . ooOoO0o . OoO0O00 / O0 * OoO0O00
  if 35 - 35: Ii1I / I11i - ooOoO0o / OoooooooOO
  if 44 - 44: OoO0O00 % O0 * IiII + iII111i
  if 79 - 79: ooOoO0o
 for oOOi1IiIiIIIiIi in parent . registered_rlocs :
  oOOo0OOoOO0 = oOOi1IiIiIIIiIi . rloc
  ooOOoo0o = lisp_map_notify ( lisp_sockets )
  ooOOoo0o . record_count = 1
  IIIIIi1 = map_register . key_id
  ooOOoo0o . key_id = IIIIIi1
  ooOOoo0o . alg_id = map_register . alg_id
  ooOOoo0o . auth_len = map_register . auth_len
  ooOOoo0o . nonce = map_register . nonce
  ooOOoo0o . nonce_key = lisp_hex_string ( ooOOoo0o . nonce )
  ooOOoo0o . etr . copy_address ( oOOo0OOoOO0 )
  ooOOoo0o . etr_port = map_register . sport
  ooOOoo0o . site = parent . site
  OO0Oo00OO0oo = ooOOoo0o . encode ( I1ii1I , parent . site . auth_key [ IIIIIi1 ] )
  ooOOoo0o . print_notify ( )
  if 16 - 16: II111iiii . ooOoO0o . i11iIiiIii * Ii1I - o0oOOo0O0Ooo . I1IiiI
  if 33 - 33: o0oOOo0O0Ooo % ooOoO0o
  if 43 - 43: I1Ii111
  if 81 - 81: OoOoOO00
  OoOOooOOoo = ooOOoo0o . nonce_key
  if ( OoOOooOOoo in lisp_map_notify_queue ) :
   o0OOoo = lisp_map_notify_queue [ OoOOooOOoo ]
   o0OOoo . retransmit_timer . cancel ( )
   del ( o0OOoo )
   if 25 - 25: i11iIiiIii * OoOoOO00 + OoO0O00 . o0oOOo0O0Ooo
  lisp_map_notify_queue [ OoOOooOOoo ] = ooOOoo0o
  if 65 - 65: I1Ii111 + i1IIi / iII111i % O0 + II111iiii * i1IIi
  if 49 - 49: o0oOOo0O0Ooo + OOooOOo - II111iiii
  if 34 - 34: ooOoO0o . I1Ii111
  if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( oOOo0OOoOO0 . print_address ( ) , False ) ) )
  if 27 - 27: Oo0Ooo
  lisp_send ( lisp_sockets , oOOo0OOoOO0 , LISP_CTRL_PORT , OO0Oo00OO0oo )
  if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
  parent . site . map_notifies_sent += 1
  if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
  if 21 - 21: II111iiii
  if 23 - 23: I11i * i1IIi . oO0o / IiII + o0oOOo0O0Ooo
  if 1 - 1: IiII / OoO0O00 . oO0o * I1Ii111 - i11iIiiIii
  ooOOoo0o . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ooOOoo0o ] )
  ooOOoo0o . retransmit_timer . start ( )
  if 50 - 50: oO0o - O0 / I1IiiI . OoOoOO00 . Oo0Ooo
 return
 if 30 - 30: IiII . OoO0O00 + Oo0Ooo
 if 48 - 48: iIii1I11I1II1 / i11iIiiIii . OoOoOO00 * I11i
 if 1 - 1: IiII . OoOoOO00 * o0oOOo0O0Ooo
 if 63 - 63: O0 / Ii1I + I1Ii111 % OoO0O00 % OOooOOo * O0
 if 35 - 35: OoO0O00 + OoooooooOO % Oo0Ooo / I11i - O0 . i1IIi
 if 76 - 76: IiII % I1IiiI * Ii1I / Ii1I / OoooooooOO + Ii1I
 if 19 - 19: OoooooooOO
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 88 - 88: I1IiiI % ooOoO0o % Oo0Ooo - O0
 OoOOooOOoo = lisp_hex_string ( nonce ) + source . print_address ( )
 if 71 - 71: OOooOOo % Ii1I - i11iIiiIii - oO0o . ooOoO0o / I1Ii111
 if 53 - 53: iII111i . Oo0Ooo
 if 91 - 91: oO0o * OoooooooOO * oO0o % oO0o * II111iiii % I1Ii111
 if 8 - 8: Ii1I
 if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
 if 94 - 94: oO0o
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( OoOOooOOoo in lisp_map_notify_queue ) :
  ooOOoo0o = lisp_map_notify_queue [ OoOOooOOoo ]
  OOo0oOO0o0oo0 = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( ooOOoo0o . nonce ) , OOo0oOO0o0oo0 ) )
  if 95 - 95: ooOoO0o * O0 + OOooOOo
  return
  if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
  if 21 - 21: ooOoO0o
 ooOOoo0o = lisp_map_notify ( lisp_sockets )
 ooOOoo0o . record_count = record_count
 key_id = key_id
 ooOOoo0o . key_id = key_id
 ooOOoo0o . alg_id = alg_id
 ooOOoo0o . auth_len = auth_len
 ooOOoo0o . nonce = nonce
 ooOOoo0o . nonce_key = lisp_hex_string ( nonce )
 ooOOoo0o . etr . copy_address ( source )
 ooOOoo0o . etr_port = port
 ooOOoo0o . site = site
 ooOOoo0o . eid_list = eid_list
 if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
 if 81 - 81: oO0o
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
 if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
 if ( map_register_ack == False ) :
  OoOOooOOoo = ooOOoo0o . nonce_key
  lisp_map_notify_queue [ OoOOooOOoo ] = ooOOoo0o
  if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
  if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 33 - 33: I11i
  if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
  if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
  if 32 - 32: oO0o
  if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
 OO0Oo00OO0oo = ooOOoo0o . encode ( eid_records , site . auth_key [ key_id ] )
 ooOOoo0o . print_notify ( )
 if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
 if ( map_register_ack == False ) :
  Oo0oOoooO = lisp_eid_record ( )
  Oo0oOoooO . decode ( eid_records )
  Oo0oOoooO . print_record ( "  " , False )
  if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
  if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
  if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
  if 94 - 94: Ii1I
  if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
 lisp_send_map_notify ( lisp_sockets , OO0Oo00OO0oo , ooOOoo0o . etr , port )
 site . map_notifies_sent += 1
 if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
 if ( map_register_ack ) : return
 if 34 - 34: iIii1I11I1II1
 if 47 - 47: OOooOOo * iII111i
 if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
 if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
 if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
 if 70 - 70: OoO0O00
 ooOOoo0o . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ooOOoo0o ] )
 ooOOoo0o . retransmit_timer . start ( )
 return
 if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
 if 85 - 85: O0 . II111iiii
 if 80 - 80: O0 * I11i * I1Ii111
 if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
 if 25 - 25: iII111i + i1IIi
 if 64 - 64: IiII % I11i / iIii1I11I1II1
 if 66 - 66: Ii1I
 if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 71 - 71: IiII - iII111i % I1IiiI * iII111i
 if 27 - 27: ooOoO0o - OoO0O00
 if 83 - 83: iII111i * OoOoOO00 - O0 * Ii1I
 if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
 map_notify . record_count = 0
 OO0Oo00OO0oo = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 32 - 32: IiII * II111iiii . Ii1I
 if 68 - 68: I11i / O0
 if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
 if 22 - 22: Ii1I / I1IiiI / II111iiii
 oOOo0OOoOO0 = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( oOOo0OOoOO0 . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , oOOo0OOoOO0 , LISP_CTRL_PORT , OO0Oo00OO0oo )
 return
 if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
 if 76 - 76: Oo0Ooo
 if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
 if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
 if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
 if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
 if 45 - 45: Ii1I * IiII - OOooOOo
 if 57 - 57: iII111i % OoO0O00 / OoooooooOO
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 69 - 69: oO0o
 ooOOoo0o = lisp_map_notify ( lisp_sockets )
 ooOOoo0o . record_count = 1
 ooOOoo0o . nonce = lisp_get_control_nonce ( )
 ooOOoo0o . nonce_key = lisp_hex_string ( ooOOoo0o . nonce )
 ooOOoo0o . etr . copy_address ( xtr )
 ooOOoo0o . etr_port = LISP_CTRL_PORT
 ooOOoo0o . eid_list = eid_list
 OoOOooOOoo = ooOOoo0o . nonce_key
 if 44 - 44: IiII - II111iiii % Ii1I
 if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
 if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
 if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
 if 59 - 59: OoOoOO00
 if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
 lisp_remove_eid_from_map_notify_queue ( ooOOoo0o . eid_list )
 if ( OoOOooOOoo in lisp_map_notify_queue ) :
  ooOOoo0o = lisp_map_notify_queue [ OoOOooOOoo ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( ooOOoo0o . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
  return
  if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
  if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
  if 7 - 7: OOooOOo
  if 22 - 22: Oo0Ooo + ooOoO0o
  if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
 lisp_map_notify_queue [ OoOOooOOoo ] = ooOOoo0o
 if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
 if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
 if 26 - 26: Oo0Ooo . Ii1I
 if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
 if 8 - 8: iIii1I11I1II1
 if 6 - 6: oO0o
 o0OooooOO = site_eid . rtrs_in_rloc_set ( )
 if 47 - 47: I1IiiI + OoOoOO00 - I1ii11iIi11i + iII111i * oO0o / IiII
 if 33 - 33: II111iiii % oO0o + ooOoO0o . iII111i
 if 77 - 77: oO0o - I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
 if 5 - 5: I1IiiI
 Oo0oOoooO = lisp_eid_record ( )
 Oo0oOoooO . record_ttl = 1440
 Oo0oOoooO . eid . copy_address ( site_eid . eid )
 Oo0oOoooO . group . copy_address ( site_eid . group )
 Oo0oOoooO . rloc_count = 0
 for iIIoOo in site_eid . registered_rlocs :
  if ( o0OooooOO ^ iIIoOo . is_rtr ( ) ) : continue
  Oo0oOoooO . rloc_count += 1
  if 22 - 22: II111iiii / iII111i
 OO0Oo00OO0oo = Oo0oOoooO . encode ( )
 if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
 if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
 if 21 - 21: o0oOOo0O0Ooo % O0
 if 81 - 81: i1IIi + i1IIi
 ooOOoo0o . print_notify ( )
 Oo0oOoooO . print_record ( "  " , False )
 if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
 if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
 if 71 - 71: I1IiiI + iII111i
 if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
 oo0o000OOoOO0 = [ ]
 for iIIoOo in site_eid . registered_rlocs :
  if ( o0OooooOO ) :
   if ( iIIoOo . is_rtr ( ) ) :
    oo0o000OOoOO0 . append ( iIIoOo . rloc )
    continue
    if 57 - 57: IiII * ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + OoOoOO00
    if 83 - 83: OoOoOO00 . Oo0Ooo . OoO0O00
    if 65 - 65: iII111i * iIii1I11I1II1
    if 48 - 48: iII111i * OoO0O00
    if 57 - 57: ooOoO0o + I1IiiI
    if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
  oOiI111IIIiIii = lisp_rloc_record ( )
  oOiI111IIIiIii . store_rloc_entry ( iIIoOo )
  oOiI111IIIiIii . local_bit = True
  oOiI111IIIiIii . probe_bit = False
  oOiI111IIIiIii . reach_bit = True
  OO0Oo00OO0oo += oOiI111IIIiIii . encode ( )
  oOiI111IIIiIii . print_record ( "    " )
  if 82 - 82: Oo0Ooo % Oo0Ooo
  if 91 - 91: I11i
  if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
  if 65 - 65: OoO0O00
  if 65 - 65: oO0o
 OO0Oo00OO0oo = ooOOoo0o . encode ( OO0Oo00OO0oo , "" )
 if ( OO0Oo00OO0oo == None ) : return
 if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
 if 50 - 50: O0 - oO0o . oO0o
 if 98 - 98: IiII % Ii1I / Ii1I
 if 10 - 10: Ii1I
 if ( oo0o000OOoOO0 != [ ] ) :
  for Ooooo0OO in oo0o000OOoOO0 :
   lisp_send_map_notify ( lisp_sockets , OO0Oo00OO0oo , Ooooo0OO , LISP_CTRL_PORT )
   if 69 - 69: I1Ii111 * OoooooooOO . o0oOOo0O0Ooo % I1IiiI
 else :
  lisp_send_map_notify ( lisp_sockets , OO0Oo00OO0oo , xtr , LISP_CTRL_PORT )
  if 70 - 70: iII111i . i11iIiiIii * I1Ii111
  if 54 - 54: o0oOOo0O0Ooo . i1IIi / iII111i
  if 21 - 21: O0 + ooOoO0o
  if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
  if 91 - 91: OoOoOO00 % iIii1I11I1II1
 ooOOoo0o . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ ooOOoo0o ] )
 ooOOoo0o . retransmit_timer . start ( )
 return
 if 81 - 81: i11iIiiIii / OoOoOO00 + iIii1I11I1II1
 if 65 - 65: o0oOOo0O0Ooo
 if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
 if 71 - 71: I1IiiI
 if 27 - 27: OoO0O00 + i1IIi * OoooooooOO * iIii1I11I1II1 - Ii1I
 if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
 if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 iiIiIiIiII = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 89 - 89: o0oOOo0O0Ooo / i11iIiiIii
 for I1iiIiI1II1ii in rle_list :
  iiiIiIi = lisp_site_eid_lookup ( I1iiIiI1II1ii [ 0 ] , I1iiIiI1II1ii [ 1 ] , True )
  if ( iiiIiIi == None ) : continue
  if 54 - 54: II111iiii + OoooooooOO
  if 92 - 92: Oo0Ooo * ooOoO0o / o0oOOo0O0Ooo % i11iIiiIii + OoooooooOO
  if 37 - 37: OoO0O00 . iII111i
  if 32 - 32: II111iiii
  if 11 - 11: i11iIiiIii - OOooOOo . i1IIi + OOooOOo - O0
  if 17 - 17: i1IIi % o0oOOo0O0Ooo % ooOoO0o / I11i
  if 68 - 68: OoOoOO00
  iiiI1i1 = iiiIiIi . registered_rlocs
  if ( len ( iiiI1i1 ) == 0 ) :
   IiI1i1ii11 = { }
   for OOoI1i1i1iIi in list ( iiiIiIi . individual_registrations . values ( ) ) :
    for iIIoOo in OOoI1i1i1iIi . registered_rlocs :
     if ( iIIoOo . is_rtr ( ) == False ) : continue
     IiI1i1ii11 [ iIIoOo . rloc . print_address ( ) ] = iIIoOo
     if 83 - 83: ooOoO0o - I1Ii111 - IiII / I1IiiI
     if 18 - 18: I1ii11iIi11i * o0oOOo0O0Ooo + OOooOOo
   iiiI1i1 = list ( IiI1i1ii11 . values ( ) )
   if 13 - 13: i11iIiiIii - i11iIiiIii % OoooooooOO / o0oOOo0O0Ooo
   if 55 - 55: OoOoOO00 - I11i . iII111i
   if 16 - 16: i11iIiiIii * ooOoO0o . IiII - I11i + i1IIi * I11i
   if 47 - 47: iIii1I11I1II1 + I1IiiI / O0 * I1ii11iIi11i - iII111i + OOooOOo
   if 13 - 13: OoooooooOO - I1ii11iIi11i % I1Ii111 * OoO0O00 - I1IiiI
   if 77 - 77: I11i - Oo0Ooo
  OOOooOoo0 = [ ]
  iII1iI = False
  if ( iiiIiIi . eid . address == 0 and iiiIiIi . eid . mask_len == 0 ) :
   iII1 = [ ]
   I1IIiI = [ ]
   if ( len ( iiiI1i1 ) != 0 and iiiI1i1 [ 0 ] . rle != None ) :
    I1IIiI = iiiI1i1 [ 0 ] . rle . rle_nodes
    if 59 - 59: I11i
   for Ii1111iiIii in I1IIiI :
    OOOooOoo0 . append ( Ii1111iiIii . rloc . rloc )
    iII1 . append ( Ii1111iiIii . rloc . rloc . print_address_no_iid ( ) )
    if 61 - 61: IiII * I1Ii111 * OoO0O00 / oO0o - OoooooooOO
   lprint ( "Notify existing RLE-nodes {}" . format ( iII1 ) )
  else :
   if 5 - 5: o0oOOo0O0Ooo % OOooOOo % II111iiii
   if 86 - 86: O0 . ooOoO0o * OoooooooOO + Ii1I / I11i / II111iiii
   if 26 - 26: OoooooooOO - I1Ii111 / Oo0Ooo - iII111i % OoOoOO00 * OoooooooOO
   if 3 - 3: oO0o
   if 3 - 3: I1ii11iIi11i . IiII + ooOoO0o
   for iIIoOo in iiiI1i1 :
    if ( iIIoOo . is_rtr ( ) ) : OOOooOoo0 . append ( iIIoOo . rloc )
    if 66 - 66: OOooOOo + oO0o - ooOoO0o / Ii1I * OoO0O00 * i11iIiiIii
    if 69 - 69: I11i % i11iIiiIii
    if 34 - 34: Ii1I . OoooooooOO + II111iiii % oO0o
    if 69 - 69: i11iIiiIii % I1IiiI * i11iIiiIii - OoO0O00 * iIii1I11I1II1
    if 70 - 70: I1Ii111 . OoOoOO00 % OoooooooOO + OoOoOO00 / II111iiii
   iII1iI = ( len ( OOOooOoo0 ) != 0 )
   if ( iII1iI == False ) :
    I1iOooO0o = lisp_site_eid_lookup ( I1iiIiI1II1ii [ 0 ] , iiIiIiIiII , False )
    if ( I1iOooO0o == None ) : continue
    if 39 - 39: I1Ii111 * I1IiiI - o0oOOo0O0Ooo . oO0o . OOooOOo * i11iIiiIii
    for iIIoOo in I1iOooO0o . registered_rlocs :
     if ( iIIoOo . rloc . is_null ( ) ) : continue
     OOOooOoo0 . append ( iIIoOo . rloc )
     if 70 - 70: OoOoOO00 / OOooOOo - o0oOOo0O0Ooo
     if 82 - 82: OOooOOo . i11iIiiIii . I1ii11iIi11i % OoOoOO00 * Ii1I / OoO0O00
     if 56 - 56: o0oOOo0O0Ooo / I1IiiI + I11i + I1IiiI
     if 34 - 34: Oo0Ooo / i11iIiiIii - ooOoO0o
     if 77 - 77: OoOoOO00 * OoooooooOO
     if 41 - 41: iIii1I11I1II1 - O0 . II111iiii + I1IiiI - II111iiii / oO0o
   if ( len ( OOOooOoo0 ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( iiiIiIi . print_eid_tuple ( ) , False ) ) )
    if 35 - 35: ooOoO0o - OoOoOO00 / iIii1I11I1II1 / OOooOOo
    continue
    if 38 - 38: i1IIi % OoooooooOO
    if 5 - 5: iIii1I11I1II1 + iIii1I11I1II1 . iIii1I11I1II1 + o0oOOo0O0Ooo
    if 45 - 45: I1IiiI - OoooooooOO - I1Ii111 - i1IIi - OoooooooOO * O0
    if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . IiII
    if 72 - 72: OoOoOO00 % OoooooooOO * O0
    if 27 - 27: I1ii11iIi11i . OoooooooOO / II111iiii . OOooOOo
  for oOOi1IiIiIIIiIi in OOOooOoo0 :
   lprint ( "Build Map-Notify for {}" . format (
 green ( iiiIiIi . print_eid_tuple ( ) , False ) ) )
   if 58 - 58: oO0o / ooOoO0o
   iII1II11II = [ iiiIiIi . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , iiiIiIi , iII1II11II , oOOi1IiIiIIIiIi )
   time . sleep ( .001 )
   if 46 - 46: o0oOOo0O0Ooo % O0
   if 30 - 30: oO0o
 return
 if 64 - 64: O0
 if 70 - 70: oO0o % I1IiiI . iIii1I11I1II1 - Oo0Ooo + OoOoOO00 % O0
 if 91 - 91: I1Ii111 - oO0o * ooOoO0o - I1ii11iIi11i + IiII + O0
 if 18 - 18: OoOoOO00 / IiII / o0oOOo0O0Ooo . OOooOOo
 if 35 - 35: I11i . ooOoO0o % I11i / iII111i / O0 % I11i
 if 29 - 29: I1Ii111 + Ii1I
 if 100 - 100: Ii1I + I1Ii111 / iIii1I11I1II1 / i1IIi % OoOoOO00
 if 6 - 6: oO0o + ooOoO0o
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for o000o0O0Oo00 in range ( rloc_count ) :
  oOiI111IIIiIii = lisp_rloc_record ( )
  packet = oOiI111IIIiIii . decode ( packet , None )
  IIO0oo0o = oOiI111IIIiIii . json
  if ( IIO0oo0o == None ) : continue
  if 65 - 65: ooOoO0o % I11i / O0 + OoooooooOO + OOooOOo % OoOoOO00
  try :
   IIO0oo0o = json . loads ( IIO0oo0o . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 82 - 82: I11i . IiII
   if 27 - 27: I1Ii111 % O0 * OoooooooOO . Oo0Ooo
  if ( "signature" not in IIO0oo0o ) : continue
  return ( oOiI111IIIiIii )
  if 51 - 51: I11i
 return ( None )
 if 80 - 80: Oo0Ooo + oO0o
 if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
 if 82 - 82: IiII % ooOoO0o
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
 if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
 if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
 if 34 - 34: I1ii11iIi11i * i1IIi % OoooooooOO / I1IiiI
 if 39 - 39: OoO0O00 + IiII - II111iiii % I11i
 if 80 - 80: o0oOOo0O0Ooo * ooOoO0o
def lisp_get_eid_hash ( eid ) :
 O0oooOo = None
 for I1iiIi in lisp_eid_hashes :
  if 13 - 13: iII111i + O0 . I1Ii111 % OoooooooOO / I1IiiI . I1ii11iIi11i
  if 55 - 55: OoOoOO00 + I11i - OOooOOo
  if 20 - 20: OoO0O00 . OoooooooOO - I1Ii111 * IiII
  if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
  i1I1iI = I1iiIi . instance_id
  if ( i1I1iI == - 1 ) : I1iiIi . instance_id = eid . instance_id
  if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
  ii1iIIiIIi111 = eid . is_more_specific ( I1iiIi )
  I1iiIi . instance_id = i1I1iI
  if ( ii1iIIiIIi111 ) :
   O0oooOo = 128 - I1iiIi . mask_len
   break
   if 35 - 35: OOooOOo * oO0o
   if 19 - 19: iIii1I11I1II1 + IiII * iII111i - IiII
 if ( O0oooOo == None ) : return ( None )
 if 87 - 87: o0oOOo0O0Ooo - I1Ii111
 OOoo00 = eid . address
 I1II1I1III = ""
 for o000o0O0Oo00 in range ( 0 , old_div ( O0oooOo , 16 ) ) :
  iI1ii11Ii = OOoo00 & 0xffff
  iI1ii11Ii = hex ( iI1ii11Ii ) [ 2 : : ]
  I1II1I1III = iI1ii11Ii . zfill ( 4 ) + ":" + I1II1I1III
  OOoo00 >>= 16
  if 6 - 6: iII111i / i1IIi + OOooOOo % OoOoOO00 . I1ii11iIi11i
 if ( O0oooOo % 16 != 0 ) :
  iI1ii11Ii = OOoo00 & 0xff
  iI1ii11Ii = hex ( iI1ii11Ii ) [ 2 : : ]
  I1II1I1III = iI1ii11Ii . zfill ( 2 ) + ":" + I1II1I1III
  if 88 - 88: OoO0O00
 return ( I1II1I1III [ 0 : - 1 ] )
 if 82 - 82: OOooOOo / I11i / OoooooooOO % oO0o
 if 27 - 27: oO0o + IiII
 if 5 - 5: iIii1I11I1II1 + OoOoOO00 * I1Ii111 * i11iIiiIii
 if 18 - 18: Oo0Ooo % OOooOOo % oO0o / I11i % O0
 if 76 - 76: OoooooooOO % O0 / OoO0O00
 if 41 - 41: i11iIiiIii - I1ii11iIi11i - II111iiii
 if 5 - 5: OoOoOO00 + i1IIi
 if 43 - 43: iII111i * I1IiiI
 if 20 - 20: I1IiiI . I11i * OoO0O00 . ooOoO0o . II111iiii
 if 6 - 6: Ii1I * OoOoOO00 % IiII + I11i
 if 20 - 20: oO0o
def lisp_lookup_public_key ( eid ) :
 i1I1iI = eid . instance_id
 if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
 if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
 if 87 - 87: ooOoO0o
 if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
 if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
 i1o0000ooOo0 = lisp_get_eid_hash ( eid )
 if ( i1o0000ooOo0 == None ) : return ( [ None , None , False ] )
 if 42 - 42: II111iiii
 i1o0000ooOo0 = "hash-" + i1o0000ooOo0
 iiii1I1I11 = lisp_address ( LISP_AFI_NAME , i1o0000ooOo0 , len ( i1o0000ooOo0 ) , i1I1iI )
 oo0oOooo0O = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 if 14 - 14: i11iIiiIii
 if 85 - 85: i11iIiiIii / Ii1I + Oo0Ooo / OoOoOO00 - I1IiiI
 if 39 - 39: OoO0O00
 if 97 - 97: iIii1I11I1II1 . I1IiiI - O0
 I1iOooO0o = lisp_site_eid_lookup ( iiii1I1I11 , oo0oOooo0O , True )
 if ( I1iOooO0o == None ) : return ( [ iiii1I1I11 , None , False ] )
 if 41 - 41: I11i . OoOoOO00 * O0 % Ii1I
 if 54 - 54: ooOoO0o
 if 13 - 13: I11i
 if 18 - 18: II111iiii * oO0o % i11iIiiIii / IiII . ooOoO0o
 OOO0OoOooO0 = None
 for iIIiI11 in I1iOooO0o . registered_rlocs :
  iI1Ii1IIii = iIIiI11 . json
  if ( iI1Ii1IIii == None ) : continue
  try :
   iI1Ii1IIii = json . loads ( iI1Ii1IIii . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( i1o0000ooOo0 ) )
   if 44 - 44: oO0o . I1IiiI
   return ( [ iiii1I1I11 , None , False ] )
   if 82 - 82: i11iIiiIii / I11i - oO0o . iIii1I11I1II1 % Ii1I
  if ( "public-key" not in iI1Ii1IIii ) : continue
  OOO0OoOooO0 = iI1Ii1IIii [ "public-key" ]
  break
  if 24 - 24: OOooOOo . I1Ii111
 return ( [ iiii1I1I11 , OOO0OoOooO0 , True ] )
 if 59 - 59: Ii1I - I1ii11iIi11i % Ii1I . iII111i
 if 78 - 78: I1ii11iIi11i
 if 69 - 69: iII111i
 if 87 - 87: ooOoO0o % OOooOOo - iII111i
 if 65 - 65: IiII + I1IiiI % I1Ii111 - oO0o
 if 81 - 81: I11i / iII111i
 if 15 - 15: OoOoOO00 - I11i - oO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii * Ii1I . I11i - OoOoOO00 % iII111i
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 19 - 19: OoOoOO00 + OOooOOo - o0oOOo0O0Ooo + i11iIiiIii . OOooOOo
 if 14 - 14: Ii1I - O0 - IiII % Ii1I / OoOoOO00 * OoooooooOO
 if 57 - 57: Oo0Ooo % Oo0Ooo % O0 . I1Ii111 % I1ii11iIi11i
 if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
 if 12 - 12: ooOoO0o
 iiO0OoO0OOO00 = json . loads ( rloc_record . json . json_string )
 if 56 - 56: i1IIi
 if ( lisp_get_eid_hash ( eid ) ) :
  Oooo00oo0o = eid
 elif ( "signature-eid" in iiO0OoO0OOO00 ) :
  I11II1iIi = iiO0OoO0OOO00 [ "signature-eid" ]
  Oooo00oo0o = lisp_address ( LISP_AFI_IPV6 , I11II1iIi , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 81 - 81: oO0o - I1IiiI
  if 40 - 40: OoOoOO00 - I11i . o0oOOo0O0Ooo + i11iIiiIii . iII111i
  if 5 - 5: i11iIiiIii - OoooooooOO - I11i . Ii1I
  if 83 - 83: Oo0Ooo * II111iiii + Ii1I
  if 59 - 59: iII111i % OoO0O00 / Oo0Ooo + I1ii11iIi11i % Ii1I
 iiii1I1I11 , OOO0OoOooO0 , OooOo0o = lisp_lookup_public_key ( Oooo00oo0o )
 if ( iiii1I1I11 == None ) :
  oOOoo = green ( Oooo00oo0o . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( oOOoo ) )
  return ( False )
  if 88 - 88: II111iiii + i11iIiiIii
  if 14 - 14: II111iiii + OOooOOo * Ii1I * I1IiiI + OOooOOo . OOooOOo
 iIi1iII = "found" if OooOo0o else bold ( "not found" , False )
 oOOoo = green ( iiii1I1I11 . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( oOOoo , iIi1iII ) )
 if ( OooOo0o == False ) : return ( False )
 if 67 - 67: OoooooooOO
 if ( OOO0OoOooO0 == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 33 - 33: I1ii11iIi11i / OoooooooOO . i1IIi - I1ii11iIi11i + OoO0O00
  if 37 - 37: IiII * I1IiiI % O0
 i1iIiiiiI1 = OOO0OoOooO0 [ 0 : 8 ] + "..." + OOO0OoOooO0 [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( i1iIiiiiI1 ) )
 if 72 - 72: IiII - iIii1I11I1II1
 if 25 - 25: IiII
 if 51 - 51: O0 / i11iIiiIii % i11iIiiIii % OoOoOO00 + iII111i - Oo0Ooo
 if 89 - 89: OoOoOO00 - I1IiiI + IiII
 if 5 - 5: I11i - I11i
 OOooO0O = iiO0OoO0OOO00 [ "signature" ]
 if 44 - 44: II111iiii
 try :
  iiO0OoO0OOO00 = binascii . a2b_base64 ( OOooO0O )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
  if 54 - 54: iII111i - I1Ii111
 O00OooOooooO = len ( iiO0OoO0OOO00 )
 if ( O00OooOooooO & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( O00OooOooooO ) )
  return ( False )
  if 9 - 9: i1IIi / i1IIi % OoO0O00 % i1IIi
  if 78 - 78: iII111i - OoO0O00 - I11i / oO0o
  if 45 - 45: I11i . OoooooooOO - i11iIiiIii - I1ii11iIi11i / oO0o
  if 54 - 54: i1IIi . ooOoO0o + O0 . ooOoO0o * iIii1I11I1II1
  if 82 - 82: iII111i % OoO0O00 * O0
 iiOO00O = Oooo00oo0o . print_address ( )
 if 38 - 38: o0oOOo0O0Ooo * o0oOOo0O0Ooo - I1IiiI . iII111i % iIii1I11I1II1 + I1ii11iIi11i
 if 56 - 56: I1Ii111 % oO0o
 if 31 - 31: OOooOOo + IiII
 if 56 - 56: OoooooooOO * II111iiii
 OOO0OoOooO0 = binascii . a2b_base64 ( OOO0OoOooO0 )
 try :
  OoOOooOOoo = ecdsa . VerifyingKey . from_pem ( OOO0OoOooO0 )
 except :
  OoooOOoOO = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( OoooOOoOO ) )
  return ( False )
  if 34 - 34: I11i % i1IIi
  if 8 - 8: OoOoOO00 / oO0o + oO0o * Ii1I
  if 71 - 71: I1Ii111 - O0 . oO0o % ooOoO0o / I1Ii111
  if 28 - 28: o0oOOo0O0Ooo / oO0o
  if 65 - 65: O0 / i1IIi
  if 78 - 78: OOooOOo . I11i % Oo0Ooo . OoOoOO00
  if 92 - 92: i11iIiiIii * OoooooooOO
  if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
  if 75 - 75: oO0o * Oo0Ooo * O0
  if 22 - 22: ooOoO0o / OoooooooOO . II111iiii / Ii1I * OoO0O00 . i1IIi
  if 62 - 62: oO0o % Ii1I - Ii1I
 try :
  I111 = OoOOooOOoo . verify ( iiO0OoO0OOO00 , iiOO00O . encode ( ) , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( iiOO00O ) )
  if 16 - 16: OoO0O00 - O0 - OOooOOo - I11i % OoOoOO00
  lprint ( "  Signature used '{}'" . format ( OOooO0O ) )
  return ( False )
  if 7 - 7: I1Ii111 / OoOoOO00 . II111iiii
 return ( I111 )
 if 9 - 9: I11i . I11i . OoooooooOO
 if 42 - 42: iII111i / oO0o / iII111i * OoO0O00
 if 25 - 25: OoOoOO00 - II111iiii + II111iiii . Ii1I * II111iiii
 if 12 - 12: IiII / Ii1I
 if 54 - 54: Oo0Ooo + Ii1I % OoooooooOO * OOooOOo / OoOoOO00
 if 39 - 39: I1IiiI % i11iIiiIii % Ii1I
 if 59 - 59: ooOoO0o % OoO0O00 / I1IiiI - II111iiii + OoooooooOO * i11iIiiIii
 if 58 - 58: IiII / Oo0Ooo + o0oOOo0O0Ooo
 if 71 - 71: Ii1I - IiII
 if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
 if 65 - 65: iII111i . oO0o
 if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
 if 31 - 31: I11i - oO0o * ooOoO0o
 if 64 - 64: I11i
 I1iiIIiIII1i = [ ]
 for oo0o00oOOooO in eid_list :
  for iiI11Ii1I1 in lisp_map_notify_queue :
   ooOOoo0o = lisp_map_notify_queue [ iiI11Ii1I1 ]
   if ( oo0o00oOOooO not in ooOOoo0o . eid_list ) : continue
   if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
   I1iiIIiIII1i . append ( iiI11Ii1I1 )
   IiII1II1I = ooOOoo0o . retransmit_timer
   if ( IiII1II1I ) : IiII1II1I . cancel ( )
   if 40 - 40: o0oOOo0O0Ooo - OoOoOO00 - iIii1I11I1II1
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( ooOOoo0o . nonce_key , green ( oo0o00oOOooO , False ) ) )
   if 46 - 46: ooOoO0o / I1ii11iIi11i * O0
   if 100 - 100: Ii1I / OoO0O00 / II111iiii / OoOoOO00 * IiII
   if 76 - 76: I1IiiI + IiII * I1ii11iIi11i * I1IiiI % Ii1I + ooOoO0o
   if 46 - 46: OoOoOO00
   if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
   if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
   if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
 for iiI11Ii1I1 in I1iiIIiIII1i : lisp_map_notify_queue . pop ( iiI11Ii1I1 )
 return
 if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
 if 20 - 20: IiII
 if 81 - 81: Oo0Ooo / I1Ii111
 if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
 if 51 - 51: iII111i - ooOoO0o
 if 32 - 32: IiII - i11iIiiIii
 if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
 if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
def lisp_decrypt_map_register ( packet ) :
 if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
 if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
 if 37 - 37: OOooOOo
 if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
 if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
 i111ii1II11ii = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 I1Iii1IiIII = ( i111ii1II11ii >> 13 ) & 0x1
 if ( I1Iii1IiIII == 0 ) : return ( packet )
 if 58 - 58: I11i + Oo0Ooo . IiII * i11iIiiIii % IiII
 iI1Ii1I = ( i111ii1II11ii >> 14 ) & 0x7
 if 58 - 58: Oo0Ooo / ooOoO0o * ooOoO0o * OoO0O00
 if 52 - 52: O0
 if 90 - 90: I11i / Oo0Ooo . II111iiii / ooOoO0o - OOooOOo
 if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
 try :
  i1ii1IIii = lisp_ms_encryption_keys [ iI1Ii1I ]
  i1ii1IIii = i1ii1IIii . zfill ( 32 )
  oO0o000oOO = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( iI1Ii1I ) )
  return ( None )
  if 99 - 99: I1ii11iIi11i % iII111i * IiII - I1IiiI
  if 60 - 60: OoO0O00
 oooOo = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( oooOo , iI1Ii1I ) )
 if 56 - 56: ooOoO0o / OoO0O00 . OoooooooOO % iII111i / IiII
 if 64 - 64: ooOoO0o % O0 / oO0o
 if 21 - 21: i11iIiiIii . o0oOOo0O0Ooo
 if 78 - 78: Oo0Ooo
 oOO0o0OOo = chacha . ChaCha ( i1ii1IIii , oO0o000oOO , 20 ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + oOO0o0OOo )
 if 77 - 77: oO0o % Oo0Ooo % O0
 if 51 - 51: IiII % IiII + OOooOOo . II111iiii / I1ii11iIi11i
 if 4 - 4: o0oOOo0O0Ooo % I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
 if 61 - 61: OoooooooOO - OoOoOO00 . O0 / ooOoO0o . Ii1I
 if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
 if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
 if 88 - 88: ooOoO0o
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
 if 20 - 20: i11iIiiIii * I11i
 if 29 - 29: IiII / OOooOOo
 if 39 - 39: O0 + II111iiii
 if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
 if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
 Ii1Ii = lisp_map_register ( )
 OOo00o0oOO0o , packet = Ii1Ii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 7 - 7: OOooOOo / OoOoOO00 . I1IiiI % ooOoO0o + OOooOOo
 Ii1Ii . sport = sport
 if 91 - 91: oO0o - ooOoO0o
 Ii1Ii . print_map_register ( )
 if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
 if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
 if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
 if 7 - 7: I1IiiI + OoooooooOO + o0oOOo0O0Ooo . OoooooooOO
 I1Ii1II1I11II = True
 if ( Ii1Ii . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  I1Ii1II1I11II = True
  if 56 - 56: Ii1I % OoO0O00 / I1IiiI / iIii1I11I1II1
 if ( Ii1Ii . alg_id == LISP_SHA_256_128_ALG_ID ) :
  I1Ii1II1I11II = False
  if 49 - 49: I1IiiI
  if 27 - 27: OOooOOo * O0 - IiII . oO0o
  if 65 - 65: I1IiiI / oO0o . I11i
  if 15 - 15: OoOoOO00 + Ii1I
  if 99 - 99: ooOoO0o / IiII
 iiIiii = [ ]
 if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
 if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
 if 48 - 48: I1Ii111 * Oo0Ooo % OoO0O00 % Ii1I
 if 8 - 8: OoO0O00 . OoO0O00
 I11iII1 = None
 IiiI1Iiii = packet
 O00o0OOoO0o = [ ]
 oO0Oo0o0 = Ii1Ii . record_count
 for o000o0O0Oo00 in range ( oO0Oo0o0 ) :
  Oo0oOoooO = lisp_eid_record ( )
  oOiI111IIIiIii = lisp_rloc_record ( )
  packet = Oo0oOoooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 56 - 56: iIii1I11I1II1 / I1Ii111 * OoO0O00 + IiII * OoOoOO00
  Oo0oOoooO . print_record ( "  " , False )
  if 68 - 68: OoOoOO00 + iIii1I11I1II1 + iII111i * IiII - iIii1I11I1II1 % OoOoOO00
  if 91 - 91: I1ii11iIi11i
  if 92 - 92: Oo0Ooo / OoO0O00 * OoooooooOO
  if 31 - 31: I11i * I1IiiI
  I1iOooO0o = lisp_site_eid_lookup ( Oo0oOoooO . eid , Oo0oOoooO . group ,
 False )
  if 80 - 80: I11i * IiII % iII111i + OoOoOO00
  o0Ii11IIii1 = I1iOooO0o . print_eid_tuple ( ) if I1iOooO0o else None
  if 83 - 83: OoooooooOO - i1IIi / i1IIi - ooOoO0o + II111iiii
  if 54 - 54: OoOoOO00 * o0oOOo0O0Ooo . OoO0O00
  if 53 - 53: oO0o % OoO0O00 / OoO0O00 / I11i * Oo0Ooo
  if 13 - 13: i1IIi % iIii1I11I1II1 - iII111i - I1IiiI - IiII + iIii1I11I1II1
  if 22 - 22: IiII - OOooOOo + I1ii11iIi11i
  if 64 - 64: OoOoOO00
  if 79 - 79: IiII
  if ( I1iOooO0o and I1iOooO0o . accept_more_specifics == False ) :
   if ( I1iOooO0o . eid_record_matches ( Oo0oOoooO ) == False ) :
    OO0ooOo0o = I1iOooO0o . parent_for_more_specifics
    if ( OO0ooOo0o ) : I1iOooO0o = OO0ooOo0o
    if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
    if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
    if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
    if 41 - 41: OoooooooOO + iII111i . OOooOOo
    if 73 - 73: oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
    if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
    if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
    if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
  oo0Ooo0o0O = ( I1iOooO0o and I1iOooO0o . accept_more_specifics )
  if ( oo0Ooo0o0O ) :
   iiIiIIii1 = lisp_site_eid ( I1iOooO0o . site )
   iiIiIIii1 . dynamic = True
   iiIiIIii1 . eid . copy_address ( Oo0oOoooO . eid )
   iiIiIIii1 . group . copy_address ( Oo0oOoooO . group )
   iiIiIIii1 . parent_for_more_specifics = I1iOooO0o
   iiIiIIii1 . add_cache ( )
   iiIiIIii1 . inherit_from_ams_parent ( )
   I1iOooO0o . more_specific_registrations . append ( iiIiIIii1 )
   I1iOooO0o = iiIiIIii1
  else :
   I1iOooO0o = lisp_site_eid_lookup ( Oo0oOoooO . eid , Oo0oOoooO . group ,
 True )
   if 28 - 28: iII111i . I1Ii111
   if 22 - 22: OoOoOO00 . iIii1I11I1II1 / oO0o + IiII * I1Ii111
  oOOoo = Oo0oOoooO . print_eid_tuple ( )
  if 57 - 57: II111iiii + Oo0Ooo - Ii1I . OOooOOo * OoOoOO00
  if ( I1iOooO0o == None ) :
   oOiiI1i11i1Ii = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( oOiiI1i11i1Ii , green ( oOOoo , False ) ,
 ", matched non-ams {}" . format ( green ( o0Ii11IIii1 , False ) if o0Ii11IIii1 else "" ) ) )
   if 87 - 87: o0oOOo0O0Ooo / O0 * iIii1I11I1II1
   if 81 - 81: Oo0Ooo
   if 69 - 69: o0oOOo0O0Ooo * ooOoO0o + OoOoOO00 . I1IiiI
   if 27 - 27: Oo0Ooo % OoooooooOO / OOooOOo / II111iiii + i11iIiiIii
   if 85 - 85: OoO0O00 % I11i + I1IiiI / i1IIi + I1ii11iIi11i - O0
   packet = oOiI111IIIiIii . end_of_rlocs ( packet , Oo0oOoooO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 13 - 13: O0 % iII111i + I1IiiI % O0 % oO0o . OoO0O00
   continue
   if 76 - 76: II111iiii + i11iIiiIii - OoooooooOO % OoOoOO00
   if 4 - 4: I1Ii111 + i11iIiiIii . Ii1I / iII111i
  I11iII1 = I1iOooO0o . site
  if 24 - 24: Ii1I / II111iiii + I1IiiI
  if ( oo0Ooo0o0O ) :
   oOO = I1iOooO0o . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( oOO , False ) , I11iII1 . site_name , green ( oOOoo , False ) ) )
   if 100 - 100: Ii1I / IiII * O0
  else :
   oOO = green ( I1iOooO0o . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( oOO , I11iII1 . site_name , green ( oOOoo , False ) ) )
   if 60 - 60: Oo0Ooo / IiII / OoOoOO00 % iIii1I11I1II1 . o0oOOo0O0Ooo % iIii1I11I1II1
   if 35 - 35: OoooooooOO % O0 * I1Ii111 - iIii1I11I1II1 % iII111i
   if 15 - 15: O0 - Ii1I + OoOoOO00
   if 93 - 93: OoO0O00
   if 68 - 68: OOooOOo
   if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
  if ( I11iII1 . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( I11iII1 . site_name ) )
   packet = oOiI111IIIiIii . end_of_rlocs ( packet , Oo0oOoooO . rloc_count )
   continue
   if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
   if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
   if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
   if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
   if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
   if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
   if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
   if 57 - 57: i11iIiiIii
  IIIIIi1 = Ii1Ii . key_id
  if ( IIIIIi1 in I11iII1 . auth_key ) :
   iiii = I11iII1 . auth_key [ IIIIIi1 ]
  else :
   iiii = ""
   if 83 - 83: II111iiii + Oo0Ooo
   if 24 - 24: I11i
  oooOoooOO0o0 = lisp_verify_auth ( OOo00o0oOO0o , Ii1Ii . alg_id ,
 Ii1Ii . auth_data , iiii )
  iIIOo = "dynamic " if I1iOooO0o . dynamic else ""
  if 40 - 40: I1ii11iIi11i / iIii1I11I1II1 / OoO0O00 / i11iIiiIii % I11i
  oO00OO0Ooo00O = bold ( "passed" if oooOoooOO0o0 else "failed" , False )
  IIIIIi1 = "key-id {}" . format ( IIIIIi1 ) if IIIIIi1 == Ii1Ii . key_id else "bad key-id {}" . format ( Ii1Ii . key_id )
  if 35 - 35: oO0o * I11i + I1Ii111
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( oO00OO0Ooo00O , iIIOo , green ( oOOoo , False ) , IIIIIi1 ) )
  if 48 - 48: O0 . iIii1I11I1II1 * OoooooooOO . iIii1I11I1II1 % o0oOOo0O0Ooo % ooOoO0o
  if 33 - 33: OoO0O00 . I1ii11iIi11i / OOooOOo
  if 51 - 51: ooOoO0o % I11i + IiII + oO0o + O0 % ooOoO0o
  if 38 - 38: OoO0O00 - iIii1I11I1II1 % ooOoO0o + I1ii11iIi11i - Ii1I
  if 69 - 69: OOooOOo / OoooooooOO % ooOoO0o % iIii1I11I1II1 / OoO0O00 + iIii1I11I1II1
  if 47 - 47: II111iiii % O0 / I1IiiI / iIii1I11I1II1 * I11i
  oo00O0ooOoOOO = True
  I1iiooOo0oo00O000 = ( lisp_get_eid_hash ( Oo0oOoooO . eid ) != None )
  if ( I1iiooOo0oo00O000 or I1iOooO0o . require_signature ) :
   IIIi = "Required " if I1iOooO0o . require_signature else ""
   oOOoo = green ( oOOoo , False )
   iIIiI11 = lisp_find_sig_in_rloc_set ( packet , Oo0oOoooO . rloc_count )
   if ( iIIiI11 == None ) :
    oo00O0ooOoOOO = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( IIIi ,
    # ooOoO0o / oO0o / o0oOOo0O0Ooo
 bold ( "failed" , False ) , oOOoo ) )
   else :
    oo00O0ooOoOOO = lisp_verify_cga_sig ( Oo0oOoooO . eid , iIIiI11 )
    oO00OO0Ooo00O = bold ( "passed" if oo00O0ooOoOOO else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( IIIi , oO00OO0Ooo00O , oOOoo ) )
    if 90 - 90: iII111i . o0oOOo0O0Ooo
    if 97 - 97: Oo0Ooo . I1ii11iIi11i - I1Ii111 - Ii1I / OOooOOo
    if 18 - 18: OoOoOO00 / OoO0O00 % ooOoO0o * Ii1I
    if 67 - 67: I11i . II111iiii + iIii1I11I1II1 - I1IiiI
  if ( oooOoooOO0o0 == False or oo00O0ooOoOOO == False ) :
   packet = oOiI111IIIiIii . end_of_rlocs ( packet , Oo0oOoooO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 25 - 25: i1IIi . OoO0O00 - Ii1I
   continue
   if 42 - 42: O0 * iII111i . i1IIi / i11iIiiIii + Ii1I
   if 80 - 80: O0 + II111iiii + oO0o . Oo0Ooo * i1IIi
   if 8 - 8: Ii1I
   if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
   if 15 - 15: O0
   if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
  if ( Ii1Ii . merge_register_requested ) :
   OO0ooOo0o = I1iOooO0o
   OO0ooOo0o . inconsistent_registration = False
   if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
   if 25 - 25: ooOoO0o
   if 33 - 33: Oo0Ooo
   if 11 - 11: I11i
   if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
   if ( I1iOooO0o . group . is_null ( ) ) :
    if ( OO0ooOo0o . site_id != Ii1Ii . site_id ) :
     OO0ooOo0o . site_id = Ii1Ii . site_id
     OO0ooOo0o . registered = False
     OO0ooOo0o . individual_registrations = { }
     OO0ooOo0o . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
     if 74 - 74: I1IiiI / o0oOOo0O0Ooo
     if 53 - 53: iIii1I11I1II1 * oO0o
   OoOOooOOoo = Ii1Ii . xtr_id
   if ( OoOOooOOoo in I1iOooO0o . individual_registrations ) :
    I1iOooO0o = I1iOooO0o . individual_registrations [ OoOOooOOoo ]
   else :
    I1iOooO0o = lisp_site_eid ( I11iII1 )
    I1iOooO0o . eid . copy_address ( OO0ooOo0o . eid )
    I1iOooO0o . group . copy_address ( OO0ooOo0o . group )
    I1iOooO0o . encrypt_json = OO0ooOo0o . encrypt_json
    OO0ooOo0o . individual_registrations [ OoOOooOOoo ] = I1iOooO0o
    if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
  else :
   I1iOooO0o . inconsistent_registration = I1iOooO0o . merge_register_requested
   if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
   if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
   if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
  I1iOooO0o . map_registers_received += 1
  if 60 - 60: oO0o * I1Ii111
  if 81 - 81: oO0o - OOooOOo - oO0o
  if 54 - 54: oO0o % I11i
  if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
  if 22 - 22: iIii1I11I1II1 - OoooooooOO
  OoooOOoOO = ( I1iOooO0o . is_rloc_in_rloc_set ( source ) == False )
  if ( Oo0oOoooO . record_ttl == 0 and OoooOOoOO ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 8 - 8: ooOoO0o % i11iIiiIii
   continue
   if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
   if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
   if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
   if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
   if 73 - 73: O0 % i11iIiiIii
   if 16 - 16: O0
  iiii1i1iI11 = I1iOooO0o . registered_rlocs
  I1iOooO0o . registered_rlocs = [ ]
  if 45 - 45: I1IiiI . iIii1I11I1II1 + OoooooooOO + oO0o
  if 26 - 26: OoOoOO00 + I1IiiI % II111iiii * Oo0Ooo . iII111i / i1IIi
  if 90 - 90: I1IiiI - OoO0O00 % I1Ii111 . i1IIi
  if 30 - 30: iIii1I11I1II1 . O0
  iIO0oO0o00oO = packet
  for I11ii1IiI1Ii in range ( Oo0oOoooO . rloc_count ) :
   oOiI111IIIiIii = lisp_rloc_record ( )
   packet = oOiI111IIIiIii . decode ( packet , None , I1iOooO0o . encrypt_json )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
   oOiI111IIIiIii . print_record ( "    " )
   if 72 - 72: ooOoO0o
   if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
   if 53 - 53: OOooOOo * O0 . iII111i
   if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
   if ( len ( I11iII1 . allowed_rlocs ) > 0 ) :
    O00oO000Oo0 = oOiI111IIIiIii . rloc . print_address ( )
    if ( O00oO000Oo0 not in I11iII1 . allowed_rlocs ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( O00oO000Oo0 , False ) ) )
     if 78 - 78: iII111i
     if 80 - 80: i1IIi * I1IiiI + OOooOOo
     I1iOooO0o . registered = False
     packet = oOiI111IIIiIii . end_of_rlocs ( packet ,
 Oo0oOoooO . rloc_count - I11ii1IiI1Ii - 1 )
     break
     if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
     if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
     if 63 - 63: O0
     if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
     if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
     if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
   iIIiI11 = lisp_rloc ( )
   iIIiI11 . store_rloc_from_record ( oOiI111IIIiIii , None , source )
   if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
   if 74 - 74: i11iIiiIii
   if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
   if 6 - 6: I11i
   if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
   if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
   if ( source . is_exact_match ( iIIiI11 . rloc ) ) :
    iIIiI11 . map_notify_requested = Ii1Ii . map_notify_requested
    if 6 - 6: Ii1I
    if 60 - 60: iII111i + I1IiiI
    if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
    if 16 - 16: Oo0Ooo
    if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
   I1iOooO0o . registered_rlocs . append ( iIIiI11 )
   if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
   if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
  iI11IIi = ( I1iOooO0o . do_rloc_sets_match ( iiii1i1iI11 ) == False )
  if 51 - 51: ooOoO0o * I1ii11iIi11i + I1IiiI * OoOoOO00
  if 73 - 73: IiII - I1Ii111
  if 6 - 6: I1ii11iIi11i % IiII * O0
  if 38 - 38: iIii1I11I1II1 / I1IiiI * i11iIiiIii - IiII
  if 43 - 43: oO0o - I11i . i11iIiiIii
  if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
  if ( Ii1Ii . map_register_refresh and iI11IIi and
 I1iOooO0o . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   I1iOooO0o . registered_rlocs = iiii1i1iI11
   continue
   if 30 - 30: I1IiiI % oO0o * OoooooooOO
   if 64 - 64: I1IiiI
   if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
   if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
   if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
   if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
  if ( I1iOooO0o . registered == False ) :
   I1iOooO0o . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
  I1iOooO0o . last_registered = lisp_get_timestamp ( )
  I1iOooO0o . registered = ( Oo0oOoooO . record_ttl != 0 )
  I1iOooO0o . last_registerer = source
  if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
  if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
  if 67 - 67: I1IiiI * Ii1I
  if 64 - 64: OOooOOo
  I1iOooO0o . auth_sha1_or_sha2 = I1Ii1II1I11II
  I1iOooO0o . proxy_reply_requested = Ii1Ii . proxy_reply_requested
  I1iOooO0o . lisp_sec_present = Ii1Ii . lisp_sec_present
  I1iOooO0o . map_notify_requested = Ii1Ii . map_notify_requested
  I1iOooO0o . mobile_node_requested = Ii1Ii . mobile_node
  I1iOooO0o . merge_register_requested = Ii1Ii . merge_register_requested
  if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
  I1iOooO0o . use_register_ttl_requested = Ii1Ii . use_ttl_for_timeout
  if ( I1iOooO0o . use_register_ttl_requested ) :
   I1iOooO0o . register_ttl = Oo0oOoooO . store_ttl ( )
  else :
   I1iOooO0o . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 2 - 2: o0oOOo0O0Ooo . II111iiii
  I1iOooO0o . xtr_id_present = Ii1Ii . xtr_id_present
  if ( I1iOooO0o . xtr_id_present ) :
   I1iOooO0o . xtr_id = Ii1Ii . xtr_id
   I1iOooO0o . site_id = Ii1Ii . site_id
   if 9 - 9: I1Ii111 - II111iiii + OoOoOO00 . OoO0O00
   if 33 - 33: Oo0Ooo
   if 12 - 12: i11iIiiIii . Oo0Ooo / OoOoOO00 + iII111i . Ii1I + ooOoO0o
   if 66 - 66: IiII
   if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
  if ( Ii1Ii . merge_register_requested ) :
   if ( OO0ooOo0o . merge_in_site_eid ( I1iOooO0o ) ) :
    iiIiii . append ( [ Oo0oOoooO . eid , Oo0oOoooO . group ] )
    if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
   if ( Ii1Ii . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , OO0ooOo0o , Ii1Ii ,
 Oo0oOoooO )
    if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
    if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
    if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  if ( iI11IIi == False ) : continue
  if ( len ( iiIiii ) != 0 ) : continue
  if 79 - 79: II111iiii / OoooooooOO
  O00o0OOoO0o . append ( I1iOooO0o . print_eid_tuple ( ) )
  if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
  if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
  if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  if 17 - 17: I1Ii111
  if 2 - 2: O0 % OoOoOO00 + oO0o
  if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
  if 51 - 51: IiII
  I11iI11i1 = copy . deepcopy ( Oo0oOoooO )
  Oo0oOoooO = Oo0oOoooO . encode ( )
  Oo0oOoooO += iIO0oO0o00oO
  iII1II11II = [ I1iOooO0o . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 59 - 59: i11iIiiIii % iIii1I11I1II1 / IiII
  for iIIiI11 in iiii1i1iI11 :
   if ( iIIiI11 . map_notify_requested == False ) : continue
   if ( iIIiI11 . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , Oo0oOoooO , iII1II11II , 1 , iIIiI11 . rloc ,
 LISP_CTRL_PORT , Ii1Ii . nonce , Ii1Ii . key_id ,
 Ii1Ii . alg_id , Ii1Ii . auth_len , I11iII1 , False )
   if 100 - 100: Ii1I . o0oOOo0O0Ooo - II111iiii . O0
   if 5 - 5: iII111i
   if 66 - 66: oO0o / OoOoOO00 . i1IIi % ooOoO0o . iII111i * I11i
   if 48 - 48: oO0o % OoOoOO00
   if 23 - 23: i1IIi - Ii1I - oO0o . OoooooooOO + OOooOOo * oO0o
  lisp_notify_subscribers ( lisp_sockets , I11iI11i1 , iIO0oO0o00oO ,
 I1iOooO0o . eid , I11iII1 )
  if 56 - 56: O0 + OoOoOO00 + OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 . i11iIiiIii
  if 84 - 84: I11i + OOooOOo - OoooooooOO / I1ii11iIi11i
  if 12 - 12: I1IiiI * iIii1I11I1II1 - II111iiii / o0oOOo0O0Ooo - OOooOOo
  if 99 - 99: I1ii11iIi11i / O0 % II111iiii % I1Ii111 * II111iiii
  if 28 - 28: I11i - Oo0Ooo + iIii1I11I1II1 + O0 * Ii1I + I1IiiI
 if ( len ( iiIiii ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , iiIiii )
  if 13 - 13: iII111i
  if 42 - 42: I1Ii111 - I1IiiI % I1IiiI * I1IiiI
  if 70 - 70: O0 / I1IiiI / I1IiiI
  if 71 - 71: OOooOOo - Oo0Ooo + IiII * oO0o
  if 90 - 90: OoOoOO00 * I1ii11iIi11i
  if 16 - 16: i1IIi - OoO0O00
 if ( Ii1Ii . merge_register_requested ) : return
 if 61 - 61: o0oOOo0O0Ooo + OoOoOO00 - ooOoO0o + ooOoO0o % ooOoO0o % II111iiii
 if 16 - 16: I1IiiI . Ii1I
 if 80 - 80: OOooOOo * O0 / iIii1I11I1II1 / IiII / OoOoOO00
 if 15 - 15: I1ii11iIi11i * iII111i + i11iIiiIii
 if 68 - 68: i1IIi / oO0o * I1ii11iIi11i - OoOoOO00 + Oo0Ooo / O0
 if ( Ii1Ii . map_notify_requested and I11iII1 != None ) :
  lisp_build_map_notify ( lisp_sockets , IiiI1Iiii , O00o0OOoO0o ,
 Ii1Ii . record_count , source , sport , Ii1Ii . nonce ,
 Ii1Ii . key_id , Ii1Ii . alg_id , Ii1Ii . auth_len ,
 I11iII1 , True )
  if 1 - 1: ooOoO0o - Oo0Ooo + I1Ii111
 return
 if 90 - 90: I1Ii111 * O0 . iII111i - Oo0Ooo % iIii1I11I1II1
 if 7 - 7: I1ii11iIi11i % o0oOOo0O0Ooo % O0 % iIii1I11I1II1
 if 10 - 10: OoooooooOO - iII111i . i1IIi % oO0o . OoooooooOO + OOooOOo
 if 59 - 59: I1IiiI * OoooooooOO % OOooOOo / I11i
 if 77 - 77: II111iiii - IiII % OOooOOo
 if 22 - 22: OoooooooOO / oO0o
 if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
 if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
def lisp_process_unicast_map_notify ( lisp_sockets , packet , source ) :
 ooOOoo0o = lisp_map_notify ( "" )
 packet = ooOOoo0o . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 12 - 12: I1Ii111
  if 17 - 17: I1Ii111 % oO0o + O0
 ooOOoo0o . print_notify ( )
 if ( ooOOoo0o . record_count == 0 ) : return
 if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
 O0Oo0O = ooOOoo0o . eid_records
 oOiI111IIIiIii = lisp_rloc_record ( )
 if 50 - 50: OoO0O00 . O0 * o0oOOo0O0Ooo . O0
 for o000o0O0Oo00 in range ( ooOOoo0o . record_count ) :
  Oo0oOoooO = lisp_eid_record ( )
  O0Oo0O = Oo0oOoooO . decode ( O0Oo0O )
  if ( packet == None ) : return
  Oo0oOoooO . print_record ( "  " , False )
  oOOoo = Oo0oOoooO . print_eid_tuple ( )
  o00O000o0O0O = Oo0oOoooO . rloc_count
  if 28 - 28: OoOoOO00 % iIii1I11I1II1 + i1IIi * I1IiiI + O0 + ooOoO0o
  if 2 - 2: o0oOOo0O0Ooo + I1IiiI + I1ii11iIi11i
  if 94 - 94: o0oOOo0O0Ooo - OoOoOO00 * oO0o
  if 80 - 80: iII111i - O0 + IiII + iIii1I11I1II1 * I1ii11iIi11i
  if 8 - 8: OoO0O00
  I1I1i1I11I = lisp_map_cache_lookup ( Oo0oOoooO . eid , Oo0oOoooO . eid )
  if ( I1I1i1I11I == None ) :
   oOO = green ( oOOoo , False )
   lprint ( "Ignoring Map-Notify EID {}, no subscribe-request entry" . format ( oOO ) )
   if 99 - 99: iII111i . I1ii11iIi11i . o0oOOo0O0Ooo
   O0Oo0O = oOiI111IIIiIii . end_of_rlocs ( O0Oo0O , o00O000o0O0O )
   continue
   if 4 - 4: I11i * Oo0Ooo . i11iIiiIii / Ii1I . I1ii11iIi11i % I1Ii111
   if 68 - 68: ooOoO0o
   if 58 - 58: iII111i * I1IiiI
   if 82 - 82: Oo0Ooo / OoO0O00 % Oo0Ooo . ooOoO0o * O0
   if 39 - 39: I1Ii111 * IiII
   if 16 - 16: ooOoO0o + OoO0O00 / I11i * OoO0O00 . Oo0Ooo % OoOoOO00
   if 65 - 65: Oo0Ooo / I1Ii111 % II111iiii % Ii1I
  if ( I1I1i1I11I . action != LISP_SEND_PUBSUB_ACTION ) :
   if ( I1I1i1I11I . subscribed_eid == None ) :
    oOO = green ( oOOoo , False )
    lprint ( "Ignoring Map-Notify for non-subscribed EID {}" . format ( oOO ) )
    if 70 - 70: II111iiii % Oo0Ooo * oO0o
    O0Oo0O = oOiI111IIIiIii . end_of_rlocs ( O0Oo0O , o00O000o0O0O )
    continue
    if 54 - 54: O0 / ooOoO0o * I1Ii111
    if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
    if 13 - 13: IiII + Oo0Ooo - I1Ii111
    if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
    if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
    if 95 - 95: oO0o / Ii1I + OoO0O00
    if 57 - 57: iIii1I11I1II1 + I1Ii111 % oO0o - Ii1I . I1IiiI
    if 39 - 39: OoO0O00 + II111iiii
  Oo00OOO0 = [ ]
  if ( I1I1i1I11I . action == LISP_SEND_PUBSUB_ACTION ) :
   I1I1i1I11I = lisp_mapping ( Oo0oOoooO . eid , Oo0oOoooO . group , [ ] )
   I1I1i1I11I . add_cache ( )
   O0oO = copy . deepcopy ( Oo0oOoooO . eid )
   o00OOo0 = copy . deepcopy ( Oo0oOoooO . group )
  else :
   O0oO = I1I1i1I11I . subscribed_eid
   o00OOo0 = I1I1i1I11I . subscribed_group
   Oo00OOO0 = I1I1i1I11I . rloc_set
   I1I1i1I11I . delete_rlocs_from_rloc_probe_list ( )
   I1I1i1I11I . rloc_set = [ ]
   if 61 - 61: OoooooooOO * II111iiii
   if 49 - 49: oO0o - I1IiiI . IiII / i11iIiiIii
   if 1 - 1: Ii1I
   if 97 - 97: Oo0Ooo - iII111i / I1ii11iIi11i
   if 49 - 49: iII111i + I11i . Oo0Ooo
  I1I1i1I11I . mapping_source = None if source == "lisp-itr" else source
  I1I1i1I11I . map_cache_ttl = Oo0oOoooO . store_ttl ( )
  I1I1i1I11I . subscribed_eid = O0oO
  I1I1i1I11I . subscribed_group = o00OOo0
  if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
  if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
  if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
  if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
  if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
  if ( len ( Oo00OOO0 ) != 0 and Oo0oOoooO . rloc_count == 0 ) :
   I1I1i1I11I . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , I1I1i1I11I )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( oOOoo , False ) ) )
   if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
   O0Oo0O = oOiI111IIIiIii . end_of_rlocs ( O0Oo0O , o00O000o0O0O )
   continue
   if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
   if 1 - 1: i11iIiiIii
   if 1 - 1: iIii1I11I1II1
   if 73 - 73: iII111i + IiII
   if 95 - 95: O0
   if 75 - 75: ooOoO0o
   if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
  O00 = oooo00O0O0OOo = 0
  for I11ii1IiI1Ii in range ( o00O000o0O0O ) :
   oOiI111IIIiIii = lisp_rloc_record ( )
   O0Oo0O = oOiI111IIIiIii . decode ( O0Oo0O , None )
   oOiI111IIIiIii . print_record ( "    " )
   if 14 - 14: I1IiiI - iIii1I11I1II1 - iIii1I11I1II1 + OoOoOO00 * OoooooooOO * I1IiiI
   if 86 - 86: I1IiiI - OoooooooOO . I11i / O0 * o0oOOo0O0Ooo
   if 97 - 97: I1IiiI
   if 80 - 80: OOooOOo . oO0o * i11iIiiIii * IiII
   iIi1iII = False
   for I1I1 in Oo00OOO0 :
    if ( I1I1 . rloc . is_exact_match ( oOiI111IIIiIii . rloc ) ) :
     iIi1iII = True
     break
     if 30 - 30: iIii1I11I1II1 - ooOoO0o / iIii1I11I1II1 / I1IiiI + OoOoOO00 - iIii1I11I1II1
     if 69 - 69: i11iIiiIii . O0
   if ( iIi1iII ) :
    iIIiI11 = copy . deepcopy ( I1I1 )
    oooo00O0O0OOo += 1
   else :
    iIIiI11 = lisp_rloc ( )
    O00 += 1
    if 21 - 21: i1IIi . OoO0O00 % I11i + II111iiii % o0oOOo0O0Ooo
    if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
    if 44 - 44: I1ii11iIi11i
    if 39 - 39: iII111i + Oo0Ooo / oO0o
    if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
   iIIiI11 . store_rloc_from_record ( oOiI111IIIiIii , None , I1I1i1I11I . mapping_source )
   I1I1i1I11I . rloc_set . append ( iIIiI11 )
   if 99 - 99: I1IiiI * II111iiii
   if 84 - 84: II111iiii - I1IiiI
  lprint ( "Update {} map-cache entry with {}/{} new/replaced RLOCs" . format ( green ( oOOoo , False ) , O00 , oooo00O0O0OOo ) )
  if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
  if 35 - 35: I11i + i1IIi
  if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
  if 97 - 97: oO0o % iIii1I11I1II1
  if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
  I1I1i1I11I . build_best_rloc_set ( )
  lisp_write_ipc_map_cache ( True , I1I1i1I11I )
  if 16 - 16: I1IiiI
  if 39 - 39: ooOoO0o * II111iiii
  if 90 - 90: OoooooooOO * ooOoO0o
  if 14 - 14: I1IiiI % i1IIi
  if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
  if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
 ii1iIIiIIi111 = lisp_get_map_server ( source )
 if ( ii1iIIiIIi111 == None ) :
  lprint ( "Cannot find Map-Server for Map-Notify source address {}" . format ( source . print_address_no_iid ( ) ) )
  if 55 - 55: i1IIi
  return
  if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
 lisp_send_map_notify_ack ( lisp_sockets , O0Oo0O , ooOOoo0o , ii1iIIiIIi111 )
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
def lisp_process_multicast_map_notify ( packet , source ) :
 ooOOoo0o = lisp_map_notify ( "" )
 packet = ooOOoo0o . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
  if 100 - 100: ooOoO0o / OoooooooOO
 ooOOoo0o . print_notify ( )
 if ( ooOOoo0o . record_count == 0 ) : return
 if 73 - 73: i11iIiiIii - Oo0Ooo
 O0Oo0O = ooOOoo0o . eid_records
 if 100 - 100: iIii1I11I1II1 + I1Ii111
 for o000o0O0Oo00 in range ( ooOOoo0o . record_count ) :
  Oo0oOoooO = lisp_eid_record ( )
  O0Oo0O = Oo0oOoooO . decode ( O0Oo0O )
  if ( packet == None ) : return
  Oo0oOoooO . print_record ( "  " , False )
  if 51 - 51: o0oOOo0O0Ooo * I11i
  if 42 - 42: OOooOOo % I11i
  if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
  if 81 - 81: I1IiiI
  I1I1i1I11I = lisp_map_cache_lookup ( Oo0oOoooO . eid , Oo0oOoooO . group )
  if ( I1I1i1I11I == None or I1I1i1I11I . action == LISP_SEND_PUBSUB_ACTION ) :
   if ( I1I1i1I11I == None ) :
    o0Oo0O0o , Oo0OoO00O , OOo00 = lisp_allow_gleaning ( Oo0oOoooO . eid ,
 Oo0oOoooO . group , None )
    if ( o0Oo0O0o == False ) : continue
    if 66 - 66: i11iIiiIii . I1IiiI
    if 60 - 60: iII111i . o0oOOo0O0Ooo + iII111i
   I1I1i1I11I = lisp_mapping ( Oo0oOoooO . eid , Oo0oOoooO . group , [ ] )
   I1I1i1I11I . add_cache ( )
   if 38 - 38: i11iIiiIii * I11i + Oo0Ooo - iIii1I11I1II1
   if 75 - 75: i1IIi * iII111i - I11i * i11iIiiIii
   if 75 - 75: I1IiiI . OoooooooOO + OOooOOo + IiII
   if 37 - 37: iII111i + i1IIi % Oo0Ooo / o0oOOo0O0Ooo / iII111i
   if 81 - 81: ooOoO0o
   if 74 - 74: OoO0O00
   if 13 - 13: I1ii11iIi11i / OoO0O00
  if ( I1I1i1I11I . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( I1I1i1I11I . print_eid_tuple ( ) , False ) ) )
   if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
   continue
   if 94 - 94: IiII * i1IIi
   if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  I1I1i1I11I . mapping_source = None if source == "lisp-etr" else source
  I1I1i1I11I . map_cache_ttl = Oo0oOoooO . store_ttl ( )
  if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
  if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
  if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
  if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
  if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
  if ( len ( I1I1i1I11I . rloc_set ) != 0 and Oo0oOoooO . rloc_count == 0 ) :
   I1I1i1I11I . rloc_set = [ ]
   I1I1i1I11I . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , I1I1i1I11I )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( I1I1i1I11I . print_eid_tuple ( ) , False ) ) )
   if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
   continue
   if 66 - 66: i1IIi
   if 98 - 98: Oo0Ooo / iIii1I11I1II1
  ii1Ii111i = I1I1i1I11I . rtrs_in_rloc_set ( )
  if 63 - 63: OOooOOo . OOooOOo - I1IiiI * i11iIiiIii * II111iiii + I1IiiI
  if 68 - 68: OoOoOO00 + iIii1I11I1II1 * IiII * I11i % IiII % o0oOOo0O0Ooo
  if 10 - 10: IiII % i1IIi
  if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
  if 87 - 87: I11i
  for I11ii1IiI1Ii in range ( Oo0oOoooO . rloc_count ) :
   oOiI111IIIiIii = lisp_rloc_record ( )
   O0Oo0O = oOiI111IIIiIii . decode ( O0Oo0O , None )
   oOiI111IIIiIii . print_record ( "    " )
   if ( Oo0oOoooO . group . is_null ( ) ) : continue
   if ( oOiI111IIIiIii . rle == None ) : continue
   if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
   if 72 - 72: OoO0O00 * Oo0Ooo - IiII
   if 74 - 74: Ii1I
   if 26 - 26: I11i . O0
   iIIiI11 = lisp_rloc ( )
   iIIiI11 . store_rloc_from_record ( oOiI111IIIiIii , None , I1I1i1I11I . mapping_source )
   if 68 - 68: Ii1I
   if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
   if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
   if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
   if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
   OOooooOoO00o0 = I1I1i1I11I . rloc_set [ 0 ] if ( I1I1i1I11I . rloc_set != [ ] ) else None
   if ( OOooooOoO00o0 != None ) :
    for i1iiIiiIiI11 in iIIiI11 . rle . rle_nodes :
     ii1ii11Iiii = OOooooOoO00o0 . get_rle ( i1iiIiiIiI11 . rloc . rloc )
     if ( ii1ii11Iiii == None ) : continue
     i1iiIiiIiI11 . rloc . uptime = ii1ii11Iiii . uptime
     i1iiIiiIiI11 . rloc . stats = copy . deepcopy ( ii1ii11Iiii . stats )
     i1iiIiiIiI11 . rloc . copy_rloc_probe_recents ( ii1ii11Iiii )
     if 14 - 14: OOooOOo % OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
     if 88 - 88: OoO0O00 % Ii1I
     if 12 - 12: OoooooooOO . O0
   if ( ii1Ii111i and iIIiI11 . is_rtr ( ) == False ) : continue
   if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
   I1I1i1I11I . rloc_set = [ iIIiI11 ]
   I1I1i1I11I . action = LISP_NO_ACTION
   I1I1i1I11I . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , I1I1i1I11I )
   if 34 - 34: i11iIiiIii / OoOoOO00
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( I1I1i1I11I . print_eid_tuple ( ) , False ) ,
   # oO0o + I1IiiI - I11i / I1IiiI + o0oOOo0O0Ooo % iIii1I11I1II1
 iIIiI11 . rle . print_rle ( False , True ) ) )
   if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
   if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
 return
 if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
 if 23 - 23: I1IiiI
 if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
 if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
 if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
 if 32 - 32: IiII
 if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
 if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 ooOOoo0o = lisp_map_notify ( "" )
 OO0Oo00OO0oo = ooOOoo0o . decode ( orig_packet )
 if ( OO0Oo00OO0oo == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 96 - 96: O0
  if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
 ooOOoo0o . print_notify ( )
 if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
 if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
 if 61 - 61: IiII . O0
 if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
 if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
 OOo0oOO0o0oo0 = source . print_address ( )
 if ( ooOOoo0o . alg_id != 0 or ooOOoo0o . auth_len != 0 ) :
  ii1iIIiIIi111 = None
  for OoOOooOOoo in lisp_map_servers_list :
   if ( OoOOooOOoo . find ( OOo0oOO0o0oo0 ) == - 1 ) : continue
   ii1iIIiIIi111 = lisp_map_servers_list [ OoOOooOOoo ]
   if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
  if ( ii1iIIiIIi111 == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( OOo0oOO0o0oo0 ) )
   if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
   return
   if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
   if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
  ii1iIIiIIi111 . map_notifies_received += 1
  if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
  oooOoooOO0o0 = lisp_verify_auth ( OO0Oo00OO0oo , ooOOoo0o . alg_id ,
 ooOOoo0o . auth_data , ii1iIIiIIi111 . password )
  if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if oooOoooOO0o0 else "failed" ) )
  if 86 - 86: OOooOOo / OoooooooOO - IiII
  if ( oooOoooOO0o0 == False ) : return
 else :
  ii1iIIiIIi111 = lisp_ms ( OOo0oOO0o0oo0 , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
  if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
  if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
  if 8 - 8: oO0o * iII111i * I11i
  if 30 - 30: I1Ii111
  if 61 - 61: iII111i
 O0Oo0O = ooOOoo0o . eid_records
 if ( ooOOoo0o . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , O0Oo0O , ooOOoo0o , ii1iIIiIIi111 )
  return
  if 50 - 50: Ii1I / I1IiiI . O0
  if 49 - 49: I1Ii111 . OoO0O00 % O0
  if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
  if 62 - 62: II111iiii + ooOoO0o + I1IiiI
  if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
  if 13 - 13: I1ii11iIi11i
  if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
  if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
 Oo0oOoooO = lisp_eid_record ( )
 OO0Oo00OO0oo = Oo0oOoooO . decode ( O0Oo0O )
 if ( OO0Oo00OO0oo == None ) : return
 if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 Oo0oOoooO . print_record ( "  " , False )
 if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
 for I11ii1IiI1Ii in range ( Oo0oOoooO . rloc_count ) :
  oOiI111IIIiIii = lisp_rloc_record ( )
  OO0Oo00OO0oo = oOiI111IIIiIii . decode ( OO0Oo00OO0oo , None )
  if ( OO0Oo00OO0oo == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 18 - 18: OoooooooOO - I1ii11iIi11i
  oOiI111IIIiIii . print_record ( "    " )
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  if 79 - 79: OOooOOo + Oo0Ooo
  if 33 - 33: iIii1I11I1II1
  if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
  if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
 if ( Oo0oOoooO . group . is_null ( ) == False ) :
  if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
  if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
  if 99 - 99: OOooOOo
  if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
  if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( Oo0oOoooO . print_eid_tuple ( ) , False ) ) )
  if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
  if 56 - 56: Oo0Ooo % I1ii11iIi11i
  ii1I11Iii = lisp_control_packet_ipc ( orig_packet , OOo0oOO0o0oo0 , "lisp-itr" , 0 )
  lisp_ipc ( ii1I11Iii , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 53 - 53: OoO0O00 . I11i - ooOoO0o
  if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
  if 74 - 74: oO0o . I1Ii111 . II111iiii
  if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
  if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
 lisp_send_map_notify_ack ( lisp_sockets , O0Oo0O , ooOOoo0o , ii1iIIiIIi111 )
 return
 if 41 - 41: iII111i * OoO0O00 - OoO0O00
 if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
 if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
 if 39 - 39: i1IIi
 if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
 if 59 - 59: i1IIi
 if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
 if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
def lisp_process_map_notify_ack ( packet , source ) :
 ooOOoo0o = lisp_map_notify ( "" )
 packet = ooOOoo0o . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
  if 71 - 71: OOooOOo
 ooOOoo0o . print_notify ( )
 if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
 if 73 - 73: iII111i / I1IiiI * ooOoO0o
 if 85 - 85: I11i + I11i + oO0o - OoOoOO00
 if 15 - 15: OoO0O00
 if 88 - 88: Ii1I % i1IIi / I1Ii111
 if ( ooOOoo0o . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 2 - 2: Ii1I . IiII % OoOoOO00
  if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
 Oo0oOoooO = lisp_eid_record ( )
 if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
 if ( Oo0oOoooO . decode ( ooOOoo0o . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 35 - 35: i11iIiiIii
 Oo0oOoooO . print_record ( "  " , False )
 if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
 oOOoo = Oo0oOoooO . print_eid_tuple ( )
 if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
 if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
 if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
 if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
 if ( ooOOoo0o . alg_id != LISP_NONE_ALG_ID and ooOOoo0o . auth_len != 0 ) :
  I1iOooO0o = lisp_sites_by_eid . lookup_cache ( Oo0oOoooO . eid , True )
  if ( I1iOooO0o == None ) :
   oOiiI1i11i1Ii = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( oOiiI1i11i1Ii , green ( oOOoo , False ) ) )
   if 12 - 12: i11iIiiIii / Ii1I + i1IIi
   return
   if 54 - 54: I1IiiI
  I11iII1 = I1iOooO0o . site
  if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
  if 37 - 37: Oo0Ooo
  if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
  if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
  I11iII1 . map_notify_acks_received += 1
  if 19 - 19: O0 * II111iiii * OoOoOO00
  IIIIIi1 = ooOOoo0o . key_id
  if ( IIIIIi1 in I11iII1 . auth_key ) :
   iiii = I11iII1 . auth_key [ IIIIIi1 ]
  else :
   iiii = ""
   if 53 - 53: Oo0Ooo
   if 16 - 16: Ii1I
  oooOoooOO0o0 = lisp_verify_auth ( packet , ooOOoo0o . alg_id ,
 ooOOoo0o . auth_data , iiii )
  if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
  IIIIIi1 = "key-id {}" . format ( IIIIIi1 ) if IIIIIi1 == ooOOoo0o . key_id else "bad key-id {}" . format ( ooOOoo0o . key_id )
  if 78 - 78: OoO0O00 + oO0o
  if 86 - 86: ooOoO0o . ooOoO0o + oO0o
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if oooOoooOO0o0 else "failed" , IIIIIi1 ) )
  if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
  if ( oooOoooOO0o0 == False ) : return
  if 31 - 31: IiII + iII111i
  if 5 - 5: O0 * Ii1I
  if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
  if 77 - 77: OOooOOo / OoooooooOO
  if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
 if ( ooOOoo0o . retransmit_timer ) : ooOOoo0o . retransmit_timer . cancel ( )
 if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
 IiIii11I1 = source . print_address ( )
 OoOOooOOoo = ooOOoo0o . nonce_key
 if 31 - 31: IiII / o0oOOo0O0Ooo
 if ( OoOOooOOoo in lisp_map_notify_queue ) :
  ooOOoo0o = lisp_map_notify_queue . pop ( OoOOooOOoo )
  if ( ooOOoo0o . retransmit_timer ) : ooOOoo0o . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( OoOOooOOoo ) )
  if 27 - 27: Oo0Ooo
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( ooOOoo0o . nonce_key , red ( IiIii11I1 , False ) ) )
  if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
  if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
 return
 if 81 - 81: I1ii11iIi11i - i11iIiiIii
 if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
 if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
 if 60 - 60: i11iIiiIii + IiII
 if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
 if 86 - 86: Ii1I / oO0o
 if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
 if 60 - 60: II111iiii / Ii1I
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
 if 66 - 66: OoooooooOO
 if 68 - 68: iII111i + I1Ii111
 if 90 - 90: o0oOOo0O0Ooo
 iIIi1Ii1 = False
 if ( group . is_null ( ) == False ) :
  iIIi1Ii1 = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 48 - 48: iII111i + Ii1I
 if ( iIIi1Ii1 == False ) :
  iIIi1Ii1 = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
 if ( iIIi1Ii1 ) :
  Ooo = lisp_print_eid_tuple ( eid , group )
  o000oOoo0 = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 20 - 20: OoO0O00 - I1IiiI % I1IiiI
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( Ooo , False ) , s ,
  # iII111i - o0oOOo0O0Ooo + i1IIi
 o000oOoo0 ) )
  if 29 - 29: iIii1I11I1II1
 return ( iIIi1Ii1 )
 if 51 - 51: I1IiiI / I1Ii111 - iIii1I11I1II1 . I1Ii111
 if 52 - 52: II111iiii / OoO0O00 . Ii1I
 if 68 - 68: iII111i
 if 67 - 67: I1IiiI * I1IiiI
 if 100 - 100: iII111i * iII111i . Oo0Ooo
 if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
 if 48 - 48: ooOoO0o + II111iiii
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 73 - 73: II111iiii
 OoO0o0OooO = lisp_map_referral ( )
 packet = OoO0o0OooO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
 OoO0o0OooO . print_map_referral ( )
 if 35 - 35: II111iiii + IiII
 OOo0oOO0o0oo0 = source . print_address ( )
 OOO0O0O = OoO0o0OooO . nonce
 if 66 - 66: o0oOOo0O0Ooo % IiII
 if 39 - 39: IiII
 if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
 if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
 for o000o0O0Oo00 in range ( OoO0o0OooO . record_count ) :
  Oo0oOoooO = lisp_eid_record ( )
  packet = Oo0oOoooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
  Oo0oOoooO . print_record ( "  " , True )
  if 62 - 62: O0
  if 52 - 52: OoooooooOO . oO0o
  if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
  if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
  OoOOooOOoo = str ( OOO0O0O )
  if ( OoOOooOOoo not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( OOO0O0O ) , OOo0oOO0o0oo0 ) )
   if 59 - 59: Ii1I
   if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
   continue
   if 6 - 6: i11iIiiIii . I11i - OoooooooOO
  oOoOO0oOo00Oo = lisp_ddt_map_requestQ [ OoOOooOOoo ]
  if ( oOoOO0oOo00Oo == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( OOO0O0O ) , OOo0oOO0o0oo0 ) )
   if 26 - 26: I1IiiI
   continue
   if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
   if 72 - 72: OoooooooOO * II111iiii + OoO0O00 % iIii1I11I1II1 . I1ii11iIi11i % OoooooooOO
   if 19 - 19: OoOoOO00 + I1Ii111
   if 19 - 19: I1ii11iIi11i / I1Ii111 + OoooooooOO - O0
   if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
   if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
  if ( lisp_map_referral_loop ( oOoOO0oOo00Oo , Oo0oOoooO . eid , Oo0oOoooO . group ,
 Oo0oOoooO . action , OOo0oOO0o0oo0 ) ) :
   oOoOO0oOo00Oo . dequeue_map_request ( )
   continue
   if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
   if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
  oOoOO0oOo00Oo . last_cached_prefix [ 0 ] = Oo0oOoooO . eid
  oOoOO0oOo00Oo . last_cached_prefix [ 1 ] = Oo0oOoooO . group
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
  if 38 - 38: IiII . I1Ii111
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
  if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
  o0o0Oo = False
  o00000oo = lisp_referral_cache_lookup ( Oo0oOoooO . eid , Oo0oOoooO . group ,
 True )
  if ( o00000oo == None ) :
   o0o0Oo = True
   o00000oo = lisp_referral ( )
   o00000oo . eid = Oo0oOoooO . eid
   o00000oo . group = Oo0oOoooO . group
   if ( Oo0oOoooO . ddt_incomplete == False ) : o00000oo . add_cache ( )
  elif ( o00000oo . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( o00000oo . print_eid_tuple ( ) , False ) ) )
   if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
   oOoOO0oOo00Oo . dequeue_map_request ( )
   continue
   if 11 - 11: iII111i
   if 60 - 60: I1ii11iIi11i / I1Ii111
  oOoO0OooO0O = Oo0oOoooO . action
  o00000oo . referral_source = source
  o00000oo . referral_type = oOoO0OooO0O
  i1i = Oo0oOoooO . store_ttl ( )
  o00000oo . referral_ttl = i1i
  o00000oo . expires = lisp_set_timestamp ( i1i )
  if 10 - 10: OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . OoOoOO00 / I1IiiI
  if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
  if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
  if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
  o0Ooo0OoOo = o00000oo . is_referral_negative ( )
  if ( OOo0oOO0o0oo0 in o00000oo . referral_set ) :
   Iii = o00000oo . referral_set [ OOo0oOO0o0oo0 ]
   if 71 - 71: II111iiii
   if ( Iii . updown == False and o0Ooo0OoOo == False ) :
    Iii . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( OOo0oOO0o0oo0 ) )
    if 34 - 34: I1ii11iIi11i * oO0o + OoooooooOO
   elif ( Iii . updown == True and o0Ooo0OoOo == True ) :
    Iii . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( OOo0oOO0o0oo0 ) )
    if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
    if 73 - 73: OOooOOo
    if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
    if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
    if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
    if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
    if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
    if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
  iiiiiIi = { }
  for OoOOooOOoo in o00000oo . referral_set : iiiiiIi [ OoOOooOOoo ] = None
  if 34 - 34: oO0o - Ii1I * o0oOOo0O0Ooo
  if 61 - 61: IiII * II111iiii / O0 . I1ii11iIi11i
  if 77 - 77: I1IiiI . IiII
  if 94 - 94: oO0o + Ii1I % IiII
  for o000o0O0Oo00 in range ( Oo0oOoooO . rloc_count ) :
   oOiI111IIIiIii = lisp_rloc_record ( )
   packet = oOiI111IIIiIii . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 11 - 11: II111iiii
   oOiI111IIIiIii . print_record ( "    " )
   if 66 - 66: I11i % iIii1I11I1II1 - ooOoO0o . II111iiii % O0 + I1IiiI
   if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
   if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
   if 73 - 73: II111iiii
   O00oO000Oo0 = oOiI111IIIiIii . rloc . print_address ( )
   if ( O00oO000Oo0 not in o00000oo . referral_set ) :
    Iii = lisp_referral_node ( )
    Iii . referral_address . copy_address ( oOiI111IIIiIii . rloc )
    o00000oo . referral_set [ O00oO000Oo0 ] = Iii
    if ( OOo0oOO0o0oo0 == O00oO000Oo0 and o0Ooo0OoOo ) : Iii . updown = False
   else :
    Iii = o00000oo . referral_set [ O00oO000Oo0 ]
    if ( O00oO000Oo0 in iiiiiIi ) : iiiiiIi . pop ( O00oO000Oo0 )
    if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
   Iii . priority = oOiI111IIIiIii . priority
   Iii . weight = oOiI111IIIiIii . weight
   if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
   if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
   if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
   if 44 - 44: iIii1I11I1II1 * iII111i
   if 32 - 32: OoOoOO00
  for OoOOooOOoo in iiiiiIi : o00000oo . referral_set . pop ( OoOOooOOoo )
  if 65 - 65: iIii1I11I1II1 + iII111i
  oOOoo = o00000oo . print_eid_tuple ( )
  if 90 - 90: i11iIiiIii - Oo0Ooo
  if ( o0o0Oo ) :
   if ( Oo0oOoooO . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( oOOoo , False ) ) )
    if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( oOOoo , False ) , Oo0oOoooO . rloc_count ) )
    if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
    if 45 - 45: OoooooooOO * I1Ii111
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( oOOoo , False ) , Oo0oOoooO . rloc_count ) )
   if 7 - 7: O0
   if 42 - 42: o0oOOo0O0Ooo / Ii1I
   if 31 - 31: OOooOOo
   if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
   if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
   if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
  if ( oOoO0OooO0O == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( oOoOO0oOo00Oo . lisp_sockets , o00000oo . eid ,
 o00000oo . group , oOoOO0oOo00Oo . nonce , oOoOO0oOo00Oo . itr , oOoOO0oOo00Oo . sport , 15 , None , False )
   oOoOO0oOo00Oo . dequeue_map_request ( )
   if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
   if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
  if ( oOoO0OooO0O == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( oOoOO0oOo00Oo . tried_root ) :
    lisp_send_negative_map_reply ( oOoOO0oOo00Oo . lisp_sockets , o00000oo . eid ,
 o00000oo . group , oOoOO0oOo00Oo . nonce , oOoOO0oOo00Oo . itr , oOoOO0oOo00Oo . sport , 0 , None , False )
    oOoOO0oOo00Oo . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( oOoOO0oOo00Oo , True )
    if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
    if 65 - 65: I1IiiI . ooOoO0o
    if 51 - 51: I1Ii111
  if ( oOoO0OooO0O == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( OOo0oOO0o0oo0 in o00000oo . referral_set ) :
    Iii = o00000oo . referral_set [ OOo0oOO0o0oo0 ]
    Iii . updown = False
    if 89 - 89: Oo0Ooo
   if ( len ( o00000oo . referral_set ) == 0 ) :
    oOoOO0oOo00Oo . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( oOoOO0oOo00Oo , False )
    if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
    if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
    if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
  if ( oOoO0OooO0O in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( oOoOO0oOo00Oo . eid . is_exact_match ( Oo0oOoooO . eid ) ) :
    if ( not oOoOO0oOo00Oo . tried_root ) :
     lisp_send_ddt_map_request ( oOoOO0oOo00Oo , True )
    else :
     lisp_send_negative_map_reply ( oOoOO0oOo00Oo . lisp_sockets ,
 o00000oo . eid , o00000oo . group , oOoOO0oOo00Oo . nonce , oOoOO0oOo00Oo . itr ,
 oOoOO0oOo00Oo . sport , 15 , None , False )
     oOoOO0oOo00Oo . dequeue_map_request ( )
     if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
   else :
    lisp_send_ddt_map_request ( oOoOO0oOo00Oo , False )
    if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
    if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
    if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
  if ( oOoO0OooO0O == LISP_DDT_ACTION_MS_ACK ) : oOoOO0oOo00Oo . dequeue_map_request ( )
  if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
 return
 if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
 if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
 if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
 if 58 - 58: O0 * OOooOOo
 if 60 - 60: ooOoO0o
 if 47 - 47: i11iIiiIii
 if 21 - 21: i1IIi - oO0o - Oo0Ooo
 if 11 - 11: i1IIi
def lisp_process_ecm ( lisp_sockets , packet , source , outer_sport ) :
 III1iI1III1I1 = lisp_ecm ( 0 )
 packet = III1iI1III1I1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
  if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
 III1iI1III1I1 . print_ecm ( )
 if 56 - 56: Ii1I . iII111i
 i111ii1II11ii = lisp_control_header ( )
 if ( i111ii1II11ii . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
  if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
 ooIiii = i111ii1II11ii . type
 del ( i111ii1II11ii )
 if 71 - 71: ooOoO0o
 if ( ooIiii != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 71 - 71: i1IIi - oO0o / ooOoO0o * Ii1I
  if 28 - 28: II111iiii . IiII / iII111i + I1ii11iIi11i - ooOoO0o * iIii1I11I1II1
  if 53 - 53: Ii1I - Ii1I . Oo0Ooo . OOooOOo / OoooooooOO + iII111i
  if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
  if 20 - 20: I1Ii111
 oooOO = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , III1iI1III1I1 . source , III1iI1III1I1 . udp_sport ,
 source , outer_sport , III1iI1III1I1 . ddt , - 1 , oooOO )
 return
 if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
 if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
 if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
 if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
 if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
 if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
 if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
 if 77 - 77: ooOoO0o + I1ii11iIi11i * o0oOOo0O0Ooo / i1IIi * I11i
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 70 - 70: oO0o / iII111i * i1IIi / II111iiii / OoOoOO00 + oO0o
 if 30 - 30: i1IIi - iII111i - i11iIiiIii . OoOoOO00 . o0oOOo0O0Ooo
 if 74 - 74: i11iIiiIii / II111iiii
 if 62 - 62: O0
 if 63 - 63: Oo0Ooo + Oo0Ooo
 if 48 - 48: Oo0Ooo * I1ii11iIi11i % II111iiii
 if 42 - 42: I1Ii111 - ooOoO0o % o0oOOo0O0Ooo * I1IiiI . o0oOOo0O0Ooo
 oOOo0OOoOO0 = ms . map_server
 if ( lisp_decent_push_configured and oOOo0OOoOO0 . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  oOOo0OOoOO0 = copy . deepcopy ( oOOo0OOoOO0 )
  oOOo0OOoOO0 . address = 0x7f000001
  iI11Ii111 = bold ( "Bootstrap" , False )
  II11iIIii = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( iI11Ii111 , II11iIIii ) )
  if 84 - 84: iIii1I11I1II1
  if 39 - 39: Ii1I . II111iiii / I1IiiI
  if 44 - 44: Ii1I / Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
  if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
  if 81 - 81: I1Ii111 % OoO0O00 / O0
  if 55 - 55: i1IIi - I1Ii111 + I11i
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
 if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
 if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
 if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
 if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
 if 24 - 24: Ii1I % II111iiii - i11iIiiIii
 if ( ms . ekey != None ) :
  i1ii1IIii = ms . ekey . zfill ( 32 )
  oO0o000oOO = "0" * 8
  OoO = chacha . ChaCha ( i1ii1IIii , oO0o000oOO , 20 ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + OoO
  oOO = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( oOO , ms . ekey_id ) )
  if 52 - 52: OoO0O00
  if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
 i11 = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  i11 = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 1 - 1: I1ii11iIi11i / i1IIi - II111iiii - OoOoOO00 . iII111i
  if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( oOOo0OOoOO0 . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , i11 ) )
 if 34 - 34: iII111i . OoOoOO00
 lisp_send ( lisp_sockets , oOOo0OOoOO0 , LISP_CTRL_PORT , packet )
 return
 if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
 if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
 if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
 if 89 - 89: I1IiiI % I11i - OOooOOo
 if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
 if 10 - 10: I1IiiI
 if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
 if 34 - 34: OoooooooOO / iII111i / O0
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 OO = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
 if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
 packet = lisp_control_packet_ipc ( packet , OO , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 40 - 40: OOooOOo - OoooooooOO
 if 36 - 36: i1IIi % OoOoOO00 - i1IIi
 if 5 - 5: I1IiiI . I1IiiI % II111iiii - I1Ii111
 if 97 - 97: I11i . ooOoO0o
 if 87 - 87: oO0o / iIii1I11I1II1 - I11i + OoooooooOO
 if 79 - 79: I1ii11iIi11i * IiII . I1ii11iIi11i
 if 65 - 65: iII111i - Ii1I - II111iiii * O0 + I1ii11iIi11i . iIii1I11I1II1
 if 76 - 76: OoO0O00 * ooOoO0o
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 32 - 32: O0 . oO0o * o0oOOo0O0Ooo . Ii1I + IiII
 if 98 - 98: iII111i . II111iiii % O0
 if 43 - 43: OOooOOo % I1Ii111 . IiII % OoO0O00 + I1Ii111 % OoooooooOO
 if 17 - 17: OoooooooOO - i1IIi * I11i
 if 33 - 33: i1IIi . Oo0Ooo + I11i
 if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
 if 78 - 78: I1Ii111 + I1Ii111
 if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 19 - 19: Ii1I
 if 51 - 51: oO0o
 if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
 if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
 if 70 - 70: I1ii11iIi11i . II111iiii
 if 54 - 54: OOooOOo
 if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
 if 63 - 63: OoOoOO00 - OoOoOO00
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
 if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
 if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
 if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
 if 14 - 14: IiII . I11i
 if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
 if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
  if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
 O00oO000Oo0 = outer_dest . print_address_no_iid ( )
 if 9 - 9: iIii1I11I1II1
 if 75 - 75: I11i . II111iiii * I1IiiI * IiII
 if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
 if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
 if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
 if ( lisp_nat_traversal ) :
  iIIo0OOO , iiI1iiIiiiI1I = lisp_get_translated_port_for_mr ( O00oO000Oo0 )
  if ( iiI1iiIiiiI1I != None ) : inner_sport = iiI1iiIiiiI1I
  if 62 - 62: O0
 III1iI1III1I1 = lisp_ecm ( inner_sport )
 if 40 - 40: OoOoOO00 - O0 / I1Ii111 + OoO0O00 + ooOoO0o
 III1iI1III1I1 . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 III1iI1III1I1 . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 III1iI1III1I1 . ddt = ddt
 OOoo0O0o = III1iI1III1I1 . encode ( packet , inner_source , inner_dest )
 if ( OOoo0O0o == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 15 - 15: iIii1I11I1II1 / I1ii11iIi11i * I1IiiI / i1IIi
 III1iI1III1I1 . print_ecm ( )
 if 57 - 57: o0oOOo0O0Ooo
 packet = OOoo0O0o + packet
 if 69 - 69: i11iIiiIii
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( O00oO000Oo0 ) )
 oOOo0OOoOO0 = lisp_convert_4to6 ( O00oO000Oo0 )
 lisp_send ( lisp_sockets , oOOo0OOoOO0 , LISP_CTRL_PORT , packet )
 return
 if 96 - 96: OOooOOo
 if 99 - 99: O0 - II111iiii + iII111i / I11i
 if 67 - 67: i1IIi
 if 1 - 1: OoOoOO00 * O0 + i11iIiiIii . ooOoO0o / OoO0O00
 if 48 - 48: o0oOOo0O0Ooo * II111iiii
 if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
 if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
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
if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 14 - 14: OOooOOo * IiII
if 15 - 15: o0oOOo0O0Ooo + OoooooooOO - OOooOOo - o0oOOo0O0Ooo . iIii1I11I1II1 / Ii1I
if 33 - 33: OoO0O00
if 91 - 91: I11i % I11i % iII111i
if 19 - 19: I11i / I11i + I1IiiI * OoO0O00 - iII111i . Oo0Ooo
if 76 - 76: iII111i % OOooOOo / OoooooooOO . I1IiiI % OoO0O00 % i1IIi
if 95 - 95: Oo0Ooo - O0 / I1ii11iIi11i . I1IiiI / o0oOOo0O0Ooo % OoOoOO00
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 38 - 38: OoOoOO00 % OoooooooOO . oO0o - OoooooooOO + I11i
if 18 - 18: OoooooooOO + ooOoO0o * OoOoOO00 - OoO0O00
if 42 - 42: oO0o % OoOoOO00 - oO0o + I11i / i11iIiiIii
if 74 - 74: OoO0O00 - II111iiii - ooOoO0o % i1IIi
if 42 - 42: i11iIiiIii / O0
if 8 - 8: I1Ii111
def byte_swap_64 ( address ) :
 iI1ii11Ii = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 51 - 51: i11iIiiIii
 if 1 - 1: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i
 if 58 - 58: i11iIiiIii * i11iIiiIii - OoO0O00
 if 8 - 8: i11iIiiIii * OoOoOO00 . o0oOOo0O0Ooo
 if 27 - 27: I1ii11iIi11i + Ii1I % I1Ii111
 if 20 - 20: Oo0Ooo
 if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
 if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
 return ( iI1ii11Ii )
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
 if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 % OoooooooOO
class lisp_cache_entries ( object ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
  if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
  if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
class lisp_cache ( object ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
  if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
 def cache_size ( self ) :
  return ( self . cache_count )
  if 87 - 87: iII111i
  if 86 - 86: IiII - I11i
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   O00O00O = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   O00O00O = prefix . mask_len
  else :
   O00O00O = prefix . mask_len + 48
   if 99 - 99: i1IIi + I1ii11iIi11i
   if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
  i1I1iI = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  Oooo0oOOOO = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    iI = prefix . addr_length ( ) * 2
    iI1ii11Ii = lisp_hex_string ( prefix . address ) . zfill ( iI )
   else :
    iI1ii11Ii = prefix . address
    if 44 - 44: II111iiii / I1ii11iIi11i
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   Oooo0oOOOO = "8003"
   iI1ii11Ii = prefix . address . print_geo ( )
  else :
   Oooo0oOOOO = ""
   iI1ii11Ii = ""
   if 39 - 39: OoooooooOO % OoO0O00
   if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
  OoOOooOOoo = i1I1iI + Oooo0oOOOO + iI1ii11Ii
  return ( [ O00O00O , OoOOooOOoo ] )
  if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
  if 29 - 29: IiII
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  O00O00O , OoOOooOOoo = self . build_key ( prefix )
  if ( O00O00O not in self . cache ) :
   self . cache [ O00O00O ] = lisp_cache_entries ( )
   self . cache_sorted = self . sort_in_entry ( self . cache_sorted , O00O00O )
   if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
  if ( OoOOooOOoo not in self . cache [ O00O00O ] . entries ) :
   self . cache_count += 1
   if 91 - 91: I1Ii111 * iII111i * OoO0O00
  self . cache [ O00O00O ] . entries [ OoOOooOOoo ] = entry
  if 79 - 79: iII111i + oO0o
  if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
 def lookup_cache ( self , prefix , exact ) :
  oooO , OoOOooOOoo = self . build_key ( prefix )
  if ( exact ) :
   if ( oooO not in self . cache ) : return ( None )
   if ( OoOOooOOoo not in self . cache [ oooO ] . entries ) : return ( None )
   return ( self . cache [ oooO ] . entries [ OoOOooOOoo ] )
   if 100 - 100: oO0o
   if 7 - 7: i11iIiiIii - O0
  iIi1iII = None
  for O00O00O in self . cache_sorted :
   if ( oooO < O00O00O ) : return ( iIi1iII )
   for iIiiI11II11i in list ( self . cache [ O00O00O ] . entries . values ( ) ) :
    if ( prefix . is_more_specific ( iIiiI11II11i . eid ) ) :
     if ( iIi1iII == None or
 iIiiI11II11i . eid . is_more_specific ( iIi1iII . eid ) ) : iIi1iII = iIiiI11II11i
     if 76 - 76: i1IIi . OOooOOo * iIii1I11I1II1 / I1ii11iIi11i % i11iIiiIii / O0
     if 83 - 83: oO0o % OoooooooOO
     if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
  return ( iIi1iII )
  if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
  if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
 def delete_cache ( self , prefix ) :
  O00O00O , OoOOooOOoo = self . build_key ( prefix )
  if ( O00O00O not in self . cache ) : return
  if ( OoOOooOOoo not in self . cache [ O00O00O ] . entries ) : return
  self . cache [ O00O00O ] . entries . pop ( OoOOooOOoo )
  self . cache_count -= 1
  if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
  if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
 def walk_cache ( self , function , parms ) :
  for O00O00O in self . cache_sorted :
   for iIiiI11II11i in list ( self . cache [ O00O00O ] . entries . values ( ) ) :
    oOOo0OOo00 , parms = function ( iIiiI11II11i , parms )
    if ( oOOo0OOo00 == False ) : return ( parms )
    if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
    if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
  return ( parms )
  if 66 - 66: iII111i + i1IIi
  if 24 - 24: O0 / OoooooooOO - OoOoOO00
 def sort_in_entry ( self , table , value ) :
  if ( table == [ ] ) : return ( [ value ] )
  if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
  IIiIIiiiiI = table
  while ( True ) :
   if ( len ( IIiIIiiiiI ) == 1 ) :
    if ( value == IIiIIiiiiI [ 0 ] ) : return ( table )
    o00O = table . index ( IIiIIiiiiI [ 0 ] )
    if ( value < IIiIIiiiiI [ 0 ] ) :
     return ( table [ 0 : o00O ] + [ value ] + table [ o00O : : ] )
     if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
    if ( value > IIiIIiiiiI [ 0 ] ) :
     return ( table [ 0 : o00O + 1 ] + [ value ] + table [ o00O + 1 : : ] )
     if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
     if 53 - 53: i11iIiiIii % I1ii11iIi11i
   o00O = old_div ( len ( IIiIIiiiiI ) , 2 )
   IIiIIiiiiI = IIiIIiiiiI [ 0 : o00O ] if ( value < IIiIIiiiiI [ o00O ] ) else IIiIIiiiiI [ o00O : : ]
   if 59 - 59: OOooOOo
   if 61 - 61: OoooooooOO + O0 - i1IIi % oO0o / I1ii11iIi11i
  return ( [ ] )
  if 50 - 50: oO0o + II111iiii * OoOoOO00 % OoO0O00 . II111iiii % o0oOOo0O0Ooo
  if 32 - 32: i1IIi / Ii1I + i11iIiiIii % oO0o
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 11 - 11: Ii1I - ooOoO0o % i11iIiiIii / OoooooooOO - O0 - IiII
  for O00O00O in self . cache_sorted :
   for OoOOooOOoo in self . cache [ O00O00O ] . entries :
    iIiiI11II11i = self . cache [ O00O00O ] . entries [ OoOOooOOoo ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( O00O00O , OoOOooOOoo ,
 iIiiI11II11i ) )
    if 25 - 25: IiII + O0 + oO0o % iIii1I11I1II1 - II111iiii . I1IiiI
    if 62 - 62: IiII . O0 + oO0o - ooOoO0o * iIii1I11I1II1
    if 8 - 8: I1ii11iIi11i
    if 65 - 65: i11iIiiIii
    if 92 - 92: oO0o * II111iiii + I1Ii111
    if 49 - 49: II111iiii * I1IiiI * O0 / ooOoO0o * IiII
    if 94 - 94: OoO0O00 - I1IiiI * oO0o
    if 35 - 35: OOooOOo / i1IIi + OoO0O00
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 31 - 31: OoO0O00 . i1IIi / OoooooooOO
if 81 - 81: ooOoO0o . Oo0Ooo . OoOoOO00 + OOooOOo % iII111i - oO0o
if 68 - 68: iII111i - O0 / Ii1I
if 15 - 15: I1Ii111 / I1ii11iIi11i / I1IiiI % i11iIiiIii + II111iiii . ooOoO0o
if 74 - 74: o0oOOo0O0Ooo
if 4 - 4: I1ii11iIi11i * II111iiii - Oo0Ooo % i1IIi % O0 * i11iIiiIii
if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
def lisp_map_cache_lookup ( source , dest ) :
 if 27 - 27: oO0o . iII111i . oO0o
 iii = dest . is_multicast_address ( )
 if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
 if 14 - 14: I11i + ooOoO0o . oO0o * I11i
 if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
 if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
 I1I1i1I11I = lisp_map_cache . lookup_cache ( dest , False )
 if ( I1I1i1I11I == None ) :
  oOOoo = source . print_sg ( dest ) if iii else dest . print_address ( )
  oOOoo = green ( oOOoo , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oOOoo ) )
  return ( None )
  if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
  if 33 - 33: I11i
  if 37 - 37: Oo0Ooo
  if 36 - 36: IiII % I11i
  if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
 if ( iii == False ) :
  i1IiI = green ( I1I1i1I11I . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , i1IiI ) )
  if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
  return ( I1I1i1I11I )
  if 82 - 82: OoooooooOO
  if 14 - 14: OoO0O00 / oO0o - OOooOOo
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
  if 16 - 16: IiII + Oo0Ooo % I11i
  if 16 - 16: ooOoO0o / I1Ii111
 I1I1i1I11I = I1I1i1I11I . lookup_source_cache ( source , False )
 if ( I1I1i1I11I == None ) :
  oOOoo = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oOOoo ) )
  return ( None )
  if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
  if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
  if 54 - 54: iIii1I11I1II1 % ooOoO0o
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
 i1IiI = green ( I1I1i1I11I . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , i1IiI ) )
 if 3 - 3: OoO0O00 % iIii1I11I1II1
 return ( I1I1i1I11I )
 if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
 if 59 - 59: iIii1I11I1II1
 if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
 if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
 if 63 - 63: I11i
 if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
 if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  oO00oOOOo = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( oO00oOOOo )
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
  if 44 - 44: OoooooooOO
  if 18 - 18: i11iIiiIii
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
  if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
 if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
 if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
 if 53 - 53: OOooOOo % ooOoO0o
 if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
 if 83 - 83: OOooOOo * I1ii11iIi11i * iII111i * I1ii11iIi11i . OoO0O00
 oO00oOOOo = lisp_referral_cache . lookup_cache ( group , exact )
 if ( oO00oOOOo == None ) : return ( None )
 if 87 - 87: ooOoO0o . O0 - oO0o
 oo00Oo = oO00oOOOo . lookup_source_cache ( eid , exact )
 if ( oo00Oo ) : return ( oo00Oo )
 if 94 - 94: ooOoO0o / Ii1I
 if ( exact ) : oO00oOOOo = None
 return ( oO00oOOOo )
 if 9 - 9: I1Ii111 * oO0o
 if 44 - 44: ooOoO0o * oO0o
 if 67 - 67: iIii1I11I1II1 . iIii1I11I1II1 + iIii1I11I1II1 * iII111i
 if 70 - 70: I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
 if 12 - 12: Oo0Ooo + I1IiiI
 if 12 - 12: OoOoOO00 / II111iiii
 if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  IIIiiiIi = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( IIIiiiIi )
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
 IIIiiiIi = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( IIIiiiIi == None ) : return ( None )
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
 i11OO = IIIiiiIi . lookup_source_cache ( eid , exact )
 if ( i11OO ) : return ( i11OO )
 if 22 - 22: Oo0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i
 if ( exact ) : IIIiiiIi = None
 return ( IIIiiiIi )
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
  I1iOooO0o = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( I1iOooO0o )
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
 I1iOooO0o = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( I1iOooO0o == None ) : return ( None )
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
 IIiIiiI1Iii = I1iOooO0o . lookup_source_cache ( eid , exact )
 if ( IIiIiiI1Iii ) : return ( IIiIiiI1Iii )
 if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
 if ( exact ) :
  I1iOooO0o = None
 else :
  OO0ooOo0o = I1iOooO0o . parent_for_more_specifics
  if ( OO0ooOo0o and OO0ooOo0o . accept_more_specifics ) :
   if ( group . is_more_specific ( OO0ooOo0o . group ) ) : I1iOooO0o = OO0ooOo0o
   if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
   if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
 return ( I1iOooO0o )
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
  iI1ii11Ii = self . address
  if ( ( ( iI1ii11Ii & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( iI1ii11Ii & 0xff000000 ) >> 24 ) == 172 ) :
   o0oO00ooo0o = ( iI1ii11Ii & 0x00ff0000 ) >> 16
   if ( o0oO00ooo0o >= 16 and o0oO00ooo0o <= 31 ) : return ( True )
   if 26 - 26: iII111i . i1IIi * OoOoOO00 + I1Ii111 . IiII % i11iIiiIii
  if ( ( ( iI1ii11Ii & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
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
  iI1ii11Ii = self . address >> 96
  return ( iI1ii11Ii == 0x20010005 )
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
  Iii1iIII1Iii = self . packet_format ( )
  OO0Oo00OO0oo = b""
  if ( self . is_ipv4 ( ) ) :
   OO0Oo00OO0oo = struct . pack ( Iii1iIII1Iii , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   III = byte_swap_64 ( self . address >> 64 )
   I1I = byte_swap_64 ( self . address & 0xffffffffffffffff )
   OO0Oo00OO0oo = struct . pack ( Iii1iIII1Iii , III , I1I )
  elif ( self . is_mac ( ) ) :
   iI1ii11Ii = self . address
   III = ( iI1ii11Ii >> 32 ) & 0xffff
   I1I = ( iI1ii11Ii >> 16 ) & 0xffff
   OOo00o0o = iI1ii11Ii & 0xffff
   OO0Oo00OO0oo = struct . pack ( Iii1iIII1Iii , III , I1I , OOo00o0o )
  elif ( self . is_e164 ( ) ) :
   iI1ii11Ii = self . address
   III = ( iI1ii11Ii >> 32 ) & 0xffffffff
   I1I = ( iI1ii11Ii & 0xffffffff )
   OO0Oo00OO0oo = struct . pack ( Iii1iIII1Iii , III , I1I )
  elif ( self . is_dist_name ( ) ) :
   OO0Oo00OO0oo += ( self . address + "\0" ) . encode ( )
   if 74 - 74: I1Ii111 - i11iIiiIii * OoooooooOO
  return ( OO0Oo00OO0oo )
  if 90 - 90: i1IIi
  if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
 def unpack_address ( self , packet ) :
  Iii1iIII1Iii = self . packet_format ( )
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 38 - 38: II111iiii % iIii1I11I1II1 * IiII * OoOoOO00 % II111iiii . I1IiiI
  iI1ii11Ii = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 35 - 35: OoooooooOO - i11iIiiIii * i11iIiiIii % Ii1I - OOooOOo . iIii1I11I1II1
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( iI1ii11Ii [ 0 ] )
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
   if ( iI1ii11Ii [ 0 ] <= 0xffff and ( iI1ii11Ii [ 0 ] & 0xff ) == 0 ) :
    O00ooO0OoOO0O = ( iI1ii11Ii [ 0 ] << 48 ) << 64
   else :
    O00ooO0OoOO0O = byte_swap_64 ( iI1ii11Ii [ 0 ] ) << 64
    if 53 - 53: II111iiii + I11i / IiII % OoO0O00 * i11iIiiIii
   O0II11II1111 = byte_swap_64 ( iI1ii11Ii [ 1 ] )
   self . address = O00ooO0OoOO0O | O0II11II1111
   if 32 - 32: I1IiiI / i1IIi / I1ii11iIi11i % i1IIi . ooOoO0o % I1ii11iIi11i
  elif ( self . is_mac ( ) ) :
   OOO00o00o = iI1ii11Ii [ 0 ]
   OOoO00O = iI1ii11Ii [ 1 ]
   IiiIi1ii111 = iI1ii11Ii [ 2 ]
   self . address = ( OOO00o00o << 32 ) + ( OOoO00O << 16 ) + IiiIi1ii111
   if 7 - 7: I1IiiI - OoOoOO00 + II111iiii
  elif ( self . is_e164 ( ) ) :
   self . address = ( iI1ii11Ii [ 0 ] << 32 ) + iI1ii11Ii [ 1 ]
   if 25 - 25: IiII
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   oOoOo000Ooooo = 0
   if 46 - 46: OOooOOo / Ii1I
  packet = packet [ oOoOo000Ooooo : : ]
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
  o000o0O0Oo00 = addr_str . find ( "[" )
  I11ii1IiI1Ii = addr_str . find ( "]" )
  if ( o000o0O0Oo00 != - 1 and I11ii1IiI1Ii != - 1 ) :
   self . instance_id = int ( addr_str [ o000o0O0Oo00 + 1 : I11ii1IiI1Ii ] )
   addr_str = addr_str [ I11ii1IiI1Ii + 1 : : ]
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
   oO00o = int ( ii1III1IiIII1 [ 0 ] ) << 24
   oO00o += int ( ii1III1IiIII1 [ 1 ] ) << 16
   oO00o += int ( ii1III1IiIII1 [ 2 ] ) << 8
   oO00o += int ( ii1III1IiIII1 [ 3 ] )
   self . address = oO00o
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
   o0o0OoOo000O = lisp_geo ( None )
   o0o0OoOo000O . name = "geo-prefix-{}" . format ( o0o0OoOo000O )
   o0o0OoOo000O . parse_geo_string ( addr_str )
   self . address = o0o0OoOo000O
  elif ( self . is_mac ( ) ) :
   addr_str = addr_str . replace ( "-" , "" )
   oO00o = int ( addr_str , 16 )
   self . address = oO00o
  elif ( self . is_e164 ( ) ) :
   addr_str = addr_str [ 1 : : ]
   oO00o = int ( addr_str , 16 )
   self . address = oO00o << 4
  elif ( self . is_dist_name ( ) ) :
   self . address = addr_str . replace ( "'" , "" )
   if 64 - 64: i1IIi * II111iiii + I1ii11iIi11i + OOooOOo % I1ii11iIi11i - OoooooooOO
  self . mask_len = self . host_mask_len ( )
  if 96 - 96: IiII + oO0o / Oo0Ooo + OoooooooOO
  if 53 - 53: Ii1I * IiII + Oo0Ooo + i11iIiiIii - iIii1I11I1II1
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   o00O = prefix_str . find ( "]" )
   OOOoOo0o0Ooo = len ( prefix_str [ o00O + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , OOOoOo0o0Ooo = prefix_str . split ( "/" )
  else :
   oO0OO00OOo0 = prefix_str . find ( "'" )
   if ( oO0OO00OOo0 == - 1 ) : return
   iI1i = prefix_str . find ( "'" , oO0OO00OOo0 + 1 )
   if ( iI1i == - 1 ) : return
   OOOoOo0o0Ooo = len ( prefix_str [ oO0OO00OOo0 + 1 : iI1i ] ) * 8
   if 66 - 66: O0 - I1ii11iIi11i * iIii1I11I1II1 - I1Ii111 / I1ii11iIi11i
   if 24 - 24: Ii1I
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( OOOoOo0o0Ooo )
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
  o00O = addr_str . find ( "]" )
  if ( o00O != - 1 ) : addr_str = addr_str [ o00O + 1 : : ]
  if 6 - 6: II111iiii / OoOoOO00 % ooOoO0o . i1IIi + I11i
  o0o0OoOo000O = addr_str . split ( "/" )
  if ( len ( o0o0OoOo000O ) == 2 ) :
   if ( o0o0OoOo000O [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 63 - 63: OoO0O00 % i11iIiiIii - iII111i * o0oOOo0O0Ooo / OoOoOO00
  o0o0OoOo000O = o0o0OoOo000O [ 0 ]
  o0o0OoOo000O = o0o0OoOo000O . split ( "-" )
  o0000OO0 = len ( o0o0OoOo000O )
  if ( o0000OO0 < 8 or o0000OO0 > 9 ) : return ( False )
  if 89 - 89: IiII
  for ooooo0O in range ( 0 , o0000OO0 ) :
   if ( ooooo0O == 3 ) :
    if ( o0o0OoOo000O [ ooooo0O ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 47 - 47: I1IiiI / o0oOOo0O0Ooo
   if ( ooooo0O == 7 ) :
    if ( o0o0OoOo000O [ ooooo0O ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 47 - 47: i1IIi / Oo0Ooo % IiII % OoO0O00 + Ii1I
   if ( o0o0OoOo000O [ ooooo0O ] . isdigit ( ) == False ) : return ( False )
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
  iI1ii11Ii = self . print_address_no_iid ( )
  i1I1iI = "[" + str ( self . instance_id )
  for o000o0O0Oo00 in self . iid_list : i1I1iI += "," + str ( o000o0O0Oo00 )
  i1I1iI += "]"
  iI1ii11Ii = "{}{}" . format ( i1I1iI , iI1ii11Ii )
  return ( iI1ii11Ii )
  if 6 - 6: ooOoO0o + OOooOOo - I1IiiI + OOooOOo
  if 16 - 16: OoO0O00 * OoOoOO00 - Oo0Ooo
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   iI1ii11Ii = self . address
   I1III = iI1ii11Ii >> 24
   iiIIIii1iII = ( iI1ii11Ii >> 16 ) & 0xff
   oooOoo00 = ( iI1ii11Ii >> 8 ) & 0xff
   OOOoooo = iI1ii11Ii & 0xff
   return ( "{}.{}.{}.{}" . format ( I1III , iiIIIii1iII , oooOoo00 , OOOoooo ) )
  elif ( self . is_ipv6 ( ) ) :
   O00oO000Oo0 = lisp_hex_string ( self . address ) . zfill ( 32 )
   O00oO000Oo0 = binascii . unhexlify ( O00oO000Oo0 )
   O00oO000Oo0 = socket . inet_ntop ( socket . AF_INET6 , O00oO000Oo0 )
   return ( "{}" . format ( O00oO000Oo0 ) )
  elif ( self . is_geo_prefix ( ) ) :
   return ( "{}" . format ( self . address . print_geo ( ) ) )
  elif ( self . is_mac ( ) ) :
   O00oO000Oo0 = lisp_hex_string ( self . address ) . zfill ( 12 )
   O00oO000Oo0 = "{}-{}-{}" . format ( O00oO000Oo0 [ 0 : 4 ] , O00oO000Oo0 [ 4 : 8 ] ,
 O00oO000Oo0 [ 8 : 12 ] )
   return ( "{}" . format ( O00oO000Oo0 ) )
  elif ( self . is_e164 ( ) ) :
   O00oO000Oo0 = lisp_hex_string ( self . address ) . zfill ( 15 )
   return ( "+{}" . format ( O00oO000Oo0 ) )
  elif ( self . is_dist_name ( ) ) :
   return ( "'{}'" . format ( self . address ) )
  elif ( self . is_null ( ) ) :
   return ( "no-address" )
   if 39 - 39: Ii1I + I1Ii111 * Oo0Ooo + OoOoOO00 / I1Ii111 - ooOoO0o
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 66 - 66: I11i * OoO0O00
  if 98 - 98: IiII . Oo0Ooo + I1Ii111
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   oO0OOOOOO0000 = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , oO0OOOOOO0000 ) )
   if 94 - 94: OOooOOo % I1IiiI * I1Ii111 * I11i - OoOoOO00 + iIii1I11I1II1
  iI1ii11Ii = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( iI1ii11Ii )
  if ( self . is_geo_prefix ( ) ) : return ( iI1ii11Ii )
  if 3 - 3: O0 / I1Ii111
  o00O = iI1ii11Ii . find ( "no-address" )
  if ( o00O == - 1 ) :
   iI1ii11Ii = "{}/{}" . format ( iI1ii11Ii , str ( self . mask_len ) )
  else :
   iI1ii11Ii = iI1ii11Ii [ 0 : o00O ]
   if 35 - 35: O0 + II111iiii + o0oOOo0O0Ooo - OoO0O00 - Ii1I
  return ( iI1ii11Ii )
  if 88 - 88: I1ii11iIi11i . O0 - o0oOOo0O0Ooo . I1ii11iIi11i * iII111i * I11i
  if 89 - 89: Oo0Ooo - oO0o + O0 / i11iIiiIii
 def print_prefix_no_iid ( self ) :
  iI1ii11Ii = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( iI1ii11Ii )
  if ( self . is_geo_prefix ( ) ) : return ( iI1ii11Ii )
  return ( "{}/{}" . format ( iI1ii11Ii , str ( self . mask_len ) ) )
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  iI1ii11Ii = self . print_address ( )
  o00O = iI1ii11Ii . find ( "]" )
  if ( o00O != - 1 ) : iI1ii11Ii = iI1ii11Ii [ o00O + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   iI1ii11Ii = iI1ii11Ii . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , iI1ii11Ii ) )
   if 4 - 4: i1IIi + OoOoOO00 + iIii1I11I1II1 - i1IIi * i11iIiiIii
  return ( "{}-{}-{}" . format ( self . instance_id , iI1ii11Ii , self . mask_len ) )
  if 99 - 99: I1ii11iIi11i - O0 % II111iiii + ooOoO0o % OoO0O00 * Ii1I
  if 8 - 8: OOooOOo
 def print_sg ( self , g ) :
  OOo0oOO0o0oo0 = self . print_prefix ( )
  ooo0000OOO0 = OOo0oOO0o0oo0 . find ( "]" ) + 1
  g = g . print_prefix ( )
  i1IiIi1i1Ii = g . find ( "]" ) + 1
  III1II1i = "[{}]({}, {})" . format ( self . instance_id , OOo0oOO0o0oo0 [ ooo0000OOO0 : : ] , g [ i1IiIi1i1Ii : : ] )
  return ( III1II1i )
  if 83 - 83: iII111i - I1Ii111
  if 28 - 28: IiII
 def hash_address ( self , addr ) :
  III = self . address
  I1I = addr . address
  if 42 - 42: oO0o + Oo0Ooo * I1ii11iIi11i . o0oOOo0O0Ooo / iIii1I11I1II1
  if ( self . is_geo_prefix ( ) ) : III = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : I1I = addr . address . print_geo ( )
  if 9 - 9: I1Ii111 * II111iiii % Ii1I - Ii1I % OoO0O00 % o0oOOo0O0Ooo
  if ( type ( III ) == str ) :
   III = int ( binascii . hexlify ( III [ 0 : 1 ] ) )
   if 26 - 26: o0oOOo0O0Ooo - I1IiiI / OoooooooOO / ooOoO0o % iIii1I11I1II1 % I1ii11iIi11i
  if ( type ( I1I ) == str ) :
   I1I = int ( binascii . hexlify ( I1I [ 0 : 1 ] ) )
   if 6 - 6: iIii1I11I1II1 * I1ii11iIi11i / I11i % I1Ii111 / Oo0Ooo
  return ( III ^ I1I )
  if 94 - 94: OoO0O00 - oO0o + iII111i . ooOoO0o * OoooooooOO
  if 42 - 42: iII111i / i11iIiiIii + II111iiii % IiII / ooOoO0o
  if 100 - 100: ooOoO0o / I1IiiI
  if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
  if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
  if 64 - 64: i1IIi
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
  OOOoOo0o0Ooo = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   O0ooOo0o0oo0O = 2 ** ( 32 - OOOoOo0o0Ooo )
   i1IiiiIIIIIi1 = prefix . instance_id
   oO0OOOOOO0000 = i1IiiiIIIIIi1 + O0ooOo0o0oo0O
   return ( self . instance_id in range ( i1IiiiIIIIIi1 , oO0OOOOOO0000 ) )
   if 41 - 41: oO0o + O0 / I1ii11iIi11i
   if 55 - 55: iIii1I11I1II1 * oO0o / iII111i / i1IIi % Oo0Ooo . OoOoOO00
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 50 - 50: IiII / o0oOOo0O0Ooo
   if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
   if 52 - 52: O0
   if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
   if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   iI1ii11Ii = self . address
   O0O0Ooo0O0ooO = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    iI1ii11Ii = self . address . print_geo ( )
    O0O0Ooo0O0ooO = prefix . address . print_geo ( )
    if 43 - 43: o0oOOo0O0Ooo + OoooooooOO
   if ( len ( iI1ii11Ii ) < len ( O0O0Ooo0O0ooO ) ) : return ( False )
   return ( iI1ii11Ii . find ( O0O0Ooo0O0ooO ) == 0 )
   if 96 - 96: iII111i . II111iiii
   if 41 - 41: OoO0O00 + Oo0Ooo % Ii1I
   if 9 - 9: OOooOOo * i1IIi
   if 93 - 93: OoOoOO00 / I1ii11iIi11i
   if 39 - 39: o0oOOo0O0Ooo % OOooOOo . iIii1I11I1II1 * I1ii11iIi11i / I1Ii111
  if ( self . mask_len < OOOoOo0o0Ooo ) : return ( False )
  if 96 - 96: OOooOOo - o0oOOo0O0Ooo - Ii1I / Oo0Ooo . OOooOOo
  ii1oOOOo = ( prefix . addr_length ( ) * 8 ) - OOOoOo0o0Ooo
  iiiIiIIIi1I = ( 2 ** OOOoOo0o0Ooo - 1 ) << ii1oOOOo
  return ( ( self . address & iiiIiIIIi1I ) == prefix . address )
  if 43 - 43: II111iiii * o0oOOo0O0Ooo % o0oOOo0O0Ooo + iIii1I11I1II1 + OoOoOO00
  if 54 - 54: II111iiii + OOooOOo * Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
 def mask_address ( self , mask_len ) :
  ii1oOOOo = ( self . addr_length ( ) * 8 ) - mask_len
  iiiIiIIIi1I = ( 2 ** mask_len - 1 ) << ii1oOOOo
  self . address &= iiiIiIIIi1I
  if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
  if 81 - 81: I11i - o0oOOo0O0Ooo % Ii1I / I1Ii111 * II111iiii
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  iIi = self . print_prefix ( )
  IIi11I1iIIii = prefix . print_prefix ( ) if prefix else ""
  return ( iIi == IIi11I1iIIii )
  if 46 - 46: I1ii11iIi11i * ooOoO0o
  if 4 - 4: I1Ii111 * II111iiii
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   I1II1I11Ii1i = lisp_myrlocs [ 0 ]
   if ( I1II1I11Ii1i == None ) : return ( False )
   I1II1I11Ii1i = I1II1I11Ii1i . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == I1II1I11Ii1i )
   if 66 - 66: O0
  if ( self . is_ipv6 ( ) ) :
   I1II1I11Ii1i = lisp_myrlocs [ 1 ]
   if ( I1II1I11Ii1i == None ) : return ( False )
   I1II1I11Ii1i = I1II1I11Ii1i . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == I1II1I11Ii1i )
   if 56 - 56: II111iiii * iIii1I11I1II1 % I1ii11iIi11i
  return ( False )
  if 83 - 83: i1IIi . i11iIiiIii / iII111i
  if 28 - 28: i1IIi - iII111i + o0oOOo0O0Ooo / Oo0Ooo * oO0o
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 8 - 8: ooOoO0o + OOooOOo * ooOoO0o / i1IIi . I1ii11iIi11i
  self . instance_id = iid
  self . mask_len = mask_len
  if 4 - 4: Ii1I - Oo0Ooo . i1IIi + iIii1I11I1II1
  if 28 - 28: O0 / ooOoO0o / IiII - I11i + IiII + OoO0O00
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
  if 58 - 58: I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
  if 24 - 24: I11i + I11i % I11i
  if 63 - 63: i11iIiiIii + iIii1I11I1II1 / oO0o % IiII - O0
  if 21 - 21: II111iiii
 def lcaf_encode_iid ( self ) :
  o000O0OOo00O = LISP_LCAF_INSTANCE_ID_TYPE
  ooOOO000O = socket . htons ( self . lcaf_length ( o000O0OOo00O ) )
  i1I1iI = self . instance_id
  Oooo0oOOOO = self . afi
  O00O00O = 0
  if ( Oooo0oOOOO < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    Oooo0oOOOO = LISP_AFI_LCAF
    O00O00O = 0
   else :
    Oooo0oOOOO = 0
    O00O00O = self . mask_len
    if 89 - 89: OOooOOo % i11iIiiIii * OoOoOO00 % oO0o / O0 * i1IIi
    if 16 - 16: IiII
    if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
  I1iiiiII11 = struct . pack ( "BBBBH" , 0 , 0 , o000O0OOo00O , O00O00O , ooOOO000O )
  I1iiiiII11 += struct . pack ( "IH" , socket . htonl ( i1I1iI ) , socket . htons ( Oooo0oOOOO ) )
  if ( Oooo0oOOOO == 0 ) : return ( I1iiiiII11 )
  if 95 - 95: I1Ii111 / OOooOOo / O0
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   I1iiiiII11 = I1iiiiII11 [ 0 : - 2 ]
   I1iiiiII11 += self . address . encode_geo ( )
   return ( I1iiiiII11 )
   if 29 - 29: O0 * I1IiiI % iIii1I11I1II1
   if 12 - 12: Oo0Ooo
  I1iiiiII11 += self . pack_address ( )
  return ( I1iiiiII11 )
  if 96 - 96: OoooooooOO - Ii1I * I1Ii111 / O0
  if 63 - 63: I1Ii111 - OOooOOo + i1IIi * i11iIiiIii - I1Ii111
 def lcaf_decode_iid ( self , packet ) :
  Iii1iIII1Iii = "BBBBH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 4 - 4: o0oOOo0O0Ooo - i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
  Oo0OoO00O , OOo00 , o000O0OOo00O , O0O0o , iI = struct . unpack ( Iii1iIII1Iii ,
 packet [ : oOoOo000Ooooo ] )
  packet = packet [ oOoOo000Ooooo : : ]
  if 90 - 90: o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if ( o000O0OOo00O != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 31 - 31: I1IiiI / iIii1I11I1II1 + I1IiiI - o0oOOo0O0Ooo % OoOoOO00 - OoOoOO00
  Iii1iIII1Iii = "IH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
  if 16 - 16: oO0o - oO0o . I1Ii111 + I1ii11iIi11i
  i1I1iI , Oooo0oOOOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  packet = packet [ oOoOo000Ooooo : : ]
  if 10 - 10: I1ii11iIi11i / Ii1I
  iI = socket . ntohs ( iI )
  self . instance_id = socket . ntohl ( i1I1iI )
  Oooo0oOOOO = socket . ntohs ( Oooo0oOOOO )
  self . afi = Oooo0oOOOO
  if ( O0O0o != 0 and Oooo0oOOOO == 0 ) : self . mask_len = O0O0o
  if ( Oooo0oOOOO == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if O0O0o else LISP_AFI_ULTIMATE_ROOT
   if 71 - 71: ooOoO0o * I1Ii111
   if 3 - 3: IiII . i11iIiiIii . Oo0Ooo - I1Ii111 . Ii1I
   if 43 - 43: O0 / Ii1I - OoO0O00 + OOooOOo
   if 54 - 54: I1Ii111 % OoO0O00 - OoooooooOO
   if 96 - 96: IiII
  if ( Oooo0oOOOO == 0 ) : return ( packet )
  if 31 - 31: Ii1I + O0 - OOooOOo * O0 * I11i
  if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
  if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
  if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 13 - 13: II111iiii
   if 22 - 22: o0oOOo0O0Ooo
   if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
   if 12 - 12: I1ii11iIi11i / O0
   if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
  if ( Oooo0oOOOO == LISP_AFI_LCAF ) :
   Iii1iIII1Iii = "BBBBH"
   oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
   if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
   if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
   Ii1Ii1Ii , Ooo0000o , o000O0OOo00O , ii11Ii1111 , IIIi1I = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
   if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
   if 16 - 16: I1IiiI + I11i
   if ( o000O0OOo00O != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
   IIIi1I = socket . ntohs ( IIIi1I )
   packet = packet [ oOoOo000Ooooo : : ]
   if ( IIIi1I > len ( packet ) ) : return ( None )
   if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
   o0o0OoOo000O = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = o0o0OoOo000O
   packet = o0o0OoOo000O . decode_geo ( packet , IIIi1I , ii11Ii1111 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
   if 78 - 78: i1IIi / ooOoO0o / oO0o
  ooOOO000O = self . addr_length ( )
  if ( len ( packet ) < ooOOO000O ) : return ( None )
  if 21 - 21: IiII % Ii1I + OOooOOo + IiII
  packet = self . unpack_address ( packet )
  return ( packet )
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
  if 24 - 24: II111iiii / I1ii11iIi11i + oO0o / Ii1I + IiII % oO0o
  if 86 - 86: I1IiiI
  if 83 - 83: I11i % Ii1I + IiII % I11i / i1IIi . oO0o
  if 56 - 56: I1Ii111 - OOooOOo % o0oOOo0O0Ooo
  if 30 - 30: I1Ii111 % i1IIi
  if 98 - 98: oO0o . i11iIiiIii / Ii1I - Ii1I
  if 23 - 23: iIii1I11I1II1
 def lcaf_encode_sg ( self , group ) :
  o000O0OOo00O = LISP_LCAF_MCAST_INFO_TYPE
  i1I1iI = socket . htonl ( self . instance_id )
  ooOOO000O = socket . htons ( self . lcaf_length ( o000O0OOo00O ) )
  I1iiiiII11 = struct . pack ( "BBBBHIHBB" , 0 , 0 , o000O0OOo00O , 0 , ooOOO000O , i1I1iI ,
 0 , self . mask_len , group . mask_len )
  if 30 - 30: I1ii11iIi11i + OoO0O00 - O0
  I1iiiiII11 += struct . pack ( "H" , socket . htons ( self . afi ) )
  I1iiiiII11 += self . pack_address ( )
  I1iiiiII11 += struct . pack ( "H" , socket . htons ( group . afi ) )
  I1iiiiII11 += group . pack_address ( )
  return ( I1iiiiII11 )
  if 42 - 42: I11i - I1Ii111
  if 24 - 24: i1IIi
 def lcaf_decode_sg ( self , packet ) :
  Iii1iIII1Iii = "BBBBHIHBB"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  if 93 - 93: OoOoOO00 - Oo0Ooo + iIii1I11I1II1 % iIii1I11I1II1 / I1ii11iIi11i - I1Ii111
  Oo0OoO00O , OOo00 , o000O0OOo00O , o0o0OoOo0 , iI , i1I1iI , IIiI1ii1i , iIii , O000 = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
  if 55 - 55: IiII / OoooooooOO
  packet = packet [ oOoOo000Ooooo : : ]
  if 23 - 23: iIii1I11I1II1
  if ( o000O0OOo00O != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
  self . instance_id = socket . ntohl ( i1I1iI )
  iI = socket . ntohs ( iI ) - 8
  if 33 - 33: I1Ii111 + OoooooooOO
  if 73 - 73: O0 . Oo0Ooo
  if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
  if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
  if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
  Iii1iIII1Iii = "H"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  if ( iI < oOoOo000Ooooo ) : return ( [ None , None ] )
  if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
  Oooo0oOOOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  iI -= oOoOo000Ooooo
  self . afi = socket . ntohs ( Oooo0oOOOO )
  self . mask_len = iIii
  ooOOO000O = self . addr_length ( )
  if ( iI < ooOOO000O ) : return ( [ None , None ] )
  if 40 - 40: I1Ii111 - iIii1I11I1II1
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 88 - 88: OOooOOo * O0 * OoOoOO00
  iI -= ooOOO000O
  if 26 - 26: Ii1I
  if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
  if 77 - 77: OoOoOO00 / I1IiiI + IiII
  if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
  if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
  Iii1iIII1Iii = "H"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  if ( iI < oOoOo000Ooooo ) : return ( [ None , None ] )
  if 21 - 21: OoooooooOO
  Oooo0oOOOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  iI -= oOoOo000Ooooo
  oo0oOooo0O = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  oo0oOooo0O . afi = socket . ntohs ( Oooo0oOOOO )
  oo0oOooo0O . mask_len = O000
  oo0oOooo0O . instance_id = self . instance_id
  ooOOO000O = self . addr_length ( )
  if ( iI < ooOOO000O ) : return ( [ None , None ] )
  if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
  packet = oo0oOooo0O . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 50 - 50: oO0o % OoOoOO00 + I1IiiI
  return ( [ packet , oo0oOooo0O ] )
  if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
 def lcaf_decode_eid ( self , packet ) :
  Iii1iIII1Iii = "BBB"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( [ None , None ] )
  if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
  if 46 - 46: o0oOOo0O0Ooo
  if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
  if 44 - 44: I11i . oO0o
  if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  o0o0OoOo0 , Ooo0000o , o000O0OOo00O = struct . unpack ( Iii1iIII1Iii ,
 packet [ : oOoOo000Ooooo ] )
  if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  if ( o000O0OOo00O == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( o000O0OOo00O == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , oo0oOooo0O = self . lcaf_decode_sg ( packet )
   return ( [ packet , oo0oOooo0O ] )
  elif ( o000O0OOo00O == LISP_LCAF_GEO_COORD_TYPE ) :
   Iii1iIII1Iii = "BBBBH"
   oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
   if ( len ( packet ) < oOoOo000Ooooo ) : return ( None )
   if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
   Ii1Ii1Ii , Ooo0000o , o000O0OOo00O , ii11Ii1111 , IIIi1I = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] )
   if 21 - 21: I11i % I1ii11iIi11i
   if 8 - 8: OOooOOo % OoO0O00 + O0 - o0oOOo0O0Ooo
   if ( o000O0OOo00O != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
   IIIi1I = socket . ntohs ( IIIi1I )
   packet = packet [ oOoOo000Ooooo : : ]
   if ( IIIi1I > len ( packet ) ) : return ( None )
   if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
   o0o0OoOo000O = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = o0o0OoOo000O
   packet = o0o0OoOo000O . decode_geo ( packet , IIIi1I , ii11Ii1111 )
   self . mask_len = self . host_mask_len ( )
   if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
  return ( [ packet , None ] )
  if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
  if 100 - 100: IiII - OoOoOO00 % iII111i
  if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
  if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
  if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
  if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
class lisp_elp_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
  if 42 - 42: OOooOOo
 def copy_elp_node ( self ) :
  oo0o = lisp_elp_node ( )
  oo0o . copy_address ( self . address )
  oo0o . probe = self . probe
  oo0o . strict = self . strict
  oo0o . eid = self . eid
  oo0o . we_are_last = self . we_are_last
  return ( oo0o )
  if 36 - 36: OoooooooOO + ooOoO0o + iII111i
  if 30 - 30: i1IIi % Ii1I
  if 18 - 18: o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . O0 * II111iiii + I1ii11iIi11i
class lisp_elp ( object ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 45 - 45: OoO0O00 / I1ii11iIi11i * ooOoO0o * OOooOOo % i11iIiiIii * iII111i
  if 33 - 33: oO0o . iII111i + Oo0Ooo
 def copy_elp ( self ) :
  I1IIii1IIi11IIiI = lisp_elp ( self . elp_name )
  I1IIii1IIi11IIiI . use_elp_node = self . use_elp_node
  I1IIii1IIi11IIiI . we_are_last = self . we_are_last
  for oo0o in self . elp_nodes :
   I1IIii1IIi11IIiI . elp_nodes . append ( oo0o . copy_elp_node ( ) )
   if 33 - 33: ooOoO0o
  return ( I1IIii1IIi11IIiI )
  if 46 - 46: OoOoOO00 / iII111i - OoO0O00 . o0oOOo0O0Ooo
  if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
 def print_elp ( self , want_marker ) :
  iIII1Iiii = ""
  for oo0o in self . elp_nodes :
   oooOoOoooo = ""
   if ( want_marker ) :
    if ( oo0o == self . use_elp_node ) :
     oooOoOoooo = "*"
    elif ( oo0o . we_are_last ) :
     oooOoOoooo = "x"
     if 26 - 26: OoooooooOO % iIii1I11I1II1 - IiII
     if 3 - 3: oO0o * II111iiii . O0
   iIII1Iiii += "{}{}({}{}{}), " . format ( oooOoOoooo ,
 oo0o . address . print_address_no_iid ( ) ,
 "r" if oo0o . eid else "R" , "P" if oo0o . probe else "p" ,
 "S" if oo0o . strict else "s" )
   if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
  return ( iIII1Iiii [ 0 : - 2 ] if iIII1Iiii != "" else "" )
  if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
  if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
 def select_elp_node ( self ) :
  oOOOO0OO , oo0ooOOO , ooo = lisp_myrlocs
  o00O = None
  if 23 - 23: ooOoO0o + ooOoO0o . I11i
  for oo0o in self . elp_nodes :
   if ( oOOOO0OO and oo0o . address . is_exact_match ( oOOOO0OO ) ) :
    o00O = self . elp_nodes . index ( oo0o )
    break
    if 90 - 90: I1Ii111 / iIii1I11I1II1 / oO0o
   if ( oo0ooOOO and oo0o . address . is_exact_match ( oo0ooOOO ) ) :
    o00O = self . elp_nodes . index ( oo0o )
    break
    if 47 - 47: i11iIiiIii - OOooOOo / I1IiiI % o0oOOo0O0Ooo % I1IiiI % I11i
    if 26 - 26: OoOoOO00 * ooOoO0o
    if 23 - 23: Ii1I + i1IIi + IiII - O0 / OOooOOo
    if 82 - 82: I1Ii111
    if 78 - 78: I1Ii111 % oO0o * iIii1I11I1II1
    if 1 - 1: i1IIi . iIii1I11I1II1
    if 2 - 2: OOooOOo % Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
  if ( o00O == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   oo0o . we_are_last = False
   return
   if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
   if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
   if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
   if 49 - 49: iII111i + OoOoOO00
   if 33 - 33: ooOoO0o
   if 19 - 19: I1Ii111 % IiII
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ o00O ] ) :
   self . use_elp_node = None
   oo0o . we_are_last = True
   return
   if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
   if 16 - 16: i1IIi
   if 88 - 88: OOooOOo
   if 79 - 79: oO0o
   if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
  self . use_elp_node = self . elp_nodes [ o00O + 1 ]
  return
  if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
  if 97 - 97: OoO0O00 - IiII + ooOoO0o % iIii1I11I1II1 % iII111i
  if 100 - 100: IiII - Ii1I * iIii1I11I1II1 . iII111i . i1IIi % Oo0Ooo
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
  if 11 - 11: I11i + oO0o % Ii1I
  if 22 - 22: ooOoO0o
 def copy_geo ( self ) :
  o0o0OoOo000O = lisp_geo ( self . geo_name )
  o0o0OoOo000O . latitude = self . latitude
  o0o0OoOo000O . lat_mins = self . lat_mins
  o0o0OoOo000O . lat_secs = self . lat_secs
  o0o0OoOo000O . longitude = self . longitude
  o0o0OoOo000O . long_mins = self . long_mins
  o0o0OoOo000O . long_secs = self . long_secs
  o0o0OoOo000O . altitude = self . altitude
  o0o0OoOo000O . radius = self . radius
  return ( o0o0OoOo000O )
  if 83 - 83: OOooOOo - i11iIiiIii - i1IIi / oO0o
  if 33 - 33: OoO0O00 + OOooOOo
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 36 - 36: o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * ooOoO0o * Ii1I * IiII
  if 39 - 39: i1IIi
 def parse_geo_string ( self , geo_str ) :
  o00O = geo_str . find ( "]" )
  if ( o00O != - 1 ) : geo_str = geo_str [ o00O + 1 : : ]
  if 79 - 79: ooOoO0o - II111iiii - oO0o
  if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
  if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
  if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
  if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , O0ii1i = geo_str . split ( "/" )
   self . radius = int ( O0ii1i )
   if 75 - 75: I1IiiI * oO0o / Oo0Ooo - II111iiii . OoO0O00
   if 8 - 8: iII111i . i11iIiiIii . IiII . I1ii11iIi11i + I11i
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 24 - 24: I1IiiI - I1IiiI . Oo0Ooo * IiII + I1IiiI / i1IIi
  Ii1ii = geo_str [ 0 : 4 ]
  O00oOoOoOoooo = geo_str [ 4 : 8 ]
  if 92 - 92: IiII + OoO0O00 + Oo0Ooo + oO0o
  if 81 - 81: Oo0Ooo % ooOoO0o / II111iiii . I11i
  if 41 - 41: IiII / OOooOOo * o0oOOo0O0Ooo . iII111i * I1IiiI . iIii1I11I1II1
  if 52 - 52: oO0o . OOooOOo . oO0o / Oo0Ooo / i1IIi - I1IiiI
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 69 - 69: Ii1I . o0oOOo0O0Ooo - OoooooooOO
  if 15 - 15: OoO0O00 / I1ii11iIi11i
  if 86 - 86: OOooOOo * OoOoOO00 % i1IIi * IiII . I1ii11iIi11i
  if 72 - 72: i1IIi - I1Ii111 . O0 * OoO0O00
  self . latitude = int ( Ii1ii [ 0 ] )
  self . lat_mins = int ( Ii1ii [ 1 ] )
  self . lat_secs = int ( Ii1ii [ 2 ] )
  if ( Ii1ii [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 62 - 62: Oo0Ooo . iII111i
  if 15 - 15: i11iIiiIii * I11i + oO0o
  if 67 - 67: IiII . OoO0O00
  if 59 - 59: oO0o * o0oOOo0O0Ooo
  self . longitude = int ( O00oOoOoOoooo [ 0 ] )
  self . long_mins = int ( O00oOoOoOoooo [ 1 ] )
  self . long_secs = int ( O00oOoOoOoooo [ 2 ] )
  if ( O00oOoOoOoooo [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 76 - 76: I1IiiI
  if 94 - 94: OoooooooOO * I1ii11iIi11i
 def print_geo ( self ) :
  iiiii = "N" if self . latitude < 0 else "S"
  oO0oOo = "E" if self . longitude < 0 else "W"
  if 88 - 88: OoooooooOO
  oOIIi = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , iiiii , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , oO0oOo )
  if 47 - 47: OOooOOo + Oo0Ooo * I11i
  if ( self . no_geo_altitude ( ) == False ) :
   oOIIi += "-" + str ( self . altitude )
   if 8 - 8: Ii1I % i1IIi
   if 29 - 29: oO0o % OoOoOO00 / OoOoOO00
   if 79 - 79: IiII % OoooooooOO
   if 51 - 51: iII111i . oO0o % ooOoO0o % Ii1I . o0oOOo0O0Ooo
   if 43 - 43: II111iiii
  if ( self . radius != 0 ) : oOIIi += "/{}" . format ( self . radius )
  return ( oOIIi )
  if 72 - 72: OoOoOO00 * oO0o - ooOoO0o / iII111i
  if 8 - 8: OoO0O00 * I1ii11iIi11i
 def geo_url ( self ) :
  iii1II = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  iii1II = "10" if ( iii1II == "" or iii1II . isdigit ( ) == False ) else iii1II
  o0OooOoO0O0 , O0OOo0ooOoo = self . dms_to_decimal ( )
  iIIi1Iii1Ii = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( o0OooOoO0O0 , O0OOo0ooOoo , o0OooOoO0O0 , O0OOo0ooOoo ,
  # ooOoO0o
  # OOooOOo % iII111i . o0oOOo0O0Ooo
 iii1II )
  return ( iIIi1Iii1Ii )
  if 34 - 34: i1IIi . i1IIi / oO0o
  if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
 def print_geo_url ( self ) :
  o0o0OoOo000O = self . print_geo ( )
  if ( self . radius == 0 ) :
   iIIi1Iii1Ii = self . geo_url ( )
   ii1111Iii11i = "<a href='{}'>{}</a>" . format ( iIIi1Iii1Ii , o0o0OoOo000O )
  else :
   iIIi1Iii1Ii = o0o0OoOo000O . replace ( "/" , "-" )
   ii1111Iii11i = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( iIIi1Iii1Ii , o0o0OoOo000O )
   if 93 - 93: iII111i
  return ( ii1111Iii11i )
  if 5 - 5: iII111i . I11i % I11i * Ii1I - I1ii11iIi11i . i11iIiiIii
  if 32 - 32: II111iiii
 def dms_to_decimal ( self ) :
  OOOOo00o , iIIi1I1i1i , O00O00Oo00Oo = self . latitude , self . lat_mins , self . lat_secs
  O00ooo0OO0ooO = float ( abs ( OOOOo00o ) )
  O00ooo0OO0ooO += float ( iIIi1I1i1i * 60 + O00O00Oo00Oo ) / 3600
  if ( OOOOo00o > 0 ) : O00ooo0OO0ooO = - O00ooo0OO0ooO
  ii1I1 = O00ooo0OO0ooO
  if 27 - 27: I11i + iIii1I11I1II1 * I1IiiI
  OOOOo00o , iIIi1I1i1i , O00O00Oo00Oo = self . longitude , self . long_mins , self . long_secs
  O00ooo0OO0ooO = float ( abs ( OOOOo00o ) )
  O00ooo0OO0ooO += float ( iIIi1I1i1i * 60 + O00O00Oo00Oo ) / 3600
  if ( OOOOo00o > 0 ) : O00ooo0OO0ooO = - O00ooo0OO0ooO
  IIIiIII = O00ooo0OO0ooO
  return ( ( ii1I1 , IIIiIII ) )
  if 3 - 3: OoOoOO00 * OOooOOo - IiII - II111iiii * oO0o
  if 23 - 23: I11i * I1ii11iIi11i . I11i
 def get_distance ( self , geo_point ) :
  OooOOO0o000o = self . dms_to_decimal ( )
  iI1Ii1 = geo_point . dms_to_decimal ( )
  iiI11 = geopy . distance . distance ( OooOOO0o000o , iI1Ii1 )
  return ( iiI11 . km )
  if 28 - 28: IiII + I1IiiI + IiII % OoOoOO00 % I1ii11iIi11i
  if 7 - 7: I1ii11iIi11i % OoOoOO00 - O0 . I1Ii111
 def point_in_circle ( self , geo_point ) :
  I1iii1III1I11II1 = self . get_distance ( geo_point )
  return ( I1iii1III1I11II1 <= self . radius )
  if 39 - 39: ooOoO0o + o0oOOo0O0Ooo + OOooOOo * OoOoOO00
  if 98 - 98: iIii1I11I1II1 - oO0o
 def encode_geo ( self ) :
  Iiii1I = socket . htons ( LISP_AFI_LCAF )
  o0000OO0 = socket . htons ( 20 + 2 )
  Ooo0000o = 0
  if 91 - 91: iII111i % iII111i . ooOoO0o / iII111i
  o0OooOoO0O0 = abs ( self . latitude )
  iiiiI1 = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : Ooo0000o |= 0x40
  if 19 - 19: OoO0O00 - Ii1I + ooOoO0o + OOooOOo
  O0OOo0ooOoo = abs ( self . longitude )
  o0Oo = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : Ooo0000o |= 0x20
  if 50 - 50: OoO0O00
  oOoooOO = 0
  if ( self . no_geo_altitude ( ) == False ) :
   oOoooOO = socket . htonl ( self . altitude )
   Ooo0000o |= 0x10
   if 62 - 62: OoOoOO00
  O0ii1i = socket . htons ( self . radius )
  if ( O0ii1i != 0 ) : Ooo0000o |= 0x06
  if 100 - 100: oO0o - OoOoOO00 % O0 * I1Ii111 - OOooOOo / I1ii11iIi11i
  O0OOO = struct . pack ( "HBBBBH" , Iiii1I , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , o0000OO0 )
  O0OOO += struct . pack ( "BBHBBHBBHIHHH" , Ooo0000o , 0 , 0 , o0OooOoO0O0 , iiiiI1 >> 16 ,
 socket . htons ( iiiiI1 & 0x0ffff ) , O0OOo0ooOoo , o0Oo >> 16 ,
 socket . htons ( o0Oo & 0xffff ) , oOoooOO , O0ii1i , 0 , 0 )
  if 11 - 11: OoO0O00
  return ( O0OOO )
  if 70 - 70: o0oOOo0O0Ooo * O0 * II111iiii
  if 38 - 38: OoO0O00 - I1IiiI * OoooooooOO / I11i . O0
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  Iii1iIII1Iii = "BBHBBHBBHIHHH"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( lcaf_len < oOoOo000Ooooo ) : return ( None )
  if 77 - 77: OOooOOo + oO0o * iIii1I11I1II1 / oO0o / OOooOOo . i11iIiiIii
  Ooo0000o , OOOo0o0OOO0000 , OooOooo0O , o0OooOoO0O0 , oOo0Oo , iiiiI1 , O0OOo0ooOoo , ooo00o000oO , o0Oo , oOoooOO , O0ii1i , i11I1IiI1Iiii11i , Oooo0oOOOO = struct . unpack ( Iii1iIII1Iii ,
  # ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
 packet [ : oOoOo000Ooooo ] )
  if 47 - 47: Oo0Ooo + oO0o % OoooooooOO
  if 23 - 23: I1Ii111 / i11iIiiIii - ooOoO0o * iII111i - Ii1I . iIii1I11I1II1
  if 11 - 11: I11i % OoOoOO00 * Oo0Ooo
  if 48 - 48: OOooOOo
  Oooo0oOOOO = socket . ntohs ( Oooo0oOOOO )
  if ( Oooo0oOOOO == LISP_AFI_LCAF ) : return ( None )
  if 66 - 66: iII111i - I1Ii111 - i11iIiiIii . o0oOOo0O0Ooo + Oo0Ooo
  if ( Ooo0000o & 0x40 ) : o0OooOoO0O0 = - o0OooOoO0O0
  self . latitude = o0OooOoO0O0
  Oo0oo0oOO = old_div ( ( ( oOo0Oo << 16 ) | socket . ntohs ( iiiiI1 ) ) , 1000 )
  self . lat_mins = old_div ( Oo0oo0oOO , 60 )
  self . lat_secs = Oo0oo0oOO % 60
  if 78 - 78: i1IIi
  if ( Ooo0000o & 0x20 ) : O0OOo0ooOoo = - O0OOo0ooOoo
  self . longitude = O0OOo0ooOoo
  III1iiI1111I = old_div ( ( ( ooo00o000oO << 16 ) | socket . ntohs ( o0Oo ) ) , 1000 )
  self . long_mins = old_div ( III1iiI1111I , 60 )
  self . long_secs = III1iiI1111I % 60
  if 13 - 13: OOooOOo
  self . altitude = socket . ntohl ( oOoooOO ) if ( Ooo0000o & 0x10 ) else - 1
  O0ii1i = socket . ntohs ( O0ii1i )
  self . radius = O0ii1i if ( Ooo0000o & 0x02 ) else O0ii1i * 1000
  if 36 - 36: oO0o * OoooooooOO / OOooOOo - Ii1I / I11i / Oo0Ooo
  self . geo_name = None
  packet = packet [ oOoOo000Ooooo : : ]
  if 93 - 93: I1ii11iIi11i * iIii1I11I1II1 / I1ii11iIi11i . I11i % o0oOOo0O0Ooo / O0
  if ( Oooo0oOOOO != 0 ) :
   self . rloc . afi = Oooo0oOOOO
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 19 - 19: iII111i / I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
  return ( packet )
  if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
  if 96 - 96: OoOoOO00 . I1IiiI . I11i * OoooooooOO + OoooooooOO * O0
  if 90 - 90: I11i + I1ii11iIi11i + OoooooooOO + OoOoOO00 + IiII / iII111i
  if 75 - 75: i11iIiiIii
  if 27 - 27: I11i - IiII - I1Ii111
  if 90 - 90: OoO0O00 . oO0o * O0 / I11i % O0 + I1Ii111
class lisp_rle_node ( object ) :
 def __init__ ( self ) :
  self . level = 0
  self . rloc = lisp_rloc ( )
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  if 84 - 84: Ii1I
 def copy_rle_node ( self ) :
  Ii1111iiIii = lisp_rle_node ( )
  Ii1111iiIii = copy . deepcopy ( self )
  return ( Ii1111iiIii )
  if 92 - 92: I11i
  if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
 def store_translated_rloc ( self , rloc , port ) :
  rloc . store_translated_rloc ( rloc . rloc , port )
  if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
  if 82 - 82: O0 * ooOoO0o * iIii1I11I1II1 . i1IIi
 def get_encap_keys ( self ) :
  I1I1I1 = "4341" if self . rloc . translated_port == 0 else str ( self . rloc . translated_port )
  if 47 - 47: I11i * I11i . OoOoOO00
  O00oO000Oo0 = self . rloc . rloc . print_address_no_iid ( ) + ":" + I1I1I1
  if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
  try :
   O0o0O0 = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ]
   if ( O0o0O0 [ 1 ] ) : return ( O0o0O0 [ 1 ] . encrypt_key , O0o0O0 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
   if 33 - 33: iIii1I11I1II1 . I11i
   if 63 - 63: oO0o - iII111i
   if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
class lisp_rle ( object ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
  if 33 - 33: oO0o
 def copy_rle ( self ) :
  IIiiiI = lisp_rle ( self . rle_name )
  for Ii1111iiIii in self . rle_nodes :
   IIiiiI . rle_nodes . append ( Ii1111iiIii . copy_rle_node ( ) )
   if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
  IIiiiI . build_rle_forwarding_list ( )
  return ( IIiiiI )
  if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
  if 45 - 45: OoooooooOO / o0oOOo0O0Ooo / iII111i
 def add_one_rle_node ( self , rle_node ) :
  o00o0O0O0oO0o = lisp_rle_node ( )
  o00o0O0O0oO0o = copy . deepcopy ( rle_node )
  self . rle_nodes . append ( o00o0O0O0oO0o )
  self . build_rle_forwarding_list ( )
  if 56 - 56: ooOoO0o
  if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
 def print_one_rle ( self , rle_node , html , do_formatting ) :
  I1I1I1 = rle_node . rloc . translated_port
  if 60 - 60: IiII % i11iIiiIii / OOooOOo
  IiIiI11iiiI1I = ""
  if ( rle_node . rloc . rloc_name != None ) :
   IiIiI11iiiI1I = rle_node . rloc . rloc_name
   if ( do_formatting ) : IiIiI11iiiI1I = blue ( IiIiI11iiiI1I , html )
   IiIiI11iiiI1I = "({})" . format ( IiIiI11iiiI1I )
   if 60 - 60: I11i
   if 98 - 98: OoOoOO00 % I1ii11iIi11i / OoOoOO00 % o0oOOo0O0Ooo / I1ii11iIi11i
  O00oO000Oo0 = rle_node . rloc . rloc . print_address_no_iid ( )
  if ( rle_node . rloc . rloc . is_local ( ) ) : O00oO000Oo0 = red ( O00oO000Oo0 , html )
  IIIi1iI1 = "{}{}{}" . format ( O00oO000Oo0 , "" if I1I1I1 == 0 else ":" + str ( I1I1I1 ) , IiIiI11iiiI1I )
  return ( IIIi1iI1 )
  if 21 - 21: I1IiiI * IiII - Oo0Ooo % ooOoO0o * i1IIi
  if 23 - 23: I11i * II111iiii + OoooooooOO . i1IIi + OoO0O00 + OoOoOO00
 def print_rle ( self , html , do_formatting ) :
  IIIi1iI1 = ""
  for Ii1111iiIii in self . rle_nodes :
   IIIi1iI1 += self . print_one_rle ( Ii1111iiIii , html , do_formatting )
   IIIi1iI1 += ", "
   if 52 - 52: iII111i * OoOoOO00
  return ( IIIi1iI1 [ 0 : - 2 ] if IIIi1iI1 != "" else "" )
  if 80 - 80: I1Ii111 / IiII * o0oOOo0O0Ooo - OoOoOO00 / iIii1I11I1II1
  if 38 - 38: II111iiii / I11i + IiII % OoooooooOO
 def print_api_rle ( self ) :
  II1I111iIII1i = { }
  for Ii1111iiIii in self . rle_nodes :
   IIIi1iI1 = self . print_one_rle ( Ii1111iiIii , False , False )
   II1I111iIII1i [ IIIi1iI1 ] = lisp_fill_rloc_in_json ( Ii1111iiIii . rloc )
   if 22 - 22: i1IIi + I1Ii111 * O0 . OOooOOo
  return ( II1I111iIII1i )
  if 55 - 55: I1ii11iIi11i - I11i
  if 73 - 73: i11iIiiIii . OoO0O00 + OoO0O00 - OOooOOo % OOooOOo - OoO0O00
 def build_rle_forwarding_list ( self ) :
  i1iIIII11I = - 1
  for Ii1111iiIii in self . rle_nodes :
   if ( i1iIIII11I == - 1 ) :
    if ( Ii1111iiIii . rloc . rloc . is_local ( ) ) : i1iIIII11I = Ii1111iiIii . level
   else :
    if ( Ii1111iiIii . level > i1iIIII11I ) : break
    if 5 - 5: I1ii11iIi11i + i1IIi * I11i % iII111i
    if 96 - 96: ooOoO0o % I1ii11iIi11i % i11iIiiIii * I11i * iII111i . i11iIiiIii
  i1iIIII11I = 0 if i1iIIII11I == - 1 else Ii1111iiIii . level
  if 65 - 65: i11iIiiIii / o0oOOo0O0Ooo % I1ii11iIi11i - O0 % OoooooooOO / o0oOOo0O0Ooo
  self . rle_forwarding_list = [ ]
  for Ii1111iiIii in self . rle_nodes :
   if ( Ii1111iiIii . level == i1iIIII11I or ( i1iIIII11I == 0 and Ii1111iiIii . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and Ii1111iiIii . rloc . rloc . is_local ( ) ) :
     O00oO000Oo0 = Ii1111iiIii . rloc . rloc . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( O00oO000Oo0 ) )
     continue
     if 36 - 36: iII111i * OoO0O00 / OOooOOo * IiII * iIii1I11I1II1 / IiII
    self . rle_forwarding_list . append ( Ii1111iiIii )
    if 79 - 79: iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
    if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
    if 65 - 65: OoOoOO00
    if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
    if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
class lisp_json ( object ) :
 def __init__ ( self , name , string , encrypted = False , ms_encrypt = False ) :
  if 33 - 33: IiII / i1IIi + I1Ii111
  if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
  if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
  if 73 - 73: OoOoOO00
  if ( type ( string ) == bytes ) : string = string . decode ( )
  if 66 - 66: Oo0Ooo
  self . json_name = name
  self . json_encrypted = False
  try :
   json . loads ( string )
  except :
   lprint ( "Invalid JSON string: '{}'" . format ( string ) )
   string = '{ "?" : "?" }'
   if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
  self . json_string = string
  if 65 - 65: OoOoOO00 % II111iiii + Oo0Ooo
  if 24 - 24: OoO0O00 % OoooooooOO
  if 16 - 16: OoOoOO00 % Oo0Ooo * OoOoOO00 . Ii1I
  if 91 - 91: I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
  if 37 - 37: IiII - oO0o
  if 92 - 92: I1IiiI
  if 51 - 51: OoO0O00 + Oo0Ooo - OOooOOo + I1ii11iIi11i
  if 32 - 32: I1ii11iIi11i % OoOoOO00 + Oo0Ooo
  if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
  if 9 - 9: OoO0O00
  if ( len ( lisp_ms_json_keys ) != 0 ) :
   if ( ms_encrypt == False ) : return
   self . json_key_id = list ( lisp_ms_json_keys . keys ( ) ) [ 0 ]
   self . json_key = lisp_ms_json_keys [ self . json_key_id ]
   self . encrypt_json ( )
   if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
   if 52 - 52: ooOoO0o
  if ( lisp_log_id == "lig" and encrypted ) :
   OoOOooOOoo = os . getenv ( "LISP_JSON_KEY" )
   if ( OoOOooOOoo != None ) :
    o00O = - 1
    if ( OoOOooOOoo [ 0 ] == "[" and "]" in OoOOooOOoo ) :
     o00O = OoOOooOOoo . find ( "]" )
     self . json_key_id = int ( OoOOooOOoo [ 1 : o00O ] )
     if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
    self . json_key = OoOOooOOoo [ o00O + 1 : : ]
    if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
    self . decrypt_json ( )
    if 60 - 60: OOooOOo * I1Ii111
    if 17 - 17: iII111i * I11i / iIii1I11I1II1 - II111iiii
    if 97 - 97: II111iiii * o0oOOo0O0Ooo
    if 13 - 13: o0oOOo0O0Ooo . II111iiii
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 76 - 76: II111iiii + I1Ii111 . OoooooooOO / IiII % i11iIiiIii
  if 87 - 87: Ii1I / OoOoOO00 / OOooOOo
 def delete ( self ) :
  if ( self . json_name in lisp_json_list ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
   if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
   if 24 - 24: iII111i + i1IIi
 def print_json ( self , html ) :
  iII1ii1 = self . json_string
  OoooOOoOO = "***"
  if ( html ) : OoooOOoOO = red ( OoooOOoOO , html )
  oOoOooooO = OoooOOoOO + self . json_string + OoooOOoOO
  if ( self . valid_json ( ) ) : return ( iII1ii1 )
  return ( oOoOooooO )
  if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
  if 64 - 64: OoO0O00 - OoO0O00
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 93 - 93: Oo0Ooo . O0
  return ( True )
  if 75 - 75: iII111i * II111iiii - I1IiiI
  if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
 def encrypt_json ( self ) :
  i1ii1IIii = self . json_key . zfill ( 32 )
  oO0o000oOO = "0" * 8
  if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
  OoiI1iII1Ii111I = json . loads ( self . json_string )
  for OoOOooOOoo in OoiI1iII1Ii111I :
   oO00o = OoiI1iII1Ii111I [ OoOOooOOoo ]
   if ( type ( oO00o ) != str ) : oO00o = str ( oO00o )
   oO00o = chacha . ChaCha ( i1ii1IIii , oO0o000oOO ) . encrypt ( oO00o )
   OoiI1iII1Ii111I [ OoOOooOOoo ] = binascii . hexlify ( oO00o )
   if 51 - 51: I1Ii111 % i11iIiiIii + i1IIi - OOooOOo - Ii1I + oO0o
  self . json_string = json . dumps ( OoiI1iII1Ii111I )
  self . json_encrypted = True
  if 5 - 5: Oo0Ooo / I1ii11iIi11i / ooOoO0o / o0oOOo0O0Ooo - i1IIi + IiII
  if 25 - 25: OoOoOO00 / ooOoO0o
 def decrypt_json ( self ) :
  i1ii1IIii = self . json_key . zfill ( 32 )
  oO0o000oOO = "0" * 8
  if 73 - 73: iII111i
  OoiI1iII1Ii111I = json . loads ( self . json_string )
  for OoOOooOOoo in OoiI1iII1Ii111I :
   oO00o = binascii . unhexlify ( OoiI1iII1Ii111I [ OoOOooOOoo ] )
   OoiI1iII1Ii111I [ OoOOooOOoo ] = chacha . ChaCha ( i1ii1IIii , oO0o000oOO ) . encrypt ( oO00o )
   if 34 - 34: o0oOOo0O0Ooo * I1ii11iIi11i
  try :
   self . json_string = json . dumps ( OoiI1iII1Ii111I )
   self . json_encrypted = False
  except :
   pass
   if 16 - 16: i1IIi
   if 84 - 84: i11iIiiIii
   if 92 - 92: o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
   if 33 - 33: I1IiiI + O0 - I11i
   if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
   if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
   if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
class lisp_stats ( object ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 38 - 38: O0 % I1ii11iIi11i + O0
  if 37 - 37: Oo0Ooo / I1IiiI
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 23 - 23: II111iiii / iII111i
  if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  o0oOOOO0 = time . time ( ) - self . last_increment
  return ( o0oOOOO0 <= 1 )
  if 92 - 92: iIii1I11I1II1
  if 47 - 47: Oo0Ooo + Oo0Ooo * ooOoO0o - OoOoOO00 + II111iiii
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  o0oOOOO0 = time . time ( ) - self . last_increment
  return ( o0oOOOO0 <= 60 )
  if 10 - 10: II111iiii / ooOoO0o . Ii1I / I1Ii111 / oO0o
  if 8 - 8: OOooOOo / ooOoO0o * I11i + OOooOOo * i1IIi
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 63 - 63: O0 - IiII . OOooOOo % IiII . I1IiiI / oO0o
  return ( c1 , c2 )
  if 79 - 79: OoOoOO00
  if 88 - 88: oO0o * o0oOOo0O0Ooo
 def normalize ( self , count ) :
  count = str ( count )
  I111I1Ii = len ( count )
  if ( I111I1Ii > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 45 - 45: I1Ii111 / Oo0Ooo * OOooOOo / Oo0Ooo
  if ( I111I1Ii > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 49 - 49: I1ii11iIi11i * O0 / Ii1I . iIii1I11I1II1
  if ( I111I1Ii > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 17 - 17: IiII
  return ( count )
  if 54 - 54: Oo0Ooo % O0 - OoooooooOO
  if 80 - 80: Oo0Ooo - I1ii11iIi11i - iIii1I11I1II1 / iIii1I11I1II1 * i1IIi
 def get_stats ( self , summary , html ) :
  O0O0iI = self . last_rate_check
  oo0ooO0oOoo = self . last_packet_count
  ooOo0OO = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 100 - 100: Ii1I * O0 / I1IiiI
  OOO0OOO = self . last_rate_check - O0O0iI
  if ( OOO0OOO == 0 ) :
   OO0oO0Oo0O0 = 0
   i1i11i111i1I1 = 0
  else :
   OO0oO0Oo0O0 = int ( old_div ( ( self . packet_count - oo0ooO0oOoo ) ,
 OOO0OOO ) )
   i1i11i111i1I1 = old_div ( ( self . byte_count - ooOo0OO ) , OOO0OOO )
   i1i11i111i1I1 = old_div ( ( i1i11i111i1I1 * 8 ) , 1000000 )
   i1i11i111i1I1 = round ( i1i11i111i1I1 , 2 )
   if 32 - 32: IiII % OOooOOo . Ii1I
   if 27 - 27: o0oOOo0O0Ooo
   if 73 - 73: i11iIiiIii % II111iiii - Ii1I . IiII
   if 77 - 77: oO0o . oO0o . OoOoOO00
   if 55 - 55: I1ii11iIi11i / iIii1I11I1II1 . OoOoOO00 - ooOoO0o
  OoOoO0OO = self . normalize ( self . packet_count )
  i1III1I = self . normalize ( self . byte_count )
  if 12 - 12: i1IIi / I1Ii111 - Oo0Ooo
  if 66 - 66: iII111i - IiII . I1Ii111
  if 29 - 29: I1Ii111 - Ii1I + O0 - oO0o - O0
  if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
  if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
  if ( summary ) :
   i11iiIiI1IIii = "<br>" if html else ""
   OoOoO0OO , i1III1I = self . stat_colors ( OoOoO0OO , i1III1I , html )
   OOoO0OOooOo = "packet-count: {}{}byte-count: {}" . format ( OoOoO0OO , i11iiIiI1IIii , i1III1I )
   II1iiiiI1ii = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( OO0oO0Oo0O0 , i1i11i111i1I1 )
   if 40 - 40: I1Ii111 / I1ii11iIi11i . I1IiiI . Ii1I * I11i
   if ( html != "" ) : II1iiiiI1ii = lisp_span ( OOoO0OOooOo , II1iiiiI1ii )
  else :
   iiIoo00oOOoOo = str ( OO0oO0Oo0O0 )
   oooo0O00oO0o0 = str ( i1i11i111i1I1 )
   if ( html ) :
    OoOoO0OO = lisp_print_cour ( OoOoO0OO )
    iiIoo00oOOoOo = lisp_print_cour ( iiIoo00oOOoOo )
    i1III1I = lisp_print_cour ( i1III1I )
    oooo0O00oO0o0 = lisp_print_cour ( oooo0O00oO0o0 )
    if 57 - 57: II111iiii
   i11iiIiI1IIii = "<br>" if html else ", "
   if 13 - 13: II111iiii * OoO0O00 - iIii1I11I1II1
   II1iiiiI1ii = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( OoOoO0OO , i11iiIiI1IIii , iiIoo00oOOoOo , i11iiIiI1IIii , i1III1I , i11iiIiI1IIii ,
   # oO0o + O0
 oooo0O00oO0o0 )
   if 59 - 59: I1Ii111
  return ( II1iiiiI1ii )
  if 88 - 88: o0oOOo0O0Ooo % I1Ii111
  if 4 - 4: i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
  if 87 - 87: I1Ii111 % i11iIiiIii + O0
  if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
  if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
  if 15 - 15: I1ii11iIi11i
  if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
  if 56 - 56: I1IiiI . ooOoO0o
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
if 37 - 37: iII111i - ooOoO0o * Ii1I + II111iiii * i11iIiiIii
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
  if 8 - 8: OoooooooOO % I11i - iII111i * OOooOOo . O0
  if ( recurse == False ) : return
  if 40 - 40: I1Ii111 . oO0o + OoO0O00 % Oo0Ooo / II111iiii
  if 19 - 19: i11iIiiIii
  if 20 - 20: i11iIiiIii . II111iiii - I1ii11iIi11i / ooOoO0o % i11iIiiIii
  if 35 - 35: Oo0Ooo - I1ii11iIi11i . Oo0Ooo
  if 13 - 13: II111iiii / OoOoOO00 * iII111i % O0 % I1ii11iIi11i * i11iIiiIii
  if 92 - 92: i11iIiiIii + OoO0O00
  OOoOOoo = lisp_get_default_route_next_hops ( )
  if ( OOoOOoo == [ ] or len ( OOoOOoo ) == 1 ) : return
  if 63 - 63: O0 * i11iIiiIii
  self . rloc_next_hop = OOoOOoo [ 0 ]
  i11iII11I1III = self
  for O0O0O0ooOoOo in OOoOOoo [ 1 : : ] :
   IiII1IIii1 = lisp_rloc ( False )
   IiII1IIii1 = copy . deepcopy ( self )
   IiII1IIii1 . rloc_next_hop = O0O0O0ooOoOo
   i11iII11I1III . next_rloc = IiII1IIii1
   i11iII11I1III = IiII1IIii1
   if 80 - 80: IiII + i11iIiiIii . I1Ii111 * Oo0Ooo % OoooooooOO
   if 12 - 12: iII111i / I11i
   if 70 - 70: Oo0Ooo + O0 - o0oOOo0O0Ooo
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 85 - 85: I1Ii111
  if 39 - 39: OoOoOO00 * oO0o
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 62 - 62: OoOoOO00 / OoOoOO00 * OoO0O00
  if 38 - 38: I1Ii111 + ooOoO0o % I11i
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 22 - 22: I1Ii111 . Ii1I % I1Ii111 * I1IiiI / iIii1I11I1II1
  if 12 - 12: Oo0Ooo / IiII % ooOoO0o / iIii1I11I1II1 % O0 / i11iIiiIii
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 58 - 58: i11iIiiIii * O0
  if 85 - 85: oO0o
  if 57 - 57: II111iiii . I1IiiI - OOooOOo
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
  if 54 - 54: i1IIi + OoOoOO00
  if 76 - 76: OoOoOO00
 def print_rloc ( self , indent ) :
  iIiIIIIIii = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , iIiIIIIIii , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
  if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  oOo = self . rloc_name
  if ( cour ) : oOo = lisp_print_cour ( oOo )
  return ( 'rloc-name: {}' . format ( blue ( oOo , cour ) ) )
  if 57 - 57: OoooooooOO . iIii1I11I1II1 % iII111i % Oo0Ooo
  if 92 - 92: I1Ii111 - Ii1I + I1Ii111
 def is_decent_nat_port ( self ) :
  IIi = self . rloc_name
  if ( IIi == None ) : return ( False )
  if ( IIi . find ( LISP_TP ) == - 1 ) : return ( False )
  return ( True )
  if 81 - 81: o0oOOo0O0Ooo . OoOoOO00 . i11iIiiIii
  if 13 - 13: i1IIi
 def store_decent_nat_port ( self ) :
  if ( self . is_decent_nat_port ( ) == False ) : return ( False )
  I1I1I1 = self . rloc_name . split ( LISP_TP ) [ - 1 ]
  self . translated_port = int ( I1I1I1 )
  return ( True )
  if 70 - 70: O0 / II111iiii
  if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
 def normalize_decent_nat_rloc_name ( self ) :
  if ( self . is_decent_nat_port ( ) == False ) : return ( self . rloc_name )
  IIi = self . rloc_name . split ( LISP_TP ) [ 0 ]
  return ( IIi )
  if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
  if 77 - 77: i1IIi . I1IiiI
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  I1I1I1 = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  if 59 - 59: O0 + OoooooooOO - i1IIi
  if ( rloc_record . rloc_name != None ) :
   self . rloc_name = rloc_record . rloc_name
   if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
   if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
   if 12 - 12: I1IiiI
   if 99 - 99: II111iiii - OoOoOO00
   if ( lisp_i_am_rtr == False ) :
    if ( self . store_decent_nat_port ( ) ) :
     self . translated_rloc . copy_address ( self . rloc )
     if 22 - 22: i11iIiiIii * II111iiii
     if 11 - 11: Oo0Ooo % i1IIi
     if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
     if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
     if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
     if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
   O0O0O0ooOoOo = self . next_rloc
   while ( O0O0O0ooOoOo != None ) :
    O0O0O0ooOoOo . rloc_name = self . rloc_name
    O0O0O0ooOoOo = O0O0O0ooOoOo . next_rloc
    if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
    if 8 - 8: OoooooooOO
    if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
    if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
    if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
    if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
  iIIiI11 = self . rloc
  if ( iIIiI11 . is_null ( ) == False and self . rloc_name != None ) :
   IIi = self . normalize_decent_nat_rloc_name ( )
   oO00OOoOOoO = lisp_get_nat_info ( iIIiI11 , IIi )
   if ( oO00OOoOOoO ) :
    I1I1I1 = oO00OOoOOoO . port
    O0OOo00 = lisp_nat_state_info [ IIi ] [ 0 ]
    O00oO000Oo0 = iIIiI11 . print_address_no_iid ( )
    o00oO = red ( O00oO000Oo0 , False )
    I1II1II1IiI = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 60 - 60: iII111i - OoooooooOO
    if 65 - 65: II111iiii * iII111i
    if 90 - 90: I11i . O0 + oO0o
    if 63 - 63: I11i . I1IiiI + OoooooooOO + O0
    if 55 - 55: i11iIiiIii * Ii1I % OOooOOo + ooOoO0o - I1ii11iIi11i . Oo0Ooo
    if 48 - 48: o0oOOo0O0Ooo
    if ( oO00OOoOOoO . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( o00oO , I1I1I1 , I1II1II1IiI ) )
     if 55 - 55: OOooOOo - OoooooooOO * iIii1I11I1II1 + iII111i % II111iiii
     if 33 - 33: I1Ii111 * oO0o * OoooooooOO + OOooOOo - I1IiiI + I1Ii111
     oO00OOoOOoO = None if ( oO00OOoOOoO == O0OOo00 ) else O0OOo00
     if ( oO00OOoOOoO and oO00OOoOOoO . timed_out ( ) ) :
      I1I1I1 = oO00OOoOOoO . port
      o00oO = red ( oO00OOoOOoO . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( o00oO , I1I1I1 ,
      # I1Ii111 % Ii1I * Oo0Ooo % o0oOOo0O0Ooo . OoOoOO00 % I1IiiI
 I1II1II1IiI ) )
      oO00OOoOOoO = None
      if 5 - 5: IiII
      if 77 - 77: i11iIiiIii . OoooooooOO % iIii1I11I1II1 % I1Ii111
      if 22 - 22: iIii1I11I1II1 + Ii1I / OOooOOo - oO0o * oO0o / IiII
      if 91 - 91: I11i - II111iiii + o0oOOo0O0Ooo + i1IIi + I1ii11iIi11i % Ii1I
      if 57 - 57: o0oOOo0O0Ooo - I1Ii111 / OoooooooOO . OoooooooOO
      if 44 - 44: oO0o / II111iiii % I1IiiI - II111iiii / OoooooooOO
      if 4 - 4: I11i * OoOoOO00
    if ( oO00OOoOOoO ) :
     if ( oO00OOoOOoO . address != O00oO000Oo0 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( o00oO , red ( oO00OOoOOoO . address , False ) ) )
      if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
      self . rloc . store_address ( oO00OOoOOoO . address )
      if 87 - 87: oO0o . I11i
     o00oO = red ( oO00OOoOOoO . address , False )
     I1I1I1 = oO00OOoOOoO . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( o00oO , I1I1I1 , I1II1II1IiI ) )
     if 15 - 15: oO0o
     self . store_translated_rloc ( iIIiI11 , I1I1I1 )
     if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
     if 89 - 89: IiII . IiII . oO0o % iII111i
     if 27 - 27: OoOoOO00 + O0 % i1IIi - Oo0Ooo
     if 96 - 96: O0 % o0oOOo0O0Ooo + OOooOOo % I1IiiI
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 51 - 51: i1IIi . o0oOOo0O0Ooo % I1IiiI - OoooooooOO / OoOoOO00 - I11i
  if 45 - 45: O0 * II111iiii / i11iIiiIii
  if 38 - 38: OoooooooOO % i11iIiiIii - O0 / O0
  if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for Ii1111iiIii in self . rle . rle_nodes :
    oOo = Ii1111iiIii . rloc . rloc_name
    oO00OOoOOoO = lisp_get_nat_info ( Ii1111iiIii . rloc . rloc , oOo )
    if ( oO00OOoOOoO == None ) : continue
    if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
    I1I1I1 = oO00OOoOOoO . port
    IIiIIIiI = oOo
    if ( IIiIIIiI ) : IIiIIIiI = blue ( oOo , False )
    if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( I1I1I1 ,
    # I1ii11iIi11i . iIii1I11I1II1
 Ii1111iiIii . rloc . rloc . print_address_no_iid ( ) , IIiIIIiI ) )
    if 93 - 93: IiII * OoooooooOO - OoO0O00 . oO0o - iIii1I11I1II1 * iII111i
    Ii1111iiIii . store_translated_rloc ( Ii1111iiIii . rloc , I1I1I1 )
    if 15 - 15: II111iiii * O0 % I1ii11iIi11i % Ii1I . OoOoOO00
    if 8 - 8: IiII / Oo0Ooo % OOooOOo + O0 - Ii1I
    if 43 - 43: O0 % i11iIiiIii + o0oOOo0O0Ooo . I11i / OOooOOo . O0
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) :
   if ( self . state != LISP_RLOC_UP_STATE ) :
    self . last_state_change = lisp_get_timestamp ( )
    if 30 - 30: i11iIiiIii + i1IIi
   self . state = LISP_RLOC_UP_STATE
   if 52 - 52: OoooooooOO % OoOoOO00 / IiII % OoO0O00
   if 36 - 36: II111iiii . O0 % O0 * iII111i * iIii1I11I1II1
   if 42 - 42: iII111i . OOooOOo + oO0o / OoOoOO00
   if 54 - 54: ooOoO0o % o0oOOo0O0Ooo + i11iIiiIii / ooOoO0o * II111iiii * Ii1I
   if 52 - 52: ooOoO0o + IiII * OoOoOO00 - OoO0O00 - OoooooooOO - oO0o
  o0O0oiiI1iI11i1 = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 6 - 6: IiII + OOooOOo % I1Ii111 % ooOoO0o . I1Ii111
  if ( rloc_record . keys != None and o0O0oiiI1iI11i1 ) :
   OoOOooOOoo = rloc_record . keys [ 1 ]
   if ( OoOOooOOoo != None ) :
    O00oO000Oo0 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( I1I1I1 )
    if 56 - 56: O0
    OoOOooOOoo . add_key_by_rloc ( O00oO000Oo0 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( O00oO000Oo0 , False ) ) )
    if 8 - 8: oO0o + O0
    if 52 - 52: I11i * OOooOOo - OoOoOO00 % iIii1I11I1II1 . II111iiii
    if 1 - 1: OOooOOo / I1IiiI / Ii1I * iII111i
  return ( I1I1I1 )
  if 14 - 14: ooOoO0o . O0 * OOooOOo
  if 34 - 34: I1ii11iIi11i . OOooOOo + OoO0O00 % o0oOOo0O0Ooo * O0 * I1IiiI
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if ( lisp_i_am_rtr == False ) :
   self . rloc_name += LISP_TP + str ( port )
   if 9 - 9: IiII / i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % I1Ii111
   if 65 - 65: I1IiiI % OoOoOO00
   if 45 - 45: o0oOOo0O0Ooo
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 33 - 33: ooOoO0o % O0 % I1ii11iIi11i % o0oOOo0O0Ooo + i11iIiiIii . I1Ii111
  if 21 - 21: I1Ii111 * I1ii11iIi11i * ooOoO0o
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 73 - 73: OoOoOO00 * O0
  return ( True )
  if 1 - 1: OOooOOo * OoooooooOO
  if 46 - 46: I1ii11iIi11i * I1Ii111 / OOooOOo / I1IiiI
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 7 - 7: OOooOOo / OoOoOO00
  if 93 - 93: iIii1I11I1II1 * Ii1I - iII111i
  if 94 - 94: iIii1I11I1II1 * iIii1I11I1II1 * I11i % i11iIiiIii
 def print_state_change ( self , new_state ) :
  Ii1IIiI1I1 = self . print_state ( )
  ii1111Iii11i = "{} -> {}" . format ( Ii1IIiI1I1 , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   ii1111Iii11i = bold ( ii1111Iii11i , False )
   if 26 - 26: I1Ii111 % I11i + OoO0O00
  return ( ii1111Iii11i )
  if 72 - 72: Oo0Ooo
  if 28 - 28: iII111i . i11iIiiIii + o0oOOo0O0Ooo
 def copy_rloc_probe_recents ( self , rloc ) :
  self . rloc_probe_rtt = rloc . rloc_probe_rtt
  self . rloc_probe_hops = rloc . rloc_probe_hops
  self . rloc_probe_latency = rloc . rloc_probe_latency
  self . last_rloc_probe = rloc . last_rloc_probe
  self . last_rloc_probe_reply = rloc . last_rloc_probe_reply
  self . last_rloc_probe_nonce = rloc . last_rloc_probe_nonce
  self . echo_nonce_capable = rloc . echo_nonce_capable
  self . recent_rloc_probe_rtts = rloc . recent_rloc_probe_rtts
  self . recent_rloc_probe_hops = rloc . recent_rloc_probe_hops
  self . recent_rloc_probe_latencies = rloc . recent_rloc_probe_latencies
  if 47 - 47: iII111i % i11iIiiIii / ooOoO0o + IiII . iII111i % iII111i
  if 18 - 18: o0oOOo0O0Ooo * OoooooooOO % i1IIi
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 17 - 17: iII111i . o0oOOo0O0Ooo / II111iiii % Oo0Ooo
  if 1 - 1: OOooOOo % o0oOOo0O0Ooo * o0oOOo0O0Ooo / oO0o
 def print_recent_rloc_probe_rtts ( self ) :
  oO0 = str ( self . recent_rloc_probe_rtts )
  oO0 = oO0 . replace ( "-1" , "?" )
  return ( oO0 )
  if 82 - 82: I1Ii111 % II111iiii
  if 10 - 10: II111iiii * Ii1I % IiII + I11i
 def compute_rloc_probe_rtt ( self ) :
  i11iII11I1III = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  i1i11 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ i11iII11I1III ] + i1i11 [ 0 : - 1 ]
  if 30 - 30: i1IIi + OOooOOo + Oo0Ooo % iII111i % O0 + i1IIi
  if 45 - 45: ooOoO0o
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 89 - 89: iIii1I11I1II1 . I1Ii111
  if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
 def print_recent_rloc_probe_hops ( self ) :
  O0ooo = str ( self . recent_rloc_probe_hops )
  return ( O0ooo )
  if 33 - 33: Ii1I
  if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 40 - 40: I1IiiI / OOooOOo * Ii1I
  if ( from_ttl < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   ooO0oiIi11 = "!"
  else :
   ooO0oiIi11 = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 59 - 59: O0 . IiII - O0 . OoO0O00 . I1ii11iIi11i . o0oOOo0O0Ooo
   if 86 - 86: iIii1I11I1II1 % O0 . o0oOOo0O0Ooo + I1Ii111 * OoOoOO00
  i11iII11I1III = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + ooO0oiIi11
  i1i11 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ i11iII11I1III ] + i1i11 [ 0 : - 1 ]
  if 25 - 25: I1IiiI
  if 10 - 10: II111iiii + i1IIi * I1IiiI * ooOoO0o
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  iI1O000 = lisp_decode_telemetry ( json_telemetry )
  if 24 - 24: O0 % OOooOOo - OoooooooOO
  ii1i111 = round ( float ( iI1O000 [ "etr-in" ] ) - float ( iI1O000 [ "itr-out" ] ) , 3 )
  O0oO0OOo000o = round ( float ( iI1O000 [ "itr-in" ] ) - float ( iI1O000 [ "etr-out" ] ) , 3 )
  if 2 - 2: O0
  i11iII11I1III = self . rloc_probe_latency
  self . rloc_probe_latency = str ( ii1i111 ) + "/" + str ( O0oO0OOo000o )
  i1i11 = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ i11iII11I1III ] + i1i11 [ 0 : - 1 ]
  if 48 - 48: i1IIi . Ii1I + i1IIi
  if 65 - 65: OoooooooOO . OOooOOo
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 83 - 83: I1Ii111 . oO0o - O0
  if 32 - 32: O0 % O0
 def print_recent_rloc_probe_latencies ( self ) :
  O0Oo = str ( self . recent_rloc_probe_latencies )
  return ( O0Oo )
  if 5 - 5: oO0o % Ii1I % I1ii11iIi11i
  if 61 - 61: OoOoOO00 + ooOoO0o + I1Ii111 + I1Ii111 % oO0o * i11iIiiIii
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  iIIiI11 = self
  while ( True ) :
   if ( iIIiI11 . last_rloc_probe_nonce == nonce ) : break
   iIIiI11 = iIIiI11 . next_rloc
   if ( iIIiI11 == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 60 - 60: OoOoOO00 . ooOoO0o
    return
    if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
    if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
    if 71 - 71: I1IiiI / O0 * i1IIi . i1IIi + Oo0Ooo
    if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
    if 11 - 11: OOooOOo
    if 25 - 25: i1IIi
  iIIiI11 . last_rloc_probe_reply = ts
  iIIiI11 . compute_rloc_probe_rtt ( )
  O0oo000 = iIIiI11 . print_state_change ( "up" )
  if ( iIIiI11 . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( iIIiI11 . rloc , True )
   iIIiI11 . state = LISP_RLOC_UP_STATE
   iIIiI11 . last_state_change = lisp_get_timestamp ( )
   I1I1i1I11I = lisp_map_cache . lookup_cache ( eid , True )
   if ( I1I1i1I11I ) : lisp_write_ipc_map_cache ( True , I1I1i1I11I )
   if 38 - 38: OoooooooOO % O0 % i11iIiiIii - I1ii11iIi11i
   if 22 - 22: I1ii11iIi11i - i1IIi / OOooOOo . o0oOOo0O0Ooo . oO0o
   if 9 - 9: ooOoO0o - I1Ii111 + IiII . iII111i
   if 52 - 52: I1Ii111 + oO0o % II111iiii - i1IIi
   if 32 - 32: I1Ii111 % ooOoO0o + I1Ii111 / I1ii11iIi11i - o0oOOo0O0Ooo + ooOoO0o
  iIIiI11 . store_rloc_probe_hops ( hc , ttl )
  if 46 - 46: OoO0O00 % OoO0O00 . O0 + II111iiii
  if 42 - 42: OOooOOo * I1Ii111
  if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
  if 91 - 91: iII111i . OoooooooOO
  if ( jt ) : iIIiI11 . store_rloc_probe_latencies ( jt )
  if 90 - 90: i11iIiiIii - I1IiiI
  II1iii1I1 = bold ( "RLOC-probe reply" , False )
  O00oO000Oo0 = iIIiI11 . rloc . print_address_no_iid ( )
  I11i11IIIII = bold ( str ( iIIiI11 . print_rloc_probe_rtt ( ) ) , False )
  III1ii = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 53 - 53: Ii1I / o0oOOo0O0Ooo * I1IiiI / i1IIi / iII111i + iII111i
  O0O0O0ooOoOo = ""
  if ( iIIiI11 . rloc_next_hop != None ) :
   oooOo , ooOOOo = iIIiI11 . rloc_next_hop
   O0O0O0ooOoOo = ", nh {}({})" . format ( ooOOOo , oooOo )
   if 93 - 93: I1ii11iIi11i % O0 + I11i
   if 31 - 31: OOooOOo + O0 * OOooOOo
  o0OooOoO0O0 = bold ( iIIiI11 . print_rloc_probe_latency ( ) , False )
  o0OooOoO0O0 = ", latency {}" . format ( o0OooOoO0O0 ) if jt else ""
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
  oOO = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( II1iii1I1 , red ( O00oO000Oo0 , False ) , III1ii , oOO ,
  # i11iIiiIii / I11i
 O0oo000 , I11i11IIIII , O0O0O0ooOoOo , str ( hc ) + "/" + str ( ttl ) , o0OooOoO0O0 ) )
  if 54 - 54: OOooOOo / Oo0Ooo % o0oOOo0O0Ooo % I1IiiI + I11i
  if ( iIIiI11 . rloc_next_hop == None ) : return
  if 45 - 45: OOooOOo . I1ii11iIi11i % oO0o % I1Ii111
  if 59 - 59: i1IIi * i1IIi % Oo0Ooo
  if 62 - 62: OoOoOO00 . iII111i + OoooooooOO / I1ii11iIi11i * O0 % I1IiiI
  if 79 - 79: ooOoO0o
  iIIiI11 = None
  o0o0oo000Oo = None
  while ( True ) :
   iIIiI11 = self if iIIiI11 == None else iIIiI11 . next_rloc
   if ( iIIiI11 == None ) : break
   if ( iIIiI11 . up_state ( ) == False ) : continue
   if ( iIIiI11 . rloc_probe_rtt == - 1 ) : continue
   if ( iIIiI11 . last_rloc_probe_nonce != nonce ) : continue
   if 95 - 95: ooOoO0o . I11i + iIii1I11I1II1 . iII111i * i11iIiiIii
   if ( o0o0oo000Oo == None ) : o0o0oo000Oo = iIIiI11
   if ( iIIiI11 . rloc_probe_rtt < o0o0oo000Oo . rloc_probe_rtt ) : o0o0oo000Oo = iIIiI11
   if 34 - 34: IiII / I1Ii111 + O0 / OoO0O00
   if 96 - 96: I1Ii111 % o0oOOo0O0Ooo + OoO0O00 - ooOoO0o
  if ( o0o0oo000Oo != None ) :
   oooOo , ooOOOo = o0o0oo000Oo . rloc_next_hop
   O0O0O0ooOoOo = bold ( "nh {}({})" . format ( ooOOOo , oooOo ) , False )
   lprint ( "    Install forwarding host-route via best {}" . format ( O0O0O0ooOoOo ) )
   lisp_install_host_route ( O00oO000Oo0 , None , False )
   lisp_install_host_route ( O00oO000Oo0 , ooOOOo , True )
   if 38 - 38: OOooOOo . O0
   if 42 - 42: OoooooooOO / I1IiiI / o0oOOo0O0Ooo . I1ii11iIi11i . OoO0O00 % II111iiii
   if 55 - 55: o0oOOo0O0Ooo
 def add_to_rloc_probe_list ( self , eid , group ) :
  O00oO000Oo0 = self . rloc . print_address_no_iid ( )
  I1I1I1 = self . translated_port
  if 87 - 87: ooOoO0o - IiII % Ii1I
  if 76 - 76: I11i - iIii1I11I1II1 - i1IIi + i1IIi
  if 60 - 60: I11i + OOooOOo - o0oOOo0O0Ooo
  if 64 - 64: II111iiii / iII111i * OoOoOO00 / OOooOOo / Ii1I
  if 19 - 19: OoOoOO00 % I1Ii111
  if ( I1I1I1 != 0 ) :
   IIIiiIiiiI1 = O00oO000Oo0 + ":" + str ( I1I1I1 )
   if ( O00oO000Oo0 in lisp_rloc_probe_list ) :
    lisp_rloc_probe_list [ IIIiiIiiiI1 ] = lisp_rloc_probe_list [ O00oO000Oo0 ]
    lisp_rloc_probe_list . pop ( O00oO000Oo0 )
    if 77 - 77: I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
   O00oO000Oo0 = IIIiiIiiiI1
   if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
   if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
   if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
   if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
   if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
  if ( O00oO000Oo0 not in lisp_rloc_probe_list ) : lisp_rloc_probe_list [ O00oO000Oo0 ] = [ ]
  if 50 - 50: IiII . OOooOOo + I1ii11iIi11i - OoooooooOO
  if 2 - 2: o0oOOo0O0Ooo % ooOoO0o / O0 / i11iIiiIii
  if 91 - 91: II111iiii * o0oOOo0O0Ooo
  if 20 - 20: iIii1I11I1II1 % Oo0Ooo * OoOoOO00 % IiII
  if 93 - 93: I11i * iIii1I11I1II1 * oO0o
  if ( group . is_null ( ) ) : group . instance_id = 0
  if 74 - 74: I1IiiI
  I1i11111Iiii = None
  for I1I1 , oOO , II11iIIii in lisp_rloc_probe_list [ O00oO000Oo0 ] :
   if ( oOO . is_exact_match ( eid ) and II11iIIii . is_exact_match ( group ) ) :
    if ( I1I1 == self ) : return
    self . copy_rloc_probe_recents ( I1I1 )
    self . uptime = I1I1 . uptime
    I1i11111Iiii = [ I1I1 , oOO , II11iIIii ]
    break
    if 13 - 13: i1IIi % i1IIi % ooOoO0o + IiII * II111iiii * OOooOOo
    if 66 - 66: iIii1I11I1II1
    if 92 - 92: OOooOOo * o0oOOo0O0Ooo - IiII
    if 83 - 83: OoO0O00 % I1IiiI % OOooOOo / oO0o + I1IiiI
    if 94 - 94: OoOoOO00 . O0
    if 86 - 86: oO0o % Oo0Ooo . OoooooooOO / OOooOOo / i1IIi
  if ( I1i11111Iiii != None ) :
   lisp_rloc_probe_list [ O00oO000Oo0 ] . remove ( I1i11111Iiii )
   if 65 - 65: Ii1I . OoooooooOO % IiII - o0oOOo0O0Ooo . OOooOOo . II111iiii
   if 100 - 100: ooOoO0o / Oo0Ooo + I1ii11iIi11i + OoooooooOO
   if 100 - 100: I11i . OOooOOo - II111iiii % I11i % iIii1I11I1II1
   if 4 - 4: o0oOOo0O0Ooo . iII111i / O0
   if 13 - 13: iII111i / IiII
  lisp_rloc_probe_list [ O00oO000Oo0 ] . append ( [ self , eid , group ] )
  if 28 - 28: iII111i
  if 97 - 97: iIii1I11I1II1
 def delete_from_rloc_probe_list ( self , eid , group ) :
  O00oO000Oo0 = self . rloc . print_address_no_iid ( )
  I1I1I1 = self . translated_port
  if ( I1I1I1 != 0 ) : O00oO000Oo0 += ":" + str ( I1I1I1 )
  if ( O00oO000Oo0 not in lisp_rloc_probe_list ) : return
  if 18 - 18: OOooOOo
  Ooooo000 = [ ]
  for iIiiI11II11i in lisp_rloc_probe_list [ O00oO000Oo0 ] :
   if ( iIiiI11II11i [ 0 ] != self ) : continue
   if ( iIiiI11II11i [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( iIiiI11II11i [ 2 ] . is_exact_match ( group ) == False ) : continue
   Ooooo000 = iIiiI11II11i
   break
   if 13 - 13: iIii1I11I1II1 - I1IiiI % o0oOOo0O0Ooo * iIii1I11I1II1
  if ( Ooooo000 == [ ] ) : return
  if 99 - 99: OoooooooOO / II111iiii . I1Ii111
  try :
   lisp_rloc_probe_list [ O00oO000Oo0 ] . remove ( Ooooo000 )
   if ( lisp_rloc_probe_list [ O00oO000Oo0 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( O00oO000Oo0 )
    if 62 - 62: OOooOOo . iII111i . I1ii11iIi11i
  except :
   return
   if 23 - 23: O0
   if 33 - 33: ooOoO0o - iII111i % IiII
   if 67 - 67: II111iiii
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  i11IiIIi11I = ""
  iIIiI11 = self
  while ( True ) :
   ooOO0 = iIIiI11 . last_rloc_probe
   if ( ooOO0 == None ) : ooOO0 = 0
   IIIiIii = iIIiI11 . last_rloc_probe_reply
   if ( IIIiIii == None ) : IIIiIii = 0
   I11i11IIIII = iIIiI11 . print_rloc_probe_rtt ( )
   OOo0oOO0o0oo0 = space ( 4 )
   if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
   if ( iIIiI11 . rloc_next_hop == None ) :
    i11IiIIi11I += "RLOC-Probing:\n"
   else :
    oooOo , ooOOOo = iIIiI11 . rloc_next_hop
    i11IiIIi11I += "RLOC-Probing for nh {}({}):\n" . format ( ooOOOo , oooOo )
    if 67 - 67: I1Ii111
    if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
   i11IiIIi11I += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( OOo0oOO0o0oo0 , lisp_print_elapsed ( ooOO0 ) ,
   # I11i - Ii1I / OOooOOo . I1ii11iIi11i
 OOo0oOO0o0oo0 , lisp_print_elapsed ( IIIiIii ) , I11i11IIIII )
   if 21 - 21: oO0o + O0 % ooOoO0o
   if ( trailing_linefeed ) : i11IiIIi11I += "\n"
   if 32 - 32: OoOoOO00 % IiII % OoO0O00
   iIIiI11 = iIIiI11 . next_rloc
   if ( iIIiI11 == None ) : break
   i11IiIIi11I += "\n"
   if 95 - 95: ooOoO0o
  return ( i11IiIIi11I )
  if 47 - 47: I1IiiI * i11iIiiIii / I1IiiI / iIii1I11I1II1 - Ii1I
  if 25 - 25: oO0o / i11iIiiIii + i11iIiiIii % IiII - o0oOOo0O0Ooo
 def get_encap_keys ( self ) :
  I1I1I1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 97 - 97: I1ii11iIi11i % iII111i * ooOoO0o % OOooOOo . I1IiiI - i11iIiiIii
  O00oO000Oo0 = self . rloc . print_address_no_iid ( ) + ":" + I1I1I1
  if 2 - 2: IiII . o0oOOo0O0Ooo % II111iiii
  try :
   O0o0O0 = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ]
   if ( O0o0O0 [ 1 ] ) : return ( O0o0O0 [ 1 ] . encrypt_key , O0o0O0 [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 69 - 69: Ii1I
   if 75 - 75: I1IiiI
   if 55 - 55: i11iIiiIii - I1IiiI . oO0o - OoooooooOO
 def rloc_recent_rekey ( self ) :
  I1I1I1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 44 - 44: I1Ii111
  O00oO000Oo0 = self . rloc . print_address_no_iid ( ) + ":" + I1I1I1
  if 98 - 98: I1IiiI % OOooOOo % iII111i
  try :
   OoOOooOOoo = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ] [ 1 ]
   if ( OoOOooOOoo == None ) : return ( False )
   if ( OoOOooOOoo . last_rekey == None ) : return ( True )
   return ( time . time ( ) - OoOOooOOoo . last_rekey < 1 )
  except :
   return ( False )
   if 15 - 15: OoO0O00
   if 52 - 52: II111iiii / ooOoO0o
   if 23 - 23: i11iIiiIii % OoO0O00 - o0oOOo0O0Ooo + OoooooooOO
 def refresh_decent_nat_rloc ( self , lisp_sockets , eid ) :
  iIiIIIIIii = self . last_state_change
  if ( iIiIIIIIii == None ) : return
  if ( ( time . time ( ) - iIiIIIIIii ) <= 60 ) : return
  if 12 - 12: Ii1I / I1IiiI . oO0o . I1IiiI + ooOoO0o - II111iiii
  oOO = green ( eid . print_address ( ) , False )
  I1I1 = red ( self . rloc . print_address_no_iid ( ) , False )
  IIi = blue ( self . rloc_name , False )
  lprint ( "Refresh map-cache for {} for RLOC {}, {}" . format ( oOO , I1I1 , IIi ) )
  if 6 - 6: Oo0Ooo + Oo0Ooo - OoOoOO00 - II111iiii
  lisp_send_map_request ( lisp_sockets , 0 , None , eid , None )
  if 25 - 25: i11iIiiIii + II111iiii * OOooOOo % OOooOOo
  if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
 def get_rle ( self , rloc ) :
  if ( self . rle == None ) : return ( None )
  for Ii1111iiIii in self . rle . rle_nodes :
   I1I1 = Ii1111iiIii . rloc . rloc
   if ( rloc . is_exact_match ( I1I1 ) ) : return ( Ii1111iiIii . rloc )
   if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
  return ( None )
  if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
  if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
  if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
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
  if 92 - 92: I11i
  if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
 def print_mapping ( self , eid_indent , rloc_indent ) :
  iIiIIIIIii = lisp_print_elapsed ( self . uptime )
  oo0oOooo0O = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 98 - 98: iII111i % IiII + OoO0O00
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , oo0oOooo0O , iIiIIIIIii ,
 len ( self . rloc_set ) ) )
  for iIIiI11 in self . rloc_set : iIIiI11 . print_rloc ( rloc_indent )
  if 23 - 23: OOooOOo
  if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 99 - 99: II111iiii + O0
  if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
 def print_ttl ( self ) :
  i1i = self . map_cache_ttl
  if ( i1i == None ) : return ( "forever" )
  if 88 - 88: Oo0Ooo . iII111i
  if ( i1i >= 3600 ) :
   if ( ( i1i % 3600 ) == 0 ) :
    i1i = str ( old_div ( i1i , 3600 ) ) + " hours"
   else :
    i1i = str ( i1i * 60 ) + " mins"
    if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
  elif ( i1i >= 60 ) :
   if ( ( i1i % 60 ) == 0 ) :
    i1i = str ( old_div ( i1i , 60 ) ) + " mins"
   else :
    i1i = str ( i1i ) + " secs"
    if 9 - 9: OoOoOO00 % i1IIi + IiII
  else :
   i1i = str ( i1i ) + " secs"
   if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
  return ( i1i )
  if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
  if 95 - 95: ooOoO0o
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
  if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 32 - 32: OoOoOO00 % i11iIiiIii
  if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
 def refresh_multicast ( self ) :
  if 44 - 44: I1Ii111 + ooOoO0o
  if 15 - 15: I11i + OoO0O00 + OoOoOO00
  if 100 - 100: I1Ii111
  if 78 - 78: OoOoOO00
  if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
  o0oOOOO0 = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  IIii1ii11ii1I = ( o0oOOOO0 in [ 0 , 1 , 2 ] )
  if ( IIii1ii11ii1I == False ) : return ( False )
  if 26 - 26: OoooooooOO % I1ii11iIi11i % OoO0O00 . I1Ii111 - I1IiiI + o0oOOo0O0Ooo
  if 8 - 8: I1IiiI * o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
  if 64 - 64: ooOoO0o
  if 23 - 23: Oo0Ooo . OoO0O00
  iI1i1iIIIII = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( iI1i1iIIIII ) : return ( False )
  if 19 - 19: oO0o - I1ii11iIi11i + iII111i . o0oOOo0O0Ooo . OoO0O00 * Oo0Ooo
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 39 - 39: i11iIiiIii - iII111i / O0 % Oo0Ooo
  if 40 - 40: O0 * Oo0Ooo % o0oOOo0O0Ooo / OoooooooOO
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  o0oOOOO0 = time . time ( ) - self . last_refresh_time
  if ( o0oOOOO0 >= self . map_cache_ttl ) : return ( True )
  if 94 - 94: iII111i
  if 79 - 79: o0oOOo0O0Ooo / I1ii11iIi11i . iII111i . II111iiii + I1ii11iIi11i * I11i
  if 49 - 49: Ii1I * OoooooooOO * i1IIi % OoOoOO00
  if 83 - 83: iIii1I11I1II1 - i1IIi - Ii1I % iII111i
  if 69 - 69: I1Ii111 * oO0o * I1IiiI
  Ooo0 = self . map_cache_ttl - ( old_div ( self . map_cache_ttl , 10 ) )
  if ( o0oOOOO0 >= Ooo0 ) : return ( True )
  return ( False )
  if 33 - 33: I11i % OoO0O00 % o0oOOo0O0Ooo
  if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  o0oOOOO0 = time . time ( ) - self . stats . last_increment
  return ( o0oOOOO0 <= 60 )
  if 52 - 52: OoooooooOO
  if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
  if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 86 - 86: Oo0Ooo / OoO0O00
  if 78 - 78: I1IiiI * I1IiiI
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for iIIiI11 in self . best_rloc_set :
   if ( iIIiI11 . rloc . is_null ( ) and iIIiI11 . rle != None ) :
    if 13 - 13: oO0o
    if 43 - 43: oO0o / Ii1I % OOooOOo
    if 45 - 45: II111iiii
    if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
    for Ii1111iiIii in iIIiI11 . rle . rle_forwarding_list :
     Ii1111iiIii . rloc . delete_from_rloc_probe_list ( self . eid , self . group )
     if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
   else :
    iIIiI11 . delete_from_rloc_probe_list ( self . eid , self . group )
    if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
    if 43 - 43: OOooOOo . O0
    if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
    if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
 def build_best_rloc_set ( self ) :
  Oo0o0 = self . best_rloc_set
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 10 - 10: OoO0O00
  if 72 - 72: O0 - I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - i1IIi
  if 98 - 98: Oo0Ooo * ooOoO0o * I11i + oO0o - O0
  if 3 - 3: i1IIi + OoOoOO00 - OoOoOO00
  OOOO0i111i = 256
  for iIIiI11 in self . rloc_set :
   if ( iIIiI11 . up_state ( ) ) : OOOO0i111i = min ( iIIiI11 . priority , OOOO0i111i )
   if 56 - 56: ooOoO0o - OoooooooOO - i11iIiiIii
   if 27 - 27: Ii1I . OoOoOO00 % oO0o % o0oOOo0O0Ooo / i11iIiiIii - iIii1I11I1II1
   if 77 - 77: o0oOOo0O0Ooo . OoOoOO00 % Ii1I
   if 94 - 94: I11i / IiII - OoOoOO00 % OoO0O00 % i11iIiiIii . Ii1I
   if 26 - 26: i1IIi - Ii1I * I1IiiI
   if 74 - 74: I1ii11iIi11i * oO0o * i1IIi % oO0o % I11i . i1IIi
   if 90 - 90: I1Ii111 + O0
   if 100 - 100: II111iiii - I1Ii111 % OoO0O00
   if 67 - 67: oO0o . I1IiiI % iIii1I11I1II1 + o0oOOo0O0Ooo / I1ii11iIi11i * II111iiii
   if 1 - 1: OoooooooOO / I1ii11iIi11i - O0
  for iIIiI11 in self . rloc_set :
   if ( iIIiI11 . priority <= OOOO0i111i ) :
    if ( iIIiI11 . unreach_state ( ) and iIIiI11 . last_rloc_probe == None ) :
     iIIiI11 . last_rloc_probe = lisp_get_timestamp ( )
     if 72 - 72: Oo0Ooo * iII111i - I11i
    self . best_rloc_set . append ( iIIiI11 )
    if 81 - 81: I1Ii111
    if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
    if 46 - 46: OOooOOo * iIii1I11I1II1
    if 33 - 33: OoO0O00 * II111iiii / i1IIi
    if 93 - 93: I1Ii111 % I11i
    if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
    if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
    if 49 - 49: IiII - OOooOOo * OOooOOo . O0
  for iIIiI11 in Oo0o0 :
   if ( iIIiI11 . priority < OOOO0i111i ) : continue
   iIIiI11 . delete_from_rloc_probe_list ( self . eid , self . group )
   if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
   if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
   if 61 - 61: OoO0O00
   if 100 - 100: OoOoOO00
   if ( iIIiI11 . rle != None ) :
    for Ii1111iiIii in iIIiI11 . rle . rle_forwarding_list :
     Ii1111iiIii . rloc . delete_from_rloc_probe_list ( self . eid , self . group )
     if 97 - 97: OoooooooOO
     if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
     if 35 - 35: iII111i % OoO0O00 * O0
     if 37 - 37: OOooOOo
  for iIIiI11 in self . best_rloc_set :
   if ( iIIiI11 . rloc . is_null ( ) ) :
    if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
    if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
    if 75 - 75: OoooooooOO
    if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
    if 23 - 23: o0oOOo0O0Ooo * II111iiii - Oo0Ooo - I1IiiI
    if ( iIIiI11 . rle != None and iIIiI11 . rle . rle_forwarding_list != [ ] ) :
     for Ii1111iiIii in iIIiI11 . rle . rle_forwarding_list :
      Ii1111iiIii . rloc . add_to_rloc_probe_list ( self . eid , self . group )
      if 86 - 86: I1IiiI - II111iiii * II111iiii * oO0o % OoooooooOO * OoOoOO00
      if 93 - 93: I1IiiI + OoO0O00 % O0 - ooOoO0o * i1IIi
    continue
    if 60 - 60: I1IiiI
   iIIiI11 . add_to_rloc_probe_list ( self . eid , self . group )
   if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
   if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
   if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  OO0Oo00OO0oo = lisp_packet . packet
  I1Iii = lisp_packet . inner_version
  iI = len ( self . best_rloc_set )
  if ( iI == 0 ) :
   self . stats . increment ( len ( OO0Oo00OO0oo ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 5 - 5: II111iiii
   if 100 - 100: O0 * iIii1I11I1II1 - OoooooooOO
  iIiI = 4 if lisp_load_split_pings else 0
  iiIIII11iIii = lisp_packet . hash_ports ( )
  if ( I1Iii == 4 ) :
   for o000o0O0Oo00 in range ( 8 + iIiI ) :
    iiIIII11iIii = iiIIII11iIii ^ struct . unpack ( "B" , OO0Oo00OO0oo [ o000o0O0Oo00 + 12 : o000o0O0Oo00 + 13 ] ) [ 0 ]
    if 16 - 16: OoO0O00 . Oo0Ooo + oO0o + Ii1I - OoooooooOO . ooOoO0o
  elif ( I1Iii == 6 ) :
   for o000o0O0Oo00 in range ( 0 , 32 + iIiI , 4 ) :
    iiIIII11iIii = iiIIII11iIii ^ struct . unpack ( "I" , OO0Oo00OO0oo [ o000o0O0Oo00 + 8 : o000o0O0Oo00 + 12 ] ) [ 0 ]
    if 44 - 44: O0
   iiIIII11iIii = ( iiIIII11iIii >> 16 ) + ( iiIIII11iIii & 0xffff )
   iiIIII11iIii = ( iiIIII11iIii >> 8 ) + ( iiIIII11iIii & 0xff )
  else :
   for o000o0O0Oo00 in range ( 0 , 12 + iIiI , 4 ) :
    iiIIII11iIii = iiIIII11iIii ^ struct . unpack ( "I" , OO0Oo00OO0oo [ o000o0O0Oo00 : o000o0O0Oo00 + 4 ] ) [ 0 ]
    if 91 - 91: ooOoO0o * OoOoOO00 * i1IIi * o0oOOo0O0Ooo - ooOoO0o % Ii1I
    if 46 - 46: O0 / iIii1I11I1II1
    if 65 - 65: OOooOOo
  if ( lisp_data_plane_logging ) :
   O0Ooo00OOOo0 = [ ]
   for I1I1 in self . best_rloc_set :
    if ( I1I1 . rloc . is_null ( ) ) : continue
    O0Ooo00OOOo0 . append ( [ I1I1 . rloc . print_address_no_iid ( ) , I1I1 . print_state ( ) ] )
    if 77 - 77: iIii1I11I1II1 - OoO0O00 - i1IIi
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( iiIIII11iIii ) , iiIIII11iIii % iI , red ( str ( O0Ooo00OOOo0 ) , False ) ) )
   if 21 - 21: oO0o . Oo0Ooo . IiII . ooOoO0o
   if 88 - 88: i11iIiiIii . I1Ii111 . O0 % II111iiii - OoO0O00
   if 33 - 33: I1ii11iIi11i + OoooooooOO % OoO0O00
   if 1 - 1: I1Ii111 + ooOoO0o . i1IIi + O0
   if 15 - 15: OoooooooOO - ooOoO0o + ooOoO0o / I1Ii111 + IiII . II111iiii
   if 1 - 1: iIii1I11I1II1
  iIIiI11 = self . best_rloc_set [ iiIIII11iIii % iI ]
  if 69 - 69: I1Ii111 * ooOoO0o % iIii1I11I1II1 * OoooooooOO + i1IIi
  if 14 - 14: i1IIi * iIii1I11I1II1 . iII111i % i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o
  if 100 - 100: I1ii11iIi11i
  if 21 - 21: o0oOOo0O0Ooo % I1ii11iIi11i / I1IiiI / o0oOOo0O0Ooo
  if ( lisp_decent_nat and iIIiI11 . stats . packet_count == 0 ) :
   I1I1 = self . find_rtr_rloc ( )
   if ( I1I1 != None ) : iIIiI11 = I1I1
   if 68 - 68: I11i * OoO0O00
   if 92 - 92: iIii1I11I1II1 - oO0o / o0oOOo0O0Ooo . I11i - iIii1I11I1II1 / OoOoOO00
   if 20 - 20: o0oOOo0O0Ooo
   if 65 - 65: OOooOOo / OoOoOO00
   if 31 - 31: OoOoOO00 * I1IiiI + i11iIiiIii % OOooOOo * OoOoOO00
   if 36 - 36: I1Ii111 * OoO0O00
  oo000O0o = lisp_get_echo_nonce ( iIIiI11 . rloc , None )
  if ( oo000O0o ) :
   oo000O0o . change_state ( iIIiI11 )
   if ( iIIiI11 . no_echoed_nonce_state ( ) ) :
    oo000O0o . request_nonce_sent = None
    if 84 - 84: OoOoOO00
    if 80 - 80: oO0o
    if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
    if 92 - 92: iII111i
    if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
    if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
  if ( iIIiI11 . up_state ( ) == False ) :
   o0o00Oo0o = iiIIII11iIii % iI
   o00O = ( o0o00Oo0o + 1 ) % iI
   while ( o00O != o0o00Oo0o ) :
    iIIiI11 = self . best_rloc_set [ o00O ]
    if ( iIIiI11 . up_state ( ) ) : break
    o00O = ( o00O + 1 ) % iI
    if 10 - 10: I1IiiI
   if ( o00O == o0o00Oo0o ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 81 - 81: I11i * oO0o . I1Ii111
    if 51 - 51: ooOoO0o / OoOoOO00 % OOooOOo * i11iIiiIii
    if 21 - 21: I1ii11iIi11i / I1ii11iIi11i % iII111i . Oo0Ooo * Oo0Ooo . i11iIiiIii
    if 73 - 73: i1IIi - i11iIiiIii - Ii1I % oO0o
    if 99 - 99: ooOoO0o % I1IiiI
    if 11 - 11: OoO0O00 - I1Ii111 . Ii1I + OoooooooOO
  if ( iIIiI11 . rle_name and iIIiI11 . rle == None ) :
   if ( iIIiI11 . rle_name in lisp_rle_list ) :
    iIIiI11 . rle = lisp_rle_list [ iIIiI11 . rle_name ]
    if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
    if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
  if ( iIIiI11 . rle ) : return ( [ None , None , None , None , iIIiI11 . rle , None ] )
  if 58 - 58: Ii1I / Oo0Ooo % IiII
  if 33 - 33: II111iiii . OOooOOo % iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % i11iIiiIii
  if 60 - 60: iII111i . o0oOOo0O0Ooo
  if 56 - 56: I1ii11iIi11i
  iIIiI11 . stats . increment ( len ( OO0Oo00OO0oo ) )
  if 89 - 89: Oo0Ooo + I1ii11iIi11i * o0oOOo0O0Ooo * oO0o % O0 % OoO0O00
  if 70 - 70: o0oOOo0O0Ooo + O0 % I1IiiI
  if 56 - 56: Ii1I
  if 84 - 84: iII111i
  if ( iIIiI11 . elp and iIIiI11 . elp . use_elp_node ) :
   return ( [ iIIiI11 . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 21 - 21: i11iIiiIii
   if 30 - 30: OoO0O00 + OoooooooOO
   if 98 - 98: I1ii11iIi11i % I1IiiI
   if 9 - 9: o0oOOo0O0Ooo / I1Ii111 % i1IIi - OOooOOo % I1IiiI / I1ii11iIi11i
   if 66 - 66: IiII
  oOo0o0 = None if ( iIIiI11 . rloc . is_null ( ) ) else iIIiI11 . rloc
  I1I1I1 = iIIiI11 . translated_port
  oOoO0OooO0O = self . action if ( oOo0o0 == None ) else None
  if 9 - 9: I1ii11iIi11i + OoooooooOO - OoooooooOO + OoO0O00 / iIii1I11I1II1
  if 23 - 23: iII111i / iIii1I11I1II1
  if 5 - 5: O0
  if 64 - 64: i1IIi * i1IIi . iII111i - O0 - oO0o % OoooooooOO
  if 14 - 14: Ii1I % OoO0O00 % I1Ii111 * O0
  OOO0O0O = None
  if ( oo000O0o and oo000O0o . request_nonce_timeout ( ) == False ) :
   OOO0O0O = oo000O0o . get_request_or_echo_nonce ( ipc_socket , oOo0o0 )
   if 8 - 8: I1IiiI - i11iIiiIii * I1IiiI
   if 6 - 6: O0 - OoOoOO00 - i11iIiiIii / iII111i
   if 63 - 63: OOooOOo
   if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
   if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
  return ( [ oOo0o0 , I1I1I1 , OOO0O0O , oOoO0OooO0O , None , iIIiI11 ] )
  if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
  if 13 - 13: Ii1I - OoOoOO00 . Ii1I
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
  if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
  if 73 - 73: Ii1I . IiII % IiII
  if 56 - 56: I1Ii111 + iII111i + iII111i
  if 99 - 99: o0oOOo0O0Ooo % I1ii11iIi11i / Oo0Ooo . O0 + OoO0O00 * OoOoOO00
  for iIIoOo in self . rloc_set :
   for iIIiI11 in rloc_address_set :
    if ( iIIiI11 . is_exact_match ( iIIoOo . rloc ) == False ) : continue
    iIIiI11 = None
    break
    if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
   if ( iIIiI11 == rloc_address_set [ - 1 ] ) : return ( False )
   if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
  return ( True )
  if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
  if 47 - 47: II111iiii % o0oOOo0O0Ooo
 def get_rloc ( self , rloc ) :
  for iIIoOo in self . rloc_set :
   I1I1 = iIIoOo . rloc
   if ( rloc . is_exact_match ( I1I1 ) ) : return ( iIIoOo )
   if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
  return ( None )
  if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
  if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
 def get_rloc_by_interface ( self , interface ) :
  for iIIoOo in self . rloc_set :
   if ( iIIoOo . interface == interface ) : return ( iIIoOo )
   if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
  return ( None )
  if 45 - 45: OOooOOo - OOooOOo % iII111i - IiII . O0
  if 6 - 6: iIii1I11I1II1 * II111iiii / O0 % IiII - I1Ii111
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   i1I = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( i1I == None ) :
    i1I = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , i1I )
    if 64 - 64: ooOoO0o
   i1I . add_source_entry ( self )
   if 28 - 28: i11iIiiIii - IiII * I1ii11iIi11i + IiII * iII111i
   if 75 - 75: o0oOOo0O0Ooo * OoOoOO00 % I1ii11iIi11i + OOooOOo . II111iiii
   if 12 - 12: ooOoO0o
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   I1I1i1I11I = lisp_map_cache . lookup_cache ( self . group , True )
   if ( I1I1i1I11I == None ) :
    I1I1i1I11I = lisp_mapping ( self . group , self . group , [ ] )
    I1I1i1I11I . eid . copy_address ( self . group )
    I1I1i1I11I . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , I1I1i1I11I )
    if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( I1I1i1I11I . group )
   I1I1i1I11I . add_source_entry ( self )
   if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
  if 78 - 78: i1IIi
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 25 - 25: Ii1I * II111iiii / OoOoOO00
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    OoOo00 = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( OoOo00 ) )
    if 2 - 2: IiII - iIii1I11I1II1
  else :
   I1I1i1I11I = lisp_map_cache . lookup_cache ( self . group , True )
   if ( I1I1i1I11I == None ) : return
   if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
   I1I1I1i1II1 = I1I1i1I11I . lookup_source_cache ( self . eid , True )
   if ( I1I1I1i1II1 == None ) : return
   if 15 - 15: i11iIiiIii
   I1I1i1I11I . source_cache . delete_cache ( self . eid )
   if ( I1I1i1I11I . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 85 - 85: I1Ii111 + iII111i - oO0o
    if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
    if 64 - 64: OoOoOO00
    if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
  if 71 - 71: ooOoO0o
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 35 - 35: OoOoOO00
  if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
  if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  i1I1iI = "," + str ( self . secondary_iid )
  return ( prefix . replace ( i1I1iI , i1I1iI + "*" ) )
  if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
  if 89 - 89: iIii1I11I1II1 . ooOoO0o
 def increment_decap_stats ( self , packet ) :
  I1I1I1 = packet . udp_dport
  if ( I1I1I1 == LISP_DATA_PORT ) :
   iIIiI11 = self . get_rloc ( packet . outer_dest )
  else :
   if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
   if 78 - 78: OoOoOO00 % oO0o
   if 39 - 39: iIii1I11I1II1
   if 72 - 72: II111iiii + I1Ii111 / Ii1I * iIii1I11I1II1
   for iIIiI11 in self . rloc_set :
    if ( iIIiI11 . translated_port != 0 ) : break
    if 95 - 95: OoooooooOO + OOooOOo + II111iiii + IiII + OoO0O00
    if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
  if ( iIIiI11 != None ) : iIIiI11 . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 65 - 65: I1ii11iIi11i + OoOoOO00
  if 43 - 43: O0 + I11i % II111iiii
 def rtrs_in_rloc_set ( self ) :
  for iIIiI11 in self . rloc_set :
   if ( iIIiI11 . is_rtr ( ) ) : return ( True )
   if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
  return ( False )
  if 70 - 70: ooOoO0o / i1IIi - I11i - i11iIiiIii
  if 79 - 79: OoO0O00 - OoooooooOO % iII111i . O0
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 93 - 93: I1Ii111
  if 3 - 3: OoO0O00 / IiII - oO0o / oO0o
 def find_rtr_rloc ( self ) :
  if 50 - 50: II111iiii + OoOoOO00
  if 17 - 17: ooOoO0o + I1ii11iIi11i
  if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
  if 48 - 48: O0
  if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
  if 84 - 84: i11iIiiIii . OoooooooOO
  if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
  for iIIiI11 in self . rloc_set :
   if ( iIIiI11 . is_rtr ( ) and iIIiI11 . up_state ( ) ) :
    if ( iIIiI11 . stats . packet_count <= 4 ) : return ( iIIiI11 )
    if 5 - 5: Ii1I
    if 19 - 19: oO0o
  return ( None )
  if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
  if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
  if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
  if 1 - 1: OoOoOO00 / I11i
class lisp_dynamic_eid ( object ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 43 - 43: o0oOOo0O0Ooo - i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
  if 69 - 69: i11iIiiIii - iIii1I11I1II1
 def get_timeout ( self , interface ) :
  try :
   iIII1 = lisp_myinterfaces [ interface ]
   self . timeout = iIII1 . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
   if 37 - 37: I1ii11iIi11i
   if 24 - 24: O0 . I1Ii111 * i11iIiiIii
   if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
class lisp_group_mapping ( object ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 16 - 16: I11i % O0
  if 56 - 56: Ii1I * OoOoOO00 . i1IIi
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 15 - 15: I1Ii111
  if 64 - 64: OOooOOo * Oo0Ooo
  if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
  if 18 - 18: I1Ii111
  if 29 - 29: i1IIi - I1IiiI / i1IIi
  if 64 - 64: IiII
  if 69 - 69: OOooOOo . I1IiiI
  if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
  if 22 - 22: iII111i % I11i % O0 - I11i
  if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 O0o = group_mapping . group_prefix
 oo0oOooo0O = lisp_address ( LISP_AFI_NONE , group_str , 0 , O0o . instance_id )
 if ( oo0oOooo0O . afi != O0o . afi ) : return ( - 1 )
 if 50 - 50: iII111i - iII111i
 if ( oo0oOooo0O . is_more_specific ( O0o ) ) : return ( O0o . mask_len )
 return ( - 1 )
 if 61 - 61: OoO0O00 + O0 + I1IiiI * Ii1I
 if 60 - 60: iIii1I11I1II1 % ooOoO0o
 if 91 - 91: iIii1I11I1II1 / OoooooooOO - i1IIi
 if 98 - 98: OoOoOO00 / Oo0Ooo
 if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
 if 97 - 97: iIii1I11I1II1 * I1Ii111
 if 39 - 39: I1Ii111 . II111iiii
def lisp_lookup_group ( group ) :
 O0Ooo00OOOo0 = None
 for OOOOOo0oO in list ( lisp_group_mapping_list . values ( ) ) :
  OOOoOo0o0Ooo = lisp_is_group_more_specific ( group , OOOOOo0oO )
  if ( OOOoOo0o0Ooo == - 1 ) : continue
  if ( O0Ooo00OOOo0 == None or OOOoOo0o0Ooo > O0Ooo00OOOo0 . group_prefix . mask_len ) : O0Ooo00OOOo0 = OOOOOo0oO
  if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 return ( O0Ooo00OOOo0 )
 if 34 - 34: I1IiiI
 if 56 - 56: Ii1I
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 71 - 71: O0 / i1IIi
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
  if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
  if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
  if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
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
  if 86 - 86: I1Ii111 + I1ii11iIi11i
  if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
  if 69 - 69: OOooOOo
 def print_flags ( self , html ) :
  if ( html == False ) :
   i11IiIIi11I = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # i1IIi
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   I11iIIiIIiIi = self . print_flags ( False )
   I11iIIiIIiIi = I11iIIiIIiIi . split ( "-" )
   i11IiIIi11I = ""
   for ooooO0 in I11iIIiIIiIi :
    Ooo00O0O00000O = lisp_site_flags [ ooooO0 . upper ( ) ]
    Ooo00O0O00000O = Ooo00O0O00000O . format ( "" if ooooO0 . isupper ( ) else "not " )
    i11IiIIi11I += lisp_span ( ooooO0 , Ooo00O0O00000O )
    if ( ooooO0 . lower ( ) != "n" ) : i11IiIIi11I += "-"
    if 15 - 15: I1Ii111 % I1ii11iIi11i - i11iIiiIii + o0oOOo0O0Ooo
    if 1 - 1: OoooooooOO / i11iIiiIii . o0oOOo0O0Ooo
  return ( i11IiIIi11I )
  if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
  if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 64 - 64: O0 - iII111i
  if 82 - 82: O0
 def build_sort_key ( self ) :
  i11I1iIi1I1I = lisp_cache ( )
  O00O00O , OoOOooOOoo = i11I1iIi1I1I . build_key ( self . eid )
  OO00o0o0Oo00 = ""
  if ( self . group . is_null ( ) == False ) :
   O000 , OO00o0o0Oo00 = i11I1iIi1I1I . build_key ( self . group )
   OO00o0o0Oo00 = "-" + OO00o0o0Oo00 [ 0 : 12 ] + "-" + str ( O000 ) + "-" + OO00o0o0Oo00 [ 12 : : ]
   if 71 - 71: i1IIi . I1IiiI
  OoOOooOOoo = OoOOooOOoo [ 0 : 12 ] + "-" + str ( O00O00O ) + "-" + OoOOooOOoo [ 12 : : ] + OO00o0o0Oo00
  del ( i11I1iIi1I1I )
  return ( OoOOooOOoo )
  if 81 - 81: O0
  if 89 - 89: oO0o % OoOoOO00 + Oo0Ooo
 def merge_in_site_eid ( self , child ) :
  i11Ii1ii = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   i11Ii1ii = self . merge_rles_in_site_eid ( )
   if 50 - 50: OOooOOo % I1ii11iIi11i / ooOoO0o * ooOoO0o . OoO0O00 + o0oOOo0O0Ooo
   if 95 - 95: i1IIi % OoOoOO00 . OoooooooOO + I1IiiI * Oo0Ooo
   if 27 - 27: iIii1I11I1II1 / iII111i
   if 11 - 11: I1ii11iIi11i - iIii1I11I1II1
   if 15 - 15: o0oOOo0O0Ooo + OoooooooOO
   if 68 - 68: ooOoO0o / I1Ii111 * OoO0O00 + ooOoO0o / iIii1I11I1II1 . iII111i
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 91 - 91: OoO0O00
  return ( i11Ii1ii )
  if 8 - 8: oO0o
  if 96 - 96: IiII
 def copy_rloc_records ( self ) :
  I1Ii1iIIiii = [ ]
  for iIIoOo in self . registered_rlocs :
   I1Ii1iIIiii . append ( copy . deepcopy ( iIIoOo ) )
   if 13 - 13: oO0o / I1Ii111 % OOooOOo * I1ii11iIi11i
  return ( I1Ii1iIIiii )
  if 25 - 25: oO0o
  if 27 - 27: Ii1I - iII111i . OOooOOo
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for I1iOooO0o in list ( self . individual_registrations . values ( ) ) :
   if ( self . site_id != I1iOooO0o . site_id ) : continue
   if ( I1iOooO0o . registered == False ) : continue
   self . registered_rlocs += I1iOooO0o . copy_rloc_records ( )
   if 74 - 74: I1IiiI % iIii1I11I1II1 - iII111i
   if 43 - 43: OoO0O00 % OoOoOO00 . OOooOOo % ooOoO0o * OOooOOo / OoOoOO00
   if 43 - 43: I1Ii111 - OOooOOo + i11iIiiIii - OoooooooOO - iII111i
   if 46 - 46: Ii1I - ooOoO0o
   if 55 - 55: I1IiiI / Oo0Ooo
   if 30 - 30: ooOoO0o % iIii1I11I1II1 . Oo0Ooo + I1Ii111 / IiII
   if 98 - 98: i1IIi - II111iiii . i11iIiiIii * I11i / i1IIi
   if 88 - 88: OOooOOo
  I1Ii1iIIiii = [ ]
  for iIIoOo in self . registered_rlocs :
   if ( iIIoOo . rloc . is_null ( ) or len ( I1Ii1iIIiii ) == 0 ) :
    I1Ii1iIIiii . append ( iIIoOo )
    continue
    if 64 - 64: iII111i % Ii1I . I1ii11iIi11i + iII111i * I11i . i11iIiiIii
   for i1IIiiIiiIiI in I1Ii1iIIiii :
    if ( i1IIiiIiiIiI . rloc . is_null ( ) ) : continue
    if ( iIIoOo . rloc . is_exact_match ( i1IIiiIiiIiI . rloc ) ) :
     if ( iIIoOo . rloc_name == i1IIiiIiiIiI . rloc_name ) : break
     if 34 - 34: OoO0O00 * iIii1I11I1II1 . iIii1I11I1II1
     if 39 - 39: o0oOOo0O0Ooo
   if ( i1IIiiIiiIiI == I1Ii1iIIiii [ - 1 ] ) : I1Ii1iIIiii . append ( iIIoOo )
   if 29 - 29: Oo0Ooo . Oo0Ooo * OoO0O00 % Ii1I - ooOoO0o
  self . registered_rlocs = I1Ii1iIIiii
  if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
  if 79 - 79: I1IiiI
  if 37 - 37: I1Ii111 + Ii1I
  if 50 - 50: i11iIiiIii
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 57 - 57: O0 * i1IIi - I1IiiI
  if 48 - 48: IiII / iIii1I11I1II1
 def merge_rles_in_site_eid ( self ) :
  if 20 - 20: oO0o / OoooooooOO
  if 95 - 95: Oo0Ooo . i11iIiiIii
  if 50 - 50: iII111i . i11iIiiIii - i1IIi
  if 24 - 24: i11iIiiIii % iII111i . oO0o
  iiIIiI11I = { }
  for iIIoOo in self . registered_rlocs :
   if ( iIIoOo . rle == None ) : continue
   for Ii1111iiIii in iIIoOo . rle . rle_nodes :
    if ( Ii1111iiIii . rloc . rloc_name == None ) : continue
    iI1ii11Ii = Ii1111iiIii . rloc . rloc . print_address_no_iid ( ) + Ii1111iiIii . rloc . rloc_name
    if 28 - 28: II111iiii * O0 % O0 - OoooooooOO - oO0o - I1ii11iIi11i
    iiIIiI11I [ iI1ii11Ii ] = Ii1111iiIii . rloc . rloc
    if 16 - 16: I1IiiI . OoO0O00 * Ii1I / oO0o
   break
   if 27 - 27: iII111i - ooOoO0o - i11iIiiIii
   if 39 - 39: i11iIiiIii / oO0o
   if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
   if 87 - 87: I1IiiI / Ii1I
   if 54 - 54: OoooooooOO / Ii1I
  self . merge_rlocs_in_site_eid ( )
  if 26 - 26: o0oOOo0O0Ooo + OoO0O00
  if 59 - 59: Ii1I * IiII
  if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
  if 66 - 66: OoOoOO00
  if 83 - 83: OOooOOo . IiII
  if 98 - 98: i11iIiiIii
  if 74 - 74: iIii1I11I1II1 * O0 + OOooOOo . o0oOOo0O0Ooo
  if 17 - 17: I1Ii111
  OOo0o0o0o00 = [ ]
  for iIIoOo in self . registered_rlocs :
   if ( self . registered_rlocs . index ( iIIoOo ) == 0 ) :
    OOo0o0o0o00 . append ( iIIoOo )
    continue
    if 75 - 75: Ii1I * Ii1I + OOooOOo + OOooOOo
   if ( iIIoOo . rle == None ) : OOo0o0o0o00 . append ( iIIoOo )
   if 41 - 41: OoO0O00
  self . registered_rlocs = OOo0o0o0o00
  if 40 - 40: OoO0O00
  if 14 - 14: O0 - O0 * Ii1I
  if 87 - 87: OoooooooOO - Ii1I * II111iiii % I1Ii111
  if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
  if 65 - 65: I1Ii111 + OOooOOo
  if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
  if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
  IIiiiI = lisp_rle ( "" )
  O0OoO0o00ooo = { }
  oOo = None
  for I1iOooO0o in list ( self . individual_registrations . values ( ) ) :
   if ( I1iOooO0o . registered == False ) : continue
   OO0IIIi1i1ii = I1iOooO0o . registered_rlocs [ 0 ] . rle
   if ( OO0IIIi1i1ii == None ) : continue
   if 23 - 23: IiII
   oOo = I1iOooO0o . registered_rlocs [ 0 ] . rloc_name
   if ( oOo == None ) : oOo = ""
   for II11iIII in OO0IIIi1i1ii . rle_nodes :
    iI1ii11Ii = II11iIII . rloc . rloc . print_address_no_iid ( ) + oOo
    if ( iI1ii11Ii in O0OoO0o00ooo ) : break
    if 54 - 54: i1IIi - I11i % Oo0Ooo / i11iIiiIii
    Ii1111iiIii = lisp_rle_node ( )
    Ii1111iiIii . rloc . rloc . copy_address ( II11iIII . rloc . rloc )
    Ii1111iiIii . level = II11iIII . level
    Ii1111iiIii . rloc . rloc_name = oOo
    IIiiiI . rle_nodes . append ( Ii1111iiIii )
    O0OoO0o00ooo [ iI1ii11Ii ] = II11iIII . rloc . rloc
    if 83 - 83: I1IiiI * OoooooooOO % I1IiiI - oO0o
    if 93 - 93: I1ii11iIi11i - OOooOOo - II111iiii * OoO0O00 . O0 - ooOoO0o
    if 53 - 53: OoO0O00 / i11iIiiIii . OoooooooOO
    if 84 - 84: I1ii11iIi11i
    if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
    if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
  if ( len ( IIiiiI . rle_nodes ) == 0 ) : IIiiiI = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = IIiiiI
   if ( oOo ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
   if 67 - 67: i1IIi * I1Ii111 * O0
   if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
   if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
   if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
  if ( list ( iiIIiI11I . keys ( ) ) == list ( O0OoO0o00ooo . keys ( ) ) ) : return ( False )
  if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # i11iIiiIii . O0 - OoOoOO00 * I1Ii111 + OoO0O00
 list ( iiIIiI11I . keys ( ) ) , list ( O0OoO0o00ooo . keys ( ) ) ) )
  if 33 - 33: IiII % ooOoO0o - OoooooooOO / II111iiii . OOooOOo
  return ( True )
  if 55 - 55: Oo0Ooo . OOooOOo + I1Ii111 * OOooOOo * i1IIi
  if 48 - 48: iII111i / i11iIiiIii % I1IiiI * iIii1I11I1II1 % Ii1I
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   OOoI1i1i1iIi = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( OOoI1i1i1iIi == None ) :
    OOoI1i1i1iIi = lisp_site_eid ( self . site )
    OOoI1i1i1iIi . eid . copy_address ( self . group )
    OOoI1i1i1iIi . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , OOoI1i1i1iIi )
    if 70 - 70: I1Ii111
    if 4 - 4: OoooooooOO - o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo
    if 96 - 96: OOooOOo
    if 10 - 10: o0oOOo0O0Ooo / OoOoOO00
    if 87 - 87: IiII
    OOoI1i1i1iIi . parent_for_more_specifics = self . parent_for_more_specifics
    if 10 - 10: OOooOOo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( OOoI1i1i1iIi . group )
   OOoI1i1i1iIi . add_source_entry ( self )
   if 72 - 72: o0oOOo0O0Ooo - oO0o - i1IIi * I1IiiI - II111iiii / Oo0Ooo
   if 93 - 93: iII111i + I11i * OoooooooOO . OoO0O00
   if 40 - 40: ooOoO0o * I1Ii111 + iII111i
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   OOoI1i1i1iIi = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( OOoI1i1i1iIi == None ) : return
   if 52 - 52: iII111i % I11i
   I1iOooO0o = OOoI1i1i1iIi . lookup_source_cache ( self . eid , True )
   if ( I1iOooO0o == None ) : return
   if 95 - 95: IiII + Ii1I / OoO0O00 - iII111i / I1IiiI
   if ( OOoI1i1i1iIi . source_cache == None ) : return
   if 27 - 27: Oo0Ooo + i1IIi + i11iIiiIii . OoO0O00 . OoO0O00
   OOoI1i1i1iIi . source_cache . delete_cache ( self . eid )
   if ( OOoI1i1i1iIi . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 56 - 56: I1Ii111 / OoO0O00 + o0oOOo0O0Ooo . OoooooooOO * Oo0Ooo
    if 14 - 14: OoO0O00
    if 21 - 21: II111iiii + i11iIiiIii + I11i % I1IiiI
    if 65 - 65: IiII + I1ii11iIi11i / iII111i / I1IiiI + Ii1I
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 88 - 88: IiII % iIii1I11I1II1
  if 3 - 3: ooOoO0o / I1Ii111 % iIii1I11I1II1 % I11i * oO0o / iIii1I11I1II1
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 75 - 75: i11iIiiIii . iII111i
  if 68 - 68: OOooOOo . I1ii11iIi11i % I1ii11iIi11i . i11iIiiIii
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
  if 21 - 21: O0 + i11iIiiIii
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
  if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
 def inherit_from_ams_parent ( self ) :
  OO0ooOo0o = self . parent_for_more_specifics
  if ( OO0ooOo0o == None ) : return
  self . force_proxy_reply = OO0ooOo0o . force_proxy_reply
  self . force_nat_proxy_reply = OO0ooOo0o . force_nat_proxy_reply
  self . force_ttl = OO0ooOo0o . force_ttl
  self . pitr_proxy_reply_drop = OO0ooOo0o . pitr_proxy_reply_drop
  self . proxy_reply_action = OO0ooOo0o . proxy_reply_action
  self . echo_nonce_capable = OO0ooOo0o . echo_nonce_capable
  self . policy = OO0ooOo0o . policy
  self . require_signature = OO0ooOo0o . require_signature
  self . encrypt_json = OO0ooOo0o . encrypt_json
  if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
  if 52 - 52: II111iiii * o0oOOo0O0Ooo
 def rtrs_in_rloc_set ( self ) :
  for iIIoOo in self . registered_rlocs :
   if ( iIIoOo . is_rtr ( ) ) : return ( True )
   if 95 - 95: I1Ii111 - OoooooooOO
  return ( False )
  if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
  if 57 - 57: Ii1I / I1IiiI * i1IIi
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for iIIoOo in self . registered_rlocs :
   if ( iIIoOo . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( iIIoOo . is_rtr ( ) ) : return ( True )
   if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
  return ( False )
  if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
  if 30 - 30: Ii1I / iII111i * Ii1I
 def is_rloc_in_rloc_set ( self , rloc ) :
  for iIIoOo in self . registered_rlocs :
   if ( iIIoOo . rle ) :
    for IIiiiI in iIIoOo . rle . rle_nodes :
     if ( IIiiiI . rloc . rloc . is_exact_match ( rloc ) ) : return ( True )
     if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
     if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
   if ( iIIoOo . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 71 - 71: i1IIi % O0 % ooOoO0o
  return ( False )
  if 24 - 24: O0
  if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
  for iIIoOo in prev_rloc_set :
   OOooooOoO00o0 = iIIoOo . rloc
   if ( self . is_rloc_in_rloc_set ( OOooooOoO00o0 ) == False ) : return ( False )
   if 79 - 79: ooOoO0o + Oo0Ooo
  return ( True )
  if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
  if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
  if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
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
   if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  self . translated_port = 0
  if 46 - 46: OoO0O00
  if 21 - 21: iIii1I11I1II1 - iII111i
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 15 - 15: O0 + iII111i + i11iIiiIii
  try :
   OooO0O0Ooo = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   iiii1IIiiiI11 = OooO0O0Ooo [ 2 ]
  except :
   return
   if 46 - 46: I11i
   if 37 - 37: I11i * I1Ii111 . OoOoOO00 * Ii1I
   if 98 - 98: Oo0Ooo
   if 51 - 51: OOooOOo * O0
   if 50 - 50: OoO0O00 - iII111i + I1IiiI . I11i . I11i
   if 40 - 40: O0 - I11i . I1IiiI + Oo0Ooo - Ii1I - I11i
  if ( len ( iiii1IIiiiI11 ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 98 - 98: OoOoOO00 - OoooooooOO * Ii1I
   if 82 - 82: OOooOOo . OoO0O00 % II111iiii . i1IIi . OoOoOO00 - oO0o
  iI1ii11Ii = iiii1IIiiiI11 [ self . a_record_index ]
  if ( iI1ii11Ii != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( iI1ii11Ii )
   self . insert_mr ( )
   if 27 - 27: OoOoOO00 * I11i
   if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
   if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
   if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
   if 61 - 61: OOooOOo
   if 80 - 80: I1ii11iIi11i
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 6 - 6: I1ii11iIi11i + OOooOOo % ooOoO0o
  for iI1ii11Ii in iiii1IIiiiI11 [ 1 : : ] :
   I1II1I1I = lisp_address ( LISP_AFI_NONE , iI1ii11Ii , 0 , 0 )
   oOoOO0oOo00Oo = lisp_get_map_resolver ( I1II1I1I , None )
   if ( oOoOO0oOo00Oo != None and oOoOO0oOo00Oo . a_record_index == iiii1IIiiiI11 . index ( iI1ii11Ii ) ) :
    continue
    if 65 - 65: iIii1I11I1II1 % i1IIi / I1IiiI / oO0o % ooOoO0o / I11i
   oOoOO0oOo00Oo = lisp_mr ( iI1ii11Ii , None , None )
   oOoOO0oOo00Oo . a_record_index = iiii1IIiiiI11 . index ( iI1ii11Ii )
   oOoOO0oOo00Oo . dns_name = self . dns_name
   oOoOO0oOo00Oo . last_dns_resolve = lisp_get_timestamp ( )
   if 2 - 2: I1ii11iIi11i
   if 90 - 90: II111iiii * I1Ii111 . ooOoO0o - I1ii11iIi11i % I11i * o0oOOo0O0Ooo
   if 85 - 85: iIii1I11I1II1
   if 76 - 76: i11iIiiIii % I1IiiI / I11i
   if 42 - 42: o0oOOo0O0Ooo . I1IiiI + I11i . OoOoOO00 - O0 / Ii1I
  O0OOOo = [ ]
  for oOoOO0oOo00Oo in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( self . dns_name != oOoOO0oOo00Oo . dns_name ) : continue
   I1II1I1I = oOoOO0oOo00Oo . map_resolver . print_address_no_iid ( )
   if ( I1II1I1I in iiii1IIiiiI11 ) : continue
   O0OOOo . append ( oOoOO0oOo00Oo )
   if 38 - 38: OoooooooOO % I1IiiI
  for oOoOO0oOo00Oo in O0OOOo : oOoOO0oOo00Oo . delete_mr ( )
  if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
  if 75 - 75: ooOoO0o
 def insert_mr ( self ) :
  OoOOooOOoo = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ OoOOooOOoo ] = self
  if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
  if 14 - 14: I11i / I11i
 def delete_mr ( self ) :
  OoOOooOOoo = self . mr_name + self . map_resolver . print_address ( )
  if ( OoOOooOOoo not in lisp_map_resolvers_list ) : return
  lisp_map_resolvers_list . pop ( OoOOooOOoo )
  if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
  if 93 - 93: oO0o / ooOoO0o - I1Ii111
  if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
class lisp_ddt_root ( object ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 26 - 26: O0 + Oo0Ooo
  if 30 - 30: IiII
  if 6 - 6: O0
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
  if 92 - 92: I11i
  if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
 def print_referral ( self , eid_indent , referral_indent ) :
  I1IIi1i = lisp_print_elapsed ( self . uptime )
  o0oOoO0000 = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , I1IIi1i ,
  # OoooooooOO
 o0oOoO0000 , len ( self . referral_set ) ) )
  if 55 - 55: iII111i . oO0o % Oo0Ooo . Oo0Ooo . O0
  for Iii in list ( self . referral_set . values ( ) ) :
   Iii . print_ref_node ( referral_indent )
   if 86 - 86: I11i % I1Ii111 + OoO0O00
   if 89 - 89: O0 . iIii1I11I1II1 * OoOoOO00 - II111iiii
   if 44 - 44: I1Ii111 . I11i - oO0o / Oo0Ooo / IiII + ooOoO0o
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 75 - 75: I11i % ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 83 - 83: OOooOOo . ooOoO0o / IiII
  if 80 - 80: I1Ii111 . I11i - I11i + I1ii11iIi11i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 42 - 42: I11i / IiII % O0 - Oo0Ooo
  if 33 - 33: I1Ii111
 def print_ttl ( self ) :
  i1i = self . referral_ttl
  if ( i1i < 60 ) : return ( str ( i1i ) + " secs" )
  if 1 - 1: IiII - iIii1I11I1II1 % OoooooooOO
  if ( ( i1i % 60 ) == 0 ) :
   i1i = str ( old_div ( i1i , 60 ) ) + " mins"
  else :
   i1i = str ( i1i ) + " secs"
   if 1 - 1: o0oOOo0O0Ooo - i11iIiiIii + I11i
  return ( i1i )
  if 47 - 47: O0 + IiII + ooOoO0o + OOooOOo / OoOoOO00
  if 31 - 31: oO0o * iII111i % OoOoOO00
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # OOooOOo - I11i * iIii1I11I1II1 - I1Ii111 % i11iIiiIii
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 32 - 32: Oo0Ooo * i1IIi . iII111i . iII111i
  if 77 - 77: OOooOOo
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   oO00oOOOo = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( oO00oOOOo == None ) :
    oO00oOOOo = lisp_referral ( )
    oO00oOOOo . eid . copy_address ( self . group )
    oO00oOOOo . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , oO00oOOOo )
    if 74 - 74: O0
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( oO00oOOOo . group )
   oO00oOOOo . add_source_entry ( self )
   if 86 - 86: OoOoOO00
   if 4 - 4: OoooooooOO * OoO0O00
   if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   oO00oOOOo = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( oO00oOOOo == None ) : return
   if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
   oo00Oo = oO00oOOOo . lookup_source_cache ( self . eid , True )
   if ( oo00Oo == None ) : return
   if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
   oO00oOOOo . source_cache . delete_cache ( self . eid )
   if ( oO00oOOOo . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 6 - 6: I1IiiI - OoOoOO00
    if 63 - 63: OOooOOo - oO0o * I1IiiI
    if 60 - 60: II111iiii - Oo0Ooo
    if 43 - 43: I1IiiI - IiII - OOooOOo
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
  if 99 - 99: O0
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 37 - 37: iIii1I11I1II1 / I1Ii111 + OoO0O00
  if 85 - 85: ooOoO0o / I1IiiI
  if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
class lisp_referral_node ( object ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 99 - 99: i11iIiiIii - I1ii11iIi11i
  if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
 def print_ref_node ( self , indent ) :
  iIiIIIIIii = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , iIiIIIIIii ,
  # iIii1I11I1II1 % Ii1I . I1ii11iIi11i % iII111i - IiII % OoO0O00
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 58 - 58: IiII + Oo0Ooo - i1IIi
  if 3 - 3: o0oOOo0O0Ooo * Ii1I
  if 53 - 53: I1ii11iIi11i / i1IIi . OoOoOO00 % Ii1I + I1IiiI
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
   if 25 - 25: oO0o + OoooooooOO / i1IIi + O0 % OoooooooOO . OoooooooOO
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
   if 78 - 78: iIii1I11I1II1 / I1Ii111 / iII111i / iIii1I11I1II1 . iIii1I11I1II1 % II111iiii
   if 26 - 26: Oo0Ooo
   if 14 - 14: O0
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
  try :
   OooO0O0Ooo = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   iiii1IIiiiI11 = OooO0O0Ooo [ 2 ]
  except :
   return
   if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
   if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
   if 37 - 37: IiII
   if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
   if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
   if 88 - 88: i1IIi - OoOoOO00
  if ( len ( iiii1IIiiiI11 ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
   if 7 - 7: Ii1I / iIii1I11I1II1
  iI1ii11Ii = iiii1IIiiiI11 [ self . a_record_index ]
  if ( iI1ii11Ii != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( iI1ii11Ii )
   self . insert_ms ( )
   if 36 - 36: iIii1I11I1II1 % i11iIiiIii
   if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
   if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
   if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
   if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
   if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
  for iI1ii11Ii in iiii1IIiiiI11 [ 1 : : ] :
   I1II1I1I = lisp_address ( LISP_AFI_NONE , iI1ii11Ii , 0 , 0 )
   ii1iIIiIIi111 = lisp_get_map_server ( I1II1I1I )
   if ( ii1iIIiIIi111 != None and ii1iIIiIIi111 . a_record_index == iiii1IIiiiI11 . index ( iI1ii11Ii ) ) :
    continue
    if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
   ii1iIIiIIi111 = copy . deepcopy ( self )
   ii1iIIiIIi111 . map_server . store_address ( iI1ii11Ii )
   ii1iIIiIIi111 . a_record_index = iiii1IIiiiI11 . index ( iI1ii11Ii )
   ii1iIIiIIi111 . last_dns_resolve = lisp_get_timestamp ( )
   ii1iIIiIIi111 . insert_ms ( )
   if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
   if 38 - 38: IiII
   if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
   if 2 - 2: Oo0Ooo - OoOoOO00
   if 22 - 22: OoO0O00 - oO0o - O0
  O0OOOo = [ ]
  for ii1iIIiIIi111 in list ( lisp_map_servers_list . values ( ) ) :
   if ( self . dns_name != ii1iIIiIIi111 . dns_name ) : continue
   I1II1I1I = ii1iIIiIIi111 . map_server . print_address_no_iid ( )
   if ( I1II1I1I in iiii1IIiiiI11 ) : continue
   O0OOOo . append ( ii1iIIiIIi111 )
   if 49 - 49: iIii1I11I1II1 + I1Ii111 / i11iIiiIii
  for ii1iIIiIIi111 in O0OOOo : ii1iIIiIIi111 . delete_ms ( )
  if 62 - 62: ooOoO0o . I1IiiI * i11iIiiIii
  if 2 - 2: i11iIiiIii
 def insert_ms ( self ) :
  OoOOooOOoo = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ OoOOooOOoo ] = self
  if 86 - 86: I1Ii111 + o0oOOo0O0Ooo
  if 17 - 17: iIii1I11I1II1
 def delete_ms ( self ) :
  OoOOooOOoo = self . ms_name + self . map_server . print_address ( )
  if ( OoOOooOOoo not in lisp_map_servers_list ) : return
  lisp_map_servers_list . pop ( OoOOooOOoo )
  if 32 - 32: IiII - OoOoOO00
  if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
  if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
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
  if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
  if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
  if 16 - 16: Oo0Ooo
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
  if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
  if 96 - 96: I1IiiI . oO0o % O0
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
  if 87 - 87: OoooooooOO
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
  if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
 def set_socket ( self , device ) :
  OOo0oOO0o0oo0 = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  OOo0oOO0o0oo0 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   OOo0oOO0o0oo0 . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   OOo0oOO0o0oo0 . close ( )
   OOo0oOO0o0oo0 = None
   if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
  self . raw_socket = OOo0oOO0o0oo0
  if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
  if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
 def set_bridge_socket ( self , device ) :
  OOo0oOO0o0oo0 = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   OOo0oOO0o0oo0 = OOo0oOO0o0oo0 . bind ( ( device , 0 ) )
   self . bridge_socket = OOo0oOO0o0oo0
  except :
   return
   if 45 - 45: II111iiii . iII111i
   if 55 - 55: ooOoO0o / iII111i / O0
   if 98 - 98: O0 % iII111i + II111iiii
   if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
class lisp_datetime ( object ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
  if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
 def valid_datetime ( self ) :
  iiiiooOOoOO = self . datetime_name
  if ( iiiiooOOoOO . find ( ":" ) == - 1 ) : return ( False )
  if ( iiiiooOOoOO . find ( "-" ) == - 1 ) : return ( False )
  iI1ii , I11I11i11 , i1iI1iI1Ii , time = iiiiooOOoOO [ 0 : 4 ] , iiiiooOOoOO [ 5 : 7 ] , iiiiooOOoOO [ 8 : 10 ] , iiiiooOOoOO [ 11 : : ]
  if 73 - 73: iIii1I11I1II1 % oO0o
  if ( ( iI1ii + I11I11i11 + i1iI1iI1Ii ) . isdigit ( ) == False ) : return ( False )
  if ( I11I11i11 < "01" and I11I11i11 > "12" ) : return ( False )
  if ( i1iI1iI1Ii < "01" and i1iI1iI1Ii > "31" ) : return ( False )
  if 36 - 36: o0oOOo0O0Ooo - iII111i - OoooooooOO . OOooOOo % ooOoO0o
  oO00O0oo00 , o000oOOOO0o0O , iIii1 = time . split ( ":" )
  if 67 - 67: OoOoOO00
  if ( ( oO00O0oo00 + o000oOOOO0o0O + iIii1 ) . isdigit ( ) == False ) : return ( False )
  if ( oO00O0oo00 < "00" and oO00O0oo00 > "23" ) : return ( False )
  if ( o000oOOOO0o0O < "00" and o000oOOOO0o0O > "59" ) : return ( False )
  if ( iIii1 < "00" and iIii1 > "59" ) : return ( False )
  return ( True )
  if 50 - 50: Oo0Ooo
  if 80 - 80: OoOoOO00 * OoO0O00 + i11iIiiIii + O0 + II111iiii
 def parse_datetime ( self ) :
  i1ii1 = self . datetime_name
  i1ii1 = i1ii1 . replace ( "-" , "" )
  i1ii1 = i1ii1 . replace ( ":" , "" )
  self . datetime = int ( i1ii1 )
  if 38 - 38: IiII
  if 88 - 88: Oo0Ooo % I1IiiI / i11iIiiIii - II111iiii % iIii1I11I1II1 . II111iiii
 def now ( self ) :
  iIiIIIIIii = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  iIiIIIIIii = lisp_datetime ( iIiIIIIIii )
  return ( iIiIIIIIii )
  if 36 - 36: I1IiiI * i1IIi + OoOoOO00
  if 63 - 63: OoOoOO00 - iII111i
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
  if 82 - 82: iIii1I11I1II1 / OOooOOo
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 7 - 7: OoooooooOO
  if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
 def past ( self ) :
  return ( self . future ( ) == False )
  if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
  if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
  if 52 - 52: OoooooooOO - OoO0O00
 def this_year ( self ) :
  I1IIII1IIiIi = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  iIiIIIIIii = str ( self . datetime ) [ 0 : 4 ]
  return ( iIiIIIIIii == I1IIII1IIiIi )
  if 58 - 58: OoooooooOO / Oo0Ooo / Oo0Ooo
  if 11 - 11: I1IiiI - oO0o - oO0o . I11i
 def this_month ( self ) :
  I1IIII1IIiIi = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  iIiIIIIIii = str ( self . datetime ) [ 0 : 6 ]
  return ( iIiIIIIIii == I1IIII1IIiIi )
  if 65 - 65: i1IIi
  if 20 - 20: i11iIiiIii + iIii1I11I1II1 / iII111i . I1IiiI
 def today ( self ) :
  I1IIII1IIiIi = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  iIiIIIIIii = str ( self . datetime ) [ 0 : 8 ]
  return ( iIiIIIIIii == I1IIII1IIiIi )
  if 8 - 8: O0 - iII111i - i1IIi * oO0o / II111iiii
  if 48 - 48: I1ii11iIi11i . IiII * oO0o
  if 92 - 92: OoOoOO00 + oO0o % Ii1I / Ii1I - iII111i
  if 11 - 11: Oo0Ooo % II111iiii * Ii1I + II111iiii
  if 9 - 9: I1Ii111
  if 69 - 69: i1IIi + ooOoO0o + Ii1I
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
  if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
  if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
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
  if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
  if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
 def match_policy_map_request ( self , mr , srloc ) :
  for i1IiI in self . match_clauses :
   III1ii = i1IiI . source_eid
   IIiIIiiiiI = mr . source_eid
   if ( III1ii and IIiIIiiiiI and IIiIIiiiiI . is_more_specific ( III1ii ) == False ) : continue
   if 8 - 8: i1IIi
   III1ii = i1IiI . dest_eid
   IIiIIiiiiI = mr . target_eid
   if ( III1ii and IIiIIiiiiI and IIiIIiiiiI . is_more_specific ( III1ii ) == False ) : continue
   if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
   III1ii = i1IiI . source_rloc
   IIiIIiiiiI = srloc
   if ( III1ii and IIiIIiiiiI and IIiIIiiiiI . is_more_specific ( III1ii ) == False ) : continue
   i1II1IIiIi1 = i1IiI . datetime_lower
   Ooo0o00O0Oo = i1IiI . datetime_upper
   if ( i1II1IIiIi1 and Ooo0o00O0Oo and i1II1IIiIi1 . now_in_range ( Ooo0o00O0Oo ) == False ) : continue
   return ( True )
   if 2 - 2: iIii1I11I1II1
  return ( False )
  if 60 - 60: OoO0O00 + iII111i + oO0o / I1Ii111 * OOooOOo + iIii1I11I1II1
  if 17 - 17: IiII . I1IiiI + I1Ii111 / OOooOOo . Ii1I . II111iiii
 def set_policy_map_reply ( self ) :
  OoO0O0Oo = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( OoO0O0Oo ) : return ( None )
  if 36 - 36: OoooooooOO / II111iiii - iIii1I11I1II1 * OOooOOo
  iIIiI11 = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   iIIiI11 . rloc . copy_address ( self . set_rloc_address )
   iI1ii11Ii = iIIiI11 . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( iI1ii11Ii ) )
   if 55 - 55: I11i
  if ( self . set_rloc_record_name ) :
   iIIiI11 . rloc_name = self . set_rloc_record_name
   ooO0o = blue ( iIIiI11 . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( ooO0o ) )
   if 7 - 7: I1Ii111 + ooOoO0o % o0oOOo0O0Ooo
  if ( self . set_geo_name ) :
   iIIiI11 . geo_name = self . set_geo_name
   ooO0o = iIIiI11 . geo_name
   Oo00 = "" if ( ooO0o in lisp_geo_list ) else "(not configured)"
   if 73 - 73: oO0o / OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
   lprint ( "Policy set-geo-name '{}' {}" . format ( ooO0o , Oo00 ) )
   if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
  if ( self . set_elp_name ) :
   iIIiI11 . elp_name = self . set_elp_name
   ooO0o = iIIiI11 . elp_name
   Oo00 = "" if ( ooO0o in lisp_elp_list ) else "(not configured)"
   if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
   lprint ( "Policy set-elp-name '{}' {}" . format ( ooO0o , Oo00 ) )
   if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
  if ( self . set_rle_name ) :
   iIIiI11 . rle_name = self . set_rle_name
   ooO0o = iIIiI11 . rle_name
   Oo00 = "" if ( ooO0o in lisp_rle_list ) else "(not configured)"
   if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
   lprint ( "Policy set-rle-name '{}' {}" . format ( ooO0o , Oo00 ) )
   if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
  if ( self . set_json_name ) :
   iIIiI11 . json_name = self . set_json_name
   ooO0o = iIIiI11 . json_name
   Oo00 = "" if ( ooO0o in lisp_json_list ) else "(not configured)"
   if 34 - 34: II111iiii + iII111i / IiII
   lprint ( "Policy set-json-name '{}' {}" . format ( ooO0o , Oo00 ) )
   if 47 - 47: OoO0O00
  return ( iIIiI11 )
  if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
  if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
  if 100 - 100: II111iiii . IiII . I11i
  if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
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
  if 3 - 3: OoooooooOO
  if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 def add ( self , eid_prefix ) :
  self . eid_prefix = eid_prefix
  i1i = self . ttl
  o0Ooo0Oooo0o = eid_prefix . print_prefix ( )
  if ( o0Ooo0Oooo0o not in lisp_pubsub_cache ) :
   lisp_pubsub_cache [ o0Ooo0Oooo0o ] = { }
   if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
  O0o0oo = lisp_pubsub_cache [ o0Ooo0Oooo0o ]
  if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
  IIIII1I1iI = "Add"
  if ( self . xtr_id in O0o0oo ) :
   IIIII1I1iI = "Replace"
   del ( O0o0oo [ self . xtr_id ] )
   if 30 - 30: IiII - iII111i - OOooOOo / O0 . I1ii11iIi11i % Ii1I
  O0o0oo [ self . xtr_id ] = self
  if 24 - 24: IiII + i11iIiiIii - OoOoOO00
  o0Ooo0Oooo0o = green ( o0Ooo0Oooo0o , False )
  IiI1ii1ii = red ( self . itr . print_address_no_iid ( ) , False )
  oOOOOOOooOOoO = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( IIIII1I1iI , o0Ooo0Oooo0o ,
 IiI1ii1ii , oOOOOOOooOOoO , i1i ) )
  if 67 - 67: IiII % iII111i * I11i
  if 62 - 62: I11i
 def delete ( self , eid_prefix ) :
  o0Ooo0Oooo0o = eid_prefix . print_prefix ( )
  IiI1ii1ii = red ( self . itr . print_address_no_iid ( ) , False )
  oOOOOOOooOOoO = "0x" + lisp_hex_string ( self . xtr_id )
  if ( o0Ooo0Oooo0o in lisp_pubsub_cache ) :
   O0o0oo = lisp_pubsub_cache [ o0Ooo0Oooo0o ]
   if ( self . xtr_id in O0o0oo ) :
    O0o0oo . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( o0Ooo0Oooo0o ,
 IiI1ii1ii , oOOOOOOooOOoO ) )
    if 60 - 60: IiII
    if 85 - 85: OoOoOO00 * IiII / OoOoOO00 + IiII
    if 17 - 17: OoO0O00
    if 91 - 91: iIii1I11I1II1 * iIii1I11I1II1 * OoooooooOO - iII111i * iIii1I11I1II1 + OoOoOO00
    if 10 - 10: oO0o . OoooooooOO / oO0o + I1IiiI / O0
    if 12 - 12: ooOoO0o / I1IiiI % Oo0Ooo - II111iiii / i11iIiiIii
    if 33 - 33: o0oOOo0O0Ooo + IiII / OoOoOO00 / ooOoO0o
    if 9 - 9: OoOoOO00
    if 44 - 44: Oo0Ooo . i11iIiiIii % OOooOOo
    if 87 - 87: o0oOOo0O0Ooo
    if 41 - 41: OoooooooOO . iII111i / oO0o
    if 16 - 16: iII111i + o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
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
class lisp_trace ( object ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 55 - 55: OoooooooOO * O0 + i1IIi % I1IiiI
  if 10 - 10: II111iiii - Ii1I . I11i . O0 + Ii1I
 def print_trace ( self ) :
  OoiI1iII1Ii111I = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( OoiI1iII1Ii111I ) )
  if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
  if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
 def encode ( self ) :
  oOOOoOO = socket . htonl ( 0x90000000 )
  OO0Oo00OO0oo = struct . pack ( "II" , oOOOoOO , 0 )
  OO0Oo00OO0oo += struct . pack ( "Q" , self . nonce )
  OO0Oo00OO0oo += json . dumps ( self . packet_json )
  return ( OO0Oo00OO0oo )
  if 21 - 21: I1ii11iIi11i - ooOoO0o
  if 81 - 81: iII111i / i11iIiiIii / I1Ii111
 def decode ( self , packet ) :
  Iii1iIII1Iii = "I"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( False )
  oOOOoOO = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  oOOOoOO = socket . ntohl ( oOOOoOO )
  if ( ( oOOOoOO & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 70 - 70: I1ii11iIi11i / i11iIiiIii
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( False )
  iI1ii11Ii = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
  iI1ii11Ii = socket . ntohl ( iI1ii11Ii )
  o0o0 = iI1ii11Ii >> 24
  oOOo = ( iI1ii11Ii >> 16 ) & 0xff
  O0000oOoO0 = ( iI1ii11Ii >> 8 ) & 0xff
  oOOOO0OO = iI1ii11Ii & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( o0o0 , oOOo , O0000oOoO0 , oOOOO0OO )
  self . local_port = str ( oOOOoOO & 0xffff )
  if 4 - 4: IiII / Oo0Ooo % OOooOOo - OOooOOo + OoooooooOO + iIii1I11I1II1
  Iii1iIII1Iii = "Q"
  oOoOo000Ooooo = struct . calcsize ( Iii1iIII1Iii )
  if ( len ( packet ) < oOoOo000Ooooo ) : return ( False )
  self . nonce = struct . unpack ( Iii1iIII1Iii , packet [ : oOoOo000Ooooo ] ) [ 0 ]
  packet = packet [ oOoOo000Ooooo : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 55 - 55: OoOoOO00 - I1Ii111
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 74 - 74: OoO0O00
  return ( True )
  if 34 - 34: OoOoOO00 * o0oOOo0O0Ooo * i11iIiiIii - I11i % oO0o / OoO0O00
  if 75 - 75: i1IIi / Ii1I * OoO0O00 - I1ii11iIi11i * O0 . IiII
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 11 - 11: I11i / Ii1I % oO0o
  if 50 - 50: i11iIiiIii
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  iIIiI11 , I1I1I1 = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( iIIiI11 == None ) :
   iIIiI11 , I1I1I1 = rts_rloc . split ( ":" )
   I1I1I1 = int ( I1I1I1 )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( iIIiI11 , I1I1I1 ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( iIIiI11 ,
 I1I1I1 ) )
   if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
   if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
  if ( lisp_socket == None ) :
   OOo0oOO0o0oo0 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   OOo0oOO0o0oo0 . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   OOo0oOO0o0oo0 . sendto ( packet , ( iIIiI11 , I1I1I1 ) )
   OOo0oOO0o0oo0 . close ( )
  else :
   lisp_socket . sendto ( packet , ( iIIiI11 , I1I1I1 ) )
   if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
   if 4 - 4: I1IiiI
   if 36 - 36: Ii1I
 def packet_length ( self ) :
  ii11 = 8 ; oooO0OO = 4 + 4 + 8
  return ( ii11 + oooO0OO + len ( json . dumps ( self . packet_json ) ) )
  if 27 - 27: i11iIiiIii * iII111i
  if 48 - 48: Oo0Ooo . i1IIi
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  OoOOooOOoo = self . local_rloc + ":" + self . local_port
  oO00o = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ OoOOooOOoo ] = oO00o
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( OoOOooOOoo , oO00o ) )
  if 49 - 49: OOooOOo / OoO0O00 % I1Ii111
  if 80 - 80: iII111i
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  OoOOooOOoo = local_rloc_and_port
  try : oO00o = lisp_rtr_nat_trace_cache [ OoOOooOOoo ]
  except : oO00o = ( None , None )
  return ( oO00o )
  if 17 - 17: oO0o % o0oOOo0O0Ooo . o0oOOo0O0Ooo + ooOoO0o + I1Ii111 - OoO0O00
  if 37 - 37: i1IIi * OOooOOo / OoooooooOO + II111iiii
  if 73 - 73: I1Ii111 - II111iiii / Ii1I + Ii1I
  if 41 - 41: II111iiii / II111iiii / iII111i * I1IiiI * I1Ii111 * oO0o
  if 2 - 2: OoOoOO00 - I1ii11iIi11i * I1IiiI * Ii1I
  if 41 - 41: OoOoOO00 . OOooOOo / OoOoOO00 % iIii1I11I1II1
  if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
  if 48 - 48: O0
  if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
  if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
  if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
def lisp_get_map_server ( address ) :
 for ii1iIIiIIi111 in list ( lisp_map_servers_list . values ( ) ) :
  if ( ii1iIIiIIi111 . map_server . is_exact_match ( address ) ) : return ( ii1iIIiIIi111 )
  if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
 return ( None )
 if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
 if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
 if 71 - 71: oO0o + I1ii11iIi11i * I1ii11iIi11i
 if 79 - 79: oO0o
 if 47 - 47: OoooooooOO - i1IIi * OOooOOo
 if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
def lisp_get_any_map_server ( ) :
 for ii1iIIiIIi111 in list ( lisp_map_servers_list . values ( ) ) : return ( ii1iIIiIIi111 )
 return ( None )
 if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
 if 8 - 8: iII111i
 if 10 - 10: OoOoOO00 % I11i
 if 49 - 49: oO0o % ooOoO0o + II111iiii
 if 21 - 21: i1IIi + OoO0O00 . I1IiiI - Oo0Ooo
 if 99 - 99: OoOoOO00
 if 46 - 46: I1ii11iIi11i / II111iiii / OoooooooOO / Ii1I
 if 37 - 37: I1ii11iIi11i - Ii1I / oO0o . I1IiiI % I1Ii111
 if 8 - 8: oO0o
 if 46 - 46: I1Ii111 + IiII + II111iiii . o0oOOo0O0Ooo + i11iIiiIii
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  iI1ii11Ii = address . print_address ( )
  oOoOO0oOo00Oo = None
  for OoOOooOOoo in lisp_map_resolvers_list :
   if ( OoOOooOOoo . find ( iI1ii11Ii ) == - 1 ) : continue
   oOoOO0oOo00Oo = lisp_map_resolvers_list [ OoOOooOOoo ]
   if 97 - 97: o0oOOo0O0Ooo % OoOoOO00 * O0 / iIii1I11I1II1 * OoO0O00 / i11iIiiIii
  return ( oOoOO0oOo00Oo )
  if 1 - 1: OoooooooOO . Ii1I
  if 68 - 68: Ii1I
  if 98 - 98: iII111i
  if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
  if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
  if 67 - 67: o0oOOo0O0Ooo
  if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
 if ( eid == "" ) :
  iIi1I = ""
 elif ( eid == None ) :
  iIi1I = "all"
 else :
  i1I = lisp_db_for_lookups . lookup_cache ( eid , False )
  iIi1I = "all" if i1I == None else i1I . use_mr_name
  if 24 - 24: OoooooooOO - oO0o - Oo0Ooo - o0oOOo0O0Ooo
  if 73 - 73: OoOoOO00 * OOooOOo / oO0o % Oo0Ooo
 oo0OOOoO00OoO = None
 for oOoOO0oOo00Oo in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( iIi1I == "" ) : return ( oOoOO0oOo00Oo )
  if ( oOoOO0oOo00Oo . mr_name != iIi1I ) : continue
  if ( oo0OOOoO00OoO == None or oOoOO0oOo00Oo . last_used < oo0OOOoO00OoO . last_used ) : oo0OOOoO00OoO = oOoOO0oOo00Oo
  if 100 - 100: IiII / i11iIiiIii * O0
 return ( oo0OOOoO00OoO )
 if 93 - 93: iII111i - I11i . I1IiiI + I11i
 if 16 - 16: o0oOOo0O0Ooo . iII111i / OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo
 if 35 - 35: ooOoO0o / I1Ii111 / I1Ii111
 if 19 - 19: OoO0O00 % i11iIiiIii % iIii1I11I1II1
 if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
 if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
 if 14 - 14: I1Ii111 + Oo0Ooo
 if 35 - 35: i11iIiiIii * Ii1I
def lisp_get_decent_map_resolver ( eid ) :
 o00O = lisp_get_decent_index ( eid )
 oooooO0O0O = str ( o00O ) + "." + lisp_decent_dns_suffix
 if 62 - 62: I1ii11iIi11i * i1IIi - I1Ii111 * I11i . i1IIi - II111iiii
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( oooooO0O0O , False ) , eid . print_prefix ( ) ) )
 if 59 - 59: Ii1I . IiII
 if 14 - 14: I11i
 oo0OOOoO00OoO = None
 for oOoOO0oOo00Oo in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( oooooO0O0O != oOoOO0oOo00Oo . dns_name ) : continue
  if ( oo0OOOoO00OoO == None or oOoOO0oOo00Oo . last_used < oo0OOOoO00OoO . last_used ) : oo0OOOoO00OoO = oOoOO0oOo00Oo
  if 100 - 100: ooOoO0o * I1ii11iIi11i % OoO0O00 * Oo0Ooo . i1IIi
 return ( oo0OOOoO00OoO )
 if 51 - 51: iIii1I11I1II1 . i11iIiiIii * i1IIi / OoOoOO00
 if 64 - 64: IiII % iII111i . Ii1I * II111iiii / OoOoOO00
 if 25 - 25: OoooooooOO + i1IIi - I1ii11iIi11i . oO0o + IiII % I1Ii111
 if 36 - 36: Ii1I
 if 88 - 88: Ii1I
 if 69 - 69: I1IiiI + Ii1I * I11i + i1IIi
 if 14 - 14: iII111i / ooOoO0o % IiII - I1IiiI . Oo0Ooo
def lisp_ipv4_input ( packet ) :
 if 30 - 30: O0 . OOooOOo
 if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
 if 83 - 83: OoooooooOO
 if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
 if ( ord ( packet [ 9 : 10 ] ) == 2 ) : return ( [ True , packet ] )
 if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
 if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
 if 50 - 50: OoO0O00 . OoooooooOO
 if 31 - 31: OoO0O00
 O0OoO0o = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
 if ( O0OoO0o == 0 ) :
  dprint ( "Packet arrived with checksum of 0!" )
 else :
  packet = lisp_ip_checksum ( packet )
  O0OoO0o = struct . unpack ( "H" , packet [ 10 : 12 ] ) [ 0 ]
  if ( O0OoO0o != 0 ) :
   dprint ( "IPv4 header checksum failed for inner header" )
   packet = lisp_format_packet ( packet [ 0 : 20 ] )
   dprint ( "Packet header: {}" . format ( packet ) )
   return ( [ False , None ] )
   if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
   if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
   if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
   if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
   if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
   if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
   if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
 i1i = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( i1i == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( i1i == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
  return ( [ False , None ] )
  if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
  if 74 - 74: OoooooooOO + Ii1I
 i1i -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , i1i ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 100 - 100: I1IiiI
 if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
 if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
def lisp_ipv6_input ( packet ) :
 oOOo0OOoOO0 = packet . inner_dest
 packet = packet . packet
 if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
 if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
 if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
 if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
 if 40 - 40: I1ii11iIi11i
 i1i = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( i1i == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( i1i == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 76 - 76: Oo0Ooo - I11i
  return ( None )
  if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
  if 39 - 39: I1IiiI
  if 8 - 8: IiII * i1IIi * i1IIi * O0
  if 69 - 69: Oo0Ooo
  if 48 - 48: iII111i
 if ( oOOo0OOoOO0 . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
  if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
 i1i -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , i1i ) + packet [ 8 : : ]
 return ( packet )
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
def lisp_mac_input ( packet ) :
 return ( packet )
 if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
 if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
 if 44 - 44: O0
 if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
 if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
def lisp_rate_limit_map_request ( dest ) :
 I1IIII1IIiIi = lisp_get_timestamp ( )
 if 79 - 79: II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 if 32 - 32: O0 + IiII
 o0oOOOO0 = I1IIII1IIiIi - lisp_no_map_request_rate_limit
 if ( o0oOOOO0 < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  oO0OO00OOo0 = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - o0oOOOO0 )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( oO0OO00OOo0 ) )
  return ( False )
  if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
  if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
  if 17 - 17: OOooOOo
  if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
  if 46 - 46: II111iiii * OoO0O00
 if ( lisp_last_map_request_sent == None ) : return ( False )
 o0oOOOO0 = I1IIII1IIiIi - lisp_last_map_request_sent
 iI1i1iIIIII = ( o0oOOOO0 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 77 - 77: ooOoO0o * I11i
 if ( iI1i1iIIIII ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( o0oOOOO0 , 3 ) ) )
  if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
  if 76 - 76: iII111i * OoooooooOO
 return ( iI1i1iIIIII )
 if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
 if 51 - 51: i11iIiiIii
 if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
 if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 if 63 - 63: II111iiii - Oo0Ooo
 if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ,
 pubsub = False ) :
 global lisp_last_map_request_sent , lisp_rloc_probe_nonce_list
 if 78 - 78: IiII - I1IiiI
 if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
 if 71 - 71: OoO0O00
 if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
 if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
 if 54 - 54: Ii1I / I1IiiI
 IiiI = Oo0o00 = None
 if ( rloc ) :
  IiiI = rloc . rloc
  Oo0o00 = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 38 - 38: II111iiii
  if 59 - 59: OoooooooOO . ooOoO0o / OOooOOo - OOooOOo / iIii1I11I1II1 / oO0o
  if 58 - 58: iIii1I11I1II1 - OoO0O00
  if 74 - 74: o0oOOo0O0Ooo . OOooOOo
  if 96 - 96: OoooooooOO
 i1i11Oo0o0O , o0O0Ii , ooo = lisp_myrlocs
 if ( i1i11Oo0o0O == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
 if ( o0O0Ii == None and IiiI != None and IiiI . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 23 - 23: I1IiiI
  if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
 o0o000Oo = lisp_map_request ( )
 o0o000Oo . record_count = 1
 o0o000Oo . nonce = lisp_get_control_nonce ( )
 o0o000Oo . rloc_probe = ( IiiI != None )
 o0o000Oo . subscribe_bit = pubsub
 o0o000Oo . xtr_id_present = pubsub
 o0o000Oo . decent_nat_xtr = lisp_decent_nat
 if 57 - 57: iIii1I11I1II1
 if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
 if 3 - 3: oO0o % OoO0O00 % OOooOOo
 if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
 if 58 - 58: ooOoO0o
 if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
 if 77 - 77: O0
 if ( rloc ) : rloc . last_rloc_probe_nonce = o0o000Oo . nonce
 if 98 - 98: iII111i - iII111i % i1IIi - I1Ii111 . I1IiiI % o0oOOo0O0Ooo
 I1iiIiI1II1ii = deid . is_multicast_address ( )
 if ( I1iiIiI1II1ii ) :
  o0o000Oo . target_eid = seid
  o0o000Oo . target_group = deid
 else :
  o0o000Oo . target_eid = deid
  if 38 - 38: IiII % OoOoOO00 . OOooOOo . I1ii11iIi11i
  if 34 - 34: iII111i . i11iIiiIii + OoO0O00 + o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
  if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
  if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
  if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
  if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
  if 60 - 60: OoOoOO00 - IiII + OoO0O00
  if 77 - 77: iIii1I11I1II1
  if 92 - 92: IiII
 if ( o0o000Oo . rloc_probe == False ) :
  i1I = lisp_get_signature_eid ( )
  if ( i1I ) :
   o0o000Oo . signature_eid . copy_address ( i1I . eid )
   o0o000Oo . privkey_filename = "./lisp-sig.pem"
   if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
   if 74 - 74: iII111i + i11iIiiIii
   if 95 - 95: Ii1I
   if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
   if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
   if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
 if ( seid == None or I1iiIiI1II1ii ) :
  o0o000Oo . source_eid . afi = LISP_AFI_NONE
 else :
  o0o000Oo . source_eid = seid
  if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
  if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
  if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
  if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
  if 49 - 49: iII111i / iII111i - OoOoOO00
  if 89 - 89: ooOoO0o
  if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
  if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
  if 11 - 11: iII111i
  if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
  if 89 - 89: I11i % II111iiii
  if 35 - 35: oO0o
  if 65 - 65: II111iiii
  if 87 - 87: oO0o / OoO0O00 - oO0o
  if 69 - 69: i11iIiiIii
 if ( IiiI != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( lisp_decent_nat == False and
 IiiI . is_private_address ( ) == False ) :
   i1i11Oo0o0O = lisp_get_any_translated_rloc ( )
   if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
  if ( i1i11Oo0o0O == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
   if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
   if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
   if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
   if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
   if 82 - 82: OOooOOo . oO0o
   if 12 - 12: i11iIiiIii + II111iiii
   if 49 - 49: OoooooooOO
 if ( IiiI == None or IiiI . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and IiiI == None ) :
   IIoOo0oooO0 = lisp_get_any_translated_rloc ( )
   if ( IIoOo0oooO0 != None ) : i1i11Oo0o0O = IIoOo0oooO0
   if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
  o0o000Oo . itr_rlocs . append ( i1i11Oo0o0O )
  if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
 if ( IiiI == None or IiiI . is_ipv6 ( ) ) :
  if ( o0O0Ii == None or o0O0Ii . is_ipv6_link_local ( ) ) :
   o0O0Ii = None
  else :
   o0o000Oo . itr_rloc_count = 1 if ( IiiI == None ) else 0
   o0o000Oo . itr_rlocs . append ( o0O0Ii )
   if 6 - 6: oO0o / II111iiii
   if 23 - 23: IiII - OoooooooOO / oO0o
   if 69 - 69: O0 - OoooooooOO
   if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
   if 50 - 50: IiII - OOooOOo % OoOoOO00
   if 66 - 66: IiII * i11iIiiIii
   if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
   if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
   if 64 - 64: OOooOOo / OoOoOO00
 if ( IiiI != None and o0o000Oo . itr_rlocs != [ ] ) :
  OOoo0O = o0o000Oo . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   OOoo0O = i1i11Oo0o0O
  elif ( deid . is_ipv6 ( ) ) :
   OOoo0O = o0O0Ii
  else :
   OOoo0O = i1i11Oo0o0O
   if 30 - 30: OOooOOo % I1Ii111 - i11iIiiIii
   if 20 - 20: i1IIi * I11i / OoO0O00 / i1IIi / I1Ii111 * O0
   if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
   if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
   if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
   if 49 - 49: IiII
 OO0Oo00OO0oo = o0o000Oo . encode ( IiiI , Oo0o00 )
 o0o000Oo . print_map_request ( )
 if 1 - 1: oO0o / I11i
 if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
 if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
 if 24 - 24: O0
 if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
 if ( IiiI != None ) :
  if ( rloc . is_rloc_translated ( ) ) :
   IIi = rloc . normalize_decent_nat_rloc_name ( )
   oO00OOoOOoO = lisp_get_nat_info ( IiiI , IIi )
   if 65 - 65: i11iIiiIii
   if 46 - 46: i11iIiiIii
   if 70 - 70: i1IIi + o0oOOo0O0Ooo
   if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
   if 29 - 29: i11iIiiIii * i1IIi
   if ( oO00OOoOOoO == None ) :
    I1I1 = rloc . rloc . print_address_no_iid ( )
    II11iIIii = "glean-{}" . format ( I1I1 ) if lisp_i_am_rtr else "nat-{}" . format ( I1I1 )
    if 36 - 36: OoO0O00 * I11i . ooOoO0o
    III1ii = rloc . translated_port
    oO00OOoOOoO = lisp_nat_info ( I1I1 , II11iIIii , III1ii )
    if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
    if 55 - 55: II111iiii - IiII
   lisp_encap_rloc_probe ( lisp_sockets , IiiI , oO00OOoOOoO , OO0Oo00OO0oo )
   return
   if 24 - 24: oO0o % Ii1I / i1IIi
   if 84 - 84: i1IIi
  if ( IiiI . is_ipv4 ( ) and IiiI . is_multicast_address ( ) ) :
   oOOo0OOoOO0 = IiiI
  else :
   O00oO000Oo0 = IiiI . print_address_no_iid ( )
   oOOo0OOoOO0 = lisp_convert_4to6 ( O00oO000Oo0 )
   if 53 - 53: OoooooooOO - i1IIi - Ii1I
   if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
   if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
   if 34 - 34: Ii1I
   if 5 - 5: II111iiii . I1ii11iIi11i
  lisp_rloc_probe_nonce_list [ o0o000Oo . nonce ] = O00oO000Oo0
  if 85 - 85: I1Ii111 . IiII + II111iiii
  lisp_send ( lisp_sockets , oOOo0OOoOO0 , LISP_CTRL_PORT , OO0Oo00OO0oo )
  return
  if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
  if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
  if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
  if 87 - 87: OOooOOo
  if 44 - 44: Oo0Ooo + iIii1I11I1II1
  if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
 I11I1 = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  oOoOO0oOo00Oo = lisp_get_decent_map_resolver ( deid )
 else :
  oOoOO0oOo00Oo = lisp_get_map_resolver ( None , I11I1 )
  if 58 - 58: II111iiii * O0
 if ( oOoOO0oOo00Oo == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 23 - 23: I11i . II111iiii
  return
  if 30 - 30: I11i . i11iIiiIii + OOooOOo % OoooooooOO + o0oOOo0O0Ooo
 oOoOO0oOo00Oo . last_used = lisp_get_timestamp ( )
 oOoOO0oOo00Oo . map_requests_sent += 1
 if ( oOoOO0oOo00Oo . last_nonce == 0 ) : oOoOO0oOo00Oo . last_nonce = o0o000Oo . nonce
 if 92 - 92: I11i
 if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
 if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
 if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
 if ( seid == None ) : seid = OOoo0O
 lisp_send_ecm ( lisp_sockets , OO0Oo00OO0oo , seid , lisp_ephem_port , deid ,
 oOoOO0oOo00Oo . map_resolver )
 if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
 if 32 - 32: O0
 if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
 if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
 if 70 - 70: iIii1I11I1II1 - I11i
 if 2 - 2: oO0o / II111iiii * OoO0O00
 if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
 oOoOO0oOo00Oo . resolve_dns_name ( )
 return
 if 40 - 40: OOooOOo
 if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
 if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
 if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
 if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
 if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
 if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
 if 98 - 98: OoO0O00 + oO0o - II111iiii
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
 if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
 if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
 if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
 i1IIIIIi111 = lisp_info ( )
 i1IIIIIi111 . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : i1IIIIIi111 . hostname += "-" + device_name
 if 10 - 10: o0oOOo0O0Ooo + ooOoO0o + Oo0Ooo
 O00oO000Oo0 = dest . print_address_no_iid ( )
 if 67 - 67: I1IiiI / i11iIiiIii - I1Ii111 % OoooooooOO
 if 36 - 36: oO0o % iII111i % oO0o
 if 56 - 56: ooOoO0o - O0 + iII111i % I11i / i1IIi
 if 78 - 78: i1IIi . iIii1I11I1II1
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
 IIII1I111iI = False
 if ( device_name ) :
  OO00 = lisp_get_default_route_next_hops ( )
  lprint ( "Found default routes {}" . format ( OO00 ) )
  if 61 - 61: iIii1I11I1II1 + i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO
  if ( len ( OO00 ) == 1 ) :
   O0O0O0ooOoOo = OO00 [ 0 ] [ 0 ]
   if ( O0O0O0ooOoOo != device_name ) :
    lprint ( "Multihoming config error, add this to your system:" )
    lprint ( "  'sudo ip route append default via <nh> dev {}'" . format ( device_name ) )
    if 78 - 78: iII111i
    return
    if 56 - 56: Oo0Ooo / I1IiiI + iIii1I11I1II1 + I1IiiI % iIii1I11I1II1
    if 64 - 64: O0
    if 55 - 55: OoO0O00 * oO0o . Ii1I + OoOoOO00 % I11i + IiII
  OooO0OO = lisp_get_host_route_next_hop ( O00oO000Oo0 )
  if ( OooO0OO == None ) :
   lprint ( "No host route found for MS {}" . format ( O00oO000Oo0 ) )
  else :
   lprint ( "Host route found for MS {}, nh {}" . format ( O00oO000Oo0 ,
 OooO0OO ) )
   if 14 - 14: OoO0O00 + I1IiiI . o0oOOo0O0Ooo - OoO0O00 + Ii1I - Ii1I
   if 98 - 98: oO0o * O0 + I11i
   if 75 - 75: i1IIi . I11i . O0 / I1ii11iIi11i / Oo0Ooo . i1IIi
   if 36 - 36: Oo0Ooo . Oo0Ooo - OOooOOo / IiII / OoooooooOO / I1IiiI
   if 7 - 7: ooOoO0o * o0oOOo0O0Ooo + ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
   if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
   if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
   if 72 - 72: i11iIiiIii * I11i
   if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
   if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
  if ( port == LISP_CTRL_PORT and OooO0OO != None ) :
   lprint ( "Waiting for host route {} to go away" . format ( O00oO000Oo0 ) )
   while ( True ) :
    time . sleep ( .01 )
    OooO0OO = lisp_get_host_route_next_hop ( O00oO000Oo0 )
    if ( OooO0OO == None ) : break
    if 64 - 64: OoooooooOO
    if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
    if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
  for ooo , O0O0O0ooOoOo in OO00 :
   if ( ooo != device_name ) : continue
   if 71 - 71: O0 - OoooooooOO
   if 82 - 82: i11iIiiIii * II111iiii % IiII
   if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
   if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
   if 67 - 67: iII111i
   if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
   if ( OooO0OO != O0O0O0ooOoOo ) :
    if ( OooO0OO != None ) :
     lisp_install_host_route ( O00oO000Oo0 , OooO0OO , False )
     if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
    lisp_install_host_route ( O00oO000Oo0 , O0O0O0ooOoOo , True )
    IIII1I111iI = True
    if 60 - 60: i1IIi / iII111i
   break
   if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
   if 2 - 2: iIii1I11I1II1
   if 85 - 85: O0 - ooOoO0o
   if 35 - 35: o0oOOo0O0Ooo - I1IiiI
   if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
   if 65 - 65: Ii1I % i11iIiiIii
 OO0Oo00OO0oo = i1IIIIIi111 . encode ( )
 i1IIIIIi111 . print_info ( )
 if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
 if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
 if 88 - 88: iII111i
 oooOi1Ii1I1i1ii1i = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 oooOi1Ii1I1i1ii1i = bold ( oooOi1Ii1I1i1ii1i , False )
 III1ii = bold ( "{}" . format ( port ) , False )
 I1II1I1I = red ( O00oO000Oo0 , False )
 Ooooo0OO = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( Ooooo0OO , I1II1I1I , III1ii , oooOi1Ii1I1i1ii1i ) )
 if 94 - 94: O0 / iII111i % i11iIiiIii - OoooooooOO - iII111i
 if 79 - 79: I11i * oO0o
 if 49 - 49: oO0o % O0 + Oo0Ooo
 if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
 if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 if 42 - 42: II111iiii . iII111i
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , OO0Oo00OO0oo )
 else :
  i111ii1II11ii = lisp_data_header ( )
  i111ii1II11ii . instance_id ( 0xffffff )
  i111ii1II11ii = i111ii1II11ii . encode ( )
  if ( i111ii1II11ii ) :
   OO0Oo00OO0oo = i111ii1II11ii + OO0Oo00OO0oo
   if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
   if 64 - 64: oO0o / IiII
   if 86 - 86: I11i
   if 36 - 36: o0oOOo0O0Ooo / OoO0O00
   if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
   if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
   if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
   if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
   if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , OO0Oo00OO0oo )
   if 86 - 86: i11iIiiIii
   if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
   if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
   if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
   if 79 - 79: I11i - II111iiii
   if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
   if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 if ( IIII1I111iI ) :
  lisp_install_host_route ( O00oO000Oo0 , None , False )
  if ( OooO0OO != None ) : lisp_install_host_route ( O00oO000Oo0 , OooO0OO , True )
  if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 return
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 if 10 - 10: i1IIi + o0oOOo0O0Ooo
 if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
 i1IIIIIi111 = lisp_info ( )
 packet = i1IIIIIi111 . decode ( packet )
 if ( packet == None ) : return
 i1IIIIIi111 . print_info ( )
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
 if 16 - 16: i11iIiiIii * Oo0Ooo
 if 76 - 76: iII111i . oO0o - i1IIi
 i1IIIIIi111 . info_reply = True
 i1IIIIIi111 . global_etr_rloc . store_address ( addr_str )
 i1IIIIIi111 . etr_port = sport
 if 94 - 94: O0 % iII111i
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 if ( i1IIIIIi111 . hostname != None ) :
  i1IIIIIi111 . private_etr_rloc . afi = LISP_AFI_NAME
  i1IIIIIi111 . private_etr_rloc . store_address ( i1IIIIIi111 . hostname )
  if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
  if 90 - 90: oO0o * I1Ii111 / O0
 if ( rtr_list != None ) : i1IIIIIi111 . rtr_list = rtr_list
 packet = i1IIIIIi111 . encode ( )
 i1IIIIIi111 . print_info ( )
 if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
 if 28 - 28: OoooooooOO + OoooooooOO
 if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
 if 15 - 15: II111iiii * OoO0O00
 if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 oOOo0OOoOO0 = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , oOOo0OOoOO0 , sport , packet )
 if 58 - 58: Ii1I
 if 20 - 20: OOooOOo
 if 93 - 93: i1IIi . IiII % O0 * iII111i
 if 84 - 84: I11i
 if 99 - 99: I1ii11iIi11i
 o0O = lisp_info_source ( i1IIIIIi111 . hostname , addr_str , sport )
 o0O . cache_address_for_info_source ( )
 return
 if 88 - 88: OoooooooOO * I1IiiI . O0 / i1IIi % oO0o
 if 36 - 36: II111iiii
 if 89 - 89: I11i * O0 * Oo0Ooo % i1IIi
 if 41 - 41: OOooOOo + ooOoO0o - OoOoOO00 . iIii1I11I1II1
 if 73 - 73: I1ii11iIi11i / OoooooooOO + II111iiii * Oo0Ooo * I1ii11iIi11i / OoO0O00
 if 49 - 49: OOooOOo % Oo0Ooo % OoOoOO00 - OoooooooOO % iII111i - O0
 if 62 - 62: iIii1I11I1II1
 if 14 - 14: I1Ii111
def lisp_get_signature_eid ( ) :
 for i1I in lisp_db_list :
  if ( i1I . signature_eid ) : return ( i1I )
  if 95 - 95: II111iiii / o0oOOo0O0Ooo * OOooOOo
 return ( None )
 if 81 - 81: i11iIiiIii / iIii1I11I1II1
 if 73 - 73: i11iIiiIii . I1ii11iIi11i * OoOoOO00
 if 95 - 95: i1IIi + iIii1I11I1II1 . I1Ii111 / I1Ii111
 if 84 - 84: Oo0Ooo . OoO0O00 * IiII
 if 95 - 95: OoO0O00
 if 100 - 100: II111iiii
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
 if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
def lisp_get_any_translated_port ( ) :
 for i1I in lisp_db_list :
  for iIIoOo in i1I . rloc_set :
   if ( iIIoOo . translated_rloc . is_null ( ) ) : continue
   return ( iIIoOo . translated_port )
   if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
   if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
 return ( None )
 if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
 if 40 - 40: o0oOOo0O0Ooo * I1IiiI
 if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
 if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
 if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
 if 16 - 16: oO0o
 if 32 - 32: OoooooooOO
def lisp_get_translated_port_for_mr ( mr_addr ) :
 for oOoOO0oOo00Oo in list ( lisp_map_resolvers_list . values ( ) ) :
  I1II1I1I = oOoOO0oOo00Oo . map_resolver . print_address_no_iid ( )
  if ( I1II1I1I == mr_addr ) :
   if ( oOoOO0oOo00Oo . translated_port == 0 ) : return ( oOoOO0oOo00Oo , lisp_get_any_translated_port ( ) )
   return ( oOoOO0oOo00Oo , oOoOO0oOo00Oo . translated_port )
   if 77 - 77: Oo0Ooo . i1IIi - I11i
   if 98 - 98: O0
 return ( None , lisp_get_any_translated_port ( ) )
 if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
 if 54 - 54: i1IIi % iII111i
 if 16 - 16: II111iiii - Oo0Ooo
 if 44 - 44: OOooOOo / Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if 85 - 85: iIii1I11I1II1 / Ii1I
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 if 80 - 80: I11i
def lisp_get_any_translated_rloc ( ) :
 for i1I in lisp_db_list :
  for iIIoOo in i1I . rloc_set :
   if ( iIIoOo . translated_rloc . is_null ( ) ) : continue
   return ( iIIoOo . translated_rloc )
   if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
   if 88 - 88: ooOoO0o + ooOoO0o / I1Ii111
 return ( None )
 if 69 - 69: O0 * o0oOOo0O0Ooo + i1IIi * ooOoO0o . o0oOOo0O0Ooo
 if 46 - 46: Oo0Ooo / Oo0Ooo * IiII
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 if 65 - 65: I11i
 if 92 - 92: iII111i . IiII + i1IIi % i1IIi
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
def lisp_get_all_translated_rlocs ( ) :
 O00O0oooO0 = [ ]
 for i1I in lisp_db_list :
  for iIIoOo in i1I . rloc_set :
   if ( iIIoOo . is_rloc_translated ( ) == False ) : continue
   iI1ii11Ii = iIIoOo . translated_rloc . print_address_no_iid ( )
   O00O0oooO0 . append ( iI1ii11Ii )
   if 6 - 6: O0 + i11iIiiIii
   if 59 - 59: ooOoO0o . iII111i - II111iiii
 return ( O00O0oooO0 )
 if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
 if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
 if 55 - 55: OoooooooOO
 if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
 if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
 if 90 - 90: OOooOOo
 if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 Ii11iI1ii1 = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 65 - 65: oO0o
 IiI1 = { }
 for iIIiI11 in rtr_list :
  if ( iIIiI11 == None ) : continue
  iI1ii11Ii = rtr_list [ iIIiI11 ]
  if ( Ii11iI1ii1 and iI1ii11Ii . is_private_address ( ) ) : continue
  IiI1 [ iIIiI11 ] = iI1ii11Ii
  if 9 - 9: II111iiii - iIii1I11I1II1 . Ii1I . OoooooooOO + I1IiiI / iIii1I11I1II1
 rtr_list = IiI1
 if 35 - 35: oO0o / oO0o
 OOOiiI1IIIiIIi = [ ]
 for Oooo0oOOOO in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( Oooo0oOOOO == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 77 - 77: i11iIiiIii % O0
  if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
  if 36 - 36: II111iiii
  if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
  if 7 - 7: i11iIiiIii
  OoOo00 = lisp_address ( Oooo0oOOOO , "" , 0 , iid )
  OoOo00 . make_default_route ( OoOo00 )
  I1I1i1I11I = lisp_map_cache . lookup_cache ( OoOo00 , True )
  if ( I1I1i1I11I ) :
   if ( I1I1i1I11I . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( I1I1i1I11I . print_eid_tuple ( ) , False ) ) )
    if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
   elif ( I1I1i1I11I . do_rloc_sets_match ( list ( rtr_list . values ( ) ) ) ) :
    continue
    if 41 - 41: IiII % II111iiii
   I1I1i1I11I . delete_cache ( )
   if 99 - 99: IiII - O0
   if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
  OOOiiI1IIIiIIi . append ( [ OoOo00 , "" ] )
  if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
  if 19 - 19: OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
  if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
  if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
  oo0oOooo0O = lisp_address ( Oooo0oOOOO , "" , 0 , iid )
  oo0oOooo0O . make_default_multicast_route ( oo0oOooo0O )
  O0oO00OO0oO0 = lisp_map_cache . lookup_cache ( oo0oOooo0O , True )
  if ( O0oO00OO0oO0 ) : O0oO00OO0oO0 = O0oO00OO0oO0 . source_cache . lookup_cache ( OoOo00 , True )
  if ( O0oO00OO0oO0 ) : O0oO00OO0oO0 . delete_cache ( )
  if 23 - 23: I11i
  OOOiiI1IIIiIIi . append ( [ OoOo00 , oo0oOooo0O ] )
  if 72 - 72: iII111i + iII111i + I1Ii111 * o0oOOo0O0Ooo - IiII
 if ( len ( OOOiiI1IIIiIIi ) == 0 ) : return
 if 11 - 11: IiII + Ii1I - IiII - OoO0O00
 if 23 - 23: I1ii11iIi11i % OOooOOo
 if 82 - 82: i1IIi . I1IiiI
 if 13 - 13: O0 * iII111i
 i1i1i1 = [ ]
 for Ooooo0OO in rtr_list :
  iiI111iiI = rtr_list [ Ooooo0OO ]
  iIIoOo = lisp_rloc ( )
  iIIoOo . rloc . copy_address ( iiI111iiI )
  iIIoOo . priority = 254
  iIIoOo . mpriority = 255
  iIIoOo . rloc_name = "RTR"
  i1i1i1 . append ( iIIoOo )
  if 20 - 20: I1ii11iIi11i * I1IiiI / Ii1I % oO0o % iII111i + i11iIiiIii
  if 28 - 28: I1Ii111 / iII111i * IiII
 for OoOo00 in OOOiiI1IIIiIIi :
  I1I1i1I11I = lisp_mapping ( OoOo00 [ 0 ] , OoOo00 [ 1 ] , i1i1i1 )
  I1I1i1I11I . mapping_source = map_resolver
  I1I1i1I11I . map_cache_ttl = LISP_MR_TTL * 60
  I1I1i1I11I . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( I1I1i1I11I . print_eid_tuple ( ) , False ) , list ( rtr_list . keys ( ) ) ) )
  if 99 - 99: i11iIiiIii / iII111i % iII111i + i11iIiiIii % OOooOOo * Ii1I
  i1i1i1 = copy . deepcopy ( i1i1i1 )
  if 66 - 66: iIii1I11I1II1
 return
 if 91 - 91: oO0o
 if 28 - 28: O0 - o0oOOo0O0Ooo / I1Ii111 . OoooooooOO % iII111i + II111iiii
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 if 83 - 83: oO0o
 if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
 if 85 - 85: iIii1I11I1II1 / I11i
 if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
 if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
 if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
 if 89 - 89: ooOoO0o
def lisp_process_info_reply ( source , packet , store ) :
 if 83 - 83: I11i . I11i * OOooOOo - OOooOOo
 if 46 - 46: iIii1I11I1II1 . I1Ii111 % I1IiiI
 if 22 - 22: i1IIi * I11i + II111iiii + II111iiii
 if 20 - 20: I11i
 i1IIIIIi111 = lisp_info ( )
 packet = i1IIIIIi111 . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 37 - 37: I1Ii111
 i1IIIIIi111 . print_info ( )
 if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
 if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
 if 41 - 41: O0 / OoooooooOO - i1IIi
 if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
 III1 = False
 if 3 - 3: OOooOOo * ooOoO0o / i11iIiiIii . OoO0O00 * ooOoO0o
 if 58 - 58: i1IIi - OoO0O00 * II111iiii
 if 92 - 92: ooOoO0o / I1Ii111 . iII111i
 if 59 - 59: Ii1I - OoO0O00 % iII111i + I1ii11iIi11i * iII111i
 for Ooooo0OO in i1IIIIIi111 . rtr_list :
  O00oO000Oo0 = Ooooo0OO . print_address_no_iid ( )
  if ( O00oO000Oo0 in lisp_rtr_list ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ O00oO000Oo0 ] != None ) : continue
   if 51 - 51: ooOoO0o - Oo0Ooo / iII111i . I11i - Ii1I / OOooOOo
  III1 = True
  lisp_rtr_list [ O00oO000Oo0 ] = Ooooo0OO
  if 4 - 4: II111iiii + OoOoOO00 . ooOoO0o - I11i . I1IiiI
  if 46 - 46: II111iiii
  if 38 - 38: OOooOOo % II111iiii
  if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
  if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
 if ( lisp_i_am_itr and III1 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for i1I1iI in list ( lisp_iid_to_interface . keys ( ) ) :
    lisp_update_default_routes ( source , int ( i1I1iI ) , lisp_rtr_list )
    if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
    if 89 - 89: I1Ii111
    if 29 - 29: I11i * ooOoO0o - OoooooooOO
    if 92 - 92: O0 % i1IIi / OOooOOo - oO0o
    if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
    if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
    if 73 - 73: OoooooooOO
 if ( lisp_i_am_itr ) :
  iiiI1Ii1IiiIi1 = i1IIIIIi111 . etr_port
  O00oO000Oo0 = source . print_address_no_iid ( )
  oOoOO0oOo00Oo , iIIo0OOO = lisp_get_translated_port_for_mr ( O00oO000Oo0 )
  if ( oOoOO0oOo00Oo == None ) :
   lprint ( "Could not store translated-port {} for map-resolver {}" . format ( iiiI1Ii1IiiIi1 , O00oO000Oo0 ) )
  else :
   oOoOO0oOo00Oo . translated_port = iiiI1Ii1IiiIi1
   lprint ( "Store translated-port {} for map-resolver {}" . format ( iiiI1Ii1IiiIi1 , O00oO000Oo0 ) )
   if 37 - 37: iII111i - ooOoO0o % O0 + I1Ii111
   if 15 - 15: I1Ii111 * iIii1I11I1II1 - iIii1I11I1II1 - O0
   if 41 - 41: O0 - i11iIiiIii - I1Ii111 + i1IIi - iIii1I11I1II1 . Oo0Ooo
   if 38 - 38: Oo0Ooo - I1ii11iIi11i
   if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
   if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
 if ( store == False ) :
  return ( [ i1IIIIIi111 . global_etr_rloc , i1IIIIIi111 . etr_port , III1 ] )
  if 3 - 3: Ii1I
  if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
  if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
  if 86 - 86: Oo0Ooo
  if 97 - 97: I1IiiI
  if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
 for i1I in lisp_db_list :
  for iIIoOo in i1I . rloc_set :
   iIIiI11 = iIIoOo . rloc
   OoO00OooO0 = iIIoOo . interface
   oOo = iIIoOo . rloc_name
   if ( iIIoOo . is_decent_nat_port ( ) ) :
    oOo = oOo . split ( LISP_TP ) [ 0 ]
    if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
    if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
   if ( OoO00OooO0 == None ) :
    if ( iIIiI11 . is_null ( ) ) : continue
    if ( iIIiI11 . is_local ( ) == False ) : continue
    if ( i1IIIIIi111 . private_etr_rloc . is_null ( ) == False and
 iIIiI11 . is_exact_match ( i1IIIIIi111 . private_etr_rloc ) == False ) :
     continue
     if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
   elif ( i1IIIIIi111 . private_etr_rloc . is_dist_name ( ) ) :
    oo0000o0oO = i1IIIIIi111 . private_etr_rloc . address
    if ( oo0000o0oO != oOo ) : continue
    if 41 - 41: OOooOOo / I1ii11iIi11i % OOooOOo * I11i / OOooOOo - oO0o
    if 18 - 18: i1IIi - OOooOOo - o0oOOo0O0Ooo - iIii1I11I1II1
   oOOoo = green ( i1I . eid . print_prefix ( ) , False )
   o00oO = red ( iIIiI11 . print_address_no_iid ( ) , False )
   if 72 - 72: OoooooooOO % I1IiiI . OoO0O00
   Iiii = i1IIIIIi111 . global_etr_rloc . is_exact_match ( iIIiI11 )
   if ( iIIoOo . translated_port == 0 and Iiii ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( o00oO ,
 OoO00OooO0 , oOOoo ) )
    continue
    if 57 - 57: o0oOOo0O0Ooo . I1IiiI / OoooooooOO . ooOoO0o + O0 * oO0o
    if 19 - 19: IiII - OoO0O00 . OOooOOo
    if 56 - 56: iIii1I11I1II1 / O0 + Oo0Ooo
    if 5 - 5: O0 / i11iIiiIii * I1IiiI % IiII * OoO0O00
    if 67 - 67: I1Ii111 . iII111i + Oo0Ooo / i11iIiiIii
   iiI1IIi1III = i1IIIIIi111 . global_etr_rloc
   i1iIiii1iI = iIIoOo . translated_rloc
   if ( i1iIiii1iI . is_exact_match ( iiI1IIi1III ) and
 i1IIIIIi111 . etr_port == iIIoOo . translated_port ) : continue
   if 93 - 93: Ii1I - iII111i - O0 * OoO0O00
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( i1IIIIIi111 . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # Oo0Ooo
 i1IIIIIi111 . etr_port , o00oO , OoO00OooO0 , oOOoo ) )
   if 63 - 63: II111iiii * I11i
   iIIoOo . rloc_name = oOo
   iIIoOo . store_translated_rloc ( i1IIIIIi111 . global_etr_rloc ,
 i1IIIIIi111 . etr_port )
   if 89 - 89: II111iiii * oO0o . OoooooooOO / IiII / IiII + iII111i
   III1 = True
   if 15 - 15: OoOoOO00 . IiII / iIii1I11I1II1 . OoooooooOO
   if 14 - 14: IiII * OoooooooOO - iIii1I11I1II1
 return ( [ i1IIIIIi111 . global_etr_rloc , i1IIIIIi111 . etr_port , III1 ] )
 if 11 - 11: I1IiiI + Oo0Ooo % I1Ii111 * Ii1I - iIii1I11I1II1 % I1ii11iIi11i
 if 43 - 43: o0oOOo0O0Ooo * o0oOOo0O0Ooo . iII111i / Oo0Ooo - i11iIiiIii
 if 66 - 66: I1IiiI / i1IIi + o0oOOo0O0Ooo % IiII - OoOoOO00 / Oo0Ooo
 if 22 - 22: oO0o % I1Ii111 - I1Ii111 / I1Ii111
 if 25 - 25: OoooooooOO / oO0o / ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
 if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
 if 33 - 33: OOooOOo % OoooooooOO
 if 98 - 98: Ii1I
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
 o0Ooo0Oooo0o = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 oo0oo = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 53 - 53: ooOoO0o . ooOoO0o
 if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
 if 18 - 18: OoO0O00 * ooOoO0o
 if 32 - 32: oO0o . OoooooooOO - o0oOOo0O0Ooo + II111iiii
 o0Ooo0Oooo0o . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , o0Ooo0Oooo0o , None )
 o0Ooo0Oooo0o . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , o0Ooo0Oooo0o , None )
 if 4 - 4: OOooOOo * I1IiiI - I11i - I11i
 if 67 - 67: I1IiiI
 if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
 if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 oo0oo . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , oo0oo , None )
 oo0oo . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , oo0oo , None )
 if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
 if 59 - 59: i11iIiiIii
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
 if 59 - 59: I1ii11iIi11i
 iII1Iii = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 iII1Iii . start ( )
 return
 if 69 - 69: ooOoO0o * O0 + iII111i + i1IIi
 if 18 - 18: ooOoO0o % OoooooooOO - OOooOOo * oO0o - OOooOOo / oO0o
 if 83 - 83: ooOoO0o % iIii1I11I1II1 + Oo0Ooo
 if 10 - 10: IiII
 if 33 - 33: i11iIiiIii . i1IIi . I1Ii111 - OoOoOO00 + OOooOOo
 if 34 - 34: I1ii11iIi11i . i1IIi * O0 / OoooooooOO
 if 22 - 22: OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
 if 58 - 58: IiII . Ii1I + II111iiii
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 iI1ii11Ii = lisp_get_interface_address ( rloc . interface )
 if ( iI1ii11Ii == None ) : return
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 Ii1IiiI = rloc . rloc . print_address_no_iid ( )
 O00 = iI1ii11Ii . print_address_no_iid ( )
 if 75 - 75: i1IIi - oO0o * Ii1I / iIii1I11I1II1 - O0 - ooOoO0o
 if ( Ii1IiiI == O00 ) : return
 if 88 - 88: ooOoO0o / ooOoO0o . I11i
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , Ii1IiiI , O00 ) )
 if 2 - 2: OoO0O00 * OoO0O00 * Ii1I + iII111i + OOooOOo - II111iiii
 if 76 - 76: II111iiii * o0oOOo0O0Ooo - IiII
 rloc . rloc . copy_address ( iI1ii11Ii )
 lisp_myrlocs [ 0 ] = iI1ii11Ii
 return
 if 93 - 93: iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . o0oOOo0O0Ooo / iII111i
 if 7 - 7: ooOoO0o
 if 11 - 11: iII111i . oO0o % I11i
 if 42 - 42: I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 * i11iIiiIii + Ii1I . ooOoO0o / OOooOOo * O0
 if 44 - 44: Oo0Ooo * o0oOOo0O0Ooo - I11i
 if 56 - 56: Ii1I * OoO0O00 % ooOoO0o . I11i % I1Ii111
 if 78 - 78: i1IIi * OOooOOo . I1ii11iIi11i . iIii1I11I1II1 + i1IIi % Ii1I
def lisp_update_encap_port ( mc ) :
 for iIIiI11 in mc . rloc_set :
  IIi = iIIiI11 . normalize_decent_nat_rloc_name ( )
  oO00OOoOOoO = lisp_get_nat_info ( iIIiI11 . rloc , IIi )
  if ( oO00OOoOOoO == None ) : continue
  if ( iIIiI11 . translated_port == oO00OOoOOoO . port ) : continue
  if 31 - 31: iII111i + Oo0Ooo / I1ii11iIi11i / I1IiiI * OoooooooOO . I1ii11iIi11i
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( iIIiI11 . translated_port , oO00OOoOOoO . port ,
  # i11iIiiIii - OoooooooOO . ooOoO0o / i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i
 red ( iIIiI11 . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 45 - 45: I1ii11iIi11i * I1ii11iIi11i
  iIIiI11 . store_translated_rloc ( iIIiI11 . rloc , oO00OOoOOoO . port )
  if 31 - 31: OoO0O00 - OOooOOo . iII111i * I1Ii111 * iII111i + I1ii11iIi11i
 return
 if 5 - 5: Oo0Ooo . I1Ii111
 if 77 - 77: i11iIiiIii / I1Ii111 / I1ii11iIi11i % oO0o
 if 83 - 83: Ii1I % iIii1I11I1II1 / I1ii11iIi11i + I11i
 if 23 - 23: iIii1I11I1II1 - I1IiiI
 if 51 - 51: OoooooooOO / IiII / I1ii11iIi11i . Oo0Ooo - o0oOOo0O0Ooo * OoooooooOO
 if 40 - 40: OoO0O00 / IiII . O0 / I1IiiI + OoO0O00 . o0oOOo0O0Ooo
 if 25 - 25: ooOoO0o * I1Ii111 * oO0o
 if 64 - 64: Ii1I / I1ii11iIi11i
 if 30 - 30: OoooooooOO + O0 / I1ii11iIi11i * o0oOOo0O0Ooo
 if 11 - 11: O0 + OoO0O00 - Oo0Ooo - Oo0Ooo . i11iIiiIii
 if 15 - 15: Ii1I % i11iIiiIii / OoOoOO00
 if 85 - 85: ooOoO0o . i1IIi / iII111i % iIii1I11I1II1 / II111iiii / I1Ii111
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 60 - 60: iIii1I11I1II1 - iIii1I11I1II1 . I11i
  if 55 - 55: OoO0O00
 I1IIII1IIiIi = lisp_get_timestamp ( )
 O0o0OoOO = mc . last_refresh_time
 if 68 - 68: Ii1I
 if 47 - 47: iII111i * I1Ii111 % o0oOOo0O0Ooo / OoOoOO00 / OoO0O00 % OoO0O00
 if 43 - 43: Oo0Ooo
 if 34 - 34: OoO0O00 . i1IIi + IiII * IiII
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
 if ( lisp_is_running ( "lisp-ms" ) and lisp_uptime + ( 5 * 60 ) >= I1IIII1IIiIi ) :
  if ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
   O0o0OoOO = 0
   lprint ( "Remove startup-mode native-forward map-cache entry" )
   if 66 - 66: o0oOOo0O0Ooo
   if 40 - 40: OOooOOo * Ii1I
   if 38 - 38: ooOoO0o
   if 5 - 5: OoooooooOO + iII111i - I11i
   if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
   if 7 - 7: I1ii11iIi11i
   if 37 - 37: O0 . II111iiii
 OOO0O = ( mc . action != LISP_NOT_REGISTERED_YET_ACTION )
 if 21 - 21: Ii1I % Oo0Ooo . iII111i . O0 + iIii1I11I1II1
 if 42 - 42: oO0o . OOooOOo * OoO0O00
 if 88 - 88: I1ii11iIi11i
 if 21 - 21: i1IIi . I1IiiI / OoooooooOO % oO0o
 if 31 - 31: O0
 if 37 - 37: Oo0Ooo . OoOoOO00 % I1ii11iIi11i * O0
 if ( OOO0O and O0o0OoOO + mc . map_cache_ttl > I1IIII1IIiIi ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 20 - 20: ooOoO0o + I1IiiI - IiII % ooOoO0o - IiII . oO0o
  if 39 - 39: O0 / oO0o % oO0o * iIii1I11I1II1
  if 7 - 7: iII111i % o0oOOo0O0Ooo / II111iiii % IiII / iIii1I11I1II1
  if 17 - 17: I11i * I11i - O0 / IiII + OoOoOO00
  if 65 - 65: I1Ii111 * i1IIi
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 10 - 10: OOooOOo % IiII
  if 20 - 20: I11i / OoooooooOO % OoOoOO00 . oO0o * I1IiiI % IiII
  if 84 - 84: I1ii11iIi11i % I11i / OOooOOo % O0
  if 63 - 63: Ii1I / I1ii11iIi11i / Oo0Ooo
  if 74 - 74: i1IIi
 iiiI1Iii11iii = lisp_print_elapsed ( mc . uptime )
 i1iIiii = lisp_print_elapsed ( mc . last_refresh_time )
 Ooo = mc . print_eid_tuple ( )
 lprint ( ( "Map-cache entry {} {}, had uptime {}, last-refresh-time {}, " + "action was {}" ) . format ( green ( Ooo , False ) ,
 # OoooooooOO . OoO0O00 . OoooooooOO * I1ii11iIi11i - Oo0Ooo - iIii1I11I1II1
 bold ( "timed out" , False ) , iiiI1Iii11iii , i1iIiii ,
 lisp_map_reply_action_string [ mc . action ] ) )
 if 91 - 91: iIii1I11I1II1 * Ii1I
 if 37 - 37: I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
 if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
 if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
 if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
 if 2 - 2: I11i - II111iiii / I1Ii111
 if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
 if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
 if 76 - 76: ooOoO0o . I11i * OoO0O00
def lisp_timeout_map_cache_walk ( mc , parms ) :
 O0OOOo = parms [ 0 ]
 OooO = parms [ 1 ]
 if 89 - 89: o0oOOo0O0Ooo - OOooOOo * I1Ii111 . i1IIi % I1IiiI . I11i
 if 99 - 99: I1Ii111 * ooOoO0o
 if 9 - 9: I1Ii111
 if 26 - 26: iIii1I11I1II1 - I11i . Oo0Ooo - I1Ii111
 if ( mc . group . is_null ( ) ) :
  oOOo0OOo00 , O0OOOo = lisp_timeout_map_cache_entry ( mc , O0OOOo )
  if ( O0OOOo == [ ] or mc != O0OOOo [ - 1 ] ) :
   OooO = lisp_write_checkpoint_entry ( OooO , mc )
   parms [ 1 ] = OooO
   if 3 - 3: I1IiiI + I1ii11iIi11i - I11i
  parms [ 0 ] = O0OOOo
  return ( [ oOOo0OOo00 , parms ] )
  if 15 - 15: OoOoOO00 . Oo0Ooo / ooOoO0o + Oo0Ooo - OoooooooOO - o0oOOo0O0Ooo
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 64 - 64: OOooOOo
 if 44 - 44: O0 % ooOoO0o - iIii1I11I1II1 * i11iIiiIii . OoOoOO00
 if 32 - 32: I1ii11iIi11i - iII111i
 if 34 - 34: OOooOOo . i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1ii11iIi11i
 O0OOOo = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , O0OOOo )
 parms [ 0 ] = O0OOOo
 return ( [ True , parms ] )
 if 32 - 32: i11iIiiIii . I1Ii111
 if 38 - 38: O0
 if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
 if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
 if 59 - 59: II111iiii - o0oOOo0O0Ooo * OoooooooOO
 if 83 - 83: oO0o . iIii1I11I1II1 . iII111i % Oo0Ooo
 if 48 - 48: oO0o % OoO0O00 - OoooooooOO . IiII
def lisp_timeout_map_cache ( lisp_map_cache ) :
 i11i11Iiii11i = [ [ ] , [ ] ]
 i11i11Iiii11i = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , i11i11Iiii11i )
 if 11 - 11: I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i
 if 33 - 33: OoO0O00 + II111iiii . Oo0Ooo * I1Ii111
 if 63 - 63: OoooooooOO + OoOoOO00 - OoooooooOO
 if 54 - 54: OoO0O00 + I1IiiI % O0 + OoO0O00
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 O0OOOo = i11i11Iiii11i [ 0 ]
 for I1I1i1I11I in O0OOOo : I1I1i1I11I . delete_cache ( )
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 OooO = i11i11Iiii11i [ 1 ]
 lisp_checkpoint ( OooO )
 return
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
 if 48 - 48: iII111i / II111iiii * I1Ii111 + I11i / ooOoO0o . OoOoOO00
 if 45 - 45: OOooOOo / Ii1I % O0
 if 7 - 7: oO0o * i11iIiiIii + OoooooooOO + I11i
 if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
 if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
 if 96 - 96: oO0o
 if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
 if 64 - 64: I1IiiI % i11iIiiIii / oO0o
 if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
 if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
 if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 if 31 - 31: OoO0O00
def lisp_store_nat_info ( hostname , rloc , port ) :
 O00oO000Oo0 = rloc . print_address_no_iid ( )
 ooOoO = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( O00oO000Oo0 , False ) , port )
 if 83 - 83: OoOoOO00 * oO0o . OOooOOo - OoO0O00
 oOo0O = lisp_nat_info ( O00oO000Oo0 , hostname , port )
 if 85 - 85: Ii1I
 if ( hostname not in lisp_nat_state_info ) :
  lisp_nat_state_info [ hostname ] = [ oOo0O ]
  lprint ( ooOoO . format ( "Store initial" ) )
  return ( True )
  if 67 - 67: i11iIiiIii / II111iiii . i11iIiiIii * i11iIiiIii / ooOoO0o . oO0o
  if 46 - 46: oO0o . OoO0O00 - iIii1I11I1II1 . IiII
  if 52 - 52: i11iIiiIii / O0 + oO0o . I11i
  if 73 - 73: OoooooooOO / I1IiiI % Oo0Ooo . oO0o + OoooooooOO
  if 84 - 84: I1ii11iIi11i - OOooOOo * II111iiii
  if 28 - 28: I1ii11iIi11i . oO0o / o0oOOo0O0Ooo - iII111i
 oO00OOoOOoO = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( oO00OOoOOoO . address == O00oO000Oo0 and oO00OOoOOoO . port == port ) :
  oO00OOoOOoO . uptime = lisp_get_timestamp ( )
  lprint ( ooOoO . format ( "Refresh existing" ) )
  return ( False )
  if 65 - 65: I1ii11iIi11i * OOooOOo * ooOoO0o + oO0o - OOooOOo
  if 100 - 100: iII111i
  if 12 - 12: OoooooooOO - I1ii11iIi11i * iII111i / ooOoO0o
  if 99 - 99: I1ii11iIi11i + I11i
  if 29 - 29: I1ii11iIi11i / oO0o
  if 2 - 2: Oo0Ooo / IiII - OoooooooOO
  if 65 - 65: OoO0O00 - Ii1I
 I1i11111Iiii = None
 for oO00OOoOOoO in lisp_nat_state_info [ hostname ] :
  if ( oO00OOoOOoO . address == O00oO000Oo0 and oO00OOoOOoO . port == port ) :
   I1i11111Iiii = oO00OOoOOoO
   break
   if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
   if 15 - 15: Oo0Ooo
   if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
 if ( I1i11111Iiii == None ) :
  lprint ( ooOoO . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( I1i11111Iiii )
  lprint ( ooOoO . format ( "Use previous" ) )
  if 84 - 84: o0oOOo0O0Ooo * I11i
  if 22 - 22: i1IIi + OOooOOo % OoooooooOO
 IIIi1 = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ oOo0O ] + IIIi1
 return ( True )
 if 26 - 26: I11i + o0oOOo0O0Ooo / OoO0O00
 if 55 - 55: i11iIiiIii
 if 46 - 46: OoooooooOO . OoOoOO00
 if 8 - 8: O0 + OOooOOo * OoooooooOO . IiII
 if 25 - 25: OoOoOO00 * OoOoOO00 * Oo0Ooo / iIii1I11I1II1
 if 63 - 63: IiII - ooOoO0o % OoO0O00 * i11iIiiIii % OOooOOo
 if 90 - 90: oO0o / Oo0Ooo + iII111i - O0
 if 76 - 76: ooOoO0o + IiII / I1ii11iIi11i . iIii1I11I1II1
def lisp_get_nat_info ( rloc , hostname ) :
 O00oO000Oo0 = rloc . print_address_no_iid ( )
 if 52 - 52: iIii1I11I1II1 * OOooOOo % i1IIi
 if ( hostname == None ) :
  for hostname in lisp_nat_state_info :
   for oO00OOoOOoO in lisp_nat_state_info [ hostname ] :
    if ( oO00OOoOOoO . address == O00oO000Oo0 ) : return ( oO00OOoOOoO )
    if 1 - 1: o0oOOo0O0Ooo + Ii1I - o0oOOo0O0Ooo % I1ii11iIi11i
    if 61 - 61: OoooooooOO
  return ( None )
  if 93 - 93: OoO0O00
  if 18 - 18: OoOoOO00 - OoOoOO00 . iII111i / Oo0Ooo % Ii1I / iIii1I11I1II1
 if ( hostname not in lisp_nat_state_info ) : return ( None )
 if 97 - 97: ooOoO0o * ooOoO0o / IiII / iII111i . i11iIiiIii
 for oO00OOoOOoO in lisp_nat_state_info [ hostname ] :
  if ( oO00OOoOOoO . address == O00oO000Oo0 ) : return ( oO00OOoOOoO )
  if 29 - 29: Oo0Ooo % i1IIi - I11i * OoooooooOO + iII111i
 return ( None )
 if 82 - 82: IiII - I1Ii111 - I1ii11iIi11i
 if 35 - 35: oO0o % OoOoOO00 + iII111i . I1Ii111 . IiII - OoooooooOO
 if 69 - 69: O0 . Ii1I / O0
 if 61 - 61: OoooooooOO / OOooOOo / iII111i % II111iiii
 if 97 - 97: I1Ii111 / iIii1I11I1II1 * OOooOOo + i11iIiiIii
 if 86 - 86: OoO0O00 - I1Ii111 * OoO0O00
 if 29 - 29: I1Ii111 % OoOoOO00 . oO0o / oO0o % I11i
 if 91 - 91: o0oOOo0O0Ooo
 if 59 - 59: I11i . I11i
 if 98 - 98: II111iiii
 if 20 - 20: iIii1I11I1II1
 if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
 if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
 if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
 if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
 if 16 - 16: o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii . I1ii11iIi11i
 if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 if 83 - 83: OoooooooOO % I1ii11iIi11i . IiII + OOooOOo . iII111i - ooOoO0o
 if 100 - 100: o0oOOo0O0Ooo
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 95 - 95: iII111i * oO0o * i1IIi
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 o0O0o0o = [ ]
 OOOO0Oo0ooo0OO0oo = [ ]
 if ( dest == None ) :
  for oOoOO0oOo00Oo in list ( lisp_map_resolvers_list . values ( ) ) :
   OOOO0Oo0ooo0OO0oo . append ( oOoOO0oOo00Oo . map_resolver )
   if 9 - 9: iIii1I11I1II1 . I1IiiI
  o0O0o0o = OOOO0Oo0ooo0OO0oo
  if ( o0O0o0o == [ ] ) :
   for ii1iIIiIIi111 in list ( lisp_map_servers_list . values ( ) ) :
    o0O0o0o . append ( ii1iIIiIIi111 . map_server )
    if 92 - 92: iIii1I11I1II1 - I11i - OOooOOo / Ii1I . o0oOOo0O0Ooo . OoO0O00
    if 33 - 33: oO0o / I11i % ooOoO0o * I11i / oO0o - OoOoOO00
  if ( o0O0o0o == [ ] ) : return
 else :
  o0O0o0o . append ( dest )
  if 89 - 89: iIii1I11I1II1 . II111iiii + IiII
  if 8 - 8: I1ii11iIi11i / II111iiii / II111iiii
  if 62 - 62: I11i - iII111i . Ii1I
  if 20 - 20: I1ii11iIi11i
  if 99 - 99: o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 O00O0oooO0 = { }
 for i1I in lisp_db_list :
  for iIIoOo in i1I . rloc_set :
   lisp_update_local_rloc ( iIIoOo )
   if ( iIIoOo . rloc . is_null ( ) ) : continue
   if ( iIIoOo . interface == None ) : continue
   if 67 - 67: I1IiiI
   iI1ii11Ii = iIIoOo . rloc . print_address_no_iid ( )
   if ( iI1ii11Ii in O00O0oooO0 ) : continue
   O00O0oooO0 [ iI1ii11Ii ] = iIIoOo . interface
   if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
   if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 if ( O00O0oooO0 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 33 - 33: OOooOOo - OoooooooOO . iII111i
  return
  if 2 - 2: I11i + i1IIi
  if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
 if ( len ( O00O0oooO0 ) > 1 ) :
  lprint ( "NAT multihoming local RLOC-list {}" . format ( O00O0oooO0 ) )
  if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
  if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
  if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
  if 12 - 12: II111iiii * O0 - Oo0Ooo + o0oOOo0O0Ooo . Oo0Ooo + iIii1I11I1II1
  if 4 - 4: I1Ii111 - I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / oO0o
  if 18 - 18: iIii1I11I1II1 . ooOoO0o
 for iI1ii11Ii in O00O0oooO0 :
  OoO00OooO0 = O00O0oooO0 [ iI1ii11Ii ]
  I1II1I1I = red ( iI1ii11Ii , False )
  lprint ( "Build Info-Request for private address {} on {}" . format ( I1II1I1I ,
 OoO00OooO0 ) )
  ooo = OoO00OooO0 if len ( O00O0oooO0 ) > 1 else None
  for dest in o0O0o0o :
   lisp_send_info_request ( lisp_sockets , dest , port , ooo )
   if 68 - 68: o0oOOo0O0Ooo
   if 36 - 36: Oo0Ooo . I11i + I1IiiI * i1IIi % Ii1I + OOooOOo
   if 5 - 5: o0oOOo0O0Ooo % oO0o / OoO0O00
   if 17 - 17: OoooooooOO - I1ii11iIi11i / OoO0O00 - I1Ii111 + i1IIi
   if 6 - 6: Oo0Ooo - II111iiii
   if 33 - 33: I1Ii111 - I1IiiI + iII111i . OoOoOO00
 if ( OOOO0Oo0ooo0OO0oo != [ ] ) :
  for oOoOO0oOo00Oo in list ( lisp_map_resolvers_list . values ( ) ) :
   oOoOO0oOo00Oo . resolve_dns_name ( )
   if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
   if 68 - 68: I11i
 return
 if 91 - 91: I11i
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
 if 71 - 71: OoOoOO00
 if 29 - 29: O0 . i11iIiiIii
 if 51 - 51: IiII
 if 53 - 53: O0
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
 if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
 if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
 if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
 if 54 - 54: IiII
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 85 - 85: OOooOOo - i1IIi
 if 10 - 10: I1ii11iIi11i
 if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
 if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
 if ( value . find ( "." ) != - 1 ) :
  iI1ii11Ii = value . split ( "." )
  if ( len ( iI1ii11Ii ) != 4 ) : return ( False )
  if 23 - 23: OoOoOO00 * I1Ii111
  for i11iI1I1 in iI1ii11Ii :
   if ( i11iI1I1 . isdigit ( ) == False ) : return ( False )
   if ( int ( i11iI1I1 ) > 255 ) : return ( False )
   if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
  return ( True )
  if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
  if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
  if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
  if 25 - 25: OoO0O00 * oO0o
  if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
 if ( value . find ( "-" ) != - 1 ) :
  iI1ii11Ii = value . split ( "-" )
  for o000o0O0Oo00 in [ "N" , "S" , "W" , "E" ] :
   if ( o000o0O0Oo00 in iI1ii11Ii ) :
    if ( len ( iI1ii11Ii ) < 8 ) : return ( False )
    return ( True )
    if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
    if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
    if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
    if 73 - 73: Oo0Ooo + II111iiii - IiII
    if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
    if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
    if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
 if ( value . find ( "-" ) != - 1 ) :
  iI1ii11Ii = value . split ( "-" )
  if ( len ( iI1ii11Ii ) != 3 ) : return ( False )
  if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
  for oO00OOO in iI1ii11Ii :
   try : int ( oO00OOO , 16 )
   except : return ( False )
   if 77 - 77: II111iiii / o0oOOo0O0Ooo
  return ( True )
  if 89 - 89: OoOoOO00 . I1ii11iIi11i * o0oOOo0O0Ooo . OoOoOO00 - i11iIiiIii * IiII
  if 37 - 37: OoooooooOO - I1Ii111 . Ii1I . i1IIi * IiII / ooOoO0o
  if 12 - 12: OoooooooOO
  if 8 - 8: i11iIiiIii . I1Ii111 * o0oOOo0O0Ooo . ooOoO0o
  if 94 - 94: I1ii11iIi11i % OoOoOO00 - OoooooooOO
 if ( value . find ( ":" ) != - 1 ) :
  iI1ii11Ii = value . split ( ":" )
  if ( len ( iI1ii11Ii ) < 2 ) : return ( False )
  if 42 - 42: I1Ii111 - i1IIi
  O0Iii = False
  oo0O00ooo0o = 0
  for oO00OOO in iI1ii11Ii :
   oo0O00ooo0o += 1
   if ( oO00OOO == "" ) :
    if ( O0Iii ) :
     if ( len ( iI1ii11Ii ) == oo0O00ooo0o ) : break
     if ( oo0O00ooo0o > 2 ) : return ( False )
     if 39 - 39: II111iiii
    O0Iii = True
    continue
    if 49 - 49: i11iIiiIii - OoO0O00
   try : int ( oO00OOO , 16 )
   except : return ( False )
   if 81 - 81: I11i - OOooOOo / oO0o - ooOoO0o
  return ( True )
  if 60 - 60: OoO0O00 / I1ii11iIi11i % iII111i % i11iIiiIii * OoooooooOO * iII111i
  if 92 - 92: I11i % iIii1I11I1II1 * iII111i - OoooooooOO - I11i
  if 34 - 34: I1Ii111 / i1IIi / O0 / OoooooooOO
  if 55 - 55: I1Ii111 . I1IiiI * iIii1I11I1II1 / Ii1I . I1IiiI
  if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if ( value [ 0 ] == "+" ) :
  iI1ii11Ii = value [ 1 : : ]
  for ooOoo0o in iI1ii11Ii :
   if ( ooOoo0o . isdigit ( ) == False ) : return ( False )
   if 44 - 44: OoooooooOO . i1IIi + Ii1I * O0 % i1IIi % I11i
  return ( True )
  if 98 - 98: I1IiiI - II111iiii % II111iiii % OOooOOo
 return ( False )
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
def lisp_process_api ( process , lisp_socket , data_structure ) :
 OO00oo , i11i11Iiii11i = data_structure . split ( "%" )
 if 38 - 38: I1IiiI + OoO0O00 % iII111i / ooOoO0o
 lprint ( "Process API request '{}', parameters: '{}'" . format ( OO00oo ,
 i11i11Iiii11i ) )
 if 93 - 93: OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
 ooo0o0oO = [ ]
 if ( OO00oo == "map-cache" ) :
  if ( i11i11Iiii11i == "" ) :
   ooo0o0oO = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , ooo0o0oO )
  else :
   ooo0o0oO = lisp_process_api_map_cache_entry ( json . loads ( i11i11Iiii11i ) )
   if 90 - 90: iIii1I11I1II1 . Ii1I / i11iIiiIii . oO0o . I11i - I11i
   if 46 - 46: I11i
 if ( OO00oo == "site-cache" ) :
  if ( i11i11Iiii11i == "" ) :
   ooo0o0oO = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 ooo0o0oO )
  else :
   ooo0o0oO = lisp_process_api_site_cache_entry ( json . loads ( i11i11Iiii11i ) )
   if 2 - 2: I1Ii111 * oO0o
   if 93 - 93: I11i
 if ( OO00oo == "site-cache-summary" ) :
  ooo0o0oO = lisp_process_api_site_cache_summary ( lisp_sites_by_eid )
  if 2 - 2: i1IIi / I1IiiI
 if ( OO00oo == "map-server" ) :
  i11i11Iiii11i = { } if ( i11i11Iiii11i == "" ) else json . loads ( i11i11Iiii11i )
  ooo0o0oO = lisp_process_api_ms_or_mr ( True , i11i11Iiii11i )
  if 29 - 29: Ii1I * iIii1I11I1II1 * i1IIi
 if ( OO00oo == "map-resolver" ) :
  i11i11Iiii11i = { } if ( i11i11Iiii11i == "" ) else json . loads ( i11i11Iiii11i )
  ooo0o0oO = lisp_process_api_ms_or_mr ( False , i11i11Iiii11i )
  if 83 - 83: oO0o % O0 . I11i / I11i / I1IiiI - OoOoOO00
 if ( OO00oo == "database-mapping" ) :
  ooo0o0oO = lisp_process_api_database_mapping ( )
  if 91 - 91: iIii1I11I1II1 - IiII + iIii1I11I1II1 % Oo0Ooo % I1IiiI
  if 84 - 84: iIii1I11I1II1 . Oo0Ooo - OoooooooOO % Oo0Ooo
  if 27 - 27: I1ii11iIi11i - ooOoO0o + I11i - I1ii11iIi11i
  if 57 - 57: Oo0Ooo
  if 31 - 31: I1IiiI % Ii1I / OOooOOo + OoooooooOO . i11iIiiIii
 ooo0o0oO = json . dumps ( ooo0o0oO )
 ii1I11Iii = lisp_api_ipc ( process , ooo0o0oO )
 lisp_ipc ( ii1I11Iii , lisp_socket , "lisp-core" )
 return
 if 87 - 87: iII111i + IiII * I1ii11iIi11i . iII111i + Ii1I - II111iiii
 if 87 - 87: OoOoOO00 . o0oOOo0O0Ooo + I1ii11iIi11i
 if 53 - 53: o0oOOo0O0Ooo * II111iiii + i1IIi
 if 83 - 83: I11i * o0oOOo0O0Ooo * Ii1I + OoooooooOO
 if 76 - 76: I1ii11iIi11i . OoooooooOO + ooOoO0o / I1IiiI
 if 56 - 56: Ii1I % I11i / O0 % O0 % iIii1I11I1II1 + I1IiiI
 if 51 - 51: O0 * Ii1I / oO0o * OoooooooOO
def lisp_process_api_map_cache ( mc , data ) :
 if 93 - 93: I1ii11iIi11i . OOooOOo + i1IIi
 if 30 - 30: Oo0Ooo + I1Ii111 / OOooOOo
 if 74 - 74: iIii1I11I1II1
 if 69 - 69: ooOoO0o % iIii1I11I1II1 * o0oOOo0O0Ooo + OoOoOO00 % I1Ii111 % Oo0Ooo
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 64 - 64: iIii1I11I1II1 * Ii1I * ooOoO0o * i11iIiiIii
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 54 - 54: IiII . Ii1I
 if 54 - 54: iII111i
 if 2 - 2: OoOoOO00 + I1IiiI . ooOoO0o - oO0o . iIii1I11I1II1
 if 76 - 76: Ii1I
 if 31 - 31: ooOoO0o
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 70 - 70: O0
 if 42 - 42: I1Ii111 + OoooooooOO + I11i
 if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
 if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
 if 27 - 27: O0 / Oo0Ooo . oO0o
 if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
 if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
def lisp_gather_map_cache_data ( mc , data ) :
 iIiiI11II11i = { }
 iIiiI11II11i [ "instance-id" ] = str ( mc . eid . instance_id )
 iIiiI11II11i [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  iIiiI11II11i [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
 iIiiI11II11i [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 iIiiI11II11i [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 iIiiI11II11i [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 iIiiI11II11i [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
 iIiiI11II11i [ "eid-memory" ] = hex ( id ( mc ) )
 if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
 if 67 - 67: oO0o
 if 12 - 12: I1IiiI + OoooooooOO
 if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
 i1i1i1 = [ ]
 for iIIiI11 in mc . rloc_set :
  I1I1 = lisp_fill_rloc_in_json ( iIIiI11 )
  if 19 - 19: OoooooooOO / IiII
  if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
  if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
  if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
  if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
  if ( iIIiI11 . rloc . is_multicast_address ( ) ) :
   I1I1 [ "multicast-rloc-set" ] = [ ]
   for ii1OOO0 in list ( iIIiI11 . multicast_rloc_probe_list . values ( ) ) :
    oOoOO0oOo00Oo = lisp_fill_rloc_in_json ( ii1OOO0 )
    I1I1 [ "multicast-rloc-set" ] . append ( oOoOO0oOo00Oo )
    if 51 - 51: OoO0O00 - OoO0O00 * IiII
    if 24 - 24: OoooooooOO . II111iiii
    if 97 - 97: II111iiii . O0
  i1i1i1 . append ( I1I1 )
  if 18 - 18: iII111i
 iIiiI11II11i [ "rloc-set" ] = i1i1i1
 if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
 data . append ( iIiiI11II11i )
 return ( [ True , data ] )
 if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
 if 25 - 25: OoO0O00
 if 54 - 54: O0
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
 if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 if 92 - 92: ooOoO0o - iII111i
 if 69 - 69: iII111i
 if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
def lisp_fill_rloc_in_json ( rloc ) :
 I1I1 = { }
 O00oO000Oo0 = None
 if ( rloc . rloc_exists ( ) ) :
  I1I1 [ "address" ] = rloc . rloc . print_address_no_iid ( )
  O00oO000Oo0 = I1I1 [ "address" ]
  if 63 - 63: oO0o * OoO0O00 * oO0o
  if 31 - 31: Oo0Ooo
 if ( rloc . translated_port != 0 ) :
  I1I1 [ "encap-port" ] = str ( rloc . translated_port )
  O00oO000Oo0 += ":" + I1I1 [ "encap-port" ]
  if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
  if 67 - 67: I1Ii111 . I1ii11iIi11i
 if ( O00oO000Oo0 and O00oO000Oo0 in lisp_crypto_keys_by_rloc_encap ) :
  OoOOooOOoo = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ] [ 1 ]
  if ( OoOOooOOoo != None and OoOOooOOoo . shared_key != None ) :
   I1I1 [ "encap-crypto" ] = "crypto-" + OoOOooOOoo . cipher_suite_string
   if 2 - 2: O0 + I1Ii111
   if 82 - 82: Ii1I / iII111i
   if 13 - 13: I11i + iII111i
 I1I1 [ "rloc-memory" ] = hex ( id ( rloc ) )
 if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
 I1I1 [ "state" ] = rloc . print_state ( )
 if ( rloc . geo ) : I1I1 [ "geo" ] = rloc . geo . print_geo ( )
 if ( rloc . elp ) : I1I1 [ "elp" ] = rloc . elp . print_elp ( False )
 if ( rloc . rle ) : I1I1 [ "rle" ] = rloc . rle . print_api_rle ( )
 if ( rloc . json ) : I1I1 [ "json" ] = rloc . json . print_json ( False )
 if ( rloc . rloc_name ) : I1I1 [ "rloc-name" ] = rloc . rloc_name
 II1iiiiI1ii = rloc . stats . get_stats ( False , False )
 if ( II1iiiiI1ii ) :
  I1I1 [ "stats" ] = II1iiiiI1ii
  I1I1 [ "recent-packet-sec" ] = rloc . stats . recent_packet_sec ( )
  I1I1 [ "recent-packet-min" ] = rloc . stats . recent_packet_min ( )
  if 59 - 59: Oo0Ooo + I1ii11iIi11i
 O0OoOOOO00Ooo = lisp_print_elapsed ( rloc . last_state_change )
 if ( O0OoOOOO00Ooo == "never" ) :
  O0OoOOOO00Ooo = lisp_print_elapsed ( rloc . uptime )
  if 27 - 27: O0 % OoOoOO00 * Oo0Ooo * Ii1I * iII111i
 I1I1 [ "uptime" ] = O0OoOOOO00Ooo
 I1I1 [ "upriority" ] = str ( rloc . priority )
 I1I1 [ "uweight" ] = str ( rloc . weight )
 I1I1 [ "mpriority" ] = str ( rloc . mpriority )
 I1I1 [ "mweight" ] = str ( rloc . mweight )
 IiiIiIi = rloc . last_rloc_probe_reply
 if ( IiiIiIi ) :
  I1I1 [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( IiiIiIi )
  I1I1 [ "rloc-probe-rtt" ] = str ( rloc . rloc_probe_rtt )
  if 57 - 57: iIii1I11I1II1 / I1ii11iIi11i . I1Ii111
 I1I1 [ "rloc-hop-count" ] = rloc . rloc_probe_hops
 I1I1 [ "recent-rloc-hop-counts" ] = rloc . recent_rloc_probe_hops
 if 59 - 59: o0oOOo0O0Ooo * iII111i % o0oOOo0O0Ooo % I1IiiI
 I1I1 [ "rloc-probe-latency" ] = rloc . rloc_probe_latency
 I1I1 [ "recent-rloc-probe-latencies" ] = rloc . recent_rloc_probe_latencies
 if 7 - 7: i1IIi + Oo0Ooo
 OoOo = [ ]
 for I11i11IIIII in rloc . recent_rloc_probe_rtts : OoOo . append ( str ( I11i11IIIII ) )
 I1I1 [ "recent-rloc-probe-rtts" ] = OoOo
 return ( I1I1 )
 if 59 - 59: OoOoOO00 . Ii1I - ooOoO0o - oO0o
 if 13 - 13: OoOoOO00 . IiII / i11iIiiIii - OOooOOo
 if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
 if 55 - 55: I1Ii111 + ooOoO0o
 if 58 - 58: iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
 if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
 if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
def lisp_process_api_map_cache_entry ( parms ) :
 i1I1iI = parms [ "instance-id" ]
 i1I1iI = 0 if ( i1I1iI == "" ) else int ( i1I1iI )
 if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
 if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 o0Ooo0Oooo0o = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 o0Ooo0Oooo0o . store_prefix ( parms [ "eid-prefix" ] )
 oOOo0OOoOO0 = o0Ooo0Oooo0o
 OO = o0Ooo0Oooo0o
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
 if 49 - 49: II111iiii
 if 99 - 99: Oo0Ooo . OOooOOo
 oo0oOooo0O = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 if ( "group-prefix" in parms ) :
  oo0oOooo0O . store_prefix ( parms [ "group-prefix" ] )
  oOOo0OOoOO0 = oo0oOooo0O
  if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
  if 70 - 70: O0 % I1Ii111
 ooo0o0oO = [ ]
 I1I1i1I11I = lisp_map_cache_lookup ( OO , oOOo0OOoOO0 )
 if ( I1I1i1I11I ) : oOOo0OOo00 , ooo0o0oO = lisp_process_api_map_cache ( I1I1i1I11I , ooo0o0oO )
 return ( ooo0o0oO )
 if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
 if 82 - 82: ooOoO0o % Oo0Ooo
 if 26 - 26: OoO0O00 + i11iIiiIii % I11i . I1ii11iIi11i
 if 76 - 76: i1IIi + ooOoO0o - Oo0Ooo + OoOoOO00 / I1ii11iIi11i . OOooOOo
 if 50 - 50: IiII - Ii1I % iIii1I11I1II1
 if 60 - 60: o0oOOo0O0Ooo - Oo0Ooo
 if 92 - 92: OoOoOO00 + IiII . OoO0O00 % iII111i / II111iiii / I11i
 if 62 - 62: I1ii11iIi11i
 if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
 if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
def lisp_process_api_site_cache_summary ( site_cache ) :
 I11iII1 = { "site" : "" , "registrations" : [ ] }
 iIiiI11II11i = { "eid-prefix" : "" , "count" : 0 , "registered-count" : 0 }
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 OoOOO00o000OOO = { }
 for O00O00O in site_cache . cache_sorted :
  for OOoI1i1i1iIi in list ( site_cache . cache [ O00O00O ] . entries . values ( ) ) :
   if ( OOoI1i1i1iIi . accept_more_specifics == False ) : continue
   if ( OOoI1i1i1iIi . site . site_name not in OoOOO00o000OOO ) :
    OoOOO00o000OOO [ OOoI1i1i1iIi . site . site_name ] = [ ]
    if 86 - 86: oO0o - o0oOOo0O0Ooo
   oOO = copy . deepcopy ( iIiiI11II11i )
   oOO [ "eid-prefix" ] = OOoI1i1i1iIi . eid . print_prefix ( )
   oOO [ "count" ] = len ( OOoI1i1i1iIi . more_specific_registrations )
   for IiO0ooo00ooO00 in OOoI1i1i1iIi . more_specific_registrations :
    if ( IiO0ooo00ooO00 . registered ) : oOO [ "registered-count" ] += 1
    if 18 - 18: OOooOOo - i11iIiiIii % II111iiii + oO0o
   OoOOO00o000OOO [ OOoI1i1i1iIi . site . site_name ] . append ( oOO )
   if 82 - 82: Ii1I
   if 2 - 2: iII111i + I11i * I1ii11iIi11i - IiII
   if 97 - 97: iIii1I11I1II1 . II111iiii - II111iiii + I1ii11iIi11i
 ooo0o0oO = [ ]
 for i1i1I11I1I in OoOOO00o000OOO :
  OOo0oOO0o0oo0 = copy . deepcopy ( I11iII1 )
  OOo0oOO0o0oo0 [ "site" ] = i1i1I11I1I
  OOo0oOO0o0oo0 [ "registrations" ] = OoOOO00o000OOO [ i1i1I11I1I ]
  ooo0o0oO . append ( OOo0oOO0o0oo0 )
  if 30 - 30: Ii1I
 return ( ooo0o0oO )
 if 10 - 10: I1Ii111 / Ii1I * I1Ii111 / OoO0O00 - I1ii11iIi11i
 if 7 - 7: I1IiiI . OoO0O00 . OoOoOO00 . I1ii11iIi11i * OoO0O00 - IiII
 if 6 - 6: OoO0O00 + II111iiii - oO0o
 if 90 - 90: Oo0Ooo % Oo0Ooo + oO0o - OoooooooOO + OOooOOo % I11i
 if 61 - 61: I1IiiI % oO0o + OOooOOo - I1Ii111
 if 5 - 5: ooOoO0o . OoO0O00
 if 40 - 40: iII111i
def lisp_process_api_site_cache ( se , data ) :
 if 87 - 87: IiII / II111iiii
 if 44 - 44: OoO0O00 . I1Ii111 - OoooooooOO * OoOoOO00 . OoO0O00
 if 84 - 84: OOooOOo . OOooOOo . oO0o % iII111i * Oo0Ooo - iIii1I11I1II1
 if 4 - 4: iII111i
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 65 - 65: Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
 if 17 - 17: I1ii11iIi11i * OOooOOo % II111iiii
 if 30 - 30: I1Ii111 . Ii1I . Oo0Ooo / OOooOOo * OoooooooOO / I1ii11iIi11i
 if 41 - 41: i1IIi
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
 if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
 if 100 - 100: OoO0O00 . Oo0Ooo
 if 29 - 29: OoO0O00
 if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 if 63 - 63: O0 % iIii1I11I1II1 . o0oOOo0O0Ooo . I1IiiI * Ii1I % i1IIi
 if 47 - 47: II111iiii * I1ii11iIi11i
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 OOoo00 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 oooooO0O0O = data [ "dns-name" ] if ( "dns-name" in data ) else None
 if ( "address" in data ) :
  OOoo00 . store_address ( data [ "address" ] )
  if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
  if 71 - 71: I1ii11iIi11i * i1IIi
 oO00o = { }
 if ( ms_or_mr ) :
  for ii1iIIiIIi111 in list ( lisp_map_servers_list . values ( ) ) :
   if ( oooooO0O0O ) :
    if ( oooooO0O0O != ii1iIIiIIi111 . dns_name ) : continue
   else :
    if ( OOoo00 . is_exact_match ( ii1iIIiIIi111 . map_server ) == False ) : continue
    if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
    if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
   oO00o [ "dns-name" ] = ii1iIIiIIi111 . dns_name
   oO00o [ "address" ] = ii1iIIiIIi111 . map_server . print_address_no_iid ( )
   oO00o [ "ms-name" ] = "" if ii1iIIiIIi111 . ms_name == None else ii1iIIiIIi111 . ms_name
   return ( [ oO00o ] )
   if 57 - 57: OOooOOo . I11i % OoOoOO00
 else :
  for oOoOO0oOo00Oo in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( oooooO0O0O ) :
    if ( oooooO0O0O != oOoOO0oOo00Oo . dns_name ) : continue
   else :
    if ( OOoo00 . is_exact_match ( oOoOO0oOo00Oo . map_resolver ) == False ) : continue
    if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
    if 78 - 78: iII111i - OOooOOo / I1Ii111
   oO00o [ "dns-name" ] = oOoOO0oOo00Oo . dns_name
   oO00o [ "address" ] = oOoOO0oOo00Oo . map_resolver . print_address_no_iid ( )
   oO00o [ "mr-name" ] = "" if oOoOO0oOo00Oo . mr_name == None else oOoOO0oOo00Oo . mr_name
   return ( [ oO00o ] )
   if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
   if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
 return ( [ ] )
 if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 if 56 - 56: I11i % OoOoOO00 - OoO0O00
 if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
 if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
 if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
 if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
def lisp_process_api_database_mapping ( ) :
 ooo0o0oO = [ ]
 if 66 - 66: OoO0O00 * Ii1I . OoO0O00
 for i1I in lisp_db_list :
  iIiiI11II11i = { }
  iIiiI11II11i [ "eid-prefix" ] = i1I . eid . print_prefix ( )
  if ( i1I . group . is_null ( ) == False ) :
   iIiiI11II11i [ "group-prefix" ] = i1I . group . print_prefix ( )
   if 90 - 90: II111iiii % Ii1I
   if 67 - 67: I1IiiI - I11i - i11iIiiIii
  Oo0O0oo = [ ]
  for I1I1 in i1I . rloc_set :
   iIIiI11 = { }
   if ( I1I1 . rloc . is_null ( ) == False ) :
    iIIiI11 [ "rloc" ] = I1I1 . rloc . print_address_no_iid ( )
    if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
   if ( I1I1 . rloc_name != None ) : iIIiI11 [ "rloc-name" ] = I1I1 . rloc_name
   if ( I1I1 . interface != None ) : iIIiI11 [ "interface" ] = I1I1 . interface
   O0O = I1I1 . translated_rloc
   if ( O0O . is_null ( ) == False ) :
    iIIiI11 [ "translated-rloc" ] = O0O . print_address_no_iid ( )
    if ( I1I1 . translated_port != 0 ) :
     iIIiI11 [ "translated-port" ] = I1I1 . translated_port
     if 4 - 4: iII111i
     if 28 - 28: ooOoO0o % i1IIi % I1ii11iIi11i
   if ( iIIiI11 != { } ) : Oo0O0oo . append ( iIIiI11 )
   if 58 - 58: I1IiiI
   if 100 - 100: I11i % ooOoO0o - OOooOOo - I1IiiI * oO0o + I1IiiI
   if 7 - 7: iIii1I11I1II1 * o0oOOo0O0Ooo / I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
   if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
   if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
  iIiiI11II11i [ "rlocs" ] = Oo0O0oo
  if 57 - 57: I1Ii111 - IiII
  if 89 - 89: oO0o + iII111i
  if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
  if 7 - 7: II111iiii
  ooo0o0oO . append ( iIiiI11II11i )
  if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
 return ( ooo0o0oO )
 if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
 if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
 if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
 if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
 if 67 - 67: I1Ii111
 if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
 if 77 - 77: ooOoO0o
def lisp_gather_site_cache_data ( se , data ) :
 iIiiI11II11i = { }
 iIiiI11II11i [ "site-name" ] = se . site . site_name
 iIiiI11II11i [ "instance-id" ] = str ( se . eid . instance_id )
 iIiiI11II11i [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  iIiiI11II11i [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
 iIiiI11II11i [ "registered" ] = "yes" if se . registered else "no"
 iIiiI11II11i [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 iIiiI11II11i [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 6 - 6: iII111i / iII111i . i11iIiiIii
 iI1ii11Ii = se . last_registerer
 iI1ii11Ii = "none" if iI1ii11Ii . is_null ( ) else iI1ii11Ii . print_address ( )
 iIiiI11II11i [ "last-registerer" ] = iI1ii11Ii
 iIiiI11II11i [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 iIiiI11II11i [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 iIiiI11II11i [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  iIiiI11II11i [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 12 - 12: I11i - OoO0O00
  if 68 - 68: IiII - OoOoOO00
  if 22 - 22: i1IIi . IiII
  if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
  if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
 i1i1i1 = [ ]
 for iIIiI11 in se . registered_rlocs :
  I1I1 = { }
  I1I1 [ "address" ] = iIIiI11 . rloc . print_address_no_iid ( ) if iIIiI11 . rloc_exists ( ) else "none"
  if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
  if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
  if ( iIIiI11 . geo ) : I1I1 [ "geo" ] = iIIiI11 . geo . print_geo ( )
  if ( iIIiI11 . elp ) : I1I1 [ "elp" ] = iIIiI11 . elp . print_elp ( False )
  if ( iIIiI11 . rle ) : I1I1 [ "rle" ] = iIIiI11 . rle . print_rle ( False , True )
  if ( iIIiI11 . json ) : I1I1 [ "json" ] = iIIiI11 . json . print_json ( False )
  if ( iIIiI11 . rloc_name ) : I1I1 [ "rloc-name" ] = iIIiI11 . rloc_name
  I1I1 [ "uptime" ] = lisp_print_elapsed ( iIIiI11 . uptime )
  I1I1 [ "upriority" ] = str ( iIIiI11 . priority )
  I1I1 [ "uweight" ] = str ( iIIiI11 . weight )
  I1I1 [ "mpriority" ] = str ( iIIiI11 . mpriority )
  I1I1 [ "mweight" ] = str ( iIIiI11 . mweight )
  if ( iIIiI11 . translated_port != 0 ) :
   I1I1 [ "encap-port" ] = str ( iIIiI11 . translated_port )
   if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
   if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
   if 42 - 42: i1IIi . OoO0O00 % iII111i
  i1i1i1 . append ( I1I1 )
  if 57 - 57: I1ii11iIi11i / I1IiiI
 iIiiI11II11i [ "registered-rlocs" ] = i1i1i1
 if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
 data . append ( iIiiI11II11i )
 return ( [ True , data ] )
 if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 if 39 - 39: OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
 if 41 - 41: II111iiii . o0oOOo0O0Ooo
def lisp_process_api_site_cache_entry ( parms ) :
 i1I1iI = parms [ "instance-id" ]
 i1I1iI = 0 if ( i1I1iI == "" ) else int ( i1I1iI )
 if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
 if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
 if 15 - 15: OoO0O00
 if 37 - 37: OoO0O00 . OoooooooOO - OOooOOo
 o0Ooo0Oooo0o = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 o0Ooo0Oooo0o . store_prefix ( parms [ "eid-prefix" ] )
 if 34 - 34: o0oOOo0O0Ooo + iIii1I11I1II1 / o0oOOo0O0Ooo / ooOoO0o
 if 53 - 53: II111iiii / iIii1I11I1II1
 if 25 - 25: I1Ii111
 if 58 - 58: OoOoOO00 * i1IIi
 if 20 - 20: IiII
 oo0oOooo0O = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 if ( "group-prefix" in parms ) :
  oo0oOooo0O . store_prefix ( parms [ "group-prefix" ] )
  if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
  if 30 - 30: i11iIiiIii . I1IiiI
 ooo0o0oO = [ ]
 OOoI1i1i1iIi = lisp_site_eid_lookup ( o0Ooo0Oooo0o , oo0oOooo0O , False )
 if ( OOoI1i1i1iIi ) : lisp_gather_site_cache_data ( OOoI1i1i1iIi , ooo0o0oO )
 return ( ooo0o0oO )
 if 5 - 5: Ii1I / O0 + iIii1I11I1II1
 if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
def lisp_get_interface_instance_id ( device , source_eid ) :
 OoO00OooO0 = None
 if ( device in lisp_myinterfaces ) :
  OoO00OooO0 = lisp_myinterfaces [ device ]
  if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
  if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
  if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
  if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
  if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
  if 13 - 13: OOooOOo / OoooooooOO
 if ( OoO00OooO0 == None or OoO00OooO0 . instance_id == None ) :
  return ( lisp_default_iid )
  if 7 - 7: II111iiii - ooOoO0o
  if 72 - 72: Ii1I
  if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
  if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
  if 87 - 87: II111iiii
  if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
  if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
  if 24 - 24: i11iIiiIii + ooOoO0o
  if 80 - 80: IiII % I11i % oO0o
 i1I1iI = OoO00OooO0 . get_instance_id ( )
 if ( source_eid == None ) : return ( i1I1iI )
 if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 oo0 = source_eid . instance_id
 O0Ooo00OOOo0 = None
 for OoO00OooO0 in lisp_multi_tenant_interfaces :
  if ( OoO00OooO0 . device != device ) : continue
  OoOo00 = OoO00OooO0 . multi_tenant_eid
  source_eid . instance_id = OoOo00 . instance_id
  if ( source_eid . is_more_specific ( OoOo00 ) == False ) : continue
  if ( O0Ooo00OOOo0 == None or O0Ooo00OOOo0 . multi_tenant_eid . mask_len < OoOo00 . mask_len ) :
   O0Ooo00OOOo0 = OoO00OooO0
   if 52 - 52: i1IIi * IiII % O0 / oO0o % OOooOOo / iII111i
   if 36 - 36: iII111i + IiII . OoO0O00 * IiII % ooOoO0o
 source_eid . instance_id = oo0
 if 100 - 100: ooOoO0o % I1ii11iIi11i
 if ( O0Ooo00OOOo0 == None ) : return ( i1I1iI )
 return ( O0Ooo00OOOo0 . get_instance_id ( ) )
 if 45 - 45: OoooooooOO . OoooooooOO
 if 50 - 50: I1IiiI % o0oOOo0O0Ooo
 if 1 - 1: II111iiii
 if 22 - 22: I1Ii111 + iII111i
 if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( device not in lisp_myinterfaces ) : return ( None )
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 OoO00OooO0 = lisp_myinterfaces [ device ]
 i11i1Iii11II = device if OoO00OooO0 . dynamic_eid_device == None else OoO00OooO0 . dynamic_eid_device
 if 34 - 34: OOooOOo . oO0o + I11i / I1Ii111 . I11i
 if 59 - 59: Ii1I
 if ( OoO00OooO0 . does_dynamic_eid_match ( eid ) ) : return ( i11i1Iii11II )
 return ( None )
 if 47 - 47: iII111i % iII111i
 if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
 if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 if 74 - 74: I11i % OOooOOo
 if 57 - 57: O0 + I1IiiI + i11iIiiIii
 if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
 if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
 II1iI = lisp_process_rloc_probe_timer
 IiII1II1I = threading . Timer ( interval , II1iI , [ lisp_sockets ] )
 lisp_rloc_probe_timer = IiII1II1I
 IiII1II1I . start ( )
 return
 if 81 - 81: iII111i * i11iIiiIii % O0 / iIii1I11I1II1 . OoO0O00
 if 24 - 24: I1ii11iIi11i + OoOoOO00 % ooOoO0o % I1IiiI * I1Ii111 - o0oOOo0O0Ooo
 if 95 - 95: Oo0Ooo * IiII - I1IiiI
 if 37 - 37: Oo0Ooo - oO0o / I1ii11iIi11i . o0oOOo0O0Ooo * Ii1I
 if 95 - 95: i11iIiiIii - ooOoO0o / I11i / I1Ii111
 if 59 - 59: iII111i
 if 59 - 59: Oo0Ooo - IiII
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for OoOOooOOoo in lisp_rloc_probe_list :
  i1ii1Iii = lisp_rloc_probe_list [ OoOOooOOoo ]
  lprint ( "RLOC {}:" . format ( OoOOooOOoo ) )
  for I1I1 , oOO , II11iIIii in i1ii1Iii :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( I1I1 ) ) , oOO . print_prefix ( ) ,
 II11iIIii . print_prefix ( ) , I1I1 . translated_port ) )
   if 13 - 13: OoOoOO00
   if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 iIIiI11 , oOO , II11iIIii = eid_list [ 0 ]
 i1II1iIiiiIi = [ lisp_print_eid_tuple ( oOO , II11iIIii ) ]
 if 12 - 12: OoooooooOO / OoooooooOO * Ii1I % OOooOOo + i11iIiiIii % OoooooooOO
 for iIIiI11 , oOO , II11iIIii in eid_list [ 1 : : ] :
  iIIiI11 . state = LISP_RLOC_UNREACH_STATE
  iIIiI11 . last_state_change = lisp_get_timestamp ( )
  i1II1iIiiiIi . append ( lisp_print_eid_tuple ( oOO , II11iIIii ) )
  if 46 - 46: II111iiii / I1Ii111 / O0 * OoooooooOO * ooOoO0o / ooOoO0o
  if 74 - 74: i11iIiiIii - oO0o % II111iiii . iIii1I11I1II1
 O0oOOoO = bold ( "unreachable" , False )
 o00oO = red ( iIIiI11 . rloc . print_address_no_iid ( ) , False )
 if 53 - 53: o0oOOo0O0Ooo
 for o0Ooo0Oooo0o in i1II1iIiiiIi :
  oOO = green ( o0Ooo0Oooo0o , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( o00oO , O0oOOoO , oOO ) )
  if 69 - 69: ooOoO0o
  if 87 - 87: OOooOOo
  if 10 - 10: iIii1I11I1II1
  if 75 - 75: oO0o + o0oOOo0O0Ooo
  if 37 - 37: oO0o + O0 . IiII * I1ii11iIi11i
  if 2 - 2: O0 . ooOoO0o
 for iIIiI11 , oOO , II11iIIii in eid_list :
  I1I1i1I11I = lisp_map_cache . lookup_cache ( oOO , True )
  if ( I1I1i1I11I ) : lisp_write_ipc_map_cache ( True , I1I1i1I11I )
  if 97 - 97: i1IIi . Oo0Ooo
 return
 if 81 - 81: OoOoOO00
 if 81 - 81: O0
 if 57 - 57: oO0o - o0oOOo0O0Ooo % i11iIiiIii / OoOoOO00 . iIii1I11I1II1
 if 68 - 68: iII111i
 if 59 - 59: O0 - i11iIiiIii + OoooooooOO - iII111i - Oo0Ooo . OoooooooOO
 if 60 - 60: O0 * iIii1I11I1II1 - Ii1I * II111iiii . ooOoO0o
 if 61 - 61: I1IiiI . iII111i
 if 19 - 19: iIii1I11I1II1 * Oo0Ooo - I1IiiI - I1IiiI + O0 - I1Ii111
def lisp_process_multicast_rloc ( multicast_rloc ) :
 O0Ooo0oo = multicast_rloc . rloc . print_address_no_iid ( )
 if 91 - 91: OOooOOo - OoOoOO00
 I1IIII1IIiIi = lisp_get_timestamp ( )
 for iI1ii11Ii in multicast_rloc . multicast_rloc_probe_list :
  ii1OOO0 = multicast_rloc . multicast_rloc_probe_list [ iI1ii11Ii ]
  if ( ii1OOO0 . last_rloc_probe_reply + LISP_RLOC_PROBE_REPLY_WAIT >= I1IIII1IIiIi ) :
   continue
   if 58 - 58: II111iiii . OOooOOo % II111iiii * oO0o % OoO0O00 % I11i
  if ( ii1OOO0 . state == LISP_RLOC_UNREACH_STATE ) : continue
  if 71 - 71: Ii1I * II111iiii * I1IiiI
  if 22 - 22: oO0o
  if 96 - 96: ooOoO0o * iII111i . IiII
  if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
  ii1OOO0 . state = LISP_RLOC_UNREACH_STATE
  ii1OOO0 . last_state_change = lisp_get_timestamp ( )
  if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
  lprint ( "Multicast-RLOC {} member-RLOC {} went unreachable" . format ( O0Ooo0oo , red ( iI1ii11Ii , False ) ) )
  if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
  if 22 - 22: i1IIi
  if 33 - 33: O0
  if 34 - 34: I1Ii111 . IiII % iII111i
  if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
  if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
  if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
  if 75 - 75: i1IIi * i11iIiiIii
  if 40 - 40: I1ii11iIi11i + OoO0O00
  if 8 - 8: i11iIiiIii - iIii1I11I1II1
  if 73 - 73: OoOoOO00
  if 25 - 25: iII111i / oO0o
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
 if 61 - 61: I1IiiI / OOooOOo
 if 67 - 67: OoOoOO00
 if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 30 - 30: O0 / oO0o * i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
 if 95 - 95: ooOoO0o % OOooOOo
 if 17 - 17: i1IIi + Ii1I
 if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
 IIIiIIIiIiII = lisp_get_default_route_next_hops ( )
 if 57 - 57: OoO0O00 . ooOoO0o * iIii1I11I1II1 * OoooooooOO
 ooOoO = "---------- Start RLOC Probing for {} RLOC entries ----------" . format ( len ( lisp_rloc_probe_list ) )
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 lprint ( bold ( ooOoO , False ) )
 if 96 - 96: Ii1I
 if 90 - 90: II111iiii
 if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
 if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
 oo0O00ooo0o = 0
 II1iii1I1 = bold ( "RLOC-probe" , False )
 for oo0oOoooOooO0 in list ( lisp_rloc_probe_list . values ( ) ) :
  if 13 - 13: OOooOOo + II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
  if 9 - 9: O0 + IiII
  if 69 - 69: I1IiiI
  if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
  if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
  O0OOoO0o0000 = None
  for iiI1I11i1Ii , o0Ooo0Oooo0o , oo0oOooo0O in oo0oOoooOooO0 :
   O00oO000Oo0 = iiI1I11i1Ii . rloc . print_address_no_iid ( )
   if 11 - 11: I11i . OoooooooOO / OoO0O00 - II111iiii / IiII + oO0o
   if 48 - 48: iII111i * OoO0O00 * OoOoOO00 * I11i
   if 74 - 74: ooOoO0o
   if 93 - 93: Oo0Ooo % ooOoO0o
   o0o00 , IiioOo , OOo00 = lisp_allow_gleaning ( o0Ooo0Oooo0o , None , iiI1I11i1Ii )
   if ( o0o00 and IiioOo == False ) :
    oOO = green ( o0Ooo0Oooo0o . print_address ( ) , False )
    O00oO000Oo0 += ":{}" . format ( iiI1I11i1Ii . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( O00oO000Oo0 , False ) , oOO ) )
    if 44 - 44: ooOoO0o * I1IiiI / II111iiii / OoooooooOO
    continue
    if 12 - 12: I1ii11iIi11i . OoOoOO00 * I1Ii111 - I1IiiI / oO0o * ooOoO0o
    if 6 - 6: i1IIi % II111iiii % Oo0Ooo + o0oOOo0O0Ooo
    if 61 - 61: I11i / i11iIiiIii
    if 89 - 89: II111iiii
    if 2 - 2: OoOoOO00 . i11iIiiIii
    if 11 - 11: Ii1I
    if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
   if ( iiI1I11i1Ii . down_state ( ) ) : continue
   if 44 - 44: iII111i
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
   if ( O0OOoO0o0000 ) :
    iiI1I11i1Ii . last_rloc_probe_nonce = O0OOoO0o0000 . last_rloc_probe_nonce
    if 99 - 99: I1IiiI - i1IIi * i11iIiiIii + OoO0O00
    if ( O0OOoO0o0000 . translated_port == iiI1I11i1Ii . translated_port and O0OOoO0o0000 . rloc_name == iiI1I11i1Ii . rloc_name ) :
     if 80 - 80: o0oOOo0O0Ooo . I11i % iIii1I11I1II1 + OoOoOO00
     oOO = green ( lisp_print_eid_tuple ( o0Ooo0Oooo0o , oo0oOooo0O ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( O00oO000Oo0 , False ) , oOO ) )
     if 87 - 87: I1Ii111 + II111iiii / I1ii11iIi11i + OoOoOO00
     if 71 - 71: I1IiiI + iIii1I11I1II1 + O0 * iII111i % IiII
     if 42 - 42: OOooOOo - I1ii11iIi11i
     if 93 - 93: I1Ii111 + OOooOOo % ooOoO0o / I1Ii111 % OOooOOo . IiII
     if 37 - 37: iII111i * oO0o / oO0o / Ii1I % I11i
     if 12 - 12: i11iIiiIii
     iiI1I11i1Ii . last_rloc_probe = O0OOoO0o0000 . last_rloc_probe
     continue
     if 62 - 62: oO0o + OOooOOo + oO0o + I1IiiI
     if 10 - 10: IiII - Oo0Ooo % ooOoO0o
     if 38 - 38: oO0o * o0oOOo0O0Ooo . I11i % II111iiii / I11i % Ii1I
     if 19 - 19: II111iiii / i11iIiiIii * II111iiii + OoOoOO00 - OoOoOO00
     if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
     if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
     if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
     if 76 - 76: IiII % I1IiiI . iII111i
   OooO0OO = None
   if ( iiI1I11i1Ii . rloc_next_hop != None ) :
    OooO0OO = lisp_get_host_route_next_hop ( O00oO000Oo0 )
    if ( OooO0OO ) :
     lprint ( "Remove forwarding next-hop {}" . format ( OooO0OO ) )
     lisp_install_host_route ( O00oO000Oo0 , None , False )
     if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
     if 2 - 2: OOooOOo
     if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
   iIIiI11 = None
   while ( True ) :
    iIIiI11 = iiI1I11i1Ii if iIIiI11 == None else iIIiI11 . next_rloc
    if ( iIIiI11 == None ) : break
    if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
    if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
    if 78 - 78: OoO0O00 - i1IIi % I1Ii111
    if 87 - 87: I11i
    if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
    if ( iIIiI11 . rloc_next_hop != None ) :
     if ( iIIiI11 . rloc_next_hop not in IIIiIIIiIiII ) :
      oooOo , ooOOOo = iIIiI11 . rloc_next_hop
      if ( iIIiI11 . up_state ( ) ) :
       iIIiI11 . state = LISP_RLOC_UNREACH_STATE
       iIIiI11 . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( iIIiI11 . rloc , False )
       if 80 - 80: I1Ii111 % O0 - IiII / II111iiii + i1IIi
      O0oOOoO = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( ooOOOo , oooOo ,
 red ( O00oO000Oo0 , False ) , O0oOOoO ) )
      continue
      if 4 - 4: OOooOOo + II111iiii
      if 1 - 1: OoooooooOO * I1Ii111 - I11i / IiII
      if 43 - 43: i11iIiiIii * I1IiiI
      if 48 - 48: Oo0Ooo - OOooOOo / iII111i % I1ii11iIi11i . OoOoOO00
      if 6 - 6: i11iIiiIii
      if 51 - 51: o0oOOo0O0Ooo - OoooooooOO - I11i % i11iIiiIii / I1IiiI + IiII
    i11iII11I1III = iIIiI11 . last_rloc_probe
    ooI11 = 0 if i11iII11I1III == None else time . time ( ) - i11iII11I1III
    if ( iIIiI11 . unreach_state ( ) and ooI11 < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( O00oO000Oo0 , False ) ) )
     if 12 - 12: Oo0Ooo
     continue
     if 8 - 8: iII111i
     if 78 - 78: i11iIiiIii % oO0o % ooOoO0o - I1Ii111
     if 53 - 53: oO0o + i1IIi . i11iIiiIii + OoO0O00 + Oo0Ooo
     if 27 - 27: OoooooooOO . I1IiiI + OoooooooOO % II111iiii . II111iiii - oO0o
     if 8 - 8: o0oOOo0O0Ooo . i1IIi . Ii1I - OoOoOO00 / iIii1I11I1II1
     if 11 - 11: oO0o - OOooOOo - I11i * I1IiiI
    oo000O0o = lisp_get_echo_nonce ( None , O00oO000Oo0 )
    if ( oo000O0o and oo000O0o . request_nonce_timeout ( ) ) :
     iIIiI11 . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     iIIiI11 . last_state_change = lisp_get_timestamp ( )
     O0oOOoO = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( O00oO000Oo0 , False ) , O0oOOoO ) )
     if 25 - 25: OoOoOO00 - OOooOOo * I11i / iII111i + o0oOOo0O0Ooo - O0
     lisp_update_rtr_updown ( iIIiI11 . rloc , False )
     continue
     if 29 - 29: ooOoO0o
     if 60 - 60: ooOoO0o / I1ii11iIi11i * i1IIi - IiII . II111iiii
     if 65 - 65: oO0o * IiII
     if 97 - 97: IiII % OoO0O00 . OoOoOO00 - Ii1I
     if 28 - 28: O0 . I11i . I1IiiI - Ii1I - iII111i - iIii1I11I1II1
     if 14 - 14: OOooOOo + ooOoO0o
    if ( oo000O0o and oo000O0o . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( O00oO000Oo0 , False ) ) )
     if 56 - 56: o0oOOo0O0Ooo - OoOoOO00 - Ii1I
     continue
     if 50 - 50: I1ii11iIi11i
     if 24 - 24: ooOoO0o
     if 19 - 19: oO0o
     if 97 - 97: IiII
     if 36 - 36: II111iiii
     if 83 - 83: I11i . ooOoO0o
    if ( iIIiI11 . last_rloc_probe != None ) :
     i11iII11I1III = iIIiI11 . last_rloc_probe_reply
     if ( i11iII11I1III == None ) : i11iII11I1III = 0
     ooI11 = time . time ( ) - i11iII11I1III
     if ( iIIiI11 . up_state ( ) and ooI11 >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 57 - 57: IiII
      iIIiI11 . state = LISP_RLOC_UNREACH_STATE
      iIIiI11 . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( iIIiI11 . rloc , False )
      O0oOOoO = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( O00oO000Oo0 , False ) , O0oOOoO ) )
      if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
      if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
      lisp_mark_rlocs_for_other_eids ( oo0oOoooOooO0 )
      if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
      if 79 - 79: I1ii11iIi11i % I11i
      if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
    iIIiI11 . last_rloc_probe = lisp_get_timestamp ( )
    if 66 - 66: I1IiiI - o0oOOo0O0Ooo
    OOO0o0O0O0O = "" if iIIiI11 . unreach_state ( ) == False else " unreachable"
    if 13 - 13: O0 + OOooOOo + I11i
    if 45 - 45: I1Ii111
    if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
    if 90 - 90: OOooOOo
    if 43 - 43: IiII + ooOoO0o
    if 4 - 4: i1IIi
    if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
    if 6 - 6: Ii1I / iII111i
    Oo00O0Oo0O = ""
    O0O0O0ooOoOo = None
    if 63 - 63: I1ii11iIi11i + OoOoOO00 - Ii1I + OoO0O00 - II111iiii
    if 47 - 47: I1IiiI * O0 + I1ii11iIi11i - OOooOOo
    if 24 - 24: i1IIi / i1IIi + I11i * II111iiii / IiII
    if 8 - 8: I11i . I11i + I11i % OoooooooOO / ooOoO0o
    if 25 - 25: I1IiiI / OoO0O00
    if 92 - 92: oO0o % I1IiiI / OoO0O00 - I11i
    if 36 - 36: i1IIi * iIii1I11I1II1 + I1ii11iIi11i + iII111i - II111iiii
    if 48 - 48: oO0o + OoOoOO00 - OoO0O00 . II111iiii * i11iIiiIii . OoooooooOO
    if ( iIIiI11 . rloc_next_hop != None and O0O0O0ooOoOo != None ) :
     oooOo , O0O0O0ooOoOo = iIIiI11 . rloc_next_hop
     lisp_install_host_route ( O00oO000Oo0 , O0O0O0ooOoOo , True )
     Oo00O0Oo0O = ", send to nh {} on {}" . format ( O0O0O0ooOoOo , bold ( oooOo , False ) )
     if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
     if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
     if 88 - 88: I1Ii111
     if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
     if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
    I11i11IIIII = iIIiI11 . print_rloc_probe_rtt ( )
    o00O00OoO = O00oO000Oo0
    if ( iIIiI11 . translated_port != 0 ) :
     o00O00OoO += ":{}" . format ( iIIiI11 . translated_port )
     if 14 - 14: oO0o + I11i * OoOoOO00 % II111iiii
    o00O00OoO = red ( o00O00OoO , False )
    if ( iIIiI11 . rloc_name != None ) :
     o00O00OoO += " (" + blue ( iIIiI11 . rloc_name , False ) + ")"
     if 38 - 38: O0 % Oo0Ooo / o0oOOo0O0Ooo / i11iIiiIii % Oo0Ooo
    lprint ( "Send {} to{} {}, last rtt: {}{}" . format ( II1iii1I1 , OOO0o0O0O0O ,
 o00O00OoO , I11i11IIIII , Oo00O0Oo0O ) )
    if 100 - 100: i1IIi / Oo0Ooo / II111iiii + iII111i . II111iiii * oO0o
    if 36 - 36: Oo0Ooo + iII111i / OOooOOo + OOooOOo % i11iIiiIii / I1IiiI
    if 59 - 59: ooOoO0o / I11i
    if 32 - 32: iIii1I11I1II1 % oO0o / I1Ii111
    if 42 - 42: I11i / I1ii11iIi11i - I1IiiI * iII111i / I1IiiI / i11iIiiIii
    if ( iIIiI11 . rloc . is_null ( ) ) :
     iIIiI11 . rloc . copy_address ( iiI1I11i1Ii . rloc )
     if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
     if 95 - 95: OoOoOO00
     if 78 - 78: I11i
     if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
     if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
    if ( iIIiI11 . multicast_rloc_probe_list != { } ) :
     lisp_process_multicast_rloc ( iIIiI11 )
     if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
     if 53 - 53: I1IiiI % I1IiiI
     if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
     if 85 - 85: IiII
     if 72 - 72: iII111i * OoOoOO00
    IIiIiiI1Iii = None if ( oo0oOooo0O . is_null ( ) ) else o0Ooo0Oooo0o
    Oo0oo = o0Ooo0Oooo0o if ( oo0oOooo0O . is_null ( ) ) else oo0oOooo0O
    lisp_send_map_request ( lisp_sockets , 0 , IIiIiiI1Iii , Oo0oo , iIIiI11 )
    O0OOoO0o0000 = iiI1I11i1Ii
    if 10 - 10: II111iiii
    if 14 - 14: oO0o . I11i . i1IIi + I1ii11iIi11i
    if 53 - 53: Ii1I
    if 35 - 35: oO0o * i1IIi / IiII / iII111i
    if 19 - 19: I1IiiI + iIii1I11I1II1 * O0 - OOooOOo
    if 32 - 32: O0 - II111iiii - i1IIi + O0 + OOooOOo
    if ( iIIiI11 . is_decent_nat_port ( ) and iIIiI11 . unreach_state ( ) ) :
     iIIiI11 . refresh_decent_nat_rloc ( lisp_sockets , Oo0oo )
     if 44 - 44: I11i * oO0o % OoooooooOO % OoO0O00 / o0oOOo0O0Ooo
     if 37 - 37: OoO0O00 + OoOoOO00 - I1IiiI
     if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
     if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
     if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
     if 20 - 20: I1IiiI + iII111i + O0 * O0
    if ( O0O0O0ooOoOo ) : lisp_install_host_route ( O00oO000Oo0 , O0O0O0ooOoOo , False )
    if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
    if 31 - 31: ooOoO0o
    if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
    if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
    if 17 - 17: I11i * i1IIi + iIii1I11I1II1 % I1IiiI
    if 44 - 44: IiII + I1IiiI . Ii1I % Oo0Ooo
   if ( OooO0OO ) :
    lprint ( "Reinstall forwarding next-hop {}" . format ( OooO0OO ) )
    lisp_install_host_route ( O00oO000Oo0 , OooO0OO , True )
    if 97 - 97: O0
    if 95 - 95: OoO0O00 % iII111i / I1IiiI * OoooooooOO
    if 31 - 31: iIii1I11I1II1
    if 62 - 62: o0oOOo0O0Ooo - iII111i / II111iiii . o0oOOo0O0Ooo
    if 20 - 20: iIii1I11I1II1 % OOooOOo
   oo0O00ooo0o += 1
   if ( ( oo0O00ooo0o % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 91 - 91: ooOoO0o
   if 96 - 96: I1IiiI . OOooOOo
   if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
 lprint ( bold ( "---------- End RLOC Probing ----------" , False ) )
 return
 if 34 - 34: IiII % oO0o
 if 54 - 54: I1IiiI
 if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
 if 31 - 31: I11i * o0oOOo0O0Ooo
 if 17 - 17: Ii1I * iIii1I11I1II1
 if 9 - 9: o0oOOo0O0Ooo - IiII
 if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
 if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
 if 23 - 23: Ii1I % i1IIi - I1Ii111
 if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 if ( lisp_i_am_itr == False ) : return
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
 if 11 - 11: IiII / I1IiiI . I1IiiI
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
 if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
 if ( lisp_register_all_rtrs ) : return
 if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
 OOOooOoO0O0 = rtr . print_address_no_iid ( )
 if 2 - 2: ooOoO0o - OoOoOO00 + oO0o . IiII + I1ii11iIi11i - OOooOOo
 if 91 - 91: o0oOOo0O0Ooo . i11iIiiIii . I1Ii111 . I1Ii111 / Ii1I + I1Ii111
 if 5 - 5: i1IIi * I1ii11iIi11i + OoOoOO00 % OOooOOo
 if 64 - 64: O0 % o0oOOo0O0Ooo + OoooooooOO - I1IiiI
 if 29 - 29: o0oOOo0O0Ooo - OoOoOO00 - OoooooooOO / OoOoOO00
 if ( OOOooOoO0O0 not in lisp_rtr_list ) : return
 if 88 - 88: OoOoOO00 - IiII
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( OOOooOoO0O0 , False ) , bold ( updown , False ) ) )
 if 96 - 96: Ii1I % iIii1I11I1II1
 if 22 - 22: I1Ii111 - I1ii11iIi11i . Ii1I + o0oOOo0O0Ooo * OoooooooOO % iIii1I11I1II1
 if 87 - 87: OoO0O00 + o0oOOo0O0Ooo
 if 46 - 46: oO0o + OoOoOO00
 ii1I11Iii = "rtr%{}%{}" . format ( OOOooOoO0O0 , updown )
 ii1I11Iii = lisp_command_ipc ( ii1I11Iii , "lisp-itr" )
 lisp_ipc ( ii1I11Iii , lisp_ipc_socket , "lisp-etr" )
 return
 if 17 - 17: Ii1I . Oo0Ooo - oO0o % OOooOOo
 if 59 - 59: O0
 if 75 - 75: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i * oO0o * I11i / OoooooooOO
 if 17 - 17: Ii1I % I1ii11iIi11i + I11i
 if 80 - 80: i1IIi . OoooooooOO % OoooooooOO . oO0o / OOooOOo
 if 85 - 85: OOooOOo
 if 80 - 80: ooOoO0o % O0 % I1ii11iIi11i + Oo0Ooo
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl ,
 mrloc , rloc_name ) :
 global lisp_rloc_probe_nonce_list
 if 82 - 82: oO0o / iIii1I11I1II1 % ooOoO0o . Ii1I / i1IIi - I1Ii111
 iIIiI11 = rloc_entry . rloc
 OOO0O0O = map_reply . nonce
 I1iIiii1 = map_reply . hop_count
 II1iii1I1 = bold ( "RLOC-probe reply" , False )
 ooOO0000OO = iIIiI11 . print_address_no_iid ( )
 o0oo = source . print_address_no_iid ( )
 oOOOooOO = lisp_rloc_probe_list
 iIOooOoo0 = rloc_entry . json . json_string if rloc_entry . json else None
 iIiIIIIIii = lisp_get_timestamp ( )
 if 38 - 38: O0 / OoO0O00
 if 80 - 80: ooOoO0o
 if 46 - 46: Ii1I
 if 48 - 48: I1Ii111 + i1IIi - Ii1I
 if 94 - 94: iII111i . I1IiiI
 if 5 - 5: OoooooooOO + o0oOOo0O0Ooo + OOooOOo * OoO0O00 . OOooOOo . I11i
 if ( mrloc != None ) :
  IiiI1I11ii1iI = mrloc . rloc . print_address_no_iid ( )
  if ( ooOO0000OO not in mrloc . multicast_rloc_probe_list ) :
   ooO0OO0 = lisp_rloc ( )
   ooO0OO0 = copy . deepcopy ( mrloc )
   ooO0OO0 . rloc . copy_address ( iIIiI11 )
   ooO0OO0 . multicast_rloc_probe_list = { }
   mrloc . multicast_rloc_probe_list [ ooOO0000OO ] = ooO0OO0
   if 46 - 46: Oo0Ooo * Ii1I - i11iIiiIii - IiII % I11i - Oo0Ooo
  ooO0OO0 = mrloc . multicast_rloc_probe_list [ ooOO0000OO ]
  ooO0OO0 . rloc_name = rloc_name
  ooO0OO0 . last_rloc_probe_nonce = mrloc . last_rloc_probe_nonce
  ooO0OO0 . last_rloc_probe = mrloc . last_rloc_probe
  I1I1 , o0Ooo0Oooo0o , oo0oOooo0O = lisp_rloc_probe_list [ IiiI1I11ii1iI ] [ 0 ]
  ooO0OO0 . process_rloc_probe_reply ( iIiIIIIIii , OOO0O0O , o0Ooo0Oooo0o , oo0oOooo0O , I1iIiii1 , ttl , iIOooOoo0 )
  mrloc . process_rloc_probe_reply ( iIiIIIIIii , OOO0O0O , o0Ooo0Oooo0o , oo0oOooo0O , I1iIiii1 , ttl , iIOooOoo0 )
  return
  if 34 - 34: I1Ii111 / I1ii11iIi11i
  if 15 - 15: I1IiiI / I1Ii111 % iII111i
  if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
  if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
  if 43 - 43: oO0o . OoO0O00 * i1IIi
  if 1 - 1: ooOoO0o / i1IIi
 if ( rloc_name and rloc_name . find ( LISP_TP ) != - 1 ) :
  port = int ( rloc_name . split ( LISP_TP ) [ - 1 ] )
  if 42 - 42: I1ii11iIi11i * ooOoO0o + OoOoOO00 % I1ii11iIi11i . IiII
  if 75 - 75: OoO0O00 * i1IIi - OOooOOo % II111iiii % OoO0O00 - OoOoOO00
  if 75 - 75: I11i * IiII * ooOoO0o
  if 31 - 31: Ii1I
  if 72 - 72: OOooOOo * Ii1I % OoO0O00
  if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
  if 42 - 42: oO0o / i1IIi . IiII
 iI1ii11Ii = ooOO0000OO
 if ( iI1ii11Ii not in oOOOooOO ) :
  iI1ii11Ii += ":" + str ( port )
  if ( iI1ii11Ii not in oOOOooOO ) :
   iI1ii11Ii = o0oo
   if ( iI1ii11Ii not in oOOOooOO ) :
    iI1ii11Ii += ":" + str ( port )
    lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( II1iii1I1 , red ( ooOO0000OO , False ) , red ( o0oo ,
    # i1IIi
 False ) , port ) )
    return
    if 5 - 5: ooOoO0o
    if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
    if 88 - 88: OoooooooOO . I1IiiI
    if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
    if 7 - 7: i1IIi
    if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
    if 34 - 34: iII111i + i11iIiiIii . IiII
    if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
    if 29 - 29: II111iiii % i11iIiiIii % O0
    if 38 - 38: o0oOOo0O0Ooo * IiII
 if ( OOO0O0O in lisp_rloc_probe_nonce_list ) :
  OoOoOo00OoO = lisp_rloc_probe_nonce_list . pop ( OOO0O0O )
  if ( OoOoOo00OoO != iI1ii11Ii ) :
   iI1ii11Ii = OoOoOo00OoO
   lprint ( "    Obtain probed RLOC address {} from nonce 0x{}" . format ( iI1ii11Ii , lisp_hex_string ( OOO0O0O ) ) )
   if 57 - 57: ooOoO0o
   if 35 - 35: iIii1I11I1II1 / I1IiiI / I1IiiI
   if 14 - 14: o0oOOo0O0Ooo - OoOoOO00 + oO0o
   if 88 - 88: iII111i * I11i
   if 57 - 57: o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
   if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
   if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
   if 80 - 80: II111iiii . i11iIiiIii
 if ( iI1ii11Ii not in lisp_rloc_probe_list ) : return
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
 for iIIiI11 , o0Ooo0Oooo0o , oo0oOooo0O in lisp_rloc_probe_list [ iI1ii11Ii ] :
  if ( lisp_i_am_rtr ) :
   if ( iIIiI11 . translated_port != 0 and iIIiI11 . translated_port != port ) :
    continue
    if 33 - 33: iIii1I11I1II1
    if 52 - 52: iIii1I11I1II1 + O0
  iIIiI11 . process_rloc_probe_reply ( iIiIIIIIii , OOO0O0O , o0Ooo0Oooo0o , oo0oOooo0O , I1iIiii1 , ttl , iIOooOoo0 )
  if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 return
 if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
 if 29 - 29: iII111i % I1Ii111
 if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
 if 63 - 63: ooOoO0o
 if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
 if 90 - 90: IiII
 if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
def lisp_db_list_length ( ) :
 oo0O00ooo0o = 0
 for i1I in lisp_db_list :
  oo0O00ooo0o += len ( i1I . dynamic_eids ) if i1I . dynamic_eid_configured ( ) else 1
  oo0O00ooo0o += len ( i1I . eid . iid_list )
  if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 return ( oo0O00ooo0o )
 if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
 if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
 if 98 - 98: OOooOOo
 if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
 if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
 if 75 - 75: II111iiii . O0 . I1Ii111 * O0 / OoooooooOO
 if 60 - 60: OOooOOo - Oo0Ooo * OOooOOo / OoO0O00
 if 55 - 55: I1ii11iIi11i * II111iiii * iIii1I11I1II1
def lisp_is_myeid ( eid ) :
 for i1I in lisp_db_list :
  if ( eid . is_more_specific ( i1I . eid ) ) : return ( True )
  if 38 - 38: iIii1I11I1II1 % I1ii11iIi11i . Ii1I + I1IiiI % i11iIiiIii - i11iIiiIii
 return ( False )
 if 62 - 62: I1Ii111 + I1IiiI
 if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
 if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
 if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
 if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
 if 59 - 59: iII111i
 if 14 - 14: oO0o . IiII + iIii1I11I1II1 - i1IIi
 if 46 - 46: i11iIiiIii * II111iiii / i11iIiiIii % i11iIiiIii * II111iiii + i11iIiiIii
 if 87 - 87: Oo0Ooo + OoO0O00 / II111iiii * OoooooooOO
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 95 - 95: I1Ii111 * o0oOOo0O0Ooo + OoO0O00 % OoOoOO00 - ooOoO0o / OoOoOO00
 if 45 - 45: OoooooooOO / oO0o / o0oOOo0O0Ooo + Ii1I + O0 . iII111i
 if 34 - 34: iIii1I11I1II1 . o0oOOo0O0Ooo + ooOoO0o
 if 96 - 96: O0 / ooOoO0o
 if 82 - 82: OoO0O00 * OOooOOo * I11i * I1Ii111 % iIii1I11I1II1
 if 50 - 50: Ii1I * Ii1I % I11i / iIii1I11I1II1 / ooOoO0o / iII111i
 if 91 - 91: Ii1I - O0 . I11i - OoooooooOO * IiII . II111iiii
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 38 - 38: I1IiiI + OoO0O00
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 oo000O0o = None
 if ( rloc_str in lisp_nonce_echo_list ) :
  oo000O0o = lisp_nonce_echo_list [ rloc_str ]
  if 11 - 11: iIii1I11I1II1 + i1IIi * IiII - Oo0Ooo
 return ( oo000O0o )
 if 66 - 66: I1Ii111 . Ii1I / I1ii11iIi11i / iIii1I11I1II1 + O0 / i1IIi
 if 72 - 72: ooOoO0o . II111iiii
 if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
 if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
 if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 if 18 - 18: o0oOOo0O0Ooo / OOooOOo
 if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
 if 100 - 100: O0
def lisp_decode_dist_name ( packet ) :
 oo0O00ooo0o = 0
 I11iII1iIi11 = b""
 if 44 - 44: O0
 while ( packet [ 0 : 1 ] != b"\x00" ) :
  if ( oo0O00ooo0o == 255 ) : return ( [ None , None ] )
  I11iII1iIi11 += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  oo0O00ooo0o += 1
  if 12 - 12: I1ii11iIi11i
  if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 packet = packet [ 1 : : ]
 return ( packet , I11iII1iIi11 . decode ( ) )
 if 38 - 38: Ii1I
 if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
 if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
 if 59 - 59: i11iIiiIii / I1IiiI * iII111i
 if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
def lisp_write_flow_log ( flow_log ) :
 o0OoO0 = open ( "./logs/lisp-flow.log" , "a" )
 if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
 oo0O00ooo0o = 0
 for o0oO0o0O0o0Oo in flow_log :
  OO0Oo00OO0oo = o0oO0o0O0o0Oo [ 3 ]
  oo0O00O0oO0OO = OO0Oo00OO0oo . print_flow ( o0oO0o0O0o0Oo [ 0 ] , o0oO0o0O0o0Oo [ 1 ] , o0oO0o0O0o0Oo [ 2 ] )
  o0OoO0 . write ( oo0O00O0oO0OO )
  oo0O00ooo0o += 1
  if 36 - 36: II111iiii - o0oOOo0O0Ooo - Ii1I
 o0OoO0 . close ( )
 del ( flow_log )
 if 2 - 2: i1IIi
 oo0O00ooo0o = bold ( str ( oo0O00ooo0o ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( oo0O00ooo0o ) )
 return
 if 63 - 63: I1ii11iIi11i % ooOoO0o
 if 82 - 82: iII111i
 if 94 - 94: OoooooooOO / iII111i * ooOoO0o / i1IIi * i11iIiiIii * II111iiii
 if 98 - 98: Ii1I * Ii1I / IiII
 if 1 - 1: OOooOOo
 if 47 - 47: i11iIiiIii - I11i
 if 38 - 38: Oo0Ooo % OoooooooOO + iII111i
def lisp_policy_command ( kv_pair ) :
 III1ii = lisp_policy ( "" )
 iIi1iii = None
 if 60 - 60: OoooooooOO + i11iIiiIii - o0oOOo0O0Ooo . OoooooooOO + oO0o / ooOoO0o
 OOO0OOoO = [ ]
 for o000o0O0Oo00 in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  OOO0OOoO . append ( lisp_policy_match ( ) )
  if 100 - 100: II111iiii . OoO0O00 - i1IIi % IiII / i11iIiiIii * oO0o
  if 22 - 22: OoOoOO00 - oO0o + OoooooooOO
 for O0000OiII111 in list ( kv_pair . keys ( ) ) :
  oO00o = kv_pair [ O0000OiII111 ]
  if 61 - 61: OoOoOO00 - I1Ii111 * ooOoO0o + Oo0Ooo / IiII
  if 79 - 79: ooOoO0o % OoooooooOO
  if 67 - 67: I1IiiI + OoooooooOO % OoO0O00 . OoooooooOO + I11i / oO0o
  if 33 - 33: I1ii11iIi11i
  if ( O0000OiII111 == "instance-id" ) :
   for o000o0O0Oo00 in range ( len ( OOO0OOoO ) ) :
    iII11I1i = oO00o [ o000o0O0Oo00 ]
    if ( iII11I1i == "" ) : continue
    III1IIIII1II = OOO0OOoO [ o000o0O0Oo00 ]
    if ( III1IIIII1II . source_eid == None ) :
     III1IIIII1II . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 78 - 78: I1Ii111 % OoO0O00 . IiII % iIii1I11I1II1 / OoO0O00
    if ( III1IIIII1II . dest_eid == None ) :
     III1IIIII1II . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 34 - 34: iIii1I11I1II1
    III1IIIII1II . source_eid . instance_id = int ( iII11I1i )
    III1IIIII1II . dest_eid . instance_id = int ( iII11I1i )
    if 33 - 33: I1ii11iIi11i + I1Ii111 * ooOoO0o / i11iIiiIii
    if 83 - 83: oO0o
  if ( O0000OiII111 == "source-eid" ) :
   for o000o0O0Oo00 in range ( len ( OOO0OOoO ) ) :
    iII11I1i = oO00o [ o000o0O0Oo00 ]
    if ( iII11I1i == "" ) : continue
    III1IIIII1II = OOO0OOoO [ o000o0O0Oo00 ]
    if ( III1IIIII1II . source_eid == None ) :
     III1IIIII1II . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 93 - 93: II111iiii
    i1I1iI = III1IIIII1II . source_eid . instance_id
    III1IIIII1II . source_eid . store_prefix ( iII11I1i )
    III1IIIII1II . source_eid . instance_id = i1I1iI
    if 89 - 89: OoO0O00 % II111iiii % iII111i
    if 66 - 66: OoooooooOO % iII111i % i11iIiiIii
  if ( O0000OiII111 == "destination-eid" ) :
   for o000o0O0Oo00 in range ( len ( OOO0OOoO ) ) :
    iII11I1i = oO00o [ o000o0O0Oo00 ]
    if ( iII11I1i == "" ) : continue
    III1IIIII1II = OOO0OOoO [ o000o0O0Oo00 ]
    if ( III1IIIII1II . dest_eid == None ) :
     III1IIIII1II . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 35 - 35: OoooooooOO - IiII
    i1I1iI = III1IIIII1II . dest_eid . instance_id
    III1IIIII1II . dest_eid . store_prefix ( iII11I1i )
    III1IIIII1II . dest_eid . instance_id = i1I1iI
    if 38 - 38: I1Ii111 % I11i . I11i % I11i + OoOoOO00
    if 79 - 79: I1ii11iIi11i + OoO0O00 * I1ii11iIi11i / I11i
  if ( O0000OiII111 == "source-rloc" ) :
   for o000o0O0Oo00 in range ( len ( OOO0OOoO ) ) :
    iII11I1i = oO00o [ o000o0O0Oo00 ]
    if ( iII11I1i == "" ) : continue
    III1IIIII1II = OOO0OOoO [ o000o0O0Oo00 ]
    III1IIIII1II . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    III1IIIII1II . source_rloc . store_prefix ( iII11I1i )
    if 13 - 13: OoOoOO00 . iII111i
    if 11 - 11: Oo0Ooo - Ii1I / OoO0O00
  if ( O0000OiII111 == "destination-rloc" ) :
   for o000o0O0Oo00 in range ( len ( OOO0OOoO ) ) :
    iII11I1i = oO00o [ o000o0O0Oo00 ]
    if ( iII11I1i == "" ) : continue
    III1IIIII1II = OOO0OOoO [ o000o0O0Oo00 ]
    III1IIIII1II . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    III1IIIII1II . dest_rloc . store_prefix ( iII11I1i )
    if 95 - 95: OoooooooOO
    if 64 - 64: I1ii11iIi11i . I1Ii111
  if ( O0000OiII111 == "rloc-record-name" ) :
   for o000o0O0Oo00 in range ( len ( OOO0OOoO ) ) :
    iII11I1i = oO00o [ o000o0O0Oo00 ]
    if ( iII11I1i == "" ) : continue
    III1IIIII1II = OOO0OOoO [ o000o0O0Oo00 ]
    III1IIIII1II . rloc_record_name = iII11I1i
    if 81 - 81: IiII . ooOoO0o + O0 . ooOoO0o + iIii1I11I1II1
    if 68 - 68: i11iIiiIii . iII111i + OoooooooOO + II111iiii + iIii1I11I1II1 % I11i
  if ( O0000OiII111 == "geo-name" ) :
   for o000o0O0Oo00 in range ( len ( OOO0OOoO ) ) :
    iII11I1i = oO00o [ o000o0O0Oo00 ]
    if ( iII11I1i == "" ) : continue
    III1IIIII1II = OOO0OOoO [ o000o0O0Oo00 ]
    III1IIIII1II . geo_name = iII11I1i
    if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
    if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
  if ( O0000OiII111 == "elp-name" ) :
   for o000o0O0Oo00 in range ( len ( OOO0OOoO ) ) :
    iII11I1i = oO00o [ o000o0O0Oo00 ]
    if ( iII11I1i == "" ) : continue
    III1IIIII1II = OOO0OOoO [ o000o0O0Oo00 ]
    III1IIIII1II . elp_name = iII11I1i
    if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
    if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
  if ( O0000OiII111 == "rle-name" ) :
   for o000o0O0Oo00 in range ( len ( OOO0OOoO ) ) :
    iII11I1i = oO00o [ o000o0O0Oo00 ]
    if ( iII11I1i == "" ) : continue
    III1IIIII1II = OOO0OOoO [ o000o0O0Oo00 ]
    III1IIIII1II . rle_name = iII11I1i
    if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
    if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
  if ( O0000OiII111 == "json-name" ) :
   for o000o0O0Oo00 in range ( len ( OOO0OOoO ) ) :
    iII11I1i = oO00o [ o000o0O0Oo00 ]
    if ( iII11I1i == "" ) : continue
    III1IIIII1II = OOO0OOoO [ o000o0O0Oo00 ]
    III1IIIII1II . json_name = iII11I1i
    if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
    if 9 - 9: i1IIi % iII111i / Ii1I
  if ( O0000OiII111 == "datetime-range" ) :
   for o000o0O0Oo00 in range ( len ( OOO0OOoO ) ) :
    iII11I1i = oO00o [ o000o0O0Oo00 ]
    III1IIIII1II = OOO0OOoO [ o000o0O0Oo00 ]
    if ( iII11I1i == "" ) : continue
    i1II1IIiIi1 = lisp_datetime ( iII11I1i [ 0 : 19 ] )
    Ooo0o00O0Oo = lisp_datetime ( iII11I1i [ 19 : : ] )
    if ( i1II1IIiIi1 . valid_datetime ( ) and Ooo0o00O0Oo . valid_datetime ( ) ) :
     III1IIIII1II . datetime_lower = i1II1IIiIi1
     III1IIIII1II . datetime_upper = Ooo0o00O0Oo
     if 83 - 83: oO0o
     if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
     if 29 - 29: OoooooooOO
     if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
     if 83 - 83: iIii1I11I1II1
     if 92 - 92: OoO0O00 - iII111i
     if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
  if ( O0000OiII111 == "set-action" ) :
   III1ii . set_action = oO00o
   if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
  if ( O0000OiII111 == "set-record-ttl" ) :
   III1ii . set_record_ttl = int ( oO00o )
   if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
  if ( O0000OiII111 == "set-instance-id" ) :
   if ( III1ii . set_source_eid == None ) :
    III1ii . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 70 - 70: I1Ii111 % iIii1I11I1II1
   if ( III1ii . set_dest_eid == None ) :
    III1ii . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 74 - 74: i1IIi % i11iIiiIii + oO0o
   iIi1iii = int ( oO00o )
   III1ii . set_source_eid . instance_id = iIi1iii
   III1ii . set_dest_eid . instance_id = iIi1iii
   if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
  if ( O0000OiII111 == "set-source-eid" ) :
   if ( III1ii . set_source_eid == None ) :
    III1ii . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 34 - 34: Oo0Ooo . i1IIi
   III1ii . set_source_eid . store_prefix ( oO00o )
   if ( iIi1iii != None ) : III1ii . set_source_eid . instance_id = iIi1iii
   if 97 - 97: I11i
  if ( O0000OiII111 == "set-destination-eid" ) :
   if ( III1ii . set_dest_eid == None ) :
    III1ii . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
   III1ii . set_dest_eid . store_prefix ( oO00o )
   if ( iIi1iii != None ) : III1ii . set_dest_eid . instance_id = iIi1iii
   if 20 - 20: oO0o % OoOoOO00
  if ( O0000OiII111 == "set-rloc-address" ) :
   III1ii . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   III1ii . set_rloc_address . store_address ( oO00o )
   if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
  if ( O0000OiII111 == "set-rloc-record-name" ) :
   III1ii . set_rloc_record_name = oO00o
   if 82 - 82: OOooOOo
  if ( O0000OiII111 == "set-elp-name" ) :
   III1ii . set_elp_name = oO00o
   if 27 - 27: I1Ii111 / IiII - i1IIi * Ii1I
  if ( O0000OiII111 == "set-geo-name" ) :
   III1ii . set_geo_name = oO00o
   if 90 - 90: ooOoO0o
  if ( O0000OiII111 == "set-rle-name" ) :
   III1ii . set_rle_name = oO00o
   if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
  if ( O0000OiII111 == "set-json-name" ) :
   III1ii . set_json_name = oO00o
   if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
  if ( O0000OiII111 == "policy-name" ) :
   III1ii . policy_name = oO00o
   if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
   if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
   if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
   if 55 - 55: Oo0Ooo - OOooOOo - O0
   if 40 - 40: OoOoOO00 - OOooOOo
   if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 III1ii . match_clauses = OOO0OOoO
 III1ii . save_policy ( )
 return
 if 35 - 35: II111iiii
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
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
if 96 - 96: O0
if 15 - 15: i1IIi . iIii1I11I1II1
if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
if 61 - 61: I1Ii111 + I11i + I1IiiI
if 48 - 48: I11i
if 67 - 67: o0oOOo0O0Ooo
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
 OoO0o = command
 if ( interface != "" ) : OoO0o = interface + ": " + OoO0o
 lprint ( "Send CLI command '{}' to hardware" . format ( OoO0o ) )
 if 66 - 66: OoooooooOO * ooOoO0o % I1ii11iIi11i . OOooOOo
 i1ii1IIiI = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 17 - 17: I1ii11iIi11i + Oo0Ooo
 os . system ( "FastCli -c '{}'" . format ( i1ii1IIiI ) )
 return
 if 75 - 75: Ii1I
 if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
 if 99 - 99: oO0o + I11i % i1IIi . iII111i
 if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
 if 65 - 65: OoO0O00
 if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
 if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
def lisp_arista_is_alive ( prefix ) :
 I1IIIi = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 i11IiIIi11I = getoutput ( "FastCli -c '{}'" . format ( I1IIIi ) )
 if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
 if 74 - 74: OoOoOO00 + I1ii11iIi11i
 if 82 - 82: II111iiii
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 i11IiIIi11I = i11IiIIi11I . split ( "\n" ) [ 1 ]
 i1iIIi = i11IiIIi11I . split ( " " )
 i1iIIi = i1iIIi [ - 1 ] . replace ( "\r" , "" )
 if 70 - 70: iIii1I11I1II1
 if 85 - 85: OoooooooOO * O0 % o0oOOo0O0Ooo % Ii1I . OoooooooOO - I11i
 if 75 - 75: Ii1I + iIii1I11I1II1 . II111iiii
 if 28 - 28: I1Ii111 / iII111i * i1IIi - I1IiiI
 return ( i1iIIi == "Y" )
 if 73 - 73: o0oOOo0O0Ooo . OoOoOO00 % II111iiii . I11i * Oo0Ooo
 if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
 if 62 - 62: IiII . O0
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
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
 if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
 if 41 - 41: oO0o
 if 12 - 12: I1IiiI + I1Ii111
 if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
 if 79 - 79: Ii1I + IiII
 if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
 if 98 - 98: I1ii11iIi11i
 if 58 - 58: IiII / i11iIiiIii % I11i
 if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
 if 21 - 21: Ii1I
 if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
 if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
 if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
 if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
 if 44 - 44: iIii1I11I1II1 . OOooOOo
 if 57 - 57: II111iiii + I1Ii111
 if 42 - 42: OoOoOO00 % O0
 if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
 if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
 if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
 if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
 if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
 if 26 - 26: Ii1I * I11i / I11i
 if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
def lisp_program_vxlan_hardware ( mc ) :
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
 if 16 - 16: I11i
 if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
 if 61 - 61: O0 % iII111i
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 41 - 41: I1Ii111 * OoooooooOO
 if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
 if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
 if 19 - 19: iIii1I11I1II1
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
 if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
 if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
 if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
 I1iiIi = mc . eid . print_prefix_no_iid ( )
 iIIiI11 = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
 if 57 - 57: i1IIi
 if 41 - 41: I11i / Ii1I
 if 1 - 1: II111iiii / iII111i
 oO0O = getoutput ( "ip route get {} | egrep vlan4094" . format ( I1iiIi ) )
 if 81 - 81: iIii1I11I1II1 * OoO0O00 - Ii1I / oO0o - ooOoO0o
 if ( oO0O != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( I1iiIi , False ) , oO0O ) )
  if 6 - 6: I1IiiI - oO0o + OoO0O00
  return
  if 58 - 58: iIii1I11I1II1 + OoOoOO00
  if 65 - 65: iII111i % Oo0Ooo * iIii1I11I1II1 + I1IiiI + II111iiii
  if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
  if 15 - 15: OoOoOO00
  if 13 - 13: I1ii11iIi11i - OOooOOo - i11iIiiIii / IiII
  if 65 - 65: IiII
  if 76 - 76: I1Ii111 % I1ii11iIi11i + ooOoO0o / I1IiiI
 O0OO0OoOO = getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( O0OO0OoOO . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 72 - 72: I1ii11iIi11i - IiII + OoO0O00 . o0oOOo0O0Ooo
 if ( O0OO0OoOO . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 95 - 95: I1Ii111 - I1IiiI % I1IiiI / O0 % iII111i
 iiO0oOoOooo = getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( iiO0oOoOooo == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 90 - 90: I11i
 iiO0oOoOooo = iiO0oOoOooo . split ( "inet " ) [ 1 ]
 iiO0oOoOooo = iiO0oOoOooo . split ( "/" ) [ 0 ]
 if 6 - 6: o0oOOo0O0Ooo / i11iIiiIii + Oo0Ooo * Oo0Ooo % OOooOOo
 if 66 - 66: I1ii11iIi11i + iII111i / Ii1I / I1IiiI * i11iIiiIii
 if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
 if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 I1Ii1ii = [ ]
 IiO0o00OO000o = getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for oOo0OoOOOo0 in IiO0o00OO000o :
  if ( oOo0OoOOOo0 . find ( "vlan4094" ) == - 1 ) : continue
  if ( oOo0OoOOOo0 . find ( "(incomplete)" ) == - 1 ) : continue
  O0O0O0ooOoOo = oOo0OoOOOo0 . split ( " " ) [ 0 ]
  I1Ii1ii . append ( O0O0O0ooOoOo )
  if 5 - 5: i1IIi - OoOoOO00 - I1IiiI * iIii1I11I1II1 - ooOoO0o
  if 24 - 24: OoO0O00
 O0O0O0ooOoOo = None
 I1II1I11Ii1i = iiO0oOoOooo
 iiO0oOoOooo = iiO0oOoOooo . split ( "." )
 for o000o0O0Oo00 in range ( 1 , 255 ) :
  iiO0oOoOooo [ 3 ] = str ( o000o0O0Oo00 )
  iI1ii11Ii = "." . join ( iiO0oOoOooo )
  if ( iI1ii11Ii in I1Ii1ii ) : continue
  if ( iI1ii11Ii == I1II1I11Ii1i ) : continue
  O0O0O0ooOoOo = iI1ii11Ii
  break
  if 100 - 100: I1Ii111 / I1Ii111
 if ( O0O0O0ooOoOo == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 17 - 17: OoooooooOO - O0
  return
  if 95 - 95: I1IiiI / I1IiiI * OoooooooOO
  if 78 - 78: Oo0Ooo / Ii1I
  if 74 - 74: OOooOOo . II111iiii - i11iIiiIii / OoooooooOO + OoOoOO00 * ooOoO0o
  if 63 - 63: OoO0O00
  if 66 - 66: iIii1I11I1II1
  if 98 - 98: iII111i . oO0o % I1Ii111 + Oo0Ooo
  if 83 - 83: Oo0Ooo % oO0o - iII111i
 iIiiiIIi1 = iIIiI11 . split ( "." )
 iIIi1II1 = lisp_hex_string ( iIiiiIIi1 [ 1 ] ) . zfill ( 2 )
 IIIiiiI = lisp_hex_string ( iIiiiIIi1 [ 2 ] ) . zfill ( 2 )
 oo0O = lisp_hex_string ( iIiiiIIi1 [ 3 ] ) . zfill ( 2 )
 i1i1I1 = "00:00:00:{}:{}:{}" . format ( iIIi1II1 , IIIiiiI , oo0O )
 IIO0o00o = "0000.00{}.{}{}" . format ( iIIi1II1 , IIIiiiI , oo0O )
 IiiIi11iIiII = "arp -i vlan4094 -s {} {}" . format ( O0O0O0ooOoOo , i1i1I1 )
 os . system ( IiiIi11iIiII )
 if 55 - 55: OoooooooOO
 if 26 - 26: OoooooooOO * iII111i - iIii1I11I1II1 + I1ii11iIi11i
 if 37 - 37: iII111i - OoooooooOO . i11iIiiIii * i1IIi - II111iiii * ooOoO0o
 if 54 - 54: OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
 iIiIiiIiiI = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( IIO0o00o , iIIiI11 )
 if 73 - 73: I1Ii111 / i11iIiiIii * iIii1I11I1II1 + OoOoOO00 + I1IiiI
 lisp_send_to_arista ( iIiIiiIiiI , None )
 if 84 - 84: I1IiiI / I1IiiI + OoO0O00 . i1IIi . I1IiiI / OoOoOO00
 if 90 - 90: IiII . OoooooooOO - i11iIiiIii . OoooooooOO - I1ii11iIi11i
 if 54 - 54: I1Ii111 % II111iiii - Ii1I . OoO0O00 + ooOoO0o / iII111i
 if 85 - 85: o0oOOo0O0Ooo - O0
 if 3 - 3: iIii1I11I1II1
 OO0o0oO00oO0o = "ip route add {} via {}" . format ( I1iiIi , O0O0O0ooOoOo )
 os . system ( OO0o0oO00oO0o )
 if 72 - 72: I11i * iII111i . I1ii11iIi11i * II111iiii / iIii1I11I1II1 % IiII
 lprint ( "Hardware programmed with commands:" )
 OO0o0oO00oO0o = OO0o0oO00oO0o . replace ( I1iiIi , green ( I1iiIi , False ) )
 lprint ( "  " + OO0o0oO00oO0o )
 lprint ( "  " + IiiIi11iIiII )
 iIiIiiIiiI = iIiIiiIiiI . replace ( iIIiI11 , red ( iIIiI11 , False ) )
 lprint ( "  " + iIiIiiIiiI )
 return
 if 75 - 75: i1IIi
 if 25 - 25: ooOoO0o . OoooooooOO . OoO0O00 . I1IiiI
 if 28 - 28: iII111i % Oo0Ooo % I1IiiI + iII111i
 if 67 - 67: i1IIi + OoooooooOO * i11iIiiIii / iIii1I11I1II1
 if 86 - 86: o0oOOo0O0Ooo + OoOoOO00 % I11i - iIii1I11I1II1 % OoOoOO00 + ooOoO0o
 if 30 - 30: II111iiii / OoOoOO00 * o0oOOo0O0Ooo + OoooooooOO
 if 32 - 32: Ii1I - Ii1I / i11iIiiIii
def lisp_clear_hardware_walk ( mc , parms ) :
 OoOo00 = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( OoOo00 ) )
 return ( [ True , None ] )
 if 48 - 48: iIii1I11I1II1 % OoooooooOO * Ii1I . i1IIi . oO0o % iIii1I11I1II1
 if 89 - 89: I11i + I11i * OoooooooOO + IiII % iIii1I11I1II1
 if 52 - 52: i1IIi
 if 85 - 85: I1Ii111 - iII111i
 if 44 - 44: I11i - I11i - IiII . I11i
 if 34 - 34: iIii1I11I1II1 - oO0o * i11iIiiIii * o0oOOo0O0Ooo
 if 15 - 15: I1Ii111
 if 25 - 25: I1ii11iIi11i * O0
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 8 - 8: i11iIiiIii
 O0ooo0 = bold ( "User cleared" , False )
 oo0O00ooo0o = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( O0ooo0 , oo0O00ooo0o ) )
 if 1 - 1: I1ii11iIi11i + iII111i
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 61 - 61: oO0o - OOooOOo % II111iiii + IiII + O0 / o0oOOo0O0Ooo
 lisp_map_cache = lisp_cache ( )
 if 78 - 78: I11i
 if 32 - 32: II111iiii / II111iiii + o0oOOo0O0Ooo + OoooooooOO
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
 if 87 - 87: OOooOOo * OoO0O00
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 if 86 - 86: II111iiii
 if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
 if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
 if 91 - 91: Ii1I
 lisp_rloc_probe_list = { }
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 72 - 72: I1ii11iIi11i
 if 5 - 5: i1IIi
 if 31 - 31: iII111i - OoooooooOO + oO0o / OoooooooOO + I1ii11iIi11i
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 93 - 93: o0oOOo0O0Ooo * I1ii11iIi11i % I1IiiI * ooOoO0o
 if 37 - 37: OoO0O00 * OoooooooOO / oO0o * I11i * I1ii11iIi11i
 if 42 - 42: OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
 if 53 - 53: o0oOOo0O0Ooo
 if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
 lisp_rtr_list = { }
 if 31 - 31: OoO0O00 % I1Ii111
 if 62 - 62: oO0o / O0 - I1Ii111 . IiII
 if 81 - 81: i11iIiiIii
 if 57 - 57: O0
 lisp_gleaned_groups = { }
 if 85 - 85: i11iIiiIii - i11iIiiIii - OoOoOO00 / II111iiii - II111iiii
 if 4 - 4: I1ii11iIi11i * O0 / OoO0O00 * II111iiii . iIii1I11I1II1 / OOooOOo
 if 97 - 97: i1IIi - OoOoOO00 . OoooooooOO
 if 24 - 24: iIii1I11I1II1 + OOooOOo * iII111i % IiII % OOooOOo
 lisp_process_data_plane_restart ( True )
 return
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
 if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
def lisp_encap_rloc_probe ( lisp_sockets , rloc , nat_info , packet ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
 if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
 if 79 - 79: IiII + I1Ii111
 O0oOo000o = lisp_myrlocs [ 0 ]
 if ( lisp_i_am_rtr and lisp_on_aws ( ) ) :
  iI1ii11Ii = lisp_get_interface_address ( "eth0" )
  if ( iI1ii11Ii == None ) : iI1ii11Ii = lisp_get_interface_address ( "ens5" )
  if ( iI1ii11Ii ) : O0oOo000o = iI1ii11Ii
  if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
  if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
  if 73 - 73: OoOoOO00
  if 44 - 44: Oo0Ooo / oO0o
  if 9 - 9: i1IIi % I1IiiI + OoO0O00 * ooOoO0o / iIii1I11I1II1 / iII111i
  if 80 - 80: OOooOOo / O0 % IiII * OoOoOO00
 iI = len ( packet ) + 28
 ooooO000 = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( iI ) , 0 , 64 ,
 17 , 0 , socket . htonl ( O0oOo000o . address ) , socket . htonl ( rloc . address ) )
 ooooO000 = lisp_ip_checksum ( ooooO000 )
 if 53 - 53: OOooOOo + i11iIiiIii
 iiI1iiIiiiI1I = socket . htons ( LISP_DATA_PORT )
 i111I1 = socket . htons ( LISP_CTRL_PORT )
 ii11 = struct . pack ( "HHHH" , iiI1iiIiiiI1I , i111I1 , socket . htons ( iI - 20 ) , 0 )
 if 25 - 25: i11iIiiIii
 if 51 - 51: iII111i . ooOoO0o
 if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
 if 6 - 6: I11i + II111iiii - I1Ii111
 ooIiii = packet [ 0 : 1 ]
 packet = lisp_packet ( ooooO000 + ii11 + packet )
 if 45 - 45: i1IIi / iII111i + i11iIiiIii * I11i + ooOoO0o / OoooooooOO
 if 56 - 56: I11i + I1Ii111
 if 80 - 80: II111iiii . Ii1I + o0oOOo0O0Ooo / II111iiii / OoO0O00 + iIii1I11I1II1
 if 29 - 29: o0oOOo0O0Ooo + OoOoOO00 + ooOoO0o - I1ii11iIi11i
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( O0oOo000o )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( O0oOo000o )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 64 - 64: O0 / OoooooooOO
 o00oO = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  ooo00 = " {}" . format ( blue ( nat_info . hostname , False ) )
 else :
  ooo00 = ""
  if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if ( lisp_is_rloc_probe_request ( ooIiii ) ) :
  II1iii1I1 = bold ( "RLOC-probe request" , False )
 else :
  II1iii1I1 = bold ( "RLOC-probe reply" , False )
  if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
  if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( II1iii1I1 , o00oO , ooo00 , packet . encap_port ) )
 if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
 if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
 if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
 if 77 - 77: OoO0O00
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 95 - 95: II111iiii
 Ooo00O000o = lisp_sockets [ 3 ]
 packet . send_packet ( Ooo00O000o , packet . outer_dest )
 del ( packet )
 return
 if 7 - 7: ooOoO0o * I1Ii111 + I1IiiI
 if 88 - 88: O0 - O0 / Ii1I - OOooOOo % I11i
 if 13 - 13: IiII % OoooooooOO * IiII - OoO0O00 % OoooooooOO * IiII
 if 91 - 91: ooOoO0o * ooOoO0o % I1Ii111 . I1ii11iIi11i + iII111i / oO0o
 if 60 - 60: Ii1I
 if 27 - 27: I1ii11iIi11i - I11i . OoO0O00 / o0oOOo0O0Ooo
 if 87 - 87: iIii1I11I1II1 - OOooOOo - OOooOOo
 if 55 - 55: Oo0Ooo + OoooooooOO . IiII / O0 + I11i
def lisp_get_default_route_next_hops ( ) :
 if 58 - 58: Ii1I
 if 35 - 35: OoO0O00 + OoOoOO00
 if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
 if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
 if ( lisp_is_macos ( ) ) :
  I1IIIi = "route -n get default"
  iIiIIIiI1 = getoutput ( I1IIIi ) . split ( "\n" )
  iii11II11i1i111iIi = OoO00OooO0 = None
  for o0OoO0 in iIiIIIiI1 :
   if ( o0OoO0 . find ( "gateway: " ) != - 1 ) : iii11II11i1i111iIi = o0OoO0 . split ( ": " ) [ 1 ]
   if ( o0OoO0 . find ( "interface: " ) != - 1 ) : OoO00OooO0 = o0OoO0 . split ( ": " ) [ 1 ]
   if 22 - 22: o0oOOo0O0Ooo . Ii1I % Ii1I % i1IIi
  return ( [ [ OoO00OooO0 , iii11II11i1i111iIi ] ] )
  if 55 - 55: oO0o . Ii1I % Ii1I
  if 30 - 30: IiII / i11iIiiIii
  if 79 - 79: Ii1I . IiII . oO0o * O0
  if 99 - 99: OOooOOo * iIii1I11I1II1 - iII111i / O0 % OoooooooOO + iIii1I11I1II1
  if 87 - 87: II111iiii * iIii1I11I1II1 - i11iIiiIii . Ii1I . Ii1I % OOooOOo
 I1IIIi = "ip route | egrep 'default via'"
 OO00 = getoutput ( I1IIIi ) . split ( "\n" )
 if 27 - 27: o0oOOo0O0Ooo
 OOoOOoo = [ ]
 for oO0O in OO00 :
  I1I1 = oO0O . split ( )
  try :
   O0O0O0ooOoOo = I1I1 [ 2 ]
   ooo = I1I1 [ 4 ]
  except :
   continue
   if 27 - 27: I1Ii111 % i1IIi
  OOoOOoo . append ( [ ooo , O0O0O0ooOoOo ] )
  if 93 - 93: I1Ii111 / o0oOOo0O0Ooo
 return ( OOoOOoo )
 if 33 - 33: OOooOOo * IiII * OoO0O00 - I1ii11iIi11i % OoO0O00
 if 16 - 16: OoO0O00 * I1IiiI
 if 58 - 58: oO0o * II111iiii * O0
 if 89 - 89: I1Ii111 + IiII % I1ii11iIi11i
 if 80 - 80: Oo0Ooo + ooOoO0o + IiII
 if 76 - 76: I1Ii111
 if 23 - 23: O0 % I1ii11iIi11i % iIii1I11I1II1
def lisp_get_host_route_next_hop ( rloc ) :
 I1IIIi = "ip route | egrep '{} via'" . format ( rloc )
 oO0O = getoutput ( I1IIIi ) . split ( )
 if 49 - 49: iII111i + I1Ii111 % OoOoOO00
 try : o00O = oO0O . index ( "via" ) + 1
 except : return ( None )
 if 67 - 67: Ii1I
 if ( o00O >= len ( oO0O ) ) : return ( None )
 return ( oO0O [ o00O ] )
 if 27 - 27: Oo0Ooo / i11iIiiIii / II111iiii . Ii1I - II111iiii / OoO0O00
 if 61 - 61: ooOoO0o - OOooOOo
 if 45 - 45: O0 . OoO0O00
 if 80 - 80: IiII + OoO0O00
 if 2 - 2: IiII + OoOoOO00 % oO0o
 if 76 - 76: o0oOOo0O0Ooo
 if 25 - 25: OoooooooOO
def lisp_install_host_route ( dest , nh , install ) :
 install = "add" if install else "delete"
 Oo00O0Oo0O = "none" if nh == None else nh
 if 78 - 78: oO0o / i11iIiiIii * O0 / OOooOOo % i11iIiiIii % O0
 lprint ( "{} host-route {}/32, nh {}" . format ( install . title ( ) , dest , Oo00O0Oo0O ) )
 if 86 - 86: IiII
 if ( nh == None ) :
  IIIII1I1iI = "ip route {} {}/32" . format ( install , dest )
 else :
  IIIII1I1iI = "ip route {} {}/32 via {}" . format ( install , dest , nh )
  if 26 - 26: IiII - I1Ii111 + i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo
 os . system ( IIIII1I1iI )
 return
 if 39 - 39: Ii1I - i1IIi + i11iIiiIii
 if 21 - 21: IiII
 if 76 - 76: o0oOOo0O0Ooo % Oo0Ooo + OoO0O00
 if 36 - 36: OOooOOo . oO0o
 if 15 - 15: I1IiiI + ooOoO0o - o0oOOo0O0Ooo
 if 62 - 62: Ii1I - OOooOOo
 if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
 if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
 o0OoO0 = open ( lisp_checkpoint_filename , "w" )
 for iIiiI11II11i in checkpoint_list :
  o0OoO0 . write ( iIiiI11II11i + "\n" )
  if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
 o0OoO0 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
 if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
 if 2 - 2: I1ii11iIi11i
 if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
 if 54 - 54: ooOoO0o
 if 47 - 47: I11i * I1IiiI / oO0o
 if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
 if 4 - 4: i1IIi
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 43 - 43: oO0o * ooOoO0o - I11i
 o0OoO0 = open ( lisp_checkpoint_filename , "r" )
 if 70 - 70: oO0o / Ii1I
 oo0O00ooo0o = 0
 for iIiiI11II11i in o0OoO0 :
  oo0O00ooo0o += 1
  oOO = iIiiI11II11i . split ( " rloc " )
  Oo0O0oo = [ ] if ( oOO [ 1 ] in [ "native-forward\n" , "\n" ] ) else oOO [ 1 ] . split ( ", " )
  if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
  if 16 - 16: iII111i
  i1i1i1 = [ ]
  for iIIiI11 in Oo0O0oo :
   iIIoOo = lisp_rloc ( False )
   I1I1 = iIIiI11 . split ( " " )
   iIIoOo . rloc . store_address ( I1I1 [ 0 ] )
   iIIoOo . priority = int ( I1I1 [ 1 ] )
   iIIoOo . weight = int ( I1I1 [ 2 ] )
   i1i1i1 . append ( iIIoOo )
   if 50 - 50: iIii1I11I1II1 - II111iiii % i1IIi
   if 48 - 48: O0
  I1I1i1I11I = lisp_mapping ( "" , "" , i1i1i1 )
  if ( I1I1i1I11I != None ) :
   I1I1i1I11I . eid . store_prefix ( oOO [ 0 ] )
   I1I1i1I11I . checkpoint_entry = True
   I1I1i1I11I . map_cache_ttl = LISP_NMR_TTL * 60
   if ( i1i1i1 == [ ] ) : I1I1i1I11I . action = LISP_NATIVE_FORWARD_ACTION
   I1I1i1I11I . add_cache ( )
   continue
   if 60 - 60: ooOoO0o - IiII % i1IIi
   if 5 - 5: oO0o
  oo0O00ooo0o -= 1
  if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
  if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
 o0OoO0 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , oo0O00ooo0o , lisp_checkpoint_filename ) )
 return
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
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
 iIiiI11II11i = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
 for iIIoOo in mc . rloc_set :
  if ( iIIoOo . rloc . is_null ( ) ) : continue
  iIiiI11II11i += "{} {} {}, " . format ( iIIoOo . rloc . print_address_no_iid ( ) ,
 iIIoOo . priority , iIIoOo . weight )
  if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
  if 79 - 79: I11i . I11i - OoOoOO00
 if ( mc . rloc_set != [ ] ) :
  iIiiI11II11i = iIiiI11II11i [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  iIiiI11II11i += "native-forward"
  if 86 - 86: OoO0O00 * Oo0Ooo . iIii1I11I1II1 * O0
  if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
 checkpoint_list . append ( iIiiI11II11i )
 return
 if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
 if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
 if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
 if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
 if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
 if 93 - 93: oO0o
def lisp_check_dp_socket ( ) :
 OOoooO0O0000o = lisp_ipc_dp_socket_name
 if ( os . path . exists ( OOoooO0O0000o ) == False ) :
  iI111Ii = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( OOoooO0O0000o , iI111Ii ) )
  return ( False )
  if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
 return ( True )
 if 54 - 54: OoOoOO00 - I1IiiI - iII111i
 if 49 - 49: i11iIiiIii * Oo0Ooo
 if 100 - 100: Oo0Ooo * oO0o
 if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
 if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
 if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
 if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
def lisp_write_to_dp_socket ( entry ) :
 try :
  oOo0oOOO = json . dumps ( entry )
  o00o00o0000oo = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( o00o00o0000oo , oOo0oOOO ) )
  lisp_ipc_dp_socket . sendto ( oOo0oOOO , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( oOo0oOOO ) )
  if 84 - 84: I1ii11iIi11i - iII111i
 return
 if 9 - 9: Ii1I - OOooOOo * oO0o + I11i
 if 24 - 24: II111iiii + I11i + Ii1I
 if 64 - 64: iIii1I11I1II1 % IiII
 if 50 - 50: OOooOOo . I11i - ooOoO0o . Ii1I - O0 * o0oOOo0O0Ooo
 if 49 - 49: I11i . O0 / Ii1I / I1IiiI + IiII
 if 58 - 58: oO0o * Oo0Ooo % I11i * i11iIiiIii % I1ii11iIi11i
 if 70 - 70: II111iiii + Oo0Ooo * I11i % OoooooooOO * ooOoO0o - II111iiii
 if 74 - 74: iIii1I11I1II1 - I1ii11iIi11i * Ii1I * I1Ii111 + i11iIiiIii
 if 50 - 50: OoO0O00
def lisp_write_ipc_keys ( rloc ) :
 O00oO000Oo0 = rloc . rloc . print_address_no_iid ( )
 I1I1I1 = rloc . translated_port
 if ( I1I1I1 != 0 ) : O00oO000Oo0 += ":" + str ( I1I1I1 )
 if ( O00oO000Oo0 not in lisp_rloc_probe_list ) : return
 if 48 - 48: Oo0Ooo
 for I1I1 , oOO , II11iIIii in lisp_rloc_probe_list [ O00oO000Oo0 ] :
  I1I1i1I11I = lisp_map_cache . lookup_cache ( oOO , True )
  if ( I1I1i1I11I == None ) : continue
  lisp_write_ipc_map_cache ( True , I1I1i1I11I )
  if 99 - 99: i1IIi + II111iiii - I1Ii111
 return
 if 9 - 9: O0 % OOooOOo / i1IIi + II111iiii % iIii1I11I1II1
 if 99 - 99: Ii1I * o0oOOo0O0Ooo / i11iIiiIii * OOooOOo * I1ii11iIi11i + OOooOOo
 if 48 - 48: I1ii11iIi11i + iIii1I11I1II1 + I1Ii111 - I1Ii111 - ooOoO0o % Oo0Ooo
 if 69 - 69: i11iIiiIii % Ii1I * O0 / IiII + IiII
 if 45 - 45: O0 * Ii1I % oO0o
 if 18 - 18: i11iIiiIii . Ii1I % I1ii11iIi11i - OoooooooOO . I1ii11iIi11i
 if 19 - 19: iII111i + I1IiiI
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 71 - 71: iII111i % o0oOOo0O0Ooo
 if 91 - 91: i11iIiiIii * iIii1I11I1II1 % oO0o . II111iiii / Ii1I + Ii1I
 if 32 - 32: OOooOOo % OOooOOo + I1ii11iIi11i / Ii1I - i11iIiiIii
 if 28 - 28: iIii1I11I1II1 - II111iiii
 Ii11 = "add" if add_or_delete else "delete"
 iIiiI11II11i = { "type" : "map-cache" , "opcode" : Ii11 }
 if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
 iii = ( mc . group . is_null ( ) == False )
 if ( iii ) :
  iIiiI11II11i [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  iIiiI11II11i [ "rles" ] = [ ]
 else :
  iIiiI11II11i [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  iIiiI11II11i [ "rlocs" ] = [ ]
  if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
 iIiiI11II11i [ "instance-id" ] = str ( mc . eid . instance_id )
 if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
 if ( iii ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for Ii1111iiIii in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    iI1ii11Ii = Ii1111iiIii . rloc . rloc . print_address_no_iid ( )
    I1I1I1 = str ( 4341 ) if Ii1111iiIii . rloc . translated_port == 0 else str ( Ii1111iiIii . rloc . translated_port )
    if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
    I1I1 = { "rle" : iI1ii11Ii , "port" : I1I1I1 }
    i1ii1IIii , oO0oI1111iI1II = Ii1111iiIii . get_encap_keys ( )
    I1I1 = lisp_build_json_keys ( I1I1 , i1ii1IIii , oO0oI1111iI1II , "encrypt-key" )
    iIiiI11II11i [ "rles" ] . append ( I1I1 )
    if 79 - 79: I11i - I1Ii111 / iIii1I11I1II1 - OOooOOo
    if 38 - 38: iIii1I11I1II1 - OoooooooOO * II111iiii . OoooooooOO + OOooOOo
 else :
  for iIIiI11 in mc . rloc_set :
   if ( iIIiI11 . rloc . is_ipv4 ( ) == False and iIIiI11 . rloc . is_ipv6 ( ) == False ) :
    continue
    if 59 - 59: OoooooooOO
   if ( iIIiI11 . up_state ( ) == False ) : continue
   if 22 - 22: II111iiii
   I1I1I1 = str ( 4341 ) if iIIiI11 . translated_port == 0 else str ( iIIiI11 . translated_port )
   if 85 - 85: I1Ii111 + I1ii11iIi11i * I11i % o0oOOo0O0Ooo + Ii1I
   I1I1 = { "rloc" : iIIiI11 . rloc . print_address_no_iid ( ) , "priority" :
 str ( iIIiI11 . priority ) , "weight" : str ( iIIiI11 . weight ) , "port" :
 I1I1I1 }
   i1ii1IIii , oO0oI1111iI1II = iIIiI11 . get_encap_keys ( )
   I1I1 = lisp_build_json_keys ( I1I1 , i1ii1IIii , oO0oI1111iI1II , "encrypt-key" )
   iIiiI11II11i [ "rlocs" ] . append ( I1I1 )
   if 23 - 23: IiII * OoO0O00
   if 42 - 42: IiII
   if 83 - 83: i1IIi * o0oOOo0O0Ooo / OoO0O00 / o0oOOo0O0Ooo
 if ( dont_send == False ) : lisp_write_to_dp_socket ( iIiiI11II11i )
 return ( iIiiI11II11i )
 if 55 - 55: Oo0Ooo % O0 - OoO0O00
 if 42 - 42: OoooooooOO * OOooOOo
 if 93 - 93: OOooOOo + II111iiii . oO0o * Oo0Ooo - O0 + I1Ii111
 if 99 - 99: OoO0O00 * o0oOOo0O0Ooo + OoOoOO00 * iIii1I11I1II1
 if 38 - 38: I1ii11iIi11i - OOooOOo * O0 - I1ii11iIi11i
 if 95 - 95: OoO0O00 . oO0o . OoooooooOO - iIii1I11I1II1
 if 35 - 35: o0oOOo0O0Ooo / OoooooooOO - i1IIi * iIii1I11I1II1 + ooOoO0o
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 66 - 66: Oo0Ooo - OoOoOO00 . I1Ii111 + O0 + o0oOOo0O0Ooo
 if 36 - 36: II111iiii % IiII . i11iIiiIii
 if 88 - 88: Oo0Ooo . IiII * Oo0Ooo
 if 92 - 92: I1IiiI % IiII
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 95 - 95: OoooooooOO / OoO0O00 % O0 / I1Ii111 * Ii1I + I1ii11iIi11i
 i1ii1IIii = keys [ 1 ] . encrypt_key
 oO0oI1111iI1II = keys [ 1 ] . icv_key
 if 7 - 7: ooOoO0o
 if 83 - 83: oO0o / I1Ii111 + I1Ii111 * I1ii11iIi11i
 if 8 - 8: I11i . I1ii11iIi11i % i1IIi + Ii1I
 if 63 - 63: I1IiiI / OoooooooOO
 iIiii1I = rloc_addr . split ( ":" )
 if ( len ( iIiii1I ) == 1 ) :
  iIiiI11II11i = { "type" : "decap-keys" , "rloc" : iIiii1I [ 0 ] }
 else :
  iIiiI11II11i = { "type" : "decap-keys" , "rloc" : iIiii1I [ 0 ] , "port" : iIiii1I [ 1 ] }
  if 85 - 85: ooOoO0o + I1Ii111 - O0 * I11i / i1IIi
 iIiiI11II11i = lisp_build_json_keys ( iIiiI11II11i , i1ii1IIii , oO0oI1111iI1II , "decrypt-key" )
 if 66 - 66: ooOoO0o % I1Ii111 - O0 + I1Ii111 - i1IIi % OoOoOO00
 lisp_write_to_dp_socket ( iIiiI11II11i )
 return
 if 13 - 13: O0 + iIii1I11I1II1 % I1IiiI * O0 + ooOoO0o
 if 60 - 60: iIii1I11I1II1 + OoooooooOO - OoO0O00
 if 44 - 44: O0 . OOooOOo . o0oOOo0O0Ooo . I1ii11iIi11i - II111iiii
 if 71 - 71: I1ii11iIi11i + o0oOOo0O0Ooo . i11iIiiIii * oO0o . i1IIi
 if 40 - 40: OoO0O00 - IiII
 if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
 if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
 if 38 - 38: iII111i - I1IiiI / ooOoO0o
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
 entry [ "keys" ] = [ ]
 OoOOooOOoo = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( OoOOooOOoo )
 return ( entry )
 if 19 - 19: I11i / Oo0Ooo + I1Ii111
 if 43 - 43: I1ii11iIi11i
 if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
 if 22 - 22: iII111i
 if 88 - 88: I11i + OoOoOO00 % IiII % OoO0O00 * O0 / OoooooooOO
 if 83 - 83: IiII + I1Ii111 . I1ii11iIi11i * iIii1I11I1II1
 if 9 - 9: ooOoO0o % IiII - OoOoOO00
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 66 - 66: oO0o % Oo0Ooo
 if 40 - 40: i11iIiiIii . O0 * I11i - oO0o / OOooOOo . oO0o
 if 86 - 86: OOooOOo - I1Ii111 * IiII - i1IIi + ooOoO0o + I11i
 if 32 - 32: IiII
 iIiiI11II11i = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 99 - 99: II111iiii
 if 34 - 34: OOooOOo + OoOoOO00 * o0oOOo0O0Ooo + I1ii11iIi11i + IiII * i1IIi
 if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
 if 68 - 68: I1ii11iIi11i - OoooooooOO
 for i1I in lisp_db_list :
  if ( i1I . eid . is_ipv4 ( ) == False and i1I . eid . is_ipv6 ( ) == False ) : continue
  IIIiiiIi11I1 = { "instance-id" : str ( i1I . eid . instance_id ) ,
 "eid-prefix" : i1I . eid . print_prefix_no_iid ( ) }
  iIiiI11II11i [ "database-mappings" ] . append ( IIIiiiIi11I1 )
  if 85 - 85: I1IiiI
 lisp_write_to_dp_socket ( iIiiI11II11i )
 if 97 - 97: I1ii11iIi11i - i11iIiiIii + OoOoOO00 * iIii1I11I1II1 * iIii1I11I1II1
 if 51 - 51: i1IIi - O0 * I1IiiI * IiII * I11i % oO0o
 if 47 - 47: i1IIi - I11i . OoooooooOO
 if 5 - 5: iII111i % Oo0Ooo - oO0o . i1IIi - i11iIiiIii % I1ii11iIi11i
 if 79 - 79: I1IiiI
 iIiiI11II11i = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( iIiiI11II11i )
 return
 if 24 - 24: I1IiiI / II111iiii - I1Ii111
 if 68 - 68: I1IiiI
 if 97 - 97: Ii1I + o0oOOo0O0Ooo / OoO0O00
 if 97 - 97: i11iIiiIii % iIii1I11I1II1 + II111iiii
 if 90 - 90: OOooOOo / I1IiiI
 if 28 - 28: OoooooooOO + i1IIi
 if 29 - 29: Oo0Ooo
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 98 - 98: OOooOOo / Oo0Ooo % Ii1I * OoooooooOO - oO0o
 if 64 - 64: I1IiiI - I1IiiI
 if 90 - 90: iII111i - I1IiiI - II111iiii / OOooOOo + Ii1I
 if 34 - 34: i11iIiiIii + I1Ii111 / O0 / iIii1I11I1II1 * OoooooooOO % Ii1I
 iIiiI11II11i = { "type" : "interfaces" , "interfaces" : [ ] }
 if 32 - 32: i11iIiiIii - OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI + O0
 for OoO00OooO0 in list ( lisp_myinterfaces . values ( ) ) :
  if ( OoO00OooO0 . instance_id == None ) : continue
  IIIiiiIi11I1 = { "interface" : OoO00OooO0 . device ,
 "instance-id" : str ( OoO00OooO0 . instance_id ) }
  iIiiI11II11i [ "interfaces" ] . append ( IIIiiiIi11I1 )
  if 36 - 36: I1ii11iIi11i + I1ii11iIi11i % I1Ii111 * ooOoO0o * OoOoOO00
  if 54 - 54: Oo0Ooo - I1IiiI % OOooOOo . I1ii11iIi11i / I1IiiI
 lisp_write_to_dp_socket ( iIiiI11II11i )
 return
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
def lisp_parse_auth_key ( value ) :
 oo0oOoooOooO0 = value . split ( "[" )
 IIi11ii = { }
 if ( len ( oo0oOoooOooO0 ) == 1 ) :
  IIi11ii [ 0 ] = value
  return ( IIi11ii )
  if 61 - 61: IiII
  if 5 - 5: OOooOOo % iIii1I11I1II1 % O0 * i11iIiiIii / I1Ii111
 for iII11I1i in oo0oOoooOooO0 :
  if ( iII11I1i == "" ) : continue
  o00O = iII11I1i . find ( "]" )
  IIIIIi1 = iII11I1i [ 0 : o00O ]
  try : IIIIIi1 = int ( IIIIIi1 )
  except : return
  if 48 - 48: IiII * oO0o
  IIi11ii [ IIIIIi1 ] = iII11I1i [ o00O + 1 : : ]
  if 53 - 53: i1IIi * iIii1I11I1II1 . OOooOOo
 return ( IIi11ii )
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
def lisp_reassemble ( packet ) :
 i1IIiI1iII = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 52 - 52: o0oOOo0O0Ooo % I11i * I11i / iIii1I11I1II1
 if 77 - 77: OoOoOO00
 if 67 - 67: OoooooooOO / OoooooooOO + IiII - ooOoO0o
 if 72 - 72: Ii1I
 if ( i1IIiI1iII == 0 or i1IIiI1iII == 0x4000 ) : return ( packet )
 if 21 - 21: ooOoO0o + iII111i
 if 39 - 39: o0oOOo0O0Ooo % I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo
 if 78 - 78: OoO0O00 / o0oOOo0O0Ooo / O0 % OOooOOo % i1IIi
 if 78 - 78: o0oOOo0O0Ooo - oO0o . II111iiii
 iiIiiiIii11i1 = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 ii1i111 = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 67 - 67: iII111i + I11i - OoO0O00 . OOooOOo * iIii1I11I1II1
 Ii1iIi1iIIIII = ( i1IIiI1iII & 0x2000 == 0 and ( i1IIiI1iII & 0x1fff ) != 0 )
 iIiiI11II11i = [ ( i1IIiI1iII & 0x1fff ) * 8 , ii1i111 - 20 , packet , Ii1iIi1iIIIII ]
 if 50 - 50: OoooooooOO / I1Ii111 % I1ii11iIi11i . O0 / i11iIiiIii
 if 87 - 87: II111iiii + OoOoOO00 + I1Ii111 % ooOoO0o / i1IIi - Oo0Ooo
 if 84 - 84: iII111i - II111iiii * i11iIiiIii - IiII * IiII / OoooooooOO
 if 18 - 18: IiII / O0 / I1ii11iIi11i
 if 47 - 47: oO0o / iIii1I11I1II1
 if 45 - 45: OoOoOO00 * o0oOOo0O0Ooo / I1ii11iIi11i * iII111i - I1ii11iIi11i
 if 48 - 48: Ii1I / OoO0O00
 if 45 - 45: O0 * OoO0O00 / I11i . II111iiii
 if ( i1IIiI1iII == 0x2000 ) :
  iiI1iiIiiiI1I , i111I1 = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  iiI1iiIiiiI1I = socket . ntohs ( iiI1iiIiiiI1I )
  i111I1 = socket . ntohs ( i111I1 )
  if ( i111I1 not in [ 4341 , 8472 , 4789 ] and iiI1iiIiiiI1I != 4341 ) :
   lisp_reassembly_queue [ iiIiiiIii11i1 ] = [ ]
   iIiiI11II11i [ 2 ] = None
   if 20 - 20: I11i - IiII
   if 75 - 75: i11iIiiIii + I11i % I11i . I1Ii111
   if 58 - 58: o0oOOo0O0Ooo * II111iiii + o0oOOo0O0Ooo . I1IiiI
   if 25 - 25: o0oOOo0O0Ooo * I11i
   if 70 - 70: OOooOOo
   if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
 if ( iiIiiiIii11i1 not in lisp_reassembly_queue ) :
  lisp_reassembly_queue [ iiIiiiIii11i1 ] = [ ]
  if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
  if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
  if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
  if 63 - 63: I1IiiI
  if 20 - 20: oO0o + OoOoOO00
 queue = lisp_reassembly_queue [ iiIiiiIii11i1 ]
 if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
 if 4 - 4: OOooOOo % oO0o
 if 18 - 18: Ii1I * I11i
 if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
 if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
 if ( len ( queue ) == 1 and queue [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( iiIiiiIii11i1 ) . zfill ( 4 ) ) )
  if 56 - 56: Oo0Ooo . I1ii11iIi11i - i11iIiiIii / iIii1I11I1II1 . ooOoO0o
  return ( None )
  if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
  if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
  if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
  if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
  if 66 - 66: I1IiiI . Oo0Ooo - oO0o
 queue . append ( iIiiI11II11i )
 queue = sorted ( queue )
 if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
 if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
 if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
 if 68 - 68: OoOoOO00 - iII111i - I1IiiI
 iI1ii11Ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iI1ii11Ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 I1I1ii1Ii = iI1ii11Ii . print_address_no_iid ( )
 iI1ii11Ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 Oooo0o0Oo00o = iI1ii11Ii . print_address_no_iid ( )
 iI1ii11Ii = red ( "{} -> {}" . format ( I1I1ii1Ii , Oooo0o0Oo00o ) , False )
 if 59 - 59: iIii1I11I1II1 / II111iiii % IiII - i11iIiiIii
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if iIiiI11II11i [ 2 ] == None else "" , iI1ii11Ii , lisp_hex_string ( iiIiiiIii11i1 ) . zfill ( 4 ) ,
 # I1Ii111
 # I1IiiI . O0 - I1Ii111 - OoO0O00
 lisp_hex_string ( i1IIiI1iII ) . zfill ( 4 ) ) )
 if 45 - 45: OoooooooOO - I11i - I1IiiI . oO0o - IiII
 if 96 - 96: I11i . I1IiiI * iII111i / IiII - I1Ii111
 if 59 - 59: O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
 if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
 if ( queue [ 0 ] [ 0 ] != 0 or queue [ - 1 ] [ 3 ] == False ) : return ( None )
 O0OoOOOooO0Oo = queue [ 0 ]
 for oo0O00o0O0Oo in queue [ 1 : : ] :
  i1IIiI1iII = oo0O00o0O0Oo [ 0 ]
  i11iiiIiIiIi , ii1iII1Ii1ii1 = O0OoOOOooO0Oo [ 0 ] , O0OoOOOooO0Oo [ 1 ]
  if ( i11iiiIiIiIi + ii1iII1Ii1ii1 != i1IIiI1iII ) : return ( None )
  O0OoOOOooO0Oo = oo0O00o0O0Oo
  if 75 - 75: I11i % II111iiii + Oo0Ooo * II111iiii + Oo0Ooo
 lisp_reassembly_queue . pop ( iiIiiiIii11i1 )
 if 75 - 75: iIii1I11I1II1 % I11i . i11iIiiIii
 if 23 - 23: i1IIi + I1Ii111 / IiII * O0 - I1Ii111
 if 90 - 90: Oo0Ooo / Ii1I
 if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
 if 77 - 77: OoO0O00 / OOooOOo
 packet = queue [ 0 ] [ 2 ]
 for oo0O00o0O0Oo in queue [ 1 : : ] : packet += oo0O00o0O0Oo [ 2 ] [ 20 : : ]
 if 97 - 97: OoOoOO00 / Ii1I * I1IiiI - Oo0Ooo % O0
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( iiIiiiIii11i1 ) . zfill ( 4 ) , len ( packet ) ) )
 if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
 if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
 if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
 if 93 - 93: O0
 if 11 - 11: OoooooooOO . I1ii11iIi11i + I1ii11iIi11i
 iI = socket . htons ( len ( packet ) )
 i111ii1II11ii = packet [ 0 : 2 ] + struct . pack ( "H" , iI ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 73 - 73: OoooooooOO
 if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
 i111ii1II11ii = lisp_ip_checksum ( i111ii1II11ii )
 return ( i111ii1II11ii + packet [ 20 : : ] )
 if 100 - 100: II111iiii + oO0o
 if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
 if 42 - 42: oO0o + OoO0O00
 if 16 - 16: Ii1I
 if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
 if 84 - 84: OOooOOo
 if 78 - 78: O0 % O0
 if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 O00oO000Oo0 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_decap ) : return ( O00oO000Oo0 )
 if 41 - 41: iII111i / Ii1I
 O00oO000Oo0 = addr . print_address_no_iid ( )
 if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_decap ) : return ( O00oO000Oo0 )
 if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 if 24 - 24: IiII / Oo0Ooo
 if 90 - 90: ooOoO0o . OOooOOo - Ii1I
 if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
 if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
 for O0ooo0o0 in lisp_crypto_keys_by_rloc_decap :
  I1II1I1I = O0ooo0o0 . split ( ":" )
  if ( len ( I1II1I1I ) == 1 ) : continue
  I1II1I1I = I1II1I1I [ 0 ] if len ( I1II1I1I ) == 2 else ":" . join ( I1II1I1I [ 0 : - 1 ] )
  if ( I1II1I1I == O00oO000Oo0 ) :
   O0o0O0 = lisp_crypto_keys_by_rloc_decap [ O0ooo0o0 ]
   lisp_crypto_keys_by_rloc_decap [ O00oO000Oo0 ] = O0o0O0
   return ( O00oO000Oo0 )
   if 20 - 20: IiII - oO0o / OoOoOO00 * ooOoO0o
   if 88 - 88: I11i + OoOoOO00
 return ( None )
 if 47 - 47: oO0o * ooOoO0o . OOooOOo * IiII - OoooooooOO
 if 79 - 79: O0 + I1ii11iIi11i
 if 82 - 82: ooOoO0o * ooOoO0o * OoooooooOO
 if 98 - 98: II111iiii
 if 38 - 38: oO0o % OoooooooOO * I1Ii111 * Oo0Ooo % I1ii11iIi11i
 if 61 - 61: OoooooooOO - OoooooooOO / II111iiii
 if 10 - 10: II111iiii - OoO0O00 / II111iiii % Ii1I - OoOoOO00
 if 90 - 90: I11i + II111iiii - oO0o - ooOoO0o / ooOoO0o / i11iIiiIii
 if 80 - 80: I1ii11iIi11i % O0 / II111iiii + iII111i
 if 22 - 22: Oo0Ooo + ooOoO0o . OOooOOo % Oo0Ooo . IiII
 if 34 - 34: Ii1I . OoOoOO00 - OOooOOo * Oo0Ooo - ooOoO0o . oO0o
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 iiIII1i11iIi1 = addr + ":" + str ( port )
 if 93 - 93: iII111i + OOooOOo . OoooooooOO . I1Ii111 . O0
 if ( lisp_i_am_rtr ) :
  if ( addr in lisp_rloc_probe_list ) : return ( addr )
  if 46 - 46: i11iIiiIii
  if 26 - 26: I11i * Oo0Ooo % OoO0O00 + Oo0Ooo - I1ii11iIi11i
  if 74 - 74: i1IIi + OoO0O00 . II111iiii + I1Ii111
  if 59 - 59: Ii1I . i11iIiiIii . o0oOOo0O0Ooo * iIii1I11I1II1 . OoOoOO00 . II111iiii
  if 67 - 67: OoO0O00 - Oo0Ooo + OOooOOo / OoOoOO00 + OOooOOo
  if 18 - 18: Oo0Ooo % OoOoOO00 % i1IIi
  for oO00OOoOOoO in list ( lisp_nat_state_info . values ( ) ) :
   for oOO0O000OOo0 in oO00OOoOOoO :
    if ( addr == oOO0O000OOo0 . address ) : return ( iiIII1i11iIi1 )
    if 66 - 66: OoOoOO00 % II111iiii
    if 16 - 16: i11iIiiIii - I1IiiI + ooOoO0o * oO0o
  return ( addr )
  if 30 - 30: II111iiii / o0oOOo0O0Ooo
 return ( iiIII1i11iIi1 )
 if 57 - 57: I11i / I1ii11iIi11i . I11i
 if 68 - 68: OoOoOO00 + O0 . I1IiiI
 if 26 - 26: I1ii11iIi11i
 if 98 - 98: Oo0Ooo
 if 72 - 72: oO0o + OoooooooOO . O0 + IiII
 if 49 - 49: i1IIi - i11iIiiIii + II111iiii + Ii1I / OoO0O00
 if 34 - 34: I1ii11iIi11i * i11iIiiIii
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 6 - 6: I1ii11iIi11i + I1IiiI / OoooooooOO % I11i * Oo0Ooo
 if 20 - 20: Oo0Ooo
 if 85 - 85: I1Ii111
 if 98 - 98: OoO0O00 - IiII % iIii1I11I1II1 . OoOoOO00 + i1IIi + OoooooooOO
 if 29 - 29: I1ii11iIi11i * I1Ii111 - i1IIi * i11iIiiIii * iIii1I11I1II1 % I11i
 if 73 - 73: OoO0O00 . I1IiiI / o0oOOo0O0Ooo
 if 12 - 12: I11i * i11iIiiIii - O0 * o0oOOo0O0Ooo - IiII + I1IiiI
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
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
def lisp_is_rloc_probe ( packet , device , rr ) :
 ii11 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == 17 )
 if ( ii11 == False ) : return ( [ packet , None , None , None ] )
 if 61 - 61: Ii1I * Oo0Ooo * I1Ii111 % I11i + iII111i % oO0o
 iiI1iiIiiiI1I = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 i111I1 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 o0oOoooOo0O0 = ( socket . htons ( LISP_CTRL_PORT ) in [ iiI1iiIiiiI1I , i111I1 ] )
 if ( o0oOoooOo0O0 == False ) : return ( [ packet , None , None , None ] )
 if 18 - 18: iII111i . i1IIi . i11iIiiIii . OOooOOo
 if ( rr == 0 ) :
  II1iii1I1 = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( II1iii1I1 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  II1iii1I1 = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
  if ( II1iii1I1 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  II1iii1I1 = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( II1iii1I1 == False ) :
   II1iii1I1 = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
   if ( II1iii1I1 == False ) : return ( [ packet , None , None , None ] )
   if 15 - 15: Ii1I - I11i % II111iiii % OoooooooOO * OoooooooOO
   if 100 - 100: OoOoOO00 / o0oOOo0O0Ooo / O0 / OoO0O00
   if 23 - 23: Ii1I + i11iIiiIii % IiII
   if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
   if 49 - 49: O0
   if 72 - 72: I1Ii111
 OO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 OO . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 96 - 96: II111iiii / OOooOOo % i1IIi / Oo0Ooo
 if 22 - 22: I1IiiI % iIii1I11I1II1 % I1ii11iIi11i
 if 68 - 68: iII111i + I11i
 if 61 - 61: oO0o . I1Ii111
 if ( OO . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 74 - 74: O0 . Ii1I - iII111i % IiII + II111iiii
 if 71 - 71: oO0o + Ii1I % oO0o
 if 17 - 17: I1Ii111 % I1Ii111 * o0oOOo0O0Ooo
 if 84 - 84: I1Ii111 + iII111i . i1IIi / O0 / I1Ii111 + o0oOOo0O0Ooo
 OO = OO . print_address_no_iid ( )
 I1I1I1 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 i1i = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 70 - 70: O0 % ooOoO0o - iII111i + oO0o
 I1I1 = bold ( "Receive(pcap-{})" . format ( device ) , False )
 o0OoO0 = bold ( "from " + OO , False )
 III1ii = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( I1I1 , len ( packet ) , o0OoO0 , I1I1I1 , III1ii ) )
 if 12 - 12: I1Ii111 - OoO0O00 % II111iiii % ooOoO0o / II111iiii % OoOoOO00
 return ( [ packet , OO , I1I1I1 , i1i ] )
 if 74 - 74: iII111i . OOooOOo * Ii1I / Oo0Ooo . OoO0O00 . I11i
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
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 91 - 91: i11iIiiIii
 ii1I11Iii = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 35 - 35: OoOoOO00 * I1Ii111 / Oo0Ooo - i1IIi - IiII + OOooOOo
 lisp_write_to_dp_socket ( ii1I11Iii )
 return
 if 96 - 96: Oo0Ooo + I1ii11iIi11i . O0
 if 62 - 62: i1IIi % OoooooooOO % OoooooooOO
 if 53 - 53: O0 * oO0o
 if 22 - 22: OOooOOo % Oo0Ooo % ooOoO0o - O0 + i1IIi
 if 67 - 67: OoO0O00 / I1IiiI - IiII + iII111i - iII111i
 if 4 - 4: IiII . Ii1I . IiII % OoO0O00
 if 12 - 12: OoOoOO00 + O0 / O0 . i1IIi
 if 58 - 58: IiII . iII111i % O0 . Ii1I * Oo0Ooo
def lisp_external_data_plane ( ) :
 I1IIIi = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( getoutput ( I1IIIi ) != "" ) : return ( True )
 if 54 - 54: OoO0O00 % OOooOOo - OoO0O00 . Oo0Ooo % i1IIi
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 95 - 95: iII111i . OoooooooOO . o0oOOo0O0Ooo / II111iiii - OoooooooOO / I1Ii111
 if 11 - 11: II111iiii / iII111i . oO0o / ooOoO0o / OOooOOo + OoO0O00
 if 37 - 37: iIii1I11I1II1 * O0
 if 64 - 64: I1Ii111 - II111iiii + oO0o % ooOoO0o * oO0o
 if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
 if 27 - 27: OoOoOO00 . I11i / OoOoOO00
 if 96 - 96: OoO0O00 - I1IiiI
 if 73 - 73: I1IiiI - o0oOOo0O0Ooo - I1Ii111
 if 34 - 34: iIii1I11I1II1 - i1IIi + OoO0O00 % Oo0Ooo + i1IIi
 if 46 - 46: I1IiiI
 if 82 - 82: iII111i . i1IIi
 if 38 - 38: Ii1I . I1IiiI . I1ii11iIi11i
 if 26 - 26: O0 - II111iiii * I1Ii111 - OoOoOO00
 if 96 - 96: I11i * Oo0Ooo / OOooOOo - IiII
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 75 - 75: OoooooooOO - O0
 iii11OOoOoOO0 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 40 - 40: OOooOOo - Ii1I * I1ii11iIi11i * OoooooooOO + II111iiii / ooOoO0o
 if ( do_clear == False ) :
  Iii11iiIiIii = iii11OOoOoOO0 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , Iii11iiIiIii )
  if 8 - 8: OoooooooOO . IiII - I1Ii111 + I1ii11iIi11i + I11i
  if 42 - 42: oO0o
 lisp_write_to_dp_socket ( iii11OOoOoOO0 )
 return
 if 72 - 72: i1IIi . OoO0O00
 if 95 - 95: OoOoOO00 + Ii1I
 if 48 - 48: Ii1I % IiII + OoO0O00 . IiII
 if 42 - 42: Ii1I
 if 70 - 70: I11i
 if 82 - 82: O0
 if 58 - 58: II111iiii . O0 - OoO0O00 - IiII
 if 4 - 4: i11iIiiIii + i11iIiiIii / O0
 if 46 - 46: I11i % ooOoO0o - Ii1I
 if 25 - 25: O0 / i11iIiiIii . O0
 if 24 - 24: I1ii11iIi11i - i11iIiiIii / iII111i . Oo0Ooo / I1ii11iIi11i
 if 92 - 92: I11i % OoooooooOO
 if 14 - 14: i11iIiiIii * i11iIiiIii * OoOoOO00
 if 84 - 84: OOooOOo % I1Ii111 + I11i / I1IiiI . iII111i
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( "entries" not in msg ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 78 - 78: oO0o . Oo0Ooo
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 18 - 18: IiII
  if 35 - 35: OoooooooOO / i1IIi - OoO0O00 + Oo0Ooo - o0oOOo0O0Ooo
 for msg in msg [ "entries" ] :
  if ( "eid-prefix" not in msg ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 100 - 100: II111iiii % i11iIiiIii % oO0o + O0
  oOOoo = msg [ "eid-prefix" ]
  if 46 - 46: OoO0O00 / I1IiiI - Oo0Ooo . o0oOOo0O0Ooo . Oo0Ooo % I11i
  if ( "instance-id" not in msg ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 43 - 43: IiII - O0 + I1Ii111 % OoooooooOO % OoO0O00 / I1Ii111
  i1I1iI = int ( msg [ "instance-id" ] )
  if 48 - 48: I1ii11iIi11i . i1IIi % i1IIi - iII111i * o0oOOo0O0Ooo + IiII
  if 45 - 45: II111iiii . II111iiii + I1IiiI / I1Ii111 . OoO0O00 - o0oOOo0O0Ooo
  if 20 - 20: ooOoO0o % oO0o
  if 28 - 28: i1IIi . II111iiii + O0 / O0 % OoOoOO00 + OOooOOo
  o0Ooo0Oooo0o = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
  o0Ooo0Oooo0o . store_prefix ( oOOoo )
  I1I1i1I11I = lisp_map_cache_lookup ( None , o0Ooo0Oooo0o )
  if ( I1I1i1I11I == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( oOOoo ) )
   if 24 - 24: OoooooooOO
   continue
   if 11 - 11: i11iIiiIii / iIii1I11I1II1 % ooOoO0o + OOooOOo
   if 73 - 73: OoOoOO00 + OoooooooOO + iIii1I11I1II1 + II111iiii * iIii1I11I1II1 - OoOoOO00
  if ( "rlocs" not in msg ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( oOOoo ) )
   if 71 - 71: O0 * OOooOOo . I1IiiI . I1Ii111 * I11i
   continue
   if 45 - 45: O0 . O0 . II111iiii * ooOoO0o
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 2 - 2: OoO0O00 . o0oOOo0O0Ooo
  iIIIII111i1 = msg [ "rlocs" ]
  if 81 - 81: i1IIi % OOooOOo - OoO0O00 - Oo0Ooo
  if 19 - 19: i1IIi
  if 97 - 97: OoO0O00 + i11iIiiIii % I1IiiI * Ii1I
  if 89 - 89: IiII % i11iIiiIii + OoO0O00 . oO0o / I1IiiI . Ii1I
  for I1I1I1Ii in iIIIII111i1 :
   if ( "rloc" not in I1I1I1Ii ) : continue
   if 19 - 19: O0 % OoooooooOO / Oo0Ooo
   o00oO = I1I1I1Ii [ "rloc" ]
   if ( o00oO == "no-address" ) : continue
   if 12 - 12: I1ii11iIi11i . iII111i - iII111i - OOooOOo - iIii1I11I1II1
   iIIiI11 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   iIIiI11 . store_address ( o00oO )
   if 50 - 50: I1IiiI - iIii1I11I1II1 . iII111i - Ii1I / I1Ii111 + iII111i
   iIIoOo = I1I1i1I11I . get_rloc ( iIIiI11 )
   if ( iIIoOo == None ) : continue
   if 46 - 46: OOooOOo + iII111i % Oo0Ooo * iII111i % OoooooooOO * IiII
   if 27 - 27: I1IiiI + I1IiiI + I1ii11iIi11i - oO0o * OOooOOo
   if 53 - 53: I1ii11iIi11i / OoooooooOO * iIii1I11I1II1
   if 4 - 4: I1IiiI . iIii1I11I1II1 + OOooOOo / IiII . o0oOOo0O0Ooo . I11i
   O0ooO0OOoo = 0 if ( "packet-count" not in I1I1I1Ii ) else I1I1I1Ii [ "packet-count" ]
   if 29 - 29: OoO0O00 + iIii1I11I1II1 * iII111i * OOooOOo + I1ii11iIi11i
   i1III1I = 0 if ( "byte-count" not in I1I1I1Ii ) else I1I1I1Ii [ "byte-count" ]
   if 97 - 97: i1IIi / I1ii11iIi11i / OoO0O00
   iIiIIIIIii = 0 if ( "seconds-last-packet" not in I1I1I1Ii ) else I1I1I1Ii [ "seconds-last-packet" ]
   if 12 - 12: OOooOOo + iIii1I11I1II1 % I1Ii111 + OOooOOo
   if 19 - 19: OoO0O00 / I1IiiI - o0oOOo0O0Ooo - i1IIi + I1ii11iIi11i * OoooooooOO
   iIIoOo . stats . packet_count += O0ooO0OOoo
   iIIoOo . stats . byte_count += i1III1I
   iIIoOo . stats . last_increment = lisp_get_timestamp ( ) - iIiIIIIIii
   if 74 - 74: I1Ii111 . I11i / Oo0Ooo
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( O0ooO0OOoo , i1III1I ,
 iIiIIIIIii , oOOoo , o00oO ) )
   if 88 - 88: oO0o % OoO0O00 - i11iIiiIii % I1Ii111 / O0 * IiII
   if 99 - 99: o0oOOo0O0Ooo . ooOoO0o / i11iIiiIii
   if 44 - 44: IiII + OOooOOo % OoO0O00 . OoooooooOO * O0
   if 72 - 72: i1IIi - iII111i * I1IiiI % O0 - I11i * O0
   if 78 - 78: I1IiiI - OoO0O00 / Ii1I . i1IIi
  if ( I1I1i1I11I . group . is_null ( ) and I1I1i1I11I . has_ttl_elapsed ( ) ) :
   oOOoo = green ( I1I1i1I11I . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( oOOoo ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , I1I1i1I11I . eid , None )
   if 30 - 30: IiII
   if 21 - 21: i1IIi . iII111i - I1IiiI
 return
 if 28 - 28: IiII / Ii1I - i1IIi - OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo
 if 77 - 77: OoooooooOO - Oo0Ooo - OoOoOO00 / I11i / O0 . i11iIiiIii
 if 27 - 27: I1Ii111 * O0
 if 9 - 9: i1IIi - Oo0Ooo - i11iIiiIii / iIii1I11I1II1 . i1IIi
 if 2 - 2: I11i + II111iiii - I11i / oO0o / I11i
 if 73 - 73: IiII % I1Ii111 . OoOoOO00
 if 96 - 96: I1IiiI / ooOoO0o / iIii1I11I1II1
 if 91 - 91: Ii1I . I11i
 if 87 - 87: Oo0Ooo / IiII * OOooOOo + I1ii11iIi11i . I11i
 if 56 - 56: oO0o + oO0o % o0oOOo0O0Ooo + OOooOOo . II111iiii + i11iIiiIii
 if 45 - 45: iIii1I11I1II1 / o0oOOo0O0Ooo * OoooooooOO - Oo0Ooo
 if 77 - 77: II111iiii
 if 8 - 8: I1IiiI * II111iiii % I1ii11iIi11i
 if 88 - 88: Oo0Ooo . oO0o + OoOoOO00 % OoooooooOO
 if 81 - 81: OoooooooOO . I1Ii111 + OoO0O00 % I1Ii111
 if 49 - 49: oO0o . oO0o % oO0o / Oo0Ooo
 if 62 - 62: ooOoO0o . i1IIi % OoO0O00 - I1ii11iIi11i - IiII
 if 57 - 57: i1IIi - II111iiii - O0 . iII111i + OoO0O00
 if 67 - 67: OOooOOo * iII111i / iIii1I11I1II1 / I1ii11iIi11i
 if 10 - 10: OoooooooOO % I1ii11iIi11i * i1IIi . iII111i
 if 96 - 96: II111iiii % i11iIiiIii - Oo0Ooo
 if 70 - 70: O0 * iIii1I11I1II1 - IiII * I11i / Ii1I + i11iIiiIii
 if 26 - 26: II111iiii - I11i % I11i / ooOoO0o + Oo0Ooo
 if 91 - 91: I1IiiI % Ii1I - OOooOOo - Oo0Ooo / I1IiiI / OoO0O00
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 40 - 40: OoooooooOO
 if 71 - 71: OOooOOo
 if 88 - 88: O0
 if 44 - 44: II111iiii - IiII / I1IiiI + ooOoO0o % iII111i - iII111i
 if 53 - 53: OoooooooOO
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  ii1I11Iii = "stats%{}" . format ( json . dumps ( msg ) )
  ii1I11Iii = lisp_command_ipc ( ii1I11Iii , "lisp-itr" )
  lisp_ipc ( ii1I11Iii , lisp_ipc_socket , "lisp-etr" )
  return
  if 41 - 41: i1IIi - oO0o
  if 41 - 41: I11i
  if 92 - 92: i11iIiiIii
  if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
  if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
  if 77 - 77: i1IIi
  if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
  if 65 - 65: O0 / OoOoOO00
 ii1I11Iii = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( ii1I11Iii , msg ) )
 if 77 - 77: OoO0O00
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 17 - 17: i1IIi
 iIi11I1 = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 91 - 91: OoO0O00 % I1IiiI % I1ii11iIi11i % iIii1I11I1II1 + II111iiii
 for ii1iIIiii1Ii in iIi11I1 :
  O0ooO0OOoo = 0 if ( ii1iIIiii1Ii not in msg ) else msg [ ii1iIIiii1Ii ] [ "packet-count" ]
  lisp_decap_stats [ ii1iIIiii1Ii ] . packet_count += O0ooO0OOoo
  if 29 - 29: I1ii11iIi11i % O0 % o0oOOo0O0Ooo
  i1III1I = 0 if ( ii1iIIiii1Ii not in msg ) else msg [ ii1iIIiii1Ii ] [ "byte-count" ]
  lisp_decap_stats [ ii1iIIiii1Ii ] . byte_count += i1III1I
  if 99 - 99: ooOoO0o . o0oOOo0O0Ooo - O0 * I1Ii111 . i11iIiiIii / iIii1I11I1II1
  iIiIIIIIii = 0 if ( ii1iIIiii1Ii not in msg ) else msg [ ii1iIIiii1Ii ] [ "seconds-last-packet" ]
  if 40 - 40: iIii1I11I1II1 + oO0o / iIii1I11I1II1 - i1IIi % OoO0O00
  lisp_decap_stats [ ii1iIIiii1Ii ] . last_increment = lisp_get_timestamp ( ) - iIiIIIIIii
  if 22 - 22: OOooOOo
 return
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
 if 28 - 28: i1IIi . oO0o . IiII + Oo0Ooo . Oo0Ooo . i1IIi
 if 34 - 34: Oo0Ooo + IiII / i1IIi
 if 33 - 33: i1IIi
 if 26 - 26: ooOoO0o - Oo0Ooo * II111iiii - Oo0Ooo
 if 15 - 15: OoO0O00 - oO0o . OoOoOO00 / O0 * oO0o
 if 45 - 45: O0
 if 89 - 89: IiII - IiII % o0oOOo0O0Ooo * Oo0Ooo % ooOoO0o
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 iIii111I1I1 , OO = punt_socket . recvfrom ( 4000 )
 if 46 - 46: IiII . i11iIiiIii + OOooOOo + I11i . O0
 ooOoO = json . loads ( iIii111I1I1 )
 if ( type ( ooOoO ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( OO ) )
  if 97 - 97: II111iiii . IiII . I1Ii111 % i11iIiiIii
  return
  if 51 - 51: oO0o
 OoO0 = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( OoO0 , OO , ooOoO ) )
 if 62 - 62: I1ii11iIi11i . oO0o
 if ( "type" not in ooOoO ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 19 - 19: I1ii11iIi11i / I1IiiI
  if 47 - 47: O0 * IiII % Ii1I % o0oOOo0O0Ooo
  if 97 - 97: I1ii11iIi11i / OoooooooOO / o0oOOo0O0Ooo
  if 78 - 78: Ii1I
  if 5 - 5: i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
 if ( ooOoO [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( ooOoO , lisp_send_sockets , lisp_ephem_port )
  return
  if 57 - 57: IiII
 if ( ooOoO [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( ooOoO , punt_socket )
  return
  if 89 - 89: I1ii11iIi11i - I1Ii111 + o0oOOo0O0Ooo
  if 62 - 62: I1ii11iIi11i + OoooooooOO * OOooOOo
  if 49 - 49: i1IIi - I11i * II111iiii
  if 4 - 4: o0oOOo0O0Ooo + o0oOOo0O0Ooo
  if 57 - 57: I1IiiI * OOooOOo . i11iIiiIii * oO0o - OoOoOO00
 if ( ooOoO [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 35 - 35: O0
  if 65 - 65: Oo0Ooo
  if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * OoooooooOO . o0oOOo0O0Ooo
  if 90 - 90: i11iIiiIii . I1IiiI + ooOoO0o * OoooooooOO * OoooooooOO + oO0o
  if 77 - 77: OOooOOo * OoOoOO00
 if ( ooOoO [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 75 - 75: Oo0Ooo * Oo0Ooo - IiII - OoOoOO00 / i11iIiiIii + I1Ii111
 if ( "interface" not in ooOoO ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( OO ) )
  if 57 - 57: i11iIiiIii / oO0o
  return
  if 37 - 37: o0oOOo0O0Ooo + OoOoOO00 - i1IIi . Oo0Ooo
  if 3 - 3: ooOoO0o % OoooooooOO / I1Ii111 + oO0o - O0
  if 72 - 72: oO0o * OoO0O00
  if 89 - 89: OoooooooOO . OOooOOo
  if 96 - 96: o0oOOo0O0Ooo + OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo * i11iIiiIii + OOooOOo
 ooo = ooOoO [ "interface" ]
 if ( ooo == "" ) :
  i1I1iI = int ( ooOoO [ "instance-id" ] )
  if ( i1I1iI == - 1 ) : return
 else :
  i1I1iI = lisp_get_interface_instance_id ( ooo , None )
  if 16 - 16: IiII / I1Ii111 . II111iiii * I11i
  if 33 - 33: I1ii11iIi11i / Oo0Ooo % i11iIiiIii
  if 37 - 37: Oo0Ooo - I1Ii111 - IiII / oO0o % I1IiiI / I1Ii111
  if 80 - 80: iII111i - oO0o % i1IIi * iIii1I11I1II1 . oO0o
  if 86 - 86: Ii1I
 IIiIiiI1Iii = None
 if ( "source-eid" in ooOoO ) :
  OoO00o = ooOoO [ "source-eid" ]
  IIiIiiI1Iii = lisp_address ( LISP_AFI_NONE , OoO00o , 0 , i1I1iI )
  if ( IIiIiiI1Iii . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( OoO00o ) )
   return
   if 36 - 36: i11iIiiIii % i11iIiiIii
   if 91 - 91: Oo0Ooo + I1Ii111 % iII111i
 Oo0oo = None
 if ( "dest-eid" in ooOoO ) :
  i1iI1I = ooOoO [ "dest-eid" ]
  Oo0oo = lisp_address ( LISP_AFI_NONE , i1iI1I , 0 , i1I1iI )
  if ( Oo0oo . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( i1iI1I ) )
   return
   if 42 - 42: iII111i - iII111i
   if 93 - 93: I11i * iIii1I11I1II1
   if 89 - 89: II111iiii . O0
   if 28 - 28: I1ii11iIi11i * IiII
   if 34 - 34: o0oOOo0O0Ooo . OOooOOo
   if 61 - 61: I1IiiI / i1IIi % oO0o * OoO0O00 - II111iiii
   if 2 - 2: I1IiiI . ooOoO0o
   if 82 - 82: O0 / oO0o
 if ( IIiIiiI1Iii ) :
  oOO = green ( IIiIiiI1Iii . print_address ( ) , False )
  i1I = lisp_db_for_lookups . lookup_cache ( IIiIiiI1Iii , False )
  if ( i1I != None ) :
   if 27 - 27: ooOoO0o + i11iIiiIii * o0oOOo0O0Ooo
   if 10 - 10: OOooOOo * OoooooooOO
   if 1 - 1: iII111i . I1ii11iIi11i - ooOoO0o + OoO0O00 . OoooooooOO
   if 71 - 71: I1ii11iIi11i
   if 59 - 59: I1Ii111 + OoO0O00 + II111iiii
   if ( i1I . dynamic_eid_configured ( ) ) :
    OoO00OooO0 = lisp_allow_dynamic_eid ( ooo , IIiIiiI1Iii )
    if ( OoO00OooO0 != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( i1I , IIiIiiI1Iii , ooo , OoO00OooO0 )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( oOO , ooo ) )
     if 12 - 12: I1Ii111 % I1ii11iIi11i - I1Ii111 + I11i
     if 62 - 62: I1Ii111 % I11i % IiII - ooOoO0o . oO0o - OoooooooOO
     if 14 - 14: OOooOOo + Oo0Ooo % i1IIi + iIii1I11I1II1
  else :
   lprint ( "Punt from non-EID source {}" . format ( oOO ) )
   if 64 - 64: OoOoOO00 / Ii1I * Oo0Ooo - I1ii11iIi11i
   if 9 - 9: i11iIiiIii % Oo0Ooo + IiII + Ii1I . ooOoO0o / i1IIi
   if 40 - 40: I1Ii111 + I1IiiI - Ii1I
   if 27 - 27: i1IIi
   if 66 - 66: iII111i - ooOoO0o / i11iIiiIii + I1ii11iIi11i - Ii1I
   if 9 - 9: O0
 if ( Oo0oo ) :
  I1I1i1I11I = lisp_map_cache_lookup ( IIiIiiI1Iii , Oo0oo )
  if ( I1I1i1I11I == None or lisp_mr_or_pubsub ( I1I1i1I11I . action ) ) :
   if 96 - 96: Oo0Ooo . II111iiii
   if 41 - 41: I1ii11iIi11i % o0oOOo0O0Ooo
   if 86 - 86: O0 * OoOoOO00 * O0 / O0
   if 50 - 50: OoooooooOO
   if 42 - 42: ooOoO0o / OoooooooOO
   if ( lisp_rate_limit_map_request ( Oo0oo ) ) : return
   if 31 - 31: II111iiii + Ii1I . iIii1I11I1II1 * OoO0O00 - O0 - OoO0O00
   O0o0oo = ( I1I1i1I11I and I1I1i1I11I . action == LISP_SEND_PUBSUB_ACTION )
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 IIiIiiI1Iii , Oo0oo , None , O0o0oo )
  else :
   oOO = green ( Oo0oo . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( oOO ) )
   if 12 - 12: oO0o + Ii1I
   if 7 - 7: iII111i / Oo0Ooo - OoO0O00 + I1Ii111 * II111iiii * ooOoO0o
 return
 if 80 - 80: oO0o - i1IIi / I11i . II111iiii % O0 % I11i
 if 70 - 70: iIii1I11I1II1 * i1IIi * OOooOOo - Oo0Ooo % i1IIi
 if 60 - 60: o0oOOo0O0Ooo . OOooOOo % II111iiii - I1ii11iIi11i
 if 4 - 4: OOooOOo % ooOoO0o
 if 39 - 39: Ii1I
 if 67 - 67: iIii1I11I1II1 - OOooOOo
 if 47 - 47: OOooOOo - OOooOOo * I1Ii111
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 iIiiI11II11i = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( iIiiI11II11i )
 return ( [ True , jdata ] )
 if 24 - 24: I1ii11iIi11i
 if 37 - 37: II111iiii - iIii1I11I1II1 / o0oOOo0O0Ooo . O0 + II111iiii
 if 9 - 9: o0oOOo0O0Ooo
 if 47 - 47: Ii1I * I1Ii111 / II111iiii
 if 73 - 73: ooOoO0o
 if 53 - 53: IiII . Oo0Ooo
 if 54 - 54: i11iIiiIii % ooOoO0o % I1Ii111 + o0oOOo0O0Ooo
 if 2 - 2: IiII
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 25 - 25: OoOoOO00 . OoO0O00 * o0oOOo0O0Ooo . OoooooooOO - Oo0Ooo + I1IiiI
 if 82 - 82: OoO0O00 - Ii1I * I11i * o0oOOo0O0Ooo
 if 17 - 17: OoooooooOO + I1Ii111
 if 91 - 91: iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 98 - 98: o0oOOo0O0Ooo % II111iiii * IiII - i11iIiiIii * oO0o
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 15 - 15: O0 - II111iiii - Oo0Ooo . I1ii11iIi11i % OoO0O00
 if 63 - 63: o0oOOo0O0Ooo / OoOoOO00 % I1ii11iIi11i % I11i
 if 58 - 58: O0 + iII111i
 if 66 - 66: i1IIi . O0 . i1IIi - iIii1I11I1II1 - ooOoO0o % I1ii11iIi11i
 if 96 - 96: i1IIi + oO0o - OoOoOO00 - OoOoOO00
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 13 - 13: I11i
 if 52 - 52: iII111i . OoOoOO00 * iIii1I11I1II1 . iII111i * IiII
 if 52 - 52: iII111i + iII111i
 if 35 - 35: I1Ii111 * oO0o + Ii1I / I1IiiI + O0 - I11i
 if 42 - 42: o0oOOo0O0Ooo
 if 89 - 89: o0oOOo0O0Ooo
 if 99 - 99: I1ii11iIi11i + Oo0Ooo
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 oOOoo = eid . print_address ( )
 if ( oOOoo in db . dynamic_eids ) :
  db . dynamic_eids [ oOOoo ] . last_packet = lisp_get_timestamp ( )
  return
  if 20 - 20: OoO0O00 / iII111i
  if 62 - 62: i1IIi % iIii1I11I1II1 + OoOoOO00 - I1IiiI . I1ii11iIi11i
  if 92 - 92: i11iIiiIii * o0oOOo0O0Ooo . Oo0Ooo
  if 15 - 15: o0oOOo0O0Ooo * IiII . iII111i % O0 . iIii1I11I1II1
  if 34 - 34: OOooOOo / iII111i * iIii1I11I1II1 + i11iIiiIii
 OOOoooOo00O = lisp_dynamic_eid ( )
 OOOoooOo00O . dynamic_eid . copy_address ( eid )
 OOOoooOo00O . interface = routed_interface
 OOOoooOo00O . last_packet = lisp_get_timestamp ( )
 OOOoooOo00O . get_timeout ( routed_interface )
 db . dynamic_eids [ oOOoo ] = OOOoooOo00O
 if 37 - 37: I11i + o0oOOo0O0Ooo . o0oOOo0O0Ooo
 II11I1iiiIIII = ""
 if ( input_interface != routed_interface ) :
  II11I1iiiIIII = ", routed-interface " + routed_interface
  if 19 - 19: IiII / OoooooooOO / OoO0O00 . OoooooooOO / I1IiiI / iII111i
  if 5 - 5: II111iiii + I1Ii111
 O0Ooo00O00Oo = green ( oOOoo , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( O0Ooo00O00Oo , input_interface , II11I1iiiIIII , OOOoooOo00O . timeout ) )
 if 44 - 44: I1IiiI * IiII / I11i - OOooOOo + II111iiii / oO0o
 if 26 - 26: OoO0O00 - OoOoOO00 / O0 / Ii1I
 if 20 - 20: I11i * OoooooooOO
 if 81 - 81: I11i * oO0o - i1IIi - Ii1I / I11i
 if 48 - 48: oO0o
 ii1I11Iii = "learn%{}%{}" . format ( oOOoo , routed_interface )
 ii1I11Iii = lisp_command_ipc ( ii1I11Iii , "lisp-itr" )
 lisp_ipc ( ii1I11Iii , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 42 - 42: iII111i
 if 86 - 86: iIii1I11I1II1 + OoOoOO00 / II111iiii
 if 14 - 14: OOooOOo . Oo0Ooo + OoO0O00 + I1Ii111 + Ii1I + i11iIiiIii
 if 71 - 71: iIii1I11I1II1 . I11i
 if 80 - 80: o0oOOo0O0Ooo + iIii1I11I1II1 + I1ii11iIi11i / iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i + oO0o / I1ii11iIi11i . OoOoOO00
 if 53 - 53: i1IIi
 if 70 - 70: I1Ii111
 if 80 - 80: O0 + I1ii11iIi11i
def lisp_itr_nat_probe ( rloc , rloc_name , lisp_ipc_listen_socket ) :
 o00oO = rloc . print_address_no_iid ( )
 if 74 - 74: II111iiii % oO0o * Oo0Ooo / iIii1I11I1II1
 if 81 - 81: II111iiii + OoOoOO00 * O0
 if 64 - 64: iIii1I11I1II1 * Ii1I
 if 5 - 5: I11i . I11i / i1IIi - o0oOOo0O0Ooo % Oo0Ooo
 ii1I11Iii = "nat%{}%{}" . format ( o00oO , rloc_name )
 ii1I11Iii = lisp_command_ipc ( ii1I11Iii , "lisp-itr" )
 lisp_ipc ( ii1I11Iii , lisp_ipc_listen_socket , "lisp-etr" )
 return
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
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 30 - 30: Oo0Ooo . II111iiii + OoooooooOO % OoO0O00 * ooOoO0o * iIii1I11I1II1
 if 91 - 91: OoooooooOO
 if 86 - 86: iII111i / OoooooooOO - I1ii11iIi11i
 if 63 - 63: ooOoO0o % Ii1I * I1IiiI
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 48 - 48: iII111i - iII111i - o0oOOo0O0Ooo + ooOoO0o - o0oOOo0O0Ooo / Ii1I
 OO0ooOo0o = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 43 - 43: I1IiiI + Ii1I
 for OoOOooOOoo in lisp_crypto_keys_by_rloc_decap :
  if 37 - 37: OoOoOO00 - OoooooooOO . ooOoO0o - IiII % iIii1I11I1II1 . iIii1I11I1II1
  if 64 - 64: OoOoOO00 + iII111i % I1Ii111 - OOooOOo + O0
  if 83 - 83: I1Ii111 + I1Ii111
  if 43 - 43: oO0o * i1IIi * Ii1I . iIii1I11I1II1 % o0oOOo0O0Ooo
  if ( OoOOooOOoo . find ( addr_str ) == - 1 ) : continue
  if 97 - 97: I1IiiI . i1IIi * OoOoOO00 / OOooOOo
  if 50 - 50: II111iiii . OoO0O00
  if 60 - 60: I11i . iIii1I11I1II1
  if 41 - 41: II111iiii / I1IiiI
  if ( OoOOooOOoo == addr_str ) : continue
  if 2 - 2: IiII / OoOoOO00 + I11i
  if 3 - 3: OoooooooOO + Oo0Ooo + OOooOOo
  if 20 - 20: Ii1I - oO0o - OoO0O00 + I1ii11iIi11i % OoO0O00 . i1IIi
  if 2 - 2: ooOoO0o * IiII . Ii1I
  iIiiI11II11i = lisp_crypto_keys_by_rloc_decap [ OoOOooOOoo ]
  if ( iIiiI11II11i == OO0ooOo0o ) : continue
  if 69 - 69: IiII % i1IIi
  if 17 - 17: o0oOOo0O0Ooo . OoO0O00 * ooOoO0o * II111iiii - OoooooooOO % iII111i
  if 47 - 47: I1IiiI * iIii1I11I1II1 - I11i - o0oOOo0O0Ooo
  if 47 - 47: IiII + OoO0O00 % ooOoO0o - iII111i - IiII - oO0o
  oo00O = iIiiI11II11i [ 1 ]
  if ( packet_icv != oo00O . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( OoOOooOOoo , False ) ) )
   continue
   if 9 - 9: i11iIiiIii - iIii1I11I1II1 + OOooOOo * oO0o % OoO0O00 * I1ii11iIi11i
   if 11 - 11: iIii1I11I1II1 . iIii1I11I1II1 * OoooooooOO * iII111i / oO0o . iIii1I11I1II1
  lprint ( "Changing decap crypto key to {}" . format ( red ( OoOOooOOoo , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = iIiiI11II11i
  if 2 - 2: i11iIiiIii + Ii1I / iII111i
 return
 if 21 - 21: II111iiii + i11iIiiIii % Ii1I . iIii1I11I1II1
 if 66 - 66: iII111i / oO0o - OoO0O00 . Oo0Ooo
 if 31 - 31: IiII % O0
 if 46 - 46: iIii1I11I1II1 - OoooooooOO . oO0o % iIii1I11I1II1 / i1IIi + Ii1I
 if 5 - 5: I1ii11iIi11i % II111iiii
 if 17 - 17: i11iIiiIii - II111iiii / O0 % OoO0O00 . Oo0Ooo + IiII
 if 60 - 60: I11i % I1IiiI
 if 99 - 99: oO0o . OOooOOo % iII111i * Ii1I
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 98 - 98: Oo0Ooo * O0 + i1IIi
 if 41 - 41: i1IIi % OoO0O00 * iIii1I11I1II1
 if 2 - 2: I1ii11iIi11i * iII111i . iIii1I11I1II1 * Oo0Ooo
 if 34 - 34: i11iIiiIii % O0 . I1IiiI / ooOoO0o + OoO0O00
 if 28 - 28: Ii1I / iIii1I11I1II1
 if 41 - 41: iIii1I11I1II1
 if 57 - 57: I1Ii111 * o0oOOo0O0Ooo - o0oOOo0O0Ooo * I11i
 if 89 - 89: Ii1I % O0
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 ooO0o = dns_name . split ( "." )
 ooO0o = "." . join ( ooO0o [ 1 : : ] )
 return ( ooO0o == lisp_decent_dns_suffix )
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
def lisp_get_decent_eid_string ( eid ) :
 oOOoo = eid . print_prefix ( )
 if 89 - 89: oO0o / iII111i + OOooOOo
 i11I1 = None
 oooo0oo0o00 = 0
 for OOo0oOOO0ooO , o0OoO0Oo0oo0000O in lisp_decent_lookup_prefixes . items ( ) :
  if ( eid . is_more_specific ( OOo0oOOO0ooO ) ) :
   if ( i11I1 == None or OOo0oOOO0ooO . mask_len > oooo0oo0o00 ) :
    oooo0oo0o00 = OOo0oOOO0ooO . mask_len
    i11I1 = o0OoO0Oo0oo0000O
    if 16 - 16: Ii1I . I1ii11iIi11i
    if 28 - 28: iII111i
    if 74 - 74: Ii1I + I1IiiI * iII111i / i11iIiiIii - ooOoO0o * OoooooooOO
    if 98 - 98: I1IiiI
    if 85 - 85: OoooooooOO * i1IIi * O0 * OoooooooOO . IiII
    if 22 - 22: ooOoO0o
    if 44 - 44: I1ii11iIi11i + IiII + IiII * I1ii11iIi11i - OoooooooOO / I1Ii111
 if ( i11I1 == None ) : return ( oOOoo )
 if 3 - 3: I1ii11iIi11i + o0oOOo0O0Ooo * I11i / Oo0Ooo
 if 31 - 31: i11iIiiIii % OoO0O00 - oO0o / o0oOOo0O0Ooo % O0
 if 53 - 53: iIii1I11I1II1 * I1ii11iIi11i
 if 46 - 46: OOooOOo % OoOoOO00 * iII111i
 oOooO00Oo00OO = copy . deepcopy ( eid )
 oOooO00Oo00OO . mask_len = i11I1
 oOooO00Oo00OO . zero_host_bits ( )
 return ( oOooO00Oo00OO . print_prefix ( ) )
 if 97 - 97: i1IIi % oO0o . I1IiiI
 if 36 - 36: o0oOOo0O0Ooo + iIii1I11I1II1
 if 54 - 54: ooOoO0o - I1Ii111 + I11i * Oo0Ooo - oO0o + I1ii11iIi11i
 if 34 - 34: O0 % iIii1I11I1II1 - OoOoOO00
 if 16 - 16: I11i . I1IiiI / IiII + OoOoOO00 . OoooooooOO
 if 91 - 91: ooOoO0o * OOooOOo - iII111i . I1IiiI * oO0o . IiII
 if 46 - 46: O0 / I1Ii111 . OOooOOo * OOooOOo % OoOoOO00 . O0
 if 31 - 31: O0 % OoO0O00 % O0 + iII111i - iIii1I11I1II1
 if 71 - 71: I1IiiI / Ii1I + IiII * OoooooooOO
 if 39 - 39: OoO0O00
 if 60 - 60: iII111i . iII111i - ooOoO0o / i1IIi
def lisp_get_decent_index ( eid ) :
 if 68 - 68: oO0o + I11i + Oo0Ooo / OOooOOo . II111iiii - iIii1I11I1II1
 if 81 - 81: I1ii11iIi11i
 if 39 - 39: II111iiii
 if 60 - 60: OoOoOO00 % Oo0Ooo
 if 19 - 19: iIii1I11I1II1 + I1IiiI + O0 * Ii1I
 oOOoo = lisp_get_decent_eid_string ( eid )
 oOO = oOOoo . encode ( )
 iiiIiIi1i1ii = hmac . new ( b"lisp-decent" , oOO , hashlib . sha256 ) . hexdigest ( )
 if 6 - 6: I11i / OoooooooOO . i1IIi + OoO0O00 + Ii1I
 if 90 - 90: O0 * i1IIi . i1IIi * I1ii11iIi11i + I1ii11iIi11i / i1IIi
 if 52 - 52: O0 / iIii1I11I1II1 * IiII
 if 50 - 50: oO0o . Ii1I . OoooooooOO * o0oOOo0O0Ooo
 iI11111ii1 = os . getenv ( "LISP_DECENT_HASH_WIDTH" )
 if ( iI11111ii1 in [ "" , None ] ) :
  iI11111ii1 = 12
 else :
  iI11111ii1 = int ( iI11111ii1 )
  if ( iI11111ii1 > 32 ) :
   iI11111ii1 = 12
  else :
   iI11111ii1 *= 2
   if 55 - 55: I1Ii111 - OOooOOo - OoO0O00 . oO0o
   if 23 - 23: iII111i + OOooOOo
   if 39 - 39: oO0o * O0
 iIiOoOoo = iiiIiIi1i1ii [ 0 : iI11111ii1 ]
 o00O = int ( iIiOoOoo , 16 ) % lisp_decent_modulus
 if 13 - 13: ooOoO0o + I1ii11iIi11i % II111iiii / I1ii11iIi11i - oO0o + i1IIi
 lprint ( "LISP-Decent modulus {}, hash-width {}, mod-value {}, index {} for {}" . format ( lisp_decent_modulus , old_div ( iI11111ii1 , 2 ) , iIiOoOoo , o00O , oOOoo ) )
 if 1 - 1: Oo0Ooo * OoO0O00 . OoO0O00 - i1IIi
 if 21 - 21: ooOoO0o * OoO0O00 % Oo0Ooo
 return ( o00O )
 if 81 - 81: OoO0O00 + I1Ii111 . OoOoOO00 * I11i * O0
 if 9 - 9: Ii1I . i1IIi % iIii1I11I1II1
 if 72 - 72: i11iIiiIii + OOooOOo . I1Ii111 + Ii1I + OOooOOo
 if 72 - 72: II111iiii * iII111i + iII111i * oO0o
 if 68 - 68: I1ii11iIi11i / OoO0O00
 if 81 - 81: IiII % oO0o + IiII * OoO0O00 % I1IiiI
 if 72 - 72: OoooooooOO
def lisp_get_decent_dns_name ( eid ) :
 o00O = lisp_get_decent_index ( eid )
 return ( str ( o00O ) + "." + lisp_decent_dns_suffix )
 if 40 - 40: IiII + o0oOOo0O0Ooo + O0 . oO0o * iIii1I11I1II1 / OOooOOo
 if 60 - 60: iII111i - I11i
 if 12 - 12: o0oOOo0O0Ooo % i1IIi
 if 29 - 29: OOooOOo . OoooooooOO . iII111i % i1IIi + i11iIiiIii
 if 9 - 9: IiII
 if 29 - 29: I11i * II111iiii / I1ii11iIi11i
 if 49 - 49: iIii1I11I1II1 + I11i + IiII . I1IiiI
 if 32 - 32: I1Ii111 - o0oOOo0O0Ooo / i1IIi
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 o0Ooo0Oooo0o = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 o00O = lisp_get_decent_index ( o0Ooo0Oooo0o )
 return ( str ( o00O ) + "." + lisp_decent_dns_suffix )
 if 12 - 12: II111iiii % Oo0Ooo / Oo0Ooo . i1IIi % Ii1I
 if 21 - 21: II111iiii - o0oOOo0O0Ooo * OoO0O00 . OOooOOo
 if 65 - 65: o0oOOo0O0Ooo + I1IiiI
 if 21 - 21: I1Ii111
 if 74 - 74: iII111i
 if 51 - 51: O0 . II111iiii - OoooooooOO + ooOoO0o - o0oOOo0O0Ooo
 if 86 - 86: OOooOOo % i11iIiiIii / OoOoOO00
 if 72 - 72: I1IiiI . oO0o
 if 76 - 76: Ii1I - Oo0Ooo * II111iiii
 if 17 - 17: I1Ii111 * O0
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 8 - 8: i11iIiiIii / OoO0O00 / OOooOOo
 II1Ii = 28 if packet . inner_version == 4 else 48
 IIOo = packet . packet [ II1Ii : : ]
 oooO0OO = lisp_trace ( )
 if ( oooO0OO . decode ( IIOo ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 17 - 17: Ii1I % I1ii11iIi11i % iIii1I11I1II1 * Oo0Ooo - I11i
  if 92 - 92: oO0o
 oooOO000oO = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 41 - 41: i1IIi * IiII - i11iIiiIii / O0 + Oo0Ooo + ooOoO0o
 if 94 - 94: OoO0O00 . O0 + iIii1I11I1II1 . oO0o % oO0o
 if 7 - 7: I1ii11iIi11i * oO0o / OoOoOO00
 if 89 - 89: OoO0O00 / oO0o % I11i - I1ii11iIi11i . o0oOOo0O0Ooo
 if 46 - 46: i11iIiiIii
 if 99 - 99: i11iIiiIii / oO0o / OoOoOO00 / O0 * I1ii11iIi11i
 if ( oooOO000oO != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : oooOO000oO += ":{}" . format ( packet . encap_port )
  if 72 - 72: ooOoO0o - I1Ii111 - iIii1I11I1II1 . I1IiiI
  if 77 - 77: Oo0Ooo * OoO0O00
  if 67 - 67: OoOoOO00 . I1Ii111 / I1IiiI * II111iiii
  if 45 - 45: I1ii11iIi11i * o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo
  if 58 - 58: OOooOOo + O0
 iIiiI11II11i = { }
 iIiiI11II11i [ "n" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 19 - 19: o0oOOo0O0Ooo
 I1I1111I1Ii1 = packet . outer_source
 if ( I1I1111I1Ii1 . is_null ( ) ) : I1I1111I1Ii1 = lisp_myrlocs [ 0 ]
 iIiiI11II11i [ "sr" ] = I1I1111I1Ii1 . print_address_no_iid ( )
 if 12 - 12: ooOoO0o . Ii1I
 if 74 - 74: iIii1I11I1II1 % OOooOOo . OoOoOO00 . OoO0O00
 if 43 - 43: iIii1I11I1II1 * Ii1I
 if 3 - 3: IiII / Oo0Ooo . Oo0Ooo . oO0o / OoooooooOO
 if 9 - 9: Oo0Ooo % OOooOOo % I11i / o0oOOo0O0Ooo - II111iiii / iIii1I11I1II1
 if ( iIiiI11II11i [ "n" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  iIiiI11II11i [ "sr" ] += ":{}" . format ( packet . inner_sport )
  if 33 - 33: Oo0Ooo / oO0o * II111iiii + iIii1I11I1II1 + O0 . O0
  if 11 - 11: oO0o - OOooOOo
 iIiiI11II11i [ "hn" ] = lisp_hostname
 OoOOooOOoo = ed [ 0 ] + "ts"
 iIiiI11II11i [ OoOOooOOoo ] = lisp_get_timestamp ( )
 if 92 - 92: iIii1I11I1II1 + i1IIi + IiII . Ii1I
 if 81 - 81: I1Ii111 + I1ii11iIi11i . I1ii11iIi11i * IiII / Oo0Ooo + iIii1I11I1II1
 if 42 - 42: ooOoO0o . I11i / i11iIiiIii
 if 70 - 70: OOooOOo + I11i % i11iIiiIii + OoO0O00 / OoO0O00
 if 76 - 76: iIii1I11I1II1 + I1ii11iIi11i
 if 8 - 8: iIii1I11I1II1 / IiII / i1IIi % I1IiiI
 if ( oooOO000oO == "?" and iIiiI11II11i [ "n" ] == "ETR" ) :
  i1I = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( i1I != None and len ( i1I . rloc_set ) >= 1 ) :
   oooOO000oO = i1I . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 92 - 92: i11iIiiIii - oO0o
   if 62 - 62: O0 + O0 . Oo0Ooo + iIii1I11I1II1 + iII111i
 iIiiI11II11i [ "dr" ] = oooOO000oO
 if 97 - 97: oO0o - iIii1I11I1II1
 if 61 - 61: II111iiii / OOooOOo - oO0o
 if 19 - 19: O0
 if 60 - 60: I1ii11iIi11i * I1ii11iIi11i + I1Ii111 + o0oOOo0O0Ooo - OoO0O00
 if ( oooOO000oO == "?" and reason != None ) :
  iIiiI11II11i [ "dr" ] += " ({})" . format ( reason )
  if 75 - 75: o0oOOo0O0Ooo + i11iIiiIii % I1ii11iIi11i
  if 45 - 45: I1Ii111 % Ii1I . ooOoO0o
  if 99 - 99: I11i - OoOoOO00 % I11i / i1IIi
  if 55 - 55: o0oOOo0O0Ooo / ooOoO0o % I1IiiI / I1Ii111
  if 30 - 30: I11i % OoOoOO00 * O0
 if ( rloc_entry != None ) :
  iIiiI11II11i [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  iIiiI11II11i [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  iIiiI11II11i [ "lats" ] = rloc_entry . recent_rloc_probe_latencies
  if 32 - 32: iII111i - Oo0Ooo / Oo0Ooo + o0oOOo0O0Ooo + Ii1I + IiII
  if 100 - 100: Oo0Ooo + o0oOOo0O0Ooo % Oo0Ooo
  if 73 - 73: o0oOOo0O0Ooo + Ii1I
  if 62 - 62: OOooOOo
  if 91 - 91: iII111i . Ii1I - OoooooooOO / Ii1I / II111iiii - O0
  if 67 - 67: oO0o * i11iIiiIii / I1ii11iIi11i . I11i % OOooOOo
 IIiIiiI1Iii = packet . inner_source . print_address ( )
 Oo0oo = packet . inner_dest . print_address ( )
 if ( oooO0OO . packet_json == [ ] ) :
  oOo0oOOO = { }
  oOo0oOOO [ "se" ] = IIiIiiI1Iii
  oOo0oOOO [ "de" ] = Oo0oo
  oOo0oOOO [ "paths" ] = [ ]
  oooO0OO . packet_json . append ( oOo0oOOO )
  if 75 - 75: ooOoO0o - OOooOOo
  if 97 - 97: i11iIiiIii / I11i % II111iiii
  if 20 - 20: I1Ii111 + OoooooooOO . o0oOOo0O0Ooo - ooOoO0o
  if 61 - 61: i11iIiiIii + OoooooooOO
  if 7 - 7: I1IiiI * OoO0O00 * I1IiiI
  if 50 - 50: I1ii11iIi11i
 for oOo0oOOO in oooO0OO . packet_json :
  if ( oOo0oOOO [ "de" ] != Oo0oo ) : continue
  oOo0oOOO [ "paths" ] . append ( iIiiI11II11i )
  break
  if 88 - 88: IiII
  if 55 - 55: Oo0Ooo + OOooOOo + IiII
  if 55 - 55: O0 . I1Ii111 * I1ii11iIi11i * o0oOOo0O0Ooo - ooOoO0o
  if 17 - 17: OOooOOo
  if 66 - 66: O0 - i11iIiiIii * O0 / iII111i . I1Ii111 / IiII
  if 96 - 96: OoOoOO00 / i11iIiiIii - OoooooooOO / II111iiii * i1IIi
  if 82 - 82: iII111i
  if 55 - 55: OoOoOO00 + I1ii11iIi11i % ooOoO0o % I1Ii111 . i1IIi % OOooOOo
 iIi1 = False
 if ( len ( oooO0OO . packet_json ) == 1 and iIiiI11II11i [ "n" ] == "ETR" and
 oooO0OO . myeid ( packet . inner_dest ) ) :
  oOo0oOOO = { }
  oOo0oOOO [ "se" ] = Oo0oo
  oOo0oOOO [ "de" ] = IIiIiiI1Iii
  oOo0oOOO [ "paths" ] = [ ]
  oooO0OO . packet_json . append ( oOo0oOOO )
  iIi1 = True
  if 88 - 88: i1IIi . I11i - oO0o
  if 76 - 76: OOooOOo * ooOoO0o
  if 47 - 47: IiII - II111iiii / OoooooooOO * iIii1I11I1II1
  if 52 - 52: II111iiii
  if 66 - 66: O0 * I11i - I11i % Oo0Ooo * ooOoO0o
  if 42 - 42: iII111i / II111iiii + I1Ii111 + I1ii11iIi11i
 oooO0OO . print_trace ( )
 IIOo = oooO0OO . encode ( )
 if 57 - 57: IiII + iII111i - I1IiiI
 if 47 - 47: iIii1I11I1II1 % O0 / o0oOOo0O0Ooo . i1IIi * IiII
 if 56 - 56: I1Ii111
 if 49 - 49: i11iIiiIii . I1Ii111 / OoooooooOO * IiII
 if 25 - 25: OoO0O00
 if 55 - 55: I1ii11iIi11i . Ii1I - O0 * I1IiiI
 if 32 - 32: I11i . OoooooooOO * I11i - iII111i
 if 35 - 35: I1IiiI * I11i + I11i
 OOOo00O0 = oooO0OO . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "sr" ]
 if ( oooOO000oO == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( OOOo00O0 ) )
  oooO0OO . return_to_sender ( lisp_socket , OOOo00O0 , IIOo )
  return ( False )
  if 39 - 39: i11iIiiIii . IiII * i1IIi
  if 25 - 25: i11iIiiIii % ooOoO0o
  if 64 - 64: ooOoO0o + II111iiii - iII111i / O0 % ooOoO0o
  if 23 - 23: OOooOOo / IiII
  if 28 - 28: OoooooooOO * I1IiiI - OoOoOO00 + Oo0Ooo
  if 33 - 33: I11i - OOooOOo + Oo0Ooo - iII111i * iII111i
 oOoO0Oo0 = oooO0OO . packet_length ( )
 if 44 - 44: Oo0Ooo % OoOoOO00 / oO0o
 if 34 - 34: II111iiii + Ii1I + OoOoOO00
 if 9 - 9: I11i / oO0o * OoO0O00
 if 26 - 26: I1IiiI % OOooOOo * OoOoOO00
 if 14 - 14: I11i * Oo0Ooo . I1Ii111 * Ii1I . i11iIiiIii * I1ii11iIi11i
 if 11 - 11: oO0o + oO0o + o0oOOo0O0Ooo / iIii1I11I1II1 / I11i
 Oo0ooO = packet . packet [ 0 : II1Ii ]
 III1ii = struct . pack ( "HH" , socket . htons ( oOoO0Oo0 ) , 0 )
 Oo0ooO = Oo0ooO [ 0 : II1Ii - 4 ] + III1ii
 if ( packet . inner_version == 6 and iIiiI11II11i [ "n" ] == "ETR" and
 len ( oooO0OO . packet_json ) == 2 ) :
  ii11 = Oo0ooO [ II1Ii - 8 : : ] + IIOo
  ii11 = lisp_udp_checksum ( IIiIiiI1Iii , Oo0oo , ii11 )
  Oo0ooO = Oo0ooO [ 0 : II1Ii - 8 ] + ii11 [ 0 : 8 ]
  if 83 - 83: iII111i * OoO0O00 * II111iiii / OoO0O00 . oO0o
  if 51 - 51: iII111i - O0 . I1Ii111 / I11i + o0oOOo0O0Ooo . I1Ii111
  if 98 - 98: IiII * O0 - I1IiiI - iIii1I11I1II1
  if 81 - 81: i11iIiiIii - I1IiiI . I1Ii111
  if 68 - 68: I1ii11iIi11i / I1ii11iIi11i * O0 / OoOoOO00 + i1IIi
  if 71 - 71: oO0o % IiII
  if 77 - 77: i1IIi * o0oOOo0O0Ooo - Oo0Ooo / I1Ii111 - Ii1I * IiII
  if 51 - 51: OoO0O00 * IiII
  if 36 - 36: II111iiii + I11i - O0
 if ( iIi1 ) :
  if ( packet . inner_version == 4 ) :
   Oo0ooO = Oo0ooO [ 0 : 12 ] + Oo0ooO [ 16 : 20 ] + Oo0ooO [ 12 : 16 ] + Oo0ooO [ 22 : 24 ] + Oo0ooO [ 20 : 22 ] + Oo0ooO [ 24 : : ]
   if 24 - 24: I1Ii111 / OoOoOO00
  else :
   Oo0ooO = Oo0ooO [ 0 : 8 ] + Oo0ooO [ 24 : 40 ] + Oo0ooO [ 8 : 24 ] + Oo0ooO [ 42 : 44 ] + Oo0ooO [ 40 : 42 ] + Oo0ooO [ 44 : : ]
   if 10 - 10: I11i . OoO0O00 / O0 / oO0o / o0oOOo0O0Ooo / ooOoO0o
   if 30 - 30: Oo0Ooo
  oooOo = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = oooOo
  if 93 - 93: II111iiii - I1IiiI
  if 80 - 80: I11i . o0oOOo0O0Ooo % IiII - OoOoOO00 % OOooOOo / OoooooooOO
  if 57 - 57: OoooooooOO % o0oOOo0O0Ooo - iIii1I11I1II1 . OoooooooOO
  if 42 - 42: o0oOOo0O0Ooo % OoooooooOO * OoO0O00 - o0oOOo0O0Ooo
  if 83 - 83: i1IIi . i1IIi * ooOoO0o
  if 26 - 26: I1IiiI - IiII
  if 99 - 99: IiII * iII111i + i1IIi * I1Ii111
 II1Ii = 2 if packet . inner_version == 4 else 4
 oOOo0OO = 20 + oOoO0Oo0 if packet . inner_version == 4 else oOoO0Oo0
 i11iiIiI1IIii = struct . pack ( "H" , socket . htons ( oOOo0OO ) )
 Oo0ooO = Oo0ooO [ 0 : II1Ii ] + i11iiIiI1IIii + Oo0ooO [ II1Ii + 2 : : ]
 if 30 - 30: Ii1I / II111iiii . Oo0Ooo - i11iIiiIii % iIii1I11I1II1
 if 87 - 87: i11iIiiIii + i11iIiiIii + OoooooooOO - i1IIi
 if 83 - 83: OoO0O00 % IiII
 if 4 - 4: Oo0Ooo % II111iiii
 if ( packet . inner_version == 4 ) :
  I1 = struct . pack ( "H" , 0 )
  Oo0ooO = Oo0ooO [ 0 : 10 ] + I1 + Oo0ooO [ 12 : : ]
  i11iiIiI1IIii = lisp_ip_checksum ( Oo0ooO [ 0 : 20 ] )
  Oo0ooO = i11iiIiI1IIii + Oo0ooO [ 20 : : ]
  if 8 - 8: oO0o / iIii1I11I1II1 + OoooooooOO
  if 11 - 11: OOooOOo . O0 + IiII . i1IIi
  if 81 - 81: OoO0O00 - I11i - OoO0O00 + oO0o
  if 20 - 20: OoooooooOO - Oo0Ooo + I1Ii111 + OoooooooOO
  if 66 - 66: I1ii11iIi11i / oO0o % IiII + II111iiii % iII111i
 packet . packet = Oo0ooO + IIOo
 return ( True )
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
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 8 - 8: I11i / OoooooooOO % OoooooooOO . Oo0Ooo
 for iIiiI11II11i in lisp_glean_mappings :
  if ( "instance-id" in iIiiI11II11i ) :
   i1I1iI = eid . instance_id
   O0II11II1111 , O00ooO0OoOO0O = iIiiI11II11i [ "instance-id" ]
   if ( i1I1iI < O0II11II1111 or i1I1iI > O00ooO0OoOO0O ) : continue
   if 30 - 30: iII111i
  if ( "eid-prefix" in iIiiI11II11i ) :
   oOO = copy . deepcopy ( iIiiI11II11i [ "eid-prefix" ] )
   oOO . instance_id = eid . instance_id
   if ( eid . is_more_specific ( oOO ) == False ) : continue
   if 25 - 25: I11i % i1IIi + OOooOOo * Ii1I . i1IIi
  if ( "group-prefix" in iIiiI11II11i ) :
   if ( group == None ) : continue
   II11iIIii = copy . deepcopy ( iIiiI11II11i [ "group-prefix" ] )
   II11iIIii . instance_id = group . instance_id
   if ( group . is_more_specific ( II11iIIii ) == False ) : continue
   if 81 - 81: I11i % OoOoOO00 . Ii1I
  if ( "rloc-prefix" in iIiiI11II11i ) :
   if ( rloc != None and rloc . is_more_specific ( iIiiI11II11i [ "rloc-prefix" ] )
 == False ) : continue
   if 82 - 82: i1IIi / II111iiii
  return ( True , iIiiI11II11i [ "rloc-probe" ] , iIiiI11II11i [ "igmp-query" ] )
  if 40 - 40: II111iiii - I1Ii111 + Oo0Ooo / IiII
 return ( False , False , False )
 if 15 - 15: I1Ii111 + ooOoO0o / II111iiii . OoOoOO00 - I1Ii111
 if 59 - 59: Ii1I * iIii1I11I1II1 - iIii1I11I1II1 % I1Ii111 - OoO0O00 / I1IiiI
 if 89 - 89: I1Ii111 . OoO0O00
 if 52 - 52: OoO0O00 - iIii1I11I1II1
 if 52 - 52: OOooOOo + I1IiiI * Ii1I % OoooooooOO / I1Ii111
 if 74 - 74: iIii1I11I1II1
 if 82 - 82: OOooOOo
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 ooOoo000oO = geid . print_address ( )
 oOOO0oOOOoO00Ooo = seid . print_address_no_iid ( )
 OOo0oOO0o0oo0 = green ( "{}" . format ( oOOO0oOOOoO00Ooo ) , False )
 oOO = green ( "(*, {})" . format ( ooOoo000oO ) , False )
 I1I1 = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 94 - 94: OoO0O00 * I1Ii111 % oO0o . iIii1I11I1II1 . II111iiii
 if 38 - 38: OoOoOO00 + O0
 if 94 - 94: I1IiiI + oO0o * I1IiiI % I1IiiI + Oo0Ooo . OoOoOO00
 if 17 - 17: I1IiiI / OoO0O00 - iIii1I11I1II1
 I1I1i1I11I = lisp_map_cache_lookup ( seid , geid )
 if ( I1I1i1I11I == None ) :
  I1I1i1I11I = lisp_mapping ( "" , "" , [ ] )
  I1I1i1I11I . group . copy_address ( geid )
  I1I1i1I11I . eid . copy_address ( geid )
  I1I1i1I11I . eid . address = 0
  I1I1i1I11I . eid . mask_len = 0
  I1I1i1I11I . mapping_source . copy_address ( rloc )
  I1I1i1I11I . map_cache_ttl = LISP_IGMP_TTL
  I1I1i1I11I . gleaned = True
  I1I1i1I11I . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( oOO ) )
  if 91 - 91: iII111i / I1ii11iIi11i
  if 19 - 19: iIii1I11I1II1
  if 3 - 3: i11iIiiIii + Ii1I / I1Ii111
  if 74 - 74: II111iiii + I11i
  if 80 - 80: OOooOOo . oO0o / iIii1I11I1II1
  if 4 - 4: iII111i + I1IiiI
 iIIoOo = oO0OO = Ii1111iiIii = None
 if ( I1I1i1I11I . rloc_set != [ ] ) :
  iIIoOo = I1I1i1I11I . rloc_set [ 0 ]
  if ( iIIoOo . rle ) :
   oO0OO = iIIoOo . rle
   for IIi in oO0OO . rle_nodes :
    if ( IIi . rloc_name != oOOO0oOOOoO00Ooo ) : continue
    Ii1111iiIii = IIi
    break
    if 47 - 47: I1IiiI + i1IIi + I1ii11iIi11i / OOooOOo * i11iIiiIii % I1Ii111
    if 7 - 7: OoOoOO00 * iII111i * i11iIiiIii + OoOoOO00
    if 20 - 20: i1IIi % Ii1I / iIii1I11I1II1 / II111iiii
    if 16 - 16: I1IiiI % Ii1I
    if 30 - 30: i11iIiiIii / i1IIi % O0 - OoooooooOO - OOooOOo
    if 55 - 55: OoooooooOO % ooOoO0o % I1Ii111 - Oo0Ooo % OoooooooOO . I11i
    if 22 - 22: i11iIiiIii
 if ( iIIoOo == None ) :
  iIIoOo = lisp_rloc ( )
  I1I1i1I11I . rloc_set = [ iIIoOo ]
  iIIoOo . priority = 253
  iIIoOo . mpriority = 255
  I1I1i1I11I . build_best_rloc_set ( )
  if 39 - 39: oO0o / OoOoOO00 % iIii1I11I1II1 - OoOoOO00
 if ( oO0OO == None ) :
  oO0OO = lisp_rle ( geid . print_address ( ) )
  iIIoOo . rle = oO0OO
  if 29 - 29: I1ii11iIi11i - I11i . I1ii11iIi11i - o0oOOo0O0Ooo - OoooooooOO % OoO0O00
 if ( Ii1111iiIii == None ) :
  Ii1111iiIii = lisp_rle_node ( )
  Ii1111iiIii . rloc . rloc_name = oOOO0oOOOoO00Ooo
  oO0OO . rle_nodes . append ( Ii1111iiIii )
  oO0OO . build_rle_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( I1I1 , OOo0oOO0o0oo0 , oOO ) )
 elif ( rloc . is_exact_match ( Ii1111iiIii . rloc . rloc ) == False or
 port != Ii1111iiIii . rloc . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( I1I1 , OOo0oOO0o0oo0 , oOO ) )
  if 74 - 74: iIii1I11I1II1 / iII111i * OoO0O00 * iIii1I11I1II1 + i11iIiiIii
  if 90 - 90: II111iiii - oO0o - oO0o + I1IiiI
  if 36 - 36: OoooooooOO % OoooooooOO / OoO0O00 * I1IiiI
  if 55 - 55: O0 - O0
  if 32 - 32: I1IiiI + o0oOOo0O0Ooo + Oo0Ooo / OoO0O00 . I11i . Oo0Ooo
 Ii1111iiIii . store_translated_rloc ( rloc , port )
 if 32 - 32: I1Ii111 / i1IIi
 if 30 - 30: i11iIiiIii . II111iiii * Oo0Ooo + II111iiii - I1IiiI
 if 80 - 80: o0oOOo0O0Ooo - iII111i % i11iIiiIii % i11iIiiIii % OoooooooOO - IiII
 if 39 - 39: II111iiii / I1Ii111 + OoooooooOO + IiII + iIii1I11I1II1
 if 59 - 59: OoOoOO00 / II111iiii . Ii1I
 if ( igmp ) :
  OoO00OOooo00 = seid . print_address ( )
  if ( OoO00OOooo00 not in lisp_gleaned_groups ) :
   lisp_gleaned_groups [ OoO00OOooo00 ] = { }
   if 90 - 90: II111iiii
  lisp_gleaned_groups [ OoO00OOooo00 ] [ ooOoo000oO ] = lisp_get_timestamp ( )
  if 77 - 77: i11iIiiIii . i11iIiiIii - iIii1I11I1II1 + OOooOOo
  if 55 - 55: OoO0O00 + Oo0Ooo
  if 74 - 74: i1IIi - I11i - oO0o % I1IiiI
  if 57 - 57: Oo0Ooo / II111iiii + OoOoOO00
  if 67 - 67: IiII * IiII % oO0o - IiII * i11iIiiIii - i11iIiiIii
  if 27 - 27: i1IIi
  if 29 - 29: OOooOOo % I11i * Oo0Ooo
  if 92 - 92: OoOoOO00 / OoooooooOO % OoooooooOO + o0oOOo0O0Ooo
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 91 - 91: OoOoOO00 - iII111i / iII111i - OoO0O00
 if 97 - 97: Oo0Ooo / IiII % OOooOOo % Ii1I
 if 59 - 59: I1IiiI / Oo0Ooo / OoOoOO00
 if 79 - 79: O0 / ooOoO0o + OoOoOO00
 I1I1i1I11I = lisp_map_cache_lookup ( seid , geid )
 if ( I1I1i1I11I == None ) : return
 if 23 - 23: I11i
 IIiiiI = I1I1i1I11I . rloc_set [ 0 ] . rle
 if ( IIiiiI == None ) : return
 if 81 - 81: OoOoOO00 * ooOoO0o + OoOoOO00
 oOo = seid . print_address_no_iid ( )
 iIi1iII = False
 for Ii1111iiIii in IIiiiI . rle_nodes :
  if ( Ii1111iiIii . rloc . rloc_name == oOo ) :
   iIi1iII = True
   break
   if 7 - 7: I1ii11iIi11i - II111iiii
   if 100 - 100: OoO0O00 . I1IiiI / i1IIi + OOooOOo / IiII
 if ( iIi1iII == False ) : return
 if 48 - 48: i11iIiiIii % i1IIi + iIii1I11I1II1 . I1Ii111
 if 67 - 67: i11iIiiIii / o0oOOo0O0Ooo . i11iIiiIii . I1ii11iIi11i - O0
 if 76 - 76: i1IIi % OOooOOo
 if 37 - 37: Oo0Ooo - oO0o / II111iiii . o0oOOo0O0Ooo % OoOoOO00 % ooOoO0o
 IIiiiI . rle_nodes . remove ( Ii1111iiIii )
 IIiiiI . build_rle_forwarding_list ( )
 if 44 - 44: I11i / I1IiiI + I1Ii111 - O0 - ooOoO0o
 ooOoo000oO = geid . print_address ( )
 OoO00OOooo00 = seid . print_address ( )
 OOo0oOO0o0oo0 = green ( "{}" . format ( OoO00OOooo00 ) , False )
 oOO = green ( "(*, {})" . format ( ooOoo000oO ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( oOO , OOo0oOO0o0oo0 ) )
 if 57 - 57: I1IiiI * OOooOOo - Ii1I
 if 82 - 82: OoOoOO00
 if 78 - 78: ooOoO0o - I1IiiI % I1ii11iIi11i
 if 90 - 90: I1ii11iIi11i / II111iiii
 if ( OoO00OOooo00 in lisp_gleaned_groups ) :
  if ( ooOoo000oO in lisp_gleaned_groups [ OoO00OOooo00 ] ) :
   lisp_gleaned_groups [ OoO00OOooo00 ] . pop ( ooOoo000oO )
   if 92 - 92: i11iIiiIii
   if 35 - 35: O0 + i11iIiiIii . OoO0O00
   if 1 - 1: OoOoOO00 + o0oOOo0O0Ooo . Ii1I / II111iiii
   if 54 - 54: ooOoO0o + iIii1I11I1II1
   if 89 - 89: I1IiiI
   if 75 - 75: O0 / I1ii11iIi11i
 if ( IIiiiI . rle_nodes == [ ] ) :
  I1I1i1I11I . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( oOO ) )
  if 36 - 36: i1IIi - IiII - I1IiiI / I11i
  if 41 - 41: I1IiiI . OoooooooOO * oO0o - I1ii11iIi11i % IiII
  if 88 - 88: i11iIiiIii * ooOoO0o
  if 19 - 19: i1IIi / I1Ii111 % II111iiii
  if 4 - 4: o0oOOo0O0Ooo - OoO0O00 % i1IIi % OoooooooOO * oO0o - Oo0Ooo
  if 18 - 18: oO0o % Oo0Ooo / o0oOOo0O0Ooo + OOooOOo
  if 65 - 65: OOooOOo
  if 23 - 23: OoOoOO00
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 OoO00OOooo00 = seid . print_address ( )
 if ( OoO00OOooo00 not in lisp_gleaned_groups ) : return
 if 26 - 26: i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o + OoO0O00
 for oo0oOooo0O in lisp_gleaned_groups [ OoO00OOooo00 ] :
  lisp_geid . store_address ( oo0oOooo0O )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
  if 86 - 86: OoOoOO00 % i11iIiiIii . ooOoO0o + i1IIi + O0 - OOooOOo
  if 24 - 24: I11i - ooOoO0o + I1IiiI % O0 % iII111i * II111iiii
  if 35 - 35: oO0o - I11i - i1IIi
  if 83 - 83: ooOoO0o % OoooooooOO % Oo0Ooo * o0oOOo0O0Ooo * oO0o % i1IIi
  if 66 - 66: Ii1I . ooOoO0o / OoooooooOO - I1IiiI - iIii1I11I1II1 + OOooOOo
  if 33 - 33: Ii1I + I1IiiI - iII111i . OoooooooOO / I1ii11iIi11i
  if 64 - 64: OoO0O00 + OoO0O00
  if 2 - 2: ooOoO0o * IiII . ooOoO0o
  if 5 - 5: o0oOOo0O0Ooo - o0oOOo0O0Ooo
  if 40 - 40: OoO0O00 % I11i - OoOoOO00
  if 51 - 51: iIii1I11I1II1 . OOooOOo % I1ii11iIi11i
  if 46 - 46: OoOoOO00 - iIii1I11I1II1 * Oo0Ooo * OOooOOo + i1IIi / iII111i
  if 11 - 11: Oo0Ooo
  if 65 - 65: I1IiiI
  if 9 - 9: OOooOOo + I1Ii111 - O0
  if 95 - 95: oO0o
  if 45 - 45: Ii1I * oO0o / oO0o + o0oOOo0O0Ooo % OoOoOO00 % I11i
  if 78 - 78: OoO0O00 + I11i
  if 87 - 87: OOooOOo % I1ii11iIi11i - IiII . II111iiii . o0oOOo0O0Ooo
  if 9 - 9: Ii1I / oO0o + I11i . iII111i
  if 3 - 3: OoooooooOO + OoooooooOO * OOooOOo / O0
  if 81 - 81: i11iIiiIii - OoOoOO00
  if 80 - 80: iIii1I11I1II1 % OOooOOo + oO0o + II111iiii - I1ii11iIi11i
  if 44 - 44: OoooooooOO * iII111i
  if 26 - 26: OoooooooOO
  if 73 - 73: II111iiii . iII111i - iIii1I11I1II1 . i1IIi . I11i
  if 60 - 60: OoO0O00 + OoO0O00
  if 50 - 50: i1IIi
  if 33 - 33: oO0o - Ii1I - Oo0Ooo * IiII / OoooooooOO - OoooooooOO
  if 31 - 31: O0 - I11i
  if 25 - 25: Oo0Ooo * o0oOOo0O0Ooo . IiII
  if 74 - 74: OOooOOo % oO0o
  if 69 - 69: Oo0Ooo . oO0o + Oo0Ooo * IiII - OoooooooOO
  if 86 - 86: I11i % OoOoOO00 . oO0o % Ii1I - i11iIiiIii - Oo0Ooo
  if 5 - 5: Oo0Ooo * oO0o . OoO0O00 % i11iIiiIii
  if 64 - 64: OOooOOo / Ii1I - Ii1I . I1Ii111 / I1IiiI
  if 12 - 12: i1IIi
  if 65 - 65: I1IiiI + i1IIi * II111iiii / II111iiii + OoooooooOO
  if 100 - 100: IiII / i1IIi + I11i
  if 57 - 57: Ii1I % II111iiii
  if 33 - 33: ooOoO0o - OOooOOo % OoOoOO00
  if 56 - 56: i1IIi . iII111i - i11iIiiIii
  if 65 - 65: I1Ii111 * O0 % Ii1I . iII111i . ooOoO0o . ooOoO0o
  if 9 - 9: I1IiiI / Oo0Ooo . iIii1I11I1II1 % o0oOOo0O0Ooo . OoOoOO00
  if 45 - 45: I1ii11iIi11i
  if 64 - 64: iIii1I11I1II1 % Oo0Ooo % I1Ii111 . iII111i . I11i * OOooOOo
  if 38 - 38: O0 - i1IIi % OoO0O00
  if 38 - 38: I1Ii111 % oO0o . OoOoOO00 % Oo0Ooo / oO0o % IiII
  if 15 - 15: iIii1I11I1II1 * Oo0Ooo * iIii1I11I1II1 % II111iiii / I1IiiI . OoO0O00
  if 81 - 81: IiII * OoOoOO00
  if 84 - 84: oO0o
  if 29 - 29: I1ii11iIi11i - i11iIiiIii + ooOoO0o % OoO0O00 + I11i
  if 34 - 34: O0 % iIii1I11I1II1 - I1Ii111 / oO0o
  if 83 - 83: I1IiiI / OOooOOo
  if 12 - 12: o0oOOo0O0Ooo / I11i . I1Ii111 % OOooOOo - II111iiii + iII111i
  if 42 - 42: O0 . i1IIi . iIii1I11I1II1 + O0 - i11iIiiIii * Oo0Ooo
  if 48 - 48: i11iIiiIii
  if 64 - 64: OoO0O00 - OOooOOo % I11i * I11i
  if 24 - 24: OoOoOO00 % O0
  if 99 - 99: IiII . i1IIi - Oo0Ooo * i1IIi / Ii1I + I1ii11iIi11i
  if 46 - 46: OOooOOo - o0oOOo0O0Ooo
  if 48 - 48: Oo0Ooo
  if 22 - 22: IiII . I1ii11iIi11i / oO0o - OoooooooOO % OoooooooOO + ooOoO0o
  if 34 - 34: iII111i * iII111i / OoO0O00 . ooOoO0o - OoOoOO00
  if 14 - 14: I1Ii111 . I11i . IiII * I1Ii111 / O0 . i11iIiiIii
  if 19 - 19: OoooooooOO / I11i % I1Ii111 % Ii1I + OOooOOo * ooOoO0o
  if 30 - 30: OOooOOo . Ii1I % i11iIiiIii . OoooooooOO . Ii1I
  if 28 - 28: OoO0O00 . iIii1I11I1II1 * I11i
  if 97 - 97: i1IIi . O0 + I11i * IiII
  if 53 - 53: oO0o
  if 9 - 9: iIii1I11I1II1
  if 18 - 18: OoO0O00
  if 93 - 93: iIii1I11I1II1
  if 84 - 84: II111iiii % I1IiiI / O0 + iII111i + OoooooooOO
  if 7 - 7: I1IiiI - OoOoOO00 - i1IIi * OoO0O00 . IiII / i1IIi
  if 50 - 50: II111iiii % I1Ii111 . Oo0Ooo
  if 97 - 97: iIii1I11I1II1 % ooOoO0o . i1IIi - Ii1I
  if 60 - 60: O0 * OoO0O00
  if 91 - 91: II111iiii . Oo0Ooo / I11i + Oo0Ooo . I1ii11iIi11i % iII111i
  if 2 - 2: IiII . I11i
  if 38 - 38: i11iIiiIii % OoOoOO00 / ooOoO0o * o0oOOo0O0Ooo * OoO0O00
  if 69 - 69: I11i / O0
  if 100 - 100: o0oOOo0O0Ooo + I1Ii111 / Ii1I * OOooOOo + I1Ii111 + II111iiii
  if 57 - 57: ooOoO0o % O0 % I11i + OoO0O00 + OoO0O00 - OoOoOO00
  if 92 - 92: OoooooooOO - II111iiii
  if 68 - 68: ooOoO0o / i11iIiiIii + i11iIiiIii + OOooOOo - I1ii11iIi11i
  if 83 - 83: iIii1I11I1II1 / II111iiii + i11iIiiIii - Oo0Ooo % OoO0O00
  if 5 - 5: iIii1I11I1II1 - I1Ii111
  if 83 - 83: Ii1I . I1Ii111 % o0oOOo0O0Ooo * i11iIiiIii - I1IiiI
  if 41 - 41: OOooOOo . iII111i
  if 82 - 82: O0 * o0oOOo0O0Ooo / oO0o
  if 6 - 6: I1Ii111 . o0oOOo0O0Ooo + I11i
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 79 - 79: Oo0Ooo
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 11 - 11: i1IIi
def lisp_process_igmp_packet ( packet ) :
 OO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 OO . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 OO = bold ( "from {}" . format ( OO . print_address_no_iid ( ) ) , False )
 if 14 - 14: i1IIi
 I1I1 = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( I1I1 , len ( packet ) , OO ,
 lisp_format_packet ( packet ) ) )
 if 3 - 3: I1Ii111
 if 82 - 82: iIii1I11I1II1 * iII111i - O0
 if 8 - 8: OoOoOO00 - I1Ii111 * OOooOOo
 if 97 - 97: OoOoOO00
 OoOO000o0oOO = ( struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ] & 0x0f ) * 4
 if 11 - 11: iII111i . OoO0O00 / oO0o + OOooOOo
 if 86 - 86: o0oOOo0O0Ooo - IiII % II111iiii + Ii1I / I1Ii111 % OoOoOO00
 if 45 - 45: Oo0Ooo / IiII - OoOoOO00
 if 63 - 63: OoOoOO00 . OoooooooOO
 OoooOOoo = packet [ OoOO000o0oOO : : ]
 II1i1IiIi = struct . unpack ( "B" , OoooOOoo [ 0 : 1 ] ) [ 0 ]
 if 99 - 99: iII111i % IiII
 if 43 - 43: o0oOOo0O0Ooo . II111iiii
 if 40 - 40: iII111i / iII111i + IiII
 if 31 - 31: OoooooooOO + Oo0Ooo / I11i . II111iiii
 if 13 - 13: OoooooooOO % I1Ii111 / iII111i
 oo0oOooo0O = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oo0oOooo0O . address = socket . ntohl ( struct . unpack ( "II" , OoooOOoo [ : 8 ] ) [ 1 ] )
 ooOoo000oO = oo0oOooo0O . print_address_no_iid ( )
 if 19 - 19: II111iiii
 if ( II1i1IiIi == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( ooOoo000oO ) )
  return ( [ ] )
  if 93 - 93: I1IiiI
  if 7 - 7: o0oOOo0O0Ooo / OoooooooOO * II111iiii % OoO0O00 + II111iiii
 iiIiII1 = ( II1i1IiIi in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( iiIiII1 == False ) :
  oOOo0o0oOooO = "{} ({})" . format ( II1i1IiIi , igmp_types [ II1i1IiIi ] ) if ( II1i1IiIi in igmp_types ) else II1i1IiIi
  if 28 - 28: Oo0Ooo
  lprint ( "IGMP type {} not supported" . format ( oOOo0o0oOooO ) )
  return ( [ ] )
  if 15 - 15: OoooooooOO
  if 58 - 58: Oo0Ooo . i11iIiiIii * ooOoO0o % I1ii11iIi11i
 if ( len ( OoooOOoo ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 73 - 73: OoOoOO00 + O0 / OoooooooOO + I11i - iIii1I11I1II1 % OoOoOO00
  if 1 - 1: I11i * i1IIi . II111iiii / OoO0O00 * OoOoOO00 - Oo0Ooo
  if 32 - 32: IiII % II111iiii * I1ii11iIi11i + II111iiii * O0 + OoO0O00
  if 29 - 29: Oo0Ooo . I1ii11iIi11i
  if 5 - 5: I1IiiI - iIii1I11I1II1 . IiII . i1IIi
 if ( II1i1IiIi == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( ooOoo000oO , False ) ) )
  lisp_update_igmp_database ( None , ooOoo000oO , False )
  return ( [ [ None , ooOoo000oO , False ] ] )
  if 55 - 55: i1IIi + I1IiiI - O0 - Oo0Ooo / O0
 if ( II1i1IiIi in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( II1i1IiIi == 0x12 ) else 2 , bold ( ooOoo000oO , False ) ) )
  if 14 - 14: iIii1I11I1II1 * OOooOOo % I11i * II111iiii
  if 4 - 4: iII111i + II111iiii + IiII . Oo0Ooo + iII111i
  if 22 - 22: oO0o - OoooooooOO . IiII
  if 77 - 77: I1ii11iIi11i . OOooOOo
  if 26 - 26: OoooooooOO + i11iIiiIii
  if ( ooOoo000oO . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   return ( [ ] )
   if 11 - 11: i11iIiiIii - OoooooooOO + i1IIi / Oo0Ooo . o0oOOo0O0Ooo
   if 5 - 5: OOooOOo - iIii1I11I1II1 - OoooooooOO % ooOoO0o
  lisp_update_igmp_database ( None , ooOoo000oO , True )
  return ( [ [ None , ooOoo000oO , True ] ] )
  if 52 - 52: o0oOOo0O0Ooo
  if 91 - 91: o0oOOo0O0Ooo % II111iiii . I1IiiI * ooOoO0o
  if 23 - 23: I1ii11iIi11i . O0 . OOooOOo - OoO0O00
  if 28 - 28: OoOoOO00 / ooOoO0o % OoOoOO00
  if 27 - 27: II111iiii / O0 % o0oOOo0O0Ooo % I11i * oO0o + I1Ii111
 oO0Oo0o0 = oo0oOooo0O . address
 OoooOOoo = OoooOOoo [ 8 : : ]
 if 79 - 79: OOooOOo + iIii1I11I1II1 . II111iiii * O0 - I1Ii111 % iIii1I11I1II1
 OOOO = "BBHI"
 o00ooo = struct . calcsize ( OOOO )
 oOoOO0oOOOO0 = "I"
 i1ii = struct . calcsize ( oOoOO0oOOOO0 )
 OO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 13 - 13: ooOoO0o - I1IiiI . I1IiiI / oO0o + ooOoO0o % I1Ii111
 if 41 - 41: oO0o - iIii1I11I1II1 * II111iiii * II111iiii % ooOoO0o
 if 17 - 17: II111iiii - oO0o % I1IiiI . O0 % I1Ii111
 if 29 - 29: I1Ii111 - i1IIi
 I11I1iiiiii = [ ]
 for o000o0O0Oo00 in range ( oO0Oo0o0 ) :
  if ( len ( OoooOOoo ) < o00ooo ) : return ( [ ] )
  O0OOO0o0o , Oo0OoO00O , iIIiIIiI11iiiI , OOoo00 = struct . unpack ( OOOO ,
 OoooOOoo [ : o00ooo ] )
  if 12 - 12: OoooooooOO
  OoooOOoo = OoooOOoo [ o00ooo : : ]
  if 31 - 31: OoooooooOO % OOooOOo + OOooOOo + i11iIiiIii + ooOoO0o
  if ( O0OOO0o0o not in lisp_igmp_record_types ) :
   lprint ( "Invalid record type {}" . format ( O0OOO0o0o ) )
   continue
   if 1 - 1: I11i % OoooooooOO
   if 94 - 94: Oo0Ooo + Oo0Ooo + IiII . o0oOOo0O0Ooo
  o00o0 = lisp_igmp_record_types [ O0OOO0o0o ]
  iIIiIIiI11iiiI = socket . ntohs ( iIIiIIiI11iiiI )
  oo0oOooo0O . address = socket . ntohl ( OOoo00 )
  ooOoo000oO = oo0oOooo0O . print_address_no_iid ( )
  if 88 - 88: oO0o / Oo0Ooo - OoOoOO00 * ooOoO0o - OoOoOO00 / i11iIiiIii
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( o00o0 , ooOoo000oO , iIIiIIiI11iiiI ) )
  if 50 - 50: iIii1I11I1II1 * OOooOOo . iII111i / ooOoO0o + OoOoOO00 - IiII
  if 80 - 80: i11iIiiIii * o0oOOo0O0Ooo
  if 71 - 71: OoO0O00 % I1ii11iIi11i * iII111i . o0oOOo0O0Ooo * oO0o - OoO0O00
  if 44 - 44: I11i / I1Ii111 * OOooOOo - I11i . iIii1I11I1II1
  if 71 - 71: OoO0O00 / IiII
  if 60 - 60: i11iIiiIii - iII111i . OoooooooOO * iII111i + II111iiii
  if 40 - 40: OOooOOo / iIii1I11I1II1 - Oo0Ooo / II111iiii % ooOoO0o . o0oOOo0O0Ooo
  oo0oII = False
  if ( O0OOO0o0o in ( 1 , 5 ) ) : oo0oII = True
  if ( O0OOO0o0o == 3 and iIIiIIiI11iiiI == 0 ) : oo0oII = False
  if ( O0OOO0o0o in ( 2 , 4 ) and iIIiIIiI11iiiI == 0 ) : oo0oII = True
  iiiI1 = "join" if ( oo0oII ) else "leave"
  if 31 - 31: i1IIi
  if 2 - 2: I1Ii111
  if 75 - 75: I1ii11iIi11i
  if 23 - 23: oO0o % i1IIi . II111iiii . IiII . I1ii11iIi11i
  if ( ooOoo000oO . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 22 - 22: OOooOOo / II111iiii . ooOoO0o
   if 2 - 2: IiII * Ii1I * I1ii11iIi11i % iII111i
   if 31 - 31: ooOoO0o * Oo0Ooo . I11i - OOooOOo . iII111i
   if 96 - 96: I11i
   if 88 - 88: O0 + OoO0O00
   if 61 - 61: i11iIiiIii
   if 47 - 47: iII111i % oO0o
   if 60 - 60: Ii1I / OoO0O00
  if ( iIIiIIiI11iiiI == 0 ) :
   I11I1iiiiii . append ( [ None , ooOoo000oO , oo0oII ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( iiiI1 , False ) ,
 bold ( ooOoo000oO , False ) ) )
   if 36 - 36: i11iIiiIii + Ii1I * iII111i . II111iiii
   if 84 - 84: oO0o
   if 50 - 50: ooOoO0o . Ii1I
   if 17 - 17: iIii1I11I1II1
   if 28 - 28: OOooOOo % iIii1I11I1II1 - o0oOOo0O0Ooo * O0 + OoOoOO00 . i1IIi
  for I11ii1IiI1Ii in range ( iIIiIIiI11iiiI ) :
   if ( len ( OoooOOoo ) < i1ii ) : return ( [ ] )
   OOoo00 = struct . unpack ( oOoOO0oOOOO0 , OoooOOoo [ : i1ii ] ) [ 0 ]
   OO . address = socket . ntohl ( OOoo00 )
   I1I1IoO0OOoOOoO = OO . print_address_no_iid ( )
   I11I1iiiiii . append ( [ I1I1IoO0OOoOOoO , ooOoo000oO , oo0oII ] )
   lprint ( "{} ({}, {})" . format ( iiiI1 ,
 green ( I1I1IoO0OOoOOoO , False ) , bold ( ooOoo000oO , False ) ) )
   OoooOOoo = OoooOOoo [ i1ii : : ]
   if 80 - 80: ooOoO0o % iII111i . I1ii11iIi11i / OoooooooOO / Ii1I
   if 53 - 53: II111iiii / i1IIi / i1IIi . oO0o - O0 * O0
   if 19 - 19: Ii1I % II111iiii / OoOoOO00 % I1Ii111
   if 23 - 23: iIii1I11I1II1 % OoooooooOO % IiII - i11iIiiIii + OoO0O00
   if 62 - 62: oO0o - IiII
   if 14 - 14: II111iiii / OOooOOo + i11iIiiIii
 for I1I1IoO0OOoOOoO , ooOoo000oO , oo0oII in I11I1iiiiii :
  lisp_update_igmp_database ( I1I1IoO0OOoOOoO , ooOoo000oO , oo0oII )
  if 35 - 35: OoOoOO00 / o0oOOo0O0Ooo * iIii1I11I1II1 - Oo0Ooo / I1ii11iIi11i / II111iiii
  if 61 - 61: iIii1I11I1II1
  if 54 - 54: II111iiii / OoO0O00 * I1IiiI - ooOoO0o - Oo0Ooo
  if 100 - 100: O0 * II111iiii - iIii1I11I1II1 + OoooooooOO
  if 13 - 13: ooOoO0o
  if 48 - 48: o0oOOo0O0Ooo - OOooOOo + O0 + i1IIi
  if 43 - 43: i11iIiiIii / IiII / OoooooooOO + oO0o * o0oOOo0O0Ooo
 return ( I11I1iiiiii )
 if 56 - 56: Oo0Ooo / Ii1I * OOooOOo
 if 28 - 28: Ii1I + iII111i
 if 96 - 96: i1IIi . O0 - OoooooooOO + iIii1I11I1II1
 if 27 - 27: OoooooooOO / IiII + O0 * ooOoO0o
 if 87 - 87: i1IIi % OoOoOO00 / IiII
 if 91 - 91: I11i - II111iiii * I1IiiI * Ii1I
 if 3 - 3: OoO0O00 - I1ii11iIi11i % iII111i
 if 71 - 71: II111iiii / OOooOOo % o0oOOo0O0Ooo
def lisp_update_igmp_database ( source_str , group_str , joinleave ) :
 if 92 - 92: I1IiiI - o0oOOo0O0Ooo - Ii1I / I1IiiI
 if 94 - 94: Ii1I * OoOoOO00 - I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo . Ii1I
 if 47 - 47: I11i - I11i * OOooOOo - I1Ii111
 if 13 - 13: iIii1I11I1II1
 oo0oOooo0O = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oo0oOooo0O . store_address ( group_str )
 if 33 - 33: I1Ii111 . I11i - Ii1I % OOooOOo - Ii1I - oO0o
 if 89 - 89: OoOoOO00 * II111iiii
 if 94 - 94: I11i - o0oOOo0O0Ooo - IiII + I1IiiI . OoooooooOO * OOooOOo
 if 4 - 4: oO0o
 o0Ooo0Oooo0o = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if source_str :
  o0Ooo0Oooo0o . store_address ( source_str )
 else :
  o0Ooo0Oooo0o . address = 0
  o0Ooo0Oooo0o . mask_len = 0
  if 12 - 12: ooOoO0o + oO0o % I1ii11iIi11i
  if 27 - 27: OOooOOo % i1IIi / iIii1I11I1II1 + OoO0O00
 OoOo00 = "({}, {})" . format ( source_str if source_str else "*" , group_str )
 if 47 - 47: OoooooooOO
 if ( joinleave ) :
  i1I = lisp_db_for_lookups . lookup_cache ( oo0oOooo0O , False )
  if ( i1I ) :
   oo00OOOo00 = i1I . lookup_source_cache ( o0Ooo0Oooo0o , False )
   if ( oo00OOOo00 ) :
    oo00OOOo00 . last_refresh_time = lisp_get_timestamp ( )
    lprint ( "Update IGMP database-mapping entry timestamp for {}" . format ( green ( OoOo00 , False ) ) )
    if 75 - 75: ooOoO0o - Oo0Ooo
    return
    if 20 - 20: oO0o
    if 50 - 50: IiII / iIii1I11I1II1
    if 96 - 96: O0 * OOooOOo
    if 7 - 7: ooOoO0o / i1IIi % iIii1I11I1II1
    if 92 - 92: O0 % I11i / Oo0Ooo / Oo0Ooo / I1IiiI
    if 29 - 29: i11iIiiIii . iII111i + I1Ii111
  OooO00oOoooOo0O0 = lisp_db_list [ 0 ] . rloc_set [ 0 ]
  if 16 - 16: i1IIi
  iIIoOo = copy . deepcopy ( OooO00oOoooOo0O0 )
  iIIoOo . priority = 1
  iIIoOo . weight = 100
  iIIoOo . mpriority = 255
  iIIoOo . mweight = 0
  iIIoOo . state = LISP_RLOC_UP_STATE
  if 34 - 34: Oo0Ooo / OoOoOO00 - Ii1I - oO0o
  o0O0oO0o = lisp_mapping ( o0Ooo0Oooo0o , oo0oOooo0O , [ iIIoOo ] )
  o0O0oO0o . map_cache_ttl = LISP_IGMP_TIMEOUT_INTERVAL
  o0O0oO0o . last_refresh_time = lisp_get_timestamp ( )
  o0O0oO0o . gleaned = True
  if 46 - 46: oO0o * OoooooooOO - o0oOOo0O0Ooo - i11iIiiIii / iIii1I11I1II1 % oO0o
  o0O0oO0o . add_db ( )
  if 21 - 21: OoO0O00 % i1IIi - Oo0Ooo - I1ii11iIi11i + iIii1I11I1II1 - I1ii11iIi11i
  lprint ( "Add IGMP database-mapping entry for {}" . format ( green ( OoOo00 , False ) ) )
 else :
  lisp_remove_igmp_database ( source_str , group_str )
  if 71 - 71: Ii1I . ooOoO0o
  if 10 - 10: iIii1I11I1II1 * IiII
  if 50 - 50: iIii1I11I1II1
  if 55 - 55: o0oOOo0O0Ooo
  if 42 - 42: IiII - i1IIi - oO0o
  if 89 - 89: Ii1I % I1Ii111 / i1IIi + II111iiii
  if 64 - 64: O0 % OoO0O00 / oO0o + iIii1I11I1II1
  if 25 - 25: iIii1I11I1II1 * OoO0O00 * ooOoO0o / OoooooooOO - ooOoO0o - II111iiii
def lisp_remove_igmp_database ( source_str , group_str ) :
 oo0oOooo0O = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 oo0oOooo0O . store_address ( group_str )
 if 14 - 14: iIii1I11I1II1 + I1IiiI * IiII . OoOoOO00 + O0
 i1I = lisp_db_for_lookups . lookup_cache ( oo0oOooo0O , False )
 if ( i1I == None ) : return
 if 96 - 96: O0 * Oo0Ooo % Ii1I * I1IiiI
 o0Ooo0Oooo0o = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if ( source_str ) :
  o0Ooo0Oooo0o . store_address ( source_str )
 else :
  o0Ooo0Oooo0o . address = 0
  o0Ooo0Oooo0o . mask_len = 0
  if 14 - 14: II111iiii - iIii1I11I1II1 / OoO0O00 - I1IiiI - iII111i
  if 51 - 51: Oo0Ooo . OoooooooOO
 OoOo00 = "({}, {})" . format ( source_str if source_str else "*" , group_str )
 if 38 - 38: I1IiiI
 oo00OOOo00 = i1I . lookup_source_cache ( o0Ooo0Oooo0o , False )
 if ( oo00OOOo00 == None ) :
  lprint ( "Could not remove not found IGMP database-mapping entry for {}" . format ( green ( OoOo00 , False ) ) )
  if 40 - 40: OoOoOO00
  return
  if 18 - 18: i1IIi - Oo0Ooo / I1ii11iIi11i * I11i
  if 42 - 42: I1IiiI
  if 41 - 41: OOooOOo / I1Ii111 + OoO0O00
  if 81 - 81: OoOoOO00 % iIii1I11I1II1 - oO0o * I1IiiI . o0oOOo0O0Ooo . I1ii11iIi11i
  if 13 - 13: OoO0O00 * o0oOOo0O0Ooo - o0oOOo0O0Ooo * Oo0Ooo + iIii1I11I1II1 / OoO0O00
 if ( oo00OOOo00 . gleaned == False ) : return
 if 66 - 66: II111iiii + IiII . OoO0O00 / ooOoO0o
 i1I . source_cache . delete_cache ( o0Ooo0Oooo0o )
 lprint ( "Remove IGMP database-mapping entry for {}" . format ( green ( OoOo00 , False ) ) )
 if 70 - 70: iIii1I11I1II1
 if 40 - 40: iII111i * iIii1I11I1II1 % I1Ii111 . I1ii11iIi11i / iII111i / iIii1I11I1II1
 if 70 - 70: ooOoO0o % o0oOOo0O0Ooo
 if 74 - 74: iII111i / OOooOOo
 if i1I . source_cache . cache_size ( ) == 0 :
  lisp_db_for_lookups . delete_cache ( oo0oOooo0O )
  if 89 - 89: Ii1I + OoOoOO00 + ooOoO0o
  if 97 - 97: I1Ii111 - IiII - iII111i * iIii1I11I1II1 % Oo0Ooo
  if 24 - 24: OoO0O00
  if 12 - 12: iIii1I11I1II1 % i1IIi * iIii1I11I1II1 % I1Ii111
  if 66 - 66: II111iiii * i11iIiiIii . OOooOOo / oO0o % I11i
  if 25 - 25: OoooooooOO - IiII
  if 100 - 100: OOooOOo + Ii1I
  if 65 - 65: ooOoO0o / IiII + I11i * O0 * OOooOOo
  if 95 - 95: O0 % I11i . I1Ii111 % Oo0Ooo % iII111i
def lisp_timeout_igmp_database ( ) :
 I1IIII1IIiIi = lisp_get_timestamp ( )
 if 72 - 72: OoO0O00 * II111iiii
 if 75 - 75: i11iIiiIii * II111iiii * Ii1I - IiII / I1ii11iIi11i / I11i
 if 97 - 97: oO0o / i11iIiiIii * iII111i . Ii1I + Ii1I * i1IIi
 if 69 - 69: OoO0O00 * OoO0O00 / Oo0Ooo * i1IIi
 for O00O00O in lisp_db_for_lookups . cache_sorted :
  for I1iIIo00 in ( list ( lisp_db_for_lookups . cache [ O00O00O ] . entries . values ( ) ) ) :
   if ( I1iIIo00 . group . is_null ( ) ) : continue
   if ( I1iIIo00 . source_cache == None ) : continue
   if 31 - 31: i11iIiiIii * OoooooooOO * I1IiiI
   if 68 - 68: II111iiii
   if 94 - 94: O0 - OoOoOO00
   if 29 - 29: OoO0O00 - OoO0O00
   O0OOOo = [ ]
   for iIii in I1iIIo00 . source_cache . cache_sorted :
    for oo00OOOo00 in ( list ( I1iIIo00 . source_cache . cache [ iIii ] . entries . values ( ) ) ) :
     if ( oo00OOOo00 . gleaned == False ) : continue
     if ( oo00OOOo00 . map_cache_ttl == None ) : continue
     if 91 - 91: OoooooooOO * iIii1I11I1II1 - O0 / I11i
     o0oOOOO0 = I1IIII1IIiIi - oo00OOOo00 . last_refresh_time
     if ( o0oOOOO0 >= oo00OOOo00 . map_cache_ttl ) :
      O0OOOo . append ( oo00OOOo00 )
      if 68 - 68: Oo0Ooo - I1ii11iIi11i . iII111i - i1IIi
      if 40 - 40: II111iiii
      if 40 - 40: iIii1I11I1II1
      if 57 - 57: o0oOOo0O0Ooo % i11iIiiIii + o0oOOo0O0Ooo
      if 73 - 73: iIii1I11I1II1 + I1Ii111 % o0oOOo0O0Ooo / OoooooooOO + OoOoOO00
      if 98 - 98: iII111i * ooOoO0o . I1IiiI * OOooOOo * OoOoOO00 * OoooooooOO
      if 43 - 43: IiII . i11iIiiIii % iIii1I11I1II1
   for oo00OOOo00 in ( O0OOOo ) :
    OoOo00 = oo00OOOo00 . print_eid_tuple ( )
    lprint ( "IGMP database entry {} {}" . format (
 green ( OoOo00 , False ) , bold ( "timed out" , False ) ) )
    I1iIIo00 . source_cache . delete_cache ( oo00OOOo00 . eid )
    if 65 - 65: i11iIiiIii + iII111i
    if 12 - 12: ooOoO0o % II111iiii / O0
    if 88 - 88: OoOoOO00 - I1ii11iIi11i % ooOoO0o + OoO0O00 % ooOoO0o
    if 27 - 27: OOooOOo - oO0o * OoooooooOO
    if 25 - 25: oO0o . OoOoOO00
   if ( I1iIIo00 . source_cache . cache_size ( ) == 0 ) :
    lprint ( "Removing empty IGMP group database entry {}" . format (
 green ( I1iIIo00 . group . print_address ( ) , False ) ) )
    lisp_db_for_lookups . delete_cache ( I1iIIo00 . group )
    if 18 - 18: OOooOOo / O0
    if 8 - 8: oO0o * IiII - iII111i % i11iIiiIii * OoOoOO00 / I11i
    if 72 - 72: I11i / IiII
    if 51 - 51: i1IIi . oO0o * Ii1I % I1Ii111 - oO0o - i1IIi
    if 29 - 29: OoooooooOO + ooOoO0o * OoO0O00 % I11i % i11iIiiIii
    if 77 - 77: II111iiii + OoooooooOO . oO0o / O0 + ooOoO0o * IiII
    if 35 - 35: OoO0O00 . OOooOOo % oO0o * I1IiiI / I1ii11iIi11i
    if 48 - 48: OoO0O00 - o0oOOo0O0Ooo - I1Ii111 . OoO0O00 . iII111i
    if 57 - 57: o0oOOo0O0Ooo
    if 47 - 47: I1ii11iIi11i * Oo0Ooo % ooOoO0o / II111iiii % o0oOOo0O0Ooo + I11i
    if 69 - 69: Oo0Ooo - OoOoOO00 . o0oOOo0O0Ooo % I11i / O0 . OoO0O00
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 24 - 24: ooOoO0o / iIii1I11I1II1
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 58 - 58: i11iIiiIii * OOooOOo + OoOoOO00
 if 68 - 68: oO0o - Oo0Ooo / iIii1I11I1II1 / ooOoO0o * i11iIiiIii % OoO0O00
 if 51 - 51: OoOoOO00 % iIii1I11I1II1
 if 93 - 93: o0oOOo0O0Ooo - IiII % i1IIi * IiII
 if 49 - 49: O0 - i1IIi . iII111i % iII111i
 if 66 - 66: O0 % OoooooooOO * IiII . Oo0Ooo
 IiI1i111i = True
 I1I1i1I11I = lisp_map_cache . lookup_cache ( seid , True )
 if ( I1I1i1I11I and len ( I1I1i1I11I . rloc_set ) != 0 ) :
  I1I1i1I11I . last_refresh_time = lisp_get_timestamp ( )
  if 94 - 94: Ii1I - OoOoOO00 * I1IiiI * o0oOOo0O0Ooo / Ii1I + i1IIi
  I1iiOo = I1I1i1I11I . rloc_set [ 0 ]
  OoOoI11ii = I1iiOo . rloc
  iI11 = I1iiOo . translated_port
  IiI1i111i = ( OoOoI11ii . is_exact_match ( rloc ) == False or
 iI11 != encap_port )
  if 7 - 7: iII111i + i1IIi * Oo0Ooo
  if ( IiI1i111i ) :
   oOO = green ( seid . print_address ( ) , False )
   I1I1 = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( oOO , I1I1 ) )
   I1iiOo . delete_from_rloc_probe_list ( I1I1i1I11I . eid , I1I1i1I11I . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 37 - 37: OoooooooOO * O0 . OoOoOO00
 else :
  I1I1i1I11I = lisp_mapping ( "" , "" , [ ] )
  I1I1i1I11I . eid . copy_address ( seid )
  I1I1i1I11I . mapping_source . copy_address ( rloc )
  I1I1i1I11I . map_cache_ttl = LISP_GLEAN_TTL
  I1I1i1I11I . gleaned = True
  oOO = green ( seid . print_address ( ) , False )
  I1I1 = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( oOO , I1I1 ) )
  I1I1i1I11I . add_cache ( )
  if 40 - 40: OoooooooOO
  if 82 - 82: I11i + OoooooooOO
  if 47 - 47: IiII
  if 79 - 79: IiII
  if 44 - 44: IiII . I1ii11iIi11i / OoO0O00 % ooOoO0o
 if ( IiI1i111i ) :
  iIIoOo = lisp_rloc ( )
  iIIoOo . store_translated_rloc ( rloc , encap_port )
  iIIoOo . add_to_rloc_probe_list ( I1I1i1I11I . eid , I1I1i1I11I . group )
  iIIoOo . priority = 253
  iIIoOo . mpriority = 255
  i1i1i1 = [ iIIoOo ]
  I1I1i1I11I . rloc_set = i1i1i1
  I1I1i1I11I . build_best_rloc_set ( )
  if 96 - 96: OoO0O00 / II111iiii / iII111i % iIii1I11I1II1 % II111iiii
  if 37 - 37: Ii1I / ooOoO0o - O0 - Ii1I % iIii1I11I1II1
  if 40 - 40: IiII - OoOoOO00 + OoooooooOO . o0oOOo0O0Ooo
  if 49 - 49: IiII - O0 % I11i . II111iiii % II111iiii
  if 53 - 53: ooOoO0o . II111iiii - II111iiii * I11i
 if ( igmp == None ) : return
 if 85 - 85: I1ii11iIi11i % I1ii11iIi11i
 if 66 - 66: I1Ii111 / Oo0Ooo / I11i
 if 2 - 2: OoOoOO00 + OoO0O00
 if 12 - 12: I1Ii111
 if 89 - 89: iIii1I11I1II1
 lisp_geid . instance_id = seid . instance_id
 if 94 - 94: I1ii11iIi11i - i1IIi % IiII
 if 5 - 5: OoO0O00
 if 38 - 38: OoooooooOO / I11i . oO0o
 if 79 - 79: i11iIiiIii
 if 94 - 94: II111iiii % iII111i
 Iii11iiIiIii = lisp_process_igmp_packet ( igmp )
 if ( Iii11iiIiIii == [ ] ) : return
 if 33 - 33: O0 . ooOoO0o / Oo0Ooo - OOooOOo
 for OO , oo0oOooo0O , oo0oII in Iii11iiIiIii :
  if ( OO != None ) : continue
  if 40 - 40: Ii1I
  if 6 - 6: iII111i % I1ii11iIi11i + IiII + I11i
  if 27 - 27: iIii1I11I1II1 * i11iIiiIii * I1Ii111 - i11iIiiIii . iIii1I11I1II1 . I11i
  if 20 - 20: I1IiiI + OoooooooOO + i11iIiiIii / OOooOOo . I11i % I11i
  lisp_geid . store_address ( oo0oOooo0O )
  o0Oo0O0o , Oo0OoO00O , OOo00 = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( o0Oo0O0o == False ) : continue
  if 89 - 89: OoOoOO00 * I1Ii111
  if ( oo0oII ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 69 - 69: oO0o / IiII * OOooOOo . I11i / I11i
   if 56 - 56: O0 + I1Ii111 * o0oOOo0O0Ooo % Ii1I . OOooOOo
   if 98 - 98: I1Ii111
   if 74 - 74: oO0o
   if 55 - 55: Oo0Ooo
   if 94 - 94: OoooooooOO
   if 87 - 87: OoO0O00 % Oo0Ooo * Oo0Ooo
   if 35 - 35: Oo0Ooo - Oo0Ooo
   if 82 - 82: iII111i
   if 6 - 6: Oo0Ooo . OoOoOO00 / i11iIiiIii - i11iIiiIii . iII111i
   if 49 - 49: I11i % I1IiiI . I1Ii111 . o0oOOo0O0Ooo % OOooOOo
   if 17 - 17: I1IiiI - I1IiiI
def lisp_is_json_telemetry ( json_string ) :
 try :
  iI1O000 = json . loads ( json_string )
  if ( type ( iI1O000 ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 12 - 12: IiII / OoO0O00 / O0 . I1IiiI / I11i
  if 44 - 44: i1IIi - O0 + OoooooooOO + Oo0Ooo
 if ( "type" not in iI1O000 ) : return ( None )
 if ( "sub-type" not in iI1O000 ) : return ( None )
 if ( iI1O000 [ "type" ] != "telemetry" ) : return ( None )
 if ( iI1O000 [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( iI1O000 )
 if 14 - 14: I1ii11iIi11i - o0oOOo0O0Ooo . oO0o
 if 72 - 72: IiII - O0 - II111iiii
 if 37 - 37: I1ii11iIi11i % i1IIi / Oo0Ooo + i11iIiiIii - I1ii11iIi11i
 if 82 - 82: IiII * I1ii11iIi11i
 if 22 - 22: I1IiiI - iIii1I11I1II1 + I1IiiI / I1ii11iIi11i
 if 5 - 5: iIii1I11I1II1 + o0oOOo0O0Ooo * I11i * iIii1I11I1II1 % oO0o - IiII
 if 19 - 19: I1ii11iIi11i % IiII + I1IiiI . II111iiii * i11iIiiIii
 if 21 - 21: iIii1I11I1II1 + iII111i % I11i
 if 20 - 20: OoO0O00 + OoOoOO00 / II111iiii - ooOoO0o * I1IiiI
 if 81 - 81: oO0o % OoOoOO00 % IiII
 if 3 - 3: i11iIiiIii * IiII
 if 64 - 64: OoO0O00 % I1Ii111 / OoO0O00 - i1IIi
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 iI1O000 = lisp_is_json_telemetry ( json_string )
 if ( iI1O000 == None ) : return ( json_string )
 if 46 - 46: OOooOOo + o0oOOo0O0Ooo
 if ( iI1O000 [ "itr-in" ] == "?" ) : iI1O000 [ "itr-in" ] = ii
 if ( iI1O000 [ "itr-out" ] == "?" ) : iI1O000 [ "itr-out" ] = io
 if ( iI1O000 [ "etr-in" ] == "?" ) : iI1O000 [ "etr-in" ] = ei
 if ( iI1O000 [ "etr-out" ] == "?" ) : iI1O000 [ "etr-out" ] = eo
 json_string = json . dumps ( iI1O000 )
 return ( json_string )
 if 5 - 5: IiII + OoooooooOO % I1Ii111 + OoOoOO00 + I1IiiI - I1ii11iIi11i
 if 8 - 8: I1ii11iIi11i
 if 84 - 84: IiII + ooOoO0o - OoO0O00 + I1Ii111 + iII111i
 if 9 - 9: I1Ii111 + i11iIiiIii - Oo0Ooo
 if 20 - 20: I1Ii111 / oO0o - Oo0Ooo
 if 85 - 85: ooOoO0o + O0 * o0oOOo0O0Ooo
 if 31 - 31: II111iiii + OOooOOo * i11iIiiIii
 if 15 - 15: I1IiiI . ooOoO0o / OOooOOo / OoOoOO00 % I11i - Oo0Ooo
 if 57 - 57: Oo0Ooo + OOooOOo
 if 57 - 57: I1ii11iIi11i + i1IIi - OoOoOO00 - I1IiiI + OOooOOo
 if 98 - 98: IiII + OoO0O00 - i11iIiiIii * IiII
 if 81 - 81: Oo0Ooo + OOooOOo + i1IIi % OOooOOo % iIii1I11I1II1
def lisp_decode_telemetry ( json_string ) :
 iI1O000 = lisp_is_json_telemetry ( json_string )
 if ( iI1O000 == None ) : return ( { } )
 return ( iI1O000 )
 if 47 - 47: OoooooooOO / oO0o
 if 100 - 100: i11iIiiIii % o0oOOo0O0Ooo * I1ii11iIi11i . I11i
 if 31 - 31: I1Ii111
 if 59 - 59: i1IIi + OOooOOo * OOooOOo
 if 42 - 42: OoooooooOO * oO0o % II111iiii * ooOoO0o - oO0o
 if 52 - 52: Ii1I . I1Ii111 * OoooooooOO
 if 42 - 42: OoOoOO00 / i11iIiiIii - OoooooooOO
 if 56 - 56: OOooOOo + iII111i * I1Ii111
 if 59 - 59: Ii1I
def lisp_telemetry_configured ( ) :
 if ( "telemetry" not in lisp_json_list ) : return ( None )
 if 30 - 30: II111iiii . iIii1I11I1II1 . I1IiiI % O0 * i11iIiiIii
 OoOo00OO0o00 = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( OoOo00OO0o00 ) == None ) : return ( None )
 if 84 - 84: oO0o % Oo0Ooo / O0 / Ii1I * I1IiiI % i11iIiiIii
 return ( OoOo00OO0o00 )
 if 62 - 62: I1IiiI % OOooOOo
 if 39 - 39: I11i * O0 - i11iIiiIii . O0
 if 35 - 35: IiII
 if 59 - 59: OoO0O00 % I11i + ooOoO0o
 if 9 - 9: O0 % O0
 if 84 - 84: i1IIi * O0 * I1ii11iIi11i - OoO0O00 + OOooOOo % OOooOOo
 if 24 - 24: i1IIi / i1IIi + OoOoOO00
def lisp_mr_or_pubsub ( action ) :
 return ( action in [ LISP_SEND_MAP_REQUEST_ACTION , LISP_SEND_PUBSUB_ACTION ] )
 if 13 - 13: OoooooooOO
 if 83 - 83: OOooOOo . Oo0Ooo . OOooOOo . Ii1I
 if 81 - 81: i1IIi - iIii1I11I1II1
 if 84 - 84: ooOoO0o . II111iiii
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
