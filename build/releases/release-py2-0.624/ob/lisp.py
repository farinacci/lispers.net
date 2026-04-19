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
def lisp_bind_interface ( sock , device ) :
 if ( device == None or sock == None ) : return
 if 94 - 94: ooOoO0o / i11iIiiIii % O0
 if 70 - 70: I11i - Oo0Ooo / OoooooooOO % OoooooooOO
 if 95 - 95: OoooooooOO % OoooooooOO . Ii1I
 if 26 - 26: oO0o + IiII - II111iiii . II111iiii + I1ii11iIi11i + OoOoOO00
 if 68 - 68: O0
 if 76 - 76: I1ii11iIi11i
 if 99 - 99: o0oOOo0O0Ooo
 try :
  if 1 - 1: Ii1I * OoOoOO00 * OoO0O00 + Oo0Ooo
  sock . setsockopt ( socket . SOL_SOCKET , 25 , device . encode ( ) )
  lprint ( "Bind interface {}" . format ( bold ( device , False ) ) )
 except Exception as oOO :
  lprint ( "Failed to bind socket to device {}: {}" . format ( device , oOO ) )
  if 90 - 90: I1Ii111 % Oo0Ooo - Oo0Ooo . iIii1I11I1II1 / OOooOOo + I11i
 return
 if 89 - 89: oO0o
 if 87 - 87: iII111i % Oo0Ooo
 if 62 - 62: OoO0O00 + ooOoO0o / iII111i * i11iIiiIii
 if 37 - 37: iII111i
 if 33 - 33: OoO0O00 - O0 - OoO0O00
 if 94 - 94: IiII * I11i * OoooooooOO / o0oOOo0O0Ooo . IiII - o0oOOo0O0Ooo
 if 13 - 13: OOooOOo / IiII - OoO0O00 / OOooOOo . i1IIi
def lisp_unbind_interface ( sock ) :
 if ( sock == None ) : return
 if 22 - 22: O0 - I11i + I1Ii111 . Ii1I * i1IIi
 try :
  if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
  sock . setsockopt ( socket . SOL_SOCKET , 25 , "" )
 except Exception as oOO :
  lprint ( "Failed to unbind socket: {}" . format ( oOO ) )
  if 10 - 10: I1Ii111 * oO0o % Oo0Ooo - I11i % Oo0Ooo
 return
 if 65 - 65: iII111i * iIii1I11I1II1 / O0 . I11i
 if 94 - 94: Oo0Ooo . ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo . iII111i
 if 98 - 98: OOooOOo + Ii1I
 if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
 if 50 - 50: iIii1I11I1II1 - iII111i - I11i
 if 60 - 60: iIii1I11I1II1 * ooOoO0o
 if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
 if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
 if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
 if 40 - 40: OOooOOo / IiII / iIii1I11I1II1 + Ii1I
 if 59 - 59: I11i * OoooooooOO + OOooOOo . iIii1I11I1II1 / i1IIi
 if 75 - 75: I11i . OOooOOo - iIii1I11I1II1 * OoO0O00 * iII111i
def lisp_get_input_interface ( packet ) :
 ooo0OO0OOooO0 = lisp_format_packet ( packet [ 0 : 12 ] )
 O00O00 = ooo0OO0OOooO0 . replace ( " " , "" )
 oOooO0OoO = O00O00 [ 0 : 12 ]
 o0oOOOOoo0 = O00O00 [ 12 : : ]
 if 80 - 80: i11iIiiIii % I1ii11iIi11i
 try : OOO00o0 = ( o0oOOOOoo0 in lisp_mymacs )
 except : OOO00o0 = False
 if 97 - 97: I1ii11iIi11i / I1ii11iIi11i / iIii1I11I1II1 % i1IIi . I1ii11iIi11i . IiII
 if ( oOooO0OoO in lisp_mymacs ) : return ( lisp_mymacs [ oOooO0OoO ] , o0oOOOOoo0 , oOooO0OoO , OOO00o0 )
 if ( OOO00o0 ) : return ( lisp_mymacs [ o0oOOOOoo0 ] , o0oOOOOoo0 , oOooO0OoO , OOO00o0 )
 return ( [ "?" ] , o0oOOOOoo0 , oOooO0OoO , OOO00o0 )
 if 4 - 4: Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / Ii1I - OOooOOo
 if 45 - 45: o0oOOo0O0Ooo % Oo0Ooo * i1IIi - O0
 if 82 - 82: II111iiii / iII111i
 if 96 - 96: Oo0Ooo / oO0o . II111iiii . Oo0Ooo
 if 91 - 91: II111iiii . OOooOOo + o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * Oo0Ooo / iII111i - OoO0O00 - OoooooooOO
 if 100 - 100: oO0o . iIii1I11I1II1 . iIii1I11I1II1
 if 55 - 55: oO0o
def lisp_get_local_interfaces ( ) :
 for i1iiI in netifaces . interfaces ( ) :
  o0o = lisp_interface ( i1iiI )
  o0o . add_interface ( )
  if 73 - 73: OoOoOO00 % o0oOOo0O0Ooo
 return
 if 71 - 71: oO0o - OoooooooOO * Oo0Ooo * I11i + o0oOOo0O0Ooo * I1ii11iIi11i
 if 85 - 85: i11iIiiIii . OoooooooOO - iIii1I11I1II1
 if 38 - 38: I11i . I11i * oO0o / OoooooooOO % ooOoO0o
 if 80 - 80: OoO0O00 / IiII * I1IiiI % IiII
 if 95 - 95: O0 / I11i . I1Ii111
 if 17 - 17: I11i
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
def lisp_get_loopback_address ( ) :
 for iI1ii11Ii in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( iI1ii11Ii [ "peer" ] == "127.0.0.1" ) : continue
  return ( iI1ii11Ii [ "peer" ] )
  if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 return ( None )
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 if 36 - 36: IiII
 if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
def lisp_is_mac_string ( mac_str ) :
 i1i1I1 = mac_str . split ( "/" )
 if ( len ( i1i1I1 ) == 2 ) : mac_str = i1i1I1 [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
 if 43 - 43: iIii1I11I1II1 % OoO0O00
 if 84 - 84: Oo0Ooo
 if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
 if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
 if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
 if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
 if 25 - 25: o0oOOo0O0Ooo
def lisp_get_local_macs ( ) :
 for i1iiI in netifaces . interfaces ( ) :
  if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
  if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
  if 41 - 41: i1IIi - I1IiiI
  if 48 - 48: I1IiiI - II111iiii / OoO0O00 + I1IiiI
  if 5 - 5: O0
  oooOo = i1iiI . replace ( ":" , "" )
  oooOo = i1iiI . replace ( "-" , "" )
  if ( oooOo . isalnum ( ) == False ) : continue
  if 75 - 75: I1Ii111 + iIii1I11I1II1
  if 19 - 19: I1IiiI + i11iIiiIii . IiII - I11i / Ii1I + o0oOOo0O0Ooo
  if 38 - 38: Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1 % I1ii11iIi11i
  if 92 - 92: I11i / O0 * I1IiiI - I11i
  if 99 - 99: i11iIiiIii % OoooooooOO
  try :
   o0000O00oO0O = netifaces . ifaddresses ( i1iiI )
  except :
   continue
   if 3 - 3: iIii1I11I1II1 % I1ii11iIi11i . OOooOOo % I11i
  if ( netifaces . AF_LINK not in o0000O00oO0O ) : continue
  i1i1I1 = o0000O00oO0O [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  i1i1I1 = i1i1I1 . replace ( ":" , "" )
  if 40 - 40: ooOoO0o * Ii1I . Ii1I + II111iiii + OoooooooOO
  if 17 - 17: IiII % Ii1I
  if 46 - 46: I1IiiI - I11i / OoooooooOO - i1IIi . i11iIiiIii
  if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
  if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
  if ( len ( i1i1I1 ) < 12 ) : continue
  if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
  if ( i1i1I1 not in lisp_mymacs ) : lisp_mymacs [ i1i1I1 ] = [ ]
  lisp_mymacs [ i1i1I1 ] . append ( i1iiI )
  if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
  if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 10 - 10: IiII / OoooooooOO
 if 50 - 50: i11iIiiIii - OoooooooOO . oO0o + O0 . i1IIi
 if 91 - 91: o0oOOo0O0Ooo . iII111i % Oo0Ooo - iII111i . oO0o % i11iIiiIii
 if 25 - 25: iIii1I11I1II1
 if 63 - 63: ooOoO0o
 if 96 - 96: I11i
 if 34 - 34: OoOoOO00 / OoO0O00 - I1IiiI . O0 . OOooOOo
 if 63 - 63: iII111i
def lisp_get_local_rloc ( ) :
 i1i1iIiI = getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( i1i1iIiI == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 23 - 23: IiII + iIii1I11I1II1 % iIii1I11I1II1 / ooOoO0o . oO0o + iIii1I11I1II1
 if 93 - 93: oO0o * o0oOOo0O0Ooo / OOooOOo - OOooOOo . iII111i / I1IiiI
 if 11 - 11: I1Ii111 - I11i % i11iIiiIii . iIii1I11I1II1 * I1IiiI - Oo0Ooo
 if 73 - 73: O0 + ooOoO0o - O0 / OoooooooOO * Oo0Ooo
 i1i1iIiI = i1i1iIiI . split ( "\n" ) [ 0 ]
 i1iiI = i1i1iIiI . split ( ) [ - 1 ]
 if 32 - 32: OoO0O00 % I1IiiI % iII111i
 iI1ii11Ii = ""
 oOOO0OO = lisp_is_macos ( )
 if ( oOOO0OO ) :
  i1i1iIiI = getoutput ( "ifconfig {} | egrep 'inet '" . format ( i1iiI ) )
  if ( i1i1iIiI == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  I11ii1iI11 = 'ip addr show | egrep "inet " | egrep "{}"' . format ( i1iiI )
  i1i1iIiI = getoutput ( I11ii1iI11 )
  if ( i1i1iIiI == "" ) :
   I11ii1iI11 = 'ip addr show | egrep "inet " | egrep "global lo"'
   i1i1iIiI = getoutput ( I11ii1iI11 )
   if 6 - 6: IiII * II111iiii % iIii1I11I1II1
  if ( i1i1iIiI == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 86 - 86: i1IIi * O0 % ooOoO0o . Oo0Ooo % ooOoO0o . Oo0Ooo
  if 71 - 71: iII111i . i11iIiiIii * O0 + O0
  if 57 - 57: OoooooooOO . I11i % II111iiii % I1IiiI + Ii1I
  if 70 - 70: IiII . i11iIiiIii
  if 76 - 76: iII111i . IiII % iII111i - I1Ii111
  if 51 - 51: OoooooooOO + o0oOOo0O0Ooo * iIii1I11I1II1 * oO0o / i1IIi
 iI1ii11Ii = ""
 i1i1iIiI = i1i1iIiI . split ( "\n" )
 if 19 - 19: iII111i - OoOoOO00 % oO0o / OoooooooOO % iII111i
 for ooO in i1i1iIiI :
  I1II1I1I = ooO . split ( ) [ 1 ]
  if ( oOOO0OO == False ) : I1II1I1I = I1II1I1I . split ( "/" ) [ 0 ]
  oOoO0 = lisp_address ( LISP_AFI_IPV4 , I1II1I1I , 32 , 0 )
  return ( oOoO0 )
  if 31 - 31: i11iIiiIii - ooOoO0o / I1ii11iIi11i - Ii1I
 return ( lisp_address ( LISP_AFI_IPV4 , iI1ii11Ii , 32 , 0 ) )
 if 5 - 5: i11iIiiIii * Oo0Ooo
 if 29 - 29: Ii1I / ooOoO0o % I11i
 if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
 if 79 - 79: O0
 if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
 if 15 - 15: I1ii11iIi11i
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
 if 88 - 88: oO0o - i1IIi % i11iIiiIii % II111iiii * OoooooooOO
 if 40 - 40: Oo0Ooo
 if 47 - 47: OoOoOO00
 if 65 - 65: O0 + I1Ii111 % Ii1I * I1IiiI / ooOoO0o / OoOoOO00
 if 71 - 71: i11iIiiIii / OoOoOO00 . oO0o
 if 33 - 33: oO0o
 if 39 - 39: OoO0O00 + O0 + ooOoO0o * II111iiii % O0 - O0
 if 41 - 41: IiII % o0oOOo0O0Ooo
 if 67 - 67: O0 % I1Ii111
 III = None
 o00O = 1
 I1I = os . getenv ( "LISP_ADDR_SELECT" )
 if ( I1I != None and I1I != "" ) :
  I1I = I1I . split ( ":" )
  if ( len ( I1I ) == 2 ) :
   III = I1I [ 0 ]
   o00O = I1I [ 1 ]
  else :
   if ( I1I [ 0 ] . isdigit ( ) ) :
    o00O = I1I [ 0 ]
   else :
    III = I1I [ 0 ]
    if 70 - 70: Ii1I . O0 - OOooOOo
    if 62 - 62: I1Ii111 * I11i
  o00O = 1 if ( o00O == "" ) else int ( o00O )
  if 74 - 74: OoOoOO00 . iIii1I11I1II1
  if 87 - 87: ooOoO0o
 II = [ None , None , None ]
 o0oo0OO = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i11Ii1 = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 I11IIIII = None
 if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
 for i1iiI in netifaces . interfaces ( ) :
  if ( III != None and III != i1iiI ) : continue
  OooO0O0Ooo = netifaces . ifaddresses ( i1iiI )
  if ( OooO0O0Ooo == { } ) : continue
  if 44 - 44: I1Ii111 - IiII
  if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if 59 - 59: II111iiii
  if 43 - 43: Oo0Ooo + OoooooooOO
  I11IIIII = lisp_get_interface_instance_id ( i1iiI , None )
  if 47 - 47: ooOoO0o
  if 92 - 92: I11i % i11iIiiIii % Oo0Ooo
  if 23 - 23: II111iiii * iII111i
  if 80 - 80: I1Ii111 / i11iIiiIii + OoooooooOO
  if ( netifaces . AF_INET in OooO0O0Ooo ) :
   oo000o = OooO0O0Ooo [ netifaces . AF_INET ]
   III11i1iI11 = 0
   for iI1ii11Ii in oo000o :
    o0oo0OO . store_address ( iI1ii11Ii [ "addr" ] )
    if ( o0oo0OO . is_ipv4_loopback ( ) ) : continue
    if ( o0oo0OO . is_ipv4_link_local ( ) ) : continue
    if ( o0oo0OO . address == 0 ) : continue
    III11i1iI11 += 1
    o0oo0OO . instance_id = I11IIIII
    if ( III == None and
 lisp_db_for_lookups . lookup_cache ( o0oo0OO , False ) ) : continue
    II [ 0 ] = o0oo0OO
    if ( III11i1iI11 == o00O ) : break
    if 58 - 58: oO0o
    if 98 - 98: o0oOOo0O0Ooo * OoO0O00
  if ( netifaces . AF_INET6 in OooO0O0Ooo ) :
   OO00o0oOO = OooO0O0Ooo [ netifaces . AF_INET6 ]
   III11i1iI11 = 0
   for iI1ii11Ii in OO00o0oOO :
    O00oO000Oo0 = iI1ii11Ii [ "addr" ]
    i11Ii1 . store_address ( O00oO000Oo0 )
    if ( i11Ii1 . is_ipv6_string_link_local ( O00oO000Oo0 ) ) : continue
    if ( i11Ii1 . is_ipv6_loopback ( ) ) : continue
    III11i1iI11 += 1
    i11Ii1 . instance_id = I11IIIII
    if ( III == None and
 lisp_db_for_lookups . lookup_cache ( i11Ii1 , False ) ) : continue
    II [ 1 ] = i11Ii1
    if ( III11i1iI11 == o00O ) : break
    if 10 - 10: oO0o - iII111i % II111iiii - I1Ii111 - i1IIi
    if 10 - 10: I1ii11iIi11i - I11i . I1Ii111
    if 8 - 8: iIii1I11I1II1 % oO0o + Oo0Ooo
    if 24 - 24: o0oOOo0O0Ooo / Ii1I / Ii1I % II111iiii - oO0o * oO0o
    if 58 - 58: OoOoOO00
    if 60 - 60: II111iiii
  if ( II [ 0 ] == None ) : continue
  if 90 - 90: OoOoOO00
  II [ 2 ] = i1iiI
  break
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
  if 18 - 18: OoooooooOO
 O0oOo00oooO = II [ 0 ] . print_address_no_iid ( ) if II [ 0 ] else "none"
 Iii = II [ 1 ] . print_address_no_iid ( ) if II [ 1 ] else "none"
 i1iiI = II [ 2 ] if II [ 2 ] else "none"
 if 22 - 22: II111iiii * ooOoO0o + I1ii11iIi11i + I11i / OoOoOO00
 III = " (user selected)" if III != None else ""
 if 52 - 52: OoooooooOO / IiII % II111iiii
 O0oOo00oooO = red ( O0oOo00oooO , False )
 Iii = red ( Iii , False )
 i1iiI = bold ( i1iiI , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( O0oOo00oooO , Iii , i1iiI , III , I11IIIII ) )
 if 40 - 40: I1IiiI % ooOoO0o % IiII + OoO0O00
 if 75 - 75: oO0o - I1ii11iIi11i + oO0o + OoooooooOO . i11iIiiIii
 lisp_myrlocs = II
 return ( ( II [ 0 ] != None ) )
 if 52 - 52: iII111i / ooOoO0o - i11iIiiIii + OoooooooOO
 if 33 - 33: O0 + Oo0Ooo - iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
 if 86 - 86: IiII
 if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
 if 33 - 33: II111iiii - IiII - ooOoO0o
 if 92 - 92: OoO0O00 * IiII
 if 92 - 92: oO0o
 if 7 - 7: iII111i
def lisp_get_all_addresses ( ) :
 oOOoOO0O00o = [ ]
 for o0o in netifaces . interfaces ( ) :
  try : Ii = netifaces . ifaddresses ( o0o )
  except : continue
  if 2 - 2: I1IiiI
  if ( netifaces . AF_INET in Ii ) :
   for iI1ii11Ii in Ii [ netifaces . AF_INET ] :
    I1II1I1I = iI1ii11Ii [ "addr" ]
    if ( I1II1I1I . find ( "127.0.0.1" ) != - 1 ) : continue
    oOOoOO0O00o . append ( I1II1I1I )
    if 69 - 69: OoooooooOO / Oo0Ooo * I1Ii111
    if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  if ( netifaces . AF_INET6 in Ii ) :
   for iI1ii11Ii in Ii [ netifaces . AF_INET6 ] :
    I1II1I1I = iI1ii11Ii [ "addr" ]
    if ( I1II1I1I == "::1" ) : continue
    if ( I1II1I1I [ 0 : 5 ] == "fe80:" ) : continue
    oOOoOO0O00o . append ( I1II1I1I )
    if 14 - 14: IiII . IiII % ooOoO0o
    if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
    if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
 return ( oOOoOO0O00o )
 if 8 - 8: i11iIiiIii . iII111i / iIii1I11I1II1 / I1ii11iIi11i / IiII - Ii1I
 if 32 - 32: o0oOOo0O0Ooo . i1IIi * Oo0Ooo
 if 98 - 98: Ii1I - II111iiii / I1IiiI . oO0o * IiII . I11i
 if 25 - 25: i11iIiiIii / OoOoOO00 - I1Ii111 / OoO0O00 . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 6 - 6: oO0o . I11i
 if 43 - 43: I1ii11iIi11i + o0oOOo0O0Ooo
 if 50 - 50: oO0o % i1IIi * O0
 if 4 - 4: iIii1I11I1II1 . i1IIi
def lisp_get_all_multicast_rles ( ) :
 Oo00oo = [ ]
 i1i1iIiI = getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( i1i1iIiI == "" ) : return ( Oo00oo )
 if 79 - 79: I1ii11iIi11i / O0 % o0oOOo0O0Ooo
 o0ooo = i1i1iIiI . split ( "\n" )
 for ooO in o0ooo :
  if ( ooO [ 0 ] == "#" ) : continue
  IiI = ooO . split ( "rle-address = " ) [ 1 ]
  ii11I = int ( IiI . split ( "." ) [ 0 ] )
  if ( ii11I >= 224 and ii11I < 240 ) : Oo00oo . append ( IiI )
  if 97 - 97: i1IIi + iII111i . ooOoO0o - iII111i
 return ( Oo00oo )
 if 53 - 53: O0 . I1IiiI
 if 74 - 74: ooOoO0o % OoOoOO00 / Oo0Ooo
 if 2 - 2: IiII % IiII % I1Ii111
 if 60 - 60: OOooOOo
 if 73 - 73: ooOoO0o
 if 86 - 86: OoOoOO00 . I11i / Oo0Ooo * I11i
 if 20 - 20: ooOoO0o - OOooOOo * OoO0O00 * o0oOOo0O0Ooo * OOooOOo / IiII
 if 40 - 40: I1IiiI * o0oOOo0O0Ooo . I1IiiI
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
  if 62 - 62: ooOoO0o + II111iiii % ooOoO0o
  if 50 - 50: OoooooooOO + oO0o * I1IiiI - Ii1I / i11iIiiIii
 def encode ( self , nonce ) :
  if 5 - 5: O0 - I1IiiI
  if 44 - 44: II111iiii . II111iiii + OOooOOo * Ii1I
  if 16 - 16: II111iiii
  if 100 - 100: O0 - i1IIi
  if 48 - 48: oO0o % ooOoO0o + O0
  if ( self . outer_source . is_null ( ) ) : return ( None )
  if 27 - 27: I1ii11iIi11i / OOooOOo
  if 33 - 33: OoooooooOO % I1ii11iIi11i . O0 / I1ii11iIi11i
  if 63 - 63: IiII + iIii1I11I1II1 + I1IiiI + I1Ii111
  if 72 - 72: OoO0O00 + i11iIiiIii + I1ii11iIi11i
  if 96 - 96: oO0o % i1IIi / o0oOOo0O0Ooo
  if 13 - 13: II111iiii - Oo0Ooo % i11iIiiIii + iII111i
  if ( nonce == None ) :
   self . lisp_header . nonce ( lisp_get_data_nonce ( ) )
  elif ( self . lisp_header . is_request_nonce ( nonce ) ) :
   self . lisp_header . request_nonce ( nonce )
  else :
   self . lisp_header . nonce ( nonce )
   if 88 - 88: O0 . oO0o % I1IiiI
  self . lisp_header . instance_id ( self . inner_dest . instance_id )
  if 10 - 10: I1IiiI + O0
  if 75 - 75: O0 % iIii1I11I1II1 / OoOoOO00 % OOooOOo / IiII
  if 31 - 31: i11iIiiIii * OoOoOO00
  if 69 - 69: i11iIiiIii
  if 61 - 61: O0
  if 21 - 21: OoO0O00 % iIii1I11I1II1 . OoO0O00
  self . lisp_header . key_id ( 0 )
  OO000OOOo0Oo = ( self . lisp_header . get_instance_id ( ) == 0xffffff )
  if ( lisp_data_plane_security and OO000OOOo0Oo == False ) :
   O00oO000Oo0 = self . outer_dest . print_address_no_iid ( ) + ":" + str ( self . encap_port )
   if 75 - 75: II111iiii + ooOoO0o % OOooOOo + Oo0Ooo
   if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_encap ) :
    oOoOOoo = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ]
    if ( oOoOOoo [ 1 ] ) :
     oOoOOoo [ 1 ] . use_count += 1
     Oo00O0o0O , O0OoOO = self . encrypt ( oOoOOoo [ 1 ] , O00oO000Oo0 )
     if ( O0OoOO ) : self . packet = Oo00O0o0O
     if 72 - 72: Ii1I % Ii1I / I1IiiI
     if 40 - 40: Oo0Ooo - OOooOOo + I1Ii111 - o0oOOo0O0Ooo % I1IiiI . ooOoO0o
     if 35 - 35: i11iIiiIii + OoooooooOO * iIii1I11I1II1 . I1Ii111
     if 48 - 48: iII111i * i1IIi % OoooooooOO * Ii1I * OoO0O00
     if 7 - 7: iII111i . Ii1I . iII111i - I1Ii111
     if 33 - 33: ooOoO0o + OoooooooOO - OoO0O00 / i1IIi / OoooooooOO
     if 82 - 82: I1ii11iIi11i / OOooOOo - iII111i / Oo0Ooo * OoO0O00
     if 55 - 55: OoooooooOO
  self . udp_checksum = 0
  if ( self . encap_port == LISP_DATA_PORT ) :
   if ( lisp_crypto_ephem_port == None ) :
    if ( self . gleaned_dest ) :
     self . udp_sport = LISP_DATA_PORT
    else :
     self . hash_packet ( )
     if 73 - 73: OoOoOO00 - I1ii11iIi11i % Oo0Ooo + I1ii11iIi11i - O0 . OoO0O00
   else :
    self . udp_sport = lisp_crypto_ephem_port
    if 38 - 38: O0
  else :
   self . udp_sport = LISP_DATA_PORT
   if 79 - 79: i1IIi . oO0o
  self . udp_dport = self . encap_port
  self . udp_length = len ( self . packet ) + 16
  if 34 - 34: I1Ii111 * II111iiii
  if 71 - 71: IiII
  if 97 - 97: I1ii11iIi11i
  if 86 - 86: Oo0Ooo - OOooOOo . OoOoOO00 . II111iiii * I1IiiI . II111iiii
  II1 = socket . htons ( self . udp_sport )
  Ooo0000o00OO = socket . htons ( self . udp_dport )
  IiiiIIIi11ii1 = socket . htons ( self . udp_length )
  ii11 = struct . pack ( "HHHH" , II1 , Ooo0000o00OO , IiiiIIIi11ii1 , self . udp_checksum )
  if 82 - 82: OOooOOo * I1ii11iIi11i % Ii1I . OOooOOo
  if 43 - 43: OoO0O00 . ooOoO0o * Oo0Ooo
  if 20 - 20: i1IIi . i1IIi - I11i
  if 89 - 89: ooOoO0o - I11i . O0 % OoooooooOO . i11iIiiIii
  IiIIiII1I = self . lisp_header . encode ( )
  if 92 - 92: I1Ii111 % Ii1I
  if 30 - 30: II111iiii - o0oOOo0O0Ooo % I1Ii111 . I11i
  if 63 - 63: iIii1I11I1II1 / ooOoO0o
  if 24 - 24: Oo0Ooo / iIii1I11I1II1 % OOooOOo * OoOoOO00 - iIii1I11I1II1
  if 50 - 50: II111iiii
  if ( self . outer_version == 4 ) :
   IiIIiiiIi = socket . htons ( self . udp_length + 20 )
   IiI111 = socket . htons ( 0x4000 )
   OO0OO00ooO0 = struct . pack ( "BBHHHBBH" , 0x45 , self . outer_tos , IiIIiiiIi , 0xdfdf ,
 IiI111 , self . outer_ttl , 17 , 0 )
   OO0OO00ooO0 += self . outer_source . pack_address ( )
   OO0OO00ooO0 += self . outer_dest . pack_address ( )
   OO0OO00ooO0 = lisp_ip_checksum ( OO0OO00ooO0 )
  elif ( self . outer_version == 6 ) :
   OO0OO00ooO0 = b""
   if 68 - 68: OoOoOO00 * I1ii11iIi11i - OoooooooOO - I11i + iIii1I11I1II1 * i11iIiiIii
   if 80 - 80: i1IIi . I1IiiI - oO0o + OOooOOo + iII111i % oO0o
   if 13 - 13: II111iiii / OoOoOO00 / OoOoOO00 + ooOoO0o
   if 49 - 49: O0 / II111iiii * I1IiiI - OoooooooOO . II111iiii % IiII
   if 13 - 13: oO0o . iIii1I11I1II1 . OOooOOo . IiII
   if 58 - 58: I11i
   if 7 - 7: II111iiii / IiII % I11i + I1IiiI - O0
  else :
   return ( None )
   if 45 - 45: I1IiiI / iII111i + oO0o + IiII
   if 15 - 15: I1IiiI % OoO0O00
  self . packet = OO0OO00ooO0 + ii11 + IiIIiII1I + self . packet
  return ( self )
  if 66 - 66: oO0o * i11iIiiIii . I1Ii111
  if 92 - 92: oO0o
 def cipher_pad ( self , packet ) :
  OOOOo0o0O0o = len ( packet )
  if ( ( OOOOo0o0O0o % 16 ) != 0 ) :
   IIII = ( old_div ( OOOOo0o0O0o , 16 ) + 1 ) * 16
   packet = packet . ljust ( IIII )
   if 42 - 42: o0oOOo0O0Ooo * OoOoOO00 . OoO0O00 - iII111i / II111iiii
  return ( packet )
  if 25 - 25: Oo0Ooo % OoOoOO00
  if 75 - 75: i1IIi
 def encrypt ( self , key , addr_str ) :
  if ( key == None or key . shared_key == None ) :
   return ( [ self . packet , False ] )
   if 74 - 74: Oo0Ooo + I1Ii111 - oO0o - OoO0O00 + iII111i - iIii1I11I1II1
   if 54 - 54: I1ii11iIi11i + II111iiii . I1IiiI / OoO0O00 . ooOoO0o
   if 58 - 58: IiII % i11iIiiIii * II111iiii . I1ii11iIi11i
   if 94 - 94: i11iIiiIii . OOooOOo + iIii1I11I1II1 * I1Ii111 * I1Ii111
   if 36 - 36: I11i - IiII . IiII
  Oo00O0o0O = self . cipher_pad ( self . packet )
  Oo0OOOO0oOoo0 = key . get_iv ( )
  if 92 - 92: IiII . Oo0Ooo - Oo0Ooo - o0oOOo0O0Ooo + I1Ii111 - O0
  iIiIIIIIii = lisp_get_timestamp ( )
  i1I1Iiii = None
  I1iIIIiiii = False
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   I1111 = chacha . ChaCha ( key . encrypt_key , Oo0OOOO0oOoo0 ) . encrypt
   I1iIIIiiii = True
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o00o = binascii . unhexlify ( key . encrypt_key )
   try :
    O0o0oo0O = AES . new ( o00o , AES . MODE_GCM , Oo0OOOO0oOoo0 )
    I1111 = O0o0oo0O . encrypt
    i1I1Iiii = O0o0oo0O . digest
   except :
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ self . packet , False ] )
    if 74 - 74: II111iiii % I11i . OoO0O00 * OoO0O00
  else :
   o00o = binascii . unhexlify ( key . encrypt_key )
   I1111 = AES . new ( o00o , AES . MODE_CBC , Oo0OOOO0oOoo0 ) . encrypt
   if 27 - 27: I11i * Oo0Ooo . Ii1I . I1IiiI % II111iiii - oO0o
   if 52 - 52: I1IiiI % OoO0O00 * Ii1I * iII111i / OOooOOo
  oooO00oo0 = I1111 ( Oo00O0o0O )
  if 74 - 74: IiII / ooOoO0o
  if ( oooO00oo0 == None ) : return ( [ self . packet , False ] )
  iIiIIIIIii = int ( str ( time . time ( ) - iIiIIIIIii ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 86 - 86: O0 . i1IIi - OoO0O00 / Oo0Ooo / I1ii11iIi11i
  if 64 - 64: OoooooooOO - i1IIi / II111iiii
  if 49 - 49: Oo0Ooo + O0 + IiII . II111iiii % ooOoO0o
  if 33 - 33: OoOoOO00 . iIii1I11I1II1 / I11i % Ii1I
  if 49 - 49: OoO0O00 + II111iiii / IiII - O0 % Ii1I
  if 27 - 27: OoO0O00 + Oo0Ooo
  if ( I1iIIIiiii ) :
   oooO00oo0 = oooO00oo0 . encode ( "raw_unicode_escape" )
   if 92 - 92: I1IiiI % iII111i
   if 31 - 31: OoooooooOO - oO0o / I1Ii111
   if 62 - 62: i11iIiiIii - I11i
   if 81 - 81: I11i
   if 92 - 92: OOooOOo - Oo0Ooo - OoooooooOO / IiII - i1IIi
   if 81 - 81: i1IIi / I1Ii111 % i11iIiiIii . iIii1I11I1II1 * OoOoOO00 + OoooooooOO
   if 31 - 31: i1IIi % II111iiii
  if ( i1I1Iiii != None ) : oooO00oo0 += i1I1Iiii ( )
  if 13 - 13: iIii1I11I1II1 - II111iiii % O0 . Ii1I % OoO0O00
  if 2 - 2: OoooooooOO - Ii1I % oO0o / I1IiiI / o0oOOo0O0Ooo
  if 3 - 3: II111iiii / OOooOOo
  if 48 - 48: ooOoO0o . I1ii11iIi11i
  if 49 - 49: i1IIi - OoOoOO00 . Oo0Ooo + iIii1I11I1II1 - ooOoO0o / Oo0Ooo
  self . lisp_header . key_id ( key . key_id )
  IiIIiII1I = self . lisp_header . encode ( )
  if 24 - 24: oO0o - iII111i / ooOoO0o
  iIiiII1Ii1ii = key . do_icv ( IiIIiII1I + Oo0OOOO0oOoo0 + oooO00oo0 , Oo0OOOO0oOoo0 )
  if 34 - 34: I1IiiI
  o0 = 4 if ( key . do_poly ) else 8
  if 76 - 76: I1IiiI - I1IiiI - o0oOOo0O0Ooo % ooOoO0o * O0
  I1i1iI = bold ( "Encrypt" , False )
  oo0O0OO = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  i11II = "poly" if key . do_poly else "sha256"
  i11II = bold ( i11II , False )
  IIi = "ICV({}): 0x{}...{}" . format ( i11II , iIiiII1Ii1ii [ 0 : o0 ] , iIiiII1Ii1ii [ - o0 : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( I1i1iI , key . key_id , addr_str , IIi , oo0O0OO , iIiIIIIIii ) )
  if 62 - 62: II111iiii - I1Ii111 + I11i * iIii1I11I1II1 * o0oOOo0O0Ooo
  if 83 - 83: OoO0O00
  iIiiII1Ii1ii = int ( iIiiII1Ii1ii , 16 )
  if ( key . do_poly ) :
   iii1IiiIiIIiI = byte_swap_64 ( ( iIiiII1Ii1ii >> 64 ) & LISP_8_64_MASK )
   o0OoOOoOOoo = byte_swap_64 ( iIiiII1Ii1ii & LISP_8_64_MASK )
   iIiiII1Ii1ii = struct . pack ( "QQ" , iii1IiiIiIIiI , o0OoOOoOOoo )
  else :
   iii1IiiIiIIiI = byte_swap_64 ( ( iIiiII1Ii1ii >> 96 ) & LISP_8_64_MASK )
   o0OoOOoOOoo = byte_swap_64 ( ( iIiiII1Ii1ii >> 32 ) & LISP_8_64_MASK )
   oo0O0 = socket . htonl ( iIiiII1Ii1ii & 0xffffffff )
   iIiiII1Ii1ii = struct . pack ( "QQI" , iii1IiiIiIIiI , o0OoOOoOOoo , oo0O0 )
   if 34 - 34: II111iiii - IiII % OoOoOO00 % Ii1I / ooOoO0o
   if 10 - 10: OoooooooOO . I1IiiI * O0 * OoO0O00 - OOooOOo
  return ( [ Oo0OOOO0oOoo0 + oooO00oo0 + iIiiII1Ii1ii , True ] )
  if 33 - 33: I1ii11iIi11i . Oo0Ooo + I1IiiI + o0oOOo0O0Ooo
  if 54 - 54: ooOoO0o * iII111i * iII111i % OoOoOO00 - OOooOOo % I1ii11iIi11i
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 44 - 44: Oo0Ooo . OOooOOo + I11i
  if 22 - 22: I1Ii111 * OoooooooOO + i11iIiiIii % OoO0O00
  if 53 - 53: I1IiiI
  if 10 - 10: I1Ii111 / i11iIiiIii - II111iiii
  if 48 - 48: OOooOOo
  if 26 - 26: iII111i * I1Ii111 * oO0o * OoOoOO00
  if ( key . do_poly ) :
   iii1IiiIiIIiI , o0OoOOoOOoo = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   I1ii1i11iI1 = byte_swap_64 ( iii1IiiIiIIiI ) << 64
   I1ii1i11iI1 |= byte_swap_64 ( o0OoOOoOOoo )
   I1ii1i11iI1 = lisp_hex_string ( I1ii1i11iI1 ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   o0 = 4
   IiOOo0 = bold ( "poly" , False )
  else :
   iii1IiiIiIIiI , o0OoOOoOOoo , oo0O0 = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   I1ii1i11iI1 = byte_swap_64 ( iii1IiiIiIIiI ) << 96
   I1ii1i11iI1 |= byte_swap_64 ( o0OoOOoOOoo ) << 32
   I1ii1i11iI1 |= socket . htonl ( oo0O0 )
   I1ii1i11iI1 = lisp_hex_string ( I1ii1i11iI1 ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   o0 = 8
   IiOOo0 = bold ( "sha" , False )
   if 85 - 85: I1Ii111 % I1ii11iIi11i
  IiIIiII1I = self . lisp_header . encode ( )
  if 95 - 95: OoO0O00 * OOooOOo * iII111i . o0oOOo0O0Ooo
  if 73 - 73: OoO0O00
  if 28 - 28: OoooooooOO - I11i
  if 84 - 84: II111iiii
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   i1IIii1i = 8
   oo0O0OO = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   i1IIii1i = 12
   oo0O0OO = bold ( "aes-gcm" , False )
  else :
   i1IIii1i = 16
   oo0O0OO = bold ( "aes-cbc" , False )
   if 60 - 60: Ii1I % Oo0Ooo / I11i . iII111i / I1Ii111 - OoooooooOO
  Oo0OOOO0oOoo0 = packet [ 0 : i1IIii1i ]
  if 76 - 76: O0
  if 71 - 71: I1IiiI . i1IIi
  if 19 - 19: II111iiii / II111iiii % I1ii11iIi11i + oO0o + oO0o + iII111i
  if 4 - 4: o0oOOo0O0Ooo + I11i / iII111i + i1IIi % o0oOOo0O0Ooo % iII111i
  ooOooOooOOO = key . do_icv ( IiIIiII1I + packet , Oo0OOOO0oOoo0 )
  if 59 - 59: I11i
  OO = "0x{}...{}" . format ( I1ii1i11iI1 [ 0 : o0 ] , I1ii1i11iI1 [ - o0 : : ] )
  I1i = "0x{}...{}" . format ( ooOooOooOOO [ 0 : o0 ] , ooOooOooOOO [ - o0 : : ] )
  if 47 - 47: iII111i . OoOoOO00
  if ( ooOooOooOOO != I1ii1i11iI1 ) :
   self . packet_error = "ICV-error"
   o0oOO0 = oo0O0OO + "/" + IiOOo0
   I11II11IiI11 = bold ( "ICV failed ({})" . format ( o0oOO0 ) , False )
   IIi = "packet-ICV {} != computed-ICV {}" . format ( OO , I1i )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( I11II11IiI11 , red ( addr_str , False ) ,
   # OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
 self . udp_sport , key . key_id , IIi ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 46 - 46: i11iIiiIii
   if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
   if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
   if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
   if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
   if 65 - 65: OoooooooOO
   lisp_retry_decap_keys ( addr_str , IiIIiII1I + packet , Oo0OOOO0oOoo0 , I1ii1i11iI1 )
   return ( [ None , False ] )
   if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
   if 83 - 83: ooOoO0o
   if 43 - 43: OOooOOo
   if 84 - 84: OOooOOo . IiII . iII111i
   if 2 - 2: Oo0Ooo - OoOoOO00
  packet = packet [ i1IIii1i : : ]
  if 49 - 49: Ii1I + II111iiii / oO0o - OoOoOO00 % OoOoOO00 + I1IiiI
  if 54 - 54: ooOoO0o % Oo0Ooo - OOooOOo
  if 16 - 16: I1ii11iIi11i * iII111i / I11i
  if 46 - 46: II111iiii
  iIiIIIIIii = lisp_get_timestamp ( )
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   i11iIi = chacha . ChaCha ( key . encrypt_key , Oo0OOOO0oOoo0 ) . decrypt
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   o00o = binascii . unhexlify ( key . encrypt_key )
   try :
    i11iIi = AES . new ( o00o , AES . MODE_GCM , Oo0OOOO0oOoo0 ) . decrypt
   except :
    self . packet_error = "no-decrypt-key"
    lprint ( "You need AES-GCM, do a 'pip install pycryptodome'" )
    return ( [ None , False ] )
    if 82 - 82: Oo0Ooo / I1IiiI . I1ii11iIi11i - Oo0Ooo
  else :
   if ( ( len ( packet ) % 16 ) != 0 ) :
    dprint ( "Ciphertext not multiple of 16 bytes, packet dropped" )
    return ( [ None , False ] )
    if 4 - 4: O0 / I11i . OoO0O00 - ooOoO0o / OOooOOo
   o00o = binascii . unhexlify ( key . encrypt_key )
   i11iIi = AES . new ( o00o , AES . MODE_CBC , Oo0OOOO0oOoo0 ) . decrypt
   if 25 - 25: I11i * OoOoOO00 - Oo0Ooo . ooOoO0o . oO0o
   if 89 - 89: O0 * I11i * OoO0O00
  II11I = i11iIi ( packet )
  iIiIIIIIii = int ( str ( time . time ( ) - iIiIIIIIii ) . split ( "." ) [ 1 ] [ 0 : 6 ] )
  if 12 - 12: I1IiiI / o0oOOo0O0Ooo
  if 86 - 86: Oo0Ooo % OoOoOO00
  if 77 - 77: Ii1I % OOooOOo / oO0o
  if 91 - 91: OoO0O00 / OoO0O00 . II111iiii . ooOoO0o - I1IiiI
  I1i1iI = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  i11II = "poly" if key . do_poly else "sha256"
  i11II = bold ( i11II , False )
  IIi = "ICV({}): {}" . format ( i11II , OO )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( I1i1iI , key . key_id , addr_str , IIi , oo0O0OO , iIiIIIIIii ) )
  if 23 - 23: I1IiiI
  if 7 - 7: iII111i % I1ii11iIi11i
  if 64 - 64: I1Ii111 + i11iIiiIii
  if 35 - 35: OoOoOO00 + i1IIi % OOooOOo
  if 68 - 68: IiII . ooOoO0o
  if 64 - 64: i1IIi + Oo0Ooo * I1IiiI / OOooOOo
  if 3 - 3: Oo0Ooo / ooOoO0o + ooOoO0o . I1ii11iIi11i
  self . packet = self . packet [ 0 : header_length ]
  return ( [ II11I , True ] )
  if 50 - 50: iIii1I11I1II1 * oO0o
  if 85 - 85: i1IIi
 def fragment_outer ( self , outer_hdr , inner_packet ) :
  Oo00 = 1000
  if 41 - 41: OoO0O00 % I1IiiI - Oo0Ooo
  if 11 - 11: Ii1I * o0oOOo0O0Ooo / IiII + OoOoOO00 + OoO0O00 % I1Ii111
  if 18 - 18: I1IiiI - OoOoOO00
  if 18 - 18: OOooOOo + OoO0O00 * oO0o - oO0o . I1ii11iIi11i * I11i
  if 95 - 95: I1ii11iIi11i / OoOoOO00
  i1II11iI1i = [ ]
  II1Ii = 0
  OOOOo0o0O0o = len ( inner_packet )
  while ( II1Ii < OOOOo0o0O0o ) :
   IiI111 = inner_packet [ II1Ii : : ]
   if ( len ( IiI111 ) > Oo00 ) : IiI111 = IiI111 [ 0 : Oo00 ]
   i1II11iI1i . append ( IiI111 )
   II1Ii += len ( IiI111 )
   if 94 - 94: II111iiii / i1IIi * i1IIi + ooOoO0o - ooOoO0o % o0oOOo0O0Ooo
   if 12 - 12: I1Ii111 / OoOoOO00 . i11iIiiIii * i11iIiiIii
   if 68 - 68: IiII * OoO0O00 . I11i / Ii1I . o0oOOo0O0Ooo - i11iIiiIii
   if 49 - 49: Oo0Ooo / Ii1I % I11i + oO0o - OoO0O00
   if 13 - 13: II111iiii
   if 83 - 83: OoooooooOO . I1IiiI + Ii1I * O0 / oO0o
  IiiiI11 = [ ]
  II1Ii = 0
  for IiI111 in i1II11iI1i :
   if 57 - 57: iIii1I11I1II1 % i1IIi / Oo0Ooo + II111iiii
   if 95 - 95: oO0o
   if 48 - 48: I11i / iIii1I11I1II1 % II111iiii
   if 39 - 39: i1IIi . I1ii11iIi11i / I11i / I11i
   ooOo0oO0O = II1Ii if ( IiI111 == i1II11iI1i [ - 1 ] ) else 0x2000 + II1Ii
   ooOo0oO0O = socket . htons ( ooOo0oO0O )
   outer_hdr = outer_hdr [ 0 : 6 ] + struct . pack ( "H" , ooOo0oO0O ) + outer_hdr [ 8 : : ]
   if 17 - 17: IiII / I1Ii111 . I1IiiI + i1IIi
   if 28 - 28: oO0o % OoOoOO00 + I1Ii111 * iII111i * Ii1I
   if 53 - 53: OOooOOo / Oo0Ooo
   if 10 - 10: I1ii11iIi11i . o0oOOo0O0Ooo
   OoOoo00Oo0OoO = socket . htons ( len ( IiI111 ) + 20 )
   outer_hdr = outer_hdr [ 0 : 2 ] + struct . pack ( "H" , OoOoo00Oo0OoO ) + outer_hdr [ 4 : : ]
   outer_hdr = lisp_ip_checksum ( outer_hdr )
   IiiiI11 . append ( outer_hdr + IiI111 )
   II1Ii += len ( IiI111 ) / 8
   if 56 - 56: OoooooooOO
  return ( IiiiI11 )
  if 84 - 84: I1Ii111
  if 53 - 53: i1IIi
 def send_icmp_too_big ( self , inner_packet ) :
  global lisp_last_icmp_too_big_sent
  global lisp_icmp_raw_socket
  if 59 - 59: o0oOOo0O0Ooo + I1IiiI % OoooooooOO - iIii1I11I1II1
  o0oOOOO0 = time . time ( ) - lisp_last_icmp_too_big_sent
  if ( o0oOOOO0 < LISP_ICMP_TOO_BIG_RATE_LIMIT ) :
   lprint ( "Rate limit sending ICMP Too-Big to {}" . format ( self . inner_source . print_address_no_iid ( ) ) )
   if 9 - 9: i1IIi - OoOoOO00
   return ( False )
   if 57 - 57: iIii1I11I1II1 * Ii1I * iII111i / oO0o
   if 46 - 46: Ii1I
   if 61 - 61: o0oOOo0O0Ooo / ooOoO0o - II111iiii
   if 87 - 87: I1ii11iIi11i / I1IiiI
   if 45 - 45: OoOoOO00 * ooOoO0o / OoooooooOO + OoO0O00 . I1Ii111 / OoO0O00
   if 64 - 64: Ii1I / i1IIi % I1IiiI - o0oOOo0O0Ooo
   if 11 - 11: I1ii11iIi11i - OoooooooOO
   if 16 - 16: IiII % OoooooooOO - ooOoO0o * Ii1I - Ii1I
   if 27 - 27: IiII + iIii1I11I1II1 / Oo0Ooo + OoO0O00 % Oo0Ooo + OoO0O00
   if 77 - 77: Oo0Ooo * ooOoO0o % Ii1I
   if 2 - 2: I11i / Oo0Ooo / Ii1I / I1ii11iIi11i / OoooooooOO
   if 22 - 22: iIii1I11I1II1 * I1IiiI / I11i + OoOoOO00
   if 98 - 98: OOooOOo
   if 69 - 69: II111iiii + Oo0Ooo - oO0o . Oo0Ooo / iIii1I11I1II1 * iIii1I11I1II1
   if 75 - 75: OoO0O00 % OoooooooOO
  iiiI = socket . htons ( 1400 )
  Ii11iiI1 = struct . pack ( "BBHHH" , 3 , 4 , 0 , 0 , iiiI )
  Ii11iiI1 += inner_packet [ 0 : 20 + 8 ]
  Ii11iiI1 = lisp_icmp_checksum ( Ii11iiI1 )
  if 77 - 77: II111iiii - i11iIiiIii
  if 78 - 78: Ii1I
  if 72 - 72: I1Ii111 * OoO0O00
  if 89 - 89: OoOoOO00 + I1IiiI
  if 68 - 68: I11i / iIii1I11I1II1 . Oo0Ooo + i11iIiiIii + o0oOOo0O0Ooo
  if 92 - 92: OoO0O00 . o0oOOo0O0Ooo . Ii1I % OoOoOO00
  if 58 - 58: I1ii11iIi11i % Ii1I * Ii1I - iII111i
  I111IiI11 = inner_packet [ 12 : 16 ]
  oOO00OoOo = self . inner_source . print_address_no_iid ( )
  oOoo = self . outer_source . pack_address ( )
  if 68 - 68: OOooOOo + Ii1I
  if 58 - 58: IiII * Ii1I . i1IIi
  if 19 - 19: oO0o
  if 85 - 85: ooOoO0o - I1IiiI / i1IIi / OoO0O00 / II111iiii
  if 94 - 94: iIii1I11I1II1 + IiII
  if 44 - 44: OoO0O00 + I11i % OoO0O00 + i1IIi + iII111i + O0
  if 18 - 18: iIii1I11I1II1 % iIii1I11I1II1 % oO0o + I1IiiI % ooOoO0o / Ii1I
  if 36 - 36: OoOoOO00 . i11iIiiIii
  IiIIiiiIi = socket . htons ( 20 + 36 )
  ooooO000 = struct . pack ( "BBHHHBBH" , 0x45 , 0 , IiIIiiiIi , 0 , 0 , 32 , 1 , 0 ) + oOoo + I111IiI11
  ooooO000 = lisp_ip_checksum ( ooooO000 )
  ooooO000 = self . fix_outer_header ( ooooO000 )
  ooooO000 += Ii11iiI1
  oO00O0o0oOOO = bold ( "Too-Big" , False )
  lprint ( "Send ICMP {} to {}, mtu 1400: {}" . format ( oO00O0o0oOOO , oOO00OoOo ,
 lisp_format_packet ( ooooO000 ) ) )
  if 96 - 96: I1IiiI - iIii1I11I1II1
  try :
   lisp_icmp_raw_socket . sendto ( ooooO000 , ( oOO00OoOo , 0 ) )
  except socket . error as oOO :
   lprint ( "lisp_icmp_raw_socket.sendto() failed: {}" . format ( oOO ) )
   return ( False )
   if 25 - 25: OoooooooOO . Ii1I % iII111i . IiII
   if 67 - 67: OoooooooOO + I1Ii111 / ooOoO0o
   if 75 - 75: IiII / OoooooooOO . I1IiiI + I1Ii111 - II111iiii
   if 33 - 33: IiII / IiII . i11iIiiIii * I1ii11iIi11i + o0oOOo0O0Ooo
   if 16 - 16: IiII
   if 10 - 10: OoOoOO00 . IiII * iIii1I11I1II1 - oO0o - OoOoOO00 / I1Ii111
  lisp_last_icmp_too_big_sent = lisp_get_timestamp ( )
  return ( True )
  if 13 - 13: oO0o + OoOoOO00 % IiII % OoooooooOO
 def fragment ( self ) :
  global lisp_icmp_raw_socket
  global lisp_ignore_df_bit
  if 22 - 22: I1Ii111
  Oo00O0o0O = self . fix_outer_header ( self . packet )
  if 23 - 23: O0
  if 41 - 41: i1IIi . OOooOOo / ooOoO0o / o0oOOo0O0Ooo % IiII - Ii1I
  if 14 - 14: I1ii11iIi11i - i11iIiiIii * I1Ii111
  if 39 - 39: OoooooooOO
  if 19 - 19: i11iIiiIii
  if 80 - 80: I1IiiI
  OOOOo0o0O0o = len ( Oo00O0o0O )
  if ( OOOOo0o0O0o <= 1500 ) : return ( [ Oo00O0o0O ] , "Fragment-None" )
  if 58 - 58: oO0o + I1ii11iIi11i % OoOoOO00
  Oo00O0o0O = self . packet
  if 22 - 22: iIii1I11I1II1 - Ii1I / I1IiiI * IiII
  if 26 - 26: o0oOOo0O0Ooo + OOooOOo - o0oOOo0O0Ooo + Oo0Ooo . oO0o
  if 97 - 97: i1IIi
  if 46 - 46: I1ii11iIi11i
  if 30 - 30: OoO0O00 / O0 * o0oOOo0O0Ooo * I1Ii111 + OoooooooOO * iII111i
  if ( self . inner_version != 4 ) :
   iIIi1I1Ii1 = random . randint ( 0 , 0xffff )
   ooOOo0O0o00o00 = Oo00O0o0O [ 0 : 4 ] + struct . pack ( "H" , iIIi1I1Ii1 ) + Oo00O0o0O [ 6 : 20 ]
   o0oI1I1i = Oo00O0o0O [ 20 : : ]
   IiiiI11 = self . fragment_outer ( ooOOo0O0o00o00 , o0oI1I1i )
   return ( IiiiI11 , "Fragment-Outer" )
   if 42 - 42: iII111i
   if 77 - 77: i1IIi * oO0o % OoooooooOO + O0 * ooOoO0o
   if 28 - 28: I11i . OoooooooOO * OOooOOo + i11iIiiIii % I1IiiI . iIii1I11I1II1
   if 63 - 63: II111iiii - I11i . OoOoOO00
   if 8 - 8: I1IiiI * ooOoO0o / IiII + OoOoOO00 . IiII - OOooOOo
  Oo0O = 56 if ( self . outer_version == 6 ) else 36
  ooOOo0O0o00o00 = Oo00O0o0O [ 0 : Oo0O ]
  oO00OO0o0ooO = Oo00O0o0O [ Oo0O : Oo0O + 20 ]
  o0oI1I1i = Oo00O0o0O [ Oo0O + 20 : : ]
  if 42 - 42: O0 * iII111i . OoOoOO00 / OOooOOo - Ii1I . I11i
  if 57 - 57: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i - ooOoO0o % iIii1I11I1II1 - Ii1I
  if 37 - 37: OoO0O00 * I11i + Ii1I + I1ii11iIi11i * o0oOOo0O0Ooo
  if 95 - 95: Ii1I - i11iIiiIii % i11iIiiIii - O0 * I1Ii111
  if 81 - 81: II111iiii * I1IiiI % i1IIi * i11iIiiIii + OoOoOO00
  oo0OoOO000O = struct . unpack ( "H" , oO00OO0o0ooO [ 6 : 8 ] ) [ 0 ]
  oo0OoOO000O = socket . ntohs ( oo0OoOO000O )
  if ( oo0OoOO000O & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    Oo0o0OoOoOo0 = Oo00O0o0O [ Oo0O : : ]
    if ( self . send_icmp_too_big ( Oo0o0OoOoOo0 ) ) : return ( [ ] , None )
    if 36 - 36: Ii1I * I1IiiI * I1ii11iIi11i . I11i * I1ii11iIi11i
   if ( lisp_ignore_df_bit ) :
    oo0OoOO000O &= ~ 0x4000
   else :
    O0ooO0 = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( O0ooO0 ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 41 - 41: o0oOOo0O0Ooo % Oo0Ooo
    if 93 - 93: ooOoO0o
    if 82 - 82: I1ii11iIi11i / ooOoO0o . i11iIiiIii + OOooOOo - OoOoOO00 / iII111i
  II1Ii = 0
  OOOOo0o0O0o = len ( o0oI1I1i )
  IiiiI11 = [ ]
  while ( II1Ii < OOOOo0o0O0o ) :
   IiiiI11 . append ( o0oI1I1i [ II1Ii : II1Ii + 1400 ] )
   II1Ii += 1400
   if 99 - 99: oO0o / i1IIi
   if 2 - 2: oO0o . iII111i
   if 42 - 42: OoO0O00 - I1ii11iIi11i * IiII - ooOoO0o
   if 75 - 75: iII111i * Oo0Ooo / I1Ii111 * Oo0Ooo / ooOoO0o
   if 14 - 14: i1IIi * iIii1I11I1II1 - Ii1I * OoOoOO00 - iII111i / oO0o
  i1II11iI1i = IiiiI11
  IiiiI11 = [ ]
  OO0OOoOOO = True if oo0OoOO000O & 0x2000 else False
  oo0OoOO000O = ( oo0OoOO000O & 0x1fff ) * 8
  for IiI111 in i1II11iI1i :
   if 96 - 96: I1ii11iIi11i - O0
   if 35 - 35: OOooOOo . I11i . I1Ii111 - I11i % I11i + I1Ii111
   if 99 - 99: o0oOOo0O0Ooo + OOooOOo
   if 34 - 34: I1Ii111 * o0oOOo0O0Ooo . I1IiiI % i11iIiiIii
   Oo0OO0 = old_div ( oo0OoOO000O , 8 )
   if ( OO0OOoOOO ) :
    Oo0OO0 |= 0x2000
   elif ( IiI111 != i1II11iI1i [ - 1 ] ) :
    Oo0OO0 |= 0x2000
    if 74 - 74: Ii1I - OoooooooOO
   Oo0OO0 = socket . htons ( Oo0OO0 )
   oO00OO0o0ooO = oO00OO0o0ooO [ 0 : 6 ] + struct . pack ( "H" , Oo0OO0 ) + oO00OO0o0ooO [ 8 : : ]
   if 19 - 19: iIii1I11I1II1 + I1Ii111 . I1Ii111 - Oo0Ooo
   if 41 - 41: I1IiiI . Oo0Ooo . IiII % OoooooooOO + OoO0O00
   if 23 - 23: I1IiiI - o0oOOo0O0Ooo % oO0o . O0 * OoooooooOO + ooOoO0o
   if 53 - 53: Oo0Ooo
   if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
   if 58 - 58: IiII % iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * iII111i
   OOOOo0o0O0o = len ( IiI111 )
   oo0OoOO000O += OOOOo0o0O0o
   OoOoo00Oo0OoO = socket . htons ( OOOOo0o0O0o + 20 )
   oO00OO0o0ooO = oO00OO0o0ooO [ 0 : 2 ] + struct . pack ( "H" , OoOoo00Oo0OoO ) + oO00OO0o0ooO [ 4 : 10 ] + struct . pack ( "H" , 0 ) + oO00OO0o0ooO [ 12 : : ]
   if 32 - 32: OoooooooOO + o0oOOo0O0Ooo
   oO00OO0o0ooO = lisp_ip_checksum ( oO00OO0o0ooO )
   o0000OOOo = oO00OO0o0ooO + IiI111
   if 56 - 56: i1IIi + OoooooooOO % OoO0O00
   if 36 - 36: iII111i * I11i * O0 * OOooOOo - o0oOOo0O0Ooo / I1ii11iIi11i
   if 54 - 54: i1IIi - OoO0O00 / OoooooooOO
   if 95 - 95: O0 + iIii1I11I1II1 . I1ii11iIi11i
   if 61 - 61: Ii1I * Ii1I
   OOOOo0o0O0o = len ( o0000OOOo )
   if ( self . outer_version == 4 ) :
    OoOoo00Oo0OoO = OOOOo0o0O0o + Oo0O
    OOOOo0o0O0o += 16
    ooOOo0O0o00o00 = ooOOo0O0o00o00 [ 0 : 2 ] + struct . pack ( "H" , OoOoo00Oo0OoO ) + ooOOo0O0o00o00 [ 4 : : ]
    if 70 - 70: I1Ii111 . I1ii11iIi11i / o0oOOo0O0Ooo * oO0o
    ooOOo0O0o00o00 = lisp_ip_checksum ( ooOOo0O0o00o00 )
    o0000OOOo = ooOOo0O0o00o00 + o0000OOOo
    o0000OOOo = self . fix_outer_header ( o0000OOOo )
    if 74 - 74: I1IiiI . ooOoO0o / iII111i . IiII
    if 74 - 74: Oo0Ooo / I1Ii111 % I1Ii111 . IiII
    if 72 - 72: i1IIi
    if 21 - 21: I1Ii111 . OOooOOo / i11iIiiIii * i1IIi
    if 82 - 82: ooOoO0o * Oo0Ooo % i11iIiiIii * i1IIi . OOooOOo
   o0Oo00o0 = Oo0O - 12
   OoOoo00Oo0OoO = socket . htons ( OOOOo0o0O0o )
   o0000OOOo = o0000OOOo [ 0 : o0Oo00o0 ] + struct . pack ( "H" , OoOoo00Oo0OoO ) + o0000OOOo [ o0Oo00o0 + 2 : : ]
   if 42 - 42: I1Ii111 / OoOoOO00 % oO0o
   IiiiI11 . append ( o0000OOOo )
   if 63 - 63: OoO0O00 % i1IIi - oO0o
  return ( IiiiI11 , "Fragment-Inner" )
  if 12 - 12: OoooooooOO + I1Ii111 / OOooOOo / Oo0Ooo * II111iiii - I1ii11iIi11i
  if 11 - 11: iII111i
 def fix_outer_header ( self , packet ) :
  if 89 - 89: OoOoOO00 - ooOoO0o . iIii1I11I1II1 + iII111i / Ii1I / iII111i
  if 25 - 25: iIii1I11I1II1 + i11iIiiIii - Ii1I * OoooooooOO
  if 22 - 22: I1Ii111 - I1IiiI
  if 96 - 96: i1IIi + Oo0Ooo - II111iiii . OoooooooOO . OOooOOo / OoO0O00
  if 88 - 88: i1IIi
  if 53 - 53: ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
  if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
  if 57 - 57: oO0o
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 : 4 ] + packet [ 2 : 3 ] + packet [ 4 : 6 ] + packet [ 7 : 8 ] + packet [ 6 : 7 ] + packet [ 8 : : ]
    if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 : 4 ] + packet [ 2 : 3 ] + packet [ 4 : : ]
    if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
    if 37 - 37: iII111i
  return ( packet )
  if 15 - 15: o0oOOo0O0Ooo % OoO0O00 / iII111i
  if 36 - 36: OoO0O00 + OoO0O00 % Oo0Ooo + Oo0Ooo / i1IIi % i1IIi
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 20 - 20: OOooOOo * oO0o
  dest = dest . print_address_no_iid ( )
  IiiiI11 , OOOoooOo00O = self . fragment ( )
  if 6 - 6: OoooooooOO - Oo0Ooo
  for o0000OOOo in IiiiI11 :
   if ( len ( IiiiI11 ) != 1 ) :
    self . packet = o0000OOOo
    self . print_packet ( OOOoooOo00O , True )
    if 52 - 52: OOooOOo + Oo0Ooo
    if 67 - 67: I1ii11iIi11i % OoooooooOO
   try : lisp_raw_socket . sendto ( o0000OOOo , ( dest , 0 ) )
   except socket . error as oOO :
    lprint ( "socket.sendto() failed: {}" . format ( oOO ) )
    if 41 - 41: OoO0O00 / IiII + I1Ii111 . I1Ii111 / oO0o
    if 74 - 74: Ii1I % i11iIiiIii . O0 * I1IiiI * i1IIi * OoooooooOO
    if 22 - 22: I1Ii111 + iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoooooooOO
    if 42 - 42: OoooooooOO - OoOoOO00 - OOooOOo * I1Ii111
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 98 - 98: OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
   if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
  Oo00O0o0O = mac_header + self . packet
  if 95 - 95: oO0o
  if 80 - 80: IiII
  if 42 - 42: OoooooooOO * II111iiii
  if 53 - 53: I1Ii111 + i1IIi . OoO0O00 / i11iIiiIii + Ii1I % OoOoOO00
  if 9 - 9: ooOoO0o . I11i - Oo0Ooo . I1Ii111
  if 39 - 39: OOooOOo
  if 70 - 70: IiII % OoO0O00 % I1IiiI
  if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
  if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
  if 2 - 2: oO0o * oO0o . OoOoOO00 * Ii1I * iIii1I11I1II1
  if 13 - 13: I11i / O0 . i11iIiiIii * i1IIi % i11iIiiIii
  l2_socket . write ( Oo00O0o0O )
  return
  if 8 - 8: OoOoOO00 - OoooooooOO
  if 99 - 99: II111iiii / IiII % OoooooooOO . i11iIiiIii
 def bridge_l2_packet ( self , eid , db ) :
  try : iI1 = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : o0o = lisp_myinterfaces [ iI1 . interface ]
  except : return
  try :
   socket = o0o . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 70 - 70: OoooooooOO . ooOoO0o / oO0o . oO0o - o0oOOo0O0Ooo
  try : socket . send ( self . packet )
  except socket . error as oOO :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( oOO ) )
   if 29 - 29: I11i % OOooOOo - ooOoO0o
   if 26 - 26: O0 . I11i + iII111i - Ii1I . I11i
   if 2 - 2: I1ii11iIi11i . Oo0Ooo * OOooOOo % II111iiii . iII111i
 def is_lisp_packet ( self , packet ) :
  ii11 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( ii11 == False ) : return ( False )
  if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
  i11I1Ii1Iiii1 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( i11I1Ii1Iiii1 ) == LISP_DATA_PORT ) : return ( True )
  i11I1Ii1Iiii1 = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( i11I1Ii1Iiii1 ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 64 - 64: Ii1I . OoooooooOO - I1ii11iIi11i
  if 19 - 19: Oo0Ooo
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  Oo00O0o0O = self . packet
  iI = len ( Oo00O0o0O )
  IiI1I1i1 = Iii11I = True
  if 2 - 2: oO0o . OOooOOo
  if 43 - 43: iIii1I11I1II1
  if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
  if 24 - 24: I1Ii111 / Ii1I * I1ii11iIi11i - OoooooooOO / I1IiiI . oO0o
  oo0OOoOo0 = 0
  i1I1iI = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   oO00oO0 = struct . unpack ( "B" , Oo00O0o0O [ 0 : 1 ] ) [ 0 ]
   self . outer_version = oO00oO0 >> 4
   if ( self . outer_version == 4 ) :
    if 80 - 80: iII111i . O0
    if 25 - 25: iII111i / iIii1I11I1II1 + I1IiiI / ooOoO0o
    if 61 - 61: oO0o % I1ii11iIi11i * I11i . I11i
    if 20 - 20: Ii1I / iII111i + II111iiii . i11iIiiIii . OOooOOo
    if 77 - 77: OoOoOO00
    oOO0ooo0O = struct . unpack ( "H" , Oo00O0o0O [ 10 : 12 ] ) [ 0 ]
    Oo00O0o0O = lisp_ip_checksum ( Oo00O0o0O )
    O0OoO0o = struct . unpack ( "H" , Oo00O0o0O [ 10 : 12 ] ) [ 0 ]
    if ( O0OoO0o != 0 ) :
     if ( oOO0ooo0O != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( iI )
       if 17 - 17: ooOoO0o
       if 13 - 13: Oo0Ooo - I11i / oO0o - Oo0Ooo - iII111i / i11iIiiIii
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 29 - 29: IiII - I11i . O0 . O0
      if 16 - 16: i1IIi * ooOoO0o % OoO0O00 + Ii1I
      if 50 - 50: oO0o - OoooooooOO + iII111i % OoO0O00
    IiIIi = LISP_AFI_IPV4
    II1Ii = 12
    self . outer_tos = struct . unpack ( "B" , Oo00O0o0O [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , Oo00O0o0O [ 8 : 9 ] ) [ 0 ]
    oo0OOoOo0 = 20
   elif ( self . outer_version == 6 ) :
    IiIIi = LISP_AFI_IPV6
    II1Ii = 8
    oo = struct . unpack ( "H" , Oo00O0o0O [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( oo ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , Oo00O0o0O [ 7 : 8 ] ) [ 0 ]
    oo0OOoOo0 = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( iI )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 24 - 24: IiII
    if 51 - 51: OOooOOo % i11iIiiIii
   self . outer_source . afi = IiIIi
   self . outer_dest . afi = IiIIi
   o0OoOoOo0O = self . outer_source . addr_length ( )
   if 37 - 37: i1IIi . I1Ii111 - II111iiii % o0oOOo0O0Ooo - i1IIi . oO0o
   self . outer_source . unpack_address ( Oo00O0o0O [ II1Ii : II1Ii + o0OoOoOo0O ] )
   II1Ii += o0OoOoOo0O
   self . outer_dest . unpack_address ( Oo00O0o0O [ II1Ii : II1Ii + o0OoOoOo0O ] )
   Oo00O0o0O = Oo00O0o0O [ oo0OOoOo0 : : ]
   self . outer_source . mask_len = self . outer_source . host_mask_len ( )
   self . outer_dest . mask_len = self . outer_dest . host_mask_len ( )
   if 34 - 34: iIii1I11I1II1 / II111iiii
   if 3 - 3: o0oOOo0O0Ooo - OoooooooOO + iII111i . I11i
   if 88 - 88: I11i - iII111i
   if 68 - 68: Oo0Ooo % oO0o . IiII - o0oOOo0O0Ooo / i1IIi / OoooooooOO
   i1II11II11 = struct . unpack ( "H" , Oo00O0o0O [ 0 : 2 ] ) [ 0 ]
   self . udp_sport = socket . ntohs ( i1II11II11 )
   i1II11II11 = struct . unpack ( "H" , Oo00O0o0O [ 2 : 4 ] ) [ 0 ]
   self . udp_dport = socket . ntohs ( i1II11II11 )
   i1II11II11 = struct . unpack ( "H" , Oo00O0o0O [ 4 : 6 ] ) [ 0 ]
   self . udp_length = socket . ntohs ( i1II11II11 )
   i1II11II11 = struct . unpack ( "H" , Oo00O0o0O [ 6 : 8 ] ) [ 0 ]
   self . udp_checksum = socket . ntohs ( i1II11II11 )
   Oo00O0o0O = Oo00O0o0O [ 8 : : ]
   if 94 - 94: iIii1I11I1II1
   if 1 - 1: O0
   if 2 - 2: OoO0O00 . I11i
   if 97 - 97: Oo0Ooo
   IiI1I1i1 = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   Iii11I = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 65 - 65: Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1 . I1Ii111 + ooOoO0o
   if 92 - 92: oO0o
   if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
   if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
   if ( self . lisp_header . decode ( Oo00O0o0O ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( iI )
    if 47 - 47: IiII . OOooOOo
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
   Oo00O0o0O = Oo00O0o0O [ 8 : : ]
   i1I1iI = self . lisp_header . get_instance_id ( )
   oo0OOoOo0 += 16
   if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
  if ( i1I1iI == 0xffffff ) : i1I1iI = 0
  if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
  if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
  if 89 - 89: ooOoO0o * I1IiiI . oO0o
  if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
  I111Ii1I1I1iI = False
  IIIOo0O = self . lisp_header . k_bits
  if ( IIIOo0O ) :
   O00oO000Oo0 = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( O00oO000Oo0 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( iI )
    if 11 - 11: O0
    self . print_packet ( "Receive" , is_lisp_packet )
    o0Oo0o = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( o0Oo0o , IIIOo0O ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 4 - 4: OoooooooOO
    if 78 - 78: II111iiii
   oO0oOo = lisp_crypto_keys_by_rloc_decap [ O00oO000Oo0 ] [ IIIOo0O ]
   if ( oO0oOo == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( iI )
    if 43 - 43: oO0o + OoOoOO00 . I1IiiI . i11iIiiIii
    self . print_packet ( "Receive" , is_lisp_packet )
    o0Oo0o = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( o0Oo0o ,
 red ( O00oO000Oo0 , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 71 - 71: o0oOOo0O0Ooo + OOooOOo . Oo0Ooo - OoOoOO00 * i11iIiiIii . OoOoOO00
    if 91 - 91: O0 - I11i % I1Ii111
    if 46 - 46: ooOoO0o / I1IiiI . IiII % OoO0O00 / i11iIiiIii
    if 13 - 13: I1Ii111 % o0oOOo0O0Ooo + OOooOOo + I1Ii111 + i11iIiiIii - I1ii11iIi11i
    if 70 - 70: II111iiii * II111iiii . I1IiiI
   oO0oOo . use_count += 1
   Oo00O0o0O , I111Ii1I1I1iI = self . decrypt ( Oo00O0o0O , oo0OOoOo0 , oO0oOo , O00oO000Oo0 )
   if ( I111Ii1I1I1iI == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( iI )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 11 - 11: iII111i
    if 20 - 20: Ii1I . I1Ii111 % Ii1I
    if 5 - 5: OOooOOo + iII111i
    if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
    if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
    if 11 - 11: I1ii11iIi11i / O0 + II111iiii
   if ( oO0oOo . cipher_suite == LISP_CS_25519_CHACHA ) :
    Oo00O0o0O = Oo00O0o0O . encode ( "raw_unicode_escape" )
    if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
    if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
    if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
    if 2 - 2: Ii1I
    if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
    if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
  oO00oO0 = struct . unpack ( "B" , Oo00O0o0O [ 0 : 1 ] ) [ 0 ]
  self . inner_version = oO00oO0 >> 4
  if ( IiI1I1i1 and self . inner_version == 4 and oO00oO0 >= 0x45 ) :
   oO0 = socket . ntohs ( struct . unpack ( "H" , Oo00O0o0O [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , Oo00O0o0O [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , Oo00O0o0O [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , Oo00O0o0O [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( Oo00O0o0O [ 12 : 16 ] )
   self . inner_dest . unpack_address ( Oo00O0o0O [ 16 : 20 ] )
   oo0OoOO000O = socket . ntohs ( struct . unpack ( "H" , Oo00O0o0O [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( oo0OoOO000O & 0x2000 or oo0OoOO000O != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , Oo00O0o0O [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , Oo00O0o0O [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 7 - 7: I1ii11iIi11i * Ii1I / Oo0Ooo * i1IIi
  elif ( IiI1I1i1 and self . inner_version == 6 and oO00oO0 >= 0x60 ) :
   oO0 = socket . ntohs ( struct . unpack ( "H" , Oo00O0o0O [ 4 : 6 ] ) [ 0 ] ) + 40
   oo = struct . unpack ( "H" , Oo00O0o0O [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( oo ) >> 4 ) & 0xff
   self . inner_ttl = struct . unpack ( "B" , Oo00O0o0O [ 7 : 8 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , Oo00O0o0O [ 6 : 7 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV6
   self . inner_dest . afi = LISP_AFI_IPV6
   self . inner_source . unpack_address ( Oo00O0o0O [ 8 : 24 ] )
   self . inner_dest . unpack_address ( Oo00O0o0O [ 24 : 40 ] )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , Oo00O0o0O [ 40 : 42 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , Oo00O0o0O [ 42 : 44 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 27 - 27: OoO0O00
  elif ( Iii11I ) :
   oO0 = len ( Oo00O0o0O )
   self . inner_tos = 0
   self . inner_ttl = 0
   self . inner_protocol = 0
   self . inner_source . afi = LISP_AFI_MAC
   self . inner_dest . afi = LISP_AFI_MAC
   self . inner_dest . unpack_address ( self . swap_mac ( Oo00O0o0O [ 0 : 6 ] ) )
   self . inner_source . unpack_address ( self . swap_mac ( Oo00O0o0O [ 6 : 12 ] ) )
  elif ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   if ( lisp_flow_logging ) : self . log_flow ( False )
   return ( self )
  else :
   self . packet_error = "bad-inner-version"
   if ( stats ) : stats [ self . packet_error ] . increment ( iI )
   if 88 - 88: OOooOOo . Oo0Ooo * IiII - iIii1I11I1II1 % oO0o
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( oO00oO0 ) ) )
   if 80 - 80: Ii1I - I1ii11iIi11i . Ii1I / i11iIiiIii + O0 . IiII
   Oo00O0o0O = lisp_format_packet ( Oo00O0o0O [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( Oo00O0o0O ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 15 - 15: Oo0Ooo + iII111i + I1IiiI * o0oOOo0O0Ooo
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = i1I1iI
  self . inner_dest . instance_id = i1I1iI
  if 33 - 33: o0oOOo0O0Ooo * Oo0Ooo
  if 88 - 88: I1Ii111 % OOooOOo - OoOoOO00 - OoOoOO00 . I1IiiI
  if 52 - 52: II111iiii / II111iiii / I1IiiI - I1Ii111
  if 91 - 91: I1IiiI + o0oOOo0O0Ooo % II111iiii + OoO0O00
  if 66 - 66: iIii1I11I1II1 * II111iiii % Oo0Ooo % I1IiiI - Ii1I
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   o0Oo00oOOo = lisp_get_echo_nonce ( self . outer_source , None )
   if ( o0Oo00oOOo == None ) :
    iIiIi111 = self . outer_source . print_address_no_iid ( )
    o0Oo00oOOo = lisp_echo_nonce ( iIiIi111 )
    if 1 - 1: I1Ii111 * OoOoOO00
   OOooO = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    o0Oo00oOOo . receive_request ( lisp_ipc_socket , OOooO )
   elif ( o0Oo00oOOo . request_nonce_sent ) :
    o0Oo00oOOo . receive_echo ( lisp_ipc_socket , OOooO )
    if 99 - 99: Oo0Ooo + OoooooooOO . iII111i + O0
    if 85 - 85: II111iiii - Ii1I
    if 93 - 93: IiII / i11iIiiIii - oO0o + OoO0O00 / i1IIi
    if 62 - 62: I1ii11iIi11i / OoooooooOO * I1IiiI - i1IIi
    if 81 - 81: oO0o / O0 * ooOoO0o % OoOoOO00 / O0
    if 85 - 85: OoooooooOO + OoooooooOO
    if 23 - 23: i1IIi
  if ( I111Ii1I1I1iI ) : self . packet += Oo00O0o0O [ : oO0 ]
  if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
  if 74 - 74: Oo0Ooo - II111iiii - IiII
  if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
  if 70 - 70: i1IIi % OoO0O00 / i1IIi
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 30 - 30: OoOoOO00 - i11iIiiIii
  if 94 - 94: OoOoOO00 % iII111i
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 39 - 39: OoOoOO00 + I1Ii111 % O0
  if 26 - 26: ooOoO0o + OoOoOO00
 def strip_outer_headers ( self ) :
  II1Ii = 16
  II1Ii += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ II1Ii : : ]
  return ( self )
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
  if 6 - 6: I1Ii111
 def hash_ports ( self ) :
  Oo00O0o0O = self . packet
  oO00oO0 = self . inner_version
  ii1iiIiiiI11 = 0
  if ( oO00oO0 == 4 ) :
   o00o0o0o = struct . unpack ( "B" , Oo00O0o0O [ 9 : 10 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( o00o0o0o )
   if ( o00o0o0o in [ 6 , 17 ] ) :
    ii1iiIiiiI11 = o00o0o0o
    ii1iiIiiiI11 += struct . unpack ( "I" , Oo00O0o0O [ 20 : 24 ] ) [ 0 ]
    ii1iiIiiiI11 = ( ii1iiIiiiI11 >> 16 ) ^ ( ii1iiIiiiI11 & 0xffff )
    if 11 - 11: iIii1I11I1II1 / Ii1I + OoooooooOO % i1IIi * i11iIiiIii
    if 86 - 86: i11iIiiIii - O0 - i11iIiiIii . iIii1I11I1II1 . IiII
  if ( oO00oO0 == 6 ) :
   o00o0o0o = struct . unpack ( "B" , Oo00O0o0O [ 6 : 7 ] ) [ 0 ]
   if ( o00o0o0o in [ 6 , 17 ] ) :
    ii1iiIiiiI11 = o00o0o0o
    ii1iiIiiiI11 += struct . unpack ( "I" , Oo00O0o0O [ 40 : 44 ] ) [ 0 ]
    ii1iiIiiiI11 = ( ii1iiIiiiI11 >> 16 ) ^ ( ii1iiIiiiI11 & 0xffff )
    if 84 - 84: i1IIi / iIii1I11I1II1 / oO0o / Ii1I
    if 7 - 7: OoOoOO00 . OOooOOo % Oo0Ooo
  return ( ii1iiIiiiI11 )
  if 55 - 55: ooOoO0o - Oo0Ooo * oO0o
  if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
 def hash_packet ( self ) :
  ii1iiIiiiI11 = self . inner_source . address ^ self . inner_dest . address
  ii1iiIiiiI11 += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   ii1iiIiiiI11 = ( ii1iiIiiiI11 >> 16 ) ^ ( ii1iiIiiiI11 & 0xffff )
  elif ( self . inner_version == 6 ) :
   ii1iiIiiiI11 = ( ii1iiIiiiI11 >> 64 ) ^ ( ii1iiIiiiI11 & 0xffffffffffffffff )
   ii1iiIiiiI11 = ( ii1iiIiiiI11 >> 32 ) ^ ( ii1iiIiiiI11 & 0xffffffff )
   ii1iiIiiiI11 = ( ii1iiIiiiI11 >> 16 ) ^ ( ii1iiIiiiI11 & 0xffff )
   if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
  self . udp_sport = 0xf000 | ( ii1iiIiiiI11 & 0xfff )
  if 64 - 64: IiII
  if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   oo000oiIIIII = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # IiII * Oo0Ooo + OoooooooOO
 green ( oo000oiIIIII , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 93 - 93: ooOoO0o
   if 15 - 15: i11iIiiIii / o0oOOo0O0Ooo / OoO0O00 . OoOoOO00 % oO0o
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   iiII1i11 = "decap"
   iiII1i11 += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   iiII1i11 = s_or_r
   if ( iiII1i11 in [ "Send" , "Replicate" ] or iiII1i11 . find ( "Fragment" ) != - 1 ) :
    iiII1i11 = "encap"
    if 57 - 57: ooOoO0o
    if 94 - 94: OoO0O00 - II111iiii % iIii1I11I1II1
  oOoo0o = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 57 - 57: OoooooooOO % II111iiii - I1Ii111
  if 1 - 1: IiII
  if 27 - 27: OoOoOO00 . I1Ii111 * OoOoOO00
  if 8 - 8: oO0o * IiII * ooOoO0o
  if 26 - 26: iII111i * OOooOOo / OOooOOo - iII111i
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   ooO = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 59 - 59: Ii1I % iII111i / II111iiii + I1IiiI * ooOoO0o
   ooO += bold ( "control-packet" , False ) + ": {} ..."
   if 100 - 100: I1ii11iIi11i
   dprint ( ooO . format ( bold ( s_or_r , False ) , red ( oOoo0o , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   ooO = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 81 - 81: I1ii11iIi11i % iII111i
   if 22 - 22: OoooooooOO + o0oOOo0O0Ooo . I11i + I1IiiI + OoooooooOO . OoOoOO00
   if 93 - 93: I1IiiI
   if 89 - 89: OoooooooOO % i11iIiiIii + I1Ii111
  if ( self . lisp_header . k_bits ) :
   if ( iiII1i11 == "encap" ) : iiII1i11 = "encrypt/encap"
   if ( iiII1i11 == "decap" ) : iiII1i11 = "decap/decrypt"
   if 12 - 12: OoOoOO00 * ooOoO0o
   if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
  oo000oiIIIII = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
  dprint ( ooO . format ( bold ( s_or_r , False ) , red ( oOoo0o , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( oo000oiIIIII , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( iiII1i11 ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 50 - 50: ooOoO0o
  if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
  if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
 def get_raw_socket ( self ) :
  i1I1iI = str ( self . lisp_header . get_instance_id ( ) )
  if ( i1I1iI == "0" ) : return ( None )
  if ( i1I1iI not in lisp_iid_to_interface ) : return ( None )
  if 29 - 29: oO0o
  o0o = lisp_iid_to_interface [ i1I1iI ]
  OOo0oOO0o0oo0 = o0o . get_socket ( )
  if ( OOo0oOO0o0oo0 == None ) :
   I1i1iI = bold ( "SO_BINDTODEVICE" , False )
   IiI1i1I11I = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( I1i1iI , "drop" if IiI1i1I11I else "forward" ) )
   if 51 - 51: OoO0O00 % iII111i
   if ( IiI1i1I11I ) : return ( None )
   if 24 - 24: I1IiiI / iIii1I11I1II1 / O0 . iIii1I11I1II1 - OoO0O00 . iIii1I11I1II1
   if 8 - 8: I1ii11iIi11i % OoO0O00 % oO0o . I1ii11iIi11i * I1ii11iIi11i
  i1I1iI = bold ( i1I1iI , False )
  oooOo = bold ( o0o . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( i1I1iI , oooOo ) )
  return ( OOo0oOO0o0oo0 )
  if 94 - 94: i11iIiiIii + OoooooooOO
  if 20 - 20: i11iIiiIii
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 86 - 86: OoOoOO00 / OOooOOo
  Iii1I = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or Iii1I ) :
   I1i11II1 = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = I1i11II1 ) . start ( )
   if ( Iii1I ) : os . system ( "rm ./log-flows" )
   return
   if 15 - 15: oO0o / I1Ii111 * OoO0O00 % oO0o % iII111i % Oo0Ooo
   if 1 - 1: o0oOOo0O0Ooo % I1IiiI / OOooOOo
  iIiIIIIIii = datetime . datetime . now ( )
  lisp_flow_log . append ( [ iIiIIIIIii , encap , self . packet , self ] )
  if 74 - 74: IiII - oO0o * OoO0O00 - I1Ii111
  if 81 - 81: o0oOOo0O0Ooo % Ii1I - i11iIiiIii
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  i1I111Iii = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 60 - 60: OOooOOo / i1IIi . I1Ii111
  ii1III11 = red ( self . outer_source . print_address_no_iid ( ) , False )
  III11IiI = red ( self . outer_dest . print_address_no_iid ( ) , False )
  IIii = green ( self . inner_source . print_address ( ) , False )
  IiIi1iI1 = green ( self . inner_dest . print_address ( ) , False )
  if 3 - 3: I11i
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   i1I111Iii += " {}:{} -> {}:{}, LISP control message type {}\n"
   i1I111Iii = i1I111Iii . format ( ii1III11 , self . udp_sport , III11IiI , self . udp_dport ,
 self . inner_version )
   return ( i1I111Iii )
   if 26 - 26: OoO0O00 % i1IIi * O0 . I1Ii111
   if 31 - 31: O0 - IiII * i11iIiiIii * i1IIi
  if ( self . outer_dest . is_null ( ) == False ) :
   i1I111Iii += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   i1I111Iii = i1I111Iii . format ( ii1III11 , self . udp_sport , III11IiI , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 78 - 78: ooOoO0o * OoOoOO00 . Ii1I . OoOoOO00 % iIii1I11I1II1
   if 67 - 67: Ii1I . Oo0Ooo
   if 39 - 39: I11i * I1Ii111
   if 63 - 63: ooOoO0o % I1IiiI . OOooOOo - ooOoO0o / Oo0Ooo % I1IiiI
   if 39 - 39: o0oOOo0O0Ooo . i1IIi % oO0o / I11i % O0
  if ( self . lisp_header . k_bits != 0 ) :
   o0O0OOooO = "\n"
   if ( self . packet_error != "" ) :
    o0O0OOooO = " ({})" . format ( self . packet_error ) + o0O0OOooO
    if 1 - 1: I1Ii111 * OoO0O00 - iII111i
   i1I111Iii += ", encrypted" + o0O0OOooO
   return ( i1I111Iii )
   if 97 - 97: iII111i . I1ii11iIi11i - iIii1I11I1II1 . ooOoO0o + I1IiiI % oO0o
   if 4 - 4: I1IiiI / II111iiii % O0 * ooOoO0o / II111iiii . Oo0Ooo
   if 16 - 16: O0 + O0 - I1IiiI
   if 30 - 30: ooOoO0o
   if 33 - 33: I1Ii111 * IiII - O0 + I1IiiI / IiII
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 19 - 19: i1IIi % II111iiii
   if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
  o00o0o0o = packet [ 9 : 10 ] if self . inner_version == 4 else packet [ 6 : 7 ]
  o00o0o0o = struct . unpack ( "B" , o00o0o0o ) [ 0 ]
  if 56 - 56: Ii1I * i11iIiiIii
  i1I111Iii += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  i1I111Iii = i1I111Iii . format ( IIii , IiIi1iI1 , len ( packet ) , self . inner_tos ,
 self . inner_ttl , o00o0o0o )
  if 92 - 92: II111iiii - O0 . I1Ii111
  if 59 - 59: OoOoOO00
  if 47 - 47: II111iiii - I1ii11iIi11i - Ii1I
  if 9 - 9: I1ii11iIi11i - IiII
  if ( o00o0o0o in [ 6 , 17 ] ) :
   o0o0 = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( o0o0 ) == 4 ) :
    o0o0 = socket . ntohl ( struct . unpack ( "I" , o0o0 ) [ 0 ] )
    i1I111Iii += ", ports {} -> {}" . format ( o0o0 >> 16 , o0o0 & 0xffff )
    if 87 - 87: i11iIiiIii * II111iiii - Ii1I % OoooooooOO
  elif ( o00o0o0o == 1 ) :
   o0oO = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( o0oO ) == 2 ) :
    o0oO = socket . ntohs ( struct . unpack ( "H" , o0oO ) [ 0 ] )
    i1I111Iii += ", icmp-seq {}" . format ( o0oO )
    if 35 - 35: I1Ii111 - i1IIi / IiII
    if 13 - 13: OoOoOO00 - OoO0O00 * OoooooooOO
  if ( self . packet_error != "" ) :
   i1I111Iii += " ({})" . format ( self . packet_error )
   if 26 - 26: OoooooooOO
  i1I111Iii += "\n"
  return ( i1I111Iii )
  if 65 - 65: OOooOOo
  if 14 - 14: ooOoO0o
 def is_trace ( self ) :
  o0o0 = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in o0o0 )
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
  if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
class lisp_data_header ( object ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 21 - 21: O0 * ooOoO0o % OoO0O00
  if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
 def print_header ( self , e_or_d ) :
  IiiI11iIi = lisp_hex_string ( self . first_long & 0xffffff )
  I1I111iIiI = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 1 - 1: Ii1I * OoooooooOO - ooOoO0o % OOooOOo - OoooooooOO
  ooO = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 83 - 83: OoooooooOO . iII111i
  return ( ooO . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 IiiI11iIi , I1I111iIiI ) )
  if 20 - 20: OoO0O00 . oO0o
  if 4 - 4: Oo0Ooo % Ii1I % OoO0O00 * iII111i % OoooooooOO
 def encode ( self ) :
  ii = "II"
  IiiI11iIi = socket . htonl ( self . first_long )
  I1I111iIiI = socket . htonl ( self . second_long )
  if 85 - 85: OoooooooOO . OoO0O00 . OoO0O00
  o00O0O0OoO = struct . pack ( ii , IiiI11iIi , I1I111iIiI )
  return ( o00O0O0OoO )
  if 83 - 83: i1IIi - OoooooooOO + OoO0O00 * I1IiiI
  if 61 - 61: iII111i % II111iiii / OoOoOO00 % I1ii11iIi11i . iIii1I11I1II1 % O0
 def decode ( self , packet ) :
  ii = "II"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( False )
  if 86 - 86: o0oOOo0O0Ooo . o0oOOo0O0Ooo . II111iiii . o0oOOo0O0Ooo
  IiiI11iIi , I1I111iIiI = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 83 - 83: OoOoOO00
  if 84 - 84: Ii1I
  self . first_long = socket . ntohl ( IiiI11iIi )
  self . second_long = socket . ntohl ( I1I111iIiI )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 70 - 70: iIii1I11I1II1
  if 45 - 45: O0 - OoOoOO00 % OOooOOo
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 100 - 100: i11iIiiIii . OOooOOo . i11iIiiIii
  if 81 - 81: I1IiiI
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 76 - 76: O0 - ooOoO0o / Ii1I . Oo0Ooo - Ii1I
  if 75 - 75: ooOoO0o % OOooOOo / o0oOOo0O0Ooo % II111iiii
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 30 - 30: o0oOOo0O0Ooo
  if 15 - 15: II111iiii - Ii1I - iII111i . oO0o / i11iIiiIii
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 38 - 38: OoO0O00
  if 3 - 3: II111iiii . I1IiiI / Oo0Ooo + o0oOOo0O0Ooo
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 54 - 54: i1IIi - II111iiii . i1IIi
  if 33 - 33: iII111i + Oo0Ooo % I11i . oO0o
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 6 - 6: IiII + I1ii11iIi11i
  if 62 - 62: oO0o . I1Ii111 - OoooooooOO * II111iiii . i11iIiiIii
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 13 - 13: iIii1I11I1II1 * o0oOOo0O0Ooo - i11iIiiIii
  if 63 - 63: OoooooooOO * I1Ii111
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 50 - 50: Oo0Ooo - o0oOOo0O0Ooo % II111iiii . O0 . oO0o % II111iiii
  if 18 - 18: I11i % OoooooooOO + OoO0O00 / I11i
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 37 - 37: i1IIi - Ii1I / IiII . II111iiii % ooOoO0o
  if 39 - 39: Ii1I % i11iIiiIii * OoO0O00
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 23 - 23: OOooOOo + ooOoO0o / i11iIiiIii * Oo0Ooo . OoO0O00
  if 28 - 28: iII111i - o0oOOo0O0Ooo
  if 92 - 92: Oo0Ooo % o0oOOo0O0Ooo - ooOoO0o / ooOoO0o / OoOoOO00
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
  if 84 - 84: OOooOOo
  if 4 - 4: IiII . I1Ii111 / Ii1I / iII111i + II111iiii
 def send_ipc ( self , ipc_socket , ipc ) :
  IiiiiI = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  oOO00OoOo = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , IiiiiI )
  lisp_ipc ( ipc , ipc_socket , oOO00OoOo )
  if 53 - 53: o0oOOo0O0Ooo % OoooooooOO - oO0o - i1IIi / OoO0O00
  if 33 - 33: IiII * I11i
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  OO0oOOOOO = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , OO0oOOOOO )
  if 87 - 87: OoooooooOO . ooOoO0o % iIii1I11I1II1 . iIii1I11I1II1 % I1ii11iIi11i . I1Ii111
  if 25 - 25: I11i + II111iiii / ooOoO0o
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  OO0oOOOOO = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , OO0oOOOOO )
  if 12 - 12: i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
  if 8 - 8: o0oOOo0O0Ooo
 def receive_request ( self , ipc_socket , nonce ) :
  ooOO0O0O = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( ooOO0O0O != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 18 - 18: oO0o * O0 - I1IiiI + O0 + I1Ii111
  if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 80 - 80: OOooOOo
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 12 - 12: Ii1I
  if 2 - 2: OoooooooOO
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 100 - 100: Oo0Ooo / O0 * i11iIiiIii * OoooooooOO
  if 46 - 46: O0 % OoooooooOO
  if 22 - 22: iII111i + OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
  if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
  if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   I1IiiI11 = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 46 - 46: OoO0O00 % I1ii11iIi11i
   if 58 - 58: oO0o + IiII % iII111i - Ii1I - OOooOOo % Ii1I
   if ( remote_rloc . address > I1IiiI11 . address ) :
    I1II1I1I = "exit"
    self . request_nonce_sent = None
   else :
    I1II1I1I = "stay in"
    self . echo_nonce_sent = None
    if 86 - 86: o0oOOo0O0Ooo
    if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
   O0o00o00OO0oO = bold ( "collision" , False )
   OoOoo00Oo0OoO = red ( I1IiiI11 . print_address_no_iid ( ) , False )
   IIIIiiI1iIiI = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( O0o00o00OO0oO ,
 OoOoo00Oo0OoO , IIIIiiI1iIiI , I1II1I1I ) )
   if 91 - 91: o0oOOo0O0Ooo * I1ii11iIi11i - iII111i . II111iiii
   if 1 - 1: OOooOOo + I1Ii111 * I1ii11iIi11i
   if 44 - 44: iII111i
   if 79 - 79: o0oOOo0O0Ooo % OOooOOo . O0
   if 56 - 56: oO0o + i1IIi * iII111i - O0
  if ( self . echo_nonce_sent != None ) :
   OOooO = self . echo_nonce_sent
   oOO = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( oOO ,
 lisp_hex_string ( OOooO ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( OOooO )
   if 84 - 84: iII111i % I1IiiI / iIii1I11I1II1 * Ii1I * iIii1I11I1II1 + I1ii11iIi11i
   if 78 - 78: IiII / iII111i * Ii1I . OOooOOo . oO0o - I1Ii111
   if 39 - 39: ooOoO0o . i1IIi + OoooooooOO . iII111i - i11iIiiIii % I1Ii111
   if 38 - 38: oO0o
   if 9 - 9: I11i . OoO0O00 . oO0o / OoooooooOO
   if 59 - 59: iIii1I11I1II1 + i1IIi % II111iiii
   if 2 - 2: II111iiii + I11i . OoO0O00
  OOooO = self . request_nonce_sent
  i1IIIi111111 = self . last_request_nonce_sent
  if ( OOooO and i1IIIi111111 != None ) :
   if ( time . time ( ) - i1IIIi111111 >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OOooO ) ) )
    if 57 - 57: Ii1I . I1Ii111 . II111iiii % OoooooooOO * O0 + iIii1I11I1II1
    return ( None )
    if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
    if 93 - 93: ooOoO0o / OOooOOo * O0
    if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
    if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
    if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
    if 6 - 6: iII111i % o0oOOo0O0Ooo + I1Ii111
    if 91 - 91: o0oOOo0O0Ooo + O0 * oO0o * IiII * I1ii11iIi11i
    if 83 - 83: OoooooooOO
    if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
  if ( OOooO == None ) :
   OOooO = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( OOooO )
   if 88 - 88: OOooOOo / i11iIiiIii / Ii1I / i11iIiiIii * I1ii11iIi11i % I11i
   self . request_nonce_sent = OOooO
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OOooO ) ) )
   if 43 - 43: OoOoOO00 * OoO0O00 % i1IIi * Ii1I + iIii1I11I1II1
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
   if 63 - 63: ooOoO0o . OOooOOo
   if 66 - 66: I1IiiI
   if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
   if 60 - 60: I1ii11iIi11i
   if ( lisp_i_am_itr == False ) : return ( OOooO | 0x80000000 )
   self . send_request_ipc ( ipc_socket , OOooO )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( OOooO ) ) )
   if 78 - 78: oO0o + II111iiii
   if 55 - 55: OoooooooOO
   if 90 - 90: I1IiiI
   if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
   if 30 - 30: IiII
   if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
   if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( OOooO | 0x80000000 )
  if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
  if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 84 - 84: OoOoOO00 - I11i
  o0oOOOO0 = time . time ( ) - self . last_request_nonce_sent
  OoO00O00O0 = self . last_echo_nonce_rcvd
  return ( o0oOOOO0 >= LISP_NONCE_ECHO_INTERVAL and OoO00O00O0 == None )
  if 76 - 76: I1IiiI % i11iIiiIii + OOooOOo
  if 17 - 17: I11i / II111iiii * o0oOOo0O0Ooo / Oo0Ooo + iII111i . oO0o
 def recently_requested ( self ) :
  OoO00O00O0 = self . last_request_nonce_sent
  if ( OoO00O00O0 == None ) : return ( False )
  if 19 - 19: OOooOOo * I11i
  o0oOOOO0 = time . time ( ) - OoO00O00O0
  return ( o0oOOOO0 <= LISP_NONCE_ECHO_INTERVAL )
  if 85 - 85: i1IIi % o0oOOo0O0Ooo * I1ii11iIi11i * OoO0O00 . II111iiii
  if 69 - 69: Ii1I / I1Ii111 % I1Ii111 / ooOoO0o + I1Ii111 / i1IIi
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 70 - 70: OOooOOo - IiII . I1Ii111
  if 11 - 11: i11iIiiIii + o0oOOo0O0Ooo - I1Ii111 * i11iIiiIii - I1IiiI
  if 49 - 49: i1IIi % oO0o / OOooOOo . I1ii11iIi11i - I1Ii111
  if 12 - 12: i11iIiiIii + I11i - I1ii11iIi11i
  OoO00O00O0 = self . last_good_echo_nonce_rcvd
  if ( OoO00O00O0 == None ) : OoO00O00O0 = 0
  o0oOOOO0 = time . time ( ) - OoO00O00O0
  if ( o0oOOOO0 <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 27 - 27: iII111i
  if 22 - 22: OoOoOO00 / I1IiiI
  if 33 - 33: I11i
  if 37 - 37: OoOoOO00 % o0oOOo0O0Ooo * OoO0O00 / i11iIiiIii * II111iiii * iII111i
  if 70 - 70: ooOoO0o . i11iIiiIii % OoOoOO00 + oO0o
  if 95 - 95: I1ii11iIi11i
  OoO00O00O0 = self . last_new_request_nonce_sent
  if ( OoO00O00O0 == None ) : OoO00O00O0 = 0
  o0oOOOO0 = time . time ( ) - OoO00O00O0
  return ( o0oOOOO0 <= LISP_NONCE_ECHO_INTERVAL )
  if 48 - 48: I11i
  if 14 - 14: iIii1I11I1II1 / o0oOOo0O0Ooo * IiII
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   ii1 = bold ( "down" , False )
   ooOOOooOOO00O = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , ii1 , ooOOOooOOO00O ) )
   if 34 - 34: Ii1I * I11i / OoooooooOO - iIii1I11I1II1
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 96 - 96: iII111i * I1IiiI + IiII . i11iIiiIii * Oo0Ooo % i1IIi
   if 65 - 65: iIii1I11I1II1 * IiII
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 89 - 89: IiII % i11iIiiIii . i11iIiiIii + oO0o / I1ii11iIi11i
  if ( self . recently_requested ( ) == False ) :
   i1III = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , i1III ) )
   if 100 - 100: IiII + i1IIi * OoO0O00
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
   if 52 - 52: Oo0Ooo / ooOoO0o / iII111i - o0oOOo0O0Ooo / iII111i
   if 74 - 74: i1IIi . iIii1I11I1II1
 def print_echo_nonce ( self ) :
  ooOoo = lisp_print_elapsed ( self . last_request_nonce_sent )
  i1I = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 3 - 3: OoOoOO00
  o00Oo0O = lisp_print_elapsed ( self . last_echo_nonce_sent )
  o00oOO = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  OOo0oOO0o0oo0 = space ( 4 )
  if 78 - 78: IiII + I11i - o0oOOo0O0Ooo + OoO0O00 / iIii1I11I1II1
  i11IiIIi11I = "Nonce-Echoing:\n"
  i11IiIIi11I += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( OOo0oOO0o0oo0 , ooOoo , OOo0oOO0o0oo0 , i1I )
  if 47 - 47: OOooOOo
  i11IiIIi11I += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( OOo0oOO0o0oo0 , o00oOO , OOo0oOO0o0oo0 , o00Oo0O )
  if 20 - 20: I1Ii111 % ooOoO0o - I1Ii111 * OoooooooOO / I1ii11iIi11i
  if 57 - 57: IiII % I11i * OOooOOo % I1ii11iIi11i
  return ( i11IiIIi11I )
  if 65 - 65: i1IIi - OoooooooOO
  if 66 - 66: I1ii11iIi11i / i1IIi * I1IiiI - OoOoOO00 + oO0o
  if 74 - 74: iII111i / I1Ii111 / II111iiii - iII111i / oO0o % I11i
  if 19 - 19: IiII % OoooooooOO + OoooooooOO
  if 7 - 7: i1IIi
  if 91 - 91: OoOoOO00 - OoOoOO00 . IiII
  if 33 - 33: I1Ii111 - iIii1I11I1II1 / Ii1I % O0
  if 80 - 80: IiII % OoooooooOO - IiII
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
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
    if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   oO0oOo = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( oO0oOo . encode ( ) )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 100 - 100: II111iiii / I1Ii111 / iII111i - I1ii11iIi11i * iIii1I11I1II1
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 7 - 7: i1IIi . IiII % i11iIiiIii * I1ii11iIi11i . I11i % I1ii11iIi11i
  if 35 - 35: I1IiiI
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 48 - 48: OoooooooOO % OoooooooOO - OoO0O00 . OoOoOO00
  if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  Oo0OOOO0oOoo0 = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   Oo0OOOO0oOoo0 = struct . pack ( "Q" , Oo0OOOO0oOoo0 & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   ii1I = struct . pack ( "I" , ( Oo0OOOO0oOoo0 >> 64 ) & LISP_4_32_MASK )
   O00oO0oOOOOOO = struct . pack ( "Q" , Oo0OOOO0oOoo0 & LISP_8_64_MASK )
   Oo0OOOO0oOoo0 = ii1I + O00oO0oOOOOOO
  else :
   Oo0OOOO0oOoo0 = struct . pack ( "QQ" , Oo0OOOO0oOoo0 >> 64 , Oo0OOOO0oOoo0 & LISP_8_64_MASK )
  return ( Oo0OOOO0oOoo0 )
  if 88 - 88: iIii1I11I1II1 % II111iiii % II111iiii . OOooOOo % oO0o
  if 15 - 15: OOooOOo . OoooooooOO * II111iiii
 def key_length ( self , key ) :
  if ( isinstance ( key , int ) ) : key = self . normalize_pub_key ( key )
  return ( old_div ( len ( key ) , 2 ) )
  if 13 - 13: I11i - ooOoO0o + iII111i % I11i . iII111i - i1IIi
  if 67 - 67: OOooOOo . i11iIiiIii + ooOoO0o . iIii1I11I1II1
 def print_key ( self , key ) :
  o00o = self . normalize_pub_key ( key )
  iiIi1i = o00o [ 0 : 4 ] . decode ( )
  I1i11IIiiIiI = o00o [ - 4 : : ] . decode ( )
  return ( "0x{}...{}({})" . format ( iiIi1i , I1i11IIiiIiI , self . key_length ( o00o ) ) )
  if 7 - 7: OoO0O00 * i11iIiiIii * iIii1I11I1II1 / OOooOOo / I1Ii111
  if 35 - 35: iII111i * OOooOOo
 def normalize_pub_key ( self , key ) :
  if ( isinstance ( key , int ) ) :
   key = lisp_hex_string ( key ) . zfill ( 256 )
   return ( key )
   if 65 - 65: II111iiii % i1IIi
  if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
  return ( key )
  if 13 - 13: OoO0O00 * I1Ii111 + Oo0Ooo - IiII
  if 31 - 31: OoO0O00
 def print_keys ( self , do_bold = True ) :
  OoOoo00Oo0OoO = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   OoOoo00Oo0OoO += "none"
  else :
   OoOoo00Oo0OoO += self . print_key ( self . local_public_key )
   if 68 - 68: OoO0O00 + i1IIi / iIii1I11I1II1 + II111iiii * iIii1I11I1II1 + I1ii11iIi11i
  IIIIiiI1iIiI = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   IIIIiiI1iIiI += "none"
  else :
   IIIIiiI1iIiI += self . print_key ( self . remote_public_key )
   if 77 - 77: i11iIiiIii - I1Ii111 . I1ii11iIi11i % Oo0Ooo . Ii1I
  iII11Iii = "ECDH" if ( self . curve25519 ) else "DH"
  OOooOoOooo = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( iII11Iii , OOooOoOooo , OoOoo00Oo0OoO , IIIIiiI1iIiI ) )
  if 88 - 88: II111iiii - iII111i / OoooooooOO
  if 71 - 71: I1ii11iIi11i
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 19 - 19: Oo0Ooo - OoO0O00 + i11iIiiIii / iIii1I11I1II1
  if 1 - 1: IiII % i1IIi
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 41 - 41: OoO0O00 * OoO0O00 / iII111i + I1ii11iIi11i . o0oOOo0O0Ooo
  oO0oOo = self . local_private_key
  II11iIIii = self . dh_g_value
  ooo0OO0OOooO0 = self . dh_p_value
  return ( int ( ( II11iIIii ** oO0oOo ) % ooo0OO0OOooO0 ) )
  if 84 - 84: i11iIiiIii + OoO0O00 * I1IiiI + I1ii11iIi11i / Ii1I
  if 80 - 80: I1ii11iIi11i
 def compute_shared_key ( self , ed , print_shared = False ) :
  oO0oOo = self . local_private_key
  ooOOO = self . remote_public_key
  if 95 - 95: I11i
  Oooo0o0oO = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( Oooo0o0oO , self . print_keys ( ) ) )
  if 51 - 51: iII111i / I1Ii111 % oO0o + oO0o * oO0o
  if ( self . curve25519 ) :
   I1IIiIIiii = curve25519 . Public ( ooOOO )
   self . shared_key = self . curve25519 . get_shared_key ( I1IIiIIiii )
  else :
   ooo0OO0OOooO0 = self . dh_p_value
   self . shared_key = ( ooOOO ** oO0oOo ) % ooo0OO0OOooO0
   if 5 - 5: i1IIi / I1IiiI / OoooooooOO
   if 74 - 74: I1ii11iIi11i % I1Ii111 - OoO0O00 * I11i . OoooooooOO * OoO0O00
   if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
   if 6 - 6: OOooOOo
   if 3 - 3: O0 - I1Ii111 * Ii1I * OOooOOo / Ii1I
   if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
   if 74 - 74: ooOoO0o - o0oOOo0O0Ooo * IiII % ooOoO0o
  if ( print_shared ) :
   o00o = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( o00o ) )
   if 93 - 93: iIii1I11I1II1 / OoOoOO00 % Oo0Ooo * I1Ii111 - OoO0O00 - o0oOOo0O0Ooo
   if 44 - 44: OoooooooOO
   if 82 - 82: OoOoOO00 . OoOoOO00
   if 10 - 10: Oo0Ooo * I1ii11iIi11i . oO0o . OoooooooOO . OOooOOo * I1ii11iIi11i
   if 80 - 80: I1Ii111 + I11i . I1Ii111 + OOooOOo
  self . compute_encrypt_icv_keys ( )
  if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
  if 43 - 43: IiII . OoooooooOO - II111iiii
  if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
  if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
  if 15 - 15: Ii1I + OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
 def compute_encrypt_icv_keys ( self ) :
  O0ooO00OO = hashlib . sha256
  if ( self . curve25519 ) :
   IiI11I1I111 = self . shared_key
  else :
   IiI11I1I111 = lisp_hex_string ( self . shared_key )
   if 72 - 72: i1IIi
   if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
   if 28 - 28: iIii1I11I1II1 . O0
   if 32 - 32: OoooooooOO
   if 29 - 29: I1ii11iIi11i
  OoOoo00Oo0OoO = self . local_public_key
  if ( type ( OoOoo00Oo0OoO ) != int ) : OoOoo00Oo0OoO = int ( binascii . hexlify ( OoOoo00Oo0OoO ) , 16 )
  IIIIiiI1iIiI = self . remote_public_key
  if ( type ( IIIIiiI1iIiI ) != int ) : IIIIiiI1iIiI = int ( binascii . hexlify ( IIIIiiI1iIiI ) , 16 )
  iI111iiI1II = "0001" + "lisp-crypto" + lisp_hex_string ( OoOoo00Oo0OoO ^ IIIIiiI1iIiI ) + "0100"
  if 96 - 96: OoOoOO00 * O0 - II111iiii . ooOoO0o - Ii1I
  OO0OOO0o0OOO0 = hmac . new ( iI111iiI1II . encode ( ) , IiI11I1I111 , O0ooO00OO ) . hexdigest ( )
  OO0OOO0o0OOO0 = int ( OO0OOO0o0OOO0 , 16 )
  if 39 - 39: O0 * I1IiiI
  if 27 - 27: iIii1I11I1II1 - oO0o
  if 73 - 73: OOooOOo . Oo0Ooo + Oo0Ooo % Oo0Ooo % O0
  if 8 - 8: iII111i . Ii1I - i1IIi % OoO0O00 / I11i
  IIiIi = ( OO0OOO0o0OOO0 >> 128 ) & LISP_16_128_MASK
  OoOOo = OO0OOO0o0OOO0 & LISP_16_128_MASK
  IIiIi = lisp_hex_string ( IIiIi ) . zfill ( 32 )
  self . encrypt_key = IIiIi . encode ( )
  i111II = 32 if self . do_poly else 40
  OoOOo = lisp_hex_string ( OoOOo ) . zfill ( i111II )
  self . icv_key = OoOOo . encode ( )
  if 50 - 50: Ii1I
  if 27 - 27: Ii1I
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   i1I1I1 = self . icv . poly1305aes
   i11i = self . icv . binascii . hexlify
   nonce = i11i ( nonce )
   I1111i = i1I1I1 ( self . encrypt_key , self . icv_key , nonce , packet )
   if ( lisp_is_python2 ( ) ) :
    I1111i = i11i ( I1111i . encode ( "raw_unicode_escape" ) )
   else :
    I1111i = i11i ( I1111i ) . decode ( )
    if 42 - 42: Oo0Ooo . oO0o + O0 / OOooOOo % OoooooooOO
  else :
   oO0oOo = binascii . unhexlify ( self . icv_key )
   I1111i = hmac . new ( oO0oOo , packet , self . icv ) . hexdigest ( )
   I1111i = I1111i [ 0 : 40 ]
   if 19 - 19: ooOoO0o / Ii1I
  return ( I1111i )
  if 43 - 43: OoOoOO00 % Ii1I + Oo0Ooo - OoooooooOO . O0 % Oo0Ooo
  if 98 - 98: o0oOOo0O0Ooo * Oo0Ooo - Ii1I . ooOoO0o
 def add_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 2 - 2: Oo0Ooo - ooOoO0o % iIii1I11I1II1
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 88 - 88: I1Ii111 - OoO0O00
  if 79 - 79: iII111i
 def delete_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 45 - 45: II111iiii + iII111i . I11i . O0 * i1IIi - Ii1I
  if 48 - 48: I1ii11iIi11i + Oo0Ooo
 def add_key_by_rloc ( self , addr_str , encap ) :
  o0OOoOoo = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 56 - 56: IiII - Ii1I + i11iIiiIii * OoO0O00 % I1IiiI
  if 37 - 37: iIii1I11I1II1 + IiII / I1Ii111 . OoooooooOO
  if ( addr_str not in o0OOoOoo ) :
   o0OOoOoo [ addr_str ] = [ None , None , None , None ]
   if 72 - 72: oO0o % ooOoO0o % OOooOOo
  o0OOoOoo [ addr_str ] [ self . key_id ] = self
  if 63 - 63: OoO0O00 . Ii1I % II111iiii / I11i - OoOoOO00
  if 4 - 4: Oo0Ooo - O0 / I11i + O0 - oO0o * Oo0Ooo
  if 25 - 25: I1IiiI
  if 64 - 64: oO0o
  if 80 - 80: o0oOOo0O0Ooo % iIii1I11I1II1
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , o0OOoOoo [ addr_str ] )
   if 63 - 63: IiII * i11iIiiIii
   if 86 - 86: I11i % I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
   if 26 - 26: II111iiii * iII111i + o0oOOo0O0Ooo / O0 + i1IIi - I11i
 def encode_lcaf ( self , rloc_addr ) :
  o000oOoOOO = self . normalize_pub_key ( self . local_public_key )
  OOOOOo00o0o = self . key_length ( o000oOoOOO )
  ooOoOoo = ( 6 + OOOOOo00o0o + 2 )
  if ( rloc_addr != None ) : ooOoOoo += rloc_addr . addr_length ( )
  if 73 - 73: Oo0Ooo % II111iiii / iII111i * oO0o
  Oo00O0o0O = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( ooOoOoo ) , 1 , 0 )
  if 60 - 60: i1IIi
  if 57 - 57: ooOoO0o
  if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if 52 - 52: I1ii11iIi11i
  if 93 - 93: iII111i . i11iIiiIii
  if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
  OOooOoOooo = self . cipher_suite
  Oo00O0o0O += struct . pack ( "BBH" , OOooOoOooo , 0 , socket . htons ( OOOOOo00o0o ) )
  if 49 - 49: O0 . Oo0Ooo / Ii1I
  if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
  if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
  if 20 - 20: iII111i . OoooooooOO + iII111i + ooOoO0o * I1ii11iIi11i
  for o000o0O0Oo00 in range ( 0 , OOOOOo00o0o * 2 , 16 ) :
   oO0oOo = int ( o000oOoOOO [ o000o0O0Oo00 : o000o0O0Oo00 + 16 ] , 16 )
   Oo00O0o0O += struct . pack ( "Q" , byte_swap_64 ( oO0oOo ) )
   if 44 - 44: i11iIiiIii
   if 69 - 69: OOooOOo * O0 + i11iIiiIii
   if 65 - 65: O0 / iII111i . i1IIi * iII111i / iIii1I11I1II1 - oO0o
   if 93 - 93: OoOoOO00 % i11iIiiIii - Ii1I % OoO0O00
   if 55 - 55: o0oOOo0O0Ooo . I1ii11iIi11i
  if ( rloc_addr ) :
   Oo00O0o0O += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   Oo00O0o0O += rloc_addr . pack_address ( )
   if 63 - 63: oO0o
  return ( Oo00O0o0O )
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 60 - 60: I1Ii111
  if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
  if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
  if 14 - 14: Ii1I - O0
  if ( lcaf_len == 0 ) :
   ii = "HHBBH"
   OOOO00oo00oo = struct . calcsize ( ii )
   if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
   if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
   IiIIi , I1i1ii1IiI1i , oo0O00o0oO00 , I1i1ii1IiI1i , lcaf_len = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
   if 42 - 42: i1IIi + iII111i . OoooooooOO + I1ii11iIi11i . I11i / Ii1I
   if 1 - 1: o0oOOo0O0Ooo
   if ( oo0O00o0oO00 != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 95 - 95: OOooOOo / i1IIi % OoO0O00 . I1Ii111 + I1Ii111
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ OOOO00oo00oo : : ]
   if 80 - 80: O0 + I1ii11iIi11i + OOooOOo
   if 95 - 95: I1ii11iIi11i
   if 98 - 98: IiII * iII111i . OoooooooOO . O0
   if 89 - 89: iII111i / O0 % OoooooooOO - O0 . OoO0O00
   if 32 - 32: ooOoO0o
   if 26 - 26: O0 * Ii1I - I1IiiI - iII111i / iIii1I11I1II1
  oo0O00o0oO00 = LISP_LCAF_SECURITY_TYPE
  ii = "BBBBH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 57 - 57: I1ii11iIi11i - OoO0O00 * iIii1I11I1II1
  II111IiI11i , I1i1ii1IiI1i , OOooOoOooo , I1i1ii1IiI1i , OOOOOo00o0o = struct . unpack ( ii ,
 packet [ : OOOO00oo00oo ] )
  if 91 - 91: II111iiii . Oo0Ooo . oO0o - OoooooooOO / OoOoOO00
  if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
  if 55 - 55: OoO0O00
  if 20 - 20: ooOoO0o * I1Ii111 * o0oOOo0O0Ooo - ooOoO0o
  if 32 - 32: Ii1I * oO0o
  if 85 - 85: i11iIiiIii . OoO0O00 + OoO0O00
  packet = packet [ OOOO00oo00oo : : ]
  OOOOOo00o0o = socket . ntohs ( OOOOOo00o0o )
  if ( len ( packet ) < OOOOOo00o0o ) : return ( None )
  if 28 - 28: Oo0Ooo
  if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
  if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
  if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
  ooo0Oo000o = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( OOooOoOooo not in ooo0Oo000o ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( ooo0Oo000o ,
 OOooOoOooo ) )
   packet = packet [ OOOOOo00o0o : : ]
   return ( packet )
   if 18 - 18: O0
   if 14 - 14: Ii1I / IiII - O0
  self . cipher_suite = OOooOoOooo
  if 16 - 16: I1Ii111 % iIii1I11I1II1 . i1IIi
  if 72 - 72: ooOoO0o * OOooOOo
  if 69 - 69: oO0o - i11iIiiIii
  if 29 - 29: Ii1I + iII111i % I1ii11iIi11i + I11i * Oo0Ooo - i11iIiiIii
  if 24 - 24: i11iIiiIii . ooOoO0o + ooOoO0o - i11iIiiIii % OOooOOo
  o000oOoOOO = 0
  for o000o0O0Oo00 in range ( 0 , OOOOOo00o0o , 8 ) :
   oO0oOo = byte_swap_64 ( struct . unpack ( "Q" , packet [ o000o0O0Oo00 : o000o0O0Oo00 + 8 ] ) [ 0 ] )
   o000oOoOOO <<= 64
   o000oOoOOO |= oO0oOo
   if 58 - 58: I1IiiI
  self . remote_public_key = o000oOoOOO
  if 94 - 94: o0oOOo0O0Ooo + Ii1I % o0oOOo0O0Ooo . I1Ii111 - ooOoO0o * I1IiiI
  if 62 - 62: Oo0Ooo * i1IIi % I1ii11iIi11i + Oo0Ooo . O0 . ooOoO0o
  if 57 - 57: Oo0Ooo - I1Ii111 + O0 % o0oOOo0O0Ooo
  if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
  if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
  if ( self . curve25519 ) :
   oO0oOo = lisp_hex_string ( self . remote_public_key )
   oO0oOo = oO0oOo . zfill ( 64 )
   iiiiI1iiIi1i = b""
   for o000o0O0Oo00 in range ( 0 , len ( oO0oOo ) , 2 ) :
    Iii1 = int ( oO0oOo [ o000o0O0Oo00 : o000o0O0Oo00 + 2 ] , 16 )
    iiiiI1iiIi1i += lisp_store_byte ( Iii1 )
    if 71 - 71: Ii1I
   self . remote_public_key = iiiiI1iiIi1i
   if 31 - 31: I11i . i11iIiiIii . OoO0O00 * Oo0Ooo % Ii1I . o0oOOo0O0Ooo
   if 92 - 92: OoooooooOO / O0 * i1IIi + iIii1I11I1II1
  packet = packet [ OOOOOo00o0o : : ]
  return ( packet )
  if 93 - 93: ooOoO0o % I1Ii111
  if 46 - 46: I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  if 43 - 43: ooOoO0o . i1IIi
  if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
  if 45 - 45: I1IiiI
  if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
  if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
  if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
  if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
def lisp_store_byte_py2 ( byte ) :
 return ( chr ( byte ) )
 if 61 - 61: Oo0Ooo - I1Ii111
def lisp_store_byte_py3 ( byte ) :
 return ( bytes ( [ byte ] ) )
 if 51 - 51: iII111i * ooOoO0o / O0 / O0
 if 52 - 52: OoooooooOO % O0
lisp_store_byte = lisp_store_byte_py2
if ( lisp_is_python3 ( ) ) : lisp_store_byte = lisp_store_byte_py3
if 56 - 56: oO0o - i1IIi * OoooooooOO - II111iiii
if 28 - 28: i1IIi / I11i . o0oOOo0O0Ooo
if 11 - 11: Oo0Ooo * OoooooooOO - i11iIiiIii
if 13 - 13: i11iIiiIii . O0 / OOooOOo * i1IIi
if 14 - 14: IiII + IiII . I11i / Ii1I . iIii1I11I1II1
if 10 - 10: II111iiii . OOooOOo / iII111i
class lisp_thread ( object ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
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
  if 97 - 97: i1IIi
  if 29 - 29: I1IiiI
 def decode ( self , packet ) :
  ii = "BBBBQ"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( False )
  if 37 - 37: I1ii11iIi11i * I1Ii111 * I1IiiI * O0
  Ii1II1i1i , II1o0o00O , o00ooo0oOo0o , self . record_count , self . nonce = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 97 - 97: o0oOOo0O0Ooo . iIii1I11I1II1 % iII111i * iIii1I11I1II1 * iIii1I11I1II1
  if 37 - 37: I1Ii111 . OoooooooOO / ooOoO0o + II111iiii
  self . type = Ii1II1i1i >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( Ii1II1i1i & 0x01 ) else False
   self . rloc_probe = True if ( Ii1II1i1i & 0x02 ) else False
   self . smr_invoked_bit = True if ( II1o0o00O & 0x40 ) else False
   if 90 - 90: Ii1I * iII111i / OOooOOo
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( Ii1II1i1i & 0x04 ) else False
   self . to_etr = True if ( Ii1II1i1i & 0x02 ) else False
   self . to_ms = True if ( Ii1II1i1i & 0x01 ) else False
   if 68 - 68: OoOoOO00
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( Ii1II1i1i & 0x08 ) else False
   if 65 - 65: oO0o
  return ( True )
  if 82 - 82: o0oOOo0O0Ooo
  if 80 - 80: i1IIi % OoOoOO00 + OoO0O00 - OoooooooOO / iIii1I11I1II1 + I1Ii111
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 65 - 65: Ii1I
  if 71 - 71: I1Ii111 % I1Ii111 . oO0o + i11iIiiIii - i11iIiiIii
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 16 - 16: iIii1I11I1II1 / I1IiiI / I1Ii111 - i11iIiiIii . ooOoO0o / OOooOOo
  if 13 - 13: o0oOOo0O0Ooo % O0 - I1Ii111 * OoooooooOO / Oo0Ooo - OoooooooOO
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 78 - 78: oO0o % OoooooooOO
  if 73 - 73: I1IiiI % ooOoO0o % IiII + i1IIi - OoooooooOO / oO0o
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 78 - 78: OoooooooOO % oO0o - i11iIiiIii
  if 37 - 37: IiII % Ii1I % i1IIi
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 23 - 23: ooOoO0o - O0 + i11iIiiIii
  if 98 - 98: OoooooooOO
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
  if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 71 - 71: Ii1I * OoOoOO00
  if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 81 - 81: iII111i % Ii1I . ooOoO0o
  if 66 - 66: I1ii11iIi11i * Ii1I / OoooooooOO * O0 % OOooOOo
  if 49 - 49: II111iiii . I1IiiI * O0 * Ii1I / I1Ii111 * OoooooooOO
  if 82 - 82: Oo0Ooo / Ii1I / Ii1I % Ii1I
  if 20 - 20: ooOoO0o
  if 63 - 63: iIii1I11I1II1 . OoO0O00
  if 100 - 100: i1IIi * i1IIi
  if 26 - 26: OOooOOo . OoO0O00 % OoOoOO00
  if 94 - 94: IiII
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
  if 15 - 15: Ii1I - IiII / O0
  if 28 - 28: I1Ii111 . i1IIi / I1ii11iIi11i
 def print_map_register ( self ) :
  Ooo0 = lisp_hex_string ( self . xtr_id )
  if 80 - 80: o0oOOo0O0Ooo
  ooO = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 46 - 46: iII111i % I1Ii111 % OoOoOO00 . OoooooooOO . II111iiii % IiII
  lprint ( ooO . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # iII111i
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , Ooo0 , self . site_id ) )
  if 73 - 73: IiII / Ii1I + I1Ii111 . OOooOOo - II111iiii / iIii1I11I1II1
  if 79 - 79: I1Ii111 * Oo0Ooo . o0oOOo0O0Ooo - I1Ii111
  if 16 - 16: I1IiiI - O0 * I1ii11iIi11i . I1ii11iIi11i % OOooOOo
  if 39 - 39: II111iiii / I11i - OoOoOO00 * OoOoOO00 - Ii1I
 def encode ( self ) :
  IiiI11iIi = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : IiiI11iIi |= 0x08000000
  if ( self . lisp_sec_present ) : IiiI11iIi |= 0x04000000
  if ( self . xtr_id_present ) : IiiI11iIi |= 0x02000000
  if ( self . map_register_refresh ) : IiiI11iIi |= 0x1000
  if ( self . use_ttl_for_timeout ) : IiiI11iIi |= 0x800
  if ( self . merge_register_requested ) : IiiI11iIi |= 0x400
  if ( self . mobile_node ) : IiiI11iIi |= 0x200
  if ( self . map_notify_requested ) : IiiI11iIi |= 0x100
  if ( self . encryption_key_id != None ) :
   IiiI11iIi |= 0x2000
   IiiI11iIi |= self . encryption_key_id << 14
   if 8 - 8: O0 . i11iIiiIii
   if 54 - 54: OOooOOo . I1ii11iIi11i * I11i % I1Ii111 . O0 * IiII
   if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
   if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
   if 18 - 18: I11i * I1ii11iIi11i / i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 69 - 69: Oo0Ooo * ooOoO0o
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
    if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
    if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
  Oo00O0o0O = struct . pack ( "I" , socket . htonl ( IiiI11iIi ) )
  Oo00O0o0O += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
  Oo00O0o0O = self . zero_auth ( Oo00O0o0O )
  return ( Oo00O0o0O )
  if 24 - 24: OoOoOO00 * Ii1I
  if 17 - 17: OoO0O00 . I1IiiI * O0
 def zero_auth ( self , packet ) :
  II1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  oO0ooo000 = b""
  i11IIII1 = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oO0ooo000 = struct . pack ( "QQI" , 0 , 0 , 0 )
   i11IIII1 = struct . calcsize ( "QQI" )
   if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oO0ooo000 = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   i11IIII1 = struct . calcsize ( "QQQQ" )
   if 56 - 56: i1IIi
  packet = packet [ 0 : II1Ii ] + oO0ooo000 + packet [ II1Ii + i11IIII1 : : ]
  return ( packet )
  if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
  if 82 - 82: IiII
 def encode_auth ( self , packet ) :
  II1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  i11IIII1 = self . auth_len
  oO0ooo000 = self . auth_data
  packet = packet [ 0 : II1Ii ] + oO0ooo000 + packet [ II1Ii + i11IIII1 : : ]
  return ( packet )
  if 10 - 10: Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
  if 54 - 54: i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i / I1IiiI . iIii1I11I1II1 / iII111i
 def decode ( self , packet ) :
  I11I = packet
  ii = "I"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( [ None , None ] )
  if 64 - 64: o0oOOo0O0Ooo % ooOoO0o % oO0o
  IiiI11iIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  IiiI11iIi = socket . ntohl ( IiiI11iIi [ 0 ] )
  packet = packet [ OOOO00oo00oo : : ]
  if 29 - 29: Ii1I % OoO0O00 . II111iiii . oO0o / OoO0O00 % iIii1I11I1II1
  ii = "QBBH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( [ None , None ] )
  if 8 - 8: O0 / II111iiii
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
  if 87 - 87: IiII
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( IiiI11iIi & 0x08000000 ) else False
  if 45 - 45: oO0o + II111iiii * O0 % OOooOOo . iIii1I11I1II1
  self . lisp_sec_present = True if ( IiiI11iIi & 0x04000000 ) else False
  self . xtr_id_present = True if ( IiiI11iIi & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( IiiI11iIi & 0x800 ) else False
  self . map_register_refresh = True if ( IiiI11iIi & 0x1000 ) else False
  self . merge_register_requested = True if ( IiiI11iIi & 0x400 ) else False
  self . mobile_node = True if ( IiiI11iIi & 0x200 ) else False
  self . map_notify_requested = True if ( IiiI11iIi & 0x100 ) else False
  self . record_count = IiiI11iIi & 0xff
  if 55 - 55: IiII
  if 43 - 43: OOooOOo
  if 17 - 17: i11iIiiIii
  if 94 - 94: OoooooooOO - IiII + oO0o . OoooooooOO / i1IIi
  self . encrypt_bit = True if IiiI11iIi & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( IiiI11iIi >> 14 ) & 0x7
   if 53 - 53: I1Ii111 % I1ii11iIi11i
   if 17 - 17: OoooooooOO % Ii1I % O0
   if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
   if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
   if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( I11I ) == False ) : return ( [ None , None ] )
   if 80 - 80: oO0o / O0
   if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
  packet = packet [ OOOO00oo00oo : : ]
  if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
  if 59 - 59: IiII
  if 54 - 54: OOooOOo
  if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
    if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
   i11IIII1 = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    OOOO00oo00oo = struct . calcsize ( "QQI" )
    if ( i11IIII1 < OOOO00oo00oo ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 33 - 33: oO0o % OoO0O00 . iIii1I11I1II1 / IiII
    i1II1iI , oOOo0oOO , oO = struct . unpack ( "QQI" , packet [ : i11IIII1 ] )
    OoOoO0OOO0oO = b""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    OOOO00oo00oo = struct . calcsize ( "QQQQ" )
    if ( i11IIII1 < OOOO00oo00oo ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 78 - 78: I1IiiI / OoooooooOO % iII111i - IiII
    i1II1iI , oOOo0oOO , oO , OoOoO0OOO0oO = struct . unpack ( "QQQQ" ,
 packet [ : i11IIII1 ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 33 - 33: ooOoO0o * OoooooooOO
    return ( [ None , None ] )
    if 14 - 14: II111iiii + O0 - iII111i
   self . auth_data = lisp_concat_auth_data ( self . alg_id , i1II1iI , oOOo0oOO ,
 oO , OoOoO0OOO0oO )
   I11I = self . zero_auth ( I11I )
   packet = packet [ self . auth_len : : ]
   if 18 - 18: o0oOOo0O0Ooo / i11iIiiIii % I1ii11iIi11i * OoooooooOO
  return ( [ I11I , packet ] )
  if 67 - 67: OoOoOO00
  if 67 - 67: I1ii11iIi11i / iII111i + iIii1I11I1II1 % I1IiiI
 def encode_xtr_id ( self , packet ) :
  o00 = self . xtr_id >> 64
  o000 = self . xtr_id & 0xffffffffffffffff
  o00 = byte_swap_64 ( o00 )
  o000 = byte_swap_64 ( o000 )
  IIIi1IiI1iII = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , o00 , o000 , IIIi1IiI1iII )
  return ( packet )
  if 85 - 85: I1ii11iIi11i + OoOoOO00 - i11iIiiIii % OoOoOO00 . oO0o + i11iIiiIii
  if 12 - 12: IiII + i1IIi . I1IiiI * iIii1I11I1II1 * I1ii11iIi11i
 def decode_xtr_id ( self , packet ) :
  OOOO00oo00oo = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - OOOO00oo00oo : : ]
  o00 , o000 , IIIi1IiI1iII = struct . unpack ( "QQQ" ,
 packet [ : OOOO00oo00oo ] )
  o00 = byte_swap_64 ( o00 )
  o000 = byte_swap_64 ( o000 )
  self . xtr_id = ( o00 << 64 ) | o000
  self . site_id = byte_swap_64 ( IIIi1IiI1iII )
  return ( True )
  if 5 - 5: ooOoO0o - I1Ii111 - iII111i
  if 38 - 38: iIii1I11I1II1 . Ii1I
  if 12 - 12: OoO0O00 - I1IiiI + OoooooooOO + OoooooooOO * I1IiiI - i1IIi
  if 64 - 64: i11iIiiIii + OoOoOO00 + o0oOOo0O0Ooo + OOooOOo
  if 33 - 33: I1IiiI - iII111i . i1IIi / i11iIiiIii
  if 84 - 84: I11i / OoooooooOO / IiII % I11i . OOooOOo + I1Ii111
  if 94 - 94: I11i
  if 48 - 48: oO0o - OoooooooOO + o0oOOo0O0Ooo % i1IIi - I1IiiI + OOooOOo
  if 56 - 56: I1IiiI - OOooOOo
  if 35 - 35: OoO0O00 / I1IiiI * O0 + I1IiiI . O0
  if 86 - 86: I1IiiI
  if 10 - 10: OoOoOO00 / oO0o % Oo0Ooo
  if 15 - 15: I11i - iIii1I11I1II1 % Ii1I
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
  if 3 - 3: IiII - I1ii11iIi11i * iII111i * I1ii11iIi11i + Oo0Ooo
  if 15 - 15: I1ii11iIi11i * Ii1I / iII111i . o0oOOo0O0Ooo / Ii1I % OoOoOO00
 def print_notify ( self ) :
  oO0ooo000 = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( oO0ooo000 ) != 40 ) :
   oO0ooo000 = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( oO0ooo000 ) != 64 ) :
   oO0ooo000 = self . auth_data
   if 75 - 75: OoooooooOO % i11iIiiIii % iIii1I11I1II1 % I1ii11iIi11i / i11iIiiIii
  ooO = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( ooO . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # IiII - I1IiiI * I1IiiI - I11i . O0 . o0oOOo0O0Ooo
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , oO0ooo000 ) )
  if 83 - 83: I11i * I1IiiI . II111iiii * i1IIi % O0
  if 35 - 35: OoOoOO00 % OoO0O00 + O0 * o0oOOo0O0Ooo % I1ii11iIi11i
  if 57 - 57: oO0o / I11i
  if 63 - 63: ooOoO0o * OoO0O00 * ooOoO0o + OoOoOO00
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   oO0ooo000 = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 25 - 25: iII111i * OoOoOO00 / I1IiiI / IiII
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   oO0ooo000 = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 11 - 11: OOooOOo + i11iIiiIii
  packet += oO0ooo000
  return ( packet )
  if 14 - 14: OoOoOO00 / IiII + OoO0O00 - Ii1I
  if 38 - 38: I1Ii111
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   IiiI11iIi = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   IiiI11iIi = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 30 - 30: II111iiii + I11i . i11iIiiIii + iIii1I11I1II1
  Oo00O0o0O = struct . pack ( "I" , socket . htonl ( IiiI11iIi ) )
  Oo00O0o0O += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 100 - 100: oO0o * o0oOOo0O0Ooo / iII111i
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = Oo00O0o0O + eid_records
   return ( self . packet )
   if 92 - 92: ooOoO0o / i11iIiiIii * OOooOOo
   if 55 - 55: ooOoO0o
   if 1 - 1: OoO0O00
   if 43 - 43: iIii1I11I1II1 - OOooOOo - o0oOOo0O0Ooo + I1ii11iIi11i - I1Ii111 % I1ii11iIi11i
   if 58 - 58: OoOoOO00
  Oo00O0o0O = self . zero_auth ( Oo00O0o0O )
  Oo00O0o0O += eid_records
  if 27 - 27: IiII * OOooOOo - OoooooooOO . Ii1I - II111iiii
  ii1iiIiiiI11 = lisp_hash_me ( Oo00O0o0O , self . alg_id , password , False )
  if 62 - 62: I1IiiI / iIii1I11I1II1 * I11i
  II1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  i11IIII1 = self . auth_len
  self . auth_data = ii1iiIiiiI11
  Oo00O0o0O = Oo00O0o0O [ 0 : II1Ii ] + ii1iiIiiiI11 + Oo00O0o0O [ II1Ii + i11IIII1 : : ]
  self . packet = Oo00O0o0O
  return ( Oo00O0o0O )
  if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
  if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
 def decode ( self , packet ) :
  I11I = packet
  ii = "I"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
  IiiI11iIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  IiiI11iIi = socket . ntohl ( IiiI11iIi [ 0 ] )
  self . map_notify_ack = ( ( IiiI11iIi >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = IiiI11iIi & 0xff
  packet = packet [ OOOO00oo00oo : : ]
  if 24 - 24: OoO0O00 % O0 % I11i
  ii = "QBBH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 61 - 61: ooOoO0o . iII111i / ooOoO0o * OoooooooOO
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 13 - 13: II111iiii
  if 17 - 17: II111iiii
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ OOOO00oo00oo : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 66 - 66: IiII * oO0o
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 73 - 73: i11iIiiIii + O0 % O0
  if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
  if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 18 - 18: OoOoOO00
  i11IIII1 = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   i1II1iI , oOOo0oOO , oO = struct . unpack ( "QQI" , packet [ : i11IIII1 ] )
   OoOoO0OOO0oO = ""
   if 30 - 30: II111iiii
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   i1II1iI , oOOo0oOO , oO , OoOoO0OOO0oO = struct . unpack ( "QQQQ" ,
 packet [ : i11IIII1 ] )
   if 27 - 27: i1IIi - iIii1I11I1II1 + O0 % Oo0Ooo / OOooOOo + i1IIi
  self . auth_data = lisp_concat_auth_data ( self . alg_id , i1II1iI , oOOo0oOO ,
 oO , OoOoO0OOO0oO )
  if 48 - 48: Oo0Ooo
  OOOO00oo00oo = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( I11I [ : OOOO00oo00oo ] )
  OOOO00oo00oo += i11IIII1
  packet += I11I [ OOOO00oo00oo : : ]
  return ( packet )
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
  if 13 - 13: OoO0O00 * iIii1I11I1II1 + II111iiii - Oo0Ooo - OoOoOO00
  if 43 - 43: iII111i / I1Ii111 * I1IiiI % ooOoO0o % I1IiiI
  if 18 - 18: OoO0O00
  if 99 - 99: iII111i / oO0o . i11iIiiIii / I11i + i1IIi - I11i
  if 50 - 50: i1IIi
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
  if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
  if 75 - 75: OoOoOO00
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 96 - 96: o0oOOo0O0Ooo * I11i * Oo0Ooo
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 36 - 36: OoooooooOO + ooOoO0o . oO0o * ooOoO0o + IiII
  if 45 - 45: oO0o / iII111i + I1ii11iIi11i - Oo0Ooo - ooOoO0o . iIii1I11I1II1
 def print_map_request ( self ) :
  Ooo0 = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   Ooo0 = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 52 - 52: I1IiiI + i1IIi . iII111i * I1IiiI
   if 31 - 31: Oo0Ooo % iIii1I11I1II1 . O0
   if 80 - 80: I11i / Oo0Ooo + I1ii11iIi11i
  ooO = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 18 - 18: II111iiii - iII111i / iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / o0oOOo0O0Ooo
  lprint ( ooO . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # OOooOOo . i1IIi / OOooOOo
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , Ooo0 ) )
  if 79 - 79: iII111i * o0oOOo0O0Ooo % iII111i / o0oOOo0O0Ooo
  oOoOOoo = self . keys
  for oo000oo0oOo0 in self . itr_rlocs :
   if ( oo000oo0oOo0 . afi == LISP_AFI_LCAF and self . json_telemetry != None ) :
    continue
    if 19 - 19: OoO0O00 . I11i / i11iIiiIii - OoOoOO00 * I11i . IiII
   Ii1i = red ( oo000oo0oOo0 . print_address_no_iid ( ) , False )
   lprint ( "  itr-rloc: afi {} {}{}" . format ( oo000oo0oOo0 . afi , Ii1i ,
 "" if ( oOoOOoo == None ) else ", " + oOoOOoo [ 1 ] . print_keys ( ) ) )
   oOoOOoo = None
   if 45 - 45: I1Ii111 - O0 . I1Ii111 / I1Ii111 / OoOoOO00
  if ( self . json_telemetry != None ) :
   lprint ( "  itr-rloc: afi {} telemetry: {}" . format ( LISP_AFI_LCAF ,
 self . json_telemetry ) )
   if 12 - 12: OOooOOo
   if 75 - 75: OOooOOo + Ii1I + oO0o . Oo0Ooo
   if 93 - 93: OOooOOo * Ii1I - o0oOOo0O0Ooo . oO0o . iII111i
 def sign_map_request ( self , privkey ) :
  OOooo = self . signature_eid . print_address ( )
  i1i1I11I = self . source_eid . print_address ( )
  i11I1ii = self . target_eid . print_address ( )
  o0o000O0o = lisp_hex_string ( self . nonce ) + i1i1I11I + i11I1ii
  self . map_request_signature = privkey . sign ( o0o000O0o . encode ( ) )
  iIiI = binascii . b2a_base64 ( self . map_request_signature )
  iIiI = { "source-eid" : i1i1I11I , "signature-eid" : OOooo ,
 "signature" : iIiI . decode ( ) }
  return ( json . dumps ( iIiI ) )
  if 42 - 42: i11iIiiIii * o0oOOo0O0Ooo % I11i % Oo0Ooo + o0oOOo0O0Ooo * i11iIiiIii
  if 66 - 66: Ii1I / IiII . OoooooooOO * Oo0Ooo % i11iIiiIii
 def verify_map_request_sig ( self , pubkey ) :
  OO0oOo00OO0 = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( OO0oOo00OO0 ) )
   return ( False )
   if 25 - 25: Oo0Ooo * IiII % I1IiiI . iII111i % iII111i * Oo0Ooo
   if 1 - 1: Oo0Ooo / ooOoO0o * Ii1I - OoooooooOO * I11i * OOooOOo
  i1i1I11I = self . source_eid . print_address ( )
  i11I1ii = self . target_eid . print_address ( )
  o0o000O0o = lisp_hex_string ( self . nonce ) + i1i1I11I + i11I1ii
  pubkey = binascii . a2b_base64 ( pubkey )
  if 63 - 63: II111iiii - o0oOOo0O0Ooo * i11iIiiIii / I11i * iII111i - iII111i
  iIi = True
  try :
   oO0oOo = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 48 - 48: I1ii11iIi11i % II111iiii + I11i
   iIi = False
   if 25 - 25: IiII * o0oOOo0O0Ooo / I1IiiI . IiII % II111iiii
   if 50 - 50: OoOoOO00 * iII111i
  if ( iIi ) :
   try :
    o0o000O0o = o0o000O0o . encode ( )
    iIi = oO0oOo . verify ( self . map_request_signature , o0o000O0o )
   except :
    iIi = False
    if 59 - 59: I1IiiI * I1IiiI / I11i
    if 92 - 92: o0oOOo0O0Ooo
    if 8 - 8: iII111i + I1ii11iIi11i . Ii1I
  ii1I11 = bold ( "passed" if iIi else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( ii1I11 , OO0oOo00OO0 ) )
  return ( iIi )
  if 47 - 47: OoooooooOO + Ii1I
  if 44 - 44: Ii1I * OoOoOO00 + Oo0Ooo . i11iIiiIii + i1IIi
 def encode_json ( self , json_string ) :
  oo0O00o0oO00 = LISP_LCAF_JSON_TYPE
  o00O00 = socket . htons ( LISP_AFI_LCAF )
  IIiii11IiIi = socket . htons ( len ( json_string ) + 4 )
  I1II1 = socket . htons ( len ( json_string ) )
  Oo00O0o0O = struct . pack ( "HBBBBHH" , o00O00 , 0 , 0 , oo0O00o0oO00 , 0 , IIiii11IiIi ,
 I1II1 )
  Oo00O0o0O += json_string . encode ( )
  Oo00O0o0O += struct . pack ( "H" , 0 )
  return ( Oo00O0o0O )
  if 90 - 90: I1IiiI - i11iIiiIii
  if 42 - 42: OOooOOo . Oo0Ooo
 def encode ( self , probe_dest , probe_port ) :
  IiiI11iIi = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  if 21 - 21: iII111i . I1IiiI / I11i
  ooOoO00 = lisp_telemetry_configured ( ) if ( self . rloc_probe ) else None
  if ( ooOoO00 != None ) : self . itr_rloc_count += 1
  IiiI11iIi = IiiI11iIi | ( self . itr_rloc_count << 8 )
  if 61 - 61: i11iIiiIii % I1Ii111 / o0oOOo0O0Ooo
  if ( self . auth_bit ) : IiiI11iIi |= 0x08000000
  if ( self . map_data_present ) : IiiI11iIi |= 0x04000000
  if ( self . rloc_probe ) : IiiI11iIi |= 0x02000000
  if ( self . smr_bit ) : IiiI11iIi |= 0x01000000
  if ( self . pitr_bit ) : IiiI11iIi |= 0x00800000
  if ( self . smr_invoked_bit ) : IiiI11iIi |= 0x00400000
  if ( self . mobile_node ) : IiiI11iIi |= 0x00200000
  if ( self . xtr_id_present ) : IiiI11iIi |= 0x00100000
  if ( self . decent_nat_xtr ) : IiiI11iIi |= 0x00008000
  if ( self . local_xtr ) : IiiI11iIi |= 0x00004000
  if ( self . dont_reply_bit ) : IiiI11iIi |= 0x00002000
  if 40 - 40: OOooOOo / Ii1I % I1IiiI / o0oOOo0O0Ooo . iII111i
  Oo00O0o0O = struct . pack ( "I" , socket . htonl ( IiiI11iIi ) )
  Oo00O0o0O += struct . pack ( "Q" , self . nonce )
  if 78 - 78: I11i - I1IiiI * IiII
  if 43 - 43: OoooooooOO . OOooOOo
  if 33 - 33: o0oOOo0O0Ooo % OoOoOO00 * I1IiiI
  if 26 - 26: I11i . iII111i . o0oOOo0O0Ooo
  if 15 - 15: OoO0O00 / iII111i
  if 46 - 46: OoooooooOO . I1Ii111
  i11III1ii1i = False
  o0OOo = self . privkey_filename
  if ( o0OOo != None and os . path . exists ( o0OOo ) ) :
   iIi1iii = open ( o0OOo , "r" ) ; oO0oOo = iIi1iii . read ( ) ; iIi1iii . close ( )
   try :
    oO0oOo = ecdsa . SigningKey . from_pem ( oO0oOo )
   except :
    return ( None )
    if 42 - 42: o0oOOo0O0Ooo - ooOoO0o . OOooOOo / iII111i / o0oOOo0O0Ooo . IiII
   I11i1I1111i = self . sign_map_request ( oO0oOo )
   i11III1ii1i = True
  elif ( self . map_request_signature != None ) :
   iIiI = binascii . b2a_base64 ( self . map_request_signature )
   I11i1I1111i = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : iIiI }
   I11i1I1111i = json . dumps ( I11i1I1111i )
   i11III1ii1i = True
   if 20 - 20: OoooooooOO * I1Ii111
  if ( i11III1ii1i ) :
   Oo00O0o0O += self . encode_json ( I11i1I1111i )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    Oo00O0o0O += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    Oo00O0o0O += self . source_eid . lcaf_encode_iid ( )
   else :
    Oo00O0o0O += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    Oo00O0o0O += self . source_eid . pack_address ( )
    if 38 - 38: iII111i . OoooooooOO
    if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
    if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
    if 61 - 61: I11i
    if 100 - 100: O0 - iIii1I11I1II1 * Oo0Ooo
    if 35 - 35: ooOoO0o
    if 57 - 57: OoO0O00 . Oo0Ooo + I1IiiI
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   O00oO000Oo0 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 18 - 18: I1IiiI - I1ii11iIi11i * I11i / i11iIiiIii - o0oOOo0O0Ooo % o0oOOo0O0Ooo
   if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_encap ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ]
    if 31 - 31: I11i
    if 100 - 100: i11iIiiIii * i11iIiiIii . iIii1I11I1II1 % iII111i * I1ii11iIi11i
    if 17 - 17: Ii1I * IiII * i11iIiiIii / I1ii11iIi11i / i11iIiiIii
    if 23 - 23: OoooooooOO + i11iIiiIii / Oo0Ooo / iII111i . iII111i * I1IiiI
    if 98 - 98: IiII
    if 23 - 23: I11i / i1IIi * OoO0O00
    if 51 - 51: OOooOOo - OoooooooOO / OoooooooOO % OoooooooOO
  for oo000oo0oOo0 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( oo000oo0oOo0 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     oOoOOoo = lisp_keys ( 1 )
     self . keys = [ None , oOoOOoo , None , None ]
     if 85 - 85: OoO0O00 . o0oOOo0O0Ooo . I1IiiI
    oOoOOoo = self . keys [ 1 ]
    oOoOOoo . add_key_by_nonce ( self . nonce )
    Oo00O0o0O += oOoOOoo . encode_lcaf ( oo000oo0oOo0 )
   else :
    Oo00O0o0O += struct . pack ( "H" , socket . htons ( oo000oo0oOo0 . afi ) )
    Oo00O0o0O += oo000oo0oOo0 . pack_address ( )
    if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
    if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
    if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
    if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
    if 24 - 24: IiII * I1IiiI / OOooOOo
    if 51 - 51: iIii1I11I1II1 / I11i * OoO0O00 * Ii1I + I1ii11iIi11i . OoooooooOO
  if ( ooOoO00 != None ) :
   iIiIIIIIii = str ( time . time ( ) )
   ooOoO00 = lisp_encode_telemetry ( ooOoO00 , io = iIiIIIIIii )
   self . json_telemetry = ooOoO00
   Oo00O0o0O += self . encode_json ( ooOoO00 )
   if 75 - 75: IiII / OoooooooOO / O0 % OOooOOo
   if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
  iII1IiI1I11i = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 10 - 10: II111iiii % I1IiiI % Ii1I * I1ii11iIi11i
  if 74 - 74: o0oOOo0O0Ooo / OoO0O00 + iII111i - i1IIi / OoooooooOO / I1ii11iIi11i
  oOoO0O = 0
  if ( self . subscribe_bit ) :
   oOoO0O = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 97 - 97: I1IiiI * o0oOOo0O0Ooo
    if 79 - 79: iII111i - ooOoO0o - OoO0O00 / iIii1I11I1II1 % Ii1I
    if 2 - 2: iIii1I11I1II1 + OoooooooOO - i1IIi / Ii1I
  ii = "BB"
  Oo00O0o0O += struct . pack ( ii , oOoO0O , iII1IiI1I11i )
  if 88 - 88: I1ii11iIi11i . OoooooooOO / Oo0Ooo / o0oOOo0O0Ooo % Oo0Ooo
  if ( self . target_group . is_null ( ) == False ) :
   Oo00O0o0O += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   Oo00O0o0O += self . target_eid . lcaf_encode_sg ( self . target_group )
  elif ( self . target_eid . instance_id != 0 or
 self . target_eid . is_geo_prefix ( ) ) :
   Oo00O0o0O += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
   Oo00O0o0O += self . target_eid . lcaf_encode_iid ( )
  else :
   Oo00O0o0O += struct . pack ( "H" , socket . htons ( self . target_eid . afi ) )
   Oo00O0o0O += self . target_eid . pack_address ( )
   if 80 - 80: Ii1I + OoO0O00 * OoooooooOO - IiII % O0 - I1Ii111
   if 80 - 80: II111iiii / I1ii11iIi11i
   if 60 - 60: OOooOOo - iII111i + iIii1I11I1II1 + II111iiii + iII111i
   if 35 - 35: Oo0Ooo * O0 / oO0o * i1IIi . I11i . O0
   if 22 - 22: oO0o / II111iiii . OoOoOO00
  if ( self . subscribe_bit ) : Oo00O0o0O = self . encode_xtr_id ( Oo00O0o0O )
  return ( Oo00O0o0O )
  if 9 - 9: i11iIiiIii + ooOoO0o . iIii1I11I1II1 * OoOoOO00
  if 4 - 4: I1Ii111 + iII111i % O0
 def lcaf_decode_json ( self , packet ) :
  ii = "BBBBHH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 98 - 98: i1IIi + I1Ii111 - I1ii11iIi11i . OoooooooOO / O0 / iII111i
  Oo0oOo0Ooo , iiI1 , oo0O00o0oO00 , IiI1 , IIiii11IiIi , I1II1 = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 53 - 53: I1Ii111 + IiII . i1IIi
  if 26 - 26: i11iIiiIii - II111iiii
  if ( oo0O00o0oO00 != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 43 - 43: I1IiiI
  if 35 - 35: ooOoO0o + OoOoOO00 * OoooooooOO - II111iiii
  if 19 - 19: i1IIi / Ii1I / OoOoOO00 . I1IiiI / Ii1I % o0oOOo0O0Ooo
  if 39 - 39: ooOoO0o - OoooooooOO
  IIiii11IiIi = socket . ntohs ( IIiii11IiIi )
  I1II1 = socket . ntohs ( I1II1 )
  packet = packet [ OOOO00oo00oo : : ]
  if ( len ( packet ) < IIiii11IiIi ) : return ( None )
  if ( IIiii11IiIi != I1II1 + 4 ) : return ( None )
  if 88 - 88: i1IIi + iIii1I11I1II1 * i11iIiiIii - OoooooooOO % o0oOOo0O0Ooo
  if 74 - 74: ooOoO0o - i11iIiiIii
  if 34 - 34: IiII + I1Ii111 + Oo0Ooo / II111iiii
  if 33 - 33: Ii1I . i1IIi - II111iiii - OoO0O00
  I11i1I1111i = packet [ 0 : I1II1 ]
  packet = packet [ I1II1 : : ]
  if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
  if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
  if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
  if 52 - 52: O0 . I1Ii111 + iII111i / i11iIiiIii
  if ( lisp_is_json_telemetry ( I11i1I1111i ) != None ) :
   self . json_telemetry = I11i1I1111i
   if 52 - 52: oO0o % Oo0Ooo * II111iiii
   if 24 - 24: i11iIiiIii * i1IIi * i1IIi
   if 27 - 27: i1IIi - oO0o + OOooOOo
   if 3 - 3: IiII % I1Ii111 . OoooooooOO
   if 19 - 19: I1Ii111 * Ii1I - oO0o
  ii = "H"
  OOOO00oo00oo = struct . calcsize ( ii )
  IiIIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  if ( IiIIi != 0 ) : return ( packet )
  if 78 - 78: OoO0O00 - Ii1I / OOooOOo
  if ( self . json_telemetry != None ) : return ( packet )
  if 81 - 81: OoOoOO00
  if 21 - 21: iII111i / OOooOOo % IiII
  if 51 - 51: I11i + ooOoO0o / I1IiiI
  if 3 - 3: iIii1I11I1II1 / OOooOOo % oO0o . Ii1I - Ii1I
  try :
   I11i1I1111i = json . loads ( I11i1I1111i )
  except :
   return ( None )
   if 55 - 55: i11iIiiIii % OoooooooOO + O0
   if 7 - 7: ooOoO0o - i11iIiiIii * iII111i / Ii1I - o0oOOo0O0Ooo
   if 62 - 62: o0oOOo0O0Ooo - iIii1I11I1II1 . I11i . Ii1I * Ii1I
   if 24 - 24: I11i
   if 93 - 93: I1IiiI % OoO0O00 / i11iIiiIii / I11i
  if ( "source-eid" not in I11i1I1111i ) : return ( packet )
  O0o00o0Oo = I11i1I1111i [ "source-eid" ]
  IiIIi = LISP_AFI_IPV4 if O0o00o0Oo . count ( "." ) == 3 else LISP_AFI_IPV6 if O0o00o0Oo . count ( ":" ) == 7 else None
  if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
  if ( IiIIi == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( O0o00o0Oo ) )
   return ( None )
   if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
   if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
  self . source_eid . afi = IiIIi
  self . source_eid . store_address ( O0o00o0Oo )
  if 64 - 64: i1IIi / IiII . IiII - I1Ii111 % OOooOOo . II111iiii
  if ( "signature-eid" not in I11i1I1111i ) : return ( packet )
  O0o00o0Oo = I11i1I1111i [ "signature-eid" ]
  if ( O0o00o0Oo . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( O0o00o0Oo ) )
   return ( None )
   if 78 - 78: I1Ii111 - O0 - I1Ii111 . iIii1I11I1II1 % I1ii11iIi11i . OoooooooOO
   if 64 - 64: IiII
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( O0o00o0Oo )
  if 21 - 21: o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO
  if ( "signature" not in I11i1I1111i ) : return ( packet )
  iIiI = binascii . a2b_base64 ( I11i1I1111i [ "signature" ] )
  self . map_request_signature = iIiI
  return ( packet )
  if 17 - 17: OOooOOo - iII111i % I1IiiI * OOooOOo * iIii1I11I1II1 . o0oOOo0O0Ooo
  if 58 - 58: oO0o - II111iiii + O0
 def decode ( self , packet , source , port ) :
  ii = "I"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 54 - 54: iIii1I11I1II1 - IiII - IiII
  IiiI11iIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  IiiI11iIi = IiiI11iIi [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
  ii = "Q"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 63 - 63: iII111i - OoO0O00 * OOooOOo
  OOooO = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  packet = packet [ OOOO00oo00oo : : ]
  if 89 - 89: iII111i / Oo0Ooo
  IiiI11iIi = socket . ntohl ( IiiI11iIi )
  self . auth_bit = True if ( IiiI11iIi & 0x08000000 ) else False
  self . map_data_present = True if ( IiiI11iIi & 0x04000000 ) else False
  self . rloc_probe = True if ( IiiI11iIi & 0x02000000 ) else False
  self . smr_bit = True if ( IiiI11iIi & 0x01000000 ) else False
  self . pitr_bit = True if ( IiiI11iIi & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( IiiI11iIi & 0x00400000 ) else False
  self . mobile_node = True if ( IiiI11iIi & 0x00200000 ) else False
  self . xtr_id_present = True if ( IiiI11iIi & 0x00100000 ) else False
  self . decent_nat_xtr = True if ( IiiI11iIi & 0x00008000 ) else False
  self . local_xtr = True if ( IiiI11iIi & 0x00004000 ) else False
  self . dont_reply_bit = True if ( IiiI11iIi & 0x00002000 ) else False
  self . itr_rloc_count = ( ( IiiI11iIi >> 8 ) & 0x1f )
  self . record_count = IiiI11iIi & 0xff
  self . nonce = OOooO [ 0 ]
  if 66 - 66: o0oOOo0O0Ooo + OoOoOO00 % OoooooooOO . I11i
  if 30 - 30: II111iiii - Oo0Ooo - i11iIiiIii + O0
  if 93 - 93: i1IIi + I1Ii111 / OoO0O00 - I11i % Oo0Ooo / Ii1I
  if 1 - 1: Oo0Ooo / Ii1I . i11iIiiIii % OOooOOo + o0oOOo0O0Ooo + O0
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 54 - 54: I1Ii111 + ooOoO0o % IiII
   if 83 - 83: o0oOOo0O0Ooo * iIii1I11I1II1
  OOOO00oo00oo = struct . calcsize ( "H" )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 36 - 36: OoOoOO00 + II111iiii - OoO0O00 % ooOoO0o * i1IIi
  IiIIi = struct . unpack ( "H" , packet [ : OOOO00oo00oo ] )
  self . source_eid . afi = socket . ntohs ( IiIIi [ 0 ] )
  packet = packet [ OOOO00oo00oo : : ]
  if 4 - 4: Ii1I + OoO0O00 * I1ii11iIi11i
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   II111iii = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( II111iii )
    if ( packet == None ) : return ( None )
    if 61 - 61: OoO0O00 . i11iIiiIii - OoO0O00
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 8 - 8: I1ii11iIi11i * IiII / Oo0Ooo
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 99 - 99: OOooOOo * I1Ii111 . ooOoO0o - i1IIi - I11i % IiII
  IIi1IiiIi1 = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  OooOo0o0Oo0 = self . itr_rloc_count + 1
  if 29 - 29: ooOoO0o
  while ( OooOo0o0Oo0 != 0 ) :
   OOOO00oo00oo = struct . calcsize ( "H" )
   if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
   if 70 - 70: oO0o . O0 % I11i % IiII - I11i * I1ii11iIi11i
   IiIIi = socket . ntohs ( struct . unpack ( "H" , packet [ : OOOO00oo00oo ] ) [ 0 ] )
   oo000oo0oOo0 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   oo000oo0oOo0 . afi = IiIIi
   if 22 - 22: i1IIi
   if 82 - 82: oO0o . iIii1I11I1II1 - I1ii11iIi11i
   if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
   if 33 - 33: O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + iII111i - oO0o
   if 27 - 27: I1Ii111 + ooOoO0o - I1Ii111 % i11iIiiIii * Oo0Ooo * o0oOOo0O0Ooo
   if ( oo000oo0oOo0 . afi == LISP_AFI_LCAF ) :
    I11I = packet
    oo0OOoOO0 = packet [ OOOO00oo00oo : : ]
    packet = self . lcaf_decode_json ( oo0OOoOO0 )
    if ( packet == None ) : return ( None )
    if ( packet == oo0OOoOO0 ) : packet = I11I
    if 16 - 16: oO0o * iII111i % i1IIi . OoOoOO00 * iIii1I11I1II1
    if 17 - 17: OoooooooOO . OOooOOo
    if 32 - 32: OoOoOO00 . oO0o + O0
    if 100 - 100: O0 / OOooOOo - ooOoO0o
    if 15 - 15: iII111i - O0 - OoooooooOO
    if 49 - 49: II111iiii . OoooooooOO
   if ( oo000oo0oOo0 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < oo000oo0oOo0 . addr_length ( ) ) : return ( None )
    packet = oo000oo0oOo0 . unpack_address ( packet [ OOOO00oo00oo : : ] )
    if ( packet == None ) : return ( None )
    if 30 - 30: OoO0O00 / i11iIiiIii - OoO0O00 / ooOoO0o + iIii1I11I1II1 + i1IIi
    if ( IIi1IiiIi1 ) :
     self . itr_rlocs . append ( oo000oo0oOo0 )
     OooOo0o0Oo0 -= 1
     continue
     if 99 - 99: OOooOOo * I1IiiI + oO0o % oO0o % OOooOOo * IiII
     if 98 - 98: OOooOOo
    O00oO000Oo0 = lisp_build_crypto_decap_lookup_key ( oo000oo0oOo0 , port )
    if 97 - 97: o0oOOo0O0Ooo
    if 35 - 35: ooOoO0o + i11iIiiIii
    if 82 - 82: i11iIiiIii + I11i + iII111i % I1IiiI
    if 84 - 84: oO0o % OOooOOo
    if 25 - 25: i11iIiiIii * OoOoOO00 + i11iIiiIii . i1IIi
    if ( lisp_nat_traversal and oo000oo0oOo0 . is_private_address ( ) and source ) : oo000oo0oOo0 = source
    if 83 - 83: I1IiiI
    oo0O0oooO000oO0O = lisp_crypto_keys_by_rloc_decap
    if ( O00oO000Oo0 in oo0O0oooO000oO0O ) : oo0O0oooO000oO0O . pop ( O00oO000Oo0 )
    if 40 - 40: OOooOOo - OoO0O00 . OoooooooOO - oO0o / ooOoO0o + Oo0Ooo
    if 70 - 70: i1IIi / I11i / O0 . ooOoO0o / II111iiii
    if 86 - 86: O0 - OoO0O00 % I11i . oO0o
    if 49 - 49: i11iIiiIii - iIii1I11I1II1 % O0 % iII111i * ooOoO0o - IiII
    if 8 - 8: iIii1I11I1II1 * Oo0Ooo
    if 11 - 11: I1IiiI / OoooooooOO . Oo0Ooo
    lisp_write_ipc_decap_key ( O00oO000Oo0 , None )
    if 19 - 19: I1ii11iIi11i
   elif ( self . json_telemetry == None ) :
    if 41 - 41: OOooOOo + ooOoO0o
    if 15 - 15: OoOoOO00 - i11iIiiIii
    if 48 - 48: II111iiii % I11i
    if 96 - 96: o0oOOo0O0Ooo
    I11I = packet
    O0o0o00O0OO00 = lisp_keys ( 1 )
    packet = O0o0o00O0OO00 . decode_lcaf ( I11I , 0 )
    if 100 - 100: OoO0O00
    if ( packet == None ) : return ( None )
    if 25 - 25: I1Ii111 - ooOoO0o + Oo0Ooo . I1IiiI % iIii1I11I1II1
    if 49 - 49: i1IIi + OoO0O00 + iII111i / Oo0Ooo
    if 5 - 5: i11iIiiIii + I11i . IiII
    if 9 - 9: i11iIiiIii / iIii1I11I1II1 - I1ii11iIi11i * I1ii11iIi11i
    ooo0Oo000o = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( O0o0o00O0OO00 . cipher_suite in ooo0Oo000o ) :
     if ( O0o0o00O0OO00 . cipher_suite == LISP_CS_25519_CBC or
 O0o0o00O0OO00 . cipher_suite == LISP_CS_25519_GCM ) :
      oO0oOo = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 99 - 99: I11i
     if ( O0o0o00O0OO00 . cipher_suite == LISP_CS_25519_CHACHA ) :
      oO0oOo = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 64 - 64: iIii1I11I1II1
    else :
     oO0oOo = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 61 - 61: Ii1I % Oo0Ooo + OoOoOO00
    packet = oO0oOo . decode_lcaf ( I11I , 0 )
    if ( packet == None ) : return ( None )
    if 60 - 60: oO0o . OoooooooOO
    if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
    IiIIi = struct . unpack ( "H" , packet [ : OOOO00oo00oo ] ) [ 0 ]
    oo000oo0oOo0 . afi = socket . ntohs ( IiIIi )
    if ( len ( packet ) < oo000oo0oOo0 . addr_length ( ) ) : return ( None )
    if 40 - 40: I11i
    packet = oo000oo0oOo0 . unpack_address ( packet [ OOOO00oo00oo : : ] )
    if ( packet == None ) : return ( None )
    if 44 - 44: ooOoO0o
    if ( IIi1IiiIi1 ) :
     self . itr_rlocs . append ( oo000oo0oOo0 )
     OooOo0o0Oo0 -= 1
     continue
     if 35 - 35: II111iiii + iII111i / I1ii11iIi11i * I1IiiI . I11i
     if 97 - 97: I1IiiI / o0oOOo0O0Ooo
    O00oO000Oo0 = lisp_build_crypto_decap_lookup_key ( oo000oo0oOo0 , port )
    if 13 - 13: I1ii11iIi11i
    OOo000 = None
    if ( lisp_nat_traversal and oo000oo0oOo0 . is_private_address ( ) and source ) : oo000oo0oOo0 = source
    if 40 - 40: I1ii11iIi11i * iIii1I11I1II1 % OoOoOO00
    if 50 - 50: i11iIiiIii + ooOoO0o
    if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_decap ) :
     oOoOOoo = lisp_crypto_keys_by_rloc_decap [ O00oO000Oo0 ]
     OOo000 = oOoOOoo [ 1 ] if oOoOOoo and oOoOOoo [ 1 ] else None
     if 41 - 41: I1IiiI * OoO0O00 + IiII / OoO0O00 . I1Ii111
     if 2 - 2: O0 % o0oOOo0O0Ooo
    iiI1ooOOOoo = True
    if ( OOo000 ) :
     if ( OOo000 . compare_keys ( oO0oOo ) ) :
      self . keys = [ None , OOo000 , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( O00oO000Oo0 , False ) ) )
      if 26 - 26: i1IIi
     else :
      iiI1ooOOOoo = False
      i111I = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( i111I , red ( O00oO000Oo0 ,
 False ) ) )
      oO0oOo . copy_keypair ( OOo000 )
      oO0oOo . uptime = OOo000 . uptime
      OOo000 = None
      if 10 - 10: ooOoO0o % O0 + iIii1I11I1II1 % O0 * oO0o
      if 53 - 53: ooOoO0o + iII111i * i1IIi + I1IiiI
      if 89 - 89: I1IiiI / II111iiii - OoOoOO00 % o0oOOo0O0Ooo
    if ( OOo000 == None ) :
     self . keys = [ None , oO0oOo , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      oO0oOo . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( O00oO000Oo0 , False ) ) )
     elif ( oO0oOo . remote_public_key != None ) :
      if ( iiI1ooOOOoo ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # OOooOOo
 red ( O00oO000Oo0 , False ) ) )
       if 5 - 5: I11i / OoOoOO00
      oO0oOo . compute_shared_key ( "decap" )
      oO0oOo . add_key_by_rloc ( O00oO000Oo0 , False )
      if 48 - 48: i1IIi - oO0o . OoooooooOO - OoO0O00 - i1IIi
      if 19 - 19: oO0o % Ii1I + I1ii11iIi11i . II111iiii * i11iIiiIii
      if 87 - 87: Ii1I / I1Ii111 % OoOoOO00 * I1ii11iIi11i - OoooooooOO / OoOoOO00
      if 24 - 24: I11i . OOooOOo * i1IIi . I1ii11iIi11i / ooOoO0o / O0
   self . itr_rlocs . append ( oo000oo0oOo0 )
   OooOo0o0Oo0 -= 1
   if 62 - 62: o0oOOo0O0Ooo % II111iiii
   if 22 - 22: oO0o - o0oOOo0O0Ooo
  OOOO00oo00oo = struct . calcsize ( "BBH" )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 89 - 89: OOooOOo
  oOoO0O , iII1IiI1I11i , IiIIi = struct . unpack ( "BBH" , packet [ : OOOO00oo00oo ] )
  self . subscribe_bit = ( oOoO0O & 0x80 )
  self . target_eid . afi = socket . ntohs ( IiIIi )
  packet = packet [ OOOO00oo00oo : : ]
  if 34 - 34: iII111i . OOooOOo
  self . target_eid . mask_len = iII1IiI1I11i
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , iII1Ii1ii111 = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( iII1Ii1ii111 ) : self . target_group = iII1Ii1ii111
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ OOOO00oo00oo : : ]
   if 22 - 22: Ii1I
  return ( packet )
  if 44 - 44: I1Ii111 % OoOoOO00 + I1Ii111 / OoO0O00
  if 73 - 73: Oo0Ooo . I11i * iII111i . I1ii11iIi11i . O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 38 - 38: oO0o
  if 17 - 17: oO0o / iII111i . Ii1I - II111iiii
 def encode_xtr_id ( self , packet ) :
  o00 = self . xtr_id >> 64
  o000 = self . xtr_id & 0xffffffffffffffff
  o00 = byte_swap_64 ( o00 )
  o000 = byte_swap_64 ( o000 )
  packet += struct . pack ( "QQ" , o00 , o000 )
  return ( packet )
  if 6 - 6: OOooOOo / OoOoOO00 * o0oOOo0O0Ooo % OoO0O00 + I1Ii111 + iII111i
  if 43 - 43: iII111i
 def decode_xtr_id ( self , packet ) :
  OOOO00oo00oo = struct . calcsize ( "QQ" )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  packet = packet [ len ( packet ) - OOOO00oo00oo : : ]
  o00 , o000 = struct . unpack ( "QQ" , packet [ : OOOO00oo00oo ] )
  o00 = byte_swap_64 ( o00 )
  o000 = byte_swap_64 ( o000 )
  self . xtr_id = ( o00 << 64 ) | o000
  return ( True )
  if 25 - 25: OOooOOo % iII111i + iII111i
  if 41 - 41: OoO0O00 / I1ii11iIi11i . I1ii11iIi11i / i1IIi - i1IIi - I1ii11iIi11i
  if 78 - 78: iII111i % iII111i % O0 - I11i - OoO0O00
  if 59 - 59: I1IiiI / I1ii11iIi11i * i1IIi % iII111i
  if 78 - 78: iIii1I11I1II1 / I1ii11iIi11i / IiII
  if 11 - 11: I11i
  if 59 - 59: OOooOOo - I1Ii111 - II111iiii / i1IIi * OOooOOo . OoooooooOO
  if 46 - 46: IiII * OoooooooOO . o0oOOo0O0Ooo - I1Ii111 * I1IiiI
  if 83 - 83: Oo0Ooo . o0oOOo0O0Ooo + iII111i + o0oOOo0O0Ooo % iIii1I11I1II1 * OoOoOO00
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
class lisp_map_reply ( object ) :
 def __init__ ( self ) :
  self . rloc_probe = False
  self . echo_nonce_capable = False
  self . security = False
  self . record_count = 0
  self . hop_count = 0
  self . nonce = 0
  self . keys = None
  if 20 - 20: O0 . I11i
  if 67 - 67: OoOoOO00 - ooOoO0o - iIii1I11I1II1
 def print_map_reply ( self ) :
  ooO = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
  lprint ( ooO . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # I1IiiI * IiII - iII111i % I1ii11iIi11i / OoooooooOO
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 65 - 65: OoO0O00 * I11i
  if 37 - 37: Ii1I % OoO0O00 . I1Ii111 + i1IIi
 def encode ( self ) :
  IiiI11iIi = ( LISP_MAP_REPLY << 28 ) | self . record_count
  IiiI11iIi |= self . hop_count << 8
  if ( self . rloc_probe ) : IiiI11iIi |= 0x08000000
  if ( self . echo_nonce_capable ) : IiiI11iIi |= 0x04000000
  if ( self . security ) : IiiI11iIi |= 0x02000000
  if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
  Oo00O0o0O = struct . pack ( "I" , socket . htonl ( IiiI11iIi ) )
  Oo00O0o0O += struct . pack ( "Q" , self . nonce )
  return ( Oo00O0o0O )
  if 65 - 65: ooOoO0o + IiII - OoOoOO00 % II111iiii - iIii1I11I1II1
  if 39 - 39: I1IiiI + I1ii11iIi11i - i11iIiiIii
 def decode ( self , packet ) :
  ii = "I"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 43 - 43: iIii1I11I1II1
  IiiI11iIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  IiiI11iIi = IiiI11iIi [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  if 73 - 73: OoOoOO00 + o0oOOo0O0Ooo
  ii = "Q"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 58 - 58: i1IIi * I1ii11iIi11i % iII111i . OoO0O00 % IiII % I11i
  OOooO = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  packet = packet [ OOOO00oo00oo : : ]
  if 63 - 63: I1ii11iIi11i % ooOoO0o % I1ii11iIi11i
  IiiI11iIi = socket . ntohl ( IiiI11iIi )
  self . rloc_probe = True if ( IiiI11iIi & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( IiiI11iIi & 0x04000000 ) else False
  self . security = True if ( IiiI11iIi & 0x02000000 ) else False
  self . hop_count = ( IiiI11iIi >> 8 ) & 0xff
  self . record_count = IiiI11iIi & 0xff
  self . nonce = OOooO [ 0 ]
  if 71 - 71: Ii1I
  if ( self . nonce in lisp_crypto_keys_by_nonce ) :
   self . keys = lisp_crypto_keys_by_nonce [ self . nonce ]
   self . keys [ 1 ] . delete_key_by_nonce ( self . nonce )
   if 43 - 43: o0oOOo0O0Ooo / ooOoO0o
  return ( packet )
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
  if 28 - 28: O0 % iII111i - i1IIi
  if 49 - 49: ooOoO0o . I11i - iIii1I11I1II1
  if 41 - 41: ooOoO0o * i11iIiiIii % ooOoO0o . oO0o
  if 97 - 97: oO0o - iII111i + IiII . OoOoOO00 + iIii1I11I1II1
  if 75 - 75: ooOoO0o + ooOoO0o . I1Ii111 % iII111i / iIii1I11I1II1 * iII111i
  if 13 - 13: II111iiii * i11iIiiIii - i1IIi * OoO0O00 + i1IIi
  if 43 - 43: O0 % oO0o * I1IiiI
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
  if 64 - 64: II111iiii + i11iIiiIii
  if 17 - 17: O0 * I1IiiI
 def print_prefix ( self ) :
  if ( self . group . is_null ( ) ) :
   return ( green ( self . eid . print_prefix ( ) , False ) )
   if 40 - 40: iIii1I11I1II1 * iII111i % iIii1I11I1II1
  return ( green ( self . eid . print_sg ( self . group ) , False ) )
  if 39 - 39: i1IIi . Ii1I - Oo0Ooo
  if 91 - 91: I1IiiI - OoooooooOO - OoooooooOO
 def print_ttl ( self ) :
  o0ooo000o00O = self . record_ttl
  if ( self . record_ttl & 0x80000000 ) :
   o0ooo000o00O = str ( self . record_ttl & 0x7fffffff ) + " secs"
  elif ( ( o0ooo000o00O % 60 ) == 0 ) :
   o0ooo000o00O = str ( old_div ( o0ooo000o00O , 60 ) ) + " hours"
  else :
   o0ooo000o00O = str ( o0ooo000o00O ) + " mins"
   if 7 - 7: I1Ii111 / Ii1I * II111iiii * OoOoOO00 - OoooooooOO
  return ( o0ooo000o00O )
  if 92 - 92: OoOoOO00 . i1IIi
  if 24 - 24: Oo0Ooo + I11i
 def store_ttl ( self ) :
  o0ooo000o00O = self . record_ttl * 60
  if ( self . record_ttl & 0x80000000 ) : o0ooo000o00O = self . record_ttl & 0x7fffffff
  return ( o0ooo000o00O )
  if 9 - 9: iII111i / O0 . Ii1I / o0oOOo0O0Ooo + I1ii11iIi11i
  if 32 - 32: IiII
 def print_record ( self , indent , ddt ) :
  iiIIi = ""
  IIi1I1iiiii = ""
  iI1i1i = bold ( "invalid-action" , False )
  if ( ddt ) :
   if ( self . action < len ( lisp_map_referral_action_string ) ) :
    iI1i1i = lisp_map_referral_action_string [ self . action ]
    iI1i1i = bold ( iI1i1i , False )
    iiIIi = ( ", " + bold ( "ddt-incomplete" , False ) ) if self . ddt_incomplete else ""
    if 46 - 46: OOooOOo
    IIi1I1iiiii = ( ", sig-count: " + str ( self . signature_count ) ) if ( self . signature_count != 0 ) else ""
    if 64 - 64: I1IiiI / OoOoOO00
    if 6 - 6: i11iIiiIii - iII111i * i1IIi - iII111i
  else :
   if ( self . action < len ( lisp_map_reply_action_string ) ) :
    iI1i1i = lisp_map_reply_action_string [ self . action ]
    if ( self . action != LISP_NO_ACTION ) :
     iI1i1i = bold ( iI1i1i , False )
     if 8 - 8: I11i / i11iIiiIii . O0 / OoO0O00 * oO0o + I1Ii111
     if 91 - 91: I1IiiI
     if 84 - 84: O0 % Ii1I
     if 3 - 3: I1IiiI . I11i / I1ii11iIi11i
  IiIIi = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  ooO = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
  lprint ( ooO . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 iI1i1i , "auth" if ( self . authoritative is True ) else "non-auth" ,
 iiIIi , IIi1I1iiiii , self . map_version , IiIIi ,
 green ( self . print_prefix ( ) , False ) ) )
  if 14 - 14: Oo0Ooo . O0 - oO0o - i11iIiiIii
  if 8 - 8: I1IiiI / iIii1I11I1II1 / OoooooooOO / Oo0Ooo / ooOoO0o
 def encode ( self ) :
  oo0OoooOo0 = self . action << 13
  if ( self . authoritative ) : oo0OoooOo0 |= 0x1000
  if ( self . ddt_incomplete ) : oo0OoooOo0 |= 0x800
  if 61 - 61: II111iiii . OoO0O00 - II111iiii
  if 75 - 75: Oo0Ooo - OoOoOO00 + oO0o % i1IIi * OOooOOo
  if 56 - 56: OoOoOO00 / OoO0O00 / I1IiiI % OoooooooOO
  if 39 - 39: I1IiiI + II111iiii * Oo0Ooo % Ii1I . o0oOOo0O0Ooo * oO0o
  IiIIi = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( IiIIi < 0 ) : IiIIi = LISP_AFI_LCAF
  i1Ii1 = ( self . group . is_null ( ) == False )
  if ( i1Ii1 ) : IiIIi = LISP_AFI_LCAF
  if 70 - 70: IiII
  OO00OO00O00O0 = ( self . signature_count << 12 ) | self . map_version
  iII1IiI1I11i = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 75 - 75: i1IIi
  Oo00O0o0O = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , iII1IiI1I11i , socket . htons ( oo0OoooOo0 ) ,
 socket . htons ( OO00OO00O00O0 ) , socket . htons ( IiIIi ) )
  if 92 - 92: I1Ii111 + iIii1I11I1II1 . OoooooooOO + oO0o + I1Ii111
  if 96 - 96: i1IIi - I1Ii111 / o0oOOo0O0Ooo / OoO0O00 - OOooOOo
  if 3 - 3: o0oOOo0O0Ooo + OoOoOO00 / oO0o - Ii1I % Ii1I
  if 8 - 8: IiII
  if ( i1Ii1 ) :
   Oo00O0o0O += self . eid . lcaf_encode_sg ( self . group )
   return ( Oo00O0o0O )
   if 68 - 68: IiII . OoooooooOO - i11iIiiIii + i11iIiiIii
   if 81 - 81: OoOoOO00 + iII111i . i11iIiiIii
   if 10 - 10: OoOoOO00 + I11i - iIii1I11I1II1 - I11i
   if 58 - 58: ooOoO0o
   if 98 - 98: Ii1I / OoO0O00 % OoooooooOO
  if ( self . eid . afi == LISP_AFI_GEO_COORD and self . eid . instance_id == 0 ) :
   Oo00O0o0O = Oo00O0o0O [ 0 : - 2 ]
   Oo00O0o0O += self . eid . address . encode_geo ( )
   return ( Oo00O0o0O )
   if 65 - 65: ooOoO0o % Oo0Ooo - I1IiiI % I1Ii111 + iIii1I11I1II1 / iIii1I11I1II1
   if 94 - 94: IiII - Oo0Ooo . o0oOOo0O0Ooo - ooOoO0o - oO0o . I11i
   if 39 - 39: oO0o + OoOoOO00
   if 68 - 68: i1IIi * oO0o / i11iIiiIii
   if 96 - 96: I1IiiI
  if ( IiIIi == LISP_AFI_LCAF ) :
   Oo00O0o0O += self . eid . lcaf_encode_iid ( )
   return ( Oo00O0o0O )
   if 78 - 78: OoO0O00
   if 72 - 72: I1ii11iIi11i / O0 % II111iiii / II111iiii
   if 48 - 48: OOooOOo % OOooOOo / iIii1I11I1II1 - i11iIiiIii
   if 57 - 57: I11i / IiII * i1IIi + II111iiii . o0oOOo0O0Ooo
   if 11 - 11: II111iiii
  Oo00O0o0O += self . eid . pack_address ( )
  return ( Oo00O0o0O )
  if 66 - 66: Ii1I - I1IiiI . OoooooooOO * I1Ii111
  if 16 - 16: IiII * OoO0O00 * i11iIiiIii - ooOoO0o
 def decode ( self , packet ) :
  ii = "IBBHHH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 88 - 88: iIii1I11I1II1 / Ii1I * IiII / I1Ii111
  self . record_ttl , self . rloc_count , self . eid . mask_len , oo0OoooOo0 , self . map_version , self . eid . afi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 31 - 31: O0 . I1IiiI
  if 8 - 8: OoOoOO00
  if 99 - 99: iII111i
  self . record_ttl = socket . ntohl ( self . record_ttl )
  oo0OoooOo0 = socket . ntohs ( oo0OoooOo0 )
  self . action = ( oo0OoooOo0 >> 13 ) & 0x7
  self . authoritative = True if ( ( oo0OoooOo0 >> 12 ) & 1 ) else False
  self . ddt_incomplete = True if ( ( oo0OoooOo0 >> 11 ) & 1 ) else False
  self . map_version = socket . ntohs ( self . map_version )
  self . signature_count = self . map_version >> 12
  self . map_version = self . map_version & 0xfff
  self . eid . afi = socket . ntohs ( self . eid . afi )
  self . eid . instance_id = 0
  packet = packet [ OOOO00oo00oo : : ]
  if 93 - 93: I1Ii111
  if 39 - 39: Ii1I
  if 10 - 10: OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i % iII111i / i11iIiiIii
  if 14 - 14: i11iIiiIii % o0oOOo0O0Ooo * O0 % iIii1I11I1II1 . IiII - II111iiii
  if ( self . eid . afi == LISP_AFI_LCAF ) :
   packet , i1I1IIIiII = self . eid . lcaf_decode_eid ( packet )
   if ( i1I1IIIiII ) : self . group = i1I1IIIiII
   self . group . instance_id = self . eid . instance_id
   return ( packet )
   if 24 - 24: I1Ii111 . oO0o + ooOoO0o . I1ii11iIi11i . II111iiii
   if 25 - 25: I1IiiI
  packet = self . eid . unpack_address ( packet )
  return ( packet )
  if 88 - 88: i1IIi
  if 93 - 93: I1ii11iIi11i . OoO0O00
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
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
  if 91 - 91: i11iIiiIii / i11iIiiIii
  if 9 - 9: I11i / I1Ii111 + iIii1I11I1II1 + I1IiiI - II111iiii
  if 96 - 96: iII111i + Oo0Ooo - OoooooooOO . i1IIi + i1IIi % iIii1I11I1II1
LISP_UDP_PROTOCOL = 17
LISP_DEFAULT_ECM_TTL = 128
if 80 - 80: OoooooooOO / O0 / I1Ii111 - Oo0Ooo . i11iIiiIii
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
  if 3 - 3: Oo0Ooo - OOooOOo * OoO0O00 - II111iiii . OoooooooOO
  if 14 - 14: I1IiiI
 def print_ecm ( self ) :
  ooO = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 41 - 41: I1Ii111 % i1IIi + OoO0O00 / oO0o
  lprint ( ooO . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
 "D" if self . ddt else "d" , "E" if self . to_etr else "e" ,
 "M" if self . to_ms else "m" ,
 green ( self . source . print_address ( ) , False ) ,
 green ( self . dest . print_address ( ) , False ) , self . udp_sport ,
 self . udp_dport ) )
  if 48 - 48: i1IIi . Oo0Ooo . i1IIi . I1ii11iIi11i * I1IiiI - Ii1I
  if 83 - 83: OoooooooOO
 def encode ( self , packet , inner_source , inner_dest ) :
  self . udp_length = len ( packet ) + 8
  self . source = inner_source
  self . dest = inner_dest
  if ( inner_dest . is_ipv4 ( ) ) :
   self . afi = LISP_AFI_IPV4
   self . length = self . udp_length + 20
   if 42 - 42: I1ii11iIi11i . i1IIi - OoOoOO00 - oO0o + i11iIiiIii
  if ( inner_dest . is_ipv6 ( ) ) :
   self . afi = LISP_AFI_IPV6
   self . length = self . udp_length
   if 65 - 65: I1IiiI - O0
   if 15 - 15: I11i + OoOoOO00 / Oo0Ooo - I1IiiI * I1ii11iIi11i % oO0o
   if 90 - 90: Ii1I / I11i
   if 98 - 98: i1IIi
   if 97 - 97: I1Ii111 + O0 - II111iiii / I11i
   if 84 - 84: iIii1I11I1II1 % Ii1I / OoooooooOO
  IiiI11iIi = ( LISP_ECM << 28 )
  if ( self . security ) : IiiI11iIi |= 0x08000000
  if ( self . ddt ) : IiiI11iIi |= 0x04000000
  if ( self . to_etr ) : IiiI11iIi |= 0x02000000
  if ( self . to_ms ) : IiiI11iIi |= 0x01000000
  if 62 - 62: OOooOOo * OoO0O00 * OoO0O00 + OoooooooOO . IiII + OoO0O00
  Ii1 = struct . pack ( "I" , socket . htonl ( IiiI11iIi ) )
  if 33 - 33: O0 + O0 % O0 . iIii1I11I1II1
  ooooO000 = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   ooooO000 = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   ooooO000 += self . source . pack_address ( )
   ooooO000 += self . dest . pack_address ( )
   ooooO000 = lisp_ip_checksum ( ooooO000 )
   if 48 - 48: i11iIiiIii * OoOoOO00 - I1IiiI + iIii1I11I1II1
  if ( self . afi == LISP_AFI_IPV6 ) :
   ooooO000 = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   ooooO000 += self . source . pack_address ( )
   ooooO000 += self . dest . pack_address ( )
   if 20 - 20: I1ii11iIi11i - iIii1I11I1II1 . iII111i
   if 52 - 52: OoO0O00 - I1Ii111
  OOo0oOO0o0oo0 = socket . htons ( self . udp_sport )
  oooOo = socket . htons ( self . udp_dport )
  OoOoo00Oo0OoO = socket . htons ( self . udp_length )
  O0o00o00OO0oO = socket . htons ( self . udp_checksum )
  ii11 = struct . pack ( "HHHH" , OOo0oOO0o0oo0 , oooOo , OoOoo00Oo0OoO , O0o00o00OO0oO )
  return ( Ii1 + ooooO000 + ii11 )
  if 9 - 9: I1IiiI . i11iIiiIii
  if 3 - 3: I1IiiI + I1ii11iIi11i * I1Ii111 - i1IIi . OOooOOo
 def decode ( self , packet ) :
  if 21 - 21: OOooOOo + o0oOOo0O0Ooo
  if 39 - 39: OoOoOO00 . I11i * OOooOOo . i1IIi
  if 69 - 69: IiII - i1IIi + o0oOOo0O0Ooo
  if 5 - 5: II111iiii
  ii = "I"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 88 - 88: OoooooooOO % II111iiii + IiII + IiII * Oo0Ooo
  IiiI11iIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 81 - 81: I1IiiI * ooOoO0o + I1Ii111
  IiiI11iIi = socket . ntohl ( IiiI11iIi [ 0 ] )
  self . security = True if ( IiiI11iIi & 0x08000000 ) else False
  self . ddt = True if ( IiiI11iIi & 0x04000000 ) else False
  self . to_etr = True if ( IiiI11iIi & 0x02000000 ) else False
  self . to_ms = True if ( IiiI11iIi & 0x01000000 ) else False
  packet = packet [ OOOO00oo00oo : : ]
  if 49 - 49: I1IiiI % oO0o % II111iiii * II111iiii + OoooooooOO + iII111i
  if 58 - 58: i11iIiiIii % iIii1I11I1II1 + OoO0O00 . I1ii11iIi11i . I1IiiI
  if 54 - 54: iII111i . OoO0O00 . iIii1I11I1II1
  if 45 - 45: I1ii11iIi11i + I1IiiI / i11iIiiIii
  if ( len ( packet ) < 1 ) : return ( None )
  oO00oO0 = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  oO00oO0 = oO00oO0 >> 4
  if 45 - 45: IiII / O0 * I1IiiI - OOooOOo * I1Ii111
  if ( oO00oO0 == 4 ) :
   OOOO00oo00oo = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
   if 19 - 19: OoOoOO00 / IiII - OOooOOo * i11iIiiIii % I1Ii111
   O0O0oOO , OoOoo00Oo0OoO , O0O0oOO , IiI111ii , ooo0OO0OOooO0 , O0o00o00OO0oO = struct . unpack ( "HHIBBH" , packet [ : OOOO00oo00oo ] )
   self . length = socket . ntohs ( OoOoo00Oo0OoO )
   self . ttl = IiI111ii
   self . protocol = ooo0OO0OOooO0
   self . ip_checksum = socket . ntohs ( O0o00o00OO0oO )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 45 - 45: O0 . I11i - I11i / OoO0O00 + I11i
   if 2 - 2: OOooOOo - iII111i
   if 79 - 79: i11iIiiIii + iIii1I11I1II1 . OoooooooOO % iII111i % IiII
   if 73 - 73: II111iiii - II111iiii + o0oOOo0O0Ooo * i1IIi
   ooo0OO0OOooO0 = struct . pack ( "H" , 0 )
   oOo0o0O = struct . calcsize ( "HHIBB" )
   I1I1Ii111 = struct . calcsize ( "H" )
   packet = packet [ : oOo0o0O ] + ooo0OO0OOooO0 + packet [ oOo0o0O + I1I1Ii111 : ]
   if 60 - 60: ooOoO0o
   packet = packet [ OOOO00oo00oo : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 92 - 92: O0 % IiII
   if 15 - 15: O0 % i1IIi - OOooOOo . IiII
  if ( oO00oO0 == 6 ) :
   OOOO00oo00oo = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
   if 1 - 1: I1IiiI
   O0O0oOO , OoOoo00Oo0OoO , ooo0OO0OOooO0 , IiI111ii = struct . unpack ( "IHBB" , packet [ : OOOO00oo00oo ] )
   self . length = socket . ntohs ( OoOoo00Oo0OoO )
   self . protocol = ooo0OO0OOooO0
   self . ttl = IiI111ii
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 40 - 40: o0oOOo0O0Ooo % I11i % O0
   packet = packet [ OOOO00oo00oo : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 88 - 88: o0oOOo0O0Ooo - oO0o
   if 73 - 73: II111iiii
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 7 - 7: O0 / OoO0O00
  OOOO00oo00oo = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 90 - 90: iII111i % oO0o / iIii1I11I1II1
  OOo0oOO0o0oo0 , oooOo , OoOoo00Oo0OoO , O0o00o00OO0oO = struct . unpack ( "HHHH" , packet [ : OOOO00oo00oo ] )
  self . udp_sport = socket . ntohs ( OOo0oOO0o0oo0 )
  self . udp_dport = socket . ntohs ( oooOo )
  self . udp_length = socket . ntohs ( OoOoo00Oo0OoO )
  self . udp_checksum = socket . ntohs ( O0o00o00OO0oO )
  packet = packet [ OOOO00oo00oo : : ]
  return ( packet )
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
  if 17 - 17: iIii1I11I1II1 . IiII / ooOoO0o % I11i + o0oOOo0O0Ooo - iIii1I11I1II1
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
  if 95 - 95: OoOoOO00 + OOooOOo - I11i * i1IIi + i1IIi * O0
  if 60 - 60: Oo0Ooo + I11i % iIii1I11I1II1 % oO0o - I1Ii111 / o0oOOo0O0Ooo
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  I11Io00oo0OO = self . rloc_name
  if ( cour ) : I11Io00oo0OO = lisp_print_cour ( I11Io00oo0OO )
  return ( 'rloc-name: {}' . format ( blue ( I11Io00oo0OO , cour ) ) )
  if 50 - 50: OoooooooOO % Oo0Ooo
  if 81 - 81: iIii1I11I1II1 + O0 * o0oOOo0O0Ooo - i11iIiiIii / iII111i
 def print_record ( self , indent ) :
  iIiIi111 = self . print_rloc_name ( )
  if ( iIiIi111 != "" ) : iIiIi111 = ", " + iIiIi111
  IIiIii1 = ""
  if ( self . geo ) :
   OOO0 = ""
   if ( self . geo . geo_name ) : OOO0 = "'{}' " . format ( self . geo . geo_name )
   IIiIii1 = ", geo: {}{}" . format ( OOO0 , self . geo . print_geo ( ) )
   if 13 - 13: I11i / OoooooooOO - I1Ii111
  O0o = ""
  if ( self . elp ) :
   OOO0 = ""
   if ( self . elp . elp_name ) : OOO0 = "'{}' " . format ( self . elp . elp_name )
   O0o = ", elp: {}{}" . format ( OOO0 , self . elp . print_elp ( True ) )
   if 61 - 61: IiII / I11i . I1Ii111 * OoOoOO00 / OoO0O00
  I11Ii1IIii1 = ""
  if ( self . rle ) :
   OOO0 = ""
   if ( self . rle . rle_name ) : OOO0 = "'{}' " . format ( self . rle . rle_name )
   I11Ii1IIii1 = ", rle: {}{}" . format ( OOO0 , self . rle . print_rle ( False ,
 True ) )
   if 73 - 73: O0 / Ii1I + i11iIiiIii - Ii1I
  iI1iI1i1I = ""
  if ( self . json ) :
   OOO0 = ""
   if ( self . json . json_name ) :
    OOO0 = "'{}' " . format ( self . json . json_name )
    if 47 - 47: i11iIiiIii * oO0o * I11i * OoOoOO00
   iI1iI1i1I = ", json: {}" . format ( self . json . print_json ( False ) )
   if 64 - 64: I1Ii111 / OoO0O00 * O0 - ooOoO0o / I1Ii111 + OoOoOO00
   if 48 - 48: OoOoOO00
  i1 = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   i1 = ", " + self . keys [ 1 ] . print_keys ( )
   if 31 - 31: I11i - O0 * IiII - iII111i
   if 23 - 23: I1Ii111 + i1IIi / I1Ii111 / o0oOOo0O0Ooo . oO0o
  ooO = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( ooO . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , iIiIi111 , IIiIii1 ,
 O0o , I11Ii1IIii1 , iI1iI1i1I , i1 ) )
  if 32 - 32: ooOoO0o / IiII
  if 28 - 28: OoooooooOO % iII111i / i11iIiiIii % OoO0O00 - Oo0Ooo
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 90 - 90: OOooOOo
  if 52 - 52: OoO0O00 * oO0o / iIii1I11I1II1 - OoOoOO00
  if 20 - 20: IiII % I1IiiI + iIii1I11I1II1 % iII111i
 def store_rloc_entry ( self , rloc_entry ) :
  OO0Oo00oo = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 39 - 39: I1ii11iIi11i / i11iIiiIii * i1IIi * Oo0Ooo
  self . rloc . copy_address ( OO0Oo00oo )
  if 39 - 39: OoO0O00 * OoooooooOO / i1IIi + Oo0Ooo
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 57 - 57: O0
   if 83 - 83: OOooOOo / Ii1I * I1IiiI % oO0o / iIii1I11I1II1
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   OOO0 = rloc_entry . geo_name
   if ( OOO0 and OOO0 in lisp_geo_list ) :
    self . geo = lisp_geo_list [ OOO0 ]
    if 1 - 1: I11i / OoooooooOO / iII111i
    if 68 - 68: i1IIi / Oo0Ooo / I11i * Oo0Ooo
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   OOO0 = rloc_entry . elp_name
   if ( OOO0 and OOO0 in lisp_elp_list ) :
    self . elp = lisp_elp_list [ OOO0 ]
    if 91 - 91: OoO0O00 . iII111i
    if 82 - 82: I1ii11iIi11i / Oo0Ooo
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   OOO0 = rloc_entry . rle_name
   if ( OOO0 and OOO0 in lisp_rle_list ) :
    self . rle = lisp_rle_list [ OOO0 ]
    if 63 - 63: I1IiiI
    if 3 - 3: iII111i + I1ii11iIi11i
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   OOO0 = rloc_entry . json_name
   if ( OOO0 and OOO0 in lisp_json_list ) :
    self . json = lisp_json_list [ OOO0 ]
    if 35 - 35: oO0o * iII111i * oO0o * I1Ii111 * IiII * i1IIi
    if 43 - 43: OoO0O00 * I1IiiI / IiII . i11iIiiIii + iII111i + o0oOOo0O0Ooo
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 1 - 1: I1IiiI % o0oOOo0O0Ooo . I1Ii111 + I11i * oO0o
  if 41 - 41: OoO0O00 * oO0o - II111iiii
 def encode_json ( self , lisp_json ) :
  I11i1I1111i = lisp_json . json_string
  I1I11Ii = 0
  if ( lisp_json . json_encrypted ) :
   I1I11Ii = ( lisp_json . json_key_id << 5 ) | 0x02
   if 85 - 85: O0 * i1IIi * Ii1I - ooOoO0o
   if 94 - 94: OoOoOO00 + OoO0O00 + I1IiiI
  oo0O00o0oO00 = LISP_LCAF_JSON_TYPE
  o00O00 = socket . htons ( LISP_AFI_LCAF )
  oOooOoO0oo = self . rloc . addr_length ( ) + 2
  if 21 - 21: oO0o - o0oOOo0O0Ooo + ooOoO0o . I1IiiI * oO0o * Ii1I
  IIiii11IiIi = socket . htons ( len ( I11i1I1111i ) + oOooOoO0oo )
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
  I1II1 = socket . htons ( len ( I11i1I1111i ) )
  Oo00O0o0O = struct . pack ( "HBBBBHH" , o00O00 , 0 , 0 , oo0O00o0oO00 , I1I11Ii ,
 IIiii11IiIi , I1II1 )
  Oo00O0o0O += I11i1I1111i . encode ( )
  if 8 - 8: OoooooooOO - OoO0O00 / i11iIiiIii / O0 . IiII
  if 86 - 86: ooOoO0o * OoooooooOO + iII111i + o0oOOo0O0Ooo
  if 79 - 79: i1IIi % I1ii11iIi11i - OoO0O00 % I1ii11iIi11i
  if 6 - 6: Oo0Ooo / iII111i . i11iIiiIii
  if ( lisp_is_json_telemetry ( I11i1I1111i ) ) :
   Oo00O0o0O += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   Oo00O0o0O += self . rloc . pack_address ( )
  else :
   Oo00O0o0O += struct . pack ( "H" , 0 )
   if 8 - 8: I1ii11iIi11i + O0 - oO0o % II111iiii . I1Ii111
  return ( Oo00O0o0O )
  if 86 - 86: IiII
  if 71 - 71: Ii1I - i1IIi . I1IiiI
 def encode_lcaf ( self ) :
  o00O00 = socket . htons ( LISP_AFI_LCAF )
  IiiiIiII11 = b""
  if ( self . geo ) :
   IiiiIiII11 = self . geo . encode_geo ( )
   if 24 - 24: OoooooooOO % OoO0O00 / OoOoOO00 + iII111i
   if 91 - 91: iIii1I11I1II1 / II111iiii + Oo0Ooo
  i1I1IiiI11 = b""
  if ( self . elp ) :
   OO0Oo = b""
   for iIII1 in self . elp . elp_nodes :
    IiIIi = socket . htons ( iIII1 . address . afi )
    iiI1 = 0
    if ( iIII1 . eid ) : iiI1 |= 0x4
    if ( iIII1 . probe ) : iiI1 |= 0x2
    if ( iIII1 . strict ) : iiI1 |= 0x1
    iiI1 = socket . htons ( iiI1 )
    OO0Oo += struct . pack ( "HH" , iiI1 , IiIIi )
    OO0Oo += iIII1 . address . pack_address ( )
    if 45 - 45: iII111i / Ii1I . i1IIi
    if 39 - 39: i11iIiiIii + i11iIiiIii * IiII
   iIiii = socket . htons ( len ( OO0Oo ) )
   i1I1IiiI11 = struct . pack ( "HBBBBH" , o00O00 , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , iIiii )
   i1I1IiiI11 += OO0Oo
   if 48 - 48: O0 % I1ii11iIi11i
   if 79 - 79: IiII . Ii1I % Oo0Ooo + o0oOOo0O0Ooo
  ii11Ii11iI1I11i1ii = b""
  if ( self . rle ) :
   O0OOOo0OO000o = b""
   for I1I1Ii1I in self . rle . rle_nodes :
    IiIIi = socket . htons ( I1I1Ii1I . rloc . rloc . afi )
    O0OOOo0OO000o += struct . pack ( "HBBH" , 0 , 0 , I1I1Ii1I . level , IiIIi )
    O0OOOo0OO000o += I1I1Ii1I . rloc . rloc . pack_address ( )
    if ( I1I1Ii1I . rloc . rloc_name ) :
     O0OOOo0OO000o += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     O0OOOo0OO000o += ( I1I1Ii1I . rloc . rloc_name + "\0" ) . encode ( )
     if 43 - 43: oO0o
     if 65 - 65: II111iiii % I1ii11iIi11i + OOooOOo + Ii1I
     if 39 - 39: i11iIiiIii % iIii1I11I1II1 + ooOoO0o + i11iIiiIii - O0 - I11i
   Ooo0o00OO0ooo0 = socket . htons ( len ( O0OOOo0OO000o ) )
   ii11Ii11iI1I11i1ii = struct . pack ( "HBBBBH" , o00O00 , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , Ooo0o00OO0ooo0 )
   ii11Ii11iI1I11i1ii += O0OOOo0OO000o
   if 54 - 54: I1IiiI / i1IIi * I1ii11iIi11i
   if 10 - 10: I1IiiI % II111iiii / I1IiiI
  iii11i11I = b""
  if ( self . json ) :
   iii11i11I = self . encode_json ( self . json )
   if 23 - 23: I1Ii111 . Ii1I % OoO0O00
   if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
  o0O00 = b""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   o0O00 = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
   if 81 - 81: I1ii11iIi11i
  Iii11i111iI = b""
  if ( self . rloc_name ) :
   Iii11i111iI += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   Iii11i111iI += ( self . rloc_name + "\0" ) . encode ( )
   if 76 - 76: I1Ii111 - O0
   if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
  ii11i1 = len ( IiiiIiII11 ) + len ( i1I1IiiI11 ) + len ( ii11Ii11iI1I11i1ii ) + len ( o0O00 ) + 2 + len ( iii11i11I ) + self . rloc . addr_length ( ) + len ( Iii11i111iI )
  if 11 - 11: OoOoOO00 + ooOoO0o * iII111i * I11i
  ii11i1 = socket . htons ( ii11i1 )
  iIiiiooOO = struct . pack ( "HBBBBHH" , o00O00 , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , ii11i1 , socket . htons ( self . rloc . afi ) )
  iIiiiooOO += self . rloc . pack_address ( )
  return ( iIiiiooOO + Iii11i111iI + IiiiIiII11 + i1I1IiiI11 + ii11Ii11iI1I11i1ii + o0O00 + iii11i11I )
  if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
  if 41 - 41: Ii1I / OoO0O00 / OoO0O00 * I11i
 def encode ( self ) :
  iiI1 = 0
  if ( self . local_bit ) : iiI1 |= 0x0004
  if ( self . probe_bit ) : iiI1 |= 0x0002
  if ( self . reach_bit ) : iiI1 |= 0x0001
  if 31 - 31: Ii1I / OoooooooOO % iIii1I11I1II1 - IiII * I1IiiI - O0
  Oo00O0o0O = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( iiI1 ) ,
 socket . htons ( self . rloc . afi ) )
  if 31 - 31: oO0o
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 74 - 74: OoO0O00
   try :
    Oo00O0o0O = Oo00O0o0O [ 0 : - 2 ] + self . encode_lcaf ( )
   except :
    lprint ( "Could not encode LCAF for RLOC-record" )
    if 11 - 11: oO0o + O0 % Ii1I . I11i * o0oOOo0O0Ooo
  else :
   Oo00O0o0O += self . rloc . pack_address ( )
   if 14 - 14: I11i . iIii1I11I1II1 + I1Ii111 % OoooooooOO
  return ( Oo00O0o0O )
  if 9 - 9: oO0o + Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
  if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
 def decode_lcaf ( self , packet , nonce , ms_json_encrypt ) :
  ii = "HBBBBH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
  IiIIi , Oo0oOo0Ooo , iiI1 , oo0O00o0oO00 , IiI1 , IIiii11IiIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
  if 30 - 30: i11iIiiIii % OOooOOo
  IIiii11IiIi = socket . ntohs ( IIiii11IiIi )
  packet = packet [ OOOO00oo00oo : : ]
  if ( IIiii11IiIi > len ( packet ) ) : return ( None )
  if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
  if 27 - 27: I1IiiI + OoOoOO00 + iII111i
  if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
  if 34 - 34: i1IIi % Oo0Ooo . oO0o
  if ( oo0O00o0oO00 == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( IIiii11IiIi > 0 ) :
    ii = "H"
    OOOO00oo00oo = struct . calcsize ( ii )
    if ( IIiii11IiIi < OOOO00oo00oo ) : return ( None )
    if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
    oO0 = len ( packet )
    IiIIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
    IiIIi = socket . ntohs ( IiIIi )
    if 62 - 62: Oo0Ooo . OoO0O00 * I1Ii111 . i11iIiiIii * O0
    if ( IiIIi == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ OOOO00oo00oo : : ]
     self . rloc_name = None
     if ( IiIIi == LISP_AFI_NAME ) :
      packet , I11Io00oo0OO = lisp_decode_dist_name ( packet )
      self . rloc_name = I11Io00oo0OO
     else :
      self . rloc . afi = IiIIi
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
      if 62 - 62: I1IiiI . Ii1I
      if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
    IIiii11IiIi -= oO0 - len ( packet )
    if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
    if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
  elif ( oo0O00o0oO00 == LISP_LCAF_GEO_COORD_TYPE ) :
   if 52 - 52: Ii1I - I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo
   if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
   if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
   if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
   iIiiiIIi = lisp_geo ( "" )
   packet = iIiiiIIi . decode_geo ( packet , IIiii11IiIi , IiI1 )
   if ( packet == None ) : return ( None )
   self . geo = iIiiiIIi
   if 36 - 36: I1IiiI * I1IiiI
  elif ( oo0O00o0oO00 == LISP_LCAF_JSON_TYPE ) :
   o00OOOo0o = IiI1 & 0x02
   if 64 - 64: IiII + OoO0O00 * iIii1I11I1II1 / iIii1I11I1II1 % OoOoOO00 - II111iiii
   if 23 - 23: I1IiiI + Ii1I % IiII + oO0o
   if 45 - 45: I11i / i11iIiiIii * Oo0Ooo * o0oOOo0O0Ooo
   if 19 - 19: OoooooooOO + Ii1I . OoOoOO00 / OoooooooOO - iIii1I11I1II1 / II111iiii
   ii = "H"
   OOOO00oo00oo = struct . calcsize ( ii )
   if ( IIiii11IiIi < OOOO00oo00oo ) : return ( None )
   if 55 - 55: OOooOOo / Oo0Ooo / I1ii11iIi11i - II111iiii - OOooOOo
   I1II1 = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
   I1II1 = socket . ntohs ( I1II1 )
   if ( IIiii11IiIi < OOOO00oo00oo + I1II1 ) : return ( None )
   if 5 - 5: oO0o
   packet = packet [ OOOO00oo00oo : : ]
   self . json = lisp_json ( "" , packet [ 0 : I1II1 ] , o00OOOo0o ,
 ms_json_encrypt )
   packet = packet [ I1II1 : : ]
   if 51 - 51: i11iIiiIii
   if 21 - 21: O0 - IiII * i1IIi + o0oOOo0O0Ooo % I11i + iIii1I11I1II1
   if 35 - 35: i11iIiiIii + i1IIi
   if 16 - 16: OoO0O00 - I1Ii111 * iII111i
   IiIIi = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 41 - 41: i11iIiiIii + i1IIi / IiII * I1ii11iIi11i / iIii1I11I1II1
   if ( IiIIi != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = IiIIi
    packet = self . rloc . unpack_address ( packet )
    if 70 - 70: I1IiiI % oO0o + iII111i % i11iIiiIii + ooOoO0o
    if 88 - 88: I11i * oO0o * I1ii11iIi11i - OOooOOo * IiII + o0oOOo0O0Ooo
  elif ( oo0O00o0oO00 == LISP_LCAF_ELP_TYPE ) :
   if 9 - 9: OoooooooOO
   if 26 - 26: OoOoOO00 + II111iiii - OoO0O00 + iII111i - iII111i % O0
   if 79 - 79: iIii1I11I1II1 - OoOoOO00 - O0 + I1ii11iIi11i
   if 69 - 69: oO0o % OoooooooOO
   iIi11IIIIIIIi = lisp_elp ( None )
   iIi11IIIIIIIi . elp_nodes = [ ]
   while ( IIiii11IiIi > 0 ) :
    iiI1 , IiIIi = struct . unpack ( "HH" , packet [ : 4 ] )
    if 90 - 90: I1IiiI + oO0o - I11i
    IiIIi = socket . ntohs ( IiIIi )
    if ( IiIIi == LISP_AFI_LCAF ) : return ( None )
    if 64 - 64: OoO0O00 * OoOoOO00
    iIII1 = lisp_elp_node ( )
    iIi11IIIIIIIi . elp_nodes . append ( iIII1 )
    if 50 - 50: I1ii11iIi11i + I11i * iII111i
    iiI1 = socket . ntohs ( iiI1 )
    iIII1 . eid = ( iiI1 & 0x4 )
    iIII1 . probe = ( iiI1 & 0x2 )
    iIII1 . strict = ( iiI1 & 0x1 )
    iIII1 . address . afi = IiIIi
    iIII1 . address . mask_len = iIII1 . address . host_mask_len ( )
    packet = iIII1 . address . unpack_address ( packet [ 4 : : ] )
    IIiii11IiIi -= iIII1 . address . addr_length ( ) + 4
    if 27 - 27: OoOoOO00 * OOooOOo * iIii1I11I1II1 / i1IIi
   iIi11IIIIIIIi . select_elp_node ( )
   self . elp = iIi11IIIIIIIi
   if 60 - 60: OOooOOo * I1Ii111 . oO0o
  elif ( oo0O00o0oO00 == LISP_LCAF_RLE_TYPE ) :
   if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
   if 51 - 51: I1IiiI . I11i - OoOoOO00
   if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
   if 97 - 97: Ii1I . Ii1I % iII111i
   IiI = lisp_rle ( "" )
   IiI . rle_nodes = [ ]
   while ( IIiii11IiIi > 0 ) :
    O0O0oOO , IIIIIi1I1Ii , i11I , IiIIi = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 45 - 45: II111iiii + iII111i
    IiIIi = socket . ntohs ( IiIIi )
    if ( IiIIi == LISP_AFI_LCAF ) : return ( None )
    if 100 - 100: II111iiii % OOooOOo * OoOoOO00
    I1I1Ii1I = lisp_rle_node ( )
    IiI . rle_nodes . append ( I1I1Ii1I )
    if 81 - 81: II111iiii / I11i - ooOoO0o - i1IIi - I1Ii111
    I1I1Ii1I . level = i11I
    I1I1Ii1I . rloc . rloc . afi = IiIIi
    I1I1Ii1I . rloc . rloc . mask_len = I1I1Ii1I . rloc . rloc . host_mask_len ( )
    packet = I1I1Ii1I . rloc . rloc . unpack_address ( packet [ 6 : : ] )
    if 38 - 38: OoOoOO00 . iII111i / O0 . OOooOOo + OOooOOo
    IIiii11IiIi -= I1I1Ii1I . rloc . rloc . addr_length ( ) + 6
    if ( IIiii11IiIi >= 2 ) :
     IiIIi = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( IiIIi ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , I1I1Ii1I . rloc . rloc_name = lisp_decode_dist_name ( packet )
      if 4 - 4: I11i
      if ( packet == None ) : return ( None )
      IIiii11IiIi -= len ( I1I1Ii1I . rloc . rloc_name ) + 1 + 2
      if 95 - 95: II111iiii % o0oOOo0O0Ooo . I11i
      if 18 - 18: O0 / OoooooooOO * Oo0Ooo % iII111i
      if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
   self . rle = IiI
   self . rle . build_rle_forwarding_list ( )
   if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
  elif ( oo0O00o0oO00 == LISP_LCAF_SECURITY_TYPE ) :
   if 46 - 46: o0oOOo0O0Ooo
   if 28 - 28: i1IIi
   if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
   if 62 - 62: I1Ii111 * I11i / I11i
   if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
   I11I = packet
   O0o0o00O0OO00 = lisp_keys ( 1 )
   packet = O0o0o00O0OO00 . decode_lcaf ( I11I , IIiii11IiIi )
   if ( packet == None ) : return ( None )
   if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
   if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
   if 94 - 94: iII111i
   if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
   ooo0Oo000o = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( O0o0o00O0OO00 . cipher_suite in ooo0Oo000o ) :
    if ( O0o0o00O0OO00 . cipher_suite == LISP_CS_25519_CBC ) :
     oO0oOo = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 81 - 81: I1IiiI
    if ( O0o0o00O0OO00 . cipher_suite == LISP_CS_25519_CHACHA ) :
     oO0oOo = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 62 - 62: Ii1I * OoOoOO00
   else :
    oO0oOo = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
   packet = oO0oOo . decode_lcaf ( I11I , IIiii11IiIi )
   if ( packet == None ) : return ( None )
   if 11 - 11: Ii1I
   if ( len ( packet ) < 2 ) : return ( None )
   IiIIi = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( IiIIi )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
   if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
   if 50 - 50: Oo0Ooo
   if 14 - 14: O0
   if 67 - 67: II111iiii / O0
   if 10 - 10: i1IIi / Oo0Ooo
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
   oO0III1iI = self . rloc_name
   if ( oO0III1iI ) : oO0III1iI = blue ( self . rloc_name , False )
   if 96 - 96: o0oOOo0O0Ooo . Oo0Ooo * i11iIiiIii
   if 30 - 30: i1IIi % iII111i / iII111i . OOooOOo
   if 80 - 80: II111iiii + I1ii11iIi11i
   if 9 - 9: I11i
   if 69 - 69: Oo0Ooo % I1Ii111
   if 80 - 80: I11i * oO0o % iIii1I11I1II1 / iII111i
   OOo000 = self . keys [ 1 ] if self . keys else None
   if ( OOo000 == None ) :
    if ( oO0oOo . remote_public_key == None ) :
     I1i1iI = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( I1i1iI , oO0III1iI ) )
     oO0oOo = None
    else :
     I1i1iI = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( I1i1iI , oO0III1iI ) )
     oO0oOo . compute_shared_key ( "encap" )
     if 100 - 100: OOooOOo - O0 . I1ii11iIi11i * Oo0Ooo . o0oOOo0O0Ooo
     if 58 - 58: II111iiii . I1IiiI . i1IIi
     if 60 - 60: iIii1I11I1II1 + ooOoO0o * i11iIiiIii + OoooooooOO
     if 43 - 43: I1ii11iIi11i % Oo0Ooo - i11iIiiIii / I1Ii111 * i1IIi
     if 78 - 78: o0oOOo0O0Ooo / OOooOOo / oO0o
     if 9 - 9: IiII + O0 / I1IiiI
     if 92 - 92: OOooOOo / i11iIiiIii + OoooooooOO
     if 9 - 9: iII111i
     if 9 - 9: O0 / o0oOOo0O0Ooo / I11i - i11iIiiIii - iII111i / IiII
     if 46 - 46: IiII + OoooooooOO % I1IiiI
   if ( OOo000 ) :
    if ( oO0oOo . remote_public_key == None ) :
     oO0oOo = None
     i111I = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( i111I , oO0III1iI ) )
    elif ( OOo000 . compare_keys ( oO0oOo ) ) :
     oO0oOo = OOo000
     lprint ( "    Maintain stored encap-keys for {}" . format ( oO0III1iI ) )
     if 51 - 51: I1IiiI * I1Ii111 . i11iIiiIii % Oo0Ooo . i1IIi - oO0o
    else :
     if ( OOo000 . remote_public_key == None ) :
      I1i1iI = "New encap-keying for existing state"
     else :
      I1i1iI = "Remote encap-rekeying"
      if 56 - 56: Oo0Ooo / II111iiii
     lprint ( "    {} for {}" . format ( bold ( I1i1iI , False ) ,
 oO0III1iI ) )
     OOo000 . remote_public_key = oO0oOo . remote_public_key
     OOo000 . compute_shared_key ( "encap" )
     oO0oOo = OOo000
     if 76 - 76: OoOoOO00 % OoO0O00 * O0
     if 39 - 39: ooOoO0o / iII111i
   self . keys = [ None , oO0oOo , None , None ]
   if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
  else :
   if 59 - 59: I11i % Ii1I / OoOoOO00
   if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
   if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
   if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
   packet = packet [ IIiii11IiIi : : ]
   if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
  return ( packet )
  if 80 - 80: Oo0Ooo
  if 58 - 58: I1Ii111 + OOooOOo
 def decode ( self , packet , nonce , ms_json_encrypt = False ) :
  ii = "BBBBHH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
  self . priority , self . weight , self . mpriority , self . mweight , iiI1 , IiIIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
  if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
  iiI1 = socket . ntohs ( iiI1 )
  IiIIi = socket . ntohs ( IiIIi )
  self . local_bit = True if ( iiI1 & 0x0004 ) else False
  self . probe_bit = True if ( iiI1 & 0x0002 ) else False
  self . reach_bit = True if ( iiI1 & 0x0001 ) else False
  if 76 - 76: iII111i - iIii1I11I1II1
  if ( IiIIi == LISP_AFI_LCAF ) :
   packet = packet [ OOOO00oo00oo - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
  else :
   self . rloc . afi = IiIIi
   packet = packet [ OOOO00oo00oo : : ]
   packet = self . rloc . unpack_address ( packet )
   if 23 - 23: I11i / OoO0O00 % OOooOOo
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
  if 21 - 21: Ii1I % O0
 def end_of_rlocs ( self , packet , rloc_count ) :
  for o000o0O0Oo00 in range ( rloc_count ) :
   packet = self . decode ( packet , None , False )
   if ( packet == None ) : return ( None )
   if 15 - 15: II111iiii * Ii1I + IiII % iII111i
  return ( packet )
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
class lisp_map_referral ( object ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 16 - 16: oO0o
  if 52 - 52: OoooooooOO % ooOoO0o - I1Ii111 * I11i
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # OoO0O00 * Ii1I
 lisp_hex_string ( self . nonce ) ) )
  if 49 - 49: OoooooooOO / oO0o / I1IiiI + o0oOOo0O0Ooo * ooOoO0o . Oo0Ooo
  if 48 - 48: I11i + IiII / IiII
 def encode ( self ) :
  IiiI11iIi = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  Oo00O0o0O = struct . pack ( "I" , socket . htonl ( IiiI11iIi ) )
  Oo00O0o0O += struct . pack ( "Q" , self . nonce )
  return ( Oo00O0o0O )
  if 65 - 65: I1ii11iIi11i - i1IIi % oO0o * iIii1I11I1II1 - IiII + ooOoO0o
  if 63 - 63: i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
 def decode ( self , packet ) :
  ii = "I"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
  IiiI11iIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  IiiI11iIi = socket . ntohl ( IiiI11iIi [ 0 ] )
  self . record_count = IiiI11iIi & 0xff
  packet = packet [ OOOO00oo00oo : : ]
  if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
  ii = "Q"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 97 - 97: Ii1I - IiII
  self . nonce = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  return ( packet )
  if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
  if 81 - 81: I1ii11iIi11i
  if 64 - 64: oO0o * OoO0O00 / OOooOOo + Ii1I % Oo0Ooo . IiII
  if 2 - 2: I1Ii111 + I11i
  if 47 - 47: i11iIiiIii + iIii1I11I1II1 % I1ii11iIi11i - oO0o % OoO0O00
  if 85 - 85: oO0o * OoOoOO00 / OoOoOO00
  if 85 - 85: OOooOOo / I1Ii111 . i1IIi / OoOoOO00 + iIii1I11I1II1
  if 71 - 71: OoO0O00
class lisp_ddt_entry ( object ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 96 - 96: I1ii11iIi11i / I1IiiI - I1ii11iIi11i / II111iiii - IiII
  if 74 - 74: Ii1I * OoooooooOO % OOooOOo + OoooooooOO + iII111i
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 83 - 83: i1IIi
  if 2 - 2: i1IIi / OOooOOo * O0
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
  if 64 - 64: iII111i / i1IIi . I1IiiI + O0
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  iii = self . delegation_set [ 0 ]
  return ( iii . print_node_type ( ) )
  if 71 - 71: o0oOOo0O0Ooo + iII111i + ooOoO0o
  if 27 - 27: OoooooooOO . iII111i * I1Ii111 % O0 + OoooooooOO - iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 86 - 86: i1IIi
  if 81 - 81: OoOoOO00
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_ddt_cache . add_cache ( self . eid , self )
  else :
   O0000O00o000 = lisp_ddt_cache . lookup_cache ( self . group , True )
   if ( O0000O00o000 == None ) :
    O0000O00o000 = lisp_ddt_entry ( )
    O0000O00o000 . eid . copy_address ( self . group )
    O0000O00o000 . group . copy_address ( self . group )
    lisp_ddt_cache . add_cache ( self . group , O0000O00o000 )
    if 62 - 62: OOooOOo . I1IiiI * iIii1I11I1II1 + OoO0O00 * ooOoO0o / oO0o
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( O0000O00o000 . group )
   O0000O00o000 . add_source_entry ( self )
   if 14 - 14: iII111i / OoO0O00
   if 75 - 75: IiII
   if 68 - 68: IiII - i1IIi % IiII . OoO0O00 . i11iIiiIii . OoooooooOO
 def add_source_entry ( self , source_ddt ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ddt . eid , source_ddt )
  if 32 - 32: iII111i + OoO0O00 % IiII + I1IiiI
  if 69 - 69: I1Ii111 + I11i - iIii1I11I1II1 - II111iiii . Ii1I
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 74 - 74: I1ii11iIi11i % o0oOOo0O0Ooo + O0 - i11iIiiIii - IiII % OOooOOo
  if 39 - 39: OoO0O00 - o0oOOo0O0Ooo
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 71 - 71: iII111i . OoO0O00 + ooOoO0o - OOooOOo - Oo0Ooo
  if 100 - 100: OoooooooOO - o0oOOo0O0Ooo + I1Ii111 . OoooooooOO % i11iIiiIii
  if 64 - 64: I1Ii111 % OoooooooOO / i1IIi / OoO0O00
class lisp_ddt_node ( object ) :
 def __init__ ( self ) :
  self . delegate_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . map_server_peer = False
  self . map_server_child = False
  self . priority = 0
  self . weight = 0
  if 2 - 2: I11i % o0oOOo0O0Ooo . OoO0O00 . OoO0O00
  if 89 - 89: ooOoO0o - oO0o + II111iiii + OoO0O00 - IiII
 def print_node_type ( self ) :
  if ( self . is_ddt_child ( ) ) : return ( "ddt-child" )
  if ( self . is_ms_child ( ) ) : return ( "map-server-child" )
  if ( self . is_ms_peer ( ) ) : return ( "map-server-peer" )
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo + OoO0O00
  if 38 - 38: OoOoOO00 + OoO0O00 . i11iIiiIii + Ii1I % i1IIi % I1IiiI
 def is_ddt_child ( self ) :
  if ( self . map_server_child ) : return ( False )
  if ( self . map_server_peer ) : return ( False )
  return ( True )
  if 93 - 93: i11iIiiIii
  if 63 - 63: iIii1I11I1II1 - iIii1I11I1II1 % o0oOOo0O0Ooo
 def is_ms_child ( self ) :
  return ( self . map_server_child )
  if 97 - 97: i1IIi % I11i % OoOoOO00
  if 25 - 25: OoOoOO00 . iIii1I11I1II1 - iII111i % II111iiii . OoOoOO00
 def is_ms_peer ( self ) :
  return ( self . map_server_peer )
  if 16 - 16: OOooOOo . Oo0Ooo . I1IiiI % O0 . I1ii11iIi11i + i11iIiiIii
  if 100 - 100: I1ii11iIi11i - i1IIi - OoO0O00 * o0oOOo0O0Ooo + OoOoOO00
  if 31 - 31: i1IIi
  if 21 - 21: o0oOOo0O0Ooo / O0 % O0 . OoooooooOO / I1IiiI
  if 94 - 94: ooOoO0o + OoO0O00 / ooOoO0o - ooOoO0o + Oo0Ooo + o0oOOo0O0Ooo
  if 50 - 50: oO0o . Oo0Ooo
  if 15 - 15: Ii1I
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
  if 64 - 64: OoooooooOO
  if 25 - 25: IiII
 def print_ddt_map_request ( self ) :
  lprint ( "Queued Map-Request from {}ITR {}->{}, nonce 0x{}" . format ( "P" if self . from_pitr else "" ,
  # I11i + OoOoOO00
 red ( self . itr . print_address ( ) , False ) ,
 green ( self . eid . print_address ( ) , False ) , self . nonce ) )
  if 85 - 85: O0 / I1ii11iIi11i + II111iiii . IiII * IiII . IiII
  if 2 - 2: OoO0O00
 def queue_map_request ( self ) :
  self . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ self ] )
  self . retransmit_timer . start ( )
  lisp_ddt_map_requestQ [ str ( self . nonce ) ] = self
  if 5 - 5: OoooooooOO . OoOoOO00 - Ii1I - OoOoOO00
  if 62 - 62: OoooooooOO + iIii1I11I1II1 . I1IiiI + I1ii11iIi11i
 def dequeue_map_request ( self ) :
  self . retransmit_timer . cancel ( )
  if ( self . nonce in lisp_ddt_map_requestQ ) :
   lisp_ddt_map_requestQ . pop ( str ( self . nonce ) )
   if 82 - 82: OoooooooOO / Ii1I . I1ii11iIi11i / o0oOOo0O0Ooo / I11i + i1IIi
   if 47 - 47: i11iIiiIii / iII111i * IiII
   if 92 - 92: OoooooooOO
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 68 - 68: I1Ii111 % oO0o % I1ii11iIi11i / i11iIiiIii
  if 9 - 9: Ii1I * IiII
  if 57 - 57: iII111i % oO0o % iII111i % OOooOOo + I1ii11iIi11i
  if 89 - 89: I1ii11iIi11i + II111iiii % i1IIi * O0 . Ii1I
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
LISP_DDT_ACTION_SITE_NOT_FOUND = - 2
LISP_DDT_ACTION_NULL = - 1
LISP_DDT_ACTION_NODE_REFERRAL = 0
LISP_DDT_ACTION_MS_REFERRAL = 1
LISP_DDT_ACTION_MS_ACK = 2
LISP_DDT_ACTION_MS_NOT_REG = 3
LISP_DDT_ACTION_DELEGATION_HOLE = 4
LISP_DDT_ACTION_NOT_AUTH = 5
LISP_DDT_ACTION_MAX = LISP_DDT_ACTION_NOT_AUTH
if 28 - 28: I1Ii111
lisp_map_referral_action_string = [
 "node-referral" , "ms-referral" , "ms-ack" , "ms-not-registered" ,
 "delegation-hole" , "not-authoritative" ]
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
if 100 - 100: i1IIi
if 4 - 4: i11iIiiIii - OOooOOo * IiII % OoooooooOO - OoOoOO00
if 81 - 81: Ii1I * ooOoO0o . oO0o . IiII
if 71 - 71: IiII + OoO0O00
if 39 - 39: I1IiiI % IiII / II111iiii / II111iiii
if 95 - 95: II111iiii + i11iIiiIii + o0oOOo0O0Ooo
if 30 - 30: O0 - O0 % iIii1I11I1II1 + iII111i * OoooooooOO
if 1 - 1: O0
if 36 - 36: oO0o . iII111i
if 62 - 62: I11i + iIii1I11I1II1 % I11i * OOooOOo + iIii1I11I1II1 % Ii1I
if 56 - 56: o0oOOo0O0Ooo
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
  if 55 - 55: oO0o - I1Ii111 / ooOoO0o % I1IiiI * OoooooooOO * I1IiiI
  if 88 - 88: Ii1I + O0
 def print_info ( self ) :
  if ( self . info_reply ) :
   Oo00O0OoooO = "Info-Reply"
   OO0Oo00oo = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # i1IIi . ooOoO0o / o0oOOo0O0Ooo % Ii1I
   # Ii1I
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : OO0Oo00oo += "empty, "
   for I11i1i1 in self . rtr_list :
    OO0Oo00oo += red ( I11i1i1 . print_address_no_iid ( ) , False ) + ", "
    if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
   OO0Oo00oo = OO0Oo00oo [ 0 : - 2 ]
  else :
   Oo00O0OoooO = "Info-Request"
   O00 = "<none>" if self . hostname == None else self . hostname
   OO0Oo00oo = ", hostname: {}" . format ( blue ( O00 , False ) )
   if 99 - 99: I11i / OoOoOO00 % OoO0O00 * Ii1I / OOooOOo
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( Oo00O0OoooO , False ) ,
 lisp_hex_string ( self . nonce ) , OO0Oo00oo ) )
  if 9 - 9: ooOoO0o - ooOoO0o * I1ii11iIi11i
  if 92 - 92: Ii1I
 def encode ( self ) :
  IiiI11iIi = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : IiiI11iIi |= ( 1 << 27 )
  if 88 - 88: OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
  if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
  if 62 - 62: I1Ii111 % II111iiii
  if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
  if 91 - 91: i11iIiiIii + Ii1I
  if 85 - 85: I11i % IiII
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  Oo00O0o0O = struct . pack ( "I" , socket . htonl ( IiiI11iIi ) )
  Oo00O0o0O += struct . pack ( "Q" , self . nonce )
  Oo00O0o0O += struct . pack ( "III" , 0 , 0 , 0 )
  if 58 - 58: I11i / i11iIiiIii * i11iIiiIii
  if 24 - 24: ooOoO0o - I1Ii111 * II111iiii - II111iiii
  if 47 - 47: IiII - iIii1I11I1II1 / OoOoOO00 * iII111i - iIii1I11I1II1 % oO0o
  if 93 - 93: Ii1I / iII111i
  if ( self . info_reply == False ) :
   if ( self . hostname == None ) :
    Oo00O0o0O += struct . pack ( "H" , 0 )
   else :
    Oo00O0o0O += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
    Oo00O0o0O += ( self . hostname + "\0" ) . encode ( )
    if 100 - 100: Oo0Ooo
   return ( Oo00O0o0O )
   if 94 - 94: I1ii11iIi11i / i1IIi * I1IiiI - I11i - I1ii11iIi11i
   if 6 - 6: I1ii11iIi11i % o0oOOo0O0Ooo + o0oOOo0O0Ooo / OOooOOo / I1IiiI
   if 67 - 67: OoOoOO00 . iII111i / OOooOOo * ooOoO0o + i1IIi
   if 100 - 100: OOooOOo . ooOoO0o + I1Ii111 . oO0o
   if 20 - 20: i11iIiiIii - i1IIi - iIii1I11I1II1 - OoooooooOO
  IiIIi = socket . htons ( LISP_AFI_LCAF )
  oo0O00o0oO00 = LISP_LCAF_NAT_TYPE
  IIiii11IiIi = socket . htons ( 16 )
  o0I1i11i = socket . htons ( self . ms_port )
  O0OoOo0ooOoOo = socket . htons ( self . etr_port )
  Oo00O0o0O += struct . pack ( "HHBBHHHH" , IiIIi , 0 , oo0O00o0oO00 , 0 , IIiii11IiIi ,
 o0I1i11i , O0OoOo0ooOoOo , socket . htons ( self . global_etr_rloc . afi ) )
  Oo00O0o0O += self . global_etr_rloc . pack_address ( )
  Oo00O0o0O += struct . pack ( "HH" , 0 , socket . htons ( self . private_etr_rloc . afi ) )
  Oo00O0o0O += self . private_etr_rloc . pack_address ( )
  if ( len ( self . rtr_list ) == 0 ) : Oo00O0o0O += struct . pack ( "H" , 0 )
  if 14 - 14: II111iiii
  if 49 - 49: I1IiiI % i11iIiiIii
  if 25 - 25: OOooOOo + i11iIiiIii * ooOoO0o
  if 4 - 4: O0 + I1IiiI + I1Ii111
  for I11i1i1 in self . rtr_list :
   Oo00O0o0O += struct . pack ( "H" , socket . htons ( I11i1i1 . afi ) )
   Oo00O0o0O += I11i1i1 . pack_address ( )
   if 80 - 80: Ii1I % OoooooooOO . i1IIi - OOooOOo
  return ( Oo00O0o0O )
  if 10 - 10: I11i + iII111i % OoO0O00 / OoO0O00
  if 91 - 91: ooOoO0o . oO0o
 def decode ( self , packet ) :
  I11I = packet
  ii = "I"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
  IiiI11iIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  IiiI11iIi = IiiI11iIi [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
  ii = "Q"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 81 - 81: i1IIi % iIii1I11I1II1
  OOooO = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
  IiiI11iIi = socket . ntohl ( IiiI11iIi )
  self . nonce = OOooO [ 0 ]
  self . info_reply = IiiI11iIi & 0x08000000
  self . hostname = None
  packet = packet [ OOOO00oo00oo : : ]
  if 82 - 82: ooOoO0o
  if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
  if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
  if 59 - 59: i11iIiiIii / OoO0O00
  if 48 - 48: iIii1I11I1II1
  ii = "HH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 19 - 19: oO0o
  if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
  if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
  if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
  if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
  IIIOo0O , i11IIII1 = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if ( i11IIII1 != 0 ) : return ( None )
  if 8 - 8: I1ii11iIi11i + II111iiii . OoO0O00 + I1IiiI - II111iiii % OoO0O00
  packet = packet [ OOOO00oo00oo : : ]
  ii = "IBBH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 85 - 85: i11iIiiIii % iII111i + II111iiii
  o0ooo000o00O , I1i1ii1IiI1i , I1iIIIiI1iI11 , i1iIiII = struct . unpack ( ii ,
 packet [ : OOOO00oo00oo ] )
  if 46 - 46: OoooooooOO - Ii1I - Ii1I . OoO0O00 . I11i % Ii1I
  if ( i1iIiII != 0 ) : return ( None )
  packet = packet [ OOOO00oo00oo : : ]
  if 26 - 26: OoooooooOO . oO0o + I1Ii111
  if 4 - 4: o0oOOo0O0Ooo % i1IIi . OOooOOo
  if 97 - 97: OoOoOO00 / iII111i * oO0o
  if 15 - 15: iIii1I11I1II1 / Ii1I / I1ii11iIi11i / Oo0Ooo
  if ( self . info_reply == False ) :
   ii = "H"
   OOOO00oo00oo = struct . calcsize ( ii )
   if ( len ( packet ) >= OOOO00oo00oo ) :
    IiIIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
    if ( socket . ntohs ( IiIIi ) == LISP_AFI_NAME ) :
     packet = packet [ OOOO00oo00oo : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 99 - 99: iII111i / O0 % ooOoO0o - II111iiii - i11iIiiIii
     if 44 - 44: i11iIiiIii . I11i - IiII + OoooooooOO . oO0o + I11i
   return ( I11I )
   if 6 - 6: i1IIi . o0oOOo0O0Ooo + OoO0O00 + OOooOOo + oO0o
   if 30 - 30: O0
   if 98 - 98: I1Ii111
   if 58 - 58: OOooOOo
   if 6 - 6: I1ii11iIi11i
  ii = "HHBBHHH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
  IiIIi , O0O0oOO , oo0O00o0oO00 , I1i1ii1IiI1i , IIiii11IiIi , o0I1i11i , O0OoOo0ooOoOo = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 18 - 18: ooOoO0o
  if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
  if ( socket . ntohs ( IiIIi ) != LISP_AFI_LCAF ) : return ( None )
  if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
  self . ms_port = socket . ntohs ( o0I1i11i )
  self . etr_port = socket . ntohs ( O0OoOo0ooOoOo )
  packet = packet [ OOOO00oo00oo : : ]
  if 29 - 29: Ii1I . II111iiii / I1Ii111
  if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
  if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
  if 81 - 81: i11iIiiIii - II111iiii + I11i
  ii = "H"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 52 - 52: II111iiii
  if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
  if 26 - 26: I1ii11iIi11i - OoO0O00
  if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
  IiIIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  if ( IiIIi != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( IiIIi )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
   if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
   if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
   if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
   if 15 - 15: Ii1I
   if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
  if ( len ( packet ) < OOOO00oo00oo ) : return ( I11I )
  if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
  IiIIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  if ( IiIIi != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( IiIIi )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( I11I )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
   if 46 - 46: II111iiii . iIii1I11I1II1
   if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
   if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
   if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
  if ( len ( packet ) < OOOO00oo00oo ) : return ( I11I )
  if 87 - 87: I1Ii111
  IiIIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  if ( IiIIi != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( IiIIi )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( I11I )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
   if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
   if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
   if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
   if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
   if 94 - 94: IiII
  while ( len ( packet ) >= OOOO00oo00oo ) :
   IiIIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
   packet = packet [ OOOO00oo00oo : : ]
   if ( IiIIi == 0 ) : continue
   I11i1i1 = lisp_address ( socket . ntohs ( IiIIi ) , "" , 0 , 0 )
   packet = I11i1i1 . unpack_address ( packet )
   if ( packet == None ) : return ( I11I )
   I11i1i1 . mask_len = I11i1i1 . host_mask_len ( )
   self . rtr_list . append ( I11i1i1 )
   if 69 - 69: I1Ii111 . I1Ii111
  return ( I11I )
  if 53 - 53: i11iIiiIii + iII111i * Oo0Ooo - I1Ii111
  if 61 - 61: o0oOOo0O0Ooo / OOooOOo . II111iiii - I1IiiI * i11iIiiIii
  if 8 - 8: iII111i % o0oOOo0O0Ooo
class lisp_nat_info ( object ) :
 def __init__ ( self , addr_str , hostname , port ) :
  self . address = addr_str
  self . hostname = hostname
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  if 87 - 87: Ii1I % I11i / I1Ii111
  if 21 - 21: OoO0O00 + Ii1I / I1Ii111
 def timed_out ( self ) :
  o0oOOOO0 = time . time ( ) - self . uptime
  return ( o0oOOOO0 >= ( LISP_INFO_INTERVAL * 2 ) )
  if 75 - 75: I1Ii111 . Ii1I % iIii1I11I1II1 / OoOoOO00
  if 38 - 38: i1IIi
  if 1 - 1: I1ii11iIi11i + OoO0O00 % I11i . OOooOOo + i1IIi / oO0o
class lisp_info_source ( object ) :
 def __init__ ( self , hostname , addr_str , port ) :
  self . address = lisp_address ( LISP_AFI_IPV4 , addr_str , 32 , 0 )
  self . port = port
  self . uptime = lisp_get_timestamp ( )
  self . nonce = None
  self . hostname = hostname
  self . no_timeout = False
  if 35 - 35: ooOoO0o % OoOoOO00 % OoO0O00 + OOooOOo / IiII * OoOoOO00
  if 65 - 65: I1IiiI . Oo0Ooo + i1IIi - Ii1I * i1IIi
 def cache_address_for_info_source ( self ) :
  oO0oOo = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ oO0oOo ] = self
  if 64 - 64: I1IiiI / OoO0O00 * I1IiiI * II111iiii . Ii1I
  if 98 - 98: I1Ii111 + o0oOOo0O0Ooo
 def cache_nonce_for_info_source ( self , nonce ) :
  self . nonce = nonce
  lisp_info_sources_by_nonce [ nonce ] = self
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
  if 55 - 55: OOooOOo . Oo0Ooo * OoOoOO00 / OoooooooOO * i11iIiiIii + oO0o
def lisp_concat_auth_data ( alg_id , auth1 , auth2 , auth3 , auth4 ) :
 if 45 - 45: Ii1I
 if ( lisp_is_x86 ( ) or lisp_is_apple_m ( ) ) :
  if ( auth1 != "" ) : auth1 = byte_swap_64 ( auth1 )
  if ( auth2 != "" ) : auth2 = byte_swap_64 ( auth2 )
  if ( auth3 != "" ) :
   if ( alg_id == LISP_SHA_1_96_ALG_ID ) : auth3 = socket . ntohl ( auth3 )
   else : auth3 = byte_swap_64 ( auth3 )
   if 8 - 8: oO0o + OOooOOo
  if ( auth4 != "" ) : auth4 = byte_swap_64 ( auth4 )
  if 37 - 37: IiII - OoOoOO00 + oO0o - Oo0Ooo + IiII
  if 33 - 33: Oo0Ooo % oO0o - I1IiiI + Oo0Ooo
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 8 )
  oO0ooo000 = auth1 + auth2 + auth3
  if 90 - 90: I1ii11iIi11i * I1Ii111 - iIii1I11I1II1 % IiII * I1Ii111 . I1Ii111
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  auth1 = lisp_hex_string ( auth1 )
  auth1 = auth1 . zfill ( 16 )
  auth2 = lisp_hex_string ( auth2 )
  auth2 = auth2 . zfill ( 16 )
  auth3 = lisp_hex_string ( auth3 )
  auth3 = auth3 . zfill ( 16 )
  auth4 = lisp_hex_string ( auth4 )
  auth4 = auth4 . zfill ( 16 )
  oO0ooo000 = auth1 + auth2 + auth3 + auth4
  if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
 return ( oO0ooo000 )
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
def lisp_open_listen_socket ( local_addr , port ) :
 if ( port . isdigit ( ) ) :
  if ( local_addr . find ( "." ) != - 1 ) :
   Iiii = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 60 - 60: oO0o . ooOoO0o
  if ( local_addr . find ( ":" ) != - 1 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   Iiii = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 6 - 6: O0 - OoO0O00 + OoooooooOO % iIii1I11I1II1
  Iiii . bind ( ( local_addr , int ( port ) ) )
 else :
  OOO0 = port
  if ( os . path . exists ( OOO0 ) ) :
   os . system ( "rm " + OOO0 )
   time . sleep ( 1 )
   if 58 - 58: i11iIiiIii * OOooOOo . Oo0Ooo / iII111i - i1IIi
  Iiii = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  Iiii . bind ( OOO0 )
  if 45 - 45: Ii1I
 return ( Iiii )
 if 89 - 89: ooOoO0o + I11i * O0 % OoOoOO00
 if 2 - 2: I1Ii111 % iIii1I11I1II1 . Ii1I - II111iiii
 if 33 - 33: I11i . i11iIiiIii % i1IIi * II111iiii * i11iIiiIii + OoOoOO00
 if 26 - 26: I1IiiI % OoOoOO00 % I11i + Oo0Ooo
 if 86 - 86: iII111i / i1IIi % Oo0Ooo
 if 84 - 84: o0oOOo0O0Ooo * OOooOOo . I11i * Ii1I
 if 32 - 32: ooOoO0o % ooOoO0o * I1ii11iIi11i % Ii1I + Oo0Ooo . OoOoOO00
def lisp_open_send_socket ( internal_name , afi ) :
 if ( internal_name == "" ) :
  if ( afi == LISP_AFI_IPV4 ) :
   Iiii = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   if 2 - 2: I1Ii111 / ooOoO0o * oO0o + IiII
  if ( afi == LISP_AFI_IPV6 ) :
   if ( lisp_is_raspbian ( ) ) : return ( None )
   Iiii = socket . socket ( socket . AF_INET6 , socket . SOCK_DGRAM )
   if 14 - 14: OoOoOO00 / iIii1I11I1II1 . o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 else :
  if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
  Iiii = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  Iiii . bind ( internal_name )
  if 92 - 92: OoO0O00 . i1IIi
 return ( Iiii )
 if 22 - 22: Ii1I . I1IiiI
 if 54 - 54: OOooOOo / I1ii11iIi11i % oO0o
 if 66 - 66: I11i + iII111i
 if 50 - 50: IiII
 if 33 - 33: OOooOOo % I1IiiI - I1IiiI / IiII
 if 22 - 22: ooOoO0o * ooOoO0o % o0oOOo0O0Ooo * Ii1I . OoO0O00
 if 55 - 55: OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 - i11iIiiIii / i1IIi / II111iiii
def lisp_close_socket ( sock , internal_name ) :
 sock . close ( )
 if ( os . path . exists ( internal_name ) ) : os . system ( "rm " + internal_name )
 return
 if 37 - 37: Ii1I + o0oOOo0O0Ooo
 if 74 - 74: Oo0Ooo / O0 + i1IIi . I1IiiI + OoO0O00 / Oo0Ooo
 if 13 - 13: o0oOOo0O0Ooo / Ii1I . II111iiii
 if 8 - 8: I11i - I11i % IiII
 if 8 - 8: I1IiiI . IiII * O0 * o0oOOo0O0Ooo
 if 17 - 17: I1IiiI . oO0o + Oo0Ooo + I11i / o0oOOo0O0Ooo
 if 25 - 25: iII111i / iII111i % OoOoOO00 / ooOoO0o
 if 81 - 81: OOooOOo * oO0o
def lisp_is_running ( node ) :
 return ( True if ( os . path . exists ( node ) ) else False )
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
def lisp_packet_ipc ( packet , source , sport ) :
 o00O0O0OoO = "packet@{}@{}@{}@" . format ( str ( len ( packet ) ) , source , str ( sport ) )
 return ( o00O0O0OoO . encode ( ) + packet )
 if 32 - 32: OoO0O00
 if 22 - 22: II111iiii . I11i
 if 61 - 61: OOooOOo % O0 . I1ii11iIi11i . iIii1I11I1II1 * I11i
 if 29 - 29: ooOoO0o + i1IIi % IiII * Ii1I
 if 94 - 94: OOooOOo / IiII
 if 18 - 18: IiII - I11i / Ii1I % IiII * i1IIi
 if 22 - 22: OoOoOO00 - Oo0Ooo
 if 41 - 41: iIii1I11I1II1 * I1Ii111 / OoO0O00
 if 33 - 33: I11i + O0
 if 9 - 9: I11i . iII111i * ooOoO0o * ooOoO0o
def lisp_control_packet_ipc ( packet , source , dest , dport ) :
 o00O0O0OoO = "control-packet@{}@{}@" . format ( dest , str ( dport ) )
 return ( o00O0O0OoO . encode ( ) + packet )
 if 68 - 68: O0 - i11iIiiIii % iIii1I11I1II1 % ooOoO0o
 if 12 - 12: II111iiii + I11i
 if 9 - 9: I1ii11iIi11i
 if 51 - 51: I1ii11iIi11i
 if 37 - 37: I1IiiI % I1Ii111
 if 22 - 22: o0oOOo0O0Ooo % OOooOOo - I11i + ooOoO0o / OOooOOo
 if 98 - 98: I11i * O0 + IiII - oO0o
 if 35 - 35: OoooooooOO * Ii1I
 if 73 - 73: ooOoO0o . OoO0O00 % I1ii11iIi11i - oO0o
def lisp_data_packet_ipc ( packet , source ) :
 o00O0O0OoO = "data-packet@{}@{}@@" . format ( str ( len ( packet ) ) , source )
 return ( o00O0O0OoO . encode ( ) + packet )
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
def lisp_command_ipc ( ipc , source ) :
 Oo00O0o0O = "command@{}@{}@@" . format ( len ( ipc ) , source ) + ipc
 return ( Oo00O0o0O . encode ( ) )
 if 23 - 23: I1Ii111
 if 76 - 76: Ii1I + Ii1I / i1IIi % o0oOOo0O0Ooo . iIii1I11I1II1 . OoOoOO00
 if 75 - 75: I11i . Ii1I / I1ii11iIi11i
 if 99 - 99: Ii1I
 if 85 - 85: I1Ii111 + I1Ii111 + OoOoOO00 / ooOoO0o / o0oOOo0O0Ooo . Oo0Ooo
 if 41 - 41: i1IIi % Ii1I . i1IIi * OoooooooOO % Ii1I
 if 21 - 21: iII111i
 if 72 - 72: I11i % o0oOOo0O0Ooo . iIii1I11I1II1 - I1Ii111 / i11iIiiIii
 if 75 - 75: OoooooooOO
 if 24 - 24: oO0o % iII111i - II111iiii / Ii1I + O0
 if 37 - 37: I1Ii111 - i1IIi / iIii1I11I1II1
def lisp_api_ipc ( source , data ) :
 Oo00O0o0O = "api@" + str ( len ( data ) ) + "@" + source + "@@" + data
 return ( Oo00O0o0O . encode ( ) )
 if 53 - 53: Ii1I - iIii1I11I1II1 % I1ii11iIi11i * i11iIiiIii + ooOoO0o
 if 63 - 63: Oo0Ooo * I1IiiI
 if 84 - 84: Oo0Ooo
 if 67 - 67: oO0o / II111iiii . I11i / oO0o
 if 46 - 46: oO0o * Oo0Ooo - I11i / iIii1I11I1II1
 if 100 - 100: i11iIiiIii % oO0o
 if 62 - 62: OOooOOo * i1IIi - OOooOOo / i11iIiiIii
 if 17 - 17: I1ii11iIi11i + ooOoO0o % Ii1I % OOooOOo
 if 73 - 73: i11iIiiIii
 if 44 - 44: o0oOOo0O0Ooo % Ii1I - OoOoOO00 + OoOoOO00 * IiII + iII111i
 if 58 - 58: I1ii11iIi11i / oO0o + i11iIiiIii * o0oOOo0O0Ooo
 if 19 - 19: OoOoOO00
def lisp_ipc ( packet , send_socket , node ) :
 if 17 - 17: Oo0Ooo
 if 76 - 76: II111iiii % I1ii11iIi11i
 if 99 - 99: oO0o - I1Ii111
 if 29 - 29: I1IiiI - I11i
 if ( lisp_is_running ( node ) == False ) :
  lprint ( "Suppress sending IPC to {}" . format ( node ) )
  return
  if 42 - 42: Oo0Ooo - O0 . OoOoOO00
  if 4 - 4: IiII
 iIi1i1i1II1 = 1500 if ( packet . find ( b"control-packet" ) == - 1 ) else 9000
 if 83 - 83: II111iiii % o0oOOo0O0Ooo
 II1Ii = 0
 OOOOo0o0O0o = len ( packet )
 iII1IiiII111i = 0
 o0O00oOO0o00 = .001
 while ( OOOOo0o0O0o > 0 ) :
  Ooi1II1ii111I1 = min ( OOOOo0o0O0o , iIi1i1i1II1 )
  oo0oOOo = packet [ II1Ii : Ooi1II1ii111I1 + II1Ii ]
  if 78 - 78: iIii1I11I1II1 % i11iIiiIii * OoO0O00 / O0 * o0oOOo0O0Ooo / IiII
  try :
   if ( type ( oo0oOOo ) == str ) : oo0oOOo = oo0oOOo . encode ( )
   send_socket . sendto ( oo0oOOo , node )
   lprint ( "Send IPC {}-out-of-{} byte to {} succeeded" . format ( len ( oo0oOOo ) , len ( packet ) , node ) )
   if 75 - 75: I1Ii111 - i1IIi - OoO0O00
   iII1IiiII111i = 0
   o0O00oOO0o00 = .001
   if 25 - 25: iII111i . o0oOOo0O0Ooo
  except socket . error as oOO :
   if ( iII1IiiII111i == 12 ) :
    lprint ( "Giving up on {}, consider it down" . format ( node ) )
    break
    if 62 - 62: I11i + i1IIi . I1ii11iIi11i - I1ii11iIi11i
    if 68 - 68: ooOoO0o % OoooooooOO
   lprint ( "Send IPC {}-out-of-{} byte to {} failed: {}" . format ( len ( oo0oOOo ) , len ( packet ) , node , oOO ) )
   if 94 - 94: Oo0Ooo * o0oOOo0O0Ooo
   if 60 - 60: iII111i . OOooOOo
   iII1IiiII111i += 1
   time . sleep ( o0O00oOO0o00 )
   if 39 - 39: O0 - i11iIiiIii - I1IiiI / Oo0Ooo - i11iIiiIii
   lprint ( "Retrying after {} ms ..." . format ( o0O00oOO0o00 * 1000 ) )
   o0O00oOO0o00 *= 2
   continue
   if 30 - 30: OoO0O00 / OoOoOO00 + I1ii11iIi11i % IiII - OoO0O00
   if 19 - 19: I1IiiI
  II1Ii += Ooi1II1ii111I1
  OOOOo0o0O0o -= Ooi1II1ii111I1
  if 99 - 99: OOooOOo - OOooOOo
 return
 if 98 - 98: o0oOOo0O0Ooo + O0 * oO0o - i11iIiiIii
 if 83 - 83: o0oOOo0O0Ooo
 if 23 - 23: o0oOOo0O0Ooo . I11i
 if 67 - 67: iII111i
 if 52 - 52: IiII . OoooooooOO
 if 34 - 34: o0oOOo0O0Ooo / IiII . OoooooooOO . Oo0Ooo / ooOoO0o + O0
 if 38 - 38: I11i
 if 66 - 66: II111iiii
def lisp_format_packet ( packet ) :
 packet = binascii . hexlify ( packet )
 II1Ii = 0
 iiI1ooOOOoo = b""
 OOOOo0o0O0o = len ( packet ) * 2
 while ( II1Ii < OOOOo0o0O0o ) :
  iiI1ooOOOoo += packet [ II1Ii : II1Ii + 8 ] + b" "
  II1Ii += 8
  OOOOo0o0O0o -= 4
  if 57 - 57: OoO0O00 / Oo0Ooo % I1IiiI * I1ii11iIi11i
 return ( iiI1ooOOOoo . decode ( ) )
 if 68 - 68: iII111i - o0oOOo0O0Ooo - OoO0O00 . O0 - i11iIiiIii
 if 2 - 2: I1ii11iIi11i * i1IIi
 if 17 - 17: I1ii11iIi11i * Ii1I % Oo0Ooo * I1Ii111 + OoO0O00 . OoooooooOO
 if 60 - 60: Ii1I . II111iiii
 if 36 - 36: IiII . iII111i * O0 . i1IIi * O0 * I1Ii111
 if 50 - 50: OoooooooOO + o0oOOo0O0Ooo + iIii1I11I1II1 + OOooOOo
 if 90 - 90: Ii1I * I11i % I1Ii111 - I1ii11iIi11i * I1Ii111 % OoO0O00
def lisp_send ( lisp_sockets , dest , port , packet ) :
 if 50 - 50: iIii1I11I1II1
 oO00o0Oo0 = lisp_sockets [ 0 ] if dest . is_ipv4 ( ) else lisp_sockets [ 1 ]
 if 85 - 85: OoooooooOO / IiII + OoOoOO00 - iIii1I11I1II1 % OoooooooOO + iIii1I11I1II1
 if 29 - 29: I1ii11iIi11i - I11i % iII111i * iII111i
 if 89 - 89: I1ii11iIi11i - o0oOOo0O0Ooo + Oo0Ooo * O0 + iIii1I11I1II1
 if 5 - 5: o0oOOo0O0Ooo + OoO0O00
 if 28 - 28: OOooOOo
 if 56 - 56: II111iiii
 if 80 - 80: o0oOOo0O0Ooo . oO0o . I1Ii111
 if 26 - 26: i1IIi - I1IiiI + IiII / OoO0O00 . I1ii11iIi11i
 if 82 - 82: I1Ii111 % iII111i . OoOoOO00 % OoO0O00 + I1ii11iIi11i
 if 69 - 69: I1IiiI * OoOoOO00 - ooOoO0o . O0
 if 15 - 15: oO0o . IiII + I1Ii111 - OoooooooOO
 if 85 - 85: II111iiii - Oo0Ooo + oO0o . i11iIiiIii + Oo0Ooo
 oOoO0 = dest . print_address_no_iid ( )
 if ( oOoO0 . find ( "::ffff:" ) != - 1 and oOoO0 . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : oO00o0Oo0 = lisp_sockets [ 0 ]
  if ( oO00o0Oo0 == None ) :
   oO00o0Oo0 = lisp_sockets [ 0 ]
   oOoO0 = oOoO0 . split ( "::ffff:" ) [ - 1 ]
   if 86 - 86: ooOoO0o . OoO0O00
   if 47 - 47: IiII % I1IiiI
   if 91 - 91: Ii1I
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + oOoO0 , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 69 - 69: iII111i
 if 96 - 96: Ii1I
 if 39 - 39: OoO0O00 - I1IiiI % II111iiii - IiII * I1ii11iIi11i
 if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
 try :
  oO00o0Oo0 . sendto ( packet , ( oOoO0 , port ) )
 except socket . error as oOO :
  lprint ( "socket.sendto() failed: {}" . format ( oOO ) )
  if 7 - 7: ooOoO0o * I11i / iIii1I11I1II1
 return
 if 15 - 15: OoooooooOO / iII111i
 if 40 - 40: o0oOOo0O0Ooo
 if 75 - 75: oO0o - OoOoOO00 * ooOoO0o . O0
 if 78 - 78: Oo0Ooo
 if 74 - 74: O0 / I11i
 if 52 - 52: I1IiiI + oO0o * II111iiii
 if 15 - 15: I11i
 if 72 - 72: O0
def lisp_receive_segments ( lisp_socket , packet , source , total_length ) :
 if 15 - 15: II111iiii / I11i % II111iiii % Ii1I % i11iIiiIii / I1Ii111
 if 93 - 93: OOooOOo / OoooooooOO % iII111i
 if 47 - 47: o0oOOo0O0Ooo - I1IiiI % O0 % I1Ii111 . O0 . OoOoOO00
 if 95 - 95: o0oOOo0O0Ooo * OOooOOo - iII111i * OoooooooOO - ooOoO0o / I1IiiI
 if 47 - 47: OoO0O00 % I1IiiI / OoOoOO00 - I1Ii111 / I1IiiI
 Ooi1II1ii111I1 = total_length - len ( packet )
 if ( Ooi1II1ii111I1 == 0 ) : return ( [ True , packet ] )
 if 13 - 13: o0oOOo0O0Ooo % ooOoO0o
 lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( packet ) ,
 total_length , source ) )
 if 15 - 15: iII111i * I1IiiI . iIii1I11I1II1 % I1IiiI / O0
 if 47 - 47: OoooooooOO - i11iIiiIii . I1IiiI / i1IIi
 if 74 - 74: OoooooooOO * ooOoO0o
 if 45 - 45: Oo0Ooo + iIii1I11I1II1 . o0oOOo0O0Ooo
 if 50 - 50: o0oOOo0O0Ooo % O0
 OOOOo0o0O0o = Ooi1II1ii111I1
 while ( OOOOo0o0O0o > 0 ) :
  try : oo0oOOo = lisp_socket . recvfrom ( 9000 )
  except : return ( [ False , None ] )
  if 67 - 67: OoOoOO00
  oo0oOOo = oo0oOOo [ 0 ]
  if 21 - 21: I11i % Oo0Ooo + Oo0Ooo / iIii1I11I1II1 % iIii1I11I1II1
  if 66 - 66: iII111i
  if 72 - 72: ooOoO0o / oO0o / iII111i . I1Ii111 . I1ii11iIi11i + IiII
  if 39 - 39: I1IiiI % I1Ii111
  if 22 - 22: OoOoOO00 - OOooOOo % i1IIi + i1IIi
  II1Ii11 = oo0oOOo . decode ( )
  if ( II1Ii11 . find ( "packet@" ) == 0 ) :
   II1Ii11 = II1Ii11 . split ( "@" )
   lprint ( "Received new message ({}-out-of-{}) while receiving " + "fragments, old message discarded" , len ( oo0oOOo ) ,
   # II111iiii / OoOoOO00 - o0oOOo0O0Ooo % I1ii11iIi11i + OoO0O00
 II1Ii11 [ 1 ] if len ( II1Ii11 ) > 2 else "?" )
   return ( [ False , oo0oOOo ] )
   if 7 - 7: iII111i - OoO0O00 + ooOoO0o * iII111i
   if 14 - 14: OoOoOO00 - OoOoOO00 / ooOoO0o
  OOOOo0o0O0o -= len ( oo0oOOo )
  packet += oo0oOOo
  if 22 - 22: I1Ii111
  lprint ( "Received {}-out-of-{} byte segment from {}" . format ( len ( oo0oOOo ) , total_length , source ) )
  if 59 - 59: I1Ii111
  if 22 - 22: OoooooooOO
 return ( [ True , packet ] )
 if 88 - 88: I1Ii111 - OoO0O00
 if 29 - 29: I1IiiI . I1Ii111
 if 74 - 74: Oo0Ooo / OoOoOO00 + OoOoOO00 % i11iIiiIii . OoO0O00 + ooOoO0o
 if 77 - 77: ooOoO0o . I11i + OoooooooOO
 if 100 - 100: ooOoO0o . oO0o % I1ii11iIi11i . IiII * IiII - o0oOOo0O0Ooo
 if 49 - 49: iIii1I11I1II1 % Ii1I / OoooooooOO - II111iiii . Ii1I
 if 65 - 65: OoooooooOO + I1Ii111 % ooOoO0o + II111iiii . i1IIi + OoooooooOO
 if 26 - 26: I1IiiI / II111iiii % I1ii11iIi11i * o0oOOo0O0Ooo . IiII / OoO0O00
 if 10 - 10: i11iIiiIii / i1IIi + O0 - i11iIiiIii % I11i - i1IIi
def lisp_bit_stuff ( payload ) :
 lprint ( "Bit-stuffing, found {} segments" . format ( len ( payload ) ) )
 Oo00O0o0O = b""
 for oo0oOOo in payload : Oo00O0o0O += oo0oOOo + b"\x40"
 return ( Oo00O0o0O [ : - 1 ] )
 if 38 - 38: O0 - I1IiiI + Oo0Ooo + ooOoO0o
 if 56 - 56: I1Ii111 + oO0o / Ii1I + I1Ii111
 if 21 - 21: OOooOOo / OoOoOO00 + OoOoOO00 + OoOoOO00 - i1IIi + Ii1I
 if 43 - 43: O0 % II111iiii
 if 60 - 60: iII111i / ooOoO0o - Ii1I - OoooooooOO
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
def lisp_receive ( lisp_socket , internal ) :
 while ( True ) :
  if 59 - 59: O0 + Oo0Ooo
  if 63 - 63: OoO0O00 / I1IiiI / oO0o . Ii1I / i1IIi
  if 50 - 50: I11i . I11i % I1IiiI - i1IIi
  if 63 - 63: OoO0O00 . iII111i
  try : I1 = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 53 - 53: OoooooooOO - I1Ii111 - I1ii11iIi11i
  if 19 - 19: oO0o / I11i / I1Ii111 . iII111i
  if 3 - 3: ooOoO0o / IiII
  if 9 - 9: IiII
  if 22 - 22: iII111i % i11iIiiIii / iIii1I11I1II1 % i1IIi + o0oOOo0O0Ooo
  if 64 - 64: II111iiii / II111iiii + OoO0O00
  if ( internal == False ) :
   Oo00O0o0O = I1 [ 0 ]
   IiiiiI = lisp_convert_6to4 ( I1 [ 1 ] [ 0 ] )
   i11I1Ii1Iiii1 = I1 [ 1 ] [ 1 ]
   if 70 - 70: Oo0Ooo * i11iIiiIii + IiII / OoOoOO00 . I1ii11iIi11i % OoOoOO00
   if ( i11I1Ii1Iiii1 == LISP_DATA_PORT ) :
    I11i1iiiIi1 = lisp_data_plane_logging
    II1i1 = lisp_format_packet ( Oo00O0o0O [ 0 : 60 ] ) + " ..."
   else :
    I11i1iiiIi1 = True
    II1i1 = lisp_format_packet ( Oo00O0o0O )
    if 48 - 48: OoooooooOO / iII111i / II111iiii + i1IIi
    if 33 - 33: I11i + I1ii11iIi11i + i11iIiiIii * I1IiiI % oO0o % OoooooooOO
   if ( I11i1iiiIi1 ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( Oo00O0o0O ) , bold ( "from " + IiiiiI , False ) , i11I1Ii1Iiii1 ,
 II1i1 ) )
    if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
   return ( [ "packet" , IiiiiI , i11I1Ii1Iiii1 , Oo00O0o0O ] )
   if 69 - 69: OoooooooOO
   if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
   if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
   if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
   if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
   if 52 - 52: II111iiii . iII111i
  iii111IIIIi1I = False
  IiI11I1I111 = I1 [ 0 ]
  if ( type ( IiI11I1I111 ) == str ) : IiI11I1I111 = IiI11I1I111 . encode ( )
  oO0o0O0oO = False
  if 83 - 83: IiII * OOooOOo - ooOoO0o * i11iIiiIii - ooOoO0o * i11iIiiIii
  while ( iii111IIIIi1I == False ) :
   IiI11I1I111 = IiI11I1I111 . split ( b"@" )
   if 63 - 63: I11i . OoO0O00 + oO0o
   if ( len ( IiI11I1I111 ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( IiI11I1I111 [ 0 ] ) )
    if 6 - 6: iII111i . IiII - I1ii11iIi11i - Oo0Ooo - i1IIi
    oO0o0O0oO = True
    break
    if 96 - 96: i1IIi . Oo0Ooo * i11iIiiIii / OoO0O00 / oO0o
    if 12 - 12: iII111i % OOooOOo % i1IIi
   iIIi1iiii1ii = IiI11I1I111 [ 0 ] . decode ( )
   try :
    Oo0o00oo00OO0 = int ( IiI11I1I111 [ 1 ] )
   except :
    I1I1II1 = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( I1I1II1 , I1 ) )
    oO0o0O0oO = True
    break
    if 28 - 28: I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * IiII + OoooooooOO
   IiiiiI = IiI11I1I111 [ 2 ] . decode ( )
   i11I1Ii1Iiii1 = IiI11I1I111 [ 3 ] . decode ( )
   if 52 - 52: I1Ii111
   if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
   if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
   if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
   if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
   if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
   if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
   if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
   if ( len ( IiI11I1I111 ) > 5 ) :
    Oo00O0o0O = lisp_bit_stuff ( IiI11I1I111 [ 4 : : ] )
   else :
    Oo00O0o0O = IiI11I1I111 [ 4 ]
    if 88 - 88: i1IIi
    if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
    if 55 - 55: OoO0O00 % IiII
    if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
    if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
    if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
   iii111IIIIi1I , Oo00O0o0O = lisp_receive_segments ( lisp_socket , Oo00O0o0O ,
 IiiiiI , Oo0o00oo00OO0 )
   if ( Oo00O0o0O == None ) : return ( [ "" , "" , "" , "" ] )
   if 63 - 63: I1Ii111 + iII111i
   if 6 - 6: I1ii11iIi11i + Ii1I
   if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
   if 97 - 97: ooOoO0o + OOooOOo
   if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
   if ( iii111IIIIi1I == False ) :
    IiI11I1I111 = Oo00O0o0O
    continue
    if 6 - 6: Oo0Ooo + I1IiiI
    if 48 - 48: oO0o . I1ii11iIi11i
   if ( i11I1Ii1Iiii1 == "" ) : i11I1Ii1Iiii1 = "no-port"
   if ( iIIi1iiii1ii == "command" and lisp_i_am_core == False ) :
    o00O = Oo00O0o0O . find ( b" {" )
    o00O000O = Oo00O0o0O if o00O == - 1 else Oo00O0o0O [ : o00O ]
    o00O000O = ": '" + o00O000O . decode ( ) + "'"
   else :
    o00O000O = ""
    if 53 - 53: ooOoO0o * oO0o - O0 . Ii1I + I1ii11iIi11i - O0
    if 37 - 37: OoO0O00 . i11iIiiIii
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( Oo00O0o0O ) , bold ( "from " + IiiiiI , False ) , i11I1Ii1Iiii1 , iIIi1iiii1ii ,
 o00O000O if ( iIIi1iiii1ii in [ "command" , "api" ] ) else ": ... " if ( iIIi1iiii1ii == "data-packet" ) else ": " + lisp_format_packet ( Oo00O0o0O ) ) )
   if 62 - 62: i1IIi % i1IIi
   if 58 - 58: OoooooooOO - i11iIiiIii
   if 67 - 67: OoO0O00 - OoooooooOO
   if 66 - 66: oO0o - II111iiii - o0oOOo0O0Ooo * OoO0O00 % OoO0O00 + I11i
   if 28 - 28: i11iIiiIii . o0oOOo0O0Ooo / II111iiii . OoO0O00 % II111iiii / I11i
  if ( oO0o0O0oO ) : continue
  return ( [ iIIi1iiii1ii , IiiiiI , i11I1Ii1Iiii1 , Oo00O0o0O ] )
  if 42 - 42: OoOoOO00 . I1ii11iIi11i
  if 77 - 77: I1ii11iIi11i % i1IIi + OOooOOo - OOooOOo - o0oOOo0O0Ooo
  if 45 - 45: I1ii11iIi11i / o0oOOo0O0Ooo / I1IiiI - Oo0Ooo * ooOoO0o - I1ii11iIi11i
  if 71 - 71: I1IiiI % OoO0O00
  if 32 - 32: oO0o
  if 2 - 2: Oo0Ooo
  if 80 - 80: I1Ii111 * II111iiii % Oo0Ooo * ooOoO0o + o0oOOo0O0Ooo
  if 96 - 96: ooOoO0o
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 iiII1IiIi1i = False
 ii11iIIi = time . time ( )
 if 89 - 89: o0oOOo0O0Ooo / II111iiii . I1ii11iIi11i / OOooOOo
 o00O0O0OoO = lisp_control_header ( )
 if ( o00O0O0OoO . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( iiII1IiIi1i )
  if 92 - 92: OOooOOo % OOooOOo
  if 67 - 67: iII111i + I1ii11iIi11i - IiII . iII111i + iIii1I11I1II1
  if 40 - 40: II111iiii - oO0o / OoO0O00 / OoOoOO00 / Oo0Ooo
  if 11 - 11: IiII + OoooooooOO % OoooooooOO . o0oOOo0O0Ooo * OoOoOO00 + O0
  if 37 - 37: I1IiiI
 oO0oOOoo0Oooo = source
 if ( source . find ( "lisp" ) == - 1 ) :
  OOo0oOO0o0oo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  OOo0oOO0o0oo0 . string_to_afi ( source )
  OOo0oOO0o0oo0 . store_address ( source )
  source = OOo0oOO0o0oo0
  if 19 - 19: I1ii11iIi11i / IiII
  if 48 - 48: i1IIi % OOooOOo * OOooOOo
 if ( o00O0O0OoO . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , ii11iIIi )
  if 5 - 5: o0oOOo0O0Ooo / i11iIiiIii
 elif ( o00O0O0OoO . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , ii11iIIi )
  if 5 - 5: oO0o % iII111i . Oo0Ooo . O0 . OoOoOO00 / iII111i
 elif ( o00O0O0OoO . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
 elif ( o00O0O0OoO . type == LISP_MAP_NOTIFY ) :
  if ( oO0oOOoo0Oooo == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-rtr" ) ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-itr" ) ) :
   lisp_process_unicast_map_notify ( lisp_sockets , packet , source )
   if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
   if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
 elif ( o00O0O0OoO . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
 elif ( o00O0O0OoO . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 16 - 16: iIii1I11I1II1 . II111iiii
 elif ( o00O0O0OoO . type == LISP_NAT_INFO and o00O0O0OoO . is_info_reply ( ) ) :
  O0O0oOO , IIIIIi1I1Ii , iiII1IiIi1i = lisp_process_info_reply ( source , packet , True )
  if 80 - 80: Oo0Ooo + IiII
 elif ( o00O0O0OoO . type == LISP_NAT_INFO and o00O0O0OoO . is_info_reply ( ) == False ) :
  O00oO000Oo0 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , O00oO000Oo0 , udp_sport ,
 None )
  if 18 - 18: OoO0O00 . Oo0Ooo
 elif ( o00O0O0OoO . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 else :
  lprint ( "Invalid LISP control packet type {}:" . format ( o00O0O0OoO . type ) )
  lprint ( lisp_format_packet ( packet ) )
  if 14 - 14: i1IIi
  if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 return ( iiII1IiIi1i )
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
 if 48 - 48: OoO0O00
 if 30 - 30: iIii1I11I1II1
 if 53 - 53: II111iiii
 if 40 - 40: Ii1I % oO0o
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp ) :
 if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
 ooo0OO0OOooO0 = bold ( "RLOC-probe" , False )
 if 78 - 78: oO0o
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( ooo0OO0OOooO0 ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 20 - 20: i1IIi + i1IIi * i1IIi
  if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( ooo0OO0OOooO0 ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 27 - 27: oO0o + Ii1I . i11iIiiIii
  if 97 - 97: iII111i . I1IiiI
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( ooo0OO0OOooO0 ) )
 return
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
 if 45 - 45: oO0o
 if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
 if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 100 - 100: i11iIiiIii - iII111i - I11i
 if 5 - 5: oO0o % IiII * iII111i
 if 98 - 98: iII111i / OOooOOo + IiII
 if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 if 82 - 82: ooOoO0o % OOooOOo % Ii1I
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 82 - 82: I1ii11iIi11i
 if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
 if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
 if 69 - 69: iIii1I11I1II1 % iII111i + ooOoO0o * i1IIi + iII111i * I1Ii111
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , map_request ,
 keys , enc , auth , mr_ttl = - 1 ) :
 if 67 - 67: Ii1I % Oo0Ooo - Oo0Ooo . I11i + IiII
 oOooo0o = map_request . rloc_probe if ( map_request != None ) else False
 III1111 = map_request . json_telemetry if ( map_request != None ) else None
 if 66 - 66: Oo0Ooo - oO0o
 if 60 - 60: iIii1I11I1II1 / O0 . OOooOOo / OoO0O00 * I1ii11iIi11i
 IiIo0oo0O = lisp_map_reply ( )
 IiIo0oo0O . rloc_probe = oOooo0o
 IiIo0oo0O . echo_nonce_capable = enc
 IiIo0oo0O . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 IiIo0oo0O . record_count = 1
 IiIo0oo0O . nonce = nonce
 Oo00O0o0O = IiIo0oo0O . encode ( )
 IiIo0oo0O . print_map_reply ( )
 if 22 - 22: iIii1I11I1II1 + Ii1I
 oooO = lisp_eid_record ( )
 oooO . rloc_count = len ( rloc_set )
 if ( III1111 != None ) : oooO . rloc_count += 1
 oooO . authoritative = auth
 oooO . record_ttl = ttl
 oooO . action = action
 oooO . eid = eid
 oooO . group = group
 if 18 - 18: OOooOOo
 Oo00O0o0O += oooO . encode ( )
 oooO . print_record ( "  " , False )
 if 78 - 78: o0oOOo0O0Ooo / I1ii11iIi11i . IiII + II111iiii - OoOoOO00 + I1ii11iIi11i
 iiIII11I = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 28 - 28: Oo0Ooo * oO0o % ooOoO0o / OoOoOO00 % OoOoOO00
 ooooo = None
 for i1iiI1i1 in rloc_set :
  I1iI1III = i1iiI1i1 . rloc . is_multicast_address ( )
  ooO0 = lisp_rloc_record ( )
  OOoO0o0Oo0o = oOooo0o and ( I1iI1III or III1111 == None )
  O00oO000Oo0 = i1iiI1i1 . rloc . print_address_no_iid ( )
  if ( O00oO000Oo0 in iiIII11I or I1iI1III ) :
   ooO0 . local_bit = True
   ooO0 . probe_bit = OOoO0o0Oo0o
   ooO0 . keys = keys
   if ( i1iiI1i1 . priority == 254 and lisp_i_am_rtr ) :
    ooO0 . rloc_name = "RTR"
    if 72 - 72: iIii1I11I1II1
   if ( ooooo == None ) :
    if ( i1iiI1i1 . translated_rloc . is_null ( ) ) :
     ooooo = i1iiI1i1 . rloc
    else :
     ooooo = i1iiI1i1 . translated_rloc
     if 49 - 49: oO0o + iII111i + I1Ii111 . IiII . Ii1I
     if 51 - 51: oO0o - oO0o * OoooooooOO / oO0o * OoO0O00 / ooOoO0o
     if 22 - 22: oO0o - iIii1I11I1II1
  ooO0 . store_rloc_entry ( i1iiI1i1 )
  ooO0 . reach_bit = True
  ooO0 . print_record ( "    " )
  Oo00O0o0O += ooO0 . encode ( )
  if 33 - 33: II111iiii * O0 + O0
  if 98 - 98: IiII * OoooooooOO . iII111i
  if 34 - 34: OoooooooOO + I1Ii111
  if 97 - 97: II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
  if 9 - 9: i1IIi - I1Ii111 + I1Ii111
 if ( III1111 != None ) :
  ooO0 = lisp_rloc_record ( )
  if ( ooooo ) : ooO0 . rloc . copy_address ( ooooo )
  ooO0 . local_bit = True
  ooO0 . probe_bit = True
  ooO0 . reach_bit = True
  if ( lisp_i_am_rtr ) :
   ooO0 . priority = 254
   ooO0 . rloc_name = "RTR"
   if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
  Ooo = lisp_encode_telemetry ( III1111 , eo = str ( time . time ( ) ) )
  ooO0 . json = lisp_json ( "telemetry" , Ooo )
  ooO0 . print_record ( "    " )
  Oo00O0o0O += ooO0 . encode ( )
  if 26 - 26: OoooooooOO . OoooooooOO * OoOoOO00 - Oo0Ooo + i11iIiiIii
 return ( Oo00O0o0O )
 if 61 - 61: O0 - I1Ii111 % II111iiii
 if 20 - 20: Oo0Ooo + iIii1I11I1II1 % I1Ii111 + O0 % I1Ii111
 if 70 - 70: OoO0O00 - OOooOOo - o0oOOo0O0Ooo % I11i - iII111i / I1ii11iIi11i
 if 18 - 18: oO0o * II111iiii . I1Ii111 - iIii1I11I1II1 / iIii1I11I1II1
 if 1 - 1: iII111i
 if 97 - 97: I1ii11iIi11i + iIii1I11I1II1 / OoO0O00 * I1Ii111 . iII111i
 if 83 - 83: OoOoOO00
def lisp_build_map_referral ( eid , group , ddt_entry , action , ttl , nonce ) :
 oOooOO0OO = lisp_map_referral ( )
 oOooOO0OO . record_count = 1
 oOooOO0OO . nonce = nonce
 Oo00O0o0O = oOooOO0OO . encode ( )
 oOooOO0OO . print_map_referral ( )
 if 30 - 30: o0oOOo0O0Ooo
 oooO = lisp_eid_record ( )
 if 47 - 47: i1IIi - IiII + oO0o / OoO0O00 . OOooOOo * I1ii11iIi11i
 OooO = 0
 if ( ddt_entry == None ) :
  oooO . eid = eid
  oooO . group = group
 else :
  OooO = len ( ddt_entry . delegation_set )
  oooO . eid = ddt_entry . eid
  oooO . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 90 - 90: O0
 oooO . rloc_count = OooO
 oooO . authoritative = True
 if 32 - 32: iIii1I11I1II1
 if 41 - 41: IiII % OoooooooOO / I11i / iIii1I11I1II1 . IiII * I1Ii111
 if 40 - 40: O0 + Ii1I / iIii1I11I1II1 . iII111i / II111iiii % i1IIi
 if 43 - 43: OoOoOO00 % Ii1I . I11i - oO0o - OOooOOo
 if 60 - 60: I1Ii111 - Oo0Ooo + O0 + o0oOOo0O0Ooo
 iiIIi = False
 if ( action == LISP_DDT_ACTION_NULL ) :
  if ( OooO == 0 ) :
   action = LISP_DDT_ACTION_NODE_REFERRAL
  else :
   iii = ddt_entry . delegation_set [ 0 ]
   if ( iii . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 88 - 88: iIii1I11I1II1 + OOooOOo . II111iiii / i11iIiiIii % OOooOOo % IiII
   if ( iii . is_ms_child ( ) ) :
    action = LISP_DDT_ACTION_MS_REFERRAL
    if 38 - 38: OOooOOo
    if 82 - 82: OoOoOO00 % II111iiii * ooOoO0o + OoooooooOO + I1IiiI
    if 89 - 89: ooOoO0o % i1IIi - OoooooooOO
    if 100 - 100: Ii1I % I1ii11iIi11i % I1IiiI
    if 19 - 19: I1ii11iIi11i . o0oOOo0O0Ooo % Oo0Ooo / OoooooooOO
    if 68 - 68: iII111i
    if 55 - 55: IiII . i11iIiiIii % OoooooooOO
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : iiIIi = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  iiIIi = ( lisp_i_am_ms and iii . is_ms_peer ( ) == False )
  if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
  if 58 - 58: O0
 oooO . action = action
 oooO . ddt_incomplete = iiIIi
 oooO . record_ttl = ttl
 if 43 - 43: O0 / i1IIi / I11i % I1IiiI
 Oo00O0o0O += oooO . encode ( )
 oooO . print_record ( "  " , True )
 if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
 if ( OooO == 0 ) : return ( Oo00O0o0O )
 if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
 for iii in ddt_entry . delegation_set :
  ooO0 = lisp_rloc_record ( )
  ooO0 . rloc = iii . delegate_address
  ooO0 . priority = iii . priority
  ooO0 . weight = iii . weight
  ooO0 . mpriority = 255
  ooO0 . mweight = 0
  ooO0 . reach_bit = True
  Oo00O0o0O += ooO0 . encode ( )
  ooO0 . print_record ( "    " )
  if 36 - 36: I1ii11iIi11i % II111iiii % I1Ii111 / I1ii11iIi11i
 return ( Oo00O0o0O )
 if 34 - 34: OoooooooOO * i11iIiiIii
 if 33 - 33: II111iiii
 if 59 - 59: iIii1I11I1II1 % I11i
 if 93 - 93: I1ii11iIi11i
 if 50 - 50: ooOoO0o % OoO0O00 % OoO0O00
 if 36 - 36: I1IiiI * O0 . IiII / I1Ii111
 if 15 - 15: I11i + iII111i
def lisp_etr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 79 - 79: i11iIiiIii * IiII % iII111i
 if ( map_request . target_group . is_null ( ) ) :
  Iiii1II1 = lisp_db_for_lookups . lookup_cache ( map_request . target_eid , False )
 else :
  Iiii1II1 = lisp_db_for_lookups . lookup_cache ( map_request . target_group , False )
  if ( Iiii1II1 ) : Iiii1II1 = Iiii1II1 . lookup_source_cache ( map_request . target_eid , False )
  if 76 - 76: OOooOOo * IiII % I1IiiI
 oOOoo = map_request . print_prefix ( )
 if 14 - 14: OoooooooOO . I1Ii111 % Ii1I + iII111i + O0
 if ( Iiii1II1 == None ) :
  lprint ( "Database-mapping entry not found for requested EID {}" . format ( green ( oOOoo , False ) ) )
  if 31 - 31: ooOoO0o / i11iIiiIii . OoO0O00 - O0 * Ii1I + Ii1I
  return
  if 59 - 59: i11iIiiIii % iII111i
  if 54 - 54: I11i . ooOoO0o / OOooOOo % I1Ii111
 I1iii = Iiii1II1 . print_eid_tuple ( )
 if 52 - 52: oO0o . OoO0O00 + OoooooooOO % II111iiii % OoOoOO00 - I1Ii111
 lprint ( "Found database-mapping EID-prefix {} for requested EID {}" . format ( green ( I1iii , False ) , green ( oOOoo , False ) ) )
 if 2 - 2: II111iiii * OOooOOo - I11i / I1IiiI
 if 13 - 13: Oo0Ooo
 if 88 - 88: Oo0Ooo / oO0o . iIii1I11I1II1 . I1IiiI + I11i
 if 58 - 58: I11i
 if 76 - 76: iIii1I11I1II1 % ooOoO0o / IiII + iIii1I11I1II1 % Oo0Ooo . Ii1I
 O00O000OO = map_request . itr_rlocs [ 0 ]
 if ( O00O000OO . is_private_address ( ) and lisp_nat_traversal ) :
  O00O000OO = source
  if 44 - 44: o0oOOo0O0Ooo . O0 + Ii1I
  if 61 - 61: ooOoO0o
 OOooO = map_request . nonce
 iiiIiIIi1 = lisp_nonce_echoing
 oOoOOoo = map_request . keys
 if 41 - 41: oO0o % iII111i % iIii1I11I1II1 / I1ii11iIi11i
 if 69 - 69: OOooOOo * I11i % i11iIiiIii
 if 63 - 63: OoOoOO00 + I1IiiI / I1ii11iIi11i / o0oOOo0O0Ooo % I1IiiI
 if 67 - 67: I1Ii111 . oO0o % I1ii11iIi11i % OOooOOo + I1IiiI
 if 4 - 4: iII111i - i11iIiiIii * ooOoO0o
 OOI1I1 = map_request . json_telemetry
 if ( OOI1I1 != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( OOI1I1 , ei = etr_in_ts )
  if 35 - 35: I1IiiI / Ii1I / i11iIiiIii
  if 76 - 76: OOooOOo % OOooOOo + o0oOOo0O0Ooo - I1ii11iIi11i * oO0o * IiII
 Iiii1II1 . map_replies_sent += 1
 if 14 - 14: I1Ii111 . OoOoOO00 % OOooOOo . i11iIiiIii * I1IiiI % Ii1I
 Oo00O0o0O = lisp_build_map_reply ( Iiii1II1 . eid , Iiii1II1 . group , Iiii1II1 . rloc_set , OOooO ,
 LISP_NO_ACTION , 1440 , map_request , oOoOOoo , iiiIiIIi1 , True , ttl )
 if 7 - 7: OoooooooOO
 if 41 - 41: OoOoOO00 + IiII % I1Ii111 / OOooOOo . I1IiiI
 if 43 - 43: II111iiii - ooOoO0o / iIii1I11I1II1
 if 30 - 30: O0 * o0oOOo0O0Ooo / iIii1I11I1II1 + iIii1I11I1II1 . OoOoOO00
 if 78 - 78: OoOoOO00 . i11iIiiIii
 if 29 - 29: i11iIiiIii % i1IIi
 if 31 - 31: o0oOOo0O0Ooo + IiII * OOooOOo
 if 26 - 26: Ii1I % O0 - i1IIi % iII111i * OoO0O00
 if 60 - 60: I1ii11iIi11i * iII111i / OoOoOO00 . o0oOOo0O0Ooo / iIii1I11I1II1
 if 94 - 94: OoO0O00 . ooOoO0o
 if 25 - 25: I1Ii111 % OOooOOo
 if 82 - 82: Ii1I
 if 17 - 17: iII111i . i1IIi . i1IIi
 if 76 - 76: OoooooooOO % IiII
 if 81 - 81: iII111i . OOooOOo * i1IIi
 if 14 - 14: oO0o
 if ( map_request . rloc_probe and len ( lisp_sockets ) == 4 ) :
  if 16 - 16: iII111i
  I1IIiIIiii = ( O00O000OO . is_private_address ( ) == False )
  I11i1i1 = O00O000OO . print_address_no_iid ( )
  if ( I1IIiIIiii and I11i1i1 in lisp_rtr_list and sport == 0 ) :
   lisp_encap_rloc_probe ( lisp_sockets , O00O000OO , None , Oo00O0o0O )
   return
   if 26 - 26: iII111i . oO0o * i11iIiiIii . iIii1I11I1II1
   if 74 - 74: Ii1I / iIii1I11I1II1 + OOooOOo . II111iiii
   if 65 - 65: OOooOOo * I11i * Oo0Ooo
   if 21 - 21: Ii1I . iIii1I11I1II1
   if 84 - 84: OOooOOo
   if 67 - 67: I1IiiI % OoO0O00 % o0oOOo0O0Ooo % IiII
   if 33 - 33: ooOoO0o % I1IiiI
   if 98 - 98: oO0o . o0oOOo0O0Ooo + II111iiii
   if 62 - 62: ooOoO0o - OoooooooOO / I1ii11iIi11i / iII111i - o0oOOo0O0Ooo
   if 70 - 70: oO0o % OoooooooOO * I1IiiI - OoOoOO00 * OoOoOO00 . OOooOOo
  I11I111Ii1II = O00O000OO . print_address_no_iid ( )
  if ( lisp_decent_nat and I11I111Ii1II not in lisp_rtr_list ) :
   IiIiI1ii = lisp_get_nat_info ( O00O000OO , None )
   if ( IiIiI1ii == None ) :
    lprint ( "Could not find NAT-info state for {}" . format ( I11I111Ii1II ) )
    return
    if 57 - 57: Oo0Ooo * iIii1I11I1II1 - OoOoOO00 % iII111i % I1ii11iIi11i + Ii1I
    if 82 - 82: IiII * Oo0Ooo - iIii1I11I1II1 - i11iIiiIii
    if 85 - 85: OoooooooOO
    if 37 - 37: OoooooooOO + O0 + I1ii11iIi11i + IiII * iII111i
    if 15 - 15: i11iIiiIii / Oo0Ooo - OOooOOo . IiII
   lisp_encap_rloc_probe ( lisp_sockets , O00O000OO , IiIiI1ii , Oo00O0o0O )
   return
   if 11 - 11: OOooOOo / i1IIi % Oo0Ooo
   if 65 - 65: OOooOOo % I1ii11iIi11i
   if 25 - 25: o0oOOo0O0Ooo - I1Ii111 * I1ii11iIi11i + OoooooooOO
   if 93 - 93: OoOoOO00 % I1ii11iIi11i * I11i
   if 34 - 34: I11i - oO0o + I11i * OoooooooOO * I11i
   if 73 - 73: OOooOOo * iII111i * OoO0O00
 lisp_send_map_reply ( lisp_sockets , Oo00O0o0O , O00O000OO , sport )
 return
 if 11 - 11: I1Ii111 * II111iiii
 if 3 - 3: Oo0Ooo * OOooOOo
 if 13 - 13: I1Ii111 + i11iIiiIii / OOooOOo
 if 98 - 98: I1IiiI * Oo0Ooo
 if 9 - 9: O0 / i11iIiiIii . iIii1I11I1II1 . IiII
 if 14 - 14: OoOoOO00 . OOooOOo - Oo0Ooo + I1Ii111 % ooOoO0o
 if 95 - 95: OoO0O00 * II111iiii + i1IIi
def lisp_rtr_process_map_request ( lisp_sockets , map_request , source , sport ,
 ttl , etr_in_ts ) :
 if 22 - 22: Ii1I / ooOoO0o % I11i + OoO0O00 . ooOoO0o
 if 61 - 61: O0 - iIii1I11I1II1 * Oo0Ooo . Ii1I + O0
 if 20 - 20: ooOoO0o / ooOoO0o - Ii1I - ooOoO0o
 if 93 - 93: O0 * OoOoOO00 * iIii1I11I1II1
 O00O000OO = map_request . itr_rlocs [ 0 ]
 if ( O00O000OO . is_private_address ( ) ) : O00O000OO = source
 OOooO = map_request . nonce
 if 3 - 3: I1ii11iIi11i - O0
 O0o00o0Oo = map_request . target_eid
 i1I1IIIiII = map_request . target_group
 if 46 - 46: iII111i
 o0O00ooOo = [ ]
 for OOo0o000O0 in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( OOo0o000O0 == None ) : continue
  OO0Oo00oo = lisp_rloc ( )
  OO0Oo00oo . rloc . copy_address ( OOo0o000O0 )
  OO0Oo00oo . priority = 254
  o0O00ooOo . append ( OO0Oo00oo )
  if 70 - 70: I11i + O0 . i11iIiiIii . OOooOOo
  if 48 - 48: iIii1I11I1II1 * Ii1I - OoooooooOO / oO0o - OoO0O00 / i11iIiiIii
 iiiIiIIi1 = lisp_nonce_echoing
 oOoOOoo = map_request . keys
 if 24 - 24: I1IiiI
 if 63 - 63: I11i - iIii1I11I1II1 * Ii1I + OoooooooOO . i11iIiiIii
 if 94 - 94: OoO0O00 . oO0o . OoOoOO00 * i11iIiiIii
 if 96 - 96: i1IIi . OoO0O00 . OoO0O00 - o0oOOo0O0Ooo - Ii1I
 if 33 - 33: ooOoO0o + I1ii11iIi11i - I1IiiI . iII111i / OoO0O00
 OOI1I1 = map_request . json_telemetry
 if ( OOI1I1 != None ) :
  map_request . json_telemetry = lisp_encode_telemetry ( OOI1I1 , ei = etr_in_ts )
  if 91 - 91: OOooOOo - OoooooooOO . OoO0O00
  if 34 - 34: Ii1I . I1IiiI . i1IIi * I1ii11iIi11i
 Oo00O0o0O = lisp_build_map_reply ( O0o00o0Oo , i1I1IIIiII , o0O00ooOo , OOooO , LISP_NO_ACTION ,
 1440 , map_request , oOoOOoo , iiiIiIIi1 , True , ttl )
 lisp_send_map_reply ( lisp_sockets , Oo00O0o0O , O00O000OO , sport )
 return
 if 77 - 77: ooOoO0o . II111iiii
 if 41 - 41: IiII
 if 27 - 27: IiII / IiII
 if 91 - 91: Ii1I
 if 93 - 93: OoO0O00 * OoO0O00 * I1ii11iIi11i * OoO0O00 * o0oOOo0O0Ooo
 if 84 - 84: I1Ii111 * OoO0O00 - ooOoO0o - Oo0Ooo . OoO0O00 % oO0o
 if 98 - 98: OoO0O00 . i1IIi
 if 58 - 58: i1IIi * O0 + I1ii11iIi11i . IiII
 if 11 - 11: OOooOOo + iIii1I11I1II1 - ooOoO0o * OoO0O00 * i11iIiiIii
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
def lisp_get_private_rloc_set ( target_site_eid , seid , group ) :
 o0O00ooOo = target_site_eid . registered_rlocs
 if 7 - 7: Oo0Ooo + ooOoO0o - I1Ii111 * iIii1I11I1II1
 I111i111iI1 = lisp_site_eid_lookup ( seid , group , False )
 if ( I111i111iI1 == None ) : return ( o0O00ooOo )
 if 100 - 100: i1IIi . Ii1I . o0oOOo0O0Ooo + Ii1I - i1IIi . I11i
 if 19 - 19: i11iIiiIii + I11i - IiII . iII111i * i1IIi
 if 66 - 66: ooOoO0o
 if 4 - 4: iII111i / iII111i * OOooOOo + o0oOOo0O0Ooo . I1Ii111 + II111iiii
 O000oOooO0oo = None
 IiII11iIIII1 = [ ]
 for i1iiI1i1 in o0O00ooOo :
  if ( i1iiI1i1 . is_rtr ( ) ) : continue
  if ( i1iiI1i1 . rloc . is_private_address ( ) ) :
   II1111111i = copy . deepcopy ( i1iiI1i1 )
   IiII11iIIII1 . append ( II1111111i )
   continue
   if 38 - 38: o0oOOo0O0Ooo + o0oOOo0O0Ooo / O0 + OoooooooOO
  O000oOooO0oo = i1iiI1i1
  break
  if 51 - 51: II111iiii - oO0o % OoooooooOO - II111iiii / O0 - OoooooooOO
 if ( O000oOooO0oo == None ) : return ( o0O00ooOo )
 O000oOooO0oo = O000oOooO0oo . rloc . print_address_no_iid ( )
 if 21 - 21: iII111i * o0oOOo0O0Ooo
 if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
 if 26 - 26: I1Ii111 + Oo0Ooo + II111iiii % OoOoOO00 % OOooOOo
 if 40 - 40: I1ii11iIi11i + i1IIi
 i1III11I11 = None
 for i1iiI1i1 in I111i111iI1 . registered_rlocs :
  if ( i1iiI1i1 . is_rtr ( ) ) : continue
  if ( i1iiI1i1 . rloc . is_private_address ( ) ) : continue
  i1III11I11 = i1iiI1i1
  break
  if 82 - 82: IiII + Oo0Ooo + iIii1I11I1II1 - I11i - I1IiiI
 if ( i1III11I11 == None ) : return ( o0O00ooOo )
 i1III11I11 = i1III11I11 . rloc . print_address_no_iid ( )
 if 65 - 65: IiII / O0 * II111iiii + oO0o
 if 52 - 52: o0oOOo0O0Ooo - OoOoOO00 * II111iiii / OoooooooOO
 if 44 - 44: OOooOOo - oO0o + o0oOOo0O0Ooo - i1IIi % o0oOOo0O0Ooo
 if 79 - 79: iII111i . iIii1I11I1II1
 IIIi1IiI1iII = target_site_eid . site_id
 if ( IIIi1IiI1iII == 0 ) :
  if ( i1III11I11 == O000oOooO0oo ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( O000oOooO0oo ) )
   if 42 - 42: i11iIiiIii / IiII . O0 / OOooOOo . iII111i * i1IIi
   return ( IiII11iIIII1 )
   if 83 - 83: iIii1I11I1II1 . II111iiii * Oo0Ooo . I1IiiI - I1IiiI - iIii1I11I1II1
  return ( o0O00ooOo )
  if 29 - 29: Oo0Ooo
  if 35 - 35: OoOoOO00 + II111iiii
  if 46 - 46: O0 / I1ii11iIi11i + OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
  if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
  if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
  if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
  if 81 - 81: iIii1I11I1II1 - Oo0Ooo - ooOoO0o . OoO0O00 + I1ii11iIi11i
 if ( IIIi1IiI1iII == I111i111iI1 . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( IIIi1IiI1iII ) )
  return ( IiII11iIIII1 )
  if 84 - 84: iII111i . OOooOOo . iII111i * oO0o % Ii1I . oO0o
 return ( o0O00ooOo )
 if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
 if 64 - 64: IiII - Oo0Ooo % iII111i % I11i
 if 42 - 42: Oo0Ooo . OoO0O00
 if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
 if 10 - 10: oO0o / I1IiiI
 if 95 - 95: II111iiii - IiII % IiII . o0oOOo0O0Ooo
 if 19 - 19: II111iiii . ooOoO0o . I11i - OoooooooOO / I1ii11iIi11i . I1Ii111
 if 57 - 57: II111iiii . I1Ii111 . i11iIiiIii / OoOoOO00 - O0
 if 56 - 56: OOooOOo / I1Ii111
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 IIIIiII = [ ]
 o0O00ooOo = [ ]
 if 45 - 45: I1IiiI / iIii1I11I1II1 - OoOoOO00
 if 10 - 10: iIii1I11I1II1 + i1IIi * Ii1I / iIii1I11I1II1 % OoOoOO00 / O0
 if 14 - 14: O0
 if 65 - 65: IiII / oO0o
 if 57 - 57: IiII + oO0o - IiII
 if 51 - 51: OoOoOO00 % IiII / iII111i - oO0o - OoO0O00 . iIii1I11I1II1
 oOO0o0o = False
 ii1ii1111ii = False
 for i1iiI1i1 in registered_rloc_set :
  if ( i1iiI1i1 . priority != 254 ) : continue
  ii1ii1111ii |= True
  if ( i1iiI1i1 . rloc . is_exact_match ( mr_source ) == False ) : continue
  oOO0o0o = True
  break
  if 1 - 1: Oo0Ooo / IiII
  if 40 - 40: OoooooooOO / Ii1I
  if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
  if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
  if 32 - 32: oO0o . I1Ii111 * I1Ii111
  if 32 - 32: I1Ii111 . Ii1I / i1IIi
  if 2 - 2: OOooOOo * ooOoO0o / I11i + OoO0O00
 if ( ii1ii1111ii == False ) : return ( registered_rloc_set )
 if 96 - 96: II111iiii * OoO0O00 + I1ii11iIi11i + OoOoOO00 / II111iiii . iII111i
 if 64 - 64: iII111i % Oo0Ooo
 if 79 - 79: IiII + iII111i / II111iiii . i1IIi + iIii1I11I1II1
 if 32 - 32: Ii1I * iII111i
 if 52 - 52: I11i
 if 100 - 100: Oo0Ooo % Oo0Ooo % I1ii11iIi11i
 if 33 - 33: I1Ii111 . I1Ii111 * i1IIi
 if 22 - 22: I1ii11iIi11i . II111iiii + iIii1I11I1II1 / OoooooooOO . ooOoO0o
 if 13 - 13: II111iiii
 if 36 - 36: iII111i - oO0o / Oo0Ooo / O0 . OoO0O00 . i1IIi
 Iiooo0O0o0o = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 16 - 16: O0 + OOooOOo * I1ii11iIi11i * IiII
 if 56 - 56: iII111i
 if 68 - 68: OoooooooOO % o0oOOo0O0Ooo . i1IIi - II111iiii * OoOoOO00
 if 46 - 46: ooOoO0o . I1IiiI - ooOoO0o + Oo0Ooo
 if 31 - 31: OOooOOo + ooOoO0o . i1IIi - OoO0O00
 for i1iiI1i1 in registered_rloc_set :
  if ( Iiooo0O0o0o and i1iiI1i1 . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and i1iiI1i1 . priority == 255 ) : continue
  if ( multicast and i1iiI1i1 . mpriority == 255 ) : continue
  if ( i1iiI1i1 . priority == 254 ) :
   IIIIiII . append ( i1iiI1i1 )
  else :
   o0O00ooOo . append ( i1iiI1i1 )
   if 16 - 16: I11i + I1IiiI - Ii1I / I1ii11iIi11i + Ii1I
   if 38 - 38: i1IIi * iIii1I11I1II1 * iII111i + OoOoOO00
   if 64 - 64: OoO0O00 % o0oOOo0O0Ooo
   if 72 - 72: O0 + OoOoOO00 % OOooOOo / oO0o / IiII
   if 98 - 98: Oo0Ooo . II111iiii * I11i
   if 39 - 39: IiII * o0oOOo0O0Ooo + Ii1I - I11i
 if ( oOO0o0o ) : return ( o0O00ooOo )
 if 70 - 70: oO0o * ooOoO0o / ooOoO0o - Ii1I * Ii1I % OOooOOo
 if 91 - 91: OoO0O00 - OoO0O00 % O0
 if 67 - 67: ooOoO0o * i1IIi
 if 66 - 66: o0oOOo0O0Ooo - I1ii11iIi11i . OoOoOO00 / iII111i - Ii1I - i1IIi
 if 97 - 97: oO0o % iII111i - OOooOOo . OoooooooOO
 if 94 - 94: Oo0Ooo
 if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
 if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
 if 43 - 43: OoooooooOO * I1IiiI
 if 2 - 2: OOooOOo / oO0o + I1ii11iIi11i + i11iIiiIii % iIii1I11I1II1 . I1ii11iIi11i
 if 100 - 100: Oo0Ooo * ooOoO0o + Ii1I / iII111i * o0oOOo0O0Ooo
 if 26 - 26: I1Ii111 * OoOoOO00
 o0O00ooOo = [ ]
 for i1iiI1i1 in registered_rloc_set :
  if ( i1iiI1i1 . rloc . is_ipv6 ( ) ) : o0O00ooOo . append ( i1iiI1i1 )
  if ( i1iiI1i1 . rloc . is_private_address ( ) ) : o0O00ooOo . append ( i1iiI1i1 )
  if 38 - 38: II111iiii
 o0O00ooOo += IIIIiII
 return ( o0O00ooOo )
 if 50 - 50: OoOoOO00 . IiII - OOooOOo
 if 46 - 46: iIii1I11I1II1
 if 97 - 97: O0 * OOooOOo - o0oOOo0O0Ooo % o0oOOo0O0Ooo * II111iiii % I11i
 if 65 - 65: iIii1I11I1II1 / OOooOOo
 if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
 if 14 - 14: I11i + Oo0Ooo + i11iIiiIii - i1IIi . O0
 if 47 - 47: o0oOOo0O0Ooo / i1IIi * IiII
 if 50 - 50: I11i
 if 9 - 9: iII111i . OoOoOO00 * iII111i
 if 54 - 54: i11iIiiIii * I1IiiI / IiII - OoO0O00 % i1IIi
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 iiI11i1i1 = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 iiI11i1i1 . add ( reply_eid )
 return ( iiI11i1i1 )
 if 37 - 37: II111iiii - O0
 if 67 - 67: I1IiiI
 if 32 - 32: OoooooooOO - I1Ii111 / i1IIi + OoOoOO00
 if 26 - 26: I11i + I11i - ooOoO0o
 if 66 - 66: iII111i - o0oOOo0O0Ooo + I1IiiI
 if 72 - 72: OoOoOO00
 if 17 - 17: ooOoO0o - i1IIi
 if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
 if 5 - 5: OoOoOO00 . I11i
 if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
 if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
 if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 if 76 - 76: I1IiiI % Ii1I + OoO0O00 + I1ii11iIi11i * II111iiii + Oo0Ooo
 if 3 - 3: Ii1I - I1IiiI + O0
def lisp_convert_reply_to_notify ( packet ) :
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
 if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
 if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
 oO0oooOOo = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 oO0oooOOo = socket . ntohl ( oO0oooOOo ) & 0xff
 OOooO = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 73 - 73: iIii1I11I1II1 % O0 / I11i
 if 42 - 42: ooOoO0o . I1IiiI + ooOoO0o
 if 23 - 23: i11iIiiIii / Oo0Ooo
 if 16 - 16: OoooooooOO + O0 / IiII / Oo0Ooo . IiII / ooOoO0o
 IiiI11iIi = ( LISP_MAP_NOTIFY << 28 ) | oO0oooOOo
 o00O0O0OoO = struct . pack ( "I" , socket . htonl ( IiiI11iIi ) )
 i11II = struct . pack ( "I" , 0 )
 if 18 - 18: OoooooooOO / I1ii11iIi11i * i1IIi / i11iIiiIii + Oo0Ooo / Ii1I
 if 12 - 12: I1IiiI - II111iiii / O0 . II111iiii + II111iiii - I1ii11iIi11i
 if 48 - 48: O0 % I1ii11iIi11i
 if 72 - 72: I1IiiI - i1IIi
 packet = o00O0O0OoO + OOooO + i11II + packet
 return ( packet )
 if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
 if 65 - 65: Oo0Ooo / OoooooooOO
 if 60 - 60: II111iiii + I1IiiI % oO0o - o0oOOo0O0Ooo
 if 50 - 50: iIii1I11I1II1 - i11iIiiIii / iII111i + ooOoO0o / OOooOOo
 if 80 - 80: IiII / OoooooooOO
 if 69 - 69: OoOoOO00 + IiII
 if 18 - 18: O0 / I11i
 if 10 - 10: I1Ii111 * i1IIi
def lisp_notify_subscribers ( lisp_sockets , eid_record , rloc_records ,
 registered_eid , site ) :
 if 48 - 48: Oo0Ooo % i1IIi / iII111i . O0
 for i1Iii1I in lisp_pubsub_cache :
  for iiI11i1i1 in list ( lisp_pubsub_cache [ i1Iii1I ] . values ( ) ) :
   oOO = iiI11i1i1 . eid_prefix
   if ( oOO . is_more_specific ( registered_eid ) == False ) : continue
   if 42 - 42: oO0o * iIii1I11I1II1 * O0 * I1ii11iIi11i * I11i
   oo000oo0oOo0 = iiI11i1i1 . itr
   i11I1Ii1Iiii1 = iiI11i1i1 . port
   Ii1i = red ( oo000oo0oOo0 . print_address_no_iid ( ) , False )
   i1iiIi1 = bold ( "subscriber" , False )
   Ooo0 = "0x" + lisp_hex_string ( iiI11i1i1 . xtr_id )
   OOooO = "0x" + lisp_hex_string ( iiI11i1i1 . nonce )
   if 32 - 32: ooOoO0o
   lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( i1iiIi1 , Ii1i , i11I1Ii1Iiii1 , Ooo0 , green ( i1Iii1I , False ) , OOooO ) )
   if 9 - 9: I1Ii111
   if 77 - 77: OoooooooOO * I1Ii111
   if 63 - 63: IiII * oO0o * iIii1I11I1II1
   if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
   if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
   if 4 - 4: O0
   IIIi11i = copy . deepcopy ( eid_record )
   IIIi11i . eid . copy_address ( oOO )
   IIIi11i = IIIi11i . encode ( ) + rloc_records
   lisp_build_map_notify ( lisp_sockets , IIIi11i , [ i1Iii1I ] , 1 , oo000oo0oOo0 ,
 i11I1Ii1Iiii1 , iiI11i1i1 . nonce , 0 , 0 , 0 , site , False )
   if 98 - 98: I11i / I11i * I1ii11iIi11i % OoOoOO00
   iiI11i1i1 . map_notify_count += 1
   if 33 - 33: IiII + I11i * oO0o
   if 18 - 18: OoOoOO00 + I1ii11iIi11i
 return
 if 67 - 67: iII111i - OoO0O00 + I11i + O0
 if 37 - 37: OOooOOo / iIii1I11I1II1
 if 1 - 1: I1ii11iIi11i * ooOoO0o
 if 35 - 35: IiII % Ii1I - oO0o - OoO0O00 * i11iIiiIii
 if 62 - 62: OoOoOO00 / I1Ii111
 if 2 - 2: Ii1I * O0 . II111iiii
 if 39 - 39: iII111i + iIii1I11I1II1 / Ii1I . IiII
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 35 - 35: ooOoO0o - oO0o
 if 24 - 24: OoooooooOO / i1IIi / Ii1I
 if 77 - 77: iII111i / OoO0O00 % Oo0Ooo % OoOoOO00 % IiII / II111iiii
 if 82 - 82: I1Ii111 + O0 . I1IiiI / I1ii11iIi11i % II111iiii
 iiI11i1i1 = lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl ,
 xtr_id )
 if 46 - 46: O0 - I1IiiI + OoooooooOO / OoOoOO00
 O0o00o0Oo = green ( reply_eid . print_prefix ( ) , False )
 oo000oo0oOo0 = red ( itr_rloc . print_address_no_iid ( ) , False )
 OO00oo0Oo = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( OO00oo0Oo ,
 O0o00o0Oo , oo000oo0oOo0 , xtr_id ) )
 if 88 - 88: O0 - i1IIi . II111iiii - O0 + O0 / I1ii11iIi11i
 if 9 - 9: iIii1I11I1II1
 if 57 - 57: i1IIi * OOooOOo
 if 35 - 35: I1Ii111 / Oo0Ooo * OoooooooOO / O0 / iIii1I11I1II1
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 iiI11i1i1 . map_notify_count += 1
 return
 if 44 - 44: o0oOOo0O0Ooo / iIii1I11I1II1
 if 40 - 40: OoO0O00 / O0
 if 60 - 60: iIii1I11I1II1 / Oo0Ooo / oO0o + iII111i
 if 66 - 66: iIii1I11I1II1 . O0 * IiII . ooOoO0o + i1IIi
 if 83 - 83: o0oOOo0O0Ooo / II111iiii + I1IiiI - iII111i + OoO0O00
 if 67 - 67: I1Ii111 - OoOoOO00 . i11iIiiIii - I1Ii111 . i11iIiiIii
 if 25 - 25: I11i % I1Ii111 + Ii1I
 if 46 - 46: ooOoO0o + Oo0Ooo + oO0o / II111iiii . iIii1I11I1II1 * I1IiiI
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source , ecm_sport ) :
 if 87 - 87: I11i + iIii1I11I1II1
 mr_sport = ecm_sport
 if 91 - 91: oO0o
 if 58 - 58: i11iIiiIii / Ii1I - OoooooooOO
 if 25 - 25: i1IIi * ooOoO0o % OOooOOo / I1IiiI
 if 75 - 75: i11iIiiIii
 if 38 - 38: iIii1I11I1II1
 if 80 - 80: OoO0O00
 O0o00o0Oo = map_request . target_eid
 i1I1IIIiII = map_request . target_group
 oOOoo = lisp_print_eid_tuple ( O0o00o0Oo , i1I1IIIiII )
 O00O000OO = map_request . itr_rlocs [ 0 ]
 Ooo0 = map_request . xtr_id
 OOooO = map_request . nonce
 oo0OoooOo0 = LISP_NO_ACTION
 iiI11i1i1 = map_request . subscribe_bit
 o0o0Oo00Oo00o = map_request . decent_nat_xtr
 if 14 - 14: I1ii11iIi11i * OoooooooOO / OoO0O00 / OoOoOO00 / OoooooooOO
 if 17 - 17: i1IIi
 if 80 - 80: i1IIi - iIii1I11I1II1 + OoooooooOO + ooOoO0o / IiII - I1ii11iIi11i
 if 90 - 90: I1IiiI * ooOoO0o - I11i + O0 - I11i
 if 59 - 59: OOooOOo % II111iiii
 iiIii = True
 i11 = ( lisp_get_eid_hash ( O0o00o0Oo ) != None )
 if ( i11 ) :
  iIiI = map_request . map_request_signature
  if ( iIiI == None ) :
   iiIii = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 53 - 53: II111iiii + Ii1I * o0oOOo0O0Ooo
  else :
   OOooo = map_request . signature_eid
   i1i1I11I1I , IiiIi1 , iiIii = lisp_lookup_public_key ( OOooo )
   if ( iiIii ) :
    iiIii = map_request . verify_map_request_sig ( IiiIi1 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( OOooo . print_address ( ) , i1i1I11I1I . print_address ( ) ) )
    if 31 - 31: OoOoOO00
    if 72 - 72: II111iiii + i11iIiiIii * OoO0O00 / II111iiii / I11i
   oo0OooOO00 = bold ( "passed" , False ) if iiIii else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( oo0OooOO00 ) )
   if 67 - 67: I1ii11iIi11i . Oo0Ooo
   if 69 - 69: ooOoO0o * OoO0O00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
   if 35 - 35: I1IiiI . OOooOOo * OoO0O00 . I1ii11iIi11i - I1IiiI
 if ( iiI11i1i1 and iiIii == False ) :
  iiI11i1i1 = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 5 - 5: i1IIi * II111iiii
  if 64 - 64: I1IiiI * iIii1I11I1II1 % I1Ii111
  if 22 - 22: OoooooooOO + I1Ii111 . o0oOOo0O0Ooo * Oo0Ooo
  if 61 - 61: iIii1I11I1II1
  if 95 - 95: I1ii11iIi11i + IiII * Ii1I - IiII
  if 58 - 58: I1ii11iIi11i - oO0o % I11i * O0
  if 43 - 43: OoOoOO00 + O0
  if 71 - 71: ooOoO0o * I1IiiI / I1ii11iIi11i
  if 8 - 8: I1Ii111 / iIii1I11I1II1
  if 29 - 29: i11iIiiIii % i1IIi + oO0o . I1ii11iIi11i
  if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
  if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
  if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
  if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
 O0O0o = O00O000OO if ( O00O000OO . afi == ecm_source . afi ) else ecm_source
 if 69 - 69: OoO0O00 + iIii1I11I1II1
 Ooo000oOOooO00 = lisp_site_eid_lookup ( O0o00o0Oo , i1I1IIIiII , False )
 if 88 - 88: I1Ii111 . O0 - oO0o + i1IIi % Oo0Ooo
 if ( Ooo000oOOooO00 == None or Ooo000oOOooO00 . is_star_g ( ) ) :
  i1iiiiI1I = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( i1iiiiI1I ,
 green ( oOOoo , False ) ) )
  if 28 - 28: i1IIi
  if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
  if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
  if 46 - 46: oO0o
  lisp_send_negative_map_reply ( lisp_sockets , O0o00o0Oo , i1I1IIIiII , OOooO , O00O000OO ,
 mr_sport , 15 , Ooo0 , iiI11i1i1 )
  if 5 - 5: i1IIi % o0oOOo0O0Ooo + OoOoOO00 - I11i . Ii1I
  return ( [ O0o00o0Oo , i1I1IIIiII , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 33 - 33: II111iiii * o0oOOo0O0Ooo
  if 8 - 8: I1ii11iIi11i % o0oOOo0O0Ooo - IiII
 I1iii = Ooo000oOOooO00 . print_eid_tuple ( )
 OooOo0OO = Ooo000oOOooO00 . site . site_name
 if 42 - 42: ooOoO0o - I11i * iII111i
 if 39 - 39: OOooOOo - I1ii11iIi11i % IiII % I1ii11iIi11i * II111iiii - Ii1I
 if 19 - 19: I11i % OoOoOO00 / OoO0O00 % I11i + o0oOOo0O0Ooo / iII111i
 if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
 if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
 if ( i11 == False and Ooo000oOOooO00 . require_signature ) :
  iIiI = map_request . map_request_signature
  OOooo = map_request . signature_eid
  if ( iIiI == None or OOooo . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( OooOo0OO ) )
   iiIii = False
  else :
   OOooo = map_request . signature_eid
   i1i1I11I1I , IiiIi1 , iiIii = lisp_lookup_public_key ( OOooo )
   if ( iiIii ) :
    iiIii = map_request . verify_map_request_sig ( IiiIi1 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( OOooo . print_address ( ) , i1i1I11I1I . print_address ( ) ) )
    if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
    if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
   oo0OooOO00 = bold ( "passed" , False ) if iiIii else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( oo0OooOO00 ) )
   if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
   if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
   if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
   if 66 - 66: iII111i % iII111i
   if 59 - 59: II111iiii . i1IIi % i1IIi
   if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
 if ( iiIii and Ooo000oOOooO00 . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( OooOo0OO , green ( I1iii , False ) , green ( oOOoo , False ) ) )
  if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
  if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
  if 13 - 13: Ii1I % i11iIiiIii
  if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
  if 50 - 50: I1ii11iIi11i + iII111i
  if 64 - 64: oO0o
  if ( Ooo000oOOooO00 . accept_more_specifics == False ) :
   O0o00o0Oo = Ooo000oOOooO00 . eid
   i1I1IIIiII = Ooo000oOOooO00 . group
   if 11 - 11: o0oOOo0O0Ooo
   if 95 - 95: i1IIi . ooOoO0o . Oo0Ooo
   if 13 - 13: OOooOOo - Oo0Ooo % O0 . I1Ii111
   if 66 - 66: I1IiiI + I11i
   if 58 - 58: I1ii11iIi11i
  o0ooo000o00O = 1
  if ( Ooo000oOOooO00 . force_ttl != None ) :
   o0ooo000o00O = Ooo000oOOooO00 . force_ttl | 0x80000000
   if 7 - 7: oO0o - I11i
  O0oO = ( Ooo000oOOooO00 . proxy_reply_action == "not-registered-yet" )
  if 45 - 45: IiII + oO0o . iII111i
  if 85 - 85: IiII * IiII * iII111i % i11iIiiIii
  if 22 - 22: I1ii11iIi11i * II111iiii - OOooOOo % i11iIiiIii
  if 10 - 10: OOooOOo / I1ii11iIi11i
  lisp_send_negative_map_reply ( lisp_sockets , O0o00o0Oo , i1I1IIIiII , OOooO , O00O000OO ,
 mr_sport , o0ooo000o00O , Ooo0 , iiI11i1i1 , not_reg_yet = O0oO )
  if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
  return ( [ O0o00o0Oo , i1I1IIIiII , LISP_DDT_ACTION_MS_NOT_REG ] )
  if 48 - 48: O0 / i1IIi / iII111i
  if 11 - 11: O0 - OoO0O00 + OoOoOO00 * ooOoO0o - Ii1I
  if 82 - 82: Ii1I - O0 * ooOoO0o . ooOoO0o
  if 32 - 32: o0oOOo0O0Ooo . OoooooooOO % OOooOOo
  if 2 - 2: OoOoOO00 + I1ii11iIi11i + oO0o
 Iii1IiIII = False
 O0oI11i11 = ""
 O0O0O = False
 if ( Ooo000oOOooO00 . force_nat_proxy_reply ) :
  O0oI11i11 = ", nat-forced"
  Iii1IiIII = ( o0o0Oo00Oo00o == False )
  O0O0O = True
 elif ( Ooo000oOOooO00 . force_proxy_reply ) :
  O0oI11i11 = ", forced"
  O0O0O = True
 elif ( Ooo000oOOooO00 . proxy_reply_requested ) :
  O0oI11i11 = ", requested"
  O0O0O = True
 elif ( map_request . pitr_bit and Ooo000oOOooO00 . pitr_proxy_reply_drop ) :
  O0oI11i11 = ", drop-to-pitr"
  oo0OoooOo0 = LISP_DROP_ACTION
 elif ( Ooo000oOOooO00 . proxy_reply_action != "" ) :
  oo0OoooOo0 = Ooo000oOOooO00 . proxy_reply_action
  O0oI11i11 = ", forced, action {}" . format ( oo0OoooOo0 )
  oo0OoooOo0 = LISP_DROP_ACTION if ( oo0OoooOo0 == "drop" ) else LISP_NATIVE_FORWARD_ACTION
  if 5 - 5: o0oOOo0O0Ooo
  if 95 - 95: iIii1I11I1II1 . OoOoOO00 % i1IIi / O0 * OoOoOO00
  if 29 - 29: oO0o * OoO0O00 . IiII
  if 99 - 99: oO0o
  if 21 - 21: IiII * OoO0O00 / OoooooooOO % o0oOOo0O0Ooo + OoO0O00
  if 25 - 25: IiII % OOooOOo + Ii1I * I1ii11iIi11i
  if 25 - 25: iIii1I11I1II1 * OoOoOO00 % I1IiiI + IiII
 i1iiI1ii = False
 IiiiI11111I1 = None
 if ( O0O0O and Ooo000oOOooO00 . policy in lisp_policies ) :
  ooo0OO0OOooO0 = lisp_policies [ Ooo000oOOooO00 . policy ]
  if ( ooo0OO0OOooO0 . match_policy_map_request ( map_request , mr_source ) ) : IiiiI11111I1 = ooo0OO0OOooO0
  if 96 - 96: iII111i + ooOoO0o
  if ( IiiiI11111I1 ) :
   o0 = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( o0 ,
 ooo0OO0OOooO0 . policy_name , ooo0OO0OOooO0 . set_action ) )
  else :
   o0 = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( o0 ,
 ooo0OO0OOooO0 . policy_name ) )
   i1iiI1ii = True
   if 100 - 100: OOooOOo . ooOoO0o + Ii1I + Ii1I
   if 70 - 70: ooOoO0o . iIii1I11I1II1 / oO0o
   if 18 - 18: Ii1I / OoooooooOO % i1IIi * o0oOOo0O0Ooo
 if ( O0oI11i11 != "" ) :
  lprint ( "Proxy-replying for EID {}, found site '{}' EID-prefix {}{}" . format ( green ( oOOoo , False ) , OooOo0OO , green ( I1iii , False ) ,
  # Ii1I * OoooooooOO * I1ii11iIi11i / O0 * o0oOOo0O0Ooo
 O0oI11i11 ) )
  if 28 - 28: o0oOOo0O0Ooo . o0oOOo0O0Ooo . o0oOOo0O0Ooo
  o0O00ooOo = Ooo000oOOooO00 . registered_rlocs
  o0ooo000o00O = 1440
  if ( Iii1IiIII ) :
   if ( Ooo000oOOooO00 . site_id != 0 ) :
    oo0Oo = map_request . source_eid
    o0O00ooOo = lisp_get_private_rloc_set ( Ooo000oOOooO00 , oo0Oo , i1I1IIIiII )
    if 21 - 21: OoO0O00 - OOooOOo / i11iIiiIii * I1ii11iIi11i * ooOoO0o % Oo0Ooo
   if ( o0O00ooOo == Ooo000oOOooO00 . registered_rlocs ) :
    I1Iii1II = ( Ooo000oOOooO00 . group . is_null ( ) == False )
    IiII11iIIII1 = lisp_get_partial_rloc_set ( o0O00ooOo , O0O0o , I1Iii1II )
    if ( IiII11iIIII1 != o0O00ooOo ) :
     o0ooo000o00O = 15
     o0O00ooOo = IiII11iIIII1
     if 18 - 18: I1IiiI * oO0o / Oo0Ooo / OOooOOo
     if 53 - 53: i1IIi - IiII - OoooooooOO - OOooOOo - OoOoOO00 / IiII
     if 22 - 22: i1IIi + IiII
     if 30 - 30: OoOoOO00
     if 75 - 75: Ii1I . i1IIi / I1IiiI * iII111i . IiII / OoOoOO00
     if 58 - 58: ooOoO0o + OOooOOo / ooOoO0o / i11iIiiIii
     if 95 - 95: ooOoO0o
     if 10 - 10: OoO0O00 % ooOoO0o * o0oOOo0O0Ooo
  if ( Ooo000oOOooO00 . force_ttl != None ) :
   o0ooo000o00O = Ooo000oOOooO00 . force_ttl | 0x80000000
   if 37 - 37: Ii1I . o0oOOo0O0Ooo
   if 34 - 34: ooOoO0o * IiII . Ii1I + iIii1I11I1II1
   if 1 - 1: i11iIiiIii + I11i
   if 78 - 78: Ii1I % Oo0Ooo / OoO0O00 . iIii1I11I1II1 . II111iiii
   if 67 - 67: oO0o % I1Ii111
   if 72 - 72: I1IiiI . i11iIiiIii . OoOoOO00 + I1IiiI - I1Ii111 + iII111i
  if ( IiiiI11111I1 ) :
   if ( IiiiI11111I1 . set_record_ttl ) :
    o0ooo000o00O = IiiiI11111I1 . set_record_ttl
    lprint ( "Policy set-record-ttl to {}" . format ( o0ooo000o00O ) )
    if 15 - 15: I1IiiI
   if ( IiiiI11111I1 . set_action == "drop" ) :
    lprint ( "Policy set-action drop, send negative Map-Reply" )
    oo0OoooOo0 = LISP_POLICY_DENIED_ACTION
    o0O00ooOo = [ ]
   else :
    OO0Oo00oo = IiiiI11111I1 . set_policy_map_reply ( )
    if ( OO0Oo00oo ) : o0O00ooOo = [ OO0Oo00oo ]
    if 88 - 88: IiII / I1ii11iIi11i % I11i + i11iIiiIii * O0 . I1Ii111
    if 69 - 69: Oo0Ooo - OOooOOo / I1IiiI . i11iIiiIii * OoO0O00
    if 45 - 45: I1Ii111 + OOooOOo
  if ( i1iiI1ii ) :
   lprint ( "Implied drop action, send negative Map-Reply" )
   oo0OoooOo0 = LISP_POLICY_DENIED_ACTION
   o0O00ooOo = [ ]
   if 78 - 78: OoOoOO00 . Oo0Ooo % I11i
   if 7 - 7: I1ii11iIi11i % Ii1I . OoooooooOO - iII111i
  iiiIiIIi1 = Ooo000oOOooO00 . echo_nonce_capable
  if 18 - 18: O0 * OoooooooOO % IiII - iIii1I11I1II1 % IiII * o0oOOo0O0Ooo
  if 13 - 13: OoO0O00 + i11iIiiIii + O0 / ooOoO0o % iIii1I11I1II1
  if 75 - 75: oO0o / i1IIi / Ii1I * Oo0Ooo
  if 75 - 75: Oo0Ooo / OoooooooOO
  if ( iiIii ) :
   Ooo0000O = Ooo000oOOooO00 . eid
   iIi111iii = Ooo000oOOooO00 . group
  else :
   Ooo0000O = O0o00o0Oo
   iIi111iii = i1I1IIIiII
   oo0OoooOo0 = LISP_AUTH_FAILURE_ACTION
   o0O00ooOo = [ ]
   if 42 - 42: I1ii11iIi11i . OOooOOo
   if 83 - 83: I1IiiI . ooOoO0o . II111iiii % OOooOOo
   if 86 - 86: i11iIiiIii + I1ii11iIi11i / OoOoOO00 * OoooooooOO
   if 6 - 6: II111iiii
   if 26 - 26: iIii1I11I1II1 / iIii1I11I1II1 . IiII * i11iIiiIii
   if 21 - 21: OOooOOo + o0oOOo0O0Ooo
  if ( iiI11i1i1 ) :
   Ooo0000O = O0o00o0Oo
   iIi111iii = i1I1IIIiII
   if 28 - 28: OOooOOo + i1IIi + II111iiii / Oo0Ooo + iIii1I11I1II1 . Oo0Ooo
   if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
   if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
   if 31 - 31: iIii1I11I1II1 % Oo0Ooo . I1IiiI % ooOoO0o
   if 38 - 38: I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
   if 46 - 46: iII111i
  packet = lisp_build_map_reply ( Ooo0000O , iIi111iii , o0O00ooOo ,
 OOooO , oo0OoooOo0 , o0ooo000o00O , map_request , None , iiiIiIIi1 , False )
  if 56 - 56: Oo0Ooo / II111iiii
  if ( iiI11i1i1 ) :
   lisp_process_pubsub ( lisp_sockets , packet , Ooo0000O , O00O000OO ,
 mr_sport , OOooO , o0ooo000o00O , Ooo0 )
  else :
   lisp_send_map_reply ( lisp_sockets , packet , O00O000OO , mr_sport )
   if 61 - 61: Ii1I - i1IIi / ooOoO0o - Oo0Ooo / IiII % Oo0Ooo
   if 53 - 53: OoooooooOO + iII111i % II111iiii * IiII
  return ( [ Ooo000oOOooO00 . eid , Ooo000oOOooO00 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 10 - 10: OoOoOO00 % I11i
  if 46 - 46: i1IIi % IiII
  if 45 - 45: I1ii11iIi11i / I1ii11iIi11i - OoO0O00
  if 54 - 54: Ii1I + I1IiiI * OoOoOO00 + oO0o
  if 10 - 10: Ii1I - I1IiiI / IiII / iII111i - I1Ii111 - o0oOOo0O0Ooo
 OooO = len ( Ooo000oOOooO00 . registered_rlocs )
 if ( OooO == 0 ) :
  lprint ( ( "Requested EID {} found site '{}' with EID-prefix {} with " + "no registered RLOCs" ) . format ( green ( oOOoo , False ) , OooOo0OO ,
  # iIii1I11I1II1 / ooOoO0o % oO0o / i1IIi / OoOoOO00
 green ( I1iii , False ) ) )
  return ( [ Ooo000oOOooO00 . eid , Ooo000oOOooO00 . group , LISP_DDT_ACTION_MS_ACK ] )
  if 72 - 72: iIii1I11I1II1
  if 69 - 69: OOooOOo - OOooOOo % I1Ii111 + I1ii11iIi11i
  if 39 - 39: OoO0O00 / O0 / o0oOOo0O0Ooo . I1IiiI
  if 100 - 100: I1Ii111 + iIii1I11I1II1 . OoOoOO00 / iII111i . iIii1I11I1II1 - Ii1I
  if 85 - 85: OoOoOO00
 OOOo0OOO = map_request . target_eid if map_request . source_eid . is_null ( ) else map_request . source_eid
 if 64 - 64: I1IiiI % ooOoO0o
 ii1iiIiiiI11 = map_request . target_eid . hash_address ( OOOo0OOO )
 ii1iiIiiiI11 %= OooO
 O0o0 = Ooo000oOOooO00 . registered_rlocs [ ii1iiIiiiI11 ]
 if 22 - 22: o0oOOo0O0Ooo / OoO0O00 + OoOoOO00 + Ii1I . II111iiii * I11i
 if ( O0o0 . rloc . is_null ( ) ) :
  lprint ( ( "Suppress forwarding Map-Request for EID {} at site '{}' " + "EID-prefix {}, no RLOC address" ) . format ( green ( oOOoo , False ) ,
  # I1IiiI / I11i . Ii1I / i11iIiiIii + IiII / iIii1I11I1II1
 OooOo0OO , green ( I1iii , False ) ) )
 else :
  lprint ( ( "Forwarding Map-Request for EID {} to ETR {} at site '{}' " + "EID-prefix {}" ) . format ( green ( oOOoo , False ) ,
  # Ii1I / ooOoO0o + I1ii11iIi11i + OoooooooOO - I11i
 red ( O0o0 . rloc . print_address ( ) , False ) , OooOo0OO ,
 green ( I1iii , False ) ) )
  if 51 - 51: I1IiiI % i1IIi + ooOoO0o / I1ii11iIi11i % iIii1I11I1II1 % IiII
  if 12 - 12: OoOoOO00 * OoO0O00 / IiII - OoO0O00 * o0oOOo0O0Ooo * iII111i
  if 84 - 84: ooOoO0o * OOooOOo / I1Ii111 * I1IiiI * ooOoO0o
  if 75 - 75: oO0o
  lisp_send_ecm ( lisp_sockets , packet , map_request . source_eid , mr_sport ,
 map_request . target_eid , O0o0 . rloc , to_etr = True )
  if 60 - 60: OoOoOO00 % I1IiiI . i11iIiiIii % OoOoOO00 - I1Ii111
 return ( [ Ooo000oOOooO00 . eid , Ooo000oOOooO00 . group , LISP_DDT_ACTION_MS_ACK ] )
 if 71 - 71: OoooooooOO * Oo0Ooo
 if 80 - 80: iIii1I11I1II1
 if 91 - 91: OoOoOO00 + OoOoOO00 + ooOoO0o
 if 44 - 44: I1ii11iIi11i * OOooOOo % OoO0O00 . I1IiiI % Ii1I + II111iiii
 if 100 - 100: oO0o - II111iiii . o0oOOo0O0Ooo
 if 63 - 63: OoOoOO00 % IiII . iII111i
 if 44 - 44: I1IiiI
def lisp_ddt_process_map_request ( lisp_sockets , map_request , ecm_source , port ) :
 if 25 - 25: oO0o
 if 100 - 100: I1IiiI / IiII + OoO0O00 . iII111i
 if 39 - 39: OoooooooOO * OOooOOo - OoO0O00
 if 3 - 3: I11i . i11iIiiIii % Oo0Ooo % II111iiii . I11i
 O0o00o0Oo = map_request . target_eid
 i1I1IIIiII = map_request . target_group
 oOOoo = lisp_print_eid_tuple ( O0o00o0Oo , i1I1IIIiII )
 OOooO = map_request . nonce
 oo0OoooOo0 = LISP_DDT_ACTION_NULL
 if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
 if 72 - 72: ooOoO0o + i11iIiiIii / i1IIi
 if 64 - 64: OOooOOo - OOooOOo
 if 42 - 42: i1IIi / ooOoO0o . I1Ii111 % OoOoOO00
 if 67 - 67: i1IIi * i11iIiiIii * I1IiiI
 i1111I = None
 if ( lisp_i_am_ms ) :
  Ooo000oOOooO00 = lisp_site_eid_lookup ( O0o00o0Oo , i1I1IIIiII , False )
  if ( Ooo000oOOooO00 == None ) : return
  if 30 - 30: OoO0O00 + I1IiiI
  if ( Ooo000oOOooO00 . registered ) :
   oo0OoooOo0 = LISP_DDT_ACTION_MS_ACK
   o0ooo000o00O = 1440
  else :
   O0o00o0Oo , i1I1IIIiII , oo0OoooOo0 = lisp_ms_compute_neg_prefix ( O0o00o0Oo , i1I1IIIiII )
   oo0OoooOo0 = LISP_DDT_ACTION_MS_NOT_REG
   o0ooo000o00O = 1
   if 4 - 4: I11i
 else :
  i1111I = lisp_ddt_cache_lookup ( O0o00o0Oo , i1I1IIIiII , False )
  if ( i1111I == None ) :
   oo0OoooOo0 = LISP_DDT_ACTION_NOT_AUTH
   o0ooo000o00O = 0
   lprint ( "DDT delegation entry not found for EID {}" . format ( green ( oOOoo , False ) ) )
   if 67 - 67: ooOoO0o . I1Ii111 . Oo0Ooo . Ii1I + iIii1I11I1II1 / OoooooooOO
  elif ( i1111I . is_auth_prefix ( ) ) :
   if 93 - 93: ooOoO0o * OoO0O00 - I1Ii111 / I1ii11iIi11i
   if 60 - 60: OoO0O00 / oO0o . I1IiiI + OoOoOO00 + I1ii11iIi11i % Ii1I
   if 70 - 70: i1IIi * II111iiii * I1IiiI
   if 7 - 7: OoooooooOO + II111iiii % o0oOOo0O0Ooo * O0 . OoO0O00 * OoooooooOO
   oo0OoooOo0 = LISP_DDT_ACTION_DELEGATION_HOLE
   o0ooo000o00O = 15
   iI1ii111i1i = i1111I . print_eid_tuple ( )
   lprint ( ( "DDT delegation entry not found but auth-prefix {} " + "found for EID {}" ) . format ( iI1ii111i1i ,
   # IiII / I11i + ooOoO0o - II111iiii . OOooOOo
 green ( oOOoo , False ) ) )
   if 17 - 17: I1ii11iIi11i . Ii1I / IiII - i1IIi - Ii1I
   if ( i1I1IIIiII . is_null ( ) ) :
    O0o00o0Oo = lisp_ddt_compute_neg_prefix ( O0o00o0Oo , i1111I ,
 lisp_ddt_cache )
   else :
    i1I1IIIiII = lisp_ddt_compute_neg_prefix ( i1I1IIIiII , i1111I ,
 lisp_ddt_cache )
    O0o00o0Oo = lisp_ddt_compute_neg_prefix ( O0o00o0Oo , i1111I ,
 i1111I . source_cache )
    if 95 - 95: IiII % I11i % iIii1I11I1II1 . OoO0O00
   i1111I = None
  else :
   iI1ii111i1i = i1111I . print_eid_tuple ( )
   lprint ( "DDT delegation entry {} found for EID {}" . format ( iI1ii111i1i , green ( oOOoo , False ) ) )
   if 11 - 11: i11iIiiIii - IiII . o0oOOo0O0Ooo / IiII - I1IiiI
   o0ooo000o00O = 1440
   if 66 - 66: iIii1I11I1II1 . i1IIi . i11iIiiIii % I1ii11iIi11i * OOooOOo % IiII
   if 34 - 34: I1IiiI % I11i - iII111i - i11iIiiIii - iIii1I11I1II1 / i1IIi
   if 7 - 7: I1IiiI + iIii1I11I1II1 . oO0o
   if 17 - 17: OoO0O00 / OoO0O00 + o0oOOo0O0Ooo / OOooOOo . I1ii11iIi11i % IiII
   if 40 - 40: OoOoOO00
   if 81 - 81: Ii1I % I1Ii111 / I1ii11iIi11i % iII111i
 Oo00O0o0O = lisp_build_map_referral ( O0o00o0Oo , i1I1IIIiII , i1111I , oo0OoooOo0 , o0ooo000o00O , OOooO )
 OOooO = map_request . nonce >> 32
 if ( map_request . nonce != 0 and OOooO != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , Oo00O0o0O , ecm_source , port )
 return
 if 39 - 39: i1IIi . iII111i . Oo0Ooo % Oo0Ooo * IiII % Ii1I
 if 40 - 40: o0oOOo0O0Ooo * i11iIiiIii . ooOoO0o
 if 63 - 63: I1Ii111 / Ii1I - iIii1I11I1II1 / i11iIiiIii / IiII + I11i
 if 57 - 57: iIii1I11I1II1 % iIii1I11I1II1
 if 23 - 23: II111iiii . ooOoO0o % I1Ii111
 if 39 - 39: OoooooooOO
 if 10 - 10: Oo0Ooo * iII111i
 if 78 - 78: Oo0Ooo / i11iIiiIii - I1IiiI
 if 51 - 51: ooOoO0o / Oo0Ooo - I1Ii111 - iII111i
 if 68 - 68: I1ii11iIi11i - iIii1I11I1II1 * OoooooooOO
 if 44 - 44: OoooooooOO + I1Ii111 + OoO0O00
 if 15 - 15: iIii1I11I1II1 % i1IIi + iII111i
 if 48 - 48: o0oOOo0O0Ooo / oO0o
def lisp_find_negative_mask_len ( eid , entry_prefix , neg_prefix ) :
 OO0000 = eid . hash_address ( entry_prefix )
 I111i1I1iii = eid . addr_length ( ) * 8
 iII1IiI1I11i = 0
 if 87 - 87: I11i
 if 67 - 67: i1IIi / i1IIi + IiII . oO0o
 if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
 if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
 for iII1IiI1I11i in range ( I111i1I1iii ) :
  IIIiI = 1 << ( I111i1I1iii - iII1IiI1I11i - 1 )
  if ( OO0000 & IIIiI ) : break
  if 56 - 56: oO0o % I11i + Ii1I
  if 76 - 76: I1Ii111 / iIii1I11I1II1 * I1ii11iIi11i / I1Ii111
 if ( iII1IiI1I11i > neg_prefix . mask_len ) : neg_prefix . mask_len = iII1IiI1I11i
 return
 if 13 - 13: Ii1I + OoOoOO00
 if 77 - 77: OoO0O00 / OoooooooOO + iIii1I11I1II1
 if 81 - 81: O0 + II111iiii * ooOoO0o / i1IIi
 if 38 - 38: Oo0Ooo - OoOoOO00 % IiII % OoooooooOO
 if 79 - 79: II111iiii % OOooOOo / I1ii11iIi11i % Oo0Ooo - o0oOOo0O0Ooo
 if 60 - 60: IiII + ooOoO0o - iII111i
 if 69 - 69: iIii1I11I1II1 + oO0o
 if 16 - 16: OoO0O00 / I11i * OoOoOO00 % OoO0O00 * oO0o * o0oOOo0O0Ooo
 if 80 - 80: o0oOOo0O0Ooo % I11i + O0 % i1IIi
 if 58 - 58: oO0o / I1ii11iIi11i * O0 % I11i
def lisp_neg_prefix_walk ( entry , parms ) :
 O0o00o0Oo , iI1ioOo0O0O , o000O0OO00oOO = parms
 if 3 - 3: I11i
 if ( iI1ioOo0O0O == None ) :
  if ( entry . eid . instance_id != O0o00o0Oo . instance_id ) :
   return ( [ True , parms ] )
   if 18 - 18: I1ii11iIi11i % I1IiiI + I1IiiI / II111iiii + I1ii11iIi11i
  if ( entry . eid . afi != O0o00o0Oo . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( iI1ioOo0O0O ) == False ) :
   return ( [ True , parms ] )
   if 76 - 76: OOooOOo
   if 45 - 45: ooOoO0o % o0oOOo0O0Ooo . II111iiii . I1Ii111
   if 52 - 52: OoooooooOO / IiII / IiII
   if 30 - 30: ooOoO0o % I11i + II111iiii . IiII - I1IiiI * OoOoOO00
   if 59 - 59: I1IiiI
   if 19 - 19: i1IIi * I1Ii111
 lisp_find_negative_mask_len ( O0o00o0Oo , entry . eid , o000O0OO00oOO )
 return ( [ True , parms ] )
 if 33 - 33: OOooOOo + OoOoOO00 % I1Ii111 / iIii1I11I1II1 % Ii1I % o0oOOo0O0Ooo
 if 49 - 49: OOooOOo
 if 1 - 1: I1ii11iIi11i - OoOoOO00 / oO0o + OoooooooOO % o0oOOo0O0Ooo
 if 96 - 96: ooOoO0o * OoOoOO00 - II111iiii
 if 40 - 40: oO0o * OOooOOo + Ii1I + I11i * Ii1I + OoooooooOO
 if 77 - 77: OOooOOo + ooOoO0o / O0
 if 16 - 16: ooOoO0o + Oo0Ooo * Oo0Ooo . I11i - IiII
 if 49 - 49: ooOoO0o . Ii1I
def lisp_ddt_compute_neg_prefix ( eid , ddt_entry , cache ) :
 if 75 - 75: OOooOOo / II111iiii - Oo0Ooo + I1Ii111
 if 42 - 42: OoooooooOO * II111iiii + Ii1I % OoO0O00 / I1Ii111
 if 11 - 11: ooOoO0o / Oo0Ooo + i1IIi / IiII
 if 4 - 4: iII111i - Oo0Ooo
 if ( eid . is_binary ( ) == False ) : return ( eid )
 if 100 - 100: OOooOOo . i1IIi
 o000O0OO00oOO = lisp_address ( eid . afi , "" , 0 , 0 )
 o000O0OO00oOO . copy_address ( eid )
 o000O0OO00oOO . mask_len = 0
 if 15 - 15: O0 % Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o * iII111i % O0
 IiIO000 = ddt_entry . print_eid_tuple ( )
 iI1ioOo0O0O = ddt_entry . eid
 if 100 - 100: Oo0Ooo - I1Ii111 . Ii1I * I1ii11iIi11i
 if 59 - 59: OoOoOO00 + Oo0Ooo . I1ii11iIi11i - Ii1I
 if 48 - 48: I1Ii111 % Ii1I + I1IiiI * OoooooooOO % OoOoOO00 % i11iIiiIii
 if 13 - 13: iII111i % i1IIi
 if 13 - 13: iII111i / OoooooooOO + Ii1I / iII111i
 eid , iI1ioOo0O0O , o000O0OO00oOO = cache . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , iI1ioOo0O0O , o000O0OO00oOO ) )
 if 29 - 29: OOooOOo + ooOoO0o % o0oOOo0O0Ooo
 if 18 - 18: I11i + OoO0O00 + OoO0O00 . ooOoO0o
 if 37 - 37: i1IIi . IiII + I1IiiI % OoOoOO00
 if 3 - 3: i11iIiiIii + Ii1I % IiII - I1Ii111 / Oo0Ooo % iIii1I11I1II1
 o000O0OO00oOO . mask_address ( o000O0OO00oOO . mask_len )
 if 86 - 86: Oo0Ooo + Oo0Ooo * oO0o * I1IiiI
 lprint ( ( "Least specific prefix computed from ddt-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # OOooOOo + OoOoOO00 * OOooOOo + OoOoOO00 / o0oOOo0O0Ooo . iIii1I11I1II1
 IiIO000 , o000O0OO00oOO . print_prefix ( ) ) )
 return ( o000O0OO00oOO )
 if 1 - 1: I1Ii111 * i11iIiiIii % I1Ii111 - OoO0O00 + I1Ii111 / Oo0Ooo
 if 3 - 3: OOooOOo - i11iIiiIii / I1Ii111 . OOooOOo - OoO0O00
 if 60 - 60: OoOoOO00 / i1IIi . Ii1I - OoO0O00 - OoooooooOO
 if 39 - 39: I1IiiI + i1IIi * OoO0O00 % I11i
 if 41 - 41: I1ii11iIi11i * IiII
 if 16 - 16: I1Ii111 % iIii1I11I1II1 / I1IiiI * OoOoOO00 / IiII / OoOoOO00
 if 29 - 29: OoooooooOO / oO0o
 if 1 - 1: OoOoOO00 . i11iIiiIii % I1Ii111 + OoooooooOO - Oo0Ooo . I1ii11iIi11i
def lisp_ms_compute_neg_prefix ( eid , group ) :
 o000O0OO00oOO = lisp_address ( eid . afi , "" , 0 , 0 )
 o000O0OO00oOO . copy_address ( eid )
 o000O0OO00oOO . mask_len = 0
 IiI1ii = lisp_address ( group . afi , "" , 0 , 0 )
 IiI1ii . copy_address ( group )
 IiI1ii . mask_len = 0
 iI1ioOo0O0O = None
 if 56 - 56: ooOoO0o / OoO0O00 / i1IIi
 if 45 - 45: OoOoOO00 + I11i / I1IiiI % OOooOOo
 if 37 - 37: iIii1I11I1II1
 if 64 - 64: II111iiii * oO0o % I1Ii111 + i1IIi
 if 57 - 57: OoOoOO00 + OoOoOO00
 if ( group . is_null ( ) ) :
  i1111I = lisp_ddt_cache . lookup_cache ( eid , False )
  if ( i1111I == None ) :
   o000O0OO00oOO . mask_len = o000O0OO00oOO . host_mask_len ( )
   IiI1ii . mask_len = IiI1ii . host_mask_len ( )
   return ( [ o000O0OO00oOO , IiI1ii , LISP_DDT_ACTION_NOT_AUTH ] )
   if 24 - 24: i1IIi . OoOoOO00 / I1Ii111 + O0
  O00OOO00o00o0 = lisp_sites_by_eid
  if ( i1111I . is_auth_prefix ( ) ) : iI1ioOo0O0O = i1111I . eid
 else :
  i1111I = lisp_ddt_cache . lookup_cache ( group , False )
  if ( i1111I == None ) :
   o000O0OO00oOO . mask_len = o000O0OO00oOO . host_mask_len ( )
   IiI1ii . mask_len = IiI1ii . host_mask_len ( )
   return ( [ o000O0OO00oOO , IiI1ii , LISP_DDT_ACTION_NOT_AUTH ] )
   if 92 - 92: II111iiii . I11i
  if ( i1111I . is_auth_prefix ( ) ) : iI1ioOo0O0O = i1111I . group
  if 44 - 44: II111iiii - I1ii11iIi11i / I1ii11iIi11i
  group , iI1ioOo0O0O , IiI1ii = lisp_sites_by_eid . walk_cache ( lisp_neg_prefix_walk , ( group , iI1ioOo0O0O , IiI1ii ) )
  if 28 - 28: iIii1I11I1II1 / IiII - iIii1I11I1II1 . i1IIi - O0 * ooOoO0o
  if 41 - 41: Ii1I + IiII
  IiI1ii . mask_address ( IiI1ii . mask_len )
  if 37 - 37: I1Ii111 / o0oOOo0O0Ooo - ooOoO0o - OoooooooOO . I1ii11iIi11i % I1Ii111
  lprint ( ( "Least specific prefix computed from site-cache for " + "group EID {} using auth-prefix {} is {}" ) . format ( group . print_address ( ) , iI1ioOo0O0O . print_prefix ( ) if ( iI1ioOo0O0O != None ) else "'not found'" ,
  # Ii1I - OoOoOO00 / I1ii11iIi11i - Ii1I
  # OoOoOO00 * i1IIi * OoOoOO00 - oO0o / o0oOOo0O0Ooo
  # Oo0Ooo + i11iIiiIii
 IiI1ii . print_prefix ( ) ) )
  if 50 - 50: iII111i + ooOoO0o * Ii1I % OOooOOo
  O00OOO00o00o0 = i1111I . source_cache
  if 30 - 30: OoO0O00 - Oo0Ooo . IiII * ooOoO0o % OOooOOo % i11iIiiIii
  if 45 - 45: I1Ii111 / OoO0O00
  if 15 - 15: Oo0Ooo + oO0o . I11i % OoO0O00
  if 13 - 13: I1ii11iIi11i / ooOoO0o * I1Ii111
  if 45 - 45: I1ii11iIi11i - I11i
 oo0OoooOo0 = LISP_DDT_ACTION_DELEGATION_HOLE if ( iI1ioOo0O0O != None ) else LISP_DDT_ACTION_NOT_AUTH
 if 60 - 60: OOooOOo - OOooOOo * OoOoOO00 / Ii1I % iII111i % Oo0Ooo
 if 75 - 75: iIii1I11I1II1 - IiII - I1Ii111
 if 4 - 4: i11iIiiIii % OoooooooOO . i11iIiiIii
 if 61 - 61: iIii1I11I1II1 . Oo0Ooo . i1IIi
 if 45 - 45: I1Ii111
 if 49 - 49: i1IIi * iII111i - iIii1I11I1II1 % I11i * O0 / OoOoOO00
 eid , iI1ioOo0O0O , o000O0OO00oOO = O00OOO00o00o0 . walk_cache ( lisp_neg_prefix_walk ,
 ( eid , iI1ioOo0O0O , o000O0OO00oOO ) )
 if 48 - 48: IiII
 if 69 - 69: o0oOOo0O0Ooo % i11iIiiIii - OOooOOo - o0oOOo0O0Ooo
 if 98 - 98: o0oOOo0O0Ooo * OoO0O00 . OoooooooOO
 if 40 - 40: I1Ii111 + Oo0Ooo + I1Ii111
 o000O0OO00oOO . mask_address ( o000O0OO00oOO . mask_len )
 if 57 - 57: I1Ii111 / II111iiii % iII111i
 lprint ( ( "Least specific prefix computed from site-cache for EID {} " + "using auth-prefix {} is {}" ) . format ( green ( eid . print_address ( ) , False ) ,
 # oO0o % IiII
 # Oo0Ooo - i11iIiiIii . I1IiiI
 iI1ioOo0O0O . print_prefix ( ) if ( iI1ioOo0O0O != None ) else "'not found'" , o000O0OO00oOO . print_prefix ( ) ) )
 if 83 - 83: I11i - i11iIiiIii - I1IiiI - OoO0O00 / i1IIi
 if 49 - 49: OoOoOO00 + iIii1I11I1II1
 return ( [ o000O0OO00oOO , IiI1ii , oo0OoooOo0 ] )
 if 53 - 53: I1Ii111
 if 2 - 2: Ii1I + I11i
 if 94 - 94: OoO0O00 / i11iIiiIii
 if 68 - 68: iIii1I11I1II1 % Oo0Ooo + Oo0Ooo
 if 44 - 44: I11i / OoO0O00
 if 66 - 66: i11iIiiIii
 if 83 - 83: I1Ii111 / iIii1I11I1II1 - oO0o
 if 3 - 3: OOooOOo - Oo0Ooo * I1IiiI - OoO0O00 / OOooOOo + IiII
def lisp_ms_send_map_referral ( lisp_sockets , map_request , ecm_source , port ,
 action , eid_prefix , group_prefix ) :
 if 83 - 83: i1IIi * i1IIi - II111iiii / OoooooooOO . Ii1I + I1Ii111
 O0o00o0Oo = map_request . target_eid
 i1I1IIIiII = map_request . target_group
 OOooO = map_request . nonce
 if 10 - 10: I11i
 if ( action == LISP_DDT_ACTION_MS_ACK ) : o0ooo000o00O = 1440
 if 24 - 24: Ii1I
 if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
 if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
 if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
 oOooOO0OO = lisp_map_referral ( )
 oOooOO0OO . record_count = 1
 oOooOO0OO . nonce = OOooO
 Oo00O0o0O = oOooOO0OO . encode ( )
 oOooOO0OO . print_map_referral ( )
 if 6 - 6: i1IIi * i11iIiiIii + ooOoO0o - IiII
 iiIIi = False
 if 97 - 97: iIii1I11I1II1 * i1IIi * II111iiii - OOooOOo - Oo0Ooo - iIii1I11I1II1
 if 26 - 26: ooOoO0o + Oo0Ooo
 if 24 - 24: I1IiiI
 if 43 - 43: OoO0O00
 if 51 - 51: OoooooooOO % IiII % Oo0Ooo
 if 50 - 50: I1IiiI - i11iIiiIii / I1ii11iIi11i . Ii1I - iIii1I11I1II1
 if ( action == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( O0o00o0Oo ,
 i1I1IIIiII )
  o0ooo000o00O = 15
  if 91 - 91: I1IiiI . I1Ii111 + II111iiii . Oo0Ooo
 if ( action == LISP_DDT_ACTION_MS_NOT_REG ) : o0ooo000o00O = 1
 if ( action == LISP_DDT_ACTION_MS_ACK ) : o0ooo000o00O = 1440
 if ( action == LISP_DDT_ACTION_DELEGATION_HOLE ) : o0ooo000o00O = 15
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : o0ooo000o00O = 0
 if 95 - 95: iII111i
 oo0oooo00OOO = False
 OooO = 0
 i1111I = lisp_ddt_cache_lookup ( O0o00o0Oo , i1I1IIIiII , False )
 if ( i1111I != None ) :
  OooO = len ( i1111I . delegation_set )
  oo0oooo00OOO = i1111I . is_ms_peer_entry ( )
  i1111I . map_referrals_sent += 1
  if 80 - 80: ooOoO0o / OOooOOo / Ii1I * i1IIi . I11i
  if 47 - 47: I1ii11iIi11i
  if 49 - 49: OoooooooOO . OoooooooOO - i1IIi
  if 40 - 40: IiII . iII111i
  if 68 - 68: iII111i
 if ( action == LISP_DDT_ACTION_NOT_AUTH ) : iiIIi = True
 if ( action in ( LISP_DDT_ACTION_MS_REFERRAL , LISP_DDT_ACTION_MS_ACK ) ) :
  iiIIi = ( oo0oooo00OOO == False )
  if 29 - 29: II111iiii / II111iiii % OoO0O00 % Oo0Ooo . II111iiii
  if 33 - 33: OoooooooOO . OoO0O00 % OoooooooOO
  if 9 - 9: IiII * O0 + OOooOOo . II111iiii
  if 14 - 14: iIii1I11I1II1 + i11iIiiIii + o0oOOo0O0Ooo + o0oOOo0O0Ooo - IiII / I1Ii111
  if 70 - 70: OoooooooOO + I1IiiI / OOooOOo
 oooO = lisp_eid_record ( )
 oooO . rloc_count = OooO
 oooO . authoritative = True
 oooO . action = action
 oooO . ddt_incomplete = iiIIi
 oooO . eid = eid_prefix
 oooO . group = group_prefix
 oooO . record_ttl = o0ooo000o00O
 if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
 Oo00O0o0O += oooO . encode ( )
 oooO . print_record ( "  " , True )
 if 16 - 16: I1Ii111 + II111iiii + IiII
 if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
 if 46 - 46: ooOoO0o % II111iiii
 if 61 - 61: OoO0O00 . I1IiiI
 if ( OooO != 0 ) :
  for iii in i1111I . delegation_set :
   ooO0 = lisp_rloc_record ( )
   ooO0 . rloc = iii . delegate_address
   ooO0 . priority = iii . priority
   ooO0 . weight = iii . weight
   ooO0 . mpriority = 255
   ooO0 . mweight = 0
   ooO0 . reach_bit = True
   Oo00O0o0O += ooO0 . encode ( )
   ooO0 . print_record ( "    " )
   if 89 - 89: IiII
   if 73 - 73: II111iiii + ooOoO0o % OOooOOo . oO0o / oO0o * i1IIi
   if 19 - 19: I1Ii111 + I11i
   if 21 - 21: OoOoOO00
   if 2 - 2: i1IIi . OOooOOo
   if 23 - 23: Ii1I - OOooOOo
   if 89 - 89: i11iIiiIii
 if ( map_request . nonce != 0 ) : port = LISP_CTRL_PORT
 lisp_send_map_referral ( lisp_sockets , Oo00O0o0O , ecm_source , port )
 return
 if 40 - 40: OoooooooOO % OoO0O00
 if 54 - 54: i1IIi * OOooOOo - oO0o * OoooooooOO + II111iiii . IiII
 if 90 - 90: O0 - II111iiii + I1IiiI . iII111i
 if 3 - 3: o0oOOo0O0Ooo + i1IIi * Oo0Ooo
 if 6 - 6: OoO0O00 * OoooooooOO * iIii1I11I1II1
 if 87 - 87: iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1
 if 79 - 79: ooOoO0o . oO0o + Ii1I * ooOoO0o + O0 . II111iiii
 if 8 - 8: IiII * OOooOOo + I11i + O0 * oO0o - oO0o
def lisp_send_negative_map_reply ( sockets , eid , group , nonce , dest , port , ttl ,
 xtr_id , pubsub , not_reg_yet = False ) :
 if 19 - 19: OoO0O00 - ooOoO0o + I1ii11iIi11i / I1ii11iIi11i % I1Ii111 % iIii1I11I1II1
 lprint ( "Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}" . format ( lisp_print_eid_tuple ( eid , group ) , lisp_hex_string ( nonce ) ,
 # ooOoO0o
 red ( dest . print_address ( ) , False ) ) )
 if 48 - 48: ooOoO0o - O0
 oo0OoooOo0 = LISP_NATIVE_FORWARD_ACTION if group . is_null ( ) else LISP_DROP_ACTION
 if 29 - 29: oO0o . oO0o
 if 96 - 96: O0
 if 85 - 85: Oo0Ooo + i11iIiiIii . OOooOOo / II111iiii / iII111i
 if 90 - 90: o0oOOo0O0Ooo - OoooooooOO - i1IIi
 if 47 - 47: I1Ii111 * Ii1I . iIii1I11I1II1 / OoOoOO00
 if ( lisp_get_eid_hash ( eid ) != None ) :
  oo0OoooOo0 = LISP_SEND_MAP_REQUEST_ACTION
  if 68 - 68: i11iIiiIii / OOooOOo / I1ii11iIi11i % IiII * IiII + II111iiii
 if ( not_reg_yet ) :
  oo0OoooOo0 = LISP_NOT_REGISTERED_YET_ACTION
  if 65 - 65: I1IiiI + OoOoOO00 - OoOoOO00 . oO0o
  if 84 - 84: Ii1I * i1IIi
  if 42 - 42: OoOoOO00 - ooOoO0o + oO0o - II111iiii
 Oo00O0o0O = lisp_build_map_reply ( eid , group , [ ] , nonce , oo0OoooOo0 , ttl , None ,
 None , False , False )
 if 92 - 92: Oo0Ooo - I11i . ooOoO0o % oO0o
 if 6 - 6: iIii1I11I1II1 + oO0o
 if 8 - 8: I1ii11iIi11i + o0oOOo0O0Ooo
 if 29 - 29: Ii1I . OOooOOo
 if ( pubsub ) :
  lisp_process_pubsub ( sockets , Oo00O0o0O , eid , dest , port , nonce , ttl ,
 xtr_id )
 else :
  lisp_send_map_reply ( sockets , Oo00O0o0O , dest , port )
  if 59 - 59: O0 . OoO0O00
 return
 if 10 - 10: I1Ii111 / OoooooooOO / OoO0O00 * ooOoO0o
 if 81 - 81: i1IIi % I11i * iIii1I11I1II1
 if 39 - 39: iIii1I11I1II1 / O0 . OoooooooOO - O0 . OoO0O00 . oO0o
 if 59 - 59: II111iiii * I1IiiI
 if 12 - 12: i11iIiiIii - IiII . iII111i . Ii1I
 if 34 - 34: i1IIi % iII111i + Oo0Ooo * OoOoOO00 + OoO0O00
 if 37 - 37: I1Ii111 / OoooooooOO
def lisp_retransmit_ddt_map_request ( mr ) :
 I1IiIiIi = mr . mr_source . print_address ( )
 OOOooo = mr . print_eid_tuple ( )
 OOooO = mr . nonce
 if 48 - 48: iIii1I11I1II1 / OOooOOo + I1Ii111
 if 85 - 85: Ii1I % ooOoO0o . I1IiiI
 if 47 - 47: I1Ii111 - I1ii11iIi11i * OoO0O00 % IiII % ooOoO0o . I1IiiI
 if 96 - 96: II111iiii
 if 73 - 73: II111iiii
 if ( mr . last_request_sent_to ) :
  ooOo00 = mr . last_request_sent_to . print_address ( )
  I11i1iI = lisp_referral_cache_lookup ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] , True )
  if ( I11i1iI and ooOo00 in I11i1iI . referral_set ) :
   I11i1iI . referral_set [ ooOo00 ] . no_responses += 1
   if 60 - 60: OOooOOo * o0oOOo0O0Ooo
   if 48 - 48: i11iIiiIii / ooOoO0o . OoOoOO00 . O0 * i11iIiiIii
   if 11 - 11: iIii1I11I1II1 . i1IIi . O0 / ooOoO0o
   if 64 - 64: i11iIiiIii + I1IiiI / Oo0Ooo - iII111i
   if 26 - 26: I1ii11iIi11i
   if 67 - 67: I1Ii111 * iIii1I11I1II1 / O0 + OoO0O00 * iIii1I11I1II1 % II111iiii
   if 13 - 13: Ii1I / ooOoO0o / iII111i % II111iiii * I1IiiI * II111iiii
 if ( mr . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( OOOooo , False ) , lisp_hex_string ( OOooO ) ) )
  if 40 - 40: Ii1I / i1IIi . iII111i
  mr . dequeue_map_request ( )
  return
  if 65 - 65: iIii1I11I1II1 * O0 . II111iiii * o0oOOo0O0Ooo . I1ii11iIi11i * I1IiiI
  if 63 - 63: II111iiii . Oo0Ooo % iIii1I11I1II1
 mr . retry_count += 1
 if 85 - 85: I1IiiI + i1IIi % I1Ii111
 OOo0oOO0o0oo0 = green ( I1IiIiIi , False )
 oooOo = green ( OOOooo , False )
 lprint ( "Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( bold ( "Map-Request" , False ) , "P" if mr . from_pitr else "" ,
 # Ii1I / i11iIiiIii . iII111i / OOooOOo . i1IIi
 red ( mr . itr . print_address ( ) , False ) , OOo0oOO0o0oo0 , oooOo ,
 lisp_hex_string ( OOooO ) ) )
 if 99 - 99: i1IIi . oO0o % Ii1I % Ii1I - OoOoOO00 . I1ii11iIi11i
 if 69 - 69: I1ii11iIi11i - I1IiiI % O0 % I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 . OOooOOo
 if 64 - 64: OoOoOO00 - i1IIi * i1IIi / iII111i * OoOoOO00 * OoO0O00
 lisp_send_ddt_map_request ( mr , False )
 if 61 - 61: OOooOOo
 if 51 - 51: Oo0Ooo * OOooOOo / iII111i
 if 49 - 49: ooOoO0o . i1IIi % I1Ii111 . I1IiiI . I1ii11iIi11i + OoO0O00
 if 65 - 65: I1ii11iIi11i + Ii1I / i11iIiiIii * I1Ii111 + OoooooooOO
 mr . retransmit_timer = threading . Timer ( LISP_DDT_MAP_REQUEST_INTERVAL ,
 lisp_retransmit_ddt_map_request , [ mr ] )
 mr . retransmit_timer . start ( )
 return
 if 7 - 7: Oo0Ooo % o0oOOo0O0Ooo
 if 40 - 40: oO0o * IiII
 if 29 - 29: O0 - II111iiii + iII111i
 if 73 - 73: I1Ii111 - I11i + IiII - o0oOOo0O0Ooo - I11i - OOooOOo
 if 40 - 40: iIii1I11I1II1 . iII111i * I1ii11iIi11i + IiII - iIii1I11I1II1
 if 83 - 83: i1IIi
 if 9 - 9: iIii1I11I1II1 + i11iIiiIii
 if 70 - 70: I1IiiI - OoO0O00 % OOooOOo + ooOoO0o % II111iiii
def lisp_get_referral_node ( referral , source_eid , dest_eid ) :
 if 19 - 19: I11i + i1IIi / i1IIi - II111iiii + I1Ii111
 if 11 - 11: i11iIiiIii % i11iIiiIii / IiII - Oo0Ooo / O0 - I11i
 if 29 - 29: OOooOOo * iIii1I11I1II1 * ooOoO0o
 if 80 - 80: oO0o * I1Ii111
 O00OO0 = [ ]
 for oooOOo0o00 in list ( referral . referral_set . values ( ) ) :
  if ( oooOOo0o00 . updown == False ) : continue
  if ( len ( O00OO0 ) == 0 or O00OO0 [ 0 ] . priority == oooOOo0o00 . priority ) :
   O00OO0 . append ( oooOOo0o00 )
  elif ( O00OO0 [ 0 ] . priority > oooOOo0o00 . priority ) :
   O00OO0 = [ ]
   O00OO0 . append ( oooOOo0o00 )
   if 8 - 8: I1IiiI . IiII . OOooOOo . O0
   if 3 - 3: Ii1I + i11iIiiIii
   if 87 - 87: ooOoO0o - iII111i % I11i
 o0oO0Oo00o0 = len ( O00OO0 )
 if ( o0oO0Oo00o0 == 0 ) : return ( None )
 if 77 - 77: iII111i / OoOoOO00 . ooOoO0o * I1ii11iIi11i
 ii1iiIiiiI11 = dest_eid . hash_address ( source_eid )
 ii1iiIiiiI11 = ii1iiIiiiI11 % o0oO0Oo00o0
 return ( O00OO0 [ ii1iiIiiiI11 ] )
 if 44 - 44: OoooooooOO + ooOoO0o / I1Ii111 + I1ii11iIi11i
 if 15 - 15: oO0o - i1IIi % iIii1I11I1II1 . i1IIi
 if 93 - 93: I11i / Ii1I - o0oOOo0O0Ooo % oO0o / OoO0O00 * I11i
 if 24 - 24: i1IIi
 if 21 - 21: II111iiii
 if 27 - 27: I1IiiI * i11iIiiIii
 if 86 - 86: I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - i1IIi . I11i / OOooOOo
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 ooOo0o00 = mr . lisp_sockets
 OOooO = mr . nonce
 oo000oo0oOo0 = mr . itr
 oOoOOOO0O = mr . mr_source
 oOOoo = mr . print_eid_tuple ( )
 if 30 - 30: I1Ii111 * i1IIi
 if 4 - 4: OoO0O00 + O0 * OOooOOo * I1Ii111 / O0
 if 58 - 58: OOooOOo % ooOoO0o * I1IiiI - I1ii11iIi11i / I11i + iII111i
 if 26 - 26: OoOoOO00
 if 63 - 63: I1Ii111 . oO0o + OoO0O00 / I1ii11iIi11i % IiII * II111iiii
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( oOOoo , False ) , lisp_hex_string ( OOooO ) ) )
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
  lprint ( "Jumping up to root for EID {}" . format ( green ( oOOoo , False ) ) )
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
 OOooO , oo000oo0oOo0 , mr . sport , 15 , None , False )
  return
  if 68 - 68: i11iIiiIii / I1IiiI / i11iIiiIii
  if 87 - 87: OoOoOO00 . OoO0O00 . I1Ii111 / Ii1I + Oo0Ooo % OoooooooOO
 O000ooOOo = OoOo00OoOo . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( O000ooOOo ,
 OoOo00OoOo . print_referral_type ( ) ) )
 if 37 - 37: o0oOOo0O0Ooo . II111iiii * II111iiii - oO0o % Ii1I - II111iiii
 oooOOo0o00 = lisp_get_referral_node ( OoOo00OoOo , oOoOOOO0O , mr . eid )
 if ( oooOOo0o00 == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( ooOo0o00 , OoOo00OoOo . eid ,
 OoOo00OoOo . group , OOooO , oo000oo0oOo0 , mr . sport , 1 , None , False )
  return
  if 31 - 31: OoooooooOO - O0 * Ii1I . OoO0O00 / I1Ii111 . OOooOOo
  if 28 - 28: iII111i % I1ii11iIi11i . I11i
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( oooOOo0o00 . referral_address . print_address ( ) ,
 # I11i - II111iiii
 OoOo00OoOo . print_referral_type ( ) , green ( oOOoo , False ) ,
 lisp_hex_string ( OOooO ) ) )
 if 84 - 84: I1ii11iIi11i * IiII / I1IiiI - Ii1I + IiII - i1IIi
 if 98 - 98: II111iiii - iII111i % i11iIiiIii + ooOoO0o
 if 76 - 76: OOooOOo - iII111i + IiII
 if 48 - 48: I1IiiI - II111iiii
 iIiII1I1Ii = ( OoOo00OoOo . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 OoOo00OoOo . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( ooOo0o00 , mr . packet , oOoOOOO0O , mr . sport , mr . eid ,
 oooOOo0o00 . referral_address , to_ms = iIiII1I1Ii , ddt = True )
 if 62 - 62: IiII - iII111i . I1ii11iIi11i . oO0o
 if 22 - 22: OoOoOO00 * i11iIiiIii * Ii1I
 if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
 if 5 - 5: OoO0O00 / ooOoO0o
 mr . last_request_sent_to = oooOOo0o00 . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 oooOOo0o00 . map_requests_sent += 1
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
 O0o00o0Oo = map_request . target_eid
 i1I1IIIiII = map_request . target_group
 OOOooo = map_request . print_eid_tuple ( )
 I1IiIiIi = mr_source . print_address ( )
 OOooO = map_request . nonce
 if 14 - 14: II111iiii + I1ii11iIi11i * Oo0Ooo
 OOo0oOO0o0oo0 = green ( I1IiIiIi , False )
 oooOo = green ( OOOooo , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # I1IiiI + OOooOOo * I1IiiI % i11iIiiIii / O0 + OoO0O00
 red ( ecm_source . print_address ( ) , False ) , OOo0oOO0o0oo0 , oooOo ,
 lisp_hex_string ( OOooO ) ) )
 if 48 - 48: oO0o
 if 15 - 15: OOooOOo
 if 3 - 3: i1IIi
 if 85 - 85: i11iIiiIii % i1IIi
 o0O0 = lisp_ddt_map_request ( lisp_sockets , packet , O0o00o0Oo , i1I1IIIiII , OOooO )
 o0O0 . packet = packet
 o0O0 . itr = ecm_source
 o0O0 . mr_source = mr_source
 o0O0 . sport = sport
 o0O0 . from_pitr = map_request . pitr_bit
 o0O0 . queue_map_request ( )
 if 76 - 76: I1ii11iIi11i / O0
 lisp_send_ddt_map_request ( o0O0 , False )
 return
 if 38 - 38: oO0o + oO0o . iII111i / OoO0O00
 if 27 - 27: o0oOOo0O0Ooo * I1ii11iIi11i
 if 100 - 100: I1Ii111 / O0 - iIii1I11I1II1 . iII111i % I1Ii111 - ooOoO0o
 if 100 - 100: OoO0O00 + I1ii11iIi11i + I1ii11iIi11i . I1Ii111
 if 83 - 83: OoOoOO00 / OOooOOo * II111iiii * OoooooooOO
 if 51 - 51: OoOoOO00 + o0oOOo0O0Ooo / Ii1I
 if 6 - 6: I11i % IiII
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 48 - 48: Ii1I
 I11I = packet
 OOO0ooOOo0O = lisp_map_request ( )
 packet = OOO0ooOOo0O . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 31 - 31: OOooOOo - ooOoO0o . Ii1I % IiII + I11i
  if 88 - 88: IiII % OoooooooOO . OoO0O00 - OoooooooOO
 OOO0ooOOo0O . print_map_request ( )
 if 49 - 49: Oo0Ooo % oO0o
 if 6 - 6: Oo0Ooo
 if 88 - 88: IiII - Oo0Ooo * I11i / I1IiiI . i1IIi
 if 67 - 67: i11iIiiIii
 if ( OOO0ooOOo0O . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , OOO0ooOOo0O , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 3 - 3: IiII
  if 47 - 47: O0
  if 60 - 60: OOooOOo / ooOoO0o + Oo0Ooo / O0 - oO0o
  if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
  if 4 - 4: I1IiiI
 if ( OOO0ooOOo0O . smr_bit ) :
  lisp_process_smr ( OOO0ooOOo0O )
  if 31 - 31: ooOoO0o * i1IIi . O0
  if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
  if 100 - 100: I1Ii111
  if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
  if 88 - 88: IiII
 if ( OOO0ooOOo0O . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( OOO0ooOOo0O )
  if 29 - 29: iII111i . ooOoO0o
  if 62 - 62: IiII
  if 95 - 95: ooOoO0o / i1IIi + II111iiii + OoO0O00 % OoO0O00
  if 18 - 18: ooOoO0o * I1IiiI / iII111i % iII111i
  if 9 - 9: i11iIiiIii % ooOoO0o % O0 + i1IIi / O0
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , OOO0ooOOo0O , mr_source ,
 mr_port , ttl , timestamp )
  if 12 - 12: I1Ii111 - iII111i * iII111i + OoO0O00 . Ii1I % I11i
  if 28 - 28: ooOoO0o % OoO0O00 - II111iiii * IiII - I1IiiI + I1IiiI
  if 84 - 84: IiII / Ii1I
  if 39 - 39: OOooOOo - iIii1I11I1II1 + OoOoOO00 % IiII * OoooooooOO % Ii1I
  if 11 - 11: I1ii11iIi11i
 if ( lisp_i_am_ms ) :
  packet = I11I
  O0o00o0Oo , i1I1IIIiII , o0i1i1iiI = lisp_ms_process_map_request ( lisp_sockets ,
 I11I , OOO0ooOOo0O , mr_source , mr_port , ecm_source , ecm_port )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , OOO0ooOOo0O , ecm_source ,
 ecm_port , o0i1i1iiI , O0o00o0Oo , i1I1IIIiII )
   if 55 - 55: i11iIiiIii / II111iiii / I1Ii111 * iIii1I11I1II1 / II111iiii * iIii1I11I1II1
  return
  if 41 - 41: o0oOOo0O0Ooo . iII111i % iII111i . OOooOOo / OOooOOo
  if 98 - 98: II111iiii + ooOoO0o - iIii1I11I1II1 . I11i . iIii1I11I1II1 - iIii1I11I1II1
  if 91 - 91: ooOoO0o
  if 66 - 66: OOooOOo
  if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , I11I , OOO0ooOOo0O ,
 ecm_source , mr_port , mr_source )
  if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
  if 9 - 9: Ii1I
  if 44 - 44: iII111i
  if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
  if 37 - 37: OoO0O00 - Ii1I + OoO0O00
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = I11I
  lisp_ddt_process_map_request ( lisp_sockets , OOO0ooOOo0O , ecm_source ,
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
 o0O0 = lisp_get_map_resolver ( source , None )
 if ( o0O0 == None ) : return
 if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
 if 38 - 38: iII111i * OoooooooOO - IiII
 if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
 if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
 o0O0 . neg_map_replies_received += 1
 o0O0 . last_reply = lisp_get_timestamp ( )
 if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
 if 76 - 76: I11i . I1IiiI
 if 66 - 66: oO0o % oO0o * IiII
 if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
 if ( ( o0O0 . neg_map_replies_received % 100 ) == 0 ) : o0O0 . total_rtt = 0
 if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
 if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
 if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
 if ( o0O0 . last_nonce == nonce ) :
  o0O0 . total_rtt += ( time . time ( ) - o0O0 . last_used )
  o0O0 . last_nonce = 0
  if 23 - 23: OOooOOo
 if ( ( o0O0 . neg_map_replies_received % 10 ) == 0 ) : o0O0 . last_nonce = 0
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
 IiIo0oo0O = lisp_map_reply ( )
 packet = IiIo0oo0O . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 86 - 86: O0 + OoO0O00 + O0 . I1IiiI
 IiIo0oo0O . print_map_reply ( )
 if 82 - 82: OoOoOO00
 if 61 - 61: oO0o . o0oOOo0O0Ooo
 if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
 if 70 - 70: I1IiiI
 o0o0OooOooo00 = None
 for o000o0O0Oo00 in range ( IiIo0oo0O . record_count ) :
  oooO = lisp_eid_record ( )
  packet = oooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 93 - 93: OoO0O00
  oooO . print_record ( "  " , False )
  if 56 - 56: i1IIi + Ii1I * iIii1I11I1II1
  if 1 - 1: iII111i
  if 25 - 25: oO0o - i1IIi
  if 67 - 67: I1IiiI % I11i - OoooooooOO
  if 2 - 2: Ii1I
  if ( oooO . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , IiIo0oo0O . nonce )
   if 25 - 25: I1Ii111 * I1IiiI + OoOoOO00 . i11iIiiIii . I1IiiI . I11i
   if 61 - 61: o0oOOo0O0Ooo / ooOoO0o + o0oOOo0O0Ooo + Ii1I * iIii1I11I1II1 * OoooooooOO
  I1iI1III = ( oooO . group . is_null ( ) == False )
  if 86 - 86: oO0o . o0oOOo0O0Ooo * OoOoOO00 / oO0o
  if 47 - 47: OOooOOo
  if 40 - 40: I1ii11iIi11i
  if 67 - 67: I1Ii111 - OoO0O00 * ooOoO0o - oO0o / OoO0O00 . I1Ii111
  if 39 - 39: Ii1I
  if ( lisp_decent_push_configured ) :
   oo0OoooOo0 = oooO . action
   if ( I1iI1III and oo0OoooOo0 == LISP_DROP_ACTION ) :
    if ( oooO . eid . is_local ( ) ) : continue
    if 90 - 90: I1Ii111 - I1Ii111 . i11iIiiIii + OoooooooOO % OOooOOo / Oo0Ooo
    if 51 - 51: o0oOOo0O0Ooo
    if 8 - 8: oO0o . oO0o . Ii1I
    if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
    if 1 - 1: IiII * I1Ii111 / I1ii11iIi11i * i11iIiiIii
    if 82 - 82: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo % OoOoOO00 * iIii1I11I1II1 % O0
    if 10 - 10: ooOoO0o
  if ( I1iI1III == False and oooO . eid . is_null ( ) ) : continue
  if 69 - 69: I11i + I1IiiI / oO0o
  if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
  if 85 - 85: I1Ii111 - oO0o
  if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
  if 96 - 96: oO0o
  if ( I1iI1III ) :
   Ii111 = lisp_map_cache . lookup_cache ( oooO . group , True )
   if ( Ii111 ) : Ii111 = Ii111 . lookup_source_cache ( oooO . eid , False )
  else :
   Ii111 = lisp_map_cache . lookup_cache ( oooO . eid , True )
   if 39 - 39: OoOoOO00
  Ooo0o = ( Ii111 == None )
  if 23 - 23: IiII + OoO0O00 + I1IiiI . I1Ii111 . o0oOOo0O0Ooo
  if 72 - 72: Ii1I * OoO0O00 / OoO0O00
  if 39 - 39: oO0o
  if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
  if 57 - 57: oO0o + O0 - OoOoOO00
  if ( Ii111 == None ) :
   IiIii1i , O0O0oOO , IIIIIi1I1Ii = lisp_allow_gleaning ( oooO . eid , oooO . group ,
 None )
   if ( IiIii1i ) : continue
  else :
   if ( Ii111 . gleaned ) : continue
   if 52 - 52: i1IIi * o0oOOo0O0Ooo + i1IIi
   if 24 - 24: i1IIi
   if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
   if 99 - 99: Oo0Ooo
   if 38 - 38: I1ii11iIi11i - I1IiiI
  o0O00ooOo = [ ]
  I1IIIIiIii = None
  I11Io00oo0OO = None
  for oO0OO in range ( oooO . rloc_count ) :
   ooO0 = lisp_rloc_record ( )
   ooO0 . keys = IiIo0oo0O . keys
   packet = ooO0 . decode ( packet , IiIo0oo0O . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 29 - 29: IiII - I1ii11iIi11i . Oo0Ooo + IiII - I1IiiI
   ooO0 . print_record ( "    " )
   if 95 - 95: O0 / o0oOOo0O0Ooo + OoO0O00 / IiII - IiII % OOooOOo
   if 16 - 16: I1IiiI * iIii1I11I1II1 % o0oOOo0O0Ooo - IiII - OOooOOo
   if 83 - 83: Ii1I
   if 20 - 20: ooOoO0o
   I1iII1 = None
   if ( Ii111 ) :
    I1iII1 = Ii111 . get_rloc ( ooO0 . rloc )
    if ( I1iII1 == None and I1iI1III and Ii111 . rloc_set != [ ] ) :
     ooOoo = Ii111 . rloc_set [ 0 ]
     I1iII1 = ooOoo . get_rle ( ooO0 . rloc )
     if 41 - 41: iII111i * OOooOOo . oO0o / ooOoO0o + OoooooooOO + ooOoO0o
     if 100 - 100: I1IiiI / I1IiiI - I1IiiI % OOooOOo * O0 * I1IiiI
   if ( I1iII1 ) :
    OO0Oo00oo = I1iII1
   else :
    OO0Oo00oo = lisp_rloc ( )
    if 20 - 20: iII111i + ooOoO0o . i11iIiiIii
    if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
    if 50 - 50: OoooooooOO * II111iiii
    if 7 - 7: ooOoO0o / I11i * iII111i
    if 17 - 17: O0 % I1Ii111
    if 28 - 28: i1IIi * ooOoO0o
    if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
   i11I1Ii1Iiii1 = OO0Oo00oo . store_rloc_from_record ( ooO0 , IiIo0oo0O . nonce , source )
   OO0Oo00oo . set_active_rloc_next_hop ( )
   OO0Oo00oo . echo_nonce_capable = IiIo0oo0O . echo_nonce_capable
   if 92 - 92: II111iiii - II111iiii % IiII
   if ( OO0Oo00oo . echo_nonce_capable ) :
    O00oO000Oo0 = OO0Oo00oo . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , O00oO000Oo0 ) == None ) :
     lisp_echo_nonce ( O00oO000Oo0 )
     if 48 - 48: oO0o / II111iiii + oO0o
     if 16 - 16: o0oOOo0O0Ooo % II111iiii - i11iIiiIii - IiII + O0 - i11iIiiIii
     if 58 - 58: OoooooooOO / I1ii11iIi11i - Oo0Ooo / II111iiii
     if 13 - 13: o0oOOo0O0Ooo + OoOoOO00 * ooOoO0o % IiII
     if 18 - 18: I1IiiI . I1ii11iIi11i + Oo0Ooo - iII111i
     if 53 - 53: ooOoO0o / IiII
   if ( OO0Oo00oo . json ) :
    if ( lisp_is_json_telemetry ( OO0Oo00oo . json . json_string ) ) :
     Ooo = OO0Oo00oo . json . json_string
     Ooo = lisp_encode_telemetry ( Ooo , ii = itr_in_ts )
     OO0Oo00oo . json . json_string = Ooo
     if 36 - 36: iIii1I11I1II1
     if 78 - 78: II111iiii * I11i
     if 47 - 47: Ii1I
     if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
     if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
     if 53 - 53: iIii1I11I1II1
   if ( I11Io00oo0OO == None ) : I11Io00oo0OO = OO0Oo00oo . rloc_name
   if 8 - 8: O0 - O0 - II111iiii
   if 77 - 77: i1IIi - ooOoO0o + O0 . OoO0O00 * I1Ii111 - I11i
   if 64 - 64: i1IIi + OoooooooOO + OOooOOo / ooOoO0o % I1IiiI . OoooooooOO
   if 96 - 96: II111iiii - OoOoOO00 + oO0o
   if 80 - 80: oO0o / OoOoOO00 - I11i / oO0o - iII111i - OoooooooOO
   if 57 - 57: o0oOOo0O0Ooo
   if 37 - 37: iII111i * o0oOOo0O0Ooo
   if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
   if ( IiIo0oo0O . rloc_probe and ooO0 . probe_bit ) :
    if ( OO0Oo00oo . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( OO0Oo00oo , source , i11I1Ii1Iiii1 ,
 IiIo0oo0O , ttl , I1IIIIiIii , I11Io00oo0OO )
     if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
    if ( OO0Oo00oo . rloc . is_multicast_address ( ) ) : I1IIIIiIii = OO0Oo00oo
    if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
    if 34 - 34: O0 * oO0o
    if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
    if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
    if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
   o0O00ooOo . append ( OO0Oo00oo )
   if 88 - 88: i11iIiiIii
   if 13 - 13: I1IiiI
   if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
   if 84 - 84: OoooooooOO - oO0o - I1Ii111
   if ( lisp_data_plane_security and OO0Oo00oo . rloc_recent_rekey ( ) ) :
    o0o0OooOooo00 = OO0Oo00oo
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
  if ( IiIo0oo0O . rloc_probe == False and lisp_nat_traversal ) :
   IiII11iIIII1 = [ ]
   iI111111iiii = [ ]
   for OO0Oo00oo in o0O00ooOo :
    iIiIi111 = OO0Oo00oo . rloc . print_address_no_iid ( )
    if 9 - 9: Oo0Ooo + OOooOOo + OoO0O00 + Ii1I - Oo0Ooo * OoOoOO00
    if 20 - 20: oO0o
    if 48 - 48: I1IiiI % OoO0O00
    if 33 - 33: Ii1I
    if 73 - 73: Ii1I . IiII
    if ( OO0Oo00oo . rloc . is_private_address ( ) ) :
     OO0Oo00oo . priority = 1
     OO0Oo00oo . state = LISP_RLOC_UNREACH_STATE
     IiII11iIIII1 . append ( OO0Oo00oo )
     iI111111iiii . append ( iIiIi111 )
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
     if ( OO0Oo00oo . priority != 254 ) :
      IiII11iIIII1 . append ( OO0Oo00oo )
      iI111111iiii . append ( iIiIi111 )
      if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
    elif ( lisp_decent_nat ) :
     IiII11iIIII1 . append ( OO0Oo00oo )
     iI111111iiii . append ( iIiIi111 )
    elif ( OO0Oo00oo . priority == 254 ) :
     IiII11iIIII1 . append ( OO0Oo00oo )
     iI111111iiii . append ( iIiIi111 )
     if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
     if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
     if 66 - 66: I1IiiI
   if ( iI111111iiii != [ ] ) :
    o0O00ooOo = IiII11iIIII1
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
  IiII11iIIII1 = [ ]
  for OO0Oo00oo in o0O00ooOo :
   if ( OO0Oo00oo . json != None ) : continue
   IiII11iIIII1 . append ( OO0Oo00oo )
   if 73 - 73: OoOoOO00
  if ( IiII11iIIII1 != [ ] ) :
   III11i1iI11 = len ( o0O00ooOo ) - len ( IiII11iIIII1 )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( III11i1iI11 ) )
   if 47 - 47: oO0o
   o0O00ooOo = IiII11iIIII1
   if 17 - 17: IiII
   if 47 - 47: I11i . I1IiiI % ooOoO0o . i11iIiiIii
   if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
   if 100 - 100: O0
   if 9 - 9: Ii1I
   if 87 - 87: I1IiiI
  if ( lisp_decent_nat ) :
   for OO0Oo00oo in o0O00ooOo :
    if ( OO0Oo00oo . is_decent_nat_port ( ) == False ) : continue
    lisp_itr_nat_probe ( OO0Oo00oo . rloc , OO0Oo00oo . rloc_name , lisp_sockets [ 2 ] )
    if 56 - 56: OOooOOo % oO0o - OoOoOO00
    if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
    if 81 - 81: oO0o / iIii1I11I1II1
    if 15 - 15: Ii1I + I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
    if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
    if 28 - 28: ooOoO0o
    if 88 - 88: oO0o
    if 77 - 77: ooOoO0o + I1Ii111 . OoOoOO00
    if 2 - 2: i1IIi - IiII + iIii1I11I1II1 % i1IIi * II111iiii
  if ( IiIo0oo0O . rloc_probe and Ii111 != None ) : o0O00ooOo = Ii111 . rloc_set
  if 26 - 26: I11i
  if 57 - 57: I1ii11iIi11i + I1Ii111 + i11iIiiIii . i1IIi / i11iIiiIii
  if 43 - 43: Ii1I % I11i
  if 5 - 5: OoooooooOO % i11iIiiIii * o0oOOo0O0Ooo * OoooooooOO - o0oOOo0O0Ooo % I11i
  if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
  iI11I11Iii = Ooo0o
  if ( Ii111 and o0O00ooOo != Ii111 . rloc_set ) :
   Ii111 . delete_rlocs_from_rloc_probe_list ( )
   iI11I11Iii = True
   if 20 - 20: I1Ii111
   if 75 - 75: I1IiiI / I1Ii111 . I1Ii111 / I1IiiI + OOooOOo + o0oOOo0O0Ooo
   if 68 - 68: i1IIi + OoO0O00
   if 60 - 60: i11iIiiIii . ooOoO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
   if 59 - 59: OoooooooOO . Ii1I . OOooOOo / iII111i - I1IiiI
  oO0O = Ii111 . uptime if ( Ii111 ) else None
  if ( Ii111 == None or iI11I11Iii ) :
   Ii111 = lisp_mapping ( oooO . eid , oooO . group , o0O00ooOo )
   Ii111 . mapping_source = source
   if 81 - 81: I1IiiI . Oo0Ooo
   if 94 - 94: o0oOOo0O0Ooo
   if 88 - 88: OoO0O00 / II111iiii
   if 27 - 27: OOooOOo - i1IIi + O0 . I1Ii111 % I11i . I1ii11iIi11i
   if 80 - 80: I1IiiI - i11iIiiIii
   if 39 - 39: I11i / O0 - I1ii11iIi11i . Oo0Ooo * OoooooooOO / o0oOOo0O0Ooo
   if ( lisp_i_am_rtr and oooO . group . is_null ( ) == False ) :
    Ii111 . map_cache_ttl = LISP_MCAST_TTL
   else :
    Ii111 . map_cache_ttl = oooO . store_ttl ( )
    if 71 - 71: O0 . OoooooooOO + Oo0Ooo . ooOoO0o / Ii1I
   Ii111 . action = oooO . action
   Ii111 . add_cache ( iI11I11Iii )
   if 92 - 92: I1ii11iIi11i . oO0o
   if 8 - 8: o0oOOo0O0Ooo / oO0o
  O000OOoo0o = "Add"
  if ( oO0O ) :
   Ii111 . uptime = oO0O
   Ii111 . refresh_time = lisp_get_timestamp ( )
   O000OOoo0o = "Replace"
   if 10 - 10: ooOoO0o / i11iIiiIii % OoO0O00 % i11iIiiIii
   if 66 - 66: II111iiii - II111iiii % OoOoOO00 % iII111i % IiII / I11i
  lprint ( "{} {} map-cache with {} RLOCs" . format ( O000OOoo0o ,
 green ( Ii111 . print_eid_tuple ( ) , False ) , len ( o0O00ooOo ) ) )
  if 50 - 50: IiII + i1IIi % I1Ii111
  if 72 - 72: I1Ii111
  if 6 - 6: II111iiii - i1IIi
  if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
  if 85 - 85: I1ii11iIi11i + OOooOOo % i1IIi
  if ( lisp_ipc_dp_socket and o0o0OooOooo00 != None ) :
   lisp_write_ipc_keys ( o0o0OooOooo00 )
   if 13 - 13: OOooOOo + i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
   if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
   if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
   if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
   if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
   if 32 - 32: I1Ii111
   if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
  if ( Ooo0o ) :
   I1III1 = bold ( "RLOC-probe" , False )
   for OO0Oo00oo in Ii111 . best_rloc_set :
    O00oO000Oo0 = red ( OO0Oo00oo . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( I1III1 , O00oO000Oo0 ) )
    lisp_send_map_request ( lisp_sockets , 0 , Ii111 . eid , Ii111 . group , OO0Oo00oo )
    if 21 - 21: i1IIi * Oo0Ooo * OoO0O00 . iIii1I11I1II1 / ooOoO0o
    if 4 - 4: Oo0Ooo - i1IIi . Oo0Ooo * I11i . i1IIi + OOooOOo
    if 3 - 3: IiII / iII111i * iII111i
 return
 if 15 - 15: O0 + I1IiiI * OoO0O00 - i1IIi + Ii1I . i1IIi
 if 99 - 99: II111iiii + iIii1I11I1II1 / o0oOOo0O0Ooo / i11iIiiIii % iIii1I11I1II1 - iIii1I11I1II1
 if 38 - 38: I1IiiI . oO0o - II111iiii
 if 37 - 37: i1IIi % oO0o / IiII * I11i + ooOoO0o % Oo0Ooo
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 % i1IIi . i11iIiiIii
 if 38 - 38: o0oOOo0O0Ooo - OoO0O00 - i11iIiiIii
 if 60 - 60: i11iIiiIii % iIii1I11I1II1 * I1ii11iIi11i * iII111i . oO0o + iII111i
 if 29 - 29: Oo0Ooo
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 16 - 16: oO0o
 packet = map_register . zero_auth ( packet )
 ii1iiIiiiI11 = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
 if 15 - 15: iII111i
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 if 72 - 72: I1Ii111 . I1Ii111 * O0 + I1ii11iIi11i / Oo0Ooo
 map_register . auth_data = ii1iiIiiiI11
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 96 - 96: oO0o . ooOoO0o * Oo0Ooo % ooOoO0o + I1Ii111 + iIii1I11I1II1
 if 45 - 45: II111iiii
 if 42 - 42: ooOoO0o
 if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
 if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
 if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
 if 10 - 10: oO0o * Oo0Ooo
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  o00oOO0Oo000o = hashlib . sha1
  if 28 - 28: OoOoOO00 * I1ii11iIi11i / Oo0Ooo
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  o00oOO0Oo000o = hashlib . sha256
  if 17 - 17: I1Ii111 - OOooOOo . ooOoO0o - i1IIi * ooOoO0o * I1ii11iIi11i
  if 16 - 16: I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
 if ( do_hex ) :
  ii1iiIiiiI11 = hmac . new ( password . encode ( ) , packet , o00oOO0Oo000o ) . hexdigest ( )
 else :
  ii1iiIiiiI11 = hmac . new ( password . encode ( ) , packet , o00oOO0Oo000o ) . digest ( )
  if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
 return ( ii1iiIiiiI11 )
 if 33 - 33: OoooooooOO . IiII * o0oOOo0O0Ooo
 if 41 - 41: Ii1I . iII111i . o0oOOo0O0Ooo % OoooooooOO % IiII
 if 81 - 81: IiII * i11iIiiIii + i1IIi + OOooOOo . i1IIi
 if 6 - 6: i11iIiiIii - oO0o % OoO0O00 + iIii1I11I1II1
 if 69 - 69: IiII
 if 13 - 13: i11iIiiIii
 if 49 - 49: OoOoOO00
 if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 80 - 80: I1IiiI - OOooOOo . oO0o
 ii1iiIiiiI11 = lisp_hash_me ( packet , alg_id , password , True )
 oOOOoO0 = ( ii1iiIiiiI11 == auth_data )
 if 23 - 23: ooOoO0o / OoOoOO00 * OOooOOo . O0 - OOooOOo
 if 5 - 5: OOooOOo % I1Ii111 * II111iiii
 if 69 - 69: OoO0O00 . o0oOOo0O0Ooo
 if 86 - 86: I1ii11iIi11i
 if ( oOOOoO0 == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( ii1iiIiiiI11 , auth_data ) )
  if 51 - 51: O0 % OoO0O00 - I1Ii111
  if 82 - 82: OoOoOO00 - OOooOOo . i1IIi / I11i
 return ( oOOOoO0 )
 if 45 - 45: i1IIi / i1IIi . ooOoO0o . O0 / I1IiiI
 if 68 - 68: I11i % iIii1I11I1II1 . ooOoO0o . I1Ii111 + OoooooooOO
 if 45 - 45: IiII - Ii1I
 if 74 - 74: ooOoO0o / I1Ii111
 if 80 - 80: I1Ii111 / O0 * O0
 if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
 if 89 - 89: i11iIiiIii - II111iiii
def lisp_retransmit_map_notify ( map_notify ) :
 oOO00OoOo = map_notify . etr
 i11I1Ii1Iiii1 = map_notify . etr_port
 if 67 - 67: IiII % I1Ii111 + i11iIiiIii
 if 53 - 53: OOooOOo
 if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
 if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
 if 52 - 52: Ii1I * I1ii11iIi11i
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( oOO00OoOo . print_address ( ) , False ) ) )
  if 21 - 21: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo * II111iiii % iIii1I11I1II1
  if 9 - 9: I1ii11iIi11i + I11i
  oO0oOo = map_notify . nonce_key
  if ( oO0oOo in lisp_map_notify_queue ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( oO0oOo ) )
   if 20 - 20: iII111i + i1IIi / oO0o % OoooooooOO * OoOoOO00
   try :
    lisp_map_notify_queue . pop ( oO0oOo )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 70 - 70: Oo0Ooo - OOooOOo * OOooOOo / o0oOOo0O0Ooo
    if 4 - 4: OoOoOO00 / OoO0O00
  return
  if 66 - 66: I1Ii111 / OoOoOO00
  if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
 ooOo0o00 = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # i1IIi - oO0o
 red ( oOO00OoOo . print_address ( ) , False ) , map_notify . retry_count ) )
 if 33 - 33: Ii1I / I1ii11iIi11i . ooOoO0o . OoooooooOO
 lisp_send_map_notify ( ooOo0o00 , map_notify . packet , oOO00OoOo , i11I1Ii1Iiii1 )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 45 - 45: OoO0O00 . I1ii11iIi11i + Ii1I / I11i - ooOoO0o / OoooooooOO
 if 44 - 44: OoO0O00 % O0 * IiII + iII111i
 if 79 - 79: ooOoO0o
 if 82 - 82: O0 - Oo0Ooo - i11iIiiIii
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 9 - 9: OoooooooOO . i11iIiiIii * iIii1I11I1II1 / IiII * i11iIiiIii
 if 57 - 57: o0oOOo0O0Ooo . I1IiiI / iII111i / ooOoO0o - OoO0O00
 if 8 - 8: iIii1I11I1II1 % ooOoO0o + OoO0O00 . oO0o % I1IiiI - O0
 if 25 - 25: i11iIiiIii * OoOoOO00 + OoO0O00 . o0oOOo0O0Ooo
 if 65 - 65: I1Ii111 + i1IIi / iII111i % O0 + II111iiii * i1IIi
 if 49 - 49: o0oOOo0O0Ooo + OOooOOo - II111iiii
 if 34 - 34: ooOoO0o . I1Ii111
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 52 - 52: I1IiiI + I1Ii111 * oO0o / i11iIiiIii * iIii1I11I1II1
 if 27 - 27: Oo0Ooo
 if 85 - 85: iIii1I11I1II1 . o0oOOo0O0Ooo + oO0o
 if 79 - 79: O0 - iIii1I11I1II1 + i1IIi . I11i
 eid_record . rloc_count = len ( parent . registered_rlocs )
 ii111 = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 4 - 4: oO0o / OoO0O00
 if 90 - 90: I11i . IiII / OoO0O00 . IiII
 if 62 - 62: i11iIiiIii * I11i + oO0o - i1IIi
 if 9 - 9: I1IiiI
 for iiIi1I in parent . registered_rlocs :
  ooO0 = lisp_rloc_record ( )
  ooO0 . store_rloc_entry ( iiIi1I )
  ooO0 . local_bit = True
  ooO0 . probe_bit = False
  ooO0 . reach_bit = True
  ii111 += ooO0 . encode ( )
  ooO0 . print_record ( "  " )
  del ( ooO0 )
  if 45 - 45: o0oOOo0O0Ooo + iIii1I11I1II1 / O0
  if 2 - 2: I11i + I1IiiI . IiII . OoOoOO00 * oO0o - ooOoO0o
  if 29 - 29: OoO0O00
  if 78 - 78: iII111i * ooOoO0o + O0 % ooOoO0o + OoO0O00
  if 41 - 41: II111iiii . oO0o + O0 % i1IIi . Ii1I
 for iiIi1I in parent . registered_rlocs :
  oOO00OoOo = iiIi1I . rloc
  O0oo0o0Oo0oo = lisp_map_notify ( lisp_sockets )
  O0oo0o0Oo0oo . record_count = 1
  IIIOo0O = map_register . key_id
  O0oo0o0Oo0oo . key_id = IIIOo0O
  O0oo0o0Oo0oo . alg_id = map_register . alg_id
  O0oo0o0Oo0oo . auth_len = map_register . auth_len
  O0oo0o0Oo0oo . nonce = map_register . nonce
  O0oo0o0Oo0oo . nonce_key = lisp_hex_string ( O0oo0o0Oo0oo . nonce )
  O0oo0o0Oo0oo . etr . copy_address ( oOO00OoOo )
  O0oo0o0Oo0oo . etr_port = map_register . sport
  O0oo0o0Oo0oo . site = parent . site
  Oo00O0o0O = O0oo0o0Oo0oo . encode ( ii111 , parent . site . auth_key [ IIIOo0O ] )
  O0oo0o0Oo0oo . print_notify ( )
  if 20 - 20: iII111i - I11i / I1ii11iIi11i * O0 + IiII % I11i
  if 69 - 69: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO - ooOoO0o
  if 94 - 94: iIii1I11I1II1 / Oo0Ooo % IiII * IiII
  if 62 - 62: I11i . IiII - OOooOOo - I1Ii111 / OoooooooOO . Ii1I
  oO0oOo = O0oo0o0Oo0oo . nonce_key
  if ( oO0oOo in lisp_map_notify_queue ) :
   I1II1i11I1i = lisp_map_notify_queue [ oO0oOo ]
   I1II1i11I1i . retransmit_timer . cancel ( )
   del ( I1II1i11I1i )
   if 65 - 65: IiII + OoO0O00 * OOooOOo . Ii1I . i1IIi / OoOoOO00
  lisp_map_notify_queue [ oO0oOo ] = O0oo0o0Oo0oo
  if 49 - 49: Oo0Ooo + OOooOOo - i1IIi
  if 13 - 13: oO0o / OoOoOO00 + OoOoOO00 - OoOoOO00 / iII111i * i11iIiiIii
  if 61 - 61: I1Ii111 % oO0o - OOooOOo
  if 91 - 91: o0oOOo0O0Ooo * Oo0Ooo
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( oOO00OoOo . print_address ( ) , False ) ) )
  if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
  lisp_send ( lisp_sockets , oOO00OoOo , LISP_CTRL_PORT , Oo00O0o0O )
  if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
  parent . site . map_notifies_sent += 1
  if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
  if 33 - 33: I11i
  if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
  if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
  O0oo0o0Oo0oo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ O0oo0o0Oo0oo ] )
  O0oo0o0Oo0oo . retransmit_timer . start ( )
  if 32 - 32: oO0o
 return
 if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
 if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
 if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
 if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
 if 94 - 94: Ii1I
 if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
 oO0oOo = lisp_hex_string ( nonce ) + source . print_address ( )
 if 34 - 34: iIii1I11I1II1
 if 47 - 47: OOooOOo * iII111i
 if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
 if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
 if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
 if 70 - 70: OoO0O00
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( oO0oOo in lisp_map_notify_queue ) :
  O0oo0o0Oo0oo = lisp_map_notify_queue [ oO0oOo ]
  OOo0oOO0o0oo0 = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( O0oo0o0Oo0oo . nonce ) , OOo0oOO0o0oo0 ) )
  if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
  return
  if 85 - 85: O0 . II111iiii
  if 80 - 80: O0 * I11i * I1Ii111
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
 if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
 if 25 - 25: iII111i + i1IIi
 if 64 - 64: IiII % I11i / iIii1I11I1II1
 if 66 - 66: Ii1I
 if ( map_register_ack == False ) :
  oO0oOo = O0oo0o0Oo0oo . nonce_key
  lisp_map_notify_queue [ oO0oOo ] = O0oo0o0Oo0oo
  if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
  if 71 - 71: IiII - iII111i % I1IiiI * iII111i
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 27 - 27: ooOoO0o - OoO0O00
  if 83 - 83: iII111i * OoOoOO00 - O0 * Ii1I
  if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
  if 32 - 32: IiII * II111iiii . Ii1I
  if 68 - 68: I11i / O0
 Oo00O0o0O = O0oo0o0Oo0oo . encode ( eid_records , site . auth_key [ key_id ] )
 O0oo0o0Oo0oo . print_notify ( )
 if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
 if ( map_register_ack == False ) :
  oooO = lisp_eid_record ( )
  oooO . decode ( eid_records )
  oooO . print_record ( "  " , False )
  if 22 - 22: Ii1I / I1IiiI / II111iiii
  if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
  if 76 - 76: Oo0Ooo
  if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
  if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
 lisp_send_map_notify ( lisp_sockets , Oo00O0o0O , O0oo0o0Oo0oo . etr , port )
 site . map_notifies_sent += 1
 if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
 if ( map_register_ack ) : return
 if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
 if 45 - 45: Ii1I * IiII - OOooOOo
 if 57 - 57: iII111i % OoO0O00 / OoooooooOO
 if 69 - 69: oO0o
 if 44 - 44: IiII - II111iiii % Ii1I
 if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
 O0oo0o0Oo0oo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ O0oo0o0Oo0oo ] )
 O0oo0o0Oo0oo . retransmit_timer . start ( )
 return
 if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
 if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
 if 59 - 59: OoOoOO00
 if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
 if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
 if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
 if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
 if 7 - 7: OOooOOo
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 22 - 22: Oo0Ooo + ooOoO0o
 if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
 if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
 if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
 map_notify . record_count = 0
 Oo00O0o0O = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 26 - 26: Oo0Ooo . Ii1I
 if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
 if 8 - 8: iIii1I11I1II1
 if 6 - 6: oO0o
 oOO00OoOo = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( oOO00OoOo . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , oOO00OoOo , LISP_CTRL_PORT , Oo00O0o0O )
 return
 if 51 - 51: I1Ii111 - o0oOOo0O0Ooo
 if 5 - 5: O0
 if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
 if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
 if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
 if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
 if 5 - 5: I1IiiI
 if 22 - 22: II111iiii / iII111i
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
 O0oo0o0Oo0oo = lisp_map_notify ( lisp_sockets )
 O0oo0o0Oo0oo . record_count = 1
 O0oo0o0Oo0oo . nonce = lisp_get_control_nonce ( )
 O0oo0o0Oo0oo . nonce_key = lisp_hex_string ( O0oo0o0Oo0oo . nonce )
 O0oo0o0Oo0oo . etr . copy_address ( xtr )
 O0oo0o0Oo0oo . etr_port = LISP_CTRL_PORT
 O0oo0o0Oo0oo . eid_list = eid_list
 oO0oOo = O0oo0o0Oo0oo . nonce_key
 if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
 if 21 - 21: o0oOOo0O0Ooo % O0
 if 81 - 81: i1IIi + i1IIi
 if 3 - 3: I1Ii111 . I1ii11iIi11i * iII111i * i11iIiiIii * IiII
 if 52 - 52: iIii1I11I1II1 % o0oOOo0O0Ooo % I1IiiI
 if 71 - 71: I1IiiI + iII111i
 lisp_remove_eid_from_map_notify_queue ( O0oo0o0Oo0oo . eid_list )
 if ( oO0oOo in lisp_map_notify_queue ) :
  O0oo0o0Oo0oo = lisp_map_notify_queue [ oO0oOo ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( O0oo0o0Oo0oo . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 47 - 47: iIii1I11I1II1 . OoO0O00 . iIii1I11I1II1
  return
  if 57 - 57: IiII * ooOoO0o * ooOoO0o * iIii1I11I1II1 * I1Ii111 + OoOoOO00
  if 83 - 83: OoOoOO00 . Oo0Ooo . OoO0O00
  if 65 - 65: iII111i * iIii1I11I1II1
  if 48 - 48: iII111i * OoO0O00
  if 57 - 57: ooOoO0o + I1IiiI
 lisp_map_notify_queue [ oO0oOo ] = O0oo0o0Oo0oo
 if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
 if 82 - 82: Oo0Ooo % Oo0Ooo
 if 91 - 91: I11i
 if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
 if 65 - 65: OoO0O00
 if 65 - 65: oO0o
 O0OooOOOOOooO = site_eid . rtrs_in_rloc_set ( )
 if 65 - 65: OOooOOo + i1IIi * Ii1I % iIii1I11I1II1 . OOooOOo % I1ii11iIi11i
 if 98 - 98: OoooooooOO . o0oOOo0O0Ooo % OOooOOo / O0 + I1Ii111 % i11iIiiIii
 if 94 - 94: O0 + II111iiii - iII111i / i1IIi
 if 25 - 25: ooOoO0o . OoO0O00 - oO0o
 oooO = lisp_eid_record ( )
 oooO . record_ttl = 1440
 oooO . eid . copy_address ( site_eid . eid )
 oooO . group . copy_address ( site_eid . group )
 oooO . rloc_count = 0
 for i1iiI1i1 in site_eid . registered_rlocs :
  if ( O0OooOOOOOooO ^ i1iiI1i1 . is_rtr ( ) ) : continue
  oooO . rloc_count += 1
  if 76 - 76: iIii1I11I1II1 / II111iiii * OoOoOO00 % iII111i . II111iiii + i11iIiiIii
 Oo00O0o0O = oooO . encode ( )
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i
 if 53 - 53: I11i
 if 64 - 64: OoO0O00 + I11i / I1IiiI . II111iiii
 if 79 - 79: I1Ii111 + IiII / OoooooooOO
 O0oo0o0Oo0oo . print_notify ( )
 oooO . print_record ( "  " , False )
 if 53 - 53: Ii1I
 if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
 if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
 if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
 IIIIiII = [ ]
 for i1iiI1i1 in site_eid . registered_rlocs :
  if ( O0OooOOOOOooO ) :
   if ( i1iiI1i1 . is_rtr ( ) ) :
    IIIIiII . append ( i1iiI1i1 . rloc )
    continue
    if 33 - 33: oO0o . oO0o / IiII + II111iiii
    if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
    if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
    if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
    if 25 - 25: OoO0O00
    if 83 - 83: II111iiii . iIii1I11I1II1
  ooO0 = lisp_rloc_record ( )
  ooO0 . store_rloc_entry ( i1iiI1i1 )
  ooO0 . local_bit = True
  ooO0 . probe_bit = False
  ooO0 . reach_bit = True
  Oo00O0o0O += ooO0 . encode ( )
  ooO0 . print_record ( "    " )
  if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
  if 8 - 8: iII111i - i1IIi
  if 81 - 81: ooOoO0o / OOooOOo % OoOoOO00 . iIii1I11I1II1
  if 45 - 45: I1IiiI . ooOoO0o - OoooooooOO
  if 84 - 84: I1ii11iIi11i
 Oo00O0o0O = O0oo0o0Oo0oo . encode ( Oo00O0o0O , "" )
 if ( Oo00O0o0O == None ) : return
 if 69 - 69: I1Ii111 + II111iiii
 if 92 - 92: OoooooooOO
 if 80 - 80: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . oO0o % I1IiiI % I11i
 if 4 - 4: OoO0O00 / iII111i / I1ii11iIi11i - o0oOOo0O0Ooo * I1Ii111
 if ( IIIIiII != [ ] ) :
  for I11i1i1 in IIIIiII :
   lisp_send_map_notify ( lisp_sockets , Oo00O0o0O , I11i1i1 , LISP_CTRL_PORT )
   if 24 - 24: OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - o0oOOo0O0Ooo . I1ii11iIi11i
 else :
  lisp_send_map_notify ( lisp_sockets , Oo00O0o0O , xtr , LISP_CTRL_PORT )
  if 2 - 2: I1IiiI . o0oOOo0O0Ooo / Oo0Ooo - OoOoOO00 - OoooooooOO
  if 73 - 73: I1Ii111 . i11iIiiIii * ooOoO0o . IiII - I11i + I1Ii111
  if 21 - 21: I1Ii111 + iIii1I11I1II1 + I1IiiI / O0 * I1ii11iIi11i
  if 57 - 57: OOooOOo * I11i . oO0o
  if 17 - 17: iII111i - OOooOOo * I1IiiI + i1IIi % I1ii11iIi11i
 O0oo0o0Oo0oo . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ O0oo0o0Oo0oo ] )
 O0oo0o0Oo0oo . retransmit_timer . start ( )
 return
 if 71 - 71: Ii1I - o0oOOo0O0Ooo - oO0o
 if 27 - 27: O0 - iIii1I11I1II1
 if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
 if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
 if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
 if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
 if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 ii1ii1Iii1I = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 40 - 40: ooOoO0o * OoooooooOO + O0 . i11iIiiIii - OoOoOO00
 for i1Ii1 in rle_list :
  I11I1I1 = lisp_site_eid_lookup ( i1Ii1 [ 0 ] , i1Ii1 [ 1 ] , True )
  if ( I11I1I1 == None ) : continue
  if 66 - 66: ooOoO0o / Ii1I * OoO0O00 * i11iIiiIii
  if 69 - 69: I11i % i11iIiiIii
  if 34 - 34: Ii1I . OoooooooOO + II111iiii % oO0o
  if 69 - 69: i11iIiiIii % I1IiiI * i11iIiiIii - OoO0O00 * iIii1I11I1II1
  if 70 - 70: I1Ii111 . OoOoOO00 % OoooooooOO + OoOoOO00 / II111iiii
  if 39 - 39: I1Ii111 * I1IiiI - o0oOOo0O0Ooo . oO0o . OOooOOo * i11iIiiIii
  if 70 - 70: OoOoOO00 / OOooOOo - o0oOOo0O0Ooo
  O0oI1Ii1III = I11I1I1 . registered_rlocs
  if ( len ( O0oI1Ii1III ) == 0 ) :
   III1IiI = { }
   for ii11i1Ii in list ( I11I1I1 . individual_registrations . values ( ) ) :
    for i1iiI1i1 in ii11i1Ii . registered_rlocs :
     if ( i1iiI1i1 . is_rtr ( ) == False ) : continue
     III1IiI [ i1iiI1i1 . rloc . print_address ( ) ] = i1iiI1i1
     if 41 - 41: iIii1I11I1II1 - O0 . II111iiii + I1IiiI - II111iiii / oO0o
     if 35 - 35: ooOoO0o - OoOoOO00 / iIii1I11I1II1 / OOooOOo
   O0oI1Ii1III = list ( III1IiI . values ( ) )
   if 38 - 38: i1IIi % OoooooooOO
   if 5 - 5: iIii1I11I1II1 + iIii1I11I1II1 . iIii1I11I1II1 + o0oOOo0O0Ooo
   if 45 - 45: I1IiiI - OoooooooOO - I1Ii111 - i1IIi - OoooooooOO * O0
   if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . IiII
   if 72 - 72: OoOoOO00 % OoooooooOO * O0
   if 27 - 27: I1ii11iIi11i . OoooooooOO / II111iiii . OOooOOo
  oO0oO = [ ]
  O0OO00OO = False
  if ( I11I1I1 . eid . address == 0 and I11I1I1 . eid . mask_len == 0 ) :
   iIiiiIIii1 = [ ]
   OooOoOO0O = [ ]
   if ( len ( O0oI1Ii1III ) != 0 and O0oI1Ii1III [ 0 ] . rle != None ) :
    OooOoOO0O = O0oI1Ii1III [ 0 ] . rle . rle_nodes
    if 7 - 7: o0oOOo0O0Ooo * I1Ii111 * o0oOOo0O0Ooo - OoO0O00 * Oo0Ooo - IiII
   for I1I1Ii1I in OooOoOO0O :
    oO0oO . append ( I1I1Ii1I . rloc . rloc )
    iIiiiIIii1 . append ( I1I1Ii1I . rloc . rloc . print_address_no_iid ( ) )
    if 10 - 10: i1IIi - OoOoOO00
   lprint ( "Notify existing RLE-nodes {}" . format ( iIiiiIIii1 ) )
  else :
   if 25 - 25: o0oOOo0O0Ooo . I1IiiI % iIii1I11I1II1 * Ii1I % I1IiiI * I11i
   if 21 - 21: O0 % II111iiii % OoOoOO00 / Ii1I * ooOoO0o
   if 82 - 82: I1IiiI % II111iiii * iIii1I11I1II1
   if 83 - 83: O0 + i1IIi
   if 47 - 47: iIii1I11I1II1 * i11iIiiIii % Ii1I + IiII
   for i1iiI1i1 in O0oI1Ii1III :
    if ( i1iiI1i1 . is_rtr ( ) ) : oO0oO . append ( i1iiI1i1 . rloc )
    if 39 - 39: i1IIi / i11iIiiIii % ooOoO0o - ooOoO0o % i1IIi
    if 73 - 73: OoO0O00 . iII111i / OOooOOo
    if 50 - 50: O0 / IiII % oO0o / I1Ii111 % IiII
    if 10 - 10: OoooooooOO
    if 39 - 39: I11i . I1IiiI % Oo0Ooo + oO0o
   O0OO00OO = ( len ( oO0oO ) != 0 )
   if ( O0OO00OO == False ) :
    Ooo000oOOooO00 = lisp_site_eid_lookup ( i1Ii1 [ 0 ] , ii1ii1Iii1I , False )
    if ( Ooo000oOOooO00 == None ) : continue
    if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
    for i1iiI1i1 in Ooo000oOOooO00 . registered_rlocs :
     if ( i1iiI1i1 . rloc . is_null ( ) ) : continue
     oO0oO . append ( i1iiI1i1 . rloc )
     if 82 - 82: IiII % ooOoO0o
     if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
     if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
     if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
     if 89 - 89: II111iiii % I1ii11iIi11i % IiII . I11i
     if 49 - 49: iII111i % i11iIiiIii * I11i - oO0o . OOooOOo . i11iIiiIii
   if ( len ( oO0oO ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( I11I1I1 . print_eid_tuple ( ) , False ) ) )
    if 26 - 26: iIii1I11I1II1 + i11iIiiIii % iII111i + I1IiiI + oO0o - ooOoO0o
    continue
    if 4 - 4: Oo0Ooo - IiII - I11i
    if 72 - 72: OoooooooOO
    if 19 - 19: Oo0Ooo . OOooOOo
    if 58 - 58: IiII % iII111i + i1IIi % I1IiiI % OOooOOo . iII111i
    if 85 - 85: i11iIiiIii . o0oOOo0O0Ooo * iII111i . I1ii11iIi11i / I1Ii111 % Ii1I
    if 27 - 27: II111iiii . iIii1I11I1II1 / I1ii11iIi11i / i1IIi / iIii1I11I1II1
  for iiIi1I in oO0oO :
   lprint ( "Build Map-Notify for {}" . format (
 green ( I11I1I1 . print_eid_tuple ( ) , False ) ) )
   if 70 - 70: i11iIiiIii . OoO0O00 / OoooooooOO * OoooooooOO - OOooOOo
   II1iiiiIIIII = [ I11I1I1 . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , I11I1I1 , II1iiiiIIIII , iiIi1I )
   time . sleep ( .001 )
   if 90 - 90: I11i / II111iiii % o0oOOo0O0Ooo * IiII * IiII
   if 46 - 46: O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - i1IIi * O0
 return
 if 49 - 49: ooOoO0o . OoO0O00
 if 84 - 84: O0
 if 75 - 75: OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00 + o0oOOo0O0Ooo + I11i
 if 70 - 70: O0 - OoO0O00
 if 60 - 60: ooOoO0o
 if 95 - 95: I11i / o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
 if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
 if 8 - 8: OoooooooOO * ooOoO0o
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for o000o0O0Oo00 in range ( rloc_count ) :
  ooO0 = lisp_rloc_record ( )
  packet = ooO0 . decode ( packet , None )
  iiIIi11 = ooO0 . json
  if ( iiIIi11 == None ) : continue
  if 70 - 70: I1Ii111 / oO0o % OoooooooOO
  try :
   iiIIi11 = json . loads ( iiIIi11 . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 65 - 65: I1Ii111 . I1ii11iIi11i * iII111i
   if 89 - 89: o0oOOo0O0Ooo / I1Ii111 - oO0o + iII111i % I1IiiI - Ii1I
  if ( "signature" not in iiIIi11 ) : continue
  return ( ooO0 )
  if 58 - 58: OoOoOO00 + O0 - OoooooooOO % OoOoOO00 % i1IIi
 return ( None )
 if 75 - 75: OoOoOO00 . IiII - OoO0O00 . o0oOOo0O0Ooo % II111iiii
 if 69 - 69: Ii1I % OoooooooOO
 if 62 - 62: Oo0Ooo / oO0o
 if 87 - 87: oO0o
 if 39 - 39: iII111i
 if 46 - 46: i11iIiiIii * iII111i / Oo0Ooo % OOooOOo % oO0o / Ii1I
 if 75 - 75: Ii1I
 if 37 - 37: I1IiiI / OoO0O00 . OoO0O00 + i11iIiiIii - oO0o
 if 57 - 57: I1IiiI . OoO0O00
 if 49 - 49: II111iiii + iII111i
 if 85 - 85: I11i / i11iIiiIii
 if 33 - 33: iIii1I11I1II1 % O0 + II111iiii * OOooOOo . Ii1I * iII111i
 if 48 - 48: I11i * iIii1I11I1II1 / oO0o
 if 34 - 34: i1IIi + oO0o * Oo0Ooo * I1Ii111 % OoooooooOO % ooOoO0o
 if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
 if 87 - 87: ooOoO0o
 if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
 if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
 if 26 - 26: O0
def lisp_get_eid_hash ( eid ) :
 O00000o = None
 for I1Ii in lisp_eid_hashes :
  if 27 - 27: O0
  if 5 - 5: i1IIi % I1IiiI . i1IIi % o0oOOo0O0Ooo + I1IiiI + Oo0Ooo
  if 2 - 2: Oo0Ooo * iIii1I11I1II1 . o0oOOo0O0Ooo
  if 35 - 35: OoO0O00
  i1I1iI = I1Ii . instance_id
  if ( i1I1iI == - 1 ) : I1Ii . instance_id = eid . instance_id
  if 57 - 57: I11i
  oo0Oo0oo0o = eid . is_more_specific ( I1Ii )
  I1Ii . instance_id = i1I1iI
  if ( oo0Oo0oo0o ) :
   O00000o = 128 - I1Ii . mask_len
   break
   if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
   if 50 - 50: iIii1I11I1II1 + OoOoOO00 % O0 + OoO0O00 . i11iIiiIii / oO0o
 if ( O00000o == None ) : return ( None )
 if 31 - 31: I1IiiI % o0oOOo0O0Ooo . i11iIiiIii % OOooOOo - iIii1I11I1II1
 oOoO0 = eid . address
 oo00 = ""
 for o000o0O0Oo00 in range ( 0 , old_div ( O00000o , 16 ) ) :
  iI1ii11Ii = oOoO0 & 0xffff
  iI1ii11Ii = hex ( iI1ii11Ii ) [ 2 : : ]
  oo00 = iI1ii11Ii . zfill ( 4 ) + ":" + oo00
  oOoO0 >>= 16
  if 59 - 59: Ii1I - I1ii11iIi11i % Ii1I . iII111i
 if ( O00000o % 16 != 0 ) :
  iI1ii11Ii = oOoO0 & 0xff
  iI1ii11Ii = hex ( iI1ii11Ii ) [ 2 : : ]
  oo00 = iI1ii11Ii . zfill ( 2 ) + ":" + oo00
  if 78 - 78: I1ii11iIi11i
 return ( oo00 [ 0 : - 1 ] )
 if 69 - 69: iII111i
 if 87 - 87: ooOoO0o % OOooOOo - iII111i
 if 65 - 65: IiII + I1IiiI % I1Ii111 - oO0o
 if 81 - 81: I11i / iII111i
 if 15 - 15: OoOoOO00 - I11i - oO0o
 if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii * Ii1I . I11i - OoOoOO00 % iII111i
 if 19 - 19: OoOoOO00 + OOooOOo - o0oOOo0O0Ooo + i11iIiiIii . OOooOOo
 if 14 - 14: Ii1I - O0 - IiII % Ii1I / OoOoOO00 * OoooooooOO
 if 57 - 57: Oo0Ooo % Oo0Ooo % O0 . I1Ii111 % I1ii11iIi11i
 if 97 - 97: Oo0Ooo % OoO0O00 * I1ii11iIi11i * ooOoO0o * OoO0O00
 if 12 - 12: ooOoO0o
def lisp_lookup_public_key ( eid ) :
 i1I1iI = eid . instance_id
 if 56 - 56: i1IIi
 if 3 - 3: OOooOOo - Oo0Ooo * Ii1I + i11iIiiIii
 if 53 - 53: i1IIi % I1ii11iIi11i
 if 65 - 65: I11i + OoOoOO00 - i11iIiiIii
 if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
 OOi11I1IIi1I = lisp_get_eid_hash ( eid )
 if ( OOi11I1IIi1I == None ) : return ( [ None , None , False ] )
 if 75 - 75: II111iiii * Oo0Ooo + OOooOOo + Ii1I - I1ii11iIi11i
 OOi11I1IIi1I = "hash-" + OOi11I1IIi1I
 i1i1I11I1I = lisp_address ( LISP_AFI_NAME , OOi11I1IIi1I , len ( OOi11I1IIi1I ) , i1I1iI )
 i1I1IIIiII = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 if 97 - 97: iIii1I11I1II1 . iIii1I11I1II1 - IiII
 if 32 - 32: OoOoOO00 / i11iIiiIii / I1Ii111 . II111iiii + OOooOOo * ooOoO0o
 if 77 - 77: i11iIiiIii / OOooOOo % i11iIiiIii
 if 19 - 19: OoooooooOO - I1IiiI * OoO0O00
 Ooo000oOOooO00 = lisp_site_eid_lookup ( i1i1I11I1I , i1I1IIIiII , True )
 if ( Ooo000oOOooO00 == None ) : return ( [ i1i1I11I1I , None , False ] )
 if 65 - 65: OoooooooOO . I11i / I1ii11iIi11i / i11iIiiIii
 if 20 - 20: OoOoOO00 / OoO0O00 - Oo0Ooo + ooOoO0o
 if 86 - 86: O0 / II111iiii / ooOoO0o % I1ii11iIi11i / iIii1I11I1II1
 if 1 - 1: O0
 IiiIi1 = None
 for OO0Oo00oo in Ooo000oOOooO00 . registered_rlocs :
  OoO0ooo0O0 = OO0Oo00oo . json
  if ( OoO0ooo0O0 == None ) : continue
  try :
   OoO0ooo0O0 = json . loads ( OoO0ooo0O0 . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( OOi11I1IIi1I ) )
   if 26 - 26: Ii1I
   return ( [ i1i1I11I1I , None , False ] )
   if 1 - 1: OoOoOO00 . o0oOOo0O0Ooo + Oo0Ooo % Oo0Ooo * I1ii11iIi11i
  if ( "public-key" not in OoO0ooo0O0 ) : continue
  IiiIi1 = OoO0ooo0O0 [ "public-key" ]
  break
  if 50 - 50: IiII / i1IIi . I1ii11iIi11i
 return ( [ i1i1I11I1I , IiiIi1 , True ] )
 if 75 - 75: I11i * oO0o + OoooooooOO . iII111i + OoO0O00
 if 44 - 44: II111iiii
 if 65 - 65: I11i . iII111i . I1IiiI - Oo0Ooo % iIii1I11I1II1 / O0
 if 54 - 54: iII111i - I1Ii111
 if 88 - 88: iII111i * OoO0O00 % OoooooooOO / oO0o
 if 7 - 7: i1IIi
 if 30 - 30: oO0o . i1IIi / I11i
 if 23 - 23: i1IIi + oO0o % iII111i - OoO0O00 - i1IIi
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 74 - 74: Ii1I + I11i . OoooooooOO - I1ii11iIi11i
 if 2 - 2: oO0o - o0oOOo0O0Ooo
 if 80 - 80: i1IIi
 if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
 if 9 - 9: IiII * oO0o - o0oOOo0O0Ooo
 iIiI = json . loads ( rloc_record . json . json_string )
 if 17 - 17: iII111i % Oo0Ooo
 if ( lisp_get_eid_hash ( eid ) ) :
  OOooo = eid
 elif ( "signature-eid" in iIiI ) :
  Ii11IiiI = iIiI [ "signature-eid" ]
  OOooo = lisp_address ( LISP_AFI_IPV6 , Ii11IiiI , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 69 - 69: OoooooooOO - OoooooooOO * ooOoO0o / oO0o * iIii1I11I1II1 . II111iiii
  if 61 - 61: oO0o . I1IiiI + i1IIi
  if 69 - 69: O0 / i1IIi - OoOoOO00 + ooOoO0o - oO0o
  if 80 - 80: o0oOOo0O0Ooo % O0 * I11i . i1IIi - ooOoO0o
  if 93 - 93: OoooooooOO / o0oOOo0O0Ooo
 i1i1I11I1I , IiiIi1 , Oooo0 = lisp_lookup_public_key ( OOooo )
 if ( i1i1I11I1I == None ) :
  oOOoo = green ( OOooo . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( oOOoo ) )
  return ( False )
  if 57 - 57: OOooOOo
  if 76 - 76: Oo0Ooo . I1Ii111 + iII111i / OoooooooOO . Oo0Ooo
 OOOOoo0o0O0 = "found" if Oooo0 else bold ( "not found" , False )
 oOOoo = green ( i1i1I11I1I . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( oOOoo , OOOOoo0o0O0 ) )
 if ( Oooo0 == False ) : return ( False )
 if 64 - 64: O0 + IiII / ooOoO0o / OoooooooOO . II111iiii / ooOoO0o
 if ( IiiIi1 == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 77 - 77: OoO0O00
  if 23 - 23: I11i + o0oOOo0O0Ooo - Ii1I % OoooooooOO
 OOoO00 = IiiIi1 [ 0 : 8 ] + "..." + IiiIi1 [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( OOoO00 ) )
 if 75 - 75: Oo0Ooo . I1Ii111 / i11iIiiIii
 if 50 - 50: Oo0Ooo . i11iIiiIii
 if 73 - 73: I11i
 if 16 - 16: i1IIi - I1IiiI * oO0o
 if 93 - 93: i1IIi + I1ii11iIi11i % Oo0Ooo + iIii1I11I1II1 / II111iiii
 Oooo0OOO000oo0OO = iIiI [ "signature" ]
 if 46 - 46: iII111i + Ii1I . ooOoO0o - ooOoO0o % i1IIi
 try :
  iIiI = binascii . a2b_base64 ( Oooo0OOO000oo0OO )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 45 - 45: Oo0Ooo / I1Ii111 / i11iIiiIii / I1ii11iIi11i
  if 44 - 44: OoOoOO00 * Oo0Ooo
 OO00 = len ( iIiI )
 if ( OO00 & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( OO00 ) )
  return ( False )
  if 2 - 2: OoOoOO00 % IiII % OoO0O00 . i1IIi / I1Ii111 - iIii1I11I1II1
  if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
  if 65 - 65: iII111i . oO0o
  if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
  if 31 - 31: I11i - oO0o * ooOoO0o
 o0o000O0o = OOooo . print_address ( )
 if 64 - 64: I11i
 if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
 if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
 if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
 IiiIi1 = binascii . a2b_base64 ( IiiIi1 )
 try :
  oO0oOo = ecdsa . VerifyingKey . from_pem ( IiiIi1 )
 except :
  iI1II1I1i1 = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( iI1II1I1i1 ) )
  return ( False )
  if 51 - 51: ooOoO0o + oO0o
  if 13 - 13: IiII - OoO0O00 - ooOoO0o
  if 46 - 46: oO0o + I1ii11iIi11i - OoOoOO00
  if 15 - 15: OoooooooOO + ooOoO0o * I1ii11iIi11i
  if 6 - 6: OoooooooOO % i1IIi % II111iiii + ooOoO0o / IiII + Ii1I
  if 97 - 97: ooOoO0o / I1Ii111 * I1ii11iIi11i
  if 83 - 83: Ii1I + ooOoO0o
  if 46 - 46: OoOoOO00
  if 66 - 66: iII111i - O0 . I1Ii111 * i1IIi / OoO0O00 / II111iiii
  if 35 - 35: ooOoO0o * OOooOOo / I11i % I11i / OoooooooOO . I1Ii111
  if 70 - 70: I1ii11iIi11i % I1ii11iIi11i / oO0o
 try :
  iIi = oO0oOo . verify ( iIiI , o0o000O0o . encode ( ) , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( o0o000O0o ) )
  if 85 - 85: OoOoOO00 % I11i / Oo0Ooo + I11i - Oo0Ooo
  lprint ( "  Signature used '{}'" . format ( Oooo0OOO000oo0OO ) )
  return ( False )
  if 20 - 20: IiII
 return ( iIi )
 if 81 - 81: Oo0Ooo / I1Ii111
 if 20 - 20: o0oOOo0O0Ooo + ooOoO0o % i1IIi
 if 51 - 51: iII111i - ooOoO0o
 if 32 - 32: IiII - i11iIiiIii
 if 41 - 41: Ii1I % Ii1I * oO0o - I11i + iIii1I11I1II1 . ooOoO0o
 if 30 - 30: Ii1I * iII111i . II111iiii / i1IIi
 if 77 - 77: oO0o . IiII + I1ii11iIi11i . i1IIi
 if 49 - 49: I1Ii111 . OoooooooOO / o0oOOo0O0Ooo - iII111i - iII111i - i11iIiiIii
 if 37 - 37: OOooOOo
 if 79 - 79: I1Ii111 - OoO0O00 + ooOoO0o + oO0o . i11iIiiIii + i1IIi
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
 if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
 if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
 if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
 if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
 OOOoo00o0oOoo = [ ]
 for O0OooOooo in eid_list :
  for Iii1IIii1I1I1 in lisp_map_notify_queue :
   O0oo0o0Oo0oo = lisp_map_notify_queue [ Iii1IIii1I1I1 ]
   if ( O0OooOooo not in O0oo0o0Oo0oo . eid_list ) : continue
   if 83 - 83: I1IiiI * i11iIiiIii - I1ii11iIi11i + I11i
   OOOoo00o0oOoo . append ( Iii1IIii1I1I1 )
   II1i1II11iiIiii = O0oo0o0Oo0oo . retransmit_timer
   if ( II1i1II11iiIiii ) : II1i1II11iiIiii . cancel ( )
   if 1 - 1: O0 % Ii1I + OOooOOo + oO0o
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( O0oo0o0Oo0oo . nonce_key , green ( O0OooOooo , False ) ) )
   if 68 - 68: o0oOOo0O0Ooo . OOooOOo % IiII
   if 38 - 38: OOooOOo . II111iiii / i11iIiiIii - OOooOOo % ooOoO0o - I1IiiI
   if 92 - 92: OoOoOO00 - oO0o % o0oOOo0O0Ooo % OoooooooOO
   if 3 - 3: O0 / ooOoO0o . Ii1I
   if 41 - 41: Oo0Ooo / OoOoOO00 % I1Ii111 - O0
   if 19 - 19: I1IiiI % I1Ii111 - O0 . iIii1I11I1II1 . I11i % O0
   if 88 - 88: ooOoO0o
 for Iii1IIii1I1I1 in OOOoo00o0oOoo : lisp_map_notify_queue . pop ( Iii1IIii1I1I1 )
 return
 if 52 - 52: iIii1I11I1II1 % ooOoO0o * iIii1I11I1II1
 if 20 - 20: i11iIiiIii * I11i
 if 29 - 29: IiII / OOooOOo
 if 39 - 39: O0 + II111iiii
 if 94 - 94: OOooOOo % I1ii11iIi11i % O0 + iII111i
 if 62 - 62: iIii1I11I1II1 . OoOoOO00 / iIii1I11I1II1 + IiII
 if 31 - 31: Ii1I . OoO0O00 . Ii1I + OoO0O00 * iIii1I11I1II1 . iII111i
 if 42 - 42: O0 / oO0o % O0 . i1IIi % OOooOOo
def lisp_decrypt_map_register ( packet ) :
 if 13 - 13: I1IiiI % ooOoO0o + OOooOOo
 if 91 - 91: oO0o - ooOoO0o
 if 20 - 20: i1IIi . IiII / o0oOOo0O0Ooo / I11i
 if 27 - 27: ooOoO0o . ooOoO0o - Ii1I % i11iIiiIii
 if 74 - 74: I1Ii111 - II111iiii % o0oOOo0O0Ooo
 o00O0O0OoO = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 IiIiiI = ( o00O0O0OoO >> 13 ) & 0x1
 if ( IiIiiI == 0 ) : return ( packet )
 if 19 - 19: ooOoO0o * iII111i
 iII1I11IIII11 = ( o00O0O0OoO >> 14 ) & 0x7
 if 17 - 17: I1IiiI / OoOoOO00 . iIii1I11I1II1
 if 31 - 31: I1Ii111 - OOooOOo
 if 57 - 57: OoooooooOO
 if 90 - 90: OoOoOO00 - I1IiiI / oO0o . I11i
 try :
  iI11ii = lisp_ms_encryption_keys [ iII1I11IIII11 ]
  iI11ii = iI11ii . zfill ( 32 )
  Oo0OOOO0oOoo0 = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( iII1I11IIII11 ) )
  return ( None )
  if 96 - 96: Oo0Ooo . O0 . iII111i . i11iIiiIii / O0 . OoO0O00
  if 84 - 84: OoOoOO00 / OoOoOO00
 oooOo = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( oooOo , iII1I11IIII11 ) )
 if 68 - 68: Oo0Ooo * oO0o - IiII % i11iIiiIii * OOooOOo
 if 43 - 43: Oo0Ooo - OoOoOO00 * ooOoO0o - OOooOOo * Oo0Ooo
 if 68 - 68: O0 % i11iIiiIii / OoO0O00
 if 44 - 44: OoOoOO00 - I11i
 II11I = chacha . ChaCha ( iI11ii , Oo0OOOO0oOoo0 , 20 ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + II11I )
 if 71 - 71: o0oOOo0O0Ooo - I1Ii111
 if 45 - 45: II111iiii - OOooOOo / oO0o % O0 . iII111i . iII111i
 if 82 - 82: iIii1I11I1II1 % Oo0Ooo * i1IIi - I1Ii111 - I1ii11iIi11i / iII111i
 if 24 - 24: IiII
 if 95 - 95: IiII + OoOoOO00 * OOooOOo
 if 92 - 92: OoOoOO00 + ooOoO0o . iII111i
 if 59 - 59: iIii1I11I1II1 % I1Ii111 + I1ii11iIi11i . OoOoOO00 * Oo0Ooo / I1Ii111
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 41 - 41: i1IIi / IiII
 if 73 - 73: o0oOOo0O0Ooo % ooOoO0o
 if 72 - 72: OoO0O00 * OoOoOO00 % I1IiiI - OOooOOo . Oo0Ooo
 if 70 - 70: ooOoO0o . o0oOOo0O0Ooo * II111iiii - O0
 if 74 - 74: oO0o % I1IiiI / oO0o / Oo0Ooo / ooOoO0o
 if 29 - 29: ooOoO0o + iIii1I11I1II1 + OoO0O00 - o0oOOo0O0Ooo
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 74 - 74: II111iiii - II111iiii + ooOoO0o + Oo0Ooo % iIii1I11I1II1
 OOoO = lisp_map_register ( )
 I11I , packet = OOoO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 81 - 81: OoOoOO00 / iIii1I11I1II1 * I1IiiI / oO0o
 OOoO . sport = sport
 if 88 - 88: I1ii11iIi11i - i11iIiiIii - OoOoOO00
 OOoO . print_map_register ( )
 if 79 - 79: IiII
 if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
 if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
 if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
 Iiii1IIIii = True
 if ( OOoO . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  Iiii1IIIii = True
  if 83 - 83: o0oOOo0O0Ooo % oO0o + i1IIi + i11iIiiIii / I1ii11iIi11i
 if ( OOoO . alg_id == LISP_SHA_256_128_ALG_ID ) :
  Iiii1IIIii = False
  if 100 - 100: I1IiiI % ooOoO0o % OoooooooOO / i11iIiiIii + i11iIiiIii % IiII
  if 39 - 39: Ii1I % o0oOOo0O0Ooo + OOooOOo / iIii1I11I1II1
  if 40 - 40: iIii1I11I1II1 / iII111i % OOooOOo % i11iIiiIii
  if 57 - 57: II111iiii % OoO0O00 * i1IIi
  if 19 - 19: ooOoO0o . iIii1I11I1II1 + I1ii11iIi11i + I1ii11iIi11i / o0oOOo0O0Ooo . Oo0Ooo
 iiii11i1iIi = [ ]
 if 15 - 15: I1Ii111 - I1Ii111 * I1ii11iIi11i
 if 74 - 74: o0oOOo0O0Ooo / O0 + Ii1I
 if 99 - 99: IiII + i1IIi + IiII - iIii1I11I1II1 . iII111i
 if 4 - 4: I1ii11iIi11i % o0oOOo0O0Ooo * Oo0Ooo
 oOo00Oo = None
 iIii111II1 = packet
 iiIIii1 = [ ]
 oO0oooOOo = OOoO . record_count
 for o000o0O0Oo00 in range ( oO0oooOOo ) :
  oooO = lisp_eid_record ( )
  ooO0 = lisp_rloc_record ( )
  packet = oooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 68 - 68: Oo0Ooo
  oooO . print_record ( "  " , False )
  if 83 - 83: OOooOOo / iIii1I11I1II1 . OoO0O00 - oO0o % Oo0Ooo
  if 30 - 30: Ii1I . OoOoOO00 / oO0o . OoO0O00
  if 93 - 93: i11iIiiIii
  if 33 - 33: i1IIi % OoooooooOO + Oo0Ooo % I1IiiI / ooOoO0o
  Ooo000oOOooO00 = lisp_site_eid_lookup ( oooO . eid , oooO . group ,
 False )
  if 40 - 40: IiII % IiII
  IiIi11Iii1Ii = Ooo000oOOooO00 . print_eid_tuple ( ) if Ooo000oOOooO00 else None
  if 35 - 35: OoooooooOO % O0 * I1Ii111 - iIii1I11I1II1 % iII111i
  if 15 - 15: O0 - Ii1I + OoOoOO00
  if 93 - 93: OoO0O00
  if 68 - 68: OOooOOo
  if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
  if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
  if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
  if ( Ooo000oOOooO00 and Ooo000oOOooO00 . accept_more_specifics == False ) :
   if ( Ooo000oOOooO00 . eid_record_matches ( oooO ) == False ) :
    IiI1IIi = Ooo000oOOooO00 . parent_for_more_specifics
    if ( IiI1IIi ) : Ooo000oOOooO00 = IiI1IIi
    if 23 - 23: OOooOOo / OoOoOO00 / OoooooooOO + i1IIi % OoooooooOO
    if 15 - 15: o0oOOo0O0Ooo % I1ii11iIi11i / II111iiii
    if 50 - 50: oO0o * Ii1I % I1Ii111
    if 74 - 74: iIii1I11I1II1 - OOooOOo / I1Ii111 / ooOoO0o . oO0o % iIii1I11I1II1
    if 91 - 91: o0oOOo0O0Ooo . o0oOOo0O0Ooo - Ii1I
    if 60 - 60: i11iIiiIii . Oo0Ooo / iIii1I11I1II1 / II111iiii
    if 31 - 31: Oo0Ooo / Oo0Ooo / iIii1I11I1II1 / I11i % OoooooooOO
    if 90 - 90: I1IiiI
  iiOo0OOoOO00o = ( Ooo000oOOooO00 and Ooo000oOOooO00 . accept_more_specifics )
  if ( iiOo0OOoOO00o ) :
   iiIiiiI1i1I = lisp_site_eid ( Ooo000oOOooO00 . site )
   iiIiiiI1i1I . dynamic = True
   iiIiiiI1i1I . eid . copy_address ( oooO . eid )
   iiIiiiI1i1I . group . copy_address ( oooO . group )
   iiIiiiI1i1I . parent_for_more_specifics = Ooo000oOOooO00
   iiIiiiI1i1I . add_cache ( )
   iiIiiiI1i1I . inherit_from_ams_parent ( )
   Ooo000oOOooO00 . more_specific_registrations . append ( iiIiiiI1i1I )
   Ooo000oOOooO00 = iiIiiiI1i1I
  else :
   Ooo000oOOooO00 = lisp_site_eid_lookup ( oooO . eid , oooO . group ,
 True )
   if 47 - 47: OoO0O00 - I1Ii111 % ooOoO0o + O0 . iIii1I11I1II1 * i11iIiiIii
   if 16 - 16: I11i . ooOoO0o - Oo0Ooo / OoO0O00 . i1IIi
  oOOoo = oooO . print_eid_tuple ( )
  if 59 - 59: ooOoO0o - ooOoO0o % I11i + OoO0O00
  if ( Ooo000oOOooO00 == None ) :
   i1iiiiI1I = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( i1iiiiI1I , green ( oOOoo , False ) ,
 ", matched non-ams {}" . format ( green ( IiIi11Iii1Ii , False ) if IiIi11Iii1Ii else "" ) ) )
   if 88 - 88: Ii1I - ooOoO0o . Oo0Ooo
   if 83 - 83: I11i + Oo0Ooo . I1ii11iIi11i * I1ii11iIi11i
   if 80 - 80: i1IIi * I11i - OOooOOo / II111iiii * iIii1I11I1II1
   if 42 - 42: OoOoOO00 . I11i % II111iiii
   if 19 - 19: OoooooooOO
   packet = ooO0 . end_of_rlocs ( packet , oooO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 31 - 31: I11i . OoOoOO00 - O0 * iII111i % I1Ii111 - II111iiii
   continue
   if 21 - 21: OOooOOo . Oo0Ooo - i1IIi
   if 56 - 56: I11i
  oOo00Oo = Ooo000oOOooO00 . site
  if 24 - 24: I1IiiI . I1IiiI % ooOoO0o
  if ( iiOo0OOoOO00o ) :
   oOO = Ooo000oOOooO00 . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( oOO , False ) , oOo00Oo . site_name , green ( oOOoo , False ) ) )
   if 32 - 32: OOooOOo / i1IIi / OOooOOo
  else :
   oOO = green ( Ooo000oOOooO00 . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( oOO , oOo00Oo . site_name , green ( oOOoo , False ) ) )
   if 97 - 97: ooOoO0o * Oo0Ooo * OoooooooOO * I1IiiI
   if 45 - 45: Oo0Ooo
   if 27 - 27: oO0o / IiII - iIii1I11I1II1 / o0oOOo0O0Ooo % OOooOOo * iIii1I11I1II1
   if 40 - 40: oO0o - II111iiii * OOooOOo % OoooooooOO
   if 52 - 52: OOooOOo + OoO0O00
   if 96 - 96: OOooOOo % O0 - Oo0Ooo % oO0o / I1IiiI . i1IIi
  if ( oOo00Oo . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( oOo00Oo . site_name ) )
   packet = ooO0 . end_of_rlocs ( packet , oooO . rloc_count )
   continue
   if 42 - 42: i1IIi
   if 52 - 52: OoO0O00 % iII111i % O0
   if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
   if 50 - 50: oO0o . I1Ii111
   if 38 - 38: iIii1I11I1II1 . Ii1I
   if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
   if 15 - 15: O0
   if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
  IIIOo0O = OOoO . key_id
  if ( IIIOo0O in oOo00Oo . auth_key ) :
   I1Ii11Ii = oOo00Oo . auth_key [ IIIOo0O ]
  else :
   I1Ii11Ii = ""
   if 37 - 37: ooOoO0o . I1IiiI
   if 1 - 1: iIii1I11I1II1 . o0oOOo0O0Ooo % I11i
  oO0OoO0OO = lisp_verify_auth ( I11I , OOoO . alg_id ,
 OOoO . auth_data , I1Ii11Ii )
  i1III1iiiIIi1 = "dynamic " if Ooo000oOOooO00 . dynamic else ""
  if 15 - 15: o0oOOo0O0Ooo + IiII * Oo0Ooo / OOooOOo
  ii1I11 = bold ( "passed" if oO0OoO0OO else "failed" , False )
  IIIOo0O = "key-id {}" . format ( IIIOo0O ) if IIIOo0O == OOoO . key_id else "bad key-id {}" . format ( OOoO . key_id )
  if 68 - 68: oO0o . OoOoOO00 * Oo0Ooo / I1Ii111
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( ii1I11 , i1III1iiiIIi1 , green ( oOOoo , False ) , IIIOo0O ) )
  if 71 - 71: I1IiiI . ooOoO0o - OOooOOo / OoooooooOO
  if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
  if 60 - 60: oO0o * I1Ii111
  if 81 - 81: oO0o - OOooOOo - oO0o
  if 54 - 54: oO0o % I11i
  if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
  iiiii11i = True
  I1Ioo = ( lisp_get_eid_hash ( oooO . eid ) != None )
  if ( I1Ioo or Ooo000oOOooO00 . require_signature ) :
   oO000ooOO0 = "Required " if Ooo000oOOooO00 . require_signature else ""
   oOOoo = green ( oOOoo , False )
   OO0Oo00oo = lisp_find_sig_in_rloc_set ( packet , oooO . rloc_count )
   if ( OO0Oo00oo == None ) :
    iiiii11i = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( oO000ooOO0 ,
    # OoOoOO00 . IiII * oO0o - OOooOOo / i11iIiiIii
 bold ( "failed" , False ) , oOOoo ) )
   else :
    iiiii11i = lisp_verify_cga_sig ( oooO . eid , OO0Oo00oo )
    ii1I11 = bold ( "passed" if iiiii11i else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( oO000ooOO0 , ii1I11 , oOOoo ) )
    if 3 - 3: iII111i + oO0o * OoOoOO00 / ooOoO0o % II111iiii
    if 81 - 81: I11i
    if 28 - 28: i11iIiiIii . OoooooooOO . iIii1I11I1II1 . Ii1I / i1IIi
    if 3 - 3: i11iIiiIii % Ii1I
  if ( oO0OoO0OO == False or iiiii11i == False ) :
   packet = ooO0 . end_of_rlocs ( packet , oooO . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 10 - 10: iII111i * oO0o + O0
   continue
   if 35 - 35: OoOoOO00 . oO0o / II111iiii
   if 97 - 97: Ii1I + I1Ii111 / II111iiii
   if 14 - 14: iII111i / IiII / oO0o
   if 55 - 55: OoO0O00 % O0
   if 92 - 92: OoooooooOO / O0
   if 14 - 14: i11iIiiIii
  if ( OOoO . merge_register_requested ) :
   IiI1IIi = Ooo000oOOooO00
   IiI1IIi . inconsistent_registration = False
   if 43 - 43: OOooOOo
   if 79 - 79: iII111i % Oo0Ooo . i1IIi % ooOoO0o
   if 93 - 93: OoOoOO00
   if 49 - 49: i1IIi * OOooOOo % I11i * Ii1I . I1Ii111 * iIii1I11I1II1
   if 72 - 72: ooOoO0o
   if ( Ooo000oOOooO00 . group . is_null ( ) ) :
    if ( IiI1IIi . site_id != OOoO . site_id ) :
     IiI1IIi . site_id = OOoO . site_id
     IiI1IIi . registered = False
     IiI1IIi . individual_registrations = { }
     IiI1IIi . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 63 - 63: Oo0Ooo . OoO0O00 . OoooooooOO / i1IIi
     if 53 - 53: OOooOOo * O0 . iII111i
     if 3 - 3: OoooooooOO * I1Ii111 * IiII - OOooOOo * I1Ii111
   oO0oOo = OOoO . xtr_id
   if ( oO0oOo in Ooo000oOOooO00 . individual_registrations ) :
    Ooo000oOOooO00 = Ooo000oOOooO00 . individual_registrations [ oO0oOo ]
   else :
    Ooo000oOOooO00 = lisp_site_eid ( oOo00Oo )
    Ooo000oOOooO00 . eid . copy_address ( IiI1IIi . eid )
    Ooo000oOOooO00 . group . copy_address ( IiI1IIi . group )
    Ooo000oOOooO00 . encrypt_json = IiI1IIi . encrypt_json
    IiI1IIi . individual_registrations [ oO0oOo ] = Ooo000oOOooO00
    if 78 - 78: iII111i
  else :
   Ooo000oOOooO00 . inconsistent_registration = Ooo000oOOooO00 . merge_register_requested
   if 80 - 80: i1IIi * I1IiiI + OOooOOo
   if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
   if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
  Ooo000oOOooO00 . map_registers_received += 1
  if 63 - 63: O0
  if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
  if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
  if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
  if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
  iI1II1I1i1 = ( Ooo000oOOooO00 . is_rloc_in_rloc_set ( source ) == False )
  if ( oooO . record_ttl == 0 and iI1II1I1i1 ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 74 - 74: i11iIiiIii
   continue
   if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
   if 6 - 6: I11i
   if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
   if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
   if 6 - 6: Ii1I
   if 60 - 60: iII111i + I1IiiI
  IiiI1Ii11i = Ooo000oOOooO00 . registered_rlocs
  Ooo000oOOooO00 . registered_rlocs = [ ]
  if 11 - 11: o0oOOo0O0Ooo + iIii1I11I1II1 - OoooooooOO
  if 29 - 29: IiII
  if 22 - 22: I1IiiI * oO0o / Oo0Ooo
  if 40 - 40: I1ii11iIi11i . I1Ii111 / I1IiiI
  Ooo0O00OoO = packet
  for oO0OO in range ( oooO . rloc_count ) :
   ooO0 = lisp_rloc_record ( )
   packet = ooO0 . decode ( packet , None , Ooo000oOOooO00 . encrypt_json )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 56 - 56: I1IiiI % II111iiii + o0oOOo0O0Ooo - ooOoO0o * OoO0O00
   ooO0 . print_record ( "    " )
   if 59 - 59: OoOoOO00 / I1IiiI % IiII - O0 * I11i + I1ii11iIi11i
   if 93 - 93: Oo0Ooo . I1IiiI - ooOoO0o . o0oOOo0O0Ooo / IiII . OoO0O00
   if 38 - 38: i11iIiiIii - i11iIiiIii % OOooOOo % OoO0O00
   if 1 - 1: o0oOOo0O0Ooo + iII111i % i11iIiiIii - OoO0O00 / I1IiiI % IiII
   if ( len ( oOo00Oo . allowed_rlocs ) > 0 ) :
    O00oO000Oo0 = ooO0 . rloc . print_address ( )
    if ( O00oO000Oo0 not in oOo00Oo . allowed_rlocs ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( O00oO000Oo0 , False ) ) )
     if 63 - 63: oO0o
     if 16 - 16: Ii1I . I1ii11iIi11i % OoooooooOO
     Ooo000oOOooO00 . registered = False
     packet = ooO0 . end_of_rlocs ( packet ,
 oooO . rloc_count - oO0OO - 1 )
     break
     if 82 - 82: iII111i / IiII * OoOoOO00 . ooOoO0o / O0
     if 88 - 88: IiII / I1IiiI - OOooOOo . I1Ii111
     if 28 - 28: i1IIi - I1IiiI * ooOoO0o * o0oOOo0O0Ooo / OOooOOo
     if 58 - 58: oO0o - OoO0O00 % I1Ii111 + I1Ii111
     if 65 - 65: iIii1I11I1II1 + OOooOOo % iIii1I11I1II1 / i11iIiiIii
     if 70 - 70: O0
   OO0Oo00oo = lisp_rloc ( )
   OO0Oo00oo . store_rloc_from_record ( ooO0 , None , source )
   if 67 - 67: Ii1I + II111iiii . i1IIi - i11iIiiIii + o0oOOo0O0Ooo
   if 72 - 72: OOooOOo . ooOoO0o / Ii1I / iIii1I11I1II1 - IiII - ooOoO0o
   if 7 - 7: OoOoOO00 + i1IIi % ooOoO0o * I11i + i11iIiiIii / II111iiii
   if 2 - 2: O0 / o0oOOo0O0Ooo - OoO0O00 * II111iiii
   if 4 - 4: I1IiiI + Oo0Ooo . iIii1I11I1II1
   if 100 - 100: i11iIiiIii
   if ( source . is_exact_match ( OO0Oo00oo . rloc ) ) :
    OO0Oo00oo . map_notify_requested = OOoO . map_notify_requested
    if 21 - 21: OoOoOO00 + iII111i . OoO0O00
    if 79 - 79: i11iIiiIii - OoO0O00 * OoO0O00 * i1IIi / iIii1I11I1II1 + iII111i
    if 27 - 27: iII111i / Ii1I / iII111i + OoooooooOO - O0 + OoO0O00
    if 62 - 62: iIii1I11I1II1
    if 60 - 60: Oo0Ooo % IiII % OoO0O00 - i11iIiiIii
   Ooo000oOOooO00 . registered_rlocs . append ( OO0Oo00oo )
   if 53 - 53: i11iIiiIii + OoooooooOO
   if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  oooOO = ( Ooo000oOOooO00 . do_rloc_sets_match ( IiiI1Ii11i ) == False )
  if 43 - 43: IiII + OOooOOo
  if 27 - 27: o0oOOo0O0Ooo / I11i + i11iIiiIii + O0 - Ii1I
  if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  if 17 - 17: I1Ii111
  if 2 - 2: O0 % OoOoOO00 + oO0o
  if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
  if ( OOoO . map_register_refresh and oooOO and
 Ooo000oOOooO00 . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   Ooo000oOOooO00 . registered_rlocs = IiiI1Ii11i
   continue
   if 51 - 51: IiII
   if 31 - 31: I11i - iIii1I11I1II1 * Ii1I + Ii1I
   if 10 - 10: OoOoOO00 - i11iIiiIii % iIii1I11I1II1 / ooOoO0o * i11iIiiIii - Ii1I
   if 64 - 64: II111iiii . i11iIiiIii . iII111i . OOooOOo
   if 95 - 95: O0 - OoOoOO00
   if 68 - 68: ooOoO0o . I1Ii111
  if ( Ooo000oOOooO00 . registered == False ) :
   Ooo000oOOooO00 . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 84 - 84: OoooooooOO + oO0o % i1IIi + o0oOOo0O0Ooo * i1IIi
  Ooo000oOOooO00 . last_registered = lisp_get_timestamp ( )
  Ooo000oOOooO00 . registered = ( oooO . record_ttl != 0 )
  Ooo000oOOooO00 . last_registerer = source
  if 51 - 51: oO0o . OoooooooOO + OOooOOo * I1ii11iIi11i - ooOoO0o
  if 41 - 41: Oo0Ooo
  if 46 - 46: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii . iII111i
  if 66 - 66: oO0o % i1IIi % OoooooooOO
  Ooo000oOOooO00 . auth_sha1_or_sha2 = Iiii1IIIii
  Ooo000oOOooO00 . proxy_reply_requested = OOoO . proxy_reply_requested
  Ooo000oOOooO00 . lisp_sec_present = OOoO . lisp_sec_present
  Ooo000oOOooO00 . map_notify_requested = OOoO . map_notify_requested
  Ooo000oOOooO00 . mobile_node_requested = OOoO . mobile_node
  Ooo000oOOooO00 . merge_register_requested = OOoO . merge_register_requested
  if 58 - 58: OOooOOo
  Ooo000oOOooO00 . use_register_ttl_requested = OOoO . use_ttl_for_timeout
  if ( Ooo000oOOooO00 . use_register_ttl_requested ) :
   Ooo000oOOooO00 . register_ttl = oooO . store_ttl ( )
  else :
   Ooo000oOOooO00 . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 89 - 89: iIii1I11I1II1 - i1IIi
  Ooo000oOOooO00 . xtr_id_present = OOoO . xtr_id_present
  if ( Ooo000oOOooO00 . xtr_id_present ) :
   Ooo000oOOooO00 . xtr_id = OOoO . xtr_id
   Ooo000oOOooO00 . site_id = OOoO . site_id
   if 26 - 26: OOooOOo - iII111i * I1ii11iIi11i / iII111i
   if 9 - 9: I1Ii111 / II111iiii * I1Ii111 / I11i - OoO0O00
   if 36 - 36: IiII . OoOoOO00 . Ii1I
   if 31 - 31: iIii1I11I1II1
   if 84 - 84: I1ii11iIi11i - iII111i * I1IiiI
  if ( OOoO . merge_register_requested ) :
   if ( IiI1IIi . merge_in_site_eid ( Ooo000oOOooO00 ) ) :
    iiii11i1iIi . append ( [ oooO . eid , oooO . group ] )
    if 88 - 88: OOooOOo / Oo0Ooo
   if ( OOoO . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , IiI1IIi , OOoO ,
 oooO )
    if 31 - 31: II111iiii
    if 32 - 32: o0oOOo0O0Ooo % o0oOOo0O0Ooo
    if 67 - 67: IiII + oO0o * IiII
  if ( oooOO == False ) : continue
  if ( len ( iiii11i1iIi ) != 0 ) : continue
  if 26 - 26: I1ii11iIi11i + i1IIi . i1IIi - oO0o + I1IiiI * o0oOOo0O0Ooo
  iiIIii1 . append ( Ooo000oOOooO00 . print_eid_tuple ( ) )
  if 62 - 62: ooOoO0o + ooOoO0o % I11i
  if 100 - 100: II111iiii . OoooooooOO
  if 32 - 32: I11i % OOooOOo * O0 / iIii1I11I1II1 / i1IIi
  if 87 - 87: OoO0O00 . I1ii11iIi11i * I1IiiI
  if 83 - 83: OOooOOo
  if 86 - 86: I1Ii111 / oO0o
  if 67 - 67: OoOoOO00 + Oo0Ooo / i11iIiiIii . I1IiiI
  OO00000 = copy . deepcopy ( oooO )
  oooO = oooO . encode ( )
  oooO += Ooo0O00OoO
  II1iiiiIIIII = [ Ooo000oOOooO00 . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 16 - 16: oO0o
  for OO0Oo00oo in IiiI1Ii11i :
   if ( OO0Oo00oo . map_notify_requested == False ) : continue
   if ( OO0Oo00oo . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , oooO , II1iiiiIIIII , 1 , OO0Oo00oo . rloc ,
 LISP_CTRL_PORT , OOoO . nonce , OOoO . key_id ,
 OOoO . alg_id , OOoO . auth_len , oOo00Oo , False )
   if 81 - 81: iIii1I11I1II1 + o0oOOo0O0Ooo . I1ii11iIi11i % o0oOOo0O0Ooo % I11i
   if 10 - 10: O0
   if 96 - 96: iIii1I11I1II1 / I11i % iIii1I11I1II1 / oO0o
   if 42 - 42: I1ii11iIi11i - OOooOOo
   if 99 - 99: OoooooooOO % OOooOOo / I11i
  lisp_notify_subscribers ( lisp_sockets , OO00000 , Ooo0O00OoO ,
 Ooo000oOOooO00 . eid , oOo00Oo )
  if 77 - 77: II111iiii - IiII % OOooOOo
  if 22 - 22: OoooooooOO / oO0o
  if 78 - 78: oO0o * I11i . i1IIi % i1IIi + i1IIi / OOooOOo
  if 66 - 66: OoooooooOO % o0oOOo0O0Ooo / I11i * I1Ii111
  if 12 - 12: I1Ii111
 if ( len ( iiii11i1iIi ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , iiii11i1iIi )
  if 17 - 17: I1Ii111 % oO0o + O0
  if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
  if 59 - 59: iII111i + O0 - I1ii11iIi11i * I1ii11iIi11i + iIii1I11I1II1
  if 41 - 41: iIii1I11I1II1 . O0 - ooOoO0o / OoOoOO00 % iIii1I11I1II1 + IiII
  if 23 - 23: OoOoOO00 + ooOoO0o . i11iIiiIii
  if 39 - 39: OoOoOO00 - I1ii11iIi11i / I1Ii111
 if ( OOoO . merge_register_requested ) : return
 if 48 - 48: IiII - oO0o + I11i % o0oOOo0O0Ooo
 if 81 - 81: Oo0Ooo . I1Ii111 * iIii1I11I1II1
 if 60 - 60: OoooooooOO
 if 41 - 41: iIii1I11I1II1 + O0 % o0oOOo0O0Ooo - IiII . I11i * O0
 if 39 - 39: i11iIiiIii . Ii1I
 if ( OOoO . map_notify_requested and oOo00Oo != None ) :
  lisp_build_map_notify ( lisp_sockets , iIii111II1 , iiIIii1 ,
 OOoO . record_count , source , sport , OOoO . nonce ,
 OOoO . key_id , OOoO . alg_id , OOoO . auth_len ,
 oOo00Oo , True )
  if 68 - 68: OOooOOo * ooOoO0o . I1IiiI - iII111i
 return
 if 81 - 81: I11i % Oo0Ooo / iII111i
 if 44 - 44: Oo0Ooo
 if 90 - 90: Oo0Ooo . ooOoO0o / IiII * I1Ii111 . ooOoO0o + II111iiii
 if 43 - 43: iIii1I11I1II1 % OOooOOo + OoOoOO00 + I1ii11iIi11i - Oo0Ooo / Ii1I
 if 94 - 94: Ii1I / Oo0Ooo % II111iiii % Oo0Ooo * oO0o
 if 54 - 54: O0 / ooOoO0o * I1Ii111
 if 5 - 5: Ii1I / OoOoOO00 - O0 * OoO0O00
 if 13 - 13: IiII + Oo0Ooo - I1Ii111
def lisp_process_unicast_map_notify ( lisp_sockets , packet , source ) :
 O0oo0o0Oo0oo = lisp_map_notify ( "" )
 packet = O0oo0o0Oo0oo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 10 - 10: OOooOOo % OoooooooOO / I1IiiI . II111iiii % iII111i
  if 47 - 47: o0oOOo0O0Ooo . i11iIiiIii * i1IIi % I11i - ooOoO0o * oO0o
 O0oo0o0Oo0oo . print_notify ( )
 if ( O0oo0o0Oo0oo . record_count == 0 ) : return
 if 95 - 95: oO0o / Ii1I + OoO0O00
 Oo00OOo = O0oo0o0Oo0oo . eid_records
 ooO0 = lisp_rloc_record ( )
 if 77 - 77: OoooooooOO + OoOoOO00
 for o000o0O0Oo00 in range ( O0oo0o0Oo0oo . record_count ) :
  oooO = lisp_eid_record ( )
  Oo00OOo = oooO . decode ( Oo00OOo )
  if ( packet == None ) : return
  oooO . print_record ( "  " , False )
  oOOoo = oooO . print_eid_tuple ( )
  OooO = oooO . rloc_count
  if 41 - 41: IiII * o0oOOo0O0Ooo
  if 7 - 7: o0oOOo0O0Ooo * OoO0O00 - I1Ii111 % i1IIi % Ii1I
  if 11 - 11: OoO0O00 - OOooOOo + I1ii11iIi11i * Oo0Ooo
  if 11 - 11: i1IIi - OoooooooOO * OoOoOO00 / oO0o - OoooooooOO - I1IiiI
  if 22 - 22: i11iIiiIii . Ii1I . Oo0Ooo * Oo0Ooo - iII111i / I1ii11iIi11i
  Ii111 = lisp_map_cache_lookup ( oooO . eid , oooO . eid )
  if ( Ii111 == None ) :
   oOO = green ( oOOoo , False )
   lprint ( "Ignoring Map-Notify EID {}, no subscribe-request entry" . format ( oOO ) )
   if 49 - 49: iII111i + I11i . Oo0Ooo
   Oo00OOo = ooO0 . end_of_rlocs ( Oo00OOo , OooO )
   continue
   if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
   if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
   if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
   if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
   if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
   if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
   if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
  if ( Ii111 . action != LISP_SEND_PUBSUB_ACTION ) :
   if ( Ii111 . subscribed_eid == None ) :
    oOO = green ( oOOoo , False )
    lprint ( "Ignoring Map-Notify for non-subscribed EID {}" . format ( oOO ) )
    if 1 - 1: i11iIiiIii
    Oo00OOo = ooO0 . end_of_rlocs ( Oo00OOo , OooO )
    continue
    if 1 - 1: iIii1I11I1II1
    if 73 - 73: iII111i + IiII
    if 95 - 95: O0
    if 75 - 75: ooOoO0o
    if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
    if 85 - 85: ooOoO0o
    if 29 - 29: iII111i . Ii1I
    if 43 - 43: I11i - I1ii11iIi11i + iIii1I11I1II1 / I1ii11iIi11i * oO0o / iIii1I11I1II1
  iI1ii11Iiiii = [ ]
  if ( Ii111 . action == LISP_SEND_PUBSUB_ACTION ) :
   Ii111 = lisp_mapping ( oooO . eid , oooO . group , [ ] )
   Ii111 . add_cache ( )
   OO0 = copy . deepcopy ( oooO . eid )
   iIi11I1i1i1 = copy . deepcopy ( oooO . group )
  else :
   OO0 = Ii111 . subscribed_eid
   iIi11I1i1i1 = Ii111 . subscribed_group
   iI1ii11Iiiii = Ii111 . rloc_set
   Ii111 . delete_rlocs_from_rloc_probe_list ( )
   Ii111 . rloc_set = [ ]
   if 66 - 66: i1IIi
   if 97 - 97: OoOoOO00 . I1IiiI
   if 51 - 51: OOooOOo . i11iIiiIii / i11iIiiIii
   if 10 - 10: iIii1I11I1II1 % i1IIi
   if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
  Ii111 . mapping_source = None if source == "lisp-itr" else source
  Ii111 . map_cache_ttl = oooO . store_ttl ( )
  Ii111 . subscribed_eid = OO0
  Ii111 . subscribed_group = iIi11I1i1i1
  if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
  if 44 - 44: I1ii11iIi11i
  if 39 - 39: iII111i + Oo0Ooo / oO0o
  if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
  if 99 - 99: I1IiiI * II111iiii
  if ( len ( iI1ii11Iiiii ) != 0 and oooO . rloc_count == 0 ) :
   Ii111 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , Ii111 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( oOOoo , False ) ) )
   if 84 - 84: II111iiii - I1IiiI
   Oo00OOo = ooO0 . end_of_rlocs ( Oo00OOo , OooO )
   continue
   if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
   if 35 - 35: I11i + i1IIi
   if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
   if 97 - 97: oO0o % iIii1I11I1II1
   if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
   if 16 - 16: I1IiiI
   if 39 - 39: ooOoO0o * II111iiii
  iiI1ooOOOoo = oo0oo0ooOO000 = 0
  for oO0OO in range ( OooO ) :
   ooO0 = lisp_rloc_record ( )
   Oo00OOo = ooO0 . decode ( Oo00OOo , None )
   ooO0 . print_record ( "    " )
   if 53 - 53: iII111i % OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
   if 55 - 55: i1IIi
   if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
   if 88 - 88: O0
   OOOOoo0o0O0 = False
   for IIIIiiI1iIiI in iI1ii11Iiiii :
    if ( IIIIiiI1iIiI . rloc . is_exact_match ( ooO0 . rloc ) ) :
     OOOOoo0o0O0 = True
     break
     if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
     if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
   if ( OOOOoo0o0O0 ) :
    OO0Oo00oo = copy . deepcopy ( IIIIiiI1iIiI )
    oo0oo0ooOO000 += 1
   else :
    OO0Oo00oo = lisp_rloc ( )
    iiI1ooOOOoo += 1
    if 90 - 90: i11iIiiIii - iII111i * oO0o
    if 79 - 79: IiII
    if 38 - 38: I1Ii111
    if 56 - 56: i11iIiiIii
    if 58 - 58: i11iIiiIii / OoOoOO00
   OO0Oo00oo . store_rloc_from_record ( ooO0 , None , Ii111 . mapping_source )
   Ii111 . rloc_set . append ( OO0Oo00oo )
   if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
   if 39 - 39: Oo0Ooo . OoO0O00
  lprint ( "Update {} map-cache entry with {}/{} new/replaced RLOCs" . format ( green ( oOOoo , False ) , iiI1ooOOOoo , oo0oo0ooOO000 ) )
  if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
  if 100 - 100: ooOoO0o / OoooooooOO
  if 73 - 73: i11iIiiIii - Oo0Ooo
  if 100 - 100: iIii1I11I1II1 + I1Ii111
  if 51 - 51: o0oOOo0O0Ooo * I11i
  Ii111 . build_best_rloc_set ( )
  lisp_write_ipc_map_cache ( True , Ii111 )
  if 42 - 42: OOooOOo % I11i
  if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
  if 81 - 81: I1IiiI
  if 82 - 82: I1Ii111 - OoooooooOO - Ii1I
  if 34 - 34: OOooOOo . iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
  if 83 - 83: iII111i - I1ii11iIi11i + iII111i
 oo0Oo0oo0o = lisp_get_map_server ( source )
 if ( oo0Oo0oo0o == None ) :
  lprint ( "Cannot find Map-Server for Map-Notify source address {}" . format ( source . print_address_no_iid ( ) ) )
  if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
  return
  if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
 lisp_send_map_notify_ack ( lisp_sockets , Oo00OOo , O0oo0o0Oo0oo , oo0Oo0oo0o )
 if 20 - 20: IiII - OOooOOo + OoOoOO00
 if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
 if 74 - 74: OoO0O00
 if 13 - 13: I1ii11iIi11i / OoO0O00
 if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
 if 94 - 94: IiII * i1IIi
 if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
 if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
 if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
 if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
def lisp_process_multicast_map_notify ( packet , source ) :
 O0oo0o0Oo0oo = lisp_map_notify ( "" )
 packet = O0oo0o0Oo0oo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
  if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
 O0oo0o0Oo0oo . print_notify ( )
 if ( O0oo0o0Oo0oo . record_count == 0 ) : return
 if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
 Oo00OOo = O0oo0o0Oo0oo . eid_records
 if 66 - 66: i1IIi
 for o000o0O0Oo00 in range ( O0oo0o0Oo0oo . record_count ) :
  oooO = lisp_eid_record ( )
  Oo00OOo = oooO . decode ( Oo00OOo )
  if ( packet == None ) : return
  oooO . print_record ( "  " , False )
  if 98 - 98: Oo0Ooo / iIii1I11I1II1
  if 33 - 33: O0 - iII111i
  if 40 - 40: iII111i * I11i
  if 25 - 25: O0 * o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  Ii111 = lisp_map_cache_lookup ( oooO . eid , oooO . group )
  if ( Ii111 == None or Ii111 . action == LISP_SEND_PUBSUB_ACTION ) :
   if ( Ii111 == None ) :
    ooO00OO , O0O0oOO , IIIIIi1I1Ii = lisp_allow_gleaning ( oooO . eid ,
 oooO . group , None )
    if ( ooO00OO == False ) : continue
    if 93 - 93: IiII
    if 90 - 90: Ii1I % o0oOOo0O0Ooo * i1IIi . IiII % i1IIi
   Ii111 = lisp_mapping ( oooO . eid , oooO . group , [ ] )
   Ii111 . add_cache ( )
   if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
   if 87 - 87: I11i
   if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
   if 72 - 72: OoO0O00 * Oo0Ooo - IiII
   if 74 - 74: Ii1I
   if 26 - 26: I11i . O0
   if 68 - 68: Ii1I
  if ( Ii111 . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( Ii111 . print_eid_tuple ( ) , False ) ) )
   if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
   continue
   if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
   if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
  Ii111 . mapping_source = None if source == "lisp-etr" else source
  Ii111 . map_cache_ttl = oooO . store_ttl ( )
  if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
  if 44 - 44: I11i * iIii1I11I1II1 . I1ii11iIi11i
  if 9 - 9: o0oOOo0O0Ooo
  if 23 - 23: ooOoO0o * OoO0O00 + O0 % I1Ii111
  if 21 - 21: Ii1I * OoOoOO00
  if ( len ( Ii111 . rloc_set ) != 0 and oooO . rloc_count == 0 ) :
   Ii111 . rloc_set = [ ]
   Ii111 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , Ii111 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( Ii111 . print_eid_tuple ( ) , False ) ) )
   if 29 - 29: iIii1I11I1II1 / ooOoO0o
   continue
   if 75 - 75: OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
   if 88 - 88: OoO0O00 % Ii1I
  iiiIii1 = Ii111 . rtrs_in_rloc_set ( )
  if 95 - 95: I1IiiI / OoooooooOO
  if 29 - 29: OoOoOO00
  if 100 - 100: o0oOOo0O0Ooo - I1IiiI / I11i
  if 43 - 43: o0oOOo0O0Ooo % iIii1I11I1II1
  if 85 - 85: oO0o + OoooooooOO - IiII % o0oOOo0O0Ooo * ooOoO0o * II111iiii
  for oO0OO in range ( oooO . rloc_count ) :
   ooO0 = lisp_rloc_record ( )
   Oo00OOo = ooO0 . decode ( Oo00OOo , None )
   ooO0 . print_record ( "    " )
   if ( oooO . group . is_null ( ) ) : continue
   if ( ooO0 . rle == None ) : continue
   if 4 - 4: Ii1I . i1IIi + Oo0Ooo % I11i . OoO0O00
   if 70 - 70: OOooOOo * OoOoOO00 / OoOoOO00 / OoOoOO00
   if 23 - 23: I1IiiI
   if 24 - 24: I1Ii111 * i1IIi % O0 * Ii1I + iII111i
   OO0Oo00oo = lisp_rloc ( )
   OO0Oo00oo . store_rloc_from_record ( ooO0 , None , Ii111 . mapping_source )
   if 14 - 14: oO0o * iII111i + Ii1I + Ii1I * IiII
   if 82 - 82: IiII * ooOoO0o / OOooOOo + OoOoOO00
   if 32 - 32: IiII
   if 90 - 90: I1ii11iIi11i / I11i * o0oOOo0O0Ooo % O0 * i11iIiiIii
   if 68 - 68: I11i . Ii1I + I11i / IiII . I11i / iIii1I11I1II1
   I1iII1 = Ii111 . rloc_set [ 0 ] if ( Ii111 . rloc_set != [ ] ) else None
   if ( I1iII1 != None ) :
    for ooiI1IiII in OO0Oo00oo . rle . rle_nodes :
     OO0OO0O = I1iII1 . get_rle ( ooiI1IiII . rloc . rloc )
     if ( OO0OO0O == None ) : continue
     ooiI1IiII . rloc . uptime = OO0OO0O . uptime
     ooiI1IiII . rloc . stats = copy . deepcopy ( OO0OO0O . stats )
     ooiI1IiII . rloc . copy_rloc_probe_recents ( OO0OO0O )
     if 74 - 74: OoOoOO00 % IiII . O0
     if 92 - 92: O0 / O0 * I11i + I1Ii111
     if 80 - 80: Oo0Ooo - IiII . I11i * I11i
   if ( iiiIii1 and OO0Oo00oo . is_rtr ( ) == False ) : continue
   if 21 - 21: OoOoOO00
   Ii111 . rloc_set = [ OO0Oo00oo ]
   Ii111 . action = LISP_NO_ACTION
   Ii111 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , Ii111 )
   if 52 - 52: OoO0O00 - ooOoO0o * I1ii11iIi11i
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( Ii111 . print_eid_tuple ( ) , False ) ,
   # i1IIi . I1Ii111
 OO0Oo00oo . rle . print_rle ( False , True ) ) )
   if 94 - 94: ooOoO0o - IiII
   if 92 - 92: Ii1I . i11iIiiIii
 return
 if 45 - 45: ooOoO0o * I1IiiI / iII111i
 if 29 - 29: i1IIi + Ii1I * OoO0O00
 if 69 - 69: Ii1I - OOooOOo * I11i . I1IiiI + o0oOOo0O0Ooo / OoO0O00
 if 45 - 45: OOooOOo
 if 57 - 57: iIii1I11I1II1 + IiII - I1IiiI
 if 64 - 64: II111iiii . IiII / I1IiiI
 if 20 - 20: OoooooooOO - I1ii11iIi11i * I1ii11iIi11i * I1ii11iIi11i
 if 87 - 87: OoooooooOO * ooOoO0o
def lisp_process_map_notify ( lisp_sockets , orig_packet , source ) :
 O0oo0o0Oo0oo = lisp_map_notify ( "" )
 Oo00O0o0O = O0oo0o0Oo0oo . decode ( orig_packet )
 if ( Oo00O0o0O == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 6 - 6: I1Ii111 / ooOoO0o / OoooooooOO . iIii1I11I1II1
  if 68 - 68: OoO0O00
 O0oo0o0Oo0oo . print_notify ( )
 if 26 - 26: I11i % i1IIi / iIii1I11I1II1 % IiII . iII111i + I1ii11iIi11i
 if 49 - 49: O0 . IiII + I1Ii111 - I11i % II111iiii
 if 15 - 15: O0 - OoOoOO00 % II111iiii + O0 % O0 + OoOoOO00
 if 34 - 34: I1Ii111
 if 69 - 69: iIii1I11I1II1 . OOooOOo % I11i
 OOo0oOO0o0oo0 = source . print_address ( )
 if ( O0oo0o0Oo0oo . alg_id != 0 or O0oo0o0Oo0oo . auth_len != 0 ) :
  oo0Oo0oo0o = None
  for oO0oOo in lisp_map_servers_list :
   if ( oO0oOo . find ( OOo0oOO0o0oo0 ) == - 1 ) : continue
   oo0Oo0oo0o = lisp_map_servers_list [ oO0oOo ]
   if 28 - 28: I1Ii111 . ooOoO0o % I1IiiI
  if ( oo0Oo0oo0o == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( OOo0oOO0o0oo0 ) )
   if 62 - 62: II111iiii + ooOoO0o + I1IiiI
   return
   if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
   if 13 - 13: I1ii11iIi11i
  oo0Oo0oo0o . map_notifies_received += 1
  if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
  oO0OoO0OO = lisp_verify_auth ( Oo00O0o0O , O0oo0o0Oo0oo . alg_id ,
 O0oo0o0Oo0oo . auth_data , oo0Oo0oo0o . password )
  if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if oO0OoO0OO else "failed" ) )
  if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
  if ( oO0OoO0OO == False ) : return
 else :
  oo0Oo0oo0o = lisp_ms ( OOo0oOO0o0oo0 , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
  if 18 - 18: OoooooooOO - I1ii11iIi11i
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  if 79 - 79: OOooOOo + Oo0Ooo
  if 33 - 33: iIii1I11I1II1
  if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
 Oo00OOo = O0oo0o0Oo0oo . eid_records
 if ( O0oo0o0Oo0oo . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , Oo00OOo , O0oo0o0Oo0oo , oo0Oo0oo0o )
  return
  if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
  if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
  if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
  if 99 - 99: OOooOOo
  if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
  if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
  if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
  if 56 - 56: Oo0Ooo % I1ii11iIi11i
 oooO = lisp_eid_record ( )
 Oo00O0o0O = oooO . decode ( Oo00OOo )
 if ( Oo00O0o0O == None ) : return
 if 53 - 53: OoO0O00 . I11i - ooOoO0o
 oooO . print_record ( "  " , False )
 if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
 for oO0OO in range ( oooO . rloc_count ) :
  ooO0 = lisp_rloc_record ( )
  Oo00O0o0O = ooO0 . decode ( Oo00O0o0O , None )
  if ( Oo00O0o0O == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 74 - 74: oO0o . I1Ii111 . II111iiii
  ooO0 . print_record ( "    " )
  if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
  if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
  if 41 - 41: iII111i * OoO0O00 - OoO0O00
  if 72 - 72: o0oOOo0O0Ooo + oO0o . I1ii11iIi11i + OoO0O00 / I1Ii111
  if 58 - 58: Oo0Ooo / II111iiii % OoooooooOO % II111iiii
 if ( oooO . group . is_null ( ) == False ) :
  if 39 - 39: i1IIi
  if 16 - 16: OoOoOO00 % iIii1I11I1II1 + Ii1I - o0oOOo0O0Ooo . Oo0Ooo + i1IIi
  if 59 - 59: i1IIi
  if 37 - 37: OoO0O00 / I1ii11iIi11i / OoOoOO00
  if 15 - 15: I1IiiI % iIii1I11I1II1 . I1Ii111
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( oooO . print_eid_tuple ( ) , False ) ) )
  if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
  if 71 - 71: OOooOOo
  OO0oOOOOO = lisp_control_packet_ipc ( orig_packet , OOo0oOO0o0oo0 , "lisp-itr" , 0 )
  lisp_ipc ( OO0oOOOOO , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
  if 73 - 73: iII111i / I1IiiI * ooOoO0o
  if 85 - 85: I11i + I11i + oO0o - OoOoOO00
  if 15 - 15: OoO0O00
  if 88 - 88: Ii1I % i1IIi / I1Ii111
 lisp_send_map_notify_ack ( lisp_sockets , Oo00OOo , O0oo0o0Oo0oo , oo0Oo0oo0o )
 return
 if 2 - 2: Ii1I . IiII % OoOoOO00
 if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
 if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
 if 35 - 35: i11iIiiIii
 if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
 if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
 if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
 if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
def lisp_process_map_notify_ack ( packet , source ) :
 O0oo0o0Oo0oo = lisp_map_notify ( "" )
 packet = O0oo0o0Oo0oo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
  if 12 - 12: i11iIiiIii / Ii1I + i1IIi
 O0oo0o0Oo0oo . print_notify ( )
 if 54 - 54: I1IiiI
 if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
 if 37 - 37: Oo0Ooo
 if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
 if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
 if ( O0oo0o0Oo0oo . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 19 - 19: O0 * II111iiii * OoOoOO00
  if 53 - 53: Oo0Ooo
 oooO = lisp_eid_record ( )
 if 16 - 16: Ii1I
 if ( oooO . decode ( O0oo0o0Oo0oo . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
 oooO . print_record ( "  " , False )
 if 78 - 78: OoO0O00 + oO0o
 oOOoo = oooO . print_eid_tuple ( )
 if 86 - 86: ooOoO0o . ooOoO0o + oO0o
 if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
 if 31 - 31: IiII + iII111i
 if 5 - 5: O0 * Ii1I
 if ( O0oo0o0Oo0oo . alg_id != LISP_NONE_ALG_ID and O0oo0o0Oo0oo . auth_len != 0 ) :
  Ooo000oOOooO00 = lisp_sites_by_eid . lookup_cache ( oooO . eid , True )
  if ( Ooo000oOOooO00 == None ) :
   i1iiiiI1I = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( i1iiiiI1I , green ( oOOoo , False ) ) )
   if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
   return
   if 77 - 77: OOooOOo / OoooooooOO
  oOo00Oo = Ooo000oOOooO00 . site
  if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
  if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
  if 31 - 31: IiII / o0oOOo0O0Ooo
  if 27 - 27: Oo0Ooo
  oOo00Oo . map_notify_acks_received += 1
  if 32 - 32: Oo0Ooo * i11iIiiIii % I1IiiI - i11iIiiIii - I1Ii111 % I1ii11iIi11i
  IIIOo0O = O0oo0o0Oo0oo . key_id
  if ( IIIOo0O in oOo00Oo . auth_key ) :
   I1Ii11Ii = oOo00Oo . auth_key [ IIIOo0O ]
  else :
   I1Ii11Ii = ""
   if 35 - 35: o0oOOo0O0Ooo % iII111i / O0 * I1IiiI . o0oOOo0O0Ooo / OOooOOo
   if 81 - 81: I1ii11iIi11i - i11iIiiIii
  oO0OoO0OO = lisp_verify_auth ( packet , O0oo0o0Oo0oo . alg_id ,
 O0oo0o0Oo0oo . auth_data , I1Ii11Ii )
  if 49 - 49: iII111i * I11i - II111iiii . o0oOOo0O0Ooo
  IIIOo0O = "key-id {}" . format ( IIIOo0O ) if IIIOo0O == O0oo0o0Oo0oo . key_id else "bad key-id {}" . format ( O0oo0o0Oo0oo . key_id )
  if 52 - 52: Ii1I + Ii1I - II111iiii . O0 + I1ii11iIi11i
  if 60 - 60: i11iIiiIii + IiII
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if oO0OoO0OO else "failed" , IIIOo0O ) )
  if 41 - 41: I1Ii111 * o0oOOo0O0Ooo + Oo0Ooo
  if ( oO0OoO0OO == False ) : return
  if 86 - 86: Ii1I / oO0o
  if 40 - 40: OoO0O00 % oO0o + Oo0Ooo
  if 60 - 60: II111iiii / Ii1I
  if 14 - 14: iII111i - Oo0Ooo / o0oOOo0O0Ooo * oO0o / Oo0Ooo - I1IiiI
  if 89 - 89: i1IIi / I1Ii111 + Ii1I - i1IIi
 if ( O0oo0o0Oo0oo . retransmit_timer ) : O0oo0o0Oo0oo . retransmit_timer . cancel ( )
 if 66 - 66: OoooooooOO
 O0o0 = source . print_address ( )
 oO0oOo = O0oo0o0Oo0oo . nonce_key
 if 68 - 68: iII111i + I1Ii111
 if ( oO0oOo in lisp_map_notify_queue ) :
  O0oo0o0Oo0oo = lisp_map_notify_queue . pop ( oO0oOo )
  if ( O0oo0o0Oo0oo . retransmit_timer ) : O0oo0o0Oo0oo . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( oO0oOo ) )
  if 90 - 90: o0oOOo0O0Ooo
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( O0oo0o0Oo0oo . nonce_key , red ( O0o0 , False ) ) )
  if 48 - 48: iII111i + Ii1I
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
 return
 if 89 - 89: OOooOOo - I1Ii111 - iII111i
 if 67 - 67: oO0o
 if 76 - 76: I1IiiI % I1IiiI - IiII / OoOoOO00 / I1ii11iIi11i
 if 42 - 42: I1IiiI + I1ii11iIi11i + Oo0Ooo * i1IIi - II111iiii
 if 15 - 15: o0oOOo0O0Ooo
 if 60 - 60: I1ii11iIi11i / I1Ii111
 if 13 - 13: I1Ii111
 if 52 - 52: II111iiii / OoO0O00 . Ii1I
def lisp_map_referral_loop ( mr , eid , group , action , s ) :
 if ( action not in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) : return ( False )
 if 68 - 68: iII111i
 if ( mr . last_cached_prefix [ 0 ] == None ) : return ( False )
 if 67 - 67: I1IiiI * I1IiiI
 if 100 - 100: iII111i * iII111i . Oo0Ooo
 if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
 if 48 - 48: ooOoO0o + II111iiii
 oO0o0O0oO = False
 if ( group . is_null ( ) == False ) :
  oO0o0O0oO = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 73 - 73: II111iiii
 if ( oO0o0O0oO == False ) :
  oO0o0O0oO = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
  if 35 - 35: II111iiii + IiII
 if ( oO0o0O0oO ) :
  I1iii = lisp_print_eid_tuple ( eid , group )
  oO0Oo0oO00O = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 54 - 54: IiII - Oo0Ooo
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( I1iii , False ) , s ,
  # IiII - ooOoO0o % i11iIiiIii - I1ii11iIi11i
 oO0Oo0oO00O ) )
  if 4 - 4: I11i % II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
 return ( oO0o0O0oO )
 if 62 - 62: O0
 if 52 - 52: OoooooooOO . oO0o
 if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
 if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
 if 59 - 59: Ii1I
 if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
 if 6 - 6: i11iIiiIii . I11i - OoooooooOO
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 26 - 26: I1IiiI
 oOooOO0OO = lisp_map_referral ( )
 packet = oOooOO0OO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
 oOooOO0OO . print_map_referral ( )
 if 72 - 72: OoooooooOO * II111iiii + OoO0O00 % iIii1I11I1II1 . I1ii11iIi11i % OoooooooOO
 OOo0oOO0o0oo0 = source . print_address ( )
 OOooO = oOooOO0OO . nonce
 if 19 - 19: OoOoOO00 + I1Ii111
 if 19 - 19: I1ii11iIi11i / I1Ii111 + OoooooooOO - O0
 if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
 if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
 for o000o0O0Oo00 in range ( oOooOO0OO . record_count ) :
  oooO = lisp_eid_record ( )
  packet = oooO . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
  oooO . print_record ( "  " , True )
  if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
  if 38 - 38: IiII . I1Ii111
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
  oO0oOo = str ( OOooO )
  if ( oO0oOo not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( OOooO ) , OOo0oOO0o0oo0 ) )
   if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
   if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
   continue
   if 11 - 11: iII111i
  o0O0 = lisp_ddt_map_requestQ [ oO0oOo ]
  if ( o0O0 == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( OOooO ) , OOo0oOO0o0oo0 ) )
   if 60 - 60: I1ii11iIi11i / I1Ii111
   continue
   if 10 - 10: OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . OoOoOO00 / I1IiiI
   if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
   if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
   if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
   if 69 - 69: iII111i % I1ii11iIi11i
   if 19 - 19: IiII
  if ( lisp_map_referral_loop ( o0O0 , oooO . eid , oooO . group ,
 oooO . action , OOo0oOO0o0oo0 ) ) :
   o0O0 . dequeue_map_request ( )
   continue
   if 35 - 35: OoOoOO00
   if 18 - 18: II111iiii . OoOoOO00 + I1ii11iIi11i * oO0o + OoooooooOO
  o0O0 . last_cached_prefix [ 0 ] = oooO . eid
  o0O0 . last_cached_prefix [ 1 ] = oooO . group
  if 39 - 39: I1IiiI * ooOoO0o / i11iIiiIii - oO0o - oO0o + O0
  if 73 - 73: OOooOOo
  if 44 - 44: I1ii11iIi11i * i1IIi - iIii1I11I1II1 - oO0o - oO0o * II111iiii
  if 98 - 98: Oo0Ooo + ooOoO0o / OOooOOo . iIii1I11I1II1 . I1IiiI . OoOoOO00
  O000OOoo0o = False
  OoOo00OoOo = lisp_referral_cache_lookup ( oooO . eid , oooO . group ,
 True )
  if ( OoOo00OoOo == None ) :
   O000OOoo0o = True
   OoOo00OoOo = lisp_referral ( )
   OoOo00OoOo . eid = oooO . eid
   OoOo00OoOo . group = oooO . group
   if ( oooO . ddt_incomplete == False ) : OoOo00OoOo . add_cache ( )
  elif ( OoOo00OoOo . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( OoOo00OoOo . print_eid_tuple ( ) , False ) ) )
   if 92 - 92: i1IIi + OoOoOO00 * i1IIi / IiII
   o0O0 . dequeue_map_request ( )
   continue
   if 4 - 4: oO0o % OoO0O00 + IiII + o0oOOo0O0Ooo
   if 82 - 82: O0 / I1Ii111 + OOooOOo . IiII + Ii1I
  oo0OoooOo0 = oooO . action
  OoOo00OoOo . referral_source = source
  OoOo00OoOo . referral_type = oo0OoooOo0
  o0ooo000o00O = oooO . store_ttl ( )
  OoOo00OoOo . referral_ttl = o0ooo000o00O
  OoOo00OoOo . expires = lisp_set_timestamp ( o0ooo000o00O )
  if 31 - 31: i1IIi * OoO0O00 - Ii1I + I11i
  if 8 - 8: O0 + i1IIi . O0
  if 67 - 67: I1IiiI
  if 42 - 42: ooOoO0o - o0oOOo0O0Ooo % oO0o - ooOoO0o
  oooO0 = OoOo00OoOo . is_referral_negative ( )
  if ( OOo0oOO0o0oo0 in OoOo00OoOo . referral_set ) :
   oooOOo0o00 = OoOo00OoOo . referral_set [ OOo0oOO0o0oo0 ]
   if 17 - 17: I1IiiI
   if ( oooOOo0o00 . updown == False and oooO0 == False ) :
    oooOOo0o00 . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( OOo0oOO0o0oo0 ) )
    if 87 - 87: OoO0O00 + Ii1I - IiII % i11iIiiIii . OOooOOo / IiII
   elif ( oooOOo0o00 . updown == True and oooO0 == True ) :
    oooOOo0o00 . updown = False
    lprint ( ( "Change up/down status for referral-node {} " + "to down, received negative referral" ) . format ( OOo0oOO0o0oo0 ) )
    if 73 - 73: iIii1I11I1II1 - ooOoO0o . II111iiii % O0 + I1IiiI
    if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
    if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
    if 73 - 73: II111iiii
    if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
    if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
    if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
    if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
  ii1iiIIiIi11 = { }
  for oO0oOo in OoOo00OoOo . referral_set : ii1iiIIiIi11 [ oO0oOo ] = None
  if 24 - 24: Oo0Ooo . oO0o / OoOoOO00 + I1IiiI
  if 47 - 47: O0 / OOooOOo . i1IIi / OoooooooOO . IiII
  if 34 - 34: OoO0O00 * II111iiii + I1Ii111
  if 20 - 20: iIii1I11I1II1 . OoO0O00 . II111iiii / Ii1I - iIii1I11I1II1 / OOooOOo
  for o000o0O0Oo00 in range ( oooO . rloc_count ) :
   ooO0 = lisp_rloc_record ( )
   packet = ooO0 . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
   ooO0 . print_record ( "    " )
   if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
   if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
   if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
   if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
   O00oO000Oo0 = ooO0 . rloc . print_address ( )
   if ( O00oO000Oo0 not in OoOo00OoOo . referral_set ) :
    oooOOo0o00 = lisp_referral_node ( )
    oooOOo0o00 . referral_address . copy_address ( ooO0 . rloc )
    OoOo00OoOo . referral_set [ O00oO000Oo0 ] = oooOOo0o00
    if ( OOo0oOO0o0oo0 == O00oO000Oo0 and oooO0 ) : oooOOo0o00 . updown = False
   else :
    oooOOo0o00 = OoOo00OoOo . referral_set [ O00oO000Oo0 ]
    if ( O00oO000Oo0 in ii1iiIIiIi11 ) : ii1iiIIiIi11 . pop ( O00oO000Oo0 )
    if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
   oooOOo0o00 . priority = ooO0 . priority
   oooOOo0o00 . weight = ooO0 . weight
   if 65 - 65: I1IiiI . ooOoO0o
   if 51 - 51: I1Ii111
   if 89 - 89: Oo0Ooo
   if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
   if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
  for oO0oOo in ii1iiIIiIi11 : OoOo00OoOo . referral_set . pop ( oO0oOo )
  if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
  oOOoo = OoOo00OoOo . print_eid_tuple ( )
  if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
  if ( O000OOoo0o ) :
   if ( oooO . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( oOOoo , False ) ) )
    if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( oOOoo , False ) , oooO . rloc_count ) )
    if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
    if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( oOOoo , False ) , oooO . rloc_count ) )
   if 51 - 51: O0 % Ii1I % Oo0Ooo - O0
   if 94 - 94: OoooooooOO - ooOoO0o % I1ii11iIi11i + I1Ii111
   if 51 - 51: I1ii11iIi11i . iII111i / i1IIi * ooOoO0o % I11i
   if 82 - 82: O0 % OoOoOO00 . iII111i . i1IIi . iII111i - Oo0Ooo
   if 58 - 58: O0 * OOooOOo
   if 60 - 60: ooOoO0o
  if ( oo0OoooOo0 == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( o0O0 . lisp_sockets , OoOo00OoOo . eid ,
 OoOo00OoOo . group , o0O0 . nonce , o0O0 . itr , o0O0 . sport , 15 , None , False )
   o0O0 . dequeue_map_request ( )
   if 47 - 47: i11iIiiIii
   if 21 - 21: i1IIi - oO0o - Oo0Ooo
  if ( oo0OoooOo0 == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( o0O0 . tried_root ) :
    lisp_send_negative_map_reply ( o0O0 . lisp_sockets , OoOo00OoOo . eid ,
 OoOo00OoOo . group , o0O0 . nonce , o0O0 . itr , o0O0 . sport , 0 , None , False )
    o0O0 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( o0O0 , True )
    if 11 - 11: i1IIi
    if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
    if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
  if ( oo0OoooOo0 == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( OOo0oOO0o0oo0 in OoOo00OoOo . referral_set ) :
    oooOOo0o00 = OoOo00OoOo . referral_set [ OOo0oOO0o0oo0 ]
    oooOOo0o00 . updown = False
    if 56 - 56: Ii1I . iII111i
   if ( len ( OoOo00OoOo . referral_set ) == 0 ) :
    o0O0 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( o0O0 , False )
    if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
    if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
    if 52 - 52: i11iIiiIii
  if ( oo0OoooOo0 in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( o0O0 . eid . is_exact_match ( oooO . eid ) ) :
    if ( not o0O0 . tried_root ) :
     lisp_send_ddt_map_request ( o0O0 , True )
    else :
     lisp_send_negative_map_reply ( o0O0 . lisp_sockets ,
 OoOo00OoOo . eid , OoOo00OoOo . group , o0O0 . nonce , o0O0 . itr ,
 o0O0 . sport , 15 , None , False )
     o0O0 . dequeue_map_request ( )
     if 1 - 1: i1IIi * iIii1I11I1II1
   else :
    lisp_send_ddt_map_request ( o0O0 , False )
    if 29 - 29: I11i
    if 12 - 12: oO0o % i1IIi - oO0o / ooOoO0o * II111iiii % ooOoO0o
    if 6 - 6: IiII / OoO0O00
  if ( oo0OoooOo0 == LISP_DDT_ACTION_MS_ACK ) : o0O0 . dequeue_map_request ( )
  if 83 - 83: IiII - iIii1I11I1II1 * ooOoO0o - oO0o
 return
 if 77 - 77: Ii1I
 if 9 - 9: OOooOOo / OoooooooOO + iII111i
 if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
 if 20 - 20: I1Ii111
 if 33 - 33: i11iIiiIii / I1Ii111 + IiII / II111iiii + I11i
 if 13 - 13: i1IIi % iII111i + OoOoOO00 / Ii1I . Ii1I + II111iiii
 if 44 - 44: OoOoOO00 / OoooooooOO % O0 * Ii1I * IiII
 if 84 - 84: o0oOOo0O0Ooo * IiII * OOooOOo * iII111i
def lisp_process_ecm ( lisp_sockets , packet , source , outer_sport ) :
 Ii1 = lisp_ecm ( 0 )
 packet = Ii1 . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 56 - 56: iII111i * II111iiii . OoooooooOO . I11i
  if 25 - 25: ooOoO0o % o0oOOo0O0Ooo - i11iIiiIii
 Ii1 . print_ecm ( )
 if 79 - 79: iII111i - I1IiiI % O0 / Oo0Ooo + OoOoOO00 . Oo0Ooo
 o00O0O0OoO = lisp_control_header ( )
 if ( o00O0O0OoO . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 59 - 59: I1ii11iIi11i * OoOoOO00 / Ii1I
  if 80 - 80: IiII - ooOoO0o / OoOoOO00 / I11i * O0 + oO0o
 O00OoO0 = o00O0O0OoO . type
 del ( o00O0O0OoO )
 if 22 - 22: iII111i % oO0o / iII111i * i1IIi / II111iiii
 if ( O00OoO0 != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 30 - 30: oO0o + Ii1I / I1ii11iIi11i
  if 23 - 23: i11iIiiIii * O0 . o0oOOo0O0Ooo + I11i
  if 23 - 23: II111iiii . oO0o
  if 9 - 9: oO0o
  if 22 - 22: Oo0Ooo + Oo0Ooo + I1Ii111
 ii11iIIi = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , Ii1 . source , Ii1 . udp_sport ,
 source , outer_sport , Ii1 . ddt , - 1 , ii11iIIi )
 return
 if 39 - 39: II111iiii - Ii1I + I1Ii111 - ooOoO0o % I1Ii111
 if 53 - 53: I1IiiI
 if 53 - 53: iIii1I11I1II1 . Oo0Ooo + Ii1I . II111iiii / I1IiiI
 if 44 - 44: Ii1I / Ii1I / OoO0O00 % ooOoO0o / I11i . I1ii11iIi11i
 if 41 - 41: I1ii11iIi11i * ooOoO0o * I11i + O0 * O0 - O0
 if 81 - 81: I1Ii111 % OoO0O00 / O0
 if 55 - 55: i1IIi - I1Ii111 + I11i
 if 93 - 93: I1IiiI % IiII . OoOoOO00 + iII111i
 if 81 - 81: ooOoO0o / I1Ii111 + OOooOOo / Oo0Ooo / OoOoOO00
 if 34 - 34: ooOoO0o * iIii1I11I1II1 % i11iIiiIii * OOooOOo - OOooOOo
def lisp_send_map_register ( lisp_sockets , packet , map_register , ms ) :
 if 63 - 63: Oo0Ooo / oO0o + iII111i % OoooooooOO * I11i
 if 34 - 34: I1IiiI + I1Ii111 % ooOoO0o
 if 24 - 24: Ii1I % II111iiii - i11iIiiIii
 if 52 - 52: OoO0O00
 if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
 if 50 - 50: IiII . i11iIiiIii % I11i
 if 22 - 22: i1IIi - II111iiii - OoOoOO00 . iII111i
 oOO00OoOo = ms . map_server
 if ( lisp_decent_push_configured and oOO00OoOo . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  oOO00OoOo = copy . deepcopy ( oOO00OoOo )
  oOO00OoOo . address = 0x7f000001
  iI11Ii111 = bold ( "Bootstrap" , False )
  II11iIIii = ms . map_server . print_address_no_iid ( )
  lprint ( "{} mapping system for peer-group {}" . format ( iI11Ii111 , II11iIIii ) )
  if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
  if 34 - 34: iII111i . OoOoOO00
  if 49 - 49: I1ii11iIi11i % oO0o - I1Ii111 . I1ii11iIi11i % II111iiii
  if 20 - 20: I1ii11iIi11i . iIii1I11I1II1 - Ii1I % OoO0O00
  if 27 - 27: iIii1I11I1II1 / I1Ii111 - I11i . OoO0O00 + ooOoO0o
  if 89 - 89: I1IiiI % I11i - OOooOOo
 packet = lisp_compute_auth ( packet , map_register , ms . password )
 if 71 - 71: OOooOOo % Oo0Ooo - o0oOOo0O0Ooo / I1Ii111 - O0 - oO0o
 if 10 - 10: I1IiiI
 if 17 - 17: i11iIiiIii % o0oOOo0O0Ooo . ooOoO0o
 if 34 - 34: OoooooooOO / iII111i / O0
 if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
 if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
 if ( ms . ekey != None ) :
  iI11ii = ms . ekey . zfill ( 32 )
  Oo0OOOO0oOoo0 = "0" * 8
  oooO00oo0 = chacha . ChaCha ( iI11ii , Oo0OOOO0oOoo0 , 20 ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + oooO00oo0
  oOO = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( oOO , ms . ekey_id ) )
  if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
  if 40 - 40: OOooOOo - OoooooooOO
 iiIIiiIii1i = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  iiIIiiIii1i = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 66 - 66: ooOoO0o * OoooooooOO
  if 7 - 7: IiII * II111iiii - I1ii11iIi11i - OoOoOO00 . I11i
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( oOO00OoOo . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , iiIIiiIii1i ) )
 if 19 - 19: I1Ii111 + O0 - I1ii11iIi11i * ooOoO0o - OOooOOo
 lisp_send ( lisp_sockets , oOO00OoOo , LISP_CTRL_PORT , packet )
 return
 if 85 - 85: I1Ii111 % OoO0O00 / i11iIiiIii . I1ii11iIi11i
 if 12 - 12: iII111i / ooOoO0o + OOooOOo / O0 . ooOoO0o
 if 63 - 63: o0oOOo0O0Ooo
 if 35 - 35: ooOoO0o * i11iIiiIii + Ii1I % O0 / OoO0O00
 if 85 - 85: i11iIiiIii % I11i * OoOoOO00 * iII111i + I1Ii111
 if 19 - 19: OoOoOO00
 if 55 - 55: i1IIi * I11i
 if 33 - 33: i1IIi . Oo0Ooo + I11i
def lisp_send_ipc_to_core ( lisp_socket , packet , dest , port ) :
 IiiiiI = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 97 - 97: OOooOOo / IiII / ooOoO0o / OoooooooOO
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 78 - 78: I1Ii111 + I1Ii111
 if 43 - 43: I1Ii111 * o0oOOo0O0Ooo + i1IIi
 packet = lisp_control_packet_ipc ( packet , IiiiiI , dest , port )
 lisp_ipc ( packet , lisp_socket , "lisp-core-pkt" )
 return
 if 19 - 19: Ii1I
 if 51 - 51: oO0o
 if 57 - 57: i11iIiiIii - Oo0Ooo + I1Ii111 * OoO0O00
 if 35 - 35: o0oOOo0O0Ooo % II111iiii + O0
 if 70 - 70: I1ii11iIi11i . II111iiii
 if 54 - 54: OOooOOo
 if 67 - 67: I1IiiI . o0oOOo0O0Ooo / i1IIi * I1ii11iIi11i . Oo0Ooo + II111iiii
 if 63 - 63: OoOoOO00 - OoOoOO00
def lisp_send_map_reply ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Reply to {}" . format ( dest . print_address_no_iid ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 31 - 31: I1ii11iIi11i % O0 - i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o * ooOoO0o
 if 18 - 18: OoO0O00 - OoO0O00 . o0oOOo0O0Ooo
 if 80 - 80: I11i + I1Ii111 / I1IiiI * OOooOOo % iII111i
 if 48 - 48: iIii1I11I1II1 + i1IIi . I1IiiI % OoO0O00 - iIii1I11I1II1 / i1IIi
 if 14 - 14: IiII . I11i
 if 13 - 13: OoOoOO00 - I11i . OOooOOo % OoO0O00
 if 79 - 79: iII111i / Ii1I % i11iIiiIii . I1IiiI % OoO0O00 / i11iIiiIii
 if 100 - 100: OOooOOo + Oo0Ooo . iIii1I11I1II1 . ooOoO0o * Oo0Ooo
def lisp_send_map_referral ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Referral to {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 16 - 16: Oo0Ooo % OoOoOO00 + I1Ii111 % I1Ii111
 if 12 - 12: I1Ii111 . Ii1I / iIii1I11I1II1 + i1IIi
 if 9 - 9: iIii1I11I1II1
 if 75 - 75: I11i . II111iiii * I1IiiI * IiII
 if 36 - 36: OOooOOo / I1ii11iIi11i / oO0o / ooOoO0o / I11i
 if 7 - 7: OoO0O00 - I11i - o0oOOo0O0Ooo / o0oOOo0O0Ooo + i11iIiiIii
 if 28 - 28: OoOoOO00 % ooOoO0o . I1IiiI + II111iiii
 if 34 - 34: iIii1I11I1II1
def lisp_send_map_notify ( lisp_sockets , packet , dest , port ) :
 lprint ( "Send Map-Notify to xTR {}" . format ( dest . print_address ( ) ) )
 lisp_send_ipc_to_core ( lisp_sockets [ 2 ] , packet , dest , port )
 return
 if 65 - 65: II111iiii - iII111i / o0oOOo0O0Ooo
 if 35 - 35: i11iIiiIii - Oo0Ooo . I1ii11iIi11i % OoOoOO00
 if 20 - 20: OoO0O00
 if 93 - 93: ooOoO0o + o0oOOo0O0Ooo - I1ii11iIi11i
 if 56 - 56: Ii1I / Oo0Ooo
 if 96 - 96: o0oOOo0O0Ooo . II111iiii
 if 14 - 14: OoooooooOO - i1IIi / i11iIiiIii - OOooOOo - i11iIiiIii . ooOoO0o
def lisp_send_ecm ( lisp_sockets , packet , inner_source , inner_sport , inner_dest ,
 outer_dest , to_etr = False , to_ms = False , ddt = False ) :
 if 8 - 8: oO0o * O0 - II111iiii + I1IiiI
 if ( inner_source == None or inner_source . is_null ( ) ) :
  inner_source = inner_dest
  if 85 - 85: OoooooooOO % i11iIiiIii / IiII % OoOoOO00 + O0
  if 6 - 6: OoooooooOO
 O00oO000Oo0 = outer_dest . print_address_no_iid ( )
 if 97 - 97: II111iiii + o0oOOo0O0Ooo * II111iiii
 if 17 - 17: o0oOOo0O0Ooo / ooOoO0o + i1IIi
 if 78 - 78: iIii1I11I1II1 * o0oOOo0O0Ooo * Oo0Ooo - OoO0O00 / OoO0O00
 if 89 - 89: o0oOOo0O0Ooo % o0oOOo0O0Ooo
 if 8 - 8: Ii1I % oO0o - o0oOOo0O0Ooo
 if ( lisp_nat_traversal ) :
  i11i1IIIiI1i , II1 = lisp_get_translated_port_for_mr ( O00oO000Oo0 )
  if ( II1 != None ) : inner_sport = II1
  if 55 - 55: Ii1I . I1IiiI
 Ii1 = lisp_ecm ( inner_sport )
 if 3 - 3: OoOoOO00 * I11i % I11i
 Ii1 . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 Ii1 . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 Ii1 . ddt = ddt
 O0o0IiIIi1I1111i1 = Ii1 . encode ( packet , inner_source , inner_dest )
 if ( O0o0IiIIi1I1111i1 == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 14 - 14: iII111i
 Ii1 . print_ecm ( )
 if 32 - 32: i1IIi + ooOoO0o * Oo0Ooo - O0 / i11iIiiIii
 packet = O0o0IiIIi1I1111i1 + packet
 if 58 - 58: OOooOOo + o0oOOo0O0Ooo
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( O00oO000Oo0 ) )
 oOO00OoOo = lisp_convert_4to6 ( O00oO000Oo0 )
 lisp_send ( lisp_sockets , oOO00OoOo , LISP_CTRL_PORT , packet )
 return
 if 48 - 48: OOooOOo % i11iIiiIii + OoooooooOO
 if 64 - 64: OoooooooOO + OoooooooOO % OoO0O00 - OoooooooOO
 if 86 - 86: OoOoOO00 - OoO0O00 + Ii1I % I1ii11iIi11i - Oo0Ooo + oO0o
 if 32 - 32: I11i . I1ii11iIi11i - oO0o + I11i / ooOoO0o
 if 24 - 24: I1IiiI / O0 . O0
 if 13 - 13: i11iIiiIii - i11iIiiIii . iIii1I11I1II1 - O0 . I11i / i11iIiiIii
 if 59 - 59: ooOoO0o + I1ii11iIi11i . OoO0O00 . O0
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
if 45 - 45: O0 . o0oOOo0O0Ooo + OoOoOO00 / I1ii11iIi11i + Ii1I % I1Ii111
LISP_RLOC_UNKNOWN_STATE = 0
LISP_RLOC_UP_STATE = 1
LISP_RLOC_DOWN_STATE = 2
LISP_RLOC_UNREACH_STATE = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE = 5
if 20 - 20: Oo0Ooo
LISP_AUTH_NONE = 0
LISP_AUTH_MD5 = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3
if 33 - 33: oO0o - OoOoOO00 - i11iIiiIii + I1Ii111 + iIii1I11I1II1
if 2 - 2: OoooooooOO + IiII / iII111i . iIii1I11I1II1 * OoOoOO00
if 84 - 84: OOooOOo
if 68 - 68: I1Ii111
if 92 - 92: oO0o * Ii1I / OoO0O00 % II111iiii
if 54 - 54: oO0o + I11i - OoO0O00
if 86 - 86: OoooooooOO
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN = 48
LISP_E164_HOST_MASK_LEN = 60
if 51 - 51: i11iIiiIii
if 91 - 91: OOooOOo
if 22 - 22: OoooooooOO + OoOoOO00 - Ii1I . iII111i / OoooooooOO / I1IiiI
if 73 - 73: i1IIi - Ii1I + oO0o * iIii1I11I1II1
if 100 - 100: i11iIiiIii / iIii1I11I1II1 + Oo0Ooo + OoO0O00 - iII111i
if 8 - 8: i11iIiiIii . O0 + o0oOOo0O0Ooo * oO0o + II111iiii
def byte_swap_64 ( address ) :
 iI1ii11Ii = ( ( address & 0x00000000000000ff ) << 56 ) | ( ( address & 0x000000000000ff00 ) << 40 ) | ( ( address & 0x0000000000ff0000 ) << 24 ) | ( ( address & 0x00000000ff000000 ) << 8 ) | ( ( address & 0x000000ff00000000 ) >> 8 ) | ( ( address & 0x0000ff0000000000 ) >> 24 ) | ( ( address & 0x00ff000000000000 ) >> 40 ) | ( ( address & 0xff00000000000000 ) >> 56 )
 if 61 - 61: ooOoO0o / ooOoO0o
 if 51 - 51: iIii1I11I1II1 / oO0o * I1Ii111 + i1IIi
 if 96 - 96: Oo0Ooo + oO0o - Oo0Ooo - OoOoOO00 % OOooOOo . iIii1I11I1II1
 if 93 - 93: iIii1I11I1II1 % OoooooooOO
 if 6 - 6: II111iiii / oO0o - OOooOOo . O0 - o0oOOo0O0Ooo
 if 72 - 72: iIii1I11I1II1 / OoooooooOO * ooOoO0o / ooOoO0o % O0 + IiII
 if 96 - 96: iII111i / i11iIiiIii + Oo0Ooo . I1IiiI + iII111i % OoOoOO00
 if 19 - 19: i11iIiiIii . Oo0Ooo . OoOoOO00 - I1IiiI
 return ( iI1ii11Ii )
 if 85 - 85: I11i - OoO0O00 % iIii1I11I1II1 . iII111i + ooOoO0o . Oo0Ooo
 if 87 - 87: iII111i
 if 86 - 86: IiII - I11i
 if 99 - 99: i1IIi + I1ii11iIi11i
 if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
 if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
 if 44 - 44: II111iiii / I1ii11iIi11i
 if 39 - 39: OoooooooOO % OoO0O00
 if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
 if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
 if 29 - 29: IiII
 if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
 if 91 - 91: I1Ii111 * iII111i * OoO0O00
 if 79 - 79: iII111i + oO0o
 if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
class lisp_cache_entries ( object ) :
 def __init__ ( self ) :
  self . entries = { }
  self . entries_sorted = [ ]
  if 97 - 97: O0 / OoOoOO00 / ooOoO0o
  if 11 - 11: II111iiii . i11iIiiIii - Ii1I . IiII
  if 10 - 10: OOooOOo * OoooooooOO
class lisp_cache ( object ) :
 def __init__ ( self ) :
  self . cache = { }
  self . cache_sorted = [ ]
  self . cache_count = 0
  if 12 - 12: II111iiii - O0 . i1IIi % oO0o % OoooooooOO
  if 36 - 36: IiII * OoOoOO00 - iIii1I11I1II1 + II111iiii
 def cache_size ( self ) :
  return ( self . cache_count )
  if 65 - 65: I1IiiI * I11i . I1Ii111 % I1ii11iIi11i + O0
  if 91 - 91: OoooooooOO % I1Ii111 * OoO0O00 - OoOoOO00
 def build_key ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) :
   I1iIIIiI1iI11 = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   I1iIIIiI1iI11 = prefix . mask_len
  else :
   I1iIIIiI1iI11 = prefix . mask_len + 48
   if 5 - 5: iIii1I11I1II1 * I11i - oO0o % oO0o % o0oOOo0O0Ooo . i1IIi
   if 95 - 95: Oo0Ooo * I1ii11iIi11i + iII111i - o0oOOo0O0Ooo - Oo0Ooo . OoO0O00
  i1I1iI = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  IiIIi = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 62 - 62: I11i
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    OOOOo0o0O0o = prefix . addr_length ( ) * 2
    iI1ii11Ii = lisp_hex_string ( prefix . address ) . zfill ( OOOOo0o0O0o )
   else :
    iI1ii11Ii = prefix . address
    if 58 - 58: I11i . OoOoOO00 + iII111i . iII111i
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   IiIIi = "8003"
   iI1ii11Ii = prefix . address . print_geo ( )
  else :
   IiIIi = ""
   iI1ii11Ii = ""
   if 43 - 43: I1Ii111 + I1Ii111 % Oo0Ooo % OoO0O00 - ooOoO0o
   if 61 - 61: OoOoOO00 + Ii1I % i11iIiiIii - I1IiiI * OoO0O00 % iIii1I11I1II1
  oO0oOo = i1I1iI + IiIIi + iI1ii11Ii
  return ( [ I1iIIIiI1iI11 , oO0oOo ] )
  if 66 - 66: iII111i + i1IIi
  if 24 - 24: O0 / OoooooooOO - OoOoOO00
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  I1iIIIiI1iI11 , oO0oOo = self . build_key ( prefix )
  if ( I1iIIIiI1iI11 not in self . cache ) :
   self . cache [ I1iIIIiI1iI11 ] = lisp_cache_entries ( )
   self . cache_sorted = self . sort_in_entry ( self . cache_sorted , I1iIIIiI1iI11 )
   if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
  if ( oO0oOo not in self . cache [ I1iIIIiI1iI11 ] . entries ) :
   self . cache_count += 1
   if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
  self . cache [ I1iIIIiI1iI11 ] . entries [ oO0oOo ] = entry
  if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
  if 53 - 53: i11iIiiIii % I1ii11iIi11i
 def lookup_cache ( self , prefix , exact ) :
  oO0OoOo0oo , oO0oOo = self . build_key ( prefix )
  if ( exact ) :
   if ( oO0OoOo0oo not in self . cache ) : return ( None )
   if ( oO0oOo not in self . cache [ oO0OoOo0oo ] . entries ) : return ( None )
   return ( self . cache [ oO0OoOo0oo ] . entries [ oO0oOo ] )
   if 63 - 63: IiII + oO0o + II111iiii * I11i
   if 49 - 49: OoO0O00
  OOOOoo0o0O0 = None
  for I1iIIIiI1iI11 in self . cache_sorted :
   if ( oO0OoOo0oo < I1iIIIiI1iI11 ) : return ( OOOOoo0o0O0 )
   for Ii in list ( self . cache [ I1iIIIiI1iI11 ] . entries . values ( ) ) :
    if ( prefix . is_more_specific ( Ii . eid ) ) :
     if ( OOOOoo0o0O0 == None or
 Ii . eid . is_more_specific ( OOOOoo0o0O0 . eid ) ) : OOOOoo0o0O0 = Ii
     if 78 - 78: I1IiiI - I1ii11iIi11i
     if 24 - 24: Ii1I + I11i
     if 5 - 5: I1Ii111 . Ii1I - ooOoO0o % OoooooooOO
  return ( OOOOoo0o0O0 )
  if 2 - 2: OOooOOo . IiII . iII111i / Oo0Ooo
  if 86 - 86: OOooOOo . o0oOOo0O0Ooo - iIii1I11I1II1
 def delete_cache ( self , prefix ) :
  I1iIIIiI1iI11 , oO0oOo = self . build_key ( prefix )
  if ( I1iIIIiI1iI11 not in self . cache ) : return
  if ( oO0oOo not in self . cache [ I1iIIIiI1iI11 ] . entries ) : return
  self . cache [ I1iIIIiI1iI11 ] . entries . pop ( oO0oOo )
  self . cache_count -= 1
  if 12 - 12: oO0o + iII111i
  if 16 - 16: O0 + oO0o - ooOoO0o * O0 . I1ii11iIi11i . oO0o
 def walk_cache ( self , function , parms ) :
  for I1iIIIiI1iI11 in self . cache_sorted :
   for Ii in list ( self . cache [ I1iIIIiI1iI11 ] . entries . values ( ) ) :
    iI1IIi1I11i1I , parms = function ( Ii , parms )
    if ( iI1IIi1I11i1I == False ) : return ( parms )
    if 31 - 31: ooOoO0o
    if 96 - 96: I1IiiI * OoO0O00 - I1IiiI * I1IiiI - OoooooooOO + OOooOOo
  return ( parms )
  if 39 - 39: I1IiiI + Oo0Ooo
  if 2 - 2: i1IIi / iII111i / iII111i
 def sort_in_entry ( self , table , value ) :
  if ( table == [ ] ) : return ( [ value ] )
  if 1 - 1: Oo0Ooo . OoOoOO00 + OOooOOo % iII111i - OOooOOo - OoOoOO00
  IiI111ii = table
  while ( True ) :
   if ( len ( IiI111ii ) == 1 ) :
    if ( value == IiI111ii [ 0 ] ) : return ( table )
    o00O = table . index ( IiI111ii [ 0 ] )
    if ( value < IiI111ii [ 0 ] ) :
     return ( table [ 0 : o00O ] + [ value ] + table [ o00O : : ] )
     if 63 - 63: O0 / iIii1I11I1II1 % II111iiii * II111iiii * I1ii11iIi11i
    if ( value > IiI111ii [ 0 ] ) :
     return ( table [ 0 : o00O + 1 ] + [ value ] + table [ o00O + 1 : : ] )
     if 69 - 69: i11iIiiIii + i11iIiiIii
     if 27 - 27: O0 % i11iIiiIii - I1Ii111 * oO0o - I11i / Oo0Ooo
   o00O = old_div ( len ( IiI111ii ) , 2 )
   IiI111ii = IiI111ii [ 0 : o00O ] if ( value < IiI111ii [ o00O ] ) else IiI111ii [ o00O : : ]
   if 78 - 78: O0 * i11iIiiIii
   if 62 - 62: OoO0O00 * I1Ii111 * Ii1I / ooOoO0o
  return ( [ ] )
  if 27 - 27: oO0o . iII111i . oO0o
  if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
 def print_cache ( self ) :
  lprint ( "Printing contents of {}: " . format ( self ) )
  if ( self . cache_size ( ) == 0 ) :
   lprint ( "  Cache is empty" )
   return
   if 14 - 14: I11i + ooOoO0o . oO0o * I11i
  for I1iIIIiI1iI11 in self . cache_sorted :
   for oO0oOo in self . cache [ I1iIIIiI1iI11 ] . entries :
    Ii = self . cache [ I1iIIIiI1iI11 ] . entries [ oO0oOo ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( I1iIIIiI1iI11 , oO0oOo ,
 Ii ) )
    if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
    if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
    if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
    if 33 - 33: I11i
    if 37 - 37: Oo0Ooo
    if 36 - 36: IiII % I11i
    if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
    if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
lisp_referral_cache = lisp_cache ( )
lisp_ddt_cache = lisp_cache ( )
lisp_sites_by_eid = lisp_cache ( )
lisp_map_cache = lisp_cache ( )
lisp_db_for_lookups = lisp_cache ( )
if 82 - 82: OoooooooOO
if 14 - 14: OoO0O00 / oO0o - OOooOOo
if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
if 16 - 16: IiII + Oo0Ooo % I11i
if 16 - 16: ooOoO0o / I1Ii111
if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
def lisp_map_cache_lookup ( source , dest ) :
 if 54 - 54: iIii1I11I1II1 % ooOoO0o
 I1iI1III = dest . is_multicast_address ( )
 if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
 if 92 - 92: I11i + OoO0O00 . OoooooooOO
 if 3 - 3: OoO0O00 % iIii1I11I1II1
 if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
 Ii111 = lisp_map_cache . lookup_cache ( dest , False )
 if ( Ii111 == None ) :
  oOOoo = source . print_sg ( dest ) if I1iI1III else dest . print_address ( )
  oOOoo = green ( oOOoo , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oOOoo ) )
  return ( None )
  if 59 - 59: iIii1I11I1II1
  if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
  if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
  if 63 - 63: I11i
  if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
 if ( I1iI1III == False ) :
  I1Iii1II = green ( Ii111 . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , I1Iii1II ) )
  if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
  return ( Ii111 )
  if 80 - 80: I1ii11iIi11i * iII111i % i1IIi * OOooOOo % II111iiii % i1IIi
  if 44 - 44: OoooooooOO
  if 18 - 18: i11iIiiIii
  if 65 - 65: i1IIi . iIii1I11I1II1 % iIii1I11I1II1
  if 35 - 35: iIii1I11I1II1 - o0oOOo0O0Ooo + I1ii11iIi11i * iII111i - OOooOOo . o0oOOo0O0Ooo
 Ii111 = Ii111 . lookup_source_cache ( source , False )
 if ( Ii111 == None ) :
  oOOoo = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oOOoo ) )
  return ( None )
  if 12 - 12: iIii1I11I1II1 % OoO0O00 * Oo0Ooo
  if 5 - 5: I11i - II111iiii * iIii1I11I1II1 / iIii1I11I1II1 % IiII * i1IIi
  if 30 - 30: i1IIi % I1IiiI . OOooOOo % iIii1I11I1II1 . I1ii11iIi11i / o0oOOo0O0Ooo
  if 53 - 53: OOooOOo % ooOoO0o
  if 94 - 94: OOooOOo - O0 - I1Ii111 / OoooooooOO - iII111i
 I1Iii1II = green ( Ii111 . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , I1Iii1II ) )
 if 83 - 83: OOooOOo * I1ii11iIi11i * iII111i * I1ii11iIi11i . OoO0O00
 return ( Ii111 )
 if 87 - 87: ooOoO0o . O0 - oO0o
 if 75 - 75: Oo0Ooo
 if 22 - 22: oO0o * I1Ii111 . II111iiii / Ii1I * O0
 if 33 - 33: oO0o * i1IIi + ooOoO0o * OOooOOo - O0 - iIii1I11I1II1
 if 35 - 35: I1Ii111
 if 12 - 12: Ii1I % I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
 if 12 - 12: Oo0Ooo + I1IiiI
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  I11i1iI = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( I11i1iI )
  if 12 - 12: OoOoOO00 / II111iiii
  if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
  if 28 - 28: I1IiiI
  if 27 - 27: I1IiiI % oO0o - iIii1I11I1II1 - o0oOOo0O0Ooo - IiII - O0
  if 46 - 46: II111iiii
 if ( eid == None or eid . is_null ( ) ) : return ( None )
 if 24 - 24: i11iIiiIii * i1IIi - I11i + o0oOOo0O0Ooo
 if 60 - 60: ooOoO0o
 if 62 - 62: i11iIiiIii
 if 88 - 88: i11iIiiIii
 if 59 - 59: oO0o - OoooooooOO % ooOoO0o
 if 90 - 90: OoOoOO00
 I11i1iI = lisp_referral_cache . lookup_cache ( group , exact )
 if ( I11i1iI == None ) : return ( None )
 if 96 - 96: II111iiii % Ii1I
 oOIIIiiIiI = I11i1iI . lookup_source_cache ( eid , exact )
 if ( oOIIIiiIiI ) : return ( oOIIIiiIiI )
 if 45 - 45: iII111i . oO0o * iII111i
 if ( exact ) : I11i1iI = None
 return ( I11i1iI )
 if 3 - 3: OoOoOO00 / Oo0Ooo - Oo0Ooo
 if 54 - 54: Oo0Ooo . OoO0O00 * I1IiiI % IiII
 if 97 - 97: o0oOOo0O0Ooo + Ii1I
 if 77 - 77: I11i - oO0o . Ii1I
 if 75 - 75: I11i * OoooooooOO % OoOoOO00 . i1IIi - Ii1I + iIii1I11I1II1
 if 74 - 74: ooOoO0o
 if 18 - 18: iIii1I11I1II1 - I11i - oO0o
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  O0000O00o000 = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( O0000O00o000 )
  if 12 - 12: O0 + O0 + ooOoO0o . I1IiiI * II111iiii
  if 47 - 47: i11iIiiIii % OOooOOo / ooOoO0o . IiII - I1IiiI
  if 10 - 10: Oo0Ooo / ooOoO0o / I1ii11iIi11i
  if 98 - 98: O0 - I1Ii111 - i11iIiiIii
  if 85 - 85: II111iiii - I1ii11iIi11i % I1IiiI . I1IiiI - OoooooooOO - I11i
 if ( eid . is_null ( ) ) : return ( None )
 if 38 - 38: i1IIi + oO0o * ooOoO0o % Ii1I % ooOoO0o
 if 80 - 80: OoO0O00 + OoOoOO00 % iII111i % OoooooooOO - ooOoO0o
 if 25 - 25: OoOoOO00 % i11iIiiIii - I1IiiI * iIii1I11I1II1 - Oo0Ooo . O0
 if 48 - 48: I1IiiI + oO0o % i11iIiiIii % iIii1I11I1II1
 if 14 - 14: iIii1I11I1II1
 if 78 - 78: I1Ii111 / Oo0Ooo - I1Ii111
 O0000O00o000 = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( O0000O00o000 == None ) : return ( None )
 if 1 - 1: OoO0O00 - I1IiiI * o0oOOo0O0Ooo
 oOoOooO0o00 = O0000O00o000 . lookup_source_cache ( eid , exact )
 if ( oOoOooO0o00 ) : return ( oOoOooO0o00 )
 if 85 - 85: i1IIi
 if ( exact ) : O0000O00o000 = None
 return ( O0000O00o000 )
 if 78 - 78: oO0o
 if 6 - 6: IiII
 if 69 - 69: iII111i
 if 87 - 87: i11iIiiIii % o0oOOo0O0Ooo + Ii1I
 if 72 - 72: Ii1I / II111iiii + o0oOOo0O0Ooo
 if 33 - 33: I1Ii111 * OoOoOO00 - OoooooooOO
 if 11 - 11: I1Ii111 - Oo0Ooo / iIii1I11I1II1 - OoooooooOO
def lisp_site_eid_lookup ( eid , group , exact ) :
 if 71 - 71: Oo0Ooo + Ii1I - OoooooooOO + I11i - iIii1I11I1II1 / O0
 if ( group . is_null ( ) ) :
  Ooo000oOOooO00 = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( Ooo000oOOooO00 )
  if 76 - 76: i11iIiiIii % o0oOOo0O0Ooo . O0 * I11i
  if 90 - 90: II111iiii + OOooOOo % I1Ii111 * iIii1I11I1II1 % iIii1I11I1II1
  if 55 - 55: II111iiii % O0 * O0 - II111iiii * I1IiiI % Oo0Ooo
  if 48 - 48: I1ii11iIi11i + OoooooooOO % i1IIi
  if 46 - 46: OoOoOO00
 if ( eid . is_null ( ) ) : return ( None )
 if 75 - 75: I1IiiI
 if 37 - 37: iIii1I11I1II1 % OoO0O00 * ooOoO0o + I11i % ooOoO0o / i11iIiiIii
 if 14 - 14: i1IIi / ooOoO0o
 if 10 - 10: ooOoO0o / OoooooooOO - ooOoO0o % O0 + oO0o - oO0o
 if 16 - 16: O0
 if 14 - 14: Ii1I . Ii1I . OOooOOo - O0 / OoO0O00 % II111iiii
 Ooo000oOOooO00 = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( Ooo000oOOooO00 == None ) : return ( None )
 if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
 if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
 if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
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
 oo0Oo = Ooo000oOOooO00 . lookup_source_cache ( eid , exact )
 if ( oo0Oo ) : return ( oo0Oo )
 if 57 - 57: OOooOOo . ooOoO0o - OoooooooOO - I1ii11iIi11i * O0
 if ( exact ) :
  Ooo000oOOooO00 = None
 else :
  IiI1IIi = Ooo000oOOooO00 . parent_for_more_specifics
  if ( IiI1IIi and IiI1IIi . accept_more_specifics ) :
   if ( group . is_more_specific ( IiI1IIi . group ) ) : Ooo000oOOooO00 = IiI1IIi
   if 85 - 85: I1IiiI * OoO0O00
   if 63 - 63: I1IiiI - i11iIiiIii
 return ( Ooo000oOOooO00 )
 if 4 - 4: OOooOOo + iIii1I11I1II1 / I1IiiI * Ii1I
 if 64 - 64: OoOoOO00
 if 94 - 94: OOooOOo * OoooooooOO * o0oOOo0O0Ooo / I1Ii111 . II111iiii
 if 37 - 37: O0 * II111iiii * I1IiiI - O0 - I11i / i1IIi
 if 27 - 27: i11iIiiIii + iIii1I11I1II1
 if 15 - 15: oO0o
 if 69 - 69: II111iiii * O0 . ooOoO0o * IiII
 if 25 - 25: I11i - I1ii11iIi11i . I1Ii111 . OoooooooOO
 if 4 - 4: IiII * OoO0O00 % I1ii11iIi11i * Ii1I . iII111i
 if 41 - 41: OoooooooOO % I11i . O0 + I1Ii111
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
 if 71 - 71: ooOoO0o . oO0o * OoooooooOO + iII111i - I1Ii111 . I1ii11iIi11i
 if 100 - 100: I11i + O0 - o0oOOo0O0Ooo * I1ii11iIi11i
class lisp_address ( object ) :
 def __init__ ( self , afi , addr_str , mask_len , iid ) :
  self . afi = afi
  self . mask_len = mask_len
  self . instance_id = iid
  self . iid_list = [ ]
  self . address = 0
  if ( addr_str != "" ) : self . store_address ( addr_str )
  if 94 - 94: Oo0Ooo . IiII / Ii1I / oO0o - I1IiiI
  if 77 - 77: i11iIiiIii . Ii1I - Ii1I
 def copy_address ( self , addr ) :
  if ( addr == None ) : return
  self . afi = addr . afi
  self . address = addr . address
  self . mask_len = addr . mask_len
  self . instance_id = addr . instance_id
  self . iid_list = addr . iid_list
  if 47 - 47: iII111i % OOooOOo . I1ii11iIi11i + I1ii11iIi11i . I1Ii111
  if 20 - 20: oO0o - o0oOOo0O0Ooo + I1IiiI % OoOoOO00
 def make_default_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  self . mask_len = 0
  self . address = 0
  if 41 - 41: oO0o . ooOoO0o
  if 59 - 59: iIii1I11I1II1 - I1IiiI . ooOoO0o
 def make_default_multicast_route ( self , addr ) :
  self . afi = addr . afi
  self . instance_id = addr . instance_id
  if ( self . afi == LISP_AFI_IPV4 ) :
   self . address = 0xe0000000
   self . mask_len = 4
   if 58 - 58: I1IiiI * I1Ii111 + iII111i + iIii1I11I1II1 + I1IiiI
  if ( self . afi == LISP_AFI_IPV6 ) :
   self . address = 0xff << 120
   self . mask_len = 8
   if 78 - 78: Oo0Ooo + ooOoO0o
  if ( self . afi == LISP_AFI_MAC ) :
   self . address = 0xffffffffffff
   self . mask_len = 48
   if 56 - 56: OoO0O00 / i1IIi + ooOoO0o . ooOoO0o . iII111i
   if 37 - 37: iIii1I11I1II1 * OoOoOO00 . OoOoOO00 + OoooooooOO + OoO0O00
   if 25 - 25: I1IiiI / IiII . OOooOOo . I1ii11iIi11i % i1IIi
 def not_set ( self ) :
  return ( self . afi == LISP_AFI_NONE )
  if 12 - 12: O0 % O0
  if 9 - 9: O0 . I1IiiI + I1ii11iIi11i / OOooOOo * I1ii11iIi11i
 def is_private_address ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  iI1ii11Ii = self . address
  if ( ( ( iI1ii11Ii & 0xff000000 ) >> 24 ) == 10 ) : return ( True )
  if ( ( ( iI1ii11Ii & 0xff000000 ) >> 24 ) == 172 ) :
   I1iIiii1Ii1 = ( iI1ii11Ii & 0x00ff0000 ) >> 16
   if ( I1iIiii1Ii1 >= 16 and I1iIiii1Ii1 <= 31 ) : return ( True )
   if 75 - 75: OoOoOO00 . OoOoOO00 - Oo0Ooo - II111iiii
  if ( ( ( iI1ii11Ii & 0xffff0000 ) >> 16 ) == 0xc0a8 ) : return ( True )
  return ( False )
  if 20 - 20: II111iiii . OOooOOo % OoooooooOO . iIii1I11I1II1 - I1IiiI
  if 80 - 80: oO0o + iIii1I11I1II1
 def is_multicast_address ( self ) :
  if ( self . is_ipv4 ( ) ) : return ( self . is_ipv4_multicast ( ) )
  if ( self . is_ipv6 ( ) ) : return ( self . is_ipv6_multicast ( ) )
  if ( self . is_mac ( ) ) : return ( self . is_mac_multicast ( ) )
  return ( False )
  if 87 - 87: I1ii11iIi11i % Ii1I . Ii1I
  if 71 - 71: OoO0O00 - IiII . i1IIi * I1IiiI % I11i
 def host_mask_len ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( LISP_IPV4_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( LISP_IPV6_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_MAC ) : return ( LISP_MAC_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_E164 ) : return ( LISP_E164_HOST_MASK_LEN )
  if ( self . afi == LISP_AFI_NAME ) : return ( len ( self . address ) * 8 )
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   return ( len ( self . address . print_geo ( ) ) * 8 )
   if 36 - 36: IiII * OoooooooOO . i11iIiiIii * i1IIi
  return ( 0 )
  if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
  if 38 - 38: II111iiii % iIii1I11I1II1 * IiII * OoOoOO00 % II111iiii . I1IiiI
 def is_iana_eid ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  iI1ii11Ii = self . address >> 96
  return ( iI1ii11Ii == 0x20010005 )
  if 35 - 35: OoooooooOO - i11iIiiIii * i11iIiiIii % Ii1I - OOooOOo . iIii1I11I1II1
  if 96 - 96: OOooOOo
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
   if 18 - 18: oO0o . I1ii11iIi11i % oO0o
  return ( 0 )
  if 43 - 43: oO0o / ooOoO0o . o0oOOo0O0Ooo . iIii1I11I1II1
  if 63 - 63: iII111i * iII111i
 def afi_to_version ( self ) :
  if ( self . afi == LISP_AFI_IPV4 ) : return ( 4 )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( 6 )
  return ( 0 )
  if 78 - 78: iIii1I11I1II1 % iIii1I11I1II1 . iIii1I11I1II1 / Ii1I . O0 + i1IIi
  if 53 - 53: Ii1I . I1ii11iIi11i - OOooOOo - ooOoO0o
 def packet_format ( self ) :
  if 17 - 17: OoooooooOO / I1IiiI * ooOoO0o % I1ii11iIi11i . OoO0O00
  if 5 - 5: OoO0O00 % I1Ii111 . oO0o . Ii1I + I1IiiI
  if 95 - 95: II111iiii . iII111i - iIii1I11I1II1 / I11i + ooOoO0o * I1Ii111
  if 92 - 92: iII111i * OoooooooOO % I1IiiI / OOooOOo
  if 46 - 46: OoOoOO00
  if ( self . afi == LISP_AFI_IPV4 ) : return ( "I" )
  if ( self . afi == LISP_AFI_IPV6 ) : return ( "QQ" )
  if ( self . afi == LISP_AFI_MAC ) : return ( "HHH" )
  if ( self . afi == LISP_AFI_E164 ) : return ( "II" )
  if ( self . afi == LISP_AFI_LCAF ) : return ( "I" )
  return ( "" )
  if 52 - 52: o0oOOo0O0Ooo - OoO0O00 % i1IIi / Ii1I % IiII
  if 100 - 100: oO0o . i11iIiiIii - ooOoO0o
 def pack_address ( self ) :
  ii = self . packet_format ( )
  Oo00O0o0O = b""
  if ( self . is_ipv4 ( ) ) :
   Oo00O0o0O = struct . pack ( ii , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   O0oOo00oooO = byte_swap_64 ( self . address >> 64 )
   Iii = byte_swap_64 ( self . address & 0xffffffffffffffff )
   Oo00O0o0O = struct . pack ( ii , O0oOo00oooO , Iii )
  elif ( self . is_mac ( ) ) :
   iI1ii11Ii = self . address
   O0oOo00oooO = ( iI1ii11Ii >> 32 ) & 0xffff
   Iii = ( iI1ii11Ii >> 16 ) & 0xffff
   II11II1111 = iI1ii11Ii & 0xffff
   Oo00O0o0O = struct . pack ( ii , O0oOo00oooO , Iii , II11II1111 )
  elif ( self . is_e164 ( ) ) :
   iI1ii11Ii = self . address
   O0oOo00oooO = ( iI1ii11Ii >> 32 ) & 0xffffffff
   Iii = ( iI1ii11Ii & 0xffffffff )
   Oo00O0o0O = struct . pack ( ii , O0oOo00oooO , Iii )
  elif ( self . is_dist_name ( ) ) :
   Oo00O0o0O += ( self . address + "\0" ) . encode ( )
   if 32 - 32: I1IiiI / i1IIi / I1ii11iIi11i % i1IIi . ooOoO0o % I1ii11iIi11i
  return ( Oo00O0o0O )
  if 97 - 97: OoO0O00 . OOooOOo % Ii1I + OoooooooOO * I1Ii111
  if 89 - 89: I11i
 def unpack_address ( self , packet ) :
  ii = self . packet_format ( )
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 91 - 91: OoooooooOO - IiII - Ii1I
  iI1ii11Ii = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 36 - 36: OOooOOo
  if ( self . is_ipv4 ( ) ) :
   self . address = socket . ntohl ( iI1ii11Ii [ 0 ] )
   if 76 - 76: OoO0O00 . i1IIi
  elif ( self . is_ipv6 ( ) ) :
   if 98 - 98: O0
   if 86 - 86: O0 * oO0o + Oo0Ooo / II111iiii + i1IIi
   if 12 - 12: I1IiiI + OOooOOo / Ii1I % i11iIiiIii - I1Ii111 % I11i
   if 49 - 49: I11i * i1IIi - iII111i
   if 98 - 98: iIii1I11I1II1 - I11i % i11iIiiIii * I1IiiI / OoOoOO00 * ooOoO0o
   if 78 - 78: i11iIiiIii % oO0o % Ii1I / I1Ii111 / I1Ii111
   if 20 - 20: iII111i / I11i / iIii1I11I1II1
   if 94 - 94: i11iIiiIii % I1ii11iIi11i % IiII - I1Ii111
   if ( iI1ii11Ii [ 0 ] <= 0xffff and ( iI1ii11Ii [ 0 ] & 0xff ) == 0 ) :
    O0O0OooO = ( iI1ii11Ii [ 0 ] << 48 ) << 64
   else :
    O0O0OooO = byte_swap_64 ( iI1ii11Ii [ 0 ] ) << 64
    if 88 - 88: I1ii11iIi11i . i1IIi * iII111i
   O0oooo = byte_swap_64 ( iI1ii11Ii [ 1 ] )
   self . address = O0O0OooO | O0oooo
   if 43 - 43: OoooooooOO + i1IIi . O0
  elif ( self . is_mac ( ) ) :
   iiIiI111 = iI1ii11Ii [ 0 ]
   OooOo = iI1ii11Ii [ 1 ]
   i1i = iI1ii11Ii [ 2 ]
   self . address = ( iiIiI111 << 32 ) + ( OooOo << 16 ) + i1i
   if 34 - 34: iIii1I11I1II1 . i11iIiiIii - OoOoOO00
  elif ( self . is_e164 ( ) ) :
   self . address = ( iI1ii11Ii [ 0 ] << 32 ) + iI1ii11Ii [ 1 ]
   if 34 - 34: i11iIiiIii * OoooooooOO
  elif ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   OOOO00oo00oo = 0
   if 74 - 74: OoooooooOO * iII111i % OOooOOo . OoooooooOO * I11i % I1Ii111
  packet = packet [ OOOO00oo00oo : : ]
  return ( packet )
  if 67 - 67: I11i * i1IIi
  if 7 - 7: i1IIi * OoOoOO00 . Ii1I
 def is_ipv4 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV4 ) else False )
  if 80 - 80: OoOoOO00 + o0oOOo0O0Ooo - II111iiii
  if 3 - 3: ooOoO0o * I1Ii111
 def is_ipv4_link_local ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 16 ) & 0xffff ) == 0xa9fe )
  if 34 - 34: Ii1I / Oo0Ooo . II111iiii - ooOoO0o - I1ii11iIi11i % OoOoOO00
  if 43 - 43: Ii1I * oO0o
 def is_ipv4_loopback ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( self . address == 0x7f000001 )
  if 57 - 57: OoooooooOO + I1IiiI % I1ii11iIi11i % ooOoO0o * I1Ii111
  if 9 - 9: i11iIiiIii
 def is_ipv4_multicast ( self ) :
  if ( self . is_ipv4 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 24 ) & 0xf0 ) == 0xe0 )
  if 85 - 85: IiII / o0oOOo0O0Ooo * ooOoO0o
  if 74 - 74: O0 - o0oOOo0O0Ooo
 def is_ipv4_string ( self , addr_str ) :
  return ( addr_str . find ( "." ) != - 1 )
  if 68 - 68: I1Ii111
  if 19 - 19: o0oOOo0O0Ooo
 def is_ipv6 ( self ) :
  return ( True if ( self . afi == LISP_AFI_IPV6 ) else False )
  if 63 - 63: OoooooooOO % ooOoO0o
  if 26 - 26: OOooOOo + Oo0Ooo
 def is_ipv6_link_local ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 112 ) & 0xffff ) == 0xfe80 )
  if 97 - 97: I1Ii111 * I1Ii111 + iII111i % Ii1I / iII111i
  if 73 - 73: OoOoOO00 % I1Ii111 . I1ii11iIi11i
 def is_ipv6_string_link_local ( self , addr_str ) :
  return ( addr_str . find ( "fe80::" ) != - 1 )
  if 45 - 45: iIii1I11I1II1 % Ii1I . OoOoOO00 . o0oOOo0O0Ooo - OoooooooOO
  if 46 - 46: I1ii11iIi11i
 def is_ipv6_loopback ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( self . address == 1 )
  if 32 - 32: iII111i * i11iIiiIii / IiII + i11iIiiIii + O0
  if 51 - 51: I1Ii111
 def is_ipv6_multicast ( self ) :
  if ( self . is_ipv6 ( ) == False ) : return ( False )
  return ( ( ( self . address >> 120 ) & 0xff ) == 0xff )
  if 95 - 95: Ii1I / Ii1I * OoO0O00 . OoooooooOO . OoooooooOO * I11i
  if 76 - 76: OoooooooOO - Ii1I + IiII % OoOoOO00 / OoooooooOO
 def is_ipv6_string ( self , addr_str ) :
  return ( addr_str . find ( ":" ) != - 1 )
  if 55 - 55: i11iIiiIii - IiII * OOooOOo + II111iiii . I1ii11iIi11i / O0
  if 16 - 16: II111iiii . Oo0Ooo * I1Ii111 + o0oOOo0O0Ooo - i11iIiiIii
 def is_mac ( self ) :
  return ( True if ( self . afi == LISP_AFI_MAC ) else False )
  if 98 - 98: II111iiii - i1IIi - ooOoO0o
  if 36 - 36: IiII + o0oOOo0O0Ooo
 def is_mac_multicast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( ( self . address & 0x010000000000 ) != 0 )
  if 81 - 81: OOooOOo / I11i % oO0o + ooOoO0o
  if 10 - 10: oO0o / i11iIiiIii
 def is_mac_broadcast ( self ) :
  if ( self . is_mac ( ) == False ) : return ( False )
  return ( self . address == 0xffffffffffff )
  if 73 - 73: OoO0O00 - i1IIi
  if 52 - 52: I1ii11iIi11i
 def is_mac_string ( self , addr_str ) :
  return ( len ( addr_str ) == 15 and addr_str . find ( "-" ) != - 1 )
  if 4 - 4: Ii1I - iII111i + i1IIi - I1Ii111 / iII111i . Oo0Ooo
  if 18 - 18: oO0o % iIii1I11I1II1 + ooOoO0o
 def is_link_local_multicast ( self ) :
  if ( self . is_ipv4 ( ) ) :
   return ( ( 0xe0ffff00 & self . address ) == 0xe0000000 )
   if 34 - 34: I1IiiI - OoooooooOO . IiII - OOooOOo % IiII
  if ( self . is_ipv6 ( ) ) :
   return ( ( self . address >> 112 ) & 0xffff == 0xff02 )
   if 19 - 19: IiII + I1ii11iIi11i % Oo0Ooo
  return ( False )
  if 32 - 32: OOooOOo
  if 46 - 46: II111iiii . OoO0O00
 def is_null ( self ) :
  return ( True if ( self . afi == LISP_AFI_NONE ) else False )
  if 97 - 97: oO0o
  if 45 - 45: i11iIiiIii / IiII + OoO0O00
 def is_ultimate_root ( self ) :
  return ( True if self . afi == LISP_AFI_ULTIMATE_ROOT else False )
  if 55 - 55: Ii1I / II111iiii - oO0o
  if 58 - 58: i1IIi . OoooooooOO % iIii1I11I1II1 * o0oOOo0O0Ooo + O0 / oO0o
 def is_iid_range ( self ) :
  return ( True if self . afi == LISP_AFI_IID_RANGE else False )
  if 77 - 77: I11i . I1ii11iIi11i
  if 92 - 92: i11iIiiIii + I11i % I1IiiI / ooOoO0o
 def is_e164 ( self ) :
  return ( True if ( self . afi == LISP_AFI_E164 ) else False )
  if 28 - 28: i1IIi . I1IiiI
  if 41 - 41: I1ii11iIi11i . I1Ii111 * OoOoOO00 . I1Ii111 / o0oOOo0O0Ooo
 def is_dist_name ( self ) :
  return ( True if ( self . afi == LISP_AFI_NAME ) else False )
  if 41 - 41: o0oOOo0O0Ooo / o0oOOo0O0Ooo . Oo0Ooo
  if 4 - 4: I1Ii111
 def is_geo_prefix ( self ) :
  return ( True if ( self . afi == LISP_AFI_GEO_COORD ) else False )
  if 85 - 85: iIii1I11I1II1 % Oo0Ooo
  if 20 - 20: IiII + i11iIiiIii * OOooOOo
 def is_binary ( self ) :
  if ( self . is_dist_name ( ) ) : return ( False )
  if ( self . is_geo_prefix ( ) ) : return ( False )
  return ( True )
  if 27 - 27: O0 * OoO0O00 * I1ii11iIi11i
  if 40 - 40: O0 + oO0o - ooOoO0o + I1IiiI - IiII
 def store_address ( self , addr_str ) :
  if ( self . afi == LISP_AFI_NONE ) : self . string_to_afi ( addr_str )
  if 60 - 60: I1Ii111 * OoO0O00 * oO0o + oO0o
  if 34 - 34: o0oOOo0O0Ooo
  if 76 - 76: oO0o + OoooooooOO % OoOoOO00 / OoOoOO00
  if 51 - 51: II111iiii / OoOoOO00
  o000o0O0Oo00 = addr_str . find ( "[" )
  oO0OO = addr_str . find ( "]" )
  if ( o000o0O0Oo00 != - 1 and oO0OO != - 1 ) :
   self . instance_id = int ( addr_str [ o000o0O0Oo00 + 1 : oO0OO ] )
   addr_str = addr_str [ oO0OO + 1 : : ]
   if ( self . is_dist_name ( ) == False ) :
    addr_str = addr_str . replace ( " " , "" )
    if 69 - 69: i11iIiiIii
    if 77 - 77: I1ii11iIi11i % OoooooooOO - Oo0Ooo - Ii1I + I11i
    if 93 - 93: I1IiiI % O0 * OoO0O00 % OoOoOO00 . I1Ii111 * I1IiiI
    if 95 - 95: IiII + o0oOOo0O0Ooo - o0oOOo0O0Ooo
    if 83 - 83: ooOoO0o
    if 59 - 59: I1ii11iIi11i
  if ( self . is_ipv4 ( ) ) :
   i11O0 = addr_str . split ( "." )
   oO00o = int ( i11O0 [ 0 ] ) << 24
   oO00o += int ( i11O0 [ 1 ] ) << 16
   oO00o += int ( i11O0 [ 2 ] ) << 8
   oO00o += int ( i11O0 [ 3 ] )
   self . address = oO00o
  elif ( self . is_ipv6 ( ) ) :
   if 41 - 41: IiII % i1IIi
   if 34 - 34: o0oOOo0O0Ooo - iII111i / O0 / OOooOOo - Oo0Ooo
   if 29 - 29: OoooooooOO - iII111i
   if 97 - 97: I1Ii111 . Oo0Ooo
   if 44 - 44: OoO0O00 + OOooOOo
   if 9 - 9: iII111i . i11iIiiIii * IiII . I11i
   if 40 - 40: i11iIiiIii + iII111i % I1IiiI % I11i - Oo0Ooo * ooOoO0o
   if 96 - 96: I1IiiI % I11i . I1Ii111 % O0 . O0
   if 14 - 14: ooOoO0o . OoOoOO00 + ooOoO0o * OoOoOO00 . OoOoOO00 * Oo0Ooo
   if 40 - 40: OoooooooOO
   if 14 - 14: o0oOOo0O0Ooo / OOooOOo . OoOoOO00 % iIii1I11I1II1 % OoOoOO00
   if 92 - 92: o0oOOo0O0Ooo + II111iiii
   if 56 - 56: OoOoOO00 - OoOoOO00 / Ii1I
   if 92 - 92: iIii1I11I1II1
   if 21 - 21: I1IiiI
   if 69 - 69: OoooooooOO + iII111i
   if 29 - 29: ooOoO0o * I1IiiI / Oo0Ooo / I1ii11iIi11i
   OOo0OO0o = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 65 - 65: OoooooooOO + OOooOOo - I1Ii111
   addr_str = binascii . hexlify ( addr_str )
   if 78 - 78: Oo0Ooo * OOooOOo + i11iIiiIii
   if ( OOo0OO0o ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 15 - 15: I1ii11iIi11i % I1Ii111 . I1ii11iIi11i - iIii1I11I1II1
   self . address = int ( addr_str , 16 )
   if 20 - 20: i1IIi - Ii1I . II111iiii + O0 % oO0o % II111iiii
  elif ( self . is_geo_prefix ( ) ) :
   iIiiiIIi = lisp_geo ( None )
   iIiiiIIi . name = "geo-prefix-{}" . format ( iIiiiIIi )
   iIiiiIIi . parse_geo_string ( addr_str )
   self . address = iIiiiIIi
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
   if 26 - 26: iIii1I11I1II1 - Ii1I / iIii1I11I1II1 . i1IIi - o0oOOo0O0Ooo
  self . mask_len = self . host_mask_len ( )
  if 48 - 48: iII111i . i11iIiiIii - iIii1I11I1II1 / iIii1I11I1II1
  if 92 - 92: II111iiii . oO0o - O0 + o0oOOo0O0Ooo * I1ii11iIi11i
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   o00O = prefix_str . find ( "]" )
   iII1IiI1I11i = len ( prefix_str [ o00O + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , iII1IiI1I11i = prefix_str . split ( "/" )
  else :
   oO0OO00OOo0 = prefix_str . find ( "'" )
   if ( oO0OO00OOo0 == - 1 ) : return
   iI1i = prefix_str . find ( "'" , oO0OO00OOo0 + 1 )
   if ( iI1i == - 1 ) : return
   iII1IiI1I11i = len ( prefix_str [ oO0OO00OOo0 + 1 : iI1i ] ) * 8
   if 32 - 32: I1IiiI % OoO0O00
   if 71 - 71: OoooooooOO . I11i . I1IiiI
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( iII1IiI1I11i )
  if 27 - 27: i11iIiiIii + Oo0Ooo * I11i / OOooOOo - iII111i
  if 42 - 42: ooOoO0o . II111iiii % OoOoOO00 - I11i
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  I111II11i1I = ( 2 ** self . mask_len ) - 1
  iiiIIiiIII1ii1I = self . addr_length ( ) * 8 - self . mask_len
  I111II11i1I <<= iiiIIiiIII1ii1I
  self . address &= I111II11i1I
  if 80 - 80: OoO0O00 + I1IiiI % i1IIi / I11i % i1IIi * i11iIiiIii
  if 27 - 27: OoOoOO00 / I1Ii111 * O0 / I1IiiI - IiII / o0oOOo0O0Ooo
 def is_geo_string ( self , addr_str ) :
  o00O = addr_str . find ( "]" )
  if ( o00O != - 1 ) : addr_str = addr_str [ o00O + 1 : : ]
  if 70 - 70: I1ii11iIi11i
  iIiiiIIi = addr_str . split ( "/" )
  if ( len ( iIiiiIIi ) == 2 ) :
   if ( iIiiiIIi [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 11 - 11: I1Ii111
  iIiiiIIi = iIiiiIIi [ 0 ]
  iIiiiIIi = iIiiiIIi . split ( "-" )
  ooo0OoO0ooO = len ( iIiiiIIi )
  if ( ooo0OoO0ooO < 8 or ooo0OoO0ooO > 9 ) : return ( False )
  if 84 - 84: o0oOOo0O0Ooo . ooOoO0o + OOooOOo - I1IiiI + OOooOOo
  for iIIIII1i1III in range ( 0 , ooo0OoO0ooO ) :
   if ( iIIIII1i1III == 3 ) :
    if ( iIiiiIIi [ iIIIII1i1III ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 9 - 9: iIii1I11I1II1 % OoO0O00
   if ( iIIIII1i1III == 7 ) :
    if ( iIiiiIIi [ iIIIII1i1III ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 45 - 45: OoooooooOO . O0 * oO0o + IiII
   if ( iIiiiIIi [ iIIIII1i1III ] . isdigit ( ) == False ) : return ( False )
   if 18 - 18: II111iiii . O0 - I11i / I11i
  return ( True )
  if 71 - 71: OoOoOO00 + iIii1I11I1II1 - II111iiii / i1IIi
  if 39 - 39: Ii1I + I1Ii111 * Oo0Ooo + OoOoOO00 / I1Ii111 - ooOoO0o
 def string_to_afi ( self , addr_str ) :
  if ( addr_str . count ( "'" ) == 2 ) :
   self . afi = LISP_AFI_NAME
   return
   if 66 - 66: I11i * OoO0O00
  if ( addr_str . find ( ":" ) != - 1 ) : self . afi = LISP_AFI_IPV6
  elif ( addr_str . find ( "." ) != - 1 ) : self . afi = LISP_AFI_IPV4
  elif ( addr_str . find ( "+" ) != - 1 ) : self . afi = LISP_AFI_E164
  elif ( self . is_geo_string ( addr_str ) ) : self . afi = LISP_AFI_GEO_COORD
  elif ( addr_str . find ( "-" ) != - 1 ) : self . afi = LISP_AFI_MAC
  else : self . afi = LISP_AFI_NONE
  if 98 - 98: IiII . Oo0Ooo + I1Ii111
  if 63 - 63: oO0o * I1IiiI * oO0o
 def print_address ( self ) :
  iI1ii11Ii = self . print_address_no_iid ( )
  i1I1iI = "[" + str ( self . instance_id )
  for o000o0O0Oo00 in self . iid_list : i1I1iI += "," + str ( o000o0O0Oo00 )
  i1I1iI += "]"
  iI1ii11Ii = "{}{}" . format ( i1I1iI , iI1ii11Ii )
  return ( iI1ii11Ii )
  if 56 - 56: oO0o - Ii1I % I1Ii111
  if 100 - 100: OOooOOo * IiII % IiII / o0oOOo0O0Ooo * OoO0O00 % OoOoOO00
 def print_address_no_iid ( self ) :
  if ( self . is_ipv4 ( ) ) :
   iI1ii11Ii = self . address
   iii1I = iI1ii11Ii >> 24
   oOo = ( iI1ii11Ii >> 16 ) & 0xff
   OO000oOO = ( iI1ii11Ii >> 8 ) & 0xff
   i1I1111I = iI1ii11Ii & 0xff
   return ( "{}.{}.{}.{}" . format ( iii1I , oOo , OO000oOO , i1I1111I ) )
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
   if 65 - 65: oO0o + O0 / i11iIiiIii
  return ( "unknown-afi:{}" . format ( self . afi ) )
  if 64 - 64: OoO0O00 % OoOoOO00 % I1IiiI - Ii1I / IiII * Ii1I
  if 74 - 74: IiII - O0 % OOooOOo % OoooooooOO - I11i
 def print_prefix ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "[*]" )
  if ( self . is_iid_range ( ) ) :
   if ( self . mask_len == 32 ) : return ( "[{}]" . format ( self . instance_id ) )
   IiIIIi1 = self . instance_id + ( 2 ** ( 32 - self . mask_len ) - 1 )
   return ( "[{}-{}]" . format ( self . instance_id , IiIIIi1 ) )
   if 25 - 25: ooOoO0o
  iI1ii11Ii = self . print_address ( )
  if ( self . is_dist_name ( ) ) : return ( iI1ii11Ii )
  if ( self . is_geo_prefix ( ) ) : return ( iI1ii11Ii )
  if 87 - 87: iII111i - OoO0O00 . Ii1I / ooOoO0o
  o00O = iI1ii11Ii . find ( "no-address" )
  if ( o00O == - 1 ) :
   iI1ii11Ii = "{}/{}" . format ( iI1ii11Ii , str ( self . mask_len ) )
  else :
   iI1ii11Ii = iI1ii11Ii [ 0 : o00O ]
   if 88 - 88: O0 % OOooOOo . iII111i
  return ( iI1ii11Ii )
  if 40 - 40: O0 . Ii1I % IiII % I1ii11iIi11i - OoOoOO00
  if 94 - 94: I1IiiI . I1Ii111
 def print_prefix_no_iid ( self ) :
  iI1ii11Ii = self . print_address_no_iid ( )
  if ( self . is_dist_name ( ) ) : return ( iI1ii11Ii )
  if ( self . is_geo_prefix ( ) ) : return ( iI1ii11Ii )
  return ( "{}/{}" . format ( iI1ii11Ii , str ( self . mask_len ) ) )
  if 37 - 37: i1IIi - O0
  if 36 - 36: I1Ii111 . OoooooooOO - i1IIi % iII111i - II111iiii * i11iIiiIii
 def print_prefix_url ( self ) :
  if ( self . is_ultimate_root ( ) ) : return ( "0--0" )
  iI1ii11Ii = self . print_address ( )
  o00O = iI1ii11Ii . find ( "]" )
  if ( o00O != - 1 ) : iI1ii11Ii = iI1ii11Ii [ o00O + 1 : : ]
  if ( self . is_geo_prefix ( ) ) :
   iI1ii11Ii = iI1ii11Ii . replace ( "/" , "-" )
   return ( "{}-{}" . format ( self . instance_id , iI1ii11Ii ) )
   if 90 - 90: OoOoOO00 % iII111i - Oo0Ooo
  return ( "{}-{}-{}" . format ( self . instance_id , iI1ii11Ii , self . mask_len ) )
  if 13 - 13: o0oOOo0O0Ooo / O0 . I1Ii111 * I1Ii111
  if 76 - 76: Ii1I - iII111i
 def print_sg ( self , g ) :
  OOo0oOO0o0oo0 = self . print_prefix ( )
  OOo0OOo = OOo0oOO0o0oo0 . find ( "]" ) + 1
  g = g . print_prefix ( )
  i11oo00ooO0 = g . find ( "]" ) + 1
  III1II1i = "[{}]({}, {})" . format ( self . instance_id , OOo0oOO0o0oo0 [ OOo0OOo : : ] , g [ i11oo00ooO0 : : ] )
  return ( III1II1i )
  if 74 - 74: Oo0Ooo * I1Ii111
  if 72 - 72: OoOoOO00 + O0 - IiII * ooOoO0o
 def hash_address ( self , addr ) :
  O0oOo00oooO = self . address
  Iii = addr . address
  if 20 - 20: II111iiii % OoOoOO00 * i11iIiiIii
  if ( self . is_geo_prefix ( ) ) : O0oOo00oooO = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : Iii = addr . address . print_geo ( )
  if 68 - 68: IiII / ooOoO0o
  if ( type ( O0oOo00oooO ) == str ) :
   O0oOo00oooO = int ( binascii . hexlify ( O0oOo00oooO [ 0 : 1 ] ) )
   if 100 - 100: ooOoO0o / I1IiiI
  if ( type ( Iii ) == str ) :
   Iii = int ( binascii . hexlify ( Iii [ 0 : 1 ] ) )
   if 69 - 69: ooOoO0o + OoO0O00 * o0oOOo0O0Ooo - ooOoO0o
  return ( O0oOo00oooO ^ Iii )
  if 66 - 66: OoooooooOO / iII111i / I1IiiI % ooOoO0o / OoO0O00 + OOooOOo
  if 64 - 64: i1IIi
  if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
  if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
  if 5 - 5: OoOoOO00 % i1IIi
  if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 76 - 76: Oo0Ooo + I1IiiI - O0
  iII1IiI1I11i = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   O0ooOo00ooOO = 2 ** ( 32 - iII1IiI1I11i )
   i1IiI = prefix . instance_id
   IiIIIi1 = i1IiI + O0ooOo00ooOO
   return ( self . instance_id in range ( i1IiI , IiIIIi1 ) )
   if 53 - 53: OoO0O00 + iII111i / OoooooooOO
   if 52 - 52: O0
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
   if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
   if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
   if 83 - 83: oO0o / OoO0O00
   if 34 - 34: OoooooooOO - i1IIi * O0
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   iI1ii11Ii = self . address
   oOOO0O = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    iI1ii11Ii = self . address . print_geo ( )
    oOOO0O = prefix . address . print_geo ( )
    if 77 - 77: II111iiii
   if ( len ( iI1ii11Ii ) < len ( oOOO0O ) ) : return ( False )
   return ( iI1ii11Ii . find ( oOOO0O ) == 0 )
   if 92 - 92: I1Ii111 / I1IiiI / I1ii11iIi11i + I11i + Ii1I
   if 51 - 51: OOooOOo
   if 85 - 85: II111iiii
   if 60 - 60: Ii1I * OOooOOo - o0oOOo0O0Ooo - Ii1I / Oo0Ooo . OOooOOo
   if 43 - 43: II111iiii * o0oOOo0O0Ooo % o0oOOo0O0Ooo + iIii1I11I1II1 + OoOoOO00
  if ( self . mask_len < iII1IiI1I11i ) : return ( False )
  if 54 - 54: II111iiii + OOooOOo * Oo0Ooo * I1Ii111 - o0oOOo0O0Ooo % Ii1I
  iiiIIiiIII1ii1I = ( prefix . addr_length ( ) * 8 ) - iII1IiI1I11i
  I111II11i1I = ( 2 ** iII1IiI1I11i - 1 ) << iiiIIiiIII1ii1I
  return ( ( self . address & I111II11i1I ) == prefix . address )
  if 69 - 69: I11i + OoOoOO00 - i11iIiiIii * O0 % O0
  if 81 - 81: I11i - o0oOOo0O0Ooo % Ii1I / I1Ii111 * II111iiii
 def mask_address ( self , mask_len ) :
  iiiIIiiIII1ii1I = ( self . addr_length ( ) * 8 ) - mask_len
  I111II11i1I = ( 2 ** mask_len - 1 ) << iiiIIiiIII1ii1I
  self . address &= I111II11i1I
  if 40 - 40: OoO0O00 . i11iIiiIii
  if 36 - 36: o0oOOo0O0Ooo * iII111i / I1ii11iIi11i % i1IIi % I1ii11iIi11i + i11iIiiIii
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  i1I1i = self . print_prefix ( )
  Iii111II1I11I = prefix . print_prefix ( ) if prefix else ""
  return ( i1I1i == Iii111II1I11I )
  if 18 - 18: OOooOOo / O0 . OoO0O00 - II111iiii * OOooOOo
  if 13 - 13: OoO0O00 % i1IIi . i11iIiiIii / iII111i
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   IiI1iI1I = lisp_myrlocs [ 0 ]
   if ( IiI1iI1I == None ) : return ( False )
   IiI1iI1I = IiI1iI1I . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == IiI1iI1I )
   if 63 - 63: I11i
  if ( self . is_ipv6 ( ) ) :
   IiI1iI1I = lisp_myrlocs [ 1 ]
   if ( IiI1iI1I == None ) : return ( False )
   IiI1iI1I = IiI1iI1I . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == IiI1iI1I )
   if 42 - 42: OOooOOo * ooOoO0o / i1IIi . i11iIiiIii - oO0o - Ii1I
  return ( False )
  if 5 - 5: i1IIi + II111iiii . ooOoO0o
  if 21 - 21: i1IIi
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 96 - 96: OoOoOO00 * OoOoOO00 % OoO0O00 * iII111i
  self . instance_id = iid
  self . mask_len = mask_len
  if 51 - 51: I1IiiI + i11iIiiIii + iII111i
  if 57 - 57: Oo0Ooo . oO0o
 def lcaf_length ( self , lcaf_type ) :
  OOOOo0o0O0o = self . addr_length ( ) + 2
  if ( lcaf_type == LISP_LCAF_AFI_LIST_TYPE ) : OOOOo0o0O0o += 4
  if ( lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE ) : OOOOo0o0O0o += 4
  if ( lcaf_type == LISP_LCAF_ASN_TYPE ) : OOOOo0o0O0o += 4
  if ( lcaf_type == LISP_LCAF_APP_DATA_TYPE ) : OOOOo0o0O0o += 8
  if ( lcaf_type == LISP_LCAF_GEO_COORD_TYPE ) : OOOOo0o0O0o += 12
  if ( lcaf_type == LISP_LCAF_OPAQUE_TYPE ) : OOOOo0o0O0o += 0
  if ( lcaf_type == LISP_LCAF_NAT_TYPE ) : OOOOo0o0O0o += 4
  if ( lcaf_type == LISP_LCAF_NONCE_LOC_TYPE ) : OOOOo0o0O0o += 4
  if ( lcaf_type == LISP_LCAF_MCAST_INFO_TYPE ) : OOOOo0o0O0o = OOOOo0o0O0o * 2 + 8
  if ( lcaf_type == LISP_LCAF_ELP_TYPE ) : OOOOo0o0O0o += 0
  if ( lcaf_type == LISP_LCAF_SECURITY_TYPE ) : OOOOo0o0O0o += 6
  if ( lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE ) : OOOOo0o0O0o += 4
  if ( lcaf_type == LISP_LCAF_RLE_TYPE ) : OOOOo0o0O0o += 4
  return ( OOOOo0o0O0o )
  if 52 - 52: IiII % OoO0O00 - OoO0O00 . I1IiiI + OoO0O00 * ooOoO0o
  if 44 - 44: iIii1I11I1II1 / Ii1I - oO0o % i11iIiiIii
  if 65 - 65: I1ii11iIi11i * Oo0Ooo / Ii1I . OOooOOo * iIii1I11I1II1 + Oo0Ooo
  if 44 - 44: ooOoO0o * iII111i * IiII % o0oOOo0O0Ooo
  if 45 - 45: OoOoOO00 % o0oOOo0O0Ooo + IiII / i11iIiiIii
  if 29 - 29: iIii1I11I1II1 . OoO0O00 / I1IiiI
  if 38 - 38: Oo0Ooo / Oo0Ooo % ooOoO0o
  if 56 - 56: oO0o / iII111i % i1IIi * II111iiii . Ii1I
  if 10 - 10: ooOoO0o - I1ii11iIi11i
  if 82 - 82: o0oOOo0O0Ooo / I11i - I11i / O0 * I1IiiI / OoO0O00
  if 71 - 71: I11i % I11i - i11iIiiIii + iIii1I11I1II1 / iII111i
  if 63 - 63: O0 * i11iIiiIii / IiII / IiII
  if 72 - 72: i11iIiiIii * OoOoOO00 % oO0o / I1Ii111
  if 9 - 9: iIii1I11I1II1 . IiII
  if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
  if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
  if 46 - 46: I1Ii111 * II111iiii + II111iiii * O0 % II111iiii
 def lcaf_encode_iid ( self ) :
  oo0O00o0oO00 = LISP_LCAF_INSTANCE_ID_TYPE
  o0OoOoOo0O = socket . htons ( self . lcaf_length ( oo0O00o0oO00 ) )
  i1I1iI = self . instance_id
  IiIIi = self . afi
  I1iIIIiI1iI11 = 0
  if ( IiIIi < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    IiIIi = LISP_AFI_LCAF
    I1iIIIiI1iI11 = 0
   else :
    IiIIi = 0
    I1iIIIiI1iI11 = self . mask_len
    if 37 - 37: OOooOOo . iIii1I11I1II1 / O0 . ooOoO0o + OOooOOo - OoooooooOO
    if 96 - 96: I1Ii111 / oO0o . I1ii11iIi11i % I1IiiI * OOooOOo
    if 99 - 99: i11iIiiIii - I1Ii111
  IIiiii1I1 = struct . pack ( "BBBBH" , 0 , 0 , oo0O00o0oO00 , I1iIIIiI1iI11 , o0OoOoOo0O )
  IIiiii1I1 += struct . pack ( "IH" , socket . htonl ( i1I1iI ) , socket . htons ( IiIIi ) )
  if ( IiIIi == 0 ) : return ( IIiiii1I1 )
  if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   IIiiii1I1 = IIiiii1I1 [ 0 : - 2 ]
   IIiiii1I1 += self . address . encode_geo ( )
   return ( IIiiii1I1 )
   if 54 - 54: II111iiii * I1IiiI
   if 49 - 49: I1ii11iIi11i
  IIiiii1I1 += self . pack_address ( )
  return ( IIiiii1I1 )
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
 def lcaf_decode_iid ( self , packet ) :
  ii = "BBBBH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  O0O0oOO , IIIIIi1I1Ii , oo0O00o0oO00 , iIi11IIii , OOOOo0o0O0o = struct . unpack ( ii ,
 packet [ : OOOO00oo00oo ] )
  packet = packet [ OOOO00oo00oo : : ]
  if 55 - 55: OoO0O00 + o0oOOo0O0Ooo % OOooOOo + oO0o * OoO0O00
  if ( oo0O00o0oO00 != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 19 - 19: IiII . Ii1I / Ii1I + O0 - OOooOOo * IiII
  ii = "IH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
  if 7 - 7: I1Ii111 - I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoO0O00
  i1I1iI , IiIIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  packet = packet [ OOOO00oo00oo : : ]
  if 17 - 17: I1IiiI * Ii1I . i11iIiiIii - oO0o . i11iIiiIii + Oo0Ooo
  OOOOo0o0O0o = socket . ntohs ( OOOOo0o0O0o )
  self . instance_id = socket . ntohl ( i1I1iI )
  IiIIi = socket . ntohs ( IiIIi )
  self . afi = IiIIi
  if ( iIi11IIii != 0 and IiIIi == 0 ) : self . mask_len = iIi11IIii
  if ( IiIIi == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if iIi11IIii else LISP_AFI_ULTIMATE_ROOT
   if 42 - 42: iII111i
   if 51 - 51: I1IiiI - OoOoOO00 * I1Ii111 * iIii1I11I1II1
   if 5 - 5: i11iIiiIii / o0oOOo0O0Ooo
   if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
   if 12 - 12: I1ii11iIi11i / O0
  if ( IiIIi == 0 ) : return ( packet )
  if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
  if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
  if 100 - 100: Oo0Ooo / I1IiiI / iII111i / I1Ii111 / oO0o % o0oOOo0O0Ooo
  if 16 - 16: I1IiiI + I11i
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 66 - 66: OoooooooOO % II111iiii / I1Ii111 . i11iIiiIii
   if 67 - 67: Ii1I + Oo0Ooo - I1IiiI - IiII + oO0o + Oo0Ooo
   if 84 - 84: I1ii11iIi11i % oO0o - OOooOOo * Ii1I
   if 78 - 78: i1IIi / ooOoO0o / oO0o
   if 21 - 21: IiII % Ii1I + OOooOOo + IiII
  if ( IiIIi == LISP_AFI_LCAF ) :
   ii = "BBBBH"
   OOOO00oo00oo = struct . calcsize ( ii )
   if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
   if 90 - 90: o0oOOo0O0Ooo
   Oo0oOo0Ooo , iiI1 , oo0O00o0oO00 , IiI1 , IIiii11IiIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
   if 38 - 38: OoOoOO00 / OOooOOo % OoooooooOO * I1ii11iIi11i
   if 7 - 7: I11i * O0 + Oo0Ooo / O0 * oO0o + i11iIiiIii
   if ( oo0O00o0oO00 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 74 - 74: OoOoOO00
   IIiii11IiIi = socket . ntohs ( IIiii11IiIi )
   packet = packet [ OOOO00oo00oo : : ]
   if ( IIiii11IiIi > len ( packet ) ) : return ( None )
   if 91 - 91: i11iIiiIii / Ii1I % OOooOOo % O0 - I11i . I11i
   iIiiiIIi = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = iIiiiIIi
   packet = iIiiiIIi . decode_geo ( packet , IIiii11IiIi , IiI1 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 78 - 78: i1IIi + I11i % OoooooooOO + i1IIi + iII111i % Ii1I
   if 87 - 87: ooOoO0o . iIii1I11I1II1
  o0OoOoOo0O = self . addr_length ( )
  if ( len ( packet ) < o0OoOoOo0O ) : return ( None )
  if 99 - 99: Ii1I + OoooooooOO * IiII * i11iIiiIii - iIii1I11I1II1
  packet = self . unpack_address ( packet )
  return ( packet )
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
  if 30 - 30: I1ii11iIi11i + OoO0O00 - O0
  if 42 - 42: I11i - I1Ii111
  if 24 - 24: i1IIi
  if 93 - 93: OoOoOO00 - Oo0Ooo + iIii1I11I1II1 % iIii1I11I1II1 / I1ii11iIi11i - I1Ii111
  if 9 - 9: I1ii11iIi11i - o0oOOo0O0Ooo / i11iIiiIii * iII111i / OoOoOO00 . I1IiiI
  if 23 - 23: I1IiiI . iII111i % i1IIi
  if 92 - 92: o0oOOo0O0Ooo % i1IIi / OoooooooOO * OoooooooOO / iIii1I11I1II1
  if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
 def lcaf_encode_sg ( self , group ) :
  oo0O00o0oO00 = LISP_LCAF_MCAST_INFO_TYPE
  i1I1iI = socket . htonl ( self . instance_id )
  o0OoOoOo0O = socket . htons ( self . lcaf_length ( oo0O00o0oO00 ) )
  IIiiii1I1 = struct . pack ( "BBBBHIHBB" , 0 , 0 , oo0O00o0oO00 , 0 , o0OoOoOo0O , i1I1iI ,
 0 , self . mask_len , group . mask_len )
  if 33 - 33: I1Ii111 + OoooooooOO
  IIiiii1I1 += struct . pack ( "H" , socket . htons ( self . afi ) )
  IIiiii1I1 += self . pack_address ( )
  IIiiii1I1 += struct . pack ( "H" , socket . htons ( group . afi ) )
  IIiiii1I1 += group . pack_address ( )
  return ( IIiiii1I1 )
  if 73 - 73: O0 . Oo0Ooo
  if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
 def lcaf_decode_sg ( self , packet ) :
  ii = "BBBBHIHBB"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( [ None , None ] )
  if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
  O0O0oOO , IIIIIi1I1Ii , oo0O00o0oO00 , I1i1ii1IiI1i , OOOOo0o0O0o , i1I1iI , I1I1111i , o00oooo0Oo0o , OoO0o0 = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
  if 36 - 36: ooOoO0o - OoOoOO00 . iIii1I11I1II1 / oO0o % OoooooooOO * iII111i
  packet = packet [ OOOO00oo00oo : : ]
  if 42 - 42: oO0o
  if ( oo0O00o0oO00 != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 71 - 71: i11iIiiIii . I1Ii111 % OoO0O00 % I1IiiI
  self . instance_id = socket . ntohl ( i1I1iI )
  OOOOo0o0O0o = socket . ntohs ( OOOOo0o0O0o ) - 8
  if 46 - 46: IiII + oO0o - ooOoO0o
  if 2 - 2: i1IIi / Ii1I % OoO0O00
  if 85 - 85: i1IIi % iIii1I11I1II1
  if 10 - 10: O0 . oO0o * I1IiiI
  if 21 - 21: OoooooooOO
  ii = "H"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( [ None , None ] )
  if ( OOOOo0o0O0o < OOOO00oo00oo ) : return ( [ None , None ] )
  if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
  IiIIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  OOOOo0o0O0o -= OOOO00oo00oo
  self . afi = socket . ntohs ( IiIIi )
  self . mask_len = o00oooo0Oo0o
  o0OoOoOo0O = self . addr_length ( )
  if ( OOOOo0o0O0o < o0OoOoOo0O ) : return ( [ None , None ] )
  if 50 - 50: oO0o % OoOoOO00 + I1IiiI
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
  OOOOo0o0O0o -= o0OoOoOo0O
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
  if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
  if 46 - 46: o0oOOo0O0Ooo
  if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
  if 44 - 44: I11i . oO0o
  ii = "H"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( [ None , None ] )
  if ( OOOOo0o0O0o < OOOO00oo00oo ) : return ( [ None , None ] )
  if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
  IiIIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  OOOOo0o0O0o -= OOOO00oo00oo
  i1I1IIIiII = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  i1I1IIIiII . afi = socket . ntohs ( IiIIi )
  i1I1IIIiII . mask_len = OoO0o0
  i1I1IIIiII . instance_id = self . instance_id
  o0OoOoOo0O = self . addr_length ( )
  if ( OOOOo0o0O0o < o0OoOoOo0O ) : return ( [ None , None ] )
  if 74 - 74: OoOoOO00 % OoO0O00 . OoOoOO00
  packet = i1I1IIIiII . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 16 - 16: OoO0O00 / Ii1I * i11iIiiIii / o0oOOo0O0Ooo + I1Ii111
  return ( [ packet , i1I1IIIiII ] )
  if 21 - 21: I11i % I1ii11iIi11i
  if 8 - 8: OOooOOo % OoO0O00 + O0 - o0oOOo0O0Ooo
 def lcaf_decode_eid ( self , packet ) :
  ii = "BBB"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( [ None , None ] )
  if 46 - 46: Oo0Ooo . ooOoO0o + OoOoOO00 - I11i / i11iIiiIii . iII111i
  if 80 - 80: II111iiii + OoO0O00 % ooOoO0o + i11iIiiIii
  if 30 - 30: Ii1I / I1ii11iIi11i % IiII - Oo0Ooo
  if 100 - 100: IiII . I1Ii111 * oO0o % OoO0O00 . iIii1I11I1II1 * Oo0Ooo
  if 100 - 100: IiII - OoOoOO00 % iII111i
  I1i1ii1IiI1i , iiI1 , oo0O00o0oO00 = struct . unpack ( ii ,
 packet [ : OOOO00oo00oo ] )
  if 24 - 24: Oo0Ooo / OoO0O00 + i11iIiiIii
  if ( oo0O00o0oO00 == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( oo0O00o0oO00 == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , i1I1IIIiII = self . lcaf_decode_sg ( packet )
   return ( [ packet , i1I1IIIiII ] )
  elif ( oo0O00o0oO00 == LISP_LCAF_GEO_COORD_TYPE ) :
   ii = "BBBBH"
   OOOO00oo00oo = struct . calcsize ( ii )
   if ( len ( packet ) < OOOO00oo00oo ) : return ( None )
   if 81 - 81: i11iIiiIii . iIii1I11I1II1 - OoooooooOO
   Oo0oOo0Ooo , iiI1 , oo0O00o0oO00 , IiI1 , IIiii11IiIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] )
   if 52 - 52: O0 - I1Ii111 + oO0o % ooOoO0o . oO0o
   if 60 - 60: oO0o + o0oOOo0O0Ooo - OOooOOo % o0oOOo0O0Ooo . I11i + OoO0O00
   if ( oo0O00o0oO00 != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 27 - 27: i11iIiiIii - I1ii11iIi11i * I1Ii111 . I1IiiI / OoO0O00 * ooOoO0o
   IIiii11IiIi = socket . ntohs ( IIiii11IiIi )
   packet = packet [ OOOO00oo00oo : : ]
   if ( IIiii11IiIi > len ( packet ) ) : return ( None )
   if 42 - 42: OOooOOo
   iIiiiIIi = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = iIiiiIIi
   packet = iIiiiIIi . decode_geo ( packet , IIiii11IiIi , IiI1 )
   self . mask_len = self . host_mask_len ( )
   if 36 - 36: OoooooooOO + ooOoO0o + iII111i
  return ( [ packet , None ] )
  if 30 - 30: i1IIi % Ii1I
  if 18 - 18: o0oOOo0O0Ooo % I1ii11iIi11i . Ii1I . O0 * II111iiii + I1ii11iIi11i
  if 45 - 45: OoO0O00 / I1ii11iIi11i * ooOoO0o * OOooOOo % i11iIiiIii * iII111i
  if 33 - 33: oO0o . iII111i + Oo0Ooo
  if 33 - 33: ooOoO0o
  if 46 - 46: OoOoOO00 / iII111i - OoO0O00 . o0oOOo0O0Ooo
class lisp_elp_node ( object ) :
 def __init__ ( self ) :
  self . address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . probe = False
  self . strict = False
  self . eid = False
  self . we_are_last = False
  if 50 - 50: I1Ii111 . O0 . OoOoOO00 + I1Ii111 + OoooooooOO . i11iIiiIii
  if 65 - 65: I1IiiI % iIii1I11I1II1
 def copy_elp_node ( self ) :
  iIII1 = lisp_elp_node ( )
  iIII1 . copy_address ( self . address )
  iIII1 . probe = self . probe
  iIII1 . strict = self . strict
  iIII1 . eid = self . eid
  iIII1 . we_are_last = self . we_are_last
  return ( iIII1 )
  if 52 - 52: I1IiiI
  if 19 - 19: I1IiiI
  if 17 - 17: I11i + OoooooooOO
class lisp_elp ( object ) :
 def __init__ ( self , name ) :
  self . elp_name = name
  self . elp_nodes = [ ]
  self . use_elp_node = None
  self . we_are_last = False
  if 63 - 63: IiII
  if 3 - 3: oO0o * II111iiii . O0
 def copy_elp ( self ) :
  iIi11IIIIIIIi = lisp_elp ( self . elp_name )
  iIi11IIIIIIIi . use_elp_node = self . use_elp_node
  iIi11IIIIIIIi . we_are_last = self . we_are_last
  for iIII1 in self . elp_nodes :
   iIi11IIIIIIIi . elp_nodes . append ( iIII1 . copy_elp_node ( ) )
   if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
  return ( iIi11IIIIIIIi )
  if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
  if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
 def print_elp ( self , want_marker ) :
  O0o = ""
  for iIII1 in self . elp_nodes :
   oOOOO0OO = ""
   if ( want_marker ) :
    if ( iIII1 == self . use_elp_node ) :
     oOOOO0OO = "*"
    elif ( iIII1 . we_are_last ) :
     oOOOO0OO = "x"
     if 75 - 75: I1ii11iIi11i
     if 23 - 23: II111iiii . OoOoOO00 - i1IIi - OoO0O00 + O0 * ooOoO0o
   O0o += "{}{}({}{}{}), " . format ( oOOOO0OO ,
 iIII1 . address . print_address_no_iid ( ) ,
 "r" if iIII1 . eid else "R" , "P" if iIII1 . probe else "p" ,
 "S" if iIII1 . strict else "s" )
   if 72 - 72: I1IiiI + OoooooooOO * oO0o . iII111i + i11iIiiIii - OoooooooOO
  return ( O0o [ 0 : - 2 ] if O0o != "" else "" )
  if 68 - 68: I11i / iII111i - I11i + OoooooooOO / iII111i
  if 46 - 46: I11i / Ii1I + i1IIi + IiII - O0 / OOooOOo
 def select_elp_node ( self ) :
  o0O000Oooooo , i111II111iIi , i1iiI = lisp_myrlocs
  o00O = None
  if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
  for iIII1 in self . elp_nodes :
   if ( o0O000Oooooo and iIII1 . address . is_exact_match ( o0O000Oooooo ) ) :
    o00O = self . elp_nodes . index ( iIII1 )
    break
    if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
   if ( i111II111iIi and iIII1 . address . is_exact_match ( i111II111iIi ) ) :
    o00O = self . elp_nodes . index ( iIII1 )
    break
    if 71 - 71: i11iIiiIii + I11i / i11iIiiIii % Oo0Ooo / iIii1I11I1II1 * OoO0O00
    if 49 - 49: iII111i + OoOoOO00
    if 33 - 33: ooOoO0o
    if 19 - 19: I1Ii111 % IiII
    if 94 - 94: I1Ii111 * I1ii11iIi11i * I1ii11iIi11i - o0oOOo0O0Ooo . i11iIiiIii
    if 16 - 16: i1IIi
    if 88 - 88: OOooOOo
  if ( o00O == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   iIII1 . we_are_last = False
   return
   if 79 - 79: oO0o
   if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
   if 68 - 68: I1IiiI - OoOoOO00 - iIii1I11I1II1 % i11iIiiIii * OoOoOO00 * OoO0O00
   if 97 - 97: OoO0O00 - IiII + ooOoO0o % iIii1I11I1II1 % iII111i
   if 100 - 100: IiII - Ii1I * iIii1I11I1II1 . iII111i . i1IIi % Oo0Ooo
   if 11 - 11: I11i + oO0o % Ii1I
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ o00O ] ) :
   self . use_elp_node = None
   iIII1 . we_are_last = True
   return
   if 22 - 22: ooOoO0o
   if 83 - 83: OOooOOo - i11iIiiIii - i1IIi / oO0o
   if 33 - 33: OoO0O00 + OOooOOo
   if 36 - 36: o0oOOo0O0Ooo . o0oOOo0O0Ooo / oO0o * ooOoO0o * Ii1I * IiII
   if 39 - 39: i1IIi
  self . use_elp_node = self . elp_nodes [ o00O + 1 ]
  return
  if 79 - 79: ooOoO0o - II111iiii - oO0o
  if 55 - 55: iII111i % iIii1I11I1II1 + Ii1I + oO0o . i11iIiiIii - OOooOOo
  if 14 - 14: oO0o - i11iIiiIii / OoOoOO00 % o0oOOo0O0Ooo / IiII * I1IiiI
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
  if 2 - 2: i1IIi / I1Ii111 + I1IiiI + I1ii11iIi11i - o0oOOo0O0Ooo + iIii1I11I1II1
  if 78 - 78: I1ii11iIi11i % i1IIi . I1Ii111 + Oo0Ooo . o0oOOo0O0Ooo % II111iiii
 def copy_geo ( self ) :
  iIiiiIIi = lisp_geo ( self . geo_name )
  iIiiiIIi . latitude = self . latitude
  iIiiiIIi . lat_mins = self . lat_mins
  iIiiiIIi . lat_secs = self . lat_secs
  iIiiiIIi . longitude = self . longitude
  iIiiiIIi . long_mins = self . long_mins
  iIiiiIIi . long_secs = self . long_secs
  iIiiiIIi . altitude = self . altitude
  iIiiiIIi . radius = self . radius
  return ( iIiiiIIi )
  if 65 - 65: Ii1I . OoOoOO00 + O0 / iIii1I11I1II1 % Ii1I % I1Ii111
  if 31 - 31: o0oOOo0O0Ooo - Oo0Ooo
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 15 - 15: O0 + OOooOOo
  if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
 def parse_geo_string ( self , geo_str ) :
  o00O = geo_str . find ( "]" )
  if ( o00O != - 1 ) : geo_str = geo_str [ o00O + 1 : : ]
  if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
  if 87 - 87: i1IIi / OoooooooOO
  if 68 - 68: I1Ii111 / iIii1I11I1II1
  if 8 - 8: ooOoO0o * IiII * OOooOOo / I1IiiI
  if 40 - 40: i11iIiiIii + OoooooooOO
  if ( geo_str . find ( "/" ) != - 1 ) :
   geo_str , iII1IIIII1I1 = geo_str . split ( "/" )
   self . radius = int ( iII1IIIII1I1 )
   if 39 - 39: i11iIiiIii * II111iiii
   if 75 - 75: OoooooooOO * IiII * OOooOOo
  geo_str = geo_str . split ( "-" )
  if ( len ( geo_str ) < 8 ) : return ( False )
  if 1 - 1: iII111i * I1IiiI . o0oOOo0O0Ooo . IiII
  I1ioOoo0O = geo_str [ 0 : 4 ]
  IIiiiiII = geo_str [ 4 : 8 ]
  if 86 - 86: OOooOOo * OoOoOO00 % i1IIi * IiII . I1ii11iIi11i
  if 72 - 72: i1IIi - I1Ii111 . O0 * OoO0O00
  if 62 - 62: Oo0Ooo . iII111i
  if 15 - 15: i11iIiiIii * I11i + oO0o
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 67 - 67: IiII . OoO0O00
  if 59 - 59: oO0o * o0oOOo0O0Ooo
  if 76 - 76: I1IiiI
  if 94 - 94: OoooooooOO * I1ii11iIi11i
  self . latitude = int ( I1ioOoo0O [ 0 ] )
  self . lat_mins = int ( I1ioOoo0O [ 1 ] )
  self . lat_secs = int ( I1ioOoo0O [ 2 ] )
  if ( I1ioOoo0O [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 28 - 28: II111iiii / II111iiii / II111iiii
  if 70 - 70: OoO0O00 + O0 * OoO0O00
  if 25 - 25: OoooooooOO . Oo0Ooo + OOooOOo + Oo0Ooo * O0 % i1IIi
  if 71 - 71: II111iiii / Ii1I + i1IIi - OoOoOO00 + Ii1I
  self . longitude = int ( IIiiiiII [ 0 ] )
  self . long_mins = int ( IIiiiiII [ 1 ] )
  self . long_secs = int ( IIiiiiII [ 2 ] )
  if ( IIiiiiII [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 31 - 31: OoooooooOO * Ii1I - iII111i . oO0o % Ii1I
  if 97 - 97: Ii1I
 def print_geo ( self ) :
  oo0 = "N" if self . latitude < 0 else "S"
  OOOo00o = "E" if self . longitude < 0 else "W"
  if 32 - 32: I1ii11iIi11i + OoOoOO00 / O0 + I1Ii111 . OoOoOO00 - ooOoO0o
  IIiIii1 = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , oo0 , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , OOOo00o )
  if 15 - 15: o0oOOo0O0Ooo * O0 / OoooooooOO + I1Ii111 + Oo0Ooo
  if ( self . no_geo_altitude ( ) == False ) :
   IIiIii1 += "-" + str ( self . altitude )
   if 92 - 92: Ii1I - o0oOOo0O0Ooo % I1IiiI + I1Ii111
   if 3 - 3: iIii1I11I1II1 + i11iIiiIii
   if 49 - 49: OoOoOO00 % iIii1I11I1II1 + I1Ii111
   if 38 - 38: i11iIiiIii
   if 75 - 75: iIii1I11I1II1 / OoO0O00 * OOooOOo % O0
  if ( self . radius != 0 ) : IIiIii1 += "/{}" . format ( self . radius )
  return ( IIiIii1 )
  if 82 - 82: Oo0Ooo / i1IIi . i1IIi / oO0o
  if 7 - 7: Oo0Ooo . iII111i % I1ii11iIi11i / iII111i
 def geo_url ( self ) :
  oo0o00000O0 = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  oo0o00000O0 = "10" if ( oo0o00000O0 == "" or oo0o00000O0 . isdigit ( ) == False ) else oo0o00000O0
  Iii1IIIIi1 , oO0I1 = self . dms_to_decimal ( )
  O0oOO0O00Oo00Oo0 = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( Iii1IIIIi1 , oO0I1 , Iii1IIIIi1 , oO0I1 ,
  # iII111i * O0 % i1IIi / Oo0Ooo * oO0o
  # OoooooooOO / II111iiii + II111iiii . I1Ii111 . OoOoOO00
 oo0o00000O0 )
  return ( O0oOO0O00Oo00Oo0 )
  if 75 - 75: Oo0Ooo + I11i
  if 87 - 87: I1IiiI
 def print_geo_url ( self ) :
  iIiiiIIi = self . print_geo ( )
  if ( self . radius == 0 ) :
   O0oOO0O00Oo00Oo0 = self . geo_url ( )
   I1i1iI = "<a href='{}'>{}</a>" . format ( O0oOO0O00Oo00Oo0 , iIiiiIIi )
  else :
   O0oOO0O00Oo00Oo0 = iIiiiIIi . replace ( "/" , "-" )
   I1i1iI = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( O0oOO0O00Oo00Oo0 , iIiiiIIi )
   if 36 - 36: OoO0O00 . ooOoO0o . O0 / OoO0O00
  return ( I1i1iI )
  if 50 - 50: Ii1I . OoOoOO00 * o0oOOo0O0Ooo
  if 68 - 68: IiII * oO0o / OoOoOO00 / I1Ii111
 def dms_to_decimal ( self ) :
  o0000ooOO , O000o , iI1Ii1 = self . latitude , self . lat_mins , self . lat_secs
  iiI11 = float ( abs ( o0000ooOO ) )
  iiI11 += float ( O000o * 60 + iI1Ii1 ) / 3600
  if ( o0000ooOO > 0 ) : iiI11 = - iiI11
  I1II11 = iiI11
  if 80 - 80: O0 - I11i - I1ii11iIi11i
  o0000ooOO , O000o , iI1Ii1 = self . longitude , self . long_mins , self . long_secs
  iiI11 = float ( abs ( o0000ooOO ) )
  iiI11 += float ( O000o * 60 + iI1Ii1 ) / 3600
  if ( o0000ooOO > 0 ) : iiI11 = - iiI11
  oo0I1i = iiI11
  return ( ( I1II11 , oo0I1i ) )
  if 17 - 17: i1IIi * Oo0Ooo * oO0o
  if 62 - 62: ooOoO0o + OoOoOO00 % OOooOOo - I1ii11iIi11i + OoO0O00
 def get_distance ( self , geo_point ) :
  o00O0oOo = self . dms_to_decimal ( )
  O00o0o00o = geo_point . dms_to_decimal ( )
  iiiIIII = geopy . distance . distance ( o00O0oOo , O00o0o00o )
  return ( iiiIIII . km )
  if 49 - 49: ooOoO0o + iII111i % OoooooooOO / Oo0Ooo % i1IIi
  if 50 - 50: OoO0O00
 def point_in_circle ( self , geo_point ) :
  oOoooOO = self . get_distance ( geo_point )
  return ( oOoooOO <= self . radius )
  if 62 - 62: OoOoOO00
  if 100 - 100: oO0o - OoOoOO00 % O0 * I1Ii111 - OOooOOo / I1ii11iIi11i
 def encode_geo ( self ) :
  o00O00 = socket . htons ( LISP_AFI_LCAF )
  ooo0OoO0ooO = socket . htons ( 20 + 2 )
  iiI1 = 0
  if 77 - 77: IiII / Oo0Ooo + iIii1I11I1II1 + OoO0O00 . OOooOOo
  Iii1IIIIi1 = abs ( self . latitude )
  I1iiI1II = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : iiI1 |= 0x40
  if 87 - 87: OoooooooOO / I11i . O0
  oO0I1 = abs ( self . longitude )
  O00Ooo = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : iiI1 |= 0x20
  if 28 - 28: OOooOOo . I1Ii111 . i11iIiiIii * Oo0Ooo
  Oo0o0OOO0000 = 0
  if ( self . no_geo_altitude ( ) == False ) :
   Oo0o0OOO0000 = socket . htonl ( self . altitude )
   iiI1 |= 0x10
   if 56 - 56: iIii1I11I1II1 - OoO0O00 . i1IIi . OOooOOo / o0oOOo0O0Ooo
  iII1IIIII1I1 = socket . htons ( self . radius )
  if ( iII1IIIII1I1 != 0 ) : iiI1 |= 0x06
  if 98 - 98: oO0o + I11i . oO0o
  I1ii11 = struct . pack ( "HBBBBH" , o00O00 , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , ooo0OoO0ooO )
  I1ii11 += struct . pack ( "BBHBBHBBHIHHH" , iiI1 , 0 , 0 , Iii1IIIIi1 , I1iiI1II >> 16 ,
 socket . htons ( I1iiI1II & 0x0ffff ) , oO0I1 , O00Ooo >> 16 ,
 socket . htons ( O00Ooo & 0xffff ) , Oo0o0OOO0000 , iII1IIIII1I1 , 0 , 0 )
  if 17 - 17: IiII * Oo0Ooo . i11iIiiIii . IiII . Oo0Ooo % IiII
  return ( I1ii11 )
  if 93 - 93: II111iiii - IiII - O0 - i11iIiiIii / OOooOOo
  if 76 - 76: OOooOOo
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  ii = "BBHBBHBBHIHHH"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( lcaf_len < OOOO00oo00oo ) : return ( None )
  if 31 - 31: OOooOOo + i1IIi / Ii1I / OoOoOO00 % OoO0O00 + Oo0Ooo
  iiI1 , Oo0o , O0Oo0ooO000OO , Iii1IIIIi1 , iI1I1I1iiI , I1iiI1II , oO0I1 , o0Oo0oo0oOO0 , O00Ooo , Oo0o0OOO0000 , iII1IIIII1I1 , iIo0ooO0 , IiIIi = struct . unpack ( ii ,
  # ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
 packet [ : OOOO00oo00oo ] )
  if 63 - 63: I1ii11iIi11i / OOooOOo
  if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
  if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
  if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
  IiIIi = socket . ntohs ( IiIIi )
  if ( IiIIi == LISP_AFI_LCAF ) : return ( None )
  if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
  if ( iiI1 & 0x40 ) : Iii1IIIIi1 = - Iii1IIIIi1
  self . latitude = Iii1IIIIi1
  OOi1Ii1ii11I1II = old_div ( ( ( iI1I1I1iiI << 16 ) | socket . ntohs ( I1iiI1II ) ) , 1000 )
  self . lat_mins = old_div ( OOi1Ii1ii11I1II , 60 )
  self . lat_secs = OOi1Ii1ii11I1II % 60
  if 38 - 38: OoOoOO00 + OoooooooOO
  if ( iiI1 & 0x20 ) : oO0I1 = - oO0I1
  self . longitude = oO0I1
  OoooOO0O00 = old_div ( ( ( o0Oo0oo0oOO0 << 16 ) | socket . ntohs ( O00Ooo ) ) , 1000 )
  self . long_mins = old_div ( OoooOO0O00 , 60 )
  self . long_secs = OoooOO0O00 % 60
  if 90 - 90: OoO0O00 . oO0o * O0 / I11i % O0 + I1Ii111
  self . altitude = socket . ntohl ( Oo0o0OOO0000 ) if ( iiI1 & 0x10 ) else - 1
  iII1IIIII1I1 = socket . ntohs ( iII1IIIII1I1 )
  self . radius = iII1IIIII1I1 if ( iiI1 & 0x02 ) else iII1IIIII1I1 * 1000
  if 48 - 48: iIii1I11I1II1 . i11iIiiIii / OoooooooOO . i1IIi . o0oOOo0O0Ooo
  self . geo_name = None
  packet = packet [ OOOO00oo00oo : : ]
  if 84 - 84: Ii1I
  if ( IiIIi != 0 ) :
   self . rloc . afi = IiIIi
   packet = self . rloc . unpack_address ( packet )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 92 - 92: I11i
  return ( packet )
  if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
  if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
  if 82 - 82: O0 * ooOoO0o * iIii1I11I1II1 . i1IIi
  if 47 - 47: I11i * I11i . OoOoOO00
  if 68 - 68: OoooooooOO + OoOoOO00 + i11iIiiIii
  if 89 - 89: Oo0Ooo + Ii1I * O0 - I1Ii111
class lisp_rle_node ( object ) :
 def __init__ ( self ) :
  self . level = 0
  self . rloc = lisp_rloc ( )
  if 33 - 33: iIii1I11I1II1 . I11i
  if 63 - 63: oO0o - iII111i
 def copy_rle_node ( self ) :
  I1I1Ii1I = lisp_rle_node ( )
  I1I1Ii1I = copy . deepcopy ( self )
  return ( I1I1Ii1I )
  if 13 - 13: I1Ii111 / i1IIi % OoooooooOO / I11i
  if 66 - 66: I1Ii111 % o0oOOo0O0Ooo . iII111i . ooOoO0o + OOooOOo * II111iiii
 def store_translated_rloc ( self , rloc , port ) :
  rloc . store_translated_rloc ( rloc . rloc , port )
  if 33 - 33: oO0o
  if 64 - 64: OoO0O00 % Oo0Ooo % I11i . iII111i % I1IiiI
 def get_encap_keys ( self ) :
  i11I1Ii1Iiii1 = "4341" if self . rloc . translated_port == 0 else str ( self . rloc . translated_port )
  if 50 - 50: i1IIi + ooOoO0o - iIii1I11I1II1
  O00oO000Oo0 = self . rloc . rloc . print_address_no_iid ( ) + ":" + i11I1Ii1Iiii1
  if 45 - 45: OoooooooOO / o0oOOo0O0Ooo / iII111i
  try :
   oOoOOoo = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ]
   if ( oOoOOoo [ 1 ] ) : return ( oOoOOoo [ 1 ] . encrypt_key , oOoOOoo [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 72 - 72: I1Ii111
   if 94 - 94: ooOoO0o . IiII - Ii1I + I1ii11iIi11i / ooOoO0o
   if 10 - 10: ooOoO0o . OOooOOo * O0 % II111iiii
   if 12 - 12: oO0o + I1IiiI * Oo0Ooo - iII111i
class lisp_rle ( object ) :
 def __init__ ( self , name ) :
  self . rle_name = name
  self . rle_nodes = [ ]
  self . rle_forwarding_list = [ ]
  if 88 - 88: OOooOOo . OoO0O00
  if 86 - 86: OoOoOO00 . o0oOOo0O0Ooo / ooOoO0o * I1IiiI . OoO0O00 / I1Ii111
 def copy_rle ( self ) :
  IiI = lisp_rle ( self . rle_name )
  for I1I1Ii1I in self . rle_nodes :
   IiI . rle_nodes . append ( I1I1Ii1I . copy_rle_node ( ) )
   if 47 - 47: I11i . iII111i * OoOoOO00 % OoooooooOO
  IiI . build_rle_forwarding_list ( )
  return ( IiI )
  if 59 - 59: OoooooooOO + I1ii11iIi11i - I11i / I1IiiI * oO0o
  if 90 - 90: I1Ii111 + i1IIi * I1Ii111 / I11i * Oo0Ooo
 def add_one_rle_node ( self , rle_node ) :
  iIiIii11I11i = lisp_rle_node ( )
  iIiIii11I11i = copy . deepcopy ( rle_node )
  self . rle_nodes . append ( iIiIii11I11i )
  self . build_rle_forwarding_list ( )
  if 93 - 93: o0oOOo0O0Ooo * II111iiii - iIii1I11I1II1 + oO0o + II111iiii / Oo0Ooo
  if 74 - 74: OoooooooOO * IiII / OoOoOO00 * OoO0O00 * I11i
 def print_one_rle ( self , rle_node , html , do_formatting ) :
  i11I1Ii1Iiii1 = rle_node . rloc . translated_port
  if 70 - 70: OoO0O00 / I1ii11iIi11i - iIii1I11I1II1 % o0oOOo0O0Ooo / i1IIi + IiII
  o0O = ""
  if ( rle_node . rloc . rloc_name != None ) :
   o0O = rle_node . rloc . rloc_name
   if ( do_formatting ) : o0O = blue ( o0O , html )
   o0O = "({})" . format ( o0O )
   if 18 - 18: I11i - I1Ii111 % i11iIiiIii . Oo0Ooo
   if 43 - 43: iII111i + o0oOOo0O0Ooo - OoO0O00 % i11iIiiIii
  O00oO000Oo0 = rle_node . rloc . rloc . print_address_no_iid ( )
  if ( rle_node . rloc . rloc . is_local ( ) ) : O00oO000Oo0 = red ( O00oO000Oo0 , html )
  I11Ii1IIii1 = "{}{}{}" . format ( O00oO000Oo0 , "" if i11I1Ii1Iiii1 == 0 else ":" + str ( i11I1Ii1Iiii1 ) , o0O )
  return ( I11Ii1IIii1 )
  if 55 - 55: IiII - iII111i / I11i
  if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
 def print_rle ( self , html , do_formatting ) :
  I11Ii1IIii1 = ""
  for I1I1Ii1I in self . rle_nodes :
   I11Ii1IIii1 += self . print_one_rle ( I1I1Ii1I , html , do_formatting )
   I11Ii1IIii1 += ", "
   if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
  return ( I11Ii1IIii1 [ 0 : - 2 ] if I11Ii1IIii1 != "" else "" )
  if 84 - 84: i1IIi
  if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
 def print_api_rle ( self ) :
  Ooo00OOo0oO0 = { }
  for I1I1Ii1I in self . rle_nodes :
   I11Ii1IIii1 = self . print_one_rle ( I1I1Ii1I , False , False )
   Ooo00OOo0oO0 [ I11Ii1IIii1 ] = lisp_fill_rloc_in_json ( I1I1Ii1I . rloc )
   if 58 - 58: I1IiiI % i11iIiiIii
  return ( Ooo00OOo0oO0 )
  if 46 - 46: oO0o + OoOoOO00 . I1ii11iIi11i * OOooOOo
  if 71 - 71: I1Ii111 / II111iiii . I1ii11iIi11i
 def build_rle_forwarding_list ( self ) :
  i11I = - 1
  for I1I1Ii1I in self . rle_nodes :
   if ( i11I == - 1 ) :
    if ( I1I1Ii1I . rloc . rloc . is_local ( ) ) : i11I = I1I1Ii1I . level
   else :
    if ( I1I1Ii1I . level > i11I ) : break
    if 92 - 92: o0oOOo0O0Ooo + II111iiii + oO0o / iII111i % OoooooooOO / I1IiiI
    if 41 - 41: OoOoOO00 * i1IIi
  i11I = 0 if i11I == - 1 else I1I1Ii1I . level
  if 94 - 94: I11i
  self . rle_forwarding_list = [ ]
  for I1I1Ii1I in self . rle_nodes :
   if ( I1I1Ii1I . level == i11I or ( i11I == 0 and I1I1Ii1I . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and I1I1Ii1I . rloc . rloc . is_local ( ) ) :
     O00oO000Oo0 = I1I1Ii1I . rloc . rloc . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( O00oO000Oo0 ) )
     continue
     if 28 - 28: OOooOOo
    self . rle_forwarding_list . append ( I1I1Ii1I )
    if 82 - 82: II111iiii
    if 66 - 66: iII111i % I1Ii111 * oO0o
    if 81 - 81: i11iIiiIii - O0 . iIii1I11I1II1 - I11i + iIii1I11I1II1
    if 50 - 50: Oo0Ooo . OoO0O00 + i11iIiiIii / i11iIiiIii
    if 27 - 27: OoOoOO00 - OoOoOO00 % II111iiii + i1IIi + I1IiiI
class lisp_json ( object ) :
 def __init__ ( self , name , string , encrypted = False , ms_encrypt = False ) :
  if 75 - 75: OoooooooOO . I11i - OoOoOO00
  if 93 - 93: OoOoOO00 . I1Ii111 % I1ii11iIi11i
  if 58 - 58: OoooooooOO . i1IIi . Oo0Ooo - o0oOOo0O0Ooo / oO0o * I1Ii111
  if 6 - 6: oO0o - OoO0O00
  if ( type ( string ) == bytes ) : string = string . decode ( )
  if 44 - 44: Oo0Ooo + I1ii11iIi11i % Oo0Ooo / I11i
  self . json_name = name
  self . json_encrypted = False
  try :
   json . loads ( string )
  except :
   lprint ( "Invalid JSON string: '{}'" . format ( string ) )
   string = '{ "?" : "?" }'
   if 57 - 57: Oo0Ooo + Ii1I * OoooooooOO
  self . json_string = string
  if 30 - 30: O0
  if 70 - 70: oO0o
  if 89 - 89: O0
  if 3 - 3: iII111i - O0 / I11i
  if 46 - 46: I1IiiI . OoooooooOO / iIii1I11I1II1 - ooOoO0o * OOooOOo
  if 55 - 55: o0oOOo0O0Ooo + iIii1I11I1II1 / I11i
  if 97 - 97: i11iIiiIii
  if 71 - 71: oO0o + Oo0Ooo
  if 7 - 7: OoOoOO00 / I1ii11iIi11i * i1IIi
  if 87 - 87: OoooooooOO * IiII - I1IiiI % I1ii11iIi11i % iIii1I11I1II1
  if ( len ( lisp_ms_json_keys ) != 0 ) :
   if ( ms_encrypt == False ) : return
   self . json_key_id = list ( lisp_ms_json_keys . keys ( ) ) [ 0 ]
   self . json_key = lisp_ms_json_keys [ self . json_key_id ]
   self . encrypt_json ( )
   if 28 - 28: I1Ii111 / o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo . Ii1I / I11i
   if 43 - 43: I1Ii111 . I1IiiI
  if ( lisp_log_id == "lig" and encrypted ) :
   oO0oOo = os . getenv ( "LISP_JSON_KEY" )
   if ( oO0oOo != None ) :
    o00O = - 1
    if ( oO0oOo [ 0 ] == "[" and "]" in oO0oOo ) :
     o00O = oO0oOo . find ( "]" )
     self . json_key_id = int ( oO0oOo [ 1 : o00O ] )
     if 16 - 16: i11iIiiIii * Oo0Ooo * Ii1I / OoOoOO00 / OOooOOo
    self . json_key = oO0oOo [ o00O + 1 : : ]
    if 11 - 11: o0oOOo0O0Ooo * OoO0O00 . o0oOOo0O0Ooo - I1IiiI / IiII - OOooOOo
    self . decrypt_json ( )
    if 19 - 19: i1IIi + IiII . OoO0O00 / O0 - I1Ii111 - Oo0Ooo
    if 24 - 24: iII111i + i1IIi
    if 31 - 31: OoOoOO00
    if 37 - 37: iIii1I11I1II1 % IiII / i11iIiiIii - oO0o
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 43 - 43: II111iiii - OoooooooOO
  if 11 - 11: I1IiiI
 def delete ( self ) :
  if ( self . json_name in lisp_json_list ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
   if 64 - 64: OoO0O00 - OoO0O00
   if 93 - 93: Oo0Ooo . O0
 def print_json ( self , html ) :
  o0OoOoOooo00o = self . json_string
  iI1II1I1i1 = "***"
  if ( html ) : iI1II1I1i1 = red ( iI1II1I1i1 , html )
  OOo0oOO000 = iI1II1I1i1 + self . json_string + iI1II1I1i1
  if ( self . valid_json ( ) ) : return ( o0OoOoOooo00o )
  return ( OOo0oOO000 )
  if 3 - 3: OoO0O00
  if 50 - 50: iII111i - I1ii11iIi11i . Ii1I + i11iIiiIii + IiII * I1Ii111
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 51 - 51: iII111i * OoO0O00 * o0oOOo0O0Ooo . i1IIi
  return ( True )
  if 54 - 54: Ii1I + i11iIiiIii - II111iiii * Oo0Ooo
  if 20 - 20: ooOoO0o / o0oOOo0O0Ooo - i1IIi + IiII
 def encrypt_json ( self ) :
  iI11ii = self . json_key . zfill ( 32 )
  Oo0OOOO0oOoo0 = "0" * 8
  if 25 - 25: OoOoOO00 / ooOoO0o
  oOo0OOooo0o = json . loads ( self . json_string )
  for oO0oOo in oOo0OOooo0o :
   oO00o = oOo0OOooo0o [ oO0oOo ]
   if ( type ( oO00o ) != str ) : oO00o = str ( oO00o )
   oO00o = chacha . ChaCha ( iI11ii , Oo0OOOO0oOoo0 ) . encrypt ( oO00o )
   oOo0OOooo0o [ oO0oOo ] = binascii . hexlify ( oO00o )
   if 2 - 2: Oo0Ooo - I1Ii111 - iII111i + o0oOOo0O0Ooo + Oo0Ooo / Oo0Ooo
  self . json_string = json . dumps ( oOo0OOooo0o )
  self . json_encrypted = True
  if 35 - 35: I11i . iII111i * I1Ii111 * O0
  if 16 - 16: I1IiiI . OoOoOO00 + iII111i % OOooOOo - O0
 def decrypt_json ( self ) :
  iI11ii = self . json_key . zfill ( 32 )
  Oo0OOOO0oOoo0 = "0" * 8
  if 51 - 51: IiII
  oOo0OOooo0o = json . loads ( self . json_string )
  for oO0oOo in oOo0OOooo0o :
   oO00o = binascii . unhexlify ( oOo0OOooo0o [ oO0oOo ] )
   oOo0OOooo0o [ oO0oOo ] = chacha . ChaCha ( iI11ii , Oo0OOOO0oOoo0 ) . encrypt ( oO00o )
   if 65 - 65: iIii1I11I1II1 / OOooOOo * OoOoOO00
  try :
   self . json_string = json . dumps ( oOo0OOooo0o )
   self . json_encrypted = False
  except :
   pass
   if 85 - 85: I1Ii111 - Oo0Ooo / I11i + OoOoOO00 . O0 - Oo0Ooo
   if 24 - 24: I1IiiI + i1IIi
   if 21 - 21: iII111i / o0oOOo0O0Ooo
   if 61 - 61: iII111i . I1Ii111 % OoooooooOO / I1Ii111
   if 8 - 8: OoOoOO00
   if 80 - 80: IiII + I1ii11iIi11i + ooOoO0o
   if 48 - 48: O0 / I1IiiI % II111iiii
class lisp_stats ( object ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 10 - 10: Ii1I / I1Ii111 / O0 - II111iiii % IiII - ooOoO0o
  if 48 - 48: OOooOOo * OoOoOO00 / oO0o + II111iiii - I1ii11iIi11i
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 85 - 85: I1ii11iIi11i * OoooooooOO . OOooOOo * OOooOOo
  if 13 - 13: I1IiiI / Ii1I - OoOoOO00 . i1IIi * oO0o * o0oOOo0O0Ooo
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  o0oOOOO0 = time . time ( ) - self . last_increment
  return ( o0oOOOO0 <= 1 )
  if 5 - 5: I11i - I1Ii111 * I11i - II111iiii + OOooOOo + II111iiii
  if 91 - 91: i1IIi + Oo0Ooo - I1ii11iIi11i + I1ii11iIi11i * O0 / O0
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  o0oOOOO0 = time . time ( ) - self . last_increment
  return ( o0oOOOO0 <= 60 )
  if 78 - 78: OoooooooOO
  if 8 - 8: Oo0Ooo - Oo0Ooo % O0 - Ii1I / o0oOOo0O0Ooo % Oo0Ooo
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 51 - 51: iIii1I11I1II1 / iIii1I11I1II1 * I1ii11iIi11i / I11i
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 18 - 18: Ii1I - i11iIiiIii + OoO0O00 . O0 - iII111i
  return ( c1 , c2 )
  if 9 - 9: OoooooooOO / iII111i + o0oOOo0O0Ooo / II111iiii / I1Ii111
  if 44 - 44: I1IiiI / iII111i / Oo0Ooo
 def normalize ( self , count ) :
  count = str ( count )
  O00ooO0 = len ( count )
  if ( O00ooO0 > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 85 - 85: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i
  if ( O00ooO0 > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 43 - 43: Ii1I * OOooOOo + OoO0O00 . Oo0Ooo % Ii1I . OoO0O00
  if ( O00ooO0 > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 90 - 90: I1Ii111 . OoooooooOO * ooOoO0o
  return ( count )
  if 82 - 82: ooOoO0o
  if 80 - 80: I1Ii111 / I11i - Oo0Ooo / IiII % O0
 def get_stats ( self , summary , html ) :
  OoO0O = self . last_rate_check
  ooo000OoO = self . last_packet_count
  IIIiIii = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 56 - 56: OOooOOo * o0oOOo0O0Ooo - O0
  i1IIIiI1I = self . last_rate_check - OoO0O
  if ( i1IIIiI1I == 0 ) :
   iIiIiiI1III = 0
   O0oO0O0OoOOo = 0
  else :
   iIiIiiI1III = int ( old_div ( ( self . packet_count - ooo000OoO ) ,
 i1IIIiI1I ) )
   O0oO0O0OoOOo = old_div ( ( self . byte_count - IIIiIii ) , i1IIIiI1I )
   O0oO0O0OoOOo = old_div ( ( O0oO0O0OoOOo * 8 ) , 1000000 )
   O0oO0O0OoOOo = round ( O0oO0O0OoOOo , 2 )
   if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
   if 41 - 41: OOooOOo + Oo0Ooo % I1IiiI
   if 3 - 3: ooOoO0o * Ii1I
   if 29 - 29: OoooooooOO + OOooOOo
   if 68 - 68: O0 + IiII / iII111i - OoOoOO00
  iIIiiIii11I1i = self . normalize ( self . packet_count )
  iI1ii = self . normalize ( self . byte_count )
  if 40 - 40: I1Ii111 / I1ii11iIi11i . I1IiiI . Ii1I * I11i
  if 21 - 21: i11iIiiIii . IiII - OoooooooOO
  if 72 - 72: iII111i
  if 80 - 80: Oo0Ooo
  if 37 - 37: i11iIiiIii - I1Ii111
  if ( summary ) :
   Iii1IiI1i1Iiii = "<br>" if html else ""
   iIIiiIii11I1i , iI1ii = self . stat_colors ( iIIiiIii11I1i , iI1ii , html )
   IIIii = "packet-count: {}{}byte-count: {}" . format ( iIIiiIii11I1i , Iii1IiI1i1Iiii , iI1ii )
   IIiO0O0 = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( iIiIiiI1III , O0oO0O0OoOOo )
   if 4 - 4: i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
   if ( html != "" ) : IIiO0O0 = lisp_span ( IIIii , IIiO0O0 )
  else :
   o0Ooo00oooo = str ( iIiIiiI1III )
   IiiiiIIii = str ( O0oO0O0OoOOo )
   if ( html ) :
    iIIiiIii11I1i = lisp_print_cour ( iIIiiIii11I1i )
    o0Ooo00oooo = lisp_print_cour ( o0Ooo00oooo )
    iI1ii = lisp_print_cour ( iI1ii )
    IiiiiIIii = lisp_print_cour ( IiiiiIIii )
    if 59 - 59: Ii1I + iIii1I11I1II1 % I1ii11iIi11i . OOooOOo / iIii1I11I1II1 - o0oOOo0O0Ooo
   Iii1IiI1i1Iiii = "<br>" if html else ", "
   if 24 - 24: OoOoOO00 . I1IiiI
   IIiO0O0 = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( iIIiiIii11I1i , Iii1IiI1i1Iiii , o0Ooo00oooo , Iii1IiI1i1Iiii , iI1ii , Iii1IiI1i1Iiii ,
   # i1IIi - I1IiiI . I1IiiI * Ii1I
 IiiiiIIii )
   if 80 - 80: OoOoOO00
  return ( IIiO0O0 )
  if 36 - 36: I11i - ooOoO0o - ooOoO0o . I1ii11iIi11i / II111iiii % OOooOOo
  if 26 - 26: OoooooooOO / ooOoO0o - iII111i / OoO0O00 . O0 * OOooOOo
  if 85 - 85: iIii1I11I1II1 + iII111i + iII111i - ooOoO0o * OoO0O00
  if 80 - 80: i11iIiiIii / OOooOOo . OoooooooOO % I11i - iII111i * iIii1I11I1II1
  if 70 - 70: Oo0Ooo
  if 75 - 75: I1Ii111
  if 40 - 40: OoO0O00 % Oo0Ooo / OoooooooOO / i11iIiiIii
  if 5 - 5: O0 % i11iIiiIii
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 60 - 60: I1ii11iIi11i / I11i
if 100 - 100: I1IiiI
if 44 - 44: iIii1I11I1II1 + Oo0Ooo - I1Ii111 . OoooooooOO
if 28 - 28: Ii1I + OOooOOo % IiII . i11iIiiIii - I1IiiI * Oo0Ooo
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
  self . probing_itr_rloc = None
  self . rloc_next_hop = None
  self . next_rloc = None
  self . multicast_rloc_probe_list = { }
  self . active_rloc_next_hop = None
  if 2 - 2: I11i * I1ii11iIi11i + O0
  if ( recurse == False ) : return
  if 44 - 44: iIii1I11I1II1 / II111iiii - ooOoO0o
  if 10 - 10: OOooOOo
  if 78 - 78: OOooOOo * I1ii11iIi11i % i11iIiiIii % o0oOOo0O0Ooo . I1ii11iIi11i / OoooooooOO
  if 12 - 12: iIii1I11I1II1 % OoO0O00 + OOooOOo * iIii1I11I1II1 - iIii1I11I1II1
  if 70 - 70: OoO0O00 % i11iIiiIii * IiII . I11i * Oo0Ooo
  if 17 - 17: i1IIi
  I1IIIIiI1i = lisp_get_default_route_next_hops ( )
  if ( I1IIIIiI1i == [ ] ) : return
  if 93 - 93: I1Ii111 / oO0o + oO0o
  self . rloc_next_hop = I1IIIIiI1i [ 0 ]
  i1IIIi111111 = self
  for i1IIIII in I1IIIIiI1i [ 1 : : ] :
   O0o0o00000ooo = lisp_rloc ( False )
   O0o0o00000ooo = copy . deepcopy ( self )
   O0o0o00000ooo . rloc_next_hop = i1IIIII
   i1IIIi111111 . next_rloc = O0o0o00000ooo
   i1IIIi111111 = O0o0o00000ooo
   if 12 - 12: Oo0Ooo / IiII % ooOoO0o / iIii1I11I1II1 % O0 / i11iIiiIii
  self . set_active_rloc_next_hop ( )
  if 58 - 58: i11iIiiIii * O0
  if 85 - 85: oO0o
 def set_active_rloc_next_hop ( self ) :
  oooOoOoO0oO = self . next_rloc
  while ( oooOoOoO0oO != None ) :
   if ( lisp_is_active_interface ( oooOoOoO0oO ) ) :
    self . active_rloc_next_hop = oooOoOoO0oO
    break
    if 54 - 54: o0oOOo0O0Ooo . i11iIiiIii + I1IiiI * ooOoO0o - ooOoO0o
   oooOoOoO0oO = oooOoOoO0oO . next_rloc
   if 28 - 28: I1Ii111 . i11iIiiIii * oO0o % ooOoO0o / iII111i . OOooOOo
   if 57 - 57: OoooooooOO . iIii1I11I1II1 % iII111i % Oo0Ooo
   if 92 - 92: I1Ii111 - Ii1I + I1Ii111
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 8 - 8: Oo0Ooo . iII111i / i11iIiiIii + iIii1I11I1II1 - OoOoOO00
  if 1 - 1: i11iIiiIii
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 25 - 25: OoooooooOO / II111iiii . OOooOOo * OoOoOO00 - OoooooooOO
  if 8 - 8: iII111i . iIii1I11I1II1 * O0
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 87 - 87: OoO0O00 * OoooooooOO + OoOoOO00 . OoooooooOO + o0oOOo0O0Ooo + Ii1I
  if 26 - 26: i1IIi
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 33 - 33: OoOoOO00 + OOooOOo . i1IIi . IiII
  if 78 - 78: OoooooooOO * I11i / OOooOOo + oO0o . I1Ii111 * iII111i
  if 98 - 98: i1IIi
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
  if 28 - 28: Oo0Ooo . I1Ii111 . iIii1I11I1II1 + I1IiiI . II111iiii * I1ii11iIi11i
  if 26 - 26: i1IIi / i11iIiiIii * II111iiii
 def print_rloc ( self , indent ) :
  iIiIIIIIii = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , iIiIIIIIii , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 11 - 11: Oo0Ooo % i1IIi
  if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  I11Io00oo0OO = self . rloc_name
  if ( cour ) : I11Io00oo0OO = lisp_print_cour ( I11Io00oo0OO )
  return ( 'rloc-name: {}' . format ( blue ( I11Io00oo0OO , cour ) ) )
  if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
  if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
 def is_decent_nat_port ( self ) :
  Oo0oOOo000 = self . rloc_name
  if ( Oo0oOOo000 == None ) : return ( False )
  if ( Oo0oOOo000 . find ( LISP_TP ) == - 1 ) : return ( False )
  return ( True )
  if 75 - 75: i1IIi + I1IiiI - iIii1I11I1II1 + O0 . OoooooooOO
  if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
 def store_decent_nat_port ( self ) :
  if ( self . is_decent_nat_port ( ) == False ) : return ( False )
  i11I1Ii1Iiii1 = self . rloc_name . split ( LISP_TP ) [ - 1 ]
  self . translated_port = int ( i11I1Ii1Iiii1 )
  return ( True )
  if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
  if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
 def normalize_decent_nat_rloc_name ( self ) :
  if ( self . is_decent_nat_port ( ) == False ) : return ( self . rloc_name )
  Oo0oOOo000 = self . rloc_name . split ( LISP_TP ) [ 0 ]
  return ( Oo0oOOo000 )
  if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
  if 76 - 76: OOooOOo % iII111i
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  i11I1Ii1Iiii1 = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . set_active_rloc_next_hop ( )
  if 80 - 80: iIii1I11I1II1 + o0oOOo0O0Ooo + iIii1I11I1II1
  if 63 - 63: OoOoOO00 - o0oOOo0O0Ooo % II111iiii - Ii1I
  if 81 - 81: iII111i % OOooOOo * oO0o
  if 84 - 84: iII111i - OoooooooOO + I1ii11iIi11i - I1IiiI
  oooOoOoO0oO = self . next_rloc
  while ( oooOoOoO0oO != None ) :
   oooOoOoO0oO . rloc . copy_address ( rloc_record . rloc )
   oooOoOoO0oO = oooOoOoO0oO . next_rloc
   if 52 - 52: oO0o / ooOoO0o / iII111i / OoOoOO00 * iIii1I11I1II1
   if 74 - 74: oO0o . I1ii11iIi11i - iIii1I11I1II1
  if ( rloc_record . rloc_name != None ) :
   self . rloc_name = rloc_record . rloc_name
   if 73 - 73: OoO0O00 / O0 . o0oOOo0O0Ooo
   if 100 - 100: Ii1I . OoO0O00 % I1ii11iIi11i % O0 * Oo0Ooo - OoOoOO00
   if 15 - 15: OOooOOo - OOooOOo - OoooooooOO * OoO0O00
   if 12 - 12: II111iiii * I1Ii111 / I1Ii111 * oO0o * Oo0Ooo
   if ( lisp_i_am_rtr == False ) :
    if ( self . store_decent_nat_port ( ) ) :
     self . translated_rloc . copy_address ( self . rloc )
     if 17 - 17: OoOoOO00 % I1Ii111 / iII111i * I1Ii111
     if 96 - 96: Oo0Ooo % o0oOOo0O0Ooo . OoOoOO00 % i11iIiiIii / OoooooooOO
     if 87 - 87: OoooooooOO - Ii1I . I11i / I1Ii111 . i1IIi
     if 86 - 86: i1IIi . oO0o % OOooOOo
     if 99 - 99: oO0o / I1Ii111 * oO0o * I11i
     if 38 - 38: o0oOOo0O0Ooo + OoOoOO00
   i1IIIII = self . next_rloc
   while ( i1IIIII != None ) :
    i1IIIII . rloc_name = self . rloc_name
    i1IIIII . translated_port = self . translated_port
    i1IIIII . translated_rloc . copy_address ( self . translated_rloc )
    i1IIIII = i1IIIII . next_rloc
    if 24 - 24: Ii1I - OOooOOo - o0oOOo0O0Ooo - I1Ii111 / OoooooooOO
    if 17 - 17: OoO0O00
    if 79 - 79: Ii1I - II111iiii
    if 57 - 57: II111iiii / OoooooooOO
    if 4 - 4: I11i * OoOoOO00
    if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
  OO0Oo00oo = self . rloc
  if ( OO0Oo00oo . is_null ( ) == False and self . rloc_name != None ) :
   Oo0oOOo000 = self . normalize_decent_nat_rloc_name ( )
   oOoO = lisp_get_nat_info ( OO0Oo00oo , Oo0oOOo000 )
   if ( oOoO ) :
    i11I1Ii1Iiii1 = oOoO . port
    II11IIi1Ii1i = lisp_nat_state_info [ Oo0oOOo000 ] [ 0 ]
    O00oO000Oo0 = OO0Oo00oo . print_address_no_iid ( )
    iIiIi111 = red ( O00oO000Oo0 , False )
    O0oOOO0oO = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 22 - 22: o0oOOo0O0Ooo * O0 % Oo0Ooo
    if 52 - 52: I1IiiI % I1Ii111 - i1IIi . o0oOOo0O0Ooo % I1ii11iIi11i
    if 34 - 34: o0oOOo0O0Ooo / OoOoOO00
    if 74 - 74: IiII + i1IIi . II111iiii
    if 1 - 1: Ii1I - o0oOOo0O0Ooo / i11iIiiIii
    if 24 - 24: O0
    if ( oOoO . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( iIiIi111 , i11I1Ii1Iiii1 , O0oOOO0oO ) )
     if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
     if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
     oOoO = None if ( oOoO == II11IIi1Ii1i ) else II11IIi1Ii1i
     if ( oOoO and oOoO . timed_out ( ) ) :
      i11I1Ii1Iiii1 = oOoO . port
      iIiIi111 = red ( oOoO . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( iIiIi111 , i11I1Ii1Iiii1 ,
      # OoooooooOO - oO0o * I1Ii111 % OOooOOo - iIii1I11I1II1 / I1ii11iIi11i
 O0oOOO0oO ) )
      oOoO = None
      if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
      if 81 - 81: Ii1I
      if 87 - 87: O0 % iII111i
      if 57 - 57: Ii1I
      if 49 - 49: I11i
      if 22 - 22: Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
      if 42 - 42: O0
    if ( oOoO ) :
     if ( oOoO . address != O00oO000Oo0 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( iIiIi111 , red ( oOoO . address , False ) ) )
      if 55 - 55: i11iIiiIii % OOooOOo
      self . rloc . store_address ( oOoO . address )
      if 10 - 10: OoOoOO00 / i11iIiiIii
     iIiIi111 = red ( oOoO . address , False )
     i11I1Ii1Iiii1 = oOoO . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( iIiIi111 , i11I1Ii1Iiii1 , O0oOOO0oO ) )
     if 21 - 21: Ii1I - i1IIi / I11i + IiII
     self . store_translated_rloc ( OO0Oo00oo , i11I1Ii1Iiii1 )
     if 44 - 44: OoooooooOO % I11i / O0
     if 94 - 94: IiII
     if 83 - 83: OoO0O00
     if 55 - 55: iII111i
     if 37 - 37: oO0o / o0oOOo0O0Ooo + I11i * OoO0O00 * o0oOOo0O0Ooo
     if 33 - 33: I1Ii111
     i1IIIII = self . next_rloc
     while ( i1IIIII != None ) :
      i1IIIII . store_translated_rloc ( self . translated_rloc , i11I1Ii1Iiii1 )
      i1IIIII = i1IIIII . next_rloc
      if 97 - 97: Ii1I / iII111i - ooOoO0o + IiII * OoOoOO00 - OOooOOo
      if 43 - 43: oO0o / II111iiii - iII111i / oO0o
      if 98 - 98: OoOoOO00 / OOooOOo
      if 31 - 31: II111iiii % I11i - I11i
      if 17 - 17: iII111i . IiII + OOooOOo % I1Ii111 % i11iIiiIii
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 100 - 100: i11iIiiIii - O0 . OoO0O00 / O0 - Ii1I - IiII
  if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
  if 66 - 66: II111iiii % I1IiiI
  if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for I1I1Ii1I in self . rle . rle_nodes :
    I11Io00oo0OO = I1I1Ii1I . rloc . rloc_name
    oOoO = lisp_get_nat_info ( I1I1Ii1I . rloc . rloc , I11Io00oo0OO )
    if ( oOoO == None ) : continue
    if 96 - 96: I1ii11iIi11i
    i11I1Ii1Iiii1 = oOoO . port
    oO0III1iI = I11Io00oo0OO
    if ( oO0III1iI ) : oO0III1iI = blue ( I11Io00oo0OO , False )
    if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( i11I1Ii1Iiii1 ,
    # i11iIiiIii * i11iIiiIii
 I1I1Ii1I . rloc . rloc . print_address_no_iid ( ) , oO0III1iI ) )
    if 54 - 54: OOooOOo % oO0o * Ii1I / I1IiiI
    I1I1Ii1I . store_translated_rloc ( I1I1Ii1I . rloc , i11I1Ii1Iiii1 )
    if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
    if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
    if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) :
   if ( self . state != LISP_RLOC_UP_STATE ) :
    self . last_state_change = lisp_get_timestamp ( )
    if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
   self . state = LISP_RLOC_UP_STATE
   if 35 - 35: II111iiii
   if 28 - 28: I1Ii111 + IiII + I1ii11iIi11i . Ii1I
   if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
   if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
   if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
  I111iiI = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 98 - 98: IiII
  if ( rloc_record . keys != None and I111iiI ) :
   oO0oOo = rloc_record . keys [ 1 ]
   if ( oO0oOo != None ) :
    O00oO000Oo0 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( i11I1Ii1Iiii1 )
    if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
    oO0oOo . add_key_by_rloc ( O00oO000Oo0 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( O00oO000Oo0 , False ) ) )
    if 57 - 57: iII111i
    if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
    if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
  return ( i11I1Ii1Iiii1 )
  if 68 - 68: I11i / II111iiii * oO0o . II111iiii * OOooOOo
  if 78 - 78: I11i * OoO0O00 / II111iiii
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if ( lisp_i_am_rtr == False ) :
   self . rloc_name += LISP_TP + str ( port )
   if 86 - 86: I1Ii111 % II111iiii
   if 90 - 90: OoO0O00 / I11i - Oo0Ooo
   if 76 - 76: O0 + OoO0O00 / ooOoO0o . II111iiii * iIii1I11I1II1 . I1Ii111
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 43 - 43: Oo0Ooo + o0oOOo0O0Ooo % o0oOOo0O0Ooo % I1ii11iIi11i / iIii1I11I1II1 . I1ii11iIi11i
  if 59 - 59: IiII . OoO0O00 - OoooooooOO . O0
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 33 - 33: Ii1I
  return ( True )
  if 95 - 95: OoooooooOO + OoO0O00 * ooOoO0o
  if 40 - 40: I1IiiI / OOooOOo * Ii1I
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 98 - 98: I1IiiI
  if 4 - 4: I1IiiI % O0 / Oo0Ooo / O0
  if 90 - 90: ooOoO0o - O0 . IiII - O0 . iIii1I11I1II1
 def print_state_change ( self , new_state ) :
  iI111iiiI = self . print_state ( )
  I1i1iI = "{} -> {}" . format ( iI111iiiI , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   I1i1iI = bold ( I1i1iI , False )
   if 55 - 55: OoOoOO00 * iIii1I11I1II1 / O0 / OoO0O00 - IiII / i1IIi
  return ( I1i1iI )
  if 85 - 85: i1IIi * Oo0Ooo
  if 15 - 15: I1ii11iIi11i * i1IIi % I11i
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
  if 73 - 73: I1IiiI / O0 % OOooOOo - II111iiii . OoO0O00 / O0
  if 84 - 84: ooOoO0o
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 92 - 92: I11i - Ii1I * oO0o . I1ii11iIi11i % o0oOOo0O0Ooo
  if 33 - 33: Ii1I * i11iIiiIii / O0 . Oo0Ooo + i1IIi . OoOoOO00
 def print_recent_rloc_probe_rtts ( self ) :
  ooooO0Oo0 = str ( self . recent_rloc_probe_rtts )
  ooooO0Oo0 = ooooO0Oo0 . replace ( "-1" , "?" )
  return ( ooooO0Oo0 )
  if 53 - 53: I1IiiI . I11i / O0 . OOooOOo
  if 63 - 63: o0oOOo0O0Ooo % i1IIi
 def compute_rloc_probe_rtt ( self ) :
  i1IIIi111111 = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  iI11II1III1 = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ i1IIIi111111 ] + iI11II1III1 [ 0 : - 1 ]
  if 37 - 37: I1Ii111 % oO0o * I1ii11iIi11i . iIii1I11I1II1 / ooOoO0o + I1IiiI
  if 100 - 100: Oo0Ooo / OOooOOo - i1IIi / I1ii11iIi11i . IiII
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 98 - 98: I11i + Oo0Ooo . IiII / iII111i % OoooooooOO
  if 35 - 35: O0 . Oo0Ooo / Oo0Ooo / Ii1I / i1IIi * I11i
 def print_recent_rloc_probe_hops ( self ) :
  oo00oo = str ( self . recent_rloc_probe_hops )
  return ( oo00oo )
  if 66 - 66: i1IIi . ooOoO0o
  if 84 - 84: O0 % ooOoO0o / I1Ii111
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 75 - 75: I11i - iII111i . O0
  if ( from_ttl < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   oo0OOooo = "!"
  else :
   oo0OOooo = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 66 - 66: o0oOOo0O0Ooo
   if 65 - 65: oO0o
  i1IIIi111111 = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + oo0OOooo
  iI11II1III1 = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ i1IIIi111111 ] + iI11II1III1 [ 0 : - 1 ]
  if 57 - 57: I1Ii111 + IiII . o0oOOo0O0Ooo % OoO0O00 - I11i * oO0o
  if 55 - 55: I1IiiI / ooOoO0o
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  O0o0OOO = lisp_decode_telemetry ( json_telemetry )
  if 55 - 55: OOooOOo + OoO0O00 % OoO0O00 . O0 + OoO0O00 / II111iiii
  OO00oo00O0O0O = round ( float ( O0o0OOO [ "etr-in" ] ) - float ( O0o0OOO [ "itr-out" ] ) , 3 )
  Oo0o0 = round ( float ( O0o0OOO [ "itr-in" ] ) - float ( O0o0OOO [ "etr-out" ] ) , 3 )
  if 27 - 27: I1IiiI . I1ii11iIi11i + iII111i % iII111i
  i1IIIi111111 = self . rloc_probe_latency
  self . rloc_probe_latency = str ( OO00oo00O0O0O ) + "/" + str ( Oo0o0 )
  iI11II1III1 = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ i1IIIi111111 ] + iI11II1III1 [ 0 : - 1 ]
  if 20 - 20: I1IiiI % Oo0Ooo - OoO0O00 - I1Ii111 - II111iiii
  if 79 - 79: II111iiii - II111iiii + OoOoOO00 / iII111i % OoooooooOO - OoO0O00
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 22 - 22: o0oOOo0O0Ooo + I1Ii111 . Oo0Ooo
  if 84 - 84: O0 + I1IiiI % Oo0Ooo + OOooOOo
 def print_recent_rloc_probe_latencies ( self ) :
  o00Ooooooo = str ( self . recent_rloc_probe_latencies )
  return ( o00Ooooooo )
  if 66 - 66: iII111i + i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * IiII
  if 59 - 59: I1ii11iIi11i + i1IIi / I11i . iII111i - II111iiii
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  OO0Oo00oo = self
  while ( True ) :
   if ( OO0Oo00oo . last_rloc_probe_nonce == nonce ) : break
   OO0Oo00oo = OO0Oo00oo . next_rloc
   if ( OO0Oo00oo == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 66 - 66: Ii1I + OoOoOO00 - I11i / o0oOOo0O0Ooo + iIii1I11I1II1
    return ( False )
    if 66 - 66: OOooOOo - I1Ii111 - OoOoOO00 - i1IIi * Ii1I
    if 23 - 23: IiII - OoOoOO00 . OoO0O00
    if 81 - 81: I1Ii111 / I1ii11iIi11i
    if 69 - 69: I1IiiI
    if 79 - 79: ooOoO0o
    if 83 - 83: I1Ii111 % II111iiii
  OO0Oo00oo . last_rloc_probe_reply = ts
  OO0Oo00oo . compute_rloc_probe_rtt ( )
  o00o00o0 = OO0Oo00oo . print_state_change ( "up" )
  if ( OO0Oo00oo . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( OO0Oo00oo . rloc , True )
   OO0Oo00oo . state = LISP_RLOC_UP_STATE
   OO0Oo00oo . last_state_change = lisp_get_timestamp ( )
   Ii111 = lisp_map_cache . lookup_cache ( eid , True )
   if ( Ii111 ) :
    if 36 - 36: iIii1I11I1II1 . iII111i * I1IiiI . I1IiiI - IiII
    if 39 - 39: O0 / ooOoO0o + I11i - OoOoOO00 * o0oOOo0O0Ooo - OoO0O00
    if 97 - 97: i11iIiiIii / O0 % OoO0O00
    if 88 - 88: i1IIi . I1IiiI
    if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
    if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
    if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
    Ii111 . build_best_rloc_set ( )
    lisp_write_ipc_map_cache ( True , Ii111 )
    if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
    if 84 - 84: I1IiiI + OOooOOo
    if 80 - 80: OOooOOo / OoOoOO00
    if 93 - 93: OOooOOo
    if 82 - 82: iIii1I11I1II1 + OoO0O00 / iIii1I11I1II1 . iIii1I11I1II1
    if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
  OO0Oo00oo . store_rloc_probe_hops ( hc , ttl )
  if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
  if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
  if 72 - 72: i11iIiiIii . iII111i . Ii1I * I1ii11iIi11i
  if 49 - 49: OoOoOO00 - O0 % I11i - ooOoO0o * OOooOOo
  if ( jt ) : OO0Oo00oo . store_rloc_probe_latencies ( jt )
  if 58 - 58: OoooooooOO - OOooOOo * oO0o / Ii1I . IiII
  I1III1 = bold ( "RLOC-probe reply" , False )
  O00oO000Oo0 = OO0Oo00oo . rloc . print_address_no_iid ( )
  I1IIiiI1Ii = bold ( str ( OO0Oo00oo . print_rloc_probe_rtt ( ) ) , False )
  ooo0OO0OOooO0 = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 98 - 98: i11iIiiIii . I1Ii111
  i1IIIII = ""
  if ( OO0Oo00oo . rloc_next_hop != None ) :
   oooOo , IIiI1 = OO0Oo00oo . rloc_next_hop
   i1IIIII = ", nh {}({})" . format ( IIiI1 , oooOo )
   if 15 - 15: Ii1I + IiII + OoO0O00 * I11i * iIii1I11I1II1 * oO0o
   if 74 - 74: I1IiiI
  Iii1IIIIi1 = bold ( OO0Oo00oo . print_rloc_probe_latency ( ) , False )
  Iii1IIIIi1 = ", latency {}" . format ( Iii1IIIIi1 ) if jt else ""
  if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
  oOO = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 27 - 27: iIii1I11I1II1 . ooOoO0o
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( I1III1 , red ( O00oO000Oo0 , False ) , ooo0OO0OOooO0 , oOO ,
  # Ii1I / OoOoOO00 / ooOoO0o * IiII * II111iiii
 o00o00o0 , I1IIiiI1Ii , i1IIIII , str ( hc ) + "/" + str ( ttl ) , Iii1IIIIi1 ) )
  if 68 - 68: iIii1I11I1II1 . OoOoOO00 * OOooOOo * oO0o
  if ( OO0Oo00oo . rloc_next_hop == None ) : return ( True )
  if 54 - 54: Ii1I % OoO0O00 % I1IiiI % OOooOOo / oO0o + I1IiiI
  if 94 - 94: OoOoOO00 . O0
  if 86 - 86: oO0o % Oo0Ooo . OoooooooOO / OOooOOo / i1IIi
  if 65 - 65: Ii1I . OoooooooOO % IiII - o0oOOo0O0Ooo . OOooOOo . II111iiii
  OO0Oo00oo = None
  O0OO = None
  while ( True ) :
   OO0Oo00oo = self if OO0Oo00oo == None else OO0Oo00oo . next_rloc
   if ( OO0Oo00oo == None ) : break
   if ( OO0Oo00oo . up_state ( ) == False ) : continue
   if ( OO0Oo00oo . rloc_probe_rtt == - 1 ) : continue
   if 44 - 44: ooOoO0o / i11iIiiIii % o0oOOo0O0Ooo % OOooOOo
   if ( O0OO == None ) : O0OO = OO0Oo00oo
   if ( OO0Oo00oo . rloc_probe_rtt < O0OO . rloc_probe_rtt ) : O0OO = OO0Oo00oo
   if 81 - 81: I11i % iIii1I11I1II1
   if 4 - 4: o0oOOo0O0Ooo . iII111i / O0
  if ( O0OO != None ) :
   oooOo , IIiI1 = O0OO . rloc_next_hop
   i11ii = lisp_get_host_route_device ( O00oO000Oo0 )
   if ( i11ii != oooOo ) :
    lisp_install_host_route ( O00oO000Oo0 , IIiI1 , oooOo )
    self . active_rloc_next_hop = O0OO
    oooOo = bold ( oooOo , False )
    IIIIiiI1iIiI = red ( O00oO000Oo0 , False )
    I1IIiiI1Ii = O0OO . rloc_probe_rtt
    lprint ( "Change data-plane host-route {} -> {} for {}, best-rtt {}" . format ( i11ii , oooOo , IIIIiiI1iIiI , I1IIiiI1Ii ) )
    if 85 - 85: iIii1I11I1II1 . iIii1I11I1II1 / IiII % I1ii11iIi11i % i11iIiiIii . i1IIi
    if 20 - 20: Ii1I % I1ii11iIi11i . iIii1I11I1II1 - I1IiiI % IiII
  return ( True )
  if 51 - 51: ooOoO0o
  if 50 - 50: O0 / II111iiii
 def add_to_rloc_probe_list ( self , eid , group ) :
  O00oO000Oo0 = self . rloc . print_address_no_iid ( )
  i11I1Ii1Iiii1 = self . translated_port
  if 94 - 94: O0 + O0 % I1ii11iIi11i % i1IIi
  if 15 - 15: I1IiiI
  if 48 - 48: Ii1I * IiII % O0 - II111iiii
  if 66 - 66: iIii1I11I1II1 / OOooOOo
  if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
  if ( i11I1Ii1Iiii1 != 0 ) :
   OoO0ooOOo0o0 = O00oO000Oo0 + ":" + str ( i11I1Ii1Iiii1 )
   if ( O00oO000Oo0 in lisp_rloc_probe_list ) :
    lisp_rloc_probe_list [ OoO0ooOOo0o0 ] = lisp_rloc_probe_list [ O00oO000Oo0 ]
    lisp_rloc_probe_list . pop ( O00oO000Oo0 )
    if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
   O00oO000Oo0 = OoO0ooOOo0o0
   if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
   if 46 - 46: I11i - ooOoO0o . I1IiiI
   if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
   if 90 - 90: i11iIiiIii / i1IIi
   if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
  if ( O00oO000Oo0 not in lisp_rloc_probe_list ) : lisp_rloc_probe_list [ O00oO000Oo0 ] = [ ]
  if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
  if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
  if 87 - 87: II111iiii - iIii1I11I1II1 % I11i % I1IiiI . o0oOOo0O0Ooo
  if 52 - 52: i11iIiiIii . oO0o / OoooooooOO - OoO0O00
  if 7 - 7: I1IiiI * I1IiiI % OOooOOo % iIii1I11I1II1 * OoO0O00 . o0oOOo0O0Ooo
  if ( group . is_null ( ) ) : group . instance_id = 0
  if 32 - 32: ooOoO0o / i1IIi
  OOiii1i1iI = None
  III1ii = None
  for IIIIiiI1iIiI , oOO , II11iIIii in lisp_rloc_probe_list [ O00oO000Oo0 ] :
   if 54 - 54: oO0o + I1ii11iIi11i + OoOoOO00
   if 26 - 26: I1IiiI - i11iIiiIii
   if 99 - 99: OOooOOo % OOooOOo
   if ( III1ii == None ) : III1ii = IIIIiiI1iIiI
   if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
   if ( oOO . is_exact_match ( eid ) and II11iIIii . is_exact_match ( group ) ) :
    if ( IIIIiiI1iIiI == self ) : return
    self . copy_rloc_probe_recents ( IIIIiiI1iIiI )
    self . uptime = IIIIiiI1iIiI . uptime
    OOiii1i1iI = [ IIIIiiI1iIiI , oOO , II11iIIii ]
    break
    if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
    if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
    if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
    if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
    if 92 - 92: I11i
    if 34 - 34: I1IiiI % iIii1I11I1II1 . I1ii11iIi11i * Oo0Ooo * iIii1I11I1II1 / O0
    if 98 - 98: iII111i % IiII + OoO0O00
  if ( OOiii1i1iI == None and III1ii != None ) :
   self . copy_rloc_probe_recents ( III1ii )
   self . uptime = III1ii . uptime
   if 23 - 23: OOooOOo
   if 83 - 83: I1ii11iIi11i / O0 * II111iiii + IiII + Oo0Ooo
   if 99 - 99: II111iiii + O0
   if 94 - 94: ooOoO0o * ooOoO0o + o0oOOo0O0Ooo . iII111i % iIii1I11I1II1 + Ii1I
   if 88 - 88: Oo0Ooo . iII111i
  if ( OOiii1i1iI != None ) :
   lisp_rloc_probe_list [ O00oO000Oo0 ] . remove ( OOiii1i1iI )
   if 89 - 89: OOooOOo + I1Ii111 % i11iIiiIii + Oo0Ooo / Oo0Ooo + OoO0O00
   if 9 - 9: OoOoOO00 % i1IIi + IiII
   if 19 - 19: I1Ii111 - II111iiii / I1Ii111 + I1IiiI - OoooooooOO + o0oOOo0O0Ooo
   if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
   if 95 - 95: ooOoO0o
  lisp_rloc_probe_list [ O00oO000Oo0 ] . append ( [ self , eid , group ] )
  if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
  if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
 def delete_from_rloc_probe_list ( self , eid , group ) :
  O00oO000Oo0 = self . rloc . print_address_no_iid ( )
  i11I1Ii1Iiii1 = self . translated_port
  if ( i11I1Ii1Iiii1 != 0 ) : O00oO000Oo0 += ":" + str ( i11I1Ii1Iiii1 )
  if ( O00oO000Oo0 not in lisp_rloc_probe_list ) : return
  if 32 - 32: OoOoOO00 % i11iIiiIii
  O0o0o00oooOO = [ ]
  for Ii in lisp_rloc_probe_list [ O00oO000Oo0 ] :
   if ( Ii [ 0 ] != self ) : continue
   if ( Ii [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( Ii [ 2 ] . is_exact_match ( group ) == False ) : continue
   O0o0o00oooOO = Ii
   break
   if 18 - 18: ooOoO0o * OoOoOO00 . OoO0O00
  if ( O0o0o00oooOO == [ ] ) : return
  if 75 - 75: OoOoOO00 + O0 * I1Ii111
  try :
   lisp_rloc_probe_list [ O00oO000Oo0 ] . remove ( O0o0o00oooOO )
   if ( lisp_rloc_probe_list [ O00oO000Oo0 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( O00oO000Oo0 )
    if 78 - 78: OoOoOO00
  except :
   return
   if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
   if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
   if 13 - 13: I1ii11iIi11i * II111iiii
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  i11IiIIi11I = ""
  OO0Oo00oo = self
  while ( True ) :
   O0Oo = OO0Oo00oo . last_rloc_probe
   if ( O0Oo == None ) : O0Oo = 0
   IIiIiI1IIIiI = OO0Oo00oo . last_rloc_probe_reply
   if ( IIiIiI1IIIiI == None ) : IIiIiI1IIIiI = 0
   I1IIiiI1Ii = OO0Oo00oo . print_rloc_probe_rtt ( )
   OOo0oOO0o0oo0 = space ( 4 )
   if 21 - 21: ooOoO0o . i1IIi / Oo0Ooo . OoO0O00
   if ( OO0Oo00oo . rloc_next_hop == None ) :
    i11IiIIi11I += "RLOC-Probing:\n"
   else :
    oooOo , IIiI1 = OO0Oo00oo . rloc_next_hop
    i11IiIIi11I += "RLOC-Probing for nh {}({}):\n" . format ( IIiI1 , oooOo )
    if 49 - 49: oO0o % i11iIiiIii * Ii1I
    if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
   i11IiIIi11I += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( OOo0oOO0o0oo0 , lisp_print_elapsed ( O0Oo ) ,
   # I1ii11iIi11i + iII111i . o0oOOo0O0Ooo . I1Ii111
 OOo0oOO0o0oo0 , lisp_print_elapsed ( IIiIiI1IIIiI ) , I1IIiiI1Ii )
   if 45 - 45: I1ii11iIi11i + i11iIiiIii - II111iiii
   if ( trailing_linefeed ) : i11IiIIi11I += "\n"
   if 81 - 81: Oo0Ooo . oO0o + O0 * Oo0Ooo % I1IiiI
   OO0Oo00oo = OO0Oo00oo . next_rloc
   if ( OO0Oo00oo == None ) : break
   i11IiIIi11I += "\n"
   if 53 - 53: O0 * iII111i
  return ( i11IiIIi11I )
  if 79 - 79: o0oOOo0O0Ooo / I1ii11iIi11i . iII111i . II111iiii + I1ii11iIi11i * I11i
  if 49 - 49: Ii1I * OoooooooOO * i1IIi % OoOoOO00
 def get_encap_keys ( self ) :
  i11I1Ii1Iiii1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 83 - 83: iIii1I11I1II1 - i1IIi - Ii1I % iII111i
  O00oO000Oo0 = self . rloc . print_address_no_iid ( ) + ":" + i11I1Ii1Iiii1
  if 69 - 69: I1Ii111 * oO0o * I1IiiI
  try :
   oOoOOoo = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ]
   if ( oOoOOoo [ 1 ] ) : return ( oOoOOoo [ 1 ] . encrypt_key , oOoOOoo [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
   if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
   if 52 - 52: OoooooooOO
 def rloc_recent_rekey ( self ) :
  i11I1Ii1Iiii1 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
  O00oO000Oo0 = self . rloc . print_address_no_iid ( ) + ":" + i11I1Ii1Iiii1
  if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
  try :
   oO0oOo = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ] [ 1 ]
   if ( oO0oOo == None ) : return ( False )
   if ( oO0oOo . last_rekey == None ) : return ( True )
   return ( time . time ( ) - oO0oOo . last_rekey < 1 )
  except :
   return ( False )
   if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
   if 86 - 86: Oo0Ooo / OoO0O00
   if 78 - 78: I1IiiI * I1IiiI
 def refresh_decent_nat_rloc ( self , lisp_sockets , eid ) :
  iIiIIIIIii = self . last_state_change
  if ( iIiIIIIIii == None ) : return
  if ( ( time . time ( ) - iIiIIIIIii ) <= 60 ) : return
  if 13 - 13: oO0o
  oOO = green ( eid . print_address ( ) , False )
  IIIIiiI1iIiI = red ( self . rloc . print_address_no_iid ( ) , False )
  Oo0oOOo000 = blue ( self . rloc_name , False )
  lprint ( "Refresh map-cache for {} for RLOC {}, {}" . format ( oOO , IIIIiiI1iIiI , Oo0oOOo000 ) )
  if 43 - 43: oO0o / Ii1I % OOooOOo
  lisp_send_map_request ( lisp_sockets , 0 , None , eid , None )
  if 45 - 45: II111iiii
  if 41 - 41: Ii1I / OOooOOo * Oo0Ooo . O0 - i11iIiiIii
 def get_rle ( self , rloc ) :
  if ( self . rle == None ) : return ( None )
  for I1I1Ii1I in self . rle . rle_nodes :
   IIIIiiI1iIiI = I1I1Ii1I . rloc . rloc
   if ( rloc . is_exact_match ( IIIIiiI1iIiI ) ) : return ( I1I1Ii1I . rloc )
   if 77 - 77: o0oOOo0O0Ooo + I1IiiI + I1Ii111 / I1ii11iIi11i * i1IIi
  return ( None )
  if 37 - 37: O0 + iIii1I11I1II1 % IiII * oO0o
  if 43 - 43: OOooOOo . O0
  if 76 - 76: OOooOOo * OoooooooOO / IiII . OoO0O00 + II111iiii
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
  if 23 - 23: OoO0O00 - OoooooooOO * I11i . iIii1I11I1II1 / o0oOOo0O0Ooo + oO0o
  if 74 - 74: II111iiii / I1IiiI * O0 * OoO0O00 . I11i
 def print_mapping ( self , eid_indent , rloc_indent ) :
  iIiIIIIIii = lisp_print_elapsed ( self . uptime )
  i1I1IIIiII = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 74 - 74: O0 . i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , i1I1IIIiII , iIiIIIIIii ,
 len ( self . rloc_set ) ) )
  for OO0Oo00oo in self . rloc_set : OO0Oo00oo . print_rloc ( rloc_indent )
  if 24 - 24: ooOoO0o % I1Ii111 + OoO0O00 * o0oOOo0O0Ooo % O0 - i11iIiiIii
  if 49 - 49: o0oOOo0O0Ooo / OoOoOO00 + iII111i
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 85 - 85: I1IiiI - o0oOOo0O0Ooo
  if 86 - 86: II111iiii + Ii1I * Ii1I
 def print_ttl ( self ) :
  o0ooo000o00O = self . map_cache_ttl
  if ( o0ooo000o00O == None ) : return ( "forever" )
  if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
  if ( o0ooo000o00O >= 3600 ) :
   if ( ( o0ooo000o00O % 3600 ) == 0 ) :
    o0ooo000o00O = str ( old_div ( o0ooo000o00O , 3600 ) ) + " hours"
   else :
    o0ooo000o00O = str ( o0ooo000o00O * 60 ) + " mins"
    if 86 - 86: Ii1I
  elif ( o0ooo000o00O >= 60 ) :
   if ( ( o0ooo000o00O % 60 ) == 0 ) :
    o0ooo000o00O = str ( old_div ( o0ooo000o00O , 60 ) ) + " mins"
   else :
    o0ooo000o00O = str ( o0ooo000o00O ) + " secs"
    if 69 - 69: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo
  else :
   o0ooo000o00O = str ( o0ooo000o00O ) + " secs"
   if 1 - 1: Ii1I
  return ( o0ooo000o00O )
  if 43 - 43: o0oOOo0O0Ooo
  if 78 - 78: I1Ii111 % i1IIi * I11i
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
  if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
 def refresh_multicast ( self ) :
  if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
  if 29 - 29: OoO0O00
  if 33 - 33: I1ii11iIi11i - O0
  if 72 - 72: Oo0Ooo * iII111i - I11i
  if 81 - 81: I1Ii111
  o0oOOOO0 = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  oooOOOo00o = ( o0oOOOO0 in [ 0 , 1 , 2 ] )
  if ( oooOOOo00o == False ) : return ( False )
  if 33 - 33: OoO0O00 * II111iiii / i1IIi
  if 93 - 93: I1Ii111 % I11i
  if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
  if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
  I111i1iI = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( I111i1iI ) : return ( False )
  if 52 - 52: OoO0O00 + iII111i . o0oOOo0O0Ooo * o0oOOo0O0Ooo - I1Ii111
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 49 - 49: I1ii11iIi11i
  if 2 - 2: i1IIi
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  o0oOOOO0 = time . time ( ) - self . last_refresh_time
  if ( o0oOOOO0 >= self . map_cache_ttl ) : return ( True )
  if 61 - 61: OoO0O00
  if 100 - 100: OoOoOO00
  if 97 - 97: OoooooooOO
  if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
  if 35 - 35: iII111i % OoO0O00 * O0
  i1I1Iii1II = self . map_cache_ttl - ( old_div ( self . map_cache_ttl , 10 ) )
  if ( o0oOOOO0 >= i1I1Iii1II ) : return ( True )
  return ( False )
  if 41 - 41: o0oOOo0O0Ooo * Ii1I + I11i . O0
  if 17 - 17: Ii1I % I1Ii111
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  o0oOOOO0 = time . time ( ) - self . stats . last_increment
  return ( o0oOOOO0 <= 60 )
  if 69 - 69: iIii1I11I1II1
  if 65 - 65: IiII % OOooOOo / o0oOOo0O0Ooo * II111iiii - oO0o
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 38 - 38: I1Ii111 * o0oOOo0O0Ooo
  if 32 - 32: iII111i / Ii1I / I1Ii111 - OoOoOO00 / OOooOOo * OoO0O00
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 32 - 32: I1ii11iIi11i + ooOoO0o . i1IIi * iIii1I11I1II1 - I1IiiI
  if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for OO0Oo00oo in self . best_rloc_set :
   if ( OO0Oo00oo . rloc . is_null ( ) and OO0Oo00oo . rle != None ) :
    if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
    if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
    if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
    if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
    for I1I1Ii1I in OO0Oo00oo . rle . rle_forwarding_list :
     I1I1Ii1I . rloc . delete_from_rloc_probe_list ( self . eid , self . group )
     if 100 - 100: OoO0O00
   else :
    OO0Oo00oo . delete_from_rloc_probe_list ( self . eid , self . group )
    if 36 - 36: oO0o + Ii1I - O0
    if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
    if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
    if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
 def build_best_rloc_set ( self ) :
  if 11 - 11: I11i
  if 85 - 85: OoOoOO00 - Ii1I / Oo0Ooo % I1ii11iIi11i
  if 12 - 12: i1IIi + o0oOOo0O0Ooo / oO0o . O0
  if 37 - 37: IiII
  if 99 - 99: i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . OoO0O00 / I1IiiI
  if 44 - 44: iII111i - OoO0O00 / i11iIiiIii
  if 55 - 55: O0 * OoO0O00 * i1IIi
  if 9 - 9: IiII
  if 64 - 64: ooOoO0o + OoooooooOO
  if 99 - 99: iIii1I11I1II1 * II111iiii * i11iIiiIii
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 10 - 10: OOooOOo
  if 75 - 75: I11i * ooOoO0o * Oo0Ooo . i1IIi . ooOoO0o . ooOoO0o
  if 24 - 24: iIii1I11I1II1
  if 72 - 72: i11iIiiIii + o0oOOo0O0Ooo % ooOoO0o * I1ii11iIi11i . i1IIi
  if 59 - 59: OoooooooOO - OoooooooOO - o0oOOo0O0Ooo + i1IIi % I1Ii111
  o0OooOoOO0ooO = 256
  for OO0Oo00oo in self . rloc_set :
   if ( OO0Oo00oo . up_state ( ) == False ) : continue
   o0OooOoOO0ooO = min ( OO0Oo00oo . priority , o0OooOoOO0ooO )
   if 20 - 20: o0oOOo0O0Ooo
   if 65 - 65: OOooOOo / OoOoOO00
   if 31 - 31: OoOoOO00 * I1IiiI + i11iIiiIii % OOooOOo * OoOoOO00
   if 36 - 36: I1Ii111 * OoO0O00
   if 84 - 84: OoOoOO00
  for OO0Oo00oo in self . rloc_set :
   if ( OO0Oo00oo . priority == o0OooOoOO0ooO ) : self . best_rloc_set . append ( OO0Oo00oo )
   if 80 - 80: oO0o
   if 59 - 59: iIii1I11I1II1 / IiII % I1ii11iIi11i + OoO0O00 - I11i % OOooOOo
   if 92 - 92: iII111i
   if 96 - 96: OoOoOO00 / OoOoOO00 / OoOoOO00 + OoooooooOO + Oo0Ooo
   if 91 - 91: OoOoOO00 + II111iiii / I11i * iIii1I11I1II1
   if 92 - 92: I1Ii111 - IiII / IiII
  for OO0Oo00oo in self . rloc_set :
   if ( OO0Oo00oo . rloc . is_null ( ) ) :
    if 42 - 42: IiII
    if 7 - 7: iIii1I11I1II1
    if 35 - 35: IiII + O0 % I1Ii111 - I1ii11iIi11i - i1IIi
    if 100 - 100: I1Ii111 + i11iIiiIii - IiII / I1ii11iIi11i / iII111i
    if 56 - 56: iII111i
    if ( OO0Oo00oo . rle != None and OO0Oo00oo . rle . rle_forwarding_list != [ ] ) :
     for I1I1Ii1I in OO0Oo00oo . rle . rle_forwarding_list :
      I1I1Ii1I . rloc . add_to_rloc_probe_list ( self . eid , self . group )
      if 91 - 91: Oo0Ooo . I11i . I1ii11iIi11i
      if 60 - 60: i11iIiiIii - OOooOOo
    continue
    if 78 - 78: I1IiiI * ooOoO0o % iIii1I11I1II1 / I1ii11iIi11i
   OO0Oo00oo . add_to_rloc_probe_list ( self . eid , self . group )
   if 61 - 61: I1Ii111 . Ii1I + OoooooooOO
   if 98 - 98: OOooOOo . ooOoO0o . OoOoOO00 - I1Ii111 . i1IIi - iIii1I11I1II1
   if 89 - 89: II111iiii * I1ii11iIi11i - I1IiiI
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  Oo00O0o0O = lisp_packet . packet
  o00Oooo00OoOO0OoO = lisp_packet . inner_version
  OOOOo0o0O0o = len ( self . best_rloc_set )
  if 26 - 26: iII111i
  if ( OOOOo0o0O0o == 0 ) :
   self . stats . increment ( len ( Oo00O0o0O ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 55 - 55: I1ii11iIi11i . ooOoO0o * Oo0Ooo + I1Ii111
   if 59 - 59: iII111i - OOooOOo - OoO0O00 . I1IiiI % o0oOOo0O0Ooo + iII111i
  ii11i1ii = 4 if lisp_load_split_pings else 0
  ii1iiIiiiI11 = lisp_packet . hash_ports ( )
  if ( o00Oooo00OoOO0OoO == 4 ) :
   for o000o0O0Oo00 in range ( 8 + ii11i1ii ) :
    ii1iiIiiiI11 = ii1iiIiiiI11 ^ struct . unpack ( "B" , Oo00O0o0O [ o000o0O0Oo00 + 12 : o000o0O0Oo00 + 13 ] ) [ 0 ]
    if 3 - 3: OoO0O00 / OoO0O00
  elif ( o00Oooo00OoOO0OoO == 6 ) :
   for o000o0O0Oo00 in range ( 0 , 32 + ii11i1ii , 4 ) :
    ii1iiIiiiI11 = ii1iiIiiiI11 ^ struct . unpack ( "I" , Oo00O0o0O [ o000o0O0Oo00 + 8 : o000o0O0Oo00 + 12 ] ) [ 0 ]
    if 18 - 18: Ii1I / I1IiiI - IiII . o0oOOo0O0Ooo / I1Ii111 % I1ii11iIi11i
   ii1iiIiiiI11 = ( ii1iiIiiiI11 >> 16 ) + ( ii1iiIiiiI11 & 0xffff )
   ii1iiIiiiI11 = ( ii1iiIiiiI11 >> 8 ) + ( ii1iiIiiiI11 & 0xff )
  else :
   for o000o0O0Oo00 in range ( 0 , 12 + ii11i1ii , 4 ) :
    ii1iiIiiiI11 = ii1iiIiiiI11 ^ struct . unpack ( "I" , Oo00O0o0O [ o000o0O0Oo00 : o000o0O0Oo00 + 4 ] ) [ 0 ]
    if 21 - 21: OoooooooOO % I1ii11iIi11i / OoooooooOO - I1ii11iIi11i * i1IIi
    if 35 - 35: I11i . Ii1I / Ii1I . OoOoOO00
    if 59 - 59: OoOoOO00 / i1IIi / iIii1I11I1II1 + i1IIi
  if ( lisp_data_plane_logging ) :
   iiiiiI11iiiI = [ ]
   for IIIIiiI1iIiI in self . best_rloc_set :
    if ( IIIIiiI1iIiI . rloc . is_null ( ) ) : continue
    iiiiiI11iiiI . append ( [ IIIIiiI1iIiI . rloc . print_address_no_iid ( ) , IIIIiiI1iIiI . print_state ( ) ] )
    if 83 - 83: iII111i . OoooooooOO - oO0o . I11i
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( ii1iiIiiiI11 ) , ii1iiIiiiI11 % OOOOo0o0O0o , red ( str ( iiiiiI11iiiI ) , False ) ) )
   if 76 - 76: I1Ii111 + O0 * OoO0O00 . I1IiiI - I1Ii111
   if 5 - 5: I1ii11iIi11i . O0 - oO0o
   if 47 - 47: iII111i . oO0o
   if 9 - 9: IiII * i11iIiiIii * iIii1I11I1II1 % I11i % I1IiiI
   if 84 - 84: OoooooooOO
   if 51 - 51: O0 * Oo0Ooo - OoooooooOO % OoOoOO00 . I1ii11iIi11i
  OO0Oo00oo = self . best_rloc_set [ ii1iiIiiiI11 % OOOOo0o0O0o ]
  if 44 - 44: ooOoO0o / IiII + O0 . II111iiii
  if 12 - 12: Oo0Ooo
  if 54 - 54: OoOoOO00 . O0 % I1ii11iIi11i - II111iiii % I11i
  if 34 - 34: OoOoOO00 % ooOoO0o * I1IiiI % IiII
  if ( lisp_decent_nat and OO0Oo00oo . stats . packet_count == 0 ) :
   IIIIiiI1iIiI = self . find_rtr_rloc ( )
   if ( IIIIiiI1iIiI != None ) : OO0Oo00oo = IIIIiiI1iIiI
   if 62 - 62: OoooooooOO . OoooooooOO / I11i % OoOoOO00
   if 2 - 2: IiII % I1ii11iIi11i * OoO0O00 + Oo0Ooo * iII111i
   if 85 - 85: OOooOOo * I1IiiI - iIii1I11I1II1 - OoOoOO00 + ooOoO0o . OoO0O00
   if 46 - 46: OoO0O00 * I1Ii111 . O0
   if 86 - 86: i11iIiiIii . Ii1I / OoOoOO00 / I11i * i1IIi
   if 40 - 40: o0oOOo0O0Ooo
  o0Oo00oOOo = lisp_get_echo_nonce ( OO0Oo00oo . rloc , None )
  if ( o0Oo00oOOo ) :
   o0Oo00oOOo . change_state ( OO0Oo00oo )
   if ( OO0Oo00oo . no_echoed_nonce_state ( ) ) :
    o0Oo00oOOo . request_nonce_sent = None
    if 33 - 33: i11iIiiIii + I1Ii111 % I1ii11iIi11i - I1Ii111 * OoO0O00
    if 1 - 1: II111iiii / I1IiiI + II111iiii % II111iiii - I1Ii111
    if 24 - 24: I11i / Oo0Ooo / i1IIi + IiII
    if 10 - 10: I11i - IiII / II111iiii / oO0o % O0 / I1Ii111
    if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
    if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
  if ( OO0Oo00oo . up_state ( ) == False ) :
   II1II1i1 = ii1iiIiiiI11 % OOOOo0o0O0o
   o00O = ( II1II1i1 + 1 ) % OOOOo0o0O0o
   while ( o00O != II1II1i1 ) :
    OO0Oo00oo = self . best_rloc_set [ o00O ]
    if ( OO0Oo00oo . up_state ( ) ) : break
    o00O = ( o00O + 1 ) % OOOOo0o0O0o
    if 6 - 6: Ii1I
   if ( o00O == II1II1i1 ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 96 - 96: I1IiiI
    if 30 - 30: oO0o . I1Ii111 * i11iIiiIii - II111iiii * I11i
    if 67 - 67: IiII
    if 87 - 87: I1Ii111 - iII111i * I11i
    if 74 - 74: Ii1I - OoOoOO00 + i11iIiiIii - II111iiii - i11iIiiIii . ooOoO0o
    if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
  if ( OO0Oo00oo . rle_name and OO0Oo00oo . rle == None ) :
   if ( OO0Oo00oo . rle_name in lisp_rle_list ) :
    OO0Oo00oo . rle = lisp_rle_list [ OO0Oo00oo . rle_name ]
    if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
    if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
  if ( OO0Oo00oo . rle ) : return ( [ None , None , None , None , OO0Oo00oo . rle , None ] )
  if 78 - 78: i1IIi
  if 25 - 25: Ii1I * II111iiii / OoOoOO00
  if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
  if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
  if ( OO0Oo00oo . elp and OO0Oo00oo . elp . use_elp_node ) :
   return ( [ OO0Oo00oo . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
   if 15 - 15: i11iIiiIii
   if 85 - 85: I1Ii111 + iII111i - oO0o
   if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
   if 64 - 64: OoOoOO00
  if ( OO0Oo00oo . active_rloc_next_hop != None ) : OO0Oo00oo = OO0Oo00oo . active_rloc_next_hop
  if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
  if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
  if 71 - 71: ooOoO0o
  if 35 - 35: OoOoOO00
  OO0Oo00oo . stats . increment ( len ( Oo00O0o0O ) )
  if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
  if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
  if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
  if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
  ooOOOoo0O00 = None if ( OO0Oo00oo . rloc . is_null ( ) ) else OO0Oo00oo . rloc
  i11I1Ii1Iiii1 = OO0Oo00oo . translated_port
  oo0OoooOo0 = self . action if ( ooOOOoo0O00 == None ) else None
  if 22 - 22: oO0o + O0 + I11i . OoO0O00 - II111iiii
  if 20 - 20: Ii1I * I1Ii111 . I1IiiI % OoOoOO00 / OoO0O00 % II111iiii
  if 43 - 43: IiII + II111iiii + oO0o / I1ii11iIi11i % i1IIi - OoO0O00
  if 59 - 59: Oo0Ooo + O0 + iII111i
  if 71 - 71: IiII - OoO0O00
  OOooO = None
  if ( o0Oo00oOOo and o0Oo00oOOo . request_nonce_timeout ( ) == False ) :
   OOooO = o0Oo00oOOo . get_request_or_echo_nonce ( ipc_socket , ooOOOoo0O00 )
   if 90 - 90: Oo0Ooo
   if 83 - 83: iIii1I11I1II1 % ooOoO0o % OOooOOo * i1IIi - o0oOOo0O0Ooo * i1IIi
   if 60 - 60: Ii1I . I1ii11iIi11i - I11i + i11iIiiIii / iII111i
   if 9 - 9: I1Ii111 . oO0o . OoO0O00 / IiII - oO0o / oO0o
   if 50 - 50: II111iiii + OoOoOO00
  return ( [ ooOOOoo0O00 , i11I1Ii1Iiii1 , OOooO , oo0OoooOo0 , None , OO0Oo00oo ] )
  if 17 - 17: ooOoO0o + I1ii11iIi11i
  if 34 - 34: Ii1I / II111iiii + OoOoOO00 . II111iiii + OoooooooOO * o0oOOo0O0Ooo
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 48 - 48: O0
  if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
  if 84 - 84: i11iIiiIii . OoooooooOO
  if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
  if 5 - 5: Ii1I
  for i1iiI1i1 in self . rloc_set :
   for OO0Oo00oo in rloc_address_set :
    if ( OO0Oo00oo . is_exact_match ( i1iiI1i1 . rloc ) == False ) : continue
    OO0Oo00oo = None
    break
    if 19 - 19: oO0o
   if ( OO0Oo00oo == rloc_address_set [ - 1 ] ) : return ( False )
   if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
  return ( True )
  if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
  if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
 def get_rloc ( self , rloc ) :
  for i1iiI1i1 in self . rloc_set :
   IIIIiiI1iIiI = i1iiI1i1 . rloc
   if ( rloc . is_exact_match ( IIIIiiI1iIiI ) ) : return ( i1iiI1i1 )
   if 1 - 1: OoOoOO00 / I11i
  return ( None )
  if 43 - 43: o0oOOo0O0Ooo - i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
  if 69 - 69: i11iIiiIii - iIii1I11I1II1
 def get_rloc_by_interface ( self , interface ) :
  for i1iiI1i1 in self . rloc_set :
   if ( i1iiI1i1 . interface == interface ) : return ( i1iiI1i1 )
   if 40 - 40: I1IiiI / oO0o + ooOoO0o
  return ( None )
  if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
  if 37 - 37: I1ii11iIi11i
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   Iiii1II1 = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( Iiii1II1 == None ) :
    Iiii1II1 = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , Iiii1II1 )
    if 24 - 24: O0 . I1Ii111 * i11iIiiIii
   Iiii1II1 . add_source_entry ( self )
   if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
   if 16 - 16: I11i % O0
   if 56 - 56: Ii1I * OoOoOO00 . i1IIi
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
    if 15 - 15: I1Ii111
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( Ii111 . group )
   Ii111 . add_source_entry ( self )
   if 64 - 64: OOooOOo * Oo0Ooo
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
  if 18 - 18: I1Ii111
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 29 - 29: i1IIi - I1IiiI / i1IIi
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    o0ooOooO00Oo = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( o0ooOooO00Oo ) )
    if 28 - 28: i1IIi % iII111i - OOooOOo % o0oOOo0O0Ooo % I11i . I11i
  else :
   Ii111 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( Ii111 == None ) : return
   if 94 - 94: OOooOOo * II111iiii
   oo0OoOO = Ii111 . lookup_source_cache ( self . eid , True )
   if ( oo0OoOO == None ) : return
   if 15 - 15: OoOoOO00 / o0oOOo0O0Ooo / iII111i % oO0o - OoO0O00
   Ii111 . source_cache . delete_cache ( self . eid )
   if ( Ii111 . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 44 - 44: I1Ii111 . Ii1I + I1ii11iIi11i
    if 29 - 29: ooOoO0o . OoOoOO00 * iIii1I11I1II1 / OoooooooOO - i1IIi
    if 98 - 98: OoOoOO00 / Oo0Ooo
    if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 97 - 97: iIii1I11I1II1 * I1Ii111
  if 39 - 39: I1Ii111 . II111iiii
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
  if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 34 - 34: I1IiiI
  if 56 - 56: Ii1I
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  i1I1iI = "," + str ( self . secondary_iid )
  return ( prefix . replace ( i1I1iI , i1I1iI + "*" ) )
  if 71 - 71: O0 / i1IIi
  if 20 - 20: OOooOOo . iIii1I11I1II1 - I1Ii111 . i1IIi
 def increment_decap_stats ( self , packet ) :
  i11I1Ii1Iiii1 = packet . udp_dport
  if ( i11I1Ii1Iiii1 == LISP_DATA_PORT ) :
   OO0Oo00oo = self . get_rloc ( packet . outer_dest )
  else :
   if 82 - 82: oO0o * i11iIiiIii % o0oOOo0O0Ooo % IiII - I11i - OoO0O00
   if 24 - 24: oO0o . II111iiii + OoO0O00 * I1ii11iIi11i / oO0o
   if 86 - 86: I1Ii111 + I1ii11iIi11i
   if 63 - 63: ooOoO0o - i11iIiiIii . o0oOOo0O0Ooo - i1IIi - IiII
   for OO0Oo00oo in self . rloc_set :
    if ( OO0Oo00oo . translated_port != 0 ) : break
    if 32 - 32: I1Ii111 / iIii1I11I1II1 + oO0o % I11i * OoooooooOO
    if 69 - 69: OOooOOo
  if ( OO0Oo00oo != None ) : OO0Oo00oo . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 9 - 9: i11iIiiIii * Oo0Ooo
  if 33 - 33: oO0o / ooOoO0o
 def rtrs_in_rloc_set ( self ) :
  for OO0Oo00oo in self . rloc_set :
   if ( OO0Oo00oo . is_rtr ( ) ) : return ( True )
   if 92 - 92: O0 . Oo0Ooo - Ii1I * I1IiiI * Oo0Ooo * iII111i
  return ( False )
  if 78 - 78: Ii1I * iIii1I11I1II1 - Ii1I - I1ii11iIi11i * I1ii11iIi11i
  if 44 - 44: o0oOOo0O0Ooo
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 1 - 1: OoooooooOO / i11iIiiIii . o0oOOo0O0Ooo
  if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
 def find_rtr_rloc ( self ) :
  if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
  if 17 - 17: i1IIi % OoO0O00 + i11iIiiIii % I1Ii111 * ooOoO0o . I1ii11iIi11i
  if 64 - 64: O0 - iII111i
  if 82 - 82: O0
  if 37 - 37: I1Ii111
  if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
  if 84 - 84: OOooOOo * ooOoO0o / O0
  for OO0Oo00oo in self . rloc_set :
   if ( OO0Oo00oo . is_rtr ( ) and OO0Oo00oo . up_state ( ) ) :
    if ( OO0Oo00oo . stats . packet_count <= 4 ) : return ( OO0Oo00oo )
    if 96 - 96: I11i . I11i % II111iiii
    if 14 - 14: iII111i / OoooooooOO
  return ( None )
  if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
  if 38 - 38: I1IiiI / II111iiii * OoOoOO00 / I1Ii111
  if 80 - 80: I1ii11iIi11i / ooOoO0o * ooOoO0o . Oo0Ooo
  if 44 - 44: Ii1I * i1IIi % OoOoOO00 . OoOoOO00
class lisp_dynamic_eid ( object ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 16 - 16: Oo0Ooo / i1IIi / iIii1I11I1II1 / iIii1I11I1II1 % o0oOOo0O0Ooo / I1ii11iIi11i
  if 11 - 11: I1IiiI
 def get_timeout ( self , interface ) :
  try :
   I11iOOOo0oo00oOoo = lisp_myinterfaces [ interface ]
   self . timeout = I11iOOOo0oo00oOoo . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 64 - 64: IiII . iII111i + Ii1I % i11iIiiIii + iIii1I11I1II1 % oO0o
   if 36 - 36: II111iiii
   if 31 - 31: o0oOOo0O0Ooo
   if 24 - 24: I1Ii111 % OOooOOo * i1IIi - iIii1I11I1II1
class lisp_group_mapping ( object ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 61 - 61: o0oOOo0O0Ooo + Ii1I
  if 16 - 16: I11i - I11i + oO0o + iII111i . OoO0O00
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 96 - 96: iIii1I11I1II1 + iII111i + I1Ii111 % I1IiiI * OOooOOo
  if 46 - 46: I1ii11iIi11i % Oo0Ooo * OOooOOo
  if 64 - 64: I1ii11iIi11i
  if 17 - 17: II111iiii + Ii1I - o0oOOo0O0Ooo * II111iiii / Oo0Ooo / II111iiii
  if 82 - 82: i11iIiiIii * OoOoOO00 . i1IIi + IiII * ooOoO0o
  if 75 - 75: iIii1I11I1II1 / IiII / II111iiii . I11i
  if 23 - 23: OOooOOo . ooOoO0o - iII111i % Ii1I . I1ii11iIi11i + IiII
  if 81 - 81: I11i
  if 5 - 5: OoooooooOO
  if 5 - 5: iII111i + oO0o % O0 . OoooooooOO + i1IIi
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 oOO0Oooo = group_mapping . group_prefix
 i1I1IIIiII = lisp_address ( LISP_AFI_NONE , group_str , 0 , oOO0Oooo . instance_id )
 if ( i1I1IIIiII . afi != oOO0Oooo . afi ) : return ( - 1 )
 if 39 - 39: o0oOOo0O0Ooo
 if ( i1I1IIIiII . is_more_specific ( oOO0Oooo ) ) : return ( oOO0Oooo . mask_len )
 return ( - 1 )
 if 29 - 29: Oo0Ooo . Oo0Ooo * OoO0O00 % Ii1I - ooOoO0o
 if 67 - 67: I1IiiI % O0 + I1IiiI * I1Ii111 * OoOoOO00 * II111iiii
 if 79 - 79: I1IiiI
 if 37 - 37: I1Ii111 + Ii1I
 if 50 - 50: i11iIiiIii
 if 57 - 57: O0 * i1IIi - I1IiiI
 if 48 - 48: IiII / iIii1I11I1II1
def lisp_lookup_group ( group ) :
 iiiiiI11iiiI = None
 for iIi1i in list ( lisp_group_mapping_list . values ( ) ) :
  iII1IiI1I11i = lisp_is_group_more_specific ( group , iIi1i )
  if ( iII1IiI1I11i == - 1 ) : continue
  if ( iiiiiI11iiiI == None or iII1IiI1I11i > iiiiiI11iiiI . group_prefix . mask_len ) : iiiiiI11iiiI = iIi1i
  if 5 - 5: OoOoOO00 . iIii1I11I1II1 + iII111i
 return ( iiiiiI11iiiI )
 if 63 - 63: i1IIi
 if 24 - 24: i11iIiiIii % iII111i . oO0o
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 44 - 44: II111iiii - OoO0O00 + i11iIiiIii
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
  if 34 - 34: I1ii11iIi11i % ooOoO0o / II111iiii * O0 % OOooOOo
  if 9 - 9: I1ii11iIi11i / I1ii11iIi11i - OOooOOo . iIii1I11I1II1
  if 33 - 33: I1IiiI + oO0o % I1IiiI / iII111i - ooOoO0o - i11iIiiIii
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
  if 39 - 39: i11iIiiIii / oO0o
  if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 87 - 87: I1IiiI / Ii1I
  if 54 - 54: OoooooooOO / Ii1I
 def print_flags ( self , html ) :
  if ( html == False ) :
   i11IiIIi11I = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # Oo0Ooo / o0oOOo0O0Ooo
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   II1o0o00O = self . print_flags ( False )
   II1o0o00O = II1o0o00O . split ( "-" )
   i11IiIIi11I = ""
   for I111I in II1o0o00O :
    iIIIIiI1iiI11 = lisp_site_flags [ I111I . upper ( ) ]
    iIIIIiI1iiI11 = iIIIIiI1iiI11 . format ( "" if I111I . isupper ( ) else "not " )
    i11IiIIi11I += lisp_span ( I111I , iIIIIiI1iiI11 )
    if ( I111I . lower ( ) != "n" ) : i11IiIIi11I += "-"
    if 3 - 3: I11i
    if 55 - 55: OoO0O00 . i11iIiiIii . o0oOOo0O0Ooo % iIii1I11I1II1 . I1ii11iIi11i * I11i
  return ( i11IiIIi11I )
  if 7 - 7: OoOoOO00 * iII111i - i11iIiiIii
  if 79 - 79: OOooOOo
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 2 - 2: I11i % I1Ii111 - OoO0O00 % OoO0O00 % OOooOOo - OoO0O00
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 3 - 3: iIii1I11I1II1 + iIii1I11I1II1 + OoO0O00
  if 59 - 59: iII111i
 def build_sort_key ( self ) :
  IIIi111i111I = lisp_cache ( )
  I1iIIIiI1iI11 , oO0oOo = IIIi111i111I . build_key ( self . eid )
  iIiIII1 = ""
  if ( self . group . is_null ( ) == False ) :
   OoO0o0 , iIiIII1 = IIIi111i111I . build_key ( self . group )
   iIiIII1 = "-" + iIiIII1 [ 0 : 12 ] + "-" + str ( OoO0o0 ) + "-" + iIiIII1 [ 12 : : ]
   if 54 - 54: Oo0Ooo / OOooOOo * iII111i * I11i
  oO0oOo = oO0oOo [ 0 : 12 ] + "-" + str ( I1iIIIiI1iI11 ) + "-" + oO0oOo [ 12 : : ] + iIiIII1
  del ( IIIi111i111I )
  return ( oO0oOo )
  if 65 - 65: iII111i + OoO0O00 - iIii1I11I1II1 / OoooooooOO . ooOoO0o . o0oOOo0O0Ooo
  if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
 def merge_in_site_eid ( self , child ) :
  o0oooO0oO0o = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   o0oooO0oO0o = self . merge_rles_in_site_eid ( )
   if 96 - 96: I1IiiI - I1Ii111 . ooOoO0o / I1IiiI
   if 19 - 19: IiII . I1IiiI
   if 82 - 82: I11i + II111iiii % oO0o - I1ii11iIi11i
   if 54 - 54: i1IIi - I11i % Oo0Ooo / i11iIiiIii
   if 83 - 83: I1IiiI * OoooooooOO % I1IiiI - oO0o
   if 93 - 93: I1ii11iIi11i - OOooOOo - II111iiii * OoO0O00 . O0 - ooOoO0o
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 53 - 53: OoO0O00 / i11iIiiIii . OoooooooOO
  return ( o0oooO0oO0o )
  if 84 - 84: I1ii11iIi11i
  if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
 def copy_rloc_records ( self ) :
  Ii1iiI1I = [ ]
  for i1iiI1i1 in self . registered_rlocs :
   Ii1iiI1I . append ( copy . deepcopy ( i1iiI1i1 ) )
   if 37 - 37: OoOoOO00 % o0oOOo0O0Ooo . oO0o % i11iIiiIii
  return ( Ii1iiI1I )
  if 42 - 42: OOooOOo - IiII + ooOoO0o / O0 * OOooOOo . OoOoOO00
  if 42 - 42: OoO0O00 % oO0o / I1ii11iIi11i
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for Ooo000oOOooO00 in list ( self . individual_registrations . values ( ) ) :
   if ( self . site_id != Ooo000oOOooO00 . site_id ) : continue
   if ( Ooo000oOOooO00 . registered == False ) : continue
   self . registered_rlocs += Ooo000oOOooO00 . copy_rloc_records ( )
   if 34 - 34: OOooOOo % OoO0O00 - o0oOOo0O0Ooo * iIii1I11I1II1 - I11i / OoooooooOO
   if 87 - 87: I1ii11iIi11i - I1Ii111 / OOooOOo * II111iiii
   if 15 - 15: Ii1I / OoOoOO00 - OoO0O00 - iIii1I11I1II1 + OoOoOO00 - I11i
   if 10 - 10: I1ii11iIi11i
   if 6 - 6: OoO0O00 + OoO0O00 * OOooOOo / IiII % ooOoO0o - I1IiiI
   if 17 - 17: II111iiii
   if 66 - 66: O0 % OoOoOO00 + IiII % I1Ii111
   if 94 - 94: OoOoOO00 / OoooooooOO % Ii1I * i11iIiiIii
  Ii1iiI1I = [ ]
  for i1iiI1i1 in self . registered_rlocs :
   if ( i1iiI1i1 . rloc . is_null ( ) or len ( Ii1iiI1I ) == 0 ) :
    Ii1iiI1I . append ( i1iiI1i1 )
    continue
    if 95 - 95: iIii1I11I1II1 % OOooOOo % O0
   for oOo0O00O0 in Ii1iiI1I :
    if ( oOo0O00O0 . rloc . is_null ( ) ) : continue
    if ( i1iiI1i1 . rloc . is_exact_match ( oOo0O00O0 . rloc ) ) :
     if ( i1iiI1i1 . rloc_name == oOo0O00O0 . rloc_name ) : break
     if 10 - 10: OoooooooOO . o0oOOo0O0Ooo / IiII + IiII . O0
     if 6 - 6: iII111i % o0oOOo0O0Ooo - oO0o - i1IIi * OOooOOo
   if ( oOo0O00O0 == Ii1iiI1I [ - 1 ] ) : Ii1iiI1I . append ( i1iiI1i1 )
   if 33 - 33: Oo0Ooo / I1Ii111
  self . registered_rlocs = Ii1iiI1I
  if 62 - 62: IiII % i11iIiiIii % OoooooooOO
  if 45 - 45: IiII + I1IiiI * I1Ii111
  if 82 - 82: OOooOOo / I11i % Ii1I * OoOoOO00
  if 88 - 88: o0oOOo0O0Ooo % OoO0O00
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 30 - 30: II111iiii / Oo0Ooo % Oo0Ooo + O0 / iIii1I11I1II1 . OoO0O00
  if 43 - 43: I1IiiI % OoOoOO00 * O0 + o0oOOo0O0Ooo
 def merge_rles_in_site_eid ( self ) :
  if 97 - 97: iIii1I11I1II1 + O0
  if 41 - 41: OoOoOO00 - II111iiii
  if 46 - 46: OOooOOo
  if 73 - 73: iII111i - IiII + II111iiii
  oOo00o00oo0 = { }
  for i1iiI1i1 in self . registered_rlocs :
   if ( i1iiI1i1 . rle == None ) : continue
   for I1I1Ii1I in i1iiI1i1 . rle . rle_nodes :
    if ( I1I1Ii1I . rloc . rloc_name == None ) : continue
    iI1ii11Ii = I1I1Ii1I . rloc . rloc . print_address_no_iid ( ) + I1I1Ii1I . rloc . rloc_name
    if 19 - 19: I1Ii111 % iIii1I11I1II1 % I11i * oO0o / I11i . I1IiiI
    oOo00o00oo0 [ iI1ii11Ii ] = I1I1Ii1I . rloc . rloc
    if 4 - 4: iII111i
   break
   if 68 - 68: OOooOOo . I1ii11iIi11i % I1ii11iIi11i . i11iIiiIii
   if 45 - 45: oO0o % I1ii11iIi11i * I1Ii111
   if 21 - 21: O0 + i11iIiiIii
   if 72 - 72: OoOoOO00 * OoooooooOO % O0 / I1ii11iIi11i % Ii1I - I11i
   if 65 - 65: iIii1I11I1II1 + II111iiii * OoO0O00 * i11iIiiIii / IiII
  self . merge_rlocs_in_site_eid ( )
  if 15 - 15: OoOoOO00 % O0 - OOooOOo - oO0o . iII111i . OoO0O00
  if 52 - 52: II111iiii * o0oOOo0O0Ooo
  if 95 - 95: I1Ii111 - OoooooooOO
  if 99 - 99: OoooooooOO % IiII . I11i + OoooooooOO
  if 57 - 57: Ii1I / I1IiiI * i1IIi
  if 21 - 21: I11i . O0 * OoooooooOO + ooOoO0o * oO0o % i11iIiiIii
  if 30 - 30: ooOoO0o * I1Ii111 + OoO0O00
  if 30 - 30: Ii1I / iII111i * Ii1I
  iI1IIi1Ii = [ ]
  for i1iiI1i1 in self . registered_rlocs :
   if ( self . registered_rlocs . index ( i1iiI1i1 ) == 0 ) :
    iI1IIi1Ii . append ( i1iiI1i1 )
    continue
    if 70 - 70: OoOoOO00
   if ( i1iiI1i1 . rle == None ) : iI1IIi1Ii . append ( i1iiI1i1 )
   if 11 - 11: OoOoOO00 * OoOoOO00 % I11i
  self . registered_rlocs = iI1IIi1Ii
  if 21 - 21: ooOoO0o . i11iIiiIii / IiII . i1IIi + OoooooooOO
  if 18 - 18: ooOoO0o - I11i - I1Ii111
  if 81 - 81: IiII - Ii1I % i1IIi
  if 48 - 48: Ii1I + I11i % iIii1I11I1II1 + ooOoO0o + ooOoO0o + OoO0O00
  if 7 - 7: O0 + II111iiii
  if 44 - 44: OOooOOo + i11iIiiIii - I1Ii111 + ooOoO0o
  if 92 - 92: O0 . iIii1I11I1II1 % iIii1I11I1II1 % OoO0O00 - i11iIiiIii - iII111i
  IiI = lisp_rle ( "" )
  oOoI1i = { }
  I11Io00oo0OO = None
  for Ooo000oOOooO00 in list ( self . individual_registrations . values ( ) ) :
   if ( Ooo000oOOooO00 . registered == False ) : continue
   iI1i1iii1 = Ooo000oOOooO00 . registered_rlocs [ 0 ] . rle
   if ( iI1i1iii1 == None ) : continue
   if 52 - 52: i11iIiiIii / oO0o / IiII
   I11Io00oo0OO = Ooo000oOOooO00 . registered_rlocs [ 0 ] . rloc_name
   if ( I11Io00oo0OO == None ) : I11Io00oo0OO = ""
   for o0OOo00O00oOO in iI1i1iii1 . rle_nodes :
    iI1ii11Ii = o0OOo00O00oOO . rloc . rloc . print_address_no_iid ( ) + I11Io00oo0OO
    if ( iI1ii11Ii in oOoI1i ) : break
    if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
    I1I1Ii1I = lisp_rle_node ( )
    I1I1Ii1I . rloc . rloc . copy_address ( o0OOo00O00oOO . rloc . rloc )
    I1I1Ii1I . level = o0OOo00O00oOO . level
    I1I1Ii1I . rloc . rloc_name = I11Io00oo0OO
    IiI . rle_nodes . append ( I1I1Ii1I )
    oOoI1i [ iI1ii11Ii ] = o0OOo00O00oOO . rloc . rloc
    if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
    if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
    if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
    if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
    if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
    if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
  if ( len ( IiI . rle_nodes ) == 0 ) : IiI = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = IiI
   if ( I11Io00oo0OO ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
   if 61 - 61: OOooOOo
   if 80 - 80: I1ii11iIi11i
   if 6 - 6: I1ii11iIi11i + OOooOOo % ooOoO0o
   if 65 - 65: iIii1I11I1II1 % i1IIi / I1IiiI / oO0o % ooOoO0o / I11i
  if ( list ( oOo00o00oo0 . keys ( ) ) == list ( oOoI1i . keys ( ) ) ) : return ( False )
  if 2 - 2: I1ii11iIi11i
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # I1Ii111 * O0 / o0oOOo0O0Ooo * iII111i * ooOoO0o - I11i
 list ( oOo00o00oo0 . keys ( ) ) , list ( oOoI1i . keys ( ) ) ) )
  if 53 - 53: iIii1I11I1II1 . OoOoOO00 % i11iIiiIii % I1IiiI / OoO0O00 % I1Ii111
  return ( True )
  if 11 - 11: I1IiiI + I11i . OoOoOO00 - II111iiii
  if 10 - 10: iII111i - IiII + OoOoOO00 + I1IiiI + Oo0Ooo
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   ii11i1Ii = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( ii11i1Ii == None ) :
    ii11i1Ii = lisp_site_eid ( self . site )
    ii11i1Ii . eid . copy_address ( self . group )
    ii11i1Ii . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , ii11i1Ii )
    if 25 - 25: I1IiiI / I1ii11iIi11i % iII111i / O0 % II111iiii
    if 20 - 20: O0 % I11i * iII111i
    if 6 - 6: OoooooooOO % ooOoO0o % OoO0O00 * IiII
    if 62 - 62: i1IIi . I11i / I11i
    if 90 - 90: O0 * OOooOOo / oO0o . Oo0Ooo * I11i
    ii11i1Ii . parent_for_more_specifics = self . parent_for_more_specifics
    if 93 - 93: oO0o / ooOoO0o - I1Ii111
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( ii11i1Ii . group )
   ii11i1Ii . add_source_entry ( self )
   if 70 - 70: OOooOOo / Ii1I - ooOoO0o + OoooooooOO / OoO0O00 - i11iIiiIii
   if 26 - 26: O0 + Oo0Ooo
   if 30 - 30: IiII
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   ii11i1Ii = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( ii11i1Ii == None ) : return
   if 6 - 6: O0
   Ooo000oOOooO00 = ii11i1Ii . lookup_source_cache ( self . eid , True )
   if ( Ooo000oOOooO00 == None ) : return
   if 92 - 92: I11i
   if ( ii11i1Ii . source_cache == None ) : return
   if 76 - 76: I11i / iIii1I11I1II1 - i11iIiiIii / O0 / O0
   ii11i1Ii . source_cache . delete_cache ( self . eid )
   if ( ii11i1Ii . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 19 - 19: Ii1I . I1IiiI - i1IIi * ooOoO0o . iIii1I11I1II1
    if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
    if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
    if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
  if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
  if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
  if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 83 - 83: OOooOOo . ooOoO0o / IiII
  if 80 - 80: I1Ii111 . I11i - I11i + I1ii11iIi11i
 def inherit_from_ams_parent ( self ) :
  IiI1IIi = self . parent_for_more_specifics
  if ( IiI1IIi == None ) : return
  self . force_proxy_reply = IiI1IIi . force_proxy_reply
  self . force_nat_proxy_reply = IiI1IIi . force_nat_proxy_reply
  self . force_ttl = IiI1IIi . force_ttl
  self . pitr_proxy_reply_drop = IiI1IIi . pitr_proxy_reply_drop
  self . proxy_reply_action = IiI1IIi . proxy_reply_action
  self . echo_nonce_capable = IiI1IIi . echo_nonce_capable
  self . policy = IiI1IIi . policy
  self . require_signature = IiI1IIi . require_signature
  self . encrypt_json = IiI1IIi . encrypt_json
  if 42 - 42: I11i / IiII % O0 - Oo0Ooo
  if 33 - 33: I1Ii111
 def rtrs_in_rloc_set ( self ) :
  for i1iiI1i1 in self . registered_rlocs :
   if ( i1iiI1i1 . is_rtr ( ) ) : return ( True )
   if 1 - 1: IiII - iIii1I11I1II1 % OoooooooOO
  return ( False )
  if 1 - 1: o0oOOo0O0Ooo - i11iIiiIii + I11i
  if 47 - 47: O0 + IiII + ooOoO0o + OOooOOo / OoOoOO00
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for i1iiI1i1 in self . registered_rlocs :
   if ( i1iiI1i1 . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( i1iiI1i1 . is_rtr ( ) ) : return ( True )
   if 31 - 31: oO0o * iII111i % OoOoOO00
  return ( False )
  if 80 - 80: ooOoO0o % I1ii11iIi11i % I11i . I1Ii111
  if 3 - 3: ooOoO0o - Oo0Ooo
 def is_rloc_in_rloc_set ( self , rloc ) :
  for i1iiI1i1 in self . registered_rlocs :
   if ( i1iiI1i1 . rle ) :
    for IiI in i1iiI1i1 . rle . rle_nodes :
     if ( IiI . rloc . rloc . is_exact_match ( rloc ) ) : return ( True )
     if 2 - 2: iII111i . iII111i
     if 77 - 77: OOooOOo
   if ( i1iiI1i1 . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 74 - 74: O0
  return ( False )
  if 86 - 86: OoOoOO00
  if 4 - 4: OoooooooOO * OoO0O00
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
  for i1iiI1i1 in prev_rloc_set :
   I1iII1 = i1iiI1i1 . rloc
   if ( self . is_rloc_in_rloc_set ( I1iII1 ) == False ) : return ( False )
   if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
  return ( True )
  if 29 - 29: iIii1I11I1II1 + OoO0O00 * II111iiii * Ii1I * iII111i . O0
  if 6 - 6: I1IiiI - OoOoOO00
  if 63 - 63: OOooOOo - oO0o * I1IiiI
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
   if 60 - 60: II111iiii - Oo0Ooo
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  self . translated_port = 0
  if 43 - 43: I1IiiI - IiII - OOooOOo
  if 19 - 19: I1Ii111 / I1Ii111 - i1IIi
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 99 - 99: O0
  try :
   OooO0O0Ooo = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   iiI1I = OooO0O0Ooo [ 2 ]
  except :
   return
   if 85 - 85: ooOoO0o / I1IiiI
   if 7 - 7: Oo0Ooo - iIii1I11I1II1 / I1ii11iIi11i * I1IiiI + Ii1I
   if 99 - 99: i11iIiiIii - I1ii11iIi11i
   if 64 - 64: IiII . OoOoOO00 . Oo0Ooo . I1Ii111 / I11i / Ii1I
   if 95 - 95: iIii1I11I1II1 . Ii1I % oO0o - I11i % IiII
   if 42 - 42: OoOoOO00 + oO0o * i1IIi + i11iIiiIii
  if ( len ( iiI1I ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 25 - 25: Ii1I - Ii1I - I1ii11iIi11i / i1IIi . OoOoOO00 % Oo0Ooo
   if 76 - 76: I1Ii111 / OoOoOO00
  iI1ii11Ii = iiI1I [ self . a_record_index ]
  if ( iI1ii11Ii != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( iI1ii11Ii )
   self . insert_mr ( )
   if 61 - 61: Oo0Ooo . i1IIi
   if 78 - 78: i11iIiiIii
   if 20 - 20: Ii1I
   if 100 - 100: OoooooooOO . I1Ii111
   if 32 - 32: iIii1I11I1II1 . iIii1I11I1II1 % II111iiii / Oo0Ooo . iIii1I11I1II1 . O0
   if 63 - 63: I1IiiI . iIii1I11I1II1 . Oo0Ooo % OOooOOo - iII111i + ooOoO0o
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 64 - 64: o0oOOo0O0Ooo / Ii1I % I1Ii111 % iII111i + OOooOOo * IiII
  for iI1ii11Ii in iiI1I [ 1 : : ] :
   I1II1I1I = lisp_address ( LISP_AFI_NONE , iI1ii11Ii , 0 , 0 )
   o0O0 = lisp_get_map_resolver ( I1II1I1I , None )
   if ( o0O0 != None and o0O0 . a_record_index == iiI1I . index ( iI1ii11Ii ) ) :
    continue
    if 87 - 87: I1ii11iIi11i . i1IIi - I11i + OoOoOO00 . O0
   o0O0 = lisp_mr ( iI1ii11Ii , None , None )
   o0O0 . a_record_index = iiI1I . index ( iI1ii11Ii )
   o0O0 . dns_name = self . dns_name
   o0O0 . last_dns_resolve = lisp_get_timestamp ( )
   if 37 - 37: IiII
   if 65 - 65: ooOoO0o * Ii1I / I1IiiI . i1IIi % ooOoO0o . OoooooooOO
   if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
   if 88 - 88: i1IIi - OoOoOO00
   if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
  i1iIi = [ ]
  for o0O0 in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( self . dns_name != o0O0 . dns_name ) : continue
   I1II1I1I = o0O0 . map_resolver . print_address_no_iid ( )
   if ( I1II1I1I in iiI1I ) : continue
   i1iIi . append ( o0O0 )
   if 68 - 68: i11iIiiIii
  for o0O0 in i1iIi : o0O0 . delete_mr ( )
  if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
  if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 def insert_mr ( self ) :
  oO0oOo = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ oO0oOo ] = self
  if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
  if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
 def delete_mr ( self ) :
  oO0oOo = self . mr_name + self . map_resolver . print_address ( )
  if ( oO0oOo not in lisp_map_resolvers_list ) : return
  lisp_map_resolvers_list . pop ( oO0oOo )
  if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
  if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
  if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
class lisp_ddt_root ( object ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
  if 38 - 38: IiII
  if 78 - 78: Oo0Ooo * I1ii11iIi11i % OOooOOo / Oo0Ooo + I1ii11iIi11i * IiII
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
  if 2 - 2: Oo0Ooo - OoOoOO00
  if 22 - 22: OoO0O00 - oO0o - O0
 def print_referral ( self , eid_indent , referral_indent ) :
  iii1iI = lisp_print_elapsed ( self . uptime )
  i1Iiiii1iI1Ii = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , iii1iI ,
  # iIii1I11I1II1
 i1Iiiii1iI1Ii , len ( self . referral_set ) ) )
  if 32 - 32: IiII - OoOoOO00
  for oooOOo0o00 in list ( self . referral_set . values ( ) ) :
   oooOOo0o00 . print_ref_node ( referral_indent )
   if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
   if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
   if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 16 - 16: Oo0Ooo
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
  if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
  if 96 - 96: I1IiiI . oO0o % O0
 def print_ttl ( self ) :
  o0ooo000o00O = self . referral_ttl
  if ( o0ooo000o00O < 60 ) : return ( str ( o0ooo000o00O ) + " secs" )
  if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
  if ( ( o0ooo000o00O % 60 ) == 0 ) :
   o0ooo000o00O = str ( old_div ( o0ooo000o00O , 60 ) ) + " mins"
  else :
   o0ooo000o00O = str ( o0ooo000o00O ) + " secs"
   if 87 - 87: OoooooooOO
  return ( o0ooo000o00O )
  if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
  if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # i11iIiiIii - o0oOOo0O0Ooo
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 62 - 62: iIii1I11I1II1 / oO0o - OoO0O00 * I1Ii111
  if 1 - 1: I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * i11iIiiIii - OOooOOo % oO0o
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . add_cache ( self . eid , self )
  else :
   I11i1iI = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( I11i1iI == None ) :
    I11i1iI = lisp_referral ( )
    I11i1iI . eid . copy_address ( self . group )
    I11i1iI . group . copy_address ( self . group )
    lisp_referral_cache . add_cache ( self . group , I11i1iI )
    if 35 - 35: I1ii11iIi11i / II111iiii * OoO0O00 - i11iIiiIii / iII111i / o0oOOo0O0Ooo
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( I11i1iI . group )
   I11i1iI . add_source_entry ( self )
   if 39 - 39: II111iiii * iII111i
   if 7 - 7: OOooOOo + OoOoOO00 . II111iiii * OoO0O00 . I1IiiI * o0oOOo0O0Ooo
   if 62 - 62: I1ii11iIi11i / iIii1I11I1II1 + oO0o . II111iiii
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   I11i1iI = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( I11i1iI == None ) : return
   if 65 - 65: Oo0Ooo % i1IIi * o0oOOo0O0Ooo * IiII
   oOIIIiiIiI = I11i1iI . lookup_source_cache ( self . eid , True )
   if ( oOIIIiiIiI == None ) : return
   if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
   I11i1iI . source_cache . delete_cache ( self . eid )
   if ( I11i1iI . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
    if 36 - 36: O0
    if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
    if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 21 - 21: i1IIi * iII111i + OoO0O00
  if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 85 - 85: OoooooooOO
  if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
  if 8 - 8: I1Ii111
class lisp_referral_node ( object ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
  if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
 def print_ref_node ( self , indent ) :
  iIiIIIIIii = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , iIiIIIIIii ,
  # OoOoOO00
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 50 - 50: Oo0Ooo
  if 80 - 80: OoOoOO00 * OoO0O00 + i11iIiiIii + O0 + II111iiii
  if 13 - 13: OOooOOo / O0
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
   if 19 - 19: iIii1I11I1II1 + IiII * I11i * II111iiii + o0oOOo0O0Ooo + i11iIiiIii
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
   if 69 - 69: iIii1I11I1II1 . II111iiii
   if 36 - 36: I1IiiI * i1IIi + OoOoOO00
   if 63 - 63: OoOoOO00 - iII111i
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
  try :
   OooO0O0Ooo = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   iiI1I = OooO0O0Ooo [ 2 ]
  except :
   return
   if 82 - 82: iIii1I11I1II1 / OOooOOo
   if 7 - 7: OoooooooOO
   if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
   if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
   if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
   if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
  if ( len ( iiI1I ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 52 - 52: OoooooooOO - OoO0O00
   if 24 - 24: iII111i / Oo0Ooo - I1ii11iIi11i + o0oOOo0O0Ooo
  iI1ii11Ii = iiI1I [ self . a_record_index ]
  if ( iI1ii11Ii != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( iI1ii11Ii )
   self . insert_ms ( )
   if 44 - 44: OoOoOO00 + I1IiiI . I1ii11iIi11i / i1IIi + II111iiii . Oo0Ooo
   if 39 - 39: o0oOOo0O0Ooo
   if 64 - 64: oO0o - i11iIiiIii
   if 62 - 62: OoooooooOO - OoooooooOO / OoO0O00 - II111iiii . iIii1I11I1II1
   if 2 - 2: O0 + o0oOOo0O0Ooo % OOooOOo . ooOoO0o % i1IIi
   if 21 - 21: OoOoOO00 / OoooooooOO + I1Ii111 - IiII
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 62 - 62: Oo0Ooo % iII111i + OoooooooOO - I1ii11iIi11i % iII111i % iIii1I11I1II1
  for iI1ii11Ii in iiI1I [ 1 : : ] :
   I1II1I1I = lisp_address ( LISP_AFI_NONE , iI1ii11Ii , 0 , 0 )
   oo0Oo0oo0o = lisp_get_map_server ( I1II1I1I )
   if ( oo0Oo0oo0o != None and oo0Oo0oo0o . a_record_index == iiI1I . index ( iI1ii11Ii ) ) :
    continue
    if 54 - 54: IiII + OoOoOO00 / II111iiii % i11iIiiIii . I1Ii111
   oo0Oo0oo0o = copy . deepcopy ( self )
   oo0Oo0oo0o . map_server . store_address ( iI1ii11Ii )
   oo0Oo0oo0o . a_record_index = iiI1I . index ( iI1ii11Ii )
   oo0Oo0oo0o . last_dns_resolve = lisp_get_timestamp ( )
   oo0Oo0oo0o . insert_ms ( )
   if 69 - 69: i1IIi + ooOoO0o + Ii1I
   if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
   if 95 - 95: ooOoO0o . Oo0Ooo % IiII + iII111i
   if 16 - 16: I11i * OoO0O00 % o0oOOo0O0Ooo - O0 % II111iiii - I1IiiI
   if 72 - 72: OoooooooOO * OoOoOO00 . OOooOOo + Ii1I . OOooOOo / II111iiii
  i1iIi = [ ]
  for oo0Oo0oo0o in list ( lisp_map_servers_list . values ( ) ) :
   if ( self . dns_name != oo0Oo0oo0o . dns_name ) : continue
   I1II1I1I = oo0Oo0oo0o . map_server . print_address_no_iid ( )
   if ( I1II1I1I in iiI1I ) : continue
   i1iIi . append ( oo0Oo0oo0o )
   if 8 - 8: i1IIi
  for oo0Oo0oo0o in i1iIi : oo0Oo0oo0o . delete_ms ( )
  if 1 - 1: OoOoOO00 . OoO0O00 . OoO0O00 * O0
  if 97 - 97: OoooooooOO % ooOoO0o . I1Ii111 / iII111i
 def insert_ms ( self ) :
  oO0oOo = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ oO0oOo ] = self
  if 59 - 59: II111iiii + O0 . I1ii11iIi11i . Oo0Ooo * OoO0O00
  if 35 - 35: oO0o / I1Ii111 * OOooOOo + OoooooooOO . IiII
 def delete_ms ( self ) :
  oO0oOo = self . ms_name + self . map_server . print_address ( )
  if ( oO0oOo not in lisp_map_servers_list ) : return
  lisp_map_servers_list . pop ( oO0oOo )
  if 1 - 1: I1IiiI + I1Ii111 / OOooOOo . Ii1I . oO0o / I1ii11iIi11i
  if 54 - 54: OOooOOo
  if 86 - 86: oO0o * Oo0Ooo / OOooOOo
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
  if 18 - 18: II111iiii - I1Ii111
  if 13 - 13: i11iIiiIii - O0 % OoOoOO00 + OOooOOo * ooOoO0o
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 55 - 55: i1IIi - OOooOOo / I11i * Ii1I
  if 20 - 20: OoOoOO00 * iIii1I11I1II1 % O0 - i1IIi
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 51 - 51: I1ii11iIi11i * Ii1I - oO0o / O0 * OoooooooOO
  if 12 - 12: i1IIi / iIii1I11I1II1 / O0 * OoO0O00
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 15 - 15: i11iIiiIii / IiII + Ii1I % OOooOOo % I1ii11iIi11i * oO0o
  if 24 - 24: OOooOOo / OOooOOo + I11i / iII111i . oO0o - iII111i
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 59 - 59: I1ii11iIi11i % II111iiii - i11iIiiIii - I1Ii111
  if 34 - 34: II111iiii + iII111i / IiII
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 47 - 47: OoO0O00
  if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
 def set_socket ( self , device ) :
  OOo0oOO0o0oo0 = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  OOo0oOO0o0oo0 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   OOo0oOO0o0oo0 . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   OOo0oOO0o0oo0 . close ( )
   OOo0oOO0o0oo0 = None
   if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
  self . raw_socket = OOo0oOO0o0oo0
  if 78 - 78: i11iIiiIii / OoO0O00 / i1IIi . i11iIiiIii
  if 100 - 100: II111iiii . IiII . I11i
 def set_bridge_socket ( self , device ) :
  OOo0oOO0o0oo0 = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   OOo0oOO0o0oo0 = OOo0oOO0o0oo0 . bind ( ( device , 0 ) )
   self . bridge_socket = OOo0oOO0o0oo0
  except :
   return
   if 60 - 60: OoOoOO00 % OOooOOo * i1IIi
   if 3 - 3: OoooooooOO
   if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
   if 23 - 23: oO0o - O0 * IiII + i11iIiiIii * Ii1I
class lisp_datetime ( object ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 8 - 8: ooOoO0o / II111iiii . I1ii11iIi11i * ooOoO0o % oO0o
  if 36 - 36: I1ii11iIi11i % OOooOOo - ooOoO0o - I11i + I1IiiI
 def valid_datetime ( self ) :
  iI1I1i1ii1I1 = self . datetime_name
  if ( iI1I1i1ii1I1 . find ( ":" ) == - 1 ) : return ( False )
  if ( iI1I1i1ii1I1 . find ( "-" ) == - 1 ) : return ( False )
  i1IiI1 , I111Ii1Ii11I , o0OO0 , time = iI1I1i1ii1I1 [ 0 : 4 ] , iI1I1i1ii1I1 [ 5 : 7 ] , iI1I1i1ii1I1 [ 8 : 10 ] , iI1I1i1ii1I1 [ 11 : : ]
  if 17 - 17: OoO0O00
  if ( ( i1IiI1 + I111Ii1Ii11I + o0OO0 ) . isdigit ( ) == False ) : return ( False )
  if ( I111Ii1Ii11I < "01" and I111Ii1Ii11I > "12" ) : return ( False )
  if ( o0OO0 < "01" and o0OO0 > "31" ) : return ( False )
  if 91 - 91: iIii1I11I1II1 * iIii1I11I1II1 * OoooooooOO - iII111i * iIii1I11I1II1 + OoOoOO00
  IIiiiiii1i11 , IiiiiII1iI , oOiI = time . split ( ":" )
  if 83 - 83: OOooOOo
  if ( ( IIiiiiii1i11 + IiiiiII1iI + oOiI ) . isdigit ( ) == False ) : return ( False )
  if ( IIiiiiii1i11 < "00" and IIiiiiii1i11 > "23" ) : return ( False )
  if ( IiiiiII1iI < "00" and IiiiiII1iI > "59" ) : return ( False )
  if ( oOiI < "00" and oOiI > "59" ) : return ( False )
  return ( True )
  if 87 - 87: o0oOOo0O0Ooo
  if 41 - 41: OoooooooOO . iII111i / oO0o
 def parse_datetime ( self ) :
  I1iI1i1 = self . datetime_name
  I1iI1i1 = I1iI1i1 . replace ( "-" , "" )
  I1iI1i1 = I1iI1i1 . replace ( ":" , "" )
  self . datetime = int ( I1iI1i1 )
  if 5 - 5: OoO0O00
  if 14 - 14: i1IIi - iII111i % o0oOOo0O0Ooo
 def now ( self ) :
  iIiIIIIIii = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  iIiIIIIIii = lisp_datetime ( iIiIIIIIii )
  return ( iIiIIIIIii )
  if 90 - 90: IiII % O0 / OoooooooOO - II111iiii - Oo0Ooo
  if 22 - 22: I1ii11iIi11i
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 74 - 74: OoOoOO00 . I1Ii111 - Oo0Ooo / I11i . OoOoOO00 * o0oOOo0O0Ooo
  if 43 - 43: I11i
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 18 - 18: OoooooooOO + OoooooooOO - i11iIiiIii / II111iiii
  if 41 - 41: Oo0Ooo . OoOoOO00 . iII111i / i11iIiiIii
 def past ( self ) :
  return ( self . future ( ) == False )
  if 65 - 65: iII111i * o0oOOo0O0Ooo * OoooooooOO + I11i + oO0o % OoO0O00
  if 1 - 1: I1ii11iIi11i . ooOoO0o
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 54 - 54: OoOoOO00 % I1IiiI . ooOoO0o + IiII / i11iIiiIii / o0oOOo0O0Ooo
  if 51 - 51: OoOoOO00 / Ii1I . I1IiiI / Ii1I . II111iiii - iIii1I11I1II1
 def this_year ( self ) :
  oOo0O0ooo0 = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  iIiIIIIIii = str ( self . datetime ) [ 0 : 4 ]
  return ( iIiIIIIIii == oOo0O0ooo0 )
  if 24 - 24: ooOoO0o * OoOoOO00 * iIii1I11I1II1 * iII111i + I1IiiI - II111iiii
  if 31 - 31: oO0o / I1ii11iIi11i
 def this_month ( self ) :
  oOo0O0ooo0 = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  iIiIIIIIii = str ( self . datetime ) [ 0 : 6 ]
  return ( iIiIIIIIii == oOo0O0ooo0 )
  if 96 - 96: i1IIi + i1IIi * I1Ii111 . II111iiii % OoooooooOO
  if 58 - 58: IiII
 def today ( self ) :
  oOo0O0ooo0 = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  iIiIIIIIii = str ( self . datetime ) [ 0 : 8 ]
  return ( iIiIIIIIii == oOo0O0ooo0 )
  if 64 - 64: iIii1I11I1II1 / OoOoOO00
  if 14 - 14: Ii1I / OoooooooOO . i1IIi % IiII % i11iIiiIii
  if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
  if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
  if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
  if 19 - 19: o0oOOo0O0Ooo
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
  if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
  if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
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
  if 71 - 71: OoO0O00 - I11i
  if 96 - 96: I1Ii111 / Ii1I
 def match_policy_map_request ( self , mr , srloc ) :
  for I1Iii1II in self . match_clauses :
   ooo0OO0OOooO0 = I1Iii1II . source_eid
   IiI111ii = mr . source_eid
   if ( ooo0OO0OOooO0 and IiI111ii and IiI111ii . is_more_specific ( ooo0OO0OOooO0 ) == False ) : continue
   if 65 - 65: I1ii11iIi11i * O0 . IiII
   ooo0OO0OOooO0 = I1Iii1II . dest_eid
   IiI111ii = mr . target_eid
   if ( ooo0OO0OOooO0 and IiI111ii and IiI111ii . is_more_specific ( ooo0OO0OOooO0 ) == False ) : continue
   if 11 - 11: I11i / Ii1I % oO0o
   ooo0OO0OOooO0 = I1Iii1II . source_rloc
   IiI111ii = srloc
   if ( ooo0OO0OOooO0 and IiI111ii and IiI111ii . is_more_specific ( ooo0OO0OOooO0 ) == False ) : continue
   OoOoo00Oo0OoO = I1Iii1II . datetime_lower
   i1o00O = I1Iii1II . datetime_upper
   if ( OoOoo00Oo0OoO and i1o00O and OoOoo00Oo0OoO . now_in_range ( i1o00O ) == False ) : continue
   return ( True )
   if 29 - 29: Oo0Ooo
  return ( False )
  if 61 - 61: i1IIi - i1IIi - I11i
  if 68 - 68: ooOoO0o - I1ii11iIi11i - OoO0O00 % O0 / I1ii11iIi11i - iIii1I11I1II1
 def set_policy_map_reply ( self ) :
  ooii11iI = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( ooii11iI ) : return ( None )
  if 3 - 3: OOooOOo - OoOoOO00
  OO0Oo00oo = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   OO0Oo00oo . rloc . copy_address ( self . set_rloc_address )
   iI1ii11Ii = OO0Oo00oo . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( iI1ii11Ii ) )
   if 49 - 49: IiII / i11iIiiIii
  if ( self . set_rloc_record_name ) :
   OO0Oo00oo . rloc_name = self . set_rloc_record_name
   OOO0 = blue ( OO0Oo00oo . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( OOO0 ) )
   if 84 - 84: iIii1I11I1II1 / i1IIi + OoOoOO00
  if ( self . set_geo_name ) :
   OO0Oo00oo . geo_name = self . set_geo_name
   OOO0 = OO0Oo00oo . geo_name
   i1I11i1i11 = "" if ( OOO0 in lisp_geo_list ) else "(not configured)"
   if 61 - 61: o0oOOo0O0Ooo
   lprint ( "Policy set-geo-name '{}' {}" . format ( OOO0 , i1I11i1i11 ) )
   if 37 - 37: ooOoO0o + I1Ii111 - Oo0Ooo + oO0o
  if ( self . set_elp_name ) :
   OO0Oo00oo . elp_name = self . set_elp_name
   OOO0 = OO0Oo00oo . elp_name
   i1I11i1i11 = "" if ( OOO0 in lisp_elp_list ) else "(not configured)"
   if 93 - 93: OOooOOo / OoOoOO00
   lprint ( "Policy set-elp-name '{}' {}" . format ( OOO0 , i1I11i1i11 ) )
   if 19 - 19: I1ii11iIi11i % I1ii11iIi11i
  if ( self . set_rle_name ) :
   OO0Oo00oo . rle_name = self . set_rle_name
   OOO0 = OO0Oo00oo . rle_name
   i1I11i1i11 = "" if ( OOO0 in lisp_rle_list ) else "(not configured)"
   if 95 - 95: Oo0Ooo / Ii1I
   lprint ( "Policy set-rle-name '{}' {}" . format ( OOO0 , i1I11i1i11 ) )
   if 78 - 78: I1IiiI * i1IIi / II111iiii
  if ( self . set_json_name ) :
   OO0Oo00oo . json_name = self . set_json_name
   OOO0 = OO0Oo00oo . json_name
   i1I11i1i11 = "" if ( OOO0 in lisp_json_list ) else "(not configured)"
   if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
   lprint ( "Policy set-json-name '{}' {}" . format ( OOO0 , i1I11i1i11 ) )
   if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
  return ( OO0Oo00oo )
  if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
  if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 48 - 48: O0
  if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
  if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
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
  if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
  if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
 def add ( self , eid_prefix ) :
  self . eid_prefix = eid_prefix
  o0ooo000o00O = self . ttl
  O0o00o0Oo = eid_prefix . print_prefix ( )
  if ( O0o00o0Oo not in lisp_pubsub_cache ) :
   lisp_pubsub_cache [ O0o00o0Oo ] = { }
   if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
  iiI11i1i1 = lisp_pubsub_cache [ O0o00o0Oo ]
  if 97 - 97: OOooOOo . OoooooooOO . OOooOOo . i11iIiiIii
  oO0OO0o = "Add"
  if ( self . xtr_id in iiI11i1i1 ) :
   oO0OO0o = "Replace"
   del ( iiI11i1i1 [ self . xtr_id ] )
   if 63 - 63: OOooOOo + I1Ii111 . i1IIi
  iiI11i1i1 [ self . xtr_id ] = self
  if 68 - 68: I1Ii111
  O0o00o0Oo = green ( O0o00o0Oo , False )
  oo000oo0oOo0 = red ( self . itr . print_address_no_iid ( ) , False )
  Ooo0 = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( oO0OO0o , O0o00o0Oo ,
 oo000oo0oOo0 , Ooo0 , o0ooo000o00O ) )
  if 23 - 23: OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
  if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
 def delete ( self , eid_prefix ) :
  O0o00o0Oo = eid_prefix . print_prefix ( )
  oo000oo0oOo0 = red ( self . itr . print_address_no_iid ( ) , False )
  Ooo0 = "0x" + lisp_hex_string ( self . xtr_id )
  if ( O0o00o0Oo in lisp_pubsub_cache ) :
   iiI11i1i1 = lisp_pubsub_cache [ O0o00o0Oo ]
   if ( self . xtr_id in iiI11i1i1 ) :
    iiI11i1i1 . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( O0o00o0Oo ,
 oo000oo0oOo0 , Ooo0 ) )
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
    if 52 - 52: Oo0Ooo - I11i - IiII - OoOoOO00
class lisp_trace ( object ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 21 - 21: oO0o % o0oOOo0O0Ooo + I1Ii111 . OOooOOo / OOooOOo
  if 41 - 41: Oo0Ooo . ooOoO0o * oO0o
 def print_trace ( self ) :
  oOo0OOooo0o = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( oOo0OOooo0o ) )
  if 31 - 31: Oo0Ooo * IiII / IiII
  if 3 - 3: I1Ii111
 def encode ( self ) :
  IiiI11iIi = socket . htonl ( 0x90000000 )
  Oo00O0o0O = struct . pack ( "II" , IiiI11iIi , 0 )
  Oo00O0o0O += struct . pack ( "Q" , self . nonce )
  Oo00O0o0O += json . dumps ( self . packet_json )
  return ( Oo00O0o0O )
  if 65 - 65: iIii1I11I1II1 % Oo0Ooo % I11i / OoooooooOO
  if 82 - 82: o0oOOo0O0Ooo
 def decode ( self , packet ) :
  ii = "I"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( False )
  IiiI11iIi = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  IiiI11iIi = socket . ntohl ( IiiI11iIi )
  if ( ( IiiI11iIi & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 33 - 33: OoOoOO00 / i11iIiiIii - I1IiiI - OoooooooOO + i1IIi * I1Ii111
  if ( len ( packet ) < OOOO00oo00oo ) : return ( False )
  iI1ii11Ii = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  if 92 - 92: iII111i + OoO0O00
  iI1ii11Ii = socket . ntohl ( iI1ii11Ii )
  o00II11i1I1Ii = iI1ii11Ii >> 24
  iIiiii = ( iI1ii11Ii >> 16 ) & 0xff
  IIi1i1 = ( iI1ii11Ii >> 8 ) & 0xff
  o0O000Oooooo = iI1ii11Ii & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( o00II11i1I1Ii , iIiiii , IIi1i1 , o0O000Oooooo )
  self . local_port = str ( IiiI11iIi & 0xffff )
  if 100 - 100: O0 . iII111i / iIii1I11I1II1
  ii = "Q"
  OOOO00oo00oo = struct . calcsize ( ii )
  if ( len ( packet ) < OOOO00oo00oo ) : return ( False )
  self . nonce = struct . unpack ( ii , packet [ : OOOO00oo00oo ] ) [ 0 ]
  packet = packet [ OOOO00oo00oo : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 47 - 47: ooOoO0o + OoOoOO00
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
  return ( True )
  if 91 - 91: I11i
  if 54 - 54: I1ii11iIi11i / i1IIi
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 14 - 14: iIii1I11I1II1 * I11i . I11i * ooOoO0o * iII111i
  if 60 - 60: iIii1I11I1II1 + i1IIi + oO0o - iIii1I11I1II1 . i11iIiiIii * OoooooooOO
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  OO0Oo00oo , i11I1Ii1Iiii1 = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( OO0Oo00oo == None ) :
   OO0Oo00oo , i11I1Ii1Iiii1 = rts_rloc . split ( ":" )
   i11I1Ii1Iiii1 = int ( i11I1Ii1Iiii1 )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( OO0Oo00oo , i11I1Ii1Iiii1 ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( OO0Oo00oo ,
 i11I1Ii1Iiii1 ) )
   if 23 - 23: iII111i - IiII % i11iIiiIii
   if 81 - 81: OoooooooOO % OoOoOO00 / IiII / OoooooooOO + i1IIi - O0
  if ( lisp_socket == None ) :
   OOo0oOO0o0oo0 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   OOo0oOO0o0oo0 . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   OOo0oOO0o0oo0 . sendto ( packet , ( OO0Oo00oo , i11I1Ii1Iiii1 ) )
   OOo0oOO0o0oo0 . close ( )
  else :
   lisp_socket . sendto ( packet , ( OO0Oo00oo , i11I1Ii1Iiii1 ) )
   if 60 - 60: OOooOOo - I1Ii111 * Oo0Ooo
   if 9 - 9: OoooooooOO * OOooOOo % OoO0O00 - ooOoO0o + Ii1I
   if 39 - 39: iIii1I11I1II1 / i1IIi % I11i % I1ii11iIi11i * IiII
 def packet_length ( self ) :
  ii11 = 8 ; iiiii1 = 4 + 4 + 8
  return ( ii11 + iiiii1 + len ( json . dumps ( self . packet_json ) ) )
  if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
  if 83 - 83: OoooooooOO
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  oO0oOo = self . local_rloc + ":" + self . local_port
  oO00o = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ oO0oOo ] = oO00o
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( oO0oOo , oO00o ) )
  if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
  if 88 - 88: Oo0Ooo % I1Ii111 * O0 - i1IIi * OoO0O00
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  oO0oOo = local_rloc_and_port
  try : oO00o = lisp_rtr_nat_trace_cache [ oO0oOo ]
  except : oO00o = ( None , None )
  return ( oO00o )
  if 74 - 74: Oo0Ooo % iIii1I11I1II1 + OOooOOo
  if 50 - 50: OoO0O00 . OoooooooOO
  if 31 - 31: OoO0O00
  if 55 - 55: OoOoOO00 + I1Ii111 * o0oOOo0O0Ooo - I1ii11iIi11i + OoOoOO00
  if 6 - 6: II111iiii % iIii1I11I1II1 * I1Ii111
  if 2 - 2: IiII - I1Ii111 . iIii1I11I1II1 - Ii1I * I11i
  if 58 - 58: i1IIi % iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo + ooOoO0o
  if 23 - 23: Oo0Ooo % Oo0Ooo / IiII
  if 63 - 63: I11i % Oo0Ooo * I1Ii111 - Oo0Ooo % i11iIiiIii . II111iiii
  if 44 - 44: I11i . I1Ii111 . I1ii11iIi11i . oO0o
  if 1 - 1: I11i % II111iiii / OoO0O00 + OoO0O00
def lisp_get_map_server ( address ) :
 for oo0Oo0oo0o in list ( lisp_map_servers_list . values ( ) ) :
  if ( oo0Oo0oo0o . map_server . is_exact_match ( address ) ) : return ( oo0Oo0oo0o )
  if 46 - 46: Oo0Ooo * Ii1I / IiII % O0 * iII111i
 return ( None )
 if 74 - 74: OoooooooOO + Ii1I
 if 100 - 100: I1IiiI
 if 59 - 59: I1IiiI - OoOoOO00 * ooOoO0o / O0
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
def lisp_get_any_map_server ( ) :
 for oo0Oo0oo0o in list ( lisp_map_servers_list . values ( ) ) : return ( oo0Oo0oo0o )
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
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  iI1ii11Ii = address . print_address ( )
  o0O0 = None
  for oO0oOo in lisp_map_resolvers_list :
   if ( oO0oOo . find ( iI1ii11Ii ) == - 1 ) : continue
   o0O0 = lisp_map_resolvers_list [ oO0oOo ]
   if 69 - 69: Oo0Ooo
  return ( o0O0 )
  if 48 - 48: iII111i
  if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
  if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
  if 89 - 89: iII111i
  if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
  if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
  if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 if ( eid == "" ) :
  ii1IIii1i1IiI = ""
 elif ( eid == None ) :
  ii1IIii1i1IiI = "all"
 else :
  Iiii1II1 = lisp_db_for_lookups . lookup_cache ( eid , False )
  ii1IIii1i1IiI = "all" if Iiii1II1 == None else Iiii1II1 . use_mr_name
  if 40 - 40: Ii1I % OoO0O00
  if 89 - 89: Ii1I % OoooooooOO - OoOoOO00 - o0oOOo0O0Ooo
 iI1ii1III = None
 for o0O0 in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( ii1IIii1i1IiI == "" ) : return ( o0O0 )
  if ( o0O0 . mr_name != ii1IIii1i1IiI ) : continue
  if ( iI1ii1III == None or o0O0 . last_used < iI1ii1III . last_used ) : iI1ii1III = o0O0
  if 96 - 96: OOooOOo
 return ( iI1ii1III )
 if 82 - 82: iII111i - I1Ii111 - OoOoOO00
 if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
 if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
 if 44 - 44: O0
 if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
 if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
def lisp_get_decent_map_resolver ( eid ) :
 o00O = lisp_get_decent_index ( eid )
 oo00oOoO = str ( o00O ) + "." + lisp_decent_dns_suffix
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( oo00oOoO , False ) , eid . print_prefix ( ) ) )
 if 32 - 32: O0 + IiII
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 iI1ii1III = None
 for o0O0 in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( oo00oOoO != o0O0 . dns_name ) : continue
  if ( iI1ii1III == None or o0O0 . last_used < iI1ii1III . last_used ) : iI1ii1III = o0O0
  if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 return ( iI1ii1III )
 if 17 - 17: OOooOOo
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 if 46 - 46: II111iiii * OoO0O00
 if 77 - 77: ooOoO0o * I11i
 if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
 if 76 - 76: iII111i * OoooooooOO
 if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
def lisp_ipv4_input ( packet ) :
 if 51 - 51: i11iIiiIii
 if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
 if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
 if 63 - 63: II111iiii - Oo0Ooo
 if ( ord ( packet [ 9 : 10 ] ) == 2 ) : return ( [ True , packet ] )
 if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
 if 78 - 78: IiII - I1IiiI
 if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
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
   if 71 - 71: OoO0O00
   if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
   if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
   if 54 - 54: Ii1I / I1IiiI
   if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
   if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
   if 18 - 18: oO0o * OOooOOo
 o0ooo000o00O = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( o0ooo000o00O == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( o0ooo000o00O == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
  return ( [ False , None ] )
  if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
  if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
 o0ooo000o00O -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , o0ooo000o00O ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
 if 63 - 63: I1IiiI
 if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
 if 23 - 23: I1IiiI
 if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
 if 57 - 57: iIii1I11I1II1
 if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
def lisp_ipv6_input ( packet ) :
 oOO00OoOo = packet . inner_dest
 packet = packet . packet
 if 3 - 3: oO0o % OoO0O00 % OOooOOo
 if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
 if 58 - 58: ooOoO0o
 if 15 - 15: O0 * OOooOOo * I11i + Ii1I * OoooooooOO + OOooOOo
 if 77 - 77: O0
 o0ooo000o00O = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( o0ooo000o00O == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( o0ooo000o00O == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 98 - 98: iII111i - iII111i % i1IIi - I1Ii111 . I1IiiI % o0oOOo0O0Ooo
  return ( None )
  if 38 - 38: IiII % OoOoOO00 . OOooOOo . I1ii11iIi11i
  if 34 - 34: iII111i . i11iIiiIii + OoO0O00 + o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
  if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
  if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
  if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
 if ( oOO00OoOo . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
  if 60 - 60: OoOoOO00 - IiII + OoO0O00
 o0ooo000o00O -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , o0ooo000o00O ) + packet [ 8 : : ]
 return ( packet )
 if 77 - 77: iIii1I11I1II1
 if 92 - 92: IiII
 if 68 - 68: OOooOOo . IiII / iIii1I11I1II1 % i11iIiiIii
 if 74 - 74: iII111i + i11iIiiIii
 if 95 - 95: Ii1I
 if 49 - 49: I1ii11iIi11i . i1IIi + OoO0O00 % O0 + OoO0O00
 if 21 - 21: ooOoO0o * oO0o / OoooooooOO % ooOoO0o / O0
 if 24 - 24: OoO0O00 - i11iIiiIii / i11iIiiIii * I1Ii111
def lisp_mac_input ( packet ) :
 return ( packet )
 if 20 - 20: IiII % iIii1I11I1II1 . iII111i + iIii1I11I1II1 + O0
 if 96 - 96: I1ii11iIi11i - IiII % OoooooooOO . iII111i
 if 30 - 30: Oo0Ooo . OoooooooOO / Oo0Ooo / oO0o
 if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 if 49 - 49: iII111i / iII111i - OoOoOO00
 if 89 - 89: ooOoO0o
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
def lisp_rate_limit_map_request ( dest ) :
 oOo0O0ooo0 = lisp_get_timestamp ( )
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 if 89 - 89: I11i % II111iiii
 if 35 - 35: oO0o
 if 65 - 65: II111iiii
 o0oOOOO0 = oOo0O0ooo0 - lisp_no_map_request_rate_limit
 if ( o0oOOOO0 < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  oO0OO00OOo0 = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - o0oOOOO0 )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( oO0OO00OOo0 ) )
  return ( False )
  if 87 - 87: oO0o / OoO0O00 - oO0o
  if 69 - 69: i11iIiiIii
  if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
  if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
  if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
 if ( lisp_last_map_request_sent == None ) : return ( False )
 o0oOOOO0 = oOo0O0ooo0 - lisp_last_map_request_sent
 I111i1iI = ( o0oOOOO0 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
 if ( I111i1iI ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( o0oOOOO0 , 3 ) ) )
  if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
  if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
 return ( I111i1iI )
 if 82 - 82: OOooOOo . oO0o
 if 12 - 12: i11iIiiIii + II111iiii
 if 49 - 49: OoooooooOO
 if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
 if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
 if 6 - 6: oO0o / II111iiii
 if 23 - 23: IiII - OoooooooOO / oO0o
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ,
 pubsub = False ) :
 global lisp_last_map_request_sent , lisp_rloc_probe_nonce_list
 if 69 - 69: O0 - OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo . i1IIi - i1IIi % i1IIi - iIii1I11I1II1
 if 50 - 50: IiII - OOooOOo % OoOoOO00
 if 66 - 66: IiII * i11iIiiIii
 if 64 - 64: i11iIiiIii . I1Ii111 % i11iIiiIii % I11i
 if 56 - 56: o0oOOo0O0Ooo + ooOoO0o + OoooooooOO
 o0Oo = II1ii11ii1 = None
 if ( rloc ) :
  o0Oo = rloc . rloc
  II1ii11ii1 = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 33 - 33: i1IIi / I1Ii111 * O0
  if 95 - 95: Ii1I + Ii1I % IiII - IiII / OOooOOo
  if 46 - 46: IiII + iII111i + II111iiii . iII111i - i11iIiiIii % OoO0O00
  if 24 - 24: oO0o + IiII . o0oOOo0O0Ooo . OoooooooOO . i11iIiiIii / I1ii11iIi11i
  if 49 - 49: IiII
  if 1 - 1: oO0o / I11i
  if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
 I1Ii1i1ii , Ooooo , i1iiI = lisp_myrlocs
 if 21 - 21: Ii1I
 if 88 - 88: O0 . O0
 if 74 - 74: I1IiiI
 if 1 - 1: iIii1I11I1II1
 if 20 - 20: I1IiiI
 if ( rloc != None and rloc . probing_itr_rloc != None and rloc . rloc . is_ipv4 ( ) ) :
  I1Ii1i1ii = rloc . probing_itr_rloc
  if 51 - 51: i11iIiiIii . OoooooooOO + OOooOOo . I1IiiI
  if 40 - 40: OoO0O00 - OoO0O00
 if ( I1Ii1i1ii == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 17 - 17: II111iiii % II111iiii - IiII / i1IIi . Oo0Ooo
 if ( Ooooo == None and o0Oo != None and o0Oo . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 42 - 42: i11iIiiIii + ooOoO0o % Ii1I + oO0o * OoOoOO00 / i1IIi
  if 44 - 44: II111iiii * i1IIi - I1ii11iIi11i
 OOO0ooOOo0O = lisp_map_request ( )
 OOO0ooOOo0O . record_count = 1
 OOO0ooOOo0O . nonce = lisp_get_control_nonce ( )
 OOO0ooOOo0O . rloc_probe = ( o0Oo != None )
 OOO0ooOOo0O . subscribe_bit = pubsub
 OOO0ooOOo0O . xtr_id_present = pubsub
 OOO0ooOOo0O . decent_nat_xtr = lisp_decent_nat
 if 28 - 28: OoOoOO00 / oO0o % Ii1I / iII111i / i1IIi . o0oOOo0O0Ooo
 if 48 - 48: oO0o . Ii1I / OoOoOO00 % o0oOOo0O0Ooo
 if 59 - 59: o0oOOo0O0Ooo % Ii1I / o0oOOo0O0Ooo % IiII % OOooOOo + o0oOOo0O0Ooo
 if 19 - 19: O0 + i11iIiiIii % O0 / II111iiii
 if 56 - 56: O0 + Oo0Ooo * II111iiii * iII111i * iII111i / I1Ii111
 if 52 - 52: oO0o
 if 73 - 73: IiII - II111iiii - OOooOOo % II111iiii + iIii1I11I1II1
 if ( rloc ) : rloc . last_rloc_probe_nonce = OOO0ooOOo0O . nonce
 if 81 - 81: i11iIiiIii - O0 + I1IiiI
 i1Ii1 = deid . is_multicast_address ( )
 if ( i1Ii1 ) :
  OOO0ooOOo0O . target_eid = seid
  OOO0ooOOo0O . target_group = deid
 else :
  OOO0ooOOo0O . target_eid = deid
  if 39 - 39: IiII * OOooOOo . OoooooooOO + Oo0Ooo + iIii1I11I1II1
  if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
  if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
  if 10 - 10: O0 / I11i
  if 29 - 29: i11iIiiIii % I11i
  if 49 - 49: I11i
  if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
  if 92 - 92: OoO0O00 . O0 / Ii1I % Oo0Ooo . Ii1I
  if 40 - 40: o0oOOo0O0Ooo - Ii1I . iII111i - O0
 if ( OOO0ooOOo0O . rloc_probe == False ) :
  Iiii1II1 = lisp_get_signature_eid ( )
  if ( Iiii1II1 ) :
   OOO0ooOOo0O . signature_eid . copy_address ( Iiii1II1 . eid )
   OOO0ooOOo0O . privkey_filename = "./lisp-sig.pem"
   if 53 - 53: Oo0Ooo - I1IiiI * O0 . II111iiii
   if 72 - 72: ooOoO0o - Ii1I . Ii1I . I11i / OoooooooOO + Ii1I
   if 32 - 32: O0
   if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
   if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
   if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
 if ( seid == None or i1Ii1 ) :
  OOO0ooOOo0O . source_eid . afi = LISP_AFI_NONE
 else :
  OOO0ooOOo0O . source_eid = seid
  if 70 - 70: iIii1I11I1II1 - I11i
  if 2 - 2: oO0o / II111iiii * OoO0O00
  if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
  if 40 - 40: OOooOOo
  if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
  if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
  if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
  if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
  if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
  if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
  if 98 - 98: OoO0O00 + oO0o - II111iiii
  if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
  if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
  if 77 - 77: iIii1I11I1II1 * Oo0Ooo . IiII / oO0o + O0
  if 76 - 76: iII111i + o0oOOo0O0Ooo - OoooooooOO * oO0o % OoooooooOO - O0
 if ( o0Oo != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( lisp_decent_nat == False and
 o0Oo . is_private_address ( ) == False ) :
   I1Ii1i1ii = lisp_get_any_translated_rloc ( )
   if 18 - 18: Ii1I
  if ( I1Ii1i1ii == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
   if 70 - 70: OoO0O00
   if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
   if 58 - 58: I11i
   if 94 - 94: Oo0Ooo
   if 39 - 39: I11i - oO0o % iII111i - ooOoO0o - OoOoOO00
   if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
   if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
 if ( o0Oo == None or o0Oo . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and o0Oo == None ) :
   I11I111Ii1II = lisp_get_any_translated_rloc ( )
   if ( I11I111Ii1II != None ) : I1Ii1i1ii = I11I111Ii1II
   if 58 - 58: II111iiii * oO0o - i1IIi . I11i
  OOO0ooOOo0O . itr_rlocs . append ( I1Ii1i1ii )
  if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
 if ( o0Oo == None or o0Oo . is_ipv6 ( ) ) :
  if ( Ooooo == None or Ooooo . is_ipv6_link_local ( ) ) :
   Ooooo = None
  else :
   OOO0ooOOo0O . itr_rloc_count = 1 if ( o0Oo == None ) else 0
   OOO0ooOOo0O . itr_rlocs . append ( Ooooo )
   if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
   if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
   if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
   if 31 - 31: i1IIi * Ii1I
   if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
   if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
   if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
   if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
   if 15 - 15: oO0o
 if ( o0Oo != None and OOO0ooOOo0O . itr_rlocs != [ ] ) :
  O00O000OO = OOO0ooOOo0O . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   O00O000OO = I1Ii1i1ii
  elif ( deid . is_ipv6 ( ) ) :
   O00O000OO = Ooooo
  else :
   O00O000OO = I1Ii1i1ii
   if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
   if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
   if 63 - 63: oO0o . IiII . o0oOOo0O0Ooo
   if 16 - 16: iII111i . I11i - Oo0Ooo / I1IiiI + OoOoOO00
   if 14 - 14: iIii1I11I1II1 / i11iIiiIii - o0oOOo0O0Ooo . iII111i * OoO0O00
   if 5 - 5: Ii1I + OoOoOO00 % I11i + IiII
 Oo00O0o0O = OOO0ooOOo0O . encode ( o0Oo , II1ii11ii1 )
 OOO0ooOOo0O . print_map_request ( )
 if 55 - 55: OoooooooOO + oO0o . o0oOOo0O0Ooo % iIii1I11I1II1 - I1Ii111
 if 40 - 40: I1IiiI . o0oOOo0O0Ooo - Oo0Ooo
 if 44 - 44: Ii1I % OoO0O00 * oO0o * OoO0O00
 if 7 - 7: I1Ii111 % i1IIi . I11i . O0 / i1IIi
 if 56 - 56: Oo0Ooo
 if 21 - 21: i11iIiiIii * o0oOOo0O0Ooo + Oo0Ooo
 if ( o0Oo != None ) :
  I1iiiI1IIi11IiI1i = rloc . is_rloc_translated ( )
  if ( I1iiiI1IIi11IiI1i ) :
   Oo0oOOo000 = rloc . normalize_decent_nat_rloc_name ( )
   oOoO = lisp_get_nat_info ( o0Oo , Oo0oOOo000 )
   if 36 - 36: iIii1I11I1II1 - I1ii11iIi11i % Ii1I % Oo0Ooo - II111iiii
   if 73 - 73: Ii1I - II111iiii + I1IiiI % i11iIiiIii * I11i
   if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
   if 30 - 30: ooOoO0o / Oo0Ooo * iII111i % OoooooooOO / I1ii11iIi11i
   if 64 - 64: OoooooooOO
   if ( oOoO == None ) :
    IIIIiiI1iIiI = rloc . rloc . print_address_no_iid ( )
    II11iIIii = "glean-{}" . format ( IIIIiiI1iIiI ) if lisp_i_am_rtr else "nat-{}" . format ( IIIIiiI1iIiI )
    if 41 - 41: Ii1I . I11i / oO0o * OoooooooOO
    ooo0OO0OOooO0 = rloc . translated_port
    oOoO = lisp_nat_info ( IIIIiiI1iIiI , II11iIIii , ooo0OO0OOooO0 )
    if 98 - 98: I1ii11iIi11i - O0 + i11iIiiIii
    if 71 - 71: O0 - OoooooooOO
   lisp_encap_rloc_probe ( lisp_sockets , o0Oo , oOoO , Oo00O0o0O , rloc . probing_itr_rloc )
   return
   if 82 - 82: i11iIiiIii * II111iiii % IiII
   if 80 - 80: Ii1I . i11iIiiIii % oO0o * o0oOOo0O0Ooo
  if ( o0Oo . is_ipv4 ( ) and o0Oo . is_multicast_address ( ) ) :
   oOO00OoOo = o0Oo
  else :
   O00oO000Oo0 = o0Oo . print_address_no_iid ( )
   oOO00OoOo = lisp_convert_4to6 ( O00oO000Oo0 )
   if 56 - 56: I1Ii111 % iII111i / II111iiii - Oo0Ooo - Oo0Ooo - iIii1I11I1II1
   if 67 - 67: iII111i
   if 80 - 80: Ii1I . iII111i * I1IiiI * Ii1I
   if 82 - 82: OoO0O00 % OoOoOO00 * i11iIiiIii . OoO0O00 . I1ii11iIi11i + Ii1I
   if 60 - 60: i1IIi / iII111i
  lisp_rloc_probe_nonce_list [ OOO0ooOOo0O . nonce ] = O00oO000Oo0
  if 10 - 10: I1Ii111 / OoOoOO00 * Ii1I % o0oOOo0O0Ooo . OoOoOO00 / I1ii11iIi11i
  lisp_send ( lisp_sockets , oOO00OoOo , LISP_CTRL_PORT , Oo00O0o0O )
  return
  if 2 - 2: iIii1I11I1II1
  if 85 - 85: O0 - ooOoO0o
  if 35 - 35: o0oOOo0O0Ooo - I1IiiI
  if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
  if 65 - 65: Ii1I % i11iIiiIii
  if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
 II1iiII1ii111 = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  o0O0 = lisp_get_decent_map_resolver ( deid )
 else :
  o0O0 = lisp_get_map_resolver ( None , II1iiII1ii111 )
  if 82 - 82: o0oOOo0O0Ooo / iIii1I11I1II1
 if ( o0O0 == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 81 - 81: iII111i / i11iIiiIii * I1Ii111 % OoooooooOO . I1IiiI
  return
  if 3 - 3: OoOoOO00 . I11i * i11iIiiIii - ooOoO0o
 o0O0 . last_used = lisp_get_timestamp ( )
 o0O0 . map_requests_sent += 1
 if ( o0O0 . last_nonce == 0 ) : o0O0 . last_nonce = OOO0ooOOo0O . nonce
 if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
 if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
 if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
 if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
 if ( seid == None ) : seid = O00O000OO
 lisp_send_ecm ( lisp_sockets , Oo00O0o0O , seid , lisp_ephem_port , deid ,
 o0O0 . map_resolver )
 if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 if 42 - 42: II111iiii . iII111i
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 if 64 - 64: oO0o / IiII
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 86 - 86: I11i
 if 36 - 36: o0oOOo0O0Ooo / OoO0O00
 if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
 if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 o0O0 . resolve_dns_name ( )
 return
 if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
 if 86 - 86: i11iIiiIii
 if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if 79 - 79: I11i - II111iiii
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 O0o00oOoO = lisp_info ( )
 O0o00oOoO . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : O0o00oOoO . hostname += "-" + device_name
 if 100 - 100: I1IiiI . i1IIi + OoOoOO00 - I1Ii111
 O00oO000Oo0 = dest . print_address_no_iid ( )
 if 95 - 95: IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
 if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
 if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
 if 2 - 2: I11i
 Oo00O0o0O = O0o00oOoO . encode ( )
 O0o00oOoO . print_info ( )
 if 12 - 12: i1IIi . I1Ii111
 if 99 - 99: Oo0Ooo / i11iIiiIii
 if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
 if 42 - 42: iII111i / Oo0Ooo
 iiii = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 iiii = bold ( iiii , False )
 ooo0OO0OOooO0 = bold ( "{}" . format ( port ) , False )
 I1II1I1I = red ( O00oO000Oo0 , False )
 I11i1i1 = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( I11i1i1 , I1II1I1I , ooo0OO0OOooO0 , iiii ) )
 if 80 - 80: I1ii11iIi11i + Ii1I
 if 16 - 16: i11iIiiIii * Oo0Ooo
 if 76 - 76: iII111i . oO0o - i1IIi
 if 94 - 94: O0 % iII111i
 Iiii = lisp_sockets [ 0 ] if port == LISP_CTRL_PORT else lisp_sockets [ 1 ]
 lisp_bind_interface ( Iiii , device_name )
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 if 72 - 72: II111iiii * iII111i . II111iiii + iII111i * IiII
 if 90 - 90: oO0o * I1Ii111 / O0
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , Oo00O0o0O )
 else :
  o00O0O0OoO = lisp_data_header ( )
  o00O0O0OoO . instance_id ( 0xffffff )
  o00O0O0OoO = o00O0O0OoO . encode ( )
  if ( o00O0O0OoO ) :
   Oo00O0o0O = o00O0O0OoO + Oo00O0o0O
   if 15 - 15: o0oOOo0O0Ooo * O0 . OOooOOo / Oo0Ooo
   if 28 - 28: OoooooooOO + OoooooooOO
   if 27 - 27: I11i . oO0o / OoooooooOO - OoO0O00 . I11i
   if 15 - 15: II111iiii * OoO0O00
   if 33 - 33: OoooooooOO . o0oOOo0O0Ooo . I1IiiI / I1ii11iIi11i . OoOoOO00
   if 58 - 58: Ii1I
   if 20 - 20: OOooOOo
   if 93 - 93: i1IIi . IiII % O0 * iII111i
   if 84 - 84: I11i
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , Oo00O0o0O )
   if 99 - 99: I1ii11iIi11i
   if 78 - 78: I1Ii111 . IiII - OOooOOo
   if 93 - 93: iIii1I11I1II1
   if 33 - 33: OOooOOo . i1IIi
   if 63 - 63: II111iiii . oO0o * IiII
   if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
   if 47 - 47: I11i
 lisp_unbind_interface ( Iiii )
 return
 if 88 - 88: OoO0O00 - OoooooooOO
 if 93 - 93: Oo0Ooo * I1IiiI
 if 60 - 60: I1Ii111 + OOooOOo % iII111i
 if 40 - 40: I11i + oO0o . O0 % oO0o
 if 12 - 12: iIii1I11I1II1
 if 9 - 9: OoOoOO00 * II111iiii / o0oOOo0O0Ooo * iII111i - II111iiii / i11iIiiIii
 if 14 - 14: i11iIiiIii + I1Ii111 . OoOoOO00 - oO0o * OoO0O00
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 23 - 23: iIii1I11I1II1
 if 32 - 32: iII111i * iIii1I11I1II1 + I1Ii111 + IiII + O0 * OoO0O00
 if 100 - 100: II111iiii
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
 O0o00oOoO = lisp_info ( )
 packet = O0o00oOoO . decode ( packet )
 if ( packet == None ) : return
 O0o00oOoO . print_info ( )
 if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
 if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
 if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
 if 40 - 40: o0oOOo0O0Ooo * I1IiiI
 O0o00oOoO . info_reply = True
 O0o00oOoO . global_etr_rloc . store_address ( addr_str )
 O0o00oOoO . etr_port = sport
 if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
 if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
 if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
 if 16 - 16: oO0o
 if ( O0o00oOoO . hostname != None ) :
  O0o00oOoO . private_etr_rloc . afi = LISP_AFI_NAME
  O0o00oOoO . private_etr_rloc . store_address ( O0o00oOoO . hostname )
  if 32 - 32: OoooooooOO
  if 77 - 77: Oo0Ooo . i1IIi - I11i
 if ( rtr_list != None ) : O0o00oOoO . rtr_list = rtr_list
 packet = O0o00oOoO . encode ( )
 O0o00oOoO . print_info ( )
 if 98 - 98: O0
 if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
 if 54 - 54: i1IIi % iII111i
 if 16 - 16: II111iiii - Oo0Ooo
 if 44 - 44: OOooOOo / Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 oOO00OoOo = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , oOO00OoOo , sport , packet )
 if 85 - 85: iIii1I11I1II1 / Ii1I
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 if 80 - 80: I11i
 iI1ii1II1i111 = lisp_info_source ( O0o00oOoO . hostname , addr_str , sport )
 iI1ii1II1i111 . cache_address_for_info_source ( )
 return
 if 80 - 80: OoOoOO00 . ooOoO0o - iIii1I11I1II1 / o0oOOo0O0Ooo * I1IiiI + II111iiii
 if 37 - 37: IiII + OOooOOo - iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % oO0o
 if 26 - 26: iIii1I11I1II1 - I1Ii111 % iIii1I11I1II1 - iII111i
 if 37 - 37: i1IIi % iIii1I11I1II1 / OoOoOO00 * o0oOOo0O0Ooo - ooOoO0o . I1Ii111
 if 91 - 91: OoOoOO00
 if 89 - 89: Ii1I . I1Ii111 * OOooOOo + I1ii11iIi11i
 if 24 - 24: oO0o % iII111i
 if 70 - 70: IiII * I1Ii111 - II111iiii / Oo0Ooo / OOooOOo
def lisp_get_signature_eid ( ) :
 for Iiii1II1 in lisp_db_list :
  if ( Iiii1II1 . signature_eid ) : return ( Iiii1II1 )
  if 6 - 6: O0 + i11iIiiIii
 return ( None )
 if 59 - 59: ooOoO0o . iII111i - II111iiii
 if 30 - 30: o0oOOo0O0Ooo % iII111i - i11iIiiIii
 if 25 - 25: i11iIiiIii + OoOoOO00 + oO0o / Ii1I * Oo0Ooo + Oo0Ooo
 if 26 - 26: I1IiiI % I1ii11iIi11i + o0oOOo0O0Ooo / I1ii11iIi11i - I1IiiI
 if 55 - 55: OoooooooOO
 if 2 - 2: Oo0Ooo + I11i / OOooOOo + OOooOOo
 if 62 - 62: OOooOOo . iIii1I11I1II1 + I1IiiI / OOooOOo
 if 90 - 90: OOooOOo
def lisp_get_any_translated_port ( ) :
 for Iiii1II1 in lisp_db_list :
  for i1iiI1i1 in Iiii1II1 . rloc_set :
   if ( i1iiI1i1 . translated_rloc . is_null ( ) ) : continue
   return ( i1iiI1i1 . translated_port )
   if 29 - 29: OoOoOO00 - I1IiiI / oO0o + Oo0Ooo + I1Ii111 + O0
   if 65 - 65: oO0o
 return ( None )
 if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
 if 13 - 13: Ii1I
 if 34 - 34: I1IiiI / iIii1I11I1II1
 if 35 - 35: oO0o / oO0o
 if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
 if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
 if 77 - 77: O0
 if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
def lisp_get_translated_port_for_mr ( mr_addr ) :
 for o0O0 in list ( lisp_map_resolvers_list . values ( ) ) :
  I1II1I1I = o0O0 . map_resolver . print_address_no_iid ( )
  if ( I1II1I1I == mr_addr ) :
   if ( o0O0 . translated_port == 0 ) : return ( o0O0 , lisp_get_any_translated_port ( ) )
   return ( o0O0 , o0O0 . translated_port )
   if 36 - 36: II111iiii
   if 78 - 78: OoO0O00 + iIii1I11I1II1 * i1IIi
 return ( None , lisp_get_any_translated_port ( ) )
 if 7 - 7: i11iIiiIii
 if 49 - 49: I1IiiI - oO0o % OOooOOo / O0 / II111iiii
 if 41 - 41: IiII % II111iiii
 if 99 - 99: IiII - O0
 if 59 - 59: iII111i % O0 + OOooOOo * ooOoO0o
 if 27 - 27: I1Ii111 % i11iIiiIii * I1IiiI
 if 19 - 19: OoOoOO00 / o0oOOo0O0Ooo - iII111i / OoO0O00
 if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
 if 13 - 13: iII111i / OOooOOo * i11iIiiIii / oO0o / OoooooooOO
def lisp_get_any_translated_rloc ( ) :
 for Iiii1II1 in lisp_db_list :
  for i1iiI1i1 in Iiii1II1 . rloc_set :
   if ( i1iiI1i1 . translated_rloc . is_null ( ) ) : continue
   return ( i1iiI1i1 . translated_rloc )
   if 89 - 89: Ii1I * Oo0Ooo / I1Ii111 * I1ii11iIi11i + O0 * Oo0Ooo
   if 74 - 74: I11i . I11i
 return ( None )
 if 74 - 74: OoOoOO00 * ooOoO0o * I1Ii111
 if 56 - 56: iIii1I11I1II1 * OoO0O00 - oO0o * Ii1I
 if 62 - 62: i1IIi + I11i / OOooOOo - OoooooooOO % i1IIi . I1IiiI
 if 13 - 13: O0 * iII111i
 if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
 if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
 if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
def lisp_get_all_translated_rlocs ( ) :
 i11111ii11I11 = [ ]
 for Iiii1II1 in lisp_db_list :
  for i1iiI1i1 in Iiii1II1 . rloc_set :
   if ( i1iiI1i1 . is_rloc_translated ( ) == False ) : continue
   iI1ii11Ii = i1iiI1i1 . translated_rloc . print_address_no_iid ( )
   i11111ii11I11 . append ( iI1ii11Ii )
   if 3 - 3: Ii1I % iIii1I11I1II1 - I1Ii111 . oO0o . iII111i / o0oOOo0O0Ooo
   if 8 - 8: O0 - I1Ii111
 return ( i11111ii11I11 )
 if 82 - 82: iII111i + II111iiii
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 if 83 - 83: oO0o
 if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
 if 85 - 85: iIii1I11I1II1 / I11i
 if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
 if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
 if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 Iiooo0O0o0o = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 89 - 89: ooOoO0o
 O0O00OOoo00 = { }
 for OO0Oo00oo in rtr_list :
  if ( OO0Oo00oo == None ) : continue
  iI1ii11Ii = rtr_list [ OO0Oo00oo ]
  if ( Iiooo0O0o0o and iI1ii11Ii . is_private_address ( ) ) : continue
  O0O00OOoo00 [ OO0Oo00oo ] = iI1ii11Ii
  if 32 - 32: ooOoO0o - i1IIi
 rtr_list = O0O00OOoo00
 if 39 - 39: II111iiii + OoooooooOO / I11i . i11iIiiIii + I1Ii111
 IIi1 = [ ]
 for IiIIi in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( IiIIi == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 23 - 23: ooOoO0o + Oo0Ooo
  if 43 - 43: Ii1I
  if 87 - 87: OoO0O00
  if 32 - 32: I11i
  if 78 - 78: ooOoO0o * iII111i
  o0ooOooO00Oo = lisp_address ( IiIIi , "" , 0 , iid )
  o0ooOooO00Oo . make_default_route ( o0ooOooO00Oo )
  Ii111 = lisp_map_cache . lookup_cache ( o0ooOooO00Oo , True )
  if ( Ii111 ) :
   if ( Ii111 . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( Ii111 . print_eid_tuple ( ) , False ) ) )
    if 31 - 31: I1IiiI + OOooOOo . OoooooooOO
   elif ( Ii111 . do_rloc_sets_match ( list ( rtr_list . values ( ) ) ) ) :
    continue
    if 24 - 24: ooOoO0o
   Ii111 . delete_cache ( )
   if 53 - 53: I1ii11iIi11i % OOooOOo
   if 92 - 92: I1IiiI / ooOoO0o
  IIi1 . append ( [ o0ooOooO00Oo , "" ] )
  if 5 - 5: OoooooooOO - oO0o
  if 52 - 52: I11i . OOooOOo * ooOoO0o / i11iIiiIii . OoO0O00 * ooOoO0o
  if 58 - 58: i1IIi - OoO0O00 * II111iiii
  if 92 - 92: ooOoO0o / I1Ii111 . iII111i
  i1I1IIIiII = lisp_address ( IiIIi , "" , 0 , iid )
  i1I1IIIiII . make_default_multicast_route ( i1I1IIIiII )
  O00OO00O = lisp_map_cache . lookup_cache ( i1I1IIIiII , True )
  if ( O00OO00O ) : O00OO00O = O00OO00O . source_cache . lookup_cache ( o0ooOooO00Oo , True )
  if ( O00OO00O ) : O00OO00O . delete_cache ( )
  if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
  IIi1 . append ( [ o0ooOooO00Oo , i1I1IIIiII ] )
  if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
 if ( len ( IIi1 ) == 0 ) : return
 if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
 if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
 if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
 if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
 o0O00ooOo = [ ]
 for I11i1i1 in rtr_list :
  ooO00O0o0O0o = rtr_list [ I11i1i1 ]
  i1iiI1i1 = lisp_rloc ( )
  i1iiI1i1 . rloc . copy_address ( ooO00O0o0O0o )
  oooOoOoO0oO = i1iiI1i1 . next_rloc
  while ( oooOoOoO0oO != None ) :
   oooOoOoO0oO . rloc . copy_address ( ooO00O0o0O0o )
   oooOoOoO0oO = oooOoOoO0oO . next_rloc
   if 28 - 28: OOooOOo - oO0o
  i1iiI1i1 . set_active_rloc_next_hop ( )
  i1iiI1i1 . priority = 254
  i1iiI1i1 . mpriority = 255
  i1iiI1i1 . rloc_name = "RTR"
  o0O00ooOo . append ( i1iiI1i1 )
  if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
  if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
 for o0ooOooO00Oo in IIi1 :
  Ii111 = lisp_mapping ( o0ooOooO00Oo [ 0 ] , o0ooOooO00Oo [ 1 ] , o0O00ooOo )
  Ii111 . mapping_source = map_resolver
  Ii111 . map_cache_ttl = LISP_MR_TTL * 60
  Ii111 . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( Ii111 . print_eid_tuple ( ) , False ) , list ( rtr_list . keys ( ) ) ) )
  if 73 - 73: OoooooooOO
  o0O00ooOo = copy . deepcopy ( o0O00ooOo )
  if 25 - 25: i1IIi . II111iiii . I1Ii111
 return
 if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
 if 61 - 61: I1ii11iIi11i
 if 12 - 12: OoO0O00
 if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
 if 7 - 7: Oo0Ooo
 if 38 - 38: Oo0Ooo - I1ii11iIi11i
 if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
 if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
 if 3 - 3: Ii1I
def lisp_process_info_reply ( source , packet , store ) :
 if 71 - 71: iIii1I11I1II1 . OOooOOo / I11i / i1IIi
 if 69 - 69: i1IIi / iII111i + Ii1I + I11i + IiII
 if 86 - 86: Oo0Ooo
 if 97 - 97: I1IiiI
 O0o00oOoO = lisp_info ( )
 packet = O0o00oOoO . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
 O0o00oOoO . print_info ( )
 if 5 - 5: O0 + OoooooooOO + i11iIiiIii * Oo0Ooo * OoOoOO00 . oO0o
 if 6 - 6: OoO0O00 % Oo0Ooo % I1IiiI % o0oOOo0O0Ooo % O0 % Oo0Ooo
 if 94 - 94: I11i . i1IIi / II111iiii + OOooOOo
 if 64 - 64: I1IiiI % ooOoO0o
 Oo0oOO0oO0O00 = False
 if 27 - 27: OOooOOo - OoooooooOO - I1ii11iIi11i - o0oOOo0O0Ooo / OOooOOo
 if 58 - 58: I11i . I11i + O0 / I1IiiI
 if 45 - 45: OoooooooOO * II111iiii
 if 28 - 28: I1ii11iIi11i
 for I11i1i1 in O0o00oOoO . rtr_list :
  O00oO000Oo0 = I11i1i1 . print_address_no_iid ( )
  if ( O00oO000Oo0 in lisp_rtr_list ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ O00oO000Oo0 ] != None ) : continue
   if 85 - 85: o0oOOo0O0Ooo
  Oo0oOO0oO0O00 = True
  lisp_rtr_list [ O00oO000Oo0 ] = I11i1i1
  if 20 - 20: OoooooooOO . ooOoO0o + ooOoO0o
  if 7 - 7: OoO0O00 / IiII - OoO0O00 . OOooOOo
  if 56 - 56: iIii1I11I1II1 / O0 + Oo0Ooo
  if 5 - 5: O0 / i11iIiiIii * I1IiiI % IiII * OoO0O00
  if 67 - 67: I1Ii111 . iII111i + Oo0Ooo / i11iIiiIii
 if ( lisp_i_am_itr and Oo0oOO0oO0O00 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for i1I1iI in list ( lisp_iid_to_interface . keys ( ) ) :
    lisp_update_default_routes ( source , int ( i1I1iI ) , lisp_rtr_list )
    if 47 - 47: iII111i
    if 16 - 16: OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
    if 60 - 60: OOooOOo . Ii1I
    if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
    if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
    if 38 - 38: IiII / I11i / IiII * iII111i
    if 30 - 30: oO0o
 if ( lisp_i_am_itr ) :
  i1I1 = O0o00oOoO . etr_port
  O00oO000Oo0 = source . print_address_no_iid ( )
  o0O0 , i11i1IIIiI1i = lisp_get_translated_port_for_mr ( O00oO000Oo0 )
  if ( o0O0 == None ) :
   lprint ( "Could not store translated-port {} for map-resolver {}" . format ( i1I1 , O00oO000Oo0 ) )
  else :
   o0O0 . translated_port = i1I1
   lprint ( "Store translated-port {} for map-resolver {}" . format ( i1I1 , O00oO000Oo0 ) )
   if 85 - 85: oO0o
   if 14 - 14: IiII / iIii1I11I1II1 . OoooooooOO
   if 14 - 14: IiII * OoooooooOO - iIii1I11I1II1
   if 11 - 11: I1IiiI + Oo0Ooo % I1Ii111 * Ii1I - iIii1I11I1II1 % I1ii11iIi11i
   if 43 - 43: o0oOOo0O0Ooo * o0oOOo0O0Ooo . iII111i / Oo0Ooo - i11iIiiIii
   if 66 - 66: I1IiiI / i1IIi + o0oOOo0O0Ooo % IiII - OoOoOO00 / Oo0Ooo
 if ( store == False ) :
  return ( [ O0o00oOoO . global_etr_rloc , O0o00oOoO . etr_port , Oo0oOO0oO0O00 ] )
  if 22 - 22: oO0o % I1Ii111 - I1Ii111 / I1Ii111
  if 25 - 25: OoooooooOO / oO0o / ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
  if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
  if 33 - 33: OOooOOo % OoooooooOO
  if 98 - 98: Ii1I
  if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
 for Iiii1II1 in lisp_db_list :
  for i1iiI1i1 in Iiii1II1 . rloc_set :
   OO0Oo00oo = i1iiI1i1 . rloc
   o0o = i1iiI1i1 . interface
   I11Io00oo0OO = i1iiI1i1 . rloc_name
   if ( i1iiI1i1 . is_decent_nat_port ( ) ) :
    I11Io00oo0OO = I11Io00oo0OO . split ( LISP_TP ) [ 0 ]
    if 95 - 95: iIii1I11I1II1 / O0 % O0
    if 53 - 53: ooOoO0o . ooOoO0o
   if ( o0o == None ) :
    if ( OO0Oo00oo . is_null ( ) ) : continue
    if ( OO0Oo00oo . is_local ( ) == False ) : continue
    if ( O0o00oOoO . private_etr_rloc . is_null ( ) == False and
 OO0Oo00oo . is_exact_match ( O0o00oOoO . private_etr_rloc ) == False ) :
     continue
     if 80 - 80: i11iIiiIii % I1Ii111 % I1IiiI / I1IiiI + oO0o + iII111i
   elif ( O0o00oOoO . private_etr_rloc . is_dist_name ( ) ) :
    iI1iIiIIiIIii = O0o00oOoO . private_etr_rloc . address
    if ( iI1iIiIIiIIii != I11Io00oo0OO ) : continue
    if 64 - 64: I1ii11iIi11i % OOooOOo + I11i % iIii1I11I1II1 % I1IiiI / OOooOOo
    if 98 - 98: i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
   oOOoo = green ( Iiii1II1 . eid . print_prefix ( ) , False )
   iIiIi111 = red ( OO0Oo00oo . print_address_no_iid ( ) , False )
   if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
   i1ioooo0OooO = O0o00oOoO . global_etr_rloc . is_exact_match ( OO0Oo00oo )
   if ( i1iiI1i1 . translated_port == 0 and i1ioooo0OooO ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( iIiIi111 ,
 o0o , oOOoo ) )
    continue
    if 68 - 68: OoOoOO00 + I1ii11iIi11i % i11iIiiIii
    if 58 - 58: OoO0O00 / Oo0Ooo + Ii1I
    if 63 - 63: OOooOOo / I1ii11iIi11i
    if 86 - 86: O0 + iII111i + OoooooooOO / iII111i * I1ii11iIi11i * OoooooooOO
    if 89 - 89: oO0o - OOooOOo / iII111i - I1IiiI
   OoOoo0o = O0o00oOoO . global_etr_rloc
   ooIII1IIiI1iii = i1iiI1i1 . translated_rloc
   if ( ooIII1IIiI1iii . is_exact_match ( OoOoo0o ) and
 O0o00oOoO . etr_port == i1iiI1i1 . translated_port ) : continue
   if 19 - 19: iII111i + OOooOOo
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( O0o00oOoO . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # i11iIiiIii - OoOoOO00 - IiII . Oo0Ooo
 O0o00oOoO . etr_port , iIiIi111 , o0o , oOOoo ) )
   if 76 - 76: I11i / Oo0Ooo
   i1iiI1i1 . rloc_name = I11Io00oo0OO
   i1iiI1i1 . store_translated_rloc ( O0o00oOoO . global_etr_rloc ,
 O0o00oOoO . etr_port )
   if 2 - 2: IiII . i11iIiiIii % Oo0Ooo
   Oo0oOO0oO0O00 = True
   if 75 - 75: IiII + OOooOOo
   if 92 - 92: OoOoOO00
 return ( [ O0o00oOoO . global_etr_rloc , O0o00oOoO . etr_port , Oo0oOO0oO0O00 ] )
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
 if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
 if 27 - 27: i11iIiiIii / OoOoOO00 % O0 / II111iiii . I11i - ooOoO0o
 if 54 - 54: oO0o * II111iiii
 if 79 - 79: o0oOOo0O0Ooo . ooOoO0o . Oo0Ooo * OoooooooOO
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 98 - 98: ooOoO0o
 O0o00o0Oo = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 o0O0OO0O0OOo0 = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 39 - 39: o0oOOo0O0Ooo / IiII - iII111i * iIii1I11I1II1 % Ii1I * OoO0O00
 if 80 - 80: i11iIiiIii
 if 19 - 19: O0 * ooOoO0o . OoOoOO00 . iIii1I11I1II1
 if 83 - 83: I11i - OoooooooOO + Ii1I - ooOoO0o * iIii1I11I1II1
 O0o00o0Oo . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , O0o00o0Oo , None )
 O0o00o0Oo . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , O0o00o0Oo , None )
 if 37 - 37: O0
 if 76 - 76: iII111i * OOooOOo
 if 7 - 7: ooOoO0o + o0oOOo0O0Ooo + o0oOOo0O0Ooo
 if 73 - 73: IiII % I11i % i11iIiiIii + ooOoO0o
 o0O0OO0O0OOo0 . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , o0O0OO0O0OOo0 , None )
 o0O0OO0O0OOo0 . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , o0O0OO0O0OOo0 , None )
 if 83 - 83: Ii1I * I1Ii111 * i11iIiiIii / iIii1I11I1II1 % I1ii11iIi11i
 if 40 - 40: iII111i
 if 21 - 21: I1Ii111 / iII111i + Oo0Ooo / I1ii11iIi11i / I1Ii111
 if 33 - 33: OoooooooOO
 Ooooo00o0 = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 Ooooo00o0 . start ( )
 return
 if 11 - 11: i1IIi + I1ii11iIi11i * I1IiiI - IiII
 if 61 - 61: OOooOOo . iII111i * I1Ii111
 if 94 - 94: I1ii11iIi11i % II111iiii . O0
 if 38 - 38: o0oOOo0O0Ooo % i11iIiiIii / I1Ii111 / I1ii11iIi11i % iII111i - oO0o
 if 76 - 76: iIii1I11I1II1 / I1ii11iIi11i + i1IIi % oO0o / iIii1I11I1II1
 if 33 - 33: OoooooooOO * i1IIi / O0 * I1ii11iIi11i
 if 55 - 55: o0oOOo0O0Ooo * Oo0Ooo . ooOoO0o
 if 25 - 25: IiII . O0 / OoOoOO00
 if 33 - 33: OoO0O00
 if 55 - 55: ooOoO0o + ooOoO0o
 if 93 - 93: oO0o - I1IiiI / I1ii11iIi11i % o0oOOo0O0Ooo / OoooooooOO + II111iiii
 if 10 - 10: o0oOOo0O0Ooo - iII111i . O0 + OoO0O00 - Oo0Ooo - i11iIiiIii
 if 37 - 37: iIii1I11I1II1
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 37 - 37: II111iiii % OoOoOO00 . IiII * ooOoO0o . I1IiiI
 iI1ii11Ii = lisp_get_interface_address ( rloc . interface )
 if ( iI1ii11Ii == None ) : return
 if 25 - 25: OoooooooOO % i1IIi . I1Ii111 / OoOoOO00 - I1ii11iIi11i
 i1Ii1I1i1IiII1i = rloc . rloc . print_address_no_iid ( )
 iiI1ooOOOoo = iI1ii11Ii . print_address_no_iid ( )
 if 79 - 79: ooOoO0o * Ii1I * I1Ii111
 if ( i1Ii1I1i1IiII1i == iiI1ooOOOoo ) : return
 if 23 - 23: OoOoOO00 / OoO0O00 % OoO0O00 + O0
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , i1Ii1I1i1IiII1i , iiI1ooOOOoo ) )
 if 40 - 40: O0 - OoO0O00
 if 34 - 34: IiII * IiII
 rloc . rloc . copy_address ( iI1ii11Ii )
 lisp_myrlocs [ 0 ] = iI1ii11Ii
 return
 if 76 - 76: OOooOOo
 if 54 - 54: O0 * II111iiii * OOooOOo
 if 44 - 44: I1IiiI
 if 66 - 66: o0oOOo0O0Ooo
 if 40 - 40: OOooOOo * Ii1I
 if 38 - 38: ooOoO0o
 if 5 - 5: OoooooooOO + iII111i - I11i
 if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
def lisp_update_encap_port ( mc ) :
 for OO0Oo00oo in mc . rloc_set :
  Oo0oOOo000 = OO0Oo00oo . normalize_decent_nat_rloc_name ( )
  oOoO = lisp_get_nat_info ( OO0Oo00oo . rloc , Oo0oOOo000 )
  if ( oOoO == None ) : continue
  if ( OO0Oo00oo . translated_port == oOoO . port ) : continue
  if 7 - 7: I1ii11iIi11i
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( OO0Oo00oo . translated_port , oOoO . port ,
  # iIii1I11I1II1 / II111iiii . OOooOOo
 red ( OO0Oo00oo . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 88 - 88: OoOoOO00 - iII111i
  OO0Oo00oo . store_translated_rloc ( OO0Oo00oo . rloc , oOoO . port )
  if 41 - 41: I11i % Ii1I
 return
 if 13 - 13: iII111i . O0 + iIii1I11I1II1
 if 42 - 42: oO0o . OOooOOo * OoO0O00
 if 88 - 88: I1ii11iIi11i
 if 21 - 21: i1IIi . I1IiiI / OoooooooOO % oO0o
 if 31 - 31: O0
 if 37 - 37: Oo0Ooo . OoOoOO00 % I1ii11iIi11i * O0
 if 20 - 20: ooOoO0o + I1IiiI - IiII % ooOoO0o - IiII . oO0o
 if 39 - 39: O0 / oO0o % oO0o * iIii1I11I1II1
 if 7 - 7: iII111i % o0oOOo0O0Ooo / II111iiii % IiII / iIii1I11I1II1
 if 17 - 17: I11i * I11i - O0 / IiII + OoOoOO00
 if 65 - 65: I1Ii111 * i1IIi
 if 10 - 10: OOooOOo % IiII
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 20 - 20: I11i / OoooooooOO % OoOoOO00 . oO0o * I1IiiI % IiII
  if 84 - 84: I1ii11iIi11i % I11i / OOooOOo % O0
 oOo0O0ooo0 = lisp_get_timestamp ( )
 o0oOIi = mc . last_refresh_time
 if 38 - 38: II111iiii * i1IIi
 if 43 - 43: O0 - OOooOOo / I1IiiI * II111iiii . OoooooooOO / OoOoOO00
 if 77 - 77: OoOoOO00
 if 10 - 10: IiII / i11iIiiIii
 if 19 - 19: OoO0O00
 if 100 - 100: I1ii11iIi11i - I1ii11iIi11i
 if 38 - 38: I1Ii111
 if ( lisp_is_running ( "lisp-ms" ) and lisp_uptime + ( 5 * 60 ) >= oOo0O0ooo0 ) :
  if ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
   o0oOIi = 0
   lprint ( "Remove startup-mode native-forward map-cache entry" )
   if 23 - 23: Ii1I . I1ii11iIi11i + I1Ii111 + i1IIi * o0oOOo0O0Ooo - i11iIiiIii
   if 92 - 92: I1Ii111 - I1IiiI + Ii1I / iII111i % OOooOOo
   if 32 - 32: i1IIi . iII111i - Ii1I % iII111i % II111iiii - oO0o
   if 36 - 36: OoooooooOO * OoooooooOO . ooOoO0o . O0
   if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
   if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
   if 40 - 40: iII111i - I1IiiI + OoOoOO00
 i1ii1iIII = ( mc . action != LISP_NOT_REGISTERED_YET_ACTION )
 if 90 - 90: i11iIiiIii + II111iiii + I1IiiI % I1ii11iIi11i
 if 3 - 3: I1Ii111 + Ii1I + Ii1I + iIii1I11I1II1 + I1Ii111 * I11i
 if 44 - 44: i1IIi - I1IiiI / IiII + IiII
 if 65 - 65: OOooOOo * I1Ii111 . i1IIi % iIii1I11I1II1
 if 31 - 31: I1IiiI * I1Ii111 * O0 * I1Ii111 . II111iiii
 if 52 - 52: iIii1I11I1II1 . oO0o % I1Ii111 + i11iIiiIii
 if ( i1ii1iIII and o0oOIi + mc . map_cache_ttl > oOo0O0ooo0 ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 43 - 43: I1ii11iIi11i + I11i - iIii1I11I1II1
  if 100 - 100: OoOoOO00
  if 28 - 28: ooOoO0o + Oo0Ooo - I1ii11iIi11i
  if 16 - 16: O0 - OoO0O00 % Ii1I % O0
  if 51 - 51: iIii1I11I1II1 * i11iIiiIii . I1IiiI + o0oOOo0O0Ooo / iII111i - I1IiiI
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 73 - 73: OOooOOo
  if 100 - 100: o0oOOo0O0Ooo - OoOoOO00
  if 91 - 91: II111iiii / i11iIiiIii . Oo0Ooo * iIii1I11I1II1
  if 6 - 6: ooOoO0o * Oo0Ooo . OoO0O00
  if 24 - 24: O0 * oO0o % O0 * iIii1I11I1II1 - OoO0O00
 I11III = lisp_print_elapsed ( mc . uptime )
 Ii1IiIii = lisp_print_elapsed ( mc . last_refresh_time )
 I1iii = mc . print_eid_tuple ( )
 lprint ( ( "Map-cache entry {} {}, had uptime {}, last-refresh-time {}, " + "action was {}" ) . format ( green ( I1iii , False ) ,
 # Oo0Ooo % o0oOOo0O0Ooo + oO0o % OoO0O00 - iIii1I11I1II1
 bold ( "timed out" , False ) , I11III , Ii1IiIii ,
 lisp_map_reply_action_string [ mc . action ] ) )
 if 18 - 18: ooOoO0o . I1Ii111 % o0oOOo0O0Ooo - o0oOOo0O0Ooo % OoooooooOO . o0oOOo0O0Ooo
 if 52 - 52: I1ii11iIi11i / OoO0O00 + II111iiii . I1Ii111
 if 36 - 36: OoOoOO00 - OoooooooOO + OoOoOO00 - o0oOOo0O0Ooo / Oo0Ooo - OoO0O00
 if 77 - 77: O0 + OoO0O00
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 37 - 37: II111iiii / I1ii11iIi11i * I1IiiI - OoooooooOO
 if 55 - 55: IiII / ooOoO0o * I1IiiI / I1Ii111 - Oo0Ooo % o0oOOo0O0Ooo
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . Oo0Ooo / IiII . OoO0O00
 if 47 - 47: OOooOOo + IiII
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
def lisp_timeout_map_cache_walk ( mc , parms ) :
 i1iIi = parms [ 0 ]
 OoO0Oo0o = parms [ 1 ]
 if 52 - 52: OoooooooOO * I1Ii111 % II111iiii
 if 40 - 40: I11i / ooOoO0o . OoO0O00 + i1IIi + iII111i - Ii1I
 if 9 - 9: o0oOOo0O0Ooo
 if 92 - 92: i11iIiiIii + OoooooooOO + O0 % oO0o
 if ( mc . group . is_null ( ) ) :
  iI1IIi1I11i1I , i1iIi = lisp_timeout_map_cache_entry ( mc , i1iIi )
  if ( i1iIi == [ ] or mc != i1iIi [ - 1 ] ) :
   OoO0Oo0o = lisp_write_checkpoint_entry ( OoO0Oo0o , mc )
   parms [ 1 ] = OoO0Oo0o
   if 90 - 90: Oo0Ooo * i11iIiiIii
  parms [ 0 ] = i1iIi
  return ( [ iI1IIi1I11i1I , parms ] )
  if 95 - 95: I1Ii111 % i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - I1Ii111
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 69 - 69: iIii1I11I1II1 * oO0o
 if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
 if 64 - 64: I1IiiI % i11iIiiIii / oO0o
 if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
 i1iIi = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , i1iIi )
 parms [ 0 ] = i1iIi
 return ( [ True , parms ] )
 if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
 if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
 if 31 - 31: OoO0O00
 if 89 - 89: II111iiii
 if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
 if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
 if 85 - 85: O0 * OOooOOo % I1Ii111
def lisp_timeout_map_cache ( lisp_map_cache ) :
 o0000O00oO0O = [ [ ] , [ ] ]
 o0000O00oO0O = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , o0000O00oO0O )
 if 33 - 33: O0
 if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
 if 43 - 43: iIii1I11I1II1
 if 88 - 88: I1IiiI - OoO0O00 . O0 . oO0o
 if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
 i1iIi = o0000O00oO0O [ 0 ]
 for Ii111 in i1iIi : Ii111 . delete_cache ( )
 if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
 if 59 - 59: OOooOOo - o0oOOo0O0Ooo
 if 82 - 82: IiII % ooOoO0o - OoO0O00 % ooOoO0o
 if 51 - 51: ooOoO0o % iII111i . o0oOOo0O0Ooo . o0oOOo0O0Ooo
 OoO0Oo0o = o0000O00oO0O [ 1 ]
 lisp_checkpoint ( OoO0Oo0o )
 return
 if 20 - 20: i1IIi - ooOoO0o % OoooooooOO * I1ii11iIi11i + II111iiii % i1IIi
 if 30 - 30: i11iIiiIii - I1IiiI + o0oOOo0O0Ooo + IiII
 if 16 - 16: I1ii11iIi11i / Ii1I + I1ii11iIi11i * I1Ii111
 if 49 - 49: ooOoO0o * OoOoOO00 . OoooooooOO . ooOoO0o + Oo0Ooo * IiII
 if 47 - 47: iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
 if 84 - 84: o0oOOo0O0Ooo * I11i
 if 22 - 22: i1IIi + OOooOOo % OoooooooOO
 if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
 if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 if 66 - 66: OoooooooOO
 if 90 - 90: IiII - OoOoOO00
 if 98 - 98: Oo0Ooo / oO0o . Ii1I
 if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
 if 37 - 37: iII111i - Ii1I . oO0o
 if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
def lisp_store_nat_info ( hostname , rloc , port ) :
 O00oO000Oo0 = rloc . print_address_no_iid ( )
 iIII11III = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( O00oO000Oo0 , False ) , port )
 if 9 - 9: iIii1I11I1II1 * OoO0O00
 IIiIi11I = lisp_nat_info ( O00oO000Oo0 , hostname , port )
 if 22 - 22: ooOoO0o . ooOoO0o % i1IIi * II111iiii * IiII
 if ( hostname not in lisp_nat_state_info ) :
  lisp_nat_state_info [ hostname ] = [ IIiIi11I ]
  lprint ( iIII11III . format ( "Store initial" ) )
  return ( True )
  if 6 - 6: II111iiii . iII111i % I1ii11iIi11i + IiII / I11i
  if 35 - 35: iII111i * Oo0Ooo
  if 61 - 61: I1Ii111 - I1IiiI - I11i * OoO0O00 - O0 + iII111i
  if 9 - 9: IiII - OOooOOo / O0 + i1IIi . O0 % oO0o
  if 57 - 57: i1IIi . OOooOOo
  if 72 - 72: ooOoO0o / I1IiiI - ooOoO0o * OoO0O00 . OOooOOo
 oOoO = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( oOoO . address == O00oO000Oo0 and oOoO . port == port ) :
  oOoO . uptime = lisp_get_timestamp ( )
  lprint ( iIII11III . format ( "Refresh existing" ) )
  return ( False )
  if 1 - 1: o0oOOo0O0Ooo + I1Ii111 + OoO0O00 * OOooOOo / I1Ii111 % i11iIiiIii
  if 49 - 49: OOooOOo - oO0o
  if 73 - 73: o0oOOo0O0Ooo . I1IiiI - I11i . ooOoO0o % II111iiii . OoooooooOO
  if 8 - 8: OoooooooOO
  if 92 - 92: ooOoO0o + IiII * II111iiii
  if 41 - 41: I1IiiI + OoOoOO00 . OOooOOo
  if 57 - 57: II111iiii . iIii1I11I1II1
 OOiii1i1iI = None
 for oOoO in lisp_nat_state_info [ hostname ] :
  if ( oOoO . address == O00oO000Oo0 and oOoO . port == port ) :
   OOiii1i1iI = oOoO
   break
   if 32 - 32: o0oOOo0O0Ooo
   if 75 - 75: I1IiiI . II111iiii - iII111i % IiII * OoO0O00 % ooOoO0o
   if 38 - 38: I1IiiI / OoooooooOO
 if ( OOiii1i1iI == None ) :
  lprint ( iIII11III . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( OOiii1i1iI )
  lprint ( iIII11III . format ( "Use previous" ) )
  if 16 - 16: i1IIi . i11iIiiIii . oO0o - I11i
  if 96 - 96: iII111i - OoOoOO00
 II111iiII = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ IIiIi11I ] + II111iiII
 return ( True )
 if 87 - 87: OOooOOo
 if 60 - 60: ooOoO0o * o0oOOo0O0Ooo . OoO0O00 * iII111i * oO0o * i1IIi
 if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
 if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
 if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
 if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
 if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
 if 76 - 76: OoO0O00
def lisp_get_nat_info ( rloc , hostname ) :
 O00oO000Oo0 = rloc . print_address_no_iid ( )
 if 92 - 92: iIii1I11I1II1 * O0 % I11i
 if ( hostname == None ) :
  for hostname in lisp_nat_state_info :
   for oOoO in lisp_nat_state_info [ hostname ] :
    if ( oOoO . address == O00oO000Oo0 ) : return ( oOoO )
    if 92 - 92: OoOoOO00 + oO0o
    if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
  return ( None )
  if 28 - 28: I1IiiI . iIii1I11I1II1
  if 12 - 12: I1Ii111 * OOooOOo
 if ( hostname not in lisp_nat_state_info ) : return ( None )
 if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
 for oOoO in lisp_nat_state_info [ hostname ] :
  if ( oOoO . address == O00oO000Oo0 ) : return ( oOoO )
  if 45 - 45: OoooooooOO * oO0o
 return ( None )
 if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
 if 16 - 16: Oo0Ooo
 if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
 if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
 if 67 - 67: I1IiiI
 if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
 if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 if 33 - 33: OOooOOo - OoooooooOO . iII111i
 if 2 - 2: I11i + i1IIi
 if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
 if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
 if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
 if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
 if 12 - 12: II111iiii * O0 - Oo0Ooo + o0oOOo0O0Ooo . Oo0Ooo + iIii1I11I1II1
 if 4 - 4: I1Ii111 - I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / oO0o
 if 18 - 18: iIii1I11I1II1 . ooOoO0o
 if 68 - 68: o0oOOo0O0Ooo
 if 36 - 36: Oo0Ooo . I11i + I1IiiI * i1IIi % Ii1I + OOooOOo
 if 5 - 5: o0oOOo0O0Ooo % oO0o / OoO0O00
 if 17 - 17: OoooooooOO - I1ii11iIi11i / OoO0O00 - I1Ii111 + i1IIi
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 6 - 6: Oo0Ooo - II111iiii
 if 33 - 33: I1Ii111 - I1IiiI + iII111i . OoOoOO00
 if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
 if 68 - 68: I11i
 if 91 - 91: I11i
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
 ooooooO = [ ]
 IiiiIiI1 = [ ]
 if ( dest == None ) :
  for o0O0 in list ( lisp_map_resolvers_list . values ( ) ) :
   IiiiIiI1 . append ( o0O0 . map_resolver )
   if 83 - 83: iIii1I11I1II1 - IiII - ooOoO0o
  ooooooO = IiiiIiI1
  if ( ooooooO == [ ] ) :
   for oo0Oo0oo0o in list ( lisp_map_servers_list . values ( ) ) :
    ooooooO . append ( oo0Oo0oo0o . map_server )
    if 41 - 41: OoO0O00
    if 16 - 16: I11i / iII111i . IiII
  if ( ooooooO == [ ] ) : return
 else :
  ooooooO . append ( dest )
  if 43 - 43: iIii1I11I1II1 % I11i % I1ii11iIi11i * I11i
  if 57 - 57: I1ii11iIi11i + i1IIi - I1Ii111
  if 7 - 7: Ii1I
  if 72 - 72: OoO0O00 . Oo0Ooo % ooOoO0o / o0oOOo0O0Ooo . IiII . iII111i
  if 28 - 28: i1IIi % iIii1I11I1II1 . i11iIiiIii - OoO0O00
 i11111ii11I11 = { }
 for Iiii1II1 in lisp_db_list :
  for i1iiI1i1 in Iiii1II1 . rloc_set :
   lisp_update_local_rloc ( i1iiI1i1 )
   if ( i1iiI1i1 . rloc . is_null ( ) ) : continue
   if ( i1iiI1i1 . interface == None ) : continue
   if 97 - 97: O0 / i1IIi - Oo0Ooo % i11iIiiIii + OOooOOo % iII111i
   iI1ii11Ii = i1iiI1i1 . rloc . print_address_no_iid ( )
   if ( iI1ii11Ii in i11111ii11I11 ) : continue
   i11111ii11I11 [ iI1ii11Ii ] = i1iiI1i1 . interface
   if 59 - 59: I11i
   if 23 - 23: OoOoOO00 * I1Ii111
 if ( i11111ii11I11 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
  return
  if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
  if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
 if ( len ( i11111ii11I11 ) > 1 ) :
  lprint ( "NAT multihoming local RLOC-list {}" . format ( i11111ii11I11 ) )
  if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
  if 25 - 25: OoO0O00 * oO0o
  if 29 - 29: OOooOOo - I1Ii111 - i11iIiiIii % i1IIi
  if 2 - 2: i11iIiiIii % iIii1I11I1II1 * OOooOOo
  if 45 - 45: oO0o + i1IIi + iII111i + o0oOOo0O0Ooo * OOooOOo + ooOoO0o
  if 83 - 83: OoO0O00 - ooOoO0o / OoooooooOO % iIii1I11I1II1 - II111iiii
 for iI1ii11Ii in i11111ii11I11 :
  o0o = i11111ii11I11 [ iI1ii11Ii ]
  I1II1I1I = red ( iI1ii11Ii , False )
  lprint ( "Build Info-Request for private address {} on {}" . format ( I1II1I1I ,
 o0o ) )
  i1iiI = o0o if len ( i11111ii11I11 ) > 1 else None
  for dest in ooooooO :
   lisp_send_info_request ( lisp_sockets , dest , port , i1iiI )
   if 73 - 73: Oo0Ooo + II111iiii - IiII
   if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
   if 47 - 47: oO0o + IiII * I1Ii111 % o0oOOo0O0Ooo - O0 % IiII
   if 66 - 66: II111iiii * I1IiiI . Oo0Ooo * OoooooooOO % OoOoOO00 . II111iiii
   if 4 - 4: iII111i + I1Ii111 % OoOoOO00 / Ii1I
   if 94 - 94: OoO0O00
 if ( IiiiIiI1 != [ ] ) :
  for o0O0 in list ( lisp_map_resolvers_list . values ( ) ) :
   o0O0 . resolve_dns_name ( )
   if 35 - 35: I1ii11iIi11i % OoO0O00 + II111iiii % II111iiii / IiII - iII111i
   if 9 - 9: I1ii11iIi11i * o0oOOo0O0Ooo . oO0o
 return
 if 48 - 48: IiII . I1Ii111 + OoooooooOO - I1Ii111 . Ii1I . I1Ii111
 if 24 - 24: ooOoO0o * iIii1I11I1II1
 if 1 - 1: I1ii11iIi11i . O0
 if 3 - 3: iIii1I11I1II1 * ooOoO0o - OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoooooooOO
 if 42 - 42: I1Ii111 - i1IIi
 if 91 - 91: iII111i . OOooOOo / iIii1I11I1II1 . Oo0Ooo . II111iiii . OoOoOO00
 if 31 - 31: OoO0O00 . I1ii11iIi11i % I11i - II111iiii
 if 70 - 70: ooOoO0o - IiII - OoO0O00 / I11i
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 59 - 59: IiII % ooOoO0o . iII111i / Ii1I * Ii1I
 if 73 - 73: I1ii11iIi11i . oO0o % I11i . I1ii11iIi11i / I1Ii111 / II111iiii
 if 23 - 23: OoooooooOO . o0oOOo0O0Ooo
 if 76 - 76: I1Ii111
 if 91 - 91: iIii1I11I1II1 / Ii1I . I1IiiI
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 if ( value . find ( "." ) != - 1 ) :
  iI1ii11Ii = value . split ( "." )
  if ( len ( iI1ii11Ii ) != 4 ) : return ( False )
  if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
  for Iii1 in iI1ii11Ii :
   if ( Iii1 . isdigit ( ) == False ) : return ( False )
   if ( int ( Iii1 ) > 255 ) : return ( False )
   if 78 - 78: II111iiii % OOooOOo
  return ( True )
  if 6 - 6: OOooOOo
  if 21 - 21: I1Ii111 - Ii1I - i1IIi % oO0o
  if 55 - 55: OOooOOo + oO0o - II111iiii
  if 5 - 5: iII111i * OoooooooOO . OoO0O00 % ooOoO0o + Ii1I
  if 59 - 59: OoOoOO00
 if ( value . find ( "-" ) != - 1 ) :
  iI1ii11Ii = value . split ( "-" )
  for o000o0O0Oo00 in [ "N" , "S" , "W" , "E" ] :
   if ( o000o0O0Oo00 in iI1ii11Ii ) :
    if ( len ( iI1ii11Ii ) < 8 ) : return ( False )
    return ( True )
    if 96 - 96: I1IiiI
    if 3 - 3: OoooooooOO
    if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
    if 56 - 56: ooOoO0o
    if 82 - 82: ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . OoOoOO00
    if 59 - 59: Oo0Ooo
    if 98 - 98: I1Ii111 * II111iiii / Oo0Ooo . Oo0Ooo % I1Ii111
 if ( value . find ( "-" ) != - 1 ) :
  iI1ii11Ii = value . split ( "-" )
  if ( len ( iI1ii11Ii ) != 3 ) : return ( False )
  if 52 - 52: OoOoOO00
  for o0o00 in iI1ii11Ii :
   try : int ( o0o00 , 16 )
   except : return ( False )
   if 36 - 36: I11i * O0 / o0oOOo0O0Ooo + OoOoOO00
  return ( True )
  if 32 - 32: OoooooooOO + ooOoO0o * Oo0Ooo * OoOoOO00 . I1ii11iIi11i
  if 52 - 52: IiII
  if 84 - 84: iIii1I11I1II1
  if 30 - 30: i11iIiiIii . oO0o . I11i - OoOoOO00 % i11iIiiIii
  if 72 - 72: II111iiii
 if ( value . find ( ":" ) != - 1 ) :
  iI1ii11Ii = value . split ( ":" )
  if ( len ( iI1ii11Ii ) < 2 ) : return ( False )
  if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
  Ooo000Oooo0o0 = False
  III11i1iI11 = 0
  for o0o00 in iI1ii11Ii :
   III11i1iI11 += 1
   if ( o0o00 == "" ) :
    if ( Ooo000Oooo0o0 ) :
     if ( len ( iI1ii11Ii ) == III11i1iI11 ) : break
     if ( III11i1iI11 > 2 ) : return ( False )
     if 58 - 58: I1Ii111 + I11i
    Ooo000Oooo0o0 = True
    continue
    if 58 - 58: I1IiiI
   try : int ( o0o00 , 16 )
   except : return ( False )
   if 90 - 90: I11i . I1IiiI + o0oOOo0O0Ooo * iIii1I11I1II1 . I1ii11iIi11i
  return ( True )
  if 39 - 39: Oo0Ooo / oO0o / I1ii11iIi11i - ooOoO0o + oO0o
  if 71 - 71: OoooooooOO - I1IiiI + I11i % I1IiiI
  if 32 - 32: OOooOOo + OoooooooOO . IiII . Oo0Ooo * iII111i
  if 86 - 86: I1ii11iIi11i . iII111i + Ii1I - IiII / i11iIiiIii + OoOoOO00
  if 50 - 50: o0oOOo0O0Ooo - IiII + OoOoOO00 - II111iiii
 if ( value [ 0 ] == "+" ) :
  iI1ii11Ii = value [ 1 : : ]
  for I111II1i1 in iI1ii11Ii :
   if ( I111II1i1 . isdigit ( ) == False ) : return ( False )
   if 56 - 56: I1ii11iIi11i
  return ( True )
  if 40 - 40: OoooooooOO
 return ( False )
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
 if 69 - 69: O0 + o0oOOo0O0Ooo / ooOoO0o
 if 7 - 7: Ii1I . Ii1I . iIii1I11I1II1 / ooOoO0o
 if 70 - 70: O0
 if 42 - 42: I1Ii111 + OoooooooOO + I11i
def lisp_process_api ( process , lisp_socket , data_structure ) :
 III11III , o0000O00oO0O = data_structure . split ( "%" )
 if 33 - 33: iII111i - Ii1I / OoOoOO00 / O0 / Oo0Ooo . oO0o
 lprint ( "Process API request '{}', parameters: '{}'" . format ( III11III ,
 o0000O00oO0O ) )
 if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
 IiI11I1I111 = [ ]
 if ( III11III == "map-cache" ) :
  if ( o0000O00oO0O == "" ) :
   IiI11I1I111 = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , IiI11I1I111 )
  else :
   IiI11I1I111 = lisp_process_api_map_cache_entry ( json . loads ( o0000O00oO0O ) )
   if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
   if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
 if ( III11III == "site-cache" ) :
  if ( o0000O00oO0O == "" ) :
   IiI11I1I111 = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 IiI11I1I111 )
  else :
   IiI11I1I111 = lisp_process_api_site_cache_entry ( json . loads ( o0000O00oO0O ) )
   if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
   if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
 if ( III11III == "site-cache-summary" ) :
  IiI11I1I111 = lisp_process_api_site_cache_summary ( lisp_sites_by_eid )
  if 67 - 67: oO0o
 if ( III11III == "map-server" ) :
  o0000O00oO0O = { } if ( o0000O00oO0O == "" ) else json . loads ( o0000O00oO0O )
  IiI11I1I111 = lisp_process_api_ms_or_mr ( True , o0000O00oO0O )
  if 12 - 12: I1IiiI + OoooooooOO
 if ( III11III == "map-resolver" ) :
  o0000O00oO0O = { } if ( o0000O00oO0O == "" ) else json . loads ( o0000O00oO0O )
  IiI11I1I111 = lisp_process_api_ms_or_mr ( False , o0000O00oO0O )
  if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
 if ( III11III == "database-mapping" ) :
  IiI11I1I111 = lisp_process_api_database_mapping ( )
  if 19 - 19: OoooooooOO / IiII
  if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
  if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
  if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
  if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
 IiI11I1I111 = json . dumps ( IiI11I1I111 )
 OO0oOOOOO = lisp_api_ipc ( process , IiI11I1I111 )
 lisp_ipc ( OO0oOOOOO , lisp_socket , "lisp-core" )
 return
 if 51 - 51: OoO0O00 - OoO0O00 * IiII
 if 24 - 24: OoooooooOO . II111iiii
 if 97 - 97: II111iiii . O0
 if 18 - 18: iII111i
 if 35 - 35: ooOoO0o / O0 / iIii1I11I1II1 - iIii1I11I1II1 + I11i
 if 8 - 8: I1Ii111 . oO0o % Oo0Ooo * OoooooooOO
 if 25 - 25: OoO0O00
def lisp_process_api_map_cache ( mc , data ) :
 if 54 - 54: O0
 if 20 - 20: ooOoO0o + Oo0Ooo - Oo0Ooo
 if 2 - 2: i1IIi - IiII . I1ii11iIi11i / i1IIi
 if 92 - 92: ooOoO0o - iII111i
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 69 - 69: iII111i
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 48 - 48: O0 + o0oOOo0O0Ooo . oO0o - IiII * OoooooooOO . OoO0O00
 if 63 - 63: oO0o * OoO0O00 * oO0o
 if 31 - 31: Oo0Ooo
 if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
 if 67 - 67: I1Ii111 . I1ii11iIi11i
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 2 - 2: O0 + I1Ii111
 if 82 - 82: Ii1I / iII111i
 if 13 - 13: I11i + iII111i
 if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
 if 59 - 59: Oo0Ooo + I1ii11iIi11i
 if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
 if 70 - 70: i1IIi . Ii1I / Ii1I
def lisp_gather_map_cache_data ( mc , data ) :
 Ii = { }
 Ii [ "instance-id" ] = str ( mc . eid . instance_id )
 Ii [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  Ii [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
 Ii [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 Ii [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 Ii [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 Ii [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 45 - 45: i1IIi + I1ii11iIi11i
 Ii [ "eid-memory" ] = hex ( id ( mc ) )
 if 49 - 49: i11iIiiIii . I1ii11iIi11i
 if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
 if 33 - 33: II111iiii
 if 39 - 39: ooOoO0o + I11i
 o0O00ooOo = [ ]
 for OO0Oo00oo in mc . rloc_set :
  IIIIiiI1iIiI = lisp_fill_rloc_in_json ( OO0Oo00oo )
  if 24 - 24: o0oOOo0O0Ooo
  if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
  if 63 - 63: oO0o
  if 7 - 7: IiII / i11iIiiIii - OOooOOo
  if 9 - 9: II111iiii + i11iIiiIii % I1Ii111 - Oo0Ooo * OOooOOo
  if ( OO0Oo00oo . rloc . is_multicast_address ( ) ) :
   IIIIiiI1iIiI [ "multicast-rloc-set" ] = [ ]
   for I1IIIIiIii in list ( OO0Oo00oo . multicast_rloc_probe_list . values ( ) ) :
    o0O0 = lisp_fill_rloc_in_json ( I1IIIIiIii )
    IIIIiiI1iIiI [ "multicast-rloc-set" ] . append ( o0O0 )
    if 55 - 55: I1Ii111 + ooOoO0o
    if 58 - 58: iII111i . I1ii11iIi11i - Oo0Ooo % o0oOOo0O0Ooo + I1Ii111
    if 58 - 58: oO0o . ooOoO0o . I1IiiI . Oo0Ooo * iIii1I11I1II1 - iII111i
  o0O00ooOo . append ( IIIIiiI1iIiI )
  if 96 - 96: OOooOOo % o0oOOo0O0Ooo / iIii1I11I1II1
 Ii [ "rloc-set" ] = o0O00ooOo
 if 60 - 60: i1IIi / iIii1I11I1II1 + I11i % iII111i
 data . append ( Ii )
 return ( [ True , data ] )
 if 64 - 64: I11i . i11iIiiIii / iIii1I11I1II1 . I11i
 if 73 - 73: OoO0O00 % iIii1I11I1II1 + IiII * I1Ii111 % II111iiii
 if 20 - 20: I11i % I1ii11iIi11i . OoO0O00 % OoOoOO00
 if 84 - 84: OoooooooOO / i11iIiiIii . IiII / I1IiiI
 if 62 - 62: iII111i - I1IiiI + OoooooooOO
 if 59 - 59: iIii1I11I1II1 + i11iIiiIii * oO0o . Oo0Ooo . I1Ii111
 if 49 - 49: II111iiii
 if 99 - 99: Oo0Ooo . OOooOOo
 if 85 - 85: OoOoOO00 . IiII + oO0o - II111iiii
def lisp_is_active_interface ( rloc ) :
 iIiIi111 = rloc . rloc . print_address_no_iid ( )
 oo0oO0OoO00 = rloc . rloc_next_hop
 if 89 - 89: Ii1I / Oo0Ooo * o0oOOo0O0Ooo / OoO0O00 + I11i
 iI11IiI1II = lisp_get_default_route_next_hops ( )
 iIoO000oO = ( iI11IiI1II and oo0oO0OoO00 == iI11IiI1II [ 0 ] )
 if 19 - 19: Oo0Ooo - I1Ii111 * OoOoOO00 + iIii1I11I1II1
 Oo0oo0O = lisp_get_host_route_next_hop ( iIiIi111 )
 if ( Oo0oo0O == None ) :
  if ( iIoO000oO ) : return ( True )
 elif ( oo0oO0OoO00 [ 1 ] == Oo0oo0O ) :
  return ( True )
  if 9 - 9: I1ii11iIi11i * iII111i / ooOoO0o / Ii1I
 return ( False )
 if 90 - 90: I1IiiI . oO0o
 if 17 - 17: OoooooooOO / oO0o * I11i
 if 63 - 63: Oo0Ooo
 if 4 - 4: ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
def lisp_fill_rloc_in_json ( rloc , head = True ) :
 IIIIiiI1iIiI = { }
 O00oO000Oo0 = None
 if ( rloc . rloc_exists ( ) ) :
  IIIIiiI1iIiI [ "address" ] = rloc . rloc . print_address_no_iid ( )
  O00oO000Oo0 = IIIIiiI1iIiI [ "address" ]
  if 71 - 71: i1IIi
  if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
 if ( rloc . translated_port != 0 ) :
  IIIIiiI1iIiI [ "encap-port" ] = str ( rloc . translated_port )
  O00oO000Oo0 += ":" + IIIIiiI1iIiI [ "encap-port" ]
  if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
  if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
 if ( O00oO000Oo0 and O00oO000Oo0 in lisp_crypto_keys_by_rloc_encap ) :
  oO0oOo = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ] [ 1 ]
  if ( oO0oOo != None and oO0oOo . shared_key != None ) :
   IIIIiiI1iIiI [ "encap-crypto" ] = "crypto-" + oO0oOo . cipher_suite_string
   if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
   if 79 - 79: iII111i
   if 29 - 29: Ii1I * I1Ii111 / OoO0O00 - O0 - i11iIiiIii * I1IiiI
 IIIIiiI1iIiI [ "rloc-memory" ] = hex ( id ( rloc ) )
 if 2 - 2: OoOoOO00 . I1ii11iIi11i * I1ii11iIi11i
 IIIIiiI1iIiI [ "state" ] = rloc . print_state ( )
 if ( rloc . geo ) : IIIIiiI1iIiI [ "geo" ] = rloc . geo . print_geo ( )
 if ( rloc . elp ) : IIIIiiI1iIiI [ "elp" ] = rloc . elp . print_elp ( False )
 if ( rloc . rle ) : IIIIiiI1iIiI [ "rle" ] = rloc . rle . print_api_rle ( )
 if ( rloc . json ) : IIIIiiI1iIiI [ "json" ] = rloc . json . print_json ( False )
 if ( rloc . rloc_name ) : IIIIiiI1iIiI [ "rloc-name" ] = rloc . rloc_name
 IIiO0O0 = rloc . stats . get_stats ( False , False )
 if ( IIiO0O0 ) :
  IIIIiiI1iIiI [ "stats" ] = IIiO0O0
  IIIIiiI1iIiI [ "recent-packet-sec" ] = rloc . stats . recent_packet_sec ( )
  IIIIiiI1iIiI [ "recent-packet-min" ] = rloc . stats . recent_packet_min ( )
  if 42 - 42: OoO0O00 . OoO0O00 + II111iiii - IiII - OOooOOo * Oo0Ooo
 iIIi111II = lisp_print_elapsed ( rloc . last_state_change )
 if ( iIIi111II == "never" ) :
  iIIi111II = lisp_print_elapsed ( rloc . uptime )
  if 78 - 78: oO0o + I1ii11iIi11i
 IIIIiiI1iIiI [ "uptime" ] = iIIi111II
 IIIIiiI1iIiI [ "upriority" ] = str ( rloc . priority )
 IIIIiiI1iIiI [ "uweight" ] = str ( rloc . weight )
 IIIIiiI1iIiI [ "mpriority" ] = str ( rloc . mpriority )
 IIIIiiI1iIiI [ "mweight" ] = str ( rloc . mweight )
 OoIIi11ii = rloc . last_rloc_probe_reply
 if ( OoIIi11ii ) :
  IIIIiiI1iIiI [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( OoIIi11ii )
  IIIIiiI1iIiI [ "rloc-probe-rtt" ] = str ( rloc . rloc_probe_rtt )
  if 88 - 88: iII111i + i11iIiiIii
 IIIIiiI1iIiI [ "rloc-hop-count" ] = rloc . rloc_probe_hops
 IIIIiiI1iIiI [ "recent-rloc-hop-counts" ] = rloc . recent_rloc_probe_hops
 if 42 - 42: I1Ii111 * O0 / OoO0O00 + iII111i
 IIIIiiI1iIiI [ "rloc-probe-latency" ] = rloc . rloc_probe_latency
 IIIIiiI1iIiI [ "recent-rloc-probe-latencies" ] = rloc . recent_rloc_probe_latencies
 if 86 - 86: OOooOOo
 II11IIiii1 = [ ]
 for I1IIiiI1Ii in rloc . recent_rloc_probe_rtts : II11IIiii1 . append ( str ( I1IIiiI1Ii ) )
 IIIIiiI1iIiI [ "recent-rloc-probe-rtts" ] = II11IIiii1
 if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
 if ( rloc . rloc_next_hop ) : IIIIiiI1iIiI [ "nh-interface" ] = rloc . rloc_next_hop
 if 65 - 65: Ii1I + IiII + I11i / I1Ii111 % iIii1I11I1II1
 if 17 - 17: I1ii11iIi11i * OOooOOo % II111iiii
 if 30 - 30: I1Ii111 . Ii1I . Oo0Ooo / OOooOOo * OoooooooOO / I1ii11iIi11i
 if 41 - 41: i1IIi
 if 75 - 75: o0oOOo0O0Ooo . I1Ii111 - I1Ii111 % Ii1I * OoooooooOO
 IIIIiiI1iIiI [ "is-active" ] = lisp_is_active_interface ( rloc )
 if 99 - 99: OOooOOo + o0oOOo0O0Ooo - OOooOOo . i1IIi
 if 86 - 86: Ii1I % oO0o - i11iIiiIii - O0 + IiII + iII111i
 if 100 - 100: OoO0O00 . Oo0Ooo
 if 29 - 29: OoO0O00
 if ( head == False ) : return ( IIIIiiI1iIiI )
 if 34 - 34: O0 - o0oOOo0O0Ooo % OOooOOo . OoO0O00 % IiII
 IIIIiiI1iIiI [ "next-hop-rlocs" ] = [ ]
 i1IIIII = rloc . next_rloc
 while ( i1IIIII != None ) :
  OooooO0o00 = lisp_fill_rloc_in_json ( i1IIIII , False )
  IIIIiiI1iIiI [ "next-hop-rlocs" ] . append ( OooooO0o00 )
  i1IIIII = i1IIIII . next_rloc
  if 24 - 24: IiII / I1ii11iIi11i / OOooOOo
  if 23 - 23: o0oOOo0O0Ooo - OoooooooOO % I1ii11iIi11i * i1IIi
 return ( IIIIiiI1iIiI )
 if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
 if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
 if 57 - 57: OOooOOo . I11i % OoOoOO00
 if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
 if 78 - 78: iII111i - OOooOOo / I1Ii111
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
 if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
def lisp_process_api_map_cache_entry ( parms ) :
 i1I1iI = parms [ "instance-id" ]
 i1I1iI = 0 if ( i1I1iI == "" ) else int ( i1I1iI )
 if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 if 56 - 56: I11i % OoOoOO00 - OoO0O00
 if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 O0o00o0Oo = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 O0o00o0Oo . store_prefix ( parms [ "eid-prefix" ] )
 oOO00OoOo = O0o00o0Oo
 IiiiiI = O0o00o0Oo
 if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
 if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
 if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
 if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
 if 66 - 66: OoO0O00 * Ii1I . OoO0O00
 i1I1IIIiII = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 if ( "group-prefix" in parms ) :
  i1I1IIIiII . store_prefix ( parms [ "group-prefix" ] )
  oOO00OoOo = i1I1IIIiII
  if 90 - 90: II111iiii % Ii1I
  if 67 - 67: I1IiiI - I11i - i11iIiiIii
 IiI11I1I111 = [ ]
 Ii111 = lisp_map_cache_lookup ( IiiiiI , oOO00OoOo )
 if ( Ii111 ) : iI1IIi1I11i1I , IiI11I1I111 = lisp_process_api_map_cache ( Ii111 , IiI11I1I111 )
 return ( IiI11I1I111 )
 if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
 if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
 if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
 if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
 if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
 if 57 - 57: I1Ii111 - IiII
 if 89 - 89: oO0o + iII111i
 if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
 if 7 - 7: II111iiii
def lisp_process_api_site_cache_summary ( site_cache ) :
 oOo00Oo = { "site" : "" , "registrations" : [ ] }
 Ii = { "eid-prefix" : "" , "count" : 0 , "registered-count" : 0 }
 if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
 II1i1I1IiI1i = { }
 for I1iIIIiI1iI11 in site_cache . cache_sorted :
  for ii11i1Ii in list ( site_cache . cache [ I1iIIIiI1iI11 ] . entries . values ( ) ) :
   if ( ii11i1Ii . accept_more_specifics == False ) : continue
   if ( ii11i1Ii . site . site_name not in II1i1I1IiI1i ) :
    II1i1I1IiI1i [ ii11i1Ii . site . site_name ] = [ ]
    if 54 - 54: oO0o * o0oOOo0O0Ooo
   oOO = copy . deepcopy ( Ii )
   oOO [ "eid-prefix" ] = ii11i1Ii . eid . print_prefix ( )
   oOO [ "count" ] = len ( ii11i1Ii . more_specific_registrations )
   for ooOo00OO in ii11i1Ii . more_specific_registrations :
    if ( ooOo00OO . registered ) : oOO [ "registered-count" ] += 1
    if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
   II1i1I1IiI1i [ ii11i1Ii . site . site_name ] . append ( oOO )
   if 67 - 67: I1Ii111
   if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
   if 77 - 77: ooOoO0o
 IiI11I1I111 = [ ]
 for OooOo0OO in II1i1I1IiI1i :
  OOo0oOO0o0oo0 = copy . deepcopy ( oOo00Oo )
  OOo0oOO0o0oo0 [ "site" ] = OooOo0OO
  OOo0oOO0o0oo0 [ "registrations" ] = II1i1I1IiI1i [ OooOo0OO ]
  IiI11I1I111 . append ( OOo0oOO0o0oo0 )
  if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
 return ( IiI11I1I111 )
 if 6 - 6: iII111i / iII111i . i11iIiiIii
 if 12 - 12: I11i - OoO0O00
 if 68 - 68: IiII - OoOoOO00
 if 22 - 22: i1IIi . IiII
 if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
 if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
 if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
def lisp_process_api_site_cache ( se , data ) :
 if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
 if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
 if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
 if 42 - 42: i1IIi . OoO0O00 % iII111i
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 57 - 57: I1ii11iIi11i / I1IiiI
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
 if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 39 - 39: OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
 if 41 - 41: II111iiii . o0oOOo0O0Ooo
 if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
 if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
 if 15 - 15: OoO0O00
 if 37 - 37: OoO0O00 . OoooooooOO - OOooOOo
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 oOoO0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 oo00oOoO = data [ "dns-name" ] if ( "dns-name" in data ) else None
 if ( "address" in data ) :
  oOoO0 . store_address ( data [ "address" ] )
  if 34 - 34: o0oOOo0O0Ooo + iIii1I11I1II1 / o0oOOo0O0Ooo / ooOoO0o
  if 53 - 53: II111iiii / iIii1I11I1II1
 oO00o = { }
 if ( ms_or_mr ) :
  for oo0Oo0oo0o in list ( lisp_map_servers_list . values ( ) ) :
   if ( oo00oOoO ) :
    if ( oo00oOoO != oo0Oo0oo0o . dns_name ) : continue
   else :
    if ( oOoO0 . is_exact_match ( oo0Oo0oo0o . map_server ) == False ) : continue
    if 25 - 25: I1Ii111
    if 58 - 58: OoOoOO00 * i1IIi
   oO00o [ "dns-name" ] = oo0Oo0oo0o . dns_name
   oO00o [ "address" ] = oo0Oo0oo0o . map_server . print_address_no_iid ( )
   oO00o [ "ms-name" ] = "" if oo0Oo0oo0o . ms_name == None else oo0Oo0oo0o . ms_name
   return ( [ oO00o ] )
   if 20 - 20: IiII
 else :
  for o0O0 in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( oo00oOoO ) :
    if ( oo00oOoO != o0O0 . dns_name ) : continue
   else :
    if ( oOoO0 . is_exact_match ( o0O0 . map_resolver ) == False ) : continue
    if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
    if 30 - 30: i11iIiiIii . I1IiiI
   oO00o [ "dns-name" ] = o0O0 . dns_name
   oO00o [ "address" ] = o0O0 . map_resolver . print_address_no_iid ( )
   oO00o [ "mr-name" ] = "" if o0O0 . mr_name == None else o0O0 . mr_name
   return ( [ oO00o ] )
   if 5 - 5: Ii1I / O0 + iIii1I11I1II1
   if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
 return ( [ ] )
 if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 if 79 - 79: iII111i
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
def lisp_process_api_database_mapping ( ) :
 IiI11I1I111 = [ ]
 if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
 for Iiii1II1 in lisp_db_list :
  Ii = { }
  Ii [ "eid-prefix" ] = Iiii1II1 . eid . print_prefix ( )
  if ( Iiii1II1 . group . is_null ( ) == False ) :
   Ii [ "group-prefix" ] = Iiii1II1 . group . print_prefix ( )
   if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
   if 13 - 13: OOooOOo / OoooooooOO
  II = [ ]
  for IIIIiiI1iIiI in Iiii1II1 . rloc_set :
   OO0Oo00oo = { }
   if ( IIIIiiI1iIiI . rloc . is_null ( ) == False ) :
    OO0Oo00oo [ "rloc" ] = IIIIiiI1iIiI . rloc . print_address_no_iid ( )
    if 7 - 7: II111iiii - ooOoO0o
   if ( IIIIiiI1iIiI . rloc_name != None ) : OO0Oo00oo [ "rloc-name" ] = IIIIiiI1iIiI . rloc_name
   if ( IIIIiiI1iIiI . interface != None ) : OO0Oo00oo [ "interface" ] = IIIIiiI1iIiI . interface
   oo0o0O0OO00 = IIIIiiI1iIiI . translated_rloc
   if ( oo0o0O0OO00 . is_null ( ) == False ) :
    OO0Oo00oo [ "translated-rloc" ] = oo0o0O0OO00 . print_address_no_iid ( )
    if ( IIIIiiI1iIiI . translated_port != 0 ) :
     OO0Oo00oo [ "translated-port" ] = IIIIiiI1iIiI . translated_port
     if 91 - 91: iII111i * oO0o . ooOoO0o . Ii1I % IiII - OOooOOo
     if 23 - 23: II111iiii . I1IiiI - OoOoOO00 * i11iIiiIii / ooOoO0o * OOooOOo
   if ( OO0Oo00oo != { } ) : II . append ( OO0Oo00oo )
   if 34 - 34: I1IiiI * oO0o + i1IIi * Oo0Ooo / ooOoO0o . Ii1I
   if 47 - 47: I11i * oO0o % I11i * i1IIi * II111iiii
   if 3 - 3: Ii1I % IiII + O0 % iIii1I11I1II1
   if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
   if 64 - 64: iII111i - Oo0Ooo
  Ii [ "rlocs" ] = II
  if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
  if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
  if 50 - 50: I1IiiI % o0oOOo0O0Ooo
  if 1 - 1: II111iiii
  IiI11I1I111 . append ( Ii )
  if 22 - 22: I1Ii111 + iII111i
 return ( IiI11I1I111 )
 if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
 if 69 - 69: Ii1I * II111iiii
 if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
 if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
 if 10 - 10: Ii1I / Oo0Ooo - i1IIi
 if 11 - 11: I11i * iII111i
def lisp_gather_site_cache_data ( se , data ) :
 Ii = { }
 Ii [ "site-name" ] = se . site . site_name
 Ii [ "instance-id" ] = str ( se . eid . instance_id )
 Ii [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  Ii [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
 Ii [ "registered" ] = "yes" if se . registered else "no"
 Ii [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 Ii [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 2 - 2: oO0o + I11i / I1Ii111 . I11i
 iI1ii11Ii = se . last_registerer
 iI1ii11Ii = "none" if iI1ii11Ii . is_null ( ) else iI1ii11Ii . print_address ( )
 Ii [ "last-registerer" ] = iI1ii11Ii
 Ii [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 Ii [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 Ii [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  Ii [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 59 - 59: Ii1I
  if 47 - 47: iII111i % iII111i
  if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
  if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
  if 74 - 74: I11i % OOooOOo
 o0O00ooOo = [ ]
 for OO0Oo00oo in se . registered_rlocs :
  IIIIiiI1iIiI = { }
  IIIIiiI1iIiI [ "address" ] = OO0Oo00oo . rloc . print_address_no_iid ( ) if OO0Oo00oo . rloc_exists ( ) else "none"
  if 57 - 57: O0 + I1IiiI + i11iIiiIii
  if 90 - 90: I1ii11iIi11i . OoO0O00 * iIii1I11I1II1 - Oo0Ooo
  if ( OO0Oo00oo . geo ) : IIIIiiI1iIiI [ "geo" ] = OO0Oo00oo . geo . print_geo ( )
  if ( OO0Oo00oo . elp ) : IIIIiiI1iIiI [ "elp" ] = OO0Oo00oo . elp . print_elp ( False )
  if ( OO0Oo00oo . rle ) : IIIIiiI1iIiI [ "rle" ] = OO0Oo00oo . rle . print_rle ( False , True )
  if ( OO0Oo00oo . json ) : IIIIiiI1iIiI [ "json" ] = OO0Oo00oo . json . print_json ( False )
  if ( OO0Oo00oo . rloc_name ) : IIIIiiI1iIiI [ "rloc-name" ] = OO0Oo00oo . rloc_name
  IIIIiiI1iIiI [ "uptime" ] = lisp_print_elapsed ( OO0Oo00oo . uptime )
  IIIIiiI1iIiI [ "upriority" ] = str ( OO0Oo00oo . priority )
  IIIIiiI1iIiI [ "uweight" ] = str ( OO0Oo00oo . weight )
  IIIIiiI1iIiI [ "mpriority" ] = str ( OO0Oo00oo . mpriority )
  IIIIiiI1iIiI [ "mweight" ] = str ( OO0Oo00oo . mweight )
  if ( OO0Oo00oo . translated_port != 0 ) :
   IIIIiiI1iIiI [ "encap-port" ] = str ( OO0Oo00oo . translated_port )
   if 28 - 28: I1IiiI . ooOoO0o - ooOoO0o * OOooOOo . IiII
   if 16 - 16: iIii1I11I1II1 % i11iIiiIii / Ii1I % iIii1I11I1II1 / iII111i
   if 27 - 27: II111iiii * OoooooooOO / Oo0Ooo % O0
  o0O00ooOo . append ( IIIIiiI1iIiI )
  if 41 - 41: oO0o / iIii1I11I1II1 % iII111i - I1Ii111 % I11i * i11iIiiIii
 Ii [ "registered-rlocs" ] = o0O00ooOo
 if 21 - 21: O0
 data . append ( Ii )
 return ( [ True , data ] )
 if 14 - 14: IiII / I1ii11iIi11i + Ii1I
 if 48 - 48: I1Ii111 * oO0o / o0oOOo0O0Ooo * OoOoOO00 * ooOoO0o
 if 38 - 38: I1IiiI * Ii1I + Oo0Ooo - OoooooooOO
 if 63 - 63: I1ii11iIi11i
 if 99 - 99: I1Ii111 % oO0o - II111iiii . ooOoO0o
 if 26 - 26: I1ii11iIi11i * iII111i . OoooooooOO - Oo0Ooo - IiII
 if 6 - 6: OOooOOo - I1IiiI . IiII
def lisp_process_api_site_cache_entry ( parms ) :
 i1I1iI = parms [ "instance-id" ]
 i1I1iI = 0 if ( i1I1iI == "" ) else int ( i1I1iI )
 if 40 - 40: II111iiii
 if 13 - 13: OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 O0o00o0Oo = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 O0o00o0Oo . store_prefix ( parms [ "eid-prefix" ] )
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 i1I1IIIiII = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 if ( "group-prefix" in parms ) :
  i1I1IIIiII . store_prefix ( parms [ "group-prefix" ] )
  if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
  if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 IiI11I1I111 = [ ]
 ii11i1Ii = lisp_site_eid_lookup ( O0o00o0Oo , i1I1IIIiII , False )
 if ( ii11i1Ii ) : lisp_gather_site_cache_data ( ii11i1Ii , IiI11I1I111 )
 return ( IiI11I1I111 )
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 if 46 - 46: OOooOOo
 if 67 - 67: OoO0O00 . I11i % OOooOOo + Oo0Ooo
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
def lisp_get_interface_instance_id ( device , source_eid ) :
 o0o = None
 if ( device in lisp_myinterfaces ) :
  o0o = lisp_myinterfaces [ device ]
  if 20 - 20: OoooooooOO * OOooOOo
  if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
  if 93 - 93: OoooooooOO / I1Ii111
  if 91 - 91: I1Ii111
  if 18 - 18: ooOoO0o * I11i
  if 53 - 53: I11i . i11iIiiIii - iIii1I11I1II1 / I1Ii111
 if ( o0o == None or o0o . instance_id == None ) :
  return ( lisp_default_iid )
  if 86 - 86: i1IIi % OoO0O00 - OoooooooOO
  if 63 - 63: o0oOOo0O0Ooo . iIii1I11I1II1 % IiII * i11iIiiIii
  if 70 - 70: iIii1I11I1II1
  if 12 - 12: OoOoOO00 / o0oOOo0O0Ooo - I1ii11iIi11i + oO0o + O0
  if 9 - 9: I1ii11iIi11i * OoooooooOO . O0 . ooOoO0o * i11iIiiIii / i1IIi
  if 38 - 38: OoOoOO00 . OoooooooOO % I1ii11iIi11i . oO0o % oO0o
  if 80 - 80: i11iIiiIii / OoOoOO00 . OOooOOo . iIii1I11I1II1
  if 81 - 81: I1ii11iIi11i * OoO0O00 . o0oOOo0O0Ooo . OoooooooOO
  if 64 - 64: Oo0Ooo . I1ii11iIi11i / ooOoO0o % oO0o . iIii1I11I1II1
 i1I1iI = o0o . get_instance_id ( )
 if ( source_eid == None ) : return ( i1I1iI )
 if 84 - 84: II111iiii . oO0o * O0 / iII111i + OoooooooOO
 OOO = source_eid . instance_id
 iiiiiI11iiiI = None
 for o0o in lisp_multi_tenant_interfaces :
  if ( o0o . device != device ) : continue
  o0ooOooO00Oo = o0o . multi_tenant_eid
  source_eid . instance_id = o0ooOooO00Oo . instance_id
  if ( source_eid . is_more_specific ( o0ooOooO00Oo ) == False ) : continue
  if ( iiiiiI11iiiI == None or iiiiiI11iiiI . multi_tenant_eid . mask_len < o0ooOooO00Oo . mask_len ) :
   iiiiiI11iiiI = o0o
   if 61 - 61: I1IiiI + O0 - I1Ii111
   if 56 - 56: I1Ii111 - i1IIi + I11i . i1IIi / II111iiii * oO0o
 source_eid . instance_id = OOO
 if 70 - 70: ooOoO0o - II111iiii . I11i
 if ( iiiiiI11iiiI == None ) : return ( i1I1iI )
 return ( iiiiiI11iiiI . get_instance_id ( ) )
 if 70 - 70: OOooOOo / iII111i - I11i + OoOoOO00 % Ii1I * IiII
 if 26 - 26: O0 / oO0o
 if 96 - 96: ooOoO0o * iII111i . IiII
 if 77 - 77: OOooOOo - I11i % o0oOOo0O0Ooo
 if 46 - 46: I1IiiI % oO0o . OoooooooOO . IiII / I11i - i1IIi
 if 43 - 43: OoOoOO00 - o0oOOo0O0Ooo
 if 22 - 22: i1IIi
 if 33 - 33: O0
 if 34 - 34: I1Ii111 . IiII % iII111i
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( device not in lisp_myinterfaces ) : return ( None )
 if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
 o0o = lisp_myinterfaces [ device ]
 OOoOo = device if o0o . dynamic_eid_device == None else o0o . dynamic_eid_device
 if 74 - 74: o0oOOo0O0Ooo - o0oOOo0O0Ooo . i11iIiiIii - I1Ii111
 if 23 - 23: iIii1I11I1II1 - i1IIi % i1IIi * i11iIiiIii
 if ( o0o . does_dynamic_eid_match ( eid ) ) : return ( OOoOo )
 return ( None )
 if 40 - 40: I1ii11iIi11i + OoO0O00
 if 8 - 8: i11iIiiIii - iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if 25 - 25: iII111i / oO0o
 if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
 if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
 if 61 - 61: I1IiiI / OOooOOo
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 67 - 67: OoOoOO00
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 22 - 22: Ii1I * I1ii11iIi11i * o0oOOo0O0Ooo - I1IiiI . i11iIiiIii
 Ii1Iii1ii1 = lisp_process_rloc_probe_timer
 II1i1II11iiIiii = threading . Timer ( interval , Ii1Iii1ii1 , [ lisp_sockets ] )
 lisp_rloc_probe_timer = II1i1II11iiIiii
 II1i1II11iiIiii . start ( )
 return
 if 20 - 20: OOooOOo * i1IIi / i1IIi + I1IiiI % o0oOOo0O0Ooo
 if 61 - 61: o0oOOo0O0Ooo
 if 39 - 39: I1ii11iIi11i / o0oOOo0O0Ooo / Oo0Ooo * II111iiii - OoO0O00
 if 66 - 66: OoO0O00 / oO0o / I1ii11iIi11i - oO0o
 if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
 if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
 if 96 - 96: Ii1I
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for oO0oOo in lisp_rloc_probe_list :
  o00oo = lisp_rloc_probe_list [ oO0oOo ]
  lprint ( "RLOC {}:" . format ( oO0oOo ) )
  for IIIIiiI1iIiI , oOO , II11iIIii in o00oo :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( IIIIiiI1iIiI ) ) , oOO . print_prefix ( ) ,
 II11iIIii . print_prefix ( ) , IIIIiiI1iIiI . translated_port ) )
   if 95 - 95: Oo0Ooo . iII111i % iII111i / iIii1I11I1II1 * OoO0O00
   if 72 - 72: I1Ii111 - o0oOOo0O0Ooo . II111iiii
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 93 - 93: ooOoO0o
 if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o
 if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
 if 9 - 9: O0 + IiII
 if 69 - 69: I1IiiI
 if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
 if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
 if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
 if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
 if 19 - 19: I1ii11iIi11i
 if 42 - 42: OoOoOO00 / IiII
 OO0Oo00oo , oOO , II11iIIii = eid_list [ 0 ]
 o000O0O0 = [ lisp_print_eid_tuple ( oOO , II11iIIii ) ]
 if 74 - 74: ooOoO0o
 for OO0Oo00oo , oOO , II11iIIii in eid_list [ 1 : : ] :
  OO0Oo00oo . state = LISP_RLOC_UNREACH_STATE
  OO0Oo00oo . last_state_change = lisp_get_timestamp ( )
  o000O0O0 . append ( lisp_print_eid_tuple ( oOO , II11iIIii ) )
  if 93 - 93: Oo0Ooo % ooOoO0o
  if 38 - 38: II111iiii . I1Ii111 . iIii1I11I1II1 / o0oOOo0O0Ooo
 i11iiiii = bold ( "unreachable" , False )
 iIiIi111 = red ( OO0Oo00oo . rloc . print_address_no_iid ( ) , False )
 if 12 - 12: I1ii11iIi11i . OoOoOO00 * I1Ii111 - I1IiiI / oO0o * ooOoO0o
 for O0o00o0Oo in o000O0O0 :
  oOO = green ( O0o00o0Oo , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( iIiIi111 , i11iiiii , oOO ) )
  if 6 - 6: i1IIi % II111iiii % Oo0Ooo + o0oOOo0O0Ooo
  if 61 - 61: I11i / i11iIiiIii
  if 89 - 89: II111iiii
  if 2 - 2: OoOoOO00 . i11iIiiIii
  if 11 - 11: Ii1I
  if 82 - 82: I11i - i1IIi . Oo0Ooo * I1Ii111
 for OO0Oo00oo , oOO , II11iIIii in eid_list :
  Ii111 = lisp_map_cache . lookup_cache ( oOO , True )
  if ( Ii111 ) : lisp_write_ipc_map_cache ( True , Ii111 )
  if 44 - 44: iII111i
 return
 if 56 - 56: II111iiii / Oo0Ooo % IiII * II111iiii - iIii1I11I1II1 + ooOoO0o
 if 33 - 33: o0oOOo0O0Ooo . I11i / I1IiiI
 if 29 - 29: o0oOOo0O0Ooo - ooOoO0o
 if 59 - 59: I11i / IiII * OoO0O00 / IiII . I1Ii111
 if 82 - 82: OOooOOo . iIii1I11I1II1 + I1Ii111
 if 14 - 14: IiII . i11iIiiIii
 if 17 - 17: ooOoO0o % ooOoO0o * oO0o
 if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
def lisp_process_multicast_rloc ( multicast_rloc ) :
 Oo0 = multicast_rloc . rloc . print_address_no_iid ( )
 if 88 - 88: I1IiiI
 oOo0O0ooo0 = lisp_get_timestamp ( )
 for iI1ii11Ii in multicast_rloc . multicast_rloc_probe_list :
  I1IIIIiIii = multicast_rloc . multicast_rloc_probe_list [ iI1ii11Ii ]
  if ( I1IIIIiIii . last_rloc_probe_reply + LISP_RLOC_PROBE_REPLY_WAIT >= oOo0O0ooo0 ) :
   continue
   if 54 - 54: o0oOOo0O0Ooo * OOooOOo / I1Ii111
  if ( I1IIIIiIii . state == LISP_RLOC_UNREACH_STATE ) : continue
  if 1 - 1: o0oOOo0O0Ooo - IiII / OoOoOO00 / OoO0O00 . I1ii11iIi11i % iIii1I11I1II1
  if 51 - 51: I1IiiI % OoOoOO00 . o0oOOo0O0Ooo * I1Ii111 + OoooooooOO
  if 27 - 27: OoOoOO00 - iII111i % OoOoOO00
  if 34 - 34: I1Ii111 . iII111i . iII111i
  I1IIIIiIii . state = LISP_RLOC_UNREACH_STATE
  I1IIIIiIii . last_state_change = lisp_get_timestamp ( )
  if 89 - 89: oO0o / I1ii11iIi11i % I1Ii111
  lprint ( "Multicast-RLOC {} member-RLOC {} went unreachable" . format ( Oo0 , red ( iI1ii11Ii , False ) ) )
  if 86 - 86: Ii1I * II111iiii % ooOoO0o
  if 82 - 82: OOooOOo . Oo0Ooo * ooOoO0o % II111iiii % II111iiii - oO0o
  if 71 - 71: iIii1I11I1II1 % i11iIiiIii . o0oOOo0O0Ooo - oO0o + Oo0Ooo
  if 69 - 69: I1IiiI - OoOoOO00 . I1ii11iIi11i
  if 88 - 88: ooOoO0o + ooOoO0o + oO0o * o0oOOo0O0Ooo . Ii1I
  if 72 - 72: I11i / I11i
  if 78 - 78: I1IiiI % II111iiii
  if 99 - 99: Oo0Ooo
  if 30 - 30: OoOoOO00 + I1Ii111 . OoOoOO00 - I11i
  if 42 - 42: OoOoOO00
  if 77 - 77: Oo0Ooo * IiII * I1ii11iIi11i + IiII
  if 37 - 37: IiII . OoooooooOO - i11iIiiIii * I1ii11iIi11i - OOooOOo
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 74 - 74: Ii1I + i11iIiiIii * iII111i / o0oOOo0O0Ooo . i11iIiiIii
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 99 - 99: OOooOOo - OoooooooOO + OoooooooOO . OOooOOo
 if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
 if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
 if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 78 - 78: OoO0O00 - i1IIi % I1Ii111
 if 87 - 87: I11i
 if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
 if 80 - 80: I1Ii111 % O0 - IiII / II111iiii + i1IIi
 i1iiI1 = lisp_get_default_route_next_hops ( )
 if 20 - 20: i1IIi * IiII % II111iiii + IiII
 iIII11III = "---------- Start RLOC Probing for {} RLOC entries ----------" . format ( len ( lisp_rloc_probe_list ) )
 if 4 - 4: Ii1I + I1ii11iIi11i
 lprint ( bold ( iIII11III , False ) )
 if 40 - 40: OOooOOo % iII111i
 if 5 - 5: O0 + i11iIiiIii . IiII - OOooOOo
 if 51 - 51: OOooOOo . I1IiiI % OoO0O00 . I1IiiI
 if 88 - 88: O0 . iIii1I11I1II1 . iIii1I11I1II1 - ooOoO0o * iIii1I11I1II1 . Oo0Ooo
 III11i1iI11 = 0
 I1III1 = bold ( "RLOC-probe" , False )
 for i1I1i1II11I in list ( lisp_rloc_probe_list . values ( ) ) :
  if 70 - 70: i11iIiiIii - OoO0O00 / i11iIiiIii
  if 46 - 46: II111iiii + O0 * OoooooooOO
  if 39 - 39: OoooooooOO % II111iiii . o0oOOo0O0Ooo
  if 29 - 29: I11i . o0oOOo0O0Ooo . i1IIi . o0oOOo0O0Ooo
  if 77 - 77: iIii1I11I1II1 + iIii1I11I1II1
  OO000oo0O = None
  for Ii1I1IIiii , O0o00o0Oo , i1I1IIIiII in i1I1i1II11I :
   O00oO000Oo0 = Ii1I1IIiii . rloc . print_address_no_iid ( )
   if 97 - 97: I1IiiI % iII111i * oO0o - i1IIi
   if 7 - 7: oO0o / ooOoO0o / IiII - I1ii11iIi11i * IiII % O0
   if 41 - 41: Ii1I + IiII / O0 . iIii1I11I1II1
   if 71 - 71: oO0o / o0oOOo0O0Ooo % iIii1I11I1II1 * iIii1I11I1II1
   IiIii1i , i1IIIIII1 , IIIIIi1I1Ii = lisp_allow_gleaning ( O0o00o0Oo , None , Ii1I1IIiii )
   if ( IiIii1i and i1IIIIII1 == False ) :
    oOO = green ( O0o00o0Oo . print_address ( ) , False )
    O00oO000Oo0 += ":{}" . format ( Ii1I1IIiii . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( O00oO000Oo0 , False ) , oOO ) )
    if 50 - 50: I1ii11iIi11i
    continue
    if 24 - 24: ooOoO0o
    if 19 - 19: oO0o
    if 97 - 97: IiII
    if 36 - 36: II111iiii
    if 83 - 83: I11i . ooOoO0o
    if 57 - 57: IiII
    if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
   if ( Ii1I1IIiii . down_state ( ) ) : continue
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
   if ( OO000oo0O ) :
    Ii1I1IIiii . last_rloc_probe_nonce = OO000oo0O . last_rloc_probe_nonce
    if ( OO000oo0O . translated_port == Ii1I1IIiii . translated_port and OO000oo0O . rloc_name == Ii1I1IIiii . rloc_name ) :
     if 4 - 4: i1IIi
     oOO = green ( lisp_print_eid_tuple ( O0o00o0Oo , i1I1IIIiII ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( O00oO000Oo0 , False ) , oOO ) )
     if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
     if 6 - 6: Ii1I / iII111i
     if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
     if 70 - 70: oO0o - I1IiiI + Ii1I
     if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
     if 37 - 37: o0oOOo0O0Ooo
     Ii1I1IIiii . last_rloc_probe = OO000oo0O . last_rloc_probe
     continue
     if 57 - 57: iII111i / i1IIi / i1IIi + IiII
     if 75 - 75: IiII / O0
     if 72 - 72: I11i
     if 35 - 35: I11i % OoooooooOO / i1IIi * i1IIi / I1IiiI
     if 42 - 42: I11i - i1IIi - oO0o / I11i + Ii1I + ooOoO0o
     if 23 - 23: OoOoOO00 . oO0o - iII111i
     if 27 - 27: Oo0Ooo * OOooOOo - OoOoOO00
     if 1 - 1: II111iiii * i11iIiiIii . OoooooooOO
   OO0Oo00oo = None
   while ( True ) :
    OO0Oo00oo = Ii1I1IIiii if OO0Oo00oo == None else OO0Oo00oo . next_rloc
    if ( OO0Oo00oo == None ) : break
    if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
    if 57 - 57: I1Ii111 . OOooOOo + I1Ii111 . iIii1I11I1II1 / oO0o / O0
    if 88 - 88: I1Ii111
    if 16 - 16: Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . OoooooooOO * OoO0O00
    if 50 - 50: II111iiii + I11i . OoooooooOO . I1Ii111 - OOooOOo
    if ( OO0Oo00oo . rloc_next_hop != None ) :
     if ( OO0Oo00oo . rloc_next_hop not in i1iiI1 ) :
      oooOo , IIiI1 = OO0Oo00oo . rloc_next_hop
      if ( OO0Oo00oo . up_state ( ) ) :
       OO0Oo00oo . state = LISP_RLOC_UNREACH_STATE
       OO0Oo00oo . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( OO0Oo00oo . rloc , False )
       if 83 - 83: oO0o
      i11iiiii = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( IIiI1 , oooOo ,
 red ( O00oO000Oo0 , False ) , i11iiiii ) )
      continue
      if 100 - 100: I1Ii111 + o0oOOo0O0Ooo * oO0o / oO0o . oO0o + iII111i
      if 71 - 71: II111iiii + iII111i + O0 % Oo0Ooo / I1IiiI
      if 52 - 52: Oo0Ooo . I1Ii111 * i1IIi / Oo0Ooo / OoO0O00
      if 29 - 29: iII111i
      if 91 - 91: Oo0Ooo - IiII
      if 47 - 47: iII111i / OOooOOo + iII111i
    i1IIIi111111 = OO0Oo00oo . last_rloc_probe
    oOo00o = 0 if i1IIIi111111 == None else time . time ( ) - i1IIIi111111
    if ( OO0Oo00oo . unreach_state ( ) and oOo00o < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( O00oO000Oo0 , False ) ) )
     if 42 - 42: i1IIi . I1Ii111 - ooOoO0o + I11i / oO0o
     continue
     if 60 - 60: i1IIi + OoooooooOO % i11iIiiIii / IiII % Oo0Ooo + I1IiiI
     if 87 - 87: Ii1I % OoooooooOO % I1Ii111 * i11iIiiIii * OoOoOO00
     if 78 - 78: I11i
     if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
     if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
     if 71 - 71: I11i * I1ii11iIi11i * OOooOOo * o0oOOo0O0Ooo
    o0Oo00oOOo = lisp_get_echo_nonce ( None , O00oO000Oo0 )
    if ( o0Oo00oOOo and o0Oo00oOOo . request_nonce_timeout ( ) ) :
     OO0Oo00oo . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     OO0Oo00oo . last_state_change = lisp_get_timestamp ( )
     i11iiiii = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( O00oO000Oo0 , False ) , i11iiiii ) )
     if 53 - 53: I1IiiI % I1IiiI
     lisp_update_rtr_updown ( OO0Oo00oo . rloc , False )
     continue
     if 80 - 80: OoO0O00 - i11iIiiIii / iII111i * I1ii11iIi11i / I1IiiI - I1Ii111
     if 85 - 85: IiII
     if 72 - 72: iII111i * OoOoOO00
     if 65 - 65: iIii1I11I1II1 / iIii1I11I1II1 % O0 / II111iiii . OOooOOo . O0
     if 65 - 65: I11i
     if 35 - 35: o0oOOo0O0Ooo - i11iIiiIii
    if ( o0Oo00oOOo and o0Oo00oOOo . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( O00oO000Oo0 , False ) ) )
     if 78 - 78: ooOoO0o - II111iiii - i1IIi
     continue
     if 18 - 18: OoooooooOO % OoOoOO00 - IiII / oO0o . OOooOOo . I1IiiI
     if 77 - 77: I1ii11iIi11i . OoO0O00 / OoOoOO00 / O0
     if 67 - 67: ooOoO0o % I11i % oO0o
     if 74 - 74: II111iiii
     if 44 - 44: Oo0Ooo + OoO0O00 + OoOoOO00 - I1IiiI
     if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
    if ( OO0Oo00oo . last_rloc_probe != None ) :
     i1IIIi111111 = OO0Oo00oo . last_rloc_probe_reply
     if ( i1IIIi111111 == None ) : i1IIIi111111 = 0
     oOo00o = time . time ( ) - i1IIIi111111
     if ( OO0Oo00oo . up_state ( ) and oOo00o >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
      OO0Oo00oo . state = LISP_RLOC_UNREACH_STATE
      OO0Oo00oo . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( OO0Oo00oo . rloc , False )
      i11iiiii = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( O00oO000Oo0 , False ) , i11iiiii ) )
      if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
      if 20 - 20: I1IiiI + iII111i + O0 * O0
      lisp_mark_rlocs_for_other_eids ( i1I1i1II11I )
      if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
      if 31 - 31: ooOoO0o
      if 87 - 87: OoooooooOO + OOooOOo - I1ii11iIi11i / I1IiiI + ooOoO0o - Oo0Ooo
    OO0Oo00oo . last_rloc_probe = lisp_get_timestamp ( )
    if 19 - 19: ooOoO0o + I1ii11iIi11i - ooOoO0o
    I1Ii1iiIII1i = "" if OO0Oo00oo . unreach_state ( ) == False else " unreachable"
    if 32 - 32: Oo0Ooo % O0 * I1Ii111 . I11i - OoO0O00
    if 22 - 22: I1IiiI * I1IiiI / iIii1I11I1II1 . o0oOOo0O0Ooo - I1ii11iIi11i
    if 53 - 53: iIii1I11I1II1 * II111iiii
    if 52 - 52: I11i / iIii1I11I1II1
    if 69 - 69: ooOoO0o . i1IIi * I1IiiI . I1Ii111 % OoOoOO00 % OoooooooOO
    if 81 - 81: ooOoO0o - II111iiii
    if 26 - 26: I1IiiI
    IIIiI1IiIiii = ""
    i1iiI = None
    if 58 - 58: i1IIi / I11i * OoooooooOO - iII111i / iIii1I11I1II1 % O0
    if 21 - 21: IiII - i1IIi % i11iIiiIii . o0oOOo0O0Ooo
    if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
    if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
    if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
    if 23 - 23: Ii1I % i1IIi - I1Ii111
    if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
    if ( OO0Oo00oo . rloc_next_hop != None ) :
     oooOo , i1IIIII = OO0Oo00oo . rloc_next_hop
     i1iiI = oooOo
     OO0Oo00oo . set_active_rloc_next_hop ( )
     IIIiI1IiIiii = ", send to nh {} on {}" . format ( i1IIIII , bold ( oooOo , False ) )
     if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
     if 11 - 11: IiII / I1IiiI . I1IiiI
     if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
     if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
     if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
     if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
     OO0Oo00oo . probing_itr_rloc = lisp_get_interface_address ( oooOo )
     if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
     if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
     if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
     if 3 - 3: I1Ii111
     if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
    if ( i1iiI ) : lisp_bind_interface ( lisp_sockets [ 3 ] , i1iiI )
    if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
    if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
    if 55 - 55: OoooooooOO / IiII + i1IIi
    if 54 - 54: ooOoO0o * Ii1I / Ii1I
    I1IIiiI1Ii = OO0Oo00oo . print_rloc_probe_rtt ( )
    iI1iII11I1ii1 = O00oO000Oo0
    if ( OO0Oo00oo . translated_port != 0 ) :
     iI1iII11I1ii1 += ":{}" . format ( OO0Oo00oo . translated_port )
     if 24 - 24: o0oOOo0O0Ooo + OoooooooOO + Oo0Ooo
    iI1iII11I1ii1 = red ( iI1iII11I1ii1 , False )
    if ( OO0Oo00oo . rloc_name != None ) :
     iI1iII11I1ii1 += " (" + blue ( OO0Oo00oo . rloc_name , False ) + ")"
     if 61 - 61: I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo
    lprint ( "Send {} to{} {}, last rtt: {}{}" . format ( I1III1 , I1Ii1iiIII1i ,
 iI1iII11I1ii1 , I1IIiiI1Ii , IIIiI1IiIiii ) )
    if 40 - 40: OOooOOo - i11iIiiIii - I11i . i1IIi * o0oOOo0O0Ooo
    if 2 - 2: I1ii11iIi11i * IiII
    if 64 - 64: OoooooooOO % OoooooooOO
    if 45 - 45: I1IiiI % I11i - I11i % i1IIi . Ii1I
    if 16 - 16: OoooooooOO
    if ( OO0Oo00oo . rloc . is_null ( ) ) :
     OO0Oo00oo . rloc . copy_address ( Ii1I1IIiii . rloc )
     if 21 - 21: iII111i % OOooOOo . o0oOOo0O0Ooo % iII111i
     if 98 - 98: Oo0Ooo . Oo0Ooo - ooOoO0o % oO0o / iII111i
     if 14 - 14: ooOoO0o
     if 19 - 19: i1IIi - iIii1I11I1II1 * I1ii11iIi11i - O0 % OOooOOo
     if 17 - 17: I1Ii111 . ooOoO0o
    if ( OO0Oo00oo . multicast_rloc_probe_list != { } ) :
     lisp_process_multicast_rloc ( OO0Oo00oo )
     if 34 - 34: o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
     if 72 - 72: IiII / II111iiii
     if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
     if 21 - 21: I1ii11iIi11i
     if 60 - 60: i1IIi / OoO0O00 . Ii1I
    oo0Oo = None if ( i1I1IIIiII . is_null ( ) ) else O0o00o0Oo
    Ii1III1 = O0o00o0Oo if ( i1I1IIIiII . is_null ( ) ) else i1I1IIIiII
    lisp_send_map_request ( lisp_sockets , 0 , oo0Oo , Ii1III1 , OO0Oo00oo )
    OO000oo0O = Ii1I1IIiii
    if 56 - 56: I1Ii111 % II111iiii
    if 11 - 11: i11iIiiIii / OoO0O00 * OoO0O00 . I1Ii111 - OOooOOo
    if 12 - 12: OOooOOo . OoOoOO00 % ooOoO0o
    if 100 - 100: OoOoOO00 . iII111i
    if ( i1iiI ) : lisp_unbind_interface ( lisp_sockets [ 3 ] )
    if 50 - 50: iIii1I11I1II1 * OOooOOo . I1IiiI . OoOoOO00 - O0 + Oo0Ooo
    if 89 - 89: IiII - iII111i + IiII
    if 39 - 39: oO0o % I11i . oO0o * I11i
    if 36 - 36: i1IIi / I1ii11iIi11i * iIii1I11I1II1
    if 44 - 44: Ii1I / I1Ii111
    if 81 - 81: OoooooooOO * I1IiiI * II111iiii . Oo0Ooo
    if ( OO0Oo00oo . is_decent_nat_port ( ) and OO0Oo00oo . unreach_state ( ) ) :
     OO0Oo00oo . refresh_decent_nat_rloc ( lisp_sockets , Ii1III1 )
     if 28 - 28: iII111i * I1IiiI + Oo0Ooo % I1ii11iIi11i / OoooooooOO * ooOoO0o
     if 45 - 45: OoO0O00 + iIii1I11I1II1 + ooOoO0o - OoO0O00
     if 22 - 22: I1IiiI
     if 28 - 28: OoO0O00 / ooOoO0o % OoOoOO00 - Ii1I * i11iIiiIii + I1ii11iIi11i
     if 90 - 90: ooOoO0o * o0oOOo0O0Ooo + Ii1I / I11i % II111iiii
     if 59 - 59: I11i + iII111i + I11i
   III11i1iI11 += 1
   if ( ( III11i1iI11 % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 84 - 84: I1IiiI * Ii1I . I1IiiI % OOooOOo * Ii1I % OoO0O00
   if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
   if 42 - 42: oO0o / i1IIi . IiII
 lprint ( bold ( "---------- End RLOC Probing ----------" , False ) )
 return
 if 12 - 12: i11iIiiIii . ooOoO0o
 if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
 if 88 - 88: OoooooooOO . I1IiiI
 if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 if 7 - 7: i1IIi
 if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
 if 34 - 34: iII111i + i11iIiiIii . IiII
 if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 29 - 29: II111iiii % i11iIiiIii % O0
 if 38 - 38: o0oOOo0O0Ooo * IiII
 if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
 if ( lisp_i_am_itr == False ) : return
 if 19 - 19: OoooooooOO
 if 34 - 34: OoOoOO00 . oO0o
 if 53 - 53: oO0o + OoooooooOO * ooOoO0o
 if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
 if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
 if ( lisp_register_all_rtrs ) : return
 if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
 ooo = rtr . print_address_no_iid ( )
 if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
 if 33 - 33: iIii1I11I1II1
 if 52 - 52: iIii1I11I1II1 + O0
 if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 if 32 - 32: OoO0O00 + OoO0O00 % o0oOOo0O0Ooo / O0
 if ( ooo not in lisp_rtr_list ) : return
 if 29 - 29: iII111i % I1Ii111
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( ooo , False ) , bold ( updown , False ) ) )
 if 95 - 95: OOooOOo - ooOoO0o % i1IIi / O0 % I11i . IiII
 if 63 - 63: ooOoO0o
 if 22 - 22: OOooOOo . i11iIiiIii + II111iiii - Oo0Ooo % i1IIi / o0oOOo0O0Ooo
 if 90 - 90: IiII
 OO0oOOOOO = "rtr%{}%{}" . format ( ooo , updown )
 OO0oOOOOO = lisp_command_ipc ( OO0oOOOOO , "lisp-itr" )
 lisp_ipc ( OO0oOOOOO , lisp_ipc_socket , "lisp-etr" )
 return
 if 38 - 38: i1IIi / ooOoO0o / I11i * I1ii11iIi11i / II111iiii . iIii1I11I1II1
 if 52 - 52: I1ii11iIi11i % ooOoO0o * Ii1I * IiII + IiII / i11iIiiIii
 if 51 - 51: iIii1I11I1II1 * o0oOOo0O0Ooo % o0oOOo0O0Ooo . Ii1I / OoooooooOO
 if 23 - 23: oO0o * I1IiiI - oO0o - ooOoO0o . IiII / i11iIiiIii
 if 53 - 53: Ii1I * Ii1I . OoOoOO00 . OOooOOo / I1ii11iIi11i % O0
 if 98 - 98: OOooOOo
 if 11 - 11: OOooOOo * iIii1I11I1II1 % IiII - I1IiiI . I11i
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl , mrloc , rloc_name ) :
 global lisp_rloc_probe_nonce_list
 if 29 - 29: OOooOOo % I11i - OOooOOo - OOooOOo * I11i . oO0o
 OO0Oo00oo = rloc_entry . rloc
 OOooO = map_reply . nonce
 Ooi1iiiIII11Ii = map_reply . hop_count
 I1III1 = bold ( "RLOC-probe reply" , False )
 oO0O0ooO = OO0Oo00oo . print_address_no_iid ( )
 OoO = source . print_address_no_iid ( )
 IiIiiIiI1i = lisp_rloc_probe_list
 OOI1I1 = rloc_entry . json . json_string if rloc_entry . json else None
 iIiIIIIIii = lisp_get_timestamp ( )
 if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
 if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
 if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
 if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
 if 59 - 59: iII111i
 if 14 - 14: oO0o . IiII + iIii1I11I1II1 - i1IIi
 if ( mrloc != None ) :
  Iiii1i1iIii1 = mrloc . rloc . print_address_no_iid ( )
  if ( oO0O0ooO not in mrloc . multicast_rloc_probe_list ) :
   ooO0oo = lisp_rloc ( )
   ooO0oo = copy . deepcopy ( mrloc )
   ooO0oo . rloc . copy_address ( OO0Oo00oo )
   ooO0oo . multicast_rloc_probe_list = { }
   mrloc . multicast_rloc_probe_list [ oO0O0ooO ] = ooO0oo
   if 95 - 95: I1Ii111 * o0oOOo0O0Ooo + OoO0O00 % OoOoOO00 - ooOoO0o / OoOoOO00
  ooO0oo = mrloc . multicast_rloc_probe_list [ oO0O0ooO ]
  ooO0oo . rloc_name = rloc_name
  ooO0oo . last_rloc_probe_nonce = mrloc . last_rloc_probe_nonce
  ooO0oo . last_rloc_probe = mrloc . last_rloc_probe
  IIIIiiI1iIiI , O0o00o0Oo , i1I1IIIiII = lisp_rloc_probe_list [ Iiii1i1iIii1 ] [ 0 ]
  ooO0oo . process_rloc_probe_reply ( iIiIIIIIii , OOooO , O0o00o0Oo , i1I1IIIiII , Ooi1iiiIII11Ii , ttl , OOI1I1 )
  mrloc . process_rloc_probe_reply ( iIiIIIIIii , OOooO , O0o00o0Oo , i1I1IIIiII , Ooi1iiiIII11Ii , ttl , OOI1I1 )
  return
  if 45 - 45: OoooooooOO / oO0o / o0oOOo0O0Ooo + Ii1I + O0 . iII111i
  if 34 - 34: iIii1I11I1II1 . o0oOOo0O0Ooo + ooOoO0o
  if 96 - 96: O0 / ooOoO0o
  if 82 - 82: OoO0O00 * OOooOOo * I11i * I1Ii111 % iIii1I11I1II1
  if 50 - 50: Ii1I * Ii1I % I11i / iIii1I11I1II1 / ooOoO0o / iII111i
  if 91 - 91: Ii1I - O0 . I11i - OoooooooOO * IiII . II111iiii
 if ( rloc_name and rloc_name . find ( LISP_TP ) != - 1 ) :
  port = int ( rloc_name . split ( LISP_TP ) [ - 1 ] )
  if 38 - 38: I1IiiI + OoO0O00
  if 11 - 11: iIii1I11I1II1 + i1IIi * IiII - Oo0Ooo
  if 66 - 66: I1Ii111 . Ii1I / I1ii11iIi11i / iIii1I11I1II1 + O0 / i1IIi
  if 72 - 72: ooOoO0o . II111iiii
  if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
  if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
  if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
 iI1ii11Ii = oO0O0ooO
 if ( iI1ii11Ii not in IiIiiIiI1i ) :
  iI1ii11Ii += ":" + str ( port )
  if ( iI1ii11Ii not in IiIiiIiI1i ) :
   iI1ii11Ii = OoO
   if ( iI1ii11Ii not in IiIiiIiI1i ) :
    iI1ii11Ii += ":" + str ( port )
    if ( iI1ii11Ii not in IiIiiIiI1i ) :
     lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( I1III1 , red ( oO0O0ooO , False ) , red ( OoO , False ) , port ) )
     if 18 - 18: o0oOOo0O0Ooo / OOooOOo
     return
     if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
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
 if ( OOooO in lisp_rloc_probe_nonce_list ) :
  oo0o0 = lisp_rloc_probe_nonce_list . pop ( OOooO )
  if ( oo0o0 != iI1ii11Ii ) :
   iI1ii11Ii = oo0o0
   lprint ( "    Obtain probed RLOC address {} from nonce 0x{}" . format ( iI1ii11Ii , lisp_hex_string ( OOooO ) ) )
   if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
   if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
   if 89 - 89: O0 * ooOoO0o
   if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
   if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
   if 82 - 82: iII111i * iII111i . IiII * II111iiii
   if 17 - 17: OoooooooOO % I1Ii111 * I1Ii111 / II111iiii . OoOoOO00 * iII111i
   if 80 - 80: IiII % i11iIiiIii
 if ( iI1ii11Ii not in lisp_rloc_probe_list ) : return
 if 6 - 6: II111iiii + i11iIiiIii - Oo0Ooo % OOooOOo + Oo0Ooo
 if 46 - 46: iII111i
 if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
 if 11 - 11: ooOoO0o - OoOoOO00
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 OOOO0OOoO0 = None
 for OO0Oo00oo , O0o00o0Oo , i1I1IIIiII in lisp_rloc_probe_list [ iI1ii11Ii ] :
  if ( lisp_i_am_rtr ) :
   if ( OO0Oo00oo . translated_port != 0 and OO0Oo00oo . translated_port != port ) :
    continue
    if 98 - 98: II111iiii
    if 56 - 56: i1IIi % IiII / I1Ii111
  OOOOoo0o0O0 = OO0Oo00oo . process_rloc_probe_reply ( iIiIIIIIii , OOooO , O0o00o0Oo , i1I1IIIiII , Ooi1iiiIII11Ii , ttl , OOI1I1 )
  if 1 - 1: I1IiiI / OoOoOO00 - oO0o + OoooooooOO
  if 51 - 51: ooOoO0o + Ii1I * o0oOOo0O0Ooo * I1IiiI / oO0o + OoO0O00
  if 92 - 92: oO0o * o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * OoooooooOO * Oo0Ooo
  if 86 - 86: iII111i / OoooooooOO * I1Ii111 % I1IiiI + Ii1I
  if 16 - 16: OoO0O00
  if ( OOOOoo0o0O0 and OOOO0OOoO0 == None ) :
   i1Ii = OO0Oo00oo
   while ( i1Ii != None ) :
    if ( i1Ii . last_rloc_probe_nonce == OOooO ) :
     OOOO0OOoO0 = i1Ii
     break
     if 16 - 16: O0 . OoOoOO00 . iII111i + Oo0Ooo
    i1Ii = i1Ii . next_rloc
    if 89 - 89: I11i - OoO0O00 . IiII - OoO0O00 - I1ii11iIi11i % I1IiiI
    if 45 - 45: I1Ii111 + I1ii11iIi11i + Ii1I % Ii1I
    if 94 - 94: OoO0O00
 if ( OOOO0OOoO0 == None ) : return
 if ( OOOO0OOoO0 . rloc_next_hop == None ) : return
 if 78 - 78: iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1ii11iIi11i / I1ii11iIi11i + IiII
 if 92 - 92: i11iIiiIii * iII111i
 if 9 - 9: O0 * IiII / Ii1I + OoO0O00
 if 75 - 75: OOooOOo * OoOoOO00
 if 82 - 82: Ii1I
 if 83 - 83: I1IiiI
 I1I1 = OOOO0OOoO0 . rloc_next_hop
 for Ii1I1IIiii , O0o00o0Oo , i1I1IIIiII in lisp_rloc_probe_list [ iI1ii11Ii ] :
  if 67 - 67: I11i . I11i % I11i + Ii1I + Oo0Ooo - I1ii11iIi11i
  if 87 - 87: I1ii11iIi11i / iIii1I11I1II1 % OoooooooOO
  if 15 - 15: iIii1I11I1II1 % I1ii11iIi11i + Oo0Ooo
  if 18 - 18: I1Ii111 + OoooooooOO . I1IiiI - I1ii11iIi11i . I1Ii111
  if 81 - 81: IiII . ooOoO0o + O0 . ooOoO0o + iIii1I11I1II1
  O000oOooO0oo = Ii1I1IIiii
  i1Ii = Ii1I1IIiii
  while ( i1Ii != None ) :
   if ( i1Ii . rloc_next_hop == I1I1 ) :
    O000oOooO0oo = i1Ii
    break
    if 68 - 68: i11iIiiIii . iII111i + OoooooooOO + II111iiii + iIii1I11I1II1 % I11i
   i1Ii = i1Ii . next_rloc
   if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
   if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
   if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
   if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
   if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
  if ( O000oOooO0oo != OOOO0OOoO0 ) :
   O000oOooO0oo . copy_rloc_probe_recents ( OOOO0OOoO0 )
   if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
   if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 return
 if 9 - 9: i1IIi % iII111i / Ii1I
 if 83 - 83: oO0o
 if 1 - 1: oO0o * iIii1I11I1II1 % iIii1I11I1II1 % iIii1I11I1II1 / oO0o + IiII
 if 29 - 29: OoooooooOO
 if 55 - 55: O0 - o0oOOo0O0Ooo % I1ii11iIi11i * I11i * oO0o
 if 83 - 83: iIii1I11I1II1
 if 92 - 92: OoO0O00 - iII111i
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
def lisp_db_list_length ( ) :
 III11i1iI11 = 0
 for Iiii1II1 in lisp_db_list :
  III11i1iI11 += len ( Iiii1II1 . dynamic_eids ) if Iiii1II1 . dynamic_eid_configured ( ) else 1
  III11i1iI11 += len ( Iiii1II1 . eid . iid_list )
  if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
 return ( III11i1iI11 )
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 if 74 - 74: i1IIi % i11iIiiIii + oO0o
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
 if 97 - 97: I11i
 if 89 - 89: iII111i % OoOoOO00 . Oo0Ooo
 if 20 - 20: oO0o % OoOoOO00
def lisp_is_myeid ( eid ) :
 for Iiii1II1 in lisp_db_list :
  if ( eid . is_more_specific ( Iiii1II1 . eid ) ) : return ( True )
  if 93 - 93: I1ii11iIi11i - Ii1I % i1IIi / i1IIi
 return ( False )
 if 82 - 82: OOooOOo
 if 27 - 27: I1Ii111 / IiII - i1IIi * Ii1I
 if 90 - 90: ooOoO0o
 if 100 - 100: iII111i * i1IIi . iII111i / O0 / OoO0O00 - oO0o
 if 65 - 65: OoOoOO00 + ooOoO0o * OoO0O00 % OoooooooOO + OoooooooOO * OoooooooOO
 if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
 if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
 if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
 if 55 - 55: Oo0Ooo - OOooOOo - O0
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 40 - 40: OoOoOO00 - OOooOOo
 if 3 - 3: IiII % I11i * I1Ii111 + iIii1I11I1II1 . oO0o
 if 35 - 35: II111iiii
 if 15 - 15: I11i * iIii1I11I1II1 + OOooOOo % IiII . o0oOOo0O0Ooo % Oo0Ooo
 if 96 - 96: O0
 if 15 - 15: i1IIi . iIii1I11I1II1
 if 3 - 3: II111iiii * i11iIiiIii * i1IIi - i1IIi
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 11 - 11: I1IiiI % Ii1I * i11iIiiIii % OOooOOo + II111iiii
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 o0Oo00oOOo = None
 if ( rloc_str in lisp_nonce_echo_list ) :
  o0Oo00oOOo = lisp_nonce_echo_list [ rloc_str ]
  if 61 - 61: I1Ii111 + I11i + I1IiiI
 return ( o0Oo00oOOo )
 if 48 - 48: I11i
 if 67 - 67: o0oOOo0O0Ooo
 if 36 - 36: IiII - I11i - Ii1I / OoOoOO00 % OoO0O00 * iIii1I11I1II1
 if 61 - 61: i11iIiiIii / Ii1I - OOooOOo . I1ii11iIi11i
 if 89 - 89: ooOoO0o % i11iIiiIii
 if 57 - 57: Oo0Ooo / ooOoO0o - O0 . ooOoO0o
 if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
 if 75 - 75: Ii1I
def lisp_decode_dist_name ( packet ) :
 III11i1iI11 = 0
 OoOOo0 = b""
 if 32 - 32: ooOoO0o * OoO0O00 - I11i - OoooooooOO % i1IIi
 while ( packet [ 0 : 1 ] != b"\x00" ) :
  if ( III11i1iI11 == 255 ) : return ( [ None , None ] )
  OoOOo0 += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  III11i1iI11 += 1
  if 81 - 81: OOooOOo * O0 + II111iiii . Oo0Ooo
  if 52 - 52: I1IiiI . oO0o % O0
 packet = packet [ 1 : : ]
 return ( packet , OoOOo0 . decode ( ) )
 if 42 - 42: I1Ii111
 if 81 - 81: I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - O0 * iII111i
 if 35 - 35: OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111 * OoO0O00
 if 78 - 78: iIii1I11I1II1 + I11i - OoOoOO00 / I1ii11iIi11i + iIii1I11I1II1 % II111iiii
 if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
 if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
 if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
 if 53 - 53: Ii1I
def lisp_write_flow_log ( flow_log ) :
 iIi1iii = open ( "./logs/lisp-flow.log" , "a" )
 if 63 - 63: I11i % OoOoOO00
 III11i1iI11 = 0
 for i1I111Iii in flow_log :
  Oo00O0o0O = i1I111Iii [ 3 ]
  IiiI111 = Oo00O0o0O . print_flow ( i1I111Iii [ 0 ] , i1I111Iii [ 1 ] , i1I111Iii [ 2 ] )
  iIi1iii . write ( IiiI111 )
  III11i1iI11 += 1
  if 52 - 52: I11i + iII111i
 iIi1iii . close ( )
 del ( flow_log )
 if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
 III11i1iI11 = bold ( str ( III11i1iI11 ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( III11i1iI11 ) )
 return
 if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
 if 62 - 62: IiII . O0
 if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
 if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
 if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
 if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
 if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
def lisp_policy_command ( kv_pair ) :
 ooo0OO0OOooO0 = lisp_policy ( "" )
 iI11Ii = None
 if 7 - 7: OoO0O00 * I1ii11iIi11i / I1Ii111
 ooOO000OOO = [ ]
 for o000o0O0Oo00 in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  ooOO000OOO . append ( lisp_policy_match ( ) )
  if 65 - 65: Oo0Ooo
  if 66 - 66: iII111i . I1ii11iIi11i - Oo0Ooo
 for o0oOoo in list ( kv_pair . keys ( ) ) :
  oO00o = kv_pair [ o0oOoo ]
  if 56 - 56: IiII
  if 5 - 5: I1ii11iIi11i * iII111i + II111iiii * Oo0Ooo * O0 - I1IiiI
  if 71 - 71: i11iIiiIii % I1IiiI + I1ii11iIi11i + II111iiii + OoooooooOO + oO0o
  if 12 - 12: I1IiiI + I1Ii111
  if ( o0oOoo == "instance-id" ) :
   for o000o0O0Oo00 in range ( len ( ooOO000OOO ) ) :
    O0O0o00 = oO00o [ o000o0O0Oo00 ]
    if ( O0O0o00 == "" ) : continue
    iI111i1Ii = ooOO000OOO [ o000o0O0Oo00 ]
    if ( iI111i1Ii . source_eid == None ) :
     iI111i1Ii . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 47 - 47: Oo0Ooo - i1IIi % Ii1I + IiII
    if ( iI111i1Ii . dest_eid == None ) :
     iI111i1Ii . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
    iI111i1Ii . source_eid . instance_id = int ( O0O0o00 )
    iI111i1Ii . dest_eid . instance_id = int ( O0O0o00 )
    if 98 - 98: I1ii11iIi11i
    if 58 - 58: IiII / i11iIiiIii % I11i
  if ( o0oOoo == "source-eid" ) :
   for o000o0O0Oo00 in range ( len ( ooOO000OOO ) ) :
    O0O0o00 = oO00o [ o000o0O0Oo00 ]
    if ( O0O0o00 == "" ) : continue
    iI111i1Ii = ooOO000OOO [ o000o0O0Oo00 ]
    if ( iI111i1Ii . source_eid == None ) :
     iI111i1Ii . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
    i1I1iI = iI111i1Ii . source_eid . instance_id
    iI111i1Ii . source_eid . store_prefix ( O0O0o00 )
    iI111i1Ii . source_eid . instance_id = i1I1iI
    if 21 - 21: Ii1I
    if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
  if ( o0oOoo == "destination-eid" ) :
   for o000o0O0Oo00 in range ( len ( ooOO000OOO ) ) :
    O0O0o00 = oO00o [ o000o0O0Oo00 ]
    if ( O0O0o00 == "" ) : continue
    iI111i1Ii = ooOO000OOO [ o000o0O0Oo00 ]
    if ( iI111i1Ii . dest_eid == None ) :
     iI111i1Ii . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
    i1I1iI = iI111i1Ii . dest_eid . instance_id
    iI111i1Ii . dest_eid . store_prefix ( O0O0o00 )
    iI111i1Ii . dest_eid . instance_id = i1I1iI
    if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
    if 59 - 59: i1IIi * OOooOOo % Oo0Ooo
  if ( o0oOoo == "source-rloc" ) :
   for o000o0O0Oo00 in range ( len ( ooOO000OOO ) ) :
    O0O0o00 = oO00o [ o000o0O0Oo00 ]
    if ( O0O0o00 == "" ) : continue
    iI111i1Ii = ooOO000OOO [ o000o0O0Oo00 ]
    iI111i1Ii . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    iI111i1Ii . source_rloc . store_prefix ( O0O0o00 )
    if 44 - 44: iIii1I11I1II1 . OOooOOo
    if 57 - 57: II111iiii + I1Ii111
  if ( o0oOoo == "destination-rloc" ) :
   for o000o0O0Oo00 in range ( len ( ooOO000OOO ) ) :
    O0O0o00 = oO00o [ o000o0O0Oo00 ]
    if ( O0O0o00 == "" ) : continue
    iI111i1Ii = ooOO000OOO [ o000o0O0Oo00 ]
    iI111i1Ii . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    iI111i1Ii . dest_rloc . store_prefix ( O0O0o00 )
    if 42 - 42: OoOoOO00 % O0
    if 70 - 70: iIii1I11I1II1 * Oo0Ooo - I1IiiI / OoO0O00 + OoOoOO00
  if ( o0oOoo == "rloc-record-name" ) :
   for o000o0O0Oo00 in range ( len ( ooOO000OOO ) ) :
    O0O0o00 = oO00o [ o000o0O0Oo00 ]
    if ( O0O0o00 == "" ) : continue
    iI111i1Ii = ooOO000OOO [ o000o0O0Oo00 ]
    iI111i1Ii . rloc_record_name = O0O0o00
    if 94 - 94: OoooooooOO + O0 * iIii1I11I1II1 * II111iiii
    if 90 - 90: I11i + O0 / I1IiiI . oO0o / O0
  if ( o0oOoo == "geo-name" ) :
   for o000o0O0Oo00 in range ( len ( ooOO000OOO ) ) :
    O0O0o00 = oO00o [ o000o0O0Oo00 ]
    if ( O0O0o00 == "" ) : continue
    iI111i1Ii = ooOO000OOO [ o000o0O0Oo00 ]
    iI111i1Ii . geo_name = O0O0o00
    if 46 - 46: O0 . O0 - oO0o . II111iiii * I1IiiI * Ii1I
    if 10 - 10: i1IIi + i1IIi . i1IIi - I1IiiI - I1IiiI
  if ( o0oOoo == "elp-name" ) :
   for o000o0O0Oo00 in range ( len ( ooOO000OOO ) ) :
    O0O0o00 = oO00o [ o000o0O0Oo00 ]
    if ( O0O0o00 == "" ) : continue
    iI111i1Ii = ooOO000OOO [ o000o0O0Oo00 ]
    iI111i1Ii . elp_name = O0O0o00
    if 26 - 26: Ii1I * I11i / I11i
    if 79 - 79: ooOoO0o / oO0o - oO0o / OoooooooOO
  if ( o0oOoo == "rle-name" ) :
   for o000o0O0Oo00 in range ( len ( ooOO000OOO ) ) :
    O0O0o00 = oO00o [ o000o0O0Oo00 ]
    if ( O0O0o00 == "" ) : continue
    iI111i1Ii = ooOO000OOO [ o000o0O0Oo00 ]
    iI111i1Ii . rle_name = O0O0o00
    if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
    if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
  if ( o0oOoo == "json-name" ) :
   for o000o0O0Oo00 in range ( len ( ooOO000OOO ) ) :
    O0O0o00 = oO00o [ o000o0O0Oo00 ]
    if ( O0O0o00 == "" ) : continue
    iI111i1Ii = ooOO000OOO [ o000o0O0Oo00 ]
    iI111i1Ii . json_name = O0O0o00
    if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
    if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
  if ( o0oOoo == "datetime-range" ) :
   for o000o0O0Oo00 in range ( len ( ooOO000OOO ) ) :
    O0O0o00 = oO00o [ o000o0O0Oo00 ]
    iI111i1Ii = ooOO000OOO [ o000o0O0Oo00 ]
    if ( O0O0o00 == "" ) : continue
    OoOoo00Oo0OoO = lisp_datetime ( O0O0o00 [ 0 : 19 ] )
    i1o00O = lisp_datetime ( O0O0o00 [ 19 : : ] )
    if ( OoOoo00Oo0OoO . valid_datetime ( ) and i1o00O . valid_datetime ( ) ) :
     iI111i1Ii . datetime_lower = OoOoo00Oo0OoO
     iI111i1Ii . datetime_upper = i1o00O
     if 16 - 16: I11i
     if 9 - 9: Ii1I / IiII * I11i - i11iIiiIii * I1ii11iIi11i / iII111i
     if 61 - 61: O0 % iII111i
     if 41 - 41: I1Ii111 * OoooooooOO
     if 76 - 76: OoooooooOO * II111iiii . II111iiii / o0oOOo0O0Ooo - iII111i
     if 49 - 49: O0 . I1ii11iIi11i . OoOoOO00 . I1Ii111 % O0 . iIii1I11I1II1
     if 19 - 19: iIii1I11I1II1
  if ( o0oOoo == "set-action" ) :
   ooo0OO0OOooO0 . set_action = oO00o
   if 97 - 97: Ii1I . I11i / ooOoO0o + Oo0Ooo
  if ( o0oOoo == "set-record-ttl" ) :
   ooo0OO0OOooO0 . set_record_ttl = int ( oO00o )
   if 100 - 100: iII111i / I1Ii111 % OoOoOO00 . O0 / OoOoOO00
  if ( o0oOoo == "set-instance-id" ) :
   if ( ooo0OO0OOooO0 . set_source_eid == None ) :
    ooo0OO0OOooO0 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 81 - 81: OoO0O00 % i11iIiiIii / OoO0O00 + ooOoO0o
   if ( ooo0OO0OOooO0 . set_dest_eid == None ) :
    ooo0OO0OOooO0 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 100 - 100: O0 . Oo0Ooo % Oo0Ooo % O0 / i11iIiiIii
   iI11Ii = int ( oO00o )
   ooo0OO0OOooO0 . set_source_eid . instance_id = iI11Ii
   ooo0OO0OOooO0 . set_dest_eid . instance_id = iI11Ii
   if 56 - 56: IiII - OOooOOo - OoOoOO00 - I11i
  if ( o0oOoo == "set-source-eid" ) :
   if ( ooo0OO0OOooO0 . set_source_eid == None ) :
    ooo0OO0OOooO0 . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 57 - 57: i1IIi
   ooo0OO0OOooO0 . set_source_eid . store_prefix ( oO00o )
   if ( iI11Ii != None ) : ooo0OO0OOooO0 . set_source_eid . instance_id = iI11Ii
   if 41 - 41: I11i / Ii1I
  if ( o0oOoo == "set-destination-eid" ) :
   if ( ooo0OO0OOooO0 . set_dest_eid == None ) :
    ooo0OO0OOooO0 . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 1 - 1: II111iiii / iII111i
   ooo0OO0OOooO0 . set_dest_eid . store_prefix ( oO00o )
   if ( iI11Ii != None ) : ooo0OO0OOooO0 . set_dest_eid . instance_id = iI11Ii
   if 83 - 83: OoO0O00 / iII111i
  if ( o0oOoo == "set-rloc-address" ) :
   ooo0OO0OOooO0 . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   ooo0OO0OOooO0 . set_rloc_address . store_address ( oO00o )
   if 59 - 59: I1Ii111 % OOooOOo . I1IiiI + I1ii11iIi11i % oO0o
  if ( o0oOoo == "set-rloc-record-name" ) :
   ooo0OO0OOooO0 . set_rloc_record_name = oO00o
   if 96 - 96: OoO0O00
  if ( o0oOoo == "set-elp-name" ) :
   ooo0OO0OOooO0 . set_elp_name = oO00o
   if 53 - 53: oO0o + OoO0O00
  if ( o0oOoo == "set-geo-name" ) :
   ooo0OO0OOooO0 . set_geo_name = oO00o
   if 58 - 58: iIii1I11I1II1 + OoOoOO00
  if ( o0oOoo == "set-rle-name" ) :
   ooo0OO0OOooO0 . set_rle_name = oO00o
   if 65 - 65: iII111i % Oo0Ooo * iIii1I11I1II1 + I1IiiI + II111iiii
  if ( o0oOoo == "set-json-name" ) :
   ooo0OO0OOooO0 . set_json_name = oO00o
   if 72 - 72: OoOoOO00 . OoooooooOO - OOooOOo
  if ( o0oOoo == "policy-name" ) :
   ooo0OO0OOooO0 . policy_name = oO00o
   if 15 - 15: OoOoOO00
   if 13 - 13: I1ii11iIi11i - OOooOOo - i11iIiiIii / IiII
   if 65 - 65: IiII
   if 76 - 76: I1Ii111 % I1ii11iIi11i + ooOoO0o / I1IiiI
   if 59 - 59: OOooOOo - o0oOOo0O0Ooo - o0oOOo0O0Ooo % I1IiiI
   if 55 - 55: o0oOOo0O0Ooo % I1ii11iIi11i - IiII + OoooooooOO
 ooo0OO0OOooO0 . match_clauses = ooOO000OOO
 ooo0OO0OOooO0 . save_policy ( )
 return
 if 44 - 44: iII111i * I1Ii111 - I1IiiI % i1IIi
 if 35 - 35: iII111i . OoOoOO00 + i1IIi . I1Ii111 - oO0o
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
if 92 - 92: o0oOOo0O0Ooo
if 8 - 8: i1IIi / IiII . O0
if 72 - 72: OOooOOo
if 20 - 20: i11iIiiIii + Oo0Ooo * Oo0Ooo % OOooOOo
if 66 - 66: I1ii11iIi11i + iII111i / Ii1I / I1IiiI * i11iIiiIii
if 41 - 41: Ii1I / Oo0Ooo . OoO0O00 . iIii1I11I1II1 % IiII . I11i
if 59 - 59: O0 + II111iiii + IiII % Oo0Ooo
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 71 - 71: oO0o
 OOOOooOO000O = command
 if ( interface != "" ) : OOOOooOO000O = interface + ": " + OOOOooOO000O
 lprint ( "Send CLI command '{}' to hardware" . format ( OOOOooOO000O ) )
 if 80 - 80: i1IIi % OOooOOo - ooOoO0o % iII111i . I1Ii111 + I1ii11iIi11i
 IiIi = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 81 - 81: ooOoO0o % Ii1I / OOooOOo * ooOoO0o + ooOoO0o
 os . system ( "FastCli -c '{}'" . format ( IiIi ) )
 return
 if 85 - 85: iII111i . I1ii11iIi11i
 if 25 - 25: I1Ii111 + oO0o + ooOoO0o . i1IIi
 if 17 - 17: OoooooooOO * I1Ii111 / I1Ii111
 if 17 - 17: OoooooooOO - O0
 if 95 - 95: I1IiiI / I1IiiI * OoooooooOO
 if 78 - 78: Oo0Ooo / Ii1I
 if 74 - 74: OOooOOo . II111iiii - i11iIiiIii / OoooooooOO + OoOoOO00 * ooOoO0o
def lisp_arista_is_alive ( prefix ) :
 I11ii1iI11 = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 i11IiIIi11I = getoutput ( "FastCli -c '{}'" . format ( I11ii1iI11 ) )
 if 63 - 63: OoO0O00
 if 66 - 66: iIii1I11I1II1
 if 98 - 98: iII111i . oO0o % I1Ii111 + Oo0Ooo
 if 83 - 83: Oo0Ooo % oO0o - iII111i
 i11IiIIi11I = i11IiIIi11I . split ( "\n" ) [ 1 ]
 iIii = i11IiIIi11I . split ( " " )
 iIii = iIii [ - 1 ] . replace ( "\r" , "" )
 if 19 - 19: II111iiii
 if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
 if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
 if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
 return ( iIii == "Y" )
 if 21 - 21: IiII
 if 43 - 43: IiII
 if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
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
 if 28 - 28: IiII + I11i
 if 1 - 1: OoooooooOO - i11iIiiIii . OoooooooOO - o0oOOo0O0Ooo - OOooOOo * I1Ii111
 if 56 - 56: Ii1I . OoO0O00
 if 43 - 43: iII111i * iII111i
 if 31 - 31: O0 - iIii1I11I1II1 . I11i . oO0o
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
 if 92 - 92: i11iIiiIii * iIii1I11I1II1 - I1Ii111 . i1IIi
 if 23 - 23: O0 - O0 . I1Ii111 . I1IiiI - I1IiiI * i1IIi
 if 8 - 8: I1IiiI . I1ii11iIi11i + oO0o % oO0o * oO0o
 if 70 - 70: II111iiii + IiII + O0 / Ii1I - i11iIiiIii
 if 72 - 72: II111iiii - II111iiii
 if 44 - 44: o0oOOo0O0Ooo + OoooooooOO
def lisp_program_vxlan_hardware ( mc ) :
 if 34 - 34: i11iIiiIii + iIii1I11I1II1 - i11iIiiIii * o0oOOo0O0Ooo - iII111i
 if 87 - 87: OOooOOo * OoO0O00
 if 61 - 61: iII111i - II111iiii . I1Ii111 % II111iiii / I11i
 if 86 - 86: II111iiii
 if 94 - 94: o0oOOo0O0Ooo % Ii1I * Ii1I % Oo0Ooo / I1ii11iIi11i
 if 40 - 40: Oo0Ooo . II111iiii / II111iiii - i1IIi
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 91 - 91: Ii1I
 if 45 - 45: I1ii11iIi11i + Oo0Ooo
 if 72 - 72: I1ii11iIi11i
 if 5 - 5: i1IIi
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 31 - 31: iII111i - OoooooooOO + oO0o / OoooooooOO + I1ii11iIi11i
 if 93 - 93: o0oOOo0O0Ooo * I1ii11iIi11i % I1IiiI * ooOoO0o
 if 37 - 37: OoO0O00 * OoooooooOO / oO0o * I11i * I1ii11iIi11i
 if 42 - 42: OoooooooOO - ooOoO0o . OOooOOo + OoOoOO00
 I1Ii = mc . eid . print_prefix_no_iid ( )
 OO0Oo00oo = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 53 - 53: o0oOOo0O0Ooo
 if 55 - 55: ooOoO0o . i1IIi - ooOoO0o + O0 + I1IiiI
 if 31 - 31: OoO0O00 % I1Ii111
 if 62 - 62: oO0o / O0 - I1Ii111 . IiII
 oOi1IiIiiIIiii = getoutput ( "ip route get {} | egrep vlan4094" . format ( I1Ii ) )
 if 86 - 86: OoooooooOO - iII111i . O0 + II111iiii / OOooOOo . ooOoO0o
 if ( oOi1IiIiiIIiii != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( I1Ii , False ) , oOi1IiIiiIIiii ) )
  if 48 - 48: O0 / OoooooooOO + I11i / OoO0O00
  return
  if 12 - 12: I11i % Ii1I % OOooOOo * Ii1I - IiII . o0oOOo0O0Ooo
  if 60 - 60: OoOoOO00 - OoooooooOO * Ii1I * iIii1I11I1II1
  if 85 - 85: OoOoOO00 - I11i * o0oOOo0O0Ooo
  if 45 - 45: ooOoO0o + I11i * O0
  if 30 - 30: I1ii11iIi11i + I1ii11iIi11i - OoO0O00 / OoO0O00 - iIii1I11I1II1
  if 80 - 80: OOooOOo . ooOoO0o + i1IIi * I1ii11iIi11i % O0
  if 77 - 77: OoOoOO00 % II111iiii % I1Ii111 . i1IIi - I11i - I1IiiI
 oOOo0o = getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( oOOo0o . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 89 - 89: iII111i + iII111i + OoOoOO00 + iIii1I11I1II1
 if ( oOOo0o . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 52 - 52: II111iiii
 oo0Oo0o0O = getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( oo0Oo0o0O == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 33 - 33: iIii1I11I1II1 - o0oOOo0O0Ooo . I1ii11iIi11i - OOooOOo
 oo0Oo0o0O = oo0Oo0o0O . split ( "inet " ) [ 1 ]
 oo0Oo0o0O = oo0Oo0o0O . split ( "/" ) [ 0 ]
 if 70 - 70: OOooOOo % Ii1I + II111iiii % II111iiii / i11iIiiIii * O0
 if 49 - 49: I1IiiI . o0oOOo0O0Ooo * i1IIi % IiII + I1Ii111
 if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
 if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
 if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if 44 - 44: Oo0Ooo / oO0o
 IiII1Ii1ii1 = [ ]
 O00o = getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for ooO in O00o :
  if ( ooO . find ( "vlan4094" ) == - 1 ) : continue
  if ( ooO . find ( "(incomplete)" ) == - 1 ) : continue
  i1IIIII = ooO . split ( " " ) [ 0 ]
  IiII1Ii1ii1 . append ( i1IIIII )
  if 98 - 98: o0oOOo0O0Ooo + Oo0Ooo / i11iIiiIii - O0 / o0oOOo0O0Ooo . I1IiiI
  if 10 - 10: OOooOOo * OoooooooOO * o0oOOo0O0Ooo % OoO0O00 . I11i
 i1IIIII = None
 IiI1iI1I = oo0Oo0o0O
 oo0Oo0o0O = oo0Oo0o0O . split ( "." )
 for o000o0O0Oo00 in range ( 1 , 255 ) :
  oo0Oo0o0O [ 3 ] = str ( o000o0O0Oo00 )
  iI1ii11Ii = "." . join ( oo0Oo0o0O )
  if ( iI1ii11Ii in IiII1Ii1ii1 ) : continue
  if ( iI1ii11Ii == IiI1iI1I ) : continue
  i1IIIII = iI1ii11Ii
  break
  if 9 - 9: ooOoO0o . O0 - OoOoOO00 + I11i
 if ( i1IIIII == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 57 - 57: OoO0O00 * IiII
  return
  if 18 - 18: iII111i + I1Ii111
  if 1 - 1: OoooooooOO % OoooooooOO * I1ii11iIi11i
  if 24 - 24: I1Ii111 % I1Ii111 % iIii1I11I1II1
  if 29 - 29: i1IIi % i1IIi - II111iiii
  if 44 - 44: II111iiii . Oo0Ooo - o0oOOo0O0Ooo
  if 45 - 45: ooOoO0o - oO0o - I1IiiI
  if 21 - 21: OoooooooOO
 IIiI1I = OO0Oo00oo . split ( "." )
 iiIii1iIIiI1 = lisp_hex_string ( IIiI1I [ 1 ] ) . zfill ( 2 )
 o0i1iiIiI = lisp_hex_string ( IIiI1I [ 2 ] ) . zfill ( 2 )
 iIIiII = lisp_hex_string ( IIiI1I [ 3 ] ) . zfill ( 2 )
 i1i1I1 = "00:00:00:{}:{}:{}" . format ( iiIii1iIIiI1 , o0i1iiIiI , iIIiII )
 II1III11iiii = "0000.00{}.{}{}" . format ( iiIii1iIIiI1 , o0i1iiIiI , iIIiII )
 I1i1iiiiIiII = "arp -i vlan4094 -s {} {}" . format ( i1IIIII , i1i1I1 )
 os . system ( I1i1iiiiIiII )
 if 77 - 77: OoO0O00
 if 95 - 95: II111iiii
 if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
 if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
 O0o0000oO0 = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( II1III11iiii , OO0Oo00oo )
 if 72 - 72: OoooooooOO * I1Ii111 * ooOoO0o
 lisp_send_to_arista ( O0o0000oO0 , None )
 if 97 - 97: ooOoO0o % I1Ii111 . I1ii11iIi11i + iII111i / I1ii11iIi11i - O0
 if 78 - 78: o0oOOo0O0Ooo - I1ii11iIi11i
 if 6 - 6: OoO0O00 / IiII - I1ii11iIi11i + o0oOOo0O0Ooo . OOooOOo
 if 70 - 70: OoOoOO00 % iIii1I11I1II1 + II111iiii / IiII
 if 46 - 46: I11i
 oOoOOOo0ooO = "ip route add {} via {}" . format ( I1Ii , i1IIIII )
 os . system ( oOoOOOo0ooO )
 if 34 - 34: iIii1I11I1II1 - I1Ii111 / OOooOOo . I1Ii111 + I1ii11iIi11i * I1IiiI
 lprint ( "Hardware programmed with commands:" )
 oOoOOOo0ooO = oOoOOOo0ooO . replace ( I1Ii , green ( I1Ii , False ) )
 lprint ( "  " + oOoOOOo0ooO )
 lprint ( "  " + I1i1iiiiIiII )
 O0o0000oO0 = O0o0000oO0 . replace ( OO0Oo00oo , red ( OO0Oo00oo , False ) )
 lprint ( "  " + O0o0000oO0 )
 return
 if 32 - 32: ooOoO0o % O0 . I1ii11iIi11i
 if 55 - 55: oO0o / i11iIiiIii - Oo0Ooo
 if 44 - 44: OoO0O00 . I1IiiI * OoOoOO00
 if 32 - 32: OoooooooOO
 if 94 - 94: I1Ii111 + o0oOOo0O0Ooo * Ii1I * I1Ii111 . iII111i . ooOoO0o
 if 73 - 73: OoO0O00
 if 8 - 8: iIii1I11I1II1 - o0oOOo0O0Ooo
def lisp_clear_hardware_walk ( mc , parms ) :
 o0ooOooO00Oo = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( o0ooOooO00Oo ) )
 return ( [ True , None ] )
 if 68 - 68: Ii1I % o0oOOo0O0Ooo / OoooooooOO + Ii1I - Ii1I
 if 79 - 79: II111iiii / IiII
 if 4 - 4: O0 - i11iIiiIii % ooOoO0o * O0 - ooOoO0o
 if 96 - 96: oO0o % II111iiii . Ii1I % OoO0O00 . iIii1I11I1II1 / IiII
 if 96 - 96: o0oOOo0O0Ooo / O0 . iIii1I11I1II1 . Ii1I % OOooOOo % II111iiii
 if 5 - 5: OoooooooOO / I1Ii111 % I1Ii111 / I1IiiI
 if 19 - 19: I1IiiI - ooOoO0o % IiII - o0oOOo0O0Ooo * OOooOOo + I1ii11iIi11i
 if 44 - 44: i1IIi
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 85 - 85: I1ii11iIi11i / IiII + oO0o
 o0OI1I1IIII11 = bold ( "User cleared" , False )
 III11i1iI11 = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( o0OI1I1IIII11 , III11i1iI11 ) )
 if 76 - 76: I1Ii111
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 23 - 23: O0 % I1ii11iIi11i % iIii1I11I1II1
 lisp_map_cache = lisp_cache ( )
 if 49 - 49: iII111i + I1Ii111 % OoOoOO00
 if 67 - 67: Ii1I
 if 27 - 27: Oo0Ooo / i11iIiiIii / II111iiii . Ii1I - II111iiii / OoO0O00
 if 61 - 61: ooOoO0o - OOooOOo
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 45 - 45: O0 . OoO0O00
 if 80 - 80: IiII + OoO0O00
 if 2 - 2: IiII + OoOoOO00 % oO0o
 if 76 - 76: o0oOOo0O0Ooo
 if 25 - 25: OoooooooOO
 lisp_rloc_probe_list = { }
 if 78 - 78: oO0o / i11iIiiIii * O0 / OOooOOo % i11iIiiIii % O0
 if 86 - 86: IiII
 if 26 - 26: IiII - I1Ii111 + i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo
 if 39 - 39: Ii1I - i1IIi + i11iIiiIii
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 21 - 21: IiII
 if 76 - 76: o0oOOo0O0Ooo % Oo0Ooo + OoO0O00
 if 36 - 36: OOooOOo . oO0o
 if 15 - 15: I1IiiI + ooOoO0o - o0oOOo0O0Ooo
 if 62 - 62: Ii1I - OOooOOo
 lisp_rtr_list = { }
 if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
 if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
 if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
 if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
 lisp_gleaned_groups = { }
 if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
 if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
 if 2 - 2: I1ii11iIi11i
 if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
 lisp_process_data_plane_restart ( True )
 return
 if 54 - 54: ooOoO0o
 if 47 - 47: I11i * I1IiiI / oO0o
 if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
 if 4 - 4: i1IIi
 if 43 - 43: oO0o * ooOoO0o - I11i
 if 70 - 70: oO0o / Ii1I
 if 15 - 15: iIii1I11I1II1 % ooOoO0o % i11iIiiIii
 if 16 - 16: iII111i
 if 50 - 50: iIii1I11I1II1 - II111iiii % i1IIi
 if 48 - 48: O0
 if 60 - 60: ooOoO0o - IiII % i1IIi
def lisp_encap_rloc_probe ( lisp_sockets , rloc , nat_info , packet , source_addr = None ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 5 - 5: oO0o
 if 29 - 29: i1IIi . OoOoOO00 . i1IIi + oO0o . I1Ii111 + O0
 if 62 - 62: I1ii11iIi11i . IiII + OoO0O00 - OoOoOO00 * O0 + I1Ii111
 if 58 - 58: oO0o . OoO0O00 / ooOoO0o
 if 61 - 61: I11i + I1Ii111
 if 27 - 27: ooOoO0o / i1IIi . oO0o - OoooooooOO
 I1i1Ii1iII = source_addr if source_addr else lisp_myrlocs [ 0 ]
 if ( lisp_i_am_rtr and lisp_on_aws ( ) ) :
  iI1ii11Ii = lisp_get_interface_address ( "eth0" )
  if ( iI1ii11Ii == None ) : iI1ii11Ii = lisp_get_interface_address ( "ens5" )
  if ( iI1ii11Ii ) : I1i1Ii1iII = iI1ii11Ii
  if 98 - 98: iIii1I11I1II1 / iII111i % OoOoOO00 + IiII * OoOoOO00
  if 40 - 40: i11iIiiIii % IiII * ooOoO0o % Oo0Ooo * I1Ii111 % I1ii11iIi11i
  if 64 - 64: I1ii11iIi11i / O0 % II111iiii * I1Ii111
  if 76 - 76: I1ii11iIi11i + o0oOOo0O0Ooo
  if 94 - 94: i11iIiiIii + I1Ii111 . iII111i - ooOoO0o % I1Ii111
  if 94 - 94: i11iIiiIii - OOooOOo - O0 * OoooooooOO - ooOoO0o
 OOOOo0o0O0o = len ( packet ) + 28
 ooooO000 = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( OOOOo0o0O0o ) , 0 , 64 ,
 17 , 0 , socket . htonl ( I1i1Ii1iII . address ) , socket . htonl ( rloc . address ) )
 ooooO000 = lisp_ip_checksum ( ooooO000 )
 if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
 II1 = socket . htons ( LISP_DATA_PORT )
 Ooo0000o00OO = socket . htons ( LISP_CTRL_PORT )
 ii11 = struct . pack ( "HHHH" , II1 , Ooo0000o00OO , socket . htons ( OOOOo0o0O0o - 20 ) , 0 )
 if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
 if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
 if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
 if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
 O00OoO0 = packet [ 0 : 1 ]
 packet = lisp_packet ( ooooO000 + ii11 + packet )
 if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
 if 79 - 79: I11i . I11i - OoOoOO00
 if 86 - 86: OoO0O00 * Oo0Ooo . iIii1I11I1II1 * O0
 if 52 - 52: iII111i - i11iIiiIii + o0oOOo0O0Ooo + i1IIi
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( I1i1Ii1iII )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( I1i1Ii1iII )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 58 - 58: OOooOOo - Ii1I * I1Ii111 - O0 . oO0o
 iIiIi111 = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  O00 = " {}" . format ( blue ( nat_info . hostname , False ) )
 else :
  O00 = ""
  if 72 - 72: i1IIi * iII111i * Ii1I / o0oOOo0O0Ooo . I1Ii111 + i11iIiiIii
 if ( lisp_is_rloc_probe_request ( O00OoO0 ) ) :
  I1III1 = bold ( "RLOC-probe request" , False )
 else :
  I1III1 = bold ( "RLOC-probe reply" , False )
  if 33 - 33: I11i / OoO0O00 * ooOoO0o + iIii1I11I1II1
  if 54 - 54: Oo0Ooo / IiII + i11iIiiIii . O0
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( I1III1 , iIiIi111 , O00 , packet . encap_port ) )
 if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
 if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
 if 93 - 93: oO0o
 if 53 - 53: OoO0O00 * i1IIi / Oo0Ooo / OoO0O00 * ooOoO0o
 if 77 - 77: iIii1I11I1II1 % I1IiiI + o0oOOo0O0Ooo + I1Ii111 * Oo0Ooo * i1IIi
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 14 - 14: iIii1I11I1II1 * iIii1I11I1II1 - OOooOOo . iII111i / ooOoO0o
 oOOo0Oo0o = lisp_sockets [ 3 ]
 if 38 - 38: iII111i / oO0o + ooOoO0o * OoooooooOO . IiII / iIii1I11I1II1
 if 89 - 89: ooOoO0o
 if 77 - 77: oO0o / oO0o - II111iiii - Oo0Ooo + ooOoO0o % Ii1I
 if 87 - 87: I1Ii111 - iII111i / Ii1I
 if 73 - 73: I1IiiI + OoOoOO00 - oO0o
 if 32 - 32: Oo0Ooo % iII111i % I1IiiI
 if 85 - 85: OoO0O00 - Ii1I / O0
 if 45 - 45: IiII + I1Ii111 / I11i
 if 84 - 84: iII111i % II111iiii
 if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
 if ( source_addr ) :
  try :
   oOOo0Oo0o . bind ( ( I1i1Ii1iII . print_address_no_iid ( ) , 0 ) )
  except Exception as oOO :
   lprint ( "raw socket bind to {} failed: {}" . format ( I1i1Ii1iII . print_address_no_iid ( ) , oOO ) )
   if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
   if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
   if 68 - 68: O0 % oO0o * IiII % O0
   if 55 - 55: O0 % I1IiiI % O0
 packet . send_packet ( oOOo0Oo0o , packet . outer_dest )
 del ( packet )
 return
 if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
 if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
 if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
 if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
 if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
 if 23 - 23: I1Ii111 / iII111i . O0 % II111iiii
 if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
 if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
def lisp_get_default_route_next_hops ( ) :
 if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
 if 65 - 65: ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . I1IiiI % O0
 if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
 if 1 - 1: I1ii11iIi11i % O0 - I1ii11iIi11i / OoooooooOO / OoO0O00
 if ( lisp_is_macos ( ) ) :
  I11ii1iI11 = "route -n get default"
  oo00O000o0 = getoutput ( I11ii1iI11 ) . split ( "\n" )
  iiiI11i11 = o0o = None
  for iIi1iii in oo00O000o0 :
   if ( iIi1iii . find ( "gateway: " ) != - 1 ) : iiiI11i11 = iIi1iii . split ( ": " ) [ 1 ]
   if ( iIi1iii . find ( "interface: " ) != - 1 ) : o0o = iIi1iii . split ( ": " ) [ 1 ]
   if 66 - 66: II111iiii - o0oOOo0O0Ooo - Ii1I
  return ( [ [ o0o , iiiI11i11 ] ] )
  if 3 - 3: I1ii11iIi11i / iIii1I11I1II1
  if 30 - 30: iIii1I11I1II1 % I1ii11iIi11i * II111iiii
  if 75 - 75: I1ii11iIi11i * I1Ii111 . Ii1I
  if 45 - 45: Oo0Ooo / OoooooooOO * iIii1I11I1II1 - I11i + I11i
  if 73 - 73: iII111i
 I11ii1iI11 = "ip route | egrep 'default via'"
 O0OOO = getoutput ( I11ii1iI11 ) . split ( "\n" )
 if 96 - 96: I1ii11iIi11i % OoO0O00 . Oo0Ooo . OOooOOo . OoooooooOO / oO0o
 I1IIIIiI1i = [ ]
 for oOi1IiIiiIIiii in O0OOO :
  IIIIiiI1iIiI = oOi1IiIiiIIiii . split ( )
  try :
   i1IIIII = IIIIiiI1iIiI [ 2 ]
   i1iiI = IIIIiiI1iIiI [ 4 ]
  except :
   continue
   if 15 - 15: I11i - i1IIi
  I1IIIIiI1i . append ( [ i1iiI , i1IIIII ] )
  if 15 - 15: ooOoO0o % I1Ii111 * OoooooooOO % IiII + I1ii11iIi11i - Ii1I
 return ( I1IIIIiI1i )
 if 67 - 67: i1IIi % I1ii11iIi11i * OOooOOo . Oo0Ooo
 if 82 - 82: iII111i . O0 / Oo0Ooo / OoooooooOO
 if 68 - 68: OoooooooOO . iIii1I11I1II1 / iII111i / OOooOOo
 if 35 - 35: I1ii11iIi11i * I11i % o0oOOo0O0Ooo + i1IIi % iII111i / IiII
 if 41 - 41: IiII . OOooOOo % ooOoO0o
 if 25 - 25: i1IIi - OoO0O00
 if 54 - 54: OOooOOo + oO0o + OoO0O00 . OoO0O00
def lisp_get_host_route_next_hop ( rloc ) :
 I11ii1iI11 = "ip route | egrep '{} via'" . format ( rloc )
 oOi1IiIiiIIiii = getoutput ( I11ii1iI11 ) . split ( )
 if 29 - 29: OOooOOo / IiII * OOooOOo + II111iiii . oO0o * o0oOOo0O0Ooo
 try : o00O = oOi1IiIiiIIiii . index ( "via" ) + 1
 except : return ( None )
 if 37 - 37: I1Ii111 . oO0o * IiII
 if ( o00O >= len ( oOi1IiIiiIIiii ) ) : return ( None )
 return ( oOi1IiIiiIIiii [ o00O ] )
 if 41 - 41: I1Ii111 - iIii1I11I1II1 + Oo0Ooo
 if 56 - 56: IiII - I1ii11iIi11i - I1ii11iIi11i . I1Ii111
 if 55 - 55: OoO0O00
 if 11 - 11: OoooooooOO - I1IiiI . I1IiiI % o0oOOo0O0Ooo
 if 56 - 56: I1Ii111
 if 23 - 23: ooOoO0o . I11i - OOooOOo
 if 40 - 40: OoOoOO00
def lisp_get_host_route_device ( rloc ) :
 I11ii1iI11 = "ip route | egrep '{} via'" . format ( rloc )
 oOi1IiIiiIIiii = getoutput ( I11ii1iI11 ) . split ( )
 if 44 - 44: O0 + Oo0Ooo - iII111i + iIii1I11I1II1 / i11iIiiIii * IiII
 try : o00O = oOi1IiIiiIIiii . index ( "dev" ) + 1
 except : return ( None )
 if 49 - 49: Oo0Ooo
 if ( o00O >= len ( oOi1IiIiiIIiii ) ) : return ( None )
 return ( oOi1IiIiiIIiii [ o00O ] )
 if 87 - 87: I1Ii111 + iII111i / IiII / ooOoO0o * OoooooooOO / OOooOOo
 if 44 - 44: IiII . I1Ii111
 if 46 - 46: O0 - ooOoO0o . I1ii11iIi11i % oO0o / OoOoOO00
 if 93 - 93: I1ii11iIi11i * o0oOOo0O0Ooo . I11i . I1ii11iIi11i % i1IIi + Ii1I
 if 63 - 63: I1IiiI / OoooooooOO
 if 16 - 16: OoOoOO00
 if 67 - 67: O0 . I1Ii111
def lisp_install_host_route ( dest , nh , device ) :
 if ( nh == None or device == None ) : return
 if 42 - 42: OoOoOO00 % I1ii11iIi11i * I1Ii111 * i1IIi . i1IIi % OOooOOo
 if 90 - 90: oO0o * Oo0Ooo * oO0o . Ii1I * i1IIi
 if 47 - 47: OOooOOo
 if 38 - 38: I11i
 os . system ( "sudo ip route delete {}/32" . format ( dest ) )
 if 15 - 15: OoO0O00 / ooOoO0o . OoO0O00 - iIii1I11I1II1 + OoooooooOO - OoO0O00
 if 44 - 44: O0 . OOooOOo . o0oOOo0O0Ooo . I1ii11iIi11i - II111iiii
 if 71 - 71: I1ii11iIi11i + o0oOOo0O0Ooo . i11iIiiIii * oO0o . i1IIi
 if 40 - 40: OoO0O00 - IiII
 oOi1IiIiiIIiii = "ip route add {}/32 via {} dev {}" . format ( dest , nh , device )
 lprint ( "Run '{}'" . format ( oOi1IiIiiIIiii ) )
 os . system ( oOi1IiIiiIIiii )
 if 43 - 43: I1Ii111 + i11iIiiIii % iII111i % I1Ii111 - ooOoO0o
 if 85 - 85: IiII % iIii1I11I1II1 . I1Ii111
 if 38 - 38: iII111i - I1IiiI / ooOoO0o
 if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
 if 19 - 19: I11i / Oo0Ooo + I1Ii111
 if 43 - 43: I1ii11iIi11i
 if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
 if 22 - 22: iII111i
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 88 - 88: I11i + OoOoOO00 % IiII % OoO0O00 * O0 / OoooooooOO
 iIi1iii = open ( lisp_checkpoint_filename , "w" )
 for Ii in checkpoint_list :
  iIi1iii . write ( Ii + "\n" )
  if 83 - 83: IiII + I1Ii111 . I1ii11iIi11i * iIii1I11I1II1
 iIi1iii . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 9 - 9: ooOoO0o % IiII - OoOoOO00
 if 66 - 66: oO0o % Oo0Ooo
 if 40 - 40: i11iIiiIii . O0 * I11i - oO0o / OOooOOo . oO0o
 if 86 - 86: OOooOOo - I1Ii111 * IiII - i1IIi + ooOoO0o + I11i
 if 32 - 32: IiII
 if 99 - 99: II111iiii
 if 34 - 34: OOooOOo + OoOoOO00 * o0oOOo0O0Ooo + I1ii11iIi11i + IiII * i1IIi
 if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 68 - 68: I1ii11iIi11i - OoooooooOO
 iIi1iii = open ( lisp_checkpoint_filename , "r" )
 if 5 - 5: I1ii11iIi11i * I1IiiI + OoooooooOO / Oo0Ooo
 III11i1iI11 = 0
 for Ii in iIi1iii :
  III11i1iI11 += 1
  oOO = Ii . split ( " rloc " )
  II = [ ] if ( oOO [ 1 ] in [ "native-forward\n" , "\n" ] ) else oOO [ 1 ] . split ( ", " )
  if 18 - 18: OoO0O00 * iII111i % I1IiiI . OOooOOo * o0oOOo0O0Ooo
  if 58 - 58: iII111i . IiII + iIii1I11I1II1
  o0O00ooOo = [ ]
  for OO0Oo00oo in II :
   i1iiI1i1 = lisp_rloc ( False )
   IIIIiiI1iIiI = OO0Oo00oo . split ( " " )
   i1iiI1i1 . rloc . store_address ( IIIIiiI1iIiI [ 0 ] )
   i1iiI1i1 . priority = int ( IIIIiiI1iIiI [ 1 ] )
   i1iiI1i1 . weight = int ( IIIIiiI1iIiI [ 2 ] )
   o0O00ooOo . append ( i1iiI1i1 )
   if 13 - 13: oO0o * I1Ii111 / I1Ii111 . I1IiiI
   if 93 - 93: I11i % OoOoOO00 - OOooOOo + iIii1I11I1II1 / OoooooooOO % i11iIiiIii
  Ii111 = lisp_mapping ( "" , "" , o0O00ooOo )
  if ( Ii111 != None ) :
   Ii111 . eid . store_prefix ( oOO [ 0 ] )
   Ii111 . checkpoint_entry = True
   Ii111 . map_cache_ttl = LISP_NMR_TTL * 60
   if ( o0O00ooOo == [ ] ) : Ii111 . action = LISP_NATIVE_FORWARD_ACTION
   Ii111 . add_cache ( )
   continue
   if 90 - 90: oO0o % iIii1I11I1II1 + o0oOOo0O0Ooo - I11i / i11iIiiIii
   if 57 - 57: I1IiiI . Oo0Ooo / I1IiiI / II111iiii - I1Ii111
  III11i1iI11 -= 1
  if 68 - 68: I1IiiI
  if 97 - 97: Ii1I + o0oOOo0O0Ooo / OoO0O00
 iIi1iii . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , III11i1iI11 , lisp_checkpoint_filename ) )
 return
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
 if 32 - 32: Ii1I + II111iiii * IiII
 if 9 - 9: I1Ii111
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 96 - 96: I1Ii111 / iIii1I11I1II1
 Ii = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 48 - 48: iII111i * IiII + OoooooooOO
 for i1iiI1i1 in mc . rloc_set :
  if ( i1iiI1i1 . rloc . is_null ( ) ) : continue
  Ii += "{} {} {}, " . format ( i1iiI1i1 . rloc . print_address_no_iid ( ) ,
 i1iiI1i1 . priority , i1iiI1i1 . weight )
  if 63 - 63: I1IiiI / Ii1I
  if 31 - 31: i1IIi - oO0o
 if ( mc . rloc_set != [ ] ) :
  Ii = Ii [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  Ii += "native-forward"
  if 99 - 99: iII111i - i11iIiiIii + oO0o
  if 66 - 66: Oo0Ooo * I11i . iIii1I11I1II1 - OoO0O00
 checkpoint_list . append ( Ii )
 return
 if 11 - 11: I1Ii111 + iIii1I11I1II1 * O0 * Oo0Ooo
 if 66 - 66: OoooooooOO % OoO0O00 + i11iIiiIii + I1Ii111 % OoO0O00
 if 80 - 80: Oo0Ooo - Ii1I
 if 54 - 54: O0 - iIii1I11I1II1 . OoO0O00 . IiII % OoO0O00
 if 28 - 28: O0 % i1IIi % OoO0O00 / o0oOOo0O0Ooo . iIii1I11I1II1 - iII111i
 if 50 - 50: o0oOOo0O0Ooo + iII111i / i1IIi % II111iiii
 if 61 - 61: IiII
def lisp_check_dp_socket ( ) :
 I11i1iii1I = lisp_ipc_dp_socket_name
 if ( os . path . exists ( I11i1iii1I ) == False ) :
  IIII1iii1111 = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( I11i1iii1I , IIII1iii1111 ) )
  return ( False )
  if 88 - 88: O0 * OoO0O00 % OoooooooOO * iII111i
 return ( True )
 if 60 - 60: Ii1I
 if 30 - 30: i1IIi * OoO0O00
 if 80 - 80: I11i
 if 96 - 96: i1IIi - I1ii11iIi11i * iII111i . OOooOOo . OoO0O00
 if 93 - 93: oO0o * Oo0Ooo * IiII
 if 26 - 26: o0oOOo0O0Ooo + O0 % i11iIiiIii . ooOoO0o . I1IiiI + Oo0Ooo
 if 90 - 90: IiII * OoooooooOO + II111iiii / iII111i + i11iIiiIii / ooOoO0o
def lisp_write_to_dp_socket ( entry ) :
 try :
  IiII1ii1I1 = json . dumps ( entry )
  iIiI11iIIII = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( iIiI11iIIII , IiII1ii1I1 ) )
  lisp_ipc_dp_socket . sendto ( IiII1ii1I1 , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( IiII1ii1I1 ) )
  if 22 - 22: Oo0Ooo . o0oOOo0O0Ooo . II111iiii . I1ii11iIi11i
 return
 if 66 - 66: i11iIiiIii % Ii1I / iII111i * I1ii11iIi11i
 if 81 - 81: O0 + o0oOOo0O0Ooo - oO0o - I1ii11iIi11i * o0oOOo0O0Ooo
 if 99 - 99: I1IiiI / ooOoO0o - I1ii11iIi11i . o0oOOo0O0Ooo
 if 91 - 91: I1IiiI % Oo0Ooo
 if 10 - 10: OOooOOo - Oo0Ooo . I1IiiI + o0oOOo0O0Ooo
 if 91 - 91: ooOoO0o
 if 54 - 54: Ii1I - I1Ii111 - II111iiii % I11i
 if 11 - 11: OoOoOO00 . OOooOOo % OoooooooOO / OoooooooOO + I1ii11iIi11i
 if 90 - 90: i11iIiiIii % i1IIi % OoO0O00 / iII111i * I1ii11iIi11i + I11i
def lisp_write_ipc_keys ( rloc ) :
 O00oO000Oo0 = rloc . rloc . print_address_no_iid ( )
 i11I1Ii1Iiii1 = rloc . translated_port
 if ( i11I1Ii1Iiii1 != 0 ) : O00oO000Oo0 += ":" + str ( i11I1Ii1Iiii1 )
 if ( O00oO000Oo0 not in lisp_rloc_probe_list ) : return
 if 51 - 51: Ii1I * Oo0Ooo - OOooOOo % I1IiiI
 for IIIIiiI1iIiI , oOO , II11iIIii in lisp_rloc_probe_list [ O00oO000Oo0 ] :
  Ii111 = lisp_map_cache . lookup_cache ( oOO , True )
  if ( Ii111 == None ) : continue
  lisp_write_ipc_map_cache ( True , Ii111 )
  if 42 - 42: I11i - O0
 return
 if 70 - 70: Ii1I / oO0o + i11iIiiIii - oO0o
 if 26 - 26: OoO0O00 % I1ii11iIi11i * O0 % OoO0O00
 if 98 - 98: OoO0O00 . ooOoO0o * I11i / i1IIi
 if 57 - 57: i11iIiiIii % OOooOOo
 if 67 - 67: oO0o - OOooOOo + II111iiii
 if 19 - 19: iIii1I11I1II1 * OoooooooOO - i11iIiiIii . I1Ii111 * OoO0O00
 if 30 - 30: iII111i + I1IiiI * ooOoO0o
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 53 - 53: iII111i + IiII
 if 52 - 52: II111iiii * i11iIiiIii - IiII * IiII / OoooooooOO
 if 18 - 18: IiII / O0 / I1ii11iIi11i
 if 47 - 47: oO0o / iIii1I11I1II1
 Ii11 = "add" if add_or_delete else "delete"
 Ii = { "type" : "map-cache" , "opcode" : Ii11 }
 if 45 - 45: OoOoOO00 * o0oOOo0O0Ooo / I1ii11iIi11i * iII111i - I1ii11iIi11i
 I1iI1III = ( mc . group . is_null ( ) == False )
 if ( I1iI1III ) :
  Ii [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  Ii [ "rles" ] = [ ]
 else :
  Ii [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  Ii [ "rlocs" ] = [ ]
  if 48 - 48: Ii1I / OoO0O00
 Ii [ "instance-id" ] = str ( mc . eid . instance_id )
 if 45 - 45: O0 * OoO0O00 / I11i . II111iiii
 if ( I1iI1III ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for I1I1Ii1I in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    iI1ii11Ii = I1I1Ii1I . rloc . rloc . print_address_no_iid ( )
    i11I1Ii1Iiii1 = str ( 4341 ) if I1I1Ii1I . rloc . translated_port == 0 else str ( I1I1Ii1I . rloc . translated_port )
    if 20 - 20: I11i - IiII
    IIIIiiI1iIiI = { "rle" : iI1ii11Ii , "port" : i11I1Ii1Iiii1 }
    iI11ii , Oo00o00 = I1I1Ii1I . get_encap_keys ( )
    IIIIiiI1iIiI = lisp_build_json_keys ( IIIIiiI1iIiI , iI11ii , Oo00o00 , "encrypt-key" )
    Ii [ "rles" ] . append ( IIIIiiI1iIiI )
    if 58 - 58: o0oOOo0O0Ooo * II111iiii + o0oOOo0O0Ooo . I1IiiI
    if 25 - 25: o0oOOo0O0Ooo * I11i
 else :
  for OO0Oo00oo in mc . rloc_set :
   if ( OO0Oo00oo . rloc . is_ipv4 ( ) == False and OO0Oo00oo . rloc . is_ipv6 ( ) == False ) :
    continue
    if 70 - 70: OOooOOo
   if ( OO0Oo00oo . up_state ( ) == False ) : continue
   if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
   i11I1Ii1Iiii1 = str ( 4341 ) if OO0Oo00oo . translated_port == 0 else str ( OO0Oo00oo . translated_port )
   if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
   IIIIiiI1iIiI = { "rloc" : OO0Oo00oo . rloc . print_address_no_iid ( ) , "priority" :
 str ( OO0Oo00oo . priority ) , "weight" : str ( OO0Oo00oo . weight ) , "port" :
 i11I1Ii1Iiii1 }
   iI11ii , Oo00o00 = OO0Oo00oo . get_encap_keys ( )
   IIIIiiI1iIiI = lisp_build_json_keys ( IIIIiiI1iIiI , iI11ii , Oo00o00 , "encrypt-key" )
   Ii [ "rlocs" ] . append ( IIIIiiI1iIiI )
   if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
   if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
   if 63 - 63: I1IiiI
 if ( dont_send == False ) : lisp_write_to_dp_socket ( Ii )
 return ( Ii )
 if 20 - 20: oO0o + OoOoOO00
 if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
 if 4 - 4: OOooOOo % oO0o
 if 18 - 18: Ii1I * I11i
 if 14 - 14: ooOoO0o . ooOoO0o * OoOoOO00 * o0oOOo0O0Ooo - iII111i - I1Ii111
 if 53 - 53: Oo0Ooo * OoOoOO00 * II111iiii % IiII - I1ii11iIi11i
 if 56 - 56: Oo0Ooo . I1ii11iIi11i - i11iIiiIii / iIii1I11I1II1 . ooOoO0o
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 28 - 28: OoooooooOO + I1IiiI / oO0o . iIii1I11I1II1 - oO0o
 if 64 - 64: I1Ii111 + Oo0Ooo / iII111i
 if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
 if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 66 - 66: I1IiiI . Oo0Ooo - oO0o
 iI11ii = keys [ 1 ] . encrypt_key
 Oo00o00 = keys [ 1 ] . icv_key
 if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
 if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
 if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
 if 68 - 68: OoOoOO00 - iII111i - I1IiiI
 I1I1ii1Ii = rloc_addr . split ( ":" )
 if ( len ( I1I1ii1Ii ) == 1 ) :
  Ii = { "type" : "decap-keys" , "rloc" : I1I1ii1Ii [ 0 ] }
 else :
  Ii = { "type" : "decap-keys" , "rloc" : I1I1ii1Ii [ 0 ] , "port" : I1I1ii1Ii [ 1 ] }
  if 82 - 82: I1IiiI . i1IIi % iIii1I11I1II1 % i1IIi * ooOoO0o
 Ii = lisp_build_json_keys ( Ii , iI11ii , Oo00o00 , "decrypt-key" )
 if 48 - 48: ooOoO0o * II111iiii
 lisp_write_to_dp_socket ( Ii )
 return
 if 59 - 59: iIii1I11I1II1 / II111iiii % IiII - i11iIiiIii
 if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
 if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
 if 80 - 80: I11i
 if 98 - 98: iII111i / I1ii11iIi11i
 if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
 if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 56 - 56: IiII * II111iiii + Oo0Ooo - O0 - OoO0O00 . I1Ii111
 entry [ "keys" ] = [ ]
 oO0oOo = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( oO0oOo )
 return ( entry )
 if 53 - 53: i1IIi + IiII
 if 90 - 90: II111iiii / oO0o / oO0o . OoOoOO00 / OoO0O00 / iIii1I11I1II1
 if 96 - 96: iIii1I11I1II1 % I1ii11iIi11i
 if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
 if 72 - 72: I1Ii111 / OoO0O00 + II111iiii
 if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
 if 25 - 25: IiII * IiII
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 54 - 54: I1Ii111
 if 90 - 90: Oo0Ooo / Ii1I
 if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
 if 77 - 77: OoO0O00 / OOooOOo
 Ii = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 97 - 97: OoOoOO00 / Ii1I * I1IiiI - Oo0Ooo % O0
 if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
 if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
 if 36 - 36: I1IiiI - oO0o * Oo0Ooo + oO0o % iII111i - i11iIiiIii
 for Iiii1II1 in lisp_db_list :
  if ( Iiii1II1 . eid . is_ipv4 ( ) == False and Iiii1II1 . eid . is_ipv6 ( ) == False ) : continue
  ooiIII = { "instance-id" : str ( Iiii1II1 . eid . instance_id ) ,
 "eid-prefix" : Iiii1II1 . eid . print_prefix_no_iid ( ) }
  Ii [ "database-mappings" ] . append ( ooiIII )
  if 73 - 73: OoooooooOO
 lisp_write_to_dp_socket ( Ii )
 if 2 - 2: o0oOOo0O0Ooo % IiII + I1ii11iIi11i - i11iIiiIii
 if 100 - 100: II111iiii + oO0o
 if 85 - 85: I1ii11iIi11i % I1ii11iIi11i . Ii1I
 if 42 - 42: oO0o + OoO0O00
 if 16 - 16: Ii1I
 Ii = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( Ii )
 return
 if 67 - 67: I1ii11iIi11i . OoooooooOO * I1Ii111 + Ii1I * OOooOOo
 if 84 - 84: OOooOOo
 if 78 - 78: O0 % O0
 if 72 - 72: o0oOOo0O0Ooo * IiII / II111iiii / iIii1I11I1II1
 if 41 - 41: iII111i / Ii1I
 if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 if 24 - 24: IiII / Oo0Ooo
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 90 - 90: ooOoO0o . OOooOOo - Ii1I
 if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
 if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
 if 55 - 55: ooOoO0o - II111iiii . ooOoO0o . iII111i / OoooooooOO
 Ii = { "type" : "interfaces" , "interfaces" : [ ] }
 if 51 - 51: I1IiiI * I1Ii111 - ooOoO0o + IiII
 for o0o in list ( lisp_myinterfaces . values ( ) ) :
  if ( o0o . instance_id == None ) : continue
  ooiIII = { "interface" : o0o . device ,
 "instance-id" : str ( o0o . instance_id ) }
  Ii [ "interfaces" ] . append ( ooiIII )
  if 22 - 22: OoOoOO00 % Ii1I + iII111i
  if 64 - 64: ooOoO0o
 lisp_write_to_dp_socket ( Ii )
 return
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
def lisp_parse_auth_key ( value ) :
 i1I1i1II11I = value . split ( "[" )
 I11IIIIII1II = { }
 if ( len ( i1I1i1II11I ) == 1 ) :
  I11IIIIII1II [ 0 ] = value
  return ( I11IIIIII1II )
  if 22 - 22: OoO0O00
  if 40 - 40: I1ii11iIi11i * I1Ii111
 for O0O0o00 in i1I1i1II11I :
  if ( O0O0o00 == "" ) : continue
  o00O = O0O0o00 . find ( "]" )
  IIIOo0O = O0O0o00 [ 0 : o00O ]
  try : IIIOo0O = int ( IIIOo0O )
  except : return
  if 6 - 6: i11iIiiIii . o0oOOo0O0Ooo * iIii1I11I1II1 . OoOoOO00 . II111iiii
  I11IIIIII1II [ IIIOo0O ] = O0O0o00 [ o00O + 1 : : ]
  if 67 - 67: OoO0O00 - Oo0Ooo + OOooOOo / OoOoOO00 + OOooOOo
 return ( I11IIIIII1II )
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
def lisp_reassemble ( packet ) :
 ooOo0oO0O = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 73 - 73: OoO0O00 . I1IiiI / o0oOOo0O0Ooo
 if 12 - 12: I11i * i11iIiiIii - O0 * o0oOOo0O0Ooo - IiII + I1IiiI
 if 7 - 7: oO0o + I1Ii111 . o0oOOo0O0Ooo / IiII + iIii1I11I1II1 % I1Ii111
 if 24 - 24: i11iIiiIii + iIii1I11I1II1
 if ( ooOo0oO0O == 0 or ooOo0oO0O == 0x4000 ) : return ( packet )
 if 22 - 22: i11iIiiIii . II111iiii / o0oOOo0O0Ooo / Ii1I . O0 . OoOoOO00
 if 89 - 89: O0 * Oo0Ooo + I1Ii111 + ooOoO0o * OoOoOO00
 if 20 - 20: OoO0O00 - OoOoOO00
 if 84 - 84: iIii1I11I1II1 + ooOoO0o . o0oOOo0O0Ooo % iII111i
 iIIi1I1Ii1 = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 OO00oo00O0O0O = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 35 - 35: I11i - oO0o * oO0o / OoooooooOO + iII111i + OoOoOO00
 I1II = ( ooOo0oO0O & 0x2000 == 0 and ( ooOo0oO0O & 0x1fff ) != 0 )
 Ii = [ ( ooOo0oO0O & 0x1fff ) * 8 , OO00oo00O0O0O - 20 , packet , I1II ]
 if 25 - 25: o0oOOo0O0Ooo % Oo0Ooo . Oo0Ooo + OoO0O00
 if 23 - 23: I11i + I1ii11iIi11i * iIii1I11I1II1 - i1IIi
 if 33 - 33: I1IiiI + o0oOOo0O0Ooo . OoOoOO00
 if 35 - 35: iII111i / Ii1I
 if 57 - 57: ooOoO0o . I1IiiI * OOooOOo
 if 87 - 87: I11i - I11i % iII111i - Ii1I
 if 29 - 29: oO0o - ooOoO0o * iIii1I11I1II1 / OoOoOO00
 if 34 - 34: I1IiiI . Oo0Ooo
 if ( ooOo0oO0O == 0x2000 ) :
  II1 , Ooo0000o00OO = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  II1 = socket . ntohs ( II1 )
  Ooo0000o00OO = socket . ntohs ( Ooo0000o00OO )
  if ( Ooo0000o00OO not in [ 4341 , 8472 , 4789 ] and II1 != 4341 ) :
   lisp_reassembly_queue [ iIIi1I1Ii1 ] = [ ]
   Ii [ 2 ] = None
   if 4 - 4: Ii1I - II111iiii * iII111i / oO0o - I1IiiI
   if 32 - 32: iIii1I11I1II1 - I11i
   if 49 - 49: I11i * I1Ii111 - iIii1I11I1II1 * O0
   if 72 - 72: I1IiiI * iII111i
   if 61 - 61: Ii1I * Oo0Ooo * I1Ii111 % I11i + iII111i % oO0o
   if 67 - 67: IiII
 if ( iIIi1I1Ii1 not in lisp_reassembly_queue ) :
  lisp_reassembly_queue [ iIIi1I1Ii1 ] = [ ]
  if 90 - 90: o0oOOo0O0Ooo
  if 5 - 5: i1IIi
  if 55 - 55: Ii1I
  if 46 - 46: OOooOOo / iII111i . i1IIi . i11iIiiIii . iIii1I11I1II1 % I11i
  if 62 - 62: I11i % II111iiii % OoooooooOO * ooOoO0o / oO0o
 queue = lisp_reassembly_queue [ iIIi1I1Ii1 ]
 if 29 - 29: o0oOOo0O0Ooo / O0 / OoO0O00
 if 23 - 23: Ii1I + i11iIiiIii % IiII
 if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
 if 49 - 49: O0
 if 72 - 72: I1Ii111
 if ( len ( queue ) == 1 and queue [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( iIIi1I1Ii1 ) . zfill ( 4 ) ) )
  if 96 - 96: II111iiii / OOooOOo % i1IIi / Oo0Ooo
  return ( None )
  if 22 - 22: I1IiiI % iIii1I11I1II1 % I1ii11iIi11i
  if 68 - 68: iII111i + I11i
  if 61 - 61: oO0o . I1Ii111
  if 74 - 74: O0 . Ii1I - iII111i % IiII + II111iiii
  if 71 - 71: oO0o + Ii1I % oO0o
 queue . append ( Ii )
 queue = sorted ( queue )
 if 17 - 17: I1Ii111 % I1Ii111 * o0oOOo0O0Ooo
 if 84 - 84: I1Ii111 + iII111i . i1IIi / O0 / I1Ii111 + o0oOOo0O0Ooo
 if 70 - 70: O0 % ooOoO0o - iII111i + oO0o
 if 12 - 12: I1Ii111 - OoO0O00 % II111iiii % ooOoO0o / II111iiii % OoOoOO00
 iI1ii11Ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iI1ii11Ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 O00ooOoO0O0Ooo = iI1ii11Ii . print_address_no_iid ( )
 iI1ii11Ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 I1Io00o00 = iI1ii11Ii . print_address_no_iid ( )
 iI1ii11Ii = red ( "{} -> {}" . format ( O00ooOoO0O0Ooo , I1Io00o00 ) , False )
 if 70 - 70: i11iIiiIii * oO0o . I11i - OoooooooOO / I1ii11iIi11i
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if Ii [ 2 ] == None else "" , iI1ii11Ii , lisp_hex_string ( iIIi1I1Ii1 ) . zfill ( 4 ) ,
 # I11i
 # i11iIiiIii * OoooooooOO + I1Ii111 / Oo0Ooo / OoooooooOO / OoOoOO00
 lisp_hex_string ( ooOo0oO0O ) . zfill ( 4 ) ) )
 if 56 - 56: II111iiii % i1IIi % OoO0O00 / I1ii11iIi11i - Oo0Ooo
 if 72 - 72: I1IiiI
 if 97 - 97: Ii1I - I1ii11iIi11i
 if 51 - 51: Ii1I * I11i . I1ii11iIi11i
 if 26 - 26: Ii1I . OOooOOo / iII111i % OoOoOO00
 if ( queue [ 0 ] [ 0 ] != 0 or queue [ - 1 ] [ 3 ] == False ) : return ( None )
 II1ii = queue [ 0 ]
 for IiI111 in queue [ 1 : : ] :
  ooOo0oO0O = IiI111 [ 0 ]
  IIi1IIIiI111I , iII1i1iiI = II1ii [ 0 ] , II1ii [ 1 ]
  if ( IIi1IIIiI111I + iII1i1iiI != ooOo0oO0O ) : return ( None )
  II1ii = IiI111
  if 22 - 22: oO0o . OOooOOo / OOooOOo % Oo0Ooo % ooOoO0o - OoO0O00
 lisp_reassembly_queue . pop ( iIIi1I1Ii1 )
 if 6 - 6: Ii1I - i1IIi
 if 43 - 43: OoO0O00 + I1ii11iIi11i * iII111i % i11iIiiIii
 if 55 - 55: IiII
 if 6 - 6: IiII % iIii1I11I1II1 + I1IiiI - II111iiii + O0
 if 9 - 9: i1IIi
 packet = queue [ 0 ] [ 2 ]
 for IiI111 in queue [ 1 : : ] : packet += IiI111 [ 2 ] [ 20 : : ]
 if 58 - 58: IiII . iII111i % O0 . Ii1I * Oo0Ooo
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( iIIi1I1Ii1 ) . zfill ( 4 ) , len ( packet ) ) )
 if 54 - 54: OoO0O00 % OOooOOo - OoO0O00 . Oo0Ooo % i1IIi
 if 95 - 95: iII111i . OoooooooOO . o0oOOo0O0Ooo / II111iiii - OoooooooOO / I1Ii111
 if 11 - 11: II111iiii / iII111i . oO0o / ooOoO0o / OOooOOo + OoO0O00
 if 37 - 37: iIii1I11I1II1 * O0
 if 64 - 64: I1Ii111 - II111iiii + oO0o % ooOoO0o * oO0o
 OOOOo0o0O0o = socket . htons ( len ( packet ) )
 o00O0O0OoO = packet [ 0 : 2 ] + struct . pack ( "H" , OOOOo0o0O0o ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
 if 27 - 27: OoOoOO00 . I11i / OoOoOO00
 o00O0O0OoO = lisp_ip_checksum ( o00O0O0OoO )
 return ( o00O0O0OoO + packet [ 20 : : ] )
 if 96 - 96: OoO0O00 - I1IiiI
 if 73 - 73: I1IiiI - o0oOOo0O0Ooo - I1Ii111
 if 34 - 34: iIii1I11I1II1 - i1IIi + OoO0O00 % Oo0Ooo + i1IIi
 if 46 - 46: I1IiiI
 if 82 - 82: iII111i . i1IIi
 if 38 - 38: Ii1I . I1IiiI . I1ii11iIi11i
 if 26 - 26: O0 - II111iiii * I1Ii111 - OoOoOO00
 if 96 - 96: I11i * Oo0Ooo / OOooOOo - IiII
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 O00oO000Oo0 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_decap ) : return ( O00oO000Oo0 )
 if 75 - 75: OoooooooOO - O0
 O00oO000Oo0 = addr . print_address_no_iid ( )
 if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_decap ) : return ( O00oO000Oo0 )
 if 39 - 39: i11iIiiIii / Ii1I / ooOoO0o
 if 93 - 93: o0oOOo0O0Ooo - Oo0Ooo / oO0o / OoOoOO00
 if 75 - 75: o0oOOo0O0Ooo * ooOoO0o % Ii1I
 if 94 - 94: OoooooooOO + II111iiii / iIii1I11I1II1 * ooOoO0o
 if 85 - 85: ooOoO0o / IiII
 for iiIiii1ii in lisp_crypto_keys_by_rloc_decap :
  I1II1I1I = iiIiii1ii . split ( ":" )
  if ( len ( I1II1I1I ) == 1 ) : continue
  I1II1I1I = I1II1I1I [ 0 ] if len ( I1II1I1I ) == 2 else ":" . join ( I1II1I1I [ 0 : - 1 ] )
  if ( I1II1I1I == O00oO000Oo0 ) :
   oOoOOoo = lisp_crypto_keys_by_rloc_decap [ iiIiii1ii ]
   lisp_crypto_keys_by_rloc_decap [ O00oO000Oo0 ] = oOoOOoo
   return ( O00oO000Oo0 )
   if 59 - 59: I1Ii111 + I1ii11iIi11i + OoO0O00 % oO0o . i1IIi % O0
   if 22 - 22: i1IIi * OoOoOO00 + Ii1I
 return ( None )
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
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 O0O0o0oo00o = addr + ":" + str ( port )
 if 12 - 12: OoooooooOO + IiII . iII111i + I1IiiI
 if ( lisp_i_am_rtr ) :
  if ( addr in lisp_rloc_probe_list ) : return ( addr )
  if 18 - 18: Oo0Ooo / o0oOOo0O0Ooo + o0oOOo0O0Ooo + ooOoO0o
  if 62 - 62: Ii1I / OoOoOO00 . O0 - IiII + I1IiiI
  if 44 - 44: OoooooooOO / i11iIiiIii + Ii1I - Oo0Ooo
  if 73 - 73: o0oOOo0O0Ooo * I1IiiI * O0
  if 78 - 78: OoooooooOO % OoO0O00 / OoOoOO00 * O0 * I11i - i1IIi
  if 61 - 61: iII111i * OoO0O00
  for oOoO in list ( lisp_nat_state_info . values ( ) ) :
   for Iii1IiIII in oOoO :
    if ( addr == Iii1IiIII . address ) : return ( O0O0o0oo00o )
    if 55 - 55: IiII + II111iiii . II111iiii + I1IiiI / I1Ii111 . o0oOOo0O0Ooo
    if 42 - 42: OoooooooOO / ooOoO0o % II111iiii - ooOoO0o
  return ( addr )
  if 15 - 15: II111iiii + I1IiiI
 return ( O0O0o0oo00o )
 if 10 - 10: OoO0O00 . OOooOOo + iIii1I11I1II1 / iIii1I11I1II1 / o0oOOo0O0Ooo
 if 31 - 31: Ii1I
 if 14 - 14: OOooOOo * I1Ii111 % OoO0O00
 if 49 - 49: I1IiiI . iII111i . II111iiii
 if 60 - 60: OoOoOO00
 if 71 - 71: O0 * OOooOOo . I1IiiI . I1Ii111 * I11i
 if 45 - 45: O0 . O0 . II111iiii * ooOoO0o
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 2 - 2: OoO0O00 . o0oOOo0O0Ooo
 if 48 - 48: Ii1I
 if 45 - 45: I1ii11iIi11i - I11i + Ii1I
 if 82 - 82: iII111i
 if 81 - 81: i1IIi % OOooOOo - OoO0O00 - Oo0Ooo
 if 19 - 19: i1IIi
 if 97 - 97: OoO0O00 + i11iIiiIii % I1IiiI * Ii1I
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
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
 if 12 - 12: OOooOOo + iIii1I11I1II1 % I1Ii111 + OOooOOo
 if 19 - 19: OoO0O00 / I1IiiI - o0oOOo0O0Ooo - i1IIi + I1ii11iIi11i * OoooooooOO
 if 74 - 74: I1Ii111 . I11i / Oo0Ooo
 if 88 - 88: oO0o % OoO0O00 - i11iIiiIii % I1Ii111 / O0 * IiII
 if 99 - 99: o0oOOo0O0Ooo . ooOoO0o / i11iIiiIii
def lisp_is_rloc_probe ( packet , device , rr ) :
 ii11 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == 17 )
 if ( ii11 == False ) : return ( [ packet , None , None , None ] )
 if 44 - 44: IiII + OOooOOo % OoO0O00 . OoooooooOO * O0
 II1 = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 Ooo0000o00OO = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 Oo000oOo = ( socket . htons ( LISP_CTRL_PORT ) in [ II1 , Ooo0000o00OO ] )
 if ( Oo000oOo == False ) : return ( [ packet , None , None , None ] )
 if 92 - 92: Ii1I . o0oOOo0O0Ooo - i1IIi + i11iIiiIii + Ii1I
 if ( rr == 0 ) :
  I1III1 = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( I1III1 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  I1III1 = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
  if ( I1III1 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  I1III1 = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( I1III1 == False ) :
   I1III1 = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
   if ( I1III1 == False ) : return ( [ packet , None , None , None ] )
   if 21 - 21: IiII . i1IIi
   if 48 - 48: i1IIi
   if 56 - 56: II111iiii + i1IIi - oO0o * I1ii11iIi11i % i1IIi
   if 48 - 48: ooOoO0o + I1IiiI - o0oOOo0O0Ooo + Ii1I
   if 99 - 99: OOooOOo / II111iiii + II111iiii + I11i
   if 9 - 9: i11iIiiIii
 IiiiiI = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IiiiiI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 27 - 27: I1Ii111 * O0
 if 9 - 9: i1IIi - Oo0Ooo - i11iIiiIii / iIii1I11I1II1 . i1IIi
 if 2 - 2: I11i + II111iiii - I11i / oO0o / I11i
 if 73 - 73: IiII % I1Ii111 . OoOoOO00
 if ( IiiiiI . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 96 - 96: I1IiiI / ooOoO0o / iIii1I11I1II1
 if 91 - 91: Ii1I . I11i
 if 87 - 87: Oo0Ooo / IiII * OOooOOo + I1ii11iIi11i . I11i
 if 56 - 56: oO0o + oO0o % o0oOOo0O0Ooo + OOooOOo . II111iiii + i11iIiiIii
 IiiiiI = IiiiiI . print_address_no_iid ( )
 i11I1Ii1Iiii1 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 o0ooo000o00O = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 45 - 45: iIii1I11I1II1 / o0oOOo0O0Ooo * OoooooooOO - Oo0Ooo
 IIIIiiI1iIiI = bold ( "Receive(pcap-{})" . format ( device ) , False )
 iIi1iii = bold ( "from " + IiiiiI , False )
 ooo0OO0OOooO0 = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( IIIIiiI1iIiI , len ( packet ) , iIi1iii , i11I1Ii1Iiii1 , ooo0OO0OOooO0 ) )
 if 77 - 77: II111iiii
 return ( [ packet , IiiiiI , i11I1Ii1Iiii1 , o0ooo000o00O ] )
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
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 91 - 91: I1IiiI % Ii1I - OOooOOo - Oo0Ooo / I1IiiI / OoO0O00
 OO0oOOOOO = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 40 - 40: OoooooooOO
 lisp_write_to_dp_socket ( OO0oOOOOO )
 return
 if 71 - 71: OOooOOo
 if 88 - 88: O0
 if 44 - 44: II111iiii - IiII / I1IiiI + ooOoO0o % iII111i - iII111i
 if 53 - 53: OoooooooOO
 if 41 - 41: i1IIi - oO0o
 if 41 - 41: I11i
 if 92 - 92: i11iIiiIii
 if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
def lisp_external_data_plane ( ) :
 I11ii1iI11 = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( getoutput ( I11ii1iI11 ) != "" ) : return ( True )
 if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 77 - 77: i1IIi
 if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
 if 65 - 65: O0 / OoOoOO00
 if 77 - 77: OoO0O00
 if 17 - 17: i1IIi
 if 35 - 35: OoOoOO00
 if 61 - 61: I1Ii111
 if 78 - 78: I1Ii111 * Ii1I % Ii1I + I1IiiI
 if 83 - 83: iIii1I11I1II1 + O0 / IiII . iIii1I11I1II1
 if 74 - 74: Oo0Ooo
 if 60 - 60: OoooooooOO
 if 16 - 16: iIii1I11I1II1 - OoOoOO00 / I1ii11iIi11i % O0 % o0oOOo0O0Ooo
 if 99 - 99: ooOoO0o . o0oOOo0O0Ooo - O0 * I1Ii111 . i11iIiiIii / iIii1I11I1II1
 if 40 - 40: iIii1I11I1II1 + oO0o / iIii1I11I1II1 - i1IIi % OoO0O00
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 22 - 22: OOooOOo
 OooOo000 = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 68 - 68: i11iIiiIii - OoOoOO00 / I1Ii111 * ooOoO0o
 if ( do_clear == False ) :
  oOOOO0oooo0o = OooOo000 [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , oOOOO0oooo0o )
  if 67 - 67: Oo0Ooo
  if 22 - 22: I1ii11iIi11i
 lisp_write_to_dp_socket ( OooOo000 )
 return
 if 23 - 23: OoOoOO00 + II111iiii - oO0o
 if 59 - 59: Oo0Ooo % I1IiiI * I1IiiI / iIii1I11I1II1 . OoOoOO00 % I11i
 if 62 - 62: OOooOOo % Ii1I / IiII % oO0o - I1Ii111
 if 47 - 47: OoO0O00
 if 78 - 78: O0 * II111iiii % O0 * O0 / oO0o
 if 47 - 47: Oo0Ooo . Oo0Ooo . I1IiiI / OoO0O00 + II111iiii + IiII
 if 23 - 23: i1IIi . II111iiii
 if 60 - 60: ooOoO0o * oO0o + Oo0Ooo / iIii1I11I1II1
 if 74 - 74: OoooooooOO + II111iiii - IiII + O0
 if 62 - 62: O0 . I11i * oO0o
 if 88 - 88: iII111i * iII111i - ooOoO0o + OoO0O00 . iII111i
 if 44 - 44: I11i / I1Ii111
 if 77 - 77: oO0o * OoOoOO00 * O0 % IiII
 if 45 - 45: OoOoOO00
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( "entries" not in msg ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 66 - 66: I11i
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 10 - 10: i11iIiiIii - O0 / iII111i * i11iIiiIii * OoooooooOO - oO0o
  if 70 - 70: i1IIi / IiII + II111iiii - I1ii11iIi11i . OoooooooOO - i1IIi
 for msg in msg [ "entries" ] :
  if ( "eid-prefix" not in msg ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 34 - 34: OoOoOO00 + iII111i - I11i . IiII
  oOOoo = msg [ "eid-prefix" ]
  if 79 - 79: ooOoO0o - II111iiii + I1IiiI - o0oOOo0O0Ooo . Ii1I
  if ( "instance-id" not in msg ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 16 - 16: o0oOOo0O0Ooo . i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
  i1I1iI = int ( msg [ "instance-id" ] )
  if 57 - 57: IiII
  if 89 - 89: I1ii11iIi11i - I1Ii111 + o0oOOo0O0Ooo
  if 62 - 62: I1ii11iIi11i + OoooooooOO * OOooOOo
  if 49 - 49: i1IIi - I11i * II111iiii
  O0o00o0Oo = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
  O0o00o0Oo . store_prefix ( oOOoo )
  Ii111 = lisp_map_cache_lookup ( None , O0o00o0Oo )
  if ( Ii111 == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( oOOoo ) )
   if 4 - 4: o0oOOo0O0Ooo + o0oOOo0O0Ooo
   continue
   if 57 - 57: I1IiiI * OOooOOo . i11iIiiIii * oO0o - OoOoOO00
   if 35 - 35: O0
  if ( "rlocs" not in msg ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( oOOoo ) )
   if 65 - 65: Oo0Ooo
   continue
   if 100 - 100: I1Ii111 . o0oOOo0O0Ooo * OoooooooOO . o0oOOo0O0Ooo
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 90 - 90: i11iIiiIii . I1IiiI + ooOoO0o * OoooooooOO * OoooooooOO + oO0o
  o0O000OOOO0o = msg [ "rlocs" ]
  if 50 - 50: I1Ii111 . II111iiii - I1IiiI
  if 2 - 2: I1ii11iIi11i + o0oOOo0O0Ooo + OoOoOO00 - iIii1I11I1II1
  if 25 - 25: OOooOOo . ooOoO0o % II111iiii
  if 20 - 20: o0oOOo0O0Ooo * O0 - I11i
  for II1iii111 in o0O000OOOO0o :
   if ( "rloc" not in II1iii111 ) : continue
   if 45 - 45: OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo * OoO0O00
   iIiIi111 = II1iii111 [ "rloc" ]
   if ( iIiIi111 == "no-address" ) : continue
   if 4 - 4: OOooOOo . IiII / I1Ii111 . II111iiii * I11i
   OO0Oo00oo = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   OO0Oo00oo . store_address ( iIiIi111 )
   if 33 - 33: I1ii11iIi11i / Oo0Ooo % i11iIiiIii
   i1iiI1i1 = Ii111 . get_rloc ( OO0Oo00oo )
   if ( i1iiI1i1 == None ) : continue
   if 37 - 37: Oo0Ooo - I1Ii111 - IiII / oO0o % I1IiiI / I1Ii111
   if 80 - 80: iII111i - oO0o % i1IIi * iIii1I11I1II1 . oO0o
   if 86 - 86: Ii1I
   if 36 - 36: i11iIiiIii % i11iIiiIii
   oO000o = 0 if ( "packet-count" not in II1iii111 ) else II1iii111 [ "packet-count" ]
   if 28 - 28: II111iiii * iII111i - o0oOOo0O0Ooo
   iI1ii = 0 if ( "byte-count" not in II1iii111 ) else II1iii111 [ "byte-count" ]
   if 42 - 42: iII111i - iII111i
   iIiIIIIIii = 0 if ( "seconds-last-packet" not in II1iii111 ) else II1iii111 [ "seconds-last-packet" ]
   if 93 - 93: I11i * iIii1I11I1II1
   if 89 - 89: II111iiii . O0
   i1iiI1i1 . stats . packet_count += oO000o
   i1iiI1i1 . stats . byte_count += iI1ii
   i1iiI1i1 . stats . last_increment = lisp_get_timestamp ( ) - iIiIIIIIii
   if 28 - 28: I1ii11iIi11i * IiII
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( oO000o , iI1ii ,
 iIiIIIIIii , oOOoo , iIiIi111 ) )
   if 34 - 34: o0oOOo0O0Ooo . OOooOOo
   if 61 - 61: I1IiiI / i1IIi % oO0o * OoO0O00 - II111iiii
   if 2 - 2: I1IiiI . ooOoO0o
   if 82 - 82: O0 / oO0o
   if 27 - 27: ooOoO0o + i11iIiiIii * o0oOOo0O0Ooo
  if ( Ii111 . group . is_null ( ) and Ii111 . has_ttl_elapsed ( ) ) :
   oOOoo = green ( Ii111 . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( oOOoo ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , Ii111 . eid , None )
   if 10 - 10: OOooOOo * OoooooooOO
   if 1 - 1: iII111i . I1ii11iIi11i - ooOoO0o + OoO0O00 . OoooooooOO
 return
 if 71 - 71: I1ii11iIi11i
 if 59 - 59: I1Ii111 + OoO0O00 + II111iiii
 if 12 - 12: I1Ii111 % I1ii11iIi11i - I1Ii111 + I11i
 if 62 - 62: I1Ii111 % I11i % IiII - ooOoO0o . oO0o - OoooooooOO
 if 14 - 14: OOooOOo + Oo0Ooo % i1IIi + iIii1I11I1II1
 if 64 - 64: OoOoOO00 / Ii1I * Oo0Ooo - I1ii11iIi11i
 if 9 - 9: i11iIiiIii % Oo0Ooo + IiII + Ii1I . ooOoO0o / i1IIi
 if 40 - 40: I1Ii111 + I1IiiI - Ii1I
 if 27 - 27: i1IIi
 if 66 - 66: iII111i - ooOoO0o / i11iIiiIii + I1ii11iIi11i - Ii1I
 if 9 - 9: O0
 if 96 - 96: Oo0Ooo . II111iiii
 if 41 - 41: I1ii11iIi11i % o0oOOo0O0Ooo
 if 86 - 86: O0 * OoOoOO00 * O0 / O0
 if 50 - 50: OoooooooOO
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
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 47 - 47: OOooOOo - OOooOOo * I1Ii111
 if 24 - 24: I1ii11iIi11i
 if 37 - 37: II111iiii - iIii1I11I1II1 / o0oOOo0O0Ooo . O0 + II111iiii
 if 9 - 9: o0oOOo0O0Ooo
 if 47 - 47: Ii1I * I1Ii111 / II111iiii
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  OO0oOOOOO = "stats%{}" . format ( json . dumps ( msg ) )
  OO0oOOOOO = lisp_command_ipc ( OO0oOOOOO , "lisp-itr" )
  lisp_ipc ( OO0oOOOOO , lisp_ipc_socket , "lisp-etr" )
  return
  if 73 - 73: ooOoO0o
  if 53 - 53: IiII . Oo0Ooo
  if 54 - 54: i11iIiiIii % ooOoO0o % I1Ii111 + o0oOOo0O0Ooo
  if 2 - 2: IiII
  if 25 - 25: OoOoOO00 . OoO0O00 * o0oOOo0O0Ooo . OoooooooOO - Oo0Ooo + I1IiiI
  if 82 - 82: OoO0O00 - Ii1I * I11i * o0oOOo0O0Ooo
  if 17 - 17: OoooooooOO + I1Ii111
  if 91 - 91: iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo
 OO0oOOOOO = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( OO0oOOOOO , msg ) )
 if 98 - 98: o0oOOo0O0Ooo % II111iiii * IiII - i11iIiiIii * oO0o
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 15 - 15: O0 - II111iiii - Oo0Ooo . I1ii11iIi11i % OoO0O00
 OO0O0 = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 60 - 60: I1IiiI - O0 + OOooOOo * i11iIiiIii * i1IIi
 for iiIi11I1I in OO0O0 :
  oO000o = 0 if ( iiIi11I1I not in msg ) else msg [ iiIi11I1I ] [ "packet-count" ]
  lisp_decap_stats [ iiIi11I1I ] . packet_count += oO000o
  if 50 - 50: oO0o - I1ii11iIi11i
  iI1ii = 0 if ( iiIi11I1I not in msg ) else msg [ iiIi11I1I ] [ "byte-count" ]
  lisp_decap_stats [ iiIi11I1I ] . byte_count += iI1ii
  if 47 - 47: i11iIiiIii . o0oOOo0O0Ooo % iII111i
  iIiIIIIIii = 0 if ( iiIi11I1I not in msg ) else msg [ iiIi11I1I ] [ "seconds-last-packet" ]
  if 12 - 12: OoOoOO00 * iIii1I11I1II1 . iII111i * o0oOOo0O0Ooo * OoooooooOO
  lisp_decap_stats [ iiIi11I1I ] . last_increment = lisp_get_timestamp ( ) - iIiIIIIIii
  if 49 - 49: I1IiiI % I1Ii111 * OoOoOO00 * II111iiii - Ii1I
 return
 if 34 - 34: O0 - OoO0O00 % O0
 if 55 - 55: o0oOOo0O0Ooo . i1IIi * I1ii11iIi11i + OoooooooOO + I1IiiI / OoO0O00
 if 85 - 85: Ii1I % OoOoOO00 / I1ii11iIi11i . OoOoOO00
 if 4 - 4: I1Ii111 - Oo0Ooo
 if 94 - 94: iIii1I11I1II1
 if 55 - 55: Ii1I . o0oOOo0O0Ooo * i11iIiiIii
 if 89 - 89: O0 % iIii1I11I1II1 . I1ii11iIi11i + OOooOOo / IiII
 if 84 - 84: i11iIiiIii . Oo0Ooo + OoOoOO00
 if 75 - 75: o0oOOo0O0Ooo
 if 54 - 54: o0oOOo0O0Ooo
 if 95 - 95: Ii1I % I11i - OoooooooOO
 if 11 - 11: OoO0O00 - oO0o
 if 50 - 50: II111iiii * IiII
 if 26 - 26: OoO0O00 . II111iiii
 if 19 - 19: iII111i / i11iIiiIii
 if 31 - 31: I1Ii111 / I1Ii111 % IiII
 if 68 - 68: O0 / OOooOOo % OoOoOO00
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 OoO00Oo0 , IiiiiI = punt_socket . recvfrom ( 4000 )
 if 56 - 56: OOooOOo + II111iiii / II111iiii - I1ii11iIi11i - OoO0O00
 iIII11III = json . loads ( OoO00Oo0 )
 if ( type ( iIII11III ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( IiiiiI ) )
  if 24 - 24: O0 / OoooooooOO % II111iiii
  return
  if 88 - 88: iII111i / ooOoO0o % oO0o % I1ii11iIi11i - i1IIi
 IIiIIi11II = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( IIiIIi11II , IiiiiI , iIII11III ) )
 if 15 - 15: II111iiii + iIii1I11I1II1
 if ( "type" not in iIII11III ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 100 - 100: OOooOOo
  if 43 - 43: OoO0O00 + I1Ii111 + OoOoOO00
  if 78 - 78: I11i
  if 30 - 30: iIii1I11I1II1
  if 74 - 74: I1IiiI - Oo0Ooo - i1IIi . iIii1I11I1II1 - I11i
 if ( iIII11III [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( iIII11III , lisp_send_sockets , lisp_ephem_port )
  return
  if 57 - 57: I1IiiI - i11iIiiIii - I1ii11iIi11i
 if ( iIII11III [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( iIII11III , punt_socket )
  return
  if 49 - 49: i1IIi . O0 % Ii1I * i1IIi
  if 39 - 39: I1ii11iIi11i
  if 74 - 74: II111iiii % oO0o * Oo0Ooo / iIii1I11I1II1
  if 81 - 81: II111iiii + OoOoOO00 * O0
  if 64 - 64: iIii1I11I1II1 * Ii1I
 if ( iIII11III [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 5 - 5: I11i . I11i / i1IIi - o0oOOo0O0Ooo % Oo0Ooo
  if 85 - 85: OOooOOo
  if 32 - 32: iII111i
  if 27 - 27: iIii1I11I1II1 - iII111i
  if 68 - 68: oO0o + OoooooooOO - i1IIi * OoOoOO00 % Oo0Ooo
 if ( iIII11III [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 19 - 19: IiII * Oo0Ooo + I1IiiI * I1Ii111 % iIii1I11I1II1
 if ( "interface" not in iIII11III ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( IiiiiI ) )
  if 15 - 15: II111iiii % OoO0O00 % Oo0Ooo + I1Ii111
  return
  if 54 - 54: I1Ii111 + OOooOOo
  if 6 - 6: Ii1I
  if 8 - 8: OoO0O00
  if 91 - 91: Ii1I
  if 12 - 12: OoooooooOO + i11iIiiIii
 i1iiI = iIII11III [ "interface" ]
 if ( i1iiI == "" ) :
  i1I1iI = int ( iIII11III [ "instance-id" ] )
  if ( i1I1iI == - 1 ) : return
 else :
  i1I1iI = lisp_get_interface_instance_id ( i1iiI , None )
  if 63 - 63: OOooOOo . i11iIiiIii
  if 50 - 50: IiII % i11iIiiIii - iII111i . OoOoOO00 / Oo0Ooo
  if 30 - 30: Oo0Ooo . II111iiii + OoooooooOO % OoO0O00 * ooOoO0o * iIii1I11I1II1
  if 91 - 91: OoooooooOO
  if 86 - 86: iII111i / OoooooooOO - I1ii11iIi11i
 oo0Oo = None
 if ( "source-eid" in iIII11III ) :
  i1i1I11I = iIII11III [ "source-eid" ]
  oo0Oo = lisp_address ( LISP_AFI_NONE , i1i1I11I , 0 , i1I1iI )
  if ( oo0Oo . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( i1i1I11I ) )
   return
   if 63 - 63: ooOoO0o % Ii1I * I1IiiI
   if 48 - 48: iII111i - iII111i - o0oOOo0O0Ooo + ooOoO0o - o0oOOo0O0Ooo / Ii1I
 Ii1III1 = None
 if ( "dest-eid" in iIII11III ) :
  ii1I1II = iIII11III [ "dest-eid" ]
  Ii1III1 = lisp_address ( LISP_AFI_NONE , ii1I1II , 0 , i1I1iI )
  if ( Ii1III1 . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( ii1I1II ) )
   return
   if 10 - 10: oO0o
   if 100 - 100: iIii1I11I1II1 * iIii1I11I1II1 . Ii1I - OoOoOO00 + I11i
   if 81 - 81: Oo0Ooo * O0 % OoooooooOO % OoOoOO00
   if 95 - 95: I11i + oO0o * i1IIi * Ii1I . iIii1I11I1II1 % o0oOOo0O0Ooo
   if 97 - 97: I1IiiI . i1IIi * OoOoOO00 / OOooOOo
   if 50 - 50: II111iiii . OoO0O00
   if 60 - 60: I11i . iIii1I11I1II1
   if 41 - 41: II111iiii / I1IiiI
 if ( oo0Oo ) :
  oOO = green ( oo0Oo . print_address ( ) , False )
  Iiii1II1 = lisp_db_for_lookups . lookup_cache ( oo0Oo , False )
  if ( Iiii1II1 != None ) :
   if 2 - 2: IiII / OoOoOO00 + I11i
   if 3 - 3: OoooooooOO + Oo0Ooo + OOooOOo
   if 20 - 20: Ii1I - oO0o - OoO0O00 + I1ii11iIi11i % OoO0O00 . i1IIi
   if 2 - 2: ooOoO0o * IiII . Ii1I
   if 69 - 69: IiII % i1IIi
   if ( Iiii1II1 . dynamic_eid_configured ( ) ) :
    o0o = lisp_allow_dynamic_eid ( i1iiI , oo0Oo )
    if ( o0o != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( Iiii1II1 , oo0Oo , i1iiI , o0o )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( oOO , i1iiI ) )
     if 17 - 17: o0oOOo0O0Ooo . OoO0O00 * ooOoO0o * II111iiii - OoooooooOO % iII111i
     if 47 - 47: I1IiiI * iIii1I11I1II1 - I11i - o0oOOo0O0Ooo
     if 47 - 47: IiII + OoO0O00 % ooOoO0o - iII111i - IiII - oO0o
  else :
   lprint ( "Punt from non-EID source {}" . format ( oOO ) )
   if 63 - 63: OoooooooOO / I1Ii111
   if 90 - 90: I1Ii111 . i11iIiiIii - iIii1I11I1II1 + I1Ii111
   if 67 - 67: IiII - I1ii11iIi11i + ooOoO0o . iIii1I11I1II1 . IiII
   if 13 - 13: I1IiiI / i11iIiiIii % iIii1I11I1II1 - Oo0Ooo . i11iIiiIii + I1IiiI
   if 77 - 77: o0oOOo0O0Ooo / II111iiii + i11iIiiIii % Ii1I . iIii1I11I1II1
   if 66 - 66: iII111i / oO0o - OoO0O00 . Oo0Ooo
 if ( Ii1III1 ) :
  Ii111 = lisp_map_cache_lookup ( oo0Oo , Ii1III1 )
  if ( Ii111 == None or lisp_mr_or_pubsub ( Ii111 . action ) ) :
   if 31 - 31: IiII % O0
   if 46 - 46: iIii1I11I1II1 - OoooooooOO . oO0o % iIii1I11I1II1 / i1IIi + Ii1I
   if 5 - 5: I1ii11iIi11i % II111iiii
   if 17 - 17: i11iIiiIii - II111iiii / O0 % OoO0O00 . Oo0Ooo + IiII
   if 60 - 60: I11i % I1IiiI
   if ( lisp_rate_limit_map_request ( Ii1III1 ) ) : return
   if 99 - 99: oO0o . OOooOOo % iII111i * Ii1I
   iiI11i1i1 = ( Ii111 and Ii111 . action == LISP_SEND_PUBSUB_ACTION )
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 oo0Oo , Ii1III1 , None , iiI11i1i1 )
  else :
   oOO = green ( Ii1III1 . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( oOO ) )
   if 98 - 98: Oo0Ooo * O0 + i1IIi
   if 41 - 41: i1IIi % OoO0O00 * iIii1I11I1II1
 return
 if 2 - 2: I1ii11iIi11i * iII111i . iIii1I11I1II1 * Oo0Ooo
 if 34 - 34: i11iIiiIii % O0 . I1IiiI / ooOoO0o + OoO0O00
 if 28 - 28: Ii1I / iIii1I11I1II1
 if 41 - 41: iIii1I11I1II1
 if 57 - 57: I1Ii111 * o0oOOo0O0Ooo - o0oOOo0O0Ooo * I11i
 if 89 - 89: Ii1I % O0
 if 81 - 81: OoooooooOO / II111iiii - ooOoO0o
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 Ii = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( Ii )
 return ( [ True , jdata ] )
 if 14 - 14: O0
 if 59 - 59: I11i % II111iiii . iIii1I11I1II1 * oO0o % Ii1I
 if 79 - 79: OoooooooOO . II111iiii
 if 55 - 55: II111iiii
 if 2 - 2: I1ii11iIi11i * i1IIi + OOooOOo / OoO0O00 % OoOoOO00 / O0
 if 47 - 47: OoooooooOO - i11iIiiIii - IiII * O0 * iII111i * Ii1I
 if 36 - 36: I1Ii111
 if 85 - 85: Oo0Ooo % OOooOOo
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 10 - 10: O0 + Oo0Ooo + Ii1I % IiII
 if 89 - 89: oO0o / iII111i + OOooOOo
 if 27 - 27: Ii1I / o0oOOo0O0Ooo % I11i
 if 96 - 96: i11iIiiIii % O0
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 11 - 11: II111iiii . i11iIiiIii % ooOoO0o * Ii1I * OoOoOO00 * OoooooooOO
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 80 - 80: OoO0O00
 if 55 - 55: iIii1I11I1II1 % OoO0O00 / II111iiii - OoO0O00
 if 95 - 95: o0oOOo0O0Ooo / OOooOOo * OOooOOo * O0
 if 93 - 93: OOooOOo / ooOoO0o
 if 89 - 89: OoooooooOO + iIii1I11I1II1 / I1ii11iIi11i % iIii1I11I1II1 / iII111i
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 74 - 74: Ii1I + I1IiiI * iII111i / i11iIiiIii - ooOoO0o * OoooooooOO
 if 98 - 98: I1IiiI
 if 85 - 85: OoooooooOO * i1IIi * O0 * OoooooooOO . IiII
 if 22 - 22: ooOoO0o
 if 44 - 44: I1ii11iIi11i + IiII + IiII * I1ii11iIi11i - OoooooooOO / I1Ii111
 if 3 - 3: I1ii11iIi11i + o0oOOo0O0Ooo * I11i / Oo0Ooo
 if 31 - 31: i11iIiiIii % OoO0O00 - oO0o / o0oOOo0O0Ooo % O0
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 oOOoo = eid . print_address ( )
 if ( oOOoo in db . dynamic_eids ) :
  db . dynamic_eids [ oOOoo ] . last_packet = lisp_get_timestamp ( )
  return
  if 53 - 53: iIii1I11I1II1 * I1ii11iIi11i
  if 46 - 46: OOooOOo % OoOoOO00 * iII111i
  if 55 - 55: I1IiiI * iIii1I11I1II1 . OoOoOO00
  if 82 - 82: iIii1I11I1II1 - iII111i % I1IiiI + I1IiiI * i1IIi % O0
  if 63 - 63: I1IiiI + OoOoOO00
 iI1 = lisp_dynamic_eid ( )
 iI1 . dynamic_eid . copy_address ( eid )
 iI1 . interface = routed_interface
 iI1 . last_packet = lisp_get_timestamp ( )
 iI1 . get_timeout ( routed_interface )
 db . dynamic_eids [ oOOoo ] = iI1
 if 55 - 55: o0oOOo0O0Ooo
 OO000OOOOOoO0 = ""
 if ( input_interface != routed_interface ) :
  OO000OOOOOoO0 = ", routed-interface " + routed_interface
  if 8 - 8: OoOoOO00 . Ii1I . I11i . II111iiii
  if 34 - 34: O0 * OoooooooOO + I1Ii111
 OOOo00OoO0O0o = green ( oOOoo , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( OOOo00OoO0O0o , input_interface , OO000OOOOOoO0 , iI1 . timeout ) )
 if 7 - 7: I1Ii111
 if 88 - 88: OOooOOo % OoOoOO00 . I1IiiI . Ii1I
 if 76 - 76: I11i
 if 42 - 42: I1ii11iIi11i . iIii1I11I1II1 % I11i
 if 54 - 54: OoOoOO00 / Ii1I
 OO0oOOOOO = "learn%{}%{}" . format ( oOOoo , routed_interface )
 OO0oOOOOO = lisp_command_ipc ( OO0oOOOOO , "lisp-itr" )
 lisp_ipc ( OO0oOOOOO , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 84 - 84: Oo0Ooo / OoO0O00 . o0oOOo0O0Ooo - iII111i . iII111i - II111iiii
 if 99 - 99: I1Ii111 % Oo0Ooo
 if 61 - 61: OoooooooOO % i11iIiiIii + OOooOOo
 if 53 - 53: iII111i . iIii1I11I1II1
 if 59 - 59: II111iiii . II111iiii - iII111i
 if 46 - 46: oO0o / iIii1I11I1II1 + OoO0O00
 if 33 - 33: Ii1I . iIii1I11I1II1 . O0 * I1ii11iIi11i . OoOoOO00 / i11iIiiIii
 if 85 - 85: iII111i
 if 23 - 23: O0
def lisp_itr_nat_probe ( rloc , rloc_name , lisp_ipc_listen_socket ) :
 iIiIi111 = rloc . print_address_no_iid ( )
 if 83 - 83: i11iIiiIii % OoooooooOO
 if 45 - 45: OoO0O00 + Ii1I
 if 90 - 90: O0 * i1IIi . i1IIi * I1ii11iIi11i + I1ii11iIi11i / i1IIi
 if 52 - 52: O0 / iIii1I11I1II1 * IiII
 OO0oOOOOO = "nat%{}%{}" . format ( iIiIi111 , rloc_name )
 OO0oOOOOO = lisp_command_ipc ( OO0oOOOOO , "lisp-itr" )
 lisp_ipc ( OO0oOOOOO , lisp_ipc_listen_socket , "lisp-etr" )
 return
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
 if 80 - 80: iII111i + OoO0O00 % OoO0O00
 if 4 - 4: OoOoOO00 * I11i * O0 . OoooooooOO + Ii1I % i1IIi
 if 11 - 11: OoOoOO00 % i11iIiiIii . OoOoOO00 % Oo0Ooo * Ii1I
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 67 - 67: IiII - OoOoOO00 / I1Ii111 % oO0o % OOooOOo
 if 19 - 19: OoO0O00 - iII111i
 if 76 - 76: OoOoOO00 * ooOoO0o - iII111i * I1IiiI + I11i
 if 4 - 4: Oo0Ooo
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 95 - 95: Oo0Ooo * i11iIiiIii - O0
 IiI1IIi = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 100 - 100: iIii1I11I1II1 / I1ii11iIi11i - o0oOOo0O0Ooo / iII111i
 for oO0oOo in lisp_crypto_keys_by_rloc_decap :
  if 73 - 73: OoooooooOO
  if 68 - 68: II111iiii / i11iIiiIii % i11iIiiIii % OoooooooOO
  if 81 - 81: i1IIi + O0 . IiII . I1IiiI / ooOoO0o
  if 75 - 75: I1ii11iIi11i / OoOoOO00
  if ( oO0oOo . find ( addr_str ) == - 1 ) : continue
  if 59 - 59: OoO0O00 . OoooooooOO % IiII
  if 35 - 35: I1ii11iIi11i + I1Ii111
  if 25 - 25: iIii1I11I1II1 / I11i % OoooooooOO / Oo0Ooo
  if 4 - 4: i1IIi % i1IIi % oO0o
  if ( oO0oOo == addr_str ) : continue
  if 51 - 51: o0oOOo0O0Ooo * i11iIiiIii
  if 44 - 44: II111iiii - o0oOOo0O0Ooo + i1IIi / I1Ii111 . I11i
  if 17 - 17: OOooOOo - O0 . II111iiii - OoooooooOO + I1ii11iIi11i
  if 100 - 100: OoOoOO00 * OOooOOo % i11iIiiIii / OoOoOO00
  Ii = lisp_crypto_keys_by_rloc_decap [ oO0oOo ]
  if ( Ii == IiI1IIi ) : continue
  if 72 - 72: I1IiiI . oO0o
  if 76 - 76: Ii1I - Oo0Ooo * II111iiii
  if 17 - 17: I1Ii111 * O0
  if 8 - 8: i11iIiiIii / OoO0O00 / OOooOOo
  IIOo = Ii [ 1 ]
  if ( packet_icv != IIOo . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( oO0oOo , False ) ) )
   continue
   if 17 - 17: Ii1I % I1ii11iIi11i % iIii1I11I1II1 * Oo0Ooo - I11i
   if 92 - 92: oO0o
  lprint ( "Changing decap crypto key to {}" . format ( red ( oO0oOo , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = Ii
  if 65 - 65: i11iIiiIii . I11i
 return
 if 5 - 5: Oo0Ooo - iII111i % iIii1I11I1II1 * OoOoOO00
 if 41 - 41: i1IIi * IiII - i11iIiiIii / O0 + Oo0Ooo + ooOoO0o
 if 94 - 94: OoO0O00 . O0 + iIii1I11I1II1 . oO0o % oO0o
 if 7 - 7: I1ii11iIi11i * oO0o / OoOoOO00
 if 89 - 89: OoO0O00 / oO0o % I11i - I1ii11iIi11i . o0oOOo0O0Ooo
 if 46 - 46: i11iIiiIii
 if 99 - 99: i11iIiiIii / oO0o / OoOoOO00 / O0 * I1ii11iIi11i
 if 72 - 72: ooOoO0o - I1Ii111 - iIii1I11I1II1 . I1IiiI
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 77 - 77: Oo0Ooo * OoO0O00
 if 67 - 67: OoOoOO00 . I1Ii111 / I1IiiI * II111iiii
 if 45 - 45: I1ii11iIi11i * o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo
 if 58 - 58: OOooOOo + O0
 if 19 - 19: o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * OOooOOo - Ii1I * OoOoOO00 % OoO0O00 * O0
 if 70 - 70: I1IiiI
 if 17 - 17: I11i % OOooOOo - i11iIiiIii . OoooooooOO % OoO0O00 + OoO0O00
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 OOO0 = dns_name . split ( "." )
 OOO0 = "." . join ( OOO0 [ 1 : : ] )
 return ( OOO0 == lisp_decent_dns_suffix )
 if 24 - 24: Ii1I . OOooOOo . IiII / Oo0Ooo . Oo0Ooo . II111iiii
 if 63 - 63: ooOoO0o . I11i
 if 39 - 39: II111iiii % oO0o % I1IiiI - iIii1I11I1II1 / I1IiiI
 if 94 - 94: iII111i + oO0o
 if 43 - 43: iIii1I11I1II1 + iIii1I11I1II1
 if 8 - 8: iIii1I11I1II1
 if 30 - 30: OOooOOo - I1ii11iIi11i * iIii1I11I1II1 + Oo0Ooo
 if 25 - 25: IiII
 if 78 - 78: OoOoOO00 * iIii1I11I1II1 * ooOoO0o - OoooooooOO - IiII
 if 40 - 40: OoO0O00 . i11iIiiIii + ooOoO0o
def lisp_get_decent_eid_string ( eid ) :
 oOOoo = eid . print_prefix ( )
 if 30 - 30: OOooOOo . OoO0O00 % iII111i - OoO0O00 % i11iIiiIii
 i1iIiIi = None
 oo0o0oOo = 0
 for OOoooOOOo0 , oOoOOooO in lisp_decent_lookup_prefixes . items ( ) :
  if ( eid . is_more_specific ( OOoooOOOo0 ) ) :
   if ( i1iIiIi == None or OOoooOOOo0 . mask_len > oo0o0oOo ) :
    oo0o0oOo = OOoooOOOo0 . mask_len
    i1iIiIi = oOoOOooO
    if 70 - 70: iIii1I11I1II1 / I1ii11iIi11i . I1Ii111 % I1ii11iIi11i
    if 40 - 40: I1Ii111 + o0oOOo0O0Ooo - I11i + OoO0O00
    if 49 - 49: i11iIiiIii % OoO0O00 - Ii1I + I1Ii111
    if 7 - 7: ooOoO0o * I1ii11iIi11i - Ii1I % i1IIi + I11i
    if 22 - 22: I1IiiI - OOooOOo - II111iiii * I1IiiI
    if 93 - 93: OOooOOo + I11i
    if 93 - 93: I1IiiI . I1ii11iIi11i * iII111i
 if ( i1iIiIi == None ) : return ( oOOoo )
 if 25 - 25: Oo0Ooo + o0oOOo0O0Ooo + OoOoOO00
 if 76 - 76: Oo0Ooo * Oo0Ooo + o0oOOo0O0Ooo % I11i + Oo0Ooo / o0oOOo0O0Ooo
 if 76 - 76: OOooOOo . ooOoO0o * iII111i . oO0o
 if 80 - 80: i1IIi . Ii1I
 oO0OooO0 = copy . deepcopy ( eid )
 oO0OooO0 . mask_len = i1iIiIi
 oO0OooO0 . zero_host_bits ( )
 return ( oO0OooO0 . print_prefix ( ) )
 if 72 - 72: II111iiii % ooOoO0o - ooOoO0o - OoOoOO00
 if 20 - 20: Ii1I
 if 75 - 75: o0oOOo0O0Ooo / I1IiiI
 if 91 - 91: OoooooooOO
 if 57 - 57: oO0o * I1IiiI / OoooooooOO . O0
 if 39 - 39: IiII / I1IiiI + i11iIiiIii + IiII - IiII . o0oOOo0O0Ooo
 if 41 - 41: Oo0Ooo + IiII % o0oOOo0O0Ooo
 if 73 - 73: O0
 if 92 - 92: I1ii11iIi11i * o0oOOo0O0Ooo - OoooooooOO * OOooOOo . IiII - o0oOOo0O0Ooo
 if 7 - 7: i1IIi . i11iIiiIii . i1IIi % IiII * iII111i * OoooooooOO
 if 48 - 48: i1IIi . IiII / i1IIi / iII111i
def lisp_get_decent_index ( eid ) :
 if 13 - 13: ooOoO0o - OoOoOO00 + I1ii11iIi11i % ooOoO0o % iIii1I11I1II1
 if 94 - 94: OOooOOo / OoO0O00 / OoO0O00 / Ii1I . IiII
 if 35 - 35: i1IIi
 if 58 - 58: Ii1I - IiII / ooOoO0o % o0oOOo0O0Ooo + I1ii11iIi11i
 if 89 - 89: IiII / OoooooooOO
 oOOoo = lisp_get_decent_eid_string ( eid )
 oOO = oOOoo . encode ( )
 IiIOO0 = hmac . new ( b"lisp-decent" , oOO , hashlib . sha256 ) . hexdigest ( )
 if 68 - 68: Oo0Ooo * OoO0O00 * OoooooooOO - OoOoOO00 % II111iiii
 if 35 - 35: I1ii11iIi11i - OoO0O00 + o0oOOo0O0Ooo * I1IiiI * I11i + Ii1I
 if 14 - 14: i11iIiiIii . o0oOOo0O0Ooo
 if 94 - 94: I1ii11iIi11i * i11iIiiIii
 oooo00o0 = os . getenv ( "LISP_DECENT_HASH_WIDTH" )
 if ( oooo00o0 in [ "" , None ] ) :
  oooo00o0 = 12
 else :
  oooo00o0 = int ( oooo00o0 )
  if ( oooo00o0 > 32 ) :
   oooo00o0 = 12
  else :
   oooo00o0 *= 2
   if 25 - 25: OoO0O00
   if 55 - 55: I1ii11iIi11i . Ii1I - O0 * I1IiiI
   if 32 - 32: I11i . OoooooooOO * I11i - iII111i
 iiI11I1IIIi11 = IiIOO0 [ 0 : oooo00o0 ]
 o00O = int ( iiI11I1IIIi11 , 16 ) % lisp_decent_modulus
 if 42 - 42: OoO0O00 + i11iIiiIii . IiII * i1IIi / I1IiiI
 lprint ( "LISP-Decent modulus {}, hash-width {}, mod-value {}, index {} for {}" . format ( lisp_decent_modulus , old_div ( oooo00o0 , 2 ) , iiI11I1IIIi11 , o00O , oOOoo ) )
 if 77 - 77: ooOoO0o
 if 64 - 64: ooOoO0o + II111iiii - iII111i / O0 % ooOoO0o
 return ( o00O )
 if 23 - 23: OOooOOo / IiII
 if 28 - 28: OoooooooOO * I1IiiI - OoOoOO00 + Oo0Ooo
 if 33 - 33: I11i - OOooOOo + Oo0Ooo - iII111i * iII111i
 if 44 - 44: Oo0Ooo % OoOoOO00 / oO0o
 if 34 - 34: II111iiii + Ii1I + OoOoOO00
 if 9 - 9: I11i / oO0o * OoO0O00
 if 26 - 26: I1IiiI % OOooOOo * OoOoOO00
def lisp_get_decent_dns_name ( eid ) :
 o00O = lisp_get_decent_index ( eid )
 return ( str ( o00O ) + "." + lisp_decent_dns_suffix )
 if 14 - 14: I11i * Oo0Ooo . I1Ii111 * Ii1I . i11iIiiIii * I1ii11iIi11i
 if 11 - 11: oO0o + oO0o + o0oOOo0O0Ooo / iIii1I11I1II1 / I11i
 if 68 - 68: OoooooooOO + i1IIi % I1ii11iIi11i . iII111i
 if 69 - 69: ooOoO0o * II111iiii + i11iIiiIii / oO0o + I1Ii111 - OOooOOo
 if 84 - 84: O0
 if 29 - 29: I11i + o0oOOo0O0Ooo . ooOoO0o * I1Ii111 - o0oOOo0O0Ooo * O0
 if 58 - 58: iII111i . oO0o + i11iIiiIii
 if 2 - 2: OOooOOo * Ii1I
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 O0o00o0Oo = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 o00O = lisp_get_decent_index ( O0o00o0Oo )
 return ( str ( o00O ) + "." + lisp_decent_dns_suffix )
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
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 57 - 57: OoooooooOO % o0oOOo0O0Ooo - iIii1I11I1II1 . OoooooooOO
 II1Ii = 28 if packet . inner_version == 4 else 48
 II1iIII1Ii = packet . packet [ II1Ii : : ]
 iiiii1 = lisp_trace ( )
 if ( iiiii1 . decode ( II1iIII1Ii ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 23 - 23: ooOoO0o / i1IIi / I1IiiI - ooOoO0o * ooOoO0o - IiII
  if 45 - 45: i1IIi * IiII * iIii1I11I1II1 + o0oOOo0O0Ooo - Oo0Ooo * i1IIi
 Oo0o0o = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 30 - 30: Ii1I + iIii1I11I1II1 . OOooOOo * Oo0Ooo
 if 1 - 1: I1ii11iIi11i . i1IIi / iII111i
 if 19 - 19: IiII + i1IIi . Oo0Ooo % O0 / OoOoOO00
 if 19 - 19: iIii1I11I1II1 + iIii1I11I1II1 / i11iIiiIii - OOooOOo
 if 44 - 44: O0
 if 90 - 90: I1ii11iIi11i % I1ii11iIi11i
 if ( Oo0o0o != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : Oo0o0o += ":{}" . format ( packet . encap_port )
  if 41 - 41: Oo0Ooo % oO0o + I1ii11iIi11i / oO0o
  if 18 - 18: I1IiiI + OoooooooOO * OOooOOo
  if 75 - 75: I11i - oO0o
  if 50 - 50: II111iiii % o0oOOo0O0Ooo % iII111i - i1IIi % Ii1I . I1IiiI
  if 78 - 78: IiII
 Ii = { }
 Ii [ "n" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 70 - 70: I1IiiI - o0oOOo0O0Ooo - I1ii11iIi11i - i11iIiiIii * ooOoO0o / I1ii11iIi11i
 oO0O00o000 = packet . outer_source
 if ( oO0O00o000 . is_null ( ) ) : oO0O00o000 = lisp_myrlocs [ 0 ]
 Ii [ "sr" ] = oO0O00o000 . print_address_no_iid ( )
 if 52 - 52: IiII - iII111i - II111iiii
 if 86 - 86: Ii1I % I11i - i11iIiiIii % O0 - O0 % O0
 if 93 - 93: ooOoO0o + iIii1I11I1II1
 if 27 - 27: i1IIi * i11iIiiIii - OoOoOO00 * Ii1I . IiII + iII111i
 if 25 - 25: I1ii11iIi11i % o0oOOo0O0Ooo - OoO0O00
 if ( Ii [ "n" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  Ii [ "sr" ] += ":{}" . format ( packet . inner_sport )
  if 28 - 28: oO0o
  if 8 - 8: I11i / OoooooooOO % OoooooooOO . Oo0Ooo
 Ii [ "hn" ] = lisp_hostname
 oO0oOo = ed [ 0 ] + "ts"
 Ii [ oO0oOo ] = lisp_get_timestamp ( )
 if 30 - 30: iII111i
 if 25 - 25: I11i % i1IIi + OOooOOo * Ii1I . i1IIi
 if 81 - 81: I11i % OoOoOO00 . Ii1I
 if 82 - 82: i1IIi / II111iiii
 if 40 - 40: II111iiii - I1Ii111 + Oo0Ooo / IiII
 if 15 - 15: I1Ii111 + ooOoO0o / II111iiii . OoOoOO00 - I1Ii111
 if ( Oo0o0o == "?" and Ii [ "n" ] == "ETR" ) :
  Iiii1II1 = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( Iiii1II1 != None and len ( Iiii1II1 . rloc_set ) >= 1 ) :
   Oo0o0o = Iiii1II1 . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 59 - 59: Ii1I * iIii1I11I1II1 - iIii1I11I1II1 % I1Ii111 - OoO0O00 / I1IiiI
   if 89 - 89: I1Ii111 . OoO0O00
 Ii [ "dr" ] = Oo0o0o
 if 52 - 52: OoO0O00 - iIii1I11I1II1
 if 52 - 52: OOooOOo + I1IiiI * Ii1I % OoooooooOO / I1Ii111
 if 74 - 74: iIii1I11I1II1
 if 82 - 82: OOooOOo
 if ( Oo0o0o == "?" and reason != None ) :
  Ii [ "dr" ] += " ({})" . format ( reason )
  if 64 - 64: II111iiii
  if 48 - 48: iII111i + i11iIiiIii * I1IiiI % OoOoOO00
  if 49 - 49: Oo0Ooo
  if 67 - 67: iIii1I11I1II1 + I1Ii111 / I1Ii111 % I11i + I1Ii111
  if 7 - 7: iIii1I11I1II1 . Oo0Ooo / OoO0O00 / OoOoOO00
 if ( rloc_entry != None ) :
  Ii [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  Ii [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  Ii [ "lats" ] = rloc_entry . recent_rloc_probe_latencies
  if 7 - 7: OoOoOO00 * I1Ii111 / Ii1I - OoO0O00 / O0 / Oo0Ooo
  if 47 - 47: OoOoOO00
  if 18 - 18: OoO0O00 - iIii1I11I1II1
  if 91 - 91: iII111i / I1ii11iIi11i
  if 19 - 19: iIii1I11I1II1
  if 3 - 3: i11iIiiIii + Ii1I / I1Ii111
 oo0Oo = packet . inner_source . print_address ( )
 Ii1III1 = packet . inner_dest . print_address ( )
 if ( iiiii1 . packet_json == [ ] ) :
  IiII1ii1I1 = { }
  IiII1ii1I1 [ "se" ] = oo0Oo
  IiII1ii1I1 [ "de" ] = Ii1III1
  IiII1ii1I1 [ "paths" ] = [ ]
  iiiii1 . packet_json . append ( IiII1ii1I1 )
  if 74 - 74: II111iiii + I11i
  if 80 - 80: OOooOOo . oO0o / iIii1I11I1II1
  if 4 - 4: iII111i + I1IiiI
  if 95 - 95: Oo0Ooo / I1ii11iIi11i % OoO0O00
  if 47 - 47: I1IiiI + i1IIi + I1ii11iIi11i / OOooOOo * i11iIiiIii % I1Ii111
  if 7 - 7: OoOoOO00 * iII111i * i11iIiiIii + OoOoOO00
 for IiII1ii1I1 in iiiii1 . packet_json :
  if ( IiII1ii1I1 [ "de" ] != Ii1III1 ) : continue
  IiII1ii1I1 [ "paths" ] . append ( Ii )
  break
  if 20 - 20: i1IIi % Ii1I / iIii1I11I1II1 / II111iiii
  if 16 - 16: I1IiiI % Ii1I
  if 30 - 30: i11iIiiIii / i1IIi % O0 - OoooooooOO - OOooOOo
  if 55 - 55: OoooooooOO % ooOoO0o % I1Ii111 - Oo0Ooo % OoooooooOO . I11i
  if 22 - 22: i11iIiiIii
  if 39 - 39: oO0o / OoOoOO00 % iIii1I11I1II1 - OoOoOO00
  if 29 - 29: I1ii11iIi11i - I11i . I1ii11iIi11i - o0oOOo0O0Ooo - OoooooooOO % OoO0O00
  if 74 - 74: iIii1I11I1II1 / iII111i * OoO0O00 * iIii1I11I1II1 + i11iIiiIii
 OoOOOOoO = False
 if ( len ( iiiii1 . packet_json ) == 1 and Ii [ "n" ] == "ETR" and
 iiiii1 . myeid ( packet . inner_dest ) ) :
  IiII1ii1I1 = { }
  IiII1ii1I1 [ "se" ] = Ii1III1
  IiII1ii1I1 [ "de" ] = oo0Oo
  IiII1ii1I1 [ "paths" ] = [ ]
  iiiii1 . packet_json . append ( IiII1ii1I1 )
  OoOOOOoO = True
  if 66 - 66: OoooooooOO / I1Ii111 . I1IiiI + OoooooooOO - o0oOOo0O0Ooo
  if 10 - 10: I1IiiI
  if 88 - 88: OoO0O00 + OoooooooOO - Oo0Ooo
  if 6 - 6: I11i . I1IiiI + i1IIi
  if 20 - 20: II111iiii / O0 % ooOoO0o . OoO0O00 / oO0o + II111iiii
  if 32 - 32: o0oOOo0O0Ooo * iII111i - iII111i * I11i . i11iIiiIii
 iiiii1 . print_trace ( )
 II1iIII1Ii = iiiii1 . encode ( )
 if 63 - 63: IiII
 if 39 - 39: II111iiii / I1Ii111 + OoooooooOO + IiII + iIii1I11I1II1
 if 59 - 59: OoOoOO00 / II111iiii . Ii1I
 if 90 - 90: II111iiii
 if 77 - 77: i11iIiiIii . i11iIiiIii - iIii1I11I1II1 + OOooOOo
 if 55 - 55: OoO0O00 + Oo0Ooo
 if 74 - 74: i1IIi - I11i - oO0o % I1IiiI
 if 57 - 57: Oo0Ooo / II111iiii + OoOoOO00
 O000OO00Ooooo = iiiii1 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "sr" ]
 if ( Oo0o0o == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( O000OO00Ooooo ) )
  iiiii1 . return_to_sender ( lisp_socket , O000OO00Ooooo , II1iIII1Ii )
  return ( False )
  if 23 - 23: I11i + OOooOOo
  if 91 - 91: I1Ii111 + II111iiii - iII111i + Oo0Ooo / OoooooooOO
  if 52 - 52: OOooOOo - i1IIi + I1ii11iIi11i % OoO0O00 * oO0o * i1IIi
  if 40 - 40: OOooOOo * Ii1I - OoOoOO00 - I1IiiI / II111iiii
  if 39 - 39: OoOoOO00 % O0 / Oo0Ooo
  if 100 - 100: O0 / iII111i % OoO0O00
 oOoO0Oo0 = iiiii1 . packet_length ( )
 if 88 - 88: ooOoO0o + O0 + i1IIi
 if 64 - 64: ooOoO0o / O0 % i1IIi + I1IiiI
 if 48 - 48: OOooOOo / IiII
 if 48 - 48: i11iIiiIii % i1IIi + iIii1I11I1II1 . I1Ii111
 if 67 - 67: i11iIiiIii / o0oOOo0O0Ooo . i11iIiiIii . I1ii11iIi11i - O0
 if 76 - 76: i1IIi % OOooOOo
 IIiIii1I = packet . packet [ 0 : II1Ii ]
 ooo0OO0OOooO0 = struct . pack ( "HH" , socket . htons ( oOoO0Oo0 ) , 0 )
 IIiIii1I = IIiIii1I [ 0 : II1Ii - 4 ] + ooo0OO0OOooO0
 if ( packet . inner_version == 6 and Ii [ "n" ] == "ETR" and
 len ( iiiii1 . packet_json ) == 2 ) :
  ii11 = IIiIii1I [ II1Ii - 8 : : ] + II1iIII1Ii
  ii11 = lisp_udp_checksum ( oo0Oo , Ii1III1 , ii11 )
  IIiIii1I = IIiIii1I [ 0 : II1Ii - 8 ] + ii11 [ 0 : 8 ]
  if 79 - 79: OoO0O00 * OoooooooOO % I11i
  if 39 - 39: I1Ii111 - I1ii11iIi11i
  if 10 - 10: OoOoOO00 - I1IiiI * OOooOOo - iII111i % OoOoOO00 . Ii1I
  if 44 - 44: OOooOOo * I1ii11iIi11i + OoooooooOO * OoooooooOO
  if 60 - 60: iIii1I11I1II1 * i11iIiiIii
  if 35 - 35: O0 + i11iIiiIii . OoO0O00
  if 1 - 1: OoOoOO00 + o0oOOo0O0Ooo . Ii1I / II111iiii
  if 54 - 54: ooOoO0o + iIii1I11I1II1
  if 89 - 89: I1IiiI
 if ( OoOOOOoO ) :
  if ( packet . inner_version == 4 ) :
   IIiIii1I = IIiIii1I [ 0 : 12 ] + IIiIii1I [ 16 : 20 ] + IIiIii1I [ 12 : 16 ] + IIiIii1I [ 22 : 24 ] + IIiIii1I [ 20 : 22 ] + IIiIii1I [ 24 : : ]
   if 75 - 75: O0 / I1ii11iIi11i
  else :
   IIiIii1I = IIiIii1I [ 0 : 8 ] + IIiIii1I [ 24 : 40 ] + IIiIii1I [ 8 : 24 ] + IIiIii1I [ 42 : 44 ] + IIiIii1I [ 40 : 42 ] + IIiIii1I [ 44 : : ]
   if 36 - 36: i1IIi - IiII - I1IiiI / I11i
   if 41 - 41: I1IiiI . OoooooooOO * oO0o - I1ii11iIi11i % IiII
  oooOo = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = oooOo
  if 88 - 88: i11iIiiIii * ooOoO0o
  if 19 - 19: i1IIi / I1Ii111 % II111iiii
  if 4 - 4: o0oOOo0O0Ooo - OoO0O00 % i1IIi % OoooooooOO * oO0o - Oo0Ooo
  if 18 - 18: oO0o % Oo0Ooo / o0oOOo0O0Ooo + OOooOOo
  if 65 - 65: OOooOOo
  if 23 - 23: OoOoOO00
  if 26 - 26: i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o + OoO0O00
 II1Ii = 2 if packet . inner_version == 4 else 4
 OOooO0OoOoO = 20 + oOoO0Oo0 if packet . inner_version == 4 else oOoO0Oo0
 Iii1IiI1i1Iiii = struct . pack ( "H" , socket . htons ( OOooO0OoOoO ) )
 IIiIii1I = IIiIii1I [ 0 : II1Ii ] + Iii1IiI1i1Iiii + IIiIii1I [ II1Ii + 2 : : ]
 if 24 - 24: I11i - ooOoO0o + I1IiiI % O0 % iII111i * II111iiii
 if 35 - 35: oO0o - I11i - i1IIi
 if 83 - 83: ooOoO0o % OoooooooOO % Oo0Ooo * o0oOOo0O0Ooo * oO0o % i1IIi
 if 66 - 66: Ii1I . ooOoO0o / OoooooooOO - I1IiiI - iIii1I11I1II1 + OOooOOo
 if ( packet . inner_version == 4 ) :
  O0o00o00OO0oO = struct . pack ( "H" , 0 )
  IIiIii1I = IIiIii1I [ 0 : 10 ] + O0o00o00OO0oO + IIiIii1I [ 12 : : ]
  Iii1IiI1i1Iiii = lisp_ip_checksum ( IIiIii1I [ 0 : 20 ] )
  IIiIii1I = Iii1IiI1i1Iiii + IIiIii1I [ 20 : : ]
  if 33 - 33: Ii1I + I1IiiI - iII111i . OoooooooOO / I1ii11iIi11i
  if 64 - 64: OoO0O00 + OoO0O00
  if 2 - 2: ooOoO0o * IiII . ooOoO0o
  if 5 - 5: o0oOOo0O0Ooo - o0oOOo0O0Ooo
  if 40 - 40: OoO0O00 % I11i - OoOoOO00
 packet . packet = IIiIii1I + II1iIII1Ii
 return ( True )
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
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 3 - 3: OoooooooOO + OoooooooOO * OOooOOo / O0
 for Ii in lisp_glean_mappings :
  if ( "instance-id" in Ii ) :
   i1I1iI = eid . instance_id
   O0oooo , O0O0OooO = Ii [ "instance-id" ]
   if ( i1I1iI < O0oooo or i1I1iI > O0O0OooO ) : continue
   if 81 - 81: i11iIiiIii - OoOoOO00
  if ( "eid-prefix" in Ii ) :
   oOO = copy . deepcopy ( Ii [ "eid-prefix" ] )
   oOO . instance_id = eid . instance_id
   if ( eid . is_more_specific ( oOO ) == False ) : continue
   if 80 - 80: iIii1I11I1II1 % OOooOOo + oO0o + II111iiii - I1ii11iIi11i
  if ( "group-prefix" in Ii ) :
   if ( group == None ) : continue
   II11iIIii = copy . deepcopy ( Ii [ "group-prefix" ] )
   II11iIIii . instance_id = group . instance_id
   if ( group . is_more_specific ( II11iIIii ) == False ) : continue
   if 44 - 44: OoooooooOO * iII111i
  if ( "rloc-prefix" in Ii ) :
   if ( rloc != None and rloc . is_more_specific ( Ii [ "rloc-prefix" ] )
 == False ) : continue
   if 26 - 26: OoooooooOO
  return ( True , Ii [ "rloc-probe" ] , Ii [ "igmp-query" ] )
  if 73 - 73: II111iiii . iII111i - iIii1I11I1II1 . i1IIi . I11i
 return ( False , False , False )
 if 60 - 60: OoO0O00 + OoO0O00
 if 50 - 50: i1IIi
 if 33 - 33: oO0o - Ii1I - Oo0Ooo * IiII / OoooooooOO - OoooooooOO
 if 31 - 31: O0 - I11i
 if 25 - 25: Oo0Ooo * o0oOOo0O0Ooo . IiII
 if 74 - 74: OOooOOo % oO0o
 if 69 - 69: Oo0Ooo . oO0o + Oo0Ooo * IiII - OoooooooOO
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 ooOoo000oO = geid . print_address ( )
 O0oO0OO0OoO = seid . print_address_no_iid ( )
 OOo0oOO0o0oo0 = green ( "{}" . format ( O0oO0OO0OoO ) , False )
 oOO = green ( "(*, {})" . format ( ooOoo000oO ) , False )
 IIIIiiI1iIiI = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 5 - 5: Oo0Ooo * oO0o . OoO0O00 % i11iIiiIii
 if 64 - 64: OOooOOo / Ii1I - Ii1I . I1Ii111 / I1IiiI
 if 12 - 12: i1IIi
 if 65 - 65: I1IiiI + i1IIi * II111iiii / II111iiii + OoooooooOO
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
  lprint ( "Add gleaned EID {} to map-cache" . format ( oOO ) )
  if 100 - 100: IiII / i1IIi + I11i
  if 57 - 57: Ii1I % II111iiii
  if 33 - 33: ooOoO0o - OOooOOo % OoOoOO00
  if 56 - 56: i1IIi . iII111i - i11iIiiIii
  if 65 - 65: I1Ii111 * O0 % Ii1I . iII111i . ooOoO0o . ooOoO0o
  if 9 - 9: I1IiiI / Oo0Ooo . iIii1I11I1II1 % o0oOOo0O0Ooo . OoOoOO00
 i1iiI1i1 = iI11i1Ii = I1I1Ii1I = None
 if ( Ii111 . rloc_set != [ ] ) :
  i1iiI1i1 = Ii111 . rloc_set [ 0 ]
  if ( i1iiI1i1 . rle ) :
   iI11i1Ii = i1iiI1i1 . rle
   for Oo0oOOo000 in iI11i1Ii . rle_nodes :
    if ( Oo0oOOo000 . rloc_name != O0oO0OO0OoO ) : continue
    I1I1Ii1I = Oo0oOOo000
    break
    if 93 - 93: iII111i
    if 94 - 94: Oo0Ooo % oO0o + Ii1I . OoO0O00 / Oo0Ooo
    if 93 - 93: i11iIiiIii * Ii1I - II111iiii + Ii1I + oO0o
    if 90 - 90: I1Ii111
    if 85 - 85: IiII
    if 37 - 37: II111iiii . i11iIiiIii / OoO0O00 / II111iiii % iII111i
    if 89 - 89: OoooooooOO % II111iiii - I11i
 if ( i1iiI1i1 == None ) :
  i1iiI1i1 = lisp_rloc ( )
  Ii111 . rloc_set = [ i1iiI1i1 ]
  i1iiI1i1 . priority = 253
  i1iiI1i1 . mpriority = 255
  Ii111 . build_best_rloc_set ( )
  if 65 - 65: i11iIiiIii + ooOoO0o % OoO0O00 + I11i
 if ( iI11i1Ii == None ) :
  iI11i1Ii = lisp_rle ( geid . print_address ( ) )
  i1iiI1i1 . rle = iI11i1Ii
  if 34 - 34: O0 % iIii1I11I1II1 - I1Ii111 / oO0o
 if ( I1I1Ii1I == None ) :
  I1I1Ii1I = lisp_rle_node ( )
  I1I1Ii1I . rloc . rloc_name = O0oO0OO0OoO
  iI11i1Ii . rle_nodes . append ( I1I1Ii1I )
  iI11i1Ii . build_rle_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( IIIIiiI1iIiI , OOo0oOO0o0oo0 , oOO ) )
 elif ( rloc . is_exact_match ( I1I1Ii1I . rloc . rloc ) == False or
 port != I1I1Ii1I . rloc . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( IIIIiiI1iIiI , OOo0oOO0o0oo0 , oOO ) )
  if 83 - 83: I1IiiI / OOooOOo
  if 12 - 12: o0oOOo0O0Ooo / I11i . I1Ii111 % OOooOOo - II111iiii + iII111i
  if 42 - 42: O0 . i1IIi . iIii1I11I1II1 + O0 - i11iIiiIii * Oo0Ooo
  if 48 - 48: i11iIiiIii
  if 64 - 64: OoO0O00 - OOooOOo % I11i * I11i
 I1I1Ii1I . store_translated_rloc ( rloc , port )
 if 24 - 24: OoOoOO00 % O0
 if 99 - 99: IiII . i1IIi - Oo0Ooo * i1IIi / Ii1I + I1ii11iIi11i
 if 46 - 46: OOooOOo - o0oOOo0O0Ooo
 if 48 - 48: Oo0Ooo
 if 22 - 22: IiII . I1ii11iIi11i / oO0o - OoooooooOO % OoooooooOO + ooOoO0o
 if ( igmp ) :
  I1IiIiIi = seid . print_address ( )
  if ( I1IiIiIi not in lisp_gleaned_groups ) :
   lisp_gleaned_groups [ I1IiIiIi ] = { }
   if 34 - 34: iII111i * iII111i / OoO0O00 . ooOoO0o - OoOoOO00
  lisp_gleaned_groups [ I1IiIiIi ] [ ooOoo000oO ] = lisp_get_timestamp ( )
  if 14 - 14: I1Ii111 . I11i . IiII * I1Ii111 / O0 . i11iIiiIii
  if 19 - 19: OoooooooOO / I11i % I1Ii111 % Ii1I + OOooOOo * ooOoO0o
  if 30 - 30: OOooOOo . Ii1I % i11iIiiIii . OoooooooOO . Ii1I
  if 28 - 28: OoO0O00 . iIii1I11I1II1 * I11i
  if 97 - 97: i1IIi . O0 + I11i * IiII
  if 53 - 53: oO0o
  if 9 - 9: iIii1I11I1II1
  if 18 - 18: OoO0O00
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 93 - 93: iIii1I11I1II1
 if 84 - 84: II111iiii % I1IiiI / O0 + iII111i + OoooooooOO
 if 7 - 7: I1IiiI - OoOoOO00 - i1IIi * OoO0O00 . IiII / i1IIi
 if 50 - 50: II111iiii % I1Ii111 . Oo0Ooo
 Ii111 = lisp_map_cache_lookup ( seid , geid )
 if ( Ii111 == None ) : return
 if 97 - 97: iIii1I11I1II1 % ooOoO0o . i1IIi - Ii1I
 IiI = Ii111 . rloc_set [ 0 ] . rle
 if ( IiI == None ) : return
 if 60 - 60: O0 * OoO0O00
 I11Io00oo0OO = seid . print_address_no_iid ( )
 OOOOoo0o0O0 = False
 for I1I1Ii1I in IiI . rle_nodes :
  if ( I1I1Ii1I . rloc . rloc_name == I11Io00oo0OO ) :
   OOOOoo0o0O0 = True
   break
   if 91 - 91: II111iiii . Oo0Ooo / I11i + Oo0Ooo . I1ii11iIi11i % iII111i
   if 2 - 2: IiII . I11i
 if ( OOOOoo0o0O0 == False ) : return
 if 38 - 38: i11iIiiIii % OoOoOO00 / ooOoO0o * o0oOOo0O0Ooo * OoO0O00
 if 69 - 69: I11i / O0
 if 100 - 100: o0oOOo0O0Ooo + I1Ii111 / Ii1I * OOooOOo + I1Ii111 + II111iiii
 if 57 - 57: ooOoO0o % O0 % I11i + OoO0O00 + OoO0O00 - OoOoOO00
 IiI . rle_nodes . remove ( I1I1Ii1I )
 IiI . build_rle_forwarding_list ( )
 if 92 - 92: OoooooooOO - II111iiii
 ooOoo000oO = geid . print_address ( )
 I1IiIiIi = seid . print_address ( )
 OOo0oOO0o0oo0 = green ( "{}" . format ( I1IiIiIi ) , False )
 oOO = green ( "(*, {})" . format ( ooOoo000oO ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( oOO , OOo0oOO0o0oo0 ) )
 if 68 - 68: ooOoO0o / i11iIiiIii + i11iIiiIii + OOooOOo - I1ii11iIi11i
 if 83 - 83: iIii1I11I1II1 / II111iiii + i11iIiiIii - Oo0Ooo % OoO0O00
 if 5 - 5: iIii1I11I1II1 - I1Ii111
 if 83 - 83: Ii1I . I1Ii111 % o0oOOo0O0Ooo * i11iIiiIii - I1IiiI
 if ( I1IiIiIi in lisp_gleaned_groups ) :
  if ( ooOoo000oO in lisp_gleaned_groups [ I1IiIiIi ] ) :
   lisp_gleaned_groups [ I1IiIiIi ] . pop ( ooOoo000oO )
   if 41 - 41: OOooOOo . iII111i
   if 82 - 82: O0 * o0oOOo0O0Ooo / oO0o
   if 6 - 6: I1Ii111 . o0oOOo0O0Ooo + I11i
   if 79 - 79: Oo0Ooo
   if 11 - 11: i1IIi
   if 14 - 14: i1IIi
 if ( IiI . rle_nodes == [ ] ) :
  Ii111 . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( oOO ) )
  if 3 - 3: I1Ii111
  if 82 - 82: iIii1I11I1II1 * iII111i - O0
  if 8 - 8: OoOoOO00 - I1Ii111 * OOooOOo
  if 97 - 97: OoOoOO00
  if 56 - 56: O0 * Oo0Ooo + I11i % i11iIiiIii * iIii1I11I1II1 * OOooOOo
  if 53 - 53: oO0o
  if 8 - 8: OoO0O00 / oO0o + IiII - o0oOOo0O0Ooo * I11i - IiII
  if 47 - 47: Ii1I / Ii1I
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 I1IiIiIi = seid . print_address ( )
 if ( I1IiIiIi not in lisp_gleaned_groups ) : return
 if 92 - 92: OoO0O00 + Oo0Ooo / I1ii11iIi11i
 for i1I1IIIiII in lisp_gleaned_groups [ I1IiIiIi ] :
  lisp_geid . store_address ( i1I1IIIiII )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
  if 86 - 86: OoooooooOO - OoOoOO00 . OoooooooOO
  if 92 - 92: i1IIi - OoooooooOO . o0oOOo0O0Ooo - i1IIi . i11iIiiIii
  if 81 - 81: IiII + OOooOOo . i1IIi - OoOoOO00
  if 30 - 30: Ii1I / IiII % II111iiii + o0oOOo0O0Ooo . Oo0Ooo / OoO0O00
  if 22 - 22: iII111i + I1IiiI * OoO0O00 - II111iiii / Oo0Ooo
  if 17 - 17: iIii1I11I1II1 / Ii1I + i1IIi / iII111i * OoooooooOO
  if 1 - 1: i11iIiiIii * I1IiiI
  if 7 - 7: o0oOOo0O0Ooo / OoooooooOO * II111iiii % OoO0O00 + II111iiii
  if 24 - 24: i1IIi + i11iIiiIii - OoO0O00
  if 64 - 64: i1IIi % Oo0Ooo * i1IIi - II111iiii * OoooooooOO * o0oOOo0O0Ooo
  if 15 - 15: oO0o
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
  if 77 - 77: I1ii11iIi11i . OOooOOo
  if 26 - 26: OoooooooOO + i11iIiiIii
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
  if 51 - 51: I1IiiI . I1IiiI / oO0o + ooOoO0o % OoO0O00 * I11i
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
  if 94 - 94: Oo0Ooo + Oo0Ooo + IiII . o0oOOo0O0Ooo
  if 62 - 62: I1Ii111 / OoooooooOO * ooOoO0o
  if 88 - 88: oO0o / Oo0Ooo - OoOoOO00 * ooOoO0o - OoOoOO00 / i11iIiiIii
  if 50 - 50: iIii1I11I1II1 * OOooOOo . iII111i / ooOoO0o + OoOoOO00 - IiII
  if 80 - 80: i11iIiiIii * o0oOOo0O0Ooo
  if 71 - 71: OoO0O00 % I1ii11iIi11i * iII111i . o0oOOo0O0Ooo * oO0o - OoO0O00
  if 44 - 44: I11i / I1Ii111 * OOooOOo - I11i . iIii1I11I1II1
  if 71 - 71: OoO0O00 / IiII
  if 60 - 60: i11iIiiIii - iII111i . OoooooooOO * iII111i + II111iiii
  if 40 - 40: OOooOOo / iIii1I11I1II1 - Oo0Ooo / II111iiii % ooOoO0o . o0oOOo0O0Ooo
  if 52 - 52: i1IIi
  if 13 - 13: OoooooooOO / i11iIiiIii - OoOoOO00 + II111iiii . i1IIi
  if 2 - 2: I1IiiI % i1IIi . O0 . I1Ii111
  if 75 - 75: I1ii11iIi11i
  if 23 - 23: oO0o % i1IIi . II111iiii . IiII . I1ii11iIi11i
  if 22 - 22: OOooOOo / II111iiii . ooOoO0o
  if 2 - 2: IiII * Ii1I * I1ii11iIi11i % iII111i
  if 31 - 31: ooOoO0o * Oo0Ooo . I11i - OOooOOo . iII111i
  if 96 - 96: I11i
  if 88 - 88: O0 + OoO0O00
  if 61 - 61: i11iIiiIii
  if 47 - 47: iII111i % oO0o
  if 60 - 60: Ii1I / OoO0O00
  if 36 - 36: i11iIiiIii + Ii1I * iII111i . II111iiii
  if 84 - 84: oO0o
  if 50 - 50: ooOoO0o . Ii1I
  if 17 - 17: iIii1I11I1II1
  if 28 - 28: OOooOOo % iIii1I11I1II1 - o0oOOo0O0Ooo * O0 + OoOoOO00 . i1IIi
  if 49 - 49: iII111i / ooOoO0o + I11i - OOooOOo + o0oOOo0O0Ooo
  if 88 - 88: O0 + Oo0Ooo - o0oOOo0O0Ooo . Ii1I
  if 75 - 75: OoooooooOO * OoooooooOO % I1IiiI - Ii1I . o0oOOo0O0Ooo
  if 89 - 89: OoooooooOO / i1IIi
  if 15 - 15: oO0o - I1Ii111
  if 6 - 6: OoooooooOO
  if 55 - 55: i1IIi % iII111i / I1Ii111 + iII111i / I11i
  if 15 - 15: I1ii11iIi11i / OoOoOO00 * OoO0O00 . OoooooooOO - I1ii11iIi11i
  if 64 - 64: OoO0O00 . II111iiii / OOooOOo + I1IiiI . OoooooooOO * OoOoOO00
  if 99 - 99: iIii1I11I1II1 - Oo0Ooo / I1ii11iIi11i / II111iiii
  if 61 - 61: iIii1I11I1II1
  if 54 - 54: II111iiii / OoO0O00 * I1IiiI - ooOoO0o - Oo0Ooo
  if 100 - 100: O0 * II111iiii - iIii1I11I1II1 + OoooooooOO
  if 13 - 13: ooOoO0o
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 48 - 48: o0oOOo0O0Ooo - OOooOOo + O0 + i1IIi
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 43 - 43: i11iIiiIii / IiII / OoooooooOO + oO0o * o0oOOo0O0Ooo
def lisp_process_igmp_packet ( packet ) :
 IiiiiI = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 IiiiiI . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 IiiiiI = bold ( "from {}" . format ( IiiiiI . print_address_no_iid ( ) ) , False )
 if 56 - 56: Oo0Ooo / Ii1I * OOooOOo
 IIIIiiI1iIiI = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( IIIIiiI1iIiI , len ( packet ) , IiiiiI ,
 lisp_format_packet ( packet ) ) )
 if 28 - 28: Ii1I + iII111i
 if 96 - 96: i1IIi . O0 - OoooooooOO + iIii1I11I1II1
 if 27 - 27: OoooooooOO / IiII + O0 * ooOoO0o
 if 87 - 87: i1IIi % OoOoOO00 / IiII
 O00o0o0oO = ( struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ] & 0x0f ) * 4
 if 64 - 64: I1ii11iIi11i % I11i % OoO0O00
 if 26 - 26: OOooOOo % o0oOOo0O0Ooo
 if 92 - 92: I1IiiI - o0oOOo0O0Ooo - Ii1I / I1IiiI
 if 94 - 94: Ii1I * OoOoOO00 - I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo . Ii1I
 I111I11ii = packet [ O00o0o0oO : : ]
 ii1I111I1I1I = struct . unpack ( "B" , I111I11ii [ 0 : 1 ] ) [ 0 ]
 if 89 - 89: OoOoOO00 * II111iiii
 if 94 - 94: I11i - o0oOOo0O0Ooo - IiII + I1IiiI . OoooooooOO * OOooOOo
 if 4 - 4: oO0o
 if 12 - 12: ooOoO0o + oO0o % I1ii11iIi11i
 if 27 - 27: OOooOOo % i1IIi / iIii1I11I1II1 + OoO0O00
 i1I1IIIiII = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1I1IIIiII . address = socket . ntohl ( struct . unpack ( "II" , I111I11ii [ : 8 ] ) [ 1 ] )
 ooOoo000oO = i1I1IIIiII . print_address_no_iid ( )
 if 47 - 47: OoooooooOO
 if ( ii1I111I1I1I == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( ooOoo000oO ) )
  return ( [ ] )
  if 74 - 74: i1IIi % I11i * oO0o
  if 37 - 37: ooOoO0o . I11i % o0oOOo0O0Ooo / ooOoO0o
 iIi1i1i = ( ii1I111I1I1I in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( iIi1i1i == False ) :
  ooOo00oo0 = "{} ({})" . format ( ii1I111I1I1I , igmp_types [ ii1I111I1I1I ] ) if ( ii1I111I1I1I in igmp_types ) else ii1I111I1I1I
  if 76 - 76: i1IIi . i1IIi % II111iiii + I1IiiI + II111iiii
  lprint ( "IGMP type {} not supported" . format ( ooOo00oo0 ) )
  return ( [ ] )
  if 37 - 37: i11iIiiIii
  if 45 - 45: IiII * iIii1I11I1II1 % i1IIi . I11i - ooOoO0o
 if ( len ( I111I11ii ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 89 - 89: oO0o / II111iiii . oO0o . ooOoO0o . o0oOOo0O0Ooo
  if 82 - 82: i11iIiiIii
  if 22 - 22: II111iiii - Oo0Ooo
  if 55 - 55: Ii1I - I11i - OoO0O00
  if 51 - 51: iII111i - I1ii11iIi11i . OoooooooOO * ooOoO0o + oO0o * oO0o
 if ( ii1I111I1I1I == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( ooOoo000oO , False ) ) )
  lisp_update_igmp_database ( None , ooOoo000oO , False )
  return ( [ [ None , ooOoo000oO , False ] ] )
  if 16 - 16: i1IIi - OOooOOo . oO0o . i1IIi
 if ( ii1I111I1I1I in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( ii1I111I1I1I == 0x12 ) else 2 , bold ( ooOoo000oO , False ) ) )
  if 96 - 96: o0oOOo0O0Ooo + I1ii11iIi11i / OoOoOO00 + I1ii11iIi11i - iIii1I11I1II1
  if 59 - 59: OoooooooOO / ooOoO0o % II111iiii . iIii1I11I1II1 * IiII
  if 50 - 50: iIii1I11I1II1
  if 55 - 55: o0oOOo0O0Ooo
  if 42 - 42: IiII - i1IIi - oO0o
  if ( ooOoo000oO . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   return ( [ ] )
   if 89 - 89: Ii1I % I1Ii111 / i1IIi + II111iiii
   if 64 - 64: O0 % OoO0O00 / oO0o + iIii1I11I1II1
  lisp_update_igmp_database ( None , ooOoo000oO , True )
  return ( [ [ None , ooOoo000oO , True ] ] )
  if 25 - 25: iIii1I11I1II1 * OoO0O00 * ooOoO0o / OoooooooOO - ooOoO0o - II111iiii
  if 14 - 14: iIii1I11I1II1 + I1IiiI * IiII . OoOoOO00 + O0
  if 96 - 96: O0 * Oo0Ooo % Ii1I * I1IiiI
  if 14 - 14: II111iiii - iIii1I11I1II1 / OoO0O00 - I1IiiI - iII111i
  if 51 - 51: Oo0Ooo . OoooooooOO
 oO0oooOOo = i1I1IIIiII . address
 I111I11ii = I111I11ii [ 8 : : ]
 if 38 - 38: I1IiiI
 iiIIiiI = "BBHI"
 OOooOOoOO0 = struct . calcsize ( iiIIiiI )
 I1IIi1IiiiII = "I"
 IIII1IIIiiII = struct . calcsize ( I1IIi1IiiiII )
 IiiiiI = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 56 - 56: O0 / i1IIi * OoO0O00
 if 98 - 98: iIii1I11I1II1 . I1Ii111 + iII111i * iIii1I11I1II1 % O0
 if 93 - 93: i1IIi - iII111i
 if 13 - 13: OOooOOo / o0oOOo0O0Ooo * I1IiiI % iII111i / OOooOOo
 o0OO00 = [ ]
 for o000o0O0Oo00 in range ( oO0oooOOo ) :
  if ( len ( I111I11ii ) < OOooOOoOO0 ) : return ( [ ] )
  OO0000oOooOo , O0O0oOO , O0ooO00oooo00O0o , oOoO0 = struct . unpack ( iiIIiiI ,
 I111I11ii [ : OOooOOoOO0 ] )
  if 26 - 26: IiII / I1IiiI * OOooOOo + Ii1I
  I111I11ii = I111I11ii [ OOooOOoOO0 : : ]
  if 65 - 65: ooOoO0o / IiII + I11i * O0 * OOooOOo
  if ( OO0000oOooOo not in lisp_igmp_record_types ) :
   lprint ( "Invalid record type {}" . format ( OO0000oOooOo ) )
   continue
   if 95 - 95: O0 % I11i . I1Ii111 % Oo0Ooo % iII111i
   if 72 - 72: OoO0O00 * II111iiii
  Oo0oO0o0oO00 = lisp_igmp_record_types [ OO0000oOooOo ]
  O0ooO00oooo00O0o = socket . ntohs ( O0ooO00oooo00O0o )
  i1I1IIIiII . address = socket . ntohl ( oOoO0 )
  ooOoo000oO = i1I1IIIiII . print_address_no_iid ( )
  if 100 - 100: I1Ii111 - i11iIiiIii
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( Oo0oO0o0oO00 , ooOoo000oO , O0ooO00oooo00O0o ) )
  if 1 - 1: Ii1I + Ii1I * OOooOOo / IiII - OoO0O00
  if 32 - 32: Oo0Ooo * i11iIiiIii / ooOoO0o
  if 1 - 1: OoOoOO00 / Oo0Ooo . o0oOOo0O0Ooo + iIii1I11I1II1 / Ii1I % I1IiiI
  if 40 - 40: IiII . I1IiiI / O0 % I1Ii111 / o0oOOo0O0Ooo / O0
  if 46 - 46: oO0o / OoO0O00
  if 43 - 43: ooOoO0o - oO0o / i1IIi . I11i . I1ii11iIi11i % oO0o
  if 40 - 40: I1ii11iIi11i
  OOoo = False
  if ( OO0000oOooOo in ( 1 , 5 ) ) : OOoo = True
  if ( OO0000oOooOo == 3 and O0ooO00oooo00O0o == 0 ) : OOoo = False
  if ( OO0000oOooOo in ( 2 , 4 ) and O0ooO00oooo00O0o == 0 ) : OOoo = True
  iII = "join" if ( OOoo ) else "leave"
  if 73 - 73: i11iIiiIii + I11i - Oo0Ooo % iIii1I11I1II1
  if 71 - 71: o0oOOo0O0Ooo / OoooooooOO + ooOoO0o + IiII * O0 % ooOoO0o
  if 100 - 100: OOooOOo * IiII
  if 49 - 49: Oo0Ooo + O0
  if ( ooOoo000oO . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 88 - 88: iIii1I11I1II1 . OoooooooOO - i11iIiiIii + iIii1I11I1II1 % OoO0O00
   if 78 - 78: II111iiii / IiII . oO0o % Ii1I + OoO0O00 - ooOoO0o
   if 74 - 74: II111iiii * o0oOOo0O0Ooo + OOooOOo
   if 94 - 94: i1IIi / O0 / OoOoOO00 - OoooooooOO
   if 28 - 28: O0 % O0
   if 100 - 100: o0oOOo0O0Ooo - Ii1I * I1Ii111 % i1IIi . I11i + I11i
   if 34 - 34: IiII % o0oOOo0O0Ooo
   if 98 - 98: i1IIi
  if ( O0ooO00oooo00O0o == 0 ) :
   o0OO00 . append ( [ None , ooOoo000oO , OOoo ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( iII , False ) ,
 bold ( ooOoo000oO , False ) ) )
   if 94 - 94: Ii1I % I1Ii111 - oO0o - i1IIi
   if 29 - 29: OoooooooOO + ooOoO0o * OoO0O00 % I11i % i11iIiiIii
   if 77 - 77: II111iiii + OoooooooOO . oO0o / O0 + ooOoO0o * IiII
   if 35 - 35: OoO0O00 . OOooOOo % oO0o * I1IiiI / I1ii11iIi11i
   if 48 - 48: OoO0O00 - o0oOOo0O0Ooo - I1Ii111 . OoO0O00 . iII111i
  for oO0OO in range ( O0ooO00oooo00O0o ) :
   if ( len ( I111I11ii ) < IIII1IIIiiII ) : return ( [ ] )
   oOoO0 = struct . unpack ( I1IIi1IiiiII , I111I11ii [ : IIII1IIIiiII ] ) [ 0 ]
   IiiiiI . address = socket . ntohl ( oOoO0 )
   oO00O0Oo = IiiiiI . print_address_no_iid ( )
   o0OO00 . append ( [ oO00O0Oo , ooOoo000oO , OOoo ] )
   lprint ( "{} ({}, {})" . format ( iII ,
 green ( oO00O0Oo , False ) , bold ( ooOoo000oO , False ) ) )
   I111I11ii = I111I11ii [ IIII1IIIiiII : : ]
   if 100 - 100: I1IiiI / I11i - IiII % Oo0Ooo - O0
   if 48 - 48: i1IIi - iIii1I11I1II1 % OoO0O00 . II111iiii / i1IIi
   if 99 - 99: I1ii11iIi11i
   if 44 - 44: I1IiiI . OoOoOO00 % ooOoO0o % oO0o - Oo0Ooo / i1IIi
   if 11 - 11: Ii1I * OoO0O00 . II111iiii - OoOoOO00 % I1Ii111 . OOooOOo
   if 57 - 57: IiII % i1IIi * OoOoOO00 * o0oOOo0O0Ooo
 for oO00O0Oo , ooOoo000oO , OOoo in o0OO00 :
  lisp_update_igmp_database ( oO00O0Oo , ooOoo000oO , OOoo )
  if 54 - 54: iIii1I11I1II1
  if 22 - 22: iII111i % oO0o - O0 % OoooooooOO * O0
  if 86 - 86: o0oOOo0O0Ooo / OoooooooOO - Oo0Ooo
  if 83 - 83: Ii1I
  if 68 - 68: I1Ii111 . oO0o * ooOoO0o % I1Ii111 + I1IiiI
  if 32 - 32: Ii1I + iIii1I11I1II1 / i1IIi - OOooOOo
  if 31 - 31: o0oOOo0O0Ooo % i11iIiiIii
 return ( o0OO00 )
 if 22 - 22: OoooooooOO % I1ii11iIi11i / Oo0Ooo . I11i
 if 33 - 33: i11iIiiIii % I1IiiI / i1IIi + Ii1I + O0 * OoO0O00
 if 46 - 46: i1IIi * Oo0Ooo + I1Ii111 + iIii1I11I1II1 / O0
 if 47 - 47: OoooooooOO . II111iiii % OoOoOO00
 if 75 - 75: i11iIiiIii + IiII
 if 79 - 79: IiII
 if 44 - 44: IiII . I1ii11iIi11i / OoO0O00 % ooOoO0o
 if 96 - 96: OoO0O00 / II111iiii / iII111i % iIii1I11I1II1 % II111iiii
def lisp_update_igmp_database ( source_str , group_str , joinleave ) :
 if 37 - 37: Ii1I / ooOoO0o - O0 - Ii1I % iIii1I11I1II1
 if 40 - 40: IiII - OoOoOO00 + OoooooooOO . o0oOOo0O0Ooo
 if 49 - 49: IiII - O0 % I11i . II111iiii % II111iiii
 if 53 - 53: ooOoO0o . II111iiii - II111iiii * I11i
 i1I1IIIiII = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1I1IIIiII . store_address ( group_str )
 if 85 - 85: I1ii11iIi11i % I1ii11iIi11i
 if 66 - 66: I1Ii111 / Oo0Ooo / I11i
 if 2 - 2: OoOoOO00 + OoO0O00
 if 12 - 12: I1Ii111
 O0o00o0Oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if source_str :
  O0o00o0Oo . store_address ( source_str )
 else :
  O0o00o0Oo . address = 0
  O0o00o0Oo . mask_len = 0
  if 89 - 89: iIii1I11I1II1
  if 94 - 94: I1ii11iIi11i - i1IIi % IiII
 o0ooOooO00Oo = "({}, {})" . format ( source_str if source_str else "*" , group_str )
 if 5 - 5: OoO0O00
 if ( joinleave ) :
  Iiii1II1 = lisp_db_for_lookups . lookup_cache ( i1I1IIIiII , False )
  if ( Iiii1II1 ) :
   iii1Io0 = Iiii1II1 . lookup_source_cache ( O0o00o0Oo , False )
   if ( iii1Io0 ) :
    iii1Io0 . last_refresh_time = lisp_get_timestamp ( )
    lprint ( "Update IGMP database-mapping entry timestamp for {}" . format ( green ( o0ooOooO00Oo , False ) ) )
    if 23 - 23: iII111i / I1ii11iIi11i / O0 . ooOoO0o / o0oOOo0O0Ooo
    return
    if 37 - 37: O0 + O0 % iII111i - OoOoOO00 % I1ii11iIi11i
    if 46 - 46: II111iiii % iII111i * IiII . I1ii11iIi11i . O0 * i11iIiiIii
    if 11 - 11: I11i
    if 20 - 20: I1IiiI + OoooooooOO + i11iIiiIii / OOooOOo . I11i % I11i
    if 89 - 89: OoOoOO00 * I1Ii111
    if 69 - 69: oO0o / IiII * OOooOOo . I11i / I11i
  Oo000Oo = lisp_db_list [ 0 ] . rloc_set [ 0 ]
  if 80 - 80: iIii1I11I1II1 * I11i * oO0o . iIii1I11I1II1 - Oo0Ooo
  i1iiI1i1 = copy . deepcopy ( Oo000Oo )
  i1iiI1i1 . priority = 1
  i1iiI1i1 . weight = 100
  i1iiI1i1 . mpriority = 255
  i1iiI1i1 . mweight = 0
  i1iiI1i1 . state = LISP_RLOC_UP_STATE
  if 94 - 94: OoooooooOO
  oO0OOOoOOO = lisp_mapping ( O0o00o0Oo , i1I1IIIiII , [ i1iiI1i1 ] )
  oO0OOOoOOO . map_cache_ttl = LISP_IGMP_TIMEOUT_INTERVAL
  oO0OOOoOOO . last_refresh_time = lisp_get_timestamp ( )
  oO0OOOoOOO . gleaned = True
  if 82 - 82: iII111i
  oO0OOOoOOO . add_db ( )
  if 6 - 6: Oo0Ooo . OoOoOO00 / i11iIiiIii - i11iIiiIii . iII111i
  lprint ( "Add IGMP database-mapping entry for {}" . format ( green ( o0ooOooO00Oo , False ) ) )
 else :
  lisp_remove_igmp_database ( source_str , group_str )
  if 49 - 49: I11i % I1IiiI . I1Ii111 . o0oOOo0O0Ooo % OOooOOo
  if 17 - 17: I1IiiI - I1IiiI
  if 12 - 12: IiII / OoO0O00 / O0 . I1IiiI / I11i
  if 44 - 44: i1IIi - O0 + OoooooooOO + Oo0Ooo
  if 14 - 14: I1ii11iIi11i - o0oOOo0O0Ooo . oO0o
  if 72 - 72: IiII - O0 - II111iiii
  if 37 - 37: I1ii11iIi11i % i1IIi / Oo0Ooo + i11iIiiIii - I1ii11iIi11i
  if 82 - 82: IiII * I1ii11iIi11i
def lisp_remove_igmp_database ( source_str , group_str ) :
 i1I1IIIiII = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1I1IIIiII . store_address ( group_str )
 if 22 - 22: I1IiiI - iIii1I11I1II1 + I1IiiI / I1ii11iIi11i
 Iiii1II1 = lisp_db_for_lookups . lookup_cache ( i1I1IIIiII , False )
 if ( Iiii1II1 == None ) : return
 if 5 - 5: iIii1I11I1II1 + o0oOOo0O0Ooo * I11i * iIii1I11I1II1 % oO0o - IiII
 O0o00o0Oo = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if ( source_str ) :
  O0o00o0Oo . store_address ( source_str )
 else :
  O0o00o0Oo . address = 0
  O0o00o0Oo . mask_len = 0
  if 19 - 19: I1ii11iIi11i % IiII + I1IiiI . II111iiii * i11iIiiIii
  if 21 - 21: iIii1I11I1II1 + iII111i % I11i
 o0ooOooO00Oo = "({}, {})" . format ( source_str if source_str else "*" , group_str )
 if 20 - 20: OoO0O00 + OoOoOO00 / II111iiii - ooOoO0o * I1IiiI
 iii1Io0 = Iiii1II1 . lookup_source_cache ( O0o00o0Oo , False )
 if ( iii1Io0 == None ) :
  lprint ( "Could not remove not found IGMP database-mapping entry for {}" . format ( green ( o0ooOooO00Oo , False ) ) )
  if 81 - 81: oO0o % OoOoOO00 % IiII
  return
  if 3 - 3: i11iIiiIii * IiII
  if 64 - 64: OoO0O00 % I1Ii111 / OoO0O00 - i1IIi
  if 46 - 46: OOooOOo + o0oOOo0O0Ooo
  if 5 - 5: IiII + OoooooooOO % I1Ii111 + OoOoOO00 + I1IiiI - I1ii11iIi11i
  if 8 - 8: I1ii11iIi11i
 if ( iii1Io0 . gleaned == False ) : return
 if 84 - 84: IiII + ooOoO0o - OoO0O00 + I1Ii111 + iII111i
 Iiii1II1 . source_cache . delete_cache ( O0o00o0Oo )
 lprint ( "Remove IGMP database-mapping entry for {}" . format ( green ( o0ooOooO00Oo , False ) ) )
 if 9 - 9: I1Ii111 + i11iIiiIii - Oo0Ooo
 if 20 - 20: I1Ii111 / oO0o - Oo0Ooo
 if 85 - 85: ooOoO0o + O0 * o0oOOo0O0Ooo
 if 31 - 31: II111iiii + OOooOOo * i11iIiiIii
 if Iiii1II1 . source_cache . cache_size ( ) == 0 :
  lisp_db_for_lookups . delete_cache ( i1I1IIIiII )
  if 15 - 15: I1IiiI . ooOoO0o / OOooOOo / OoOoOO00 % I11i - Oo0Ooo
  if 57 - 57: Oo0Ooo + OOooOOo
  if 57 - 57: I1ii11iIi11i + i1IIi - OoOoOO00 - I1IiiI + OOooOOo
  if 98 - 98: IiII + OoO0O00 - i11iIiiIii * IiII
  if 81 - 81: Oo0Ooo + OOooOOo + i1IIi % OOooOOo % iIii1I11I1II1
  if 47 - 47: OoooooooOO / oO0o
  if 100 - 100: i11iIiiIii % o0oOOo0O0Ooo * I1ii11iIi11i . I11i
  if 31 - 31: I1Ii111
  if 59 - 59: i1IIi + OOooOOo * OOooOOo
def lisp_timeout_igmp_database ( ) :
 oOo0O0ooo0 = lisp_get_timestamp ( )
 if 42 - 42: OoooooooOO * oO0o % II111iiii * ooOoO0o - oO0o
 if 52 - 52: Ii1I . I1Ii111 * OoooooooOO
 if 42 - 42: OoOoOO00 / i11iIiiIii - OoooooooOO
 if 56 - 56: OOooOOo + iII111i * I1Ii111
 for I1iIIIiI1iI11 in lisp_db_for_lookups . cache_sorted :
  for oo0oooo0o0o in ( list ( lisp_db_for_lookups . cache [ I1iIIIiI1iI11 ] . entries . values ( ) ) ) :
   if ( oo0oooo0o0o . group . is_null ( ) ) : continue
   if ( oo0oooo0o0o . source_cache == None ) : continue
   if 5 - 5: I11i * II111iiii - II111iiii + iII111i . OOooOOo % I1IiiI
   if 4 - 4: I11i / OOooOOo + oO0o + IiII
   if 73 - 73: O0 . O0 . O0 + IiII
   if 59 - 59: OoO0O00 % I11i + ooOoO0o
   i1iIi = [ ]
   for o00oooo0Oo0o in oo0oooo0o0o . source_cache . cache_sorted :
    for iii1Io0 in ( list ( oo0oooo0o0o . source_cache . cache [ o00oooo0Oo0o ] . entries . values ( ) ) ) :
     if ( iii1Io0 . gleaned == False ) : continue
     if ( iii1Io0 . map_cache_ttl == None ) : continue
     if 9 - 9: O0 % O0
     o0oOOOO0 = oOo0O0ooo0 - iii1Io0 . last_refresh_time
     if ( o0oOOOO0 >= iii1Io0 . map_cache_ttl ) :
      i1iIi . append ( iii1Io0 )
      if 84 - 84: i1IIi * O0 * I1ii11iIi11i - OoO0O00 + OOooOOo % OOooOOo
      if 24 - 24: i1IIi / i1IIi + OoOoOO00
      if 13 - 13: OoooooooOO
      if 83 - 83: OOooOOo . Oo0Ooo . OOooOOo . Ii1I
      if 81 - 81: i1IIi - iIii1I11I1II1
      if 84 - 84: ooOoO0o . II111iiii
      if 71 - 71: I1Ii111 / II111iiii / I11i
   for iii1Io0 in ( i1iIi ) :
    o0ooOooO00Oo = iii1Io0 . print_eid_tuple ( )
    lprint ( "IGMP database entry {} {}" . format (
 green ( o0ooOooO00Oo , False ) , bold ( "timed out" , False ) ) )
    oo0oooo0o0o . source_cache . delete_cache ( iii1Io0 . eid )
    if 71 - 71: OoooooooOO
    if 97 - 97: O0 * II111iiii - Oo0Ooo + OoooooooOO - Ii1I - IiII
    if 71 - 71: O0 + O0 + I11i . O0 % Oo0Ooo / o0oOOo0O0Ooo
    if 70 - 70: O0 + O0 * iII111i / o0oOOo0O0Ooo - oO0o
    if 54 - 54: O0 + Oo0Ooo - II111iiii / Ii1I % i1IIi / iII111i
   if ( oo0oooo0o0o . source_cache . cache_size ( ) == 0 ) :
    lprint ( "Removing empty IGMP group database entry {}" . format (
 green ( oo0oooo0o0o . group . print_address ( ) , False ) ) )
    lisp_db_for_lookups . delete_cache ( oo0oooo0o0o . group )
    if 52 - 52: I1Ii111
    if 6 - 6: I1Ii111 + OoOoOO00
    if 1 - 1: o0oOOo0O0Ooo % OoooooooOO / Oo0Ooo % II111iiii + ooOoO0o
    if 41 - 41: OoOoOO00 + o0oOOo0O0Ooo - OoooooooOO
    if 64 - 64: OoO0O00 + I1Ii111
    if 6 - 6: O0 / II111iiii / I1Ii111 / I11i / oO0o / oO0o
    if 49 - 49: iII111i - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o
    if 49 - 49: I1IiiI
    if 85 - 85: OOooOOo . II111iiii - OoO0O00 % O0 / iIii1I11I1II1 . I1IiiI
    if 21 - 21: i11iIiiIii + I1IiiI . ooOoO0o % IiII
    if 76 - 76: IiII . I1ii11iIi11i + Oo0Ooo % Ii1I % Oo0Ooo + IiII
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 87 - 87: I1ii11iIi11i . IiII * i1IIi + OoooooooOO + OoOoOO00 % Oo0Ooo
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 26 - 26: OoooooooOO % OoO0O00
 if 23 - 23: iII111i * iII111i + oO0o - O0
 if 96 - 96: Ii1I / ooOoO0o % I1IiiI / i1IIi
 if 19 - 19: Ii1I + i11iIiiIii - i1IIi
 if 92 - 92: ooOoO0o / oO0o % Ii1I / OOooOOo / Ii1I
 if 18 - 18: ooOoO0o % OOooOOo . IiII * i11iIiiIii + Oo0Ooo
 oOoO0oOo0oo00 = True
 Ii111 = lisp_map_cache . lookup_cache ( seid , True )
 if ( Ii111 and len ( Ii111 . rloc_set ) != 0 ) :
  Ii111 . last_refresh_time = lisp_get_timestamp ( )
  if 53 - 53: I1ii11iIi11i - ooOoO0o / OOooOOo * i11iIiiIii * i1IIi
  o0ooo0oOO = Ii111 . rloc_set [ 0 ]
  I11 = o0ooo0oOO . rloc
  oOOOO = o0ooo0oOO . translated_port
  oOoO0oOo0oo00 = ( I11 . is_exact_match ( rloc ) == False or
 oOOOO != encap_port )
  if 69 - 69: OoooooooOO * o0oOOo0O0Ooo + oO0o * I1IiiI - OoO0O00
  if ( oOoO0oOo0oo00 ) :
   oOO = green ( seid . print_address ( ) , False )
   IIIIiiI1iIiI = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( oOO , IIIIiiI1iIiI ) )
   o0ooo0oOO . delete_from_rloc_probe_list ( Ii111 . eid , Ii111 . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 83 - 83: OoOoOO00 + II111iiii . oO0o - II111iiii
 else :
  Ii111 = lisp_mapping ( "" , "" , [ ] )
  Ii111 . eid . copy_address ( seid )
  Ii111 . mapping_source . copy_address ( rloc )
  Ii111 . map_cache_ttl = LISP_GLEAN_TTL
  Ii111 . gleaned = True
  oOO = green ( seid . print_address ( ) , False )
  IIIIiiI1iIiI = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( oOO , IIIIiiI1iIiI ) )
  Ii111 . add_cache ( )
  if 40 - 40: i1IIi . iII111i + I1Ii111 * i11iIiiIii
  if 50 - 50: ooOoO0o / i1IIi / I11i - I1ii11iIi11i / Ii1I + I1ii11iIi11i
  if 82 - 82: I1Ii111 % o0oOOo0O0Ooo
  if 39 - 39: iIii1I11I1II1 . i11iIiiIii
  if 26 - 26: OoooooooOO % I1IiiI + O0 / iII111i . I1Ii111
 if ( oOoO0oOo0oo00 ) :
  i1iiI1i1 = lisp_rloc ( )
  i1iiI1i1 . store_translated_rloc ( rloc , encap_port )
  i1iiI1i1 . add_to_rloc_probe_list ( Ii111 . eid , Ii111 . group )
  i1iiI1i1 . priority = 253
  i1iiI1i1 . mpriority = 255
  o0O00ooOo = [ i1iiI1i1 ]
  Ii111 . rloc_set = o0O00ooOo
  Ii111 . build_best_rloc_set ( )
  if 59 - 59: OoooooooOO + Oo0Ooo % I1Ii111 - oO0o
  if 89 - 89: I1Ii111 - iII111i - OOooOOo . I1IiiI + oO0o
  if 78 - 78: oO0o . Oo0Ooo
  if 8 - 8: O0 . o0oOOo0O0Ooo / I1IiiI % ooOoO0o * OOooOOo
  if 22 - 22: i1IIi * O0
 if ( igmp == None ) : return
 if 70 - 70: o0oOOo0O0Ooo / Ii1I
 if 67 - 67: IiII + ooOoO0o
 if 20 - 20: iIii1I11I1II1 % ooOoO0o * O0 * iIii1I11I1II1 * OOooOOo * OoO0O00
 if 36 - 36: iIii1I11I1II1 . OoO0O00 % iIii1I11I1II1 / ooOoO0o / II111iiii + oO0o
 if 97 - 97: i11iIiiIii + OoooooooOO + O0 + o0oOOo0O0Ooo / ooOoO0o
 lisp_geid . instance_id = seid . instance_id
 if 96 - 96: O0
 if 93 - 93: II111iiii + Oo0Ooo * OOooOOo
 if 15 - 15: ooOoO0o
 if 85 - 85: OOooOOo
 if 5 - 5: II111iiii - OoooooooOO - O0
 oOOOO0oooo0o = lisp_process_igmp_packet ( igmp )
 if ( oOOOO0oooo0o == [ ] ) : return
 if 54 - 54: iIii1I11I1II1 / OoooooooOO / OoO0O00 / o0oOOo0O0Ooo
 for IiiiiI , i1I1IIIiII , OOoo in oOOOO0oooo0o :
  if ( IiiiiI != None ) : continue
  if 42 - 42: Ii1I
  if 8 - 8: oO0o
  if 68 - 68: oO0o . II111iiii * oO0o
  if 9 - 9: Oo0Ooo - O0 % IiII - OoOoOO00 * OOooOOo . Ii1I
  lisp_geid . store_address ( i1I1IIIiII )
  ooO00OO , O0O0oOO , IIIIIi1I1Ii = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( ooO00OO == False ) : continue
  if 49 - 49: II111iiii % Ii1I * OOooOOo % OOooOOo
  if ( OOoo ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 88 - 88: i1IIi / OoooooooOO - I1IiiI - II111iiii * OoooooooOO
   if 34 - 34: OoOoOO00 - iIii1I11I1II1 - Oo0Ooo * o0oOOo0O0Ooo % O0 * i11iIiiIii
   if 82 - 82: IiII - Oo0Ooo + I1Ii111 - O0
   if 46 - 46: i1IIi
   if 55 - 55: I1Ii111 . I1IiiI % o0oOOo0O0Ooo
   if 44 - 44: i11iIiiIii
   if 81 - 81: Ii1I
   if 63 - 63: OoooooooOO % oO0o / i11iIiiIii
   if 16 - 16: OoO0O00 % OoOoOO00 / i1IIi - ooOoO0o % II111iiii % II111iiii
   if 10 - 10: I1ii11iIi11i . II111iiii
   if 28 - 28: iIii1I11I1II1 * I1ii11iIi11i % OOooOOo % I11i * i11iIiiIii
   if 91 - 91: I11i * II111iiii - I11i + iII111i + OoOoOO00 - IiII
def lisp_is_json_telemetry ( json_string ) :
 try :
  O0o0OOO = json . loads ( json_string )
  if ( type ( O0o0OOO ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 23 - 23: I11i - OoOoOO00
  if 42 - 42: ooOoO0o * OoooooooOO / iIii1I11I1II1 / i1IIi . I1Ii111 . Oo0Ooo
 if ( "type" not in O0o0OOO ) : return ( None )
 if ( "sub-type" not in O0o0OOO ) : return ( None )
 if ( O0o0OOO [ "type" ] != "telemetry" ) : return ( None )
 if ( O0o0OOO [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( O0o0OOO )
 if 73 - 73: O0 % iII111i * i11iIiiIii
 if 89 - 89: oO0o * I1ii11iIi11i . ooOoO0o . IiII
 if 8 - 8: IiII
 if 80 - 80: I1ii11iIi11i . IiII % OoO0O00 * I1IiiI
 if 4 - 4: O0 - IiII + i1IIi * iIii1I11I1II1 * i1IIi - OOooOOo
 if 20 - 20: ooOoO0o % OoOoOO00 . I11i
 if 26 - 26: i11iIiiIii + o0oOOo0O0Ooo + ooOoO0o * i1IIi
 if 85 - 85: iII111i % OoO0O00 / OoooooooOO
 if 77 - 77: iIii1I11I1II1 . OoOoOO00 + I1IiiI + I1IiiI % iII111i * Ii1I
 if 96 - 96: oO0o + O0 / O0 / Oo0Ooo + ooOoO0o . I1ii11iIi11i
 if 50 - 50: oO0o - OoOoOO00 . Oo0Ooo
 if 14 - 14: I1IiiI
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 O0o0OOO = lisp_is_json_telemetry ( json_string )
 if ( O0o0OOO == None ) : return ( json_string )
 if 54 - 54: i11iIiiIii + i11iIiiIii / Ii1I
 if ( O0o0OOO [ "itr-in" ] == "?" ) : O0o0OOO [ "itr-in" ] = ii
 if ( O0o0OOO [ "itr-out" ] == "?" ) : O0o0OOO [ "itr-out" ] = io
 if ( O0o0OOO [ "etr-in" ] == "?" ) : O0o0OOO [ "etr-in" ] = ei
 if ( O0o0OOO [ "etr-out" ] == "?" ) : O0o0OOO [ "etr-out" ] = eo
 json_string = json . dumps ( O0o0OOO )
 return ( json_string )
 if 55 - 55: II111iiii + oO0o + OOooOOo / O0 * oO0o / Oo0Ooo
 if 34 - 34: I1IiiI % OoooooooOO . i1IIi - OoooooooOO + I11i / oO0o
 if 17 - 17: OOooOOo - oO0o + O0 - Ii1I * i1IIi
 if 2 - 2: I1ii11iIi11i - Ii1I - OOooOOo - ooOoO0o
 if 49 - 49: OoooooooOO
 if 69 - 69: o0oOOo0O0Ooo % II111iiii
 if 4 - 4: ooOoO0o % Oo0Ooo * II111iiii * OoO0O00 / I1Ii111 - iII111i
 if 25 - 25: i11iIiiIii + OoOoOO00
 if 53 - 53: OoooooooOO * o0oOOo0O0Ooo + IiII
 if 72 - 72: OoOoOO00 * ooOoO0o - iIii1I11I1II1 + OoooooooOO
 if 2 - 2: Ii1I / ooOoO0o / iII111i + I1Ii111
 if 18 - 18: OoOoOO00 + i1IIi / OoooooooOO
def lisp_decode_telemetry ( json_string ) :
 O0o0OOO = lisp_is_json_telemetry ( json_string )
 if ( O0o0OOO == None ) : return ( { } )
 return ( O0o0OOO )
 if 58 - 58: I1IiiI . o0oOOo0O0Ooo % I1ii11iIi11i - O0
 if 36 - 36: IiII + OOooOOo + I11i + OoO0O00 . O0 / oO0o
 if 54 - 54: I1ii11iIi11i * IiII . I1Ii111 + OoO0O00 / OoOoOO00
 if 89 - 89: i1IIi - Oo0Ooo % iIii1I11I1II1 * IiII . O0
 if 74 - 74: I1ii11iIi11i + II111iiii / OoooooooOO
 if 34 - 34: Oo0Ooo - O0 . Oo0Ooo + i11iIiiIii + OoooooooOO
 if 92 - 92: Oo0Ooo * i1IIi - o0oOOo0O0Ooo * i1IIi
 if 44 - 44: I11i * Oo0Ooo * I11i % Oo0Ooo
 if 40 - 40: Ii1I - O0 + ooOoO0o + OoooooooOO + II111iiii . OOooOOo
def lisp_telemetry_configured ( ) :
 if ( "telemetry" not in lisp_json_list ) : return ( None )
 if 12 - 12: Ii1I * IiII - i11iIiiIii - IiII . I11i
 I11i1I1111i = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( I11i1I1111i ) == None ) : return ( None )
 if 27 - 27: I1Ii111 . I1ii11iIi11i + I1ii11iIi11i + OoOoOO00 / i11iIiiIii - Oo0Ooo
 return ( I11i1I1111i )
 if 52 - 52: iII111i % IiII / IiII % I1Ii111 / OoOoOO00
 if 15 - 15: OoOoOO00 - OoO0O00 + I1Ii111
 if 16 - 16: O0
 if 28 - 28: iII111i % I1IiiI * i1IIi - i1IIi % iIii1I11I1II1
 if 87 - 87: o0oOOo0O0Ooo * I11i - OoO0O00 - OoOoOO00 / OoOoOO00 - oO0o
 if 89 - 89: iII111i - iII111i
 if 41 - 41: Ii1I . I1Ii111 / I1IiiI / I1IiiI % OoooooooOO - OOooOOo
def lisp_mr_or_pubsub ( action ) :
 return ( action in [ LISP_SEND_MAP_REQUEST_ACTION , LISP_SEND_PUBSUB_ACTION ] )
 if 91 - 91: ooOoO0o % IiII / OoOoOO00 - IiII / iIii1I11I1II1 + i11iIiiIii
 if 23 - 23: o0oOOo0O0Ooo
 if 35 - 35: OoO0O00 / I1IiiI
 if 37 - 37: o0oOOo0O0Ooo + ooOoO0o * I1IiiI . Oo0Ooo
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
