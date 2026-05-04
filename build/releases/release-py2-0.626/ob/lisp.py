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
 if ( device == None or sock == None or lisp_is_macos ( ) ) : return
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
 return
 if 22 - 22: O0 - I11i + I1Ii111 . Ii1I * i1IIi
 if 26 - 26: iIii1I11I1II1 * o0oOOo0O0Ooo . I11i
 if 10 - 10: I1Ii111 * oO0o % Oo0Ooo - I11i % Oo0Ooo
 if 65 - 65: iII111i * iIii1I11I1II1 / O0 . I11i
 if 94 - 94: Oo0Ooo . ooOoO0o * i11iIiiIii - o0oOOo0O0Ooo . iII111i
 if 98 - 98: OOooOOo + Ii1I
 if 52 - 52: Oo0Ooo / OoOoOO00 - I1Ii111 . iII111i
 if 50 - 50: iIii1I11I1II1 - iII111i - I11i
 if 60 - 60: iIii1I11I1II1 * ooOoO0o
 if 71 - 71: OoOoOO00 % Oo0Ooo % ooOoO0o
 if 34 - 34: I11i / I11i % IiII . OoOoOO00 / Oo0Ooo
 if 99 - 99: ooOoO0o * I1IiiI - ooOoO0o % Ii1I
def lisp_get_input_interface ( packet ) :
 I1i1I = lisp_format_packet ( packet [ 0 : 12 ] )
 I111Iii1 = I1i1I . replace ( " " , "" )
 i11i = I111Iii1 [ 0 : 12 ]
 O0o0O00o0o = I111Iii1 [ 12 : : ]
 if 6 - 6: I1ii11iIi11i - oO0o * i11iIiiIii + OoOoOO00 / ooOoO0o % OOooOOo
 try : II11IiIIiiI = ( O0o0O00o0o in lisp_mymacs )
 except : II11IiIIiiI = False
 if 67 - 67: I1ii11iIi11i . II111iiii - Ii1I % OoooooooOO
 if ( i11i in lisp_mymacs ) : return ( lisp_mymacs [ i11i ] , O0o0O00o0o , i11i , II11IiIIiiI )
 if ( II11IiIIiiI ) : return ( lisp_mymacs [ O0o0O00o0o ] , O0o0O00o0o , i11i , II11IiIIiiI )
 return ( [ "?" ] , O0o0O00o0o , i11i , II11IiIIiiI )
 if 49 - 49: I1ii11iIi11i + O0 . Ii1I * OoooooooOO
 if 82 - 82: I1ii11iIi11i
 if 54 - 54: o0oOOo0O0Ooo + I11i - iIii1I11I1II1 % ooOoO0o % IiII
 if 19 - 19: I1ii11iIi11i / iIii1I11I1II1 % i1IIi . OoooooooOO
 if 57 - 57: ooOoO0o . Oo0Ooo - OoO0O00 - i11iIiiIii * I1Ii111 / o0oOOo0O0Ooo
 if 79 - 79: I1ii11iIi11i + o0oOOo0O0Ooo % Oo0Ooo * o0oOOo0O0Ooo
 if 21 - 21: iII111i
 if 24 - 24: iII111i / ooOoO0o
def lisp_get_local_interfaces ( ) :
 for ooOooO in netifaces . interfaces ( ) :
  oo = lisp_interface ( ooOooO )
  oo . add_interface ( )
  if 43 - 43: O0 - ooOoO0o % OoooooooOO % OOooOOo + iII111i
 return
 if 61 - 61: ooOoO0o . i11iIiiIii + oO0o
 if 8 - 8: iIii1I11I1II1
 if 55 - 55: oO0o
 if 37 - 37: IiII / i11iIiiIii / Oo0Ooo
 if 97 - 97: I1Ii111 . I11i / I1IiiI
 if 83 - 83: I11i - I1ii11iIi11i * oO0o
 if 90 - 90: Oo0Ooo * I1IiiI
def lisp_get_loopback_address ( ) :
 for iI1ii11Ii in netifaces . ifaddresses ( "lo" ) [ netifaces . AF_INET ] :
  if ( iI1ii11Ii [ "peer" ] == "127.0.0.1" ) : continue
  return ( iI1ii11Ii [ "peer" ] )
  if 75 - 75: I1ii11iIi11i - OoOoOO00 * i11iIiiIii . OoooooooOO - Oo0Ooo . I11i
 return ( None )
 if 6 - 6: I11i * oO0o / OoooooooOO % Ii1I * o0oOOo0O0Ooo
 if 28 - 28: IiII * I1IiiI % IiII
 if 95 - 95: O0 / I11i . I1Ii111
 if 17 - 17: I11i
 if 56 - 56: ooOoO0o * o0oOOo0O0Ooo + I11i
 if 48 - 48: IiII * OoO0O00 % I1Ii111 - I11i
 if 72 - 72: i1IIi % ooOoO0o % IiII % oO0o - oO0o
 if 97 - 97: o0oOOo0O0Ooo * O0 / o0oOOo0O0Ooo * OoO0O00 * Oo0Ooo
def lisp_is_mac_string ( mac_str ) :
 i1i1I1 = mac_str . split ( "/" )
 if ( len ( i1i1I1 ) == 2 ) : mac_str = i1i1I1 [ 0 ]
 return ( len ( mac_str ) == 14 and mac_str . count ( "-" ) == 2 )
 if 38 - 38: I1Ii111
 if 25 - 25: iIii1I11I1II1 % II111iiii / I11i / I1ii11iIi11i
 if 22 - 22: oO0o * iII111i
 if 4 - 4: OoOoOO00 - oO0o + I1IiiI
 if 36 - 36: IiII
 if 19 - 19: OoOoOO00 . o0oOOo0O0Ooo . OoooooooOO
 if 13 - 13: OOooOOo . Oo0Ooo / II111iiii
 if 43 - 43: iIii1I11I1II1 % OoO0O00
def lisp_get_local_macs ( ) :
 for ooOooO in netifaces . interfaces ( ) :
  if 84 - 84: Oo0Ooo
  if 44 - 44: OoooooooOO * i11iIiiIii / Oo0Ooo
  if 75 - 75: OoooooooOO . OOooOOo + OoO0O00 / Ii1I - I1IiiI % Ii1I
  if 89 - 89: iII111i * iIii1I11I1II1 + i11iIiiIii . OoooooooOO
  if 51 - 51: OOooOOo / ooOoO0o + OoO0O00 % OoOoOO00 / Ii1I
  oooOo = ooOooO . replace ( ":" , "" )
  oooOo = ooOooO . replace ( "-" , "" )
  if ( oooOo . isalnum ( ) == False ) : continue
  if 25 - 25: o0oOOo0O0Ooo
  if 25 - 25: ooOoO0o * iII111i / I11i / I11i % o0oOOo0O0Ooo
  if 19 - 19: oO0o - iIii1I11I1II1 / ooOoO0o . OoO0O00 * O0 - O0
  if 41 - 41: i1IIi - I1IiiI
  if 48 - 48: I1IiiI - II111iiii / OoO0O00 + I1IiiI
  try :
   i1 = netifaces . ifaddresses ( ooOooO )
  except :
   continue
   if 22 - 22: iIii1I11I1II1 * I1Ii111 / Oo0Ooo
  if ( netifaces . AF_LINK not in i1 ) : continue
  i1i1I1 = i1 [ netifaces . AF_LINK ] [ 0 ] [ "addr" ]
  i1i1I1 = i1i1I1 . replace ( ":" , "" )
  if 31 - 31: i11iIiiIii
  if 56 - 56: I11i / Ii1I + Oo0Ooo - i1IIi - IiII + iIii1I11I1II1
  if 75 - 75: I1ii11iIi11i
  if 92 - 92: I11i / O0 * I1IiiI - I11i
  if 99 - 99: i11iIiiIii % OoooooooOO
  if ( len ( i1i1I1 ) < 12 ) : continue
  if 56 - 56: IiII * I1Ii111
  if ( i1i1I1 not in lisp_mymacs ) : lisp_mymacs [ i1i1I1 ] = [ ]
  lisp_mymacs [ i1i1I1 ] . append ( ooOooO )
  if 98 - 98: I11i + O0 * I1Ii111 + i11iIiiIii - OOooOOo - iIii1I11I1II1
  if 5 - 5: OOooOOo % Oo0Ooo % IiII % ooOoO0o
 lprint ( "Local MACs are: {}" . format ( lisp_mymacs ) )
 return
 if 17 - 17: Ii1I + II111iiii + OoooooooOO / OOooOOo / IiII
 if 80 - 80: o0oOOo0O0Ooo % i1IIi / I11i
 if 56 - 56: i1IIi . i11iIiiIii
 if 15 - 15: II111iiii * oO0o % iII111i / i11iIiiIii - oO0o + Oo0Ooo
 if 9 - 9: I11i - oO0o + O0 / iII111i % i1IIi
 if 97 - 97: o0oOOo0O0Ooo * ooOoO0o
 if 78 - 78: I11i . OOooOOo + oO0o * iII111i - i1IIi
 if 27 - 27: Ii1I % i1IIi . Oo0Ooo % I1Ii111
def lisp_get_local_rloc ( ) :
 i1iI = getoutput ( "netstat -rn | egrep 'default|0.0.0.0'" )
 if ( i1iI == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 if 73 - 73: OoooooooOO . Oo0Ooo / O0 - O0
 if 25 - 25: iIii1I11I1II1 * I11i - oO0o % i11iIiiIii + Ii1I % oO0o
 if 5 - 5: iIii1I11I1II1 . oO0o
 if 2 - 2: iIii1I11I1II1 * I1IiiI % i1IIi % I1ii11iIi11i + OoooooooOO + I1IiiI
 i1iI = i1iI . split ( "\n" ) [ 0 ]
 ooOooO = i1iI . split ( ) [ - 1 ]
 if 16 - 16: OOooOOo
 iI1ii11Ii = ""
 oooO0o0oOoO = lisp_is_macos ( )
 if ( oooO0o0oOoO ) :
  i1iI = getoutput ( "ifconfig {} | egrep 'inet '" . format ( ooOooO ) )
  if ( i1iI == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
 else :
  I11iii = 'ip addr show | egrep "inet " | egrep "{}"' . format ( ooOooO )
  i1iI = getoutput ( I11iii )
  if ( i1iI == "" ) :
   I11iii = 'ip addr show | egrep "inet " | egrep "global lo"'
   i1iI = getoutput ( I11iii )
   if 11 - 11: oO0o + I1Ii111 . IiII * OoooooooOO - I1ii11iIi11i - OOooOOo
  if ( i1iI == "" ) : return ( lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 ) )
  if 16 - 16: iII111i / iIii1I11I1II1 + OOooOOo * iII111i * I11i
  if 8 - 8: I1Ii111
  if 15 - 15: Oo0Ooo / Ii1I % O0 + I1ii11iIi11i
  if 96 - 96: ooOoO0o . OoooooooOO
  if 39 - 39: OOooOOo + OoO0O00
  if 80 - 80: OOooOOo % OoO0O00 / OoOoOO00
 iI1ii11Ii = ""
 i1iI = i1iI . split ( "\n" )
 if 54 - 54: Oo0Ooo % OoO0O00 - OOooOOo - I11i
 for o0 in i1iI :
  I1II1I1I = o0 . split ( ) [ 1 ]
  if ( oooO0o0oOoO == False ) : I1II1I1I = I1II1I1I . split ( "/" ) [ 0 ]
  I1iI111ii111i = lisp_address ( LISP_AFI_IPV4 , I1II1I1I , 32 , 0 )
  return ( I1iI111ii111i )
  if 83 - 83: iIii1I11I1II1
 return ( lisp_address ( LISP_AFI_IPV4 , iI1ii11Ii , 32 , 0 ) )
 if 97 - 97: i11iIiiIii + Oo0Ooo * OOooOOo % iII111i . IiII
 if 4 - 4: O0 . iII111i - iIii1I11I1II1
 if 19 - 19: OOooOOo % OoO0O00 / Ii1I + II111iiii % OoooooooOO
 if 89 - 89: Ii1I
 if 51 - 51: iII111i
 if 68 - 68: iII111i - o0oOOo0O0Ooo * OoO0O00 % ooOoO0o . ooOoO0o - iIii1I11I1II1
 if 22 - 22: OoooooooOO / I1ii11iIi11i % iII111i * OoOoOO00
 if 32 - 32: OoooooooOO % oO0o % iIii1I11I1II1 / O0
 if 61 - 61: II111iiii . O0 - Ii1I - I1ii11iIi11i / i11iIiiIii - II111iiii
 if 98 - 98: Ii1I - I1IiiI . i11iIiiIii * Oo0Ooo
 if 29 - 29: Ii1I / ooOoO0o % I11i
def lisp_get_local_addresses ( ) :
 global lisp_myrlocs
 if 10 - 10: iIii1I11I1II1 % OoooooooOO % I1ii11iIi11i
 if 39 - 39: II111iiii * OoOoOO00 . O0 * I11i
 if 89 - 89: Ii1I - ooOoO0o . I11i - I1Ii111 - I1IiiI
 if 79 - 79: IiII + IiII + Ii1I
 if 39 - 39: O0 - OoooooooOO
 if 63 - 63: iIii1I11I1II1 % o0oOOo0O0Ooo * ooOoO0o
 if 79 - 79: O0
 if 32 - 32: II111iiii . O0 + Ii1I / OoOoOO00 / IiII / OOooOOo
 if 15 - 15: I1ii11iIi11i
 if 4 - 4: IiII + iIii1I11I1II1 * iII111i + Oo0Ooo * o0oOOo0O0Ooo % II111iiii
 OO0o0o0oo = None
 o00O = 1
 iIiII1 = os . getenv ( "LISP_ADDR_SELECT" )
 if ( iIiII1 != None and iIiII1 != "" ) :
  iIiII1 = iIiII1 . split ( ":" )
  if ( len ( iIiII1 ) == 2 ) :
   OO0o0o0oo = iIiII1 [ 0 ]
   o00O = iIiII1 [ 1 ]
  else :
   if ( iIiII1 [ 0 ] . isdigit ( ) ) :
    o00O = iIiII1 [ 0 ]
   else :
    OO0o0o0oo = iIiII1 [ 0 ]
    if 47 - 47: I11i
    if 92 - 92: OoooooooOO % I1IiiI / OoOoOO00 * OoOoOO00 % i11iIiiIii / OoooooooOO
  o00O = 1 if ( o00O == "" ) else int ( o00O )
  if 47 - 47: i11iIiiIii / Oo0Ooo - Oo0Ooo * OoO0O00
  if 48 - 48: IiII
 OOooO = [ None , None , None ]
 II1i1i1I1iII = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 I1I = lisp_address ( LISP_AFI_IPV6 , "" , 128 , 0 )
 o0oOo0000ooO = None
 if 15 - 15: ooOoO0o . o0oOOo0O0Ooo + OoOoOO00 . iIii1I11I1II1 % ooOoO0o + O0
 for ooOooO in netifaces . interfaces ( ) :
  if ( OO0o0o0oo != None and OO0o0o0oo != ooOooO ) : continue
  OooO0O0Ooo = netifaces . ifaddresses ( ooOooO )
  if ( OooO0O0Ooo == { } ) : continue
  if 22 - 22: o0oOOo0O0Ooo + Oo0Ooo . ooOoO0o + I1ii11iIi11i * iII111i . i11iIiiIii
  if 90 - 90: OOooOOo * OoOoOO00 - Oo0Ooo + o0oOOo0O0Ooo
  if 53 - 53: OoooooooOO . OoooooooOO + o0oOOo0O0Ooo - iII111i + OOooOOo
  if 44 - 44: I1Ii111 - IiII
  o0oOo0000ooO = lisp_get_interface_instance_id ( ooOooO , None )
  if 100 - 100: oO0o . OoO0O00 - Ii1I + O0 * OoO0O00
  if 59 - 59: II111iiii
  if 43 - 43: Oo0Ooo + OoooooooOO
  if 47 - 47: ooOoO0o
  if ( netifaces . AF_INET in OooO0O0Ooo ) :
   oo000o = OooO0O0Ooo [ netifaces . AF_INET ]
   o00oOoo0o00 = 0
   for iI1ii11Ii in oo000o :
    II1i1i1I1iII . store_address ( iI1ii11Ii [ "addr" ] )
    if ( II1i1i1I1iII . is_ipv4_loopback ( ) ) : continue
    if ( II1i1i1I1iII . is_ipv4_link_local ( ) ) : continue
    if ( II1i1i1I1iII . address == 0 ) : continue
    o00oOoo0o00 += 1
    II1i1i1I1iII . instance_id = o0oOo0000ooO
    if ( OO0o0o0oo == None and
 lisp_db_for_lookups . lookup_cache ( II1i1i1I1iII , False ) ) : continue
    OOooO [ 0 ] = II1i1i1I1iII
    if ( o00oOoo0o00 == o00O ) : break
    if 42 - 42: OoO0O00 * i11iIiiIii
    if 16 - 16: iII111i % I1IiiI - ooOoO0o
  if ( netifaces . AF_INET6 in OooO0O0Ooo ) :
   OO00o0oOO = OooO0O0Ooo [ netifaces . AF_INET6 ]
   o00oOoo0o00 = 0
   for iI1ii11Ii in OO00o0oOO :
    O00oO000Oo0 = iI1ii11Ii [ "addr" ]
    I1I . store_address ( O00oO000Oo0 )
    if ( I1I . is_ipv6_string_link_local ( O00oO000Oo0 ) ) : continue
    if ( I1I . is_ipv6_loopback ( ) ) : continue
    o00oOoo0o00 += 1
    I1I . instance_id = o0oOo0000ooO
    if ( OO0o0o0oo == None and
 lisp_db_for_lookups . lookup_cache ( I1I , False ) ) : continue
    OOooO [ 1 ] = I1I
    if ( o00oOoo0o00 == o00O ) : break
    if 100 - 100: OoooooooOO * oO0o
    if 83 - 83: iIii1I11I1II1 - ooOoO0o - I1Ii111 / OoO0O00 - O0
    if 81 - 81: Ii1I - oO0o * I1ii11iIi11i / I1Ii111
    if 21 - 21: OoO0O00
    if 63 - 63: I11i . O0 * I11i + iIii1I11I1II1
    if 46 - 46: i1IIi + II111iiii * i1IIi - Ii1I
  if ( OOooO [ 0 ] == None ) : continue
  if 79 - 79: II111iiii - oO0o * I1ii11iIi11i - OoOoOO00 . I1ii11iIi11i
  OOooO [ 2 ] = ooOooO
  break
  if 11 - 11: O0 * OoOoOO00
  if 37 - 37: OoOoOO00 + O0 . O0 * Oo0Ooo % I1Ii111 / iII111i
 iIIi = OOooO [ 0 ] . print_address_no_iid ( ) if OOooO [ 0 ] else "none"
 OOOo00o = OOooO [ 1 ] . print_address_no_iid ( ) if OOooO [ 1 ] else "none"
 ooOooO = OOooO [ 2 ] if OOooO [ 2 ] else "none"
 if 3 - 3: o0oOOo0O0Ooo
 OO0o0o0oo = " (user selected)" if OO0o0o0oo != None else ""
 if 16 - 16: i1IIi . i1IIi / I1Ii111 % OoOoOO00 / I1IiiI * I1ii11iIi11i
 iIIi = red ( iIIi , False )
 OOOo00o = red ( OOOo00o , False )
 ooOooO = bold ( ooOooO , False )
 lprint ( "Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}" . format ( iIIi , OOOo00o , ooOooO , OO0o0o0oo , o0oOo0000ooO ) )
 if 30 - 30: o0oOOo0O0Ooo + OoooooooOO + OOooOOo / II111iiii * Oo0Ooo
 if 59 - 59: Ii1I / OoOoOO00 * OoO0O00 * iII111i % oO0o
 lisp_myrlocs = OOooO
 return ( ( OOooO [ 0 ] != None ) )
 if 61 - 61: Oo0Ooo - O0 - OoooooooOO
 if 4 - 4: II111iiii - oO0o % Oo0Ooo * i11iIiiIii
 if 18 - 18: Oo0Ooo % O0
 if 66 - 66: iIii1I11I1II1 % i11iIiiIii / I1IiiI
 if 47 - 47: I1ii11iIi11i * oO0o + iIii1I11I1II1 - oO0o / IiII
 if 86 - 86: IiII
 if 43 - 43: I1IiiI / iII111i / ooOoO0o + iIii1I11I1II1 + OoooooooOO
 if 33 - 33: II111iiii - IiII - ooOoO0o
 if 92 - 92: OoO0O00 * IiII
def lisp_get_all_addresses ( ) :
 ooo00o0OO = [ ]
 for oo in netifaces . interfaces ( ) :
  try : I1I11i = netifaces . ifaddresses ( oo )
  except : continue
  if 38 - 38: i11iIiiIii . iIii1I11I1II1 . OOooOOo / OoO0O00
  if ( netifaces . AF_INET in I1I11i ) :
   for iI1ii11Ii in I1I11i [ netifaces . AF_INET ] :
    I1II1I1I = iI1ii11Ii [ "addr" ]
    if ( I1II1I1I . find ( "127.0.0.1" ) != - 1 ) : continue
    ooo00o0OO . append ( I1II1I1I )
    if 18 - 18: Oo0Ooo * I1Ii111
    if 99 - 99: II111iiii * iIii1I11I1II1 % O0 * oO0o / II111iiii % OoooooooOO
  if ( netifaces . AF_INET6 in I1I11i ) :
   for iI1ii11Ii in I1I11i [ netifaces . AF_INET6 ] :
    I1II1I1I = iI1ii11Ii [ "addr" ]
    if ( I1II1I1I == "::1" ) : continue
    if ( I1II1I1I [ 0 : 5 ] == "fe80:" ) : continue
    ooo00o0OO . append ( I1II1I1I )
    if 14 - 14: IiII . IiII % ooOoO0o
    if 42 - 42: o0oOOo0O0Ooo . OOooOOo - ooOoO0o
    if 33 - 33: II111iiii / O0 / IiII - I11i - i1IIi
 return ( ooo00o0OO )
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
 i1iI = getoutput ( 'egrep "rle-address =" ./lisp.config' )
 if ( i1iI == "" ) : return ( Oo00oo )
 if 79 - 79: I1ii11iIi11i / O0 % o0oOOo0O0Ooo
 o0ooo = i1iI . split ( "\n" )
 for o0 in o0ooo :
  if ( o0 [ 0 ] == "#" ) : continue
  IiI = o0 . split ( "rle-address = " ) [ 1 ]
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
  o0OoOo0O00 = 4 if ( key . do_poly ) else 8
  if 9 - 9: OOooOOo
  I1i = bold ( "Encrypt" , False )
  II = bold ( key . cipher_suite_string , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  I1IIiIi = "poly" if key . do_poly else "sha256"
  I1IIiIi = bold ( I1IIiIi , False )
  OOOOoOoO = "ICV({}): 0x{}...{}" . format ( I1IIiIi , iIiiII1Ii1ii [ 0 : o0OoOo0O00 ] , iIiiII1Ii1ii [ - o0OoOo0O00 : : ] )
  dprint ( "{} for key-id: {}, {}, {}, {}-time: {} usec" . format ( I1i , key . key_id , addr_str , OOOOoOoO , II , iIiIIIIIii ) )
  if 72 - 72: OoOoOO00 / I1Ii111 * IiII % iIii1I11I1II1
  if 53 - 53: OoO0O00 . O0 . I1IiiI * OOooOOo / o0oOOo0O0Ooo
  iIiiII1Ii1ii = int ( iIiiII1Ii1ii , 16 )
  if ( key . do_poly ) :
   iiIIiI1 = byte_swap_64 ( ( iIiiII1Ii1ii >> 64 ) & LISP_8_64_MASK )
   IIiIIiIIii1i = byte_swap_64 ( iIiiII1Ii1ii & LISP_8_64_MASK )
   iIiiII1Ii1ii = struct . pack ( "QQ" , iiIIiI1 , IIiIIiIIii1i )
  else :
   iiIIiI1 = byte_swap_64 ( ( iIiiII1Ii1ii >> 96 ) & LISP_8_64_MASK )
   IIiIIiIIii1i = byte_swap_64 ( ( iIiiII1Ii1ii >> 32 ) & LISP_8_64_MASK )
   iI1i1Ii111I = socket . htonl ( iIiiII1Ii1ii & 0xffffffff )
   iIiiII1Ii1ii = struct . pack ( "QQI" , iiIIiI1 , IIiIIiIIii1i , iI1i1Ii111I )
   if 17 - 17: O0 * iIii1I11I1II1 % IiII . IiII / O0
   if 52 - 52: I1IiiI - iIii1I11I1II1 - I1ii11iIi11i
  return ( [ Oo0OOOO0oOoo0 + oooO00oo0 + iIiiII1Ii1ii , True ] )
  if 38 - 38: I1IiiI + o0oOOo0O0Ooo - IiII
  if 85 - 85: iII111i * iII111i % OoOoOO00 - OOooOOo % OoO0O00 - I1IiiI
 def decrypt ( self , packet , header_length , key , addr_str ) :
  if 3 - 3: OOooOOo + i1IIi % I1ii11iIi11i
  if 100 - 100: OoooooooOO + i11iIiiIii % o0oOOo0O0Ooo + I1IiiI . Oo0Ooo . II111iiii
  if 93 - 93: II111iiii . i11iIiiIii + II111iiii % oO0o
  if 98 - 98: I1Ii111 * oO0o * OoOoOO00 + Ii1I * iII111i
  if 4 - 4: IiII
  if 16 - 16: iIii1I11I1II1 * iII111i + oO0o . O0 . o0oOOo0O0Ooo
  if ( key . do_poly ) :
   iiIIiI1 , IIiIIiIIii1i = struct . unpack ( "QQ" , packet [ - 16 : : ] )
   oo00o00O0 = byte_swap_64 ( iiIIiI1 ) << 64
   oo00o00O0 |= byte_swap_64 ( IIiIIiIIii1i )
   oo00o00O0 = lisp_hex_string ( oo00o00O0 ) . zfill ( 32 )
   packet = packet [ 0 : - 16 ]
   o0OoOo0O00 = 4
   O00o0O = bold ( "poly" , False )
  else :
   iiIIiI1 , IIiIIiIIii1i , iI1i1Ii111I = struct . unpack ( "QQI" , packet [ - 20 : : ] )
   oo00o00O0 = byte_swap_64 ( iiIIiI1 ) << 96
   oo00o00O0 |= byte_swap_64 ( IIiIIiIIii1i ) << 32
   oo00o00O0 |= socket . htonl ( iI1i1Ii111I )
   oo00o00O0 = lisp_hex_string ( oo00o00O0 ) . zfill ( 40 )
   packet = packet [ 0 : - 20 ]
   o0OoOo0O00 = 8
   O00o0O = bold ( "sha" , False )
   if 73 - 73: OoO0O00
  IiIIiII1I = self . lisp_header . encode ( )
  if 28 - 28: OoooooooOO - I11i
  if 84 - 84: II111iiii
  if 36 - 36: OOooOOo - OoOoOO00 - iIii1I11I1II1
  if 10 - 10: I1ii11iIi11i / Ii1I * i1IIi % O0 + I11i
  if ( key . cipher_suite == LISP_CS_25519_CHACHA ) :
   I1i1ii1ii = 8
   II = bold ( "chacha" , False )
  elif ( key . cipher_suite == LISP_CS_25519_GCM ) :
   I1i1ii1ii = 12
   II = bold ( "aes-gcm" , False )
  else :
   I1i1ii1ii = 16
   II = bold ( "aes-cbc" , False )
   if 32 - 32: IiII / OoooooooOO
  Oo0OOOO0oOoo0 = packet [ 0 : I1i1ii1ii ]
  if 30 - 30: OoOoOO00 / I1IiiI - OoO0O00 - iII111i - i11iIiiIii
  if 84 - 84: i1IIi - I1IiiI % iII111i
  if 80 - 80: o0oOOo0O0Ooo % iII111i
  if 80 - 80: Ii1I
  ii = key . do_icv ( IiIIiII1I + packet , Oo0OOOO0oOoo0 )
  if 66 - 66: I1ii11iIi11i . Oo0Ooo
  I1 = "0x{}...{}" . format ( oo00o00O0 [ 0 : o0OoOo0O00 ] , oo00o00O0 [ - o0OoOo0O00 : : ] )
  OO = "0x{}...{}" . format ( ii [ 0 : o0OoOo0O00 ] , ii [ - o0OoOo0O00 : : ] )
  if 34 - 34: I1Ii111 . OoOoOO00 / i11iIiiIii / iII111i
  if ( ii != oo00o00O0 ) :
   self . packet_error = "ICV-error"
   II1iII1 = II + "/" + O00o0O
   I11II11IiI11 = bold ( "ICV failed ({})" . format ( II1iII1 ) , False )
   OOOOoOoO = "packet-ICV {} != computed-ICV {}" . format ( I1 , OO )
   dprint ( ( "{} from RLOC {}, receive-port: {}, key-id: {}, " + "packet dropped, {}" ) . format ( I11II11IiI11 , red ( addr_str , False ) ,
   # OoooooooOO * Ii1I * I1IiiI . ooOoO0o * Ii1I / iII111i
 self . udp_sport , key . key_id , OOOOoOoO ) )
   dprint ( "{}" . format ( key . print_keys ( ) ) )
   if 46 - 46: i11iIiiIii
   if 15 - 15: O0 / i1IIi / i1IIi . iII111i % OoOoOO00 + I1IiiI
   if 48 - 48: I1Ii111 % iII111i % Ii1I % iIii1I11I1II1 . Ii1I
   if 14 - 14: iII111i * OoO0O00 % O0 + I11i + I1ii11iIi11i
   if 23 - 23: Oo0Ooo % iII111i + Ii1I - I1Ii111
   if 65 - 65: OoooooooOO
   lisp_retry_decap_keys ( addr_str , IiIIiII1I + packet , Oo0OOOO0oOoo0 , oo00o00O0 )
   return ( [ None , False ] )
   if 22 - 22: OOooOOo + II111iiii + Oo0Ooo
   if 83 - 83: ooOoO0o
   if 43 - 43: OOooOOo
   if 84 - 84: OOooOOo . IiII . iII111i
   if 2 - 2: Oo0Ooo - OoOoOO00
  packet = packet [ I1i1ii1ii : : ]
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
  I1i = bold ( "Decrypt" , False )
  addr_str = "RLOC: " + red ( addr_str , False )
  I1IIiIi = "poly" if key . do_poly else "sha256"
  I1IIiIi = bold ( I1IIiIi , False )
  OOOOoOoO = "ICV({}): {}" . format ( I1IIiIi , I1 )
  dprint ( "{} for key-id: {}, {}, {} (good), {}-time: {} usec" . format ( I1i , key . key_id , addr_str , OOOOoOoO , II , iIiIIIIIii ) )
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
   ooO = Oo00O0o0O [ 0 : 4 ] + struct . pack ( "H" , iIIi1I1Ii1 ) + Oo00O0o0O [ 6 : 20 ]
   Oo0O0o00o00 = Oo00O0o0O [ 20 : : ]
   IiiiI11 = self . fragment_outer ( ooO , Oo0O0o00o00 )
   return ( IiiiI11 , "Fragment-Outer" )
   if 90 - 90: I1Ii111 . II111iiii . I1ii11iIi11i
   if 32 - 32: ooOoO0o - OoO0O00 . iII111i . iII111i % i1IIi * Ii1I
   if 65 - 65: iII111i / ooOoO0o . II111iiii
   if 90 - 90: I11i
   if 95 - 95: OoO0O00
  OoiIIii1Ii1 = 56 if ( self . outer_version == 6 ) else 36
  ooO = Oo00O0o0O [ 0 : OoiIIii1Ii1 ]
  o0O0o = Oo00O0o0O [ OoiIIii1Ii1 : OoiIIii1Ii1 + 20 ]
  Oo0O0o00o00 = Oo00O0o0O [ OoiIIii1Ii1 + 20 : : ]
  if 47 - 47: OOooOOo * Ii1I % iIii1I11I1II1 / ooOoO0o
  if 61 - 61: IiII + iII111i - OoO0O00 * oO0o
  if 87 - 87: II111iiii % II111iiii
  if 51 - 51: ooOoO0o * iIii1I11I1II1 . iII111i
  if 25 - 25: OOooOOo - Ii1I . I11i
  OO0OOO = struct . unpack ( "H" , o0O0o [ 6 : 8 ] ) [ 0 ]
  OO0OOO = socket . ntohs ( OO0OOO )
  if ( OO0OOO & 0x4000 ) :
   if ( lisp_icmp_raw_socket != None ) :
    Oo0O00OO = Oo00O0o0O [ OoiIIii1Ii1 : : ]
    if ( self . send_icmp_too_big ( Oo0O00OO ) ) : return ( [ ] , None )
    if 75 - 75: IiII % o0oOOo0O0Ooo - I1Ii111
   if ( lisp_ignore_df_bit ) :
    OO0OOO &= ~ 0x4000
   else :
    O0oOo0o0000 = bold ( "DF-bit set" , False )
    dprint ( "{} in inner header, packet discarded" . format ( O0oOo0o0000 ) )
    return ( [ ] , "Fragment-None-DF-bit" )
    if 26 - 26: ooOoO0o + OoO0O00 / OoOoOO00 . II111iiii * Ii1I
    if 21 - 21: I1IiiI - I1IiiI + iII111i % I1IiiI * oO0o
    if 74 - 74: iII111i / I11i . I1IiiI - OoooooooOO + II111iiii + I11i
  II1Ii = 0
  OOOOo0o0O0o = len ( Oo0O0o00o00 )
  IiiiI11 = [ ]
  while ( II1Ii < OOOOo0o0O0o ) :
   IiiiI11 . append ( Oo0O0o00o00 [ II1Ii : II1Ii + 1400 ] )
   II1Ii += 1400
   if 36 - 36: Ii1I * I1IiiI * I1ii11iIi11i . I11i * I1ii11iIi11i
   if 76 - 76: OOooOOo + O0 / IiII - OoO0O00
   if 27 - 27: Oo0Ooo - iIii1I11I1II1 * iII111i * II111iiii * I1ii11iIi11i
   if 9 - 9: i11iIiiIii + OOooOOo - OoOoOO00 / ooOoO0o % i1IIi / oO0o
   if 22 - 22: i1IIi
  i1II11iI1i = IiiiI11
  IiiiI11 = [ ]
  IIIII1II1111 = True if OO0OOO & 0x2000 else False
  OO0OOO = ( OO0OOO & 0x1fff ) * 8
  for IiI111 in i1II11iI1i :
   if 99 - 99: Oo0Ooo / I1Ii111 * Oo0Ooo / iIii1I11I1II1 * IiII
   if 99 - 99: iIii1I11I1II1 - ooOoO0o
   if 79 - 79: I1IiiI + oO0o % I11i % oO0o
   if 56 - 56: I1ii11iIi11i + oO0o . OoO0O00 + OoooooooOO * I1ii11iIi11i - O0
   I1iO00O000oOO0oO = old_div ( OO0OOO , 8 )
   if ( IIIII1II1111 ) :
    I1iO00O000oOO0oO |= 0x2000
   elif ( IiI111 != i1II11iI1i [ - 1 ] ) :
    I1iO00O000oOO0oO |= 0x2000
    if 88 - 88: o0oOOo0O0Ooo . I1IiiI % oO0o . Oo0Ooo % ooOoO0o . oO0o
   I1iO00O000oOO0oO = socket . htons ( I1iO00O000oOO0oO )
   o0O0o = o0O0o [ 0 : 6 ] + struct . pack ( "H" , I1iO00O000oOO0oO ) + o0O0o [ 8 : : ]
   if 53 - 53: i1IIi % Ii1I - OoooooooOO / OoOoOO00 - iIii1I11I1II1
   if 9 - 9: I1Ii111 - OoO0O00 + iIii1I11I1II1 % O0 + I11i + IiII
   if 50 - 50: i1IIi + ooOoO0o
   if 64 - 64: o0oOOo0O0Ooo % oO0o . ooOoO0o
   if 6 - 6: ooOoO0o / i11iIiiIii - Oo0Ooo
   if 3 - 3: IiII - OoooooooOO * OoooooooOO - I1IiiI / I1Ii111 * I1ii11iIi11i
   OOOOo0o0O0o = len ( IiI111 )
   OO0OOO += OOOOo0o0O0o
   OoOoo00Oo0OoO = socket . htons ( OOOOo0o0O0o + 20 )
   o0O0o = o0O0o [ 0 : 2 ] + struct . pack ( "H" , OoOoo00Oo0OoO ) + o0O0o [ 4 : 10 ] + struct . pack ( "H" , 0 ) + o0O0o [ 12 : : ]
   if 58 - 58: IiII % iIii1I11I1II1 / i11iIiiIii % o0oOOo0O0Ooo . I1Ii111 * iII111i
   o0O0o = lisp_ip_checksum ( o0O0o )
   iiI1II = o0O0o + IiI111
   if 100 - 100: I1Ii111 * Oo0Ooo - iIii1I11I1II1 + I1IiiI - i1IIi + iII111i
   if 19 - 19: I1Ii111 + iII111i * I1Ii111
   if 71 - 71: o0oOOo0O0Ooo . I1IiiI - I1ii11iIi11i - Oo0Ooo - i1IIi - I1IiiI
   if 45 - 45: OoO0O00 * OoO0O00
   if 9 - 9: iIii1I11I1II1
   OOOOo0o0O0o = len ( iiI1II )
   if ( self . outer_version == 4 ) :
    OoOoo00Oo0OoO = OOOOo0o0O0o + OoiIIii1Ii1
    OOOOo0o0O0o += 16
    ooO = ooO [ 0 : 2 ] + struct . pack ( "H" , OoOoo00Oo0OoO ) + ooO [ 4 : : ]
    if 57 - 57: ooOoO0o / Ii1I % o0oOOo0O0Ooo % i11iIiiIii
    ooO = lisp_ip_checksum ( ooO )
    iiI1II = ooO + iiI1II
    iiI1II = self . fix_outer_header ( iiI1II )
    if 95 - 95: I1Ii111 - o0oOOo0O0Ooo
    if 65 - 65: i11iIiiIii - OoooooooOO / O0 * IiII % I11i
    if 53 - 53: OOooOOo + I1Ii111
    if 10 - 10: I11i * i1IIi . oO0o / I1Ii111 . OOooOOo / I1Ii111
    if 1 - 1: iII111i % ooOoO0o
   O0ooo0 = OoiIIii1Ii1 - 12
   OoOoo00Oo0OoO = socket . htons ( OOOOo0o0O0o )
   iiI1II = iiI1II [ 0 : O0ooo0 ] + struct . pack ( "H" , OoOoo00Oo0OoO ) + iiI1II [ O0ooo0 + 2 : : ]
   if 89 - 89: IiII - i1IIi - IiII
   IiiiI11 . append ( iiI1II )
   if 74 - 74: OoO0O00 % OoO0O00
  return ( IiiiI11 , "Fragment-Inner" )
  if 28 - 28: OoOoOO00 % oO0o - OOooOOo + OOooOOo + oO0o / iIii1I11I1II1
  if 91 - 91: I1IiiI / II111iiii * OOooOOo
 def fix_outer_header ( self , packet ) :
  if 94 - 94: II111iiii - iIii1I11I1II1 - iIii1I11I1II1
  if 83 - 83: I1ii11iIi11i * iIii1I11I1II1 + OoOoOO00 * i1IIi . OoooooooOO % Ii1I
  if 81 - 81: OoO0O00 - iIii1I11I1II1
  if 60 - 60: I1Ii111
  if 77 - 77: I1IiiI / I1ii11iIi11i
  if 95 - 95: I1Ii111 * i1IIi + oO0o
  if 40 - 40: II111iiii
  if 7 - 7: OOooOOo / OoO0O00
  if ( self . outer_version == 4 or self . inner_version == 4 ) :
   if ( lisp_is_macos ( ) ) :
    packet = packet [ 0 : 2 ] + packet [ 3 : 4 ] + packet [ 2 : 3 ] + packet [ 4 : 6 ] + packet [ 7 : 8 ] + packet [ 6 : 7 ] + packet [ 8 : : ]
    if 88 - 88: i1IIi
   else :
    packet = packet [ 0 : 2 ] + packet [ 3 : 4 ] + packet [ 2 : 3 ] + packet [ 4 : : ]
    if 53 - 53: ooOoO0o . OOooOOo . o0oOOo0O0Ooo + oO0o
    if 17 - 17: iIii1I11I1II1 + i1IIi . I1ii11iIi11i + Ii1I % i1IIi . oO0o
  return ( packet )
  if 57 - 57: oO0o
  if 92 - 92: II111iiii - OoO0O00 - OOooOOo % I1IiiI - OoOoOO00 * I1Ii111
 def send_packet ( self , lisp_raw_socket , dest ) :
  if ( lisp_flow_logging and dest != self . inner_dest ) : self . log_flow ( True )
  if 16 - 16: iIii1I11I1II1 + OoooooooOO - ooOoO0o * IiII
  dest = dest . print_address_no_iid ( )
  IiiiI11 , iiI1IiI1I1I = self . fragment ( )
  if 42 - 42: Oo0Ooo + I1IiiI + I11i + i1IIi / OoooooooOO
  for iiI1II in IiiiI11 :
   if ( len ( IiiiI11 ) != 1 ) :
    self . packet = iiI1II
    self . print_packet ( iiI1IiI1I1I , True )
    if 20 - 20: oO0o - o0oOOo0O0Ooo * OoO0O00 % i1IIi - iIii1I11I1II1 . OOooOOo
    if 31 - 31: oO0o % i1IIi . OoooooooOO - o0oOOo0O0Ooo + OoooooooOO
   try : lisp_raw_socket . sendto ( iiI1II , ( dest , 0 ) )
   except socket . error as oOO :
    lprint ( "socket.sendto() failed: {}" . format ( oOO ) )
    if 45 - 45: OOooOOo + I11i / OoooooooOO - Ii1I + OoooooooOO
    if 42 - 42: iIii1I11I1II1 * I1IiiI * I1Ii111
    if 62 - 62: OOooOOo * O0 % IiII . IiII . I1IiiI
    if 91 - 91: i1IIi . iII111i
 def send_l2_packet ( self , l2_socket , mac_header ) :
  if ( l2_socket == None ) :
   lprint ( "No layer-2 socket, drop IPv6 packet" )
   return
   if 37 - 37: iII111i - I11i + iIii1I11I1II1 / I1Ii111 - OoO0O00 . o0oOOo0O0Ooo
  if ( mac_header == None ) :
   lprint ( "Could not build MAC header, drop IPv6 packet" )
   return
   if 62 - 62: I1ii11iIi11i
   if 47 - 47: I1Ii111 % OOooOOo * OoO0O00 . iIii1I11I1II1 % Oo0Ooo + OoooooooOO
  Oo00O0o0O = mac_header + self . packet
  if 2 - 2: I1Ii111 % OoooooooOO - ooOoO0o * I1ii11iIi11i * IiII
  if 99 - 99: iIii1I11I1II1 . Oo0Ooo / ooOoO0o . OOooOOo % I1IiiI * I11i
  if 95 - 95: oO0o
  if 80 - 80: IiII
  if 42 - 42: OoooooooOO * II111iiii
  if 53 - 53: I1Ii111 + i1IIi . OoO0O00 / i11iIiiIii + Ii1I % OoOoOO00
  if 9 - 9: ooOoO0o . I11i - Oo0Ooo . I1Ii111
  if 39 - 39: OOooOOo
  if 70 - 70: IiII % OoO0O00 % I1IiiI
  if 95 - 95: OoOoOO00 - I1Ii111 / O0 * I1IiiI - o0oOOo0O0Ooo
  if 12 - 12: iIii1I11I1II1 % Oo0Ooo . iII111i . IiII % i11iIiiIii
  l2_socket . write ( Oo00O0o0O )
  return
  if 2 - 2: oO0o * oO0o . OoOoOO00 * Ii1I * iIii1I11I1II1
  if 13 - 13: I11i / O0 . i11iIiiIii * i1IIi % i11iIiiIii
 def bridge_l2_packet ( self , eid , db ) :
  try : iIi1Iii1 = db . dynamic_eids [ eid . print_address_no_iid ( ) ]
  except : return
  try : oo = lisp_myinterfaces [ iIi1Iii1 . interface ]
  except : return
  try :
   socket = oo . get_bridge_socket ( )
   if ( socket == None ) : return
  except : return
  if 87 - 87: OoooooooOO
  try : socket . send ( self . packet )
  except socket . error as oOO :
   lprint ( "bridge_l2_packet(): socket.send() failed: {}" . format ( oOO ) )
   if 1 - 1: iIii1I11I1II1 / o0oOOo0O0Ooo
   if 98 - 98: O0 % I1IiiI / OoooooooOO * I1ii11iIi11i - oO0o
   if 51 - 51: iII111i + I11i
 def is_lisp_packet ( self , packet ) :
  ii11 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == LISP_UDP_PROTOCOL )
  if ( ii11 == False ) : return ( False )
  if 54 - 54: II111iiii * O0 % I1IiiI . I11i
  O0ooO0O00oo0 = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
  if ( socket . ntohs ( O0ooO0O00oo0 ) == LISP_DATA_PORT ) : return ( True )
  O0ooO0O00oo0 = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
  if ( socket . ntohs ( O0ooO0O00oo0 ) == LISP_DATA_PORT ) : return ( True )
  return ( False )
  if 46 - 46: OoOoOO00 + I1IiiI % OoooooooOO * i11iIiiIii - Oo0Ooo
  if 47 - 47: iII111i * OoOoOO00 * IiII
 def decode ( self , is_lisp_packet , lisp_ipc_socket , stats ) :
  self . packet_error = ""
  Oo00O0o0O = self . packet
  iIiii1IIi1I = len ( Oo00O0o0O )
  IiIi = ii1IiI = True
  if 73 - 73: OoooooooOO * O0 * ooOoO0o
  if 7 - 7: II111iiii + i1IIi
  if 95 - 95: i11iIiiIii + OoooooooOO / OOooOOo - iIii1I11I1II1 + iIii1I11I1II1
  if 29 - 29: IiII % ooOoO0o + OoO0O00 . i1IIi + I1IiiI
  I111I = 0
  i1I1iI = self . lisp_header . get_instance_id ( )
  if ( is_lisp_packet ) :
   oooO = struct . unpack ( "B" , Oo00O0o0O [ 0 : 1 ] ) [ 0 ]
   self . outer_version = oooO >> 4
   if ( self . outer_version == 4 ) :
    if 98 - 98: i1IIi - iII111i
    if 49 - 49: o0oOOo0O0Ooo . Ii1I . oO0o
    if 9 - 9: IiII - II111iiii * OoO0O00
    if 78 - 78: iIii1I11I1II1 / O0 * oO0o / iII111i / OoOoOO00
    if 15 - 15: ooOoO0o / oO0o
    O0Oo00o0o = struct . unpack ( "H" , Oo00O0o0O [ 10 : 12 ] ) [ 0 ]
    Oo00O0o0O = lisp_ip_checksum ( Oo00O0o0O )
    O0OoO0o = struct . unpack ( "H" , Oo00O0o0O [ 10 : 12 ] ) [ 0 ]
    if ( O0OoO0o != 0 ) :
     if ( O0Oo00o0o != 0 or lisp_is_macos ( ) == False ) :
      self . packet_error = "checksum-error"
      if ( stats ) :
       stats [ self . packet_error ] . increment ( iIiii1IIi1I )
       if 80 - 80: i11iIiiIii % iIii1I11I1II1 / i11iIiiIii
       if 66 - 66: OoOoOO00 . iIii1I11I1II1 * I1ii11iIi11i - Ii1I - iIii1I11I1II1
      lprint ( "IPv4 header checksum failed for outer header" )
      if ( lisp_flow_logging ) : self . log_flow ( False )
      return ( None )
      if 28 - 28: OoOoOO00 % OoooooooOO
      if 13 - 13: IiII . Oo0Ooo - I11i / oO0o - Oo0Ooo - I1IiiI
      if 84 - 84: II111iiii
    Oo0ooooO0o00 = LISP_AFI_IPV4
    II1Ii = 12
    self . outer_tos = struct . unpack ( "B" , Oo00O0o0O [ 1 : 2 ] ) [ 0 ]
    self . outer_ttl = struct . unpack ( "B" , Oo00O0o0O [ 8 : 9 ] ) [ 0 ]
    I111I = 20
   elif ( self . outer_version == 6 ) :
    Oo0ooooO0o00 = LISP_AFI_IPV6
    II1Ii = 8
    iIIIIIi11Ii = struct . unpack ( "H" , Oo00O0o0O [ 0 : 2 ] ) [ 0 ]
    self . outer_tos = ( socket . ntohs ( iIIIIIi11Ii ) >> 4 ) & 0xff
    self . outer_ttl = struct . unpack ( "B" , Oo00O0o0O [ 7 : 8 ] ) [ 0 ]
    I111I = 40
   else :
    self . packet_error = "outer-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( iIiii1IIi1I )
    lprint ( "Cannot decode outer header" )
    return ( None )
    if 92 - 92: oO0o / I1ii11iIi11i
    if 6 - 6: i11iIiiIii / i1IIi / IiII . I1IiiI - OOooOOo % i11iIiiIii
   self . outer_source . afi = Oo0ooooO0o00
   self . outer_dest . afi = Oo0ooooO0o00
   o0OoOoOo0O = self . outer_source . addr_length ( )
   if 37 - 37: i1IIi . I1Ii111 - II111iiii % o0oOOo0O0Ooo - i1IIi . oO0o
   self . outer_source . unpack_address ( Oo00O0o0O [ II1Ii : II1Ii + o0OoOoOo0O ] )
   II1Ii += o0OoOoOo0O
   self . outer_dest . unpack_address ( Oo00O0o0O [ II1Ii : II1Ii + o0OoOoOo0O ] )
   Oo00O0o0O = Oo00O0o0O [ I111I : : ]
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
   IiIi = ( self . udp_dport == LISP_DATA_PORT or
 self . udp_sport == LISP_DATA_PORT )
   ii1IiI = ( self . udp_dport in ( LISP_L2_DATA_PORT , LISP_VXLAN_DATA_PORT ) )
   if 65 - 65: Oo0Ooo % OOooOOo / i11iIiiIii / iIii1I11I1II1 . I1Ii111 + ooOoO0o
   if 92 - 92: oO0o
   if 96 - 96: I1Ii111 * iIii1I11I1II1 / OoOoOO00 % OOooOOo * II111iiii
   if 3 - 3: OOooOOo . Oo0Ooo / i11iIiiIii + OoO0O00
   if ( self . lisp_header . decode ( Oo00O0o0O ) == False ) :
    self . packet_error = "lisp-header-error"
    if ( stats ) : stats [ self . packet_error ] . increment ( iIiii1IIi1I )
    if 47 - 47: IiII . OOooOOo
    if ( lisp_flow_logging ) : self . log_flow ( False )
    lprint ( "Cannot decode LISP header" )
    return ( None )
    if 96 - 96: I11i % II111iiii / ooOoO0o % OOooOOo / ooOoO0o % i11iIiiIii
   Oo00O0o0O = Oo00O0o0O [ 8 : : ]
   i1I1iI = self . lisp_header . get_instance_id ( )
   I111I += 16
   if 57 - 57: I11i - I11i % II111iiii % Oo0Ooo . o0oOOo0O0Ooo % Oo0Ooo
  if ( i1I1iI == 0xffffff ) : i1I1iI = 0
  if 91 - 91: I1IiiI - OoO0O00 - Oo0Ooo - Ii1I * iIii1I11I1II1
  if 68 - 68: OoO0O00 % O0 * iIii1I11I1II1 / oO0o * o0oOOo0O0Ooo + OOooOOo
  if 89 - 89: ooOoO0o * I1IiiI . oO0o
  if 75 - 75: ooOoO0o - iII111i % iII111i + ooOoO0o * o0oOOo0O0Ooo - I1ii11iIi11i
  I111Ii1I1I1iI = False
  III = self . lisp_header . k_bits
  if ( III ) :
   O00oO000Oo0 = lisp_get_crypto_decap_lookup_key ( self . outer_source ,
 self . udp_sport )
   if ( O00oO000Oo0 == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( iIiii1IIi1I )
    if 84 - 84: i11iIiiIii / o0oOOo0O0Ooo % iIii1I11I1II1 . ooOoO0o . OoO0O00 / iII111i
    self . print_packet ( "Receive" , is_lisp_packet )
    ooooo0oo0OO = bold ( "No key available" , False )
    dprint ( "{} for key-id {} to decrypt packet" . format ( ooooo0oo0OO , III ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 41 - 41: Oo0Ooo / OoO0O00 / OoOoOO00 - i11iIiiIii - OoOoOO00
    if 4 - 4: I11i . IiII
   I1IIiiI1II = lisp_crypto_keys_by_rloc_decap [ O00oO000Oo0 ] [ III ]
   if ( I1IIiiI1II == None ) :
    self . packet_error = "no-decrypt-key"
    if ( stats ) : stats [ self . packet_error ] . increment ( iIiii1IIi1I )
    if 9 - 9: I1Ii111 % I11i + ooOoO0o / I1IiiI . Ii1I
    self . print_packet ( "Receive" , is_lisp_packet )
    ooooo0oo0OO = bold ( "No key available" , False )
    dprint ( "{} to decrypt packet from RLOC {}" . format ( ooooo0oo0OO ,
 red ( O00oO000Oo0 , False ) ) )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 86 - 86: i11iIiiIii + iIii1I11I1II1
    if 87 - 87: OoO0O00 * OoOoOO00 - Oo0Ooo % OOooOOo * i11iIiiIii
    if 59 - 59: I1Ii111 + OoooooooOO / I1IiiI / OoooooooOO . iII111i
    if 20 - 20: Ii1I . I1Ii111 % Ii1I
    if 5 - 5: OOooOOo + iII111i
   I1IIiiI1II . use_count += 1
   Oo00O0o0O , I111Ii1I1I1iI = self . decrypt ( Oo00O0o0O , I111I , I1IIiiI1II , O00oO000Oo0 )
   if ( I111Ii1I1I1iI == False ) :
    if ( stats ) : stats [ self . packet_error ] . increment ( iIiii1IIi1I )
    if ( lisp_flow_logging ) : self . log_flow ( False )
    return ( None )
    if 23 - 23: I1Ii111 % iIii1I11I1II1 . I11i
    if 95 - 95: Oo0Ooo + i11iIiiIii % OOooOOo - oO0o
    if 11 - 11: I1ii11iIi11i / O0 + II111iiii
    if 95 - 95: I1Ii111 + IiII * iIii1I11I1II1
    if 17 - 17: OoO0O00 - Oo0Ooo * O0 / Ii1I
    if 19 - 19: i1IIi - iIii1I11I1II1 . I11i
   if ( I1IIiiI1II . cipher_suite == LISP_CS_25519_CHACHA ) :
    Oo00O0o0O = Oo00O0o0O . encode ( "raw_unicode_escape" )
    if 2 - 2: Ii1I
    if 12 - 12: i11iIiiIii - iIii1I11I1II1 * IiII * iII111i
    if 19 - 19: O0 + oO0o + o0oOOo0O0Ooo
    if 81 - 81: iIii1I11I1II1
    if 51 - 51: o0oOOo0O0Ooo . I1ii11iIi11i * Ii1I / Oo0Ooo * II111iiii / O0
    if 44 - 44: i11iIiiIii % I1Ii111 % oO0o + I11i * oO0o . Ii1I
  oooO = struct . unpack ( "B" , Oo00O0o0O [ 0 : 1 ] ) [ 0 ]
  self . inner_version = oooO >> 4
  if ( IiIi and self . inner_version == 4 and oooO >= 0x45 ) :
   OoOo0Oooo0o = socket . ntohs ( struct . unpack ( "H" , Oo00O0o0O [ 2 : 4 ] ) [ 0 ] )
   self . inner_tos = struct . unpack ( "B" , Oo00O0o0O [ 1 : 2 ] ) [ 0 ]
   self . inner_ttl = struct . unpack ( "B" , Oo00O0o0O [ 8 : 9 ] ) [ 0 ]
   self . inner_protocol = struct . unpack ( "B" , Oo00O0o0O [ 9 : 10 ] ) [ 0 ]
   self . inner_source . afi = LISP_AFI_IPV4
   self . inner_dest . afi = LISP_AFI_IPV4
   self . inner_source . unpack_address ( Oo00O0o0O [ 12 : 16 ] )
   self . inner_dest . unpack_address ( Oo00O0o0O [ 16 : 20 ] )
   OO0OOO = socket . ntohs ( struct . unpack ( "H" , Oo00O0o0O [ 6 : 8 ] ) [ 0 ] )
   self . inner_is_fragment = ( OO0OOO & 0x2000 or OO0OOO != 0 )
   if ( self . inner_protocol == LISP_UDP_PROTOCOL ) :
    self . inner_sport = struct . unpack ( "H" , Oo00O0o0O [ 20 : 22 ] ) [ 0 ]
    self . inner_sport = socket . ntohs ( self . inner_sport )
    self . inner_dport = struct . unpack ( "H" , Oo00O0o0O [ 22 : 24 ] ) [ 0 ]
    self . inner_dport = socket . ntohs ( self . inner_dport )
    if 65 - 65: OoOoOO00 + I1Ii111 % I1IiiI
  elif ( IiIi and self . inner_version == 6 and oooO >= 0x60 ) :
   OoOo0Oooo0o = socket . ntohs ( struct . unpack ( "H" , Oo00O0o0O [ 4 : 6 ] ) [ 0 ] ) + 40
   iIIIIIi11Ii = struct . unpack ( "H" , Oo00O0o0O [ 0 : 2 ] ) [ 0 ]
   self . inner_tos = ( socket . ntohs ( iIIIIIi11Ii ) >> 4 ) & 0xff
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
    if 54 - 54: I1Ii111 / o0oOOo0O0Ooo
  elif ( ii1IiI ) :
   OoOo0Oooo0o = len ( Oo00O0o0O )
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
   if ( stats ) : stats [ self . packet_error ] . increment ( iIiii1IIi1I )
   if 39 - 39: OOooOOo % oO0o * I1ii11iIi11i - O0 + I1IiiI + o0oOOo0O0Ooo
   lprint ( "Cannot decode encapsulation, header version {}" . format ( hex ( oooO ) ) )
   if 64 - 64: II111iiii / II111iiii
   Oo00O0o0O = lisp_format_packet ( Oo00O0o0O [ 0 : 20 ] )
   lprint ( "Packet header: {}" . format ( Oo00O0o0O ) )
   if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
   return ( None )
   if 52 - 52: I1Ii111 * I1ii11iIi11i
  self . inner_source . mask_len = self . inner_source . host_mask_len ( )
  self . inner_dest . mask_len = self . inner_dest . host_mask_len ( )
  self . inner_source . instance_id = i1I1iI
  self . inner_dest . instance_id = i1I1iI
  if 35 - 35: o0oOOo0O0Ooo % OoO0O00
  if 27 - 27: Ii1I - iIii1I11I1II1 * Ii1I
  if 30 - 30: o0oOOo0O0Ooo + Ii1I / OoooooooOO - IiII % oO0o
  if 21 - 21: OoooooooOO % OoOoOO00 - OoOoOO00 / I1ii11iIi11i / o0oOOo0O0Ooo
  if 15 - 15: ooOoO0o / ooOoO0o % OoooooooOO . I1Ii111
  if ( lisp_nonce_echoing and is_lisp_packet ) :
   oOoOooO0OOOoo = lisp_get_echo_nonce ( self . outer_source , None )
   if ( oOoOooO0OOOoo == None ) :
    I1I111i = self . outer_source . print_address_no_iid ( )
    oOoOooO0OOOoo = lisp_echo_nonce ( I1I111i )
    if 90 - 90: I1IiiI . II111iiii - i1IIi + oO0o
   o0oOoo00 = self . lisp_header . get_nonce ( )
   if ( self . lisp_header . is_e_bit_set ( ) ) :
    oOoOooO0OOOoo . receive_request ( lisp_ipc_socket , o0oOoo00 )
   elif ( oOoOooO0OOOoo . request_nonce_sent ) :
    oOoOooO0OOOoo . receive_echo ( lisp_ipc_socket , o0oOoo00 )
    if 21 - 21: O0 * ooOoO0o % OoOoOO00 / O0
    if 85 - 85: OoooooooOO + OoooooooOO
    if 23 - 23: i1IIi
    if 31 - 31: Oo0Ooo - iIii1I11I1II1 / I11i . OoO0O00
    if 74 - 74: Oo0Ooo - II111iiii - IiII
    if 50 - 50: I1IiiI - oO0o + oO0o * I11i + oO0o
    if 70 - 70: i1IIi % OoO0O00 / i1IIi
  if ( I111Ii1I1I1iI ) : self . packet += Oo00O0o0O [ : OoOo0Oooo0o ]
  if 30 - 30: OoOoOO00 - i11iIiiIii
  if 94 - 94: OoOoOO00 % iII111i
  if 39 - 39: OoOoOO00 + I1Ii111 % O0
  if 26 - 26: ooOoO0o + OoOoOO00
  if ( lisp_flow_logging and is_lisp_packet ) : self . log_flow ( False )
  return ( self )
  if 17 - 17: I1ii11iIi11i - iII111i % Oo0Ooo * O0 % O0 * OOooOOo
  if 6 - 6: I1Ii111
 def swap_mac ( self , mac ) :
  return ( mac [ 1 ] + mac [ 0 ] + mac [ 3 ] + mac [ 2 ] + mac [ 5 ] + mac [ 4 ] )
  if 46 - 46: II111iiii * I1Ii111
  if 23 - 23: i1IIi - O0
 def strip_outer_headers ( self ) :
  II1Ii = 16
  II1Ii += 20 if ( self . outer_version == 4 ) else 40
  self . packet = self . packet [ II1Ii : : ]
  return ( self )
  if 6 - 6: ooOoO0o % OoooooooOO * I1Ii111 - IiII
  if 24 - 24: I11i / iIii1I11I1II1 . OoooooooOO % OoOoOO00 . Ii1I
 def hash_ports ( self ) :
  Oo00O0o0O = self . packet
  oooO = self . inner_version
  ooo00OoOooooo = 0
  if ( oooO == 4 ) :
   OoooooO0 = struct . unpack ( "B" , Oo00O0o0O [ 9 : 10 ] ) [ 0 ]
   if ( self . inner_is_fragment ) : return ( OoooooO0 )
   if ( OoooooO0 in [ 6 , 17 ] ) :
    ooo00OoOooooo = OoooooO0
    ooo00OoOooooo += struct . unpack ( "I" , Oo00O0o0O [ 20 : 24 ] ) [ 0 ]
    ooo00OoOooooo = ( ooo00OoOooooo >> 16 ) ^ ( ooo00OoOooooo & 0xffff )
    if 7 - 7: OoOoOO00 . OOooOOo % Oo0Ooo
    if 55 - 55: ooOoO0o - Oo0Ooo * oO0o
  if ( oooO == 6 ) :
   OoooooO0 = struct . unpack ( "B" , Oo00O0o0O [ 6 : 7 ] ) [ 0 ]
   if ( OoooooO0 in [ 6 , 17 ] ) :
    ooo00OoOooooo = OoooooO0
    ooo00OoOooooo += struct . unpack ( "I" , Oo00O0o0O [ 40 : 44 ] ) [ 0 ]
    ooo00OoOooooo = ( ooo00OoOooooo >> 16 ) ^ ( ooo00OoOooooo & 0xffff )
    if 72 - 72: o0oOOo0O0Ooo % o0oOOo0O0Ooo + iII111i + I1ii11iIi11i / Oo0Ooo
    if 30 - 30: Oo0Ooo + I1IiiI + i11iIiiIii / OoO0O00
  return ( ooo00OoOooooo )
  if 64 - 64: IiII
  if 80 - 80: I1IiiI - i11iIiiIii / OoO0O00 / OoOoOO00 + OoOoOO00
 def hash_packet ( self ) :
  ooo00OoOooooo = self . inner_source . address ^ self . inner_dest . address
  ooo00OoOooooo += self . hash_ports ( )
  if ( self . inner_version == 4 ) :
   ooo00OoOooooo = ( ooo00OoOooooo >> 16 ) ^ ( ooo00OoOooooo & 0xffff )
  elif ( self . inner_version == 6 ) :
   ooo00OoOooooo = ( ooo00OoOooooo >> 64 ) ^ ( ooo00OoOooooo & 0xffffffffffffffff )
   ooo00OoOooooo = ( ooo00OoOooooo >> 32 ) ^ ( ooo00OoOooooo & 0xffffffff )
   ooo00OoOooooo = ( ooo00OoOooooo >> 16 ) ^ ( ooo00OoOooooo & 0xffff )
   if 89 - 89: O0 + IiII * I1Ii111
  self . udp_sport = 0xf000 | ( ooo00OoOooooo & 0xfff )
  if 30 - 30: OoOoOO00
  if 39 - 39: I1ii11iIi11i + o0oOOo0O0Ooo + I1Ii111 + IiII
 def print_packet ( self , s_or_r , is_lisp_packet ) :
  if ( is_lisp_packet == False ) :
   i1i1 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
   dprint ( ( "{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..." ) . format ( bold ( s_or_r , False ) ,
   # I11i
 green ( i1i1 , False ) , self . inner_tos ,
 self . inner_ttl , len ( self . packet ) ,
 lisp_format_packet ( self . packet [ 0 : 60 ] ) ) )
   return
   if 27 - 27: i1IIi
   if 53 - 53: OoO0O00
  if ( s_or_r . find ( "Receive" ) != - 1 ) :
   oooOoOO0o = "decap"
   oooOoOO0o += "-vxlan" if self . udp_dport == LISP_VXLAN_DATA_PORT else ""
  else :
   oooOoOO0o = s_or_r
   if ( oooOoOO0o in [ "Send" , "Replicate" ] or oooOoOO0o . find ( "Fragment" ) != - 1 ) :
    oooOoOO0o = "encap"
    if 78 - 78: O0 - I1Ii111 * OOooOOo + I11i + II111iiii
    if 15 - 15: Oo0Ooo . i11iIiiIii + ooOoO0o / I1ii11iIi11i / iII111i + OoooooooOO
  ooo0oOoO00Oo = "{} -> {}" . format ( self . outer_source . print_address_no_iid ( ) ,
 self . outer_dest . print_address_no_iid ( ) )
  if 46 - 46: ooOoO0o - ooOoO0o * I1ii11iIi11i / iII111i * OOooOOo / o0oOOo0O0Ooo
  if 67 - 67: OOooOOo - Ii1I % iII111i / II111iiii + I1IiiI * ooOoO0o
  if 100 - 100: I1ii11iIi11i
  if 81 - 81: I1ii11iIi11i % iII111i
  if 22 - 22: OoooooooOO + o0oOOo0O0Ooo . I11i + I1IiiI + OoooooooOO . OoOoOO00
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   o0 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, " )
   if 93 - 93: I1IiiI
   o0 += bold ( "control-packet" , False ) + ": {} ..."
   if 89 - 89: OoooooooOO % i11iIiiIii + I1Ii111
   dprint ( o0 . format ( bold ( s_or_r , False ) , red ( ooo0oOoO00Oo , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport ,
 self . udp_dport , lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
   return
  else :
   o0 = ( "{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ..." )
   if 12 - 12: OoOoOO00 * ooOoO0o
   if 59 - 59: II111iiii * OoooooooOO - OoooooooOO
   if 33 - 33: O0 . i11iIiiIii % o0oOOo0O0Ooo
   if 50 - 50: ooOoO0o
  if ( self . lisp_header . k_bits ) :
   if ( oooOoOO0o == "encap" ) : oooOoOO0o = "encrypt/encap"
   if ( oooOoOO0o == "decap" ) : oooOoOO0o = "decap/decrypt"
   if 81 - 81: i11iIiiIii * iIii1I11I1II1 / Oo0Ooo * OOooOOo
   if 83 - 83: i11iIiiIii - I1IiiI * i11iIiiIii
  i1i1 = "{} -> {}" . format ( self . inner_source . print_address ( ) ,
 self . inner_dest . print_address ( ) )
  if 59 - 59: iII111i - OoooooooOO / ooOoO0o + I1ii11iIi11i . o0oOOo0O0Ooo - iII111i
  dprint ( o0 . format ( bold ( s_or_r , False ) , red ( ooo0oOoO00Oo , False ) ,
 self . outer_tos , self . outer_ttl , self . udp_sport , self . udp_dport ,
 green ( i1i1 , False ) , self . inner_tos , self . inner_ttl ,
 len ( self . packet ) , self . lisp_header . print_header ( oooOoOO0o ) ,
 lisp_format_packet ( self . packet [ 0 : 56 ] ) ) )
  if 29 - 29: oO0o
  if 26 - 26: O0 % OOooOOo - IiII . OOooOOo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . inner_source , self . inner_dest ) )
  if 70 - 70: o0oOOo0O0Ooo + I11i / iII111i + ooOoO0o / I1IiiI
  if 33 - 33: OoooooooOO . O0
 def get_raw_socket ( self ) :
  i1I1iI = str ( self . lisp_header . get_instance_id ( ) )
  if ( i1I1iI == "0" ) : return ( None )
  if ( i1I1iI not in lisp_iid_to_interface ) : return ( None )
  if 59 - 59: iIii1I11I1II1
  oo = lisp_iid_to_interface [ i1I1iI ]
  OOo0oOO0o0oo0 = oo . get_socket ( )
  if ( OOo0oOO0o0oo0 == None ) :
   I1i = bold ( "SO_BINDTODEVICE" , False )
   i1OOoO0OO0oO = ( os . getenv ( "LISP_ENFORCE_BINDTODEVICE" ) != None )
   lprint ( "{} required for multi-tenancy support, {} packet" . format ( I1i , "drop" if i1OOoO0OO0oO else "forward" ) )
   if 4 - 4: OoooooooOO
   if ( i1OOoO0OO0oO ) : return ( None )
   if 7 - 7: IiII
   if 26 - 26: OOooOOo + Oo0Ooo
  i1I1iI = bold ( i1I1iI , False )
  oooOo = bold ( oo . device , False )
  dprint ( "Send packet on instance-id {} interface {}" . format ( i1I1iI , oooOo ) )
  return ( OOo0oOO0o0oo0 )
  if 71 - 71: I1IiiI . ooOoO0o
  if 43 - 43: I1ii11iIi11i * OOooOOo
 def log_flow ( self , encap ) :
  global lisp_flow_log
  if 1 - 1: OoO0O00 * ooOoO0o + IiII . oO0o / ooOoO0o
  O0O00Oo = os . path . exists ( "./log-flows" )
  if ( len ( lisp_flow_log ) == LISP_FLOW_LOG_SIZE or O0O00Oo ) :
   IiiI1II1 = [ lisp_flow_log ]
   lisp_flow_log = [ ]
   threading . Thread ( target = lisp_write_flow_log , args = IiiI1II1 ) . start ( )
   if ( O0O00Oo ) : os . system ( "rm ./log-flows" )
   return
   if 100 - 100: OoO0O00 - iII111i * I11i + o0oOOo0O0Ooo
   if 54 - 54: I1IiiI . oO0o + OoOoOO00 % I1Ii111 * I1Ii111
  iIiIIIIIii = datetime . datetime . now ( )
  lisp_flow_log . append ( [ iIiIIIIIii , encap , self . packet , self ] )
  if 61 - 61: I1ii11iIi11i / OoO0O00
  if 31 - 31: i1IIi . II111iiii * o0oOOo0O0Ooo / i11iIiiIii
 def print_flow ( self , ts , encap , packet ) :
  ts = ts . strftime ( "%m/%d/%y %H:%M:%S.%f" ) [ : - 3 ]
  oO00o0 = "{}: {}" . format ( ts , "encap" if encap else "decap" )
  if 55 - 55: ooOoO0o - oO0o % I1IiiI
  ooOooo0OoOo0o = red ( self . outer_source . print_address_no_iid ( ) , False )
  Ooo0O0ooo0o = red ( self . outer_dest . print_address_no_iid ( ) , False )
  O0Oo = green ( self . inner_source . print_address ( ) , False )
  O0oOo00Oo0oo0 = green ( self . inner_dest . print_address ( ) , False )
  if 36 - 36: I1Ii111 / I1Ii111 % oO0o
  if ( self . lisp_header . get_instance_id ( ) == 0xffffff ) :
   oO00o0 += " {}:{} -> {}:{}, LISP control message type {}\n"
   oO00o0 = oO00o0 . format ( ooOooo0OoOo0o , self . udp_sport , Ooo0O0ooo0o , self . udp_dport ,
 self . inner_version )
   return ( oO00o0 )
   if 97 - 97: OoooooooOO * o0oOOo0O0Ooo + OoooooooOO % Ii1I * Oo0Ooo
   if 35 - 35: iIii1I11I1II1 % iII111i - i1IIi
  if ( self . outer_dest . is_null ( ) == False ) :
   oO00o0 += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
   oO00o0 = oO00o0 . format ( ooOooo0OoOo0o , self . udp_sport , Ooo0O0ooo0o , self . udp_dport ,
 len ( packet ) , self . outer_tos , self . outer_ttl )
   if 20 - 20: I11i % ooOoO0o . OOooOOo / I1Ii111
   if 50 - 50: oO0o + i11iIiiIii / i11iIiiIii + ooOoO0o + I1Ii111
   if 65 - 65: ooOoO0o * O0 * iII111i
   if 60 - 60: iIii1I11I1II1 . ooOoO0o + I1IiiI % oO0o
   if 4 - 4: I1IiiI / II111iiii % O0 * ooOoO0o / II111iiii . Oo0Ooo
  if ( self . lisp_header . k_bits != 0 ) :
   iiIiii = "\n"
   if ( self . packet_error != "" ) :
    iiIiii = " ({})" . format ( self . packet_error ) + iiIiii
    if 3 - 3: I11i / I1Ii111 * IiII - O0 + I1IiiI / IiII
   oO00o0 += ", encrypted" + iiIiii
   return ( oO00o0 )
   if 19 - 19: i1IIi % II111iiii
   if 85 - 85: IiII - o0oOOo0O0Ooo % OOooOOo - II111iiii
   if 56 - 56: Ii1I * i11iIiiIii
   if 92 - 92: II111iiii - O0 . I1Ii111
   if 59 - 59: OoOoOO00
  if ( self . outer_dest . is_null ( ) == False ) :
   packet = packet [ 36 : : ] if self . outer_version == 4 else packet [ 56 : : ]
   if 47 - 47: II111iiii - I1ii11iIi11i - Ii1I
   if 9 - 9: I1ii11iIi11i - IiII
  OoooooO0 = packet [ 9 : 10 ] if self . inner_version == 4 else packet [ 6 : 7 ]
  OoooooO0 = struct . unpack ( "B" , OoooooO0 ) [ 0 ]
  if 64 - 64: i1IIi
  oO00o0 += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
  oO00o0 = oO00o0 . format ( O0Oo , O0oOo00Oo0oo0 , len ( packet ) , self . inner_tos ,
 self . inner_ttl , OoooooO0 )
  if 71 - 71: IiII * o0oOOo0O0Ooo
  if 99 - 99: o0oOOo0O0Ooo
  if 28 - 28: OoooooooOO % O0 - OOooOOo / o0oOOo0O0Ooo / I1IiiI
  if 41 - 41: II111iiii * IiII / OoO0O00 . oO0o
  if ( OoooooO0 in [ 6 , 17 ] ) :
   IiiiiI = packet [ 20 : 24 ] if self . inner_version == 4 else packet [ 40 : 44 ]
   if ( len ( IiiiiI ) == 4 ) :
    IiiiiI = socket . ntohl ( struct . unpack ( "I" , IiiiiI ) [ 0 ] )
    oO00o0 += ", ports {} -> {}" . format ( IiiiiI >> 16 , IiiiiI & 0xffff )
    if 12 - 12: i11iIiiIii . I11i * OOooOOo % i1IIi . ooOoO0o
  elif ( OoooooO0 == 1 ) :
   O0oooo000o = packet [ 26 : 28 ] if self . inner_version == 4 else packet [ 46 : 48 ]
   if ( len ( O0oooo000o ) == 2 ) :
    O0oooo000o = socket . ntohs ( struct . unpack ( "H" , O0oooo000o ) [ 0 ] )
    oO00o0 += ", icmp-seq {}" . format ( O0oooo000o )
    if 42 - 42: OoO0O00 % oO0o / Oo0Ooo / IiII
    if 86 - 86: I1Ii111 + II111iiii + OoooooooOO + Ii1I
  if ( self . packet_error != "" ) :
   oO00o0 += " ({})" . format ( self . packet_error )
   if 84 - 84: i1IIi - II111iiii . OoooooooOO / OoOoOO00 % Ii1I
  oO00o0 += "\n"
  return ( oO00o0 )
  if 7 - 7: i1IIi / IiII / iII111i
  if 97 - 97: OoO0O00 + iIii1I11I1II1
 def is_trace ( self ) :
  IiiiiI = [ self . inner_sport , self . inner_dport ]
  return ( self . inner_protocol == LISP_UDP_PROTOCOL and
 LISP_TRACE_PORT in IiiiiI )
  if 79 - 79: ooOoO0o + oO0o - II111iiii . Oo0Ooo
  if 26 - 26: IiII
  if 52 - 52: O0 + ooOoO0o
  if 11 - 11: i1IIi / I1Ii111 * I1ii11iIi11i * I1Ii111 * ooOoO0o - i11iIiiIii
  if 96 - 96: I1ii11iIi11i % I1ii11iIi11i
  if 1 - 1: I1IiiI . Ii1I
  if 26 - 26: oO0o - ooOoO0o % Oo0Ooo - oO0o + IiII
  if 33 - 33: Ii1I + OoOoOO00 - I1ii11iIi11i + iIii1I11I1II1 % i1IIi * IiII
  if 21 - 21: O0 * ooOoO0o % OoO0O00
  if 14 - 14: O0 / I1Ii111 / ooOoO0o + IiII - IiII
  if 10 - 10: O0 - I1ii11iIi11i / I1Ii111 % OoOoOO00 / OoooooooOO / Ii1I
  if 73 - 73: ooOoO0o + IiII % o0oOOo0O0Ooo . I1ii11iIi11i / OOooOOo . I1Ii111
  if 76 - 76: I11i . I1ii11iIi11i * OoooooooOO % iII111i
  if 24 - 24: OoooooooOO
  if 83 - 83: O0 / OoO0O00
  if 62 - 62: I11i
LISP_N_BIT = 0x80000000
LISP_L_BIT = 0x40000000
LISP_E_BIT = 0x20000000
LISP_V_BIT = 0x10000000
LISP_I_BIT = 0x08000000
LISP_P_BIT = 0x04000000
LISP_K_BITS = 0x03000000
if 73 - 73: Ii1I % OoO0O00 * OOooOOo
class lisp_data_header ( object ) :
 def __init__ ( self ) :
  self . first_long = 0
  self . second_long = 0
  self . k_bits = 0
  if 84 - 84: Oo0Ooo
  if 18 - 18: OoooooooOO
 def print_header ( self , e_or_d ) :
  ooo = lisp_hex_string ( self . first_long & 0xffffff )
  ii111I1I1I = lisp_hex_string ( self . second_long ) . zfill ( 8 )
  if 34 - 34: I1ii11iIi11i % i1IIi - OoO0O00
  o0 = ( "{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + "iid/lsb: {}" )
  if 18 - 18: I1IiiI + I1Ii111 - iII111i % II111iiii / OoOoOO00 % O0
  return ( o0 . format ( bold ( e_or_d , False ) ,
 "N" if ( self . first_long & LISP_N_BIT ) else "n" ,
 "L" if ( self . first_long & LISP_L_BIT ) else "l" ,
 "E" if ( self . first_long & LISP_E_BIT ) else "e" ,
 "V" if ( self . first_long & LISP_V_BIT ) else "v" ,
 "I" if ( self . first_long & LISP_I_BIT ) else "i" ,
 "P" if ( self . first_long & LISP_P_BIT ) else "p" ,
 "K" if ( self . k_bits in [ 2 , 3 ] ) else "k" ,
 "K" if ( self . k_bits in [ 1 , 3 ] ) else "k" ,
 ooo , ii111I1I1I ) )
  if 59 - 59: O0 . o0oOOo0O0Ooo % I1ii11iIi11i * oO0o + I11i
  if 82 - 82: OoooooooOO
 def encode ( self ) :
  Oo0O = "II"
  ooo = socket . htonl ( self . first_long )
  ii111I1I1I = socket . htonl ( self . second_long )
  if 8 - 8: o0oOOo0O0Ooo . II111iiii . iII111i - i11iIiiIii
  I11 = struct . pack ( Oo0O , ooo , ii111I1I1I )
  return ( I11 )
  if 9 - 9: OoO0O00
  if 43 - 43: Ii1I . OOooOOo + I1IiiI * i11iIiiIii
 def decode ( self , packet ) :
  Oo0O = "II"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( False )
  if 20 - 20: Ii1I . Oo0Ooo - I11i % I11i - I1IiiI * OOooOOo
  ooo , ii111I1I1I = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  if 80 - 80: II111iiii / o0oOOo0O0Ooo . OOooOOo . o0oOOo0O0Ooo
  if 29 - 29: OoooooooOO % II111iiii % i11iIiiIii - Oo0Ooo
  self . first_long = socket . ntohl ( ooo )
  self . second_long = socket . ntohl ( ii111I1I1I )
  self . k_bits = ( self . first_long & LISP_K_BITS ) >> 24
  return ( True )
  if 5 - 5: I1ii11iIi11i . II111iiii . i1IIi
  if 35 - 35: o0oOOo0O0Ooo + OoO0O00 - I1ii11iIi11i
 def key_id ( self , key_id ) :
  self . first_long &= ~ ( 0x3 << 24 )
  self . first_long |= ( ( key_id & 0x3 ) << 24 )
  self . k_bits = key_id
  if 24 - 24: II111iiii
  if 23 - 23: Oo0Ooo - iII111i
 def nonce ( self , nonce ) :
  self . first_long |= LISP_N_BIT
  self . first_long |= nonce
  if 79 - 79: I11i . O0 - i1IIi
  if 42 - 42: oO0o - i11iIiiIii % oO0o - I1Ii111 * O0 / II111iiii
 def map_version ( self , version ) :
  self . first_long |= LISP_V_BIT
  self . first_long |= version
  if 5 - 5: Oo0Ooo
  if 84 - 84: I1ii11iIi11i
 def instance_id ( self , iid ) :
  if ( iid == 0 ) : return
  self . first_long |= LISP_I_BIT
  self . second_long &= 0xff
  self . second_long |= ( iid << 8 )
  if 53 - 53: oO0o
  if 26 - 26: I1Ii111 / I1Ii111 + Oo0Ooo - o0oOOo0O0Ooo % II111iiii . OoooooooOO
 def get_instance_id ( self ) :
  return ( ( self . second_long >> 8 ) & 0xffffff )
  if 7 - 7: II111iiii - I1ii11iIi11i / I11i % OoooooooOO + i1IIi
  if 42 - 42: I11i + i1IIi - Ii1I / IiII . iII111i
 def locator_status_bits ( self , lsbs ) :
  self . first_long |= LISP_L_BIT
  self . second_long &= 0xffffff00
  self . second_long |= ( lsbs & 0xff )
  if 30 - 30: Oo0Ooo + Ii1I % i11iIiiIii * i1IIi + I1IiiI % OOooOOo
  if 30 - 30: i11iIiiIii * Oo0Ooo . II111iiii + I1ii11iIi11i / o0oOOo0O0Ooo % I1Ii111
 def is_request_nonce ( self , nonce ) :
  return ( nonce & 0x80000000 )
  if 78 - 78: I1ii11iIi11i + OoooooooOO - I1IiiI * OoOoOO00 * iII111i
  if 7 - 7: OOooOOo . IiII . I1Ii111 / Ii1I / Oo0Ooo
 def request_nonce ( self , nonce ) :
  self . first_long |= LISP_E_BIT
  self . first_long |= LISP_N_BIT
  self . first_long |= ( nonce & 0xffffff )
  if 83 - 83: I11i / Oo0Ooo
  if 23 - 23: iIii1I11I1II1
 def is_e_bit_set ( self ) :
  return ( self . first_long & LISP_E_BIT )
  if 10 - 10: I11i - o0oOOo0O0Ooo % OoooooooOO - I1ii11iIi11i
  if 64 - 64: OoO0O00 / I1IiiI
 def get_nonce ( self ) :
  return ( self . first_long & 0xffffff )
  if 23 - 23: I11i * I1Ii111 * o0oOOo0O0Ooo - I1IiiI % OoOoOO00 + o0oOOo0O0Ooo
  if 41 - 41: IiII * OoooooooOO . ooOoO0o % i11iIiiIii
  if 11 - 11: iIii1I11I1II1 . I1Ii111 - Oo0Ooo / I11i + II111iiii
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
  if 29 - 29: I11i . i11iIiiIii + i1IIi - Ii1I + O0 . I1IiiI
  if 8 - 8: o0oOOo0O0Ooo
 def send_ipc ( self , ipc_socket , ipc ) :
  ooOO0O0O = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
  oOO00OoOo = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
  ipc = lisp_command_ipc ( ipc , ooOO0O0O )
  lisp_ipc ( ipc , ipc_socket , oOO00OoOo )
  if 18 - 18: oO0o * O0 - I1IiiI + O0 + I1Ii111
  if 70 - 70: o0oOOo0O0Ooo / I11i + oO0o % I1IiiI % Oo0Ooo + OoO0O00
 def send_request_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  ooo0ooo0Oo = "nonce%R%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , ooo0ooo0Oo )
  if 40 - 40: IiII . OoooooooOO . I1IiiI + O0 % i1IIi / IiII
  if 36 - 36: OoooooooOO - OoOoOO00 - OoO0O00 * I1Ii111 - oO0o
 def send_echo_ipc ( self , ipc_socket , nonce ) :
  nonce = lisp_hex_string ( nonce )
  ooo0ooo0Oo = "nonce%E%{}%{}" . format ( self . rloc_str , nonce )
  self . send_ipc ( ipc_socket , ooo0ooo0Oo )
  if 99 - 99: ooOoO0o / I1IiiI . Ii1I - Ii1I * I1IiiI
  if 24 - 24: I11i * OoO0O00 - oO0o / iIii1I11I1II1 - Oo0Ooo . OOooOOo
 def receive_request ( self , ipc_socket , nonce ) :
  I1IiiI11 = self . request_nonce_rcvd
  self . request_nonce_rcvd = nonce
  self . last_request_nonce_rcvd = lisp_get_timestamp ( )
  if ( lisp_i_am_rtr ) : return
  if ( I1IiiI11 != nonce ) : self . send_request_ipc ( ipc_socket , nonce )
  if 46 - 46: OoO0O00 % I1ii11iIi11i
  if 58 - 58: oO0o + IiII % iII111i - Ii1I - OOooOOo % Ii1I
 def receive_echo ( self , ipc_socket , nonce ) :
  if ( self . request_nonce_sent != nonce ) : return
  self . last_echo_nonce_rcvd = lisp_get_timestamp ( )
  if ( self . echo_nonce_rcvd == nonce ) : return
  if 86 - 86: o0oOOo0O0Ooo
  self . echo_nonce_rcvd = nonce
  if ( lisp_i_am_rtr ) : return
  self . send_echo_ipc ( ipc_socket , nonce )
  if 15 - 15: oO0o - iIii1I11I1II1 - II111iiii - IiII % I1ii11iIi11i
  if 80 - 80: IiII * iII111i . i1IIi % Ii1I % I1ii11iIi11i + ooOoO0o
 def get_request_or_echo_nonce ( self , ipc_socket , remote_rloc ) :
  if 6 - 6: I1ii11iIi11i . oO0o . OoO0O00 + IiII
  if 65 - 65: I1ii11iIi11i / ooOoO0o
  if 23 - 23: OOooOOo / OOooOOo * o0oOOo0O0Ooo * OOooOOo
  if 57 - 57: iII111i
  if 29 - 29: I1IiiI
  if ( self . request_nonce_sent and self . echo_nonce_sent and remote_rloc ) :
   I1IIi11I1IiIi = lisp_myrlocs [ 0 ] if remote_rloc . is_ipv4 ( ) else lisp_myrlocs [ 1 ]
   if 56 - 56: oO0o + i1IIi * iII111i - O0
   if 84 - 84: iII111i % I1IiiI / iIii1I11I1II1 * Ii1I * iIii1I11I1II1 + I1ii11iIi11i
   if ( remote_rloc . address > I1IIi11I1IiIi . address ) :
    I1II1I1I = "exit"
    self . request_nonce_sent = None
   else :
    I1II1I1I = "stay in"
    self . echo_nonce_sent = None
    if 78 - 78: IiII / iII111i * Ii1I . OOooOOo . oO0o - I1Ii111
    if 39 - 39: ooOoO0o . i1IIi + OoooooooOO . iII111i - i11iIiiIii % I1Ii111
   iiIi1iIiI = bold ( "collision" , False )
   OoOoo00Oo0OoO = red ( I1IIi11I1IiIi . print_address_no_iid ( ) , False )
   IIi1iii = red ( remote_rloc . print_address_no_iid ( ) , False )
   lprint ( "Echo nonce {}, {} -> {}, {} request-nonce mode" . format ( iiIi1iIiI ,
 OoOoo00Oo0OoO , IIi1iii , I1II1I1I ) )
   if 50 - 50: OoooooooOO / OoO0O00 % iIii1I11I1II1
   if 41 - 41: I1ii11iIi11i % I1ii11iIi11i + IiII . iII111i % I1Ii111 * ooOoO0o
   if 57 - 57: Ii1I . I1Ii111 . II111iiii % OoooooooOO * O0 + iIii1I11I1II1
   if 94 - 94: i1IIi * OoO0O00 * OoOoOO00
   if 93 - 93: ooOoO0o / OOooOOo * O0
  if ( self . echo_nonce_sent != None ) :
   o0oOoo00 = self . echo_nonce_sent
   oOO = bold ( "Echoing" , False )
   lprint ( "{} nonce 0x{} to {}" . format ( oOO ,
 lisp_hex_string ( o0oOoo00 ) , red ( self . rloc_str , False ) ) )
   self . last_echo_nonce_sent = lisp_get_timestamp ( )
   self . echo_nonce_sent = None
   return ( o0oOoo00 )
   if 17 - 17: OoO0O00 / ooOoO0o % I1IiiI
   if 47 - 47: Oo0Ooo * OoO0O00 / o0oOOo0O0Ooo * I1IiiI
   if 60 - 60: I1ii11iIi11i / IiII . i11iIiiIii / OoO0O00 % II111iiii
   if 6 - 6: iII111i % o0oOOo0O0Ooo + I1Ii111
   if 91 - 91: o0oOOo0O0Ooo + O0 * oO0o * IiII * I1ii11iIi11i
   if 83 - 83: OoooooooOO
   if 52 - 52: o0oOOo0O0Ooo / OoOoOO00 % oO0o % OoO0O00 / IiII % o0oOOo0O0Ooo
  o0oOoo00 = self . request_nonce_sent
  O0oo = self . last_request_nonce_sent
  if ( o0oOoo00 and O0oo != None ) :
   if ( time . time ( ) - O0oo >= LISP_NONCE_ECHO_INTERVAL ) :
    self . request_nonce_sent = None
    lprint ( "Stop request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o0oOoo00 ) ) )
    if 23 - 23: i11iIiiIii * I1ii11iIi11i % OoO0O00 % ooOoO0o % OoOoOO00
    return ( None )
    if 71 - 71: i1IIi * Ii1I + iIii1I11I1II1
    if 80 - 80: o0oOOo0O0Ooo . iII111i . OoooooooOO
    if 63 - 63: ooOoO0o . OOooOOo
    if 66 - 66: I1IiiI
    if 99 - 99: OoO0O00 % O0 . I1Ii111 - I1ii11iIi11i . Oo0Ooo / OoOoOO00
    if 60 - 60: I1ii11iIi11i
    if 78 - 78: oO0o + II111iiii
    if 55 - 55: OoooooooOO
    if 90 - 90: I1IiiI
  if ( o0oOoo00 == None ) :
   o0oOoo00 = lisp_get_data_nonce ( )
   if ( self . recently_requested ( ) ) : return ( o0oOoo00 )
   if 4 - 4: OOooOOo % ooOoO0o - OOooOOo - o0oOOo0O0Ooo
   self . request_nonce_sent = o0oOoo00
   lprint ( "Start request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o0oOoo00 ) ) )
   if 30 - 30: IiII
   self . last_new_request_nonce_sent = lisp_get_timestamp ( )
   if 34 - 34: oO0o - II111iiii - o0oOOo0O0Ooo + iII111i + I1Ii111
   if 70 - 70: OoooooooOO + OoO0O00 * Oo0Ooo
   if 20 - 20: i11iIiiIii - II111iiii - ooOoO0o % oO0o . ooOoO0o
   if 50 - 50: iIii1I11I1II1 + I1Ii111 - I11i - OoooooooOO
   if 84 - 84: OoOoOO00 - I11i
   if ( lisp_i_am_itr == False ) : return ( o0oOoo00 | 0x80000000 )
   self . send_request_ipc ( ipc_socket , o0oOoo00 )
  else :
   lprint ( "Continue request-nonce mode for {}, nonce 0x{}" . format ( red ( self . rloc_str , False ) , lisp_hex_string ( o0oOoo00 ) ) )
   if 80 - 80: i11iIiiIii % OOooOOo - Oo0Ooo % OOooOOo
   if 89 - 89: Ii1I * I11i + OoOoOO00 / i11iIiiIii
   if 68 - 68: OoooooooOO * I11i
   if 86 - 86: o0oOOo0O0Ooo / OoOoOO00
   if 40 - 40: iII111i
   if 62 - 62: ooOoO0o / OOooOOo
   if 74 - 74: iII111i % I1Ii111 / I1Ii111 - iIii1I11I1II1 - II111iiii + OOooOOo
  self . last_request_nonce_sent = lisp_get_timestamp ( )
  return ( o0oOoo00 | 0x80000000 )
  if 92 - 92: I11i % I1Ii111
  if 18 - 18: ooOoO0o + I1Ii111 / OOooOOo / oO0o + iIii1I11I1II1 % IiII
 def request_nonce_timeout ( self ) :
  if ( self . request_nonce_sent == None ) : return ( False )
  if ( self . request_nonce_sent == self . echo_nonce_rcvd ) : return ( False )
  if 94 - 94: I11i
  o0oOOOO0 = time . time ( ) - self . last_request_nonce_sent
  iI11IiiI1 = self . last_echo_nonce_rcvd
  return ( o0oOOOO0 >= LISP_NONCE_ECHO_INTERVAL and iI11IiiI1 == None )
  if 83 - 83: oO0o / iIii1I11I1II1
  if 68 - 68: I1Ii111 - OoOoOO00 . i11iIiiIii + o0oOOo0O0Ooo
 def recently_requested ( self ) :
  iI11IiiI1 = self . last_request_nonce_sent
  if ( iI11IiiI1 == None ) : return ( False )
  if 71 - 71: i11iIiiIii / i1IIi * I1IiiI / OoOoOO00
  o0oOOOO0 = time . time ( ) - iI11IiiI1
  return ( o0oOOOO0 <= LISP_NONCE_ECHO_INTERVAL )
  if 33 - 33: I11i . Oo0Ooo
  if 89 - 89: iII111i + i1IIi - IiII + ooOoO0o . II111iiii
 def recently_echoed ( self ) :
  if ( self . request_nonce_sent == None ) : return ( True )
  if 85 - 85: iIii1I11I1II1 - Ii1I * Oo0Ooo . oO0o + I1Ii111
  if 13 - 13: O0 + iIii1I11I1II1 % II111iiii + iIii1I11I1II1
  if 85 - 85: I1IiiI * iIii1I11I1II1 . iII111i / iII111i
  if 43 - 43: I1IiiI
  iI11IiiI1 = self . last_good_echo_nonce_rcvd
  if ( iI11IiiI1 == None ) : iI11IiiI1 = 0
  o0oOOOO0 = time . time ( ) - iI11IiiI1
  if ( o0oOOOO0 <= LISP_NONCE_ECHO_INTERVAL ) : return ( True )
  if 78 - 78: OoO0O00 % II111iiii + OoOoOO00 / I1IiiI
  if 34 - 34: o0oOOo0O0Ooo % I1ii11iIi11i + Ii1I * I11i / oO0o
  if 18 - 18: ooOoO0o
  if 92 - 92: OoO0O00 % iIii1I11I1II1 / IiII * iII111i . i1IIi + oO0o
  if 24 - 24: IiII . iII111i * IiII % i11iIiiIii . i11iIiiIii + i1IIi
  if 64 - 64: iIii1I11I1II1 / IiII / Oo0Ooo - I1ii11iIi11i
  iI11IiiI1 = self . last_new_request_nonce_sent
  if ( iI11IiiI1 == None ) : iI11IiiI1 = 0
  o0oOOOO0 = time . time ( ) - iI11IiiI1
  return ( o0oOOOO0 <= LISP_NONCE_ECHO_INTERVAL )
  if 100 - 100: IiII + i1IIi * OoO0O00
  if 64 - 64: oO0o * i11iIiiIii . Oo0Ooo
 def change_state ( self , rloc ) :
  if ( rloc . up_state ( ) and self . recently_echoed ( ) == False ) :
   OOo0OO00 = bold ( "down" , False )
   ii1i = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
   lprint ( "Take {} {}, last good echo: {}" . format ( red ( self . rloc_str , False ) , OOo0OO00 , ii1i ) )
   if 31 - 31: Oo0Ooo
   rloc . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   return
   if 1 - 1: i1IIi
   if 27 - 27: I11i
  if ( rloc . no_echoed_nonce_state ( ) == False ) : return
  if 47 - 47: OoooooooOO
  if ( self . recently_requested ( ) == False ) :
   II1o0OOO = bold ( "up" , False )
   lprint ( "Bring {} {}, retry request-nonce mode" . format ( red ( self . rloc_str , False ) , II1o0OOO ) )
   if 38 - 38: I1IiiI * o0oOOo0O0Ooo - OOooOOo % IiII + I11i - Oo0Ooo
   rloc . state = LISP_RLOC_UP_STATE
   rloc . last_state_change = lisp_get_timestamp ( )
   if 55 - 55: iIii1I11I1II1 + OoOoOO00
   if 7 - 7: Ii1I / I1Ii111 % ooOoO0o - I1Ii111 * I1IiiI
   if 18 - 18: oO0o - IiII % I11i * Ii1I
 def print_echo_nonce ( self ) :
  OoOooO0oO = lisp_print_elapsed ( self . last_request_nonce_sent )
  ooOOO00o = lisp_print_elapsed ( self . last_good_echo_nonce_rcvd )
  if 81 - 81: I1ii11iIi11i * II111iiii
  II1iI11Iiii = lisp_print_elapsed ( self . last_echo_nonce_sent )
  iIIIiI1iII1i = lisp_print_elapsed ( self . last_request_nonce_rcvd )
  OOo0oOO0o0oo0 = space ( 4 )
  if 15 - 15: O0 % Oo0Ooo % IiII % OoooooooOO - IiII
  i11IiIIi11I = "Nonce-Echoing:\n"
  i11IiIIi11I += ( "{}Last request-nonce sent: {}\n{}Last echo-nonce " + "received: {}\n" ) . format ( OOo0oOO0o0oo0 , OoOooO0oO , OOo0oOO0o0oo0 , ooOOO00o )
  if 27 - 27: I1Ii111 - o0oOOo0O0Ooo * I1ii11iIi11i - I1IiiI
  i11IiIIi11I += ( "{}Last request-nonce received: {}\n{}Last echo-nonce " + "sent: {}" ) . format ( OOo0oOO0o0oo0 , iIIIiI1iII1i , OOo0oOO0o0oo0 , II1iI11Iiii )
  if 22 - 22: Oo0Ooo % OoooooooOO - Oo0Ooo - iII111i . Ii1I
  if 100 - 100: II111iiii / I1Ii111 / iII111i - I1ii11iIi11i * iIii1I11I1II1
  return ( i11IiIIi11I )
  if 7 - 7: i1IIi . IiII % i11iIiiIii * I1ii11iIi11i . I11i % I1ii11iIi11i
  if 35 - 35: I1IiiI
  if 48 - 48: OoooooooOO % OoooooooOO - OoO0O00 . OoOoOO00
  if 22 - 22: ooOoO0o . i11iIiiIii . OoooooooOO . i1IIi
  if 12 - 12: OoOoOO00 % OOooOOo + oO0o . O0 % iIii1I11I1II1
  if 41 - 41: OoooooooOO
  if 13 - 13: I11i + I1Ii111 - I1Ii111 % oO0o / I11i
  if 4 - 4: I1IiiI + OOooOOo - IiII + iII111i
  if 78 - 78: Ii1I
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
    if 29 - 29: II111iiii
   self . local_private_key = random . randint ( 0 , 2 ** 128 - 1 )
   I1IIiiI1II = lisp_hex_string ( self . local_private_key ) . zfill ( 32 )
   self . curve25519 = curve25519 . Private ( I1IIiiI1II . encode ( ) )
  else :
   self . local_private_key = random . randint ( 0 , 0x1fff )
   if 79 - 79: iIii1I11I1II1 - i11iIiiIii + ooOoO0o - II111iiii . iIii1I11I1II1
  self . local_public_key = self . compute_public_key ( )
  self . remote_public_key = None
  self . shared_key = None
  self . encrypt_key = None
  self . icv_key = None
  self . icv = poly1305 if do_poly else hashlib . sha256
  self . iv = None
  self . get_iv ( )
  self . do_poly = do_poly
  if 84 - 84: Oo0Ooo % I11i * O0 * I11i
  if 66 - 66: OOooOOo / iIii1I11I1II1 - OoOoOO00 % O0 . ooOoO0o
 def copy_keypair ( self , key ) :
  self . local_private_key = key . local_private_key
  self . local_public_key = key . local_public_key
  self . curve25519 = key . curve25519
  if 12 - 12: Oo0Ooo + I1IiiI
  if 37 - 37: i1IIi * i11iIiiIii
 def get_iv ( self ) :
  if ( self . iv == None ) :
   self . iv = random . randint ( 0 , LISP_16_128_MASK )
  else :
   self . iv += 1
   if 95 - 95: i11iIiiIii % I1Ii111 * Oo0Ooo + i1IIi . O0 + I1ii11iIi11i
  Oo0OOOO0oOoo0 = self . iv
  if ( self . cipher_suite == LISP_CS_25519_CHACHA ) :
   Oo0OOOO0oOoo0 = struct . pack ( "Q" , Oo0OOOO0oOoo0 & LISP_8_64_MASK )
  elif ( self . cipher_suite == LISP_CS_25519_GCM ) :
   II1iiiiI1Ii11 = struct . pack ( "I" , ( Oo0OOOO0oOoo0 >> 64 ) & LISP_4_32_MASK )
   O0ooIII1II1iiI11 = struct . pack ( "Q" , Oo0OOOO0oOoo0 & LISP_8_64_MASK )
   Oo0OOOO0oOoo0 = II1iiiiI1Ii11 + O0ooIII1II1iiI11
  else :
   Oo0OOOO0oOoo0 = struct . pack ( "QQ" , Oo0OOOO0oOoo0 >> 64 , Oo0OOOO0oOoo0 & LISP_8_64_MASK )
  return ( Oo0OOOO0oOoo0 )
  if 38 - 38: i1IIi / iIii1I11I1II1 + iII111i
  if 26 - 26: I1ii11iIi11i . Ii1I % o0oOOo0O0Ooo
 def key_length ( self , key ) :
  if ( isinstance ( key , int ) ) : key = self . normalize_pub_key ( key )
  return ( old_div ( len ( key ) , 2 ) )
  if 4 - 4: I1Ii111
  if 80 - 80: Oo0Ooo . O0 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 def print_key ( self , key ) :
  o00o = self . normalize_pub_key ( key )
  OOoo000Ooo = o00o [ 0 : 4 ] . decode ( )
  iiii1II = o00o [ - 4 : : ] . decode ( )
  return ( "0x{}...{}({})" . format ( OOoo000Ooo , iiii1II , self . key_length ( o00o ) ) )
  if 28 - 28: OoooooooOO % I11i
  if 3 - 3: o0oOOo0O0Ooo / Oo0Ooo - OoO0O00 + II111iiii
 def normalize_pub_key ( self , key ) :
  if ( isinstance ( key , int ) ) :
   key = lisp_hex_string ( key ) . zfill ( 256 )
   return ( key )
   if 3 - 3: i11iIiiIii
  if ( self . curve25519 ) : return ( binascii . hexlify ( key ) )
  return ( key )
  if 20 - 20: i1IIi * iII111i + OoO0O00 * OoO0O00 / Oo0Ooo
  if 83 - 83: I1ii11iIi11i
 def print_keys ( self , do_bold = True ) :
  OoOoo00Oo0OoO = bold ( "local-key: " , False ) if do_bold else "local-key: "
  if ( self . local_public_key == None ) :
   OoOoo00Oo0OoO += "none"
  else :
   OoOoo00Oo0OoO += self . print_key ( self . local_public_key )
   if 53 - 53: OoOoOO00 % ooOoO0o . OoO0O00 + I1IiiI / I1ii11iIi11i
  IIi1iii = bold ( "remote-key: " , False ) if do_bold else "remote-key: "
  if ( self . remote_public_key == None ) :
   IIi1iii += "none"
  else :
   IIi1iii += self . print_key ( self . remote_public_key )
   if 76 - 76: I1ii11iIi11i . iIii1I11I1II1 - i11iIiiIii / I1ii11iIi11i - o0oOOo0O0Ooo
  o00Oooo0o0 = "ECDH" if ( self . curve25519 ) else "DH"
  I1i111II = self . cipher_suite
  return ( "{} cipher-suite: {}, {}, {}" . format ( o00Oooo0o0 , I1i111II , OoOoo00Oo0OoO , IIi1iii ) )
  if 99 - 99: OoooooooOO - OOooOOo - Oo0Ooo % I1ii11iIi11i
  if 30 - 30: O0 + II111iiii / i11iIiiIii
 def compare_keys ( self , keys ) :
  if ( self . dh_g_value != keys . dh_g_value ) : return ( False )
  if ( self . dh_p_value != keys . dh_p_value ) : return ( False )
  if ( self . remote_public_key != keys . remote_public_key ) : return ( False )
  return ( True )
  if 48 - 48: OoooooooOO / I1IiiI
  if 19 - 19: OOooOOo * I1ii11iIi11i - ooOoO0o * i11iIiiIii + I11i
 def compute_public_key ( self ) :
  if ( self . curve25519 ) : return ( self . curve25519 . get_public ( ) . public )
  if 92 - 92: OoO0O00
  I1IIiiI1II = self . local_private_key
  II11iIIii = self . dh_g_value
  I1i1I = self . dh_p_value
  return ( int ( ( II11iIIii ** I1IIiiI1II ) % I1i1I ) )
  if 99 - 99: OoOoOO00 . iII111i - OoooooooOO - O0
  if 6 - 6: OOooOOo
 def compute_shared_key ( self , ed , print_shared = False ) :
  I1IIiiI1II = self . local_private_key
  Ii1111i11 = self . remote_public_key
  if 58 - 58: Ii1I * iIii1I11I1II1 + ooOoO0o . ooOoO0o
  O00O00000 = bold ( "Compute {} shared-key" . format ( ed ) , False )
  lprint ( "{}, key-material: {}" . format ( O00O00000 , self . print_keys ( ) ) )
  if 31 - 31: Ii1I
  if ( self . curve25519 ) :
   II1III = curve25519 . Public ( Ii1111i11 )
   self . shared_key = self . curve25519 . get_shared_key ( II1III )
  else :
   I1i1I = self . dh_p_value
   self . shared_key = ( Ii1111i11 ** I1IIiiI1II ) % I1i1I
   if 44 - 44: OoooooooOO
   if 82 - 82: OoOoOO00 . OoOoOO00
   if 10 - 10: Oo0Ooo * I1ii11iIi11i . oO0o . OoooooooOO . OOooOOo * I1ii11iIi11i
   if 80 - 80: I1Ii111 + I11i . I1Ii111 + OOooOOo
   if 85 - 85: i11iIiiIii . I11i + Ii1I / Ii1I
   if 43 - 43: IiII . OoooooooOO - II111iiii
   if 90 - 90: I1IiiI - iIii1I11I1II1 + I1ii11iIi11i * OOooOOo * oO0o
  if ( print_shared ) :
   o00o = self . print_key ( self . shared_key )
   lprint ( "Computed shared-key: {}" . format ( o00o ) )
   if 19 - 19: I1Ii111 * II111iiii % Oo0Ooo - i1IIi
   if 27 - 27: OoOoOO00 . O0 / I1ii11iIi11i . iIii1I11I1II1
   if 15 - 15: Ii1I + OoO0O00 % iIii1I11I1II1 - I1ii11iIi11i - i1IIi % o0oOOo0O0Ooo
   if 54 - 54: IiII - II111iiii . ooOoO0o + Ii1I
   if 45 - 45: oO0o + II111iiii . iII111i / I1ii11iIi11i
  self . compute_encrypt_icv_keys ( )
  if 76 - 76: Ii1I + iII111i - IiII * iIii1I11I1II1 % i1IIi
  if 72 - 72: ooOoO0o + II111iiii . O0 - iII111i / OoooooooOO . I1Ii111
  if 28 - 28: iIii1I11I1II1 . O0
  if 32 - 32: OoooooooOO
  self . rekey_count += 1
  self . last_rekey = lisp_get_timestamp ( )
  if 29 - 29: I1ii11iIi11i
  if 41 - 41: Ii1I
 def compute_encrypt_icv_keys ( self ) :
  I1iiI1II11 = hashlib . sha256
  if ( self . curve25519 ) :
   ooooO000O0OOO0o0O = self . shared_key
  else :
   ooooO000O0OOO0o0O = lisp_hex_string ( self . shared_key )
   if 62 - 62: Oo0Ooo * IiII / O0
   if 35 - 35: OOooOOo / iIii1I11I1II1
   if 62 - 62: O0 % OoOoOO00 % OOooOOo + OOooOOo + Oo0Ooo
   if 8 - 8: OOooOOo
   if 7 - 7: Ii1I - i1IIi % OoO0O00 / iIii1I11I1II1 % o0oOOo0O0Ooo
  OoOoo00Oo0OoO = self . local_public_key
  if ( type ( OoOoo00Oo0OoO ) != int ) : OoOoo00Oo0OoO = int ( binascii . hexlify ( OoOoo00Oo0OoO ) , 16 )
  IIi1iii = self . remote_public_key
  if ( type ( IIi1iii ) != int ) : IIi1iii = int ( binascii . hexlify ( IIi1iii ) , 16 )
  iI = "0001" + "lisp-crypto" + lisp_hex_string ( OoOoo00Oo0OoO ^ IIi1iii ) + "0100"
  if 5 - 5: I1IiiI - o0oOOo0O0Ooo . OoooooooOO - II111iiii
  i11IIIi1ii1i = hmac . new ( iI . encode ( ) , ooooO000O0OOO0o0O , I1iiI1II11 ) . hexdigest ( )
  i11IIIi1ii1i = int ( i11IIIi1ii1i , 16 )
  if 43 - 43: I1IiiI % I1ii11iIi11i * Ii1I
  if 31 - 31: Ii1I / iII111i
  if 3 - 3: IiII
  if 37 - 37: Ii1I * OoooooooOO * I11i + Oo0Ooo . I1IiiI
  o0ooo0 = ( i11IIIi1ii1i >> 128 ) & LISP_16_128_MASK
  o0OO0OOoo0oO = i11IIIi1ii1i & LISP_16_128_MASK
  o0ooo0 = lisp_hex_string ( o0ooo0 ) . zfill ( 32 )
  self . encrypt_key = o0ooo0 . encode ( )
  OOOOo00oOOO00 = 32 if self . do_poly else 40
  o0OO0OOoo0oO = lisp_hex_string ( o0OO0OOoo0oO ) . zfill ( OOOOo00oOOO00 )
  self . icv_key = o0OO0OOoo0oO . encode ( )
  if 13 - 13: I1ii11iIi11i / OoO0O00 * i11iIiiIii % OoO0O00 % OoO0O00 * II111iiii
  if 17 - 17: I11i . O0 * i1IIi - OoOoOO00 % i1IIi
 def do_icv ( self , packet , nonce ) :
  if ( self . icv_key == None ) : return ( "" )
  if ( self . do_poly ) :
   I1iI1I = self . icv . poly1305aes
   iiiI1I1I = self . icv . binascii . hexlify
   nonce = iiiI1I1I ( nonce )
   O0iIIii1 = I1iI1I ( self . encrypt_key , self . icv_key , nonce , packet )
   if ( lisp_is_python2 ( ) ) :
    O0iIIii1 = iiiI1I1I ( O0iIIii1 . encode ( "raw_unicode_escape" ) )
   else :
    O0iIIii1 = iiiI1I1I ( O0iIIii1 ) . decode ( )
    if 12 - 12: I11i . Ii1I + I11i - OOooOOo * iII111i - O0
  else :
   I1IIiiI1II = binascii . unhexlify ( self . icv_key )
   O0iIIii1 = hmac . new ( I1IIiiI1II , packet , self . icv ) . hexdigest ( )
   O0iIIii1 = O0iIIii1 [ 0 : 40 ]
   if 44 - 44: i1IIi % oO0o / OoOoOO00 % IiII . I1ii11iIi11i
  return ( O0iIIii1 )
  if 38 - 38: OoOoOO00 . I11i
  if 66 - 66: iII111i
 def add_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) :
   lisp_crypto_keys_by_nonce [ nonce ] = [ None , None , None , None ]
   if 61 - 61: i11iIiiIii / oO0o / i11iIiiIii
  lisp_crypto_keys_by_nonce [ nonce ] [ self . key_id ] = self
  if 61 - 61: I11i / iIii1I11I1II1 - i1IIi - IiII * i11iIiiIii
  if 86 - 86: I11i % I11i - OoOoOO00 + I1Ii111 / I1IiiI * OoooooooOO
 def delete_key_by_nonce ( self , nonce ) :
  if ( nonce not in lisp_crypto_keys_by_nonce ) : return
  lisp_crypto_keys_by_nonce . pop ( nonce )
  if 26 - 26: II111iiii * iII111i + o0oOOo0O0Ooo / O0 + i1IIi - I11i
  if 56 - 56: OOooOOo
 def add_key_by_rloc ( self , addr_str , encap ) :
  OoOoOOO000 = lisp_crypto_keys_by_rloc_encap if encap else lisp_crypto_keys_by_rloc_decap
  if 57 - 57: o0oOOo0O0Ooo - IiII . OOooOOo
  if 7 - 7: I1ii11iIi11i / OoOoOO00 . OoO0O00 / Oo0Ooo . O0 . I11i
  if ( addr_str not in OoOoOOO000 ) :
   OoOoOOO000 [ addr_str ] = [ None , None , None , None ]
   if 60 - 60: II111iiii + I1Ii111 / oO0o % OoooooooOO - i1IIi
  OoOoOOO000 [ addr_str ] [ self . key_id ] = self
  if 57 - 57: ooOoO0o
  if 99 - 99: Oo0Ooo + I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
  if 52 - 52: I1ii11iIi11i
  if 93 - 93: iII111i . i11iIiiIii
  if 24 - 24: OOooOOo . OoO0O00 + I1Ii111 . oO0o - I1ii11iIi11i % iII111i
  if ( encap == False ) :
   lisp_write_ipc_decap_key ( addr_str , OoOoOOO000 [ addr_str ] )
   if 49 - 49: O0 . Oo0Ooo / Ii1I
   if 29 - 29: I1ii11iIi11i / oO0o * O0 - i11iIiiIii - OoO0O00 + Ii1I
   if 86 - 86: I1IiiI / I1ii11iIi11i * Ii1I % i11iIiiIii
 def encode_lcaf ( self , rloc_addr ) :
  I1i111IIiI11IiiI1i = self . normalize_pub_key ( self . local_public_key )
  i1ii1IiI1I1I = self . key_length ( I1i111IIiI11IiiI1i )
  o0OOooOOOoO = ( 6 + i1ii1IiI1I1I + 2 )
  if ( rloc_addr != None ) : o0OOooOOOoO += rloc_addr . addr_length ( )
  if 79 - 79: I1ii11iIi11i - oO0o - o0oOOo0O0Ooo . OOooOOo
  Oo00O0o0O = struct . pack ( "HBBBBHBB" , socket . htons ( LISP_AFI_LCAF ) , 0 , 0 ,
 LISP_LCAF_SECURITY_TYPE , 0 , socket . htons ( o0OOooOOOoO ) , 1 , 0 )
  if 65 - 65: i11iIiiIii . OoO0O00 % iII111i + IiII - i11iIiiIii
  if 60 - 60: I1Ii111
  if 14 - 14: Oo0Ooo % oO0o * iII111i - i11iIiiIii / I1ii11iIi11i * i11iIiiIii
  if 95 - 95: iIii1I11I1II1 + OoOoOO00 . I1IiiI + OoOoOO00 * I11i + OOooOOo
  if 14 - 14: Ii1I - O0
  if 68 - 68: II111iiii - I1ii11iIi11i - OoO0O00 * iIii1I11I1II1 / I1IiiI * I1ii11iIi11i
  I1i111II = self . cipher_suite
  Oo00O0o0O += struct . pack ( "BBH" , I1i111II , 0 , socket . htons ( i1ii1IiI1I1I ) )
  if 45 - 45: I1Ii111 * I11i / iIii1I11I1II1 / I1IiiI % II111iiii
  if 49 - 49: Ii1I / iII111i . iII111i . iII111i + i11iIiiIii % I11i
  if 7 - 7: IiII * ooOoO0o + OoOoOO00
  if 22 - 22: iII111i
  for o000o0O0Oo00 in range ( 0 , i1ii1IiI1I1I * 2 , 16 ) :
   I1IIiiI1II = int ( I1i111IIiI11IiiI1i [ o000o0O0Oo00 : o000o0O0Oo00 + 16 ] , 16 )
   Oo00O0o0O += struct . pack ( "Q" , byte_swap_64 ( I1IIiiI1II ) )
   if 48 - 48: I1ii11iIi11i . I1IiiI
   if 73 - 73: O0 . I1Ii111 - OoooooooOO % I11i % i1IIi
   if 14 - 14: I1Ii111 + Ii1I * Oo0Ooo
   if 49 - 49: Oo0Ooo
   if 57 - 57: O0 * ooOoO0o - iII111i - iIii1I11I1II1 * iII111i
  if ( rloc_addr ) :
   Oo00O0o0O += struct . pack ( "H" , socket . htons ( rloc_addr . afi ) )
   Oo00O0o0O += rloc_addr . pack_address ( )
   if 9 - 9: IiII . I11i
  return ( Oo00O0o0O )
  if 23 - 23: O0 % OoooooooOO - O0 . I1IiiI + i11iIiiIii
  if 96 - 96: ooOoO0o % O0
 def decode_lcaf ( self , packet , lcaf_len ) :
  if 51 - 51: I1IiiI - iII111i / I1ii11iIi11i . I1ii11iIi11i + I1ii11iIi11i
  if 87 - 87: II111iiii . Ii1I * OoO0O00
  if 74 - 74: o0oOOo0O0Ooo % OoOoOO00 . iII111i % I1Ii111 . O0 % II111iiii
  if 5 - 5: oO0o - OoooooooOO / OoOoOO00
  if ( lcaf_len == 0 ) :
   Oo0O = "HHBBH"
   ii1ii11Ii = struct . calcsize ( Oo0O )
   if ( len ( packet ) < ii1ii11Ii ) : return ( None )
   if 30 - 30: I11i % o0oOOo0O0Ooo + i1IIi * OoooooooOO * OoO0O00 - II111iiii
   Oo0ooooO0o00 , ooO0000 , Ooo00O0OooOOO , ooO0000 , lcaf_len = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
   if 28 - 28: Oo0Ooo
   if 62 - 62: Oo0Ooo + OoooooooOO / iII111i
   if ( Ooo00O0OooOOO != LISP_LCAF_SECURITY_TYPE ) :
    packet = packet [ lcaf_len + 6 : : ]
    return ( packet )
    if 60 - 60: Ii1I / OoOoOO00 . I11i % OOooOOo
   lcaf_len = socket . ntohs ( lcaf_len )
   packet = packet [ ii1ii11Ii : : ]
   if 61 - 61: O0 . Ii1I . O0 * i11iIiiIii * II111iiii / I1Ii111
   if 69 - 69: I11i
   if 17 - 17: I11i
   if 38 - 38: I1Ii111 % OOooOOo
   if 9 - 9: O0 . iIii1I11I1II1
   if 44 - 44: I1ii11iIi11i % IiII
  Ooo00O0OooOOO = LISP_LCAF_SECURITY_TYPE
  Oo0O = "BBBBH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 6 - 6: OoO0O00
  OoI11I , ooO0000 , I1i111II , ooO0000 , i1ii1IiI1I1I = struct . unpack ( Oo0O ,
 packet [ : ii1ii11Ii ] )
  if 69 - 69: oO0o - i11iIiiIii
  if 29 - 29: Ii1I + iII111i % I1ii11iIi11i + I11i * Oo0Ooo - i11iIiiIii
  if 24 - 24: i11iIiiIii . ooOoO0o + ooOoO0o - i11iIiiIii % OOooOOo
  if 58 - 58: I1IiiI
  if 94 - 94: o0oOOo0O0Ooo + Ii1I % o0oOOo0O0Ooo . I1Ii111 - ooOoO0o * I1IiiI
  if 62 - 62: Oo0Ooo * i1IIi % I1ii11iIi11i + Oo0Ooo . O0 . ooOoO0o
  packet = packet [ ii1ii11Ii : : ]
  i1ii1IiI1I1I = socket . ntohs ( i1ii1IiI1I1I )
  if ( len ( packet ) < i1ii1IiI1I1I ) : return ( None )
  if 57 - 57: Oo0Ooo - I1Ii111 + O0 % o0oOOo0O0Ooo
  if 72 - 72: OOooOOo . OoOoOO00 / II111iiii
  if 69 - 69: OOooOOo * II111iiii - ooOoO0o - i1IIi + i11iIiiIii
  if 50 - 50: OoooooooOO * i1IIi / oO0o
  oOo0 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM , LISP_CS_25519_CHACHA ,
 LISP_CS_1024 ]
  if ( I1i111II not in oOo0 ) :
   lprint ( "Cipher-suites {} supported, received {}" . format ( oOo0 ,
 I1i111II ) )
   packet = packet [ i1ii1IiI1I1I : : ]
   return ( packet )
   if 19 - 19: o0oOOo0O0Ooo
   if 19 - 19: OoooooooOO
  self . cipher_suite = I1i111II
  if 95 - 95: Ii1I . IiII / I11i . i11iIiiIii . IiII
  if 43 - 43: i11iIiiIii + o0oOOo0O0Ooo % o0oOOo0O0Ooo * OoooooooOO / I1Ii111
  if 9 - 9: iIii1I11I1II1 / II111iiii * OOooOOo
  if 96 - 96: Ii1I + I1ii11iIi11i * OoOoOO00 * IiII * I1ii11iIi11i . I1ii11iIi11i
  if 43 - 43: ooOoO0o . i1IIi
  I1i111IIiI11IiiI1i = 0
  for o000o0O0Oo00 in range ( 0 , i1ii1IiI1I1I , 8 ) :
   I1IIiiI1II = byte_swap_64 ( struct . unpack ( "Q" , packet [ o000o0O0Oo00 : o000o0O0Oo00 + 8 ] ) [ 0 ] )
   I1i111IIiI11IiiI1i <<= 64
   I1i111IIiI11IiiI1i |= I1IIiiI1II
   if 68 - 68: IiII % Oo0Ooo . O0 - OoOoOO00 + I1ii11iIi11i . i11iIiiIii
  self . remote_public_key = I1i111IIiI11IiiI1i
  if 45 - 45: I1IiiI
  if 17 - 17: OoooooooOO - ooOoO0o + Ii1I . OoooooooOO % Oo0Ooo
  if 92 - 92: I1Ii111 - OOooOOo % OoO0O00 - o0oOOo0O0Ooo % i1IIi
  if 38 - 38: I1ii11iIi11i . I11i / OoOoOO00 % I11i
  if 10 - 10: O0 . I1IiiI * o0oOOo0O0Ooo / iII111i
  if ( self . curve25519 ) :
   I1IIiiI1II = lisp_hex_string ( self . remote_public_key )
   I1IIiiI1II = I1IIiiI1II . zfill ( 64 )
   oO0OO00o = b""
   for o000o0O0Oo00 in range ( 0 , len ( I1IIiiI1II ) , 2 ) :
    oooooOOOO0oOo = int ( I1IIiiI1II [ o000o0O0Oo00 : o000o0O0Oo00 + 2 ] , 16 )
    oO0OO00o += lisp_store_byte ( oooooOOOO0oOo )
    if 26 - 26: II111iiii + i1IIi
   self . remote_public_key = oO0OO00o
   if 14 - 14: iIii1I11I1II1 - ooOoO0o + oO0o + i11iIiiIii / iIii1I11I1II1
   if 63 - 63: i11iIiiIii
  packet = packet [ i1ii1IiI1I1I : : ]
  return ( packet )
  if 21 - 21: I1Ii111
  if 70 - 70: I11i . OoOoOO00
  if 86 - 86: IiII
  if 25 - 25: Ii1I . O0 . i11iIiiIii + OoooooooOO / OOooOOo
  if 83 - 83: i1IIi % OoOoOO00 % Oo0Ooo
  if 91 - 91: o0oOOo0O0Ooo
  if 14 - 14: i11iIiiIii
  if 17 - 17: IiII + I11i % Oo0Ooo + oO0o
  if 87 - 87: I11i
def lisp_store_byte_py2 ( byte ) :
 return ( chr ( byte ) )
 if 54 - 54: Ii1I
def lisp_store_byte_py3 ( byte ) :
 return ( bytes ( [ byte ] ) )
 if 27 - 27: iII111i % Oo0Ooo . I1ii11iIi11i . i1IIi % OoOoOO00 . o0oOOo0O0Ooo
 if 37 - 37: iII111i + I1Ii111 * Ii1I + IiII
lisp_store_byte = lisp_store_byte_py2
if ( lisp_is_python3 ( ) ) : lisp_store_byte = lisp_store_byte_py3
if 39 - 39: O0 * Oo0Ooo - I1IiiI + Ii1I / II111iiii
if 66 - 66: ooOoO0o + oO0o % OoooooooOO
if 23 - 23: oO0o . OoOoOO00 + iIii1I11I1II1
if 17 - 17: IiII
if 12 - 12: i1IIi . OoO0O00
if 14 - 14: OOooOOo + II111iiii % OOooOOo . oO0o * ooOoO0o
class lisp_thread ( object ) :
 def __init__ ( self , name ) :
  self . thread_name = name
  self . thread_number = - 1
  self . number_of_pcap_threads = 0
  self . number_of_worker_threads = 0
  self . input_queue = queue . Queue ( )
  self . input_stats = lisp_stats ( )
  self . lisp_packet = lisp_packet ( None )
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
  if 90 - 90: Ii1I * iII111i / OOooOOo
  if 68 - 68: OoOoOO00
 def decode ( self , packet ) :
  Oo0O = "BBBBQ"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( False )
  if 65 - 65: oO0o
  o000oOOO , iIi1 , o0000o0OOOo , self . record_count , self . nonce = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  if 3 - 3: IiII
  if 18 - 18: I1IiiI
  self . type = o000oOOO >> 4
  if ( self . type == LISP_MAP_REQUEST ) :
   self . smr_bit = True if ( o000oOOO & 0x01 ) else False
   self . rloc_probe = True if ( o000oOOO & 0x02 ) else False
   self . smr_invoked_bit = True if ( iIi1 & 0x40 ) else False
   if 32 - 32: iIii1I11I1II1 * I1IiiI . OOooOOo * iIii1I11I1II1
  if ( self . type == LISP_ECM ) :
   self . ddt_bit = True if ( o000oOOO & 0x04 ) else False
   self . to_etr = True if ( o000oOOO & 0x02 ) else False
   self . to_ms = True if ( o000oOOO & 0x01 ) else False
   if 92 - 92: oO0o - ooOoO0o . OoooooooOO * oO0o / Oo0Ooo
  if ( self . type == LISP_NAT_INFO ) :
   self . info_reply = True if ( o000oOOO & 0x08 ) else False
   if 16 - 16: I11i / OoooooooOO - IiII % I1IiiI % I11i
  return ( True )
  if 97 - 97: OOooOOo * i1IIi / OoooooooOO
  if 64 - 64: OOooOOo + o0oOOo0O0Ooo / i11iIiiIii - OoOoOO00 + OOooOOo
 def is_info_request ( self ) :
  return ( ( self . type == LISP_NAT_INFO and self . is_info_reply ( ) == False ) )
  if 90 - 90: i1IIi % OoO0O00 / ooOoO0o - O0 + i11iIiiIii
  if 98 - 98: OoooooooOO
 def is_info_reply ( self ) :
  return ( True if self . info_reply else False )
  if 61 - 61: o0oOOo0O0Ooo . IiII . O0 + OoooooooOO + O0
  if 65 - 65: i1IIi * OOooOOo * OoooooooOO - IiII . iII111i - OoO0O00
 def is_rloc_probe ( self ) :
  return ( True if self . rloc_probe else False )
  if 71 - 71: Ii1I * OoOoOO00
  if 33 - 33: i1IIi . i1IIi * OoooooooOO % I1Ii111 * o0oOOo0O0Ooo
 def is_smr ( self ) :
  return ( True if self . smr_bit else False )
  if 64 - 64: ooOoO0o / ooOoO0o + I1ii11iIi11i * OOooOOo % OOooOOo
  if 87 - 87: OoO0O00 * Oo0Ooo
 def is_smr_invoked ( self ) :
  return ( True if self . smr_invoked_bit else False )
  if 83 - 83: i1IIi * I1Ii111 - IiII / Ii1I
  if 48 - 48: oO0o . II111iiii - OoOoOO00 % i1IIi . OoOoOO00
 def is_ddt ( self ) :
  return ( True if self . ddt_bit else False )
  if 32 - 32: Ii1I * I1IiiI - OOooOOo . Oo0Ooo / O0 + Ii1I
  if 67 - 67: OoOoOO00 % Oo0Ooo
 def is_to_etr ( self ) :
  return ( True if self . to_etr else False )
  if 7 - 7: i11iIiiIii % I1ii11iIi11i / I1Ii111 % Oo0Ooo - OoO0O00
  if 73 - 73: I1ii11iIi11i
 def is_to_ms ( self ) :
  return ( True if self . to_ms else False )
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
  if 15 - 15: Ii1I - IiII / O0
  if 28 - 28: I1Ii111 . i1IIi / I1ii11iIi11i
  if 77 - 77: i11iIiiIii / I1Ii111 / i11iIiiIii % OoOoOO00 - I1Ii111
  if 80 - 80: I1Ii111 % OoOoOO00 . OoooooooOO . II111iiii % IiII
  if 6 - 6: I1Ii111 % IiII / Ii1I + I1Ii111 . oO0o
  if 70 - 70: iIii1I11I1II1 / Ii1I
  if 61 - 61: O0 * o0oOOo0O0Ooo + I1Ii111 - OOooOOo . I1IiiI - IiII
  if 7 - 7: I1ii11iIi11i
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
  if 81 - 81: Oo0Ooo % II111iiii % o0oOOo0O0Ooo / I11i
  if 95 - 95: OoOoOO00 - O0 % OoooooooOO
 def print_map_register ( self ) :
  iIo0O00o00o0 = lisp_hex_string ( self . xtr_id )
  if 87 - 87: Ii1I % I1ii11iIi11i * Oo0Ooo
  o0 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
 "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
 "0x{}, site-id: {}" )
  if 59 - 59: Oo0Ooo / I11i - iIii1I11I1II1 * iIii1I11I1II1
  lprint ( o0 . format ( bold ( "Map-Register" , False ) , "P" if self . proxy_reply_requested else "p" ,
  # I1Ii111 * I11i
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_ttl_for_timeout else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node else "m" ,
 "N" if self . map_notify_requested else "n" ,
 "F" if self . map_register_refresh else "f" ,
 "E" if self . encrypt_bit else "e" ,
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , iIo0O00o00o0 , self . site_id ) )
  if 25 - 25: i11iIiiIii / iIii1I11I1II1 * OoooooooOO . OOooOOo
  if 69 - 69: Oo0Ooo * ooOoO0o
  if 91 - 91: o0oOOo0O0Ooo . ooOoO0o / OoO0O00 / i11iIiiIii * o0oOOo0O0Ooo
  if 52 - 52: I1IiiI - i11iIiiIii / IiII . oO0o
 def encode ( self ) :
  ooo = ( LISP_MAP_REGISTER << 28 ) | self . record_count
  if ( self . proxy_reply_requested ) : ooo |= 0x08000000
  if ( self . lisp_sec_present ) : ooo |= 0x04000000
  if ( self . xtr_id_present ) : ooo |= 0x02000000
  if ( self . map_register_refresh ) : ooo |= 0x1000
  if ( self . use_ttl_for_timeout ) : ooo |= 0x800
  if ( self . merge_register_requested ) : ooo |= 0x400
  if ( self . mobile_node ) : ooo |= 0x200
  if ( self . map_notify_requested ) : ooo |= 0x100
  if ( self . encryption_key_id != None ) :
   ooo |= 0x2000
   ooo |= self . encryption_key_id << 14
   if 38 - 38: oO0o + OoooooooOO * OoOoOO00 % oO0o
   if 91 - 91: i1IIi - I1ii11iIi11i * I1IiiI
   if 24 - 24: OoOoOO00 * Ii1I
   if 17 - 17: OoO0O00 . I1IiiI * O0
   if 81 - 81: OOooOOo
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . auth_len = 0
  else :
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    self . auth_len = LISP_SHA1_160_AUTH_DATA_LEN
    if 58 - 58: II111iiii . I1Ii111 . Ii1I * OoooooooOO / Ii1I / I11i
   if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    self . auth_len = LISP_SHA2_256_AUTH_DATA_LEN
    if 41 - 41: I11i + OoO0O00 . iII111i
    if 73 - 73: i11iIiiIii * I1IiiI + o0oOOo0O0Ooo / oO0o
    if 56 - 56: i1IIi
  Oo00O0o0O = struct . pack ( "I" , socket . htonl ( ooo ) )
  Oo00O0o0O += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 11 - 11: i11iIiiIii % o0oOOo0O0Ooo / I11i * OoooooooOO
  Oo00O0o0O = self . zero_auth ( Oo00O0o0O )
  return ( Oo00O0o0O )
  if 82 - 82: IiII
  if 10 - 10: Oo0Ooo % OOooOOo / I11i * IiII - o0oOOo0O0Ooo
 def zero_auth ( self , packet ) :
  II1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  Oo0oo = b""
  ooo0o = 0
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   Oo0oo = struct . pack ( "QQI" , 0 , 0 , 0 )
   ooo0o = struct . calcsize ( "QQI" )
   if 80 - 80: I1Ii111 * OoOoOO00
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   Oo0oo = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   ooo0o = struct . calcsize ( "QQQQ" )
   if 64 - 64: o0oOOo0O0Ooo % ooOoO0o % oO0o
  packet = packet [ 0 : II1Ii ] + Oo0oo + packet [ II1Ii + ooo0o : : ]
  return ( packet )
  if 29 - 29: Ii1I % OoO0O00 . II111iiii . oO0o / OoO0O00 % iIii1I11I1II1
  if 8 - 8: O0 / II111iiii
 def encode_auth ( self , packet ) :
  II1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  ooo0o = self . auth_len
  Oo0oo = self . auth_data
  packet = packet [ 0 : II1Ii ] + Oo0oo + packet [ II1Ii + ooo0o : : ]
  return ( packet )
  if 62 - 62: iIii1I11I1II1 % I1Ii111 % I1ii11iIi11i * IiII
  if 87 - 87: IiII
 def decode ( self , packet ) :
  II1i1i = packet
  Oo0O = "I"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( [ None , None ] )
  if 17 - 17: o0oOOo0O0Ooo . IiII . i11iIiiIii + OoooooooOO % i11iIiiIii
  ooo = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  ooo = socket . ntohl ( ooo [ 0 ] )
  packet = packet [ ii1ii11Ii : : ]
  if 1 - 1: o0oOOo0O0Ooo % Oo0Ooo / i11iIiiIii * I1IiiI - i1IIi / o0oOOo0O0Ooo
  Oo0O = "QBBH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( [ None , None ] )
  if 24 - 24: I1ii11iIi11i * OoO0O00 . OoooooooOO % Ii1I % O0
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  if 46 - 46: iII111i + I1Ii111 % OoooooooOO * I1ii11iIi11i
  if 89 - 89: IiII - IiII % iII111i / I11i + oO0o - IiII
  self . auth_len = socket . ntohs ( self . auth_len )
  self . proxy_reply_requested = True if ( ooo & 0x08000000 ) else False
  if 97 - 97: Ii1I % OoOoOO00 / I1ii11iIi11i / iIii1I11I1II1 * OoooooooOO * OOooOOo
  self . lisp_sec_present = True if ( ooo & 0x04000000 ) else False
  self . xtr_id_present = True if ( ooo & 0x02000000 ) else False
  self . use_ttl_for_timeout = True if ( ooo & 0x800 ) else False
  self . map_register_refresh = True if ( ooo & 0x1000 ) else False
  self . merge_register_requested = True if ( ooo & 0x400 ) else False
  self . mobile_node = True if ( ooo & 0x200 ) else False
  self . map_notify_requested = True if ( ooo & 0x100 ) else False
  self . record_count = ooo & 0xff
  if 80 - 80: oO0o / O0
  if 55 - 55: I1IiiI * I11i / O0 % OoOoOO00
  if 71 - 71: i11iIiiIii * OoOoOO00 * OOooOOo + oO0o + Oo0Ooo
  if 59 - 59: IiII
  self . encrypt_bit = True if ooo & 0x2000 else False
  if ( self . encrypt_bit ) :
   self . encryption_key_id = ( ooo >> 14 ) & 0x7
   if 54 - 54: OOooOOo
   if 27 - 27: OoOoOO00 - OoO0O00 + o0oOOo0O0Ooo + ooOoO0o . OoO0O00
   if 86 - 86: II111iiii - OoooooooOO - ooOoO0o % iII111i
   if 16 - 16: ooOoO0o + Oo0Ooo + OoooooooOO
   if 87 - 87: I1IiiI . oO0o / IiII - OoooooooOO
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( II1i1i ) == False ) : return ( [ None , None ] )
   if 33 - 33: oO0o % OoO0O00 . iIii1I11I1II1 / IiII
   if 3 - 3: Ii1I + OoO0O00
  packet = packet [ ii1ii11Ii : : ]
  if 60 - 60: OoO0O00 . OoOoOO00 - I1ii11iIi11i - I1IiiI - II111iiii % Oo0Ooo
  if 62 - 62: O0 + iII111i - iII111i % iIii1I11I1II1
  if 47 - 47: I1Ii111 + I1IiiI
  if 40 - 40: iIii1I11I1II1 % Ii1I + II111iiii - I1IiiI
  if ( self . auth_len != 0 ) :
   if ( len ( packet ) < self . auth_len ) : return ( [ None , None ] )
   if 80 - 80: oO0o
   if ( self . alg_id not in ( LISP_NONE_ALG_ID , LISP_SHA_1_96_ALG_ID ,
 LISP_SHA_256_128_ALG_ID ) ) :
    lprint ( "Invalid authentication alg-id: {}" . format ( self . alg_id ) )
    return ( [ None , None ] )
    if 81 - 81: OoooooooOO / ooOoO0o * iIii1I11I1II1 . Oo0Ooo + oO0o / O0
    if 84 - 84: II111iiii - o0oOOo0O0Ooo
   ooo0o = self . auth_len
   if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
    ii1ii11Ii = struct . calcsize ( "QQI" )
    if ( ooo0o < ii1ii11Ii ) :
     lprint ( "Invalid sha1-96 authentication length" )
     return ( [ None , None ] )
     if 78 - 78: IiII
    ooO0OoOO0 , o0oo00 , o000 = struct . unpack ( "QQI" , packet [ : ooo0o ] )
    IIIi1IiI1iII = b""
   elif ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
    ii1ii11Ii = struct . calcsize ( "QQQQ" )
    if ( ooo0o < ii1ii11Ii ) :
     lprint ( "Invalid sha2-256 authentication length" )
     return ( [ None , None ] )
     if 85 - 85: I1ii11iIi11i + OoOoOO00 - i11iIiiIii % OoOoOO00 . oO0o + i11iIiiIii
    ooO0OoOO0 , o0oo00 , o000 , IIIi1IiI1iII = struct . unpack ( "QQQQ" ,
 packet [ : ooo0o ] )
   else :
    lprint ( "Unsupported authentication alg-id value {}" . format ( self . alg_id ) )
    if 12 - 12: IiII + i1IIi . I1IiiI * iIii1I11I1II1 * I1ii11iIi11i
    return ( [ None , None ] )
    if 5 - 5: ooOoO0o - I1Ii111 - iII111i
   self . auth_data = lisp_concat_auth_data ( self . alg_id , ooO0OoOO0 , o0oo00 ,
 o000 , IIIi1IiI1iII )
   II1i1i = self . zero_auth ( II1i1i )
   packet = packet [ self . auth_len : : ]
   if 38 - 38: iIii1I11I1II1 . Ii1I
  return ( [ II1i1i , packet ] )
  if 12 - 12: OoO0O00 - I1IiiI + OoooooooOO + OoooooooOO * I1IiiI - i1IIi
  if 64 - 64: i11iIiiIii + OoOoOO00 + o0oOOo0O0Ooo + OOooOOo
 def encode_xtr_id ( self , packet ) :
  Iii1iii11 = self . xtr_id >> 64
  Ii11II11i1 = self . xtr_id & 0xffffffffffffffff
  Iii1iii11 = byte_swap_64 ( Iii1iii11 )
  Ii11II11i1 = byte_swap_64 ( Ii11II11i1 )
  IIIi1IIiI = byte_swap_64 ( self . site_id )
  packet += struct . pack ( "QQQ" , Iii1iii11 , Ii11II11i1 , IIIi1IIiI )
  return ( packet )
  if 33 - 33: OoooooooOO - I1IiiI - I1IiiI % I1IiiI % OoO0O00
  if 98 - 98: O0 + O0
 def decode_xtr_id ( self , packet ) :
  ii1ii11Ii = struct . calcsize ( "QQQ" )
  if ( len ( packet ) < ii1ii11Ii ) : return ( [ None , None ] )
  packet = packet [ len ( packet ) - ii1ii11Ii : : ]
  Iii1iii11 , Ii11II11i1 , IIIi1IIiI = struct . unpack ( "QQQ" ,
 packet [ : ii1ii11Ii ] )
  Iii1iii11 = byte_swap_64 ( Iii1iii11 )
  Ii11II11i1 = byte_swap_64 ( Ii11II11i1 )
  self . xtr_id = ( Iii1iii11 << 64 ) | Ii11II11i1
  self . site_id = byte_swap_64 ( IIIi1IIiI )
  return ( True )
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
  if 11 - 11: OOooOOo + i11iIiiIii
  if 14 - 14: OoOoOO00 / IiII + OoO0O00 - Ii1I
 def print_notify ( self ) :
  Oo0oo = binascii . hexlify ( self . auth_data )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID and len ( Oo0oo ) != 40 ) :
   Oo0oo = self . auth_data
  elif ( self . alg_id == LISP_SHA_256_128_ALG_ID and len ( Oo0oo ) != 64 ) :
   Oo0oo = self . auth_data
   if 38 - 38: I1Ii111
  o0 = ( "{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
 "{}{}{}, auth-len: {}, auth-data: {}" )
  lprint ( o0 . format ( bold ( "Map-Notify-Ack" , False ) if self . map_notify_ack else bold ( "Map-Notify" , False ) ,
  # Oo0Ooo - II111iiii
 self . record_count , lisp_hex_string ( self . nonce ) , self . key_id ,
 self . alg_id , " (sha1)" if ( self . key_id == LISP_SHA_1_96_ALG_ID ) else ( " (sha2)" if ( self . key_id == LISP_SHA_256_128_ALG_ID ) else "" ) , self . auth_len , Oo0oo ) )
  if 7 - 7: i11iIiiIii + ooOoO0o . I1Ii111 + i1IIi - o0oOOo0O0Ooo
  if 82 - 82: II111iiii + ooOoO0o * OOooOOo . iIii1I11I1II1 - i11iIiiIii * iIii1I11I1II1
  if 42 - 42: o0oOOo0O0Ooo * oO0o . OOooOOo
  if 46 - 46: I1ii11iIi11i - I1Ii111 % I1ii11iIi11i - i11iIiiIii
 def zero_auth ( self , packet ) :
  if ( self . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   Oo0oo = struct . pack ( "QQI" , 0 , 0 , 0 )
   if 50 - 50: I1Ii111 % IiII
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   Oo0oo = struct . pack ( "QQQQ" , 0 , 0 , 0 , 0 )
   if 63 - 63: OoooooooOO . Ii1I - oO0o / II111iiii + I1IiiI
  packet += Oo0oo
  return ( packet )
  if 97 - 97: I11i
  if 84 - 84: IiII - OoOoOO00 . IiII + ooOoO0o . iII111i
 def encode ( self , eid_records , password ) :
  if ( self . map_notify_ack ) :
   ooo = ( LISP_MAP_NOTIFY_ACK << 28 ) | self . record_count
  else :
   ooo = ( LISP_MAP_NOTIFY << 28 ) | self . record_count
   if 96 - 96: Ii1I % iII111i * Ii1I % I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
  Oo00O0o0O = struct . pack ( "I" , socket . htonl ( ooo ) )
  Oo00O0o0O += struct . pack ( "QBBH" , self . nonce , self . key_id , self . alg_id ,
 socket . htons ( self . auth_len ) )
  if 7 - 7: OoO0O00 - ooOoO0o % i1IIi
  if ( self . alg_id == LISP_NONE_ALG_ID ) :
   self . packet = Oo00O0o0O + eid_records
   return ( self . packet )
   if 24 - 24: OoO0O00 % O0 % I11i
   if 61 - 61: ooOoO0o . iII111i / ooOoO0o * OoooooooOO
   if 13 - 13: II111iiii
   if 17 - 17: II111iiii
   if 66 - 66: IiII * oO0o
  Oo00O0o0O = self . zero_auth ( Oo00O0o0O )
  Oo00O0o0O += eid_records
  if 73 - 73: i11iIiiIii + O0 % O0
  ooo00OoOooooo = lisp_hash_me ( Oo00O0o0O , self . alg_id , password , False )
  if 70 - 70: II111iiii * OoooooooOO - Ii1I + oO0o * O0
  II1Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  ooo0o = self . auth_len
  self . auth_data = ooo00OoOooooo
  Oo00O0o0O = Oo00O0o0O [ 0 : II1Ii ] + ooo00OoOooooo + Oo00O0o0O [ II1Ii + ooo0o : : ]
  self . packet = Oo00O0o0O
  return ( Oo00O0o0O )
  if 49 - 49: oO0o . Ii1I . OoOoOO00 - I1ii11iIi11i
  if 74 - 74: ooOoO0o % I1ii11iIi11i * i1IIi
 def decode ( self , packet ) :
  II1i1i = packet
  Oo0O = "I"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 18 - 18: OoOoOO00
  ooo = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  ooo = socket . ntohl ( ooo [ 0 ] )
  self . map_notify_ack = ( ( ooo >> 28 ) == LISP_MAP_NOTIFY_ACK )
  self . record_count = ooo & 0xff
  packet = packet [ ii1ii11Ii : : ]
  if 30 - 30: II111iiii
  Oo0O = "QBBH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 27 - 27: i1IIi - iIii1I11I1II1 + O0 % Oo0Ooo / OOooOOo + i1IIi
  self . nonce , self . key_id , self . alg_id , self . auth_len = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  if 48 - 48: Oo0Ooo
  if 70 - 70: OoooooooOO * i11iIiiIii
  self . nonce_key = lisp_hex_string ( self . nonce )
  self . auth_len = socket . ntohs ( self . auth_len )
  packet = packet [ ii1ii11Ii : : ]
  self . eid_records = packet [ self . auth_len : : ]
  if 60 - 60: IiII / iIii1I11I1II1 + OoooooooOO - I1ii11iIi11i * i11iIiiIii
  if ( self . auth_len == 0 ) : return ( self . eid_records )
  if 47 - 47: O0 . I1IiiI / ooOoO0o % i11iIiiIii
  if 47 - 47: Ii1I . OoOoOO00 . iIii1I11I1II1 . o0oOOo0O0Ooo
  if 39 - 39: o0oOOo0O0Ooo
  if 89 - 89: OoooooooOO + iII111i . I1Ii111 / Ii1I
  if ( len ( packet ) < self . auth_len ) : return ( None )
  if 75 - 75: iIii1I11I1II1 * iII111i / OoOoOO00 * II111iiii . i1IIi
  ooo0o = self . auth_len
  if ( self . alg_id == LISP_SHA_1_96_ALG_ID ) :
   ooO0OoOO0 , o0oo00 , o000 = struct . unpack ( "QQI" , packet [ : ooo0o ] )
   IIIi1IiI1iII = ""
   if 6 - 6: Ii1I % Ii1I / OoooooooOO * oO0o . I1IiiI . i1IIi
  if ( self . alg_id == LISP_SHA_256_128_ALG_ID ) :
   ooO0OoOO0 , o0oo00 , o000 , IIIi1IiI1iII = struct . unpack ( "QQQQ" ,
 packet [ : ooo0o ] )
   if 59 - 59: I11i . I11i * I1IiiI - Ii1I % OoOoOO00
  self . auth_data = lisp_concat_auth_data ( self . alg_id , ooO0OoOO0 , o0oo00 ,
 o000 , IIIi1IiI1iII )
  if 19 - 19: OoooooooOO / Oo0Ooo - I1Ii111 . OoOoOO00
  ii1ii11Ii = struct . calcsize ( "I" ) + struct . calcsize ( "QHH" )
  packet = self . zero_auth ( II1i1i [ : ii1ii11Ii ] )
  ii1ii11Ii += ooo0o
  packet += II1i1i [ ii1ii11Ii : : ]
  return ( packet )
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
  if 56 - 56: OoO0O00 + I1Ii111 / Ii1I
  if 75 - 75: OoOoOO00
  if 96 - 96: o0oOOo0O0Ooo * I11i * Oo0Ooo
  if 36 - 36: OoooooooOO + ooOoO0o . oO0o * ooOoO0o + IiII
  if 45 - 45: oO0o / iII111i + I1ii11iIi11i - Oo0Ooo - ooOoO0o . iIii1I11I1II1
  if 52 - 52: I1IiiI + i1IIi . iII111i * I1IiiI
  if 31 - 31: Oo0Ooo % iIii1I11I1II1 . O0
  if 80 - 80: I11i / Oo0Ooo + I1ii11iIi11i
  if 18 - 18: II111iiii - iII111i / iIii1I11I1II1 % OoOoOO00 % I1ii11iIi11i / o0oOOo0O0Ooo
  if 47 - 47: OOooOOo
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
  if 24 - 24: Ii1I % o0oOOo0O0Ooo
  if 87 - 87: o0oOOo0O0Ooo % iII111i / ooOoO0o - IiII + i11iIiiIii
 def print_prefix ( self ) :
  if ( self . target_group . is_null ( ) ) :
   return ( green ( self . target_eid . print_prefix ( ) , False ) )
   if 85 - 85: OoooooooOO * IiII . OOooOOo / iII111i / OoooooooOO
  return ( green ( self . target_eid . print_sg ( self . target_group ) , False ) )
  if 87 - 87: OoO0O00
  if 32 - 32: i11iIiiIii - OoOoOO00 * I11i . Oo0Ooo * ooOoO0o
 def print_map_request ( self ) :
  iIo0O00o00o0 = ""
  if ( self . xtr_id != None and self . subscribe_bit ) :
   iIo0O00o00o0 = "subscribe, xtr-id: 0x{}, " . format ( lisp_hex_string ( self . xtr_id ) )
   if 21 - 21: OOooOOo
   if 11 - 11: oO0o % i11iIiiIii * O0
   if 28 - 28: I1Ii111 / iIii1I11I1II1 + OOooOOo . I1ii11iIi11i % OOooOOo + OoO0O00
  o0 = ( "{} -> flags: {}{}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
 "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
 "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:" )
  if 79 - 79: oO0o
  lprint ( o0 . format ( bold ( "Map-Request" , False ) , "A" if self . auth_bit else "a" ,
  # Ii1I * OOooOOo * oO0o
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
 self . target_eid . afi , green ( self . print_prefix ( ) , False ) , iIo0O00o00o0 ) )
  if 76 - 76: o0oOOo0O0Ooo
  oOoOOoo = self . keys
  for II1iIiiiIiI1 in self . itr_rlocs :
   if ( II1iIiiiIiI1 . afi == LISP_AFI_LCAF and self . json_telemetry != None ) :
    continue
    if 3 - 3: OOooOOo - o0oOOo0O0Ooo * iIii1I11I1II1 . Ii1I + OoOoOO00 % I1Ii111
   iiI1i111I1 = red ( II1iIiiiIiI1 . print_address_no_iid ( ) , False )
   lprint ( "  itr-rloc: afi {} {}{}" . format ( II1iIiiiIiI1 . afi , iiI1i111I1 ,
 "" if ( oOoOOoo == None ) else ", " + oOoOOoo [ 1 ] . print_keys ( ) ) )
   oOoOOoo = None
   if 26 - 26: OoooooooOO . i1IIi + OoO0O00
  if ( self . json_telemetry != None ) :
   lprint ( "  itr-rloc: afi {} telemetry: {}" . format ( LISP_AFI_LCAF ,
 self . json_telemetry ) )
   if 42 - 42: i11iIiiIii * o0oOOo0O0Ooo % I11i % Oo0Ooo + o0oOOo0O0Ooo * i11iIiiIii
   if 66 - 66: Ii1I / IiII . OoooooooOO * Oo0Ooo % i11iIiiIii
   if 100 - 100: I1ii11iIi11i % II111iiii * i11iIiiIii - iII111i
 def sign_map_request ( self , privkey ) :
  o0o00O0 = self . signature_eid . print_address ( )
  o0000 = self . source_eid . print_address ( )
  iiI11I11i111I = self . target_eid . print_address ( )
  O0Ooo = lisp_hex_string ( self . nonce ) + o0000 + iiI11I11i111I
  self . map_request_signature = privkey . sign ( O0Ooo . encode ( ) )
  O00oooOoO = binascii . b2a_base64 ( self . map_request_signature )
  O00oooOoO = { "source-eid" : o0000 , "signature-eid" : o0o00O0 ,
 "signature" : O00oooOoO . decode ( ) }
  return ( json . dumps ( O00oooOoO ) )
  if 37 - 37: Oo0Ooo - I11i / OOooOOo / IiII * i1IIi
  if 55 - 55: I1IiiI
 def verify_map_request_sig ( self , pubkey ) :
  OOo0O = green ( self . signature_eid . print_address ( ) , False )
  if ( pubkey == None ) :
   lprint ( "Public-key not found for signature-EID {}" . format ( OOo0O ) )
   return ( False )
   if 83 - 83: ooOoO0o + i1IIi / I11i + I1Ii111
   if 12 - 12: OoO0O00 . iII111i + I1ii11iIi11i . Ii1I
  o0000 = self . source_eid . print_address ( )
  iiI11I11i111I = self . target_eid . print_address ( )
  O0Ooo = lisp_hex_string ( self . nonce ) + o0000 + iiI11I11i111I
  pubkey = binascii . a2b_base64 ( pubkey )
  if 50 - 50: Oo0Ooo
  I11IiIi1I = True
  try :
   I1IIiiI1II = ecdsa . VerifyingKey . from_pem ( pubkey )
  except :
   lprint ( "Invalid public-key in mapping system for sig-eid {}" . format ( self . signature_eid . print_address_no_iid ( ) ) )
   if 74 - 74: OoO0O00 % iIii1I11I1II1 + OoO0O00 + i1IIi . OoOoOO00 % Oo0Ooo
   I11IiIi1I = False
   if 81 - 81: ooOoO0o + OoOoOO00 % i1IIi % I1IiiI + i1IIi
   if 2 - 2: iII111i + iII111i
  if ( I11IiIi1I ) :
   try :
    O0Ooo = O0Ooo . encode ( )
    I11IiIi1I = I1IIiiI1II . verify ( self . map_request_signature , O0Ooo )
   except :
    I11IiIi1I = False
    if 51 - 51: OoooooooOO + i11iIiiIii
    if 57 - 57: Oo0Ooo % o0oOOo0O0Ooo
    if 99 - 99: o0oOOo0O0Ooo / i11iIiiIii / II111iiii + OOooOOo . i1IIi + OoOoOO00
  II11 = bold ( "passed" if I11IiIi1I else "failed" , False )
  lprint ( "Signature verification {} for EID {}" . format ( II11 , OOo0O ) )
  return ( I11IiIi1I )
  if 41 - 41: oO0o . o0oOOo0O0Ooo / I11i
  if 84 - 84: OOooOOo + II111iiii . o0oOOo0O0Ooo * Oo0Ooo
 def encode_json ( self , json_string ) :
  Ooo00O0OooOOO = LISP_LCAF_JSON_TYPE
  o00oOoO00O = socket . htons ( LISP_AFI_LCAF )
  Oo0OoooOoO0O0 = socket . htons ( len ( json_string ) + 4 )
  iIi1i = socket . htons ( len ( json_string ) )
  Oo00O0o0O = struct . pack ( "HBBBBHH" , o00oOoO00O , 0 , 0 , Ooo00O0OooOOO , 0 , Oo0OoooOoO0O0 ,
 iIi1i )
  Oo00O0o0O += json_string . encode ( )
  Oo00O0o0O += struct . pack ( "H" , 0 )
  return ( Oo00O0o0O )
  if 84 - 84: OoooooooOO . OoO0O00 / OoOoOO00 * i1IIi
  if 6 - 6: iIii1I11I1II1 * iIii1I11I1II1
 def encode ( self , probe_dest , probe_port ) :
  ooo = ( LISP_MAP_REQUEST << 28 ) | self . record_count
  if 77 - 77: OOooOOo % oO0o + iIii1I11I1II1 * Ii1I . IiII . Oo0Ooo
  IIiiiI = lisp_telemetry_configured ( ) if ( self . rloc_probe ) else None
  if ( IIiiiI != None ) : self . itr_rloc_count += 1
  ooo = ooo | ( self . itr_rloc_count << 8 )
  if 58 - 58: OoooooooOO * i11iIiiIii
  if ( self . auth_bit ) : ooo |= 0x08000000
  if ( self . map_data_present ) : ooo |= 0x04000000
  if ( self . rloc_probe ) : ooo |= 0x02000000
  if ( self . smr_bit ) : ooo |= 0x01000000
  if ( self . pitr_bit ) : ooo |= 0x00800000
  if ( self . smr_invoked_bit ) : ooo |= 0x00400000
  if ( self . mobile_node ) : ooo |= 0x00200000
  if ( self . xtr_id_present ) : ooo |= 0x00100000
  if ( self . decent_nat_xtr ) : ooo |= 0x00008000
  if ( self . local_xtr ) : ooo |= 0x00004000
  if ( self . dont_reply_bit ) : ooo |= 0x00002000
  if 19 - 19: I1ii11iIi11i * O0 - ooOoO0o
  Oo00O0o0O = struct . pack ( "I" , socket . htonl ( ooo ) )
  Oo00O0o0O += struct . pack ( "Q" , self . nonce )
  if 27 - 27: iII111i / o0oOOo0O0Ooo . OoOoOO00 * Ii1I * I1Ii111
  if 81 - 81: I1Ii111
  if 45 - 45: OOooOOo * II111iiii * OoooooooOO / OoooooooOO * I1Ii111
  if 38 - 38: iII111i . OoooooooOO
  if 28 - 28: I1Ii111 * i1IIi . I1ii11iIi11i
  if 75 - 75: O0 / oO0o * ooOoO0o - OOooOOo / i1IIi
  o0OOo0oOOo = False
  OoOOOoo = self . privkey_filename
  if ( OoOOOoo != None and os . path . exists ( OoOOOoo ) ) :
   O0Oo0 = open ( OoOOOoo , "r" ) ; I1IIiiI1II = O0Oo0 . read ( ) ; O0Oo0 . close ( )
   try :
    I1IIiiI1II = ecdsa . SigningKey . from_pem ( I1IIiiI1II )
   except :
    return ( None )
    if 59 - 59: I11i
   Oo000 = self . sign_map_request ( I1IIiiI1II )
   o0OOo0oOOo = True
  elif ( self . map_request_signature != None ) :
   O00oooOoO = binascii . b2a_base64 ( self . map_request_signature )
   Oo000 = { "source-eid" : self . source_eid . print_address ( ) ,
 "signature-eid" : self . signature_eid . print_address ( ) ,
 "signature" : O00oooOoO }
   Oo000 = json . dumps ( Oo000 )
   o0OOo0oOOo = True
   if 85 - 85: i11iIiiIii
  if ( o0OOo0oOOo ) :
   Oo00O0o0O += self . encode_json ( Oo000 )
  else :
   if ( self . source_eid . instance_id != 0 ) :
    Oo00O0o0O += struct . pack ( "H" , socket . htons ( LISP_AFI_LCAF ) )
    Oo00O0o0O += self . source_eid . lcaf_encode_iid ( )
   else :
    Oo00O0o0O += struct . pack ( "H" , socket . htons ( self . source_eid . afi ) )
    Oo00O0o0O += self . source_eid . pack_address ( )
    if 2 - 2: ooOoO0o . I1ii11iIi11i * Ii1I . Ii1I * I1Ii111
    if 89 - 89: II111iiii . I1ii11iIi11i
    if 4 - 4: I1IiiI * OoooooooOO
    if 21 - 21: OoooooooOO
    if 36 - 36: iII111i
    if 91 - 91: ooOoO0o + IiII . I1IiiI / I11i / IiII
    if 23 - 23: I1ii11iIi11i - OOooOOo - i1IIi
  if ( probe_dest ) :
   if ( probe_port == 0 ) : probe_port = LISP_DATA_PORT
   O00oO000Oo0 = probe_dest . print_address_no_iid ( ) + ":" + str ( probe_port )
   if 20 - 20: OoooooooOO / Oo0Ooo * OoO0O00 . o0oOOo0O0Ooo . I1IiiI
   if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_encap ) :
    self . keys = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ]
    if 75 - 75: iIii1I11I1II1 - Ii1I % O0 % IiII
    if 6 - 6: Oo0Ooo % oO0o * ooOoO0o - i1IIi . OoOoOO00
    if 20 - 20: Oo0Ooo / I1Ii111 . Oo0Ooo
    if 60 - 60: I1ii11iIi11i - I1IiiI * O0 * Oo0Ooo . i1IIi . OoOoOO00
    if 24 - 24: IiII * I1IiiI / OOooOOo
    if 51 - 51: iIii1I11I1II1 / I11i * OoO0O00 * Ii1I + I1ii11iIi11i . OoooooooOO
    if 75 - 75: IiII / OoooooooOO / O0 % OOooOOo
  for II1iIiiiIiI1 in self . itr_rlocs :
   if ( lisp_data_plane_security and self . itr_rlocs . index ( II1iIiiiIiI1 ) == 0 ) :
    if ( self . keys == None or self . keys [ 1 ] == None ) :
     oOoOOoo = lisp_keys ( 1 )
     self . keys = [ None , oOoOOoo , None , None ]
     if 87 - 87: II111iiii / iIii1I11I1II1 % I1ii11iIi11i
    oOoOOoo = self . keys [ 1 ]
    oOoOOoo . add_key_by_nonce ( self . nonce )
    Oo00O0o0O += oOoOOoo . encode_lcaf ( II1iIiiiIiI1 )
   else :
    Oo00O0o0O += struct . pack ( "H" , socket . htons ( II1iIiiiIiI1 . afi ) )
    Oo00O0o0O += II1iIiiiIiI1 . pack_address ( )
    if 11 - 11: o0oOOo0O0Ooo * OoO0O00
    if 92 - 92: OoOoOO00 . Oo0Ooo * I11i
    if 86 - 86: O0
    if 55 - 55: Ii1I / I1Ii111 / I1ii11iIi11i % ooOoO0o % I1IiiI
    if 55 - 55: oO0o + OoooooooOO % i1IIi
    if 24 - 24: I1ii11iIi11i - Oo0Ooo
  if ( IIiiiI != None ) :
   iIiIIIIIii = str ( time . time ( ) )
   IIiiiI = lisp_encode_telemetry ( IIiiiI , io = iIiIIIIIii )
   self . json_telemetry = IIiiiI
   Oo00O0o0O += self . encode_json ( IIiiiI )
   if 36 - 36: I1IiiI . OOooOOo % II111iiii * IiII
   if 34 - 34: I11i % iII111i - ooOoO0o - I1IiiI
  I1ioOo = 0 if self . target_eid . is_binary ( ) == False else self . target_eid . mask_len
  if 31 - 31: IiII % I11i
  if 9 - 9: OoooooooOO / Oo0Ooo / o0oOOo0O0Ooo % Oo0Ooo
  O00OOo = 0
  if ( self . subscribe_bit ) :
   O00OOo = 0x80
   self . xtr_id_present = True
   if ( self . xtr_id == None ) :
    self . xtr_id = random . randint ( 0 , ( 2 ** 128 ) - 1 )
    if 77 - 77: O0 - Ii1I * II111iiii / I1ii11iIi11i / Ii1I - oO0o
    if 66 - 66: OoO0O00 % Oo0Ooo . II111iiii
    if 84 - 84: ooOoO0o * OoooooooOO + O0
  Oo0O = "BB"
  Oo00O0o0O += struct . pack ( Oo0O , O00OOo , I1ioOo )
  if 84 - 84: i1IIi . I11i . i1IIi . Oo0Ooo
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
   if 21 - 21: II111iiii . O0 + Oo0Ooo - i11iIiiIii
   if 5 - 5: iIii1I11I1II1 * i11iIiiIii + OoO0O00 + I11i * O0 % ooOoO0o
   if 88 - 88: o0oOOo0O0Ooo / i11iIiiIii * I1ii11iIi11i
   if 23 - 23: O0 / iII111i
   if 66 - 66: i1IIi % OoooooooOO * i11iIiiIii + oO0o * O0 / OoO0O00
  if ( self . subscribe_bit ) : Oo00O0o0O = self . encode_xtr_id ( Oo00O0o0O )
  return ( Oo00O0o0O )
  if 14 - 14: I1IiiI . IiII
  if 29 - 29: OoooooooOO / IiII + OoOoOO00 - I1Ii111 + IiII . i1IIi
 def lcaf_decode_json ( self , packet ) :
  Oo0O = "BBBBHH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 26 - 26: i11iIiiIii - II111iiii
  iIII1 , oooo0ooo0 , Ooo00O0OooOOO , iI11 , Oo0OoooOoO0O0 , iIi1i = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  if 51 - 51: I1ii11iIi11i / OoooooooOO * IiII
  if 78 - 78: iII111i / I1ii11iIi11i . i11iIiiIii
  if ( Ooo00O0OooOOO != LISP_LCAF_JSON_TYPE ) : return ( packet )
  if 69 - 69: I11i - II111iiii
  if 66 - 66: I1IiiI . I1IiiI - OoOoOO00 * OoooooooOO * II111iiii + I1IiiI
  if 59 - 59: Ii1I
  if 59 - 59: II111iiii - OoO0O00
  Oo0OoooOoO0O0 = socket . ntohs ( Oo0OoooOoO0O0 )
  iIi1i = socket . ntohs ( iIi1i )
  packet = packet [ ii1ii11Ii : : ]
  if ( len ( packet ) < Oo0OoooOoO0O0 ) : return ( None )
  if ( Oo0OoooOoO0O0 != iIi1i + 4 ) : return ( None )
  if 31 - 31: I11i - OoOoOO00 / o0oOOo0O0Ooo * OoOoOO00 / Oo0Ooo + o0oOOo0O0Ooo
  if 46 - 46: IiII * OoO0O00 / OOooOOo + Oo0Ooo
  if 24 - 24: ooOoO0o % OOooOOo . O0 * Oo0Ooo
  if 52 - 52: O0 . I1Ii111 + iII111i / i11iIiiIii
  Oo000 = packet [ 0 : iIi1i ]
  packet = packet [ iIi1i : : ]
  if 52 - 52: oO0o % Oo0Ooo * II111iiii
  if 24 - 24: i11iIiiIii * i1IIi * i1IIi
  if 27 - 27: i1IIi - oO0o + OOooOOo
  if 3 - 3: IiII % I1Ii111 . OoooooooOO
  if ( lisp_is_json_telemetry ( Oo000 ) != None ) :
   self . json_telemetry = Oo000
   if 19 - 19: I1Ii111 * Ii1I - oO0o
   if 78 - 78: OoO0O00 - Ii1I / OOooOOo
   if 81 - 81: OoOoOO00
   if 21 - 21: iII111i / OOooOOo % IiII
   if 51 - 51: I11i + ooOoO0o / I1IiiI
  Oo0O = "H"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  Oo0ooooO0o00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  if ( Oo0ooooO0o00 != 0 ) : return ( packet )
  if 3 - 3: iIii1I11I1II1 / OOooOOo % oO0o . Ii1I - Ii1I
  if ( self . json_telemetry != None ) : return ( packet )
  if 55 - 55: i11iIiiIii % OoooooooOO + O0
  if 7 - 7: ooOoO0o - i11iIiiIii * iII111i / Ii1I - o0oOOo0O0Ooo
  if 62 - 62: o0oOOo0O0Ooo - iIii1I11I1II1 . I11i . Ii1I * Ii1I
  if 24 - 24: I11i
  try :
   Oo000 = json . loads ( Oo000 )
  except :
   return ( None )
   if 93 - 93: I1IiiI % OoO0O00 / i11iIiiIii / I11i
   if 60 - 60: ooOoO0o - Ii1I . I1IiiI * oO0o * i11iIiiIii
   if 29 - 29: OoO0O00 - Oo0Ooo . oO0o / OoO0O00 % i11iIiiIii
   if 26 - 26: ooOoO0o . I1Ii111 / II111iiii % Ii1I
   if 82 - 82: OOooOOo % O0 % iIii1I11I1II1 % IiII + i11iIiiIii
  if ( "source-eid" not in Oo000 ) : return ( packet )
  Ooo0O = Oo000 [ "source-eid" ]
  Oo0ooooO0o00 = LISP_AFI_IPV4 if Ooo0O . count ( "." ) == 3 else LISP_AFI_IPV6 if Ooo0O . count ( ":" ) == 7 else None
  if 87 - 87: iIii1I11I1II1 * II111iiii - I1Ii111 % I1Ii111 - OOooOOo
  if ( Oo0ooooO0o00 == None ) :
   lprint ( "Bad JSON 'source-eid' value: {}" . format ( Ooo0O ) )
   return ( None )
   if 10 - 10: I1Ii111
   if 78 - 78: O0
  self . source_eid . afi = Oo0ooooO0o00
  self . source_eid . store_address ( Ooo0O )
  if 60 - 60: oO0o
  if ( "signature-eid" not in Oo000 ) : return ( packet )
  Ooo0O = Oo000 [ "signature-eid" ]
  if ( Ooo0O . count ( ":" ) != 7 ) :
   lprint ( "Bad JSON 'signature-eid' value: {}" . format ( Ooo0O ) )
   return ( None )
   if 5 - 5: o0oOOo0O0Ooo / o0oOOo0O0Ooo - ooOoO0o * OoooooooOO . OoooooooOO . I1Ii111
   if 56 - 56: iII111i % I1IiiI * OOooOOo * i11iIiiIii
  self . signature_eid . afi = LISP_AFI_IPV6
  self . signature_eid . store_address ( Ooo0O )
  if 15 - 15: I1IiiI - oO0o - II111iiii + O0
  if ( "signature" not in Oo000 ) : return ( packet )
  O00oooOoO = binascii . a2b_base64 ( Oo000 [ "signature" ] )
  self . map_request_signature = O00oooOoO
  return ( packet )
  if 54 - 54: iIii1I11I1II1 - IiII - IiII
  if 18 - 18: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii
 def decode ( self , packet , source , port ) :
  Oo0O = "I"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 63 - 63: iII111i - OoO0O00 * OOooOOo
  ooo = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  ooo = ooo [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  if 89 - 89: iII111i / Oo0Ooo
  Oo0O = "Q"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 66 - 66: o0oOOo0O0Ooo + OoOoOO00 % OoooooooOO . I11i
  o0oOoo00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  packet = packet [ ii1ii11Ii : : ]
  if 30 - 30: II111iiii - Oo0Ooo - i11iIiiIii + O0
  ooo = socket . ntohl ( ooo )
  self . auth_bit = True if ( ooo & 0x08000000 ) else False
  self . map_data_present = True if ( ooo & 0x04000000 ) else False
  self . rloc_probe = True if ( ooo & 0x02000000 ) else False
  self . smr_bit = True if ( ooo & 0x01000000 ) else False
  self . pitr_bit = True if ( ooo & 0x00800000 ) else False
  self . smr_invoked_bit = True if ( ooo & 0x00400000 ) else False
  self . mobile_node = True if ( ooo & 0x00200000 ) else False
  self . xtr_id_present = True if ( ooo & 0x00100000 ) else False
  self . decent_nat_xtr = True if ( ooo & 0x00008000 ) else False
  self . local_xtr = True if ( ooo & 0x00004000 ) else False
  self . dont_reply_bit = True if ( ooo & 0x00002000 ) else False
  self . itr_rloc_count = ( ( ooo >> 8 ) & 0x1f )
  self . record_count = ooo & 0xff
  self . nonce = o0oOoo00 [ 0 ]
  if 93 - 93: i1IIi + I1Ii111 / OoO0O00 - I11i % Oo0Ooo / Ii1I
  if 1 - 1: Oo0Ooo / Ii1I . i11iIiiIii % OOooOOo + o0oOOo0O0Ooo + O0
  if 54 - 54: I1Ii111 + ooOoO0o % IiII
  if 83 - 83: o0oOOo0O0Ooo * iIii1I11I1II1
  if ( self . xtr_id_present ) :
   if ( self . decode_xtr_id ( packet ) == False ) : return ( None )
   if 36 - 36: OoOoOO00 + II111iiii - OoO0O00 % ooOoO0o * i1IIi
   if 4 - 4: Ii1I + OoO0O00 * I1ii11iIi11i
  ii1ii11Ii = struct . calcsize ( "H" )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 13 - 13: OoOoOO00 - IiII * iIii1I11I1II1 * O0
  Oo0ooooO0o00 = struct . unpack ( "H" , packet [ : ii1ii11Ii ] )
  self . source_eid . afi = socket . ntohs ( Oo0ooooO0o00 [ 0 ] )
  packet = packet [ ii1ii11Ii : : ]
  if 26 - 26: OoooooooOO + oO0o + OoO0O00 . O0
  if ( self . source_eid . afi == LISP_AFI_LCAF ) :
   Ii1I111Ii = packet
   packet = self . source_eid . lcaf_decode_iid ( packet )
   if ( packet == None ) :
    packet = self . lcaf_decode_json ( Ii1I111Ii )
    if ( packet == None ) : return ( None )
    if 92 - 92: o0oOOo0O0Ooo * Ii1I / IiII % Oo0Ooo
  elif ( self . source_eid . afi != LISP_AFI_NONE ) :
   packet = self . source_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 52 - 52: OoooooooOO + OoO0O00 * i1IIi / i11iIiiIii - I1Ii111
  self . source_eid . mask_len = self . source_eid . host_mask_len ( )
  if 81 - 81: O0 % o0oOOo0O0Ooo / Ii1I / ooOoO0o . i11iIiiIii + IiII
  i11iI1i11I111 = ( os . getenv ( "LISP_NO_CRYPTO" ) != None )
  self . itr_rlocs = [ ]
  oo0 = self . itr_rloc_count + 1
  if 50 - 50: oO0o
  while ( oo0 != 0 ) :
   ii1ii11Ii = struct . calcsize ( "H" )
   if ( len ( packet ) < ii1ii11Ii ) : return ( None )
   if 55 - 55: I1ii11iIi11i
   Oo0ooooO0o00 = socket . ntohs ( struct . unpack ( "H" , packet [ : ii1ii11Ii ] ) [ 0 ] )
   II1iIiiiIiI1 = lisp_address ( LISP_AFI_NONE , "" , 32 , 0 )
   II1iIiiiIiI1 . afi = Oo0ooooO0o00
   if 55 - 55: Oo0Ooo % Ii1I . iIii1I11I1II1 * I1Ii111
   if 33 - 33: O0 - I1IiiI / I1ii11iIi11i / OoO0O00 + iII111i - oO0o
   if 27 - 27: I1Ii111 + ooOoO0o - I1Ii111 % i11iIiiIii * Oo0Ooo * o0oOOo0O0Ooo
   if 88 - 88: OOooOOo
   if 25 - 25: OoO0O00 + o0oOOo0O0Ooo . ooOoO0o - Ii1I . oO0o * Ii1I
   if ( II1iIiiiIiI1 . afi == LISP_AFI_LCAF ) :
    II1i1i = packet
    o0Oo = packet [ ii1ii11Ii : : ]
    packet = self . lcaf_decode_json ( o0Oo )
    if ( packet == None ) : return ( None )
    if ( packet == o0Oo ) : packet = II1i1i
    if 17 - 17: OoooooooOO . OOooOOo
    if 32 - 32: OoOoOO00 . oO0o + O0
    if 100 - 100: O0 / OOooOOo - ooOoO0o
    if 15 - 15: iII111i - O0 - OoooooooOO
    if 49 - 49: II111iiii . OoooooooOO
    if 30 - 30: OoO0O00 / i11iIiiIii - OoO0O00 / ooOoO0o + iIii1I11I1II1 + i1IIi
   if ( II1iIiiiIiI1 . afi != LISP_AFI_LCAF ) :
    if ( len ( packet ) < II1iIiiiIiI1 . addr_length ( ) ) : return ( None )
    packet = II1iIiiiIiI1 . unpack_address ( packet [ ii1ii11Ii : : ] )
    if ( packet == None ) : return ( None )
    if 99 - 99: OOooOOo * I1IiiI + oO0o % oO0o % OOooOOo * IiII
    if ( i11iI1i11I111 ) :
     self . itr_rlocs . append ( II1iIiiiIiI1 )
     oo0 -= 1
     continue
     if 98 - 98: OOooOOo
     if 97 - 97: o0oOOo0O0Ooo
    O00oO000Oo0 = lisp_build_crypto_decap_lookup_key ( II1iIiiiIiI1 , port )
    if 35 - 35: ooOoO0o + i11iIiiIii
    if 82 - 82: i11iIiiIii + I11i + iII111i % I1IiiI
    if 84 - 84: oO0o % OOooOOo
    if 25 - 25: i11iIiiIii * OoOoOO00 + i11iIiiIii . i1IIi
    if 83 - 83: I1IiiI
    if ( lisp_nat_traversal and II1iIiiiIiI1 . is_private_address ( ) and source ) : II1iIiiiIiI1 = source
    if 90 - 90: II111iiii
    I1Ii1iiI1 = lisp_crypto_keys_by_rloc_decap
    if ( O00oO000Oo0 in I1Ii1iiI1 ) : I1Ii1iiI1 . pop ( O00oO000Oo0 )
    if 77 - 77: o0oOOo0O0Ooo . o0oOOo0O0Ooo * I1Ii111 + OOooOOo - i11iIiiIii
    if 45 - 45: I1IiiI . I1IiiI - Oo0Ooo * OOooOOo
    if 71 - 71: i1IIi / I11i
    if 14 - 14: OoooooooOO
    if 99 - 99: o0oOOo0O0Ooo * o0oOOo0O0Ooo
    if 6 - 6: i11iIiiIii + oO0o % ooOoO0o + i11iIiiIii - OOooOOo
    lisp_write_ipc_decap_key ( O00oO000Oo0 , None )
    if 12 - 12: iII111i . oO0o % IiII * OoooooooOO . IiII
   elif ( self . json_telemetry == None ) :
    if 15 - 15: I1IiiI . I1IiiI / i11iIiiIii
    if 17 - 17: iIii1I11I1II1 / OoO0O00 - II111iiii
    if 46 - 46: iIii1I11I1II1 * oO0o / i11iIiiIii + II111iiii + I11i
    if 30 - 30: O0 * IiII - I1Ii111 % O0 * Ii1I
    II1i1i = packet
    II1II111iIi = lisp_keys ( 1 )
    packet = II1II111iIi . decode_lcaf ( II1i1i , 0 )
    if 71 - 71: Oo0Ooo * iIii1I11I1II1 * I11i + I1IiiI
    if ( packet == None ) : return ( None )
    if 13 - 13: OoO0O00 - Oo0Ooo / OoO0O00
    if 34 - 34: i11iIiiIii + OoO0O00 + i11iIiiIii . IiII % O0
    if 64 - 64: o0oOOo0O0Ooo . iIii1I11I1II1
    if 86 - 86: ooOoO0o - I11i . iIii1I11I1II1 - iIii1I11I1II1
    oOo0 = [ LISP_CS_25519_CBC , LISP_CS_25519_GCM ,
 LISP_CS_25519_CHACHA ]
    if ( II1II111iIi . cipher_suite in oOo0 ) :
     if ( II1II111iIi . cipher_suite == LISP_CS_25519_CBC or
 II1II111iIi . cipher_suite == LISP_CS_25519_GCM ) :
      I1IIiiI1II = lisp_keys ( 1 , do_poly = False , do_chacha = False )
      if 61 - 61: Ii1I % Oo0Ooo + OoOoOO00
     if ( II1II111iIi . cipher_suite == LISP_CS_25519_CHACHA ) :
      I1IIiiI1II = lisp_keys ( 1 , do_poly = True , do_chacha = True )
      if 60 - 60: oO0o . OoooooooOO
    else :
     I1IIiiI1II = lisp_keys ( 1 , do_poly = False , do_curve = False ,
 do_chacha = False )
     if 40 - 40: I11i
    packet = I1IIiiI1II . decode_lcaf ( II1i1i , 0 )
    if ( packet == None ) : return ( None )
    if 44 - 44: ooOoO0o
    if ( len ( packet ) < ii1ii11Ii ) : return ( None )
    Oo0ooooO0o00 = struct . unpack ( "H" , packet [ : ii1ii11Ii ] ) [ 0 ]
    II1iIiiiIiI1 . afi = socket . ntohs ( Oo0ooooO0o00 )
    if ( len ( packet ) < II1iIiiiIiI1 . addr_length ( ) ) : return ( None )
    if 35 - 35: II111iiii + iII111i / I1ii11iIi11i * I1IiiI . I11i
    packet = II1iIiiiIiI1 . unpack_address ( packet [ ii1ii11Ii : : ] )
    if ( packet == None ) : return ( None )
    if 97 - 97: I1IiiI / o0oOOo0O0Ooo
    if ( i11iI1i11I111 ) :
     self . itr_rlocs . append ( II1iIiiiIiI1 )
     oo0 -= 1
     continue
     if 13 - 13: I1ii11iIi11i
     if 72 - 72: Oo0Ooo + IiII / Ii1I * Oo0Ooo
    O00oO000Oo0 = lisp_build_crypto_decap_lookup_key ( II1iIiiiIiI1 , port )
    if 41 - 41: OOooOOo - OoOoOO00 . I1IiiI + i11iIiiIii + OoO0O00 * iII111i
    oOo0oO0 = None
    if ( lisp_nat_traversal and II1iIiiiIiI1 . is_private_address ( ) and source ) : II1iIiiiIiI1 = source
    if 2 - 2: O0 % o0oOOo0O0Ooo
    if 3 - 3: i11iIiiIii / OOooOOo + oO0o
    if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_decap ) :
     oOoOOoo = lisp_crypto_keys_by_rloc_decap [ O00oO000Oo0 ]
     oOo0oO0 = oOoOOoo [ 1 ] if oOoOOoo and oOoOOoo [ 1 ] else None
     if 10 - 10: OoO0O00 . OoO0O00 + O0
     if 13 - 13: i1IIi . I1IiiI
    i11Ii111Ii = True
    if ( oOo0oO0 ) :
     if ( oOo0oO0 . compare_keys ( I1IIiiI1II ) ) :
      self . keys = [ None , oOo0oO0 , None , None ]
      lprint ( "Maintain stored decap-keys for RLOC {}" . format ( red ( O00oO000Oo0 , False ) ) )
      if 73 - 73: I1Ii111
     else :
      i11Ii111Ii = False
      III111Ii = bold ( "Remote decap-rekeying" , False )
      lprint ( "{} for RLOC {}" . format ( III111Ii , red ( O00oO000Oo0 ,
 False ) ) )
      I1IIiiI1II . copy_keypair ( oOo0oO0 )
      I1IIiiI1II . uptime = oOo0oO0 . uptime
      oOo0oO0 = None
      if 34 - 34: OoooooooOO - oO0o / OOooOOo / o0oOOo0O0Ooo + OOooOOo . i11iIiiIii
      if 19 - 19: OoOoOO00 % OoOoOO00
      if 74 - 74: i11iIiiIii / I1ii11iIi11i - oO0o . OoO0O00
    if ( oOo0oO0 == None ) :
     self . keys = [ None , I1IIiiI1II , None , None ]
     if ( lisp_i_am_etr == False and lisp_i_am_rtr == False ) :
      I1IIiiI1II . local_public_key = None
      lprint ( "{} for {}" . format ( bold ( "Ignoring decap-keys" ,
 False ) , red ( O00oO000Oo0 , False ) ) )
     elif ( I1IIiiI1II . remote_public_key != None ) :
      if ( i11Ii111Ii ) :
       lprint ( "{} for RLOC {}" . format ( bold ( "New decap-keying" , False ) ,
       # iII111i / OOooOOo
 red ( O00oO000Oo0 , False ) ) )
       if 61 - 61: iIii1I11I1II1 % IiII - II111iiii
      I1IIiiI1II . compute_shared_key ( "decap" )
      I1IIiiI1II . add_key_by_rloc ( O00oO000Oo0 , False )
      if 4 - 4: I1IiiI * iII111i % IiII * oO0o + OoooooooOO - OoooooooOO
      if 48 - 48: OoooooooOO * I11i
      if 87 - 87: i1IIi . I1ii11iIi11i / ooOoO0o / O0
      if 62 - 62: o0oOOo0O0Ooo % II111iiii
   self . itr_rlocs . append ( II1iIiiiIiI1 )
   oo0 -= 1
   if 22 - 22: oO0o - o0oOOo0O0Ooo
   if 89 - 89: OOooOOo
  ii1ii11Ii = struct . calcsize ( "BBH" )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 34 - 34: iII111i . OOooOOo
  O00OOo , I1ioOo , Oo0ooooO0o00 = struct . unpack ( "BBH" , packet [ : ii1ii11Ii ] )
  self . subscribe_bit = ( O00OOo & 0x80 )
  self . target_eid . afi = socket . ntohs ( Oo0ooooO0o00 )
  packet = packet [ ii1ii11Ii : : ]
  if 13 - 13: OoO0O00 * OOooOOo + oO0o
  self . target_eid . mask_len = I1ioOo
  if ( self . target_eid . afi == LISP_AFI_LCAF ) :
   packet , Ii1 = self . target_eid . lcaf_decode_eid ( packet )
   if ( packet == None ) : return ( None )
   if ( Ii1 ) : self . target_group = Ii1
  else :
   packet = self . target_eid . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = packet [ ii1ii11Ii : : ]
   if 79 - 79: OoooooooOO / OoO0O00 % Ii1I - OoOoOO00 * i1IIi + I1Ii111
  return ( packet )
  if 42 - 42: i11iIiiIii % I1Ii111 + i11iIiiIii % i11iIiiIii % I1ii11iIi11i
  if 6 - 6: oO0o . o0oOOo0O0Ooo / I1IiiI
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . target_eid , self . target_group ) )
  if 64 - 64: iII111i
  if 65 - 65: O0 / II111iiii * IiII % Ii1I + o0oOOo0O0Ooo
 def encode_xtr_id ( self , packet ) :
  Iii1iii11 = self . xtr_id >> 64
  Ii11II11i1 = self . xtr_id & 0xffffffffffffffff
  Iii1iii11 = byte_swap_64 ( Iii1iii11 )
  Ii11II11i1 = byte_swap_64 ( Ii11II11i1 )
  packet += struct . pack ( "QQ" , Iii1iii11 , Ii11II11i1 )
  return ( packet )
  if 43 - 43: I1Ii111 + OoO0O00 * OoooooooOO
  if 85 - 85: iII111i + OOooOOo
 def decode_xtr_id ( self , packet ) :
  ii1ii11Ii = struct . calcsize ( "QQ" )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  packet = packet [ len ( packet ) - ii1ii11Ii : : ]
  Iii1iii11 , Ii11II11i1 = struct . unpack ( "QQ" , packet [ : ii1ii11Ii ] )
  Iii1iii11 = byte_swap_64 ( Iii1iii11 )
  Ii11II11i1 = byte_swap_64 ( Ii11II11i1 )
  self . xtr_id = ( Iii1iii11 << 64 ) | Ii11II11i1
  return ( True )
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
  o0 = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + "nonce: 0x{}"
  if 31 - 31: II111iiii + o0oOOo0O0Ooo * i11iIiiIii . o0oOOo0O0Ooo
  lprint ( o0 . format ( bold ( "Map-Reply" , False ) , "R" if self . rloc_probe else "r" ,
  # I1IiiI * IiII - iII111i % I1ii11iIi11i / OoooooooOO
 "E" if self . echo_nonce_capable else "e" ,
 "S" if self . security else "s" , self . hop_count , self . record_count ,
 lisp_hex_string ( self . nonce ) ) )
  if 65 - 65: OoO0O00 * I11i
  if 37 - 37: Ii1I % OoO0O00 . I1Ii111 + i1IIi
 def encode ( self ) :
  ooo = ( LISP_MAP_REPLY << 28 ) | self . record_count
  ooo |= self . hop_count << 8
  if ( self . rloc_probe ) : ooo |= 0x08000000
  if ( self . echo_nonce_capable ) : ooo |= 0x04000000
  if ( self . security ) : ooo |= 0x02000000
  if 85 - 85: Oo0Ooo % I1ii11iIi11i / OOooOOo
  Oo00O0o0O = struct . pack ( "I" , socket . htonl ( ooo ) )
  Oo00O0o0O += struct . pack ( "Q" , self . nonce )
  return ( Oo00O0o0O )
  if 65 - 65: ooOoO0o + IiII - OoOoOO00 % II111iiii - iIii1I11I1II1
  if 39 - 39: I1IiiI + I1ii11iIi11i - i11iIiiIii
 def decode ( self , packet ) :
  Oo0O = "I"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 43 - 43: iIii1I11I1II1
  ooo = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  ooo = ooo [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  if 73 - 73: OoOoOO00 + o0oOOo0O0Ooo
  Oo0O = "Q"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 58 - 58: i1IIi * I1ii11iIi11i % iII111i . OoO0O00 % IiII % I11i
  o0oOoo00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  packet = packet [ ii1ii11Ii : : ]
  if 63 - 63: I1ii11iIi11i % ooOoO0o % I1ii11iIi11i
  ooo = socket . ntohl ( ooo )
  self . rloc_probe = True if ( ooo & 0x08000000 ) else False
  self . echo_nonce_capable = True if ( ooo & 0x04000000 ) else False
  self . security = True if ( ooo & 0x02000000 ) else False
  self . hop_count = ( ooo >> 8 ) & 0xff
  self . record_count = ooo & 0xff
  self . nonce = o0oOoo00 [ 0 ]
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
  Oo0ooooO0o00 = LISP_AFI_LCAF if ( self . eid . afi < 0 ) else self . eid . afi
  o0 = ( "{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
 "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}" )
  if 2 - 2: IiII + I11i / iIii1I11I1II1 . i11iIiiIii . i1IIi * ooOoO0o
  lprint ( o0 . format ( indent , self . print_ttl ( ) , self . rloc_count ,
 iI1i1i , "auth" if ( self . authoritative is True ) else "non-auth" ,
 iiIIi , IIi1I1iiiii , self . map_version , Oo0ooooO0o00 ,
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
  Oo0ooooO0o00 = self . eid . afi if ( self . eid . instance_id == 0 ) else LISP_AFI_LCAF
  if ( Oo0ooooO0o00 < 0 ) : Oo0ooooO0o00 = LISP_AFI_LCAF
  i1Ii1 = ( self . group . is_null ( ) == False )
  if ( i1Ii1 ) : Oo0ooooO0o00 = LISP_AFI_LCAF
  if 70 - 70: IiII
  OO00OO00O00O0 = ( self . signature_count << 12 ) | self . map_version
  I1ioOo = 0 if self . eid . is_binary ( ) == False else self . eid . mask_len
  if 75 - 75: i1IIi
  Oo00O0o0O = struct . pack ( "IBBHHH" , socket . htonl ( self . record_ttl ) ,
 self . rloc_count , I1ioOo , socket . htons ( oo0OoooOo0 ) ,
 socket . htons ( OO00OO00O00O0 ) , socket . htons ( Oo0ooooO0o00 ) )
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
  if ( Oo0ooooO0o00 == LISP_AFI_LCAF ) :
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
  Oo0O = "IBBHHH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 88 - 88: iIii1I11I1II1 / Ii1I * IiII / I1Ii111
  self . record_ttl , self . rloc_count , self . eid . mask_len , oo0OoooOo0 , self . map_version , self . eid . afi = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
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
  packet = packet [ ii1ii11Ii : : ]
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
  o0 = ( "{} -> flags: {}{}{}{}, " + "inner IP: {} -> {}, inner UDP: {} -> {}" )
  if 41 - 41: I1Ii111 % i1IIi + OoO0O00 / oO0o
  lprint ( o0 . format ( bold ( "ECM" , False ) , "S" if self . security else "s" ,
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
  ooo = ( LISP_ECM << 28 )
  if ( self . security ) : ooo |= 0x08000000
  if ( self . ddt ) : ooo |= 0x04000000
  if ( self . to_etr ) : ooo |= 0x02000000
  if ( self . to_ms ) : ooo |= 0x01000000
  if 62 - 62: OOooOOo * OoO0O00 * OoO0O00 + OoooooooOO . IiII + OoO0O00
  Ii1Ii1iii = struct . pack ( "I" , socket . htonl ( ooo ) )
  if 12 - 12: I1Ii111 - oO0o . OoOoOO00
  ooooO000 = ""
  if ( self . afi == LISP_AFI_IPV4 ) :
   ooooO000 = struct . pack ( "BBHHHBBH" , 0x45 , 0 , socket . htons ( self . length ) ,
 0 , 0 , self . ttl , self . protocol , socket . htons ( self . ip_checksum ) )
   ooooO000 += self . source . pack_address ( )
   ooooO000 += self . dest . pack_address ( )
   ooooO000 = lisp_ip_checksum ( ooooO000 )
   if 43 - 43: OoooooooOO . o0oOOo0O0Ooo + I1ii11iIi11i
  if ( self . afi == LISP_AFI_IPV6 ) :
   ooooO000 = struct . pack ( "BBHHBB" , 0x60 , 0 , 0 , socket . htons ( self . length ) ,
 self . protocol , self . ttl )
   ooooO000 += self . source . pack_address ( )
   ooooO000 += self . dest . pack_address ( )
   if 8 - 8: iII111i
   if 52 - 52: OoO0O00 - I1Ii111
  OOo0oOO0o0oo0 = socket . htons ( self . udp_sport )
  oooOo = socket . htons ( self . udp_dport )
  OoOoo00Oo0OoO = socket . htons ( self . udp_length )
  iiIi1iIiI = socket . htons ( self . udp_checksum )
  ii11 = struct . pack ( "HHHH" , OOo0oOO0o0oo0 , oooOo , OoOoo00Oo0OoO , iiIi1iIiI )
  return ( Ii1Ii1iii + ooooO000 + ii11 )
  if 9 - 9: I1IiiI . i11iIiiIii
  if 3 - 3: I1IiiI + I1ii11iIi11i * I1Ii111 - i1IIi . OOooOOo
 def decode ( self , packet ) :
  if 21 - 21: OOooOOo + o0oOOo0O0Ooo
  if 39 - 39: OoOoOO00 . I11i * OOooOOo . i1IIi
  if 69 - 69: IiII - i1IIi + o0oOOo0O0Ooo
  if 5 - 5: II111iiii
  Oo0O = "I"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 88 - 88: OoooooooOO % II111iiii + IiII + IiII * Oo0Ooo
  ooo = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  if 81 - 81: I1IiiI * ooOoO0o + I1Ii111
  ooo = socket . ntohl ( ooo [ 0 ] )
  self . security = True if ( ooo & 0x08000000 ) else False
  self . ddt = True if ( ooo & 0x04000000 ) else False
  self . to_etr = True if ( ooo & 0x02000000 ) else False
  self . to_ms = True if ( ooo & 0x01000000 ) else False
  packet = packet [ ii1ii11Ii : : ]
  if 49 - 49: I1IiiI % oO0o % II111iiii * II111iiii + OoooooooOO + iII111i
  if 58 - 58: i11iIiiIii % iIii1I11I1II1 + OoO0O00 . I1ii11iIi11i . I1IiiI
  if 54 - 54: iII111i . OoO0O00 . iIii1I11I1II1
  if 45 - 45: I1ii11iIi11i + I1IiiI / i11iIiiIii
  if ( len ( packet ) < 1 ) : return ( None )
  oooO = struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ]
  oooO = oooO >> 4
  if 45 - 45: IiII / O0 * I1IiiI - OOooOOo * I1Ii111
  if ( oooO == 4 ) :
   ii1ii11Ii = struct . calcsize ( "HHIBBH" )
   if ( len ( packet ) < ii1ii11Ii ) : return ( None )
   if 19 - 19: OoOoOO00 / IiII - OOooOOo * i11iIiiIii % I1Ii111
   O0O0oOO , OoOoo00Oo0OoO , O0O0oOO , IiI111ii , I1i1I , iiIi1iIiI = struct . unpack ( "HHIBBH" , packet [ : ii1ii11Ii ] )
   self . length = socket . ntohs ( OoOoo00Oo0OoO )
   self . ttl = IiI111ii
   self . protocol = I1i1I
   self . ip_checksum = socket . ntohs ( iiIi1iIiI )
   self . source . afi = self . dest . afi = LISP_AFI_IPV4
   if 45 - 45: O0 . I11i - I11i / OoO0O00 + I11i
   if 2 - 2: OOooOOo - iII111i
   if 79 - 79: i11iIiiIii + iIii1I11I1II1 . OoooooooOO % iII111i % IiII
   if 73 - 73: II111iiii - II111iiii + o0oOOo0O0Ooo * i1IIi
   I1i1I = struct . pack ( "H" , 0 )
   oOo0o0O = struct . calcsize ( "HHIBB" )
   I1I1Ii111 = struct . calcsize ( "H" )
   packet = packet [ : oOo0o0O ] + I1i1I + packet [ oOo0o0O + I1I1Ii111 : ]
   if 60 - 60: ooOoO0o
   packet = packet [ ii1ii11Ii : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 92 - 92: O0 % IiII
   if 15 - 15: O0 % i1IIi - OOooOOo . IiII
  if ( oooO == 6 ) :
   ii1ii11Ii = struct . calcsize ( "IHBB" )
   if ( len ( packet ) < ii1ii11Ii ) : return ( None )
   if 1 - 1: I1IiiI
   O0O0oOO , OoOoo00Oo0OoO , I1i1I , IiI111ii = struct . unpack ( "IHBB" , packet [ : ii1ii11Ii ] )
   self . length = socket . ntohs ( OoOoo00Oo0OoO )
   self . protocol = I1i1I
   self . ttl = IiI111ii
   self . source . afi = self . dest . afi = LISP_AFI_IPV6
   if 40 - 40: o0oOOo0O0Ooo % I11i % O0
   packet = packet [ ii1ii11Ii : : ]
   packet = self . source . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   packet = self . dest . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   if 88 - 88: o0oOOo0O0Ooo - oO0o
   if 73 - 73: II111iiii
  self . source . mask_len = self . source . host_mask_len ( )
  self . dest . mask_len = self . dest . host_mask_len ( )
  if 7 - 7: O0 / OoO0O00
  ii1ii11Ii = struct . calcsize ( "HHHH" )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 90 - 90: iII111i % oO0o / iIii1I11I1II1
  OOo0oOO0o0oo0 , oooOo , OoOoo00Oo0OoO , iiIi1iIiI = struct . unpack ( "HHHH" , packet [ : ii1ii11Ii ] )
  self . udp_sport = socket . ntohs ( OOo0oOO0o0oo0 )
  self . udp_dport = socket . ntohs ( oooOo )
  self . udp_length = socket . ntohs ( OoOoo00Oo0OoO )
  self . udp_checksum = socket . ntohs ( iiIi1iIiI )
  packet = packet [ ii1ii11Ii : : ]
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
  I11I = self . rloc_name
  if ( cour ) : I11I = lisp_print_cour ( I11I )
  return ( 'rloc-name: {}' . format ( blue ( I11I , cour ) ) )
  if 89 - 89: o0oOOo0O0Ooo
  if 95 - 95: i1IIi . OoOoOO00 % OoOoOO00 + OOooOOo / OoooooooOO
 def print_record ( self , indent ) :
  I1I111i = self . print_rloc_name ( )
  if ( I1I111i != "" ) : I1I111i = ", " + I1I111i
  IIi1iIIii1 = ""
  if ( self . geo ) :
   IIiIii1 = ""
   if ( self . geo . geo_name ) : IIiIii1 = "'{}' " . format ( self . geo . geo_name )
   IIi1iIIii1 = ", geo: {}{}" . format ( IIiIii1 , self . geo . print_geo ( ) )
   if 91 - 91: I1ii11iIi11i / Ii1I - OoOoOO00 . I11i / oO0o
  I1i1iI1i1i1 = ""
  if ( self . elp ) :
   IIiIii1 = ""
   if ( self . elp . elp_name ) : IIiIii1 = "'{}' " . format ( self . elp . elp_name )
   I1i1iI1i1i1 = ", elp: {}{}" . format ( IIiIii1 , self . elp . print_elp ( True ) )
   if 99 - 99: OoOoOO00 / OoooooooOO + iII111i * I11i * i11iIiiIii + OOooOOo
  Ii11I = ""
  if ( self . rle ) :
   IIiIii1 = ""
   if ( self . rle . rle_name ) : IIiIii1 = "'{}' " . format ( self . rle . rle_name )
   Ii11I = ", rle: {}{}" . format ( IIiIii1 , self . rle . print_rle ( False ,
 True ) )
   if 32 - 32: Oo0Ooo
  O0iI1iI1i1I = ""
  if ( self . json ) :
   IIiIii1 = ""
   if ( self . json . json_name ) :
    IIiIii1 = "'{}' " . format ( self . json . json_name )
    if 47 - 47: i11iIiiIii * oO0o * I11i * OoOoOO00
   O0iI1iI1i1I = ", json: {}" . format ( self . json . print_json ( False ) )
   if 64 - 64: I1Ii111 / OoO0O00 * O0 - ooOoO0o / I1Ii111 + OoOoOO00
   if 48 - 48: OoOoOO00
  i1I11iI11i1 = ""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   i1I11iI11i1 = ", " + self . keys [ 1 ] . print_keys ( )
   if 42 - 42: i1IIi / I1Ii111 / o0oOOo0O0Ooo . I1IiiI - II111iiii / ooOoO0o
   if 88 - 88: OOooOOo % OoooooooOO
  o0 = ( "{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
 + "{}{}{}{}{}{}{}" )
  lprint ( o0 . format ( indent , self . print_flags ( ) , self . priority ,
 self . weight , self . mpriority , self . mweight , self . rloc . afi ,
 red ( self . rloc . print_address_no_iid ( ) , False ) , I1I111i , IIi1iIIii1 ,
 I1i1iI1i1i1 , Ii11I , O0iI1iI1i1I , i1I11iI11i1 ) )
  if 28 - 28: i11iIiiIii % OoO0O00 - IiII + OOooOOo . o0oOOo0O0Ooo
  if 66 - 66: II111iiii + I1ii11iIi11i - OoOoOO00 . o0oOOo0O0Ooo / IiII % OoOoOO00
 def print_flags ( self ) :
  return ( "{}{}{}" . format ( "L" if self . local_bit else "l" , "P" if self . probe_bit else "p" , "R" if self . reach_bit else "r" ) )
  if 32 - 32: iII111i . OOooOOo * o0oOOo0O0Ooo - Oo0Ooo % O0
  if 91 - 91: OoooooooOO . oO0o + I1ii11iIi11i / i11iIiiIii * ooOoO0o
  if 25 - 25: I1ii11iIi11i + OoO0O00 * OoooooooOO
 def store_rloc_entry ( self , rloc_entry ) :
  iIIiIi1111iiIii = rloc_entry . rloc if ( rloc_entry . translated_rloc . is_null ( ) ) else rloc_entry . translated_rloc
  if 43 - 43: II111iiii % OoooooooOO
  self . rloc . copy_address ( iIIiIi1111iiIii )
  if 81 - 81: i1IIi - i1IIi / I1Ii111 + Oo0Ooo % I1Ii111
  if ( rloc_entry . rloc_name ) :
   self . rloc_name = rloc_entry . rloc_name
   if 26 - 26: OoO0O00
   if 81 - 81: i1IIi / Oo0Ooo - iIii1I11I1II1 - i11iIiiIii / II111iiii
  if ( rloc_entry . geo ) :
   self . geo = rloc_entry . geo
  else :
   IIiIii1 = rloc_entry . geo_name
   if ( IIiIii1 and IIiIii1 in lisp_geo_list ) :
    self . geo = lisp_geo_list [ IIiIii1 ]
    if 35 - 35: I1IiiI - IiII * I1Ii111 - ooOoO0o % oO0o
    if 88 - 88: IiII * OoO0O00 / IiII * I1IiiI + O0 / IiII
  if ( rloc_entry . elp ) :
   self . elp = rloc_entry . elp
  else :
   IIiIii1 = rloc_entry . elp_name
   if ( IIiIii1 and IIiIii1 in lisp_elp_list ) :
    self . elp = lisp_elp_list [ IIiIii1 ]
    if 41 - 41: OoOoOO00
    if 81 - 81: Ii1I . I1IiiI % o0oOOo0O0Ooo . OoOoOO00
  if ( rloc_entry . rle ) :
   self . rle = rloc_entry . rle
  else :
   IIiIii1 = rloc_entry . rle_name
   if ( IIiIii1 and IIiIii1 in lisp_rle_list ) :
    self . rle = lisp_rle_list [ IIiIii1 ]
    if 94 - 94: oO0o % Oo0Ooo + OoO0O00 * oO0o - i11iIiiIii / I11i
    if 46 - 46: IiII - OoO0O00 * iII111i . I1Ii111 - ooOoO0o . i1IIi
  if ( rloc_entry . json ) :
   self . json = rloc_entry . json
  else :
   IIiIii1 = rloc_entry . json_name
   if ( IIiIii1 and IIiIii1 in lisp_json_list ) :
    self . json = lisp_json_list [ IIiIii1 ]
    if 53 - 53: I1Ii111 * I1IiiI + Oo0Ooo + I1IiiI + OOooOOo
    if 8 - 8: i11iIiiIii + OoOoOO00 . I1ii11iIi11i / OoooooooOO % II111iiii
  self . priority = rloc_entry . priority
  self . weight = rloc_entry . weight
  self . mpriority = rloc_entry . mpriority
  self . mweight = rloc_entry . mweight
  if 21 - 21: oO0o - o0oOOo0O0Ooo + ooOoO0o . I1IiiI * oO0o * Ii1I
  if 41 - 41: i1IIi % i11iIiiIii + I11i % OoooooooOO / I1ii11iIi11i
 def encode_json ( self , lisp_json ) :
  Oo000 = lisp_json . json_string
  IiiIiiii = 0
  if ( lisp_json . json_encrypted ) :
   IiiIiiii = ( lisp_json . json_key_id << 5 ) | 0x02
   if 87 - 87: IiII - OoO0O00 * Oo0Ooo / o0oOOo0O0Ooo % oO0o % Ii1I
   if 25 - 25: Ii1I - I1ii11iIi11i + Oo0Ooo . I1IiiI
  Ooo00O0OooOOO = LISP_LCAF_JSON_TYPE
  o00oOoO00O = socket . htons ( LISP_AFI_LCAF )
  iii1IIIi1Iii = self . rloc . addr_length ( ) + 2
  if 93 - 93: IiII . OoOoOO00 % Ii1I - i1IIi . iIii1I11I1II1 / I1Ii111
  Oo0OoooOoO0O0 = socket . htons ( len ( Oo000 ) + iii1IIIi1Iii )
  if 75 - 75: II111iiii / oO0o
  iIi1i = socket . htons ( len ( Oo000 ) )
  Oo00O0o0O = struct . pack ( "HBBBBHH" , o00oOoO00O , 0 , 0 , Ooo00O0OooOOO , IiiIiiii ,
 Oo0OoooOoO0O0 , iIi1i )
  Oo00O0o0O += Oo000 . encode ( )
  if 26 - 26: I11i - i1IIi % OOooOOo - OoooooooOO
  if 23 - 23: OoOoOO00 + I1Ii111 * OoO0O00
  if 22 - 22: OoO0O00
  if 28 - 28: OoO0O00 + IiII % Oo0Ooo
  if ( lisp_is_json_telemetry ( Oo000 ) ) :
   Oo00O0o0O += struct . pack ( "H" , socket . htons ( self . rloc . afi ) )
   Oo00O0o0O += self . rloc . pack_address ( )
  else :
   Oo00O0o0O += struct . pack ( "H" , 0 )
   if 95 - 95: i11iIiiIii / I1Ii111 - I1Ii111
  return ( Oo00O0o0O )
  if 61 - 61: OoOoOO00 / Oo0Ooo % II111iiii / II111iiii / o0oOOo0O0Ooo
  if 34 - 34: OoO0O00 * II111iiii + i11iIiiIii % Ii1I
 def encode_lcaf ( self ) :
  o00oOoO00O = socket . htons ( LISP_AFI_LCAF )
  iIi1i1I = b""
  if ( self . geo ) :
   iIi1i1I = self . geo . encode_geo ( )
   if 36 - 36: OoooooooOO + O0
   if 32 - 32: Ii1I / I1ii11iIi11i . Ii1I
  o00OOOoooo00 = b""
  if ( self . elp ) :
   o000iI11i1ii11i11 = b""
   for OOo0OO in self . elp . elp_nodes :
    Oo0ooooO0o00 = socket . htons ( OOo0OO . address . afi )
    oooo0ooo0 = 0
    if ( OOo0OO . eid ) : oooo0ooo0 |= 0x4
    if ( OOo0OO . probe ) : oooo0ooo0 |= 0x2
    if ( OOo0OO . strict ) : oooo0ooo0 |= 0x1
    oooo0ooo0 = socket . htons ( oooo0ooo0 )
    o000iI11i1ii11i11 += struct . pack ( "HH" , oooo0ooo0 , Oo0ooooO0o00 )
    o000iI11i1ii11i11 += OOo0OO . address . pack_address ( )
    if 74 - 74: O0 * IiII . I11i - I1Ii111 + O0 + I11i
    if 48 - 48: oO0o . o0oOOo0O0Ooo - OOooOOo
   iII1I11iI = socket . htons ( len ( o000iI11i1ii11i11 ) )
   o00OOOoooo00 = struct . pack ( "HBBBBH" , o00oOoO00O , 0 , 0 , LISP_LCAF_ELP_TYPE ,
 0 , iII1I11iI )
   o00OOOoooo00 += o000iI11i1ii11i11
   if 14 - 14: I1ii11iIi11i * oO0o . O0
   if 72 - 72: i11iIiiIii % I11i / I1Ii111 + I1IiiI * iII111i
  O0ooo0O = b""
  if ( self . rle ) :
   i1iIi = b""
   for Iiiiii in self . rle . rle_nodes :
    Oo0ooooO0o00 = socket . htons ( Iiiiii . rloc . rloc . afi )
    i1iIi += struct . pack ( "HBBH" , 0 , 0 , Iiiiii . level , Oo0ooooO0o00 )
    i1iIi += Iiiiii . rloc . rloc . pack_address ( )
    if ( Iiiiii . rloc . rloc_name ) :
     i1iIi += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
     i1iIi += ( Iiiiii . rloc . rloc_name + "\0" ) . encode ( )
     if 61 - 61: IiII . IiII
     if 17 - 17: OoOoOO00 % Oo0Ooo / I1Ii111 . Ii1I % OoO0O00
     if 32 - 32: I1IiiI + ooOoO0o / O0 * i11iIiiIii % Oo0Ooo + II111iiii
   o0O00 = socket . htons ( len ( i1iIi ) )
   O0ooo0O = struct . pack ( "HBBBBH" , o00oOoO00O , 0 , 0 , LISP_LCAF_RLE_TYPE ,
 0 , o0O00 )
   O0ooo0O += i1iIi
   if 78 - 78: iIii1I11I1II1 / I1IiiI - IiII
   if 81 - 81: I1ii11iIi11i
  Iii11i111iI = b""
  if ( self . json ) :
   Iii11i111iI = self . encode_json ( self . json )
   if 76 - 76: I1Ii111 - O0
   if 23 - 23: O0 * Ii1I * ooOoO0o % ooOoO0o
  ii11i1 = b""
  if ( self . rloc . is_null ( ) == False and self . keys and self . keys [ 1 ] ) :
   ii11i1 = self . keys [ 1 ] . encode_lcaf ( self . rloc )
   if 11 - 11: OoOoOO00 + ooOoO0o * iII111i * I11i
   if 11 - 11: I1IiiI
  ii1 = b""
  if ( self . rloc_name ) :
   ii1 += struct . pack ( "H" , socket . htons ( LISP_AFI_NAME ) )
   ii1 += ( self . rloc_name + "\0" ) . encode ( )
   if 9 - 9: oO0o / Oo0Ooo
   if 85 - 85: i11iIiiIii / I1IiiI . OoO0O00 . I11i . oO0o * IiII
  I1iI1 = len ( iIi1i1I ) + len ( o00OOOoooo00 ) + len ( O0ooo0O ) + len ( ii11i1 ) + 2 + len ( Iii11i111iI ) + self . rloc . addr_length ( ) + len ( ii1 )
  if 44 - 44: ooOoO0o / Ii1I / OoooooooOO % iIii1I11I1II1 - I1Ii111
  I1iI1 = socket . htons ( I1iI1 )
  OoooO0 = struct . pack ( "HBBBBHH" , o00oOoO00O , 0 , 0 , LISP_LCAF_AFI_LIST_TYPE ,
 0 , I1iI1 , socket . htons ( self . rloc . afi ) )
  OoooO0 += self . rloc . pack_address ( )
  return ( OoooO0 + ii1 + iIi1i1I + o00OOOoooo00 + O0ooo0O + ii11i1 + Iii11i111iI )
  if 11 - 11: OOooOOo . oO0o + OOooOOo
  if 10 - 10: Ii1I
 def encode ( self ) :
  oooo0ooo0 = 0
  if ( self . local_bit ) : oooo0ooo0 |= 0x0004
  if ( self . probe_bit ) : oooo0ooo0 |= 0x0002
  if ( self . reach_bit ) : oooo0ooo0 |= 0x0001
  if 85 - 85: iIii1I11I1II1 - iIii1I11I1II1 - OoO0O00 % iII111i . I1Ii111
  Oo00O0o0O = struct . pack ( "BBBBHH" , self . priority , self . weight ,
 self . mpriority , self . mweight , socket . htons ( oooo0ooo0 ) ,
 socket . htons ( self . rloc . afi ) )
  if 16 - 16: iII111i
  if ( self . geo or self . elp or self . rle or self . keys or self . rloc_name or self . json ) :
   if 36 - 36: Ii1I / I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo
   try :
    Oo00O0o0O = Oo00O0o0O [ 0 : - 2 ] + self . encode_lcaf ( )
   except :
    lprint ( "Could not encode LCAF for RLOC-record" )
    if 64 - 64: I11i % i11iIiiIii % I1ii11iIi11i
  else :
   Oo00O0o0O += self . rloc . pack_address ( )
   if 14 - 14: I1Ii111 - OoOoOO00 - I1ii11iIi11i % I11i + OoooooooOO
  return ( Oo00O0o0O )
  if 4 - 4: I1Ii111 - I1IiiI / iIii1I11I1II1 + I1ii11iIi11i % iIii1I11I1II1 * I1IiiI
  if 30 - 30: i11iIiiIii % OOooOOo
 def decode_lcaf ( self , packet , nonce , ms_json_encrypt ) :
  Oo0O = "HBBBBH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 52 - 52: I11i - oO0o . i11iIiiIii - II111iiii + Ii1I . iII111i
  Oo0ooooO0o00 , iIII1 , oooo0ooo0 , Ooo00O0OooOOO , iI11 , Oo0OoooOoO0O0 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  if 27 - 27: I1IiiI + OoOoOO00 + iII111i
  if 70 - 70: I11i + IiII . ooOoO0o - I1ii11iIi11i
  Oo0OoooOoO0O0 = socket . ntohs ( Oo0OoooOoO0O0 )
  packet = packet [ ii1ii11Ii : : ]
  if ( Oo0OoooOoO0O0 > len ( packet ) ) : return ( None )
  if 34 - 34: i1IIi % Oo0Ooo . oO0o
  if 36 - 36: I1ii11iIi11i / I1Ii111 - IiII + OOooOOo + I1Ii111
  if 62 - 62: Oo0Ooo . OoO0O00 * I1Ii111 . i11iIiiIii * O0
  if 10 - 10: Oo0Ooo / OoOoOO00 * OOooOOo - IiII + Ii1I
  if ( Ooo00O0OooOOO == LISP_LCAF_AFI_LIST_TYPE ) :
   while ( Oo0OoooOoO0O0 > 0 ) :
    Oo0O = "H"
    ii1ii11Ii = struct . calcsize ( Oo0O )
    if ( Oo0OoooOoO0O0 < ii1ii11Ii ) : return ( None )
    if 62 - 62: I1IiiI . Ii1I
    OoOo0Oooo0o = len ( packet )
    Oo0ooooO0o00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
    Oo0ooooO0o00 = socket . ntohs ( Oo0ooooO0o00 )
    if 74 - 74: Ii1I - I11i % ooOoO0o - I1IiiI - Ii1I - II111iiii
    if ( Oo0ooooO0o00 == LISP_AFI_LCAF ) :
     packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
     if ( packet == None ) : return ( None )
    else :
     packet = packet [ ii1ii11Ii : : ]
     self . rloc_name = None
     if ( Oo0ooooO0o00 == LISP_AFI_NAME ) :
      packet , I11I = lisp_decode_dist_name ( packet )
      self . rloc_name = I11I
     else :
      self . rloc . afi = Oo0ooooO0o00
      packet = self . rloc . unpack_address ( packet )
      if ( packet == None ) : return ( None )
      self . rloc . mask_len = self . rloc . host_mask_len ( )
      if 81 - 81: i1IIi * I1ii11iIi11i + IiII - OoO0O00 * i1IIi
      if 6 - 6: iIii1I11I1II1 % OoOoOO00 % II111iiii % o0oOOo0O0Ooo
      if 52 - 52: Ii1I - I1IiiI * iIii1I11I1II1 % Oo0Ooo * OOooOOo
    Oo0OoooOoO0O0 -= OoOo0Oooo0o - len ( packet )
    if 67 - 67: OoooooooOO * I11i * Ii1I * iIii1I11I1II1
    if 22 - 22: OoO0O00 / o0oOOo0O0Ooo
  elif ( Ooo00O0OooOOO == LISP_LCAF_GEO_COORD_TYPE ) :
   if 35 - 35: I1Ii111 / I1Ii111 + o0oOOo0O0Ooo - oO0o
   if 40 - 40: OoOoOO00 - II111iiii
   if 29 - 29: I1IiiI - O0
   if 36 - 36: I1IiiI * I1IiiI
   o00OOOo0o = lisp_geo ( "" )
   packet = o00OOOo0o . decode_geo ( packet , Oo0OoooOoO0O0 , iI11 )
   if ( packet == None ) : return ( None )
   self . geo = o00OOOo0o
   if 64 - 64: IiII + OoO0O00 * iIii1I11I1II1 / iIii1I11I1II1 % OoOoOO00 - II111iiii
  elif ( Ooo00O0OooOOO == LISP_LCAF_JSON_TYPE ) :
   Ii11I1 = iI11 & 0x02
   if 62 - 62: i1IIi - I1Ii111 % i11iIiiIii
   if 96 - 96: OoooooooOO - Oo0Ooo * OoooooooOO
   if 4 - 4: OoOoOO00 / OoooooooOO - iIii1I11I1II1 / o0oOOo0O0Ooo / I11i
   if 31 - 31: Oo0Ooo / I1ii11iIi11i - II111iiii - OOooOOo
   Oo0O = "H"
   ii1ii11Ii = struct . calcsize ( Oo0O )
   if ( Oo0OoooOoO0O0 < ii1ii11Ii ) : return ( None )
   if 5 - 5: oO0o
   iIi1i = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
   iIi1i = socket . ntohs ( iIi1i )
   if ( Oo0OoooOoO0O0 < ii1ii11Ii + iIi1i ) : return ( None )
   if 51 - 51: i11iIiiIii
   packet = packet [ ii1ii11Ii : : ]
   self . json = lisp_json ( "" , packet [ 0 : iIi1i ] , Ii11I1 ,
 ms_json_encrypt )
   packet = packet [ iIi1i : : ]
   if 21 - 21: O0 - IiII * i1IIi + o0oOOo0O0Ooo % I11i + iIii1I11I1II1
   if 35 - 35: i11iIiiIii + i1IIi
   if 16 - 16: OoO0O00 - I1Ii111 * iII111i
   if 41 - 41: i11iIiiIii + i1IIi / IiII * I1ii11iIi11i / iIii1I11I1II1
   Oo0ooooO0o00 = socket . ntohs ( struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ] )
   packet = packet [ 2 : : ]
   if 70 - 70: I1IiiI % oO0o + iII111i % i11iIiiIii + ooOoO0o
   if ( Oo0ooooO0o00 != 0 and lisp_is_json_telemetry ( self . json . json_string ) ) :
    self . rloc . afi = Oo0ooooO0o00
    packet = self . rloc . unpack_address ( packet )
    if 88 - 88: I11i * oO0o * I1ii11iIi11i - OOooOOo * IiII + o0oOOo0O0Ooo
    if 9 - 9: OoooooooOO
  elif ( Ooo00O0OooOOO == LISP_LCAF_ELP_TYPE ) :
   if 26 - 26: OoOoOO00 + II111iiii - OoO0O00 + iII111i - iII111i % O0
   if 79 - 79: iIii1I11I1II1 - OoOoOO00 - O0 + I1ii11iIi11i
   if 69 - 69: oO0o % OoooooooOO
   if 21 - 21: I1Ii111
   o0OOOOOOOo0 = lisp_elp ( None )
   o0OOOOOOOo0 . elp_nodes = [ ]
   while ( Oo0OoooOoO0O0 > 0 ) :
    oooo0ooo0 , Oo0ooooO0o00 = struct . unpack ( "HH" , packet [ : 4 ] )
    if 49 - 49: oO0o / I11i - oO0o
    Oo0ooooO0o00 = socket . ntohs ( Oo0ooooO0o00 )
    if ( Oo0ooooO0o00 == LISP_AFI_LCAF ) : return ( None )
    if 31 - 31: OoOoOO00 + I1IiiI + I1ii11iIi11i + I11i * II111iiii % oO0o
    OOo0OO = lisp_elp_node ( )
    o0OOOOOOOo0 . elp_nodes . append ( OOo0OO )
    if 90 - 90: OOooOOo * iIii1I11I1II1 / i1IIi
    oooo0ooo0 = socket . ntohs ( oooo0ooo0 )
    OOo0OO . eid = ( oooo0ooo0 & 0x4 )
    OOo0OO . probe = ( oooo0ooo0 & 0x2 )
    OOo0OO . strict = ( oooo0ooo0 & 0x1 )
    OOo0OO . address . afi = Oo0ooooO0o00
    OOo0OO . address . mask_len = OOo0OO . address . host_mask_len ( )
    packet = OOo0OO . address . unpack_address ( packet [ 4 : : ] )
    Oo0OoooOoO0O0 -= OOo0OO . address . addr_length ( ) + 4
    if 60 - 60: OOooOOo * I1Ii111 . oO0o
   o0OOOOOOOo0 . select_elp_node ( )
   self . elp = o0OOOOOOOo0
   if 47 - 47: oO0o % OOooOOo / OOooOOo % OoOoOO00 % I1Ii111 / OoOoOO00
  elif ( Ooo00O0OooOOO == LISP_LCAF_RLE_TYPE ) :
   if 51 - 51: I1IiiI . I11i - OoOoOO00
   if 10 - 10: Oo0Ooo * OOooOOo / IiII . o0oOOo0O0Ooo
   if 97 - 97: Ii1I . Ii1I % iII111i
   if 49 - 49: Oo0Ooo % OOooOOo - OoooooooOO + IiII
   IiI = lisp_rle ( "" )
   IiI . rle_nodes = [ ]
   while ( Oo0OoooOoO0O0 > 0 ) :
    O0O0oOO , Ooooo00OO , i11I1 , Oo0ooooO0o00 = struct . unpack ( "HBBH" , packet [ : 6 ] )
    if 26 - 26: OoOoOO00 % iII111i % II111iiii / I11i - ooOoO0o - o0oOOo0O0Ooo
    Oo0ooooO0o00 = socket . ntohs ( Oo0ooooO0o00 )
    if ( Oo0ooooO0o00 == LISP_AFI_LCAF ) : return ( None )
    if 22 - 22: Ii1I + OoOoOO00 . iII111i / O0 . OOooOOo + OOooOOo
    Iiiiii = lisp_rle_node ( )
    IiI . rle_nodes . append ( Iiiiii )
    if 4 - 4: I11i
    Iiiiii . level = i11I1
    Iiiiii . rloc . rloc . afi = Oo0ooooO0o00
    Iiiiii . rloc . rloc . mask_len = Iiiiii . rloc . rloc . host_mask_len ( )
    packet = Iiiiii . rloc . rloc . unpack_address ( packet [ 6 : : ] )
    if 95 - 95: II111iiii % o0oOOo0O0Ooo . I11i
    Oo0OoooOoO0O0 -= Iiiiii . rloc . rloc . addr_length ( ) + 6
    if ( Oo0OoooOoO0O0 >= 2 ) :
     Oo0ooooO0o00 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
     if ( socket . ntohs ( Oo0ooooO0o00 ) == LISP_AFI_NAME ) :
      packet = packet [ 2 : : ]
      packet , Iiiiii . rloc . rloc_name = lisp_decode_dist_name ( packet )
      if 18 - 18: O0 / OoooooooOO * Oo0Ooo % iII111i
      if ( packet == None ) : return ( None )
      Oo0OoooOoO0O0 -= len ( Iiiiii . rloc . rloc_name ) + 1 + 2
      if 24 - 24: I1ii11iIi11i % OOooOOo + OoooooooOO + OoO0O00
      if 100 - 100: Oo0Ooo % OoO0O00 - OoOoOO00
      if 46 - 46: o0oOOo0O0Ooo
   self . rle = IiI
   self . rle . build_rle_forwarding_list ( )
   if 28 - 28: i1IIi
  elif ( Ooo00O0OooOOO == LISP_LCAF_SECURITY_TYPE ) :
   if 81 - 81: oO0o % OoooooooOO . I1Ii111 - OoOoOO00 / I1IiiI
   if 62 - 62: I1Ii111 * I11i / I11i
   if 42 - 42: ooOoO0o * ooOoO0o / Ii1I / OOooOOo * OOooOOo
   if 92 - 92: Oo0Ooo / iII111i - OoooooooOO - o0oOOo0O0Ooo % ooOoO0o
   if 35 - 35: i1IIi % iII111i % I11i * iIii1I11I1II1 % Ii1I - Oo0Ooo
   II1i1i = packet
   II1II111iIi = lisp_keys ( 1 )
   packet = II1II111iIi . decode_lcaf ( II1i1i , Oo0OoooOoO0O0 )
   if ( packet == None ) : return ( None )
   if 94 - 94: iII111i
   if 68 - 68: OoooooooOO % OOooOOo / OoooooooOO / I1Ii111 + Ii1I - o0oOOo0O0Ooo
   if 81 - 81: I1IiiI
   if 62 - 62: Ii1I * OoOoOO00
   oOo0 = [ LISP_CS_25519_CBC , LISP_CS_25519_CHACHA ]
   if ( II1II111iIi . cipher_suite in oOo0 ) :
    if ( II1II111iIi . cipher_suite == LISP_CS_25519_CBC ) :
     I1IIiiI1II = lisp_keys ( 1 , do_poly = False , do_chacha = False )
     if 27 - 27: Oo0Ooo + Oo0Ooo / II111iiii % I1Ii111
    if ( II1II111iIi . cipher_suite == LISP_CS_25519_CHACHA ) :
     I1IIiiI1II = lisp_keys ( 1 , do_poly = True , do_chacha = True )
     if 11 - 11: Ii1I
   else :
    I1IIiiI1II = lisp_keys ( 1 , do_poly = False , do_chacha = False )
    if 54 - 54: I1IiiI * I1Ii111 / ooOoO0o / iIii1I11I1II1 % iII111i / oO0o
   packet = I1IIiiI1II . decode_lcaf ( II1i1i , Oo0OoooOoO0O0 )
   if ( packet == None ) : return ( None )
   if 11 - 11: ooOoO0o + I1IiiI + Ii1I . II111iiii
   if ( len ( packet ) < 2 ) : return ( None )
   Oo0ooooO0o00 = struct . unpack ( "H" , packet [ : 2 ] ) [ 0 ]
   self . rloc . afi = socket . ntohs ( Oo0ooooO0o00 )
   if ( len ( packet ) < self . rloc . addr_length ( ) ) : return ( None )
   packet = self . rloc . unpack_address ( packet [ 2 : : ] )
   if ( packet == None ) : return ( None )
   self . rloc . mask_len = self . rloc . host_mask_len ( )
   if 50 - 50: Oo0Ooo
   if 14 - 14: O0
   if 67 - 67: II111iiii / O0
   if 10 - 10: i1IIi / Oo0Ooo
   if 20 - 20: Oo0Ooo * I1Ii111 / I1ii11iIi11i . ooOoO0o
   if 67 - 67: o0oOOo0O0Ooo . Oo0Ooo % I11i
   if ( self . rloc . is_null ( ) ) : return ( packet )
   if 38 - 38: OOooOOo - OoO0O00 . ooOoO0o
   i1IiiI1i = self . rloc_name
   if ( i1IiiI1i ) : i1IiiI1i = blue ( self . rloc_name , False )
   if 23 - 23: iII111i . Ii1I - OoO0O00 / I1ii11iIi11i / O0
   if 4 - 4: i1IIi % Oo0Ooo % Ii1I * ooOoO0o - I11i
   if 76 - 76: iIii1I11I1II1 / ooOoO0o % I1ii11iIi11i % OOooOOo
   if 13 - 13: IiII
   if 56 - 56: Oo0Ooo
   if 55 - 55: i11iIiiIii + iIii1I11I1II1 / i1IIi / I1ii11iIi11i
   oOo0oO0 = self . keys [ 1 ] if self . keys else None
   if ( oOo0oO0 == None ) :
    if ( I1IIiiI1II . remote_public_key == None ) :
     I1i = bold ( "No remote encap-public-key supplied" , False )
     lprint ( "    {} for {}" . format ( I1i , i1IiiI1i ) )
     I1IIiiI1II = None
    else :
     I1i = bold ( "New encap-keying with new state" , False )
     lprint ( "    {} for {}" . format ( I1i , i1IiiI1i ) )
     I1IIiiI1II . compute_shared_key ( "encap" )
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
   if ( oOo0oO0 ) :
    if ( I1IIiiI1II . remote_public_key == None ) :
     I1IIiiI1II = None
     III111Ii = bold ( "Remote encap-unkeying occurred" , False )
     lprint ( "    {} for {}" . format ( III111Ii , i1IiiI1i ) )
    elif ( oOo0oO0 . compare_keys ( I1IIiiI1II ) ) :
     I1IIiiI1II = oOo0oO0
     lprint ( "    Maintain stored encap-keys for {}" . format ( i1IiiI1i ) )
     if 52 - 52: I1ii11iIi11i % i1IIi . IiII % OoOoOO00
    else :
     if ( oOo0oO0 . remote_public_key == None ) :
      I1i = "New encap-keying for existing state"
     else :
      I1i = "Remote encap-rekeying"
      if 50 - 50: OOooOOo * I1IiiI / o0oOOo0O0Ooo
     lprint ( "    {} for {}" . format ( bold ( I1i , False ) ,
 i1IiiI1i ) )
     oOo0oO0 . remote_public_key = I1IIiiI1II . remote_public_key
     oOo0oO0 . compute_shared_key ( "encap" )
     I1IIiiI1II = oOo0oO0
     if 91 - 91: iIii1I11I1II1 / OOooOOo * O0 . o0oOOo0O0Ooo + oO0o / I1ii11iIi11i
     if 33 - 33: II111iiii + Ii1I
   self . keys = [ None , I1IIiiI1II , None , None ]
   if 46 - 46: IiII + O0 + i1IIi + ooOoO0o / iII111i
  else :
   if 94 - 94: oO0o + iII111i * OoOoOO00 - i1IIi / OoooooooOO
   if 59 - 59: I11i % Ii1I / OoOoOO00
   if 99 - 99: Ii1I + II111iiii / i11iIiiIii - IiII / iII111i + iII111i
   if 55 - 55: IiII + OoooooooOO * I1ii11iIi11i . IiII * I1ii11iIi11i + IiII
   packet = packet [ Oo0OoooOoO0O0 : : ]
   if 81 - 81: iIii1I11I1II1 . ooOoO0o + OoOoOO00
  return ( packet )
  if 31 - 31: I11i / OoOoOO00 + o0oOOo0O0Ooo
  if 80 - 80: Oo0Ooo
 def decode ( self , packet , nonce , ms_json_encrypt = False ) :
  Oo0O = "BBBBHH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 58 - 58: I1Ii111 + OOooOOo
  self . priority , self . weight , self . mpriority , self . mweight , oooo0ooo0 , Oo0ooooO0o00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  if 76 - 76: II111iiii - o0oOOo0O0Ooo % OoO0O00 + iII111i
  if 38 - 38: I1Ii111 - I11i * i1IIi + iIii1I11I1II1
  oooo0ooo0 = socket . ntohs ( oooo0ooo0 )
  Oo0ooooO0o00 = socket . ntohs ( Oo0ooooO0o00 )
  self . local_bit = True if ( oooo0ooo0 & 0x0004 ) else False
  self . probe_bit = True if ( oooo0ooo0 & 0x0002 ) else False
  self . reach_bit = True if ( oooo0ooo0 & 0x0001 ) else False
  if 41 - 41: Ii1I . OoO0O00 + I1ii11iIi11i + OoOoOO00
  if ( Oo0ooooO0o00 == LISP_AFI_LCAF ) :
   packet = packet [ ii1ii11Ii - 2 : : ]
   packet = self . decode_lcaf ( packet , nonce , ms_json_encrypt )
  else :
   self . rloc . afi = Oo0ooooO0o00
   packet = packet [ ii1ii11Ii : : ]
   packet = self . rloc . unpack_address ( packet )
   if 76 - 76: iII111i - iIii1I11I1II1
  self . rloc . mask_len = self . rloc . host_mask_len ( )
  return ( packet )
  if 23 - 23: I11i / OoO0O00 % OOooOOo
  if 9 - 9: ooOoO0o % I1ii11iIi11i . OoooooooOO + OoO0O00 % OOooOOo * OoooooooOO
 def end_of_rlocs ( self , packet , rloc_count ) :
  for o000o0O0Oo00 in range ( rloc_count ) :
   packet = self . decode ( packet , None , False )
   if ( packet == None ) : return ( None )
   if 21 - 21: Ii1I % O0
  return ( packet )
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
class lisp_map_referral ( object ) :
 def __init__ ( self ) :
  self . record_count = 0
  self . nonce = 0
  if 92 - 92: iII111i % I1ii11iIi11i
  if 16 - 16: oO0o
 def print_map_referral ( self ) :
  lprint ( "{} -> record-count: {}, nonce: 0x{}" . format ( bold ( "Map-Referral" , False ) , self . record_count ,
  # OOooOOo - OOooOOo / ooOoO0o * I1Ii111
 lisp_hex_string ( self . nonce ) ) )
  if 73 - 73: OoO0O00 * Ii1I
  if 49 - 49: OoooooooOO / oO0o / I1IiiI + o0oOOo0O0Ooo * ooOoO0o . Oo0Ooo
 def encode ( self ) :
  ooo = ( LISP_MAP_REFERRAL << 28 ) | self . record_count
  Oo00O0o0O = struct . pack ( "I" , socket . htonl ( ooo ) )
  Oo00O0o0O += struct . pack ( "Q" , self . nonce )
  return ( Oo00O0o0O )
  if 48 - 48: I11i + IiII / IiII
  if 65 - 65: I1ii11iIi11i - i1IIi % oO0o * iIii1I11I1II1 - IiII + ooOoO0o
 def decode ( self , packet ) :
  Oo0O = "I"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 63 - 63: i11iIiiIii - OOooOOo . OoOoOO00 + IiII . OoO0O00
  ooo = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  ooo = socket . ntohl ( ooo [ 0 ] )
  self . record_count = ooo & 0xff
  packet = packet [ ii1ii11Ii : : ]
  if 70 - 70: iIii1I11I1II1 % OoooooooOO / OoO0O00 . O0 - I11i % II111iiii
  Oo0O = "Q"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 84 - 84: OOooOOo * i1IIi . iIii1I11I1II1 * iII111i + I1Ii111 + II111iiii
  self . nonce = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  return ( packet )
  if 97 - 97: Ii1I - IiII
  if 64 - 64: oO0o . ooOoO0o / ooOoO0o - II111iiii
  if 81 - 81: I1ii11iIi11i
  if 64 - 64: oO0o * OoO0O00 / OOooOOo + Ii1I % Oo0Ooo . IiII
  if 2 - 2: I1Ii111 + I11i
  if 47 - 47: i11iIiiIii + iIii1I11I1II1 % I1ii11iIi11i - oO0o % OoO0O00
  if 85 - 85: oO0o * OoOoOO00 / OoOoOO00
  if 85 - 85: OOooOOo / I1Ii111 . i1IIi / OoOoOO00 + iIii1I11I1II1
class lisp_ddt_entry ( object ) :
 def __init__ ( self ) :
  self . eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . group = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . delegation_set = [ ]
  self . source_cache = None
  self . map_referrals_sent = 0
  if 71 - 71: OoO0O00
  if 96 - 96: I1ii11iIi11i / I1IiiI - I1ii11iIi11i / II111iiii - IiII
 def is_auth_prefix ( self ) :
  if ( len ( self . delegation_set ) != 0 ) : return ( False )
  if ( self . is_star_g ( ) ) : return ( False )
  return ( True )
  if 74 - 74: Ii1I * OoooooooOO % OOooOOo + OoooooooOO + iII111i
  if 83 - 83: i1IIi
 def is_ms_peer_entry ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( False )
  return ( self . delegation_set [ 0 ] . is_ms_peer ( ) )
  if 2 - 2: i1IIi / OOooOOo * O0
  if 99 - 99: OoooooooOO . OoOoOO00 / II111iiii
 def print_referral_type ( self ) :
  if ( len ( self . delegation_set ) == 0 ) : return ( "unknown" )
  O0ooii = self . delegation_set [ 0 ]
  return ( O0ooii . print_node_type ( ) )
  if 25 - 25: O0
  if 3 - 3: Oo0Ooo + OoOoOO00 - ooOoO0o % ooOoO0o / O0
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 16 - 16: OOooOOo % Oo0Ooo * I1ii11iIi11i . iII111i . iIii1I11I1II1 * i1IIi
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
   iIIiIi1111iiIii = ( ", ms-port: {}, etr-port: {}, global-rloc: {}, " + "ms-rloc: {}, private-rloc: {}, RTR-list: " ) . format ( self . ms_port , self . etr_port ,
   # i1IIi . ooOoO0o / o0oOOo0O0Ooo % Ii1I
   # Ii1I
 red ( self . global_etr_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . global_ms_rloc . print_address_no_iid ( ) , False ) ,
 red ( self . private_etr_rloc . print_address_no_iid ( ) , False ) )
   if ( len ( self . rtr_list ) == 0 ) : iIIiIi1111iiIii += "empty, "
   for I11i1i1 in self . rtr_list :
    iIIiIi1111iiIii += red ( I11i1i1 . print_address_no_iid ( ) , False ) + ", "
    if 23 - 23: OOooOOo / I11i / OoooooooOO - Ii1I / OoO0O00 - OoO0O00
   iIIiIi1111iiIii = iIIiIi1111iiIii [ 0 : - 2 ]
  else :
   Oo00O0OoooO = "Info-Request"
   O00 = "<none>" if self . hostname == None else self . hostname
   iIIiIi1111iiIii = ", hostname: {}" . format ( blue ( O00 , False ) )
   if 99 - 99: I11i / OoOoOO00 % OoO0O00 * Ii1I / OOooOOo
  lprint ( "{} -> nonce: 0x{}{}" . format ( bold ( Oo00O0OoooO , False ) ,
 lisp_hex_string ( self . nonce ) , iIIiIi1111iiIii ) )
  if 9 - 9: ooOoO0o - ooOoO0o * I1ii11iIi11i
  if 92 - 92: Ii1I
 def encode ( self ) :
  ooo = ( LISP_NAT_INFO << 28 )
  if ( self . info_reply ) : ooo |= ( 1 << 27 )
  if 88 - 88: OoooooooOO * i1IIi % I1ii11iIi11i % Oo0Ooo
  if 1 - 1: OoO0O00 / iIii1I11I1II1 % I1ii11iIi11i - o0oOOo0O0Ooo
  if 62 - 62: I1Ii111 % II111iiii
  if 91 - 91: I11i % Ii1I - IiII + iIii1I11I1II1 * iIii1I11I1II1
  if 91 - 91: i11iIiiIii + Ii1I
  if 85 - 85: I11i % IiII
  if 68 - 68: Oo0Ooo . I1Ii111 - o0oOOo0O0Ooo * iIii1I11I1II1 - II111iiii % i1IIi
  Oo00O0o0O = struct . pack ( "I" , socket . htonl ( ooo ) )
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
  Oo0ooooO0o00 = socket . htons ( LISP_AFI_LCAF )
  Ooo00O0OooOOO = LISP_LCAF_NAT_TYPE
  Oo0OoooOoO0O0 = socket . htons ( 16 )
  o0I1i11i = socket . htons ( self . ms_port )
  O0OoOo0ooOoOo = socket . htons ( self . etr_port )
  Oo00O0o0O += struct . pack ( "HHBBHHHH" , Oo0ooooO0o00 , 0 , Ooo00O0OooOOO , 0 , Oo0OoooOoO0O0 ,
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
  II1i1i = packet
  Oo0O = "I"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 66 - 66: II111iiii + OOooOOo + i11iIiiIii / II111iiii
  ooo = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  ooo = ooo [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  if 37 - 37: I1IiiI + OoO0O00 . OoO0O00 % OoOoOO00 + o0oOOo0O0Ooo
  Oo0O = "Q"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 81 - 81: i1IIi % iIii1I11I1II1
  o0oOoo00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  if 41 - 41: oO0o - iII111i / o0oOOo0O0Ooo . iII111i % Oo0Ooo + OOooOOo
  ooo = socket . ntohl ( ooo )
  self . nonce = o0oOoo00 [ 0 ]
  self . info_reply = ooo & 0x08000000
  self . hostname = None
  packet = packet [ ii1ii11Ii : : ]
  if 82 - 82: ooOoO0o
  if 89 - 89: OOooOOo / I1ii11iIi11i . I1IiiI + i11iIiiIii
  if 11 - 11: oO0o . i11iIiiIii * ooOoO0o % OoooooooOO % O0
  if 59 - 59: i11iIiiIii / OoO0O00
  if 48 - 48: iIii1I11I1II1
  Oo0O = "HH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 19 - 19: oO0o
  if 69 - 69: I1ii11iIi11i % iII111i - OoooooooOO % Ii1I * oO0o
  if 12 - 12: OoOoOO00 / I1Ii111 . O0 . IiII - OOooOOo - OoO0O00
  if 28 - 28: II111iiii . OoOoOO00 - o0oOOo0O0Ooo
  if 89 - 89: I1Ii111 * OoooooooOO . OOooOOo . I11i % i11iIiiIii
  III , ooo0o = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  if ( ooo0o != 0 ) : return ( None )
  if 8 - 8: I1ii11iIi11i + II111iiii . OoO0O00 + I1IiiI - II111iiii % OoO0O00
  packet = packet [ ii1ii11Ii : : ]
  Oo0O = "IBBH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 85 - 85: i11iIiiIii % iII111i + II111iiii
  o0ooo000o00O , ooO0000 , I1iIIIiI1iI11 , i1iIiII = struct . unpack ( Oo0O ,
 packet [ : ii1ii11Ii ] )
  if 46 - 46: OoooooooOO - Ii1I - Ii1I . OoO0O00 . I11i % Ii1I
  if ( i1iIiII != 0 ) : return ( None )
  packet = packet [ ii1ii11Ii : : ]
  if 26 - 26: OoooooooOO . oO0o + I1Ii111
  if 4 - 4: o0oOOo0O0Ooo % i1IIi . OOooOOo
  if 97 - 97: OoOoOO00 / iII111i * oO0o
  if 15 - 15: iIii1I11I1II1 / Ii1I / I1ii11iIi11i / Oo0Ooo
  if ( self . info_reply == False ) :
   Oo0O = "H"
   ii1ii11Ii = struct . calcsize ( Oo0O )
   if ( len ( packet ) >= ii1ii11Ii ) :
    Oo0ooooO0o00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
    if ( socket . ntohs ( Oo0ooooO0o00 ) == LISP_AFI_NAME ) :
     packet = packet [ ii1ii11Ii : : ]
     packet , self . hostname = lisp_decode_dist_name ( packet )
     if 99 - 99: iII111i / O0 % ooOoO0o - II111iiii - i11iIiiIii
     if 44 - 44: i11iIiiIii . I11i - IiII + OoooooooOO . oO0o + I11i
   return ( II1i1i )
   if 6 - 6: i1IIi . o0oOOo0O0Ooo + OoO0O00 + OOooOOo + oO0o
   if 30 - 30: O0
   if 98 - 98: I1Ii111
   if 58 - 58: OOooOOo
   if 6 - 6: I1ii11iIi11i
  Oo0O = "HHBBHHH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 37 - 37: i11iIiiIii . II111iiii + OOooOOo + i1IIi * OOooOOo
  Oo0ooooO0o00 , O0O0oOO , Ooo00O0OooOOO , ooO0000 , Oo0OoooOoO0O0 , o0I1i11i , O0OoOo0ooOoOo = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  if 18 - 18: ooOoO0o
  if 18 - 18: I1Ii111 + OoOoOO00 % OOooOOo - IiII - i1IIi + I1ii11iIi11i
  if ( socket . ntohs ( Oo0ooooO0o00 ) != LISP_AFI_LCAF ) : return ( None )
  if 33 - 33: I11i * Ii1I / Oo0Ooo + oO0o % OOooOOo % OoooooooOO
  self . ms_port = socket . ntohs ( o0I1i11i )
  self . etr_port = socket . ntohs ( O0OoOo0ooOoOo )
  packet = packet [ ii1ii11Ii : : ]
  if 29 - 29: Ii1I . II111iiii / I1Ii111
  if 79 - 79: IiII . OoOoOO00 / oO0o % OoO0O00 / Ii1I + I11i
  if 78 - 78: o0oOOo0O0Ooo + I1Ii111 % i11iIiiIii % I1IiiI - Ii1I
  if 81 - 81: i11iIiiIii - II111iiii + I11i
  Oo0O = "H"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 52 - 52: II111iiii
  if 62 - 62: iII111i / OoO0O00 + i11iIiiIii / Oo0Ooo
  if 26 - 26: I1ii11iIi11i - OoO0O00
  if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i + O0
  Oo0ooooO0o00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  if ( Oo0ooooO0o00 != 0 ) :
   self . global_etr_rloc . afi = socket . ntohs ( Oo0ooooO0o00 )
   packet = self . global_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( None )
   self . global_etr_rloc . mask_len = self . global_etr_rloc . host_mask_len ( )
   if 12 - 12: I11i . OOooOOo + o0oOOo0O0Ooo . OoO0O00 + o0oOOo0O0Ooo
   if 56 - 56: i1IIi / i1IIi . OoO0O00 % i1IIi - OoOoOO00 % OOooOOo
   if 66 - 66: i11iIiiIii * IiII % IiII . I1IiiI / ooOoO0o
   if 50 - 50: IiII . iII111i / o0oOOo0O0Ooo % OoOoOO00 * IiII % I11i
   if 15 - 15: Ii1I
   if 29 - 29: I11i / I1IiiI / OoooooooOO . OoOoOO00 / I11i . I1Ii111
  if ( len ( packet ) < ii1ii11Ii ) : return ( II1i1i )
  if 69 - 69: O0 * OoOoOO00 + o0oOOo0O0Ooo + I1IiiI % iII111i . OoooooooOO
  Oo0ooooO0o00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  if ( Oo0ooooO0o00 != 0 ) :
   self . global_ms_rloc . afi = socket . ntohs ( Oo0ooooO0o00 )
   packet = self . global_ms_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( II1i1i )
   self . global_ms_rloc . mask_len = self . global_ms_rloc . host_mask_len ( )
   if 45 - 45: I1Ii111 + oO0o - o0oOOo0O0Ooo - OoOoOO00 + I1IiiI / II111iiii
   if 46 - 46: II111iiii . iIii1I11I1II1
   if 62 - 62: I1ii11iIi11i % i1IIi % I1Ii111 * ooOoO0o % OOooOOo + I1IiiI
   if 100 - 100: II111iiii - o0oOOo0O0Ooo * OoooooooOO . ooOoO0o / II111iiii / oO0o
   if 43 - 43: iIii1I11I1II1 + ooOoO0o * iII111i + iIii1I11I1II1 . I1Ii111
  if ( len ( packet ) < ii1ii11Ii ) : return ( II1i1i )
  if 87 - 87: I1Ii111
  Oo0ooooO0o00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  if ( Oo0ooooO0o00 != 0 ) :
   self . private_etr_rloc . afi = socket . ntohs ( Oo0ooooO0o00 )
   packet = self . private_etr_rloc . unpack_address ( packet )
   if ( packet == None ) : return ( II1i1i )
   self . private_etr_rloc . mask_len = self . private_etr_rloc . host_mask_len ( )
   if 47 - 47: II111iiii + I1IiiI . Oo0Ooo / iIii1I11I1II1
   if 14 - 14: i1IIi / OoO0O00 / iII111i % I1Ii111
   if 72 - 72: OoO0O00 . II111iiii - IiII + IiII + iIii1I11I1II1 % oO0o
   if 21 - 21: iII111i + OoOoOO00 - i11iIiiIii % O0 + OOooOOo
   if 30 - 30: o0oOOo0O0Ooo - Oo0Ooo + iII111i / O0
   if 94 - 94: IiII
  while ( len ( packet ) >= ii1ii11Ii ) :
   Oo0ooooO0o00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
   packet = packet [ ii1ii11Ii : : ]
   if ( Oo0ooooO0o00 == 0 ) : continue
   I11i1i1 = lisp_address ( socket . ntohs ( Oo0ooooO0o00 ) , "" , 0 , 0 )
   packet = I11i1i1 . unpack_address ( packet )
   if ( packet == None ) : return ( II1i1i )
   I11i1i1 . mask_len = I11i1i1 . host_mask_len ( )
   self . rtr_list . append ( I11i1i1 )
   if 69 - 69: I1Ii111 . I1Ii111
  return ( II1i1i )
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
  I1IIiiI1II = self . address . print_address_no_iid ( ) + self . hostname
  lisp_info_sources_by_address [ I1IIiiI1II ] = self
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
  Oo0oo = auth1 + auth2 + auth3
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
  Oo0oo = auth1 + auth2 + auth3 + auth4
  if 90 - 90: o0oOOo0O0Ooo - O0 % O0 - oO0o . OoooooooOO
 return ( Oo0oo )
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
  IIiIii1 = port
  if ( os . path . exists ( IIiIii1 ) ) :
   os . system ( "rm " + IIiIii1 )
   time . sleep ( 1 )
   if 58 - 58: i11iIiiIii * OOooOOo . Oo0Ooo / iII111i - i1IIi
  Iiii = socket . socket ( socket . AF_UNIX , socket . SOCK_DGRAM )
  Iiii . bind ( IIiIii1 )
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
 I11 = "packet@{}@{}@{}@" . format ( str ( len ( packet ) ) , source , str ( sport ) )
 return ( I11 . encode ( ) + packet )
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
 I11 = "control-packet@{}@{}@" . format ( dest , str ( dport ) )
 return ( I11 . encode ( ) + packet )
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
 I11 = "data-packet@{}@{}@@" . format ( str ( len ( packet ) ) , source )
 return ( I11 . encode ( ) + packet )
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
 i11Ii111Ii = b""
 OOOOo0o0O0o = len ( packet ) * 2
 while ( II1Ii < OOOOo0o0O0o ) :
  i11Ii111Ii += packet [ II1Ii : II1Ii + 8 ] + b" "
  II1Ii += 8
  OOOOo0o0O0o -= 4
  if 57 - 57: OoO0O00 / Oo0Ooo % I1IiiI * I1ii11iIi11i
 return ( i11Ii111Ii . decode ( ) )
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
 I1iI111ii111i = dest . print_address_no_iid ( )
 if ( I1iI111ii111i . find ( "::ffff:" ) != - 1 and I1iI111ii111i . count ( "." ) == 3 ) :
  if ( lisp_i_am_rtr ) : oO00o0Oo0 = lisp_sockets [ 0 ]
  if ( oO00o0Oo0 == None ) :
   oO00o0Oo0 = lisp_sockets [ 0 ]
   I1iI111ii111i = I1iI111ii111i . split ( "::ffff:" ) [ - 1 ]
   if 86 - 86: ooOoO0o . OoO0O00
   if 47 - 47: IiII % I1IiiI
   if 91 - 91: Ii1I
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Send" , False ) ,
 len ( packet ) , bold ( "to " + I1iI111ii111i , False ) , port ,
 lisp_format_packet ( packet ) ) )
 if 69 - 69: iII111i
 if 96 - 96: Ii1I
 if 39 - 39: OoO0O00 - I1IiiI % II111iiii - IiII * I1ii11iIi11i
 if 64 - 64: OOooOOo + Oo0Ooo . OoOoOO00 . OOooOOo + i11iIiiIii
 try :
  oO00o0Oo0 . sendto ( packet , ( I1iI111ii111i , port ) )
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
  try : I1ooO0OoOo = lisp_socket . recvfrom ( 9000 )
  except : return ( [ "" , "" , "" , "" ] )
  if 61 - 61: i11iIiiIii % I1Ii111
  if 82 - 82: i1IIi
  if 21 - 21: O0 * IiII . iII111i / iII111i % i11iIiiIii / I11i
  if 15 - 15: o0oOOo0O0Ooo / OoO0O00 - i1IIi
  if 30 - 30: OoO0O00 / ooOoO0o % ooOoO0o
  if 40 - 40: i1IIi . iIii1I11I1II1 * OoOoOO00
  if ( internal == False ) :
   Oo00O0o0O = I1ooO0OoOo [ 0 ]
   ooOO0O0O = lisp_convert_6to4 ( I1ooO0OoOo [ 1 ] [ 0 ] )
   O0ooO0O00oo0 = I1ooO0OoOo [ 1 ] [ 1 ]
   if 83 - 83: iIii1I11I1II1 + Ii1I - Ii1I % II111iiii
   if ( O0ooO0O00oo0 == LISP_DATA_PORT ) :
    ooOI1i = lisp_data_plane_logging
    I1IIi = lisp_format_packet ( Oo00O0o0O [ 0 : 60 ] ) + " ..."
   else :
    ooOI1i = True
    I1IIi = lisp_format_packet ( Oo00O0o0O )
    if 20 - 20: OoO0O00 * II111iiii
    if 22 - 22: Oo0Ooo * I11i
   if ( ooOI1i ) :
    lprint ( "{} {} bytes {} {}, packet: {}" . format ( bold ( "Receive" ,
 False ) , len ( Oo00O0o0O ) , bold ( "from " + ooOO0O0O , False ) , O0ooO0O00oo0 ,
 I1IIi ) )
    if 48 - 48: i11iIiiIii * I1IiiI % oO0o % OoooooooOO
   return ( [ "packet" , ooOO0O0O , O0ooO0O00oo0 , Oo00O0o0O ] )
   if 4 - 4: OoO0O00 . I1IiiI - O0 % iII111i . OOooOOo
   if 69 - 69: OoooooooOO
   if 19 - 19: O0 + iIii1I11I1II1 / OoOoOO00 / oO0o + II111iiii - OOooOOo
   if 70 - 70: i1IIi * o0oOOo0O0Ooo + I1Ii111 . ooOoO0o - O0 + i11iIiiIii
   if 81 - 81: iIii1I11I1II1 - OoO0O00 . i11iIiiIii
   if 4 - 4: o0oOOo0O0Ooo / OoO0O00 - I11i
  ooo0oo = False
  ooooO000O0OOO0o0O = I1ooO0OoOo [ 0 ]
  if ( type ( ooooO000O0OOO0o0O ) == str ) : ooooO000O0OOO0o0O = ooooO000O0OOO0o0O . encode ( )
  OOOOOo0O0oOO = False
  if 99 - 99: OoO0O00 * I11i
  while ( ooo0oo == False ) :
   ooooO000O0OOO0o0O = ooooO000O0OOO0o0O . split ( b"@" )
   if 33 - 33: I1Ii111 % IiII * OOooOOo - I1Ii111
   if ( len ( ooooO000O0OOO0o0O ) < 4 ) :
    lprint ( "Possible fragment (length {}), from old message, " + "discarding" , len ( ooooO000O0OOO0o0O [ 0 ] ) )
    if 100 - 100: ooOoO0o . i11iIiiIii * Oo0Ooo - i11iIiiIii
    OOOOOo0O0oOO = True
    break
    if 72 - 72: oO0o + I11i . OoooooooOO
    if 84 - 84: oO0o * oO0o - i1IIi + ooOoO0o
   o0OoiIiI111 = ooooO000O0OOO0o0O [ 0 ] . decode ( )
   try :
    oo0o0o = int ( ooooO000O0OOO0o0O [ 1 ] )
   except :
    i1i11i1i11ii11I = bold ( "Internal packet reassembly error" , False )
    lprint ( "{}: {}" . format ( i1i11i1i11ii11I , I1ooO0OoOo ) )
    OOOOOo0O0oOO = True
    break
    if 54 - 54: o0oOOo0O0Ooo / iII111i + IiII - o0oOOo0O0Ooo - I11i
   ooOO0O0O = ooooO000O0OOO0o0O [ 2 ] . decode ( )
   O0ooO0O00oo0 = ooooO000O0OOO0o0O [ 3 ] . decode ( )
   if 28 - 28: I1IiiI - iIii1I11I1II1 - o0oOOo0O0Ooo * IiII + OoooooooOO
   if 52 - 52: I1Ii111
   if 86 - 86: O0 * IiII + OoOoOO00 + OoO0O00
   if 53 - 53: I1IiiI % i11iIiiIii + o0oOOo0O0Ooo . I1ii11iIi11i
   if 73 - 73: iII111i - o0oOOo0O0Ooo / OOooOOo + iII111i + o0oOOo0O0Ooo % II111iiii
   if 74 - 74: I11i * iIii1I11I1II1 - OoO0O00 / i1IIi / OoO0O00 / IiII
   if 60 - 60: oO0o % I1Ii111 % Oo0Ooo
   if 34 - 34: o0oOOo0O0Ooo * OOooOOo % Ii1I + I1IiiI
   if ( len ( ooooO000O0OOO0o0O ) > 5 ) :
    Oo00O0o0O = lisp_bit_stuff ( ooooO000O0OOO0o0O [ 4 : : ] )
   else :
    Oo00O0o0O = ooooO000O0OOO0o0O [ 4 ]
    if 77 - 77: OoOoOO00 + IiII + Oo0Ooo
    if 88 - 88: i1IIi
    if 45 - 45: iII111i % I1ii11iIi11i / i11iIiiIii - II111iiii . Oo0Ooo / ooOoO0o
    if 55 - 55: OoO0O00 % IiII
    if 93 - 93: OoO0O00 . I1ii11iIi11i / OOooOOo % OoooooooOO + i1IIi + I1Ii111
    if 94 - 94: II111iiii + i11iIiiIii % Ii1I / ooOoO0o * OoOoOO00
   ooo0oo , Oo00O0o0O = lisp_receive_segments ( lisp_socket , Oo00O0o0O ,
 ooOO0O0O , oo0o0o )
   if ( Oo00O0o0O == None ) : return ( [ "" , "" , "" , "" ] )
   if 68 - 68: O0 / Oo0Ooo / iIii1I11I1II1
   if 63 - 63: I1Ii111 + iII111i
   if 6 - 6: I1ii11iIi11i + Ii1I
   if 36 - 36: iII111i + iII111i * OoO0O00 * I1ii11iIi11i
   if 97 - 97: ooOoO0o + OOooOOo
   if ( ooo0oo == False ) :
    ooooO000O0OOO0o0O = Oo00O0o0O
    continue
    if 70 - 70: o0oOOo0O0Ooo + Ii1I - i11iIiiIii + I11i * o0oOOo0O0Ooo . Ii1I
    if 6 - 6: Oo0Ooo + I1IiiI
   if ( O0ooO0O00oo0 == "" ) : O0ooO0O00oo0 = "no-port"
   if ( o0OoiIiI111 == "command" and lisp_i_am_core == False ) :
    o00O = Oo00O0o0O . find ( b" {" )
    iII = Oo00O0o0O if o00O == - 1 else Oo00O0o0O [ : o00O ]
    iII = ": '" + iII . decode ( ) + "'"
   else :
    iII = ""
    if 59 - 59: IiII - Ii1I
    if 62 - 62: OOooOOo * o0oOOo0O0Ooo + IiII * o0oOOo0O0Ooo * i11iIiiIii - O0
   lprint ( "{} {} bytes {} {}, {}{}" . format ( bold ( "Receive" , False ) ,
 len ( Oo00O0o0O ) , bold ( "from " + ooOO0O0O , False ) , O0ooO0O00oo0 , o0OoiIiI111 ,
 iII if ( o0OoiIiI111 in [ "command" , "api" ] ) else ": ... " if ( o0OoiIiI111 == "data-packet" ) else ": " + lisp_format_packet ( Oo00O0o0O ) ) )
   if 37 - 37: I1ii11iIi11i - Oo0Ooo . i11iIiiIii / i11iIiiIii + oO0o
   if 19 - 19: i1IIi / i1IIi - OoooooooOO - OOooOOo . i1IIi
   if 57 - 57: OOooOOo / I1ii11iIi11i * oO0o
   if 53 - 53: o0oOOo0O0Ooo * Ii1I
   if 42 - 42: I11i + iII111i / iIii1I11I1II1
  if ( OOOOOo0O0oOO ) : continue
  return ( [ o0OoiIiI111 , ooOO0O0O , O0ooO0O00oo0 , Oo00O0o0O ] )
  if 1 - 1: O0 - II111iiii
  if 75 - 75: II111iiii / OoO0O00 % II111iiii
  if 3 - 3: Ii1I - Ii1I % I1ii11iIi11i
  if 44 - 44: OOooOOo - o0oOOo0O0Ooo
  if 69 - 69: IiII + I1ii11iIi11i / o0oOOo0O0Ooo / OOooOOo
  if 31 - 31: oO0o + I1ii11iIi11i * i1IIi % I1IiiI % I1IiiI + iIii1I11I1II1
  if 62 - 62: OoooooooOO
  if 38 - 38: iII111i % iII111i * ooOoO0o / OoO0O00 + ooOoO0o
def lisp_parse_packet ( lisp_sockets , packet , source , udp_sport , ttl = - 1 ) :
 O0o = False
 IIIOOo0o = time . time ( )
 if 21 - 21: II111iiii - OOooOOo * O0
 I11 = lisp_control_header ( )
 if ( I11 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return ( O0o )
  if 52 - 52: IiII / I1IiiI - o0oOOo0O0Ooo
  if 6 - 6: I1ii11iIi11i / OOooOOo
  if 92 - 92: OOooOOo % OOooOOo
  if 67 - 67: iII111i + I1ii11iIi11i - IiII . iII111i + iIii1I11I1II1
  if 40 - 40: II111iiii - oO0o / OoO0O00 / OoOoOO00 / Oo0Ooo
 I11iiiOOoOooO = source
 if ( source . find ( "lisp" ) == - 1 ) :
  OOo0oOO0o0oo0 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  OOo0oOO0o0oo0 . string_to_afi ( source )
  OOo0oOO0o0oo0 . store_address ( source )
  source = OOo0oOO0o0oo0
  if 10 - 10: I1Ii111 + I1IiiI . iIii1I11I1II1 + IiII / i11iIiiIii - O0
  if 27 - 27: OoooooooOO / I1ii11iIi11i
 if ( I11 . type == LISP_MAP_REQUEST ) :
  lisp_process_map_request ( lisp_sockets , packet , None , 0 , source ,
 udp_sport , False , ttl , IIIOOo0o )
  if 87 - 87: I11i + IiII / OOooOOo
 elif ( I11 . type == LISP_MAP_REPLY ) :
  lisp_process_map_reply ( lisp_sockets , packet , source , ttl , IIIOOo0o )
  if 70 - 70: II111iiii
 elif ( I11 . type == LISP_MAP_REGISTER ) :
  lisp_process_map_register ( lisp_sockets , packet , source , udp_sport )
  if 21 - 21: i11iIiiIii . iII111i * O0 - iII111i
 elif ( I11 . type == LISP_MAP_NOTIFY ) :
  if ( I11iiiOOoOooO == "lisp-etr" ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-rtr" ) ) :
   lisp_process_multicast_map_notify ( packet , source )
  elif ( lisp_is_running ( "lisp-itr" ) ) :
   lisp_process_unicast_map_notify ( lisp_sockets , packet , source )
   if 5 - 5: O0 . OoOoOO00 / iII111i
   if 78 - 78: Ii1I - I1ii11iIi11i + iIii1I11I1II1 + OoooooooOO . OoO0O00 - ooOoO0o
 elif ( I11 . type == LISP_MAP_NOTIFY_ACK ) :
  lisp_process_map_notify_ack ( packet , source )
  if 81 - 81: o0oOOo0O0Ooo * OoooooooOO
 elif ( I11 . type == LISP_MAP_REFERRAL ) :
  lisp_process_map_referral ( lisp_sockets , packet , source )
  if 32 - 32: OoOoOO00 - I11i * i11iIiiIii . I1ii11iIi11i . IiII . iIii1I11I1II1
 elif ( I11 . type == LISP_NAT_INFO and I11 . is_info_reply ( ) ) :
  O0O0oOO , Ooooo00OO , O0o = lisp_process_info_reply ( source , packet , True )
  if 41 - 41: iII111i / OoOoOO00 / OoO0O00 / ooOoO0o
 elif ( I11 . type == LISP_NAT_INFO and I11 . is_info_reply ( ) == False ) :
  O00oO000Oo0 = source . print_address_no_iid ( )
  lisp_process_info_request ( lisp_sockets , packet , O00oO000Oo0 , udp_sport ,
 None )
  if 16 - 16: iIii1I11I1II1 . II111iiii
 elif ( I11 . type == LISP_ECM ) :
  lisp_process_ecm ( lisp_sockets , packet , source , udp_sport )
  if 80 - 80: Oo0Ooo + IiII
 else :
  I1II1I1I = source . print_address ( )
  lprint ( "Invalid LISP control packet type {} from {}:" . format ( I11 . type , I1II1I1I ) )
  lprint ( lisp_format_packet ( packet ) )
  if 18 - 18: OoO0O00 . Oo0Ooo
  if 52 - 52: OoOoOO00 . iIii1I11I1II1 / OoOoOO00
 return ( O0o )
 if 14 - 14: i1IIi
 if 63 - 63: OoOoOO00 . i11iIiiIii / IiII
 if 36 - 36: OOooOOo * OoOoOO00 + i11iIiiIii + O0 + O0
 if 18 - 18: Oo0Ooo . I1ii11iIi11i * ooOoO0o % Ii1I + I1ii11iIi11i
 if 23 - 23: oO0o / o0oOOo0O0Ooo + I11i % IiII * OoO0O00
 if 48 - 48: OoO0O00
 if 30 - 30: iIii1I11I1II1
def lisp_process_rloc_probe_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp ) :
 if 53 - 53: II111iiii
 I1i1I = bold ( "RLOC-probe" , False )
 if 40 - 40: Ii1I % oO0o
 if ( lisp_i_am_etr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( I1i1I ) )
  lisp_etr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 69 - 69: iIii1I11I1II1 - O0 . I1Ii111 % I1IiiI / o0oOOo0O0Ooo
  if 78 - 78: oO0o
 if ( lisp_i_am_rtr ) :
  lprint ( "Received {} Map-Request, send RLOC-probe Map-Reply" . format ( I1i1I ) )
  lisp_rtr_process_map_request ( lisp_sockets , map_request , source , port ,
 ttl , timestamp )
  return
  if 20 - 20: i1IIi + i1IIi * i1IIi
  if 32 - 32: I1IiiI + IiII + iII111i . iIii1I11I1II1 * Ii1I
 lprint ( "Ignoring received {} Map-Request, not an ETR or RTR" . format ( I1i1I ) )
 return
 if 27 - 27: oO0o + Ii1I . i11iIiiIii
 if 97 - 97: iII111i . I1IiiI
 if 71 - 71: OOooOOo - IiII % oO0o * I1ii11iIi11i
 if 48 - 48: o0oOOo0O0Ooo * iIii1I11I1II1 + Oo0Ooo
 if 45 - 45: oO0o
def lisp_process_smr ( map_request ) :
 lprint ( "Received SMR-based Map-Request" )
 return
 if 50 - 50: Ii1I * Ii1I / O0 . Oo0Ooo + iII111i
 if 9 - 9: OoooooooOO % O0 % I1ii11iIi11i
 if 100 - 100: i11iIiiIii - iII111i - I11i
 if 5 - 5: oO0o % IiII * iII111i
 if 98 - 98: iII111i / OOooOOo + IiII
def lisp_process_smr_invoked_request ( map_request ) :
 lprint ( "Received SMR-invoked Map-Request" )
 return
 if 100 - 100: II111iiii . i11iIiiIii / oO0o - OOooOOo + OoOoOO00 % I1ii11iIi11i
 if 82 - 82: ooOoO0o % OOooOOo % Ii1I
 if 82 - 82: I1ii11iIi11i
 if 52 - 52: i11iIiiIii % I1Ii111 - iII111i / O0 - I1ii11iIi11i / iII111i
 if 7 - 7: OoooooooOO . OOooOOo . OOooOOo
 if 53 - 53: OOooOOo * OoOoOO00 % iII111i
 if 86 - 86: OOooOOo . OOooOOo + IiII - I1ii11iIi11i . OoO0O00
def lisp_build_map_reply ( eid , group , rloc_set , nonce , action , ttl , map_request ,
 keys , enc , auth , mr_ttl = - 1 ) :
 if 66 - 66: I1IiiI * OoOoOO00 . I1IiiI / Oo0Ooo - Ii1I
 OoO000Oo000 = map_request . rloc_probe if ( map_request != None ) else False
 O0OOoOO000 = map_request . json_telemetry if ( map_request != None ) else None
 if 42 - 42: iIii1I11I1II1 + iIii1I11I1II1 . I11i
 if 27 - 27: OoOoOO00 * Oo0Ooo - ooOoO0o
 OOoOOOO0ooooo = lisp_map_reply ( )
 OOoOOOO0ooooo . rloc_probe = OoO000Oo000
 OOoOOOO0ooooo . echo_nonce_capable = enc
 OOoOOOO0ooooo . hop_count = 0 if ( mr_ttl == - 1 ) else mr_ttl
 OOoOOOO0ooooo . record_count = 1
 OOoOOOO0ooooo . nonce = nonce
 Oo00O0o0O = OOoOOOO0ooooo . encode ( )
 OOoOOOO0ooooo . print_map_reply ( )
 if 70 - 70: I1ii11iIi11i + iII111i . O0 . I1ii11iIi11i + Oo0Ooo / OOooOOo
 iIiiIi11Iii = lisp_eid_record ( )
 iIiiIi11Iii . rloc_count = len ( rloc_set )
 if ( O0OOoOO000 != None ) : iIiiIi11Iii . rloc_count += 1
 iIiiIi11Iii . authoritative = auth
 iIiiIi11Iii . record_ttl = ttl
 iIiiIi11Iii . action = action
 iIiiIi11Iii . eid = eid
 iIiiIi11Iii . group = group
 if 34 - 34: iIii1I11I1II1 / Ii1I % ooOoO0o
 Oo00O0o0O += iIiiIi11Iii . encode ( )
 iIiiIi11Iii . print_record ( "  " , False )
 if 26 - 26: I1ii11iIi11i . IiII + II111iiii - Oo0Ooo
 IiIII11Ii11 = lisp_get_all_addresses ( ) + lisp_get_all_translated_rlocs ( )
 if 38 - 38: I1IiiI - OOooOOo * OoOoOO00 + O0 * I1IiiI
 iiiII = None
 for oO0o0 in rloc_set :
  I1iI1III = oO0o0 . rloc . is_multicast_address ( )
  ooO0 = lisp_rloc_record ( )
  OOoO0o0Oo0o = OoO000Oo000 and ( I1iI1III or O0OOoOO000 == None )
  O00oO000Oo0 = oO0o0 . rloc . print_address_no_iid ( )
  if ( O00oO000Oo0 in IiIII11Ii11 or I1iI1III ) :
   ooO0 . local_bit = True
   ooO0 . probe_bit = OOoO0o0Oo0o
   ooO0 . keys = keys
   if ( oO0o0 . priority == 254 and lisp_i_am_rtr ) :
    ooO0 . rloc_name = "RTR"
    if 72 - 72: iIii1I11I1II1
   if ( iiiII == None ) :
    if ( oO0o0 . translated_rloc . is_null ( ) ) :
     iiiII = oO0o0 . rloc
    else :
     iiiII = oO0o0 . translated_rloc
     if 49 - 49: oO0o + iII111i + I1Ii111 . IiII . Ii1I
     if 51 - 51: oO0o - oO0o * OoooooooOO / oO0o * OoO0O00 / ooOoO0o
     if 22 - 22: oO0o - iIii1I11I1II1
  ooO0 . store_rloc_entry ( oO0o0 )
  ooO0 . reach_bit = True
  ooO0 . print_record ( "    " )
  Oo00O0o0O += ooO0 . encode ( )
  if 33 - 33: II111iiii * O0 + O0
  if 98 - 98: IiII * OoooooooOO . iII111i
  if 34 - 34: OoooooooOO + I1Ii111
  if 97 - 97: II111iiii + I11i + OOooOOo / i11iIiiIii - iII111i
  if 9 - 9: i1IIi - I1Ii111 + I1Ii111
 if ( O0OOoOO000 != None ) :
  ooO0 = lisp_rloc_record ( )
  if ( iiiII ) : ooO0 . rloc . copy_address ( iiiII )
  ooO0 . local_bit = True
  ooO0 . probe_bit = True
  ooO0 . reach_bit = True
  if ( lisp_i_am_rtr ) :
   ooO0 . priority = 254
   ooO0 . rloc_name = "RTR"
   if 81 - 81: II111iiii % I11i % O0 . I1Ii111 % ooOoO0o - O0
  Ooo = lisp_encode_telemetry ( O0OOoOO000 , eo = str ( time . time ( ) ) )
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
 iIiiIi11Iii = lisp_eid_record ( )
 if 47 - 47: i1IIi - IiII + oO0o / OoO0O00 . OOooOOo * I1ii11iIi11i
 OooO = 0
 if ( ddt_entry == None ) :
  iIiiIi11Iii . eid = eid
  iIiiIi11Iii . group = group
 else :
  OooO = len ( ddt_entry . delegation_set )
  iIiiIi11Iii . eid = ddt_entry . eid
  iIiiIi11Iii . group = ddt_entry . group
  ddt_entry . map_referrals_sent += 1
  if 90 - 90: O0
 iIiiIi11Iii . rloc_count = OooO
 iIiiIi11Iii . authoritative = True
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
   O0ooii = ddt_entry . delegation_set [ 0 ]
   if ( O0ooii . is_ddt_child ( ) ) :
    action = LISP_DDT_ACTION_NODE_REFERRAL
    if 88 - 88: iIii1I11I1II1 + OOooOOo . II111iiii / i11iIiiIii % OOooOOo % IiII
   if ( O0ooii . is_ms_child ( ) ) :
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
  iiIIi = ( lisp_i_am_ms and O0ooii . is_ms_peer ( ) == False )
  if 88 - 88: Ii1I * o0oOOo0O0Ooo / oO0o
  if 58 - 58: O0
 iIiiIi11Iii . action = action
 iIiiIi11Iii . ddt_incomplete = iiIIi
 iIiiIi11Iii . record_ttl = ttl
 if 43 - 43: O0 / i1IIi / I11i % I1IiiI
 Oo00O0o0O += iIiiIi11Iii . encode ( )
 iIiiIi11Iii . print_record ( "  " , True )
 if 82 - 82: i11iIiiIii * i11iIiiIii + I1Ii111 - I1ii11iIi11i * oO0o - Ii1I
 if ( OooO == 0 ) : return ( Oo00O0o0O )
 if 40 - 40: o0oOOo0O0Ooo + OoO0O00 % i1IIi % iII111i * I1Ii111
 for O0ooii in ddt_entry . delegation_set :
  ooO0 = lisp_rloc_record ( )
  ooO0 . rloc = O0ooii . delegate_address
  ooO0 . priority = O0ooii . priority
  ooO0 . weight = O0ooii . weight
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
 o0oOoo00 = map_request . nonce
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
 Oo00O0o0O = lisp_build_map_reply ( Iiii1II1 . eid , Iiii1II1 . group , Iiii1II1 . rloc_set , o0oOoo00 ,
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
  II1III = ( O00O000OO . is_private_address ( ) == False )
  I11i1i1 = O00O000OO . print_address_no_iid ( )
  if ( II1III and I11i1i1 in lisp_rtr_list and sport == 0 ) :
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
 o0oOoo00 = map_request . nonce
 if 3 - 3: I1ii11iIi11i - O0
 Ooo0O = map_request . target_eid
 i1I1IIIiII = map_request . target_group
 if 46 - 46: iII111i
 o0O00ooOo = [ ]
 for OOo0o000O0 in [ lisp_myrlocs [ 0 ] , lisp_myrlocs [ 1 ] ] :
  if ( OOo0o000O0 == None ) : continue
  iIIiIi1111iiIii = lisp_rloc ( )
  iIIiIi1111iiIii . rloc . copy_address ( OOo0o000O0 )
  iIIiIi1111iiIii . priority = 254
  o0O00ooOo . append ( iIIiIi1111iiIii )
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
 Oo00O0o0O = lisp_build_map_reply ( Ooo0O , i1I1IIIiII , o0O00ooOo , o0oOoo00 , LISP_NO_ACTION ,
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
 Ii = [ ]
 for oO0o0 in o0O00ooOo :
  if ( oO0o0 . is_rtr ( ) ) : continue
  if ( oO0o0 . rloc . is_private_address ( ) ) :
   II11iIIII1 = copy . deepcopy ( oO0o0 )
   Ii . append ( II11iIIII1 )
   continue
   if 39 - 39: OoO0O00 % I1Ii111 * I11i * Ii1I
  O000oOooO0oo = oO0o0
  break
  if 84 - 84: Oo0Ooo / OoO0O00 - II111iiii - OoOoOO00 - O0
 if ( O000oOooO0oo == None ) : return ( o0O00ooOo )
 O000oOooO0oo = O000oOooO0oo . rloc . print_address_no_iid ( )
 if 18 - 18: oO0o * I11i / o0oOOo0O0Ooo - OoooooooOO
 if 21 - 21: O0 - OoooooooOO
 if 21 - 21: iII111i * o0oOOo0O0Ooo
 if 85 - 85: I1ii11iIi11i . OoOoOO00 . i1IIi % OOooOOo * I11i . I1Ii111
 I1II1i1 = None
 for oO0o0 in I111i111iI1 . registered_rlocs :
  if ( oO0o0 . is_rtr ( ) ) : continue
  if ( oO0o0 . rloc . is_private_address ( ) ) : continue
  I1II1i1 = oO0o0
  break
  if 47 - 47: II111iiii + I1ii11iIi11i + O0 / OOooOOo . I11i
 if ( I1II1i1 == None ) : return ( o0O00ooOo )
 I1II1i1 = I1II1i1 . rloc . print_address_no_iid ( )
 if 38 - 38: Ii1I + OoOoOO00 % I1Ii111 % iII111i
 if 72 - 72: OoOoOO00 * I1ii11iIi11i + iIii1I11I1II1
 if 51 - 51: oO0o + I1IiiI - I1Ii111 * Oo0Ooo . II111iiii
 if 63 - 63: I1ii11iIi11i - ooOoO0o - II111iiii + II111iiii
 IIIi1IIiI = target_site_eid . site_id
 if ( IIIi1IIiI == 0 ) :
  if ( I1II1i1 == O000oOooO0oo ) :
   lprint ( "Return private RLOCs for sites behind {}" . format ( O000oOooO0oo ) )
   if 17 - 17: I1ii11iIi11i % OoO0O00 % oO0o
   return ( Ii )
   if 60 - 60: i1IIi % Ii1I - O0 / iII111i
  return ( o0O00ooOo )
  if 14 - 14: i1IIi * OoooooooOO . IiII
  if 26 - 26: O0
  if 70 - 70: i1IIi % IiII % iIii1I11I1II1 . II111iiii * Oo0Ooo . o0oOOo0O0Ooo
  if 33 - 33: iIii1I11I1II1 / OoooooooOO / I1IiiI + II111iiii
  if 42 - 42: OoOoOO00 / i1IIi * O0
  if 46 - 46: OOooOOo - I1Ii111 + I1IiiI - ooOoO0o
  if 96 - 96: IiII + i1IIi - I11i * I11i - OoO0O00 % II111iiii
 if ( IIIi1IIiI == I111i111iI1 . site_id ) :
  lprint ( "Return private RLOCs for sites in site-id {}" . format ( IIIi1IIiI ) )
  return ( Ii )
  if 47 - 47: I1Ii111 . i11iIiiIii + oO0o . I1ii11iIi11i
 return ( o0O00ooOo )
 if 12 - 12: iIii1I11I1II1 % I1Ii111 * OoOoOO00 / OoooooooOO % OoooooooOO
 if 81 - 81: iIii1I11I1II1 - Oo0Ooo - ooOoO0o . OoO0O00 + I1ii11iIi11i
 if 84 - 84: iII111i . OOooOOo . iII111i * oO0o % Ii1I . oO0o
 if 86 - 86: iII111i * ooOoO0o / iIii1I11I1II1 + Ii1I . iII111i
 if 64 - 64: IiII - Oo0Ooo % iII111i % I11i
 if 42 - 42: Oo0Ooo . OoO0O00
 if 22 - 22: ooOoO0o - o0oOOo0O0Ooo + I11i / I1IiiI + OOooOOo
 if 10 - 10: oO0o / I1IiiI
 if 95 - 95: II111iiii - IiII % IiII . o0oOOo0O0Ooo
def lisp_get_partial_rloc_set ( registered_rloc_set , mr_source , multicast ) :
 IiI1iiiI1I1 = [ ]
 o0O00ooOo = [ ]
 if 3 - 3: I1Ii111 . i1IIi
 if 3 - 3: O0 + i1IIi - OOooOOo / I1Ii111
 if 13 - 13: oO0o + Oo0Ooo + Oo0Ooo / OoO0O00 + i1IIi + I1IiiI
 if 56 - 56: OoOoOO00
 if 10 - 10: iIii1I11I1II1 + i1IIi * Ii1I / iIii1I11I1II1 % OoOoOO00 / O0
 if 14 - 14: O0
 o0OOO = False
 II1I11Ii = False
 for oO0o0 in registered_rloc_set :
  if ( oO0o0 . priority != 254 ) : continue
  II1I11Ii |= True
  if ( oO0o0 . rloc . is_exact_match ( mr_source ) == False ) : continue
  o0OOO = True
  break
  if 89 - 89: oO0o % i11iIiiIii - iIii1I11I1II1 + oO0o
  if 15 - 15: I1ii11iIi11i - I1IiiI % OOooOOo
  if 9 - 9: Ii1I / O0
  if 95 - 95: iII111i / I11i
  if 86 - 86: O0 / II111iiii . Oo0Ooo / Oo0Ooo * II111iiii
  if 22 - 22: Ii1I
  if 81 - 81: iIii1I11I1II1 . ooOoO0o % I11i
 if ( II1I11Ii == False ) : return ( registered_rloc_set )
 if 64 - 64: I1Ii111 . Oo0Ooo * o0oOOo0O0Ooo
 if 32 - 32: oO0o . I1Ii111 * I1Ii111
 if 32 - 32: I1Ii111 . Ii1I / i1IIi
 if 2 - 2: OOooOOo * ooOoO0o / I11i + OoO0O00
 if 96 - 96: II111iiii * OoO0O00 + I1ii11iIi11i + OoOoOO00 / II111iiii . iII111i
 if 64 - 64: iII111i % Oo0Ooo
 if 79 - 79: IiII + iII111i / II111iiii . i1IIi + iIii1I11I1II1
 if 32 - 32: Ii1I * iII111i
 if 52 - 52: I11i
 if 100 - 100: Oo0Ooo % Oo0Ooo % I1ii11iIi11i
 i1Oo0o = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 57 - 57: II111iiii / i11iIiiIii . OoooooooOO
 if 98 - 98: O0
 if 27 - 27: oO0o * OoooooooOO * oO0o
 if 23 - 23: O0 . OoO0O00 . i1IIi
 if 19 - 19: O0 . OoooooooOO % iIii1I11I1II1 - Ii1I . Ii1I + I1IiiI
 for oO0o0 in registered_rloc_set :
  if ( i1Oo0o and oO0o0 . rloc . is_private_address ( ) ) : continue
  if ( multicast == False and oO0o0 . priority == 255 ) : continue
  if ( multicast and oO0o0 . mpriority == 255 ) : continue
  if ( oO0o0 . priority == 254 ) :
   IiI1iiiI1I1 . append ( oO0o0 )
  else :
   o0O00ooOo . append ( oO0o0 )
   if 98 - 98: oO0o . Oo0Ooo
   if 9 - 9: I1Ii111 % IiII - i11iIiiIii - OOooOOo % iII111i % OoooooooOO
   if 6 - 6: i1IIi - II111iiii * OoOoOO00 + oO0o
   if 6 - 6: I1IiiI - ooOoO0o + I1IiiI + OoO0O00 - i11iIiiIii % ooOoO0o
   if 64 - 64: OoooooooOO + OOooOOo
   if 36 - 36: I1IiiI - Ii1I / I1ii11iIi11i + Oo0Ooo % I1ii11iIi11i
 if ( o0OOO ) : return ( o0O00ooOo )
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
 if 94 - 94: Oo0Ooo
 if 10 - 10: i11iIiiIii / I1ii11iIi11i . i1IIi + i1IIi * iII111i
 o0O00ooOo = [ ]
 for oO0o0 in registered_rloc_set :
  if ( oO0o0 . rloc . is_ipv6 ( ) ) : o0O00ooOo . append ( oO0o0 )
  if ( oO0o0 . rloc . is_private_address ( ) ) : o0O00ooOo . append ( oO0o0 )
  if 64 - 64: II111iiii % I1ii11iIi11i . OoOoOO00 . iIii1I11I1II1 / I1ii11iIi11i
 o0O00ooOo += IiI1iiiI1I1
 return ( o0O00ooOo )
 if 43 - 43: OoooooooOO * I1IiiI
 if 2 - 2: OOooOOo / oO0o + I1ii11iIi11i + i11iIiiIii % iIii1I11I1II1 . I1ii11iIi11i
 if 100 - 100: Oo0Ooo * ooOoO0o + Ii1I / iII111i * o0oOOo0O0Ooo
 if 26 - 26: I1Ii111 * OoOoOO00
 if 38 - 38: II111iiii
 if 50 - 50: OoOoOO00 . IiII - OOooOOo
 if 46 - 46: iIii1I11I1II1
 if 97 - 97: O0 * OOooOOo - o0oOOo0O0Ooo % o0oOOo0O0Ooo * II111iiii % I11i
 if 65 - 65: iIii1I11I1II1 / OOooOOo
 if 2 - 2: I11i - OOooOOo / o0oOOo0O0Ooo
def lisp_store_pubsub_state ( reply_eid , itr_rloc , mr_sport , nonce , ttl , xtr_id ) :
 I1IIIi = lisp_pubsub ( itr_rloc , mr_sport , nonce , ttl , xtr_id )
 I1IIIi . add ( reply_eid )
 return ( I1IIIi )
 if 17 - 17: OoOoOO00 . I1IiiI
 if 30 - 30: i1IIi * OoOoOO00 * I11i . O0
 if 45 - 45: iII111i
 if 99 - 99: o0oOOo0O0Ooo % ooOoO0o % i11iIiiIii
 if 32 - 32: IiII - Ii1I
 if 44 - 44: OoooooooOO . oO0o
 if 30 - 30: I1Ii111 % IiII / II111iiii
 if 68 - 68: oO0o / O0 / OOooOOo
 if 3 - 3: o0oOOo0O0Ooo / o0oOOo0O0Ooo
 if 17 - 17: OoO0O00 * i1IIi
 if 50 - 50: OoOoOO00 + I11i
 if 56 - 56: OOooOOo * OOooOOo + I1IiiI % I1IiiI - I11i
 if 1 - 1: OoooooooOO . ooOoO0o - i1IIi
 if 73 - 73: iIii1I11I1II1 - I1Ii111 % Oo0Ooo . O0
 if 16 - 16: OoO0O00 / Oo0Ooo / IiII . Oo0Ooo - OoooooooOO
def lisp_convert_reply_to_notify ( packet ) :
 if 5 - 5: OoOoOO00 . I11i
 if 28 - 28: I11i % OOooOOo + Oo0Ooo / OoO0O00 % o0oOOo0O0Ooo + OoO0O00
 if 20 - 20: ooOoO0o . iII111i % OOooOOo + i11iIiiIii
 if 64 - 64: i1IIi . o0oOOo0O0Ooo * I1Ii111 - O0
 OOO0OO0OOoO = struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ]
 OOO0OO0OOoO = socket . ntohl ( OOO0OO0OOoO ) & 0xff
 o0oOoo00 = packet [ 4 : 12 ]
 packet = packet [ 12 : : ]
 if 3 - 3: Ii1I - I1IiiI + O0
 if 90 - 90: Ii1I + OoooooooOO . i11iIiiIii / Oo0Ooo % OoOoOO00 / IiII
 if 45 - 45: OoooooooOO / oO0o . I1ii11iIi11i + OOooOOo
 if 54 - 54: Ii1I - o0oOOo0O0Ooo + OoOoOO00 / OoooooooOO
 ooo = ( LISP_MAP_NOTIFY << 28 ) | OOO0OO0OOoO
 I11 = struct . pack ( "I" , socket . htonl ( ooo ) )
 I1IIiIi = struct . pack ( "I" , 0 )
 if 61 - 61: I11i / IiII % OoooooooOO - i11iIiiIii * i1IIi % o0oOOo0O0Ooo
 if 67 - 67: o0oOOo0O0Ooo - Ii1I
 if 29 - 29: OoOoOO00 . I1ii11iIi11i
 if 24 - 24: OOooOOo + i1IIi . I11i . OoOoOO00 + OoooooooOO
 packet = I11 + o0oOoo00 + I1IIiIi + packet
 return ( packet )
 if 98 - 98: ooOoO0o + i1IIi / I1IiiI
 if 1 - 1: IiII . OoooooooOO + II111iiii
 if 6 - 6: O0 * Oo0Ooo
 if 20 - 20: OoooooooOO * i1IIi * IiII / OoooooooOO - Oo0Ooo / i11iIiiIii
 if 28 - 28: iIii1I11I1II1 % OOooOOo * I1IiiI
 if 28 - 28: O0 . OoOoOO00
 if 27 - 27: I1ii11iIi11i / II111iiii + O0 % I1ii11iIi11i
 if 72 - 72: I1IiiI - i1IIi
def lisp_notify_subscribers ( lisp_sockets , eid_record , rloc_records ,
 registered_eid , site ) :
 if 11 - 11: iIii1I11I1II1 . OoO0O00 * Ii1I
 for oOoOO in lisp_pubsub_cache :
  for I1IIIi in list ( lisp_pubsub_cache [ oOoOO ] . values ( ) ) :
   oOO = I1IIIi . eid_prefix
   if ( oOO . is_more_specific ( registered_eid ) == False ) : continue
   if 45 - 45: I1IiiI % OOooOOo
   II1iIiiiIiI1 = I1IIIi . itr
   O0ooO0O00oo0 = I1IIIi . port
   iiI1i111I1 = red ( II1iIiiiIiI1 . print_address_no_iid ( ) , False )
   O0OoooO = bold ( "subscriber" , False )
   iIo0O00o00o0 = "0x" + lisp_hex_string ( I1IIIi . xtr_id )
   o0oOoo00 = "0x" + lisp_hex_string ( I1IIIi . nonce )
   if 81 - 81: OOooOOo * Ii1I
   lprint ( "    Notify {} {}:{} xtr-id {} for {}, nonce {}" . format ( O0OoooO , iiI1i111I1 , O0ooO0O00oo0 , iIo0O00o00o0 , green ( oOoOO , False ) , o0oOoo00 ) )
   if 23 - 23: OoooooooOO * OOooOOo
   if 24 - 24: IiII + I1IiiI / OoooooooOO
   if 8 - 8: II111iiii . I1Ii111 * OoOoOO00 / iII111i - Oo0Ooo
   if 17 - 17: iII111i . O0
   if 27 - 27: I11i + iIii1I11I1II1 - i11iIiiIii
   if 81 - 81: I11i + oO0o * iIii1I11I1II1 * IiII
   I1iII1iiI = copy . deepcopy ( eid_record )
   I1iII1iiI . eid . copy_address ( oOO )
   I1iII1iiI = I1iII1iiI . encode ( ) + rloc_records
   lisp_build_map_notify ( lisp_sockets , I1iII1iiI , [ oOoOO ] , 1 , II1iIiiiIiI1 ,
 O0ooO0O00oo0 , I1IIIi . nonce , 0 , 0 , 0 , site , False )
   if 11 - 11: iIii1I11I1II1 / O0 * I1Ii111 . OoooooooOO % OoooooooOO * I1Ii111
   I1IIIi . map_notify_count += 1
   if 63 - 63: IiII * oO0o * iIii1I11I1II1
   if 18 - 18: II111iiii * o0oOOo0O0Ooo % i11iIiiIii . OoOoOO00
 return
 if 40 - 40: oO0o - o0oOOo0O0Ooo * II111iiii
 if 4 - 4: O0
 if 9 - 9: Oo0Ooo . i1IIi - i1IIi + I1Ii111 * ooOoO0o . I1ii11iIi11i
 if 17 - 17: I11i * I1ii11iIi11i % I1IiiI + OoO0O00 + IiII
 if 90 - 90: OoooooooOO - I1IiiI / I1ii11iIi11i + oO0o - o0oOOo0O0Ooo
 if 84 - 84: OoOoOO00 + O0 % Oo0Ooo
 if 22 - 22: iIii1I11I1II1 % i11iIiiIii
def lisp_process_pubsub ( lisp_sockets , packet , reply_eid , itr_rloc , port , nonce ,
 ttl , xtr_id ) :
 if 29 - 29: ooOoO0o - iII111i + IiII % Ii1I - oO0o - ooOoO0o
 if 43 - 43: oO0o
 if 22 - 22: I1Ii111 + i11iIiiIii
 if 49 - 49: O0 % II111iiii . OOooOOo + iII111i + iIii1I11I1II1 / i11iIiiIii
 I1IIIi = lisp_store_pubsub_state ( reply_eid , itr_rloc , port , nonce , ttl ,
 xtr_id )
 if 79 - 79: II111iiii + ooOoO0o - i1IIi - i1IIi + II111iiii . i1IIi
 Ooo0O = green ( reply_eid . print_prefix ( ) , False )
 II1iIiiiIiI1 = red ( itr_rloc . print_address_no_iid ( ) , False )
 Oo00O0O0Oo0o0 = bold ( "Map-Notify" , False )
 xtr_id = "0x" + lisp_hex_string ( xtr_id )
 lprint ( "{} pubsub request for {} to ack ITR {} xtr-id: {}" . format ( Oo00O0O0Oo0o0 ,
 Ooo0O , II1iIiiiIiI1 , xtr_id ) )
 if 80 - 80: OoooooooOO * OoooooooOO . I1IiiI
 if 82 - 82: OoOoOO00 / oO0o - OoOoOO00 . I1IiiI
 if 17 - 17: OoOoOO00
 if 76 - 76: I1ii11iIi11i - ooOoO0o % OoooooooOO / Oo0Ooo % IiII / ooOoO0o
 packet = lisp_convert_reply_to_notify ( packet )
 lisp_send_map_notify ( lisp_sockets , packet , itr_rloc , port )
 I1IIIi . map_notify_count += 1
 return
 if 57 - 57: O0
 if 23 - 23: OoO0O00 / II111iiii . I1ii11iIi11i . O0
 if 13 - 13: I1ii11iIi11i
 if 32 - 32: OOooOOo / I11i + I1Ii111 / Oo0Ooo * OoooooooOO / II111iiii
 if 8 - 8: OoO0O00
 if 17 - 17: iIii1I11I1II1 - Oo0Ooo
 if 25 - 25: O0 + I1ii11iIi11i
 if 53 - 53: OoooooooOO . Oo0Ooo
def lisp_ms_process_map_request ( lisp_sockets , packet , map_request , mr_source ,
 mr_sport , ecm_source , ecm_sport ) :
 if 35 - 35: OOooOOo % i11iIiiIii % ooOoO0o . O0
 mr_sport = ecm_sport
 if 9 - 9: ooOoO0o + iII111i / i1IIi % Oo0Ooo - o0oOOo0O0Ooo / I1IiiI
 if 42 - 42: OOooOOo + oO0o % O0 * I1ii11iIi11i + i11iIiiIii
 if 16 - 16: i1IIi . I11i + OoO0O00 % Ii1I * IiII + I1IiiI
 if 96 - 96: II111iiii + O0 - II111iiii
 if 97 - 97: I1IiiI
 if 87 - 87: I11i + iIii1I11I1II1
 Ooo0O = map_request . target_eid
 i1I1IIIiII = map_request . target_group
 oOOoo = lisp_print_eid_tuple ( Ooo0O , i1I1IIIiII )
 O00O000OO = map_request . itr_rlocs [ 0 ]
 iIo0O00o00o0 = map_request . xtr_id
 o0oOoo00 = map_request . nonce
 oo0OoooOo0 = LISP_NO_ACTION
 I1IIIi = map_request . subscribe_bit
 oOOooO0oo = map_request . decent_nat_xtr
 if 66 - 66: OOooOOo / I1IiiI * I1IiiI - i11iIiiIii % Oo0Ooo . i11iIiiIii
 if 14 - 14: OoO0O00 . I1IiiI % I11i * iII111i / OoOoOO00
 if 16 - 16: OoO0O00 * ooOoO0o / II111iiii % OOooOOo . I1ii11iIi11i * i1IIi
 if 18 - 18: I1IiiI + OoOoOO00
 if 17 - 17: i1IIi . Ii1I
 OOoO = True
 iI1I111iI1I1I = ( lisp_get_eid_hash ( Ooo0O ) != None )
 if ( iI1I111iI1I1I ) :
  O00oooOoO = map_request . map_request_signature
  if ( O00oooOoO == None ) :
   OOoO = False
   lprint ( ( "EID-crypto-hash signature verification {}, " + "no signature found" ) . format ( bold ( "failed" , False ) ) )
   if 7 - 7: I1IiiI - OOooOOo % II111iiii / I1IiiI / i1IIi
  else :
   o0o00O0 = map_request . signature_eid
   oO , i1IIIi11III1 , OOoO = lisp_lookup_public_key ( o0o00O0 )
   if ( OOoO ) :
    OOoO = map_request . verify_map_request_sig ( i1IIIi11III1 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( o0o00O0 . print_address ( ) , oO . print_address ( ) ) )
    if 77 - 77: OOooOOo
    if 38 - 38: oO0o % OoO0O00 % oO0o . i11iIiiIii + o0oOOo0O0Ooo . i11iIiiIii
   oOOo0ooOo = bold ( "passed" , False ) if OOoO else bold ( "failed" , False )
   lprint ( "EID-crypto-hash signature verification {}" . format ( oOOo0ooOo ) )
   if 30 - 30: iIii1I11I1II1 - O0 % Oo0Ooo * OoooooooOO / I1IiiI
   if 65 - 65: OOooOOo % iIii1I11I1II1 / Oo0Ooo - o0oOOo0O0Ooo % I1Ii111
   if 96 - 96: IiII + o0oOOo0O0Ooo - I11i + I1IiiI . iII111i
 if ( I1IIIi and OOoO == False ) :
  I1IIIi = False
  lprint ( "Suppress creating pubsub state due to signature failure" )
  if 68 - 68: OoO0O00
  if 56 - 56: i11iIiiIii / I1Ii111 / II111iiii / oO0o
  if 35 - 35: OOooOOo / I1Ii111 . I1ii11iIi11i / OoooooooOO + I1Ii111 . I1Ii111
  if 52 - 52: O0 - I1Ii111 . oO0o
  if 43 - 43: IiII * Ii1I - I1ii11iIi11i * I1ii11iIi11i
  if 53 - 53: oO0o % I11i * OoO0O00 . i1IIi
  if 35 - 35: I11i . IiII + ooOoO0o
  if 19 - 19: O0 - i1IIi / I1Ii111
  if 14 - 14: I11i - i11iIiiIii
  if 49 - 49: oO0o . I1ii11iIi11i
  if 51 - 51: OOooOOo + o0oOOo0O0Ooo . OOooOOo
  if 23 - 23: iIii1I11I1II1 + OoO0O00 / I1IiiI
  if 48 - 48: OoOoOO00 + I11i + oO0o . I1IiiI
  if 7 - 7: iII111i * i1IIi % OoOoOO00 % Ii1I . I1IiiI
 O0O0o = O00O000OO if ( O00O000OO . afi == ecm_source . afi ) else ecm_source
 if 69 - 69: OoO0O00 + iIii1I11I1II1
 Ooo000oOOooO00 = lisp_site_eid_lookup ( Ooo0O , i1I1IIIiII , False )
 if 88 - 88: I1Ii111 . O0 - oO0o + i1IIi % Oo0Ooo
 if ( Ooo000oOOooO00 == None or Ooo000oOOooO00 . is_star_g ( ) ) :
  i1iiiiI1I = bold ( "Site not found" , False )
  lprint ( "{} for requested EID {}" . format ( i1iiiiI1I ,
 green ( oOOoo , False ) ) )
  if 28 - 28: i1IIi
  if 69 - 69: OOooOOo % ooOoO0o - i1IIi . Oo0Ooo
  if 35 - 35: iIii1I11I1II1 - I11i / iIii1I11I1II1 % ooOoO0o % I1IiiI
  if 46 - 46: oO0o
  lisp_send_negative_map_reply ( lisp_sockets , Ooo0O , i1I1IIIiII , o0oOoo00 , O00O000OO ,
 mr_sport , 15 , iIo0O00o00o0 , I1IIIi )
  if 5 - 5: i1IIi % o0oOOo0O0Ooo + OoOoOO00 - I11i . Ii1I
  return ( [ Ooo0O , i1I1IIIiII , LISP_DDT_ACTION_SITE_NOT_FOUND ] )
  if 33 - 33: II111iiii * o0oOOo0O0Ooo
  if 8 - 8: I1ii11iIi11i % o0oOOo0O0Ooo - IiII
 I1iii = Ooo000oOOooO00 . print_eid_tuple ( )
 OooOo0OO = Ooo000oOOooO00 . site . site_name
 if 42 - 42: ooOoO0o - I11i * iII111i
 if 39 - 39: OOooOOo - I1ii11iIi11i % IiII % I1ii11iIi11i * II111iiii - Ii1I
 if 19 - 19: I11i % OoOoOO00 / OoO0O00 % I11i + o0oOOo0O0Ooo / iII111i
 if 35 - 35: ooOoO0o % I11i * I1ii11iIi11i
 if 10 - 10: OoO0O00 + OoooooooOO + I1Ii111
 if ( iI1I111iI1I1I == False and Ooo000oOOooO00 . require_signature ) :
  O00oooOoO = map_request . map_request_signature
  o0o00O0 = map_request . signature_eid
  if ( O00oooOoO == None or o0o00O0 . is_null ( ) ) :
   lprint ( "Signature required for site {}" . format ( OooOo0OO ) )
   OOoO = False
  else :
   o0o00O0 = map_request . signature_eid
   oO , i1IIIi11III1 , OOoO = lisp_lookup_public_key ( o0o00O0 )
   if ( OOoO ) :
    OOoO = map_request . verify_map_request_sig ( i1IIIi11III1 )
   else :
    lprint ( "Public-key lookup failed for sig-eid {}, hash-eid {}" . format ( o0o00O0 . print_address ( ) , oO . print_address ( ) ) )
    if 57 - 57: Ii1I % Ii1I * Oo0Ooo % i11iIiiIii
    if 12 - 12: oO0o . Oo0Ooo . I1IiiI - i11iIiiIii / o0oOOo0O0Ooo
   oOOo0ooOo = bold ( "passed" , False ) if OOoO else bold ( "failed" , False )
   lprint ( "Required signature verification {}" . format ( oOOo0ooOo ) )
   if 54 - 54: i11iIiiIii + I1Ii111 . I1Ii111 * I1ii11iIi11i % I1Ii111 - OoooooooOO
   if 76 - 76: IiII + i1IIi + i11iIiiIii . oO0o
   if 23 - 23: ooOoO0o - OoO0O00 + oO0o . OOooOOo - I1IiiI
   if 66 - 66: iII111i % iII111i
   if 59 - 59: II111iiii . i1IIi % i1IIi
   if 40 - 40: I1Ii111 . II111iiii * o0oOOo0O0Ooo + I11i - i1IIi
 if ( OOoO and Ooo000oOOooO00 . registered == False ) :
  lprint ( "Site '{}' with EID-prefix {} is not registered for EID {}" . format ( OooOo0OO , green ( I1iii , False ) , green ( oOOoo , False ) ) )
  if 67 - 67: o0oOOo0O0Ooo - O0 - i1IIi . ooOoO0o . iII111i
  if 43 - 43: II111iiii . o0oOOo0O0Ooo + i11iIiiIii . O0 / O0 . II111iiii
  if 13 - 13: Ii1I % i11iIiiIii
  if 3 - 3: ooOoO0o % OoOoOO00 * I1Ii111 - OoO0O00 / i1IIi % I1IiiI
  if 50 - 50: I1ii11iIi11i + iII111i
  if 64 - 64: oO0o
  if ( Ooo000oOOooO00 . accept_more_specifics == False ) :
   Ooo0O = Ooo000oOOooO00 . eid
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
  lisp_send_negative_map_reply ( lisp_sockets , Ooo0O , i1I1IIIiII , o0oOoo00 , O00O000OO ,
 mr_sport , o0ooo000o00O , iIo0O00o00o0 , I1IIIi , not_reg_yet = O0oO )
  if 21 - 21: OoO0O00 % Oo0Ooo . o0oOOo0O0Ooo + IiII
  return ( [ Ooo0O , i1I1IIIiII , LISP_DDT_ACTION_MS_NOT_REG ] )
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
  Iii1IiIII = ( oOOooO0oo == False )
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
  I1i1I = lisp_policies [ Ooo000oOOooO00 . policy ]
  if ( I1i1I . match_policy_map_request ( map_request , mr_source ) ) : IiiiI11111I1 = I1i1I
  if 96 - 96: iII111i + ooOoO0o
  if ( IiiiI11111I1 ) :
   o0OoOo0O00 = bold ( "matched" , False )
   lprint ( "Map-Request {} policy '{}', set-action '{}'" . format ( o0OoOo0O00 ,
 I1i1I . policy_name , I1i1I . set_action ) )
  else :
   o0OoOo0O00 = bold ( "no match" , False )
   lprint ( "Map-Request {} for policy '{}', implied drop" . format ( o0OoOo0O00 ,
 I1i1I . policy_name ) )
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
    Ii = lisp_get_partial_rloc_set ( o0O00ooOo , O0O0o , I1Iii1II )
    if ( Ii != o0O00ooOo ) :
     o0ooo000o00O = 15
     o0O00ooOo = Ii
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
    iIIiIi1111iiIii = IiiiI11111I1 . set_policy_map_reply ( )
    if ( iIIiIi1111iiIii ) : o0O00ooOo = [ iIIiIi1111iiIii ]
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
  if ( OOoO ) :
   Ooo0000O = Ooo000oOOooO00 . eid
   iIi111iii = Ooo000oOOooO00 . group
  else :
   Ooo0000O = Ooo0O
   iIi111iii = i1I1IIIiII
   oo0OoooOo0 = LISP_AUTH_FAILURE_ACTION
   o0O00ooOo = [ ]
   if 42 - 42: I1ii11iIi11i . OOooOOo
   if 83 - 83: I1IiiI . ooOoO0o . II111iiii % OOooOOo
   if 86 - 86: i11iIiiIii + I1ii11iIi11i / OoOoOO00 * OoooooooOO
   if 6 - 6: II111iiii
   if 26 - 26: iIii1I11I1II1 / iIii1I11I1II1 . IiII * i11iIiiIii
   if 21 - 21: OOooOOo + o0oOOo0O0Ooo
  if ( I1IIIi ) :
   Ooo0000O = Ooo0O
   iIi111iii = i1I1IIIiII
   if 28 - 28: OOooOOo + i1IIi + II111iiii / Oo0Ooo + iIii1I11I1II1 . Oo0Ooo
   if 73 - 73: Ii1I * iIii1I11I1II1 / o0oOOo0O0Ooo - o0oOOo0O0Ooo / i1IIi
   if 64 - 64: Ii1I * I1ii11iIi11i % II111iiii
   if 31 - 31: iIii1I11I1II1 % Oo0Ooo . I1IiiI % ooOoO0o
   if 38 - 38: I1ii11iIi11i + I1Ii111 * I11i / OoO0O00 + o0oOOo0O0Ooo
   if 46 - 46: iII111i
  packet = lisp_build_map_reply ( Ooo0000O , iIi111iii , o0O00ooOo ,
 o0oOoo00 , oo0OoooOo0 , o0ooo000o00O , map_request , None , iiiIiIIi1 , False )
  if 56 - 56: Oo0Ooo / II111iiii
  if ( I1IIIi ) :
   lisp_process_pubsub ( lisp_sockets , packet , Ooo0000O , O00O000OO ,
 mr_sport , o0oOoo00 , o0ooo000o00O , iIo0O00o00o0 )
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
 ooo00OoOooooo = map_request . target_eid . hash_address ( OOOo0OOO )
 ooo00OoOooooo %= OooO
 O0o0 = Ooo000oOOooO00 . registered_rlocs [ ooo00OoOooooo ]
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
 Ooo0O = map_request . target_eid
 i1I1IIIiII = map_request . target_group
 oOOoo = lisp_print_eid_tuple ( Ooo0O , i1I1IIIiII )
 o0oOoo00 = map_request . nonce
 oo0OoooOo0 = LISP_DDT_ACTION_NULL
 if 88 - 88: iIii1I11I1II1 . OOooOOo % iII111i
 if 72 - 72: ooOoO0o + i11iIiiIii / i1IIi
 if 64 - 64: OOooOOo - OOooOOo
 if 42 - 42: i1IIi / ooOoO0o . I1Ii111 % OoOoOO00
 if 67 - 67: i1IIi * i11iIiiIii * I1IiiI
 i1111I = None
 if ( lisp_i_am_ms ) :
  Ooo000oOOooO00 = lisp_site_eid_lookup ( Ooo0O , i1I1IIIiII , False )
  if ( Ooo000oOOooO00 == None ) : return
  if 30 - 30: OoO0O00 + I1IiiI
  if ( Ooo000oOOooO00 . registered ) :
   oo0OoooOo0 = LISP_DDT_ACTION_MS_ACK
   o0ooo000o00O = 1440
  else :
   Ooo0O , i1I1IIIiII , oo0OoooOo0 = lisp_ms_compute_neg_prefix ( Ooo0O , i1I1IIIiII )
   oo0OoooOo0 = LISP_DDT_ACTION_MS_NOT_REG
   o0ooo000o00O = 1
   if 4 - 4: I11i
 else :
  i1111I = lisp_ddt_cache_lookup ( Ooo0O , i1I1IIIiII , False )
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
    Ooo0O = lisp_ddt_compute_neg_prefix ( Ooo0O , i1111I ,
 lisp_ddt_cache )
   else :
    i1I1IIIiII = lisp_ddt_compute_neg_prefix ( i1I1IIIiII , i1111I ,
 lisp_ddt_cache )
    Ooo0O = lisp_ddt_compute_neg_prefix ( Ooo0O , i1111I ,
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
 Oo00O0o0O = lisp_build_map_referral ( Ooo0O , i1I1IIIiII , i1111I , oo0OoooOo0 , o0ooo000o00O , o0oOoo00 )
 o0oOoo00 = map_request . nonce >> 32
 if ( map_request . nonce != 0 and o0oOoo00 != 0xdfdf0e1d ) : port = LISP_CTRL_PORT
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
 I1ioOo = 0
 if 87 - 87: I11i
 if 67 - 67: i1IIi / i1IIi + IiII . oO0o
 if 70 - 70: i1IIi . I11i * o0oOOo0O0Ooo . iII111i
 if 75 - 75: oO0o * OoO0O00 * I11i + oO0o + O0 . I1Ii111
 for I1ioOo in range ( I111i1I1iii ) :
  IIIiI = 1 << ( I111i1I1iii - I1ioOo - 1 )
  if ( OO0000 & IIIiI ) : break
  if 56 - 56: oO0o % I11i + Ii1I
  if 76 - 76: I1Ii111 / iIii1I11I1II1 * I1ii11iIi11i / I1Ii111
 if ( I1ioOo > neg_prefix . mask_len ) : neg_prefix . mask_len = I1ioOo
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
 Ooo0O , iI1ioOo0O0O , o000O0OO00oOO = parms
 if 3 - 3: I11i
 if ( iI1ioOo0O0O == None ) :
  if ( entry . eid . instance_id != Ooo0O . instance_id ) :
   return ( [ True , parms ] )
   if 18 - 18: I1ii11iIi11i % I1IiiI + I1IiiI / II111iiii + I1ii11iIi11i
  if ( entry . eid . afi != Ooo0O . afi ) : return ( [ True , parms ] )
 else :
  if ( entry . eid . is_more_specific ( iI1ioOo0O0O ) == False ) :
   return ( [ True , parms ] )
   if 76 - 76: OOooOOo
   if 45 - 45: ooOoO0o % o0oOOo0O0Ooo . II111iiii . I1Ii111
   if 52 - 52: OoooooooOO / IiII / IiII
   if 30 - 30: ooOoO0o % I11i + II111iiii . IiII - I1IiiI * OoOoOO00
   if 59 - 59: I1IiiI
   if 19 - 19: i1IIi * I1Ii111
 lisp_find_negative_mask_len ( Ooo0O , entry . eid , o000O0OO00oOO )
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
 Ooo0O = map_request . target_eid
 i1I1IIIiII = map_request . target_group
 o0oOoo00 = map_request . nonce
 if 10 - 10: I11i
 if ( action == LISP_DDT_ACTION_MS_ACK ) : o0ooo000o00O = 1440
 if 24 - 24: Ii1I
 if 30 - 30: II111iiii / Ii1I - I11i - OoO0O00
 if 25 - 25: I11i % i1IIi / I11i * i11iIiiIii
 if 71 - 71: IiII % I11i - OoooooooOO + I1IiiI / Oo0Ooo % I11i
 oOooOO0OO = lisp_map_referral ( )
 oOooOO0OO . record_count = 1
 oOooOO0OO . nonce = o0oOoo00
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
  eid_prefix , group_prefix , action = lisp_ms_compute_neg_prefix ( Ooo0O ,
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
 i1111I = lisp_ddt_cache_lookup ( Ooo0O , i1I1IIIiII , False )
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
 iIiiIi11Iii = lisp_eid_record ( )
 iIiiIi11Iii . rloc_count = OooO
 iIiiIi11Iii . authoritative = True
 iIiiIi11Iii . action = action
 iIiiIi11Iii . ddt_incomplete = iiIIi
 iIiiIi11Iii . eid = eid_prefix
 iIiiIi11Iii . group = group_prefix
 iIiiIi11Iii . record_ttl = o0ooo000o00O
 if 19 - 19: I1Ii111 + i1IIi % OoooooooOO + i1IIi
 Oo00O0o0O += iIiiIi11Iii . encode ( )
 iIiiIi11Iii . print_record ( "  " , True )
 if 16 - 16: I1Ii111 + II111iiii + IiII
 if 34 - 34: iIii1I11I1II1 - II111iiii - ooOoO0o + oO0o
 if 46 - 46: ooOoO0o % II111iiii
 if 61 - 61: OoO0O00 . I1IiiI
 if ( OooO != 0 ) :
  for O0ooii in i1111I . delegation_set :
   ooO0 = lisp_rloc_record ( )
   ooO0 . rloc = O0ooii . delegate_address
   ooO0 . priority = O0ooii . priority
   ooO0 . weight = O0ooii . weight
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
 o0oOoo00 = mr . nonce
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
  lprint ( "DDT Map-Request retry limit reached for EID {}, nonce 0x{}" . format ( green ( OOOooo , False ) , lisp_hex_string ( o0oOoo00 ) ) )
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
 lisp_hex_string ( o0oOoo00 ) ) )
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
 o0o = len ( O00OO0 )
 if ( o0o == 0 ) : return ( None )
 if 86 - 86: Ii1I - I1IiiI - iII111i % Ii1I . I1ii11iIi11i % i1IIi
 ooo00OoOooooo = dest_eid . hash_address ( source_eid )
 ooo00OoOooooo = ooo00OoOooooo % o0o
 return ( O00OO0 [ ooo00OoOooooo ] )
 if 84 - 84: OoOoOO00
 if 99 - 99: OoO0O00 - OoOoOO00 - i1IIi / OoO0O00 * I1ii11iIi11i * iIii1I11I1II1
 if 65 - 65: iII111i - O0 / i1IIi . I1Ii111
 if 85 - 85: o0oOOo0O0Ooo % Ii1I
 if 81 - 81: oO0o / OoO0O00 * i1IIi % iIii1I11I1II1
 if 23 - 23: II111iiii . II111iiii
 if 17 - 17: i11iIiiIii / IiII * I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - iIii1I11I1II1
def lisp_send_ddt_map_request ( mr , send_to_root ) :
 i11iIiIi1i = mr . lisp_sockets
 o0oOoo00 = mr . nonce
 II1iIiiiIiI1 = mr . itr
 OOOOoOOO = mr . mr_source
 oOOoo = mr . print_eid_tuple ( )
 if 47 - 47: II111iiii + iII111i / i1IIi * Ii1I . OoO0O00 + IiII
 if 7 - 7: i1IIi % O0 * ooOoO0o - OOooOOo % ooOoO0o * I1ii11iIi11i
 if 34 - 34: OoOoOO00 - I11i
 if 85 - 85: OoOoOO00 . oO0o
 if 98 - 98: I1Ii111
 if ( mr . send_count == 8 ) :
  lprint ( "Giving up on map-request-queue entry {}, nonce 0x{}" . format ( green ( oOOoo , False ) , lisp_hex_string ( o0oOoo00 ) ) )
  if 49 - 49: OoO0O00 / I1ii11iIi11i % IiII * II111iiii
  mr . dequeue_map_request ( )
  return
  if 92 - 92: iIii1I11I1II1 . OoooooooOO . ooOoO0o / II111iiii
  if 30 - 30: i1IIi * Ii1I + Ii1I / I1Ii111
  if 84 - 84: I1IiiI - Oo0Ooo * OoO0O00 * oO0o
  if 13 - 13: I1Ii111 * i11iIiiIii % o0oOOo0O0Ooo + oO0o - iII111i
  if 32 - 32: I1Ii111 / I1ii11iIi11i - Ii1I % o0oOOo0O0Ooo * I1Ii111 % II111iiii
  if 33 - 33: ooOoO0o % I11i
 if ( send_to_root ) :
  OOoo0o0O000 = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  O0oOooO = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  mr . tried_root = True
  lprint ( "Jumping up to root for EID {}" . format ( green ( oOOoo , False ) ) )
 else :
  OOoo0o0O000 = mr . eid
  O0oOooO = mr . group
  if 50 - 50: OOooOOo % i11iIiiIii
  if 99 - 99: IiII
  if 87 - 87: IiII
  if 35 - 35: oO0o . O0 . Ii1I / ooOoO0o
  if 36 - 36: i11iIiiIii . II111iiii . I11i . II111iiii
 I1i11I = lisp_referral_cache_lookup ( OOoo0o0O000 , O0oOooO , False )
 if ( I1i11I == None ) :
  lprint ( "No referral cache entry found" )
  lisp_send_negative_map_reply ( i11iIiIi1i , OOoo0o0O000 , O0oOooO ,
 o0oOoo00 , II1iIiiiIiI1 , mr . sport , 15 , None , False )
  return
  if 37 - 37: ooOoO0o
  if 56 - 56: Oo0Ooo * OoO0O00 . ooOoO0o . o0oOOo0O0Ooo
 OoOo00OoOo = I1i11I . print_eid_tuple ( )
 lprint ( "Found referral cache entry {}, referral-type: {}" . format ( OoOo00OoOo ,
 I1i11I . print_referral_type ( ) ) )
 if 68 - 68: i11iIiiIii / I1IiiI / i11iIiiIii
 oooOOo0o00 = lisp_get_referral_node ( I1i11I , OOOOoOOO , mr . eid )
 if ( oooOOo0o00 == None ) :
  lprint ( "No reachable referral-nodes found" )
  mr . dequeue_map_request ( )
  lisp_send_negative_map_reply ( i11iIiIi1i , I1i11I . eid ,
 I1i11I . group , o0oOoo00 , II1iIiiiIiI1 , mr . sport , 1 , None , False )
  return
  if 87 - 87: OoOoOO00 . OoO0O00 . I1Ii111 / Ii1I + Oo0Ooo % OoooooooOO
  if 78 - 78: OOooOOo - Ii1I * i1IIi . OoO0O00 - O0
 lprint ( "Send DDT Map-Request to {} {} for EID {}, nonce 0x{}" . format ( oooOOo0o00 . referral_address . print_address ( ) ,
 # O0 * I1Ii111 - II111iiii
 I1i11I . print_referral_type ( ) , green ( oOOoo , False ) ,
 lisp_hex_string ( o0oOoo00 ) ) )
 if 60 - 60: oO0o % oO0o
 if 76 - 76: I1Ii111 / o0oOOo0O0Ooo
 if 19 - 19: O0 . i1IIi % iIii1I11I1II1 + OOooOOo * OoOoOO00 / I11i
 if 82 - 82: I1ii11iIi11i
 o0o000Oo = ( I1i11I . referral_type == LISP_DDT_ACTION_MS_REFERRAL or
 I1i11I . referral_type == LISP_DDT_ACTION_MS_ACK )
 lisp_send_ecm ( i11iIiIi1i , mr . packet , OOOOoOOO , mr . sport , mr . eid ,
 oooOOo0o00 . referral_address , to_ms = o0o000Oo , ddt = True )
 if 89 - 89: I1IiiI / o0oOOo0O0Ooo % i1IIi * ooOoO0o
 if 59 - 59: I11i / OoOoOO00 % ooOoO0o . Ii1I
 if 48 - 48: OoOoOO00 % IiII % i1IIi + o0oOOo0O0Ooo
 if 33 - 33: iIii1I11I1II1 . O0
 mr . last_request_sent_to = oooOOo0o00 . referral_address
 mr . last_sent = lisp_get_timestamp ( )
 mr . send_count += 1
 oooOOo0o00 . map_requests_sent += 1
 return
 if 54 - 54: iIii1I11I1II1
 if 54 - 54: iII111i + OOooOOo + OoO0O00
 if 6 - 6: oO0o - OoooooooOO * iIii1I11I1II1 * I1ii11iIi11i
 if 65 - 65: IiII + OoOoOO00
 if 93 - 93: Ii1I
 if 43 - 43: iIii1I11I1II1 / iII111i - Ii1I + I11i % iII111i - OoO0O00
 if 5 - 5: OoO0O00 / ooOoO0o
 if 92 - 92: Oo0Ooo / iII111i + O0 * ooOoO0o * OOooOOo % Oo0Ooo
def lisp_mr_process_map_request ( lisp_sockets , packet , map_request , ecm_source ,
 sport , mr_source ) :
 if 97 - 97: oO0o / Ii1I
 Ooo0O = map_request . target_eid
 i1I1IIIiII = map_request . target_group
 OOOooo = map_request . print_eid_tuple ( )
 I1IiIiIi = mr_source . print_address ( )
 o0oOoo00 = map_request . nonce
 if 70 - 70: iII111i / Oo0Ooo . OoOoOO00 - II111iiii * II111iiii % I1IiiI
 OOo0oOO0o0oo0 = green ( I1IiIiIi , False )
 oooOo = green ( OOOooo , False )
 lprint ( "Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}" . format ( "P" if map_request . pitr_bit else "" ,
 # OoOoOO00 % I1Ii111 * OOooOOo
 red ( ecm_source . print_address ( ) , False ) , OOo0oOO0o0oo0 , oooOo ,
 lisp_hex_string ( o0oOoo00 ) ) )
 if 22 - 22: ooOoO0o % I1Ii111 . ooOoO0o + ooOoO0o * Ii1I
 if 69 - 69: I1Ii111
 if 48 - 48: Ii1I % I1ii11iIi11i + IiII % OoOoOO00
 if 95 - 95: iII111i * I11i * OoO0O00 - OoO0O00
 II1iI1iII11 = lisp_ddt_map_request ( lisp_sockets , packet , Ooo0O , i1I1IIIiII , o0oOoo00 )
 II1iI1iII11 . packet = packet
 II1iI1iII11 . itr = ecm_source
 II1iI1iII11 . mr_source = mr_source
 II1iI1iII11 . sport = sport
 II1iI1iII11 . from_pitr = map_request . pitr_bit
 II1iI1iII11 . queue_map_request ( )
 if 81 - 81: i11iIiiIii % ooOoO0o
 lisp_send_ddt_map_request ( II1iI1iII11 , False )
 return
 if 61 - 61: Oo0Ooo . IiII + OoOoOO00
 if 53 - 53: OoOoOO00
 if 43 - 43: I1ii11iIi11i * Oo0Ooo
 if 95 - 95: IiII + iII111i % I1IiiI
 if 18 - 18: Oo0Ooo
 if 8 - 8: O0 + iIii1I11I1II1 - O0
 if 67 - 67: O0
def lisp_process_map_request ( lisp_sockets , packet , ecm_source , ecm_port ,
 mr_source , mr_port , ddt_request , ttl , timestamp ) :
 if 22 - 22: I11i / i1IIi . II111iiii % ooOoO0o / I11i - Ii1I
 II1i1i = packet
 iiIIIIiI = lisp_map_request ( )
 packet = iiIIIIiI . decode ( packet , mr_source , mr_port )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Request packet" )
  return
  if 18 - 18: II111iiii + ooOoO0o / I1ii11iIi11i - I1Ii111 * I1Ii111 / I1ii11iIi11i
  if 10 - 10: iIii1I11I1II1
 iiIIIIiI . print_map_request ( )
 if 81 - 81: I1Ii111 - ooOoO0o * Oo0Ooo - OoO0O00 + I1ii11iIi11i
 if 16 - 16: iII111i * i1IIi - IiII + OOooOOo
 if 89 - 89: o0oOOo0O0Ooo . Oo0Ooo
 if 48 - 48: o0oOOo0O0Ooo / O0 % i1IIi
 if ( iiIIIIiI . rloc_probe ) :
  lisp_process_rloc_probe_request ( lisp_sockets , iiIIIIiI , mr_source ,
 mr_port , ttl , timestamp )
  return
  if 82 - 82: OoOoOO00 * Ii1I . I1ii11iIi11i * OoO0O00 % Oo0Ooo
  if 95 - 95: OoO0O00 / oO0o
  if 15 - 15: I1IiiI - o0oOOo0O0Ooo % iIii1I11I1II1 % I11i * OoOoOO00 % IiII
  if 74 - 74: iII111i - O0 * o0oOOo0O0Ooo / OoooooooOO + II111iiii + Ii1I
  if 39 - 39: i11iIiiIii . IiII + I1ii11iIi11i % IiII
 if ( iiIIIIiI . smr_bit ) :
  lisp_process_smr ( iiIIIIiI )
  if 96 - 96: I11i / I1IiiI . i1IIi
  if 67 - 67: i11iIiiIii
  if 3 - 3: IiII
  if 47 - 47: O0
  if 60 - 60: OOooOOo / ooOoO0o + Oo0Ooo / O0 - oO0o
 if ( iiIIIIiI . smr_invoked_bit ) :
  lisp_process_smr_invoked_request ( iiIIIIiI )
  if 23 - 23: I1ii11iIi11i . I1Ii111 + OOooOOo
  if 4 - 4: I1IiiI
  if 31 - 31: ooOoO0o * i1IIi . O0
  if 5 - 5: OOooOOo . I1ii11iIi11i + ooOoO0o . ooOoO0o + iII111i
  if 100 - 100: I1Ii111
 if ( lisp_i_am_etr ) :
  lisp_etr_process_map_request ( lisp_sockets , iiIIIIiI , mr_source ,
 mr_port , ttl , timestamp )
  if 71 - 71: ooOoO0o * i1IIi / OoOoOO00 * i11iIiiIii - iII111i
  if 88 - 88: IiII
  if 29 - 29: iII111i . ooOoO0o
  if 62 - 62: IiII
  if 95 - 95: ooOoO0o / i1IIi + II111iiii + OoO0O00 % OoO0O00
 if ( lisp_i_am_ms ) :
  packet = II1i1i
  Ooo0O , i1I1IIIiII , I1iI111i11i1 = lisp_ms_process_map_request ( lisp_sockets ,
 II1i1i , iiIIIIiI , mr_source , mr_port , ecm_source , ecm_port )
  if ( ddt_request ) :
   lisp_ms_send_map_referral ( lisp_sockets , iiIIIIiI , ecm_source ,
 ecm_port , I1iI111i11i1 , Ooo0O , i1I1IIIiII )
   if 96 - 96: I1IiiI . O0 / iIii1I11I1II1
  return
  if 95 - 95: ooOoO0o * OoO0O00 % OoooooooOO % OoO0O00
  if 79 - 79: II111iiii % Ii1I * oO0o * iII111i + II111iiii
  if 51 - 51: I1IiiI + iII111i + I1IiiI / Ii1I * IiII + OOooOOo
  if 70 - 70: I11i . IiII + IiII
  if 74 - 74: Ii1I
 if ( lisp_i_am_mr and not ddt_request ) :
  lisp_mr_process_map_request ( lisp_sockets , II1i1i , iiIIIIiI ,
 ecm_source , mr_port , mr_source )
  if 11 - 11: I1ii11iIi11i
  if 83 - 83: O0
  if 97 - 97: O0
  if 50 - 50: I1Ii111 / OoooooooOO . o0oOOo0O0Ooo + I1IiiI * i11iIiiIii
  if 28 - 28: I1Ii111 * II111iiii
 if ( lisp_i_am_ddt or ddt_request ) :
  packet = II1i1i
  lisp_ddt_process_map_request ( lisp_sockets , iiIIIIiI , ecm_source ,
 ecm_port )
  if 14 - 14: iIii1I11I1II1 / Ii1I + o0oOOo0O0Ooo . iII111i % iII111i . i1IIi
 return
 if 67 - 67: IiII * II111iiii + ooOoO0o - i11iIiiIii
 if 15 - 15: I11i
 if 67 - 67: iIii1I11I1II1
 if 91 - 91: ooOoO0o
 if 66 - 66: OOooOOo
 if 5 - 5: i1IIi * OoOoOO00 + i1IIi % I11i
 if 79 - 79: OOooOOo % iIii1I11I1II1 / OoOoOO00
 if 9 - 9: Ii1I
def lisp_store_mr_stats ( source , nonce ) :
 II1iI1iII11 = lisp_get_map_resolver ( source , None )
 if ( II1iI1iII11 == None ) : return
 if 44 - 44: iII111i
 if 46 - 46: I11i . i11iIiiIii * OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
 if 37 - 37: OoO0O00 - Ii1I + OoO0O00
 if 49 - 49: OoooooooOO - I1ii11iIi11i % I1ii11iIi11i / i1IIi . ooOoO0o
 II1iI1iII11 . neg_map_replies_received += 1
 II1iI1iII11 . last_reply = lisp_get_timestamp ( )
 if 60 - 60: Oo0Ooo
 if 46 - 46: OoOoOO00 + i1IIi
 if 43 - 43: II111iiii * IiII % iIii1I11I1II1 % i11iIiiIii % I1ii11iIi11i
 if 81 - 81: oO0o % I1ii11iIi11i % ooOoO0o * O0 - OOooOOo
 if ( ( II1iI1iII11 . neg_map_replies_received % 100 ) == 0 ) : II1iI1iII11 . total_rtt = 0
 if 17 - 17: O0 % O0 / I1ii11iIi11i . Oo0Ooo . iII111i
 if 4 - 4: OoO0O00
 if 65 - 65: Oo0Ooo % O0 / I1Ii111 * IiII - oO0o
 if 32 - 32: Ii1I * OoO0O00 + ooOoO0o
 if ( II1iI1iII11 . last_nonce == nonce ) :
  II1iI1iII11 . total_rtt += ( time . time ( ) - II1iI1iII11 . last_used )
  II1iI1iII11 . last_nonce = 0
  if 41 - 41: IiII + I11i * ooOoO0o + Oo0Ooo . ooOoO0o
 if ( ( II1iI1iII11 . neg_map_replies_received % 10 ) == 0 ) : II1iI1iII11 . last_nonce = 0
 return
 if 38 - 38: iII111i * OoooooooOO - IiII
 if 36 - 36: I1Ii111 * II111iiii + I1ii11iIi11i - iII111i * iII111i
 if 91 - 91: O0 + I1Ii111 * II111iiii - O0 . i11iIiiIii . Oo0Ooo
 if 54 - 54: ooOoO0o * I11i / I1ii11iIi11i % ooOoO0o
 if 76 - 76: I11i . I1IiiI
 if 66 - 66: oO0o % oO0o * IiII
 if 39 - 39: i1IIi * Ii1I + OoOoOO00 / oO0o
def lisp_process_map_reply ( lisp_sockets , packet , source , ttl , itr_in_ts ) :
 global lisp_map_cache
 if 6 - 6: I1ii11iIi11i / II111iiii / OoOoOO00 . i11iIiiIii - iII111i
 OOoOOOO0ooooo = lisp_map_reply ( )
 packet = OOoOOOO0ooooo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Reply packet" )
  return
  if 43 - 43: i11iIiiIii * i11iIiiIii * I1Ii111
 OOoOOOO0ooooo . print_map_reply ( )
 if 80 - 80: oO0o . I1IiiI * II111iiii + o0oOOo0O0Ooo / o0oOOo0O0Ooo % OoooooooOO
 if 31 - 31: o0oOOo0O0Ooo - OoO0O00 % I1IiiI
 if 23 - 23: OOooOOo
 if 97 - 97: Oo0Ooo / OoooooooOO . OoooooooOO
 iI11I1i = None
 for o000o0O0Oo00 in range ( OOoOOOO0ooooo . record_count ) :
  iIiiIi11Iii = lisp_eid_record ( )
  packet = iIiiIi11Iii . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Reply packet" )
   return
   if 99 - 99: IiII % O0 - I11i . iII111i
  iIiiIi11Iii . print_record ( "  " , False )
  if 11 - 11: I11i
  if 83 - 83: i11iIiiIii - ooOoO0o / O0
  if 43 - 43: i1IIi * OoOoOO00 % iIii1I11I1II1 % Ii1I
  if 57 - 57: OoO0O00 - iII111i - I1ii11iIi11i / Oo0Ooo . oO0o * Oo0Ooo
  if 6 - 6: i11iIiiIii + I1IiiI . iII111i
  if ( iIiiIi11Iii . rloc_count == 0 ) :
   lisp_store_mr_stats ( source , OOoOOOO0ooooo . nonce )
   if 13 - 13: II111iiii - oO0o . o0oOOo0O0Ooo
   if 82 - 82: Oo0Ooo * OoooooooOO / ooOoO0o / I1IiiI
  I1iI1III = ( iIiiIi11Iii . group . is_null ( ) == False )
  if 70 - 70: I1IiiI
  if 74 - 74: ooOoO0o * II111iiii
  if 96 - 96: i11iIiiIii . I1IiiI - II111iiii . I11i
  if 79 - 79: OoO0O00 . OoOoOO00 - i1IIi + Ii1I * i11iIiiIii . OoooooooOO
  if 83 - 83: o0oOOo0O0Ooo / oO0o
  if ( lisp_decent_push_configured ) :
   oo0OoooOo0 = iIiiIi11Iii . action
   if ( I1iI1III and oo0OoooOo0 == LISP_DROP_ACTION ) :
    if ( iIiiIi11Iii . eid . is_local ( ) ) : continue
    if 24 - 24: Ii1I + oO0o / OoooooooOO % i11iIiiIii
    if 1 - 1: iII111i / I1Ii111 * I1IiiI + OoOoOO00 . OoooooooOO
    if 5 - 5: I1IiiI
    if 74 - 74: i1IIi * Oo0Ooo - OoOoOO00 * o0oOOo0O0Ooo
    if 85 - 85: iIii1I11I1II1 * IiII / i11iIiiIii - ooOoO0o - o0oOOo0O0Ooo
    if 30 - 30: OoOoOO00 - OOooOOo . Oo0Ooo
    if 11 - 11: IiII - I1Ii111 - OoO0O00 * o0oOOo0O0Ooo
  if ( I1iI1III == False and iIiiIi11Iii . eid . is_null ( ) ) : continue
  if 99 - 99: O0 - OoO0O00
  if 95 - 95: Ii1I . IiII * o0oOOo0O0Ooo
  if 91 - 91: I1Ii111
  if 49 - 49: I11i
  if 17 - 17: Oo0Ooo % o0oOOo0O0Ooo
  if ( I1iI1III ) :
   IIII1 = lisp_map_cache . lookup_cache ( iIiiIi11Iii . group , True )
   if ( IIII1 ) : IIII1 = IIII1 . lookup_source_cache ( iIiiIi11Iii . eid , False )
  else :
   IIII1 = lisp_map_cache . lookup_cache ( iIiiIi11Iii . eid , True )
   if 100 - 100: i11iIiiIii / i1IIi . I1ii11iIi11i
  I1i11Ii111Ii = ( IIII1 == None )
  if 42 - 42: I1Ii111 - I11i + O0 . O0 . ooOoO0o
  if 69 - 69: I11i + I1IiiI / oO0o
  if 89 - 89: i1IIi % OoOoOO00 . I1ii11iIi11i
  if 85 - 85: I1Ii111 - oO0o
  if 34 - 34: iIii1I11I1II1 / IiII + OoOoOO00 - IiII / ooOoO0o + OoOoOO00
  if ( IIII1 == None ) :
   oO0oo000O , O0O0oOO , Ooooo00OO = lisp_allow_gleaning ( iIiiIi11Iii . eid , iIiiIi11Iii . group ,
 None )
   if ( oO0oo000O ) : continue
  else :
   if ( IIII1 . gleaned ) : continue
   if 14 - 14: ooOoO0o - OoooooooOO / iIii1I11I1II1
   if 98 - 98: i1IIi
   if 81 - 81: OoOoOO00 * i11iIiiIii + I1IiiI
   if 2 - 2: I11i - IiII + I1IiiI % OoO0O00 + iIii1I11I1II1 + oO0o
   if 49 - 49: I1IiiI * I1Ii111 . I1IiiI - II111iiii
  o0O00ooOo = [ ]
  oOOoOo0 = None
  I11I = None
  for iii1iII in range ( iIiiIi11Iii . rloc_count ) :
   ooO0 = lisp_rloc_record ( )
   ooO0 . keys = OOoOOOO0ooooo . keys
   packet = ooO0 . decode ( packet , OOoOOOO0ooooo . nonce )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Reply packet" )
    return
    if 93 - 93: o0oOOo0O0Ooo + i1IIi
   ooO0 . print_record ( "    " )
   if 24 - 24: i1IIi
   if 54 - 54: iIii1I11I1II1 - IiII + o0oOOo0O0Ooo + I1ii11iIi11i + IiII
   if 99 - 99: Oo0Ooo
   if 38 - 38: I1ii11iIi11i - I1IiiI
   I1IIIIiIii = None
   if ( IIII1 ) :
    I1IIIIiIii = IIII1 . get_rloc ( ooO0 . rloc )
    if ( I1IIIIiIii == None and I1iI1III and IIII1 . rloc_set != [ ] ) :
     OoOooO0oO = IIII1 . rloc_set [ 0 ]
     I1IIIIiIii = OoOooO0oO . get_rle ( ooO0 . rloc )
     if 83 - 83: Oo0Ooo / I1ii11iIi11i % OoO0O00
     if 29 - 29: IiII - I1ii11iIi11i . Oo0Ooo + IiII - I1IiiI
   if ( I1IIIIiIii ) :
    iIIiIi1111iiIii = I1IIIIiIii
   else :
    iIIiIi1111iiIii = lisp_rloc ( )
    if 95 - 95: O0 / o0oOOo0O0Ooo + OoO0O00 / IiII - IiII % OOooOOo
    if 16 - 16: I1IiiI * iIii1I11I1II1 % o0oOOo0O0Ooo - IiII - OOooOOo
    if 83 - 83: Ii1I
    if 20 - 20: ooOoO0o
    if 38 - 38: IiII + OoO0O00 . OOooOOo - I1Ii111 + IiII
    if 82 - 82: OOooOOo
    if 26 - 26: ooOoO0o + OoooooooOO + ooOoO0o * I1Ii111
   O0ooO0O00oo0 = iIIiIi1111iiIii . store_rloc_from_record ( ooO0 , OOoOOOO0ooooo . nonce , source )
   iIIiIi1111iiIii . set_active_rloc_next_hop ( )
   iIIiIi1111iiIii . echo_nonce_capable = OOoOOOO0ooooo . echo_nonce_capable
   if 26 - 26: I1IiiI - OOooOOo
   if ( iIIiIi1111iiIii . echo_nonce_capable ) :
    O00oO000Oo0 = iIIiIi1111iiIii . rloc . print_address_no_iid ( )
    if ( lisp_get_echo_nonce ( None , O00oO000Oo0 ) == None ) :
     lisp_echo_nonce ( O00oO000Oo0 )
     if 34 - 34: I1Ii111 % I1IiiI . OoOoOO00 / iII111i + ooOoO0o . i11iIiiIii
     if 51 - 51: OoooooooOO * I1Ii111 * I11i - I1ii11iIi11i + I1Ii111
     if 50 - 50: OoooooooOO * II111iiii
     if 7 - 7: ooOoO0o / I11i * iII111i
     if 17 - 17: O0 % I1Ii111
     if 28 - 28: i1IIi * ooOoO0o
   if ( iIIiIi1111iiIii . json ) :
    if ( lisp_is_json_telemetry ( iIIiIi1111iiIii . json . json_string ) ) :
     Ooo = iIIiIi1111iiIii . json . json_string
     Ooo = lisp_encode_telemetry ( Ooo , ii = itr_in_ts )
     iIIiIi1111iiIii . json . json_string = Ooo
     if 14 - 14: II111iiii + II111iiii - I11i / I11i . OoOoOO00 + OoO0O00
     if 92 - 92: II111iiii - II111iiii % IiII
     if 48 - 48: oO0o / II111iiii + oO0o
     if 16 - 16: o0oOOo0O0Ooo % II111iiii - i11iIiiIii - IiII + O0 - i11iIiiIii
     if 58 - 58: OoooooooOO / I1ii11iIi11i - Oo0Ooo / II111iiii
     if 13 - 13: o0oOOo0O0Ooo + OoOoOO00 * ooOoO0o % IiII
   if ( I11I == None ) : I11I = iIIiIi1111iiIii . rloc_name
   if 18 - 18: I1IiiI . I1ii11iIi11i + Oo0Ooo - iII111i
   if 53 - 53: ooOoO0o / IiII
   if 36 - 36: iIii1I11I1II1
   if 78 - 78: II111iiii * I11i
   if 47 - 47: Ii1I
   if 42 - 42: I11i . oO0o - I1IiiI / OoO0O00
   if 75 - 75: I1IiiI / OoOoOO00 . I11i * iIii1I11I1II1
   if 53 - 53: iIii1I11I1II1
   if ( OOoOOOO0ooooo . rloc_probe and ooO0 . probe_bit ) :
    if ( iIIiIi1111iiIii . rloc . afi == source . afi ) :
     lisp_process_rloc_probe_reply ( iIIiIi1111iiIii , source , O0ooO0O00oo0 ,
 OOoOOOO0ooooo , ttl , oOOoOo0 , I11I )
     if 8 - 8: O0 - O0 - II111iiii
    if ( iIIiIi1111iiIii . rloc . is_multicast_address ( ) ) : oOOoOo0 = iIIiIi1111iiIii
    if 77 - 77: i1IIi - ooOoO0o + O0 . OoO0O00 * I1Ii111 - I11i
    if 64 - 64: i1IIi + OoooooooOO + OOooOOo / ooOoO0o % I1IiiI . OoooooooOO
    if 96 - 96: II111iiii - OoOoOO00 + oO0o
    if 80 - 80: oO0o / OoOoOO00 - I11i / oO0o - iII111i - OoooooooOO
    if 57 - 57: o0oOOo0O0Ooo
   o0O00ooOo . append ( iIIiIi1111iiIii )
   if 37 - 37: iII111i * o0oOOo0O0Ooo
   if 23 - 23: ooOoO0o + OoooooooOO * iII111i . I11i
   if 2 - 2: iIii1I11I1II1 * I1ii11iIi11i - OoooooooOO
   if 93 - 93: iII111i % ooOoO0o * Oo0Ooo
   if ( lisp_data_plane_security and iIIiIi1111iiIii . rloc_recent_rekey ( ) ) :
    iI11I1i = iIIiIi1111iiIii
    if 34 - 34: O0 * oO0o
    if 58 - 58: OOooOOo . iII111i - Oo0Ooo / iII111i . I11i
    if 86 - 86: iIii1I11I1II1 - iII111i % Ii1I
    if 18 - 18: oO0o / IiII - OOooOOo % Ii1I
    if 88 - 88: i11iIiiIii
    if 13 - 13: I1IiiI
    if 52 - 52: Ii1I * oO0o / I1Ii111 . IiII
    if 84 - 84: OoooooooOO - oO0o - I1Ii111
    if 69 - 69: OoOoOO00 * Ii1I % OoooooooOO % OOooOOo * OoOoOO00
    if 20 - 20: IiII
    if 17 - 17: o0oOOo0O0Ooo % iIii1I11I1II1
  if ( OOoOOOO0ooooo . rloc_probe == False and lisp_nat_traversal ) :
   Ii = [ ]
   ooo0oOo = [ ]
   for iIIiIi1111iiIii in o0O00ooOo :
    I1I111i = iIIiIi1111iiIii . rloc . print_address_no_iid ( )
    if 79 - 79: I11i
    if 38 - 38: I1ii11iIi11i * ooOoO0o
    if 77 - 77: OOooOOo - i11iIiiIii - I1ii11iIi11i
    if 94 - 94: OoO0O00 % iII111i - I1Ii111 + OoO0O00 - I1IiiI
    if 65 - 65: OOooOOo
    if ( iIIiIi1111iiIii . rloc . is_private_address ( ) ) :
     iIIiIi1111iiIii . priority = 1
     iIIiIi1111iiIii . state = LISP_RLOC_UNREACH_STATE
     Ii . append ( iIIiIi1111iiIii )
     ooo0oOo . append ( I1I111i )
     continue
     if 90 - 90: O0
     if 91 - 91: O0 * OoOoOO00 - OoOoOO00 * II111iiii - iII111i
     if 38 - 38: oO0o * I11i % OOooOOo
     if 80 - 80: O0 % II111iiii / O0 . Oo0Ooo * OoOoOO00 + OOooOOo
     if 47 - 47: Ii1I - Oo0Ooo * OoOoOO00
     if 20 - 20: oO0o
     if 48 - 48: I1IiiI % OoO0O00
     if 33 - 33: Ii1I
     if 73 - 73: Ii1I . IiII
     if 43 - 43: I11i . IiII - iII111i * I1IiiI * iII111i
    if ( lisp_i_am_rtr ) :
     if ( iIIiIi1111iiIii . priority != 254 ) :
      Ii . append ( iIIiIi1111iiIii )
      ooo0oOo . append ( I1I111i )
      if 90 - 90: i11iIiiIii * i1IIi
    elif ( lisp_decent_nat ) :
     Ii . append ( iIIiIi1111iiIii )
     ooo0oOo . append ( I1I111i )
    elif ( iIIiIi1111iiIii . priority == 254 ) :
     Ii . append ( iIIiIi1111iiIii )
     ooo0oOo . append ( I1I111i )
     if 88 - 88: i11iIiiIii - OoOoOO00
     if 53 - 53: iIii1I11I1II1 % I1Ii111 / Oo0Ooo % Oo0Ooo
     if 6 - 6: iII111i
   if ( ooo0oOo != [ ] ) :
    o0O00ooOo = Ii
    ii1IiiiI1 = "NAT-decent" if ( lisp_decent_nat ) else "NAT-traversal"
    if 64 - 64: OoO0O00 + I1ii11iIi11i / OoO0O00 * I1Ii111 . Oo0Ooo
    lprint ( "{} optimized RLOC-set: {}" . format ( ii1IiiiI1 , ooo0oOo ) )
    if 5 - 5: iII111i - iIii1I11I1II1 * IiII
    if 52 - 52: OOooOOo
    if 50 - 50: OoOoOO00 % o0oOOo0O0Ooo - II111iiii - i1IIi
    if 35 - 35: Oo0Ooo - ooOoO0o % OoO0O00
    if 26 - 26: i1IIi * I1Ii111 * OoO0O00 - IiII
    if 26 - 26: Oo0Ooo - ooOoO0o . iII111i * OoOoOO00 / OoooooooOO
    if 66 - 66: I1IiiI
  Ii = [ ]
  for iIIiIi1111iiIii in o0O00ooOo :
   if ( iIIiIi1111iiIii . json != None ) : continue
   Ii . append ( iIIiIi1111iiIii )
   if 45 - 45: II111iiii * I1Ii111 - II111iiii / I1IiiI % oO0o
  if ( Ii != [ ] ) :
   o00oOoo0o00 = len ( o0O00ooOo ) - len ( Ii )
   lprint ( "Pruning {} no-address RLOC-records for map-cache" . format ( o00oOoo0o00 ) )
   if 83 - 83: oO0o % OoO0O00 + I1ii11iIi11i / OoooooooOO % iII111i
   o0O00ooOo = Ii
   if 22 - 22: I1Ii111
   if 41 - 41: O0 * i1IIi
   if 89 - 89: iIii1I11I1II1 . I11i % I1ii11iIi11i + II111iiii . OoO0O00
   if 5 - 5: I1ii11iIi11i / I1IiiI . iII111i
   if 7 - 7: Ii1I
   if 62 - 62: I1ii11iIi11i + IiII . O0 - OoooooooOO * o0oOOo0O0Ooo % O0
  if ( lisp_decent_nat ) :
   for iIIiIi1111iiIii in o0O00ooOo :
    if ( iIIiIi1111iiIii . is_decent_nat_port ( ) == False ) : continue
    lisp_itr_nat_probe ( iIIiIi1111iiIii . rloc , iIIiIi1111iiIii . rloc_name , lisp_sockets [ 2 ] )
    if 63 - 63: OOooOOo + iII111i - IiII - I1IiiI % IiII . OoO0O00
    if 73 - 73: OoOoOO00
    if 47 - 47: oO0o
    if 17 - 17: IiII
    if 47 - 47: I11i . I1IiiI % ooOoO0o . i11iIiiIii
    if 63 - 63: I1ii11iIi11i % I11i % OoooooooOO
    if 100 - 100: O0
    if 9 - 9: Ii1I
    if 87 - 87: I1IiiI
  if ( OOoOOOO0ooooo . rloc_probe and IIII1 != None ) : o0O00ooOo = IIII1 . rloc_set
  if 56 - 56: OOooOOo % oO0o - OoOoOO00
  if 27 - 27: I1ii11iIi11i - IiII * OoooooooOO * I1ii11iIi11i + i11iIiiIii . IiII
  if 81 - 81: oO0o / iIii1I11I1II1
  if 15 - 15: Ii1I + I1IiiI . OOooOOo / OoooooooOO + I11i - I11i
  if 27 - 27: Ii1I / o0oOOo0O0Ooo . iIii1I11I1II1 . I1IiiI - OoO0O00
  i1iI1II1i1Ii1 = I1i11Ii111Ii
  if ( IIII1 and o0O00ooOo != IIII1 . rloc_set ) :
   IIII1 . delete_rlocs_from_rloc_probe_list ( )
   i1iI1II1i1Ii1 = True
   if 61 - 61: IiII + iII111i
   if 15 - 15: II111iiii / iIii1I11I1II1 / I1ii11iIi11i % OoOoOO00 % OoO0O00 - I1Ii111
   if 17 - 17: OoooooooOO
   if 23 - 23: OoO0O00
   if 26 - 26: I11i % IiII . OoooooooOO % i11iIiiIii * IiII
  O0O0 = IIII1 . uptime if ( IIII1 ) else None
  if ( IIII1 == None or i1iI1II1i1Ii1 ) :
   IIII1 = lisp_mapping ( iIiiIi11Iii . eid , iIiiIi11Iii . group , o0O00ooOo )
   IIII1 . mapping_source = source
   if 58 - 58: i11iIiiIii % Ii1I + Oo0Ooo - OoOoOO00 - i11iIiiIii / O0
   if 36 - 36: OOooOOo
   if 42 - 42: OOooOOo * ooOoO0o * i11iIiiIii + OoooooooOO . iIii1I11I1II1
   if 95 - 95: i1IIi * O0 / II111iiii * OoOoOO00 * I1IiiI
   if 38 - 38: OOooOOo - OoOoOO00 / OoO0O00 / o0oOOo0O0Ooo - i11iIiiIii
   if 4 - 4: I1IiiI * o0oOOo0O0Ooo - I11i - OoooooooOO . OoooooooOO
   if ( lisp_i_am_rtr and iIiiIi11Iii . group . is_null ( ) == False ) :
    IIII1 . map_cache_ttl = LISP_MCAST_TTL
   else :
    IIII1 . map_cache_ttl = iIiiIi11Iii . store_ttl ( )
    if 79 - 79: oO0o - iII111i
   IIII1 . action = iIiiIi11Iii . action
   IIII1 . add_cache ( i1iI1II1i1Ii1 )
   if 34 - 34: OoooooooOO + Ii1I - iII111i + OoooooooOO / I1IiiI
   if 39 - 39: o0oOOo0O0Ooo . i1IIi * OoO0O00 / II111iiii / I1ii11iIi11i * OOooOOo
  iiO0 = "Add"
  if ( O0O0 ) :
   IIII1 . uptime = O0O0
   IIII1 . refresh_time = lisp_get_timestamp ( )
   iiO0 = "Replace"
   if 58 - 58: I1ii11iIi11i / i11iIiiIii + iII111i + I11i / oO0o
   if 8 - 8: I1ii11iIi11i
  lprint ( "{} {} map-cache with {} RLOCs" . format ( iiO0 ,
 green ( IIII1 . print_eid_tuple ( ) , False ) , len ( o0O00ooOo ) ) )
  if 100 - 100: OoooooooOO / I11i - Ii1I
  if 11 - 11: OoO0O00
  if 20 - 20: Oo0Ooo
  if 34 - 34: I1Ii111 % i11iIiiIii / oO0o - i1IIi . o0oOOo0O0Ooo / oO0o
  if 68 - 68: I1Ii111 % Ii1I * Oo0Ooo - O0 . IiII
  if ( lisp_ipc_dp_socket and iI11I1i != None ) :
   lisp_write_ipc_keys ( iI11I1i )
   if 1 - 1: I1ii11iIi11i
   if 18 - 18: i11iIiiIii % OoO0O00 % OOooOOo . OOooOOo * Ii1I / II111iiii
   if 81 - 81: iII111i % IiII / I11i
   if 50 - 50: IiII + i1IIi % I1Ii111
   if 72 - 72: I1Ii111
   if 6 - 6: II111iiii - i1IIi
   if 78 - 78: OoOoOO00 - Oo0Ooo * II111iiii % iIii1I11I1II1 . i11iIiiIii % iII111i
  if ( I1i11Ii111Ii ) :
   oO00oo0 = bold ( "RLOC-probe" , False )
   for iIIiIi1111iiIii in IIII1 . best_rloc_set :
    O00oO000Oo0 = red ( iIIiIi1111iiIii . rloc . print_address_no_iid ( ) , False )
    lprint ( "Trigger {} to {}" . format ( oO00oo0 , O00oO000Oo0 ) )
    lisp_send_map_request ( lisp_sockets , 0 , IIII1 . eid , IIII1 . group , iIIiIi1111iiIii )
    if 36 - 36: i11iIiiIii / OOooOOo . O0 . OoO0O00 - Ii1I
    if 31 - 31: OoOoOO00 * o0oOOo0O0Ooo / O0 . iII111i / i11iIiiIii
    if 22 - 22: I1IiiI . OoooooooOO * I1ii11iIi11i + i11iIiiIii - O0 + i11iIiiIii
 return
 if 98 - 98: OOooOOo + I1IiiI / IiII / OoooooooOO / OOooOOo
 if 8 - 8: OoooooooOO * OOooOOo * iII111i - iII111i
 if 32 - 32: I1Ii111
 if 28 - 28: I11i . i11iIiiIii % iIii1I11I1II1 + OoOoOO00
 if 4 - 4: OOooOOo + I1ii11iIi11i - iII111i + OOooOOo / IiII
 if 23 - 23: iIii1I11I1II1 + OoooooooOO + ooOoO0o . iII111i . Oo0Ooo - iIii1I11I1II1
 if 25 - 25: O0 + I1IiiI % OOooOOo / Oo0Ooo . IiII / I1Ii111
 if 84 - 84: ooOoO0o . O0 + I1IiiI * OoO0O00 - I1IiiI
def lisp_compute_auth ( packet , map_register , password ) :
 if ( map_register . alg_id == LISP_NONE_ALG_ID ) : return ( packet )
 if 24 - 24: Ii1I
 packet = map_register . zero_auth ( packet )
 ooo00OoOooooo = lisp_hash_me ( packet , map_register . alg_id , password , False )
 if 23 - 23: Oo0Ooo * i1IIi / I1IiiI . I11i - I1ii11iIi11i . iIii1I11I1II1
 if 15 - 15: O0 + o0oOOo0O0Ooo / oO0o
 if 27 - 27: Ii1I * II111iiii / oO0o
 if 99 - 99: I11i + ooOoO0o % I11i + O0 - Ii1I - I1Ii111
 map_register . auth_data = ooo00OoOooooo
 packet = map_register . encode_auth ( packet )
 return ( packet )
 if 3 - 3: Oo0Ooo . I1IiiI
 if 61 - 61: OoO0O00 - I1ii11iIi11i . Ii1I * i11iIiiIii
 if 97 - 97: ooOoO0o
 if 58 - 58: iII111i
 if 47 - 47: II111iiii % Oo0Ooo . iIii1I11I1II1 . oO0o
 if 52 - 52: I11i * I1IiiI % I11i - iII111i - Ii1I - OoooooooOO
 if 15 - 15: iII111i
def lisp_hash_me ( packet , alg_id , password , do_hex ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 95 - 95: i11iIiiIii . Ii1I / II111iiii + II111iiii + Ii1I / I11i
 if ( alg_id == LISP_SHA_1_96_ALG_ID ) :
  O00oo = hashlib . sha1
  if 59 - 59: ooOoO0o * oO0o . IiII
 if ( alg_id == LISP_SHA_256_128_ALG_ID ) :
  O00oo = hashlib . sha256
  if 99 - 99: OoOoOO00 + OoO0O00 * iIii1I11I1II1 * iIii1I11I1II1 + II111iiii
  if 42 - 42: ooOoO0o
 if ( do_hex ) :
  ooo00OoOooooo = hmac . new ( password . encode ( ) , packet , O00oo ) . hexdigest ( )
 else :
  ooo00OoOooooo = hmac . new ( password . encode ( ) , packet , O00oo ) . digest ( )
  if 62 - 62: II111iiii * o0oOOo0O0Ooo . OoO0O00 / II111iiii
 return ( ooo00OoOooooo )
 if 5 - 5: OoO0O00 + O0 . OoooooooOO + I1IiiI + i1IIi * OOooOOo
 if 19 - 19: OoooooooOO + i11iIiiIii / II111iiii - Oo0Ooo . OOooOOo
 if 10 - 10: oO0o * Oo0Ooo
 if 55 - 55: OoO0O00 - i1IIi - I11i * oO0o
 if 91 - 91: I1Ii111
 if 77 - 77: I1ii11iIi11i . ooOoO0o - iIii1I11I1II1 + Ii1I % II111iiii * II111iiii
 if 41 - 41: II111iiii + Oo0Ooo - IiII / I1Ii111 - OOooOOo . oO0o
 if 100 - 100: ooOoO0o / I1ii11iIi11i * OoOoOO00 . I1ii11iIi11i . o0oOOo0O0Ooo * iIii1I11I1II1
def lisp_verify_auth ( packet , alg_id , auth_data , password ) :
 if ( alg_id == LISP_NONE_ALG_ID ) : return ( True )
 if 15 - 15: iII111i + o0oOOo0O0Ooo / IiII
 ooo00OoOooooo = lisp_hash_me ( packet , alg_id , password , True )
 iiOO0o0o00 = ( ooo00OoOooooo == auth_data )
 if 53 - 53: IiII / Ii1I % IiII * i11iIiiIii + OoO0O00
 if 22 - 22: OOooOOo
 if 23 - 23: I1ii11iIi11i
 if 53 - 53: I11i
 if ( iiOO0o0o00 == False ) :
  lprint ( "Hashed value: {} does not match packet value: {}" . format ( ooo00OoOooooo , auth_data ) )
  if 64 - 64: iIii1I11I1II1 + O0 % IiII
  if 13 - 13: i11iIiiIii
 return ( iiOO0o0o00 )
 if 49 - 49: OoOoOO00
 if 61 - 61: I1Ii111 / I1Ii111 / iII111i / ooOoO0o - I1IiiI . o0oOOo0O0Ooo
 if 80 - 80: I1IiiI - OOooOOo . oO0o
 if 75 - 75: oO0o + OoOoOO00 - OoooooooOO
 if 38 - 38: I11i / ooOoO0o / OoOoOO00 * OOooOOo . oO0o
 if 8 - 8: OoO0O00 . OOooOOo % I1Ii111 * OOooOOo / I1IiiI
 if 3 - 3: IiII - I1ii11iIi11i . o0oOOo0O0Ooo
def lisp_retransmit_map_notify ( map_notify ) :
 oOO00OoOo = map_notify . etr
 O0ooO0O00oo0 = map_notify . etr_port
 if 39 - 39: oO0o . I1Ii111 + oO0o % OoOoOO00 - i11iIiiIii
 if 69 - 69: I11i / OoO0O00
 if 73 - 73: i11iIiiIii / i1IIi
 if 8 - 8: O0 / OOooOOo + iII111i % iIii1I11I1II1 % iIii1I11I1II1 . ooOoO0o
 if 47 - 47: OoO0O00 / o0oOOo0O0Ooo / Ii1I * I1IiiI % ooOoO0o / I1Ii111
 if ( map_notify . retry_count == LISP_MAX_MAP_NOTIFY_RETRIES ) :
  lprint ( "Map-Notify with nonce 0x{} retry limit reached for ETR {}" . format ( map_notify . nonce_key , red ( oOO00OoOo . print_address ( ) , False ) ) )
  if 80 - 80: I1Ii111 / O0 * O0
  if 40 - 40: OoO0O00 - oO0o / o0oOOo0O0Ooo . oO0o
  I1IIiiI1II = map_notify . nonce_key
  if ( I1IIiiI1II in lisp_map_notify_queue ) :
   map_notify . retransmit_timer . cancel ( )
   lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( I1IIiiI1II ) )
   if 89 - 89: i11iIiiIii - II111iiii
   try :
    lisp_map_notify_queue . pop ( I1IIiiI1II )
   except :
    lprint ( "Key not found in Map-Notify queue" )
    if 67 - 67: IiII % I1Ii111 + i11iIiiIii
    if 53 - 53: OOooOOo
  return
  if 95 - 95: oO0o - OOooOOo % I1Ii111 / OoooooooOO % OoooooooOO - O0
  if 21 - 21: I1Ii111 . i1IIi - iII111i % I1ii11iIi11i . OOooOOo
 i11iIiIi1i = map_notify . lisp_sockets
 map_notify . retry_count += 1
 if 52 - 52: Ii1I * I1ii11iIi11i
 lprint ( "Retransmit {} with nonce 0x{} to xTR {}, retry {}" . format ( bold ( "Map-Notify" , False ) , map_notify . nonce_key ,
 # i11iIiiIii % I1IiiI
 red ( oOO00OoOo . print_address ( ) , False ) , map_notify . retry_count ) )
 if 65 - 65: IiII
 lisp_send_map_notify ( i11iIiIi1i , map_notify . packet , oOO00OoOo , O0ooO0O00oo0 )
 if ( map_notify . site ) : map_notify . site . map_notifies_sent += 1
 if 53 - 53: iIii1I11I1II1 / II111iiii . I1ii11iIi11i + OoooooooOO % OOooOOo
 if 41 - 41: i1IIi / oO0o % OoooooooOO * OOooOOo + I1ii11iIi11i
 if 56 - 56: OOooOOo * OOooOOo / o0oOOo0O0Ooo
 if 4 - 4: OoOoOO00 / OoO0O00
 map_notify . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ map_notify ] )
 map_notify . retransmit_timer . start ( )
 return
 if 66 - 66: I1Ii111 / OoOoOO00
 if 53 - 53: OoOoOO00 . i11iIiiIii - OoooooooOO
 if 92 - 92: O0 - i11iIiiIii + OoO0O00 - OoooooooOO - o0oOOo0O0Ooo
 if 25 - 25: oO0o / oO0o / Ii1I / O0
 if 56 - 56: ooOoO0o
 if 19 - 19: O0 * I1IiiI + I1ii11iIi11i
 if 25 - 25: I11i - ooOoO0o / OoO0O00 / iII111i - OoO0O00
def lisp_send_merged_map_notify ( lisp_sockets , parent , map_register ,
 eid_record ) :
 if 86 - 86: OoO0O00
 if 89 - 89: OoooooooOO % iII111i * I1ii11iIi11i + I1ii11iIi11i . Oo0Ooo
 if 4 - 4: I11i
 if 8 - 8: IiII
 eid_record . rloc_count = len ( parent . registered_rlocs )
 i11 = eid_record . encode ( )
 eid_record . print_record ( "Merged Map-Notify " , False )
 if 4 - 4: iIii1I11I1II1 % I1IiiI - OoooooooOO / iII111i
 if 55 - 55: O0 + iII111i * OoOoOO00 . i11iIiiIii * Ii1I + oO0o
 if 66 - 66: i1IIi . I1ii11iIi11i
 if 86 - 86: Oo0Ooo
 for iII1I1 in parent . registered_rlocs :
  ooO0 = lisp_rloc_record ( )
  ooO0 . store_rloc_entry ( iII1I1 )
  ooO0 . local_bit = True
  ooO0 . probe_bit = False
  ooO0 . reach_bit = True
  i11 += ooO0 . encode ( )
  ooO0 . print_record ( "  " )
  del ( ooO0 )
  if 25 - 25: iII111i % OoO0O00
  if 9 - 9: i1IIi / OoOoOO00 + o0oOOo0O0Ooo + OOooOOo - I1IiiI / i1IIi
  if 8 - 8: o0oOOo0O0Ooo * OoO0O00 % IiII / OoooooooOO * ooOoO0o - i11iIiiIii
  if 14 - 14: Oo0Ooo . iII111i
  if 50 - 50: iIii1I11I1II1
 for iII1I1 in parent . registered_rlocs :
  oOO00OoOo = iII1I1 . rloc
  I1IIiIiii = lisp_map_notify ( lisp_sockets )
  I1IIiIiii . record_count = 1
  III = map_register . key_id
  I1IIiIiii . key_id = III
  I1IIiIiii . alg_id = map_register . alg_id
  I1IIiIiii . auth_len = map_register . auth_len
  I1IIiIiii . nonce = map_register . nonce
  I1IIiIiii . nonce_key = lisp_hex_string ( I1IIiIiii . nonce )
  I1IIiIiii . etr . copy_address ( oOO00OoOo )
  I1IIiIiii . etr_port = map_register . sport
  I1IIiIiii . site = parent . site
  Oo00O0o0O = I1IIiIiii . encode ( i11 , parent . site . auth_key [ III ] )
  I1IIiIiii . print_notify ( )
  if 73 - 73: II111iiii . i1IIi
  if 80 - 80: i11iIiiIii % II111iiii / OoO0O00 - o0oOOo0O0Ooo * I11i . I1IiiI
  if 86 - 86: OoO0O00
  if 86 - 86: I1Ii111 - OoOoOO00 . o0oOOo0O0Ooo % oO0o
  I1IIiiI1II = I1IIiIiii . nonce_key
  if ( I1IIiiI1II in lisp_map_notify_queue ) :
   iii = lisp_map_notify_queue [ I1IIiiI1II ]
   iii . retransmit_timer . cancel ( )
   del ( iii )
   if 48 - 48: Oo0Ooo / IiII . OoO0O00
  lisp_map_notify_queue [ I1IIiiI1II ] = I1IIiIiii
  if 45 - 45: o0oOOo0O0Ooo + iIii1I11I1II1 / O0
  if 2 - 2: I11i + I1IiiI . IiII . OoOoOO00 * oO0o - ooOoO0o
  if 29 - 29: OoO0O00
  if 78 - 78: iII111i * ooOoO0o + O0 % ooOoO0o + OoO0O00
  lprint ( "Send merged Map-Notify to ETR {}" . format ( red ( oOO00OoOo . print_address ( ) , False ) ) )
  if 41 - 41: II111iiii . oO0o + O0 % i1IIi . Ii1I
  lisp_send ( lisp_sockets , oOO00OoOo , LISP_CTRL_PORT , Oo00O0o0O )
  if 90 - 90: ooOoO0o * I1IiiI / II111iiii % Oo0Ooo % OoooooooOO
  parent . site . map_notifies_sent += 1
  if 78 - 78: OoooooooOO . IiII
  if 55 - 55: I11i / I1ii11iIi11i * O0 + IiII % I11i
  if 69 - 69: o0oOOo0O0Ooo % iIii1I11I1II1 . OoooooooOO - ooOoO0o
  if 94 - 94: iIii1I11I1II1 / Oo0Ooo % IiII * IiII
  I1IIiIiii . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ I1IIiIiii ] )
  I1IIiIiii . retransmit_timer . start ( )
  if 62 - 62: I11i . IiII - OOooOOo - I1Ii111 / OoooooooOO . Ii1I
 return
 if 28 - 28: iII111i / I1ii11iIi11i - OoOoOO00 * Oo0Ooo + Ii1I * OoOoOO00
 if 94 - 94: oO0o
 if 95 - 95: ooOoO0o * O0 + OOooOOo
 if 11 - 11: i1IIi / OoOoOO00 + OoOoOO00 + I1ii11iIi11i + OOooOOo
 if 21 - 21: ooOoO0o
 if 28 - 28: OoOoOO00 + OoOoOO00 - OoOoOO00 / ooOoO0o
 if 81 - 81: oO0o
def lisp_build_map_notify ( lisp_sockets , eid_records , eid_list , record_count ,
 source , port , nonce , key_id , alg_id , auth_len , site , map_register_ack ) :
 if 34 - 34: o0oOOo0O0Ooo * OOooOOo - i1IIi * o0oOOo0O0Ooo * Oo0Ooo
 I1IIiiI1II = lisp_hex_string ( nonce ) + source . print_address ( )
 if 59 - 59: iIii1I11I1II1 / Oo0Ooo % II111iiii
 if 55 - 55: ooOoO0o - IiII + o0oOOo0O0Ooo
 if 48 - 48: O0 - iIii1I11I1II1 * OOooOOo
 if 33 - 33: I11i
 if 63 - 63: Ii1I % II111iiii / OoOoOO00 + Oo0Ooo
 if 28 - 28: OoO0O00 + I1IiiI . oO0o + II111iiii - O0
 lisp_remove_eid_from_map_notify_queue ( eid_list )
 if ( I1IIiiI1II in lisp_map_notify_queue ) :
  I1IIiIiii = lisp_map_notify_queue [ I1IIiiI1II ]
  OOo0oOO0o0oo0 = red ( source . print_address_no_iid ( ) , False )
  lprint ( "Map-Notify with nonce 0x{} pending for xTR {}" . format ( lisp_hex_string ( I1IIiIiii . nonce ) , OOo0oOO0o0oo0 ) )
  if 32 - 32: oO0o
  return
  if 62 - 62: i11iIiiIii + OoooooooOO + IiII - OoO0O00 / oO0o * iIii1I11I1II1
  if 91 - 91: o0oOOo0O0Ooo - i11iIiiIii + Oo0Ooo % iIii1I11I1II1
 I1IIiIiii = lisp_map_notify ( lisp_sockets )
 I1IIiIiii . record_count = record_count
 key_id = key_id
 I1IIiIiii . key_id = key_id
 I1IIiIiii . alg_id = alg_id
 I1IIiIiii . auth_len = auth_len
 I1IIiIiii . nonce = nonce
 I1IIiIiii . nonce_key = lisp_hex_string ( nonce )
 I1IIiIiii . etr . copy_address ( source )
 I1IIiIiii . etr_port = port
 I1IIiIiii . site = site
 I1IIiIiii . eid_list = eid_list
 if 58 - 58: iII111i / ooOoO0o - I1Ii111 + I1Ii111 * ooOoO0o
 if 48 - 48: iII111i % O0 % Ii1I * OoO0O00 . OoO0O00
 if 74 - 74: OoO0O00 * i1IIi + I1ii11iIi11i / o0oOOo0O0Ooo / i1IIi
 if 94 - 94: Ii1I
 if ( map_register_ack == False ) :
  I1IIiiI1II = I1IIiIiii . nonce_key
  lisp_map_notify_queue [ I1IIiiI1II ] = I1IIiIiii
  if 13 - 13: OoO0O00 - II111iiii . iII111i + OoOoOO00 / i11iIiiIii
  if 32 - 32: ooOoO0o / II111iiii / I1ii11iIi11i
 if ( map_register_ack ) :
  lprint ( "Send Map-Notify to ack Map-Register" )
 else :
  lprint ( "Send Map-Notify for RLOC-set change" )
  if 34 - 34: iIii1I11I1II1
  if 47 - 47: OOooOOo * iII111i
  if 71 - 71: IiII - OoooooooOO * i11iIiiIii . OoooooooOO % i1IIi . Oo0Ooo
  if 3 - 3: OoO0O00 + i11iIiiIii + oO0o * IiII
  if 19 - 19: iII111i / II111iiii . I1Ii111 * I1IiiI - OOooOOo
 Oo00O0o0O = I1IIiIiii . encode ( eid_records , site . auth_key [ key_id ] )
 I1IIiIiii . print_notify ( )
 if 70 - 70: OoO0O00
 if ( map_register_ack == False ) :
  iIiiIi11Iii = lisp_eid_record ( )
  iIiiIi11Iii . decode ( eid_records )
  iIiiIi11Iii . print_record ( "  " , False )
  if 42 - 42: OoooooooOO - I1Ii111 + I1ii11iIi11i * iII111i * iII111i / OoO0O00
  if 85 - 85: O0 . II111iiii
  if 80 - 80: O0 * I11i * I1Ii111
  if 89 - 89: Ii1I * OoO0O00 . i1IIi . O0 - IiII - OoOoOO00
  if 25 - 25: iII111i + i1IIi
 lisp_send_map_notify ( lisp_sockets , Oo00O0o0O , I1IIiIiii . etr , port )
 site . map_notifies_sent += 1
 if 64 - 64: IiII % I11i / iIii1I11I1II1
 if ( map_register_ack ) : return
 if 66 - 66: Ii1I
 if 55 - 55: OOooOOo + I1IiiI + IiII . Ii1I * oO0o
 if 71 - 71: IiII - iII111i % I1IiiI * iII111i
 if 27 - 27: ooOoO0o - OoO0O00
 if 83 - 83: iII111i * OoOoOO00 - O0 * Ii1I
 if 79 - 79: I11i / iII111i % Ii1I / OoOoOO00 % O0 / IiII
 I1IIiIiii . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ I1IIiIiii ] )
 I1IIiIiii . retransmit_timer . start ( )
 return
 if 32 - 32: IiII * II111iiii . Ii1I
 if 68 - 68: I11i / O0
 if 6 - 6: oO0o - oO0o . I1IiiI % I1ii11iIi11i
 if 22 - 22: Ii1I / I1IiiI / II111iiii
 if 31 - 31: II111iiii - Ii1I * OOooOOo - i11iIiiIii / OoooooooOO - I1Ii111
 if 76 - 76: Oo0Ooo
 if 93 - 93: i1IIi - I1IiiI * i11iIiiIii / Ii1I . Ii1I - i1IIi
 if 19 - 19: iIii1I11I1II1 * OOooOOo * Oo0Ooo % I1IiiI
def lisp_send_map_notify_ack ( lisp_sockets , eid_records , map_notify , ms ) :
 map_notify . map_notify_ack = True
 if 93 - 93: IiII % OoOoOO00 / I1IiiI + o0oOOo0O0Ooo * ooOoO0o / i1IIi
 if 25 - 25: O0 / Oo0Ooo - o0oOOo0O0Ooo * Oo0Ooo
 if 45 - 45: Ii1I * IiII - OOooOOo
 if 57 - 57: iII111i % OoO0O00 / OoooooooOO
 map_notify . record_count = 0
 Oo00O0o0O = map_notify . encode ( eid_records , ms . password )
 map_notify . print_notify ( )
 if 69 - 69: oO0o
 if 44 - 44: IiII - II111iiii % Ii1I
 if 64 - 64: Ii1I % OoO0O00 + OOooOOo % OoOoOO00 + IiII
 if 92 - 92: iII111i * Oo0Ooo - OoOoOO00
 oOO00OoOo = ms . map_server
 lprint ( "Send Map-Notify-Ack to {}" . format (
 red ( oOO00OoOo . print_address ( ) , False ) ) )
 lisp_send ( lisp_sockets , oOO00OoOo , LISP_CTRL_PORT , Oo00O0o0O )
 return
 if 33 - 33: i11iIiiIii - OoOoOO00 . OOooOOo * II111iiii . Ii1I
 if 59 - 59: OoOoOO00
 if 29 - 29: iII111i - II111iiii * OoooooooOO * OoooooooOO
 if 15 - 15: IiII / OOooOOo / iIii1I11I1II1 / OoOoOO00
 if 91 - 91: i11iIiiIii % O0 . Oo0Ooo / I1Ii111
 if 62 - 62: Oo0Ooo . II111iiii % OoO0O00 . Ii1I * OOooOOo + II111iiii
 if 7 - 7: OOooOOo
 if 22 - 22: Oo0Ooo + ooOoO0o
def lisp_send_multicast_map_notify ( lisp_sockets , site_eid , eid_list , xtr ) :
 if 71 - 71: OOooOOo . Ii1I * i11iIiiIii . I11i
 I1IIiIiii = lisp_map_notify ( lisp_sockets )
 I1IIiIiii . record_count = 1
 I1IIiIiii . nonce = lisp_get_control_nonce ( )
 I1IIiIiii . nonce_key = lisp_hex_string ( I1IIiIiii . nonce )
 I1IIiIiii . etr . copy_address ( xtr )
 I1IIiIiii . etr_port = LISP_CTRL_PORT
 I1IIiIiii . eid_list = eid_list
 I1IIiiI1II = I1IIiIiii . nonce_key
 if 9 - 9: O0 / I1ii11iIi11i . iII111i . O0 + IiII % I11i
 if 27 - 27: i11iIiiIii - I1ii11iIi11i / O0 - i1IIi + I1IiiI * iII111i
 if 26 - 26: Oo0Ooo . Ii1I
 if 7 - 7: OoOoOO00 - o0oOOo0O0Ooo + oO0o
 if 8 - 8: iIii1I11I1II1
 if 6 - 6: oO0o
 lisp_remove_eid_from_map_notify_queue ( I1IIiIiii . eid_list )
 if ( I1IIiiI1II in lisp_map_notify_queue ) :
  I1IIiIiii = lisp_map_notify_queue [ I1IIiiI1II ]
  lprint ( "Map-Notify with nonce 0x{} pending for ITR {}" . format ( I1IIiIiii . nonce , red ( xtr . print_address_no_iid ( ) , False ) ) )
  if 51 - 51: I1Ii111 - o0oOOo0O0Ooo
  return
  if 5 - 5: O0
  if 7 - 7: OoOoOO00 + OoO0O00 * I1IiiI
  if 63 - 63: I1ii11iIi11i + iII111i * i1IIi
  if 63 - 63: I1ii11iIi11i / II111iiii % oO0o + ooOoO0o . Ii1I % I11i
  if 59 - 59: I1Ii111 % o0oOOo0O0Ooo - I1IiiI * i1IIi
 lisp_map_notify_queue [ I1IIiiI1II ] = I1IIiIiii
 if 5 - 5: I1IiiI
 if 22 - 22: II111iiii / iII111i
 if 18 - 18: i11iIiiIii * ooOoO0o . I1IiiI + i1IIi + I11i
 if 62 - 62: O0 % o0oOOo0O0Ooo + iIii1I11I1II1 + iIii1I11I1II1 * ooOoO0o
 if 21 - 21: o0oOOo0O0Ooo % O0
 if 81 - 81: i1IIi + i1IIi
 I1O00o0OO0o0Oo0 = site_eid . rtrs_in_rloc_set ( )
 if 24 - 24: iII111i / OoOoOO00 + O0
 if 14 - 14: OoO0O00
 if 11 - 11: ooOoO0o * IiII * I1Ii111 * ooOoO0o
 if 92 - 92: I1IiiI
 iIiiIi11Iii = lisp_eid_record ( )
 iIiiIi11Iii . record_ttl = 1440
 iIiiIi11Iii . eid . copy_address ( site_eid . eid )
 iIiiIi11Iii . group . copy_address ( site_eid . group )
 iIiiIi11Iii . rloc_count = 0
 for oO0o0 in site_eid . registered_rlocs :
  if ( I1O00o0OO0o0Oo0 ^ oO0o0 . is_rtr ( ) ) : continue
  iIiiIi11Iii . rloc_count += 1
  if 94 - 94: OoOoOO00 % OoOoOO00 . i11iIiiIii
 Oo00O0o0O = iIiiIi11Iii . encode ( )
 if 40 - 40: II111iiii - iII111i * iIii1I11I1II1
 if 48 - 48: iII111i * OoO0O00
 if 57 - 57: ooOoO0o + I1IiiI
 if 32 - 32: I1ii11iIi11i + OOooOOo - I11i
 I1IIiIiii . print_notify ( )
 iIiiIi11Iii . print_record ( "  " , False )
 if 82 - 82: Oo0Ooo % Oo0Ooo
 if 91 - 91: I11i
 if 98 - 98: I11i - II111iiii . IiII % Oo0Ooo
 if 65 - 65: OoO0O00
 IiI1iiiI1I1 = [ ]
 for oO0o0 in site_eid . registered_rlocs :
  if ( I1O00o0OO0o0Oo0 ) :
   if ( oO0o0 . is_rtr ( ) ) :
    IiI1iiiI1I1 . append ( oO0o0 . rloc )
    continue
    if 65 - 65: oO0o
    if 77 - 77: I11i * i1IIi - OOooOOo / OoOoOO00
    if 50 - 50: O0 - oO0o . oO0o
    if 98 - 98: IiII % Ii1I / Ii1I
    if 10 - 10: Ii1I
    if 69 - 69: I1Ii111 * OoooooooOO . o0oOOo0O0Ooo % I1IiiI
  ooO0 = lisp_rloc_record ( )
  ooO0 . store_rloc_entry ( oO0o0 )
  ooO0 . local_bit = True
  ooO0 . probe_bit = False
  ooO0 . reach_bit = True
  Oo00O0o0O += ooO0 . encode ( )
  ooO0 . print_record ( "    " )
  if 70 - 70: iII111i . i11iIiiIii * I1Ii111
  if 54 - 54: o0oOOo0O0Ooo . i1IIi / iII111i
  if 21 - 21: O0 + ooOoO0o
  if 53 - 53: Ii1I - II111iiii * iIii1I11I1II1
  if 91 - 91: OoOoOO00 % iIii1I11I1II1
 Oo00O0o0O = I1IIiIiii . encode ( Oo00O0o0O , "" )
 if ( Oo00O0o0O == None ) : return
 if 81 - 81: i11iIiiIii / OoOoOO00 + iIii1I11I1II1
 if 65 - 65: o0oOOo0O0Ooo
 if 73 - 73: I11i . I1ii11iIi11i - OoO0O00 + OoooooooOO
 if 71 - 71: I1IiiI
 if ( IiI1iiiI1I1 != [ ] ) :
  for I11i1i1 in IiI1iiiI1I1 :
   lisp_send_map_notify ( lisp_sockets , Oo00O0o0O , I11i1i1 , LISP_CTRL_PORT )
   if 27 - 27: OoO0O00 + i1IIi * OoooooooOO * iIii1I11I1II1 - Ii1I
 else :
  lisp_send_map_notify ( lisp_sockets , Oo00O0o0O , xtr , LISP_CTRL_PORT )
  if 85 - 85: OoO0O00 + II111iiii / OoO0O00 . II111iiii * OoOoOO00 * I1IiiI
  if 19 - 19: iII111i / Ii1I + iIii1I11I1II1 * O0 - Oo0Ooo
  if 47 - 47: iIii1I11I1II1 % I1ii11iIi11i
  if 33 - 33: oO0o . oO0o / IiII + II111iiii
  if 34 - 34: OoO0O00 . OoOoOO00 / i1IIi / OOooOOo
 I1IIiIiii . retransmit_timer = threading . Timer ( LISP_MAP_NOTIFY_INTERVAL ,
 lisp_retransmit_map_notify , [ I1IIiIiii ] )
 I1IIiIiii . retransmit_timer . start ( )
 return
 if 12 - 12: o0oOOo0O0Ooo . Oo0Ooo / II111iiii
 if 18 - 18: I1Ii111 % II111iiii + Ii1I * Oo0Ooo - OoooooooOO . Oo0Ooo
 if 25 - 25: OoO0O00
 if 83 - 83: II111iiii . iIii1I11I1II1
 if 77 - 77: O0 . OoOoOO00 % oO0o / OOooOOo
 if 8 - 8: iII111i - i1IIi
 if 81 - 81: ooOoO0o / OOooOOo % OoOoOO00 . iIii1I11I1II1
def lisp_queue_multicast_map_notify ( lisp_sockets , rle_list ) :
 iiI = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 if 100 - 100: i11iIiiIii * I1ii11iIi11i
 for i1Ii1 in rle_list :
  o0o0oo0 = lisp_site_eid_lookup ( i1Ii1 [ 0 ] , i1Ii1 [ 1 ] , True )
  if ( o0o0oo0 == None ) : continue
  if 98 - 98: OoooooooOO - i11iIiiIii - iII111i + Ii1I - I1IiiI
  if 75 - 75: OOooOOo
  if 25 - 25: iII111i / I1ii11iIi11i - ooOoO0o
  if 53 - 53: IiII / OoooooooOO / ooOoO0o + Oo0Ooo - OOooOOo - iIii1I11I1II1
  if 53 - 53: OOooOOo . I1IiiI . o0oOOo0O0Ooo / o0oOOo0O0Ooo
  if 40 - 40: OoooooooOO + iII111i % I1Ii111 . ooOoO0o
  if 2 - 2: ooOoO0o
  O00o0O0 = o0o0oo0 . registered_rlocs
  if ( len ( O00o0O0 ) == 0 ) :
   iI1iI = { }
   for o0o0Oo0O00OO in list ( o0o0oo0 . individual_registrations . values ( ) ) :
    for oO0o0 in o0o0Oo0O00OO . registered_rlocs :
     if ( oO0o0 . is_rtr ( ) == False ) : continue
     iI1iI [ oO0o0 . rloc . print_address ( ) ] = oO0o0
     if 34 - 34: I1ii11iIi11i / Oo0Ooo % Ii1I - o0oOOo0O0Ooo - oO0o
     if 27 - 27: O0 - iIii1I11I1II1
   O00o0O0 = list ( iI1iI . values ( ) )
   if 78 - 78: Oo0Ooo / o0oOOo0O0Ooo
   if 35 - 35: o0oOOo0O0Ooo . OoO0O00 / o0oOOo0O0Ooo / IiII - I1ii11iIi11i . Oo0Ooo
   if 97 - 97: i11iIiiIii + I1ii11iIi11i - I11i . oO0o
   if 76 - 76: IiII * II111iiii * I1ii11iIi11i + OoooooooOO - OoOoOO00 . Ii1I
   if 51 - 51: II111iiii % I1Ii111 * O0 . ooOoO0o * OoOoOO00
   if 17 - 17: I1IiiI % I11i
  iIii1II111Ii = [ ]
  iiIiII11I = False
  if ( o0o0oo0 . eid . address == 0 and o0o0oo0 . eid . mask_len == 0 ) :
   oOOo0000Oo = [ ]
   o0oOOo0Oo0o = [ ]
   if ( len ( O00o0O0 ) != 0 and O00o0O0 [ 0 ] . rle != None ) :
    o0oOOo0Oo0o = O00o0O0 [ 0 ] . rle . rle_nodes
    if 65 - 65: OOooOOo % ooOoO0o . I1ii11iIi11i + IiII . OoO0O00
   for Iiiiii in o0oOOo0Oo0o :
    iIii1II111Ii . append ( Iiiiii . rloc . rloc )
    oOOo0000Oo . append ( Iiiiii . rloc . rloc . print_address_no_iid ( ) )
    if 14 - 14: O0 % iII111i * OoOoOO00 + II111iiii . OoOoOO00
   lprint ( "Notify existing RLE-nodes {}" . format ( oOOo0000Oo ) )
  else :
   if 29 - 29: ooOoO0o * o0oOOo0O0Ooo * I1IiiI
   if 14 - 14: oO0o . OOooOOo * OOooOOo . OoO0O00
   if 27 - 27: OOooOOo - iII111i - IiII
   if 14 - 14: i11iIiiIii . I1ii11iIi11i % OoOoOO00 * Ii1I / OoO0O00
   if 56 - 56: o0oOOo0O0Ooo / I1IiiI + I11i + I1IiiI
   for oO0o0 in O00o0O0 :
    if ( oO0o0 . is_rtr ( ) ) : iIii1II111Ii . append ( oO0o0 . rloc )
    if 34 - 34: Oo0Ooo / i11iIiiIii - ooOoO0o
    if 77 - 77: OoOoOO00 * OoooooooOO
    if 41 - 41: iIii1I11I1II1 - O0 . II111iiii + I1IiiI - II111iiii / oO0o
    if 35 - 35: ooOoO0o - OoOoOO00 / iIii1I11I1II1 / OOooOOo
    if 38 - 38: i1IIi % OoooooooOO
   iiIiII11I = ( len ( iIii1II111Ii ) != 0 )
   if ( iiIiII11I == False ) :
    Ooo000oOOooO00 = lisp_site_eid_lookup ( i1Ii1 [ 0 ] , iiI , False )
    if ( Ooo000oOOooO00 == None ) : continue
    if 5 - 5: iIii1I11I1II1 + iIii1I11I1II1 . iIii1I11I1II1 + o0oOOo0O0Ooo
    for oO0o0 in Ooo000oOOooO00 . registered_rlocs :
     if ( oO0o0 . rloc . is_null ( ) ) : continue
     iIii1II111Ii . append ( oO0o0 . rloc )
     if 45 - 45: I1IiiI - OoooooooOO - I1Ii111 - i1IIi - OoooooooOO * O0
     if 67 - 67: OoOoOO00 * o0oOOo0O0Ooo . IiII
     if 72 - 72: OoOoOO00 % OoooooooOO * O0
     if 27 - 27: I1ii11iIi11i . OoooooooOO / II111iiii . OOooOOo
     if 58 - 58: oO0o / ooOoO0o
     if 31 - 31: o0oOOo0O0Ooo % I11i - OoO0O00
   if ( len ( iIii1II111Ii ) == 0 ) :
    lprint ( "No ITRs or RTRs found for {}, Map-Notify suppressed" . format ( green ( o0o0oo0 . print_eid_tuple ( ) , False ) ) )
    if 40 - 40: o0oOOo0O0Ooo % OoOoOO00 + I11i / O0 - II111iiii
    continue
    if 9 - 9: OoooooooOO - OOooOOo . I11i * oO0o
    if 3 - 3: iIii1I11I1II1 - OoO0O00
    if 38 - 38: O0 + ooOoO0o * I1Ii111 - oO0o * o0oOOo0O0Ooo
    if 97 - 97: Oo0Ooo - O0 * OoooooooOO
    if 52 - 52: i1IIi + IiII
    if 11 - 11: I1IiiI % iIii1I11I1II1 * Ii1I % ooOoO0o
  for iII1I1 in iIii1II111Ii :
   lprint ( "Build Map-Notify for {}" . format (
 green ( o0o0oo0 . print_eid_tuple ( ) , False ) ) )
   if 33 - 33: iII111i / O0 % II111iiii % OoOoOO00 / I1Ii111
   OO0o0oo0oOo = [ o0o0oo0 . print_eid_tuple ( ) ]
   lisp_send_multicast_map_notify ( lisp_sockets , o0o0oo0 , OO0o0oo0oOo , iII1I1 )
   time . sleep ( .001 )
   if 21 - 21: ooOoO0o - I11i . i11iIiiIii
   if 39 - 39: Oo0Ooo * II111iiii % OOooOOo / oO0o . ooOoO0o
 return
 if 75 - 75: I11i / O0 + OoooooooOO + OOooOOo % iII111i + I1IiiI
 if 10 - 10: II111iiii * I11i - IiII * iIii1I11I1II1 . OoooooooOO
 if 39 - 39: I11i . I1IiiI % Oo0Ooo + oO0o
 if 76 - 76: I1IiiI * OoooooooOO - i11iIiiIii / I11i / Oo0Ooo
 if 82 - 82: IiII % ooOoO0o
 if 100 - 100: Oo0Ooo . oO0o - iII111i + OoooooooOO
 if 27 - 27: Oo0Ooo . I1Ii111 - i1IIi * I1IiiI
 if 96 - 96: I1ii11iIi11i - Ii1I . I1ii11iIi11i
def lisp_find_sig_in_rloc_set ( packet , rloc_count ) :
 for o000o0O0Oo00 in range ( rloc_count ) :
  ooO0 = lisp_rloc_record ( )
  packet = ooO0 . decode ( packet , None )
  Oo0Oo00O000 = ooO0 . json
  if ( Oo0Oo00O000 == None ) : continue
  if 91 - 91: oO0o
  try :
   Oo0Oo00O000 = json . loads ( Oo0Oo00O000 . json_string )
  except :
   lprint ( "Found corrupted JSON signature" )
   continue
   if 74 - 74: oO0o
   if 1 - 1: II111iiii . Oo0Ooo * iII111i . OoO0O00 . iII111i
  if ( "signature" not in Oo0Oo00O000 ) : continue
  return ( ooO0 )
  if 35 - 35: oO0o - ooOoO0o
 return ( None )
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
 if 87 - 87: I1Ii111 + O0 / I1ii11iIi11i / OoOoOO00 . Oo0Ooo - IiII
 if 24 - 24: OoOoOO00
 if 19 - 19: ooOoO0o
 if 43 - 43: O0 . I1Ii111 % OoooooooOO / I1IiiI . o0oOOo0O0Ooo - OoOoOO00
 if 46 - 46: I11i - OoooooooOO % o0oOOo0O0Ooo
 if 7 - 7: OoooooooOO - I1Ii111 * IiII
 if 20 - 20: o0oOOo0O0Ooo . OoooooooOO * I1IiiI . Oo0Ooo * OoOoOO00
 if 3 - 3: I1Ii111 % i11iIiiIii % O0 % II111iiii
 if 8 - 8: OoooooooOO * ooOoO0o
def lisp_get_eid_hash ( eid ) :
 iiIIi11 = None
 for o00Oo in lisp_eid_hashes :
  if 65 - 65: I1Ii111 . I1ii11iIi11i * iII111i
  if 89 - 89: o0oOOo0O0Ooo / I1Ii111 - oO0o + iII111i % I1IiiI - Ii1I
  if 58 - 58: OoOoOO00 + O0 - OoooooooOO % OoOoOO00 % i1IIi
  if 75 - 75: OoOoOO00 . IiII - OoO0O00 . o0oOOo0O0Ooo % II111iiii
  i1I1iI = o00Oo . instance_id
  if ( i1I1iI == - 1 ) : o00Oo . instance_id = eid . instance_id
  if 69 - 69: Ii1I % OoooooooOO
  oOO0 = eid . is_more_specific ( o00Oo )
  o00Oo . instance_id = i1I1iI
  if ( oOO0 ) :
   iiIIi11 = 128 - o00Oo . mask_len
   break
   if 5 - 5: iIii1I11I1II1 + OoOoOO00 * I1Ii111 * i11iIiiIii
   if 18 - 18: Oo0Ooo % OOooOOo % oO0o / I11i % O0
 if ( iiIIi11 == None ) : return ( None )
 if 76 - 76: OoooooooOO % O0 / OoO0O00
 I1iI111ii111i = eid . address
 iiIIiiiII = ""
 for o000o0O0Oo00 in range ( 0 , old_div ( iiIIi11 , 16 ) ) :
  iI1ii11Ii = I1iI111ii111i & 0xffff
  iI1ii11Ii = hex ( iI1ii11Ii ) [ 2 : : ]
  iiIIiiiII = iI1ii11Ii . zfill ( 4 ) + ":" + iiIIiiiII
  I1iI111ii111i >>= 16
  if 25 - 25: iII111i / I1IiiI * OoooooooOO
 if ( iiIIi11 % 16 != 0 ) :
  iI1ii11Ii = I1iI111ii111i & 0xff
  iI1ii11Ii = hex ( iI1ii11Ii ) [ 2 : : ]
  iiIIiiiII = iI1ii11Ii . zfill ( 2 ) + ":" + iiIIiiiII
  if 72 - 72: I1IiiI
 return ( iiIIiiiII [ 0 : - 1 ] )
 if 86 - 86: OoO0O00 . ooOoO0o . O0 / IiII - Ii1I
 if 84 - 84: IiII + OoooooooOO % iIii1I11I1II1
 if 61 - 61: OoO0O00 * I1Ii111 / oO0o
 if 90 - 90: I1Ii111 % OoooooooOO % ooOoO0o
 if 17 - 17: I1ii11iIi11i + o0oOOo0O0Ooo / OoO0O00 . Oo0Ooo - o0oOOo0O0Ooo / oO0o
 if 87 - 87: ooOoO0o
 if 74 - 74: i11iIiiIii . i11iIiiIii . iIii1I11I1II1
 if 100 - 100: i11iIiiIii - oO0o + iIii1I11I1II1 * OoOoOO00 % OOooOOo % i11iIiiIii
 if 26 - 26: O0
 if 97 - 97: OOooOOo + I11i % I1Ii111 % i11iIiiIii / I1ii11iIi11i
 if 21 - 21: O0 + iIii1I11I1II1 / i11iIiiIii . OOooOOo * i1IIi
def lisp_lookup_public_key ( eid ) :
 i1I1iI = eid . instance_id
 if 3 - 3: i1IIi % o0oOOo0O0Ooo + OoOoOO00
 if 32 - 32: OoO0O00 . Oo0Ooo * iIii1I11I1II1
 if 12 - 12: O0 + I1ii11iIi11i + I11i . I1Ii111
 if 48 - 48: Ii1I . iIii1I11I1II1 - iIii1I11I1II1 * I11i . OoooooooOO
 if 73 - 73: Ii1I / II111iiii - iIii1I11I1II1 . ooOoO0o * II111iiii . OOooOOo
 Ii1IIi = lisp_get_eid_hash ( eid )
 if ( Ii1IIi == None ) : return ( [ None , None , False ] )
 if 15 - 15: i11iIiiIii / I1IiiI - iII111i
 Ii1IIi = "hash-" + Ii1IIi
 oO = lisp_address ( LISP_AFI_NAME , Ii1IIi , len ( Ii1IIi ) , i1I1iI )
 i1I1IIIiII = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 if 75 - 75: o0oOOo0O0Ooo . I11i
 if 4 - 4: iIii1I11I1II1 % i1IIi % i11iIiiIii / OOooOOo
 if 93 - 93: I1ii11iIi11i - iII111i % O0 - Ii1I
 if 84 - 84: I1ii11iIi11i . iIii1I11I1II1 % IiII * I11i + ooOoO0o
 Ooo000oOOooO00 = lisp_site_eid_lookup ( oO , i1I1IIIiII , True )
 if ( Ooo000oOOooO00 == None ) : return ( [ oO , None , False ] )
 if 59 - 59: oO0o * OoO0O00 - I11i * I1IiiI
 if 60 - 60: iII111i - OoooooooOO / iII111i % OoO0O00 . OoOoOO00 - o0oOOo0O0Ooo
 if 71 - 71: iII111i * o0oOOo0O0Ooo * i11iIiiIii * O0
 if 77 - 77: OOooOOo % iII111i + I11i / OoOoOO00
 i1IIIi11III1 = None
 for iIIiIi1111iiIii in Ooo000oOOooO00 . registered_rlocs :
  IIIii1i1I = iIIiIi1111iiIii . json
  if ( IIIii1i1I == None ) : continue
  try :
   IIIii1i1I = json . loads ( IIIii1i1I . json_string )
  except :
   lprint ( "Registered RLOC JSON format is invalid for {}" . format ( Ii1IIi ) )
   if 80 - 80: OOooOOo . OoooooooOO * ooOoO0o % OoOoOO00
   return ( [ oO , None , False ] )
   if 18 - 18: Ii1I % iII111i + OoooooooOO + O0
  if ( "public-key" not in IIIii1i1I ) : continue
  i1IIIi11III1 = IIIii1i1I [ "public-key" ]
  break
  if 83 - 83: ooOoO0o - OOooOOo % iII111i + IiII + IiII - ooOoO0o
 return ( [ oO , i1IIIi11III1 , True ] )
 if 43 - 43: O0
 if 97 - 97: i1IIi . I1ii11iIi11i . OOooOOo - ooOoO0o
 if 40 - 40: i11iIiiIii % i1IIi - iII111i
 if 22 - 22: I1IiiI - I11i + OoOoOO00 - i11iIiiIii
 if 72 - 72: i11iIiiIii - iII111i . i11iIiiIii
 if 61 - 61: oO0o . i11iIiiIii / Ii1I % iII111i
 if 36 - 36: OoO0O00 + Ii1I / I11i - iII111i % OoO0O00 / Oo0Ooo
 if 38 - 38: Ii1I - ooOoO0o - O0 + oO0o . iIii1I11I1II1
def lisp_verify_cga_sig ( eid , rloc_record ) :
 if 90 - 90: i1IIi * OoOoOO00
 if 27 - 27: iIii1I11I1II1
 if 95 - 95: iII111i / ooOoO0o % Ii1I
 if 44 - 44: OOooOOo . OOooOOo
 if 5 - 5: oO0o + OoooooooOO
 O00oooOoO = json . loads ( rloc_record . json . json_string )
 if 88 - 88: oO0o + OOooOOo
 if ( lisp_get_eid_hash ( eid ) ) :
  o0o00O0 = eid
 elif ( "signature-eid" in O00oooOoO ) :
  i1iIiIIII = O00oooOoO [ "signature-eid" ]
  o0o00O0 = lisp_address ( LISP_AFI_IPV6 , i1iIiIIII , 0 , 0 )
 else :
  lprint ( "  No signature-eid found in RLOC-record" )
  return ( False )
  if 37 - 37: IiII * I1IiiI % O0
  if 32 - 32: ooOoO0o % II111iiii
  if 60 - 60: i11iIiiIii
  if 11 - 11: o0oOOo0O0Ooo
  if 77 - 77: o0oOOo0O0Ooo / iIii1I11I1II1 * iIii1I11I1II1 / o0oOOo0O0Ooo * iII111i
 oO , i1IIIi11III1 , ii1iIII1I1I = lisp_lookup_public_key ( o0o00O0 )
 if ( oO == None ) :
  oOOoo = green ( o0o00O0 . print_address ( ) , False )
  lprint ( "  Could not parse hash in EID {}" . format ( oOOoo ) )
  return ( False )
  if 57 - 57: I1IiiI + i11iIiiIii * i1IIi
  if 59 - 59: IiII % OoO0O00 % iIii1I11I1II1 - OoOoOO00 / iII111i
 iiO0Ii1IiiiI = "found" if ii1iIII1I1I else bold ( "not found" , False )
 oOOoo = green ( oO . print_address ( ) , False )
 lprint ( "  Lookup for crypto-hashed EID {} {}" . format ( oOOoo , iiO0Ii1IiiiI ) )
 if ( ii1iIII1I1I == False ) : return ( False )
 if 32 - 32: I1Ii111 % oO0o * iII111i * OOooOOo
 if ( i1IIIi11III1 == None ) :
  lprint ( "  RLOC-record with public-key not found" )
  return ( False )
  if 45 - 45: oO0o / O0
  if 5 - 5: OoO0O00 / O0
 o0o0 = i1IIIi11III1 [ 0 : 8 ] + "..." + i1IIIi11III1 [ - 8 : : ]
 lprint ( "  RLOC-record with public-key '{}' found" . format ( o0o0 ) )
 if 45 - 45: oO0o % oO0o
 if 85 - 85: i1IIi + oO0o % Ii1I + iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i / II111iiii . oO0o - o0oOOo0O0Ooo
 if 80 - 80: i1IIi
 if 40 - 40: O0 . ooOoO0o * iII111i . I11i + I1Ii111 % OoO0O00
 i1IIIii11IiI = O00oooOoO [ "signature" ]
 if 56 - 56: I1Ii111 % oO0o
 try :
  O00oooOoO = binascii . a2b_base64 ( i1IIIii11IiI )
 except :
  lprint ( "  Incorrect padding in signature string" )
  return ( False )
  if 31 - 31: OOooOOo + IiII
  if 56 - 56: OoooooooOO * II111iiii
 OoooOOoOO = len ( O00oooOoO )
 if ( OoooOOoOO & 1 ) :
  lprint ( "  Signature length is odd, length {}" . format ( OoooOOoOO ) )
  return ( False )
  if 34 - 34: I11i % i1IIi
  if 8 - 8: OoOoOO00 / oO0o + oO0o * Ii1I
  if 71 - 71: I1Ii111 - O0 . oO0o % ooOoO0o / I1Ii111
  if 28 - 28: o0oOOo0O0Ooo / oO0o
  if 65 - 65: O0 / i1IIi
 O0Ooo = o0o00O0 . print_address ( )
 if 78 - 78: OOooOOo . I11i % Oo0Ooo . OoOoOO00
 if 92 - 92: i11iIiiIii * OoooooooOO
 if 36 - 36: iII111i - OoO0O00 + I1IiiI + Ii1I . OoooooooOO
 if 75 - 75: oO0o * Oo0Ooo * O0
 i1IIIi11III1 = binascii . a2b_base64 ( i1IIIi11III1 )
 try :
  I1IIiiI1II = ecdsa . VerifyingKey . from_pem ( i1IIIi11III1 )
 except :
  I1ii = bold ( "Bad public-key" , False )
  lprint ( "  {}, not in PEM format" . format ( I1ii ) )
  return ( False )
  if 26 - 26: Ii1I * O0
  if 44 - 44: OoO0O00 - I11i
  if 65 - 65: Ii1I % OOooOOo . OoO0O00 - o0oOOo0O0Ooo
  if 8 - 8: OOooOOo % OoOoOO00 % Oo0Ooo . II111iiii
  if 92 - 92: OoOoOO00
  if 26 - 26: Oo0Ooo
  if 3 - 3: I11i . OoO0O00 . i1IIi - I1IiiI * oO0o
  if 93 - 93: i1IIi + I1ii11iIi11i % Oo0Ooo + iIii1I11I1II1 / II111iiii
  if 100 - 100: iIii1I11I1II1 / II111iiii / Ii1I * Ii1I - OoO0O00
  if 36 - 36: ooOoO0o % i1IIi / OoOoOO00 % OoOoOO00 + Ii1I
  if 35 - 35: Ii1I . ooOoO0o - ooOoO0o % OoO0O00 / oO0o
 try :
  I11IiIi1I = I1IIiiI1II . verify ( O00oooOoO , O0Ooo . encode ( ) , hashfunc = hashlib . sha256 )
 except :
  lprint ( "  Signature library failed for signature data '{}'" . format ( O0Ooo ) )
  if 33 - 33: I1Ii111 / i11iIiiIii / I1ii11iIi11i
  lprint ( "  Signature used '{}'" . format ( i1IIIii11IiI ) )
  return ( False )
  if 44 - 44: OoOoOO00 * Oo0Ooo
 return ( I11IiIi1I )
 if 51 - 51: OOooOOo / IiII % I1Ii111 . OoOoOO00 % Ii1I
 if 88 - 88: OoO0O00
 if 28 - 28: I1Ii111 - iIii1I11I1II1
 if 88 - 88: Oo0Ooo * i1IIi % OOooOOo
 if 65 - 65: iII111i . oO0o
 if 67 - 67: I1IiiI / iII111i / O0 % ooOoO0o - IiII / Ii1I
 if 31 - 31: I11i - oO0o * ooOoO0o
 if 64 - 64: I11i
 if 41 - 41: I1Ii111 * OoooooooOO / OoOoOO00 + OoO0O00 . OoOoOO00 + I1Ii111
 if 9 - 9: IiII . I11i . I1Ii111 / i1IIi * OoOoOO00 - O0
def lisp_remove_eid_from_map_notify_queue ( eid_list ) :
 if 3 - 3: O0 / iIii1I11I1II1 % IiII + I11i
 if 43 - 43: Oo0Ooo % I11i
 if 53 - 53: OoOoOO00 % OoooooooOO * o0oOOo0O0Ooo % OoooooooOO
 if 47 - 47: iIii1I11I1II1 - OOooOOo + I1ii11iIi11i * ooOoO0o + Oo0Ooo + OoO0O00
 if 64 - 64: OoOoOO00 - OoOoOO00 . OoooooooOO + ooOoO0o
 O0ooOoo0O000O = [ ]
 for I1I1iI11IiII in eid_list :
  for Ooo00oooOoO in lisp_map_notify_queue :
   I1IIiIiii = lisp_map_notify_queue [ Ooo00oooOoO ]
   if ( I1I1iI11IiII not in I1IIiIiii . eid_list ) : continue
   if 99 - 99: i1IIi * I11i % OoooooooOO % i11iIiiIii % I1Ii111 . OOooOOo
   O0ooOoo0O000O . append ( Ooo00oooOoO )
   IiII111Ii = I1IIiIiii . retransmit_timer
   if ( IiII111Ii ) : IiII111Ii . cancel ( )
   if 71 - 71: o0oOOo0O0Ooo + Oo0Ooo % OoooooooOO
   lprint ( "Remove from Map-Notify queue nonce 0x{} for EID {}" . format ( I1IIiIiii . nonce_key , green ( I1I1iI11IiII , False ) ) )
   if 5 - 5: i1IIi % Oo0Ooo / OoooooooOO * OoOoOO00 + OOooOOo - ooOoO0o
   if 24 - 24: oO0o / ooOoO0o % I1IiiI / I1ii11iIi11i
   if 88 - 88: OoO0O00
   if 96 - 96: IiII % I1ii11iIi11i % Oo0Ooo - i11iIiiIii % iIii1I11I1II1
   if 100 - 100: IiII - Ii1I
   if 9 - 9: II111iiii / Ii1I / O0 - OoOoOO00 - IiII
   if 6 - 6: OoOoOO00 / O0 * i1IIi * OoooooooOO
 for Ooo00oooOoO in O0ooOoo0O000O : lisp_map_notify_queue . pop ( Ooo00oooOoO )
 return
 if 60 - 60: iII111i - iII111i - Oo0Ooo . i11iIiiIii
 if 67 - 67: oO0o * OoOoOO00 * OoO0O00 + O0 * oO0o
 if 39 - 39: i1IIi
 if 32 - 32: IiII . ooOoO0o / OoO0O00 / iII111i . iIii1I11I1II1 % IiII
 if 28 - 28: I1Ii111 + OoooooooOO + IiII . ooOoO0o . I1IiiI / oO0o
 if 66 - 66: Ii1I - I11i + Oo0Ooo . ooOoO0o
 if 89 - 89: IiII . II111iiii / OoO0O00 + I1ii11iIi11i * i11iIiiIii
 if 85 - 85: o0oOOo0O0Ooo - Oo0Ooo / I1Ii111
def lisp_decrypt_map_register ( packet ) :
 if 100 - 100: OoO0O00 * iIii1I11I1II1 - IiII . i1IIi % i11iIiiIii % Oo0Ooo
 if 22 - 22: ooOoO0o - OOooOOo
 if 90 - 90: i11iIiiIii . i11iIiiIii - iIii1I11I1II1
 if 20 - 20: ooOoO0o - i11iIiiIii
 if 23 - 23: OoO0O00 + I1IiiI / I1ii11iIi11i * I1ii11iIi11i % ooOoO0o
 I11 = socket . ntohl ( struct . unpack ( "I" , packet [ 0 : 4 ] ) [ 0 ] )
 OoOoOO0o0oO0 = ( I11 >> 13 ) & 0x1
 if ( OoOoOO0o0oO0 == 0 ) : return ( packet )
 if 17 - 17: IiII * oO0o
 IiiIiiiiI1iI1 = ( I11 >> 14 ) & 0x7
 if 50 - 50: OOooOOo - O0 + iII111i - IiII % Oo0Ooo
 if 88 - 88: OOooOOo
 if 19 - 19: i11iIiiIii - Ii1I
 if 68 - 68: I1IiiI * o0oOOo0O0Ooo * OoOoOO00 - Ii1I
 try :
  OooOooo0 = lisp_ms_encryption_keys [ IiiIiiiiI1iI1 ]
  OooOooo0 = OooOooo0 . zfill ( 32 )
  Oo0OOOO0oOoo0 = "0" * 8
 except :
  lprint ( "Cannot decrypt Map-Register with key-id {}" . format ( IiiIiiiiI1iI1 ) )
  return ( None )
  if 80 - 80: I1IiiI - OOooOOo + OoOoOO00
  if 53 - 53: OoooooooOO . I11i * OOooOOo + i11iIiiIii * O0 . iIii1I11I1II1
 oooOo = bold ( "Decrypt" , False )
 lprint ( "{} Map-Register with key-id {}" . format ( oooOo , IiiIiiiiI1iI1 ) )
 if 72 - 72: IiII . ooOoO0o . Oo0Ooo - iIii1I11I1II1 % IiII
 if 97 - 97: OoooooooOO
 if 26 - 26: I11i . I1IiiI / IiII / Oo0Ooo % Oo0Ooo / O0
 if 27 - 27: I11i - I11i % OoO0O00 - iII111i . OOooOOo - iIii1I11I1II1
 II11I = chacha . ChaCha ( OooOooo0 , Oo0OOOO0oOoo0 , 20 ) . decrypt ( packet [ 4 : : ] )
 return ( packet [ 0 : 4 ] + II11I )
 if 15 - 15: OoO0O00 + iIii1I11I1II1
 if 89 - 89: OoooooooOO * Ii1I
 if 4 - 4: Ii1I + OoO0O00 * O0
 if 13 - 13: I11i + O0 / oO0o % O0 . I11i
 if 22 - 22: OoOoOO00 . I1IiiI % ooOoO0o + I1Ii111 - OoooooooOO
 if 55 - 55: OoooooooOO * O0 - II111iiii / IiII
 if 18 - 18: II111iiii % O0 - o0oOOo0O0Ooo * ooOoO0o
def lisp_process_map_register ( lisp_sockets , packet , source , sport ) :
 global lisp_registered_count
 if 74 - 74: I11i . oO0o + I11i * o0oOOo0O0Ooo / O0
 if 55 - 55: OoO0O00 / i11iIiiIii / o0oOOo0O0Ooo
 if 19 - 19: ooOoO0o * iII111i
 if 38 - 38: ooOoO0o
 if 35 - 35: o0oOOo0O0Ooo * IiII * Oo0Ooo
 if 34 - 34: I11i - OoooooooOO % i1IIi + I1IiiI
 packet = lisp_decrypt_map_register ( packet )
 if ( packet == None ) : return
 if 14 - 14: I1IiiI . o0oOOo0O0Ooo / I1Ii111
 OoOOoooO0oo = lisp_map_register ( )
 II1i1i , packet = OoOOoooO0oo . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Register packet" )
  return
  if 34 - 34: ooOoO0o % II111iiii / ooOoO0o
 OoOOoooO0oo . sport = sport
 if 87 - 87: Oo0Ooo
 OoOOoooO0oo . print_map_register ( )
 if 7 - 7: iIii1I11I1II1
 if 85 - 85: iIii1I11I1II1 . O0
 if 43 - 43: II111iiii / OoOoOO00 + OOooOOo % Oo0Ooo * OOooOOo
 if 62 - 62: ooOoO0o * OOooOOo . I11i + Oo0Ooo - I1Ii111
 I11I1I1iiiIIi = True
 if ( OoOOoooO0oo . auth_len == LISP_SHA1_160_AUTH_DATA_LEN ) :
  I11I1I1iiiIIi = True
  if 63 - 63: I11i % I1ii11iIi11i / o0oOOo0O0Ooo
 if ( OoOOoooO0oo . alg_id == LISP_SHA_256_128_ALG_ID ) :
  I11I1I1iiiIIi = False
  if 95 - 95: oO0o * I1IiiI / OOooOOo
  if 79 - 79: O0 . iII111i . iII111i % ooOoO0o
  if 74 - 74: ooOoO0o
  if 37 - 37: oO0o / i1IIi * iII111i - i1IIi
  if 12 - 12: OoO0O00 * IiII + OoOoOO00 * I1Ii111 % OoOoOO00 + OoOoOO00
 II11iI1iI1I = [ ]
 if 33 - 33: OoO0O00 * I1IiiI / i1IIi
 if 88 - 88: Ii1I / ooOoO0o - I11i % OoO0O00 * iII111i
 if 47 - 47: i11iIiiIii + Oo0Ooo % oO0o % O0
 if 98 - 98: oO0o - O0 / iII111i % oO0o % I1IiiI / i1IIi
 o0oOO0 = None
 iII11IiI = packet
 i1Ii11iIiI1Ii = [ ]
 OOO0OO0OOoO = OoOOoooO0oo . record_count
 for o000o0O0Oo00 in range ( OOO0OO0OOoO ) :
  iIiiIi11Iii = lisp_eid_record ( )
  ooO0 = lisp_rloc_record ( )
  packet = iIiiIi11Iii . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Register packet" )
   return
   if 50 - 50: i1IIi . oO0o + Oo0Ooo * I1ii11iIi11i - i11iIiiIii - OoOoOO00
  iIiiIi11Iii . print_record ( "  " , False )
  if 79 - 79: IiII
  if 65 - 65: Oo0Ooo - i11iIiiIii * OoOoOO00 . I1Ii111 . iIii1I11I1II1
  if 48 - 48: iIii1I11I1II1 - oO0o / OoO0O00 + O0 . Ii1I + I1Ii111
  if 17 - 17: OoOoOO00 . Oo0Ooo - I1Ii111 / I1Ii111 + I11i % i1IIi
  Ooo000oOOooO00 = lisp_site_eid_lookup ( iIiiIi11Iii . eid , iIiiIi11Iii . group ,
 False )
  if 31 - 31: OoooooooOO . O0 / OoO0O00 . I1Ii111
  iii111 = Ooo000oOOooO00 . print_eid_tuple ( ) if Ooo000oOOooO00 else None
  if 52 - 52: OoOoOO00 - OoooooooOO / i11iIiiIii
  if 58 - 58: I11i * I11i + OoooooooOO * Oo0Ooo / I11i . i11iIiiIii
  if 90 - 90: OOooOOo - I1IiiI % o0oOOo0O0Ooo
  if 26 - 26: Oo0Ooo . II111iiii - I11i . Ii1I % OOooOOo
  if 4 - 4: I11i + I1Ii111 / i1IIi + OoooooooOO
  if 84 - 84: ooOoO0o
  if 47 - 47: Oo0Ooo
  if ( Ooo000oOOooO00 and Ooo000oOOooO00 . accept_more_specifics == False ) :
   if ( Ooo000oOOooO00 . eid_record_matches ( iIiiIi11Iii ) == False ) :
    ooOOoo0o = Ooo000oOOooO00 . parent_for_more_specifics
    if ( ooOOoo0o ) : Ooo000oOOooO00 = ooOOoo0o
    if 18 - 18: iII111i
    if 91 - 91: i11iIiiIii % OoOoOO00
    if 17 - 17: OoOoOO00
    if 62 - 62: I1Ii111 * I11i - II111iiii + Oo0Ooo - Ii1I . ooOoO0o
    if 70 - 70: OoOoOO00 * o0oOOo0O0Ooo / IiII
    if 6 - 6: iII111i
    if 4 - 4: I1ii11iIi11i % o0oOOo0O0Ooo * Oo0Ooo
    if 97 - 97: OoOoOO00
  i1Iiii1Iii1 = ( Ooo000oOOooO00 and Ooo000oOOooO00 . accept_more_specifics )
  if ( i1Iiii1Iii1 ) :
   OO0ooOo = lisp_site_eid ( Ooo000oOOooO00 . site )
   OO0ooOo . dynamic = True
   OO0ooOo . eid . copy_address ( iIiiIi11Iii . eid )
   OO0ooOo . group . copy_address ( iIiiIi11Iii . group )
   OO0ooOo . parent_for_more_specifics = Ooo000oOOooO00
   OO0ooOo . add_cache ( )
   OO0ooOo . inherit_from_ams_parent ( )
   Ooo000oOOooO00 . more_specific_registrations . append ( OO0ooOo )
   Ooo000oOOooO00 = OO0ooOo
  else :
   Ooo000oOOooO00 = lisp_site_eid_lookup ( iIiiIi11Iii . eid , iIiiIi11Iii . group ,
 True )
   if 66 - 66: iIii1I11I1II1 . OOooOOo * Oo0Ooo . iII111i
   if 76 - 76: O0 % iIii1I11I1II1
  oOOoo = iIiiIi11Iii . print_eid_tuple ( )
  if 62 - 62: oO0o % II111iiii + I1ii11iIi11i
  if ( Ooo000oOOooO00 == None ) :
   i1iiiiI1I = bold ( "Site not found" , False )
   lprint ( "  {} for EID {}{}" . format ( i1iiiiI1I , green ( oOOoo , False ) ,
 ", matched non-ams {}" . format ( green ( iii111 , False ) if iii111 else "" ) ) )
   if 5 - 5: OoOoOO00 / oO0o . I1Ii111 + i11iIiiIii . I1IiiI
   if 78 - 78: OoOoOO00 / Ii1I / II111iiii + ooOoO0o / Oo0Ooo
   if 30 - 30: IiII * I1ii11iIi11i . I1IiiI * i1IIi + IiII
   if 68 - 68: iIii1I11I1II1 . o0oOOo0O0Ooo % iIii1I11I1II1
   if 35 - 35: OoooooooOO % O0 * I1Ii111 - iIii1I11I1II1 % iII111i
   packet = ooO0 . end_of_rlocs ( packet , iIiiIi11Iii . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 15 - 15: O0 - Ii1I + OoOoOO00
   continue
   if 93 - 93: OoO0O00
   if 68 - 68: OOooOOo
  o0oOO0 = Ooo000oOOooO00 . site
  if 87 - 87: IiII * IiII - OoO0O00 / I1ii11iIi11i + OOooOOo / i11iIiiIii
  if ( i1Iiii1Iii1 ) :
   oOO = Ooo000oOOooO00 . parent_for_more_specifics . print_eid_tuple ( )
   lprint ( "  Found ams {} for site '{}' for registering prefix {}" . format ( green ( oOO , False ) , o0oOO0 . site_name , green ( oOOoo , False ) ) )
   if 21 - 21: o0oOOo0O0Ooo / oO0o + oO0o + Oo0Ooo / o0oOOo0O0Ooo
  else :
   oOO = green ( Ooo000oOOooO00 . print_eid_tuple ( ) , False )
   lprint ( "  Found {} for site '{}' for registering prefix {}" . format ( oOO , o0oOO0 . site_name , green ( oOOoo , False ) ) )
   if 39 - 39: i11iIiiIii - OoO0O00 - i11iIiiIii / OoooooooOO
   if 15 - 15: i1IIi . iII111i + IiII / I1ii11iIi11i - i1IIi / iII111i
   if 27 - 27: OoOoOO00 / OoooooooOO + i1IIi % iIii1I11I1II1 / OoO0O00
   if 73 - 73: I1ii11iIi11i / OoOoOO00 / IiII + oO0o
   if 73 - 73: I11i * o0oOOo0O0Ooo * I1IiiI . OoooooooOO % I1Ii111
   if 9 - 9: oO0o % I1Ii111 . O0 + I1ii11iIi11i - Ii1I - I1ii11iIi11i
  if ( o0oOO0 . shutdown ) :
   lprint ( ( "  Rejecting registration for site '{}', configured in " +
 "admin-shutdown state" ) . format ( o0oOO0 . site_name ) )
   packet = ooO0 . end_of_rlocs ( packet , iIiiIi11Iii . rloc_count )
   continue
   if 57 - 57: i11iIiiIii
   if 21 - 21: iIii1I11I1II1 / I1IiiI / iII111i
   if 19 - 19: Oo0Ooo / iIii1I11I1II1 / I11i
   if 71 - 71: iIii1I11I1II1 * I1IiiI
   if 35 - 35: O0
   if 10 - 10: Ii1I - I1Ii111 / Oo0Ooo + O0
   if 67 - 67: Ii1I % i11iIiiIii . Oo0Ooo
   if 78 - 78: I1IiiI - iIii1I11I1II1
  III = OoOOoooO0oo . key_id
  if ( III in o0oOO0 . auth_key ) :
   ii1II1II11I = o0oOO0 . auth_key [ III ]
  else :
   ii1II1II11I = ""
   if 98 - 98: O0
   if 92 - 92: i11iIiiIii
  I1IooOoOO = lisp_verify_auth ( II1i1i , OoOOoooO0oo . alg_id ,
 OoOOoooO0oo . auth_data , ii1II1II11I )
  O0O0O0OO0o0 = "dynamic " if Ooo000oOOooO00 . dynamic else ""
  if 38 - 38: OoO0O00 - iIii1I11I1II1 % ooOoO0o + I1ii11iIi11i - Ii1I
  II11 = bold ( "passed" if I1IooOoOO else "failed" , False )
  III = "key-id {}" . format ( III ) if III == OoOOoooO0oo . key_id else "bad key-id {}" . format ( OoOOoooO0oo . key_id )
  if 69 - 69: OOooOOo / OoooooooOO % ooOoO0o % iIii1I11I1II1 / OoO0O00 + iIii1I11I1II1
  lprint ( "  Authentication {} for {}EID-prefix {}, {}" . format ( II11 , O0O0O0OO0o0 , green ( oOOoo , False ) , III ) )
  if 47 - 47: II111iiii % O0 / I1IiiI / iIii1I11I1II1 * I11i
  if 60 - 60: O0 * iII111i % I1ii11iIi11i
  if 92 - 92: OoOoOO00 / iIii1I11I1II1
  if 67 - 67: i1IIi + i11iIiiIii - i1IIi % OoOoOO00
  if 3 - 3: I1IiiI % ooOoO0o
  if 32 - 32: OOooOOo / i1IIi / OOooOOo
  O00O0oOOoOo0o = True
  Ooo0O00oOOOO = ( lisp_get_eid_hash ( iIiiIi11Iii . eid ) != None )
  if ( Ooo0O00oOOOO or Ooo000oOOooO00 . require_signature ) :
   o0oOoO0O000 = "Required " if Ooo000oOOooO00 . require_signature else ""
   oOOoo = green ( oOOoo , False )
   iIIiIi1111iiIii = lisp_find_sig_in_rloc_set ( packet , iIiiIi11Iii . rloc_count )
   if ( iIIiIi1111iiIii == None ) :
    O00O0oOOoOo0o = False
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}, no signature found" ) . format ( o0oOoO0O000 ,
    # O0 - Oo0Ooo % oO0o / iIii1I11I1II1
 bold ( "failed" , False ) , oOOoo ) )
   else :
    O00O0oOOoOo0o = lisp_verify_cga_sig ( iIiiIi11Iii . eid , iIIiIi1111iiIii )
    II11 = bold ( "passed" if O00O0oOOoOo0o else "failed" , False )
    lprint ( ( "  {}EID-crypto-hash signature verification {} " + "for EID-prefix {}" ) . format ( o0oOoO0O000 , II11 , oOOoo ) )
    if 31 - 31: O0 + i1IIi
    if 52 - 52: OoO0O00 % iII111i % O0
    if 11 - 11: i1IIi / i11iIiiIii + Ii1I % Oo0Ooo % O0
    if 50 - 50: oO0o . I1Ii111
  if ( I1IooOoOO == False or O00O0oOOoOo0o == False ) :
   packet = ooO0 . end_of_rlocs ( packet , iIiiIi11Iii . rloc_count )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 38 - 38: iIii1I11I1II1 . Ii1I
   continue
   if 82 - 82: OOooOOo * Ii1I + I1ii11iIi11i . OoO0O00
   if 15 - 15: O0
   if 44 - 44: Ii1I . Oo0Ooo . I1Ii111 + oO0o
   if 32 - 32: OOooOOo - II111iiii + IiII * iIii1I11I1II1 - Oo0Ooo
   if 25 - 25: ooOoO0o
   if 33 - 33: Oo0Ooo
  if ( OoOOoooO0oo . merge_register_requested ) :
   ooOOoo0o = Ooo000oOOooO00
   ooOOoo0o . inconsistent_registration = False
   if 11 - 11: I11i
   if 55 - 55: i11iIiiIii * OoOoOO00 - OoOoOO00 * OoO0O00 / iII111i
   if 64 - 64: iIii1I11I1II1 . Ii1I * Oo0Ooo - OoO0O00
   if 74 - 74: I1IiiI / o0oOOo0O0Ooo
   if 53 - 53: iIii1I11I1II1 * oO0o
   if ( Ooo000oOOooO00 . group . is_null ( ) ) :
    if ( ooOOoo0o . site_id != OoOOoooO0oo . site_id ) :
     ooOOoo0o . site_id = OoOOoooO0oo . site_id
     ooOOoo0o . registered = False
     ooOOoo0o . individual_registrations = { }
     ooOOoo0o . registered_rlocs = [ ]
     lisp_registered_count -= 1
     if 43 - 43: IiII * Oo0Ooo / OOooOOo % oO0o
     if 11 - 11: OoOoOO00 * Oo0Ooo / I11i * OOooOOo
     if 15 - 15: ooOoO0o - OOooOOo / OoooooooOO
   I1IIiiI1II = OoOOoooO0oo . xtr_id
   if ( I1IIiiI1II in Ooo000oOOooO00 . individual_registrations ) :
    Ooo000oOOooO00 = Ooo000oOOooO00 . individual_registrations [ I1IIiiI1II ]
   else :
    Ooo000oOOooO00 = lisp_site_eid ( o0oOO0 )
    Ooo000oOOooO00 . eid . copy_address ( ooOOoo0o . eid )
    Ooo000oOOooO00 . group . copy_address ( ooOOoo0o . group )
    Ooo000oOOooO00 . encrypt_json = ooOOoo0o . encrypt_json
    ooOOoo0o . individual_registrations [ I1IIiiI1II ] = Ooo000oOOooO00
    if 41 - 41: OoOoOO00 . iII111i . i1IIi + oO0o
  else :
   Ooo000oOOooO00 . inconsistent_registration = Ooo000oOOooO00 . merge_register_requested
   if 60 - 60: oO0o * I1Ii111
   if 81 - 81: oO0o - OOooOOo - oO0o
   if 54 - 54: oO0o % I11i
  Ooo000oOOooO00 . map_registers_received += 1
  if 71 - 71: oO0o / I1ii11iIi11i . Ii1I % II111iiii
  if 22 - 22: iIii1I11I1II1 - OoooooooOO
  if 8 - 8: ooOoO0o % i11iIiiIii
  if 41 - 41: I1Ii111 . ooOoO0o - i11iIiiIii + Ii1I . OOooOOo . OoOoOO00
  if 70 - 70: i1IIi % OoOoOO00 / iII111i + i11iIiiIii % ooOoO0o + IiII
  I1ii = ( Ooo000oOOooO00 . is_rloc_in_rloc_set ( source ) == False )
  if ( iIiiIi11Iii . record_ttl == 0 and I1ii ) :
   lprint ( "  Ignore deregistration request from {}" . format ( red ( source . print_address_no_iid ( ) , False ) ) )
   if 58 - 58: OOooOOo / i11iIiiIii . Oo0Ooo % iII111i
   continue
   if 92 - 92: OoOoOO00 / ooOoO0o % iII111i / iIii1I11I1II1
   if 73 - 73: O0 % i11iIiiIii
   if 16 - 16: O0
   if 15 - 15: i1IIi % i11iIiiIii
   if 18 - 18: Ii1I . OoO0O00 . iII111i * oO0o + O0
   if 35 - 35: OoOoOO00 . oO0o / II111iiii
  o0o0ooO = Ooo000oOOooO00 . registered_rlocs
  Ooo000oOOooO00 . registered_rlocs = [ ]
  if 20 - 20: IiII / o0oOOo0O0Ooo - I11i / O0 + I1Ii111
  if 21 - 21: O0 / iIii1I11I1II1
  if 9 - 9: OoO0O00
  if 5 - 5: OOooOOo % iII111i % Oo0Ooo . I11i
  IiII11i1I11i1 = packet
  for iii1iII in range ( iIiiIi11Iii . rloc_count ) :
   ooO0 = lisp_rloc_record ( )
   packet = ooO0 . decode ( packet , None , Ooo000oOOooO00 . encrypt_json )
   if ( packet == None ) :
    lprint ( "  Could not decode RLOC-record in Map-Register packet" )
    return
    if 84 - 84: I11i . ooOoO0o . o0oOOo0O0Ooo - Oo0Ooo . OoO0O00 . OoooooooOO
   ooO0 . print_record ( "    " )
   if 17 - 17: Oo0Ooo - ooOoO0o
   if 67 - 67: O0
   if 81 - 81: iII111i
   if 93 - 93: IiII
   if ( len ( o0oOO0 . allowed_rlocs ) > 0 ) :
    O00oO000Oo0 = ooO0 . rloc . print_address ( )
    if ( O00oO000Oo0 not in o0oOO0 . allowed_rlocs ) :
     lprint ( ( "  Reject registration, RLOC {} not " + "configured in allowed RLOC-set" ) . format ( red ( O00oO000Oo0 , False ) ) )
     if 92 - 92: ooOoO0o * I1Ii111 % iIii1I11I1II1 % iII111i
     if 80 - 80: i1IIi * I1IiiI + OOooOOo
     Ooo000oOOooO00 . registered = False
     packet = ooO0 . end_of_rlocs ( packet ,
 iIiiIi11Iii . rloc_count - iii1iII - 1 )
     break
     if 91 - 91: I1IiiI % OoOoOO00 * Oo0Ooo / I1ii11iIi11i
     if 57 - 57: i11iIiiIii / o0oOOo0O0Ooo . II111iiii
     if 63 - 63: O0
     if 64 - 64: i11iIiiIii / oO0o . oO0o - Oo0Ooo
     if 48 - 48: i1IIi + I1ii11iIi11i + I1Ii111 - iII111i
     if 3 - 3: i1IIi + OoooooooOO * ooOoO0o + I1Ii111 % OOooOOo / IiII
   iIIiIi1111iiIii = lisp_rloc ( )
   iIIiIi1111iiIii . store_rloc_from_record ( ooO0 , None , source )
   if 70 - 70: oO0o + i1IIi % o0oOOo0O0Ooo - I11i
   if 74 - 74: i11iIiiIii
   if 93 - 93: I1Ii111 % OOooOOo * I1IiiI % iII111i / iIii1I11I1II1 + OoO0O00
   if 6 - 6: I11i
   if 70 - 70: ooOoO0o + OoooooooOO % OoOoOO00 % oO0o / Ii1I . I11i
   if 63 - 63: I1ii11iIi11i - ooOoO0o . OOooOOo / O0 . iIii1I11I1II1 - Ii1I
   if ( source . is_exact_match ( iIIiIi1111iiIii . rloc ) ) :
    iIIiIi1111iiIii . map_notify_requested = OoOOoooO0oo . map_notify_requested
    if 6 - 6: Ii1I
    if 60 - 60: iII111i + I1IiiI
    if 36 - 36: i1IIi . O0 . OoO0O00 % OOooOOo * I11i / Ii1I
    if 16 - 16: Oo0Ooo
    if 44 - 44: iIii1I11I1II1 - II111iiii . IiII . i1IIi
   Ooo000oOOooO00 . registered_rlocs . append ( iIIiIi1111iiIii )
   if 37 - 37: OoooooooOO + Oo0Ooo - Oo0Ooo + I1ii11iIi11i . I1Ii111 / I1IiiI
   if 60 - 60: I1IiiI % Ii1I / I1Ii111 + Ii1I
  iI11IIi = ( Ooo000oOOooO00 . do_rloc_sets_match ( o0o0ooO ) == False )
  if 51 - 51: ooOoO0o * I1ii11iIi11i + I1IiiI * OoOoOO00
  if 73 - 73: IiII - I1Ii111
  if 6 - 6: I1ii11iIi11i % IiII * O0
  if 38 - 38: iIii1I11I1II1 / I1IiiI * i11iIiiIii - IiII
  if 43 - 43: oO0o - I11i . i11iIiiIii
  if 78 - 78: i11iIiiIii + Oo0Ooo * Ii1I - o0oOOo0O0Ooo % i11iIiiIii
  if ( OoOOoooO0oo . map_register_refresh and iI11IIi and
 Ooo000oOOooO00 . registered ) :
   lprint ( "  Reject registration, refreshes cannot change RLOC-set" )
   Ooo000oOOooO00 . registered_rlocs = o0o0ooO
   continue
   if 30 - 30: I1IiiI % oO0o * OoooooooOO
   if 64 - 64: I1IiiI
   if 11 - 11: I1ii11iIi11i % iII111i / II111iiii % ooOoO0o % IiII
   if 14 - 14: ooOoO0o / IiII . o0oOOo0O0Ooo
   if 27 - 27: I1IiiI - OOooOOo . II111iiii * I1ii11iIi11i % ooOoO0o / I1IiiI
   if 90 - 90: o0oOOo0O0Ooo / I1ii11iIi11i - oO0o - Ii1I - I1IiiI + I1Ii111
  if ( Ooo000oOOooO00 . registered == False ) :
   Ooo000oOOooO00 . first_registered = lisp_get_timestamp ( )
   lisp_registered_count += 1
   if 93 - 93: I1IiiI - I11i . I1IiiI - iIii1I11I1II1
  Ooo000oOOooO00 . last_registered = lisp_get_timestamp ( )
  Ooo000oOOooO00 . registered = ( iIiiIi11Iii . record_ttl != 0 )
  Ooo000oOOooO00 . last_registerer = source
  if 1 - 1: O0 . Ii1I % Ii1I + II111iiii . oO0o
  if 24 - 24: o0oOOo0O0Ooo . I1Ii111 % O0
  if 67 - 67: I1IiiI * Ii1I
  if 64 - 64: OOooOOo
  Ooo000oOOooO00 . auth_sha1_or_sha2 = I11I1I1iiiIIi
  Ooo000oOOooO00 . proxy_reply_requested = OoOOoooO0oo . proxy_reply_requested
  Ooo000oOOooO00 . lisp_sec_present = OoOOoooO0oo . lisp_sec_present
  Ooo000oOOooO00 . map_notify_requested = OoOOoooO0oo . map_notify_requested
  Ooo000oOOooO00 . mobile_node_requested = OoOOoooO0oo . mobile_node
  Ooo000oOOooO00 . merge_register_requested = OoOOoooO0oo . merge_register_requested
  if 90 - 90: iII111i . OoOoOO00 + i1IIi % ooOoO0o * I11i + OoooooooOO
  Ooo000oOOooO00 . use_register_ttl_requested = OoOOoooO0oo . use_ttl_for_timeout
  if ( Ooo000oOOooO00 . use_register_ttl_requested ) :
   Ooo000oOOooO00 . register_ttl = iIiiIi11Iii . store_ttl ( )
  else :
   Ooo000oOOooO00 . register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
   if 2 - 2: o0oOOo0O0Ooo . II111iiii
  Ooo000oOOooO00 . xtr_id_present = OoOOoooO0oo . xtr_id_present
  if ( Ooo000oOOooO00 . xtr_id_present ) :
   Ooo000oOOooO00 . xtr_id = OoOOoooO0oo . xtr_id
   Ooo000oOOooO00 . site_id = OoOOoooO0oo . site_id
   if 9 - 9: I1Ii111 - II111iiii + OoOoOO00 . OoO0O00
   if 33 - 33: Oo0Ooo
   if 12 - 12: i11iIiiIii . Oo0Ooo / OoOoOO00 + iII111i . Ii1I + ooOoO0o
   if 66 - 66: IiII
   if 41 - 41: II111iiii + Oo0Ooo / iII111i . IiII / iII111i / I1IiiI
  if ( OoOOoooO0oo . merge_register_requested ) :
   if ( ooOOoo0o . merge_in_site_eid ( Ooo000oOOooO00 ) ) :
    II11iI1iI1I . append ( [ iIiiIi11Iii . eid , iIiiIi11Iii . group ] )
    if 78 - 78: o0oOOo0O0Ooo % OoOoOO00 . O0
   if ( OoOOoooO0oo . map_notify_requested ) :
    lisp_send_merged_map_notify ( lisp_sockets , ooOOoo0o , OoOOoooO0oo ,
 iIiiIi11Iii )
    if 41 - 41: iIii1I11I1II1 . OOooOOo - Oo0Ooo % OOooOOo
    if 90 - 90: i11iIiiIii + OoooooooOO - i11iIiiIii + OoooooooOO
    if 23 - 23: i11iIiiIii - IiII - I1ii11iIi11i + I1ii11iIi11i % I1IiiI
  if ( iI11IIi == False ) : continue
  if ( len ( II11iI1iI1I ) != 0 ) : continue
  if 79 - 79: II111iiii / OoooooooOO
  i1Ii11iIiI1Ii . append ( Ooo000oOOooO00 . print_eid_tuple ( ) )
  if 35 - 35: i1IIi + IiII + II111iiii % OOooOOo
  if 25 - 25: I11i + i11iIiiIii + O0 - Ii1I
  if 69 - 69: I11i . OoOoOO00 / OOooOOo / i1IIi . II111iiii
  if 17 - 17: I1Ii111
  if 2 - 2: O0 % OoOoOO00 + oO0o
  if 24 - 24: iII111i + iII111i - OoooooooOO % OoooooooOO * O0
  if 51 - 51: IiII
  I11iI11i1 = copy . deepcopy ( iIiiIi11Iii )
  iIiiIi11Iii = iIiiIi11Iii . encode ( )
  iIiiIi11Iii += IiII11i1I11i1
  OO0o0oo0oOo = [ Ooo000oOOooO00 . print_eid_tuple ( ) ]
  lprint ( "    Changed RLOC-set, Map-Notifying old RLOC-set" )
  if 59 - 59: i11iIiiIii % iIii1I11I1II1 / IiII
  for iIIiIi1111iiIii in o0o0ooO :
   if ( iIIiIi1111iiIii . map_notify_requested == False ) : continue
   if ( iIIiIi1111iiIii . rloc . is_exact_match ( source ) ) : continue
   lisp_build_map_notify ( lisp_sockets , iIiiIi11Iii , OO0o0oo0oOo , 1 , iIIiIi1111iiIii . rloc ,
 LISP_CTRL_PORT , OoOOoooO0oo . nonce , OoOOoooO0oo . key_id ,
 OoOOoooO0oo . alg_id , OoOOoooO0oo . auth_len , o0oOO0 , False )
   if 100 - 100: Ii1I . o0oOOo0O0Ooo - II111iiii . O0
   if 5 - 5: iII111i
   if 66 - 66: oO0o / OoOoOO00 . i1IIi % ooOoO0o . iII111i * I11i
   if 48 - 48: oO0o % OoOoOO00
   if 23 - 23: i1IIi - Ii1I - oO0o . OoooooooOO + OOooOOo * oO0o
  lisp_notify_subscribers ( lisp_sockets , I11iI11i1 , IiII11i1I11i1 ,
 Ooo000oOOooO00 . eid , o0oOO0 )
  if 56 - 56: O0 + OoOoOO00 + OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 . i11iIiiIii
  if 84 - 84: I11i + OOooOOo - OoooooooOO / I1ii11iIi11i
  if 12 - 12: I1IiiI * iIii1I11I1II1 - II111iiii / o0oOOo0O0Ooo - OOooOOo
  if 99 - 99: I1ii11iIi11i / O0 % II111iiii % I1Ii111 * II111iiii
  if 28 - 28: I11i - Oo0Ooo + iIii1I11I1II1 + O0 * Ii1I + I1IiiI
 if ( len ( II11iI1iI1I ) != 0 ) :
  lisp_queue_multicast_map_notify ( lisp_sockets , II11iI1iI1I )
  if 13 - 13: iII111i
  if 42 - 42: I1Ii111 - I1IiiI % I1IiiI * I1IiiI
  if 70 - 70: O0 / I1IiiI / I1IiiI
  if 71 - 71: OOooOOo - Oo0Ooo + IiII * oO0o
  if 90 - 90: OoOoOO00 * I1ii11iIi11i
  if 16 - 16: i1IIi - OoO0O00
 if ( OoOOoooO0oo . merge_register_requested ) : return
 if 61 - 61: o0oOOo0O0Ooo + OoOoOO00 - ooOoO0o + ooOoO0o % ooOoO0o % II111iiii
 if 16 - 16: I1IiiI . Ii1I
 if 80 - 80: OOooOOo * O0 / iIii1I11I1II1 / IiII / OoOoOO00
 if 15 - 15: I1ii11iIi11i * iII111i + i11iIiiIii
 if 68 - 68: i1IIi / oO0o * I1ii11iIi11i - OoOoOO00 + Oo0Ooo / O0
 if ( OoOOoooO0oo . map_notify_requested and o0oOO0 != None ) :
  lisp_build_map_notify ( lisp_sockets , iII11IiI , i1Ii11iIiI1Ii ,
 OoOOoooO0oo . record_count , source , sport , OoOOoooO0oo . nonce ,
 OoOOoooO0oo . key_id , OoOOoooO0oo . alg_id , OoOOoooO0oo . auth_len ,
 o0oOO0 , True )
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
 I1IIiIiii = lisp_map_notify ( "" )
 packet = I1IIiIiii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 12 - 12: I1Ii111
  if 17 - 17: I1Ii111 % oO0o + O0
 I1IIiIiii . print_notify ( )
 if ( I1IIiIiii . record_count == 0 ) : return
 if 15 - 15: o0oOOo0O0Ooo - OoooooooOO % ooOoO0o % oO0o / i11iIiiIii / Oo0Ooo
 O0Oo0O = I1IIiIiii . eid_records
 ooO0 = lisp_rloc_record ( )
 if 50 - 50: OoO0O00 . O0 * o0oOOo0O0Ooo . O0
 for o000o0O0Oo00 in range ( I1IIiIiii . record_count ) :
  iIiiIi11Iii = lisp_eid_record ( )
  O0Oo0O = iIiiIi11Iii . decode ( O0Oo0O )
  if ( packet == None ) : return
  iIiiIi11Iii . print_record ( "  " , False )
  oOOoo = iIiiIi11Iii . print_eid_tuple ( )
  OooO = iIiiIi11Iii . rloc_count
  if 28 - 28: OoOoOO00 % iIii1I11I1II1 + i1IIi * I1IiiI + O0 + ooOoO0o
  if 2 - 2: o0oOOo0O0Ooo + I1IiiI + I1ii11iIi11i
  if 94 - 94: o0oOOo0O0Ooo - OoOoOO00 * oO0o
  if 80 - 80: iII111i - O0 + IiII + iIii1I11I1II1 * I1ii11iIi11i
  if 8 - 8: OoO0O00
  IIII1 = lisp_map_cache_lookup ( iIiiIi11Iii . eid , iIiiIi11Iii . eid )
  if ( IIII1 == None ) :
   oOO = green ( oOOoo , False )
   lprint ( "Ignoring Map-Notify EID {}, no subscribe-request entry" . format ( oOO ) )
   if 99 - 99: iII111i . I1ii11iIi11i . o0oOOo0O0Ooo
   O0Oo0O = ooO0 . end_of_rlocs ( O0Oo0O , OooO )
   continue
   if 4 - 4: I11i * Oo0Ooo . i11iIiiIii / Ii1I . I1ii11iIi11i % I1Ii111
   if 68 - 68: ooOoO0o
   if 58 - 58: iII111i * I1IiiI
   if 82 - 82: Oo0Ooo / OoO0O00 % Oo0Ooo . ooOoO0o * O0
   if 39 - 39: I1Ii111 * IiII
   if 16 - 16: ooOoO0o + OoO0O00 / I11i * OoO0O00 . Oo0Ooo % OoOoOO00
   if 65 - 65: Oo0Ooo / I1Ii111 % II111iiii % Ii1I
  if ( IIII1 . action != LISP_SEND_PUBSUB_ACTION ) :
   if ( IIII1 . subscribed_eid == None ) :
    oOO = green ( oOOoo , False )
    lprint ( "Ignoring Map-Notify for non-subscribed EID {}" . format ( oOO ) )
    if 70 - 70: II111iiii % Oo0Ooo * oO0o
    O0Oo0O = ooO0 . end_of_rlocs ( O0Oo0O , OooO )
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
  if ( IIII1 . action == LISP_SEND_PUBSUB_ACTION ) :
   IIII1 = lisp_mapping ( iIiiIi11Iii . eid , iIiiIi11Iii . group , [ ] )
   IIII1 . add_cache ( )
   O0oOo00OOo0 = copy . deepcopy ( iIiiIi11Iii . eid )
   oooOOOOoOo0o = copy . deepcopy ( iIiiIi11Iii . group )
  else :
   O0oOo00OOo0 = IIII1 . subscribed_eid
   oooOOOOoOo0o = IIII1 . subscribed_group
   Oo00OOO0 = IIII1 . rloc_set
   IIII1 . delete_rlocs_from_rloc_probe_list ( )
   IIII1 . rloc_set = [ ]
   if 1 - 1: Ii1I
   if 97 - 97: Oo0Ooo - iII111i / I1ii11iIi11i
   if 49 - 49: iII111i + I11i . Oo0Ooo
   if 23 - 23: I1IiiI . Ii1I + ooOoO0o . OoooooooOO
   if 57 - 57: OOooOOo / OoOoOO00 / i11iIiiIii - I11i - I11i . Ii1I
  IIII1 . mapping_source = None if source == "lisp-itr" else source
  IIII1 . map_cache_ttl = iIiiIi11Iii . store_ttl ( )
  IIII1 . subscribed_eid = O0oOo00OOo0
  IIII1 . subscribed_group = oooOOOOoOo0o
  if 53 - 53: ooOoO0o . iII111i + Ii1I * I1Ii111
  if 49 - 49: II111iiii . I1ii11iIi11i * OoOoOO00 - OOooOOo
  if 48 - 48: OoO0O00 . iIii1I11I1II1 - OoooooooOO + I1Ii111 / i11iIiiIii . Oo0Ooo
  if 61 - 61: II111iiii + OOooOOo . o0oOOo0O0Ooo . iIii1I11I1II1
  if 63 - 63: I11i + i11iIiiIii . o0oOOo0O0Ooo . i1IIi + OoOoOO00
  if ( len ( Oo00OOO0 ) != 0 and iIiiIi11Iii . rloc_count == 0 ) :
   IIII1 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , IIII1 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( oOOoo , False ) ) )
   if 1 - 1: i11iIiiIii
   O0Oo0O = ooO0 . end_of_rlocs ( O0Oo0O , OooO )
   continue
   if 1 - 1: iIii1I11I1II1
   if 73 - 73: iII111i + IiII
   if 95 - 95: O0
   if 75 - 75: ooOoO0o
   if 8 - 8: O0 - OoooooooOO + I1ii11iIi11i / Oo0Ooo . oO0o + I1Ii111
   if 85 - 85: ooOoO0o
   if 29 - 29: iII111i . Ii1I
  i11Ii111Ii = I1IIii1I = 0
  for iii1iII in range ( OooO ) :
   ooO0 = lisp_rloc_record ( )
   O0Oo0O = ooO0 . decode ( O0Oo0O , None )
   ooO0 . print_record ( "    " )
   if 33 - 33: OoO0O00 . IiII . IiII + OoooooooOO
   if 33 - 33: I1ii11iIi11i % i11iIiiIii / II111iiii . I1Ii111 % o0oOOo0O0Ooo . ooOoO0o
   if 15 - 15: oO0o % O0
   if 70 - 70: ooOoO0o - IiII . ooOoO0o / iIii1I11I1II1 - ooOoO0o / OoooooooOO
   iiO0Ii1IiiiI = False
   for IIi1iii in Oo00OOO0 :
    if ( IIi1iii . rloc . is_exact_match ( ooO0 . rloc ) ) :
     iiO0Ii1IiiiI = True
     break
     if 12 - 12: o0oOOo0O0Ooo / iIii1I11I1II1 + OOooOOo
     if 20 - 20: i11iIiiIii
   if ( iiO0Ii1IiiiI ) :
    iIIiIi1111iiIii = copy . deepcopy ( IIi1iii )
    I1IIii1I += 1
   else :
    iIIiIi1111iiIii = lisp_rloc ( )
    i11Ii111Ii += 1
    if 10 - 10: iIii1I11I1II1 % i1IIi
    if 78 - 78: I11i + II111iiii % o0oOOo0O0Ooo
    if 17 - 17: i11iIiiIii + oO0o * iII111i . II111iiii
    if 44 - 44: I1ii11iIi11i
    if 39 - 39: iII111i + Oo0Ooo / oO0o
   iIIiIi1111iiIii . store_rloc_from_record ( ooO0 , None , IIII1 . mapping_source )
   IIII1 . rloc_set . append ( iIIiIi1111iiIii )
   if 95 - 95: I1Ii111 * oO0o / ooOoO0o . Ii1I . OoOoOO00
   if 99 - 99: I1IiiI * II111iiii
  lprint ( "Update {} map-cache entry with {}/{} new/replaced RLOCs" . format ( green ( oOOoo , False ) , i11Ii111Ii , I1IIii1I ) )
  if 84 - 84: II111iiii - I1IiiI
  if 41 - 41: iIii1I11I1II1 % I1Ii111 % OoOoOO00
  if 35 - 35: I11i + i1IIi
  if 85 - 85: Ii1I * Ii1I . OoOoOO00 / Oo0Ooo
  if 97 - 97: oO0o % iIii1I11I1II1
  IIII1 . build_best_rloc_set ( )
  lisp_write_ipc_map_cache ( True , IIII1 )
  if 87 - 87: II111iiii % I1IiiI + oO0o - I11i / I11i
  if 16 - 16: I1IiiI
  if 39 - 39: ooOoO0o * II111iiii
  if 90 - 90: OoooooooOO * ooOoO0o
  if 14 - 14: I1IiiI % i1IIi
  if 35 - 35: ooOoO0o % o0oOOo0O0Ooo % ooOoO0o
 oOO0 = lisp_get_map_server ( source )
 if ( oOO0 == None ) :
  lprint ( "Cannot find Map-Server for Map-Notify source address {}" . format ( source . print_address_no_iid ( ) ) )
  if 77 - 77: OOooOOo % I1Ii111 / i11iIiiIii . i1IIi % OOooOOo
  return
  if 55 - 55: i1IIi
 lisp_send_map_notify_ack ( lisp_sockets , O0Oo0O , I1IIiIiii , oOO0 )
 if 64 - 64: oO0o . OOooOOo * i11iIiiIii + I1Ii111
 if 88 - 88: O0
 if 75 - 75: iII111i - Oo0Ooo / OoooooooOO - O0
 if 36 - 36: OoO0O00 % Ii1I . Oo0Ooo
 if 90 - 90: i11iIiiIii - iII111i * oO0o
 if 79 - 79: IiII
 if 38 - 38: I1Ii111
 if 56 - 56: i11iIiiIii
 if 58 - 58: i11iIiiIii / OoOoOO00
 if 23 - 23: I1IiiI % iIii1I11I1II1 - oO0o - iII111i - o0oOOo0O0Ooo
def lisp_process_multicast_map_notify ( packet , source ) :
 I1IIiIiii = lisp_map_notify ( "" )
 packet = I1IIiIiii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 39 - 39: Oo0Ooo . OoO0O00
  if 74 - 74: I1IiiI . O0 . IiII + IiII - IiII
 I1IIiIiii . print_notify ( )
 if ( I1IIiIiii . record_count == 0 ) : return
 if 100 - 100: ooOoO0o / OoooooooOO
 O0Oo0O = I1IIiIiii . eid_records
 if 73 - 73: i11iIiiIii - Oo0Ooo
 for o000o0O0Oo00 in range ( I1IIiIiii . record_count ) :
  iIiiIi11Iii = lisp_eid_record ( )
  O0Oo0O = iIiiIi11Iii . decode ( O0Oo0O )
  if ( packet == None ) : return
  iIiiIi11Iii . print_record ( "  " , False )
  if 100 - 100: iIii1I11I1II1 + I1Ii111
  if 51 - 51: o0oOOo0O0Ooo * I11i
  if 42 - 42: OOooOOo % I11i
  if 84 - 84: Oo0Ooo * OoOoOO00 / Ii1I / IiII / o0oOOo0O0Ooo . I1ii11iIi11i
  IIII1 = lisp_map_cache_lookup ( iIiiIi11Iii . eid , iIiiIi11Iii . group )
  if ( IIII1 == None or IIII1 . action == LISP_SEND_PUBSUB_ACTION ) :
   if ( IIII1 == None ) :
    o0OO0 , O0O0oOO , Ooooo00OO = lisp_allow_gleaning ( iIiiIi11Iii . eid ,
 iIiiIi11Iii . group , None )
    if ( o0OO0 == False ) : continue
    if 55 - 55: I1IiiI % OOooOOo
    if 3 - 3: iIii1I11I1II1 / I1IiiI . Oo0Ooo - iIii1I11I1II1
   IIII1 = lisp_mapping ( iIiiIi11Iii . eid , iIiiIi11Iii . group , [ ] )
   IIII1 . add_cache ( )
   if 83 - 83: iII111i - I1ii11iIi11i + iII111i
   if 4 - 4: o0oOOo0O0Ooo % iIii1I11I1II1 + I11i
   if 60 - 60: I1ii11iIi11i / I1Ii111 % i11iIiiIii % oO0o % I1IiiI . Oo0Ooo
   if 20 - 20: IiII - OOooOOo + OoOoOO00
   if 83 - 83: OoooooooOO / I1IiiI + iII111i - iIii1I11I1II1 % ooOoO0o
   if 74 - 74: OoO0O00
   if 13 - 13: I1ii11iIi11i / OoO0O00
  if ( IIII1 . gleaned ) :
   lprint ( "Ignore Map-Notify for gleaned {}" . format ( green ( IIII1 . print_eid_tuple ( ) , False ) ) )
   if 90 - 90: iIii1I11I1II1 - OoO0O00 . i1IIi / o0oOOo0O0Ooo + O0
   continue
   if 94 - 94: IiII * i1IIi
   if 90 - 90: O0 % I1IiiI . o0oOOo0O0Ooo % ooOoO0o % I1IiiI
  IIII1 . mapping_source = None if source == "lisp-etr" else source
  IIII1 . map_cache_ttl = iIiiIi11Iii . store_ttl ( )
  if 16 - 16: OoO0O00 / OOooOOo / iIii1I11I1II1 / OoooooooOO . oO0o - I1Ii111
  if 43 - 43: OoOoOO00 % OOooOOo / I1IiiI + I1IiiI
  if 40 - 40: OOooOOo . I1Ii111 + I1Ii111
  if 4 - 4: iIii1I11I1II1 - iIii1I11I1II1 * I11i
  if 32 - 32: I1IiiI + II111iiii * iII111i + O0 / O0 * Oo0Ooo
  if ( len ( IIII1 . rloc_set ) != 0 and iIiiIi11Iii . rloc_count == 0 ) :
   IIII1 . rloc_set = [ ]
   IIII1 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , IIII1 )
   lprint ( "Update {} map-cache entry with no RLOC-set" . format ( green ( IIII1 . print_eid_tuple ( ) , False ) ) )
   if 64 - 64: i11iIiiIii / iII111i + i11iIiiIii . I11i
   continue
   if 66 - 66: i1IIi
   if 98 - 98: Oo0Ooo / iIii1I11I1II1
  ii1Ii111i = IIII1 . rtrs_in_rloc_set ( )
  if 63 - 63: OOooOOo . OOooOOo - I1IiiI * i11iIiiIii * II111iiii + I1IiiI
  if 68 - 68: OoOoOO00 + iIii1I11I1II1 * IiII * I11i % IiII % o0oOOo0O0Ooo
  if 10 - 10: IiII % i1IIi
  if 79 - 79: OoooooooOO % I11i / o0oOOo0O0Ooo + IiII + O0 + iII111i
  if 87 - 87: I11i
  for iii1iII in range ( iIiiIi11Iii . rloc_count ) :
   ooO0 = lisp_rloc_record ( )
   O0Oo0O = ooO0 . decode ( O0Oo0O , None )
   ooO0 . print_record ( "    " )
   if ( iIiiIi11Iii . group . is_null ( ) ) : continue
   if ( ooO0 . rle == None ) : continue
   if 39 - 39: I1ii11iIi11i * i11iIiiIii % I1Ii111
   if 72 - 72: OoO0O00 * Oo0Ooo - IiII
   if 74 - 74: Ii1I
   if 26 - 26: I11i . O0
   iIIiIi1111iiIii = lisp_rloc ( )
   iIIiIi1111iiIii . store_rloc_from_record ( ooO0 , None , IIII1 . mapping_source )
   if 68 - 68: Ii1I
   if 26 - 26: o0oOOo0O0Ooo - I1ii11iIi11i / O0 % i11iIiiIii
   if 7 - 7: I1Ii111 . Oo0Ooo + IiII / iIii1I11I1II1
   if 22 - 22: iIii1I11I1II1 - O0 . iII111i - IiII - ooOoO0o
   if 54 - 54: OoO0O00 . iII111i . OoOoOO00 * OoO0O00 + o0oOOo0O0Ooo . ooOoO0o
   I1IIIIiIii = IIII1 . rloc_set [ 0 ] if ( IIII1 . rloc_set != [ ] ) else None
   if ( I1IIIIiIii != None ) :
    for i1iiIiiIiI11 in iIIiIi1111iiIii . rle . rle_nodes :
     ii1ii11Iiii = I1IIIIiIii . get_rle ( i1iiIiiIiI11 . rloc . rloc )
     if ( ii1ii11Iiii == None ) : continue
     i1iiIiiIiI11 . rloc . uptime = ii1ii11Iiii . uptime
     i1iiIiiIiI11 . rloc . stats = copy . deepcopy ( ii1ii11Iiii . stats )
     i1iiIiiIiI11 . rloc . copy_rloc_probe_recents ( ii1ii11Iiii )
     if 14 - 14: OOooOOo % OoooooooOO + I1IiiI % OoOoOO00 / O0 - IiII
     if 88 - 88: OoO0O00 % Ii1I
     if 12 - 12: OoooooooOO . O0
   if ( ii1Ii111i and iIIiIi1111iiIii . is_rtr ( ) == False ) : continue
   if 33 - 33: OoooooooOO / I11i . II111iiii * i1IIi
   IIII1 . rloc_set = [ iIIiIi1111iiIii ]
   IIII1 . action = LISP_NO_ACTION
   IIII1 . build_best_rloc_set ( )
   lisp_write_ipc_map_cache ( True , IIII1 )
   if 34 - 34: i11iIiiIii / OoOoOO00
   lprint ( "Update {} map-cache entry with RLE {}" . format ( green ( IIII1 . print_eid_tuple ( ) , False ) ,
   # oO0o + I1IiiI - I11i / I1IiiI + o0oOOo0O0Ooo % iIii1I11I1II1
 iIIiIi1111iiIii . rle . print_rle ( False , True ) ) )
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
 I1IIiIiii = lisp_map_notify ( "" )
 Oo00O0o0O = I1IIiIiii . decode ( orig_packet )
 if ( Oo00O0o0O == None ) :
  lprint ( "Could not decode Map-Notify packet" )
  return
  if 96 - 96: O0
  if 2 - 2: OoO0O00 / iII111i + o0oOOo0O0Ooo
 I1IIiIiii . print_notify ( )
 if 27 - 27: I11i - OoOoOO00 - ooOoO0o - I1IiiI
 if 51 - 51: I11i + I11i + O0 + O0 * I1Ii111
 if 61 - 61: IiII . O0
 if 38 - 38: Ii1I * I1ii11iIi11i - i11iIiiIii + ooOoO0o * I11i
 if 74 - 74: OoOoOO00 . o0oOOo0O0Ooo
 OOo0oOO0o0oo0 = source . print_address ( )
 if ( I1IIiIiii . alg_id != 0 or I1IIiIiii . auth_len != 0 ) :
  oOO0 = None
  for I1IIiiI1II in lisp_map_servers_list :
   if ( I1IIiiI1II . find ( OOo0oOO0o0oo0 ) == - 1 ) : continue
   oOO0 = lisp_map_servers_list [ I1IIiiI1II ]
   if 40 - 40: ooOoO0o + I1ii11iIi11i * i11iIiiIii / i1IIi
  if ( oOO0 == None ) :
   lprint ( ( "  Could not find Map-Server {} to authenticate " + "Map-Notify" ) . format ( OOo0oOO0o0oo0 ) )
   if 95 - 95: oO0o / IiII * II111iiii * Ii1I . OoO0O00 . OoO0O00
   return
   if 85 - 85: I1IiiI / II111iiii * OoO0O00 + ooOoO0o / OoO0O00 % OOooOOo
   if 100 - 100: I1Ii111 % OoooooooOO % OoOoOO00 % I1IiiI
  oOO0 . map_notifies_received += 1
  if 32 - 32: OoO0O00 + OOooOOo . OoO0O00 - Oo0Ooo
  I1IooOoOO = lisp_verify_auth ( Oo00O0o0O , I1IIiIiii . alg_id ,
 I1IIiIiii . auth_data , oOO0 . password )
  if 12 - 12: I1IiiI * OoO0O00 - II111iiii . i1IIi
  lprint ( "  Authentication {} for Map-Notify" . format ( "succeeded" if I1IooOoOO else "failed" ) )
  if 86 - 86: OOooOOo / OoooooooOO - IiII
  if ( I1IooOoOO == False ) : return
 else :
  oOO0 = lisp_ms ( OOo0oOO0o0oo0 , None , "" , 0 , "" , False , False , False , False , 0 , 0 , 0 ,
 None )
  if 56 - 56: I1ii11iIi11i - i1IIi * OoooooooOO * O0 * I1IiiI - I1Ii111
  if 32 - 32: OoooooooOO . OOooOOo . OoO0O00 . IiII / I11i % i1IIi
  if 21 - 21: O0 . OoO0O00 * I1ii11iIi11i % iII111i + OoooooooOO
  if 8 - 8: oO0o * iII111i * I11i
  if 30 - 30: I1Ii111
  if 61 - 61: iII111i
 O0Oo0O = I1IIiIiii . eid_records
 if ( I1IIiIiii . record_count == 0 ) :
  lisp_send_map_notify_ack ( lisp_sockets , O0Oo0O , I1IIiIiii , oOO0 )
  return
  if 50 - 50: Ii1I / I1IiiI . O0
  if 49 - 49: I1Ii111 . OoO0O00 % O0
  if 15 - 15: I11i - Oo0Ooo / I1Ii111 . ooOoO0o % I1IiiI
  if 62 - 62: II111iiii + ooOoO0o + I1IiiI
  if 70 - 70: o0oOOo0O0Ooo + Ii1I . OoO0O00 * Ii1I + OOooOOo + ooOoO0o
  if 13 - 13: I1ii11iIi11i
  if 97 - 97: oO0o - Oo0Ooo . i11iIiiIii % ooOoO0o * i11iIiiIii - OoooooooOO
  if 44 - 44: I11i % OoooooooOO / iII111i - i11iIiiIii * i1IIi * o0oOOo0O0Ooo
 iIiiIi11Iii = lisp_eid_record ( )
 Oo00O0o0O = iIiiIi11Iii . decode ( O0Oo0O )
 if ( Oo00O0o0O == None ) : return
 if 51 - 51: Ii1I + IiII / I1ii11iIi11i + O0 % Ii1I
 iIiiIi11Iii . print_record ( "  " , False )
 if 55 - 55: iII111i % o0oOOo0O0Ooo - oO0o % OoooooooOO
 for iii1iII in range ( iIiiIi11Iii . rloc_count ) :
  ooO0 = lisp_rloc_record ( )
  Oo00O0o0O = ooO0 . decode ( Oo00O0o0O , None )
  if ( Oo00O0o0O == None ) :
   lprint ( "  Could not decode RLOC-record in Map-Notify packet" )
   return
   if 18 - 18: OoooooooOO - I1ii11iIi11i
  ooO0 . print_record ( "    " )
  if 94 - 94: OOooOOo . Oo0Ooo + Ii1I * o0oOOo0O0Ooo
  if 79 - 79: OOooOOo + Oo0Ooo
  if 33 - 33: iIii1I11I1II1
  if 75 - 75: I1Ii111 / iIii1I11I1II1 . OoooooooOO
  if 98 - 98: iIii1I11I1II1 / I1IiiI + i1IIi
 if ( iIiiIi11Iii . group . is_null ( ) == False ) :
  if 80 - 80: II111iiii . Oo0Ooo * oO0o % II111iiii / I1ii11iIi11i
  if 66 - 66: iII111i / OoO0O00 / i11iIiiIii
  if 99 - 99: OOooOOo
  if 51 - 51: i11iIiiIii . o0oOOo0O0Ooo / iII111i
  if 53 - 53: oO0o / i1IIi - Oo0Ooo - i1IIi + IiII
  lprint ( "Send {} Map-Notify IPC message to ITR process" . format ( green ( iIiiIi11Iii . print_eid_tuple ( ) , False ) ) )
  if 79 - 79: oO0o % o0oOOo0O0Ooo / o0oOOo0O0Ooo % iII111i
  if 56 - 56: Oo0Ooo % I1ii11iIi11i
  ooo0ooo0Oo = lisp_control_packet_ipc ( orig_packet , OOo0oOO0o0oo0 , "lisp-itr" , 0 )
  lisp_ipc ( ooo0ooo0Oo , lisp_sockets [ 2 ] , "lisp-core-pkt" )
  if 53 - 53: OoO0O00 . I11i - ooOoO0o
  if 11 - 11: I11i + i11iIiiIii / oO0o % oO0o * o0oOOo0O0Ooo / OoOoOO00
  if 74 - 74: oO0o . I1Ii111 . II111iiii
  if 92 - 92: I1Ii111 % OoooooooOO * I1Ii111
  if 78 - 78: Oo0Ooo . I11i . oO0o + O0 / O0
 lisp_send_map_notify_ack ( lisp_sockets , O0Oo0O , I1IIiIiii , oOO0 )
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
 I1IIiIiii = lisp_map_notify ( "" )
 packet = I1IIiIiii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Notify-Ack packet" )
  return
  if 71 - 71: I11i - Ii1I + i11iIiiIii % I1ii11iIi11i - OoO0O00 - OOooOOo
  if 71 - 71: OOooOOo
 I1IIiIiii . print_notify ( )
 if 27 - 27: OOooOOo * O0 * i11iIiiIii / OoOoOO00 - i1IIi
 if 73 - 73: iII111i / I1IiiI * ooOoO0o
 if 85 - 85: I11i + I11i + oO0o - OoOoOO00
 if 15 - 15: OoO0O00
 if 88 - 88: Ii1I % i1IIi / I1Ii111
 if ( I1IIiIiii . record_count < 1 ) :
  lprint ( "No EID-prefix found, cannot authenticate Map-Notify-Ack" )
  return
  if 2 - 2: Ii1I . IiII % OoOoOO00
  if 42 - 42: OoOoOO00 * OoO0O00 * IiII - IiII % Oo0Ooo . IiII
 iIiiIi11Iii = lisp_eid_record ( )
 if 38 - 38: I1Ii111 . IiII - ooOoO0o . i11iIiiIii
 if ( iIiiIi11Iii . decode ( I1IIiIiii . eid_records ) == None ) :
  lprint ( "Could not decode EID-record, cannot authenticate " +
 "Map-Notify-Ack" )
  return
  if 35 - 35: i11iIiiIii
 iIiiIi11Iii . print_record ( "  " , False )
 if 62 - 62: O0 - o0oOOo0O0Ooo + I1Ii111 * I1ii11iIi11i / OOooOOo
 oOOoo = iIiiIi11Iii . print_eid_tuple ( )
 if 87 - 87: Oo0Ooo / OoooooooOO + O0 / o0oOOo0O0Ooo % II111iiii - O0
 if 63 - 63: OOooOOo - OoO0O00 * i1IIi - I1ii11iIi11i . I1IiiI
 if 59 - 59: i11iIiiIii . OOooOOo % Oo0Ooo + O0
 if 84 - 84: I1Ii111 / O0 - IiII . I11i / o0oOOo0O0Ooo
 if ( I1IIiIiii . alg_id != LISP_NONE_ALG_ID and I1IIiIiii . auth_len != 0 ) :
  Ooo000oOOooO00 = lisp_sites_by_eid . lookup_cache ( iIiiIi11Iii . eid , True )
  if ( Ooo000oOOooO00 == None ) :
   i1iiiiI1I = bold ( "Site not found" , False )
   lprint ( ( "{} for EID {}, cannot authenticate Map-Notify-Ack" ) . format ( i1iiiiI1I , green ( oOOoo , False ) ) )
   if 12 - 12: i11iIiiIii / Ii1I + i1IIi
   return
   if 54 - 54: I1IiiI
  o0oOO0 = Ooo000oOOooO00 . site
  if 55 - 55: I1ii11iIi11i % IiII % o0oOOo0O0Ooo + i1IIi * OoooooooOO % II111iiii
  if 37 - 37: Oo0Ooo
  if 33 - 33: OoooooooOO - O0 . O0 - o0oOOo0O0Ooo % o0oOOo0O0Ooo % OoO0O00
  if 27 - 27: ooOoO0o . i11iIiiIii / o0oOOo0O0Ooo * OoO0O00 * OoOoOO00 * oO0o
  o0oOO0 . map_notify_acks_received += 1
  if 19 - 19: O0 * II111iiii * OoOoOO00
  III = I1IIiIiii . key_id
  if ( III in o0oOO0 . auth_key ) :
   ii1II1II11I = o0oOO0 . auth_key [ III ]
  else :
   ii1II1II11I = ""
   if 53 - 53: Oo0Ooo
   if 16 - 16: Ii1I
  I1IooOoOO = lisp_verify_auth ( packet , I1IIiIiii . alg_id ,
 I1IIiIiii . auth_data , ii1II1II11I )
  if 73 - 73: i11iIiiIii + I1IiiI - IiII - IiII + IiII . Ii1I
  III = "key-id {}" . format ( III ) if III == I1IIiIiii . key_id else "bad key-id {}" . format ( I1IIiIiii . key_id )
  if 78 - 78: OoO0O00 + oO0o
  if 86 - 86: ooOoO0o . ooOoO0o + oO0o
  lprint ( "  Authentication {} for Map-Notify-Ack, {}" . format ( "succeeded" if I1IooOoOO else "failed" , III ) )
  if 84 - 84: OOooOOo - OoOoOO00 + i1IIi * I1ii11iIi11i % I1ii11iIi11i * I1Ii111
  if ( I1IooOoOO == False ) : return
  if 31 - 31: IiII + iII111i
  if 5 - 5: O0 * Ii1I
  if 78 - 78: iII111i * iIii1I11I1II1 . OoO0O00 . OoOoOO00 % I1Ii111
  if 77 - 77: OOooOOo / OoooooooOO
  if 11 - 11: iIii1I11I1II1 - Ii1I - OoOoOO00 . oO0o / I1ii11iIi11i
 if ( I1IIiIiii . retransmit_timer ) : I1IIiIiii . retransmit_timer . cancel ( )
 if 79 - 79: i11iIiiIii % o0oOOo0O0Ooo * II111iiii . i1IIi * Ii1I - i11iIiiIii
 O0o0 = source . print_address ( )
 I1IIiiI1II = I1IIiIiii . nonce_key
 if 31 - 31: IiII / o0oOOo0O0Ooo
 if ( I1IIiiI1II in lisp_map_notify_queue ) :
  I1IIiIiii = lisp_map_notify_queue . pop ( I1IIiiI1II )
  if ( I1IIiIiii . retransmit_timer ) : I1IIiIiii . retransmit_timer . cancel ( )
  lprint ( "Dequeue Map-Notify from retransmit queue, key is: {}" . format ( I1IIiiI1II ) )
  if 27 - 27: Oo0Ooo
 else :
  lprint ( "Map-Notify with nonce 0x{} queue entry not found for {}" . format ( I1IIiIiii . nonce_key , red ( O0o0 , False ) ) )
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
 OOOOOo0O0oOO = False
 if ( group . is_null ( ) == False ) :
  OOOOOo0O0oOO = mr . last_cached_prefix [ 1 ] . is_more_specific ( group )
  if 48 - 48: iII111i + Ii1I
 if ( OOOOOo0O0oOO == False ) :
  OOOOOo0O0oOO = mr . last_cached_prefix [ 0 ] . is_more_specific ( eid )
  if 45 - 45: oO0o / iIii1I11I1II1 % O0 % IiII % I1ii11iIi11i
  if 89 - 89: OOooOOo - I1Ii111 - iII111i
 if ( OOOOOo0O0oOO ) :
  I1iii = lisp_print_eid_tuple ( eid , group )
  o000oOoo0 = lisp_print_eid_tuple ( mr . last_cached_prefix [ 0 ] ,
 mr . last_cached_prefix [ 1 ] )
  if 20 - 20: OoO0O00 - I1IiiI % I1IiiI
  lprint ( ( "Map-Referral prefix {} from {} is not more-specific " + "than cached prefix {}" ) . format ( green ( I1iii , False ) , s ,
  # iII111i - o0oOOo0O0Ooo + i1IIi
 o000oOoo0 ) )
  if 29 - 29: iIii1I11I1II1
 return ( OOOOOo0O0oOO )
 if 51 - 51: I1IiiI / I1Ii111 - iIii1I11I1II1 . I1Ii111
 if 52 - 52: II111iiii / OoO0O00 . Ii1I
 if 68 - 68: iII111i
 if 67 - 67: I1IiiI * I1IiiI
 if 100 - 100: iII111i * iII111i . Oo0Ooo
 if 10 - 10: Oo0Ooo % ooOoO0o * Oo0Ooo
 if 48 - 48: ooOoO0o + II111iiii
def lisp_process_map_referral ( lisp_sockets , packet , source ) :
 if 73 - 73: II111iiii
 oOooOO0OO = lisp_map_referral ( )
 packet = oOooOO0OO . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode Map-Referral packet" )
  return
  if 63 - 63: i11iIiiIii . Oo0Ooo . OOooOOo - II111iiii
 oOooOO0OO . print_map_referral ( )
 if 35 - 35: II111iiii + IiII
 OOo0oOO0o0oo0 = source . print_address ( )
 o0oOoo00 = oOooOO0OO . nonce
 if 66 - 66: o0oOOo0O0Ooo % IiII
 if 39 - 39: IiII
 if 18 - 18: iII111i % o0oOOo0O0Ooo - i1IIi
 if 53 - 53: o0oOOo0O0Ooo + IiII - ooOoO0o % i11iIiiIii - i11iIiiIii - I1Ii111
 for o000o0O0Oo00 in range ( oOooOO0OO . record_count ) :
  iIiiIi11Iii = lisp_eid_record ( )
  packet = iIiiIi11Iii . decode ( packet )
  if ( packet == None ) :
   lprint ( "Could not decode EID-record in Map-Referral packet" )
   return
   if 79 - 79: II111iiii + i11iIiiIii . OOooOOo . I11i / iIii1I11I1II1
  iIiiIi11Iii . print_record ( "  " , True )
  if 62 - 62: O0
  if 52 - 52: OoooooooOO . oO0o
  if 38 - 38: ooOoO0o . i1IIi / iII111i + I1IiiI - II111iiii
  if 21 - 21: i11iIiiIii + II111iiii - i1IIi / OoooooooOO * OOooOOo % Oo0Ooo
  I1IIiiI1II = str ( o0oOoo00 )
  if ( I1IIiiI1II not in lisp_ddt_map_requestQ ) :
   lprint ( ( "Map-Referral nonce 0x{} from {} not found in " + "Map-Request queue, EID-record ignored" ) . format ( lisp_hex_string ( o0oOoo00 ) , OOo0oOO0o0oo0 ) )
   if 59 - 59: Ii1I
   if 77 - 77: I1ii11iIi11i * Ii1I * O0 * I1IiiI % OoO0O00 - iIii1I11I1II1
   continue
   if 6 - 6: i11iIiiIii . I11i - OoooooooOO
  II1iI1iII11 = lisp_ddt_map_requestQ [ I1IIiiI1II ]
  if ( II1iI1iII11 == None ) :
   lprint ( ( "No Map-Request queue entry found for Map-Referral " +
 "nonce 0x{} from {}, EID-record ignored" ) . format ( lisp_hex_string ( o0oOoo00 ) , OOo0oOO0o0oo0 ) )
   if 26 - 26: I1IiiI
   continue
   if 26 - 26: IiII . Ii1I / IiII - OoO0O00 % OoO0O00
   if 72 - 72: OoooooooOO * II111iiii + OoO0O00 % iIii1I11I1II1 . I1ii11iIi11i % OoooooooOO
   if 19 - 19: OoOoOO00 + I1Ii111
   if 19 - 19: I1ii11iIi11i / I1Ii111 + OoooooooOO - O0
   if 49 - 49: I1ii11iIi11i / OoOoOO00 - I1IiiI + iII111i . OOooOOo % oO0o
   if 34 - 34: OoO0O00 - I1IiiI + OoOoOO00
  if ( lisp_map_referral_loop ( II1iI1iII11 , iIiiIi11Iii . eid , iIiiIi11Iii . group ,
 iIiiIi11Iii . action , OOo0oOO0o0oo0 ) ) :
   II1iI1iII11 . dequeue_map_request ( )
   continue
   if 22 - 22: iIii1I11I1II1 . i1IIi . OOooOOo % Oo0Ooo - i1IIi
   if 78 - 78: I1IiiI / i1IIi % II111iiii % I1IiiI % Ii1I
  II1iI1iII11 . last_cached_prefix [ 0 ] = iIiiIi11Iii . eid
  II1iI1iII11 . last_cached_prefix [ 1 ] = iIiiIi11Iii . group
  if 29 - 29: i1IIi % o0oOOo0O0Ooo + OOooOOo / Oo0Ooo
  if 38 - 38: IiII . I1Ii111
  if 69 - 69: ooOoO0o + OoOoOO00 + II111iiii % I1Ii111 + Ii1I . ooOoO0o
  if 73 - 73: I11i % I11i . ooOoO0o + OoOoOO00
  iiO0 = False
  I1i11I = lisp_referral_cache_lookup ( iIiiIi11Iii . eid , iIiiIi11Iii . group ,
 True )
  if ( I1i11I == None ) :
   iiO0 = True
   I1i11I = lisp_referral ( )
   I1i11I . eid = iIiiIi11Iii . eid
   I1i11I . group = iIiiIi11Iii . group
   if ( iIiiIi11Iii . ddt_incomplete == False ) : I1i11I . add_cache ( )
  elif ( I1i11I . referral_source . not_set ( ) ) :
   lprint ( "Do not replace static referral entry {}" . format ( green ( I1i11I . print_eid_tuple ( ) , False ) ) )
   if 33 - 33: i11iIiiIii . i11iIiiIii * i11iIiiIii / iIii1I11I1II1 / I1ii11iIi11i . ooOoO0o
   II1iI1iII11 . dequeue_map_request ( )
   continue
   if 11 - 11: iII111i
   if 60 - 60: I1ii11iIi11i / I1Ii111
  oo0OoooOo0 = iIiiIi11Iii . action
  I1i11I . referral_source = source
  I1i11I . referral_type = oo0OoooOo0
  o0ooo000o00O = iIiiIi11Iii . store_ttl ( )
  I1i11I . referral_ttl = o0ooo000o00O
  I1i11I . expires = lisp_set_timestamp ( o0ooo000o00O )
  if 10 - 10: OoO0O00 * iIii1I11I1II1 / I11i % II111iiii . OoOoOO00 / I1IiiI
  if 4 - 4: Oo0Ooo * o0oOOo0O0Ooo
  if 45 - 45: Ii1I % OOooOOo * Ii1I - iIii1I11I1II1
  if 18 - 18: I1Ii111 / Oo0Ooo % Ii1I + OoO0O00
  o0Ooo0OoOo = I1i11I . is_referral_negative ( )
  if ( OOo0oOO0o0oo0 in I1i11I . referral_set ) :
   oooOOo0o00 = I1i11I . referral_set [ OOo0oOO0o0oo0 ]
   if 71 - 71: II111iiii
   if ( oooOOo0o00 . updown == False and o0Ooo0OoOo == False ) :
    oooOOo0o00 . updown = True
    lprint ( "Change up/down status for referral-node {} to up" . format ( OOo0oOO0o0oo0 ) )
    if 34 - 34: I1ii11iIi11i * oO0o + OoooooooOO
   elif ( oooOOo0o00 . updown == True and o0Ooo0OoOo == True ) :
    oooOOo0o00 . updown = False
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
  for I1IIiiI1II in I1i11I . referral_set : iiiiiIi [ I1IIiiI1II ] = None
  if 34 - 34: oO0o - Ii1I * o0oOOo0O0Ooo
  if 61 - 61: IiII * II111iiii / O0 . I1ii11iIi11i
  if 77 - 77: I1IiiI . IiII
  if 94 - 94: oO0o + Ii1I % IiII
  for o000o0O0Oo00 in range ( iIiiIi11Iii . rloc_count ) :
   ooO0 = lisp_rloc_record ( )
   packet = ooO0 . decode ( packet , None )
   if ( packet == None ) :
    lprint ( "Could not decode RLOC-record in Map-Referral packet" )
    return
    if 11 - 11: II111iiii
   ooO0 . print_record ( "    " )
   if 66 - 66: I11i % iIii1I11I1II1 - ooOoO0o . II111iiii % O0 + I1IiiI
   if 67 - 67: OoOoOO00 % OoooooooOO / OoO0O00 - OoO0O00 / O0
   if 19 - 19: iIii1I11I1II1 / OOooOOo % I11i % I1IiiI / I1ii11iIi11i
   if 73 - 73: II111iiii
   O00oO000Oo0 = ooO0 . rloc . print_address ( )
   if ( O00oO000Oo0 not in I1i11I . referral_set ) :
    oooOOo0o00 = lisp_referral_node ( )
    oooOOo0o00 . referral_address . copy_address ( ooO0 . rloc )
    I1i11I . referral_set [ O00oO000Oo0 ] = oooOOo0o00
    if ( OOo0oOO0o0oo0 == O00oO000Oo0 and o0Ooo0OoOo ) : oooOOo0o00 . updown = False
   else :
    oooOOo0o00 = I1i11I . referral_set [ O00oO000Oo0 ]
    if ( O00oO000Oo0 in iiiiiIi ) : iiiiiIi . pop ( O00oO000Oo0 )
    if 26 - 26: II111iiii . iIii1I11I1II1 - I1Ii111 % OOooOOo
   oooOOo0o00 . priority = ooO0 . priority
   oooOOo0o00 . weight = ooO0 . weight
   if 83 - 83: OOooOOo + OoooooooOO % I1Ii111 % IiII + i11iIiiIii
   if 10 - 10: OoooooooOO . Ii1I % I1Ii111 + IiII
   if 78 - 78: OoOoOO00 - oO0o . I1ii11iIi11i * i11iIiiIii
   if 44 - 44: iIii1I11I1II1 * iII111i
   if 32 - 32: OoOoOO00
  for I1IIiiI1II in iiiiiIi : I1i11I . referral_set . pop ( I1IIiiI1II )
  if 65 - 65: iIii1I11I1II1 + iII111i
  oOOoo = I1i11I . print_eid_tuple ( )
  if 90 - 90: i11iIiiIii - Oo0Ooo
  if ( iiO0 ) :
   if ( iIiiIi11Iii . ddt_incomplete ) :
    lprint ( "Suppress add {} to referral-cache" . format ( green ( oOOoo , False ) ) )
    if 31 - 31: OoOoOO00 + OoOoOO00 + OoooooooOO % O0
   else :
    lprint ( "Add {}, referral-count {} to referral-cache" . format ( green ( oOOoo , False ) , iIiiIi11Iii . rloc_count ) )
    if 14 - 14: i1IIi / OoooooooOO . I1IiiI * I1Ii111 + OoO0O00
    if 45 - 45: OoooooooOO * I1Ii111
  else :
   lprint ( "Replace {}, referral-count: {} in referral-cache" . format ( green ( oOOoo , False ) , iIiiIi11Iii . rloc_count ) )
   if 7 - 7: O0
   if 42 - 42: o0oOOo0O0Ooo / Ii1I
   if 31 - 31: OOooOOo
   if 20 - 20: i11iIiiIii * oO0o * ooOoO0o
   if 65 - 65: I1ii11iIi11i / Oo0Ooo / I1IiiI + IiII
   if 71 - 71: OoO0O00 . I1Ii111 + OoooooooOO
  if ( oo0OoooOo0 == LISP_DDT_ACTION_DELEGATION_HOLE ) :
   lisp_send_negative_map_reply ( II1iI1iII11 . lisp_sockets , I1i11I . eid ,
 I1i11I . group , II1iI1iII11 . nonce , II1iI1iII11 . itr , II1iI1iII11 . sport , 15 , None , False )
   II1iI1iII11 . dequeue_map_request ( )
   if 9 - 9: OoooooooOO / iIii1I11I1II1 % I1IiiI . I1IiiI / I11i - iII111i
   if 60 - 60: I11i - OoO0O00 - OoOoOO00 * ooOoO0o - i1IIi
  if ( oo0OoooOo0 == LISP_DDT_ACTION_NOT_AUTH ) :
   if ( II1iI1iII11 . tried_root ) :
    lisp_send_negative_map_reply ( II1iI1iII11 . lisp_sockets , I1i11I . eid ,
 I1i11I . group , II1iI1iII11 . nonce , II1iI1iII11 . itr , II1iI1iII11 . sport , 0 , None , False )
    II1iI1iII11 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( II1iI1iII11 , True )
    if 18 - 18: ooOoO0o + i11iIiiIii + O0 + OOooOOo / Ii1I
    if 65 - 65: I1IiiI . ooOoO0o
    if 51 - 51: I1Ii111
  if ( oo0OoooOo0 == LISP_DDT_ACTION_MS_NOT_REG ) :
   if ( OOo0oOO0o0oo0 in I1i11I . referral_set ) :
    oooOOo0o00 = I1i11I . referral_set [ OOo0oOO0o0oo0 ]
    oooOOo0o00 . updown = False
    if 89 - 89: Oo0Ooo
   if ( len ( I1i11I . referral_set ) == 0 ) :
    II1iI1iII11 . dequeue_map_request ( )
   else :
    lisp_send_ddt_map_request ( II1iI1iII11 , False )
    if 15 - 15: OOooOOo * II111iiii - OOooOOo * iIii1I11I1II1
    if 95 - 95: I1Ii111 / OoooooooOO * I11i * OoooooooOO
    if 88 - 88: I1IiiI / Oo0Ooo / oO0o + oO0o % OOooOOo + Oo0Ooo
  if ( oo0OoooOo0 in ( LISP_DDT_ACTION_NODE_REFERRAL ,
 LISP_DDT_ACTION_MS_REFERRAL ) ) :
   if ( II1iI1iII11 . eid . is_exact_match ( iIiiIi11Iii . eid ) ) :
    if ( not II1iI1iII11 . tried_root ) :
     lisp_send_ddt_map_request ( II1iI1iII11 , True )
    else :
     lisp_send_negative_map_reply ( II1iI1iII11 . lisp_sockets ,
 I1i11I . eid , I1i11I . group , II1iI1iII11 . nonce , II1iI1iII11 . itr ,
 II1iI1iII11 . sport , 15 , None , False )
     II1iI1iII11 . dequeue_map_request ( )
     if 63 - 63: o0oOOo0O0Ooo + i11iIiiIii % OOooOOo % iIii1I11I1II1 / I1ii11iIi11i - iII111i
   else :
    lisp_send_ddt_map_request ( II1iI1iII11 , False )
    if 72 - 72: iII111i % oO0o . IiII + I1ii11iIi11i . IiII . II111iiii
    if 10 - 10: I11i . ooOoO0o + I11i * Ii1I
    if 55 - 55: OOooOOo / iII111i + OoooooooOO - OoooooooOO
  if ( oo0OoooOo0 == LISP_DDT_ACTION_MS_ACK ) : II1iI1iII11 . dequeue_map_request ( )
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
 Ii1Ii1iii = lisp_ecm ( 0 )
 packet = Ii1Ii1iii . decode ( packet )
 if ( packet == None ) :
  lprint ( "Could not decode ECM packet" )
  return
  if 77 - 77: I11i + i1IIi * OoOoOO00 % OoooooooOO
  if 56 - 56: I1Ii111 * i1IIi % i11iIiiIii
 Ii1Ii1iii . print_ecm ( )
 if 56 - 56: Ii1I . iII111i
 I11 = lisp_control_header ( )
 if ( I11 . decode ( packet ) == None ) :
  lprint ( "Could not decode control header" )
  return
  if 76 - 76: I1IiiI / Ii1I % OoOoOO00 + IiII / i11iIiiIii . o0oOOo0O0Ooo
  if 31 - 31: oO0o * oO0o % o0oOOo0O0Ooo . O0 + iII111i
 ooIiii = I11 . type
 del ( I11 )
 if 71 - 71: ooOoO0o
 if ( ooIiii != LISP_MAP_REQUEST ) :
  lprint ( "Received ECM without Map-Request inside" )
  return
  if 71 - 71: i1IIi - oO0o / ooOoO0o * Ii1I
  if 28 - 28: II111iiii . IiII / iII111i + I1ii11iIi11i - ooOoO0o * iIii1I11I1II1
  if 53 - 53: Ii1I - Ii1I . Oo0Ooo . OOooOOo / OoooooooOO + iII111i
  if 52 - 52: IiII / OOooOOo * iIii1I11I1II1 + o0oOOo0O0Ooo
  if 20 - 20: I1Ii111
 IIIOOo0o = time . time ( )
 lisp_process_map_request ( lisp_sockets , packet , Ii1Ii1iii . source , Ii1Ii1iii . udp_sport ,
 source , outer_sport , Ii1Ii1iii . ddt , - 1 , IIIOOo0o )
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
 oOO00OoOo = ms . map_server
 if ( lisp_decent_push_configured and oOO00OoOo . is_multicast_address ( ) and
 ( ms . map_registers_multicast_sent == 1 or ms . map_registers_sent == 1 ) ) :
  oOO00OoOo = copy . deepcopy ( oOO00OoOo )
  oOO00OoOo . address = 0x7f000001
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
  OooOooo0 = ms . ekey . zfill ( 32 )
  Oo0OOOO0oOoo0 = "0" * 8
  oooO00oo0 = chacha . ChaCha ( OooOooo0 , Oo0OOOO0oOoo0 , 20 ) . encrypt ( packet [ 4 : : ] )
  packet = packet [ 0 : 4 ] + oooO00oo0
  oOO = bold ( "Encrypt" , False )
  lprint ( "{} Map-Register with key-id {}" . format ( oOO , ms . ekey_id ) )
  if 52 - 52: OoO0O00
  if 76 - 76: ooOoO0o - iII111i % ooOoO0o / oO0o . OOooOOo
 i11IIIi = ""
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  i11IIIi = ", decent-index {}" . format ( bold ( ms . dns_name , False ) )
  if 57 - 57: OoOoOO00 . iII111i
  if 43 - 43: I1Ii111 * OOooOOo - IiII . i11iIiiIii
 lprint ( "Send Map-Register to map-server {}{}{}" . format ( oOO00OoOo . print_address ( ) , ", ms-name '{}'" . format ( ms . ms_name ) , i11IIIi ) )
 if 34 - 34: iII111i . OoOoOO00
 lisp_send ( lisp_sockets , oOO00OoOo , LISP_CTRL_PORT , packet )
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
 ooOO0O0O = lisp_socket . getsockname ( )
 dest = dest . print_address_no_iid ( )
 if 75 - 75: I11i % OOooOOo - OoO0O00 * I11i * IiII
 lprint ( "Send IPC {} bytes to {} {}, control-packet: {}" . format ( len ( packet ) , dest , port , lisp_format_packet ( packet ) ) )
 if 11 - 11: I1ii11iIi11i . O0 - iII111i * IiII . i1IIi . iII111i
 if 82 - 82: i1IIi * I11i * Ii1I - IiII . i11iIiiIii
 packet = lisp_control_packet_ipc ( packet , ooOO0O0O , dest , port )
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
  iIIo0OOO , II1 = lisp_get_translated_port_for_mr ( O00oO000Oo0 )
  if ( II1 != None ) : inner_sport = II1
  if 62 - 62: O0
 Ii1Ii1iii = lisp_ecm ( inner_sport )
 if 40 - 40: OoOoOO00 - O0 / I1Ii111 + OoO0O00 + ooOoO0o
 Ii1Ii1iii . to_etr = to_etr if lisp_is_running ( "lisp-etr" ) else False
 Ii1Ii1iii . to_ms = to_ms if lisp_is_running ( "lisp-ms" ) else False
 Ii1Ii1iii . ddt = ddt
 OOoo0O0o = Ii1Ii1iii . encode ( packet , inner_source , inner_dest )
 if ( OOoo0O0o == None ) :
  lprint ( "Could not encode ECM message" )
  return
  if 15 - 15: iIii1I11I1II1 / I1ii11iIi11i * I1IiiI / i1IIi
 Ii1Ii1iii . print_ecm ( )
 if 57 - 57: o0oOOo0O0Ooo
 packet = OOoo0O0o + packet
 if 69 - 69: i11iIiiIii
 lprint ( "Send Encapsulated-Control-Message to {}" . format ( O00oO000Oo0 ) )
 oOO00OoOo = lisp_convert_4to6 ( O00oO000Oo0 )
 lisp_send ( lisp_sockets , oOO00OoOo , LISP_CTRL_PORT , packet )
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
   I1iIIIiI1iI11 = 0
  elif ( prefix . afi == LISP_AFI_IID_RANGE ) :
   I1iIIIiI1iI11 = prefix . mask_len
  else :
   I1iIIIiI1iI11 = prefix . mask_len + 48
   if 99 - 99: i1IIi + I1ii11iIi11i
   if 24 - 24: ooOoO0o / OoooooooOO % I1ii11iIi11i * ooOoO0o
  i1I1iI = lisp_hex_string ( prefix . instance_id ) . zfill ( 8 )
  Oo0ooooO0o00 = lisp_hex_string ( prefix . afi ) . zfill ( 4 )
  if 14 - 14: I1ii11iIi11i + OoO0O00 - I1IiiI - Oo0Ooo
  if ( prefix . afi > 0 ) :
   if ( prefix . is_binary ( ) ) :
    OOOOo0o0O0o = prefix . addr_length ( ) * 2
    iI1ii11Ii = lisp_hex_string ( prefix . address ) . zfill ( OOOOo0o0O0o )
   else :
    iI1ii11Ii = prefix . address
    if 44 - 44: II111iiii / I1ii11iIi11i
  elif ( prefix . afi == LISP_AFI_GEO_COORD ) :
   Oo0ooooO0o00 = "8003"
   iI1ii11Ii = prefix . address . print_geo ( )
  else :
   Oo0ooooO0o00 = ""
   iI1ii11Ii = ""
   if 39 - 39: OoooooooOO % OoO0O00
   if 83 - 83: OOooOOo % I1IiiI + O0 % OoooooooOO
  I1IIiiI1II = i1I1iI + Oo0ooooO0o00 + iI1ii11Ii
  return ( [ I1iIIIiI1iI11 , I1IIiiI1II ] )
  if 84 - 84: I11i - Oo0Ooo % ooOoO0o - II111iiii
  if 29 - 29: IiII
 def add_cache ( self , prefix , entry ) :
  if ( prefix . is_binary ( ) ) : prefix . zero_host_bits ( )
  I1iIIIiI1iI11 , I1IIiiI1II = self . build_key ( prefix )
  if ( I1iIIIiI1iI11 not in self . cache ) :
   self . cache [ I1iIIIiI1iI11 ] = lisp_cache_entries ( )
   self . cache_sorted = self . sort_in_entry ( self . cache_sorted , I1iIIIiI1iI11 )
   if 4 - 4: II111iiii * o0oOOo0O0Ooo - IiII * iII111i
  if ( I1IIiiI1II not in self . cache [ I1iIIIiI1iI11 ] . entries ) :
   self . cache_count += 1
   if 91 - 91: I1Ii111 * iII111i * OoO0O00
  self . cache [ I1iIIIiI1iI11 ] . entries [ I1IIiiI1II ] = entry
  if 79 - 79: iII111i + oO0o
  if 19 - 19: I1Ii111 - OOooOOo . ooOoO0o . O0 + II111iiii . OoooooooOO
 def lookup_cache ( self , prefix , exact ) :
  oooOoooOoo00o , I1IIiiI1II = self . build_key ( prefix )
  if ( exact ) :
   if ( oooOoooOoo00o not in self . cache ) : return ( None )
   if ( I1IIiiI1II not in self . cache [ oooOoooOoo00o ] . entries ) : return ( None )
   return ( self . cache [ oooOoooOoo00o ] . entries [ I1IIiiI1II ] )
   if 24 - 24: OoooooooOO % iII111i . II111iiii - O0 . i1IIi % Ii1I
   if 65 - 65: Oo0Ooo
  iiO0Ii1IiiiI = None
  for I1iIIIiI1iI11 in self . cache_sorted :
   if ( oooOoooOoo00o < I1iIIIiI1iI11 ) : return ( iiO0Ii1IiiiI )
   for I1I11i in list ( self . cache [ I1iIIIiI1iI11 ] . entries . values ( ) ) :
    if ( prefix . is_more_specific ( I1I11i . eid ) ) :
     if ( iiO0Ii1IiiiI == None or
 I1I11i . eid . is_more_specific ( iiO0Ii1IiiiI . eid ) ) : iiO0Ii1IiiiI = I1I11i
     if 64 - 64: I1ii11iIi11i * OoOoOO00 + II111iiii . I11i - I1IiiI * O0
     if 74 - 74: OoO0O00 * O0 - oO0o * OoooooooOO % I1Ii111
     if 95 - 95: OoOoOO00 + ooOoO0o . iIii1I11I1II1 * o0oOOo0O0Ooo
  return ( iiO0Ii1IiiiI )
  if 75 - 75: OOooOOo - i11iIiiIii - i1IIi - IiII * iII111i
  if 38 - 38: o0oOOo0O0Ooo - I1ii11iIi11i % o0oOOo0O0Ooo
 def delete_cache ( self , prefix ) :
  I1iIIIiI1iI11 , I1IIiiI1II = self . build_key ( prefix )
  if ( I1iIIIiI1iI11 not in self . cache ) : return
  if ( I1IIiiI1II not in self . cache [ I1iIIIiI1iI11 ] . entries ) : return
  self . cache [ I1iIIIiI1iI11 ] . entries . pop ( I1IIiiI1II )
  self . cache_count -= 1
  if 8 - 8: oO0o + I11i . I1ii11iIi11i
  if 57 - 57: I11i
 def walk_cache ( self , function , parms ) :
  for I1iIIIiI1iI11 in self . cache_sorted :
   for I1I11i in list ( self . cache [ I1iIIIiI1iI11 ] . entries . values ( ) ) :
    i1oO0000OOO0O , parms = function ( I1I11i , parms )
    if ( i1oO0000OOO0O == False ) : return ( parms )
    if 91 - 91: OOooOOo + oO0o % i11iIiiIii
    if 91 - 91: OoO0O00 % iIii1I11I1II1
  return ( parms )
  if 66 - 66: iII111i + i1IIi
  if 24 - 24: O0 / OoooooooOO - OoOoOO00
 def sort_in_entry ( self , table , value ) :
  if ( table == [ ] ) : return ( [ value ] )
  if 51 - 51: OoO0O00 + o0oOOo0O0Ooo - II111iiii * I11i + Ii1I
  IiI111ii = table
  while ( True ) :
   if ( len ( IiI111ii ) == 1 ) :
    if ( value == IiI111ii [ 0 ] ) : return ( table )
    o00O = table . index ( IiI111ii [ 0 ] )
    if ( value < IiI111ii [ 0 ] ) :
     return ( table [ 0 : o00O ] + [ value ] + table [ o00O : : ] )
     if 16 - 16: I1Ii111 * i1IIi . I1IiiI . OOooOOo % Ii1I - o0oOOo0O0Ooo
    if ( value > IiI111ii [ 0 ] ) :
     return ( table [ 0 : o00O + 1 ] + [ value ] + table [ o00O + 1 : : ] )
     if 89 - 89: Ii1I * I1ii11iIi11i * I1IiiI % iII111i % Ii1I + O0
     if 53 - 53: i11iIiiIii % I1ii11iIi11i
   o00O = old_div ( len ( IiI111ii ) , 2 )
   IiI111ii = IiI111ii [ 0 : o00O ] if ( value < IiI111ii [ o00O ] ) else IiI111ii [ o00O : : ]
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
  for I1iIIIiI1iI11 in self . cache_sorted :
   for I1IIiiI1II in self . cache [ I1iIIIiI1iI11 ] . entries :
    I1I11i = self . cache [ I1iIIIiI1iI11 ] . entries [ I1IIiiI1II ]
    lprint ( "  Mask-length: {}, key: {}, entry: {}" . format ( I1iIIIiI1iI11 , I1IIiiI1II ,
 I1I11i ) )
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
 I1iI1III = dest . is_multicast_address ( )
 if 37 - 37: Oo0Ooo . I1ii11iIi11i / OoooooooOO % ooOoO0o / I1IiiI + ooOoO0o
 if 14 - 14: I11i + ooOoO0o . oO0o * I11i
 if 98 - 98: Ii1I . i1IIi * OoO0O00 * Ii1I * iIii1I11I1II1
 if 22 - 22: OoooooooOO - OoO0O00 + OoOoOO00 - OOooOOo + i11iIiiIii - oO0o
 IIII1 = lisp_map_cache . lookup_cache ( dest , False )
 if ( IIII1 == None ) :
  oOOoo = source . print_sg ( dest ) if I1iI1III else dest . print_address ( )
  oOOoo = green ( oOOoo , False )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oOOoo ) )
  return ( None )
  if 9 - 9: I1Ii111 - i1IIi . ooOoO0o
  if 33 - 33: I11i
  if 37 - 37: Oo0Ooo
  if 36 - 36: IiII % I11i
  if 72 - 72: oO0o % I11i % OOooOOo * iIii1I11I1II1 - OOooOOo % O0
 if ( I1iI1III == False ) :
  I1Iii1II = green ( IIII1 . eid . print_prefix ( ) , False )
  dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( dest . print_address ( ) , False ) , I1Iii1II ) )
  if 84 - 84: oO0o - o0oOOo0O0Ooo / II111iiii . o0oOOo0O0Ooo
  return ( IIII1 )
  if 82 - 82: OoooooooOO
  if 14 - 14: OoO0O00 / oO0o - OOooOOo
  if 100 - 100: IiII - I11i . iIii1I11I1II1 / iIii1I11I1II1
  if 16 - 16: IiII + Oo0Ooo % I11i
  if 16 - 16: ooOoO0o / I1Ii111
 IIII1 = IIII1 . lookup_source_cache ( source , False )
 if ( IIII1 == None ) :
  oOOoo = source . print_sg ( dest )
  dprint ( "Lookup for EID {} not found in map-cache" . format ( oOOoo ) )
  return ( None )
  if 78 - 78: OoOoOO00 - II111iiii - OOooOOo + I1IiiI + O0 / I1IiiI
  if 59 - 59: OOooOOo . I1IiiI / i1IIi / II111iiii . II111iiii
  if 54 - 54: iIii1I11I1II1 % ooOoO0o
  if 37 - 37: OOooOOo % OoOoOO00 - II111iiii * o0oOOo0O0Ooo . I1IiiI . OoOoOO00
  if 92 - 92: I11i + OoO0O00 . OoooooooOO
 I1Iii1II = green ( IIII1 . print_eid_tuple ( ) , False )
 dprint ( "Lookup for EID {} found map-cache entry {}" . format ( green ( source . print_sg ( dest ) , False ) , I1Iii1II ) )
 if 3 - 3: OoO0O00 % iIii1I11I1II1
 return ( IIII1 )
 if 62 - 62: OoooooooOO * o0oOOo0O0Ooo
 if 59 - 59: iIii1I11I1II1
 if 18 - 18: ooOoO0o % I1IiiI / iIii1I11I1II1 + O0
 if 99 - 99: i11iIiiIii - o0oOOo0O0Ooo + o0oOOo0O0Ooo . OoooooooOO * iII111i . Oo0Ooo
 if 63 - 63: I11i
 if 60 - 60: I1IiiI / I1ii11iIi11i / I11i / Ii1I + iIii1I11I1II1
 if 85 - 85: O0 / OOooOOo . OoOoOO00 / I1ii11iIi11i
def lisp_referral_cache_lookup ( eid , group , exact ) :
 if ( group and group . is_null ( ) ) :
  I11i1iI = lisp_referral_cache . lookup_cache ( eid , exact )
  return ( I11i1iI )
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
 I11i1iI = lisp_referral_cache . lookup_cache ( group , exact )
 if ( I11i1iI == None ) : return ( None )
 if 87 - 87: ooOoO0o . O0 - oO0o
 oo00Oo = I11i1iI . lookup_source_cache ( eid , exact )
 if ( oo00Oo ) : return ( oo00Oo )
 if 94 - 94: ooOoO0o / Ii1I
 if ( exact ) : I11i1iI = None
 return ( I11i1iI )
 if 9 - 9: I1Ii111 * oO0o
 if 44 - 44: ooOoO0o * oO0o
 if 67 - 67: iIii1I11I1II1 . iIii1I11I1II1 + iIii1I11I1II1 * iII111i
 if 70 - 70: I1IiiI - I11i / iIii1I11I1II1 . I1IiiI % I1ii11iIi11i
 if 12 - 12: Oo0Ooo + I1IiiI
 if 12 - 12: OoOoOO00 / II111iiii
 if 100 - 100: I1ii11iIi11i % iIii1I11I1II1 . IiII . OoooooooOO / II111iiii
def lisp_ddt_cache_lookup ( eid , group , exact ) :
 if ( group . is_null ( ) ) :
  O0000O00o000 = lisp_ddt_cache . lookup_cache ( eid , exact )
  return ( O0000O00o000 )
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
 O0000O00o000 = lisp_ddt_cache . lookup_cache ( group , exact )
 if ( O0000O00o000 == None ) : return ( None )
 if 82 - 82: OoO0O00 - iIii1I11I1II1 . iIii1I11I1II1 + I1ii11iIi11i
 i11OO = O0000O00o000 . lookup_source_cache ( eid , exact )
 if ( i11OO ) : return ( i11OO )
 if 22 - 22: Oo0Ooo - o0oOOo0O0Ooo + I1ii11iIi11i
 if ( exact ) : O0000O00o000 = None
 return ( O0000O00o000 )
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
  Ooo000oOOooO00 = lisp_sites_by_eid . lookup_cache ( eid , exact )
  return ( Ooo000oOOooO00 )
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
 Ooo000oOOooO00 = lisp_sites_by_eid . lookup_cache ( group , exact )
 if ( Ooo000oOOooO00 == None ) : return ( None )
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
 oo0Oo = Ooo000oOOooO00 . lookup_source_cache ( eid , exact )
 if ( oo0Oo ) : return ( oo0Oo )
 if 5 - 5: iIii1I11I1II1 % OoOoOO00 % OOooOOo % O0 * oO0o . iIii1I11I1II1
 if ( exact ) :
  Ooo000oOOooO00 = None
 else :
  ooOOoo0o = Ooo000oOOooO00 . parent_for_more_specifics
  if ( ooOOoo0o and ooOOoo0o . accept_more_specifics ) :
   if ( group . is_more_specific ( ooOOoo0o . group ) ) : Ooo000oOOooO00 = ooOOoo0o
   if 96 - 96: i11iIiiIii + oO0o / I1ii11iIi11i . IiII % o0oOOo0O0Ooo
   if 41 - 41: o0oOOo0O0Ooo . i1IIi - OOooOOo
 return ( Ooo000oOOooO00 )
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
  Oo0O = self . packet_format ( )
  Oo00O0o0O = b""
  if ( self . is_ipv4 ( ) ) :
   Oo00O0o0O = struct . pack ( Oo0O , socket . htonl ( self . address ) )
  elif ( self . is_ipv6 ( ) ) :
   iIIi = byte_swap_64 ( self . address >> 64 )
   OOOo00o = byte_swap_64 ( self . address & 0xffffffffffffffff )
   Oo00O0o0O = struct . pack ( Oo0O , iIIi , OOOo00o )
  elif ( self . is_mac ( ) ) :
   iI1ii11Ii = self . address
   iIIi = ( iI1ii11Ii >> 32 ) & 0xffff
   OOOo00o = ( iI1ii11Ii >> 16 ) & 0xffff
   OOo00o0o = iI1ii11Ii & 0xffff
   Oo00O0o0O = struct . pack ( Oo0O , iIIi , OOOo00o , OOo00o0o )
  elif ( self . is_e164 ( ) ) :
   iI1ii11Ii = self . address
   iIIi = ( iI1ii11Ii >> 32 ) & 0xffffffff
   OOOo00o = ( iI1ii11Ii & 0xffffffff )
   Oo00O0o0O = struct . pack ( Oo0O , iIIi , OOOo00o )
  elif ( self . is_dist_name ( ) ) :
   Oo00O0o0O += ( self . address + "\0" ) . encode ( )
   if 74 - 74: I1Ii111 - i11iIiiIii * OoooooooOO
  return ( Oo00O0o0O )
  if 90 - 90: i1IIi
  if 52 - 52: IiII + ooOoO0o - II111iiii - OoooooooOO * OoO0O00 - iIii1I11I1II1
 def unpack_address ( self , packet ) :
  Oo0O = self . packet_format ( )
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 38 - 38: II111iiii % iIii1I11I1II1 * IiII * OoOoOO00 % II111iiii . I1IiiI
  iI1ii11Ii = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
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
   ii1ii11Ii = 0
   if 46 - 46: OOooOOo / Ii1I
  packet = packet [ ii1ii11Ii : : ]
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
  iii1iII = addr_str . find ( "]" )
  if ( o000o0O0Oo00 != - 1 and iii1iII != - 1 ) :
   self . instance_id = int ( addr_str [ o000o0O0Oo00 + 1 : iii1iII ] )
   addr_str = addr_str [ iii1iII + 1 : : ]
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
   ii1io0O0oO0oOO = ( addr_str [ 2 : 4 ] == "::" )
   try :
    addr_str = socket . inet_pton ( socket . AF_INET6 , addr_str )
   except :
    addr_str = socket . inet_pton ( socket . AF_INET6 , "0::0" )
    if 30 - 30: I1ii11iIi11i + I1IiiI + Ii1I + I1Ii111
   addr_str = binascii . hexlify ( addr_str )
   if 10 - 10: i1IIi
   if ( ii1io0O0oO0oOO ) :
    addr_str = addr_str [ 2 : 4 ] + addr_str [ 0 : 2 ] + addr_str [ 4 : : ]
    if 12 - 12: II111iiii % OoOoOO00
   self . address = int ( addr_str , 16 )
   if 18 - 18: oO0o / ooOoO0o * I1IiiI / Oo0Ooo / I11i - OOooOOo
  elif ( self . is_geo_prefix ( ) ) :
   o00OOOo0o = lisp_geo ( None )
   o00OOOo0o . name = "geo-prefix-{}" . format ( o00OOOo0o )
   o00OOOo0o . parse_geo_string ( addr_str )
   self . address = o00OOOo0o
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
   if 53 - 53: ooOoO0o / OoOoOO00 - OoooooooOO * oO0o
  self . mask_len = self . host_mask_len ( )
  if 45 - 45: o0oOOo0O0Ooo . I1Ii111 % Ii1I
  if 42 - 42: Oo0Ooo + i11iIiiIii - OOooOOo . I1ii11iIi11i % I1Ii111 . I1ii11iIi11i
 def store_prefix ( self , prefix_str ) :
  if ( self . is_geo_string ( prefix_str ) ) :
   o00O = prefix_str . find ( "]" )
   I1ioOo = len ( prefix_str [ o00O + 1 : : ] ) * 8
  elif ( prefix_str . find ( "/" ) != - 1 ) :
   prefix_str , I1ioOo = prefix_str . split ( "/" )
  else :
   oO0OO00OOo0 = prefix_str . find ( "'" )
   if ( oO0OO00OOo0 == - 1 ) : return
   iI1i = prefix_str . find ( "'" , oO0OO00OOo0 + 1 )
   if ( iI1i == - 1 ) : return
   I1ioOo = len ( prefix_str [ oO0OO00OOo0 + 1 : iI1i ] ) * 8
   if 59 - 59: OoooooooOO
   if 91 - 91: i11iIiiIii / Oo0Ooo % I11i / O0
  self . string_to_afi ( prefix_str )
  self . store_address ( prefix_str )
  self . mask_len = int ( I1ioOo )
  if 80 - 80: II111iiii / I1ii11iIi11i % I1IiiI . Ii1I
  if 8 - 8: oO0o
 def zero_host_bits ( self ) :
  if ( self . mask_len < 0 ) : return
  IIi1Iii = ( 2 ** self . mask_len ) - 1
  i1iiIIIi1IIii = self . addr_length ( ) * 8 - self . mask_len
  IIi1Iii <<= i1iiIIIi1IIii
  self . address &= IIi1Iii
  if 68 - 68: I11i + Oo0Ooo
  if 15 - 15: O0
 def is_geo_string ( self , addr_str ) :
  o00O = addr_str . find ( "]" )
  if ( o00O != - 1 ) : addr_str = addr_str [ o00O + 1 : : ]
  if 75 - 75: iII111i / OoOoOO00
  o00OOOo0o = addr_str . split ( "/" )
  if ( len ( o00OOOo0o ) == 2 ) :
   if ( o00OOOo0o [ 1 ] . isdigit ( ) == False ) : return ( False )
   if 2 - 2: i1IIi + oO0o % iII111i % I1ii11iIi11i + ooOoO0o . iII111i
  o00OOOo0o = o00OOOo0o [ 0 ]
  o00OOOo0o = o00OOOo0o . split ( "-" )
  I1II111 = len ( o00OOOo0o )
  if ( I1II111 < 8 or I1II111 > 9 ) : return ( False )
  if 95 - 95: IiII - O0 * oO0o * O0
  for iii1I in range ( 0 , I1II111 ) :
   if ( iii1I == 3 ) :
    if ( o00OOOo0o [ iii1I ] in [ "N" , "S" ] ) : continue
    return ( False )
    if 47 - 47: I1IiiI / o0oOOo0O0Ooo
   if ( iii1I == 7 ) :
    if ( o00OOOo0o [ iii1I ] in [ "W" , "E" ] ) : continue
    return ( False )
    if 47 - 47: i1IIi / Oo0Ooo % IiII % OoO0O00 + Ii1I
   if ( o00OOOo0o [ iii1I ] . isdigit ( ) == False ) : return ( False )
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
  i1IiI = g . find ( "]" ) + 1
  III1II1i = "[{}]({}, {})" . format ( self . instance_id , OOo0oOO0o0oo0 [ ooo0000OOO0 : : ] , g [ i1IiI : : ] )
  return ( III1II1i )
  if 23 - 23: Oo0Ooo
  if 91 - 91: I1Ii111
 def hash_address ( self , addr ) :
  iIIi = self . address
  OOOo00o = addr . address
  if 59 - 59: i1IIi % OOooOOo
  if ( self . is_geo_prefix ( ) ) : iIIi = self . address . print_geo ( )
  if ( addr . is_geo_prefix ( ) ) : OOOo00o = addr . address . print_geo ( )
  if 81 - 81: i11iIiiIii / OoO0O00 * OoOoOO00 % iII111i - iIii1I11I1II1 + I1ii11iIi11i
  if ( type ( iIIi ) == str ) :
   iIIi = int ( binascii . hexlify ( iIIi [ 0 : 1 ] ) )
   if 20 - 20: O0 . I1Ii111 * Ii1I * II111iiii
  if ( type ( OOOo00o ) == str ) :
   OOOo00o = int ( binascii . hexlify ( OOOo00o [ 0 : 1 ] ) )
   if 66 - 66: Ii1I % OoO0O00 % II111iiii - OOooOOo * o0oOOo0O0Ooo
  return ( iIIi ^ OOOo00o )
  if 33 - 33: OoooooooOO / I11i
  if 98 - 98: I1ii11iIi11i . Ii1I . iIii1I11I1II1 * I1ii11iIi11i / Ii1I
  if 74 - 74: Oo0Ooo * I1Ii111
  if 72 - 72: OoOoOO00 + O0 - IiII * ooOoO0o
  if 20 - 20: II111iiii % OoOoOO00 * i11iIiiIii
  if 68 - 68: IiII / ooOoO0o
 def is_more_specific ( self , prefix ) :
  if ( prefix . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( True )
  if 100 - 100: ooOoO0o / I1IiiI
  I1ioOo = prefix . mask_len
  if ( prefix . afi == LISP_AFI_IID_RANGE ) :
   O00OOO0 = 2 ** ( 32 - I1ioOo )
   Ooo0 = prefix . instance_id
   oO0OOOOOO0000 = Ooo0 + O00OOO0
   return ( self . instance_id in range ( Ooo0 , oO0OOOOOO0000 ) )
   if 79 - 79: ooOoO0o / OoO0O00 + OOooOOo
   if 64 - 64: i1IIi
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  if ( self . afi != prefix . afi ) :
   if ( prefix . afi != LISP_AFI_NONE ) : return ( False )
   if 26 - 26: OoOoOO00 / o0oOOo0O0Ooo . OOooOOo + I1IiiI + Ii1I . iII111i
   if 89 - 89: I1Ii111 * I1IiiI . i1IIi - iIii1I11I1II1 * I1Ii111
   if 5 - 5: OoOoOO00 % i1IIi
   if 31 - 31: Oo0Ooo * O0 . OOooOOo . o0oOOo0O0Ooo + OoO0O00 + II111iiii
   if 76 - 76: Oo0Ooo + I1IiiI - O0
  if ( self . is_binary ( ) == False ) :
   if ( prefix . afi == LISP_AFI_NONE ) : return ( True )
   if ( type ( self . address ) != type ( prefix . address ) ) : return ( False )
   iI1ii11Ii = self . address
   O0ooOo00ooOO = prefix . address
   if ( self . is_geo_prefix ( ) ) :
    iI1ii11Ii = self . address . print_geo ( )
    O0ooOo00ooOO = prefix . address . print_geo ( )
    if 50 - 50: IiII / o0oOOo0O0Ooo
   if ( len ( iI1ii11Ii ) < len ( O0ooOo00ooOO ) ) : return ( False )
   return ( iI1ii11Ii . find ( O0ooOo00ooOO ) == 0 )
   if 9 - 9: Oo0Ooo - OoO0O00 + iII111i / OoooooooOO
   if 52 - 52: O0
   if 34 - 34: OoooooooOO + OoOoOO00 - Oo0Ooo . OOooOOo * iIii1I11I1II1
   if 93 - 93: i11iIiiIii / Oo0Ooo * OoOoOO00 / ooOoO0o + OoO0O00 * OOooOOo
   if 81 - 81: IiII * iII111i + i1IIi + I1Ii111 / OoO0O00
  if ( self . mask_len < I1ioOo ) : return ( False )
  if 83 - 83: oO0o / OoO0O00
  i1iiIIIi1IIii = ( prefix . addr_length ( ) * 8 ) - I1ioOo
  IIi1Iii = ( 2 ** I1ioOo - 1 ) << i1iiIIIi1IIii
  return ( ( self . address & IIi1Iii ) == prefix . address )
  if 34 - 34: OoooooooOO - i1IIi * O0
  if 83 - 83: I1IiiI + OoO0O00
 def mask_address ( self , mask_len ) :
  i1iiIIIi1IIii = ( self . addr_length ( ) * 8 ) - mask_len
  IIi1Iii = ( 2 ** mask_len - 1 ) << i1iiIIIi1IIii
  self . address &= IIi1Iii
  if 41 - 41: Ii1I + II111iiii . OOooOOo * I1Ii111 / II111iiii
  if 32 - 32: Oo0Ooo - Ii1I % o0oOOo0O0Ooo
 def is_exact_match ( self , prefix ) :
  if ( self . instance_id != prefix . instance_id ) : return ( False )
  IiiI111IIIIi = self . print_prefix ( )
  oOO00o = prefix . print_prefix ( ) if prefix else ""
  return ( IiiI111IIIIi == oOO00o )
  if 82 - 82: o0oOOo0O0Ooo + iIii1I11I1II1 + o0oOOo0O0Ooo + ooOoO0o
  if 41 - 41: OOooOOo * ooOoO0o
 def is_local ( self ) :
  if ( self . is_ipv4 ( ) ) :
   I1I111I1II1i1 = lisp_myrlocs [ 0 ]
   if ( I1I111I1II1i1 == None ) : return ( False )
   I1I111I1II1i1 = I1I111I1II1i1 . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == I1I111I1II1i1 )
   if 8 - 8: iII111i
  if ( self . is_ipv6 ( ) ) :
   I1I111I1II1i1 = lisp_myrlocs [ 1 ]
   if ( I1I111I1II1i1 == None ) : return ( False )
   I1I111I1II1i1 = I1I111I1II1i1 . print_address_no_iid ( )
   return ( self . print_address_no_iid ( ) == I1I111I1II1i1 )
   if 77 - 77: OOooOOo % I1IiiI - iII111i % I1Ii111
  return ( False )
  if 29 - 29: iIii1I11I1II1 / i11iIiiIii + Oo0Ooo
  if 99 - 99: I1IiiI - iII111i * Ii1I - OoOoOO00 / i11iIiiIii - i1IIi
 def store_iid_range ( self , iid , mask_len ) :
  if ( self . afi == LISP_AFI_NONE ) :
   if ( iid == 0 and mask_len == 0 ) : self . afi = LISP_AFI_ULTIMATE_ROOT
   else : self . afi = LISP_AFI_IID_RANGE
   if 46 - 46: I1ii11iIi11i * ooOoO0o
  self . instance_id = iid
  self . mask_len = mask_len
  if 4 - 4: I1Ii111 * II111iiii
  if 4 - 4: ooOoO0o * Oo0Ooo - I1ii11iIi11i % ooOoO0o % OoOoOO00
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
  if 41 - 41: iIii1I11I1II1
  if 26 - 26: Oo0Ooo / i1IIi + Oo0Ooo
 def lcaf_encode_iid ( self ) :
  Ooo00O0OooOOO = LISP_LCAF_INSTANCE_ID_TYPE
  o0OoOoOo0O = socket . htons ( self . lcaf_length ( Ooo00O0OooOOO ) )
  i1I1iI = self . instance_id
  Oo0ooooO0o00 = self . afi
  I1iIIIiI1iI11 = 0
  if ( Oo0ooooO0o00 < 0 ) :
   if ( self . afi == LISP_AFI_GEO_COORD ) :
    Oo0ooooO0o00 = LISP_AFI_LCAF
    I1iIIIiI1iI11 = 0
   else :
    Oo0ooooO0o00 = 0
    I1iIIIiI1iI11 = self . mask_len
    if 76 - 76: I1ii11iIi11i * i1IIi % oO0o
    if 80 - 80: i1IIi * II111iiii . O0 % I1ii11iIi11i / ooOoO0o
    if 58 - 58: I1IiiI * I1ii11iIi11i - i1IIi % I1Ii111 % O0
  i1111I1 = struct . pack ( "BBBBH" , 0 , 0 , Ooo00O0OooOOO , I1iIIIiI1iI11 , o0OoOoOo0O )
  i1111I1 += struct . pack ( "IH" , socket . htonl ( i1I1iI ) , socket . htons ( Oo0ooooO0o00 ) )
  if ( Oo0ooooO0o00 == 0 ) : return ( i1111I1 )
  if 35 - 35: OoooooooOO
  if ( self . afi == LISP_AFI_GEO_COORD ) :
   i1111I1 = i1111I1 [ 0 : - 2 ]
   i1111I1 += self . address . encode_geo ( )
   return ( i1111I1 )
   if 13 - 13: oO0o - O0 * i11iIiiIii / IiII / IiII
   if 72 - 72: i11iIiiIii * OoOoOO00 % oO0o / I1Ii111
  i1111I1 += self . pack_address ( )
  return ( i1111I1 )
  if 9 - 9: iIii1I11I1II1 . IiII
  if 42 - 42: i1IIi / Ii1I * I1ii11iIi11i
 def lcaf_decode_iid ( self , packet ) :
  Oo0O = "BBBBH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 9 - 9: I11i % i1IIi / i1IIi / OoO0O00
  O0O0oOO , Ooooo00OO , Ooo00O0OooOOO , I1Ii1i1iiI1i1 , OOOOo0o0O0o = struct . unpack ( Oo0O ,
 packet [ : ii1ii11Ii ] )
  packet = packet [ ii1ii11Ii : : ]
  if 32 - 32: iIii1I11I1II1
  if ( Ooo00O0OooOOO != LISP_LCAF_INSTANCE_ID_TYPE ) : return ( None )
  if 8 - 8: oO0o * OoooooooOO - ooOoO0o
  Oo0O = "IH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( None )
  if 80 - 80: O0 * oO0o
  i1I1iI , Oo0ooooO0o00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  packet = packet [ ii1ii11Ii : : ]
  if 75 - 75: I1IiiI * ooOoO0o % oO0o / i11iIiiIii
  OOOOo0o0O0o = socket . ntohs ( OOOOo0o0O0o )
  self . instance_id = socket . ntohl ( i1I1iI )
  Oo0ooooO0o00 = socket . ntohs ( Oo0ooooO0o00 )
  self . afi = Oo0ooooO0o00
  if ( I1Ii1i1iiI1i1 != 0 and Oo0ooooO0o00 == 0 ) : self . mask_len = I1Ii1i1iiI1i1
  if ( Oo0ooooO0o00 == 0 ) :
   self . afi = LISP_AFI_IID_RANGE if I1Ii1i1iiI1i1 else LISP_AFI_ULTIMATE_ROOT
   if 91 - 91: OOooOOo
   if 60 - 60: i11iIiiIii . iIii1I11I1II1 . OOooOOo % IiII
   if 68 - 68: I11i / iII111i - IiII . iIii1I11I1II1 / o0oOOo0O0Ooo
   if 54 - 54: II111iiii * I1IiiI
   if 49 - 49: I1ii11iIi11i
  if ( Oo0ooooO0o00 == 0 ) : return ( packet )
  if 31 - 31: o0oOOo0O0Ooo - OoOoOO00 + I1ii11iIi11i . oO0o - O0
  if 61 - 61: I1ii11iIi11i * II111iiii . i1IIi
  if 60 - 60: OoooooooOO % ooOoO0o * i11iIiiIii * OoooooooOO % IiII
  if 15 - 15: oO0o
  if ( self . is_dist_name ( ) ) :
   packet , self . address = lisp_decode_dist_name ( packet )
   self . mask_len = len ( self . address ) * 8
   return ( packet )
   if 40 - 40: I1Ii111
   if 77 - 77: II111iiii - o0oOOo0O0Ooo . Ii1I
   if 47 - 47: o0oOOo0O0Ooo % OOooOOo + I1Ii111
   if 64 - 64: ooOoO0o / IiII . I1IiiI
   if 77 - 77: o0oOOo0O0Ooo % I1Ii111 . OOooOOo
  if ( Oo0ooooO0o00 == LISP_AFI_LCAF ) :
   Oo0O = "BBBBH"
   ii1ii11Ii = struct . calcsize ( Oo0O )
   if ( len ( packet ) < ii1ii11Ii ) : return ( None )
   if 90 - 90: I11i
   iIII1 , oooo0ooo0 , Ooo00O0OooOOO , iI11 , Oo0OoooOoO0O0 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
   if 53 - 53: I1ii11iIi11i + i11iIiiIii / iIii1I11I1II1 + OoooooooOO + IiII * I1IiiI
   if 16 - 16: i11iIiiIii - oO0o . i11iIiiIii + OoO0O00 + i11iIiiIii
   if ( Ooo00O0OooOOO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 85 - 85: I1ii11iIi11i - ooOoO0o + I1Ii111 + I1Ii111
   Oo0OoooOoO0O0 = socket . ntohs ( Oo0OoooOoO0O0 )
   packet = packet [ ii1ii11Ii : : ]
   if ( Oo0OoooOoO0O0 > len ( packet ) ) : return ( None )
   if 13 - 13: II111iiii
   o00OOOo0o = lisp_geo ( "" )
   self . afi = LISP_AFI_GEO_COORD
   self . address = o00OOOo0o
   packet = o00OOOo0o . decode_geo ( packet , Oo0OoooOoO0O0 , iI11 )
   self . mask_len = self . host_mask_len ( )
   return ( packet )
   if 22 - 22: o0oOOo0O0Ooo
   if 45 - 45: I1Ii111 + OoooooooOO + o0oOOo0O0Ooo * II111iiii
  o0OoOoOo0O = self . addr_length ( )
  if ( len ( packet ) < o0OoOoOo0O ) : return ( None )
  if 12 - 12: I1ii11iIi11i / O0
  packet = self . unpack_address ( packet )
  return ( packet )
  if 18 - 18: OoOoOO00 . i11iIiiIii + i1IIi / OoooooooOO - IiII % OoO0O00
  if 47 - 47: iII111i % IiII + I1Ii111 * o0oOOo0O0Ooo * OoooooooOO
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
 def lcaf_encode_sg ( self , group ) :
  Ooo00O0OooOOO = LISP_LCAF_MCAST_INFO_TYPE
  i1I1iI = socket . htonl ( self . instance_id )
  o0OoOoOo0O = socket . htons ( self . lcaf_length ( Ooo00O0OooOOO ) )
  i1111I1 = struct . pack ( "BBBBHIHBB" , 0 , 0 , Ooo00O0OooOOO , 0 , o0OoOoOo0O , i1I1iI ,
 0 , self . mask_len , group . mask_len )
  if 23 - 23: I1ii11iIi11i
  i1111I1 += struct . pack ( "H" , socket . htons ( self . afi ) )
  i1111I1 += self . pack_address ( )
  i1111I1 += struct . pack ( "H" , socket . htons ( group . afi ) )
  i1111I1 += group . pack_address ( )
  return ( i1111I1 )
  if 68 - 68: OoO0O00 . oO0o / IiII - II111iiii % Oo0Ooo
  if 24 - 24: II111iiii / I1ii11iIi11i + oO0o / Ii1I + IiII % oO0o
 def lcaf_decode_sg ( self , packet ) :
  Oo0O = "BBBBHIHBB"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( [ None , None ] )
  if 86 - 86: I1IiiI
  O0O0oOO , Ooooo00OO , Ooo00O0OooOOO , ooO0000 , OOOOo0o0O0o , i1I1iI , O0O000o0ooO , o000Ooo0 , oOoOooO00oooo = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
  if 50 - 50: o0oOOo0O0Ooo - O0 + OoO0O00
  packet = packet [ ii1ii11Ii : : ]
  if 22 - 22: I1Ii111 % O0 / I1Ii111 / I1Ii111
  if ( Ooo00O0OooOOO != LISP_LCAF_MCAST_INFO_TYPE ) : return ( [ None , None ] )
  if 64 - 64: Oo0Ooo + iIii1I11I1II1 % i1IIi
  self . instance_id = socket . ntohl ( i1I1iI )
  OOOOo0o0O0o = socket . ntohs ( OOOOo0o0O0o ) - 8
  if 15 - 15: I1Ii111 - I1Ii111 . I1ii11iIi11i - I1IiiI
  if 52 - 52: i1IIi . iIii1I11I1II1 % I1IiiI + I1IiiI / I1IiiI . iII111i
  if 82 - 82: I11i * Ii1I
  if 55 - 55: IiII / OoooooooOO
  if 23 - 23: iIii1I11I1II1
  Oo0O = "H"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( [ None , None ] )
  if ( OOOOo0o0O0o < ii1ii11Ii ) : return ( [ None , None ] )
  if 7 - 7: IiII / OOooOOo + Oo0Ooo . I1IiiI
  Oo0ooooO0o00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  OOOOo0o0O0o -= ii1ii11Ii
  self . afi = socket . ntohs ( Oo0ooooO0o00 )
  self . mask_len = o000Ooo0
  o0OoOoOo0O = self . addr_length ( )
  if ( OOOOo0o0O0o < o0OoOoOo0O ) : return ( [ None , None ] )
  if 33 - 33: I1Ii111 + OoooooooOO
  packet = self . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 73 - 73: O0 . Oo0Ooo
  OOOOo0o0O0o -= o0OoOoOo0O
  if 28 - 28: I1IiiI . O0 % o0oOOo0O0Ooo / I11i
  if 48 - 48: II111iiii % I1ii11iIi11i - II111iiii
  if 29 - 29: I1Ii111 - I1Ii111 - I11i * iIii1I11I1II1 % OoO0O00 % IiII
  if 73 - 73: i1IIi . OoooooooOO / OoOoOO00 % Ii1I / Ii1I / Ii1I
  if 40 - 40: I1Ii111 - iIii1I11I1II1
  Oo0O = "H"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( [ None , None ] )
  if ( OOOOo0o0O0o < ii1ii11Ii ) : return ( [ None , None ] )
  if 88 - 88: OOooOOo * O0 * OoOoOO00
  Oo0ooooO0o00 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  OOOOo0o0O0o -= ii1ii11Ii
  i1I1IIIiII = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  i1I1IIIiII . afi = socket . ntohs ( Oo0ooooO0o00 )
  i1I1IIIiII . mask_len = oOoOooO00oooo
  i1I1IIIiII . instance_id = self . instance_id
  o0OoOoOo0O = self . addr_length ( )
  if ( OOOOo0o0O0o < o0OoOoOo0O ) : return ( [ None , None ] )
  if 26 - 26: Ii1I
  packet = i1I1IIIiII . unpack_address ( packet )
  if ( packet == None ) : return ( [ None , None ] )
  if 65 - 65: iII111i / iIii1I11I1II1 + I11i - iIii1I11I1II1 - Ii1I . I1Ii111
  return ( [ packet , i1I1IIIiII ] )
  if 77 - 77: OoOoOO00 / I1IiiI + IiII
  if 66 - 66: i11iIiiIii * OoooooooOO + iII111i / Ii1I
 def lcaf_decode_eid ( self , packet ) :
  Oo0O = "BBB"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( [ None , None ] )
  if 42 - 42: Ii1I / iIii1I11I1II1 / Oo0Ooo . O0 . oO0o * I1IiiI
  if 21 - 21: OoooooooOO
  if 76 - 76: i1IIi * i11iIiiIii / OOooOOo + I1Ii111
  if 50 - 50: oO0o % OoOoOO00 + I1IiiI
  if 15 - 15: II111iiii - iII111i / I1ii11iIi11i
  ooO0000 , oooo0ooo0 , Ooo00O0OooOOO = struct . unpack ( Oo0O ,
 packet [ : ii1ii11Ii ] )
  if 81 - 81: Ii1I - i1IIi % oO0o * Oo0Ooo * OoOoOO00
  if ( Ooo00O0OooOOO == LISP_LCAF_INSTANCE_ID_TYPE ) :
   return ( [ self . lcaf_decode_iid ( packet ) , None ] )
  elif ( Ooo00O0OooOOO == LISP_LCAF_MCAST_INFO_TYPE ) :
   packet , i1I1IIIiII = self . lcaf_decode_sg ( packet )
   return ( [ packet , i1I1IIIiII ] )
  elif ( Ooo00O0OooOOO == LISP_LCAF_GEO_COORD_TYPE ) :
   Oo0O = "BBBBH"
   ii1ii11Ii = struct . calcsize ( Oo0O )
   if ( len ( packet ) < ii1ii11Ii ) : return ( None )
   if 79 - 79: oO0o + I1IiiI % iII111i + II111iiii % OoO0O00 % iII111i
   iIII1 , oooo0ooo0 , Ooo00O0OooOOO , iI11 , Oo0OoooOoO0O0 = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] )
   if 46 - 46: o0oOOo0O0Ooo
   if 61 - 61: OoO0O00 . O0 + I1ii11iIi11i + OoO0O00
   if ( Ooo00O0OooOOO != LISP_LCAF_GEO_COORD_TYPE ) : return ( None )
   if 44 - 44: I11i . oO0o
   Oo0OoooOoO0O0 = socket . ntohs ( Oo0OoooOoO0O0 )
   packet = packet [ ii1ii11Ii : : ]
   if ( Oo0OoooOoO0O0 > len ( packet ) ) : return ( None )
   if 65 - 65: I1ii11iIi11i * II111iiii % I11i + II111iiii . i1IIi / ooOoO0o
   o00OOOo0o = lisp_geo ( "" )
   self . instance_id = 0
   self . afi = LISP_AFI_GEO_COORD
   self . address = o00OOOo0o
   packet = o00OOOo0o . decode_geo ( packet , Oo0OoooOoO0O0 , iI11 )
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
  OOo0OO = lisp_elp_node ( )
  OOo0OO . copy_address ( self . address )
  OOo0OO . probe = self . probe
  OOo0OO . strict = self . strict
  OOo0OO . eid = self . eid
  OOo0OO . we_are_last = self . we_are_last
  return ( OOo0OO )
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
  o0OOOOOOOo0 = lisp_elp ( self . elp_name )
  o0OOOOOOOo0 . use_elp_node = self . use_elp_node
  o0OOOOOOOo0 . we_are_last = self . we_are_last
  for OOo0OO in self . elp_nodes :
   o0OOOOOOOo0 . elp_nodes . append ( OOo0OO . copy_elp_node ( ) )
   if 42 - 42: OOooOOo
  return ( o0OOOOOOOo0 )
  if 36 - 36: OoooooooOO + ooOoO0o + iII111i
  if 30 - 30: i1IIi % Ii1I
 def print_elp ( self , want_marker ) :
  I1i1iI1i1i1 = ""
  for OOo0OO in self . elp_nodes :
   IIiIi11iIi = ""
   if ( want_marker ) :
    if ( OOo0OO == self . use_elp_node ) :
     IIiIi11iIi = "*"
    elif ( OOo0OO . we_are_last ) :
     IIiIi11iIi = "x"
     if 56 - 56: II111iiii * iII111i + I1ii11iIi11i
     if 96 - 96: OOooOOo % i11iIiiIii * I1IiiI % i11iIiiIii + OoO0O00 - iII111i
   I1i1iI1i1i1 += "{}{}({}{}{}), " . format ( IIiIi11iIi ,
 OOo0OO . address . print_address_no_iid ( ) ,
 "r" if OOo0OO . eid else "R" , "P" if OOo0OO . probe else "p" ,
 "S" if OOo0OO . strict else "s" )
   if 39 - 39: ooOoO0o . OoOoOO00
  return ( I1i1iI1i1i1 [ 0 : - 2 ] if I1i1iI1i1i1 != "" else "" )
  if 60 - 60: o0oOOo0O0Ooo + iII111i
  if 8 - 8: OoOoOO00 - iIii1I11I1II1 * I1Ii111
 def select_elp_node ( self ) :
  iII1iii , oooOoOoooo , ooOooO = lisp_myrlocs
  o00O = None
  if 26 - 26: OoooooooOO % iIii1I11I1II1 - IiII
  for OOo0OO in self . elp_nodes :
   if ( iII1iii and OOo0OO . address . is_exact_match ( iII1iii ) ) :
    o00O = self . elp_nodes . index ( OOo0OO )
    break
    if 3 - 3: oO0o * II111iiii . O0
   if ( oooOoOoooo and OOo0OO . address . is_exact_match ( oooOoOoooo ) ) :
    o00O = self . elp_nodes . index ( OOo0OO )
    break
    if 19 - 19: I1IiiI / I1IiiI / Oo0Ooo + oO0o + i1IIi
    if 31 - 31: iII111i / OoooooooOO - I1Ii111 . iII111i
    if 38 - 38: ooOoO0o . OoooooooOO - II111iiii * i11iIiiIii / i1IIi . OoooooooOO
    if 51 - 51: oO0o - I1ii11iIi11i + I1ii11iIi11i
    if 100 - 100: I11i - I1ii11iIi11i . i1IIi
    if 85 - 85: II111iiii
    if 58 - 58: i1IIi - OoO0O00 + ooOoO0o
  if ( o00O == None ) :
   self . use_elp_node = self . elp_nodes [ 0 ]
   OOo0OO . we_are_last = False
   return
   if 6 - 6: IiII % I1IiiI + OoooooooOO * oO0o . iII111i + oO0o
   if 4 - 4: I11i % I1IiiI
   if 72 - 72: I1IiiI % II111iiii % iII111i / OoOoOO00
   if 96 - 96: OoOoOO00 % Ii1I
   if 50 - 50: IiII - II111iiii
   if 10 - 10: OoooooooOO % Ii1I * OOooOOo + IiII * oO0o
  if ( self . elp_nodes [ - 1 ] == self . elp_nodes [ o00O ] ) :
   self . use_elp_node = None
   OOo0OO . we_are_last = True
   return
   if 13 - 13: II111iiii
   if 14 - 14: i11iIiiIii . IiII
   if 70 - 70: Oo0Ooo * OOooOOo + I1Ii111 % OoOoOO00 / O0
   if 23 - 23: O0 * oO0o / I1IiiI + i1IIi * O0 % oO0o
   if 11 - 11: I1Ii111 . OoooooooOO * iIii1I11I1II1 / I1ii11iIi11i - ooOoO0o . iII111i
  self . use_elp_node = self . elp_nodes [ o00O + 1 ]
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
  o00OOOo0o = lisp_geo ( self . geo_name )
  o00OOOo0o . latitude = self . latitude
  o00OOOo0o . lat_mins = self . lat_mins
  o00OOOo0o . lat_secs = self . lat_secs
  o00OOOo0o . longitude = self . longitude
  o00OOOo0o . long_mins = self . long_mins
  o00OOOo0o . long_secs = self . long_secs
  o00OOOo0o . altitude = self . altitude
  o00OOOo0o . radius = self . radius
  return ( o00OOOo0o )
  if 16 - 16: i1IIi
  if 88 - 88: OOooOOo
 def no_geo_altitude ( self ) :
  return ( self . altitude == - 1 )
  if 79 - 79: oO0o
  if 52 - 52: oO0o + OoO0O00 / OoooooooOO - iIii1I11I1II1 / iII111i - oO0o
 def parse_geo_string ( self , geo_str ) :
  o00O = geo_str . find ( "]" )
  if ( o00O != - 1 ) : geo_str = geo_str [ o00O + 1 : : ]
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
  oO0 = geo_str [ 4 : 8 ]
  if 4 - 4: i11iIiiIii - iIii1I11I1II1 % o0oOOo0O0Ooo * oO0o
  if 19 - 19: Ii1I
  if 47 - 47: IiII - IiII
  if 33 - 33: ooOoO0o
  if ( len ( geo_str ) > 8 ) : self . altitude = int ( geo_str [ 8 ] )
  if 23 - 23: I1Ii111 + OoO0O00
  if 35 - 35: Oo0Ooo - iIii1I11I1II1 - I1Ii111 % OOooOOo
  if 59 - 59: i1IIi
  if 38 - 38: Oo0Ooo . o0oOOo0O0Ooo % oO0o / i11iIiiIii * OoO0O00 % OoOoOO00
  self . latitude = int ( o0OoOO00 [ 0 ] )
  self . lat_mins = int ( o0OoOO00 [ 1 ] )
  self . lat_secs = int ( o0OoOO00 [ 2 ] )
  if ( o0OoOO00 [ 3 ] == "N" ) : self . latitude = - self . latitude
  if 18 - 18: OOooOOo
  if 12 - 12: I1Ii111 % II111iiii / o0oOOo0O0Ooo - iIii1I11I1II1 + II111iiii
  if 41 - 41: OOooOOo
  if 8 - 8: i11iIiiIii . IiII . I1ii11iIi11i + i1IIi % I1Ii111
  self . longitude = int ( oO0 [ 0 ] )
  self . long_mins = int ( oO0 [ 1 ] )
  self . long_secs = int ( oO0 [ 2 ] )
  if ( oO0 [ 3 ] == "E" ) : self . longitude = - self . longitude
  return ( True )
  if 64 - 64: I1IiiI . Oo0Ooo * OoO0O00
  if 87 - 87: i1IIi / OoooooooOO
 def print_geo ( self ) :
  o0ooO = "N" if self . latitude < 0 else "S"
  O0oOoOoOoooo0 = "E" if self . longitude < 0 else "W"
  if 53 - 53: OoO0O00 * Oo0Ooo + Oo0Ooo
  IIi1iIIii1 = "{}-{}-{}-{}-{}-{}-{}-{}" . format ( abs ( self . latitude ) ,
 self . lat_mins , self . lat_secs , o0ooO , abs ( self . longitude ) ,
 self . long_mins , self . long_secs , O0oOoOoOoooo0 )
  if 62 - 62: OOooOOo - i1IIi + i11iIiiIii * I11i / OoO0O00
  if ( self . no_geo_altitude ( ) == False ) :
   IIi1iIIii1 += "-" + str ( self . altitude )
   if 84 - 84: IiII * OOooOOo
   if 1 - 1: iII111i * I1IiiI . o0oOOo0O0Ooo . IiII
   if 6 - 6: OOooOOo . oO0o / Oo0Ooo / o0oOOo0O0Ooo
   if 24 - 24: Oo0Ooo % OoooooooOO
   if 78 - 78: OoooooooOO - II111iiii . OoO0O00 / I1ii11iIi11i
  if ( self . radius != 0 ) : IIi1iIIii1 += "/{}" . format ( self . radius )
  return ( IIi1iIIii1 )
  if 86 - 86: OOooOOo * OoOoOO00 % i1IIi * IiII . I1ii11iIi11i
  if 72 - 72: i1IIi - I1Ii111 . O0 * OoO0O00
 def geo_url ( self ) :
  oOo0oO0OO = os . getenv ( "LISP_GEO_ZOOM_LEVEL" )
  oOo0oO0OO = "10" if ( oOo0oO0OO == "" or oOo0oO0OO . isdigit ( ) == False ) else oOo0oO0OO
  iIIi1II1iI1i , ooOooooo0 = self . dms_to_decimal ( )
  i1iIi1i = ( "http://maps.googleapis.com/maps/api/staticmap?center={},{}" + "&markers=color:blue%7Clabel:lisp%7C{},{}" + "&zoom={}&size=1024x1024&sensor=false" ) . format ( iIIi1II1iI1i , ooOooooo0 , iIIi1II1iI1i , ooOooooo0 ,
  # OoOoOO00
  # OOooOOo + Oo0Ooo * I11i
 oOo0oO0OO )
  return ( i1iIi1i )
  if 8 - 8: Ii1I % i1IIi
  if 29 - 29: oO0o % OoOoOO00 / OoOoOO00
 def print_geo_url ( self ) :
  o00OOOo0o = self . print_geo ( )
  if ( self . radius == 0 ) :
   i1iIi1i = self . geo_url ( )
   I1i = "<a href='{}'>{}</a>" . format ( i1iIi1i , o00OOOo0o )
  else :
   i1iIi1i = o00OOOo0o . replace ( "/" , "-" )
   I1i = "<a href='/lisp/geo-map/{}'>{}</a>" . format ( i1iIi1i , o00OOOo0o )
   if 79 - 79: IiII % OoooooooOO
  return ( I1i )
  if 51 - 51: iII111i . oO0o % ooOoO0o % Ii1I . o0oOOo0O0Ooo
  if 43 - 43: II111iiii
 def dms_to_decimal ( self ) :
  OOOOo00oo0OO , iii1II , o0OooOoO0O0 = self . latitude , self . lat_mins , self . lat_secs
  O0OOo0ooOoo = float ( abs ( OOOOo00oo0OO ) )
  O0OOo0ooOoo += float ( iii1II * 60 + o0OooOoO0O0 ) / 3600
  if ( OOOOo00oo0OO > 0 ) : O0OOo0ooOoo = - O0OOo0ooOoo
  iIIi1Iii1Ii = O0OOo0ooOoo
  if 13 - 13: Ii1I + O0 % o0oOOo0O0Ooo % Oo0Ooo / i1IIi . II111iiii
  OOOOo00oo0OO , iii1II , o0OooOoO0O0 = self . longitude , self . long_mins , self . long_secs
  O0OOo0ooOoo = float ( abs ( OOOOo00oo0OO ) )
  O0OOo0ooOoo += float ( iii1II * 60 + o0OooOoO0O0 ) / 3600
  if ( OOOOo00oo0OO > 0 ) : O0OOo0ooOoo = - O0OOo0ooOoo
  IIi1iI11i1i1i = O0OOo0ooOoo
  return ( ( iIIi1Iii1Ii , IIi1iI11i1i1i ) )
  if 83 - 83: I1Ii111 % oO0o % i11iIiiIii % i11iIiiIii - I1IiiI
  if 16 - 16: ooOoO0o - o0oOOo0O0Ooo
 def get_distance ( self , geo_point ) :
  Ii11iiI1I1 = self . dms_to_decimal ( )
  O0oOO0O00Oo00Oo0 = geo_point . dms_to_decimal ( )
  O0ooo0OO0oo = geopy . distance . distance ( Ii11iiI1I1 , O0oOO0O00Oo00Oo0 )
  return ( O0ooo0OO0oo . km )
  if 47 - 47: II111iiii . iIii1I11I1II1
  if 95 - 95: II111iiii % Oo0Ooo + I11i
 def point_in_circle ( self , geo_point ) :
  oOOoO = self . get_distance ( geo_point )
  return ( oOOoO <= self . radius )
  if 1 - 1: O0 / OoOoOO00 + i11iIiiIii + ooOoO0o % o0oOOo0O0Ooo + OOooOOo
  if 63 - 63: II111iiii * i1IIi - I1Ii111 + iIii1I11I1II1 % I11i - OOooOOo
 def encode_geo ( self ) :
  o00oOoO00O = socket . htons ( LISP_AFI_LCAF )
  I1II111 = socket . htons ( 20 + 2 )
  oooo0ooo0 = 0
  if 95 - 95: iIii1I11I1II1 / oO0o - IiII - iII111i / iII111i % iIii1I11I1II1
  iIIi1II1iI1i = abs ( self . latitude )
  iI1Ii1 = ( ( self . lat_mins * 60 ) + self . lat_secs ) * 1000
  if ( self . latitude < 0 ) : oooo0ooo0 |= 0x40
  if 43 - 43: i1IIi / I1ii11iIi11i
  ooOooooo0 = abs ( self . longitude )
  O0O0OI1IIiI1IIIii = ( ( self . long_mins * 60 ) + self . long_secs ) * 1000
  if ( self . longitude < 0 ) : oooo0ooo0 |= 0x20
  if 93 - 93: oO0o
  IiI1 = 0
  if ( self . no_geo_altitude ( ) == False ) :
   IiI1 = socket . htonl ( self . altitude )
   oooo0ooo0 |= 0x10
   if 22 - 22: oO0o + Ii1I - ooOoO0o + OoOoOO00 % OOooOOo - Oo0Ooo
  O0OoooOoo = socket . htons ( self . radius )
  if ( O0OoooOoo != 0 ) : oooo0ooo0 |= 0x06
  if 59 - 59: OoOoOO00 * iII111i - OOooOOo
  IIiI1 = struct . pack ( "HBBBBH" , o00oOoO00O , 0 , 0 , LISP_LCAF_GEO_COORD_TYPE ,
 0 , I1II111 )
  IIiI1 += struct . pack ( "BBHBBHBBHIHHH" , oooo0ooo0 , 0 , 0 , iIIi1II1iI1i , iI1Ii1 >> 16 ,
 socket . htons ( iI1Ii1 & 0x0ffff ) , ooOooooo0 , O0O0OI1IIiI1IIIii >> 16 ,
 socket . htons ( O0O0OI1IIiI1IIIii & 0xffff ) , IiI1 , O0OoooOoo , 0 , 0 )
  if 62 - 62: iIii1I11I1II1 * I1IiiI % iII111i * II111iiii / OoO0O00
  return ( IIiI1 )
  if 16 - 16: iIii1I11I1II1
  if 39 - 39: oO0o / OoO0O00 - Ii1I + ooOoO0o + OOooOOo
 def decode_geo ( self , packet , lcaf_len , radius_hi ) :
  Oo0O = "BBHBBHBBHIHHH"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( lcaf_len < ii1ii11Ii ) : return ( None )
  if 84 - 84: iII111i / Oo0Ooo
  oooo0ooo0 , iIoOoooOO , o00OO0O , iIIi1II1iI1i , o0o0O00o0 , iI1Ii1 , ooOooooo0 , iiiI1I1 , O0O0OI1IIiI1IIIii , IiI1 , O0OoooOoo , OoII1Iiii1 , Oo0ooooO0o00 = struct . unpack ( Oo0O ,
  # Ii1I
 packet [ : ii1ii11Ii ] )
  if 93 - 93: I1Ii111 % I1IiiI - iIii1I11I1II1
  if 28 - 28: OOooOOo . I1Ii111 . i11iIiiIii * Oo0Ooo
  if 74 - 74: OoooooooOO * i11iIiiIii * OoO0O00 * o0oOOo0O0Ooo
  if 48 - 48: iII111i * I1ii11iIi11i * oO0o % O0 . OoO0O00
  Oo0ooooO0o00 = socket . ntohs ( Oo0ooooO0o00 )
  if ( Oo0ooooO0o00 == LISP_AFI_LCAF ) : return ( None )
  if 11 - 11: OOooOOo / o0oOOo0O0Ooo
  if ( oooo0ooo0 & 0x40 ) : iIIi1II1iI1i = - iIIi1II1iI1i
  self . latitude = iIIi1II1iI1i
  oOo0Oo = old_div ( ( ( o0o0O00o0 << 16 ) | socket . ntohs ( iI1Ii1 ) ) , 1000 )
  self . lat_mins = old_div ( oOo0Oo , 60 )
  self . lat_secs = oOo0Oo % 60
  if 68 - 68: iIii1I11I1II1 % Ii1I / I11i
  if ( oooo0ooo0 & 0x20 ) : ooOooooo0 = - ooOooooo0
  self . longitude = ooOooooo0
  I1iIiii11I111 = old_div ( ( ( iiiI1I1 << 16 ) | socket . ntohs ( O0O0OI1IIiI1IIIii ) ) , 1000 )
  self . long_mins = old_div ( I1iIiii11I111 , 60 )
  self . long_secs = I1iIiii11I111 % 60
  if 61 - 61: IiII - o0oOOo0O0Ooo
  self . altitude = socket . ntohl ( IiI1 ) if ( oooo0ooo0 & 0x10 ) else - 1
  O0OoooOoo = socket . ntohs ( O0OoooOoo )
  self . radius = O0OoooOoo if ( oooo0ooo0 & 0x02 ) else O0OoooOoo * 1000
  if 8 - 8: OOooOOo . Ii1I
  self . geo_name = None
  packet = packet [ ii1ii11Ii : : ]
  if 15 - 15: ooOoO0o / OOooOOo + i1IIi / Ii1I / OOooOOo
  if ( Oo0ooooO0o00 != 0 ) :
   self . rloc . afi = Oo0ooooO0o00
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
  self . level = 0
  self . rloc = lisp_rloc ( )
  if 88 - 88: I1Ii111 + iIii1I11I1II1 / o0oOOo0O0Ooo
  if 93 - 93: ooOoO0o % iIii1I11I1II1 - OOooOOo . IiII + ooOoO0o
 def copy_rle_node ( self ) :
  Iiiiii = lisp_rle_node ( )
  Iiiiii = copy . deepcopy ( self )
  return ( Iiiiii )
  if 63 - 63: I1ii11iIi11i / OOooOOo
  if 28 - 28: I11i / I1Ii111 + IiII * OoooooooOO - iIii1I11I1II1
 def store_translated_rloc ( self , rloc , port ) :
  rloc . store_translated_rloc ( rloc . rloc , port )
  if 6 - 6: I11i % o0oOOo0O0Ooo / OoooooooOO . I1Ii111
  if 17 - 17: I1ii11iIi11i + OoooooooOO / iIii1I11I1II1 . II111iiii + Oo0Ooo
 def get_encap_keys ( self ) :
  O0ooO0O00oo0 = "4341" if self . rloc . translated_port == 0 else str ( self . rloc . translated_port )
  if 7 - 7: O0 - I1ii11iIi11i - iIii1I11I1II1
  O00oO000Oo0 = self . rloc . rloc . print_address_no_iid ( ) + ":" + O0ooO0O00oo0
  if 96 - 96: OoOoOO00 . I1IiiI . I11i * OoooooooOO + OoooooooOO * O0
  try :
   oOoOOoo = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ]
   if ( oOoOOoo [ 1 ] ) : return ( oOoOOoo [ 1 ] . encrypt_key , oOoOOoo [ 1 ] . icv_key )
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
  IiI = lisp_rle ( self . rle_name )
  for Iiiiii in self . rle_nodes :
   IiI . rle_nodes . append ( Iiiiii . copy_rle_node ( ) )
   if 92 - 92: I11i
  IiI . build_rle_forwarding_list ( )
  return ( IiI )
  if 64 - 64: iII111i / iII111i * iII111i % O0 / IiII . I1ii11iIi11i
  if 23 - 23: i1IIi / I1ii11iIi11i + o0oOOo0O0Ooo
 def add_one_rle_node ( self , rle_node ) :
  Oo00oooOO00o0 = lisp_rle_node ( )
  Oo00oooOO00o0 = copy . deepcopy ( rle_node )
  self . rle_nodes . append ( Oo00oooOO00o0 )
  self . build_rle_forwarding_list ( )
  if 49 - 49: OoO0O00 + OoOoOO00 . i11iIiiIii + o0oOOo0O0Ooo * Oo0Ooo
  if 38 - 38: oO0o % I1Ii111 . I1IiiI / iIii1I11I1II1 . oO0o % II111iiii
 def print_one_rle ( self , rle_node , html , do_formatting ) :
  O0ooO0O00oo0 = rle_node . rloc . translated_port
  if 54 - 54: iIii1I11I1II1 % II111iiii - OOooOOo * i1IIi
  iI111iIi1I = ""
  if ( rle_node . rloc . rloc_name != None ) :
   iI111iIi1I = rle_node . rloc . rloc_name
   if ( do_formatting ) : iI111iIi1I = blue ( iI111iIi1I , html )
   iI111iIi1I = "({})" . format ( iI111iIi1I )
   if 100 - 100: II111iiii - O0 / oO0o - I11i % OOooOOo + Oo0Ooo
   if 2 - 2: iII111i % OoOoOO00 + OoOoOO00 + o0oOOo0O0Ooo / ooOoO0o
  O00oO000Oo0 = rle_node . rloc . rloc . print_address_no_iid ( )
  if ( rle_node . rloc . rloc . is_local ( ) ) : O00oO000Oo0 = red ( O00oO000Oo0 , html )
  Ii11I = "{}{}{}" . format ( O00oO000Oo0 , "" if O0ooO0O00oo0 == 0 else ":" + str ( O0ooO0O00oo0 ) , iI111iIi1I )
  return ( Ii11I )
  if 12 - 12: i1IIi + II111iiii / o0oOOo0O0Ooo
  if 81 - 81: I1Ii111 . Ii1I * ooOoO0o . IiII - OoOoOO00
 def print_rle ( self , html , do_formatting ) :
  Ii11I = ""
  for Iiiiii in self . rle_nodes :
   Ii11I += self . print_one_rle ( Iiiiii , html , do_formatting )
   Ii11I += ", "
   if 79 - 79: ooOoO0o - O0
  return ( Ii11I [ 0 : - 2 ] if Ii11I != "" else "" )
  if 56 - 56: ooOoO0o
  if 89 - 89: O0 % iIii1I11I1II1 / OoOoOO00 - I1Ii111 - I1IiiI
 def print_api_rle ( self ) :
  o0oo0O00oOo = { }
  for Iiiiii in self . rle_nodes :
   Ii11I = self . print_one_rle ( Iiiiii , False , False )
   o0oo0O00oOo [ Ii11I ] = lisp_fill_rloc_in_json ( Iiiiii . rloc )
   if 52 - 52: OoooooooOO * II111iiii / I1Ii111 + I1ii11iIi11i + I11i . ooOoO0o
  return ( o0oo0O00oOo )
  if 81 - 81: OoooooooOO + Ii1I - OoooooooOO + I1ii11iIi11i - i1IIi
  if 73 - 73: oO0o / iII111i * I1Ii111 + i1IIi * I1Ii111 / I1Ii111
 def build_rle_forwarding_list ( self ) :
  i11I1 = - 1
  for Iiiiii in self . rle_nodes :
   if ( i11I1 == - 1 ) :
    if ( Iiiiii . rloc . rloc . is_local ( ) ) : i11I1 = Iiiiii . level
   else :
    if ( Iiiiii . level > i11I1 ) : break
    if 75 - 75: iIii1I11I1II1 / OoO0O00 / i1IIi
    if 36 - 36: o0oOOo0O0Ooo + I1Ii111 / iII111i
  i11I1 = 0 if i11I1 == - 1 else Iiiiii . level
  if 48 - 48: I1IiiI % ooOoO0o * o0oOOo0O0Ooo * II111iiii - OoOoOO00
  self . rle_forwarding_list = [ ]
  for Iiiiii in self . rle_nodes :
   if ( Iiiiii . level == i11I1 or ( i11I1 == 0 and Iiiiii . level == 128 ) ) :
    if ( lisp_i_am_rtr == False and Iiiiii . rloc . rloc . is_local ( ) ) :
     O00oO000Oo0 = Iiiiii . rloc . rloc . print_address_no_iid ( )
     lprint ( "Exclude local RLE RLOC {}" . format ( O00oO000Oo0 ) )
     continue
     if 12 - 12: I1IiiI - Oo0Ooo / I11i
    self . rle_forwarding_list . append ( Iiiiii )
    if 79 - 79: II111iiii . I1Ii111 * I1Ii111 + I11i + I1Ii111 % I1IiiI
    if 42 - 42: I11i - i1IIi . Oo0Ooo - i1IIi
    if 87 - 87: O0 . o0oOOo0O0Ooo % OOooOOo / I11i - I1Ii111 % i11iIiiIii
    if 3 - 3: oO0o + iII111i + OOooOOo
    if 54 - 54: i11iIiiIii + OoO0O00 - IiII - iII111i / I11i
class lisp_json ( object ) :
 def __init__ ( self , name , string , encrypted = False , ms_encrypt = False ) :
  if 85 - 85: OOooOOo * OOooOOo * I1Ii111 - ooOoO0o . O0 % iII111i
  if 5 - 5: i1IIi * iII111i . o0oOOo0O0Ooo - I1ii11iIi11i
  if 84 - 84: i1IIi
  if 17 - 17: IiII + iII111i * OoO0O00 / iII111i
  if ( type ( string ) == bytes ) : string = string . decode ( )
  if 67 - 67: i1IIi * IiII . OoOoOO00 % iIii1I11I1II1 - iIii1I11I1II1 * I1ii11iIi11i
  self . json_name = name
  self . json_encrypted = False
  try :
   json . loads ( string )
  except :
   lprint ( "Invalid JSON string: '{}'" . format ( string ) )
   string = '{ "?" : "?" }'
   if 96 - 96: iII111i / i11iIiiIii / oO0o + Oo0Ooo
  self . json_string = string
  if 65 - 65: OoOoOO00
  if 87 - 87: I11i % i1IIi + i11iIiiIii * II111iiii
  if 58 - 58: OoO0O00 * I1IiiI - II111iiii / Ii1I - I1IiiI % OoooooooOO
  if 33 - 33: IiII / i1IIi + I1Ii111
  if 5 - 5: O0 / iII111i % II111iiii . Oo0Ooo - I11i
  if 84 - 84: oO0o * iII111i % i11iIiiIii - O0 . iIii1I11I1II1 - OoOoOO00
  if 73 - 73: OoOoOO00
  if 66 - 66: Oo0Ooo
  if 42 - 42: i11iIiiIii / II111iiii . OOooOOo
  if 65 - 65: OoOoOO00 % II111iiii + Oo0Ooo
  if ( len ( lisp_ms_json_keys ) != 0 ) :
   if ( ms_encrypt == False ) : return
   self . json_key_id = list ( lisp_ms_json_keys . keys ( ) ) [ 0 ]
   self . json_key = lisp_ms_json_keys [ self . json_key_id ]
   self . encrypt_json ( )
   if 24 - 24: OoO0O00 % OoooooooOO
   if 16 - 16: OoOoOO00 % Oo0Ooo * OoOoOO00 . Ii1I
  if ( lisp_log_id == "lig" and encrypted ) :
   I1IIiiI1II = os . getenv ( "LISP_JSON_KEY" )
   if ( I1IIiiI1II != None ) :
    o00O = - 1
    if ( I1IIiiI1II [ 0 ] == "[" and "]" in I1IIiiI1II ) :
     o00O = I1IIiiI1II . find ( "]" )
     self . json_key_id = int ( I1IIiiI1II [ 1 : o00O ] )
     if 91 - 91: I1Ii111 - OoooooooOO . i1IIi . I1ii11iIi11i
    self . json_key = I1IIiiI1II [ o00O + 1 : : ]
    if 37 - 37: IiII - oO0o
    self . decrypt_json ( )
    if 92 - 92: I1IiiI
    if 51 - 51: OoO0O00 + Oo0Ooo - OOooOOo + I1ii11iIi11i
    if 32 - 32: I1ii11iIi11i % OoOoOO00 + Oo0Ooo
    if 92 - 92: II111iiii . O0 . iIii1I11I1II1 % IiII - i11iIiiIii
 def add ( self ) :
  self . delete ( )
  lisp_json_list [ self . json_name ] = self
  if 9 - 9: OoO0O00
  if 60 - 60: O0 / OoOoOO00 % i11iIiiIii % II111iiii / OoooooooOO
 def delete ( self ) :
  if ( self . json_name in lisp_json_list ) :
   del ( lisp_json_list [ self . json_name ] )
   lisp_json_list [ self . json_name ] = None
   if 52 - 52: ooOoO0o
   if 100 - 100: Oo0Ooo - o0oOOo0O0Ooo + iIii1I11I1II1 / ooOoO0o % iIii1I11I1II1
   if 4 - 4: OoOoOO00 / Oo0Ooo - OoO0O00 . OoOoOO00 / I1Ii111
 def print_json ( self , html ) :
  o00oO00o0Ooo = self . json_string
  I1ii = "***"
  if ( html ) : I1ii = red ( I1ii , html )
  ooOoooOo00Ooo = I1ii + self . json_string + I1ii
  if ( self . valid_json ( ) ) : return ( o00oO00o0Ooo )
  return ( ooOoooOo00Ooo )
  if 95 - 95: I11i . IiII
  if 5 - 5: OoooooooOO + I1IiiI % OOooOOo + ooOoO0o . o0oOOo0O0Ooo * i11iIiiIii
 def valid_json ( self ) :
  try :
   json . loads ( self . json_string )
  except :
   return ( False )
   if 43 - 43: I1IiiI - oO0o + OOooOOo * OoooooooOO
  return ( True )
  if 92 - 92: i11iIiiIii / II111iiii * OoO0O00
  if 51 - 51: I1ii11iIi11i
 def encrypt_json ( self ) :
  OooOooo0 = self . json_key . zfill ( 32 )
  Oo0OOOO0oOoo0 = "0" * 8
  if 95 - 95: I1IiiI / iII111i + i1IIi
  iII1ii1 = json . loads ( self . json_string )
  for I1IIiiI1II in iII1ii1 :
   oO00o = iII1ii1 [ I1IIiiI1II ]
   if ( type ( oO00o ) != str ) : oO00o = str ( oO00o )
   oO00o = chacha . ChaCha ( OooOooo0 , Oo0OOOO0oOoo0 ) . encrypt ( oO00o )
   iII1ii1 [ I1IIiiI1II ] = binascii . hexlify ( oO00o )
   if 59 - 59: oO0o
  self . json_string = json . dumps ( iII1ii1 )
  self . json_encrypted = True
  if 43 - 43: II111iiii - OoooooooOO
  if 11 - 11: I1IiiI
 def decrypt_json ( self ) :
  OooOooo0 = self . json_key . zfill ( 32 )
  Oo0OOOO0oOoo0 = "0" * 8
  if 76 - 76: iII111i - II111iiii % Oo0Ooo . I1Ii111
  iII1ii1 = json . loads ( self . json_string )
  for I1IIiiI1II in iII1ii1 :
   oO00o = binascii . unhexlify ( iII1ii1 [ I1IIiiI1II ] )
   iII1ii1 [ I1IIiiI1II ] = chacha . ChaCha ( OooOooo0 , Oo0OOOO0oOoo0 ) . encrypt ( oO00o )
   if 64 - 64: OoO0O00 - OoO0O00
  try :
   self . json_string = json . dumps ( iII1ii1 )
   self . json_encrypted = False
  except :
   pass
   if 93 - 93: Oo0Ooo . O0
   if 75 - 75: iII111i * II111iiii - I1IiiI
   if 30 - 30: i1IIi / ooOoO0o . ooOoO0o
   if 22 - 22: I11i % iIii1I11I1II1 - i11iIiiIii * OoOoOO00 - I1Ii111
   if 97 - 97: i11iIiiIii . OoOoOO00 + oO0o * O0 % OoO0O00 - Ii1I
   if 46 - 46: I1Ii111
   if 87 - 87: o0oOOo0O0Ooo - iII111i * OoO0O00 * o0oOOo0O0Ooo . o0oOOo0O0Ooo / OOooOOo
class lisp_stats ( object ) :
 def __init__ ( self ) :
  self . packet_count = 0
  self . byte_count = 0
  self . last_rate_check = 0
  self . last_packet_count = 0
  self . last_byte_count = 0
  self . last_increment = None
  if 50 - 50: i11iIiiIii - II111iiii * OoooooooOO + II111iiii - ooOoO0o
  if 52 - 52: i1IIi + i1IIi * i1IIi / OoOoOO00
 def increment ( self , octets ) :
  self . packet_count += 1
  self . byte_count += octets
  self . last_increment = lisp_get_timestamp ( )
  if 98 - 98: iII111i . i1IIi + o0oOOo0O0Ooo * OoooooooOO - i11iIiiIii
  if 21 - 21: i11iIiiIii . oO0o * o0oOOo0O0Ooo + Oo0Ooo * OoOoOO00 * o0oOOo0O0Ooo
 def recent_packet_sec ( self ) :
  if ( self . last_increment == None ) : return ( False )
  o0oOOOO0 = time . time ( ) - self . last_increment
  return ( o0oOOOO0 <= 1 )
  if 33 - 33: I1IiiI + O0 - I11i
  if 90 - 90: I1Ii111 * OoooooooOO . iIii1I11I1II1 % OoO0O00 / I11i + iII111i
 def recent_packet_min ( self ) :
  if ( self . last_increment == None ) : return ( False )
  o0oOOOO0 = time . time ( ) - self . last_increment
  return ( o0oOOOO0 <= 60 )
  if 63 - 63: o0oOOo0O0Ooo . IiII . Oo0Ooo - iIii1I11I1II1 / I1Ii111
  if 66 - 66: ooOoO0o * I1Ii111 - II111iiii
 def stat_colors ( self , c1 , c2 , html ) :
  if ( self . recent_packet_sec ( ) ) :
   return ( green_last_sec ( c1 ) , green_last_sec ( c2 ) )
   if 38 - 38: O0 % I1ii11iIi11i + O0
  if ( self . recent_packet_min ( ) ) :
   return ( green_last_min ( c1 ) , green_last_min ( c2 ) )
   if 37 - 37: Oo0Ooo / I1IiiI
  return ( c1 , c2 )
  if 23 - 23: II111iiii / iII111i
  if 55 - 55: i11iIiiIii - Ii1I % OoooooooOO * OoooooooOO
 def normalize ( self , count ) :
  count = str ( count )
  oO0iII1IIii1iii = len ( count )
  if ( oO0iII1IIii1iii > 12 ) :
   count = count [ 0 : - 10 ] + "." + count [ - 10 : - 7 ] + "T"
   return ( count )
   if 98 - 98: II111iiii % I1Ii111
  if ( oO0iII1IIii1iii > 9 ) :
   count = count [ 0 : - 9 ] + "." + count [ - 9 : - 7 ] + "B"
   return ( count )
   if 64 - 64: I11i
  if ( oO0iII1IIii1iii > 6 ) :
   count = count [ 0 : - 6 ] + "." + count [ - 6 ] + "M"
   return ( count )
   if 26 - 26: ooOoO0o * I11i + OOooOOo * i1IIi
  return ( count )
  if 48 - 48: o0oOOo0O0Ooo - I1ii11iIi11i / iII111i
  if 63 - 63: O0 - IiII . OOooOOo % IiII . I1IiiI / oO0o
 def get_stats ( self , summary , html ) :
  o0o0OOo = self . last_rate_check
  O00O0OoOOo = self . last_packet_count
  OoOOOO = self . last_byte_count
  self . last_rate_check = lisp_get_timestamp ( )
  self . last_packet_count = self . packet_count
  self . last_byte_count = self . byte_count
  if 86 - 86: O0 / Ii1I . OoooooooOO . O0
  O0OOoo = self . last_rate_check - o0o0OOo
  if ( O0OOoo == 0 ) :
   OOOOoo0o = 0
   Ii1I1IiiII = 0
  else :
   OOOOoo0o = int ( old_div ( ( self . packet_count - O00O0OoOOo ) ,
 O0OOoo ) )
   Ii1I1IiiII = old_div ( ( self . byte_count - OoOOOO ) , O0OOoo )
   Ii1I1IiiII = old_div ( ( Ii1I1IiiII * 8 ) , 1000000 )
   Ii1I1IiiII = round ( Ii1I1IiiII , 2 )
   if 6 - 6: Ii1I . OoooooooOO / iII111i + o0oOOo0O0Ooo / II111iiii
   if 28 - 28: OoO0O00 + I1IiiI / iII111i / OOooOOo + OoO0O00 * I1Ii111
   if 76 - 76: I1IiiI . ooOoO0o
   if 85 - 85: o0oOOo0O0Ooo + Oo0Ooo * I1ii11iIi11i
   if 43 - 43: Ii1I * OOooOOo + OoO0O00 . Oo0Ooo % Ii1I . OoO0O00
  o00 = self . normalize ( self . packet_count )
  Ii111i1I1iI = self . normalize ( self . byte_count )
  if 80 - 80: OOooOOo . II111iiii % o0oOOo0O0Ooo . o0oOOo0O0Ooo % i11iIiiIii % OOooOOo
  if 28 - 28: Ii1I
  if 88 - 88: iIii1I11I1II1 + i11iIiiIii - OoOoOO00 - I1ii11iIi11i - I1IiiI
  if 58 - 58: iIii1I11I1II1
  if 56 - 56: OOooOOo * o0oOOo0O0Ooo - O0
  if ( summary ) :
   i1IIIiI1I = "<br>" if html else ""
   o00 , Ii111i1I1iI = self . stat_colors ( o00 , Ii111i1I1iI , html )
   iIiIiiI1III = "packet-count: {}{}byte-count: {}" . format ( o00 , i1IIIiI1I , Ii111i1I1iI )
   O0oO0O0OoOOo = "packet-rate: {} pps\nbit-rate: {} Mbps" . format ( OOOOoo0o , Ii1I1IiiII )
   if 68 - 68: iII111i + II111iiii + I1ii11iIi11i * OOooOOo / oO0o
   if ( html != "" ) : O0oO0O0OoOOo = lisp_span ( iIiIiiI1III , O0oO0O0OoOOo )
  else :
   iI1Iii = str ( OOOOoo0o )
   I1iiIiI1IIii1 = str ( Ii1I1IiiII )
   if ( html ) :
    o00 = lisp_print_cour ( o00 )
    iI1Iii = lisp_print_cour ( iI1Iii )
    Ii111i1I1iI = lisp_print_cour ( Ii111i1I1iI )
    I1iiIiI1IIii1 = lisp_print_cour ( I1iiIiI1IIii1 )
    if 64 - 64: i11iIiiIii + ooOoO0o + oO0o + II111iiii / oO0o
   i1IIIiI1I = "<br>" if html else ", "
   if 7 - 7: iII111i % o0oOOo0O0Ooo
   O0oO0O0OoOOo = ( "packet-count: {}{}packet-rate: {} pps{}byte-count: " + "{}{}bit-rate: {} mbps" ) . format ( o00 , i1IIIiI1I , iI1Iii , i1IIIiI1I , Ii111i1I1iI , i1IIIiI1I ,
   # i1IIi / II111iiii . I1Ii111 + i11iIiiIii . Oo0Ooo
 I1iiIiI1IIii1 )
   if 70 - 70: iIii1I11I1II1 * I1ii11iIi11i
  return ( O0oO0O0OoOOo )
  if 17 - 17: Ii1I * i1IIi % OoO0O00
  if 12 - 12: I1ii11iIi11i
  if 86 - 86: iIii1I11I1II1 % iII111i
  if 80 - 80: Oo0Ooo
  if 37 - 37: i11iIiiIii - I1Ii111
  if 50 - 50: I1IiiI / Ii1I / Ii1I + O0 % I11i - i1IIi
  if 72 - 72: II111iiii . OoO0O00 . II111iiii * I1ii11iIi11i
  if 42 - 42: II111iiii
lisp_decap_stats = {
 "good-packets" : lisp_stats ( ) , "ICV-error" : lisp_stats ( ) ,
 "checksum-error" : lisp_stats ( ) , "lisp-header-error" : lisp_stats ( ) ,
 "no-decrypt-key" : lisp_stats ( ) , "bad-inner-version" : lisp_stats ( ) ,
 "outer-header-error" : lisp_stats ( )
 }
if 45 - 45: I1ii11iIi11i . I1Ii111 . i1IIi * OOooOOo
if 53 - 53: Ii1I . i11iIiiIii + o0oOOo0O0Ooo % I11i - I1ii11iIi11i * I1ii11iIi11i
if 87 - 87: I1Ii111 % i11iIiiIii + O0
if 67 - 67: OoooooooOO / i1IIi / ooOoO0o . i1IIi - i11iIiiIii . i1IIi
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
  if 41 - 41: i11iIiiIii / ooOoO0o - Ii1I + I11i
  if ( recurse == False ) : return
  if 15 - 15: I1ii11iIi11i
  if 22 - 22: iIii1I11I1II1 - i1IIi - i11iIiiIii / I1IiiI + o0oOOo0O0Ooo
  if 56 - 56: I1IiiI . ooOoO0o
  if 35 - 35: iIii1I11I1II1 % Oo0Ooo + o0oOOo0O0Ooo * o0oOOo0O0Ooo % ooOoO0o
  if 10 - 10: I1ii11iIi11i / II111iiii % II111iiii - OoooooooOO * o0oOOo0O0Ooo / ooOoO0o
  if 26 - 26: OoO0O00 . O0 * iII111i % OoOoOO00 % iIii1I11I1II1
  I111I11i = lisp_get_default_route_next_hops ( )
  if ( I111I11i == [ ] ) : return
  if 3 - 3: OOooOOo
  self . rloc_next_hop = I111I11i [ 0 ]
  O0oo = self
  for o000o0oO0 in I111I11i [ 1 : : ] :
   II1IiI = lisp_rloc ( False )
   II1IiI = copy . deepcopy ( self )
   II1IiI . rloc_next_hop = o000o0oO0
   O0oo . next_rloc = II1IiI
   O0oo = II1IiI
   if 28 - 28: i11iIiiIii . OoooooooOO
  self . set_active_rloc_next_hop ( )
  if 79 - 79: i11iIiiIii
  if 60 - 60: I1ii11iIi11i / I11i
 def set_active_rloc_next_hop ( self ) :
  oOOOoO = self . next_rloc
  while ( oOOOoO != None ) :
   if ( lisp_is_active_interface ( oOOOoO ) ) :
    self . active_rloc_next_hop = oOOOoO
    break
    if 40 - 40: I1Ii111
   oOOOoO = oOOOoO . next_rloc
   if 18 - 18: OoOoOO00 * Ii1I
   if 81 - 81: IiII . i11iIiiIii - I1IiiI * i11iIiiIii + OoO0O00
   if 94 - 94: I1ii11iIi11i + OoO0O00 . II111iiii + oO0o . II111iiii
 def up_state ( self ) :
  return ( self . state == LISP_RLOC_UP_STATE )
  if 96 - 96: i11iIiiIii
  if 66 - 66: ooOoO0o * iII111i - iII111i - O0 . o0oOOo0O0Ooo
 def unreach_state ( self ) :
  return ( self . state == LISP_RLOC_UNREACH_STATE )
  if 23 - 23: iIii1I11I1II1 / I11i % OoOoOO00 . OoO0O00
  if 90 - 90: iIii1I11I1II1 - OOooOOo . Ii1I % OoO0O00
 def no_echoed_nonce_state ( self ) :
  return ( self . state == LISP_RLOC_NO_ECHOED_NONCE_STATE )
  if 89 - 89: i11iIiiIii
  if 86 - 86: Oo0Ooo % iIii1I11I1II1 . II111iiii / I11i % OoO0O00 % OoO0O00
 def down_state ( self ) :
  return ( self . state in [ LISP_RLOC_DOWN_STATE , LISP_RLOC_ADMIN_DOWN_STATE ] )
  if 40 - 40: o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo * i1IIi
  if 94 - 94: oO0o - II111iiii + OoOoOO00
  if 90 - 90: Oo0Ooo + Oo0Ooo + I1Ii111
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
  if 81 - 81: i1IIi % iIii1I11I1II1 % Ii1I * ooOoO0o % i1IIi * I1IiiI
  if 15 - 15: ooOoO0o
 def print_rloc ( self , indent ) :
  iIiIIIIIii = lisp_print_elapsed ( self . uptime )
  lprint ( "{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}" . format ( indent ,
 red ( self . rloc . print_address ( ) , False ) , iIiIIIIIii , self . print_state ( ) ,
 self . priority , self . weight , self . mpriority , self . mweight ) )
  if 26 - 26: IiII % ooOoO0o / OOooOOo
  if 14 - 14: i11iIiiIii . I1ii11iIi11i
 def print_rloc_name ( self , cour = False ) :
  if ( self . rloc_name == None ) : return ( "" )
  I11I = self . rloc_name
  if ( cour ) : I11I = lisp_print_cour ( I11I )
  return ( 'rloc-name: {}' . format ( blue ( I11I , cour ) ) )
  if 20 - 20: O0 . iIii1I11I1II1 * I1ii11iIi11i - O0 + I1ii11iIi11i / I1IiiI
  if 67 - 67: OoO0O00 / OoOoOO00 / i11iIiiIii % OoOoOO00
 def is_decent_nat_port ( self ) :
  OOO = self . rloc_name
  if ( OOO == None ) : return ( False )
  if ( OOO . find ( LISP_TP ) == - 1 ) : return ( False )
  return ( True )
  if 4 - 4: OOooOOo / ooOoO0o * ooOoO0o / I1Ii111 . i11iIiiIii * I11i
  if 61 - 61: iIii1I11I1II1 * iII111i
 def store_decent_nat_port ( self ) :
  if ( self . is_decent_nat_port ( ) == False ) : return ( False )
  O0ooO0O00oo0 = self . rloc_name . split ( LISP_TP ) [ - 1 ]
  self . translated_port = int ( O0ooO0O00oo0 )
  return ( True )
  if 67 - 67: i11iIiiIii - Ii1I / Ii1I . iII111i
  if 36 - 36: oO0o + Oo0Ooo * I1Ii111 % OOooOOo . Oo0Ooo . I1IiiI
 def normalize_decent_nat_rloc_name ( self ) :
  if ( self . is_decent_nat_port ( ) == False ) : return ( self . rloc_name )
  OOO = self . rloc_name . split ( LISP_TP ) [ 0 ]
  return ( OOO )
  if 81 - 81: o0oOOo0O0Ooo . OoOoOO00 . i11iIiiIii
  if 13 - 13: i1IIi
 def store_rloc_from_record ( self , rloc_record , nonce , source ) :
  O0ooO0O00oo0 = LISP_DATA_PORT
  self . rloc . copy_address ( rloc_record . rloc )
  self . set_active_rloc_next_hop ( )
  if 70 - 70: O0 / II111iiii
  if 98 - 98: OoOoOO00 - O0 . O0 + ooOoO0o * iIii1I11I1II1
  if 7 - 7: IiII * OoOoOO00 + iIii1I11I1II1 / OoOoOO00 + Oo0Ooo / o0oOOo0O0Ooo
  if 77 - 77: i1IIi . I1IiiI
  oOOOoO = self . next_rloc
  while ( oOOOoO != None ) :
   oOOOoO . rloc . copy_address ( rloc_record . rloc )
   oOOOoO = oOOOoO . next_rloc
   if 59 - 59: O0 + OoooooooOO - i1IIi
   if 87 - 87: IiII * OoooooooOO / Oo0Ooo % iIii1I11I1II1 % oO0o
  if ( rloc_record . rloc_name != None ) :
   self . rloc_name = rloc_record . rloc_name
   if 97 - 97: ooOoO0o % i1IIi . IiII / Oo0Ooo . I1Ii111 . OoO0O00
   if 12 - 12: I1IiiI
   if 99 - 99: II111iiii - OoOoOO00
   if 22 - 22: i11iIiiIii * II111iiii
   if ( lisp_i_am_rtr == False ) :
    if ( self . store_decent_nat_port ( ) ) :
     self . translated_rloc . copy_address ( self . rloc )
     if 11 - 11: Oo0Ooo % i1IIi
     if 70 - 70: II111iiii * Oo0Ooo * OOooOOo - I1IiiI + iIii1I11I1II1 + ooOoO0o
     if 27 - 27: I1ii11iIi11i - I1Ii111 * O0 % ooOoO0o / I1IiiI
     if 53 - 53: i11iIiiIii * i11iIiiIii % O0 % IiII
     if 57 - 57: I1IiiI % i1IIi * OoO0O00 + I1Ii111 . I11i % I11i
     if 69 - 69: I1ii11iIi11i / OoOoOO00 + iIii1I11I1II1
   o000o0oO0 = self . next_rloc
   while ( o000o0oO0 != None ) :
    o000o0oO0 . rloc_name = self . rloc_name
    o000o0oO0 . translated_port = self . translated_port
    o000o0oO0 . translated_rloc . copy_address ( self . translated_rloc )
    o000o0oO0 = o000o0oO0 . next_rloc
    if 8 - 8: OoooooooOO
    if 72 - 72: OoooooooOO % I1ii11iIi11i - OoO0O00 . OoooooooOO
    if 83 - 83: o0oOOo0O0Ooo * Ii1I - Oo0Ooo * iII111i - i11iIiiIii
    if 6 - 6: I1IiiI + i11iIiiIii + O0 / i1IIi
    if 50 - 50: iII111i . II111iiii % I1Ii111 % I1IiiI / o0oOOo0O0Ooo . I1IiiI
    if 76 - 76: OOooOOo % iII111i
  iIIiIi1111iiIii = self . rloc
  if ( iIIiIi1111iiIii . is_null ( ) == False and self . rloc_name != None ) :
   OOO = self . normalize_decent_nat_rloc_name ( )
   ooOOoO = lisp_get_nat_info ( iIIiIi1111iiIii , OOO )
   if ( ooOOoO ) :
    O0ooO0O00oo0 = ooOOoO . port
    O0OOo00 = lisp_nat_state_info [ OOO ] [ 0 ]
    O00oO000Oo0 = iIIiIi1111iiIii . print_address_no_iid ( )
    I1I111i = red ( O00oO000Oo0 , False )
    I1II1II1IiI = "" if self . rloc_name == None else blue ( self . rloc_name , False )
    if 60 - 60: iII111i - OoooooooOO
    if 65 - 65: II111iiii * iII111i
    if 90 - 90: I11i . O0 + oO0o
    if 63 - 63: I11i . I1IiiI + OoooooooOO + O0
    if 55 - 55: i11iIiiIii * Ii1I % OOooOOo + ooOoO0o - I1ii11iIi11i . Oo0Ooo
    if 48 - 48: o0oOOo0O0Ooo
    if ( ooOOoO . timed_out ( ) ) :
     lprint ( ( "    Matched stored NAT state timed out for " + "RLOC {}:{}, {}" ) . format ( I1I111i , O0ooO0O00oo0 , I1II1II1IiI ) )
     if 55 - 55: OOooOOo - OoooooooOO * iIii1I11I1II1 + iII111i % II111iiii
     if 33 - 33: I1Ii111 * oO0o * OoooooooOO + OOooOOo - I1IiiI + I1Ii111
     ooOOoO = None if ( ooOOoO == O0OOo00 ) else O0OOo00
     if ( ooOOoO and ooOOoO . timed_out ( ) ) :
      O0ooO0O00oo0 = ooOOoO . port
      I1I111i = red ( ooOOoO . address , False )
      lprint ( ( "    Youngest stored NAT state timed out " + " for RLOC {}:{}, {}" ) . format ( I1I111i , O0ooO0O00oo0 ,
      # I1Ii111 % Ii1I * Oo0Ooo % o0oOOo0O0Ooo . OoOoOO00 % I1IiiI
 I1II1II1IiI ) )
      ooOOoO = None
      if 5 - 5: IiII
      if 77 - 77: i11iIiiIii . OoooooooOO % iIii1I11I1II1 % I1Ii111
      if 22 - 22: iIii1I11I1II1 + Ii1I / OOooOOo - oO0o * oO0o / IiII
      if 91 - 91: I11i - II111iiii + o0oOOo0O0Ooo + i1IIi + I1ii11iIi11i % Ii1I
      if 57 - 57: o0oOOo0O0Ooo - I1Ii111 / OoooooooOO . OoooooooOO
      if 44 - 44: oO0o / II111iiii % I1IiiI - II111iiii / OoooooooOO
      if 4 - 4: I11i * OoOoOO00
    if ( ooOOoO ) :
     if ( ooOOoO . address != O00oO000Oo0 ) :
      lprint ( "RLOC conflict, RLOC-record {}, NAT state {}" . format ( I1I111i , red ( ooOOoO . address , False ) ) )
      if 18 - 18: iIii1I11I1II1 % OOooOOo - I1ii11iIi11i * i1IIi + Oo0Ooo
      self . rloc . store_address ( ooOOoO . address )
      if 87 - 87: oO0o . I11i
     I1I111i = red ( ooOOoO . address , False )
     O0ooO0O00oo0 = ooOOoO . port
     lprint ( "    Use NAT translated RLOC {}:{} for {}" . format ( I1I111i , O0ooO0O00oo0 , I1II1II1IiI ) )
     if 15 - 15: oO0o
     self . store_translated_rloc ( iIIiIi1111iiIii , O0ooO0O00oo0 )
     if 45 - 45: Oo0Ooo * IiII * OoO0O00 + iIii1I11I1II1
     if 89 - 89: IiII . IiII . oO0o % iII111i
     if 27 - 27: OoOoOO00 + O0 % i1IIi - Oo0Ooo
     if 96 - 96: O0 % o0oOOo0O0Ooo + OOooOOo % I1IiiI
     if 51 - 51: i1IIi . o0oOOo0O0Ooo % I1IiiI - OoooooooOO / OoOoOO00 - I11i
     if 45 - 45: O0 * II111iiii / i11iIiiIii
     o000o0oO0 = self . next_rloc
     while ( o000o0oO0 != None ) :
      o000o0oO0 . store_translated_rloc ( self . translated_rloc , O0ooO0O00oo0 )
      o000o0oO0 = o000o0oO0 . next_rloc
      if 38 - 38: OoooooooOO % i11iIiiIii - O0 / O0
      if 59 - 59: OoO0O00 % iII111i + oO0o * II111iiii . OOooOOo
      if 26 - 26: OOooOOo % OoooooooOO . Ii1I / iIii1I11I1II1 * I1IiiI
      if 85 - 85: IiII / Ii1I - I1ii11iIi11i * OOooOOo
      if 19 - 19: I1ii11iIi11i
  self . geo = rloc_record . geo
  self . elp = rloc_record . elp
  self . json = rloc_record . json
  if 12 - 12: ooOoO0o * I1ii11iIi11i * O0 / oO0o + iII111i - iIii1I11I1II1
  if 81 - 81: Ii1I
  if 87 - 87: O0 % iII111i
  if 57 - 57: Ii1I
  self . rle = rloc_record . rle
  if ( self . rle ) :
   for Iiiiii in self . rle . rle_nodes :
    I11I = Iiiiii . rloc . rloc_name
    ooOOoO = lisp_get_nat_info ( Iiiiii . rloc . rloc , I11I )
    if ( ooOOoO == None ) : continue
    if 49 - 49: I11i
    O0ooO0O00oo0 = ooOOoO . port
    i1IiiI1i = I11I
    if ( i1IiiI1i ) : i1IiiI1i = blue ( I11I , False )
    if 22 - 22: Oo0Ooo % OOooOOo + O0 - OoO0O00 % I11i * O0
    lprint ( ( "      Store translated encap-port {} for RLE-" + "node {}, rloc-name '{}'" ) . format ( O0ooO0O00oo0 ,
    # O0 . OoooooooOO - I11i
 Iiiiii . rloc . rloc . print_address_no_iid ( ) , i1IiiI1i ) )
    if 3 - 3: II111iiii . OoOoOO00 / i1IIi . I1ii11iIi11i - Ii1I
    Iiiiii . store_translated_rloc ( Iiiiii . rloc , O0ooO0O00oo0 )
    if 20 - 20: I11i + IiII
    if 44 - 44: OoooooooOO % I11i / O0
    if 94 - 94: IiII
  self . priority = rloc_record . priority
  self . mpriority = rloc_record . mpriority
  self . weight = rloc_record . weight
  self . mweight = rloc_record . mweight
  if ( rloc_record . reach_bit and rloc_record . local_bit and
 rloc_record . probe_bit == False ) :
   if ( self . state != LISP_RLOC_UP_STATE ) :
    self . last_state_change = lisp_get_timestamp ( )
    if 83 - 83: OoO0O00
   self . state = LISP_RLOC_UP_STATE
   if 55 - 55: iII111i
   if 37 - 37: oO0o / o0oOOo0O0Ooo + I11i * OoO0O00 * o0oOOo0O0Ooo
   if 33 - 33: I1Ii111
   if 97 - 97: Ii1I / iII111i - ooOoO0o + IiII * OoOoOO00 - OOooOOo
   if 43 - 43: oO0o / II111iiii - iII111i / oO0o
  oO0oII11i = source . is_exact_match ( rloc_record . rloc ) if source != None else None
  if 76 - 76: iII111i
  if ( rloc_record . keys != None and oO0oII11i ) :
   I1IIiiI1II = rloc_record . keys [ 1 ]
   if ( I1IIiiI1II != None ) :
    O00oO000Oo0 = rloc_record . rloc . print_address_no_iid ( ) + ":" + str ( O0ooO0O00oo0 )
    if 48 - 48: OOooOOo % I1Ii111 % ooOoO0o . I1ii11iIi11i * O0 . O0
    I1IIiiI1II . add_key_by_rloc ( O00oO000Oo0 , True )
    lprint ( "    Store encap-keys for nonce 0x{}, RLOC {}" . format ( lisp_hex_string ( nonce ) , red ( O00oO000Oo0 , False ) ) )
    if 25 - 25: O0 - Ii1I - IiII
    if 72 - 72: Ii1I % O0 + II111iiii . i11iIiiIii
    if 66 - 66: II111iiii % I1IiiI
  return ( O0ooO0O00oo0 )
  if 88 - 88: iIii1I11I1II1 * iIii1I11I1II1 + I1Ii111 * OOooOOo . I1IiiI
  if 96 - 96: I1ii11iIi11i
 def store_translated_rloc ( self , rloc , port ) :
  self . rloc . copy_address ( rloc )
  self . translated_rloc . copy_address ( rloc )
  self . translated_port = port
  if ( lisp_i_am_rtr == False ) :
   self . rloc_name += LISP_TP + str ( port )
   if 37 - 37: OoO0O00 % o0oOOo0O0Ooo * O0 * O0 + iII111i
   if 18 - 18: i11iIiiIii . o0oOOo0O0Ooo - OOooOOo % oO0o * Ii1I / I1IiiI
   if 46 - 46: o0oOOo0O0Ooo . ooOoO0o / Ii1I
 def is_rloc_translated ( self ) :
  return ( self . translated_rloc . is_null ( ) == False )
  if 97 - 97: Ii1I . Oo0Ooo - O0 - I1Ii111 . i1IIi
  if 47 - 47: IiII * ooOoO0o - i1IIi % OoOoOO00 * i11iIiiIii . OoooooooOO
 def rloc_exists ( self ) :
  if ( self . rloc . is_null ( ) == False ) : return ( True )
  if ( self . rle_name or self . geo_name or self . elp_name or self . json_name ) :
   return ( False )
   if 84 - 84: OoOoOO00 / IiII - i1IIi - I1IiiI * OOooOOo
  return ( True )
  if 35 - 35: II111iiii
  if 28 - 28: I1Ii111 + IiII + I1ii11iIi11i . Ii1I
 def is_rtr ( self ) :
  return ( ( self . priority == 254 and self . mpriority == 255 and self . weight == 0 and self . mweight == 0 ) )
  if 82 - 82: ooOoO0o - ooOoO0o . Ii1I . i11iIiiIii % Ii1I + OOooOOo
  if 33 - 33: Oo0Ooo - OOooOOo / OoOoOO00 % II111iiii % OOooOOo + I1Ii111
  if 41 - 41: I11i + Oo0Ooo . Oo0Ooo / iII111i . OoOoOO00
 def print_state_change ( self , new_state ) :
  I111iiI = self . print_state ( )
  I1i = "{} -> {}" . format ( I111iiI , new_state )
  if ( new_state == "up" and self . unreach_state ( ) ) :
   I1i = bold ( I1i , False )
   if 98 - 98: IiII
  return ( I1i )
  if 75 - 75: OoooooooOO % IiII + Ii1I - i1IIi / OoooooooOO
  if 57 - 57: iII111i
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
  if 18 - 18: II111iiii % i11iIiiIii + I11i - OOooOOo
  if 100 - 100: o0oOOo0O0Ooo / Ii1I - iIii1I11I1II1 / oO0o
 def print_rloc_probe_rtt ( self ) :
  if ( self . rloc_probe_rtt == - 1 ) : return ( "none" )
  return ( self . rloc_probe_rtt )
  if 68 - 68: I11i / II111iiii * oO0o . II111iiii * OOooOOo
  if 78 - 78: I11i * OoO0O00 / II111iiii
 def print_recent_rloc_probe_rtts ( self ) :
  o0o0OoOO0O0 = str ( self . recent_rloc_probe_rtts )
  o0o0OoOO0O0 = o0o0OoOO0O0 . replace ( "-1" , "?" )
  return ( o0o0OoOO0O0 )
  if 85 - 85: i1IIi . i11iIiiIii + ooOoO0o
  if 89 - 89: iIii1I11I1II1 . I1Ii111
 def compute_rloc_probe_rtt ( self ) :
  O0oo = self . rloc_probe_rtt
  self . rloc_probe_rtt = - 1
  if ( self . last_rloc_probe_reply == None ) : return
  if ( self . last_rloc_probe == None ) : return
  self . rloc_probe_rtt = self . last_rloc_probe_reply - self . last_rloc_probe
  self . rloc_probe_rtt = round ( self . rloc_probe_rtt , 3 )
  II1I1I = self . recent_rloc_probe_rtts
  self . recent_rloc_probe_rtts = [ O0oo ] + II1I1I [ 0 : - 1 ]
  if 33 - 33: iIii1I11I1II1 . I1ii11iIi11i - O0 - IiII
  if 51 - 51: OoooooooOO . I1IiiI . i11iIiiIii
 def print_rloc_probe_hops ( self ) :
  return ( self . rloc_probe_hops )
  if 76 - 76: OoOoOO00 + iII111i . ooOoO0o + OoO0O00 + I1IiiI / IiII
  if 70 - 70: O0 * i11iIiiIii / Ii1I - II111iiii / O0
 def print_recent_rloc_probe_hops ( self ) :
  i1OooO0oooOoOO0 = str ( self . recent_rloc_probe_hops )
  return ( i1OooO0oooOoOO0 )
  if 72 - 72: i11iIiiIii . OoO0O00 . IiII - OoOoOO00 * i1IIi
  if 14 - 14: I1ii11iIi11i . OoO0O00
 def store_rloc_probe_hops ( self , to_hops , from_ttl ) :
  if ( to_hops == 0 ) :
   to_hops = "?"
  elif ( to_hops < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   to_hops = "!"
  else :
   to_hops = str ( LISP_RLOC_PROBE_TTL - to_hops )
   if 26 - 26: iII111i / ooOoO0o / Oo0Ooo / Oo0Ooo . I1ii11iIi11i * OOooOOo
  if ( from_ttl < old_div ( LISP_RLOC_PROBE_TTL , 2 ) ) :
   I1iI1iI1ii = "!"
  else :
   I1iI1iI1ii = str ( LISP_RLOC_PROBE_TTL - from_ttl )
   if 29 - 29: iII111i . ooOoO0o . I1Ii111
   if 71 - 71: IiII % O0 % I11i - I1ii11iIi11i
  O0oo = self . rloc_probe_hops
  self . rloc_probe_hops = to_hops + "/" + I1iI1iI1ii
  II1I1I = self . recent_rloc_probe_hops
  self . recent_rloc_probe_hops = [ O0oo ] + II1I1I [ 0 : - 1 ]
  if 55 - 55: ooOoO0o * Ii1I
  if 30 - 30: O0
 def store_rloc_probe_latencies ( self , json_telemetry ) :
  iiiI1i = lisp_decode_telemetry ( json_telemetry )
  if 65 - 65: OoooooooOO . OOooOOo
  o0O = round ( float ( iiiI1i [ "etr-in" ] ) - float ( iiiI1i [ "itr-out" ] ) , 3 )
  oo0oo = round ( float ( iiiI1i [ "itr-in" ] ) - float ( iiiI1i [ "etr-out" ] ) , 3 )
  if 66 - 66: iII111i / i1IIi - Oo0Ooo . Ii1I
  O0oo = self . rloc_probe_latency
  self . rloc_probe_latency = str ( o0O ) + "/" + str ( oo0oo )
  II1I1I = self . recent_rloc_probe_latencies
  self . recent_rloc_probe_latencies = [ O0oo ] + II1I1I [ 0 : - 1 ]
  if 65 - 65: I1ii11iIi11i % ooOoO0o - OoOoOO00 + ooOoO0o + Oo0Ooo
  if 95 - 95: I1Ii111 * i11iIiiIii - I1IiiI - OoOoOO00 . ooOoO0o
 def print_rloc_probe_latency ( self ) :
  return ( self . rloc_probe_latency )
  if 34 - 34: OoooooooOO % I1ii11iIi11i + OoooooooOO % i11iIiiIii / IiII - ooOoO0o
  if 74 - 74: iIii1I11I1II1 % II111iiii + IiII
 def print_recent_rloc_probe_latencies ( self ) :
  OO0o = str ( self . recent_rloc_probe_latencies )
  return ( OO0o )
  if 10 - 10: i1IIi + Oo0Ooo
  if 32 - 32: i1IIi * I1Ii111 % I1IiiI / IiII . I1Ii111
 def process_rloc_probe_reply ( self , ts , nonce , eid , group , hc , ttl , jt ) :
  iIIiIi1111iiIii = self
  while ( True ) :
   if ( iIIiIi1111iiIii . last_rloc_probe_nonce == nonce ) : break
   iIIiIi1111iiIii = iIIiIi1111iiIii . next_rloc
   if ( iIIiIi1111iiIii == None ) :
    lprint ( "    No matching nonce state found for nonce 0x{}" . format ( lisp_hex_string ( nonce ) ) )
    if 11 - 11: OOooOOo
    return ( False )
    if 25 - 25: i1IIi
    if 99 - 99: OOooOOo + OoooooooOO . I1Ii111 * Oo0Ooo % oO0o
    if 75 - 75: iII111i
    if 8 - 8: I1ii11iIi11i . I11i / I1ii11iIi11i - i1IIi
    if 22 - 22: OOooOOo
    if 7 - 7: O0 - I1ii11iIi11i - OoO0O00 * I1Ii111
  iIIiIi1111iiIii . last_rloc_probe_reply = ts
  iIIiIi1111iiIii . compute_rloc_probe_rtt ( )
  IIII11IIiii = iIIiIi1111iiIii . print_state_change ( "up" )
  if ( iIIiIi1111iiIii . state != LISP_RLOC_UP_STATE ) :
   lisp_update_rtr_updown ( iIIiIi1111iiIii . rloc , True )
   iIIiIi1111iiIii . state = LISP_RLOC_UP_STATE
   iIIiIi1111iiIii . last_state_change = lisp_get_timestamp ( )
   IIII1 = lisp_map_cache . lookup_cache ( eid , True )
   if ( IIII1 ) :
    if 100 - 100: OoO0O00 * i1IIi * o0oOOo0O0Ooo * Oo0Ooo - o0oOOo0O0Ooo
    if 100 - 100: iII111i - i11iIiiIii + OoO0O00
    if 50 - 50: II111iiii
    if 42 - 42: OOooOOo * I1Ii111
    if 53 - 53: II111iiii % OOooOOo / I1ii11iIi11i * OoOoOO00 % I1ii11iIi11i * iII111i
    if 91 - 91: iII111i . OoooooooOO
    if 90 - 90: i11iIiiIii - I1IiiI
    IIII1 . build_best_rloc_set ( )
    lisp_write_ipc_map_cache ( True , IIII1 )
    if 39 - 39: iII111i % OoooooooOO % Ii1I % I1IiiI
    if 63 - 63: OoO0O00 - I1Ii111 - II111iiii
    if 79 - 79: II111iiii - II111iiii + OoOoOO00 / iII111i % OoooooooOO - OoO0O00
    if 22 - 22: o0oOOo0O0Ooo + I1Ii111 . Oo0Ooo
    if 84 - 84: O0 + I1IiiI % Oo0Ooo + OOooOOo
    if 94 - 94: OOooOOo
  iIIiIi1111iiIii . store_rloc_probe_hops ( hc , ttl )
  if 81 - 81: i11iIiiIii + iIii1I11I1II1 . i11iIiiIii / OOooOOo / iII111i
  if 34 - 34: i11iIiiIii - o0oOOo0O0Ooo * OoooooooOO * I1ii11iIi11i * Oo0Ooo % I1ii11iIi11i
  if 31 - 31: I11i . o0oOOo0O0Ooo
  if 82 - 82: I11i - Oo0Ooo
  if ( jt ) : iIIiIi1111iiIii . store_rloc_probe_latencies ( jt )
  if 77 - 77: I1IiiI + OoO0O00 % iIii1I11I1II1 - OOooOOo
  oO00oo0 = bold ( "RLOC-probe reply" , False )
  O00oO000Oo0 = iIIiIi1111iiIii . rloc . print_address_no_iid ( )
  OO0OO0o0oO = bold ( str ( iIIiIi1111iiIii . print_rloc_probe_rtt ( ) ) , False )
  I1i1I = ":{}" . format ( self . translated_port ) if self . translated_port != 0 else ""
  if 62 - 62: OoOoOO00 . iII111i + OoooooooOO / I1ii11iIi11i * O0 % I1IiiI
  o000o0oO0 = ""
  if ( iIIiIi1111iiIii . rloc_next_hop != None ) :
   oooOo , o0o00o0oo000O = iIIiIi1111iiIii . rloc_next_hop
   o000o0oO0 = ", nh {}({})" . format ( o0o00o0oo000O , oooOo )
   if 29 - 29: O0 % Oo0Ooo * i11iIiiIii % IiII . i11iIiiIii % I1IiiI
   if 53 - 53: Oo0Ooo * I1Ii111
  iIIi1II1iI1i = bold ( iIIiIi1111iiIii . print_rloc_probe_latency ( ) , False )
  iIIi1II1iI1i = ", latency {}" . format ( iIIi1II1iI1i ) if jt else ""
  if 21 - 21: OoO0O00
  oOO = green ( lisp_print_eid_tuple ( eid , group ) , False )
  if 96 - 96: I1Ii111 % o0oOOo0O0Ooo + OoO0O00 - ooOoO0o
  lprint ( ( "    Received {} from {}{} for {}, {}, rtt {}{}, " + "to-ttl/from-ttl {}{}" ) . format ( oO00oo0 , red ( O00oO000Oo0 , False ) , I1i1I , oOO ,
  # i11iIiiIii / O0 % OoO0O00
 IIII11IIiii , OO0OO0o0oO , o000o0oO0 , str ( hc ) + "/" + str ( ttl ) , iIIi1II1iI1i ) )
  if 88 - 88: i1IIi . I1IiiI
  if 8 - 8: I1ii11iIi11i . OoO0O00 % o0oOOo0O0Ooo / O0
  if 51 - 51: oO0o + Ii1I * Ii1I * I1ii11iIi11i % I11i - I1ii11iIi11i
  if 15 - 15: i1IIi / OoO0O00 - Oo0Ooo
  if ( iIIiIi1111iiIii . next_rloc == None ) : return ( True )
  if 74 - 74: o0oOOo0O0Ooo % Ii1I - II111iiii / ooOoO0o
  if 84 - 84: I1IiiI + OOooOOo
  if 80 - 80: OOooOOo / OoOoOO00
  if 93 - 93: OOooOOo
  iIIiIi1111iiIii = None
  OooOooo = None
  while ( True ) :
   iIIiIi1111iiIii = self if iIIiIi1111iiIii == None else iIIiIi1111iiIii . next_rloc
   if ( iIIiIi1111iiIii == None ) : break
   if ( iIIiIi1111iiIii . up_state ( ) == False ) : continue
   if ( iIIiIi1111iiIii . rloc_probe_rtt == - 1 ) : continue
   if 36 - 36: iII111i % I1ii11iIi11i + OoOoOO00 - i11iIiiIii % II111iiii % I11i
   if ( OooOooo == None ) : OooOooo = iIIiIi1111iiIii
   if ( iIIiIi1111iiIii . rloc_probe_rtt < OooOooo . rloc_probe_rtt ) : OooOooo = iIIiIi1111iiIii
   if 92 - 92: O0 * OoooooooOO + I1ii11iIi11i / IiII
   if 97 - 97: o0oOOo0O0Ooo . Ii1I + I1Ii111
  if ( OooOooo != None ) :
   oooOo , o0o00o0oo000O = OooOooo . rloc_next_hop
   OoI1II1II1iI111 = lisp_get_host_route_device ( O00oO000Oo0 )
   if ( OoI1II1II1iI111 != oooOo ) :
    lisp_install_host_route ( O00oO000Oo0 , o0o00o0oo000O , oooOo )
    self . active_rloc_next_hop = OooOooo
    oooOo = bold ( oooOo , False )
    IIi1iii = red ( O00oO000Oo0 , False )
    OO0OO0o0oO = OooOooo . rloc_probe_rtt
    lprint ( "Change data-plane host-route {} -> {} for {}, best-rtt {}" . format ( OoI1II1II1iI111 , oooOo , IIi1iii , OO0OO0o0oO ) )
    if 69 - 69: I1ii11iIi11i % I1Ii111 / OoooooooOO % oO0o
    if 4 - 4: OoOoOO00 * i11iIiiIii - OoOoOO00 * o0oOOo0O0Ooo % I1ii11iIi11i
  return ( True )
  if 19 - 19: OOooOOo
  if 73 - 73: ooOoO0o / O0 / I1Ii111 . OoooooooOO
 def add_to_rloc_probe_list ( self , eid , group ) :
  O00oO000Oo0 = self . rloc . print_address_no_iid ( )
  O0ooO0O00oo0 = self . translated_port
  if 88 - 88: OoooooooOO - oO0o
  if 80 - 80: ooOoO0o
  if 38 - 38: IiII + OoO0O00 * I11i * iIii1I11I1II1 * oO0o
  if 74 - 74: I1IiiI
  if 39 - 39: iII111i * IiII / iII111i * IiII % I1ii11iIi11i
  if ( O0ooO0O00oo0 != 0 ) :
   iiO0oO = O00oO000Oo0 + ":" + str ( O0ooO0O00oo0 )
   if ( O00oO000Oo0 in lisp_rloc_probe_list ) :
    lisp_rloc_probe_list [ iiO0oO ] = lisp_rloc_probe_list [ O00oO000Oo0 ]
    lisp_rloc_probe_list . pop ( O00oO000Oo0 )
    if 98 - 98: IiII * OOooOOo / O0 - I1Ii111 . I1Ii111 + OOooOOo
   O00oO000Oo0 = iiO0oO
   if 61 - 61: iII111i * Ii1I % Ii1I + I1IiiI
   if 23 - 23: oO0o + I1Ii111 / OoooooooOO / O0 + IiII
   if 80 - 80: i11iIiiIii - OoooooooOO + II111iiii / i1IIi - oO0o
   if 100 - 100: Ii1I
   if 73 - 73: IiII - O0
  if ( O00oO000Oo0 not in lisp_rloc_probe_list ) : lisp_rloc_probe_list [ O00oO000Oo0 ] = [ ]
  if 54 - 54: OOooOOo
  if 28 - 28: i1IIi - Oo0Ooo * OoO0O00 + OoooooooOO - Ii1I * i11iIiiIii
  if 71 - 71: iII111i - OOooOOo / iIii1I11I1II1 % i11iIiiIii
  if 39 - 39: o0oOOo0O0Ooo
  if 32 - 32: iIii1I11I1II1 . II111iiii / IiII % O0 / iII111i
  if ( group . is_null ( ) ) : group . instance_id = 0
  if 97 - 97: iIii1I11I1II1
  i11Iiiii11 = None
  oOo0o0Oo = None
  for IIi1iii , oOO , II11iIIii in lisp_rloc_probe_list [ O00oO000Oo0 ] :
   if 99 - 99: OoooooooOO / II111iiii . I1Ii111
   if 62 - 62: OOooOOo . iII111i . I1ii11iIi11i
   if 23 - 23: O0
   if ( oOo0o0Oo == None ) : oOo0o0Oo = IIi1iii
   if 33 - 33: ooOoO0o - iII111i % IiII
   if ( oOO . is_exact_match ( eid ) and II11iIIii . is_exact_match ( group ) ) :
    if ( IIi1iii == self ) : return
    self . copy_rloc_probe_recents ( IIi1iii )
    self . uptime = IIi1iii . uptime
    i11Iiiii11 = [ IIi1iii , oOO , II11iIIii ]
    break
    if 67 - 67: II111iiii
    if 66 - 66: iIii1I11I1II1 / OOooOOo
    if 65 - 65: IiII . oO0o + O0 - i11iIiiIii + iIii1I11I1II1
    if 82 - 82: iIii1I11I1II1 * iII111i + iIii1I11I1II1 / OoO0O00 + O0
    if 67 - 67: I1Ii111
    if 94 - 94: I1Ii111 % iIii1I11I1II1 - II111iiii . ooOoO0o + i11iIiiIii - i11iIiiIii
    if 55 - 55: OoooooooOO % iIii1I11I1II1 % I1ii11iIi11i % i1IIi
  if ( i11Iiiii11 == None and oOo0o0Oo != None ) :
   self . copy_rloc_probe_recents ( oOo0o0Oo )
   self . uptime = oOo0o0Oo . uptime
   if 46 - 46: I11i - ooOoO0o . I1IiiI
   if 36 - 36: I11i + OoO0O00 * O0 * OoOoOO00 * iII111i
   if 90 - 90: i11iIiiIii / i1IIi
   if 35 - 35: Ii1I . I11i / oO0o / OoOoOO00
   if 5 - 5: I1ii11iIi11i . o0oOOo0O0Ooo * iII111i * I1ii11iIi11i % I1Ii111
  if ( i11Iiiii11 != None ) :
   lisp_rloc_probe_list [ O00oO000Oo0 ] . remove ( i11Iiiii11 )
   if 83 - 83: iIii1I11I1II1 * o0oOOo0O0Ooo % i11iIiiIii + OoO0O00 . O0
   if 87 - 87: II111iiii - iIii1I11I1II1 % I11i % I1IiiI . o0oOOo0O0Ooo
   if 52 - 52: i11iIiiIii . oO0o / OoooooooOO - OoO0O00
   if 7 - 7: I1IiiI * I1IiiI % OOooOOo % iIii1I11I1II1 * OoO0O00 . o0oOOo0O0Ooo
   if 32 - 32: ooOoO0o / i1IIi
  lisp_rloc_probe_list [ O00oO000Oo0 ] . append ( [ self , eid , group ] )
  if 55 - 55: oO0o . OoOoOO00 + OoooooooOO - ooOoO0o . OoooooooOO
  if 77 - 77: I1IiiI
 def delete_from_rloc_probe_list ( self , eid , group ) :
  O00oO000Oo0 = self . rloc . print_address_no_iid ( )
  O0ooO0O00oo0 = self . translated_port
  if ( O0ooO0O00oo0 != 0 ) : O00oO000Oo0 += ":" + str ( O0ooO0O00oo0 )
  if ( O00oO000Oo0 not in lisp_rloc_probe_list ) : return
  if 16 - 16: I1IiiI + ooOoO0o - O0 / o0oOOo0O0Ooo
  iIIIiiIIi = [ ]
  for I1I11i in lisp_rloc_probe_list [ O00oO000Oo0 ] :
   if ( I1I11i [ 0 ] != self ) : continue
   if ( I1I11i [ 1 ] . is_exact_match ( eid ) == False ) : continue
   if ( I1I11i [ 2 ] . is_exact_match ( group ) == False ) : continue
   iIIIiiIIi = I1I11i
   break
   if 99 - 99: OOooOOo % OOooOOo
  if ( iIIIiiIIi == [ ] ) : return
  if 87 - 87: I11i % Ii1I % Oo0Ooo . II111iiii / oO0o
  try :
   lisp_rloc_probe_list [ O00oO000Oo0 ] . remove ( iIIIiiIIi )
   if ( lisp_rloc_probe_list [ O00oO000Oo0 ] == [ ] ) :
    lisp_rloc_probe_list . pop ( O00oO000Oo0 )
    if 19 - 19: O0 . OOooOOo + I1Ii111 * I1ii11iIi11i
  except :
   return
   if 91 - 91: o0oOOo0O0Ooo / oO0o . o0oOOo0O0Ooo + IiII + ooOoO0o . I1Ii111
   if 90 - 90: i1IIi + oO0o * oO0o / ooOoO0o . IiII
   if 98 - 98: I11i % OoO0O00 . iII111i - o0oOOo0O0Ooo
 def print_rloc_probe_state ( self , trailing_linefeed ) :
  i11IiIIi11I = ""
  iIIiIi1111iiIii = self
  while ( True ) :
   oO00Ooo0O0 = iIIiIi1111iiIii . last_rloc_probe
   if ( oO00Ooo0O0 == None ) : oO00Ooo0O0 = 0
   ii1II1Iii111iI1 = iIIiIi1111iiIii . last_rloc_probe_reply
   if ( ii1II1Iii111iI1 == None ) : ii1II1Iii111iI1 = 0
   OO0OO0o0oO = iIIiIi1111iiIii . print_rloc_probe_rtt ( )
   OOo0oOO0o0oo0 = space ( 4 )
   if 8 - 8: OoOoOO00 / Oo0Ooo * ooOoO0o
   if ( iIIiIi1111iiIii . rloc_next_hop == None ) :
    i11IiIIi11I += "RLOC-Probing:\n"
   else :
    oooOo , o0o00o0oo000O = iIIiIi1111iiIii . rloc_next_hop
    i11IiIIi11I += "RLOC-Probing for nh {}({}):\n" . format ( o0o00o0oo000O , oooOo )
    if 33 - 33: O0 / ooOoO0o * I1Ii111
    if 100 - 100: iIii1I11I1II1 * I11i - iII111i
   i11IiIIi11I += ( "{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + "received: {}, rtt {}" ) . format ( OOo0oOO0o0oo0 , lisp_print_elapsed ( oO00Ooo0O0 ) ,
   # Ii1I . II111iiii * iIii1I11I1II1
 OOo0oOO0o0oo0 , lisp_print_elapsed ( ii1II1Iii111iI1 ) , OO0OO0o0oO )
   if 40 - 40: I1Ii111 * OOooOOo + I1Ii111 % i11iIiiIii + i1IIi
   if ( trailing_linefeed ) : i11IiIIi11I += "\n"
   if 39 - 39: OoO0O00 + OoO0O00 . iII111i
   iIIiIi1111iiIii = iIIiIi1111iiIii . next_rloc
   if ( iIIiIi1111iiIii == None ) : break
   i11IiIIi11I += "\n"
   if 46 - 46: IiII / IiII / oO0o
  return ( i11IiIIi11I )
  if 93 - 93: OoO0O00 / I1Ii111
  if 51 - 51: OoooooooOO + o0oOOo0O0Ooo
 def get_encap_keys ( self ) :
  O0ooO0O00oo0 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 100 - 100: OoO0O00 / OoOoOO00 / OOooOOo / OoO0O00
  O00oO000Oo0 = self . rloc . print_address_no_iid ( ) + ":" + O0ooO0O00oo0
  if 95 - 95: ooOoO0o
  try :
   oOoOOoo = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ]
   if ( oOoOOoo [ 1 ] ) : return ( oOoOOoo [ 1 ] . encrypt_key , oOoOOoo [ 1 ] . icv_key )
   return ( None , None )
  except :
   return ( None , None )
   if 95 - 95: Ii1I + i1IIi . I1IiiI % I1Ii111 / Ii1I * O0
   if 68 - 68: I1Ii111 - IiII - oO0o - Oo0Ooo - o0oOOo0O0Ooo
   if 32 - 32: OoOoOO00 % i11iIiiIii
 def rloc_recent_rekey ( self ) :
  O0ooO0O00oo0 = "4341" if self . translated_port == 0 else str ( self . translated_port )
  if 53 - 53: I1Ii111 * Ii1I / IiII . i1IIi * II111iiii / o0oOOo0O0Ooo
  O00oO000Oo0 = self . rloc . print_address_no_iid ( ) + ":" + O0ooO0O00oo0
  if 44 - 44: I1Ii111 + ooOoO0o
  try :
   I1IIiiI1II = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ] [ 1 ]
   if ( I1IIiiI1II == None ) : return ( False )
   if ( I1IIiiI1II . last_rekey == None ) : return ( True )
   return ( time . time ( ) - I1IIiiI1II . last_rekey < 1 )
  except :
   return ( False )
   if 15 - 15: I11i + OoO0O00 + OoOoOO00
   if 100 - 100: I1Ii111
   if 78 - 78: OoOoOO00
 def refresh_decent_nat_rloc ( self , lisp_sockets , eid ) :
  iIiIIIIIii = self . last_state_change
  if ( iIiIIIIIii == None ) : return
  if ( ( time . time ( ) - iIiIIIIIii ) <= 60 ) : return
  if 16 - 16: I1Ii111 % OoO0O00 - OoO0O00 % OoOoOO00 * OoO0O00
  oOO = green ( eid . print_address ( ) , False )
  IIi1iii = red ( self . rloc . print_address_no_iid ( ) , False )
  OOO = blue ( self . rloc_name , False )
  lprint ( "Refresh map-cache for {} for RLOC {}, {}" . format ( oOO , IIi1iii , OOO ) )
  if 36 - 36: OoOoOO00 * II111iiii . OoooooooOO * I11i . I11i
  lisp_send_map_request ( lisp_sockets , 0 , None , eid , None )
  if 13 - 13: I1ii11iIi11i * II111iiii
  if 93 - 93: OOooOOo / O0 - o0oOOo0O0Ooo + OoO0O00 * I1IiiI
 def get_rle ( self , rloc ) :
  if ( self . rle == None ) : return ( None )
  for Iiiiii in self . rle . rle_nodes :
   IIi1iii = Iiiiii . rloc . rloc
   if ( rloc . is_exact_match ( IIi1iii ) ) : return ( Iiiiii . rloc )
   if 53 - 53: I1ii11iIi11i
  return ( None )
  if 91 - 91: o0oOOo0O0Ooo - I1ii11iIi11i . i1IIi
  if 64 - 64: ooOoO0o
  if 23 - 23: Oo0Ooo . OoO0O00
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
  if 49 - 49: oO0o % i11iIiiIii * Ii1I
  if 9 - 9: Oo0Ooo - OoO0O00 + ooOoO0o / o0oOOo0O0Ooo
 def print_mapping ( self , eid_indent , rloc_indent ) :
  iIiIIIIIii = lisp_print_elapsed ( self . uptime )
  i1I1IIIiII = "" if self . group . is_null ( ) else ", group {}" . format ( self . group . print_prefix ( ) )
  if 61 - 61: O0 - i11iIiiIii * o0oOOo0O0Ooo
  lprint ( "{}eid {}{}, uptime {}, {} rlocs:" . format ( eid_indent ,
 green ( self . eid . print_prefix ( ) , False ) , i1I1IIIiII , iIiIIIIIii ,
 len ( self . rloc_set ) ) )
  for iIIiIi1111iiIii in self . rloc_set : iIIiIi1111iiIii . print_rloc ( rloc_indent )
  if 92 - 92: Oo0Ooo + OOooOOo - i11iIiiIii
  if 26 - 26: O0 % Oo0Ooo + ooOoO0o - Ii1I . Oo0Ooo
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 33 - 33: I1Ii111 / iII111i . I1Ii111 % II111iiii
  if 52 - 52: I1ii11iIi11i
 def print_ttl ( self ) :
  o0ooo000o00O = self . map_cache_ttl
  if ( o0ooo000o00O == None ) : return ( "forever" )
  if 1 - 1: II111iiii + I1ii11iIi11i * OoOoOO00 % ooOoO0o - iII111i % OoooooooOO
  if ( o0ooo000o00O >= 3600 ) :
   if ( ( o0ooo000o00O % 3600 ) == 0 ) :
    o0ooo000o00O = str ( old_div ( o0ooo000o00O , 3600 ) ) + " hours"
   else :
    o0ooo000o00O = str ( o0ooo000o00O * 60 ) + " mins"
    if 77 - 77: iII111i + o0oOOo0O0Ooo
  elif ( o0ooo000o00O >= 60 ) :
   if ( ( o0ooo000o00O % 60 ) == 0 ) :
    o0ooo000o00O = str ( old_div ( o0ooo000o00O , 60 ) ) + " mins"
   else :
    o0ooo000o00O = str ( o0ooo000o00O ) + " secs"
    if 60 - 60: I1ii11iIi11i
  else :
   o0ooo000o00O = str ( o0ooo000o00O ) + " secs"
   if 23 - 23: iII111i % I1IiiI % I1Ii111 * oO0o * I1IiiI
  return ( o0ooo000o00O )
  if 74 - 74: O0 / I11i . Oo0Ooo / I11i % OoO0O00 % o0oOOo0O0Ooo
  if 83 - 83: OoO0O00 - i11iIiiIii + iIii1I11I1II1
 def refresh ( self ) :
  if ( self . group . is_null ( ) ) : return ( self . refresh_unicast ( ) )
  return ( self . refresh_multicast ( ) )
  if 52 - 52: OoooooooOO
  if 44 - 44: O0 / OoooooooOO + ooOoO0o * I1ii11iIi11i
 def refresh_unicast ( self ) :
  return ( self . is_active ( ) and self . has_ttl_elapsed ( ) and
 self . gleaned == False )
  if 36 - 36: I1ii11iIi11i / OoO0O00 - oO0o % O0
  if 12 - 12: i1IIi * ooOoO0o / oO0o + I1IiiI / OoooooooOO
 def refresh_multicast ( self ) :
  if 86 - 86: Oo0Ooo / OoO0O00
  if 78 - 78: I1IiiI * I1IiiI
  if 13 - 13: oO0o
  if 43 - 43: oO0o / Ii1I % OOooOOo
  if 45 - 45: II111iiii
  o0oOOOO0 = int ( ( time . time ( ) - self . uptime ) % self . map_cache_ttl )
  I111i = ( o0oOOOO0 in [ 0 , 1 , 2 ] )
  if ( I111i == False ) : return ( False )
  if 40 - 40: i11iIiiIii . OOooOOo % o0oOOo0O0Ooo + OoO0O00
  if 31 - 31: ooOoO0o * I1ii11iIi11i
  if 23 - 23: OoOoOO00 - I11i . iIii1I11I1II1
  if 87 - 87: OoO0O00 - i11iIiiIii / O0 % OOooOOo % OOooOOo * i1IIi
  iIIii1II1ii1 = ( ( time . time ( ) - self . last_multicast_map_request ) <= 2 )
  if ( iIIii1II1ii1 ) : return ( False )
  if 28 - 28: OoO0O00
  self . last_multicast_map_request = lisp_get_timestamp ( )
  return ( True )
  if 51 - 51: I11i % II111iiii / I1IiiI * ooOoO0o
  if 10 - 10: OoO0O00
 def has_ttl_elapsed ( self ) :
  if ( self . map_cache_ttl == None ) : return ( False )
  o0oOOOO0 = time . time ( ) - self . last_refresh_time
  if ( o0oOOOO0 >= self . map_cache_ttl ) : return ( True )
  if 72 - 72: O0 - I1IiiI . Oo0Ooo / o0oOOo0O0Ooo - i1IIi
  if 98 - 98: Oo0Ooo * ooOoO0o * I11i + oO0o - O0
  if 3 - 3: i1IIi + OoOoOO00 - OoOoOO00
  if 85 - 85: o0oOOo0O0Ooo / o0oOOo0O0Ooo + Oo0Ooo * II111iiii + Ii1I * Ii1I
  if 26 - 26: o0oOOo0O0Ooo + oO0o * i11iIiiIii / II111iiii
  o0O0OoOOoo0 = self . map_cache_ttl - ( old_div ( self . map_cache_ttl , 10 ) )
  if ( o0oOOOO0 >= o0O0OoOOoo0 ) : return ( True )
  return ( False )
  if 43 - 43: o0oOOo0O0Ooo
  if 78 - 78: I1Ii111 % i1IIi * I11i
 def is_active ( self ) :
  if ( self . stats . last_increment == None ) : return ( False )
  o0oOOOO0 = time . time ( ) - self . stats . last_increment
  return ( o0oOOOO0 <= 60 )
  if 59 - 59: OoOoOO00 % OoO0O00 % i11iIiiIii . II111iiii % I1ii11iIi11i + i1IIi
  if 99 - 99: I11i + IiII * I1Ii111 - OOooOOo - i1IIi
 def match_eid_tuple ( self , db ) :
  if ( self . eid . is_exact_match ( db . eid ) == False ) : return ( False )
  if ( self . group . is_exact_match ( db . group ) == False ) : return ( False )
  return ( True )
  if 77 - 77: I11i . IiII / OoO0O00 / I1Ii111
  if 8 - 8: o0oOOo0O0Ooo + iII111i / OoO0O00 * ooOoO0o - oO0o . iII111i
 def sort_rloc_set ( self ) :
  self . rloc_set . sort ( key = operator . attrgetter ( 'rloc.address' ) )
  if 32 - 32: OoooooooOO . I1Ii111 - I1ii11iIi11i
  if 29 - 29: OoO0O00
 def delete_rlocs_from_rloc_probe_list ( self ) :
  for iIIiIi1111iiIii in self . best_rloc_set :
   if ( iIIiIi1111iiIii . rloc . is_null ( ) and iIIiIi1111iiIii . rle != None ) :
    if 33 - 33: I1ii11iIi11i - O0
    if 72 - 72: Oo0Ooo * iII111i - I11i
    if 81 - 81: I1Ii111
    if 85 - 85: O0 % OoOoOO00 . I1ii11iIi11i
    for Iiiiii in iIIiIi1111iiIii . rle . rle_forwarding_list :
     Iiiiii . rloc . delete_from_rloc_probe_list ( self . eid , self . group )
     if 46 - 46: OOooOOo * iIii1I11I1II1
   else :
    iIIiIi1111iiIii . delete_from_rloc_probe_list ( self . eid , self . group )
    if 33 - 33: OoO0O00 * II111iiii / i1IIi
    if 93 - 93: I1Ii111 % I11i
    if 64 - 64: I1IiiI % OoOoOO00 / Oo0Ooo
    if 40 - 40: Ii1I + iIii1I11I1II1 / oO0o . II111iiii % O0 - IiII
 def build_best_rloc_set ( self ) :
  if 49 - 49: IiII - OOooOOo * OOooOOo . O0
  if 60 - 60: OoOoOO00 % iIii1I11I1II1 + IiII % o0oOOo0O0Ooo
  if 64 - 64: OoOoOO00 * I1ii11iIi11i . OoooooooOO . i1IIi
  if 61 - 61: OoO0O00
  if 100 - 100: OoOoOO00
  if 97 - 97: OoooooooOO
  if 91 - 91: o0oOOo0O0Ooo / O0 % OoO0O00
  if 35 - 35: iII111i % OoO0O00 * O0
  if 37 - 37: OOooOOo
  if 100 - 100: Oo0Ooo * I1IiiI . ooOoO0o
  self . best_rloc_set = [ ]
  if ( self . rloc_set == None ) : return
  if 53 - 53: OOooOOo + o0oOOo0O0Ooo * Ii1I + O0
  if 75 - 75: OoooooooOO
  if 24 - 24: I1Ii111 % i11iIiiIii % oO0o . OOooOOo % IiII
  if 23 - 23: o0oOOo0O0Ooo * II111iiii - Oo0Ooo - I1IiiI
  if 86 - 86: I1IiiI - II111iiii * II111iiii * oO0o % OoooooooOO * OoOoOO00
  Oo0OOo0 = 256
  for iIIiIi1111iiIii in self . rloc_set :
   if ( iIIiIi1111iiIii . up_state ( ) == False ) : continue
   Oo0OOo0 = min ( iIIiIi1111iiIii . priority , Oo0OOo0 )
   if 100 - 100: iIii1I11I1II1 - I1IiiI
   if 9 - 9: I11i % i1IIi / ooOoO0o % iII111i - oO0o - II111iiii
   if 29 - 29: ooOoO0o . II111iiii . i1IIi % oO0o
   if 11 - 11: OoOoOO00 . OoO0O00 % I11i * iII111i % I1Ii111 . O0
   if 17 - 17: OOooOOo / i11iIiiIii - i11iIiiIii . II111iiii . ooOoO0o
  for iIIiIi1111iiIii in self . rloc_set :
   if ( iIIiIi1111iiIii . priority == Oo0OOo0 ) : self . best_rloc_set . append ( iIIiIi1111iiIii )
   if 38 - 38: OOooOOo . OoooooooOO . II111iiii + OoO0O00 / oO0o . OoooooooOO
   if 100 - 100: OoO0O00
   if 36 - 36: oO0o + Ii1I - O0
   if 19 - 19: O0 + I1Ii111 . I1Ii111 * IiII * ooOoO0o + i1IIi
   if 51 - 51: ooOoO0o % OoOoOO00 % i1IIi / O0
   if 11 - 11: OOooOOo . I1ii11iIi11i * OOooOOo * OoO0O00
  for iIIiIi1111iiIii in self . rloc_set :
   if ( iIIiIi1111iiIii . rloc . is_null ( ) ) :
    if 11 - 11: I11i
    if 85 - 85: OoOoOO00 - Ii1I / Oo0Ooo % I1ii11iIi11i
    if 12 - 12: i1IIi + o0oOOo0O0Ooo / oO0o . O0
    if 37 - 37: IiII
    if 99 - 99: i11iIiiIii % i11iIiiIii . I11i * I1ii11iIi11i . OoO0O00 / I1IiiI
    if ( iIIiIi1111iiIii . rle != None and iIIiIi1111iiIii . rle . rle_forwarding_list != [ ] ) :
     for Iiiiii in iIIiIi1111iiIii . rle . rle_forwarding_list :
      Iiiiii . rloc . add_to_rloc_probe_list ( self . eid , self . group )
      if 44 - 44: iII111i - OoO0O00 / i11iIiiIii
      if 55 - 55: O0 * OoO0O00 * i1IIi
    continue
    if 9 - 9: IiII
   iIIiIi1111iiIii . add_to_rloc_probe_list ( self . eid , self . group )
   if 64 - 64: ooOoO0o + OoooooooOO
   if 99 - 99: iIii1I11I1II1 * II111iiii * i11iIiiIii
   if 10 - 10: OOooOOo
 def select_rloc ( self , lisp_packet , ipc_socket ) :
  Oo00O0o0O = lisp_packet . packet
  O000oOooo00o = lisp_packet . inner_version
  OOOOo0o0O0o = len ( self . best_rloc_set )
  if 15 - 15: I11i
  if ( OOOOo0o0O0o == 0 ) :
   self . stats . increment ( len ( Oo00O0o0O ) )
   return ( [ None , None , None , self . action , None , None ] )
   if 82 - 82: I11i . ooOoO0o - ooOoO0o
   if 11 - 11: I1ii11iIi11i / o0oOOo0O0Ooo % I1ii11iIi11i / OoooooooOO
  Ii11I11Iii = 4 if lisp_load_split_pings else 0
  ooo00OoOooooo = lisp_packet . hash_ports ( )
  if ( O000oOooo00o == 4 ) :
   for o000o0O0Oo00 in range ( 8 + Ii11I11Iii ) :
    ooo00OoOooooo = ooo00OoOooooo ^ struct . unpack ( "B" , Oo00O0o0O [ o000o0O0Oo00 + 12 : o000o0O0Oo00 + 13 ] ) [ 0 ]
    if 62 - 62: o0oOOo0O0Ooo
  elif ( O000oOooo00o == 6 ) :
   for o000o0O0Oo00 in range ( 0 , 32 + Ii11I11Iii , 4 ) :
    ooo00OoOooooo = ooo00OoOooooo ^ struct . unpack ( "I" , Oo00O0o0O [ o000o0O0Oo00 + 8 : o000o0O0Oo00 + 12 ] ) [ 0 ]
    if 54 - 54: iIii1I11I1II1 / OoooooooOO + o0oOOo0O0Ooo . i1IIi - OoooooooOO
   ooo00OoOooooo = ( ooo00OoOooooo >> 16 ) + ( ooo00OoOooooo & 0xffff )
   ooo00OoOooooo = ( ooo00OoOooooo >> 8 ) + ( ooo00OoOooooo & 0xff )
  else :
   for o000o0O0Oo00 in range ( 0 , 12 + Ii11I11Iii , 4 ) :
    ooo00OoOooooo = ooo00OoOooooo ^ struct . unpack ( "I" , Oo00O0o0O [ o000o0O0Oo00 : o000o0O0Oo00 + 4 ] ) [ 0 ]
    if 70 - 70: Ii1I / OoOoOO00 * Oo0Ooo
    if 32 - 32: I1Ii111 . OoOoOO00 % OoooooooOO + I1Ii111 * OoO0O00
    if 84 - 84: OoOoOO00
  if ( lisp_data_plane_logging ) :
   oO0oo00OO = [ ]
   for IIi1iii in self . best_rloc_set :
    if ( IIi1iii . rloc . is_null ( ) ) : continue
    oO0oo00OO . append ( [ IIi1iii . rloc . print_address_no_iid ( ) , IIi1iii . print_state ( ) ] )
    if 52 - 52: I11i % I1Ii111 % i11iIiiIii
   dprint ( "Packet hash {}, index {}, best-rloc-list: {}" . format ( hex ( ooo00OoOooooo ) , ooo00OoOooooo % OOOOo0o0O0o , red ( str ( oO0oo00OO ) , False ) ) )
   if 84 - 84: I1IiiI % II111iiii + Oo0Ooo + OoOoOO00 + Oo0Ooo . I1Ii111
   if 58 - 58: II111iiii + I1Ii111 / I11i
   if 13 - 13: I1ii11iIi11i + II111iiii * IiII * OoooooooOO + O0 * O0
   if 15 - 15: Oo0Ooo % I11i * O0
   if 61 - 61: I1ii11iIi11i - ooOoO0o / OoOoOO00 % OOooOOo * i1IIi . IiII
   if 27 - 27: I1ii11iIi11i % iII111i . Oo0Ooo * iIii1I11I1II1
  iIIiIi1111iiIii = self . best_rloc_set [ ooo00OoOooooo % OOOOo0o0O0o ]
  if 40 - 40: I11i
  if 58 - 58: o0oOOo0O0Ooo / OOooOOo . oO0o % ooOoO0o
  if 33 - 33: I1IiiI * I1ii11iIi11i . OoO0O00 - I1Ii111 . OoO0O00
  if 79 - 79: ooOoO0o
  if ( lisp_decent_nat and iIIiIi1111iiIii . stats . packet_count == 0 ) :
   IIi1iii = self . find_rtr_rloc ( )
   if ( IIi1iii != None ) : iIIiIi1111iiIii = IIi1iii
   if 90 - 90: OOooOOo
   if 4 - 4: OoOoOO00 - I1Ii111 . i1IIi - IiII . ooOoO0o + II111iiii
   if 56 - 56: I1ii11iIi11i / i1IIi + I11i % Oo0Ooo
   if 86 - 86: O0 * II111iiii
   if 75 - 75: iIii1I11I1II1 - Oo0Ooo - OoOoOO00 % I1ii11iIi11i . II111iiii
   if 11 - 11: I1ii11iIi11i - I1ii11iIi11i . ooOoO0o * Oo0Ooo + I1Ii111
  oOoOooO0OOOoo = lisp_get_echo_nonce ( iIIiIi1111iiIii . rloc , None )
  if ( oOoOooO0OOOoo ) :
   oOoOooO0OOOoo . change_state ( iIIiIi1111iiIii )
   if ( iIIiIi1111iiIii . no_echoed_nonce_state ( ) ) :
    oOoOooO0OOOoo . request_nonce_sent = None
    if 59 - 59: iII111i - OOooOOo - OoO0O00 . I1IiiI % o0oOOo0O0Ooo + iII111i
    if 10 - 10: iIii1I11I1II1 - Ii1I
    if 84 - 84: iII111i
    if 21 - 21: i11iIiiIii
    if 30 - 30: OoO0O00 + OoooooooOO
    if 98 - 98: I1ii11iIi11i % I1IiiI
  if ( iIIiIi1111iiIii . up_state ( ) == False ) :
   II11o0ooOOo0OoO = ooo00OoOooooo % OOOOo0o0O0o
   o00O = ( II11o0ooOOo0OoO + 1 ) % OOOOo0o0O0o
   while ( o00O != II11o0ooOOo0OoO ) :
    iIIiIi1111iiIii = self . best_rloc_set [ o00O ]
    if ( iIIiIi1111iiIii . up_state ( ) ) : break
    o00O = ( o00O + 1 ) % OOOOo0o0O0o
    if 63 - 63: I11i
   if ( o00O == II11o0ooOOo0OoO ) :
    self . build_best_rloc_set ( )
    return ( [ None , None , None , None , None , None ] )
    if 32 - 32: Ii1I . I1ii11iIi11i + OoooooooOO - OoooooooOO + i1IIi
    if 42 - 42: i1IIi
    if 33 - 33: iIii1I11I1II1 * i11iIiiIii
    if 7 - 7: oO0o
    if 89 - 89: i11iIiiIii / o0oOOo0O0Ooo / I1ii11iIi11i % iII111i . OoooooooOO - iIii1I11I1II1
    if 63 - 63: Ii1I % I1Ii111 + O0 * OoO0O00 . oO0o
  if ( iIIiIi1111iiIii . rle_name and iIIiIi1111iiIii . rle == None ) :
   if ( iIIiIi1111iiIii . rle_name in lisp_rle_list ) :
    iIIiIi1111iiIii . rle = lisp_rle_list [ iIIiIi1111iiIii . rle_name ]
    if 34 - 34: I1IiiI . I1ii11iIi11i . O0 - OoOoOO00 - i11iIiiIii / iII111i
    if 63 - 63: OOooOOo
  if ( iIIiIi1111iiIii . rle ) : return ( [ None , None , None , None , iIIiIi1111iiIii . rle , None ] )
  if 84 - 84: i11iIiiIii * iIii1I11I1II1 % I11i % iII111i + OoooooooOO . o0oOOo0O0Ooo
  if 78 - 78: o0oOOo0O0Ooo . iII111i + O0 / I1ii11iIi11i + I1ii11iIi11i + II111iiii
  if 96 - 96: iIii1I11I1II1 * II111iiii . iIii1I11I1II1
  if 13 - 13: Ii1I - OoOoOO00 . Ii1I
  if ( iIIiIi1111iiIii . elp and iIIiIi1111iiIii . elp . use_elp_node ) :
   return ( [ iIIiIi1111iiIii . elp . use_elp_node . address , None , None , None , None ,
 None ] )
   if 7 - 7: Ii1I - I11i / I1ii11iIi11i + iII111i
   if 47 - 47: I11i * IiII / oO0o - OoooooooOO . OoooooooOO / I11i
   if 73 - 73: Ii1I . IiII % IiII
   if 56 - 56: I1Ii111 + iII111i + iII111i
   if 99 - 99: o0oOOo0O0Ooo % I1ii11iIi11i / Oo0Ooo . O0 + OoO0O00 * OoOoOO00
  if ( iIIiIi1111iiIii . active_rloc_next_hop != None ) : iIIiIi1111iiIii = iIIiIi1111iiIii . active_rloc_next_hop
  if 48 - 48: iIii1I11I1II1 + O0 * I11i * i11iIiiIii . Ii1I / i1IIi
  if 48 - 48: i1IIi % iIii1I11I1II1 + I1IiiI - OoOoOO00 % I11i . I1Ii111
  if 66 - 66: I1Ii111 * i11iIiiIii + I1IiiI % II111iiii
  if 47 - 47: II111iiii % o0oOOo0O0Ooo
  iIIiIi1111iiIii . stats . increment ( len ( Oo00O0o0O ) )
  if 26 - 26: I1ii11iIi11i / I11i / Oo0Ooo / i1IIi + O0 * ooOoO0o
  if 53 - 53: IiII / II111iiii / oO0o % O0 / I1Ii111
  if 91 - 91: oO0o * OoOoOO00 + O0 % Oo0Ooo
  if 62 - 62: iIii1I11I1II1 - i11iIiiIii % iIii1I11I1II1 . ooOoO0o / OOooOOo * OoOoOO00
  II1II1i1 = None if ( iIIiIi1111iiIii . rloc . is_null ( ) ) else iIIiIi1111iiIii . rloc
  O0ooO0O00oo0 = iIIiIi1111iiIii . translated_port
  oo0OoooOo0 = self . action if ( II1II1i1 == None ) else None
  if 6 - 6: Ii1I
  if 96 - 96: I1IiiI
  if 30 - 30: oO0o . I1Ii111 * i11iIiiIii - II111iiii * I11i
  if 67 - 67: IiII
  if 87 - 87: I1Ii111 - iII111i * I11i
  o0oOoo00 = None
  if ( oOoOooO0OOOoo and oOoOooO0OOOoo . request_nonce_timeout ( ) == False ) :
   o0oOoo00 = oOoOooO0OOOoo . get_request_or_echo_nonce ( ipc_socket , II1II1i1 )
   if 74 - 74: Ii1I - OoOoOO00 + i11iIiiIii - II111iiii - i11iIiiIii . ooOoO0o
   if 83 - 83: I1Ii111 % ooOoO0o + OoooooooOO
   if 50 - 50: i11iIiiIii % I1IiiI * iII111i / Ii1I
   if 12 - 12: iII111i / OoO0O00 - II111iiii + Oo0Ooo
   if 78 - 78: i1IIi
  return ( [ II1II1i1 , O0ooO0O00oo0 , o0oOoo00 , oo0OoooOo0 , None , iIIiIi1111iiIii ] )
  if 25 - 25: Ii1I * II111iiii / OoOoOO00
  if 86 - 86: i1IIi + I1IiiI + I1Ii111 % II111iiii . IiII - iIii1I11I1II1
 def do_rloc_sets_match ( self , rloc_address_set ) :
  if ( len ( self . rloc_set ) != len ( rloc_address_set ) ) : return ( False )
  if 54 - 54: i11iIiiIii . Ii1I % I1IiiI . I1Ii111 . OoooooooOO
  if 49 - 49: OOooOOo % I11i - OOooOOo + Ii1I . I1ii11iIi11i + ooOoO0o
  if 15 - 15: i11iIiiIii
  if 85 - 85: I1Ii111 + iII111i - oO0o
  if 59 - 59: IiII . oO0o / i11iIiiIii . I1Ii111
  for oO0o0 in self . rloc_set :
   for iIIiIi1111iiIii in rloc_address_set :
    if ( iIIiIi1111iiIii . is_exact_match ( oO0o0 . rloc ) == False ) : continue
    iIIiIi1111iiIii = None
    break
    if 64 - 64: OoOoOO00
   if ( iIIiIi1111iiIii == rloc_address_set [ - 1 ] ) : return ( False )
   if 20 - 20: OoOoOO00 / O0 * OOooOOo % I11i + OoO0O00 + o0oOOo0O0Ooo
  return ( True )
  if 51 - 51: Ii1I - OoOoOO00 / i11iIiiIii + O0
  if 71 - 71: ooOoO0o
 def get_rloc ( self , rloc ) :
  for oO0o0 in self . rloc_set :
   IIi1iii = oO0o0 . rloc
   if ( rloc . is_exact_match ( IIi1iii ) ) : return ( oO0o0 )
   if 35 - 35: OoOoOO00
  return ( None )
  if 55 - 55: iII111i - o0oOOo0O0Ooo + IiII * II111iiii
  if 6 - 6: I1Ii111 / i1IIi / IiII . o0oOOo0O0Ooo
 def get_rloc_by_interface ( self , interface ) :
  for oO0o0 in self . rloc_set :
   if ( oO0o0 . interface == interface ) : return ( oO0o0 )
   if 69 - 69: ooOoO0o - OoOoOO00 . I1IiiI . I11i + OoOoOO00 / i11iIiiIii
  return ( None )
  if 20 - 20: OoO0O00 . OoooooooOO - ooOoO0o . I11i / Oo0Ooo
  if 89 - 89: iIii1I11I1II1 . ooOoO0o
 def add_db ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_db_for_lookups . add_cache ( self . eid , self )
  else :
   Iiii1II1 = lisp_db_for_lookups . lookup_cache ( self . group , True )
   if ( Iiii1II1 == None ) :
    Iiii1II1 = lisp_mapping ( self . group , self . group , [ ] )
    lisp_db_for_lookups . add_cache ( self . group , Iiii1II1 )
    if 82 - 82: OoOoOO00 - II111iiii . OoO0O00 * ooOoO0o
   Iiii1II1 . add_source_entry ( self )
   if 78 - 78: OoOoOO00 % oO0o
   if 39 - 39: iIii1I11I1II1
   if 72 - 72: II111iiii + I1Ii111 / Ii1I * iIii1I11I1II1
 def add_cache ( self , do_ipc = True ) :
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . add_cache ( self . eid , self )
   if ( lisp_program_hardware ) : lisp_program_vxlan_hardware ( self )
  else :
   IIII1 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( IIII1 == None ) :
    IIII1 = lisp_mapping ( self . group , self . group , [ ] )
    IIII1 . eid . copy_address ( self . group )
    IIII1 . group . copy_address ( self . group )
    lisp_map_cache . add_cache ( self . group , IIII1 )
    if 95 - 95: OoooooooOO + OOooOOo + II111iiii + IiII + OoO0O00
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( IIII1 . group )
   IIII1 . add_source_entry ( self )
   if 86 - 86: II111iiii / iII111i - I1ii11iIi11i
  if ( do_ipc ) : lisp_write_ipc_map_cache ( True , self )
  if 65 - 65: I1ii11iIi11i + OoOoOO00
  if 43 - 43: O0 + I11i % II111iiii
 def delete_cache ( self ) :
  self . delete_rlocs_from_rloc_probe_list ( )
  lisp_write_ipc_map_cache ( False , self )
  if 56 - 56: IiII + Oo0Ooo . IiII % iIii1I11I1II1 % ooOoO0o % ooOoO0o
  if ( self . group . is_null ( ) ) :
   lisp_map_cache . delete_cache ( self . eid )
   if ( lisp_program_hardware ) :
    O0OoO0 = self . eid . print_prefix_no_iid ( )
    os . system ( "ip route delete {}" . format ( O0OoO0 ) )
    if 51 - 51: I11i + i11iIiiIii / O0 % I1Ii111
  else :
   IIII1 = lisp_map_cache . lookup_cache ( self . group , True )
   if ( IIII1 == None ) : return
   if 8 - 8: oO0o . OoO0O00 / IiII - oO0o / OoOoOO00 - i1IIi
   iiiI1Ii = IIII1 . lookup_source_cache ( self . eid , True )
   if ( iiiI1Ii == None ) : return
   if 86 - 86: OoO0O00 % II111iiii
   IIII1 . source_cache . delete_cache ( self . eid )
   if ( IIII1 . source_cache . cache_size ( ) == 0 ) :
    lisp_map_cache . delete_cache ( self . group )
    if 16 - 16: II111iiii + OoooooooOO * o0oOOo0O0Ooo
    if 48 - 48: O0
    if 99 - 99: II111iiii * oO0o / I1ii11iIi11i - i1IIi
    if 84 - 84: i11iIiiIii . OoooooooOO
 def add_source_entry ( self , source_mc ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_mc . eid , source_mc )
  if 69 - 69: I1Ii111 * II111iiii % I1Ii111 * i11iIiiIii . ooOoO0o / Oo0Ooo
  if 5 - 5: Ii1I
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 19 - 19: oO0o
  if 61 - 61: OoOoOO00 + iIii1I11I1II1 / I1ii11iIi11i - i1IIi
 def dynamic_eid_configured ( self ) :
  return ( self . dynamic_eids != None )
  if 11 - 11: oO0o * o0oOOo0O0Ooo . I1IiiI
  if 12 - 12: I1IiiI % OoO0O00 / I1Ii111 / O0 % o0oOOo0O0Ooo
 def star_secondary_iid ( self , prefix ) :
  if ( self . secondary_iid == None ) : return ( prefix )
  i1I1iI = "," + str ( self . secondary_iid )
  return ( prefix . replace ( i1I1iI , i1I1iI + "*" ) )
  if 1 - 1: OoOoOO00 / I11i
  if 43 - 43: o0oOOo0O0Ooo - i1IIi / Ii1I . OoOoOO00 + i11iIiiIii
 def increment_decap_stats ( self , packet ) :
  O0ooO0O00oo0 = packet . udp_dport
  if ( O0ooO0O00oo0 == LISP_DATA_PORT ) :
   iIIiIi1111iiIii = self . get_rloc ( packet . outer_dest )
  else :
   if 69 - 69: i11iIiiIii - iIii1I11I1II1
   if 40 - 40: I1IiiI / oO0o + ooOoO0o
   if 100 - 100: OoOoOO00 % iII111i * ooOoO0o . O0
   if 37 - 37: I1ii11iIi11i
   for iIIiIi1111iiIii in self . rloc_set :
    if ( iIIiIi1111iiIii . translated_port != 0 ) : break
    if 24 - 24: O0 . I1Ii111 * i11iIiiIii
    if 84 - 84: ooOoO0o / I1ii11iIi11i - o0oOOo0O0Ooo . OoooooooOO * iIii1I11I1II1
  if ( iIIiIi1111iiIii != None ) : iIIiIi1111iiIii . stats . increment ( len ( packet . packet ) )
  self . stats . increment ( len ( packet . packet ) )
  if 16 - 16: I11i % O0
  if 56 - 56: Ii1I * OoOoOO00 . i1IIi
 def rtrs_in_rloc_set ( self ) :
  for iIIiIi1111iiIii in self . rloc_set :
   if ( iIIiIi1111iiIii . is_rtr ( ) ) : return ( True )
   if 15 - 15: I1Ii111
  return ( False )
  if 64 - 64: OOooOOo * Oo0Ooo
  if 96 - 96: Oo0Ooo / I1ii11iIi11i * iIii1I11I1II1 / iII111i
 def add_recent_source ( self , source ) :
  self . recent_sources [ source . print_address ( ) ] = lisp_get_timestamp ( )
  if 18 - 18: I1Ii111
  if 29 - 29: i1IIi - I1IiiI / i1IIi
 def find_rtr_rloc ( self ) :
  if 64 - 64: IiII
  if 69 - 69: OOooOOo . I1IiiI
  if 11 - 11: I1Ii111 * I1IiiI - I1Ii111 / iII111i
  if 22 - 22: iII111i % I11i % O0 - I11i
  if 71 - 71: I1Ii111 / II111iiii - OoooooooOO % i1IIi + OoOoOO00 % OoooooooOO
  if 52 - 52: Ii1I . OoOoOO00 / o0oOOo0O0Ooo / iII111i
  if 83 - 83: OoO0O00 - Oo0Ooo + I1Ii111 . I1IiiI
  for iIIiIi1111iiIii in self . rloc_set :
   if ( iIIiIi1111iiIii . is_rtr ( ) and iIIiIi1111iiIii . up_state ( ) ) :
    if ( iIIiIi1111iiIii . stats . packet_count <= 4 ) : return ( iIIiIi1111iiIii )
    if 78 - 78: I11i / ooOoO0o . OoOoOO00 * i1IIi
    if 15 - 15: i1IIi . II111iiii * OoOoOO00 / Oo0Ooo
  return ( None )
  if 99 - 99: iII111i - o0oOOo0O0Ooo / O0
  if 97 - 97: iIii1I11I1II1 * I1Ii111
  if 39 - 39: I1Ii111 . II111iiii
  if 94 - 94: OoO0O00 - OoO0O00 + iIii1I11I1II1 + O0 * oO0o
class lisp_dynamic_eid ( object ) :
 def __init__ ( self ) :
  self . dynamic_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . uptime = lisp_get_timestamp ( )
  self . interface = None
  self . last_packet = None
  self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
  if 9 - 9: Ii1I * Oo0Ooo / oO0o / Ii1I
  if 34 - 34: I1IiiI
 def get_timeout ( self , interface ) :
  try :
   o0oooooOoOO = lisp_myinterfaces [ interface ]
   self . timeout = o0oooooOoOO . dynamic_eid_timeout
  except :
   self . timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
   if 14 - 14: I1Ii111
   if 23 - 23: IiII * Ii1I - Ii1I . oO0o - IiII
   if 56 - 56: i1IIi + i11iIiiIii % OoO0O00 - ooOoO0o / OoO0O00
   if 23 - 23: IiII - OoO0O00 / I1ii11iIi11i * oO0o
class lisp_group_mapping ( object ) :
 def __init__ ( self , group_name , ms_name , group_prefix , sources , rle_addr ) :
  self . group_name = group_name
  self . group_prefix = group_prefix
  self . use_ms_name = ms_name
  self . sources = sources
  self . rle_address = rle_addr
  if 77 - 77: O0 * oO0o . I1ii11iIi11i - i1IIi
  if 87 - 87: i1IIi % I1Ii111
 def add_group ( self ) :
  lisp_group_mapping_list [ self . group_name ] = self
  if 37 - 37: I11i
  if 61 - 61: OoooooooOO % iIii1I11I1II1 % O0 % I1Ii111 / Oo0Ooo . I1IiiI
  if 20 - 20: ooOoO0o - I1Ii111
  if 97 - 97: O0
  if 56 - 56: Ii1I * I1IiiI * ooOoO0o
  if 39 - 39: iII111i % Ii1I * iIii1I11I1II1 - Ii1I - I1Ii111
  if 60 - 60: i11iIiiIii + i11iIiiIii - OoooooooOO + OoooooooOO
  if 5 - 5: o0oOOo0O0Ooo
  if 78 - 78: OOooOOo * O0 * II111iiii % OoOoOO00
  if 12 - 12: Oo0Ooo . o0oOOo0O0Ooo - i1IIi - oO0o % IiII . I11i
def lisp_is_group_more_specific ( group_str , group_mapping ) :
 IiII1i11i1I = group_mapping . group_prefix
 i1I1IIIiII = lisp_address ( LISP_AFI_NONE , group_str , 0 , IiII1i11i1I . instance_id )
 if ( i1I1IIIiII . afi != IiII1i11i1I . afi ) : return ( - 1 )
 if 64 - 64: O0 - iII111i
 if ( i1I1IIIiII . is_more_specific ( IiII1i11i1I ) ) : return ( IiII1i11i1I . mask_len )
 return ( - 1 )
 if 82 - 82: O0
 if 37 - 37: I1Ii111
 if 98 - 98: iII111i - OoOoOO00 / I1Ii111 . OOooOOo - OOooOOo - ooOoO0o
 if 84 - 84: OOooOOo * ooOoO0o / O0
 if 96 - 96: I11i . I11i % II111iiii
 if 14 - 14: iII111i / OoooooooOO
 if 8 - 8: OOooOOo + I1IiiI - Oo0Ooo + i1IIi . Ii1I . I1Ii111
def lisp_lookup_group ( group ) :
 oO0oo00OO = None
 for Ii1ii in list ( lisp_group_mapping_list . values ( ) ) :
  I1ioOo = lisp_is_group_more_specific ( group , Ii1ii )
  if ( I1ioOo == - 1 ) : continue
  if ( oO0oo00OO == None or I1ioOo > oO0oo00OO . group_prefix . mask_len ) : oO0oo00OO = Ii1ii
  if 50 - 50: OOooOOo % I1ii11iIi11i / ooOoO0o * ooOoO0o . OoO0O00 + o0oOOo0O0Ooo
 return ( oO0oo00OO )
 if 95 - 95: i1IIi % OoOoOO00 . OoooooooOO + I1IiiI * Oo0Ooo
 if 27 - 27: iIii1I11I1II1 / iII111i
lisp_site_flags = {
 "P" : "ETR is {}Requesting Map-Server to Proxy Map-Reply" ,
 "S" : "ETR is {}LISP-SEC capable" ,
 "I" : "xTR-ID and site-ID are {}included in Map-Register" ,
 "T" : "Use Map-Register TTL field to timeout registration is {}set" ,
 "R" : "Merging registrations are {}requested" ,
 "M" : "ETR is {}a LISP Mobile-Node" ,
 "N" : "ETR is {}requesting Map-Notify messages from Map-Server"
 }
if 11 - 11: I1ii11iIi11i - iIii1I11I1II1
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
  if 15 - 15: o0oOOo0O0Ooo + OoooooooOO
  if 68 - 68: ooOoO0o / I1Ii111 * OoO0O00 + ooOoO0o / iIii1I11I1II1 . iII111i
  if 91 - 91: OoO0O00
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
  if 8 - 8: oO0o
  if 96 - 96: IiII
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 37 - 37: Ii1I % i11iIiiIii + iIii1I11I1II1 % Oo0Ooo - iIii1I11I1II1
  if 26 - 26: o0oOOo0O0Ooo . i1IIi
 def print_flags ( self , html ) :
  if ( html == False ) :
   i11IiIIi11I = "{}-{}-{}-{}-{}-{}-{}" . format ( "P" if self . proxy_reply_requested else "p" ,
   # I1Ii111 % OOooOOo * i1IIi - iIii1I11I1II1
 "S" if self . lisp_sec_present else "s" ,
 "I" if self . xtr_id_present else "i" ,
 "T" if self . use_register_ttl_requested else "t" ,
 "R" if self . merge_register_requested else "r" ,
 "M" if self . mobile_node_requested else "m" ,
 "N" if self . map_notify_requested else "n" )
  else :
   iIi1 = self . print_flags ( False )
   iIi1 = iIi1 . split ( "-" )
   i11IiIIi11I = ""
   for oO0o0O0 in iIi1 :
    IIi1I1 = lisp_site_flags [ oO0o0O0 . upper ( ) ]
    IIi1I1 = IIi1I1 . format ( "" if oO0o0O0 . isupper ( ) else "not " )
    i11IiIIi11I += lisp_span ( oO0o0O0 , IIi1I1 )
    if ( oO0o0O0 . lower ( ) != "n" ) : i11IiIIi11I += "-"
    if 72 - 72: OoOoOO00 . OOooOOo % I1Ii111
    if 99 - 99: OoOoOO00 % OoO0O00
  return ( i11IiIIi11I )
  if 79 - 79: Oo0Ooo * oO0o % I1ii11iIi11i . OoooooooOO
  if 85 - 85: oO0o / ooOoO0o % o0oOOo0O0Ooo
 def copy_state_to_parent ( self , child ) :
  self . xtr_id = child . xtr_id
  self . site_id = child . site_id
  self . first_registered = child . first_registered
  self . last_registered = child . last_registered
  self . last_registerer = child . last_registerer
  self . register_ttl = child . register_ttl
  if ( self . registered == False ) :
   self . first_registered = lisp_get_timestamp ( )
   if 34 - 34: Oo0Ooo / II111iiii
  self . auth_sha1_or_sha2 = child . auth_sha1_or_sha2
  self . registered = child . registered
  self . proxy_reply_requested = child . proxy_reply_requested
  self . lisp_sec_present = child . lisp_sec_present
  self . xtr_id_present = child . xtr_id_present
  self . use_register_ttl_requested = child . use_register_ttl_requested
  self . merge_register_requested = child . merge_register_requested
  self . mobile_node_requested = child . mobile_node_requested
  self . map_notify_requested = child . map_notify_requested
  if 82 - 82: i11iIiiIii * OoOoOO00 . i1IIi + IiII * ooOoO0o
  if 75 - 75: iIii1I11I1II1 / IiII / II111iiii . I11i
 def build_sort_key ( self ) :
  IIIOo0OO00o0oo = lisp_cache ( )
  I1iIIIiI1iI11 , I1IIiiI1II = IIIOo0OO00o0oo . build_key ( self . eid )
  iI11IiiIiiI = ""
  if ( self . group . is_null ( ) == False ) :
   oOoOooO00oooo , iI11IiiIiiI = IIIOo0OO00o0oo . build_key ( self . group )
   iI11IiiIiiI = "-" + iI11IiiIiiI [ 0 : 12 ] + "-" + str ( oOoOooO00oooo ) + "-" + iI11IiiIiiI [ 12 : : ]
   if 7 - 7: I1IiiI + OoO0O00 * iIii1I11I1II1 . iIii1I11I1II1
  I1IIiiI1II = I1IIiiI1II [ 0 : 12 ] + "-" + str ( I1iIIIiI1iI11 ) + "-" + I1IIiiI1II [ 12 : : ] + iI11IiiIiiI
  del ( IIIOo0OO00o0oo )
  return ( I1IIiiI1II )
  if 39 - 39: o0oOOo0O0Ooo
  if 29 - 29: Oo0Ooo . Oo0Ooo * OoO0O00 % Ii1I - ooOoO0o
 def merge_in_site_eid ( self , child ) :
  OoOo0o000O = False
  if ( self . group . is_null ( ) ) :
   self . merge_rlocs_in_site_eid ( )
  else :
   OoOo0o000O = self . merge_rles_in_site_eid ( )
   if 28 - 28: I1IiiI . i1IIi + I1Ii111 + OoOoOO00 % O0
   if 3 - 3: I1Ii111 + oO0o . I1IiiI / OoOoOO00
   if 25 - 25: iIii1I11I1II1 * OoooooooOO
   if 33 - 33: OoooooooOO - I1Ii111
   if 22 - 22: Oo0Ooo
   if 1 - 1: iIii1I11I1II1 + oO0o % i11iIiiIii
  if ( child != None ) :
   self . copy_state_to_parent ( child )
   self . map_registers_received += 1
   if 25 - 25: iII111i + i11iIiiIii
  return ( OoOo0o000O )
  if 10 - 10: OoO0O00 - oO0o + Oo0Ooo / i11iIiiIii + Ii1I + I11i
  if 59 - 59: ooOoO0o * II111iiii
 def copy_rloc_records ( self ) :
  ooOoOOOoO = [ ]
  for oO0o0 in self . registered_rlocs :
   ooOoOOOoO . append ( copy . deepcopy ( oO0o0 ) )
   if 14 - 14: OoO0O00 * I1IiiI
  return ( ooOoOOOoO )
  if 78 - 78: I1IiiI / iII111i - ooOoO0o - i11iIiiIii
  if 39 - 39: i11iIiiIii / oO0o
 def merge_rlocs_in_site_eid ( self ) :
  self . registered_rlocs = [ ]
  for Ooo000oOOooO00 in list ( self . individual_registrations . values ( ) ) :
   if ( self . site_id != Ooo000oOOooO00 . site_id ) : continue
   if ( Ooo000oOOooO00 . registered == False ) : continue
   self . registered_rlocs += Ooo000oOOooO00 . copy_rloc_records ( )
   if 71 - 71: I1Ii111 * iIii1I11I1II1 - I1Ii111
   if 87 - 87: I1IiiI / Ii1I
   if 54 - 54: OoooooooOO / Ii1I
   if 26 - 26: o0oOOo0O0Ooo + OoO0O00
   if 59 - 59: Ii1I * IiII
   if 64 - 64: ooOoO0o . Oo0Ooo - OoOoOO00
   if 66 - 66: OoOoOO00
   if 83 - 83: OOooOOo . IiII
  ooOoOOOoO = [ ]
  for oO0o0 in self . registered_rlocs :
   if ( oO0o0 . rloc . is_null ( ) or len ( ooOoOOOoO ) == 0 ) :
    ooOoOOOoO . append ( oO0o0 )
    continue
    if 98 - 98: i11iIiiIii
   for OoOoo0Ooo0O0o in ooOoOOOoO :
    if ( OoOoo0Ooo0O0o . rloc . is_null ( ) ) : continue
    if ( oO0o0 . rloc . is_exact_match ( OoOoo0Ooo0O0o . rloc ) ) :
     if ( oO0o0 . rloc_name == OoOoo0Ooo0O0o . rloc_name ) : break
     if 48 - 48: oO0o + i11iIiiIii % i11iIiiIii % i11iIiiIii % OOooOOo * I11i
     if 63 - 63: OoO0O00 % OoO0O00 % OOooOOo - i11iIiiIii + Oo0Ooo + iIii1I11I1II1
   if ( OoOoo0Ooo0O0o == ooOoOOOoO [ - 1 ] ) : ooOoOOOoO . append ( oO0o0 )
   if 44 - 44: OoO0O00
  self . registered_rlocs = ooOoOOOoO
  if 59 - 59: iII111i
  if 7 - 7: o0oOOo0O0Ooo * OoooooooOO - Ii1I * II111iiii % I1Ii111
  if 82 - 82: OoOoOO00 - OoOoOO00 + iIii1I11I1II1 + o0oOOo0O0Ooo + IiII - o0oOOo0O0Ooo
  if 65 - 65: I1Ii111 + OOooOOo
  if ( len ( self . registered_rlocs ) == 0 ) : self . registered = False
  return
  if 97 - 97: oO0o % OoOoOO00 * oO0o % II111iiii + iIii1I11I1II1
  if 11 - 11: ooOoO0o . o0oOOo0O0Ooo
 def merge_rles_in_site_eid ( self ) :
  if 94 - 94: ooOoO0o . oO0o * OoooooooOO % oO0o
  if 77 - 77: ooOoO0o % I1IiiI
  if 26 - 26: o0oOOo0O0Ooo
  if 72 - 72: I1IiiI
  oOOOo0o0oooo0 = { }
  for oO0o0 in self . registered_rlocs :
   if ( oO0o0 . rle == None ) : continue
   for Iiiiii in oO0o0 . rle . rle_nodes :
    if ( Iiiiii . rloc . rloc_name == None ) : continue
    iI1ii11Ii = Iiiiii . rloc . rloc . print_address_no_iid ( ) + Iiiiii . rloc . rloc_name
    if 32 - 32: OoOoOO00 - iII111i % oO0o / I1ii11iIi11i - o0oOOo0O0Ooo
    oOOOo0o0oooo0 [ iI1ii11Ii ] = Iiiiii . rloc . rloc
    if 52 - 52: Ii1I / OoooooooOO % i11iIiiIii + iII111i
   break
   if 59 - 59: Ii1I / o0oOOo0O0Ooo / oO0o + iII111i * I1ii11iIi11i - o0oOOo0O0Ooo
   if 70 - 70: O0 / I1ii11iIi11i + ooOoO0o . OoO0O00 - OoO0O00 / i11iIiiIii
   if 1 - 1: iIii1I11I1II1 % I1ii11iIi11i
   if 49 - 49: iII111i + o0oOOo0O0Ooo % I1ii11iIi11i . O0 % OoooooooOO . o0oOOo0O0Ooo
   if 3 - 3: i11iIiiIii - i1IIi * o0oOOo0O0Ooo / OoOoOO00 % Oo0Ooo
  self . merge_rlocs_in_site_eid ( )
  if 65 - 65: OoooooooOO + iII111i - i11iIiiIii - IiII + oO0o
  if 67 - 67: i1IIi * I1Ii111 * O0
  if 16 - 16: OoO0O00 + iII111i + i1IIi + I1ii11iIi11i - I1IiiI
  if 88 - 88: oO0o % iII111i + I1ii11iIi11i - II111iiii . I11i
  if 18 - 18: I1ii11iIi11i - i1IIi - IiII * II111iiii % I1Ii111 . II111iiii
  if 80 - 80: oO0o + OoO0O00 + o0oOOo0O0Ooo . OoOoOO00
  if 75 - 75: i11iIiiIii
  if 58 - 58: iII111i
  iIi111I1iiii = [ ]
  for oO0o0 in self . registered_rlocs :
   if ( self . registered_rlocs . index ( oO0o0 ) == 0 ) :
    iIi111I1iiii . append ( oO0o0 )
    continue
    if 66 - 66: O0 % OoOoOO00 + IiII % I1Ii111
   if ( oO0o0 . rle == None ) : iIi111I1iiii . append ( oO0o0 )
   if 94 - 94: OoOoOO00 / OoooooooOO % Ii1I * i11iIiiIii
  self . registered_rlocs = iIi111I1iiii
  if 95 - 95: iIii1I11I1II1 % OOooOOo % O0
  if 93 - 93: I1ii11iIi11i
  if 61 - 61: o0oOOo0O0Ooo * ooOoO0o
  if 82 - 82: O0 * O0 % I1IiiI / o0oOOo0O0Ooo
  if 46 - 46: IiII . O0 . I11i % I1ii11iIi11i * oO0o - oO0o
  if 92 - 92: I1IiiI - I1IiiI
  if 28 - 28: oO0o * iII111i + IiII
  IiI = lisp_rle ( "" )
  oOOO = { }
  I11I = None
  for Ooo000oOOooO00 in list ( self . individual_registrations . values ( ) ) :
   if ( Ooo000oOOooO00 . registered == False ) : continue
   O00Oo0 = Ooo000oOOooO00 . registered_rlocs [ 0 ] . rle
   if ( O00Oo0 == None ) : continue
   if 83 - 83: Ii1I * IiII + Ii1I / OoO0O00 - II111iiii
   I11I = Ooo000oOOooO00 . registered_rlocs [ 0 ] . rloc_name
   if ( I11I == None ) : I11I = ""
   for o0OOOii in O00Oo0 . rle_nodes :
    iI1ii11Ii = o0OOOii . rloc . rloc . print_address_no_iid ( ) + I11I
    if ( iI1ii11Ii in oOOO ) : break
    if 42 - 42: I11i - I1Ii111 / OoOoOO00
    Iiiiii = lisp_rle_node ( )
    Iiiiii . rloc . rloc . copy_address ( o0OOOii . rloc . rloc )
    Iiiiii . level = o0OOOii . level
    Iiiiii . rloc . rloc_name = I11I
    IiI . rle_nodes . append ( Iiiiii )
    oOOO [ iI1ii11Ii ] = o0OOOii . rloc . rloc
    if 45 - 45: o0oOOo0O0Ooo
    if 97 - 97: iIii1I11I1II1 + O0
    if 41 - 41: OoOoOO00 - II111iiii
    if 46 - 46: OOooOOo
    if 73 - 73: iII111i - IiII + II111iiii
    if 58 - 58: Oo0Ooo % I1IiiI
  if ( len ( IiI . rle_nodes ) == 0 ) : IiI = None
  if ( len ( self . registered_rlocs ) != 0 ) :
   self . registered_rlocs [ 0 ] . rle = IiI
   if ( I11I ) : self . registered_rlocs [ 0 ] . rloc_name = None
   if 78 - 78: iII111i / iIii1I11I1II1 * IiII . ooOoO0o / I1Ii111 % I11i
   if 14 - 14: II111iiii % iIii1I11I1II1 - I1IiiI % i11iIiiIii . OOooOOo * I1ii11iIi11i
   if 12 - 12: I1ii11iIi11i % I1ii11iIi11i . OoO0O00 . OoOoOO00
   if 73 - 73: I1ii11iIi11i * i1IIi * Oo0Ooo / O0
   if 1 - 1: iII111i * OOooOOo + II111iiii / Ii1I . I1ii11iIi11i
  if ( list ( oOOOo0o0oooo0 . keys ( ) ) == list ( oOOO . keys ( ) ) ) : return ( False )
  if 61 - 61: oO0o % OoOoOO00 % ooOoO0o . I1Ii111 / OoO0O00
  lprint ( "{} {} from {} to {}" . format ( green ( self . print_eid_tuple ( ) , False ) , bold ( "RLE change" , False ) ,
  # IiII . iIii1I11I1II1
 list ( oOOOo0o0oooo0 . keys ( ) ) , list ( oOOO . keys ( ) ) ) )
  if 94 - 94: I1ii11iIi11i + I1ii11iIi11i . iIii1I11I1II1 % i11iIiiIii - iII111i
  return ( True )
  if 41 - 41: iII111i / o0oOOo0O0Ooo / I1IiiI * OOooOOo
  if 94 - 94: o0oOOo0O0Ooo * I11i
 def add_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . add_cache ( self . eid , self )
  else :
   o0o0Oo0O00OO = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( o0o0Oo0O00OO == None ) :
    o0o0Oo0O00OO = lisp_site_eid ( self . site )
    o0o0Oo0O00OO . eid . copy_address ( self . group )
    o0o0Oo0O00OO . group . copy_address ( self . group )
    lisp_sites_by_eid . add_cache ( self . group , o0o0Oo0O00OO )
    if 20 - 20: IiII
    if 37 - 37: I1ii11iIi11i / I1IiiI + I1Ii111 % i1IIi / i1IIi
    if 91 - 91: I11i
    if 94 - 94: OoO0O00
    if 19 - 19: I11i * i11iIiiIii - OoO0O00 / ooOoO0o * I1Ii111 + OoO0O00
    o0o0Oo0O00OO . parent_for_more_specifics = self . parent_for_more_specifics
    if 30 - 30: Ii1I / iII111i * Ii1I
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( o0o0Oo0O00OO . group )
   o0o0Oo0O00OO . add_source_entry ( self )
   if 11 - 11: OoOoOO00 - OoOoOO00 % oO0o
   if 3 - 3: I1IiiI - OoooooooOO % iIii1I11I1II1 + I1Ii111 + OoOoOO00
   if 71 - 71: i1IIi % O0 % ooOoO0o
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_sites_by_eid . delete_cache ( self . eid )
  else :
   o0o0Oo0O00OO = lisp_sites_by_eid . lookup_cache ( self . group , True )
   if ( o0o0Oo0O00OO == None ) : return
   if 24 - 24: O0
   Ooo000oOOooO00 = o0o0Oo0O00OO . lookup_source_cache ( self . eid , True )
   if ( Ooo000oOOooO00 == None ) : return
   if 88 - 88: OoooooooOO / Oo0Ooo / oO0o
   if ( o0o0Oo0O00OO . source_cache == None ) : return
   if 99 - 99: I1Ii111 % OoOoOO00 % IiII - Ii1I
   o0o0Oo0O00OO . source_cache . delete_cache ( self . eid )
   if ( o0o0Oo0O00OO . source_cache . cache_size ( ) == 0 ) :
    lisp_sites_by_eid . delete_cache ( self . group )
    if 79 - 79: ooOoO0o + Oo0Ooo
    if 80 - 80: OoOoOO00 % OoO0O00 . OoO0O00 * OoO0O00 * O0
    if 18 - 18: II111iiii . o0oOOo0O0Ooo + OoO0O00
    if 69 - 69: OoO0O00 . ooOoO0o * ooOoO0o * iIii1I11I1II1
 def add_source_entry ( self , source_se ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_se . eid , source_se )
  if 8 - 8: iII111i . oO0o . OOooOOo + iII111i . Ii1I
  if 46 - 46: OoO0O00
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 21 - 21: iIii1I11I1II1 - iII111i
  if 15 - 15: O0 + iII111i + i11iIiiIii
 def is_star_g ( self ) :
  if ( self . group . is_null ( ) ) : return ( False )
  return ( self . eid . is_exact_match ( self . group ) )
  if 31 - 31: iIii1I11I1II1 * iIii1I11I1II1 . I11i
  if 52 - 52: i11iIiiIii / oO0o / IiII
 def eid_record_matches ( self , eid_record ) :
  if ( self . eid . is_exact_match ( eid_record . eid ) == False ) : return ( False )
  if ( eid_record . group . is_null ( ) ) : return ( True )
  return ( eid_record . group . is_exact_match ( self . group ) )
  if 84 - 84: I11i . oO0o + ooOoO0o
  if 75 - 75: I1Ii111
 def inherit_from_ams_parent ( self ) :
  ooOOoo0o = self . parent_for_more_specifics
  if ( ooOOoo0o == None ) : return
  self . force_proxy_reply = ooOOoo0o . force_proxy_reply
  self . force_nat_proxy_reply = ooOOoo0o . force_nat_proxy_reply
  self . force_ttl = ooOOoo0o . force_ttl
  self . pitr_proxy_reply_drop = ooOOoo0o . pitr_proxy_reply_drop
  self . proxy_reply_action = ooOOoo0o . proxy_reply_action
  self . echo_nonce_capable = ooOOoo0o . echo_nonce_capable
  self . policy = ooOOoo0o . policy
  self . require_signature = ooOOoo0o . require_signature
  self . encrypt_json = ooOOoo0o . encrypt_json
  if 97 - 97: ooOoO0o % Oo0Ooo . o0oOOo0O0Ooo
  if 22 - 22: O0 % I11i + OoO0O00 - iII111i + I1IiiI . O0
 def rtrs_in_rloc_set ( self ) :
  for oO0o0 in self . registered_rlocs :
   if ( oO0o0 . is_rtr ( ) ) : return ( True )
   if 73 - 73: ooOoO0o + O0 - I11i . I1IiiI + OOooOOo
  return ( False )
  if 36 - 36: I11i % OoO0O00 * OoOoOO00 - I1Ii111
  if 16 - 16: ooOoO0o % OOooOOo . OoO0O00 % II111iiii . iIii1I11I1II1
 def is_rtr_in_rloc_set ( self , rtr_rloc ) :
  for oO0o0 in self . registered_rlocs :
   if ( oO0o0 . rloc . is_exact_match ( rtr_rloc ) == False ) : continue
   if ( oO0o0 . is_rtr ( ) ) : return ( True )
   if 21 - 21: oO0o + II111iiii / OoOoOO00 * I11i
  return ( False )
  if 90 - 90: OoOoOO00 % OoOoOO00 + I11i
  if 70 - 70: I1IiiI . ooOoO0o / I11i / OoO0O00
 def is_rloc_in_rloc_set ( self , rloc ) :
  for oO0o0 in self . registered_rlocs :
   if ( oO0o0 . rle ) :
    for IiI in oO0o0 . rle . rle_nodes :
     if ( IiI . rloc . rloc . is_exact_match ( rloc ) ) : return ( True )
     if 40 - 40: oO0o % iIii1I11I1II1 * iIii1I11I1II1 / Oo0Ooo * OoO0O00
     if 61 - 61: OOooOOo
   if ( oO0o0 . rloc . is_exact_match ( rloc ) ) : return ( True )
   if 80 - 80: I1ii11iIi11i
  return ( False )
  if 6 - 6: I1ii11iIi11i + OOooOOo % ooOoO0o
  if 65 - 65: iIii1I11I1II1 % i1IIi / I1IiiI / oO0o % ooOoO0o / I11i
 def do_rloc_sets_match ( self , prev_rloc_set ) :
  if ( len ( self . registered_rlocs ) != len ( prev_rloc_set ) ) : return ( False )
  if 2 - 2: I1ii11iIi11i
  for oO0o0 in prev_rloc_set :
   I1IIIIiIii = oO0o0 . rloc
   if ( self . is_rloc_in_rloc_set ( I1IIIIiIii ) == False ) : return ( False )
   if 90 - 90: II111iiii * I1Ii111 . ooOoO0o - I1ii11iIi11i % I11i * o0oOOo0O0Ooo
  return ( True )
  if 85 - 85: iIii1I11I1II1
  if 76 - 76: i11iIiiIii % I1IiiI / I11i
  if 42 - 42: o0oOOo0O0Ooo . I1IiiI + I11i . OoOoOO00 - O0 / Ii1I
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
   if 66 - 66: IiII + OoOoOO00 + I1IiiI + i1IIi + OoooooooOO % I1IiiI
  self . last_used = 0
  self . last_reply = 0
  self . last_nonce = 0
  self . map_requests_sent = 0
  self . neg_map_replies_received = 0
  self . total_rtt = 0
  self . translated_port = 0
  if 80 - 80: iII111i / O0 % OoooooooOO / Oo0Ooo
  if 75 - 75: ooOoO0o
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 72 - 72: oO0o . OoooooooOO % ooOoO0o % OoO0O00 * oO0o * OoO0O00
  try :
   OooO0O0Ooo = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   i1111 = OooO0O0Ooo [ 2 ]
  except :
   return
   if 100 - 100: I1IiiI
   if 68 - 68: oO0o
   if 95 - 95: I1Ii111 % II111iiii + oO0o
   if 66 - 66: OOooOOo * i1IIi * o0oOOo0O0Ooo % OoOoOO00 % OoooooooOO * OoooooooOO
   if 51 - 51: II111iiii . OoOoOO00 / O0
   if 39 - 39: IiII . O0
  if ( len ( i1111 ) <= self . a_record_index ) :
   self . delete_mr ( )
   return
   if 4 - 4: I1Ii111
   if 15 - 15: I11i % I11i / iIii1I11I1II1 - i11iIiiIii / i1IIi
  iI1ii11Ii = i1111 [ self . a_record_index ]
  if ( iI1ii11Ii != self . map_resolver . print_address_no_iid ( ) ) :
   self . delete_mr ( )
   self . map_resolver . store_address ( iI1ii11Ii )
   self . insert_mr ( )
   if 9 - 9: OoooooooOO
   if 71 - 71: Ii1I
   if 59 - 59: i1IIi * ooOoO0o . iIii1I11I1II1
   if 87 - 87: ooOoO0o % I1ii11iIi11i . I1IiiI
   if 42 - 42: iII111i % i11iIiiIii % o0oOOo0O0Ooo . O0 % iII111i
   if 72 - 72: Oo0Ooo . Oo0Ooo . IiII . Oo0Ooo
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 80 - 80: I1Ii111 + IiII + O0 - I1Ii111 . iIii1I11I1II1
  for iI1ii11Ii in i1111 [ 1 : : ] :
   I1II1I1I = lisp_address ( LISP_AFI_NONE , iI1ii11Ii , 0 , 0 )
   II1iI1iII11 = lisp_get_map_resolver ( I1II1I1I , None )
   if ( II1iI1iII11 != None and II1iI1iII11 . a_record_index == i1111 . index ( iI1ii11Ii ) ) :
    continue
    if 53 - 53: OoO0O00 / i11iIiiIii * I1Ii111
   II1iI1iII11 = lisp_mr ( iI1ii11Ii , None , None )
   II1iI1iII11 . a_record_index = i1111 . index ( iI1ii11Ii )
   II1iI1iII11 . dns_name = self . dns_name
   II1iI1iII11 . last_dns_resolve = lisp_get_timestamp ( )
   if 62 - 62: oO0o / Oo0Ooo / IiII + I11i * ooOoO0o
   if 84 - 84: ooOoO0o + OoOoOO00 * I1ii11iIi11i % OoooooooOO . O0
   if 27 - 27: OoO0O00 * OoooooooOO - II111iiii / o0oOOo0O0Ooo
   if 76 - 76: I11i % I1Ii111 % iII111i + IiII * iII111i + OoOoOO00
   if 83 - 83: OOooOOo . ooOoO0o / IiII
  O0O0OOOo0 = [ ]
  for II1iI1iII11 in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( self . dns_name != II1iI1iII11 . dns_name ) : continue
   I1II1I1I = II1iI1iII11 . map_resolver . print_address_no_iid ( )
   if ( I1II1I1I in i1111 ) : continue
   O0O0OOOo0 . append ( II1iI1iII11 )
   if 73 - 73: O0 - I1IiiI + I1Ii111 . OoOoOO00 . IiII - OOooOOo
  for II1iI1iII11 in O0O0OOOo0 : II1iI1iII11 . delete_mr ( )
  if 13 - 13: i11iIiiIii
  if 42 - 42: Oo0Ooo - I11i . OOooOOo + OoO0O00
 def insert_mr ( self ) :
  I1IIiiI1II = self . mr_name + self . map_resolver . print_address ( )
  lisp_map_resolvers_list [ I1IIiiI1II ] = self
  if 10 - 10: Oo0Ooo * OoooooooOO * OOooOOo
  if 50 - 50: ooOoO0o + oO0o
 def delete_mr ( self ) :
  I1IIiiI1II = self . mr_name + self . map_resolver . print_address ( )
  if ( I1IIiiI1II not in lisp_map_resolvers_list ) : return
  lisp_map_resolvers_list . pop ( I1IIiiI1II )
  if 74 - 74: Ii1I + OOooOOo - I11i * iIii1I11I1II1 - I1Ii111 % i11iIiiIii
  if 32 - 32: Oo0Ooo * i1IIi . iII111i . iII111i
  if 77 - 77: OOooOOo
class lisp_ddt_root ( object ) :
 def __init__ ( self ) :
  self . root_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . public_key = ""
  self . priority = 0
  self . weight = 0
  if 74 - 74: O0
  if 86 - 86: OoOoOO00
  if 4 - 4: OoooooooOO * OoO0O00
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
  if 93 - 93: OoO0O00 - I1Ii111 - OoO0O00
  if 1 - 1: o0oOOo0O0Ooo . oO0o * i11iIiiIii * IiII - OoO0O00 - OoooooooOO
 def print_referral ( self , eid_indent , referral_indent ) :
  Ii1I1i = lisp_print_elapsed ( self . uptime )
  O0oiIIIIII1I = lisp_print_future ( self . expires )
  lprint ( "{}Referral EID {}, uptime/expires {}/{}, {} referrals:" . format ( eid_indent , green ( self . eid . print_prefix ( ) , False ) , Ii1I1i ,
  # II111iiii - oO0o
 O0oiIIIIII1I , len ( self . referral_set ) ) )
  if 29 - 29: OoO0O00 + I1IiiI - I1ii11iIi11i
  for oooOOo0o00 in list ( self . referral_set . values ( ) ) :
   oooOOo0o00 . print_ref_node ( referral_indent )
   if 86 - 86: Oo0Ooo / I1Ii111 / I1Ii111 - ooOoO0o / O0
   if 7 - 7: II111iiii + Oo0Ooo . I1Ii111
   if 44 - 44: i1IIi / I1IiiI * I11i . Oo0Ooo - iIii1I11I1II1 / IiII
 def print_referral_type ( self ) :
  if ( self . eid . afi == LISP_AFI_ULTIMATE_ROOT ) : return ( "root" )
  if ( self . referral_type == LISP_DDT_ACTION_NULL ) :
   return ( "null-referral" )
   if 56 - 56: Ii1I + i1IIi * oO0o
  if ( self . referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND ) :
   return ( "no-site-action" )
   if 4 - 4: IiII - IiII . OoOoOO00 . iIii1I11I1II1
  if ( self . referral_type > LISP_DDT_ACTION_MAX ) :
   return ( "invalid-action" )
   if 36 - 36: i1IIi * I11i
  return ( lisp_map_referral_action_string [ self . referral_type ] )
  if 80 - 80: iIii1I11I1II1 % Ii1I . I1ii11iIi11i % iII111i - IiII % OoO0O00
  if 58 - 58: IiII + Oo0Ooo - i1IIi
 def print_eid_tuple ( self ) :
  return ( lisp_print_eid_tuple ( self . eid , self . group ) )
  if 3 - 3: o0oOOo0O0Ooo * Ii1I
  if 53 - 53: I1ii11iIi11i / i1IIi . OoOoOO00 % Ii1I + I1IiiI
 def print_ttl ( self ) :
  o0ooo000o00O = self . referral_ttl
  if ( o0ooo000o00O < 60 ) : return ( str ( o0ooo000o00O ) + " secs" )
  if 25 - 25: oO0o + OoooooooOO / i1IIi + O0 % OoooooooOO . OoooooooOO
  if ( ( o0ooo000o00O % 60 ) == 0 ) :
   o0ooo000o00O = str ( old_div ( o0ooo000o00O , 60 ) ) + " mins"
  else :
   o0ooo000o00O = str ( o0ooo000o00O ) + " secs"
   if 78 - 78: iIii1I11I1II1 / I1Ii111 / iII111i / iIii1I11I1II1 . iIii1I11I1II1 % II111iiii
  return ( o0ooo000o00O )
  if 26 - 26: Oo0Ooo
  if 14 - 14: O0
 def is_referral_negative ( self ) :
  return ( self . referral_type in ( LISP_DDT_ACTION_MS_NOT_REG , LISP_DDT_ACTION_DELEGATION_HOLE ,
  # i11iIiiIii * O0 / OOooOOo . Oo0Ooo
 LISP_DDT_ACTION_NOT_AUTH ) )
  if 61 - 61: iII111i + oO0o * I1IiiI * Ii1I - Ii1I
  if 74 - 74: iII111i + OOooOOo * IiII * i11iIiiIii % I1ii11iIi11i - i1IIi
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
    if 43 - 43: OoOoOO00 . Oo0Ooo . IiII . IiII - ooOoO0o
   if ( self . eid . is_null ( ) ) : self . eid . make_default_route ( I11i1iI . group )
   I11i1iI . add_source_entry ( self )
   if 97 - 97: O0 % I1IiiI
   if 69 - 69: ooOoO0o . OoooooooOO
   if 17 - 17: ooOoO0o / OoO0O00 / I1IiiI / OOooOOo % IiII
 def delete_cache ( self ) :
  if ( self . group . is_null ( ) ) :
   lisp_referral_cache . delete_cache ( self . eid )
  else :
   I11i1iI = lisp_referral_cache . lookup_cache ( self . group , True )
   if ( I11i1iI == None ) : return
   if 88 - 88: i1IIi - OoOoOO00
   oo00Oo = I11i1iI . lookup_source_cache ( self . eid , True )
   if ( oo00Oo == None ) : return
   if 66 - 66: OoooooooOO - OoooooooOO * I11i / II111iiii + oO0o / Ii1I
   I11i1iI . source_cache . delete_cache ( self . eid )
   if ( I11i1iI . source_cache . cache_size ( ) == 0 ) :
    lisp_referral_cache . delete_cache ( self . group )
    if 7 - 7: Ii1I / iIii1I11I1II1
    if 36 - 36: iIii1I11I1II1 % i11iIiiIii
    if 35 - 35: Oo0Ooo + I1IiiI - O0 - I1Ii111
    if 64 - 64: i1IIi * OoOoOO00 / II111iiii * oO0o
 def add_source_entry ( self , source_ref ) :
  if ( self . source_cache == None ) : self . source_cache = lisp_cache ( )
  self . source_cache . add_cache ( source_ref . eid , source_ref )
  if 35 - 35: i1IIi - Ii1I - Ii1I . O0 % iII111i * iII111i
  if 15 - 15: OoooooooOO . Ii1I * I1Ii111 . ooOoO0o % OoO0O00 * Oo0Ooo
 def lookup_source_cache ( self , source , exact ) :
  if ( self . source_cache == None ) : return ( None )
  return ( self . source_cache . lookup_cache ( source , exact ) )
  if 10 - 10: iII111i + i11iIiiIii . OOooOOo % iII111i - i1IIi
  if 10 - 10: iIii1I11I1II1 * i11iIiiIii - O0
  if 45 - 45: oO0o % OOooOOo - IiII + o0oOOo0O0Ooo + i11iIiiIii
class lisp_referral_node ( object ) :
 def __init__ ( self ) :
  self . referral_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
  self . priority = 0
  self . weight = 0
  self . updown = True
  self . map_requests_sent = 0
  self . no_responses = 0
  self . uptime = lisp_get_timestamp ( )
  if 79 - 79: IiII % I1Ii111 . I1IiiI + O0 * oO0o * ooOoO0o
  if 38 - 38: IiII
 def print_ref_node ( self , indent ) :
  iIiIIIIIii = lisp_print_elapsed ( self . uptime )
  lprint ( "{}referral {}, uptime {}, {}, priority/weight: {}/{}" . format ( indent , red ( self . referral_address . print_address ( ) , False ) , iIiIIIIIii ,
  # ooOoO0o * Ii1I + II111iiii - OoO0O00 % Oo0Ooo
 "up" if self . updown else "down" , self . priority , self . weight ) )
  if 94 - 94: i11iIiiIii * I1ii11iIi11i / OoOoOO00 + i1IIi
  if 37 - 37: OOooOOo + O0 - OoOoOO00 + OoO0O00
  if 13 - 13: i11iIiiIii * oO0o
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
   if 41 - 41: ooOoO0o
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
   if 89 - 89: i11iIiiIii . i11iIiiIii . IiII
   if 29 - 29: o0oOOo0O0Ooo * iIii1I11I1II1 . iIii1I11I1II1
   if 32 - 32: IiII - OoOoOO00
 def resolve_dns_name ( self ) :
  if ( self . dns_name == None ) : return
  if ( self . last_dns_resolve and
 time . time ( ) - self . last_dns_resolve < 30 ) : return
  if 88 - 88: OOooOOo - II111iiii + i1IIi * Oo0Ooo
  try :
   OooO0O0Ooo = socket . gethostbyname_ex ( self . dns_name )
   self . last_dns_resolve = lisp_get_timestamp ( )
   i1111 = OooO0O0Ooo [ 2 ]
  except :
   return
   if 48 - 48: I1Ii111 + IiII % iII111i * iII111i + I1Ii111
   if 83 - 83: OoO0O00 . I11i * I1ii11iIi11i - II111iiii
   if 41 - 41: OoooooooOO . OoOoOO00 * iIii1I11I1II1
   if 18 - 18: IiII / I1Ii111 % i1IIi * i11iIiiIii
   if 16 - 16: Oo0Ooo
   if 24 - 24: o0oOOo0O0Ooo . OoOoOO00
  if ( len ( i1111 ) <= self . a_record_index ) :
   self . delete_ms ( )
   return
   if 50 - 50: I1ii11iIi11i / iIii1I11I1II1 - Oo0Ooo - i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o
   if 92 - 92: OoooooooOO - I1ii11iIi11i . I11i / O0 % iII111i
  iI1ii11Ii = i1111 [ self . a_record_index ]
  if ( iI1ii11Ii != self . map_server . print_address_no_iid ( ) ) :
   self . delete_ms ( )
   self . map_server . store_address ( iI1ii11Ii )
   self . insert_ms ( )
   if 96 - 96: I1IiiI . oO0o % O0
   if 19 - 19: iIii1I11I1II1 + I1Ii111 / OoooooooOO % OOooOOo - i1IIi + I11i
   if 87 - 87: OoooooooOO
   if 97 - 97: ooOoO0o * IiII / iIii1I11I1II1
   if 65 - 65: i1IIi - i11iIiiIii + oO0o % I1IiiI - OoO0O00 % ooOoO0o
   if 23 - 23: o0oOOo0O0Ooo . o0oOOo0O0Ooo - iIii1I11I1II1 / o0oOOo0O0Ooo
  if ( lisp_is_decent_dns_suffix ( self . dns_name ) == False ) : return
  if ( self . a_record_index != 0 ) : return
  if 65 - 65: I1Ii111 + I1Ii111 . I1ii11iIi11i . OoOoOO00 % o0oOOo0O0Ooo * o0oOOo0O0Ooo
  for iI1ii11Ii in i1111 [ 1 : : ] :
   I1II1I1I = lisp_address ( LISP_AFI_NONE , iI1ii11Ii , 0 , 0 )
   oOO0 = lisp_get_map_server ( I1II1I1I )
   if ( oOO0 != None and oOO0 . a_record_index == i1111 . index ( iI1ii11Ii ) ) :
    continue
    if 2 - 2: oO0o % iII111i + I1ii11iIi11i / II111iiii * I1ii11iIi11i
   oOO0 = copy . deepcopy ( self )
   oOO0 . map_server . store_address ( iI1ii11Ii )
   oOO0 . a_record_index = i1111 . index ( iI1ii11Ii )
   oOO0 . last_dns_resolve = lisp_get_timestamp ( )
   oOO0 . insert_ms ( )
   if 45 - 45: II111iiii . iII111i
   if 55 - 55: ooOoO0o / iII111i / O0
   if 98 - 98: O0 % iII111i + II111iiii
   if 13 - 13: I1IiiI * oO0o - o0oOOo0O0Ooo
   if 23 - 23: iIii1I11I1II1 + oO0o . oO0o / o0oOOo0O0Ooo
  O0O0OOOo0 = [ ]
  for oOO0 in list ( lisp_map_servers_list . values ( ) ) :
   if ( self . dns_name != oOO0 . dns_name ) : continue
   I1II1I1I = oOO0 . map_server . print_address_no_iid ( )
   if ( I1II1I1I in i1111 ) : continue
   O0O0OOOo0 . append ( oOO0 )
   if 77 - 77: i1IIi * o0oOOo0O0Ooo * IiII
  for oOO0 in O0O0OOOo0 : oOO0 . delete_ms ( )
  if 24 - 24: i11iIiiIii / iIii1I11I1II1 / iII111i
  if 31 - 31: OOooOOo . iIii1I11I1II1 - oO0o
 def insert_ms ( self ) :
  I1IIiiI1II = self . ms_name + self . map_server . print_address ( )
  lisp_map_servers_list [ I1IIiiI1II ] = self
  if 36 - 36: O0
  if 30 - 30: i11iIiiIii * Oo0Ooo . IiII
 def delete_ms ( self ) :
  I1IIiiI1II = self . ms_name + self . map_server . print_address ( )
  if ( I1IIiiI1II not in lisp_map_servers_list ) : return
  lisp_map_servers_list . pop ( I1IIiiI1II )
  if 65 - 65: oO0o * IiII * OOooOOo / OoooooooOO % I11i / I1Ii111
  if 21 - 21: i1IIi * iII111i + OoO0O00
  if 27 - 27: I11i / oO0o . iII111i + o0oOOo0O0Ooo - OOooOOo
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
  if 85 - 85: OoooooooOO
  if 83 - 83: iII111i * I11i . OOooOOo - OoO0O00 % IiII
 def add_interface ( self ) :
  lisp_myinterfaces [ self . device ] = self
  if 8 - 8: I1Ii111
  if 86 - 86: ooOoO0o + iII111i * O0 % OoO0O00 + OoOoOO00
 def get_instance_id ( self ) :
  return ( self . instance_id )
  if 49 - 49: OOooOOo / i1IIi - II111iiii . iIii1I11I1II1 + I11i . OOooOOo
  if 9 - 9: iIii1I11I1II1 + Ii1I + I11i
 def get_socket ( self ) :
  return ( self . raw_socket )
  if 96 - 96: OoO0O00 + i11iIiiIii + OoO0O00
  if 7 - 7: i1IIi . I1IiiI
 def get_bridge_socket ( self ) :
  return ( self . bridge_socket )
  if 68 - 68: OoooooooOO
  if 91 - 91: IiII . ooOoO0o * I11i
 def does_dynamic_eid_match ( self , eid ) :
  if ( self . dynamic_eid . is_null ( ) ) : return ( False )
  return ( eid . is_more_specific ( self . dynamic_eid ) )
  if 39 - 39: o0oOOo0O0Ooo + i11iIiiIii
  if 69 - 69: iIii1I11I1II1 . II111iiii
 def set_socket ( self , device ) :
  OOo0oOO0o0oo0 = socket . socket ( socket . AF_INET , socket . SOCK_RAW , socket . IPPROTO_RAW )
  OOo0oOO0o0oo0 . setsockopt ( socket . SOL_IP , socket . IP_HDRINCL , 1 )
  try :
   OOo0oOO0o0oo0 . setsockopt ( socket . SOL_SOCKET , socket . SO_BINDTODEVICE , device )
  except :
   OOo0oOO0o0oo0 . close ( )
   OOo0oOO0o0oo0 = None
   if 36 - 36: I1IiiI * i1IIi + OoOoOO00
  self . raw_socket = OOo0oOO0o0oo0
  if 63 - 63: OoOoOO00 - iII111i
  if 83 - 83: i1IIi / iII111i % ooOoO0o % i11iIiiIii + I1ii11iIi11i
 def set_bridge_socket ( self , device ) :
  OOo0oOO0o0oo0 = socket . socket ( socket . PF_PACKET , socket . SOCK_RAW )
  try :
   OOo0oOO0o0oo0 = OOo0oOO0o0oo0 . bind ( ( device , 0 ) )
   self . bridge_socket = OOo0oOO0o0oo0
  except :
   return
   if 82 - 82: iIii1I11I1II1 / OOooOOo
   if 7 - 7: OoooooooOO
   if 71 - 71: OOooOOo * Oo0Ooo . Oo0Ooo % iIii1I11I1II1
   if 56 - 56: IiII * iIii1I11I1II1 - iIii1I11I1II1 . O0
class lisp_datetime ( object ) :
 def __init__ ( self , datetime_str ) :
  self . datetime_name = datetime_str
  self . datetime = None
  self . parse_datetime ( )
  if 56 - 56: I1Ii111 / iIii1I11I1II1 % IiII * iIii1I11I1II1 . I1ii11iIi11i . OOooOOo
  if 1 - 1: Ii1I . Ii1I % II111iiii + I11i + OoOoOO00
 def valid_datetime ( self ) :
  ooOoOo0O = self . datetime_name
  if ( ooOoOo0O . find ( ":" ) == - 1 ) : return ( False )
  if ( ooOoOo0O . find ( "-" ) == - 1 ) : return ( False )
  iII1IIiI , IiiiII , IiIIiI1Ii , time = ooOoOo0O [ 0 : 4 ] , ooOoOo0O [ 5 : 7 ] , ooOoOo0O [ 8 : 10 ] , ooOoOo0O [ 11 : : ]
  if 21 - 21: OoO0O00 - i11iIiiIii
  if ( ( iII1IIiI + IiiiII + IiIIiI1Ii ) . isdigit ( ) == False ) : return ( False )
  if ( IiiiII < "01" and IiiiII > "12" ) : return ( False )
  if ( IiIIiI1Ii < "01" and IiIIiI1Ii > "31" ) : return ( False )
  if 29 - 29: i11iIiiIii
  o0o00ooOoOO , I1I11II1Ii1I1 , o0O0oO0o = time . split ( ":" )
  if 9 - 9: I1Ii111
  if ( ( o0o00ooOoOO + I1I11II1Ii1I1 + o0O0oO0o ) . isdigit ( ) == False ) : return ( False )
  if ( o0o00ooOoOO < "00" and o0o00ooOoOO > "23" ) : return ( False )
  if ( I1I11II1Ii1I1 < "00" and I1I11II1Ii1I1 > "59" ) : return ( False )
  if ( o0O0oO0o < "00" and o0O0oO0o > "59" ) : return ( False )
  return ( True )
  if 69 - 69: i1IIi + ooOoO0o + Ii1I
  if 88 - 88: OoOoOO00 + iII111i % O0 + OOooOOo / OoooooooOO / OOooOOo
 def parse_datetime ( self ) :
  O0o00o000 = self . datetime_name
  O0o00o000 = O0o00o000 . replace ( "-" , "" )
  O0o00o000 = O0o00o000 . replace ( ":" , "" )
  self . datetime = int ( O0o00o000 )
  if 70 - 70: o0oOOo0O0Ooo - O0 % I1ii11iIi11i
  if 28 - 28: I1Ii111 % iII111i
 def now ( self ) :
  iIiIIIIIii = datetime . datetime . now ( ) . strftime ( "%Y-%m-%d-%H:%M:%S" )
  iIiIIIIIii = lisp_datetime ( iIiIIIIIii )
  return ( iIiIIIIIii )
  if 18 - 18: OoOoOO00
  if 42 - 42: Ii1I . OOooOOo / O0 / i1IIi . i11iIiiIii
 def print_datetime ( self ) :
  return ( self . datetime_name )
  if 62 - 62: OoOoOO00
  if 6 - 6: OoO0O00 * ooOoO0o . oO0o
 def future ( self ) :
  return ( self . datetime > self . now ( ) . datetime )
  if 77 - 77: iIii1I11I1II1
  if 96 - 96: iII111i * I1ii11iIi11i
 def past ( self ) :
  return ( self . future ( ) == False )
  if 77 - 77: i11iIiiIii / iIii1I11I1II1 . I1ii11iIi11i
  if 90 - 90: I1IiiI + I1IiiI % oO0o
 def now_in_range ( self , upper ) :
  return ( self . past ( ) and upper . future ( ) )
  if 95 - 95: OOooOOo + OoooooooOO . i11iIiiIii * OoO0O00 * I1IiiI / I1Ii111
  if 5 - 5: Ii1I . oO0o / o0oOOo0O0Ooo - OoooooooOO
 def this_year ( self ) :
  O0OoOOo = str ( self . now ( ) . datetime ) [ 0 : 4 ]
  iIiIIIIIii = str ( self . datetime ) [ 0 : 4 ]
  return ( iIiIIIIIii == O0OoOOo )
  if 17 - 17: I1Ii111 / OOooOOo . i11iIiiIii - I11i
  if 7 - 7: I1Ii111 + ooOoO0o % o0oOOo0O0Ooo
 def this_month ( self ) :
  O0OoOOo = str ( self . now ( ) . datetime ) [ 0 : 6 ]
  iIiIIIIIii = str ( self . datetime ) [ 0 : 6 ]
  return ( iIiIIIIIii == O0OoOOo )
  if 53 - 53: i1IIi / iII111i % Ii1I % OoooooooOO
  if 63 - 63: OOooOOo + I1ii11iIi11i . i1IIi . Ii1I - I1ii11iIi11i * o0oOOo0O0Ooo
 def today ( self ) :
  O0OoOOo = str ( self . now ( ) . datetime ) [ 0 : 8 ]
  iIiIIIIIii = str ( self . datetime ) [ 0 : 8 ]
  return ( iIiIIIIIii == O0OoOOo )
  if 79 - 79: ooOoO0o - O0
  if 20 - 20: OOooOOo
  if 22 - 22: iIii1I11I1II1 / I1Ii111
  if 6 - 6: iII111i . i11iIiiIii / Oo0Ooo
  if 86 - 86: I11i % I1Ii111 % oO0o - ooOoO0o / i1IIi
  if 68 - 68: i1IIi % O0 % iII111i
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
  if 55 - 55: I1ii11iIi11i % OOooOOo - o0oOOo0O0Ooo - II111iiii
  if 52 - 52: I1Ii111
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
  if 34 - 34: II111iiii + iII111i / IiII
  if 47 - 47: OoO0O00
 def match_policy_map_request ( self , mr , srloc ) :
  for I1Iii1II in self . match_clauses :
   I1i1I = I1Iii1II . source_eid
   IiI111ii = mr . source_eid
   if ( I1i1I and IiI111ii and IiI111ii . is_more_specific ( I1i1I ) == False ) : continue
   if 40 - 40: o0oOOo0O0Ooo / iII111i . o0oOOo0O0Ooo
   I1i1I = I1Iii1II . dest_eid
   IiI111ii = mr . target_eid
   if ( I1i1I and IiI111ii and IiI111ii . is_more_specific ( I1i1I ) == False ) : continue
   if 63 - 63: o0oOOo0O0Ooo * iIii1I11I1II1 * II111iiii . OoO0O00 - oO0o / OoOoOO00
   I1i1I = I1Iii1II . source_rloc
   IiI111ii = srloc
   if ( I1i1I and IiI111ii and IiI111ii . is_more_specific ( I1i1I ) == False ) : continue
   OoOoo00Oo0OoO = I1Iii1II . datetime_lower
   OooOi1 = I1Iii1II . datetime_upper
   if ( OoOoo00Oo0OoO and OooOi1 and OoOoo00Oo0OoO . now_in_range ( OooOi1 ) == False ) : continue
   return ( True )
   if 43 - 43: II111iiii
  return ( False )
  if 11 - 11: I1ii11iIi11i % Ii1I + IiII + i1IIi % O0 . OoooooooOO
  if 75 - 75: OoooooooOO * I1Ii111 * o0oOOo0O0Ooo + I1ii11iIi11i . iIii1I11I1II1 / O0
 def set_policy_map_reply ( self ) :
  II1iI11i = ( self . set_rloc_address == None and
 self . set_rloc_record_name == None and self . set_geo_name == None and
 self . set_elp_name == None and self . set_rle_name == None )
  if ( II1iI11i ) : return ( None )
  if 80 - 80: Ii1I
  iIIiIi1111iiIii = lisp_rloc ( )
  if ( self . set_rloc_address ) :
   iIIiIi1111iiIii . rloc . copy_address ( self . set_rloc_address )
   iI1ii11Ii = iIIiIi1111iiIii . rloc . print_address_no_iid ( )
   lprint ( "Policy set-rloc-address to {}" . format ( iI1ii11Ii ) )
   if 33 - 33: II111iiii . I1ii11iIi11i * ooOoO0o % Oo0Ooo - I11i % I1ii11iIi11i
  if ( self . set_rloc_record_name ) :
   iIIiIi1111iiIii . rloc_name = self . set_rloc_record_name
   IIiIii1 = blue ( iIIiIi1111iiIii . rloc_name , False )
   lprint ( "Policy set-rloc-record-name to {}" . format ( IIiIii1 ) )
   if 51 - 51: ooOoO0o - I11i + Oo0Ooo / II111iiii
  if ( self . set_geo_name ) :
   iIIiIi1111iiIii . geo_name = self . set_geo_name
   IIiIii1 = iIIiIi1111iiIii . geo_name
   OO0o0oo0O0oO = "" if ( IIiIii1 in lisp_geo_list ) else "(not configured)"
   if 36 - 36: i11iIiiIii - OOooOOo + iII111i + iII111i * I11i * oO0o
   lprint ( "Policy set-geo-name '{}' {}" . format ( IIiIii1 , OO0o0oo0O0oO ) )
   if 14 - 14: O0 - iII111i * I1Ii111 - I1IiiI + IiII
  if ( self . set_elp_name ) :
   iIIiIi1111iiIii . elp_name = self . set_elp_name
   IIiIii1 = iIIiIi1111iiIii . elp_name
   OO0o0oo0O0oO = "" if ( IIiIii1 in lisp_elp_list ) else "(not configured)"
   if 46 - 46: OoooooooOO * OoO0O00 . I1Ii111
   lprint ( "Policy set-elp-name '{}' {}" . format ( IIiIii1 , OO0o0oo0O0oO ) )
   if 95 - 95: ooOoO0o . I1ii11iIi11i . ooOoO0o / I1IiiI * OoOoOO00 . O0
  if ( self . set_rle_name ) :
   iIIiIi1111iiIii . rle_name = self . set_rle_name
   IIiIii1 = iIIiIi1111iiIii . rle_name
   OO0o0oo0O0oO = "" if ( IIiIii1 in lisp_rle_list ) else "(not configured)"
   if 78 - 78: oO0o
   lprint ( "Policy set-rle-name '{}' {}" . format ( IIiIii1 , OO0o0oo0O0oO ) )
   if 33 - 33: oO0o + i1IIi
  if ( self . set_json_name ) :
   iIIiIi1111iiIii . json_name = self . set_json_name
   IIiIii1 = iIIiIi1111iiIii . json_name
   OO0o0oo0O0oO = "" if ( IIiIii1 in lisp_json_list ) else "(not configured)"
   if 32 - 32: iIii1I11I1II1
   lprint ( "Policy set-json-name '{}' {}" . format ( IIiIii1 , OO0o0oo0O0oO ) )
   if 71 - 71: Ii1I * I1IiiI
  return ( iIIiIi1111iiIii )
  if 62 - 62: II111iiii / I1IiiI . I1ii11iIi11i
  if 49 - 49: IiII / OoOoOO00 / O0 * i11iIiiIii
 def save_policy ( self ) :
  lisp_policies [ self . policy_name ] = self
  if 47 - 47: i11iIiiIii + iII111i + i11iIiiIii
  if 66 - 66: o0oOOo0O0Ooo . I1IiiI + OoooooooOO . iII111i / OoooooooOO - IiII
  if 47 - 47: o0oOOo0O0Ooo / II111iiii * i11iIiiIii * OoO0O00 . iIii1I11I1II1
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
  if 34 - 34: I11i / o0oOOo0O0Ooo * OOooOOo * OOooOOo
  if 89 - 89: I1ii11iIi11i . OoooooooOO
 def add ( self , eid_prefix ) :
  self . eid_prefix = eid_prefix
  o0ooo000o00O = self . ttl
  Ooo0O = eid_prefix . print_prefix ( )
  if ( Ooo0O not in lisp_pubsub_cache ) :
   lisp_pubsub_cache [ Ooo0O ] = { }
   if 61 - 61: i1IIi + i11iIiiIii
  I1IIIi = lisp_pubsub_cache [ Ooo0O ]
  if 59 - 59: i11iIiiIii * OOooOOo + i1IIi * iIii1I11I1II1 + I11i
  oOo0oOOo = "Add"
  if ( self . xtr_id in I1IIIi ) :
   oOo0oOOo = "Replace"
   del ( I1IIIi [ self . xtr_id ] )
   if 56 - 56: i11iIiiIii / II111iiii
  I1IIIi [ self . xtr_id ] = self
  if 41 - 41: Oo0Ooo . OoOoOO00 . iII111i / i11iIiiIii
  Ooo0O = green ( Ooo0O , False )
  II1iIiiiIiI1 = red ( self . itr . print_address_no_iid ( ) , False )
  iIo0O00o00o0 = "0x" + lisp_hex_string ( self . xtr_id )
  lprint ( "{} pubsub state {} for {}, xtr-id: {}, ttl {}" . format ( oOo0oOOo , Ooo0O ,
 II1iIiiiIiI1 , iIo0O00o00o0 , o0ooo000o00O ) )
  if 65 - 65: iII111i * o0oOOo0O0Ooo * OoooooooOO + I11i + oO0o % OoO0O00
  if 1 - 1: I1ii11iIi11i . ooOoO0o
 def delete ( self , eid_prefix ) :
  Ooo0O = eid_prefix . print_prefix ( )
  II1iIiiiIiI1 = red ( self . itr . print_address_no_iid ( ) , False )
  iIo0O00o00o0 = "0x" + lisp_hex_string ( self . xtr_id )
  if ( Ooo0O in lisp_pubsub_cache ) :
   I1IIIi = lisp_pubsub_cache [ Ooo0O ]
   if ( self . xtr_id in I1IIIi ) :
    I1IIIi . pop ( self . xtr_id )
    lprint ( "Remove pubsub state {} for {}, xtr-id: {}" . format ( Ooo0O ,
 II1iIiiiIiI1 , iIo0O00o00o0 ) )
    if 54 - 54: OoOoOO00 % I1IiiI . ooOoO0o + IiII / i11iIiiIii / o0oOOo0O0Ooo
    if 51 - 51: OoOoOO00 / Ii1I . I1IiiI / Ii1I . II111iiii - iIii1I11I1II1
    if 78 - 78: I11i
    if 42 - 42: Ii1I
    if 50 - 50: iIii1I11I1II1 / Ii1I . ooOoO0o / ooOoO0o * OoOoOO00 * iII111i
    if 15 - 15: o0oOOo0O0Ooo % II111iiii + I1IiiI
    if 21 - 21: I1ii11iIi11i - ooOoO0o
    if 81 - 81: iII111i / i11iIiiIii / I1Ii111
    if 70 - 70: I1ii11iIi11i / i11iIiiIii
    if 90 - 90: II111iiii / OoOoOO00 . Ii1I . OoooooooOO
    if 76 - 76: OoooooooOO
    if 78 - 78: IiII % i11iIiiIii
    if 23 - 23: iIii1I11I1II1 - o0oOOo0O0Ooo - Ii1I % OOooOOo
    if 100 - 100: oO0o . OoO0O00 . i11iIiiIii % II111iiii * IiII
    if 81 - 81: OOooOOo - OOooOOo + OoOoOO00
    if 19 - 19: o0oOOo0O0Ooo
    if 20 - 20: I1Ii111 + iIii1I11I1II1 % I1IiiI + ooOoO0o
    if 86 - 86: o0oOOo0O0Ooo * i11iIiiIii - I11i
    if 71 - 71: OoO0O00 - I11i
    if 96 - 96: I1Ii111 / Ii1I
    if 65 - 65: I1ii11iIi11i * O0 . IiII
    if 11 - 11: I11i / Ii1I % oO0o
class lisp_trace ( object ) :
 def __init__ ( self ) :
  self . nonce = lisp_get_control_nonce ( )
  self . packet_json = [ ]
  self . local_rloc = None
  self . local_port = None
  self . lisp_socket = None
  if 50 - 50: i11iIiiIii
  if 93 - 93: i1IIi / Ii1I * II111iiii - Oo0Ooo . OoOoOO00 - OOooOOo
 def print_trace ( self ) :
  iII1ii1 = self . packet_json
  lprint ( "LISP-Trace JSON: '{}'" . format ( iII1ii1 ) )
  if 25 - 25: I11i / ooOoO0o % ooOoO0o - OOooOOo
  if 59 - 59: I1IiiI + o0oOOo0O0Ooo . iIii1I11I1II1 - O0 - i11iIiiIii
 def encode ( self ) :
  ooo = socket . htonl ( 0x90000000 )
  Oo00O0o0O = struct . pack ( "II" , ooo , 0 )
  Oo00O0o0O += struct . pack ( "Q" , self . nonce )
  Oo00O0o0O += json . dumps ( self . packet_json )
  return ( Oo00O0o0O )
  if 4 - 4: I1IiiI
  if 36 - 36: Ii1I
 def decode ( self , packet ) :
  Oo0O = "I"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( False )
  ooo = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  ooo = socket . ntohl ( ooo )
  if ( ( ooo & 0xff000000 ) != 0x90000000 ) : return ( False )
  if 76 - 76: i11iIiiIii + i1IIi
  if ( len ( packet ) < ii1ii11Ii ) : return ( False )
  iI1ii11Ii = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  if 56 - 56: OoOoOO00 + II111iiii / i11iIiiIii * OoOoOO00 * OoooooooOO
  iI1ii11Ii = socket . ntohl ( iI1ii11Ii )
  iIIiO00o0o = iI1ii11Ii >> 24
  OoOOOO0O0 = ( iI1ii11Ii >> 16 ) & 0xff
  i1ii1Iii1 = ( iI1ii11Ii >> 8 ) & 0xff
  iII1iii = iI1ii11Ii & 0xff
  self . local_rloc = "{}.{}.{}.{}" . format ( iIIiO00o0o , OoOOOO0O0 , i1ii1Iii1 , iII1iii )
  self . local_port = str ( ooo & 0xffff )
  if 59 - 59: i1IIi * Oo0Ooo / Ii1I % OoO0O00
  Oo0O = "Q"
  ii1ii11Ii = struct . calcsize ( Oo0O )
  if ( len ( packet ) < ii1ii11Ii ) : return ( False )
  self . nonce = struct . unpack ( Oo0O , packet [ : ii1ii11Ii ] ) [ 0 ]
  packet = packet [ ii1ii11Ii : : ]
  if ( len ( packet ) == 0 ) : return ( True )
  if 88 - 88: i1IIi / II111iiii
  try :
   self . packet_json = json . loads ( packet )
  except :
   return ( False )
   if 91 - 91: I1IiiI * I1Ii111 * i11iIiiIii - oO0o - IiII + I1ii11iIi11i
  return ( True )
  if 99 - 99: OoO0O00 % o0oOOo0O0Ooo
  if 3 - 3: OOooOOo / OoOoOO00 % iIii1I11I1II1
 def myeid ( self , eid ) :
  return ( lisp_is_myeid ( eid ) )
  if 47 - 47: ooOoO0o . i11iIiiIii / OoO0O00
  if 48 - 48: O0
 def return_to_sender ( self , lisp_socket , rts_rloc , packet ) :
  iIIiIi1111iiIii , O0ooO0O00oo0 = self . rtr_cache_nat_trace_find ( rts_rloc )
  if ( iIIiIi1111iiIii == None ) :
   iIIiIi1111iiIii , O0ooO0O00oo0 = rts_rloc . split ( ":" )
   O0ooO0O00oo0 = int ( O0ooO0O00oo0 )
   lprint ( "Send LISP-Trace to address {}:{}" . format ( iIIiIi1111iiIii , O0ooO0O00oo0 ) )
  else :
   lprint ( "Send LISP-Trace to translated address {}:{}" . format ( iIIiIi1111iiIii ,
 O0ooO0O00oo0 ) )
   if 89 - 89: i11iIiiIii % OoO0O00 . OoOoOO00 + Oo0Ooo + OoOoOO00
   if 53 - 53: Ii1I / OoOoOO00 % iII111i * OoooooooOO + Oo0Ooo
  if ( lisp_socket == None ) :
   OOo0oOO0o0oo0 = socket . socket ( socket . AF_INET , socket . SOCK_DGRAM )
   OOo0oOO0o0oo0 . bind ( ( "0.0.0.0" , LISP_TRACE_PORT ) )
   OOo0oOO0o0oo0 . sendto ( packet , ( iIIiIi1111iiIii , O0ooO0O00oo0 ) )
   OOo0oOO0o0oo0 . close ( )
  else :
   lisp_socket . sendto ( packet , ( iIIiIi1111iiIii , O0ooO0O00oo0 ) )
   if 70 - 70: OoO0O00 % OoO0O00 * OoooooooOO
   if 96 - 96: ooOoO0o * Ii1I + I11i + II111iiii * I1IiiI / iII111i
   if 40 - 40: OoooooooOO - I11i % OOooOOo - I1IiiI . I1IiiI + Ii1I
 def packet_length ( self ) :
  ii11 = 8 ; O0oii1III1II1 = 4 + 4 + 8
  return ( ii11 + O0oii1III1II1 + len ( json . dumps ( self . packet_json ) ) )
  if 6 - 6: Oo0Ooo + OoooooooOO - i1IIi * OOooOOo
  if 11 - 11: I11i / OOooOOo . o0oOOo0O0Ooo - O0 * OoooooooOO % iII111i
 def rtr_cache_nat_trace ( self , translated_rloc , translated_port ) :
  I1IIiiI1II = self . local_rloc + ":" + self . local_port
  oO00o = ( translated_rloc , translated_port )
  lisp_rtr_nat_trace_cache [ I1IIiiI1II ] = oO00o
  lprint ( "Cache NAT Trace addresses {} -> {}" . format ( I1IIiiI1II , oO00o ) )
  if 7 - 7: OoOoOO00 . IiII + OoooooooOO - I1Ii111 / oO0o
  if 32 - 32: iIii1I11I1II1 + I11i + OOooOOo - OoooooooOO + i11iIiiIii * o0oOOo0O0Ooo
 def rtr_cache_nat_trace_find ( self , local_rloc_and_port ) :
  I1IIiiI1II = local_rloc_and_port
  try : oO00o = lisp_rtr_nat_trace_cache [ I1IIiiI1II ]
  except : oO00o = ( None , None )
  return ( oO00o )
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
def lisp_get_map_server ( address ) :
 for oOO0 in list ( lisp_map_servers_list . values ( ) ) :
  if ( oOO0 . map_server . is_exact_match ( address ) ) : return ( oOO0 )
  if 68 - 68: Ii1I
 return ( None )
 if 98 - 98: iII111i
 if 33 - 33: OoO0O00 - ooOoO0o % O0 % iIii1I11I1II1 * iII111i - iII111i
 if 27 - 27: i11iIiiIii + I1ii11iIi11i + i1IIi
 if 67 - 67: o0oOOo0O0Ooo
 if 58 - 58: IiII % o0oOOo0O0Ooo + i1IIi
 if 33 - 33: II111iiii
 if 61 - 61: I1Ii111
def lisp_get_any_map_server ( ) :
 for oOO0 in list ( lisp_map_servers_list . values ( ) ) : return ( oOO0 )
 return ( None )
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
def lisp_get_map_resolver ( address , eid ) :
 if ( address != None ) :
  iI1ii11Ii = address . print_address ( )
  II1iI1iII11 = None
  for I1IIiiI1II in lisp_map_resolvers_list :
   if ( I1IIiiI1II . find ( iI1ii11Ii ) == - 1 ) : continue
   II1iI1iII11 = lisp_map_resolvers_list [ I1IIiiI1II ]
   if 70 - 70: iIii1I11I1II1
  return ( II1iI1iII11 )
  if 100 - 100: OOooOOo . oO0o % ooOoO0o * ooOoO0o . I1Ii111 - oO0o
  if 33 - 33: Oo0Ooo . i1IIi - OoooooooOO
  if 14 - 14: I1Ii111 + Oo0Ooo
  if 35 - 35: i11iIiiIii * Ii1I
  if 100 - 100: O0 . iII111i / iIii1I11I1II1
  if 47 - 47: ooOoO0o + OoOoOO00
  if 67 - 67: IiII - I1ii11iIi11i * i1IIi - ooOoO0o
 if ( eid == "" ) :
  oOooOoo00o = ""
 elif ( eid == None ) :
  oOooOoo00o = "all"
 else :
  Iiii1II1 = lisp_db_for_lookups . lookup_cache ( eid , False )
  oOooOoo00o = "all" if Iiii1II1 == None else Iiii1II1 . use_mr_name
  if 16 - 16: I11i * ooOoO0o * I1ii11iIi11i % OoO0O00 * iIii1I11I1II1
  if 39 - 39: oO0o - O0
 Iii111i111i = None
 for II1iI1iII11 in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( oOooOoo00o == "" ) : return ( II1iI1iII11 )
  if ( II1iI1iII11 . mr_name != oOooOoo00o ) : continue
  if ( Iii111i111i == None or II1iI1iII11 . last_used < Iii111i111i . last_used ) : Iii111i111i = II1iI1iII11
  if 29 - 29: IiII / OoooooooOO + I1ii11iIi11i
 return ( Iii111i111i )
 if 21 - 21: I1ii11iIi11i
 if 35 - 35: IiII % Oo0Ooo * Ii1I . IiII
 if 16 - 16: I1ii11iIi11i % I1IiiI + Ii1I * I11i + i1IIi
 if 14 - 14: iII111i / ooOoO0o % IiII - I1IiiI . Oo0Ooo
 if 30 - 30: O0 . OOooOOo
 if 23 - 23: i1IIi + OoooooooOO * OOooOOo . Oo0Ooo
 if 83 - 83: OoooooooOO
 if 53 - 53: o0oOOo0O0Ooo - Oo0Ooo / IiII + O0
def lisp_get_decent_map_resolver ( eid ) :
 o00O = lisp_get_decent_index ( eid )
 OO00Oo0oO0O = str ( o00O ) + "." + lisp_decent_dns_suffix
 if 80 - 80: iIii1I11I1II1 + OoOoOO00 % I1IiiI
 lprint ( "Use LISP-Decent map-resolver {} for EID {}" . format ( bold ( OO00Oo0oO0O , False ) , eid . print_prefix ( ) ) )
 if 14 - 14: I1IiiI / OoO0O00 . o0oOOo0O0Ooo
 if 72 - 72: IiII + oO0o * o0oOOo0O0Ooo
 Iii111i111i = None
 for II1iI1iII11 in list ( lisp_map_resolvers_list . values ( ) ) :
  if ( OO00Oo0oO0O != II1iI1iII11 . dns_name ) : continue
  if ( Iii111i111i == None or II1iI1iII11 . last_used < Iii111i111i . last_used ) : Iii111i111i = II1iI1iII11
  if 39 - 39: O0 + iII111i + ooOoO0o / iIii1I11I1II1
 return ( Iii111i111i )
 if 91 - 91: Ii1I
 if 62 - 62: I1Ii111 . iIii1I11I1II1 - Ii1I * I1ii11iIi11i % I11i % i1IIi
 if 72 - 72: oO0o
 if 3 - 3: ooOoO0o - Oo0Ooo / iII111i
 if 40 - 40: IiII + oO0o
 if 95 - 95: I1Ii111 % OOooOOo + Ii1I * i11iIiiIii + i11iIiiIii
 if 27 - 27: i11iIiiIii - iIii1I11I1II1 % I1Ii111
def lisp_ipv4_input ( packet ) :
 if 10 - 10: i11iIiiIii - Ii1I - OoooooooOO % II111iiii
 if 42 - 42: OoOoOO00 + iII111i % Oo0Ooo
 if 25 - 25: IiII % O0 * I11i * OoOoOO00 / OoooooooOO
 if 80 - 80: I1IiiI . oO0o - I1IiiI - OoOoOO00 * ooOoO0o / O0
 if ( ord ( packet [ 9 : 10 ] ) == 2 ) : return ( [ True , packet ] )
 if 54 - 54: Oo0Ooo % iIii1I11I1II1 * Oo0Ooo
 if 80 - 80: I1ii11iIi11i - I1ii11iIi11i
 if 26 - 26: I1ii11iIi11i - I1IiiI * I1Ii111 % iIii1I11I1II1
 if 77 - 77: o0oOOo0O0Ooo + I1Ii111 . OOooOOo . i1IIi . I1IiiI
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
   if 100 - 100: ooOoO0o . i11iIiiIii + Ii1I - OOooOOo - i11iIiiIii - OoooooooOO
   if 42 - 42: OoOoOO00 . I1IiiI / OoOoOO00 / I1ii11iIi11i . OoO0O00
   if 67 - 67: Ii1I - O0 . OoooooooOO . I1Ii111 . o0oOOo0O0Ooo
   if 73 - 73: I11i - oO0o . I1Ii111 + oO0o
   if 48 - 48: IiII . IiII * o0oOOo0O0Ooo * II111iiii % ooOoO0o
   if 40 - 40: I1ii11iIi11i
   if 76 - 76: Oo0Ooo - I11i
 o0ooo000o00O = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ]
 if ( o0ooo000o00O == 0 ) :
  dprint ( "IPv4 packet arrived with ttl 0, packet discarded" )
  return ( [ False , None ] )
 elif ( o0ooo000o00O == 1 ) :
  dprint ( "IPv4 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 82 - 82: OoO0O00 % oO0o . I11i / O0 - I1Ii111
  return ( [ False , None ] )
  if 39 - 39: I1IiiI
  if 8 - 8: IiII * i1IIi * i1IIi * O0
 o0ooo000o00O -= 1
 packet = packet [ 0 : 8 ] + struct . pack ( "B" , o0ooo000o00O ) + packet [ 9 : : ]
 packet = packet [ 0 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : : ]
 packet = lisp_ip_checksum ( packet )
 return ( [ False , packet ] )
 if 69 - 69: Oo0Ooo
 if 48 - 48: iII111i
 if 11 - 11: i11iIiiIii * OoOoOO00 . OoO0O00
 if 47 - 47: Oo0Ooo % I1Ii111 + ooOoO0o
 if 89 - 89: iII111i
 if 29 - 29: I1ii11iIi11i . ooOoO0o * II111iiii / iII111i . OoooooooOO - OoOoOO00
 if 99 - 99: IiII % O0 - I1Ii111 * OoO0O00
def lisp_ipv6_input ( packet ) :
 oOO00OoOo = packet . inner_dest
 packet = packet . packet
 if 77 - 77: OoooooooOO - I11i / I1IiiI % OoOoOO00 - OOooOOo
 if 37 - 37: ooOoO0o
 if 22 - 22: I1ii11iIi11i + II111iiii / OoooooooOO % o0oOOo0O0Ooo * OoOoOO00 . Oo0Ooo
 if 26 - 26: OoO0O00 % oO0o * Ii1I % OoooooooOO - oO0o
 if 46 - 46: I1IiiI + OoO0O00 - O0 * O0
 o0ooo000o00O = struct . unpack ( "B" , packet [ 7 : 8 ] ) [ 0 ]
 if ( o0ooo000o00O == 0 ) :
  dprint ( "IPv6 packet arrived with hop-limit 0, packet discarded" )
  return ( None )
 elif ( o0ooo000o00O == 1 ) :
  dprint ( "IPv6 packet {}, packet discarded" . format ( bold ( "ttl expiry" , False ) ) )
  if 75 - 75: OOooOOo + iIii1I11I1II1 * OOooOOo
  return ( None )
  if 82 - 82: iII111i - I1Ii111 - OoOoOO00
  if 96 - 96: Oo0Ooo . Oo0Ooo % o0oOOo0O0Ooo - I1IiiI * iIii1I11I1II1
  if 29 - 29: i1IIi / Ii1I / oO0o * iII111i
  if 44 - 44: O0
  if 95 - 95: OOooOOo + OOooOOo - OoOoOO00
 if ( oOO00OoOo . is_ipv6_link_local ( ) ) :
  dprint ( "Do not encapsulate IPv6 link-local packets" )
  return ( None )
  if 83 - 83: II111iiii * ooOoO0o - O0 - i11iIiiIii
  if 62 - 62: I1IiiI + II111iiii * iIii1I11I1II1 % iII111i + IiII / ooOoO0o
 o0ooo000o00O -= 1
 packet = packet [ 0 : 7 ] + struct . pack ( "B" , o0ooo000o00O ) + packet [ 8 : : ]
 return ( packet )
 if 14 - 14: iIii1I11I1II1 * I1ii11iIi11i + OOooOOo + O0
 if 79 - 79: II111iiii - iII111i
 if 89 - 89: O0 - OoO0O00
 if 8 - 8: I1ii11iIi11i / oO0o - OoooooooOO + ooOoO0o + o0oOOo0O0Ooo % i11iIiiIii
 if 32 - 32: O0 + IiII
 if 93 - 93: OoOoOO00 - I11i / iII111i - iIii1I11I1II1 + I11i % oO0o
 if 24 - 24: Ii1I / iIii1I11I1II1 + o0oOOo0O0Ooo
 if 17 - 17: OOooOOo
def lisp_mac_input ( packet ) :
 return ( packet )
 if 75 - 75: Ii1I / i1IIi % I1ii11iIi11i . Ii1I
 if 46 - 46: II111iiii * OoO0O00
 if 77 - 77: ooOoO0o * I11i
 if 85 - 85: OoO0O00 * I1Ii111 - OoooooooOO / iIii1I11I1II1 - i1IIi + Ii1I
 if 76 - 76: iII111i * OoooooooOO
 if 49 - 49: II111iiii - OOooOOo + II111iiii + OoOoOO00
 if 51 - 51: i11iIiiIii
 if 39 - 39: o0oOOo0O0Ooo % I1Ii111 % i1IIi - II111iiii + i11iIiiIii
 if 62 - 62: I1ii11iIi11i - I1IiiI * i11iIiiIii % oO0o
def lisp_rate_limit_map_request ( dest ) :
 O0OoOOo = lisp_get_timestamp ( )
 if 63 - 63: II111iiii - Oo0Ooo
 if 55 - 55: iIii1I11I1II1 / O0 * O0 * i11iIiiIii * OoooooooOO
 if 94 - 94: II111iiii . II111iiii / OoOoOO00 % oO0o * i1IIi % Oo0Ooo
 if 78 - 78: IiII - I1IiiI
 o0oOOOO0 = O0OoOOo - lisp_no_map_request_rate_limit
 if ( o0oOOOO0 < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME ) :
  oO0OO00OOo0 = int ( LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - o0oOOOO0 )
  dprint ( "No Rate-Limit Mode for another {} secs" . format ( oO0OO00OOo0 ) )
  return ( False )
  if 59 - 59: oO0o + i1IIi - IiII % OOooOOo % iIii1I11I1II1
  if 71 - 71: OoO0O00
  if 72 - 72: II111iiii + o0oOOo0O0Ooo / i1IIi * Oo0Ooo / i1IIi
  if 52 - 52: I1Ii111 % OoO0O00 . I1Ii111 * I1ii11iIi11i * OoOoOO00 + i1IIi
  if 54 - 54: Ii1I / I1IiiI
 if ( lisp_last_map_request_sent == None ) : return ( False )
 o0oOOOO0 = O0OoOOo - lisp_last_map_request_sent
 iIIii1II1ii1 = ( o0oOOOO0 < LISP_MAP_REQUEST_RATE_LIMIT )
 if 7 - 7: iIii1I11I1II1 . O0 + OOooOOo . Ii1I * Oo0Ooo
 if ( iIIii1II1ii1 ) :
  dprint ( "Rate-limiting Map-Request for {}, sent {} secs ago" . format ( green ( dest . print_address ( ) , False ) , round ( o0oOOOO0 , 3 ) ) )
  if 25 - 25: I1Ii111 . Oo0Ooo % II111iiii . IiII - O0
  if 18 - 18: oO0o * OOooOOo
 return ( iIIii1II1ii1 )
 if 19 - 19: iIii1I11I1II1 / I1ii11iIi11i - I1ii11iIi11i / iIii1I11I1II1
 if 42 - 42: iIii1I11I1II1 / OOooOOo - O0 * OoooooooOO / i1IIi
 if 33 - 33: OOooOOo . o0oOOo0O0Ooo % OoO0O00 - I1Ii111 . OoooooooOO
 if 96 - 96: II111iiii % I11i / Ii1I - i11iIiiIii
 if 63 - 63: I1IiiI
 if 15 - 15: iIii1I11I1II1 - I1ii11iIi11i % OoO0O00 * II111iiii / I11i + I11i
 if 23 - 23: I1IiiI
def lisp_send_map_request ( lisp_sockets , lisp_ephem_port , seid , deid , rloc ,
 pubsub = False ) :
 global lisp_last_map_request_sent , lisp_rloc_probe_nonce_list
 if 51 - 51: i11iIiiIii / ooOoO0o - OoooooooOO + OoOoOO00 + oO0o
 if 57 - 57: iIii1I11I1II1
 if 19 - 19: Ii1I / o0oOOo0O0Ooo + O0 / iIii1I11I1II1 + II111iiii
 if 3 - 3: oO0o % OoO0O00 % OOooOOo
 if 64 - 64: o0oOOo0O0Ooo . II111iiii * IiII % Oo0Ooo + I11i - OoooooooOO
 if 58 - 58: ooOoO0o
 Ii11I111Ii11 = i1I111Iii11iI = None
 if ( rloc ) :
  Ii11I111Ii11 = rloc . rloc
  i1I111Iii11iI = rloc . translated_port if lisp_i_am_rtr else LISP_DATA_PORT
  if 38 - 38: IiII % OoOoOO00 . OOooOOo . I1ii11iIi11i
  if 34 - 34: iII111i . i11iIiiIii + OoO0O00 + o0oOOo0O0Ooo / ooOoO0o - i11iIiiIii
  if 63 - 63: ooOoO0o % OoO0O00 % ooOoO0o
  if 28 - 28: IiII * I1Ii111 * o0oOOo0O0Ooo + ooOoO0o - IiII / IiII
  if 73 - 73: iIii1I11I1II1 . I1ii11iIi11i + OOooOOo
  if 51 - 51: I11i % Oo0Ooo * OOooOOo % OoooooooOO - OoOoOO00 % Ii1I
  if 60 - 60: OoOoOO00 - IiII + OoO0O00
 o0oOoOo00oo , o0o0o0O , ooOooO = lisp_myrlocs
 if 75 - 75: I1ii11iIi11i
 if 50 - 50: OoO0O00 % OoOoOO00
 if 7 - 7: iII111i / ooOoO0o * i1IIi
 if 63 - 63: I1IiiI / O0 * o0oOOo0O0Ooo / OoO0O00 - I1IiiI
 if 1 - 1: I1Ii111 . iII111i / IiII % iIii1I11I1II1 . iII111i + OoOoOO00
 if ( rloc != None and rloc . probing_itr_rloc != None and rloc . rloc . is_ipv4 ( ) ) :
  o0oOoOo00oo = rloc . probing_itr_rloc
  if 12 - 12: ooOoO0o
  if 54 - 54: I11i - O0 * iII111i . II111iiii
 if ( o0oOoOo00oo == None ) :
  lprint ( "Suppress sending Map-Request, IPv4 RLOC not found" )
  return
  if 51 - 51: Oo0Ooo
 if ( o0o0o0O == None and Ii11I111Ii11 != None and Ii11I111Ii11 . is_ipv6 ( ) ) :
  lprint ( "Suppress sending Map-Request, IPv6 RLOC not found" )
  return
  if 31 - 31: Oo0Ooo / oO0o
  if 44 - 44: I1ii11iIi11i % o0oOOo0O0Ooo / iIii1I11I1II1 - o0oOOo0O0Ooo / I11i * I1Ii111
 iiIIIIiI = lisp_map_request ( )
 iiIIIIiI . record_count = 1
 iiIIIIiI . nonce = lisp_get_control_nonce ( )
 iiIIIIiI . rloc_probe = ( Ii11I111Ii11 != None )
 iiIIIIiI . subscribe_bit = pubsub
 iiIIIIiI . xtr_id_present = pubsub
 iiIIIIiI . decent_nat_xtr = lisp_decent_nat
 if 49 - 49: iII111i / iII111i - OoOoOO00
 if 89 - 89: ooOoO0o
 if 16 - 16: oO0o + oO0o + i1IIi + iIii1I11I1II1
 if 93 - 93: I1IiiI - i11iIiiIii * I1Ii111 - O0 + iII111i
 if 11 - 11: iII111i
 if 100 - 100: OoooooooOO / ooOoO0o . OoO0O00
 if 89 - 89: I11i % II111iiii
 if ( rloc ) : rloc . last_rloc_probe_nonce = iiIIIIiI . nonce
 if 35 - 35: oO0o
 i1Ii1 = deid . is_multicast_address ( )
 if ( i1Ii1 ) :
  iiIIIIiI . target_eid = seid
  iiIIIIiI . target_group = deid
 else :
  iiIIIIiI . target_eid = deid
  if 65 - 65: II111iiii
  if 87 - 87: oO0o / OoO0O00 - oO0o
  if 69 - 69: i11iIiiIii
  if 29 - 29: IiII . ooOoO0o / iII111i - OOooOOo / OOooOOo % Oo0Ooo
  if 42 - 42: OoO0O00 . I1Ii111 . I1IiiI + Oo0Ooo * O0
  if 35 - 35: Oo0Ooo / iII111i - O0 - OOooOOo * Oo0Ooo . i11iIiiIii
  if 43 - 43: OoOoOO00 % oO0o % OoO0O00 / Ii1I . I11i
  if 86 - 86: I1Ii111 * i1IIi + IiII - OoOoOO00
  if 14 - 14: I1ii11iIi11i / i11iIiiIii * I11i % o0oOOo0O0Ooo + IiII / I1ii11iIi11i
 if ( iiIIIIiI . rloc_probe == False ) :
  Iiii1II1 = lisp_get_signature_eid ( )
  if ( Iiii1II1 ) :
   iiIIIIiI . signature_eid . copy_address ( Iiii1II1 . eid )
   iiIIIIiI . privkey_filename = "./lisp-sig.pem"
   if 82 - 82: OOooOOo . oO0o
   if 12 - 12: i11iIiiIii + II111iiii
   if 49 - 49: OoooooooOO
   if 48 - 48: i1IIi . IiII - O0 + OoooooooOO
   if 6 - 6: I1Ii111 * OOooOOo + o0oOOo0O0Ooo . I1ii11iIi11i * I1Ii111
   if 6 - 6: oO0o / II111iiii
 if ( seid == None or i1Ii1 ) :
  iiIIIIiI . source_eid . afi = LISP_AFI_NONE
 else :
  iiIIIIiI . source_eid = seid
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
  if 1 - 1: oO0o / I11i
 if ( Ii11I111Ii11 != None and lisp_nat_traversal and lisp_i_am_rtr == False ) :
  if ( lisp_decent_nat == False and
 Ii11I111Ii11 . is_private_address ( ) == False ) :
   o0oOoOo00oo = lisp_get_any_translated_rloc ( )
   if 99 - 99: OoO0O00 % IiII + I1Ii111 - oO0o
  if ( o0oOoOo00oo == None ) :
   lprint ( "Suppress sending Map-Request, translated RLOC not found" )
   return
   if 28 - 28: OOooOOo - O0 - O0 % i11iIiiIii * OoooooooOO
   if 60 - 60: OoooooooOO / i1IIi / i1IIi / Ii1I . IiII
   if 24 - 24: O0
   if 6 - 6: I1IiiI . i11iIiiIii . OoooooooOO . I1IiiI . o0oOOo0O0Ooo
   if 65 - 65: i11iIiiIii
   if 46 - 46: i11iIiiIii
   if 70 - 70: i1IIi + o0oOOo0O0Ooo
   if 44 - 44: iII111i . II111iiii % o0oOOo0O0Ooo
 if ( Ii11I111Ii11 == None or Ii11I111Ii11 . is_ipv4 ( ) ) :
  if ( lisp_nat_traversal and Ii11I111Ii11 == None ) :
   I11I111Ii1II = lisp_get_any_translated_rloc ( )
   if ( I11I111Ii1II != None ) : o0oOoOo00oo = I11I111Ii1II
   if 29 - 29: i11iIiiIii * i1IIi
  iiIIIIiI . itr_rlocs . append ( o0oOoOo00oo )
  if 36 - 36: OoO0O00 * I11i . ooOoO0o
 if ( Ii11I111Ii11 == None or Ii11I111Ii11 . is_ipv6 ( ) ) :
  if ( o0o0o0O == None or o0o0o0O . is_ipv6_link_local ( ) ) :
   o0o0o0O = None
  else :
   iiIIIIiI . itr_rloc_count = 1 if ( Ii11I111Ii11 == None ) else 0
   iiIIIIiI . itr_rlocs . append ( o0o0o0O )
   if 50 - 50: oO0o * OoOoOO00 / OoO0O00 / ooOoO0o + II111iiii
   if 55 - 55: II111iiii - IiII
   if 24 - 24: oO0o % Ii1I / i1IIi
   if 84 - 84: i1IIi
   if 53 - 53: OoooooooOO - i1IIi - Ii1I
   if 73 - 73: I1ii11iIi11i - Ii1I * o0oOOo0O0Ooo
   if 29 - 29: o0oOOo0O0Ooo % IiII % OOooOOo + OoooooooOO - o0oOOo0O0Ooo
   if 34 - 34: Ii1I
   if 5 - 5: II111iiii . I1ii11iIi11i
 if ( Ii11I111Ii11 != None and iiIIIIiI . itr_rlocs != [ ] ) :
  O00O000OO = iiIIIIiI . itr_rlocs [ 0 ]
 else :
  if ( deid . is_ipv4 ( ) ) :
   O00O000OO = o0oOoOo00oo
  elif ( deid . is_ipv6 ( ) ) :
   O00O000OO = o0o0o0O
  else :
   O00O000OO = o0oOoOo00oo
   if 85 - 85: I1Ii111 . IiII + II111iiii
   if 92 - 92: iII111i / o0oOOo0O0Ooo * oO0o . I11i % o0oOOo0O0Ooo
   if 87 - 87: Ii1I / Oo0Ooo % iIii1I11I1II1 / iII111i
   if 42 - 42: OoO0O00 . I1IiiI . OOooOOo + ooOoO0o
   if 87 - 87: OOooOOo
   if 44 - 44: Oo0Ooo + iIii1I11I1II1
 Oo00O0o0O = iiIIIIiI . encode ( Ii11I111Ii11 , i1I111Iii11iI )
 iiIIIIiI . print_map_request ( )
 if 67 - 67: iII111i . OOooOOo / ooOoO0o * iIii1I11I1II1
 if 29 - 29: I1Ii111 / OoOoOO00 % I1ii11iIi11i * IiII / II111iiii
 if 10 - 10: O0 / I11i
 if 29 - 29: i11iIiiIii % I11i
 if 49 - 49: I11i
 if 69 - 69: o0oOOo0O0Ooo . O0 * I11i
 if ( Ii11I111Ii11 != None ) :
  OOo = rloc . is_rloc_translated ( )
  if ( OOo ) :
   OOO = rloc . normalize_decent_nat_rloc_name ( )
   ooOOoO = lisp_get_nat_info ( Ii11I111Ii11 , OOO )
   if 6 - 6: iIii1I11I1II1 % Ii1I + oO0o + o0oOOo0O0Ooo - i11iIiiIii
   if 78 - 78: O0 * o0oOOo0O0Ooo - Oo0Ooo - I1Ii111
   if 33 - 33: O0
   if 28 - 28: I1ii11iIi11i * O0 * O0 % OoooooooOO % I11i
   if 48 - 48: Ii1I
   if ( ooOOoO == None ) :
    IIi1iii = rloc . rloc . print_address_no_iid ( )
    II11iIIii = "glean-{}" . format ( IIi1iii ) if lisp_i_am_rtr else "nat-{}" . format ( IIi1iii )
    if 32 - 32: O0
    I1i1I = rloc . translated_port
    ooOOoO = lisp_nat_info ( IIi1iii , II11iIIii , I1i1I )
    if 42 - 42: i1IIi * I1ii11iIi11i * OoOoOO00
    if 43 - 43: I1ii11iIi11i % I1ii11iIi11i % i1IIi
   lisp_encap_rloc_probe ( lisp_sockets , Ii11I111Ii11 , ooOOoO , Oo00O0o0O , rloc . probing_itr_rloc )
   return
   if 56 - 56: I1IiiI - OoO0O00 - iII111i . o0oOOo0O0Ooo . I1Ii111
   if 70 - 70: iIii1I11I1II1 - I11i
  if ( Ii11I111Ii11 . is_ipv4 ( ) and Ii11I111Ii11 . is_multicast_address ( ) ) :
   oOO00OoOo = Ii11I111Ii11
  else :
   O00oO000Oo0 = Ii11I111Ii11 . print_address_no_iid ( )
   oOO00OoOo = lisp_convert_4to6 ( O00oO000Oo0 )
   if 2 - 2: oO0o / II111iiii * OoO0O00
   if 71 - 71: i1IIi + I11i * OoO0O00 . OOooOOo + oO0o
   if 40 - 40: OOooOOo
   if 14 - 14: OoooooooOO - OoooooooOO % i11iIiiIii % ooOoO0o / ooOoO0o
   if 33 - 33: iII111i / i1IIi . II111iiii % I1ii11iIi11i
  lisp_rloc_probe_nonce_list [ iiIIIIiI . nonce ] = O00oO000Oo0
  if 74 - 74: iII111i / OOooOOo / O0 / iIii1I11I1II1 + IiII
  lisp_send ( lisp_sockets , oOO00OoOo , LISP_CTRL_PORT , Oo00O0o0O )
  return
  if 26 - 26: OOooOOo % i1IIi . I1Ii111 / O0 + I1Ii111
  if 39 - 39: I1ii11iIi11i * I1IiiI * II111iiii . Oo0Ooo % I1IiiI
  if 100 - 100: iIii1I11I1II1 - OoooooooOO * OoooooooOO - iII111i / ooOoO0o
  if 98 - 98: OoO0O00 + oO0o - II111iiii
  if 84 - 84: Oo0Ooo . OoOoOO00 - iII111i
  if 5 - 5: OoooooooOO . O0 / OOooOOo + I11i - Ii1I
 OooOo0OOo00O0 = None if lisp_i_am_rtr else seid
 if ( lisp_decent_pull_xtr_configured ( ) ) :
  II1iI1iII11 = lisp_get_decent_map_resolver ( deid )
 else :
  II1iI1iII11 = lisp_get_map_resolver ( None , OooOo0OOo00O0 )
  if 57 - 57: OoooooooOO * oO0o % OoooooooOO - O0
 if ( II1iI1iII11 == None ) :
  lprint ( "Cannot find Map-Resolver for source-EID {}" . format ( green ( seid . print_address ( ) , False ) ) )
  if 18 - 18: Ii1I
  return
  if 82 - 82: OoOoOO00 + OoO0O00 - IiII / ooOoO0o
 II1iI1iII11 . last_used = lisp_get_timestamp ( )
 II1iI1iII11 . map_requests_sent += 1
 if ( II1iI1iII11 . last_nonce == 0 ) : II1iI1iII11 . last_nonce = iiIIIIiI . nonce
 if 70 - 70: OoO0O00
 if 43 - 43: ooOoO0o + OOooOOo + II111iiii - I1IiiI
 if 58 - 58: I11i
 if 94 - 94: Oo0Ooo
 if ( seid == None ) : seid = O00O000OO
 lisp_send_ecm ( lisp_sockets , Oo00O0o0O , seid , lisp_ephem_port , deid ,
 II1iI1iII11 . map_resolver )
 if 39 - 39: I11i - oO0o % iII111i - ooOoO0o - OoOoOO00
 if 8 - 8: i1IIi % i1IIi % OoooooooOO % i1IIi . iIii1I11I1II1
 if 70 - 70: O0 + II111iiii % IiII / I1Ii111 - IiII
 if 58 - 58: II111iiii * oO0o - i1IIi . I11i
 lisp_last_map_request_sent = lisp_get_timestamp ( )
 if 23 - 23: OoO0O00 - I1IiiI * i11iIiiIii
 if 62 - 62: OoO0O00 . i11iIiiIii / i1IIi
 if 3 - 3: OoO0O00 + O0 % Oo0Ooo * Oo0Ooo % i11iIiiIii
 if 29 - 29: ooOoO0o / iII111i / OOooOOo - iIii1I11I1II1
 II1iI1iII11 . resolve_dns_name ( )
 return
 if 31 - 31: i1IIi * Ii1I
 if 94 - 94: oO0o / Ii1I % iIii1I11I1II1 + i1IIi / O0 - iII111i
 if 77 - 77: o0oOOo0O0Ooo - IiII . i1IIi
 if 70 - 70: i1IIi . I1Ii111 . iII111i - OoOoOO00 + II111iiii + OOooOOo
 if 52 - 52: OOooOOo . OoOoOO00 - ooOoO0o % i1IIi
 if 15 - 15: oO0o
 if 6 - 6: oO0o . iIii1I11I1II1 - I1ii11iIi11i % IiII
 if 58 - 58: iII111i * oO0o / iII111i - Oo0Ooo / I1Ii111 * oO0o
def lisp_send_info_request ( lisp_sockets , dest , port , device_name ) :
 if 63 - 63: oO0o . IiII . o0oOOo0O0Ooo
 if 16 - 16: iII111i . I11i - Oo0Ooo / I1IiiI + OoOoOO00
 if 14 - 14: iIii1I11I1II1 / i11iIiiIii - o0oOOo0O0Ooo . iII111i * OoO0O00
 if 5 - 5: Ii1I + OoOoOO00 % I11i + IiII
 OooO0OO = lisp_info ( )
 OooO0OO . nonce = lisp_get_control_nonce ( )
 if ( device_name ) : OooO0OO . hostname += "-" + device_name
 if 14 - 14: OoO0O00 + I1IiiI . o0oOOo0O0Ooo - OoO0O00 + Ii1I - Ii1I
 O00oO000Oo0 = dest . print_address_no_iid ( )
 if 98 - 98: oO0o * O0 + I11i
 if 75 - 75: i1IIi . I11i . O0 / I1ii11iIi11i / Oo0Ooo . i1IIi
 if 36 - 36: Oo0Ooo . Oo0Ooo - OOooOOo / IiII / OoooooooOO / I1IiiI
 if 7 - 7: ooOoO0o * o0oOOo0O0Ooo + ooOoO0o / Oo0Ooo % o0oOOo0O0Ooo . ooOoO0o
 Oo00O0o0O = OooO0OO . encode ( )
 OooO0OO . print_info ( )
 if 19 - 19: o0oOOo0O0Ooo % I11i . I1ii11iIi11i
 if 70 - 70: Oo0Ooo - I11i / I1ii11iIi11i % OoO0O00 % II111iiii
 if 72 - 72: i11iIiiIii * I11i
 if 69 - 69: I1Ii111 . Ii1I * I1ii11iIi11i % I11i - o0oOOo0O0Ooo
 I11I1 = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
 I11I1 = bold ( I11I1 , False )
 I1i1I = bold ( "{}" . format ( port ) , False )
 I1II1I1I = red ( O00oO000Oo0 , False )
 I11i1i1 = "RTR " if port == LISP_DATA_PORT else "MS "
 lprint ( "Send Info-Request to {}{}, port {} {}" . format ( I11i1i1 , I1II1I1I , I1i1I , I11I1 ) )
 if 83 - 83: I1ii11iIi11i / oO0o
 if 16 - 16: OoO0O00
 if 59 - 59: Ii1I
 if 23 - 23: oO0o * ooOoO0o . o0oOOo0O0Ooo + I1IiiI - O0
 Iiii = lisp_sockets [ 0 ] if port == LISP_CTRL_PORT else lisp_sockets [ 1 ]
 lisp_bind_interface ( Iiii , device_name )
 if 5 - 5: I1ii11iIi11i / OoooooooOO . Oo0Ooo % i11iIiiIii * Ii1I
 if 29 - 29: o0oOOo0O0Ooo % Ii1I . i11iIiiIii % oO0o * I1ii11iIi11i - IiII
 if 83 - 83: iII111i / II111iiii - Oo0Ooo - Oo0Ooo - OOooOOo . OoooooooOO
 if 84 - 84: iIii1I11I1II1 - ooOoO0o % iII111i % Ii1I / iII111i
 if 95 - 95: iII111i + OoooooooOO + O0 . OoOoOO00 + I1ii11iIi11i
 if 79 - 79: OoooooooOO / iII111i / IiII . OoooooooOO
 if ( port == LISP_CTRL_PORT ) :
  lisp_send ( lisp_sockets , dest , LISP_CTRL_PORT , Oo00O0o0O )
 else :
  I11 = lisp_data_header ( )
  I11 . instance_id ( 0xffffff )
  I11 = I11 . encode ( )
  if ( I11 ) :
   Oo00O0o0O = I11 + Oo00O0o0O
   if 92 - 92: I11i + O0 % II111iiii - I1ii11iIi11i + OoooooooOO . iIii1I11I1II1
   if 85 - 85: O0 - ooOoO0o
   if 35 - 35: o0oOOo0O0Ooo - I1IiiI
   if 47 - 47: i11iIiiIii * iII111i . OoOoOO00 * I1Ii111 % i11iIiiIii + Ii1I
   if 65 - 65: Ii1I % i11iIiiIii
   if 98 - 98: iII111i * o0oOOo0O0Ooo % Oo0Ooo
   if 7 - 7: oO0o * OoooooooOO % o0oOOo0O0Ooo . I1Ii111 + O0
   if 14 - 14: I11i * II111iiii % o0oOOo0O0Ooo / iII111i . OoooooooOO % iII111i
   if 88 - 88: iII111i
   lisp_send ( lisp_sockets , dest , LISP_DATA_PORT , Oo00O0o0O )
   if 94 - 94: OoooooooOO
   if 32 - 32: I1ii11iIi11i
   if 8 - 8: I11i * i11iIiiIii - ooOoO0o
   if 47 - 47: ooOoO0o . I1IiiI / i11iIiiIii * iII111i * I1IiiI
   if 8 - 8: oO0o % oO0o . iII111i / i1IIi % IiII
   if 71 - 71: OoOoOO00 + oO0o % O0 + Oo0Ooo
   if 62 - 62: i1IIi . Ii1I * i1IIi * O0 . I1IiiI % o0oOOo0O0Ooo
 lisp_unbind_interface ( Iiii )
 return
 if 16 - 16: I11i . Ii1I - ooOoO0o . OOooOOo % O0 / oO0o
 if 42 - 42: II111iiii . iII111i
 if 67 - 67: i1IIi - i11iIiiIii / ooOoO0o * oO0o
 if 64 - 64: oO0o / IiII
 if 86 - 86: I11i
 if 36 - 36: o0oOOo0O0Ooo / OoO0O00
 if 6 - 6: I11i % I1IiiI + iII111i * OoooooooOO . O0
def lisp_process_info_request ( lisp_sockets , packet , addr_str , sport , rtr_list ) :
 if 87 - 87: ooOoO0o / Ii1I % O0 . OoO0O00
 if 55 - 55: i1IIi . o0oOOo0O0Ooo % OoooooooOO + II111iiii . OoOoOO00
 if 32 - 32: IiII * I1Ii111 * Oo0Ooo . i1IIi * OoooooooOO
 if 12 - 12: I1IiiI . OOooOOo % Oo0Ooo
 OooO0OO = lisp_info ( )
 packet = OooO0OO . decode ( packet )
 if ( packet == None ) : return
 OooO0OO . print_info ( )
 if 86 - 86: i11iIiiIii
 if 57 - 57: iII111i - OoooooooOO - ooOoO0o % II111iiii
 if 62 - 62: i11iIiiIii . Oo0Ooo / Oo0Ooo . IiII . OoooooooOO
 if 86 - 86: I1ii11iIi11i * OoOoOO00 + iII111i
 if 79 - 79: I11i - II111iiii
 OooO0OO . info_reply = True
 OooO0OO . global_etr_rloc . store_address ( addr_str )
 OooO0OO . etr_port = sport
 if 27 - 27: I1IiiI + o0oOOo0O0Ooo * oO0o % I1IiiI
 if 66 - 66: OoO0O00 + IiII . o0oOOo0O0Ooo . IiII
 if 88 - 88: oO0o + oO0o % OoO0O00 . OoooooooOO - OoooooooOO . Oo0Ooo
 if 44 - 44: I1IiiI * IiII . OoooooooOO
 if 62 - 62: I11i - Ii1I / i11iIiiIii * I1IiiI + ooOoO0o + o0oOOo0O0Ooo
 if ( OooO0OO . hostname != None ) :
  OooO0OO . private_etr_rloc . afi = LISP_AFI_NAME
  OooO0OO . private_etr_rloc . store_address ( OooO0OO . hostname )
  if 10 - 10: i1IIi + o0oOOo0O0Ooo
  if 47 - 47: OOooOOo * IiII % I1Ii111 . OoOoOO00 - OoooooooOO / OoooooooOO
  if 79 - 79: I11i % i11iIiiIii % I1IiiI . OoooooooOO * oO0o . Ii1I
  if 14 - 14: iIii1I11I1II1 / I11i - o0oOOo0O0Ooo / IiII / o0oOOo0O0Ooo . OoO0O00
  if 2 - 2: I11i
  if 12 - 12: i1IIi . I1Ii111
  if 99 - 99: Oo0Ooo / i11iIiiIii
 if ( sport == 0 and lisp_i_am_etr ) :
  I1II1I1I = red ( addr_str , False )
  i1IIIiI1I = " ({})" . format ( blue ( OooO0OO . hostname , False ) ) if ( OooO0OO . hostname != None ) else ""
  lprint ( "Suppress replying to Info-Request from {}{}" . format ( I1II1I1I , i1IIIiI1I ) )
  return
  if 81 - 81: Ii1I . i1IIi % iII111i . OoO0O00 % IiII
  if 42 - 42: iII111i / Oo0Ooo
 if ( rtr_list != None ) : OooO0OO . rtr_list = rtr_list
 packet = OooO0OO . encode ( )
 OooO0OO . print_info ( )
 if 14 - 14: O0 . Oo0Ooo
 if 8 - 8: i11iIiiIii
 if 80 - 80: I1ii11iIi11i + Ii1I
 if 16 - 16: i11iIiiIii * Oo0Ooo
 if 76 - 76: iII111i . oO0o - i1IIi
 lprint ( "Send Info-Reply to {}" . format ( red ( addr_str , False ) ) )
 oOO00OoOo = lisp_convert_4to6 ( addr_str )
 lisp_send ( lisp_sockets , oOO00OoOo , sport , packet )
 if 94 - 94: O0 % iII111i
 if 90 - 90: IiII
 if 1 - 1: I1ii11iIi11i % OoOoOO00 . I1ii11iIi11i . OoooooooOO % oO0o + Ii1I
 if 46 - 46: I1IiiI + OoO0O00 - Oo0Ooo
 if 13 - 13: OoOoOO00
 Ooo0Oo0000O0O = lisp_info_source ( OooO0OO . hostname , addr_str , sport )
 Ooo0Oo0000O0O . cache_address_for_info_source ( )
 return
 if 19 - 19: iIii1I11I1II1 . I1Ii111 - i11iIiiIii - OoooooooOO . Oo0Ooo % II111iiii
 if 28 - 28: OoooooooOO / iII111i / iIii1I11I1II1
 if 72 - 72: I1ii11iIi11i - OoooooooOO
 if 5 - 5: iIii1I11I1II1 % ooOoO0o / II111iiii
 if 44 - 44: O0 % OoooooooOO
 if 6 - 6: I1IiiI / I1ii11iIi11i . I1ii11iIi11i + iIii1I11I1II1
 if 78 - 78: OOooOOo . I1Ii111
 if 60 - 60: i1IIi
def lisp_get_signature_eid ( ) :
 for Iiii1II1 in lisp_db_list :
  if ( Iiii1II1 . signature_eid ) : return ( Iiii1II1 )
  if 69 - 69: O0 * iII111i % I11i . O0 * Ii1I - I1IiiI
 return ( None )
 if 9 - 9: IiII - I1Ii111 % iIii1I11I1II1 . i1IIi / OOooOOo . i1IIi
 if 63 - 63: II111iiii . oO0o * IiII
 if 73 - 73: iII111i . i1IIi + oO0o + OOooOOo + ooOoO0o - iIii1I11I1II1
 if 47 - 47: I11i
 if 88 - 88: OoO0O00 - OoooooooOO
 if 93 - 93: Oo0Ooo * I1IiiI
 if 60 - 60: I1Ii111 + OOooOOo % iII111i
 if 40 - 40: I11i + oO0o . O0 % oO0o
def lisp_get_any_translated_port ( ) :
 for Iiii1II1 in lisp_db_list :
  for oO0o0 in Iiii1II1 . rloc_set :
   if ( oO0o0 . translated_rloc . is_null ( ) ) : continue
   return ( oO0o0 . translated_port )
   if 12 - 12: iIii1I11I1II1
   if 9 - 9: OoOoOO00 * II111iiii / o0oOOo0O0Ooo * iII111i - II111iiii / i11iIiiIii
 return ( None )
 if 14 - 14: i11iIiiIii + I1Ii111 . OoOoOO00 - oO0o * OoO0O00
 if 23 - 23: iIii1I11I1II1
 if 32 - 32: iII111i * iIii1I11I1II1 + I1Ii111 + IiII + O0 * OoO0O00
 if 100 - 100: II111iiii
 if 34 - 34: I11i % OOooOOo - iII111i % II111iiii
 if 14 - 14: I11i * o0oOOo0O0Ooo % II111iiii
 if 36 - 36: ooOoO0o - iIii1I11I1II1 / IiII + OoOoOO00
 if 42 - 42: ooOoO0o + I1IiiI * iII111i / OoOoOO00 . i1IIi - OoooooooOO
def lisp_get_translated_port_for_mr ( mr_addr ) :
 for II1iI1iII11 in list ( lisp_map_resolvers_list . values ( ) ) :
  I1II1I1I = II1iI1iII11 . map_resolver . print_address_no_iid ( )
  if ( I1II1I1I == mr_addr ) :
   if ( II1iI1iII11 . translated_port == 0 ) : return ( II1iI1iII11 , lisp_get_any_translated_port ( ) )
   return ( II1iI1iII11 , II1iI1iII11 . translated_port )
   if 8 - 8: iIii1I11I1II1 - Oo0Ooo + iII111i
   if 40 - 40: o0oOOo0O0Ooo * I1IiiI
 return ( None , lisp_get_any_translated_port ( ) )
 if 75 - 75: O0 * OOooOOo / ooOoO0o + I11i
 if 56 - 56: I1IiiI % OoooooooOO % Oo0Ooo
 if 19 - 19: i11iIiiIii - iIii1I11I1II1 . i1IIi . I1Ii111 / I1IiiI * I1Ii111
 if 41 - 41: oO0o . o0oOOo0O0Ooo . I11i * OoOoOO00
 if 16 - 16: oO0o
 if 32 - 32: OoooooooOO
 if 77 - 77: Oo0Ooo . i1IIi - I11i
 if 98 - 98: O0
 if 87 - 87: OoO0O00 % I1Ii111 - OOooOOo - II111iiii + iII111i
def lisp_get_any_translated_rloc ( ) :
 for Iiii1II1 in lisp_db_list :
  for oO0o0 in Iiii1II1 . rloc_set :
   if ( oO0o0 . translated_rloc . is_null ( ) ) : continue
   return ( oO0o0 . translated_rloc )
   if 54 - 54: i1IIi % iII111i
   if 16 - 16: II111iiii - Oo0Ooo
 return ( None )
 if 44 - 44: OOooOOo / Oo0Ooo - I1ii11iIi11i + I11i . oO0o
 if 85 - 85: iIii1I11I1II1 / Ii1I
 if 43 - 43: I1IiiI % I1Ii111 - oO0o . II111iiii / iIii1I11I1II1
 if 97 - 97: I1Ii111 + I1ii11iIi11i
 if 21 - 21: O0 + o0oOOo0O0Ooo * OoooooooOO % IiII % I1ii11iIi11i
 if 80 - 80: I11i
 if 28 - 28: OoOoOO00 * OoooooooOO * i11iIiiIii
def lisp_get_all_translated_rlocs ( ) :
 o0o0000 = [ ]
 for Iiii1II1 in lisp_db_list :
  for oO0o0 in Iiii1II1 . rloc_set :
   if ( oO0o0 . is_rloc_translated ( ) == False ) : continue
   iI1ii11Ii = oO0o0 . translated_rloc . print_address_no_iid ( )
   o0o0000 . append ( iI1ii11Ii )
   if 93 - 93: OoOoOO00
   if 55 - 55: iIii1I11I1II1 / o0oOOo0O0Ooo * I1IiiI + Oo0Ooo / Oo0Ooo * IiII
 return ( o0o0000 )
 if 65 - 65: iIii1I11I1II1 * o0oOOo0O0Ooo - iII111i % II111iiii - I1ii11iIi11i
 if 65 - 65: I11i
 if 92 - 92: iII111i . IiII + i1IIi % i1IIi
 if 11 - 11: I1ii11iIi11i + iIii1I11I1II1 - I1Ii111 * iIii1I11I1II1 * IiII + oO0o
 if 6 - 6: I1Ii111 * OOooOOo + i1IIi - Ii1I / oO0o
 if 81 - 81: I1Ii111 % oO0o * i1IIi * OoooooooOO / Oo0Ooo
 if 70 - 70: I1IiiI
 if 35 - 35: i11iIiiIii
def lisp_update_default_routes ( map_resolver , iid , rtr_list ) :
 i1Oo0o = ( os . getenv ( "LISP_RTR_BEHIND_NAT" ) != None )
 if 59 - 59: ooOoO0o . iII111i - II111iiii
 iII1ii1IiII = { }
 for iIIiIi1111iiIii in rtr_list :
  if ( iIIiIi1111iiIii == None ) : continue
  iI1ii11Ii = rtr_list [ iIIiIi1111iiIii ]
  if ( i1Oo0o and iI1ii11Ii . is_private_address ( ) ) : continue
  iII1ii1IiII [ iIIiIi1111iiIii ] = iI1ii11Ii
  if 26 - 26: Ii1I * Oo0Ooo + II111iiii + Ii1I
 rtr_list = iII1ii1IiII
 if 70 - 70: I1ii11iIi11i + i1IIi
 OoOoooOO = [ ]
 for Oo0ooooO0o00 in [ LISP_AFI_IPV4 , LISP_AFI_IPV6 , LISP_AFI_MAC ] :
  if ( Oo0ooooO0o00 == LISP_AFI_MAC and lisp_l2_overlay == False ) : break
  if 40 - 40: OoOoOO00 % OOooOOo
  if 69 - 69: iIii1I11I1II1 - OoOoOO00 % i1IIi . I1IiiI
  if 66 - 66: OOooOOo . I1Ii111 / OoOoOO00 - I1IiiI / oO0o + OoO0O00
  if 38 - 38: O0 * iIii1I11I1II1 - oO0o
  if 38 - 38: iIii1I11I1II1 / I1Ii111 + ooOoO0o . II111iiii - iIii1I11I1II1
  O0OoO0 = lisp_address ( Oo0ooooO0o00 , "" , 0 , iid )
  O0OoO0 . make_default_route ( O0OoO0 )
  IIII1 = lisp_map_cache . lookup_cache ( O0OoO0 , True )
  if ( IIII1 ) :
   if ( IIII1 . checkpoint_entry ) :
    lprint ( "Updating checkpoint entry for {}" . format ( green ( IIII1 . print_eid_tuple ( ) , False ) ) )
    if 13 - 13: Ii1I
   elif ( IIII1 . do_rloc_sets_match ( list ( rtr_list . values ( ) ) ) ) :
    continue
    if 34 - 34: I1IiiI / iIii1I11I1II1
   IIII1 . delete_cache ( )
   if 35 - 35: oO0o / oO0o
   if 86 - 86: o0oOOo0O0Ooo . Oo0Ooo - Ii1I / i11iIiiIii
  OoOoooOO . append ( [ O0OoO0 , "" ] )
  if 63 - 63: oO0o - O0 + I1ii11iIi11i + Ii1I / i1IIi
  if 77 - 77: O0
  if 49 - 49: o0oOOo0O0Ooo / i11iIiiIii
  if 36 - 36: II111iiii
  i1I1IIIiII = lisp_address ( Oo0ooooO0o00 , "" , 0 , iid )
  i1I1IIIiII . make_default_multicast_route ( i1I1IIIiII )
  oO0oooo = lisp_map_cache . lookup_cache ( i1I1IIIiII , True )
  if ( oO0oooo ) : oO0oooo = oO0oooo . source_cache . lookup_cache ( O0OoO0 , True )
  if ( oO0oooo ) : oO0oooo . delete_cache ( )
  if 1 - 1: I1ii11iIi11i % OOooOOo / oO0o
  OoOoooOO . append ( [ O0OoO0 , i1I1IIIiII ] )
  if 33 - 33: O0 / OoO0O00 / OOooOOo / II111iiii * ooOoO0o
 if ( len ( OoOoooOO ) == 0 ) : return
 if 25 - 25: O0 * o0oOOo0O0Ooo - iII111i % OoO0O00
 if 6 - 6: ooOoO0o % Oo0Ooo / I1Ii111 % i11iIiiIii * OoooooooOO + I1ii11iIi11i
 if 21 - 21: o0oOOo0O0Ooo - iII111i / OoO0O00
 if 12 - 12: I1ii11iIi11i - I11i * O0 % I1IiiI + O0 - II111iiii
 o0O00ooOo = [ ]
 for I11i1i1 in rtr_list :
  I11IiIi1 = rtr_list [ I11i1i1 ]
  oO0o0 = lisp_rloc ( )
  oO0o0 . rloc . copy_address ( I11IiIi1 )
  oOOOoO = oO0o0 . next_rloc
  while ( oOOOoO != None ) :
   oOOOoO . rloc . copy_address ( I11IiIi1 )
   oOOOoO = oOOOoO . next_rloc
   if 93 - 93: I1IiiI % I1Ii111 + OoOoOO00 * ooOoO0o - Oo0Ooo . I11i
  oO0o0 . set_active_rloc_next_hop ( )
  oO0o0 . priority = 254
  oO0o0 . mpriority = 255
  oO0o0 . rloc_name = "RTR"
  o0O00ooOo . append ( oO0o0 )
  if 23 - 23: I11i
  if 72 - 72: iII111i + iII111i + I1Ii111 * o0oOOo0O0Ooo - IiII
 for O0OoO0 in OoOoooOO :
  IIII1 = lisp_mapping ( O0OoO0 [ 0 ] , O0OoO0 [ 1 ] , o0O00ooOo )
  IIII1 . mapping_source = map_resolver
  IIII1 . map_cache_ttl = LISP_MR_TTL * 60
  IIII1 . add_cache ( )
  lprint ( "Add {} to map-cache with RTR RLOC-set: {}" . format ( green ( IIII1 . print_eid_tuple ( ) , False ) , list ( rtr_list . keys ( ) ) ) )
  if 11 - 11: IiII + Ii1I - IiII - OoO0O00
  o0O00ooOo = copy . deepcopy ( o0O00ooOo )
  if 23 - 23: I1ii11iIi11i % OOooOOo
 return
 if 82 - 82: i1IIi . I1IiiI
 if 13 - 13: O0 * iII111i
 if 26 - 26: i1IIi - I1Ii111 - ooOoO0o
 if 73 - 73: o0oOOo0O0Ooo . OoooooooOO
 if 96 - 96: i1IIi - OOooOOo / I11i % OoOoOO00 - i11iIiiIii % II111iiii
 if 47 - 47: I1Ii111 * iII111i
 if 90 - 90: i1IIi * Ii1I . OoO0O00 % I11i * ooOoO0o . OOooOOo
 if 76 - 76: iIii1I11I1II1 . i11iIiiIii * II111iiii - iII111i
 if 51 - 51: I1IiiI
 if 52 - 52: I1Ii111
def lisp_process_info_reply ( source , packet , store ) :
 if 82 - 82: iII111i + II111iiii
 if 29 - 29: O0 % Ii1I * ooOoO0o % O0
 if 83 - 83: oO0o
 if 95 - 95: Oo0Ooo * O0 % i1IIi / iII111i + oO0o
 OooO0OO = lisp_info ( )
 packet = OooO0OO . decode ( packet )
 if ( packet == None ) : return ( [ None , None , False ] )
 if 85 - 85: iIii1I11I1II1 / I11i
 OooO0OO . print_info ( )
 if 65 - 65: I11i / i1IIi * OoOoOO00 * Ii1I * OoO0O00
 if 74 - 74: I1ii11iIi11i . I1ii11iIi11i % IiII + OOooOOo . OoO0O00 * I11i
 if 20 - 20: OOooOOo % i1IIi * Ii1I / i11iIiiIii
 if 89 - 89: ooOoO0o
 O0O00OOoo00 = False
 if 32 - 32: ooOoO0o - i1IIi
 if 39 - 39: II111iiii + OoooooooOO / I11i . i11iIiiIii + I1Ii111
 if 19 - 19: I1ii11iIi11i / OOooOOo . I1IiiI / ooOoO0o + OoO0O00 + i11iIiiIii
 if 80 - 80: OoO0O00 . O0 / Ii1I % I1Ii111 / iII111i * I1IiiI
 for I11i1i1 in OooO0OO . rtr_list :
  O00oO000Oo0 = I11i1i1 . print_address_no_iid ( )
  if ( O00oO000Oo0 in lisp_rtr_list ) :
   if ( lisp_register_all_rtrs == False ) : continue
   if ( lisp_rtr_list [ O00oO000Oo0 ] != None ) : continue
   if 41 - 41: O0 / OoooooooOO - i1IIi
  O0O00OOoo00 = True
  lisp_rtr_list [ O00oO000Oo0 ] = I11i1i1
  if 6 - 6: i1IIi - I1ii11iIi11i % I1Ii111 - II111iiii / ooOoO0o / i11iIiiIii
  if 32 - 32: oO0o / IiII - I11i . ooOoO0o
  if 69 - 69: i11iIiiIii * i11iIiiIii
  if 100 - 100: I1ii11iIi11i * I1ii11iIi11i + i1IIi
  if 96 - 96: I1Ii111 / I1IiiI + ooOoO0o
 if ( lisp_i_am_itr and O0O00OOoo00 ) :
  if ( lisp_iid_to_interface == { } ) :
   lisp_update_default_routes ( source , lisp_default_iid , lisp_rtr_list )
  else :
   for i1I1iI in list ( lisp_iid_to_interface . keys ( ) ) :
    lisp_update_default_routes ( source , int ( i1I1iI ) , lisp_rtr_list )
    if 16 - 16: I1ii11iIi11i % o0oOOo0O0Ooo % OOooOOo % OoOoOO00 + ooOoO0o % I1ii11iIi11i
    if 85 - 85: oO0o * OoooooooOO * iIii1I11I1II1 + iII111i
    if 67 - 67: Ii1I / i11iIiiIii % OoOoOO00 % O0 / OoOoOO00
    if 54 - 54: I11i . OoOoOO00 / II111iiii . i1IIi + OOooOOo % II111iiii
    if 82 - 82: i11iIiiIii . OoooooooOO % OoOoOO00 * O0 - I1Ii111
    if 78 - 78: OoOoOO00 % Ii1I % OOooOOo % Oo0Ooo % I11i . Ii1I
    if 73 - 73: OoooooooOO / i1IIi . iIii1I11I1II1
 if ( lisp_i_am_itr ) :
  ooO00O0o0O0o = OooO0OO . etr_port
  O00oO000Oo0 = source . print_address_no_iid ( )
  II1iI1iII11 , iIIo0OOO = lisp_get_translated_port_for_mr ( O00oO000Oo0 )
  if ( II1iI1iII11 == None ) :
   lprint ( "Could not store translated-port {} for map-resolver {}" . format ( ooO00O0o0O0o , O00oO000Oo0 ) )
  else :
   II1iI1iII11 . translated_port = ooO00O0o0O0o
   lprint ( "Store translated-port {} for map-resolver {}" . format ( ooO00O0o0O0o , O00oO000Oo0 ) )
   if 28 - 28: OOooOOo - oO0o
   if 83 - 83: o0oOOo0O0Ooo . OoO0O00 % iIii1I11I1II1 % OoOoOO00 - i11iIiiIii
   if 71 - 71: I1ii11iIi11i - II111iiii / O0 % i1IIi + oO0o
   if 73 - 73: OoooooooOO
   if 25 - 25: i1IIi . II111iiii . I1Ii111
   if 81 - 81: II111iiii + OoOoOO00 * II111iiii / iIii1I11I1II1 - Oo0Ooo % oO0o
 if ( store == False ) :
  return ( [ OooO0OO . global_etr_rloc , OooO0OO . etr_port , O0O00OOoo00 ] )
  if 66 - 66: ooOoO0o % O0 + iIii1I11I1II1 * I1Ii111 - I1Ii111
  if 61 - 61: I1ii11iIi11i
  if 12 - 12: OoO0O00
  if 97 - 97: OOooOOo . Oo0Ooo . oO0o * i1IIi
  if 7 - 7: Oo0Ooo
  if 38 - 38: Oo0Ooo - I1ii11iIi11i
 for Iiii1II1 in lisp_db_list :
  for oO0o0 in Iiii1II1 . rloc_set :
   iIIiIi1111iiIii = oO0o0 . rloc
   oo = oO0o0 . interface
   I11I = oO0o0 . rloc_name
   if ( oO0o0 . is_decent_nat_port ( ) ) :
    I11I = I11I . split ( LISP_TP ) [ 0 ]
    if 19 - 19: Ii1I * OoO0O00 / OoO0O00 . II111iiii % iIii1I11I1II1
    if 61 - 61: I1ii11iIi11i * oO0o % iII111i + IiII + i11iIiiIii * I11i
   if ( oo == None ) :
    if ( iIIiIi1111iiIii . is_null ( ) ) : continue
    if ( iIIiIi1111iiIii . is_local ( ) == False ) : continue
    if ( OooO0OO . private_etr_rloc . is_null ( ) == False and
 iIIiIi1111iiIii . is_exact_match ( OooO0OO . private_etr_rloc ) == False ) :
     continue
     if 3 - 3: Ii1I
   elif ( OooO0OO . private_etr_rloc . is_dist_name ( ) ) :
    OoI1i1 = OooO0OO . private_etr_rloc . address
    if ( OoI1i1 != I11I ) : continue
    if 73 - 73: OoO0O00 / iII111i
    if 40 - 40: I11i + IiII * Oo0Ooo . OoooooooOO * I1IiiI
   oOOoo = green ( Iiii1II1 . eid . print_prefix ( ) , False )
   I1I111i = red ( iIIiIi1111iiIii . print_address_no_iid ( ) , False )
   if 91 - 91: ooOoO0o / oO0o * OOooOOo . II111iiii - I11i - I11i
   IiIi1i = OooO0OO . global_etr_rloc . is_exact_match ( iIIiIi1111iiIii )
   if ( oO0o0 . translated_port == 0 and IiIi1i ) :
    lprint ( "No NAT for {} ({}), EID-prefix {}" . format ( I1I111i ,
 oo , oOOoo ) )
    continue
    if 96 - 96: OoOoOO00 . O0 - ooOoO0o
    if 83 - 83: Oo0Ooo % I1IiiI % I11i
    if 54 - 54: Oo0Ooo . oO0o * I11i . i1IIi / Oo0Ooo
    if 28 - 28: I1IiiI - I1IiiI % I11i * OOooOOo
    if 97 - 97: iII111i
   I1iI1IO0O0O = OooO0OO . global_etr_rloc
   IiIIIIi1I = oO0o0 . translated_rloc
   if ( IiIIIIi1I . is_exact_match ( I1iI1IO0O0O ) and
 OooO0OO . etr_port == oO0o0 . translated_port ) : continue
   if 73 - 73: I1IiiI . OoO0O00
   lprint ( "Store translation {}:{} for {} ({}), EID-prefix {}" . format ( red ( OooO0OO . global_etr_rloc . print_address_no_iid ( ) , False ) ,
   # OoooooooOO * II111iiii
 OooO0OO . etr_port , I1I111i , oo , oOOoo ) )
   if 28 - 28: I1ii11iIi11i
   oO0o0 . rloc_name = I11I
   oO0o0 . store_translated_rloc ( OooO0OO . global_etr_rloc ,
 OooO0OO . etr_port )
   if 85 - 85: o0oOOo0O0Ooo
   O0O00OOoo00 = True
   if 20 - 20: OoooooooOO . ooOoO0o + ooOoO0o
   if 7 - 7: OoO0O00 / IiII - OoO0O00 . OOooOOo
 return ( [ OooO0OO . global_etr_rloc , OooO0OO . etr_port , O0O00OOoo00 ] )
 if 56 - 56: iIii1I11I1II1 / O0 + Oo0Ooo
 if 5 - 5: O0 / i11iIiiIii * I1IiiI % IiII * OoO0O00
 if 67 - 67: I1Ii111 . iII111i + Oo0Ooo / i11iIiiIii
 if 47 - 47: iII111i
 if 16 - 16: OoO0O00 * II111iiii + OoO0O00 % Oo0Ooo
 if 60 - 60: OOooOOo . Ii1I
 if 13 - 13: i1IIi . iII111i / OoOoOO00 . I1Ii111
 if 65 - 65: oO0o % I1Ii111 % OoO0O00 . iIii1I11I1II1
def lisp_test_mr ( lisp_sockets , port ) :
 return
 lprint ( "Test Map-Resolvers" )
 if 38 - 38: IiII / I11i / IiII * iII111i
 Ooo0O = lisp_address ( LISP_AFI_IPV4 , "" , 0 , 0 )
 iiii1I11i = lisp_address ( LISP_AFI_IPV6 , "" , 0 , 0 )
 if 65 - 65: OoOoOO00
 if 31 - 31: iIii1I11I1II1 . iIii1I11I1II1 / IiII + I1ii11iIi11i * iIii1I11I1II1 / iIii1I11I1II1
 if 100 - 100: Ii1I / I1Ii111 + I1Ii111
 if 52 - 52: iIii1I11I1II1 % OoO0O00 - IiII % i11iIiiIii - o0oOOo0O0Ooo
 Ooo0O . store_address ( "10.0.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , Ooo0O , None )
 Ooo0O . store_address ( "192.168.0.1" )
 lisp_send_map_request ( lisp_sockets , port , None , Ooo0O , None )
 if 25 - 25: Oo0Ooo - OOooOOo . i1IIi * OoOoOO00 / I11i / o0oOOo0O0Ooo
 if 54 - 54: OoOoOO00 / i1IIi + OOooOOo - I1ii11iIi11i - I1IiiI * I1Ii111
 if 91 - 91: OoooooooOO * OoooooooOO
 if 27 - 27: ooOoO0o / I1IiiI * I1ii11iIi11i . o0oOOo0O0Ooo
 iiii1I11i . store_address ( "0100::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iiii1I11i , None )
 iiii1I11i . store_address ( "8000::1" )
 lisp_send_map_request ( lisp_sockets , port , None , iiii1I11i , None )
 if 30 - 30: o0oOOo0O0Ooo / i11iIiiIii
 if 33 - 33: OOooOOo % OoooooooOO
 if 98 - 98: Ii1I
 if 38 - 38: ooOoO0o - iII111i * OOooOOo % I1ii11iIi11i + Oo0Ooo
 oo0ooo0 = threading . Timer ( LISP_TEST_MR_INTERVAL , lisp_test_mr ,
 [ lisp_sockets , port ] )
 oo0ooo0 . start ( )
 return
 if 97 - 97: I11i * OOooOOo . I1IiiI * OoO0O00 / I1IiiI
 if 34 - 34: OoooooooOO * ooOoO0o / ooOoO0o + I1IiiI
 if 61 - 61: oO0o
 if 56 - 56: Oo0Ooo
 if 52 - 52: oO0o . ooOoO0o
 if 68 - 68: OOooOOo + I11i % iIii1I11I1II1 % I1IiiI
 if 32 - 32: oO0o * i11iIiiIii - I11i % Oo0Ooo * I1ii11iIi11i
 if 79 - 79: II111iiii / Oo0Ooo / I1ii11iIi11i
 if 30 - 30: I11i . o0oOOo0O0Ooo / II111iiii
 if 59 - 59: i11iIiiIii
 if 5 - 5: i11iIiiIii + o0oOOo0O0Ooo . OoO0O00 % OoOoOO00 + I11i
 if 59 - 59: I1ii11iIi11i
 if 47 - 47: I1IiiI + Oo0Ooo
def lisp_update_local_rloc ( rloc ) :
 if ( rloc . interface == None ) : return
 if 78 - 78: i1IIi / I1ii11iIi11i % ooOoO0o * OoO0O00
 iI1ii11Ii = lisp_get_interface_address ( rloc . interface )
 if ( iI1ii11Ii == None ) : return
 if 10 - 10: i1IIi % ooOoO0o / iII111i
 O0OO = rloc . rloc . print_address_no_iid ( )
 i11Ii111Ii = iI1ii11Ii . print_address_no_iid ( )
 if 64 - 64: oO0o - iII111i
 if ( O0OO == i11Ii111Ii ) : return
 if 34 - 34: OoOoOO00 * Oo0Ooo . O0 . I1IiiI * I11i
 lprint ( "Local interface address changed on {} from {} to {}" . format ( rloc . interface , O0OO , i11Ii111Ii ) )
 if 15 - 15: O0
 if 21 - 21: OoOoOO00 * OOooOOo + oO0o + O0
 rloc . rloc . copy_address ( iI1ii11Ii )
 lisp_myrlocs [ 0 ] = iI1ii11Ii
 return
 if 59 - 59: i1IIi / OoooooooOO . OoO0O00 / OOooOOo % o0oOOo0O0Ooo - i11iIiiIii
 if 58 - 58: IiII . Ii1I + II111iiii
 if 31 - 31: i11iIiiIii + i11iIiiIii + I11i * Oo0Ooo . I11i
 if 28 - 28: OOooOOo * iIii1I11I1II1 * OoOoOO00
 if 75 - 75: Oo0Ooo % IiII + II111iiii + oO0o
 if 35 - 35: I1ii11iIi11i - oO0o - O0 / iII111i % IiII
 if 10 - 10: OOooOOo + oO0o - I1Ii111 . I1IiiI
 if 11 - 11: I1ii11iIi11i . I1Ii111 / o0oOOo0O0Ooo + IiII
def lisp_update_encap_port ( mc ) :
 for iIIiIi1111iiIii in mc . rloc_set :
  OOO = iIIiIi1111iiIii . normalize_decent_nat_rloc_name ( )
  ooOOoO = lisp_get_nat_info ( iIIiIi1111iiIii . rloc , OOO )
  if ( ooOOoO == None ) : continue
  if ( iIIiIi1111iiIii . translated_port == ooOOoO . port ) : continue
  if 73 - 73: OoO0O00 . i11iIiiIii * OoO0O00 * i1IIi + I11i
  lprint ( ( "Encap-port changed from {} to {} for RLOC {}, " + "EID-prefix {}" ) . format ( iIIiIi1111iiIii . translated_port , ooOOoO . port ,
  # i1IIi * i11iIiiIii
 red ( iIIiIi1111iiIii . rloc . print_address_no_iid ( ) , False ) ,
 green ( mc . print_eid_tuple ( ) , False ) ) )
  if 81 - 81: O0 / II111iiii . OOooOOo
  iIIiIi1111iiIii . store_translated_rloc ( iIIiIi1111iiIii . rloc , ooOOoO . port )
  if 75 - 75: i1IIi - oO0o * Ii1I / iIii1I11I1II1 - O0 - ooOoO0o
 return
 if 88 - 88: ooOoO0o / ooOoO0o . I11i
 if 2 - 2: OoO0O00 * OoO0O00 * Ii1I + iII111i + OOooOOo - II111iiii
 if 76 - 76: II111iiii * o0oOOo0O0Ooo - IiII
 if 93 - 93: iIii1I11I1II1 % Ii1I * Ii1I + i11iIiiIii . o0oOOo0O0Ooo / iII111i
 if 7 - 7: ooOoO0o
 if 11 - 11: iII111i . oO0o % I11i
 if 42 - 42: I1ii11iIi11i
 if 77 - 77: iIii1I11I1II1 * i11iIiiIii + Ii1I . ooOoO0o / OOooOOo * O0
 if 44 - 44: Oo0Ooo * o0oOOo0O0Ooo - I11i
 if 56 - 56: Ii1I * OoO0O00 % ooOoO0o . I11i % I1Ii111
 if 78 - 78: i1IIi * OOooOOo . I1ii11iIi11i . iIii1I11I1II1 + i1IIi % Ii1I
 if 31 - 31: iII111i + Oo0Ooo / I1ii11iIi11i / I1IiiI * OoooooooOO . I1ii11iIi11i
def lisp_timeout_map_cache_entry ( mc , delete_list ) :
 if ( mc . map_cache_ttl == None ) :
  lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 100 - 100: iIii1I11I1II1 . i1IIi / OOooOOo * i11iIiiIii
  if 93 - 93: I1ii11iIi11i
 O0OoOOo = lisp_get_timestamp ( )
 iIIi1IIiI1111 = mc . last_refresh_time
 if 47 - 47: i11iIiiIii - O0 / I1Ii111 + o0oOOo0O0Ooo % OoooooooOO
 if 5 - 5: OOooOOo * I1ii11iIi11i
 if 63 - 63: Ii1I - II111iiii % OoOoOO00 . I11i - i1IIi
 if 31 - 31: I1IiiI . I1Ii111 - OoooooooOO / i1IIi
 if 89 - 89: I1ii11iIi11i
 if 55 - 55: o0oOOo0O0Ooo * Oo0Ooo . ooOoO0o
 if 25 - 25: IiII . O0 / OoOoOO00
 if ( lisp_is_running ( "lisp-ms" ) and lisp_uptime + ( 5 * 60 ) >= O0OoOOo ) :
  if ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
   iIIi1IIiI1111 = 0
   lprint ( "Remove startup-mode native-forward map-cache entry" )
   if 33 - 33: OoO0O00
   if 55 - 55: ooOoO0o + ooOoO0o
   if 93 - 93: oO0o - I1IiiI / I1ii11iIi11i % o0oOOo0O0Ooo / OoooooooOO + II111iiii
   if 10 - 10: o0oOOo0O0Ooo - iII111i . O0 + OoO0O00 - Oo0Ooo - i11iIiiIii
   if 37 - 37: iIii1I11I1II1
   if 37 - 37: II111iiii % OoOoOO00 . IiII * ooOoO0o . I1IiiI
   if 25 - 25: OoooooooOO % i1IIi . I1Ii111 / OoOoOO00 - I1ii11iIi11i
 i1I = ( mc . action != LISP_NOT_REGISTERED_YET_ACTION )
 if 5 - 5: IiII * Ii1I - I1IiiI
 if 81 - 81: oO0o . OOooOOo - Ii1I . OoOoOO00
 if 100 - 100: Ii1I * i1IIi * i1IIi - iII111i + OoO0O00 + OoO0O00
 if 9 - 9: oO0o / OoO0O00 . I1IiiI
 if 24 - 24: IiII * i11iIiiIii % o0oOOo0O0Ooo - ooOoO0o + ooOoO0o . II111iiii
 if 69 - 69: I1IiiI . i11iIiiIii - o0oOOo0O0Ooo
 if ( i1I and iIIi1IIiI1111 + mc . map_cache_ttl > O0OoOOo ) :
  if ( mc . action == LISP_NO_ACTION ) : lisp_update_encap_port ( mc )
  return ( [ True , delete_list ] )
  if 40 - 40: OOooOOo * Ii1I
  if 38 - 38: ooOoO0o
  if 5 - 5: OoooooooOO + iII111i - I11i
  if 95 - 95: OOooOOo / i11iIiiIii - Ii1I + I1ii11iIi11i
  if 7 - 7: I1ii11iIi11i
 if ( lisp_nat_traversal and mc . eid . address == 0 and mc . eid . mask_len == 0 ) :
  return ( [ True , delete_list ] )
  if 37 - 37: O0 . II111iiii
  if 70 - 70: o0oOOo0O0Ooo / iII111i + i1IIi + I11i % iIii1I11I1II1 % Oo0Ooo
  if 1 - 1: O0 + OoO0O00 . i11iIiiIii + I1Ii111 - OoO0O00 - IiII
  if 1 - 1: I1ii11iIi11i / i1IIi . I1IiiI / Ii1I
  if 19 - 19: iIii1I11I1II1 / Oo0Ooo . O0 - Oo0Ooo
 oOoo0O0OO00O0 = lisp_print_elapsed ( mc . uptime )
 IIIii1I1I = lisp_print_elapsed ( mc . last_refresh_time )
 I1iii = mc . print_eid_tuple ( )
 lprint ( ( "Map-cache entry {} {}, had uptime {}, last-refresh-time {}, " + "action was {}" ) . format ( green ( I1iii , False ) ,
 # O0
 bold ( "timed out" , False ) , oOoo0O0OO00O0 , IIIii1I1I ,
 lisp_map_reply_action_string [ mc . action ] ) )
 if 69 - 69: I1IiiI % Ii1I - OoooooooOO / iIii1I11I1II1 * OoooooooOO
 if 70 - 70: o0oOOo0O0Ooo % OoooooooOO % I1IiiI . OoOoOO00 * I1IiiI - ooOoO0o
 if 92 - 92: I1IiiI . I11i
 if 66 - 66: I1Ii111 / I11i / OoooooooOO % OoOoOO00 . oO0o * iII111i
 delete_list . append ( mc )
 return ( [ True , delete_list ] )
 if 34 - 34: I1ii11iIi11i * I1ii11iIi11i % I11i / OOooOOo % oO0o . OoOoOO00
 if 25 - 25: I1ii11iIi11i / I11i + i1IIi . I1IiiI + ooOoO0o
 if 29 - 29: IiII + I1ii11iIi11i
 if 8 - 8: IiII % I1IiiI
 if 10 - 10: OoooooooOO / OoOoOO00
 if 77 - 77: OoOoOO00
 if 10 - 10: IiII / i11iIiiIii
 if 19 - 19: OoO0O00
def lisp_timeout_map_cache_walk ( mc , parms ) :
 O0O0OOOo0 = parms [ 0 ]
 oOOOo0o0o = parms [ 1 ]
 if 77 - 77: OoO0O00 - I1Ii111 * i1IIi
 if 54 - 54: I1Ii111 . oO0o % OoOoOO00 * I1IiiI
 if 20 - 20: iII111i % I1IiiI % iIii1I11I1II1 * I1ii11iIi11i / iII111i
 if 79 - 79: iII111i % II111iiii - Oo0Ooo - I1Ii111 - OoooooooOO
 if ( mc . group . is_null ( ) ) :
  i1oO0000OOO0O , O0O0OOOo0 = lisp_timeout_map_cache_entry ( mc , O0O0OOOo0 )
  if ( O0O0OOOo0 == [ ] or mc != O0O0OOOo0 [ - 1 ] ) :
   oOOOo0o0o = lisp_write_checkpoint_entry ( oOOOo0o0o , mc )
   parms [ 1 ] = oOOOo0o0o
   if 9 - 9: ooOoO0o . O0
  parms [ 0 ] = O0O0OOOo0
  return ( [ i1oO0000OOO0O , parms ] )
  if 5 - 5: I11i % I1IiiI - OoO0O00 . Oo0Ooo
 if ( mc . source_cache == None ) : return ( [ True , parms ] )
 if 79 - 79: iII111i + IiII % I11i . Oo0Ooo / IiII * iII111i
 if 40 - 40: iII111i - I1IiiI + OoOoOO00
 if 2 - 2: I11i - II111iiii / I1Ii111
 if 27 - 27: OoO0O00 - I1ii11iIi11i * i11iIiiIii + Oo0Ooo
 O0O0OOOo0 = mc . source_cache . walk_cache ( lisp_timeout_map_cache_entry , O0O0OOOo0 )
 parms [ 0 ] = O0O0OOOo0
 return ( [ True , parms ] )
 if 29 - 29: I1ii11iIi11i / IiII . I1Ii111 + Ii1I + OoO0O00
 if 76 - 76: ooOoO0o . I11i * OoO0O00
 if 53 - 53: II111iiii / OoOoOO00 / IiII * oO0o
 if 52 - 52: O0 % iII111i * iIii1I11I1II1 / I11i / I1IiiI * ooOoO0o
 if 93 - 93: iIii1I11I1II1 . II111iiii * OOooOOo - iIii1I11I1II1 . oO0o % Oo0Ooo
 if 92 - 92: OoO0O00
 if 42 - 42: I1ii11iIi11i - iIii1I11I1II1 % ooOoO0o
def lisp_timeout_map_cache ( lisp_map_cache ) :
 i1 = [ [ ] , [ ] ]
 i1 = lisp_map_cache . walk_cache ( lisp_timeout_map_cache_walk , i1 )
 if 7 - 7: Oo0Ooo / ooOoO0o + o0oOOo0O0Ooo
 if 38 - 38: o0oOOo0O0Ooo . O0 - OoO0O00 % I11i
 if 80 - 80: o0oOOo0O0Ooo
 if 100 - 100: iIii1I11I1II1 . OoOoOO00 . OoooooooOO / I1ii11iIi11i - I1IiiI * I11i
 if 5 - 5: i1IIi * o0oOOo0O0Ooo - I1Ii111 + I1IiiI - II111iiii
 O0O0OOOo0 = i1 [ 0 ]
 for IIII1 in O0O0OOOo0 : IIII1 . delete_cache ( )
 if 15 - 15: I1Ii111
 if 38 - 38: O0
 if 50 - 50: i11iIiiIii * OoO0O00 + iII111i / O0 * oO0o % ooOoO0o
 if 6 - 6: OoO0O00 . o0oOOo0O0Ooo / Ii1I + Ii1I
 oOOOo0o0o = i1 [ 1 ]
 lisp_checkpoint ( oOOOo0o0o )
 return
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
 if 11 - 11: Oo0Ooo + I1IiiI % i11iIiiIii % Oo0Ooo + ooOoO0o + i1IIi
 if 100 - 100: II111iiii - OOooOOo + iII111i - i11iIiiIii . O0 / iII111i
 if 64 - 64: Ii1I
 if 4 - 4: OoOoOO00
 if 78 - 78: i1IIi - iII111i + O0 - I1IiiI % o0oOOo0O0Ooo
def lisp_store_nat_info ( hostname , rloc , port ) :
 O00oO000Oo0 = rloc . print_address_no_iid ( )
 I11iI1i1 = "{} NAT state for {}, RLOC {}, port {}" . format ( "{}" ,
 blue ( hostname , False ) , red ( O00oO000Oo0 , False ) , port )
 if 48 - 48: i1IIi + iII111i - Ii1I
 i1IIiIi1 = lisp_nat_info ( O00oO000Oo0 , hostname , port )
 if 9 - 9: II111iiii * Oo0Ooo * I1Ii111 . IiII
 if ( hostname not in lisp_nat_state_info ) :
  lisp_nat_state_info [ hostname ] = [ i1IIiIi1 ]
  lprint ( I11iI1i1 . format ( "Store initial" ) )
  return ( True )
  if 80 - 80: i11iIiiIii . i11iIiiIii . i11iIiiIii . OoooooooOO - OOooOOo * OoooooooOO
  if 96 - 96: oO0o
  if 80 - 80: IiII - oO0o % Ii1I - iIii1I11I1II1 . OoO0O00
  if 64 - 64: I1IiiI % i11iIiiIii / oO0o
  if 78 - 78: II111iiii - Oo0Ooo . iIii1I11I1II1 - ooOoO0o . oO0o
  if 84 - 84: iII111i . ooOoO0o * I1IiiI * Oo0Ooo / I1Ii111
 ooOOoO = lisp_nat_state_info [ hostname ] [ 0 ]
 if ( ooOOoO . address == O00oO000Oo0 and ooOOoO . port == port ) :
  ooOOoO . uptime = lisp_get_timestamp ( )
  lprint ( I11iI1i1 . format ( "Refresh existing" ) )
  return ( False )
  if 93 - 93: i1IIi * i11iIiiIii % OoOoOO00 % iII111i
  if 31 - 31: OoO0O00
  if 89 - 89: II111iiii
  if 33 - 33: OOooOOo / oO0o % OoOoOO00 * O0
  if 65 - 65: OoO0O00 % OoOoOO00 % I1ii11iIi11i / OoooooooOO
  if 85 - 85: O0 * OOooOOo % I1Ii111
  if 33 - 33: O0
 i11Iiiii11 = None
 for ooOOoO in lisp_nat_state_info [ hostname ] :
  if ( ooOOoO . address == O00oO000Oo0 and ooOOoO . port == port ) :
   i11Iiiii11 = ooOOoO
   break
   if 30 - 30: II111iiii . O0 . oO0o * I1ii11iIi11i + oO0o . o0oOOo0O0Ooo
   if 43 - 43: iIii1I11I1II1
   if 88 - 88: I1IiiI - OoO0O00 . O0 . oO0o
 if ( i11Iiiii11 == None ) :
  lprint ( I11iI1i1 . format ( "Store new" ) )
 else :
  lisp_nat_state_info [ hostname ] . remove ( i11Iiiii11 )
  lprint ( I11iI1i1 . format ( "Use previous" ) )
  if 75 - 75: II111iiii % OOooOOo / iIii1I11I1II1 / OoO0O00 + oO0o
  if 16 - 16: oO0o + I1Ii111 - II111iiii - o0oOOo0O0Ooo / i11iIiiIii
 oOO0O00O0 = lisp_nat_state_info [ hostname ]
 lisp_nat_state_info [ hostname ] = [ i1IIiIi1 ] + oOO0O00O0
 return ( True )
 if 69 - 69: o0oOOo0O0Ooo * OOooOOo - ooOoO0o
 if 14 - 14: o0oOOo0O0Ooo . OoooooooOO - I1ii11iIi11i * iII111i / ooOoO0o
 if 99 - 99: I1ii11iIi11i + I11i
 if 29 - 29: I1ii11iIi11i / oO0o
 if 2 - 2: Oo0Ooo / IiII - OoooooooOO
 if 65 - 65: OoO0O00 - Ii1I
 if 98 - 98: OoOoOO00 * I1Ii111 * iIii1I11I1II1 * OoOoOO00
 if 15 - 15: Oo0Ooo
def lisp_get_nat_info ( rloc , hostname ) :
 O00oO000Oo0 = rloc . print_address_no_iid ( )
 if 100 - 100: IiII + I1ii11iIi11i + iII111i . i1IIi . I1ii11iIi11i / OoooooooOO
 if ( hostname == None ) :
  for hostname in lisp_nat_state_info :
   for ooOOoO in lisp_nat_state_info [ hostname ] :
    if ( ooOOoO . address == O00oO000Oo0 ) : return ( ooOOoO )
    if 84 - 84: o0oOOo0O0Ooo * I11i
    if 22 - 22: i1IIi + OOooOOo % OoooooooOO
  return ( None )
  if 34 - 34: oO0o / O0 - II111iiii % Oo0Ooo + I11i
  if 23 - 23: o0oOOo0O0Ooo + i11iIiiIii . I1IiiI + iIii1I11I1II1
 if ( hostname not in lisp_nat_state_info ) : return ( None )
 if 18 - 18: o0oOOo0O0Ooo . O0 + I1Ii111
 for ooOOoO in lisp_nat_state_info [ hostname ] :
  if ( ooOOoO . address == O00oO000Oo0 ) : return ( ooOOoO )
  if 66 - 66: OoooooooOO
 return ( None )
 if 90 - 90: IiII - OoOoOO00
 if 98 - 98: Oo0Ooo / oO0o . Ii1I
 if 56 - 56: ooOoO0o % OoO0O00 * i11iIiiIii % IiII % I1IiiI - oO0o
 if 37 - 37: iII111i - Ii1I . oO0o
 if 47 - 47: IiII / I1ii11iIi11i . o0oOOo0O0Ooo . ooOoO0o + OOooOOo . OOooOOo
 if 25 - 25: oO0o
 if 43 - 43: Ii1I - o0oOOo0O0Ooo % oO0o - O0
 if 20 - 20: OoO0O00 . ooOoO0o / OoOoOO00 - OoOoOO00 . iII111i / OOooOOo
 if 39 - 39: iIii1I11I1II1 % ooOoO0o
 if 75 - 75: i1IIi * II111iiii * O0 * i11iIiiIii % iII111i / iII111i
 if 36 - 36: IiII / I1IiiI % iII111i / iII111i
 if 38 - 38: OOooOOo * I1ii11iIi11i * I1Ii111 + I11i
 if 65 - 65: O0 + O0 * I1Ii111
 if 66 - 66: OOooOOo / O0 + i1IIi . O0 % I1ii11iIi11i - OoooooooOO
 if 16 - 16: I11i % iII111i
 if 29 - 29: I1IiiI - ooOoO0o * OoO0O00 . i11iIiiIii % OoOoOO00 * o0oOOo0O0Ooo
 if 43 - 43: OoO0O00 * OOooOOo / I1Ii111 % OoOoOO00 . oO0o / OOooOOo
 if 62 - 62: O0 * I1ii11iIi11i - O0 / I11i % ooOoO0o
 if 1 - 1: O0 / iIii1I11I1II1
 if 17 - 17: OoOoOO00 + ooOoO0o * II111iiii * OoOoOO00 + I1IiiI + i11iIiiIii
def lisp_build_info_requests ( lisp_sockets , dest , port ) :
 if ( lisp_nat_traversal == False ) : return
 if 46 - 46: i1IIi - II111iiii . I1IiiI . i11iIiiIii
 if 54 - 54: O0 * I1ii11iIi11i / OOooOOo / IiII * IiII
 if 69 - 69: Oo0Ooo * OoooooooOO / I1IiiI
 if 16 - 16: o0oOOo0O0Ooo
 if 3 - 3: i11iIiiIii . I1ii11iIi11i
 if 65 - 65: II111iiii * iII111i - OoO0O00 + oO0o % OoO0O00
 OooOO0o0O00 = [ ]
 o0O000Oo = [ ]
 if ( dest == None ) :
  for II1iI1iII11 in list ( lisp_map_resolvers_list . values ( ) ) :
   o0O000Oo . append ( II1iI1iII11 . map_resolver )
   if 100 - 100: iII111i . o0oOOo0O0Ooo - I1Ii111 % oO0o
  OooOO0o0O00 = o0O000Oo
  if ( OooOO0o0O00 == [ ] ) :
   for oOO0 in list ( lisp_map_servers_list . values ( ) ) :
    OooOO0o0O00 . append ( oOO0 . map_server )
    if 11 - 11: o0oOOo0O0Ooo . OoooooooOO - i1IIi
    if 71 - 71: I1IiiI . OOooOOo . I1ii11iIi11i
  if ( OooOO0o0O00 == [ ] ) : return
 else :
  OooOO0o0O00 . append ( dest )
  if 90 - 90: i11iIiiIii + I1Ii111 % II111iiii
  if 67 - 67: OoOoOO00 / iII111i * OoO0O00 % i11iIiiIii
  if 76 - 76: OoO0O00
  if 92 - 92: iIii1I11I1II1 * O0 % I11i
  if 92 - 92: OoOoOO00 + oO0o
 o0o0000 = { }
 for Iiii1II1 in lisp_db_list :
  for oO0o0 in Iiii1II1 . rloc_set :
   lisp_update_local_rloc ( oO0o0 )
   if ( oO0o0 . rloc . is_null ( ) ) : continue
   if ( oO0o0 . interface == None ) : continue
   if 89 - 89: IiII % iII111i / iIii1I11I1II1 . Ii1I . Oo0Ooo + ooOoO0o
   iI1ii11Ii = oO0o0 . rloc . print_address_no_iid ( )
   if ( iI1ii11Ii in o0o0000 ) : continue
   o0o0000 [ iI1ii11Ii ] = oO0o0 . interface
   if 28 - 28: I1IiiI . iIii1I11I1II1
   if 12 - 12: I1Ii111 * OOooOOo
 if ( o0o0000 == { } ) :
  lprint ( 'Suppress Info-Request, no "interface = <device>" RLOC ' + "found in any database-mappings" )
  if 11 - 11: II111iiii % O0 % O0 % o0oOOo0O0Ooo
  return
  if 45 - 45: OoooooooOO * oO0o
  if 74 - 74: ooOoO0o * I11i / oO0o - IiII + OoOoOO00
 if ( len ( o0o0000 ) > 1 ) :
  lprint ( "NAT multihoming local RLOC-list {}" . format ( o0o0000 ) )
  if 16 - 16: Oo0Ooo
  if 29 - 29: Oo0Ooo . I1ii11iIi11i / II111iiii / oO0o / o0oOOo0O0Ooo + I11i
  if 4 - 4: OoooooooOO % I1ii11iIi11i . OoO0O00 * o0oOOo0O0Ooo + I1ii11iIi11i * IiII
  if 67 - 67: I1IiiI
  if 93 - 93: ooOoO0o . Ii1I + IiII / Oo0Ooo % I11i
  if 40 - 40: Oo0Ooo % OoOoOO00 . IiII / I1IiiI % OoooooooOO
 for iI1ii11Ii in o0o0000 :
  oo = o0o0000 [ iI1ii11Ii ]
  I1II1I1I = red ( iI1ii11Ii , False )
  lprint ( "Build Info-Request for private address {} on {}" . format ( I1II1I1I ,
 oo ) )
  ooOooO = oo if len ( o0o0000 ) > 1 else None
  for dest in OooOO0o0O00 :
   lisp_send_info_request ( lisp_sockets , dest , port , ooOooO )
   if 33 - 33: OOooOOo - OoooooooOO . iII111i
   if 2 - 2: I11i + i1IIi
   if 52 - 52: I11i - OoO0O00 % I1Ii111 . OOooOOo
   if 90 - 90: O0 - Oo0Ooo / i1IIi * iIii1I11I1II1 % o0oOOo0O0Ooo / oO0o
   if 73 - 73: iII111i % iIii1I11I1II1 + o0oOOo0O0Ooo % Ii1I . II111iiii + IiII
   if 55 - 55: OoOoOO00 * II111iiii / iII111i + OOooOOo / OoooooooOO
 if ( o0O000Oo != [ ] ) :
  for II1iI1iII11 in list ( lisp_map_resolvers_list . values ( ) ) :
   II1iI1iII11 . resolve_dns_name ( )
   if 12 - 12: II111iiii * O0 - Oo0Ooo + o0oOOo0O0Ooo . Oo0Ooo + iIii1I11I1II1
   if 4 - 4: I1Ii111 - I1Ii111 / I1ii11iIi11i . i1IIi + I1ii11iIi11i / oO0o
 return
 if 18 - 18: iIii1I11I1II1 . ooOoO0o
 if 68 - 68: o0oOOo0O0Ooo
 if 36 - 36: Oo0Ooo . I11i + I1IiiI * i1IIi % Ii1I + OOooOOo
 if 5 - 5: o0oOOo0O0Ooo % oO0o / OoO0O00
 if 17 - 17: OoooooooOO - I1ii11iIi11i / OoO0O00 - I1Ii111 + i1IIi
 if 6 - 6: Oo0Ooo - II111iiii
 if 33 - 33: I1Ii111 - I1IiiI + iII111i . OoOoOO00
 if 91 - 91: OOooOOo / Ii1I / IiII * OOooOOo
def lisp_valid_address_format ( kw , value ) :
 if ( kw != "address" ) : return ( True )
 if 68 - 68: I11i
 if 91 - 91: I11i
 if 24 - 24: ooOoO0o . i1IIi - O0 + I11i
 if 71 - 71: OoOoOO00
 if 29 - 29: O0 . i11iIiiIii
 if ( value [ 0 ] == "'" and value [ - 1 ] == "'" ) : return ( True )
 if 51 - 51: IiII
 if 53 - 53: O0
 if 19 - 19: o0oOOo0O0Ooo / iII111i % OoOoOO00
 if 65 - 65: o0oOOo0O0Ooo
 if ( value . find ( "." ) != - 1 ) :
  iI1ii11Ii = value . split ( "." )
  if ( len ( iI1ii11Ii ) != 4 ) : return ( False )
  if 89 - 89: iIii1I11I1II1 + OoooooooOO + i1IIi + OoooooooOO % IiII * OoO0O00
  for oooooOOOO0oOo in iI1ii11Ii :
   if ( oooooOOOO0oOo . isdigit ( ) == False ) : return ( False )
   if ( int ( oooooOOOO0oOo ) > 255 ) : return ( False )
   if 53 - 53: OOooOOo . IiII % I11i - OoO0O00 - Oo0Ooo
  return ( True )
  if 58 - 58: I1Ii111 / OoooooooOO . I11i % I1Ii111
  if 8 - 8: Oo0Ooo % ooOoO0o / i11iIiiIii
  if 54 - 54: IiII
  if 85 - 85: OOooOOo - i1IIi
  if 10 - 10: I1ii11iIi11i
 if ( value . find ( "-" ) != - 1 ) :
  iI1ii11Ii = value . split ( "-" )
  for o000o0O0Oo00 in [ "N" , "S" , "W" , "E" ] :
   if ( o000o0O0Oo00 in iI1ii11Ii ) :
    if ( len ( iI1ii11Ii ) < 8 ) : return ( False )
    return ( True )
    if 3 - 3: ooOoO0o * O0 / o0oOOo0O0Ooo
    if 22 - 22: OoOoOO00 + OOooOOo . iII111i % iIii1I11I1II1 - I11i
    if 23 - 23: OoOoOO00 * I1Ii111
    if 18 - 18: o0oOOo0O0Ooo % i11iIiiIii . Ii1I . O0
    if 85 - 85: I1ii11iIi11i * iIii1I11I1II1 + o0oOOo0O0Ooo * OoO0O00
    if 25 - 25: o0oOOo0O0Ooo / Ii1I / Oo0Ooo . ooOoO0o - ooOoO0o * O0
    if 14 - 14: O0 - Ii1I + iIii1I11I1II1 + II111iiii . ooOoO0o + Ii1I
 if ( value . find ( "-" ) != - 1 ) :
  iI1ii11Ii = value . split ( "-" )
  if ( len ( iI1ii11Ii ) != 3 ) : return ( False )
  if 25 - 25: OoO0O00 * oO0o
  for III11iiiI in iI1ii11Ii :
   try : int ( III11iiiI , 16 )
   except : return ( False )
   if 78 - 78: ooOoO0o
  return ( True )
  if 11 - 11: ooOoO0o + oO0o + i1IIi + iII111i + IiII
  if 51 - 51: ooOoO0o - Ii1I % oO0o
  if 42 - 42: iII111i * OoooooooOO
  if 63 - 63: II111iiii
  if 73 - 73: Oo0Ooo + II111iiii - IiII
 if ( value . find ( ":" ) != - 1 ) :
  iI1ii11Ii = value . split ( ":" )
  if ( len ( iI1ii11Ii ) < 2 ) : return ( False )
  if 60 - 60: i1IIi . i11iIiiIii / i1IIi . I11i % OOooOOo
  II1111 = False
  o00oOoo0o00 = 0
  for III11iiiI in iI1ii11Ii :
   o00oOoo0o00 += 1
   if ( III11iiiI == "" ) :
    if ( II1111 ) :
     if ( len ( iI1ii11Ii ) == o00oOoo0o00 ) : break
     if ( o00oOoo0o00 > 2 ) : return ( False )
     if 65 - 65: O0 % OOooOOo * ooOoO0o * II111iiii
    II1111 = True
    continue
    if 9 - 9: Oo0Ooo * Ii1I
   try : int ( III11iiiI , 16 )
   except : return ( False )
   if 17 - 17: OoOoOO00
  return ( True )
  if 28 - 28: oO0o
  if 45 - 45: I1Ii111 % OoOoOO00 / I1Ii111 % OoO0O00 . I1IiiI
  if 100 - 100: OoO0O00 - Ii1I + i1IIi / o0oOOo0O0Ooo / IiII
  if 85 - 85: OoOoOO00
  if 90 - 90: o0oOOo0O0Ooo . OoOoOO00 - i11iIiiIii * IiII
 if ( value [ 0 ] == "+" ) :
  iI1ii11Ii = value [ 1 : : ]
  for Iii1i11i in iI1ii11Ii :
   if ( Iii1i11i . isdigit ( ) == False ) : return ( False )
   if 30 - 30: iIii1I11I1II1 * OoooooooOO . I1ii11iIi11i . i11iIiiIii . I1Ii111 * iIii1I11I1II1
  return ( True )
  if 53 - 53: OoOoOO00 * I1ii11iIi11i % OoOoOO00 - OoO0O00 / I1ii11iIi11i / I1Ii111
 return ( False )
 if 23 - 23: i11iIiiIii * OoooooooOO % OoooooooOO % i11iIiiIii . iIii1I11I1II1 + II111iiii
 if 49 - 49: i11iIiiIii - OoO0O00
 if 81 - 81: I11i - OOooOOo / oO0o - ooOoO0o
 if 60 - 60: OoO0O00 / I1ii11iIi11i % iII111i % i11iIiiIii * OoooooooOO * iII111i
 if 92 - 92: I11i % iIii1I11I1II1 * iII111i - OoooooooOO - I11i
 if 34 - 34: I1Ii111 / i1IIi / O0 / OoooooooOO
 if 55 - 55: I1Ii111 . I1IiiI * iIii1I11I1II1 / Ii1I . I1IiiI
 if 63 - 63: ooOoO0o . Ii1I - I1Ii111 - oO0o * I1Ii111 + ooOoO0o
 if 85 - 85: II111iiii + I1ii11iIi11i
 if 33 - 33: iII111i
 if 14 - 14: O0 * Oo0Ooo / i1IIi
 if 95 - 95: O0 % i1IIi % ooOoO0o % oO0o - I1IiiI
 if 78 - 78: II111iiii % OOooOOo
 if 6 - 6: OOooOOo
def lisp_process_api ( process , lisp_socket , data_structure ) :
 I1I11iII , i1 = data_structure . split ( "%" )
 if 48 - 48: OOooOOo - II111iiii - i11iIiiIii
 lprint ( "Process API request '{}', parameters: '{}'" . format ( I1I11iII ,
 i1 ) )
 if 82 - 82: i11iIiiIii % I11i . OoOoOO00 + Ii1I * iIii1I11I1II1 - OoOoOO00
 ooooO000O0OOO0o0O = [ ]
 if ( I1I11iII == "map-cache" ) :
  if ( i1 == "" ) :
   ooooO000O0OOO0o0O = lisp_map_cache . walk_cache ( lisp_process_api_map_cache , ooooO000O0OOO0o0O )
  else :
   ooooO000O0OOO0o0O = lisp_process_api_map_cache_entry ( json . loads ( i1 ) )
   if 96 - 96: I1IiiI
   if 3 - 3: OoooooooOO
 if ( I1I11iII == "site-cache" ) :
  if ( i1 == "" ) :
   ooooO000O0OOO0o0O = lisp_sites_by_eid . walk_cache ( lisp_process_api_site_cache ,
 ooooO000O0OOO0o0O )
  else :
   ooooO000O0OOO0o0O = lisp_process_api_site_cache_entry ( json . loads ( i1 ) )
   if 3 - 3: IiII / O0 * i11iIiiIii . iII111i - iIii1I11I1II1
   if 56 - 56: ooOoO0o
 if ( I1I11iII == "site-cache-summary" ) :
  ooooO000O0OOO0o0O = lisp_process_api_site_cache_summary ( lisp_sites_by_eid )
  if 82 - 82: ooOoO0o . IiII . I1Ii111 - iIii1I11I1II1 + II111iiii . OoOoOO00
 if ( I1I11iII == "map-server" ) :
  i1 = { } if ( i1 == "" ) else json . loads ( i1 )
  ooooO000O0OOO0o0O = lisp_process_api_ms_or_mr ( True , i1 )
  if 59 - 59: Oo0Ooo
 if ( I1I11iII == "map-resolver" ) :
  i1 = { } if ( i1 == "" ) else json . loads ( i1 )
  ooooO000O0OOO0o0O = lisp_process_api_ms_or_mr ( False , i1 )
  if 98 - 98: I1Ii111 * II111iiii / Oo0Ooo . Oo0Ooo % I1Ii111
 if ( I1I11iII == "database-mapping" ) :
  ooooO000O0OOO0o0O = lisp_process_api_database_mapping ( )
  if 52 - 52: OoOoOO00
  if 59 - 59: ooOoO0o / OoooooooOO
  if 71 - 71: OOooOOo + I11i * O0 / o0oOOo0O0Ooo + I1IiiI + Ii1I
  if 41 - 41: ooOoO0o * I1Ii111
  if 40 - 40: OoOoOO00
 ooooO000O0OOO0o0O = json . dumps ( ooooO000O0OOO0o0O )
 ooo0ooo0Oo = lisp_api_ipc ( process , ooooO000O0OOO0o0O )
 lisp_ipc ( ooo0ooo0Oo , lisp_socket , "lisp-core" )
 return
 if 60 - 60: IiII . i11iIiiIii * II111iiii . Ii1I
 if 10 - 10: O0
 if 65 - 65: I11i % i11iIiiIii + i11iIiiIii % II111iiii
 if 95 - 95: I1Ii111 - I11i . II111iiii . i1IIi / II111iiii + Oo0Ooo
 if 96 - 96: iIii1I11I1II1 * iII111i / OOooOOo * iIii1I11I1II1 - O0
 if 28 - 28: I11i / I1IiiI - I1Ii111 + I1ii11iIi11i % iIii1I11I1II1
 if 35 - 35: iIii1I11I1II1 % Oo0Ooo % iII111i / iIii1I11I1II1 - I1ii11iIi11i . Oo0Ooo
def lisp_process_api_map_cache ( mc , data ) :
 if 81 - 81: II111iiii + oO0o
 if 67 - 67: ooOoO0o + I11i - I1ii11iIi11i - OoooooooOO
 if 37 - 37: I11i % I1IiiI
 if 32 - 32: OOooOOo + OoooooooOO . IiII . Oo0Ooo * iII111i
 if ( mc . group . is_null ( ) ) : return ( lisp_gather_map_cache_data ( mc , data ) )
 if 86 - 86: I1ii11iIi11i . iII111i + Ii1I - IiII / i11iIiiIii + OoOoOO00
 if ( mc . source_cache == None ) : return ( [ True , data ] )
 if 50 - 50: o0oOOo0O0Ooo - IiII + OoOoOO00 - II111iiii
 if 24 - 24: I1Ii111 - IiII % I1IiiI - OoooooooOO % Ii1I
 if 56 - 56: I1ii11iIi11i
 if 40 - 40: OoooooooOO
 if 100 - 100: IiII - I11i
 data = mc . source_cache . walk_cache ( lisp_gather_map_cache_data , data )
 return ( [ True , data ] )
 if 79 - 79: iII111i % O0
 if 73 - 73: Oo0Ooo
 if 13 - 13: OOooOOo - ooOoO0o
 if 8 - 8: I1Ii111 % oO0o
 if 19 - 19: O0 + OoO0O00 - i1IIi % OoOoOO00 / Oo0Ooo + OoooooooOO
 if 93 - 93: i11iIiiIii % OOooOOo . I11i * ooOoO0o
 if 90 - 90: OoO0O00
def lisp_gather_map_cache_data ( mc , data ) :
 I1I11i = { }
 I1I11i [ "instance-id" ] = str ( mc . eid . instance_id )
 I1I11i [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
 if ( mc . group . is_null ( ) == False ) :
  I1I11i [ "group-prefix" ] = mc . group . print_prefix_no_iid ( )
  if 54 - 54: OOooOOo + Oo0Ooo * o0oOOo0O0Ooo - iIii1I11I1II1 * ooOoO0o
 I1I11i [ "uptime" ] = lisp_print_elapsed ( mc . uptime )
 I1I11i [ "expires" ] = lisp_print_elapsed ( mc . uptime )
 I1I11i [ "action" ] = lisp_map_reply_action_string [ mc . action ]
 I1I11i [ "ttl" ] = "--" if mc . map_cache_ttl == None else str ( mc . map_cache_ttl / 60 )
 if 76 - 76: i11iIiiIii * I1IiiI - IiII . o0oOOo0O0Ooo % iII111i . i11iIiiIii
 I1I11i [ "eid-memory" ] = hex ( id ( mc ) )
 if 69 - 69: O0 + o0oOOo0O0Ooo / ooOoO0o
 if 7 - 7: Ii1I . Ii1I . iIii1I11I1II1 / ooOoO0o
 if 70 - 70: O0
 if 42 - 42: I1Ii111 + OoooooooOO + I11i
 o0O00ooOo = [ ]
 for iIIiIi1111iiIii in mc . rloc_set :
  IIi1iii = lisp_fill_rloc_in_json ( iIIiIi1111iiIii )
  if 48 - 48: Oo0Ooo . IiII / ooOoO0o + I11i
  if 40 - 40: I1IiiI + I1ii11iIi11i * I1IiiI % Ii1I
  if 27 - 27: O0 / Oo0Ooo . oO0o
  if 34 - 34: I1Ii111 % Ii1I / Oo0Ooo % ooOoO0o / i11iIiiIii * I1IiiI
  if 36 - 36: i11iIiiIii * i1IIi % iII111i . Oo0Ooo
  if ( iIIiIi1111iiIii . rloc . is_multicast_address ( ) ) :
   IIi1iii [ "multicast-rloc-set" ] = [ ]
   for oOOoOo0 in list ( iIIiIi1111iiIii . multicast_rloc_probe_list . values ( ) ) :
    II1iI1iII11 = lisp_fill_rloc_in_json ( oOOoOo0 )
    IIi1iii [ "multicast-rloc-set" ] . append ( II1iI1iII11 )
    if 54 - 54: o0oOOo0O0Ooo % i1IIi % I1ii11iIi11i . o0oOOo0O0Ooo / OoOoOO00
    if 55 - 55: O0 / OoooooooOO % Ii1I * O0 + iIii1I11I1II1 . iIii1I11I1II1
    if 55 - 55: Ii1I . OoooooooOO % Ii1I . IiII
  o0O00ooOo . append ( IIi1iii )
  if 67 - 67: oO0o
 I1I11i [ "rloc-set" ] = o0O00ooOo
 if 12 - 12: I1IiiI + OoooooooOO
 data . append ( I1I11i )
 return ( [ True , data ] )
 if 25 - 25: iIii1I11I1II1 - I1IiiI . i11iIiiIii + ooOoO0o
 if 19 - 19: OoooooooOO / IiII
 if 40 - 40: OoOoOO00 / OoooooooOO * iIii1I11I1II1 / i1IIi . OoooooooOO
 if 88 - 88: I1IiiI % I1IiiI / II111iiii - IiII
 if 72 - 72: OoO0O00 - I1ii11iIi11i . Oo0Ooo / OoO0O00
 if 86 - 86: i11iIiiIii - oO0o . i11iIiiIii
 if 51 - 51: OoO0O00 - OoO0O00 * IiII
 if 24 - 24: OoooooooOO . II111iiii
 if 97 - 97: II111iiii . O0
def lisp_is_active_interface ( rloc ) :
 I1I111i = rloc . rloc . print_address_no_iid ( )
 iI1i1iiIiIi = rloc . rloc_next_hop
 if 74 - 74: o0oOOo0O0Ooo
 II1IiiiIIii = lisp_get_default_route_next_hops ( )
 i1IIIiI = ( II1IiiiIIii and iI1i1iiIiIi == II1IiiiIIii [ 0 ] )
 if 66 - 66: IiII . I1IiiI
 ooO000o0O0Oo = lisp_get_host_route_next_hop ( I1I111i )
 if ( ooO000o0O0Oo == None ) :
  if ( i1IIIiI ) : return ( True )
 elif ( iI1i1iiIiIi [ 1 ] == ooO000o0O0Oo ) :
  return ( True )
  if 15 - 15: oO0o - IiII * OoooooooOO . OoO0O00
 return ( False )
 if 63 - 63: oO0o * OoO0O00 * oO0o
 if 31 - 31: Oo0Ooo
 if 90 - 90: I11i . IiII * iIii1I11I1II1 . I11i + i1IIi
 if 67 - 67: I1Ii111 . I1ii11iIi11i
 if 2 - 2: O0 + I1Ii111
 if 82 - 82: Ii1I / iII111i
 if 13 - 13: I11i + iII111i
def lisp_fill_rloc_in_json ( rloc , head = True ) :
 IIi1iii = { }
 O00oO000Oo0 = None
 if ( rloc . rloc_exists ( ) ) :
  IIi1iii [ "address" ] = rloc . rloc . print_address_no_iid ( )
  O00oO000Oo0 = IIi1iii [ "address" ]
  if 54 - 54: I1ii11iIi11i - I1IiiI . Ii1I
  if 59 - 59: Oo0Ooo + I1ii11iIi11i
 if ( rloc . translated_port != 0 ) :
  IIi1iii [ "encap-port" ] = str ( rloc . translated_port )
  O00oO000Oo0 += ":" + IIi1iii [ "encap-port" ]
  if 87 - 87: ooOoO0o * OoooooooOO + OoO0O00 + oO0o - I1Ii111
  if 70 - 70: i1IIi . Ii1I / Ii1I
 if ( O00oO000Oo0 and O00oO000Oo0 in lisp_crypto_keys_by_rloc_encap ) :
  I1IIiiI1II = lisp_crypto_keys_by_rloc_encap [ O00oO000Oo0 ] [ 1 ]
  if ( I1IIiiI1II != None and I1IIiiI1II . shared_key != None ) :
   IIi1iii [ "encap-crypto" ] = "crypto-" + I1IIiiI1II . cipher_suite_string
   if 9 - 9: iII111i + I1Ii111 + iII111i % ooOoO0o + i11iIiiIii + i11iIiiIii
   if 45 - 45: i1IIi + I1ii11iIi11i
   if 49 - 49: i11iIiiIii . I1ii11iIi11i
 IIi1iii [ "rloc-memory" ] = hex ( id ( rloc ) )
 if 91 - 91: ooOoO0o - OOooOOo - OOooOOo * o0oOOo0O0Ooo
 IIi1iii [ "state" ] = rloc . print_state ( )
 if ( rloc . geo ) : IIi1iii [ "geo" ] = rloc . geo . print_geo ( )
 if ( rloc . elp ) : IIi1iii [ "elp" ] = rloc . elp . print_elp ( False )
 if ( rloc . rle ) : IIi1iii [ "rle" ] = rloc . rle . print_api_rle ( )
 if ( rloc . json ) : IIi1iii [ "json" ] = rloc . json . print_json ( False )
 if ( rloc . rloc_name ) : IIi1iii [ "rloc-name" ] = rloc . rloc_name
 O0oO0O0OoOOo = rloc . stats . get_stats ( False , False )
 if ( O0oO0O0OoOOo ) :
  IIi1iii [ "stats" ] = O0oO0O0OoOOo
  IIi1iii [ "recent-packet-sec" ] = rloc . stats . recent_packet_sec ( )
  IIi1iii [ "recent-packet-min" ] = rloc . stats . recent_packet_min ( )
  if 33 - 33: II111iiii
 i11iiI = lisp_print_elapsed ( rloc . last_state_change )
 if ( i11iiI == "never" ) :
  i11iiI = lisp_print_elapsed ( rloc . uptime )
  if 5 - 5: i11iIiiIii - oO0o + o0oOOo0O0Ooo % ooOoO0o
 IIi1iii [ "uptime" ] = i11iiI
 IIi1iii [ "upriority" ] = str ( rloc . priority )
 IIi1iii [ "uweight" ] = str ( rloc . weight )
 IIi1iii [ "mpriority" ] = str ( rloc . mpriority )
 IIi1iii [ "mweight" ] = str ( rloc . mweight )
 ooOo0Oo0o = rloc . last_rloc_probe_reply
 if ( ooOo0Oo0o ) :
  IIi1iii [ "last-rloc-probe-reply" ] = lisp_print_elapsed ( ooOo0Oo0o )
  IIi1iii [ "rloc-probe-rtt" ] = str ( rloc . rloc_probe_rtt )
  if 76 - 76: Ii1I / oO0o . I1Ii111
 IIi1iii [ "rloc-hop-count" ] = rloc . rloc_probe_hops
 IIi1iii [ "recent-rloc-hop-counts" ] = rloc . recent_rloc_probe_hops
 if 94 - 94: o0oOOo0O0Ooo - OoOoOO00 / I1Ii111
 IIi1iii [ "rloc-probe-latency" ] = rloc . rloc_probe_latency
 IIi1iii [ "recent-rloc-probe-latencies" ] = rloc . recent_rloc_probe_latencies
 if 99 - 99: O0 % oO0o % OOooOOo - Oo0Ooo
 II1iIi1ii1IIi = [ ]
 for OO0OO0o0oO in rloc . recent_rloc_probe_rtts : II1iIi1ii1IIi . append ( str ( OO0OO0o0oO ) )
 IIi1iii [ "recent-rloc-probe-rtts" ] = II1iIi1ii1IIi
 if 82 - 82: iII111i + OoooooooOO % iIii1I11I1II1 - o0oOOo0O0Ooo - i1IIi / Oo0Ooo
 if ( rloc . rloc_next_hop ) : IIi1iii [ "nh-interface" ] = rloc . rloc_next_hop
 if 13 - 13: iII111i % oO0o - I11i . i11iIiiIii / iIii1I11I1II1
 if 11 - 11: iII111i % OoO0O00 % iIii1I11I1II1 + IiII * Ii1I
 if 93 - 93: OOooOOo / iII111i
 if 74 - 74: I1ii11iIi11i
 if 83 - 83: iII111i + i1IIi - OoooooooOO
 IIi1iii [ "is-active" ] = lisp_is_active_interface ( rloc )
 if 16 - 16: i1IIi
 if 86 - 86: OoOoOO00 - iII111i - Oo0Ooo
 if 33 - 33: Ii1I - OoO0O00
 if 15 - 15: O0 . iIii1I11I1II1 - I1Ii111 + O0 + ooOoO0o / I1IiiI
 if ( head == False ) : return ( IIi1iii )
 if 8 - 8: iII111i % O0 - OoOoOO00
 IIi1iii [ "next-hop-rlocs" ] = [ ]
 o000o0oO0 = rloc . next_rloc
 while ( o000o0oO0 != None ) :
  IIi1i1i1 = lisp_fill_rloc_in_json ( o000o0oO0 , False )
  IIi1iii [ "next-hop-rlocs" ] . append ( IIi1i1i1 )
  o000o0oO0 = o000o0oO0 . next_rloc
  if 13 - 13: I1ii11iIi11i % OoO0O00 / Ii1I * IiII
  if 82 - 82: ooOoO0o % Oo0Ooo
 return ( IIi1iii )
 if 26 - 26: OoO0O00 + i11iIiiIii % I11i . I1ii11iIi11i
 if 76 - 76: i1IIi + ooOoO0o - Oo0Ooo + OoOoOO00 / I1ii11iIi11i . OOooOOo
 if 50 - 50: IiII - Ii1I % iIii1I11I1II1
 if 60 - 60: o0oOOo0O0Ooo - Oo0Ooo
 if 92 - 92: OoOoOO00 + IiII . OoO0O00 % iII111i / II111iiii / I11i
 if 62 - 62: I1ii11iIi11i
 if 100 - 100: iII111i / ooOoO0o / IiII % II111iiii
def lisp_process_api_map_cache_entry ( parms ) :
 i1I1iI = parms [ "instance-id" ]
 i1I1iI = 0 if ( i1I1iI == "" ) else int ( i1I1iI )
 if 6 - 6: OoooooooOO - I1IiiI + OoooooooOO
 if 89 - 89: oO0o % Oo0Ooo . O0 . ooOoO0o
 if 46 - 46: IiII * I11i - OoO0O00 - Ii1I
 if 93 - 93: iIii1I11I1II1 / o0oOOo0O0Ooo - I11i - OOooOOo % ooOoO0o
 Ooo0O = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 Ooo0O . store_prefix ( parms [ "eid-prefix" ] )
 oOO00OoOo = Ooo0O
 ooOO0O0O = Ooo0O
 if 16 - 16: ooOoO0o * o0oOOo0O0Ooo - IiII + I1ii11iIi11i / o0oOOo0O0Ooo - O0
 if 71 - 71: i1IIi
 if 79 - 79: iII111i * O0 / Ii1I / O0 % i1IIi
 if 52 - 52: OoooooooOO % oO0o - I11i % OoOoOO00 . II111iiii
 if 62 - 62: Ii1I . I1ii11iIi11i . iII111i + I11i * o0oOOo0O0Ooo
 i1I1IIIiII = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 if ( "group-prefix" in parms ) :
  i1I1IIIiII . store_prefix ( parms [ "group-prefix" ] )
  oOO00OoOo = i1I1IIIiII
  if 56 - 56: oO0o * iIii1I11I1II1 . II111iiii - II111iiii + II111iiii - i11iIiiIii
  if 79 - 79: iII111i
 ooooO000O0OOO0o0O = [ ]
 IIII1 = lisp_map_cache_lookup ( ooOO0O0O , oOO00OoOo )
 if ( IIII1 ) : i1oO0000OOO0O , ooooO000O0OOO0o0O = lisp_process_api_map_cache ( IIII1 , ooooO000O0OOO0o0O )
 return ( ooooO000O0OOO0o0O )
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
def lisp_process_api_site_cache_summary ( site_cache ) :
 o0oOO0 = { "site" : "" , "registrations" : [ ] }
 I1I11i = { "eid-prefix" : "" , "count" : 0 , "registered-count" : 0 }
 if 23 - 23: i1IIi . iIii1I11I1II1 / I1IiiI . OoOoOO00 . iII111i / IiII
 O0O0o00 = { }
 for I1iIIIiI1iI11 in site_cache . cache_sorted :
  for o0o0Oo0O00OO in list ( site_cache . cache [ I1iIIIiI1iI11 ] . entries . values ( ) ) :
   if ( o0o0Oo0O00OO . accept_more_specifics == False ) : continue
   if ( o0o0Oo0O00OO . site . site_name not in O0O0o00 ) :
    O0O0o00 [ o0o0Oo0O00OO . site . site_name ] = [ ]
    if 91 - 91: OoooooooOO
   oOO = copy . deepcopy ( I1I11i )
   oOO [ "eid-prefix" ] = o0o0Oo0O00OO . eid . print_prefix ( )
   oOO [ "count" ] = len ( o0o0Oo0O00OO . more_specific_registrations )
   for I1Iii1i1 in o0o0Oo0O00OO . more_specific_registrations :
    if ( I1Iii1i1 . registered ) : oOO [ "registered-count" ] += 1
    if 1 - 1: Oo0Ooo / OOooOOo * OoooooooOO / OoO0O00 - iIii1I11I1II1
   O0O0o00 [ o0o0Oo0O00OO . site . site_name ] . append ( oOO )
   if 25 - 25: iIii1I11I1II1 % OOooOOo - iII111i * IiII * Ii1I
   if 18 - 18: OoO0O00 - oO0o % i11iIiiIii - i1IIi % I1Ii111 * Ii1I
   if 80 - 80: o0oOOo0O0Ooo - I1IiiI . OoOoOO00 . IiII
 ooooO000O0OOO0o0O = [ ]
 for OooOo0OO in O0O0o00 :
  OOo0oOO0o0oo0 = copy . deepcopy ( o0oOO0 )
  OOo0oOO0o0oo0 [ "site" ] = OooOo0OO
  OOo0oOO0o0oo0 [ "registrations" ] = O0O0o00 [ OooOo0OO ]
  ooooO000O0OOO0o0O . append ( OOo0oOO0o0oo0 )
  if 85 - 85: O0 / Oo0Ooo + iIii1I11I1II1 / I1IiiI + o0oOOo0O0Ooo % O0
 return ( ooooO000O0OOO0o0O )
 if 79 - 79: OOooOOo . OoO0O00 % oO0o * IiII
 if 75 - 75: iIii1I11I1II1
 if 11 - 11: o0oOOo0O0Ooo
 if 89 - 89: Ii1I % i1IIi
 if 47 - 47: II111iiii * I1ii11iIi11i
 if 70 - 70: I1ii11iIi11i - o0oOOo0O0Ooo
 if 71 - 71: I1ii11iIi11i * i1IIi
def lisp_process_api_site_cache ( se , data ) :
 if 67 - 67: I1ii11iIi11i % OoOoOO00 . iII111i / Ii1I . I1IiiI
 if 48 - 48: IiII + II111iiii . I1IiiI % o0oOOo0O0Ooo
 if 57 - 57: OOooOOo . I11i % OoOoOO00
 if 68 - 68: iIii1I11I1II1 % I1ii11iIi11i % II111iiii / O0 + iII111i
 if ( se . group . is_null ( ) ) : return ( lisp_gather_site_cache_data ( se , data ) )
 if 78 - 78: iII111i - OOooOOo / I1Ii111
 if ( se . source_cache == None ) : return ( [ True , data ] )
 if 38 - 38: I11i % i1IIi + o0oOOo0O0Ooo + I1ii11iIi11i + I1IiiI
 if 1 - 1: II111iiii * o0oOOo0O0Ooo . O0 - Ii1I / oO0o
 if 17 - 17: OoooooooOO % OoooooooOO + Oo0Ooo + I1Ii111
 if 56 - 56: I11i % OoOoOO00 - OoO0O00
 if 31 - 31: iII111i % i11iIiiIii - Ii1I / OOooOOo - I1Ii111
 data = se . source_cache . walk_cache ( lisp_gather_site_cache_data , data )
 return ( [ True , data ] )
 if 60 - 60: o0oOOo0O0Ooo + Oo0Ooo . O0
 if 51 - 51: i11iIiiIii / iIii1I11I1II1 . I1IiiI - Ii1I * I1Ii111 . iII111i
 if 72 - 72: Ii1I . I11i / i1IIi % i1IIi + I1ii11iIi11i
 if 56 - 56: OoO0O00 - OoOoOO00 - II111iiii * o0oOOo0O0Ooo
 if 87 - 87: ooOoO0o * OoooooooOO % O0 * OoooooooOO . I1Ii111
 if 66 - 66: OoO0O00 * Ii1I . OoO0O00
 if 90 - 90: II111iiii % Ii1I
def lisp_process_api_ms_or_mr ( ms_or_mr , data ) :
 I1iI111ii111i = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
 OO00Oo0oO0O = data [ "dns-name" ] if ( "dns-name" in data ) else None
 if ( "address" in data ) :
  I1iI111ii111i . store_address ( data [ "address" ] )
  if 67 - 67: I1IiiI - I11i - i11iIiiIii
  if 45 - 45: ooOoO0o - IiII / OoO0O00 / IiII
 oO00o = { }
 if ( ms_or_mr ) :
  for oOO0 in list ( lisp_map_servers_list . values ( ) ) :
   if ( OO00Oo0oO0O ) :
    if ( OO00Oo0oO0O != oOO0 . dns_name ) : continue
   else :
    if ( I1iI111ii111i . is_exact_match ( oOO0 . map_server ) == False ) : continue
    if 63 - 63: ooOoO0o . i11iIiiIii + iII111i . OoO0O00 / ooOoO0o % iII111i
    if 23 - 23: iIii1I11I1II1 - ooOoO0o / I11i * I11i
   oO00o [ "dns-name" ] = oOO0 . dns_name
   oO00o [ "address" ] = oOO0 . map_server . print_address_no_iid ( )
   oO00o [ "ms-name" ] = "" if oOO0 . ms_name == None else oOO0 . ms_name
   return ( [ oO00o ] )
   if 62 - 62: OOooOOo - I1IiiI * oO0o + O0 / ooOoO0o * iIii1I11I1II1
 else :
  for II1iI1iII11 in list ( lisp_map_resolvers_list . values ( ) ) :
   if ( OO00Oo0oO0O ) :
    if ( OO00Oo0oO0O != II1iI1iII11 . dns_name ) : continue
   else :
    if ( I1iI111ii111i . is_exact_match ( II1iI1iII11 . map_resolver ) == False ) : continue
    if 25 - 25: I1Ii111 % Oo0Ooo + OoO0O00 % OOooOOo
    if 85 - 85: I1IiiI . i11iIiiIii - ooOoO0o * I11i * OoOoOO00 * I11i
   oO00o [ "dns-name" ] = II1iI1iII11 . dns_name
   oO00o [ "address" ] = II1iI1iII11 . map_resolver . print_address_no_iid ( )
   oO00o [ "mr-name" ] = "" if II1iI1iII11 . mr_name == None else II1iI1iII11 . mr_name
   return ( [ oO00o ] )
   if 29 - 29: I1Ii111 * I1Ii111 . iII111i + o0oOOo0O0Ooo
   if 57 - 57: I1Ii111 - IiII
 return ( [ ] )
 if 89 - 89: oO0o + iII111i
 if 52 - 52: OOooOOo % O0 * I1ii11iIi11i . I1ii11iIi11i / IiII
 if 7 - 7: II111iiii
 if 7 - 7: iIii1I11I1II1 . O0 + Ii1I % I1IiiI * O0 + OoO0O00
 if 3 - 3: Oo0Ooo * OoooooooOO * oO0o % OoOoOO00 * OoOoOO00 . ooOoO0o
 if 16 - 16: ooOoO0o / o0oOOo0O0Ooo - O0 * I1IiiI
 if 13 - 13: iII111i . iII111i % O0 % o0oOOo0O0Ooo
 if 99 - 99: OoO0O00 - OoOoOO00 + OoO0O00
def lisp_process_api_database_mapping ( ) :
 ooooO000O0OOO0o0O = [ ]
 if 67 - 67: I1Ii111
 for Iiii1II1 in lisp_db_list :
  I1I11i = { }
  I1I11i [ "eid-prefix" ] = Iiii1II1 . eid . print_prefix ( )
  if ( Iiii1II1 . group . is_null ( ) == False ) :
   I1I11i [ "group-prefix" ] = Iiii1II1 . group . print_prefix ( )
   if 31 - 31: OoO0O00 * Oo0Ooo % O0 * II111iiii + ooOoO0o * I1IiiI
   if 77 - 77: ooOoO0o
  OOooO = [ ]
  for IIi1iii in Iiii1II1 . rloc_set :
   iIIiIi1111iiIii = { }
   if ( IIi1iii . rloc . is_null ( ) == False ) :
    iIIiIi1111iiIii [ "rloc" ] = IIi1iii . rloc . print_address_no_iid ( )
    if 98 - 98: I1Ii111 + I1ii11iIi11i % OoO0O00 * Ii1I + iII111i
   if ( IIi1iii . rloc_name != None ) : iIIiIi1111iiIii [ "rloc-name" ] = IIi1iii . rloc_name
   if ( IIi1iii . interface != None ) : iIIiIi1111iiIii [ "interface" ] = IIi1iii . interface
   i1i1iI1I = IIi1iii . translated_rloc
   if ( i1i1iI1I . is_null ( ) == False ) :
    iIIiIi1111iiIii [ "translated-rloc" ] = i1i1iI1I . print_address_no_iid ( )
    if ( IIi1iii . translated_port != 0 ) :
     iIIiIi1111iiIii [ "translated-port" ] = IIi1iii . translated_port
     if 68 - 68: IiII - OoOoOO00
     if 22 - 22: i1IIi . IiII
   if ( iIIiIi1111iiIii != { } ) : OOooO . append ( iIIiIi1111iiIii )
   if 8 - 8: IiII % o0oOOo0O0Ooo . i11iIiiIii
   if 69 - 69: I1Ii111 / Ii1I - ooOoO0o
   if 38 - 38: II111iiii % OoooooooOO / OoooooooOO . Ii1I . Ii1I
   if 13 - 13: oO0o - i1IIi / i1IIi + OoooooooOO
   if 57 - 57: OoooooooOO / O0 + I1ii11iIi11i % I11i * oO0o / Ii1I
  I1I11i [ "rlocs" ] = OOooO
  if 49 - 49: I1IiiI * ooOoO0o * OOooOOo + OoO0O00 + ooOoO0o
  if 42 - 42: i1IIi . OoO0O00 % iII111i
  if 57 - 57: I1ii11iIi11i / I1IiiI
  if 69 - 69: iII111i - iII111i . OoO0O00 / oO0o - OoO0O00 + I1Ii111
  ooooO000O0OOO0o0O . append ( I1I11i )
  if 98 - 98: iII111i . oO0o - O0 % I1IiiI . I1ii11iIi11i / i1IIi
 return ( ooooO000O0OOO0o0O )
 if 72 - 72: I1IiiI / Oo0Ooo % IiII - O0 / O0 * O0
 if 83 - 83: O0 / I1Ii111 - OoooooooOO
 if 42 - 42: Ii1I / i1IIi - IiII / I1Ii111
 if 39 - 39: OoooooooOO
 if 4 - 4: iIii1I11I1II1 - Oo0Ooo / OOooOOo % OoooooooOO . Oo0Ooo - Oo0Ooo
 if 41 - 41: II111iiii . o0oOOo0O0Ooo
 if 92 - 92: Ii1I - O0 - i11iIiiIii + IiII % I1Ii111 + II111iiii
def lisp_gather_site_cache_data ( se , data ) :
 I1I11i = { }
 I1I11i [ "site-name" ] = se . site . site_name
 I1I11i [ "instance-id" ] = str ( se . eid . instance_id )
 I1I11i [ "eid-prefix" ] = se . eid . print_prefix_no_iid ( )
 if ( se . group . is_null ( ) == False ) :
  I1I11i [ "group-prefix" ] = se . group . print_prefix_no_iid ( )
  if 71 - 71: ooOoO0o * I1Ii111 + i11iIiiIii + i1IIi . I1IiiI
 I1I11i [ "registered" ] = "yes" if se . registered else "no"
 I1I11i [ "first-registered" ] = lisp_print_elapsed ( se . first_registered )
 I1I11i [ "last-registered" ] = lisp_print_elapsed ( se . last_registered )
 if 15 - 15: OoO0O00
 iI1ii11Ii = se . last_registerer
 iI1ii11Ii = "none" if iI1ii11Ii . is_null ( ) else iI1ii11Ii . print_address ( )
 I1I11i [ "last-registerer" ] = iI1ii11Ii
 I1I11i [ "ams" ] = "yes" if ( se . accept_more_specifics ) else "no"
 I1I11i [ "dynamic" ] = "yes" if ( se . dynamic ) else "no"
 I1I11i [ "site-id" ] = str ( se . site_id )
 if ( se . xtr_id_present ) :
  I1I11i [ "xtr-id" ] = "0x" + lisp_hex_string ( se . xtr_id )
  if 37 - 37: OoO0O00 . OoooooooOO - OOooOOo
  if 34 - 34: o0oOOo0O0Ooo + iIii1I11I1II1 / o0oOOo0O0Ooo / ooOoO0o
  if 53 - 53: II111iiii / iIii1I11I1II1
  if 25 - 25: I1Ii111
  if 58 - 58: OoOoOO00 * i1IIi
 o0O00ooOo = [ ]
 for iIIiIi1111iiIii in se . registered_rlocs :
  IIi1iii = { }
  IIi1iii [ "address" ] = iIIiIi1111iiIii . rloc . print_address_no_iid ( ) if iIIiIi1111iiIii . rloc_exists ( ) else "none"
  if 20 - 20: IiII
  if 81 - 81: I1Ii111 . i1IIi / o0oOOo0O0Ooo
  if ( iIIiIi1111iiIii . geo ) : IIi1iii [ "geo" ] = iIIiIi1111iiIii . geo . print_geo ( )
  if ( iIIiIi1111iiIii . elp ) : IIi1iii [ "elp" ] = iIIiIi1111iiIii . elp . print_elp ( False )
  if ( iIIiIi1111iiIii . rle ) : IIi1iii [ "rle" ] = iIIiIi1111iiIii . rle . print_rle ( False , True )
  if ( iIIiIi1111iiIii . json ) : IIi1iii [ "json" ] = iIIiIi1111iiIii . json . print_json ( False )
  if ( iIIiIi1111iiIii . rloc_name ) : IIi1iii [ "rloc-name" ] = iIIiIi1111iiIii . rloc_name
  IIi1iii [ "uptime" ] = lisp_print_elapsed ( iIIiIi1111iiIii . uptime )
  IIi1iii [ "upriority" ] = str ( iIIiIi1111iiIii . priority )
  IIi1iii [ "uweight" ] = str ( iIIiIi1111iiIii . weight )
  IIi1iii [ "mpriority" ] = str ( iIIiIi1111iiIii . mpriority )
  IIi1iii [ "mweight" ] = str ( iIIiIi1111iiIii . mweight )
  if ( iIIiIi1111iiIii . translated_port != 0 ) :
   IIi1iii [ "encap-port" ] = str ( iIIiIi1111iiIii . translated_port )
   if 30 - 30: i11iIiiIii . I1IiiI
   if 5 - 5: Ii1I / O0 + iIii1I11I1II1
   if 22 - 22: ooOoO0o . ooOoO0o * OOooOOo % OoOoOO00
  o0O00ooOo . append ( IIi1iii )
  if 51 - 51: OoOoOO00 . oO0o - OoOoOO00
 I1I11i [ "registered-rlocs" ] = o0O00ooOo
 if 79 - 79: iII111i
 data . append ( I1I11i )
 return ( [ True , data ] )
 if 71 - 71: i1IIi / OoO0O00 / OOooOOo + I1Ii111
 if 80 - 80: Oo0Ooo . iIii1I11I1II1 . OoooooooOO % iII111i . oO0o
 if 10 - 10: i11iIiiIii * OoooooooOO . i11iIiiIii
 if 35 - 35: OOooOOo * OOooOOo + o0oOOo0O0Ooo / i1IIi - I11i
 if 12 - 12: I1ii11iIi11i - i11iIiiIii + I1IiiI . Oo0Ooo
 if 26 - 26: oO0o + I1Ii111 + IiII * o0oOOo0O0Ooo . oO0o
 if 95 - 95: OoOoOO00 . I1Ii111 / Ii1I . I1Ii111 % OoO0O00
def lisp_process_api_site_cache_entry ( parms ) :
 i1I1iI = parms [ "instance-id" ]
 i1I1iI = 0 if ( i1I1iI == "" ) else int ( i1I1iI )
 if 16 - 16: Ii1I / I1IiiI / I1IiiI - OoooooooOO
 if 13 - 13: OOooOOo / OoooooooOO
 if 7 - 7: II111iiii - ooOoO0o
 if 72 - 72: Ii1I
 Ooo0O = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 Ooo0O . store_prefix ( parms [ "eid-prefix" ] )
 if 27 - 27: ooOoO0o / IiII + OoO0O00 + Ii1I % I1Ii111
 if 86 - 86: O0 % i11iIiiIii - Ii1I * oO0o % OOooOOo * i1IIi
 if 87 - 87: II111iiii
 if 53 - 53: OoOoOO00 * i11iIiiIii / I1Ii111
 if 100 - 100: ooOoO0o + I1IiiI * oO0o + ooOoO0o
 i1I1IIIiII = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
 if ( "group-prefix" in parms ) :
  i1I1IIIiII . store_prefix ( parms [ "group-prefix" ] )
  if 24 - 24: i11iIiiIii + ooOoO0o
  if 80 - 80: IiII % I11i % oO0o
 ooooO000O0OOO0o0O = [ ]
 o0o0Oo0O00OO = lisp_site_eid_lookup ( Ooo0O , i1I1IIIiII , False )
 if ( o0o0Oo0O00OO ) : lisp_gather_site_cache_data ( o0o0Oo0O00OO , ooooO000O0OOO0o0O )
 return ( ooooO000O0OOO0o0O )
 if 97 - 97: i1IIi * i11iIiiIii / Ii1I - I1IiiI % IiII
 if 70 - 70: iIii1I11I1II1
 if 2 - 2: IiII - i1IIi * IiII % O0 / Ii1I
 if 64 - 64: iII111i - Oo0Ooo
 if 73 - 73: iIii1I11I1II1 * I1Ii111 * OoO0O00
 if 68 - 68: ooOoO0o * Ii1I / I1ii11iIi11i * OoooooooOO + OoooooooOO . OoooooooOO
 if 50 - 50: I1IiiI % o0oOOo0O0Ooo
def lisp_get_interface_instance_id ( device , source_eid ) :
 oo = None
 if ( device in lisp_myinterfaces ) :
  oo = lisp_myinterfaces [ device ]
  if 1 - 1: II111iiii
  if 22 - 22: I1Ii111 + iII111i
  if 50 - 50: iII111i % OoOoOO00 - II111iiii + II111iiii / OoO0O00
  if 69 - 69: Ii1I * II111iiii
  if 24 - 24: I1Ii111 * I1ii11iIi11i . OOooOOo . I1IiiI - I1ii11iIi11i
  if 56 - 56: I1IiiI * Oo0Ooo + OoO0O00 - oO0o * I1Ii111
 if ( oo == None or oo . instance_id == None ) :
  return ( lisp_default_iid )
  if 68 - 68: ooOoO0o * i11iIiiIii * OOooOOo % iII111i
  if 10 - 10: Ii1I / Oo0Ooo - i1IIi
  if 11 - 11: I11i * iII111i
  if 28 - 28: II111iiii + IiII / Oo0Ooo * I1IiiI - OOooOOo
  if 2 - 2: oO0o + I11i / I1Ii111 . I11i
  if 59 - 59: Ii1I
  if 47 - 47: iII111i % iII111i
  if 81 - 81: oO0o / I1ii11iIi11i . OoooooooOO % II111iiii / oO0o
  if 23 - 23: IiII + oO0o + o0oOOo0O0Ooo . I1ii11iIi11i / i11iIiiIii + iIii1I11I1II1
 i1I1iI = oo . get_instance_id ( )
 if ( source_eid == None ) : return ( i1I1iI )
 if 74 - 74: I11i % OOooOOo
 ooOoo0 = source_eid . instance_id
 oO0oo00OO = None
 for oo in lisp_multi_tenant_interfaces :
  if ( oo . device != device ) : continue
  O0OoO0 = oo . multi_tenant_eid
  source_eid . instance_id = O0OoO0 . instance_id
  if ( source_eid . is_more_specific ( O0OoO0 ) == False ) : continue
  if ( oO0oo00OO == None or oO0oo00OO . multi_tenant_eid . mask_len < O0OoO0 . mask_len ) :
   oO0oo00OO = oo
   if 53 - 53: I1ii11iIi11i
   if 85 - 85: iIii1I11I1II1 - II111iiii + Ii1I
 source_eid . instance_id = ooOoo0
 if 3 - 3: ooOoO0o - I1Ii111
 if ( oO0oo00OO == None ) : return ( i1I1iI )
 return ( oO0oo00OO . get_instance_id ( ) )
 if 97 - 97: OOooOOo
 if 87 - 87: iII111i
 if 73 - 73: II111iiii
 if 2 - 2: i1IIi % iII111i . oO0o / II111iiii * I1IiiI
 if 17 - 17: O0 + iII111i + oO0o / iIii1I11I1II1 % oO0o
 if 81 - 81: iII111i * i11iIiiIii % O0 / iIii1I11I1II1 . OoO0O00
 if 24 - 24: I1ii11iIi11i + OoOoOO00 % ooOoO0o % I1IiiI * I1Ii111 - o0oOOo0O0Ooo
 if 95 - 95: Oo0Ooo * IiII - I1IiiI
 if 37 - 37: Oo0Ooo - oO0o / I1ii11iIi11i . o0oOOo0O0Ooo * Ii1I
def lisp_allow_dynamic_eid ( device , eid ) :
 if ( device not in lisp_myinterfaces ) : return ( None )
 if 95 - 95: i11iIiiIii - ooOoO0o / I11i / I1Ii111
 oo = lisp_myinterfaces [ device ]
 oOoOO0oOO0oo = device if oo . dynamic_eid_device == None else oo . dynamic_eid_device
 if 87 - 87: II111iiii . iIii1I11I1II1 . OoOoOO00
 if 23 - 23: Oo0Ooo / II111iiii % OOooOOo % iII111i - Oo0Ooo / OoO0O00
 if ( oo . does_dynamic_eid_match ( eid ) ) : return ( oOoOO0oOO0oo )
 return ( None )
 if 7 - 7: Ii1I / I11i / II111iiii % I11i * I11i + iIii1I11I1II1
 if 6 - 6: iIii1I11I1II1 * oO0o - iIii1I11I1II1 . O0 . O0
 if 96 - 96: I1Ii111 * II111iiii % i11iIiiIii - oO0o
 if 32 - 32: i11iIiiIii * o0oOOo0O0Ooo . OoooooooOO / O0
 if 14 - 14: i11iIiiIii . I1Ii111 % I1ii11iIi11i . I1ii11iIi11i % IiII
 if 93 - 93: iIii1I11I1II1 / IiII
 if 91 - 91: i11iIiiIii % ooOoO0o - iII111i * I1Ii111 . i11iIiiIii
def lisp_start_rloc_probe_timer ( interval , lisp_sockets ) :
 global lisp_rloc_probe_timer
 if 1 - 1: IiII + iIii1I11I1II1 * I1ii11iIi11i - IiII - i1IIi
 if ( lisp_rloc_probe_timer != None ) : lisp_rloc_probe_timer . cancel ( )
 if 75 - 75: II111iiii * o0oOOo0O0Ooo / I1ii11iIi11i
 i1IiI11III = lisp_process_rloc_probe_timer
 IiII111Ii = threading . Timer ( interval , i1IiI11III , [ lisp_sockets ] )
 lisp_rloc_probe_timer = IiII111Ii
 IiII111Ii . start ( )
 return
 if 40 - 40: OoO0O00 / I11i % iIii1I11I1II1 - ooOoO0o
 if 51 - 51: Oo0Ooo % iIii1I11I1II1 % oO0o + o0oOOo0O0Ooo
 if 32 - 32: I1Ii111 * I1IiiI + Ii1I
 if 30 - 30: OoooooooOO / I1IiiI . iIii1I11I1II1 / ooOoO0o
 if 20 - 20: OoooooooOO * OOooOOo
 if 77 - 77: Ii1I - OoooooooOO . OoOoOO00
 if 93 - 93: OoooooooOO / I1Ii111
def lisp_show_rloc_probe_list ( ) :
 lprint ( bold ( "----- RLOC-probe-list -----" , False ) )
 for I1IIiiI1II in lisp_rloc_probe_list :
  ooo000OOo0Ooo = lisp_rloc_probe_list [ I1IIiiI1II ]
  lprint ( "RLOC {}:" . format ( I1IIiiI1II ) )
  for IIi1iii , oOO , II11iIIii in ooo000OOo0Ooo :
   lprint ( "  [{}, {}, {}, {}]" . format ( hex ( id ( IIi1iii ) ) , oOO . print_prefix ( ) ,
 II11iIIii . print_prefix ( ) , IIi1iii . translated_port ) )
   if 15 - 15: OoO0O00 * i1IIi % OoO0O00 - oO0o / iIii1I11I1II1 - o0oOOo0O0Ooo
   if 69 - 69: ooOoO0o
 lprint ( bold ( "---------------------------" , False ) )
 return
 if 87 - 87: OOooOOo
 if 10 - 10: iIii1I11I1II1
 if 75 - 75: oO0o + o0oOOo0O0Ooo
 if 37 - 37: oO0o + O0 . IiII * I1ii11iIi11i
 if 2 - 2: O0 . ooOoO0o
 if 97 - 97: i1IIi . Oo0Ooo
 if 81 - 81: OoOoOO00
 if 81 - 81: O0
 if 57 - 57: oO0o - o0oOOo0O0Ooo % i11iIiiIii / OoOoOO00 . iIii1I11I1II1
def lisp_mark_rlocs_for_other_eids ( eid_list ) :
 if 68 - 68: iII111i
 if 59 - 59: O0 - i11iIiiIii + OoooooooOO - iII111i - Oo0Ooo . OoooooooOO
 if 60 - 60: O0 * iIii1I11I1II1 - Ii1I * II111iiii . ooOoO0o
 if 61 - 61: I1IiiI . iII111i
 iIIiIi1111iiIii , oOO , II11iIIii = eid_list [ 0 ]
 IiIIIIIiIi1I = [ lisp_print_eid_tuple ( oOO , II11iIIii ) ]
 if 95 - 95: OoOoOO00 * iIii1I11I1II1 / OoooooooOO % i1IIi
 for iIIiIi1111iiIii , oOO , II11iIIii in eid_list [ 1 : : ] :
  iIIiIi1111iiIii . state = LISP_RLOC_UNREACH_STATE
  iIIiIi1111iiIii . last_state_change = lisp_get_timestamp ( )
  IiIIIIIiIi1I . append ( lisp_print_eid_tuple ( oOO , II11iIIii ) )
  if 91 - 91: OOooOOo - OoOoOO00
  if 58 - 58: II111iiii . OOooOOo % II111iiii * oO0o % OoO0O00 % I11i
 o00ooooO0O00 = bold ( "unreachable" , False )
 I1I111i = red ( iIIiIi1111iiIii . rloc . print_address_no_iid ( ) , False )
 if 10 - 10: Ii1I * o0oOOo0O0Ooo + iII111i - o0oOOo0O0Ooo % OoOoOO00
 for Ooo0O in IiIIIIIiIi1I :
  oOO = green ( Ooo0O , False )
  lprint ( "RLOC {} went {} for EID {}" . format ( I1I111i , o00ooooO0O00 , oOO ) )
  if 96 - 96: i11iIiiIii + O0 - i1IIi / o0oOOo0O0Ooo * I11i
  if 24 - 24: oO0o / o0oOOo0O0Ooo + i1IIi
  if 15 - 15: i11iIiiIii / O0
  if 34 - 34: I1Ii111 . IiII % iII111i
  if 94 - 94: OOooOOo % i11iIiiIii . OOooOOo
  if 55 - 55: OoOoOO00 . OoOoOO00 % o0oOOo0O0Ooo . I11i . I1ii11iIi11i - o0oOOo0O0Ooo
 for iIIiIi1111iiIii , oOO , II11iIIii in eid_list :
  IIII1 = lisp_map_cache . lookup_cache ( oOO , True )
  if ( IIII1 ) : lisp_write_ipc_map_cache ( True , IIII1 )
  if 1 - 1: i11iIiiIii - i1IIi * oO0o - iIii1I11I1II1
 return
 if 75 - 75: i1IIi * i11iIiiIii
 if 40 - 40: I1ii11iIi11i + OoO0O00
 if 8 - 8: i11iIiiIii - iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if 25 - 25: iII111i / oO0o
 if 61 - 61: OoooooooOO . Ii1I . I11i + oO0o
 if 73 - 73: II111iiii % i11iIiiIii * I1ii11iIi11i + O0
 if 61 - 61: I1IiiI / OOooOOo
def lisp_process_multicast_rloc ( multicast_rloc ) :
 oo0000O = multicast_rloc . rloc . print_address_no_iid ( )
 if 57 - 57: I1IiiI . II111iiii . i1IIi * O0
 O0OoOOo = lisp_get_timestamp ( )
 for iI1ii11Ii in multicast_rloc . multicast_rloc_probe_list :
  oOOoOo0 = multicast_rloc . multicast_rloc_probe_list [ iI1ii11Ii ]
  if ( oOOoOo0 . last_rloc_probe_reply + LISP_RLOC_PROBE_REPLY_WAIT >= O0OoOOo ) :
   continue
   if 90 - 90: i11iIiiIii + iIii1I11I1II1 + O0 % I1IiiI
  if ( oOOoOo0 . state == LISP_RLOC_UNREACH_STATE ) : continue
  if 95 - 95: ooOoO0o % OOooOOo
  if 17 - 17: i1IIi + Ii1I
  if 35 - 35: iIii1I11I1II1 - Oo0Ooo - OoooooooOO % I1ii11iIi11i
  if 27 - 27: Oo0Ooo * II111iiii - OOooOOo + o0oOOo0O0Ooo
  oOOoOo0 . state = LISP_RLOC_UNREACH_STATE
  oOOoOo0 . last_state_change = lisp_get_timestamp ( )
  if 26 - 26: oO0o / I1ii11iIi11i - oO0o
  lprint ( "Multicast-RLOC {} member-RLOC {} went unreachable" . format ( oo0000O , red ( iI1ii11Ii , False ) ) )
  if 9 - 9: ooOoO0o * iIii1I11I1II1 * OoooooooOO
  if 13 - 13: iII111i . i11iIiiIii * o0oOOo0O0Ooo . iII111i
  if 96 - 96: Ii1I
  if 90 - 90: II111iiii
  if 93 - 93: i11iIiiIii / Ii1I * Oo0Ooo . iII111i % iII111i / IiII
  if 15 - 15: OoOoOO00 % I1Ii111 - iIii1I11I1II1
  if 52 - 52: i11iIiiIii * ooOoO0o
  if 15 - 15: OoooooooOO . oO0o . i11iIiiIii / o0oOOo0O0Ooo
  if 91 - 91: ooOoO0o
  if 47 - 47: II111iiii + I11i + ooOoO0o % Oo0Ooo / iII111i
  if 9 - 9: O0 + IiII
  if 69 - 69: I1IiiI
def lisp_process_rloc_probe_timer ( lisp_sockets ) :
 lisp_set_exception ( )
 if 11 - 11: I11i % I1Ii111 + O0 . Ii1I . I1ii11iIi11i % I1Ii111
 lisp_start_rloc_probe_timer ( LISP_RLOC_PROBE_INTERVAL , lisp_sockets )
 if ( lisp_rloc_probing == False ) : return
 if 28 - 28: IiII . o0oOOo0O0Ooo + iII111i - OoOoOO00 / OOooOOo
 if 86 - 86: ooOoO0o * OoOoOO00 + oO0o / II111iiii % OOooOOo
 if 89 - 89: O0 * Ii1I / OoO0O00 / OoOoOO00 % iII111i * iIii1I11I1II1
 if 72 - 72: iIii1I11I1II1 / iIii1I11I1II1 * I11i
 if ( lisp_print_rloc_probe_list ) : lisp_show_rloc_probe_list ( )
 if 19 - 19: I1ii11iIi11i
 if 42 - 42: OoOoOO00 / IiII
 if 65 - 65: ooOoO0o - ooOoO0o * OoO0O00
 if 99 - 99: I11i % ooOoO0o . I1Ii111
 I1IIii = lisp_get_default_route_next_hops ( )
 if 16 - 16: iIii1I11I1II1 / O0 - o0oOOo0O0Ooo + ooOoO0o * I1IiiI / i1IIi
 I11iI1i1 = "---------- Start RLOC Probing for {} RLOC entries ----------" . format ( len ( lisp_rloc_probe_list ) )
 if 28 - 28: I1Ii111 . OoooooooOO
 lprint ( bold ( I11iI1i1 , False ) )
 if 56 - 56: I1ii11iIi11i + i1IIi * I1Ii111 / ooOoO0o - I1ii11iIi11i . I11i
 if 25 - 25: Oo0Ooo / o0oOOo0O0Ooo + I1IiiI - I11i / i11iIiiIii
 if 89 - 89: II111iiii
 if 2 - 2: OoOoOO00 . i11iIiiIii
 o00oOoo0o00 = 0
 oO00oo0 = bold ( "RLOC-probe" , False )
 for i1II1ii1I1I in list ( lisp_rloc_probe_list . values ( ) ) :
  if 2 - 2: IiII - II111iiii / Oo0Ooo % IiII * I1ii11iIi11i
  if 26 - 26: ooOoO0o . OoOoOO00 / iIii1I11I1II1
  if 54 - 54: I1IiiI % II111iiii
  if 29 - 29: ooOoO0o - OOooOOo - I11i / I1Ii111
  if 88 - 88: O0 + IiII
  Oo0Oo0 = None
  for i1i , Ooo0O , i1I1IIIiII in i1II1ii1I1I :
   O00oO000Oo0 = i1i . rloc . print_address_no_iid ( )
   if 17 - 17: ooOoO0o % ooOoO0o * oO0o
   if 8 - 8: ooOoO0o + OoO0O00 . II111iiii / iIii1I11I1II1 - OOooOOo
   if 87 - 87: iIii1I11I1II1 . IiII % I1IiiI . OoO0O00 - I1Ii111
   if 53 - 53: I1Ii111 % i11iIiiIii
   oO0oo000O , Oo0oOoO0 , Ooooo00OO = lisp_allow_gleaning ( Ooo0O , None , i1i )
   if ( oO0oo000O and Oo0oOoO0 == False ) :
    oOO = green ( Ooo0O . print_address ( ) , False )
    O00oO000Oo0 += ":{}" . format ( i1i . translated_port )
    lprint ( "Suppress probe to RLOC {} for gleaned EID {}" . format ( red ( O00oO000Oo0 , False ) , oOO ) )
    if 59 - 59: o0oOOo0O0Ooo
    continue
    if 82 - 82: iIii1I11I1II1 + IiII + OoOoOO00 - OoooooooOO * II111iiii
    if 44 - 44: I11i + OoOoOO00 % I1IiiI + iIii1I11I1II1
    if 95 - 95: iII111i
    if 84 - 84: II111iiii + OOooOOo - I1Ii111 - Oo0Ooo * Ii1I * OOooOOo
    if 30 - 30: I1Ii111 % OOooOOo . Oo0Ooo * ooOoO0o % II111iiii % oO0o
    if 28 - 28: Ii1I % iIii1I11I1II1 % i11iIiiIii . oO0o
    if 54 - 54: Oo0Ooo - Oo0Ooo % oO0o
   if ( i1i . down_state ( ) ) : continue
   if 31 - 31: OoOoOO00
   if 60 - 60: Oo0Ooo % Oo0Ooo * IiII * O0 - Ii1I - I11i
   if 20 - 20: I11i % Ii1I
   if 19 - 19: II111iiii / i11iIiiIii * II111iiii + OoOoOO00 - OoOoOO00
   if 7 - 7: OoOoOO00 - OoO0O00 % OoOoOO00 . I1ii11iIi11i % Oo0Ooo * iII111i
   if 90 - 90: IiII - OOooOOo + iIii1I11I1II1
   if 88 - 88: ooOoO0o . o0oOOo0O0Ooo . OOooOOo - I11i
   if 76 - 76: IiII % I1IiiI . iII111i
   if 5 - 5: ooOoO0o . oO0o - OoOoOO00 - OoooooooOO
   if 2 - 2: OOooOOo
   if 37 - 37: IiII - iIii1I11I1II1 * i11iIiiIii . ooOoO0o
   if ( Oo0Oo0 ) :
    i1i . last_rloc_probe_nonce = Oo0Oo0 . last_rloc_probe_nonce
    if ( Oo0Oo0 . translated_port == i1i . translated_port and Oo0Oo0 . rloc_name == i1i . rloc_name ) :
     if 78 - 78: OOooOOo - I1ii11iIi11i + iII111i % OoOoOO00
     oOO = green ( lisp_print_eid_tuple ( Ooo0O , i1I1IIIiII ) , False )
     lprint ( "Suppress probe to duplicate RLOC {} for {}" . format ( red ( O00oO000Oo0 , False ) , oOO ) )
     if 28 - 28: I11i + i1IIi / i11iIiiIii * OOooOOo * II111iiii
     if 78 - 78: OoO0O00 - i1IIi % I1Ii111
     if 87 - 87: I11i
     if 37 - 37: iII111i . I1Ii111 - iII111i - I11i - iIii1I11I1II1 - II111iiii
     if 80 - 80: I1Ii111 % O0 - IiII / II111iiii + i1IIi
     if 4 - 4: OOooOOo + II111iiii
     i1i . last_rloc_probe = Oo0Oo0 . last_rloc_probe
     continue
     if 1 - 1: OoooooooOO * I1Ii111 - I11i / IiII
     if 43 - 43: i11iIiiIii * I1IiiI
     if 48 - 48: Oo0Ooo - OOooOOo / iII111i % I1ii11iIi11i . OoOoOO00
     if 6 - 6: i11iIiiIii
     if 51 - 51: o0oOOo0O0Ooo - OoooooooOO - I11i % i11iIiiIii / I1IiiI + IiII
     if 91 - 91: O0
     if 13 - 13: o0oOOo0O0Ooo
     if 15 - 15: iIii1I11I1II1 * Oo0Ooo . iIii1I11I1II1 . Ii1I % iII111i - i11iIiiIii
   iIIiIi1111iiIii = None
   while ( True ) :
    iIIiIi1111iiIii = i1i if iIIiIi1111iiIii == None else iIIiIi1111iiIii . next_rloc
    if ( iIIiIi1111iiIii == None ) : break
    if 77 - 77: ooOoO0o - o0oOOo0O0Ooo * OoOoOO00 % oO0o
    if 4 - 4: i11iIiiIii + OoOoOO00
    if 45 - 45: ooOoO0o / OoooooooOO . Oo0Ooo
    if 35 - 35: i11iIiiIii / o0oOOo0O0Ooo / oO0o / I11i . O0
    if 53 - 53: i1IIi
    if ( iIIiIi1111iiIii . rloc_next_hop != None ) :
     if ( iIIiIi1111iiIii . rloc_next_hop not in I1IIii ) :
      oooOo , o0o00o0oo000O = iIIiIi1111iiIii . rloc_next_hop
      if ( iIIiIi1111iiIii . up_state ( ) ) :
       iIIiIi1111iiIii . state = LISP_RLOC_UNREACH_STATE
       iIIiIi1111iiIii . last_state_change = lisp_get_timestamp ( )
       lisp_update_rtr_updown ( iIIiIi1111iiIii . rloc , False )
       if 51 - 51: OoOoOO00 / iIii1I11I1II1 . oO0o - I1ii11iIi11i - OOooOOo
      o00ooooO0O00 = bold ( "unreachable" , False )
      lprint ( "Next-hop {}({}) for RLOC {} is {}" . format ( o0o00o0oo000O , oooOo ,
 red ( O00oO000Oo0 , False ) , o00ooooO0O00 ) )
      continue
      if 90 - 90: i1IIi / oO0o * I1Ii111 + II111iiii % I11i
      if 41 - 41: o0oOOo0O0Ooo - II111iiii . ooOoO0o . iII111i - ooOoO0o / iII111i
      if 59 - 59: O0 / II111iiii * II111iiii - ooOoO0o
      if 63 - 63: I1ii11iIi11i * IiII % OoO0O00 . OoOoOO00 - II111iiii % IiII
      if 8 - 8: iIii1I11I1II1
      if 71 - 71: oO0o / o0oOOo0O0Ooo % iIii1I11I1II1 * iIii1I11I1II1
    O0oo = iIIiIi1111iiIii . last_rloc_probe
    i1IIIIII1 = 0 if O0oo == None else time . time ( ) - O0oo
    if ( iIIiIi1111iiIii . unreach_state ( ) and i1IIIIII1 < LISP_RLOC_PROBE_INTERVAL ) :
     lprint ( "Waiting for probe-reply from RLOC {}" . format ( red ( O00oO000Oo0 , False ) ) )
     if 50 - 50: I1ii11iIi11i
     continue
     if 24 - 24: ooOoO0o
     if 19 - 19: oO0o
     if 97 - 97: IiII
     if 36 - 36: II111iiii
     if 83 - 83: I11i . ooOoO0o
     if 57 - 57: IiII
    oOoOooO0OOOoo = lisp_get_echo_nonce ( None , O00oO000Oo0 )
    if ( oOoOooO0OOOoo and oOoOooO0OOOoo . request_nonce_timeout ( ) ) :
     iIIiIi1111iiIii . state = LISP_RLOC_NO_ECHOED_NONCE_STATE
     iIIiIi1111iiIii . last_state_change = lisp_get_timestamp ( )
     o00ooooO0O00 = bold ( "unreachable" , False )
     lprint ( "RLOC {} went {}, nonce-echo failed" . format ( red ( O00oO000Oo0 , False ) , o00ooooO0O00 ) )
     if 34 - 34: I1ii11iIi11i + i11iIiiIii - I1ii11iIi11i / OoOoOO00 + i1IIi . i11iIiiIii
     lisp_update_rtr_updown ( iIIiIi1111iiIii . rloc , False )
     continue
     if 48 - 48: I1ii11iIi11i % OoOoOO00 * OoOoOO00 % o0oOOo0O0Ooo * II111iiii / OoOoOO00
     if 73 - 73: OoOoOO00 + OOooOOo * II111iiii . OOooOOo % I1Ii111 % oO0o
     if 79 - 79: I1ii11iIi11i % I11i
     if 78 - 78: i11iIiiIii % I1Ii111 + iIii1I11I1II1 + iII111i
     if 66 - 66: I1IiiI - o0oOOo0O0Ooo
     if 67 - 67: oO0o . iII111i * Ii1I - OOooOOo / oO0o
    if ( oOoOooO0OOOoo and oOoOooO0OOOoo . recently_echoed ( ) ) :
     lprint ( ( "Suppress RLOC-probe to {}, nonce-echo " + "received" ) . format ( red ( O00oO000Oo0 , False ) ) )
     if 98 - 98: OoOoOO00 * OoO0O00 . Oo0Ooo
     continue
     if 6 - 6: I11i % iIii1I11I1II1 + I1Ii111
     if 48 - 48: II111iiii . OOooOOo . ooOoO0o - iII111i
     if 90 - 90: OOooOOo
     if 43 - 43: IiII + ooOoO0o
     if 4 - 4: i1IIi
     if 89 - 89: Oo0Ooo / iIii1I11I1II1 . OoOoOO00
    if ( iIIiIi1111iiIii . last_rloc_probe != None ) :
     O0oo = iIIiIi1111iiIii . last_rloc_probe_reply
     if ( O0oo == None ) : O0oo = 0
     i1IIIIII1 = time . time ( ) - O0oo
     if ( iIIiIi1111iiIii . up_state ( ) and i1IIIIII1 >= LISP_RLOC_PROBE_REPLY_WAIT ) :
      if 6 - 6: Ii1I / iII111i
      iIIiIi1111iiIii . state = LISP_RLOC_UNREACH_STATE
      iIIiIi1111iiIii . last_state_change = lisp_get_timestamp ( )
      lisp_update_rtr_updown ( iIIiIi1111iiIii . rloc , False )
      o00ooooO0O00 = bold ( "unreachable" , False )
      lprint ( "RLOC {} went {}, probe it" . format ( red ( O00oO000Oo0 , False ) , o00ooooO0O00 ) )
      if 69 - 69: iIii1I11I1II1 % I1Ii111 % OOooOOo + O0 - OoOoOO00 % oO0o
      if 70 - 70: oO0o - I1IiiI + Ii1I
      lisp_mark_rlocs_for_other_eids ( i1II1ii1I1I )
      if 54 - 54: OoOoOO00 / ooOoO0o - I1IiiI
      if 37 - 37: o0oOOo0O0Ooo
      if 57 - 57: iII111i / i1IIi / i1IIi + IiII
    iIIiIi1111iiIii . last_rloc_probe = lisp_get_timestamp ( )
    if 75 - 75: IiII / O0
    oO000oo0oo = "" if iIIiIi1111iiIii . unreach_state ( ) == False else " unreachable"
    if 25 - 25: I1Ii111 + o0oOOo0O0Ooo
    if 74 - 74: I1IiiI / OoO0O00 - Oo0Ooo % Ii1I
    if 97 - 97: iIii1I11I1II1 + OoOoOO00
    if 58 - 58: II111iiii % iII111i + oO0o + OOooOOo
    if 47 - 47: OoO0O00
    if 98 - 98: i11iIiiIii . OoooooooOO
    if 37 - 37: OoooooooOO + O0 . I11i % OoOoOO00
    O0O = ""
    ooOooO = None
    if 70 - 70: I1Ii111
    if 22 - 22: i1IIi
    if 61 - 61: IiII
    if 3 - 3: ooOoO0o . Oo0Ooo . ooOoO0o / OoO0O00 / o0oOOo0O0Ooo . I1Ii111
    if 20 - 20: iII111i + II111iiii + i11iIiiIii
    if 75 - 75: OoooooooOO
    if 63 - 63: iII111i % oO0o . ooOoO0o * I1Ii111 + o0oOOo0O0Ooo * II111iiii
    if ( iIIiIi1111iiIii . rloc_next_hop != None ) :
     oooOo , o000o0oO0 = iIIiIi1111iiIii . rloc_next_hop
     ooOooO = oooOo
     iIIiIi1111iiIii . set_active_rloc_next_hop ( )
     O0O = ", send to nh {} on {}" . format ( o000o0oO0 , bold ( oooOo , False ) )
     if 61 - 61: oO0o
     if 45 - 45: I11i * OoOoOO00 % Oo0Ooo / iII111i
     if 78 - 78: II111iiii
     if 38 - 38: I11i - i11iIiiIii
     if 38 - 38: I1IiiI * i1IIi / OoO0O00 + iIii1I11I1II1 / I1Ii111 % II111iiii
     if 62 - 62: OoOoOO00 * i1IIi + iII111i
     iIIiIi1111iiIii . probing_itr_rloc = lisp_get_interface_address ( oooOo )
     if 43 - 43: OOooOOo % i11iIiiIii / I1ii11iIi11i + i1IIi / ooOoO0o
     if 74 - 74: Ii1I + iIii1I11I1II1
     if 23 - 23: OoO0O00 * i1IIi * oO0o % I1ii11iIi11i
     if 92 - 92: iII111i / I1IiiI / i11iIiiIii
     if 75 - 75: Oo0Ooo + IiII / I11i % I11i % IiII / I1Ii111
    if ( ooOooO ) : lisp_bind_interface ( lisp_sockets [ 3 ] , ooOooO )
    if 95 - 95: OoOoOO00
    if 78 - 78: I11i
    if 62 - 62: iIii1I11I1II1 . o0oOOo0O0Ooo . ooOoO0o % oO0o % O0 % oO0o
    if 51 - 51: Oo0Ooo / IiII - Oo0Ooo
    OO0OO0o0oO = iIIiIi1111iiIii . print_rloc_probe_rtt ( )
    O00O00OOo0oo0 = O00oO000Oo0
    if ( iIIiIi1111iiIii . translated_port != 0 ) :
     O00O00OOo0oo0 += ":{}" . format ( iIIiIi1111iiIii . translated_port )
     if 92 - 92: i1IIi + I1Ii111 . i1IIi % I1ii11iIi11i
    O00O00OOo0oo0 = red ( O00O00OOo0oo0 , False )
    if ( iIIiIi1111iiIii . rloc_name != None ) :
     O00O00OOo0oo0 += " (" + blue ( iIIiIi1111iiIii . rloc_name , False ) + ")"
     if 59 - 59: iII111i * O0
    lprint ( "Send {} to{} {}, last rtt: {}{}" . format ( oO00oo0 , oO000oo0oo ,
 O00O00OOo0oo0 , OO0OO0o0oO , O0O ) )
    if 88 - 88: ooOoO0o / OoOoOO00 % IiII - iIii1I11I1II1 / I11i
    if 15 - 15: O0 . II111iiii
    if 14 - 14: oO0o . I11i . i1IIi + I1ii11iIi11i
    if 53 - 53: Ii1I
    if 35 - 35: oO0o * i1IIi / IiII / iII111i
    if ( iIIiIi1111iiIii . rloc . is_null ( ) ) :
     iIIiIi1111iiIii . rloc . copy_address ( i1i . rloc )
     if 19 - 19: I1IiiI + iIii1I11I1II1 * O0 - OOooOOo
     if 32 - 32: O0 - II111iiii - i1IIi + O0 + OOooOOo
     if 44 - 44: I11i * oO0o % OoooooooOO % OoO0O00 / o0oOOo0O0Ooo
     if 37 - 37: OoO0O00 + OoOoOO00 - I1IiiI
     if 68 - 68: i11iIiiIii / OOooOOo . i1IIi . i11iIiiIii . I11i
    if ( iIIiIi1111iiIii . multicast_rloc_probe_list != { } ) :
     lisp_process_multicast_rloc ( iIIiIi1111iiIii )
     if 56 - 56: iIii1I11I1II1 - II111iiii * i1IIi / Ii1I
     if 65 - 65: OOooOOo / I1IiiI . OoooooooOO + I1IiiI + OoooooooOO + i11iIiiIii
     if 20 - 20: I1IiiI + iII111i + O0 * O0
     if 18 - 18: I11i - I11i . OoOoOO00 . ooOoO0o
     if 31 - 31: ooOoO0o
    oo0Oo = None if ( i1I1IIIiII . is_null ( ) ) else Ooo0O
    OoO0oO = Ooo0O if ( i1I1IIIiII . is_null ( ) ) else i1I1IIIiII
    lisp_send_map_request ( lisp_sockets , 0 , oo0Oo , OoO0oO , iIIiIi1111iiIii )
    Oo0Oo0 = i1i
    if 45 - 45: ooOoO0o - OoooooooOO + OoOoOO00
    if 45 - 45: I1ii11iIi11i - OoooooooOO * IiII - OoOoOO00 % I11i / iIii1I11I1II1
    if 32 - 32: OoOoOO00 - O0 * I1IiiI
    if 81 - 81: ooOoO0o + O0 . o0oOOo0O0Ooo * OoO0O00 % i1IIi
    if ( ooOooO ) : lisp_unbind_interface ( lisp_sockets [ 3 ] )
    if 81 - 81: OoooooooOO + O0 / oO0o . I1ii11iIi11i - i1IIi - iII111i
    if 14 - 14: OoooooooOO - II111iiii
    if 74 - 74: OOooOOo
    if 91 - 91: ooOoO0o
    if 96 - 96: I1IiiI . OOooOOo
    if 94 - 94: OoooooooOO + II111iiii % ooOoO0o - II111iiii / O0
    if ( iIIiIi1111iiIii . is_decent_nat_port ( ) and iIIiIi1111iiIii . unreach_state ( ) ) :
     iIIiIi1111iiIii . refresh_decent_nat_rloc ( lisp_sockets , OoO0oO )
     if 34 - 34: IiII % oO0o
     if 54 - 54: I1IiiI
     if 80 - 80: OoOoOO00 . I1IiiI / I1ii11iIi11i . iII111i
     if 31 - 31: I11i * o0oOOo0O0Ooo
     if 17 - 17: Ii1I * iIii1I11I1II1
     if 9 - 9: o0oOOo0O0Ooo - IiII
   o00oOoo0o00 += 1
   if ( ( o00oOoo0o00 % 10 ) == 0 ) : time . sleep ( 0.020 )
   if 78 - 78: i11iIiiIii . o0oOOo0O0Ooo
   if 72 - 72: Oo0Ooo % II111iiii + O0 * OoOoOO00 - OOooOOo + I1Ii111
   if 23 - 23: I1IiiI - O0 - iII111i . II111iiii / oO0o
 lprint ( bold ( "---------- End RLOC Probing ----------" , False ) )
 return
 if 1 - 1: I11i . OOooOOo / oO0o % I11i * Oo0Ooo + Oo0Ooo
 if 23 - 23: Ii1I % i1IIi - I1Ii111
 if 95 - 95: OoOoOO00 - ooOoO0o . i1IIi . OoooooooOO
 if 38 - 38: I1IiiI + I1ii11iIi11i - Oo0Ooo . i11iIiiIii - i1IIi
 if 11 - 11: IiII / I1IiiI . I1IiiI
 if 87 - 87: OoooooooOO * OoO0O00 * iIii1I11I1II1
 if 16 - 16: o0oOOo0O0Ooo * I11i + OoooooooOO + O0 / iIii1I11I1II1
 if 60 - 60: Ii1I % IiII * OoooooooOO * ooOoO0o * Ii1I
def lisp_update_rtr_updown ( rtr , updown ) :
 global lisp_ipc_socket
 if 8 - 8: I1Ii111 - o0oOOo0O0Ooo
 if 52 - 52: OoOoOO00 % O0 + I1ii11iIi11i . i11iIiiIii
 if 59 - 59: Ii1I - I1Ii111 . ooOoO0o - OoOoOO00 + oO0o . OoO0O00
 if 88 - 88: OOooOOo - ooOoO0o * o0oOOo0O0Ooo . OoooooooOO
 if ( lisp_i_am_itr == False ) : return
 if 3 - 3: I1Ii111
 if 24 - 24: Ii1I + i11iIiiIii * I1Ii111 - OoOoOO00 / Ii1I - OoOoOO00
 if 69 - 69: I11i - I1IiiI . oO0o - OoooooooOO
 if 33 - 33: o0oOOo0O0Ooo - o0oOOo0O0Ooo
 if 55 - 55: OoooooooOO / IiII + i1IIi
 if ( lisp_register_all_rtrs ) : return
 if 54 - 54: ooOoO0o * Ii1I / Ii1I
 iI1iII11I1ii1 = rtr . print_address_no_iid ( )
 if 24 - 24: o0oOOo0O0Ooo + OoooooooOO + Oo0Ooo
 if 61 - 61: I1ii11iIi11i / Ii1I . o0oOOo0O0Ooo
 if 40 - 40: OOooOOo - i11iIiiIii - I11i . i1IIi * o0oOOo0O0Ooo
 if 2 - 2: I1ii11iIi11i * IiII
 if 64 - 64: OoooooooOO % OoooooooOO
 if ( iI1iII11I1ii1 not in lisp_rtr_list ) : return
 if 45 - 45: I1IiiI % I11i - I11i % i1IIi . Ii1I
 updown = "up" if updown else "down"
 lprint ( "Send ETR IPC message, RTR {} has done {}" . format (
 red ( iI1iII11I1ii1 , False ) , bold ( updown , False ) ) )
 if 16 - 16: OoooooooOO
 if 21 - 21: iII111i % OOooOOo . o0oOOo0O0Ooo % iII111i
 if 98 - 98: Oo0Ooo . Oo0Ooo - ooOoO0o % oO0o / iII111i
 if 14 - 14: ooOoO0o
 ooo0ooo0Oo = "rtr%{}%{}" . format ( iI1iII11I1ii1 , updown )
 ooo0ooo0Oo = lisp_command_ipc ( ooo0ooo0Oo , "lisp-itr" )
 lisp_ipc ( ooo0ooo0Oo , lisp_ipc_socket , "lisp-etr" )
 return
 if 19 - 19: i1IIi - iIii1I11I1II1 * I1ii11iIi11i - O0 % OOooOOo
 if 17 - 17: I1Ii111 . ooOoO0o
 if 34 - 34: o0oOOo0O0Ooo / OOooOOo + Ii1I % Oo0Ooo % I1ii11iIi11i
 if 72 - 72: IiII / II111iiii
 if 25 - 25: i1IIi + OoOoOO00 + oO0o + OoooooooOO
 if 21 - 21: I1ii11iIi11i
 if 60 - 60: i1IIi / OoO0O00 . Ii1I
def lisp_process_rloc_probe_reply ( rloc_entry , source , port , map_reply , ttl , mrloc , rloc_name ) :
 global lisp_rloc_probe_nonce_list
 if 16 - 16: i11iIiiIii + OoOoOO00 % Oo0Ooo + I1ii11iIi11i * Ii1I / I1Ii111
 iIIiIi1111iiIii = rloc_entry . rloc
 o0oOoo00 = map_reply . nonce
 iii1IiII11i = map_reply . hop_count
 oO00oo0 = bold ( "RLOC-probe reply" , False )
 i1I11iiI1 = iIIiIi1111iiIii . print_address_no_iid ( )
 Iii1iIIIIiI1I = source . print_address_no_iid ( )
 O00OO0O = lisp_rloc_probe_list
 OOI1I1 = rloc_entry . json . json_string if rloc_entry . json else None
 iIiIIIIIii = lisp_get_timestamp ( )
 if 5 - 5: oO0o * Oo0Ooo % II111iiii + I1Ii111 / I1ii11iIi11i
 if 15 - 15: I1IiiI / I1Ii111 % iII111i
 if 57 - 57: I1Ii111 . iIii1I11I1II1 / Oo0Ooo / IiII / iII111i * OoOoOO00
 if 35 - 35: i1IIi + I1Ii111 - ooOoO0o . I1ii11iIi11i + Oo0Ooo
 if 43 - 43: oO0o . OoO0O00 * i1IIi
 if 1 - 1: ooOoO0o / i1IIi
 if ( mrloc != None ) :
  III11IiI1111I = mrloc . rloc . print_address_no_iid ( )
  if ( i1I11iiI1 not in mrloc . multicast_rloc_probe_list ) :
   o00oOOO0O00 = lisp_rloc ( )
   o00oOOO0O00 = copy . deepcopy ( mrloc )
   o00oOOO0O00 . rloc . copy_address ( iIIiIi1111iiIii )
   o00oOOO0O00 . multicast_rloc_probe_list = { }
   mrloc . multicast_rloc_probe_list [ i1I11iiI1 ] = o00oOOO0O00
   if 84 - 84: I1IiiI * Ii1I . I1IiiI % OOooOOo * Ii1I % OoO0O00
  o00oOOO0O00 = mrloc . multicast_rloc_probe_list [ i1I11iiI1 ]
  o00oOOO0O00 . rloc_name = rloc_name
  o00oOOO0O00 . last_rloc_probe_nonce = mrloc . last_rloc_probe_nonce
  o00oOOO0O00 . last_rloc_probe = mrloc . last_rloc_probe
  IIi1iii , Ooo0O , i1I1IIIiII = lisp_rloc_probe_list [ III11IiI1111I ] [ 0 ]
  o00oOOO0O00 . process_rloc_probe_reply ( iIiIIIIIii , o0oOoo00 , Ooo0O , i1I1IIIiII , iii1IiII11i , ttl , OOI1I1 )
  mrloc . process_rloc_probe_reply ( iIiIIIIIii , o0oOoo00 , Ooo0O , i1I1IIIiII , iii1IiII11i , ttl , OOI1I1 )
  return
  if 72 - 72: OoOoOO00 + o0oOOo0O0Ooo - i1IIi - OoO0O00 % OoOoOO00
  if 42 - 42: oO0o / i1IIi . IiII
  if 12 - 12: i11iIiiIii . ooOoO0o
  if 80 - 80: O0 / iIii1I11I1II1 % iII111i * ooOoO0o / i11iIiiIii . OoOoOO00
  if 88 - 88: OoooooooOO . I1IiiI
  if 6 - 6: I1Ii111 - i11iIiiIii - oO0o
 if ( rloc_name and rloc_name . find ( LISP_TP ) != - 1 ) :
  port = int ( rloc_name . split ( LISP_TP ) [ - 1 ] )
  if 7 - 7: i1IIi
  if 6 - 6: OoooooooOO - Oo0Ooo - I1ii11iIi11i
  if 34 - 34: iII111i + i11iIiiIii . IiII
  if 54 - 54: Oo0Ooo + I11i - iII111i * ooOoO0o % i11iIiiIii . IiII
  if 29 - 29: II111iiii % i11iIiiIii % O0
  if 38 - 38: o0oOOo0O0Ooo * IiII
  if 51 - 51: OoooooooOO . Ii1I % OoooooooOO - I1IiiI + I1Ii111 % oO0o
 iI1ii11Ii = i1I11iiI1
 if ( iI1ii11Ii not in O00OO0O ) :
  iI1ii11Ii += ":" + str ( port )
  if ( iI1ii11Ii not in O00OO0O ) :
   iI1ii11Ii = Iii1iIIIIiI1I
   if ( iI1ii11Ii not in O00OO0O ) :
    iI1ii11Ii += ":" + str ( port )
    if ( iI1ii11Ii not in O00OO0O ) :
     lprint ( "    Received unsolicited {} from {}/{}, port {}" . format ( oO00oo0 , red ( i1I11iiI1 , False ) , red ( Iii1iIIIIiI1I , False ) , port ) )
     if 28 - 28: i11iIiiIii - I1IiiI * OoO0O00
     return
     if 19 - 19: OoooooooOO
     if 34 - 34: OoOoOO00 . oO0o
     if 53 - 53: oO0o + OoooooooOO * ooOoO0o
     if 85 - 85: I1ii11iIi11i - o0oOOo0O0Ooo % o0oOOo0O0Ooo % iII111i * OoOoOO00
     if 50 - 50: I1Ii111 + I1Ii111 + I11i - OoOoOO00
     if 65 - 65: oO0o / I11i + iII111i - I1ii11iIi11i
     if 80 - 80: II111iiii . i11iIiiIii
     if 66 - 66: ooOoO0o * iII111i * OOooOOo % OoO0O00 / I1ii11iIi11i
     if 33 - 33: iIii1I11I1II1
     if 52 - 52: iIii1I11I1II1 + O0
     if 84 - 84: OOooOOo / iII111i . I1IiiI / O0 % OOooOOo . iII111i
 if ( o0oOoo00 in lisp_rloc_probe_nonce_list ) :
  II1IiIi1111 = lisp_rloc_probe_nonce_list . pop ( o0oOoo00 )
  if ( II1IiIi1111 != iI1ii11Ii ) :
   iI1ii11Ii = II1IiIi1111
   lprint ( "    Obtain probed RLOC address {} from nonce 0x{}" . format ( iI1ii11Ii , lisp_hex_string ( o0oOoo00 ) ) )
   if 87 - 87: Ii1I % II111iiii * Ii1I / O0
   if 6 - 6: oO0o * ooOoO0o . I1Ii111 / OOooOOo . OoOoOO00
   if 4 - 4: Ii1I / II111iiii + o0oOOo0O0Ooo / IiII
   if 9 - 9: ooOoO0o + i1IIi / ooOoO0o / I11i * I1ii11iIi11i / OoooooooOO
   if 28 - 28: o0oOOo0O0Ooo
   if 97 - 97: I1Ii111 - I1Ii111 * OoO0O00 % II111iiii * IiII
   if 2 - 2: I1Ii111 % iII111i . OoooooooOO - o0oOOo0O0Ooo
   if 30 - 30: i1IIi / I1Ii111 * oO0o - oO0o / oO0o
 if ( iI1ii11Ii not in lisp_rloc_probe_list ) : return
 if 9 - 9: IiII / o0oOOo0O0Ooo . IiII * O0 % i11iIiiIii % OoOoOO00
 if 29 - 29: I1ii11iIi11i % ooOoO0o . OOooOOo . Ii1I . IiII
 if 69 - 69: o0oOOo0O0Ooo . i11iIiiIii * I11i + IiII / I11i
 if 66 - 66: I1ii11iIi11i % I1Ii111 - i11iIiiIii % I11i
 if 62 - 62: i11iIiiIii % iIii1I11I1II1 / IiII . I1IiiI * O0
 II11Ii1II = None
 for iIIiIi1111iiIii , Ooo0O , i1I1IIIiII in lisp_rloc_probe_list [ iI1ii11Ii ] :
  if ( lisp_i_am_rtr ) :
   if ( iIIiIi1111iiIii . translated_port != 0 and iIIiIi1111iiIii . translated_port != port ) :
    continue
    if 37 - 37: iII111i - iIii1I11I1II1 / I1Ii111 + iIii1I11I1II1 % I1ii11iIi11i . OoO0O00
    if 79 - 79: I1ii11iIi11i / i11iIiiIii . i1IIi - I1Ii111 + I1IiiI
  iiO0Ii1IiiiI = iIIiIi1111iiIii . process_rloc_probe_reply ( iIiIIIIIii , o0oOoo00 , Ooo0O , i1I1IIIiII , iii1IiII11i , ttl , OOI1I1 )
  if 9 - 9: iIii1I11I1II1 / iIii1I11I1II1
  if 24 - 24: OOooOOo . I1IiiI % i11iIiiIii
  if 43 - 43: OoooooooOO . o0oOOo0O0Ooo - I1ii11iIi11i + OoO0O00 . I1Ii111 . iII111i
  if 1 - 1: iII111i / OoO0O00 / OoOoOO00 * Oo0Ooo * OoooooooOO
  if 59 - 59: iII111i
  if ( iiO0Ii1IiiiI and II11Ii1II == None ) :
   IIIiiI11ii = iIIiIi1111iiIii
   while ( IIIiiI11ii != None ) :
    if ( IIIiiI11ii . last_rloc_probe_nonce == o0oOoo00 ) :
     II11Ii1II = IIIiiI11ii
     break
     if 30 - 30: iII111i . OoO0O00 . i11iIiiIii / I1ii11iIi11i * Oo0Ooo
    IIIiiI11ii = IIIiiI11ii . next_rloc
    if 38 - 38: IiII + II111iiii
    if 20 - 20: iII111i * I1IiiI * iII111i - o0oOOo0O0Ooo + i1IIi + ooOoO0o
    if 49 - 49: II111iiii * I1IiiI / oO0o
 if ( II11Ii1II == None ) : return
 if ( II11Ii1II . rloc_next_hop == None ) : return
 if 50 - 50: Ii1I + O0 . I1IiiI * Oo0Ooo
 if 15 - 15: Oo0Ooo
 if 53 - 53: OoooooooOO * O0 / iII111i * ooOoO0o % I1Ii111 + OOooOOo
 if 95 - 95: I1Ii111 % OoOoOO00 . IiII * iII111i % Ii1I
 if 18 - 18: iIii1I11I1II1 / ooOoO0o / I1Ii111 % oO0o * Ii1I
 if 14 - 14: oO0o
 Oo0o = II11Ii1II . rloc_next_hop
 for i1i , Ooo0O , i1I1IIIiII in lisp_rloc_probe_list [ iI1ii11Ii ] :
  if 38 - 38: I1IiiI + OoO0O00
  if 11 - 11: iIii1I11I1II1 + i1IIi * IiII - Oo0Ooo
  if 66 - 66: I1Ii111 . Ii1I / I1ii11iIi11i / iIii1I11I1II1 + O0 / i1IIi
  if 72 - 72: ooOoO0o . II111iiii
  if 32 - 32: I1Ii111 - oO0o + OoooooooOO . OoOoOO00 + i11iIiiIii / i1IIi
  O000oOooO0oo = i1i
  IIIiiI11ii = i1i
  while ( IIIiiI11ii != None ) :
   if ( IIIiiI11ii . rloc_next_hop == Oo0o ) :
    O000oOooO0oo = IIIiiI11ii
    break
    if 26 - 26: I1IiiI + OoooooooOO % OoOoOO00 . IiII - II111iiii . OoOoOO00
   IIIiiI11ii = IIIiiI11ii . next_rloc
   if 37 - 37: OoO0O00 % O0 + OoOoOO00 * I11i . Ii1I * OoO0O00
   if 18 - 18: o0oOOo0O0Ooo / OOooOOo
   if 28 - 28: O0 / Ii1I - oO0o % I1ii11iIi11i % O0 . OoO0O00
   if 100 - 100: O0
   if 19 - 19: Ii1I * iIii1I11I1II1 * Oo0Ooo - i11iIiiIii * i11iIiiIii - OOooOOo
  if ( O000oOooO0oo != II11Ii1II ) :
   O000oOooO0oo . copy_rloc_probe_recents ( II11Ii1II )
   if 88 - 88: O0 . iIii1I11I1II1 . I1ii11iIi11i
   if 80 - 80: oO0o / i1IIi * iIii1I11I1II1
 return
 if 38 - 38: Ii1I
 if 20 - 20: iIii1I11I1II1 + Oo0Ooo - Ii1I / i11iIiiIii . OoO0O00
 if 66 - 66: OoooooooOO - Ii1I / iII111i . I1IiiI + I1ii11iIi11i - I1Ii111
 if 36 - 36: I1Ii111 - OoO0O00 . I1ii11iIi11i * I1ii11iIi11i
 if 9 - 9: OOooOOo - oO0o - iIii1I11I1II1 * i11iIiiIii / I11i
 if 2 - 2: i1IIi % iII111i * ooOoO0o / OoOoOO00 + Oo0Ooo
 if 59 - 59: i11iIiiIii / I1IiiI * iII111i
 if 16 - 16: i11iIiiIii * II111iiii - ooOoO0o
def lisp_db_list_length ( ) :
 o00oOoo0o00 = 0
 for Iiii1II1 in lisp_db_list :
  o00oOoo0o00 += len ( Iiii1II1 . dynamic_eids ) if Iiii1II1 . dynamic_eid_configured ( ) else 1
  o00oOoo0o00 += len ( Iiii1II1 . eid . iid_list )
  if 80 - 80: iIii1I11I1II1 + iIii1I11I1II1 + I1Ii111 - IiII * iII111i - Ii1I
 return ( o00oOoo0o00 )
 if 89 - 89: O0 * ooOoO0o
 if 36 - 36: I1ii11iIi11i * II111iiii * iII111i + I1IiiI + OoO0O00 + oO0o
 if 28 - 28: Ii1I - i11iIiiIii . oO0o / II111iiii
 if 82 - 82: iII111i * iII111i . IiII * II111iiii
 if 17 - 17: OoooooooOO % I1Ii111 * I1Ii111 / II111iiii . OoOoOO00 * iII111i
 if 80 - 80: IiII % i11iIiiIii
 if 6 - 6: II111iiii + i11iIiiIii - Oo0Ooo % OOooOOo + Oo0Ooo
 if 46 - 46: iII111i
def lisp_is_myeid ( eid ) :
 for Iiii1II1 in lisp_db_list :
  if ( eid . is_more_specific ( Iiii1II1 . eid ) ) : return ( True )
  if 31 - 31: OoO0O00 + I1Ii111 / iIii1I11I1II1
 return ( False )
 if 11 - 11: ooOoO0o - OoOoOO00
 if 19 - 19: O0 . OoOoOO00 - i1IIi . oO0o
 if 96 - 96: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoO0O00 * iIii1I11I1II1 + ooOoO0o - ooOoO0o
 if 4 - 4: OoO0O00 - OOooOOo
 if 21 - 21: I1Ii111 * i11iIiiIii
 if 63 - 63: oO0o + OoOoOO00
 if 50 - 50: o0oOOo0O0Ooo / Oo0Ooo * ooOoO0o * Ii1I
 if 97 - 97: I1IiiI / oO0o + I1Ii111 + I1Ii111
 if 86 - 86: o0oOOo0O0Ooo % ooOoO0o + OoOoOO00 * ooOoO0o
def lisp_format_macs ( sa , da ) :
 sa = sa [ 0 : 4 ] + "-" + sa [ 4 : 8 ] + "-" + sa [ 8 : 12 ]
 da = da [ 0 : 4 ] + "-" + da [ 4 : 8 ] + "-" + da [ 8 : 12 ]
 return ( "{} -> {}" . format ( sa , da ) )
 if 20 - 20: Ii1I * iII111i / ooOoO0o
 if 18 - 18: Oo0Ooo * Ii1I / i11iIiiIii . OoO0O00 + OoooooooOO
 if 23 - 23: I1IiiI - I1ii11iIi11i . O0 . OoOoOO00 . OoO0O00
 if 81 - 81: IiII * I11i - iIii1I11I1II1
 if 41 - 41: oO0o * I11i + I1IiiI - OoO0O00
 if 63 - 63: Oo0Ooo * Ii1I - Ii1I
 if 76 - 76: OoO0O00 . IiII % iIii1I11I1II1 / I1IiiI + iIii1I11I1II1 . I1IiiI
def lisp_get_echo_nonce ( rloc , rloc_str ) :
 if ( lisp_nonce_echoing == False ) : return ( None )
 if 57 - 57: IiII - i1IIi * ooOoO0o
 if ( rloc ) : rloc_str = rloc . print_address_no_iid ( )
 oOoOooO0OOOoo = None
 if ( rloc_str in lisp_nonce_echo_list ) :
  oOoOooO0OOOoo = lisp_nonce_echo_list [ rloc_str ]
  if 5 - 5: oO0o . O0 * IiII / Ii1I + OoO0O00
 return ( oOoOooO0OOOoo )
 if 75 - 75: OOooOOo * OoOoOO00
 if 82 - 82: Ii1I
 if 83 - 83: I1IiiI
 if 22 - 22: IiII / Ii1I + I1Ii111 % iIii1I11I1II1
 if 75 - 75: OoOoOO00 % OoOoOO00 % o0oOOo0O0Ooo % I1ii11iIi11i + IiII
 if 45 - 45: I11i - iIii1I11I1II1
 if 20 - 20: OoOoOO00
 if 84 - 84: OoOoOO00
def lisp_decode_dist_name ( packet ) :
 o00oOoo0o00 = 0
 o0O0 = b""
 if 1 - 1: I1IiiI - O0
 while ( packet [ 0 : 1 ] != b"\x00" ) :
  if ( o00oOoo0o00 == 255 ) : return ( [ None , None ] )
  o0O0 += packet [ 0 : 1 ]
  packet = packet [ 1 : : ]
  o00oOoo0o00 += 1
  if 59 - 59: OOooOOo % IiII . ooOoO0o + O0 . ooOoO0o + iIii1I11I1II1
  if 68 - 68: i11iIiiIii . iII111i + OoooooooOO + II111iiii + iIii1I11I1II1 % I11i
 packet = packet [ 1 : : ]
 return ( packet , o0O0 . decode ( ) )
 if 7 - 7: i1IIi - o0oOOo0O0Ooo - I1IiiI
 if 62 - 62: OoOoOO00 * oO0o - I1IiiI / Ii1I
 if 48 - 48: o0oOOo0O0Ooo % o0oOOo0O0Ooo - OoOoOO00
 if 13 - 13: OoO0O00 - Ii1I . ooOoO0o / O0 * OoOoOO00
 if 57 - 57: O0 + OoooooooOO % o0oOOo0O0Ooo / I1Ii111 / OOooOOo - OoOoOO00
 if 48 - 48: o0oOOo0O0Ooo - II111iiii + OoOoOO00
 if 54 - 54: II111iiii - OoO0O00 - o0oOOo0O0Ooo - O0 % I1Ii111
 if 9 - 9: i1IIi % iII111i / Ii1I
def lisp_write_flow_log ( flow_log ) :
 O0Oo0 = open ( "./logs/lisp-flow.log" , "a" )
 if 83 - 83: oO0o
 o00oOoo0o00 = 0
 for oO00o0 in flow_log :
  Oo00O0o0O = oO00o0 [ 3 ]
  II1i1iiiII1ii = Oo00O0o0O . print_flow ( oO00o0 [ 0 ] , oO00o0 [ 1 ] , oO00o0 [ 2 ] )
  O0Oo0 . write ( II1i1iiiII1ii )
  o00oOoo0o00 += 1
  if 17 - 17: I1ii11iIi11i % Ii1I . IiII - I1ii11iIi11i
 O0Oo0 . close ( )
 del ( flow_log )
 if 85 - 85: iII111i - iIii1I11I1II1 . I1IiiI * OoO0O00 - iII111i
 o00oOoo0o00 = bold ( str ( o00oOoo0o00 ) , False )
 lprint ( "Wrote {} flow entries to ./logs/lisp-flow.log" . format ( o00oOoo0o00 ) )
 return
 if 97 - 97: ooOoO0o / I11i . IiII + I1Ii111 . iIii1I11I1II1
 if 24 - 24: ooOoO0o - oO0o % OoOoOO00 * Oo0Ooo
 if 54 - 54: Ii1I - OoooooooOO % I1IiiI + oO0o
 if 70 - 70: I1Ii111 % iIii1I11I1II1
 if 74 - 74: i1IIi % i11iIiiIii + oO0o
 if 94 - 94: OoO0O00 * I1IiiI / O0 + I1Ii111 / i11iIiiIii
 if 34 - 34: Oo0Ooo . i1IIi
def lisp_policy_command ( kv_pair ) :
 I1i1I = lisp_policy ( "" )
 o0O00oOOoo = None
 if 82 - 82: I1Ii111 + o0oOOo0O0Ooo - iII111i - Ii1I
 i1i1I1I1 = [ ]
 for o000o0O0Oo00 in range ( len ( kv_pair [ "datetime-range" ] ) ) :
  i1i1I1I1 . append ( lisp_policy_match ( ) )
  if 84 - 84: IiII % iIii1I11I1II1
  if 98 - 98: iII111i * i11iIiiIii * i1IIi / i1IIi % I1ii11iIi11i . OoO0O00
 for OOO000OOo0oo in list ( kv_pair . keys ( ) ) :
  oO00o = kv_pair [ OOO000OOo0oo ]
  if 49 - 49: o0oOOo0O0Ooo + i1IIi / iII111i
  if 43 - 43: i1IIi . OoO0O00 + I1ii11iIi11i
  if 88 - 88: OoooooooOO / I11i % II111iiii % OOooOOo - I11i
  if 55 - 55: Oo0Ooo - OOooOOo - O0
  if ( OOO000OOo0oo == "instance-id" ) :
   for o000o0O0Oo00 in range ( len ( i1i1I1I1 ) ) :
    iI1i1111 = oO00o [ o000o0O0Oo00 ]
    if ( iI1i1111 == "" ) : continue
    oooOOooo000Oo = i1i1I1I1 [ o000o0O0Oo00 ]
    if ( oooOOooo000Oo . source_eid == None ) :
     oooOOooo000Oo . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 81 - 81: IiII . o0oOOo0O0Ooo % ooOoO0o + O0 . iIii1I11I1II1
    if ( oooOOooo000Oo . dest_eid == None ) :
     oooOOooo000Oo . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 29 - 29: i1IIi
    oooOOooo000Oo . source_eid . instance_id = int ( iI1i1111 )
    oooOOooo000Oo . dest_eid . instance_id = int ( iI1i1111 )
    if 12 - 12: OOooOOo
    if 84 - 84: i11iIiiIii * o0oOOo0O0Ooo
  if ( OOO000OOo0oo == "source-eid" ) :
   for o000o0O0Oo00 in range ( len ( i1i1I1I1 ) ) :
    iI1i1111 = oO00o [ o000o0O0Oo00 ]
    if ( iI1i1111 == "" ) : continue
    oooOOooo000Oo = i1i1I1I1 [ o000o0O0Oo00 ]
    if ( oooOOooo000Oo . source_eid == None ) :
     oooOOooo000Oo . source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 24 - 24: Ii1I . OOooOOo
    i1I1iI = oooOOooo000Oo . source_eid . instance_id
    oooOOooo000Oo . source_eid . store_prefix ( iI1i1111 )
    oooOOooo000Oo . source_eid . instance_id = i1I1iI
    if 34 - 34: I11i % Oo0Ooo . II111iiii - OoO0O00 - I1Ii111 + Oo0Ooo
    if 71 - 71: O0 + OOooOOo % OoooooooOO
  if ( OOO000OOo0oo == "destination-eid" ) :
   for o000o0O0Oo00 in range ( len ( i1i1I1I1 ) ) :
    iI1i1111 = oO00o [ o000o0O0Oo00 ]
    if ( iI1i1111 == "" ) : continue
    oooOOooo000Oo = i1i1I1I1 [ o000o0O0Oo00 ]
    if ( oooOOooo000Oo . dest_eid == None ) :
     oooOOooo000Oo . dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
     if 51 - 51: I1ii11iIi11i * o0oOOo0O0Ooo * I11i
    i1I1iI = oooOOooo000Oo . dest_eid . instance_id
    oooOOooo000Oo . dest_eid . store_prefix ( iI1i1111 )
    oooOOooo000Oo . dest_eid . instance_id = i1I1iI
    if 27 - 27: OoOoOO00 % OoO0O00 * oO0o . II111iiii - i11iIiiIii
    if 56 - 56: OOooOOo . IiII - OOooOOo / i11iIiiIii * I1ii11iIi11i
  if ( OOO000OOo0oo == "source-rloc" ) :
   for o000o0O0Oo00 in range ( len ( i1i1I1I1 ) ) :
    iI1i1111 = oO00o [ o000o0O0Oo00 ]
    if ( iI1i1111 == "" ) : continue
    oooOOooo000Oo = i1i1I1I1 [ o000o0O0Oo00 ]
    oooOOooo000Oo . source_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    oooOOooo000Oo . source_rloc . store_prefix ( iI1i1111 )
    if 66 - 66: oO0o + ooOoO0o
    if 1 - 1: ooOoO0o
  if ( OOO000OOo0oo == "destination-rloc" ) :
   for o000o0O0Oo00 in range ( len ( i1i1I1I1 ) ) :
    iI1i1111 = oO00o [ o000o0O0Oo00 ]
    if ( iI1i1111 == "" ) : continue
    oooOOooo000Oo = i1i1I1I1 [ o000o0O0Oo00 ]
    oooOOooo000Oo . dest_rloc = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    oooOOooo000Oo . dest_rloc . store_prefix ( iI1i1111 )
    if 61 - 61: o0oOOo0O0Ooo / OoooooooOO . I1ii11iIi11i + Oo0Ooo
    if 75 - 75: Ii1I
  if ( OOO000OOo0oo == "rloc-record-name" ) :
   for o000o0O0Oo00 in range ( len ( i1i1I1I1 ) ) :
    iI1i1111 = oO00o [ o000o0O0Oo00 ]
    if ( iI1i1111 == "" ) : continue
    oooOOooo000Oo = i1i1I1I1 [ o000o0O0Oo00 ]
    oooOOooo000Oo . rloc_record_name = iI1i1111
    if 79 - 79: i1IIi . I1ii11iIi11i * o0oOOo0O0Ooo / I11i . I11i / ooOoO0o
    if 99 - 99: oO0o + I11i % i1IIi . iII111i
  if ( OOO000OOo0oo == "geo-name" ) :
   for o000o0O0Oo00 in range ( len ( i1i1I1I1 ) ) :
    iI1i1111 = oO00o [ o000o0O0Oo00 ]
    if ( iI1i1111 == "" ) : continue
    oooOOooo000Oo = i1i1I1I1 [ o000o0O0Oo00 ]
    oooOOooo000Oo . geo_name = iI1i1111
    if 58 - 58: Oo0Ooo % i11iIiiIii . Oo0Ooo / Oo0Ooo - I1IiiI . Ii1I
    if 65 - 65: OoO0O00
  if ( OOO000OOo0oo == "elp-name" ) :
   for o000o0O0Oo00 in range ( len ( i1i1I1I1 ) ) :
    iI1i1111 = oO00o [ o000o0O0Oo00 ]
    if ( iI1i1111 == "" ) : continue
    oooOOooo000Oo = i1i1I1I1 [ o000o0O0Oo00 ]
    oooOOooo000Oo . elp_name = iI1i1111
    if 16 - 16: IiII % I1IiiI % iIii1I11I1II1 . I1IiiI . I1ii11iIi11i - IiII
    if 6 - 6: I1Ii111 + OoO0O00 + O0 * OoOoOO00 . iIii1I11I1II1 . I1Ii111
  if ( OOO000OOo0oo == "rle-name" ) :
   for o000o0O0Oo00 in range ( len ( i1i1I1I1 ) ) :
    iI1i1111 = oO00o [ o000o0O0Oo00 ]
    if ( iI1i1111 == "" ) : continue
    oooOOooo000Oo = i1i1I1I1 [ o000o0O0Oo00 ]
    oooOOooo000Oo . rle_name = iI1i1111
    if 93 - 93: ooOoO0o % iIii1I11I1II1 + I1ii11iIi11i
    if 74 - 74: OoOoOO00 + I1ii11iIi11i
  if ( OOO000OOo0oo == "json-name" ) :
   for o000o0O0Oo00 in range ( len ( i1i1I1I1 ) ) :
    iI1i1111 = oO00o [ o000o0O0Oo00 ]
    if ( iI1i1111 == "" ) : continue
    oooOOooo000Oo = i1i1I1I1 [ o000o0O0Oo00 ]
    oooOOooo000Oo . json_name = iI1i1111
    if 82 - 82: II111iiii
    if 55 - 55: I11i . iIii1I11I1II1 / Ii1I - OoO0O00 * I1ii11iIi11i % iIii1I11I1II1
  if ( OOO000OOo0oo == "datetime-range" ) :
   for o000o0O0Oo00 in range ( len ( i1i1I1I1 ) ) :
    iI1i1111 = oO00o [ o000o0O0Oo00 ]
    oooOOooo000Oo = i1i1I1I1 [ o000o0O0Oo00 ]
    if ( iI1i1111 == "" ) : continue
    OoOoo00Oo0OoO = lisp_datetime ( iI1i1111 [ 0 : 19 ] )
    OooOi1 = lisp_datetime ( iI1i1111 [ 19 : : ] )
    if ( OoOoo00Oo0OoO . valid_datetime ( ) and OooOi1 . valid_datetime ( ) ) :
     oooOOooo000Oo . datetime_lower = OoOoo00Oo0OoO
     oooOOooo000Oo . datetime_upper = OooOi1
     if 48 - 48: ooOoO0o + Oo0Ooo / Oo0Ooo
     if 15 - 15: iIii1I11I1II1 . I1Ii111 * OoooooooOO * O0 % OOooOOo
     if 53 - 53: Ii1I
     if 63 - 63: I11i % OoOoOO00
     if 46 - 46: iIii1I11I1II1 . II111iiii / OoooooooOO - ooOoO0o * iII111i
     if 52 - 52: I11i + iII111i
     if 9 - 9: OoOoOO00 % II111iiii . I11i * Oo0Ooo
  if ( OOO000OOo0oo == "set-action" ) :
   I1i1I . set_action = oO00o
   if 53 - 53: II111iiii / i1IIi + OoooooooOO * O0
  if ( OOO000OOo0oo == "set-record-ttl" ) :
   I1i1I . set_record_ttl = int ( oO00o )
   if 62 - 62: IiII . O0
  if ( OOO000OOo0oo == "set-instance-id" ) :
   if ( I1i1I . set_source_eid == None ) :
    I1i1I . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 87 - 87: I1ii11iIi11i / oO0o / IiII . OOooOOo
   if ( I1i1I . set_dest_eid == None ) :
    I1i1I . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 91 - 91: OOooOOo % oO0o . OoOoOO00 . I1IiiI - OoOoOO00
   o0O00oOOoo = int ( oO00o )
   I1i1I . set_source_eid . instance_id = o0O00oOOoo
   I1i1I . set_dest_eid . instance_id = o0O00oOOoo
   if 18 - 18: O0 - I1IiiI + i1IIi % i11iIiiIii
  if ( OOO000OOo0oo == "set-source-eid" ) :
   if ( I1i1I . set_source_eid == None ) :
    I1i1I . set_source_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 97 - 97: iII111i * OoooooooOO + I1Ii111 + ooOoO0o - ooOoO0o
   I1i1I . set_source_eid . store_prefix ( oO00o )
   if ( o0O00oOOoo != None ) : I1i1I . set_source_eid . instance_id = o0O00oOOoo
   if 63 - 63: o0oOOo0O0Ooo * OOooOOo + iIii1I11I1II1 + Oo0Ooo
  if ( OOO000OOo0oo == "set-destination-eid" ) :
   if ( I1i1I . set_dest_eid == None ) :
    I1i1I . set_dest_eid = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
    if 25 - 25: oO0o + IiII % o0oOOo0O0Ooo
   I1i1I . set_dest_eid . store_prefix ( oO00o )
   if ( o0O00oOOoo != None ) : I1i1I . set_dest_eid . instance_id = o0O00oOOoo
   if 24 - 24: OoOoOO00
  if ( OOO000OOo0oo == "set-rloc-address" ) :
   I1i1I . set_rloc_address = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   I1i1I . set_rloc_address . store_address ( oO00o )
   if 87 - 87: I1ii11iIi11i / ooOoO0o * i1IIi
  if ( OOO000OOo0oo == "set-rloc-record-name" ) :
   I1i1I . set_rloc_record_name = oO00o
   if 71 - 71: OoOoOO00 - I11i
  if ( OOO000OOo0oo == "set-elp-name" ) :
   I1i1I . set_elp_name = oO00o
   if 83 - 83: oO0o + oO0o - Oo0Ooo . Oo0Ooo - iII111i . OOooOOo
  if ( OOO000OOo0oo == "set-geo-name" ) :
   I1i1I . set_geo_name = oO00o
   if 56 - 56: OoOoOO00 * IiII + i1IIi
  if ( OOO000OOo0oo == "set-rle-name" ) :
   I1i1I . set_rle_name = oO00o
   if 40 - 40: I1ii11iIi11i / O0
  if ( OOO000OOo0oo == "set-json-name" ) :
   I1i1I . set_json_name = oO00o
   if 87 - 87: ooOoO0o
  if ( OOO000OOo0oo == "policy-name" ) :
   I1i1I . policy_name = oO00o
   if 100 - 100: iII111i + II111iiii * Oo0Ooo * OOooOOo
   if 6 - 6: IiII % OOooOOo
   if 3 - 3: OoOoOO00 / OoOoOO00 - II111iiii
   if 41 - 41: oO0o
   if 12 - 12: I1IiiI + I1Ii111
   if 66 - 66: I1Ii111 + OOooOOo + I1Ii111 . OoooooooOO * oO0o / OoO0O00
 I1i1I . match_clauses = i1i1I1I1
 I1i1I . save_policy ( )
 return
 if 74 - 74: O0 % OOooOOo * OoOoOO00 / oO0o - Oo0Ooo
 if 79 - 79: Ii1I + IiII
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
if 21 - 21: o0oOOo0O0Ooo * iII111i * o0oOOo0O0Ooo * o0oOOo0O0Ooo . Oo0Ooo
if 98 - 98: I1ii11iIi11i
if 58 - 58: IiII / i11iIiiIii % I11i
if 74 - 74: OoooooooOO - I1ii11iIi11i + OOooOOo % IiII . o0oOOo0O0Ooo
if 21 - 21: Ii1I
if 72 - 72: I1Ii111 . OoooooooOO / I1Ii111 - Ii1I / I1ii11iIi11i * I1ii11iIi11i
if 72 - 72: IiII . Ii1I + OoooooooOO * OoOoOO00 + Oo0Ooo . iII111i
def lisp_send_to_arista ( command , interface ) :
 interface = "" if ( interface == None ) else "interface " + interface
 if 92 - 92: O0 * Ii1I - I1ii11iIi11i - IiII . OoO0O00 + I1IiiI
 oo0OOOooo0Oo = command
 if ( interface != "" ) : oo0OOOooo0Oo = interface + ": " + oo0OOOooo0Oo
 lprint ( "Send CLI command '{}' to hardware" . format ( oo0OOOooo0Oo ) )
 if 37 - 37: OoO0O00 * i1IIi
 o00oOoOOOO0 = '''
        enable
        configure
        {}
        {}
    ''' . format ( interface , command )
 if 61 - 61: I1Ii111 / ooOoO0o . iIii1I11I1II1
 os . system ( "FastCli -c '{}'" . format ( o00oOoOOOO0 ) )
 return
 if 26 - 26: OoO0O00 % OoooooooOO % iIii1I11I1II1 . i1IIi / O0 - OoOoOO00
 if 90 - 90: O0
 if 62 - 62: iIii1I11I1II1
 if 65 - 65: ooOoO0o / Ii1I + I11i . i1IIi + i1IIi . o0oOOo0O0Ooo
 if 21 - 21: I1IiiI + Oo0Ooo / Ii1I * OoooooooOO
 if 71 - 71: o0oOOo0O0Ooo % ooOoO0o / oO0o - oO0o / OoooooooOO
 if 91 - 91: iIii1I11I1II1 - O0 * o0oOOo0O0Ooo * o0oOOo0O0Ooo . II111iiii
def lisp_arista_is_alive ( prefix ) :
 I11iii = "enable\nsh plat trident l3 software routes {}\n" . format ( prefix )
 i11IiIIi11I = getoutput ( "FastCli -c '{}'" . format ( I11iii ) )
 if 69 - 69: II111iiii - Oo0Ooo + i1IIi . II111iiii + o0oOOo0O0Ooo
 if 20 - 20: OoooooooOO - OoO0O00 * ooOoO0o * OoOoOO00 / OOooOOo
 if 64 - 64: O0 + iII111i / I11i * OoOoOO00 + o0oOOo0O0Ooo + I1Ii111
 if 16 - 16: I11i
 i11IiIIi11I = i11IiIIi11I . split ( "\n" ) [ 1 ]
 I111IOo = i11IiIIi11I . split ( " " )
 I111IOo = I111IOo [ - 1 ] . replace ( "\r" , "" )
 if 56 - 56: OoooooooOO - O0 % OoO0O00 % iII111i / I1Ii111
 if 17 - 17: ooOoO0o % O0 . II111iiii / oO0o / o0oOOo0O0Ooo
 if 82 - 82: iIii1I11I1II1 * iIii1I11I1II1 . I1ii11iIi11i
 if 7 - 7: I1Ii111 % O0 . iIii1I11I1II1
 return ( I111IOo == "Y" )
 if 19 - 19: iIii1I11I1II1
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
 if 71 - 71: oO0o
 if 75 - 75: Oo0Ooo * oO0o + iIii1I11I1II1 / Oo0Ooo
 if 51 - 51: Ii1I * Ii1I + iII111i * oO0o / OOooOOo - ooOoO0o
 if 16 - 16: I1Ii111 + O0 - O0 * iIii1I11I1II1 / iII111i
 if 4 - 4: iII111i
 if 75 - 75: I1IiiI * IiII % OoO0O00 - ooOoO0o * iII111i
 if 32 - 32: iII111i
 if 59 - 59: OoOoOO00 - I1Ii111
 if 34 - 34: ooOoO0o . OoooooooOO / ooOoO0o + OoooooooOO
 if 24 - 24: OoooooooOO * I1ii11iIi11i / O0 / Oo0Ooo * I1IiiI / ooOoO0o
 if 33 - 33: Ii1I
 if 20 - 20: Ii1I + I11i
 if 98 - 98: OOooOOo
def lisp_program_vxlan_hardware ( mc ) :
 if 58 - 58: i11iIiiIii / OoOoOO00
 if 18 - 18: ooOoO0o + O0 - OOooOOo + iIii1I11I1II1 . OOooOOo * iIii1I11I1II1
 if 83 - 83: OoO0O00 - Oo0Ooo * I1IiiI % Oo0Ooo % oO0o
 if 64 - 64: OoOoOO00 + oO0o / OoooooooOO . i11iIiiIii / II111iiii
 if 55 - 55: ooOoO0o . i11iIiiIii . o0oOOo0O0Ooo
 if 52 - 52: IiII . oO0o + i11iIiiIii % IiII
 if ( os . path . exists ( "/persist/local/lispers.net" ) == False ) : return
 if 45 - 45: i1IIi - I1IiiI / IiII - I1IiiI
 if 21 - 21: IiII
 if 43 - 43: IiII
 if 9 - 9: OOooOOo * ooOoO0o + ooOoO0o . I1Ii111
 if ( len ( mc . best_rloc_set ) == 0 ) : return
 if 8 - 8: IiII * iIii1I11I1II1
 if 7 - 7: I1Ii111 / OoooooooOO % O0 - I1ii11iIi11i
 if 49 - 49: OoooooooOO . I1ii11iIi11i / OoooooooOO * oO0o
 if 81 - 81: I1ii11iIi11i . ooOoO0o + I1ii11iIi11i
 o00Oo = mc . eid . print_prefix_no_iid ( )
 iIIiIi1111iiIii = mc . best_rloc_set [ 0 ] . rloc . print_address_no_iid ( )
 if 84 - 84: OoooooooOO
 if 95 - 95: o0oOOo0O0Ooo
 if 22 - 22: ooOoO0o / o0oOOo0O0Ooo - OoooooooOO / Oo0Ooo - I1Ii111 / OOooOOo
 if 41 - 41: oO0o . II111iiii
 iiiIiIii = getoutput ( "ip route get {} | egrep vlan4094" . format ( o00Oo ) )
 if 41 - 41: i1IIi % ooOoO0o * Oo0Ooo . OoO0O00 . OoOoOO00
 if ( iiiIiIii != "" ) :
  lprint ( "Route {} already in hardware: '{}'" . format ( green ( o00Oo , False ) , iiiIiIii ) )
  if 35 - 35: II111iiii * Oo0Ooo / iIii1I11I1II1 + O0 + II111iiii / I1IiiI
  return
  if 49 - 49: i11iIiiIii % I1ii11iIi11i * O0 . o0oOOo0O0Ooo . I1ii11iIi11i / o0oOOo0O0Ooo
  if 99 - 99: I1ii11iIi11i * O0 / OoO0O00 % i1IIi + ooOoO0o
  if 85 - 85: OOooOOo / O0 - iIii1I11I1II1 . I11i . ooOoO0o - I1IiiI
  if 97 - 97: iIii1I11I1II1 * Oo0Ooo
  if 76 - 76: OoO0O00 / i11iIiiIii % ooOoO0o % I11i * O0
  if 84 - 84: II111iiii - iII111i / IiII . O0 % i1IIi / I1ii11iIi11i
  if 2 - 2: OoooooooOO . OoO0O00 . II111iiii / Ii1I - OOooOOo % Oo0Ooo
 iIIIi1iiii11 = getoutput ( "ifconfig | egrep 'vxlan|vlan4094'" )
 if ( iIIIi1iiii11 . find ( "vxlan" ) == - 1 ) :
  lprint ( "No VXLAN interface found, cannot program hardware" )
  return
  if 46 - 46: OoOoOO00 % I11i - iIii1I11I1II1 % Oo0Ooo
 if ( iIIIi1iiii11 . find ( "vlan4094" ) == - 1 ) :
  lprint ( "No vlan4094 interface found, cannot program hardware" )
  return
  if 48 - 48: o0oOOo0O0Ooo / II111iiii / OoOoOO00 * o0oOOo0O0Ooo + I1IiiI . OoOoOO00
 O0oOO0o = getoutput ( "ip addr | egrep vlan4094 | egrep inet" )
 if ( O0oOO0o == "" ) :
  lprint ( "No IP address found on vlan4094, cannot program hardware" )
  return
  if 6 - 6: i1IIi . oO0o % IiII . Oo0Ooo % I11i
 O0oOO0o = O0oOO0o . split ( "inet " ) [ 1 ]
 O0oOO0o = O0oOO0o . split ( "/" ) [ 0 ]
 if 86 - 86: OoooooooOO + IiII % o0oOOo0O0Ooo . i1IIi . iII111i
 if 25 - 25: iII111i * I1ii11iIi11i + I11i - I1ii11iIi11i
 if 75 - 75: IiII
 if 74 - 74: o0oOOo0O0Ooo - iIii1I11I1II1
 if 92 - 92: i11iIiiIii * iIii1I11I1II1 - I1Ii111 . i1IIi
 if 23 - 23: O0 - O0 . I1Ii111 . I1IiiI - I1IiiI * i1IIi
 if 8 - 8: I1IiiI . I1ii11iIi11i + oO0o % oO0o * oO0o
 OoO0oo = [ ]
 O0IiIiI = getoutput ( "arp -i vlan4094" ) . split ( "\n" )
 for o0 in O0IiIiI :
  if ( o0 . find ( "vlan4094" ) == - 1 ) : continue
  if ( o0 . find ( "(incomplete)" ) == - 1 ) : continue
  o000o0oO0 = o0 . split ( " " ) [ 0 ]
  OoO0oo . append ( o000o0oO0 )
  if 52 - 52: iII111i / Oo0Ooo
  if 3 - 3: I1Ii111 . oO0o . iII111i - IiII
 o000o0oO0 = None
 I1I111I1II1i1 = O0oOO0o
 O0oOO0o = O0oOO0o . split ( "." )
 for o000o0O0Oo00 in range ( 1 , 255 ) :
  O0oOO0o [ 3 ] = str ( o000o0O0Oo00 )
  iI1ii11Ii = "." . join ( O0oOO0o )
  if ( iI1ii11Ii in OoO0oo ) : continue
  if ( iI1ii11Ii == I1I111I1II1i1 ) : continue
  o000o0oO0 = iI1ii11Ii
  break
  if 18 - 18: OoO0O00 % I11i - iII111i - II111iiii . I1Ii111 % II111iiii
 if ( o000o0oO0 == None ) :
  lprint ( "Address allocation failed for vlan4094, cannot program " + "hardware" )
  if 28 - 28: iIii1I11I1II1 * I1Ii111 / Ii1I % IiII - Ii1I
  return
  if 82 - 82: Oo0Ooo / Oo0Ooo - O0 - OoooooooOO + II111iiii
  if 64 - 64: I1Ii111 / iIii1I11I1II1
  if 79 - 79: OoO0O00 / Oo0Ooo - I11i
  if 7 - 7: O0 . I1IiiI / o0oOOo0O0Ooo % iII111i
  if 47 - 47: OoooooooOO
  if 65 - 65: I1ii11iIi11i . o0oOOo0O0Ooo * I1Ii111
  if 52 - 52: IiII - ooOoO0o / I11i + OoO0O00 * II111iiii
 I11IIIIii = iIIiIi1111iiIii . split ( "." )
 oOOoOO0o0 = lisp_hex_string ( I11IIIIii [ 1 ] ) . zfill ( 2 )
 o0Oooo = lisp_hex_string ( I11IIIIii [ 2 ] ) . zfill ( 2 )
 I1IIiI = lisp_hex_string ( I11IIIIii [ 3 ] ) . zfill ( 2 )
 i1i1I1 = "00:00:00:{}:{}:{}" . format ( oOOoOO0o0 , o0Oooo , I1IIiI )
 o00oO = "0000.00{}.{}{}" . format ( oOOoOO0o0 , o0Oooo , I1IIiI )
 i1IiIiiIIiii = "arp -i vlan4094 -s {} {}" . format ( o000o0oO0 , i1i1I1 )
 os . system ( i1IiIiiIIiii )
 if 86 - 86: OoooooooOO - iII111i . O0 + II111iiii / OOooOOo . ooOoO0o
 if 48 - 48: O0 / OoooooooOO + I11i / OoO0O00
 if 12 - 12: I11i % Ii1I % OOooOOo * Ii1I - IiII . o0oOOo0O0Ooo
 if 60 - 60: OoOoOO00 - OoooooooOO * Ii1I * iIii1I11I1II1
 oO00OOOO = ( "mac address-table static {} vlan 4094 " + "interface vxlan 1 vtep {}" ) . format ( o00oO , iIIiIi1111iiIii )
 if 96 - 96: O0 % Ii1I / I1ii11iIi11i + I1ii11iIi11i - OoO0O00 / oO0o
 lisp_send_to_arista ( oO00OOOO , None )
 if 41 - 41: Ii1I
 if 78 - 78: OOooOOo
 if 44 - 44: i1IIi * I1ii11iIi11i % Ii1I . Ii1I * I11i + II111iiii
 if 15 - 15: i1IIi - I11i - I1Ii111 / OoO0O00 + Oo0Ooo + I1IiiI
 if 81 - 81: IiII
 oO0OOoOoo0o = "ip route add {} via {}" . format ( o00Oo , o000o0oO0 )
 os . system ( oO0OOoOoo0o )
 if 16 - 16: I11i
 lprint ( "Hardware programmed with commands:" )
 oO0OOoOoo0o = oO0OOoOoo0o . replace ( o00Oo , green ( o00Oo , False ) )
 lprint ( "  " + oO0OOoOoo0o )
 lprint ( "  " + i1IiIiiIIiii )
 oO00OOOO = oO00OOOO . replace ( iIIiIi1111iiIii , red ( iIIiIi1111iiIii , False ) )
 lprint ( "  " + oO00OOOO )
 return
 if 98 - 98: II111iiii + i1IIi * oO0o % I1IiiI
 if 53 - 53: i11iIiiIii . I1ii11iIi11i - OOooOOo - OOooOOo
 if 97 - 97: I1IiiI % iII111i % OoooooooOO / ooOoO0o / i11iIiiIii
 if 7 - 7: O0 % IiII / o0oOOo0O0Ooo
 if 79 - 79: IiII + I1Ii111
 if 59 - 59: iII111i - oO0o . ooOoO0o / IiII * i11iIiiIii
 if 61 - 61: I11i - Oo0Ooo * II111iiii + iIii1I11I1II1
def lisp_clear_hardware_walk ( mc , parms ) :
 O0OoO0 = mc . eid . print_prefix_no_iid ( )
 os . system ( "ip route delete {}" . format ( O0OoO0 ) )
 return ( [ True , None ] )
 if 37 - 37: OoooooooOO % II111iiii / o0oOOo0O0Ooo . OOooOOo * I1ii11iIi11i . iIii1I11I1II1
 if 73 - 73: OoOoOO00
 if 44 - 44: Oo0Ooo / oO0o
 if 9 - 9: i1IIi % I1IiiI + OoO0O00 * ooOoO0o / iIii1I11I1II1 / iII111i
 if 80 - 80: OOooOOo / O0 % IiII * OoOoOO00
 if 53 - 53: OOooOOo + i11iIiiIii
 if 25 - 25: i11iIiiIii
 if 51 - 51: iII111i . ooOoO0o
def lisp_clear_map_cache ( ) :
 global lisp_map_cache , lisp_rloc_probe_list
 global lisp_crypto_keys_by_rloc_encap , lisp_crypto_keys_by_rloc_decap
 global lisp_rtr_list , lisp_gleaned_groups
 global lisp_no_map_request_rate_limit
 if 70 - 70: I11i / O0 - I11i + o0oOOo0O0Ooo . ooOoO0o . o0oOOo0O0Ooo
 i1Ii1I1 = bold ( "User cleared" , False )
 o00oOoo0o00 = lisp_map_cache . cache_count
 lprint ( "{} map-cache with {} entries" . format ( i1Ii1I1 , o00oOoo0o00 ) )
 if 18 - 18: iII111i + I1Ii111
 if ( lisp_program_hardware ) :
  lisp_map_cache . walk_cache ( lisp_clear_hardware_walk , None )
  if 1 - 1: OoooooooOO % OoooooooOO * I1ii11iIi11i
 lisp_map_cache = lisp_cache ( )
 if 24 - 24: I1Ii111 % I1Ii111 % iIii1I11I1II1
 if 29 - 29: i1IIi % i1IIi - II111iiii
 if 44 - 44: II111iiii . Oo0Ooo - o0oOOo0O0Ooo
 if 45 - 45: ooOoO0o - oO0o - I1IiiI
 lisp_no_map_request_rate_limit = lisp_get_timestamp ( )
 if 21 - 21: OoooooooOO
 if 28 - 28: I1ii11iIi11i + oO0o . Oo0Ooo % iIii1I11I1II1 / I1Ii111
 if 8 - 8: O0 . I1IiiI * o0oOOo0O0Ooo + I1IiiI
 if 44 - 44: i1IIi % iII111i . i11iIiiIii / I11i + OoooooooOO
 if 21 - 21: OoOoOO00 . OoO0O00 . OoOoOO00 + OoOoOO00
 lisp_rloc_probe_list = { }
 if 30 - 30: I1IiiI - iII111i - OOooOOo + oO0o
 if 51 - 51: Ii1I % O0 / II111iiii . Oo0Ooo
 if 90 - 90: i11iIiiIii * II111iiii % iIii1I11I1II1 . I1ii11iIi11i / Oo0Ooo . OOooOOo
 if 77 - 77: OoO0O00
 lisp_crypto_keys_by_rloc_encap = { }
 lisp_crypto_keys_by_rloc_decap = { }
 if 95 - 95: II111iiii
 if 59 - 59: iIii1I11I1II1 % OOooOOo / OoOoOO00 * I1Ii111 * OoooooooOO * O0
 if 43 - 43: OoO0O00 * I1IiiI * OOooOOo * O0 - O0 / o0oOOo0O0Ooo
 if 77 - 77: I11i % I1Ii111 . IiII % OoooooooOO * o0oOOo0O0Ooo
 if 87 - 87: iII111i + IiII / ooOoO0o * ooOoO0o * OOooOOo
 lisp_rtr_list = { }
 if 97 - 97: I1Ii111
 if 47 - 47: iII111i / I1ii11iIi11i - Ii1I . II111iiii
 if 56 - 56: O0 - i1IIi % o0oOOo0O0Ooo + IiII
 if 42 - 42: o0oOOo0O0Ooo . OOooOOo % I11i - OoOoOO00
 lisp_gleaned_groups = { }
 if 38 - 38: OoooooooOO
 if 27 - 27: O0 + I1ii11iIi11i % Ii1I . i1IIi + OoO0O00 + OoOoOO00
 if 22 - 22: II111iiii / I1IiiI + o0oOOo0O0Ooo * I1IiiI . OoooooooOO * OOooOOo
 if 49 - 49: I1ii11iIi11i * I1IiiI + OOooOOo + i11iIiiIii * I1ii11iIi11i . o0oOOo0O0Ooo
 lisp_process_data_plane_restart ( True )
 return
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
def lisp_encap_rloc_probe ( lisp_sockets , rloc , nat_info , packet , source_addr = None ) :
 if ( len ( lisp_sockets ) != 4 ) : return
 if 19 - 19: I1IiiI - ooOoO0o % IiII - o0oOOo0O0Ooo * OOooOOo + I1ii11iIi11i
 if 44 - 44: i1IIi
 if 85 - 85: I1ii11iIi11i / IiII + oO0o
 if 95 - 95: IiII . OoO0O00
 if 36 - 36: IiII % Ii1I - OoOoOO00 + OoO0O00 + IiII * Ii1I
 if 15 - 15: I1IiiI / O0 % I1ii11iIi11i % OoOoOO00 . OoOoOO00 + iII111i
 OOo0o0o = source_addr if source_addr else lisp_myrlocs [ 0 ]
 if ( lisp_i_am_rtr and lisp_on_aws ( ) ) :
  iI1ii11Ii = lisp_get_interface_address ( "eth0" )
  if ( iI1ii11Ii == None ) : iI1ii11Ii = lisp_get_interface_address ( "ens5" )
  if ( iI1ii11Ii ) : OOo0o0o = iI1ii11Ii
  if 37 - 37: O0 . II111iiii
  if 56 - 56: II111iiii / oO0o + o0oOOo0O0Ooo / OOooOOo * OoO0O00
  if 29 - 29: O0
  if 43 - 43: Oo0Ooo / OoO0O00 * Oo0Ooo . IiII + I11i
  if 46 - 46: iIii1I11I1II1 % i1IIi - OoooooooOO . Ii1I
  if 91 - 91: iII111i - i11iIiiIii
 OOOOo0o0O0o = len ( packet ) + 28
 ooooO000 = struct . pack ( "BBHIBBHII" , 0x45 , 0 , socket . htons ( OOOOo0o0O0o ) , 0 , 64 ,
 17 , 0 , socket . htonl ( OOo0o0o . address ) , socket . htonl ( rloc . address ) )
 ooooO000 = lisp_ip_checksum ( ooooO000 )
 if 27 - 27: iII111i
 II1 = socket . htons ( LISP_DATA_PORT )
 Ooo0000o00OO = socket . htons ( LISP_CTRL_PORT )
 ii11 = struct . pack ( "HHHH" , II1 , Ooo0000o00OO , socket . htons ( OOOOo0o0O0o - 20 ) , 0 )
 if 66 - 66: O0 . iIii1I11I1II1 * II111iiii * OOooOOo * IiII
 if 44 - 44: i11iIiiIii % ooOoO0o * i11iIiiIii + Oo0Ooo + I1ii11iIi11i + Ii1I
 if 43 - 43: i1IIi . iIii1I11I1II1
 if 86 - 86: OOooOOo + OoOoOO00 - OoO0O00 + i1IIi + iIii1I11I1II1
 ooIiii = packet [ 0 : 1 ]
 packet = lisp_packet ( ooooO000 + ii11 + packet )
 if 68 - 68: OoOoOO00 . I1IiiI + ooOoO0o - o0oOOo0O0Ooo
 if 62 - 62: Ii1I - OOooOOo
 if 88 - 88: iIii1I11I1II1 * Oo0Ooo / II111iiii / IiII / OoO0O00 % ooOoO0o
 if 19 - 19: I11i * iII111i . O0 * iII111i % I1ii11iIi11i - OoOoOO00
 packet . inner_dest . copy_address ( rloc )
 packet . inner_dest . instance_id = 0xffffff
 packet . inner_source . copy_address ( OOo0o0o )
 packet . inner_ttl = 64
 packet . outer_dest . copy_address ( rloc )
 packet . outer_source . copy_address ( OOo0o0o )
 packet . outer_version = packet . outer_dest . afi_to_version ( )
 packet . outer_ttl = 64
 packet . encap_port = nat_info . port if nat_info else LISP_DATA_PORT
 if 68 - 68: I1Ii111 - OoO0O00 % Ii1I + i1IIi . ooOoO0o
 I1I111i = red ( rloc . print_address_no_iid ( ) , False )
 if ( nat_info ) :
  O00 = " {}" . format ( blue ( nat_info . hostname , False ) )
 else :
  O00 = ""
  if 36 - 36: oO0o * iIii1I11I1II1 - O0 - IiII * O0 + i11iIiiIii
 if ( lisp_is_rloc_probe_request ( ooIiii ) ) :
  oO00oo0 = bold ( "RLOC-probe request" , False )
 else :
  oO00oo0 = bold ( "RLOC-probe reply" , False )
  if 76 - 76: OoO0O00 % O0 / Ii1I + I1IiiI
  if 23 - 23: I1IiiI % IiII . o0oOOo0O0Ooo
 lprint ( ( "Data encapsulate {} to {}{} port {} for " + "NAT-traversal" ) . format ( oO00oo0 , I1I111i , O00 , packet . encap_port ) )
 if 2 - 2: I1ii11iIi11i
 if 51 - 51: iIii1I11I1II1 / II111iiii / iIii1I11I1II1 / oO0o % i1IIi
 if 54 - 54: ooOoO0o
 if 47 - 47: I11i * I1IiiI / oO0o
 if 98 - 98: Ii1I / oO0o * O0 + I1Ii111 - I1Ii111 + iII111i
 if ( packet . encode ( None ) == None ) : return
 packet . print_packet ( "Send" , True )
 if 4 - 4: i1IIi
 iII111iiI1iI = lisp_sockets [ 3 ]
 if 68 - 68: OOooOOo
 if 99 - 99: OoooooooOO
 if 2 - 2: Oo0Ooo + iIii1I11I1II1 - II111iiii % OoOoOO00 / i11iIiiIii
 if 6 - 6: oO0o + iII111i * i1IIi * i11iIiiIii
 if 10 - 10: IiII / i1IIi . OoOoOO00 . Oo0Ooo
 if 21 - 21: oO0o
 if 41 - 41: oO0o . O0 * Oo0Ooo - o0oOOo0O0Ooo * ooOoO0o + OoOoOO00
 if 40 - 40: I1Ii111
 if 58 - 58: oO0o . OoO0O00 / ooOoO0o
 if 61 - 61: I11i + I1Ii111
 if ( source_addr ) :
  try :
   iII111iiI1iI . bind ( ( OOo0o0o . print_address_no_iid ( ) , 0 ) )
  except Exception as oOO :
   lprint ( "raw socket bind to {} failed: {}" . format ( OOo0o0o . print_address_no_iid ( ) , oOO ) )
   if 27 - 27: ooOoO0o / i1IIi . oO0o - OoooooooOO
   if 48 - 48: ooOoO0o % ooOoO0o / OoooooooOO + i1IIi * oO0o + ooOoO0o
   if 69 - 69: iII111i . iII111i
   if 46 - 46: IiII * Oo0Ooo + I1Ii111
 packet . send_packet ( iII111iiI1iI , packet . outer_dest )
 del ( packet )
 return
 if 79 - 79: IiII
 if 89 - 89: IiII * I11i + I1ii11iIi11i * oO0o - II111iiii
 if 58 - 58: ooOoO0o . I1Ii111 / i1IIi % I1ii11iIi11i + o0oOOo0O0Ooo
 if 94 - 94: i11iIiiIii + I1Ii111 . iII111i - ooOoO0o % I1Ii111
 if 94 - 94: i11iIiiIii - OOooOOo - O0 * OoooooooOO - ooOoO0o
 if 35 - 35: iII111i . i11iIiiIii - OOooOOo % Oo0Ooo + Ii1I . iIii1I11I1II1
 if 91 - 91: o0oOOo0O0Ooo / OoO0O00 + I1IiiI % i11iIiiIii % i1IIi
 if 22 - 22: I1Ii111 * O0 % OoO0O00 * I1ii11iIi11i
def lisp_get_default_route_next_hops ( ) :
 if 47 - 47: OoO0O00 / OOooOOo / OoOoOO00 % i11iIiiIii / OoOoOO00
 if 52 - 52: ooOoO0o / I11i % i11iIiiIii - I1Ii111 % ooOoO0o - o0oOOo0O0Ooo
 if 67 - 67: OoOoOO00 / I1Ii111 + i11iIiiIii - IiII
 if 79 - 79: I11i . I11i - OoOoOO00
 if ( lisp_is_macos ( ) ) :
  I11iii = "route -n get default"
  OOoO0ooOOO0O = getoutput ( I11iii ) . split ( "\n" )
  iiI1II11 = oo = None
  for O0Oo0 in OOoO0ooOOO0O :
   if ( O0Oo0 . find ( "gateway: " ) != - 1 ) : iiI1II11 = O0Oo0 . split ( ": " ) [ 1 ]
   if ( O0Oo0 . find ( "interface: " ) != - 1 ) : oo = O0Oo0 . split ( ": " ) [ 1 ]
   if 61 - 61: O0 . I11i - IiII * ooOoO0o / OoooooooOO * Ii1I
  return ( [ [ oo , iiI1II11 ] ] )
  if 16 - 16: I1Ii111 + I1IiiI . i1IIi - I11i
  if 92 - 92: ooOoO0o + o0oOOo0O0Ooo . I1ii11iIi11i
  if 25 - 25: IiII + i11iIiiIii . O0
  if 94 - 94: OoooooooOO + iII111i * OoooooooOO / o0oOOo0O0Ooo
  if 12 - 12: iIii1I11I1II1 / iIii1I11I1II1 / II111iiii
 I11iii = "ip route | egrep 'default via'"
 oO00OoooO = getoutput ( I11iii ) . split ( "\n" )
 if 97 - 97: Ii1I * Ii1I * iIii1I11I1II1
 I111I11i = [ ]
 for iiiIiIii in oO00OoooO :
  IIi1iii = iiiIiIii . split ( )
  try :
   o000o0oO0 = IIi1iii [ 2 ]
   ooOooO = IIi1iii [ 4 ]
  except :
   continue
   if 47 - 47: o0oOOo0O0Ooo + I1Ii111 * I1Ii111
  I111I11i . append ( [ ooOooO , o000o0oO0 ] )
  if 38 - 38: Ii1I . IiII
 return ( I111I11i )
 if 11 - 11: O0 . II111iiii % ooOoO0o % o0oOOo0O0Ooo
 if 45 - 45: o0oOOo0O0Ooo + iII111i / II111iiii + iII111i
 if 1 - 1: i1IIi * Oo0Ooo * oO0o
 if 85 - 85: OoooooooOO . IiII / IiII . ooOoO0o . IiII % II111iiii
 if 65 - 65: oO0o - OoO0O00 / iII111i + ooOoO0o
 if 80 - 80: o0oOOo0O0Ooo + II111iiii * Ii1I % OoOoOO00 % I1IiiI + I1ii11iIi11i
 if 46 - 46: Oo0Ooo / Oo0Ooo % iII111i % I1IiiI
def lisp_get_host_route_next_hop ( rloc ) :
 I11iii = "ip route | egrep '{} via'" . format ( rloc )
 iiiIiIii = getoutput ( I11iii ) . split ( )
 if 85 - 85: OoO0O00 - Ii1I / O0
 try : o00O = iiiIiIii . index ( "via" ) + 1
 except : return ( None )
 if 45 - 45: IiII + I1Ii111 / I11i
 if ( o00O >= len ( iiiIiIii ) ) : return ( None )
 return ( iiiIiIii [ o00O ] )
 if 84 - 84: iII111i % II111iiii
 if 86 - 86: IiII % II111iiii / i1IIi * I1ii11iIi11i - O0 * OOooOOo
 if 53 - 53: OOooOOo * oO0o + i1IIi % Oo0Ooo + II111iiii
 if 34 - 34: oO0o % iII111i / IiII . IiII + i11iIiiIii
 if 68 - 68: O0 % oO0o * IiII % O0
 if 55 - 55: O0 % I1IiiI % O0
 if 27 - 27: I1IiiI + I1ii11iIi11i * I1Ii111 % Ii1I - Oo0Ooo
def lisp_get_host_route_device ( rloc ) :
 I11iii = "ip route | egrep '{} via'" . format ( rloc )
 iiiIiIii = getoutput ( I11iii ) . split ( )
 if 87 - 87: i11iIiiIii % OOooOOo - OoOoOO00 * ooOoO0o / Oo0Ooo
 try : o00O = iiiIiIii . index ( "dev" ) + 1
 except : return ( None )
 if 74 - 74: OoooooooOO * ooOoO0o - I11i / I1ii11iIi11i % iIii1I11I1II1
 if ( o00O >= len ( iiiIiIii ) ) : return ( None )
 return ( iiiIiIii [ o00O ] )
 if 94 - 94: Ii1I * I1Ii111 + OoOoOO00 . iIii1I11I1II1
 if 44 - 44: Oo0Ooo . Oo0Ooo * Oo0Ooo
 if 23 - 23: I1Ii111 / iII111i . O0 % II111iiii
 if 67 - 67: I11i / iIii1I11I1II1 / ooOoO0o
 if 90 - 90: II111iiii % I1Ii111 - IiII . Oo0Ooo % OOooOOo - OoOoOO00
 if 89 - 89: Oo0Ooo - I1ii11iIi11i . I1Ii111
 if 65 - 65: ooOoO0o % OOooOOo + OOooOOo % I1Ii111 . I1IiiI % O0
def lisp_install_host_route ( dest , nh , device ) :
 if ( nh == None or device == None or lisp_is_macos ( ) ) : return
 if 46 - 46: OoO0O00 * I1Ii111 + iII111i . oO0o % OOooOOo / i11iIiiIii
 if 1 - 1: I1ii11iIi11i % O0 - I1ii11iIi11i / OoooooooOO / OoO0O00
 if 82 - 82: i1IIi % Ii1I
 if 85 - 85: I1Ii111 * i11iIiiIii * iIii1I11I1II1 % iIii1I11I1II1
 os . system ( "sudo ip route delete {}/32" . format ( dest ) )
 if 64 - 64: OoO0O00 / Ii1I
 if 79 - 79: Ii1I % OOooOOo
 if 39 - 39: I1ii11iIi11i / Ii1I - II111iiii . i1IIi
 if 59 - 59: II111iiii
 iiiIiIii = "ip route add {}/32 via {} dev {}" . format ( dest , nh , device )
 lprint ( "Run '{}'" . format ( iiiIiIii ) )
 os . system ( iiiIiIii )
 if 36 - 36: ooOoO0o . II111iiii - OoOoOO00 % I1ii11iIi11i * O0
 if 91 - 91: iII111i + Oo0Ooo / OoooooooOO * iIii1I11I1II1 - OoO0O00
 if 73 - 73: iIii1I11I1II1 % I1Ii111 % II111iiii * Oo0Ooo * OoO0O00
 if 48 - 48: OOooOOo * i11iIiiIii - i11iIiiIii + iIii1I11I1II1 + I1IiiI % OoooooooOO
 if 61 - 61: i1IIi
 if 56 - 56: iIii1I11I1II1 / I11i * iII111i * I11i * OoooooooOO
 if 44 - 44: I1ii11iIi11i - OOooOOo % I11i - I1Ii111 / iIii1I11I1II1 - OOooOOo
 if 38 - 38: iIii1I11I1II1 - OoooooooOO * II111iiii . OoooooooOO + OOooOOo
def lisp_checkpoint ( checkpoint_list ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 59 - 59: OoooooooOO
 O0Oo0 = open ( lisp_checkpoint_filename , "w" )
 for I1I11i in checkpoint_list :
  O0Oo0 . write ( I1I11i + "\n" )
  if 22 - 22: II111iiii
 O0Oo0 . close ( )
 lprint ( "{} {} entries to file '{}'" . format ( bold ( "Checkpoint" , False ) ,
 len ( checkpoint_list ) , lisp_checkpoint_filename ) )
 return
 if 85 - 85: I1Ii111 + I1ii11iIi11i * I11i % o0oOOo0O0Ooo + Ii1I
 if 23 - 23: IiII * OoO0O00
 if 42 - 42: IiII
 if 83 - 83: i1IIi * o0oOOo0O0Ooo / OoO0O00 / o0oOOo0O0Ooo
 if 55 - 55: Oo0Ooo % O0 - OoO0O00
 if 42 - 42: OoooooooOO * OOooOOo
 if 93 - 93: OOooOOo + II111iiii . oO0o * Oo0Ooo - O0 + I1Ii111
 if 99 - 99: OoO0O00 * o0oOOo0O0Ooo + OoOoOO00 * iIii1I11I1II1
def lisp_load_checkpoint ( ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if ( os . path . exists ( lisp_checkpoint_filename ) == False ) : return
 if 38 - 38: I1ii11iIi11i - OOooOOo * O0 - I1ii11iIi11i
 O0Oo0 = open ( lisp_checkpoint_filename , "r" )
 if 95 - 95: OoO0O00 . oO0o . OoooooooOO - iIii1I11I1II1
 o00oOoo0o00 = 0
 for I1I11i in O0Oo0 :
  o00oOoo0o00 += 1
  oOO = I1I11i . split ( " rloc " )
  OOooO = [ ] if ( oOO [ 1 ] in [ "native-forward\n" , "\n" ] ) else oOO [ 1 ] . split ( ", " )
  if 35 - 35: o0oOOo0O0Ooo / OoooooooOO - i1IIi * iIii1I11I1II1 + ooOoO0o
  if 66 - 66: Oo0Ooo - OoOoOO00 . I1Ii111 + O0 + o0oOOo0O0Ooo
  o0O00ooOo = [ ]
  for iIIiIi1111iiIii in OOooO :
   oO0o0 = lisp_rloc ( False )
   IIi1iii = iIIiIi1111iiIii . split ( " " )
   oO0o0 . rloc . store_address ( IIi1iii [ 0 ] )
   oO0o0 . priority = int ( IIi1iii [ 1 ] )
   oO0o0 . weight = int ( IIi1iii [ 2 ] )
   o0O00ooOo . append ( oO0o0 )
   if 36 - 36: II111iiii % IiII . i11iIiiIii
   if 88 - 88: Oo0Ooo . IiII * Oo0Ooo
  IIII1 = lisp_mapping ( "" , "" , o0O00ooOo )
  if ( IIII1 != None ) :
   IIII1 . eid . store_prefix ( oOO [ 0 ] )
   IIII1 . checkpoint_entry = True
   IIII1 . map_cache_ttl = LISP_NMR_TTL * 60
   if ( o0O00ooOo == [ ] ) : IIII1 . action = LISP_NATIVE_FORWARD_ACTION
   IIII1 . add_cache ( )
   continue
   if 92 - 92: I1IiiI % IiII
   if 95 - 95: OoooooooOO / OoO0O00 % O0 / I1Ii111 * Ii1I + I1ii11iIi11i
  o00oOoo0o00 -= 1
  if 7 - 7: ooOoO0o
  if 83 - 83: oO0o / I1Ii111 + I1Ii111 * I1ii11iIi11i
 O0Oo0 . close ( )
 lprint ( "{} {} map-cache entries from file '{}'" . format (
 bold ( "Loaded" , False ) , o00oOoo0o00 , lisp_checkpoint_filename ) )
 return
 if 8 - 8: I11i . I1ii11iIi11i % i1IIi + Ii1I
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
def lisp_write_checkpoint_entry ( checkpoint_list , mc ) :
 if ( lisp_checkpoint_map_cache == False ) : return
 if 38 - 38: iII111i - I1IiiI / ooOoO0o
 I1I11i = "{} rloc " . format ( mc . eid . print_prefix ( ) )
 if 46 - 46: OOooOOo . O0 / i11iIiiIii . OOooOOo
 for oO0o0 in mc . rloc_set :
  if ( oO0o0 . rloc . is_null ( ) ) : continue
  I1I11i += "{} {} {}, " . format ( oO0o0 . rloc . print_address_no_iid ( ) ,
 oO0o0 . priority , oO0o0 . weight )
  if 19 - 19: I11i / Oo0Ooo + I1Ii111
  if 43 - 43: I1ii11iIi11i
 if ( mc . rloc_set != [ ] ) :
  I1I11i = I1I11i [ 0 : - 2 ]
 elif ( mc . action == LISP_NATIVE_FORWARD_ACTION ) :
  I1I11i += "native-forward"
  if 18 - 18: I11i / OOooOOo % I11i - o0oOOo0O0Ooo
  if 22 - 22: iII111i
 checkpoint_list . append ( I1I11i )
 return
 if 88 - 88: I11i + OoOoOO00 % IiII % OoO0O00 * O0 / OoooooooOO
 if 83 - 83: IiII + I1Ii111 . I1ii11iIi11i * iIii1I11I1II1
 if 9 - 9: ooOoO0o % IiII - OoOoOO00
 if 66 - 66: oO0o % Oo0Ooo
 if 40 - 40: i11iIiiIii . O0 * I11i - oO0o / OOooOOo . oO0o
 if 86 - 86: OOooOOo - I1Ii111 * IiII - i1IIi + ooOoO0o + I11i
 if 32 - 32: IiII
def lisp_check_dp_socket ( ) :
 oo0O0 = lisp_ipc_dp_socket_name
 if ( os . path . exists ( oo0O0 ) == False ) :
  oOOO00o = bold ( "does not exist" , False )
  lprint ( "Socket '{}' {}" . format ( oo0O0 , oOOO00o ) )
  return ( False )
  if 73 - 73: I1ii11iIi11i - IiII - O0 . oO0o + Oo0Ooo % iII111i
 return ( True )
 if 68 - 68: I1ii11iIi11i - OoooooooOO
 if 5 - 5: I1ii11iIi11i * I1IiiI + OoooooooOO / Oo0Ooo
 if 18 - 18: OoO0O00 * iII111i % I1IiiI . OOooOOo * o0oOOo0O0Ooo
 if 58 - 58: iII111i . IiII + iIii1I11I1II1
 if 13 - 13: oO0o * I1Ii111 / I1Ii111 . I1IiiI
 if 93 - 93: I11i % OoOoOO00 - OOooOOo + iIii1I11I1II1 / OoooooooOO % i11iIiiIii
 if 90 - 90: oO0o % iIii1I11I1II1 + o0oOOo0O0Ooo - I11i / i11iIiiIii
def lisp_write_to_dp_socket ( entry ) :
 try :
  OOiiIi = json . dumps ( entry )
  Oo0 = bold ( "Write IPC" , False )
  lprint ( "{} record to named socket: '{}'" . format ( Oo0 , OOiiIi ) )
  lisp_ipc_dp_socket . sendto ( OOiiIi , lisp_ipc_dp_socket_name )
 except :
  lprint ( "Failed to write IPC record to named socket: '{}'" . format ( OOiiIi ) )
  if 49 - 49: OoooooooOO % OoO0O00 - ooOoO0o
 return
 if 37 - 37: Oo0Ooo . II111iiii . II111iiii * OOooOOo / I1IiiI
 if 28 - 28: OoooooooOO + i1IIi
 if 29 - 29: Oo0Ooo
 if 98 - 98: OOooOOo / Oo0Ooo % Ii1I * OoooooooOO - oO0o
 if 64 - 64: I1IiiI - I1IiiI
 if 90 - 90: iII111i - I1IiiI - II111iiii / OOooOOo + Ii1I
 if 34 - 34: i11iIiiIii + I1Ii111 / O0 / iIii1I11I1II1 * OoooooooOO % Ii1I
 if 32 - 32: i11iIiiIii - OoOoOO00 / iIii1I11I1II1 * o0oOOo0O0Ooo % I1IiiI + O0
 if 36 - 36: I1ii11iIi11i + I1ii11iIi11i % I1Ii111 * ooOoO0o * OoOoOO00
def lisp_write_ipc_keys ( rloc ) :
 O00oO000Oo0 = rloc . rloc . print_address_no_iid ( )
 O0ooO0O00oo0 = rloc . translated_port
 if ( O0ooO0O00oo0 != 0 ) : O00oO000Oo0 += ":" + str ( O0ooO0O00oo0 )
 if ( O00oO000Oo0 not in lisp_rloc_probe_list ) : return
 if 54 - 54: Oo0Ooo - I1IiiI % OOooOOo . I1ii11iIi11i / I1IiiI
 for IIi1iii , oOO , II11iIIii in lisp_rloc_probe_list [ O00oO000Oo0 ] :
  IIII1 = lisp_map_cache . lookup_cache ( oOO , True )
  if ( IIII1 == None ) : continue
  lisp_write_ipc_map_cache ( True , IIII1 )
  if 75 - 75: OOooOOo - O0 % iII111i . Ii1I % I1ii11iIi11i + I1ii11iIi11i
 return
 if 32 - 32: Ii1I + II111iiii * IiII
 if 9 - 9: I1Ii111
 if 96 - 96: I1Ii111 / iIii1I11I1II1
 if 48 - 48: iII111i * IiII + OoooooooOO
 if 63 - 63: I1IiiI / Ii1I
 if 31 - 31: i1IIi - oO0o
 if 99 - 99: iII111i - i11iIiiIii + oO0o
def lisp_write_ipc_map_cache ( add_or_delete , mc , dont_send = False ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 66 - 66: Oo0Ooo * I11i . iIii1I11I1II1 - OoO0O00
 if 11 - 11: I1Ii111 + iIii1I11I1II1 * O0 * Oo0Ooo
 if 66 - 66: OoooooooOO % OoO0O00 + i11iIiiIii + I1Ii111 % OoO0O00
 if 80 - 80: Oo0Ooo - Ii1I
 Ii11 = "add" if add_or_delete else "delete"
 I1I11i = { "type" : "map-cache" , "opcode" : Ii11 }
 if 54 - 54: O0 - iIii1I11I1II1 . OoO0O00 . IiII % OoO0O00
 I1iI1III = ( mc . group . is_null ( ) == False )
 if ( I1iI1III ) :
  I1I11i [ "eid-prefix" ] = mc . group . print_prefix_no_iid ( )
  I1I11i [ "rles" ] = [ ]
 else :
  I1I11i [ "eid-prefix" ] = mc . eid . print_prefix_no_iid ( )
  I1I11i [ "rlocs" ] = [ ]
  if 28 - 28: O0 % i1IIi % OoO0O00 / o0oOOo0O0Ooo . iIii1I11I1II1 - iII111i
 I1I11i [ "instance-id" ] = str ( mc . eid . instance_id )
 if 50 - 50: o0oOOo0O0Ooo + iII111i / i1IIi % II111iiii
 if ( I1iI1III ) :
  if ( len ( mc . rloc_set ) >= 1 and mc . rloc_set [ 0 ] . rle ) :
   for Iiiiii in mc . rloc_set [ 0 ] . rle . rle_forwarding_list :
    iI1ii11Ii = Iiiiii . rloc . rloc . print_address_no_iid ( )
    O0ooO0O00oo0 = str ( 4341 ) if Iiiiii . rloc . translated_port == 0 else str ( Iiiiii . rloc . translated_port )
    if 61 - 61: IiII
    IIi1iii = { "rle" : iI1ii11Ii , "port" : O0ooO0O00oo0 }
    OooOooo0 , I11i1iii1I = Iiiiii . get_encap_keys ( )
    IIi1iii = lisp_build_json_keys ( IIi1iii , OooOooo0 , I11i1iii1I , "encrypt-key" )
    I1I11i [ "rles" ] . append ( IIi1iii )
    if 28 - 28: oO0o * Oo0Ooo - i1IIi * iIii1I11I1II1 . OOooOOo % Ii1I
    if 68 - 68: IiII - iII111i . IiII + iII111i . iIii1I11I1II1 - Ii1I
 else :
  for iIIiIi1111iiIii in mc . rloc_set :
   if ( iIIiIi1111iiIii . rloc . is_ipv4 ( ) == False and iIIiIi1111iiIii . rloc . is_ipv6 ( ) == False ) :
    continue
    if 30 - 30: i1IIi * OoO0O00
   if ( iIIiIi1111iiIii . up_state ( ) == False ) : continue
   if 80 - 80: I11i
   O0ooO0O00oo0 = str ( 4341 ) if iIIiIi1111iiIii . translated_port == 0 else str ( iIIiIi1111iiIii . translated_port )
   if 96 - 96: i1IIi - I1ii11iIi11i * iII111i . OOooOOo . OoO0O00
   IIi1iii = { "rloc" : iIIiIi1111iiIii . rloc . print_address_no_iid ( ) , "priority" :
 str ( iIIiIi1111iiIii . priority ) , "weight" : str ( iIIiIi1111iiIii . weight ) , "port" :
 O0ooO0O00oo0 }
   OooOooo0 , I11i1iii1I = iIIiIi1111iiIii . get_encap_keys ( )
   IIi1iii = lisp_build_json_keys ( IIi1iii , OooOooo0 , I11i1iii1I , "encrypt-key" )
   I1I11i [ "rlocs" ] . append ( IIi1iii )
   if 93 - 93: oO0o * Oo0Ooo * IiII
   if 26 - 26: o0oOOo0O0Ooo + O0 % i11iIiiIii . ooOoO0o . I1IiiI + Oo0Ooo
   if 90 - 90: IiII * OoooooooOO + II111iiii / iII111i + i11iIiiIii / ooOoO0o
 if ( dont_send == False ) : lisp_write_to_dp_socket ( I1I11i )
 return ( I1I11i )
 if 20 - 20: II111iiii % I1ii11iIi11i - OoooooooOO * Ii1I / I11i - OoooooooOO
 if 11 - 11: I1IiiI + Ii1I + i11iIiiIii * I1ii11iIi11i - oO0o
 if 46 - 46: OoooooooOO - Oo0Ooo
 if 4 - 4: II111iiii . OOooOOo - Ii1I - i11iIiiIii
 if 27 - 27: iII111i * iII111i - OoO0O00 % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 64 - 64: I1ii11iIi11i * ooOoO0o - OoooooooOO - I1IiiI
 if 59 - 59: I1ii11iIi11i . I1Ii111 - OOooOOo / Oo0Ooo + OOooOOo . I1ii11iIi11i
def lisp_write_ipc_decap_key ( rloc_addr , keys ) :
 if ( lisp_i_am_itr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 69 - 69: Oo0Ooo
 if 34 - 34: I1Ii111 - ooOoO0o . o0oOOo0O0Ooo
 if 52 - 52: o0oOOo0O0Ooo % I11i * I11i / iIii1I11I1II1
 if 77 - 77: OoOoOO00
 if ( keys == None or len ( keys ) == 0 or keys [ 1 ] == None ) : return
 if 67 - 67: OoooooooOO / OoooooooOO + IiII - ooOoO0o
 OooOooo0 = keys [ 1 ] . encrypt_key
 I11i1iii1I = keys [ 1 ] . icv_key
 if 72 - 72: Ii1I
 if 21 - 21: ooOoO0o + iII111i
 if 39 - 39: o0oOOo0O0Ooo % I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo
 if 78 - 78: OoO0O00 / o0oOOo0O0Ooo / O0 % OOooOOo % i1IIi
 oOoOoO0O0 = rloc_addr . split ( ":" )
 if ( len ( oOoOoO0O0 ) == 1 ) :
  I1I11i = { "type" : "decap-keys" , "rloc" : oOoOoO0O0 [ 0 ] }
 else :
  I1I11i = { "type" : "decap-keys" , "rloc" : oOoOoO0O0 [ 0 ] , "port" : oOoOoO0O0 [ 1 ] }
  if 56 - 56: OoO0O00 . OOooOOo * OoO0O00 . ooOoO0o * OoooooooOO
 I1I11i = lisp_build_json_keys ( I1I11i , OooOooo0 , I11i1iii1I , "decrypt-key" )
 if 75 - 75: i1IIi - I11i
 lisp_write_to_dp_socket ( I1I11i )
 return
 if 5 - 5: OoO0O00 - oO0o - OOooOOo + II111iiii
 if 19 - 19: iIii1I11I1II1 * OoooooooOO - i11iIiiIii . I1Ii111 * OoO0O00
 if 30 - 30: iII111i + I1IiiI * ooOoO0o
 if 53 - 53: iII111i + IiII
 if 52 - 52: II111iiii * i11iIiiIii - IiII * IiII / OoooooooOO
 if 18 - 18: IiII / O0 / I1ii11iIi11i
 if 47 - 47: oO0o / iIii1I11I1II1
 if 45 - 45: OoOoOO00 * o0oOOo0O0Ooo / I1ii11iIi11i * iII111i - I1ii11iIi11i
def lisp_build_json_keys ( entry , ekey , ikey , key_type ) :
 if ( ekey == None ) : return ( entry )
 if 48 - 48: Ii1I / OoO0O00
 entry [ "keys" ] = [ ]
 I1IIiiI1II = { "key-id" : "1" , key_type : ekey , "icv-key" : ikey }
 entry [ "keys" ] . append ( I1IIiiI1II )
 return ( entry )
 if 45 - 45: O0 * OoO0O00 / I11i . II111iiii
 if 20 - 20: I11i - IiII
 if 75 - 75: i11iIiiIii + I11i % I11i . I1Ii111
 if 58 - 58: o0oOOo0O0Ooo * II111iiii + o0oOOo0O0Ooo . I1IiiI
 if 25 - 25: o0oOOo0O0Ooo * I11i
 if 70 - 70: OOooOOo
 if 11 - 11: I11i * II111iiii * Oo0Ooo + OOooOOo % i1IIi
def lisp_write_ipc_database_mappings ( ephem_port ) :
 if ( lisp_i_am_etr == False ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 73 - 73: OoO0O00 + O0 / Ii1I . OoooooooOO % iIii1I11I1II1 * i1IIi
 if 84 - 84: o0oOOo0O0Ooo . iII111i / o0oOOo0O0Ooo + I1ii11iIi11i % OoO0O00
 if 52 - 52: OoOoOO00 / Ii1I % OoOoOO00 % i11iIiiIii + I1IiiI / o0oOOo0O0Ooo
 if 63 - 63: I1IiiI
 I1I11i = { "type" : "database-mappings" , "database-mappings" : [ ] }
 if 20 - 20: oO0o + OoOoOO00
 if 32 - 32: o0oOOo0O0Ooo % oO0o % I1IiiI * OoooooooOO
 if 4 - 4: OOooOOo % oO0o
 if 18 - 18: Ii1I * I11i
 for Iiii1II1 in lisp_db_list :
  if ( Iiii1II1 . eid . is_ipv4 ( ) == False and Iiii1II1 . eid . is_ipv6 ( ) == False ) : continue
  I1OOOOO00O00O0 = { "instance-id" : str ( Iiii1II1 . eid . instance_id ) ,
 "eid-prefix" : Iiii1II1 . eid . print_prefix_no_iid ( ) }
  I1I11i [ "database-mappings" ] . append ( I1OOOOO00O00O0 )
  if 50 - 50: I1ii11iIi11i / I1ii11iIi11i * OOooOOo - Oo0Ooo . oO0o
 lisp_write_to_dp_socket ( I1I11i )
 if 56 - 56: O0 . iIii1I11I1II1
 if 100 - 100: Oo0Ooo % OoooooooOO
 if 28 - 28: oO0o . o0oOOo0O0Ooo
 if 14 - 14: Oo0Ooo - I1Ii111 + Oo0Ooo / iII111i
 if 61 - 61: Ii1I * Ii1I . OoOoOO00 + OoO0O00 * i11iIiiIii * OoO0O00
 I1I11i = { "type" : "etr-nat-port" , "port" : ephem_port }
 lisp_write_to_dp_socket ( I1I11i )
 return
 if 4 - 4: OoooooooOO % iII111i % Oo0Ooo * IiII % o0oOOo0O0Ooo . o0oOOo0O0Ooo
 if 66 - 66: I1IiiI . Oo0Ooo - oO0o
 if 53 - 53: oO0o / Ii1I + oO0o + II111iiii
 if 70 - 70: OoooooooOO - I1Ii111 + OoOoOO00
 if 61 - 61: I1IiiI * I1Ii111 * i11iIiiIii
 if 68 - 68: OoOoOO00 - iII111i - I1IiiI
 if 37 - 37: iII111i - I1Ii111 + i1IIi / o0oOOo0O0Ooo % iII111i / iII111i
def lisp_write_ipc_interfaces ( ) :
 if ( lisp_i_am_etr ) : return
 if ( lisp_ipc_dp_socket == None ) : return
 if ( lisp_check_dp_socket ( ) == False ) : return
 if 8 - 8: i1IIi % I11i
 if 12 - 12: ooOoO0o / II111iiii + ooOoO0o * I1ii11iIi11i / i1IIi - iIii1I11I1II1
 if 71 - 71: IiII - i11iIiiIii
 if 3 - 3: i11iIiiIii - o0oOOo0O0Ooo / oO0o . OoO0O00 * I11i + o0oOOo0O0Ooo
 I1I11i = { "type" : "interfaces" , "interfaces" : [ ] }
 if 18 - 18: OoooooooOO % oO0o / IiII - ooOoO0o
 for oo in list ( lisp_myinterfaces . values ( ) ) :
  if ( oo . instance_id == None ) : continue
  I1OOOOO00O00O0 = { "interface" : oo . device ,
 "instance-id" : str ( oo . instance_id ) }
  I1I11i [ "interfaces" ] . append ( I1OOOOO00O00O0 )
  if 80 - 80: I11i
  if 98 - 98: iII111i / I1ii11iIi11i
 lisp_write_to_dp_socket ( I1I11i )
 return
 if 87 - 87: iII111i - O0 * ooOoO0o / II111iiii % OoooooooOO . o0oOOo0O0Ooo
 if 55 - 55: OOooOOo - o0oOOo0O0Ooo * I1IiiI / o0oOOo0O0Ooo + I1Ii111 + iIii1I11I1II1
 if 3 - 3: II111iiii % iII111i / IiII * ooOoO0o . OoooooooOO
 if 56 - 56: IiII * II111iiii + Oo0Ooo - O0 - OoO0O00 . I1Ii111
 if 53 - 53: i1IIi + IiII
 if 90 - 90: II111iiii / oO0o / oO0o . OoOoOO00 / OoO0O00 / iIii1I11I1II1
 if 96 - 96: iIii1I11I1II1 % I1ii11iIi11i
 if 35 - 35: i1IIi - OoooooooOO * Ii1I / OOooOOo % I11i
 if 72 - 72: I1Ii111 / OoO0O00 + II111iiii
 if 40 - 40: Ii1I + O0 . i11iIiiIii % I11i / Oo0Ooo
 if 25 - 25: IiII * IiII
 if 54 - 54: I1Ii111
 if 90 - 90: Oo0Ooo / Ii1I
 if 66 - 66: i11iIiiIii - I11i + oO0o . OoooooooOO
def lisp_parse_auth_key ( value ) :
 i1II1ii1I1I = value . split ( "[" )
 oO00 = { }
 if ( len ( i1II1ii1I1I ) == 1 ) :
  oO00 [ 0 ] = value
  return ( oO00 )
  if 76 - 76: IiII + Ii1I
  if 64 - 64: Oo0Ooo % O0
 for iI1i1111 in i1II1ii1I1I :
  if ( iI1i1111 == "" ) : continue
  o00O = iI1i1111 . find ( "]" )
  III = iI1i1111 [ 0 : o00O ]
  try : III = int ( III )
  except : return
  if 66 - 66: O0 + I1IiiI % iIii1I11I1II1 . i1IIi % II111iiii - i1IIi
  oO00 [ III ] = iI1i1111 [ o00O + 1 : : ]
  if 93 - 93: O0 + OoooooooOO % IiII % oO0o % I1ii11iIi11i
 return ( oO00 )
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
 if 41 - 41: iII111i / Ii1I
 if 11 - 11: Oo0Ooo % OOooOOo . ooOoO0o
 if 24 - 24: IiII / Oo0Ooo
def lisp_reassemble ( packet ) :
 ooOo0oO0O = socket . ntohs ( struct . unpack ( "H" , packet [ 6 : 8 ] ) [ 0 ] )
 if 90 - 90: ooOoO0o . OOooOOo - Ii1I
 if 60 - 60: i11iIiiIii % iII111i . I1IiiI * I1ii11iIi11i
 if 30 - 30: Ii1I + i11iIiiIii . I11i + o0oOOo0O0Ooo - OoO0O00
 if 55 - 55: ooOoO0o - II111iiii . ooOoO0o . iII111i / OoooooooOO
 if ( ooOo0oO0O == 0 or ooOo0oO0O == 0x4000 ) : return ( packet )
 if 51 - 51: I1IiiI * I1Ii111 - ooOoO0o + IiII
 if 22 - 22: OoOoOO00 % Ii1I + iII111i
 if 64 - 64: ooOoO0o
 if 87 - 87: IiII - Ii1I / Oo0Ooo / I1ii11iIi11i . iII111i
 iIIi1I1Ii1 = socket . ntohs ( struct . unpack ( "H" , packet [ 4 : 6 ] ) [ 0 ] )
 o0O = socket . ntohs ( struct . unpack ( "H" , packet [ 2 : 4 ] ) [ 0 ] )
 if 49 - 49: IiII * OoooooooOO * iIii1I11I1II1 * Oo0Ooo / iII111i % oO0o
 o00OOOOOooooo = ( ooOo0oO0O & 0x2000 == 0 and ( ooOo0oO0O & 0x1fff ) != 0 )
 I1I11i = [ ( ooOo0oO0O & 0x1fff ) * 8 , o0O - 20 , packet , o00OOOOOooooo ]
 if 77 - 77: II111iiii / OOooOOo + OOooOOo / Ii1I
 if 46 - 46: OoOoOO00 * I1ii11iIi11i % o0oOOo0O0Ooo / I1IiiI - i1IIi * ooOoO0o
 if 2 - 2: Ii1I - I1IiiI - Oo0Ooo . iII111i / i1IIi
 if 73 - 73: OoooooooOO + Ii1I * OOooOOo
 if 5 - 5: I1IiiI * O0 * Ii1I
 if 61 - 61: OOooOOo * Oo0Ooo - i11iIiiIii
 if 99 - 99: I1IiiI + O0 + OoOoOO00 + I1ii11iIi11i
 if 80 - 80: OoOoOO00
 if ( ooOo0oO0O == 0x2000 ) :
  II1 , Ooo0000o00OO = struct . unpack ( "HH" , packet [ 20 : 24 ] )
  II1 = socket . ntohs ( II1 )
  Ooo0000o00OO = socket . ntohs ( Ooo0000o00OO )
  if ( Ooo0000o00OO not in [ 4341 , 8472 , 4789 ] and II1 != 4341 ) :
   lisp_reassembly_queue [ iIIi1I1Ii1 ] = [ ]
   I1I11i [ 2 ] = None
   if 46 - 46: iIii1I11I1II1 % OoooooooOO - I1Ii111 % Oo0Ooo % i11iIiiIii % OOooOOo
   if 2 - 2: i11iIiiIii
   if 93 - 93: OoOoOO00
   if 14 - 14: II111iiii
   if 68 - 68: Ii1I % Oo0Ooo + I1ii11iIi11i + I1ii11iIi11i + oO0o % Oo0Ooo
   if 22 - 22: OoO0O00
 if ( iIIi1I1Ii1 not in lisp_reassembly_queue ) :
  lisp_reassembly_queue [ iIIi1I1Ii1 ] = [ ]
  if 40 - 40: I1ii11iIi11i * I1Ii111
  if 6 - 6: i11iIiiIii . o0oOOo0O0Ooo * iIii1I11I1II1 . OoOoOO00 . II111iiii
  if 67 - 67: OoO0O00 - Oo0Ooo + OOooOOo / OoOoOO00 + OOooOOo
  if 18 - 18: Oo0Ooo % OoOoOO00 % i1IIi
  if 66 - 66: OoOoOO00 % II111iiii
 queue = lisp_reassembly_queue [ iIIi1I1Ii1 ]
 if 16 - 16: i11iIiiIii - I1IiiI + ooOoO0o * oO0o
 if 30 - 30: II111iiii / o0oOOo0O0Ooo
 if 57 - 57: I11i / I1ii11iIi11i . I11i
 if 68 - 68: OoOoOO00 + O0 . I1IiiI
 if 26 - 26: I1ii11iIi11i
 if ( len ( queue ) == 1 and queue [ 0 ] [ 2 ] == None ) :
  dprint ( "Drop non-LISP encapsulated fragment 0x{}" . format ( lisp_hex_string ( iIIi1I1Ii1 ) . zfill ( 4 ) ) )
  if 98 - 98: Oo0Ooo
  return ( None )
  if 72 - 72: oO0o + OoooooooOO . O0 + IiII
  if 49 - 49: i1IIi - i11iIiiIii + II111iiii + Ii1I / OoO0O00
  if 34 - 34: I1ii11iIi11i * i11iIiiIii
  if 6 - 6: I1ii11iIi11i + I1IiiI / OoooooooOO % I11i * Oo0Ooo
  if 20 - 20: Oo0Ooo
 queue . append ( I1I11i )
 queue = sorted ( queue )
 if 85 - 85: I1Ii111
 if 98 - 98: OoO0O00 - IiII % iIii1I11I1II1 . OoOoOO00 + i1IIi + OoooooooOO
 if 29 - 29: I1ii11iIi11i * I1Ii111 - i1IIi * i11iIiiIii * iIii1I11I1II1 % I11i
 if 73 - 73: OoO0O00 . I1IiiI / o0oOOo0O0Ooo
 iI1ii11Ii = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 iI1ii11Ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 I1Ii1iIII1Ii1 = iI1ii11Ii . print_address_no_iid ( )
 iI1ii11Ii . address = socket . ntohl ( struct . unpack ( "I" , packet [ 16 : 20 ] ) [ 0 ] )
 I1I11i1ii = iI1ii11Ii . print_address_no_iid ( )
 iI1ii11Ii = red ( "{} -> {}" . format ( I1Ii1iIII1Ii1 , I1I11i1ii ) , False )
 if 47 - 47: iIii1I11I1II1
 dprint ( "{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}" . format ( bold ( "Received" , False ) , " non-LISP encapsulated" if I1I11i [ 2 ] == None else "" , iI1ii11Ii , lisp_hex_string ( iIIi1I1Ii1 ) . zfill ( 4 ) ,
 # OoooooooOO * i11iIiiIii
 # i1IIi / o0oOOo0O0Ooo
 lisp_hex_string ( ooOo0oO0O ) . zfill ( 4 ) ) )
 if 13 - 13: O0 . IiII + IiII % OoOoOO00 . Oo0Ooo
 if 49 - 49: ooOoO0o * OoooooooOO + oO0o / OoOoOO00 + I1ii11iIi11i * Oo0Ooo
 if 13 - 13: ooOoO0o
 if 83 - 83: I1IiiI % I1ii11iIi11i * IiII % oO0o
 if 23 - 23: OoooooooOO + iII111i + OoOoOO00 + iII111i
 if ( queue [ 0 ] [ 0 ] != 0 or queue [ - 1 ] [ 3 ] == False ) : return ( None )
 IIiI1IiII = queue [ 0 ]
 for IiI111 in queue [ 1 : : ] :
  ooOo0oO0O = IiI111 [ 0 ]
  iII1 , OoooOOOoO = IIiI1IiII [ 0 ] , IIiI1IiII [ 1 ]
  if ( iII1 + OoooOOOoO != ooOo0oO0O ) : return ( None )
  IIiI1IiII = IiI111
  if 46 - 46: i1IIi / Ii1I % I1ii11iIi11i
 lisp_reassembly_queue . pop ( iIIi1I1Ii1 )
 if 43 - 43: ooOoO0o
 if 90 - 90: IiII % oO0o - I11i
 if 70 - 70: iII111i - II111iiii % I1ii11iIi11i - IiII - ooOoO0o
 if 20 - 20: OoOoOO00
 if 34 - 34: I1IiiI . Oo0Ooo
 packet = queue [ 0 ] [ 2 ]
 for IiI111 in queue [ 1 : : ] : packet += IiI111 [ 2 ] [ 20 : : ]
 if 4 - 4: Ii1I - II111iiii * iII111i / oO0o - I1IiiI
 dprint ( "{} fragments arrived for packet 0x{}, length {}" . format ( bold ( "All" , False ) , lisp_hex_string ( iIIi1I1Ii1 ) . zfill ( 4 ) , len ( packet ) ) )
 if 32 - 32: iIii1I11I1II1 - I11i
 if 49 - 49: I11i * I1Ii111 - iIii1I11I1II1 * O0
 if 72 - 72: I1IiiI * iII111i
 if 61 - 61: Ii1I * Oo0Ooo * I1Ii111 % I11i + iII111i % oO0o
 if 67 - 67: IiII
 OOOOo0o0O0o = socket . htons ( len ( packet ) )
 I11 = packet [ 0 : 2 ] + struct . pack ( "H" , OOOOo0o0O0o ) + packet [ 4 : 6 ] + struct . pack ( "H" , 0 ) + packet [ 8 : 10 ] + struct . pack ( "H" , 0 ) + packet [ 12 : 20 ]
 if 90 - 90: o0oOOo0O0Ooo
 if 5 - 5: i1IIi
 I11 = lisp_ip_checksum ( I11 )
 return ( I11 + packet [ 20 : : ] )
 if 55 - 55: Ii1I
 if 46 - 46: OOooOOo / iII111i . i1IIi . i11iIiiIii . iIii1I11I1II1 % I11i
 if 62 - 62: I11i % II111iiii % OoooooooOO * ooOoO0o / oO0o
 if 29 - 29: o0oOOo0O0Ooo / O0 / OoO0O00
 if 23 - 23: Ii1I + i11iIiiIii % IiII
 if 64 - 64: i11iIiiIii + OoooooooOO . oO0o * Ii1I
 if 49 - 49: O0
 if 72 - 72: I1Ii111
def lisp_get_crypto_decap_lookup_key ( addr , port ) :
 O00oO000Oo0 = addr . print_address_no_iid ( ) + ":" + str ( port )
 if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_decap ) : return ( O00oO000Oo0 )
 if 96 - 96: II111iiii / OOooOOo % i1IIi / Oo0Ooo
 O00oO000Oo0 = addr . print_address_no_iid ( )
 if ( O00oO000Oo0 in lisp_crypto_keys_by_rloc_decap ) : return ( O00oO000Oo0 )
 if 22 - 22: I1IiiI % iIii1I11I1II1 % I1ii11iIi11i
 if 68 - 68: iII111i + I11i
 if 61 - 61: oO0o . I1Ii111
 if 74 - 74: O0 . Ii1I - iII111i % IiII + II111iiii
 if 71 - 71: oO0o + Ii1I % oO0o
 for i111I11I1i1 in lisp_crypto_keys_by_rloc_decap :
  I1II1I1I = i111I11I1i1 . split ( ":" )
  if ( len ( I1II1I1I ) == 1 ) : continue
  I1II1I1I = I1II1I1I [ 0 ] if len ( I1II1I1I ) == 2 else ":" . join ( I1II1I1I [ 0 : - 1 ] )
  if ( I1II1I1I == O00oO000Oo0 ) :
   oOoOOoo = lisp_crypto_keys_by_rloc_decap [ i111I11I1i1 ]
   lisp_crypto_keys_by_rloc_decap [ O00oO000Oo0 ] = oOoOOoo
   return ( O00oO000Oo0 )
   if 27 - 27: O0 / OoO0O00
   if 92 - 92: I1ii11iIi11i % O0 % ooOoO0o - OoOoOO00
 return ( None )
 if 83 - 83: I1Ii111 . I1Ii111 - OoO0O00 % Ii1I
 if 30 - 30: OOooOOo * II111iiii
 if 48 - 48: iIii1I11I1II1 * I1Ii111 % i1IIi % iIii1I11I1II1 % Oo0Ooo
 if 1 - 1: oO0o % oO0o % i11iIiiIii
 if 28 - 28: OoooooooOO * I1IiiI % iII111i
 if 15 - 15: OOooOOo * Ii1I / ooOoO0o
 if 70 - 70: i11iIiiIii * oO0o . I11i - OoooooooOO / I1ii11iIi11i
 if 10 - 10: IiII * OoOoOO00 . II111iiii . II111iiii * Oo0Ooo
 if 23 - 23: I1ii11iIi11i + I11i
 if 74 - 74: i1IIi % I1IiiI
 if 44 - 44: Oo0Ooo - OoooooooOO % ooOoO0o + II111iiii
def lisp_build_crypto_decap_lookup_key ( addr , port ) :
 addr = addr . print_address_no_iid ( )
 OOO00o0O = addr + ":" + str ( port )
 if 26 - 26: Ii1I . OOooOOo / iII111i % OoOoOO00
 if ( lisp_i_am_rtr ) :
  if ( addr in lisp_rloc_probe_list ) : return ( addr )
  if 8 - 8: I1IiiI / O0 * I1IiiI . ooOoO0o * I1IiiI + I1Ii111
  if 52 - 52: i1IIi - IiII + OOooOOo
  if 96 - 96: Oo0Ooo + I1ii11iIi11i . O0
  if 62 - 62: i1IIi % OoooooooOO % OoooooooOO
  if 53 - 53: O0 * oO0o
  if 22 - 22: OOooOOo % Oo0Ooo % ooOoO0o - O0 + i1IIi
  for ooOOoO in list ( lisp_nat_state_info . values ( ) ) :
   for Iii1IiIII in ooOOoO :
    if ( addr == Iii1IiIII . address ) : return ( OOO00o0O )
    if 67 - 67: OoO0O00 / I1IiiI - IiII + iII111i - iII111i
    if 4 - 4: IiII . Ii1I . IiII % OoO0O00
  return ( addr )
  if 12 - 12: OoOoOO00 + O0 / O0 . i1IIi
 return ( OOO00o0O )
 if 58 - 58: IiII . iII111i % O0 . Ii1I * Oo0Ooo
 if 54 - 54: OoO0O00 % OOooOOo - OoO0O00 . Oo0Ooo % i1IIi
 if 95 - 95: iII111i . OoooooooOO . o0oOOo0O0Ooo / II111iiii - OoooooooOO / I1Ii111
 if 11 - 11: II111iiii / iII111i . oO0o / ooOoO0o / OOooOOo + OoO0O00
 if 37 - 37: iIii1I11I1II1 * O0
 if 64 - 64: I1Ii111 - II111iiii + oO0o % ooOoO0o * oO0o
 if 27 - 27: iIii1I11I1II1 - Ii1I . i11iIiiIii / IiII . I1Ii111 / i11iIiiIii
def lisp_is_rloc_probe_request ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x12 )
 if 27 - 27: OoOoOO00 . I11i / OoOoOO00
 if 96 - 96: OoO0O00 - I1IiiI
 if 73 - 73: I1IiiI - o0oOOo0O0Ooo - I1Ii111
 if 34 - 34: iIii1I11I1II1 - i1IIi + OoO0O00 % Oo0Ooo + i1IIi
 if 46 - 46: I1IiiI
 if 82 - 82: iII111i . i1IIi
 if 38 - 38: Ii1I . I1IiiI . I1ii11iIi11i
def lisp_is_rloc_probe_reply ( lisp_type ) :
 lisp_type = struct . unpack ( "B" , lisp_type ) [ 0 ]
 return ( lisp_type == 0x28 )
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
def lisp_is_rloc_probe ( packet , device , rr ) :
 ii11 = ( struct . unpack ( "B" , packet [ 9 : 10 ] ) [ 0 ] == 17 )
 if ( ii11 == False ) : return ( [ packet , None , None , None ] )
 if 46 - 46: I11i % ooOoO0o - Ii1I
 II1 = struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ]
 Ooo0000o00OO = struct . unpack ( "H" , packet [ 22 : 24 ] ) [ 0 ]
 iiii = ( socket . htons ( LISP_CTRL_PORT ) in [ II1 , Ooo0000o00OO ] )
 if ( iiii == False ) : return ( [ packet , None , None , None ] )
 if 6 - 6: o0oOOo0O0Ooo % I1ii11iIi11i
 if ( rr == 0 ) :
  oO00oo0 = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( oO00oo0 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == 1 ) :
  oO00oo0 = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
  if ( oO00oo0 == False ) : return ( [ packet , None , None , None ] )
 elif ( rr == - 1 ) :
  oO00oo0 = lisp_is_rloc_probe_request ( packet [ 28 : 29 ] )
  if ( oO00oo0 == False ) :
   oO00oo0 = lisp_is_rloc_probe_reply ( packet [ 28 : 29 ] )
   if ( oO00oo0 == False ) : return ( [ packet , None , None , None ] )
   if 23 - 23: iIii1I11I1II1
   if 84 - 84: I1ii11iIi11i + I1Ii111
   if 23 - 23: OoooooooOO % OoO0O00 . i11iIiiIii * i11iIiiIii * OoOoOO00
   if 84 - 84: OOooOOo % I1Ii111 + I11i / I1IiiI . iII111i
   if 78 - 78: oO0o . Oo0Ooo
   if 18 - 18: IiII
 ooOO0O0O = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 ooOO0O0O . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 if 35 - 35: OoooooooOO / i1IIi - OoO0O00 + Oo0Ooo - o0oOOo0O0Ooo
 if 100 - 100: II111iiii % i11iIiiIii % oO0o + O0
 if 46 - 46: OoO0O00 / I1IiiI - Oo0Ooo . o0oOOo0O0Ooo . Oo0Ooo % I11i
 if 43 - 43: IiII - O0 + I1Ii111 % OoooooooOO % OoO0O00 / I1Ii111
 if ( ooOO0O0O . is_local ( ) ) : return ( [ None , None , None , None ] )
 if 48 - 48: I1ii11iIi11i . i1IIi % i1IIi - iII111i * o0oOOo0O0Ooo + IiII
 if 45 - 45: II111iiii . II111iiii + I1IiiI / I1Ii111 . OoO0O00 - o0oOOo0O0Ooo
 if 20 - 20: ooOoO0o % oO0o
 if 28 - 28: i1IIi . II111iiii + O0 / O0 % OoOoOO00 + OOooOOo
 ooOO0O0O = ooOO0O0O . print_address_no_iid ( )
 O0ooO0O00oo0 = socket . ntohs ( struct . unpack ( "H" , packet [ 20 : 22 ] ) [ 0 ] )
 o0ooo000o00O = struct . unpack ( "B" , packet [ 8 : 9 ] ) [ 0 ] - 1
 packet = packet [ 28 : : ]
 if 24 - 24: OoooooooOO
 IIi1iii = bold ( "Receive(pcap-{})" . format ( device ) , False )
 O0Oo0 = bold ( "from " + ooOO0O0O , False )
 I1i1I = lisp_format_packet ( packet )
 lprint ( "{} {} bytes {} {}, packet: {}" . format ( IIi1iii , len ( packet ) , O0Oo0 , O0ooO0O00oo0 , I1i1I ) )
 if 11 - 11: i11iIiiIii / iIii1I11I1II1 % ooOoO0o + OOooOOo
 return ( [ packet , ooOO0O0O , O0ooO0O00oo0 , o0ooo000o00O ] )
 if 73 - 73: OoOoOO00 + OoooooooOO + iIii1I11I1II1 + II111iiii * iIii1I11I1II1 - OoOoOO00
 if 71 - 71: O0 * OOooOOo . I1IiiI . I1Ii111 * I11i
 if 45 - 45: O0 . O0 . II111iiii * ooOoO0o
 if 2 - 2: OoO0O00 . o0oOOo0O0Ooo
 if 48 - 48: Ii1I
 if 45 - 45: I1ii11iIi11i - I11i + Ii1I
 if 82 - 82: iII111i
 if 81 - 81: i1IIi % OOooOOo - OoO0O00 - Oo0Ooo
 if 19 - 19: i1IIi
 if 97 - 97: OoO0O00 + i11iIiiIii % I1IiiI * Ii1I
 if 89 - 89: IiII % i11iIiiIii + OoO0O00 . oO0o / I1IiiI . Ii1I
def lisp_ipc_write_xtr_parameters ( cp , dp ) :
 if ( lisp_ipc_dp_socket == None ) : return
 if 11 - 11: ooOoO0o - I1Ii111 - I11i + OoOoOO00
 ooo0ooo0Oo = { "type" : "xtr-parameters" , "control-plane-logging" : cp ,
 "data-plane-logging" : dp , "rtr" : lisp_i_am_rtr }
 if 20 - 20: I11i + O0
 lisp_write_to_dp_socket ( ooo0ooo0Oo )
 return
 if 27 - 27: Oo0Ooo
 if 12 - 12: I1ii11iIi11i . iII111i - iII111i - OOooOOo - iIii1I11I1II1
 if 50 - 50: I1IiiI - iIii1I11I1II1 . iII111i - Ii1I / I1Ii111 + iII111i
 if 46 - 46: OOooOOo + iII111i % Oo0Ooo * iII111i % OoooooooOO * IiII
 if 27 - 27: I1IiiI + I1IiiI + I1ii11iIi11i - oO0o * OOooOOo
 if 53 - 53: I1ii11iIi11i / OoooooooOO * iIii1I11I1II1
 if 4 - 4: I1IiiI . iIii1I11I1II1 + OOooOOo / IiII . o0oOOo0O0Ooo . I11i
 if 52 - 52: ooOoO0o % i11iIiiIii . IiII + OoO0O00
def lisp_external_data_plane ( ) :
 I11iii = 'egrep "ipc-data-plane = yes" ./lisp.config'
 if ( getoutput ( I11iii ) != "" ) : return ( True )
 if 66 - 66: II111iiii . Ii1I
 if ( os . getenv ( "LISP_RUN_LISP_XTR" ) != None ) : return ( True )
 return ( False )
 if 42 - 42: iIii1I11I1II1 * iII111i * I1IiiI
 if 66 - 66: Oo0Ooo * i1IIi / I1ii11iIi11i / OoO0O00
 if 12 - 12: OOooOOo + iIii1I11I1II1 % I1Ii111 + OOooOOo
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
 if 65 - 65: o0oOOo0O0Ooo * OoO0O00 / o0oOOo0O0Ooo
def lisp_process_data_plane_restart ( do_clear = False ) :
 os . system ( "touch ./lisp.config" )
 if 77 - 77: OoooooooOO - Oo0Ooo - OoOoOO00 / I11i / O0 . i11iIiiIii
 i1ii1IiIIiii = { "type" : "entire-map-cache" , "entries" : [ ] }
 if 15 - 15: Ii1I . Oo0Ooo
 if ( do_clear == False ) :
  Oo0oO = i1ii1IiIIiii [ "entries" ]
  lisp_map_cache . walk_cache ( lisp_ipc_walk_map_cache , Oo0oO )
  if 73 - 73: iII111i + i11iIiiIii * OoOoOO00 * Oo0Ooo * OoooooooOO
  if 32 - 32: iIii1I11I1II1 * I1Ii111
 lisp_write_to_dp_socket ( i1ii1IiIIiii )
 return
 if 23 - 23: Ii1I
 if 74 - 74: OoooooooOO % I1Ii111 + OoO0O00 * i11iIiiIii - I11i - I1ii11iIi11i
 if 98 - 98: Ii1I - Oo0Ooo - o0oOOo0O0Ooo
 if 7 - 7: II111iiii + OoO0O00 . I1IiiI - iII111i . o0oOOo0O0Ooo
 if 65 - 65: Ii1I + O0
 if 30 - 30: OoOoOO00
 if 86 - 86: II111iiii % I1ii11iIi11i
 if 88 - 88: Oo0Ooo . oO0o + OoOoOO00 % OoooooooOO
 if 81 - 81: OoooooooOO . I1Ii111 + OoO0O00 % I1Ii111
 if 49 - 49: oO0o . oO0o % oO0o / Oo0Ooo
 if 62 - 62: ooOoO0o . i1IIi % OoO0O00 - I1ii11iIi11i - IiII
 if 57 - 57: i1IIi - II111iiii - O0 . iII111i + OoO0O00
 if 67 - 67: OOooOOo * iII111i / iIii1I11I1II1 / I1ii11iIi11i
 if 10 - 10: OoooooooOO % I1ii11iIi11i * i1IIi . iII111i
def lisp_process_data_plane_stats ( msg , lisp_sockets , lisp_port ) :
 if ( "entries" not in msg ) :
  lprint ( "No 'entries' in stats IPC message" )
  return
  if 96 - 96: II111iiii % i11iIiiIii - Oo0Ooo
 if ( type ( msg [ "entries" ] ) != list ) :
  lprint ( "'entries' in stats IPC message must be an array" )
  return
  if 70 - 70: O0 * iIii1I11I1II1 - IiII * I11i / Ii1I + i11iIiiIii
  if 26 - 26: II111iiii - I11i % I11i / ooOoO0o + Oo0Ooo
 for msg in msg [ "entries" ] :
  if ( "eid-prefix" not in msg ) :
   lprint ( "No 'eid-prefix' in stats IPC message" )
   continue
   if 91 - 91: I1IiiI % Ii1I - OOooOOo - Oo0Ooo / I1IiiI / OoO0O00
  oOOoo = msg [ "eid-prefix" ]
  if 40 - 40: OoooooooOO
  if ( "instance-id" not in msg ) :
   lprint ( "No 'instance-id' in stats IPC message" )
   continue
   if 71 - 71: OOooOOo
  i1I1iI = int ( msg [ "instance-id" ] )
  if 88 - 88: O0
  if 44 - 44: II111iiii - IiII / I1IiiI + ooOoO0o % iII111i - iII111i
  if 53 - 53: OoooooooOO
  if 41 - 41: i1IIi - oO0o
  Ooo0O = lisp_address ( LISP_AFI_NONE , "" , 0 , i1I1iI )
  Ooo0O . store_prefix ( oOOoo )
  IIII1 = lisp_map_cache_lookup ( None , Ooo0O )
  if ( IIII1 == None ) :
   lprint ( "Map-cache entry for {} not found for stats update" . format ( oOOoo ) )
   if 41 - 41: I11i
   continue
   if 92 - 92: i11iIiiIii
   if 62 - 62: i1IIi / I1IiiI - o0oOOo0O0Ooo
  if ( "rlocs" not in msg ) :
   lprint ( "No 'rlocs' in stats IPC message for {}" . format ( oOOoo ) )
   if 3 - 3: O0 * OoOoOO00 * I11i / OoOoOO00
   continue
   if 77 - 77: i1IIi
  if ( type ( msg [ "rlocs" ] ) != list ) :
   lprint ( "'rlocs' in stats IPC message must be an array" )
   continue
   if 3 - 3: iII111i * OoO0O00 - oO0o + iII111i . o0oOOo0O0Ooo + I1IiiI
  ooO0o = msg [ "rlocs" ]
  if 43 - 43: O0
  if 22 - 22: OoOoOO00 . O0 - I1Ii111
  if 78 - 78: I1Ii111 * Ii1I % Ii1I + I1IiiI
  if 83 - 83: iIii1I11I1II1 + O0 / IiII . iIii1I11I1II1
  for oOooo0 in ooO0o :
   if ( "rloc" not in oOooo0 ) : continue
   if 67 - 67: II111iiii
   I1I111i = oOooo0 [ "rloc" ]
   if ( I1I111i == "no-address" ) : continue
   if 46 - 46: iII111i - o0oOOo0O0Ooo . IiII * ooOoO0o . o0oOOo0O0Ooo
   iIIiIi1111iiIii = lisp_address ( LISP_AFI_NONE , "" , 0 , 0 )
   iIIiIi1111iiIii . store_address ( I1I111i )
   if 52 - 52: O0 . II111iiii * iIii1I11I1II1 . Ii1I + iIii1I11I1II1 + i1IIi
   oO0o0 = IIII1 . get_rloc ( iIIiIi1111iiIii )
   if ( oO0o0 == None ) : continue
   if 64 - 64: OOooOOo . OoO0O00 / O0 / OOooOOo
   if 65 - 65: i1IIi - oO0o . I1Ii111 . ooOoO0o % I1ii11iIi11i % I1ii11iIi11i
   if 1 - 1: I1Ii111 + I1Ii111
   if 96 - 96: iII111i + OoOoOO00 - o0oOOo0O0Ooo + Ii1I
   ii1IIi = 0 if ( "packet-count" not in oOooo0 ) else oOooo0 [ "packet-count" ]
   if 10 - 10: OoOoOO00 / OoOoOO00 + II111iiii - oO0o
   Ii111i1I1iI = 0 if ( "byte-count" not in oOooo0 ) else oOooo0 [ "byte-count" ]
   if 59 - 59: Oo0Ooo % I1IiiI * I1IiiI / iIii1I11I1II1 . OoOoOO00 % I11i
   iIiIIIIIii = 0 if ( "seconds-last-packet" not in oOooo0 ) else oOooo0 [ "seconds-last-packet" ]
   if 62 - 62: OOooOOo % Ii1I / IiII % oO0o - I1Ii111
   if 47 - 47: OoO0O00
   oO0o0 . stats . packet_count += ii1IIi
   oO0o0 . stats . byte_count += Ii111i1I1iI
   oO0o0 . stats . last_increment = lisp_get_timestamp ( ) - iIiIIIIIii
   if 78 - 78: O0 * II111iiii % O0 * O0 / oO0o
   lprint ( "Update stats {}/{}/{}s for {} RLOC {}" . format ( ii1IIi , Ii111i1I1iI ,
 iIiIIIIIii , oOOoo , I1I111i ) )
   if 47 - 47: Oo0Ooo . Oo0Ooo . I1IiiI / OoO0O00 + II111iiii + IiII
   if 23 - 23: i1IIi . II111iiii
   if 60 - 60: ooOoO0o * oO0o + Oo0Ooo / iIii1I11I1II1
   if 74 - 74: OoooooooOO + II111iiii - IiII + O0
   if 62 - 62: O0 . I11i * oO0o
  if ( IIII1 . group . is_null ( ) and IIII1 . has_ttl_elapsed ( ) ) :
   oOOoo = green ( IIII1 . print_eid_tuple ( ) , False )
   lprint ( "Refresh map-cache entry {}" . format ( oOOoo ) )
   lisp_send_map_request ( lisp_sockets , lisp_port , None , IIII1 . eid , None )
   if 88 - 88: iII111i * iII111i - ooOoO0o + OoO0O00 . iII111i
   if 44 - 44: I11i / I1Ii111
 return
 if 77 - 77: oO0o * OoOoOO00 * O0 % IiII
 if 45 - 45: OoOoOO00
 if 66 - 66: I11i
 if 10 - 10: i11iIiiIii - O0 / iII111i * i11iIiiIii * OoooooooOO - oO0o
 if 70 - 70: i1IIi / IiII + II111iiii - I1ii11iIi11i . OoooooooOO - i1IIi
 if 34 - 34: OoOoOO00 + iII111i - I11i . IiII
 if 79 - 79: ooOoO0o - II111iiii + I1IiiI - o0oOOo0O0Ooo . Ii1I
 if 16 - 16: o0oOOo0O0Ooo . i1IIi * ooOoO0o / OoOoOO00 % i11iIiiIii
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
 if 77 - 77: OOooOOo * OoOoOO00
 if 75 - 75: Oo0Ooo * Oo0Ooo - IiII - OoOoOO00 / i11iIiiIii + I1Ii111
 if 57 - 57: i11iIiiIii / oO0o
 if 37 - 37: o0oOOo0O0Ooo + OoOoOO00 - i1IIi . Oo0Ooo
 if 3 - 3: ooOoO0o % OoooooooOO / I1Ii111 + oO0o - O0
 if 72 - 72: oO0o * OoO0O00
 if 89 - 89: OoooooooOO . OOooOOo
def lisp_process_data_plane_decap_stats ( msg , lisp_ipc_socket ) :
 if 96 - 96: o0oOOo0O0Ooo + OoOoOO00 / i11iIiiIii - o0oOOo0O0Ooo * i11iIiiIii + OOooOOo
 if 16 - 16: IiII / I1Ii111 . II111iiii * I11i
 if 33 - 33: I1ii11iIi11i / Oo0Ooo % i11iIiiIii
 if 37 - 37: Oo0Ooo - I1Ii111 - IiII / oO0o % I1IiiI / I1Ii111
 if 80 - 80: iII111i - oO0o % i1IIi * iIii1I11I1II1 . oO0o
 if ( lisp_i_am_itr ) :
  lprint ( "Send decap-stats IPC message to lisp-etr process" )
  ooo0ooo0Oo = "stats%{}" . format ( json . dumps ( msg ) )
  ooo0ooo0Oo = lisp_command_ipc ( ooo0ooo0Oo , "lisp-itr" )
  lisp_ipc ( ooo0ooo0Oo , lisp_ipc_socket , "lisp-etr" )
  return
  if 86 - 86: Ii1I
  if 36 - 36: i11iIiiIii % i11iIiiIii
  if 91 - 91: Oo0Ooo + I1Ii111 % iII111i
  if 7 - 7: I1Ii111 + II111iiii
  if 63 - 63: OoO0O00 - o0oOOo0O0Ooo / iII111i % II111iiii * IiII
  if 71 - 71: IiII
  if 34 - 34: II111iiii
  if 7 - 7: IiII / I1ii11iIi11i
 ooo0ooo0Oo = bold ( "IPC" , False )
 lprint ( "Process decap-stats {} message: '{}'" . format ( ooo0ooo0Oo , msg ) )
 if 88 - 88: iIii1I11I1II1 / o0oOOo0O0Ooo
 if ( lisp_i_am_etr ) : msg = json . loads ( msg )
 if 68 - 68: OoooooooOO % Ii1I + ooOoO0o / oO0o
 ooooo = [ "good-packets" , "ICV-error" , "checksum-error" ,
 "lisp-header-error" , "no-decrypt-key" , "bad-inner-version" ,
 "outer-header-error" ]
 if 99 - 99: I1IiiI / oO0o . OoO0O00 / ooOoO0o + IiII
 for Ii1o0 in ooooo :
  ii1IIi = 0 if ( Ii1o0 not in msg ) else msg [ Ii1o0 ] [ "packet-count" ]
  lisp_decap_stats [ Ii1o0 ] . packet_count += ii1IIi
  if 16 - 16: I1ii11iIi11i - ooOoO0o + OoO0O00 . I11i / O0
  Ii111i1I1iI = 0 if ( Ii1o0 not in msg ) else msg [ Ii1o0 ] [ "byte-count" ]
  lisp_decap_stats [ Ii1o0 ] . byte_count += Ii111i1I1iI
  if 56 - 56: I1IiiI + Oo0Ooo * II111iiii + iIii1I11I1II1
  iIiIIIIIii = 0 if ( Ii1o0 not in msg ) else msg [ Ii1o0 ] [ "seconds-last-packet" ]
  if 56 - 56: o0oOOo0O0Ooo * I1IiiI - I11i * I1Ii111 - I11i
  lisp_decap_stats [ Ii1o0 ] . last_increment = lisp_get_timestamp ( ) - iIiIIIIIii
  if 92 - 92: oO0o % iIii1I11I1II1 * o0oOOo0O0Ooo * OoooooooOO - iIii1I11I1II1
 return
 if 51 - 51: Ii1I - OoO0O00 + i1IIi
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
 if 27 - 27: Ii1I
 if 90 - 90: I1ii11iIi11i
 if 43 - 43: OoO0O00 . I1IiiI . oO0o + Ii1I
def lisp_process_punt ( punt_socket , lisp_send_sockets , lisp_ephem_port ) :
 I1IIII1i111IIiii11 , ooOO0O0O = punt_socket . recvfrom ( 4000 )
 if 29 - 29: I11i . iII111i % iIii1I11I1II1 * i1IIi * oO0o
 I11iI1i1 = json . loads ( I1IIII1i111IIiii11 )
 if ( type ( I11iI1i1 ) != dict ) :
  lprint ( "Invalid punt message from {}, not in JSON format" . format ( ooOO0O0O ) )
  if 68 - 68: i1IIi + I1ii11iIi11i - o0oOOo0O0Ooo . OOooOOo % o0oOOo0O0Ooo
  return
  if 30 - 30: i1IIi . OOooOOo % Oo0Ooo * iIii1I11I1II1
 OOo0OI1I1iiII1I = bold ( "Punt" , False )
 lprint ( "{} message from '{}': '{}'" . format ( OOo0OI1I1iiII1I , ooOO0O0O , I11iI1i1 ) )
 if 26 - 26: iIii1I11I1II1 . o0oOOo0O0Ooo
 if ( "type" not in I11iI1i1 ) :
  lprint ( "Punt IPC message has no 'type' key" )
  return
  if 49 - 49: II111iiii
  if 9 - 9: o0oOOo0O0Ooo
  if 47 - 47: Ii1I * I1Ii111 / II111iiii
  if 73 - 73: ooOoO0o
  if 53 - 53: IiII . Oo0Ooo
 if ( I11iI1i1 [ "type" ] == "statistics" ) :
  lisp_process_data_plane_stats ( I11iI1i1 , lisp_send_sockets , lisp_ephem_port )
  return
  if 54 - 54: i11iIiiIii % ooOoO0o % I1Ii111 + o0oOOo0O0Ooo
 if ( I11iI1i1 [ "type" ] == "decap-statistics" ) :
  lisp_process_data_plane_decap_stats ( I11iI1i1 , punt_socket )
  return
  if 2 - 2: IiII
  if 25 - 25: OoOoOO00 . OoO0O00 * o0oOOo0O0Ooo . OoooooooOO - Oo0Ooo + I1IiiI
  if 82 - 82: OoO0O00 - Ii1I * I11i * o0oOOo0O0Ooo
  if 17 - 17: OoooooooOO + I1Ii111
  if 91 - 91: iIii1I11I1II1 % i11iIiiIii - o0oOOo0O0Ooo
 if ( I11iI1i1 [ "type" ] == "restart" ) :
  lisp_process_data_plane_restart ( )
  return
  if 98 - 98: o0oOOo0O0Ooo % II111iiii * IiII - i11iIiiIii * oO0o
  if 15 - 15: O0 - II111iiii - Oo0Ooo . I1ii11iIi11i % OoO0O00
  if 63 - 63: o0oOOo0O0Ooo / OoOoOO00 % I1ii11iIi11i % I11i
  if 58 - 58: O0 + iII111i
  if 66 - 66: i1IIi . O0 . i1IIi - iIii1I11I1II1 - ooOoO0o % I1ii11iIi11i
 if ( I11iI1i1 [ "type" ] != "discovery" ) :
  lprint ( "Punt IPC message has wrong format" )
  return
  if 96 - 96: i1IIi + oO0o - OoOoOO00 - OoOoOO00
 if ( "interface" not in I11iI1i1 ) :
  lprint ( "Invalid punt message from {}, required keys missing" . format ( ooOO0O0O ) )
  if 13 - 13: I11i
  return
  if 52 - 52: iII111i . OoOoOO00 * iIii1I11I1II1 . iII111i * IiII
  if 52 - 52: iII111i + iII111i
  if 35 - 35: I1Ii111 * oO0o + Ii1I / I1IiiI + O0 - I11i
  if 42 - 42: o0oOOo0O0Ooo
  if 89 - 89: o0oOOo0O0Ooo
 ooOooO = I11iI1i1 [ "interface" ]
 if ( ooOooO == "" ) :
  i1I1iI = int ( I11iI1i1 [ "instance-id" ] )
  if ( i1I1iI == - 1 ) : return
 else :
  i1I1iI = lisp_get_interface_instance_id ( ooOooO , None )
  if 99 - 99: I1ii11iIi11i + Oo0Ooo
  if 20 - 20: OoO0O00 / iII111i
  if 62 - 62: i1IIi % iIii1I11I1II1 + OoOoOO00 - I1IiiI . I1ii11iIi11i
  if 92 - 92: i11iIiiIii * o0oOOo0O0Ooo . Oo0Ooo
  if 15 - 15: o0oOOo0O0Ooo * IiII . iII111i % O0 . iIii1I11I1II1
 oo0Oo = None
 if ( "source-eid" in I11iI1i1 ) :
  o0000 = I11iI1i1 [ "source-eid" ]
  oo0Oo = lisp_address ( LISP_AFI_NONE , o0000 , 0 , i1I1iI )
  if ( oo0Oo . is_null ( ) ) :
   lprint ( "Invalid source-EID format '{}'" . format ( o0000 ) )
   return
   if 34 - 34: OOooOOo / iII111i * iIii1I11I1II1 + i11iIiiIii
   if 37 - 37: I11i + o0oOOo0O0Ooo . o0oOOo0O0Ooo
 OoO0oO = None
 if ( "dest-eid" in I11iI1i1 ) :
  II11I1iiiIIII = I11iI1i1 [ "dest-eid" ]
  OoO0oO = lisp_address ( LISP_AFI_NONE , II11I1iiiIIII , 0 , i1I1iI )
  if ( OoO0oO . is_null ( ) ) :
   lprint ( "Invalid dest-EID format '{}'" . format ( II11I1iiiIIII ) )
   return
   if 19 - 19: IiII / OoooooooOO / OoO0O00 . OoooooooOO / I1IiiI / iII111i
   if 5 - 5: II111iiii + I1Ii111
   if 80 - 80: OOooOOo * I1IiiI + iII111i . OoOoOO00 % I1Ii111 % o0oOOo0O0Ooo
   if 20 - 20: ooOoO0o * OoooooooOO + IiII
   if 56 - 56: OOooOOo + II111iiii / II111iiii - I1ii11iIi11i - OoO0O00
   if 24 - 24: O0 / OoooooooOO % II111iiii
   if 88 - 88: iII111i / ooOoO0o % oO0o % I1ii11iIi11i - i1IIi
   if 21 - 21: OoOoOO00 % oO0o . OoooooooOO + IiII % OoOoOO00
 if ( oo0Oo ) :
  oOO = green ( oo0Oo . print_address ( ) , False )
  Iiii1II1 = lisp_db_for_lookups . lookup_cache ( oo0Oo , False )
  if ( Iiii1II1 != None ) :
   if 37 - 37: II111iiii
   if 48 - 48: ooOoO0o . i11iIiiIii
   if 67 - 67: OoO0O00 + Oo0Ooo + I1Ii111
   if 47 - 47: I11i . O0 / I11i . OOooOOo % I1IiiI
   if 54 - 54: i1IIi . iIii1I11I1II1 - I11i
   if ( Iiii1II1 . dynamic_eid_configured ( ) ) :
    oo = lisp_allow_dynamic_eid ( ooOooO , oo0Oo )
    if ( oo != None and lisp_i_am_itr ) :
     lisp_itr_discover_eid ( Iiii1II1 , oo0Oo , ooOooO , oo )
    else :
     lprint ( ( "Disallow dynamic source-EID {} " + "on interface {}" ) . format ( oOO , ooOooO ) )
     if 57 - 57: I1IiiI - i11iIiiIii - I1ii11iIi11i
     if 49 - 49: i1IIi . O0 % Ii1I * i1IIi
     if 39 - 39: I1ii11iIi11i
  else :
   lprint ( "Punt from non-EID source {}" . format ( oOO ) )
   if 74 - 74: II111iiii % oO0o * Oo0Ooo / iIii1I11I1II1
   if 81 - 81: II111iiii + OoOoOO00 * O0
   if 64 - 64: iIii1I11I1II1 * Ii1I
   if 5 - 5: I11i . I11i / i1IIi - o0oOOo0O0Ooo % Oo0Ooo
   if 85 - 85: OOooOOo
   if 32 - 32: iII111i
 if ( OoO0oO ) :
  IIII1 = lisp_map_cache_lookup ( oo0Oo , OoO0oO )
  if ( IIII1 == None or lisp_mr_or_pubsub ( IIII1 . action ) ) :
   if 27 - 27: iIii1I11I1II1 - iII111i
   if 68 - 68: oO0o + OoooooooOO - i1IIi * OoOoOO00 % Oo0Ooo
   if 19 - 19: IiII * Oo0Ooo + I1IiiI * I1Ii111 % iIii1I11I1II1
   if 15 - 15: II111iiii % OoO0O00 % Oo0Ooo + I1Ii111
   if 54 - 54: I1Ii111 + OOooOOo
   if ( lisp_rate_limit_map_request ( OoO0oO ) ) : return
   if 6 - 6: Ii1I
   I1IIIi = ( IIII1 and IIII1 . action == LISP_SEND_PUBSUB_ACTION )
   lisp_send_map_request ( lisp_send_sockets , lisp_ephem_port ,
 oo0Oo , OoO0oO , None , I1IIIi )
  else :
   oOO = green ( OoO0oO . print_address ( ) , False )
   lprint ( "Map-cache entry for {} already exists" . format ( oOO ) )
   if 8 - 8: OoO0O00
   if 91 - 91: Ii1I
 return
 if 12 - 12: OoooooooOO + i11iIiiIii
 if 63 - 63: OOooOOo . i11iIiiIii
 if 50 - 50: IiII % i11iIiiIii - iII111i . OoOoOO00 / Oo0Ooo
 if 30 - 30: Oo0Ooo . II111iiii + OoooooooOO % OoO0O00 * ooOoO0o * iIii1I11I1II1
 if 91 - 91: OoooooooOO
 if 86 - 86: iII111i / OoooooooOO - I1ii11iIi11i
 if 63 - 63: ooOoO0o % Ii1I * I1IiiI
def lisp_ipc_map_cache_entry ( mc , jdata ) :
 I1I11i = lisp_write_ipc_map_cache ( True , mc , dont_send = True )
 jdata . append ( I1I11i )
 return ( [ True , jdata ] )
 if 48 - 48: iII111i - iII111i - o0oOOo0O0Ooo + ooOoO0o - o0oOOo0O0Ooo / Ii1I
 if 43 - 43: I1IiiI + Ii1I
 if 37 - 37: OoOoOO00 - OoooooooOO . ooOoO0o - IiII % iIii1I11I1II1 . iIii1I11I1II1
 if 64 - 64: OoOoOO00 + iII111i % I1Ii111 - OOooOOo + O0
 if 83 - 83: I1Ii111 + I1Ii111
 if 43 - 43: oO0o * i1IIi * Ii1I . iIii1I11I1II1 % o0oOOo0O0Ooo
 if 97 - 97: I1IiiI . i1IIi * OoOoOO00 / OOooOOo
 if 50 - 50: II111iiii . OoO0O00
def lisp_ipc_walk_map_cache ( mc , jdata ) :
 if 60 - 60: I11i . iIii1I11I1II1
 if 41 - 41: II111iiii / I1IiiI
 if 2 - 2: IiII / OoOoOO00 + I11i
 if 3 - 3: OoooooooOO + Oo0Ooo + OOooOOo
 if ( mc . group . is_null ( ) ) : return ( lisp_ipc_map_cache_entry ( mc , jdata ) )
 if 20 - 20: Ii1I - oO0o - OoO0O00 + I1ii11iIi11i % OoO0O00 . i1IIi
 if ( mc . source_cache == None ) : return ( [ True , jdata ] )
 if 2 - 2: ooOoO0o * IiII . Ii1I
 if 69 - 69: IiII % i1IIi
 if 17 - 17: o0oOOo0O0Ooo . OoO0O00 * ooOoO0o * II111iiii - OoooooooOO % iII111i
 if 47 - 47: I1IiiI * iIii1I11I1II1 - I11i - o0oOOo0O0Ooo
 if 47 - 47: IiII + OoO0O00 % ooOoO0o - iII111i - IiII - oO0o
 jdata = mc . source_cache . walk_cache ( lisp_ipc_map_cache_entry , jdata )
 return ( [ True , jdata ] )
 if 63 - 63: OoooooooOO / I1Ii111
 if 90 - 90: I1Ii111 . i11iIiiIii - iIii1I11I1II1 + I1Ii111
 if 67 - 67: IiII - I1ii11iIi11i + ooOoO0o . iIii1I11I1II1 . IiII
 if 13 - 13: I1IiiI / i11iIiiIii % iIii1I11I1II1 - Oo0Ooo . i11iIiiIii + I1IiiI
 if 77 - 77: o0oOOo0O0Ooo / II111iiii + i11iIiiIii % Ii1I . iIii1I11I1II1
 if 66 - 66: iII111i / oO0o - OoO0O00 . Oo0Ooo
 if 31 - 31: IiII % O0
def lisp_itr_discover_eid ( db , eid , input_interface , routed_interface ,
 lisp_ipc_listen_socket ) :
 oOOoo = eid . print_address ( )
 if ( oOOoo in db . dynamic_eids ) :
  db . dynamic_eids [ oOOoo ] . last_packet = lisp_get_timestamp ( )
  return
  if 46 - 46: iIii1I11I1II1 - OoooooooOO . oO0o % iIii1I11I1II1 / i1IIi + Ii1I
  if 5 - 5: I1ii11iIi11i % II111iiii
  if 17 - 17: i11iIiiIii - II111iiii / O0 % OoO0O00 . Oo0Ooo + IiII
  if 60 - 60: I11i % I1IiiI
  if 99 - 99: oO0o . OOooOOo % iII111i * Ii1I
 iIi1Iii1 = lisp_dynamic_eid ( )
 iIi1Iii1 . dynamic_eid . copy_address ( eid )
 iIi1Iii1 . interface = routed_interface
 iIi1Iii1 . last_packet = lisp_get_timestamp ( )
 iIi1Iii1 . get_timeout ( routed_interface )
 db . dynamic_eids [ oOOoo ] = iIi1Iii1
 if 98 - 98: Oo0Ooo * O0 + i1IIi
 ii1IiiI1Ii = ""
 if ( input_interface != routed_interface ) :
  ii1IiiI1Ii = ", routed-interface " + routed_interface
  if 83 - 83: Oo0Ooo . Ii1I + i11iIiiIii % O0 . I1IiiI / OoOoOO00
  if 96 - 96: i1IIi / Ii1I / iIii1I11I1II1
 iIIOO0O00o0 = green ( oOOoo , False ) + bold ( " discovered" , False )
 lprint ( "Dynamic-EID {} on interface {}{}, timeout {}" . format ( iIIOO0O00o0 , input_interface , ii1IiiI1Ii , iIi1Iii1 . timeout ) )
 if 78 - 78: iII111i
 if 44 - 44: oO0o / II111iiii
 if 97 - 97: O0
 if 6 - 6: Ii1I % OoooooooOO % IiII / iIii1I11I1II1
 if 71 - 71: Ii1I % OoooooooOO / II111iiii . o0oOOo0O0Ooo
 ooo0ooo0Oo = "learn%{}%{}" . format ( oOOoo , routed_interface )
 ooo0ooo0Oo = lisp_command_ipc ( ooo0ooo0Oo , "lisp-itr" )
 lisp_ipc ( ooo0ooo0Oo , lisp_ipc_listen_socket , "lisp-etr" )
 return
 if 7 - 7: IiII . ooOoO0o
 if 56 - 56: OoooooooOO / I11i % OoO0O00
 if 22 - 22: OoOoOO00 . I1ii11iIi11i * OoooooooOO
 if 66 - 66: I1Ii111
 if 90 - 90: ooOoO0o . Ii1I % i11iIiiIii + iII111i * iII111i / Oo0Ooo
 if 68 - 68: oO0o
 if 42 - 42: OoOoOO00
 if 40 - 40: IiII % OoOoOO00 * oO0o / iII111i + OOooOOo
 if 27 - 27: Ii1I / o0oOOo0O0Ooo % I11i
def lisp_itr_nat_probe ( rloc , rloc_name , lisp_ipc_listen_socket ) :
 I1I111i = rloc . print_address_no_iid ( )
 if 96 - 96: i11iIiiIii % O0
 if 11 - 11: II111iiii . i11iIiiIii % ooOoO0o * Ii1I * OoOoOO00 * OoooooooOO
 if 80 - 80: OoO0O00
 if 55 - 55: iIii1I11I1II1 % OoO0O00 / II111iiii - OoO0O00
 ooo0ooo0Oo = "nat%{}%{}" . format ( I1I111i , rloc_name )
 ooo0ooo0Oo = lisp_command_ipc ( ooo0ooo0Oo , "lisp-itr" )
 lisp_ipc ( ooo0ooo0Oo , lisp_ipc_listen_socket , "lisp-etr" )
 return
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
def lisp_retry_decap_keys ( addr_str , packet , iv , packet_icv ) :
 if ( lisp_search_decap_keys == False ) : return
 if 82 - 82: iIii1I11I1II1 - iII111i % I1IiiI + I1IiiI * i1IIi % O0
 if 63 - 63: I1IiiI + OoOoOO00
 if 55 - 55: o0oOOo0O0Ooo
 if 95 - 95: OoO0O00 * ooOoO0o * oO0o % Oo0Ooo
 if ( addr_str . find ( ":" ) != - 1 ) : return
 if 36 - 36: I1IiiI - Ii1I + oO0o . iIii1I11I1II1
 ooOOoo0o = lisp_crypto_keys_by_rloc_decap [ addr_str ]
 if 47 - 47: Ii1I
 for I1IIiiI1II in lisp_crypto_keys_by_rloc_decap :
  if 12 - 12: I1IiiI / IiII + OoOoOO00 . I1Ii111 / I1Ii111
  if 97 - 97: OOooOOo - iII111i . I1IiiI * oO0o . OoOoOO00 * IiII
  if 29 - 29: iIii1I11I1II1
  if 94 - 94: Ii1I - i11iIiiIii % O0 + Ii1I / O0 % I11i
  if ( I1IIiiI1II . find ( addr_str ) == - 1 ) : continue
  if 42 - 42: I1ii11iIi11i . iIii1I11I1II1 % I11i
  if 54 - 54: OoOoOO00 / Ii1I
  if 84 - 84: Oo0Ooo / OoO0O00 . o0oOOo0O0Ooo - iII111i . iII111i - II111iiii
  if 99 - 99: I1Ii111 % Oo0Ooo
  if ( I1IIiiI1II == addr_str ) : continue
  if 61 - 61: OoooooooOO % i11iIiiIii + OOooOOo
  if 53 - 53: iII111i . iIii1I11I1II1
  if 59 - 59: II111iiii . II111iiii - iII111i
  if 46 - 46: oO0o / iIii1I11I1II1 + OoO0O00
  I1I11i = lisp_crypto_keys_by_rloc_decap [ I1IIiiI1II ]
  if ( I1I11i == ooOOoo0o ) : continue
  if 33 - 33: Ii1I . iIii1I11I1II1 . O0 * I1ii11iIi11i . OoOoOO00 / i11iIiiIii
  if 85 - 85: iII111i
  if 23 - 23: O0
  if 83 - 83: i11iIiiIii % OoooooooOO
  iI1111 = I1I11i [ 1 ]
  if ( packet_icv != iI1111 . do_icv ( packet , iv ) ) :
   lprint ( "Test ICV with key {} failed" . format ( red ( I1IIiiI1II , False ) ) )
   continue
   if 9 - 9: i1IIi
   if 88 - 88: I1ii11iIi11i + i1IIi
  lprint ( "Changing decap crypto key to {}" . format ( red ( I1IIiiI1II , False ) ) )
  lisp_crypto_keys_by_rloc_decap [ addr_str ] = I1I11i
  if 56 - 56: Oo0Ooo - i1IIi
 return
 if 7 - 7: IiII . oO0o + oO0o . Ii1I . OoooooooOO * o0oOOo0O0Ooo
 if 25 - 25: o0oOOo0O0Ooo % ooOoO0o
 if 91 - 91: I1Ii111 * i11iIiiIii / o0oOOo0O0Ooo * oO0o - o0oOOo0O0Ooo * OOooOOo
 if 2 - 2: i1IIi - OoOoOO00 / iII111i
 if 70 - 70: IiII / O0 - i1IIi
 if 23 - 23: OoOoOO00
 if 2 - 2: II111iiii * OoOoOO00 . iIii1I11I1II1 . ooOoO0o . ooOoO0o + iII111i
 if 60 - 60: I1ii11iIi11i / I1ii11iIi11i
def lisp_decent_pull_xtr_configured ( ) :
 return ( lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None )
 if 44 - 44: i11iIiiIii / ooOoO0o - iIii1I11I1II1 + OoO0O00
 if 62 - 62: i1IIi / I1Ii111 + ooOoO0o
 if 80 - 80: iII111i + OoO0O00 % OoO0O00
 if 4 - 4: OoOoOO00 * I11i * O0 . OoooooooOO + Ii1I % i1IIi
 if 11 - 11: OoOoOO00 % i11iIiiIii . OoOoOO00 % Oo0Ooo * Ii1I
 if 67 - 67: IiII - OoOoOO00 / I1Ii111 % oO0o % OOooOOo
 if 19 - 19: OoO0O00 - iII111i
 if 76 - 76: OoOoOO00 * ooOoO0o - iII111i * I1IiiI + I11i
def lisp_is_decent_dns_suffix ( dns_name ) :
 if ( lisp_decent_dns_suffix == None ) : return ( False )
 IIiIii1 = dns_name . split ( "." )
 IIiIii1 = "." . join ( IIiIii1 [ 1 : : ] )
 return ( IIiIii1 == lisp_decent_dns_suffix )
 if 4 - 4: Oo0Ooo
 if 95 - 95: Oo0Ooo * i11iIiiIii - O0
 if 100 - 100: iIii1I11I1II1 / I1ii11iIi11i - o0oOOo0O0Ooo / iII111i
 if 73 - 73: OoooooooOO
 if 68 - 68: II111iiii / i11iIiiIii % i11iIiiIii % OoooooooOO
 if 81 - 81: i1IIi + O0 . IiII . I1IiiI / ooOoO0o
 if 75 - 75: I1ii11iIi11i / OoOoOO00
 if 59 - 59: OoO0O00 . OoooooooOO % IiII
 if 35 - 35: I1ii11iIi11i + I1Ii111
 if 25 - 25: iIii1I11I1II1 / I11i % OoooooooOO / Oo0Ooo
def lisp_get_decent_eid_string ( eid ) :
 oOOoo = eid . print_prefix ( )
 if 4 - 4: i1IIi % i1IIi % oO0o
 oOoO0OoOOooo = None
 O0OoO = 0
 for iI1I , o0ooO0oooO0 in lisp_decent_lookup_prefixes . items ( ) :
  if ( eid . is_more_specific ( iI1I ) ) :
   if ( oOoO0OoOOooo == None or iI1I . mask_len > O0OoO ) :
    O0OoO = iI1I . mask_len
    oOoO0OoOOooo = o0ooO0oooO0
    if 47 - 47: IiII % II111iiii + i1IIi . IiII
    if 93 - 93: O0
    if 41 - 41: OoooooooOO . OoO0O00
    if 69 - 69: O0 * I1ii11iIi11i
    if 53 - 53: iIii1I11I1II1 . Ii1I / Ii1I % I1ii11iIi11i % I1Ii111
    if 13 - 13: I11i + O0 * oO0o - II111iiii
    if 4 - 4: I11i
 if ( oOoO0OoOOooo == None ) : return ( oOOoo )
 if 5 - 5: Oo0Ooo - iII111i % iIii1I11I1II1 * OoOoOO00
 if 41 - 41: i1IIi * IiII - i11iIiiIii / O0 + Oo0Ooo + ooOoO0o
 if 94 - 94: OoO0O00 . O0 + iIii1I11I1II1 . oO0o % oO0o
 if 7 - 7: I1ii11iIi11i * oO0o / OoOoOO00
 OO0O = copy . deepcopy ( eid )
 OO0O . mask_len = oOoO0OoOOooo
 OO0O . zero_host_bits ( )
 return ( OO0O . print_prefix ( ) )
 if 64 - 64: I1ii11iIi11i . OoOoOO00 - i11iIiiIii . Ii1I * i1IIi
 if 4 - 4: OoooooooOO - OoOoOO00
 if 96 - 96: I1ii11iIi11i
 if 72 - 72: ooOoO0o - I1Ii111 - iIii1I11I1II1 . I1IiiI
 if 77 - 77: Oo0Ooo * OoO0O00
 if 67 - 67: OoOoOO00 . I1Ii111 / I1IiiI * II111iiii
 if 45 - 45: I1ii11iIi11i * o0oOOo0O0Ooo . iIii1I11I1II1 * Oo0Ooo
 if 58 - 58: OOooOOo + O0
 if 19 - 19: o0oOOo0O0Ooo
 if 8 - 8: OOooOOo * OOooOOo - Ii1I * OoOoOO00 % OoO0O00 * O0
 if 70 - 70: I1IiiI
def lisp_get_decent_index ( eid ) :
 if 17 - 17: I11i % OOooOOo - i11iIiiIii . OoooooooOO % OoO0O00 + OoO0O00
 if 24 - 24: Ii1I . OOooOOo . IiII / Oo0Ooo . Oo0Ooo . II111iiii
 if 63 - 63: ooOoO0o . I11i
 if 39 - 39: II111iiii % oO0o % I1IiiI - iIii1I11I1II1 / I1IiiI
 if 94 - 94: iII111i + oO0o
 oOOoo = lisp_get_decent_eid_string ( eid )
 oOO = oOOoo . encode ( )
 iiiiii = hmac . new ( b"lisp-decent" , oOO , hashlib . sha256 ) . hexdigest ( )
 if 30 - 30: OOooOOo - I1ii11iIi11i * iIii1I11I1II1 + Oo0Ooo
 if 25 - 25: IiII
 if 78 - 78: OoOoOO00 * iIii1I11I1II1 * ooOoO0o - OoooooooOO - IiII
 if 40 - 40: OoO0O00 . i11iIiiIii + ooOoO0o
 I1o00OooOO0 = os . getenv ( "LISP_DECENT_HASH_WIDTH" )
 if ( I1o00OooOO0 in [ "" , None ] ) :
  I1o00OooOO0 = 12
 else :
  I1o00OooOO0 = int ( I1o00OooOO0 )
  if ( I1o00OooOO0 > 32 ) :
   I1o00OooOO0 = 12
  else :
   I1o00OooOO0 *= 2
   if 28 - 28: I1ii11iIi11i . o0oOOo0O0Ooo . i1IIi
   if 13 - 13: Ii1I * i1IIi
   if 34 - 34: o0oOOo0O0Ooo / oO0o . OOooOOo - O0 + O0 . I1IiiI
 i11IiIIiiI1I = iiiiii [ 0 : I1o00OooOO0 ]
 o00O = int ( i11IiIIiiI1I , 16 ) % lisp_decent_modulus
 if 19 - 19: O0
 lprint ( "LISP-Decent modulus {}, hash-width {}, mod-value {}, index {} for {}" . format ( lisp_decent_modulus , old_div ( I1o00OooOO0 , 2 ) , i11IiIIiiI1I , o00O , oOOoo ) )
 if 60 - 60: I1ii11iIi11i * I1ii11iIi11i + I1Ii111 + o0oOOo0O0Ooo - OoO0O00
 if 75 - 75: o0oOOo0O0Ooo + i11iIiiIii % I1ii11iIi11i
 return ( o00O )
 if 45 - 45: I1Ii111 % Ii1I . ooOoO0o
 if 99 - 99: I11i - OoOoOO00 % I11i / i1IIi
 if 55 - 55: o0oOOo0O0Ooo / ooOoO0o % I1IiiI / I1Ii111
 if 30 - 30: I11i % OoOoOO00 * O0
 if 32 - 32: iII111i - Oo0Ooo / Oo0Ooo + o0oOOo0O0Ooo + Ii1I + IiII
 if 100 - 100: Oo0Ooo + o0oOOo0O0Ooo % Oo0Ooo
 if 73 - 73: o0oOOo0O0Ooo + Ii1I
def lisp_get_decent_dns_name ( eid ) :
 o00O = lisp_get_decent_index ( eid )
 return ( str ( o00O ) + "." + lisp_decent_dns_suffix )
 if 62 - 62: OOooOOo
 if 91 - 91: iII111i . Ii1I - OoooooooOO / Ii1I / II111iiii - O0
 if 67 - 67: oO0o * i11iIiiIii / I1ii11iIi11i . I11i % OOooOOo
 if 75 - 75: ooOoO0o - OOooOOo
 if 97 - 97: i11iIiiIii / I11i % II111iiii
 if 20 - 20: I1Ii111 + OoooooooOO . o0oOOo0O0Ooo - ooOoO0o
 if 61 - 61: i11iIiiIii + OoooooooOO
 if 7 - 7: I1IiiI * OoO0O00 * I1IiiI
def lisp_get_decent_dns_name_from_str ( iid , eid_str ) :
 Ooo0O = lisp_address ( LISP_AFI_NONE , eid_str , 0 , iid )
 o00O = lisp_get_decent_index ( Ooo0O )
 return ( str ( o00O ) + "." + lisp_decent_dns_suffix )
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
def lisp_trace_append ( packet , reason = None , ed = "encap" , lisp_socket = None ,
 rloc_entry = None ) :
 if 35 - 35: i1IIi
 II1Ii = 28 if packet . inner_version == 4 else 48
 O0o000OOO = packet . packet [ II1Ii : : ]
 O0oii1III1II1 = lisp_trace ( )
 if ( O0oii1III1II1 . decode ( O0o000OOO ) == False ) :
  lprint ( "Could not decode JSON portion of a LISP-Trace packet" )
  return ( False )
  if 89 - 89: IiII / OoooooooOO
  if 13 - 13: II111iiii . OOooOOo - O0 * oO0o
 O0O0OOo0Oo = "?" if packet . outer_dest . is_null ( ) else packet . outer_dest . print_address_no_iid ( )
 if 35 - 35: I1ii11iIi11i - OoO0O00 + o0oOOo0O0Ooo * I1IiiI * I11i + Ii1I
 if 14 - 14: i11iIiiIii . o0oOOo0O0Ooo
 if 94 - 94: I1ii11iIi11i * i11iIiiIii
 if 95 - 95: OoooooooOO - II111iiii . I1Ii111
 if 97 - 97: i1IIi * iIii1I11I1II1
 if 44 - 44: O0 - o0oOOo0O0Ooo - I1Ii111 % O0
 if ( O0O0OOo0Oo != "?" and packet . encap_port != LISP_DATA_PORT ) :
  if ( ed == "encap" ) : O0O0OOo0Oo += ":{}" . format ( packet . encap_port )
  if 31 - 31: i11iIiiIii - I11i
  if 91 - 91: I11i - iII111i
  if 35 - 35: I1IiiI * I11i + I11i
  if 67 - 67: I1ii11iIi11i - I1IiiI + Ii1I * Ii1I + Oo0Ooo
  if 41 - 41: i11iIiiIii
 I1I11i = { }
 I1I11i [ "n" ] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else "RTR" if lisp_i_am_rtr else "?"
 if 97 - 97: i1IIi / Ii1I / ooOoO0o . Ii1I - ooOoO0o + oO0o
 i1i1iiiI1iI = packet . outer_source
 if ( i1i1iiiI1iI . is_null ( ) ) : i1i1iiiI1iI = lisp_myrlocs [ 0 ]
 I1I11i [ "sr" ] = i1i1iiiI1iI . print_address_no_iid ( )
 if 90 - 90: I1IiiI - OoO0O00
 if 50 - 50: iII111i / I11i - OoO0O00
 if 70 - 70: I1Ii111 + iII111i % Oo0Ooo + I11i
 if 36 - 36: oO0o + I1IiiI
 if 44 - 44: Oo0Ooo / OoOoOO00 % O0
 if ( I1I11i [ "n" ] == "ITR" and packet . inner_sport != LISP_TRACE_PORT ) :
  I1I11i [ "sr" ] += ":{}" . format ( packet . inner_sport )
  if 35 - 35: ooOoO0o % oO0o
  if 41 - 41: Ii1I + I1IiiI
 I1I11i [ "hn" ] = lisp_hostname
 I1IIiiI1II = ed [ 0 ] + "ts"
 I1I11i [ I1IIiiI1II ] = lisp_get_timestamp ( )
 if 94 - 94: iIii1I11I1II1 + IiII * iIii1I11I1II1 % IiII + I1Ii111
 if 1 - 1: i11iIiiIii * iIii1I11I1II1 - OoOoOO00 % OoO0O00 - oO0o
 if 30 - 30: iIii1I11I1II1 / OOooOOo % Oo0Ooo - OoooooooOO
 if 74 - 74: I1ii11iIi11i . iII111i
 if 69 - 69: ooOoO0o * II111iiii + i11iIiiIii / oO0o + I1Ii111 - OOooOOo
 if 84 - 84: O0
 if ( O0O0OOo0Oo == "?" and I1I11i [ "n" ] == "ETR" ) :
  Iiii1II1 = lisp_db_for_lookups . lookup_cache ( packet . inner_dest , False )
  if ( Iiii1II1 != None and len ( Iiii1II1 . rloc_set ) >= 1 ) :
   O0O0OOo0Oo = Iiii1II1 . rloc_set [ 0 ] . rloc . print_address_no_iid ( )
   if 29 - 29: I11i + o0oOOo0O0Ooo . ooOoO0o * I1Ii111 - o0oOOo0O0Ooo * O0
   if 58 - 58: iII111i . oO0o + i11iIiiIii
 I1I11i [ "dr" ] = O0O0OOo0Oo
 if 2 - 2: OOooOOo * Ii1I
 if 17 - 17: I1ii11iIi11i * O0 / OoOoOO00 + i1IIi
 if 71 - 71: oO0o % IiII
 if 77 - 77: i1IIi * o0oOOo0O0Ooo - Oo0Ooo / I1Ii111 - Ii1I * IiII
 if ( O0O0OOo0Oo == "?" and reason != None ) :
  I1I11i [ "dr" ] += " ({})" . format ( reason )
  if 51 - 51: OoO0O00 * IiII
  if 36 - 36: II111iiii + I11i - O0
  if 24 - 24: I1Ii111 / OoOoOO00
  if 10 - 10: I11i . OoO0O00 / O0 / oO0o / o0oOOo0O0Ooo / ooOoO0o
  if 30 - 30: Oo0Ooo
 if ( rloc_entry != None ) :
  I1I11i [ "rtts" ] = rloc_entry . recent_rloc_probe_rtts
  I1I11i [ "hops" ] = rloc_entry . recent_rloc_probe_hops
  I1I11i [ "lats" ] = rloc_entry . recent_rloc_probe_latencies
  if 93 - 93: II111iiii - I1IiiI
  if 80 - 80: I11i . o0oOOo0O0Ooo % IiII - OoOoOO00 % OOooOOo / OoooooooOO
  if 57 - 57: OoooooooOO % o0oOOo0O0Ooo - iIii1I11I1II1 . OoooooooOO
  if 42 - 42: o0oOOo0O0Ooo % OoooooooOO * OoO0O00 - o0oOOo0O0Ooo
  if 83 - 83: i1IIi . i1IIi * ooOoO0o
  if 26 - 26: I1IiiI - IiII
 oo0Oo = packet . inner_source . print_address ( )
 OoO0oO = packet . inner_dest . print_address ( )
 if ( O0oii1III1II1 . packet_json == [ ] ) :
  OOiiIi = { }
  OOiiIi [ "se" ] = oo0Oo
  OOiiIi [ "de" ] = OoO0oO
  OOiiIi [ "paths" ] = [ ]
  O0oii1III1II1 . packet_json . append ( OOiiIi )
  if 99 - 99: IiII * iII111i + i1IIi * I1Ii111
  if 88 - 88: o0oOOo0O0Ooo . IiII - Oo0Ooo
  if 24 - 24: Oo0Ooo - OOooOOo / Ii1I / II111iiii . Oo0Ooo - Ii1I
  if 5 - 5: IiII
  if 66 - 66: OoO0O00 . I1ii11iIi11i . OoooooooOO
  if 21 - 21: I11i / IiII + i1IIi . Oo0Ooo % II111iiii
 for OOiiIi in O0oii1III1II1 . packet_json :
  if ( OOiiIi [ "de" ] != OoO0oO ) : continue
  OOiiIi [ "paths" ] . append ( I1I11i )
  break
  if 8 - 8: oO0o / iIii1I11I1II1 + OoooooooOO
  if 11 - 11: OOooOOo . O0 + IiII . i1IIi
  if 81 - 81: OoO0O00 - I11i - OoO0O00 + oO0o
  if 20 - 20: OoooooooOO - Oo0Ooo + I1Ii111 + OoooooooOO
  if 66 - 66: I1ii11iIi11i / oO0o % IiII + II111iiii % iII111i
  if 54 - 54: iII111i * O0 / I1IiiI % Ii1I
  if 12 - 12: IiII % I1IiiI - o0oOOo0O0Ooo - I1ii11iIi11i - i11iIiiIii * i1IIi
  if 96 - 96: II111iiii % o0oOOo0O0Ooo % oO0o * ooOoO0o
 o00OOO0O0o0 = False
 if ( len ( O0oii1III1II1 . packet_json ) == 1 and I1I11i [ "n" ] == "ETR" and
 O0oii1III1II1 . myeid ( packet . inner_dest ) ) :
  OOiiIi = { }
  OOiiIi [ "se" ] = OoO0oO
  OOiiIi [ "de" ] = oo0Oo
  OOiiIi [ "paths" ] = [ ]
  O0oii1III1II1 . packet_json . append ( OOiiIi )
  o00OOO0O0o0 = True
  if 89 - 89: I1ii11iIi11i % Ii1I % I1ii11iIi11i . Ii1I . O0
  if 9 - 9: OoOoOO00 / iIii1I11I1II1 * I1Ii111 / i1IIi * i11iIiiIii - IiII
  if 49 - 49: Ii1I
  if 37 - 37: i1IIi % iII111i + OOooOOo - OoO0O00 - i11iIiiIii / oO0o
  if 8 - 8: I11i / OoooooooOO % OoooooooOO . Oo0Ooo
  if 30 - 30: iII111i
 O0oii1III1II1 . print_trace ( )
 O0o000OOO = O0oii1III1II1 . encode ( )
 if 25 - 25: I11i % i1IIi + OOooOOo * Ii1I . i1IIi
 if 81 - 81: I11i % OoOoOO00 . Ii1I
 if 82 - 82: i1IIi / II111iiii
 if 40 - 40: II111iiii - I1Ii111 + Oo0Ooo / IiII
 if 15 - 15: I1Ii111 + ooOoO0o / II111iiii . OoOoOO00 - I1Ii111
 if 59 - 59: Ii1I * iIii1I11I1II1 - iIii1I11I1II1 % I1Ii111 - OoO0O00 / I1IiiI
 if 89 - 89: I1Ii111 . OoO0O00
 if 52 - 52: OoO0O00 - iIii1I11I1II1
 O00o00o = O0oii1III1II1 . packet_json [ 0 ] [ "paths" ] [ 0 ] [ "sr" ]
 if ( O0O0OOo0Oo == "?" ) :
  lprint ( "LISP-Trace return to sender RLOC {}" . format ( O00o00o ) )
  O0oii1III1II1 . return_to_sender ( lisp_socket , O00o00o , O0o000OOO )
  return ( False )
  if 19 - 19: O0 % iII111i . OOooOOo . OoooooooOO - OoOoOO00 / oO0o
  if 42 - 42: i11iIiiIii * I1IiiI % OoOoOO00 + Oo0Ooo . OOooOOo
  if 74 - 74: i1IIi . Ii1I * I1Ii111
  if 44 - 44: O0 * O0 - II111iiii . II111iiii + OoO0O00
  if 47 - 47: I1Ii111
  if 96 - 96: I1Ii111 / Ii1I - I1IiiI
 oOoO0Oo0 = O0oii1III1II1 . packet_length ( )
 if 44 - 44: Oo0Ooo . OoOoOO00
 if 17 - 17: I1IiiI / OoO0O00 - iIii1I11I1II1
 if 91 - 91: iII111i / I1ii11iIi11i
 if 19 - 19: iIii1I11I1II1
 if 3 - 3: i11iIiiIii + Ii1I / I1Ii111
 if 74 - 74: II111iiii + I11i
 o0oooI1IiI = packet . packet [ 0 : II1Ii ]
 I1i1I = struct . pack ( "HH" , socket . htons ( oOoO0Oo0 ) , 0 )
 o0oooI1IiI = o0oooI1IiI [ 0 : II1Ii - 4 ] + I1i1I
 if ( packet . inner_version == 6 and I1I11i [ "n" ] == "ETR" and
 len ( O0oii1III1II1 . packet_json ) == 2 ) :
  ii11 = o0oooI1IiI [ II1Ii - 8 : : ] + O0o000OOO
  ii11 = lisp_udp_checksum ( oo0Oo , OoO0oO , ii11 )
  o0oooI1IiI = o0oooI1IiI [ 0 : II1Ii - 8 ] + ii11 [ 0 : 8 ]
  if 78 - 78: OoOoOO00 + OoO0O00 * I1IiiI / i1IIi
  if 26 - 26: OOooOOo * i11iIiiIii % O0 * o0oOOo0O0Ooo
  if 93 - 93: iII111i * i11iIiiIii + OoOoOO00
  if 20 - 20: i1IIi % Ii1I / iIii1I11I1II1 / II111iiii
  if 16 - 16: I1IiiI % Ii1I
  if 30 - 30: i11iIiiIii / i1IIi % O0 - OoooooooOO - OOooOOo
  if 55 - 55: OoooooooOO % ooOoO0o % I1Ii111 - Oo0Ooo % OoooooooOO . I11i
  if 22 - 22: i11iIiiIii
  if 39 - 39: oO0o / OoOoOO00 % iIii1I11I1II1 - OoOoOO00
 if ( o00OOO0O0o0 ) :
  if ( packet . inner_version == 4 ) :
   o0oooI1IiI = o0oooI1IiI [ 0 : 12 ] + o0oooI1IiI [ 16 : 20 ] + o0oooI1IiI [ 12 : 16 ] + o0oooI1IiI [ 22 : 24 ] + o0oooI1IiI [ 20 : 22 ] + o0oooI1IiI [ 24 : : ]
   if 29 - 29: I1ii11iIi11i - I11i . I1ii11iIi11i - o0oOOo0O0Ooo - OoooooooOO % OoO0O00
  else :
   o0oooI1IiI = o0oooI1IiI [ 0 : 8 ] + o0oooI1IiI [ 24 : 40 ] + o0oooI1IiI [ 8 : 24 ] + o0oooI1IiI [ 42 : 44 ] + o0oooI1IiI [ 40 : 42 ] + o0oooI1IiI [ 44 : : ]
   if 74 - 74: iIii1I11I1II1 / iII111i * OoO0O00 * iIii1I11I1II1 + i11iIiiIii
   if 90 - 90: II111iiii - oO0o - oO0o + I1IiiI
  oooOo = packet . inner_dest
  packet . inner_dest = packet . inner_source
  packet . inner_source = oooOo
  if 36 - 36: OoooooooOO % OoooooooOO / OoO0O00 * I1IiiI
  if 55 - 55: O0 - O0
  if 32 - 32: I1IiiI + o0oOOo0O0Ooo + Oo0Ooo / OoO0O00 . I11i . Oo0Ooo
  if 32 - 32: I1Ii111 / i1IIi
  if 30 - 30: i11iIiiIii . II111iiii * Oo0Ooo + II111iiii - I1IiiI
  if 80 - 80: o0oOOo0O0Ooo - iII111i % i11iIiiIii % i11iIiiIii % OoooooooOO - IiII
  if 39 - 39: II111iiii / I1Ii111 + OoooooooOO + IiII + iIii1I11I1II1
 II1Ii = 2 if packet . inner_version == 4 else 4
 oOoo0 = 20 + oOoO0Oo0 if packet . inner_version == 4 else oOoO0Oo0
 i1IIIiI1I = struct . pack ( "H" , socket . htons ( oOoo0 ) )
 o0oooI1IiI = o0oooI1IiI [ 0 : II1Ii ] + i1IIIiI1I + o0oooI1IiI [ II1Ii + 2 : : ]
 if 90 - 90: II111iiii
 if 77 - 77: i11iIiiIii . i11iIiiIii - iIii1I11I1II1 + OOooOOo
 if 55 - 55: OoO0O00 + Oo0Ooo
 if 74 - 74: i1IIi - I11i - oO0o % I1IiiI
 if ( packet . inner_version == 4 ) :
  iiIi1iIiI = struct . pack ( "H" , 0 )
  o0oooI1IiI = o0oooI1IiI [ 0 : 10 ] + iiIi1iIiI + o0oooI1IiI [ 12 : : ]
  i1IIIiI1I = lisp_ip_checksum ( o0oooI1IiI [ 0 : 20 ] )
  o0oooI1IiI = i1IIIiI1I + o0oooI1IiI [ 20 : : ]
  if 57 - 57: Oo0Ooo / II111iiii + OoOoOO00
  if 67 - 67: IiII * IiII % oO0o - IiII * i11iIiiIii - i11iIiiIii
  if 27 - 27: i1IIi
  if 29 - 29: OOooOOo % I11i * Oo0Ooo
  if 92 - 92: OoOoOO00 / OoooooooOO % OoooooooOO + o0oOOo0O0Ooo
 packet . packet = o0oooI1IiI + O0o000OOO
 return ( True )
 if 91 - 91: OoOoOO00 - iII111i / iII111i - OoO0O00
 if 97 - 97: Oo0Ooo / IiII % OOooOOo % Ii1I
 if 59 - 59: I1IiiI / Oo0Ooo / OoOoOO00
 if 79 - 79: O0 / ooOoO0o + OoOoOO00
 if 23 - 23: I11i
 if 81 - 81: OoOoOO00 * ooOoO0o + OoOoOO00
 if 7 - 7: I1ii11iIi11i - II111iiii
 if 100 - 100: OoO0O00 . I1IiiI / i1IIi + OOooOOo / IiII
 if 48 - 48: i11iIiiIii % i1IIi + iIii1I11I1II1 . I1Ii111
 if 67 - 67: i11iIiiIii / o0oOOo0O0Ooo . i11iIiiIii . I1ii11iIi11i - O0
def lisp_allow_gleaning ( eid , group , rloc ) :
 if ( lisp_glean_mappings == [ ] ) : return ( False , False , False )
 if 76 - 76: i1IIi % OOooOOo
 for I1I11i in lisp_glean_mappings :
  if ( "instance-id" in I1I11i ) :
   i1I1iI = eid . instance_id
   O0II11II1111 , O00ooO0OoOO0O = I1I11i [ "instance-id" ]
   if ( i1I1iI < O0II11II1111 or i1I1iI > O00ooO0OoOO0O ) : continue
   if 37 - 37: Oo0Ooo - oO0o / II111iiii . o0oOOo0O0Ooo % OoOoOO00 % ooOoO0o
  if ( "eid-prefix" in I1I11i ) :
   oOO = copy . deepcopy ( I1I11i [ "eid-prefix" ] )
   oOO . instance_id = eid . instance_id
   if ( eid . is_more_specific ( oOO ) == False ) : continue
   if 44 - 44: I11i / I1IiiI + I1Ii111 - O0 - ooOoO0o
  if ( "group-prefix" in I1I11i ) :
   if ( group == None ) : continue
   II11iIIii = copy . deepcopy ( I1I11i [ "group-prefix" ] )
   II11iIIii . instance_id = group . instance_id
   if ( group . is_more_specific ( II11iIIii ) == False ) : continue
   if 57 - 57: I1IiiI * OOooOOo - Ii1I
  if ( "rloc-prefix" in I1I11i ) :
   if ( rloc != None and rloc . is_more_specific ( I1I11i [ "rloc-prefix" ] )
 == False ) : continue
   if 82 - 82: OoOoOO00
  return ( True , I1I11i [ "rloc-probe" ] , I1I11i [ "igmp-query" ] )
  if 78 - 78: ooOoO0o - I1IiiI % I1ii11iIi11i
 return ( False , False , False )
 if 90 - 90: I1ii11iIi11i / II111iiii
 if 92 - 92: i11iIiiIii
 if 35 - 35: O0 + i11iIiiIii . OoO0O00
 if 1 - 1: OoOoOO00 + o0oOOo0O0Ooo . Ii1I / II111iiii
 if 54 - 54: ooOoO0o + iIii1I11I1II1
 if 89 - 89: I1IiiI
 if 75 - 75: O0 / I1ii11iIi11i
def lisp_build_gleaned_multicast ( seid , geid , rloc , port , igmp ) :
 ooOoo000oO = geid . print_address ( )
 IiI1ii1I1 = seid . print_address_no_iid ( )
 OOo0oOO0o0oo0 = green ( "{}" . format ( IiI1ii1I1 ) , False )
 oOO = green ( "(*, {})" . format ( ooOoo000oO ) , False )
 IIi1iii = red ( rloc . print_address_no_iid ( ) + ":" + str ( port ) , False )
 if 4 - 4: OoooooooOO * oO0o
 if 63 - 63: IiII - I1IiiI * i11iIiiIii * OoooooooOO * Oo0Ooo
 if 30 - 30: I1Ii111 % II111iiii
 if 4 - 4: o0oOOo0O0Ooo - OoO0O00 % i1IIi % OoooooooOO * oO0o - Oo0Ooo
 IIII1 = lisp_map_cache_lookup ( seid , geid )
 if ( IIII1 == None ) :
  IIII1 = lisp_mapping ( "" , "" , [ ] )
  IIII1 . group . copy_address ( geid )
  IIII1 . eid . copy_address ( geid )
  IIII1 . eid . address = 0
  IIII1 . eid . mask_len = 0
  IIII1 . mapping_source . copy_address ( rloc )
  IIII1 . map_cache_ttl = LISP_IGMP_TTL
  IIII1 . gleaned = True
  IIII1 . add_cache ( )
  lprint ( "Add gleaned EID {} to map-cache" . format ( oOO ) )
  if 18 - 18: oO0o % Oo0Ooo / o0oOOo0O0Ooo + OOooOOo
  if 65 - 65: OOooOOo
  if 23 - 23: OoOoOO00
  if 26 - 26: i11iIiiIii * o0oOOo0O0Ooo . ooOoO0o + OoO0O00
  if 86 - 86: OoOoOO00 % i11iIiiIii . ooOoO0o + i1IIi + O0 - OOooOOo
  if 24 - 24: I11i - ooOoO0o + I1IiiI % O0 % iII111i * II111iiii
 oO0o0 = iII1i1111 = Iiiiii = None
 if ( IIII1 . rloc_set != [ ] ) :
  oO0o0 = IIII1 . rloc_set [ 0 ]
  if ( oO0o0 . rle ) :
   iII1i1111 = oO0o0 . rle
   for OOO in iII1i1111 . rle_nodes :
    if ( OOO . rloc_name != IiI1ii1I1 ) : continue
    Iiiiii = OOO
    break
    if 82 - 82: I1Ii111
    if 38 - 38: I11i - i1IIi - iII111i - Ii1I . ooOoO0o / I1ii11iIi11i
    if 19 - 19: OoOoOO00 + OOooOOo . I11i / OoOoOO00
    if 80 - 80: iIii1I11I1II1 / OoooooooOO * I1ii11iIi11i / oO0o
    if 22 - 22: OoO0O00 + Oo0Ooo . iII111i
    if 98 - 98: IiII
    if 99 - 99: II111iiii
 if ( oO0o0 == None ) :
  oO0o0 = lisp_rloc ( )
  IIII1 . rloc_set = [ oO0o0 ]
  oO0o0 . priority = 253
  oO0o0 . mpriority = 255
  IIII1 . build_best_rloc_set ( )
  if 56 - 56: Oo0Ooo - OOooOOo + o0oOOo0O0Ooo + I11i
 if ( iII1i1111 == None ) :
  iII1i1111 = lisp_rle ( geid . print_address ( ) )
  oO0o0 . rle = iII1i1111
  if 50 - 50: i11iIiiIii + I11i . I1ii11iIi11i % OoOoOO00
 if ( Iiiiii == None ) :
  Iiiiii = lisp_rle_node ( )
  Iiiiii . rloc . rloc_name = IiI1ii1I1
  iII1i1111 . rle_nodes . append ( Iiiiii )
  iII1i1111 . build_rle_forwarding_list ( )
  lprint ( "Add RLE {} from {} for gleaned EID {}" . format ( IIi1iii , OOo0oOO0o0oo0 , oOO ) )
 elif ( rloc . is_exact_match ( Iiiiii . rloc . rloc ) == False or
 port != Iiiiii . rloc . translated_port ) :
  lprint ( "Changed RLE {} from {} for gleaned EID {}" . format ( IIi1iii , OOo0oOO0o0oo0 , oOO ) )
  if 95 - 95: ooOoO0o + I1Ii111 . OoOoOO00 + OOooOOo
  if 19 - 19: iIii1I11I1II1 % i11iIiiIii
  if 37 - 37: I1IiiI . OoO0O00 . OOooOOo + OOooOOo
  if 91 - 91: I1Ii111
  if 13 - 13: IiII + Ii1I * oO0o / OoO0O00
 Iiiiii . store_translated_rloc ( rloc , port )
 if 62 - 62: Ii1I - I11i + i1IIi % OoO0O00 + I11i
 if 87 - 87: OOooOOo % I1ii11iIi11i - IiII . II111iiii . o0oOOo0O0Ooo
 if 9 - 9: Ii1I / oO0o + I11i . iII111i
 if 3 - 3: OoooooooOO + OoooooooOO * OOooOOo / O0
 if 81 - 81: i11iIiiIii - OoOoOO00
 if ( igmp ) :
  I1IiIiIi = seid . print_address ( )
  if ( I1IiIiIi not in lisp_gleaned_groups ) :
   lisp_gleaned_groups [ I1IiIiIi ] = { }
   if 80 - 80: iIii1I11I1II1 % OOooOOo + oO0o + II111iiii - I1ii11iIi11i
  lisp_gleaned_groups [ I1IiIiIi ] [ ooOoo000oO ] = lisp_get_timestamp ( )
  if 44 - 44: OoooooooOO * iII111i
  if 26 - 26: OoooooooOO
  if 73 - 73: II111iiii . iII111i - iIii1I11I1II1 . i1IIi . I11i
  if 60 - 60: OoO0O00 + OoO0O00
  if 50 - 50: i1IIi
  if 33 - 33: oO0o - Ii1I - Oo0Ooo * IiII / OoooooooOO - OoooooooOO
  if 31 - 31: O0 - I11i
  if 25 - 25: Oo0Ooo * o0oOOo0O0Ooo . IiII
def lisp_remove_gleaned_multicast ( seid , geid ) :
 if 74 - 74: OOooOOo % oO0o
 if 69 - 69: Oo0Ooo . oO0o + Oo0Ooo * IiII - OoooooooOO
 if 86 - 86: I11i % OoOoOO00 . oO0o % Ii1I - i11iIiiIii - Oo0Ooo
 if 5 - 5: Oo0Ooo * oO0o . OoO0O00 % i11iIiiIii
 IIII1 = lisp_map_cache_lookup ( seid , geid )
 if ( IIII1 == None ) : return
 if 64 - 64: OOooOOo / Ii1I - Ii1I . I1Ii111 / I1IiiI
 IiI = IIII1 . rloc_set [ 0 ] . rle
 if ( IiI == None ) : return
 if 12 - 12: i1IIi
 I11I = seid . print_address_no_iid ( )
 iiO0Ii1IiiiI = False
 for Iiiiii in IiI . rle_nodes :
  if ( Iiiiii . rloc . rloc_name == I11I ) :
   iiO0Ii1IiiiI = True
   break
   if 65 - 65: I1IiiI + i1IIi * II111iiii / II111iiii + OoooooooOO
   if 100 - 100: IiII / i1IIi + I11i
 if ( iiO0Ii1IiiiI == False ) : return
 if 57 - 57: Ii1I % II111iiii
 if 33 - 33: ooOoO0o - OOooOOo % OoOoOO00
 if 56 - 56: i1IIi . iII111i - i11iIiiIii
 if 65 - 65: I1Ii111 * O0 % Ii1I . iII111i . ooOoO0o . ooOoO0o
 IiI . rle_nodes . remove ( Iiiiii )
 IiI . build_rle_forwarding_list ( )
 if 9 - 9: I1IiiI / Oo0Ooo . iIii1I11I1II1 % o0oOOo0O0Ooo . OoOoOO00
 ooOoo000oO = geid . print_address ( )
 I1IiIiIi = seid . print_address ( )
 OOo0oOO0o0oo0 = green ( "{}" . format ( I1IiIiIi ) , False )
 oOO = green ( "(*, {})" . format ( ooOoo000oO ) , False )
 lprint ( "Gleaned EID {} RLE removed for {}" . format ( oOO , OOo0oOO0o0oo0 ) )
 if 45 - 45: I1ii11iIi11i
 if 64 - 64: iIii1I11I1II1 % Oo0Ooo % I1Ii111 . iII111i . I11i * OOooOOo
 if 38 - 38: O0 - i1IIi % OoO0O00
 if 38 - 38: I1Ii111 % oO0o . OoOoOO00 % Oo0Ooo / oO0o % IiII
 if ( I1IiIiIi in lisp_gleaned_groups ) :
  if ( ooOoo000oO in lisp_gleaned_groups [ I1IiIiIi ] ) :
   lisp_gleaned_groups [ I1IiIiIi ] . pop ( ooOoo000oO )
   if 15 - 15: iIii1I11I1II1 * Oo0Ooo * iIii1I11I1II1 % II111iiii / I1IiiI . OoO0O00
   if 81 - 81: IiII * OoOoOO00
   if 84 - 84: oO0o
   if 29 - 29: I1ii11iIi11i - i11iIiiIii + ooOoO0o % OoO0O00 + I11i
   if 34 - 34: O0 % iIii1I11I1II1 - I1Ii111 / oO0o
   if 83 - 83: I1IiiI / OOooOOo
 if ( IiI . rle_nodes == [ ] ) :
  IIII1 . delete_cache ( )
  lprint ( "Gleaned EID {} remove, no more RLEs" . format ( oOO ) )
  if 12 - 12: o0oOOo0O0Ooo / I11i . I1Ii111 % OOooOOo - II111iiii + iII111i
  if 42 - 42: O0 . i1IIi . iIii1I11I1II1 + O0 - i11iIiiIii * Oo0Ooo
  if 48 - 48: i11iIiiIii
  if 64 - 64: OoO0O00 - OOooOOo % I11i * I11i
  if 24 - 24: OoOoOO00 % O0
  if 99 - 99: IiII . i1IIi - Oo0Ooo * i1IIi / Ii1I + I1ii11iIi11i
  if 46 - 46: OOooOOo - o0oOOo0O0Ooo
  if 48 - 48: Oo0Ooo
def lisp_change_gleaned_multicast ( seid , rloc , port ) :
 I1IiIiIi = seid . print_address ( )
 if ( I1IiIiIi not in lisp_gleaned_groups ) : return
 if 22 - 22: IiII . I1ii11iIi11i / oO0o - OoooooooOO % OoooooooOO + ooOoO0o
 for i1I1IIIiII in lisp_gleaned_groups [ I1IiIiIi ] :
  lisp_geid . store_address ( i1I1IIIiII )
  lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , port , False )
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
  if 79 - 79: Oo0Ooo
  if 11 - 11: i1IIi
  if 14 - 14: i1IIi
  if 3 - 3: I1Ii111
  if 82 - 82: iIii1I11I1II1 * iII111i - O0
  if 8 - 8: OoOoOO00 - I1Ii111 * OOooOOo
  if 97 - 97: OoOoOO00
  if 56 - 56: O0 * Oo0Ooo + I11i % i11iIiiIii * iIii1I11I1II1 * OOooOOo
  if 53 - 53: oO0o
  if 8 - 8: OoO0O00 / oO0o + IiII - o0oOOo0O0Ooo * I11i - IiII
  if 47 - 47: Ii1I / Ii1I
  if 92 - 92: OoO0O00 + Oo0Ooo / I1ii11iIi11i
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
igmp_types = { 17 : "IGMP-query" , 18 : "IGMPv1-report" , 19 : "DVMRP" ,
 20 : "PIMv1" , 22 : "IGMPv2-report" , 23 : "IGMPv2-leave" ,
 30 : "mtrace-response" , 31 : "mtrace-request" , 34 : "IGMPv3-report" }
if 62 - 62: I1Ii111 / OoooooooOO * ooOoO0o
lisp_igmp_record_types = { 1 : "include-mode" , 2 : "exclude-mode" ,
 3 : "change-to-include" , 4 : "change-to-exclude" , 5 : "allow-new-source" ,
 6 : "block-old-sources" }
if 88 - 88: oO0o / Oo0Ooo - OoOoOO00 * ooOoO0o - OoOoOO00 / i11iIiiIii
def lisp_process_igmp_packet ( packet ) :
 ooOO0O0O = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 ooOO0O0O . address = socket . ntohl ( struct . unpack ( "I" , packet [ 12 : 16 ] ) [ 0 ] )
 ooOO0O0O = bold ( "from {}" . format ( ooOO0O0O . print_address_no_iid ( ) ) , False )
 if 50 - 50: iIii1I11I1II1 * OOooOOo . iII111i / ooOoO0o + OoOoOO00 - IiII
 IIi1iii = bold ( "Receive" , False )
 lprint ( "{} {}-byte {}, IGMP packet: {}" . format ( IIi1iii , len ( packet ) , ooOO0O0O ,
 lisp_format_packet ( packet ) ) )
 if 80 - 80: i11iIiiIii * o0oOOo0O0Ooo
 if 71 - 71: OoO0O00 % I1ii11iIi11i * iII111i . o0oOOo0O0Ooo * oO0o - OoO0O00
 if 44 - 44: I11i / I1Ii111 * OOooOOo - I11i . iIii1I11I1II1
 if 71 - 71: OoO0O00 / IiII
 Ooo00oO0o = ( struct . unpack ( "B" , packet [ 0 : 1 ] ) [ 0 ] & 0x0f ) * 4
 if 40 - 40: OOooOOo / iIii1I11I1II1 - Oo0Ooo / II111iiii % ooOoO0o . o0oOOo0O0Ooo
 if 52 - 52: i1IIi
 if 13 - 13: OoooooooOO / i11iIiiIii - OoOoOO00 + II111iiii . i1IIi
 if 2 - 2: I1IiiI % i1IIi . O0 . I1Ii111
 oo00Oooo = packet [ Ooo00oO0o : : ]
 iIiIi1ii1iI1 = struct . unpack ( "B" , oo00Oooo [ 0 : 1 ] ) [ 0 ]
 if 90 - 90: OOooOOo % iII111i - I11i / ooOoO0o * Oo0Ooo . o0oOOo0O0Ooo
 if 73 - 73: OOooOOo
 if 84 - 84: I11i . i1IIi * O0 + oO0o + i11iIiiIii . OoOoOO00
 if 26 - 26: oO0o * i1IIi - Ii1I / Oo0Ooo + I1ii11iIi11i
 if 35 - 35: iII111i
 i1I1IIIiII = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1I1IIIiII . address = socket . ntohl ( struct . unpack ( "II" , oo00Oooo [ : 8 ] ) [ 1 ] )
 ooOoo000oO = i1I1IIIiII . print_address_no_iid ( )
 if 80 - 80: iII111i
 if ( iIiIi1ii1iI1 == 17 ) :
  lprint ( "IGMP Query for group {}" . format ( ooOoo000oO ) )
  return ( [ ] )
  if 30 - 30: oO0o . i1IIi + ooOoO0o . OoooooooOO % iIii1I11I1II1 . II111iiii
  if 92 - 92: o0oOOo0O0Ooo % IiII . Oo0Ooo - iIii1I11I1II1 . OoOoOO00
 ii1I1I1I1I1 = ( iIiIi1ii1iI1 in ( 0x12 , 0x16 , 0x17 , 0x22 ) )
 if ( ii1I1I1I1I1 == False ) :
  oOOI111i1iIii1 = "{} ({})" . format ( iIiIi1ii1iI1 , igmp_types [ iIiIi1ii1iI1 ] ) if ( iIiIi1ii1iI1 in igmp_types ) else iIiIi1ii1iI1
  if 53 - 53: II111iiii / i1IIi / i1IIi . oO0o - O0 * O0
  lprint ( "IGMP type {} not supported" . format ( oOOI111i1iIii1 ) )
  return ( [ ] )
  if 19 - 19: Ii1I % II111iiii / OoOoOO00 % I1Ii111
  if 23 - 23: iIii1I11I1II1 % OoooooooOO % IiII - i11iIiiIii + OoO0O00
 if ( len ( oo00Oooo ) < 8 ) :
  lprint ( "IGMP message too small" )
  return ( [ ] )
  if 62 - 62: oO0o - IiII
  if 14 - 14: II111iiii / OOooOOo + i11iIiiIii
  if 35 - 35: OoOoOO00 / o0oOOo0O0Ooo * iIii1I11I1II1 - Oo0Ooo / I1ii11iIi11i / II111iiii
  if 61 - 61: iIii1I11I1II1
  if 54 - 54: II111iiii / OoO0O00 * I1IiiI - ooOoO0o - Oo0Ooo
 if ( iIiIi1ii1iI1 == 0x17 ) :
  lprint ( "IGMPv2 leave (*, {})" . format ( bold ( ooOoo000oO , False ) ) )
  lisp_update_igmp_database ( None , ooOoo000oO , False )
  return ( [ [ None , ooOoo000oO , False ] ] )
  if 100 - 100: O0 * II111iiii - iIii1I11I1II1 + OoooooooOO
 if ( iIiIi1ii1iI1 in ( 0x12 , 0x16 ) ) :
  lprint ( "IGMPv{} join (*, {})" . format ( 1 if ( iIiIi1ii1iI1 == 0x12 ) else 2 , bold ( ooOoo000oO , False ) ) )
  if 13 - 13: ooOoO0o
  if 48 - 48: o0oOOo0O0Ooo - OOooOOo + O0 + i1IIi
  if 43 - 43: i11iIiiIii / IiII / OoooooooOO + oO0o * o0oOOo0O0Ooo
  if 56 - 56: Oo0Ooo / Ii1I * OOooOOo
  if 28 - 28: Ii1I + iII111i
  if ( ooOoo000oO . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   return ( [ ] )
   if 96 - 96: i1IIi . O0 - OoooooooOO + iIii1I11I1II1
   if 27 - 27: OoooooooOO / IiII + O0 * ooOoO0o
  lisp_update_igmp_database ( None , ooOoo000oO , True )
  return ( [ [ None , ooOoo000oO , True ] ] )
  if 87 - 87: i1IIi % OoOoOO00 / IiII
  if 91 - 91: I11i - II111iiii * I1IiiI * Ii1I
  if 3 - 3: OoO0O00 - I1ii11iIi11i % iII111i
  if 71 - 71: II111iiii / OOooOOo % o0oOOo0O0Ooo
  if 92 - 92: I1IiiI - o0oOOo0O0Ooo - Ii1I / I1IiiI
 OOO0OO0OOoO = i1I1IIIiII . address
 oo00Oooo = oo00Oooo [ 8 : : ]
 if 94 - 94: Ii1I * OoOoOO00 - I1Ii111 - o0oOOo0O0Ooo % Oo0Ooo . Ii1I
 I111I11ii = "BBHI"
 ii1I111I1I1I = struct . calcsize ( I111I11ii )
 oOo00O0OOO0o = "I"
 I1iioO00OOo = struct . calcsize ( oOo00O0OOO0o )
 ooOO0O0O = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if 63 - 63: i1IIi - OoO0O00 / OoO0O00 . O0 + OoooooooOO
 if 74 - 74: i1IIi % I11i * oO0o
 if 37 - 37: ooOoO0o . I11i % o0oOOo0O0Ooo / ooOoO0o
 if 40 - 40: oO0o . OoOoOO00
 ii1i1iIiIi11 = [ ]
 for o000o0O0Oo00 in range ( OOO0OO0OOoO ) :
  if ( len ( oo00Oooo ) < ii1I111I1I1I ) : return ( [ ] )
  i11ii1iIiIIi , O0O0oOO , iIO0oooO0000oO , I1iI111ii111i = struct . unpack ( I111I11ii ,
 oo00Oooo [ : ii1I111I1I1I ] )
  if 17 - 17: oO0o . O0
  oo00Oooo = oo00Oooo [ ii1I111I1I1I : : ]
  if 98 - 98: OoooooooOO % i1IIi . OOooOOo / II111iiii
  if ( i11ii1iIiIIi not in lisp_igmp_record_types ) :
   lprint ( "Invalid record type {}" . format ( i11ii1iIiIIi ) )
   continue
   if 37 - 37: o0oOOo0O0Ooo + oO0o % OoO0O00 % o0oOOo0O0Ooo
   if 91 - 91: iIii1I11I1II1 % I1Ii111 - OoOoOO00 / ooOoO0o
  OoOOoo0oO = lisp_igmp_record_types [ i11ii1iIiIIi ]
  iIO0oooO0000oO = socket . ntohs ( iIO0oooO0000oO )
  i1I1IIIiII . address = socket . ntohl ( I1iI111ii111i )
  ooOoo000oO = i1I1IIIiII . print_address_no_iid ( )
  if 21 - 21: OoO0O00 % i1IIi - Oo0Ooo - I1ii11iIi11i + iIii1I11I1II1 - I1ii11iIi11i
  lprint ( "Record type: {}, group: {}, source-count: {}" . format ( OoOOoo0oO , ooOoo000oO , iIO0oooO0000oO ) )
  if 71 - 71: Ii1I . ooOoO0o
  if 10 - 10: iIii1I11I1II1 * IiII
  if 50 - 50: iIii1I11I1II1
  if 55 - 55: o0oOOo0O0Ooo
  if 42 - 42: IiII - i1IIi - oO0o
  if 89 - 89: Ii1I % I1Ii111 / i1IIi + II111iiii
  if 64 - 64: O0 % OoO0O00 / oO0o + iIii1I11I1II1
  Ii1Ii1IiI1ii = False
  if ( i11ii1iIiIIi in ( 1 , 5 ) ) : Ii1Ii1IiI1ii = True
  if ( i11ii1iIiIIi == 3 and iIO0oooO0000oO == 0 ) : Ii1Ii1IiI1ii = False
  if ( i11ii1iIiIIi in ( 2 , 4 ) and iIO0oooO0000oO == 0 ) : Ii1Ii1IiI1ii = True
  o0oIIi1I1 = "join" if ( Ii1Ii1IiI1ii ) else "leave"
  if 7 - 7: IiII + I1IiiI % OOooOOo . II111iiii - II111iiii
  if 12 - 12: I1ii11iIi11i + iII111i + II111iiii - i11iIiiIii
  if 37 - 37: iIii1I11I1II1 + I1IiiI
  if 40 - 40: OoOoOO00
  if ( ooOoo000oO . find ( "224.0.0." ) != - 1 ) :
   lprint ( "Suppress registration for link-local groups" )
   continue
   if 18 - 18: i1IIi - Oo0Ooo / I1ii11iIi11i * I11i
   if 42 - 42: I1IiiI
   if 41 - 41: OOooOOo / I1Ii111 + OoO0O00
   if 81 - 81: OoOoOO00 % iIii1I11I1II1 - oO0o * I1IiiI . o0oOOo0O0Ooo . I1ii11iIi11i
   if 13 - 13: OoO0O00 * o0oOOo0O0Ooo - o0oOOo0O0Ooo * Oo0Ooo + iIii1I11I1II1 / OoO0O00
   if 66 - 66: II111iiii + IiII . OoO0O00 / ooOoO0o
   if 70 - 70: iIii1I11I1II1
   if 40 - 40: iII111i * iIii1I11I1II1 % I1Ii111 . I1ii11iIi11i / iII111i / iIii1I11I1II1
  if ( iIO0oooO0000oO == 0 ) :
   ii1i1iIiIi11 . append ( [ None , ooOoo000oO , Ii1Ii1IiI1ii ] )
   lprint ( "IGMPv3 {} (*, {})" . format ( bold ( o0oIIi1I1 , False ) ,
 bold ( ooOoo000oO , False ) ) )
   if 70 - 70: ooOoO0o % o0oOOo0O0Ooo
   if 74 - 74: iII111i / OOooOOo
   if 89 - 89: Ii1I + OoOoOO00 + ooOoO0o
   if 97 - 97: I1Ii111 - IiII - iII111i * iIii1I11I1II1 % Oo0Ooo
   if 24 - 24: OoO0O00
  for iii1iII in range ( iIO0oooO0000oO ) :
   if ( len ( oo00Oooo ) < I1iioO00OOo ) : return ( [ ] )
   I1iI111ii111i = struct . unpack ( oOo00O0OOO0o , oo00Oooo [ : I1iioO00OOo ] ) [ 0 ]
   ooOO0O0O . address = socket . ntohl ( I1iI111ii111i )
   Ii1i1i1I11 = ooOO0O0O . print_address_no_iid ( )
   ii1i1iIiIi11 . append ( [ Ii1i1i1I11 , ooOoo000oO , Ii1Ii1IiI1ii ] )
   lprint ( "{} ({}, {})" . format ( o0oIIi1I1 ,
 green ( Ii1i1i1I11 , False ) , bold ( ooOoo000oO , False ) ) )
   oo00Oooo = oo00Oooo [ I1iioO00OOo : : ]
   if 29 - 29: i11iIiiIii
   if 17 - 17: oO0o % i1IIi % o0oOOo0O0Ooo / IiII / ooOoO0o
   if 32 - 32: Ii1I % I11i - II111iiii
   if 100 - 100: I1Ii111 * I1Ii111 % O0
   if 67 - 67: I11i % O0 . Ii1I % OOooOOo * iII111i + I11i
   if 19 - 19: II111iiii + I1Ii111 % i11iIiiIii * II111iiii * Ii1I - OoooooooOO
 for Ii1i1i1I11 , ooOoo000oO , Ii1Ii1IiI1ii in ii1i1iIiIi11 :
  lisp_update_igmp_database ( Ii1i1i1I11 , ooOoo000oO , Ii1Ii1IiI1ii )
  if 86 - 86: I11i - ooOoO0o
  if 100 - 100: I1Ii111 - i11iIiiIii
  if 1 - 1: Ii1I + Ii1I * OOooOOo / IiII - OoO0O00
  if 32 - 32: Oo0Ooo * i11iIiiIii / ooOoO0o
  if 1 - 1: OoOoOO00 / Oo0Ooo . o0oOOo0O0Ooo + iIii1I11I1II1 / Ii1I % I1IiiI
  if 40 - 40: IiII . I1IiiI / O0 % I1Ii111 / o0oOOo0O0Ooo / O0
  if 46 - 46: oO0o / OoO0O00
 return ( ii1i1iIiIi11 )
 if 43 - 43: ooOoO0o - oO0o / i1IIi . I11i . I1ii11iIi11i % oO0o
 if 40 - 40: I1ii11iIi11i
 if 60 - 60: Oo0Ooo / II111iiii . iIii1I11I1II1 + I1ii11iIi11i . I11i + o0oOOo0O0Ooo
 if 40 - 40: o0oOOo0O0Ooo
 if 73 - 73: iIii1I11I1II1 + I1Ii111 % o0oOOo0O0Ooo / OoooooooOO + OoOoOO00
 if 98 - 98: iII111i * ooOoO0o . I1IiiI * OOooOOo * OoOoOO00 * OoooooooOO
 if 43 - 43: IiII . i11iIiiIii % iIii1I11I1II1
 if 65 - 65: i11iIiiIii + iII111i
def lisp_update_igmp_database ( source_str , group_str , joinleave ) :
 if 12 - 12: ooOoO0o % II111iiii / O0
 if 88 - 88: OoOoOO00 - I1ii11iIi11i % ooOoO0o + OoO0O00 % ooOoO0o
 if 27 - 27: OOooOOo - oO0o * OoooooooOO
 if 25 - 25: oO0o . OoOoOO00
 i1I1IIIiII = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1I1IIIiII . store_address ( group_str )
 if 18 - 18: OOooOOo / O0
 if 8 - 8: oO0o * IiII - iII111i % i11iIiiIii * OoOoOO00 / I11i
 if 72 - 72: I11i / IiII
 if 51 - 51: i1IIi . oO0o * Ii1I % I1Ii111 - oO0o - i1IIi
 Ooo0O = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if source_str :
  Ooo0O . store_address ( source_str )
 else :
  Ooo0O . address = 0
  Ooo0O . mask_len = 0
  if 29 - 29: OoooooooOO + ooOoO0o * OoO0O00 % I11i % i11iIiiIii
  if 77 - 77: II111iiii + OoooooooOO . oO0o / O0 + ooOoO0o * IiII
 O0OoO0 = "({}, {})" . format ( source_str if source_str else "*" , group_str )
 if 35 - 35: OoO0O00 . OOooOOo % oO0o * I1IiiI / I1ii11iIi11i
 if ( joinleave ) :
  Iiii1II1 = lisp_db_for_lookups . lookup_cache ( i1I1IIIiII , False )
  if ( Iiii1II1 ) :
   IIIIi1iI = Iiii1II1 . lookup_source_cache ( Ooo0O , False )
   if ( IIIIi1iI ) :
    IIIIi1iI . last_refresh_time = lisp_get_timestamp ( )
    lprint ( "Update IGMP database-mapping entry timestamp for {}" . format ( green ( O0OoO0 , False ) ) )
    if 84 - 84: o0oOOo0O0Ooo . ooOoO0o + I1ii11iIi11i * I11i
    return
    if 40 - 40: Ii1I * II111iiii
    if 35 - 35: OOooOOo % oO0o * O0 + OoOoOO00
    if 70 - 70: I11i / O0 . i1IIi + II111iiii
    if 22 - 22: I1ii11iIi11i . IiII + I1IiiI . OoOoOO00 % ooOoO0o % I1ii11iIi11i
    if 61 - 61: i1IIi + iIii1I11I1II1
    if 96 - 96: i11iIiiIii % o0oOOo0O0Ooo + iII111i / iIii1I11I1II1 + OOooOOo * I1ii11iIi11i
  O0o0OOOooo00 = lisp_db_list [ 0 ] . rloc_set [ 0 ]
  if 85 - 85: OOooOOo - I1Ii111 . O0 . IiII
  oO0o0 = copy . deepcopy ( O0o0OOOooo00 )
  oO0o0 . priority = 1
  oO0o0 . weight = 100
  oO0o0 . mpriority = 255
  oO0o0 . mweight = 0
  oO0o0 . state = LISP_RLOC_UP_STATE
  if 39 - 39: oO0o - OoooooooOO
  I11o0O00O0ooOO0o = lisp_mapping ( Ooo0O , i1I1IIIiII , [ oO0o0 ] )
  I11o0O00O0ooOO0o . map_cache_ttl = LISP_IGMP_TIMEOUT_INTERVAL
  I11o0O00O0ooOO0o . last_refresh_time = lisp_get_timestamp ( )
  I11o0O00O0ooOO0o . gleaned = True
  if 15 - 15: OOooOOo / i1IIi / o0oOOo0O0Ooo % i11iIiiIii
  I11o0O00O0ooOO0o . add_db ( )
  if 22 - 22: OoooooooOO % I1ii11iIi11i / Oo0Ooo . I11i
  lprint ( "Add IGMP database-mapping entry for {}" . format ( green ( O0OoO0 , False ) ) )
 else :
  lisp_remove_igmp_database ( source_str , group_str )
  if 33 - 33: i11iIiiIii % I1IiiI / i1IIi + Ii1I + O0 * OoO0O00
  if 46 - 46: i1IIi * Oo0Ooo + I1Ii111 + iIii1I11I1II1 / O0
  if 47 - 47: OoooooooOO . II111iiii % OoOoOO00
  if 75 - 75: i11iIiiIii + IiII
  if 79 - 79: IiII
  if 44 - 44: IiII . I1ii11iIi11i / OoO0O00 % ooOoO0o
  if 96 - 96: OoO0O00 / II111iiii / iII111i % iIii1I11I1II1 % II111iiii
  if 37 - 37: Ii1I / ooOoO0o - O0 - Ii1I % iIii1I11I1II1
def lisp_remove_igmp_database ( source_str , group_str ) :
 i1I1IIIiII = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 i1I1IIIiII . store_address ( group_str )
 if 40 - 40: IiII - OoOoOO00 + OoooooooOO . o0oOOo0O0Ooo
 Iiii1II1 = lisp_db_for_lookups . lookup_cache ( i1I1IIIiII , False )
 if ( Iiii1II1 == None ) : return
 if 49 - 49: IiII - O0 % I11i . II111iiii % II111iiii
 Ooo0O = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
 if ( source_str ) :
  Ooo0O . store_address ( source_str )
 else :
  Ooo0O . address = 0
  Ooo0O . mask_len = 0
  if 53 - 53: ooOoO0o . II111iiii - II111iiii * I11i
  if 85 - 85: I1ii11iIi11i % I1ii11iIi11i
 O0OoO0 = "({}, {})" . format ( source_str if source_str else "*" , group_str )
 if 66 - 66: I1Ii111 / Oo0Ooo / I11i
 IIIIi1iI = Iiii1II1 . lookup_source_cache ( Ooo0O , False )
 if ( IIIIi1iI == None ) :
  lprint ( "Could not remove not found IGMP database-mapping entry for {}" . format ( green ( O0OoO0 , False ) ) )
  if 2 - 2: OoOoOO00 + OoO0O00
  return
  if 12 - 12: I1Ii111
  if 89 - 89: iIii1I11I1II1
  if 94 - 94: I1ii11iIi11i - i1IIi % IiII
  if 5 - 5: OoO0O00
  if 38 - 38: OoooooooOO / I11i . oO0o
 if ( IIIIi1iI . gleaned == False ) : return
 if 79 - 79: i11iIiiIii
 Iiii1II1 . source_cache . delete_cache ( Ooo0O )
 lprint ( "Remove IGMP database-mapping entry for {}" . format ( green ( O0OoO0 , False ) ) )
 if 94 - 94: II111iiii % iII111i
 if 33 - 33: O0 . ooOoO0o / Oo0Ooo - OOooOOo
 if 40 - 40: Ii1I
 if 6 - 6: iII111i % I1ii11iIi11i + IiII + I11i
 if Iiii1II1 . source_cache . cache_size ( ) == 0 :
  lisp_db_for_lookups . delete_cache ( i1I1IIIiII )
  if 27 - 27: iIii1I11I1II1 * i11iIiiIii * I1Ii111 - i11iIiiIii . iIii1I11I1II1 . I11i
  if 20 - 20: I1IiiI + OoooooooOO + i11iIiiIii / OOooOOo . I11i % I11i
  if 89 - 89: OoOoOO00 * I1Ii111
  if 69 - 69: oO0o / IiII * OOooOOo . I11i / I11i
  if 56 - 56: O0 + I1Ii111 * o0oOOo0O0Ooo % Ii1I . OOooOOo
  if 98 - 98: I1Ii111
  if 74 - 74: oO0o
  if 55 - 55: Oo0Ooo
  if 94 - 94: OoooooooOO
def lisp_timeout_igmp_database ( ) :
 O0OoOOo = lisp_get_timestamp ( )
 if 87 - 87: OoO0O00 % Oo0Ooo * Oo0Ooo
 if 35 - 35: Oo0Ooo - Oo0Ooo
 if 82 - 82: iII111i
 if 6 - 6: Oo0Ooo . OoOoOO00 / i11iIiiIii - i11iIiiIii . iII111i
 for I1iIIIiI1iI11 in lisp_db_for_lookups . cache_sorted :
  for I1iii11IIi in ( list ( lisp_db_for_lookups . cache [ I1iIIIiI1iI11 ] . entries . values ( ) ) ) :
   if ( I1iii11IIi . group . is_null ( ) ) : continue
   if ( I1iii11IIi . source_cache == None ) : continue
   if 28 - 28: I1IiiI / Ii1I . IiII / OoooooooOO
   if 45 - 45: O0
   if 24 - 24: OoO0O00 % o0oOOo0O0Ooo - i1IIi
   if 36 - 36: Oo0Ooo
   O0O0OOOo0 = [ ]
   for o000Ooo0 in I1iii11IIi . source_cache . cache_sorted :
    for IIIIi1iI in ( list ( I1iii11IIi . source_cache . cache [ o000Ooo0 ] . entries . values ( ) ) ) :
     if ( IIIIi1iI . gleaned == False ) : continue
     if ( IIIIi1iI . map_cache_ttl == None ) : continue
     if 18 - 18: Oo0Ooo . I1ii11iIi11i - i11iIiiIii
     o0oOOOO0 = O0OoOOo - IIIIi1iI . last_refresh_time
     if ( o0oOOOO0 >= IIIIi1iI . map_cache_ttl ) :
      O0O0OOOo0 . append ( IIIIi1iI )
      if 51 - 51: OoOoOO00 % IiII - O0 - II111iiii
      if 37 - 37: I1ii11iIi11i % i1IIi / Oo0Ooo + i11iIiiIii - I1ii11iIi11i
      if 82 - 82: IiII * I1ii11iIi11i
      if 22 - 22: I1IiiI - iIii1I11I1II1 + I1IiiI / I1ii11iIi11i
      if 5 - 5: iIii1I11I1II1 + o0oOOo0O0Ooo * I11i * iIii1I11I1II1 % oO0o - IiII
      if 19 - 19: I1ii11iIi11i % IiII + I1IiiI . II111iiii * i11iIiiIii
      if 21 - 21: iIii1I11I1II1 + iII111i % I11i
   for IIIIi1iI in ( O0O0OOOo0 ) :
    O0OoO0 = IIIIi1iI . print_eid_tuple ( )
    lprint ( "IGMP database entry {} {}" . format (
 green ( O0OoO0 , False ) , bold ( "timed out" , False ) ) )
    I1iii11IIi . source_cache . delete_cache ( IIIIi1iI . eid )
    if 20 - 20: OoO0O00 + OoOoOO00 / II111iiii - ooOoO0o * I1IiiI
    if 81 - 81: oO0o % OoOoOO00 % IiII
    if 3 - 3: i11iIiiIii * IiII
    if 64 - 64: OoO0O00 % I1Ii111 / OoO0O00 - i1IIi
    if 46 - 46: OOooOOo + o0oOOo0O0Ooo
   if ( I1iii11IIi . source_cache . cache_size ( ) == 0 ) :
    lprint ( "Removing empty IGMP group database entry {}" . format (
 green ( I1iii11IIi . group . print_address ( ) , False ) ) )
    lisp_db_for_lookups . delete_cache ( I1iii11IIi . group )
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
lisp_geid = lisp_address ( LISP_AFI_IPV4 , "" , 32 , 0 )
if 81 - 81: Oo0Ooo + OOooOOo + i1IIi % OOooOOo % iIii1I11I1II1
def lisp_glean_map_cache ( seid , rloc , encap_port , igmp ) :
 if 47 - 47: OoooooooOO / oO0o
 if 100 - 100: i11iIiiIii % o0oOOo0O0Ooo * I1ii11iIi11i . I11i
 if 31 - 31: I1Ii111
 if 59 - 59: i1IIi + OOooOOo * OOooOOo
 if 42 - 42: OoooooooOO * oO0o % II111iiii * ooOoO0o - oO0o
 if 52 - 52: Ii1I . I1Ii111 * OoooooooOO
 iIIii = True
 IIII1 = lisp_map_cache . lookup_cache ( seid , True )
 if ( IIII1 and len ( IIII1 . rloc_set ) != 0 ) :
  IIII1 . last_refresh_time = lisp_get_timestamp ( )
  if 56 - 56: OOooOOo + iII111i * I1Ii111
  oo0oooo0o0o = IIII1 . rloc_set [ 0 ]
  I1IiIii111IiI = oo0oooo0o0o . rloc
  I1II11 = oo0oooo0o0o . translated_port
  iIIii = ( I1IiIii111IiI . is_exact_match ( rloc ) == False or
 I1II11 != encap_port )
  if 53 - 53: O0
  if ( iIIii ) :
   oOO = green ( seid . print_address ( ) , False )
   IIi1iii = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
   lprint ( "Change gleaned EID {} to RLOC {}" . format ( oOO , IIi1iii ) )
   oo0oooo0o0o . delete_from_rloc_probe_list ( IIII1 . eid , IIII1 . group )
   lisp_change_gleaned_multicast ( seid , rloc , encap_port )
   if 3 - 3: I1IiiI
 else :
  IIII1 = lisp_mapping ( "" , "" , [ ] )
  IIII1 . eid . copy_address ( seid )
  IIII1 . mapping_source . copy_address ( rloc )
  IIII1 . map_cache_ttl = LISP_GLEAN_TTL
  IIII1 . gleaned = True
  oOO = green ( seid . print_address ( ) , False )
  IIi1iii = red ( rloc . print_address_no_iid ( ) + ":" + str ( encap_port ) , False )
  lprint ( "Add gleaned EID {} to map-cache with RLOC {}" . format ( oOO , IIi1iii ) )
  IIII1 . add_cache ( )
  if 8 - 8: OoO0O00 - OoO0O00 % I11i + O0 * OOooOOo / O0
  if 6 - 6: I1Ii111 * I1Ii111 / oO0o . Oo0Ooo - OoO0O00
  if 68 - 68: i1IIi % i1IIi + OoO0O00 / i1IIi
  if 46 - 46: i11iIiiIii
  if 19 - 19: iIii1I11I1II1 - OoooooooOO - iIii1I11I1II1 + Ii1I - iII111i
 if ( iIIii ) :
  oO0o0 = lisp_rloc ( )
  oO0o0 . store_translated_rloc ( rloc , encap_port )
  oO0o0 . add_to_rloc_probe_list ( IIII1 . eid , IIII1 . group )
  oO0o0 . priority = 253
  oO0o0 . mpriority = 255
  o0O00ooOo = [ oO0o0 ]
  IIII1 . rloc_set = o0O00ooOo
  IIII1 . build_best_rloc_set ( )
  if 29 - 29: iIii1I11I1II1 / II111iiii * ooOoO0o . II111iiii
  if 71 - 71: I1Ii111 / II111iiii / I11i
  if 71 - 71: OoooooooOO
  if 97 - 97: O0 * II111iiii - Oo0Ooo + OoooooooOO - Ii1I - IiII
  if 71 - 71: O0 + O0 + I11i . O0 % Oo0Ooo / o0oOOo0O0Ooo
 if ( igmp == None ) : return
 if 70 - 70: O0 + O0 * iII111i / o0oOOo0O0Ooo - oO0o
 if 54 - 54: O0 + Oo0Ooo - II111iiii / Ii1I % i1IIi / iII111i
 if 52 - 52: I1Ii111
 if 6 - 6: I1Ii111 + OoOoOO00
 if 1 - 1: o0oOOo0O0Ooo % OoooooooOO / Oo0Ooo % II111iiii + ooOoO0o
 lisp_geid . instance_id = seid . instance_id
 if 41 - 41: OoOoOO00 + o0oOOo0O0Ooo - OoooooooOO
 if 64 - 64: OoO0O00 + I1Ii111
 if 6 - 6: O0 / II111iiii / I1Ii111 / I11i / oO0o / oO0o
 if 49 - 49: iII111i - o0oOOo0O0Ooo / OoO0O00 + ooOoO0o
 if 49 - 49: I1IiiI
 Oo0oO = lisp_process_igmp_packet ( igmp )
 if ( Oo0oO == [ ] ) : return
 if 85 - 85: OOooOOo . II111iiii - OoO0O00 % O0 / iIii1I11I1II1 . I1IiiI
 for ooOO0O0O , i1I1IIIiII , Ii1Ii1IiI1ii in Oo0oO :
  if ( ooOO0O0O != None ) : continue
  if 21 - 21: i11iIiiIii + I1IiiI . ooOoO0o % IiII
  if 76 - 76: IiII . I1ii11iIi11i + Oo0Ooo % Ii1I % Oo0Ooo + IiII
  if 87 - 87: I1ii11iIi11i . IiII * i1IIi + OoooooooOO + OoOoOO00 % Oo0Ooo
  if 26 - 26: OoooooooOO % OoO0O00
  lisp_geid . store_address ( i1I1IIIiII )
  o0OO0 , O0O0oOO , Ooooo00OO = lisp_allow_gleaning ( seid , lisp_geid , rloc )
  if ( o0OO0 == False ) : continue
  if 23 - 23: iII111i * iII111i + oO0o - O0
  if ( Ii1Ii1IiI1ii ) :
   lisp_build_gleaned_multicast ( seid , lisp_geid , rloc , encap_port ,
 True )
  else :
   lisp_remove_gleaned_multicast ( seid , lisp_geid )
   if 96 - 96: Ii1I / ooOoO0o % I1IiiI / i1IIi
   if 19 - 19: Ii1I + i11iIiiIii - i1IIi
   if 92 - 92: ooOoO0o / oO0o % Ii1I / OOooOOo / Ii1I
   if 18 - 18: ooOoO0o % OOooOOo . IiII * i11iIiiIii + Oo0Ooo
   if 52 - 52: oO0o * oO0o / Ii1I
   if 6 - 6: OOooOOo . I1IiiI . I11i
   if 94 - 94: o0oOOo0O0Ooo % II111iiii - I1Ii111 * OOooOOo
   if 87 - 87: i1IIi
   if 78 - 78: I1ii11iIi11i
   if 89 - 89: OoooooooOO
   if 21 - 21: oO0o . OoOoOO00 - O0 - I11i % I1Ii111
   if 39 - 39: Oo0Ooo + OoOoOO00
def lisp_is_json_telemetry ( json_string ) :
 try :
  iiiI1i = json . loads ( json_string )
  if ( type ( iiiI1i ) != dict ) : return ( None )
 except :
  lprint ( "Could not decode telemetry json: {}" . format ( json_string ) )
  return ( None )
  if 58 - 58: I1Ii111 % OoO0O00 / IiII - oO0o - I1IiiI
  if 44 - 44: Oo0Ooo - O0 + I1ii11iIi11i / II111iiii - Oo0Ooo
 if ( "type" not in iiiI1i ) : return ( None )
 if ( "sub-type" not in iiiI1i ) : return ( None )
 if ( iiiI1i [ "type" ] != "telemetry" ) : return ( None )
 if ( iiiI1i [ "sub-type" ] != "timestamps" ) : return ( None )
 return ( iiiI1i )
 if 57 - 57: i1IIi
 if 46 - 46: I1Ii111 * OoOoOO00 . i1IIi * i1IIi * o0oOOo0O0Ooo / I11i
 if 27 - 27: Ii1I + iII111i - I11i / I1Ii111
 if 51 - 51: O0 / i11iIiiIii . II111iiii
 if 74 - 74: OoO0O00 . OoooooooOO / iIii1I11I1II1 . I1Ii111 * I1ii11iIi11i
 if 59 - 59: OOooOOo / I1ii11iIi11i + I1Ii111
 if 65 - 65: o0oOOo0O0Ooo % o0oOOo0O0Ooo * i11iIiiIii % Oo0Ooo % oO0o / Ii1I
 if 18 - 18: oO0o
 if 39 - 39: OOooOOo
 if 17 - 17: II111iiii
 if 52 - 52: ooOoO0o + OOooOOo * i1IIi / i1IIi * O0
 if 70 - 70: o0oOOo0O0Ooo / Ii1I
def lisp_encode_telemetry ( json_string , ii = "?" , io = "?" , ei = "?" , eo = "?" ) :
 iiiI1i = lisp_is_json_telemetry ( json_string )
 if ( iiiI1i == None ) : return ( json_string )
 if 67 - 67: IiII + ooOoO0o
 if ( iiiI1i [ "itr-in" ] == "?" ) : iiiI1i [ "itr-in" ] = ii
 if ( iiiI1i [ "itr-out" ] == "?" ) : iiiI1i [ "itr-out" ] = io
 if ( iiiI1i [ "etr-in" ] == "?" ) : iiiI1i [ "etr-in" ] = ei
 if ( iiiI1i [ "etr-out" ] == "?" ) : iiiI1i [ "etr-out" ] = eo
 json_string = json . dumps ( iiiI1i )
 return ( json_string )
 if 20 - 20: iIii1I11I1II1 % ooOoO0o * O0 * iIii1I11I1II1 * OOooOOo * OoO0O00
 if 36 - 36: iIii1I11I1II1 . OoO0O00 % iIii1I11I1II1 / ooOoO0o / II111iiii + oO0o
 if 97 - 97: i11iIiiIii + OoooooooOO + O0 + o0oOOo0O0Ooo / ooOoO0o
 if 96 - 96: O0
 if 93 - 93: II111iiii + Oo0Ooo * OOooOOo
 if 15 - 15: ooOoO0o
 if 85 - 85: OOooOOo
 if 5 - 5: II111iiii - OoooooooOO - O0
 if 54 - 54: iIii1I11I1II1 / OoooooooOO / OoO0O00 / o0oOOo0O0Ooo
 if 42 - 42: Ii1I
 if 8 - 8: oO0o
 if 68 - 68: oO0o . II111iiii * oO0o
def lisp_decode_telemetry ( json_string ) :
 iiiI1i = lisp_is_json_telemetry ( json_string )
 if ( iiiI1i == None ) : return ( { } )
 return ( iiiI1i )
 if 9 - 9: Oo0Ooo - O0 % IiII - OoOoOO00 * OOooOOo . Ii1I
 if 49 - 49: II111iiii % Ii1I * OOooOOo % OOooOOo
 if 88 - 88: i1IIi / OoooooooOO - I1IiiI - II111iiii * OoooooooOO
 if 34 - 34: OoOoOO00 - iIii1I11I1II1 - Oo0Ooo * o0oOOo0O0Ooo % O0 * i11iIiiIii
 if 82 - 82: IiII - Oo0Ooo + I1Ii111 - O0
 if 46 - 46: i1IIi
 if 55 - 55: I1Ii111 . I1IiiI % o0oOOo0O0Ooo
 if 44 - 44: i11iIiiIii
 if 81 - 81: Ii1I
def lisp_telemetry_configured ( ) :
 if ( "telemetry" not in lisp_json_list ) : return ( None )
 if 63 - 63: OoooooooOO % oO0o / i11iIiiIii
 Oo000 = lisp_json_list [ "telemetry" ] . json_string
 if ( lisp_is_json_telemetry ( Oo000 ) == None ) : return ( None )
 if 16 - 16: OoO0O00 % OoOoOO00 / i1IIi - ooOoO0o % II111iiii % II111iiii
 return ( Oo000 )
 if 10 - 10: I1ii11iIi11i . II111iiii
 if 28 - 28: iIii1I11I1II1 * I1ii11iIi11i % OOooOOo % I11i * i11iIiiIii
 if 91 - 91: I11i * II111iiii - I11i + iII111i + OoOoOO00 - IiII
 if 23 - 23: I11i - OoOoOO00
 if 42 - 42: ooOoO0o * OoooooooOO / iIii1I11I1II1 / i1IIi . I1Ii111 . Oo0Ooo
 if 73 - 73: O0 % iII111i * i11iIiiIii
 if 89 - 89: oO0o * I1ii11iIi11i . ooOoO0o . IiII
def lisp_mr_or_pubsub ( action ) :
 return ( action in [ LISP_SEND_MAP_REQUEST_ACTION , LISP_SEND_PUBSUB_ACTION ] )
 if 8 - 8: IiII
 if 80 - 80: I1ii11iIi11i . IiII % OoO0O00 * I1IiiI
 if 4 - 4: O0 - IiII + i1IIi * iIii1I11I1II1 * i1IIi - OOooOOo
 if 20 - 20: ooOoO0o % OoOoOO00 . I11i
# dd678faae9ac167bc83abf78e5cb2f3f0688d3a3
