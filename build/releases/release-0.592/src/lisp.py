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
standard_library.install_aliases()
from builtins import hex
from builtins import str
from builtins import int
from builtins import range
from builtins import object
from past.utils import old_div
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
from Crypto.Cipher import AES
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

#
# For printing the lisp_rloc_probe_list{}.
#
lisp_print_rloc_probe_list = False

#------------------------------------------------------------------------------

#
# Global variables.
#
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

lisp_map_notify_queue = {}   # Key is concat of nonce and etr address
lisp_map_servers_list = {}   # Key is ms-name/address string, value lisp_ms() 
lisp_ddt_map_requestQ = {}
lisp_db_list = []            # Elements are class lisp_mapping()
lisp_group_mapping_list = {} # Elements are class lisp_group_mapping()
lisp_map_resolvers_list = {} # Key is mr-name/address string, value lisp_mr() 
lisp_rtr_list = {}           # Key is address string, value is lisp_address()
lisp_elp_list = {}
lisp_rle_list = {}
lisp_geo_list = {}
lisp_json_list = {}
lisp_myrlocs = [None, None, None]
lisp_mymacs = {}

#
# Used for multi-tenancy. First dictionary array is indexed by device name
# and second one has value lisp_interface() indexed by a instance-id string.
#
lisp_myinterfaces = {}
lisp_iid_to_interface = {}
lisp_multi_tenant_interfaces = []

lisp_test_mr_timer = None
lisp_rloc_probe_timer = None

#
# Stats variables.
# 
lisp_registered_count = 0

#
# For tracking Map-Requesters behind NAT devices.
#
lisp_info_sources_by_address = {}
lisp_info_sources_by_nonce = {}

#
# Store computed keys per RLOC. The key is the nonce from the Map-Request 
# at the time creates the g, p, and public-key values. The value is an 
# array of 4 elements, indexed by key-id.
#
lisp_crypto_keys_by_nonce = {}
lisp_crypto_keys_by_rloc_encap = {}       # Key is "<rloc>:<port>" tuple
lisp_crypto_keys_by_rloc_decap = {}       # Key is "<rloc>:<port>" tuple
lisp_data_plane_security = False
lisp_search_decap_keys = True

lisp_data_plane_logging = False
lisp_frame_logging = False
lisp_flow_logging = False

#
# When NAT-traversal is enabled and lisp-crypto is enabled, an ITR needs
# to send RLOC-probe requests with an ephemeral port that is also used
# for data encapsulation to the RTR. This way the RTR can find the crypto
# key when multiple xTRs are behind the same NAT.
#
lisp_crypto_ephem_port = None

#
# Is the lisp-itr process running as a PITR?
#
lisp_pitr = False

#
# Are we listening on all MAC frames?
#
lisp_l2_overlay = False

#
# RLOC-probing variables. And for NAT-traversal, register only reachable
# RTRs which is determined from the lisp_rloc_probe_list.
#
lisp_rloc_probing = False
lisp_rloc_probe_list = {}
lisp_rloc_probe_nonce_list = {}

#
# Command "lisp xtr-parameters" register-reachabile-rtrs has opposite polarity
# to lisp_register_all_rtrs. So by default we do not consider RLOC-probing
# reachability status in registering RTRs to the mapping system.
#
lisp_register_all_rtrs = True

#
# Nonce Echo variables.
#
lisp_nonce_echoing = False
lisp_nonce_echo_list = {}

#
# xTR configuration parameters.
#
lisp_nat_traversal = False
lisp_decent_nat = False
LISP_TP = "@tp-"

#
# xTR configuration parameters. This flag is used to indicate that when a
# map-cache entry is created or updated, that we write specific information
# to say a Broadcom chip, that will do VXLAN encapsulation. This is a way
# to get existing hardware to do L3 overlays with the LISP control-plane
# when all it supports is VXLAN. See lisp_program_vxlan_hardware()
#
lisp_program_hardware = False

#
# Should we write to the lisp.checkpoint file.
#
lisp_checkpoint_map_cache = False
lisp_checkpoint_filename = "./lisp.checkpoint"

#
# Should we write map-cache entries to a named socket for another data-plane?
#
lisp_ipc_data_plane = False
lisp_ipc_dp_socket = None
lisp_ipc_dp_socket_name = "lisp-ipc-data-plane"

#
# This lock is used so the lisp-core process doesn't intermix command 
# processing data with show data and packet data.
#
lisp_ipc_lock = None

#
# Use this as a default instance-ID when there are no "lisp interface" commands
# configured. This default instance-ID is taken from the first database-mapping
# command.
#
lisp_default_iid = 0
lisp_default_secondary_iid = 0

#
# Configured list of RTRs that the lisp-core process will insert into
# Info-Reply messages.
#
lisp_ms_rtr_list = []                    # Array of type lisp.lisp_address()

#
# Used in an RTR to store a translated port for a translated RLOC. Key is
# hostname that is sent in a Info-Request is a nested array. See 
# lisp_store_nat_info() for details.
#
lisp_nat_state_info = {}

#
# Used for doing global rate-limiting of Map-Requests. When the process
# starts up or the map-cache is cleared by user we don't do rate-limiting for
# 1 minute so we can load up the cache quicker.
#
lisp_last_map_request_sent = None
lisp_no_map_request_rate_limit = time.time()

#
# Used for doing global rate-limiting of ICMP Too Big messages.
#
lisp_last_icmp_too_big_sent = 0

#
# Array to store 1000 flows.
#
LISP_FLOW_LOG_SIZE = 100
lisp_flow_log = []

#
# Store configured or API added policy parameters.
#
lisp_policies = {}

#
# Load-split pings. We'll has the first long of a ICMP echo-request and
# echo-reply for testing purposes. To show per packet load-splitting.
#
lisp_load_split_pings = False

#
# This array is a configured list of IPv6-prefixes that define what part
# of a matching address is used as the crypto-hash. They must be on 4-bit 
# boundaries for easy matching.
#
lisp_eid_hashes = []

#
# IPv4 reassembly buffer. We pcapture IPv4 fragments. They can come to the ETR
# when IPv6 is encapsulated in IPv4 and we have an MTU violation for the
# encapsulated packet. The array is index by the IPv4 ident field and contains
# an array of packet buffers. Once all fragments have arrived, the IP header
# is removed from all fragments except the first one.
#
lisp_reassembly_queue = {}

#
# Map-Server pubsub cache. Remember Map-Requesters that set the N-bit for
# a EID target it is requesting. Key is EID-prefix in string format with
# bracketed instance-ID included in slash format. The value of the dictionary
# array is a dictionary array of ITR addresses in string format.
#
lisp_pubsub_cache = {}

#
# When "decentralized-push-xtr = yes" is configured, the xTR is also running as
# a Map-Server and Map-Resolver. So Map-Register messages the ETR sends is
# looped back to the lisp-ms process.
#
lisp_decent_push_configured = False

#
# When "decentralized-pull-xtr-[modulus,dns-suffix] is configured, the xTR is
# also running as a Map-Server and Map-Resolver. So Map-Register messages the
# ETR sends is looped back to the lisp-ms process.
#
lisp_decent_modulus = 0
lisp_decent_dns_suffix = None

#
# lisp.lisp_ipc_socket is used by the lisp-itr process during RLOC-probing
# to send the lisp-etr process status about RTRs learned. This is part of
# NAT-traversal support.
#
lisp_ipc_socket = None

#
# Configured in the "lisp encryption-keys" command.
#
lisp_ms_encryption_keys = {}
lisp_ms_json_keys = {}

#
# Used to stare NAT translated address state in an RTR when a ltr client
# is sending RLOC-based LISP-Trace messages. If the RTR encounters any
# LISP-Trace error proessing called from lisp_rtr_data_plane() then it
# can return a partially filled LISP-Trace packet to the ltr client that
# site behind a NAT device.
#
# Dictiionary array format is:
#     key = self.local_addr + ":" + self.local_port
#     lisp_rtr_nat_trace_cache[key] = (translated_rloc, translated_port)
#
# And the array elements are added in lisp_trace.rtr_cache_nat_trace().
#
lisp_rtr_nat_trace_cache = {}

#
# Configured glean mappings. The data structure is an array of dictionary
# arrays with keywords "eid-prefix", "group-prefix", "rloc-prefix", and
# "instance-id". If keywords are not in dictionary array, the value is
# wildcarded. The values eid-prefix, group-prefix and rloc-prefix is
# lisp_address() so longest match lookups can be performed. The instance-id
# value is an array of 2 elements that store same value in both elements if
# not a range or the low and high range values.
#
lisp_glean_mappings = []

#
# Gleaned groups data structure. Used to find all (S,G) and (*,G) the gleaned
# EID has joined. This data structure will be used to time out entries that
# have stopped joining. In which case, the RLE is removed from the (S,G) or
# (*,G) that join timed out.
#
# The dictionary array is indexed by "[<iid>]<eid>" and the value field is a
# dictoinary array indexed by group address string. The value of the nested
# dictionay array is a timestamp. When EID 1.1.1.1 has joined groups 224.1.1.1,
# and 224.2.2.2, here is how timestamp 1111 and 2222 are stored.
#
# >>> lisp_gleaned_groups = {}
# >>> lisp_gleaned_groups["[1539]1.1.1.1"] = {}
# >>> lisp_gleaned_groups["[1539]1.1.1.1"]["224.1.1.1"] = 1111
# >>> lisp_gleaned_groups["[1539]1.1.1.1"]["224.2.2.2"] = 2222
# >>> lisp_gleaned_groups
# {'[1539]1.1.1.1': {'224.2.2.2': 2222, '224.1.1.1': 1111}}
#
lisp_gleaned_groups = {}

#
# Use this socket for all ICMP Too-Big messages sent by any process. We are
# centralizing it here.
#
lisp_icmp_raw_socket = None
if (os.getenv("LISP_SEND_ICMP_TOO_BIG") != None):
    lisp_icmp_raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
        socket.IPPROTO_ICMP)
    lisp_icmp_raw_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
#endif

lisp_ignore_df_bit = (os.getenv("LISP_IGNORE_DF_BIT") != None)

#------------------------------------------------------------------------------

#
# UDP ports used by LISP.
#
LISP_DATA_PORT       = 4341
LISP_CTRL_PORT       = 4342
LISP_L2_DATA_PORT    = 8472
LISP_VXLAN_DATA_PORT = 4789
LISP_VXLAN_GPE_PORT  = 4790
LISP_TRACE_PORT      = 2434

#
# Packet type definitions.
#
LISP_MAP_REQUEST    = 1
LISP_MAP_REPLY      = 2
LISP_MAP_REGISTER   = 3
LISP_MAP_NOTIFY     = 4
LISP_MAP_NOTIFY_ACK = 5
LISP_MAP_REFERRAL   = 6
LISP_NAT_INFO       = 7
LISP_ECM            = 8
LISP_TRACE          = 9

#
# Map-Reply action values.
#
LISP_NO_ACTION                 = 0
LISP_NATIVE_FORWARD_ACTION     = 1
LISP_SEND_MAP_REQUEST_ACTION   = 2
LISP_DROP_ACTION               = 3
LISP_POLICY_DENIED_ACTION      = 4
LISP_AUTH_FAILURE_ACTION       = 5
LISP_SEND_PUBSUB_ACTION        = 6
LISP_NOT_REGISTERED_YET_ACTION = 7

lisp_map_reply_action_string = ["no-action", "native-forward", 
    "send-map-request", "drop-action", "policy-denied",
    "auth-failure", "send-subscribe", "not-registered-yet"]

#
# Various HMACs alg-ids and lengths (in bytes) used by LISP.
#
LISP_NONE_ALG_ID            = 0
LISP_SHA_1_96_ALG_ID        = 1
LISP_SHA_256_128_ALG_ID     = 2
LISP_MD5_AUTH_DATA_LEN      = 16
LISP_SHA1_160_AUTH_DATA_LEN = 20
LISP_SHA2_256_AUTH_DATA_LEN = 32

#
# LCAF types as defined in draft-ietf-lisp-lcaf.
#
LISP_LCAF_NULL_TYPE        = 0
LISP_LCAF_AFI_LIST_TYPE    = 1
LISP_LCAF_INSTANCE_ID_TYPE = 2
LISP_LCAF_ASN_TYPE         = 3
LISP_LCAF_APP_DATA_TYPE    = 4
LISP_LCAF_GEO_COORD_TYPE   = 5
LISP_LCAF_OPAQUE_TYPE      = 6
LISP_LCAF_NAT_TYPE         = 7
LISP_LCAF_NONCE_LOC_TYPE   = 8
LISP_LCAF_MCAST_INFO_TYPE  = 9
LISP_LCAF_ELP_TYPE         = 10
LISP_LCAF_SECURITY_TYPE    = 11
LISP_LCAF_SOURCE_DEST_TYPE = 12
LISP_LCAF_RLE_TYPE         = 13
LISP_LCAF_JSON_TYPE        = 14
LISP_LCAF_KV_TYPE          = 15
LISP_LCAF_ENCAP_TYPE       = 16

#
# TTL constant definitions.
#
LISP_MR_TTL       = (24*60)
LISP_REGISTER_TTL = 3
LISP_SHORT_TTL    = 1
LISP_NMR_TTL      = 15
LISP_GLEAN_TTL    = 15
LISP_MCAST_TTL    = 15
LISP_IGMP_TTL     = 240

LISP_SITE_TIMEOUT_CHECK_INTERVAL     = 60  # In units of seconds, 1 minute
LISP_PUBSUB_TIMEOUT_CHECK_INTERVAL   = 60  # In units of seconds, 1 minute
LISP_REFERRAL_TIMEOUT_CHECK_INTERVAL = 60  # In units of seconds, 1 minute
LISP_TEST_MR_INTERVAL                = 60  # In units of seconds, 1 minute
LISP_MAP_NOTIFY_INTERVAL             = 2   # In units of seconds
LISP_DDT_MAP_REQUEST_INTERVAL        = 2   # In units of seconds
LISP_MAX_MAP_NOTIFY_RETRIES          = 3
LISP_INFO_INTERVAL                   = 15  # In units of seconds
LISP_MAP_REQUEST_RATE_LIMIT          = .5  # In units of seconds, 500 ms
LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME  = 60  # In units of seconds, 1 minute
LISP_ICMP_TOO_BIG_RATE_LIMIT         = 1   # In units of seconds
LISP_RLOC_PROBE_TTL                  = 64  # Typical default, don't change!
LISP_RLOC_PROBE_INTERVAL             = 10  # In units of seconds
LISP_RLOC_PROBE_REPLY_WAIT           = 15  # In units of seconds
LISP_DEFAULT_DYN_EID_TIMEOUT         = 15  # In units of seconds
LISP_NONCE_ECHO_INTERVAL             = 10 
LISP_IGMP_TIMEOUT_INTERVAL           = 180 # In units of seconds, 3 minutes

#
# Cipher Suites defined in RFC 8061:
#
# Cipher Suite 0:
#     Reserved
# 
#  Cipher Suite 1 (LISP_2048MODP_AES128_CBC_SHA256):
#     Diffie-Hellman Group: 2048-bit MODP [RFC3526]
#     Encryption:  AES with 128-bit keys in CBC mode [AES-CBC]
#     Integrity:   Integrated with AEAD_AES_128_CBC_HMAC_SHA_256 [AES-CBC]
#     IV length:   16 bytes
#     KDF:         HMAC-SHA-256
# 
#  Cipher Suite 2 (LISP_EC25519_AES128_CBC_SHA256):
#     Diffie-Hellman Group: 256-bit Elliptic-Curve 25519 [CURVE25519]
#     Encryption:  AES with 128-bit keys in CBC mode [AES-CBC]
#     Integrity:   Integrated with AEAD_AES_128_CBC_HMAC_SHA_256 [AES-CBC]
#     IV length:   16 bytes
#     KDF:         HMAC-SHA-256
# 
#  Cipher Suite 3 (LISP_2048MODP_AES128_GCM):
#     Diffie-Hellman Group: 2048-bit MODP [RFC3526]
#     Encryption:  AES with 128-bit keys in GCM mode [RFC5116]
#     Integrity:   Integrated with AEAD_AES_128_GCM [RFC5116]
#     IV length:   12 bytes
#     KDF:         HMAC-SHA-256
# 
#  Cipher Suite 4 (LISP_3072MODP_AES128_GCM):
#     Diffie-Hellman Group: 3072-bit MODP [RFC3526]
#     Encryption:  AES with 128-bit keys in GCM mode [RFC5116]
#     Integrity:   Integrated with AEAD_AES_128_GCM [RFC5116]
#     IV length:   12 bytes
#     KDF:         HMAC-SHA-256
# 
#  Cipher Suite 5 (LISP_256_EC25519_AES128_GCM):
#     Diffie-Hellman Group: 256-bit Elliptic-Curve 25519 [CURVE25519]
#     Encryption:  AES with 128-bit keys in GCM mode [RFC5116]
#     Integrity:   Integrated with AEAD_AES_128_GCM [RFC5116]
#     IV length:   12 bytes
#     KDF:         HMAC-SHA-256
# 
#  Cipher Suite 6 (LISP_256_EC25519_CHACHA20_POLY1305):
#     Diffie-Hellman Group: 256-bit Elliptic-Curve 25519 [CURVE25519]
#     Encryption: Chacha20-Poly1305 [CHACHA-POLY] [RFC7539]
#     Integrity:  Integrated with AEAD_CHACHA20_POLY1305 [CHACHA-POLY]
#     IV length:  8 bytes
#     KDF:        HMAC-SHA-256
#
LISP_CS_1024    = 0
LISP_CS_1024_G  = 2
LISP_CS_1024_P  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF

LISP_CS_2048_CBC   = 1
LISP_CS_2048_CBC_G = 2
LISP_CS_2048_CBC_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF

LISP_CS_25519_CBC = 2
LISP_CS_2048_GCM  = 3

LISP_CS_3072    = 4
LISP_CS_3072_G  = 2
LISP_CS_3072_P  = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF

LISP_CS_25519_GCM    = 5
LISP_CS_25519_CHACHA = 6

LISP_4_32_MASK   = 0xFFFFFFFF
LISP_8_64_MASK   = 0xFFFFFFFFFFFFFFFF
LISP_16_128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

use_chacha = (os.getenv("LISP_USE_CHACHA") != None)
use_poly = (os.getenv("LISP_USE_POLY") != None)

#------------------------------------------------------------------------------

#
# lisp_record_traceback
#
# Open ./logs/lisp-traceback.log file and write traceback info to it.
#
def lisp_record_traceback(*args):

    ts = datetime.datetime.now().strftime("%m/%d/%y %H:%M:%S.%f")[:-3]
    fd = open("./logs/lisp-traceback.log", "a")
    fd.write("---------- Exception occurred: {} ----------\n".format(ts))
    try:
        traceback.print_last(file=fd)
    except:
        fd.write("traceback.print_last(file=fd) failed")
    #endtry
    try:
        traceback.print_last()
    except:
        print("traceback.print_last() failed")
    #endtry
    fd.close()
    return
#enddef

#
# lisp_set_exception
#
# Set exception callback to call lisp.lisp_record_traceback().
#
def lisp_set_exception():
    sys.excepthook = lisp_record_traceback
    return
#enddef

#
# lisp_is_raspbian
#
# Return True if this system is running Raspbian on a Raspberry Pi machine.
#
def lisp_is_raspbian():
    if (distro.linux_distribution()[0] != "debian"): return(False)
    return(platform.machine() in ["armv6l", "armv7l"])
#enddef

#
# lisp_is_ubuntu
#
# Return True if this system is running Ubuntu Linux.
#
def lisp_is_ubuntu():
    return(distro.linux_distribution()[0] == "Ubuntu")
#enddef

#
# lisp_is_fedora
#
# Return True if this system is running Fedora Linux.
#
def lisp_is_fedora():
    return(distro.linux_distribution()[0] == "fedora")
#enddef

#
# lisp_is_centos
#
# Return True if this system is running CentOS Linux.
#
def lisp_is_centos():
    return(distro.linux_distribution()[0] == "centos")
#enddef

#
# lisp_is_debian
#
# Return True if this system is running Debian Jessie.
#
def lisp_is_debian():
    return(distro.linux_distribution()[0] == "debian")
#enddef

#
# lisp_is_debian
#
# Return True if this system is running Debian Jessie.
#
def lisp_is_debian_kali():
    return(distro.linux_distribution()[0] == "Kali")
#enddef

#
# lisp_is_macos
#
# Return True if this system is running MacOS operating system.
#
def lisp_is_macos():
    return(platform.uname()[0] == "Darwin")
#enddef

#
# lisp_is_alpine
#
# Return True if this system is running the Apline Linux operating system.
#
def lisp_is_alpine():
    return(os.path.exists("/etc/alpine-release"))
#enddef

#
# lisp_is_x86
#
# Return True if this process is an x86 little-endian machine.
#
def lisp_is_x86():
    cpu = platform.machine()
    return(cpu in ("x86", "i686", "x86_64"))
#enddef

#
# lisp_is_linux
#
# Return True if this is a ubuntu or fedora system.
#
def lisp_is_linux():
    return(platform.uname()[0] == "Linux")
#enddef

#
# lisp_is_python2
#
# Return True if this code is running Python 2.7.x.
#
def lisp_is_python2():
    ver = sys.version.split()[0]
    return(ver[0:3] == "2.7")
#enddef

#
# lisp_is_python3
#
# Return True if this code is running Python 3.x.x.
#
def lisp_is_python3():
    ver = sys.version.split()[0]
    return(ver[0:2] == "3.")
#enddef

#
# lisp_on_aws
#
# Return True if this node is running in an Amazon VM on AWS.
#
def lisp_on_aws():
    vm = getoutput("sudo dmidecode -s bios-version")
    if (vm.find("command not found") != -1 and lisp_on_docker()):
        aws = bold("AWS check", False)
        lprint("{} - dmidecode not installed in docker container".format(aws))
    #endif
    return(vm.lower().find("amazon") != -1)
#enddef

#
# lisp_on_gcp
#
# Return True if this node is running in an Google Compute Engine VM.
#
def lisp_on_gcp():
    vm = getoutput("sudo dmidecode -s bios-version")
    if (vm.find("command not found") != -1 and lisp_on_docker()):
        aws = bold("GCP check", False)
        lprint("{} - dmidecode not installed in docker container".format(aws))
    #endif
    return(vm.lower().find("google") != -1)
#enddef

#
# lisp_on_docker
#
# Are we in a docker container?
#
def lisp_on_docker():
    return(os.path.exists("/.dockerenv"))
#enddef

#
# lisp_process_logfile
#
# Check to see if logfile exists. If not, it is startup time to create one
# or another procedure rotated the file out of the directory.
#
def lisp_process_logfile():
    logfile = "./logs/lisp-{}.log".format(lisp_log_id)
    if (os.path.exists(logfile)): return

    sys.stdout.close()
    sys.stdout = open(logfile, "a")

    lisp_print_banner(bold("logfile rotation", False))
    return
#enddef

#
# lisp_i_am
#
# The individual components tell the libraries who they are so we can prefix
# the component name for print() and logs().
#
def lisp_i_am(name):
    global lisp_log_id, lisp_i_am_itr, lisp_i_am_etr, lisp_i_am_rtr
    global lisp_i_am_mr, lisp_i_am_ms, lisp_i_am_ddt, lisp_i_am_core
    global lisp_hostname

    lisp_log_id = name
    if (name == "itr"): lisp_i_am_itr = True
    if (name == "etr"): lisp_i_am_etr = True
    if (name == "rtr"): lisp_i_am_rtr = True
    if (name == "mr"): lisp_i_am_mr = True
    if (name == "ms"): lisp_i_am_ms = True
    if (name == "ddt"): lisp_i_am_ddt = True
    if (name == "core"): lisp_i_am_core = True

    #
    # Set hostname to normalize dino-macbook.local or dino-macbook.wp.comcast.
    # net to "dino-macbook".
    #
    lisp_hostname = socket.gethostname()
    index = lisp_hostname.find(".")
    if (index != -1): lisp_hostname = lisp_hostname[0:index]
    return
#enddef

#
# lprint
#
# Print with timestamp and component name prefixed. If "force" is any argument,
# then we don't care about the lisp_debug_logging setting and a log message
# is issued.
#
def lprint(*args):
    force = ("force" in args)
    if (lisp_debug_logging == False and force == False): return

    lisp_process_logfile()
    ts = datetime.datetime.now().strftime("%m/%d/%y %H:%M:%S.%f")
    ts = ts[:-3]
    print("{}: {}:".format(ts, lisp_log_id), end=" ")

    for arg in args:
        if (arg == "force"): continue
        print(arg, end=" ")
    #endfor
    print()
    
    try: sys.stdout.flush()
    except: pass
    return
#enddef

#
# fprint
#
# Do a lprint() when debug logging is off but "force" flag is supplied and
# can print messages..
#
def fprint(*args):
    nargs = args + ("force",)
    lprint(*nargs)
    return
#enddef

#
# dprint
#
# Data-plane logging. Call lprint() only if lisp.lisp_data_plane_logging is
# True.
#
def dprint(*args):
    if (lisp_data_plane_logging): lprint(*args)
    return
#enddef

#
# cprint
#
# Print the class instance.
#
def cprint(instance):
    print("{}:".format(instance))
    pprint.pprint(instance.__dict__)
#enddef

#
# debug
#
# Used for debugging. Used to find location of temporary "printf" code so it
# can be removed for production code.
#
def debug(*args):
    lisp_process_logfile()

    ts = datetime.datetime.now().strftime("%m/%d/%y %H:%M:%S.%f")
    ts = ts[:-3]

    print(red(">>>", False), end=" ")
    print("{}:".format(ts), end=" ")
    for arg in args: print(arg, end=" ")
    print(red("<<<\n", False))
    try: sys.stdout.flush()
    except: pass
    return
#enddef

#
# lisp_print_caller
#
# Print out calling stack.
#
def lisp_print_caller():
    fprint(traceback.print_last())
#enddef

#
# lisp_print_banner
#
# Print out startup and shutdown banner.
#
def lisp_print_banner(string):
    global lisp_version, lisp_hostname

    if (lisp_version == ""):
        lisp_version = getoutput("cat lisp-version.txt")
    #endif
    hn = bold(lisp_hostname, False)
    lprint("lispers.net LISP {} {}, version {}, hostname {}".format(string, 
        datetime.datetime.now(), lisp_version, hn))
    return
#enddef

#
# green
#
# For printing banner.
#
def green(string, html):
    if (html): return('<font color="green"><b>{}</b></font>'.format(string))
    return(bold("\033[92m" + string + "\033[0m", html))
#enddef

#
# green_last_sec
#
# For printing packets in the last 1 second.
#
def green_last_sec(string):
    return(green(string, True))
#enddef

#
# green_last_minute
#
# For printing packets in the last 1 minute.
#
def green_last_min(string):
    return('<font color="#58D68D"><b>{}</b></font>'.format(string))
#enddef

#
# red
#
# For printing banner.
#
def red(string, html):
    if (html): return('<font color="red"><b>{}</b></font>'.format(string))
    return(bold("\033[91m" + string + "\033[0m", html))
#enddef

#
# blue
#
# For printing distinguished-name AFIs.
#
def blue(string, html):
    if (html): return('<font color="blue"><b>{}</b></font>'.format(string))
    return(bold("\033[94m" + string + "\033[0m", html))
#enddef

#
# bold
#
# For printing banner.
#
def bold(string, html):
    if (html): return("<b>{}</b>".format(string))
    return("\033[1m" + string + "\033[0m")
#enddef

#
# convert_font
#
# Converts from text baesd bold/color to HTML bold/color.
#
def convert_font(string):
    escapes = [ ["[91m", red], ["[92m", green], ["[94m", blue], ["[1m", bold] ]
    right = "[0m"
    
    for e in escapes:
        left = e[0]
        color = e[1]
        offset = len(left)
        index = string.find(left)
        if (index != -1): break
    #endfor

    while (index != -1):
        end = string[index::].find(right)
        bold_string = string[index+offset:index+end]
        string = string[:index] + color(bold_string, True) + \
            string[index+end+offset::]
        index = string.find(left)
    #endwhile

    #
    # Call this function one more time if a color was in bold.
    #
    if (string.find("[1m") != -1): string = convert_font(string)
    return(string)
#enddef

#
# lisp_space
#
# Put whitespace in URL encoded string.
#
def lisp_space(num):
    output = ""
    for i in range(num): output += "&#160;"
    return(output)
#enddef

#
# lisp_button
#
# Return string of a LISP html button.
#
def lisp_button(string, url):
    b = '<button style="background-color:transparent;border-radius:10px; ' + \
        'type="button">'

    if (url == None):
        html = b + string + "</button>"
    else:
        a = '<a href="{}">'.format(url)
        s = lisp_space(2)
        html = s + a + b + string + "</button></a>" + s
    #endif
    return(html)
#enddef

#
# lisp_print_cour
#
# Print in HTML Courier-New font.
#
def lisp_print_cour(string):
    output = '<font face="Courier New">{}</font>'.format(string)
    return(output)
#enddef

#
# lisp_print_sans
#
# Print in HTML Sans-Serif font.
#
def lisp_print_sans(string):
    output = '<font face="Sans-Serif">{}</font>'.format(string)
    return(output)
#enddef

#
# lisp_span
#
# Print out string when a pointer hovers over some text.
#
def lisp_span(string, hover_string):
    output = '<span title="{}">{}</span>'.format(hover_string, string)
    return(output)
#enddef

#
# lisp_eid_help_hover
#
# Create hover title for any input EID form.
#
def lisp_eid_help_hover(output):
    eid_help_str = \
'''Unicast EID format:
  For longest match lookups: 
    <address> or [<iid>]<address>
  For exact match lookups: 
    <prefix> or [<iid>]<prefix>
Multicast EID format:
  For longest match lookups:
    <address>-><group> or
    [<iid>]<address>->[<iid>]<group>'''

    hover = lisp_span(output, eid_help_str)
    return(hover)
#enddef

#
# lisp_geo_help_hover
#
# Create hover title for any input Geo or EID form.
#
def lisp_geo_help_hover(output):
    eid_help_str = \
'''EID format:
    <address> or [<iid>]<address>
    '<name>' or [<iid>]'<name>'
Geo-Point format:
    d-m-s-<N|S>-d-m-s-<W|E> or 
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>
Geo-Prefix format:
    d-m-s-<N|S>-d-m-s-<W|E>/<km> or
    [<iid>]d-m-s-<N|S>-d-m-s-<W|E>/<km>'''

    hover = lisp_span(output, eid_help_str)
    return(hover)
#enddef

#
# space
#
# Put whitespace in URL encoded string.
#
def space(num):
    output = ""
    for i in range(num): output += "&#160;"
    return(output)
#enddef

#
# lisp_get_ephemeral_port
#
# Select random UDP port for use of a source port in a Map-Request and 
# destination port in a Map-Reply.
#
def lisp_get_ephemeral_port():
    return(random.randrange(32768, 65535))
#enddef

#
# lisp_get_data_nonce
#
# Get a 24-bit random nonce to insert in data header.
#
def lisp_get_data_nonce():
    return(random.randint(0, 0xffffff))
#enddef

#
# lisp_get_control_nonce
#
# Get a 64-bit random nonce to insert in control packets.
#
def lisp_get_control_nonce():
    return(random.randint(0, (2**64)-1))
#enddef

#
# lisp_hex_string
#
# Take an integer, either 16, 32, or 64 bits in width and return a hex string.
# But don't return the leading "0x". And don't return a trailing "L" if the
# integer is a negative 64-bit value (high-order bit set).
#
def lisp_hex_string(integer_value):
    value = hex(integer_value)[2::]
    if (value[-1] == "L"): value = value[0:-1]
    return(value)
#enddef

#
# lisp_get_timestamp
#
# Use time library to get a current timestamp.
#
def lisp_get_timestamp():
    return(time.time())
#enddef
lisp_uptime = lisp_get_timestamp()

#
# lisp_set_timestamp
#
# Use time library to set time into the future.
#
def lisp_set_timestamp(seconds):
    return(time.time() + seconds)
#enddef

#
# lisp_print_elapsed
#
# Time value (variable ts) was created via time.time().
#
def lisp_print_elapsed(ts):
    if (ts == 0 or ts == None): return("never")
    elapsed = time.time() - ts
    elapsed = round(elapsed, 0)
    return(str(datetime.timedelta(seconds=elapsed)))
#enddef

#
# lisp_print_future
#
# Time value (variable ts) was created via time.time().
#
def lisp_print_future(ts):
    if (ts == 0): return("never")
    future = ts - time.time()
    if (future < 0): return("expired")
    future = round(future, 0)
    return(str(datetime.timedelta(seconds=future)))
#enddef

#
# lisp_print_eid_tuple
#
# Prints in html or returns a string of the following combinations:
#
#         [<iid>]<eid>/<ml>
#         <eid>/<ml>
#         ([<iid>]<source-eid>/ml, [<iid>]<group>/ml)
#
# This is called by most of the data structure classes as "print_eid_tuple()".
#
def lisp_print_eid_tuple(eid, group):
    eid_str = eid.print_prefix()
    if (group.is_null()): return(eid_str)

    group_str = group.print_prefix()
    iid = group.instance_id

    if (eid.is_null() or eid.is_exact_match(group)): 
        index = group_str.find("]") + 1
        return("[{}](*, {})".format(iid, group_str[index::]))
    #endif

    sg_str = eid.print_sg(group)
    return(sg_str)
#enddef

#
# lisp_convert_6to4
#
# IPC messages will store an IPv4 address in an IPv6 "::ffff:<ipv4-addr>"
# format since we have a udp46 tunnel open. Convert it an IPv4 address.
#
def lisp_convert_6to4(addr_str):
    if (addr_str.find("::ffff:") == -1): return(addr_str)
    addr = addr_str.split(":")
    return(addr[-1])
#enddef

#
# lisp_convert_4to6
#
# We are sending on a udp46 socket, so if the destination is IPv6
# we have an address format we can use. If destination is IPv4 we
# need to put the address in a IPv6 IPv4-compatible format.
#
# Returns a lisp_address().
#
def lisp_convert_4to6(addr_str):
    addr = lisp_address(LISP_AFI_IPV6, "", 128, 0)
    if (addr.is_ipv4_string(addr_str)): addr_str = "::ffff:" + addr_str
    addr.store_address(addr_str)
    return(addr)
#enddef

#
# lisp_gethostbyname
#
# Return an address if string is a name or address. If socket.gethostbyname()
# fails, try socekt.getaddrinfo(). We may be running on Alpine Linux which
# doesn't return DNS names with gethostbyname().
#
def lisp_gethostbyname(string):
    ipv4 = string.split(".")
    ipv6 = string.split(":")
    mac = string.split("-")

    if (len(ipv4) == 4):
        if (ipv4[0].isdigit() and ipv4[1].isdigit() and ipv4[2].isdigit() and
            ipv4[3].isdigit()): return(string)
    #endif
    if (len(ipv6) > 1):
        try:
            int(ipv6[0], 16)
            return(string)
        except:
            pass
        #endtry
    #endif

    #
    # Make sure there are hex digits between dashes, otherwise could be a
    # valid DNS name with dashes.
    #
    if (len(mac) == 3): 
        for i in range(3):
            try: int(mac[i], 16)
            except: break
        #endfor
    #endif

    try:
        addr = socket.gethostbyname(string)
        return(addr)
    except:
        if (lisp_is_alpine() == False): return("")
    #endtry

    #
    # Try different approach on Alpine.
    #
    try:
        addr = socket.getaddrinfo(string, 0)[0]
        if (addr[3] != string): return("")
        addr = addr[4][0]
    except:
        addr = ""
    #endtry
    return(addr)
#enddef

#
# lisp_ip_checksum
#
# Input to this function is 20-bytes in packed form. Calculate IP header
# checksum and place in byte 10 and byte 11 of header.
#
def lisp_ip_checksum(data, hdrlen=20):
    if (len(data) < hdrlen): 
        lprint("IPv4 packet too short, length {}".format(len(data)))
        return(data)
    #endif

    ip = binascii.hexlify(data) 

    #
    # Go 2-bytes at a time so we only have to fold carry-over once.
    #
    checksum = 0
    for i in range(0, hdrlen*2, 4):
        checksum += int(ip[i:i+4], 16)
    #endfor

    #
    # Add in carry and byte-swap.
    #
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    checksum = socket.htons(~checksum & 0xffff)

    #
    # Pack in 2-byte buffer and insert at bytes 10 and 11.
    #
    checksum = struct.pack("H", checksum)
    ip = data[0:10] + checksum + data[12::]
    return(ip)
#enddef

#
# lisp_icmp_checksum
#
# Checksum a ICMP Destination Unreachable Too Big message. It will staticly
# checksum 36 bytes.
#
def lisp_icmp_checksum(data):
    if (len(data) < 36): 
        lprint("ICMP packet too short, length {}".format(len(data)))
        return(data)
    #endif

    icmp = binascii.hexlify(data) 

    #
    # Go 2-bytes at a time so we only have to fold carry-over once.
    #
    checksum = 0
    for i in range(0, 36, 4):
        checksum += int(icmp[i:i+4], 16)
    #endfor

    #
    # Add in carry and byte-swap.
    #
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    checksum = socket.htons(~checksum & 0xffff)

    #
    # Pack in 2-byte buffer and insert at bytes 2 and 4.
    #
    checksum = struct.pack("H", checksum)
    icmp = data[0:2] + checksum + data[4::]
    return(icmp)
#enddef

#
# lisp_udp_checksum
#
# Calculate the UDP pseudo header checksum. The variable 'data' is a UDP
# packet buffer starting with the UDP header with the checksum field zeroed.
#
# What is returned is the UDP packet buffer with a non-zero/computed checksum.
#
# The UDP pseudo-header is prepended to the UDP packet buffer which the
# checksum runs over:
#
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   +                                                               +
#   |                                                               |
#   +                         Source Address                        +
#   |                                                               |
#   +                                                               +
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                                                               |
#   +                                                               +
#   |                                                               |
#   +                      Destination Address                      +
#   |                                                               |
#   +                                                               +
#   |                                                               |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                   Upper-Layer Packet Length                   |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      zero                     |  Next Header  |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
def lisp_udp_checksum(source, dest, data):

    #
    # Build pseudo-header for IPv6.
    #
    s = lisp_address(LISP_AFI_IPV6, source, LISP_IPV6_HOST_MASK_LEN, 0)
    d = lisp_address(LISP_AFI_IPV6, dest, LISP_IPV6_HOST_MASK_LEN, 0)
    udplen = socket.htonl(len(data))
    next_header = socket.htonl(LISP_UDP_PROTOCOL)
    pheader = s.pack_address()
    pheader += d.pack_address()
    pheader += struct.pack("II", udplen, next_header)

    #
    # Append UDP packet to pseudo-header. Add zeros to make 4 byte aligned.
    #
    udp = binascii.hexlify(pheader + data)
    add = len(udp) % 4
    for i in range(0,add): udp += "0"

    #
    # Go 2-bytes at a time so we only have to fold carry-over once.
    #
    checksum = 0
    for i in range(0, len(udp), 4):
        checksum += int(udp[i:i+4], 16)
    #endfor

    #
    # Add in carry and byte-swap.
    #
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    checksum = socket.htons(~checksum & 0xffff)

    #
    # Pack in 2-byte buffer and insert at last 2 bytes of UDP header.
    #
    checksum = struct.pack("H", checksum)
    udp = data[0:6] + checksum + data[8::]
    return(udp)
#enddef

#
# lisp_igmp_checksum
#
# Comppute IGMP checksum. This is specialzed for an IGMP query 12-byte
# header.
#
def lisp_igmp_checksum(igmp):
    g = binascii.hexlify(igmp) 

    #
    # Go 2-bytes at a time so we only have to fold carry-over once.
    #
    checksum = 0
    for i in range(0, 24, 4):
        checksum += int(g[i:i+4], 16)
    #endfor

    #
    # Add in carry and byte-swap.
    #
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    checksum = socket.htons(~checksum & 0xffff)

    #
    # Pack in 2-byte buffer and insert at bytes 10 and 11.
    #
    checksum = struct.pack("H", checksum)
    igmp = igmp[0:2] + checksum + igmp[4::]
    return(igmp)
#enddef

#
# lisp_get_interface_address
#
# Based on supplied interface device, return IPv4 local interface address.
#
def lisp_get_interface_address(device):

    #
    # Check for illegal device name.
    #
    if (device not in netifaces.interfaces()): return(None)

    #
    # Check if there are no IPv4 addresses assigned to interface.
    #
    addresses = netifaces.ifaddresses(device)
    if (netifaces.AF_INET not in addresses): return(None)

    #
    # Find first private address.
    #
    return_address = lisp_address(LISP_AFI_IPV4, "", 32, 0)

    for addr in addresses[netifaces.AF_INET]:
        addr_str = addr["addr"]
        return_address.store_address(addr_str)
        return(return_address)
    #endfor
    return(None)
#enddef

#
# lisp_get_input_interface
#
# Based on destination-MAC address of incoming pcap'ed packet, index into 
# lisp_mymacs{} to get a interface name string (device name) for all 
# interfaces that have the MAC address assigned.
#
# If dest-MAC is not us, look at source MAC to see if we are in a loopback
# situation testing application and xTR in the same system.
#
def lisp_get_input_interface(packet):
    p = lisp_format_packet(packet[0:12])
    macs = p.replace(" ", "")
    da = macs[0:12]
    sa = macs[12::]
    
    try: my_sa = (sa in lisp_mymacs)
    except: my_sa = False

    if (da in lisp_mymacs): return(lisp_mymacs[da], sa, da, my_sa)
    if (my_sa): return(lisp_mymacs[sa], sa, da, my_sa)
    return(["?"], sa, da, my_sa)
#enddef

#
# lisp_get_local_interfaces
#
# Go populate the lisp.myinterfaces{} dictionary array. Key is device ID
# returned by the netifaces API.
#
def lisp_get_local_interfaces():
    for device in netifaces.interfaces():
        interface = lisp_interface(device)
        interface.add_interface()
    #endfor
    return
#enddef

#
# lisp_get_loopback_address
#
# Get first loopback address on device lo which is not 127.0.0.1.
#
def lisp_get_loopback_address():
    for addr in netifaces.ifaddresses("lo")[netifaces.AF_INET]:
        if (addr["peer"] == "127.0.0.1"): continue
        return(addr["peer"])
    #endif
    return(None)
#enddef

#
# lisp_is_mac_string
#
# Return True if the supplied string parameter is iin form of "xxxx-xxxx-xxxx".
# The input prefix could be "xxxx-xxxx-xxxx/48".
#
def lisp_is_mac_string(mac_str):
    mac = mac_str.split("/")
    if (len(mac) == 2): mac_str = mac[0]
    return(len(mac_str) == 14 and mac_str.count("-") == 2)
#enddef

#
# lisp_get_local_macs
#
# Walk all interfaces, and for each ethernet interface, put the MAC address
# as a key into lisp_mymacs with a value of array of interface names.
#
def lisp_get_local_macs():
    for device in netifaces.interfaces():

        #
        # Ignore bogus interface names that containers may create. Allow
        # interfaces ones with colons, dashes and alphanumeric characters.
        #
        d = device.replace(":", "")
        d = device.replace("-", "")
        if (d.isalnum() == False): continue
        
        #
        # Need this for EOS because a "pimreg" interface will crash the call
        # to netifaces.ifaddresses("pimreg").
        #
        try:
            parms = netifaces.ifaddresses(device)
        except:
            continue
        #endtry
        if (netifaces.AF_LINK not in parms): continue
        mac = parms[netifaces.AF_LINK][0]["addr"]
        mac = mac.replace(":", "")

        #
        # GRE tunnels have strange MAC addresses (less than 48-bits). Ignore
        # them.
        #
        if (len(mac) < 12): continue

        if (mac not in lisp_mymacs): lisp_mymacs[mac] = []
        lisp_mymacs[mac].append(device)
    #endfor

    lprint("Local MACs are: {}".format(lisp_mymacs))
    return
#enddef

#
# lisp_get_local_rloc
#
# Use "ip addr show" on Linux and "ifconfig" on MacOS to get a local IPv4
# address. Get interface name from "netstat -rn" to grep for.
#
def lisp_get_local_rloc():
    out = getoutput("netstat -rn | egrep 'default|0.0.0.0'")
    if (out == ""): return(lisp_address(LISP_AFI_IPV4, "", 32, 0))

    #
    # Get last item on first line of output.
    #
    out = out.split("\n")[0]
    device = out.split()[-1]

    addr = ""
    macos = lisp_is_macos()
    if (macos):
        out = getoutput("ifconfig {} | egrep 'inet '".format(device))
        if (out == ""): return(lisp_address(LISP_AFI_IPV4, "", 32, 0))
    else:
        cmd = 'ip addr show | egrep "inet " | egrep "{}"'.format(device)
        out = getoutput(cmd)
        if (out == ""):
            cmd = 'ip addr show | egrep "inet " | egrep "global lo"'
            out = getoutput(cmd)
        #endif
        if (out == ""): return(lisp_address(LISP_AFI_IPV4, "", 32, 0))
    #endif

    #
    # Check for multi-line. And favor returning private address so NAT 
    # traversal is used in lig.
    #
    addr = ""
    out = out.split("\n")

    for line in out:
        a = line.split()[1]
        if (macos == False): a = a.split("/")[0]
        address = lisp_address(LISP_AFI_IPV4, a, 32, 0)
        return(address)
    #endif
    return(lisp_address(LISP_AFI_IPV4, addr, 32, 0))
#endif

#
# lisp_get_local_addresses
#
# Use netifaces module to get a IPv4 and IPv6 local RLOC of this system.
# Return an array of 2 elements where [0] is an IPv4 RLOC and [1] is an
# IPv6 RLOC.
#
# Stores data in lisp.lisp_myrlocs[].
#
def lisp_get_local_addresses():
    global lisp_myrlocs

    #
    # Check to see if we should not get the first address. Use environment
    # variable (1-based addressing) to determine which one to get. If the
    # number of addresses are less than the index, use the last one.
    #
    # The format of the environment variable could be <number> or 
    # <device>:<number>. The format could also be "<device>:" but make sure
    # the user typed in a ":".
    #
    device_select = None
    index = 1
    parm = os.getenv("LISP_ADDR_SELECT")
    if (parm != None and parm != ""):
        parm = parm.split(":")
        if (len(parm) == 2): 
            device_select = parm[0]
            index = parm[1]
        else:
            if (parm[0].isdigit()):
                index = parm[0]
            else:
                device_select = parm[0]
            #endif
        #endif
        index = 1 if (index == "") else int(index)
    #endif

    rlocs = [None, None, None]
    rloc4 = lisp_address(LISP_AFI_IPV4, "", 32, 0)
    rloc6 = lisp_address(LISP_AFI_IPV6, "", 128, 0)
    device_iid = None

    for device in netifaces.interfaces():
        if (device_select != None and device_select != device): continue
        addresses = netifaces.ifaddresses(device)
        if (addresses == {}): continue

        #
        # Set instance-ID for interface.
        #
        device_iid = lisp_get_interface_instance_id(device, None)

        #
        # Look for a non-link-local and non-loopback address.
        #
        if (netifaces.AF_INET in addresses):
            ipv4 = addresses[netifaces.AF_INET]
            count = 0
            for addr in ipv4:
                rloc4.store_address(addr["addr"])
                if (rloc4.is_ipv4_loopback()): continue
                if (rloc4.is_ipv4_link_local()): continue
                if (rloc4.address == 0): continue
                count += 1
                rloc4.instance_id = device_iid
                if (device_select == None and 
                    lisp_db_for_lookups.lookup_cache(rloc4, False)): continue
                rlocs[0] = rloc4
                if (count == index): break
            #endfor
        #endif
        if (netifaces.AF_INET6 in addresses):
            ipv6 = addresses[netifaces.AF_INET6]
            count = 0
            for addr in ipv6:
                addr_str = addr["addr"]
                rloc6.store_address(addr_str)
                if (rloc6.is_ipv6_string_link_local(addr_str)): continue
                if (rloc6.is_ipv6_loopback()): continue
                count += 1
                rloc6.instance_id = device_iid
                if (device_select == None and 
                    lisp_db_for_lookups.lookup_cache(rloc6, False)): continue
                rlocs[1] = rloc6
                if (count == index): break
            #endfor
        #endif

        #
        # Did we find an address? If not, loop and get the next interface.
        #
        if (rlocs[0] == None): continue

        rlocs[2] = device
        break
    #endfor

    addr1 = rlocs[0].print_address_no_iid() if rlocs[0] else "none"
    addr2 = rlocs[1].print_address_no_iid() if rlocs[1] else "none"
    device = rlocs[2] if rlocs[2] else "none"

    device_select = " (user selected)" if device_select != None else ""

    addr1 = red(addr1, False)
    addr2 = red(addr2, False)
    device = bold(device, False)
    lprint("Local addresses are IPv4: {}, IPv6: {} from device {}{}, iid {}". \
        format(addr1, addr2, device, device_select, device_iid))

    lisp_myrlocs = rlocs
    return((rlocs[0] != None))
#enddef

#
# lisp_get_all_addresses
#
# Return a list of all local IPv4 and IPv6 addresses from kernel. This is
# going to be used for building pcap and iptables filters. So no loopback or
# link-local addresses are returned.
#
def lisp_get_all_addresses():
    address_list = []
    for interface in netifaces.interfaces():
        try: entry = netifaces.ifaddresses(interface)
        except: continue

        if (netifaces.AF_INET in entry):
            for addr in entry[netifaces.AF_INET]:
                a = addr["addr"]
                if (a.find("127.0.0.1") != -1): continue
                address_list.append(a)
            #endfor
        #endif
        if (netifaces.AF_INET6 in entry):
            for addr in entry[netifaces.AF_INET6]:
                a = addr["addr"]
                if (a == "::1"): continue
                if (a[0:5] == "fe80:"): continue
                address_list.append(a)
            #endfor
        #endif
    #endfor
    return(address_list)
#enddef

#
# lisp_get_all_multicast_rles
#
# Grep lisp.config and get all multicast RLEs that appear in the configuration.
# Returns either an empty array or filled with one or more multicast addresses.
#
def lisp_get_all_multicast_rles():
    rles = []
    out = getoutput('egrep "rle-address =" ./lisp.config')
    if (out == ""): return(rles)

    lines = out.split("\n")
    for line in lines:
        if (line[0] == "#"): continue
        rle = line.split("rle-address = ")[1]
        rle_byte = int(rle.split(".")[0])
        if (rle_byte >= 224 and rle_byte < 240): rles.append(rle)
    #endfor
    return(rles)
#enddef

#------------------------------------------------------------------------------

#
# LISP packet contents. This keeps state for a LISP encapsulated packet that
# is processed by an RTR and ETR.
#
class lisp_packet(object):
    def __init__(self, packet):
        self.outer_source = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.outer_dest = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.outer_tos = 0
        self.outer_ttl = 0
        self.udp_sport = 0
        self.udp_dport = 0
        self.udp_length = 0
        self.udp_checksum = 0
        self.inner_source = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.inner_dest = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.inner_tos = 0
        self.inner_ttl = 0
        self.inner_protocol = 0
        self.inner_sport = 0
        self.inner_dport = 0
        self.lisp_header = lisp_data_header()
        self.packet = packet
        self.inner_version = 0
        self.outer_version = 0
        self.encap_port = LISP_DATA_PORT
        self.inner_is_fragment = False
        self.packet_error = ""
        self.gleaned_dest = False
    #enddef

    def encode(self, nonce):
        
        #
        # We could be running with no RLOCs found. If lisp_myrlocs[] is None,
        # then self.outer_source will be LISP_AFI_NONE.
        #
        if (self.outer_source.is_null()): return(None)

        #
        # We have to build the LISP header here because if we are doing 
        # lisp-crypto, the ICV covers the LISP header. The function 
        # lisp_packet.encrypt() will put in the key-id.
        #
        if (nonce == None):
            self.lisp_header.nonce(lisp_get_data_nonce())
        elif (self.lisp_header.is_request_nonce(nonce)):
            self.lisp_header.request_nonce(nonce)
        else:
            self.lisp_header.nonce(nonce)
        #endif
        self.lisp_header.instance_id(self.inner_dest.instance_id)

        #
        # Encrypt the packet. If something went wrong, send unencrypted packet
        # by telling RLOC with key-id 0. For now, just use key-id 1. We are
        # supporting just a single key.
        #
        self.lisp_header.key_id(0)
        control = (self.lisp_header.get_instance_id() == 0xffffff)
        if (lisp_data_plane_security and control == False):
            addr_str = self.outer_dest.print_address_no_iid() + ":" + \
                str(self.encap_port)
            if (addr_str in lisp_crypto_keys_by_rloc_encap):
                keys = lisp_crypto_keys_by_rloc_encap[addr_str]
                if (keys[1]):
                    keys[1].use_count += 1
                    packet, encrypted = self.encrypt(keys[1], addr_str)
                    if (encrypted): self.packet = packet
                #endif
            #endif
        #endif
        
        #
        # Start with UDP header. Call hash_packet() to set source-port value.
        # Unless we are doing lisp-crypto and nat-traversal.
        #
        self.udp_checksum = 0
        if (self.encap_port == LISP_DATA_PORT):
            if (lisp_crypto_ephem_port == None):
                if (self.gleaned_dest):
                    self.udp_sport = LISP_DATA_PORT
                else:
                    self.hash_packet()
                #endif
            else:
                self.udp_sport = lisp_crypto_ephem_port
            #endif
        else:
            self.udp_sport = LISP_DATA_PORT
        #endif
        self.udp_dport = self.encap_port
        self.udp_length = len(self.packet) + 16

        #
        # Swap UDP port numbers and length field since they are 16-bit values.
        #
        sport = socket.htons(self.udp_sport)
        dport = socket.htons(self.udp_dport)
        udp_len = socket.htons(self.udp_length)
        udp = struct.pack("HHHH", sport, dport, udp_len, self.udp_checksum)

        #
        # Encode the LISP header.
        #
        lisp = self.lisp_header.encode()

        #
        # Now prepend all 3 headers, LISP, UDP, outer header. See lisp_packet.
        # fix_outer_header() for byte-swap details for the frag-offset field.
        #
        if (self.outer_version == 4):
            tl = socket.htons(self.udp_length + 20)
            frag = socket.htons(0x4000)
            outer = struct.pack("BBHHHBBH", 0x45, self.outer_tos, tl, 0xdfdf, 
                frag, self.outer_ttl, 17, 0)
            outer += self.outer_source.pack_address()
            outer += self.outer_dest.pack_address()
            outer = lisp_ip_checksum(outer)
        elif (self.outer_version == 6):
            outer = b""
#           short = 6 << 12
#           short |= self.outer_tos << 4
#           short = socket.htons(short)
#           tl = socket.htons(self.udp_length)
#           outer = struct.pack("HHHBB", short, 0, tl, 17, self.outer_ttl)
#           outer += self.outer_source.pack_address()
#           outer += self.outer_dest.pack_address()
        else:
            return(None)
        #endif

        self.packet = outer + udp + lisp + self.packet
        return(self)
    #enddef

    def cipher_pad(self, packet):
        length = len(packet)
        if ((length % 16) != 0):
            pad = (old_div(length, 16) + 1) * 16
            packet = packet.ljust(pad)
        #endif
        return(packet)
    #enddef

    def encrypt(self, key, addr_str):
        if (key == None or key.shared_key == None): 
            return([self.packet, False])
        #endif

        #
        # Pad packet to multiple of 16 bytes and call AES cipher.
        #
        packet = self.cipher_pad(self.packet)
        iv = key.get_iv()

        ts = lisp_get_timestamp()
        aead = None
        encode_ciphertext = False
        if (key.cipher_suite == LISP_CS_25519_CHACHA):
            encrypt = chacha.ChaCha(key.encrypt_key, iv).encrypt
            encode_ciphertext = True
        elif (key.cipher_suite == LISP_CS_25519_GCM):
            k = binascii.unhexlify(key.encrypt_key)
            try:
                aesgcm = AES.new(k, AES.MODE_GCM, iv)
                encrypt = aesgcm.encrypt
                aead = aesgcm.digest
            except:
                lprint("You need AES-GCM, do a 'pip install pycryptodome'")
                return([self.packet, False])
            #endtry
        else:
            k = binascii.unhexlify(key.encrypt_key)
            encrypt = AES.new(k, AES.MODE_CBC, iv).encrypt
        #endif

        ciphertext = encrypt(packet)

        if (ciphertext == None): return([self.packet, False])
        ts = int(str(time.time() - ts).split(".")[1][0:6])

        #
        # Chacha produced ciphertext in unicode for py2. Convert to raw-
        # unicode-escape before proceeding, or else you can append to strings
        # generated from different sources. Do this in do_icv() too.
        #
        if (encode_ciphertext):
            ciphertext = ciphertext.encode("raw_unicode_escape")
        #endif

        #
        # GCM requires 16 bytes of an AEAD MAC tag at the end of the
        # ciphertext. Needed to interoperate with the Go implemenation of
        # AES-GCM. The MAC digest was computed above.
        #
        if (aead != None): ciphertext += aead()
        
        #
        # Compute ICV and append to packet. ICV covers the LISP header, the
        # IV, and the cipertext.
        #
        self.lisp_header.key_id(key.key_id)
        lisp = self.lisp_header.encode()

        icv = key.do_icv(lisp + iv + ciphertext, iv)

        ps = 4 if (key.do_poly) else 8

        string = bold("Encrypt", False)
        cipher_str = bold(key.cipher_suite_string, False)
        addr_str = "RLOC: " + red(addr_str, False)
        auth = "poly" if key.do_poly else "sha256"
        auth = bold(auth, False)
        icv_str = "ICV({}): 0x{}...{}".format(auth, icv[0:ps], icv[-ps::])
        dprint("{} for key-id: {}, {}, {}, {}-time: {} usec".format( \
            string, key.key_id, addr_str, icv_str, cipher_str, ts))

        icv = int(icv, 16)
        if (key.do_poly):
            icv1 = byte_swap_64((icv >> 64) & LISP_8_64_MASK)
            icv2 = byte_swap_64(icv & LISP_8_64_MASK)
            icv = struct.pack("QQ", icv1, icv2)
        else:
            icv1 = byte_swap_64((icv >> 96) & LISP_8_64_MASK)
            icv2 = byte_swap_64((icv >> 32) & LISP_8_64_MASK)
            icv3 = socket.htonl(icv & 0xffffffff)
            icv = struct.pack("QQI", icv1, icv2, icv3)
        #endif

        return([iv + ciphertext + icv, True])
    #enddef

    def decrypt(self, packet, header_length, key, addr_str):

        #
        # Do ICV first. If it succeeds, then decrypt. Get ICV from packet and
        # truncate packet to run hash over. Compare packet hash with computed
        # hash.
        #
        if (key.do_poly):
            icv1, icv2 = struct.unpack("QQ", packet[-16::])
            packet_icv = byte_swap_64(icv1) << 64
            packet_icv |= byte_swap_64(icv2)
            packet_icv = lisp_hex_string(packet_icv).zfill(32)
            packet = packet[0:-16]
            ps = 4
            hash_str = bold("poly", False)
        else:
            icv1, icv2, icv3 = struct.unpack("QQI", packet[-20::])
            packet_icv = byte_swap_64(icv1) << 96
            packet_icv |= byte_swap_64(icv2) << 32
            packet_icv |= socket.htonl(icv3)
            packet_icv = lisp_hex_string(packet_icv).zfill(40)
            packet = packet[0:-20]
            ps = 8
            hash_str = bold("sha", False)
        #endif
        lisp = self.lisp_header.encode()

        #
        # Get the IV and use it to decrypt and authenticate..
        #
        if (key.cipher_suite == LISP_CS_25519_CHACHA):
            iv_len = 8
            cipher_str = bold("chacha", False)
        elif (key.cipher_suite == LISP_CS_25519_GCM):
            iv_len = 12
            cipher_str = bold("aes-gcm", False)
        else:
            iv_len = 16
            cipher_str = bold("aes-cbc", False)
        #endif
        iv = packet[0:iv_len]

        #
        # Compute ICV over LISP header and packet payload.
        #
        computed_icv = key.do_icv(lisp + packet, iv)

        p_icv = "0x{}...{}".format(packet_icv[0:ps], packet_icv[-ps::])
        c_icv = "0x{}...{}".format(computed_icv[0:ps], computed_icv[-ps::])

        if (computed_icv != packet_icv):
            self.packet_error = "ICV-error"
            funcs = cipher_str + "/" + hash_str
            fail = bold("ICV failed ({})".format(funcs), False)
            icv_str = "packet-ICV {} != computed-ICV {}".format(p_icv, c_icv)
            dprint(("{} from RLOC {}, receive-port: {}, key-id: {}, " + \
                "packet dropped, {}").format(fail, red(addr_str, False),
                 self.udp_sport, key.key_id, icv_str))
            dprint("{}".format(key.print_keys()))

            #
            # This is the 4-tuple NAT case. There another addr:port that
            # should have the crypto-key the encapsulator is using. This is
            # typically done on the RTR.
            #
            lisp_retry_decap_keys(addr_str, lisp + packet, iv, packet_icv)
            return([None, False])
        #endif

        #
        # Advance over IV for decryption.
        #
        packet = packet[iv_len::]

        #
        # Call AES or chacha cipher. Make sure for AES that
        #
        ts = lisp_get_timestamp()
        if (key.cipher_suite == LISP_CS_25519_CHACHA):
            decrypt = chacha.ChaCha(key.encrypt_key, iv).decrypt
        elif (key.cipher_suite == LISP_CS_25519_GCM):
            k = binascii.unhexlify(key.encrypt_key)
            try:
                decrypt = AES.new(k, AES.MODE_GCM, iv).decrypt
            except:
                self.packet_error = "no-decrypt-key"
                lprint("You need AES-GCM, do a 'pip install pycryptodome'")
                return([None, False])
            #endtry
        else:
            if ((len(packet) % 16) != 0):
                dprint("Ciphertext not multiple of 16 bytes, packet dropped")
                return([None, False])
            #endif
            k = binascii.unhexlify(key.encrypt_key)
            decrypt = AES.new(k, AES.MODE_CBC, iv).decrypt
        #endif

        plaintext = decrypt(packet)
        ts = int(str(time.time() - ts).split(".")[1][0:6])

        #
        # Now decrypt packet and return plaintext payload.
        #
        string = bold("Decrypt", False)
        addr_str = "RLOC: " + red(addr_str, False)
        auth = "poly" if key.do_poly else "sha256"
        auth = bold(auth, False)
        icv_str = "ICV({}): {}".format(auth, p_icv)
        dprint("{} for key-id: {}, {}, {} (good), {}-time: {} usec". \
            format(string, key.key_id, addr_str, icv_str, cipher_str, ts))

        #
        # Keep self.packet the outer header, UDP header, and LISP header.
        # We will append the plaintext in the caller once we parse the inner
        # packet length so we can truncate any padding the encryptor put on.
        #
        self.packet = self.packet[0:header_length]
        return([plaintext, True])
    #enddef
    
    def fragment_outer(self, outer_hdr, inner_packet):
        frag_len = 1000

        #
        # Break up packet payload in fragments and put in array to have 
        # IP header added in next loop below.
        #
        frags = []
        offset = 0
        length = len(inner_packet)
        while (offset < length):
            frag = inner_packet[offset::]
            if (len(frag) > frag_len): frag = frag[0:frag_len]
            frags.append(frag)
            offset += len(frag)
        #endwhile

        #
        # Now fix outer IPv4 header with fragment-offset values and add the
        # IPv4 value.
        #
        fragments = []
        offset = 0
        for frag in frags:

            #
            # Set frag-offset field in outer IPv4 header.
            #
            fo = offset if (frag == frags[-1]) else 0x2000 + offset
            fo = socket.htons(fo)
            outer_hdr = outer_hdr[0:6] + struct.pack("H", fo) + outer_hdr[8::]

            #
            # Set total-length field in outer IPv4 header and checksum.
            #
            l = socket.htons(len(frag) + 20)
            outer_hdr = outer_hdr[0:2] + struct.pack("H", l) + outer_hdr[4::]
            outer_hdr = lisp_ip_checksum(outer_hdr)
            fragments.append(outer_hdr + frag)
            offset += len(frag) / 8
        #endfor
        return(fragments)
    #enddef

    def send_icmp_too_big(self, inner_packet):
        global lisp_last_icmp_too_big_sent
        global lisp_icmp_raw_socket
        
        elapsed = time.time() - lisp_last_icmp_too_big_sent
        if (elapsed < LISP_ICMP_TOO_BIG_RATE_LIMIT):
            lprint("Rate limit sending ICMP Too-Big to {}".format( \
                self.inner_source.print_address_no_iid()))
            return(False)
        #endif

        #
        #   Destination Unreachable Message - Too Big Message
        #
        #    0                   1                   2                   3
        #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #   |    Type = 3   |   Code = 4    |          Checksum             |
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #   |            unused             |          MTU = 1400           |
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #   |      Internet Header + 64 bits of Original Data Datagram      |
        #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        #
        mtu = socket.htons(1400)
        icmp = struct.pack("BBHHH", 3, 4, 0, 0, mtu)
        icmp += inner_packet[0:20+8]
        icmp = lisp_icmp_checksum(icmp)

        #
        # Build IP header. Make source of ICMP invoking packet the destination
        # and our address the source. We can get our address when we thought
        # we could encap. So lisp_packet.outer_source has the RLOC address of
        # this system.
        #
        host = inner_packet[12:16]
        dest = self.inner_source.print_address_no_iid()
        me = self.outer_source.pack_address()

        #
        # IP_HDRINCL requires the total-length and frag-offset fields to be
        # host byte order. We need to build the total-length field just like
        # lisp_packet.encode(), checksum, and then fix outer header. So that
        # logic is semantically repliciated here. Same logic is in lisp_packet.
        # fragment() as well.
        #
        tl = socket.htons(20+36)
        ip = struct.pack("BBHHHBBH", 0x45, 0, tl, 0, 0, 32, 1, 0) + me + host
        ip = lisp_ip_checksum(ip)
        ip = self.fix_outer_header(ip)
        ip += icmp
        tb = bold("Too-Big", False)
        lprint("Send ICMP {} to {}, mtu 1400: {}".format(tb, dest,
            lisp_format_packet(ip)))

        try:
            lisp_icmp_raw_socket.sendto(ip, (dest, 0))
        except socket.error as e:
            lprint("lisp_icmp_raw_socket.sendto() failed: {}".format(e))
            return(False)
        #endtry

        #
        # Caller function sends packet on raw socket. Kernel routes out
        # interface to destination.
        #
        lisp_last_icmp_too_big_sent = lisp_get_timestamp()
        return(True)

    def fragment(self):
        global lisp_icmp_raw_socket
        global lisp_ignore_df_bit
        
        packet = self.fix_outer_header(self.packet)

        #
        # If inner header is IPv4, we will fragment the inner header and encap
        # each fragment. If the inner header is IPv6, we will not add the
        # Fragmentation Header into the inner IPv6 packet.
        #
        length = len(packet)
        if (length <= 1500): return([packet], "Fragment-None")

        packet = self.packet

        #
        # Fragment outer IPv4 header if inner packet is IPv6 (or Mac frame). 
        # We cannot fragment IPv6 packet since we are not the source.
        #
        if (self.inner_version != 4):
            ident = random.randint(0, 0xffff)
            outer_hdr = packet[0:4] + struct.pack("H", ident) + packet[6:20]
            inner_packet = packet[20::]
            fragments = self.fragment_outer(outer_hdr, inner_packet)
            return(fragments, "Fragment-Outer")
        #endif

        #
        # Fragment inner IPv4 packet.
        #
        outer_hdr_len = 56 if (self.outer_version == 6) else 36
        outer_hdr = packet[0:outer_hdr_len]
        inner_hdr = packet[outer_hdr_len: outer_hdr_len + 20]
        inner_packet = packet[outer_hdr_len + 20::]

        #
        # If DF-bit is set, don't fragment packet. Do MTU discovery if
        # configured with env variable.
        #
        frag_field = struct.unpack("H", inner_hdr[6:8])[0]
        frag_field = socket.ntohs(frag_field)
        if (frag_field & 0x4000):
            if (lisp_icmp_raw_socket != None):
                inner = packet[outer_hdr_len::]
                if (self.send_icmp_too_big(inner)): return([], None)
            #endif
            if (lisp_ignore_df_bit):
                frag_field &= ~0x4000
            else:
                df_bit = bold("DF-bit set", False)
                dprint("{} in inner header, packet discarded".format(df_bit))
                return([], "Fragment-None-DF-bit")
            #endif
        #endif

        offset = 0
        length = len(inner_packet)
        fragments = []
        while (offset < length):
            fragments.append(inner_packet[offset:offset+1400])
            offset += 1400
        #endwhile

        #
        # Now put inner header and outer header on each fragment.
        #
        frags = fragments
        fragments = []
        mf = True if frag_field & 0x2000 else False
        frag_field = (frag_field & 0x1fff) * 8
        for frag in frags:

            #
            # Set fragment-offset and MF bit if not last fragment.
            #
            ff = old_div(frag_field, 8)
            if (mf):
                ff |= 0x2000
            elif (frag != frags[-1]):
                ff |= 0x2000
            #endif
            ff = socket.htons(ff)
            inner_hdr = inner_hdr[0:6] + struct.pack("H", ff) + inner_hdr[8::]

            #
            # Set length of fragment, set up offset for next fragment-offset,
            # and header checksum fragment packet. Then prepend inner header
            # to payload.
            #
            length = len(frag)
            frag_field += length
            l = socket.htons(length + 20)
            inner_hdr = inner_hdr[0:2] + struct.pack("H", l) + \
                inner_hdr[4:10] + struct.pack("H", 0) + inner_hdr[12::]
            inner_hdr = lisp_ip_checksum(inner_hdr)
            fragment = inner_hdr + frag

            #
            # Change outer header length and header checksum if IPv4 outer
            # header. If IPv6 outer header, raw sockets prepends the header.
            #
            length = len(fragment)
            if (self.outer_version == 4):
                l = length + outer_hdr_len
                length += 16
                outer_hdr = outer_hdr[0:2] + struct.pack("H", l) + \
                    outer_hdr[4::]
                outer_hdr = lisp_ip_checksum(outer_hdr)
                fragment = outer_hdr + fragment
                fragment = self.fix_outer_header(fragment)
            #endif

            # 
            # Finally fix outer UDP header length. Byte-swap it.
            #
            udp_len_index = outer_hdr_len - 12
            l = socket.htons(length)
            fragment = fragment[0:udp_len_index] + struct.pack("H", l) + \
                fragment[udp_len_index+2::]
            fragments.append(fragment)
        #endfor
        return(fragments, "Fragment-Inner")
    #enddef

    def fix_outer_header(self, packet):

        #
        # IP_HDRINCL requires the total-length and frag-offset fields to be 
        # in host byte order. So have to byte-swapped here. But when testing
        # we (UPC guys) discovered the frag field didn't need swapping. The
        # conclusion is that byte-swapping is necessary for MacOS but not for
        # Linux OSes.
        #
        if (self.outer_version == 4 or self.inner_version == 4):
            if (lisp_is_macos()):
                packet = packet[0:2] + packet[3:4] + packet[2:3] + \
                    packet[4:6] + packet[7:8] + packet[6:7] + packet[8::]
            else:
                packet = packet[0:2] + packet[3:4] + packet[2:3] + packet[4::]
            #endif
        #endif
        return(packet)
    #enddef

    def send_packet(self, lisp_raw_socket, dest):
        if (lisp_flow_logging and dest != self.inner_dest): self.log_flow(True)

        dest = dest.print_address_no_iid()
        fragments, in_or_out = self.fragment()

        for fragment in fragments:
            if (len(fragments) != 1):
                self.packet = fragment
                self.print_packet(in_or_out, True)
            #endif

            try: lisp_raw_socket.sendto(fragment, (dest, 0))
            except socket.error as e:
                lprint("socket.sendto() failed: {}".format(e))
            #endtry
        #endfor
    #enddef

    def send_l2_packet(self, l2_socket, mac_header):
        if (l2_socket == None):
            lprint("No layer-2 socket, drop IPv6 packet")
            return
        #endif
        if (mac_header == None): 
            lprint("Could not build MAC header, drop IPv6 packet")
            return
        #endif

        packet = mac_header + self.packet

#        try: l2_socket.send(packet)
#        except socket.error as e:
#            lprint("send_l2_packet(): socket.send() failed: {}".format(e))
#        #endtry
#        return

        #
        # Use tuntap tunnel interface instead of raw sockets for IPv6 
        # decapsulated packets.
        #
        l2_socket.write(packet)
        return
    #enddef

    def bridge_l2_packet(self, eid, db):
        try: dyn_eid = db.dynamic_eids[eid.print_address_no_iid()]
        except: return
        try: interface = lisp_myinterfaces[dyn_eid.interface]
        except: return
        try: 
            socket = interface.get_bridge_socket()
            if (socket == None): return
        except: return

        try: socket.send(self.packet)
        except socket.error as e:
            lprint("bridge_l2_packet(): socket.send() failed: {}".format(e))
        #endtry
    #enddef

    def is_lisp_packet(self, packet):
        udp = (struct.unpack("B", packet[9:10])[0] == LISP_UDP_PROTOCOL)
        if (udp == False): return(False)

        port = struct.unpack("H", packet[22:24])[0]
        if (socket.ntohs(port) == LISP_DATA_PORT): return(True)
        port = struct.unpack("H", packet[20:22])[0]
        if (socket.ntohs(port) == LISP_DATA_PORT): return(True)
        return(False)
    #enddef

    def decode(self, is_lisp_packet, lisp_ipc_socket, stats):
        self.packet_error = ""
        packet = self.packet
        orig_len = len(packet)
        L3 = L2 = True

        #
        # Get version number of outer header so we can decode outer addresses.
        #
        header_len = 0
        iid = self.lisp_header.get_instance_id()
        if (is_lisp_packet):
            version = struct.unpack("B", packet[0:1])[0]
            self.outer_version = version >> 4
            if (self.outer_version == 4): 

                #
                # MacOS is zeroing the IP header checksum for a raw socket. 
                # If we receive this, bypass the checksum calculation.
                #
                orig_checksum = struct.unpack("H", packet[10:12])[0]
                packet = lisp_ip_checksum(packet)
                checksum = struct.unpack("H", packet[10:12])[0]
                if (checksum != 0):
                    if (orig_checksum != 0 or lisp_is_macos() == False):
                        self.packet_error = "checksum-error"
                        if (stats): 
                            stats[self.packet_error].increment(orig_len)
                        #endif

                        lprint("IPv4 header checksum failed for outer header")
                        if (lisp_flow_logging): self.log_flow(False)
                        return(None)
                    #endif
                #endif

                afi = LISP_AFI_IPV4
                offset = 12
                self.outer_tos = struct.unpack("B", packet[1:2])[0]
                self.outer_ttl = struct.unpack("B", packet[8:9])[0]
                header_len = 20
            elif (self.outer_version == 6): 
                afi = LISP_AFI_IPV6
                offset = 8
                tos = struct.unpack("H", packet[0:2])[0]
                self.outer_tos = (socket.ntohs(tos) >> 4) & 0xff
                self.outer_ttl = struct.unpack("B", packet[7:8])[0]
                header_len = 40
            else: 
                self.packet_error = "outer-header-error"
                if (stats): stats[self.packet_error].increment(orig_len)
                lprint("Cannot decode outer header")
                return(None)
            #endif
    
            self.outer_source.afi = afi
            self.outer_dest.afi = afi
            addr_length = self.outer_source.addr_length()
    
            self.outer_source.unpack_address(packet[offset:offset+addr_length])
            offset += addr_length
            self.outer_dest.unpack_address(packet[offset:offset+addr_length])
            packet = packet[header_len::]
            self.outer_source.mask_len = self.outer_source.host_mask_len()
            self.outer_dest.mask_len = self.outer_dest.host_mask_len()
    
            #
            # Get UDP fields
            #
            short = struct.unpack("H", packet[0:2])[0]
            self.udp_sport = socket.ntohs(short)
            short = struct.unpack("H", packet[2:4])[0]
            self.udp_dport = socket.ntohs(short)
            short = struct.unpack("H", packet[4:6])[0]
            self.udp_length = socket.ntohs(short)
            short = struct.unpack("H", packet[6:8])[0]
            self.udp_checksum = socket.ntohs(short)
            packet = packet[8::]

            #
            # Determine what is inside, a packet or a frame.
            #
            L3 = (self.udp_dport == LISP_DATA_PORT or 
                self.udp_sport == LISP_DATA_PORT)
            L2 = (self.udp_dport in (LISP_L2_DATA_PORT, LISP_VXLAN_DATA_PORT))

            #
            # Get LISP header fields.
            #
            if (self.lisp_header.decode(packet) == False): 
                self.packet_error = "lisp-header-error"
                if (stats): stats[self.packet_error].increment(orig_len)

                if (lisp_flow_logging): self.log_flow(False)
                lprint("Cannot decode LISP header")
                return(None)
            #endif
            packet = packet[8::]
            iid = self.lisp_header.get_instance_id()
            header_len += 16
        #endif
        if (iid == 0xffffff): iid = 0

        #
        # Time to decrypt if K-bits set.
        #
        decrypted = False
        key_id = self.lisp_header.k_bits
        if (key_id):
            addr_str = lisp_get_crypto_decap_lookup_key(self.outer_source, 
                self.udp_sport)
            if (addr_str == None):
                self.packet_error = "no-decrypt-key"
                if (stats): stats[self.packet_error].increment(orig_len)

                self.print_packet("Receive", is_lisp_packet)
                ks = bold("No key available", False)
                dprint("{} for key-id {} to decrypt packet".format(ks, key_id))
                if (lisp_flow_logging): self.log_flow(False)
                return(None)
            #endif

            key = lisp_crypto_keys_by_rloc_decap[addr_str][key_id]
            if (key == None):
                self.packet_error = "no-decrypt-key"
                if (stats): stats[self.packet_error].increment(orig_len)

                self.print_packet("Receive", is_lisp_packet)
                ks = bold("No key available", False)
                dprint("{} to decrypt packet from RLOC {}".format(ks, 
                    red(addr_str, False)))
                if (lisp_flow_logging): self.log_flow(False)
                return(None)
            #endif

            #
            # Decrypt and continue processing inner header.
            #
            key.use_count += 1
            packet, decrypted = self.decrypt(packet, header_len, key, addr_str)
            if (decrypted == False): 
                if (stats): stats[self.packet_error].increment(orig_len)
                if (lisp_flow_logging): self.log_flow(False)
                return(None)
            #endif
            
            #
            # Chacha produced plaintext in unicode for py2. Convert to raw-
            # unicode-escape before proceedingl Do this in do_icv() too.
            #
            if (key.cipher_suite == LISP_CS_25519_CHACHA):
                packet = packet.encode("raw_unicode_escape")
            #endif
        #endif

        #
        # Get inner header fields.
        #
        version = struct.unpack("B", packet[0:1])[0]
        self.inner_version = version >> 4
        if (L3 and self.inner_version == 4 and version >= 0x45): 
            packet_len = socket.ntohs(struct.unpack("H", packet[2:4])[0])
            self.inner_tos = struct.unpack("B", packet[1:2])[0]
            self.inner_ttl = struct.unpack("B", packet[8:9])[0]
            self.inner_protocol = struct.unpack("B", packet[9:10])[0]
            self.inner_source.afi = LISP_AFI_IPV4
            self.inner_dest.afi = LISP_AFI_IPV4
            self.inner_source.unpack_address(packet[12:16])
            self.inner_dest.unpack_address(packet[16:20])
            frag_field = socket.ntohs(struct.unpack("H", packet[6:8])[0])
            self.inner_is_fragment = (frag_field & 0x2000 or frag_field != 0)
            if (self.inner_protocol == LISP_UDP_PROTOCOL):
                self.inner_sport = struct.unpack("H", packet[20:22])[0]
                self.inner_sport = socket.ntohs(self.inner_sport)
                self.inner_dport = struct.unpack("H", packet[22:24])[0]
                self.inner_dport = socket.ntohs(self.inner_dport)
            #endif                
        elif (L3 and self.inner_version == 6 and version >= 0x60): 
            packet_len = socket.ntohs(struct.unpack("H", packet[4:6])[0]) + 40
            tos = struct.unpack("H", packet[0:2])[0]
            self.inner_tos = (socket.ntohs(tos) >> 4) & 0xff
            self.inner_ttl = struct.unpack("B", packet[7:8])[0]
            self.inner_protocol = struct.unpack("B", packet[6:7])[0]
            self.inner_source.afi = LISP_AFI_IPV6
            self.inner_dest.afi = LISP_AFI_IPV6
            self.inner_source.unpack_address(packet[8:24])
            self.inner_dest.unpack_address(packet[24:40])
            if (self.inner_protocol == LISP_UDP_PROTOCOL):
                self.inner_sport = struct.unpack("H", packet[40:42])[0]
                self.inner_sport = socket.ntohs(self.inner_sport)
                self.inner_dport = struct.unpack("H", packet[42:44])[0]
                self.inner_dport = socket.ntohs(self.inner_dport)
            #endif                
        elif (L2):
            packet_len = len(packet)
            self.inner_tos = 0
            self.inner_ttl = 0
            self.inner_protocol = 0
            self.inner_source.afi = LISP_AFI_MAC
            self.inner_dest.afi = LISP_AFI_MAC
            self.inner_dest.unpack_address(self.swap_mac(packet[0:6]))
            self.inner_source.unpack_address(self.swap_mac(packet[6:12]))
        elif (self.lisp_header.get_instance_id() == 0xffffff): 
            if (lisp_flow_logging): self.log_flow(False)
            return(self)
        else:
            self.packet_error = "bad-inner-version"
            if (stats): stats[self.packet_error].increment(orig_len)

            lprint("Cannot decode encapsulation, header version {}".format(\
                hex(version)))
            packet = lisp_format_packet(packet[0:20])
            lprint("Packet header: {}".format(packet))
            if (lisp_flow_logging and is_lisp_packet): self.log_flow(False)
            return(None)
        #endif
        self.inner_source.mask_len = self.inner_source.host_mask_len()
        self.inner_dest.mask_len = self.inner_dest.host_mask_len()
        self.inner_source.instance_id = iid
        self.inner_dest.instance_id = iid

        #
        # If we are configured to do Nonce-Echoing, do lookup on source-EID
        # to obtain source RLOC to store nonce to echo.
        #
        if (lisp_nonce_echoing and is_lisp_packet):
            echo_nonce = lisp_get_echo_nonce(self.outer_source, None)
            if (echo_nonce == None):
                rloc_str = self.outer_source.print_address_no_iid()
                echo_nonce = lisp_echo_nonce(rloc_str)
            #endif
            nonce = self.lisp_header.get_nonce()
            if (self.lisp_header.is_e_bit_set()):
                echo_nonce.receive_request(lisp_ipc_socket, nonce)
            elif (echo_nonce.request_nonce_sent):
                echo_nonce.receive_echo(lisp_ipc_socket, nonce)
            #endif
        #endif

        #
        # If we decrypted, we may have to truncate packet if the encrypter
        # padded the packet. 
        #
        if (decrypted): self.packet += packet[:packet_len]
        
        #
        # Log a packet that was parsed correctly.
        #
        if (lisp_flow_logging and is_lisp_packet): self.log_flow(False)
        return(self)
    #enddef

    def swap_mac(self, mac):
        return(mac[1] + mac[0] + mac[3] + mac[2] + mac[5] + mac[4])
    #enddef

    def strip_outer_headers(self):
        offset = 16
        offset += 20 if (self.outer_version == 4) else 40
        self.packet = self.packet[offset::]
        return(self)
    #enddef

    def hash_ports(self):
        packet = self.packet
        version = self.inner_version
        hashval = 0
        if (version == 4):
            protocol = struct.unpack("B", packet[9:10])[0]
            if (self.inner_is_fragment): return(protocol)
            if (protocol in [6, 17]):
                hashval = protocol
                hashval += struct.unpack("I", packet[20:24])[0]
                hashval = (hashval >> 16) ^ (hashval & 0xffff)
            #endif
        #endif
        if (version == 6):
            protocol = struct.unpack("B", packet[6:7])[0]
            if (protocol in [6, 17]):
                hashval = protocol
                hashval += struct.unpack("I", packet[40:44])[0]
                hashval = (hashval >> 16) ^ (hashval & 0xffff)
            #endif
        #endif
        return(hashval)
    #enddef

    def hash_packet(self):
        hashval = self.inner_source.address ^ self.inner_dest.address
        hashval += self.hash_ports()
        if (self.inner_version == 4):
            hashval = (hashval >> 16) ^ (hashval & 0xffff)
        elif (self.inner_version == 6):
             hashval = (hashval >> 64) ^ (hashval & 0xffffffffffffffff)
             hashval = (hashval >> 32) ^ (hashval & 0xffffffff)
             hashval = (hashval >> 16) ^ (hashval & 0xffff)
        #endif
        self.udp_sport = 0xf000 | (hashval & 0xfff)
    #enddef

    def print_packet(self, s_or_r, is_lisp_packet):
        if (is_lisp_packet == False):
            iaddr_str = "{} -> {}".format(self.inner_source.print_address(),
                self.inner_dest.print_address())
            dprint(("{} {}, tos/ttl: {}/{}, length: {}, packet: {} ..."). \
                format(bold(s_or_r, False), 
                green(iaddr_str, False), self.inner_tos, 
                self.inner_ttl, len(self.packet), 
                lisp_format_packet(self.packet[0:60])))
            return
        #endif

        if (s_or_r.find("Receive") != -1):
            ed = "decap"
            ed += "-vxlan" if self.udp_dport == LISP_VXLAN_DATA_PORT else ""
        else:
            ed = s_or_r
            if (ed in ["Send", "Replicate"] or ed.find("Fragment") != -1):
                ed = "encap"
            #endif
        #endif
        oaddr_str = "{} -> {}".format(self.outer_source.print_address_no_iid(),
                self.outer_dest.print_address_no_iid())

        #
        # Special case where Info-Request is inside of a 4341 packet for
        # NAT-traversal.
        #
        if (self.lisp_header.get_instance_id() == 0xffffff):
            line = ("{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + \
                "{}/{}, outer UDP: {} -> {}, ")
            line += bold("control-packet", False) + ": {} ..."

            dprint(line.format(bold(s_or_r, False), red(oaddr_str, False),
                self.outer_tos, self.outer_ttl, self.udp_sport, 
                self.udp_dport, lisp_format_packet(self.packet[0:56])))
            return
        else:
            line = ("{} LISP packet, outer RLOCs: {}, outer tos/ttl: " + \
                "{}/{}, outer UDP: {} -> {}, inner EIDs: {}, " + \
                "inner tos/ttl: {}/{}, length: {}, {}, packet: {} ...")
        #endif

        if (self.lisp_header.k_bits):
            if (ed == "encap"): ed = "encrypt/encap"
            if (ed == "decap"): ed = "decap/decrypt"
        #endif

        iaddr_str = "{} -> {}".format(self.inner_source.print_address(),
                self.inner_dest.print_address())

        dprint(line.format(bold(s_or_r, False), red(oaddr_str, False),
            self.outer_tos, self.outer_ttl, self.udp_sport, self.udp_dport, 
            green(iaddr_str, False), self.inner_tos, self.inner_ttl, 
            len(self.packet), self.lisp_header.print_header(ed),
            lisp_format_packet(self.packet[0:56])))
    #enddef

    def print_eid_tuple(self):
        return(lisp_print_eid_tuple(self.inner_source, self.inner_dest))
    #enddef

    def get_raw_socket(self):
        iid = str(self.lisp_header.get_instance_id())
        if (iid == "0"): return(None)
        if (iid not in lisp_iid_to_interface): return(None)

        interface = lisp_iid_to_interface[iid]
        s = interface.get_socket()
        if (s == None):
            string = bold("SO_BINDTODEVICE", False)
            enforce = (os.getenv("LISP_ENFORCE_BINDTODEVICE") != None)
            lprint("{} required for multi-tenancy support, {} packet".format( \
                string, "drop" if enforce else "forward"))
            if (enforce): return(None)
        #endif

        iid = bold(iid, False)
        d = bold(interface.device, False)
        dprint("Send packet on instance-id {} interface {}".format(iid, d))
        return(s)
    #enddef

    def log_flow(self, encap):
        global lisp_flow_log

        dump = os.path.exists("./log-flows")
        if (len(lisp_flow_log) == LISP_FLOW_LOG_SIZE or dump):
            args = [lisp_flow_log]
            lisp_flow_log = []
            threading.Thread(target=lisp_write_flow_log, args=args).start() 
            if (dump): os.system("rm ./log-flows")
            return
        #endif

        ts = datetime.datetime.now()
        lisp_flow_log.append([ts, encap, self.packet, self])
    #endif

    def print_flow(self, ts, encap, packet):
        ts = ts.strftime("%m/%d/%y %H:%M:%S.%f")[:-3]
        flow = "{}: {}".format(ts, "encap" if encap else "decap")

        osrc = red(self.outer_source.print_address_no_iid(), False)
        odst = red(self.outer_dest.print_address_no_iid(), False)
        isrc = green(self.inner_source.print_address(), False)
        idst = green(self.inner_dest.print_address(), False)

        if (self.lisp_header.get_instance_id() == 0xffffff):
            flow += " {}:{} -> {}:{}, LISP control message type {}\n"
            flow = flow.format(osrc, self.udp_sport, odst, self.udp_dport, 
                self.inner_version)                              
            return(flow)
        #endif

        if (self.outer_dest.is_null() == False):
            flow += " {}:{} -> {}:{}, len/tos/ttl {}/{}/{}"
            flow = flow.format(osrc, self.udp_sport, odst, self.udp_dport, 
                len(packet), self.outer_tos, self.outer_ttl)
        #endif

        #
        # Can't look at inner header if encrypted. Protecting user privacy.
        #
        if (self.lisp_header.k_bits != 0):
            error = "\n"
            if (self.packet_error != ""):
                error = " ({})".format(self.packet_error) + error
            #endif
            flow += ", encrypted" + error
            return(flow)
        #endif

        #
        # Position to inner header.
        #
        if (self.outer_dest.is_null() == False):
            packet = packet[36::] if self.outer_version == 4 else packet[56::]
        #endif

        protocol = packet[9:10] if self.inner_version == 4 else packet[6:7]
        protocol = struct.unpack("B", protocol)[0]

        flow += " {} -> {}, len/tos/ttl/prot {}/{}/{}/{}"
        flow = flow.format(isrc, idst, len(packet), self.inner_tos, 
            self.inner_ttl, protocol)

        #
        # Show some popular transport layer data.
        #
        if (protocol in [6, 17]):
            ports = packet[20:24] if self.inner_version == 4 else packet[40:44]
            if (len(ports) == 4):
                ports = socket.ntohl(struct.unpack("I", ports)[0])
                flow += ", ports {} -> {}".format(ports >> 16, ports & 0xffff)
            #endif
        elif (protocol == 1):
            seq = packet[26:28] if self.inner_version == 4 else packet[46:48]
            if (len(seq) == 2): 
                seq = socket.ntohs(struct.unpack("H", seq)[0])
                flow += ", icmp-seq {}".format(seq)
            #endif
        #endof
        if (self.packet_error != ""):
            flow += " ({})".format(self.packet_error)
        #endif
        flow += "\n"
        return(flow)
    #endif

    def is_trace(self):
        ports = [self.inner_sport, self.inner_dport]
        return(self.inner_protocol == LISP_UDP_PROTOCOL and 
               LISP_TRACE_PORT in ports)
    #enddef
#endclass

#
# LISP encapsulation header definition.
#
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     / |       Source Port = xxxx      |       Dest Port = 4341        |
#   UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     \ |           UDP Length          |        UDP Checksum           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   L   |N|L|E|V|I|P|K|K|            Nonce/Map-Version                  |
#   I \ +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   S / |                 Instance ID/Locator-Status-Bits               |
#   P   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
LISP_N_BIT  = 0x80000000
LISP_L_BIT  = 0x40000000
LISP_E_BIT  = 0x20000000
LISP_V_BIT  = 0x10000000
LISP_I_BIT  = 0x08000000
LISP_P_BIT  = 0x04000000
LISP_K_BITS = 0x03000000

class lisp_data_header(object):
    def __init__(self):
        self.first_long = 0
        self.second_long = 0
        self.k_bits = 0
    #enddef
        
    def print_header(self, e_or_d):
        first_long = lisp_hex_string(self.first_long & 0xffffff)
        second_long = lisp_hex_string(self.second_long).zfill(8)

        line = ("{} LISP-header -> flags: {}{}{}{}{}{}{}{}, nonce: {}, " + \
            "iid/lsb: {}")
        return(line.format(bold(e_or_d, False),
            "N" if (self.first_long & LISP_N_BIT) else "n",
            "L" if (self.first_long & LISP_L_BIT) else "l",
            "E" if (self.first_long & LISP_E_BIT) else "e",
            "V" if (self.first_long & LISP_V_BIT) else "v",
            "I" if (self.first_long & LISP_I_BIT) else "i",
            "P" if (self.first_long & LISP_P_BIT) else "p",
            "K" if (self.k_bits in [2,3]) else "k",
            "K" if (self.k_bits in [1,3]) else "k",
            first_long, second_long))
    #enddef

    def encode(self):
        packet_format = "II"
        first_long = socket.htonl(self.first_long)
        second_long = socket.htonl(self.second_long)

        header = struct.pack(packet_format, first_long, second_long)
        return(header)
    #enddef
        
    def decode(self, packet):
        packet_format = "II"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(False)

        first_long, second_long = \
            struct.unpack(packet_format, packet[:format_size])

        self.first_long = socket.ntohl(first_long)
        self.second_long = socket.ntohl(second_long)
        self.k_bits = (self.first_long & LISP_K_BITS) >> 24
        return(True)
    #enddef

    def key_id(self, key_id):
        self.first_long &= ~(0x3 << 24)
        self.first_long |= ((key_id & 0x3) << 24)
        self.k_bits = key_id
    #enddef

    def nonce(self, nonce):
        self.first_long |= LISP_N_BIT
        self.first_long |= nonce
    #enddef
        
    def map_version(self, version):
        self.first_long |= LISP_V_BIT
        self.first_long |= version
    #enddef

    def instance_id(self, iid):
        if (iid == 0): return
        self.first_long |= LISP_I_BIT
        self.second_long &= 0xff
        self.second_long |= (iid << 8)
    #enddef

    def get_instance_id(self):
        return((self.second_long >> 8) & 0xffffff)
    #enddef

    def locator_status_bits(self, lsbs):
        self.first_long |= LISP_L_BIT
        self.second_long &= 0xffffff00
        self.second_long |= (lsbs & 0xff)
    #enddef

    def is_request_nonce(self, nonce):
        return(nonce & 0x80000000)
    #enddef

    def request_nonce(self, nonce):
        self.first_long |= LISP_E_BIT
        self.first_long |= LISP_N_BIT
        self.first_long |= (nonce & 0xffffff)
    #enddef

    def is_e_bit_set(self):
        return(self.first_long & LISP_E_BIT)
    #enddef

    def get_nonce(self):
        return(self.first_long & 0xffffff)
    #enddef
#endclass

class lisp_echo_nonce(object):
    def __init__(self, rloc_str):
        self.rloc_str = rloc_str
        self.rloc = lisp_address(LISP_AFI_NONE, rloc_str, 0, 0)
        self.request_nonce_sent = None
        self.echo_nonce_sent = None
        self.last_request_nonce_sent = None
        self.last_new_request_nonce_sent = None
        self.last_echo_nonce_sent = None
        self.last_new_echo_nonce_sent = None
        self.request_nonce_rcvd = None
        self.echo_nonce_rcvd = None
        self.last_request_nonce_rcvd = None
        self.last_echo_nonce_rcvd = None
        self.last_good_echo_nonce_rcvd = None
        lisp_nonce_echo_list[rloc_str] = self
    #enddef

    def send_ipc(self, ipc_socket, ipc):
        source = "lisp-itr" if lisp_i_am_itr else "lisp-etr"
        dest = "lisp-etr" if lisp_i_am_itr else "lisp-itr"
        ipc = lisp_command_ipc(ipc, source)
        lisp_ipc(ipc, ipc_socket, dest)
    #enddef

    def send_request_ipc(self, ipc_socket, nonce):
        nonce = lisp_hex_string(nonce)
        ipc = "nonce%R%{}%{}".format(self.rloc_str, nonce)
        self.send_ipc(ipc_socket, ipc)
    #enddef

    def send_echo_ipc(self, ipc_socket, nonce):
        nonce = lisp_hex_string(nonce)
        ipc = "nonce%E%{}%{}".format(self.rloc_str, nonce)
        self.send_ipc(ipc_socket, ipc)
    #enddef

    def receive_request(self, ipc_socket, nonce):
        old_nonce = self.request_nonce_rcvd
        self.request_nonce_rcvd = nonce
        self.last_request_nonce_rcvd = lisp_get_timestamp()
        if (lisp_i_am_rtr): return
        if (old_nonce != nonce): self.send_request_ipc(ipc_socket, nonce)
    #enddef

    def receive_echo(self, ipc_socket, nonce):
        if (self.request_nonce_sent != nonce): return
        self.last_echo_nonce_rcvd = lisp_get_timestamp()
        if (self.echo_nonce_rcvd == nonce): return

        self.echo_nonce_rcvd = nonce
        if (lisp_i_am_rtr): return
        self.send_echo_ipc(ipc_socket, nonce)
    #enddef

    def get_request_or_echo_nonce(self, ipc_socket, remote_rloc):

        #
        # If we are in both request-nonce and echo-nonce mode, let the
        # higher IP addressed RLOC be in request mode.
        #
        if (self.request_nonce_sent and self.echo_nonce_sent and remote_rloc):
            local_rloc = lisp_myrlocs[0] if remote_rloc.is_ipv4() \
                else lisp_myrlocs[1]

            if (remote_rloc.address > local_rloc.address):
                a = "exit"
                self.request_nonce_sent = None
            else:
                a = "stay in"
                self.echo_nonce_sent = None
            #endif

            c = bold("collision", False)
            l = red(local_rloc.print_address_no_iid(), False)
            r = red(remote_rloc.print_address_no_iid(), False)
            lprint("Echo nonce {}, {} -> {}, {} request-nonce mode".format(c,
               l, r, a))
        #endif

        #
        # If we are echoing, return echo-nonce. Or get out of echo-nonce mode.
        #
        if (self.echo_nonce_sent != None):
            nonce = self.echo_nonce_sent
            e = bold("Echoing", False)
            lprint("{} nonce 0x{} to {}".format(e, 
                lisp_hex_string(nonce), red(self.rloc_str, False)))
            self.last_echo_nonce_sent = lisp_get_timestamp()
            self.echo_nonce_sent = None
            return(nonce)
            #endif
        #endif

        #
        # Should we stop requesting nonce-echoing? Only do so if we received
        # a echo response and some time (10 seconds) has past.
        #
        nonce = self.request_nonce_sent
        last = self.last_request_nonce_sent
        if (nonce and last != None):
            if (time.time() - last >= LISP_NONCE_ECHO_INTERVAL): 
                self.request_nonce_sent = None
                lprint("Stop request-nonce mode for {}, nonce 0x{}".format( \
                    red(self.rloc_str, False), lisp_hex_string(nonce)))
                return(None)
            #endif
        #endif

        #
        # Start echoing the nonce. Get a new nonce. If a echo-nonce is stored
        # use the same nonce as last time regardless if we received an echo
        # response. High-order bit set is telling caller to set the e-bit in 
        # header.
        #
        if (nonce == None):
            nonce = lisp_get_data_nonce()
            if (self.recently_requested()): return(nonce)

            self.request_nonce_sent = nonce
            lprint("Start request-nonce mode for {}, nonce 0x{}".format( \
                red(self.rloc_str, False), lisp_hex_string(nonce)))
            self.last_new_request_nonce_sent = lisp_get_timestamp()

            #
            # Send the request-nonce to the ETR so it can tell us when the
            # other side has echoed this request-nonce. 
            #
            if (lisp_i_am_itr == False): return(nonce | 0x80000000)
            self.send_request_ipc(ipc_socket, nonce)
        else:
            lprint("Continue request-nonce mode for {}, nonce 0x{}".format( \
                red(self.rloc_str, False), lisp_hex_string(nonce)))
        #endif

        #
        # Continue sending request-nonce. But if we never received an echo,
        # don't update timer.
        #
        self.last_request_nonce_sent = lisp_get_timestamp()
        return(nonce | 0x80000000)
    #enddef

    def request_nonce_timeout(self):
        if (self.request_nonce_sent == None): return(False)
        if (self.request_nonce_sent == self.echo_nonce_rcvd): return(False)

        elapsed = time.time() - self.last_request_nonce_sent
        last_resp = self.last_echo_nonce_rcvd
        return(elapsed >= LISP_NONCE_ECHO_INTERVAL and last_resp == None)
    #enddef

    def recently_requested(self):
        last_resp = self.last_request_nonce_sent
        if (last_resp == None): return(False)

        elapsed = time.time() - last_resp
        return(elapsed <= LISP_NONCE_ECHO_INTERVAL)
    #enddef

    def recently_echoed(self):
        if (self.request_nonce_sent == None): return(True)

        #
        # Check how long its been since last received echo.
        #
        last_resp = self.last_good_echo_nonce_rcvd
        if (last_resp == None): last_resp = 0
        elapsed = time.time() - last_resp
        if (elapsed <= LISP_NONCE_ECHO_INTERVAL): return(True)

        #
        # If last received echo was a while ago and a new request-nonce was
        # sent recently, say the echo happen so we can bootstrap a new request
        # and echo exchange.
        #
        last_resp = self.last_new_request_nonce_sent
        if (last_resp == None): last_resp = 0
        elapsed = time.time() - last_resp
        return(elapsed <= LISP_NONCE_ECHO_INTERVAL)
    #enddef

    def change_state(self, rloc):
        if (rloc.up_state() and self.recently_echoed() == False):
            down = bold("down", False)
            good_echo = lisp_print_elapsed(self.last_good_echo_nonce_rcvd)
            lprint("Take {} {}, last good echo: {}".format( \
                red(self.rloc_str, False), down, good_echo))
            rloc.state = LISP_RLOC_NO_ECHOED_NONCE_STATE
            rloc.last_state_change = lisp_get_timestamp()
            return
        #endif

        if (rloc.no_echoed_nonce_state() == False): return

        if (self.recently_requested() == False):
            up = bold("up", False)
            lprint("Bring {} {}, retry request-nonce mode".format( \
                red(self.rloc_str, False), up))
            rloc.state = LISP_RLOC_UP_STATE
            rloc.last_state_change = lisp_get_timestamp()
        #endif
    #enddef

    def print_echo_nonce(self):
        rs = lisp_print_elapsed(self.last_request_nonce_sent)
        er = lisp_print_elapsed(self.last_good_echo_nonce_rcvd)

        es = lisp_print_elapsed(self.last_echo_nonce_sent)
        rr = lisp_print_elapsed(self.last_request_nonce_rcvd)
        s = space(4)

        output = "Nonce-Echoing:\n"
        output += ("{}Last request-nonce sent: {}\n{}Last echo-nonce " + \
            "received: {}\n").format(s, rs, s, er)
        output += ("{}Last request-nonce received: {}\n{}Last echo-nonce " + \
            "sent: {}").format(s, rr, s, es)

        return(output)
    #enddef
#endclass

#
# lisp_keys
#
# Class to hold Diffie-Hellman keys. For ECDH use RFC5114 gx value of 
# "192-bit Random ECP Group".
#
class lisp_keys(object):
    def __init__(self, key_id, do_curve=True, do_chacha=use_chacha,
        do_poly=use_poly):
        self.uptime = lisp_get_timestamp()
        self.last_rekey = None
        self.rekey_count = 0
        self.use_count = 0
        self.key_id = key_id
        self.cipher_suite = LISP_CS_1024
        self.dh_g_value = LISP_CS_1024_G
        self.dh_p_value = LISP_CS_1024_P
        self.curve25519 = None
        self.cipher_suite_string = ""
        if (do_curve):
            if (do_chacha):
                self.cipher_suite = LISP_CS_25519_CHACHA
                self.cipher_suite_string = "chacha"
            elif (os.getenv("LISP_USE_AES_GCM") != None):
                self.cipher_suite = LISP_CS_25519_GCM
                self.cipher_suite_string = "aes-gcm"
            else:
                self.cipher_suite = LISP_CS_25519_CBC
                self.cipher_suite_string = "aes-cbc"
            #endif
            self.local_private_key = random.randint(0, 2**128-1)
            key = lisp_hex_string(self.local_private_key).zfill(32)
            self.curve25519 = curve25519.Private(key.encode())
        else:
            self.local_private_key = random.randint(0, 0x1fff)
        #endif
        self.local_public_key = self.compute_public_key()
        self.remote_public_key = None
        self.shared_key = None
        self.encrypt_key = None
        self.icv_key = None
        self.icv = poly1305 if do_poly else hashlib.sha256 
        self.iv = None
        self.get_iv()
        self.do_poly = do_poly
    #enddef

    def copy_keypair(self, key):
        self.local_private_key = key.local_private_key
        self.local_public_key = key.local_public_key
        self.curve25519 = key.curve25519
    #enddef

    def get_iv(self):
        if (self.iv == None):
            self.iv = random.randint(0, LISP_16_128_MASK)
        else:
            self.iv += 1
        #endif
        iv = self.iv
        if (self.cipher_suite == LISP_CS_25519_CHACHA):
            iv = struct.pack("Q", iv & LISP_8_64_MASK)
        elif (self.cipher_suite == LISP_CS_25519_GCM):
            ivh = struct.pack("I", (iv >> 64) & LISP_4_32_MASK)
            ivl = struct.pack("Q", iv & LISP_8_64_MASK)
            iv = ivh + ivl
        else:
            iv = struct.pack("QQ", iv >> 64, iv & LISP_8_64_MASK)
        return(iv)
    #enddef

    def key_length(self, key):
        if (isinstance(key, int)): key = self.normalize_pub_key(key)
        return(old_div(len(key), 2))
    #enddef

    def print_key(self, key):
        k = self.normalize_pub_key(key)
        top = k[0:4].decode()
        bot = k[-4::].decode()
        return("0x{}...{}({})".format(top, bot, self.key_length(k)))
    #enddef
 
    def normalize_pub_key(self, key):
        if (isinstance(key, int)):
            key = lisp_hex_string(key).zfill(256)
            return(key)
        #endif
        if (self.curve25519): return(binascii.hexlify(key))
        return(key)
    #enddef

    def print_keys(self, do_bold=True):
        l = bold("local-key: ", False) if do_bold else "local-key: "
        if (self.local_public_key == None):
            l += "none"
        else:
            l += self.print_key(self.local_public_key)
        #endif
        r = bold("remote-key: ", False) if do_bold else "remote-key: "
        if (self.remote_public_key == None):
            r += "none"
        else:
            r += self.print_key(self.remote_public_key)
        #endif
        dh = "ECDH" if (self.curve25519) else "DH"
        cs = self.cipher_suite
        return("{} cipher-suite: {}, {}, {}".format(dh, cs, l, r))
    #enddef

    def compare_keys(self, keys):
        if (self.dh_g_value != keys.dh_g_value): return(False)
        if (self.dh_p_value != keys.dh_p_value): return(False)
        if (self.remote_public_key != keys.remote_public_key): return(False)
        return(True)
    #enddef

    def compute_public_key(self):
        if (self.curve25519): return(self.curve25519.get_public().public)

        key = self.local_private_key
        g = self.dh_g_value
        p = self.dh_p_value
        return(int((g**key) % p))
    #enddef

    def compute_shared_key(self, ed, print_shared=False):
        key = self.local_private_key
        remote_key = self.remote_public_key

        compute = bold("Compute {} shared-key".format(ed), False)
        lprint("{}, key-material: {}".format(compute, self.print_keys()))

        if (self.curve25519):
            public = curve25519.Public(remote_key)
            self.shared_key = self.curve25519.get_shared_key(public)
        else:
            p = self.dh_p_value
            self.shared_key = (remote_key**key) % p
        #endif

        #
        # This should only be used in a lab for debugging and never live since
        # its a security risk to expose the shared-key (even though the entire
        # key is not displayed).
        #
        if (print_shared): 
            k = self.print_key(self.shared_key)
            lprint("Computed shared-key: {}".format(k))
        #endif

        #
        # Now compute keys we use for encryption and ICV authentication.
        #
        self.compute_encrypt_icv_keys()

        #
        # Increment counters and timestamp.
        #
        self.rekey_count += 1
        self.last_rekey = lisp_get_timestamp()
    #enddef
    
    def compute_encrypt_icv_keys(self):
        alg = hashlib.sha256
        if (self.curve25519):
            data = self.shared_key
        else:
            data = lisp_hex_string(self.shared_key)
        #endif

        #
        # context = "0001" || "lisp-crypto" || "<lpub> xor <rpub>" || "0100"
        #
        l = self.local_public_key
        if (type(l) != int): l = int(binascii.hexlify(l), 16)
        r = self.remote_public_key
        if (type(r) != int): r = int(binascii.hexlify(r), 16)
        context = "0001" + "lisp-crypto" + lisp_hex_string(l ^ r) + "0100"

        key_material = hmac.new(context.encode(), data, alg).hexdigest()
        key_material = int(key_material, 16)

        #
        # key-material = key-material-1-encrypt || key-material-2-icv
        #
        ek = (key_material >> 128) & LISP_16_128_MASK
        ik = key_material & LISP_16_128_MASK
        ek = lisp_hex_string(ek).zfill(32)
        self.encrypt_key = ek.encode()
        fill = 32 if self.do_poly else 40
        ik = lisp_hex_string(ik).zfill(fill)
        self.icv_key = ik.encode()
    #enddef

    def do_icv(self, packet, nonce):
        if (self.icv_key == None): return("")
        if (self.do_poly):
            poly = self.icv.poly1305aes
            hexlify = self.icv.binascii.hexlify
            nonce = hexlify(nonce)
            hash_output = poly(self.encrypt_key, self.icv_key, nonce, packet)
            if (lisp_is_python2()):
                hash_output = hexlify(hash_output.encode("raw_unicode_escape"))
            else:
                hash_output = hexlify(hash_output).decode()
            #endif
        else:
            key = binascii.unhexlify(self.icv_key)
            hash_output = hmac.new(key, packet, self.icv).hexdigest()
            hash_output = hash_output[0:40]
        #endif
        return(hash_output)
    #enddef

    def add_key_by_nonce(self, nonce):
        if (nonce not in lisp_crypto_keys_by_nonce):
            lisp_crypto_keys_by_nonce[nonce] = [None, None, None, None]
        #endif
        lisp_crypto_keys_by_nonce[nonce][self.key_id] = self
    #enddef
        
    def delete_key_by_nonce(self, nonce):
        if (nonce not in lisp_crypto_keys_by_nonce): return
        lisp_crypto_keys_by_nonce.pop(nonce)
    #enddef

    def add_key_by_rloc(self, addr_str, encap):
        by_rlocs = lisp_crypto_keys_by_rloc_encap if encap else \
            lisp_crypto_keys_by_rloc_decap

        if (addr_str not in by_rlocs):
            by_rlocs[addr_str] = [None, None, None, None]
        #endif
        by_rlocs[addr_str][self.key_id] = self

        #
        # If "ipc-data-plane = yes" is configured, we need to tell the data-
        # plane from the lisp-etr process what the decryption key is.
        #
        if (encap == False):
            lisp_write_ipc_decap_key(addr_str, by_rlocs[addr_str])
        #endif
    #enddef

    def encode_lcaf(self, rloc_addr):
        pub_key = self.normalize_pub_key(self.local_public_key)
        key_len = self.key_length(pub_key)
        sec_len = (6 + key_len + 2)
        if (rloc_addr != None): sec_len += rloc_addr.addr_length()

        packet = struct.pack("HBBBBHBB", socket.htons(LISP_AFI_LCAF), 0, 0,
            LISP_LCAF_SECURITY_TYPE, 0, socket.htons(sec_len), 1, 0)

        #
        # Put in cipher suite value. Support 1024-bit keys only. Then insert
        # key-length and public key material. Do not negotiate ECDH 25519
        # cipher suite if library not installed on system.
        #
        cs = self.cipher_suite
        packet += struct.pack("BBH", cs, 0, socket.htons(key_len))

        #
        # Insert public-key.
        #
        for i in range(0, key_len * 2, 16):
            key = int(pub_key[i:i+16], 16)
            packet += struct.pack("Q", byte_swap_64(key))
        #endfor

        #
        # Insert RLOC address.
        #
        if (rloc_addr):
            packet += struct.pack("H", socket.htons(rloc_addr.afi))
            packet += rloc_addr.pack_address()
        #endif
        return(packet)
    #enddef

    def decode_lcaf(self, packet, lcaf_len):

        #
        # Called by lisp_map_request().
        #
        if (lcaf_len == 0):
            packet_format = "HHBBH"
            format_size = struct.calcsize(packet_format)
            if (len(packet) < format_size): return(None)

            afi, rsvd, lcaf_type, rsvd, lcaf_len = struct.unpack( \
                packet_format, packet[:format_size])

            if (lcaf_type != LISP_LCAF_SECURITY_TYPE):
                packet = packet[lcaf_len + 6::]
                return(packet)
            #endif
            lcaf_len = socket.ntohs(lcaf_len)
            packet = packet[format_size::]
        #endif

        #
        # Fall through or called by lisp_rloc_record() when lcaf_len is 
        # non-zero.
        #
        lcaf_type = LISP_LCAF_SECURITY_TYPE
        packet_format = "BBBBH"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)
        
        key_count, rsvd, cs, rsvd, key_len = struct.unpack(packet_format, 
            packet[:format_size])

        #
        # Advance packet pointer to beginning of key material. Validate there
        # is enough packet to pull the key out according the encoded key
        # length found earlier in the packet.
        #
        packet = packet[format_size::]
        key_len = socket.ntohs(key_len)
        if (len(packet) < key_len): return(None)

        #
        # Check Cipher Suites supported.
        #
        cs_list = [LISP_CS_25519_CBC, LISP_CS_25519_GCM, LISP_CS_25519_CHACHA,
            LISP_CS_1024]
        if (cs not in cs_list):
            lprint("Cipher-suites {} supported, received {}".format(cs_list,
                cs))
            packet = packet[key_len::]
            return(packet)
        #endif

        self.cipher_suite = cs

        #
        # Iterate to pull 8 bytes (64-bits) out at at time. The key is stored
        # internally as an integer.
        #
        pub_key = 0
        for i in range(0, key_len, 8):
            key = byte_swap_64(struct.unpack("Q", packet[i:i+8])[0])
            pub_key <<= 64
            pub_key |= key
        #endfor
        self.remote_public_key = pub_key

        #
        # Convert to 32-byte binary string. Make sure leading 0s are included.
        # ;-)
        #
        if (self.curve25519):
            key = lisp_hex_string(self.remote_public_key)
            key = key.zfill(64)
            new_key = b""
            for i in range(0, len(key), 2):
                byte = int(key[i:i+2], 16)
                new_key += lisp_store_byte(byte)
            #endfor
            self.remote_public_key = new_key
        #endif

        packet = packet[key_len::]
        return(packet)
    #enddef
#endclass

#
# lisp_store_byte
#
# We have to store a byte differently in a py2 string versus a py3 byte string.
# Check if the code was compiled with either python2 or python3.
#
def lisp_store_byte_py2(byte):
    return(chr(byte))
#enddef
def lisp_store_byte_py3(byte):
    return(bytes([byte]))
#enddef

lisp_store_byte = lisp_store_byte_py2
if (lisp_is_python3()): lisp_store_byte = lisp_store_byte_py3

#
# lisp_thread()
#
# Used to multi-thread the data-plane.
#
class lisp_thread(object):
    def __init__(self, name):
        self.thread_name = name
        self.thread_number = -1
        self.number_of_pcap_threads = 0
        self.number_of_worker_threads = 0
        self.input_queue = queue.Queue()
        self.input_stats = lisp_stats()
        self.lisp_packet = lisp_packet(None)
    #enddef
#endclass

#------------------------------------------------------------------------------

# 
#   The LISP fixed control header:
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |Type=x |              Reserved                 | Record Count  |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                         Nonce . . .                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                         . . . Nonce                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
class lisp_control_header(object):
    def __init__(self):
        self.type = 0
        self.record_count = 0
        self.nonce = 0
        self.rloc_probe = False
        self.smr_bit = False
        self.smr_invoked_bit = False
        self.ddt_bit = False
        self.to_etr = False
        self.to_ms = False
        self.info_reply = False
    #enddef

    def decode(self, packet):
        packet_format = "BBBBQ"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(False)

        typeval, bits, reserved, self.record_count, self.nonce = \
            struct.unpack(packet_format, packet[:format_size])

        self.type = typeval >> 4
        if (self.type == LISP_MAP_REQUEST):
            self.smr_bit = True if (typeval & 0x01) else False
            self.rloc_probe = True if (typeval & 0x02) else False
            self.smr_invoked_bit = True if (bits & 0x40) else False
        #endif
        if (self.type == LISP_ECM):
            self.ddt_bit = True if (typeval & 0x04) else False
            self.to_etr = True if (typeval & 0x02) else False
            self.to_ms = True if (typeval & 0x01) else False
        #endif
        if (self.type == LISP_NAT_INFO):
            self.info_reply = True if (typeval & 0x08) else False
        #endif
        return(True)
    #enddef
    
    def is_info_request(self):
        return((self.type == LISP_NAT_INFO and self.is_info_reply() == False))
    #enddef

    def is_info_reply(self):
        return(True if self.info_reply else False)
    #enddef

    def is_rloc_probe(self):
        return(True if self.rloc_probe else False)
    #enddef

    def is_smr(self):
        return(True if self.smr_bit else False)
    #enddef

    def is_smr_invoked(self):
        return(True if self.smr_invoked_bit else False)
    #enddef

    def is_ddt(self):
        return(True if self.ddt_bit else False)
    #enddef

    def is_to_etr(self):
        return(True if self.to_etr else False)
    #enddef

    def is_to_ms(self):
        return(True if self.to_ms else False)
    #enddef
#endclass    

#
#   The Map-Register message format is:
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |Type=3 |P|S|I|    Reserved   | kid |e|F|T|a|m|M| Record Count  |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                         Nonce . . .                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                         . . . Nonce                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |    Key ID     | Algorithm ID  |  Authentication Data Length   |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       ~                     Authentication Data                       ~
#   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |   |                          Record TTL                           |
#   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
#   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   c   | Rsvd  |  Map-Version Number   |        EID-Prefix-AFI         |
#   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   r   |                          EID-Prefix                           |
#   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
#   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | o |        Unused Flags     |L|p|R|           Loc-AFI             |
#   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  \|                             Locator                           |
#   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                                                               |
#       |                                                               |
#       +-                   ... xTR router-ID ...                     -+
#       |                                                               |
#       |                                                               |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                                                               |
#       +-                    ... xTR site-ID ...                      -+
#       |                                                               |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# kid are 1 of 8 values that describe the encryption key-id used for
# encrypting Map-Register messages.When the Map-Register is encrypted, the
# entire message not including the first 4 bytes are chacha20 encrypted. The
# e-bit must be set by the ETR to indicate that the Map-Register was encrypted.
#
class lisp_map_register(object):
    def __init__(self):
        self.proxy_reply_requested = False
        self.lisp_sec_present = False
        self.xtr_id_present = False
        self.map_notify_requested = False
        self.mobile_node = False
        self.merge_register_requested = False
        self.use_ttl_for_timeout = False
        self.map_register_refresh = False
        self.record_count = 0
        self.nonce = 0
        self.alg_id = 0
        self.key_id = 0
        self.auth_len = 0
        self.auth_data = 0
        self.xtr_id = 0
        self.site_id = 0
        self.record_count = 0
        self.sport = 0
        self.encrypt_bit = 0
        self.encryption_key_id = None
    #enddef

    def print_map_register(self):
        xtr_id = lisp_hex_string(self.xtr_id)

        line = ("{} -> flags: {}{}{}{}{}{}{}{}{}, record-count: " +
            "{}, nonce: 0x{}, key/alg-id: {}/{}{}, auth-len: {}, xtr-id: " +
            "0x{}, site-id: {}")

        lprint(line.format(bold("Map-Register", False),  \
            "P" if self.proxy_reply_requested else "p", 
            "S" if self.lisp_sec_present else "s",
            "I" if self.xtr_id_present else "i",
            "T" if self.use_ttl_for_timeout else "t",
            "R" if self.merge_register_requested else "r",
            "M" if self.mobile_node else "m",
            "N" if self.map_notify_requested else "n",
            "F" if self.map_register_refresh else "f",
            "E" if self.encrypt_bit else "e",
            self.record_count, lisp_hex_string(self.nonce), self.key_id, 
            self.alg_id, " (sha1)" if (self.key_id == LISP_SHA_1_96_ALG_ID) \
            else (" (sha2)" if (self.key_id == LISP_SHA_256_128_ALG_ID) else \
            ""), self.auth_len, xtr_id, self.site_id))
    #enddef

    def encode(self):
        first_long = (LISP_MAP_REGISTER << 28) | self.record_count
        if (self.proxy_reply_requested): first_long |= 0x08000000
        if (self.lisp_sec_present): first_long |= 0x04000000
        if (self.xtr_id_present): first_long |= 0x02000000
        if (self.map_register_refresh): first_long |= 0x1000
        if (self.use_ttl_for_timeout): first_long |= 0x800
        if (self.merge_register_requested): first_long |= 0x400
        if (self.mobile_node): first_long |= 0x200
        if (self.map_notify_requested): first_long |= 0x100
        if (self.encryption_key_id != None):
            first_long |= 0x2000
            first_long |= self.encryption_key_id << 14
        #endif

        #
        # Append zeroed authentication data so we can compute hash latter.
        #
        if (self.alg_id == LISP_NONE_ALG_ID):
            self.auth_len = 0
        else:
            if (self.alg_id == LISP_SHA_1_96_ALG_ID):
                self.auth_len = LISP_SHA1_160_AUTH_DATA_LEN
            #endif
            if (self.alg_id == LISP_SHA_256_128_ALG_ID):
                self.auth_len = LISP_SHA2_256_AUTH_DATA_LEN
            #endif
        #endif

        packet = struct.pack("I", socket.htonl(first_long))
        packet += struct.pack("QBBH", self.nonce, self.key_id, self.alg_id,
            socket.htons(self.auth_len))

        packet = self.zero_auth(packet)
        return(packet)
    #enddef

    def zero_auth(self, packet):
        offset = struct.calcsize("I") + struct.calcsize("QHH")
        auth_data = b""
        auth_len = 0
        if (self.alg_id == LISP_NONE_ALG_ID): return(packet)
        if (self.alg_id == LISP_SHA_1_96_ALG_ID):
            auth_data = struct.pack("QQI", 0, 0, 0)
            auth_len = struct.calcsize("QQI")
        #endif
        if (self.alg_id == LISP_SHA_256_128_ALG_ID):
            auth_data = struct.pack("QQQQ", 0, 0, 0, 0)
            auth_len = struct.calcsize("QQQQ")
        #endif
        packet = packet[0:offset] + auth_data + packet[offset+auth_len::]
        return(packet)
    #enddef

    def encode_auth(self, packet):
        offset = struct.calcsize("I") + struct.calcsize("QHH")
        auth_len = self.auth_len
        auth_data = self.auth_data
        packet = packet[0:offset] + auth_data + packet[offset + auth_len::]
        return(packet)
    #enddef

    def decode(self, packet):
        orig_packet = packet
        packet_format = "I"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return([None, None])

        first_long = struct.unpack(packet_format, packet[:format_size])
        first_long = socket.ntohl(first_long[0])
        packet = packet[format_size::]

        packet_format = "QBBH"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return([None, None])

        self.nonce, self.key_id, self.alg_id, self.auth_len = \
            struct.unpack(packet_format, packet[:format_size])

        self.nonce = byte_swap_64(self.nonce)
        self.auth_len = socket.ntohs(self.auth_len)
        self.proxy_reply_requested = True if (first_long & 0x08000000) \
            else False
        self.lisp_sec_present = True if (first_long & 0x04000000) else False
        self.xtr_id_present = True if (first_long & 0x02000000) else False
        self.use_ttl_for_timeout = True if (first_long & 0x800) else False
        self.map_register_refresh = True if (first_long & 0x1000) else False
        self.merge_register_requested = True if (first_long & 0x400) else False
        self.mobile_node = True if (first_long & 0x200) else False
        self.map_notify_requested = True if (first_long & 0x100) else False
        self.record_count = first_long & 0xff

        #
        # Decode e-bit and key-id for Map-Register decryption.
        #
        self.encrypt_bit = True if first_long & 0x2000 else False
        if (self.encrypt_bit):
            self.encryption_key_id =  (first_long >> 14) & 0x7
        #endif

        #
        # Decode xTR-ID and site-ID if sender set the xtr_id_present bit.
        #
        if (self.xtr_id_present): 
            if (self.decode_xtr_id(orig_packet) == False): return([None, None])
        #endif

        packet = packet[format_size::]

        #
        # Parse authentication and zero out the auth field in the packet.
        #
        if (self.auth_len != 0): 
            if (len(packet) < self.auth_len): return([None, None])

            if (self.alg_id not in (LISP_NONE_ALG_ID, LISP_SHA_1_96_ALG_ID,
                LISP_SHA_256_128_ALG_ID)):
                lprint("Invalid authentication alg-id: {}".format(self.alg_id))
                return([None, None])
            #endif

            auth_len = self.auth_len
            if (self.alg_id == LISP_SHA_1_96_ALG_ID):
                format_size = struct.calcsize("QQI")
                if (auth_len < format_size): 
                    lprint("Invalid sha1-96 authentication length")
                    return([None, None])
                #endif
                auth1, auth2, auth3 = struct.unpack("QQI", packet[:auth_len])
                auth4 = b""
            elif (self.alg_id == LISP_SHA_256_128_ALG_ID):
                format_size = struct.calcsize("QQQQ")
                if (auth_len < format_size):
                    lprint("Invalid sha2-256 authentication length")
                    return([None, None])
                #endif
                auth1, auth2, auth3, auth4 = struct.unpack("QQQQ", 
                    packet[:auth_len])
            else:
                lprint("Unsupported authentication alg-id value {}".format( \
                    self.alg_id))
                return([None, None])
            #endif
            self.auth_data = lisp_concat_auth_data(self.alg_id, auth1, auth2, 
                auth3, auth4)                       
            orig_packet = self.zero_auth(orig_packet)
            packet = packet[self.auth_len::]
        #endif
        return([orig_packet, packet])
    #enddef
    
    def encode_xtr_id(self, packet):
        xtr_id_upper = self.xtr_id >> 64
        xtr_id_lower = self.xtr_id & 0xffffffffffffffff
        xtr_id_upper = byte_swap_64(xtr_id_upper)
        xtr_id_lower = byte_swap_64(xtr_id_lower)
        site_id = byte_swap_64(self.site_id)
        packet += struct.pack("QQQ", xtr_id_upper, xtr_id_lower, site_id)
        return(packet)
    #enddef

    def decode_xtr_id(self, packet):
        format_size = struct.calcsize("QQQ")
        if (len(packet) < format_size): return([None, None])
        packet = packet[len(packet)-format_size::]
        xtr_id_upper, xtr_id_lower, site_id = struct.unpack("QQQ", 
            packet[:format_size])
        xtr_id_upper = byte_swap_64(xtr_id_upper)
        xtr_id_lower = byte_swap_64(xtr_id_lower)
        self.xtr_id = (xtr_id_upper << 64) | xtr_id_lower
        self.site_id = byte_swap_64(site_id)
        return(True)
    #enddef
#endclass    

#  The Map-Notify/Map-Notify-Ack  message format is:
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |Type=4/5|             Reserved                 | Record Count  |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                         Nonce . . .                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                         . . . Nonce                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |    Key ID     | Algorithm ID  |  Authentication Data Length   |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       ~                     Authentication Data                       ~
#   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |   |                          Record TTL                           |
#   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
#   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   c   | Rsvd  |  Map-Version Number   |         EID-Prefix-AFI        |
#   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   r   |                          EID-Prefix                           |
#   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
#   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | o |        Unused Flags     |L|p|R|           Loc-AFI             |
#   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  \|                             Locator                           |
#   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
class lisp_map_notify(object):
    def __init__(self, lisp_sockets):
        self.etr = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.etr_port = 0
        self.retransmit_timer = None
        self.lisp_sockets = lisp_sockets
        self.retry_count = 0
        self.record_count = 0
        self.alg_id = LISP_NONE_ALG_ID
        self.key_id = 0
        self.auth_len = 0
        self.auth_data = ""
        self.nonce = 0
        self.nonce_key = ""
        self.packet = None
        self.site = ""
        self.map_notify_ack = False
        self.eid_records = ""
        self.eid_list = []
    #enddef

    def print_notify(self):
        auth_data = binascii.hexlify(self.auth_data)
        if (self.alg_id == LISP_SHA_1_96_ALG_ID and len(auth_data) != 40): 
            auth_data = self.auth_data
        elif (self.alg_id == LISP_SHA_256_128_ALG_ID and len(auth_data) != 64):
            auth_data = self.auth_data
        #endif
        line = ("{} -> record-count: {}, nonce: 0x{}, key/alg-id: " +
            "{}{}{}, auth-len: {}, auth-data: {}")
        lprint(line.format(bold("Map-Notify-Ack", False) if \
            self.map_notify_ack else bold("Map-Notify", False),
            self.record_count, lisp_hex_string(self.nonce), self.key_id,
            self.alg_id, " (sha1)" if (self.key_id == LISP_SHA_1_96_ALG_ID) \
            else (" (sha2)" if (self.key_id == LISP_SHA_256_128_ALG_ID) else \
            ""), self.auth_len, auth_data))
    #enddef

    def zero_auth(self, packet):
        if (self.alg_id == LISP_NONE_ALG_ID): return(packet)
        if (self.alg_id == LISP_SHA_1_96_ALG_ID):
            auth_data = struct.pack("QQI", 0, 0, 0)
        #endif
        if (self.alg_id == LISP_SHA_256_128_ALG_ID):
            auth_data = struct.pack("QQQQ", 0, 0, 0, 0)
        #endif
        packet += auth_data
        return(packet)
    #enddef

    def encode(self, eid_records, password):
        if (self.map_notify_ack):
            first_long = (LISP_MAP_NOTIFY_ACK << 28) | self.record_count
        else:
            first_long = (LISP_MAP_NOTIFY << 28) | self.record_count
        #endif
        packet = struct.pack("I", socket.htonl(first_long))
        packet += struct.pack("QBBH", self.nonce, self.key_id, self.alg_id,
            socket.htons(self.auth_len))

        if (self.alg_id == LISP_NONE_ALG_ID):
            self.packet = packet + eid_records
            return(self.packet)
        #endif

        #
        # Run authentication hash across packet.
        #
        packet = self.zero_auth(packet)
        packet += eid_records

        hashval = lisp_hash_me(packet, self.alg_id, password, False)
            
        offset = struct.calcsize("I") + struct.calcsize("QHH")
        auth_len = self.auth_len
        self.auth_data = hashval
        packet = packet[0:offset] + hashval + packet[offset + auth_len::]
        self.packet = packet
        return(packet)
    #enddef

    def decode(self, packet):
        orig_packet = packet
        packet_format = "I"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        first_long = struct.unpack(packet_format, packet[:format_size])
        first_long = socket.ntohl(first_long[0])
        self.map_notify_ack = ((first_long >> 28) == LISP_MAP_NOTIFY_ACK)
        self.record_count = first_long & 0xff
        packet = packet[format_size::]

        packet_format = "QBBH"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        self.nonce, self.key_id, self.alg_id, self.auth_len = \
            struct.unpack(packet_format, packet[:format_size])
        self.nonce_key = lisp_hex_string(self.nonce)
        self.auth_len = socket.ntohs(self.auth_len)
        packet = packet[format_size::]
        self.eid_records = packet[self.auth_len::]

        if (self.auth_len == 0): return(self.eid_records)

        #
        # Parse authentication and zero out the auth field in the packet.
        #
        if (len(packet) < self.auth_len): return(None)

        auth_len = self.auth_len
        if (self.alg_id == LISP_SHA_1_96_ALG_ID):
            auth1, auth2, auth3 = struct.unpack("QQI", packet[:auth_len])
            auth4 = ""
        #endif
        if (self.alg_id == LISP_SHA_256_128_ALG_ID):
            auth1, auth2, auth3, auth4 = struct.unpack("QQQQ", 
                packet[:auth_len])
        #endif
        self.auth_data = lisp_concat_auth_data(self.alg_id, auth1, auth2, 
            auth3, auth4)                       

        format_size = struct.calcsize("I") + struct.calcsize("QHH")
        packet = self.zero_auth(orig_packet[:format_size])
        format_size += auth_len
        packet += orig_packet[format_size::]
        return(packet)
    #enddef
#endclass

#
#  Map-Request message format is:
#     
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |Type=1 |A|M|P|S|p|s|m|I|  Rsvd |N|L|D|   IRC   | Record Count  |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                         Nonce . . .                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                         . . . Nonce                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |         Source-EID-AFI        |   Source EID Address  ...     |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |         ITR-RLOC-AFI 1        |    ITR-RLOC Address 1  ...    |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                              ...                              |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |         ITR-RLOC-AFI n        |    ITR-RLOC Address n  ...    |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     / |N| Reserved    | EID mask-len  |        EID-prefix-AFI         |
#  Rec +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     \ |                       EID-prefix  ...                         |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                   Map-Reply Record  ...                       |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                     Mapping Protocol Data                     |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                             xTR-ID                            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# When a Map-Request is signed, the hash is over the IPv6 CGA based EID,
# the Map-Request Nonce, and the EID-record. The signature is placed in
# the Source-EID as a LCAF JSON Type string of { "source-eid" : "<cga>", 
# "signature-eid" : "<cga-of-signer>", "signature" : "<sig"> }. 
#
# Generating private/public key-pairs via:
#
#   openssl genpkey -algorithm RSA -out privkey.pem \
#                   -pkeyopt rsa_keygen_bits:2048
#   openssl rsa -pubout -in privkey.pem -out pubkey.pem
#
# And use ecdsa.VerifyingKey.from_pem() after reading in file.
#
# xTR-ID is appended to the end of a Map-Request when a subscription request
# is piggybacked (when self.subscribe_bit is True).
#
class lisp_map_request(object):
    def __init__(self):
        self.auth_bit = False
        self.map_data_present = False
        self.rloc_probe = False
        self.smr_bit = False
        self.pitr_bit = False
        self.smr_invoked_bit = False
        self.mobile_node = False
        self.xtr_id_present = False
        self.decent_nat_xtr = False
        self.local_xtr = False
        self.dont_reply_bit = False
        self.itr_rloc_count = 0
        self.record_count = 0
        self.nonce = 0
        self.signature_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.source_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.target_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.target_group = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.itr_rlocs = []
        self.keys = None
        self.privkey_filename = None
        self.map_request_signature = None
        self.subscribe_bit = False
        self.xtr_id = None
        self.json_telemetry = None
    #enddef

    def print_prefix(self):
        if (self.target_group.is_null()): 
            return(green(self.target_eid.print_prefix(), False))
        #endif
        return(green(self.target_eid.print_sg(self.target_group), False))
    #enddef

    def print_map_request(self):
        xtr_id = ""
        if (self.xtr_id != None and self.subscribe_bit):
            xtr_id = "subscribe, xtr-id: 0x{}, ".format(lisp_hex_string( \
                self.xtr_id))
        #endif

        line = ("{} -> flags: {}{}{}{}{}{}{}{}{}{}{}, itr-rloc-" +
            "count: {} (+1), record-count: {}, nonce: 0x{}, source-eid: " +
            "afi {}, {}{}, target-eid: afi {}, {}, {}ITR-RLOCs:")

        lprint(line.format(bold("Map-Request", False), \
            "A" if self.auth_bit else "a",
            "D" if self.map_data_present else "d",
            "R" if self.rloc_probe else "r",
            "S" if self.smr_bit else "s",
            "P" if self.pitr_bit else "p",
            "I" if self.smr_invoked_bit else "i",
            "M" if self.mobile_node else "m",
            "X" if self.xtr_id_present else "x",
            "N" if self.decent_nat_xtr else "n",
            "L" if self.local_xtr else "l",
            "D" if self.dont_reply_bit else "d", self.itr_rloc_count,
            self.record_count, lisp_hex_string(self.nonce), 
            self.source_eid.afi, green(self.source_eid.print_address(), False),
            " (with sig)" if self.map_request_signature != None else "",
            self.target_eid.afi, green(self.print_prefix(), False), xtr_id))

        keys = self.keys
        for itr in self.itr_rlocs:
            if (itr.afi == LISP_AFI_LCAF and self.json_telemetry != None):
                continue
            #endif
            itr_str = red(itr.print_address_no_iid(), False)
            lprint("  itr-rloc: afi {} {}{}".format(itr.afi, itr_str,
                "" if (keys == None) else ", " + keys[1].print_keys()))
            keys = None
        #endfor
        if (self.json_telemetry != None):
            lprint("  itr-rloc: afi {} telemetry: {}".format(LISP_AFI_LCAF,
                self.json_telemetry))
        #endif
    #enddef

    def sign_map_request(self, privkey):
        sig_eid = self.signature_eid.print_address()
        source_eid = self.source_eid.print_address()
        target_eid = self.target_eid.print_address()
        sig_data = lisp_hex_string(self.nonce) + source_eid + target_eid
        self.map_request_signature = privkey.sign(sig_data.encode())
        sig = binascii.b2a_base64(self.map_request_signature)
        sig = { "source-eid" : source_eid, "signature-eid" : sig_eid, 
            "signature" : sig.decode() }
        return(json.dumps(sig))
    #enddef

    def verify_map_request_sig(self, pubkey):
        sseid = green(self.signature_eid.print_address(), False)
        if (pubkey == None):
            lprint("Public-key not found for signature-EID {}".format(sseid))
            return(False)
        #endif
                 
        source_eid = self.source_eid.print_address()
        target_eid = self.target_eid.print_address()
        sig_data = lisp_hex_string(self.nonce) + source_eid + target_eid
        pubkey = binascii.a2b_base64(pubkey)

        good = True
        try:
            key = ecdsa.VerifyingKey.from_pem(pubkey)
        except:
            lprint("Invalid public-key in mapping system for sig-eid {}". \
                format(self.signature_eid.print_address_no_iid()))
            good = False
        #endtry
            
        if (good):
            try:
                sig_data = sig_data.encode()
                good = key.verify(self.map_request_signature, sig_data)
            except:
                good = False
            #endtry
        #endif

        passfail = bold("passed" if good else "failed", False)
        lprint("Signature verification {} for EID {}".format(passfail, sseid))
        return(good)
    #enddef

    def encode_json(self, json_string):
        lcaf_type = LISP_LCAF_JSON_TYPE
        lcaf_afi = socket.htons(LISP_AFI_LCAF)
        lcaf_len = socket.htons(len(json_string) + 4)
        json_len = socket.htons(len(json_string))
        packet = struct.pack("HBBBBHH", lcaf_afi, 0, 0, lcaf_type, 0, lcaf_len,
            json_len)
        packet += json_string.encode()
        packet += struct.pack("H", 0)
        return(packet)
    #enddef

    def encode(self, probe_dest, probe_port):
        first_long = (LISP_MAP_REQUEST << 28) | self.record_count

        telemetry = lisp_telemetry_configured() if (self.rloc_probe) else None
        if (telemetry != None): self.itr_rloc_count += 1
        first_long = first_long | (self.itr_rloc_count << 8)

        if (self.auth_bit): first_long |= 0x08000000
        if (self.map_data_present): first_long |= 0x04000000
        if (self.rloc_probe): first_long |= 0x02000000
        if (self.smr_bit): first_long |= 0x01000000
        if (self.pitr_bit): first_long |= 0x00800000
        if (self.smr_invoked_bit): first_long |= 0x00400000
        if (self.mobile_node): first_long |= 0x00200000
        if (self.xtr_id_present): first_long |= 0x00100000
        if (self.decent_nat_xtr): first_long |= 0x00008000
        if (self.local_xtr): first_long |= 0x00004000
        if (self.dont_reply_bit): first_long |= 0x00002000

        packet = struct.pack("I", socket.htonl(first_long))
        packet += struct.pack("Q", self.nonce)

        #
        # Check if Map-Request is going to be signed. If so, encode json-string
        # in source-EID field. Otherwise, just encode source-EID with instance-
        # id in source-EID field.
        #
        encode_sig = False
        filename = self.privkey_filename
        if (filename != None and os.path.exists(filename)):
            f = open(filename, "r"); key = f.read(); f.close()
            try:
                key = ecdsa.SigningKey.from_pem(key)
            except:
                return(None)
            #endtry
            json_string = self.sign_map_request(key)
            encode_sig = True
        elif (self.map_request_signature != None):
            sig = binascii.b2a_base64(self.map_request_signature)
            json_string = { "source-eid" : self.source_eid.print_address(),
                "signature-eid" : self.signature_eid.print_address(),
                "signature" : sig }
            json_string = json.dumps(json_string)
            encode_sig = True
        #endif
        if (encode_sig):
            packet += self.encode_json(json_string)
        else:
            if (self.source_eid.instance_id != 0):
                packet += struct.pack("H", socket.htons(LISP_AFI_LCAF))
                packet += self.source_eid.lcaf_encode_iid()
            else:
                packet += struct.pack("H", socket.htons(self.source_eid.afi))
                packet += self.source_eid.pack_address()
            #endif
        #endif

        #
        # For RLOC-probes, see if keys already negotiated for RLOC. If so,
        # use them so a new DH exchange does not happen.
        #
        if (probe_dest):
            if (probe_port == 0): probe_port = LISP_DATA_PORT
            addr_str = probe_dest.print_address_no_iid() + ":" + \
                str(probe_port)
            if (addr_str in lisp_crypto_keys_by_rloc_encap):
                self.keys = lisp_crypto_keys_by_rloc_encap[addr_str]
            #endif
        #endif

        #
        # If security is enabled, put security parameters in the first 
        # ITR-RLOC.
        #
        for itr in self.itr_rlocs:
            if (lisp_data_plane_security and self.itr_rlocs.index(itr) == 0):
                if (self.keys == None or self.keys[1] == None): 
                    keys = lisp_keys(1)
                    self.keys = [None, keys, None, None]
                #endif
                keys = self.keys[1]
                keys.add_key_by_nonce(self.nonce)
                packet += keys.encode_lcaf(itr)
            else:
                packet += struct.pack("H", socket.htons(itr.afi))
                packet += itr.pack_address()
            #endif
        #endfor

        #
        # Add telemetry, if configured and this is an RLOC-probe Map-Request.
        #
        if (telemetry != None):
            ts = str(time.time())
            telemetry = lisp_encode_telemetry(telemetry, io=ts)
            self.json_telemetry = telemetry
            packet += self.encode_json(telemetry)
        #endif

        mask_len = 0 if self.target_eid.is_binary() == False else \
            self.target_eid.mask_len

        subscribe = 0
        if (self.subscribe_bit):
            subscribe = 0x80
            self.xtr_id_present = True
            if (self.xtr_id == None): 
                self.xtr_id = random.randint(0, (2**128)-1)
            #endif
        #endif

        packet_format = "BB"
        packet += struct.pack(packet_format, subscribe, mask_len)

        if (self.target_group.is_null() == False):
            packet += struct.pack("H", socket.htons(LISP_AFI_LCAF))
            packet += self.target_eid.lcaf_encode_sg(self.target_group)
        elif (self.target_eid.instance_id != 0 or 
            self.target_eid.is_geo_prefix()):
            packet += struct.pack("H", socket.htons(LISP_AFI_LCAF))
            packet += self.target_eid.lcaf_encode_iid()
        else:
            packet += struct.pack("H", socket.htons(self.target_eid.afi))
            packet += self.target_eid.pack_address()
        #endif

        #
        # If this is a subscription request, append xTR-ID to end of packet.
        #
        if (self.subscribe_bit): packet = self.encode_xtr_id(packet)
        return(packet)
    #enddef

    def lcaf_decode_json(self, packet):
        packet_format = "BBBBHH"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        rsvd1, flags, lcaf_type, rsvd2, lcaf_len, json_len = \
            struct.unpack(packet_format, packet[:format_size])

        if (lcaf_type != LISP_LCAF_JSON_TYPE): return(packet)

        #
        # Do lcaf-length and json-length checks first.
        #
        lcaf_len = socket.ntohs(lcaf_len)
        json_len = socket.ntohs(json_len)
        packet = packet[format_size::]
        if (len(packet) < lcaf_len): return(None)
        if (lcaf_len != json_len + 4): return(None)

        #
        # Pull out JSON string from packet.
        #
        json_string = packet[0:json_len]
        packet = packet[json_len::]

        #
        # If telemetry data in the JSON, do not need to convert to dict array.
        #
        if (lisp_is_json_telemetry(json_string) != None):
            self.json_telemetry = json_string
        #endif

        #
        # Get JSON encoded afi-address in JSON, we are expecting AFI of 0.
        #
        packet_format = "H"
        format_size = struct.calcsize(packet_format)
        afi = struct.unpack(packet_format, packet[:format_size])[0]
        packet = packet[format_size::]
        if (afi != 0): return(packet)

        if (self.json_telemetry != None): return(packet)

        #
        # Convert string to dictionary array.
        #
        try:
            json_string = json.loads(json_string)
        except:
            return(None)
        #endtry

        #
        # Store JSON data internally.
        #
        if ("source-eid" not in json_string): return(packet)
        eid = json_string["source-eid"]
        afi = LISP_AFI_IPV4 if eid.count(".") == 3 else LISP_AFI_IPV6 if \
              eid.count(":") == 7 else None
        if (afi == None):
            lprint("Bad JSON 'source-eid' value: {}".format(eid))
            return(None)
        #endif

        self.source_eid.afi = afi
        self.source_eid.store_address(eid)

        if ("signature-eid" not in json_string): return(packet)
        eid = json_string["signature-eid"]
        if (eid.count(":") != 7): 
            lprint("Bad JSON 'signature-eid' value: {}".format(eid))
            return(None)
        #endif

        self.signature_eid.afi = LISP_AFI_IPV6
        self.signature_eid.store_address(eid)

        if ("signature" not in json_string): return(packet)
        sig = binascii.a2b_base64(json_string["signature"])
        self.map_request_signature = sig
        return(packet)
    #enddef

    def decode(self, packet, source, port):
        packet_format = "I"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        first_long = struct.unpack(packet_format, packet[:format_size])
        first_long = first_long[0]
        packet = packet[format_size::]

        packet_format = "Q"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)
        
        nonce = struct.unpack(packet_format, packet[:format_size])
        packet = packet[format_size::]

        first_long = socket.ntohl(first_long)
        self.auth_bit = True if (first_long & 0x08000000) else False
        self.map_data_present = True if (first_long & 0x04000000) else False
        self.rloc_probe = True if (first_long & 0x02000000) else False
        self.smr_bit = True if (first_long & 0x01000000) else False
        self.pitr_bit = True if (first_long & 0x00800000) else False
        self.smr_invoked_bit = True if (first_long & 0x00400000) else False
        self.mobile_node = True if (first_long & 0x00200000) else False
        self.xtr_id_present = True if (first_long & 0x00100000) else False
        self.decent_nat_xtr = True if (first_long & 0x00008000) else False
        self.local_xtr = True if (first_long & 0x00004000) else False
        self.dont_reply_bit = True if (first_long & 0x00002000) else False
        self.itr_rloc_count = ((first_long >> 8) & 0x1f)
        self.record_count = first_long & 0xff
        self.nonce = nonce[0]

        #
        # Decode xTR-ID if sender set the xtr_id_present bit.
        #
        if (self.xtr_id_present): 
            if (self.decode_xtr_id(packet) == False): return(None)
        #endif

        format_size = struct.calcsize("H")
        if (len(packet) < format_size): return(None)

        afi = struct.unpack("H", packet[:format_size])
        self.source_eid.afi = socket.ntohs(afi[0])
        packet = packet[format_size::]

        if (self.source_eid.afi == LISP_AFI_LCAF):
            save_packet = packet
            packet = self.source_eid.lcaf_decode_iid(packet)
            if (packet == None): 
                packet = self.lcaf_decode_json(save_packet)
                if (packet == None): return(None)
            #endif
        elif (self.source_eid.afi != LISP_AFI_NONE):
            packet = self.source_eid.unpack_address(packet)
            if (packet == None): return(None)
        #endif
        self.source_eid.mask_len = self.source_eid.host_mask_len()

        no_crypto = (os.getenv("LISP_NO_CRYPTO") != None)
        self.itr_rlocs = []
        itr_rloc_count = self.itr_rloc_count + 1
        
        while (itr_rloc_count != 0):
            format_size = struct.calcsize("H")
            if (len(packet) < format_size): return(None)

            afi = socket.ntohs(struct.unpack("H", packet[:format_size])[0])
            itr = lisp_address(LISP_AFI_NONE, "", 32, 0)
            itr.afi = afi

            #
            # We may have telemetry in the ITR-RLOCs. Check here to avoid
            # security key material logic.
            #
            if (itr.afi == LISP_AFI_LCAF):
                orig_packet = packet
                json_packet = packet[format_size::]
                packet = self.lcaf_decode_json(json_packet)
                if (packet == None): return(None)
                if (packet == json_packet): packet = orig_packet
            #endif

            #
            # If Security Type LCAF, get security parameters and store in
            # lisp_keys().
            #
            if (itr.afi != LISP_AFI_LCAF):
                if (len(packet) < itr.addr_length()): return(None)
                packet = itr.unpack_address(packet[format_size::])
                if (packet == None): return(None)

                if (no_crypto):
                    self.itr_rlocs.append(itr)
                    itr_rloc_count -= 1
                    continue
                #endif

                addr_str = lisp_build_crypto_decap_lookup_key(itr, port)

                #
                # Decide if we should remove security key state if ITR decided
                # to stop doing key exchange when it previously had.
                #
                if (lisp_nat_traversal and itr.is_private_address() and \
                    source): itr = source
                rloc_keys = lisp_crypto_keys_by_rloc_decap
                if (addr_str in rloc_keys): rloc_keys.pop(addr_str)

                #
                # If "ipc-data-plane = yes" is configured, we need to tell the
                # data-plane from the lisp-etr process there is no longer a 
                # decryption key.
                #
                lisp_write_ipc_decap_key(addr_str, None)

            elif (self.json_telemetry == None):
                
                #
                # Decode key material if we found no telemetry data.
                #
                orig_packet = packet
                decode_key = lisp_keys(1)
                packet = decode_key.decode_lcaf(orig_packet, 0)

                if (packet == None): return(None)

                #
                # Other side may not do ECDH.
                #
                cs_list = [LISP_CS_25519_CBC, LISP_CS_25519_GCM,
                    LISP_CS_25519_CHACHA]
                if (decode_key.cipher_suite in cs_list):
                    if (decode_key.cipher_suite == LISP_CS_25519_CBC or
                        decode_key.cipher_suite == LISP_CS_25519_GCM):
                        key = lisp_keys(1, do_poly=False, do_chacha=False)
                    #endif
                    if (decode_key.cipher_suite == LISP_CS_25519_CHACHA):
                        key = lisp_keys(1, do_poly=True, do_chacha=True)
                    #endif
                else:
                    key = lisp_keys(1, do_poly=False, do_curve=False,
                        do_chacha=False)
                #endif
                packet = key.decode_lcaf(orig_packet, 0)
                if (packet == None): return(None)

                if (len(packet) < format_size): return(None)
                afi = struct.unpack("H", packet[:format_size])[0]
                itr.afi = socket.ntohs(afi)
                if (len(packet) < itr.addr_length()): return(None)

                packet = itr.unpack_address(packet[format_size::])
                if (packet == None): return(None)

                if (no_crypto):
                    self.itr_rlocs.append(itr)
                    itr_rloc_count -= 1
                    continue
                #endif
                    
                addr_str = lisp_build_crypto_decap_lookup_key(itr, port)
                
                stored_key = None
                if (lisp_nat_traversal and itr.is_private_address() and \
                    source): itr = source

                if (addr_str in lisp_crypto_keys_by_rloc_decap):
                    keys = lisp_crypto_keys_by_rloc_decap[addr_str]
                    stored_key = keys[1] if keys and keys[1] else None
                #endif

                new = True
                if (stored_key):
                    if (stored_key.compare_keys(key)):
                        self.keys = [None, stored_key, None, None]
                        lprint("Maintain stored decap-keys for RLOC {}". \
                            format(red(addr_str, False)))
                    else:
                        new = False
                        remote = bold("Remote decap-rekeying", False)
                        lprint("{} for RLOC {}".format(remote, red(addr_str, 
                            False)))
                        key.copy_keypair(stored_key)
                        key.uptime = stored_key.uptime
                        stored_key = None
                    #endif
                #endif

                if (stored_key == None):
                    self.keys = [None, key, None, None]
                    if (lisp_i_am_etr == False and lisp_i_am_rtr == False):
                        key.local_public_key = None
                        lprint("{} for {}".format(bold("Ignoring decap-keys", 
                            False), red(addr_str, False)))
                    elif (key.remote_public_key != None): 
                        if (new):
                            lprint("{} for RLOC {}".format( \
                                bold("New decap-keying", False), 
                                red(addr_str, False)))
                        #endif
                        key.compute_shared_key("decap")
                        key.add_key_by_rloc(addr_str, False)
                    #endif
                #endif
            #endif 

            self.itr_rlocs.append(itr)
            itr_rloc_count -= 1
        #endwhile

        format_size = struct.calcsize("BBH")
        if (len(packet) < format_size): return(None)

        subscribe, mask_len, afi = struct.unpack("BBH", packet[:format_size])
        self.subscribe_bit = (subscribe & 0x80)
        self.target_eid.afi = socket.ntohs(afi)
        packet = packet[format_size::]

        self.target_eid.mask_len = mask_len
        if (self.target_eid.afi == LISP_AFI_LCAF):
            packet, target_group = self.target_eid.lcaf_decode_eid(packet)
            if (packet == None): return(None)
            if (target_group): self.target_group = target_group
        else:
            packet = self.target_eid.unpack_address(packet)
            if (packet == None): return(None)
            packet = packet[format_size::]
        #endif
        return(packet)
    #enddef

    def print_eid_tuple(self):
        return(lisp_print_eid_tuple(self.target_eid, self.target_group))
    #enddef

    def encode_xtr_id(self, packet):
        xtr_id_upper = self.xtr_id >> 64
        xtr_id_lower = self.xtr_id & 0xffffffffffffffff
        xtr_id_upper = byte_swap_64(xtr_id_upper)
        xtr_id_lower = byte_swap_64(xtr_id_lower)
        packet += struct.pack("QQ", xtr_id_upper, xtr_id_lower)
        return(packet)
    #enddef

    def decode_xtr_id(self, packet):
        format_size = struct.calcsize("QQ")
        if (len(packet) < format_size): return(None)
        packet = packet[len(packet)-format_size::]
        xtr_id_upper, xtr_id_lower = struct.unpack("QQ", packet[:format_size])
        xtr_id_upper = byte_swap_64(xtr_id_upper)
        xtr_id_lower = byte_swap_64(xtr_id_lower)
        self.xtr_id = (xtr_id_upper << 64) | xtr_id_lower
        return(True)
    #enddef
#endclass

#
# Map-Reply Message Format
#   
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |Type=2 |P|E|S|     Reserved     |   Hop Count  | Record Count  |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                         Nonce . . .                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                         . . . Nonce                           |
#   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |   |                          Record  TTL                          |
#   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   R   |N|Locator Count | EID mask-len  | ACT |A|      Reserved        |
#   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   c   | Rsvd  |  Map-Version Number   |            EID-AFI            |
#   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   r   |                          EID-prefix                           |
#   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
#   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | o |        Unused Flags     |L|p|R|           Loc-AFI             |
#   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  \|                             Locator                           |
#   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                     Mapping Protocol Data                     |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
class lisp_map_reply(object):
    def __init__(self):
        self.rloc_probe = False
        self.echo_nonce_capable = False
        self.security = False
        self.record_count = 0
        self.hop_count = 0
        self.nonce = 0
        self.keys = None
    #enddef

    def print_map_reply(self):
        line = "{} -> flags: {}{}{}, hop-count: {}, record-count: {}, " + \
            "nonce: 0x{}"
        lprint(line.format(bold("Map-Reply", False), \
            "R" if self.rloc_probe else "r",
            "E" if self.echo_nonce_capable else "e",
            "S" if self.security else "s", self.hop_count, self.record_count, 
            lisp_hex_string(self.nonce)))
    #enddef

    def encode(self):
        first_long = (LISP_MAP_REPLY << 28) | self.record_count
        first_long |= self.hop_count << 8
        if (self.rloc_probe): first_long |= 0x08000000
        if (self.echo_nonce_capable): first_long |= 0x04000000
        if (self.security): first_long |= 0x02000000

        packet = struct.pack("I", socket.htonl(first_long))
        packet += struct.pack("Q", self.nonce)
        return(packet)
    #enddef

    def decode(self, packet):
        packet_format = "I"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        first_long = struct.unpack(packet_format, packet[:format_size])
        first_long = first_long[0]
        packet = packet[format_size::]

        packet_format = "Q"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        nonce = struct.unpack(packet_format, packet[:format_size])
        packet = packet[format_size::]

        first_long = socket.ntohl(first_long)
        self.rloc_probe = True if (first_long & 0x08000000) else False
        self.echo_nonce_capable = True if (first_long & 0x04000000) else False
        self.security = True if (first_long & 0x02000000) else False
        self.hop_count = (first_long >> 8) & 0xff
        self.record_count = first_long & 0xff
        self.nonce = nonce[0]

        if (self.nonce in lisp_crypto_keys_by_nonce):
            self.keys = lisp_crypto_keys_by_nonce[self.nonce]
            self.keys[1].delete_key_by_nonce(self.nonce)
        #endif
        return(packet)
    #enddef
#endclass

#
# This is the structure of an EID record in a Map-Request, Map-Reply, and
# Map-Register.
#
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          Record TTL                           |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  | Locator Count | EID mask-len  | ACT |A|I|E|     Reserved      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  | Rsvd  |  Map-Version Number   |        EID-Prefix-AFI         |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          EID-Prefix                           |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# When E is set, the entire locator-set records are encrypted with the chacha
# cipher.
#
# And this for a EID-record in a Map-Referral.
#
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          Record  TTL                          |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  | Referral Count| EID mask-len  | ACT |A|I|E|     Reserved      |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |SigCnt |   Map Version Number  |            EID-AFI            |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                          EID-prefix ...                       |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
class lisp_eid_record(object):
    def __init__(self):
        self.record_ttl = 0
        self.rloc_count = 0
        self.action = 0
        self.authoritative = False
        self.ddt_incomplete = False
        self.signature_count = 0
        self.map_version = 0
        self.eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.group = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.record_ttl = 0
    #enddef

    def print_prefix(self):
        if (self.group.is_null()): 
            return(green(self.eid.print_prefix(), False))
        #endif
        return(green(self.eid.print_sg(self.group), False))
    #enddef

    def print_ttl(self):
        ttl = self.record_ttl
        if (self.record_ttl & 0x80000000):
            ttl = str(self.record_ttl & 0x7fffffff) + " secs"
        elif ((ttl % 60) == 0):
            ttl = str(old_div(ttl, 60)) + " hours"
        else:
            ttl = str(ttl) + " mins"
        #endif
        return(ttl)
    #enddef

    def store_ttl(self):
        ttl = self.record_ttl * 60
        if (self.record_ttl & 0x80000000): ttl = self.record_ttl & 0x7fffffff
        return(ttl)
    #enddef

    def print_record(self, indent, ddt):
        incomplete = ""
        sig_count = ""
        action_str = bold("invalid-action", False)
        if (ddt):
            if (self.action < len(lisp_map_referral_action_string)):
                action_str = lisp_map_referral_action_string[self.action]
                action_str = bold(action_str, False)
                incomplete = (", " + bold("ddt-incomplete", False)) if \
                    self.ddt_incomplete else ""
                sig_count = (", sig-count: " + str(self.signature_count)) if \
                    (self.signature_count != 0) else ""
            #endif
        else:
            if (self.action < len(lisp_map_reply_action_string)):
                action_str = lisp_map_reply_action_string[self.action]
                if (self.action != LISP_NO_ACTION): 
                    action_str = bold(action_str, False)
                #endif
            #endif
        #endif

        afi = LISP_AFI_LCAF if (self.eid.afi < 0) else self.eid.afi
        line = ("{}EID-record -> record-ttl: {}, rloc-count: {}, action: " +
            "{}, {}{}{}, map-version: {}, afi: {}, [iid]eid/ml: {}")

        lprint(line.format(indent, self.print_ttl(), self.rloc_count, 
            action_str, "auth" if (self.authoritative is True) else "non-auth",
            incomplete, sig_count, self.map_version, afi, 
            green(self.print_prefix(), False)))
    #enddef

    def encode(self):
        action = self.action << 13
        if (self.authoritative): action |= 0x1000
        if (self.ddt_incomplete): action |= 0x800

        #
        # Decide on AFI value.
        #
        afi = self.eid.afi if (self.eid.instance_id == 0) else LISP_AFI_LCAF
        if (afi < 0): afi = LISP_AFI_LCAF
        sg = (self.group.is_null() == False)
        if (sg): afi = LISP_AFI_LCAF

        sig_mv = (self.signature_count << 12) | self.map_version
        mask_len = 0 if self.eid.is_binary() == False else self.eid.mask_len

        packet = struct.pack("IBBHHH", socket.htonl(self.record_ttl), 
            self.rloc_count, mask_len, socket.htons(action), 
            socket.htons(sig_mv), socket.htons(afi))

        #
        # Check if we are encoding an (S,G) entry.
        #
        if (sg):
            packet += self.eid.lcaf_encode_sg(self.group)
            return(packet)
        #endif

        #
        # Check if we are encoding an geo-prefix in an EID-record.
        #
        if (self.eid.afi == LISP_AFI_GEO_COORD and self.eid.instance_id == 0):
            packet = packet[0:-2]
            packet += self.eid.address.encode_geo()
            return(packet)
        #endif

        #
        # Check if instance-ID needs to be encoded in the EID record.
        #
        if (afi == LISP_AFI_LCAF):
            packet += self.eid.lcaf_encode_iid()
            return(packet)
        #endif

        #
        # Just encode the AFI for the EID.
        #
        packet += self.eid.pack_address()
        return(packet)
    #enddef

    def decode(self, packet):
        packet_format = "IBBHHH"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        self.record_ttl, self.rloc_count, self.eid.mask_len, action, \
            self.map_version, self.eid.afi = \
            struct.unpack(packet_format, packet[:format_size])

        self.record_ttl = socket.ntohl(self.record_ttl)
        action = socket.ntohs(action)
        self.action = (action >> 13) & 0x7
        self.authoritative = True if ((action >> 12) & 1) else False
        self.ddt_incomplete = True if ((action >> 11) & 1) else False
        self.map_version = socket.ntohs(self.map_version)
        self.signature_count = self.map_version >> 12
        self.map_version = self.map_version & 0xfff
        self.eid.afi = socket.ntohs(self.eid.afi)
        self.eid.instance_id = 0
        packet = packet[format_size::]

        #
        # Check if instance-ID LCAF is encoded in the EID-record.
        #
        if (self.eid.afi == LISP_AFI_LCAF):
            packet, group = self.eid.lcaf_decode_eid(packet)
            if (group): self.group = group
            self.group.instance_id = self.eid.instance_id
            return(packet)
        #endif

        packet = self.eid.unpack_address(packet)
        return(packet)
    #enddef

    def print_eid_tuple(self):
        return(lisp_print_eid_tuple(self.eid, self.group))
    #enddef
#endclass

#
# Encapsualted Control Message Format
# 
#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      / |                       IPv4 or IPv6 Header                     |
#    OH  |                      (uses RLOC addresses)                    |
#      \ |                                                               |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      / |       Source Port = xxxx      |       Dest Port = 4342        |
#    UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      \ |           UDP Length          |        UDP Checksum           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    LH  |Type=8 |S|D|E|M|            Reserved                           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      / |                       IPv4 or IPv6 Header                     |
#    IH  |                  (uses RLOC or EID addresses)                 |
#      \ |                                                               |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      / |       Source Port = xxxx      |       Dest Port = yyyy        |
#    UDP +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      \ |           UDP Length          |        UDP Checksum           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    LCM |                      LISP Control Message                     |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#

LISP_UDP_PROTOCOL    = 17
LISP_DEFAULT_ECM_TTL = 128

class lisp_ecm(object):
    def __init__(self, sport):
        self.security = False
        self.ddt = False
        self.to_etr = False
        self.to_ms = False
        self.length = 0
        self.ttl = LISP_DEFAULT_ECM_TTL
        self.protocol = LISP_UDP_PROTOCOL
        self.ip_checksum = 0
        self.source = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.dest = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.udp_sport = sport
        self.udp_dport = LISP_CTRL_PORT
        self.udp_checksum = 0
        self.udp_length = 0
        self.afi = LISP_AFI_NONE
    #enddef

    def print_ecm(self):
        line = ("{} -> flags: {}{}{}{}, " + \
            "inner IP: {} -> {}, inner UDP: {} -> {}")
        lprint(line.format(bold("ECM", False), "S" if self.security else "s",
            "D" if self.ddt else "d", "E" if self.to_etr else "e",
            "M" if self.to_ms else "m", 
            green(self.source.print_address(), False),
            green(self.dest.print_address(), False), self.udp_sport, 
            self.udp_dport))
    #enddef

    def encode(self, packet, inner_source, inner_dest):
        self.udp_length = len(packet) + 8
        self.source = inner_source
        self.dest = inner_dest
        if (inner_dest.is_ipv4()): 
            self.afi = LISP_AFI_IPV4
            self.length = self.udp_length + 20
        #endif
        if (inner_dest.is_ipv6()): 
            self.afi = LISP_AFI_IPV6
            self.length = self.udp_length
        #endif

        #
        # Encode ECM header first, then the IPv4 or IPv6 header, then the
        # UDP header.
        #
        first_long = (LISP_ECM << 28)
        if (self.security): first_long |= 0x08000000
        if (self.ddt): first_long |= 0x04000000
        if (self.to_etr): first_long |= 0x02000000
        if (self.to_ms): first_long |= 0x01000000

        ecm = struct.pack("I", socket.htonl(first_long))

        ip = ""
        if (self.afi == LISP_AFI_IPV4):
            ip = struct.pack("BBHHHBBH", 0x45, 0, socket.htons(self.length),
                0, 0, self.ttl, self.protocol, socket.htons(self.ip_checksum))
            ip += self.source.pack_address()
            ip += self.dest.pack_address()
            ip = lisp_ip_checksum(ip)
        #endif
        if (self.afi == LISP_AFI_IPV6):
            ip = struct.pack("BBHHBB", 0x60, 0, 0, socket.htons(self.length),
                self.protocol, self.ttl)
            ip += self.source.pack_address()
            ip += self.dest.pack_address()
        #endif

        s = socket.htons(self.udp_sport)
        d = socket.htons(self.udp_dport)
        l = socket.htons(self.udp_length)
        c = socket.htons(self.udp_checksum)
        udp = struct.pack("HHHH", s, d, l, c)
        return(ecm + ip + udp)
    #enddef

    def decode(self, packet):

        #
        # Decode ECM header.
        #
        packet_format = "I"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        first_long = struct.unpack(packet_format, packet[:format_size])

        first_long  = socket.ntohl(first_long[0])
        self.security = True if (first_long & 0x08000000) else False
        self.ddt = True if (first_long & 0x04000000) else False
        self.to_etr = True if (first_long & 0x02000000) else False
        self.to_ms = True if (first_long & 0x01000000) else False
        packet = packet[format_size::]

        #
        # Decode inner IPv4/IPv6 and UDP header.
        #
        if (len(packet) < 1): return(None)
        version = struct.unpack("B", packet[0:1])[0]
        version = version >> 4

        if (version == 4):
            format_size = struct.calcsize("HHIBBH")
            if (len(packet) < format_size): return(None)

            x, l, x, t, p, c = struct.unpack("HHIBBH", packet[:format_size])
            self.length = socket.ntohs(l)
            self.ttl = t
            self.protocol = p
            self.ip_checksum = socket.ntohs(c)
            self.source.afi = self.dest.afi = LISP_AFI_IPV4

            #
            # Zero out IPv4 header checksum.
            #
            p = struct.pack("H", 0)
            offset1 = struct.calcsize("HHIBB")
            offset2 = struct.calcsize("H")
            packet = packet[:offset1] + p + packet[offset1+offset2:]

            packet = packet[format_size::]
            packet = self.source.unpack_address(packet)
            if (packet == None): return(None)
            packet = self.dest.unpack_address(packet)
            if (packet == None): return(None)
        #endif

        if (version == 6):
            format_size = struct.calcsize("IHBB")
            if (len(packet) < format_size): return(None)

            x, l, p, t = struct.unpack("IHBB", packet[:format_size])
            self.length = socket.ntohs(l)
            self.protocol = p
            self.ttl = t
            self.source.afi = self.dest.afi = LISP_AFI_IPV6

            packet = packet[format_size::]
            packet = self.source.unpack_address(packet)
            if (packet == None): return(None)
            packet = self.dest.unpack_address(packet)
            if (packet == None): return(None)
        #endif
        
        self.source.mask_len = self.source.host_mask_len()
        self.dest.mask_len = self.dest.host_mask_len()

        format_size = struct.calcsize("HHHH")
        if (len(packet) < format_size): return(None)

        s, d, l, c = struct.unpack("HHHH", packet[:format_size])
        self.udp_sport = socket.ntohs(s)
        self.udp_dport = socket.ntohs(d)
        self.udp_length = socket.ntohs(l)
        self.udp_checksum = socket.ntohs(c)
        packet = packet[format_size::]
        return(packet)
    #enddef
#endclass

#
# This is the structure of an RLOC record in a Map-Request, Map-Reply, and
# Map-Register's EID record.
#
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   /|    Priority   |    Weight     |  M Priority   |   M Weight    |
#  L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  o |        Unused Flags     |L|p|R|           Loc-AFI             |
#  c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   \|                             Locator                           |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#   AFI-List LISP Canonical Address Format:
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           AFI = 16387         |    Rsvd1      |     Flags     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |   Type = 1    |     Rsvd2     |         2 + 4 + 2 + 16        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |            AFI = 1            |       IPv4 Address ...        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |     ...  IPv4 Address         |            AFI = 2            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                          IPv6 Address ...                     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                     ...  IPv6 Address  ...                    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                     ...  IPv6 Address  ...                    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                     ...  IPv6 Address                         |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#   Geo Coordinate LISP Canonical Address Format:
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           AFI = 16387         |     Rsvd1     |     Flags     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |   Type = 5    |     Rsvd2     |            Length             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |U|N|E|A|M|R|K|    Reserved     |     Location Uncertainty      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |  Lat Degrees  |        Latitude Milliseconds                  |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |  Long Degrees |        Longitude Milliseconds                 |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                            Altitude                           |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |             Radius            |          Reserved             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |              AFI = x          |         Address  ...          |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#  Explicit Locator Path (ELP) Canonical Address Format:
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           AFI = 16387         |    Rsvd1      |    Flags      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |   Type = 10   |     Rsvd2     |               n               |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |              AFI = x          |           Rsvd3         |L|P|S|
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                         Reencap Hop 1  ...                    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |              AFI = x          |           Rsvd3         |L|P|S|
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                         Reencap Hop k  ...                    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#   Replication List Entry Address Format:
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           AFI = 16387         |     Rsvd1     |     Flags     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |   Type = 13   |    Rsvd2      |             4 + n             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |              Rsvd3            |     Rsvd4     |  Level Value  |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |              AFI = x          |           RTR/ETR #1 ...      |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |              AFI = 17         |    RTR/ETR #1 RLOC Name ...   |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |              Rsvd3            |     Rsvd4     |  Level Value  |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |              AFI = x          |           RTR/ETR  #n ...     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |              AFI = 17         |    RTR/ETR #n RLOC Name ...   |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#   Security Key Canonical Address Format:
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           AFI = 16387         |     Rsvd1     |     Flags     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |   Type = 11   |      Rsvd2    |             6 + n             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |   Key Count   |      Rsvd3    |A| Cipher Suite|   Rsvd4     |R|
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           Key Length          |     Public Key Material ...   |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                    ... Public Key Material                    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |              AFI = x          |       Locator Address ...     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#   JSON Data Model Type Address Format:
#  
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           AFI = 16387         |     Rsvd1     |     Flags     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |   Type = 14   | kid | Rvd2|E|B|            Length             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           JSON length         | JSON binary/text encoding ... |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |              AFI = x          |       Optional Address ...    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#    When the E-bit is set to 1, then the kid is key-id and indicates that
#    value fields in JSON string are encrypted with the encryption key
#    associated with key-id 'kid'.
#
class lisp_rloc_record(object):
    def __init__(self):
        self.priority = 0
        self.weight = 0
        self.mpriority = 0
        self.mweight = 0
        self.local_bit = False
        self.probe_bit = False
        self.reach_bit = False
        self.rloc = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.geo = None
        self.elp = None
        self.rle = None
        self.json = None
        self.rloc_name = None
        self.keys = None
    #enddef

    def print_rloc_name(self, cour=False):
        if (self.rloc_name == None): return("")
        rloc_name = self.rloc_name
        if (cour): rloc_name = lisp_print_cour(rloc_name)
        return('rloc-name: {}'.format(blue(rloc_name, cour)))
    #enddef

    def print_record(self, indent):
        rloc_str = self.print_rloc_name()
        if (rloc_str != ""): rloc_str = ", " + rloc_str
        geo_str = ""
        if (self.geo):
            name = ""
            if (self.geo.geo_name): name = "'{}' ".format(self.geo.geo_name)
            geo_str = ", geo: {}{}".format(name, self.geo.print_geo())
        #endif
        elp_str = ""
        if (self.elp):
            name = ""
            if (self.elp.elp_name): name = "'{}' ".format(self.elp.elp_name)
            elp_str = ", elp: {}{}".format(name, self.elp.print_elp(True))
        #endif
        rle_str = ""
        if (self.rle):
            name = ""
            if (self.rle.rle_name): name = "'{}' ".format(self.rle.rle_name)
            rle_str = ", rle: {}{}".format(name, self.rle.print_rle(False,
                True))
        #endif
        json_str = ""
        if (self.json):
            name = ""
            if (self.json.json_name): 
                name = "'{}' ".format(self.json.json_name)
            #endif
            json_str = ", json: {}".format(self.json.print_json(False))
        #endif

        sec_str = ""
        if (self.rloc.is_null() == False and self.keys and self.keys[1]): 
            sec_str = ", " + self.keys[1].print_keys()
        #endif

        line = ("{}RLOC-record -> flags: {}, {}/{}/{}/{}, afi: {}, rloc: "
                + "{}{}{}{}{}{}{}")
        lprint(line.format(indent, self.print_flags(), self.priority, 
            self.weight, self.mpriority, self.mweight, self.rloc.afi, 
            red(self.rloc.print_address_no_iid(), False), rloc_str, geo_str, 
            elp_str, rle_str, json_str, sec_str))
    #enddef

    def print_flags(self):
        return("{}{}{}".format("L" if self.local_bit else "l", "P" \
            if self.probe_bit else "p", "R" if self.reach_bit else "r"))
    #enddef
        
    def store_rloc_entry(self, rloc_entry):
        rloc = rloc_entry.rloc if (rloc_entry.translated_rloc.is_null()) \
            else rloc_entry.translated_rloc
        self.rloc.copy_address(rloc)

        if (rloc_entry.rloc_name):
            self.rloc_name = rloc_entry.rloc_name
        #endif

        if (rloc_entry.geo):
            self.geo = rloc_entry.geo
        else:
            name = rloc_entry.geo_name
            if (name and name in lisp_geo_list):
                self.geo = lisp_geo_list[name]
            #endif
        #endif
        if (rloc_entry.elp):
            self.elp = rloc_entry.elp
        else:
            name = rloc_entry.elp_name
            if (name and name in lisp_elp_list):
                self.elp = lisp_elp_list[name]
            #endif
        #endif
        if (rloc_entry.rle):
            self.rle = rloc_entry.rle
        else:
            name = rloc_entry.rle_name
            if (name and name in lisp_rle_list):
                self.rle = lisp_rle_list[name]
            #endif
        #endif
        if (rloc_entry.json):
            self.json = rloc_entry.json
        else:
            name = rloc_entry.json_name
            if (name and name in lisp_json_list):
                self.json = lisp_json_list[name]
            #endif
        #endif
        self.priority = rloc_entry.priority
        self.weight = rloc_entry.weight
        self.mpriority = rloc_entry.mpriority
        self.mweight = rloc_entry.mweight
    #enddef

    def encode_json(self, lisp_json):
        json_string = lisp_json.json_string
        kid = 0
        if (lisp_json.json_encrypted):
            kid = (lisp_json.json_key_id << 5) | 0x02
        #endif
        
        lcaf_type = LISP_LCAF_JSON_TYPE
        lcaf_afi = socket.htons(LISP_AFI_LCAF)
        addr_len = self.rloc.addr_length() + 2

        lcaf_len = socket.htons(len(json_string) + addr_len)

        json_len = socket.htons(len(json_string))
        packet = struct.pack("HBBBBHH", lcaf_afi, 0, 0, lcaf_type, kid,
            lcaf_len, json_len)
        packet += json_string.encode()

        #
        # If telemetry, store RLOC address in LCAF.
        #
        if (lisp_is_json_telemetry(json_string)):
            packet += struct.pack("H", socket.htons(self.rloc.afi))
            packet += self.rloc.pack_address()
        else:
            packet += struct.pack("H", 0)
        #endif
        return(packet)
    #enddef

    def encode_lcaf(self):
        lcaf_afi = socket.htons(LISP_AFI_LCAF)
        gpkt = b"" 
        if (self.geo):
            gpkt = self.geo.encode_geo()
        #endif

        epkt = b""
        if (self.elp):
            elp_recs = b""
            for elp_node in self.elp.elp_nodes:
                afi = socket.htons(elp_node.address.afi)
                flags = 0
                if (elp_node.eid): flags |= 0x4
                if (elp_node.probe): flags |= 0x2
                if (elp_node.strict): flags |= 0x1
                flags = socket.htons(flags)
                elp_recs += struct.pack("HH", flags, afi)
                elp_recs += elp_node.address.pack_address()
            #endfor

            elp_len = socket.htons(len(elp_recs))
            epkt = struct.pack("HBBBBH", lcaf_afi, 0, 0, LISP_LCAF_ELP_TYPE, 
                0, elp_len)
            epkt += elp_recs
        #endif
            
        rpkt = b""
        if (self.rle):
            rle_recs = b""
            for rle_node in self.rle.rle_nodes:
                afi = socket.htons(rle_node.address.afi)
                rle_recs += struct.pack("HBBH", 0, 0, rle_node.level, afi)
                rle_recs += rle_node.address.pack_address()
                if (rle_node.rloc_name):
                    rle_recs += struct.pack("H", socket.htons(LISP_AFI_NAME))
                    rle_recs += (rle_node.rloc_name + "\0").encode()
                #endif
            #endfor

            rle_len = socket.htons(len(rle_recs))
            rpkt = struct.pack("HBBBBH", lcaf_afi, 0, 0, LISP_LCAF_RLE_TYPE, 
                0, rle_len)
            rpkt += rle_recs
        #endif

        jpkt = b""
        if (self.json):
            jpkt = self.encode_json(self.json)
        #endif

        spkt = b""
        if (self.rloc.is_null() == False and self.keys and self.keys[1]): 
            spkt = self.keys[1].encode_lcaf(self.rloc)
        #endif

        npkt = b""
        if (self.rloc_name):
            npkt += struct.pack("H", socket.htons(LISP_AFI_NAME))
            npkt += (self.rloc_name + "\0").encode()
        #endif

        apkt_len = len(gpkt) + len(epkt) + len(rpkt) + len(spkt) + 2 + \
            len(jpkt) + self.rloc.addr_length() + len(npkt)
        apkt_len = socket.htons(apkt_len)
        apkt = struct.pack("HBBBBHH", lcaf_afi, 0, 0, LISP_LCAF_AFI_LIST_TYPE, 
                0, apkt_len, socket.htons(self.rloc.afi))
        apkt += self.rloc.pack_address()
        return(apkt + npkt + gpkt + epkt + rpkt + spkt + jpkt)
    #enddef

    def encode(self):
        flags = 0
        if (self.local_bit): flags |= 0x0004
        if (self.probe_bit): flags |= 0x0002
        if (self.reach_bit): flags |= 0x0001

        packet = struct.pack("BBBBHH", self.priority, self.weight,
            self.mpriority, self.mweight, socket.htons(flags), 
            socket.htons(self.rloc.afi))
        
        if (self.geo or self.elp or self.rle or self.keys or self.rloc_name \
            or self.json):
            try:
                packet = packet[0:-2] + self.encode_lcaf()
            except:
                lprint("Could not encode LCAF for RLOC-record")
            #endtry
        else:
            packet += self.rloc.pack_address()
        #endif
        return(packet)
    #enddef

    def decode_lcaf(self, packet, nonce, ms_json_encrypt):
        packet_format = "HBBBBH"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        afi, rsvd1, flags, lcaf_type, rsvd2, lcaf_len = \
            struct.unpack(packet_format, packet[:format_size])

        lcaf_len = socket.ntohs(lcaf_len)
        packet = packet[format_size::]
        if (lcaf_len > len(packet)): return(None)

        #
        # Process AFI-List LCAF.
        #
        if (lcaf_type == LISP_LCAF_AFI_LIST_TYPE):
            while (lcaf_len > 0):
                packet_format = "H"
                format_size = struct.calcsize(packet_format)
                if (lcaf_len < format_size): return(None)

                packet_len = len(packet)
                afi = struct.unpack(packet_format, packet[:format_size])[0]
                afi = socket.ntohs(afi)

                if (afi == LISP_AFI_LCAF): 
                    packet = self.decode_lcaf(packet, nonce, ms_json_encrypt)
                    if (packet == None): return(None)
                else:
                    packet = packet[format_size::]
                    self.rloc_name = None
                    if (afi == LISP_AFI_NAME):
                        packet, rloc_name = lisp_decode_dist_name(packet)
                        self.rloc_name = rloc_name
                    else:
                        self.rloc.afi = afi
                        packet = self.rloc.unpack_address(packet)
                        if (packet == None): return(None)
                        self.rloc.mask_len = self.rloc.host_mask_len()
                    #endif
                #endif

                lcaf_len -= packet_len - len(packet)
            #endwhile

        elif (lcaf_type == LISP_LCAF_GEO_COORD_TYPE):

            #
            # Process Geo-Coordinate LCAF.
            #
            geo = lisp_geo("")
            packet = geo.decode_geo(packet, lcaf_len, rsvd2)
            if (packet == None): return(None)
            self.geo = geo

        elif (lcaf_type == LISP_LCAF_JSON_TYPE):
            encrypted_json = rsvd2 & 0x02

            #
            # Process JSON LCAF.
            #
            packet_format = "H"
            format_size = struct.calcsize(packet_format)
            if (lcaf_len < format_size): return(None)

            json_len = struct.unpack(packet_format, packet[:format_size])[0]
            json_len = socket.ntohs(json_len)
            if (lcaf_len < format_size + json_len): return(None)

            packet = packet[format_size::]
            self.json = lisp_json("", packet[0:json_len], encrypted_json,
                ms_json_encrypt)
            packet = packet[json_len::]

            #
            # If telemetry, store RLOC address in LCAF.
            #
            afi = socket.ntohs(struct.unpack("H", packet[:2])[0])
            packet = packet[2::]

            if (afi != 0 and lisp_is_json_telemetry(self.json.json_string)):
                self.rloc.afi = afi
                packet = self.rloc.unpack_address(packet)
            #endif

        elif (lcaf_type == LISP_LCAF_ELP_TYPE):

            #
            # Process ELP LCAF.
            #
            elp = lisp_elp(None)
            elp.elp_nodes = []
            while (lcaf_len > 0):
                flags, afi = struct.unpack("HH", packet[:4])

                afi = socket.ntohs(afi)
                if (afi == LISP_AFI_LCAF): return(None)

                elp_node = lisp_elp_node()
                elp.elp_nodes.append(elp_node)

                flags = socket.ntohs(flags)
                elp_node.eid = (flags & 0x4)
                elp_node.probe = (flags & 0x2)
                elp_node.strict = (flags & 0x1)
                elp_node.address.afi = afi
                elp_node.address.mask_len = elp_node.address.host_mask_len()
                packet = elp_node.address.unpack_address(packet[4::])
                lcaf_len -= elp_node.address.addr_length() + 4
            #endwhile
            elp.select_elp_node()
            self.elp = elp

        elif (lcaf_type == LISP_LCAF_RLE_TYPE):

            #
            # Process RLE LCAF.
            #
            rle = lisp_rle(None)
            rle.rle_nodes = []
            while (lcaf_len > 0):
                x, y, level, afi = struct.unpack("HBBH", packet[:6])

                afi = socket.ntohs(afi)
                if (afi == LISP_AFI_LCAF): return(None)

                rle_node = lisp_rle_node()
                rle.rle_nodes.append(rle_node)

                rle_node.level = level
                rle_node.address.afi = afi
                rle_node.address.mask_len = rle_node.address.host_mask_len()
                packet = rle_node.address.unpack_address(packet[6::])

                lcaf_len -= rle_node.address.addr_length() + 6
                if (lcaf_len >= 2):
                    afi = struct.unpack("H", packet[:2])[0]
                    if (socket.ntohs(afi) == LISP_AFI_NAME):
                        packet = packet[2::]
                        packet, rle_node.rloc_name = \
                            lisp_decode_dist_name(packet)
                        if (packet == None): return(None)
                        lcaf_len -= len(rle_node.rloc_name) + 1 + 2
                    #endif
                #endif
            #endwhile
            self.rle = rle
            self.rle.build_forwarding_list()

        elif (lcaf_type == LISP_LCAF_SECURITY_TYPE):

            #
            # Get lisp_key() data structure so we can parse keys in the Map-
            # Reply RLOC-record. Then get the RLOC address.
            #
            orig_packet = packet
            decode_key = lisp_keys(1)
            packet = decode_key.decode_lcaf(orig_packet, lcaf_len)
            if (packet == None): return(None)

            #
            # Other side may not do ECDH.
            #
            cs_list = [LISP_CS_25519_CBC, LISP_CS_25519_CHACHA]
            if (decode_key.cipher_suite in cs_list):
                if (decode_key.cipher_suite == LISP_CS_25519_CBC):
                    key = lisp_keys(1, do_poly=False, do_chacha=False)
                #endif
                if (decode_key.cipher_suite == LISP_CS_25519_CHACHA):
                    key = lisp_keys(1, do_poly=True, do_chacha=True)
                #endif
            else:
                key = lisp_keys(1, do_poly=False, do_chacha=False)
            #endif
            packet = key.decode_lcaf(orig_packet, lcaf_len)
            if (packet == None): return(None)

            if (len(packet) < 2): return(None)
            afi = struct.unpack("H", packet[:2])[0]
            self.rloc.afi = socket.ntohs(afi)
            if (len(packet) < self.rloc.addr_length()): return(None)
            packet = self.rloc.unpack_address(packet[2::])
            if (packet == None): return(None)
            self.rloc.mask_len = self.rloc.host_mask_len()

            #
            # Some RLOC records may not have RLOC addresses but other LCAF
            # types. Don't process security keys because we need RLOC addresses
            # to index into security data structures.
            #
            if (self.rloc.is_null()): return(packet)

            rloc_name_str = self.rloc_name
            if (rloc_name_str): rloc_name_str = blue(self.rloc_name, False)

            #
            # If we found no stored key, store the newly created lisp_keys()
            # to the RLOC list if and only if a remote public-key was supplied
            # in the Map-Reply.
            #
            stored_key = self.keys[1] if self.keys else None
            if (stored_key == None):
                if (key.remote_public_key == None):
                    string = bold("No remote encap-public-key supplied", False)
                    lprint("    {} for {}".format(string, rloc_name_str))
                    key = None
                else:
                    string = bold("New encap-keying with new state", False)
                    lprint("    {} for {}".format(string, rloc_name_str))
                    key.compute_shared_key("encap")
                #endif
            #endif

            #
            # If we have stored-key, the other side received the local public
            # key that is stored in variable 'stored_key'. If the remote side
            # did not supply a public-key, it doesn't want to do lisp-crypto.
            # If it did supply a public key, check to see if the same as
            # last time, and if so, do nothing, else we do a rekeying.
            #
            if (stored_key):
                if (key.remote_public_key == None):
                    key = None
                    remote = bold("Remote encap-unkeying occurred", False)
                    lprint("    {} for {}".format(remote, rloc_name_str))
                elif (stored_key.compare_keys(key)):
                    key = stored_key
                    lprint("    Maintain stored encap-keys for {}".format( \
                        rloc_name_str))
                else:
                    if (stored_key.remote_public_key == None):
                        string = "New encap-keying for existing state"
                    else:
                        string = "Remote encap-rekeying"
                    #endif
                    lprint("    {} for {}".format(bold(string, False), 
                        rloc_name_str))
                    stored_key.remote_public_key = key.remote_public_key
                    stored_key.compute_shared_key("encap")
                    key = stored_key
                #endif
            #endif
            self.keys = [None, key, None, None]
  
        else:

            #
            # All other LCAFs we skip over and ignore.
            #
            packet = packet[lcaf_len::]
        #endif
        return(packet)
    #enddef

    def decode(self, packet, nonce, ms_json_encrypt=False):
        packet_format = "BBBBHH"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        self.priority, self.weight, self.mpriority, self.mweight, flags, \
            afi = struct.unpack(packet_format, packet[:format_size])

        flags = socket.ntohs(flags)
        afi = socket.ntohs(afi)
        self.local_bit = True if (flags & 0x0004) else False
        self.probe_bit = True if (flags & 0x0002) else False
        self.reach_bit = True if (flags & 0x0001) else False

        if (afi == LISP_AFI_LCAF):
            packet = packet[format_size-2::]
            packet = self.decode_lcaf(packet, nonce, ms_json_encrypt)
        else:
            self.rloc.afi = afi
            packet = packet[format_size::]
            packet = self.rloc.unpack_address(packet)
        #endif
        self.rloc.mask_len = self.rloc.host_mask_len()
        return(packet)
    #enddef

    def end_of_rlocs(self, packet, rloc_count):
        for i in range(rloc_count): 
            packet = self.decode(packet, None, False)
            if (packet == None): return(None)
        #endfor
        return(packet)
    #enddef
#endclass

#
# Map-Referral Message Format
#
#        0                   1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |Type=6 |                Reserved               | Record Count  |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                         Nonce . . .                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#       |                         . . . Nonce                           |
#   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |   |                          Record  TTL                          |
#   |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   R   | Referral Count| EID mask-len  | ACT |A|I|     Reserved        |
#   e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   c   |SigCnt |   Map Version Number  |            EID-AFI            |
#   o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   r   |                          EID-prefix ...                       |
#   d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
#   | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   | o |        Unused Flags         |R|         Loc/LCAF-AFI          |
#   | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  \|                             Locator ...                       |
#   +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
class lisp_map_referral(object):
    def __init__(self):
        self.record_count = 0
        self.nonce = 0
    #enddef

    def print_map_referral(self):
        lprint("{} -> record-count: {}, nonce: 0x{}".format( \
            bold("Map-Referral", False), self.record_count, 
            lisp_hex_string(self.nonce)))
    #enddef

    def encode(self):
        first_long = (LISP_MAP_REFERRAL << 28) | self.record_count
        packet = struct.pack("I", socket.htonl(first_long))
        packet += struct.pack("Q", self.nonce)
        return(packet)
    #enddef

    def decode(self, packet):
        packet_format = "I"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        first_long = struct.unpack(packet_format, packet[:format_size])
        first_long = socket.ntohl(first_long[0])
        self.record_count = first_long & 0xff
        packet = packet[format_size::]

        packet_format = "Q"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        self.nonce = struct.unpack(packet_format, packet[:format_size])[0]
        packet = packet[format_size::]
        return(packet)
    #enddef
#endclass

#
# This is a DDT cache type data structure that holds information configured
# in the "lisp ddt-authoritative-prefix" and "lisp delegate" commands. The
# self.delegatione_set[] is a list of lisp_ddt_node()s.
#
class lisp_ddt_entry(object):
    def __init__(self):
        self.eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.group = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.uptime = lisp_get_timestamp()
        self.delegation_set = []
        self.source_cache = None
        self.map_referrals_sent = 0
    #enddef

    def is_auth_prefix(self):
        if (len(self.delegation_set) != 0): return(False)
        if (self.is_star_g()): return(False)
        return(True)
    #enddef

    def is_ms_peer_entry(self):
        if (len(self.delegation_set) == 0): return(False)
        return(self.delegation_set[0].is_ms_peer())
    #enddef

    def print_referral_type(self):
        if (len(self.delegation_set) == 0): return("unknown")
        ddt_node = self.delegation_set[0]
        return(ddt_node.print_node_type())
    #enddef

    def print_eid_tuple(self):
        return(lisp_print_eid_tuple(self.eid, self.group))
    #enddef

    def add_cache(self):
        if (self.group.is_null()):
            lisp_ddt_cache.add_cache(self.eid, self)
        else:
            ddt = lisp_ddt_cache.lookup_cache(self.group, True)
            if (ddt == None): 
                ddt = lisp_ddt_entry()
                ddt.eid.copy_address(self.group)
                ddt.group.copy_address(self.group)
                lisp_ddt_cache.add_cache(self.group, ddt)
            #endif
            if (self.eid.is_null()): self.eid.make_default_route(ddt.group)
            ddt.add_source_entry(self)
        #endif
    #enddef

    def add_source_entry(self, source_ddt):
        if (self.source_cache == None): self.source_cache = lisp_cache()
        self.source_cache.add_cache(source_ddt.eid, source_ddt)
    #enddef
        
    def lookup_source_cache(self, source, exact):
        if (self.source_cache == None): return(None)
        return(self.source_cache.lookup_cache(source, exact))
    #enddef

    def is_star_g(self):
        if (self.group.is_null()): return(False)
        return(self.eid.is_exact_match(self.group))
    #enddef
#endclass

class lisp_ddt_node(object):
    def __init__(self):
        self.delegate_address = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.public_key = ""
        self.map_server_peer = False
        self.map_server_child = False
        self.priority = 0
        self.weight = 0
    #enddef

    def print_node_type(self):
        if (self.is_ddt_child()): return("ddt-child")
        if (self.is_ms_child()): return("map-server-child")
        if (self.is_ms_peer()): return("map-server-peer")
    #enddef

    def is_ddt_child(self):
        if (self.map_server_child): return(False)
        if (self.map_server_peer): return(False)
        return(True)
    #enddef
        
    def is_ms_child(self):
        return(self.map_server_child)
    #enddef

    def is_ms_peer(self):
        return(self.map_server_peer)
    #enddef
#endclass

#
# This is a Map-Request queue used on a Map-Resolver when waiting for a
# Map-Referral to be retunred by a DDT-node or a Map-Server.
#
class lisp_ddt_map_request(object):
    def __init__(self, lisp_sockets, packet, eid, group, nonce):
        self.uptime = lisp_get_timestamp()
        self.lisp_sockets = lisp_sockets
        self.packet = packet
        self.eid = eid
        self.group = group
        self.nonce = nonce
        self.mr_source = None
        self.sport = 0
        self.itr = None
        self.retry_count = 0
        self.send_count = 0
        self.retransmit_timer = None
        self.last_request_sent_to = None
        self.from_pitr = False
        self.tried_root = False
        self.last_cached_prefix = [None, None]
    #enddef

    def print_ddt_map_request(self):
        lprint("Queued Map-Request from {}ITR {}->{}, nonce 0x{}".format( \
            "P" if self.from_pitr else "", 
            red(self.itr.print_address(), False),
            green(self.eid.print_address(), False), self.nonce))
    #enddef

    def queue_map_request(self):
        self.retransmit_timer = threading.Timer(LISP_DDT_MAP_REQUEST_INTERVAL, 
            lisp_retransmit_ddt_map_request, [self])
        self.retransmit_timer.start()
        lisp_ddt_map_requestQ[str(self.nonce)] = self
    #enddef

    def dequeue_map_request(self):
        self.retransmit_timer.cancel()
        if (self.nonce in lisp_ddt_map_requestQ):
            lisp_ddt_map_requestQ.pop(str(self.nonce))
        #endif
    #enddef

    def print_eid_tuple(self):
        return(lisp_print_eid_tuple(self.eid, self.group))
    #enddef
#endclass

#
#   -------------------------------------------------------------------
#    Type (Action field)          Incomplete Referral-set   TTL values
#   -------------------------------------------------------------------
#     0    NODE-REFERRAL              NO         YES           1440
#
#     1    MS-REFERRAL                NO         YES           1440
#
#     2    MS-ACK                     *          *             1440
#
#     3    MS-NOT-REGISTERED          *          *             1
#
#     4    DELEGATION-HOLE            NO         NO            15
#
#     5    NOT-AUTHORITATIVE          YES        NO            0
#   -------------------------------------------------------------------
#
LISP_DDT_ACTION_SITE_NOT_FOUND   = -2
LISP_DDT_ACTION_NULL             = -1
LISP_DDT_ACTION_NODE_REFERRAL    = 0
LISP_DDT_ACTION_MS_REFERRAL      = 1
LISP_DDT_ACTION_MS_ACK           = 2
LISP_DDT_ACTION_MS_NOT_REG       = 3
LISP_DDT_ACTION_DELEGATION_HOLE  = 4
LISP_DDT_ACTION_NOT_AUTH         = 5
LISP_DDT_ACTION_MAX              = LISP_DDT_ACTION_NOT_AUTH

lisp_map_referral_action_string = [  
    "node-referral", "ms-referral", "ms-ack", "ms-not-registered", 
    "delegation-hole", "not-authoritative"]

#
# Info-Request/Reply
#
#       0                   1                   2                     3
#       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |Type=7 |R|            Reserved                                 |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                         Nonce . . .                           |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                      . . . Nonce                              |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |              Key ID           |  Authentication Data Length   |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      ~                     Authentication Data                       ~
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                              TTL                              |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |   Reserved    | EID mask-len  |        EID-prefix-AFI         |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |                          EID-prefix                           |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#    Info-Request specific information following the EID-prefix with
#    EID-prefix-AFI set to 0. EID appened below follows with hostname
#    or AFI=0:
#
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |             AFI = 17          |  <hostname--null-terminated>  |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#      |             AFI = 0           |   <Nothing Follows AFI=0>     |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#    Info-Reply specific information following the EID-prefix:
#
#   +->+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  |           AFI = 16387         |    Rsvd1      |     Flags     |
#   |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  |    Type = 7     |     Rsvd2   |             4 + n             |
#   |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   N  |        MS UDP Port Number     |      ETR UDP Port Number      |
#   A  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   T  |              AFI = x          | Global ETR RLOC Address  ...  |
#      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   L  |              AFI = x          |       MS RLOC Address  ...    |
#   C  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   A  |              AFI = x          | Private ETR RLOC Address ...  |
#   F  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  |              AFI = x          |      RTR RLOC Address 1 ...   |
#   |  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  |              AFI = x          |       RTR RLOC Address n ...  |
#   +->+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# This encoding will not use authentication so we respond to anyone who
# sends an Info-Request. And the EID-prefix will have AFI=0.
#
class lisp_info(object):
    def __init__(self):
        self.info_reply = False
        self.nonce = 0
        self.private_etr_rloc = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.global_etr_rloc = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.global_ms_rloc = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.ms_port = 0
        self.etr_port = 0
        self.rtr_list = []
        self.hostname = lisp_hostname
    #enddef

    def print_info(self):
        if (self.info_reply):
            req_or_reply = "Info-Reply"
            rloc = (", ms-port: {}, etr-port: {}, global-rloc: {}, " + \
                "ms-rloc: {}, private-rloc: {}, RTR-list: ").format( \
                self.ms_port, self.etr_port, 
                red(self.global_etr_rloc.print_address_no_iid(), False),
                red(self.global_ms_rloc.print_address_no_iid(), False),
                red(self.private_etr_rloc.print_address_no_iid(), False))
            if (len(self.rtr_list) == 0): rloc += "empty, "
            for rtr in self.rtr_list:
                rloc += red(rtr.print_address_no_iid(), False) + ", "
            #endfor
            rloc = rloc[0:-2]
        else:
            req_or_reply = "Info-Request"
            hostname = "<none>" if self.hostname == None else self.hostname
            rloc = ", hostname: {}".format(blue(hostname, False))
        #endif
        lprint("{} -> nonce: 0x{}{}".format(bold(req_or_reply, False), 
            lisp_hex_string(self.nonce), rloc))
    #enddef

    def encode(self):
        first_long = (LISP_NAT_INFO << 28)
        if (self.info_reply): first_long |= (1 << 27)

        #
        # Encode first-long, nonce, key-id longword, TTL and EID mask-len/
        # EID-prefix AFI. There is no auth data field since auth len is 0.
        # Zero out key-id, auth-data-len, ttl, reserved, eid-mask-len, and
        # eid-prefix-afi.
        #
        packet = struct.pack("I", socket.htonl(first_long))
        packet += struct.pack("Q", self.nonce)
        packet += struct.pack("III", 0, 0, 0)
        
        #
        # Add hostname null terminated string with AFI 17.
        #
        if (self.info_reply == False):
            if (self.hostname == None):
                packet += struct.pack("H", 0)
            else:
                packet += struct.pack("H", socket.htons(LISP_AFI_NAME))
                packet += (self.hostname + "\0").encode()
            #endif
            return(packet)
        #endif

        #
        # If Info-Reply, encode Type 7 LCAF.
        #
        afi = socket.htons(LISP_AFI_LCAF)
        lcaf_type = LISP_LCAF_NAT_TYPE
        lcaf_len = socket.htons(16)
        ms_port = socket.htons(self.ms_port)
        etr_port = socket.htons(self.etr_port)
        packet += struct.pack("HHBBHHHH", afi, 0, lcaf_type, 0, lcaf_len, 
            ms_port, etr_port, socket.htons(self.global_etr_rloc.afi))
        packet += self.global_etr_rloc.pack_address()
        packet += struct.pack("HH", 0, socket.htons(self.private_etr_rloc.afi))
        packet += self.private_etr_rloc.pack_address()
        if (len(self.rtr_list) == 0): packet += struct.pack("H", 0)

        #
        # Encode RTR list.
        #
        for rtr in self.rtr_list:
            packet += struct.pack("H", socket.htons(rtr.afi))
            packet += rtr.pack_address()
        #endfor
        return(packet)
    #enddef

    def decode(self, packet):
        orig_packet = packet
        packet_format = "I"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        first_long = struct.unpack(packet_format, packet[:format_size])
        first_long = first_long[0]
        packet = packet[format_size::]

        packet_format = "Q"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        nonce = struct.unpack(packet_format, packet[:format_size])

        first_long = socket.ntohl(first_long)
        self.nonce = nonce[0]
        self.info_reply = first_long & 0x08000000
        self.hostname = None
        packet = packet[format_size::]

        #
        # Parse key-id, auth-len, auth-data, and EID-record. We don't support
        # any of these. On encode, we set 3 longs worth of 0.
        #
        packet_format = "HH"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        #
        # If an LCAF value appears in the key-id field, then this is an
        # old style Echo-Reply (that NX-OS implemented).
        #
        key_id, auth_len = struct.unpack(packet_format, packet[:format_size])
        if (auth_len != 0): return(None)

        packet = packet[format_size::]
        packet_format = "IBBH"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)
        
        ttl, rsvd, ml, eid_afi = struct.unpack(packet_format, 
            packet[:format_size])

        if (eid_afi != 0): return(None)
        packet = packet[format_size::]

        #
        # Check if name supplied.
        #
        if (self.info_reply == False):
            packet_format = "H"
            format_size = struct.calcsize(packet_format)
            if (len(packet) >= format_size):
                afi = struct.unpack(packet_format, packet[:format_size])[0]
                if (socket.ntohs(afi) == LISP_AFI_NAME): 
                    packet = packet[format_size::]
                    packet, self.hostname = lisp_decode_dist_name(packet)
                #endif
            #endif
            return(orig_packet)
        #endif

        #
        # Process Info-Reply.
        #
        packet_format = "HHBBHHH"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        afi, x, lcaf_type, rsvd, lcaf_len, ms_port, etr_port = \
            struct.unpack(packet_format, packet[:format_size])

        if (socket.ntohs(afi) != LISP_AFI_LCAF): return(None)

        self.ms_port = socket.ntohs(ms_port)
        self.etr_port = socket.ntohs(etr_port)
        packet = packet[format_size::]

        #
        # Get addresses one AFI at a time.
        #
        packet_format = "H"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        #
        # Get global ETR RLOC address.
        #
        afi = struct.unpack(packet_format, packet[:format_size])[0]
        packet = packet[format_size::]
        if (afi != 0): 
            self.global_etr_rloc.afi = socket.ntohs(afi)
            packet = self.global_etr_rloc.unpack_address(packet)
            if (packet == None): return(None)
            self.global_etr_rloc.mask_len = \
                self.global_etr_rloc.host_mask_len()
        #endif

        #
        # Get global MS RLOC address.
        #
        if (len(packet) < format_size): return(orig_packet)

        afi = struct.unpack(packet_format, packet[:format_size])[0]
        packet = packet[format_size::]
        if (afi != 0): 
            self.global_ms_rloc.afi = socket.ntohs(afi)
            packet = self.global_ms_rloc.unpack_address(packet)
            if (packet == None): return(orig_packet)
            self.global_ms_rloc.mask_len = self.global_ms_rloc.host_mask_len()
        #endif

        #
        # Get private ETR RLOC address.
        #
        if (len(packet) < format_size): return(orig_packet)

        afi = struct.unpack(packet_format, packet[:format_size])[0]
        packet = packet[format_size::]
        if (afi != 0): 
            self.private_etr_rloc.afi = socket.ntohs(afi)
            packet = self.private_etr_rloc.unpack_address(packet)
            if (packet == None): return(orig_packet)
            self.private_etr_rloc.mask_len = \
                self.private_etr_rloc.host_mask_len()
        #endif

        #
        # Get RTR list if any.
        #
        while (len(packet) >= format_size):
            afi = struct.unpack(packet_format, packet[:format_size])[0]
            packet = packet[format_size::]
            if (afi == 0): continue
            rtr = lisp_address(socket.ntohs(afi), "", 0, 0)
            packet = rtr.unpack_address(packet)
            if (packet == None): return(orig_packet)
            rtr.mask_len = rtr.host_mask_len()
            self.rtr_list.append(rtr)
        #endwhile
        return(orig_packet)
    #enddef
#endclass

class lisp_nat_info(object):
    def __init__(self, addr_str, hostname, port):
        self.address = addr_str
        self.hostname = hostname
        self.port = port
        self.uptime = lisp_get_timestamp()
    #enddef

    def timed_out(self):
        elapsed = time.time() - self.uptime
        return(elapsed >= (LISP_INFO_INTERVAL * 2))
    #enddef
#endclass

class lisp_info_source(object):
    def __init__(self, hostname, addr_str, port):
        self.address = lisp_address(LISP_AFI_IPV4, addr_str, 32, 0)
        self.port = port
        self.uptime = lisp_get_timestamp()
        self.nonce = None
        self.hostname = hostname
        self.no_timeout = False
    #enddef

    def cache_address_for_info_source(self):
        key = self.address.print_address_no_iid() + self.hostname
        lisp_info_sources_by_address[key] = self
    #enddef

    def cache_nonce_for_info_source(self, nonce):
        self.nonce = nonce
        lisp_info_sources_by_nonce[nonce] = self
    #enddef
#endclass

#------------------------------------------------------------------------------

#
# lisp_concat_auth_data
#
# Take each longword and convert to binascii by byte-swapping and zero filling
# longword that leads with 0.
#
def lisp_concat_auth_data(alg_id, auth1, auth2, auth3, auth4):

    if (lisp_is_x86()):
        if (auth1 != ""): auth1 = byte_swap_64(auth1)
        if (auth2 != ""): auth2 = byte_swap_64(auth2)
        if (auth3 != ""): 
            if (alg_id == LISP_SHA_1_96_ALG_ID): auth3 = socket.ntohl(auth3)
            else: auth3 = byte_swap_64(auth3)
        #endif
        if (auth4 != ""): auth4 = byte_swap_64(auth4)
    #endif

    if (alg_id == LISP_SHA_1_96_ALG_ID):
        auth1 = lisp_hex_string(auth1)
        auth1 = auth1.zfill(16)
        auth2 = lisp_hex_string(auth2)
        auth2 = auth2.zfill(16)
        auth3 = lisp_hex_string(auth3)
        auth3 = auth3.zfill(8)
        auth_data = auth1 + auth2 + auth3
    #endif
    if (alg_id == LISP_SHA_256_128_ALG_ID):
        auth1 = lisp_hex_string(auth1)
        auth1 = auth1.zfill(16)
        auth2 = lisp_hex_string(auth2)
        auth2 = auth2.zfill(16)
        auth3 = lisp_hex_string(auth3)
        auth3 = auth3.zfill(16)
        auth4 = lisp_hex_string(auth4)
        auth4 = auth4.zfill(16)
        auth_data = auth1 + auth2 + auth3 + auth4
    #endif
    return(auth_data)
#enddef

#
# lisp_open_listen_socket
#
# Open either internal socket or network socket. If network socket, it will
# open it with a local address of 0::0 which means the one socket can be
# used for IPv4 or IPv6. This is goodness and reduces the number of threads
# required.
#
def lisp_open_listen_socket(local_addr, port):
    if (port.isdigit()):
        if (local_addr.find(".") != -1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #endif
        if (local_addr.find(":") != -1):
            if (lisp_is_raspbian()): return(None)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        #endif
        sock.bind((local_addr, int(port)))
    else:
        name = port
        if (os.path.exists(name)): 
            os.system("rm " + name)
            time.sleep(1)
        #endif
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(name)
    #endif
    return(sock)
#enddef

#
# lisp_open_send_socket
#
# Open socket for sending to port 4342.
#
def lisp_open_send_socket(internal_name, afi):
    if (internal_name == ""):
        if (afi == LISP_AFI_IPV4):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #endif
        if (afi == LISP_AFI_IPV6):
            if (lisp_is_raspbian()): return(None)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        #endif
    else:
        if (os.path.exists(internal_name)): os.system("rm " + internal_name)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(internal_name)
    #endif
    return(sock)
#enddef

#
# lisp_close_socket
#
# Close network and internal sockets.
#
def lisp_close_socket(sock, internal_name):
    sock.close()
    if (os.path.exists(internal_name)): os.system("rm " + internal_name)
    return
#endif

#
# lisp_is_running
#
# Test if one of "lisp-itr", "lisp-etr", "lisp-mr", "lisp-ms", "lisp-ddt", or
# "lisp-core" is running.
#
def lisp_is_running(node):
    return(True if (os.path.exists(node)) else False)
#enddef

#
# lisp_packet_ipc
#
# Build IPC message for a LISP control packet destined for UDP port 4342. This
# packet goes to the lisp-core process and then it IPCs it to the appropriate
# LISP component process.
#
# Returns a byte string.
#
def lisp_packet_ipc(packet, source, sport):
    header = "packet@{}@{}@{}@".format(str(len(packet)), source, str(sport))
    return(header.encode() + packet)
#enddef

#
# lisp_control_packet_ipc
#
# Build IPC message for a packet that needs to be source from UDP port 4342.
# Always sent by a LISP component process to the lisp-core process.
#
# Returns a byte string.
#
def lisp_control_packet_ipc(packet, source, dest, dport):
    header = "control-packet@{}@{}@".format(dest, str(dport))
    return(header.encode() + packet)
#enddef

#
# lisp_data_packet_ipc
#
# Build IPC message for a MAC, IPv4, or IPv6 data packet.
#
# Returns a byte string.
#
def lisp_data_packet_ipc(packet, source):
    header = "data-packet@{}@{}@@".format(str(len(packet)), source)
    return(header.encode() + packet)
#enddef

#
# lisp_command_ipc
#
# Build IPC message for a command message. Note this command IPC message must
# have same number of parameters as the "packet@" IPC. So an intentional
# double @ is put in after the source to indicate a null port.
#
# Returns a byte string. Variable "ipc" is a string.
#
def lisp_command_ipc(ipc, source):
    packet = "command@{}@{}@@".format(len(ipc), source) + ipc
    return(packet.encode())
#enddef

#
# lisp_api_ipc
#
# Build IPC message for a command message. Note this command IPC message must
# have same number of parameters as the "packet@" IPC. So an intentional
# double @ is put in after the source to indicate a null port.
#
# Returns a byte string. Variable "data" is a string.
#
def lisp_api_ipc(source, data):
    packet = "api@" + str(len(data)) + "@" + source + "@@" + data
    return(packet.encode())
#enddef

#
# lisp_ipc
#
# Send IPC message to internal AF_UNIX socket if LISP component is running. We
# need to send in 15000 byte segments since the socket interface will not allow
# to support more. And socket.setsockopt() won't alow to increase SO_SNDBUF.
#
# Variable "packet" is of type byte string. Caller must adhere. Since packet
# is going out a socket interface (even if internal).
#
def lisp_ipc(packet, send_socket, node):

    #
    # Can't send an IPC message to a process that is not running.
    #
    if (lisp_is_running(node) == False):
        lprint("Suppress sending IPC to {}".format(node))
        return
    #endif

    ipc_len = 1500 if (packet.find(b"control-packet") == -1) else 9000

    offset = 0
    length = len(packet)
    retry_count = 0
    sleep_time = .001
    while (length > 0):
        segment_len = min(length, ipc_len)
        segment = packet[offset:segment_len+offset]

        try:
            if (type(segment) == str): segment = segment.encode()
            send_socket.sendto(segment, node)
            lprint("Send IPC {}-out-of-{} byte to {} succeeded".format( \
                len(segment), len(packet), node))
            retry_count = 0
            sleep_time = .001

        except socket.error as e:
            if (retry_count == 12):
                lprint("Giving up on {}, consider it down".format(node))
                break
            #endif

            lprint("Send IPC {}-out-of-{} byte to {} failed: {}".format( \
                len(segment), len(packet), node, e))

            retry_count += 1
            time.sleep(sleep_time)

            lprint("Retrying after {} ms ...".format(sleep_time * 1000))
            sleep_time *= 2
            continue
        #endtry

        offset += segment_len
        length -= segment_len
    #endwhile
    return
#enddef

#
# lisp_format_packet
#
# Put a whitespace between every 4 bytes of a packet dump. Returns string
# and not byte string like supplied "packet" type.
#
def lisp_format_packet(packet):
    packet = binascii.hexlify(packet)
    offset = 0
    new = b""
    length = len(packet) * 2
    while (offset < length):
        new += packet[offset:offset+8] + b" "
        offset += 8
        length -= 4
    #endfor
    return(new.decode())
#enddef

#
# lisp_send
#
# Send packet out.
#
def lisp_send(lisp_sockets, dest, port, packet):

    lisp_socket = lisp_sockets[0] if dest.is_ipv4() else lisp_sockets[1]

    #
    # Remove square brackets. Use an IPv4 socket when address is IPv4, even
    # when embedded in ::ffff:<ipv4-address>. This is a special case when
    # an RTR sits behind a NAT and is sending a Map-Request. The ECM and
    # Map-Request need to use the same ephemeral port and the Map-Reply
    # needs to come to the ephemeral listening socket lisp_sockets[0];
    #
    # Also, on getchip and raspberry-pi OSes, there is no support for IPv6
    # sockets, so we need to use the IPv4 embedded address and the IPv4
    # socket.
    #
    address = dest.print_address_no_iid()
    if (address.find("::ffff:") != -1 and address.count(".") == 3):
        if (lisp_i_am_rtr): lisp_socket = lisp_sockets[0]
        if (lisp_socket == None):
            lisp_socket = lisp_sockets[0]
            address = address.split("::ffff:")[-1]
        #endif
    #endif

    lprint("{} {} bytes {} {}, packet: {}".format(bold("Send", False), 
        len(packet), bold("to " + address, False), port, 
        lisp_format_packet(packet)))

    #
    # Send on socket.
    #
    try:
        lisp_socket.sendto(packet, (address, port))
    except socket.error as e:
        lprint("socket.sendto() failed: {}".format(e))
    #endtry
    return
#enddef

#
# lisp_receive_segments
#
# Process 1500 byte segments if received IPC packet greater than what sockets
# can support.
#
def lisp_receive_segments(lisp_socket, packet, source, total_length):

    #
    # If the total length is equal to the segment length. We only have one
    # segment which is the packet. Return it.
    #
    segment_len = total_length - len(packet)
    if (segment_len == 0): return([True, packet])

    lprint("Received {}-out-of-{} byte segment from {}".format(len(packet),
        total_length, source))

    #
    # Otherwise, receive each segment and assemble it to return entire packet
    # to caller.
    #
    length = segment_len
    while (length > 0):
        try: segment = lisp_socket.recvfrom(9000)
        except: return([False, None])
        
        segment = segment[0]

        #
        # The sender gave up and sent a new message that made it to us, last
        # partial packet must be dropped.
        #
        seg = segment.decode()
        if (seg.find("packet@") == 0):
            seg = seg.split("@")
            lprint("Received new message ({}-out-of-{}) while receiving " + \
                "fragments, old message discarded", len(segment), 
                seg[1] if len(seg) > 2 else "?")
            return([False, segment])
        #endif

        length -= len(segment)
        packet += segment

        lprint("Received {}-out-of-{} byte segment from {}".format( \
            len(segment), total_length, source))
    #endwhile
    return([True, packet])
#enddef

#
# lisp_bit_stuff
#
# For every element in the array, insert a 0x40 ("@"). This is a bit-stuffing
# procedure. Only look at array elements with index 2 and above. Caller
# passes a byte string.
#
def lisp_bit_stuff(payload):
    lprint("Bit-stuffing, found {} segments".format(len(payload)))
    packet = b""
    for segment in payload: packet += segment + b"\x40"
    return(packet[:-1])
#enddef

#
# lisp_receive
#
# Wait for packet to come in. This function call will block. For command
# IPCs, we need to loop to assemble all segments.
#
# For an internal socket, the format of a recvfrom() 'packet-data' is:
#
#    "command" @ <total-length> @ <source> @ <packet-buffer>
#    "packet"  @ <total-length> @ <source> @ <command-buffer>
#
# So when an array of length 4 does not exist, we are receiving a fragment.
#
# For an external network socket, the format of a recvfrom() is:
#
#    packet_data[0] = <packet-buffer>
#    packet_data[1] = [<source>, <port>]
#
def lisp_receive(lisp_socket, internal):
    while (True):

        #
        # Read from socket. Return if we received an error.
        #
        try: packet_data = lisp_socket.recvfrom(9000)
        except: return(["", "", "", ""])

        #
        # This is a packet received on the network. If it was fragmented at the
        # sender, then IP did it so it is assebled into a complete datagram
        # in this sytem.
        #
        if (internal == False):
            packet = packet_data[0]
            source = lisp_convert_6to4(packet_data[1][0])
            port = packet_data[1][1]

            if (port == LISP_DATA_PORT):
                do_log = lisp_data_plane_logging
                packet_str = lisp_format_packet(packet[0:60]) + " ..."
            else:
                do_log = True
                packet_str = lisp_format_packet(packet)
            #endif

            if (do_log):
                lprint("{} {} bytes {} {}, packet: {}".format(bold("Receive", 
                    False), len(packet), bold("from " + source, False), port, 
                    packet_str))
            #endif
            return(["packet", source, port, packet])
        #endif

        #
        # This is an IPC message that can be fragmented by lisp-core or the
        # sending socket interface.
        #
        assembled = False
        data = packet_data[0]
        if (type(data) == str): data = data.encode()
        loop = False

        while (assembled == False):
            data = data.split(b"@")

            if (len(data) < 4):
                lprint("Possible fragment (length {}), from old message, " + \
                    "discarding", len(data[0]))
                loop = True
                break
            #endif

            opcode = data[0].decode()
            try:
                total_length = int(data[1])
            except:
                error_str = bold("Internal packet reassembly error", False)
                lprint("{}: {}".format(error_str, packet_data))
                loop = True
                break
            #endtry
            source = data[2].decode()
            port = data[3].decode()

            #
            # If any of the data payload has a 0x40 byte (which is "@" in
            # ascii), we will confuse the IPC separator from real data.
            # So go to the payload and put in 0x40 where split() seperated
            # the data. This particularly happens with Map-Notify messages
            # since the first byte of the message is 0x40.
            #
            if (len(data) > 5): 
                packet = lisp_bit_stuff(data[4::])
            else:
                packet = data[4]
            #endif

            #
            # Check for reassembly. Once reassembled, then we can process one 
            # large packet.
            #
            assembled, packet = lisp_receive_segments(lisp_socket, packet,
                source, total_length)
            if (packet == None): return(["", "", "", ""])

            #
            # We did not finish assembling a message but the sender sent a new
            # one.
            #
            if (assembled == False): 
                data = packet
                continue
            #endif

            if (port == ""): port = "no-port"
            if (opcode == "command" and lisp_i_am_core == False):
                index = packet.find(b" {")
                command = packet if index == -1 else packet[:index]
                command = ": '" + command.decode() + "'"
            else:
                command = ""
            #endif
                
            lprint("{} {} bytes {} {}, {}{}".format(bold("Receive", False),
                len(packet), bold("from " + source, False), port, opcode, 
                command if (opcode in ["command", "api"]) else ": ... " if \
                (opcode == "data-packet") else \
                ": " + lisp_format_packet(packet)))
            #endif
        #endwhile

        if (loop): continue
        return([opcode, source, port, packet])
    #endwhile
#enddef

#
# lisp_parse_packet
#
# Parse LISP control message.
#
def lisp_parse_packet(lisp_sockets, packet, source, udp_sport, ttl=-1):
    trigger_flag = False
    timestamp = time.time()

    header = lisp_control_header()
    if (header.decode(packet) == None):
        lprint("Could not decode control header")
        return(trigger_flag)
    #endif

    #
    # Store source in internal lisp_address() format.
    #
    from_ipc = source
    if (source.find("lisp") == -1):
        s = lisp_address(LISP_AFI_NONE, "", 0, 0)
        s.string_to_afi(source)
        s.store_address(source)
        source = s
    #endif

    if (header.type == LISP_MAP_REQUEST): 
        lisp_process_map_request(lisp_sockets, packet, None, 0, source, 
            udp_sport, False, ttl, timestamp)

    elif (header.type == LISP_MAP_REPLY): 
        lisp_process_map_reply(lisp_sockets, packet, source, ttl, timestamp)

    elif (header.type == LISP_MAP_REGISTER): 
        lisp_process_map_register(lisp_sockets, packet, source, udp_sport)

    elif (header.type == LISP_MAP_NOTIFY): 
        if (from_ipc == "lisp-etr"):
            lisp_process_multicast_map_notify(packet, source)
        elif (lisp_is_running("lisp-rtr")):
            lisp_process_multicast_map_notify(packet, source)
        elif (lisp_is_running("lisp-itr")):
            lisp_process_unicast_map_notify(lisp_sockets, packet, source)
        #endif

    elif (header.type == LISP_MAP_NOTIFY_ACK): 
        lisp_process_map_notify_ack(packet, source)

    elif (header.type == LISP_MAP_REFERRAL): 
        lisp_process_map_referral(lisp_sockets, packet, source)

    elif (header.type == LISP_NAT_INFO and header.is_info_reply()):
        x, y, trigger_flag = lisp_process_info_reply(source, packet, True)

    elif (header.type == LISP_NAT_INFO and header.is_info_reply() == False):
        addr_str = source.print_address_no_iid()
        lisp_process_info_request(lisp_sockets, packet, addr_str, udp_sport, 
            None)

    elif (header.type == LISP_ECM): 
        lisp_process_ecm(lisp_sockets, packet, source, udp_sport)

    else:
        lprint("Invalid LISP control packet type {}:".format(header.type))
        lprint(lisp_format_packet(packet))

    #endif
    return(trigger_flag)
#enddef

#
# lisp_process_rloc_probe_request
#
# Process Map-Request with RLOC-probe bit set.
#
def lisp_process_rloc_probe_request(lisp_sockets, map_request, source, port,
    ttl, timestamp):

    p = bold("RLOC-probe", False)

    if (lisp_i_am_etr):
        lprint("Received {} Map-Request, send RLOC-probe Map-Reply".format(p))
        lisp_etr_process_map_request(lisp_sockets, map_request, source, port,
            ttl, timestamp)
        return
    #endif

    if (lisp_i_am_rtr):
        lprint("Received {} Map-Request, send RLOC-probe Map-Reply".format(p))
        lisp_rtr_process_map_request(lisp_sockets, map_request, source, port,
            ttl, timestamp)
        return
    #endif

    lprint("Ignoring received {} Map-Request, not an ETR or RTR".format(p))
    return
#enddef

#
# lisp_process_smr
#
def lisp_process_smr(map_request):
    lprint("Received SMR-based Map-Request")
    return
#enddef

#
# lisp_process_smr_invoked_request
#
def lisp_process_smr_invoked_request(map_request):
    lprint("Received SMR-invoked Map-Request")
    return
#enddef

#
# lisp_build_map_reply
#
# Build a Map-Reply and return a packet to the caller.
#
def lisp_build_map_reply(eid, group, rloc_set, nonce, action, ttl, map_request,
    keys, enc, auth, mr_ttl=-1):

    rloc_probe = map_request.rloc_probe if (map_request != None) else False
    json_telemetry = map_request.json_telemetry if (map_request != None) else \
        None

    map_reply = lisp_map_reply()
    map_reply.rloc_probe = rloc_probe
    map_reply.echo_nonce_capable = enc
    map_reply.hop_count = 0 if (mr_ttl == -1) else mr_ttl
    map_reply.record_count = 1
    map_reply.nonce = nonce
    packet = map_reply.encode()
    map_reply.print_map_reply()

    eid_record = lisp_eid_record()
    eid_record.rloc_count = len(rloc_set)
    if (json_telemetry != None): eid_record.rloc_count += 1
    eid_record.authoritative = auth
    eid_record.record_ttl = ttl
    eid_record.action = action
    eid_record.eid = eid
    eid_record.group = group

    packet += eid_record.encode()
    eid_record.print_record("  ", False)

    local_rlocs = lisp_get_all_addresses() + lisp_get_all_translated_rlocs()

    probing_rloc = None
    for rloc_entry in rloc_set:
        multicast = rloc_entry.rloc.is_multicast_address()
        rloc_record = lisp_rloc_record()
        probe_bit = rloc_probe and (multicast or json_telemetry == None)
        addr_str = rloc_entry.rloc.print_address_no_iid()
        if (addr_str in local_rlocs or multicast):
            rloc_record.local_bit = True
            rloc_record.probe_bit = probe_bit
            rloc_record.keys = keys
            if (rloc_entry.priority == 254 and lisp_i_am_rtr):
                rloc_record.rloc_name = "RTR"
            #endif
            if (probing_rloc == None):
                if (rloc_entry.translated_rloc.is_null()):
                    probing_rloc = rloc_entry.rloc 
                else: 
                    probing_rloc = rloc_entry.translated_rloc
                #endif
            #endif
        #endif
        rloc_record.store_rloc_entry(rloc_entry)
        rloc_record.reach_bit = True
        rloc_record.print_record("    ")
        packet += rloc_record.encode()
    #endfor

    #
    # Add etr-out-ts if telemetry data was present in Map-Request.
    #
    if (json_telemetry != None):
        rloc_record = lisp_rloc_record()
        if (probing_rloc): rloc_record.rloc.copy_address(probing_rloc)
        rloc_record.local_bit = True
        rloc_record.probe_bit = True
        rloc_record.reach_bit = True
        if (lisp_i_am_rtr):
            rloc_record.priority = 254
            rloc_record.rloc_name = "RTR"
        #endif
        js = lisp_encode_telemetry(json_telemetry, eo=str(time.time()))
        rloc_record.json = lisp_json("telemetry", js)
        rloc_record.print_record("    ")
        packet += rloc_record.encode()
    #endif
    return(packet)
#enddef

#
# lisp_build_map_referral
#
# Build a Map-Referral and return a packet to the caller.
#
def lisp_build_map_referral(eid, group, ddt_entry, action, ttl, nonce):
    map_referral = lisp_map_referral()
    map_referral.record_count = 1
    map_referral.nonce = nonce
    packet = map_referral.encode()
    map_referral.print_map_referral()

    eid_record = lisp_eid_record()

    rloc_count = 0
    if (ddt_entry == None):
        eid_record.eid = eid
        eid_record.group = group
    else:
        rloc_count = len(ddt_entry.delegation_set)
        eid_record.eid = ddt_entry.eid
        eid_record.group = ddt_entry.group
        ddt_entry.map_referrals_sent += 1
    #endif
    eid_record.rloc_count = rloc_count
    eid_record.authoritative = True

    #
    # Use action passed into this function. But if NULL, select the action
    # based on the first ddt-node child type.
    #
    incomplete = False
    if (action == LISP_DDT_ACTION_NULL):
        if (rloc_count == 0):
            action = LISP_DDT_ACTION_NODE_REFERRAL
        else:
            ddt_node = ddt_entry.delegation_set[0]
            if (ddt_node.is_ddt_child()): 
                action = LISP_DDT_ACTION_NODE_REFERRAL
            #endif
            if (ddt_node.is_ms_child()): 
                action = LISP_DDT_ACTION_MS_REFERRAL
            #endif
        #endif
    #endif

    #
    # Conditions when the incomplete bit should be set in the Map-Referral.
    #
    if (action == LISP_DDT_ACTION_NOT_AUTH): incomplete = True
    if (action in (LISP_DDT_ACTION_MS_REFERRAL, LISP_DDT_ACTION_MS_ACK)):
        incomplete = (lisp_i_am_ms and ddt_node.is_ms_peer() == False)
    #endif

    eid_record.action = action
    eid_record.ddt_incomplete = incomplete
    eid_record.record_ttl = ttl

    packet += eid_record.encode()
    eid_record.print_record("  ", True)

    if (rloc_count == 0): return(packet)

    for ddt_node in ddt_entry.delegation_set:
        rloc_record = lisp_rloc_record()
        rloc_record.rloc = ddt_node.delegate_address
        rloc_record.priority = ddt_node.priority
        rloc_record.weight = ddt_node.weight
        rloc_record.mpriority = 255
        rloc_record.mweight = 0
        rloc_record.reach_bit = True
        packet += rloc_record.encode()
        rloc_record.print_record("    ")
    #endfor
    return(packet)
#enddef

#
# lisp_etr_process_map_request
#
# Do ETR processing of a Map-Request.
#
def lisp_etr_process_map_request(lisp_sockets, map_request, source, sport,
    ttl, etr_in_ts):

    if (map_request.target_group.is_null()):
        db = lisp_db_for_lookups.lookup_cache(map_request.target_eid, False)
    else:
        db = lisp_db_for_lookups.lookup_cache(map_request.target_group, False)
        if (db): db = db.lookup_source_cache(map_request.target_eid, False)
    #endif
    eid_str = map_request.print_prefix()

    if (db == None):
        lprint("Database-mapping entry not found for requested EID {}". \
            format(green(eid_str, False)))
        return
    #endif

    prefix_str = db.print_eid_tuple()

    lprint("Found database-mapping EID-prefix {} for requested EID {}". \
        format(green(prefix_str, False), green(eid_str, False)))

    #
    # Get ITR-RLOC to return Map-Reply to.
    #
    itr_rloc = map_request.itr_rlocs[0]
    if (itr_rloc.is_private_address() and lisp_nat_traversal): 
        itr_rloc = source
    #endif

    nonce = map_request.nonce
    enc = lisp_nonce_echoing
    keys = map_request.keys

    #
    # If we found telemetry data in the Map-Request, add the input timestamp
    # now and add output timestamp when building the Map-Reply.
    #
    jt = map_request.json_telemetry
    if (jt != None):
        map_request.json_telemetry = lisp_encode_telemetry(jt, ei=etr_in_ts)
    #endif

    db.map_replies_sent += 1

    packet = lisp_build_map_reply(db.eid, db.group, db.rloc_set, nonce, 
        LISP_NO_ACTION, 1440, map_request, keys, enc, True, ttl)

    #
    # If we are sending a RLOC-probe Map-Reply to an RTR, data encapsulate it.
    # If we are getting RLOC-probe Map-Requests from an xTR behind a NAT, and 
    # we are an ETR not behind a NAT, we want return the RLOC-probe Map-Reply 
    # to the swapped control ports.
    #
    # We could be getting a RLOC-probe from an xTR that is behind the same
    # NAT as us. So do not data encapsulate the RLOC-probe reply.
    #
    # There is a special hack here. If the sport is 0, this RLOC-probe
    # request is coming from an RTR. If we are doing gleaning on the RTR,
    # this xTR needs to data encapsulate the RLOC-probe reply. The lisp_rtr_
    # list will not be set because a gleaned xTR does not have NAT-traversal
    # enabled.
    #
    if (map_request.rloc_probe and len(lisp_sockets) == 4):

        public = (itr_rloc.is_private_address() == False)
        rtr = itr_rloc.print_address_no_iid()
        if (public and rtr in lisp_rtr_list and sport == 0):
            lisp_encap_rloc_probe(lisp_sockets, itr_rloc, None, packet)
            return
        #endif

        #
        # For decent-nat, an ITR will send probe request with ports
        # 4341->ephem-etr. To get probe reply through its NAT, we the ETR
        # need to send with ports 4341->ephem-itr. Port to use for
        # Map-Reply was sent when lisp-itr told this lisp-etr process to
        # NAT probe the RLOC address to open NAT. Now we will use it for
        # RLOC-probe replies.
        #
        if (lisp_decent_nat):
            ni = lisp_get_nat_info(itr_rloc, None)
            if (ni == None):
                ir = itr_rloc.print_address_no_iid()
                lprint("Could not find NAT-info state for {}".format(ir))
                return
            #endif

            #
            # Encapsulate the RLOC-probe reply from port 4341.
            #
            lisp_encap_rloc_probe(lisp_sockets, itr_rloc, ni, packet)
            return
        #endif
    #endif

    #
    # Send to lisp-core process to send packet from UDP port 4342.
    #
    lisp_send_map_reply(lisp_sockets, packet, itr_rloc, sport)
    return
#enddef

#
# lisp_rtr_process_map_request
#
# Do ETR processing of a Map-Request.
#
def lisp_rtr_process_map_request(lisp_sockets, map_request, source, sport,
    ttl, etr_in_ts):

    #
    # Get ITR-RLOC to return Map-Reply to.
    #
    itr_rloc = map_request.itr_rlocs[0]
    if (itr_rloc.is_private_address()): itr_rloc = source
    nonce = map_request.nonce

    eid = map_request.target_eid
    group = map_request.target_group

    rloc_set = []
    for myrloc in [lisp_myrlocs[0], lisp_myrlocs[1]]:
        if (myrloc == None): continue
        rloc = lisp_rloc()
        rloc.rloc.copy_address(myrloc)
        rloc.priority = 254
        rloc_set.append(rloc)
    #endfor

    enc = lisp_nonce_echoing
    keys = map_request.keys

    #
    # If we found telemetry data in the Map-Request, add the input timestamp
    # now and add output timestamp in building the Map-Reply.
    #
    jt = map_request.json_telemetry
    if (jt != None):
        map_request.json_telemetry = lisp_encode_telemetry(jt, ei=etr_in_ts)
    #endif

    packet = lisp_build_map_reply(eid, group, rloc_set, nonce, LISP_NO_ACTION,
        1440, map_request, keys, enc, True, ttl)
    lisp_send_map_reply(lisp_sockets, packet, itr_rloc, sport)
    return
#enddef

#
# lisp_get_private_rloc_set
#
# If the source-EID and target-EID of a Map-Request are behind the same NAT,
# that is, have the same global RLOC address, then return just the private
# addresses in the Map-Reply so the xTRs have shortest RLOC paths between
# each other and don't have to hair-pin through the NAT/firewall device.
#
def lisp_get_private_rloc_set(target_site_eid, seid, group):
    rloc_set = target_site_eid.registered_rlocs

    source_site_eid = lisp_site_eid_lookup(seid, group, False)
    if (source_site_eid == None): return(rloc_set)

    #
    # Get global RLOC address from target site.
    #
    target_rloc = None
    new_set = []
    for rloc_entry in rloc_set:
        if (rloc_entry.is_rtr()): continue
        if (rloc_entry.rloc.is_private_address()):
            new_rloc = copy.deepcopy(rloc_entry)
            new_set.append(new_rloc)
            continue
        #endif
        target_rloc = rloc_entry
        break
    #endfor
    if (target_rloc == None): return(rloc_set)
    target_rloc = target_rloc.rloc.print_address_no_iid()

    #
    # Get global RLOC address from source site.
    #
    source_rloc = None
    for rloc_entry in source_site_eid.registered_rlocs:
        if (rloc_entry.is_rtr()): continue
        if (rloc_entry.rloc.is_private_address()): continue
        source_rloc = rloc_entry
        break
    #endfor
    if (source_rloc == None): return(rloc_set)
    source_rloc = source_rloc.rloc.print_address_no_iid()

    #
    # If the xTRs are behind the same NAT, then we return private addresses.
    #
    site_id = target_site_eid.site_id
    if (site_id == 0):
        if (source_rloc == target_rloc): 
            lprint("Return private RLOCs for sites behind {}".format( \
                target_rloc))
            return(new_set)
        #endif
        return(rloc_set)
    #endif

    #
    # If the xTRs are not behind the same NAT, but are configured in the
    # same site-id, they can reach each other with private addresses. So
    # return them in the RLOC-set.
    #
    if (site_id == source_site_eid.site_id):
        lprint("Return private RLOCs for sites in site-id {}".format(site_id))
        return(new_set)
    #endif
    return(rloc_set)
#enddef
                
#
# lisp_get_partial_rloc_set
#
# If the Map-Request source is found in the RLOC-set, return all RLOCs that
# do not have the same priority as the Map-Request source (an RTR supporting
# NAT-traversal) RLOC. Otherwise, return all RLOCs that are not priority 254.
#
def lisp_get_partial_rloc_set(registered_rloc_set, mr_source, multicast):
    rtr_list = []
    rloc_set = []

    #
    # Search the RTR list to see if the Map-Requestor is an RTR. If so,
    # return the RLOC-set to the RTR so it can replicate directly to ETRs.
    # Otherwise, return the RTR-list locator-set to the requesting ITR/PITR.
    #
    rtr_is_requestor = False
    behind_nat = False
    for rloc_entry in registered_rloc_set:
        if (rloc_entry.priority != 254): continue
        behind_nat |= True
        if (rloc_entry.rloc.is_exact_match(mr_source) == False): continue
        rtr_is_requestor = True
        break
    #endfor

    #
    # If we find an RTR in the RLOC-set, then the site's RLOC-set is behind
    # a NAT. Otherwise, do not return a partial RLOC-set. This RLOC-set is in 
    # public space.
    #
    if (behind_nat == False): return(registered_rloc_set)

    #
    # An RTR can be behind a NAT when deployed in a cloud infrastructure.
    # When the MS is in the same cloud infrastructure, the source address
    # of the Map-Request (ECM) is not translated. So we are forced to put
    # the private address in the rtr-list the MS advertises. But we should
    # not return the private address in any Map-Replies. We use the private
    # address in the rtr-list for the sole purpose to identify the RTR so
    # we can return the RLOC-set of the ETRs.
    #
    ignore_private = (os.getenv("LISP_RTR_BEHIND_NAT") != None)

    #
    # Create two small lists. A list of RTRs which are unicast priority of
    # 254 and a rloc-set which are records that are not priority 254.
    #
    for rloc_entry in registered_rloc_set:
        if (ignore_private and rloc_entry.rloc.is_private_address()): continue
        if (multicast == False and rloc_entry.priority == 255): continue
        if (multicast and rloc_entry.mpriority == 255): continue
        if (rloc_entry.priority == 254): 
            rtr_list.append(rloc_entry)
        else:
            rloc_set.append(rloc_entry)
        #endif
    #endif

    #
    # The RTR is sending the Map-Request.
    #
    if (rtr_is_requestor): return(rloc_set)

    #
    # An ITR is sending the Map-Request.
    #
    # Chcek the case where an ETR included a local RLOC and may be behind
    # the same NAT as the requester. In this case, the requester can encap
    # directly the private RLOC. If it is not reachable, the ITR can encap
    # to the RTR. The ITR will cache a subset of the RLOC-set in this entry
    # (so it can check the global RLOC first and not encap to itself).
    #
    # This can also be true for IPv6 RLOCs. So include them.
    #
    rloc_set = []
    for rloc_entry in registered_rloc_set:
        if (rloc_entry.rloc.is_ipv6()): rloc_set.append(rloc_entry)
        if (rloc_entry.rloc.is_private_address()): rloc_set.append(rloc_entry)
    #endfor
    rloc_set += rtr_list
    return(rloc_set)
#enddef

#
# lisp_store_pubsub_state
#
# Take information from Map-Request to create a pubsub cache. We remember
# the map-server lookup EID-prefix. So when the RLOC-set changes for this
# EID-prefix, we trigger a Map-Notify messate to the ITR's RLOC and port 
# number.
#
def lisp_store_pubsub_state(reply_eid, itr_rloc, mr_sport, nonce, ttl, xtr_id):
    pubsub = lisp_pubsub(itr_rloc, mr_sport, nonce, ttl, xtr_id)
    pubsub.add(reply_eid)
    return(pubsub)
#enddef

#
# lisp_convert_reply_to_notify
#
# In lisp_ms_process_map_request(), a proxy map-reply is built to return to
# a requesting ITR. If the requesting ITR set the N-bit in the Map-Request,
# a subscription request is being requested, return a Map-Notify so it knows
# it has been acked.
#
# This function takes a fully built Map-Reply, changes the first 4 bytes to
# make the message a Map-Notify and inserts 4-bytes of Key-ID, Alg-ID, and
# Authentication Length of 0. Then we have converted the Map-Reply into a
# Map-Notify.
#
def lisp_convert_reply_to_notify(packet):

    #
    # Get data we need from Map-Reply for Map-Notify.
    #
    record_count = struct.unpack("I", packet[0:4])[0]
    record_count = socket.ntohl(record_count) & 0xff
    nonce = packet[4:12]
    packet = packet[12::]

    #
    # Build Map-Notify header.
    #
    first_long = (LISP_MAP_NOTIFY << 28) | record_count
    header = struct.pack("I", socket.htonl(first_long))
    auth = struct.pack("I", 0)

    #
    # Concat fields of Map-Notify.
    #
    packet = header + nonce + auth + packet
    return(packet)
#enddef

#
# lisp_notify_subscribers
# 
# There has been an RLOC-set change, inform all subscribers who have subscribed
# to this EID-prefix.
#
def lisp_notify_subscribers(lisp_sockets, eid_record, rloc_records,
    registered_eid, site):

    for peid in lisp_pubsub_cache:
        for pubsub in list(lisp_pubsub_cache[peid].values()):
            e = pubsub.eid_prefix
            if (e.is_more_specific(registered_eid) == False): continue

            itr = pubsub.itr
            port = pubsub.port
            itr_str = red(itr.print_address_no_iid(), False)
            sub_str = bold("subscriber", False)
            xtr_id = "0x" + lisp_hex_string(pubsub.xtr_id)
            nonce = "0x" + lisp_hex_string(pubsub.nonce)
  
            lprint("    Notify {} {}:{} xtr-id {} for {}, nonce {}".format( \
                sub_str, itr_str, port, xtr_id, green(peid, False), nonce))

            #
            # Do not use memory from EID-record of Map-Register since we are
            # over-writing EID for Map-Notify message.
            #
            pubsub_record = copy.deepcopy(eid_record)
            pubsub_record.eid.copy_address(e)
            pubsub_record = pubsub_record.encode() + rloc_records
            lisp_build_map_notify(lisp_sockets, pubsub_record, [peid], 1, itr,
                port, pubsub.nonce, 0, 0, 0, site, False)

            pubsub.map_notify_count += 1
        #endfor
    #endfor
    return
#enddef

#
# lisp_process_pubsub
#
# Take a fully built Map-Reply and send a Map-Notify as a pubsub ack. 
#
def lisp_process_pubsub(lisp_sockets, packet, reply_eid, itr_rloc, port, nonce,
    ttl, xtr_id):

    #
    # Store subscriber state.
    #
    pubsub = lisp_store_pubsub_state(reply_eid, itr_rloc, port, nonce, ttl,
        xtr_id)

    eid = green(reply_eid.print_prefix(), False)
    itr = red(itr_rloc.print_address_no_iid(), False)
    mn = bold("Map-Notify", False)
    xtr_id = "0x" + lisp_hex_string(xtr_id)
    lprint("{} pubsub request for {} to ack ITR {} xtr-id: {}".format(mn, 
         eid, itr, xtr_id))

    #
    # Convert Map-Reply to Map-Notify header and send out.
    #
    packet = lisp_convert_reply_to_notify(packet)
    lisp_send_map_notify(lisp_sockets, packet, itr_rloc, port)
    pubsub.map_notify_count += 1
    return
#enddef

#
# lisp_ms_process_map_request
#
# Do Map-Server processing of a Map-Request. Returns various LISP-DDT internal
# and external action values.
#
def lisp_ms_process_map_request(lisp_sockets, packet, map_request, mr_source, 
    mr_sport, ecm_source):

    #
    # Look up EID in site cache. If we find it and it has registered for
    # proxy-replying, this map-server will send the Map-Reply. Otherwise,
    # send to one of the ETRs at the registered site.
    #
    eid = map_request.target_eid
    group = map_request.target_group
    eid_str = lisp_print_eid_tuple(eid, group)
    itr_rloc = map_request.itr_rlocs[0]
    xtr_id = map_request.xtr_id
    nonce = map_request.nonce
    action = LISP_NO_ACTION
    pubsub = map_request.subscribe_bit
    decent_nat_xtr = map_request.decent_nat_xtr

    #
    # Check if we are verifying Map-Request signatures. If so, do a mapping
    # database lookup on the source-EID to get public-key.
    #
    sig_good = True
    is_crypto_hash = (lisp_get_eid_hash(eid) != None)
    if (is_crypto_hash):
        sig = map_request.map_request_signature
        if (sig == None):
            sig_good = False
            lprint(("EID-crypto-hash signature verification {}, " + \
                "no signature found").format(bold("failed", False)))
        else:
            sig_eid = map_request.signature_eid
            hash_eid, pubkey, sig_good = lisp_lookup_public_key(sig_eid)
            if (sig_good):
                sig_good = map_request.verify_map_request_sig(pubkey)
            else:
                lprint("Public-key lookup failed for sig-eid {}, hash-eid {}".\
                    format(sig_eid.print_address(), hash_eid.print_address()))
            #endif
            pf = bold("passed", False) if sig_good else bold("failed", False)
            lprint("EID-crypto-hash signature verification {}".format(pf))
        #endif
    #endif

    if (pubsub and sig_good == False):
        pubsub = False
        lprint("Suppress creating pubsub state due to signature failure")
    #endif

    #
    # There are two cases here that need attention. If the Map-Request was
    # an IPv6 Map-Request but the ECM came to us in a IPv4 packet, we need
    # to return the Map-Reply in IPv4. And if the Map-Request came to us
    # through a NAT, sending the Map-Reply to the Map-Request port won't
    # get translated by the NAT. So we have to return the Map-Reply to the
    # ECM port. Hopefully, the RTR is listening on the ECM port and using
    # the Map-Request port as the ECM port as well. This is typically only
    # a problem on the RTR, when behind a NAT. For an ITR, it usaully 
    # doesn't send Map-Requests since NAT-traversal logic installs default 
    # map-cache entries.
    #
    reply_dest = itr_rloc if (itr_rloc.afi == ecm_source.afi) else ecm_source

    site_eid = lisp_site_eid_lookup(eid, group, False)

    if (site_eid == None or site_eid.is_star_g()):
        notfound = bold("Site not found", False)
        lprint("{} for requested EID {}".format(notfound, 
            green(eid_str, False)))

        #
        # Send negative Map-Reply with TTL 15 minutes.
        #
        lisp_send_negative_map_reply(lisp_sockets, eid, group, nonce, itr_rloc,
            mr_sport, 15, xtr_id, pubsub) 

        return([eid, group, LISP_DDT_ACTION_SITE_NOT_FOUND])
    #endif

    prefix_str = site_eid.print_eid_tuple()
    site_name = site_eid.site.site_name

    #
    # If we are requesting for non Crypto-EIDs and signatures are configured
    # to be requred and no signature is in the Map-Request, bail.
    #
    if (is_crypto_hash == False and site_eid.require_signature):
        sig = map_request.map_request_signature
        sig_eid = map_request.signature_eid
        if (sig == None or sig_eid.is_null()):
            lprint("Signature required for site {}".format(site_name))
            sig_good = False
        else:
            sig_eid = map_request.signature_eid
            hash_eid, pubkey, sig_good = lisp_lookup_public_key(sig_eid)
            if (sig_good):
                sig_good = map_request.verify_map_request_sig(pubkey)
            else:
                lprint("Public-key lookup failed for sig-eid {}, hash-eid {}".\
                    format(sig_eid.print_address(), hash_eid.print_address()))
            #endif
            pf = bold("passed", False) if sig_good else bold("failed", False)
            lprint("Required signature verification {}".format(pf))
        #endif
    #endif

    #
    # Check if site-eid is registered.
    #
    if (sig_good and site_eid.registered == False):
        lprint("Site '{}' with EID-prefix {} is not registered for EID {}". \
            format(site_name, green(prefix_str, False), green(eid_str, False)))

        #
        # We do not to return a coarser EID-prefix to the Map-Resolver. The
        # AMS site entry may be one.
        #
        if (site_eid.accept_more_specifics == False):
            eid = site_eid.eid
            group = site_eid.group
        #endif 

        #
        # Send forced-TTLs even for native-forward entries.
        #
        ttl = 1
        if (site_eid.force_ttl != None):
            ttl = site_eid.force_ttl | 0x80000000
        #endif
        not_yet = (site_eid.proxy_reply_action == "not-registered-yet")

        #
        # Send negative Map-Reply with TTL 1 minute.
        #
        lisp_send_negative_map_reply(lisp_sockets, eid, group, nonce, itr_rloc,
            mr_sport, ttl, xtr_id, pubsub, not_reg_yet=not_yet)

        return([eid, group, LISP_DDT_ACTION_MS_NOT_REG])
    #endif

    #
    # Should we proxy-reply?
    #
    nat = False
    pr_str = ""
    check_policy = False
    if (site_eid.force_nat_proxy_reply):
        pr_str = ", nat-forced"
        nat = (decent_nat_xtr == False)
        check_policy = True
    elif (site_eid.force_proxy_reply):
        pr_str = ", forced"
        check_policy = True
    elif (site_eid.proxy_reply_requested):
        pr_str = ", requested"
        check_policy = True
    elif (map_request.pitr_bit and site_eid.pitr_proxy_reply_drop):
        pr_str = ", drop-to-pitr"
        action = LISP_DROP_ACTION
    elif (site_eid.proxy_reply_action != ""):
        action = site_eid.proxy_reply_action
        pr_str = ", forced, action {}".format(action)
        action = LISP_DROP_ACTION if (action == "drop") else \
            LISP_NATIVE_FORWARD_ACTION
    #endif

    #
    # Apply policy to determine if we send a negative map-reply with action
    # "policy-denied" or we send a map-reply with the policy set parameters.
    #
    policy_drop = False
    policy = None
    if (check_policy and site_eid.policy in lisp_policies):
        p = lisp_policies[site_eid.policy]
        if (p.match_policy_map_request(map_request, mr_source)): policy = p

        if (policy):
            ps = bold("matched", False)
            lprint("Map-Request {} policy '{}', set-action '{}'".format(ps, 
                p.policy_name, p.set_action))
        else:
            ps = bold("no match", False)
            lprint("Map-Request {} for policy '{}', implied drop".format(ps, 
                p.policy_name))
            policy_drop = True
        #endif
    #endif

    if (pr_str != ""):
        lprint("Proxy-replying for EID {}, found site '{}' EID-prefix {}{}". \
            format(green(eid_str, False), site_name, green(prefix_str, False),
            pr_str))

        rloc_set = site_eid.registered_rlocs
        ttl = 1440
        if (nat): 
            if (site_eid.site_id != 0):
                seid = map_request.source_eid
                rloc_set = lisp_get_private_rloc_set(site_eid, seid, group)
            #endif
            if (rloc_set == site_eid.registered_rlocs):
                m = (site_eid.group.is_null() == False)
                new_set = lisp_get_partial_rloc_set(rloc_set, reply_dest, m)
                if (new_set != rloc_set):
                    ttl = 15
                    rloc_set = new_set
                #endif
            #endif
        #endif

        #
        # Force TTL if configured. To denote seconds in TTL field of EID-record
        # set high-order bit in ttl value.
        #
        if (site_eid.force_ttl != None):
            ttl = site_eid.force_ttl | 0x80000000
        #endif

        #
        # Does policy say what the ttl should be? And if we should drop the
        # Map-Request and return a negative Map-Reply
        #
        if (policy): 
            if (policy.set_record_ttl):
                ttl = policy.set_record_ttl
                lprint("Policy set-record-ttl to {}".format(ttl))
            #endif
            if (policy.set_action == "drop"):
                lprint("Policy set-action drop, send negative Map-Reply")
                action = LISP_POLICY_DENIED_ACTION
                rloc_set = []
            else:
                rloc = policy.set_policy_map_reply()
                if (rloc): rloc_set = [rloc]
            #endif
        #endif

        if (policy_drop):
            lprint("Implied drop action, send negative Map-Reply")
            action = LISP_POLICY_DENIED_ACTION
            rloc_set = []
        #endif

        enc = site_eid.echo_nonce_capable

        #
        # Don't tell spoofer any prefix information about the target EID.
        # 
        if (sig_good):
            reply_eid = site_eid.eid
            reply_group = site_eid.group
        else:
            reply_eid = eid
            reply_group = group
            action = LISP_AUTH_FAILURE_ACTION
            rloc_set = []
        #endif

        #
        # When replying to a subscribe-request, return target EID and not
        # maybe shorter matched EID-prefix regitered.
        #
        if (pubsub):
            reply_eid = eid
            reply_group = group
        #endif

        #
        # If this Map-Request is also a subscription request, return same
        # information in a Map-Notify.
        #
        packet = lisp_build_map_reply(reply_eid, reply_group, rloc_set, 
            nonce, action, ttl, map_request, None, enc, False)

        if (pubsub):
            lisp_process_pubsub(lisp_sockets, packet, reply_eid, itr_rloc, 
                mr_sport, nonce, ttl, xtr_id)
        else:
            lisp_send_map_reply(lisp_sockets, packet, itr_rloc, mr_sport)
        #endif

        return([site_eid.eid, site_eid.group, LISP_DDT_ACTION_MS_ACK])
    #endif

    #
    # If there are no registered RLOCs, return.
    #
    rloc_count = len(site_eid.registered_rlocs)
    if (rloc_count == 0):
        lprint(("Requested EID {} found site '{}' with EID-prefix {} with " + \
            "no registered RLOCs").format(green(eid_str, False), site_name, 
            green(prefix_str, False)))
        return([site_eid.eid, site_eid.group, LISP_DDT_ACTION_MS_ACK])
    #endif

    #
    # Forward to ETR at registered site. We have to put in an ECM.
    #
    hash_address = map_request.target_eid if map_request.source_eid.is_null() \
        else map_request.source_eid
    hashval = map_request.target_eid.hash_address(hash_address)
    hashval %= rloc_count
    etr = site_eid.registered_rlocs[hashval]

    if (etr.rloc.is_null()):
        lprint(("Suppress forwarding Map-Request for EID {} at site '{}' " + \
            "EID-prefix {}, no RLOC address").format(green(eid_str, False), 
            site_name, green(prefix_str, False)))
    else:
        lprint(("Forwarding Map-Request for EID {} to ETR {} at site '{}' " + \
            "EID-prefix {}").format(green(eid_str, False), 
            red(etr.rloc.print_address(), False), site_name, 
            green(prefix_str, False)))

        #
        # Send ECM.
        #
        lisp_send_ecm(lisp_sockets, packet, map_request.source_eid, mr_sport, 
            map_request.target_eid, etr.rloc, to_etr=True)
    #endif
    return([site_eid.eid, site_eid.group, LISP_DDT_ACTION_MS_ACK])
#enddef

#
# lisp_ddt_process_map_request
#
# Do DDT-node processing of a Map-Request received from an Map-Resolver.
#
def lisp_ddt_process_map_request(lisp_sockets, map_request, ecm_source, port):

    #
    # Lookup target EID address in DDT cache.
    #
    eid = map_request.target_eid
    group = map_request.target_group
    eid_str = lisp_print_eid_tuple(eid, group)
    nonce = map_request.nonce
    action = LISP_DDT_ACTION_NULL

    #
    # First check to see if EID is registered locally if we are a Map-Server.
    # Otherwise, do DDT lookup.
    #
    ddt_entry = None
    if (lisp_i_am_ms):
        site_eid = lisp_site_eid_lookup(eid, group, False)
        if (site_eid == None): return

        if (site_eid.registered):
            action = LISP_DDT_ACTION_MS_ACK
            ttl = 1440
        else:
            eid, group, action = lisp_ms_compute_neg_prefix(eid, group)
            action = LISP_DDT_ACTION_MS_NOT_REG
            ttl = 1
        #endif
    else:
        ddt_entry = lisp_ddt_cache_lookup(eid, group, False)
        if (ddt_entry == None):
            action = LISP_DDT_ACTION_NOT_AUTH
            ttl = 0
            lprint("DDT delegation entry not found for EID {}".format( \
                green(eid_str, False)))
        elif (ddt_entry.is_auth_prefix()):

            #
            # Check auth-prefix. That means there are no referrals.
            #
            action = LISP_DDT_ACTION_DELEGATION_HOLE
            ttl = 15
            ddt_entry_str = ddt_entry.print_eid_tuple()
            lprint(("DDT delegation entry not found but auth-prefix {} " + \
                "found for EID {}").format(ddt_entry_str, 
                green(eid_str, False)))

            if (group.is_null()):
                eid = lisp_ddt_compute_neg_prefix(eid, ddt_entry, 
                    lisp_ddt_cache)
            else:
                group = lisp_ddt_compute_neg_prefix(group, ddt_entry, 
                    lisp_ddt_cache)
                eid = lisp_ddt_compute_neg_prefix(eid, ddt_entry, 
                    ddt_entry.source_cache)
            #endif
            ddt_entry = None
        else:
            ddt_entry_str = ddt_entry.print_eid_tuple()
            lprint("DDT delegation entry {} found for EID {}".format( \
                ddt_entry_str, green(eid_str, False)))
            ttl = 1440
        #endif
    #endif

    #
    # Build and return a Map-Referral message to the source of the Map-Request.
    #
    packet = lisp_build_map_referral(eid, group, ddt_entry, action, ttl, nonce)
    nonce = map_request.nonce >> 32
    if (map_request.nonce != 0 and nonce != 0xdfdf0e1d): port = LISP_CTRL_PORT 
    lisp_send_map_referral(lisp_sockets, packet, ecm_source, port)
    return
#enddef

#
# lisp_find_negative_mask_len
#
# XOR the two addresses so we can find the first bit that is different. Then
# count the number of bits from the left that bit position is. That is the
# new mask-length. Compare to the neg-prefix mask-length we have found so
# far. If the new one is longer than the stored one so far, replace it.
#
# This function assumes the address size and the address-family are the same
# for 'eid' and 'entry_prefix'. Caller must make sure of that.
#
def lisp_find_negative_mask_len(eid, entry_prefix, neg_prefix):
    diff_address = eid.hash_address(entry_prefix)
    address_size = eid.addr_length() * 8
    mask_len = 0

    #
    # The first set bit is the one that is different.
    #
    for mask_len in range(address_size):
        bit_test = 1 << (address_size - mask_len - 1)
        if (diff_address & bit_test): break
    #endfor

    if (mask_len > neg_prefix.mask_len): neg_prefix.mask_len = mask_len
    return
#enddef

#
# lisp_neg_prefix_walk
#
# Callback routine to decide which prefixes should be considered by function
# lisp_find_negative_mask_len().
#
# 'entry' in this routine could be a lisp_ddt_entry() or a lisp_site_eid().
#
def lisp_neg_prefix_walk(entry, parms):
    eid, auth_prefix, neg_prefix = parms

    if (auth_prefix == None):
        if (entry.eid.instance_id != eid.instance_id): 
            return([True, parms])
        #endif
        if (entry.eid.afi != eid.afi): return([True, parms])
    else:
        if (entry.eid.is_more_specific(auth_prefix) == False):
            return([True, parms])
        #endif
    #endif

    #
    # Find bits that match.
    #
    lisp_find_negative_mask_len(eid, entry.eid, neg_prefix)
    return([True, parms])
#enddef

#
# lisp_ddt_compute_neg_prefix
#
# Walk the DDT cache to compute the least specific prefix within the auth-
# prefix found.
#
def lisp_ddt_compute_neg_prefix(eid, ddt_entry, cache):

    #
    # Do not compute negative prefixes for distinguished-names or geo-prefixes.
    #
    if (eid.is_binary() == False): return(eid)

    neg_prefix = lisp_address(eid.afi, "", 0, 0)
    neg_prefix.copy_address(eid)
    neg_prefix.mask_len = 0

    auth_prefix_str = ddt_entry.print_eid_tuple()
    auth_prefix = ddt_entry.eid
            
    #
    # Walk looking for the shortest prefix that DOES not match any site EIDs
    # configured.
    #
    eid, auth_prefix, neg_prefix = cache.walk_cache(lisp_neg_prefix_walk, 
        (eid, auth_prefix, neg_prefix))
    
    #
    # Store high-order bits that are covered by the mask-length.
    #
    neg_prefix.mask_address(neg_prefix.mask_len)

    lprint(("Least specific prefix computed from ddt-cache for EID {} " + \
        "using auth-prefix {} is {}").format(green(eid.print_address(), False),
        auth_prefix_str, neg_prefix.print_prefix()))
    return(neg_prefix)
#enddef

#
# lisp_ms_compute_neg_prefix
#
# From the site cache and the DDT cache, compute a negative EID-prefix to not
# be shorter than a configured authoritative-prefix.
#
def lisp_ms_compute_neg_prefix(eid, group):
    neg_prefix = lisp_address(eid.afi, "", 0, 0)
    neg_prefix.copy_address(eid)
    neg_prefix.mask_len = 0
    gneg_prefix = lisp_address(group.afi, "", 0, 0)
    gneg_prefix.copy_address(group)
    gneg_prefix.mask_len = 0
    auth_prefix = None

    #
    # Look for auth-prefix in DDT cache. If not found, we return the host
    # based EID in a negative Map-Referral, action non-authoritative.
    #
    if (group.is_null()):
        ddt_entry = lisp_ddt_cache.lookup_cache(eid, False)
        if (ddt_entry == None): 
            neg_prefix.mask_len = neg_prefix.host_mask_len()
            gneg_prefix.mask_len = gneg_prefix.host_mask_len()
            return([neg_prefix, gneg_prefix, LISP_DDT_ACTION_NOT_AUTH])
        #endif
        cache = lisp_sites_by_eid
        if (ddt_entry.is_auth_prefix()): auth_prefix = ddt_entry.eid
    else:
        ddt_entry = lisp_ddt_cache.lookup_cache(group, False)
        if (ddt_entry == None): 
            neg_prefix.mask_len = neg_prefix.host_mask_len()
            gneg_prefix.mask_len = gneg_prefix.host_mask_len()
            return([neg_prefix, gneg_prefix, LISP_DDT_ACTION_NOT_AUTH])
        #endif
        if (ddt_entry.is_auth_prefix()): auth_prefix = ddt_entry.group

        group, auth_prefix, gneg_prefix = lisp_sites_by_eid.walk_cache( \
            lisp_neg_prefix_walk, (group, auth_prefix, gneg_prefix))

        gneg_prefix.mask_address(gneg_prefix.mask_len)

        lprint(("Least specific prefix computed from site-cache for " + \
            "group EID {} using auth-prefix {} is {}").format( \
            group.print_address(), auth_prefix.print_prefix() if \
            (auth_prefix != None) else "'not found'", 
            gneg_prefix.print_prefix()))

        cache = ddt_entry.source_cache
    #endif

    #
    # Return the auth-prefix if we found it in the DDT cache.
    #
    action = LISP_DDT_ACTION_DELEGATION_HOLE if (auth_prefix != None) else \
        LISP_DDT_ACTION_NOT_AUTH

    #
    # Walk looking for the shortest prefix that DOES not match any site EIDs
    # configured.
    #
    eid, auth_prefix, neg_prefix = cache.walk_cache(lisp_neg_prefix_walk, 
        (eid, auth_prefix, neg_prefix))
    
    #
    # Store high-order bits that are covered by the mask-length.
    #
    neg_prefix.mask_address(neg_prefix.mask_len)

    lprint(("Least specific prefix computed from site-cache for EID {} " + \
        "using auth-prefix {} is {}").format( \
        green(eid.print_address(), False), 
        auth_prefix.print_prefix() if (auth_prefix != None) else \
       "'not found'", neg_prefix.print_prefix()))

    return([neg_prefix, gneg_prefix, action])
#enddef

#
# lisp_ms_send_map_referral
#
# This function is for a Map-Server to send a Map-Referral to a requesting
# node.
#
def lisp_ms_send_map_referral(lisp_sockets, map_request, ecm_source, port, 
    action, eid_prefix, group_prefix):

    eid = map_request.target_eid
    group = map_request.target_group
    nonce = map_request.nonce

    if (action == LISP_DDT_ACTION_MS_ACK): ttl = 1440

    #
    # Build Map-Server specific Map-Referral.
    #
    map_referral = lisp_map_referral()
    map_referral.record_count = 1
    map_referral.nonce = nonce
    packet = map_referral.encode()
    map_referral.print_map_referral()

    incomplete = False

    #
    # Figure out what action code, EID-prefix, and ttl to return in the EID-
    # record. Temporary return requested prefix until we have lisp_ms_compute_
    # neg_prefix() working.
    #
    if (action == LISP_DDT_ACTION_SITE_NOT_FOUND):
        eid_prefix, group_prefix, action = lisp_ms_compute_neg_prefix(eid, 
            group)
        ttl = 15
    #endif
    if (action == LISP_DDT_ACTION_MS_NOT_REG): ttl = 1
    if (action == LISP_DDT_ACTION_MS_ACK): ttl = 1440
    if (action == LISP_DDT_ACTION_DELEGATION_HOLE): ttl = 15
    if (action == LISP_DDT_ACTION_NOT_AUTH): ttl = 0

    is_ms_peer = False
    rloc_count = 0
    ddt_entry = lisp_ddt_cache_lookup(eid, group, False)
    if (ddt_entry != None):
        rloc_count = len(ddt_entry.delegation_set)
        is_ms_peer = ddt_entry.is_ms_peer_entry()
        ddt_entry.map_referrals_sent += 1
    #endif

    #
    # Conditions when the incomplete bit should be set in the Map-Referral.
    #
    if (action == LISP_DDT_ACTION_NOT_AUTH): incomplete = True
    if (action in (LISP_DDT_ACTION_MS_REFERRAL, LISP_DDT_ACTION_MS_ACK)):
        incomplete = (is_ms_peer == False)
    #endif

    #
    # Store info in EID-record.
    #
    eid_record = lisp_eid_record()
    eid_record.rloc_count = rloc_count
    eid_record.authoritative = True
    eid_record.action = action
    eid_record.ddt_incomplete = incomplete
    eid_record.eid = eid_prefix
    eid_record.group= group_prefix
    eid_record.record_ttl = ttl

    packet += eid_record.encode()
    eid_record.print_record("  ", True)

    #
    # Build referral-set.
    #
    if (rloc_count != 0):
        for ddt_node in ddt_entry.delegation_set:
            rloc_record = lisp_rloc_record()
            rloc_record.rloc = ddt_node.delegate_address
            rloc_record.priority = ddt_node.priority
            rloc_record.weight = ddt_node.weight
            rloc_record.mpriority = 255
            rloc_record.mweight = 0
            rloc_record.reach_bit = True
            packet += rloc_record.encode()
            rloc_record.print_record("    ")
        #endfor
    #endif

    #
    # Build packet and send Map-Referral message to the source of the 
    # Map-Request.
    #
    if (map_request.nonce != 0): port = LISP_CTRL_PORT 
    lisp_send_map_referral(lisp_sockets, packet, ecm_source, port)
    return
#enddef

#
# lisp_send_negative_map_reply
#
# Send a negative Map-Reply. This is one with a specific action code and zero
# RLOCs in the locator-set.
#
def lisp_send_negative_map_reply(sockets, eid, group, nonce, dest, port, ttl,
    xtr_id, pubsub, not_reg_yet=False):

    lprint("Build negative Map-Reply EID-prefix {}, nonce 0x{} to ITR {}". \
        format(lisp_print_eid_tuple(eid, group), lisp_hex_string(nonce), 
        red(dest.print_address(), False)))

    action = LISP_NATIVE_FORWARD_ACTION if group.is_null() else \
        LISP_DROP_ACTION

    #
    # If this is a crypto-EID, return LISP_SEND_MAP_REQUEST_ACTION.
    #
    if (lisp_get_eid_hash(eid) != None):
        action = LISP_SEND_MAP_REQUEST_ACTION
    #endif
    if (not_reg_yet):
        action = LISP_NOT_REGISTERED_YET_ACTION
    #endif


    packet = lisp_build_map_reply(eid, group, [], nonce, action, ttl, None,
        None, False, False)
    
    #
    # Send Map-Notify if this Map-Request is a subscribe-request.
    #
    if (pubsub):
        lisp_process_pubsub(sockets, packet, eid, dest, port, nonce, ttl, 
            xtr_id)
    else:
        lisp_send_map_reply(sockets, packet, dest, port)
    #endif
    return
#enddef

#
# lisp_retransmit_ddt_map_request
#
# Have the Map-Resolver transmit a DDT Map-Request.
#
def lisp_retransmit_ddt_map_request(mr):
    seid_str = mr.mr_source.print_address()
    deid_str = mr.print_eid_tuple()
    nonce = mr.nonce

    #
    # Get referral-node for who we sent Map-Request to last time. We need
    # to increment, the no-response timer.
    #
    if (mr.last_request_sent_to):
        last_node = mr.last_request_sent_to.print_address()
        ref = lisp_referral_cache_lookup(mr.last_cached_prefix[0], 
            mr.last_cached_prefix[1], True)
        if (ref and last_node in ref.referral_set):
            ref.referral_set[last_node].no_responses += 1
        #endif
    #endif

    #
    # Did we reach the max number of retries? We are giving up since no 
    # Map-Notify-Acks have been received.
    #
    if (mr.retry_count == LISP_MAX_MAP_NOTIFY_RETRIES):
        lprint("DDT Map-Request retry limit reached for EID {}, nonce 0x{}". \
            format(green(deid_str, False), lisp_hex_string(nonce)))
        mr.dequeue_map_request()
        return
    #endif

    mr.retry_count += 1

    s = green(seid_str, False)
    d = green(deid_str, False)
    lprint("Retransmit DDT {} from {}ITR {} EIDs: {} -> {}, nonce 0x{}". \
        format(bold("Map-Request", False), "P" if mr.from_pitr else "", 
        red(mr.itr.print_address(), False), s, d, 
        lisp_hex_string(nonce)))

    #
    # Do referral lookup and send the DDT Map-Request again.
    # 
    lisp_send_ddt_map_request(mr, False)

    #
    # Restart retransmit timer.
    #
    mr.retransmit_timer = threading.Timer(LISP_DDT_MAP_REQUEST_INTERVAL, 
        lisp_retransmit_ddt_map_request, [mr])
    mr.retransmit_timer.start()
    return
#enddef

#
# lisp_get_referral_node
#
# Get a referral-node of highest priority that is in the up state. Returns
# class lisp_referral_node().
#
def lisp_get_referral_node(referral, source_eid, dest_eid):

    #
    # Build list of high-priority up referral-nodes.
    #
    ref_set = []
    for ref_node in list(referral.referral_set.values()):
        if (ref_node.updown == False): continue
        if (len(ref_set) == 0 or ref_set[0].priority == ref_node.priority): 
            ref_set.append(ref_node)
        elif (ref_set[0].priority > ref_node.priority):
            ref_set = []
            ref_set.append(ref_node)
        #endif
    #endfor

    ref_count = len(ref_set)
    if (ref_count == 0): return(None)

    hashval = dest_eid.hash_address(source_eid)
    hashval = hashval % ref_count
    return(ref_set[hashval])
#enddef

#
# lisp_send_ddt_map_request
#
# Send a DDT Map-Request based on a EID lookup in the referral cache.
#
def lisp_send_ddt_map_request(mr, send_to_root):
    lisp_sockets = mr.lisp_sockets
    nonce = mr.nonce
    itr = mr.itr
    mr_source = mr.mr_source
    eid_str = mr.print_eid_tuple()

    #
    # Check if the maximum allowable Map-Requests have been sent for this
    # map-request-queue entry.
    #
    if (mr.send_count == 8):
        lprint("Giving up on map-request-queue entry {}, nonce 0x{}".format( \
           green(eid_str, False), lisp_hex_string(nonce)))
        mr.dequeue_map_request()
        return
    #endif

    #
    # If caller wants us to use the root versus best match lookup. We only
    # so this once per Map-Request queue entry.
    #
    if (send_to_root):
        lookup_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
        lookup_group = lisp_address(LISP_AFI_NONE, "", 0, 0)
        mr.tried_root = True
        lprint("Jumping up to root for EID {}".format(green(eid_str, False)))
    else:
        lookup_eid = mr.eid
        lookup_group = mr.group
    #endif

    #
    # Do longest match on EID into DDT referral cache.
    #
    referral = lisp_referral_cache_lookup(lookup_eid, lookup_group, False)
    if (referral == None):
        lprint("No referral cache entry found")
        lisp_send_negative_map_reply(lisp_sockets, lookup_eid, lookup_group,
            nonce, itr, mr.sport, 15, None, False)
        return
    #endif

    ref_str = referral.print_eid_tuple()
    lprint("Found referral cache entry {}, referral-type: {}".format(ref_str,
        referral.print_referral_type()))

    ref_node = lisp_get_referral_node(referral, mr_source, mr.eid)
    if (ref_node == None):
        lprint("No reachable referral-nodes found")
        mr.dequeue_map_request()
        lisp_send_negative_map_reply(lisp_sockets, referral.eid, 
            referral.group, nonce, itr, mr.sport, 1, None, False)
        return
    #endif

    lprint("Send DDT Map-Request to {} {} for EID {}, nonce 0x{}". \
        format(ref_node.referral_address.print_address(), 
        referral.print_referral_type(), green(eid_str, False), 
        lisp_hex_string(nonce)))

    #
    # Encapsulate Map-Request and send out.
    #
    to_ms = (referral.referral_type == LISP_DDT_ACTION_MS_REFERRAL or
             referral.referral_type == LISP_DDT_ACTION_MS_ACK)
    lisp_send_ecm(lisp_sockets, mr.packet, mr_source, mr.sport, mr.eid,
        ref_node.referral_address, to_ms=to_ms, ddt=True)

    #
    # Do some stats.
    #
    mr.last_request_sent_to = ref_node.referral_address
    mr.last_sent = lisp_get_timestamp()
    mr.send_count += 1
    ref_node.map_requests_sent += 1
    return
#enddef

#
# lisp_mr_process_map_request
#
# Process a Map-Request received by an ITR. We need to forward this Map-Request
# to the longest matched referral from the referral-cache.
#
def lisp_mr_process_map_request(lisp_sockets, packet, map_request, ecm_source, 
    sport, mr_source):

    eid = map_request.target_eid
    group = map_request.target_group
    deid_str = map_request.print_eid_tuple()
    seid_str = mr_source.print_address()
    nonce = map_request.nonce

    s = green(seid_str, False)
    d = green(deid_str, False)
    lprint("Received Map-Request from {}ITR {} EIDs: {} -> {}, nonce 0x{}". \
        format("P" if map_request.pitr_bit else "", 
        red(ecm_source.print_address(), False), s, d, 
        lisp_hex_string(nonce)))

    #
    # Queue the Map-Request. We need to reliably transmit it.
    #
    mr = lisp_ddt_map_request(lisp_sockets, packet, eid, group, nonce)
    mr.packet = packet
    mr.itr = ecm_source
    mr.mr_source = mr_source
    mr.sport = sport
    mr.from_pitr = map_request.pitr_bit
    mr.queue_map_request()

    lisp_send_ddt_map_request(mr, False)
    return
#enddef

#
# lisp_process_map_request
#
# Process received Map-Request as a Map-Server or an ETR.
#
def lisp_process_map_request(lisp_sockets, packet, ecm_source, ecm_port, 
    mr_source, mr_port, ddt_request, ttl, timestamp):

    orig_packet = packet
    map_request = lisp_map_request()
    packet = map_request.decode(packet, mr_source, mr_port)
    if (packet == None):
        lprint("Could not decode Map-Request packet")
        return
    #endif

    map_request.print_map_request()

    #
    # If RLOC-probe request, process separately.
    #
    if (map_request.rloc_probe): 
        lisp_process_rloc_probe_request(lisp_sockets, map_request, mr_source,
            mr_port, ttl, timestamp)
        return
    #endif

    #
    # Process SMR.
    #
    if (map_request.smr_bit):
        lisp_process_smr(map_request)
    #endif

    #
    # Process SMR-invoked Map-Request.
    #
    if (map_request.smr_invoked_bit):  
        lisp_process_smr_invoked_request(map_request)
    #endif

    #
    # Do ETR processing of the Map-Request if we found a database-mapping.
    #
    if (lisp_i_am_etr):
        lisp_etr_process_map_request(lisp_sockets, map_request, mr_source,
            mr_port, ttl, timestamp)
    #endif

    #
    # Do Map-Server processing of the Map-Request.
    #
    if (lisp_i_am_ms):
        packet = orig_packet
        eid, group, ddt_action = lisp_ms_process_map_request(lisp_sockets, 
            orig_packet, map_request, mr_source, mr_port, ecm_source)
        if (ddt_request):
            lisp_ms_send_map_referral(lisp_sockets, map_request, ecm_source, 
                ecm_port, ddt_action, eid, group)
        #endif
        return
    #endif

    #
    # Map-Request is from an ITR destined to a Map-Resolver.
    #
    if (lisp_i_am_mr and not ddt_request):
        lisp_mr_process_map_request(lisp_sockets, orig_packet, map_request, 
            ecm_source, mr_port, mr_source)
    #endif                                      

    #
    # Do DDT-node processing of the Map-Request.
    #
    if (lisp_i_am_ddt or ddt_request):
        packet = orig_packet
        lisp_ddt_process_map_request(lisp_sockets, map_request, ecm_source, 
            ecm_port)
    #endif
    return
#enddef

#
# lisp_store_mr_stats
#
# Store counter and timing stats for the map-resolver that just sent us a
# negative Map-Reply.
#
def lisp_store_mr_stats(source, nonce):
    mr = lisp_get_map_resolver(source, None)
    if (mr == None): return

    #
    # Count and record timestamp.
    #
    mr.neg_map_replies_received += 1
    mr.last_reply = lisp_get_timestamp()

    #
    # For every 100 replies, reset the total_rtt so we can get a new average.
    #
    if ((mr.neg_map_replies_received % 100) == 0): mr.total_rtt = 0

    #
    # If Map-Reply matches stored nonce, then we can do an RTT calculation.
    #
    if (mr.last_nonce == nonce): 
        mr.total_rtt += (time.time() - mr.last_used)
        mr.last_nonce = 0
    #endif
    if ((mr.neg_map_replies_received % 10) == 0): mr.last_nonce = 0
    return
#enddef

#
# lisp_process_map_reply
#
# Process received Map-Reply.
#
def lisp_process_map_reply(lisp_sockets, packet, source, ttl, itr_in_ts):
    global lisp_map_cache

    map_reply = lisp_map_reply()
    packet = map_reply.decode(packet)
    if (packet == None):
        lprint("Could not decode Map-Reply packet")
        return
    #endif
    map_reply.print_map_reply()

    #
    # Process each EID record in Map-Reply message.
    #
    rloc_key_change = None
    for i in range(map_reply.record_count):
        eid_record = lisp_eid_record()
        packet = eid_record.decode(packet)
        if (packet == None):
            lprint("Could not decode EID-record in Map-Reply packet")
            return
        #endif
        eid_record.print_record("  ", False)

        #
        # If negative Map-Reply, see if from a Map-Resolver, do some counting
        # and timing stats.
        #
        if (eid_record.rloc_count == 0): 
            lisp_store_mr_stats(source, map_reply.nonce)
        #endif

        multicast = (eid_record.group.is_null() == False)

        #
        # If this is a (0.0.0.0/0, G) with drop-action, we don't want to
        # cache more-specific (S,G) entry. It is a startup timing problem.
        #
        if (lisp_decent_push_configured):
            action = eid_record.action
            if (multicast and action == LISP_DROP_ACTION):
                if (eid_record.eid.is_local()): continue
            #endif
        #endif

        #
        # Some RLOC-probe Map-Replies may have no EID value in the EID-record.
        # Like from RTRs or PETRs.
        #
        if (multicast == False and eid_record.eid.is_null()): continue

        #
        # Do not lose state for other RLOCs that may be stored in an already
        # cached map-cache entry.
        #
        if (multicast):
            mc = lisp_map_cache.lookup_cache(eid_record.group, True)
            if (mc):
                mc = mc.lookup_source_cache(eid_record.eid, False)
            #endif
        else:
            mc = lisp_map_cache.lookup_cache(eid_record.eid, True)
        #endif
        new_mc = (mc == None)

        #
        # Do not let map-cache entries from Map-Replies override gleaned
        # entries.
        #
        if (mc == None):
            glean, x, y = lisp_allow_gleaning(eid_record.eid, eid_record.group,
                None)
            if (glean): continue
        else:
            if (mc.gleaned): continue
        #endif

        #
        # Process each RLOC record in EID record.
        #
        rloc_set = []
        mrloc = None
        rloc_name = None
        for j in range(eid_record.rloc_count):
            rloc_record = lisp_rloc_record()
            rloc_record.keys = map_reply.keys
            packet = rloc_record.decode(packet, map_reply.nonce)
            if (packet == None):
                lprint("Could not decode RLOC-record in Map-Reply packet")
                return
            #endif
            rloc_record.print_record("    ")

            old_rloc = None
            if (mc): old_rloc = mc.get_rloc(rloc_record.rloc)

            if (old_rloc):
                rloc = old_rloc
            else:
                rloc = lisp_rloc()
            #endif

            #
            # Copy RLOC data from record, add to locator-set. Check to see
            # if the RLOC has been translated by a NAT. If so, go get the
            # translated port and store in rloc entry.
            #
            port = rloc.store_rloc_from_record(rloc_record, map_reply.nonce,
                source)
            rloc.echo_nonce_capable = map_reply.echo_nonce_capable

            if (rloc.echo_nonce_capable):
                addr_str = rloc.rloc.print_address_no_iid()
                if (lisp_get_echo_nonce(None, addr_str) == None):
                    lisp_echo_nonce(addr_str)
                #endif
            #endif

            #
            # Add itr-in timestamp if telemetry data included in RLOC record..
            #
            if (rloc.json):
                if (lisp_is_json_telemetry(rloc.json.json_string)):
                    js = rloc.json.json_string
                    js = lisp_encode_telemetry(js, ii=itr_in_ts)
                    rloc.json.json_string = js
                #endif
            #endif

            #
            # Store RLOC name for multicast RLOC members records.
            #
            if (rloc_name == None):
                rloc_name = rloc.rloc_name
            #enif

            #
            # Process state for RLOC-probe reply from this specific RLOC. And
            # update RLOC state for map-cache entry. Ignore an RLOC with a
            # different address-family of the recieved packet. The ITR really
            # doesn't know it can reach the RLOC unless it probes for that
            # address-family.
            #
            if (map_reply.rloc_probe and rloc_record.probe_bit):
                if (rloc.rloc.afi == source.afi):
                    lisp_process_rloc_probe_reply(rloc, source, port,
                        map_reply, ttl, mrloc, rloc_name)
                #endif
                if (rloc.rloc.is_multicast_address()): mrloc = rloc
            #endif

            #
            # Append to rloc-set array to be stored in map-cache entry.
            # 
            rloc_set.append(rloc)

            #
            # Did keys change for thie RLOC, flag it if so.
            #
            if (lisp_data_plane_security and rloc.rloc_recent_rekey()):
                rloc_key_change = rloc
            #endif
        #endfor

        #
        # If the map-cache entry is for an xTR behind a NAT, we'll find an
        # RTR RLOC (which is priority 254). Store private RLOCs that may
        # come along with the RTR RLOC because the destination RLOC could
        # be behind the same NAT as this ITR. This ITR, however could be
        # behind another NAT or in public space. We want to mark the 
        # private address RLOC unreachable for the two later cases.
        #
        if (map_reply.rloc_probe == False and lisp_nat_traversal):
            new_set = []
            log_set = []
            for rloc in rloc_set:
                rloc_str = rloc.rloc.print_address_no_iid()

                #
                # Set initial state for private RLOCs to UNREACH and test
                # with RLOC-probes if up behind same NAT.
                #
                if (rloc.rloc.is_private_address()):
                    rloc.priority = 1
                    rloc.state = LISP_RLOC_UNREACH_STATE
                    new_set.append(rloc)
                    log_set.append(rloc_str)
                    continue
                #endif

                #
                # RTR should not put RTR RLOC in map-cache. But xTRs do. No
                # RTR RLOCs should only go in the RTR map-cache.
                #
                # With decent-nat configured an ITR will put non-RTR RLOCs
                # in the RLOC-set. We can pierce the hole built to get to
                # the ETR directly!
                #
                if (lisp_i_am_rtr):
                    if (rloc.priority != 254):
                        new_set.append(rloc)
                        log_set.append(rloc_str)
                    #endif
                elif (lisp_decent_nat):
                    new_set.append(rloc)
                    log_set.append(rloc_str)
                elif (rloc.priority == 254):
                    new_set.append(rloc)
                    log_set.append(rloc_str)
                #endif
            #endif

            if (log_set != []):
                rloc_set = new_set
                nat_str = "NAT-decent" if (lisp_decent_nat) else \
                    "NAT-traversal"
                lprint("{} optimized RLOC-set: {}".format(nat_str, log_set))
            #endif
        #endif

        #
        # If any RLOC-records do not have RLOCs, don't put them in the map-
        # cache.
        #
        new_set = []
        for rloc in rloc_set:
            if (rloc.json != None): continue
            new_set.append(rloc)
        #endfor
        if (new_set != []):
            count = len(rloc_set) - len(new_set)
            lprint("Pruning {} no-address RLOC-records for map-cache".format( \
                count))
            rloc_set = new_set
        #endif

        #
        # If any RLOCs have decent-nat ports, Tell the ETR about them so they
        # can be probed with Info-Requests.
        #
        if (lisp_decent_nat):
            for rloc in rloc_set:
                if (rloc.is_decent_nat_port() == False): continue
                lisp_itr_nat_probe(rloc.rloc, rloc.rloc_name, lisp_sockets[2])
            #endfor
        #endif

        #
        # If this is an RLOC-probe reply and the RLOCs are registered with
        # merge semantics, this Map-Reply may not include the other RLOCs.
        # In this case, do not wipe out the other RLOCs. Get them from the
        # existing entry.
        #
        if (map_reply.rloc_probe and mc != None): rloc_set = mc.rloc_set

        #
        # If we are overwriting the rloc-set cached in the map-cache entry,
        # then remove the old rloc pointers from the RLOC-probe list.
        #
        rloc_set_change = new_mc
        if (mc and rloc_set != mc.rloc_set):
            mc.delete_rlocs_from_rloc_probe_list()
            rloc_set_change = True
        #endif

        #
        # Add to map-cache. If this is a replace, save uptime.
        #
        uptime = mc.uptime if (mc) else None
        if (mc == None or rloc_set_change):
            mc = lisp_mapping(eid_record.eid, eid_record.group, rloc_set)
            mc.mapping_source = source

            #
            # If this is a multicast map-cache entry in an RTR, set map-cache
            # TTL small so Map-Requests can be sent more often to capture
            # RLE changes.
            #
            if (lisp_i_am_rtr and eid_record.group.is_null() == False):
                mc.map_cache_ttl = LISP_MCAST_TTL
            else:
                mc.map_cache_ttl = eid_record.store_ttl()
            #endif
            mc.action = eid_record.action
            mc.add_cache(rloc_set_change)
        #endif
        
        add_or_replace = "Add"
        if (uptime):
            mc.uptime = uptime
            mc.refresh_time = lisp_get_timestamp()
            add_or_replace = "Replace"
        #endif

        lprint("{} {} map-cache with {} RLOCs".format(add_or_replace,
            green(mc.print_eid_tuple(), False), len(rloc_set)))

        #
        # If there were any changes to the RLOC-set or the keys for any
        # existing RLOC in the RLOC-set, tell the external data-plane.
        #
        if (lisp_ipc_dp_socket and rloc_key_change != None):
            lisp_write_ipc_keys(rloc_key_change)
        #endif

        #
        # Send RLOC-probe to highest priority RLOCs if this is a new map-cache
        # entry. But if any of the RLOCs were used before in other map-cache
        # entries, no need to send RLOC-probes.
        #
        if (new_mc): 
            probe = bold("RLOC-probe", False)
            for rloc in mc.best_rloc_set:
                addr_str = red(rloc.rloc.print_address_no_iid(), False)
                lprint("Trigger {} to {}".format(probe, addr_str))
                lisp_send_map_request(lisp_sockets, 0, mc.eid, mc.group, rloc)
            #endfor
        #endif
    #endfor
    return
#enddef

#
# lisp_compute_auth
#
# Create HMAC hash from packet contents store in lisp_map_register() and
# encode in packet buffer.
#
def lisp_compute_auth(packet, map_register, password):
    if (map_register.alg_id == LISP_NONE_ALG_ID): return(packet)

    packet = map_register.zero_auth(packet)
    hashval = lisp_hash_me(packet, map_register.alg_id, password, False)

    #
    # Store packed hash value in lisp_map_register().
    #
    map_register.auth_data = hashval
    packet = map_register.encode_auth(packet)
    return(packet)
#enddef

#
# lisp_hash_me
#
# Call HMAC hashing code from multiple places. Returns hash value.
#
def lisp_hash_me(packet, alg_id, password, do_hex):
    if (alg_id == LISP_NONE_ALG_ID): return(True)

    if (alg_id == LISP_SHA_1_96_ALG_ID):
        hashalg = hashlib.sha1
    #endif
    if (alg_id == LISP_SHA_256_128_ALG_ID):
        hashalg = hashlib.sha256
    #endif

    if (do_hex):
        hashval = hmac.new(password.encode(), packet, hashalg).hexdigest()
    else:
        hashval = hmac.new(password.encode(), packet, hashalg).digest()
    #endif
    return(hashval)
#enddef

#
# lisp_verify_auth
#
# Compute sha1 or sha2 hash over Map-Register packet and compare with one
# transmitted in packet that is stored in class lisp_map_register.
#
def lisp_verify_auth(packet, alg_id, auth_data, password):
    if (alg_id == LISP_NONE_ALG_ID): return(True)

    hashval = lisp_hash_me(packet, alg_id, password, True)
    matched = (hashval == auth_data)

    #
    # Print differences if hashes if they do not match.
    #
    if (matched == False): 
        lprint("Hashed value: {} does not match packet value: {}".format( \
            hashval, auth_data))
    #endif
    return(matched)
#enddef

#
# lisp_retransmit_map_notify
#
# Retransmit the already build Map-Notify message.
#
def lisp_retransmit_map_notify(map_notify):
    dest = map_notify.etr
    port = map_notify.etr_port

    #
    # Did we reach the max number of retries? We are giving up since no 
    # Map-Notify-Acks have been received.
    #
    if (map_notify.retry_count == LISP_MAX_MAP_NOTIFY_RETRIES):
        lprint("Map-Notify with nonce 0x{} retry limit reached for ETR {}". \
            format(map_notify.nonce_key, red(dest.print_address(), False)))

        key = map_notify.nonce_key
        if (key in lisp_map_notify_queue):
            map_notify.retransmit_timer.cancel()
            lprint("Dequeue Map-Notify from retransmit queue, key is: {}". \
                format(key))
            try:
                lisp_map_notify_queue.pop(key)
            except:
                lprint("Key not found in Map-Notify queue")
            #endtry
        #endif
        return
    #endif

    lisp_sockets = map_notify.lisp_sockets
    map_notify.retry_count += 1

    lprint("Retransmit {} with nonce 0x{} to xTR {}, retry {}".format( \
        bold("Map-Notify", False), map_notify.nonce_key, 
        red(dest.print_address(), False), map_notify.retry_count))

    lisp_send_map_notify(lisp_sockets, map_notify.packet, dest, port)
    if (map_notify.site): map_notify.site.map_notifies_sent += 1

    #
    # Restart retransmit timer.
    #
    map_notify.retransmit_timer = threading.Timer(LISP_MAP_NOTIFY_INTERVAL, 
        lisp_retransmit_map_notify, [map_notify])
    map_notify.retransmit_timer.start()
    return
#enddef

#
# lisp_send_merged_map_notify
#
# Send Map-Notify with a merged RLOC-set to each ETR in the RLOC-set.
#
def lisp_send_merged_map_notify(lisp_sockets, parent, map_register, 
    eid_record):

    #
    # Build EID-record once.
    #
    eid_record.rloc_count = len(parent.registered_rlocs)
    packet_record = eid_record.encode()
    eid_record.print_record("Merged Map-Notify ", False)

    #
    # Buld RLOC-records for merged RLOC-set.
    #
    for xtr in parent.registered_rlocs:
        rloc_record = lisp_rloc_record()
        rloc_record.store_rloc_entry(xtr)
        rloc_record.local_bit = True
        rloc_record.probe_bit = False
        rloc_record.reach_bit = True
        packet_record += rloc_record.encode()
        rloc_record.print_record("  ")
        del(rloc_record)
    #endfor

    #
    # Build Map-Notify for each xTR that needs to receive the Map-Notify.
    #
    for xtr in parent.registered_rlocs:
        dest = xtr.rloc
        map_notify = lisp_map_notify(lisp_sockets)
        map_notify.record_count = 1
        key_id = map_register.key_id
        map_notify.key_id = key_id
        map_notify.alg_id = map_register.alg_id
        map_notify.auth_len = map_register.auth_len
        map_notify.nonce = map_register.nonce
        map_notify.nonce_key = lisp_hex_string(map_notify.nonce)
        map_notify.etr.copy_address(dest)
        map_notify.etr_port = map_register.sport
        map_notify.site = parent.site
        packet = map_notify.encode(packet_record, parent.site.auth_key[key_id])
        map_notify.print_notify()

        #
        # Put Map-Notify state on retransmission queue.
        #
        key = map_notify.nonce_key
        if (key in lisp_map_notify_queue):
            remove = lisp_map_notify_queue[key]
            remove.retransmit_timer.cancel()
            del(remove)
        #endif
        lisp_map_notify_queue[key] = map_notify

        #
        # Send out.
        #
        lprint("Send merged Map-Notify to ETR {}".format( \
            red(dest.print_address(), False)))
        lisp_send(lisp_sockets, dest, LISP_CTRL_PORT, packet)

        parent.site.map_notifies_sent += 1

        #
        # Set retransmit timer.
        #
        map_notify.retransmit_timer = threading.Timer(LISP_MAP_NOTIFY_INTERVAL,
            lisp_retransmit_map_notify, [map_notify])
        map_notify.retransmit_timer.start()
    #endfor
    return
#enddef

#
# lisp_build_map_notify
#
# Setup retransmission queue entry to send the first Map-Notify.
#
def lisp_build_map_notify(lisp_sockets, eid_records, eid_list, record_count, 
    source, port, nonce, key_id, alg_id, auth_len, site, map_register_ack):

    key = lisp_hex_string(nonce) + source.print_address()

    #
    # If we are already sending Map-Notifies for the 2-tuple, no need to
    # queue an entry and send one out. Let the retransmission timer trigger
    # the sending.
    #
    lisp_remove_eid_from_map_notify_queue(eid_list)
    if (key in lisp_map_notify_queue):
        map_notify = lisp_map_notify_queue[key]
        s = red(source.print_address_no_iid(), False)
        lprint("Map-Notify with nonce 0x{} pending for xTR {}".format( \
            lisp_hex_string(map_notify.nonce), s))
        return
    #endif

    map_notify = lisp_map_notify(lisp_sockets)
    map_notify.record_count = record_count
    key_id = key_id
    map_notify.key_id = key_id
    map_notify.alg_id = alg_id
    map_notify.auth_len = auth_len
    map_notify.nonce = nonce
    map_notify.nonce_key = lisp_hex_string(nonce)
    map_notify.etr.copy_address(source)
    map_notify.etr_port = port
    map_notify.site = site
    map_notify.eid_list = eid_list

    #
    # Put Map-Notify state on retransmission queue.
    #
    if (map_register_ack == False):
        key = map_notify.nonce_key
        lisp_map_notify_queue[key] = map_notify
    #endif

    if (map_register_ack):
        lprint("Send Map-Notify to ack Map-Register")
    else:
        lprint("Send Map-Notify for RLOC-set change")
    #endif

    #
    # Build packet and copy EID records from Map-Register.
    #
    packet = map_notify.encode(eid_records, site.auth_key[key_id])
    map_notify.print_notify()

    if (map_register_ack == False):
        eid_record = lisp_eid_record()
        eid_record.decode(eid_records)
        eid_record.print_record("  ", False)
    #endif

    #
    # Send out.
    #
    lisp_send_map_notify(lisp_sockets, packet, map_notify.etr, port)
    site.map_notifies_sent += 1

    if (map_register_ack): return

    #
    # Set retransmit timer if this is an unsolcited Map-Notify. Otherwise,
    # we are acknowledging a Map-Register and the registerer is not going
    # to send a Map-Notify-Ack so we shouldn't expect one.
    #
    map_notify.retransmit_timer = threading.Timer(LISP_MAP_NOTIFY_INTERVAL, 
        lisp_retransmit_map_notify, [map_notify])
    map_notify.retransmit_timer.start()
    return
#enddef

#
# lisp_send_map_notify_ack
#
# Change Map-Notify message to have a new type (Map-Notify-Ack) and 
# reauthenticate message.
#
def lisp_send_map_notify_ack(lisp_sockets, eid_records, map_notify, ms):
    map_notify.map_notify_ack = True

    #
    # Build packet and copy EID records from Map-Register.
    #
    packet = map_notify.encode(eid_records, ms.password)
    map_notify.print_notify()

    #
    # Send the Map-Notify-Ack.
    #
    dest = ms.map_server
    lprint("Send Map-Notify-Ack to {}".format(
        red(dest.print_address(), False)))
    lisp_send(lisp_sockets, dest, LISP_CTRL_PORT, packet)
    return
#enddef

#
# lisp_send_multicast_map_notify
#
# Send a Map-Notify message to an xTR for the supplied (S,G) passed into this
# function.
#
def lisp_send_multicast_map_notify(lisp_sockets, site_eid, eid_list, xtr):

    map_notify = lisp_map_notify(lisp_sockets)
    map_notify.record_count = 1
    map_notify.nonce = lisp_get_control_nonce()
    map_notify.nonce_key = lisp_hex_string(map_notify.nonce)
    map_notify.etr.copy_address(xtr)
    map_notify.etr_port = LISP_CTRL_PORT
    map_notify.eid_list = eid_list
    key = map_notify.nonce_key

    #
    # If we are already sending Map-Notifies for the 2-tuple, no need to
    # queue an entry and send one out. Let the retransmission timer trigger
    # the sending.
    #
    lisp_remove_eid_from_map_notify_queue(map_notify.eid_list)
    if (key in lisp_map_notify_queue):
        map_notify = lisp_map_notify_queue[key]
        lprint("Map-Notify with nonce 0x{} pending for ITR {}".format( \
            map_notify.nonce, red(xtr.print_address_no_iid(), False)))
        return
    #endif

    #
    # Put Map-Notify state on retransmission queue.
    #
    lisp_map_notify_queue[key] = map_notify

    #
    # Determine if there are any RTRs in the RLOC-set for this (S,G).
    #
    rtrs_exist = site_eid.rtrs_in_rloc_set()
    if (rtrs_exist): 
        if (site_eid.is_rtr_in_rloc_set(xtr)): rtrs_exist = False
    #endif

    #
    # Build EID-record.
    #
    eid_record = lisp_eid_record()
    eid_record.record_ttl = 1440
    eid_record.eid.copy_address(site_eid.eid)
    eid_record.group.copy_address(site_eid.group)
    eid_record.rloc_count = 0
    for rloc_entry in site_eid.registered_rlocs: 
        if (rtrs_exist ^ rloc_entry.is_rtr()): continue
        eid_record.rloc_count += 1
    #endfor
    packet = eid_record.encode()

    #
    # Print contents of Map-Notify.
    #
    map_notify.print_notify()
    eid_record.print_record("  ", False)

    #
    # Build locator-set with only RTR RLOCs if they exist.
    #
    for rloc_entry in site_eid.registered_rlocs: 
        if (rtrs_exist ^ rloc_entry.is_rtr()): continue
        rloc_record = lisp_rloc_record()
        rloc_record.store_rloc_entry(rloc_entry)
        rloc_record.local_bit = True
        rloc_record.probe_bit = False
        rloc_record.reach_bit = True
        packet += rloc_record.encode()
        rloc_record.print_record("    ")
    #endfor

    #
    # Encode it.
    #
    packet = map_notify.encode(packet, "")
    if (packet == None): return

    #
    # Send Map-Notify to xTR.
    #
    lisp_send_map_notify(lisp_sockets, packet, xtr, LISP_CTRL_PORT)

    #
    # Set retransmit timer.
    #
    map_notify.retransmit_timer = threading.Timer(LISP_MAP_NOTIFY_INTERVAL, 
        lisp_retransmit_map_notify, [map_notify])
    map_notify.retransmit_timer.start()
    return
#enddef

#
# lisp_queue_multicast_map_notify
#
# This funciton will look for the ITRs in the local site cache.
#
def lisp_queue_multicast_map_notify(lisp_sockets, rle_list):
    null_group = lisp_address(LISP_AFI_NONE, "", 0, 0)

    for sg in rle_list:
        sg_site_eid = lisp_site_eid_lookup(sg[0], sg[1], True)
        if (sg_site_eid == None): continue

        #
        # (S,G) RLOC-set could be empty when last RLE goes away. We will have
        # to search all individual registrations searching for RTRs.
        #
        # We store in a dictonary array so we can remove duplicates.
        #
        sg_rloc_set = sg_site_eid.registered_rlocs
        if (len(sg_rloc_set) == 0):
            temp_set = {}
            for se in list(sg_site_eid.individual_registrations.values()):
                for rloc_entry in se.registered_rlocs:
                    if (rloc_entry.is_rtr() == False): continue
                    temp_set[rloc_entry.rloc.print_address()] = rloc_entry
                #endfor
            #endfor
            sg_rloc_set = list(temp_set.values())
        #endif
            
        #
        # If this is a (0.0.0.0/0, G) or a (0::/0, G), we send a Map-Notify
        # to all members (all RLOCs in the sg_rloc_set.
        #
        notify = []
        found_rtrs = False
        if (sg_site_eid.eid.address == 0 and sg_site_eid.eid.mask_len == 0):
            notify_str = []
            rle_nodes = []
            if (len(sg_rloc_set) != 0 and sg_rloc_set[0].rle != None):
                rle_nodes = sg_rloc_set[0].rle.rle_nodes
            #endif
            for rle_node in rle_nodes: 
                notify.append(rle_node.address)
                notify_str.append(rle_node.address.print_address_no_iid())
            #endfor
            lprint("Notify existing RLE-nodes {}".format(notify_str))
        else:

            #
            # If the (S,G) has an RTR registered, then we will send a 
            # Map-Notify to the RTR instead the ITRs of the source-site.
            #
            for rloc_entry in sg_rloc_set:
                if (rloc_entry.is_rtr()): notify.append(rloc_entry.rloc)
            #endfor

            #
            # If no RTRs were found, get ITRs from source-site.
            #
            found_rtrs = (len(notify) != 0)
            if (found_rtrs == False):
                site_eid = lisp_site_eid_lookup(sg[0], null_group, False)
                if (site_eid == None): continue

                for rloc_entry in site_eid.registered_rlocs:
                    if (rloc_entry.rloc.is_null()): continue
                    notify.append(rloc_entry.rloc)
                #endfor
            #endif

            #
            # No ITRs or RTRs fond.
            #
            if (len(notify) == 0):
                lprint("No ITRs or RTRs found for {}, Map-Notify suppressed". \
                    format(green(sg_site_eid.print_eid_tuple(), False)))
                continue
            #endif
        #endif

        #
        # Send multicast Map-Notify to either ITR-list or RTR-list.
        #
        for xtr in notify:
            lprint("Build Map-Notify to {}TR {} for {}".format("R" if \
                found_rtrs else "x", red(xtr.print_address_no_iid(), False), 
                green(sg_site_eid.print_eid_tuple(), False)))
            
            el = [sg_site_eid.print_eid_tuple()]
            lisp_send_multicast_map_notify(lisp_sockets, sg_site_eid, el, xtr)
            time.sleep(.001)
        #endfor
    #endfor
    return
#enddef

#
# lisp_find_sig_in_rloc_set
#
# Look for a "signature" key in a JSON RLOC-record. Return None, if not found.
# Return RLOC record if found.
#
def lisp_find_sig_in_rloc_set(packet, rloc_count):
    for i in range(rloc_count):
        rloc_record = lisp_rloc_record()
        packet = rloc_record.decode(packet, None)
        json_sig = rloc_record.json
        if (json_sig == None): continue

        try:
            json_sig = json.loads(json_sig.json_string)
        except:
            lprint("Found corrupted JSON signature")
            continue
        #endtry

        if ("signature" not in json_sig): continue
        return(rloc_record)
    #endfor
    return(None)
#enddef

#
# lisp_get_eid_hash
#
# From an EID, return EID hash value. Here is an example where all but the
# high-order byte is the EID hash for each hash-length:
#
# EID:      fd4f:5b9f:f67c:6dbd:3799:48e1:c6a2:9430
# EID-hash:   4f:5b9f:f67c:6dbd:3799:48e1:c6a2:9430  eid_hash_len = 120
# EID-hash:                6dbd:3799:48e1:c6a2:9430  eid_hash_len = 80
#
# Note when an eid-prefix in lisp_eid_hashes[] has an instance-id of -1, it
# means the eid-prefix is used for all EIDs from any instance-id.
#
# Returns a string with hex digits between colons and the hash length in bits.
# Returns None if the IPv6 EID is not a crypto-hash address. These addresses
# are not authenticated.
#
def lisp_get_eid_hash(eid):
    hash_mask_len = None
    for eid_prefix in lisp_eid_hashes:

        #
        # For wildcarding the instance-ID.
        #
        iid = eid_prefix.instance_id
        if (iid == -1): eid_prefix.instance_id = eid.instance_id

        ms = eid.is_more_specific(eid_prefix)
        eid_prefix.instance_id = iid
        if (ms): 
            hash_mask_len = 128 - eid_prefix.mask_len
            break
        #endif
    #endfor
    if (hash_mask_len == None): return(None)

    address = eid.address
    eid_hash = ""
    for i in range(0, old_div(hash_mask_len, 16)):
        addr = address & 0xffff
        addr = hex(addr)[2::]
        eid_hash = addr.zfill(4) + ":" + eid_hash
        address >>= 16
    #endfor
    if (hash_mask_len % 16 != 0): 
        addr = address & 0xff
        addr = hex(addr)[2::]
        eid_hash = addr.zfill(2) + ":" + eid_hash
    #endif
    return(eid_hash[0:-1])
#enddef

#
# lisp_lookup_public_key
#
# Given an EID, do a mapping system lookup for a distinguished-name EID
# 'hash-<cga-hash>' to obtain the public-key from an RLOC-record.
#
# Return [hash_id, pubkey, True/False]. Values can be of value None but last
# boolean argument is if the hash lookup was found.
#
def lisp_lookup_public_key(eid):
    iid = eid.instance_id

    #
    # Parse out CGA hash to do public-key lookup with instance-ID and hash
    # as a distinguished-name EID.
    #
    pubkey_hash = lisp_get_eid_hash(eid)
    if (pubkey_hash == None): return([None, None, False])

    pubkey_hash = "hash-" + pubkey_hash
    hash_eid = lisp_address(LISP_AFI_NAME, pubkey_hash, len(pubkey_hash), iid)
    group = lisp_address(LISP_AFI_NONE, "", 0, iid)

    #
    # Do lookup in local instance-ID.
    #
    site_eid = lisp_site_eid_lookup(hash_eid, group, True)
    if (site_eid == None): return([hash_eid, None, False])

    #
    # Look for JSON RLOC with key "public-key".
    #
    pubkey = None
    for rloc in site_eid.registered_rlocs:
        json_pubkey = rloc.json
        if (json_pubkey == None): continue
        try:
            json_pubkey = json.loads(json_pubkey.json_string)
        except:
            lprint("Registered RLOC JSON format is invalid for {}".format( \
                pubkey_hash))
            return([hash_eid, None, False])
        #endtry
        if ("public-key" not in json_pubkey): continue
        pubkey = json_pubkey["public-key"]
        break
    #endfor
    return([hash_eid, pubkey, True])
#enddef

#
# lisp_verify_cga_sig
#
# Verify signature of an IPv6 CGA-based EID if the public-key hash exists
# in the local mapping database (with same instance-ID).
#
def lisp_verify_cga_sig(eid, rloc_record):

    #
    # Use signature-eid if in JSON string. Otherwise, Crypto-EID is signature-
    # EID.
    #
    sig = json.loads(rloc_record.json.json_string)

    if (lisp_get_eid_hash(eid)):
        sig_eid = eid
    elif ("signature-eid" in sig):
        sig_eid_str = sig["signature-eid"]
        sig_eid = lisp_address(LISP_AFI_IPV6, sig_eid_str, 0, 0)
    else:
        lprint("  No signature-eid found in RLOC-record")
        return(False)
    #endif

    #
    # Lookup CGA hash in mapping datbase to get public-key.
    #
    hash_eid, pubkey, lookup_good = lisp_lookup_public_key(sig_eid)
    if (hash_eid == None):
        eid_str = green(sig_eid.print_address(), False)
        lprint("  Could not parse hash in EID {}".format(eid_str))
        return(False)
    #endif

    found = "found" if lookup_good else bold("not found", False)
    eid_str = green(hash_eid.print_address(), False)
    lprint("  Lookup for crypto-hashed EID {} {}".format(eid_str, found))
    if (lookup_good == False): return(False)

    if (pubkey == None):
        lprint("  RLOC-record with public-key not found")
        return(False)
    #endif

    pubkey_str = pubkey[0:8] + "..." + pubkey[-8::]
    lprint("  RLOC-record with public-key '{}' found".format(pubkey_str))

    #
    # Get signature from RLOC-record in a form to let key.verify() do its 
    # thing.
    #
    sig_str = sig["signature"]

    try:
        sig = binascii.a2b_base64(sig_str)
    except:
        lprint("  Incorrect padding in signature string")
        return(False)
    #endtry
        
    sig_len = len(sig)
    if (sig_len & 1):
        lprint("  Signature length is odd, length {}".format(sig_len))
        return(False)
    #endif

    #
    # The signature is over the following string: "[<iid>]<eid>".
    #
    sig_data = sig_eid.print_address()
 
    #
    # Verify signature of CGA and public-key.
    #
    pubkey = binascii.a2b_base64(pubkey)
    try:
        key = ecdsa.VerifyingKey.from_pem(pubkey)
    except:
        bad = bold("Bad public-key", False)
        lprint("  {}, not in PEM format".format(bad))
        return(False)
    #endtry

    #
    # The hashfunc must be supplied to get signature interoperability between
    # a Go signer an a Python verifier. The signature data must go through
    # a sha256 hash first. Python signer must use:
    #
    # ecdsa.SigningKey.sign(sig_data, hashfunc=hashlib.sha256)
    #
    # Note to use sha256 you need a curve of NIST256p.
    #
    try:
        good = key.verify(sig, sig_data.encode(), hashfunc=hashlib.sha256)
    except:
        lprint("  Signature library failed for signature data '{}'".format( \
            sig_data))
        lprint("  Signature used '{}'".format(sig_str))
        return(False)
    #endtry
    return(good)
#enddef

#
# lisp_remove_eid_from_map_notify_queue
#
# Check to see if any EIDs from the input list are in the Map-Notify 
# retransmission queue. If so, remove them. That is, pop the key from the 
# dictionary array. The key is the catentation of the xTR address and 
# map-notify nonce.
#
def lisp_remove_eid_from_map_notify_queue(eid_list):

    #
    # Determine from the supplied EID-list, if any EID is in any EID-list of
    # a queued Map-Notify.
    #
    keys_to_remove = []
    for eid_tuple in eid_list:
        for mn_key in lisp_map_notify_queue:
            map_notify = lisp_map_notify_queue[mn_key]
            if (eid_tuple not in map_notify.eid_list): continue

            keys_to_remove.append(mn_key)
            timer = map_notify.retransmit_timer
            if (timer): timer.cancel()

            lprint("Remove from Map-Notify queue nonce 0x{} for EID {}".\
                format(map_notify.nonce_key, green(eid_tuple, False)))
        #endfor
    #endfor

    #
    # Now remove keys that were determined to be removed.
    #
    for mn_key in keys_to_remove: lisp_map_notify_queue.pop(mn_key)
    return
#enddef

#
# lisp_decrypt_map_register
#
# Check if we should just return a non encrypted packet, or decrypt and return
# a plaintext Map-Register message.
#
def lisp_decrypt_map_register(packet):

    #
    # Parse first 4 bytes which is not encrypted. If packet is not encrypted,
    # return to caller. If it is encrypted, get 3-bit key-id next to e-bit.
    #
    header = socket.ntohl(struct.unpack("I", packet[0:4])[0])
    e_bit = (header >> 13) & 0x1
    if (e_bit == 0): return(packet)
    
    ekey_id = (header >> 14) & 0x7

    #
    # Use 16-byte key which is 32 string characters.
    #
    try:
        ekey = lisp_ms_encryption_keys[ekey_id]
        ekey = ekey.zfill(32)
        iv = "0" * 8
    except:
        lprint("Cannot decrypt Map-Register with key-id {}".format(ekey_id))
        return(None)
    #endtry

    d = bold("Decrypt", False)
    lprint("{} Map-Register with key-id {}".format(d, ekey_id))

    #
    # Use 20 rounds so we can interoperate with ct-lisp mobile platforms.
    #
    plaintext = chacha.ChaCha(ekey, iv, 20).decrypt(packet[4::])
    return(packet[0:4] + plaintext)
#enddef

#
# lisp_process_map_register
#
# Process received Map-Register message.
#
def lisp_process_map_register(lisp_sockets, packet, source, sport):
    global lisp_registered_count

    #
    # First check if we are expecting an encrypted Map-Register. This call
    # will either return a unencrypted packet, a decrypted packet, or None
    # if the key-id from the Map-Register is not registered.
    #
    packet = lisp_decrypt_map_register(packet)
    if (packet == None): return

    map_register = lisp_map_register()
    orig_packet, packet = map_register.decode(packet)
    if (packet == None):
        lprint("Could not decode Map-Register packet")
        return
    #endif
    map_register.sport = sport

    map_register.print_map_register()

    #
    # Verify that authentication parameters are consistent.
    #
    sha1_or_sha2 = True
    if (map_register.auth_len == LISP_SHA1_160_AUTH_DATA_LEN):
        sha1_or_sha2 = True
    #endif
    if (map_register.alg_id == LISP_SHA_256_128_ALG_ID):
        sha1_or_sha2 = False
    #endif

    #
    # For tracking which (S,G) RLEs have changed.
    #
    rle_list = []

    #
    # Process each EID record in Map-Register message.
    #
    site = None
    start_eid_records = packet
    eid_list = []
    record_count = map_register.record_count
    for i in range(record_count):
        eid_record = lisp_eid_record()
        rloc_record = lisp_rloc_record()
        packet = eid_record.decode(packet)
        if (packet == None):
            lprint("Could not decode EID-record in Map-Register packet")
            return
        #endif
        eid_record.print_record("  ", False)

        #
        # Lookup lisp_site entry.
        #
        site_eid = lisp_site_eid_lookup(eid_record.eid, eid_record.group, 
            False)

        match_str = site_eid.print_eid_tuple() if site_eid else None

        #
        # Allowing overlapping ams registered prefixes. Make sure we get the
        # configured parent entry and not the registered more-specific. This
        # registration could be a more-specific of the registered more-specific
        # entry.
        #
        if (site_eid and site_eid.accept_more_specifics == False):
            if (site_eid.eid_record_matches(eid_record) == False):
                parent = site_eid.parent_for_more_specifics
                if (parent): site_eid = parent
            #endif
        #endif

        #
        # Check if this is a new more-specific EID-prefix registration that
        # will match a static configured site-eid with "accept-more-specifics"
        # configured.
        #
        ams = (site_eid and site_eid.accept_more_specifics)
        if (ams):
            ms_site_eid = lisp_site_eid(site_eid.site)
            ms_site_eid.dynamic = True
            ms_site_eid.eid.copy_address(eid_record.eid)
            ms_site_eid.group.copy_address(eid_record.group)
            ms_site_eid.parent_for_more_specifics = site_eid
            ms_site_eid.add_cache()
            ms_site_eid.inherit_from_ams_parent()
            site_eid.more_specific_registrations.append(ms_site_eid)
            site_eid = ms_site_eid
        else:
            site_eid = lisp_site_eid_lookup(eid_record.eid, eid_record.group, 
                True)                                
        #endif

        eid_str = eid_record.print_eid_tuple()

        if (site_eid == None):
            notfound = bold("Site not found", False)
            lprint("  {} for EID {}{}".format(notfound, green(eid_str, False),
                ", matched non-ams {}".format(green(match_str, False) if \
                match_str else "")))

            #
            # Need to hop over RLOC-set so we can get to the next EID-record.
            #
            packet = rloc_record.end_of_rlocs(packet, eid_record.rloc_count)
            if (packet == None):
                lprint("  Could not decode RLOC-record in Map-Register packet")
                return
            #endif
            continue
        #endif

        site = site_eid.site

        if (ams):
            e = site_eid.parent_for_more_specifics.print_eid_tuple()
            lprint("  Found ams {} for site '{}' for registering prefix {}". \
                format(green(e, False), site.site_name, green(eid_str, False)))
        else:
            e = green(site_eid.print_eid_tuple(), False)
            lprint("  Found {} for site '{}' for registering prefix {}". \
                format(e, site.site_name, green(eid_str, False)))
        #endif

        #
        # Check if site configured in admin-shutdown mode.
        #
        if (site.shutdown):
            lprint(("  Rejecting registration for site '{}', configured in " +
                "admin-shutdown state").format(site.site_name))
            packet = rloc_record.end_of_rlocs(packet, eid_record.rloc_count)
            continue
        #endif

        #
        # Verify authentication before processing locator-set. Quick hack
        # while I figure out why sha1 and sha2 authentication is not working
        # from cisco. An NX-OS Map-Register will have a 0 nonce. We are going
        # to use this to bypass the authentication check.
        #
        key_id = map_register.key_id
        if (key_id in site.auth_key):
            password = site.auth_key[key_id]
        else:
            password = ""
        #endif

        auth_good = lisp_verify_auth(orig_packet, map_register.alg_id, 
            map_register.auth_data, password)
        dynamic = "dynamic " if site_eid.dynamic else ""

        passfail = bold("passed" if auth_good else "failed", False)
        key_id = "key-id {}".format(key_id) if key_id == map_register.key_id \
            else "bad key-id {}".format(map_register.key_id)
        lprint("  Authentication {} for {}EID-prefix {}, {}".format( \
            passfail, dynamic, green(eid_str, False), key_id))

        #
        # If the IPv6 EID is a CGA, verify signature if it exists in an
        # RLOC-record.
        #
        cga_good = True
        is_crypto_eid = (lisp_get_eid_hash(eid_record.eid) != None)
        if (is_crypto_eid or site_eid.require_signature):
            required = "Required " if site_eid.require_signature else ""
            eid_str = green(eid_str, False)
            rloc = lisp_find_sig_in_rloc_set(packet, eid_record.rloc_count)
            if (rloc == None):
                cga_good = False
                lprint(("  {}EID-crypto-hash signature verification {} " + \
                    "for EID-prefix {}, no signature found").format(required,
                    bold("failed", False), eid_str))
            else:
                cga_good = lisp_verify_cga_sig(eid_record.eid, rloc)
                passfail = bold("passed" if cga_good else "failed", False)
                lprint(("  {}EID-crypto-hash signature verification {} " + \
                    "for EID-prefix {}").format(required, passfail, eid_str))
            #endif
        #endif

        if (auth_good == False or cga_good == False):
            packet = rloc_record.end_of_rlocs(packet, eid_record.rloc_count)
            if (packet == None):
                lprint("  Could not decode RLOC-record in Map-Register packet")
                return
            #endif
            continue
        #endif

        #
        # If merge being requested get individual site-eid. If not, and what
        # was cached had merge bit set, set flag to issue error.
        #
        if (map_register.merge_register_requested): 
            parent = site_eid
            parent.inconsistent_registration = False
            
            #
            # Clear out all registrations, there is a new site-id registering.
            # Or there can be multiple sites registering for a multicast (S,G).
            #
            if (site_eid.group.is_null()):
                if (parent.site_id != map_register.site_id):
                    parent.site_id = map_register.site_id
                    parent.registered = False
                    parent.individual_registrations = {}
                    parent.registered_rlocs = []
                    lisp_registered_count -= 1
                #endif
            #endif

            key = map_register.xtr_id
            if (key in site_eid.individual_registrations):
                site_eid = site_eid.individual_registrations[key]
            else:
                site_eid = lisp_site_eid(site)
                site_eid.eid.copy_address(parent.eid)
                site_eid.group.copy_address(parent.group)
                site_eid.encrypt_json = parent.encrypt_json
                parent.individual_registrations[key] = site_eid
            #endif
        else:
            site_eid.inconsistent_registration = \
                site_eid.merge_register_requested
        #endif

        site_eid.map_registers_received += 1

        #
        # If TTL is 0, unregister entry if source of Map-Reqister is in the
        # list of currently registered RLOCs.
        #
        bad = (site_eid.is_rloc_in_rloc_set(source) == False)
        if (eid_record.record_ttl == 0 and bad):
            lprint("  Ignore deregistration request from {}".format( \
                red(source.print_address_no_iid(), False)))
            continue
        #endif

        # 
        # Clear out previously stored RLOCs. Put new ones in if validated
        # against configured ones.
        #
        previous_rlocs = site_eid.registered_rlocs
        site_eid.registered_rlocs = []

        #
        # Process each RLOC record in EID record.
        #
        start_rloc_records = packet
        for j in range(eid_record.rloc_count):
            rloc_record = lisp_rloc_record()
            packet = rloc_record.decode(packet, None, site_eid.encrypt_json)
            if (packet == None):
                lprint("  Could not decode RLOC-record in Map-Register packet")
                return
            #endif
            rloc_record.print_record("    ")

            #
            # Run RLOC in Map-Register against configured RLOC policies.
            #
            if (len(site.allowed_rlocs) > 0):
                addr_str = rloc_record.rloc.print_address()
                if (addr_str not in site.allowed_rlocs):
                    lprint(("  Reject registration, RLOC {} not " + \
                        "configured in allowed RLOC-set").format( \
                        red(addr_str, False)))
                    site_eid.registered = False
                    packet = rloc_record.end_of_rlocs(packet, 
                        eid_record.rloc_count - j - 1)
                    break
                #endif
            #endif

            #
            # RLOC validated good. Otherwise, go to next EID record
            #
            rloc = lisp_rloc()
            rloc.store_rloc_from_record(rloc_record, None, source)

            #
            # If the source of the Map-Register is in the locator-set, then
            # store if it wants Map-Notify messages when a new locator-set
            # is registered later.
            #
            if (source.is_exact_match(rloc.rloc)):
                rloc.map_notify_requested = map_register.map_notify_requested
            #endif

            #
            # Add to RLOC set for site-eid.
            #
            site_eid.registered_rlocs.append(rloc)
        #endfor

        changed_rloc_set = \
            (site_eid.do_rloc_sets_match(previous_rlocs) == False)

        #
        # Do not replace RLOCs if the Map-Register is a refresh and the 
        # locator-set is different.
        #
        if (map_register.map_register_refresh and changed_rloc_set and 
            site_eid.registered):
            lprint("  Reject registration, refreshes cannot change RLOC-set")
            site_eid.registered_rlocs = previous_rlocs
            continue
        #endif

        #
        # Copy fields from packet into internal data structure. First set
        # site EID specific state.
        #
        if (site_eid.registered == False):
            site_eid.first_registered = lisp_get_timestamp()
            lisp_registered_count += 1
        #endif
        site_eid.last_registered = lisp_get_timestamp()
        site_eid.registered = (eid_record.record_ttl != 0)
        site_eid.last_registerer = source

        #
        # Now set site specific state.
        #
        site_eid.auth_sha1_or_sha2 = sha1_or_sha2
        site_eid.proxy_reply_requested = map_register.proxy_reply_requested
        site_eid.lisp_sec_present = map_register.lisp_sec_present
        site_eid.map_notify_requested = map_register.map_notify_requested
        site_eid.mobile_node_requested = map_register.mobile_node
        site_eid.merge_register_requested = \
            map_register.merge_register_requested
        site_eid.use_register_ttl_requested = map_register.use_ttl_for_timeout
        if (site_eid.use_register_ttl_requested):
            site_eid.register_ttl = eid_record.store_ttl()
        else:
            site_eid.register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
        #endif
        site_eid.xtr_id_present = map_register.xtr_id_present
        if (site_eid.xtr_id_present):
            site_eid.xtr_id = map_register.xtr_id
            site_eid.site_id = map_register.site_id
        #endif

        #
        # If merge requested, do it now for this EID-prefix.
        #
        if (map_register.merge_register_requested):
            if (parent.merge_in_site_eid(site_eid)):
                rle_list.append([eid_record.eid, eid_record.group])
            #endif
            if (map_register.map_notify_requested):
                lisp_send_merged_map_notify(lisp_sockets, parent, map_register,
                    eid_record)
            #endif
        #endif

        if (changed_rloc_set == False): continue
        if (len(rle_list) != 0): continue

        eid_list.append(site_eid.print_eid_tuple())

        #
        # Send Map-Notify if the RLOC-set changed for thie site-eid. Send it
        # to the previously registered RLOCs only if they requested it. Do
        # not consider RLOC-sets with RLEs in them because at the end of
        # the EID-record loop, we'll send a multicast Map-Notify.
        #
        peid_record = copy.deepcopy(eid_record)
        eid_record = eid_record.encode()
        eid_record += start_rloc_records
        el = [site_eid.print_eid_tuple()]
        lprint("    Changed RLOC-set, Map-Notifying old RLOC-set")

        for rloc in previous_rlocs:
            if (rloc.map_notify_requested == False): continue
            if (rloc.rloc.is_exact_match(source)): continue
            lisp_build_map_notify(lisp_sockets, eid_record, el, 1, rloc.rloc, 
                LISP_CTRL_PORT, map_register.nonce, map_register.key_id,
                map_register.alg_id, map_register.auth_len, site, False)
        #endfor

        #
        # Check subscribers.
        #
        lisp_notify_subscribers(lisp_sockets, peid_record, start_rloc_records,
            site_eid.eid, site)
    #endfor

    #
    # Send Map-Noitfy to ITRs if any (S,G) RLE has changed.
    #
    if (len(rle_list) != 0): 
        lisp_queue_multicast_map_notify(lisp_sockets, rle_list)
    #endif

    #
    # The merged Map-Notify will serve as a Map-Register ack. So don't need
    # to send another one below.
    #
    if (map_register.merge_register_requested): return

    #
    # Should we ack the Map-Register? Only if the Want-Map-Notify bit was set
    # by the registerer.
    #
    if (map_register.map_notify_requested and site != None):
        lisp_build_map_notify(lisp_sockets, start_eid_records, eid_list,
            map_register.record_count, source, sport, map_register.nonce,
            map_register.key_id, map_register.alg_id, map_register.auth_len, 
            site, True)
    #endif
    return
#enddef

#
# lisp_process_unicast_map_notify
#
# Have ITR process a Map-Notify as a result of sending a subscribe-request.
# Update map-cache entry with new RLOC-set.
#
def lisp_process_unicast_map_notify(lisp_sockets, packet, source):
    map_notify = lisp_map_notify("")
    packet = map_notify.decode(packet)
    if (packet == None):
        lprint("Could not decode Map-Notify packet")
        return
    #endif

    map_notify.print_notify()
    if (map_notify.record_count == 0): return

    eid_records = map_notify.eid_records

    for i in range(map_notify.record_count):
        eid_record = lisp_eid_record()
        eid_records = eid_record.decode(eid_records)
        if (packet == None): return
        eid_record.print_record("  ", False)
        eid_str = eid_record.print_eid_tuple()

        #
        # If no map-cache entry exists or does not have action LISP_SEND_
        # PUBSUB_ACTION, ignore.
        #
        mc = lisp_map_cache_lookup(eid_record.eid, eid_record.eid)
        if (mc == None):
            e = green(eid_str, False)
            lprint("Ignoring Map-Notify EID {}, no subscribe-request entry". \
                format(e))
            continue
        #endif

        #
        # Check if map-cache entry is configured subscribe-request entry.
        # Otherwise, it is an entry created from the subscribe-request entry
        # from a returned Map-Notify.
        #
        if (mc.action != LISP_SEND_PUBSUB_ACTION):
            if (mc.subscribed_eid == None):
                e = green(eid_str, False)
                lprint("Ignoring Map-Notify for non-subscribed EID {}". \
                    format(e))
                continue
            #endif
        #endif

        #
        # Check if this is the map-cache entry for the EID or the SEND_PUBSUB
        # configured map-cache entry. Reuse the memory if the EID entry exists
        # and empty RLOC-set since we will rebuild it.
        #
        old_rloc_set = []
        if (mc.action == LISP_SEND_PUBSUB_ACTION):
            mc = lisp_mapping(eid_record.eid, eid_record.group, [])
            mc.add_cache()
            subscribed_eid = copy.deepcopy(eid_record.eid)
            subscribed_group = copy.deepcopy(eid_record.group)
        else:
            subscribed_eid = mc.subscribed_eid
            subscribed_group = mc.subscribed_group
            old_rloc_set = mc.rloc_set
            mc.delete_rlocs_from_rloc_probe_list()
            mc.rloc_set = []
        #endif

        #
        # Store some data from the EID-record of the Map-Notify.
        #
        mc.mapping_source = None if source == "lisp-itr" else source
        mc.map_cache_ttl = eid_record.store_ttl()
        mc.subscribed_eid = subscribed_eid
        mc.subscribed_group = subscribed_group

        #
        # If no RLOCs in the Map-Notify and we had RLOCs in the existing
        # map-cache entry, remove them.
        #
        if (len(old_rloc_set) != 0 and eid_record.rloc_count == 0):
            mc.build_best_rloc_set()
            lisp_write_ipc_map_cache(True, mc)
            lprint("Update {} map-cache entry with no RLOC-set".format( \
                green(eid_str, False)))
            continue
        #endif

        #
        # Now add all RLOCs to a new RLOC-set. If the RLOC existed in old set,
        # copy old RLOC data. We want to retain, uptimes, stats, and RLOC-
        # probe data in the new entry with the same RLOC address.
        #
        new = replaced = 0
        for j in range(eid_record.rloc_count):
            rloc_record = lisp_rloc_record()
            eid_records = rloc_record.decode(eid_records, None)
            rloc_record.print_record("    ")

            #
            # See if this RLOC address is in old RLOC-set, if so, do copy.
            #
            found = False
            for r in old_rloc_set:
                if (r.rloc.is_exact_match(rloc_record.rloc)):
                    found = True
                    break
                #endif
            #endfor
            if (found):
                rloc = copy.deepcopy(r)
                replaced += 1
            else:
                rloc = lisp_rloc()
                new += 1
            #endif

            #
            # Move data from RLOC-record of Map-Notify to RLOC entry.
            #
            rloc.store_rloc_from_record(rloc_record, None, mc.mapping_source)
            mc.rloc_set.append(rloc)
        #endfor

        lprint("Update {} map-cache entry with {}/{} new/replaced RLOCs".\
            format(green(eid_str, False), new, replaced))

        #
        # Build best RLOC-set and write to external data-plane, if any.
        #
        mc.build_best_rloc_set()
        lisp_write_ipc_map_cache(True, mc)
    #endfor

    #
    # Find map-server data structure from source address of Map-Notify then
    # send Map-Notify-Ack to it.
    #
    ms = lisp_get_map_server(source)
    if (ms == None):
        lprint("Cannot find Map-Server for Map-Notify source address {}".\
            format(source.print_address_no_iid()))
        return
    #endif
    lisp_send_map_notify_ack(lisp_sockets, eid_records, map_notify, ms)
#enddef

#
# lisp_process_multicast_map_notify
#
# Have the ITR process receive a multicast Map-Notify message. We will update
# the map-cache with a new RLE for the (S,G) entry. We do not have to 
# authenticate the Map-Notify or send a Map-Notify-Ack since the lisp-etr
# process as already done so.
#
def lisp_process_multicast_map_notify(packet, source):
    map_notify = lisp_map_notify("")
    packet = map_notify.decode(packet)
    if (packet == None):
        lprint("Could not decode Map-Notify packet")
        return
    #endif

    map_notify.print_notify()
    if (map_notify.record_count == 0): return

    eid_records = map_notify.eid_records

    for i in range(map_notify.record_count):
        eid_record = lisp_eid_record()
        eid_records = eid_record.decode(eid_records)
        if (packet == None): return
        eid_record.print_record("  ", False)

        #
        # Get or create map-cache entry for (S,G).
        #
        mc = lisp_map_cache_lookup(eid_record.eid, eid_record.group)
        if (mc == None):
            allow, x, y = lisp_allow_gleaning(eid_record.eid, eid_record.group,
                None)
            if (allow == False): continue

            mc = lisp_mapping(eid_record.eid, eid_record.group, [])
            mc.add_cache()
        #endif

        #
        # Gleaned map-cache entries always override what is regitered in
        # the mapping system. Since the mapping system RLE entries are RTRs
        # and RTRs store gleaned mappings for group members.
        #
        if (mc.gleaned):
            lprint("Ignore Map-Notify for gleaned {}".format( \
                green(mc.print_eid_tuple(), False)))
            continue
        #endif

        mc.mapping_source = None if source == "lisp-etr" else source
        mc.map_cache_ttl = eid_record.store_ttl()

        #
        # If no RLOCs in the Map-Notify and we had RLOCs in the existing
        # map-cache entry, remove them.
        #
        if (len(mc.rloc_set) != 0 and eid_record.rloc_count == 0):
            mc.rloc_set = []
            mc.build_best_rloc_set()
            lisp_write_ipc_map_cache(True, mc)
            lprint("Update {} map-cache entry with no RLOC-set".format( \
                green(mc.print_eid_tuple(), False)))
            continue
        #endif

        rtr_mc = mc.rtrs_in_rloc_set()

        #
        # If there are RTRs in the RLOC set for an existing map-cache entry,
        # only put RTR RLOCs from the Map-Notify in the map-cache.
        #
        for j in range(eid_record.rloc_count):
            rloc_record = lisp_rloc_record()
            eid_records = rloc_record.decode(eid_records, None)
            rloc_record.print_record("    ")
            if (eid_record.group.is_null()): continue
            if (rloc_record.rle == None): continue

            #
            # Get copy of stats from old stored record so the display can
            # look continuous even though the physical pointer is changing.
            #
            stats = mc.rloc_set[0].stats if len(mc.rloc_set) != 0 else None

            #
            # Store in map-cache.
            #
            rloc = lisp_rloc()
            rloc.store_rloc_from_record(rloc_record, None, mc.mapping_source)
            if (stats != None): rloc.stats = copy.deepcopy(stats)

            if (rtr_mc and rloc.is_rtr() == False): continue
                
            mc.rloc_set = [rloc]
            mc.build_best_rloc_set()
            lisp_write_ipc_map_cache(True, mc)

            lprint("Update {} map-cache entry with RLE {}".format( \
                green(mc.print_eid_tuple(), False),
                rloc.rle.print_rle(False, True)))
        #endfor
    #endfor
    return
#enddef

#
# lisp_process_map_notify
#
# Process Map-Notify message. All that needs to be done is to validate it with
# the Map-Server that sent it and return a Map-Notify-Ack.
#
def lisp_process_map_notify(lisp_sockets, orig_packet, source):
    map_notify = lisp_map_notify("")
    packet = map_notify.decode(orig_packet)
    if (packet == None):
        lprint("Could not decode Map-Notify packet")
        return
    #endif

    map_notify.print_notify()

    #
    # Get map-server so we can do statistics and find auth-key, if a auth-key
    # was provided in a Map-Notify message.
    #
    s = source.print_address()
    if (map_notify.alg_id != 0 or map_notify.auth_len != 0):
        ms = None
        for key in lisp_map_servers_list:
            if (key.find(s) == -1): continue
            ms = lisp_map_servers_list[key]
        #endfor
        if (ms == None):
            lprint(("  Could not find Map-Server {} to authenticate " + \
                "Map-Notify").format(s))
            return
        #endif
    
        ms.map_notifies_received += 1
    
        auth_good = lisp_verify_auth(packet, map_notify.alg_id, 
            map_notify.auth_data, ms.password)
    
        lprint("  Authentication {} for Map-Notify".format("succeeded" if \
            auth_good else "failed"))
        if (auth_good == False): return
    else:
        ms = lisp_ms(s, None, "", 0, "", False, False, False, False, 0, 0, 0,
            None)
    #endif

    #
    # Send out Map-Notify-Ack. Skip over packet so lisp_send_map_notify()
    # starts the packet with EID-records.
    #
    eid_records = map_notify.eid_records
    if (map_notify.record_count == 0): 
        lisp_send_map_notify_ack(lisp_sockets, eid_records, map_notify, ms)
        return
    #endif

    #
    # If this is a Map-Notify for an (S,G) entry, send the message to the
    # lisp-itr process so it can update its map-cache for an active source
    # in this site. There is probably a RLE change that the ITR needs to know
    # about.
    #
    eid_record = lisp_eid_record()
    packet = eid_record.decode(eid_records)
    if (packet == None): return

    eid_record.print_record("  ", False)

    for j in range(eid_record.rloc_count):
        rloc_record = lisp_rloc_record()
        packet = rloc_record.decode(packet, None)
        if (packet == None):
            lprint("  Could not decode RLOC-record in Map-Notify packet")
            return
        #endif
        rloc_record.print_record("    ")
    #endfor

    #
    # Right now, don't do anything with non-multicast EID records.
    #
    if (eid_record.group.is_null() == False): 

        #
        # Forward to lisp-itr process via the lisp-core process so multicast
        # Map-Notify messages are processed by the ITR process.
        #
        lprint("Send {} Map-Notify IPC message to ITR process".format( \
            green(eid_record.print_eid_tuple(), False)))

        ipc = lisp_control_packet_ipc(orig_packet, s, "lisp-itr", 0)
        lisp_ipc(ipc, lisp_sockets[2], "lisp-core-pkt")
    #endif

    #
    # Send Map-Notify-Ack after processing contents of Map-Notify.
    #
    lisp_send_map_notify_ack(lisp_sockets, eid_records, map_notify, ms)
    return
#enddef

#
# lisp_process_map_notify_ack
#
# Process received Map-Notify-Ack. This causes the Map-Notify to be removed
# from the lisp_map_notify_queue{}.
#
def lisp_process_map_notify_ack(packet, source):
    map_notify = lisp_map_notify("")
    packet = map_notify.decode(packet)
    if (packet == None):
        lprint("Could not decode Map-Notify-Ack packet")
        return
    #endif

    map_notify.print_notify()

    #
    # Get an EID-prefix out of the Map-Notify-Ack so we can find the site
    # associated with it.
    #
    if (map_notify.record_count < 1):
        lprint("No EID-prefix found, cannot authenticate Map-Notify-Ack")
        return
    #endif

    eid_record = lisp_eid_record()

    if (eid_record.decode(map_notify.eid_records) == None):
        lprint("Could not decode EID-record, cannot authenticate " + 
            "Map-Notify-Ack")
        return
    #endof
    eid_record.print_record("  ", False)

    eid_str = eid_record.print_eid_tuple()

    #
    # Find site associated with EID-prefix from first record.
    #
    if (map_notify.alg_id != LISP_NONE_ALG_ID and map_notify.auth_len != 0):
        site_eid = lisp_sites_by_eid.lookup_cache(eid_record.eid, True)
        if (site_eid == None):
            notfound = bold("Site not found", False)
            lprint(("{} for EID {}, cannot authenticate Map-Notify-Ack"). \
                format(notfound, green(eid_str, False)))
            return
        #endif
        site = site_eid.site

        #
        # Count it.
        #
        site.map_notify_acks_received += 1

        key_id = map_notify.key_id
        if (key_id in site.auth_key):
            password = site.auth_key[key_id]
        else:
            password = ""
        #endif

        auth_good = lisp_verify_auth(packet, map_notify.alg_id, 
            map_notify.auth_data, password)

        key_id = "key-id {}".format(key_id) if key_id == map_notify.key_id \
            else "bad key-id {}".format(map_notify.key_id)

        lprint("  Authentication {} for Map-Notify-Ack, {}".format( \
            "succeeded" if auth_good else "failed", key_id))
        if (auth_good == False): return
    #endif

    #
    # Remove Map-Notify from retransmission queue.
    #
    if (map_notify.retransmit_timer): map_notify.retransmit_timer.cancel()

    etr = source.print_address()
    key = map_notify.nonce_key

    if (key in lisp_map_notify_queue):
        map_notify = lisp_map_notify_queue.pop(key)
        if (map_notify.retransmit_timer): map_notify.retransmit_timer.cancel()
        lprint("Dequeue Map-Notify from retransmit queue, key is: {}". \
            format(key))
    else:
        lprint("Map-Notify with nonce 0x{} queue entry not found for {}". \
            format(map_notify.nonce_key, red(etr, False)))
    #endif
    return
#enddef

#
# lisp_map_referral_loop
#
# Check to see if arrived Map-Referral EID-prefix is more-specific than the
# last one we received.
#
def lisp_map_referral_loop(mr, eid, group, action, s):
    if (action not in (LISP_DDT_ACTION_NODE_REFERRAL, 
        LISP_DDT_ACTION_MS_REFERRAL)): return(False)

    if (mr.last_cached_prefix[0] == None): return(False)

    #
    # Check group first, if any. Then EID-prefix as source if (S,G).
    #
    loop = False
    if (group.is_null() == False):
        loop = mr.last_cached_prefix[1].is_more_specific(group)
    #endif
    if (loop == False):
        loop = mr.last_cached_prefix[0].is_more_specific(eid)
    #endif

    if (loop):
        prefix_str = lisp_print_eid_tuple(eid, group)
        cached_str = lisp_print_eid_tuple(mr.last_cached_prefix[0],
            mr.last_cached_prefix[1])

        lprint(("Map-Referral prefix {} from {} is not more-specific " + \
            "than cached prefix {}").format(green(prefix_str, False), s, 
            cached_str))
    #endif
    return(loop)
#enddef

#
# lisp_process_map_referral
#
# This function processes a Map-Referral message by a Map-Resolver.
#
def lisp_process_map_referral(lisp_sockets, packet, source):

    map_referral = lisp_map_referral()
    packet = map_referral.decode(packet)
    if (packet == None):
        lprint("Could not decode Map-Referral packet")
        return
    #endif
    map_referral.print_map_referral()

    s = source.print_address()
    nonce = map_referral.nonce

    #
    # Process each EID record in Map-Reply message.
    #
    for i in range(map_referral.record_count):
        eid_record = lisp_eid_record()
        packet = eid_record.decode(packet)
        if (packet == None):
            lprint("Could not decode EID-record in Map-Referral packet")
            return
        #endif
        eid_record.print_record("  ", True)

        #
        # Check if we have an outstanding request for this Map-Referral reply.
        #
        key = str(nonce)
        if (key not in lisp_ddt_map_requestQ):
            lprint(("Map-Referral nonce 0x{} from {} not found in " + \
                "Map-Request queue, EID-record ignored").format( \
                lisp_hex_string(nonce), s))
            continue
        #endif
        mr = lisp_ddt_map_requestQ[key]
        if (mr == None):
            lprint(("No Map-Request queue entry found for Map-Referral " +
                "nonce 0x{} from {}, EID-record ignored").format( \
                lisp_hex_string(nonce), s))
            continue
        #endif

        #
        # Check for Map-Referral looping. If there is no loop cache the EID
        # returned from the Map-Referral in the Map-Request queue entry.
        #
        if (lisp_map_referral_loop(mr, eid_record.eid, eid_record.group,
            eid_record.action, s)): 
            mr.dequeue_map_request()
            continue
        #endif

        mr.last_cached_prefix[0] = eid_record.eid
        mr.last_cached_prefix[1] = eid_record.group

        #
        # Lookup referral in referral-cache.
        #
        add_or_replace = False
        referral = lisp_referral_cache_lookup(eid_record.eid, eid_record.group,
            True)
        if (referral == None): 
            add_or_replace = True
            referral = lisp_referral()
            referral.eid = eid_record.eid
            referral.group = eid_record.group
            if (eid_record.ddt_incomplete == False): referral.add_cache()
        elif (referral.referral_source.not_set()):
            lprint("Do not replace static referral entry {}".format( \
                green(referral.print_eid_tuple(), False)))
            mr.dequeue_map_request()
            continue
        #endif

        action = eid_record.action
        referral.referral_source = source
        referral.referral_type = action
        ttl = eid_record.store_ttl()
        referral.referral_ttl = ttl
        referral.expires = lisp_set_timestamp(ttl)

        # 
        # Mark locator up if the Map-Referral source is in the referral-set.
        #
        negative = referral.is_referral_negative()
        if (s in referral.referral_set):
            ref_node = referral.referral_set[s]

            if (ref_node.updown == False and negative == False):
                ref_node.updown = True
                lprint("Change up/down status for referral-node {} to up". \
                    format(s))
            elif (ref_node.updown == True and negative == True):
                ref_node.updown = False
                lprint(("Change up/down status for referral-node {} " + \
                    "to down, received negative referral").format(s))
            #endif
        #endif

        #
        # Set dirty-bit so we can remove referral-nodes from cached entry
        # that wasn't in packet.
        #
        dirty_set = {}
        for key in referral.referral_set: dirty_set[key] = None

        #
        # Process each referral RLOC-record in EID record.
        #
        for i in range(eid_record.rloc_count):
            rloc_record = lisp_rloc_record()
            packet = rloc_record.decode(packet, None)
            if (packet == None):
                lprint("Could not decode RLOC-record in Map-Referral packet")
                return
            #endif
            rloc_record.print_record("    ")

            #
            # Copy over existing referral-node
            #
            addr_str = rloc_record.rloc.print_address()
            if (addr_str not in referral.referral_set):
                ref_node = lisp_referral_node()
                ref_node.referral_address.copy_address(rloc_record.rloc)
                referral.referral_set[addr_str] = ref_node
                if (s == addr_str and negative): ref_node.updown = False
            else:
                ref_node = referral.referral_set[addr_str]
                if (addr_str in dirty_set): dirty_set.pop(addr_str)
            #endif
            ref_node.priority = rloc_record.priority
            ref_node.weight = rloc_record.weight
        #endfor
            
        #
        # Now remove dirty referral-node entries.
        #
        for key in dirty_set: referral.referral_set.pop(key)

        eid_str = referral.print_eid_tuple()

        if (add_or_replace):
            if (eid_record.ddt_incomplete):
                lprint("Suppress add {} to referral-cache".format( \
                    green(eid_str, False)))
            else:
                lprint("Add {}, referral-count {} to referral-cache".format( \
                    green(eid_str, False), eid_record.rloc_count))
            #endif
        else:
            lprint("Replace {}, referral-count: {} in referral-cache".format( \
                green(eid_str, False), eid_record.rloc_count))
        #endif

        #
        # Process actions.
        #
        if (action == LISP_DDT_ACTION_DELEGATION_HOLE):
            lisp_send_negative_map_reply(mr.lisp_sockets, referral.eid, 
                referral.group, mr.nonce, mr.itr, mr.sport, 15, None, False)
            mr.dequeue_map_request()
        #endif            

        if (action == LISP_DDT_ACTION_NOT_AUTH):
            if (mr.tried_root):
                lisp_send_negative_map_reply(mr.lisp_sockets, referral.eid, 
                    referral.group, mr.nonce, mr.itr, mr.sport, 0, None, False)
                mr.dequeue_map_request()
            else:
                lisp_send_ddt_map_request(mr, True)
            #endif
        #endif            
        
        if (action == LISP_DDT_ACTION_MS_NOT_REG):
            if (s in referral.referral_set):
                ref_node = referral.referral_set[s]
                ref_node.updown = False
            #endif
            if (len(referral.referral_set) == 0):
                mr.dequeue_map_request()
            else:
                lisp_send_ddt_map_request(mr, False)
            #endif
        #endif            

        if (action in (LISP_DDT_ACTION_NODE_REFERRAL, 
            LISP_DDT_ACTION_MS_REFERRAL)):
            if (mr.eid.is_exact_match(eid_record.eid)):
                if (not mr.tried_root):
                    lisp_send_ddt_map_request(mr, True)
                else:
                    lisp_send_negative_map_reply(mr.lisp_sockets, 
                        referral.eid, referral.group, mr.nonce, mr.itr, 
                        mr.sport, 15, None, False)
                    mr.dequeue_map_request()
                #endif
            else:
                lisp_send_ddt_map_request(mr, False)
            #endif
        #endif

        if (action == LISP_DDT_ACTION_MS_ACK): mr.dequeue_map_request()
    #endfor
    return
#enddef

#
# lisp_process_ecm
#
# Process a received Encapsulated-Control-Message. It is assumed for right now
# that all ECMs have a Map-Request embedded.
# 
def lisp_process_ecm(lisp_sockets, packet, source, ecm_port):
    ecm = lisp_ecm(0)
    packet = ecm.decode(packet)
    if (packet == None):
        lprint("Could not decode ECM packet")
        return
    #endif

    ecm.print_ecm()

    header = lisp_control_header()
    if (header.decode(packet) == None):
        lprint("Could not decode control header")
        return
    #endif
        
    packet_type = header.type
    del(header)

    if (packet_type != LISP_MAP_REQUEST): 
        lprint("Received ECM without Map-Request inside")
        return
    #endif

    #
    # Process Map-Request.
    #
    mr_port = ecm.udp_sport
    timestamp = time.time()
    lisp_process_map_request(lisp_sockets, packet, source, ecm_port, 
        ecm.source, mr_port, ecm.ddt, -1, timestamp)
    return
#enddef

#------------------------------------------------------------------------------

#
# lisp_send_map_register
#
# Compute authenticaiton for Map-Register message and sent to supplied 
# Map-Server.
#
def lisp_send_map_register(lisp_sockets, packet, map_register, ms):

    #
    # If we are doing LISP-Decent and have a multicast group configured as
    # a Map-Server, we can't join the group by using the group so we have to
    # send to the loopback address to bootstrap our membership. We join to
    # one other member of the peer-group so we can get the group membership.
    #
    dest = ms.map_server
    if (lisp_decent_push_configured and dest.is_multicast_address() and
        (ms.map_registers_multicast_sent == 1 or ms.map_registers_sent == 1)):
        dest = copy.deepcopy(dest)
        dest.address = 0x7f000001
        b = bold("Bootstrap", False)
        g = ms.map_server.print_address_no_iid()
        lprint("{} mapping system for peer-group {}".format(b, g))
    #endif

    #
    # Modify authentication hash in Map-Register message if supplied when
    # lisp_map_register() was called.
    #
    packet = lisp_compute_auth(packet, map_register, ms.password)

    #
    # Should we encrypt the Map-Register? Use 16-byte key which is
    # 32 string characters. Use 20 rounds so the decrypter can interoperate
    # with ct-lisp mobile platforms.
    #
    if (ms.ekey != None):
        ekey = ms.ekey.zfill(32)
        iv = "0" * 8
        ciphertext = chacha.ChaCha(ekey, iv, 20).encrypt(packet[4::])
        packet = packet[0:4] + ciphertext
        e = bold("Encrypt", False)
        lprint("{} Map-Register with key-id {}".format(e, ms.ekey_id))
    #endif

    decent = ""
    if (lisp_decent_pull_xtr_configured()):
        decent = ", decent-index {}".format(bold(ms.dns_name, False))
    #endif        

    lprint("Send Map-Register to map-server {}{}{}".format( \
        dest.print_address(), ", ms-name '{}'".format(ms.ms_name), decent))
    lisp_send(lisp_sockets, dest, LISP_CTRL_PORT, packet)
    return
#enddef

#
# lisp_send_ipc_to_core
#
# Send LISP control packet that is to be source from UDP port 4342 to the
# lisp-core process.
#
def lisp_send_ipc_to_core(lisp_socket, packet, dest, port):
    source = lisp_socket.getsockname()
    dest = dest.print_address_no_iid()

    lprint("Send IPC {} bytes to {} {}, control-packet: {}".format( \
        len(packet), dest, port, lisp_format_packet(packet)))

    packet = lisp_control_packet_ipc(packet, source, dest, port)
    lisp_ipc(packet, lisp_socket, "lisp-core-pkt")
    return
#enddef

#
# lisp_send_map_reply
#
# Send Map-Reply message to supplied destination. Note the destination must
# be routable in RLOC space.
#
def lisp_send_map_reply(lisp_sockets, packet, dest, port):
    lprint("Send Map-Reply to {}".format(dest.print_address_no_iid()))
    lisp_send_ipc_to_core(lisp_sockets[2], packet, dest, port)
    return
#enddef

#
# lisp_send_map_referral
#
# Send Map-Referral message to supplied destination. Note the destination must
# be routable in RLOC space.
#
def lisp_send_map_referral(lisp_sockets, packet, dest, port):
    lprint("Send Map-Referral to {}".format(dest.print_address()))
    lisp_send_ipc_to_core(lisp_sockets[2], packet, dest, port)
    return
#enddef

#
# lisp_send_map_notify
#
# Send Map-Notify message to supplied destination. Note the destination must
# be routable in RLOC space.
#
def lisp_send_map_notify(lisp_sockets, packet, dest, port):
    lprint("Send Map-Notify to xTR {}".format(dest.print_address()))
    lisp_send_ipc_to_core(lisp_sockets[2], packet, dest, port)
    return
#enddef

#
# lisp_send_ecm
#
# Send Encapsulated Control Message.
#
def lisp_send_ecm(lisp_sockets, packet, inner_source, inner_sport, inner_dest, 
    outer_dest, to_etr=False, to_ms=False, ddt=False):
    
    if (inner_source == None or inner_source.is_null()): 
        inner_source = inner_dest
    #endif

    #
    # For sending Map-Requests, if the NAT-traversal configured, use same
    # socket used to send the Info-Request.
    #
    if (lisp_nat_traversal): 
        sport = lisp_get_any_translated_port()
        if (sport != None): inner_sport = sport
    #endif
    ecm = lisp_ecm(inner_sport)

    ecm.to_etr = to_etr if lisp_is_running("lisp-etr") else False
    ecm.to_ms = to_ms if lisp_is_running("lisp-ms") else False
    ecm.ddt = ddt
    ecm_packet = ecm.encode(packet, inner_source, inner_dest)
    if (ecm_packet == None): 
        lprint("Could not encode ECM message")
        return
    #endif
    ecm.print_ecm()

    packet = ecm_packet + packet

    addr_str = outer_dest.print_address_no_iid()
    lprint("Send Encapsulated-Control-Message to {}".format(addr_str))
    dest = lisp_convert_4to6(addr_str)
    lisp_send(lisp_sockets, dest, LISP_CTRL_PORT, packet)
    return
#enddef

#------------------------------------------------------------------------------

#
# Below are constant definitions used for internal data structures.
#
LISP_AFI_GEO_COORD     = -3
LISP_AFI_IID_RANGE     = -2
LISP_AFI_ULTIMATE_ROOT = -1
LISP_AFI_NONE          = 0
LISP_AFI_IPV4          = 1
LISP_AFI_IPV6          = 2
LISP_AFI_MAC           = 6
LISP_AFI_E164          = 8
LISP_AFI_NAME          = 17
LISP_AFI_LCAF          = 16387

LISP_RLOC_UNKNOWN_STATE         = 0
LISP_RLOC_UP_STATE              = 1
LISP_RLOC_DOWN_STATE            = 2
LISP_RLOC_UNREACH_STATE         = 3
LISP_RLOC_NO_ECHOED_NONCE_STATE = 4
LISP_RLOC_ADMIN_DOWN_STATE      = 5

LISP_AUTH_NONE = 0
LISP_AUTH_MD5  = 1
LISP_AUTH_SHA1 = 2
LISP_AUTH_SHA2 = 3

#------------------------------------------------------------------------------

#
# This is a general address format for EIDs, RLOCs, EID-prefixes in any AFI or
# LCAF format.
#
LISP_IPV4_HOST_MASK_LEN = 32
LISP_IPV6_HOST_MASK_LEN = 128
LISP_MAC_HOST_MASK_LEN  = 48
LISP_E164_HOST_MASK_LEN = 60

#
# byte_swap_64
#
# Byte-swap a 64-bit number.
# 
def byte_swap_64(address):
    addr = \
        ((address & 0x00000000000000ff) << 56) | \
        ((address & 0x000000000000ff00) << 40) | \
        ((address & 0x0000000000ff0000) << 24) | \
        ((address & 0x00000000ff000000) << 8)  | \
        ((address & 0x000000ff00000000) >> 8)  | \
        ((address & 0x0000ff0000000000) >> 24) | \
        ((address & 0x00ff000000000000) >> 40) | \
        ((address & 0xff00000000000000) >> 56)
    return(addr)
#enddef

#
# lisp_cache is a data structure to implement a multi-way tree. The first
# level array is an associative array of mask-lengths. Then each mask-length
# entry will be an associatative array of the following key:
#
#     <32-bit-instance-id> <16-bit-address-family> <eid-prefix>
#
# Data structure:
#      self.cache{}
#      self.cache_sorted[]
#      self.cache{}.entries{}
#      self.cache{}.entries_sorted[]
#
class lisp_cache_entries(object):
    def __init__(self):
        self.entries = {}
        self.entries_sorted = []
    #enddef
#endclass

class lisp_cache(object):
    def __init__(self):
        self.cache = {}
        self.cache_sorted = []
        self.cache_count = 0
    #enddef

    def cache_size(self):
        return(self.cache_count)
    #enddef

    def build_key(self, prefix):
        if (prefix.afi == LISP_AFI_ULTIMATE_ROOT): 
            ml = 0
        elif (prefix.afi == LISP_AFI_IID_RANGE): 
            ml = prefix.mask_len
        else: 
            ml = prefix.mask_len + 48
        #endif

        iid = lisp_hex_string(prefix.instance_id).zfill(8)
        afi = lisp_hex_string(prefix.afi).zfill(4)

        if (prefix.afi > 0):
            if (prefix.is_binary()):
                length = prefix.addr_length() * 2
                addr = lisp_hex_string(prefix.address).zfill(length)
            else:
                addr = prefix.address
            #endif
        elif (prefix.afi == LISP_AFI_GEO_COORD):
            afi = "8003"
            addr = prefix.address.print_geo()
        else:
            afi = ""
            addr = ""
        #endif

        key = iid + afi + addr
        return([ml, key])
    #enddef

    def add_cache(self, prefix, entry):
        if (prefix.is_binary()): prefix.zero_host_bits()
        ml, key = self.build_key(prefix)
        if (ml not in self.cache):
            self.cache[ml] = lisp_cache_entries()
            self.cache_sorted = self.sort_in_entry(self.cache_sorted, ml)
        #endif
        if (key not in self.cache[ml].entries):
            self.cache_count += 1
        #endif
        self.cache[ml].entries[key] = entry
    #enddef
        
    def lookup_cache(self, prefix, exact):
        ml_key, key = self.build_key(prefix)
        if (exact):
            if (ml_key not in self.cache): return(None)
            if (key not in self.cache[ml_key].entries): return(None)
            return(self.cache[ml_key].entries[key])
        #endif

        found = None
        for ml in self.cache_sorted:
            if (ml_key < ml): return(found)
            for entry in list(self.cache[ml].entries.values()):
                if (prefix.is_more_specific(entry.eid)):
                    if (found == None or
                        entry.eid.is_more_specific(found.eid)): found = entry
                #endif
            #endfor
        #endfor
        return(found)
    #enddef

    def delete_cache(self, prefix):
        ml, key = self.build_key(prefix)
        if (ml not in self.cache): return
        if (key not in self.cache[ml].entries): return
        self.cache[ml].entries.pop(key)
        self.cache_count -= 1
    #enddef

    def walk_cache(self, function, parms):
        for ml in self.cache_sorted:
            for entry in list(self.cache[ml].entries.values()):
                status, parms = function(entry, parms)
                if (status == False): return(parms)
            #endfor
        #endfor
        return(parms)
    #enddef

    def sort_in_entry(self, table, value):
        if (table == []): return([value])

        t = table
        while (True):
            if (len(t) == 1):
                if (value == t[0]): return(table)
                index = table.index(t[0])
                if (value < t[0]):
                    return(table[0:index] + [value] + table[index::])
                #endif
                if (value > t[0]):
                    return(table[0:index+1] + [value] + table[index+1::])
                #endif
            #endif
            index = old_div(len(t), 2)
            t = t[0:index] if (value < t[index]) else t[index::]
        #endwhile

        return([])
    #enddef

    def print_cache(self):
        lprint("Printing contents of {}: ".format(self))
        if (self.cache_size() == 0):
            lprint("  Cache is empty")
            return
        #endif
        for ml in self.cache_sorted:
            for key in self.cache[ml].entries:
                entry = self.cache[ml].entries[key]
                lprint("  Mask-length: {}, key: {}, entry: {}".format(ml, key, 
                    entry))
            #endfor
        #endfor
    #enddef
#endclass

#
# Caches.
# 
lisp_referral_cache = lisp_cache()
lisp_ddt_cache = lisp_cache()
lisp_sites_by_eid = lisp_cache()
lisp_map_cache = lisp_cache()
lisp_db_for_lookups = lisp_cache()     # Elements are class lisp_mapping()

#
# lisp_map_cache_lookup
#
# Do hierarchical lookup in the lisp_map_cache lisp_cache(). This is used
# by the ITR and RTR data-planes.
#
def lisp_map_cache_lookup(source, dest):

    multicast = dest.is_multicast_address()

    #
    # Look up destination in map-cache.
    #
    mc = lisp_map_cache.lookup_cache(dest, False)
    if (mc == None): 
        eid_str = source.print_sg(dest) if multicast else dest.print_address()
        eid_str = green(eid_str, False)
        dprint("Lookup for EID {} not found in map-cache".format(eid_str))
        return(None)
    #endif

    #
    # Unicast lookup succeeded.
    #
    if (multicast == False):
        m = green(mc.eid.print_prefix(), False)
        dprint("Lookup for EID {} found map-cache entry {}".format( \
            green(dest.print_address(), False), m))
        return(mc)
    #endif

    #
    # If destination is multicast, then do source lookup.
    #
    mc = mc.lookup_source_cache(source, False)
    if (mc == None):
        eid_str = source.print_sg(dest)
        dprint("Lookup for EID {} not found in map-cache".format(eid_str))
        return(None)
    #endif

    #
    # Multicast lookup succeeded.
    #
    m = green(mc.print_eid_tuple(), False)
    dprint("Lookup for EID {} found map-cache entry {}".format( \
        green(source.print_sg(dest), False), m))
    return(mc)
#enddef

#
# lisp_referral_cache_lookup
#
# Do hierarchical lookup in the lisp_referral_cache lisp_cache().
#
def lisp_referral_cache_lookup(eid, group, exact):
    if (group and group.is_null()):
        ref = lisp_referral_cache.lookup_cache(eid, exact)
        return(ref)
    #endif

    #
    # No source to do 2-stage lookup, return None.
    #
    if (eid == None or eid.is_null()): return(None)

    #
    # Do 2-stage lookup, first on group and within its structure for source.
    # If we found both entries, return source entry. If we didn't find source
    # entry, then return group entry if longest match requested.
    #
    ref = lisp_referral_cache.lookup_cache(group, exact)
    if (ref == None): return(None)

    sref = ref.lookup_source_cache(eid, exact)
    if (sref): return(sref)

    if (exact): ref = None
    return(ref)
#enddef

#
# lisp_ddt_cache_lookup
#
# Do hierarchical lookup in the lisp_ddt_cache lisp_cache().
#
def lisp_ddt_cache_lookup(eid, group, exact):
    if (group.is_null()):
        ddt = lisp_ddt_cache.lookup_cache(eid, exact)
        return(ddt)
    #endif

    #
    # No source to do 2-stage lookup, return None.
    #
    if (eid.is_null()): return(None)

    #
    # Do 2-stage lookup, first on group and within its structure for source.
    # If we found both entries, return source entry. If we didn't find source
    # entry, then return group entry if longest match requested.
    #
    ddt = lisp_ddt_cache.lookup_cache(group, exact)
    if (ddt == None): return(None)

    sddt = ddt.lookup_source_cache(eid, exact)
    if (sddt): return(sddt)

    if (exact): ddt = None
    return(ddt)
#enddef

#
# lisp_site_eid_lookup
#
# Do hierarchical lookup in the lisp_sites_by_eid lisp_cache().
#
def lisp_site_eid_lookup(eid, group, exact):

    if (group.is_null()):
        site_eid = lisp_sites_by_eid.lookup_cache(eid, exact)
        return(site_eid)
    #endif

    #
    # No source to do 2-stage lookup, return None.
    #
    if (eid.is_null()): return(None)

    #
    # Do 2-stage lookup, first on group and within its structure for source.
    # If we found both entries, return source entry. If we didn't find source
    # entry, then return group entry if longest match requested.
    #
    site_eid = lisp_sites_by_eid.lookup_cache(group, exact)
    if (site_eid == None): return(None)

    #
    # There is a special case we have to deal with here. If there exists a
    # (0.0.0.0/0, 224.0.0.0/4) entry that has been configured with accept-
    # more-specifics, this entry will not be retunred if there is a more-
    # specific already cached. For instance, if a Map-Register was received
    # for (1.1.1.1/32, 224.1.1.1/32), it will match the (0.0.0.0/0, 
    # 224.0.0.0/4) entry. But when (1.1.1.1/32, 224.1.1.1/32) is cached and
    # a Map-Register is received for (2.2.2.2/32, 224.1.1.1/32), rather than
    # matching the ams entry, it will match the more specific entry and return
    # (*, 224.1.1.1/32). Since the source lookup will be performed below and
    # not find 2.2.2.2, what is retunred is 224.1.1.1/32 and not 224.0.0.0/4.
    #
    # So we will look at the retunred entry and if a source is not found, we
    # will check to see if the parent of the 224.1.1.1/32 matches the group
    # we are looking up. This, of course, is only done for longest match 
    # lookups.
    #
    seid = site_eid.lookup_source_cache(eid, exact)
    if (seid): return(seid)

    if (exact): 
        site_eid = None
    else:
        parent = site_eid.parent_for_more_specifics
        if (parent and parent.accept_more_specifics): 
            if (group.is_more_specific(parent.group)): site_eid = parent
        #endif
    #endif
    return(site_eid)
#enddef

#
# LISP Address encodings. Both in AFI formats and LCAF formats.
#
# Here is an EID encoded in:
#
#  Instance ID LISP Canonical Address Format:
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |           AFI = 16387         |     Rsvd1     |     Flags     |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |   Type = 2    | IID mask-len  |             4 + n             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                         Instance ID                           |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |              AFI = x          |         Address  ...          |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# There is a python parcularity with shifting greater than 120 bits to the
# left. If the high-order bit hits bit 127, then it shifts it another 8 bits.
# This causes IPv6 addresses to lose their high-order byte. So note the check
# for shift >= 120 below.
#
class lisp_address(object):
    def __init__(self, afi, addr_str, mask_len, iid):
        self.afi = afi
        self.mask_len = mask_len
        self.instance_id = iid
        self.iid_list = []
        self.address = 0
        if (addr_str != ""): self.store_address(addr_str)
    #enddef

    def copy_address(self, addr):
        if (addr == None): return
        self.afi = addr.afi
        self.address = addr.address
        self.mask_len = addr.mask_len
        self.instance_id = addr.instance_id
        self.iid_list = addr.iid_list
    #enddef

    def make_default_route(self, addr):
        self.afi = addr.afi
        self.instance_id = addr.instance_id
        self.mask_len = 0
        self.address = 0
    #enddef

    def make_default_multicast_route(self, addr):
        self.afi = addr.afi
        self.instance_id = addr.instance_id
        if (self.afi == LISP_AFI_IPV4):
            self.address = 0xe0000000
            self.mask_len = 4
        #endif
        if (self.afi == LISP_AFI_IPV6):
            self.address = 0xff << 120
            self.mask_len = 8
        #endif
        if (self.afi == LISP_AFI_MAC):
            self.address = 0xffffffffffff
            self.mask_len = 48
        #endif
    #enddef

    def not_set(self):
        return(self.afi == LISP_AFI_NONE)
    #enddef

    def is_private_address(self):
        if (self.is_ipv4() == False): return(False)
        addr = self.address
        if (((addr & 0xff000000) >> 24) == 10): return(True)
        if (((addr & 0xff000000) >> 24) == 172): 
            byte2 = (addr & 0x00ff0000) >> 16
            if (byte2 >= 16 and byte2 <= 31): return(True)
        #endif
        if (((addr & 0xffff0000) >> 16) == 0xc0a8): return(True)
        return(False)
    #enddef

    def is_multicast_address(self):
        if (self.is_ipv4()): return(self.is_ipv4_multicast())
        if (self.is_ipv6()): return(self.is_ipv6_multicast())
        if (self.is_mac()): return(self.is_mac_multicast())
        return(False)
    #enddef

    def host_mask_len(self):
        if (self.afi == LISP_AFI_IPV4): return(LISP_IPV4_HOST_MASK_LEN)
        if (self.afi == LISP_AFI_IPV6): return(LISP_IPV6_HOST_MASK_LEN)
        if (self.afi == LISP_AFI_MAC): return(LISP_MAC_HOST_MASK_LEN)
        if (self.afi == LISP_AFI_E164): return(LISP_E164_HOST_MASK_LEN)
        if (self.afi == LISP_AFI_NAME): return(len(self.address) * 8)
        if (self.afi == LISP_AFI_GEO_COORD): 
            return(len(self.address.print_geo()) * 8)
        #endif
        return(0)
    #enddef

    def is_iana_eid(self):
        if (self.is_ipv6() == False): return(False)
        addr = self.address >> 96
        return(addr == 0x20010005)
    #enddef

    def addr_length(self):
        if (self.afi == LISP_AFI_IPV4): return(4)
        if (self.afi == LISP_AFI_IPV6): return(16)
        if (self.afi == LISP_AFI_MAC): return(6)
        if (self.afi == LISP_AFI_E164): return(8)
        if (self.afi == LISP_AFI_LCAF): return(0)
        if (self.afi == LISP_AFI_NAME): return(len(self.address) + 1)
        if (self.afi == LISP_AFI_IID_RANGE): return(4)
        if (self.afi == LISP_AFI_GEO_COORD): 
            return(len(self.address.print_geo()))
        #endif
        return(0)
    #enddef

    def afi_to_version(self):
        if (self.afi == LISP_AFI_IPV4): return(4)
        if (self.afi == LISP_AFI_IPV6): return(6)
        return(0)
    #enddef

    def packet_format(self):

        #
        # Note that "I" is used to produce 4 bytes because when "L" is used,
        # it was producing 8 bytes in struct.pack().
        #
        if (self.afi == LISP_AFI_IPV4): return("I")
        if (self.afi == LISP_AFI_IPV6): return("QQ")
        if (self.afi == LISP_AFI_MAC): return("HHH")
        if (self.afi == LISP_AFI_E164): return("II")
        if (self.afi == LISP_AFI_LCAF): return("I")
        return("")
    #enddef

    def pack_address(self):
        packet_format = self.packet_format()
        packet = b""
        if (self.is_ipv4()): 
            packet = struct.pack(packet_format, socket.htonl(self.address))
        elif (self.is_ipv6()):
            addr1 = byte_swap_64(self.address >> 64)
            addr2 = byte_swap_64(self.address & 0xffffffffffffffff)
            packet = struct.pack(packet_format, addr1, addr2)
        elif (self.is_mac()): 
            addr = self.address
            addr1 = (addr >> 32) & 0xffff
            addr2 = (addr >> 16) & 0xffff
            addr3 = addr & 0xffff
            packet = struct.pack(packet_format, addr1, addr2, addr3)
        elif (self.is_e164()): 
            addr = self.address
            addr1 = (addr >> 32) & 0xffffffff
            addr2 = (addr & 0xffffffff)
            packet = struct.pack(packet_format, addr1, addr2)
        elif (self.is_dist_name()):
            packet += (self.address + "\0").encode()
        #endif
        return(packet)
    #enddef

    def unpack_address(self, packet):
        packet_format = self.packet_format()
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        addr = struct.unpack(packet_format, packet[:format_size])

        if (self.is_ipv4()):
            self.address = socket.ntohl(addr[0])

        elif (self.is_ipv6()):

            #
            # Sigh, we have a high-order byte with zero-fill issue when
            # parsing a binary IPv6 address from a packet. If we have an
            # address that starts with fe::, then addr[0] is one byte in
            # length and byte-swapping is not necessary (or we would make
            # the high-order 16 bits 00fe). Sigh.
            #
            if (addr[0] <= 0xffff and (addr[0] & 0xff) == 0):
                high = (addr[0] << 48) << 64
            else:
                high = byte_swap_64(addr[0]) << 64
            #endif
            low = byte_swap_64(addr[1])
            self.address = high | low

        elif (self.is_mac()):
            short1 = addr[0]
            short2 = addr[1]
            short3 = addr[2]
            self.address = (short1 << 32) + (short2 << 16) + short3

        elif (self.is_e164()):
            self.address = (addr[0] << 32) + addr[1]

        elif (self.is_dist_name()):
            packet, self.address = lisp_decode_dist_name(packet)
            self.mask_len = len(self.address) * 8
            format_size = 0
        #endif
        packet = packet[format_size::]
        return(packet)
    #enddef
        
    def is_ipv4(self):
        return(True if (self.afi == LISP_AFI_IPV4) else False)
    #enddef

    def is_ipv4_link_local(self):
        if (self.is_ipv4() == False): return(False)
        return(((self.address >> 16) & 0xffff) == 0xa9fe)    
    #enddef

    def is_ipv4_loopback(self):
        if (self.is_ipv4() == False): return(False)
        return(self.address == 0x7f000001)
    #enddef

    def is_ipv4_multicast(self):
        if (self.is_ipv4() == False): return(False)
        return(((self.address >> 24) & 0xf0) == 0xe0)
    #enddef

    def is_ipv4_string(self, addr_str):
        return(addr_str.find(".") != -1)
    #enddef

    def is_ipv6(self):
        return(True if (self.afi == LISP_AFI_IPV6) else False)
    #enddef

    def is_ipv6_link_local(self):
        if (self.is_ipv6() == False): return(False)
        return(((self.address >> 112) & 0xffff) == 0xfe80)
    #enddef

    def is_ipv6_string_link_local(self, addr_str):
        return(addr_str.find("fe80::") != -1)
    #enddef

    def is_ipv6_loopback(self):
        if (self.is_ipv6() == False): return(False)
        return(self.address == 1)
    #enddef

    def is_ipv6_multicast(self):
        if (self.is_ipv6() == False): return(False)
        return(((self.address >> 120) & 0xff) == 0xff)
    #enddef

    def is_ipv6_string(self, addr_str):
        return(addr_str.find(":") != -1)
    #enddef

    def is_mac(self):
        return(True if (self.afi == LISP_AFI_MAC) else False)
    #enddef

    def is_mac_multicast(self):
        if (self.is_mac() == False): return(False)
        return((self.address & 0x010000000000) != 0)
    #enddef

    def is_mac_broadcast(self):
        if (self.is_mac() == False): return(False)
        return(self.address == 0xffffffffffff)
    #enddef

    def is_mac_string(self, addr_str):
        return(len(addr_str) == 15 and addr_str.find("-") != -1)
    #enddef

    def is_link_local_multicast(self):
        if (self.is_ipv4()): 
            return((0xe0ffff00 & self.address) == 0xe0000000)
        #endif
        if (self.is_ipv6()): 
            return((self.address >> 112) & 0xffff == 0xff02)
        #endif
        return(False)            
    #enddef

    def is_null(self):
        return(True if (self.afi == LISP_AFI_NONE) else False)
    #enddef

    def is_ultimate_root(self):
        return(True if self.afi == LISP_AFI_ULTIMATE_ROOT else False)
    #enddef

    def is_iid_range(self):
        return(True if self.afi == LISP_AFI_IID_RANGE else False)
    #enddef

    def is_e164(self):
        return(True if (self.afi == LISP_AFI_E164) else False)
    #enddef

    def is_dist_name(self):
        return(True if (self.afi == LISP_AFI_NAME) else False)
    #enddef

    def is_geo_prefix(self):
        return(True if (self.afi == LISP_AFI_GEO_COORD) else False)
    #enddef

    def is_binary(self):
        if (self.is_dist_name()): return(False)
        if (self.is_geo_prefix()): return(False)
        return(True)
    #enddef

    def store_address(self, addr_str):
        if (self.afi == LISP_AFI_NONE): self.string_to_afi(addr_str)

        #
        # Parse instance-id.
        #
        i = addr_str.find("[")
        j = addr_str.find("]")
        if (i != -1 and j != -1): 
            self.instance_id = int(addr_str[i+1:j])
            addr_str = addr_str[j+1::]
            if (self.is_dist_name() == False):
                addr_str = addr_str.replace(" ", "")
            #endif
        #endif

        #
        # Parse AFI based address.
        #
        if (self.is_ipv4()): 
            octet = addr_str.split(".")
            value = int(octet[0]) << 24
            value += int(octet[1]) << 16
            value += int(octet[2]) << 8
            value += int(octet[3])
            self.address = value
        elif (self.is_ipv6()):

            #
            # There will be a common IPv6 address input mistake that will 
            # occur. The address ff::/8 (or an address ff::1) is actually
            # encoded as 0x00ff as the high-order 16-bits. The correct way to
            # specify the prefix is ff00::/8 but one would wonder why the
            # lower order 0x00 bits are needed if a /8 is used. So to
            # summarize:
            #
            # Entering ff::/8 will give you the 0::/8 prefix.
            # Entering ff00::/8 is not the same as ff00::/16.
            #
            # Allow user to specify ff::/8 which allows for placing the the
            # byte in the high-order byte of the 128-bit quantity. Check
            # for double-colon in the input string to detect the single byte
            # and then below byte-swap the first 2-bytes.
            #
            odd_byte = (addr_str[2:4] == "::")
            try:
                addr_str = socket.inet_pton(socket.AF_INET6, addr_str)
            except:
                addr_str = socket.inet_pton(socket.AF_INET6, "0::0")
            #endtry
            addr_str = binascii.hexlify(addr_str)

            if (odd_byte):
                addr_str = addr_str[2:4] + addr_str[0:2] + addr_str[4::]
            #endif
            self.address = int(addr_str, 16)

        elif (self.is_geo_prefix()):
            geo = lisp_geo(None)
            geo.name = "geo-prefix-{}".format(geo)
            geo.parse_geo_string(addr_str)
            self.address = geo
        elif (self.is_mac()):
            addr_str = addr_str.replace("-", "")
            value = int(addr_str, 16)
            self.address = value
        elif (self.is_e164()):
            addr_str = addr_str[1::]
            value = int(addr_str, 16)
            self.address = value << 4
        elif (self.is_dist_name()):
            self.address = addr_str.replace("'", "")
        #endif
        self.mask_len = self.host_mask_len()
    #enddef

    def store_prefix(self, prefix_str):
        if (self.is_geo_string(prefix_str)):
            index = prefix_str.find("]")
            mask_len = len(prefix_str[index+1::]) * 8
        elif (prefix_str.find("/") != -1):
            prefix_str, mask_len = prefix_str.split("/")
        else:
            left = prefix_str.find("'")
            if (left == -1): return
            right = prefix_str.find("'", left+1)
            if (right == -1): return
            mask_len = len(prefix_str[left+1:right]) * 8
        #endif

        self.string_to_afi(prefix_str)
        self.store_address(prefix_str)
        self.mask_len = int(mask_len)
    #enddef

    def zero_host_bits(self):
        if (self.mask_len < 0): return
        mask = (2 ** self.mask_len) - 1
        shift = self.addr_length() * 8 - self.mask_len
        mask <<= shift
        self.address &= mask
    #enddef

    def is_geo_string(self, addr_str):
        index = addr_str.find("]")
        if (index != -1): addr_str = addr_str[index+1::]
        
        geo = addr_str.split("/")
        if (len(geo) == 2):
            if (geo[1].isdigit() == False): return(False)
        #endif
        geo = geo[0]
        geo = geo.split("-")
        geo_len = len(geo)
        if (geo_len < 8 or geo_len > 9): return(False)

        for num in range(0, geo_len):
            if (num == 3):
                if (geo[num] in ["N", "S"]): continue
                return(False)
            #enif
            if (num == 7):
                if (geo[num] in ["W", "E"]): continue
                return(False)
            #endif
            if (geo[num].isdigit() == False): return(False)
        #endfor
        return(True)
    #enddef
        
    def string_to_afi(self, addr_str):
        if (addr_str.count("'") == 2):
            self.afi = LISP_AFI_NAME
            return
        #endif
        if (addr_str.find(":") != -1): self.afi = LISP_AFI_IPV6
        elif (addr_str.find(".") != -1): self.afi = LISP_AFI_IPV4
        elif (addr_str.find("+") != -1): self.afi = LISP_AFI_E164
        elif (self.is_geo_string(addr_str)): self.afi = LISP_AFI_GEO_COORD
        elif (addr_str.find("-") != -1): self.afi = LISP_AFI_MAC
        else: self.afi = LISP_AFI_NONE
    #enddef

    def print_address(self):
        addr = self.print_address_no_iid()
        iid = "[" + str(self.instance_id)
        for i in self.iid_list: iid += "," + str(i)
        iid += "]"
        addr = "{}{}".format(iid, addr)
        return(addr)
    #enddef

    def print_address_no_iid(self):
        if (self.is_ipv4()): 
            addr = self.address
            value1 = addr >> 24
            value2 = (addr >> 16) & 0xff
            value3 = (addr >> 8) & 0xff
            value4 = addr & 0xff
            return("{}.{}.{}.{}".format(value1, value2, value3, value4))
        elif (self.is_ipv6()):
            addr_str = lisp_hex_string(self.address).zfill(32)
            addr_str = binascii.unhexlify(addr_str)
            addr_str = socket.inet_ntop(socket.AF_INET6, addr_str)
            return("{}".format(addr_str))
        elif (self.is_geo_prefix()): 
            return("{}".format(self.address.print_geo()))
        elif (self.is_mac()): 
            addr_str = lisp_hex_string(self.address).zfill(12)
            addr_str = "{}-{}-{}".format(addr_str[0:4], addr_str[4:8], 
                addr_str[8:12])
            return("{}".format(addr_str))
        elif (self.is_e164()): 
            addr_str = lisp_hex_string(self.address).zfill(15)
            return("+{}".format(addr_str))
        elif (self.is_dist_name()): 
            return("'{}'".format(self.address))
        elif (self.is_null()): 
            return("no-address")
        #endif
        return("unknown-afi:{}".format(self.afi))
    #enddef

    def print_prefix(self):
        if (self.is_ultimate_root()): return("[*]")
        if (self.is_iid_range()): 
            if (self.mask_len == 32): return("[{}]".format(self.instance_id))
            upper = self.instance_id + (2**(32 - self.mask_len) - 1)
            return("[{}-{}]".format(self.instance_id, upper))
        #endif
        addr = self.print_address()
        if (self.is_dist_name()): return(addr)
        if (self.is_geo_prefix()): return(addr)

        index = addr.find("no-address")
        if (index == -1): 
            addr = "{}/{}".format(addr, str(self.mask_len))
        else:
            addr = addr[0:index]
        #endif
        return(addr)
    #enddef

    def print_prefix_no_iid(self):
        addr = self.print_address_no_iid()
        if (self.is_dist_name()): return(addr)
        if (self.is_geo_prefix()): return(addr)
        return("{}/{}".format(addr, str(self.mask_len)))
    #enddef

    def print_prefix_url(self):
        if (self.is_ultimate_root()): return("0--0")
        addr = self.print_address()
        index = addr.find("]")
        if (index != -1): addr = addr[index+1::]
        if (self.is_geo_prefix()): 
            addr = addr.replace("/", "-")
            return("{}-{}".format(self.instance_id, addr))
        #endif
        return("{}-{}-{}".format(self.instance_id, addr, self.mask_len))
    #enddef

    def print_sg(self, g):
        s = self.print_prefix()
        si = s.find("]") + 1
        g = g.print_prefix()
        gi = g.find("]") + 1
        sg_str = "[{}]({}, {})".format(self.instance_id, s[si::], g[gi::])
        return(sg_str)
    #enddef

    def hash_address(self, addr):
        addr1 = self.address
        addr2 = addr.address

        if (self.is_geo_prefix()): addr1 = self.address.print_geo()
        if (addr.is_geo_prefix()): addr2 = addr.address.print_geo()

        if (type(addr1) == str):
            addr1 = int(binascii.hexlify(addr1[0:1]))
        #endif
        if (type(addr2) == str):
            addr2 = int(binascii.hexlify(addr2[0:1]))
        #endif
        return(addr1 ^ addr2)
    #enddef

    #
    # Is self more specific or equal to the prefix supplied in variable 
    # 'prefix'. Return True if so.
    #
    def is_more_specific(self, prefix):
        if (prefix.afi == LISP_AFI_ULTIMATE_ROOT): return(True)

        mask_len = prefix.mask_len
        if (prefix.afi == LISP_AFI_IID_RANGE):
            size = 2**(32 - mask_len)
            lower = prefix.instance_id
            upper = lower + size
            return(self.instance_id in range(lower, upper))
        #endif

        if (self.instance_id != prefix.instance_id): return(False)
        if (self.afi != prefix.afi): 
            if (prefix.afi != LISP_AFI_NONE): return(False)
        #endif

        #
        # Handle string addresses like distinguished names and geo-prefixes.
        #
        if (self.is_binary() == False):
            if (prefix.afi == LISP_AFI_NONE): return(True)
            if (type(self.address) != type(prefix.address)): return(False)
            addr = self.address
            paddr = prefix.address
            if (self.is_geo_prefix()):
                addr = self.address.print_geo()
                paddr = prefix.address.print_geo()
            #endif
            if (len(addr) < len(paddr)): return(False)
            return(addr.find(paddr) == 0)
        #endif

        #
        # Handle numeric addresses.
        #
        if (self.mask_len < mask_len): return(False)

        shift = (prefix.addr_length() * 8) - mask_len
        mask = (2**mask_len - 1) << shift
        return((self.address & mask) == prefix.address)
    #enddef

    def mask_address(self, mask_len):
        shift = (self.addr_length() * 8) - mask_len
        mask = (2**mask_len - 1) << shift
        self.address &= mask
    #enddef
                                      
    def is_exact_match(self, prefix):
        if (self.instance_id != prefix.instance_id): return(False)
        p1 = self.print_prefix()
        p2 = prefix.print_prefix() if prefix else ""
        return(p1 == p2)
    #enddef

    def is_local(self):
        if (self.is_ipv4()): 
            local = lisp_myrlocs[0]
            if (local == None): return(False)
            local = local.print_address_no_iid()
            return(self.print_address_no_iid() == local)
        #endif
        if (self.is_ipv6()): 
            local = lisp_myrlocs[1]
            if (local == None): return(False)
            local = local.print_address_no_iid()
            return(self.print_address_no_iid() == local)
        #endif
        return(False)
    #enddef

    def store_iid_range(self, iid, mask_len):
        if (self.afi == LISP_AFI_NONE):
            if (iid == 0 and mask_len == 0): self.afi = LISP_AFI_ULTIMATE_ROOT
            else: self.afi = LISP_AFI_IID_RANGE
        #endif
        self.instance_id = iid
        self.mask_len = mask_len
    #enddef

    def lcaf_length(self, lcaf_type):
        length = self.addr_length() + 2
        if (lcaf_type == LISP_LCAF_AFI_LIST_TYPE): length += 4
        if (lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE): length += 4
        if (lcaf_type == LISP_LCAF_ASN_TYPE): length += 4
        if (lcaf_type == LISP_LCAF_APP_DATA_TYPE): length += 8
        if (lcaf_type == LISP_LCAF_GEO_COORD_TYPE): length += 12
        if (lcaf_type == LISP_LCAF_OPAQUE_TYPE): length += 0
        if (lcaf_type == LISP_LCAF_NAT_TYPE): length += 4
        if (lcaf_type == LISP_LCAF_NONCE_LOC_TYPE): length += 4
        if (lcaf_type == LISP_LCAF_MCAST_INFO_TYPE): length = length * 2 + 8
        if (lcaf_type == LISP_LCAF_ELP_TYPE): length += 0
        if (lcaf_type == LISP_LCAF_SECURITY_TYPE): length += 6
        if (lcaf_type == LISP_LCAF_SOURCE_DEST_TYPE): length += 4
        if (lcaf_type == LISP_LCAF_RLE_TYPE): length += 4
        return(length)
    #enddef

    #
    # Instance ID LISP Canonical Address Format:
    #
    #   0                   1                   2                   3
    #   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |           AFI = 16387         |     Rsvd1     |     Flags     |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |   Type = 2    | IID mask-len  |             4 + n             |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                         Instance ID                           |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |              AFI = x          |         Address  ...          |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    def lcaf_encode_iid(self):
        lcaf_type = LISP_LCAF_INSTANCE_ID_TYPE
        addr_length = socket.htons(self.lcaf_length(lcaf_type))
        iid = self.instance_id
        afi = self.afi
        ml = 0
        if (afi < 0): 
            if (self.afi == LISP_AFI_GEO_COORD):
                afi = LISP_AFI_LCAF
                ml = 0
            else:
                afi = 0
                ml = self.mask_len
            #endif
        #endif

        lcaf = struct.pack("BBBBH", 0, 0, lcaf_type, ml, addr_length)
        lcaf += struct.pack("IH", socket.htonl(iid), socket.htons(afi))
        if (afi == 0): return(lcaf)
        
        if (self.afi == LISP_AFI_GEO_COORD):
            lcaf = lcaf[0:-2]
            lcaf += self.address.encode_geo()
            return(lcaf)
        #endif

        lcaf += self.pack_address()
        return(lcaf)
    #enddef

    def lcaf_decode_iid(self, packet):
        packet_format = "BBBBH"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        x, y, lcaf_type, iid_ml, length = struct.unpack(packet_format, 
            packet[:format_size])
        packet = packet[format_size::]

        if (lcaf_type != LISP_LCAF_INSTANCE_ID_TYPE): return(None)

        packet_format = "IH"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(None)

        iid, afi = struct.unpack(packet_format, packet[:format_size])
        packet = packet[format_size::]

        length = socket.ntohs(length)
        self.instance_id = socket.ntohl(iid)
        afi = socket.ntohs(afi)
        self.afi = afi
        if (iid_ml != 0 and afi == 0): self.mask_len = iid_ml
        if (afi == 0):
            self.afi = LISP_AFI_IID_RANGE if iid_ml else LISP_AFI_ULTIMATE_ROOT
        #endif

        #
        # No address encoded.
        #
        if (afi == 0): return(packet)

        #
        # Look for distinguished-name.
        #
        if (self.is_dist_name()):
            packet, self.address = lisp_decode_dist_name(packet)
            self.mask_len = len(self.address) * 8
            return(packet)
        #endif

        #
        # Only process geo-prefixes inside of an LCAF encoded Instance-ID type.
        #
        if (afi == LISP_AFI_LCAF):
            packet_format = "BBBBH"
            format_size = struct.calcsize(packet_format)
            if (len(packet) < format_size): return(None)

            rsvd1, flags, lcaf_type, rsvd2, lcaf_len = \
                struct.unpack(packet_format, packet[:format_size])

            if (lcaf_type != LISP_LCAF_GEO_COORD_TYPE): return(None)

            lcaf_len = socket.ntohs(lcaf_len)
            packet = packet[format_size::]
            if (lcaf_len > len(packet)): return(None)

            geo = lisp_geo("")
            self.afi = LISP_AFI_GEO_COORD
            self.address = geo
            packet = geo.decode_geo(packet, lcaf_len, rsvd2)
            self.mask_len = self.host_mask_len()
            return(packet)
        #endif

        addr_length = self.addr_length()
        if (len(packet) < addr_length): return(None)

        packet = self.unpack_address(packet)
        return(packet)
    #enddef

    #
    # Multicast Info Canonical Address Format:
    #
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |           AFI = 16387         |     Rsvd1     |     Flags     |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |   Type = 9    |  Rsvd2  |R|L|J|             8 + n             |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |                         Instance-ID                           |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |            Reserved           | Source MaskLen| Group MaskLen |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |              AFI = x          |   Source/Subnet Address  ...  |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #  |              AFI = x          |       Group Address  ...      |
    #  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    def lcaf_encode_sg(self, group):
        lcaf_type = LISP_LCAF_MCAST_INFO_TYPE
        iid = socket.htonl(self.instance_id)
        addr_length = socket.htons(self.lcaf_length(lcaf_type))
        lcaf = struct.pack("BBBBHIHBB", 0, 0, lcaf_type, 0, addr_length, iid,
            0, self.mask_len, group.mask_len)

        lcaf += struct.pack("H", socket.htons(self.afi))
        lcaf += self.pack_address()
        lcaf += struct.pack("H", socket.htons(group.afi))
        lcaf += group.pack_address()
        return(lcaf)
    #enddef

    def lcaf_decode_sg(self, packet):
        packet_format = "BBBBHIHBB"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return([None, None])

        x, y, lcaf_type, rsvd, length, iid, z, sml, gml = \
            struct.unpack(packet_format, packet[:format_size])
        packet = packet[format_size::]

        if (lcaf_type != LISP_LCAF_MCAST_INFO_TYPE): return([None, None])

        self.instance_id = socket.ntohl(iid)
        length = socket.ntohs(length) - 8

        #
        # Get AFI and source address. Validate if enough length and there
        # are bytes in the packet.
        #
        packet_format = "H"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return([None, None])
        if (length < format_size): return([None, None])

        afi = struct.unpack(packet_format, packet[:format_size])[0]
        packet = packet[format_size::]
        length -= format_size
        self.afi = socket.ntohs(afi)
        self.mask_len = sml
        addr_length = self.addr_length()
        if (length < addr_length): return([None, None])

        packet = self.unpack_address(packet)
        if (packet == None): return([None, None])

        length -= addr_length

        #
        # Get AFI and source address. Validate if enough length and there
        # are bytes in the packet.
        #
        packet_format = "H"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return([None, None])
        if (length < format_size): return([None, None])

        afi = struct.unpack(packet_format, packet[:format_size])[0]
        packet = packet[format_size::]
        length -= format_size
        group = lisp_address(LISP_AFI_NONE, "", 0, 0)
        group.afi = socket.ntohs(afi)
        group.mask_len = gml
        group.instance_id = self.instance_id
        addr_length = self.addr_length()
        if (length < addr_length): return([None, None])

        packet = group.unpack_address(packet)
        if (packet == None): return([None, None])

        return([packet, group])
    #enddef

    def lcaf_decode_eid(self, packet):
        packet_format = "BBB"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return([None, None])

        #
        # Do not advance packet pointer. The specific LCAF decoders will do
        # it themselves.
        #
        rsvd, flags, lcaf_type = struct.unpack(packet_format, 
            packet[:format_size])

        if (lcaf_type == LISP_LCAF_INSTANCE_ID_TYPE):
            return([self.lcaf_decode_iid(packet), None])
        elif (lcaf_type == LISP_LCAF_MCAST_INFO_TYPE):
            packet, group = self.lcaf_decode_sg(packet)
            return([packet, group])
        elif (lcaf_type == LISP_LCAF_GEO_COORD_TYPE):
            packet_format = "BBBBH"
            format_size = struct.calcsize(packet_format)
            if (len(packet) < format_size): return(None)
            
            rsvd1, flags, lcaf_type, rsvd2, lcaf_len = \
                struct.unpack(packet_format, packet[:format_size])

            if (lcaf_type != LISP_LCAF_GEO_COORD_TYPE): return(None)

            lcaf_len = socket.ntohs(lcaf_len)
            packet = packet[format_size::]
            if (lcaf_len > len(packet)): return(None)

            geo = lisp_geo("")
            self.instance_id = 0
            self.afi = LISP_AFI_GEO_COORD
            self.address = geo
            packet = geo.decode_geo(packet, lcaf_len, rsvd2)
            self.mask_len = self.host_mask_len()
        #endif
        return([packet, None])
    #enddef
#endclass

#
# Data structure for storing learned or configured ELPs.
#
class lisp_elp_node(object):
    def __init__(self):
        self.address = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.probe = False
        self.strict = False
        self.eid = False
        self.we_are_last = False
    #enddef

    def copy_elp_node(self):
        elp_node = lisp_elp_node()
        elp_node.copy_address(self.address)
        elp_node.probe = self.probe
        elp_node.strict = self.strict
        elp_node.eid = self.eid
        elp_node.we_are_last = self.we_are_last
        return(elp_node)
    #enddef
#endclass

class lisp_elp(object):
    def __init__(self, name):
        self.elp_name = name
        self.elp_nodes = []
        self.use_elp_node = None
        self.we_are_last = False
    #enddef

    def copy_elp(self):
        elp = lisp_elp(self.elp_name)
        elp.use_elp_node = self.use_elp_node
        elp.we_are_last = self.we_are_last
        for elp_node in self.elp_nodes: 
            elp.elp_nodes.append(elp_node.copy_elp_node())
        #endfor
        return(elp)
    #enddef
    
    def print_elp(self, want_marker):
        elp_str = ""
        for elp_node in self.elp_nodes:
            use_or_last = ""
            if (want_marker):
                if (elp_node == self.use_elp_node):
                    use_or_last = "*"
                elif (elp_node.we_are_last):
                    use_or_last = "x"
                #endif
            #endif
            elp_str += "{}{}({}{}{}), ".format(use_or_last,
                elp_node.address.print_address_no_iid(),
                "r" if elp_node.eid else "R", "P" if elp_node.probe else "p",
                "S" if elp_node.strict else "s")
        #endfor
        return(elp_str[0:-2] if elp_str != "" else "")
    #enddef

    def select_elp_node(self):
        v4, v6, device = lisp_myrlocs
        index = None

        for elp_node in self.elp_nodes:
            if (v4 and elp_node.address.is_exact_match(v4)):
                index = self.elp_nodes.index(elp_node)
                break
            #endif
            if (v6 and elp_node.address.is_exact_match(v6)):
                index = self.elp_nodes.index(elp_node)
                break
            #endif
        #endfor

        #
        # If we did not find a match, this is possibly an ITR. We need to give
        # if the first ELP node.
        #
        if (index == None):
            self.use_elp_node = self.elp_nodes[0]
            elp_node.we_are_last = False
            return
        #endif

        #
        # If we matched the last item in the ELP nodes, we are the end of the
        # path. Flag it for display purposes and return None.
        #
        if (self.elp_nodes[-1] == self.elp_nodes[index]):
            self.use_elp_node = None
            elp_node.we_are_last = True
            return
        #endif

        #
        # Return the next node after the one that matches this system.
        #
        self.use_elp_node = self.elp_nodes[index+1]
        return
    #enddef
#endclass

class lisp_geo(object):
    def __init__(self, name):
        self.geo_name = name
        self.latitude = 0xffffffff       # Negative when North, otherwise South
        self.lat_mins = 0
        self.lat_secs = 0
        self.longitude = 0xffffffff      # Negative when  East, otherwise West
        self.long_mins = 0
        self.long_secs = 0
        self.altitude = -1
        self.radius = 0
    #enddef

    def copy_geo(self):
        geo = lisp_geo(self.geo_name)
        geo.latitude = self.latitude
        geo.lat_mins = self.lat_mins
        geo.lat_secs = self.lat_secs
        geo.longitude = self.longitude
        geo.long_mins = self.long_mins
        geo.long_secs = self.long_secs
        geo.altitude = self.altitude
        geo.radius = self.radius
        return(geo)
    #enddef

    def no_geo_altitude(self):
        return(self.altitude == -1)
    #enddef

    def parse_geo_string(self, geo_str):
        index = geo_str.find("]")
        if (index != -1): geo_str = geo_str[index+1::]

        #
        # Check if radius is specified. That is a geo-prefix and not just a
        # geo-point.
        #
        if (geo_str.find("/") != -1):
            geo_str, radius = geo_str.split("/")
            self.radius = int(radius)
        #endif
            
        geo_str = geo_str.split("-")
        if (len(geo_str) < 8): return(False)

        latitude = geo_str[0:4]
        longitude = geo_str[4:8]

        #
        # Get optional altitude.
        #
        if (len(geo_str) > 8): self.altitude = int(geo_str[8])

        #
        # Get latitude values.
        #
        self.latitude = int(latitude[0])
        self.lat_mins = int(latitude[1])
        self.lat_secs = int(latitude[2])
        if (latitude[3] == "N"): self.latitude = -self.latitude

        #
        # Get longitude values.
        #
        self.longitude = int(longitude[0])
        self.long_mins = int(longitude[1])
        self.long_secs = int(longitude[2])
        if (longitude[3] == "E"): self.longitude = -self.longitude
        return(True)
    #enddef

    def print_geo(self):
        n_or_s = "N" if self.latitude < 0 else "S"
        e_or_w = "E" if self.longitude < 0 else "W"

        geo_str = "{}-{}-{}-{}-{}-{}-{}-{}".format(abs(self.latitude),
            self.lat_mins, self.lat_secs, n_or_s, abs(self.longitude),
            self.long_mins, self.long_secs, e_or_w)

        if (self.no_geo_altitude() == False): 
            geo_str += "-" + str(self.altitude) 
        #endif

        #
        # Print "/<radius>" if not 0.
        #
        if (self.radius != 0): geo_str += "/{}".format(self.radius)
        return(geo_str)
    #enddef

    def geo_url(self):
        zoom = os.getenv("LISP_GEO_ZOOM_LEVEL")
        zoom = "10" if (zoom == "" or zoom.isdigit() == False) else zoom
        lat, lon = self.dms_to_decimal()
        url = ("http://maps.googleapis.com/maps/api/staticmap?center={},{}" + \
            "&markers=color:blue%7Clabel:lisp%7C{},{}" + \
            "&zoom={}&size=1024x1024&sensor=false").format(lat, lon, lat, lon,
             zoom)
        return(url)
    #enddef

    def print_geo_url(self):
        geo = self.print_geo()
        if (self.radius == 0):
            url = self.geo_url()
            string = "<a href='{}'>{}</a>".format(url, geo)
        else:
            url = geo.replace("/", "-")
            string = "<a href='/lisp/geo-map/{}'>{}</a>".format(url, geo)
        #endif
        return(string)
    #enddef

    def dms_to_decimal(self):
        degs, mins, secs = self.latitude, self.lat_mins, self.lat_secs
        dd = float(abs(degs))
        dd += float(mins * 60 + secs) / 3600
        if (degs > 0): dd = -dd
        dd_lat = dd

        degs, mins, secs = self.longitude, self.long_mins, self.long_secs
        dd = float(abs(degs))
        dd += float(mins * 60 + secs) / 3600
        if (degs > 0): dd = -dd
        dd_long = dd
        return((dd_lat, dd_long))
    #enddef
    
    def get_distance(self, geo_point):
        dd_prefix = self.dms_to_decimal()
        dd_point = geo_point.dms_to_decimal()
        distance = geopy.distance.distance(dd_prefix, dd_point)
        return(distance.km)
    #enddef

    def point_in_circle(self, geo_point):
        km = self.get_distance(geo_point)
        return(km <= self.radius)
    #enddef

    def encode_geo(self):
        lcaf_afi = socket.htons(LISP_AFI_LCAF)
        geo_len = socket.htons(20 + 2)
        flags = 0

        lat = abs(self.latitude)
        lat_ms = ((self.lat_mins * 60) + self.lat_secs)  * 1000
        if (self.latitude < 0): flags |= 0x40

        lon = abs(self.longitude)
        lon_ms = ((self.long_mins * 60) + self.long_secs)  * 1000
        if (self.longitude < 0): flags |= 0x20

        alt = 0 
        if (self.no_geo_altitude() == False):
            alt = socket.htonl(self.altitude)        
            flags |= 0x10
        #endif
        radius = socket.htons(self.radius)
        if (radius != 0): flags |= 0x06

        pkt = struct.pack("HBBBBH", lcaf_afi, 0, 0, LISP_LCAF_GEO_COORD_TYPE, 
            0, geo_len)
        pkt += struct.pack("BBHBBHBBHIHHH", flags, 0, 0, lat, lat_ms >> 16,
            socket.htons(lat_ms & 0x0ffff), lon, lon_ms >> 16, 
            socket.htons(lon_ms & 0xffff), alt, radius, 0, 0)

        return(pkt)
    #enddef

    def decode_geo(self, packet, lcaf_len, radius_hi):
        packet_format = "BBHBBHBBHIHHH"
        format_size = struct.calcsize(packet_format)
        if (lcaf_len < format_size): return(None)

        flags, r1, uncertainty, lat, lat_hi, lat_ms, lon, lon_hi, lon_ms, \
            alt, radius, r2, afi = struct.unpack(packet_format,
            packet[:format_size])

        #
        # No nested LCAFs in Geo-Coord type.
        #
        afi = socket.ntohs(afi)
        if (afi == LISP_AFI_LCAF): return(None)

        if (flags & 0x40): lat = -lat
        self.latitude = lat
        lat_secs = old_div(((lat_hi << 16) | socket.ntohs(lat_ms)), 1000)
        self.lat_mins = old_div(lat_secs, 60)
        self.lat_secs = lat_secs % 60
        
        if (flags & 0x20): lon = -lon
        self.longitude = lon
        lon_secs = old_div(((lon_hi << 16) | socket.ntohs(lon_ms)), 1000)
        self.long_mins = old_div(lon_secs, 60)
        self.long_secs = lon_secs % 60

        self.altitude = socket.ntohl(alt) if (flags & 0x10) else -1
        radius = socket.ntohs(radius)
        self.radius = radius if (flags & 0x02) else radius * 1000

        self.geo_name = None
        packet = packet[format_size::]

        if (afi != 0):
            self.rloc.afi = afi
            packet = self.rloc.unpack_address(packet)
            self.rloc.mask_len = self.rloc.host_mask_len()
        #endif
        return(packet)
    #enddef
#endclass

#
# Structure for Replication List Entries. 
#
class lisp_rle_node(object):
    def __init__(self):
        self.address = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.level = 0
        self.translated_port = 0
        self.rloc_name = None
    #enddef
        
    def copy_rle_node(self):
        rle_node = lisp_rle_node()
        rle_node.address.copy_address(self.address)
        rle_node.level = self.level
        rle_node.translated_port = self.translated_port
        rle_node.rloc_name = self.rloc_name
        return(rle_node)
    #enddef

    def store_translated_rloc(self, rloc, port):
        self.address.copy_address(rloc)
        self.translated_port = port
    #enddef

    def get_encap_keys(self):
        port = "4341" if self.translated_port == 0 else \
               str(self.translated_port)
        addr_str = self.address.print_address_no_iid() + ":" + port

        try:
            keys = lisp_crypto_keys_by_rloc_encap[addr_str]
            if (keys[1]): return(keys[1].encrypt_key, keys[1].icv_key)
            return(None, None)
        except:
            return(None, None)
        #endtry
    #enddef

    def normalize_decent_nat_rle_name(self):
        if (self.rloc_name == None): return(None)
        return(self.rloc_name.split(LISP_TP)[0])
    #enddef
#endclass

class lisp_rle(object):
    def __init__(self, name):
        self.rle_name = name
        self.rle_nodes = []
        self.rle_forwarding_list = []
    #enddef
    
    def copy_rle(self):
        rle = lisp_rle(self.rle_name)
        for rle_node in self.rle_nodes:
            rle.rle_nodes.append(rle_node.copy_rle_node())
        #endfor
        rle.build_forwarding_list()
        return(rle)
    #enddef
 
    def print_rle(self, html, do_formatting):
        rle_str = ""
        for rle_node in self.rle_nodes:
            port = rle_node.translated_port

            rle_name_str = ""
            if (rle_node.rloc_name != None):
                rle_name_str = rle_node.rloc_name
                if (do_formatting): rle_name_str = blue(rle_name_str, html)
                rle_name_str = "({})".format(rle_name_str)
            #endif

            addr_str = rle_node.address.print_address_no_iid()
            if (rle_node.address.is_local()): addr_str = red(addr_str, html)
            rle_str += "{}{}{}, ".format(addr_str, "" if port == 0 else \
                ":" + str(port), rle_name_str)
        #endfor
        return(rle_str[0:-2] if rle_str != "" else "")
    #enddef

    def build_forwarding_list(self):
        level = -1
        for rle_node in self.rle_nodes:
            if (level == -1):
                if (rle_node.address.is_local()): level = rle_node.level
            else:
                if (rle_node.level > level): break
            #endif
        #endfor
        level = 0 if level == -1 else rle_node.level

        self.rle_forwarding_list = []
        for rle_node in self.rle_nodes:
            if (rle_node.level == level or (level == 0 and 
                rle_node.level == 128)):
                if (lisp_i_am_rtr == False and rle_node.address.is_local()):
                    addr_str = rle_node.address.print_address_no_iid()
                    lprint("Exclude local RLE RLOC {}".format(addr_str))
                    continue
                #endif
                self.rle_forwarding_list.append(rle_node)
            #endif
        #endfor
    #enddef
#endclass

class lisp_json(object):
    def __init__(self, name, string, encrypted=False, ms_encrypt=False):

        #
        # Deal with py3.
        #
        if (type(string) == bytes): string = string.decode()

        self.json_name = name
        self.json_encrypted = False
        try:
            json.loads(string)
        except:
            lprint("Invalid JSON string: '{}'".format(string))
            string = '{ "?" : "?" }'
        #endtry
        self.json_string = string

        #
        # Decide to encrypt or decrypt. The map-server encrypts and stores
        # ciphertext in mapping system. The lig client decrypts to show user
        # data if it has the key in env variable LISP_JSON_KEY. Format of
        # env variable is "<key>" or "[<key-id>]<key>".
        #
        # If the LISP site-eid is not configured to encrypt the JSON than
        # store in plaintext.
        #
        if (len(lisp_ms_json_keys) != 0):
            if (ms_encrypt == False): return
            self.json_key_id = list(lisp_ms_json_keys.keys())[0]
            self.json_key = lisp_ms_json_keys[self.json_key_id]
            self.encrypt_json()
        #endif

        if (lisp_log_id == "lig" and encrypted):
            key = os.getenv("LISP_JSON_KEY")
            if (key != None):
                index = -1
                if (key[0] == "[" and "]" in key):
                    index = key.find("]")
                    self.json_key_id = int(key[1:index])
                #endif
                self.json_key = key[index+1::]
                #endif
                self.decrypt_json()
            #endif
        #endif
    #enddef

    def add(self):
        self.delete()
        lisp_json_list[self.json_name] = self
    #enddef

    def delete(self):
        if (self.json_name in lisp_json_list):
            del(lisp_json_list[self.json_name])
            lisp_json_list[self.json_name] = None
        #endif
    #enddef

    def print_json(self, html):
        good_string = self.json_string
        bad = "***"
        if (html): bad = red(bad, html)
        bad_string = bad + self.json_string + bad
        if (self.valid_json()): return(good_string)
        return(bad_string)
    #enddef

    def valid_json(self):
        try:
            json.loads(self.json_string)
        except:
            return(False)
        #endtry
        return(True)
    #enddef

    def encrypt_json(self):
        ekey = self.json_key.zfill(32)
        iv = "0" * 8

        jd = json.loads(self.json_string)
        for key in jd:
            value = jd[key]
            if (type(value) != str): value = str(value)
            value = chacha.ChaCha(ekey, iv).encrypt(value)
            jd[key] = binascii.hexlify(value)
        #endfor
        self.json_string = json.dumps(jd)
        self.json_encrypted = True
    #enddef

    def decrypt_json(self):
        ekey = self.json_key.zfill(32)
        iv = "0" * 8

        jd = json.loads(self.json_string)
        for key in jd:
            value = binascii.unhexlify(jd[key])
            jd[key] = chacha.ChaCha(ekey, iv).encrypt(value)
        #endfor
        try:
            self.json_string = json.dumps(jd)
            self.json_encrypted = False
        except:
            pass
        #endtry
    #enddef
#endclass

#
# LISP forwarding stats info.
#
class lisp_stats(object):
    def __init__(self):
        self.packet_count = 0
        self.byte_count = 0
        self.last_rate_check = 0
        self.last_packet_count = 0
        self.last_byte_count = 0
        self.last_increment = None
    #enddef

    def increment(self, octets):
        self.packet_count += 1
        self.byte_count += octets
        self.last_increment = lisp_get_timestamp()
    #enddef

    def recent_packet_sec(self):
        if (self.last_increment == None): return(False)
        elapsed = time.time() - self.last_increment
        return(elapsed <= 1)
    #enddef

    def recent_packet_min(self):
        if (self.last_increment == None): return(False)
        elapsed = time.time() - self.last_increment
        return(elapsed <= 60)
    #enddef

    def stat_colors(self, c1, c2, html):
        if (self.recent_packet_sec()): 
            return(green_last_sec(c1), green_last_sec(c2))
        #endif
        if (self.recent_packet_min()): 
            return(green_last_min(c1), green_last_min(c2))
        #endif
        return(c1, c2)
    #enddef

    def normalize(self, count):
        count = str(count)
        digits = len(count)
        if (digits > 12):
            count = count[0:-10] + "." + count[-10:-7] + "T"
            return(count)
        #endif
        if (digits > 9):
            count = count[0:-9] + "." + count[-9:-7] + "B"
            return(count)
        #endif
        if (digits > 6):
            count = count[0:-6] + "." + count[-6] + "M"
            return(count)
        #endif
        return(count)
    #enddef

    def get_stats(self, summary, html):
        last_rate = self.last_rate_check
        last_packets = self.last_packet_count
        last_bytes = self.last_byte_count
        self.last_rate_check = lisp_get_timestamp()
        self.last_packet_count = self.packet_count
        self.last_byte_count = self.byte_count

        rate_diff = self.last_rate_check - last_rate
        if (rate_diff == 0):
            packet_rate = 0
            bit_rate = 0
        else:
            packet_rate = int(old_div((self.packet_count - last_packets),
                rate_diff))
            bit_rate = old_div((self.byte_count - last_bytes), rate_diff)
            bit_rate = old_div((bit_rate * 8), 1000000)
            bit_rate = round(bit_rate, 2)
        #endif

        #
        # Normalize and put in string form.
        #
        packets = self.normalize(self.packet_count)
        bc = self.normalize(self.byte_count)

        #
        # The summary version gives you the string above in a pull-down html
        # menu and the title string is the string below.
        #
        if (summary):
            h = "<br>" if html else ""
            packets, bc = self.stat_colors(packets, bc, html)
            title = "packet-count: {}{}byte-count: {}".format(packets, h, bc)
            stats = "packet-rate: {} pps\nbit-rate: {} Mbps".format( \
                packet_rate, bit_rate)
            if (html != ""): stats = lisp_span(title, stats)
        else:
            prate = str(packet_rate)
            brate = str(bit_rate)
            if (html):
                packets = lisp_print_cour(packets)
                prate = lisp_print_cour(prate)
                bc = lisp_print_cour(bc)
                brate = lisp_print_cour(brate)
            #endif
            h = "<br>" if html else ", "

            stats = ("packet-count: {}{}packet-rate: {} pps{}byte-count: " + \
                "{}{}bit-rate: {} mbps").format(packets, h, prate, h, bc, h, 
                brate)
        #endif
        return(stats)
    #enddef
#endclass

#
# ETR/RTR decapsulation total packet and errors stats. Anytime a lisp_packet().
# packet_error value is added, this dictionary array needs to add the key
# string.
#
lisp_decap_stats = {
    "good-packets" : lisp_stats(), "ICV-error" : lisp_stats(), 
    "checksum-error" : lisp_stats(), "lisp-header-error" : lisp_stats(), 
    "no-decrypt-key" : lisp_stats(),  "bad-inner-version" : lisp_stats(), 
    "outer-header-error" : lisp_stats()
}

#
# This a locator record definition as defined in RFCs.
#
class lisp_rloc(object):
    def __init__(self, recurse=True):
        self.rloc = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.rloc_name = None
        self.interface = None
        self.translated_rloc = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.translated_port = 0
        self.priority = 255
        self.weight = 0
        self.mpriority = 255
        self.mweight = 0
        self.uptime = lisp_get_timestamp()
        self.state = LISP_RLOC_UP_STATE
        self.last_state_change = None
        self.rle_name = None
        self.elp_name = None
        self.geo_name = None
        self.json_name = None
        self.geo = None
        self.elp = None
        self.rle = None
        self.json = None
        self.stats = lisp_stats()
        self.last_rloc_probe = None
        self.last_rloc_probe_reply = None
        self.rloc_probe_rtt = -1
        self.recent_rloc_probe_rtts = [-1, -1, -1]
        self.rloc_probe_hops = "?/?"
        self.recent_rloc_probe_hops = ["?/?", "?/?", "?/?"]
        self.rloc_probe_latency = "?/?"
        self.recent_rloc_probe_latencies = ["?/?", "?/?", "?/?"]
        self.last_rloc_probe_nonce = 0
        self.echo_nonce_capable = False
        self.map_notify_requested = False
        self.rloc_next_hop = None
        self.next_rloc = None
        self.multicast_rloc_probe_list = {}

        if (recurse == False): return
        
        #
        # This is for a box with multiple egress interfaces. We create an
        # rloc chain, one for each <device, nh> tuple. So we can RLOC-probe
        # individually.
        #
        next_hops = lisp_get_default_route_next_hops()
        if (next_hops == [] or len(next_hops) == 1): return

        self.rloc_next_hop = next_hops[0]
        last = self
        for nh in next_hops[1::]:
            hop = lisp_rloc(False)
            hop = copy.deepcopy(self)
            hop.rloc_next_hop = nh
            last.next_rloc = hop
            last = hop
        #endfor
    #enddef

    def up_state(self):
        return(self.state == LISP_RLOC_UP_STATE)
    #enddef
        
    def unreach_state(self):
        return(self.state == LISP_RLOC_UNREACH_STATE)
    #enddef

    def no_echoed_nonce_state(self):
        return(self.state == LISP_RLOC_NO_ECHOED_NONCE_STATE)
    #enddef

    def down_state(self):
        return(self.state in \
            [LISP_RLOC_DOWN_STATE, LISP_RLOC_ADMIN_DOWN_STATE])
    #enddef

    def print_state(self):
        if (self.state is LISP_RLOC_UNKNOWN_STATE): 
            return("unknown-state")
        if (self.state is LISP_RLOC_UP_STATE): 
            return("up-state")
        if (self.state is LISP_RLOC_DOWN_STATE): 
            return("down-state")
        if (self.state is LISP_RLOC_ADMIN_DOWN_STATE): 
            return("admin-down-state")
        if (self.state is LISP_RLOC_UNREACH_STATE): 
            return("unreach-state")
        if (self.state is LISP_RLOC_NO_ECHOED_NONCE_STATE): 
            return("no-echoed-nonce-state")
        return("invalid-state")
    #enddef

    def print_rloc(self, indent):
        ts = lisp_print_elapsed(self.uptime)
        lprint("{}rloc {}, uptime {}, {}, parms {}/{}/{}/{}".format(indent, 
            red(self.rloc.print_address(), False), ts, self.print_state(), 
            self.priority, self.weight, self.mpriority, self.mweight))
    #enddef

    def print_rloc_name(self, cour=False):
        if (self.rloc_name == None): return("")
        rloc_name = self.rloc_name
        if (cour): rloc_name = lisp_print_cour(rloc_name)
        return('rloc-name: {}'.format(blue(rloc_name, cour)))
    #enddef

    def is_decent_nat_port(self):
        rn = self.rloc_name
        if (rn == None): return(False)
        if (rn.find(LISP_TP) == -1): return(False)
        return(True)
    #enddef        

    def store_decent_nat_port(self):
        if (self.is_decent_nat_port() == False): return(False)
        port = self.rloc_name.split(LISP_TP)[-1]
        self.translated_port = int(port)
        return(True)
    #enddef        

    def normalize_decent_nat_rloc_name(self):
        if (self.is_decent_nat_port() == False): return(self.rloc_name)
        rn = self.rloc_name.split(LISP_TP)[0]
        return(rn)
    #enddef        

    def store_rloc_from_record(self, rloc_record, nonce, source):
        port = LISP_DATA_PORT
        self.rloc.copy_address(rloc_record.rloc)

        if (rloc_record.rloc_name != None):
            self.rloc_name = rloc_record.rloc_name

            #
            # Store translated information for a decent-nat map-cache RLOC.
            #
            if (lisp_i_am_rtr == False):
                if (self.store_decent_nat_port()):
                    self.translated_rloc.copy_address(self.rloc)
                #endif
            #endif

            #
            # Copy to all next-hops in multi-homing case.
            #
            nh = self.next_rloc
            while (nh != None):
                nh.rloc_name = self.rloc_name
                nh = nh.next_rloc
            #endwhile
        #endif

        #
        # Store translated port if RLOC was translated by a NAT.
        #
        rloc = self.rloc
        if (rloc.is_null() == False and self.rloc_name != None):
            rn = self.normalize_decent_nat_rloc_name()
            nat_info = lisp_get_nat_info(rloc, rn)
            if (nat_info):
                port = nat_info.port
                head = lisp_nat_state_info[rn][0]
                addr_str = rloc.print_address_no_iid()
                rloc_str = red(addr_str, False)
                rloc_nstr = "" if self.rloc_name == None else \
                   blue(self.rloc_name, False)

                #
                # Don't use timed-out state. And check if the RLOC from the
                # RLOC-record is different than the youngest NAT state.
                #
                if (nat_info.timed_out()):
                    lprint(("    Matched stored NAT state timed out for " + \
                        "RLOC {}:{}, {}").format(rloc_str, port, rloc_nstr))

                    nat_info = None if (nat_info == head) else head
                    if (nat_info and nat_info.timed_out()):
                        port = nat_info.port
                        rloc_str = red(nat_info.address, False)
                        lprint(("    Youngest stored NAT state timed out " + \
                            " for RLOC {}:{}, {}").format(rloc_str, port,
                            rloc_nstr))
                        nat_info = None
                    #endif
                #endif

                #
                # Check to see if RLOC for map-cache is same RLOC for NAT
                # state info.
                #
                if (nat_info):
                    if (nat_info.address != addr_str):
                        lprint("RLOC conflict, RLOC-record {}, NAT state {}". \
                            format(rloc_str, red(nat_info.address, False)))
                        self.rloc.store_address(nat_info.address)
                    #endif
                    rloc_str = red(nat_info.address, False)
                    port = nat_info.port
                    lprint("    Use NAT translated RLOC {}:{} for {}". \
                        format(rloc_str, port, rloc_nstr))
                    self.store_translated_rloc(rloc, port)
                #endif
            #endif
        #endif

        self.geo = rloc_record.geo
        self.elp = rloc_record.elp
        self.json = rloc_record.json

        #
        # RLE nodes may be behind NATs too.
        #
        self.rle = rloc_record.rle
        if (self.rle):
            for rle_node in self.rle.rle_nodes:
                rloc_name = rle_node.rloc_name
                rn = rle_node.normalize_decent_nat_rloc_name()
                nat_info = lisp_get_nat_info(rle_node.address, rn)
                if (nat_info == None): continue

                port = nat_info.port
                rloc_name_str = rloc_name
                if (rloc_name_str): rloc_name_str = blue(rloc_name, False)

                lprint(("      Store translated encap-port {} for RLE-" + \
                    "node {}, rloc-name '{}'").format(port, 
                     rle_node.address.print_address_no_iid(), rloc_name_str))
                rle_node.translated_port = port
            #endfor
        #endif

        self.priority = rloc_record.priority
        self.mpriority = rloc_record.mpriority
        self.weight = rloc_record.weight
        self.mweight = rloc_record.mweight
        if (rloc_record.reach_bit and rloc_record.local_bit and 
            rloc_record.probe_bit == False):
            if (self.state != LISP_RLOC_UP_STATE):
                self.last_state_change = lisp_get_timestamp()
            #endif
            self.state = LISP_RLOC_UP_STATE
        #endif

        #
        # Store keys in RLOC lisp-crypto data structure.
        #
        rloc_is_source = source.is_exact_match(rloc_record.rloc) if \
            source != None else None
        if (rloc_record.keys != None and rloc_is_source):
            key = rloc_record.keys[1]
            if (key != None):
                addr_str = rloc_record.rloc.print_address_no_iid() + ":" + \
                    str(port)
                key.add_key_by_rloc(addr_str, True)
                lprint("    Store encap-keys for nonce 0x{}, RLOC {}".format( \
                    lisp_hex_string(nonce), red(addr_str, False)))
            #endif
        #endif
        return(port)
    #enddef
    
    def store_translated_rloc(self, rloc, port):
        self.rloc.copy_address(rloc)
        self.translated_rloc.copy_address(rloc)
        self.translated_port = port
        if (lisp_i_am_rtr == False):
            self.rloc_name += LISP_TP + str(port)
        #endif
    #enddef

    def is_rloc_translated(self):
        return(self.translated_rloc.is_null() == False)
    #enddef

    def rloc_exists(self):
        if (self.rloc.is_null() == False): return(True)
        if (self.rle_name or self.geo_name or self.elp_name or self.json_name):
            return(False)
        #endif
        return(True)
    #enddef

    def is_rtr(self):
        return((self.priority == 254 and self.mpriority == 255 and \
            self.weight == 0 and self.mweight == 0))
    #enddef

    def print_state_change(self, new_state):
        current_state = self.print_state()
        string = "{} -> {}".format(current_state, new_state)
        if (new_state == "up" and self.unreach_state()):
            string = bold(string, False)
        #endif
        return(string)
    #enddef

    def print_rloc_probe_rtt(self):
        if (self.rloc_probe_rtt == -1): return("none")
        return(self.rloc_probe_rtt)
    #enddef

    def print_recent_rloc_probe_rtts(self):
        rtts = str(self.recent_rloc_probe_rtts)
        rtts = rtts.replace("-1", "?")
        return(rtts)
    #enddef

    def compute_rloc_probe_rtt(self):
        last = self.rloc_probe_rtt
        self.rloc_probe_rtt = -1
        if (self.last_rloc_probe_reply == None): return
        if (self.last_rloc_probe == None): return
        self.rloc_probe_rtt = self.last_rloc_probe_reply - self.last_rloc_probe
        self.rloc_probe_rtt = round(self.rloc_probe_rtt, 3)
        last_list = self.recent_rloc_probe_rtts
        self.recent_rloc_probe_rtts = [last] + last_list[0:-1]
    #enddef

    def print_rloc_probe_hops(self):
        return(self.rloc_probe_hops)
    #enddef

    def print_recent_rloc_probe_hops(self):
        hops = str(self.recent_rloc_probe_hops)
        return(hops)
    #enddef

    def store_rloc_probe_hops(self, to_hops, from_ttl):
        if (to_hops == 0): 
            to_hops = "?"
        elif (to_hops < old_div(LISP_RLOC_PROBE_TTL, 2)):
            to_hops = "!"
        else: 
            to_hops = str(LISP_RLOC_PROBE_TTL - to_hops)
        #endif
        if (from_ttl < old_div(LISP_RLOC_PROBE_TTL, 2)):
            from_hops = "!"
        else:
            from_hops = str(LISP_RLOC_PROBE_TTL - from_ttl)
        #endif

        last = self.rloc_probe_hops
        self.rloc_probe_hops = to_hops + "/" + from_hops
        last_list = self.recent_rloc_probe_hops
        self.recent_rloc_probe_hops = [last] + last_list[0:-1]
    #enddef

    def store_rloc_probe_latencies(self, json_telemetry):
        tel = lisp_decode_telemetry(json_telemetry)

        fl = round(float(tel["etr-in"]) - float(tel["itr-out"]), 3)
        rl = round(float(tel["itr-in"]) - float(tel["etr-out"]), 3)

        last = self.rloc_probe_latency
        self.rloc_probe_latency = str(fl) + "/" + str(rl)
        last_list = self.recent_rloc_probe_latencies
        self.recent_rloc_probe_latencies = [last] + last_list[0:-1]
    #enddef

    def print_rloc_probe_latency(self):
        return(self.rloc_probe_latency)
    #enddef

    def print_recent_rloc_probe_latencies(self):
        latencies = str(self.recent_rloc_probe_latencies)
        return(latencies)
    #enddef

    def process_rloc_probe_reply(self, ts, nonce, eid, group, hc, ttl, jt):
        rloc = self
        while (True):
            if (rloc.last_rloc_probe_nonce == nonce): break
            rloc = rloc.next_rloc
            if (rloc == None): 
                lprint("    No matching nonce state found for nonce 0x{}". \
                    format(lisp_hex_string(nonce)))
                return
            #endif
        #endwhile

        #
        # Compute RTTs.
        #
        rloc.last_rloc_probe_reply = ts
        rloc.compute_rloc_probe_rtt()
        state_string = rloc.print_state_change("up")
        if (rloc.state != LISP_RLOC_UP_STATE):
            lisp_update_rtr_updown(rloc.rloc, True)
            rloc.state = LISP_RLOC_UP_STATE
            rloc.last_state_change = lisp_get_timestamp()
            mc = lisp_map_cache.lookup_cache(eid, True)
            if (mc): lisp_write_ipc_map_cache(True, mc)
        #endif

        #
        # Store hops.
        #
        rloc.store_rloc_probe_hops(hc, ttl)

        #
        # Store one-way latency if telemetry data json in Map-Reply.
        #
        if (jt): rloc.store_rloc_probe_latencies(jt)

        probe = bold("RLOC-probe reply", False)
        addr_str = rloc.rloc.print_address_no_iid()
        rtt = bold(str(rloc.print_rloc_probe_rtt()), False)
        p = ":{}".format(self.translated_port) if self.translated_port != 0 \
            else ""
        nh = ""
        if (rloc.rloc_next_hop != None):
            d, n = rloc.rloc_next_hop
            nh = ", nh {}({})".format(n, d)
        #endif
                                      
        lat = bold(rloc.print_rloc_probe_latency(), False)
        lat = ", latency {}".format(lat) if jt else ""

        e = green(lisp_print_eid_tuple(eid, group), False)

        lprint(("    Received {} from {}{} for {}, {}, rtt {}{}, " + \
            "to-ttl/from-ttl {}{}").format(probe, red(addr_str, False), p, e, 
            state_string, rtt, nh, str(hc) + "/" + str(ttl), lat))

        if (rloc.rloc_next_hop == None): return

        #
        # Now select better RTT next-hop.
        #
        rloc = None
        install = None
        while (True):
            rloc = self if rloc == None else rloc.next_rloc
            if (rloc == None): break
            if (rloc.up_state() == False): continue
            if (rloc.rloc_probe_rtt == -1): continue
            if (rloc.last_rloc_probe_nonce != nonce): continue

            if (install == None): install = rloc
            if (rloc.rloc_probe_rtt < install.rloc_probe_rtt): install = rloc
        #endwhile

        if (install != None):
            d, n = install.rloc_next_hop
            nh = bold("nh {}({})".format(n, d), False)
            lprint("    Install forwarding host-route via best {}".format(nh))
            lisp_install_host_route(addr_str, None, False)
            lisp_install_host_route(addr_str, n, True)
        #endif
    #enddef

    def add_to_rloc_probe_list(self, eid, group):
        addr_str = self.rloc.print_address_no_iid()
        port = self.translated_port
        if (port != 0): addr_str += ":" + str(port)

        if (addr_str not in lisp_rloc_probe_list):
            lisp_rloc_probe_list[addr_str] = []
        #endif

        if (group.is_null()): group.instance_id = 0
        for r, e, g in lisp_rloc_probe_list[addr_str]:
            if (e.is_exact_match(eid) and g.is_exact_match(group)):
                if (r == self): 
                    if (lisp_rloc_probe_list[addr_str] == []):
                        lisp_rloc_probe_list.pop(addr_str)
                    #endif
                    return
                #endif
                lisp_rloc_probe_list[addr_str].remove([r, e, g])
                break
            #endif
        #endfor
        lisp_rloc_probe_list[addr_str].append([self, eid, group])

        #
        # Copy reach/unreach state from first RLOC that the active RLOC-probing
        # is run on.
        #
        rloc = lisp_rloc_probe_list[addr_str][0][0]
        if (rloc.state == LISP_RLOC_UNREACH_STATE):
            self.state = LISP_RLOC_UNREACH_STATE
            self.last_state_change = lisp_get_timestamp()
        #endif
    #enddef

    def delete_from_rloc_probe_list(self, eid, group):
        addr_str = self.rloc.print_address_no_iid()
        port = self.translated_port
        if (port != 0): addr_str += ":" + str(port)
        if (addr_str not in lisp_rloc_probe_list): return

        array = []
        for entry in lisp_rloc_probe_list[addr_str]:
            if (entry[0] != self): continue
            if (entry[1].is_exact_match(eid) == False): continue
            if (entry[2].is_exact_match(group) == False): continue
            array = entry
            break
        #endfor
        if (array == []): return

        try: 
            lisp_rloc_probe_list[addr_str].remove(array)
            if (lisp_rloc_probe_list[addr_str] == []):
                lisp_rloc_probe_list.pop(addr_str)
            #endif
        except:
            return
        #endtry
    #enddef

    def print_rloc_probe_state(self, trailing_linefeed):
        output = ""
        rloc = self
        while (True):
            sent = rloc.last_rloc_probe
            if (sent == None): sent = 0
            resp = rloc.last_rloc_probe_reply
            if (resp == None): resp = 0
            rtt = rloc.print_rloc_probe_rtt()
            s = space(4)

            if (rloc.rloc_next_hop == None): 
                output += "RLOC-Probing:\n"
            else:
                d, n = rloc.rloc_next_hop
                output += "RLOC-Probing for nh {}({}):\n".format(n, d)
            #endif

            output += ("{}RLOC-probe request sent: {}\n{}RLOC-probe reply " + \
                "received: {}, rtt {}").format(s, lisp_print_elapsed(sent), 
                s, lisp_print_elapsed(resp), rtt)

            if (trailing_linefeed): output += "\n"

            rloc = rloc.next_rloc
            if (rloc == None): break
            output += "\n"
        #endwhile
        return(output)
    #enddef

    def get_encap_keys(self):
        port = "4341" if self.translated_port == 0 else \
               str(self.translated_port)
        addr_str = self.rloc.print_address_no_iid() + ":" + port

        try:
            keys = lisp_crypto_keys_by_rloc_encap[addr_str]
            if (keys[1]): return(keys[1].encrypt_key, keys[1].icv_key)
            return(None, None)
        except:
            return(None, None)
        #endtry
    #enddef

    def rloc_recent_rekey(self):
        port = "4341" if self.translated_port == 0 else \
               str(self.translated_port)
        addr_str = self.rloc.print_address_no_iid() + ":" + port

        try:
            key = lisp_crypto_keys_by_rloc_encap[addr_str][1]
            if (key == None): return(False)
            if (key.last_rekey == None): return(True)
            return(time.time() - key.last_rekey < 1)
        except:
            return(False)
        #endtry
    #enddef

    def refresh_decent_nat_rloc(self, lisp_sockets, eid):
        ts = self.last_state_change
        if (ts == None): return
        if ((time.time() - ts) <= 60): return

        e = green(eid.print_address(), False)
        r = red(self.rloc.print_address_no_iid(), False)
        rn = blue(self.rloc_name, False)
        lprint("Refresh map-cache for {} for RLOC {}, {}".format(e, r, rn))

        lisp_send_map_request(lisp_sockets, 0, None, eid, None)
    #enddef
#endclass        

class lisp_mapping(object):
    def __init__(self, eid, group, rloc_set):
        self.eid = eid
        if (eid == ""): self.eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.group = group
        if (group == ""): self.group = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.rloc_set = rloc_set
        self.best_rloc_set = []
        self.build_best_rloc_set()
        self.uptime = lisp_get_timestamp()
        self.action = LISP_NO_ACTION
        self.expires = None
        self.map_cache_ttl = None
        self.register_ttl = LISP_REGISTER_TTL
        self.last_refresh_time = self.uptime
        self.source_cache = None
        self.map_replies_sent = 0
        self.mapping_source = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.use_mr_name = "all"
        self.use_ms_name = "all"
        self.stats = lisp_stats()
        self.dynamic_eids = None
        self.checkpoint_entry = False
        self.secondary_iid = None
        self.signature_eid = False
        self.gleaned = False
        self.recent_sources = {}
        self.last_multicast_map_request = 0
        self.subscribed_eid = None
        self.subscribed_group = None
    #enddef

    def print_mapping(self, eid_indent, rloc_indent):
        ts = lisp_print_elapsed(self.uptime)
        group = "" if self.group.is_null() else \
                ", group {}".format(self.group.print_prefix())
        lprint("{}eid {}{}, uptime {}, {} rlocs:".format(eid_indent, 
           green(self.eid.print_prefix(), False), group, ts, 
           len(self.rloc_set)))
        for rloc in self.rloc_set: rloc.print_rloc(rloc_indent)
    #enddef

    def print_eid_tuple(self):
        return(lisp_print_eid_tuple(self.eid, self.group))
    #enddef

    def print_ttl(self):
        ttl = self.map_cache_ttl
        if (ttl == None): return("forever")

        if (ttl >= 3600): 
            if ((ttl % 3600) == 0): 
                ttl = str(old_div(ttl, 3600)) + " hours"
            else:
                ttl = str(ttl * 60) + " mins"
            #endif
        elif (ttl >= 60):
            if ((ttl % 60) == 0): 
                ttl = str(old_div(ttl, 60)) + " mins"
            else:
                ttl = str(ttl) + " secs"
            #endif
        else:
            ttl = str(ttl) + " secs"
        #endif
        return(ttl)
    #enddef

    def refresh(self):
        if (self.group.is_null()): return(self.refresh_unicast())
        return(self.refresh_multicast())
    #enddef

    def refresh_unicast(self):
        return(self.is_active() and self.has_ttl_elapsed() and
            self.gleaned == False)
    #enddef

    def refresh_multicast(self):

        #
        # Take uptime modulo TTL and if the value is greater than 10% of
        # TTL, refresh entry. So that is around every 13 or 14 seconds.
        #
        elapsed = int((time.time() - self.uptime) % self.map_cache_ttl)
        refresh = (elapsed in [0, 1, 2])
        if (refresh == False): return(False)

        #
        # Don't send a refreshing Map-Request if we just sent one.
        #
        rate_limit = ((time.time() - self.last_multicast_map_request) <= 2)
        if (rate_limit): return(False)

        self.last_multicast_map_request = lisp_get_timestamp()
        return(True)
    #enddef

    def has_ttl_elapsed(self):
        if (self.map_cache_ttl == None): return(False)
        elapsed = time.time() - self.last_refresh_time
        if (elapsed >= self.map_cache_ttl): return(True)

        #
        # TTL is about to elapse. We need to refresh entry if we are 90%
        # close to expiring.
        #
        almost_ttl = self.map_cache_ttl - (old_div(self.map_cache_ttl, 10))
        if (elapsed >= almost_ttl): return(True)
        return(False)
    #enddef

    def is_active(self):
        if (self.stats.last_increment == None): return(False)
        elapsed = time.time() - self.stats.last_increment
        return(elapsed <= 60)
    #enddef

    def match_eid_tuple(self, db):
        if (self.eid.is_exact_match(db.eid) == False): return(False)
        if (self.group.is_exact_match(db.group) == False): return(False)
        return(True)
    #enddef

    def sort_rloc_set(self):
        self.rloc_set.sort(key=operator.attrgetter('rloc.address'))
    #enddef

    def delete_rlocs_from_rloc_probe_list(self):
        for rloc in self.best_rloc_set: 
            rloc.delete_from_rloc_probe_list(self.eid, self.group)
        #endfor
    #enddef

    def build_best_rloc_set(self):
        old_best = self.best_rloc_set
        self.best_rloc_set = []
        if (self.rloc_set == None): return

        #
        # Get best priority for first up RLOC.
        #
        pr = 256
        for rloc in self.rloc_set: 
            if (rloc.up_state()): pr = min(rloc.priority, pr)
        #endif

        #
        # For each up RLOC with best priority, put in best-rloc for data-plane.
        # For each unreachable RLOC that has better priority than the best
        # computed above, we want to RLOC-probe. So put in the RLOC probe list
        # and best list. We need to set the timestamp last_rloc_probe or
        # lisp_process_rloc_probe_timer() will think the unreach RLOC went 
        # down and is waiting for an RLOC-probe reply (it will never get).
        #
        for rloc in self.rloc_set:
            if (rloc.priority <= pr): 
                if (rloc.unreach_state() and rloc.last_rloc_probe == None):
                    rloc.last_rloc_probe = lisp_get_timestamp()
                #endif
                self.best_rloc_set.append(rloc)
            #endif
        #endfor

        #
        # Put RLOC in lisp.lisp_rloc_probe_list if doesn't exist. And if
        # we removed the RLOC out of the best list, we need to remove 
        # references.
        #
        for rloc in old_best: 
            if (rloc.priority < pr): continue
            rloc.delete_from_rloc_probe_list(self.eid, self.group)
        #endfor
        for rloc in self.best_rloc_set: 
            if (rloc.rloc.is_null()): continue
            rloc.add_to_rloc_probe_list(self.eid, self.group)
        #endfor
    #enddef

    def select_rloc(self, lisp_packet, ipc_socket):
        packet = lisp_packet.packet
        inner_version = lisp_packet.inner_version
        length = len(self.best_rloc_set)
        if (length == 0): 
            self.stats.increment(len(packet))
            return([None, None, None, self.action, None, None])
        #endif

        ls = 4 if lisp_load_split_pings else 0
        hashval = lisp_packet.hash_ports()
        if (inner_version == 4):
            for i in range(8+ls): 
                hashval = hashval ^ struct.unpack("B", packet[i+12:i+13])[0]
            #endfor
        elif (inner_version == 6):
            for i in range(0, 32+ls, 4): 
                hashval = hashval ^ struct.unpack("I", packet[i+8:i+12])[0]
            #endfor
            hashval = (hashval >> 16) + (hashval & 0xffff)
            hashval = (hashval >> 8) + (hashval & 0xff)
        else:
            for i in range(0, 12+ls, 4):
                hashval = hashval ^ struct.unpack("I", packet[i:i+4])[0]
            #endfor
        #endif

        if (lisp_data_plane_logging):
            best = []
            for r in self.best_rloc_set: 
                if (r.rloc.is_null()): continue
                best.append([r.rloc.print_address_no_iid(), r.print_state()])
            #endfor
            dprint("Packet hash {}, index {}, best-rloc-list: {}".format( \
                hex(hashval), hashval % length, red(str(best), False)))
        #endif

        #
        # Get hashed value RLOC.
        #
        rloc = self.best_rloc_set[hashval % length]

        #
        # Check decent-nat entry that is new, return RTR rloc.
        #
        if (lisp_decent_nat and rloc.stats.packet_count == 0):
            r = self.find_rtr_rloc()
            if (r != None): rloc = r
        #endif

        #
        # IF this RLOC is not in up state but was taken out of up state by
        # not receiving echoed-nonces, try requesting again after some time.
        #
        echo_nonce = lisp_get_echo_nonce(rloc.rloc, None)
        if (echo_nonce): 
            echo_nonce.change_state(rloc)
            if (rloc.no_echoed_nonce_state()): 
                echo_nonce.request_nonce_sent = None
            #endif
        #endif

        #
        # Find a reachabile RLOC.
        #
        if (rloc.up_state() == False):
            stop = hashval % length
            index = (stop + 1) % length
            while (index != stop):
                rloc = self.best_rloc_set[index]
                if (rloc.up_state()): break
                index = (index + 1) % length
            #endwhile
            if (index == stop): 
                self.build_best_rloc_set()
                return([None, None, None, None, None, None])
            #endif
        #endif

        # 
        # We are going to use this RLOC. Increment statistics.
        #
        rloc.stats.increment(len(packet))

        #
        # Give RLE preference.
        #
        if (rloc.rle_name and rloc.rle == None): 
            if (rloc.rle_name in lisp_rle_list):
                rloc.rle = lisp_rle_list[rloc.rle_name]
            #endif
        #endif
        if (rloc.rle): return([None, None, None, None, rloc.rle, None])

        #
        # Next check if ELP is cached for this RLOC entry.
        #
        if (rloc.elp and rloc.elp.use_elp_node):
            return([rloc.elp.use_elp_node.address, None, None, None, None,
                None])
        #endif

        #
        # Return RLOC address.
        #
        rloc_addr = None if (rloc.rloc.is_null()) else rloc.rloc
        port = rloc.translated_port
        action = self.action if (rloc_addr == None) else None

        #
        # Check to see if we are requesting an nonce to be echoed, or we are
        # echoing a nonce.
        #
        nonce = None
        if (echo_nonce and echo_nonce.request_nonce_timeout() == False):
            nonce = echo_nonce.get_request_or_echo_nonce(ipc_socket, rloc_addr)
        #endif

        #
        # If no RLOC address, check for native-forward.
        #
        return([rloc_addr, port, nonce, action, None, rloc])
    #enddef

    def do_rloc_sets_match(self, rloc_address_set):
        if (len(self.rloc_set) != len(rloc_address_set)): return(False)

        #
        # Compare an array of lisp_address()es with the lisp_mapping() 
        # rloc-set which is an array of lisp_rloc()s.
        #
        for rloc_entry in self.rloc_set:
            for rloc in rloc_address_set:
                if (rloc.is_exact_match(rloc_entry.rloc) == False): continue
                rloc = None
                break
            #endfor
            if (rloc == rloc_address_set[-1]): return(False)
        #endfor
        return(True)
    #enddef
    
    def get_rloc(self, rloc):
        for rloc_entry in self.rloc_set:
            r = rloc_entry.rloc
            if (rloc.is_exact_match(r)): return(rloc_entry)
        #endfor
        return(None)
    #enddef

    def get_rloc_by_interface(self, interface):
        for rloc_entry in self.rloc_set:
            if (rloc_entry.interface == interface): return(rloc_entry)
        #endfor
        return(None)
    #enddef

    def add_db(self):
        if (self.group.is_null()):
            lisp_db_for_lookups.add_cache(self.eid, self)
        else:
            db = lisp_db_for_lookups.lookup_cache(self.group, True)
            if (db == None): 
                db = lisp_mapping(self.group, self.group, [])
                lisp_db_for_lookups.add_cache(self.group, db)
            #endif
            db.add_source_entry(self)
        #endif
    #enddef

    def add_cache(self, do_ipc=True):
        if (self.group.is_null()):
            lisp_map_cache.add_cache(self.eid, self)
            if (lisp_program_hardware): lisp_program_vxlan_hardware(self)
        else:
            mc = lisp_map_cache.lookup_cache(self.group, True)
            if (mc == None): 
                mc = lisp_mapping(self.group, self.group, [])
                mc.eid.copy_address(self.group)
                mc.group.copy_address(self.group)
                lisp_map_cache.add_cache(self.group, mc)
            #endif
            if (self.eid.is_null()): self.eid.make_default_route(mc.group)
            mc.add_source_entry(self)
        #endif
        if (do_ipc): lisp_write_ipc_map_cache(True, self)
    #enddef

    def delete_cache(self):
        self.delete_rlocs_from_rloc_probe_list()
        lisp_write_ipc_map_cache(False, self)

        if (self.group.is_null()):
            lisp_map_cache.delete_cache(self.eid)
            if (lisp_program_hardware): 
                prefix = self.eid.print_prefix_no_iid()
                os.system("ip route delete {}".format(prefix))
            #endif
        else:
            mc = lisp_map_cache.lookup_cache(self.group, True)
            if (mc == None): return

            smc = mc.lookup_source_cache(self.eid, True)
            if (smc == None): return

            mc.source_cache.delete_cache(self.eid)
            if (mc.source_cache.cache_size() == 0): 
                lisp_map_cache.delete_cache(self.group)
            #endif
        #endif
    #enddef

    def add_source_entry(self, source_mc):
        if (self.source_cache == None): self.source_cache = lisp_cache()
        self.source_cache.add_cache(source_mc.eid, source_mc)
    #enddef
        
    def lookup_source_cache(self, source, exact):
        if (self.source_cache == None): return(None)
        return(self.source_cache.lookup_cache(source, exact))
    #enddef

    def dynamic_eid_configured(self):
        return(self.dynamic_eids != None)
    #enddef

    def star_secondary_iid(self, prefix):
        if (self.secondary_iid == None): return(prefix)
        iid = "," + str(self.secondary_iid)
        return(prefix.replace(iid, iid + "*"))
    #enddef

    def increment_decap_stats(self, packet):
        port = packet.udp_dport
        if (port == LISP_DATA_PORT):
            rloc = self.get_rloc(packet.outer_dest)
        else:

            #
            # Only works with one translated RLOC.
            #
            for rloc in self.rloc_set:
                if (rloc.translated_port != 0): break
            #endfor
        #endif
        if (rloc != None): rloc.stats.increment(len(packet.packet))
        self.stats.increment(len(packet.packet))
    #enddef

    def rtrs_in_rloc_set(self):
        for rloc in self.rloc_set:
            if (rloc.is_rtr()): return(True)
        #endfor
        return(False)
    #enddef

    def add_recent_source(self, source):
        self.recent_sources[source.print_address()] = lisp_get_timestamp()
    #enddef

    def find_rtr_rloc(self):

        #
        # Find RTR when a decent-nat RLOC was just created. This deals with the
        # "you must send before you can receive". Use the RTR to get packet to
        # the ETR so it can do a map-cache lookup on the ITR to get tranlsated
        # addressing. Return None if no RTR found in rloc-set.
        #
        for rloc in self.rloc_set:
            if (rloc.is_rtr() and rloc.up_state()):
                if (rloc.stats.packet_count <= 4): return(rloc)
            #endif
        #endfor
        return(None)
    #enddef

#endclass

class lisp_dynamic_eid(object):
    def __init__(self):
        self.dynamic_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.uptime = lisp_get_timestamp()
        self.interface = None
        self.last_packet = None
        self.timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
    #enddef

    def get_timeout(self, interface):
        try:
            lisp_interface = lisp_myinterfaces[interface]
            self.timeout = lisp_interface.dynamic_eid_timeout
        except:
            self.timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
        #endtry
    #enddef
#endclass

class lisp_group_mapping(object):
    def __init__(self, group_name, ms_name, group_prefix, sources, rle_addr):
        self.group_name = group_name
        self.group_prefix = group_prefix
        self.use_ms_name = ms_name
        self.sources = sources
        self.rle_address = rle_addr
    #enddef

    def add_group(self):
        lisp_group_mapping_list[self.group_name] = self
    #enddef
#endclass

#
# lisp_is_group_more_specific
#
# Take group address in string format and see if it is more specific than
# the group-prefix in class lisp_group_mapping(). If more specific, return
# mask-length, otherwise return -1.
#
def lisp_is_group_more_specific(group_str, group_mapping):
    iid = group_mapping.group_prefix.instance_id
    mask_len = group_mapping.group_prefix.mask_len
    group = lisp_address(LISP_AFI_IPV4, group_str, 32, iid)
    if (group.is_more_specific(group_mapping.group_prefix)): return(mask_len)
    return(-1)
#enddef

#
# lisp_lookup_group
#
# Lookup group address in lisp_group_mapping_list{}.
#
def lisp_lookup_group(group):
    best = None
    for gm in list(lisp_group_mapping_list.values()):
        mask_len = lisp_is_group_more_specific(group, gm)
        if (mask_len == -1): continue
        if (best == None or mask_len > best.group_prefix.mask_len): best = gm
    #endfor
    return(best)
#enddef

lisp_site_flags = {
    "P": "ETR is {}Requesting Map-Server to Proxy Map-Reply",
    "S": "ETR is {}LISP-SEC capable",
    "I": "xTR-ID and site-ID are {}included in Map-Register",
    "T": "Use Map-Register TTL field to timeout registration is {}set",
    "R": "Merging registrations are {}requested",
    "M": "ETR is {}a LISP Mobile-Node",
    "N": "ETR is {}requesting Map-Notify messages from Map-Server"
}

class lisp_site(object):
    def __init__(self):
        self.site_name = ""
        self.description = ""
        self.shutdown = False
        self.auth_sha1_or_sha2 = False
        self.auth_key = {}
        self.encryption_key = None
        self.allowed_prefixes = {}
        self.allowed_prefixes_sorted = []
        self.allowed_rlocs = {}
        self.map_notifies_sent = 0
        self.map_notify_acks_received = 0
    #enddef
#endclass

class lisp_site_eid(object):
    def __init__(self, site):
        self.site = site
        self.eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.group = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.first_registered = 0
        self.last_registered = 0
        self.last_registerer = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.register_ttl = LISP_SITE_TIMEOUT_CHECK_INTERVAL * 3
        self.registered = False
        self.registered_rlocs = []
        self.auth_sha1_or_sha2 = False
        self.individual_registrations = {}
        self.map_registers_received = 0
        self.proxy_reply_requested = False
        self.force_proxy_reply = False
        self.force_nat_proxy_reply = False
        self.force_ttl = None
        self.pitr_proxy_reply_drop = False
        self.proxy_reply_action = ""
        self.lisp_sec_present = False
        self.map_notify_requested = False
        self.mobile_node_requested = False
        self.echo_nonce_capable = False
        self.use_register_ttl_requested = False
        self.merge_register_requested = False
        self.xtr_id_present = False
        self.xtr_id = 0
        self.site_id = 0
        self.accept_more_specifics = False
        self.parent_for_more_specifics = None
        self.dynamic = False
        self.more_specific_registrations = []
        self.source_cache = None
        self.inconsistent_registration = False
        self.policy = None
        self.require_signature = False
        self.encrypt_json = False
    #enddef

    def print_eid_tuple(self):
        return(lisp_print_eid_tuple(self.eid, self.group))
    #enddef

    def print_flags(self, html):
        if (html == False):
            output = "{}-{}-{}-{}-{}-{}-{}".format( \
                "P" if self.proxy_reply_requested else "p",
                "S" if self.lisp_sec_present else "s",
                "I" if self.xtr_id_present else "i",
                "T" if self.use_register_ttl_requested else "t",
                "R" if self.merge_register_requested else "r",
                "M" if self.mobile_node_requested else "m",
                "N" if self.map_notify_requested else "n")
        else:
            bits = self.print_flags(False)
            bits = bits.split("-")
            output = ""
            for bit in bits:
                bit_str = lisp_site_flags[bit.upper()]
                bit_str = bit_str.format("" if bit.isupper() else "not ")
                output += lisp_span(bit, bit_str)
                if (bit.lower() != "n"): output += "-"
            #endfor
        #endif
        return(output)
    #enddef

    def copy_state_to_parent(self, child):
        self.xtr_id = child.xtr_id
        self.site_id = child.site_id
        self.first_registered = child.first_registered
        self.last_registered = child.last_registered
        self.last_registerer = child.last_registerer
        self.register_ttl = child.register_ttl
        if (self.registered == False):
            self.first_registered = lisp_get_timestamp()
        #endif
        self.auth_sha1_or_sha2 = child.auth_sha1_or_sha2
        self.registered = child.registered
        self.proxy_reply_requested = child.proxy_reply_requested
        self.lisp_sec_present = child.lisp_sec_present
        self.xtr_id_present = child.xtr_id_present
        self.use_register_ttl_requested = child.use_register_ttl_requested
        self.merge_register_requested = child.merge_register_requested
        self.mobile_node_requested = child.mobile_node_requested
        self.map_notify_requested = child.map_notify_requested
    #enddef

    def build_sort_key(self):
        sort_cache = lisp_cache()
        ml, key = sort_cache.build_key(self.eid)
        gkey = ""
        if (self.group.is_null() == False):
            gml, gkey = sort_cache.build_key(self.group)
            gkey = "-" + gkey[0:12] + "-" + str(gml) + "-" + gkey[12::]
        #endif
        key = key[0:12] + "-" + str(ml) + "-" + key[12::] + gkey
        del(sort_cache)
        return(key)
    #enddef

    def merge_in_site_eid(self, child):
        rle_changed = False
        if (self.group.is_null()):
            self.merge_rlocs_in_site_eid()
        else:
            rle_changed = self.merge_rles_in_site_eid()
        #endif

        #
        # If a child registration was passed, copy some fields to the parent
        # copy.
        #
        if (child != None):
            self.copy_state_to_parent(child)
            self.map_registers_received += 1
        #endif
        return(rle_changed)
    #enddef

    def copy_rloc_records(self):
        new_list = []
        for rloc_entry in self.registered_rlocs:
            new_list.append(copy.deepcopy(rloc_entry))
        #endfor
        return(new_list)
    #enddef

    def merge_rlocs_in_site_eid(self):
        self.registered_rlocs = []
        for site_eid in list(self.individual_registrations.values()):
            if (self.site_id != site_eid.site_id): continue
            if (site_eid.registered == False): continue
            self.registered_rlocs += site_eid.copy_rloc_records()
        #endfor

        #
        # Remove duplicate RLOC addresses if multiple ETRs registered with
        # the same RTR-set.
        #
        new_list = []
        for rloc_entry in self.registered_rlocs:
            if (rloc_entry.rloc.is_null() or len(new_list) == 0):
                new_list.append(rloc_entry)
                continue
            #endif
            for re in new_list:
                if (re.rloc.is_null()): continue
                if (rloc_entry.rloc.is_exact_match(re.rloc)): break
            #endfor
            if (re == new_list[-1]): new_list.append(rloc_entry)
        #endfor
        self.registered_rlocs = new_list

        #
        # Removal case.
        #
        if (len(self.registered_rlocs) == 0): self.registered = False
        return
    #enddef

    def merge_rles_in_site_eid(self):

        #
        # Build temporary old list of RLE nodes in dictionary array.
        #
        old_rle = {}
        for rloc_entry in self.registered_rlocs:
            if (rloc_entry.rle == None): continue
            for rle_node in rloc_entry.rle.rle_nodes:
                addr = rle_node.address.print_address_no_iid()
                old_rle[addr] = rle_node.address
            #endfor
            break
        #endif

        #
        # Merge in all RLOC entries of an RLOC-set.
        #
        self.merge_rlocs_in_site_eid()

        #
        # Remove RLEs that were added as RLOC-records in merge_rlocs_in_
        # site_eid(). We only care about the first RLE that is the merged
        # set of all the individual registered RLEs. We assume this appears
        # first and that all subsequent RLOC-records are the RTR list for
        # each registering ETR.
        #
        new_rloc_list = []
        for rloc_entry in self.registered_rlocs:
            if (self.registered_rlocs.index(rloc_entry) == 0):
                new_rloc_list.append(rloc_entry)
                continue
            #endif
            if (rloc_entry.rle == None): new_rloc_list.append(rloc_entry)
        #endfor
        self.registered_rlocs = new_rloc_list

        #
        # Merge RLEs from individuals into master copy and make a temporary
        # new_rle list to compare with old_rle. If there is a RLOC-name for
        # the RLE, clear it from the merged registration. We want names to
        # be per RLE entry and not the RLOC record entry it resides in.
        #
        rle = lisp_rle("")
        new_rle = {}
        rloc_name = None
        for site_eid in list(self.individual_registrations.values()):
            if (site_eid.registered == False): continue
            irle = site_eid.registered_rlocs[0].rle
            if (irle == None): continue

            rloc_name = site_eid.registered_rlocs[0].rloc_name
            for irle_node in irle.rle_nodes:
                addr = irle_node.address.print_address_no_iid()
                if (addr in new_rle): break

                rle_node = lisp_rle_node()
                rle_node.address.copy_address(irle_node.address)
                rle_node.level = irle_node.level
                rle_node.rloc_name = rloc_name
                rle.rle_nodes.append(rle_node)
                new_rle[addr] = irle_node.address
            #endfor
        #endfor

        # 
        # Store new copy.
        #
        if (len(rle.rle_nodes) == 0): rle = None
        if (len(self.registered_rlocs) != 0): 
            self.registered_rlocs[0].rle = rle
            if (rloc_name): self.registered_rlocs[0].rloc_name = None
        #endif

        #
        # Check for changes.
        #
        if (list(old_rle.keys()) == list(new_rle.keys())): return(False)

        lprint("{} {} from {} to {}".format( \
            green(self.print_eid_tuple(), False), bold("RLE change", False), 
            list(old_rle.keys()), list(new_rle.keys())))

        return(True)
    #enddef

    def add_cache(self):
        if (self.group.is_null()):
            lisp_sites_by_eid.add_cache(self.eid, self)
        else:
            se = lisp_sites_by_eid.lookup_cache(self.group, True)
            if (se == None): 
                se = lisp_site_eid(self.site)
                se.eid.copy_address(self.group)
                se.group.copy_address(self.group)
                lisp_sites_by_eid.add_cache(self.group, se)

                #
                # See lisp_site_eid_lookup() for special case details for
                # longest match looks for (S,G) entries.
                #
                se.parent_for_more_specifics = self.parent_for_more_specifics
            #endif
            if (self.eid.is_null()): self.eid.make_default_route(se.group)
            se.add_source_entry(self)
        #endif
    #enddef

    def delete_cache(self):
        if (self.group.is_null()):
            lisp_sites_by_eid.delete_cache(self.eid)
        else:
            se = lisp_sites_by_eid.lookup_cache(self.group, True)
            if (se == None): return

            site_eid = se.lookup_source_cache(self.eid, True)
            if (site_eid == None): return

            if (se.source_cache == None): return

            se.source_cache.delete_cache(self.eid)
            if (se.source_cache.cache_size() == 0): 
                lisp_sites_by_eid.delete_cache(self.group)
            #endif
        #endif
    #enddef

    def add_source_entry(self, source_se):
        if (self.source_cache == None): self.source_cache = lisp_cache()
        self.source_cache.add_cache(source_se.eid, source_se)
    #enddef
        
    def lookup_source_cache(self, source, exact):
        if (self.source_cache == None): return(None)
        return(self.source_cache.lookup_cache(source, exact))
    #enddef

    def is_star_g(self):
        if (self.group.is_null()): return(False)
        return(self.eid.is_exact_match(self.group))
    #enddef

    def eid_record_matches(self, eid_record):
        if (self.eid.is_exact_match(eid_record.eid) == False): return(False)
        if (eid_record.group.is_null()): return(True)
        return(eid_record.group.is_exact_match(self.group))
    #enddef

    def inherit_from_ams_parent(self):
        parent = self.parent_for_more_specifics
        if (parent == None): return
        self.force_proxy_reply = parent.force_proxy_reply
        self.force_nat_proxy_reply = parent.force_nat_proxy_reply
        self.force_ttl = parent.force_ttl
        self.pitr_proxy_reply_drop = parent.pitr_proxy_reply_drop
        self.proxy_reply_action = parent.proxy_reply_action
        self.echo_nonce_capable = parent.echo_nonce_capable
        self.policy = parent.policy
        self.require_signature = parent.require_signature
        self.encrypt_json = parent.encrypt_json
    #enddef

    def rtrs_in_rloc_set(self):
        for rloc_entry in self.registered_rlocs: 
            if (rloc_entry.is_rtr()): return(True)
        #endfor
        return(False)
    #enddef

    def is_rtr_in_rloc_set(self, rtr_rloc):
        for rloc_entry in self.registered_rlocs: 
            if (rloc_entry.rloc.is_exact_match(rtr_rloc) == False): continue
            if (rloc_entry.is_rtr()): return(True)
        #endfor
        return(False)
    #enddef

    def is_rloc_in_rloc_set(self, rloc):
        for rloc_entry in self.registered_rlocs: 
            if (rloc_entry.rle):
                for rle in rloc_entry.rle.rle_nodes:
                    if (rle.address.is_exact_match(rloc)): return(True)
                #endif
            #endif
            if (rloc_entry.rloc.is_exact_match(rloc)): return(True)
        #endfor
        return(False)
    #enddef

    def do_rloc_sets_match(self, prev_rloc_set):
        if (len(self.registered_rlocs) != len(prev_rloc_set)): return(False)

        for rloc_entry in prev_rloc_set:
            old_rloc = rloc_entry.rloc
            if (self.is_rloc_in_rloc_set(old_rloc) == False): return(False)
        #endfor
        return(True)
    #enddef
#endclass

class lisp_mr(object):
    def __init__(self, addr_str, dns_name, mr_name):
        self.mr_name = mr_name if (mr_name != None) else "all"
        self.dns_name = dns_name
        self.map_resolver = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.last_dns_resolve = None
        self.a_record_index = 0
        if (addr_str): 
            self.map_resolver.store_address(addr_str)
            self.insert_mr()
        else:
            self.resolve_dns_name()
        #endif
        self.last_used = 0
        self.last_reply = 0
        self.last_nonce = 0
        self.map_requests_sent = 0
        self.neg_map_replies_received = 0
        self.total_rtt = 0
    #enddef

    def resolve_dns_name(self):
        if (self.dns_name == None): return
        if (self.last_dns_resolve and 
            time.time() - self.last_dns_resolve < 30): return

        try:
            addresses = socket.gethostbyname_ex(self.dns_name)
            self.last_dns_resolve = lisp_get_timestamp()
            a_records = addresses[2]
        except:
            return
        #endtry

        #
        # Check if number of A-records have changed and this one is no longer
        # valid.
        #
        if (len(a_records) <= self.a_record_index):
            self.delete_mr()
            return
        #endif

        addr = a_records[self.a_record_index]
        if (addr != self.map_resolver.print_address_no_iid()):
            self.delete_mr()
            self.map_resolver.store_address(addr)
            self.insert_mr()
        #endif

        #
        # If pull-based decent DNS suffix, then create other lisp_mr() for
        # all A-records. Only have master to this (A-record index 0).
        #
        if (lisp_is_decent_dns_suffix(self.dns_name) == False): return
        if (self.a_record_index != 0): return
        
        for addr in a_records[1::]:
            a = lisp_address(LISP_AFI_NONE, addr, 0, 0)
            mr = lisp_get_map_resolver(a, None)
            if (mr != None and mr.a_record_index == a_records.index(addr)):
                continue
            #endif
            mr = lisp_mr(addr, None, None)
            mr.a_record_index = a_records.index(addr)
            mr.dns_name = self.dns_name
            mr.last_dns_resolve = lisp_get_timestamp()
        #endfor

        #
        # Check for deletes.
        #
        delete_list = []
        for mr in list(lisp_map_resolvers_list.values()):
            if (self.dns_name != mr.dns_name): continue
            a = mr.map_resolver.print_address_no_iid()
            if (a in a_records): continue
            delete_list.append(mr)
        #endfor
        for mr in delete_list: mr.delete_mr()
    #enddef

    def insert_mr(self):
        key = self.mr_name + self.map_resolver.print_address()
        lisp_map_resolvers_list[key] = self
    #enddef
                    
    def delete_mr(self):
        key = self.mr_name + self.map_resolver.print_address()
        if (key not in lisp_map_resolvers_list): return
        lisp_map_resolvers_list.pop(key)
    #enddef
#endclass

class lisp_ddt_root(object):
    def __init__(self):
        self.root_address = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.public_key = ""
        self.priority = 0
        self.weight = 0
    #enddef
#endclass        

class lisp_referral(object):
    def __init__(self):
        self.eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.group = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.referral_set = {}
        self.referral_type = LISP_DDT_ACTION_NULL
        self.referral_source = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.referral_ttl = 0
        self.uptime = lisp_get_timestamp()
        self.expires = 0
        self.source_cache = None
    #enddef

    def print_referral(self, eid_indent, referral_indent):
        uts = lisp_print_elapsed(self.uptime)
        ets = lisp_print_future(self.expires)
        lprint("{}Referral EID {}, uptime/expires {}/{}, {} referrals:". \
            format(eid_indent, green(self.eid.print_prefix(), False), uts, 
            ets, len(self.referral_set)))

        for ref_node in list(self.referral_set.values()):
            ref_node.print_ref_node(referral_indent)
        #endfor
    #enddef

    def print_referral_type(self):
        if (self.eid.afi == LISP_AFI_ULTIMATE_ROOT): return("root")
        if (self.referral_type == LISP_DDT_ACTION_NULL): 
            return("null-referral")
        #endif
        if (self.referral_type == LISP_DDT_ACTION_SITE_NOT_FOUND): 
            return("no-site-action")
        #endif
        if (self.referral_type > LISP_DDT_ACTION_MAX):
            return("invalid-action")
        #endif
        return(lisp_map_referral_action_string[self.referral_type])
    #enddef

    def print_eid_tuple(self):
        return(lisp_print_eid_tuple(self.eid, self.group))
    #enddef

    def print_ttl(self):
        ttl = self.referral_ttl
        if (ttl < 60): return(str(ttl) + " secs")

        if ((ttl % 60) == 0): 
            ttl = str(old_div(ttl, 60)) + " mins"
        else:
            ttl = str(ttl) + " secs"
        #endif
        return(ttl)
    #enddef

    def is_referral_negative(self):
        return (self.referral_type in \
            (LISP_DDT_ACTION_MS_NOT_REG, LISP_DDT_ACTION_DELEGATION_HOLE,
            LISP_DDT_ACTION_NOT_AUTH))
    #enddef

    def add_cache(self):
        if (self.group.is_null()):
            lisp_referral_cache.add_cache(self.eid, self)
        else:
            ref = lisp_referral_cache.lookup_cache(self.group, True)
            if (ref == None): 
                ref = lisp_referral()
                ref.eid.copy_address(self.group)
                ref.group.copy_address(self.group)
                lisp_referral_cache.add_cache(self.group, ref)
            #endif
            if (self.eid.is_null()): self.eid.make_default_route(ref.group)
            ref.add_source_entry(self)
        #endif
    #enddef

    def delete_cache(self):
        if (self.group.is_null()):
            lisp_referral_cache.delete_cache(self.eid)
        else:
            ref = lisp_referral_cache.lookup_cache(self.group, True)
            if (ref == None): return

            sref = ref.lookup_source_cache(self.eid, True)
            if (sref == None): return

            ref.source_cache.delete_cache(self.eid)
            if (ref.source_cache.cache_size() == 0): 
                lisp_referral_cache.delete_cache(self.group)
            #endif
        #endif
    #enddef

    def add_source_entry(self, source_ref):
        if (self.source_cache == None): self.source_cache = lisp_cache()
        self.source_cache.add_cache(source_ref.eid, source_ref)
    #enddef
        
    def lookup_source_cache(self, source, exact):
        if (self.source_cache == None): return(None)
        return(self.source_cache.lookup_cache(source, exact))
    #enddef
#endclass

class lisp_referral_node(object):
    def __init__(self):
        self.referral_address = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.priority = 0
        self.weight = 0
        self.updown = True
        self.map_requests_sent = 0
        self.no_responses = 0
        self.uptime = lisp_get_timestamp()
    #enddef

    def print_ref_node(self, indent):
        ts = lisp_print_elapsed(self.uptime)
        lprint("{}referral {}, uptime {}, {}, priority/weight: {}/{}".format( \
            indent, red(self.referral_address.print_address(), False), ts, 
            "up" if self.updown else "down", self.priority, self.weight))
    #enddef
#endclass

class lisp_ms(object):
    def __init__(self, addr_str, dns_name, ms_name, alg_id, key_id, pw, pr, 
        mr, rr, wmn, site_id, ekey_id, ekey):
        self.ms_name = ms_name if (ms_name != None) else "all"
        self.dns_name = dns_name
        self.map_server = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.last_dns_resolve = None
        self.a_record_index = 0
        if (lisp_map_servers_list == {}):
            self.xtr_id = lisp_get_control_nonce()
        else:
            self.xtr_id = list(lisp_map_servers_list.values())[0].xtr_id
        #endif
        self.alg_id = alg_id
        self.key_id = key_id
        self.password = pw
        self.proxy_reply = pr
        self.merge_registrations = mr
        self.refresh_registrations = rr
        self.want_map_notify = wmn
        self.site_id = site_id
        self.map_registers_sent = 0
        self.map_registers_multicast_sent = 0
        self.map_notifies_received = 0
        self.map_notify_acks_sent = 0
        self.ekey_id = ekey_id
        self.ekey = ekey
        if (addr_str): 
            self.map_server.store_address(addr_str)
            self.insert_ms()
        else:
            self.resolve_dns_name()
        #endif
    #enddef

    def resolve_dns_name(self):
        if (self.dns_name == None): return
        if (self.last_dns_resolve and 
            time.time() - self.last_dns_resolve < 30): return

        try:
            addresses = socket.gethostbyname_ex(self.dns_name)
            self.last_dns_resolve = lisp_get_timestamp()
            a_records = addresses[2]
        except:
            return
        #endtry

        #
        # Check if number of A-records have changed and this one is no longer
        # valid.
        #
        if (len(a_records) <= self.a_record_index):
            self.delete_ms()
            return
        #endif

        addr = a_records[self.a_record_index]
        if (addr != self.map_server.print_address_no_iid()):
            self.delete_ms()
            self.map_server.store_address(addr)
            self.insert_ms()
        #endif

        #
        # If pull-based decent DNS suffix, then create other lisp_ms() for
        # all A-records. Only have master to this (A-record index 0).
        #
        if (lisp_is_decent_dns_suffix(self.dns_name) == False): return
        if (self.a_record_index != 0): return
        
        for addr in a_records[1::]:
            a = lisp_address(LISP_AFI_NONE, addr, 0, 0)
            ms = lisp_get_map_server(a)
            if (ms != None and ms.a_record_index == a_records.index(addr)):
                continue
            #endif
            ms = copy.deepcopy(self)
            ms.map_server.store_address(addr)
            ms.a_record_index = a_records.index(addr)
            ms.last_dns_resolve = lisp_get_timestamp()
            ms.insert_ms()
        #endfor

        #
        # Check for deletes.
        #
        delete_list = []
        for ms in list(lisp_map_servers_list.values()):
            if (self.dns_name != ms.dns_name): continue
            a = ms.map_server.print_address_no_iid()
            if (a in a_records): continue
            delete_list.append(ms)
        #endfor
        for ms in delete_list: ms.delete_ms()
    #enddef

    def insert_ms(self):
        key = self.ms_name + self.map_server.print_address()
        lisp_map_servers_list[key] = self
    #enddef
                    
    def delete_ms(self):
        key = self.ms_name + self.map_server.print_address()
        if (key not in lisp_map_servers_list): return
        lisp_map_servers_list.pop(key)
    #enddef
#endclass

class lisp_interface(object):
    def __init__(self, device):
        self.interface_name = ""
        self.device = device
        self.instance_id = None
        self.bridge_socket = None
        self.raw_socket = None
        self.dynamic_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
        self.dynamic_eid_device = None
        self.dynamic_eid_timeout = LISP_DEFAULT_DYN_EID_TIMEOUT
        self.multi_tenant_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
    #enddef

    def add_interface(self):
        lisp_myinterfaces[self.device] = self
    #enddef
        
    def get_instance_id(self):
        return(self.instance_id)
    #enddef
        
    def get_socket(self):
        return(self.raw_socket)
    #enddef
    
    def get_bridge_socket(self):
        return(self.bridge_socket)
    #enddef
    
    def does_dynamic_eid_match(self, eid):
        if (self.dynamic_eid.is_null()): return(False)
        return(eid.is_more_specific(self.dynamic_eid))
    #enddef

    def set_socket(self, device):
         s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
         s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
         try:
             s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, device)
         except:
             s.close()
             s = None
         #endtry
         self.raw_socket = s
    #enddef

    def set_bridge_socket(self, device):
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
        try:
            s = s.bind((device, 0))
            self.bridge_socket = s
        except:
            return
        #endtry
    #enddef
#endclass

class lisp_datetime(object):
    def __init__(self, datetime_str):
        self.datetime_name = datetime_str
        self.datetime = None
        self.parse_datetime()
    #enddef

    def valid_datetime(self):
        ds = self.datetime_name
        if (ds.find(":") == -1): return(False)
        if (ds.find("-") == -1): return(False)
        year, month, day, time = ds[0:4], ds[5:7], ds[8:10], ds[11::]

        if ((year + month + day).isdigit() == False): return(False)
        if (month < "01" and month > "12"): return(False)
        if (day < "01" and day > "31"): return(False)

        hour, mi, sec = time.split(":")

        if ((hour + mi + sec).isdigit() == False): return(False)
        if (hour < "00" and hour > "23"): return(False)
        if (mi < "00" and mi > "59"): return(False)
        if (sec < "00" and sec > "59"): return(False)
        return(True)
    #enddef

    def parse_datetime(self):
        dt = self.datetime_name
        dt = dt.replace("-", "")
        dt = dt.replace(":", "")
        self.datetime = int(dt)
    #enddef

    def now(self):
        ts = datetime.datetime.now().strftime("%Y-%m-%d-%H:%M:%S")
        ts = lisp_datetime(ts)
        return(ts)
    #enddef

    def print_datetime(self):
        return(self.datetime_name)
    #enddef

    def future(self):
        return(self.datetime > self.now().datetime)
    #enddef

    def past(self):
        return(self.future() == False)
    #enddef

    def now_in_range(self, upper):
        return(self.past() and upper.future())
    #enddef

    def this_year(self):
        now = str(self.now().datetime)[0:4]
        ts = str(self.datetime)[0:4]
        return(ts == now)
    #enddef

    def this_month(self):
        now = str(self.now().datetime)[0:6]
        ts = str(self.datetime)[0:6]
        return(ts == now)
    #enddef

    def today(self):
        now = str(self.now().datetime)[0:8]
        ts = str(self.datetime)[0:8]
        return(ts == now)
    #enddef
#endclass

#
# Policy data structures.
#
class lisp_policy_match(object):
    def __init__(self):
        self.source_eid = None
        self.dest_eid = None
        self.source_rloc = None
        self.dest_rloc = None
        self.rloc_record_name = None
        self.geo_name = None
        self.elp_name = None
        self.rle_name = None
        self.json_name = None
        self.datetime_lower = None
        self.datetime_upper = None
#endclass

class lisp_policy(object):
    def __init__(self, policy_name):
        self.policy_name = policy_name
        self.match_clauses = []
        self.set_action = None
        self.set_record_ttl = None
        self.set_source_eid = None
        self.set_dest_eid = None
        self.set_rloc_address = None
        self.set_rloc_record_name = None
        self.set_geo_name = None
        self.set_elp_name = None
        self.set_rle_name = None
        self.set_json_name = None
    #enddef
   
    def match_policy_map_request(self, mr, srloc):
        for m in self.match_clauses:
            p = m.source_eid
            t = mr.source_eid
            if (p and t and t.is_more_specific(p) == False): continue

            p = m.dest_eid
            t = mr.target_eid
            if (p and t and t.is_more_specific(p) == False): continue

            p = m.source_rloc
            t = srloc
            if (p and t and t.is_more_specific(p) == False): continue
            l = m.datetime_lower
            u = m.datetime_upper
            if (l and u and l.now_in_range(u) == False): continue
            return(True)
        #endfor
        return(False)
    #enddef

    def set_policy_map_reply(self):
        all_none = (self.set_rloc_address == None and 
            self.set_rloc_record_name == None and self.set_geo_name == None and
            self.set_elp_name == None and self.set_rle_name == None)
        if (all_none): return(None)

        rloc = lisp_rloc()
        if (self.set_rloc_address): 
            rloc.rloc.copy_address(self.set_rloc_address)
            addr = rloc.rloc.print_address_no_iid()
            lprint("Policy set-rloc-address to {}".format(addr))
        #endif
        if (self.set_rloc_record_name): 
            rloc.rloc_name = self.set_rloc_record_name
            name = blue(rloc.rloc_name, False)
            lprint("Policy set-rloc-record-name to {}".format(name))
        #endif
        if (self.set_geo_name): 
            rloc.geo_name = self.set_geo_name
            name = rloc.geo_name
            not_found = "" if (name in lisp_geo_list) else \
                "(not configured)"
            lprint("Policy set-geo-name '{}' {}".format(name, not_found))
        #endif
        if (self.set_elp_name): 
            rloc.elp_name = self.set_elp_name
            name = rloc.elp_name
            not_found = "" if (name in lisp_elp_list) else \
                "(not configured)"
            lprint("Policy set-elp-name '{}' {}".format(name, not_found))
        #endif
        if (self.set_rle_name): 
            rloc.rle_name = self.set_rle_name
            name = rloc.rle_name
            not_found = "" if (name in lisp_rle_list) else \
                "(not configured)"
            lprint("Policy set-rle-name '{}' {}".format(name, not_found))
        #endif
        if (self.set_json_name): 
            rloc.json_name = self.set_json_name
            name = rloc.json_name
            not_found = "" if (name in lisp_json_list) else \
                "(not configured)"
            lprint("Policy set-json-name '{}' {}".format(name, not_found))
        #endif
        return(rloc)
    #enddef

    def save_policy(self):
        lisp_policies[self.policy_name] = self
    #enddef
#endclass

class lisp_pubsub(object):
    def __init__(self, itr, port, nonce, ttl, xtr_id):
        self.itr = itr
        self.port = port
        self.nonce = nonce
        self.uptime = lisp_get_timestamp()
        self.ttl = ttl
        self.xtr_id = xtr_id
        self.map_notify_count = 0
        self.eid_prefix = None
    #enddef

    def add(self, eid_prefix):
        self.eid_prefix = eid_prefix
        ttl = self.ttl
        eid = eid_prefix.print_prefix()
        if (eid not in lisp_pubsub_cache):
            lisp_pubsub_cache[eid] = {}
        #endif
        pubsub = lisp_pubsub_cache[eid]

        ar = "Add"
        if (self.xtr_id in pubsub):
            ar = "Replace"
            del(pubsub[self.xtr_id])
        #endif
        pubsub[self.xtr_id] = self

        eid = green(eid, False)
        itr = red(self.itr.print_address_no_iid(), False)
        xtr_id = "0x" + lisp_hex_string(self.xtr_id)
        lprint("{} pubsub state {} for {}, xtr-id: {}, ttl {}".format(ar, eid,
             itr, xtr_id, ttl))
    #enddef

    def delete(self, eid_prefix):
        eid = eid_prefix.print_prefix()
        itr = red(self.itr.print_address_no_iid(), False)
        xtr_id = "0x" + lisp_hex_string(self.xtr_id)
        if (eid in lisp_pubsub_cache):
            pubsub = lisp_pubsub_cache[eid]
            if (self.xtr_id in pubsub):
                pubsub.pop(self.xtr_id)
                lprint("Remove pubsub state {} for {}, xtr-id: {}".format(eid,
                     itr, xtr_id))
            #endif
        #endif
    #enddef
#endclass

#
# lisp_trace
#
# The LISP-Trace message format is:
#
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Type=9 |         0           |        Local Private Port       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                  Local Private IPv4 RLOC                      | 
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Nonce . . .                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         . . . Nonce                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
class lisp_trace(object):
    def __init__(self):
        self.nonce = lisp_get_control_nonce()
        self.packet_json = []
        self.local_rloc = None
        self.local_port = None
        self.lisp_socket = None
    #enddef

    def print_trace(self):
        jd = self.packet_json
        lprint("LISP-Trace JSON: '{}'".format(jd))
    #enddef
            
    def encode(self):
        first_long = socket.htonl(0x90000000)
        packet = struct.pack("II", first_long, 0)
        packet += struct.pack("Q", self.nonce)
        packet += json.dumps(self.packet_json)
        return(packet)
    #enddef

    def decode(self, packet):
        packet_format = "I"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(False)
        first_long = struct.unpack(packet_format, packet[:format_size])[0]
        packet = packet[format_size::]
        first_long = socket.ntohl(first_long)
        if ((first_long & 0xff000000) != 0x90000000): return(False)

        if (len(packet) < format_size): return(False)
        addr = struct.unpack(packet_format, packet[:format_size])[0]
        packet = packet[format_size::]

        addr = socket.ntohl(addr)
        v1 = addr >> 24
        v2 = (addr >> 16) & 0xff
        v3 = (addr >> 8) & 0xff
        v4 = addr & 0xff
        self.local_rloc = "{}.{}.{}.{}".format(v1, v2, v3, v4)
        self.local_port = str(first_long & 0xffff)

        packet_format = "Q"
        format_size = struct.calcsize(packet_format)
        if (len(packet) < format_size): return(False)
        self.nonce = struct.unpack(packet_format, packet[:format_size])[0]
        packet = packet[format_size::]
        if (len(packet) == 0): return(True)

        try:
            self.packet_json = json.loads(packet)
        except:
            return(False)
        #entry
        return(True)
    #enddef

    def myeid(self, eid):
        return(lisp_is_myeid(eid))
    #enddef

    def return_to_sender(self, lisp_socket, rts_rloc, packet):
        rloc, port = self.rtr_cache_nat_trace_find(rts_rloc)
        if (rloc == None):
            rloc, port = rts_rloc.split(":")
            port = int(port)
            lprint("Send LISP-Trace to address {}:{}".format(rloc, port))
        else:
            lprint("Send LISP-Trace to translated address {}:{}".format(rloc,
                port))
        #endif

        if (lisp_socket == None):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(("0.0.0.0", LISP_TRACE_PORT))
            s.sendto(packet, (rloc, port))
            s.close()
        else:
            lisp_socket.sendto(packet, (rloc, port))
        #endif
    #enddef

    def packet_length(self):
        udp = 8; trace = 4 + 4 + 8
        return(udp + trace + len(json.dumps(self.packet_json)))
    #enddef

    def rtr_cache_nat_trace(self, translated_rloc, translated_port):
        key = self.local_rloc + ":" + self.local_port
        value = (translated_rloc, translated_port)
        lisp_rtr_nat_trace_cache[key] = value
        lprint("Cache NAT Trace addresses {} -> {}".format(key, value))
    #enddef

    def rtr_cache_nat_trace_find(self, local_rloc_and_port):
        key = local_rloc_and_port
        try: value = lisp_rtr_nat_trace_cache[key]
        except: value = (None, None)
        return(value)
    #enddef
#endclass        

#------------------------------------------------------------------------------

#
# lisp_get_map_server
#
# Return a lisp_ms() class instance. Variable 'address' is a lisp_address()
# class instance.
#
def lisp_get_map_server(address):
    for ms in list(lisp_map_servers_list.values()):
        if (ms.map_server.is_exact_match(address)): return(ms)
    #endfor
    return(None)
#enddef

#
# lisp_get_any_map_server
#
# Return the first lisp_ms() class instance.
#
def lisp_get_any_map_server():
    for ms in list(lisp_map_servers_list.values()): return(ms)
    return(None)
#enddef

#
# lisp_get_map_resolver
#
# Get least recently used Map-Resolver if address is not supplied. Variable
# 'eid' takes on 3 values, an EID value in the form of lisp_address(), None,
# or "". Value "" means to use any MR, like the first one. Value None means
# to use a map-resolver-name that has not been configured (i.e. "all").
#
def lisp_get_map_resolver(address, eid):
    if (address != None):
        addr = address.print_address()
        mr = None
        for key in lisp_map_resolvers_list:
            if (key.find(addr) == -1): continue
            mr = lisp_map_resolvers_list[key]
        #endfor
        return(mr)
    #endif

    #
    # Get database-mapping entry to find out which map-resolver name set we
    # should use, or pick one from a non-configured mr-name list. Or, get the
    # first one for info-requests.
    #
    if (eid == ""): 
        mr_name = ""
    elif (eid == None): 
        mr_name = "all"
    else:
        db = lisp_db_for_lookups.lookup_cache(eid, False)
        mr_name = "all" if db == None else db.use_mr_name
    #endif

    older = None
    for mr in list(lisp_map_resolvers_list.values()):
        if (mr_name == ""): return(mr)
        if (mr.mr_name != mr_name): continue
        if (older == None or mr.last_used < older.last_used): older = mr
    #endfor
    return(older)
#enddef

#
# lisp_get_decent_map_resolver
#
# Get the Map-Resolver based on the LISP-Decent pull mapping system lookup
# algorithm
#
def lisp_get_decent_map_resolver(eid):
    index = lisp_get_decent_index(eid)
    dns_name = str(index) + "." + lisp_decent_dns_suffix

    lprint("Use LISP-Decent map-resolver {} for EID {}".format( \
        bold(dns_name, False), eid.print_prefix()))

    older = None
    for mr in list(lisp_map_resolvers_list.values()):
        if (dns_name != mr.dns_name): continue
        if (older == None or mr.last_used < older.last_used): older = mr
    #endfor
    return(older)
#enddef

#
# lisp_ipv4_input
#
# Process IPv4 data packet for input checking.
#
def lisp_ipv4_input(packet):

    #
    # Check IGMP packet first. And don't do IP checksum and don't test TTL.
    #
    if (ord(packet[9:10]) == 2): return([True, packet])

    #
    # Now calculate checksum for verification.
    #
    checksum = struct.unpack("H", packet[10:12])[0]
    if (checksum == 0):
        dprint("Packet arrived with checksum of 0!")
    else:
        packet = lisp_ip_checksum(packet)
        checksum = struct.unpack("H", packet[10:12])[0]
        if (checksum != 0):
            dprint("IPv4 header checksum failed for inner header")
            packet = lisp_format_packet(packet[0:20])
            dprint("Packet header: {}".format(packet))
            return([False, None])
        #endif
    #endif

    #
    # Now check TTL and if not 0, recalculate checksum and return to
    # encapsulate.
    #
    ttl = struct.unpack("B", packet[8:9])[0]
    if (ttl == 0):
        dprint("IPv4 packet arrived with ttl 0, packet discarded")
        return([False, None])
    elif (ttl == 1):
        dprint("IPv4 packet {}, packet discarded".format( \
            bold("ttl expiry", False)))
        return([False, None])
    #endif

    ttl -= 1
    packet = packet[0:8] + struct.pack("B", ttl) + packet[9::]
    packet = packet[0:10] + struct.pack("H", 0) + packet[12::]
    packet = lisp_ip_checksum(packet)
    return([False, packet])
#enddef

#
# lisp_ipv6_input
#
# Process IPv6 data packet for input checking.
#
def lisp_ipv6_input(packet):
    dest = packet.inner_dest
    packet = packet.packet

    #
    # Now check TTL and if not 0, recalculate checksum and return to
    # encapsulate.
    #
    ttl = struct.unpack("B", packet[7:8])[0]
    if (ttl == 0):
        dprint("IPv6 packet arrived with hop-limit 0, packet discarded")
        return(None)
    elif (ttl == 1):
        dprint("IPv6 packet {}, packet discarded".format( \
            bold("ttl expiry", False)))
        return(None)
    #endif

    #
    # Check for IPv6 link-local addresses. They should not go on overlay.
    #
    if (dest.is_ipv6_link_local()):
        dprint("Do not encapsulate IPv6 link-local packets")
        return(None)
    #endif

    ttl -= 1
    packet = packet[0:7] + struct.pack("B", ttl) + packet[8::]
    return(packet)
#enddef

#
# lisp_mac_input
#
# Process MAC data frame for input checking. All we need to do is get the
# destination MAC address.
#
def lisp_mac_input(packet):
    return(packet)
#enddef

#
# lisp_rate_limit_map_request
#
# Check to see if we have sent a data-triggered Map-Request in the last 
# LISP_MAP_REQUEST_RATE_LIMIT seconds. Return True if we should not send
# a Map-Request (rate-limit it).
#
def lisp_rate_limit_map_request(dest):
    now = lisp_get_timestamp()
    
    #
    # Do we have rate-limiting disabled temporarily?
    #
    elapsed = now - lisp_no_map_request_rate_limit
    if (elapsed < LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME):
        left = int(LISP_NO_MAP_REQUEST_RATE_LIMIT_TIME - elapsed)
        dprint("No Rate-Limit Mode for another {} secs".format(left))
        return(False)
    #endif

    #
    # Do we send a Map-Request recently?
    #
    if (lisp_last_map_request_sent == None): return(False)
    elapsed = now - lisp_last_map_request_sent
    rate_limit = (elapsed < LISP_MAP_REQUEST_RATE_LIMIT)

    if (rate_limit):
        dprint("Rate-limiting Map-Request for {}, sent {} secs ago".format( \
            green(dest.print_address(), False), round(elapsed, 3)))
    #endif
    return(rate_limit)
#enddef

#
# lisp_send_map_request
#
# From this process, build and send a Map-Request for supplied EID.
#
def lisp_send_map_request(lisp_sockets, lisp_ephem_port, seid, deid, rloc,
    pubsub=False):
    global lisp_last_map_request_sent, lisp_rloc_probe_nonce_list

    #
    # Set RLOC-probe parameters if caller wants Map-Request to be an 
    # RLOC-probe. We use probe_port as 4341 so we the ITR and RTR keying data 
    # structures can be the same.
    #
    probe_dest = probe_port = None
    if (rloc):
        probe_dest = rloc.rloc
        probe_port = rloc.translated_port if lisp_i_am_rtr else LISP_DATA_PORT
    #endif

    #
    # If there are no RLOCs found, do not build and send the Map-Request.
    #
    itr_rloc4, itr_rloc6, device = lisp_myrlocs
    if (itr_rloc4 == None): 
        lprint("Suppress sending Map-Request, IPv4 RLOC not found")
        return
    #endif
    if (itr_rloc6 == None and probe_dest != None and probe_dest.is_ipv6()):
        lprint("Suppress sending Map-Request, IPv6 RLOC not found")
        return
    #endif

    map_request = lisp_map_request()
    map_request.record_count = 1
    map_request.nonce = lisp_get_control_nonce()
    map_request.rloc_probe = (probe_dest != None)
    map_request.subscribe_bit = pubsub
    map_request.xtr_id_present = pubsub
    map_request.decent_nat_xtr = lisp_decent_nat

    #
    # Hold request nonce so we can match replies from xTRs that have multiple
    # RLOCs. Reason being is because source address may not be the probed
    # destination. And on our ETR implementation, we can get the probe request
    # destination in the lisp-core/lisp-etr/lisp-rtr processes.
    #
    if (rloc): rloc.last_rloc_probe_nonce = map_request.nonce

    sg = deid.is_multicast_address()
    if (sg):
        map_request.target_eid = seid
        map_request.target_group = deid
    else:
        map_request.target_eid = deid
    #endif

    #
    # If lookup is for an IPv6 EID or there is a signature key configured and
    # there is a private key file in current directory, tell lisp_map_request()
    # to sign Map-Request. For an RTR, we want to verify its map-request
    # signature, so it needs to include its own IPv6 EID that matches the
    # private-key file.
    #
    if (map_request.rloc_probe == False):
        db = lisp_get_signature_eid()
        if (db):
            map_request.signature_eid.copy_address(db.eid)
            map_request.privkey_filename = "./lisp-sig.pem"
        #endif
    #endif

    #
    # Fill in source-eid field.
    #
    if (seid == None or sg):
        map_request.source_eid.afi = LISP_AFI_NONE
    else:
        map_request.source_eid = seid
    #endif

    #
    # If ITR-RLOC is a private IPv4 address, we need it to be a global address
    # for RLOC-probes. 
    #
    # However, if we are an RTR and have a private address, the RTR is behind 
    # a NAT. The RLOC-probe is encapsulated with source-port 4341 to get 
    # through NAT. The ETR receiving the RLOC-probe request must return the 
    # RLOC-probe reply with same translated address/port pair (the same values 
    # when it encapsulates data packets).
    #
    # For RLOC-probes from a decent-nat ITR to a decent-nat ETR, we use the
    # local/private address. Just like we do for Info-Requests.
    #
    if (probe_dest != None and lisp_nat_traversal and lisp_i_am_rtr == False):
        if (lisp_decent_nat == False and
            probe_dest.is_private_address() == False):
            itr_rloc4 = lisp_get_any_translated_rloc()
        #endif
        if (itr_rloc4 == None):
            lprint("Suppress sending Map-Request, translated RLOC not found")
            return
        #endif
    #endif    

    #
    # Fill in ITR-RLOCs field. If we don't find an IPv6 address there is
    # nothing to store in the ITR-RLOCs list. And we have to use an inner
    # source address of 0::0.
    #
    if (probe_dest == None or probe_dest.is_ipv4()):
        if (lisp_nat_traversal and probe_dest == None): 
            ir = lisp_get_any_translated_rloc()
            if (ir != None): itr_rloc4 = ir
        #endif
        map_request.itr_rlocs.append(itr_rloc4)
    #endif
    if (probe_dest == None or probe_dest.is_ipv6()):
        if (itr_rloc6 == None or itr_rloc6.is_ipv6_link_local()):
            itr_rloc6 = None
        else:
            map_request.itr_rloc_count = 1 if (probe_dest == None) else 0
            map_request.itr_rlocs.append(itr_rloc6)
        #endif
    #endif

    #
    # Decide what inner source address needs to be for the ECM. We have to
    # look at the address-family of the destination EID. If the destination-EID
    # is a MAC address, we will use IPv4 in the inner header with a destination
    # address of 0.0.0.0.
    #
    if (probe_dest != None and map_request.itr_rlocs != []):
        itr_rloc = map_request.itr_rlocs[0]
    else:
        if (deid.is_ipv4()): 
            itr_rloc = itr_rloc4
        elif (deid.is_ipv6()):
            itr_rloc = itr_rloc6
        else:
            itr_rloc = itr_rloc4
        #endif
    #endif

    #
    # And finally add one EID record. The EID we are looking up.
    #
    packet = map_request.encode(probe_dest, probe_port)
    map_request.print_map_request()

    #
    # If this is an RLOC-probe, send directly to RLOC and not to mapping
    # system. If the RLOC is behind a NAT, we need to data encapsulate it
    # from port 4341 to translated destination address and port.
    #
    if (probe_dest != None):
        if (rloc.is_rloc_translated()):
            rn = rloc.normalize_decent_nat_rloc_name()
            nat_info = lisp_get_nat_info(probe_dest, rn)

            #
            # Handle gleaned RLOC case or a decent-nat ITR case probing ETR
            # directly through its NAT.
            #
            if (nat_info == None):
                r = rloc.rloc.print_address_no_iid()
                g = "glean-{}".format(r) if lisp_i_am_rtr else \
                    "nat-{}".format(r)
                p = rloc.translated_port
                nat_info = lisp_nat_info(r, g, p)
            #endif

            lisp_encap_rloc_probe(lisp_sockets, probe_dest, nat_info, packet)
            return
        #endif

        if (probe_dest.is_ipv4() and probe_dest.is_multicast_address()):
            dest = probe_dest
        else:
            addr_str = probe_dest.print_address_no_iid()
            dest = lisp_convert_4to6(addr_str)
        #endif

        #
        # For finding the probed RLOC address for multihoming cases.
        #
        lisp_rloc_probe_nonce_list[map_request.nonce] = addr_str

        lisp_send(lisp_sockets, dest, LISP_CTRL_PORT, packet)
        return
    #endif

    #
    # Get least recently used Map-Resolver. In the RTR make sure there is a
    # Map-Resolver in lisp.config with no mr-name or mr-name=all.
    #
    local_eid = None if lisp_i_am_rtr else seid
    if (lisp_decent_pull_xtr_configured()):
        mr = lisp_get_decent_map_resolver(deid)
    else:
        mr = lisp_get_map_resolver(None, local_eid)
    #endif
    if (mr == None): 
        lprint("Cannot find Map-Resolver for source-EID {}".format( \
            green(seid.print_address(), False)))
        return
    #endif
    mr.last_used = lisp_get_timestamp()
    mr.map_requests_sent += 1
    if (mr.last_nonce == 0): mr.last_nonce = map_request.nonce

    #
    # Send ECM based Map-Request to Map-Resolver.
    #
    if (seid == None): seid = itr_rloc
    lisp_send_ecm(lisp_sockets, packet, seid, lisp_ephem_port, deid, 
        mr.map_resolver)

    #
    # Set global timestamp for Map-Request rate-limiting.
    #
    lisp_last_map_request_sent = lisp_get_timestamp()

    #
    # Do DNS lookup for Map-Resolver if "dns-name" configured.
    #
    mr.resolve_dns_name()
    return
#enddef

#
# lisp_send_info_request
#
# Send info-request to any map-server configured or to an address supplied
# by the caller.
#
def lisp_send_info_request(lisp_sockets, dest, port, device_name):

    #
    # Build Info-Request message.
    #
    info = lisp_info()
    info.nonce = lisp_get_control_nonce()
    if (device_name): info.hostname += "-" + device_name

    addr_str = dest.print_address_no_iid()

    #
    # Find next-hop for interface 'device_name' if supplied. The "ip route"
    # command will produce this:
    #
    # pi@lisp-pi ~/lisp $ ip route | egrep "default via"
    # default via 192.168.1.1 dev eth1 
    # default via 192.168.1.1 dev wlan0 
    #
    # We then turn the line we want into a "ip route add" command. Then at
    # the end of this function we remove the route.
    #
    # We do this on the ETR only so we don't have Info-Requests from the lisp-
    # itr and lisp-etr process both add and delete host routes (for Info-
    # Request sending purposes) at the same time.
    #
    added_route = False
    if (device_name):
        default_routes = lisp_get_default_route_next_hops()
        lprint("Found default routes {}".format(default_routes))

        if (len(default_routes) == 1):
            nh = default_routes[0][0]
            if (nh != device_name):
                lprint("Multihoming config error, add this to your system:")
                lprint("  'sudo ip route append default via <nh> dev {}'". \
                       format(device_name))
                return
            #endif
        #endif

        save_nh = lisp_get_host_route_next_hop(addr_str)
        if (save_nh == None):
            lprint("No host route found for MS {}".format(addr_str))
        else:
            lprint("Host route found for MS {}, nh {}".format(addr_str,
                save_nh))
        #endif

        #
        # If we found a host route for the map-server, then both the lisp-itr
        # and lisp-etr processes are in this routine at the same time.
        # wait for the host route to go away before proceeding. We will use
        # the map-server host route as a IPC lock. For the data port, only
        # the lisp-etr processes will add host route to the RTR for Info-
        # Requests.
        #
        if (port == LISP_CTRL_PORT and save_nh != None):
            lprint("Waiting for host route {} to go away".format(addr_str))
            while (True):
                time.sleep(.01)
                save_nh = lisp_get_host_route_next_hop(addr_str)
                if (save_nh == None): break
            #endwhile
        #endif

        for device, nh in default_routes:
            if (device != device_name): continue

            #
            # If there is a data route pointing to same next-hop, don't 
            # change the routing table. Otherwise, remove saved next-hop,
            # add the one we want and later undo this.
            #
            if (save_nh != nh):
                if (save_nh != None):
                    lisp_install_host_route(addr_str, save_nh, False)
                #endif
                lisp_install_host_route(addr_str, nh, True)
                added_route = True
            #endif
            break
        #endfor
    #endif

    #
    # Encode the Info-Request message and print it.
    #
    packet = info.encode()
    info.print_info()

    #
    # Send it.
    #
    cd = "(for control)" if port == LISP_CTRL_PORT else "(for data)"
    cd = bold(cd, False)
    p = bold("{}".format(port), False)
    a = red(addr_str, False)
    rtr = "RTR " if port == LISP_DATA_PORT else "MS "
    lprint("Send Info-Request to {}{}, port {} {}".format(rtr, a, p, cd))

    #
    # Send packet to control port via control-sockets interface. For a 4341
    # do the same via the lisp-core process but prepend a LISP data header
    # to the message.
    #
    if (port == LISP_CTRL_PORT):
        lisp_send(lisp_sockets, dest, LISP_CTRL_PORT, packet)
    else:
        header = lisp_data_header()
        header.instance_id(0xffffff)
        header = header.encode()
        if (header):
            packet = header + packet

            #
            # The NAT-traversal spec says to use port 4342 as the source port
            # but that would mean return data packets will go to the lisp-core
            # process. We are going to use an ephemeral port here so packets
            # come to this lisp-etr process. The commented out call is to
            # allow Info-Requests to use source port 4342 but will break the 
            # data-plane in this lispers.net implementation.
            #
            lisp_send(lisp_sockets, dest, LISP_DATA_PORT, packet)
#           lisp_send_ipc_to_core(lisp_sockets[2], packet, dest, port)
        #endif
    #endif

    #
    # Remove static route to RTR if had added one and restore data route.
    #
    if (added_route): 
        lisp_install_host_route(addr_str, None, False)
        if (save_nh != None): lisp_install_host_route(addr_str, save_nh, True)
    #endif
    return
#enddef

#
# lisp_process_info_request
#
# Process received Info-Request message. Return a Info-Reply to sender.
#
def lisp_process_info_request(lisp_sockets, packet, addr_str, sport, rtr_list):

    #
    # Parse Info-Request so we can return the nonce in the Info-Reply.
    #
    info = lisp_info()
    packet = info.decode(packet)
    if (packet == None): return
    info.print_info()

    #
    # Start building the Info-Reply. Copy translated source and translated
    # source port from Info-Request.
    #
    info.info_reply = True
    info.global_etr_rloc.store_address(addr_str) 
    info.etr_port = sport

    #
    # Put Info-Request hostname (if it was encoded) in private-rloc in
    # Info-Reply. Encode it as an AFI=17 distinguished-name.
    #
    if (info.hostname != None):
        info.private_etr_rloc.afi = LISP_AFI_NAME
        info.private_etr_rloc.store_address(info.hostname)
    #endif

    if (rtr_list != None): info.rtr_list = rtr_list
    packet = info.encode()
    info.print_info()

    #
    # Send the Info-Reply via the lisp-core process. We are sending from
    # a udp46 socket, so we need to prepend ::ffff.
    #
    lprint("Send Info-Reply to {}".format(red(addr_str, False)))
    dest = lisp_convert_4to6(addr_str)
    lisp_send(lisp_sockets, dest, sport, packet)

    #
    # Cache info sources so we can decide to process Map-Requests from it
    # specially so we can proxy-Map-Request when the sources are behind NATs.
    #
    info_source = lisp_info_source(info.hostname, addr_str, sport)
    info_source.cache_address_for_info_source()
    return
#enddef

#
# lisp_get_signature_eid
#
# Go through the lisp_db_list (database-mappings) and return the first entry
# with signature-eid is True.
#
def lisp_get_signature_eid():
    for db in lisp_db_list:
        if (db.signature_eid): return(db)
    #endfor
    return(None)
#enddef

#
# lisp_get_any_translated_port
#
# Find a translated port so we can set it to the inner UDP port number for
# ECM Map-Requests.
#
def lisp_get_any_translated_port():
    for db in lisp_db_list:
        for rloc_entry in db.rloc_set:
            if (rloc_entry.translated_rloc.is_null()): continue
            return(rloc_entry.translated_port)
        #endfor
    #endfor
    return(None)
#enddef

#
# lisp_get_any_translated_rloc
#
# Find a translated RLOC in any lisp_mapping() from the lisp_db_list. We need
# this to store in an RLE for (S,G) Map-Registers when the ETR is behind NAT
# devies.
#
def lisp_get_any_translated_rloc():
    for db in lisp_db_list:
        for rloc_entry in db.rloc_set:
            if (rloc_entry.translated_rloc.is_null()): continue
            return(rloc_entry.translated_rloc)
        #endfor
    #endfor
    return(None)
#enddef

#
# lisp_get_all_translated_rlocs
#
# Return an array of each translated RLOC address in string format.
#
def lisp_get_all_translated_rlocs():
    rloc_list = []
    for db in lisp_db_list:
        for rloc_entry in db.rloc_set:
            if (rloc_entry.is_rloc_translated() == False): continue
            addr = rloc_entry.translated_rloc.print_address_no_iid()
            rloc_list.append(addr)
        #endfor
    #endfor
    return(rloc_list)
#enddef

#
# lisp_update_default_routes
#
# We are an ITR and we received a new RTR-list from the Map-Server. Update
# the RLOCs of the default map-cache entries if they are different.
#
def lisp_update_default_routes(map_resolver, iid, rtr_list):
    ignore_private = (os.getenv("LISP_RTR_BEHIND_NAT") != None)
    
    new_rtr_list = {}
    for rloc in rtr_list:
        if (rloc == None): continue
        addr = rtr_list[rloc]
        if (ignore_private and addr.is_private_address()): continue
        new_rtr_list[rloc] = addr
    #endfor
    rtr_list = new_rtr_list

    prefix_list = []
    for afi in [LISP_AFI_IPV4, LISP_AFI_IPV6, LISP_AFI_MAC]:
        if (afi == LISP_AFI_MAC and lisp_l2_overlay == False): break

        #
        # Do unicast routes. We assume unicast and multicast routes are sync'ed
        # with the same RLOC-set.
        #
        prefix = lisp_address(afi, "", 0, iid)
        prefix.make_default_route(prefix)
        mc = lisp_map_cache.lookup_cache(prefix, True)
        if (mc):
            if (mc.checkpoint_entry):
                lprint("Updating checkpoint entry for {}".format( \
                        green(mc.print_eid_tuple(), False)))
            elif (mc.do_rloc_sets_match(list(rtr_list.values()))): 
                continue
            #endif
            mc.delete_cache()
        #endif

        prefix_list.append([prefix, ""])

        #
        # Do multicast routes.
        #
        group = lisp_address(afi, "", 0, iid)
        group.make_default_multicast_route(group)
        gmc = lisp_map_cache.lookup_cache(group, True)
        if (gmc): gmc = gmc.source_cache.lookup_cache(prefix, True)
        if (gmc): gmc.delete_cache()

        prefix_list.append([prefix, group])
    #endfor
    if (len(prefix_list) == 0): return

    #
    # Build RLOC-set.
    #
    rloc_set = []
    for rtr in rtr_list:
        rtr_addr = rtr_list[rtr]
        rloc_entry = lisp_rloc()
        rloc_entry.rloc.copy_address(rtr_addr)
        rloc_entry.priority = 254
        rloc_entry.mpriority = 255
        rloc_entry.rloc_name = "RTR"
        rloc_set.append(rloc_entry)
    #endfor

    for prefix in prefix_list:
        mc = lisp_mapping(prefix[0], prefix[1], rloc_set)
        mc.mapping_source = map_resolver
        mc.map_cache_ttl = LISP_MR_TTL * 60
        mc.add_cache()
        lprint("Add {} to map-cache with RTR RLOC-set: {}".format( \
            green(mc.print_eid_tuple(), False), list(rtr_list.keys())))
        rloc_set = copy.deepcopy(rloc_set)
    #endfor
    return
#enddef

#
# lisp_process_info_reply
#
# Process received Info-Reply message. Store global RLOC and translated port
# in database-mapping entries if requested.
#
# Returns [global-rloc-address, translated-port-number, new_rtr_set].
#
def lisp_process_info_reply(source, packet, store):
    
    #
    # Parse Info-Reply.
    #
    info = lisp_info()
    packet = info.decode(packet)
    if (packet == None): return([None, None, False])

    info.print_info()

    #
    # Set return flag to trigger a Map-Regiser message.
    #
    trigger = False

    #
    # Store RTR list.
    #
    for rtr in info.rtr_list:
        addr_str = rtr.print_address_no_iid()
        if (addr_str in lisp_rtr_list):
            if (lisp_register_all_rtrs == False): continue
            if (lisp_rtr_list[addr_str] != None): continue
        #endif
        trigger = True
        lisp_rtr_list[addr_str] = rtr
    #endfor

    #
    # If an ITR, install default map-cache entries.
    #
    if (lisp_i_am_itr and trigger):
        if (lisp_iid_to_interface == {}):
            lisp_update_default_routes(source, lisp_default_iid, lisp_rtr_list)
        else:
            for iid in list(lisp_iid_to_interface.keys()):
                lisp_update_default_routes(source, int(iid), lisp_rtr_list)
            #endfor
        #endif
    #endif

    #
    # Either store in database-mapping entries or return to caller.
    #
    if (store == False): 
        return([info.global_etr_rloc, info.etr_port, trigger])
    #endif

    #
    # If no private-etr-rloc was supplied in the Info-Reply, use the global
    # RLOC for all private RLOCs in the database-mapping entries.
    #
    for db in lisp_db_list:
        for rloc_entry in db.rloc_set:
            rloc = rloc_entry.rloc
            interface = rloc_entry.interface
            rloc_name = rloc_entry.rloc_name
            if (rloc_entry.is_decent_nat_port()):
                rloc_name = rloc_name.split(LISP_TP)[0]
            #endif

            if (interface == None):            
                if (rloc.is_null()): continue
                if (rloc.is_local() == False): continue
                if (info.private_etr_rloc.is_null() == False and 
                    rloc.is_exact_match(info.private_etr_rloc) == False): 
                    continue
                #endif
            elif (info.private_etr_rloc.is_dist_name()):
                info_rn = info.private_etr_rloc.address
                if (info_rn != rloc_name): continue
            #endif

            eid_str = green(db.eid.print_prefix(), False)
            rloc_str = red(rloc.print_address_no_iid(), False)

            rlocs_match = info.global_etr_rloc.is_exact_match(rloc)
            if (rloc_entry.translated_port == 0 and rlocs_match):
                lprint("No NAT for {} ({}), EID-prefix {}".format(rloc_str,
                    interface, eid_str))
                continue
            #endif

            #
            # Nothing changed?
            #
            translated = info.global_etr_rloc
            stored = rloc_entry.translated_rloc
            if (stored.is_exact_match(translated) and
                info.etr_port == rloc_entry.translated_port): continue

            lprint("Store translation {}:{} for {} ({}), EID-prefix {}". \
                format(red(info.global_etr_rloc.print_address_no_iid(), False),
                info.etr_port, rloc_str, interface, eid_str))

            rloc_entry.rloc_name = rloc_name
            rloc_entry.store_translated_rloc(info.global_etr_rloc,
                info.etr_port)

            trigger = True
        #endfor
    #endfor
    return([info.global_etr_rloc, info.etr_port, trigger])
#enddef

#
# lisp_test_mr
#
# Send Map-Requests for arbitrary EIDs to (1) prime the map-cache and to (2)
# test the RTT of the Map-Resolvers.
#
def lisp_test_mr(lisp_sockets, port):
    return
    lprint("Test Map-Resolvers")

    eid = lisp_address(LISP_AFI_IPV4, "", 0, 0)
    eid6 = lisp_address(LISP_AFI_IPV6, "", 0, 0)

    #
    # Send 10.0.0.1 and 192.168.0.1
    #
    eid.store_address("10.0.0.1")
    lisp_send_map_request(lisp_sockets, port, None, eid, None)
    eid.store_address("192.168.0.1")
    lisp_send_map_request(lisp_sockets, port, None, eid, None)

    #
    # Send 0100::1 and 8000::1.
    #
    eid6.store_address("0100::1")
    lisp_send_map_request(lisp_sockets, port, None, eid6, None)
    eid6.store_address("8000::1")
    lisp_send_map_request(lisp_sockets, port, None, eid6, None)

    #
    # Restart periodic timer.
    #
    lisp_test_mr_timer = threading.Timer(LISP_TEST_MR_INTERVAL, lisp_test_mr, 
        [lisp_sockets, port])
    lisp_test_mr_timer.start()
    return
#enddef

#
# lisp_update_local_rloc
#
# Check if local RLOC has changed and update the lisp_rloc() entry in 
# lisp_db(). That is check to see if the private address changed since this
# ETR could have moved to another NAT or the same NAT device reassigned a
# new private address.
#
# This function is also used when the interface address is not private. It
# allows us to change the RLOC when the address changes.
#
def lisp_update_local_rloc(rloc):
    if (rloc.interface == None): return

    addr = lisp_get_interface_address(rloc.interface)
    if (addr == None): return

    old = rloc.rloc.print_address_no_iid()
    new = addr.print_address_no_iid()

    if (old == new): return

    lprint("Local interface address changed on {} from {} to {}".format( \
        rloc.interface, old, new))

    rloc.rloc.copy_address(addr)
    lisp_myrlocs[0] = addr
    return
#enddef

#
# lisp_update_encap_port
#
# Check to see if the encapsulation port changed for an RLOC for the supplied
# map-cache entry.
#
def lisp_update_encap_port(mc):
    for rloc in mc.rloc_set:
        rn = rloc.normalize_decent_nat_rloc_name()
        nat_info = lisp_get_nat_info(rloc.rloc, rn)
        if (nat_info == None): continue
        if (rloc.translated_port == nat_info.port): continue

        lprint(("Encap-port changed from {} to {} for RLOC {}, " + \
            "EID-prefix {}").format(rloc.translated_port, nat_info.port,
            red(rloc.rloc.print_address_no_iid(), False), 
            green(mc.print_eid_tuple(), False)))

        rloc.store_translated_rloc(rloc.rloc, nat_info.port)
    #endfor
    return
#enddef
                                                 
#
# lisp_timeout_map_cache_entry
#
# Check if a specific map-cache entry needs to be removed due timer expiry.
# If entry does not time out, go through RLOC-set to see if the encapsulation
# port needs updating.
#
# If "program-hardware = yes" is configured, then check a platform specific
# flag (an Arista platform specific command).
#
def lisp_timeout_map_cache_entry(mc, delete_list):
    if (mc.map_cache_ttl == None): 
        lisp_update_encap_port(mc)
        return([True, delete_list])
    #endif

    now = lisp_get_timestamp()
    last_refresh_time = mc.last_refresh_time

    #
    # If mapping system runs on this system, disregard packet activity.
    # There could be a race condition for active sources, where destinations
    # are not registered yet due to system restart. If the LISP subsystem
    # is within 5 minutes of restarting, time out native-forward entries.
    #
    if (lisp_is_running("lisp-ms") and lisp_uptime + (5*60) >= now):
        if (mc.action == LISP_NATIVE_FORWARD_ACTION):
            last_refresh_time = 0
            lprint("Remove startup-mode native-forward map-cache entry")
        #endif
    #endif

    #
    # If the action is not-registered-yet, time out the map-cache entry so
    # we can test to see if it became registered.
    #
    do_refresh_check = (mc.action != LISP_NOT_REGISTERED_YET_ACTION)

    #
    # Check refresh timers. Native-Forward entries just return if active,
    # else check for encap-port changes for NAT entries. Then return if
    # entry still active.
    #
    if (do_refresh_check and last_refresh_time + mc.map_cache_ttl > now): 
        if (mc.action == LISP_NO_ACTION): lisp_update_encap_port(mc)
        return([True, delete_list])
    #endif

    #
    # Do not time out NAT-traversal default entries (0.0.0.0/0 and 0::/0).
    #
    if (lisp_nat_traversal and mc.eid.address == 0 and mc.eid.mask_len == 0):
        return([True, delete_list])
    #endif

    #
    # Timed out.
    #
    ut = lisp_print_elapsed(mc.uptime)
    lrt = lisp_print_elapsed(mc.last_refresh_time)
    prefix_str = mc.print_eid_tuple()
    lprint(("Map-cache entry {} {}, had uptime {}, last-refresh-time {}, " + \
       "action was {}").format(green(prefix_str, False),
        bold("timed out", False), ut, lrt,
        lisp_map_reply_action_string[mc.action]))

    #
    # Add to delete-list to remove after this loop.
    #
    delete_list.append(mc)
    return([True, delete_list])
#enddef

#
# lisp_timeout_map_cache_walk
#
# Walk the entries in the lisp_map_cache(). And then subsequently walk the
# entries in lisp_mapping.source_cache().
#
def lisp_timeout_map_cache_walk(mc, parms):
    delete_list = parms[0]
    checkpoint_list = parms[1]
    
    #
    # There is only destination state in this map-cache entry.
    #
    if (mc.group.is_null()): 
        status, delete_list = lisp_timeout_map_cache_entry(mc, delete_list)
        if (delete_list == [] or mc != delete_list[-1]):
            checkpoint_list = lisp_write_checkpoint_entry(checkpoint_list, mc)
        #endif
        return([status, parms])
    #endif

    if (mc.source_cache == None): return([True, parms])

    #
    # There is (source, group) state so walk all sources for this group
    # entry.
    #
    parms = mc.source_cache.walk_cache(lisp_timeout_map_cache_entry, parms)
    return([True, parms])
#enddef

#
# lisp_timeout_map_cache
#
# Look at TTL expiration for each map-cache entry.
#
def lisp_timeout_map_cache(lisp_map_cache):
    parms = [[], []]
    parms = lisp_map_cache.walk_cache(lisp_timeout_map_cache_walk, parms)

    #
    # Now remove from lisp_referral_cache all the timed out entries on the
    # delete_list[].
    #
    delete_list = parms[0]
    for mc in delete_list: mc.delete_cache()

    #
    # Write contents of checkpoint_list array to checkpoint file.
    #
    checkpoint_list = parms[1]
    lisp_checkpoint(checkpoint_list)
    return
#enddef

#
# lisp_store_nat_info
#
# Store source RLOC and port number of an Info-Request packet sent to port
# 4341 where the packet was translated by a NAT device.
#
# The lisp_nat_state_info{} is a dictionary array with an array a lisp_nat_
# info() values. We keep all the current and previous NAT state associated
# with the Info-Request hostname. This is so we can track how much movement
# is occuring.
#
# Return True if the address and port number changed so the caller can fix up 
# RLOCs in map-cache entries.
#
def lisp_store_nat_info(hostname, rloc, port):
    addr_str = rloc.print_address_no_iid()
    msg = "{} NAT state for {}, RLOC {}, port {}".format("{}", 
       blue(hostname, False), red(addr_str, False), port)
    
    new_nat_info = lisp_nat_info(addr_str, hostname, port)

    if (hostname not in lisp_nat_state_info):
        lisp_nat_state_info[hostname] = [new_nat_info]
        lprint(msg.format("Store initial"))
        return(True)
    #endif

    #
    # The youngest entry is always the first element. So check to see if this
    # is a refresh of the youngest (current) entry.
    #
    nat_info = lisp_nat_state_info[hostname][0]
    if (nat_info.address == addr_str and nat_info.port == port):
        nat_info.uptime = lisp_get_timestamp()
        lprint(msg.format("Refresh existing"))
        return(False)
    #endif

    #
    # So the youngest entry is not the newest entry. See if it exists as
    # an old entry. If not, we prepend the new state, otherwise, we prepend
    # the new state and remove the old state from the array.
    #
    old_entry = None
    for nat_info in lisp_nat_state_info[hostname]:
        if (nat_info.address == addr_str and nat_info.port == port): 
            old_entry = nat_info
            break
        #endif
    #endfor

    if (old_entry == None):
        lprint(msg.format("Store new"))
    else:
        lisp_nat_state_info[hostname].remove(old_entry)
        lprint(msg.format("Use previous"))
    #endif

    existing = lisp_nat_state_info[hostname]
    lisp_nat_state_info[hostname] = [new_nat_info] + existing
    return(True)
#enddef

#
# lisp_get_nat_info
#
# Do lookup to get port number to store in map-cache entry as the encapsulation
# port. If hostname is None, then search by RLOC IP address.
#
def lisp_get_nat_info(rloc, hostname):
    addr_str = rloc.print_address_no_iid()

    if (hostname == None):
        for hostname in lisp_nat_state_info:
            for nat_info in lisp_nat_state_info[hostname]:
                if (nat_info.address == addr_str): return(nat_info)
            #endfor
        #endfor
        return(None)
    #endif

    if (hostname not in lisp_nat_state_info): return(None)

    for nat_info in lisp_nat_state_info[hostname]:
        if (nat_info.address == addr_str): return(nat_info)
    #endfor
    return(None)
#enddef

#
# lisp_build_info_requests
#
# Check database-mappings to see if there are any private local RLOCs. If
# so, get the translated global RLOC by sending an Info-Request to a 
# Map-Server.
#
# To support multi-homing, that is more than one "interface = <device>" 
# rloc sub-command clause, you need the following default routes in the
# kernel so Info-Requests can be load-split across interfaces:
#
#   sudo ip route add default via <next-hop> dev eth0
#   sudo ip route append default via <another-or-same-next-hop> dev eth1
#
# By having these default routes, we can get the next-hop address for the
# NAT interface we are sending the 4341 Info-Request to install a emphemeral
# static route to force the Info-Request to go out a specific interface.
#
def lisp_build_info_requests(lisp_sockets, dest, port):
    if (lisp_nat_traversal == False): return

    #
    # Send Info-Request to each configured Map-Resolver and exit loop.
    # If we don't find one, try finding a Map-Server. We may send Info-
    # Request to an RTR to open up NAT state.
    #
    dest_list = []
    mr_list = []
    if (dest == None):
        for mr in list(lisp_map_resolvers_list.values()):
            mr_list.append(mr.map_resolver)
        #endif
        dest_list = mr_list
        if (dest_list == []):
            for ms in list(lisp_map_servers_list.values()):
                dest_list.append(ms.map_server)
            #endfor
        #endif
        if (dest_list == []): return
    else:
        dest_list.append(dest)
    #endif

    #
    # Find the NAT-traversed interfaces.
    #
    rloc_list = {}
    for db in lisp_db_list:
        for rloc_entry in db.rloc_set:
            lisp_update_local_rloc(rloc_entry)
            if (rloc_entry.rloc.is_null()): continue
            if (rloc_entry.interface == None): continue

            addr = rloc_entry.rloc.print_address_no_iid()
            if (addr in rloc_list): continue
            rloc_list[addr] = rloc_entry.interface
        #endfor
    #endfor
    if (rloc_list == {}): 
        lprint('Suppress Info-Request, no "interface = <device>" RLOC ' + \
            "found in any database-mappings")
        return
    #endif

    if (len(rloc_list) > 1):
        lprint("NAT multihoming local RLOC-list {}".format(rloc_list))
    #endif

    #
    # Send out Info-Requests out the NAT-traversed interfaces that have
    # addresses assigned on them.
    #
    for addr in rloc_list:
        interface = rloc_list[addr]
        a = red(addr, False)
        lprint("Build Info-Request for private address {} on {}".format(a,
            interface))
        device = interface if len(rloc_list) > 1 else None
        for dest in dest_list:
            lisp_send_info_request(lisp_sockets, dest, port, device)
        #endfor
    #endfor

    #
    # Do DNS lookup for Map-Resolver if "dns-name" configured.
    #
    if (mr_list != []):
        for mr in list(lisp_map_resolvers_list.values()):
            mr.resolve_dns_name()
        #endfor
    #endif
    return
#enddef

#
# lisp_valid_address_format
#
# Check to see if the string is a valid address. We are validating IPv4, IPv6
# and MAC addresses.
#
def lisp_valid_address_format(kw, value):
    if (kw != "address"): return(True)

    #
    # Check if address is a Distinguished-Name. Must have single quotes.
    # Check this first because names could have ".", ":", or "-" in them.
    #
    if (value[0] == "'" and value[-1] == "'"): return(True)

    #
    # Do IPv4 test for dotted decimal x.x.x.x.
    #
    if (value.find(".") != -1): 
        addr = value.split(".")
        if (len(addr) != 4): return(False)

        for byte in addr:
            if (byte.isdigit() == False): return(False)
            if (int(byte) > 255): return(False)
        #endfor
        return(True)
    #endif
    
    #
    # Test for a geo-prefix. They have N, S, W, E characters in them.
    #
    if (value.find("-") != -1): 
        addr = value.split("-")
        for i in ["N", "S", "W", "E"]:
            if (i in addr):
                if (len(addr) < 8): return(False)
                return(True)
            #endif
        #endfor
    #endif

    #
    # Do MAC test in format xxxx-xxxx-xxxx.
    #
    if (value.find("-") != -1): 
        addr = value.split("-")
        if (len(addr) != 3): return(False)

        for hexgroup in addr:
            try: int(hexgroup, 16)
            except: return(False)
        #endfor
        return(True)
    #endif

    #
    # Do IPv6 test in format aaaa:bbbb::cccc:dddd
    #
    if (value.find(":") != -1): 
        addr = value.split(":")
        if (len(addr) < 2): return(False)

        found_null = False
        count = 0
        for hexgroup in addr:
            count += 1
            if (hexgroup == ""):
                if (found_null):
                    if (len(addr) == count): break
                    if (count > 2): return(False)
                #endif
                found_null = True
                continue
            #endif
            try: int(hexgroup, 16)
            except: return(False)
        #endfor
        return(True)
    #endif

    #
    # Do E.164 format test. The address is a "+" followed by <= 15 BCD digits.
    #
    if (value[0] == "+"): 
        addr = value[1::]
        for digit in addr: 
            if (digit.isdigit() == False): return(False)
        #endfor
        return(True)
    #endif
    return(False)
#enddef

#
# lisp_process_api
#
# Used by all lisp processes (not the lisp-core process) to read data 
# structures and return them to the LISP process.
#
# Variable data_structure has following format:
#
#     "<data-structure-name>%{<dictionary-array-of-parameters>}"
#
# Variable "data_structure" is a string and not a byte string. Caller converts.
#
def lisp_process_api(process, lisp_socket, data_structure):
    api_name, parms = data_structure.split("%")

    lprint("Process API request '{}', parameters: '{}'".format(api_name, 
        parms))

    data = []
    if (api_name == "map-cache"):
        if (parms == ""):
            data = lisp_map_cache.walk_cache(lisp_process_api_map_cache, data)
        else:
            data = lisp_process_api_map_cache_entry(json.loads(parms))
        #endif
    #endif
    if (api_name == "site-cache"):
        if (parms == ""):
            data = lisp_sites_by_eid.walk_cache(lisp_process_api_site_cache, 
                data)
        else:
            data = lisp_process_api_site_cache_entry(json.loads(parms))
        #endif
    #endif
    if (api_name == "site-cache-summary"):
        data = lisp_process_api_site_cache_summary(lisp_sites_by_eid)
    #endif
    if (api_name ==  "map-server"):
        parms = {} if (parms == "") else json.loads(parms)
        data = lisp_process_api_ms_or_mr(True, parms)
    #endif
    if (api_name ==  "map-resolver"):
        parms = {} if (parms == "") else json.loads(parms)
        data = lisp_process_api_ms_or_mr(False, parms)
    #endif
    if (api_name ==  "database-mapping"):
        data = lisp_process_api_database_mapping()
    #endif

    #
    # Send IPC back to lisp-core process.
    #
    data = json.dumps(data)
    ipc = lisp_api_ipc(process, data)
    lisp_ipc(ipc, lisp_socket, "lisp-core")
    return
#enddef

#
# lisp_process_api_map_cache
#
# Return map-cache to API caller.
#
def lisp_process_api_map_cache(mc, data):
    
    #
    # There is only destination state in this map-cache entry.
    #
    if (mc.group.is_null()): return(lisp_gather_map_cache_data(mc, data))

    if (mc.source_cache == None): return([True, data])

    #
    # There is (source, group) state so walk all sources for this group
    # entry.
    #
    data = mc.source_cache.walk_cache(lisp_gather_map_cache_data, data)
    return([True, data])
#enddef

#
# lisp_gather_map_cache_data
#
# Return map-cache to API caller.
#
def lisp_gather_map_cache_data(mc, data):
    entry = {}
    entry["instance-id"] = str(mc.eid.instance_id)
    entry["eid-prefix"] = mc.eid.print_prefix_no_iid()
    if (mc.group.is_null() == False):
        entry["group-prefix"] = mc.group.print_prefix_no_iid()
    #endif
    entry["uptime"] = lisp_print_elapsed(mc.uptime)
    entry["expires"] = lisp_print_elapsed(mc.uptime)
    entry["action"] =  lisp_map_reply_action_string[mc.action]
    entry["ttl"] = "--" if mc.map_cache_ttl == None else \
        str(mc.map_cache_ttl / 60)

    #
    # Encode in RLOC-set which is an array of entries.
    #
    rloc_set = []
    for rloc in mc.rloc_set:
        r = lisp_fill_rloc_in_json(rloc)

        #
        # If this is a multicast RLOC, then add the array for member RLOCs
        # that may have responded to a multicast RLOC-probe.
        #
        if (rloc.rloc.is_multicast_address()):
            r["multicast-rloc-set"] = []
            for mrloc in list(rloc.multicast_rloc_probe_list.values()):
                mr = lisp_fill_rloc_in_json(mrloc)
                r["multicast-rloc-set"].append(mr)
            #endfor
        #endif

        rloc_set.append(r)
    #endfor
    entry["rloc-set"] = rloc_set
    
    data.append(entry)
    return([True, data])
#enddef

#
# lisp_fill_rloc_in_json
#
# Fill in fields from lisp_rloc() into the JSON that is reported via the
# restful API.
#
def lisp_fill_rloc_in_json(rloc):
    r = {}
    addr_str = None
    if (rloc.rloc_exists()): 
        r["address"] = rloc.rloc.print_address_no_iid()
        addr_str = r["address"]
    #endif

    if (rloc.translated_port != 0):
        r["encap-port"] = str(rloc.translated_port)
        addr_str +=  ":" + r["encap-port"] 
    #endif

    if (addr_str and addr_str in lisp_crypto_keys_by_rloc_encap):
        key = lisp_crypto_keys_by_rloc_encap[addr_str][1]
        if (key != None and key.shared_key != None): 
            r["encap-crypto"] = "crypto-" + key.cipher_suite_string
        #endif
    #endif
        
    r["state"] = rloc.print_state()
    if (rloc.geo): r["geo"] = rloc.geo.print_geo()
    if (rloc.elp): r["elp"] = rloc.elp.print_elp(False)
    if (rloc.rle): r["rle"] = rloc.rle.print_rle(False, False)
    if (rloc.json): r["json"] = rloc.json.print_json(False)
    if (rloc.rloc_name): r["rloc-name"] = rloc.rloc_name
    stats = rloc.stats.get_stats(False, False)
    if (stats):
        r["stats"] = stats
        r["recent-packet-sec"] = rloc.stats.recent_packet_sec()
        r["recent-packet-min"] = rloc.stats.recent_packet_min()
    #endif
    state_change = lisp_print_elapsed(rloc.last_state_change)
    if (state_change == "never"):
        state_change = lisp_print_elapsed(rloc.uptime)
    #endif
    r["uptime"] = state_change
    r["upriority"] = str(rloc.priority)
    r["uweight"] = str(rloc.weight)
    r["mpriority"] = str(rloc.mpriority)
    r["mweight"] = str(rloc.mweight)
    reply = rloc.last_rloc_probe_reply
    if (reply):
        r["last-rloc-probe-reply"] = lisp_print_elapsed(reply)
        r["rloc-probe-rtt"] = str(rloc.rloc_probe_rtt)
    #endif
    r["rloc-hop-count"] = rloc.rloc_probe_hops
    r["recent-rloc-hop-counts"] = rloc.recent_rloc_probe_hops

    r["rloc-probe-latency"] = rloc.rloc_probe_latency
    r["recent-rloc-probe-latencies"] = rloc.recent_rloc_probe_latencies

    recent_rtts = []
    for rtt in rloc.recent_rloc_probe_rtts: recent_rtts.append(str(rtt))
    r["recent-rloc-probe-rtts"] = recent_rtts
    return(r)
#enddef

#
# lisp_process_api_map_cache_entry
#
# Parse API parameters in dictionary array, do longest match lookup.
#
def lisp_process_api_map_cache_entry(parms):
    iid = parms["instance-id"]
    iid = 0 if (iid == "") else int(iid)

    #
    # Get EID or source of (S,G).
    #
    eid = lisp_address(LISP_AFI_NONE, "", 0, iid)
    eid.store_prefix(parms["eid-prefix"])
    dest = eid
    source = eid

    #
    # See if we are doing a group lookup. Make that destination and the EID
    # the source.
    #
    group = lisp_address(LISP_AFI_NONE, "", 0, iid)
    if ("group-prefix" in parms):
        group.store_prefix(parms["group-prefix"])
        dest = group
    #endif

    data = []
    mc = lisp_map_cache_lookup(source, dest)
    if (mc): status, data = lisp_process_api_map_cache(mc, data)
    return(data)
#enddef

#
# lisp_process_api_site_cache_summary
#
# Returns:
#
# [ { "site" : '<site-name>", "registrations" : [  {"eid-prefix" : "<eid>",
#     "count" : "<count>", "registered-count" : "<registered>" }, ... ]
# } ]
#
def lisp_process_api_site_cache_summary(site_cache):
    site = { "site" : "", "registrations" : [] }
    entry = { "eid-prefix" : "",  "count" : 0, "registered-count" : 0 }

    sites = {}
    for ml in site_cache.cache_sorted:
        for se in list(site_cache.cache[ml].entries.values()):
            if (se.accept_more_specifics == False): continue
            if (se.site.site_name not in sites):
                sites[se.site.site_name] = []
            #endif
            e = copy.deepcopy(entry)
            e["eid-prefix"] = se.eid.print_prefix()
            e["count"] = len(se.more_specific_registrations)
            for mse in se.more_specific_registrations:
                if (mse.registered): e["registered-count"] += 1
            #endfor
            sites[se.site.site_name].append(e)
        #endfor
    #endfor

    data = []
    for site_name in sites:
        s = copy.deepcopy(site)
        s["site"] = site_name
        s["registrations"] = sites[site_name]
        data.append(s)
    #endfor
    return(data)
#enddef    
    
#
# lisp_process_api_site_cache
#
# Return site-cache to API caller.
#
def lisp_process_api_site_cache(se, data):
    
    #
    # There is only destination state in this site-cache entry.
    #
    if (se.group.is_null()): return(lisp_gather_site_cache_data(se, data))

    if (se.source_cache == None): return([True, data])

    #
    # There is (source, group) state so walk all sources for this group
    # entry.
    #
    data = se.source_cache.walk_cache(lisp_gather_site_cache_data, data)
    return([True, data])
#enddef

#
# lisp_process_api_ms_or_mr
#
# Return map-cache to API caller.
#
def lisp_process_api_ms_or_mr(ms_or_mr, data):
    address = lisp_address(LISP_AFI_NONE, "", 0, 0)
    dns_name = data["dns-name"] if ("dns-name" in data) else None
    if ("address" in data):
        address.store_address(data["address"])
    #endif

    value = {}
    if (ms_or_mr):
        for ms in list(lisp_map_servers_list.values()):
            if (dns_name):
                if (dns_name != ms.dns_name): continue
            else:
                if (address.is_exact_match(ms.map_server) == False): continue
            #endif

            value["dns-name"] = ms.dns_name
            value["address"] = ms.map_server.print_address_no_iid()
            value["ms-name"] = "" if ms.ms_name == None else ms.ms_name
            return([value])
        #endfor
    else:
        for mr in list(lisp_map_resolvers_list.values()):
            if (dns_name):
                if (dns_name != mr.dns_name): continue
            else:
                if (address.is_exact_match(mr.map_resolver) == False): continue
            #endif

            value["dns-name"] = mr.dns_name
            value["address"] = mr.map_resolver.print_address_no_iid()
            value["mr-name"] = "" if mr.mr_name == None else mr.mr_name
            return([value])
        #endfor
    #endif
    return([])
#enddef

#
# lisp_process_api_database_mapping
#
# Return array of database-mappings configured, include dynamic data like
# translated_rloc in particular.
#
def lisp_process_api_database_mapping():
    data = []

    for db in lisp_db_list:
        entry = {}
        entry["eid-prefix"] = db.eid.print_prefix()
        if (db.group.is_null() == False):
            entry["group-prefix"] = db.group.print_prefix()
        #endif

        rlocs = []
        for r in db.rloc_set:
            rloc = {}
            if (r.rloc.is_null() == False):
                rloc["rloc"] = r.rloc.print_address_no_iid()
            #endif
            if (r.rloc_name != None): rloc["rloc-name"] = r.rloc_name
            if (r.interface != None): rloc["interface"] = r.interface
            tr = r.translated_rloc
            if (tr.is_null() == False):
                rloc["translated-rloc"] = tr.print_address_no_iid()
                if (r.translated_port != 0):
                    rloc["translated-port"] = r.translated_port
                #endif
            #endif
            if (rloc != {}): rlocs.append(rloc)
        #endfor

        #
        # Add RLOCs array to EID entry.
        #
        entry["rlocs"] = rlocs

        #
        # Add EID entry to return array.
        #
        data.append(entry)
    #endfor
    return(data)
#enddef

#
# lisp_gather_site_cache_data
#
# Return site-cache to API caller.
#
def lisp_gather_site_cache_data(se, data):
    entry = {}
    entry["site-name"] = se.site.site_name
    entry["instance-id"] = str(se.eid.instance_id)
    entry["eid-prefix"] = se.eid.print_prefix_no_iid()
    if (se.group.is_null() == False):
        entry["group-prefix"] = se.group.print_prefix_no_iid()
    #endif
    entry["registered"] = "yes" if se.registered else "no"
    entry["first-registered"] = lisp_print_elapsed(se.first_registered)
    entry["last-registered"] = lisp_print_elapsed(se.last_registered)

    addr = se.last_registerer
    addr = "none" if addr.is_null() else addr.print_address() 
    entry["last-registerer"] = addr
    entry["ams"] = "yes" if (se.accept_more_specifics) else "no"
    entry["dynamic"] = "yes" if (se.dynamic) else "no"
    entry["site-id"] = str(se.site_id)
    if (se.xtr_id_present): 
        entry["xtr-id"] = "0x"+ lisp_hex_string(se.xtr_id)
    #endif

    #
    # Encode in RLOC-set which is an array of entries.
    #
    rloc_set = []
    for rloc in se.registered_rlocs:
        r = {}
        r["address"] = rloc.rloc.print_address_no_iid() if rloc.rloc_exists() \
             else "none"

        if (rloc.geo): r["geo"] = rloc.geo.print_geo()
        if (rloc.elp): r["elp"] = rloc.elp.print_elp(False)
        if (rloc.rle): r["rle"] = rloc.rle.print_rle(False, True)
        if (rloc.json): r["json"] = rloc.json.print_json(False)
        if (rloc.rloc_name): r["rloc-name"] = rloc.rloc_name
        r["uptime"] = lisp_print_elapsed(rloc.uptime)
        r["upriority"] = str(rloc.priority)
        r["uweight"] = str(rloc.weight)
        r["mpriority"] = str(rloc.mpriority)
        r["mweight"] = str(rloc.mweight)
        if (rloc.translated_port != 0):
            r["encap-port"] = str(rloc.translated_port)
        #endif
    #endif

        rloc_set.append(r)
    #endfor
    entry["registered-rlocs"] = rloc_set
    
    data.append(entry)
    return([True, data])
#enddef

#
# lisp_process_api_site_cache_entry
#
# Parse API parameters in dictionary array, do longest match lookup.
#
def lisp_process_api_site_cache_entry(parms):
    iid = parms["instance-id"]
    iid = 0 if (iid == "") else int(iid)

    #
    # Get EID or source of (S,G).
    #
    eid = lisp_address(LISP_AFI_NONE, "", 0, iid)
    eid.store_prefix(parms["eid-prefix"])

    #
    # See if we are doing a group lookup. Make that destination and the EID
    # the source.
    #
    group = lisp_address(LISP_AFI_NONE, "", 0, iid)
    if ("group-prefix" in parms):
        group.store_prefix(parms["group-prefix"])
    #endif

    data = []
    se = lisp_site_eid_lookup(eid, group, False)
    if (se): lisp_gather_site_cache_data(se, data)
    return(data)
#enddef

#
# lisp_get_interface_instance_id
#
# Return instance-ID from lisp_interface() class.
#
def lisp_get_interface_instance_id(device, source_eid):
    interface = None
    if (device in lisp_myinterfaces):
        interface = lisp_myinterfaces[device]
    #endif

    #
    # Didn't find an instance-ID configured on a "lisp interface", return
    # the default.
    #
    if (interface == None or interface.instance_id == None): 
        return(lisp_default_iid)
    #endif

    #
    # If there is a single interface data structure for a given device,
    # return the instance-ID conifgured for it. Otherwise, check to see
    # if this is a multi-tenant EID-prefix. And then test all configured
    # prefixes in each lisp_interface() for a best match. This allows
    # for multi-tenancy on a single xTR interface.
    #
    iid = interface.get_instance_id()
    if (source_eid == None): return(iid)

    save_iid = source_eid.instance_id
    best = None
    for interface in lisp_multi_tenant_interfaces:
        if (interface.device != device): continue
        prefix = interface.multi_tenant_eid
        source_eid.instance_id = prefix.instance_id
        if (source_eid.is_more_specific(prefix) == False): continue
        if (best == None or best.multi_tenant_eid.mask_len < prefix.mask_len):
            best = interface
        #endif
    #endfor
    source_eid.instance_id = save_iid

    if (best == None): return(iid)
    return(best.get_instance_id())
#enddef

#
# lisp_allow_dynamic_eid
#
# Returns dynamic-eid-deivce (or device if "dynamic-eid-device" not configured)
# if supplied EID matches configured dynamic-EID in a "lisp interface" command.
# Otherwise, returns None.
#
def lisp_allow_dynamic_eid(device, eid):
    if (device not in lisp_myinterfaces): return(None)

    interface = lisp_myinterfaces[device]
    return_interface = device if interface.dynamic_eid_device == None else \
        interface.dynamic_eid_device

    if (interface.does_dynamic_eid_match(eid)): return(return_interface)
    return(None)
#enddef

#
# lisp_start_rloc_probe_timer
#
# Set the RLOC-probe timer to expire in 1 minute (by default).
#
def lisp_start_rloc_probe_timer(interval, lisp_sockets):
    global lisp_rloc_probe_timer

    if (lisp_rloc_probe_timer != None): lisp_rloc_probe_timer.cancel()

    func = lisp_process_rloc_probe_timer
    timer = threading.Timer(interval, func, [lisp_sockets])
    lisp_rloc_probe_timer = timer
    timer.start()
    return
#enddef

#
# lisp_show_rloc_probe_list
#
# Print out the lisp_show_rloc_probe_list in a readable way for debugging.
#
def lisp_show_rloc_probe_list():
    lprint(bold("----- RLOC-probe-list -----", False))
    for key in lisp_rloc_probe_list:
        rloc_array = lisp_rloc_probe_list[key]
        lprint("RLOC {}:".format(key))
        for r, e, g in rloc_array:
            lprint("  [{}, {}, {}, {}]".format(hex(id(r)), e.print_prefix(), 
                g.print_prefix(), r.translated_port))
        #endfor
    #endfor
    lprint(bold("---------------------------", False))
    return
#enddef

#
# lisp_mark_rlocs_for_other_eids
#
# When the parent RLOC that we have RLOC-probe state for comes reachable or
# goes unreachable, set the state appropriately for other EIDs using the SAME
# RLOC. The parent is the first RLOC in the eid-list.
#
def lisp_mark_rlocs_for_other_eids(eid_list):

    #
    # Don't process parent but put its EID in printed list.
    #
    rloc, e, g = eid_list[0]
    eids = [lisp_print_eid_tuple(e, g)]

    for rloc, e, g in eid_list[1::]:
        rloc.state = LISP_RLOC_UNREACH_STATE
        rloc.last_state_change = lisp_get_timestamp()
        eids.append(lisp_print_eid_tuple(e, g))
    #endfor

    unreach = bold("unreachable", False)
    rloc_str = red(rloc.rloc.print_address_no_iid(), False)

    for eid in eids:
        e = green(eid, False)
        lprint("RLOC {} went {} for EID {}".format(rloc_str, unreach, e))
    #endfor

    #
    # For each EID, tell external data-plane about new RLOC-set (RLOCs minus
    # the ones that just went unreachable).
    #
    for rloc, e, g in eid_list:
        mc = lisp_map_cache.lookup_cache(e, True)
        if (mc): lisp_write_ipc_map_cache(True, mc)
    #endfor
    return
#enddef

#
# lisp_process_multicast_rloc
#
# Time-out member RLOCs for this mutlicast RLOC. Check if an RLOC-probe reply
# has been received within the timeout interval.
#
def lisp_process_multicast_rloc(multicast_rloc):
    maddr = multicast_rloc.rloc.print_address_no_iid()

    now = lisp_get_timestamp()
    for addr in multicast_rloc.multicast_rloc_probe_list:
        mrloc = multicast_rloc.multicast_rloc_probe_list[addr]
        if (mrloc.last_rloc_probe_reply + LISP_RLOC_PROBE_REPLY_WAIT >= now):
            continue
        #endif
        if (mrloc.state == LISP_RLOC_UNREACH_STATE): continue

        #
        # It went down.
        #
        mrloc.state = LISP_RLOC_UNREACH_STATE
        mrloc.last_state_change = lisp_get_timestamp()

        lprint("Multicast-RLOC {} member-RLOC {} went unreachable".format( \
            maddr, red(addr, False)))
    #endfor
#enddef

#
# lisp_process_rloc_probe_timer
#
# Periodic RLOC-probe timer has expired. Go through cached RLOCs from map-
# cache and decide to suppress or rate-limit RLOC-probes. This function
# is also used to time out "unreachability" state so we can start RLOC-probe
# a previously determined unreachable RLOC.
#
def lisp_process_rloc_probe_timer(lisp_sockets):
    lisp_set_exception()

    lisp_start_rloc_probe_timer(LISP_RLOC_PROBE_INTERVAL, lisp_sockets)
    if (lisp_rloc_probing == False): return

    #
    # Debug code. Must rebuild image to set boolean to True.
    #
    if (lisp_print_rloc_probe_list): lisp_show_rloc_probe_list()
 
    #
    # Check for egress multi-homing.
    #
    default_next_hops = lisp_get_default_route_next_hops()

    msg = "---------- Start RLOC Probing for {} RLOC entries ----------". \
        format(len(lisp_rloc_probe_list))
    lprint(bold(msg, False))

    #
    # Walk the list.
    #
    count = 0
    probe = bold("RLOC-probe", False)
    for values in list(lisp_rloc_probe_list.values()):

        #
        # Just do one RLOC-probe for the RLOC even if it is used for 
        # multiple EID-prefixes.
        #
        last_rloc = None
        for parent_rloc, eid, group in values:
            addr_str = parent_rloc.rloc.print_address_no_iid()

            #
            # Do not RLOC-probe gleaned entries if configured.
            #
            glean, do_probe, y = lisp_allow_gleaning(eid, None, parent_rloc)
            if (glean and do_probe == False):
                e = green(eid.print_address(), False)
                addr_str += ":{}".format(parent_rloc.translated_port)
                lprint("Suppress probe to RLOC {} for gleaned EID {}".format( \
                    red(addr_str, False), e))
                continue
            #endif

            #
            # Do not send RLOC-probes to RLOCs that are in down-state or admin-
            # down-state. The RLOC-probe reply will apply for all EID-prefixes
            # and the RLOC state will be updated for each.
            #
            if (parent_rloc.down_state()): continue

            #
            # Do not send multiple RLOC-probes to the same RLOC for 
            # different EID-prefixes. Multiple RLOC entries could have 
            # same RLOC address but differnet translated ports. These 
            # need to be treated as different ETRs (they are both behind 
            # the same NAT) from an RTR's perspective. On an ITR, if the 
            # RLOC-names are different for the same RLOC address, we need
            # to treat these as different ETRs since an ITR does not keep
            # port state for an RLOC.
            #
            if (last_rloc):
                parent_rloc.last_rloc_probe_nonce = \
                    last_rloc.last_rloc_probe_nonce
                if (last_rloc.translated_port == parent_rloc.translated_port \
                   and last_rloc.rloc_name == parent_rloc.rloc_name): 
                    e = green(lisp_print_eid_tuple(eid, group), False)
                    lprint("Suppress probe to duplicate RLOC {} for {}". \
                        format(red(addr_str, False), e))

                    #
                    # Copy last-rloc send probe timer, so all EIDs using the
                    # same RLOC can have sync'ed rtts.
                    #
                    parent_rloc.last_rloc_probe = last_rloc.last_rloc_probe
                    continue
                #endif
            #endif

            #
            # If this RLOC has a host-route stored for forwarding, get it,
            # and save it since we need to change nex-hops now to direct
            # RLOC-probes.
            #
            save_nh = None
            if (parent_rloc.rloc_next_hop != None):
                save_nh = lisp_get_host_route_next_hop(addr_str)
                if (save_nh):
                    lprint("Remove forwarding next-hop {}".format(save_nh))
                    lisp_install_host_route(addr_str, None, False)
                #endif
            #endif

            rloc = None
            while (True):
                rloc = parent_rloc if rloc == None else rloc.next_rloc
                if (rloc == None): break

                #
                # First check if next-hop/interface is up for egress multi-
                # homing.
                #
                if (rloc.rloc_next_hop != None):
                    if (rloc.rloc_next_hop not in default_next_hops):
                        d, n = rloc.rloc_next_hop
                        if (rloc.up_state()):
                            rloc.state = LISP_RLOC_UNREACH_STATE
                            rloc.last_state_change = lisp_get_timestamp()
                            lisp_update_rtr_updown(rloc.rloc, False)
                        #endif
                        unreach = bold("unreachable", False)
                        lprint("Next-hop {}({}) for RLOC {} is {}".format(n, d,
                            red(addr_str, False), unreach))
                        continue
                    #endif
                #endif

                #
                # Send RLOC-probe to unreach-state RLOCs if down for a minute.
                #
                last = rloc.last_rloc_probe
                delta = 0 if last == None else time.time() - last
                if (rloc.unreach_state() and delta < LISP_RLOC_PROBE_INTERVAL):
                    lprint("Waiting for probe-reply from RLOC {}".format( \
                        red(addr_str, False)))
                    continue
                #endif

                #
                # Check to see if we are in nonce-echo mode and no echo has 
                # been returned.
                #
                echo_nonce = lisp_get_echo_nonce(None, addr_str)
                if (echo_nonce and echo_nonce.request_nonce_timeout()):
                    rloc.state = LISP_RLOC_NO_ECHOED_NONCE_STATE
                    rloc.last_state_change = lisp_get_timestamp()
                    unreach = bold("unreachable", False)
                    lprint("RLOC {} went {}, nonce-echo failed".format( \
                        red(addr_str, False), unreach))
                    lisp_update_rtr_updown(rloc.rloc, False)
                    continue
                #endif

                #
                # Suppress sending RLOC probe if we just a nonce-echo in the 
                # last minute.
                #
                if (echo_nonce and echo_nonce.recently_echoed()):
                    lprint(("Suppress RLOC-probe to {}, nonce-echo " + \
                        "received").format(red(addr_str, False)))
                    continue
                #endif
  
                #
                # Check if we have not received a RLOC-probe reply for one 
                # timer interval. If not, put RLOC state in "unreach-state".
                #
                if (rloc.last_rloc_probe != None):
                    last = rloc.last_rloc_probe_reply
                    if (last == None): last = 0
                    delta = time.time() - last
                    if (rloc.up_state() and \
                        delta >= LISP_RLOC_PROBE_REPLY_WAIT):
                        rloc.state = LISP_RLOC_UNREACH_STATE
                        rloc.last_state_change = lisp_get_timestamp()
                        lisp_update_rtr_updown(rloc.rloc, False)
                        unreach = bold("unreachable", False)
                        lprint("RLOC {} went {}, probe it".format( \
                            red(addr_str, False), unreach))

                        lisp_mark_rlocs_for_other_eids(values)
                    #endif
                #endif
                
                rloc.last_rloc_probe = lisp_get_timestamp()

                reach = "" if rloc.unreach_state() == False else " unreachable"

                #
                # Send Map-Request RLOC-probe. We may have to send one for each
                # egress interface to the same RLOC address. Install host 
                # route in RLOC so we can direct the RLOC-probe on an egress 
                # interface. Save forwarding next-hop so we can reinstall
                # after the RLOC-probe goes out directed interface.
                #
                nh_str = ""
                nh = None
#               if (rloc.rloc_next_hop != None):

                #
                # Temporarily (will fix later), do not install host routes
                # for RLOC-probes. It causes the kernel to drop Map-Requests
                # locally. Will look at using Netlink API for better results.
                # The "and nh != None" disables host-route installation.
                #
                if (rloc.rloc_next_hop != None and nh != None):
                    d, nh = rloc.rloc_next_hop
                    lisp_install_host_route(addr_str, nh, True)
                    nh_str = ", send to nh {} on {}".format(nh, bold(d, False))
                #endif

                #
                # Print integrated log message before sending RLOC-probe.
                #
                rtt = rloc.print_rloc_probe_rtt()
                astr = addr_str
                if (rloc.translated_port != 0): 
                    astr += ":{}".format(rloc.translated_port)
                #endif
                astr= red(astr, False)
                if (rloc.rloc_name != None):
                    astr += " (" + blue(rloc.rloc_name, False) + ")"
                #endif
                lprint("Send {} to{} {}, last rtt: {}{}".format(probe, reach, 
                    astr, rtt, nh_str))

                #
                # Might be first time and other RLOCs on the chain may not
                # have RLOC address. Copy now.
                #
                if (rloc.rloc.is_null()): 
                    rloc.rloc.copy_address(parent_rloc.rloc)
                #endif

                #
                # Time-out member RLOCs for multicast RLOC probing.
                #
                if (rloc.multicast_rloc_probe_list != {}):
                    lisp_process_multicast_rloc(rloc)
                #endif

                #
                # Send RLOC-probe Map-Request.
                #
                seid = None if (group.is_null()) else eid
                deid = eid if (group.is_null()) else group
                lisp_send_map_request(lisp_sockets, 0, seid, deid, rloc)
                last_rloc = parent_rloc

                #
                # Check mapping system to see if a translated address or port
                # has changed. This occurs when a decent-nat RLOC has been
                # unreachable for 1 minute.
                #
                if (rloc.is_decent_nat_port() and rloc.unreach_state()):
                    rloc.refresh_decent_nat_rloc(lisp_sockets, deid)
                #endif

                #
                # Remove installed host route. And install forwarding next-hop
                # when we move to a new RLOC to test.
                #
                if (nh): lisp_install_host_route(addr_str, nh, False)
            #endwhile

            #
            # And install forwarding next-hop for last RLOC now we are going
            # to process a new RLOC.
            #
            if (save_nh):
                lprint("Reinstall forwarding next-hop {}".format(save_nh))
                lisp_install_host_route(addr_str, save_nh, True)
            #endif

            #
            # Send 10 RLOC-probes and then sleep for 20 ms.
            #
            count += 1
            if ((count % 10) == 0): time.sleep(0.020)
        #endfor
    #endfor

    lprint(bold("---------- End RLOC Probing ----------", False))
    return
#enddef

#
# lisp_update_rtr_updown
#
# The lisp-itr process will send an IPC message to the lisp-etr process for
# the RLOC-probe status change for an RTR. 
#
def lisp_update_rtr_updown(rtr, updown):
    global lisp_ipc_socket

    #
    # This is only done on an ITR.
    #
    if (lisp_i_am_itr == False): return

    #
    # When the xtr-parameter indicates to register all RTRs, we are doing it
    # conditionally so we don't care about the status. Suppress IPC messages.
    #
    if (lisp_register_all_rtrs): return

    rtr_str = rtr.print_address_no_iid()

    #
    # Check if RTR address is in LISP the lisp-itr process learned from the
    # map-server.
    #
    if (rtr_str not in lisp_rtr_list): return

    updown = "up" if updown else "down"
    lprint("Send ETR IPC message, RTR {} has done {}".format(
        red(rtr_str, False), bold(updown, False)))

    #
    # Build IPC message.
    #
    ipc = "rtr%{}%{}".format(rtr_str, updown)
    ipc = lisp_command_ipc(ipc, "lisp-itr")
    lisp_ipc(ipc, lisp_ipc_socket, "lisp-etr")
    return
#enddef

#
# lisp_process_rloc_probe_reply
#
# We have received a RLOC-probe Map-Reply, process it.
#
def lisp_process_rloc_probe_reply(rloc_entry, source, port, map_reply, ttl,
    mrloc, rloc_name):
    global lisp_rloc_probe_nonce_list
    
    rloc = rloc_entry.rloc
    nonce = map_reply.nonce
    hc = map_reply.hop_count
    probe = bold("RLOC-probe reply", False)
    map_reply_addr = rloc.print_address_no_iid()
    source_addr = source.print_address_no_iid()
    pl = lisp_rloc_probe_list
    jt = rloc_entry.json.json_string if rloc_entry.json else None
    ts = lisp_get_timestamp()

    #
    # If this RLOC-probe reply is in response to a RLOC-probe request to a
    # multicast RLOC, then store all responses. Create a lisp_rloc() for new
    # entries.
    #
    if (mrloc != None):
        multicast_rloc = mrloc.rloc.print_address_no_iid()
        if (map_reply_addr not in mrloc.multicast_rloc_probe_list):
            nrloc = lisp_rloc()
            nrloc = copy.deepcopy(mrloc)
            nrloc.rloc.copy_address(rloc)
            nrloc.multicast_rloc_probe_list = {}
            mrloc.multicast_rloc_probe_list[map_reply_addr] = nrloc
        #endif
        nrloc = mrloc.multicast_rloc_probe_list[map_reply_addr]
        nrloc.rloc_name = rloc_name
        nrloc.last_rloc_probe_nonce = mrloc.last_rloc_probe_nonce
        nrloc.last_rloc_probe = mrloc.last_rloc_probe
        r, eid, group = lisp_rloc_probe_list[multicast_rloc][0]
        nrloc.process_rloc_probe_reply(ts, nonce, eid, group, hc, ttl, jt)
        mrloc.process_rloc_probe_reply(ts, nonce, eid, group, hc, ttl, jt)
        return
    #endif
        
    #
    # For decent-NAT cases, get the translated ephermal port from the
    # rloc-name. Use it to find RLOC-probe state.
    #
    if (rloc_name.find(LISP_TP) != -1):
        port = int(rloc_name.split(LISP_TP)[-1])
    #endif
    
    #
    # If we can't find RLOC address from the Map-Reply in the probe-list,
    # maybe the same ETR is sending sourcing from a different address. Check
    # that address in the probe-list.
    #
    addr = map_reply_addr
    if (addr not in pl):
        addr += ":" + str(port)
        if (addr not in pl):
            addr = source_addr
            if (addr not in pl):
                addr += ":" + str(port)
                lprint("    Received unsolicited {} from {}/{}, port {}". \
                    format(probe, red(map_reply_addr, False), red(source_addr,
                        False), port))
                return
            #endif
        #endif
    #endif

    #
    # For multi-homing, the rloc address may need to be found from the nonce
    # since the Map-Request doesn't store the probe destination address and
    # the ETR doesn't get the destination address on the received Map-Request
    # to reflect the probe-bit for the correct RLOC in the Map-Reply.
    #
    if (nonce in lisp_rloc_probe_nonce_list):
        probed_rloc = lisp_rloc_probe_nonce_list.pop(nonce)
        if (probed_rloc != addr):
            addr = probed_rloc
            lprint("    Obtain probed RLOC address {} from nonce 0x{}". \
                format(addr, lisp_hex_string(nonce)))
        #endif
    #endif

    #
    # Look for RLOC in the RLOC-probe list for EID tuple and fix-up stored
    # RLOC-probe state.
    #
    for rloc, eid, group in lisp_rloc_probe_list[addr]:
        if (lisp_i_am_rtr):
            if (rloc.translated_port != 0 and rloc.translated_port != port):
                continue
            #endif
        #endif
        rloc.process_rloc_probe_reply(ts, nonce, eid, group, hc, ttl, jt)
    #endfor
    return
#enddef

#
# lisp_db_list_length
#
# Returns the number of entries that need to be registered. This will include
# static and dynamic EIDs.
# 
def lisp_db_list_length():
    count = 0
    for db in lisp_db_list:
        count += len(db.dynamic_eids) if db.dynamic_eid_configured() else 1
        count += len(db.eid.iid_list)
    #endif
    return(count)
#endif

#
# lisp_is_myeid
#
# Return true if supplied EID is an EID supported by this ETR. That means a
# longest match lookup is done.
#
def lisp_is_myeid(eid):
    for db in lisp_db_list:
        if (eid.is_more_specific(db.eid)): return(True)
    #endfor
    return(False)
#enddef    

#
# lisp_format_macs
#
# Take two MAC address strings and format them with dashes and place them in
# a format string "0000-1111-2222 -> 3333-4444-5555" for displaying in
# lisp.dprint().
#
def lisp_format_macs(sa, da):
    sa = sa[0:4] + "-" + sa[4:8] + "-" + sa[8:12]
    da = da[0:4] + "-" + da[4:8] + "-" + da[8:12]
    return("{} -> {}".format(sa, da))
#enddef

#
# lisp_get_echo_nonce
#
# Get lisp_nonce_echo() state from lisp_nonce_echo_list{}.
#
def lisp_get_echo_nonce(rloc, rloc_str):
    if (lisp_nonce_echoing == False): return(None)

    if (rloc): rloc_str = rloc.print_address_no_iid()
    echo_nonce = None
    if (rloc_str in lisp_nonce_echo_list):
        echo_nonce = lisp_nonce_echo_list[rloc_str]
    #endif
    return(echo_nonce)
#enddef

#
# lisp_decode_dist_name
#
# When we have reached an AFI=17 in an EID or RLOC record, return the 
# distinguished name, and new position of packet.
#
def lisp_decode_dist_name(packet):
    count = 0
    dist_name = b""

    while(packet[0:1] != b"\x00"):
        if (count == 255): return([None, None])
        dist_name += packet[0:1]
        packet = packet[1::]
        count += 1
    #endwhile

    packet = packet[1::]
    return(packet, dist_name.decode())
#enddef

#
# lisp_write_flow_log
#
# The supplied flow_log variable is an array of [datetime, lisp_packet]. This
# function is called and run in its own thread and then exits.
#
def lisp_write_flow_log(flow_log):
    f = open("./logs/lisp-flow.log", "a")

    count = 0
    for flow in flow_log:
        packet = flow[3]
        flow_str = packet.print_flow(flow[0], flow[1], flow[2])
        f.write(flow_str)
        count += 1
    #endfor
    f.close()
    del(flow_log)

    count = bold(str(count), False)
    lprint("Wrote {} flow entries to ./logs/lisp-flow.log".format(count))
    return
#enddef

#
# lisp_policy_command
#
# Configure "lisp policy" commands for all processes that need it.
#
def lisp_policy_command(kv_pair):
    p = lisp_policy("")
    set_iid = None

    match_set = []
    for i in range(len(kv_pair["datetime-range"])):
        match_set.append(lisp_policy_match())
    #endfor

    for kw in list(kv_pair.keys()):
        value = kv_pair[kw]

        #
        # Check for match parameters.
        #
        if (kw == "instance-id"):
            for i in range(len(match_set)):
                v = value[i]
                if (v == ""): continue
                match = match_set[i]
                if (match.source_eid == None):
                    match.source_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
                #endif
                if (match.dest_eid == None):
                    match.dest_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
                #endif
                match.source_eid.instance_id = int(v)
                match.dest_eid.instance_id = int(v)
            #endfor
        #endif
        if (kw == "source-eid"):
            for i in range(len(match_set)):
                v = value[i]
                if (v == ""): continue
                match = match_set[i]
                if (match.source_eid == None):
                    match.source_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
                #endif
                iid = match.source_eid.instance_id
                match.source_eid.store_prefix(v)
                match.source_eid.instance_id = iid
            #endfor
        #endif
        if (kw == "destination-eid"):
            for i in range(len(match_set)):
                v = value[i]
                if (v == ""): continue
                match = match_set[i]
                if (match.dest_eid == None):
                    match.dest_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
                #endif
                iid = match.dest_eid.instance_id
                match.dest_eid.store_prefix(v)
                match.dest_eid.instance_id = iid
            #endfor
        #endif
        if (kw == "source-rloc"):
            for i in range(len(match_set)):
                v = value[i]
                if (v == ""): continue
                match = match_set[i]
                match.source_rloc = lisp_address(LISP_AFI_NONE, "", 0, 0)
                match.source_rloc.store_prefix(v)
            #endfor
        #endif
        if (kw == "destination-rloc"):
            for i in range(len(match_set)):
                v = value[i]
                if (v == ""): continue
                match = match_set[i]
                match.dest_rloc = lisp_address(LISP_AFI_NONE, "", 0, 0)
                match.dest_rloc.store_prefix(v)
            #endfor
        #endif
        if (kw == "rloc-record-name"):
            for i in range(len(match_set)):
                v = value[i]
                if (v == ""): continue
                match = match_set[i]
                match.rloc_record_name = v
            #endfor
        #endif
        if (kw == "geo-name"):
            for i in range(len(match_set)):
                v = value[i]
                if (v == ""): continue
                match = match_set[i]
                match.geo_name = v
            #endfor
        #endif
        if (kw == "elp-name"):
            for i in range(len(match_set)):
                v = value[i]
                if (v == ""): continue
                match = match_set[i]
                match.elp_name = v
            #endfor
        #endif
        if (kw == "rle-name"):
            for i in range(len(match_set)):
                v = value[i]
                if (v == ""): continue
                match = match_set[i]
                match.rle_name = v
            #endfor
        #endif
        if (kw == "json-name"):
            for i in range(len(match_set)):
                v = value[i]
                if (v == ""): continue
                match = match_set[i]
                match.json_name = v
            #endfor
        #endif
        if (kw == "datetime-range"):
            for i in range(len(match_set)):
                v = value[i]
                match = match_set[i]
                if (v == ""): continue
                l = lisp_datetime(v[0:19])
                u = lisp_datetime(v[19::])
                if (l.valid_datetime() and u.valid_datetime()):
                    match.datetime_lower = l
                    match.datetime_upper = u
                #endif
            #endfor
        #endif

        #
        # Check for set parameters.
        #
        if (kw == "set-action"):
            p.set_action = value
        #endif
        if (kw == "set-record-ttl"):
            p.set_record_ttl = int(value)
        #endif
        if (kw == "set-instance-id"):
            if (p.set_source_eid == None):
                p.set_source_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
            #endif
            if (p.set_dest_eid == None):
                p.set_dest_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
            #endif
            set_iid = int(value)
            p.set_source_eid.instance_id = set_iid
            p.set_dest_eid.instance_id = set_iid
        #endif
        if (kw == "set-source-eid"):
            if (p.set_source_eid == None):
                p.set_source_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
            #endif
            p.set_source_eid.store_prefix(value)
            if (set_iid != None): p.set_source_eid.instance_id = set_iid
        #endif
        if (kw == "set-destination-eid"):
            if (p.set_dest_eid == None):
                p.set_dest_eid = lisp_address(LISP_AFI_NONE, "", 0, 0)
            #endif
            p.set_dest_eid.store_prefix(value)
            if (set_iid != None): p.set_dest_eid.instance_id = set_iid
        #endif
        if (kw == "set-rloc-address"):
            p.set_rloc_address = lisp_address(LISP_AFI_NONE, "", 0, 0)
            p.set_rloc_address.store_address(value)
        #endif
        if (kw == "set-rloc-record-name"):
            p.set_rloc_record_name = value
        #endif
        if (kw == "set-elp-name"):
            p.set_elp_name = value
        #endif
        if (kw == "set-geo-name"):
            p.set_geo_name = value
        #endif
        if (kw == "set-rle-name"):
            p.set_rle_name = value
        #endif
        if (kw == "set-json-name"):
            p.set_json_name = value
        #endif
        if (kw == "policy-name"):
            p.policy_name = value
        #endif
    #endfor

    #
    # Store match clauses and policy.
    #
    p.match_clauses = match_set
    p.save_policy()
    return
#enddef

lisp_policy_commands = {
    "lisp policy" : [lisp_policy_command, {
        "policy-name" : [True], 
        "match" : [], 
        "instance-id" : [True, 0, 0xffffffff],  
        "source-eid" : [True], 
        "destination-eid" : [True], 
        "source-rloc" : [True], 
        "destination-rloc" : [True], 
        "rloc-record-name" : [True], 
        "elp-name" : [True],
        "geo-name" : [True],
        "rle-name" : [True],
        "json-name" : [True],
        "datetime-range" : [True],
        "set-action" : [False, "process", "drop"],
        "set-record-ttl" : [True, 0, 0x7fffffff],
        "set-instance-id" : [True, 0, 0xffffffff],  
        "set-source-eid" : [True], 
        "set-destination-eid" : [True], 
        "set-rloc-address" : [True], 
        "set-rloc-record-name" : [True], 
        "set-elp-name" : [True],
        "set-geo-name" : [True],
        "set-rle-name" : [True],
        "set-json-name" : [True] } ]
}

#
# lisp_send_to_arista
#
# Send supplied CLI command to Arista so it can be configured via its design
# rules.
#
def lisp_send_to_arista(command, interface):
    interface = "" if (interface == None) else "interface " + interface

    cmd_str = command
    if (interface != ""): cmd_str = interface + ": " + cmd_str
    lprint("Send CLI command '{}' to hardware".format(cmd_str))

    commands = '''
        enable
        configure
        {}
        {}
    '''.format(interface, command)

    os.system("FastCli -c '{}'".format(commands))
    return
#enddef

#
# lisp_arista_is_alive
#
# Ask hardware if EID-prefix is alive. Return True if so.
#
def lisp_arista_is_alive(prefix):
    cmd = "enable\nsh plat trident l3 software routes {}\n".format(prefix)
    output = getoutput("FastCli -c '{}'".format(cmd))

    #
    # Skip over header line.
    #
    output = output.split("\n")[1]
    flag = output.split(" ")
    flag = flag[-1].replace("\r", "")

    #
    # Last column has "Y" or "N" for hit bit.
    #
    return(flag == "Y")
#enddef

#
# lisp_program_vxlan_hardware
#
# This function is going to populate hardware that can do VXLAN encapsulation.
# It will add an IPv4 route via the kernel pointing to a next-hop on a
# VLAN interface that is being bridged to other potential VTEPs.
#
# The responsibility of this routine is to do the following programming:
#
#     route add <eid-prefix> <next-hop>
#     arp -s <next-hop> <mac-address>
#
# to the kernel and to do this Arista specific command:
#
#     mac address-table static <mac-address> vlan 4094 interface vxlan 1 
#         vtep <vtep-address>
#
# Assumptions are:
#
# (1) Next-hop address is on the subnet for interface vlan4094.
# (2) VXLAN routing is already setup and will bridge <mac-address> to
#     the VTEP address this function supplies.
# (3) A "ip virtual-router mac-address" is configured that will match the
#     algorithmic mapping this function is doing between VTEP's IP address
#     and the MAC address it will listen on to do VXLAN routing.
#
# The required configuration on the VTEPs are:
#
#   vlan 4094
#   interface vlan4094
#     ip address ...            ! <next-hop> above point to subnet
#
#   interface Vxlan1
#      vxlan source-interface Loopback0
#      vxlan vlan 4094 vni 10000
#      vxlan flood vtep add 17.17.17.17  ! any address to bring up vlan4094
#
#   int loopback0
#      ip address a.b.c.d/m     ! this is the VTEP or RLOC <vtep-address>
#
#   ip virtual-router mac-address 0000.00bb.ccdd
#    
def lisp_program_vxlan_hardware(mc):

    #
    # For now, only do this on an Arista system. There isn't a python 
    # specific signature so just look to see if /persist/local/lispers.net
    # exists.
    #
    if (os.path.exists("/persist/local/lispers.net") == False): return

    #
    # If no RLOCs, just return. Otherwise program the first RLOC.
    #
    if (len(mc.best_rloc_set) == 0): return

    #
    # Get EID-prefix and RLOC (VTEP address) in string form.
    #
    eid_prefix = mc.eid.print_prefix_no_iid()
    rloc = mc.best_rloc_set[0].rloc.print_address_no_iid()

    #
    # Check to see if route is already present. If so, just return.
    #
    route = getoutput("ip route get {} | egrep vlan4094".format( \
        eid_prefix))
    if (route != ""):
        lprint("Route {} already in hardware: '{}'".format( \
            green(eid_prefix, False), route))
        return
    #endif

    #
    # Look for a vxlan interface and a vlan4094 interface. If they do not
    # exist, issue message and return. If we don't have an IP address on
    # vlan4094, then exit as well.
    #
    ifconfig = getoutput("ifconfig | egrep 'vxlan|vlan4094'")
    if (ifconfig.find("vxlan") == -1):
        lprint("No VXLAN interface found, cannot program hardware")
        return
    #endif
    if (ifconfig.find("vlan4094") == -1):
        lprint("No vlan4094 interface found, cannot program hardware")
        return
    #endif
    ipaddr = getoutput("ip addr | egrep vlan4094 | egrep inet")
    if (ipaddr == ""):
        lprint("No IP address found on vlan4094, cannot program hardware")
        return
    #endif
    ipaddr = ipaddr.split("inet ")[1]
    ipaddr = ipaddr.split("/")[0]

    #
    # Get a unique next-hop IP address on vlan4094's subnet. To be used as
    # a handle to get VTEP's mac address. And then that VTEP's MAC address
    # is a handle to tell VXLAN to encapsulate IP packet (with frame header)
    # to the VTEP address.
    #
    arp_entries = []
    arp_lines = getoutput("arp -i vlan4094").split("\n")
    for line in arp_lines:
        if (line.find("vlan4094") == -1): continue
        if (line.find("(incomplete)") == -1): continue
        nh = line.split(" ")[0]
        arp_entries.append(nh)
    #endfor

    nh = None
    local = ipaddr
    ipaddr = ipaddr.split(".")
    for i in range(1, 255):
        ipaddr[3] = str(i)
        addr = ".".join(ipaddr)
        if (addr in arp_entries): continue
        if (addr == local): continue
        nh = addr
        break
    #endfor
    if (nh == None):
        lprint("Address allocation failed for vlan4094, cannot program " + \
            "hardware")
        return
    #endif

    #
    # Derive MAC address from VTEP address an associate it with the next-hop 
    # address on vlan4094. This MAC address must be the MAC address on the
    # foreign VTEP configure with "ip virtual-router mac-address <mac>".
    #
    rloc_octets = rloc.split(".")
    octet1 = lisp_hex_string(rloc_octets[1]).zfill(2)
    octet2 = lisp_hex_string(rloc_octets[2]).zfill(2)
    octet3 = lisp_hex_string(rloc_octets[3]).zfill(2)
    mac = "00:00:00:{}:{}:{}".format(octet1, octet2, octet3)
    arista_mac = "0000.00{}.{}{}".format(octet1, octet2, octet3)
    arp_command = "arp -i vlan4094 -s {} {}".format(nh, mac)
    os.system(arp_command)

    #
    # Add VXLAN entry for MAC address.
    #
    vxlan_command = ("mac address-table static {} vlan 4094 " + \
        "interface vxlan 1 vtep {}").format(arista_mac, rloc)
    lisp_send_to_arista(vxlan_command, None)

    #
    # Add route now connecting: eid-prefix -> next-hop -> mac-address ->
    # VTEP address.
    #
    route_command = "ip route add {} via {}".format(eid_prefix, nh)
    os.system(route_command)

    lprint("Hardware programmed with commands:")
    route_command = route_command.replace(eid_prefix, green(eid_prefix, False))
    lprint("  " + route_command)
    lprint("  " + arp_command)
    vxlan_command = vxlan_command.replace(rloc, red(rloc, False))
    lprint("  " + vxlan_command)
    return
#enddef

#
# lisp_clear_hardware_walk
#
# Remove EID-prefix from kernel.
#
def lisp_clear_hardware_walk(mc, parms):
    prefix = mc.eid.print_prefix_no_iid()
    os.system("ip route delete {}".format(prefix))
    return([True, None])
#enddef

#
# lisp_clear_map_cache
#
# Just create a new lisp_cache data structure. But if we have to program
# hardware, traverse the map-cache.
#
def lisp_clear_map_cache():
    global lisp_map_cache, lisp_rloc_probe_list
    global lisp_crypto_keys_by_rloc_encap, lisp_crypto_keys_by_rloc_decap
    global lisp_rtr_list, lisp_gleaned_groups
    global lisp_no_map_request_rate_limit

    clear = bold("User cleared", False)
    count = lisp_map_cache.cache_count
    lprint("{} map-cache with {} entries".format(clear, count))

    if (lisp_program_hardware):
        lisp_map_cache.walk_cache(lisp_clear_hardware_walk, None)
    #endif
    lisp_map_cache = lisp_cache()

    #
    # Clear rate-limiting temporarily.
    #
    lisp_no_map_request_rate_limit = lisp_get_timestamp()

    #
    # Need to clear the RLOC-probe list or else we'll have RLOC-probes 
    # create incomplete RLOC-records.
    #
    lisp_rloc_probe_list = {}

    #
    # Also clear the encap and decap lisp-crypto arrays.
    #
    lisp_crypto_keys_by_rloc_encap = {}
    lisp_crypto_keys_by_rloc_decap = {}

    #
    # If we are an ITR, clear the RTR-list so a new set of default routes can
    # be added when the next Info-Reply comes in.
    #
    lisp_rtr_list = {}

    #
    # Clear gleaned groups data structure.
    #
    lisp_gleaned_groups = {}

    #
    # Tell external data-plane.
    #
    lisp_process_data_plane_restart(True)
    return
#enddef

#
# lisp_encap_rloc_probe
#
# Input to this function is a RLOC-probe Map-Request and the NAT-traversal
# information for an ETR that sits behind a NAT. We need to get the RLOC-probe
# through the NAT so we have to data encapsulated with a source-port of 4341
# and a destination address and port that was translated by the NAT. That
# information is in the lisp_nat_info() class.
#
def lisp_encap_rloc_probe(lisp_sockets, rloc, nat_info, packet):
    if (len(lisp_sockets) != 4): return

    #
    # Check if called by RTR, use the lisp_rtr_source_rloc equivalent.
    #
    local_addr = lisp_myrlocs[0]
    if (lisp_i_am_rtr and lisp_on_aws()):
        addr = lisp_get_interface_address("eth0")
        if (addr == None): addr = lisp_get_interface_address("ens5")
        if (addr): local_addr = addr
    #endif

    #
    # Build Map-Request IP header. Source and destination addresses same as
    # the data encapsulation outer header.
    #
    length = len(packet) + 28
    ip = struct.pack("BBHIBBHII", 0x45, 0, socket.htons(length), 0, 64,
        17, 0, socket.htonl(local_addr.address), socket.htonl(rloc.address))
    ip = lisp_ip_checksum(ip)

    sport = socket.htons(LISP_DATA_PORT)
    dport = socket.htons(LISP_CTRL_PORT) 
    udp = struct.pack("HHHH", sport, dport, socket.htons(length - 20), 0)

    #
    # Start data encapsulation logic.
    #
    packet_type = packet[0:1]
    packet = lisp_packet(ip + udp + packet)

    #
    # Setup fields we need for lisp_packet.encode().
    #
    packet.inner_dest.copy_address(rloc)
    packet.inner_dest.instance_id = 0xffffff
    packet.inner_source.copy_address(local_addr)
    packet.inner_ttl = 64
    packet.outer_dest.copy_address(rloc)
    packet.outer_source.copy_address(local_addr)
    packet.outer_version = packet.outer_dest.afi_to_version()
    packet.outer_ttl = 64
    packet.encap_port = nat_info.port if nat_info else LISP_DATA_PORT

    rloc_str = red(rloc.print_address_no_iid(), False)
    if (nat_info): 
        hostname = " {}".format(blue(nat_info.hostname, False))
    else:
        hostname = ""
    #endif
    if (lisp_is_rloc_probe_request(packet_type)):
        probe = bold("RLOC-probe request", False)
    else:
        probe = bold("RLOC-probe reply", False)
    #endif

    lprint(("Data encapsulate {} to {}{} port {} for " + \
        "NAT-traversal").format(probe, rloc_str, hostname, packet.encap_port))

    #
    # Build data encapsulation header.
    #
    if (packet.encode(None) == None): return
    packet.print_packet("Send", True)

    raw_socket = lisp_sockets[3]
    packet.send_packet(raw_socket, packet.outer_dest)
    del(packet)
    return
#enddef

#
# lisp_get_default_route_next_hops
#
# Put the interface names of each next-hop for the IPv4 default in an array
# and return to caller. The array has elements of [<device>, <nh>].
#
def lisp_get_default_route_next_hops():

    #
    # Get default route next-hop info differently for MacOS.
    #
    if (lisp_is_macos()): 
        cmd = "route -n get default"
        fields = getoutput(cmd).split("\n")
        gw = interface = None
        for f in fields:
            if (f.find("gateway: ") != -1): gw = f.split(": ")[1]
            if (f.find("interface: ") != -1): interface = f.split(": ")[1]
        #endfor
        return([[interface, gw]])
    #endif

    #
    # Get default route next-hop info for Linuxes.
    #
    cmd = "ip route | egrep 'default via'"
    default_routes = getoutput(cmd).split("\n")

    next_hops = []
    for route in default_routes:
        r = route.split()
        try:
            device = r[-1]
            nh = r[-3]
        except:
            continue
        #endtry
        next_hops.append([device, nh])
    #endfor
    return(next_hops)
#enddef

#
# lisp_get_host_route_next_hop
#
# For already installed host route, get next-hop.
#
def lisp_get_host_route_next_hop(rloc):
    cmd = "ip route | egrep '{} via'".format(rloc)
    route = getoutput(cmd).split()

    try: index = route.index("via") + 1
    except: return(None)
    
    if (index >= len(route)): return(None)
    return(route[index])
#enddef

#
# lisp_install_host_route
#
# Install/deinstall host route.
#
def lisp_install_host_route(dest, nh, install):
    install = "add" if install else "delete"
    nh_str = "none" if nh == None else nh

    lprint("{} host-route {}/32, nh {}".format(install.title(), dest, nh_str))

    if (nh == None):
        ar = "ip route {} {}/32".format(install, dest)
    else:
        ar = "ip route {} {}/32 via {}".format(install, dest, nh)
    #endif
    os.system(ar)
    return
#enddef

#
# lisp_checkpoint
#
# This function will write entries from the checkpoint array to the checkpoint
# file "lisp.checkpoint".
#
def lisp_checkpoint(checkpoint_list):
    if (lisp_checkpoint_map_cache == False): return

    f = open(lisp_checkpoint_filename, "w")
    for entry in checkpoint_list: 
        f.write(entry + "\n")
    #endfor
    f.close()
    lprint("{} {} entries to file '{}'".format(bold("Checkpoint", False), 
        len(checkpoint_list), lisp_checkpoint_filename))
    return
#enddef

#
# lisp_load_checkpoint
#
# Read entries from checkpoint file and write to map cache. Check function
# lisp_write_checkpoint_entry() for entry format description.
#
def lisp_load_checkpoint():
    if (lisp_checkpoint_map_cache == False): return
    if (os.path.exists(lisp_checkpoint_filename) == False): return

    f = open(lisp_checkpoint_filename, "r")

    count = 0
    for entry in f:
        count += 1
        e = entry.split(" rloc ")
        rlocs = [] if (e[1] in ["native-forward\n", "\n"]) else \
            e[1].split(", ")

        rloc_set = []
        for rloc in rlocs:
            rloc_entry = lisp_rloc(False)
            r = rloc.split(" ")
            rloc_entry.rloc.store_address(r[0])
            rloc_entry.priority = int(r[1])
            rloc_entry.weight = int(r[2])
            rloc_set.append(rloc_entry)
        #endfor

        mc = lisp_mapping("", "", rloc_set)
        if (mc != None): 
            mc.eid.store_prefix(e[0])
            mc.checkpoint_entry = True
            mc.map_cache_ttl = LISP_NMR_TTL * 60
            if (rloc_set == []): mc.action = LISP_NATIVE_FORWARD_ACTION
            mc.add_cache()
            continue
        #endif

        count -= 1
    #endfor

    f.close()
    lprint("{} {} map-cache entries from file '{}'".format(
        bold("Loaded", False), count, lisp_checkpoint_filename))
    return
#enddef

#
# lisp_write_checkpoint_entry
#
# Write one map-cache entry to checkpoint array list. The format of a 
# checkpoint entry is:
#
# [<iid>]<eid-prefix> rloc <rloc>, <rloc>, ...
#
# where <rloc> is formatted as:
#
# <rloc-address> <priority> <weight>
#
def lisp_write_checkpoint_entry(checkpoint_list, mc):
    if (lisp_checkpoint_map_cache == False): return

    entry = "{} rloc ".format(mc.eid.print_prefix())

    for rloc_entry in mc.rloc_set:
        if (rloc_entry.rloc.is_null()): continue
        entry += "{} {} {}, ".format(rloc_entry.rloc.print_address_no_iid(), 
            rloc_entry.priority, rloc_entry.weight)
    #endfor

    if (mc.rloc_set != []):
        entry = entry[0:-2]
    elif (mc.action == LISP_NATIVE_FORWARD_ACTION): 
        entry += "native-forward"
    #endif

    checkpoint_list.append(entry)
    return
#enddef

#
# lisp_check_dp_socket
#
# Check if lisp-ipc-data-plane socket exists.
#
def lisp_check_dp_socket():
    socket_name = lisp_ipc_dp_socket_name
    if (os.path.exists(socket_name) == False): 
        dne = bold("does not exist", False)
        lprint("Socket '{}' {}".format(socket_name, dne))
        return(False)
    #endif
    return(True)
#enddef

#
# lisp_write_to_dp_socket
#
# Check if lisp-ipc-data-plane socket exists.
#
def lisp_write_to_dp_socket(entry):
    try: 
        rec = json.dumps(entry)
        write = bold("Write IPC", False)
        lprint("{} record to named socket: '{}'".format(write, rec))
        lisp_ipc_dp_socket.sendto(rec, lisp_ipc_dp_socket_name)
    except:
        lprint("Failed to write IPC record to named socket: '{}'".format(rec))
    #endtry
    return
#enddef

#
# lisp_write_ipc_keys
#
# Security keys have changed for an RLOC. Find all map-cache entries that are
# affected. The lisp_rloc_probe_rlocs has the list of EIDs for a given RLOC
# address. Tell the external data-plane for each one.
#
def lisp_write_ipc_keys(rloc):
    addr_str = rloc.rloc.print_address_no_iid()
    port = rloc.translated_port
    if (port != 0): addr_str += ":" + str(port)
    if (addr_str not in lisp_rloc_probe_list): return

    for r, e, g in lisp_rloc_probe_list[addr_str]:
        mc = lisp_map_cache.lookup_cache(e, True)
        if (mc == None): continue
        lisp_write_ipc_map_cache(True, mc)
    #endfor
    return
#enddef

#
# lisp_write_ipc_map_cache
#
# Write a map-cache entry to named socket "lisp-ipc-data-plane".
#
def lisp_write_ipc_map_cache(add_or_delete, mc, dont_send=False):
    if (lisp_i_am_etr): return
    if (lisp_ipc_dp_socket == None): return
    if (lisp_check_dp_socket() == False): return

    #
    # Write record in JSON format.
    #
    add = "add" if add_or_delete else "delete"
    entry = { "type" : "map-cache", "opcode" : add }

    multicast = (mc.group.is_null() == False)
    if (multicast):
        entry["eid-prefix"] = mc.group.print_prefix_no_iid()
        entry["rles"] = []
    else:
        entry["eid-prefix"] = mc.eid.print_prefix_no_iid()
        entry["rlocs"] = []
    #endif
    entry["instance-id"] = str(mc.eid.instance_id)
    
    if (multicast):
        if (len(mc.rloc_set) >= 1 and mc.rloc_set[0].rle):
            for rle_node in mc.rloc_set[0].rle.rle_forwarding_list:
                addr = rle_node.address.print_address_no_iid()
                port = str(4341) if rle_node.translated_port == 0 else \
                    str(rle_node.translated_port)                       
                r = { "rle" : addr, "port" : port }
                ekey, ikey = rle_node.get_encap_keys()
                r = lisp_build_json_keys(r, ekey, ikey, "encrypt-key")
                entry["rles"].append(r)
            #endfor
        #endif
    else:
        for rloc in mc.rloc_set:
            if (rloc.rloc.is_ipv4() == False and rloc.rloc.is_ipv6() == False):
                continue
            #endif
            if (rloc.up_state() == False): continue

            port = str(4341) if rloc.translated_port == 0 else \
                str(rloc.translated_port)                       
            r = { "rloc" : rloc.rloc.print_address_no_iid(), "priority" : 
                str(rloc.priority), "weight" : str(rloc.weight), "port" :
                port  }
            ekey, ikey = rloc.get_encap_keys()
            r = lisp_build_json_keys(r, ekey, ikey, "encrypt-key")
            entry["rlocs"].append(r)
        #endfor
    #endif

    if (dont_send == False): lisp_write_to_dp_socket(entry)
    return(entry)
#enddef

#
# lisp_write_ipc_decap_key
#
# In the lisp-etr process, write an RLOC record to the ipc-data-plane socket.
#
def lisp_write_ipc_decap_key(rloc_addr, keys):
    if (lisp_i_am_itr): return
    if (lisp_ipc_dp_socket == None): return
    if (lisp_check_dp_socket() == False): return

    #
    # Get decryption key. If there is none, do not send message.
    #
    if (keys == None or len(keys) == 0 or keys[1] == None): return

    ekey = keys[1].encrypt_key
    ikey = keys[1].icv_key

    #
    # Write record in JSON format. Store encryption key.
    #
    rp = rloc_addr.split(":")
    if (len(rp) == 1):
        entry = { "type" : "decap-keys", "rloc" : rp[0] }
    else:
        entry = { "type" : "decap-keys", "rloc" : rp[0], "port" : rp[1] }
    #endif
    entry = lisp_build_json_keys(entry, ekey, ikey, "decrypt-key")

    lisp_write_to_dp_socket(entry)
    return
#enddef

#
# lisp_build_json_keys
#
# Build the following for both the ITR encryption side and the ETR decryption
# side.
#
def lisp_build_json_keys(entry, ekey, ikey, key_type):
    if (ekey == None): return(entry)

    entry["keys"] = []
    key = { "key-id" : "1", key_type : ekey, "icv-key" : ikey }
    entry["keys"].append(key)
    return(entry)
#enddef

#
# lisp_write_ipc_database_mappings
#
# In the lisp-etr process, write an RLOC record to the ipc-data-plane socket.
#
def lisp_write_ipc_database_mappings(ephem_port):
    if (lisp_i_am_etr == False): return
    if (lisp_ipc_dp_socket == None): return
    if (lisp_check_dp_socket() == False): return

    #
    # Write record in JSON format. Store encryption key.
    #
    entry = { "type" : "database-mappings", "database-mappings" : [] }

    #
    # Write only IPv4 and IPv6 EIDs.
    #
    for db in lisp_db_list:
        if (db.eid.is_ipv4() == False and db.eid.is_ipv6() == False): continue
        record = { "instance-id" : str(db.eid.instance_id), 
            "eid-prefix" : db.eid.print_prefix_no_iid() }
        entry["database-mappings"].append(record)
    #endfor
    lisp_write_to_dp_socket(entry)

    #
    # Write ephemeral NAT port an external data-plane needs to receive
    # encapsulated packets from the RTR.
    #
    entry = { "type" : "etr-nat-port", "port" : ephem_port }
    lisp_write_to_dp_socket(entry)
    return
#enddef

#
# lisp_write_ipc_interfaces
#
# In the lisp-etr process, write an RLOC record to the ipc-data-plane socket.
#
def lisp_write_ipc_interfaces():
    if (lisp_i_am_etr): return
    if (lisp_ipc_dp_socket == None): return
    if (lisp_check_dp_socket() == False): return

    #
    # Write record in JSON format. Store encryption key.
    #
    entry = { "type" : "interfaces", "interfaces" : [] }

    for interface in list(lisp_myinterfaces.values()):
        if (interface.instance_id == None): continue
        record = { "interface" : interface.device, 
            "instance-id" : str(interface.instance_id) }
        entry["interfaces"].append(record)
    #endfor

    lisp_write_to_dp_socket(entry)
    return
#enddef

#
# lisp_parse_auth_key
#
# Look for values for "authentication-key" in the various forms of:
#
# <password>
# [<key-id>]<password>
# [<key-id>]<password> [<key-id>]<password> [<key-id>]<password>
#
# Return a auth_key{} where the keys from the dictionary array are type
# integers and the values are type string.
#
def lisp_parse_auth_key(value):
    values = value.split("[")
    auth_key = {}
    if (len(values) == 1):
        auth_key[0] = value
        return(auth_key)
    #endif

    for v in values:
        if (v == ""): continue
        index = v.find("]")
        key_id = v[0:index]
        try: key_id = int(key_id)
        except: return

        auth_key[key_id] = v[index+1::]
    #endfor
    return(auth_key)
#enddef

#
# lisp_reassemble
#
# Reassemble an IPv4 datagram. The result is a LISP encapsulated packet.
#
# An entry in the queue is a multi-tuple of:
#
#    <frag-offset>, <frag-length>, <packet-with-header>, <last-frag-is-true>
#
# When it is not a LISP/VXLAN encapsualted packet, the multi-tuple will be
# for the first fragment:
#
#    <frag-offset>, <frag-length>, None, <last-frag-is-true>
#
def lisp_reassemble(packet):
    fo = socket.ntohs(struct.unpack("H", packet[6:8])[0])

    #
    # Not a fragment, return packet and process.
    #
    if (fo == 0 or fo == 0x4000): return(packet)

    #
    # Get key fields from fragment.
    #
    ident = socket.ntohs(struct.unpack("H", packet[4:6])[0])
    fl = socket.ntohs(struct.unpack("H", packet[2:4])[0])

    last_frag = (fo & 0x2000 == 0 and (fo & 0x1fff) != 0)
    entry = [(fo & 0x1fff) * 8, fl - 20, packet, last_frag]

    #
    # If first fragment, check to see if LISP packet. Do not reassemble if
    # source or destination port is not 4341, 8472 or 4789. But add this to 
    # the queue so when other fragments come in, we know to not queue them. 
    # If other fragments came in before the first fragment, remove them from 
    # the queue.
    #
    if (fo == 0x2000):
        sport, dport = struct.unpack("HH", packet[20:24])
        sport = socket.ntohs(sport)
        dport = socket.ntohs(dport)
        if (dport not in [4341, 8472, 4789] and sport != 4341): 
            lisp_reassembly_queue[ident] = []
            entry[2] = None
        #endif
    #endif

    #
    # Initialized list if first fragment. Indexed by IPv4 Ident.
    #
    if (ident not in lisp_reassembly_queue):
        lisp_reassembly_queue[ident] = []
    #endif

    #
    # Get fragment queue based on IPv4 Ident.
    #
    queue = lisp_reassembly_queue[ident]

    #
    # Do not queue fragment if first fragment arrived and we determined its
    # not a LISP encapsulated packet.
    #
    if (len(queue) == 1 and queue[0][2] == None):
        dprint("Drop non-LISP encapsulated fragment 0x{}".format( \
            lisp_hex_string(ident).zfill(4)))
        return(None)
    #endif

    #
    # Insert in sorted order.
    #
    queue.append(entry)
    queue = sorted(queue)

    #
    # Print addresses.
    #
    addr = lisp_address(LISP_AFI_IPV4, "", 32, 0)
    addr.address = socket.ntohl(struct.unpack("I", packet[12:16])[0])
    src = addr.print_address_no_iid()
    addr.address = socket.ntohl(struct.unpack("I", packet[16:20])[0])
    dst = addr.print_address_no_iid()
    addr = red("{} -> {}".format(src, dst), False)

    dprint("{}{} fragment, RLOCs: {}, packet 0x{}, frag-offset: 0x{}".format( \
        bold("Received", False), " non-LISP encapsulated" if \
        entry[2] == None else "", addr, lisp_hex_string(ident).zfill(4), 
        lisp_hex_string(fo).zfill(4)))

    #
    # Check if all fragments arrived. First check if first and last fragments
    # are in queue.
    #
    if (queue[0][0] != 0 or queue[-1][3] == False): return(None)
    last_entry = queue[0]
    for frag in queue[1::]:
        fo = frag[0]
        last_fo, last_fl = last_entry[0], last_entry[1]
        if (last_fo + last_fl != fo): return(None)
        last_entry = frag
    #endfor
    lisp_reassembly_queue.pop(ident)

    #
    # If we did not return, we have all fragments. Now append them. Keep the
    # IP header in the first fragment but remove in each other fragment.
    #
    packet = queue[0][2]
    for frag in queue[1::]: packet += frag[2][20::]

    dprint("{} fragments arrived for packet 0x{}, length {}".format( \
        bold("All", False), lisp_hex_string(ident).zfill(4), len(packet)))

    #
    # Fix length and frag-offset field before returning and fixup checksum.
    #
    length = socket.htons(len(packet))
    header = packet[0:2] + struct.pack("H", length) + packet[4:6] + \
        struct.pack("H", 0) + packet[8:10] + struct.pack("H", 0) + \
        packet[12:20]
    header = lisp_ip_checksum(header)
    return(header + packet[20::])
#enddef

#
# lisp_get_crypto_decap_lookup_key
#
# Return None if we cannot find <addr>:<<port> or <addr>:0 in lisp_crypto_
# keys_by_rloc_decap{}.
#
def lisp_get_crypto_decap_lookup_key(addr, port):
    addr_str = addr.print_address_no_iid() + ":" + str(port)
    if (addr_str in lisp_crypto_keys_by_rloc_decap): return(addr_str)
        
    addr_str = addr.print_address_no_iid()
    if (addr_str in lisp_crypto_keys_by_rloc_decap): return(addr_str)

    #
    # We are at non-NAT based xTR. We need to get the keys from an RTR
    # or another non-NAT based xTR. Move addr+port to addr.
    #
    for ap in lisp_crypto_keys_by_rloc_decap:
        a = ap.split(":")
        if (len(a) == 1): continue
        a = a[0] if len(a) == 2 else ":".join(a[0:-1])
        if (a == addr_str):
            keys = lisp_crypto_keys_by_rloc_decap[ap]
            lisp_crypto_keys_by_rloc_decap[addr_str] = keys
            return(addr_str)
        #endif
    #endfor
    return(None)
#enddef

#
# lisp_build_crypto_decap_lookup_key
#
# Decide to return <addr>:<port> or <addr> depending if the RLOC is behind
# a NAT. This is used on the RTR. Check the lisp probing cache. If we find
# an RLOC with a port number stored, then it is behind a NAT. Otherwise,
# the supplied port is not relevant and we want to create a "port-less" decap
# entry for an xTR that is in public address space.
#
def lisp_build_crypto_decap_lookup_key(addr, port):
    addr = addr.print_address_no_iid()
    addr_and_port = addr + ":" + str(port)
  
    if (lisp_i_am_rtr):
        if (addr in lisp_rloc_probe_list): return(addr)
    
        #
        # Have to check NAT cache to see if RLOC is translated. If not, this
        # is an xTR in public space. We'll have to change this in the future
        # so we don't do a full table traversal. But this only happensu
        #
        for nat_info in list(lisp_nat_state_info.values()):
            for nat in nat_info:
                if (addr == nat.address): return(addr_and_port)
            #endfor
        #endif
        return(addr)
    #endif
    return(addr_and_port)
#enddef

#
# lisp_is_rloc_probe_request
#
# Pass LISP first byte to test for 0x12, a Map-Request RLOC-probe.
#
def lisp_is_rloc_probe_request(lisp_type):
    lisp_type = struct.unpack("B", lisp_type)[0]
    return(lisp_type == 0x12)
#enddef

#
# lisp_is_rloc_probe_reply
#
# Pass LISP first byte to test for 0x28, a Map-Reply RLOC-probe.
#
def lisp_is_rloc_probe_reply(lisp_type):
    lisp_type = struct.unpack("B", lisp_type)[0]
    return(lisp_type == 0x28)
#enddef

#
# lisp_is_rloc_probe
#
# If this is a RLOC-probe received by the data-plane (from a pcap filter),
# then return source address, source port, ttl, and position packet to the
# beginning of the LISP header. The packet pointer entering this function is
# the beginning of an IPv4 header.
# 
# If rr (request-or-reply) is:
#
#  0: Check for Map-Request RLOC-probe  (ETR case)
#  1: Check for Map-Reply RLOC-probe    (ITR case)
# -1: Check for either                  (RTR case)
#
# Return packet pointer untouched if not an RLOC-probe. If it is an RLOC-probe
# request or reply from ourselves, return packet pointer None and source None.
#
def lisp_is_rloc_probe(packet, device, rr):
    udp = (struct.unpack("B", packet[9:10])[0] == 17)
    if (udp == False): return([packet, None, None, None])

    sport = struct.unpack("H", packet[20:22])[0]
    dport = struct.unpack("H", packet[22:24])[0]
    is_lisp = (socket.htons(LISP_CTRL_PORT) in [sport, dport])
    if (is_lisp == False): return([packet, None, None, None])

    if (rr == 0):
        probe = lisp_is_rloc_probe_request(packet[28:29])
        if (probe == False): return([packet, None, None, None])
    elif (rr == 1):
        probe = lisp_is_rloc_probe_reply(packet[28:29])
        if (probe == False): return([packet, None, None, None])
    elif (rr == -1):
        probe = lisp_is_rloc_probe_request(packet[28:29])
        if (probe == False): 
            probe = lisp_is_rloc_probe_reply(packet[28:29])
            if (probe == False): return([packet, None, None, None])
        #endif
    #endif

    #
    # Get source address, source port, and TTL. Decrement TTL.
    #
    source = lisp_address(LISP_AFI_IPV4, "", 32, 0)
    source.address = socket.ntohl(struct.unpack("I", packet[12:16])[0])

    #
    # If this is a RLOC-probe from ourselves, drop.
    #
    if (source.is_local()): return([None, None, None, None])

    #
    # Accept, and return source, port, and ttl to caller.
    #
    source = source.print_address_no_iid()
    port = socket.ntohs(struct.unpack("H", packet[20:22])[0])
    ttl = struct.unpack("B", packet[8:9])[0] - 1
    packet = packet[28::]

    r = bold("Receive(pcap-{})".format(device), False)
    f = bold("from " + source, False)
    p = lisp_format_packet(packet)
    lprint("{} {} bytes {} {}, packet: {}".format(r, len(packet), f, port, p))

    return([packet, source, port, ttl])
#enddef

#
# lisp_ipc_write_xtr_parameters
#
# When an external data-plane is running, write the following parameters
# to it:
#
# ipc = { "type" : "xtr-parameters", "control-plane-logging" : False,
#         "data-plane-logging" : False, "rtr" : False }
#
def lisp_ipc_write_xtr_parameters(cp, dp):
    if (lisp_ipc_dp_socket == None): return

    ipc = { "type" : "xtr-parameters", "control-plane-logging" : cp,
        "data-plane-logging" : dp, "rtr" : lisp_i_am_rtr }

    lisp_write_to_dp_socket(ipc)
    return
#enddef

#
# lisp_external_data_plane
#
# Return True if an external data-plane is running. That means that "ipc-data-
# plane = yes" is configured or the lisp-xtr go binary is running.
#
def lisp_external_data_plane():
    cmd = 'egrep "ipc-data-plane = yes" ./lisp.config'
    if (getoutput(cmd) != ""): return(True)
    
    if (os.getenv("LISP_RUN_LISP_XTR") != None): return(True)
    return(False)
#enddef

#
# lisp_process_data_plane_restart
#
# The external data-plane has restarted. We will touch the lisp.config file so
# all configuration information is sent and then traverse the map-cache
# sending each entry to the data-plane so it can regain its state.
#
# This function will also clear the external data-plane map-cache when a user
# clears the map-cache in the lisp-itr or lisp-rtr process.
#
# { "type" : "restart" }
#
def lisp_process_data_plane_restart(do_clear=False):
    os.system("touch ./lisp.config")

    jdata = { "type" : "entire-map-cache", "entries" : [] }

    if (do_clear == False):
        entries = jdata["entries"]
        lisp_map_cache.walk_cache(lisp_ipc_walk_map_cache, entries)
    #endif

    lisp_write_to_dp_socket(jdata)
    return
#enddef

#
# lisp_process_data_plane_stats
#
# { "type" : "statistics", "entries" :
#   [ { "instance-id" : "<iid>", "eid-prefix" : "<eid>", "rlocs" : [
#     { "rloc" : "<rloc-1>", "packet-count" : <count>, "byte-count" : <bcount>,
#       "seconds-last-packet" : "<timestamp>" },  ...
#     { "rloc" : "<rloc-n>", "packet-count" : <count>, "byte-count" : <bcount>,
#        "seconds-last-packet" : <system-uptime> } ], ... }
#    ]
# }
#
def lisp_process_data_plane_stats(msg, lisp_sockets, lisp_port):
    if ("entries" not in msg):
        lprint("No 'entries' in stats IPC message")
        return
    #endif
    if (type(msg["entries"]) != list):
        lprint("'entries' in stats IPC message must be an array")
        return
    #endif

    for msg in msg["entries"]:
        if ("eid-prefix" not in msg):
            lprint("No 'eid-prefix' in stats IPC message")
            continue
        #endif
        eid_str = msg["eid-prefix"]

        if ("instance-id" not in msg):
            lprint("No 'instance-id' in stats IPC message")
            continue
        #endif
        iid = int(msg["instance-id"])

        #
        # Lookup EID-prefix in map-cache.
        #
        eid = lisp_address(LISP_AFI_NONE, "", 0, iid)
        eid.store_prefix(eid_str)
        mc = lisp_map_cache_lookup(None, eid)
        if (mc == None): 
            lprint("Map-cache entry for {} not found for stats update". \
                format(eid_str))
            continue
        #endif

        if ("rlocs" not in msg):
            lprint("No 'rlocs' in stats IPC message for {}".format( \
                eid_str))
            continue
        #endif
        if (type(msg["rlocs"]) != list):
            lprint("'rlocs' in stats IPC message must be an array")
            continue
        #endif
        ipc_rlocs = msg["rlocs"]

        #
        # Loop through RLOCs in IPC message.
        #
        for ipc_rloc in ipc_rlocs:
            if ("rloc" not in ipc_rloc): continue

            rloc_str = ipc_rloc["rloc"]
            if (rloc_str == "no-address"): continue

            rloc = lisp_address(LISP_AFI_NONE, "", 0, 0)
            rloc.store_address(rloc_str)

            rloc_entry = mc.get_rloc(rloc)
            if (rloc_entry == None): continue

            #
            # Update stats.
            #
            pc = 0 if ("packet-count" not in ipc_rloc) else \
                ipc_rloc["packet-count"]
            bc = 0 if ("byte-count" not in ipc_rloc) else \
                ipc_rloc["byte-count"]
            ts = 0 if ("seconds-last-packet" not in ipc_rloc) else \
                ipc_rloc["seconds-last-packet"]
        
            rloc_entry.stats.packet_count += pc
            rloc_entry.stats.byte_count += bc
            rloc_entry.stats.last_increment = lisp_get_timestamp() - ts
        
            lprint("Update stats {}/{}/{}s for {} RLOC {}".format(pc, bc,
                ts, eid_str, rloc_str))
        #endfor

        #
        # Check if this map-cache entry needs refreshing.
        #
        if (mc.group.is_null() and mc.has_ttl_elapsed()):
            eid_str = green(mc.print_eid_tuple(), False)
            lprint("Refresh map-cache entry {}".format(eid_str))
            lisp_send_map_request(lisp_sockets, lisp_port, None, mc.eid, None)
        #endif
    #endfor
    return
#enddef

#
# lisp_process_data_plane_decap_stats
#
# { "type" : "decap-statistics",
#   "no-decrypt-key" : { "packet-count" : <count>, "byte-count" : <bcount>,
#        "seconds-last-packet" : <seconds> },
#   "outer-header-error" : { "packet-count" : <count>, "byte-count" : <bcount>,
#        "seconds-last-packet" : <seconds> },
#   "bad-inner-version" : { "packet-count" : <count>, "byte-count" : <bcount>,
#        "seconds-last-packet" : <seconds> },
#   "good-packets" : { "packet-count" : <count>, "byte-count" : <bcount>,
#        "seconds-last-packet" : <seconds> },
#   "ICV-error" : { "packet-count" : <count>, "byte-count" : <bcount>,
#        "seconds-last-packet" : <seconds> },
#   "checksum-error" : { "packet-count" : <count>, "byte-count" : <bcount>,
#        "seconds-last-packet" : <seconds> }
# }
#
# If are an RTR, we can process the stats directly. If are an ITR we need
# to send an IPC message the the lisp-etr process.
#
# Variable "msg" is a string and not a byte string. Caller converts.
#
def lisp_process_data_plane_decap_stats(msg, lisp_ipc_socket):

    #
    # Send IPC message to lisp-etr process. Variable 'msg' is a dict array.
    # Needs to be passed in IPC message as a string.
    #
    if (lisp_i_am_itr):
        lprint("Send decap-stats IPC message to lisp-etr process")
        ipc = "stats%{}".format(json.dumps(msg))
        ipc = lisp_command_ipc(ipc, "lisp-itr")
        lisp_ipc(ipc, lisp_ipc_socket, "lisp-etr")
        return
    #endif

    #
    # Process stats counters in lisp-etr and lisp-rtr processes. Variable 'msg'
    # is a dictionary array when the ITR/RTR is processing msg. When an ETR
    # is processing it, it recevied a json string from the ITR so it needs
    # to convert to a dictionary array.
    #
    ipc = bold("IPC", False)
    lprint("Process decap-stats {} message: '{}'".format(ipc, msg))

    if (lisp_i_am_etr): msg = json.loads(msg)
    
    key_names = ["good-packets", "ICV-error", "checksum-error",
        "lisp-header-error", "no-decrypt-key", "bad-inner-version",
        "outer-header-error"]

    for key_name in key_names:
        pc = 0 if (key_name not in msg) else msg[key_name]["packet-count"]
        lisp_decap_stats[key_name].packet_count += pc

        bc = 0 if (key_name not in msg) else msg[key_name]["byte-count"]
        lisp_decap_stats[key_name].byte_count += bc

        ts = 0 if (key_name not in msg) else \
            msg[key_name]["seconds-last-packet"]
        lisp_decap_stats[key_name].last_increment = lisp_get_timestamp() - ts
    #endfor
    return
#enddef

#
# lisp_process_punt
#
# Another data-plane is punting a packet to us so we can discover a source
# EID, send a map-request, or store statistics data. The format of the JSON
# messages are for types: "discovery", "restart", "statistics", and "decap-
# statistics". This function calls functions for the stats and restart types
# but this function processes logic for:
#
# { "type" : "discovery", "source-eid" : <eid-source-address>, 
#   "dest-eid" : <eid-dest-address>, "interface" : "<device-name>",
#   "instance-id" : <iid> }
#
# And:
#
def lisp_process_punt(punt_socket, lisp_send_sockets, lisp_ephem_port):
    message, source = punt_socket.recvfrom(4000)

    msg = json.loads(message)
    if (type(msg) != dict):
        lprint("Invalid punt message from {}, not in JSON format". \
            format(source))
        return
    #endif
    punt = bold("Punt", False)
    lprint("{} message from '{}': '{}'".format(punt, source, msg))

    if ("type" not in msg):
        lprint("Punt IPC message has no 'type' key")
        return
    #endif

    #
    # Process statistics message.
    #
    if (msg["type"] == "statistics"):
        lisp_process_data_plane_stats(msg, lisp_send_sockets, lisp_ephem_port)
        return
    #endif
    if (msg["type"] == "decap-statistics"):
        lisp_process_data_plane_decap_stats(msg, punt_socket)
        return
    #endif

    #
    # Process statistics message.
    #
    if (msg["type"] == "restart"):
        lisp_process_data_plane_restart()
        return
    #endif

    #
    # Process possible punt packet discovery message.
    #
    if (msg["type"] != "discovery"):
        lprint("Punt IPC message has wrong format")
        return
    #endif
    if ("interface" not in msg):
        lprint("Invalid punt message from {}, required keys missing". \
            format(source))
        return
    #endif

    #
    # Drop control-messages designated as instance-ID 0xffffff (or -1 in JSON).
    #
    device = msg["interface"]
    if (device == ""):
        iid = int(msg["instance-id"])
        if (iid == -1): return
    else:
        iid = lisp_get_interface_instance_id(device, None)
    #endif

    #
    # Validate EID format.
    #
    seid = None
    if ("source-eid" in msg):
        source_eid = msg["source-eid"]
        seid = lisp_address(LISP_AFI_NONE, source_eid, 0, iid)
        if (seid.is_null()):
            lprint("Invalid source-EID format '{}'".format(source_eid))
            return
        #endif
    #endif
    deid = None
    if ("dest-eid" in msg):
        dest_eid = msg["dest-eid"]
        deid = lisp_address(LISP_AFI_NONE, dest_eid, 0, iid)
        if (deid.is_null()):
            lprint("Invalid dest-EID format '{}'".format(dest_eid))
            return
        #endif
    #endif

    #
    # Do source-EID discovery.
    #
    # Make sure we have a configured database-mapping entry for this EID.
    #
    if (seid):
        e = green(seid.print_address(), False)
        db = lisp_db_for_lookups.lookup_cache(seid, False)
        if (db != None):

            #
            # Check accept policy and if accepted, discover EID by putting 
            # in discovery cache. ETR will register it.
            #
            if (db.dynamic_eid_configured()):
                interface = lisp_allow_dynamic_eid(device, seid)
                if (interface != None and lisp_i_am_itr):
                    lisp_itr_discover_eid(db, seid, device, interface)
                else:
                    lprint(("Disallow dynamic source-EID {} " + \
                        "on interface {}").format(e, device))
                #endif
            #endif
        else:
            lprint("Punt from non-EID source {}".format(e))
        #endif
    #endif

    #
    # Do Map-Request processing on destination.
    #
    if (deid):
        mc = lisp_map_cache_lookup(seid, deid)
        if (mc == None or lisp_mr_or_pubsub(mc.action)):

            #
            # Check if we should rate-limit Map-Request and if not send
            # Map-Request.
            #
            if (lisp_rate_limit_map_request(deid)): return

            pubsub = (mc and mc.action == LISP_SEND_PUBSUB_ACTION)
            lisp_send_map_request(lisp_send_sockets, lisp_ephem_port, 
                seid, deid, None, pubsub)
        else:
            e = green(deid.print_address(), False)
            lprint("Map-cache entry for {} already exists".format(e))
        #endif
    #endif
    return
#enddef

#
# lisp_ipc_map_cache_entry
#
# Callback from class lisp_cache.walk_cache().
#
def lisp_ipc_map_cache_entry(mc, jdata):
    entry = lisp_write_ipc_map_cache(True, mc, dont_send=True)
    jdata.append(entry)
    return([True, jdata])
#enddef

#
# lisp_ipc_walk_map_cache
#
# Walk the entries in the lisp_map_cache(). And then subsequently walk the
# entries in lisp_mapping.source_cache().
#
def lisp_ipc_walk_map_cache(mc, jdata):
    
    #
    # There is only destination state in this map-cache entry.
    #
    if (mc.group.is_null()): return(lisp_ipc_map_cache_entry(mc, jdata))

    if (mc.source_cache == None): return([True, jdata])

    #
    # There is (source, group) state so walk all sources for this group
    # entry.
    #
    jdata = mc.source_cache.walk_cache(lisp_ipc_map_cache_entry, jdata)
    return([True, jdata])
#enddef

#
# lisp_itr_discover_eid
#
# Put dynamic-EID in db.dynamic_eids{} array.
#
def lisp_itr_discover_eid(db, eid, input_interface, routed_interface,
    lisp_ipc_listen_socket):
    eid_str = eid.print_address()
    if (eid_str in db.dynamic_eids):
        db.dynamic_eids[eid_str].last_packet = lisp_get_timestamp()
        return
    #endif

    #
    # Add to list.
    #
    dyn_eid = lisp_dynamic_eid()
    dyn_eid.dynamic_eid.copy_address(eid)
    dyn_eid.interface = routed_interface
    dyn_eid.last_packet = lisp_get_timestamp()
    dyn_eid.get_timeout(routed_interface)
    db.dynamic_eids[eid_str] = dyn_eid

    routed = ""
    if (input_interface != routed_interface):
        routed = ", routed-interface " + routed_interface
    #endif

    eid_string = green(eid_str, False) + bold(" discovered", False)
    lprint("Dynamic-EID {} on interface {}{}, timeout {}".format( \
        eid_string,input_interface, routed, dyn_eid.timeout))

    #
    # Tell ETR process so it can register dynamic-EID.
    #
    ipc = "learn%{}%{}".format(eid_str, routed_interface)
    ipc = lisp_command_ipc(ipc, "lisp-itr")
    lisp_ipc(ipc, lisp_ipc_listen_socket, "lisp-etr")
    return
#enddef

#
# lisp_itr_nat_probe
#
# Tell the lisp-etr process to send Info-Requests to this ETR RLOC. It
# knows which socket to send from so the encapsulated data back comes
# to the ephemeral port from well-known port 4341.
#
def lisp_itr_nat_probe(rloc, rloc_name, lisp_ipc_listen_socket):
    rloc_str = rloc.print_address_no_iid()

    #
    # Tell ETR process so it can register dynamic-EID.
    #
    ipc = "nat%{}%{}".format(rloc_str, rloc_name)
    ipc = lisp_command_ipc(ipc, "lisp-itr")
    lisp_ipc(ipc, lisp_ipc_listen_socket, "lisp-etr")
    return
#enddef

#
# lisp_retry_decap_keys
#
# A decap-key was copied from x.x.x.x:p to x.x.x.x, but it was the wrong one.
# Copy x.x.x.x.q to x.x.x.x. This is an expensive function. But it is hardly
# used. And once it is used for a particular addr_str, it shouldn't be used
# again.
#
# This function is only used when an ICV error occurs when x.x.x.x is the
# crypto-key used.
#
def lisp_retry_decap_keys(addr_str, packet, iv, packet_icv):
    if (lisp_search_decap_keys == False): return

    #
    # Only use this function when the key matched was not port based.
    #
    if (addr_str.find(":") != -1): return

    parent = lisp_crypto_keys_by_rloc_decap[addr_str]

    for key in lisp_crypto_keys_by_rloc_decap:

        #
        # Find entry that has same source RLOC.
        #
        if (key.find(addr_str) == -1): continue

        #
        # Skip over parent entry.
        #
        if (key == addr_str): continue

        #
        # If crypto-keys the same, go to find next one.
        #
        entry = lisp_crypto_keys_by_rloc_decap[key]
        if (entry == parent): continue

        #
        # Try ICV check. If works, then go to this key.
        #
        crypto_key = entry[1]
        if (packet_icv != crypto_key.do_icv(packet, iv)):
            lprint("Test ICV with key {} failed".format(red(key, False)))
            continue
         #endif

        lprint("Changing decap crypto key to {}".format(red(key, False)))
        lisp_crypto_keys_by_rloc_decap[addr_str] = entry
    #endif
    return
#enddef

#
# lisp_decent_pull_xtr_configured
#
# Return True if configured LISP-Decent modulus is not 0. Meaning we are using
# the LISP-Decent pull-based mapping system.
#
def lisp_decent_pull_xtr_configured():
    return(lisp_decent_modulus != 0 and lisp_decent_dns_suffix != None)
#enddef

#
# lisp_is_decent_dns_suffix
#
# Return True if supplied DNS name ends with a configured LISP-Decent DNS
# suffix.
#
def lisp_is_decent_dns_suffix(dns_name):
    if (lisp_decent_dns_suffix == None): return(False)
    name = dns_name.split(".")
    name = ".".join(name[1::])
    return(name == lisp_decent_dns_suffix)
#enddef

#
# lisp_get_decent_index
#
# Hash the EID-prefix and mod the configured LISP-Decent modulus value. We
# do a sha256() over a string representation of "[<iid>]<eid>", take the
# high-order 6 bytes from the hash and do the modulus on that value.
#
# The seed/password for the sha256 hash is string "".
#
def lisp_get_decent_index(eid):
    eid_str = eid.print_prefix()
    hash_value = hmac.new(b"lisp-decent", eid_str, hashlib.sha256).hexdigest()

    #
    # Get hash-length to modulate from LISP_DECENT_HASH_WIDTH in bytes.
    #
    hash_width = os.getenv("LISP_DECENT_HASH_WIDTH")
    if (hash_width in ["", None]):
        hash_width = 12
    else:
        hash_width = int(hash_width)
        if (hash_width > 32):
            hash_width = 12
        else:
            hash_width *= 2
        #endif
    #endif

    mod_value = hash_value[0:hash_width]
    index = int(mod_value, 16) % lisp_decent_modulus

    lprint("LISP-Decent modulus {}, hash-width {}, mod-value {}, index {}". \
        format(lisp_decent_modulus, old_div(hash_width, 2) , mod_value, index))

    return(index)
#enddef

#
# lisp_get_decent_dns_name
#
# Based on EID, get index and prepend to LISP-Decent DNS name suffix.
#
def lisp_get_decent_dns_name(eid):
    index = lisp_get_decent_index(eid)
    return(str(index) + "." + lisp_decent_dns_suffix)
#enddef

#
# lisp_get_decent_dns_name_from_str
#
# Supplied source and group are addresses passed as strings. Build in internal
# lisp_address() to pass into lisp_get_decent_index().
#
def lisp_get_decent_dns_name_from_str(iid, eid_str):
    eid = lisp_address(LISP_AFI_NONE, eid_str, 0, iid)
    index = lisp_get_decent_index(eid)
    return(str(index) + "." + lisp_decent_dns_suffix)
#enddef

#
# lisp_trace_append
#
# Append JSON data to trace packet. If this is the ETR, the EIDs will be
# swapped to return packet to originator.
#
# Returning False means the caller should return (and not forward the packet).
#
def lisp_trace_append(packet, reason=None, ed="encap", lisp_socket=None,
    rloc_entry=None):

    offset = 28 if packet.inner_version == 4 else 48
    trace_pkt = packet.packet[offset::]
    trace = lisp_trace()
    if (trace.decode(trace_pkt) == False):
        lprint("Could not decode JSON portion of a LISP-Trace packet")
        return(False)
    #endif

    next_rloc = "?" if packet.outer_dest.is_null() else \
        packet.outer_dest.print_address_no_iid()

    #
    # Display port if in this call is a encapsulating RTR using a translated
    # RLOC.
    #
    if (next_rloc != "?" and packet.encap_port != LISP_DATA_PORT):
        if (ed == "encap"): next_rloc += ":{}".format(packet.encap_port)
    #endif        

    #
    # Add node entry data for the encapsulation or decapsulation.
    #
    entry = {}
    entry["n"] = "ITR" if lisp_i_am_itr else "ETR" if lisp_i_am_etr else \
        "RTR" if lisp_i_am_rtr else "?"
    srloc = packet.outer_source
    if (srloc.is_null()): srloc = lisp_myrlocs[0]
    entry["sr"] = srloc.print_address_no_iid()

    #
    # In the source RLOC include the ephemeral port number of the ltr client
    # so RTRs can return errors to the client behind a NAT.
    #
    if (entry["n"] == "ITR" and packet.inner_sport != LISP_TRACE_PORT):
        entry["sr"] += ":{}".format(packet.inner_sport)
    #endif
        
    entry["hn"] = lisp_hostname
    key = ed[0] + "ts"
    entry[key] = lisp_get_timestamp()

    #
    # If this is a ETR decap entry and the drloc is "?", the packet came in on
    # lisp_etr_nat_data_plane() where the kernel strips the outer header. Get
    # the local/private RLOC from our database-mapping.
    #
    if (next_rloc == "?" and entry["n"] == "ETR"):
        db = lisp_db_for_lookups.lookup_cache(packet.inner_dest, False)
        if (db != None and len(db.rloc_set) >= 1):
            next_rloc = db.rloc_set[0].rloc.print_address_no_iid()
        #endif
    #endif
    entry["dr"] = next_rloc

    #
    # If there is a reason there is no dest RLOC, include it.
    #
    if (next_rloc == "?" and reason != None):
        entry["dr"] += " ({})".format(reason)
    #endif

    #
    # Add recent-rtts, recent-hops, and recent-latencies.
    #
    if (rloc_entry != None):
        entry["rtts"] = rloc_entry.recent_rloc_probe_rtts
        entry["hops"] = rloc_entry.recent_rloc_probe_hops
        entry["lats"] = rloc_entry.recent_rloc_probe_latencies
    #endif

    #
    # Build seid->deid record if it does not exist. Then append node entry
    # to record below, in the search loop.
    #
    seid = packet.inner_source.print_address()
    deid = packet.inner_dest.print_address()
    if (trace.packet_json == []):
        rec = {}
        rec["se"] = seid
        rec["de"] = deid
        rec["paths"] = []
        trace.packet_json.append(rec)
    #endif

    #
    # Search for record. If we appending the first ITR node entry, get its
    # RLOC address in case we have to return-to-sender.
    #
    for rec in trace.packet_json:
        if (rec["de"] != deid): continue
        rec["paths"].append(entry)
        break
    #endfor

    #
    # If we are destination-EID, add a new record deid->seid if we have not
    # completed a round-trip. The ETR will deliver this packet from its own
    # EID which means the co-located ITR will pcap the packet and add its
    # encap node entry.
    #
    swap = False
    if (len(trace.packet_json) == 1 and entry["n"] == "ETR" and
        trace.myeid(packet.inner_dest)):
        rec = {}
        rec["se"] = deid
        rec["de"] = seid
        rec["paths"] = []
        trace.packet_json.append(rec)
        swap = True
    #endif

    #
    # Print the JSON packet after we appended data to it. Put the new JSON in
    # packet. Fix up lengths and checksums from inner headers.
    #
    trace.print_trace()
    trace_pkt = trace.encode()

    #
    # If next_rloc is not known, we need to return packet to sender.
    #
    # Otherwise we are forwarding a packet that is about to encapsulated or we
    # are forwarding a packet that was just decapsulated with the addresses
    # swapped so we can turn it around.
    #
    sender_rloc = trace.packet_json[0]["paths"][0]["sr"]
    if (next_rloc == "?"):
        lprint("LISP-Trace return to sender RLOC {}".format(sender_rloc))
        trace.return_to_sender(lisp_socket, sender_rloc, trace_pkt)
        return(False)
    #endif

    #
    # Compute length of trace packet. This includes the UDP header, Trace
    # header, and JSON payload.
    #
    udplen = trace.packet_length()
    
    #
    # Fix up UDP length and recompute UDP checksum if IPv6 packet, zero
    # otherwise. Only do checksum when the Trace went round-trip and this is
    # the local ETR delivery EID-based Trace packet to the client ltr.
    #
    headers = packet.packet[0:offset]
    p = struct.pack("HH", socket.htons(udplen), 0)
    headers = headers[0:offset-4] + p
    if (packet.inner_version == 6 and entry["n"] == "ETR" and 
        len(trace.packet_json) == 2):
        udp = headers[offset-8::] + trace_pkt
        udp = lisp_udp_checksum(seid, deid, udp)
        headers = headers[0:offset-8] + udp[0:8]
    #endif

    #
    # If we are swapping addresses, do it here so the JSON append and IP
    # header fields changes are all reflected in new IPv4 header checksum.
    #
    # Clear the DF-bit because we may have to fragment as the packet is going
    # to grow with trace data.
    #
    if (swap):
        if (packet.inner_version == 4):
            headers = headers[0:12] + headers[16:20] + headers[12:16] + \
                headers[22:24] + headers[20:22] + headers[24::]
        else:
            headers = headers[0:8] + headers[24:40] + headers[8:24] + \
                headers[42:44] + headers[40:42] + headers[44::]
        #endif
        d = packet.inner_dest
        packet.inner_dest = packet.inner_source
        packet.inner_source = d
#       df_flags = struct.unpack("B", headers[6:7])[0] & 0xbf
#       headers = headers[0:6] + struct.pack("B", df_flags) + headers[7::]
    #endif

    #
    # Fix up IP length.
    #
    offset = 2 if packet.inner_version == 4 else 4
    iplen = 20 + udplen if packet.inner_version == 4 else udplen
    h = struct.pack("H", socket.htons(iplen))
    headers = headers[0:offset] + h + headers[offset+2::]

    #
    # Fix up IPv4 header checksum.
    #
    if (packet.inner_version == 4):
        c = struct.pack("H", 0)
        headers = headers[0:10] + c + headers[12::]
        h = lisp_ip_checksum(headers[0:20])
        headers = h + headers[20::]
    #endif

    #
    # Caller is forwarding packet, either as an ITR, RTR, or ETR.
    #
    packet.packet = headers + trace_pkt
    return(True)
#enddef

#
# lisp_allow_gleaning
#
# Check the lisp_glean_mapping array to see if we should glean the EID and
# RLOC. Find first match. Return False if there are no configured glean
# mappings. The second return value is either True or False depending if the
# matched entry was configured to RLOC-probe the RLOC for the gleaned entry.
#
def lisp_allow_gleaning(eid, group, rloc):
    if (lisp_glean_mappings == []): return(False, False, False)
    
    for entry in lisp_glean_mappings:
        if ("instance-id" in entry):
            iid = eid.instance_id
            low, high = entry["instance-id"]
            if (iid < low or iid > high): continue
        #endif
        if ("eid-prefix" in entry):
            e = copy.deepcopy(entry["eid-prefix"])
            e.instance_id = eid.instance_id
            if (eid.is_more_specific(e) == False): continue
        #endif
        if ("group-prefix" in entry):
            if (group == None): continue
            g = copy.deepcopy(entry["group-prefix"])
            g.instance_id = group.instance_id
            if (group.is_more_specific(g) == False): continue
        #endif
        if ("rloc-prefix" in entry):
            if (rloc != None and rloc.is_more_specific(entry["rloc-prefix"])
                == False): continue
        #endif
        return(True, entry["rloc-probe"], entry["igmp-query"])
    #endfor
    return(False, False, False)
#enddef

#
# lisp_build_gleaned_multicast
#
# Build (*,G) map-cache entry in RTR with gleaned RLOC info from IGMP report.
#
def lisp_build_gleaned_multicast(seid, geid, rloc, port, igmp):
    group_str = geid.print_address()
    seid_name = seid.print_address_no_iid()
    s = green("{}".format(seid_name), False)
    e = green("(*, {})".format(group_str), False)
    r = red(rloc.print_address_no_iid() + ":" + str(port), False)
    
    #
    # Support (*,G) only gleaning. Scales better anyway.
    #
    mc = lisp_map_cache_lookup(seid, geid)
    if (mc == None):
        mc = lisp_mapping("", "", [])
        mc.group.copy_address(geid)
        mc.eid.copy_address(geid)
        mc.eid.address = 0
        mc.eid.mask_len = 0
        mc.mapping_source.copy_address(rloc)
        mc.map_cache_ttl = LISP_IGMP_TTL
        mc.gleaned = True
        mc.add_cache()
        lprint("Add gleaned EID {} to map-cache".format(e))
    #endif

    #
    # Check to see if RLE node exists. If so, update the RLE node RLOC and
    # encap-port.
    #
    rloc_entry = rle_entry = rle_node = None
    if (mc.rloc_set != []):
        rloc_entry = mc.rloc_set[0]
        if (rloc_entry.rle):
            rle_entry = rloc_entry.rle
            for rn in rle_entry.rle_nodes:
                if (rn.rloc_name != seid_name): continue
                rle_node = rn
                break
            #endfor
        #endif
    #endif
    
    #
    # Adding RLE to existing rloc-set or create new one.
    #
    if (rloc_entry == None):
        rloc_entry = lisp_rloc()
        mc.rloc_set = [rloc_entry]
        rloc_entry.priority = 253
        rloc_entry.mpriority = 255
        mc.build_best_rloc_set()
    #endif
    if (rle_entry == None):
        rle_entry = lisp_rle(geid.print_address())
        rloc_entry.rle = rle_entry
    #endif
    if (rle_node == None):
        rle_node = lisp_rle_node()
        rle_node.rloc_name = seid_name
        rle_entry.rle_nodes.append(rle_node)
        rle_entry.build_forwarding_list()
        lprint("Add RLE {} from {} for gleaned EID {}".format(r, s, e))
    elif (rloc.is_exact_match(rle_node.address) == False or
          port != rle_node.translated_port):
        lprint("Changed RLE {} from {} for gleaned EID {}".format(r, s, e))
    #endif

    #
    # Add or update.
    #
    rle_node.store_translated_rloc(rloc, port)

    #
    # An IGMP report was received. Update timestamp so we don't time out
    # actively joined groups.              
    #
    if (igmp):
        seid_str = seid.print_address()
        if (seid_str not in lisp_gleaned_groups):
            lisp_gleaned_groups[seid_str] = {}
        #endif
        lisp_gleaned_groups[seid_str][group_str] = lisp_get_timestamp()
    #endif
#enddef

#
# lisp_remove_gleaned_multicast
#
# Remove an RLE from a gleaned entry since an IGMP Leave message was received.
#
def lisp_remove_gleaned_multicast(seid, geid):

    #
    # Support (*,G) only gleaning. Scales better anyway.
    #
    mc = lisp_map_cache_lookup(seid, geid)
    if (mc == None): return
    
    rle = mc.rloc_set[0].rle
    if (rle == None): return

    rloc_name = seid.print_address_no_iid()
    found = False
    for rle_node in rle.rle_nodes:
        if (rle_node.rloc_name == rloc_name):
            found = True
            break
        #endif
    #endfor
    if (found == False): return

    #
    # Found entry to remove.
    #
    rle.rle_nodes.remove(rle_node)
    rle.build_forwarding_list()

    group_str = geid.print_address()
    seid_str = seid.print_address()
    s = green("{}".format(seid_str), False)
    e = green("(*, {})".format(group_str), False)
    lprint("Gleaned EID {} RLE removed for {}".format(e, s))

    #
    # Remove that EID has joined the group.
    #
    if (seid_str in lisp_gleaned_groups):
        if (group_str in lisp_gleaned_groups[seid_str]):
            lisp_gleaned_groups[seid_str].pop(group_str)
        #endif
    #endif

    #
    # Remove map-cache entry if no more RLEs present.
    #
    if (rle.rle_nodes == []):
        mc.delete_cache()
        lprint("Gleaned EID {} remove, no more RLEs".format(e))
    #endif
#enddef

#
# lisp_change_gleaned_multicast
#
# Change RLOC for each gleaned group this EID has joined.
#
def lisp_change_gleaned_multicast(seid, rloc, port):
    seid_str = seid.print_address()
    if (seid_str not in lisp_gleaned_groups): return

    for group in lisp_gleaned_groups[seid_str]:
        lisp_geid.store_address(group)
        lisp_build_gleaned_multicast(seid, lisp_geid, rloc, port, False)
    #endfor
#enddef

#
# lisp_process_igmp_packet
#
# Process IGMP packets.
#
# Basically odd types are Joins and even types are Leaves.
#
#
# An IGMPv1 and IGMPv2 report format is:
#
#      0                   1                   2                   3
#      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |Version| Type  |    Unused     |           Checksum            |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                         Group Address                         |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# An IGMPv3 report format is:
# 
#      0                   1                   2                   3
#      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |  Type = 0x22  |    Reserved   |           Checksum            |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |           Reserved            |  Number of Group Records (M)  |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                                               |
#     .                                                               .
#     .                        Group Record [1]                       .
#     .                                                               .
#     |                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                                               |
#     .                                                               .
#     .                        Group Record [2]                       .
#     .                                                               .
#     |                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                               .                               |
#     .                               .                               .
#     |                               .                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                                               |
#     .                                                               .
#     .                        Group Record [M]                       .
#     .                                                               .
#     |                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# An IGMPv3 group record format is:
#
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                       Multicast Address                       |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                       Source Address [1]                      |
#     +-                                                             -+
#     |                       Source Address [2]                      |
#     +-                                                             -+
#     .                               .                               .
#     .                               .                               .
#     .                               .                               .
#     +-                                                             -+
#     |                       Source Address [N]                      |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                                                               |
#     .                                                               .
#     .                         Auxiliary Data                        .
#     .                                                               .
#     |                                                               |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
#
# The function returns a boolean (True) when packet is an IGMP query and
# an array when it is a report. Caller must check where there is context
# to deal with IGMP queries.
#
# IMPORTANT NOTE: for encapsulated IGMP Queries to be forwarded correctly
# after the ETR decapsulates them, you need this in the kernel (put this
# statement in the RL script):
#
#    ip route add 224.0.0.1/32 dev lo
#
# For OOR runnnig as a LISP-MN use:
#
#    ip route add 224.0.0.1/32 dev utun4
#
igmp_types = { 17 : "IGMP-query", 18 : "IGMPv1-report", 19 : "DVMRP",
    20 : "PIMv1", 22 : "IGMPv2-report", 23 : "IGMPv2-leave",  
    30 : "mtrace-response", 31 : "mtrace-request", 34 : "IGMPv3-report" }

lisp_igmp_record_types = { 1 : "include-mode", 2 : "exclude-mode", 
    3 : "change-to-include", 4 : "change-to-exclude", 5 : "allow-new-source", 
    6 : "block-old-sources" }

def lisp_process_igmp_packet(packet):
    source = lisp_address(LISP_AFI_IPV4, "", 32, 0)
    source.address = socket.ntohl(struct.unpack("I", packet[12:16])[0])
    source = bold("from {}".format(source.print_address_no_iid()), False)

    r = bold("Receive", False)
    lprint("{} {}-byte {}, IGMP packet: {}".format(r, len(packet), source,
        lisp_format_packet(packet)))

    #
    # Jump over IP header.
    #
    header_offset = (struct.unpack("B", packet[0:1])[0] & 0x0f) * 4

    #
    # Check for IGMPv3 type value 0x22. Or process an IGMPv2 report.
    #
    igmp = packet[header_offset::]
    igmp_type = struct.unpack("B", igmp[0:1])[0]

    #
    # Maybe this is an IGMPv1 or IGMPv2 message so get group address. If 
    # IGMPv3, we will fix up group address in loop (for each group record).
    #
    group = lisp_address(LISP_AFI_IPV4, "", 32, 0)
    group.address = socket.ntohl(struct.unpack("II", igmp[:8])[1])
    group_str = group.print_address_no_iid()

    if (igmp_type == 17):
        lprint("IGMP Query for group {}".format(group_str))
        return(True)
    #endif

    reports_and_leaves_only = (igmp_type in (0x12, 0x16, 0x17, 0x22))
    if (reports_and_leaves_only == False):
        igmp_str = "{} ({})".format(igmp_type, igmp_types[igmp_type]) if \
            (igmp_type in igmp_types) else igmp_type
        lprint("IGMP type {} not supported".format(igmp_str))
        return([])
    #endif

    if (len(igmp) < 8):
        lprint("IGMP message too small")
        return([])
    #endif

    #
    # Process either IGMPv1 or IGMPv2 and exit.
    #
    if (igmp_type == 0x17):
        lprint("IGMPv2 leave (*, {})".format(bold(group_str, False)))
        return([[None, group_str, False]])
    #endif
    if (igmp_type in (0x12, 0x16)):
        lprint("IGMPv{} join (*, {})".format( \
            1 if (igmp_type == 0x12) else 2, bold(group_str, False)))

        #
        # Suppress for link-local groups.
        #
        if (group_str.find("224.0.0.") != -1):
            lprint("Suppress registration for link-local groups")
        else:
            return([[None, group_str, True]])
        #endif

        #
        # Finished with IGMPv1 or IGMPv2 processing.
        #
        return([])
    #endif

    #
    # Parse each record for IGMPv3 (igmp_type == 0x22).
    #
    record_count = group.address
    igmp = igmp[8::]

    group_format = "BBHI"
    group_size = struct.calcsize(group_format)
    source_format = "I"
    source_size = struct.calcsize(source_format)
    source = lisp_address(LISP_AFI_IPV4, "", 32, 0)

    #
    # Traverse each group record.
    #
    register_entries = []
    for i in range(record_count):
        if (len(igmp) < group_size): return
        record_type, x, source_count, address = struct.unpack(group_format, 
            igmp[:group_size])

        igmp = igmp[group_size::]

        if (record_type not in lisp_igmp_record_types):
            lprint("Invalid record type {}".format(record_type))
            continue
        #endif

        record_type_str = lisp_igmp_record_types[record_type]
        source_count = socket.ntohs(source_count)
        group.address = socket.ntohl(address)
        group_str = group.print_address_no_iid()

        lprint("Record type: {}, group: {}, source-count: {}".format( \
            record_type_str, group_str, source_count))

        #
        # Determine if this is a join or leave. MODE_IS_INCLUDE (1) is a join. 
        # MODE_TO_EXCLUDE (4) with no sources is a join. CHANGE_TO_INCLUDE (5)
        # is a join. Everything else is a leave.
        #
        joinleave = False
        if (record_type in (1, 5)): joinleave = True
        if (record_type in (2, 4) and source_count == 0): joinleave = True
        j_or_l = "join" if (joinleave) else "leave"

        #
        # Suppress registration for link-local groups.
        #
        if (group_str.find("224.0.0.") != -1):
            lprint("Suppress registration for link-local groups")
            continue
        #endif

        #
        # (*,G) Join or Leave has been received if source count is 0.
        #
        # If this is IGMPv2 or just IGMPv3 reporting a group address, encode
        # a (*,G) for the element in the register_entries array.
        #
        if (source_count == 0):
            register_entries.append([None, group_str, joinleave])
            lprint("IGMPv3 {} (*, {})".format(bold(j_or_l, False), 
                bold(group_str, False)))
        #endif

        #
        # Process (S,G)s (source records)..
        #
        for j in range(source_count):
            if (len(igmp) < source_size): return
            address = struct.unpack(source_format, igmp[:source_size])[0]
            source.address = socket.ntohl(address)
            source_str = source.print_address_no_iid()
            register_entries.append([source_str, group_str, joinleave])
            lprint("{} ({}, {})".format(j_or_l, 
                green(source_str, False), bold(group_str, False)))
            igmp = igmp[source_size::]
        #endfor
    #endfor

    #
    # Return (S,G) entries to return to call to send a Map-Register.
    # They are put in a multicast Info LCAF Type with ourselves as an RLE.
    # This is spec'ed in RFC 8378.
    #
    return(register_entries)
#enddef

#
# lisp_glean_map_cache
#
# Add or update a gleaned EID/RLOC to the map-cache. This function will do
# this for the source EID of a packet and IGMP reported groups with one call.
#
lisp_geid = lisp_address(LISP_AFI_IPV4, "", 32, 0)

def lisp_glean_map_cache(seid, rloc, encap_port, igmp):

    #
    # First do lookup to see if EID is in map-cache. Check to see if RLOC
    # or encap-port needs updating. If not, return. Set refresh timer since
    # we received a packet from the source gleaned EID.
    #
    rloc_change = True
    mc = lisp_map_cache.lookup_cache(seid, True)
    if (mc and len(mc.rloc_set) != 0):
        mc.last_refresh_time = lisp_get_timestamp()
            
        cached_rloc = mc.rloc_set[0]
        orloc = cached_rloc.rloc
        oport = cached_rloc.translated_port
        rloc_change = (orloc.is_exact_match(rloc) == False or
            oport != encap_port)
        
        if (rloc_change):
            e = green(seid.print_address(), False)
            r = red(rloc.print_address_no_iid() + ":" + str(encap_port), False)
            lprint("Change gleaned EID {} to RLOC {}".format(e, r))
            cached_rloc.delete_from_rloc_probe_list(mc.eid, mc.group)
            lisp_change_gleaned_multicast(seid, rloc, encap_port)
        #endif
    else:
        mc = lisp_mapping("", "", [])
        mc.eid.copy_address(seid)
        mc.mapping_source.copy_address(rloc)
        mc.map_cache_ttl = LISP_GLEAN_TTL
        mc.gleaned = True
        e = green(seid.print_address(), False)
        r = red(rloc.print_address_no_iid() + ":" + str(encap_port), False)
        lprint("Add gleaned EID {} to map-cache with RLOC {}".format(e, r))
        mc.add_cache()
    #endif

    #
    # Adding RLOC to new map-cache entry or updating RLOC for existing entry..
    #
    if (rloc_change):
        rloc_entry = lisp_rloc()
        rloc_entry.store_translated_rloc(rloc, encap_port)
        rloc_entry.add_to_rloc_probe_list(mc.eid, mc.group)
        rloc_entry.priority = 253
        rloc_entry.mpriority = 255
        rloc_set = [rloc_entry]
        mc.rloc_set = rloc_set
        mc.build_best_rloc_set()
    #endif

    #
    # Unicast gleaning only.
    #
    if (igmp == None): return

    #
    # Process IGMP report. For each group, put in map-cache with gleaned
    # source RLOC and source port.
    #
    lisp_geid.instance_id = seid.instance_id

    #
    # Add (S,G) or (*,G) to map-cache. Do not do lookup in group-mappings.
    # The lisp-etr process will do this.
    #
    entries = lisp_process_igmp_packet(igmp)
    if (type(entries) == bool): return

    for source, group, joinleave in entries:
        if (source != None): continue

        #
        # Does policy allow gleaning for this joined multicast group.
        #
        lisp_geid.store_address(group)
        allow, x, y = lisp_allow_gleaning(seid, lisp_geid, rloc)
        if (allow == False): continue

        if (joinleave):
            lisp_build_gleaned_multicast(seid, lisp_geid, rloc, encap_port,
                True)
        else:
            lisp_remove_gleaned_multicast(seid, lisp_geid)
        #endif
    #endfor
#enddef

#
# lisp_is_json_telemetry
#
# Return dictionary arraay if json string has the following two key/value
# pairs in it. Otherwise, return None.
#
# { "type" : "telemetry", "sub-type" : "timestamps" }
#
def lisp_is_json_telemetry(json_string):
    try:
        tel = json.loads(json_string)
        if (type(tel) != dict): return(None)
    except:
        lprint("Could not decode telemetry json: {}".format(json_string))
        return(None)
    #endtry

    if ("type" not in tel): return(None)
    if ("sub-type" not in tel): return(None)
    if (tel["type"] != "telemetry"): return(None)
    if (tel["sub-type"] != "timestamps"): return(None)
    return(tel)
#enddef

#
# lisp_encode_telemetry
#
# Take json string:
#
# { "type" : "telemetry", "sub-type" : "timestamps", "itr-out" : "?",
#   "etr-in" : "?", "etr-out" : "?", "itr-in" : "?" }
#
# And fill in timestamps for the 4 fields. Input to this function is a string.
#
def lisp_encode_telemetry(json_string, ii="?", io="?", ei="?", eo="?"):
    tel = lisp_is_json_telemetry(json_string)
    if (tel == None): return(json_string)

    if (tel["itr-in"] == "?"): tel["itr-in"] = ii
    if (tel["itr-out"] == "?"): tel["itr-out"] = io
    if (tel["etr-in"] == "?"): tel["etr-in"] = ei
    if (tel["etr-out"] == "?"): tel["etr-out"] = eo
    json_string = json.dumps(tel)
    return(json_string)
#enddef

#
# lisp_decode_telemetry
#
# Take json string:
#
# { "type" : "telemetry", "sub-type" : "timestamps", "itr-out" : "?",
#   "etr-in" : "?", "etr-out" : "?", "itr-in" : "?" }
#
# And return values in a dictionary array. Input to this function is a string.
#
def lisp_decode_telemetry(json_string):
    tel = lisp_is_json_telemetry(json_string)
    if (tel == None): return({})
    return(tel)
#enddef

#
# lisp_telemetry_configured
#
# Return JSON string template of telemetry data if it has been configured.
# If it has been configured we'll find a "lisp json" command with json-name
# "telemetry". If found, return the json string. Otherwise, return None.
#
def lisp_telemetry_configured():
    if ("telemetry" not in lisp_json_list): return(None)

    json_string = lisp_json_list["telemetry"].json_string
    if (lisp_is_json_telemetry(json_string) == None): return(None)

    return(json_string)
#enddef

#
# lisp_mr_or_pubsub
#
# Test action for Map-Request or Map-Request with Subscribe bit set.
#
def lisp_mr_or_pubsub(action):
    return(action in [LISP_SEND_MAP_REQUEST_ACTION, LISP_SEND_PUBSUB_ACTION])
#enddef
    
#------------------------------------------------------------------------------
