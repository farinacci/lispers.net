#!/usr/bin/env python
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
# make-eid-hash.py
#
# Creates an IPv6 EID with a prefix and hash of an instance-ID, EID-prefix,
# and public key. This script will ask for an instance-ID and an EID-prefix,
# then will generate a ECDSA key-pair. What is displayed to standard output
# is:
#
# (1) Instance-ID and crypto-hash EID
# (2) A public-key
# (3) A signature of the string "[<iid>]<eid>"
#
# The output (public-key and signature) can go into a lisp.config file.
#
# Usage: python make-eid-hash.py
#
#------------------------------------------------------------------------------

import ecdsa
import sys
import hashlib
from binascii import b2a_base64 as b2a
from binascii import unhexlify as u
from binascii import hexlify as h

#
# Get parameters.
#
eid_prefix = raw_input("Enter EID-prefix (zero-fill prefix bits): ")
if (eid_prefix.find("/") == -1 or eid_prefix.count(":") == 0):
    print "EID-prefix must be an IPv6 address in slash format"
    exit(1)
#endif
eid_prefix, mask_len = eid_prefix.split("/")
mask_len = int(mask_len)
if ((mask_len % 4) != 0):
    print "Mask-length must be a multiple of 4"
    exit(1)
#endif

iid = raw_input("Enter Instance-ID: ")
try:
    iid = 0 if (iid == "") else int(iid)
except:
    print "Invalid Instance-ID"
    exit(1)
#endif
print ""

#
# Generate key-pair.
#
key = ecdsa.SigningKey.generate(curve=ecdsa.NIST256p)
pubkey = key.get_verifying_key().to_der()

#
# Build EID. The hash is <4-byte-iid><variable-length-prefix><pubkey>
#
eid_prefix = eid_prefix.replace(":", "")
eid_prefix = int(eid_prefix, 16)

hiid = hex(iid)[2::].zfill(8)
heid = hex(eid_prefix)[2::]

#
# Hash sum the 3-tuple. Put heid in IPv6 standard format.
#
hash_data = hiid + heid + pubkey
hash_value = hashlib.sha256(hash_data).hexdigest()

nibbles = (128 - mask_len) / 4
hv = hash_value[0:nibbles]
hash_value = int(hv, 16)

eid = (eid_prefix << (128-mask_len)) + hash_value
eid = hex(eid)[2:-1]
eid = eid[0:4] + ":" + eid[4:8] + ":" + eid[8:12] + ":" + eid[12:16] + ":" + \
    eid[16:20] + ":" + eid[20:24] + ":" + eid[24:28] + ":" + eid[28:32]
eid = eid.replace(":000", ":")
eid = eid.replace(":00", ":")
eid = eid.replace(":0", ":")

#
# Now do signature. Make sure sig_data is hashed with sha256. This is required
# for Go to Python interoperability. The lispers.net verifier needs to assume
# this for both signers. Note to use sha256, you need curve NIST256p.
#
sig_data = "[{}]{}".format(iid, eid)
sig = key.sign(sig_data, hashfunc=hashlib.sha256)

#
# Return values in base64 format
#
print "----------------------------------------------------------------------"
print ""
print "Crypto-hashed EID: {}".format(sig_data)
print ""
print "Private-key for lisp-sig.pem/lisp-lig.pem file:\n{}".format( \
    key.to_pem())

pubkey = b2a(key.get_verifying_key().to_pem())
print "Public-key for lisp.config file:\n{}".format(pubkey)
sig = b2a(sig)
print "EID signature for lisp.config file:\n{}".format(sig)

print "----------------------------------------------------------------------"
print ""

print "Add the following commands to the lisp.config file:"

hvv = hv
if ((len(hvv) % 4) == 0):
    hv = []
else:
    hv = [ hvv[0:2] ]
    hvv = hvv[2::]
#endif
for i in range(0, len(hvv), 4): 
    hv.append(hvv[i:i+4])
#endfor

hv = ":".join(hv)
ev = eid[-4::]
pubkey = pubkey.replace("\n", "")
sig = sig.replace("\n", "")

commands = '''
lisp json {
    json-name = pubkey-<ev>
    json-string = { "public-key" : "<pubkey>" }
}
lisp database-mapping {
    prefix {
        instance-id = <iid>
        eid-prefix = 'hash-<hv>'
    }
    rloc {
        json-name = pubkey-<ev>
        priority = 255
    }
}
lisp json {
    json-name = signature-<ev>
    json-string = { "signature-eid" : "[<iid>]<eid>", "signature" : "<sig>" }
}
lisp database-mapping {
    prefix {
        instance-id = <iid>
        eid-prefix = <eid>/128
        signature-eid = yes
    }
    rloc {
        interface = <interface>
    }
    rloc {
        json-name = signature-<ev>
        priority = 255
    }
}
'''
commands = commands.replace("<ev>", ev)
commands = commands.replace("<hv>", hv)
commands = commands.replace("<iid>", str(iid))
commands = commands.replace("<eid>", eid)
commands = commands.replace("<pubkey>", pubkey)
commands = commands.replace("<sig>", sig)

print commands
print "----------------------------------------------------------------------"

exit(0)
