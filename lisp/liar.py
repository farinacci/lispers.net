#!/usr/bin/python
#
# liar.py - LISP Interactive Map-Register Agent
#
# Usage: python3 liar.py [-quic] <eid> <rloc> <ms> <ms-key>
#
# This client tool will send a Map-Register message to a Map-Server and then
# exit. It is used to import state from other systems into the LISP mapping
# system. 
#
# When the -quic switch is supplied, then the Map-Register is sent as a UDP
# message over a QUIC connection. Otherwise, the Map-Register is simply
# sent over a UDP datagra.
#
# The program will format the Map-Register with a single EID-record. The
# <eid> encoded can be an IPv4 address, an IPv6 address, or a distinguished
# name (ascii string). The RLOC-record within the EID-record contains the
# RLOC specified by <rloc>. It can be an IPv4 or IPv6 address. The RLOC-record
# will also contain an "rloc-name" accompany the <rloc> address. It will be
# "liar-<hostname>" so the map-server has knowledge that the mapping entry
# was created by this tool.
#
# This program runs stand alone and does not depend on any lispers.net code. If
# you want to lookup mapping entries you can use the lispers.net "lig" client
# which does depend on lispers.net being installed  on the system. 
#
#------------------------------------------------------------------------------

import sys
import socket
import struct
import random
import binascii
import hmac
import hashlib

#------------------------------------------------------------------------------

usage = 'Usage: python3 liar.py [-quic] "[[<iid>]]<eid>" <rloc> <ms> <ms-key>'

IPV4_AFI = 1
IPV6_AFI = 2
NAME_AFI = 17
LCAF_AFI = 16387

#------------------------------------------------------------------------------

#
# main
#
# Called from "__main__" test so we can do forward refernces.
#
def main():

    #
    # Get command line parameters, parse them and validate them..
    #
    if (len(sys.argv) == 1):
        print(usage)
        return
    #endif
    quic = ("-quic" in sys.argv)
    if (quic): sys.argv.remove("-quic")

    if (len(sys.argv) < 5):
        print(usage)
        return
    #endif

    orig_eid = sys.argv[1]
    afe, iid, eid, ml = validate_eid(orig_eid)
    if (afe == None): return

    orig_rloc = sys.argv[2]
    afl, rloc = validate_rloc(orig_rloc)
    if (afl == None): return

    orig_ms = sys.argv[3]
    ms = validate_ms(orig_ms)
    if (ms == None): return

    ms_key = sys.argv[4]

    #
    # Open send socket.
    #
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #
    # Build and send a Map-Register. And for now, just exit. One message
    # will be sent.
    #
    pkt, nonce = build_map_register(afe, iid, eid, ml, afl, rloc, ms, ms_key)

    #
    # Send on socket.
    #
    s.sendto(pkt, (ms, 4342))

    e = green(orig_eid); r = red(orig_rloc); m = bold(orig_ms);
    print("Map-Register sent to {} for EID {} RLOC {} with nonce {}". \
          format(m, e, r, hex(nonce)))

    #
    # Cleanup resources.
    #
    s.close()
    return
#enddef    

# -----------------------------------------------------------------------------

#
# build_map_register
#
# Build this LISP Map-Register message:
#
#      0                   1                   2                   3
#      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |Type=3 |P|S|I|    Reserved   | kid |e|F|T|a|m|M| Record Count  |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                         Nonce . . .                           |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |                         . . . Nonce                           |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     |    Key ID     | Algorithm ID  |  Authentication Data Length   |
#     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     ~                     Authentication Data                       ~
# +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   |                          Record TTL                           |
# |   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# R   | Locator Count | EID mask-len  | ACT |A|      Reserved         |
# e   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# c   | Rsvd  |  Map-Version Number   |        EID-Prefix-AFI         |
# o   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# r   |                          EID-Prefix                           |
# d   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  /|    Priority   |    Weight     |  M Priority   |   M Weight    |
# | L +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | o |        Unused Flags     |L|p|R|           Loc-AFI             |
# | c +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  \|                             Locator                           |
# +-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
def build_map_register(afe, iid, eid, ml, afl, rloc, ms, ms_key):
    sl = socket.htonl
    ss = socket.htons

    #
    # Build RLOC-record. RLOC is an AFI-List LCAF so an RLOC address and
    # name can be enocded.
    #
    rloc_name = "liar-{}".format(socket.gethostname())
    rloc_name = (rloc_name + "\0").encode()
    rloc_record = struct.pack("BBBB", 1, 100, 0, 0)
    rloc_record += struct.pack("HHHBB", 0, ss(LCAF_AFI), 0, 1, 0)

    lcaf_len = 4 + 2 if (afl == IPV4_AFI) else 16 + 2
    lcaf_len += len(rloc_name) + 2
    rloc_record += struct.pack("H", ss(lcaf_len))

    #
    # Insert RLOC address first and then dist-name next.
    #
    rloc_record += struct.pack("H", ss(afl))
    if (afl == IPV4_AFI): rloc_record += struct.pack("I", sl(rloc))
    if (afl == IPV6_AFI):
        a1 = byte_swap_64(rloc >> 64)
        a2 = byte_swap_64(rloc & 0xffffffffffffffff)
        rloc_record += struct.pack("QQ", a1, a2)
    #endif
    rloc_record += struct.pack("H", ss(NAME_AFI))
    rloc_record += rloc_name

    #
    # Build EID-record. Append RLOC-recort to it.
    #
    eid_record = struct.pack("IBBHHHH", sl(60), 1, ml, 0, 0, ss(LCAF_AFI), 0)
    eid_record += struct.pack("BB", 2, 0)
    lcaf_len = 4 + 2
    lcaf_len += 4 if (afe == IPV4_AFI) else 16
    eid_record += struct.pack("H", ss(lcaf_len))
    eid_record += struct.pack("IH", sl(iid), ss(afe))

    if (afe == IPV4_AFI): eid_record += struct.pack("I", sl(eid))
    if (afe == NAME_AFI): eid_record += (eid + "\0").encode()
    if (afe == IPV6_AFI):
        a1 = byte_swap_64(eid >> 64)
        a2 = byte_swap_64(eid & 0xffffffffffffffff)
        eid_record += struct.pack("QQ", a1, a2)
    #endif
    eid_record += rloc_record

    #
    # Build rest of Map-Register with zeroed auth-data and append EID-record
    # to it. Set T-bit so we can use our own TTL.
    #
    pkt = struct.pack("I", sl(0x30000801))
    nonce = random.randint(0, 0xffffffffffffffff)
    pkt += struct.pack("QBBH", nonce, 0, 2, ss(32))
    pkt += struct.pack("QQQQ", 0, 0, 0, 0)
    pkt += eid_record

    #
    # Compute authentication hash across entire packet using ms_key. Use
    # 32-byte produced sha256() hash.
    #
    hashval = hmac.new(ms_key.encode(), pkt, hashlib.sha256).digest()
    pkt = pkt[0:16] + hashval + pkt[16+32::]

#   print_packet(pkt)
    return(pkt, nonce)
#enddef

#
# print_packet
#
# For looking at packet hex.
#
def print_packet(packet):
    packet = binascii.hexlify(packet)
    offset = 0
    new = b""
    length = len(packet) * 2
    while (offset < length):
        new += packet[offset:offset+8] + b" "
        offset += 8
        length -= 4
    #endfor
    print(new.decode())
#enddef

#
# validate_eid
#
# Validate 3 types of EIDs on command line. IPv4 'x.x.x.x", IPv6 "xx:yy:;zz",
# or distinguished-names "<string>".
#
def validate_eid(eid):

    #
    # Parse instance-id first. If not supplied, iid is 0.
    #
    iid = 0
    i = eid.find("["); j = eid.find("]")
    if (i != -1 and j != -1): 
        iid = int(eid[i+1:j])
        eid = eid[j+1::]
    #endif
    
    e = eid.split("/")
    ml = int(e[1]) if len(e) == 2 else None
    eid = e[0]

    #
    # Check for IPv4.
    #
    if (eid.count(".") == 3):
        try:
            eid = socket.inet_pton(socket.AF_INET, eid)
        except:
            print("Invalid IPv4 EID address format")
            return(None, None, None, None)
        #endtry
        eid = int(binascii.hexlify(eid), 16)
        if (ml == None): ml = 32
        return(IPV4_AFI, iid, eid, ml)
    #endif

    #
    # Check for IPv6.
    #
    if (eid.find(":") != -1):
        try:
            eid = socket.inet_pton(socket.AF_INET6, eid)
        except:
            print("Invalid IPv6 EID address format")
            return(None, None, None, None)
        #endtry
        eid = int(binascii.hexlify(eid), 16)
        if (ml == None): ml = 128
        return(IPV6_AFI, iid, eid, ml)
    #endif

    if (eid.count(".") > 3):
        print("Invalid distinguished-name EID format")
        return(None, None, None, None)
    #endif

    #
    # Must be a distinguished-name.
    #
    return(NAME_AFI, iid, eid, len(eid) * 8)
#enddef

#
# validate_rloc
#
# Parse IPv4 or IPv6 RLOC and return in binary format byte swapped..
#
def validate_rloc(rloc):

    #
    # Check for IPv4.
    #
    if (rloc.count(".") == 3):
        try:
           rloc = socket.inet_pton(socket.AF_INET, rloc)
        except:
            print("Invalid IPv4 RLOC address format")
            return(None, None)
        #endtry
        rloc = int(binascii.hexlify(rloc), 16)
        return(IPV4_AFI, rloc)
    #endif

    #
    # Check for IPv6.
    #
    if (rloc.find(":") != -1):
        try:
            rloc = socket.inet_pton(socket.AF_INET6, rloc)
        except:
            print("Invalid IPv6 RLOC address format")
            return(None, None)
        #endtry
        rloc = int(binascii.hexlify(rloc), 16)
        return(IPV6_AFI, rloc)
    #endif

    return(None, None)
#enddef

#
# validate_ms
#
# Just do a DNS hostname lookup. 
#
def validate_ms(ms):
    try:
        ms = socket.gethostbyname(ms)
    except:
        print("Could not resolve map-server DNS name")
        return(None)
    #endtry
    return(ms)
#enddef

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

#------------------------------------------------------------------------------

#
# Text coloring functions.
#
def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef
def green(string):
    return(bold("\033[92m" + string + "\033[0m"))
#enddef    
def red(string):
    return(bold("\033[91m" + string + "\033[0m"))
#enddef    

#------------------------------------------------------------------------------

if (__name__=="__main__"):
    main()
    exit(0)
#endif

#------------------------------------------------------------------------------
