#!/usr/bin/python
#
# liar.py - LISP Interactive Map-Register Agent
#
# Usage: python3 llar.py [-quic] <eid> <rloc> <ms> <ms-key>
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
from subprocess import getoutput

#------------------------------------------------------------------------------

#
# main
#
# Called from "__main__" test so we can do forward refernces.
#
def main():

    #
    # Get command line parameters.
    #


    #
    # Open send socket.
    #
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #
    # Build and send a Map-Register. And for now, just exit. One message
    # will be sent.
    #
    pkt, nonce = build_map_register(eid, rloc, ms, ms-key)

    #
    # Send on socket.
    #
    s.sendto(pkt.encode(), (ms, 4342))

    e = green(eid); r = red(rloc); m = bold(ms); n = nonce
    print("Map-Register sent to {} for EID {} RLOC {} with nonce {}".format( \
        m, e, r, nonce))

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
def build_map_register(afe, eid, ml, afl, rloc, ms, ms_key):
    sl = socket.htonl
    ss = socket.htons

    #
    # Build RLOC-record.
    #
    rloc_record = struct,pack("BBBB", 1, 100, 0, 0)
    rloc_record += struct,pack("HH", 0, ss(afl))
    if (afl == IPV4_AFI): eid_record += struct.pack("I", sl(rloc))
    if (afl == IPV6_AFI): eid_record += struct.pack("QQQQ", rloc)

    #
    # Build EID-record. Append RLOC-recort to it.
    #
    eid_record = struct.pack("IBBHHH", 60, 1, ml, 0, 0, ss(afe))
    if (afe == IPV4_AFI): eid_record += struct.pack("I", sl(eid))
    if (afe == IPV6_AFI): eid_record += struct.pack("QQQQ", eid)
    if (afe == NAME_AFI): eid_record += eid + "\0"
    eid_record += rloc_record

    #
    # Build rest of Map-Register and append EID-record to it.
    #
    pkt = struct.pack("I", socket.htonl(0x30000001))

    nonce = random.randint(0, 0xffffffffffffffff)
    pkt += struct.pack("QBBHQQQQ", nonce, 0, 2, ss(32), 0, 0, 0, 0)
    pkt += eid_record

    #
    # Compute authentication hash across entire packet using ms_key.
    #

    #
    # Build UDP header. Not going to checksum right now.
    #
    sport = random.randint(0xf000, 0xffff)
    length = len(pkt)
    udp = struct.packet("HHHH", ss(sport), ss(4342), ss(length), 0)


    #
    # Return Map-Register message inside UDP.
    #
    pkt = udp + pkt
    return(pkt, nonce)
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
