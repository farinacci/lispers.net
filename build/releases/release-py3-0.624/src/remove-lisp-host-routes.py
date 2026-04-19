#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
# remove-lisp-host-routes.py
#
# This python script will remove /32 host routes that were installed by
# lispers.net during RLOC probing for multi-homing.
#
# Only removes routes for global/public IP addresses to avoid removing
# system routes for private/local addresses.
#
# -----------------------------------------------------------------------------
from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
import os
from subprocess import getoutput
import ipaddress

#------------------------------------------------------------------------------

#
# Clean up /32 host routes that may have been installed by lispers.net
# during RLOC probing. Only removes routes for global/public IP addresses
# to avoid removing system routes for private/local addresses.
#

print("Removing LISP host-routes ...")

#
# Note: ip route output shows /32 routes as just the IP address (no /32)
# followed by via, another IP, dev, and device name at end of line.
# Valid host routes have exactly 5 tokens: <ip> via <ip> dev <device>
#
try:
    output = getoutput(r"ip route | egrep 'via'")

    if (output == ""):
        print("ip route grep returned nothing")
        exit(1)
    #endif

    removed_routes = []
    for line in output.split("\n"):
        if (line == ""): continue
        tokens = line.split()
        if (len(tokens) != 5): continue
            
        #
        # Only clean up routes for non-private addresses that look like
        # they could be RLOC probes. Skip private address ranges.
        #
        dest = tokens[0]
        try:
            addr = ipaddress.ip_address(unicode(dest))
            if (addr.is_private or addr.is_loopback or
                addr.is_link_local or addr.is_multicast):
                continue
            #endif

            os.system("sudo ip route delete {}/32".format(dest))
            removed_routes.append(dest)
        except:
            pass
        #endtry
    #endfor

    print("Removed routes:", removed_routes)
except:
    pass
#endtry

exit(0)

#------------------------------------------------------------------------------
