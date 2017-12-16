#
# lisp-provision-site.py
#
#
# This script creates "lisp site" command for map-servers. It provisions
# LISP sites so ETRs can get their Map-Registers accepted.
#
# Usage: python lisp-provision-site.py [<path-to-lispapi>]
#

import sys
import os
import socket

#------------------------------------------------------------------------------

class prefix():
    def __init__(self):
        self.eid_prefix = ""
        self.group = ""
        self.instance_id = ""
        self.ams = False
        self.fpr = False
        self.fnpr = False
        self.pprd = False
        self.pra = ""

    def parse_eid_prefix(self, string):
        addr_str = raw_input(string)
        if (addr_str == ""): return

        self.instance_id = "0"
        left = addr_str.find("[")
        right = addr_str.find("]")
        if (left == -1):
            self.eid_prefix = addr_str
        else:
            self.instance_id = addr_str[left+1:right]
            self.eid_prefix = addr_str[right+1::]
        #endif

    def print_eid_prefix(self):
        if (self.instance_id == ""): return(self.eid_prefix)
        return("[" + self.instance_id + "]" + self.eid_prefix)
    
#endclass

def yes_or_no(string):
    while (True):
        value = raw_input(string)
        if (value == "yes" or value == "no"): break
    #endwhile
    return((value == "yes"))
#enddef

def print_yes_or_no(value):
    return("yes" if value else "no")

#------------------------------------------------------------------------------

if (len(sys.argv) > 1): sys.path.append(sys.argv[1])

try:
    import lispapi
except:
    if (os.path.exists("lispapi.pyo")):
        print "Try command 'python -O lisp-provision-site.pyo'"
    else:
        print "Cannot find lispapi module"
    #endif
    exit(1)
#endtry

print """
---------- lispers.net Map-Server Site Provisioning Tool  ----------
"""

#
# First test if environment variable with password is setup.
#
if (os.getenv("LISPAPI_PW") == None):
    print "LISPAPI_PW environment variable needs password setting"
    exit(0)
#endif

site_name = raw_input("Enter Site name: ")
site_description = raw_input("Enter Site description: ")
site_auth_key = raw_input("Enter authentication key: ")

map_servers = []
while (True):
    ms = raw_input("Enter Map-Server address (enter return when done): ")
    if (ms == ""): break
    ms_input = ms
    ms = socket.gethostbyname(ms)
    api = lispapi.api_init(ms, "root")
    if (api.get_enable() == None):
        print "Authentication failed to Map-Server {}".format(ms_input)
        continue
    #endif
    map_servers.append({"addr": ms, "api": api})
#endwhile
print ""

prefixes = []
while (True):
    p = prefix()
    p.parse_eid_prefix("Alllowed EID-prefix: (enter return when done): ")
    if (p.eid_prefix == ""): break
    p.ams = yes_or_no("  accept-more-specifics (yes/no): ")
    p.fpr = yes_or_no("  force-proxy-reply (yes/no): ")
    p.pprd = yes_or_no("  pitr-proxy-reply-drop (yes/no): ")
    p.pra = raw_input("  proxy-reply-action (native-forward/drop/<enter>): ")
    if (p.pra != "native-forward" and p.pra != "drop"): p.pra = ""
    prefixes.append(p)
#endwhile

#
# Summarize input before verification.
#
print "\nConfigure site '{}' in Map-Servers: ".format(site_name),
for ms in map_servers: print "{}  ".format(ms["addr"]), 
print ""
print "  Site Name: {}".format(site_name)
print "  Site Description: {}".format(site_description)
print "  Authentication Key: {}".format(site_auth_key)

for p in prefixes:
    print "  Allowed EID-prefix: {}".format(p.eid_prefix)
    print "    accept-more-specifics = {}".format(print_yes_or_no(p.ams))
    print "    force-proxy-reply = {}".format(print_yes_or_no(p.fpr))
    print "    force-nat-proxy-reply = {}".format(print_yes_or_no(p.fnpr))
    print "    pitr-proxy-reply-drop = {}".format(print_yes_or_no(p.pprd))
    if (p.pra != ""): print "    proxy-reply-action = {}".format(p.pra)
#endfor

#
# Ask for verification.
#
go_or_stop = raw_input("\ngo/stop? ")
if (go_or_stop != "go"): 
    print "Abort provisioning"
    exit(0)
#endif

#
# Ready to start talking to devices. Right now, we assume the same password
# for each device.
#
print "Configuring Site {} now ...".format(site_name)

#
# -------------------- Call APIs --------------------
#
for ms in map_servers:
    add_site = ms["api"].add_ms_site
    build_prefix = ms["api"].build_ms_site_allowed_prefix
    enable_ms = api.enable_ms
    print "Provisioning Map-Server {} ... ".format(ms["addr"]), 
    prefix_list = []
    for p in prefixes:
        build_prefix(prefix_list, p.instance_id, p.eid_prefix, p.group, p.ams,
             p.fpr, p.fnpr, p.pprd, p.pra)
    #endfor
    s = add_site(site_name, site_auth_key, prefix_list, site_description)
    print "{}\n".format("complete" if s == "good" else "failed")
    if (s != "good"): break
    enable_ms()
#endfor

#
# All API calls worked. We are done.
#
print "Site provisioning complete!"
exit(0)

#------------------------------------------------------------------------------

