#
# lisp-provision-xtr.py
#
# This script creates "lisp database-mapping" commands for xTRs. And can
# also configure map-server and map-resolver command clauses that xTRs use.
#
# Usage: python lisp-provision-xtr.py [<path-to-lispapi>]
#

import sys
import os
import socket

#------------------------------------------------------------------------------

class db():
    def __init__(self):
        self.eid_prefix = ""
        self.group = ""
        self.instance_id = ""
        self.rloc_set = []

    def parse_prefix(self, string):
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

    def print_prefix(self):
        if (self.instance_id == ""): return(self.eid_prefix)
        return("[" + self.instance_id + "]" + self.eid_prefix)
    
    def add_rloc(self, rloc):
        self.rloc_set.append(rloc)
    
#endclass

#------------------------------------------------------------------------------

if (len(sys.argv) > 1): sys.path.append(sys.argv[1])

try:
    import lispapi
except:
    if (os.path.exists("lispapi.pyo")):
        print "Try command 'python -O lisp-provision-xtr.pyo'"
    else:
        print "Cannot find lispapi module"
    #endif
    exit(1)
#endtry

#
# Get port number from environment variable.
#
port = os.getenv("LISPAPI_PORT")
port = 8080 if (port == None) else int(port)

print """
---------- lispers.net xTR Provisioning Tool  ----------
"""

#
# First test if environment variable with password is setup.
#
if (os.getenv("LISPAPI_PW") == None):
    print "LISPAPI_PW environment variable needs password setting"
    exit(0)
#endif

#
# Get IP address of xTR to send API requests to.
#
xtr_rloc = raw_input("Enter xTR RLOC address to provision: ")

#
# Authenticate first before asking for more input parameters.
#
xtr = lispapi.api_init(xtr_rloc, "root", port=port)
if (xtr.get_enable() == None):
    print "Authentication failed to xTR {}".format(xtr_rloc)
    exit(0)
#endif

#
# Ask if the user wants to configure Map-Servers.
#
while (True):
    y_or_n = raw_input("Configure Map-Servers for this xTR (yes/no): ")
    if (y_or_n in ("yes", "no")): break
#endwhile

#
# If yes, then grab each Map-Server address and auth-key and store to write
# to xTR below (after verification).
#
map_servers = []
if (y_or_n == "yes"):
    while (True):
        ms = raw_input("Enter Map-Server address (enter return when done): ")
        if (ms == ""): break
        auth_key = raw_input("Enter authentication key for Map-Server: ")
        ms = socket.gethostbyname(ms)
        map_servers.append([ms, auth_key])
    #endwhile
    print "Map-Servers will be used as Map-Resolvers"
#endif
print ""
#endif

#
# Ask for database-mappings.
#
prefixes = []
while (True):
    p = db()
    p.parse_prefix("Enter EID-prefix: (enter return when done): ")
    if (p.eid_prefix == ""): break
    while (True):
        rloc = raw_input(("Enter RLOC (or local interface) for " + \
            "EID-prefix {} (enter return when done): ").format( \
            p.print_prefix()))
        if (rloc == ""): break
        p.add_rloc(rloc)
    #endif
    prefixes.append(p)
#endwhile

#
# Summarize input before verification.
#
if (len(prefixes) != 0): 
    print "\nConfigure database-mappings in xTR {}: ".format(xtr_rloc)
    for p in prefixes:
        print "  EID-prefix: {}, RLOC-set: ".format(p.print_prefix()), 
        for rloc in p.rloc_set: print "{}  ".format(rloc),
        print ""
    #endfor
#endif

if (len(map_servers) != 0):
    print "\nConfigure Map-Servers in xTR {}:".format(xtr_rloc)
    print "  ",
    for ms in map_servers: print "{}  ".format(ms[0]),
#endif

#
# Ask for verification.
#
go_or_stop = raw_input("\ngo/stop? ")
if (go_or_stop != "go"): 
    print "Abort provisioning"
    exit(0)
#endif

print "Configuring ITR and ETR ... ", 
xtr.enable_itr()
xtr.enable_etr()
print "complete"

if (len(map_servers) != 0):
    print "Configuring Map-Servers ... ", 
    for ms in map_servers: xtr.add_etr_map_server(ms[0], ms[1])
    print "complete"
    print "Configuring Map-Resolvers ... ", 
    for ms in map_servers: xtr.add_itr_map_resolver(ms[0])
    print "complete"
#endif

if (len(prefixes) != 0): print "Configuring Database-Mappings ... ", 
for p in prefixes:
    xtr.add_etr_database_mapping(p.instance_id, p.eid_prefix, p.group, 
        p.rloc_set)
#endfor
print "complete"
print ""

#
# All API calls worked. We are done.
#
print "xTR provisioning complete!"
exit(0)

#------------------------------------------------------------------------------

