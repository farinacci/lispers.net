#
# lisp-map-cache.py
#
# This script will query a list of xTRs to retrieve their map-caches.
#
# Usage: python lisp-map-cache.py [<list-of-hosts>]
#

import sys
import os

#------------------------------------------------------------------------------

#
# print_map_cache
#
# For each xTR in list, print the map-cache retunred in tabluar format.
#
def print_map_cache(xtr, map_cache):
    print "LISP Map-Cache for '{}', {} entries\n".format(xtr, len(map_cache))
    for mc in map_cache:
        i = mc["instance-id"]
        e = mc["eid-prefix"]
        if (mc.has_key("group-prefix")):
            e = "({}, {})".format(e, mc["group-prefix"])
        #endif
        u = mc["uptime"]
        rlocs = mc["rloc-set"]

        rloc_set_len = len(rlocs)
        if (rloc_set_len):
            r = "{} rlocs:".format(rloc_set_len)
        else:
            r = "action: {}".format(mc["action"])
        #endif

        print "[{}]{}, uptime: {}, {}".format(i, e, u, r)
        for rloc in rlocs:
            r = rloc["address"] if rloc.has_key("address") else "none"
            u = rloc["uptime"]
            s = rloc["stats"]
            p_and_w = rloc["upriority"] + "/" + rloc["uweight"] + "/" + \
                rloc["mpriority"] + "/" + rloc["mweight"]
            print "  {}, uptime: {}, {}".format(r, u, p_and_w)

            if (rloc.has_key("geo")): print "    geo: {}".format(rloc["geo"])
            if (rloc.has_key("elp")): print "    elp: {}".format(rloc["elp"])
            if (rloc.has_key("rle")): print "    rle: {}".format(rloc["rle"])

            index = s.find("byte-count")
            print "    {}".format(s[:index-2])
            print "    {}".format(s[index:])
        #endfor
        print ""
    #endfor
    return
#enddef

#------------------------------------------------------------------------------

path = os.getenv("LISPAPI_PATH")
if (path != None): sys.path.append(path)

try:
    import lispapi
except:
    if (os.path.exists("lispapi.pyo")):
        print "Try command 'python -O lisp-map-cache.py'"
    else:
        print "Cannot find lispapi module, use LISPAPI_PATH env variable"
    #endif
    exit(1)
#endtry

#
# Check if environment variables with username and password are stored.
#
username = os.getenv("LISPAPI_USER")
if (username == None):
    print "LISPAPI_USER environment variable needs username setting"
    exit(0)
#endif
password = os.getenv("LISPAPI_PW")
if (password == None):
    print "LISPAPI_PW environment variable needs password setting"
    exit(0)
#endif
port = os.getenv("LISPAPI_PORT")
if (port == None): port = 8080

#
# The host data structure will be a 3-element array of:
#
#     [<hostname>, <api-handle>, <map-cache-contents>]
#
hosts = []
if (len(sys.argv) > 1):
    args = sys.argv[1::]
    for host in args: hosts.append([host, None, None])
else:
    while (True):
        host = raw_input("Enter hostname (enter return when done): ")
        if (host == ""): break
        hosts.append([host, None, None])
    #endwhile
#endif

print "Connecting to APIs ...",
sys.stdout.flush()

#
# Open API with each hostname. Store in 2-element of array.
#
for host in hosts:
    host[1] = lispapi.api_init(host[0], username, password, port=port)
#endfor
print ""

#
# Call lispapi.get_system() and store contents in 3-element of array.
#
for host in hosts:
    if (host[1] == None):
        print "Could not open API to {}".format(host[0])
    else:
        print "Querying {} ... ".format(host[0]), 
        host[2] = host[1].get_map_cache()
        print "done"
    #endif
#endfor
print ""

#
# Print system info all at one time.
#
for host in hosts:
    map_cache = host[2]
    if (map_cache == None): continue
    if (type(map_cache) == list):
        if (len(map_cache) == 0): 
            print "Empty map-cache"
            continue
        #endif
        if ("?" in map_cache[0].keys()): 
            print "Not authenticated to access {}".format(host[0])
            continue
        #endif
    #endif

    #
    # Print the map-cache.
    #
    print_map_cache(host[0], host[2])
#endfor

exit(0)

#------------------------------------------------------------------------------

