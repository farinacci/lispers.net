#
# lisp-sys-info.py
#
# This script takes a hostname list from the command line and uses the
# lispapi.get_system() API call to get general information from the lispers.net
# system.
#
# Usage: python lisp-sys-info.py [<list-of-hosts>]
#
# A host name can be an IPv4 address, DNS name and either can be appended with
# ":<port>" so you can query through firewalls.
#

import sys
import os

#------------------------------------------------------------------------------

#
# bold
#
# For printing hostnames.
#
def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef

#------------------------------------------------------------------------------

path = os.getenv("LISPAPI_PATH")
if (path != None): sys.path.append(path)

try:
    import lispapi
except:
    if (os.path.exists("lispapi.pyo")):
        print "Try command 'python -O lisp-provision-xtr.pyo'"
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

#
# The host data structure will be a 3-element array of:
#
#     [<hostname>, <api-handle>, <get_system-contents>]
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
    hp = host[0].split(":")
    if (len(hp) != 2): hp = None
    if (hp == None):
        host[1] = lispapi.api_init(host[0], username, password)
    else:
        host[1] = lispapi.api_init(hp[0], username, password, port=hp[1])
    #endif
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
        host[2] = host[1].get_system()
        print "done"
    #endif
#endfor
print ""

#
# Print system info all at one time.
#
for host in hosts:
    info = host[2]
    if (info == None or len(info) == 0): continue
    print "System info for {}:".format(bold(host[0]))

    if (type(info) == list and "?" in info[0].keys()): 
        print "Not authenticated"
        continue
    #endif

    uptime = info["system-uptime"]

    ut = uptime.split("load average")[0]
    load = uptime.split("load average")[1]

    ut = ut.split("up")[1]
    ut = ut.split("users")[0]
    ut = ut.split(",")
    ut = ut[0][1::] + ", " + ut[1][1::] if (len(ut) > 1) else ut[0]

    index = load.find(":") + 2
    load = load[index::]

    print "  Hostname: {}, uptime: {}, load: {}".format(info["hostname"], ut, 
        load)
    print "  LISP-version: {}, LISP-uptime: {}".format( \
        info["lisp-version"], info["lisp-uptime"])

    rlocs = ""
    for rloc in info["lisp-rlocs"]: rlocs += rloc + ", "
    print "  LISP-RLOCs: {}".format(rlocs[:-2])

    if (info["traceback-log"] == "yes"):
        print "  *** Traceback exception occurred ***"
    #endif
#endfor

exit(0)

#------------------------------------------------------------------------------

