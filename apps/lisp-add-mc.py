#
# lisp-add-mc.py
#
# This script is a quick add to a map-cache to any xTR via the lispapi.
#
# Usage: python lisp-add-mc.py "[<iid>]<eid-prefix>" <list-of-rlocs>
# Usage: python lisp-add-mc.py <eid-prefix> <list-of-rlocs>
# Usage: python lisp-add-mc.py help
#

import sys
import os

#------------------------------------------------------------------------------

path = os.getenv("LISPAPI_PATH")
if (path != None): sys.path.append(path)

try:
    import lispapi
except:
    print "'setenv LISPAPI_PATH' to locate path to lispapi.pyo"
    exit(1)
#endtry

#
# Asking for help or not enough command line arguments.
#
print_usage = False
print_usage = ("help" in sys.argv or len(sys.argv) < 3)
if (print_usage):
    print 'Usage: python lisp-add-mc.py "[<iid>]<eid-prefix>" <list-of-rlocs>'
    print 'Usage: python lisp-add-mc.py <eid-prefix> <list-of-rlocs>'
    print 'Usage: python lisp-add-mc.py help'
    exit(0)
#endif

#
# Get login parameters for remote system.
#
system = None
while (system == None):
    system = raw_input("Enter lispers.net system: ")
    if (system == ""): system = None
#endwhile
username = None
while (username == None):
    username = raw_input("Enter username for {}: ".format(system))
    if (username == ""): username = None
#endif
password = raw_input("Enter password for {}: ".format(system))

#
# Get command line arguments for lispapi.add_map_cache().
#
iid = "0"
eid = sys.argv[1]
rlocs = sys.argv[2::]

#
# Parse EID-prefix to see if instance-ID is passed in square brackets.
#
left_bracket = eid.find("[")
if (left_bracket != -1):
    right_bracket = eid.find("]")
    if (right_bracket == -1):
        print "Invalid EID-prefix format"
        exit(1)
    #endif
    iid = eid[left_bracket+1 : right_bracket]
    eid = eid[right_bracket+1::]
#endif

print "Connect to '{}' via lispers.net API ...".format(system),
sys.stdout.flush()

lisp = lispapi.api_init(system, username, password)
if (lisp.enable_status != None):
    print "success"
else:
    print "failed"
    exit(1)
#endif

print "Add [{}]{} to map-cache, RLOC-set: {} ...".format(iid, eid, rlocs)

#
# Add the entry.
#
status = lisp.add_itr_map_cache(iid, eid, "", rlocs)

#
# Return good or bad message and return.
#
print "{}".format("Succeeded" if status == "good" else "Failed")
exit(0)

#------------------------------------------------------------------------------

