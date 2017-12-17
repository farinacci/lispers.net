#
# remove-lisp-locks.py
#
# This python script will remove an named socket file descriptors
#

import os
import commands

#------------------------------------------------------------------------------

files = commands.getoutput("ls lisp-* | egrep -v 'py|log|pem|txt|config'")

ipc_dp = "lisp-ipc-data-plane"
if (files != ""):
    print "Removed LISP file descriptors:",
    files = files.split("\n")

    if (ipc_dp in files): files.remove(ipc_dp)
    files.append("lispers.net-itr")
    print files
#endif

for f in files: 
    if (f == ""): continue
    os.system("rm -f {}".format(f))
#endfor

exit(0)

#------------------------------------------------------------------------------
