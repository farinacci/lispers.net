#!/usr/bin/env python
#
# is-lisp-running.py
#
# This script checks to see if there is any LISP processes running on the
# local system.
#
# Usage: python -O is-lisp-running.pyo
#
#------------------------------------------------------------------------------

import commands
import lispapi

def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef

#
# Add title.
#
version = commands.getoutput("cat lisp-version.txt")
lisp = lispapi.api_init("localhost", "root", "")
rv = lisp.get_system()
if (rv != None and rv.has_key("lisp-version")):
    rv = ", release {} running".format(bold(rv["lisp-version"]))
#endif

#
# Get data.
#
command = "ps auxww | egrep 'lisp-' | egrep -v grep | " + \
   "egrep -v is-lisp-running | egrep -v tee | egrep -v pslisp"
output = commands.getoutput(command)
if (output == None or output == ""):
    print "No lispers.net code running, release {} installed".format(version)
    exit(0)
#endif
if (rv == None): rv = ""

print "--- lispers.net release {} installed{} ---".format(bold(version), rv)

#
# Format title.
#
pid = "PID".ljust(8)
cpu = "%CPU".ljust(8)
mem = "%MEM".ljust(8)
process = "Process"
print "{}{}{}{}".format(pid, cpu, mem, process)

#
# Run through each line.
#
lines = output.split("\n")
for line in lines:
    items = line.split()
    pid = items[1].ljust(8)
    cpu = items[2].ljust(8)
    mem = items[3].ljust(8)
    process = " ".join(items[10::])
    print "{}{}{}{}".format(pid, cpu, mem, process)
#endfor
exit(0)
