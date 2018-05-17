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
import os

def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef

#
# Add title.
#
version = commands.getoutput("cat lisp-version.txt")
rv = commands.getoutput("head -1 logs/lisp-core.log")
if (rv.find("version") != -1):
    rv = rv.split("version ")[1]
    rv = rv.split(",")[0]
    rv = ", release {} running".format(bold(rv))
else:
    rv = None
#endif

#
# Get data.
#
command = "ps auxww | egrep 'lisp-' |" + \
    "egrep -v 'grep|is-lisp-running|tee|pslisp|sudo|log'"
output = commands.getoutput(command)
if (output == None or output == ""):
    print "No lispers.net code running, release {} installed".format(version)
    exit(0)
#endif
if (rv == None): rv = ""

print "--- lispers.net release {} installed{} ---".format(bold(version), rv)

lines = output.split("\n")

#
# Special case Alpine Linux. It has different ps output.
#
if (os.path.exists("/etc/alpine-release")):
    pid = "PID".ljust(8)
    cpu = "TIME".ljust(8)
    process = "Process"
    print "{}{}{}".format(pid, cpu, process)
    for line in lines:
        items = line.split()
        pid = items[0].ljust(8)
        cpu = items[2].ljust(8)
        process = items[-1]
        if (process.isdigit()): process = items[-2] + " " + process
        print "{}{}{}".format(pid, cpu, process)
    #endfor
    exit(0)
#endif

#
# All other Linux variants.
#
pid = "PID".ljust(8)
cpu = "%CPU".ljust(8)
mem = "%MEM".ljust(8)
process = "Process"
print "{}{}{}{}".format(pid, cpu, mem, process)

for line in lines:
    items = line.split()
    pid = items[1].ljust(8)
    cpu = items[2].ljust(8)
    mem = items[3].ljust(8)
    process = " ".join(items[10::])
    print "{}{}{}{}".format(pid, cpu, mem, process)
#endfor
exit(0)
