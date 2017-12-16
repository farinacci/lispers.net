#
# lisp-onoff.py
#
# This script will toggle "yes" or "no" valued configuration file item. What
# are supported are "lisp enable", "lisp debug", and "lisp xtr-parameters"
# sub-commands.
#
# This script will prompt for system, username, and password.
#
# Usage: python -O lisp-onoff.pyo [<command-name> [yes | no]]
#
#------------------------------------------------------------------------------

import sys
import os

#------------------------------------------------------------------------------

#
# set_command
#
# Build API function name and call it to set desired parameter.
#
def set_command(lisp, command, yn):
    translate = { "map-resolver" : "mr", "map-server" : "ms", 
        "ddt-node" : "ddt" }

    debug = False
    index = command.find("debug-")
    if (index != -1):
        command = command[len("debug-")::]
        debug = True
    #endif

    call = "enable_" if yn == "yes" else "disable_"
    if (command in translate): command = translate[command]

    #
    # debug APIs.
    #
    if (debug):
        func = getattr(lisp, call + command + "_debug")
        return(func())
    #endif

    #
    # enable APIs.
    #
    if (command in lisp.enable_status):
        func = getattr(lisp, call + command)
        return(func())
    #endif

    #
    # xtr-parameters APIs.
    #
    if (command in lisp.xtr_parameters):
        if (command == "data-plane-security"):
            command = "itr_security"
        elif (command == "nat-traversal"):
            command = "xtr_nat_traversal"
        elif (command == "rloc-probing"):
            command = "xtr_rloc_probing"
        elif (command == "nonce-echoing"):
            command = "xtr_nonce_echoing"
        elif (command == "data-plane-logging"):
            command = "xtr_data_plane_logging"
        elif (command == "flow-logging"):
            command = "xtr_flow_logging"
        else:
            return(False)
        #endif
        func = getattr(lisp, call + command)
        return(func())
    #endif
    return(False)
#enddef

#
# print_valid_commands
#
# Print list of commands that can be set via the lispapi API.
#
def print_valid_commands(lisp):
    for command in lisp.enable_status:
        print "  {}".format(command)
    #endfor
    for command in lisp.debug_status:
        print "  debug-{}".format(command)
    #endfor
    for command in lisp.xtr_parameters:
        print "  {}".format(command)
    #endfor
#enddef

#
# print_pretty
#
# Print dictionary array in lispers.net configuration file format.
#
def print_pretty(data):
    for item in data:
        yesno = data[item]
        if (yesno == "yes"): yesno = green(yesno)
        if (yesno == "no"): yesno = red(yesno)
        print "  {} = {}".format(item, yesno)
    #endfor
#enddef

#
# bold
#
# Boldface supplied string.
#
def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef

#
# green
#
# For printing banner.
#
def green(string):
    return("\033[92m" + string + "\033[0m")
#enddef

#
# red
#
# For printing banner.
#
def red(string):
    return("\033[91m" + string + "\033[0m")
#enddef

#------------------------------------------------------------------------------

path = os.getenv("LISPAPI_PATH")
if (path != None): sys.path.append(path)

try:
    import lispapi
except:
    if (os.path.exists("lispapi.pyo")):
        print "Try command 'python -O lisp-onoff.pyo'"
    else:
        print "Cannot find lispapi module, use LISPAPI_PATH env variable"
    #endif
    exit(1)
#endtry

#
# Check for help string.
#
if ("help" in sys.argv):
    print "Usage: python -O lisp-onoff.pyo [<command-name> [yes | no]]"
    exit(0)
#endif

#
# Check if environment variables with username and password are stored.
#
system = os.getenv("LISPAPI_SYSTEM")
username = os.getenv("LISPAPI_USER")
password = os.getenv("LISPAPI_PW")
command = None

#
# This is a convienence item. Check to see if we are running in a directory
# locally that has the lispers.net code installed. If so, use system 
# 'localhost' and username 'root' with no password.
#
if (system == None and os.path.exists("RESTART-LISP")):
    system = "localhost"
    username = "root"
    password = ""
#endif

#
# If environment variables not selected, prompt.
#
while (system == None):
    system = raw_input("Enter lispers.net system: ")
    if (system == ""): system = None
#endwhile
while (username == None):
    username = raw_input("Enter username for {}: ".format(system))
    if (username == ""): username = None
#endif
while (password == None):
    password = raw_input("Enter password for {}: ".format(system))
    if (password == ""): password = None
#endif

print "Connecting to {} ...".format(bold(system)),
sys.stdout.flush()
lisp = lispapi.api_init(system, username, password)
if (lisp == None or lisp.enable_status == None): 
    print "failed"
    exit(1)
#endif
print "connected"
print ""

#
# Check if we setting a command value.
# 
command = sys.argv[1] if (len(sys.argv) >= 2) else None
yn = sys.argv[2] if (len(sys.argv) == 3) else None
if (yn):
    if (yn in ["yes", "y"]): 
        yn = "yes"
    elif (yn in ["no", "n"]):
        yn = "no"
    else:
        yn = None
    #endif
#endif

if (command):
    test_command = command
    index = command.find("debug-")
    if (index != -1): test_command = command[len("debug-")::]

    commands = lisp.enable_status.keys() + lisp.debug_status.keys() + \
        lisp.xtr_parameters.keys()
    if (test_command not in commands):
        print "Invalid command '{}', valid commands are:".format(command)
        print_valid_commands(lisp)
        exit(1)
    #endif

    while (yn == None):
        yn = "Enter 'y' to enable or 'n' to disable '{}': ".format(command)
        yn = raw_input(yn)
        yn = "yes" if yn == "y" else "no" if yn == "n" else None
    #endwhile

    command_string = bold("'{} = {}'".format(command, yn))
    doit = raw_input("Confirm to set {}, y/n: ".format(command_string))
    if (doit != "y"): exit(0)

    print ""
    print "Sending command '{} = {}' ...".format(command, yn),

    #
    # Call the API.
    #
    good = set_command(lisp, command, yn)
    if (good == False): print bold("failed")
    print bold("done")
    print ""
#endif

print "lisp enable {",
sys.stdout.flush()
lisp.get_enable()
print ""
print_pretty(lisp.enable_status)
print "}"

print "lisp debug {",
sys.stdout.flush()
lisp.get_debug()
print ""
print_pretty(lisp.debug_status)
print "}"

print "lisp xtr-parameters {",
sys.stdout.flush()
lisp.get_xtr_parameters()
print ""
print_pretty(lisp.xtr_parameters)
print "}"

exit(0)

#------------------------------------------------------------------------------
