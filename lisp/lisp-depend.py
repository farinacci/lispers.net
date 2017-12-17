#
# lisp-depend.py
#
# This is a script that tells you what modules the lispers.net python code
# depends on.
#
import platform

version = platform.python_version_tuple()
if (version[0] != "2" or version[1] != "7"):
    print "lispers.net code depends on python version 2.7.x"
    exit(1)
#endif

dependencies = [
    "binascii", 
    "bottle",
    "cherrypy",
    "commands",
    "datetime",
    "hashlib",
    "hmac",
    "json",
    "lisp",
    "lispapi",
    "lispconfig",
    "multiprocessing",
    "netifaces",
    "operator",
    "os",
    "pcappy",
    "platform",
    "Queue",
    "random",
    "requests",
    "select",
    "socket",
    "ssl",
    "struct",
    "subprocess",
    "sys",
    "threading",
    "time",
    "traceback",
    "Crypto.Cipher",
]

print "Printing dependencies:"

good = 0
bad = 0
for module in dependencies:
    module_str = "Import {} ...".format(module).ljust(30)
    try:
        __import__(module)
        print "{} {}".format(module_str, "good")
        good += 1
    except:
        print "{} {}".format(module, "not on system")
        bad += 1
    #endtry
#endfor

print "\n{} good imports, {} bad imports".format(good, bad)
exit(0)
