# -----------------------------------------------------------------------------
#             
# Copyright 2013-2019 lispers.net - Dino Farinacci <farinacci@gmail.com>
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.    
# 
# -----------------------------------------------------------------------------
#
# lisp-depend.py
#
# This is a script that tells you what modules the lispers.net python code
# depends on.
# 
# -----------------------------------------------------------------------------

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
