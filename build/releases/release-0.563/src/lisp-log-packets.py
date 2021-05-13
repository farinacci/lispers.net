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
# lisp-log-packets.py
#
# Set the following commands in the local system:
# 
# lisp debug {
#     itr = yes
#     etr = yes
# }
# lisp xtr-parameters {
#     data-plane-logging = yes
# }
#
# By using the lispapi. The command will toggle the setting. When environment
# variable LISP_PW is set, the value is the password that is used to connect.
# to the LISP API.
#
# Usage: python lisp-log-packets.py [force] [<api-port>] [help]
#
# Note when <api-port> is negative, it is passed into the lispapi to tell it
# to use http versus https. This port number should be the same value as
# passed on the ./RESTART-LISP command.
#
#------------------------------------------------------------------------------
from __future__ import print_function
import lispapi
import sys
import os

#
# Get command-line parameters.
#
force = True
api_port = 8080
for arg in sys.argv[1::]:
    if (arg == "help"):
        print("Usage: python log-packets.py [force] [<api-port>] [help]")
        exit(0)
    #endif
    if (arg == "force"): force = True
    if (arg.isdigit()): api_port = int(arg)
    if (arg[0] == "-" and arg[1::].isdigit()): api_port = -int(arg[1::])
#endfor

#
# Get user supplied password, if any.
#
pw = os.getenv("LISP_PW")
if (pw == None): pw = ""

#
# Open API to localhost. If debug status dict array None, the open failed.
#
lisp = lispapi.api_init("localhost", "root", pw, port=api_port)
if (lisp.debug_status == None):
    print ("Could not connect to API, is lispers.net running?, " + \
        "LISP_PW set?, or using the correct port number?")
    exit(1)
#endif

#
# Get current settings for control-plane.
#
itr = lisp.is_itr_debug_enabled()
etr = lisp.is_etr_debug_enabled()
rtr = lisp.is_rtr_debug_enabled()

#
# Get current settings for data-plane logging.
#
xtr_parms = lisp.get_xtr_parameters()
if (xtr_parms == None):
    print("Could not get xtr-parameters from API")
    exit(1)
#endif

dp_logging = xtr_parms["data-plane-logging"] == "yes"
rtr_running = lisp.is_rtr_enabled()

if (dp_logging):
    lisp.disable_xtr_data_plane_logging()
    lisp.disable_itr_debug()
    lisp.disable_etr_debug()
    if (rtr_running): lisp.disable_rtr_debug()
    print("Data-plane logging has been disabled")
else:
    if (rtr_running):
        if (rtr and force == False):
            print("Control-plane logging is enabled, no action taken")
            exit(0)
        #endif
        lisp.enable_rtr_debug()
    else:
        if ((itr or etr) and force == False):
            print("Control-plane logging is enabled, no action taken")
            exit(0)
        #endif
        lisp.enable_itr_debug()
        lisp.enable_etr_debug()
    #endif
    lisp.enable_xtr_data_plane_logging()
    print("Data-plane logging has been enabled")
#endif

exit(0)

#------------------------------------------------------------------------------
