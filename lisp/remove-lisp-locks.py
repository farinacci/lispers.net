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
# remove-lisp-locks.py
#
# This python script will remove an named socket file descriptors
# 
# -----------------------------------------------------------------------------

import os
import commands

#------------------------------------------------------------------------------

command = "ls lisp-* | egrep -v 'py|log|pem|txt|config' | " + \
    "egrep -v lisp-xtr | egrep -v lisp-ztr"

files = commands.getoutput(command)

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
