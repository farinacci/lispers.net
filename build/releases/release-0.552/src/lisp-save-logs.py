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
# lisp-save-logs.py
#
# Before starting up the lisp-core.py process, save existing *.log files in
# current directory to a date/timestamped sub-directory.
# 
# -----------------------------------------------------------------------------

import os
import datetime
try:
    from commands import getoutput
except:
    from subprocess import getoutput
#entry    


#------------------------------------------------------------------------------

ts = datetime.datetime.now().strftime("%m-%d-%y-%H:%M:%S")
dirname = "logs." + ts
os.system("mkdir logs/{}".format(dirname))
os.system("mv ./logs/*.log " + "logs/" + dirname)

#
# Check to see if there are more than 10 logs.* directory. If so delete all
# of them so there is a max of 10.
#
files = getoutput("ls -dltr logs/logs.*")
files = files.split("\n")
file_count = len(files)
if (file_count > 10):
    for line in files:
        log_file = line.split(" ")
        os.system("sudo rm -fr {}".format(log_file[-1]))
        print("Removed old log directory {}".format(log_file[-1]))
        file_count -= 1
        if (file_count == 10): break
    #endfor
#endif

exit(0)
    
#------------------------------------------------------------------------------
