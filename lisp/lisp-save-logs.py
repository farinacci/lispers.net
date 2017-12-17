#
# lisp-save-logs.py
#
# Before starting up the lisp-core.py process, save existing *.log files in
# current directory to a date/timestamped sub-directory.
#

import os
import datetime
import commands

#------------------------------------------------------------------------------

ts = datetime.datetime.now().strftime("%m-%d-%y-%H:%M:%S")
dirname = "logs." + ts
os.system("mkdir {}".format(dirname))
os.system("mv ./logs/*.log " + dirname)

#
# Check to see if there are more than 10 logs.* directory. If so delete all
# of them so there is a max of 10.
#
files = commands.getoutput("ls -dltr logs.*")
files = files.split("\n")
file_count = len(files)
if (file_count > 10):
    for line in files:
        log_file = line.split(" ")
        os.system("sudo rm -fr {}".format(log_file[-1]))
        print "Removed old log directory {}".format(log_file[-1])
        file_count -= 1
        if (file_count == 10): break
    #endfor
#endif

exit(0)
    
#------------------------------------------------------------------------------
