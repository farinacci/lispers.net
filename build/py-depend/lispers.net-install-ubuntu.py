#------------------------------------------------------------------------------
#
# lispers.net-install-ubuntu.py
#
# First-time install script to install py dependencies the lispers.net code
# needs. This is a script that automates the steps in how-to-install.txt.
#
# This script assumes that the lispers.net release tarball is untar'ed 
# in the current directory.
#
# Usage: python -O lispers.net-install-ubuntu.pyo
#
#------------------------------------------------------------------------------

import os

#
# We are going to install libssl. We always do.
#
print "Running 'sudo apt-get install libssl-dev' ..." 
os.system("sudo apt-get install libssl-dev")

#
# We need psmisc so ./STOP-LISP can call killall.
#
print "Running 'sudo apt-get install psmisc' ..." 
os.system("sudo apt-get install psmisc")

#
# We need this to get Python.h for C code.
#
print "Running 'sudo apt-get install python2.7-dev' ..." 
os.system("sudo apt-get install python2.7-dev")

#
# My startup scripts prefer tcsh.
#
print "Running 'sudo apt-get install tcsh' ..." 
os.system("sudo apt-get install tcsh")

#
# "pip install" does all the real python dependency work but the system needs
# to have pip.
#
print "Running 'sudo python get-pip.py' ..." 
os.system("sudo python get-pip.py")

#
# Do the heavy lifting.
#
print "Running 'sudo pip install' ..." 
os.system("sudo pip install -r pip-requirements.txt " + \
    "--allow-external pcappy --allow-unverified pcappy")

#
# Now test to see that everything lispers.net needs is installed.
#
print "Now run 'python lispers.net-test-install.pyo' to verify install"
exit(0)

#------------------------------------------------------------------------------
