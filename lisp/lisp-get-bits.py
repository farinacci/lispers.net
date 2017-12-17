#
# lisp-get-bits
#
# Usage: python lisp-get-bits.pyo <url-for-lispers.net-image> [force]
#
# Do a wget on supplied URL and install in current directory.
#

import sys
import os

#
# Get parameter step.
#
if (len(sys.argv) == 1):
    print "Usage: python lisp-get-bits.pyo <url-for-lispers.net-image> [force]"
    exit(1)
#endif

#
# Check to see if wget is installed on the system.
#
if (os.system("which wget > /dev/null") != 0):
    print "wget not installed"
    exit(1)
#endif

force = ("force" in sys.argv)

url = sys.argv[1]
image = url.split("/")[-1]
index = image.find("tgz") + len("tgz")
image = image[0:index]

#
# Check if file exists, if so, ask user if they want to remove it.
#
if (force == False and os.path.exists(image)):
    line = "{} already exists, remove it? (y/n): ".format(image)
    if (raw_input(line) != "y"): exit(0)
    os.system("rm -fr {}".format(image))
#endif

#
# Download step.
#
print "Downloading {} ...".format(url)

if (os.system("wget -q {}".format(url)) != 0):
    print "Could not download image"
    exit(1)
#endif
os.system("mv file {}".format(image))

#
# Untar step.
#
if (force == False):
    yesno = raw_input("Do you want to install image? (y/n): ")
    if (yesno != "y"): exit(0)
#endif

print "Untaring {} ...".format(image)
if (os.system("tar zxvf {}".format(image)) != 0):
    print "Could not untar image"
    exit(1)
#endif

print "To restart the LISP subsystem, run './RESTART-LISP'"
exit(0)
