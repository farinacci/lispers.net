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
# make-provision-release.py
#
# This script takes a lispers.net tgz file and adds lisp.config.provision-xtr,
# provision.py and RL.provision-xtr files to it so the tgz can be provisioned
# for a particular instance-ID and mapping system.
#
# Usage: python make-provision-release.py [<release> <iid> <build-tag>]
#
# -----------------------------------------------------------------------------
from __future__ import print_function
import os
try:
    from commands import getoutput
except:
    from subprocess import getoutput
#endtry    
import sys
from builtins import input

#------------------------------------------------------------------------------

def bold(string):
    return("\033[1m" + string + "\033[0m")
#enddef

def green(string):
    return("\033[92m" + string + "\033[0m")
#enddef

#------------------------------------------------------------------------------

#
# First check that this is running in the build directory.
#
curdir = getoutput("pwd")
curdir = curdir.split("/")
if (curdir[-1] != "build"):
    print("Need to be in directory named 'build'")
    exit(1)
#endif
if (os.path.exists("./releases") == False):
    print("Directory './releases' needs to be in build directory")
    exit(1)
#endif

#
# Get input parameters.
#
if (len(sys.argv) == 4): 
    version = sys.argv[1]
    iid = sys.argv[2]
    tag = sys.argv[3]
else:
    version = input("Enter version number (in format x.y): ")
    iid = input("Enter LISP xTR instance-ID: ")
    tag = input("Enter tag to be part of tgz filename: ")
    print("")
#endif

release = "./releases/release-{}".format(version)
if (os.path.exists(release) == False):
    print("Could not find directory {}".format(release))
    exit(1)
#endif
tgz = "lispers.net-x86-release-{}.tgz".format(version)
tmp = "/tmp/{}".format(tgz)

#
# Make /tmp directory to untar release so we can combine provision files
# with a "provisioned release" tarball.
#
print("Adding provision files to release {} tarball files ...". \
      format(bold(version)), end=" "),
os.system("mkdir -p {}; cp {}/{} {}".format(tmp, release, tgz, tmp))
os.system("chmod 755 {}/{}".format(tmp, tgz))
os.system("cd {}; tar zxf {}; rm {}".format(tmp, tgz, tgz))
os.system("cp lisp.config.provision-xtr provision-lisp.py {}".format(tmp))
os.system("cp RL.provision-xtr {}/RL".format(tmp))
print("done")

#
# Don't need RL-template in this release since we customize the RL file for
# the instance-ID and MacOS device (or eth0 for docker).
#
print("Customize RL.provision-xtr file with provisioning parameters ...",
      end=" ")
f = open("{}/RL".format(tmp), "r"); buf = f.read(); f.close()
buf = buf.replace('set IID = "0"', 'set IID = "{}"'.format(iid))
f = open("{}/RL".format(tmp), "w"); f.write(buf); f.close()
os.system("rm {}/RL-template".format(tmp))
print("done")      

#
# Create new "provisioned release" tarball.
#
ptgz = "lispers.net-x86-release-{}-iid-{}-{}.tgz".format(version, iid, tag)
print("Creating provisioned tarball for release {}, instance-ID {} ...". \
      format(bold(version), bold(iid)), end= " ")
cmd = "cd {}; export COPYFILE_DISABLE=true; tar czf {} *".format(tmp, ptgz)
os.system(cmd)
print("done")      

#
# Copy to release directory where tarball of standard release resides.
#      
os.system("cp {}/{} {}/{}".format(tmp, ptgz, release, ptgz))
os.system("rm -fr {}".format(tmp))

#
# We are done. Tell user where it is.
#
print("New file {} written to {} directory".format(green(ptgz),
    bold("releases/release-{}".format(version))))
exit(0)

#------------------------------------------------------------------------------
