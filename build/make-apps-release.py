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
# make-apps-release.py
#
# This python script will do a release of the lispers.net application code and
# the LISPAPI module.
#
# The build defaults to creating pyo files with Python version 2.7.x. If env
# variable in calling shell has LISPERS.NET_PYTHON3 defined, then Python
# version 3.8.x will be used to create pyc files that are renamed to pyo
# files.
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
import time
import platform
from builtins import input

#------------------------------------------------------------------------------

obfuscate_on = True

use_python3 = (os.getenv("LISPERS.NET_PYTHON3") != None)
PYTHON = "python3" if use_python3 else "python"
print("This build is using python {}".format("3.8" if use_python3 else "2.7"))

#------------------------------------------------------------------------------

#
# First check that this is running in the build directory and that peer
# directories "lisp" and "docs" exist.
#
curdir = getoutput("pwd")
curdir = curdir.split("/")
if (curdir[-1] != "build"):
    print("Need to be in directory named 'build'")
    exit(1)
#endif
if (os.path.exists("../lisp") == False):
    print("Directory '../lisp' needs to be a peer directory")
    exit(1)
#endif
if (os.path.exists("../docs") == False):
    print("Directory '../docs' needs to be a peer directory")
    exit(1)
#endif

start_time = time.time()
build_date = getoutput("date")

if (len(sys.argv) > 1): 
    version = sys.argv[1]
else:
    version = input("Enter version number (in format x.y): ")
#endif

dir = "releases/apps-release-{}".format(version)
status = os.system("mkdir " + dir)
if (status != 0):
    print("Could not create directory {}".format(dir))
    exit(1)
#endif

print("Copying files from ../apps to " + dir + " build directory ...", end=" ")
command = '''
cp ../lisp/lispapi.txt ../lisp/lispapi.py ../apps/*py ./{}/.
'''.format(dir)

status = os.system(command)
if (status != 0):
    print("failed")
    exit(1)
#endif
print("done")

#
# Move *.py files to src directory. We will obfuscate the source files in
# the main release directory and then compile them.
#
os.system("mkdir {}/src; mv {}/*py {}/src/.".format(dir, dir, dir))

#
# Obfuscate the py files. They are put in directory ./ob.
#
if (obfuscate_on):
    py_files = getoutput("cd {}/src; ls *py".format(dir)).split("\n")
    for py_file in py_files:
        print("Obfuscating {} ... ".format(py_file))
        dash_a = "-a" if (py_file == "lispapi.py") else ""
        os.system("pyobfuscate {} {}/src/{} > {}/{}".format(dash_a, dir, 
            py_file, dir, py_file))
    #endfor
else:
    os.system("cp {}/src/*py {}/.".format(dir, dir))
#endif

#
# Do the compile.
#
print("{} compiling".format(PYTHON))
status = os.system("cd ./{}; {} -O -m compileall *py".format(dir, PYTHON))
if (status != 0):
    print("Compilation failed")
    exit(1)
#endif

#
# Put obfuscated files in the ob/ directory.
#
if (obfuscate_on):
    os.system("mkdir {}/ob; mv {}/*py {}/ob/".format(dir, dir, dir))
else:
    os.system("rm -fr {}/*py".format(dir))
#endif

#
# Put the version and date file in the directory.
#
os.system('cp ../docs/how-to-use-apps.txt ./{}/.'.format(dir))

#
# Now tar and gzip files for release.
#
tar_file = "lispers.net" + "-apps-release-" + version + ".tgz"
print("Build tgz file {} ... ".format(tar_file), end=" ")
files = '''*.pyo *.txt'''
command = "cd {}; tar czf {} {}".format(dir, tar_file, files)
status = os.system(command)
if (status != 0):
    print("failed")
    exit(1)
#endif
print("done")

#
# Put pyo files in the bin/ directory.
#
os.system("mkdir {}/bin; mv {}/*pyo {}/bin/".format(dir, dir, dir))

elapsed = round(time.time() - start_time, 3)
print("Script run time: {} seconds".format(elapsed))
exit(0)

#------------------------------------------------------------------------------
