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
# make-release.py
#
# This python script will do a release of the lispers.net LISP code.
# 
# -----------------------------------------------------------------------------

import os
import commands
import sys
import time
import platform

#------------------------------------------------------------------------------

obfuscate_on = True
root = "./.."

#
# Check that pyflakes and pyobfuscate are installed.
#
pyflakes = commands.getoutput("pyflakes -h")
if (pyflakes.find("not found") != -1):
    print "Need to 'apt-get install pyflakes'"
    exit(1)
#endif    
pyobfuscate = commands.getoutput("pyobfuscate -h")
if (obfuscate_on and pyobfuscate.find("not found") != -1):
    print "Need pyobfuscate, turn off or install via at " + \
        "'https://github.com/astrand/pyobfuscate'"
    exit(1)
#endif    

#
# First check that this is running in the build directory and that peer
# directories "lisp" and "docs" exist.
#
curdir = commands.getoutput("pwd")
curdir = curdir.split("/")
if (curdir[-1] != "build"):
    print "Need to be in directory named 'build'"
    exit(1)
#endif
if (os.path.exists("../lisp") == False):
    print "Directory '../lisp' needs to be a peer directory"
    exit(1)
#endif
if (os.path.exists("../docs") == False):
    print "Directory '../docs' needs to be a peer directory"
    exit(1)
#endif

#
# Second check if we can build on this machine.
#
machine = platform.machine()
if (machine.find("x86") != -1):
    cpu = "x86"
elif (machine.find("mips") != -1):
    cpu = "mips"
else:
    print "Build does not support cpu type {}".format(machine)
    exit(1)
#endif

start_time = time.time()
build_date = commands.getoutput("date")

#
# Run pyflakes. We don't want to build a release with python errors.
#
print "Checking for python errors with pyflakes ... ", 
status = os.system("pyflakes {}/lisp/*py > /dev/null".format(root))
if (status != 0):
    print("found pyflakes errors")
    exit(1)
#endif
print("done")

#
# Check and ask if you want to build release with debug code in it.
#
print "Checking for any lisp.debug() calls ... ", 
command = ('egrep "debug\(" {}/lisp/*py | egrep -v "def|self|_debug" > ' + \
    '/dev/null').format(root)
status = os.system(command)
print("done")
if (status == 0):
    if (raw_input("Build release with debug code? (y/n): ") != "y"): exit(1)
#endif

if (len(sys.argv) > 1): 
    version = sys.argv[1]
else:
    version = raw_input("Enter version number (in format x.y): ")
#endif

dir = "releases/release-{}".format(version)
status = os.system("mkdir " + dir)
if (status != 0):
    print "Could not create directory {}".format(dir)
    exit(1)
#endif
os.system("rm latest; ln -sf {} latest".format(dir)) 

print "Copying files from ../lisp to " + dir + " build directory ...",
command = '''
cp ../lisp/lispapi.txt ../lisp/*py ../lisp/*-LISP ../lisp/RL-* ../lisp/*.pem.default ../build/release-notes.txt ../lisp/pslisp ../lisp/log-packets ../lisp/lispers.net-geo.html ./{}/.
'''.format(dir)

status = os.system(command)
if (status != 0):
    print "failed"
    exit(1)
#endif
print "done"

print "Copying install scripts to " + dir + " build directory ...",
command = "cp ./py-depend/lispers.net-test-install.py ./{}/.".format(dir)
status = os.system(command)
if (status != 0):
    print "failed"
    exit(1)
#endif
command = "cp ./py-depend/lispers.net-install-ubuntu.py ./{}/.".format(dir)
status = os.system(command)
if (status != 0):
    print "failed"
    exit(1)
#endif
print "done"

#
# Move *.py files to src directory. We will obfuscate the source files in
# the main release directory and then compile them.
#
os.system("mkdir {}/src; mv {}/*py {}/src/.".format(dir, dir, dir))

#
# Obfuscate the py files. They are put in directory ./ob.
#
if (obfuscate_on):
    py_files = commands.getoutput("cd {}/src; ls *py".format(dir)).split("\n")
    libraries = ["lisp.py", "lispconfig.py", "lispapi.py", "chacha.py",
        "poly1305.py"]
    print "Obfuscating py files ...",
    for py_file in py_files:
        dash_a = "-a" if py_file in libraries else ""
        os.system("pyobfuscate {} {}/src/{} > {}/{}".format(dash_a, dir, 
            py_file, dir, py_file))
    #endfor
    print "done"
else:
    os.system("cp {}/src/*py {}/.".format(dir, dir))
#endif

#
# Do the compile.
#
print "Compiling for machine '{}'".format(machine)
status = os.system("cd ./{}; python -O -m compileall *py".format(dir))
if (status != 0):
    print "Compilation failed"
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
# Make bin directory.
#
os.system("mkdir {}/bin".format(dir))

#
# First check if lisp-xtr has been previously built. If found and in Linux
# ELF format, then move to bin directory and *.go files to src directory.
#
lisp_xtr = ""
go_binary = "{}/lisp/lisp-xtr".format(root)
if (os.path.exists("{}".format(go_binary)) == False):
    print "Binary 'lisp-xtr' not found, not included in build"
elif (commands.getoutput("file {} | egrep ELF".format(go_binary)) == ""):
    print "Binary 'lisp-xtr' not in ELF format, not included in build"
else:
    print "Copying go files and go binary 'lisp-xtr*'  ... ", 
    os.system("cp {}/lisp/*.go {}/src/.".format(root, dir))
    os.system("cp {} {}/.".format(go_binary, dir))
    lisp_xtr = "lisp-xtr"
    if (os.path.exists("{}".format(go_binary + ".alpine"))):
        os.system("cp {} {}/.".format(go_binary + ".alpine", dir))
        lisp_xtr += " lisp-xtr.alpine"
    #endif
    print "done"
#endif

#
# Put the version and date file in the directory.
#
os.system('cd ./{}; echo "{}" > lisp-version.txt'.format(dir, version))
os.system('cd ./{}; echo "{}" > lisp-build-date.txt'.format(dir, build_date))
os.system('cp ../docs/lisp.config.example ./{}/.'.format(dir))
os.system('cp ../docs/how-to-install.txt ./{}/.'.format(dir))
os.system('cp ./py-depend/pip-requirements.txt ./{}/.'.format(dir))

#
# Now tar and gzip files for release. COPYFILE is so MacOs does not put in
# ._<foo> files.
#
tar_file = "lispers.net-" + cpu + "-release-" + version + ".tgz"
print "Build tgz file {} ... ".format(tar_file),
files = "*.pyo *.txt lisp.config.example lisp-cert.pem.default *-LISP " + \
    "RL-* pslisp log-packets lispers.net-geo.html {}".format( \
    lisp_xtr)
command = "cd {}; export COPYFILE_DISABLE=true; tar czf {} {}".format(dir,
    tar_file, files)
status = os.system(command)
if (status != 0):
    print "failed"
    exit(1)
#endif
print "done"

#
# Put go binary and pyo files in the bin/ directory.
#
os.system("mv {}/*pyo {}/bin/".format(dir, dir))
if (lisp_xtr != ""):
    os.system("mv {}/lisp-xtr* {}/bin/".format(dir, dir))
#endif

print "Copying version information to ../lisp directory ... ", 
command = '''
    cd ./{}; 
    cp lisp-version.txt ../../../lisp/.;
    cp lisp-build-date.txt ../../../lisp/.;
    chmod -R 555 *;
    chmod 444 lispers.net*tgz;
    ln -s lispers.net*tgz lispers.net.tgz;
    cd ../;
'''.format(dir)
status = os.system(command)
if (status != 0):
    print "failed"
    exit(1)
#endif
print "done"

elapsed = round(time.time() - start_time, 3)
print "Script run time: {} seconds".format(elapsed)
exit(0)

#------------------------------------------------------------------------------
