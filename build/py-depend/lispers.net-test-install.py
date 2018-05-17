import importlib
import commands

modules = [ "bottle", "requests", "cherrypy", "pcappy", "netifaces", 
    "setuptools", "Crypto.Cipher", "OpenSSL", "curve25519", "geopy", "pytun",
    "ecdsa" ]

failed = []
for module in modules:
    try: importlib.import_module(module)
    except: failed.append(module)
#endfor

#
# Check if pycrptodome is installed.
#
found = commands.getoutput("pip list | egrep pycryptodome")
if (found != ""): found = (found.find("pycryptodome") != -1)
if (found == False): failed.append("pycryptodome")

if (len(failed) == 0):
    print "Install complete"
else:
    print "Install NOT complete for {}".format(failed)
#endif

exit(0)
