import importlib

modules = [ "bottle", "requests", "cherrypy", "pcappy", "netifaces", 
    "setuptools", "Crypto.Cipher", "OpenSSL", "curve25519", "geopy", "pytun",
    "ecdsa" ]

failed = []
for module in modules:
    try: importlib.import_module(module)
    except: failed.append(module)
#endfor

if (len(failed) == 0):
    print "Install complete"
else:
    print "Install NOT complete for {}".format(failed)
#endif
exit(0)
