#!/usr/bin/python3
# -*- encoding: utf-8 -*-

"""
Poly1305-AES in python.

This is a PEP-compliant implementation of D.J. Berstein's Poly1305-Algorithm.
Some parts of the code are taken from Ken Raeburn's python implementation
from http://cr.yp.to/mac/poly1305aes.py.

"""

## Original release notes by Ken Raeburn:
##
##  # Hack implementation of DJB's Poly1305-AES MAC.
##  # Written 2005-01-18 by Ken Raeburn, and placed in the public domain.
##  # Apologies for the clunkiness, I'm still learning Python

import binascii
import sys
import warnings

PY3K = int(sys.version[0]) >= 3

try:
    from Crypto.Cipher import AES
except ImportError:
    pycrypto = False
else:
    pycrypto = True

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.algorithms import AES as AES_C
    from cryptography.hazmat.primitives.ciphers.modes import ECB
    from cryptography.hazmat.primitives.ciphers import Cipher
except ImportError:
    crypto = False
else:
    crypto = True

try:
    import M2Crypto
except ImportError:
    m2crypto = False
else:
    m2crypto = True


if pycrypto:
    def _aes_encrypt(key, val):
        "Encrypt one single data block with AES -- PyCrypto based"
        return AES.new(key, mode=AES.MODE_ECB).encrypt(val)
elif crypto:
    def _aes_encrypt(key, val):
        "Encrypt one single data block with AES -- cryptography based"
        e = Cipher(AES_C(key), ECB(), default_backend()).encryptor()
        return e.update(val)+e.finalize() 
elif m2crypto:
    def _aes_encrypt(key, val):
            "Encrypt one single data block with AES -- M2Crypto based"
            c = M2Crypto.EVP.Cipher(alg='aes_128_ecb', key=key, op=1)
            return c.update(val)+c.final()
else:
    warnings.warn("No AES libary found! Most functions won't work!",
                  ImportWarning)
    def _aes_encrypt(*args):
        "No crypto libary found!"
        raise NotImplementedError("No crypto libary found!")


import hmac
if hasattr(hmac, 'compare_digest'):
    def constant_time_compare(a,b):
        return hmac.compare_digest(a,b)
else:
    def constant_time_compare(a,b):
            if len(a) != len(b):
                return False
            result = 0
            if PY3K and isinstance(a, bytes) and isinstance(b, bytes):
                for x, y in zip(a, b):
                    result |= x ^ y
            else:
                for x, y in zip(a, b):
                    result |= ord(x) ^ ord(y)
            return result == 0

constant_time_compare.__doc__ = """
Returns True if the two strings are equal, False otherwise.
    
The time taken is independent of the number of characters that match.
For the sake of simplicity, this function executes in constant time only
when the two strings have the same length. It short-circuits when an error
occurs they have different lengths. Since Poly1305 MAC's have a constant
length, this is acceptable.

:param a: The first parameter
:type a: byte or ascii string
:param b: The second parameter
:type b: byte or ascii string
"""

def new(*args, **kwargs):
    """
    Returns a Poly1305-object with given parameters.

    See the Poly1305-class for details.
    """

class Poly1305:
    """
    The main class.

    :param key_aes: your cipher key, the length
        depends on your cipher (16, 24 or 32 for AES)
    :type key_aes: bytes
    
    :param r: your poly1305 key with a length of 16
    :type r: bytes
    
    :param nonce: your *random* nonce with a length of 16
    :type nonce: bytes
    
    :param string: the message you want to sign
    :type string: bytes

    :param method: the encryption method with the syntax encrypt(key, val).
        Defaults to AES from cryptography, pycypto or m2crypto.
    :type method: method with args (key, msg)
    """
    digest_size = 16
    
    def __init__(self, key_aes, r, nonce , string=b"", method=_aes_encrypt):
        self.__key_aes = key_aes
        self.__r = r
        self.__nonce = nonce
        self.__string = string
        self.__aes = method

    def update(self, msg):
        """
        Update the hmac object with msg.
        Repeated calls are equivalent to a single call with the concatenation
        of all the arguments: m.update(a); m.update(b) is equivalent
        to m.update(a + b).

        :type msg: bytes
        """
        
        self.__string += msg

    def digest(self):
        """
        Return the digest of the bytes passed to the update()
        method so far. This bytes object will be the same
        length of 16 constructor. It may contain non-ASCII bytes,
        including NUL bytes.
        """

        k, r, n, msg = (self.__key_aes, self.__r,
                        self.__nonce, self.__string)
        mod1305 = (1 << 130) - 5
        rval = str2num_littleend(r)
        q = (len(msg) + 15) / 16
        tot = 0
        for i in range(int(q)):
            sub = msg[i*16 : i*16+16] + b"\x01"
            sub += (17 - len(sub)) * b"\x00"
            num = str2num_littleend(sub)
            tot = (tot + num) * rval
        tot = tot % mod1305
        enc = self.__aes(k, n)
        enc = str2num_littleend(enc)
        result = (tot + enc) % (1 << 128)
        # Convert to a 16-byte string, little-endian order.
        result = ''.join(map(lambda i: chr(0xff & (result >> 8*i)), range(16)))
        if PY3K:
            result = result.encode("latin-1")
        
        return result

    def hexdigest(self):
        """
        Like digest() except the digest is returned as a string twice the
        length containing only hexadecimal digits. This may be used to
        exchange the value safely in email or other non-binary environments.
        """
        return binascii.hexlify(self.digest()).decode()

    def copy(self):
        """
        Return a copy (“clone”) of the Poly1305 object. This can be used to
        efficiently compute the digests of strings that share a common
        initial substring.

        .. warning::

            Using two Poly1305-objects with the same key & nonce is insecure.
            The nonce must only be used one time per key.
        """
        return Poly1305(self.__key_aes, self.__r,
                        self.__nonce, self.__string,
                        self.__aes)


def poly1305aes(k, r, n, m):
    """\
    Poly1305-AES computation function.
    This function grants interoperability with the old version
    which was written by Ken Raeburn.

    :param k: your cipher key, the length depends on your cipher
    :type k: bytes
    
    :param r: your poly1305 key with a length of 16
    :type r: bytes
    
    :param n: your *random* nonce with a length of 16
    :type n: bytes
    
    :param m: the message you want to sign
    :type m: bytes

    
    """
    return Poly1305(k, r, n, m, _aes_encrypt).digest()


####################################

def str2num_littleend(val):
    "Helper function to make a byte string to a number (int or long)."
    return int(binascii.hexlify(val[::-1]), 16)

if sys.version[0] == "3":
    def hexify(s):
        b = []
        for i in s: # bytes...
            if type(i) == int:
                i = chr(i).encode()
            elif type(i) == bytes:
                pass
            elif type(i) == str:
                i = i.encode()
            b.append(i)
        return b' '.join(map(binascii.hexlify, b))
elif sys.version[0] == "2":
    def hexify(s):
        return b" ".join(map(binascii.hexlify, s))

hexify.__doc__ = ("Helper function to turn a binary "
                  "string into a human readable hex-encoded "
                  "form.")

####################################
