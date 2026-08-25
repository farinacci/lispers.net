""" pytun (Python 3 port)

Tiny pure-Python tun/tap tunnel handler for Linux. Ported to Python 3.x
from Gawen Arab's original Python-2 module (MIT). Provides TunTunnel /
TapTunnel with .name, .fileno(), .write()/.send(), .read()/.recv().

Linux only: uses /dev/net/tun + TUNSETIFF ioctl. Requires root or
CAP_NET_ADMIN. Does nothing useful on macOS/BSD (utun is a different API).
"""

__author__ = "Gawen Arab (py3 port)"
__license__ = "MIT"
__version__ = "1.0.1-py3"

import os
import fcntl
import struct
import logging
import functools

TUN_KO_PATH = "/dev/net/tun"

logger = logging.getLogger("pytun")

class Tunnel(object):
    """ tun/tap handler class """

    class AlreadyOpened(Exception):
        pass

    class NotPermitted(Exception):
        pass

    MODES = {
        "tun": 0x0001,   # IFF_TUN
        "tap": 0x0002,   # IFF_TAP
    }

    IFF_NO_PI = 0x1000   # set to strip the 4-byte packet-info header

    # ioctl call (Linux)
    TUNSETIFF = 0x400454ca

    def __init__(self, mode=None, pattern=None, auto_open=None, no_pi=False):
        mode = mode if mode is not None else "tun"
        pattern = pattern if pattern is not None else ""
        auto_open = auto_open if auto_open is not None else True

        super(Tunnel, self).__init__()

        self.pattern = pattern
        self.mode = mode
        self.no_pi = no_pi

        self.name = None
        self.fd = None

        if isinstance(self.mode, str):
            self.mode = self.MODES.get(self.mode, None)
            assert self.mode is not None, "%r is not a valid tunnel type." % (mode,)

        if auto_open:
            self.open()

    def __del__(self):
        self.close()

    @property
    def mode_name(self):
        for name, ident in self.MODES.items():
            if ident == self.mode:
                return name

    def fileno(self):
        """ Makes this class select()/poll() compatible. """
        return self.fd

    def open(self):
        if self.fd is not None:
            raise self.AlreadyOpened()

        self.fd = os.open(TUN_KO_PATH, os.O_RDWR)

        flags = self.mode
        if self.no_pi:
            flags |= self.IFF_NO_PI

        pattern = self.pattern
        if isinstance(pattern, str):
            pattern = pattern.encode()

        try:
            ret = fcntl.ioctl(self.fd, self.TUNSETIFF,
                struct.pack("16sH", pattern, flags))
        except IOError as e:
            if e.errno == 1:
                self.close()
                raise self.NotPermitted()
            self.close()
            raise

        self.name = ret[:16].strip(b"\x00").decode()
        logger.info("Tunnel '%s' opened." % (self.name,))

    def close(self):
        if self.fd is None:
            return
        os.close(self.fd)
        self.fd = None

    def write(self, buf):
        """ Write a frame/packet to the tunnel. Returns bytes written. """
        return os.write(self.fd, buf)

    # lisp.py calls .write(); keep .send() as an alias for callers that
    # expect the original pytun API.
    send = write

    def read(self, size=1500):
        return os.read(self.fd, size)

    recv = read

    def __repr__(self):
        return "<%s tunnel '%s'>" % (self.mode_name.capitalize(), self.name)

class TunTunnel(Tunnel):
    """ tun (layer-3) handler class. """
    def __init__(self, *kargs, **kwargs):
        super(TunTunnel, self).__init__("tun", *kargs, **kwargs)

class TapTunnel(Tunnel):
    """ tap (layer-2) handler class. """
    def __init__(self, *kargs, **kwargs):
        super(TapTunnel, self).__init__("tap", *kargs, **kwargs)

tunnel = functools.partial(Tunnel, auto_open=True)
open = tunnel
