"""Classes to represent Packet Filter Tables."""

from socket import *
from ctypes import *
import re

from PF.PFConstants import *
from PF._PFStruct import *
from PF.PFUtils import *


__all__ = ['PFTableAddr',
           'PFTable']


# PFTableAddr class ############################################################
class PFTableAddr:
    """Represents an address in a PF table."""

    def __init__(self, addr=None, **kw):
        """Check argument and initialize class attributes."""
        if isinstance(addr, pfr_addr):
            self._from_struct(addr)
        elif isinstance(addr, basestring):
            self._from_string(addr)
        elif addr is None:
            self._from_struct(pfr_addr())
        else:
            raise TypeError, "'addr' must be a pfr_addr structure or a string"

        self._from_kw(**kw)

    def _from_struct(self, a):
        """Initialize class attributes from a pfr_addr structure"""
        l = {AF_INET: 4, AF_INET6: 16}[a.pfra_af]

        self.af    = a.pfra_af
        self.addr  = inet_ntop(self.af, string_at(addressof(a.pfra_u), l))
        self.mask  = ctonm(a.pfra_net, self.af)
        self.neg   = bool(a.pfra_not)
        self.fback = a.pfra_fback

    def _from_string(self, a):
        """Initalize a new instance from a string."""
        addr_re = "(?P<neg>!)?\s*"                      + \
                  "(?P<address>(?P<ipv4>[0-9.]+)|"      + \
                              "(?P<ipv6>[0-9a-f:]+))"    + \
                              "(?:/(?P<mask>\d+))?\s*"

        m = re.compile(addr_re).match(a)
        if not m:
            raise ValueError, "Could not parse address: '%s'" % a

        self.neg = bool(m.group("neg"))

        if m.group("ipv4"):
            self.af = AF_INET
            self.addr = m.group("ipv4")
        elif m.group("ipv6"):
            self.af = AF_INET6
            self.addr = m.group("ipv6")

        net = m.group("mask") or {AF_INET: 32, AF_INET6: 128}[self.af]
        self.mask = ctonm(int(net), self.af)

        self.fback = 0

    def _from_kw(self, **kw):
        """Initalize a new instance by specifying its attributes values."""
        for k, v in kw.iteritems():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                raise TypeError, "Unexpected keyword argument '%s'" % k

    def _to_struct(self):
        """Convert this instance to a pfr_addr structure."""
        a = pfr_addr()

        addr = inet_pton(self.af, self.addr)
        memmove(a.pfra_ip6addr, c_char_p(addr), len(addr))

        a.pfra_af    = self.af
        a.pfra_net   = nmtoc(self.mask, self.af)
        a.pfra_not   = int(self.neg)
        a.pfra_fback = self.fback

        return a

    def _to_string(self):
        """Return the string representation of the address."""
        s = ""

        if self.neg:
            s += "! "

        s += self.addr

        bits = nmtoc(self.mask, self.af)
        if not ((self.af == AF_INET and bits == 32) or (bits == 128)):
            s += "/%i" % bits

        return s

    def __str__(self):
        return self._to_string()


# PFTable class ################################################################
class PFTable:
    """Represents a PF table."""

    def __init__(self, table=None, **kw):
        """Check argument and initialize class attributes."""
        if isinstance(table, pfr_table):
            self._from_struct(table)
        elif isinstance(table, basestring):
            self._from_struct(pfr_table())
            self.name = table
        elif table is None:
            self._from_struct(pfr_table())
        else:
            raise TypeError, "'table' must be a pfr_table structure or a string"

        self._from_kw(**kw)

    def _from_struct(self, t):
        """Initialize class attributes from a pfr_table structure"""
        self.anchor = t.pfrt_anchor
        self.name   = t.pfrt_name
        self.flags  = t.pfrt_flags
        self.fback  = t.pfrt_fback

    def _from_kw(self, **kw):
        """Initalize a new instance by specifying its attributes values."""
        for k, v in kw.iteritems():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                raise TypeError, "Unexpected keyword argument '%s'" % k

    def _to_struct(self):
        """Convert this instance to a pfr_table structure."""
        t = pfr_table()

        t.pfrt_anchor = self.anchor
        t.pfrt_name   = self.name
        t.pfrt_flags  = self.flags
        t.pfrt_fback  = self.fback

        return t

    def _to_string(self):
        """Return the string representation of the table."""
        s  = ('c' if (self.flags & PFR_TFLAG_CONST) else '-')
        s += ('p' if (self.flags & PFR_TFLAG_PERSIST) else '-')
        s += ('a' if (self.flags & PFR_TFLAG_ACTIVE) else '-')
        s += ('i' if (self.flags & PFR_TFLAG_INACTIVE) else '-')
        s += ('r' if (self.flags & PFR_TFLAG_REFERENCED) else '-')
        s += ('h' if (self.flags & PFR_TFLAG_REFDANCHOR) else '-')
        s += ('C' if (self.flags & PFR_TFLAG_COUNTERS) else '-')
        s += " %s" % self.name

        return s

    def __str__(self):
        return self._to_string()
