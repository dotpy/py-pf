"""Classes to represent Packet Filter Tables."""

import re
import time
from socket import *
from ctypes import *

from pf.constants import *
from pf._struct import *
from pf._base import PFObject
from pf._utils import ctonm, nmtoc


__all__ = ['PFTableAddr',
           'PFTable',
           'PFTStats']


class PFTableAddr(PFObject):
    """Represents an address in a PF table."""

    _struct_type = pfr_addr

    def __init__(self, addr=None, **kw):
        """Check argument and initialize class attributes."""
        if addr is None:
            addr = pfr_addr()

        super(PFTableAddr, self).__init__(addr, **kw)

    def _from_struct(self, a):
        """Initialize class attributes from a pfr_addr structure."""
        l = {AF_INET: 4, AF_INET6: 16}[a.pfra_af]

        self.af     = a.pfra_af
        self.addr   = inet_ntop(self.af, string_at(addressof(a.pfra_u), l))
        self.mask   = ctonm(a.pfra_net, self.af)
        self.neg    = bool(a.pfra_not)
        self.fback  = a.pfra_fback
        self.ifname = a.pfra_ifname
        self.type   = a.pfra_type
        self.states = a.pfra_states
        self.weight = a.pfra_weight

    def _from_string(self, a):
        """Initalize a new instance from a string."""
        addr_re = "(?P<neg>!)?\s*"                      + \
                  "(?P<address>(?P<ipv4>[0-9.]+)|"      + \
                              "(?P<ipv6>[0-9a-f:]+))"   + \
                              "(?:/(?P<mask>\d+))?\s*"

        m = re.compile(addr_re).match(a)
        if not m:
            raise ValueError("Could not parse address: '{}'".format(a))

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
        self.ifname = ""               # ?
        self.type   = PFRKE_PLAIN      # ?
        self.states = 0
        self.weight = 0

    def _to_struct(self):
        """Convert this instance to a pfr_addr structure."""
        a = pfr_addr()

        addr = inet_pton(self.af, self.addr)
        memmove(a.pfra_ip6addr, c_char_p(addr), len(addr))

        a.pfra_af     = self.af
        a.pfra_net    = nmtoc(self.mask, self.af)
        a.pfra_not    = int(self.neg)
        a.pfra_fback  = self.fback
        a.pfra_ifname = self.ifname
        a.pfra_type   = self.type

        return a

    def _to_string(self):
        """Return the string representation of the address."""
        s = ("! {!s}" if self.neg else "{!s}").format(self.addr)
        bits = nmtoc(self.mask, self.af)
        if not ((self.af == AF_INET and bits == 32) or (bits == 128)):
            s += "/{}".format(bits)

        return s


class PFTable(PFObject):
    """Represents a PF table."""

    _struct_type = pfr_table

    def __init__(self, table=None, *addrs, **kw):
        """Check argument and initialize class attributes."""
        if table is None:
            table = pfr_table()
        elif isinstance(table, basestring):
            table = pfr_table(pfrt_name=table)

        self._addrs = []
        for addr in addrs:
            if not isinstance(addr, PFTableAddr):
                addr = PFTableAddr(addr)
            self._addrs.append(addr)

        super(PFTable, self).__init__(table, **kw)

    @property
    def addrs(self):
        """Return a tuple containing the address in the table."""
        return tuple(self._addrs)

    def _from_struct(self, t):
        """Initialize class attributes from a pfr_table structure"""
        self.anchor = t.pfrt_anchor
        self.name   = t.pfrt_name
        self.flags  = t.pfrt_flags
        self.fback  = t.pfrt_fback

    def _to_struct(self):
        """Convert this instance to a pfr_table structure."""
        t = pfr_table()

        t.pfrt_anchor = self.anchor
        t.pfrt_name   = self.name
        t.pfrt_flags  = self.flags & (PFR_TFLAG_CONST|PFR_TFLAG_PERSIST)
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
        s += "\t{.name}".format(self)

        if self.anchor:
            s += "\t{.anchor}".format(self)

        return s


class PFTStats(PFObject):
    """Class containing statistics for a PF table."""

    _struct_type = pfr_tstats

    def __init__(self, tstats):
        """Initialize class attributes."""
        super(PFTStats, self).__init__(tstats)

    def _from_struct(self, s):
        """Initialize class attributes from a pfr_tstats structure."""
        self.table   = PFTable(s.pfrts_t)
        self.packets = {"in":  tuple(s.pfrts_packets[PFR_DIR_IN]),
                        "out": tuple(s.pfrts_packets[PFR_DIR_OUT])}
        self.bytes   = {"in":  tuple(s.pfrts_bytes[PFR_DIR_IN]),
                        "out": tuple(s.pfrts_bytes[PFR_DIR_OUT])}
        self.cleared = s.pfrts_tzero
        self.cnt     = s.pfrts_cnt
        self.evalcnt = {"match":   s.pfrts_match,
                        "nomatch": s.pfrts_nomatch}
        self.refcnt  = {"rules":   s.pfrts_refcnt[PFR_REFCNT_RULE],
                        "anchors": s.pfrts_refcnt[PFR_REFCNT_ANCHOR]}

    def _to_string(self):
        """Return the string representation of the table statistics."""
        s  = "{.table}\n".format(self)
        s += "\tAddresses:   {.cnt:d}\n".format(self)
        s += "\tCleared:     {}\n".format(time.ctime(self.cleared))
        s += "\tReferences:  [ Anchors: {anchors:<18d} Rules: {rules:<18d} ]\n"
        s += "\tEvaluations: [ NoMatch: {nomatch:<18d} Match: {match:<18d} ]\n"
        s = s.format(**dict(self.refcnt, **self.evalcnt))

        pfr_ops = ("Block:", "Pass:", "XPass:")
        for o, p, b in zip(pfr_ops, self.packets["in"], self.bytes["in"]):
            l = "\tIn/{:<6s}    [ Packets: {:<18d} Bytes: {:<18d} ]\n"
            s += l.format(o, p, b)
        for o, p, b in zip(pfr_ops, self.packets["out"], self.bytes["out"]):
            l = "\tOut/{:<6s}   [ Packets: {:<18d} Bytes: {:<18d} ]\n"
            s += l.format(o, p, b)

        return s.rstrip()
