"""Classes to represent Packet Filter Rules."""


from socket import *
from ctypes import *

from _PFStruct import *
from PFConstants import *
from PFUtils import *


__all__ = ['PFRuleAddr']


# Dictionaries for mapping strings to constants ################################
pf_port_ops = {"":      PF_OP_NONE,
               "><":    PF_OP_IRG,
               "<>":    PF_OP_XRG,
               "=":     PF_OP_EQ,
               "!=":    PF_OP_NE,
               "<":     PF_OP_LT,
               "<=":    PF_OP_LE,
               ">":     PF_OP_GT,
               ">=":    PF_OP_GE,
               ":":     PF_OP_RRG}

afs         = {"inet":  AF_INET,
               "inet6": AF_INET6}


# PFRuleAddr class #############################################################
class PFRuleAddr:
    """Class representing an address/port pair."""

    def __init__(self, addr=None, af=0, proto=IPPROTO_TCP, **kw):
        """Check arguments and initialize instance attributes."""
        if af in (0, AF_INET, AF_INET6):
            self.af = af
        elif af in ("inet", "inet6"):
            self.af = afs[af]
        elif isinstance(af, (int, str)):
            raise ValueError, "Not a valid address family: '%s'" % af
        else:
            raise TypeError, "'af' must be an integer or a string"

        if isinstance(addr, pf_rule_addr):
            self._from_struct(addr)
        elif isinstance(addr, str):
            self._from_string(addr)
        elif addr is None:
            self._from_struct(pf_rule_addr())
        else:
            raise TypeError, "'addr' must be a pf_rule_addr or a string"

        if isinstance(proto, int):
            self.proto = proto
        elif isinstance(proto, str):
            try:
                self.proto = getprotobyname(proto)
            except:
                raise ValueError, "Not a valid protocol: '%s'" % proto
        else:
            raise TypeError, "'proto' must be an integer or a string"

        if kw:
            self._from_kw(**kw)

    def _from_struct(self, a):
        """Initalize a new instance from a pf_rule_addr structure."""
        self.type = a.addr.type
        self.iflags = a.addr.iflags
        self.neg = bool(a.neg)

        if self.type == PF_ADDR_DYNIFTL:
            self.ifname = a.addr.v.ifname
            self.dyncnt = a.addr.p.dyncnt
        elif self.type == PF_ADDR_TABLE:
            self.tblname = a.addr.v.tblname
            self.tblcnt = a.addr.p.tblcnt
        elif self.type == PF_ADDR_ADDRMASK:
            try:
                l = {AF_INET: 4, AF_INET6: 16}[self.af]
            except KeyError:
                self.addr = self.mask = None
            else:
                addr = string_at(addressof(a.addr.v.a.addr), l)
                mask = string_at(addressof(a.addr.v.a.mask), l)
                self.addr = inet_ntop(self.af, addr)
                self.mask = inet_ntop(self.af, mask)
        elif self.type == PF_ADDR_RTLABEL:
            self.rtlabelname = a.addr.v.rtlabelname
            self.rtlabel = a.addr.v.rtlabel

        self.port = map(ntohs, a.port)
        self.port_op = a.port_op

    def _from_string(self, a):
        """Initalize a new instance from a string."""
        raise NotImplementedError

    def _from_kw(self, **kw):
        """Initalize a new instance by specifying its attributes values."""
        raise NotImplementedError

    def _to_struct(self):
        """Convert this instance to a pf_rule_addr structure."""
        a = pf_rule_addr()

        a.addr.type = self.type
        a.addr.iflags = self.iflags
        a.neg = int(self.neg)

        if self.type == PF_ADDR_DYNIFTL:
            a.addr.v.ifname = self.ifname
            a.addr.p.dyncnt = self.dyncnt
        elif self.type == PF_ADDR_TABLE:
            a.addr.v.tblname = self.tblname
            a.addr.p.tblcnt = self.tblcnt
        elif self.type == PF_ADDR_ADDRMASK:
            if self.addr:
                a.addr.v.a.addr = inet_pton(self.af, self.addr)
                a.addr.v.a.mask = inet_pton(self.af, self.mask)
        elif self.type == PF_ADDR_RTLABEL:
            a.addr.v.rtlabelname = self.rtlabelname
            a.addr.v.rtlabel = self.rtlabel

        a.port[:] = map(htons, self.port)
        a.port_op = self.port_op

        return a

    def _to_string(self):
        """Return the string representation of the address/port pair."""
        s = ""

        if self.neg:
            s += "! "

        if self.type == PF_ADDR_DYNIFTL:
            s += "(%s" % self.ifname
            if self.iflags & PFI_AFLAG_NETWORK:
                s += ":network"
            if self.iflags & PFI_AFLAG_BROADCAST:
                s += ":broadcast"
            if self.iflags & PFI_AFLAG_PEER:
                s += ":peer"
            if self.iflags & PFI_AFLAG_NOALIAS:
                s += ":0"
            s += ")"
        elif self.type == PF_ADDR_TABLE:
            if self.tblcnt == -1:
                return s + "<%s:*>" % self.tblname
            else:
                return s + "<%s:%i>" % (self.tblname, self.tblcnt)
        elif self.type == PF_ADDR_ADDRMASK:
            if self.is_any():
                s += "any"
            else:
                s += self.addr
        elif self.type == PF_ADDR_NOROUTE:
            return s + "no-route"
        elif self.type == PF_ADDR_URPFFAILED:
            return s + "urpf-failed"
        elif self.type == PF_ADDR_RTLABEL:
            return "route \"%s\"" % self.rtlabelname
        else:
            return s + "?"

        if (self._unmask(self.addr) == 0) and (self._unmask(self.mask) == 0):
            bits = self._unmask(self.mask)
            if not ((self.af == AF_INET and bits == 32) or (bits == 128)):
                s += "/%i" % bits

        if self.port_op or self.port[0]:
            p1, p2 = self.port

            if self.port_op in (PF_OP_EQ, PF_OP_NE):
                try:
                    p1 = getservbyport(p1, getprotobynumber(self.proto))
                except:
                    pass

            if self.port_op == PF_OP_NONE:
                s += ":%s" % (p1 or "")
            elif self.port_op == PF_OP_IRG:
                s += " port %s >< %s" % (p1, p2)
            elif self.port_op == PF_OP_XRG:
                s += " port %s <> %s" % (p1, p2)
            elif self.port_op == PF_OP_EQ:
                s += " port = %s" % p1
            elif self.port_op == PF_OP_NE:
                s += " port != %s" % p1
            elif self.port_op == PF_OP_LT:
                s += " port < %s" % p1
            elif self.port_op == PF_OP_LE:
                s += " port <= %s" % p1
            elif self.port_op == PF_OP_GT:
                s += " port > %s" % p1
            elif self.port_op == PF_OP_GE:
                s += " port >= %s" % p1
            elif self.port_op == PF_OP_RRG:
                s += " port %s:%s" % (p1, p2)

        return s

    def _unmask(self, mask):
        """Return the number of 1s in the specified bitmask"""
        bits = 0

        for b in map(ord, inet_pton(self.af, mask)):
            while b:
                bits += b & 1
                b >>= 1

        return bits

    def is_any(self):
        """Return true if this address matches any host."""
        if self.type != PF_ADDR_ADDRMASK:
            return False
        elif not self.af:
            return True
        return (self._unmask(self.addr) == 0) and (self._unmask(self.mask) == 0)

    def __str__(self):
        return self._to_string()

    def __eq__(self, a):
        if self.type != a.type or self.iflags  != a.iflags  or \
           self.neg  != a.neg  or self.af      != a.af      or \
           self.port != a.port or self.port_op != a.port_op:
            return False

        if self.type == PF_ADDR_DYNIFTL:
            return (self.ifname == a.ifname and self.dyncnt == a.dyncnt)
        elif self.type == PF_ADDR_TABLE:
            return (self.tblname == a.tblname and self.tblcnt == a.tblcnt)
        elif self.type == PF_ADDR_ADDRMASK:
            return (self.addr == a.addr and self.mask == a.mask)
        elif self.type == PF_ADDR_RTLABEL:
            return (self.rtlabelname == a.rtlabelname and
                    self.rtlabel == a.rtlabel)
        else:
            return True

    def __ne__(self, a):
        return not self.__eq__(a)

