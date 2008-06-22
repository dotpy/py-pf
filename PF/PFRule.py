"""Classes to represent Packet Filter Rules."""


from socket import *
from ctypes import *
import re

from _PFStruct import *
from PFConstants import *
from PFUtils import *


__all__ = ['PFRuleAddr',
           'PFPool',
           'PFRule',
           'PFRuleset']


# Dictionaries for mapping strings to constants ################################
pf_actions  = {"pass":      PF_PASS,
               "scrub":     PF_SCRUB,
               "nat":       PF_NAT,
               "rdr":       PF_RDR,
               "binat":     PF_BINAT}

pf_port_ops = {"":          PF_OP_NONE,
               "><":        PF_OP_IRG,
               "<>":        PF_OP_XRG,
               "=":         PF_OP_EQ,
               "!=":        PF_OP_NE,
               "<":         PF_OP_LT,
               "<=":        PF_OP_LE,
               ">":         PF_OP_GT,
               ">=":        PF_OP_GE,
               ":":         PF_OP_RRG}

pf_if_mods  = {"network":   PFI_AFLAG_NETWORK,
               "broadcast": PFI_AFLAG_BROADCAST,
               "peer":      PFI_AFLAG_PEER,
               "0":         PFI_AFLAG_NOALIAS}

afs         = {"inet":      AF_INET,
               "inet6":     AF_INET6}


# PFRuleAddr class #############################################################
class PFRuleAddr:
    """Class representing an address/port pair."""

    def __init__(self, addr=None, af=AF_UNSPEC, proto=IPPROTO_TCP, **kw):
        """Check arguments and initialize instance attributes."""
        if af in (AF_UNSPEC, AF_INET, AF_INET6):
            self.af = af
        elif af in ("inet", "inet6"):
            self.af = afs[af]
        elif isinstance(af, (int, str)):
            raise ValueError, "Not a valid address family: '%s'" % af
        else:
            raise TypeError, "'af' must be an integer or a string"

        self._len = {AF_UNSPEC: 0, AF_INET: 4, AF_INET6: 16}[self.af]

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
        self.neg = bool(a.neg)
        addr, mask = a.addr.v.a.addr, a.addr.v.a.mask

        if self.af == AF_UNSPEC and \
           (self.type in (PF_ADDR_DYNIFTL, PF_ADDR_RANGE) or
            self.type == PF_ADDR_ADDRMASK and (sum(addr.v6) + sum(mask.v6))):
            raise ValueError, "Address family not specified"

        if self.type == PF_ADDR_DYNIFTL:
            self.ifname = a.addr.v.ifname
            self.iflags = a.addr.iflags
            self.dyncnt = a.addr.p.dyncnt
            self.mask = inet_ntop(self.af,
                                  string_at(addressof(mask), self._len))
        elif self.type == PF_ADDR_TABLE:
            self.tblname = a.addr.v.tblname
            self.tblcnt = a.addr.p.tblcnt
        elif self.type == PF_ADDR_ADDRMASK:
            if self.af == AF_UNSPEC:
                self.addr = self.mask = None    # 'any' address with unknown af
            else:
                self.addr = inet_ntop(self.af,
                                      string_at(addressof(addr), self._len))
                self.mask = inet_ntop(self.af,
                                      string_at(addressof(mask), self._len))
        elif self.type == PF_ADDR_RTLABEL:
            self.rtlabelname = a.addr.v.rtlabelname
            self.rtlabel = a.addr.v.rtlabel
        elif self.type == PF_ADDR_RANGE:
            self.addr = (inet_ntop(self.af,
                                   string_at(addressof(addr), self._len)),
                         inet_ntop(self.af,
                                   string_at(addressof(mask), self._len)))

        self.port = tuple(map(ntohs, a.port))
        self.port_op = a.port_op

    def _from_string(self, a):
        """Initalize a new instance from a string."""
        type_re = "(?P<nort>no-route)|"                                   + \
                  "(?P<urpf>urpf-failed)|"                                + \
                  "(?P<any>any)|"                                         + \
                  "(?P<tbl><(?P<tblname>\w+)>)|"                          + \
                  "(?P<rt>route\s+(?P<rtlbl>rtlabel))|"                   + \
                  "(?P<if>\((?P<ifname>[a-z]+[0-9]+)"                     + \
                           "(?P<mod>(:network|:broadcast|:peer|:0)*)\)"   + \
                           "(?:/(?P<ifmask>\d+))?)|"                      + \
                  "(?P<ipv4rg>(?P<ipv4_1>[0-9.]+)\s*-\s*"                 + \
                             "(?P<ipv4_2>[0-9.]+))|"                      + \
                  "(?P<ipv6rg>(?P<ipv6_1>[0-9a-f:]+)\s*-\s*"              + \
                             "(?P<ipv6_2>[0-9a-f:]+))|"                   + \
                  "(?P<ipv4>[0-9.]+)(?:/(?P<mask4>\d+))?|"                + \
                  "(?P<ipv6>[0-9a-f:]+)(?:/(?P<mask6>\d+))?"
        addr_re = "(?P<addr>(?P<neg>!)?\s*"                               + \
                           "(?P<address>" + type_re + "))\s*"
        port_re = "(?P<port>port\s+"                                      + \
                           "(?:(?P<p1>\w+)?\s*"                           + \
                              "(?P<op>=|!=|<|<=|>|>=|:|<>|><))?\s*"       + \
                           "(?P<p2>\w+))?"

        m = re.compile(addr_re + port_re).match(a)
        if not m:
            raise ValueError, "Could not parse address: '%s'" % a

        self.neg = bool(m.group("neg"))

        if m.group("nort"):
            self.type = PF_ADDR_NOROUTE
        elif m.group("urpf"):
            self.type = PF_ADDR_URPFFAILED
        elif m.group("any"):
            self.type = PF_ADDR_ADDRMASK
            if self.af == AF_UNSPEC:
                self.addr = self.mask = None
            else:
                self.addr = self.mask = self._mask(0)
        elif m.group("tbl"):
            self.type = PF_ADDR_TABLE
            self.tblname = m.group("tblname")
            self.tblcnt = -1
        elif m.group("rt"):
            self.type = PF_ADDR_RTLABEL
            self.rtlabelname = m.group("rtlbl")
            self.rtlabel = 0
        elif m.group("if"):
            if self.af == AF_UNSPEC:
                raise ValueError, "Address family not specified"
            self.type = PF_ADDR_DYNIFTL
            self.ifname = m.group("ifname")
            if (m.group("ifmask")):
                self.mask = self._mask(int(m.group("ifmask")))
            else:
                self.mask = self._mask(self._len * 8)
            self.dyncnt = 0
            self.iflags = 0
            for mod in filter(None, m.group("mod").split(":")):
                self.iflags |= pf_if_mods[mod]
        elif m.group("ipv4rg"):
            self.af, self._len = AF_INET, 4
            self.type = PF_ADDR_ADDRMASK
            self.addr = m.group("ipv4_1", "ipv4_2")
        elif m.group("ipv6rg"):
            self.af, self._len = AF_INET6, 16
            self.type = PF_ADDR_ADDRMASK
            self.addr = m.group("ipv6_1", "ipv6_2")
        elif m.group("ipv4"):
            self.af, self._len = AF_INET, 4
            self.type = PF_ADDR_ADDRMASK
            self.addr = m.group("ipv4")
            if m.group("mask4"):
                self.mask = self._mask(int(m.group("mask4")))
            else:
                self.mask = self._mask(32)
        elif m.group("ipv6"):
            self.af, self._len = AF_INET6, 16
            self.type = PF_ADDR_ADDRMASK
            self.addr = m.group("ipv6")
            if m.group("mask6"):
                self.mask = self._mask(int(m.group("mask6")))
            else:
                self.mask = self._mask(128)

        if m.start("port") != -1:
            if not m.group("op"):
                self.port_op = PF_OP_EQ
            else:
                self.port_op = pf_port_ops[m.group("op")]

            if self.port_op in (PF_OP_IRG, PF_OP_XRG, PF_OP_RRG):
                self.port = tuple(map(int, m.group("p1", "p2")))
            else:
                self.port = (int(m.group("p2")), 0)
        else:
            self.port_op = PF_OP_NONE
            self.port = (0, 0)

    def _from_kw(self, **kw):
        """Initalize a new instance by specifying its attributes values."""
        for k, v in kw.iteritems():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                raise TypeError, "Unexpected keyword argument '%s'" % k

    def _to_struct(self):
        """Convert this instance to a pf_rule_addr structure."""
        a = pf_rule_addr()

        a.addr.type = self.type
        a.neg = int(self.neg)

        if self.type in (PF_ADDR_DYNIFTL, PF_ADDR_ADDRMASK):
            addr, mask = pf_addr(), pf_addr()

        if self.type == PF_ADDR_DYNIFTL:
            a.addr.v.ifname = self.ifname
            a.addr.p.dyncnt = self.dyncnt
            a.addr.iflags = self.iflags
            mask.addr8[0:self._len] = map(ord, inet_pton(self.af, self.mask))
            a.addr.v.a.mask = mask
        elif self.type == PF_ADDR_TABLE:
            a.addr.v.tblname = self.tblname
            a.addr.p.tblcnt = self.tblcnt
        elif self.type == PF_ADDR_ADDRMASK:
            if self.addr:
                addr.addr8[0:self._len] = map(ord,
                                              inet_pton(self.af, self.addr))
                mask.addr8[0:self._len] = map(ord,
                                              inet_pton(self.af, self.mask))
                a.addr.v.a.addr, a.addr.v.a.mask = addr, mask
        elif self.type == PF_ADDR_RTLABEL:
            a.addr.v.rtlabelname = self.rtlabelname
            a.addr.v.rtlabel = self.rtlabel
        elif self.type == PF_ADDR_RANGE:
            addr.addr8[0:self._len] = map(ord, inet_pton(self.af, self.addr[0]))
            mask.addr8[0:self._len] = map(ord, inet_pton(self.af, self.addr[1]))
            a.addr.v.a.addr, a.addr.v.a.mask = addr, mask

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
            return s + "<%s>" % self.tblname
        elif self.type == PF_ADDR_ADDRMASK:
            if self._azero():
                s += "any"
            else:
                s += self.addr
        elif self.type == PF_ADDR_NOROUTE:
            return s + "no-route"
        elif self.type == PF_ADDR_URPFFAILED:
            return s + "urpf-failed"
        elif self.type == PF_ADDR_RTLABEL:
            return "route \"%s\"" % self.rtlabelname
        elif self.type == PF_ADDR_RANGE:
            s += "%s - %s" % self.addr
        else:
            return s + "?"

        if self.type != PF_ADDR_RANGE and not self._azero():
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
        """Return the number of 1s in the specified bitmask."""
        bits = 0

        for b in map(ord, inet_pton(self.af, mask)):
            while b:
                bits += b & 1
                b >>= 1

        return bits

    def _mask(self, bits):
        """Return the bitmask corresponding to the number of bits specified."""
        if (self.af == AF_INET and bits > 32) or (bits > 128):
            raise ValueError, "Too many bits for the address family"

        try:
            l = {AF_INET: 32, AF_INET6: 128}[self.af]
        except KeyError:
            raise ValueError, "Address family is unknown"

        b = "1" * bits + "0" * (l - bits)
        mask = "".join([chr(int(b[i:i+8], base=2)) for i in range(0, l, 8)])

        return inet_ntop(self.af, mask)

    def _azero(self):
        """Return True if both address and netmask are zero."""
        try:
            return (self._unmask(self.addr) == 0) and \
                   (self._unmask(self.mask) == 0)
        except:
            return True

    def is_any(self):
        """Return true if this address matches any host."""
        return (self.type == PF_ADDR_ADDRMASK) and self._azero()

    def __str__(self):
        return self._to_string()

    def __eq__(self, a):
        if self.type != a.type or self.neg != a.neg or self.af != a.af or \
           self.port != a.port or self.port_op != a.port_op:
            return False

        if self.type == PF_ADDR_DYNIFTL:
            return (self.ifname == a.ifname and self.mask == a.mask and
                    self.iflags == a.iflags)
        elif self.type == PF_ADDR_TABLE:
            return (self.tblname == a.tblname)
        elif self.type == PF_ADDR_ADDRMASK:
            return (self.addr == a.addr and self.mask == a.mask)
        elif self.type == PF_ADDR_RTLABEL:
            return (self.rtlabelname == a.rtlabelname)
        elif self.type == PF_ADDR_RANGE:
            return (self.addr == a.addr)

        return True

    def __ne__(self, a):
        return not self.__eq__(a)


# PFPool class #################################################################
class PFPool:
    """Class representing an address pool."""

    def __init__(self, id, pool=None, *addrs, **kw):
        """Check arguments and initialize instance attributes."""
        if not isinstance(id, int):
            raise TypeError, "'id' must be an integer"
        self.id = id

        if isinstance(pool, pf_pool):
            self._from_struct(pool)
        elif isinstance(pool, str):
            self._from_string(pool)
        elif pool is None:
            self._from_struct(pf_pool())
        else:
            raise TypeError, "'pool' must be a pf_pool structure or a string"

        self.addrs = []

        for addr in addrs:
            if isinstance(addr, PFRuleAddr):
                self.addrs.append(addr)
            elif isinstance(addr, str):
                self.addrs.append(PFRuleAddr(addr))
            else:
                raise TypeError, "'addrs' must be PFRuleAddr objects or strings"

        if kw:
            self._from_kw(**kw)

    def _from_struct(self, p):
        """Initalize a new instance from a pf_pool structure."""
        self.key        = "0x%08x%08x%08x%08x" % tuple(p.key.key32[:])
        self.tblidx     = p.tblidx
        self.proxy_port = tuple(p.proxy_port[:])
        self.port_op    = p.port_op
        self.opts       = p.opts

    def _from_string(self, p):
        """Initalize a new instance from a string."""
        raise NotImplementedError

    def _from_kw(self, **kw):
        """Initalize a new instance by specifying its attributes values."""
        for k, v in kw.iteritems():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                raise TypeError, "Unexpected keyword argument '%s'" % k

    def _to_struct(self):
        """Convert a PFPool object to a pf_pool structure."""
        raise NotImplementedError

    def _to_string(self):
        """Return the string representation of the address pool."""
        p1, p2 = self.proxy_port

        addrs = []
        for addr in self.addrs:
            if self.id in (PF_NAT, PF_RDR, PF_BINAT):
                addrs.append("%s" % addr)
            elif self.id == PF_PASS:
                if addr._azero():
                    addrs.append(addr.ifname)
                else:
                    addrs.append("(%s %s)" % (addr.ifname, addr))

        s = ", ".join(addrs)
        if len(addrs) > 1:
            s = "{ %s }" % s

        if self.id == PF_NAT:
            if (p1, p2) != (PF_NAT_PROXY_PORT_LOW, PF_NAT_PROXY_PORT_HIGH) and \
               (p1, p2) != (0, 0):
                if p1 == p2:
                    s += " port %u" % p1
                else:
                    s += " port %u:%u" % (p1, p2)
        elif self.id == PF_RDR:
            if p1:
                s += " port %u" % p1
                if p2 and (p2 != p1):
                    s += ":%u" % p2

        opt = self.opts & PF_POOL_TYPEMASK
        if opt == PF_POOL_BITMASK:
            s += " bitmask"
        elif opt == PF_POOL_RANDOM:
            s += " random"
        elif opt == PF_POOL_SRCHASH:
            s += " source-hash %s" % self.key
        elif opt == PF_POOL_ROUNDROBIN:
            s += " round-robin"

        if self.opts & PF_POOL_STICKYADDR:
            s += " sticky-address"

        if (self.id == PF_NAT) and (p1 == 0) and (p2 == 0):
            s += " static-port"

        return s

    def append(self, addr):
        """Append a new address to the 'addrs' list."""
        if not isinstance(addr, PFRuleAddr):
            raise TypeError, "'addr' must be a PFRuleAddr object"
        self.addrs.append(addr)

    def __str__(self):
        return self._to_string()


# PFRule class #################################################################
class PFRule:
    """Class representing a Packet Filter rule."""

    def __init__(self, rule=None, **kw):
        """Check arguments and initialize instance attributes."""
        if isinstance(rule, pf_rule):
            self._from_struct(rule)
        elif isinstance(rule, str):
            self._from_string(rule)
        elif rule is None:
            self._from_struct(pf_rule(rtableid=-1))
        else:
            raise TypeError, "'rule' must be a pf_rule structure or a string"

        if kw:
            self._from_kw(**kw)

    def _from_struct(self, r):
        """Initalize a new instance from a pf_rule structure."""
        self.src               = PFRuleAddr(r.src, r.af, r.proto)
        self.dst               = PFRuleAddr(r.dst, r.af, r.proto)
        self.label             = r.label
        self.ifname            = r.ifname
        self.qname             = r.qname
        self.pqname            = r.pqname
        self.tagname           = r.tagname
        self.match_tagname     = r.match_tagname
        self.overload_tblname  = r.overload_tblname
        self.rpool             = None
        self.evaluations       = r.evaluations
        self.packets           = tuple(r.packets)
        self.bytes             = tuple(r.bytes)
        self.os_fingerprint    = r.os_fingerprint
        self.rtableid          = r.rtableid
        self.timeout           = tuple(r.timeout)
        self.states            = r.states
        self.max_states        = r.max_states
        self.src_nodes         = r.src_nodes
        self.max_src_nodes     = r.max_src_nodes
        self.max_src_states    = r.max_src_states
        self.max_src_conn      = r.max_src_conn
        self.max_src_conn_rate = (r.max_src_conn_rate.limit,
                                  r.max_src_conn_rate.seconds)
        self.qid               = r.qid
        self.pqid              = r.pqid
        self.rt_listid         = r.rt_listid
        self.nr                = r.nr
        self.prob              = r.prob
        self.cuid              = r.cuid
        self.cpid              = r.cpid
        self.return_icmp       = r.return_icmp
        self.return_icmp6      = r.return_icmp6
        self.max_mss           = r.max_mss
        self.tag               = r.tag
        self.match_tag         = r.match_tag
        self.uid               = tuple(r.uid.uid)
        self.uid_op            = r.uid.op
        self.gid               = tuple(r.gid.gid)
        self.gid_op            = r.gid.op
        self.rule_flag         = r.rule_flag
        self.action            = r.action
        self.direction         = r.direction
        self.log               = r.log
        self.logif             = r.logif
        self.quick             = bool(r.quick)
        self.ifnot             = bool(r.ifnot)
        self.match_tag_not     = bool(r.match_tag_not)
        self.natpass           = bool(r.natpass)
        self.keep_state        = r.keep_state
        self.af                = r.af
        self.proto             = r.proto
        self.type              = r.type
        self.code              = r.code
        self.flags             = "".join([f for n, f in enumerate("FSRPAUEW")
                                            if r.flags & (1 << n)])
        self.flagset           = "".join([f for n, f in enumerate("FSRPAUEW")
                                            if r.flagset & (1 << n)])
        self.min_ttl           = r.min_ttl
        self.allow_opts        = bool(r.allow_opts)
        self.rt                = r.rt
        self.return_ttl        = r.return_ttl
        self.tos               = r.tos
        self.anchor_relative   = r.anchor_relative
        self.anchor_wildcard   = r.anchor_wildcard
        self.flush             = r.flush

    def _from_string(self, r):
        """Initalize a new instance from a string."""
        raise NotImplementedError

    def _from_kw(self, **kw):
        """Initalize a new instance by specifying its attributes values."""
        for k, v in kw.iteritems():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                raise TypeError, "Unexpected keyword argument '%s'" % k

    def _to_struct(self):
        """Convert a PFRule object to a pf_rule structure."""
        r = pf_rule()

        r.src                       = self.src._to_struct()
        r.dst                       = self.dst._to_struct()
        r.label                     = self.label
        r.ifname                    = self.ifname
        r.qname                     = self.qname
        r.pqname                    = self.pqname
        r.tagname                   = self.tagname
        r.match_tagname             = self.match_tagname
        r.overload_tblname          = self.overload_tblname
        r.evaluations               = self.evaluations
        r.packets[:]                = self.packets
        r.bytes[:]                  = self.bytes
        r.os_fingerprint            = self.os_fingerprint
        r.rtableid                  = self.rtableid
        r.timeout[:]                = self.timeout
        r.states                    = self.states
        r.max_states                = self.max_states
        r.src_nodes                 = self.src_nodes
        r.max_src_nodes             = self.max_src_nodes
        r.max_src_states            = self.max_src_states
        r.max_src_conn              = self.max_src_conn
        r.max_src_conn_rate.limit   = self.max_src_conn_rate[0]
        r.max_src_conn_rate.seconds = self.max_src_conn_rate[1]
        r.qid                       = self.qid
        r.pqid                      = self.pqid
        r.rt_listid                 = self.rt_listid
        r.nr                        = self.nr
        r.prob                      = self.prob
        r.cuid                      = self.cuid
        r.cpid                      = self.cpid
        r.return_icmp               = self.return_icmp
        r.return_icmp6              = self.return_icmp6
        r.max_mss                   = self.max_mss
        r.tag                       = self.tag
        r.match_tag                 = self.match_tag
        r.uid.uid[:]                = self.uid
        r.uid.op                    = self.uid_op
        r.gid.gid[:]                = self.gid
        r.gid.op                    = self.gid_op
        r.rule_flag                 = self.rule_flag
        r.action                    = self.action
        r.direction                 = self.direction
        r.log                       = self.log
        r.logif                     = self.logif
        r.quick                     = int(self.quick)
        r.ifnot                     = int(self.ifnot)
        r.match_tag_not             = int(self.match_tag_not)
        r.natpass                   = int(self.natpass)
        r.keep_state                = self.keep_state
        r.af                        = self.af
        r.proto                     = self.proto
        r.type                      = self.type
        r.code                      = self.code
        r.flags                     = reduce(int.__or__,
                                             [1 << "FSRPAUEW".find(f)
                                              for f in self.flags], 0)
        r.flagset                   = reduce(int.__or__,
                                             [1 << "FSRPAUEW".find(f)
                                              for f in self.flagset], 0)
        r.min_ttl                   = self.min_ttl
        r.allow_opts                = int(self.allow_opts)
        r.rt                        = self.rt
        r.return_ttl                = self.return_ttl
        r.tos                       = self.tos
        r.anchor_relative           = self.anchor_relative
        r.anchor_wildcard           = self.anchor_wildcard
        r.flush                     = self.flush

        return r

    def _to_string(self):
        """Return the string representation of the rule."""
        pf_actions = ("pass", "block", "scrub", "no scrub", "nat", "no nat",
                      "binat", "no binat", "rdr", "no rdr")
        pf_anchors = ("anchor", "anchor", "anchor", "anchor", "nat-anchor",
                      "nat-anchor", "binat-anchor", "binat-anchor",
                      "rdr-anchor", "rdr-anchor")

        if self.action > PF_NORDR:
            s = "action(%d)" % self.action
        elif isinstance(self, PFRuleset):
            if self.path:
                s = pf_anchors[self.action]
                if not self.path.startswith("_"):
                    s += " \"%s\"" % self.path.split("/")[-1]
        else:
            s = pf_actions[self.action]
            if self.natpass:
                s += " pass"

        if self.action == PF_DROP:
            if self.rule_flag & PFRULE_RETURN:
                s += " return"
            elif self.rule_flag & PFRULE_RETURNRST:
                s += " return-rst"
                if self.return_ttl:
                    s += "(ttl %d)" % self.return_ttl
            elif self.rule_flag & PFRULE_RETURNICMP:
                ic  = geticmpcodebynumber(self.return_icmp >> 8,
                                          self.return_icmp & 0xff, AF_INET)
                ic6 = geticmpcodebynumber(self.return_icmp6 >> 8,
                                          self.return_icmp6 & 0xff, AF_INET6)
                if self.af == AF_INET:
                    s += " return-icmp(%s)" % (ic or self.return_icmp & 0xff)
                elif self.af == AF_INET6:
                    s += " return-icmp6(%s)" % (ic6 or self.return_icmp6 & 0xff)
                else:
                    s += "(%s, %s)" % ((ic or self.return_icmp & 0xff),
                                       (ic6 or self.return_icmp6 & 0xff))
            else:
                s += " drop"

        if self.direction == PF_IN:
            s += " in"
        elif self.direction == PF_OUT:
            s += " out"

        if self.log:
            s += " log"
            if (self.log & ~PF_LOG) or self.logif:
                l = []
                if self.log & PF_LOG_ALL:
                    l.append("all")
                if self.log & PF_LOG_SOCKET_LOOKUP:
                    l.append("user")
                if self.logif:
                    l.append("to pflog%u" % self.logif)
                s += " (%s)" % ", ".join(l)

        if self.quick:
            s += " quick"

        if self.ifname:
            if self.ifnot:
                s += " on ! %s" % self.ifname
            else:
                s += " on %s" % self.ifname

        if self.rt:
            if self.rt == PF_ROUTETO:
                s += " route-to"
            elif self.rt == PF_REPLYTO:
                s += " reply-to"
            elif self.rt == PF_DUPTO:
                s += " dup-to"
            elif  self.rt == PF_FASTROUTE:
                s += " fastroute"
            if self.rt != PF_FASTROUTE:
                s += " %s" % self.rpool

        if self.af:
            if self.af == AF_INET:
                s += " inet"
            else:
                s += " inet6"

        if self.proto:
            s += " proto %s" % (getprotobynumber(self.proto) or self.proto)

        if self.src.is_any() and self.dst.is_any() and    \
           not self.src.neg and not self.dst.neg and      \
           not (self.src.port_op or self.src.port[0]) and \
           not (self.dst.port_op or self.dst.port[0]) and \
           self.os_fingerprint == PF_OSFP_ANY:
            s += " all"
        else:
            s += " from %s" % self.src
            #if self.os_fingerprint != PF_OSFP_ANY:
            s += " to %s" % self.dst

        if self.uid_op:
            s += " user %s" % self._print_id(self.uid, self.uid_op)
        if self.gid_op:
            s += " group %s" % self._print_id(self.gid, self.gid_op)

        if self.flags or self.flagset:
            s += " flags %s/%s" % (self.flags, self.flagset)
        elif self.action == PF_PASS and self.proto in (0, IPPROTO_TCP) and   \
             not (self.rule_flag & PFRULE_FRAGMENT) and self.keep_state and  \
             not isinstance(self, PFRuleset):
            s += " flags any"

        if self.type:
            it = geticmptypebynumber(self.type-1, self.af)
            if self.af != AF_INET6:
                s += " icmp-type"
            else:
                s += " icmp6-type"
            s += " %s" % (it or self.type-1)
            if self.code:
                ic = geticmpcodebynumber(self.type-1, self.code-1, self.af)
                s += " code %s" % (ic or self.code-1)

        if self.tos:
            s += " tos 0x%2.2x" % self.tos

        if not self.keep_state and self.action == PF_PASS and \
           not isinstance(self, PFRuleset):
            s += " no state"
        elif self.keep_state == PF_STATE_NORMAL:
            s += " keep state"
        elif self.keep_state == PF_STATE_MODULATE:
            s += " modulate state"
        elif self.keep_state == PF_STATE_SYNPROXY:
            s += " synproxy state"

        # prob
        # opts

        if self.rule_flag & PFRULE_FRAGMENT:
            s += " fragment"
        if self.rule_flag & PFRULE_NODF:
            s += " no-df"
        if self.rule_flag & PFRULE_RANDOMID:
            s += " random-id"

        if self.min_ttl:
            s += " min-ttl %d" % self.min_ttl
        if self.max_mss:
            s += " max-mss %d" % self.max_mss
        if self.allow_opts:
            s += " allow-opts"

        if self.action == PF_SCRUB:
            if self.rule_flag & PFRULE_REASSEMBLE_TCP:
                s += " reassemble tcp"
            if self.rule_flag & PFRULE_FRAGDROP:
                s += " fragment drop-ovl"
            elif self.rule_flag & PFRULE_FRAGCROP:
                s += " fragment crop"
            else:
                s += " fragment reassemble"

        if self.label:
            s += " label \"%s\"" % self.label

        if self.qname and self.pqname:
            s += " queue(%s, %s)" % (self.qname, self.pqname)
        elif self.qname:
            s += " queue %s" % self.qname

        if self.tagname:
            s += " tag %s" % self.tagname
        if self.match_tagname:
            if self.match_tag_not:
                s += " !"
            s += " tagged %s" % self.match_tagname

        if self.rtableid != -1:
            s += " rtable %u" % self.rtableid

        if not isinstance(self, PFRuleset) and \
           self.action in (PF_NAT, PF_BINAT, PF_RDR):
            s += " -> %s" % self.rpool

        return s

    def _print_id(self, id, op):
        """Return a string representing the user or group ID"""
        if id[0] == UID_MAX and op in (PF_OP_EQ, PF_OP_NE):
            id = ("unknown", id[1])

        if op == PF_OP_IRG:
            return " %s >< %s" % id
        elif op == PF_OP_XRG:
            return " %s <> %s" % id
        elif op == PF_OP_EQ:
            return " = %s" % id[0]
        elif op == PF_OP_NE:
            return " != %s" % id[0]
        elif op == PF_OP_LT:
            return " < %s" % id[0]
        elif op == PF_OP_LE:
            return " <= %s" % id[0]
        elif op == PF_OP_GT:
            return " > %s" % id[0]
        elif op == PF_OP_GE:
            return " >= %s" % id[0]
        elif op == PF_OP_RRG:
            return " %s:%s" % id

    def __str__(self):
        return self._to_string()


# PFRuleset class ##############################################################
class PFRuleset(PFRule):
    """Class representing a Packet Filter ruleset or anchor."""

    def __init__(self, path="", rule=None, **kw):
        """Check arguments and initialize instance attributes."""
        PFRule.__init__(self, rule, **kw)

        if not isinstance(path, str):
            raise TypeError, "'path' must be a string"
        self.path = path

        self.rules = {PF_PASS:  [],
                      PF_SCRUB: [],
                      PF_NAT:   [],
                      PF_RDR:   [],
                      PF_BINAT: []}

    def _to_string(self):
        """Return the string representation of the ruleset."""
        actions = (PF_NAT, PF_RDR, PF_BINAT, PF_SCRUB, PF_PASS)
        s = ""

        for action in actions:
            for rule in self.rules[action]:
                s += "%s\n" % PFRule._to_string(rule)

        return s[:-1]

    def append(self, action, rule):
        """Append a rule of type 'action' to the list of rules."""
        if action in pf_actions.keys():
            a = pf_actions[action]
        elif action in pf_actions.values():
            a = action
        elif isinstance(action, (str, int)):
            raise ValueError, "Not a valid action: '%s'" % action
        else:
            raise TypeError, "'action' must be a string or an integer"

        if not isinstance(rule, (PFRule, PFRuleset)):
            raise TypeError, "'rule' must be a PFRule or a PFRuleset"
        self.rules[a].append(rule)

