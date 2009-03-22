"""Classes to represent Packet Filter Rules."""


from socket import *
from ctypes import *
import re
import pwd, grp

from PF import *
from PF._PFStruct import *
from PF.PFUtils import *

__all__ = ['PFUid',
           'PFGid',
           'PFPort',
           'PFAddr',
           'PFRuleAddr',
           'PFPool',
           'PFRule',
           'PFRuleset']


# Dictionaries for mapping strings to constants ################################
pf_ops      = {"":          PF_OP_NONE,
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


# Helper functions #############################################################
def azero(seq):
    """Return True if all numbers in 'seq' are 0s."""
    return not filter(None, seq)


# PFUid and PFGid classes ######################################################
class PFOp:
    """Class representing a generic comparison operation."""

    def __init__(self, num=None, op=PF_OP_NONE):
        """Check arguments and initialize instance attributes."""
        self.op = op

        if num is None:
            self.num = (0, 0)
        elif isinstance(num, int):
            self.num = (num, 0)
        elif isinstance(num, tuple):
            self.num = num
        elif isinstance(num, basestring):
            self._from_string(num)
        elif isinstance(num, Structure):
            self._from_struct(num)
        else:
            raise TypeError("Wrong type for 'num': %s" % type(num))

    def _from_struct(self, operation):
        """Initalize a new instance from a structure."""
        raise NotImplementedError

    def _from_string(self, operation):
        """Initalize a new instance from a string."""
        op_re = "(?:(?P<n1>[0-9]+)?\s*"                  + \
                   "(?P<op>=|!=|<|<=|>|>=|:|<>|><))?\s*" + \
                "(?P<n2>[0-9a-z-]+)?"

        m = re.compile(op_re).match(operation)
        if not m:
            raise ValueError("Could not parse string: '%s'" % operation)

        if not m.group("op"):
            self.op = PF_OP_EQ
        else:
            self.op = pf_ops[m.group("op")]

        try:
            n2 = int(m.group("n2"))
        except ValueError:
            if self.op in (PF_OP_EQ, PF_OP_NE):
                n2 = self._str_to_num(m.group("n2"))
            else:
                raise

        if self.op in (PF_OP_IRG, PF_OP_XRG, PF_OP_RRG):
            n1 = int(m.group("n1"))
            self.num = (n1, n2)
        else:
            self.num = (n2, 0)

    def _to_struct(self):
        """Return the structure representing the operation."""
        raise NotImplementedError

    def _to_string(self):
        """Return the string representation of the operation."""
        n1, n2 = self.num

        if self.op == PF_OP_NONE and not n1:
            return ""

        if self.op in (PF_OP_EQ, PF_OP_NE):
            try:
                n1 = self._num_to_str(n1)
            except error:
                pass

        if self.op == PF_OP_NONE:
            return "%s" % (n1 or "")
        elif self.op == PF_OP_IRG:
            return "%s >< %s" % (n1, n2)
        elif self.op == PF_OP_XRG:
            return "%s <> %s" % (n1, n2)
        elif self.op == PF_OP_EQ:
            return "= %s" % n1
        elif self.op == PF_OP_NE:
            return "!= %s" % n1
        elif self.op == PF_OP_LT:
            return "< %s" % n1
        elif self.op == PF_OP_LE:
            return "<= %s" % n1
        elif self.op == PF_OP_GT:
            return "> %s" % n1
        elif self.op == PF_OP_GE:
            return ">= %s" % n1
        elif self.op == PF_OP_RRG:
            return "%s:%s" % (n1, n2)

    def _num_to_str(self, n):
        """Convert a numeric operand to a string."""
        raise NotImplementedError

    def _str_to_num(self, s):
        """Convert a string to a numeric operand."""
        raise NotImplementedError

    def __str__(self):
        return self._to_string()

    def __eq__(self, operation):
        return (self.num == operation.num and self.op == operation.op)

    def __ne__(self, operation):
        return not self.__eq__(operation)


class PFUid(PFOp):
    """Class representing a user ID."""

    def __init__(self, num=None, op=PF_OP_NONE):
        """Check arguments and initialize instance attributes."""
        PFOp.__init__(self, num, op)

    def _from_struct(self, uid):
        """Initialize a new instance from a pf_rule_uid structure."""
        self.num = tuple(uid.uid)
        self.op  = uid.op

    def _to_struct(self):
        """Convert this instance to a pf_rule_uid structure."""
        return pf_rule_uid(self.num, self.op)

    def _num_to_str(self, n):
        """Convert a numeric user ID to a string."""
        try:
            return pwd.getpwuid(n).pw_name
        except KeyError:
            return n

    def _str_to_num(self, s):
        """Convert a string to a numeric user ID."""
        return pwd.getpwnam(s).pw_uid


class PFGid(PFOp):
    """Class representing a group ID."""
    def __init__(self, num=None, op=PF_OP_NONE):
        """Check arguments and initialize instance attributes."""
        PFOp.__init__(self, num, op)

    def _from_struct(self, gid):
        """Initialize a new instance from a pf_rule_gid structure."""
        self.num = tuple(gid.gid)
        self.op  = gid.op

    def _to_struct(self):
        """Convert this instance to a pf_rule_gid structure."""
        return pf_rule_gid(self.num, self.op)

    def _num_to_str(self, n):
        """Convert a numeric group ID to a string."""
        try:
            return grp.getgrgid(n).gr_name
        except KeyError:
            return n

    def _str_to_num(self, s):
        """Convert a string to a numeric group ID."""
        return grp.getgrnam(s).gr_gid


# PFPort class #################################################################
class PFPort(PFOp):
    """Class representing a TCP/UDP port."""

    def __init__(self, num=None, proto=None, op=PF_OP_NONE):
        """Check arguments and initialize instance attributes."""
        self.proto = proto
        PFOp.__init__(self, num, op)

    def _num_to_str(self, n):
        """Convert a numeric port to a service name."""
        try:
            return getservbyport(n, getprotobynumber(self.proto))
        except (TypeError, error):
            return n

    def _str_to_num(self, s):
        """Convert a service name to a numeric port."""
        return getservbyname(s, getprotobynumber(self.proto))

    def __eq__(self, p):
        return (self.num   == p.num and
                self.op    == p.op   and
                self.proto == p.proto)


# PFAddr class #################################################################
class PFAddr:
    """Class representing an address."""

    def __init__(self, addr=None, af=AF_UNSPEC, **kw):
        """Check arguments and initialize instance attributes."""
        self.af = af

        if isinstance(addr, pf_addr_wrap):
            self._from_struct(addr)
        elif isinstance(addr, basestring):
            self._from_string(addr)
        elif addr is None:
            t = (kw["type"] if kw.has_key("type") else PF_ADDR_ADDRMASK)
            self._from_struct(pf_addr_wrap(type=t))
        else:
            raise TypeError("'addr' must be a pf_addr_wrap or a string")

        self._from_kw(**kw)

    def _from_struct(self, a):
        """Initalize a new instance from a pf_addr_wrap structure."""
        self.type = a.type
        a6, m6 = a.v.a.addr.v6, a.v.a.mask.v6

        if self.type == PF_ADDR_DYNIFTL  and self.af != AF_UNSPEC          or \
           self.type == PF_ADDR_ADDRMASK and not (azero(a6) and azero(m6)) or \
           self.type == PF_ADDR_RANGE:
            try:
                l = {AF_INET: 4, AF_INET6: 16}[self.af]
            except KeyError:
                raise PFError("No valid address family specified")
            else:
                addr = inet_ntop(self.af, string_at(addressof(a6), l))
                mask = inet_ntop(self.af, string_at(addressof(m6), l))
        else:
            addr = mask = None

        if self.type == PF_ADDR_DYNIFTL:
            self.ifname = a.v.ifname
            self.iflags = a.iflags
            self.dyncnt = a.p.dyncnt
            self.mask = mask
        elif self.type == PF_ADDR_TABLE:
            self.tblname = a.v.tblname
            self.tblcnt = a.p.tblcnt
        elif self.type == PF_ADDR_ADDRMASK:
            self.addr = addr
            self.mask = mask
        elif self.type == PF_ADDR_RTLABEL:
            self.rtlabelname = a.v.rtlabelname
            self.rtlabel = a.v.rtlabel
        elif self.type == PF_ADDR_RANGE:
            self.addr = (addr, mask)

    def _from_string(self, a):
        """Initalize a new instance from a string."""
        addr_re = "(?P<nort>no-route)|"                                 + \
                  "(?P<urpf>urpf-failed)|"                              + \
                  "(?P<any>any)|"                                       + \
                  "(?P<tbl><(?P<tblname>\w+)>)|"                        + \
                  "(?P<rt>route\s+(?P<rtlbl>\w+))|"                     + \
                  "(?P<if>\((?P<ifname>[a-z]+[0-9]+)"                   + \
                           "(?P<mod>(:network|:broadcast|:peer|:0)*)\)" + \
                           "(?:/(?P<ifmask>\d+))?)|"                    + \
                  "(?P<ipv4rg>(?P<ipv4_1>[0-9.]+)\s*-\s*"               + \
                             "(?P<ipv4_2>[0-9.]+))|"                    + \
                  "(?P<ipv6rg>(?P<ipv6_1>[0-9a-f:]+)\s*-\s*"            + \
                             "(?P<ipv6_2>[0-9a-f:]+))|"                 + \
                  "(?P<ipv4>[0-9.]+)(?:/(?P<mask4>\d+))?|"              + \
                  "(?P<ipv6>[0-9a-f:]+)(?:/(?P<mask6>\d+))?"

        m = re.compile(addr_re).match(a)
        if not m:
            raise ValueError("Could not parse address: '%s'" % a)

        if m.group("nort"):
            self.type = PF_ADDR_NOROUTE
        elif m.group("urpf"):
            self.type = PF_ADDR_URPFFAILED
        elif m.group("any"):
            self.type = PF_ADDR_ADDRMASK
            self.addr = self.mask = None
        elif m.group("tbl"):
            self.type = PF_ADDR_TABLE
            self.tblname = m.group("tblname")
            self.tblcnt = -1
        elif m.group("rt"):
            self.type = PF_ADDR_RTLABEL
            self.rtlabelname = m.group("rtlbl")
            self.rtlabel = 0
        elif m.group("if"):
            self.type = PF_ADDR_DYNIFTL
            self.ifname = m.group("ifname")
            try:
                b = {AF_INET: 32, AF_INET6: 128}[self.af]
            except KeyError:
                self.mask = None
            else:
                if (m.group("ifmask")):
                    self.mask = ctonm(int(m.group("ifmask")))
                else:
                    self.mask = ctonm(b)
            self.dyncnt = 0
            self.iflags = 0
            for mod in m.group("mod").split(":")[1:]:
                self.iflags |= pf_if_mods[mod]
        elif m.group("ipv4rg"):
            self.af = AF_INET
            self.type = PF_ADDR_RANGE
            self.addr = m.group("ipv4_1", "ipv4_2")
        elif m.group("ipv6rg"):
            self.af = AF_INET6
            self.type = PF_ADDR_RANGE
            self.addr = m.group("ipv6_1", "ipv6_2")
        elif m.group("ipv4"):
            self.af = AF_INET
            self.type = PF_ADDR_ADDRMASK
            self.addr = m.group("ipv4")
            if m.group("mask4"):
                self.mask = ctonm(int(m.group("mask4")))
            else:
                self.mask = ctonm(32, self.af)
        elif m.group("ipv6"):
            self.af = AF_INET6
            self.type = PF_ADDR_ADDRMASK
            self.addr = m.group("ipv6")
            if m.group("mask6"):
                self.mask = ctonm(int(m.group("mask6")))
            else:
                self.mask = ctonm(128, self.af)

    def _from_kw(self, **kw):
        """Initalize a new instance by specifying its attributes values."""
        for k, v in kw.iteritems():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                raise ValueError("Unexpected keyword argument '%s'" % k)

    def _to_struct(self):
        """Convert this instance to a pf_rule_addr structure."""
        a = pf_addr_wrap()
        a.type = self.type

        if self.type == PF_ADDR_DYNIFTL:
            a.v.ifname = self.ifname
            a.p.dyncnt = self.dyncnt
            a.iflags = self.iflags
            if self.af == AF_UNSPEC:
                mask = '\xff' * 16
            else:
                mask = inet_pton(self.af, self.mask)
            memmove(a.v.a.mask.v6, c_char_p(mask), len(mask))
        elif self.type == PF_ADDR_TABLE:
            a.v.tblname = self.tblname
            a.p.tblcnt = self.tblcnt
        elif self.type == PF_ADDR_ADDRMASK and self.addr:
            addr = inet_pton(self.af, self.addr)
            mask = inet_pton(self.af, self.mask)
            memmove(a.v.a.addr.v6, c_char_p(addr), len(addr))
            memmove(a.v.a.mask.v6, c_char_p(mask), len(mask))
        elif self.type == PF_ADDR_RTLABEL:
            a.v.rtlabelname = self.rtlabelname
            a.v.rtlabel = self.rtlabel
        elif self.type == PF_ADDR_RANGE:
            addr1 = inet_pton(self.af, self.addr[0])
            addr2 = inet_pton(self.af, self.addr[1])
            memmove(a.v.a.addr.v6, c_char_p(addr1), len(addr1))
            memmove(a.v.a.mask.v6, c_char_p(addr2), len(addr2))

        return a

    def _to_string(self):
        """Return the string representation of the address."""
        if self.type == PF_ADDR_DYNIFTL:
            s = "(%s" % self.ifname
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
            return "<%s>" % self.tblname
        elif self.type == PF_ADDR_ADDRMASK:
            s = self.addr or "any"
        elif self.type == PF_ADDR_NOROUTE:
            return "no-route"
        elif self.type == PF_ADDR_URPFFAILED:
            return "urpf-failed"
        elif self.type == PF_ADDR_RTLABEL:
            return "route \"%s\"" % self.rtlabelname
        elif self.type == PF_ADDR_RANGE:
            s = "%s - %s" % self.addr
        else:
            return "?"

        if self.type != PF_ADDR_RANGE and self.mask:
            bits = nmtoc(self.mask, self.af)
            if not ((self.af == AF_INET and bits == 32) or (bits == 128)):
                s += "/%i" % bits

        return s

    def _is_any(self):
        """Return true if this address matches any host."""
        return (self.type == PF_ADDR_ADDRMASK and self.addr is None)

    def __str__(self):
        return self._to_string()

    def __eq__(self, a):
        if (self.type != a.type or self.af != a.af):
            return False

        if self.type == PF_ADDR_DYNIFTL:
            return (self.ifname == a.ifname and
                    self.mask   == a.mask   and
                    self.iflags == a.iflags)
        elif self.type == PF_ADDR_TABLE:
            return (self.tblname == a.tblname)
        elif self.type == PF_ADDR_ADDRMASK:
            return (self.addr == a.addr and
                    self.mask == a.mask)
        elif self.type == PF_ADDR_RTLABEL:
            return (self.rtlabelname == a.rtlabelname)
        elif self.type == PF_ADDR_RANGE:
            return (self.addr == a.addr)

        return True

    def __ne__(self, a):
        return not self.__eq__(a)


# PFRuleAddr class #############################################################
class PFRuleAddr:
    """Class representing an address/port pair."""

    def __init__(self, addr=None, port=None, neg=False, **kw):
        """Check arguments and initialize instance attributes."""
        if isinstance(addr, pf_rule_addr):
            self.addr = PFAddr(addr.addr, kw['af'])
            self.port = PFPort(tuple(map(ntohs, addr.port)),
                               kw['proto'], addr.port_op)
            self.neg  = bool(addr.neg)
            return
        elif isinstance(addr, PFAddr):
            self.addr = addr
        elif addr is None:
            self.addr = PFAddr()
        else:
            raise TypeError("'addr' must be a PFAddr instance")

        if isinstance(port, PFPort):
            self.port = port
        elif port is None:
            self.port = PFPort()
        else:
            raise TypeError("'port' must be a PFPort instance")

        self.neg = bool(neg)

    def _to_struct(self):
        """Convert this instance to a pf_rule_addr structure."""
        a = pf_rule_addr()

        a.addr    = self.addr._to_struct()
        a.port    = tuple(map(htons, self.port.num))
        a.port_op = self.port.op
        a.neg     = int(self.neg)

        return a

    def _to_string(self):
        """Return the string representation of the address/port pair."""
        s = ("! %s" if self.neg else "%s") % self.addr
        p = "%s" % self.port
        if p:
            s += (":" if self.port.op == PF_OP_NONE else " port ") + p

        return s

    def __str__(self):
        return self._to_string()

    def __eq__(self, a):
        return (self.addr == a.addr and
                self.port == a.port and
                self.neg  == a.neg)

    def __ne__(self, a):
        return not self.__eq__(a)


# PFPool class #################################################################
class PFPool:
    """Class representing an address pool."""

    def __init__(self, id, *addrs, **kw):
        """Check arguments and initialize instance attributes."""
        if isinstance(id, int):
            self.id = id
        else:
            raise TypeError("'id' must be an integer")

        try:
            p = kw.pop("pool")
        except KeyError:
            p = pf_pool()
            if self.id == PF_NAT:
                p.proxy_port = (PF_NAT_PROXY_PORT_LOW, PF_NAT_PROXY_PORT_HIGH)
        self._from_struct(p)

        self._from_kw(**kw)
        self._addrs = []
        self.append(*addrs)

    def _from_struct(self, p):
        """Initalize a new instance from a pf_pool structure."""
        self.key        = "0x%08x%08x%08x%08x" % tuple(p.key.key32[:])
        self.tblidx     = p.tblidx
        self.proxy_port = PFPort(tuple(p.proxy_port), op=p.port_op)
        self.opts       = p.opts

    def _from_kw(self, **kw):
        """Initalize a new instance by specifying its attributes values."""
        for k, v in kw.iteritems():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                raise ValueError("Unexpected keyword argument '%s'" % k)

    def _to_struct(self):
        """Convert a PFPool object to a pf_pool structure."""
        p = pf_pool()

        p.proxy_port = self.proxy_port.num
        p.port_op = self.proxy_port.op
        p.opts = self.opts

        return p

    def _to_string(self):
        """Return the string representation of the address pool."""
        p1, p2 = self.proxy_port.num

        addrs = []
        for a in self._addrs:
            if self.id == PF_PASS and a.addr.addr:
                addrs.append("(%s %s)" % (a.ifname, a))
            else:
                addrs.append("%s" % a)

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

        if (self.id == PF_NAT) and (p1 == p2 == 0):
            s += " static-port"

        return s

    def append(self, *addrs):
        """Append one or more addresses to the pool."""
        for addr in addrs:
            if isinstance(addr, PFAddr):
                self._addrs.append(addr)
            else:
                self._addrs.append(PFAddr(addr))

    def remove(self, *addrs):
        """Remove one or more addresses from the pool."""
        for addr in addrs:
            if isinstance(addr, PFAddr):
                self._addr.remove(addr)
            else:
                self._addrs.remove(PFAddr(addr))

    def get_addrs(self):
        """Return the list of the addresses in the pool."""
        return self._addrs

    def clear(self):
        """Remove all addresses from the pool."""
        self._addrs = []

    def __str__(self):
        return self._to_string()


# PFRule class #################################################################
class PFRule:
    """Class representing a Packet Filter rule."""

    def __init__(self, rule=None, **kw):
        """Check arguments and initialize instance attributes."""
        if isinstance(rule, pf_rule):
            self._from_struct(rule)
        elif isinstance(rule, basestring):
            self._from_string(rule)
        elif rule is None:
            self._from_struct(pf_rule(rtableid=-1))
        else:
            raise TypeError("'rule' must be a pf_rule structure or a string")

        self._from_kw(**kw)

    def _from_struct(self, r):
        """Initalize a new instance from a pf_rule structure."""
        self.src               = PFRuleAddr(r.src, af=r.af, proto=r.proto)
        self.dst               = PFRuleAddr(r.dst, af=r.af, proto=r.proto)
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
        self.states_cur        = r.states_cur
        self.states_tot        = r.states_tot
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
        self.uid               = PFUid(r.uid)
        self.gid               = PFGid(r.gid)
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
        ###self.divert            = 

    def _from_string(self, r):
        """Initalize a new instance from a string."""
        raise NotImplementedError

    def _from_kw(self, **kw):
        """Initalize a new instance by specifying its attributes values."""
        for k, v in kw.iteritems():
            if hasattr(self, k):
                setattr(self, k, v)
            else:
                raise TypeError("Unexpected keyword argument '%s'" % k)

    def _to_struct(self):
        """Convert a PFRule object to a pf_rule structure."""
        r = pf_rule()

        r.src               = self.src._to_struct()
        r.dst               = self.dst._to_struct()
        r.label             = self.label
        r.ifname            = self.ifname
        r.qname             = self.qname
        r.pqname            = self.pqname
        r.tagname           = self.tagname
        r.match_tagname     = self.match_tagname
        r.overload_tblname  = self.overload_tblname
        r.evaluations       = self.evaluations
        r.packets           = self.packets
        r.bytes             = self.bytes
        r.os_fingerprint    = self.os_fingerprint
        r.rtableid          = self.rtableid
        r.timeout           = self.timeout
        r.states_cur        = self.states_cur
        r.states_tot        = self.states_tot
        r.max_states        = self.max_states
        r.src_nodes         = self.src_nodes
        r.max_src_nodes     = self.max_src_nodes
        r.max_src_states    = self.max_src_states
        r.max_src_conn      = self.max_src_conn
        r.max_src_conn_rate = self.max_src_conn_rate
        r.qid               = self.qid
        r.pqid              = self.pqid
        r.rt_listid         = self.rt_listid
        r.nr                = self.nr
        r.prob              = self.prob
        r.cuid              = self.cuid
        r.cpid              = self.cpid
        r.return_icmp       = self.return_icmp
        r.return_icmp6      = self.return_icmp6
        r.max_mss           = self.max_mss
        r.tag               = self.tag
        r.match_tag         = self.match_tag
        r.uid               = self.uid._to_struct()
        r.gid               = self.gid._to_struct()
        r.rule_flag         = self.rule_flag
        r.action            = self.action
        r.direction         = self.direction
        r.log               = self.log
        r.logif             = self.logif
        r.quick             = int(self.quick)
        r.ifnot             = int(self.ifnot)
        r.match_tag_not     = int(self.match_tag_not)
        r.natpass           = int(self.natpass)
        r.keep_state        = self.keep_state
        r.af                = self.af
        r.proto             = self.proto
        r.type              = self.type
        r.code              = self.code
        r.flags             = sum([1 << "FSRPAUEW".find(f) for f in self.flags])
        r.flagset           = sum([1 << "FSRPAUEW".find(f) for f in self.flagset])
        r.min_ttl           = self.min_ttl
        r.allow_opts        = int(self.allow_opts)
        r.rt                = self.rt
        r.return_ttl        = self.return_ttl
        r.tos               = self.tos
        r.anchor_relative   = self.anchor_relative
        r.anchor_wildcard   = self.anchor_wildcard
        r.flush             = self.flush
        ###r.divert            = 

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
            if self.name:
                s = pf_anchors[self.action]
                if not self.name.startswith("_"):
                    s += " \"%s\"" % self.name
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

        if self.src.addr._is_any() and self.dst.addr._is_any() and \
           not self.src.neg and not self.dst.neg               and \
           not (self.src.port.op or self.src.port.num[0])      and \
           not (self.dst.port.op or self.dst.port.num[0])      and \
           self.os_fingerprint == PF_OSFP_ANY:
            s += " all"
        else:
            s += " from %s" % self.src
            #if self.os_fingerprint != PF_OSFP_ANY:
            s += " to %s" % self.dst

        if self.uid.op:
            s += " user %s" % self.uid
        if self.gid.op:
            s += " group %s" % self.gid

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
        if self.rule_flag & PFRULE_SET_TOS:
            s += " set-tos 0x%2.2x" % self.set_tos
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

        # divert

        if not isinstance(self, PFRuleset) and \
           self.action in (PF_NAT, PF_BINAT, PF_RDR):
            s += " -> %s" % self.rpool

        return s

    def __str__(self):
        return self._to_string()


# PFRuleset class ##############################################################
class PFRuleset(PFRule):
    """Class representing a Packet Filter ruleset or anchor."""

    def __init__(self, name="", rule=None, **kw):
        """Check arguments and initialize instance attributes."""
        PFRule.__init__(self, rule, **kw)

        if not isinstance(name, basestring):
            raise TypeError("'name' must be a string")
        self.name = name

        self._rules = {PF_RULESET_NAT:    [],
                       PF_RULESET_RDR:    [],
                       PF_RULESET_BINAT:  [],
                       PF_RULESET_SCRUB:  [],
                       PF_RULESET_FILTER: []}

    def append(self, action, *rules):
        """Append one or more rules to the rules of type 'action'."""
        if rules != filter(lambda r: isinstance(r, PFRule), rules):
            raise TypeError("'rules' must be PFRule or PFRuleset instances")

        try:
            self._rules[action].extend(rules)
        except KeyError:
            raise ValueError("'action' must be a PF_RULESET_* constant")

    def insert(self, action, index, *rules):
        """Insert one or more rules of type 'action' before 'index'."""
        if rules != filter(lambda r: isinstance(r, PFRule), rules):
            raise TypeError("'rules' must be PFRule or PFRuleset instances")

        try:
            self._rules[action] = self._rules[action][:index] + \
                                  list(rules) + self._rules[action][index:]
        except KeyError:
            raise ValueError("'action' must be a PF_RULESET_* constant")

    def remove(self, action, index=-1):
        """Remove the rule of type 'action' at 'index'."""
        try:
            self._rules[action].pop(index)
        except KeyError:
            raise ValueError("'action' must be a PF_RULESET_* constant")

    def clear(self, action=None):
        """Clear all rules or rules of type 'action' (if specified)."""
        if action is None:
            for a in self._rules.keys():
                self.clear(a)
        else:
            try:
                self._rules[action] = []
            except KeyError:
                raise ValueError("'action' must be a PF_RULESET_* constant")

    def get_rules(self, action=None):
        """Return the rules in this ruleset.

        If an 'action' is specified, return the list of rules for that action;
        otherwise, return a dictionary containing all the rules.
        """
        if action is None:
            return self._rules

        try:
            return self._rules[action]
        except KeyError:
            raise ValueError("'action' must be a PF_RULESET_* constant")

    def _to_string(self):
        """Return the string representation of the ruleset."""
        rulesets = (PF_RULESET_NAT, PF_RULESET_RDR, PF_RULESET_BINAT,
                    PF_RULESET_SCRUB, PF_RULESET_FILTER)

        return "\n".join([PFRule._to_string(rule) for r in rulesets
                                                  for rule in self._rules[r]])
