"""Classes to represent Packet Filter Rules."""

from socket import *
from ctypes import *
import re
import pwd
import grp

from pf.exceptions import PFError
from pf.constants import *
from pf._struct import *
from pf._base import PFObject
from pf._utils import *
from pf.table import PFTable


__all__ = ['PFUid',
           'PFGid',
           'PFPort',
           'PFAddr',
           'PFRuleAddr',
           'PFPool',
           'PFRule',
           'PFRuleset']


# Helper functions
def azero(seq):
    """Return True if all numbers in 'seq' are 0s."""
    return not filter(None, seq)


class PFOp(PFObject):
    """Class representing a generic comparison operation."""

    def __init__(self, num=None, op=PF_OP_NONE):
        """Check arguments and initialize instance attributes."""
        self.op = op

        if isinstance(num, basestring) or isinstance(num, Structure):
            super(PFOp, self).__init__(num)
        elif num is None:
            self.num = (0, 0)
        elif isinstance(num, int):
            self.num = (num, 0)
        elif isinstance(num, tuple):
            self.num = num

    def _from_struct(self, operation):
        """Initalize a new instance from a structure."""
        raise NotImplementedError

    def _from_string(self, operation):
        """Initalize a new instance from a string."""
        op_re = "(?:(?P<n1>[0-9]+)?\s*"                  + \
                   "(?P<op>=|!=|<>|><|<|<=|>|>=|:))?\s*" + \
                "(?P<n2>[0-9a-z-]+)?"

        m = re.compile(op_re).match(operation)
        if not m:
            raise ValueError("Could not parse string: {}".format(operation))

        self.op = pf_ops[m.group("op")] if m.group("op") else PF_OP_EQ

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
            n1 = self._num_to_str(n1)

        s = {PF_OP_NONE: "{0}",
             PF_OP_IRG:  "{0} >< {1}",
             PF_OP_XRG:  "{0} <> {1}",
             PF_OP_EQ:   "= {0}",
             PF_OP_NE:   "!= {0}",
             PF_OP_LT:   "< {0}",
             PF_OP_LE:   "<= {0}",
             PF_OP_GT:   "> {0}",
             PF_OP_GE:   ">= {0}",
             PF_OP_RRG:  "{0}:{1}"}[self.op]

        return s.format(n1, n2)

    def _num_to_str(self, n):
        """Convert a numeric operand to a string."""
        raise NotImplementedError

    def _str_to_num(self, s):
        """Convert a string to a numeric operand."""
        raise NotImplementedError

    def __eq__(self, operation):
        return (self.num == operation.num and self.op == operation.op)

    def __ne__(self, operation):
        return not self.__eq__(operation)


class PFUid(PFOp):
    """Class representing a user ID."""

    _struct_type = pf_rule_uid

    def __init__(self, num=None, op=PF_OP_NONE):
        """Check arguments and initialize instance attributes."""
        super(PFUid, self).__init__(num, op)

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

    _struct_type = pf_rule_gid

    def __init__(self, num=None, op=PF_OP_NONE):
        """Check arguments and initialize instance attributes."""
        super(PFGid, self).__init__(num, op)

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


class PFPort(PFOp):
    """Class representing a TCP/UDP port."""

    def __init__(self, num=None, proto=None, op=PF_OP_NONE):
        """Check arguments and initialize instance attributes."""
        self.proto = proto
        super(PFPort, self).__init__(num, op)

    def _num_to_str(self, n):
        """Convert a numeric port to a service name."""
        return n
        #try:
        #    return getservbyport(n, getprotobynumber(self.proto))
        #except (TypeError, error):
        #    return n

    def _str_to_num(self, s):
        """Convert a service name to a numeric port."""
        return getservbyname(s, getprotobynumber(self.proto))

    def __eq__(self, p):
        return (self.num   == p.num and
                self.op    == p.op  and
                self.proto == p.proto)


class PFAddr(PFObject):
    """Class representing an address."""

    _struct_type = pf_addr_wrap

    def __init__(self, addr=None, af=AF_UNSPEC, **kw):
        """Check arguments and initialize instance attributes."""
        self.af = af

        if addr is None:
            t = (kw["type"] if kw.has_key("type") else PF_ADDR_ADDRMASK)
            addr = pf_addr_wrap(type=t)

        super(PFAddr, self).__init__(addr, **kw)

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
                  "(?P<if>\((?P<ifname>[a-z]+[0-9]*)"                   + \
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
            raise ValueError("Could not parse address: {}".format(a))

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
                    self.mask = ctonm(int(m.group("ifmask")), self.af)
                else:
                    self.mask = ctonm(b, self.af)
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
                self.mask = ctonm(int(m.group("mask4")), self.af)
            else:
                self.mask = ctonm(32, self.af)
        elif m.group("ipv6"):
            self.af = AF_INET6
            self.type = PF_ADDR_ADDRMASK
            self.addr = m.group("ipv6")
            if m.group("mask6"):
                self.mask = ctonm(int(m.group("mask6")), self.af)
            else:
                self.mask = ctonm(128, self.af)

    def _to_struct(self):
        """Convert this instance to a pf_addr_wrap structure."""
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
            s = "({.ifname}".format(self)
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
            return "<{.tblname}>".format(self)
        elif self.type == PF_ADDR_ADDRMASK:
            s = self.addr or "any"
        elif self.type == PF_ADDR_NOROUTE:
            return "no-route"
        elif self.type == PF_ADDR_URPFFAILED:
            return "urpf-failed"
        elif self.type == PF_ADDR_RTLABEL:
            return "route \"{.rtlabelname}\"".format(self)
        elif self.type == PF_ADDR_RANGE:
            s = "{0.addr[0]} - {0.addr[1]}".format(self)
        else:
            return "?"

        if self.type != PF_ADDR_RANGE and self.mask:
            bits = nmtoc(self.mask, self.af)
            if not ((self.af == AF_INET and bits == 32) or (bits == 128)):
                s += "/{}".format(bits)

        return s

    def _is_any(self):
        """Return true if this address matches any host."""
        return (self.type == PF_ADDR_ADDRMASK and self.addr is None)

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


class PFRuleAddr(PFObject):
    """Class representing an address/port pair."""

    _struct_type = pf_rule_addr

    def __init__(self, addr=None, port=None, neg=False, **kw):
        """Check arguments and initialize instance attributes."""
        if isinstance(addr, self._struct_type):
            self.addr   = PFAddr(addr.addr, kw['af'])
            self.port   = PFPort(tuple(map(ntohs, addr.port)),
                                 kw['proto'], addr.port_op)
            self.neg    = bool(addr.neg)
            self.weight = addr.weight
        else:
            self.addr   = addr or PFAddr()
            self.port   = port or PFPort()
            self.neg    = bool(neg)
            self.weight = 0

    def _to_struct(self):
        """Convert this instance to a pf_rule_addr structure."""
        a = pf_rule_addr()

        a.addr    = self.addr._to_struct()
        a.port    = tuple(map(htons, self.port.num))
        a.port_op = self.port.op
        a.neg     = int(self.neg)
        a.weight  = self.weight

        return a

    def _to_string(self):
        """Return the string representation of the address/port pair."""
        s = ("! {.addr}" if self.neg else "{.addr}").format(self)
        p = "{.port}".format(self)
        if p:
            s += (":" if self.port.op == PF_OP_NONE else " port ") + p

        return s

    def __eq__(self, a):
        return (self.addr == a.addr and
                self.port == a.port and
                self.neg  == a.neg)

    def __ne__(self, a):
        return not self.__eq__(a)


class PFPool(PFObject):
    """Class representing an address pool."""

    _struct_type = pf_pool

    def __init__(self, id, pool, **kw):
        """Check arguments and initialize instance attributes."""
        self.id = id

        if isinstance(pool, PFAddr):
            self._af = pool.af
            p = pf_pool(addr=pool._to_struct())
            if self.id == PF_POOL_NAT:
                p.proxy_port = (PF_NAT_PROXY_PORT_LOW, PF_NAT_PROXY_PORT_HIGH)
        elif isinstance(pool, pf_pool):
            self._af = kw.pop("af", AF_UNSPEC)
            p = pool

        super(PFPool, self).__init__(p, **kw)

    def _from_struct(self, p):
        """Initalize a new instance from a pf_pool structure."""
        self.addr       = PFAddr(p.addr, self._af)
        self.key        = "{:#010x}{:08x}{:08x}{:08x}".format(*p.key.key32)
        self.counter    = p.counter
        self.ifname     = p.ifname
        self.tblidx     = p.tblidx
        self.states     = p.states
        self.curweight  = p.curweight
        self.weight     = p.weight
        self.proxy_port = PFPort(tuple(p.proxy_port), op=p.port_op)
        self.opts       = p.opts

    def _to_struct(self):
        """Convert a PFPool object to a pf_pool structure."""
        p = pf_pool()

        if self.addr._is_any():
            p.addr = PFAddr(type=PF_ADDR_NONE)._to_struct()
        else:
            p.addr       = self.addr._to_struct()
        p.ifname     = self.ifname
        p.states     = self.states
        p.curweight  = self.curweight
        p.weight     = self.weight
        p.proxy_port = self.proxy_port.num
        p.port_op    = self.proxy_port.op
        p.opts       = self.opts

        return p

    def _to_string(self):
        """Return the string representation of the address pool."""
        p1, p2 = self.proxy_port.num
        s = ""

        if self.ifname:
            if self.addr.addr is not None:
                s += "{.addr}@".format(self)
            s += self.ifname
        else:
            s += "{.addr}".format(self)

        if self.id == PF_POOL_NAT:
            if (p1, p2) != (PF_NAT_PROXY_PORT_LOW, PF_NAT_PROXY_PORT_HIGH) and \
               (p1, p2) != (0, 0):
                if p1 == p2:
                    s += " port {}".format(p1)
                else:
                    s += " port {}:{}".format(p1, p2)
        elif self.id == PF_POOL_RDR:
            if p1:
                s += " port {}".format(p1)
                if p2 and (p2 != p1):
                    s += ":{}".format(p2)

        opt = self.opts & PF_POOL_TYPEMASK
        if opt == PF_POOL_BITMASK:
            s += " bitmask"
        elif opt == PF_POOL_RANDOM:
            s += " random"
        elif opt == PF_POOL_SRCHASH:
            s += " source-hash {0.key}".format(self)
        elif opt == PF_POOL_ROUNDROBIN:
            s += " round-robin"
        elif opt == PF_POOL_LEASTSTATES:
            s += " least-states"

        if self.opts & PF_POOL_STICKYADDR:
            s += " sticky-address"

        if (self.id == PF_POOL_NAT) and (p1 == p2 == 0):
            s += " static-port"

        return s


class PFRule(PFObject):
    """Class representing a Packet Filter rule."""

    _struct_type = pf_rule

    def __init__(self, rule=None, **kw):
        """Check arguments and initialize instance attributes."""
        if rule is None:
            rule = pf_rule(rtableid=-1, onrdomain=-1)
        super(PFRule, self).__init__(rule, **kw)

    def _from_struct(self, r):
        """Initalize a new instance from a pf_rule structure."""
        self.src               = PFRuleAddr(r.src, af=r.af, proto=r.proto)
        self.dst               = PFRuleAddr(r.dst, af=r.af, proto=r.proto)
        #skip
        self.label             = r.label
        self.ifname            = r.ifname
        self.rcv_ifname        = r.rcv_ifname
        self.qname             = r.qname
        self.pqname            = r.pqname
        self.tagname           = r.tagname
        self.match_tagname     = r.match_tagname
        self.overload_tblname  = r.overload_tblname
        #entries

        self.nat               = PFPool(PF_POOL_NAT, r.nat, af=r.af)
        if self.nat.addr._is_any():
            self.nat = PFPool(PF_POOL_NAT, PFAddr(type=PF_ADDR_NONE))
        self.rdr               = PFPool(PF_POOL_RDR, r.rdr, af=r.af)
        if self.rdr.addr._is_any():
            self.rdr = PFPool(PF_POOL_RDR, PFAddr(type=PF_ADDR_NONE))
        self.route             = PFPool(PF_POOL_ROUTE, r.route, af=r.af)
        if self.route.addr._is_any():
            self.route = PFPool(PF_POOL_ROUTE, PFAddr(type=PF_ADDR_NONE))

        self.evaluations       = r.evaluations
        self.packets           = tuple(r.packets)
        self.bytes             = tuple(r.bytes)
        self.os_fingerprint    = r.os_fingerprint
        self.rtableid          = r.rtableid
        self.onrdomain         = r.onrdomain
        self.timeout           = list(r.timeout)
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
        self.scrub_flags       = r.scrub_flags
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
        self.set_tos           = r.set_tos
        self.anchor_relative   = r.anchor_relative
        self.anchor_wildcard   = r.anchor_wildcard
        self.flush             = r.flush
        self.set_prio          = tuple(r.set_prio)
        self.naf               = r.naf
        self.divert            = (None, None)
        self.divert_packet     = (None, None)
        if r.divert.port:
            if azero(r.divert.addr.v6):
                addr = None
            else:
                l = {AF_INET: 4, AF_INET6: 16}[self.af]
                addr = PFAddr(inet_ntop(r.af,
                                        string_at(addressof(r.divert.addr), l)))
            self.divert = (addr, PFPort(ntohs(r.divert.port)))
        if r.divert_packet.port:
            self.divert_packet = PFPort(ntohs(r.divert_packet.port))
        else:
            self.divert_packet = None

    def _to_struct(self):
        """Convert a PFRule object to a pf_rule structure."""
        r = pf_rule()

        r.src               = self.src._to_struct()
        r.dst               = self.dst._to_struct()
        #skip
        r.label             = self.label
        r.ifname            = self.ifname
        r.rcv_ifname        = self.rcv_ifname
        r.qname             = self.qname
        r.pqname            = self.pqname
        r.tagname           = self.tagname
        r.match_tagname     = self.match_tagname
        r.overload_tblname  = self.overload_tblname
        #entries
        r.nat               = self.nat._to_struct()
        r.rdr               = self.rdr._to_struct()
        r.route             = self.route._to_struct()
        r.evaluations       = self.evaluations
        r.packets           = self.packets
        r.bytes             = self.bytes
        r.os_fingerprint    = self.os_fingerprint
        r.rtableid          = self.rtableid
        r.onrdomain         = self.onrdomain
        for i, t in enumerate(self.timeout):
            r.timeout[i] = t
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
        r.keep_state        = self.keep_state
        r.af                = self.af
        r.proto             = self.proto
        r.type              = self.type
        r.code              = self.code
        r.flags             = sum([1<<"FSRPAUEW".find(f) for f in self.flags])
        r.flagset           = sum([1<<"FSRPAUEW".find(f) for f in self.flagset])
        r.min_ttl           = self.min_ttl
        r.allow_opts        = int(self.allow_opts)
        r.rt                = self.rt
        r.return_ttl        = self.return_ttl
        r.tos               = self.tos
        r.set_tos           = self.set_tos
        r.anchor_relative   = self.anchor_relative
        r.anchor_wildcard   = self.anchor_wildcard
        r.flush             = self.flush
        r.set_prio[:]       = self.set_prio
        r.naf               = self.naf
        if self.divert[0]:
            r.divert.addr   = self.divert[0]._to_struct().v.a.addr
        if self.divert[1]:
            r.divert.port   = htons(self.divert[1].num[0])
        if self.divert_packet:
            r.divert_packet.port = htons(self.divert_packet.num[0])

        return r

    def _to_string(self):
        """Return the string representation of the rule."""
        pf_actions = ("pass", "block", "scrub", "no scrub", "nat", "no nat",
                      "binat", "no binat", "rdr", "no rdr", "", "", "match")
        pf_anchors = ("anchor", "anchor", "anchor", "anchor", "nat-anchor",
                      "nat-anchor", "binat-anchor", "binat-anchor",
                      "rdr-anchor", "rdr-anchor")

        if self.action > PF_MATCH:
            s = "action({.action})".format(self)
        elif isinstance(self, PFRuleset):
            s = pf_anchors[self.action]
            if not self.name.startswith("_"):
                s += " \"{.name}\"".format(self)
        else:
            s = pf_actions[self.action]

        if self.action == PF_DROP:
            if self.rule_flag & PFRULE_RETURN:
                s += " return"
            elif self.rule_flag & PFRULE_RETURNRST:
                s += " return-rst"
                if self.return_ttl:
                    s += "(ttl {.return_ttl})".format(self)
            elif self.rule_flag & PFRULE_RETURNICMP:
                ic  = geticmpcodebynumber(self.return_icmp >> 8,
                                          self.return_icmp & 0xff, AF_INET)
                ic6 = geticmpcodebynumber(self.return_icmp6 >> 8,
                                          self.return_icmp6 & 0xff, AF_INET6)
                s += " return-icmp"
                if self.af == AF_INET:
                    s += "({})".format(ic or self.return_icmp & 0xff)
                elif self.af == AF_INET6:
                    s += "6({})".format(ic6 or self.return_icmp6 & 0xff)
                else:
                    s += "({}, {})".format((ic or self.return_icmp & 0xff),
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
                if self.log & PF_LOG_MATCHES:
                    l.append("matches")
                if self.log & PF_LOG_SOCKET_LOOKUP:
                    l.append("user")
                if self.logif:
                    l.append("to pflog{.logif}".format(self))
                s += " ({})".format(", ".join(l))

        if self.quick:
            s += " quick"

        if self.ifname and self.ifname != "all":
            # "on all" not printed because it would make
            # the rule not parseable by pfctl
            if self.ifnot:
                s += " on ! {.ifname}".format(self)
            else:
                s += " on {.ifname}".format(self)

        if self.onrdomain >= 0:
            if self.ifnot:
                s += " on ! rdomain {.onrdomain}".format(self)
            else:
                s += " on rdomain {.onrdomain}".format(self)

        if self.af:
            s += " inet" if (self.af == AF_INET) else " inet6"

        if self.proto:
            s += " proto {}".format(getprotobynumber(self.proto) or self.proto)

        if self.src.addr._is_any() and self.dst.addr._is_any() and \
           not self.src.neg and not self.dst.neg               and \
           not self.src.port.op and not self.dst.port.op       and \
           self.os_fingerprint == PF_OSFP_ANY:
            s += " all"
        else:
            s += " from {.src}".format(self)
            #if self.os_fingerprint != PF_OSFP_ANY:
            s += " to {.dst}".format(self)

        if self.rcv_ifname:
            s += " received on {.rcv_ifname}".format(self)
        if self.uid.op:
            s += " user {.uid}".format(self)
        if self.gid.op:
            s += " group {.gid}".format(self)

        if self.flags or self.flagset:
            s += " flags {0.flags}/{0.flagset}".format(self)
        elif self.action in (PF_PASS, PF_MATCH)     and \
             self.proto in (0, IPPROTO_TCP)         and \
             not (self.rule_flag & PFRULE_FRAGMENT) and \
             not isinstance(self, PFRuleset)        and \
             self.keep_state:
            s += " flags any"

        if self.type:
            it = geticmptypebynumber(self.type-1, self.af)
            if self.af != AF_INET6:
                s += " icmp-type"
            else:
                s += " icmp6-type"
            s += " {}".format(it or self.type-1)
            if self.code:
                ic = geticmpcodebynumber(self.type-1, self.code-1, self.af)
                s += " code {}".format(ic or self.code-1)

        if self.tos:
            s += " tos {.tos:#04x}".format(self)

        if self.scrub_flags & PFSTATE_SETMASK:
            opts = []
            if self.scrub_flags[0] != PFSTATE_SETPRIO:
                if self.set_prio[0] == self.set_prio[1]:
                    opts.append("prio {}".format(self.set_prio[0]))
                else:
                    opts.append("prio ({}, {})".format(*self.set_prio))
            if self.scrub_flags & PFSTATE_SETTOS:
                opts.append("tos {.set_tos:#04x}".format(self))
            s += " set ( {} )".format(", ".join(opts))

        has_opts = False
        if (self.max_states or self.max_src_nodes or self.max_src_states)  or \
           self.rule_flag & (PFRULE_NOSYNC|PFRULE_SRCTRACK|PFRULE_IFBOUND) or \
           self.rule_flag & (PFRULE_STATESLOPPY|PFRULE_PFLOW)              or \
           filter(None, self.timeout):
            has_opts = True

        if not self.keep_state and self.action == PF_PASS and \
           not isinstance(self, PFRuleset):
            s += " no state"
        elif (self.keep_state == PF_STATE_NORMAL) and has_opts:
            s += " keep state"
        elif self.keep_state == PF_STATE_MODULATE:
            s += " modulate state"
        elif self.keep_state == PF_STATE_SYNPROXY:
            s += " synproxy state"

        if self.prob:
            s += " probability {:.0f}%".format(self.prob*100.0/(UINT_MAX+1))

        if has_opts:
            opts = []
            if self.max_states:
                opts.append("max {.max_states}".format(self))
            if self.rule_flag & PFRULE_NOSYNC:
                opts.append("no-sync")
            if self.rule_flag & PFRULE_SRCTRACK:
                if self.rule_flag & PFRULE_RULESRCTRACK:
                    opts.append("source-track rule")
                else:
                    opts.append("source-track global")
            if self.max_src_states:
                opts.append("max-src-states {.max_src_states}".format(self))
            if self.max_src_conn:
                opts.append("max-src-conn {.max_src_conn}".format(self))
            if self.max_src_conn_rate[0]:
                opts.append("max-src-conn-rate " +
                            "{}/{}".format(*self.max_src_conn_rate))
            if self.max_src_nodes:
                opts.append("max-src-nodes {.max_src_nodes}".format(self))
            if self.overload_tblname:
                opt = "overload <{.overload_tblname}>".format(self)
                if self.flush:
                    opt += " flush"
                if self.flush & PF_FLUSH_GLOBAL:
                    opt += " global"
                opts.append(opt)
            if self.rule_flag & PFRULE_IFBOUND:
                opts.append("if-bound")
            if self.rule_flag & PFRULE_STATESLOPPY:
                opts.append("sloppy")
            if self.rule_flag & PFRULE_PFLOW:
                opts.append("pflow")
            for i, t in enumerate(self.timeout):
                if t:
                    tm = [k for (k, v) in pf_timeouts.iteritems() if v == i][0]
                    opts.append("{} {}".format(tm, t))

            s += " ({})".format(", ".join(opts))

        if self.rule_flag & PFRULE_FRAGMENT:
            s += " fragment"

        if self.scrub_flags >= PFSTATE_NODF or self.min_ttl or self.max_mss:
            opts = []
            if self.scrub_flags & PFSTATE_NODF:
                opts.append("no-df")
            if self.scrub_flags & PFSTATE_RANDOMID:
                opts.append("random-id")
            if self.min_ttl:
                opts.append("min-ttl {.min_ttl}".format(self))
            if self.scrub_flags & PFSTATE_SCRUB_TCP:
                opts.append("reassemble tcp")
            if self.max_mss:
                opts.append("max_mss {.max_mss}".format(self))
            s += " scrub ({})".format(" ".join(opts))

        if self.allow_opts:
            s += " allow-opts"
        if self.label:
            s += " label \"{.label}\"".format(self)
        if self.rule_flag & PFRULE_ONCE:
            s += " once"

        if self.qname and self.pqname:
            s += " queue({0.qname}, {0.pqname})".format(self)
        elif self.qname:
            s += " queue {.qname}".format(self)

        if self.tagname:
            s += " tag {.tagname}".format(self)
        if self.match_tagname:
            if self.match_tag_not:
                s += " !"
            s += " tagged {.match_tagname}".format(self)

        if self.rtableid != -1:
            s += " rtable {.rtableid}".format(self)

        if self.divert[1]:
            if not self.divert[0]:
                s += " divert-reply"
            else:
                s += " divert-to {} port {}".format(*self.divert)

        if self.divert_packet:
            s += " divert-packet port {.divert_packet}".format(self)

        if not isinstance(self, PFRuleset):
            if self.nat.addr.type != PF_ADDR_NONE:
                if self.rule_flag & PFRULE_AFTO:
                    af = " inet" if (self.naf == AF_INET) else " inet6"
                    s += " af-to {} from {.nat}".format(af, self)
                    if self.rdr.addr.type != PF_ADDR_NONE:
                        s += " to {.rdr}".format(self)
                else:
                    s += " nat-to {.nat}".format(self)
            elif self.rdr.addr.type != PF_ADDR_NONE:
                s += " rdr-to {.rdr}".format(self)

        if self.rt == PF_ROUTETO:
            s += " route-to {.route}".format(self)
        elif self.rt == PF_REPLYTO:
            s += " reply-to {.route}".format(self)
        elif self.rt == PF_DUPTO:
            s += " dup-to {.route}".format(self)

        return s


class PFRuleset(PFRule):
    """Class representing a Packet Filter ruleset or anchor."""

    def __init__(self, name="", rule=None, **kw):
        """Check arguments and initialize instance attributes."""
        self.name    = name
        self._altqs  = []
        self._tables = []
        self._rules  = []
        super(PFRuleset, self).__init__(rule, **kw)

    def append(self, *items):
        """Append one or more rules and/or tables and/or altqs."""
        self._rules.extend(filter(lambda i: isinstance(i, PFRule), items))
        self._tables.extend(filter(lambda i: isinstance(i, PFTable), items))

    def insert(self, index, rule):
        """Insert a 'rule' before 'index'."""
        self._rules.insert(index, rule)

    def remove(self, index=-1):
        """Remove the rule at 'index'."""
        self._rules.pop(index)

    @property
    def rules(self):
        """Return the rules in this ruleset."""
        return self._rules

    @property
    def tables(self):
        """Return the tables in this ruleset."""
        return self._tables

    def _to_string(self):
        """Return the string representation of the ruleset."""
        return "\n".join([PFRule._to_string(rule) for rule in self._rules])
