"""Classes representing the entries in the firewall's state table."""

from socket import *
from ctypes import *
from struct import *

from pf.constants import *
from pf._struct import *
from pf._base import PFObject
from pf._utils import getprotobynumber, tcpstates, udpstates
from pf.rule import PFAddr, PFPort


__all__ = ['PFStatePeer',
           'PFStateKey',
           'PFState']


class PFStatePeer(PFObject):
    """Represents a connection endpoint."""

    _struct_type = pfsync_state_peer

    def __init__(self, peer):
        """Check argument and initialize class attributes."""
        super(PFStatePeer, self).__init__(peer)

    def _from_struct(self, p):
        """Initialize class attributes from a pfsync_state_peer structure."""
        self.seqlo       = ntohl(p.seqlo)
        self.seqhi       = ntohl(p.seqhi)
        self.seqdiff     = ntohl(p.seqdiff)
        self.max_win     = p.max_win
        self.mss         = p.mss
        self.state       = p.state
        self.wscale      = p.wscale

        self.pfss_flags  = p.scrub.pfss_flags
        self.pfss_ttl    = p.scrub.pfss_ttl
        self.scrub_flag  = p.scrub.scrub_flag
        self.pfss_ts_mod = p.scrub.pfss_ts_mod


class PFStateKey(PFObject):
    """Represents a state key."""

    _struct_type = pfsync_state_key

    def __init__(self, key, af):
        """Check argument and initialize class attributes."""
        self.af = af
        super(PFStateKey, self).__init__(key)

    def _from_struct(self, k):
        """Initialize class attributes from a pfsync_state_key structure."""
        a = (pf_addr_wrap(), pf_addr_wrap())
        

        a[0].v.a.addr, a[1].v.a.addr = k.addr
        mask = '\xff' * {AF_INET: 4, AF_INET6: 16}[self.af]
        memmove(a[0].v.a.mask.v6, c_char_p(mask), len(mask))
        memmove(a[1].v.a.mask.v6, c_char_p(mask), len(mask))

        self.addr    = (PFAddr(a[0], self.af), PFAddr(a[1], self.af))
        self.port    = (PFPort(ntohs(k.port[0])), PFPort(ntohs(k.port[1])))
        self.rdomain = ntohs(k.rdomain)


class PFState(PFObject):
    """Represents an entry in Packet Filter's state table."""

    _struct_type = pfsync_state

    def __init__(self, state):
        """Check argument and initialize class attributes."""
        super(PFState, self).__init__(state)

    def _from_struct(self, s):
        """Initialize class attributes from a pfsync_state structure."""
        self.id              = unpack("Q", pack(">Q", s.id))[0]
        self.ifname          = s.ifname

        a                    = pf_addr_wrap()
        a.v.a.addr           = s.rt_addr
        self.rt_addr         = PFAddr(a, s.af)

        self.rule            = ntohl(s.rule)
        self.anchor          = ntohl(s.anchor)
        self.nat_rule        = ntohl(s.nat_rule)
        self.creation        = ntohl(s.creation)
        self.expire          = ntohl(s.expire)

        p = unpack('>IIII', string_at(addressof(s.packets), sizeof(s.packets)))
        self.packets         = ((p[0] << 32 | p[1]), (p[2] << 32 | p[3]))
        b = unpack('>IIII', string_at(addressof(s.bytes), sizeof(s.bytes)))
        self.bytes           = ((b[0] << 32 | b[1]), (b[2] << 32 | b[3]))

        self.creatorid       = ntohl(s.creatorid) & 0xffffffff
        self.rtableid        = s.rtableid
        selfmax_mss          = s.max_mss
        self.af              = s.af
        self.proto           = s.proto
        self.direction       = s.direction
        self.log             = s.log
        self.timeout         = s.timeout
        self.sync_flags      = s.sync_flags
        self.updates         = s.updates
        self.min_ttl         = s.min_ttl
        self.set_tos         = s.set_tos
        self.state_flags     = s.state_flags

        if self.direction == PF_OUT:
            self.src         = PFStatePeer(s.src)
            self.dst         = PFStatePeer(s.dst)
            self.sk          = PFStateKey(s.key[PF_SK_STACK], s.af)
            self.nk          = PFStateKey(s.key[PF_SK_WIRE], s.af)
            if self.proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
                self.sk.port = (self.nk.port[0], self.sk.port[1])
        else:
            self.src         = PFStatePeer(s.dst)
            self.dst         = PFStatePeer(s.src)
            self.sk          = PFStateKey(s.key[PF_SK_WIRE], s.af)
            self.nk          = PFStateKey(s.key[PF_SK_STACK], s.af)
            if self.proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
                self.sk.port = (self.sk.port[0], self.nk.port[1])

    def _to_string(self):
        """Return a string representing the state."""
        sk, nk   = self.sk, self.nk
        sp       = (sk.port[0].num[0], sk.port[1].num[0])
        np       = (nk.port[0].num[0], nk.port[1].num[0])
        src, dst = self.src, self.dst
        afto     = (nk.af != sk.af)

        s  = "{.ifname} ".format(self)
        s += "{} ".format(getprotobynumber(self.proto) or self.proto)

        s += "{0.addr[1]}:{0.port[1]}".format(nk)
        if afto or (nk.addr[1] != sk.addr[1]) or (np[1] != sp[1]) or \
           (nk.rdomain != sk.rdomain):
            i = int(not afto)
            s += " ({}:{})".format(sk.addr[i], sk.port[i])

        if self.direction == PF_OUT or (afto and self.direction == PF_IN):
            s += " -> "
        else:
            s += " <- "

        s += "{0.addr[0]}:{0.port[0]}".format(nk)
        if afto or (nk.addr[1] != nk.addr[1]) or (np[1] != sp[1]) or \
           (nk.rdomain != sk.rdomain):
            i = int(afto)
            s += " ({}:{})".format(sk.addr[i], sk.port[i])

        s += "       "
        if self.proto == IPPROTO_TCP:
            if (src.state <= TCPS_TIME_WAIT and
                dst.state <= TCPS_TIME_WAIT):
                s += "{}:{}".format(tcpstates[src.state],
                                      tcpstates[dst.state])
            elif (src.state == PF_TCPS_PROXY_SRC or
                  dst.state == PF_TCPS_PROXY_SRC):
                s += "PROXY:SRC"
            elif (src.state == PF_TCPS_PROXY_DST or
                  dst.state == PF_TCPS_PROXY_DST):
                s += "PROXY:DST"
            else:
                s += "<BAD STATE LEVELS {.state}:{.state}>".format(src, dst)

            s += "\n"
            for p in src, dst:
                s += "   [{.seqlo} + {}]".format(p, (p.seqhi - p.seqlo))
                if p.seqdiff:
                    s += "(+{.seqdiff})".format(p)
                if src.wscale and dst.wscale:
                    s += " wscale {}".format(p.wscale & PF_WSCALE_MASK)

        elif (self.proto == IPPROTO_UDP  and
              src.state < PFUDPS_NSTATES and dst.state < PFUDPS_NSTATES) or \
             (self.proto not in (IPPROTO_ICMP, IPPROTO_ICMPV6) and
              src.state < PFOTHERS_NSTATES and dst.state < PFOTHERS_NSTATES):
            s += "{}:{}".format(states[src.state], states[dst.state])
        else:
            s += "{.state}:{.state}".format(src, dst)

        hrs, sec = divmod(self.creation, 60)
        hrs, min = divmod(hrs, 60)
        s += "\n   age {:02d}:{:02d}:{:02d}".format(hrs, min, sec)

        hrs, sec = divmod(self.expire, 60)
        hrs, min = divmod(hrs, 60)
        s += ", expires in {:02d}:{:02d}:{:02d}".format(hrs, min, sec)

        s += ", {0.packets[0]}:{0.packets[1]} pkts".format(self)
        s += ", {0.bytes[0]}:{0.bytes[1]} bytes".format(self)

        if self.anchor != 0xffffffff:
            s += ", anchor {0.anchor}" .format(self)
        if self.rule != 0xffffffff:
            s += ", rule {0.rule}".format(self)
        if self.state_flags & PFSTATE_SLOPPY:
            s += ", sloppy"
        if self.state_flags & PFSTATE_PFLOW:
            s += ", pflow"
        if self.sync_flags & PFSYNC_FLAG_SRCNODE:
            s += ", source-track"
        if self.sync_flags & PFSYNC_FLAG_NATSRCNODE:
            s += ", sticky-address\n"

        s += "\n   id: {0.id:016x} creatorid: {0.creatorid:08x}".format(self)
        if self.sync_flags & PFSTATE_NOSYNC:
            s += " (no-sync)"

        return s
