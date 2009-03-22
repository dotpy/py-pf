"""Classes representing the entries in the firewall's state table."""


from socket import *
from ctypes import *
from struct import *

from PF import *
from PF._PFStruct import *
from PF.PFUtils import *


__all__ = ['PFStatePeer',
           'PFStateKey',
           'PFState']


# Dictionaries for mapping constants to strings ################################
tcpstates = {TCPS_CLOSED:       "CLOSED",
             TCPS_LISTEN:       "LISTEN",
             TCPS_SYN_SENT:     "SYN_SENT",
             TCPS_SYN_RECEIVED: "SYN_RCVD",
             TCPS_ESTABLISHED:  "ESTABLISHED",
             TCPS_CLOSE_WAIT:   "CLOSE_WAIT",
             TCPS_FIN_WAIT_1:   "FIN_WAIT_1",
             TCPS_CLOSING:      "CLOSING",
             TCPS_LAST_ACK:     "LAST_ACK",
             TCPS_FIN_WAIT_2:   "FIN_WAIT_2",
             TCPS_TIME_WAIT:    "TIME_WAIT"}

states    = {PFUDPS_NO_TRAFFIC: "NO_TRAFFIC",
             PFUDPS_SINGLE:     "SINGLE",
             PFUDPS_MULTIPLE:   "MULTIPLE"}


# PFStatePeer class ############################################################
class PFStatePeer:
    """Represents a connection endpoint."""

    def __init__(self, peer):
        """Check argument and initialize class attributes."""
        if not isinstance(peer, pfsync_state_peer):
            raise TypeError("'peer' must be a pfsync_state_peer structure")
        self._from_struct(peer)

    def _from_struct(self, p):
        """Initialize class attributes from a pfsync_state_peer structure."""
        self.seqlo       = p.seqlo
        self.seqhi       = p.seqhi
        self.seqdiff     = p.seqdiff
        self.max_win     = p.max_win
        self.mss         = p.mss
        self.state       = p.state
        self.wscale      = p.wscale

        self.pfss_flags  = p.scrub.pfss_flags
        self.pfss_ttl    = p.scrub.pfss_ttl
        self.scrub_flag  = p.scrub.scrub_flag
        self.pfss_ts_mod = p.scrub.pfss_ts_mod


class PFStateKey:
    """Represents a state key."""

    def __init__(self, key, af):
        """Check argument and initialize class attributes."""
        self.af = af

        if not isinstance(key, pfsync_state_key):
            raise TypeError("'state' must be a pfsync_state_key structure")

        self._from_struct(key)

    def _from_struct(self, k):
        """Initialize class attributes from a pfsync_state_key structure."""
        a = (pf_addr_wrap(), pf_addr_wrap())

        a[0].v.a.addr, a[1].v.a.addr = k.addr
        mask = '\xff' * {AF_INET: 4, AF_INET6: 16}[self.af]
        memmove(a[0].v.a.mask.v6, c_char_p(mask), len(mask))
        memmove(a[1].v.a.mask.v6, c_char_p(mask), len(mask))

        self.addr = (PFAddr(a[0], self.af), PFAddr(a[1], self.af))
        self.port = (PFPort(ntohs(k.port[0])), PFPort(ntohs(k.port[1])))


class PFState:
    """Represents an entry in Packet Filter's state table."""

    def __init__(self, state):
        """Check argument and initialize class attributes."""
        if not isinstance(state, pfsync_state):
            raise TypeError("'state' must be a pfsync_state structure")
        self._from_struct(state)

    def _from_struct(self, s):
        """Initialize class attributes from a pfsync_state structure."""
        id = unpack('>II', string_at(addressof(s.id), sizeof(s.id)))
        self.id          = id[0] << 32 | id[1]
        self.ifname      = s.ifname

        a                = pf_addr_wrap()
        a.v.a.addr       = s.rt_addr
        self.rt_addr     = PFAddr(a, s.af)

        self.rule        = ntohl(s.rule)
        self.anchor      = ntohl(s.anchor)
        self.nat_rule    = ntohl(s.nat_rule)
        self.creation    = ntohl(s.creation)
        self.expire      = ntohl(s.expire)

        p = unpack('>IIII', string_at(addressof(s.packets), sizeof(s.packets)))
        self.packets     = ((p[0] << 32 | p[1]), (p[2] << 32 | p[3]))
        b = unpack('>IIII', string_at(addressof(s.bytes), sizeof(s.bytes)))
        self.bytes       = ((b[0] << 32 | b[1]), (b[2] << 32 | b[3]))

        self.creatorid   = ntohl(s.creatorid) & 0xffffffff
        self.af          = s.af
        self.proto       = s.proto
        self.direction   = s.direction
        self.log         = s.log
        self.state_flags = s.state_flags
        self.timeout     = s.timeout
        self.sync_flags  = s.sync_flags
        self.updates     = s.updates

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

        s = "%s " % self.ifname
        s += "%s " % (getprotobynumber(self.proto) or self.proto)

        s += "%s" % nk.addr[1]
        if np[1]:
            s += (":%u" if self.af == AF_INET else "[%u]") % np[1]

        if (nk.addr[1] != sk.addr[1]) or (np[1] != sp[1]):
            s += " (%s" % sk.addr[1]
            if sp[1]:
                s += (":%u)" if self.af == AF_INET else "[%u])") % sp[1]

        s += (" -> " if self.direction == PF_OUT else " <- ")

        s += "%s" % nk.addr[0]
        if np[0]:
            s += (":%u" if self.af == AF_INET else "[%u]") % np[0]

        if (nk.addr[0] != sk.addr[0]) or (np[0] != sp[0]):
            s += " (%s" % sk.addr[0]
            if sp[0]:
                s += (":%u)" if self.af == AF_INET else "[%u])") % sp[0]

        s += "       "
        if self.proto == IPPROTO_TCP:
            if (src.state <= TCPS_TIME_WAIT and
                dst.state <= TCPS_TIME_WAIT):
                s += "%s:%s" % (tcpstates[src.state], tcpstates[dst.state])
            elif (src.state == PF_TCPS_PROXY_SRC or
                  dst.state == PF_TCPS_PROXY_SRC):
                s += "PROXY:SRC"
            elif (src.state == PF_TCPS_PROXY_DST or
                  dst.state == PF_TCPS_PROXY_DST):
                s += "PROXY:DST"
            else:
                s += "<BAD STATE LEVELS %u:%u>" % (src.state, dst.state)
        elif (self.proto == IPPROTO_UDP  and
              src.state < PFUDPS_NSTATES and dst.state < PFUDPS_NSTATES):
            s += "%s:%s" % (states[src.state], states[dst.state])
        elif (self.proto != IPPROTO_ICMP and
              src.state < PFOTHERS_NSTATES and dst.state < PFOTHERS_NSTATES):
            s += "%s:%s" % (states[src.state], states[dst.state])
        else:
            s += "%u:%u" % (src.state, dst.state)

        hrs, sec = divmod(self.creation, 60)
        hrs, min = divmod(hrs, 60)
        s += "\n   age %.2u:%.2u:%.2u" % (hrs, min, sec)

        hrs, sec = divmod(self.expire, 60)
        hrs, min = divmod(hrs, 60)
        s += ", expires in %.2u:%.2u:%.2u" % (hrs, min, sec)

        s += ", %u:%u pkts" % self.packets
        s += ", %u:%u bytes" % self.bytes

        if self.anchor != -1:
            s += ", anchor %u" % self.anchor
        if self.rule != -1:
            s += ", rule %u" % self.rule
        if self.state_flags & PFSTATE_SLOPPY:
            s += ", sloppy"
        if self.sync_flags & PFSYNC_FLAG_SRCNODE:
            s += ", source-track"
        if self.sync_flags & PFSYNC_FLAG_NATSRCNODE:
            s += ", sticky-address\n"

        s += "\n   id: %016x creatorid: %08x" % (self.id, self.creatorid)
        if self.sync_flags & PFSTATE_NOSYNC:
            s += " (no-sync)"

        return s

    def __str__(self):
        return self._to_string()
