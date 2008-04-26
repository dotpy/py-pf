"""Classes representing the entries in the firewall's state table."""


__all__ = ['PFState',
           'PFStatePeer']


from socket import *
from ctypes import memset

from _PFStruct import *
from PFConstants import *
from PFUtils import *
from PFRule import PFRuleAddr


class PFStatePeer:
    """Represents each of the two endpoints of the connection."""

    def __init__(self, peer):
        """Check argument and initialize class attributes"""
        if not isinstance(peer, pfsync_state_peer):
            raise TypeError, "'peer' must be a pfsync_state_peer structure"
        self._from_struct(peer)

    def _from_struct(self, p):
        """Initialize class attributes from a pfsync_state_peer structure"""
        self.seqlo       = p.seqlo
        self.seqhi       = p.seqhi
        self.seqdiff     = p.seqdiff
        self.max_win     = p.max_win
        self.mss         = p.mss
        self.state       = p.state
        self.wscale      = p.wscale
        self.pad         = p.pad

        self.pfss_flags  = p.scrub.pfss_flags
        self.pfss_ttl    = p.scrub.pfss_ttl
        self.scrub_flag  = p.scrub.scrub_flag
        self.pfss_ts_mod = p.scrub.pfss_ts_mod


class PFState:
    """Represents an entry in Packet Filter's state table"""

    def __init__(self, state):
        """Check argument and initialize class attributes"""
        if not isinstance(state, pfsync_state):
            raise TypeError, "'state' must be a pfsync_state structure"
        self._from_struct(state)

    def _from_struct(self, s):
        """Initialize class attributes from a pfsync_state structure"""
        self.id          = (s.id[0] << 32 | s.id[1])
        self.ifname      = s.ifname
        self.af          = s.af
        self.proto       = s.proto

        ra               = pf_rule_addr()
        memset(ra.addr.v.a.mask.addr32, 0xff, 16)

        ra.addr.v.a.addr = s.lan.addr
        ra.port[0]       = s.lan.port
        self.lan         = PFRuleAddr(ra, s.af, s.proto)

        ra.addr.v.a.addr = s.gwy.addr
        ra.port[0]       = s.gwy.port
        self.gwy         = PFRuleAddr(ra, s.af, s.proto)

        ra.addr.v.a.addr = s.ext.addr
        ra.port[0]       = s.ext.port
        self.ext         = PFRuleAddr(ra, s.af, s.proto)

        self.direction   = s.direction
        self.log         = s.log
        self.allow_opts  = s.allow_opts
        self.timeout     = s.timeout
        self.sync_flags  = s.sync_flags
        self.updates     = s.updates
        self.rule        = s.rule
        self.anchor      = s.anchor
        self.nat_rule    = s.nat_rule
        self.creation    = s.creation
        self.expire      = s.expire
        self.packets     = ((s.packets[0][0] << 32 | s.packets[0][1]),
                            (s.packets[1][0] << 32 | s.packets[1][1]))
        self.bytes       = ((s.bytes[0][0] << 32 | s.bytes[0][1]),
                            (s.bytes[1][0] << 32 | s.bytes[1][1]))
        self.creatorid   = ntohl(s.creatorid) & 0xffffffff

        if self.direction == PF_OUT:
            self.src     = PFStatePeer(s.src)
            self.dst     = PFStatePeer(s.dst)
        else:
            self.src     = PFStatePeer(s.dst)
            self.dst     = PFStatePeer(s.src)

    def _to_string(self):
        """Return a string representing the state"""
        s =  "%s " % self.ifname
        s += "%s " % (getprotobynumber(self.proto) or self.proto)

        if self.lan != self.gwy:
            nodes = (self.lan, self.gwy, self.ext)
        else:
            nodes = (self.gwy, self.ext)

        if self.direction == PF_OUT:
            s += " -> ".join(map(str, nodes))
        else:
            s += " <- ".join(map(str, nodes))

        s += "       "

        tcpstates = ("CLOSED",      "LISTEN",     "SYN_SENT",   "SYN_RCVD",
                     "ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT_1", "CLOSING",
                     "LAST_ACK",    "FIN_WAIT_2", "TIME_WAIT")
        states    = ("NO_TRAFFIC",  "SINGLE",     "MULTIPLE")

        if self.proto == IPPROTO_TCP:
            if self.src.state <= TCPS_TIME_WAIT and \
               self.dst.state <= TCPS_TIME_WAIT:
                s += "%s:%s" % (tcpstates[self.src.state],
                                tcpstates[self.dst.state])
            elif self.src.state == PF_TCPS_PROXY_SRC or \
                 self.dst.state == PF_TCPS_PROXY_SRC:
                s += "PROXY:SRC"
            elif self.src.state == PF_TCPS_PROXY_DST or \
                 self.dst.state == PF_TCPS_PROXY_DST:
                s += "PROXY:DST"
            else:
                s += "<BAD STATE LEVELS %u:%u>" % (self.src.state,
                                                   self.dst.state)
        elif self.proto == IPPROTO_UDP and \
             self.src.state < PFUDPS_NSTATES and \
             self.dst.state < PFUDPS_NSTATES:
            s += "%s:%s" % (states[self.src.state], states[self.dst.state])
        elif self.proto != IPPROTO_ICMP and \
             self.src.state < PFOTHERS_NSTATES and \
             self.dst.state < PFOTHERS_NSTATES:
            s += "%s:%s" % (states[self.src.state], states[self.dst.state])
        else:
            s += "%u:%u" % (self.src.state, self.dst.state)

        hrs, sec = divmod(self.creation, 60)
        hrs, min = divmod(hrs, 60)
        s += "\n   age %.2u:%.2u:%.2u" % (hrs, min, sec)

        hrs, sec = divmod(self.expire, 60)
        hrs, min = divmod(hrs, 60)
        s += ", expires in %.2u:%.2u:%.2u" % (hrs, min, sec)

        s += ", %u:%u pkts" % self.packets
        s += ", %u:%u bytes" % self.bytes

        if self.anchor != 0xffffffff:
            s += ", anchor %u" % self.anchor
        if self.rule != 0xffffffff:
            s += ", rule %u" % self.rule
        if self.sync_flags & PFSYNC_FLAG_SRCNODE:
            s += ", source-track"
        if self.sync_flags & PFSYNC_FLAG_NATSRCNODE:
            s += ", sticky-address\n"
        s += "\n"

        s += "   id: %016x creatorid: %08x" % (self.id, self.creatorid)
        if self.sync_flags & PFSTATE_NOSYNC:
            s += " (no-sync)"

        return s

    def __str__(self):
        return self._to_string()

