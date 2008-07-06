"""A class for managing PF through the ioctl(2) interface provided by pf(4).

This class communicates with the kernel through the ioctl(2) interface provided
by the pf(4) pseudo-device; this allows Python to natively send commands to the
kernel, thanks to the fcntl and ctypes modules.
"""


import os
import stat
from fcntl import ioctl
from errno import *
from ctypes import *
from socket import *

from _PFStruct import *
from PF import *


__all__ = ['PacketFilter']


# ioctl() operations ###########################################################
IOCPARM_MASK     = 0x1fff
IOC_VOID         = 0x20000000L
IOC_OUT          = 0x40000000L
IOC_IN           = 0x80000000L
IOC_INOUT        = IOC_IN | IOC_OUT

def _IOC(inout, group, num, len):
    return (inout | ((len & IOCPARM_MASK) << 16) | ((group) << 8) | (num))

def _IO(group, num):
    return _IOC(IOC_VOID, ord(group), num, 0)

def _IOWR(group, num, type):
    return _IOC(IOC_INOUT, ord(group), num, sizeof(type))

DIOCSTART        = _IO  ('D',  1)
DIOCSTOP         = _IO  ('D',  2)
DIOCADDRULE      = _IOWR('D',  4, pfioc_rule)
DIOCGETRULES     = _IOWR('D',  6, pfioc_rule)
DIOCGETRULE      = _IOWR('D',  7, pfioc_rule)
DIOCCLRSTATES    = _IOWR('D', 18, pfioc_state_kill)
#DIOCGETSTATE     = _IOWR('D', 19, pfioc_state)
DIOCSETSTATUSIF  = _IOWR('D', 20, pfioc_if)
DIOCGETSTATUS    = _IOWR('D', 21, pf_status)
DIOCCLRSTATUS    = _IO  ('D', 22)
#DIOCNATLOOK      = _IOWR('D', 23, pfioc_natlook)
DIOCSETDEBUG     = _IOWR('D', 24, c_uint32)
DIOCGETSTATES    = _IOWR('D', 25, pfioc_states)
#DIOCCHANGERULE   = _IOWR('D', 26, pfioc_rule)
DIOCSETTIMEOUT   = _IOWR('D', 29, pfioc_tm)
DIOCGETTIMEOUT   = _IOWR('D', 30, pfioc_tm)
#DIOCADDSTATE     = _IOWR('D', 37, pfioc_state)
#DIOCCLRRULECTRS  = _IO  ('D', 38)
DIOCGETLIMIT     = _IOWR('D', 39, pfioc_limit)
DIOCSETLIMIT     = _IOWR('D', 40, pfioc_limit)
DIOCKILLSTATES   = _IOWR('D', 41, pfioc_state_kill)
DIOCSTARTALTQ    = _IO  ('D', 42)
DIOCSTOPALTQ     = _IO  ('D', 43)
#DIOCADDALTQ      = _IOWR('D', 45, pfioc_altq)
#DIOCGETALTQS     = _IOWR('D', 47, pfioc_altq)
#DIOCGETALTQ      = _IOWR('D', 48, pfioc_altq)
#DIOCCHANGEALTQ   = _IOWR('D', 49, pfioc_altq)
#DIOCGETQSTATS    = _IOWR('D', 50, pfioc_qstats)
DIOCBEGINADDRS   = _IOWR('D', 51, pfioc_pooladdr)
DIOCADDADDR      = _IOWR('D', 52, pfioc_pooladdr)
DIOCGETADDRS     = _IOWR('D', 53, pfioc_pooladdr)
DIOCGETADDR      = _IOWR('D', 54, pfioc_pooladdr)
#DIOCCHANGEADDR   = _IOWR('D', 55, pfioc_pooladdr)
#DIOCGETRULESETS  = _IOWR('D', 58, pfioc_ruleset)
#DIOCGETRULESET   = _IOWR('D', 59, pfioc_ruleset)
#DIOCRCLRTABLES   = _IOWR('D', 60, pfioc_table)
#DIOCRADDTABLES   = _IOWR('D', 61, pfioc_table)
#DIOCRDELTABLES   = _IOWR('D', 62, pfioc_table)
#DIOCRGETTABLES   = _IOWR('D', 63, pfioc_table)
#DIOCRGETTSTATS   = _IOWR('D', 64, pfioc_table)
#DIOCRCLRTSTATS   = _IOWR('D', 65, pfioc_table)
#DIOCRCLRADDRS    = _IOWR('D', 66, pfioc_table)
#DIOCRADDADDRS    = _IOWR('D', 67, fioc_table)
#DIOCRDELADDRS    = _IOWR('D', 68, pfioc_table)
#DIOCRSETADDRS    = _IOWR('D', 69, pfioc_table)
#DIOCRGETADDRS    = _IOWR('D', 70, pfioc_table)
#DIOCRGETASTATS   = _IOWR('D', 71, pfioc_table)
#DIOCRCLRASTATS   = _IOWR('D', 72, pfioc_table)
#DIOCRTSTADDRS    = _IOWR('D', 73, pfioc_table)
#DIOCRSETTFLAGS   = _IOWR('D', 74, pfioc_table)
#DIOCRINADEFINE   = _IOWR('D', 77, pfioc_table)
#DIOCOSFPFLUSH    = _IO  ('D', 78)
#DIOCOSFPADD      = _IOWR('D', 79, pf_osfp_ioctl)
#DIOCOSFPGET      = _IOWR('D', 80, pf_osfp_ioctl)
DIOCXBEGIN       = _IOWR('D', 81, pfioc_trans)
DIOCXCOMMIT      = _IOWR('D', 82, pfioc_trans)
DIOCXROLLBACK    = _IOWR('D', 83, pfioc_trans)
#DIOCGETSRCNODES  = _IOWR('D', 84, pfioc_src_nodes)
#DIOCCLRSRCNODES  = _IO  ('D', 85)
DIOCSETHOSTID    = _IOWR('D', 86, c_uint32)
#DIOCIGETIFACES   = _IOWR('D', 87, pfioc_iface)
#DIOCSETIFFLAG    = _IOWR('D', 89, pfioc_iface)
#DIOCCLRIFFLAG    = _IOWR('D', 90, pfioc_iface)
#DIOCKILLSRCNODES = _IOWR('D', 91, pfioc_src_node_kill)


# Dictionaries for mapping strings to constants ################################
dbg_levels       = {"none":            PF_DEBUG_NONE,
                    "urgent":          PF_DEBUG_URGENT,
                    "misc":            PF_DEBUG_MISC,
                    "loud":            PF_DEBUG_NOISY}

pf_limits        = {"states":          PF_LIMIT_STATES,
                    "src-nodes":       PF_LIMIT_SRC_NODES,
                    "frags":           PF_LIMIT_FRAGS,
                    "tables":          PF_LIMIT_TABLES,
                    "table-entries":   PF_LIMIT_TABLE_ENTRIES}

pf_timeouts      = {"tcp.first":       PFTM_TCP_FIRST_PACKET,
                    "tcp.opening":     PFTM_TCP_OPENING,
                    "tcp.established": PFTM_TCP_ESTABLISHED,
                    "tcp.closing":     PFTM_TCP_CLOSING,
                    "tcp.finwait":     PFTM_TCP_FIN_WAIT,
                    "tcp.closed":      PFTM_TCP_CLOSED,
                    "tcp.tsdiff":      PFTM_TS_DIFF,
                    "udp.first":       PFTM_UDP_FIRST_PACKET,
                    "udp.single":      PFTM_UDP_SINGLE,
                    "udp.multiple":    PFTM_UDP_MULTIPLE,
                    "icmp.first":      PFTM_ICMP_FIRST_PACKET,
                    "icmp.error":      PFTM_ICMP_ERROR_REPLY,
                    "other.first":     PFTM_OTHER_FIRST_PACKET,
                    "other.single":    PFTM_OTHER_SINGLE,
                    "other.multiple":  PFTM_OTHER_MULTIPLE,
                    "frag":            PFTM_FRAG,
                    "interval":        PFTM_INTERVAL,
                    "adaptive.start":  PFTM_ADAPTIVE_START,
                    "adaptive.end":    PFTM_ADAPTIVE_END,
                    "src.track":       PFTM_SRC_NODE}


# PacketFilter class ###########################################################
class PacketFilter:
    """Class representing the kernel's packet filtering subsystem.

    It provides a set of methods that allow you to send commands to the kernel
    through the ioctl(2) interface provided by the pf(4) pseudo-device.
    Basically, all methods in this class are just wrappers to ioctl(2) calls.
    """

    def __init__(self, dev="/dev/pf"):
        """Set the pf device.

        Raise PFError if the pf device is not valid.
        """
        try:
            mode = os.stat(dev)[stat.ST_MODE]
        except OSError, (e, s):
            raise PFError, "%s: '%s'" % (s, dev)
        else:
            if not stat.S_ISCHR(mode):
                raise PFError, "Not a character device: '%s'" % dev

        self.dev = dev

    def enable(self):
        """Enable Packet Filtering and Network Address Translation.

        Raise IOError if the ioctl() request fails.
        """
        d = open(self.dev, "w")

        try:
            ioctl(d, DIOCSTART)
        except IOError, (e, s):
            if e != EEXIST:       # EEXIST means PF is already enabled
                raise

        d.close()

    def disable(self):
        """Disable Packet Filtering and Network Address Translation.

        Raise IOError if the ioctl() request fails.
        """
        d = open(self.dev, "w")

        try:
            ioctl(d, DIOCSTOP)
        except IOError, (e, s):
            if e != ENOENT:       # ENOENT means PF is already disabled
                raise

        d.close()

    def enable_altq(self):
        """Enable the ALTQ bandwidth control and packet prioritization system.

        Raise PFError if ALTQ is not supported by the system or IOError if the
        ioctl() request fails.
        """
        d = open(self.dev, "w")

        try:
            ioctl(d, DIOCSTARTALTQ)
        except IOError, (e, s):
            if e == ENODEV:
                raise PFError, "No ALTQ support in kernel"
            elif e != EEXIST:     # EEXIST means ALTQ is already enabled
                raise

        d.close()

    def disable_altq(self):
        """Disable the ALTQ bandwidth control and packet prioritization system.

        Raise PFError if ALTQ is not supported by the system or IOError if the
        ioctl() request fails.
        """
        d = open(self.dev, "w")

        try:
            ioctl(d, DIOCSTOPALTQ)
        except IOError, (e, s):
            if e == ENODEV:
                raise PFError, "No ALTQ support in kernel"
            elif e != ENOENT:     # ENOENT means ALTQ is already disabled
                raise

        d.close()


    def set_debug(self, level):
        """Set the debug level.

        The debug level can be either one of the PF_DEBUG_* constants or a
        string. Raise IOError if the ioctl() request fails.
        """
        if level in dbg_levels.keys():
            l = c_uint32(dbg_levels[level])
        elif level in dbg_levels.values():
            l = c_uint32(level)
        elif isinstance(level, (int, str)):
            raise ValueError, "Not a valid debug level: '%s'" % level
        else:
            raise TypeError, "'level'must be an integer or a string"

        d = open(self.dev, "w")
        ioctl(d, DIOCSETDEBUG, l)
        d.close()


    def set_hostid(self, id):
        """Set the host ID.

        The host ID is used by pfsync to identify the host that created a state
        table entry. 'id' must be an integer.
        """
        if isinstance(id, int):
            i = c_uint32(htonl(id))
        else:
            raise TypeError, "'id'must be an integer"

        d = open(self.dev, "w")
        ioctl(d, DIOCSETHOSTID, i)
        d.close()


    def get_limit(self, limit=None):
        """Return the hard limits on the memory pools used by Packet Filter.

        'limit' can be either one of the PF_LIMIT_* constants or a string;
        return the value of the requested limit (UINT_MAX means unlimited) or,
        if called with no arguments, a dictionary containing all the available
        limits.
        Raise IOError if the ioctl() request fails.
        """
        if limit is None:
            return dict([(k, self.get_limit(k)) for k in pf_limits.keys()])
        elif limit in pf_limits.keys():
            i = pf_limits[limit]
        elif limit in pf_limits.values():
            i = limit
        elif isinstance(limit, (int, str)):
            raise ValueError, "Not a valid limit: '%s'" % limit
        else:
            raise TypeError, "'limit' must be an integer or a string"

        pl = pfioc_limit(index=i)

        d = open(self.dev, "r")
        ioctl(d, DIOCGETLIMIT, pl.asBuffer())
        d.close()

        return pl.limit

    def set_limit(self, limit, value):
        """Set hard limits on the memory pools used by Packet Filter.

        'limit' can be either one of the PF_LIMIT_* constants or a string; a
        'value' of UINT_MAX means unlimited.
        Raise IOError if the ioctl() request fails or PFError if the current
        pool size exceeds the requested hard limit.
        """
        if limit in pf_limits.keys():
            i = pf_limits[limit]
        elif limit in pf_limits.values():
            i = limit
        elif isinstance(limit, (int, str)):
            raise ValueError, "Not a valid limit: '%s'" % limit
        else:
            raise TypeError, "'limit' must be an integer or a string"

        if not isinstance(value, (int, long)):
            raise TypeError, "'value' must be an integer"

        pl = pfioc_limit(index=i, limit=value)

        d = open(self.dev, "w")
        try:
            ioctl(d, DIOCSETLIMIT, pl.asBuffer())
        except IOError, (e, s):
            if e == EBUSY:
                raise PFError, "Current pool size exceeds requested hard limit"
            raise
        d.close()


    def get_timeout(self, timeout=None):
        """Return the state timeout of 'timeout'.

        'timeout' can be either one of the PFTM_* constants or a string; return
        the value of the requested timeout or, if called with no arguments, a
        dictionary containing all the available timeouts.
        Raise IOError if the ioctl() request fails.
        """
        if timeout is None:
            return dict([(k, self.get_timeout(k)) for k in pf_timeouts.keys()])
        elif timeout in pf_timeouts.keys():
            t = pf_timeouts[timeout]
        elif timeout in pf_timeouts.values():
            t = timeout
        elif isinstance(timeout, (int, str)):
            raise ValueError, "Not a valid timeout: '%s'" % timeout
        else:
            raise TypeError, "'timeout' must be an integer or a string"

        pt = pfioc_tm(timeout=t)

        d = open(self.dev, "r")
        ioctl(d, DIOCGETTIMEOUT, pt.asBuffer())
        d.close()

        return pt.seconds

    def set_timeout(self, timeout, value):
        """Set the state timeout of 'timeout' to 'value'.

        'timeout' can be either one of the PFTM_* constants or a string; return
        the old value of the specified timeout.
        Raise IOError if the ioctl() request fails.
        """
        if timeout in pf_timeouts.keys():
            t = pf_timeouts[timeout]
        elif timeout in pf_timeouts.values():
            t = timeout
        elif isinstance(timeout, (int, str)):
            raise ValueError, "Not a valid timeout: '%s'" % timeout
        else:
            raise TypeError, "'timeout' must be an integer or a string"

        if not isinstance(value, int):
            raise TypeError, "'value' must be an integer"

        pt = pfioc_tm(timeout=t, seconds=value)

        d = open(self.dev, "w")
        ioctl(d, DIOCSETTIMEOUT, pt.asBuffer())
        d.close()

        return pt.seconds


    def set_status_if(self, ifname=None):
        """Specify the interface for which statistics are accumulated.

        If 'ifname' is None, turn off the collection of per-interface
        statistics. Raise IOError if the ioctl() request fails or PFError if
        'ifname' is not a valid interface name.
        """
        if not ifname:
            ifname = ""
        elif not isinstance(ifname, str):
            raise TypeError, "'ifname' must be a string or None"

        try:
            pi = pfioc_if(ifname=ifname)
        except ValueError:
            raise PFError, "Interface name too long: '%s'" % ifname

        d = open(self.dev, "w")
        try:
            ioctl(d, DIOCSETSTATUSIF, pi.asBuffer())
        except IOError, (e, s):
            if e == EINVAL:
                raise PFError, "Not a valid interface name: '%s'" % ifname
            raise
        d.close()

    def get_status(self):
        """Return a PFStatus object containing the internal PF statistics.

        Raise IOError if the ioctl() request fails.
        """
        s = pf_status()

        d = open(self.dev, "w")
        ioctl(d, DIOCGETSTATUS, s)
        d.close()

        return PFStatus(s)

    def clear_status(self):
        """Clear the internal packet filter statistics.

        Raise IOError if the ioctl() request fails.
        """
        d = open(self.dev, "w")
        ioctl(d, DIOCCLRSTATUS)
        d.close()


    def get_states(self):
        """Retrieve the state table entries.

        Return a tuple of PFState objects representing the states currently
        tracked by PF. Raise IOError if the ioctl() request fails.
        """
        ps = pfioc_states()

        d = open(self.dev, "w")
        ioctl(d, DIOCGETSTATES, ps.asBuffer())
        ps_num = ps.ps_len / sizeof(pfsync_state)
        ps_states = (pfsync_state * ps_num)()

        if ps_num:
            ps.ps_states = addressof(ps_states)
            ioctl(d, DIOCGETSTATES, ps.asBuffer())

        d.close()

        return tuple([PFState(s) for s in ps_states])

    def clear_states(self, ifname=None):
        """Clear all states.

        If an interface name is provided, only states for that interface will
        be cleared. Return the number of cleared states.
        Raise IOError if the ioctl() request fails.
        """
        if not ifname:
            ifname = ""
        elif not isinstance(ifname, str):
            raise TypeError, "'ifname' must be a string"

        try:
            psk = pfioc_state_kill(psk_ifname=ifname)
        except ValueError:
            raise ValueError, "Interface name too long: '%s'" % ifname

        d = open(self.dev, "w")
        ioctl(d, DIOCCLRSTATES, psk.asBuffer())
        d.close()

        return psk.psk_af

    def kill_states(self, af=AF_UNSPEC, proto=None, src=None, dst=None, ifname=None):
        """Clear states matching the specified arguments.

        Return the number of killed states.
        """
        if not isinstance(af, int):
            raise TypeError, "'af' must be a string"

        if not proto:
            proto = 0
        elif not isinstance(proto, int):
            raise TypeError, "'proto' must be an integer"

        if not ifname:
            ifname = ""
        elif not isinstance(ifname, str):
            raise TypeError, "'ifname' must be an integer"

        try:
            psk = pfioc_state_kill(psk_af=af,
                                   psk_proto=proto,
                                   psk_ifname=ifname)
        except ValueError:
            raise

        if isinstance(src, PFRuleAddr):
            psk.psk_src = src._to_struct()
        elif src is not None:
            raise ValueError, "'src' must be a PFRuleAddr instance"

        if isinstance(dst, PFRuleAddr):
            psk.psk_dst = dst._to_struct()
        elif dst is not None:
            raise ValueError, "'dst' must be a PFRuleAddr instance"

        d = open(self.dev, "w")
        ioctl(d, DIOCKILLSTATES, psk.asBuffer())
        d.close()

        return psk.psk_af


    def _get_pool(self, pr, dev):
        """Return the address pool for the specified rule."""
        pool = PFPool(pr.rule.action, pr.rule.rpool)
        pp   = pfioc_pooladdr(ticket=pr.ticket, r_action=pr.rule.action,
                              r_num=pr.nr, anchor=pr.anchor)
        ioctl(dev, DIOCGETADDRS, pp.asBuffer())

        for nr in range(pp.nr):
            pp.nr = nr
            ioctl(dev, DIOCGETADDR, pp.asBuffer())
            pool.append(PFRuleAddr(pf_rule_addr(addr=pp.addr.addr), pr.rule.af))

        return pool

    def _get_rules(self, path, dev):
        """Return the rules corresponding to the path specified."""
        actions = {PF_RULESET_FILTER: PF_PASS,
                   PF_RULESET_SCRUB:  PF_SCRUB,
                   PF_RULESET_NAT:    PF_NAT,
                   PF_RULESET_RDR:    PF_RDR,
                   PF_RULESET_BINAT:  PF_BINAT}

        pr = pfioc_rule(anchor=path)
        rules = {}

        for rs in (PF_RULESET_FILTER, PF_RULESET_SCRUB, PF_RULESET_NAT,
                   PF_RULESET_RDR, PF_RULESET_BINAT):
            rules[rs] = []

            pr.rule.action = actions[rs]
            ioctl(dev, DIOCGETRULES, pr.asBuffer())

            for nr in range(pr.nr):
                pr.nr = nr
                ioctl(dev, DIOCGETRULE, pr.asBuffer())
                if pr.anchor_call:
                    #r = PFRuleset(pr.anchor_call, pr.rule)
                    r = PFRuleset(pr.anchor_call.split("/")[-1], pr.rule)
                    p = "/".join(filter(None, (path, r.name)))
                    r.rules = self._get_rules(p, dev)
                else:
                    r = PFRule(pr.rule)
                r.rpool = self._get_pool(pr, dev)
                rules[rs].append(r)

        return rules

    def get_ruleset(self, path=""):
        """Return a PFRuleset object containing the active ruleset.

        'path' is the name of the anchor to retrieve rules from.
        """
        if not isinstance(path, str):
            raise TypeError, "'path' must be a string"

        d = open(self.dev, "r")
        rs = PFRuleset(path.split("/")[-1])
        rs.rules = self._get_rules(path, d)
        d.close()

        return rs

    def load_ruleset(self, ruleset, path="", rs_num=None):
        """Load the given ruleset.

        'path' is the name of the anchor where to load rules; 'rs_num' is a
        single constant or a tuple of constants specifying which types of rules
        should be loaded (e.g. PF_RULESET_FILTER, PF_RULESET_NAT, etc.).
        """
        if not isinstance(ruleset, PFRuleset):
            raise TypeError, "'ruleset' must be a PFRuleset instance"

        if not isinstance(path, str):
            raise TypeError, "'path' must be a string"

        if isinstance(rs_num, int):
            rs_num = (rs_num, )
        elif rs_num is None:
            rs_num = (PF_RULESET_NAT, PF_RULESET_BINAT, PF_RULESET_RDR,
                      PF_RULESET_SCRUB, PF_RULESET_FILTER)
        elif not isinstance(rs_num, tuple):
            raise TypeError, "'rs_num' must be a tuple or an integer"

        pt = pfioc_trans()
        array = (pfioc_trans_e * len(rs_num))()

        for a, n in zip(array, rs_num):
            a.rs_num = n
            a.anchor = path

        pt.size  = len(rs_num)
        pt.esize = sizeof(pfioc_trans_e)
        pt.array = addressof(array)

        d = open(self.dev, "w")
        ioctl(d, DIOCXBEGIN, pt.asBuffer())

        try:
            for a in array:
                for rule in ruleset.rules[a.rs_num]:
                    pp = pfioc_pooladdr()
                    pr = pfioc_rule()

                    ioctl(d, DIOCBEGINADDRS, pp.asBuffer())

                    pr.ticket = a.ticket
                    pr.pool_ticket = pp.ticket
                    pr.rule = rule._to_struct()
                    pr.anchor = path

                    if isinstance(rule, PFRuleset):
                        pr.anchor_call = rule.name

                    if rule.rpool:
                        pr.rule.rpool = rule.rpool._to_struct()
                        for addr in rule.rpool.addrs:
                            pp.addr.addr = addr._to_struct().addr
                            ioctl(d, DIOCADDADDR, pp.asBuffer())

                    ioctl(d, DIOCADDRULE, pr.asBuffer())

                    if isinstance(rule, PFRuleset):
                        p = "/".join(filter(None, (path, rule.name)))
                        self.load_ruleset(rule, p, rs_num)
        except IOError, (e, s):
            ioctl(d, DIOCXROLLBACK, pt.asBuffer())
            raise PFError, "Failed to load ruleset: %s" % s

        ioctl(d, DIOCXCOMMIT, pt.asBuffer())

        d.close()

