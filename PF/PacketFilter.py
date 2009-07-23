"""A class for managing OpenBSD's Packet Filter.

This class communicates with the kernel through the ioctl(2) interface provided
by the pf(4) pseudo-device; this allows Python to natively send commands to the
kernel, thanks to the fcntl and ctypes modules.
"""


from __future__ import with_statement
import os
import stat
from fcntl import ioctl
from errno import *
from ctypes import *
from socket import *

from PF import *
from PF._PFStruct import *


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
DIOCRCLRTABLES   = _IOWR('D', 60, pfioc_table)
DIOCRADDTABLES   = _IOWR('D', 61, pfioc_table)
DIOCRDELTABLES   = _IOWR('D', 62, pfioc_table)
DIOCRGETTABLES   = _IOWR('D', 63, pfioc_table)
#DIOCRGETTSTATS   = _IOWR('D', 64, pfioc_table)
#DIOCRCLRTSTATS   = _IOWR('D', 65, pfioc_table)
DIOCRCLRADDRS    = _IOWR('D', 66, pfioc_table)
DIOCRADDADDRS    = _IOWR('D', 67, pfioc_table)
DIOCRDELADDRS    = _IOWR('D', 68, pfioc_table)
DIOCRSETADDRS    = _IOWR('D', 69, pfioc_table)
DIOCRGETADDRS    = _IOWR('D', 70, pfioc_table)
#DIOCRGETASTATS   = _IOWR('D', 71, pfioc_table)
#DIOCRCLRASTATS   = _IOWR('D', 72, pfioc_table)
#DIOCRTSTADDRS    = _IOWR('D', 73, pfioc_table)
#DIOCRSETTFLAGS   = _IOWR('D', 74, pfioc_table)
DIOCRINADEFINE   = _IOWR('D', 77, pfioc_table)
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
DIOCSETREASS     = _IOWR('D', 92, c_uint32)

# Dictionaries for mapping strings to constants ################################
dbg_levels  = {"none":            PF_DEBUG_NONE,
               "urgent":          PF_DEBUG_URGENT,
               "misc":            PF_DEBUG_MISC,
               "loud":            PF_DEBUG_NOISY}

pf_limits   = {"states":          PF_LIMIT_STATES,
               "src-nodes":       PF_LIMIT_SRC_NODES,
               "frags":           PF_LIMIT_FRAGS,
               "tables":          PF_LIMIT_TABLES,
               "table-entries":   PF_LIMIT_TABLE_ENTRIES}

pf_timeouts = {"tcp.first":       PFTM_TCP_FIRST_PACKET,
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
    Basically, all methods in this class are just wrappers to ioctl(2) calls,
    and may consequently raise IOError if the ioctl() request fails.
    """

    def __init__(self, dev='/dev/pf'):
        """Set the pf device."""
        self.dev = dev

    def enable(self):
        """Enable Packet Filtering and Network Address Translation."""
        with open(self.dev, 'w') as d:
            try:
                ioctl(d, DIOCSTART)
            except IOError, (e, s):
                if e != EEXIST:       # EEXIST means PF is already enabled
                    raise

    def disable(self):
        """Disable Packet Filtering and Network Address Translation."""
        with open(self.dev, 'w') as d:
            try:
                ioctl(d, DIOCSTOP)
            except IOError, (e, s):
                if e != ENOENT:       # ENOENT means PF is already disabled
                    raise

    def enable_altq(self):
        """Enable the ALTQ bandwidth control and packet prioritization system.

        Raise PFError if ALTQ is not supported by the system.
        """
        with open(self.dev, 'w') as d:
            try:
                ioctl(d, DIOCSTARTALTQ)
            except IOError, (e, s):
                if e == ENODEV:
                    raise PFError("No ALTQ support in kernel")
                elif e != EEXIST:     # EEXIST means ALTQ is already enabled
                    raise

    def disable_altq(self):
        """Disable the ALTQ bandwidth control and packet prioritization system.

        Raise PFError if ALTQ is not supported by the system.
        """
        with open(self.dev, 'w') as d:
            try:
                ioctl(d, DIOCSTOPALTQ)
            except IOError, (e, s):
                if e == ENODEV:
                    raise PFError("No ALTQ support in kernel")
                elif e != ENOENT:     # ENOENT means ALTQ is already disabled
                    raise

    def set_debug(self, level):
        """Set the debug level.

        The debug level can be either one of the PF_DEBUG_* constants or a
        string.
        """
        if level in dbg_levels.keys():
            level = dbg_levels[level]

        pt = pfioc_trans(esize=sizeof(pfioc_trans_e))
        with open(self.dev, 'w') as d:
            ioctl(d, DIOCXBEGIN, pt.asBuffer())
            ioctl(d, DIOCSETDEBUG, c_uint32(level))
            ioctl(d, DIOCXCOMMIT, pt.asBuffer())

    def set_hostid(self, id):
        """Set the host ID.

        The host ID is used by pfsync to identify the host that created a state
        table entry. 'id' must be a 32-bit unsigned integer.
        """
        pt = pfioc_trans(esize=sizeof(pfioc_trans_e))
        with open(self.dev, 'w') as d:
            ioctl(d, DIOCXBEGIN, pt.asBuffer())
            ioctl(d, DIOCSETHOSTID, c_uint32(htonl(id)))
            ioctl(d, DIOCXCOMMIT, pt.asBuffer())

    def set_reassembly(self, reassembly):
        """Enable reassembly of network traffic.

        The 'reassembly' argument specifies the flags for the reassembly
        operation; available flags are PF_REASS_ENABLED and PF_REASS_NODF.
        """
        pt = pfioc_trans(esize=sizeof(pfioc_trans_e))
        with open(self.dev, 'w') as d:
            ioctl(d, DIOCXBEGIN, pt.asBuffer())
            ioctl(d, DIOCSETREASS, c_uint32(reassembly))
            ioctl(d, DIOCXCOMMIT, pt.asBuffer())

    def get_limit(self, limit=None):
        """Return the hard limits on the memory pools used by Packet Filter.

        'limit' can be either one of the PF_LIMIT_* constants or a string;
        return the value of the requested limit (UINT_MAX means unlimited) or,
        if called with no arguments, a dictionary containing all the available
        limits.
        """
        if limit is None:
            return dict([(k, self.get_limit(k)) for k in pf_limits.keys()])
        elif limit in pf_limits.keys():
            limit = pf_limits[limit]

        pl = pfioc_limit(index=limit)

        with open(self.dev, 'r') as d:
            ioctl(d, DIOCGETLIMIT, pl.asBuffer())

        return pl.limit

    def set_limit(self, limit, value):
        """Set hard limits on the memory pools used by Packet Filter.

        'limit' can be either one of the PF_LIMIT_* constants or a string; a
        'value' of UINT_MAX means unlimited. Raise PFError if the current pool
        size exceeds the requested hard limit.
        """
        if limit in pf_limits.keys():
            limit = pf_limits[limit]

        pl = pfioc_limit(index=limit, limit=value)
        pt = pfioc_trans(esize=sizeof(pfioc_trans_e))
        with open(self.dev, 'w') as d:
            ioctl(d, DIOCXBEGIN, pt.asBuffer())
            try:
                ioctl(d, DIOCSETLIMIT, pl.asBuffer())
            except IOError, (e, s):
                if e == EBUSY:
                    raise PFError("Current pool size exceeds requested hard limit")
                raise
            ioctl(d, DIOCXCOMMIT, pt.asBuffer())

    def get_timeout(self, timeout=None):
        """Return the configured timeout values for states.

        'timeout' can be either one of the PFTM_* constants or a string; return
        the value of the requested timeout or, if called with no arguments, a
        dictionary containing all the available timeouts.
        """
        if timeout is None:
            return dict([(k, self.get_timeout(k)) for k in pf_timeouts.keys()])
        elif timeout in pf_timeouts.keys():
            timeout = pf_timeouts[timeout]

        tm = pfioc_tm(timeout=timeout)
        with open(self.dev, 'r') as d:
            ioctl(d, DIOCGETTIMEOUT, tm.asBuffer())

        return tm.seconds

    def set_timeout(self, timeout, value):
        """Set the timeout 'value' for a specific state.

        'timeout' can be either one of the PFTM_* constants or a string; return
        the old value of the specified timeout.
        """
        if timeout in pf_timeouts.keys():
            timeout = pf_timeouts[timeout]

        tm = pfioc_tm(timeout=timeout, seconds=value)
        pt = pfioc_trans(esize=sizeof(pfioc_trans_e))
        with open(self.dev, 'w') as d:
            ioctl(d, DIOCXBEGIN, pt.asBuffer())
            ioctl(d, DIOCSETTIMEOUT, tm.asBuffer())
            ioctl(d, DIOCXCOMMIT, pt.asBuffer())

        return tm.seconds

    def set_status_if(self, ifname=""):
        """Specify the interface for which statistics are accumulated.

        If no 'ifname' is provided, turn off the collection of per-interface
        statistics. Raise PFError if 'ifname' is not a valid interface name.
        """
        pi = pfioc_if(ifname=ifname)
        pt = pfioc_trans(esize=sizeof(pfioc_trans_e))
        with open(self.dev, 'w') as d:
            ioctl(d, DIOCXBEGIN, pt.asBuffer())
            try:
                ioctl(d, DIOCSETSTATUSIF, pi.asBuffer())
            except IOError, (e, s):
                if e == EINVAL:
                    raise PFError("Not a valid interface name: '%s'" % ifname)
                raise
            else:
                ioctl(d, DIOCXCOMMIT, pt.asBuffer())

    def get_status(self):
        """Return a PFStatus object containing the internal PF statistics."""
        s = pf_status()
        with open(self.dev, 'w') as d:
            ioctl(d, DIOCGETSTATUS, s.asBuffer())

        return PFStatus(s)

    def clear_status(self):
        """Clear the internal packet filter statistics."""
        with open(self.dev, 'w') as d:
            ioctl(d, DIOCCLRSTATUS)

    def get_states(self):
        """Retrieve Packet Filter's state table entries.

        Return a tuple of PFState objects representing the states currently
        tracked by PF.
        """
        ps = pfioc_states()

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCGETSTATES, ps.asBuffer())
            ps_num = ps.ps_len / sizeof(pfsync_state)
            ps_states = (pfsync_state * ps_num)()

            if ps_num:
                ps.ps_states = addressof(ps_states)
                ioctl(d, DIOCGETSTATES, ps.asBuffer())

        return tuple([PFState(s) for s in ps_states])

    def clear_states(self, ifname=""):
        """Clear all states.

        If an interface name is provided, only states for that interface will
        be cleared. Return the number of cleared states.
        """
        psk = pfioc_state_kill(psk_ifname=ifname)

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCCLRSTATES, psk.asBuffer())

        return psk.psk_af

    def kill_states(self, af=AF_UNSPEC, proto=0, src=None, dst=None, ifname="",
                    label=""):
        """Clear states matching the specified arguments.

        States can be secified by address family, layer-4 protocol, source and
        destination addresses, interface name and label. Return the number of
        killed states.
        """
        psk = pfioc_state_kill(psk_af=af, psk_proto=proto, psk_ifname=ifname,
                               psk_label=label)
        if src:
            psk.psk_src = src._to_struct()
        if dst:
            psk.psk_dst = dst._to_struct()

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCKILLSTATES, psk.asBuffer())

        return psk.psk_killed

    def _get_pool(self, pr, dev):
        """Return the address pool for the specified rule."""
        pool = PFPool(pr.rule.action, pool=pr.rule.rpool)
        pp   = pfioc_pooladdr(ticket=pr.ticket, r_action=pr.rule.action,
                              r_num=pr.nr, anchor=pr.anchor)
        ioctl(dev, DIOCGETADDRS, pp.asBuffer())

        for nr in range(pp.nr):
            pp.nr = nr
            ioctl(dev, DIOCGETADDR, pp.asBuffer())
            pool._append(PFAddr(pp.addr.addr, af=pr.rule.af))

        return pool

    def _get_rules(self, path, dev):
        """Return the rules corresponding to the path specified."""
        actions = {PF_RULESET_FILTER: PF_PASS,
                   PF_RULESET_NAT:    PF_NAT,
                   PF_RULESET_RDR:    PF_RDR,
                   PF_RULESET_BINAT:  PF_BINAT}

        pr = pfioc_rule(anchor=path)
        rules = {}

        for rs in actions.keys():
            rules[rs] = []

            pr.rule.action = actions[rs]
            ioctl(dev, DIOCGETRULES, pr.asBuffer())

            for nr in range(pr.nr):
                pr.nr = nr
                ioctl(dev, DIOCGETRULE, pr.asBuffer())

                if pr.anchor_call:
                    name = os.path.basename(pr.anchor_call)
                    if name == '*':
                        r = PFRuleset(pr.anchor_call, pr.rule)
                    else:
                        r = PFRuleset(name, pr.rule)
                        r._rules = self._get_rules(pr.anchor_call, dev)
                else:
                    r = PFRule(pr.rule)

                r.rpool = self._get_pool(pr, dev)
                rules[rs].append(r)

        rules[PF_RULESET_TABLE] = self.get_tables(PFTable(anchor=path))
        return rules

    def get_ruleset(self, path=""):
        """Return a PFRuleset object containing the active ruleset.

        'path' is the name of the anchor to retrieve rules from.
        """
        rs = PFRuleset(os.path.basename(path))

        with open(self.dev, 'r') as d:
            rs._rules = self._get_rules(path, d)

        return rs

    def _load_ruleset(self, ruleset, path, dev, trans_e):
        """Recursively load ruleset."""
        if trans_e.rs_num == PF_RULESET_TABLE:
            for table in ruleset.rules[trans_e.rs_num]:
                table.anchor = path   # Force anchor ???
                io = pfioc_table(pfrio_table=table._to_struct(),
                                 pfrio_ticket=trans_e.ticket)
                if table.addrs:
                    io.pfrio_flags |= PFR_FLAG_ADDRSTOO
                    addrs = table.addrs
                    buf = (pfr_addr * len(addrs))(*[addr._to_struct()
                                                    for addr in addrs])
                    io.pfrio_buffer = addressof(buf)
                    io.pfrio_esize = sizeof(pfr_addr)
                    io.pfrio_size = len(addrs)

                ioctl(dev, DIOCRINADEFINE, io.asBuffer())
        else:
            for rule in ruleset.rules[trans_e.rs_num]:
                pp = pfioc_pooladdr()
                pr = pfioc_rule()

                ioctl(dev, DIOCBEGINADDRS, pp.asBuffer())

                pr.ticket = trans_e.ticket
                pr.pool_ticket = pp.ticket
                pr.rule = rule._to_struct()
                pr.anchor = path

                if isinstance(rule, PFRuleset):
                    pr.anchor_call = os.path.join(path, rule.name)

                if rule.rpool:
                    pr.rule.rpool = rule.rpool._to_struct()
                    for addr in rule.rpool.addrs:
                        pp.addr.addr = addr._to_struct()
                        ioctl(dev, DIOCADDADDR, pp.asBuffer())

                ioctl(dev, DIOCADDRULE, pr.asBuffer())

                if isinstance(rule, PFRuleset):
                    self._load_ruleset(rule, pr.anchor_call, dev, trans_e)

    def _inadefine(self, path, dev, ticket, *tables):
        """Define one or more tables in the inactive ruleset."""
        for table in tables:
            table.anchor = path
            io = pfioc_table(pfrio_table=table._to_struct(),
                             pfrio_ticket=ticket)
            if table.addrs:
                io.pfrio_flags |= PFR_FLAG_ADDRSTOO

                addrs = table.addrs
                buf = (pfr_addr * len(addrs))(*[a._to_struct() for a in addrs])
                io.pfrio_buffer = addressof(buf)
                io.pfrio_esize = sizeof(pfr_addr)
                io.pfrio_size = len(addrs)

            ioctl(dev, DIOCRINADEFINE, io.asBuffer())

    def load_ruleset(self, ruleset, path="", rs_type=None):
        """Load the given ruleset.

        'ruleset' must be a PFRuleset object; 'path' is the name of the anchor
        where to load rules; 'rs_type' is one, or a tuple of, PF_RULESET_*
        constants: if omitted, all ruleset types will be loaded.
        """
        if isinstance(rs_type, int):
            rs_type = (rs_type, )
        elif rs_type is None:
            rs_type = (PF_RULESET_TABLE, PF_RULESET_NAT, PF_RULESET_BINAT,
                       PF_RULESET_RDR, PF_RULESET_FILTER)

        pt = pfioc_trans()
        array = (pfioc_trans_e * len(rs_type))()

        for a, t in zip(array, rs_type):
            a.rs_num = t
            a.anchor = path

        pt.size  = len(rs_type)
        pt.esize = sizeof(pfioc_trans_e)
        pt.array = addressof(array)

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCXBEGIN, pt.asBuffer())

            try:
                for a in array:
                    if a.rs_num == PF_RULESET_TABLE:
                        self._inadefine(path, d, a.ticket,
                                        *ruleset.rules[PF_RULESET_TABLE])
                        continue

                    for rule in ruleset.rules[a.rs_num]:
                        pp = pfioc_pooladdr()
                        pr = pfioc_rule()

                        ioctl(d, DIOCBEGINADDRS, pp.asBuffer())

                        pr.ticket = a.ticket
                        pr.pool_ticket = pp.ticket
                        pr.rule = rule._to_struct()
                        pr.anchor = path

                        if isinstance(rule, PFRuleset):
                            pr.anchor_call = os.path.join(path, rule.name)

                        if rule.rpool:
                            pr.rule.rpool = rule.rpool._to_struct()
                            for addr in rule.rpool.addrs:
                                pp.addr.addr = addr._to_struct()
                                ioctl(d, DIOCADDADDR, pp.asBuffer())

                        ioctl(d, DIOCADDRULE, pr.asBuffer())

                        if isinstance(rule, PFRuleset):
                            self.load_ruleset(rule, pr.anchor_call)
            except IOError, (e, s):
                ioctl(d, DIOCXROLLBACK, pt.asBuffer())
                raise PFError, "Failed to load ruleset: %s" % s
            else:
                ioctl(d, DIOCXCOMMIT, pt.asBuffer())

    def add_tables(self, *tables):
        """Create one or more tables.

        'tables' must be PFTable objects; return the number of tables created.
        """
        io = pfioc_table()

        buffer = (pfr_table * len(tables))(*[t._to_struct() for t in tables])
        io.pfrio_buffer = addressof(buffer)
        io.pfrio_esize = sizeof(pfr_table)
        io.pfrio_size = len(tables)

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCRADDTABLES, io.asBuffer())

        for t in filter(lambda t: t.addrs, tables):
            self.add_addrs(t, *t.addrs)

        return io.pfrio_nadd

    def clear_tables(self, filter=None):
        """Clear all tables.

        'filter' is a PFTable object that allows you to specify the attributes
        of the tables to delete. Return the number of tables deleted.
        """
        io = pfioc_table()

        if filter is not None:
            io.pfrio_table = pfr_table(pfrt_name=filter.name,
                                       pfrt_anchor=filter.anchor)

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCRCLRTABLES, io.asBuffer())

        return io.pfrio_ndel

    def del_tables(self, *tables):
        """Delete one or more tables.

        'tables' must be PFTable objects. Return the number of tables deleted.
        """
        io = pfioc_table()

        buffer = (pfr_table * len(tables))()
        for (t, b) in zip(tables, buffer):
            b.pfrt_name = t.name
            b.pfrt_anchor = t.anchor

        io.pfrio_buffer = addressof(buffer)
        io.pfrio_esize = sizeof(pfr_table)
        io.pfrio_size = len(tables)

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCRDELTABLES, io.asBuffer())

        return io.pfrio_ndel

    def get_tables(self, filter=None, buf_size=10):
        """Get the list of all tables.

        'filter' is a PFTable object that allows you to specify the attributes
        of the tables to retrieve. Return a list of PFTable objects containing
        the currently-loaded tables.
        """
        io = pfioc_table()

        if filter is not None:
            io.pfrio_table = pfr_table(pfrt_name=filter.name,
                                       pfrt_anchor=filter.anchor)

        with open(self.dev, 'w') as d:
            while True:
                buffer = (pfr_table * buf_size)()
                io.pfrio_buffer = addressof(buffer)
                io.pfrio_esize = sizeof(pfr_table)
                io.pfrio_size = buf_size

                ioctl(d, DIOCRGETTABLES, io.asBuffer())

                if io.pfrio_size > buf_size:
                    buf_size = io.pfrio_size
                else:
                    break

        tables = []
        for t in buffer[:io.pfrio_size]:
            try:
                addrs = self.get_addrs(PFTable(t))
            except IOError, (e, s):
                if e!= ESRCH:
                    raise
            else:
                tables.append(PFTable(t, addrs))

        return tuple(tables)

    def add_addrs(self, table, *addrs):
        """Add one or more addresses to a table.

        'table' can be either a PFTable instance or a string containing the
        table name; 'addrs' can be either PFTableAddr instances or strings.
        Return the number of addresses effectively added.
        """
        if isinstance(table, basestring):
            table = pfr_table(pfrt_name=table)
        else:
            table = pfr_table(pfrt_name=table.name, pfrt_anchor=table.anchor)

        _addrs = []
        for addr in addrs:
            if isinstance(addr, PFTableAddr):
                _addrs.append(addr)
            else:
                _addrs.append(PFTableAddr(addr))

        io = pfioc_table()

        buffer = (pfr_addr * len(addrs))(*[a._to_struct() for a in _addrs])
        io.pfrio_buffer = addressof(buffer)
        io.pfrio_table = table
        io.pfrio_esize = sizeof(pfr_addr)
        io.pfrio_size = len(addrs)

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCRADDADDRS, io.asBuffer())

        return io.pfrio_nadd

    def clear_addrs(self, table):
        """Clear all addresses in the specified table.

        Return the number of addresses removed.
        """
        if isinstance(table, basestring):
            table = pfr_table(pfrt_name=table)
        else:
            table = pfr_table(pfrt_name=table.name, pfrt_anchor=table.anchor)

        io = pfioc_table()
        io.pfrio_table = table

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCRCLRADDRS, io.asBuffer())

        return io.pfrio_ndel

    def del_addrs(self, table, *addrs):
        """Delete one or more addresses from the specified table.

        'table' can be either a PFTable instance or a string containing the
        table name; 'addrs' can be either PFTableAddr instances or strings.
        Return the number of addresses deleted.
        """
        if isinstance(table, basestring):
            table = pfr_table(pfrt_name=table)
        else:
            table = pfr_table(pfrt_name=table.name, pfrt_anchor=table.anchor)

        _addrs = []
        for addr in addrs:
            if isinstance(addr, PFTableAddr):
                _addrs.append(addr)
            elif isinstance(addr, basestring):
                _addrs.append(PFTableAddr(addr))

        io = pfioc_table()

        buffer = (pfr_addr * len(addrs))(*[a._to_struct() for a in _addrs])
        io.pfrio_buffer = addressof(buffer)
        io.pfrio_table = table
        io.pfrio_esize = sizeof(pfr_addr)
        io.pfrio_size = len(addrs)

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCRDELADDRS, io.asBuffer())

        return io.pfrio_ndel

    def set_addrs(self, table, *addrs):
        """Replace the content of a table.

        'table' can be either a PFTable instance or a string containing the
        table name; 'addrs' can be either PFTableAddr instances or strings.
        Return a tuple containing the number of addresses deleted, added and
        changed.
        """
        if isinstance(table, basestring):
            table = pfr_table(pfrt_name=table)
        else:
            table = pfr_table(pfrt_name=table.name, pfrt_anchor=table.anchor)

        _addrs = []
        for addr in addrs:
            if isinstance(addr, PFTableAddr):
                _addrs.append(addr)
            elif isinstance(addr, basestring):
                _addrs.append(PFTableAddr(addr))

        io = pfioc_table()

        buffer = (pfr_addr * len(addrs))(*[a._to_struct() for a in _addrs])
        io.pfrio_buffer = addressof(buffer)
        io.pfrio_table = table
        io.pfrio_esize = sizeof(pfr_addr)
        io.pfrio_size = len(addrs)

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCRSETADDRS, io.asBuffer())

        return (io.pfrio_ndel, io.pfrio_nadd, io.pfrio_nchange)

    def get_addrs(self, table, buf_size=10):
        """Get all the addresses of the specified table.

        'table' can be either a PFTable instance or a string containing the
        table name. Return a list of PFTableAddr objects.
        """
        if isinstance(table, basestring):
            table = pfr_table(pfrt_name=table)
        else:
            table = pfr_table(pfrt_name=table.name, pfrt_anchor=table.anchor)

        io = pfioc_table()
        io.pfrio_table = table

        with open(self.dev, 'w') as d:
            while True:
                buffer = (pfr_addr * buf_size)()
                io.pfrio_buffer = addressof(buffer)
                io.pfrio_esize = sizeof(pfr_addr)
                io.pfrio_size = buf_size

                ioctl(d, DIOCRGETADDRS, io.asBuffer())

                if io.pfrio_size > buf_size:
                    buf_size = io.pfrio_size
                else:
                    break

        return tuple([PFTableAddr(a) for a in buffer[:io.pfrio_size]])
