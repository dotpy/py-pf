"""A class for managing OpenBSD's Packet Filter.

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

from pf.exceptions import PFError
from pf.constants import *
from pf._struct import *
from pf._base import PFObject
from pf.queue import *
from pf.state import PFState
from pf.status import PFStatus, PFIface
from pf.table import PFTableAddr, PFTable, PFTStats
from pf.rule import PFRule, PFRuleset, pf_timeouts
from pf._utils import dbg_levels, pf_limits, pf_timeouts, pf_hints


__all__ = ['PacketFilter']


# ioctl() operations
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
DIOCSETSTATUSIF  = _IOWR('D', 20, pfioc_iface)
DIOCGETSTATUS    = _IOWR('D', 21, pf_status)
DIOCCLRSTATUS    = _IOWR('D', 22, pfioc_iface)
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
#DIOCGETRULESETS  = _IOWR('D', 58, pfioc_ruleset)
#DIOCGETRULESET   = _IOWR('D', 59, pfioc_ruleset)
DIOCRCLRTABLES   = _IOWR('D', 60, pfioc_table)
DIOCRADDTABLES   = _IOWR('D', 61, pfioc_table)
DIOCRDELTABLES   = _IOWR('D', 62, pfioc_table)
DIOCRGETTABLES   = _IOWR('D', 63, pfioc_table)
DIOCRGETTSTATS   = _IOWR('D', 64, pfioc_table)
DIOCRCLRTSTATS   = _IOWR('D', 65, pfioc_table)
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
DIOCIGETIFACES   = _IOWR('D', 87, pfioc_iface)
DIOCSETIFFLAG    = _IOWR('D', 89, pfioc_iface)
DIOCCLRIFFLAG    = _IOWR('D', 90, pfioc_iface)
#DIOCKILLSRCNODES = _IOWR('D', 91, pfioc_src_node_kill)
DIOCSETREASS     = _IOWR('D', 92, c_uint32)
DIOCADDQUEUE	 = _IOWR('D', 93, pfioc_queue)
DIOCGETQUEUES	 = _IOWR('D', 94, pfioc_queue)
DIOCGETQUEUE	 = _IOWR('D', 95, pfioc_queue)
DIOCGETQSTATS	 = _IOWR('D', 96, pfioc_qstats)


class _PFTrans(object):
    """Class for managing transactions with the Packet Filter subsystem."""

    def __init__(self, dev, path="", *trans_type):
        """Initialize the required structures."""
        self.dev = dev
        self.size = len(trans_type)
        self.array = (pfioc_trans_e * self.size)()

        for a, t in zip(self.array, trans_type):
            a.type = t
            a.anchor = path

        self._pt = pfioc_trans(size=self.size, esize=sizeof(pfioc_trans_e),
                               array=addressof(self.array))

    def __enter__(self):
        """Start the transaction."""
        ioctl(self.dev, DIOCXBEGIN, self._pt.asBuffer())
        return self

    def __exit__(self, type, value, traceback):
        """Commit changes if no exceptions occurred; otherwise, rollback."""
        if type is None:
            ioctl(self.dev, DIOCXCOMMIT, self._pt.asBuffer())
        else:
            ioctl(self.dev, DIOCXROLLBACK, self._pt.asBuffer())


class PacketFilter(object):
    """Class representing the kernel's packet filtering subsystem.

    It provides a set of methods that allow you to send commands to the kernel
    through the ioctl(2) interface provided by the pf(4) pseudo-device.
    Basically, all methods in this class are just wrappers to ioctl(2) calls,
    and may consequently raise IOError if the ioctl() request fails.
    """

    def __init__(self, dev="/dev/pf"):
        """Set the pf device."""
        self.dev = dev

    def enable(self):
        """Enable Packet Filtering."""
        with open(self.dev, 'w') as d:
            try:
                ioctl(d, DIOCSTART)
            except IOError, (e, s):
                if e != EEXIST:       # EEXIST means PF is already enabled
                    raise

    def disable(self):
        """Disable Packet Filtering."""
        with open(self.dev, 'w') as d:
            try:
                ioctl(d, DIOCSTOP)
            except IOError, (e, s):
                if e != ENOENT:       # ENOENT means PF is already disabled
                    raise 

    def set_debug(self, level):
        """Set the debug level.

        The debug level can be either one of the LOG_* constants or a string.
        """
        if level in dbg_levels:
            level = dbg_levels[level]

        with open(self.dev, 'w') as d:
            with _PFTrans(d):
                ioctl(d, DIOCSETDEBUG, c_uint32(level))

    def set_hostid(self, id):
        """Set the host ID.

        The host ID is used by pfsync to identify the host that created a state
        table entry. 'id' must be a 32-bit unsigned integer.
        """
        with open(self.dev, 'w') as d:
            with _PFTrans(d):
                ioctl(d, DIOCSETHOSTID, c_uint32(htonl(id)))

    def set_reassembly(self, reassembly):
        """Enable reassembly of network traffic.

        The 'reassembly' argument specifies the flags for the reassembly
        operation; available flags are PF_REASS_ENABLED and PF_REASS_NODF.
        """
        with open(self.dev, 'w') as d:
            with _PFTrans(d):
                ioctl(d, DIOCSETREASS, c_uint32(reassembly))

    def get_limit(self, limit=None):
        """Return the hard limits on the memory pools used by Packet Filter.

        'limit' can be either one of the PF_LIMIT_* constants or a string;
        return the value of the requested limit (UINT_MAX means unlimited) or,
        if called with no arguments, a dictionary containing all the available
        limits.
        """
        if limit is None:
            return dict([(l, self.get_limit(l)) for l in pf_limits])
        elif limit in pf_limits:
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
        if limit in pf_limits:
            limit = pf_limits[limit]

        pl = pfioc_limit(index=limit, limit=value)
        with open(self.dev, 'w') as d:
            with _PFTrans(d):
                try:
                    ioctl(d, DIOCSETLIMIT, pl.asBuffer())
                except IOError, (e, s):
                    if e == EBUSY:
                        raise PFError("Current pool size > {0:d}".format(value))
                    raise

    def get_timeout(self, timeout=None):
        """Return the configured timeout values for PF states.

        'timeout' can be either one of the PFTM_* constants or a string; return
        the value of the requested timeout or, if called with no arguments, a
        dictionary containing all the available timeouts.
        """
        if timeout is None:
            return dict([(t, self.get_timeout(t)) for t in pf_timeouts])
        elif timeout in pf_timeouts:
            timeout = pf_timeouts[timeout]

        tm = pfioc_tm(timeout=timeout)
        with open(self.dev, 'r') as d:
            ioctl(d, DIOCGETTIMEOUT, tm.asBuffer())

        return tm.seconds

    def set_timeout(self, timeout, value):
        """Set the timeout 'value' for a specific PF state.

        'timeout' can be either one of the PFTM_* constants or a string; return
        the old value of the specified timeout.
        """
        if timeout in pf_timeouts:
            timeout = pf_timeouts[timeout]

        tm = pfioc_tm(timeout=timeout, seconds=value)
        with open(self.dev, 'w') as d:
            with _PFTrans(d):
                ioctl(d, DIOCSETTIMEOUT, tm.asBuffer())

        return tm.seconds

    def set_optimization(self, opt="normal"):
        """Set the optimization profile for state handling like pfctl."""
        for name, val in pf_hints[opt].iteritems():
            self.set_timeout(name, val)

    def get_optimization(self):
        """ """
        tm = self.get_timeout()
        for name, val in pf_hints.iteritems():
            if val["tcp.first"] == tm["tcp.first"]:
                return name

    def get_ifaces(self, ifname=""):
        """Get the list of interfaces and interface drivers known to pf.

        Return a tuple of PFIface objects or a single PFIface object if a
        specific 'ifname' is specified.
        """
        pi = pfioc_iface(pfiio_name=ifname, pfiio_esize=sizeof(pfi_kif))

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCIGETIFACES, pi.asBuffer())
            buf = (pfi_kif * pi.pfiio_size)()
            pi.pfiio_buffer = addressof(buf)
            ioctl(d, DIOCIGETIFACES, pi.asBuffer())

        if ifname and len(buf) == 1:
            return PFIface(buf[0])
        else:
            return tuple(map(PFIface, buf))

    def set_ifflags(self, ifname, flags):
        """Set the user setable 'flags' on the interface 'ifname'."""
        pi = pfioc_iface(pfiio_name=ifname, pfiio_flags=flags)
        with open(self.dev, 'w') as d:
            with _PFTrans(d):
                ioctl(d, DIOCSETIFFLAG, pi.asBuffer())

    def clear_ifflags(self, ifname, flags=None):
        """Clear the specified user setable 'flags' on the interface 'ifname'.

        If no flags are specified, clear all flags.
        """
        if flags is None:
            flags = PFI_IFLAG_SKIP

        pi = pfioc_iface(pfiio_name=ifname, pfiio_flags=flags)
        with open(self.dev, 'w') as d:
            with _PFTrans(d):
                ioctl(d, DIOCCLRIFFLAG, pi.asBuffer())

    def set_status_if(self, ifname=""):
        """Specify the interface for which statistics are accumulated.

        If no 'ifname' is provided, turn off the collection of per-interface
        statistics. Raise PFError if 'ifname' is not a valid interface name.
        """
        pi = pfioc_iface(pfiio_name=ifname)
        with open(self.dev, 'w') as d:
            with _PFTrans(d):
                try:
                    ioctl(d, DIOCSETSTATUSIF, pi.asBuffer())
                except IOError, (e, s):
                    if e == EINVAL:
                        raise PFError("Invalid ifname: '{0}'".format(ifname))
                    raise

    def get_status(self):
        """Return a PFStatus object containing the internal PF statistics."""
        s = pf_status()
        with open(self.dev, 'w') as d:
            ioctl(d, DIOCGETSTATUS, s.asBuffer())

        return PFStatus(s)

    def clear_status(self, ifname=""):
        """Clear the internal packet filter statistics.

        An optional 'ifname' can be specified in order to clear statistics only
        for a specific interface.
        """
        pi = pfioc_iface(pfiio_name=ifname)
        with open(self.dev, 'w') as d:
            ioctl(d, DIOCCLRSTATUS, pi.asBuffer())

    def get_states(self):
        """Retrieve Packet Filter's state table entries.

        Return a tuple of PFState objects representing the states currently
        tracked by PF.
        """
        ps = pfioc_states()

        l  = 0
        with open(self.dev, 'w') as d:
            while True:
                if l:
                    ps_states = (pfsync_state * (l / sizeof(pfsync_state)))()
                    ps.ps_buf = addressof(ps_states)
                    ps.ps_len = l
                ioctl(d, DIOCGETSTATES, ps.asBuffer())
                if ps.ps_len == 0:
                    return ()
                if ps.ps_len <= l:
                    break
                l = (ps.ps_len * 2)

        ps_num = (ps.ps_len / sizeof(pfsync_state))
        return tuple([PFState(s) for s in ps_states[:ps_num]])

    def clear_states(self, ifname=""):
        """Clear all states.

        If an interface name is provided, only states for that interface will
        be cleared. Return the number of cleared states.
        """
        psk = pfioc_state_kill(psk_ifname=ifname)

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCCLRSTATES, psk.asBuffer())

        return psk.psk_killed

    def kill_states(self, af=AF_UNSPEC, proto=0, src=None, dst=None, ifname="",
                    label="", rdomain=0):
        """Clear states matching the specified arguments.

        States can be specified by address family, layer-4 protocol, source and
        destination addresses, interface name, label and routing domain. Return
        the number of killed states.
        """
        psk = pfioc_state_kill(psk_af=af, psk_proto=proto, psk_ifname=ifname,
                               psk_label=label, psk_rdomain=rdomain)
        if src:
            psk.psk_src = src._to_struct()
        if dst:
            psk.psk_dst = dst._to_struct()

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCKILLSTATES, psk.asBuffer())

        return psk.psk_killed

    def clear_rules(self, path=""):
        """Clear all rules contained in the anchor 'path'."""
        self.load_ruleset(PFRuleset(), path, PF_TRANS_RULESET)

    def load_queues(self, *queues):
        """Load a set of queues on an interface.

        'queues' must be PFQueue objects.
        """
        with open(self.dev, 'w') as d:
            with _PFTrans(d, "", PF_TRANS_RULESET) as t:
                for queue in queues:
                    q = pfioc_queue(ticket=t.array[0].ticket,
                                    queue=queue._to_struct())
                    ioctl(d, DIOCADDQUEUE, q)

    def get_queues(self):
        """Retrieve the currently loaded queues.

        Return a tuple of PFQueue objects.
        """
        queues = []
        pq = pfioc_queue()
        with open(self.dev, 'r') as d:
            ioctl(d, DIOCGETQUEUES, pq)

            qstats = queue_stats()
            for nr in range(pq.nr):
                pqs = pfioc_qstats(nr=nr, ticket=pq.ticket,
                                   buf=addressof(qstats.data),
                                   nbytes=sizeof(class_stats))
                ioctl(d, DIOCGETQSTATS, pqs)
                queue = PFQueue(pqs.queue)
                queue.stats = PFQueueStats(qstats.data)
                queues.append(queue)

        return queues

    def _get_rules(self, path, dev, clear):
        """Recursively retrieve rules from the specified ruleset."""
        if path.endswith("/*"):
            path = path[:-2]

        pr = pfioc_rule(anchor=path)
        if clear:
            pr.action = PF_GET_CLR_CNTR

        pr.rule.action = PF_PASS
        ioctl(dev, DIOCGETRULES, pr.asBuffer())

        tables = list(self.get_tables(PFTable(anchor=path)))
        rules = []
        for nr in range(pr.nr):
            pr.nr = nr
            ioctl(dev, DIOCGETRULE, pr.asBuffer())
            if pr.anchor_call:
                path = os.path.join(pr.anchor, pr.anchor_call)
                rs = PFRuleset(pr.anchor_call, pr.rule)
                rs.append(*self._get_rules(path, dev, clear))
                rules.append(rs)
            else:
                rules.append(PFRule(pr.rule))

        return tables + rules

    def get_ruleset(self, path="", clear=False, **kw):
        """Return a PFRuleset object containing the active ruleset.
        
        'path' is the path of the anchor to retrieve rules from. If 'clear' is
        True, per-rule statistics will be cleared. Keyword arguments can be
        passed for returning only matching rules.
        """
        rs = PFRuleset(os.path.basename(path))

        with open(self.dev, 'r') as d:
            for rule in self._get_rules(path, d, clear):
                if isinstance(rule, PFRule):
                    if not all((getattr(rule, attr) == value)
                               for (attr, value) in kw.iteritems()):
                        continue
                rs.append(rule)
        return rs

    def _inadefine(self, table, dev, path, ticket):
        """Define a table in the inactive ruleset."""
        table.anchor = path
        io = pfioc_table(pfrio_table=table._to_struct(), pfrio_ticket=ticket,
                         pfrio_esize=sizeof(pfr_addr))

        if table.addrs:
            io.pfrio_flags |= PFR_FLAG_ADDRSTOO
            addrs = table.addrs
            buf = (pfr_addr * len(addrs))(*[a._to_struct() for a in addrs])
            io.pfrio_buffer = addressof(buf)
            io.pfrio_size = len(addrs)

        ioctl(dev, DIOCRINADEFINE, io.asBuffer())

    def load_ruleset(self, ruleset, path="", *tr_type):
        """Load the given ruleset.

        'ruleset' must be a PFRuleset object; 'path' is the name of the anchor
        where to load rules; 'tr_type' is one or more PF_TRANS_* constants: if
        omitted, all ruleset types will be loaded.
        """
        if not tr_type:
            tr_type = (PF_TRANS_TABLE, PF_TRANS_RULESET)

        with open(self.dev, 'w') as d:
            with _PFTrans(d, path, *tr_type) as t:
                for a in t.array:
                    if a.type == PF_TRANS_TABLE:
                        for t in ruleset.tables:
                            self._inadefine(t, d, path, a.ticket)
                    elif a.type == PF_TRANS_RULESET:
                        for r in ruleset.rules:
                            pr = pfioc_rule(ticket=a.ticket, anchor=path,
                                            rule=r._to_struct())

                            if isinstance(r, PFRuleset):
                                pr.anchor_call = r.name

                            ioctl(d, DIOCADDRULE, pr.asBuffer())

                            if isinstance(r, PFRuleset):
                                self.load_ruleset(r, os.path.join(path, r.name),
                                                  *tr_type)

    def add_tables(self, *tables):
        """Create one or more tables.

        'tables' must be PFTable objects; return the number of tables created.
        """
        io = pfioc_table(pfrio_esize=sizeof(pfr_table), pfrio_size=len(tables))

        buffer = (pfr_table * len(tables))(*[t._to_struct() for t in tables])
        io.pfrio_buffer = addressof(buffer)

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
        io = pfioc_table(pfrio_esize=sizeof(pfr_table), pfrio_size=len(tables))

        buffer = (pfr_table * len(tables))()
        for (t, b) in zip(tables, buffer):
            b.pfrt_name = t.name
            b.pfrt_anchor = t.anchor

        io.pfrio_buffer = addressof(buffer)

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCRDELTABLES, io.asBuffer())

        return io.pfrio_ndel

    def get_tables(self, filter=None, buf_size=10):
        """Get the list of all tables.

        'filter' is a PFTable object that allows you to specify the attributes
        of the tables to retrieve. Return a tuple of PFTable objects containing
        the currently-loaded tables.
        """
        io = pfioc_table(pfrio_esize=sizeof(pfr_table))

        if filter is not None:
            io.pfrio_table = pfr_table(pfrt_name=filter.name,
                                       pfrt_anchor=filter.anchor)

        with open(self.dev, 'w') as d:
            while True:
                buffer = (pfr_table * buf_size)()
                io.pfrio_buffer = addressof(buffer)
                io.pfrio_size = buf_size

                ioctl(d, DIOCRGETTABLES, io.asBuffer())

                if io.pfrio_size <= buf_size:
                    break
                buf_size = io.pfrio_size

        tables = []
        for t in buffer[:io.pfrio_size]:
            try:
                addrs = self.get_addrs(PFTable(t))
            except IOError, (e, s):
                pass       # Ignore tables of which you can't get the addresses
            else:
                tables.append(PFTable(t, *addrs))

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

        io = pfioc_table(pfrio_table=table, pfrio_esize=sizeof(pfr_addr),
                         pfrio_size=len(addrs))

        buffer = (pfr_addr * len(addrs))(*[a._to_struct() for a in _addrs])
        io.pfrio_buffer = addressof(buffer)

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

        io = pfioc_table(pfrio_table=table)

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
            else:
                _addrs.append(PFTableAddr(addr))

        io = pfioc_table(pfrio_table=table, pfrio_esize=sizeof(pfr_addr),
                         pfrio_size=len(addrs))

        buffer = (pfr_addr * len(addrs))(*[a._to_struct() for a in _addrs])
        io.pfrio_buffer = addressof(buffer)

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
            else:
                _addrs.append(PFTableAddr(addr))

        io = pfioc_table(pfrio_table=table, pfrio_esize=sizeof(pfr_addr),
                         pfrio_size=len(addrs))

        buffer = (pfr_addr * len(addrs))(*[a._to_struct() for a in _addrs])
        io.pfrio_buffer = addressof(buffer)

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCRSETADDRS, io.asBuffer())

        return (io.pfrio_ndel, io.pfrio_nadd, io.pfrio_nchange)

    def get_addrs(self, table, buf_size=10):
        """Get the addresses in the specified table.

        'table' can be either a PFTable instance or a string containing the
        table name. Return a list of PFTableAddr objects.
        """
        if isinstance(table, basestring):
            table = pfr_table(pfrt_name=table)
        else:
            table = pfr_table(pfrt_name=table.name, pfrt_anchor=table.anchor)

        io = pfioc_table(pfrio_table=table, pfrio_esize=sizeof(pfr_addr))

        with open(self.dev, 'w') as d:
            while True:
                buffer = (pfr_addr * buf_size)()
                io.pfrio_buffer = addressof(buffer)
                io.pfrio_size = buf_size

                ioctl(d, DIOCRGETADDRS, io.asBuffer())

                if io.pfrio_size <= buf_size:
                    break
                buf_size = io.pfrio_size

        return tuple([PFTableAddr(a) for a in buffer[:io.pfrio_size]])

    def get_tstats(self, filter=None, buf_size=10):
        """Get statistics information for one or more tables.

        'filter' is a PFTable object that allows you to specify the attributes
        of the tables to retrieve statistics for. Return a tuple of PFTStats
        objects.
        """
        io = pfioc_table(pfrio_esize=sizeof(pfr_tstats))

        if filter is not None:
            io.pfrio_table = pfr_table(pfrt_name=filter.name,
                                       pfrt_anchor=filter.anchor)

        with open(self.dev, 'w') as d:
            while True:
                buffer = (pfr_tstats * buf_size)()
                io.pfrio_buffer = addressof(buffer)
                io.pfrio_size = buf_size

                ioctl(d, DIOCRGETTSTATS, io.asBuffer())

                if io.pfrio_size <= buf_size:
                    break
                buf_size = io.pfrio_size

        stats = []
        for t in buffer[:io.pfrio_size]:
            if t.pfrts_tzero:
                stats.append(PFTStats(t))

        return tuple(stats)

    def clear_tstats(self, *tables):
        """Clear the statistics of one or more tables.

        'tables' must be PFTable objects. Return the number of tables cleared.
        """
        io = pfioc_table(pfrio_esize=sizeof(pfr_table), pfrio_size=len(tables))

        buffer = (pfr_table * len(tables))()
        for (t, b) in zip(tables, buffer):
            b.pfrt_name = t.name
            b.pfrt_anchor = t.anchor

        io.pfrio_buffer = addressof(buffer)

        with open(self.dev, 'w') as d:
            ioctl(d, DIOCRCLRTSTATS, io.asBuffer())

        return io.pfrio_nadd
