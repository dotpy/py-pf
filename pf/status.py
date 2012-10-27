"""Classes representing the internal Packet Filter statistics and counters.

PFStatus objects contain a series of runtime statistical information describing
the current status of the Packet Filter.
"""

import time
from socket import ntohl

from pf.constants import *
from pf._struct import pf_status, pfi_kif
from pf._base import PFObject
from pf._utils import dbg_levels


__all__ = ['PFStatus',
           'PFIface']


class PFStatus(PFObject):
    """Class representing the internal Packet Filter statistics and counters."""

    _struct_type = pf_status

    def __init__(self, status):
        """Check argument and initialize class attributes."""
        super(PFStatus, self).__init__(status)

    def _from_struct(self, s):
        """Initialize class attributes from a pf_status structure."""
        self.ifname    = s.ifname
        self.running   = bool(s.running)
        self.stateid   = s.stateid
        self.since     = s.since
        self.states    = s.states
        self.src_nodes = s.src_nodes
        self.debug     = s.debug
        self.hostid    = ntohl(s.hostid) & 0xffffffff
        self.reass     = s.reass
        self.pf_chksum = "0x" + "".join(map("{:02x}".format, s.pf_chksum))

        self.cnt       = {'match':                    s.counters[0],
                          'bad-offset':               s.counters[1],
                          'fragment':                 s.counters[2],
                          'short':                    s.counters[3],
                          'normalize':                s.counters[4],
                          'memory':                   s.counters[5],
                          'bad-timestamp':            s.counters[6],
                          'congestion':               s.counters[7],
                          'ip-option':                s.counters[8],
                          'proto-cksum':              s.counters[9],
                          'state-mismatch':           s.counters[10],
                          'state-insert':             s.counters[11],
                          'state-limit':              s.counters[12],
                          'src-limit':                s.counters[13],
                          'synproxy':                 s.counters[14]}

        self.lcnt      = {'max states per rule':      s.lcounters[0],
                          'max-src-states':           s.lcounters[1],
                          'max-src-nodes':            s.lcounters[2],
                          'max-src-conn':             s.lcounters[3],
                          'max-src-conn-rate':        s.lcounters[4],
                          'overload table insertion': s.lcounters[5],
                          'overload flush states':    s.lcounters[6]}

        self.fcnt      = {'searches':                 s.fcounters[0],
                          'inserts':                  s.fcounters[1],
                          'removals':                 s.fcounters[2]}

        self.scnt      = {'searches':                 s.scounters[0],
                          'inserts':                  s.scounters[1],
                          'removals':                 s.scounters[2]}

        self.bytes     = {'in':   (s.bcounters[0][0], s.bcounters[1][0]),
                          'out':  (s.bcounters[0][1], s.bcounters[1][1])}

        self.packets   = {'in':  ((s.pcounters[0][0][PF_PASS],
                                   s.pcounters[1][0][PF_PASS]),
                                  (s.pcounters[0][0][PF_DROP],
                                   s.pcounters[1][0][PF_DROP])),
                          'out': ((s.pcounters[0][1][PF_PASS],
                                   s.pcounters[1][1][PF_PASS]),
                                  (s.pcounters[0][1][PF_DROP],
                                   s.pcounters[1][1][PF_DROP]))}

    def _to_string(self):
        """Return a string containing the statistics."""
        s = "Status: " + ('Enabled' if self.running else 'Disabled')

        if self.since:
            runtime = int(time.time()) - self.since
            day, sec = divmod(runtime, 60)
            day, min = divmod(day, 60)
            day, hrs = divmod(day, 24)
            s += " for {} days {:02}:{:02}:{:02}".format(day, hrs, min, sec)

        dbg = next((k for k, v in dbg_levels.iteritems() if v == self.debug),
                   "unknown")
        s = "{:<44}{:>15}\n\n".format(s, "Debug: " + dbg)
        s += "Hostid:   0x{.hostid:08x}\n".format(self)
        s += "Checksum: {.pf_chksum}\n\n".format(self)

        if self.ifname:
            fmt = "  {0:<25} {1[0]:>14d} {1[1]:>16d}\n"
            s += "Interface Stats for {.ifname:<16} ".format(self)
            s += "{:>5} {:>16}\n".format("IPv4", "IPv6")
            s += fmt.format("Bytes In", self.bytes["in"])
            s += fmt.format("Bytes Out", self.bytes["out"])
            s += "  Packets In\n"
            s += fmt.format("  Passed", self.packets["in"][PF_PASS])
            s += fmt.format("  Blocked", self.packets["in"][PF_DROP])
            s += "  Packets Out\n"
            s += fmt.format("  Passed", self.packets["out"][PF_PASS])
            s += fmt.format("  Blocked", self.packets["out"][PF_DROP])
            s += "\n"

        s += "{:<27} {:>14} {:>16}\n".format("State Table", "Total", "Rate")
        s += "  {:<25} {.states:>14d}".format("current entries", self)
        for k, v in self.fcnt.iteritems():
            s += "\n  {:<25} {:>14d} ".format(k, v)
            if self.since and runtime:
                s += "{:>14.1f}/s".format(float(v)/runtime)

        s += "\nSource Tracking Table\n"
        s += "  {:<25} {.src_nodes:>14d}".format("current entries", self)
        for k, v in self.scnt.iteritems():
            s += "\n  {:<25} {:>14d} ".format(k, v)
            if self.since and runtime:
                s += "{:>14.1f}/s".format(float(v)/runtime)

        s += "\nCounters"
        for k, v in self.cnt.iteritems():
            s += "\n  {:<25} {:>14d} ".format(k, v)
            if self.since and runtime:
                s += "{:>14.1f}/s".format(float(v)/runtime)

        s += "\nLimit Counters"
        for k, v in self.lcnt.iteritems():
            s += "\n  {:<25} {:>14d} ".format(k, v)
            if self.since and runtime:
                s += "{:>14.1f}/s".format(float(v)/runtime)

        return s


class PFIface(PFObject):
    """Class representing a network interface."""

    _struct_type = pfi_kif

    def __init__(self, iface):
        """Check argument and initialize class attributes."""
        super(PFIface, self).__init__(iface)

    def _from_struct(self, i):
        """Initialize class attributes from a pfi_kif structure."""
        self.name      = i.pfik_name
        self.packets   = {'in':  ((i.pfik_packets[0][0][PF_PASS],
                                   i.pfik_packets[1][0][PF_PASS]),
                                  (i.pfik_packets[0][0][PF_DROP],
                                   i.pfik_packets[1][0][PF_DROP])),
                          'out': ((i.pfik_packets[0][1][PF_PASS],
                                   i.pfik_packets[1][1][PF_PASS]),
                                  (i.pfik_packets[0][1][PF_DROP],
                                   i.pfik_packets[1][1][PF_DROP]))}
        self.bytes     = {'in':  ((i.pfik_bytes[0][0][PF_PASS],
                                   i.pfik_bytes[1][0][PF_PASS]),
                                  (i.pfik_bytes[0][0][PF_DROP],
                                   i.pfik_bytes[1][0][PF_DROP])),
                          'out': ((i.pfik_bytes[0][1][PF_PASS],
                                   i.pfik_bytes[1][1][PF_PASS]),
                                  (i.pfik_bytes[0][1][PF_DROP],
                                   i.pfik_bytes[1][1][PF_DROP]))}
        self.flags     = i.pfik_flags
        self.flags_new = i.pfik_flags_new
        self.states    = i.pfik_states
        self.cleared   = i.pfik_tzero
        self.rules     = i.pfik_rules
        self.routes    = i.pfik_routes

    def _to_string(self):
        """Return a string containing the description of the interface."""
        if (self.flags & PFI_IFLAG_SKIP):
            s = "{.name} (skip)\n".format(self)
        else:
            s = "{.name}\n".format(self)
        s += "\tCleared:     {}\n".format(time.ctime(self.cleared))
        s += "\tReferences:  [ States:  {.states:<18d}".format(self)
        s+= " Rules: {.rules:<18d} ]\n".format(self)

        pfik_ops = ("Pass:", "Block:")
        for o, p, b in zip(pfik_ops, self.packets["in"], self.bytes["in"]):
            l = "\tIn4/{:<6s}   [ Packets: {:<18d} Bytes: {:<18d} ]\n"
            s += l.format(o, p[0], b[0])
        for o, p, b in zip(pfik_ops, self.packets["out"], self.bytes["out"]):
            l = "\tOut4/{:<6s}  [ Packets: {:<18d} Bytes: {:<18d} ]\n"
            s += l.format(o, p[0], b[0])
        for o, p, b in zip(pfik_ops, self.packets["in"], self.bytes["in"]):
            l = "\tIn6/{:<6s}   [ Packets: {:<18d} Bytes: {:<18d} ]\n"
            s += l.format(o, p[1], b[1])
        for o, p, b in zip(pfik_ops, self.packets["out"], self.bytes["out"]):
            l = "\tOut6/{:<6s}  [ Packets: {:<18d} Bytes: {:<18d} ]\n"
            s += l.format(o, p[1], b[1])

        return s
