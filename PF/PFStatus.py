"""Class representing the internal Packet Filter statistics and counters.

PFStatus objects contain a series of runtime statistical information describing
the current status of the Packet Filter.
"""

__all__ = ['PFStatus']


import time
from socket import *

from _PFStruct import pf_status
from PFConstants import *


# PFStatus class ###############################################################
class PFStatus:
    """Represents the internal packet filter statistics and counters."""

    def __init__(self, status):
        """Check argument and initialize class attributes"""
        if not isinstance(status, pf_status):
            raise TypeError, "'status' must be a pf_status structure"
        self._from_struct(status)

    def _from_struct(self, s):
        """Initialize class attributes from a pf_status structure"""
        self.ifname    = s.ifname
        self.running   = bool(s.running)
        self.since     = s.since
        self.states    = s.states
        self.src_nodes = s.src_nodes
        self.debug     = s.debug
        self.hostid    = (ntohl(s.hostid) & 0xffffffff)
        self.chksum    = "0x" + "".join(["%02x" % b for b in s.pf_chksum])

        self.cnt       = {"match":                    s.counters[0],
                          "bad-offset":               s.counters[1],
                          "fragment":                 s.counters[2],
                          "short":                    s.counters[3],
                          "normalize":                s.counters[4],
                          "memory":                   s.counters[5],
                          "bad-timestamp":            s.counters[6],
                          "congestion":               s.counters[7],
                          "ip-option":                s.counters[8],
                          "proto-cksum":              s.counters[9],
                          "state-mismatch":           s.counters[10],
                          "state-insert":             s.counters[11],
                          "state-limit":              s.counters[12],
                          "src-limit":                s.counters[13],
                          "synproxy":                 s.counters[14]}

        self.lcnt      = {"max states per rule":      s.lcounters[0],
                          "max-src-states":           s.lcounters[1],
                          "max-src-nodes":            s.lcounters[2],
                          "max-src-conn":             s.lcounters[3],
                          "max-src-conn-rate":        s.lcounters[4],
                          "overload table insertion": s.lcounters[5],
                          "overload flush states":    s.lcounters[6]}

        self.fcnt      = {"searches":                 s.fcounters[0],
                          "inserts":                  s.fcounters[1],
                          "removals":                 s.fcounters[2]}

        self.scnt      = {"searches":                 s.scounters[0],
                          "inserts":                  s.scounters[1],
                          "removals":                 s.scounters[2]}

        self.bcnt      = {"in":   (s.bcounters[0][0], s.bcounters[1][0]),
                          "out":  (s.bcounters[0][1], s.bcounters[1][1])}

        self.pcnt      = {"in":  ((s.pcounters[0][0][PF_PASS],
                                   s.pcounters[1][0][PF_PASS]),
                                  (s.pcounters[0][0][PF_DROP],
                                   s.pcounters[1][0][PF_DROP])),
                          "out": ((s.pcounters[0][1][PF_PASS],
                                   s.pcounters[1][1][PF_PASS]),
                                  (s.pcounters[0][1][PF_DROP],
                                   s.pcounters[1][1][PF_DROP]))}

    def _to_string(self):
        """Return a string containing the statistics."""
        if self.running:
            s = "Status: Enabled"
        else:
            s = "Status: Disabled"

        if self.since:
            runtime = time.time() - self.since
            day, sec = divmod(runtime, 60)
            day, min = divmod(day, 60)
            day, hrs = divmod(day, 24)
            s += " for %i days %02i:%02i:%02i" % (day, hrs, min, sec)

        debug = ("None", "Urgent", "Misc", "Loud")[self.debug]
        s = "%-44s%15s\n\n" % (s, "Debug: " + debug)

        s += "Hostid:   0x%08x\n" % self.hostid
        s += "Checksum: %s\n\n" % self.chksum

        if self.ifname:
            fmt = "  %-25s %14u %16u\n"
            s += "Interface Stats for %-16s %5s %16s\n" % (self.ifname,
                                                           "IPv4", "IPv6")
            s += fmt % (("Bytes In",)  + self.bcnt["in"])
            s += fmt % (("Bytes Out",) + self.bcnt["out"])
            s += "  Packets In\n"
            s += fmt % (("  Passed",)  + self.pcnt["in"][PF_PASS])
            s += fmt % (("  Blocked",) + self.pcnt["in"][PF_DROP])
            s += "  Packets Out\n"
            s += fmt % (("  Passed",)  + self.pcnt["out"][PF_PASS])
            s += fmt % (("  Blocked",) + self.pcnt["out"][PF_DROP])
            s += "\n"

        s += "%-27s %14s %16s\n" % ("State Table", "Total", "Rate")
        s += "  %-25s %14u" % ("current entries", self.states)
        for k, v in self.fcnt.iteritems():
            s += "\n  %-25s %14u " % (k, v)
            if self.since:
                s += "%14.1f/s" % (v/runtime)

        s += "\nSource Tracking Table"
        s += "\n  %-25s %14u" % ("current entries", self.src_nodes)
        for k, v in self.scnt.iteritems():
            s += "\n  %-25s %14u " % (k, v)
            if self.since:
                s += "%14.1f/s" % (v/runtime)

        s += "\nCounters"
        for k, v in self.cnt.iteritems():
            s += "\n  %-25s %14u " % (k, v)
            if self.since:
                s += "%14.1f/s" % (v/runtime)

        s += "\nLimit Counters"
        for k, v in self.lcnt.iteritems():
            s += "\n  %-25s %14u " % (k, v)
            if self.since:
                s += "%14.1f/s" % (v/runtime)

        return s

    def __str__(self):
        return self._to_string()

