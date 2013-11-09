"""Classes to represent Packet Filter's queueing schedulers and statistics."""

from pf.exceptions import PFError
from pf.constants import *
from pf._struct import *
from pf._base import PFObject
from pf._utils import rate2str, getifmtu


__all__ = ['PFAltqCBQ',
           'PFAltqHFSC',
           'PFAltqPriQ',
           'CBQStats',
           'PriQStats',
           'HFSCStats']


class PFAltq(PFObject):
    """Parent class for the specific queue classes."""

    _struct_type = pf_altq

    def __init__(self, altq=None, **kw):
        """Check argument and initialize class attributes.

        'altq' can be either a pfaltq structure or a string with the name of
        the queue.
        """
        if isinstance(altq, basestring):
            kw["qname"] = altq
        if altq is None or isinstance(altq, basestring):
            altq = pf_altq(qlimit=DEFAULT_QLIMIT, priority=DEFAULT_PRIORITY)

        super(PFAltq, self).__init__(altq, **kw)

        if not self.ifname:
            raise PFError("Interface name not specified")

        mtu, ifbw = getifmtu(self.ifname)
        if not self.ifbandwidth:
            if not ifbw:
                raise PFError("No ifbandwidth for interface " +
                              "'{.ifname}'".format(self))
            self.ifbandwidth = ifbw

        if not self.qname and not self.parent:
            # This is a root ALTQ discipline
            self.bandwidth = 0
            self.priority = 0

            if not self.tbrsize:
                self.tbrsize = mtu * 24
                if self.ifbandwidth <= 1 * 1000 * 1000:
                    self.tbrsize = mtu
                elif self.ifbandwidth <= 4 * 1000 * 1000:
                    self.tbrsize = mtu * 4
                elif self.ifbandwidth <= 8 * 1000 * 1000:
                    self.tbrsize = mtu * 8

    def _from_struct(self, q):
        """Initialize class attributes from a pf_altq structure."""
        self.ifname      = q.ifname
        #self.altq_disc   = q.altq_disc
        #self.entries     = q.entries
        self.scheduler   = q.scheduler
        self.tbrsize     = q.tbrsize
        self.ifbandwidth = q.ifbandwidth
        self.qname       = q.qname
        self.parent      = q.parent
        self.parent_qid  = q.parent_qid
        self.bandwidth   = q.bandwidth
        self.priority    = q.priority
        self.qlimit      = q.qlimit
        self.flags       = q.flags
        #self.pq_u        = q.pq_u
        self.qid         = q.qid

        self._opts_from_struct(q)

    def _to_struct(self):
        """Convert this instance to a pf_altq structure."""
        q = pf_altq()

        q.ifname      = self.ifname
        #q.altq_disc   = self.altq_disc
        #q.entries     = self.entries
        q.scheduler   = self.scheduler
        q.tbrsize     = self.tbrsize
        q.ifbandwidth = self.ifbandwidth
        q.qname       = self.qname
        q.parent      = self.parent
        q.parent_qid  = self.parent_qid
        q.bandwidth   = self.bandwidth
        q.priority    = self.priority
        q.qlimit      = self.qlimit
        q.flags       = self.flags
        #q.pq_u        = self.pq_u
        q.qid         = self.qid

        self._opts_to_struct(q)
        return q

    def _opts_from_struct(self, q):
        raise NotImplementedError()

    def _opts_to_struct(self, q):
        raise NotImplementedError()

    def _str_opts(self):
        raise NotImplementedError()

    def _str_altq(self):
        """Convert a root ALTQ discipline to a string."""
        altqs = {ALTQT_CBQ: "cbq", ALTQT_PRIQ: "priq", ALTQT_HFSC: "hfsc"}

        s  = "altq on {.ifname} ".format(self)
        s += "{} {}".format(altqs[self.scheduler], self._str_opts())

        if (0 < self.ifbandwidth < 100):
            s += "bandwidth {.ifbandwidth}% ".format(self)
        elif (self.ifbandwidth >= 100):
            s += "bandwidth {} ".format(rate2str(self.ifbandwidth))
        if self.qlimit != DEFAULT_QLIMIT:
            s += "qlimit {.qlimit} ".format(self)
        s += "tbrsize {.tbrsize}".format(self)

        return s

    def _str_queue(self):
        """Convert a child ALTQ discipline to a string."""
        altqs = {ALTQT_CBQ: "cbq", ALTQT_PRIQ: "priq", ALTQT_HFSC: "hfsc"}
        opts = self._str_opts()

        s = "queue {0.qname} on {0.ifname} ".format(self)

        if self.scheduler in (ALTQT_CBQ, ALTQT_HFSC):
            if (0 < self.bandwidth < 100):
                s += "bandwidth {.bandwidth}% ".format(self)
            elif (self.bandwidth >= 100):
                s += "bandwidth {} ".format(rate2str(self.bandwidth))
        if self.priority != DEFAULT_PRIORITY:
            s += "priority {.priority} ".format(self)
        if self.qlimit != DEFAULT_QLIMIT:
            s += "qlimit {.qlimit} ".format(self)
        if opts:
            s += "{}{}".format(altqs[self.scheduler], opts)

        return s

    def _to_string(self):
        """Return the string representation of the queue."""
        return (self._str_queue() if self.qname else self._str_altq())


class PFAltqCBQ(PFAltq):
    """Class representing a Class Based Queueing queue."""

    def __init__(self, altq=None, **kw):
        """Check argument and initialize class attributes."""
        super(PFAltqCBQ, self).__init__(altq, scheduler=ALTQT_CBQ, **kw)
        if (altq is None or isinstance(altq, basestring)) and self.qname:
            self._set_opts()
        if self.qname and not self.parent:
            self.optflags |= (CBQCLF_ROOTCLASS | CBQCLF_WRR)

    def _opts_from_struct(self, q):
        """Initialize options from a cbq_opts structure."""
        self.opts = {"minburst":    q.pq_u.cbq_opts.minburst,
                     "maxburst":    q.pq_u.cbq_opts.maxburst,
                     "pktsize":     q.pq_u.cbq_opts.pktsize,
                     "maxpktsize":  q.pq_u.cbq_opts.maxpktsize,
                     "ns_per_byte": q.pq_u.cbq_opts.ns_per_byte,
                     "maxidle":     q.pq_u.cbq_opts.maxidle,
                     "minidle":     q.pq_u.cbq_opts.minidle,
                     "offtime":     q.pq_u.cbq_opts.offtime}

        self.optflags = q.pq_u.cbq_opts.flags

    def _opts_to_struct(self, q):
        """Insert options into the cbq_opts structure."""
        q.pq_u.cbq_opts.minburst    = self.opts["minburst"]
        q.pq_u.cbq_opts.maxburst    = self.opts["maxburst"]
        q.pq_u.cbq_opts.pktsize     = self.opts["pktsize"]
        q.pq_u.cbq_opts.maxpktsize  = self.opts["maxpktsize"]
        q.pq_u.cbq_opts.ns_per_byte = self.opts["ns_per_byte"]
        q.pq_u.cbq_opts.maxidle     = self.opts["maxidle"]
        q.pq_u.cbq_opts.minidle     = self.opts["minidle"]
        q.pq_u.cbq_opts.offtime     = self.opts["offtime"]
        q.pq_u.cbq_opts.flags       = self.optflags

    def _set_opts(self):
        """Set scheduler-specific options based on heuristics."""
        # Constants
        MCLSHIFT = 11                 # from /usr/src/sys/sys/param.h
        MCLBYTES = 1 << MCLSHIFT      # from /usr/src/sys/sys/param.h
        RM_NS_PER_SEC  = 1000000000   # from pfctl_altq.c
        RM_FILTER_GAIN = 5            # from pfctl_altq.c

        mtu, ifbw = getifmtu(self.ifname)
        pktsize = ((mtu & ~MCLBYTES) if (mtu > MCLBYTES) else mtu)
        maxpktsize = mtu
        if pktsize > maxpktsize:
            pktsize = maxpktsize

        f = 0.0001
        if self.bandwidth:
            f = float(self.bandwidth) / self.ifbandwidth
        if_ns_per_byte = (1.0 / self.ifbandwidth) * RM_NS_PER_SEC * 8
        ns_per_byte = if_ns_per_byte / f
        ptime = pktsize * if_ns_per_byte
        cptime = ptime * (1.0 - f) / f
        maxburst = (4 if (cptime > 10 * 1000000) else 16)
        minburst = (2 if (maxburst >= 2) else maxburst)

        z = 1 <<  RM_FILTER_GAIN
        g = 1.0 - (1.0 / z)
        gton = g ** maxburst
        gtom = g ** (minburst -1)
        maxidle = ((1.0 / f - 1.0) * ((1.0 - gton) / gton))
        maxidle_s = 1.0 - g
        maxidle = ptime * (maxidle if (maxidle > maxidle_s) else maxidle_s)
        offtime = cptime * (1.0 + 1.0 / (1.0 - g) * (1.0 - gtom) / gtom)
        minidle = -(maxpktsize * ns_per_byte)

        maxidle = ((maxidle*8.0) / ns_per_byte) * (2 ** RM_FILTER_GAIN)
        offtime = ((offtime*8.0) / ns_per_byte) * (2 ** RM_FILTER_GAIN)
        minidle = ((minidle*8.0) / ns_per_byte) * (2 ** RM_FILTER_GAIN)

        self.opts["minburst"]    = minburst
        self.opts["maxburst"]    = maxburst
        self.opts["pktsize"]     = pktsize
        self.opts["maxpktsize"]  = maxpktsize
        self.opts["ns_per_byte"] = int(ns_per_byte)
        self.opts["maxidle"]     = int(abs(maxidle / 1000.0))
        self.opts["minidle"]     = int(minidle / 1000.0)
        self.opts["offtime"]     = int(abs(offtime / 1000.0))

    def _str_opts(self):
        """Return the string representation of class-specific options."""
        opts = []
        if self.optflags & CBQCLF_RED:
            opts.append("red")
        if self.optflags & CBQCLF_ECN:
            opts.append("ecn")
        if self.optflags & CBQCLF_BORROW:
            opts.append("borrow")
        if self.optflags & CBQCLF_WRR:
            opts.append("wrr")
        if self.optflags & CBQCLF_ROOTCLASS:
            opts.append("root")
        if self.optflags & CBQCLF_DEFCLASS:
            opts.append("default")

        return ("( {0} ) ".format(" ".join(opts)) if opts else "")


class PFAltqHFSC(PFAltq):
    """Class representing a Hierarchical Fair Service Curve queue."""

    def __init__(self, altq=None, **kw):
        """Check argument and initialize class attributes."""
        super(PFAltqHFSC, self).__init__(altq, scheduler=ALTQT_HFSC, **kw)

    def _opts_from_struct(self, q):
        """Initialize options from a hfsc_opts structure."""
        self.rtsc = (q.pq_u.hfsc_opts.rtsc_m1, q.pq_u.hfsc_opts.rtsc_d,
                     q.pq_u.hfsc_opts.rtsc_m2)
        self.lssc = (q.pq_u.hfsc_opts.lssc_m1, q.pq_u.hfsc_opts.lssc_d,
                     q.pq_u.hfsc_opts.lssc_m2)
        self.ulsc = (q.pq_u.hfsc_opts.ulsc_m1, q.pq_u.hfsc_opts.ulsc_d,
                     q.pq_u.hfsc_opts.ulsc_m2)
        self.optflags = q.pq_u.hfsc_opts.flags

    def _opts_to_struct(self, q):
        """Insert options into the hfsc_opts structure."""
        q.pq_u.hfsc_opts.rtsc_m1 = self.rtsc[0]
        q.pq_u.hfsc_opts.rtsc_d  = self.rtsc[1]
        q.pq_u.hfsc_opts.rtsc_m2 = self.rtsc[2]
        q.pq_u.hfsc_opts.lssc_m1 = self.lssc[0]
        q.pq_u.hfsc_opts.lssc_d  = self.lssc[1]
        q.pq_u.hfsc_opts.lssc_m2 = self.lssc[2]
        q.pq_u.hfsc_opts.ulsc_m1 = self.ulsc[0]
        q.pq_u.hfsc_opts.ulsc_d  = self.ulsc[1]
        q.pq_u.hfsc_opts.ulsc_m2 = self.ulsc[2]
        q.pq_u.hfsc_opts.flags   = self.optflags

    def _str_sc(self, m1, d, m2):
        """Return the string representation of the service curve."""
        s = ""
        if m2:
            s = " {}".format(rate2str(m2))
        if d:
            s = "({} {}{})".format(rate2str(m1), d, s)
        return s

    def _str_opts(self):
        """Return the string representation of class-specific options."""
        opts = []
        if (self.optflags or self.rtsc[2] or self.ulsc[2] or
            (self.lssc[2] and (self.lssc[2] != self.bandwidth or
                               self.lssc[1]))):
            if self.optflags & HFCF_RED:
                opts.append("red")
            if self.optflags & HFCF_ECN:
                opts.append("ecn")
            if self.optflags & HFCF_DEFAULTCLASS:
                opts.append("default")
            if self.rtsc[2]:
                opts.append("realtime" + self._str_sc(*self.rtsc))
            if (self.lssc[2] and (self.lssc[2] != self.bandwidth or
                                  self.lssc[1])):
                opts.append("linkshare" + self._str_sc(*self.lssc))
            if self.ulsc[2]:
                opts.append("upperlimit" + self._str_sc(*self.ulsc))

        return ("( {} ) ".format(" ".join(opts)) if opts else "")


class PFAltqPriQ(PFAltq):
    """Class representing a Priority Queueing queue."""

    def __init__(self, altq=None, **kw):
        """Check argument and initialize class attributes."""
        super(PFAltqPriQ, self).__init__(altq, scheduler=ALTQT_PRIQ, **kw)

    def _opts_from_struct(self, q):
        """Initialize options from a priq_opts structure."""
        self.optflags = q.pq_u.priq_opts.flags

    def _opts_to_struct(self, q):
        """Insert options into the priq_opts structure."""
        q.pq_u.priq_opts.flags = self.optflags

    def _str_opts(self):
        """Return the string representation of class-specific options."""
        opts = []
        if self.optflags & PRCF_RED:
            opts.append("red")
        if self.optflags & PRCF_ECN:
            opts.append("ecn")
        if self.optflags & PRCF_DEFAULTCLASS:
            opts.append("default")

        return ("( {} ) ".format(" ".join(opts)) if opts else "")


class CBQStats(PFObject):
    """Class representing statistics for a CBQ queue."""

    _struct_type = class_stats_t

    def __init__(self, queue, stats):
        """Check argument and initialize class attributes."""
        super(CBQStats, self).__init__(stats)
        self.queue = queue

    def _from_struct(self, s):
        """Initialize attributes from a class_stats_t structure."""
        self.packets = (s.xmit_cnt.packets, s.drop_cnt.packets)
        self.bytes   = (s.xmit_cnt.bytes, s.drop_cnt.bytes)
        self.length  = s.qcnt
        self.limit   = s.qmax
        self.borrows = s.borrows
        self.delays  = s.delays

    def _to_string(self):
        """Return the string representation of the statistics."""
        s  = "{0.queue}\n"
        s += "  [ pkts: {0.packets[0]:10}  bytes: {0.bytes[0]:10}"
        s += "  dropped pkts: {0.packets[1]:6} bytes: {0.bytes[1]:6} ]\n"
        s += "  [ qlength: {0.length:3}/{0.limit:3}"
        s += "  borrows: {0.borrows:6}  suspends: {0.delays:6} ]"
        return s.format(self)


class PriQStats(PFObject):
    """Class representing statistics for a PRIQ queue."""

    _struct_type = priq_classstats

    def __init__(self, queue, stats):
        """Check argument and initialize class attributes."""
        super(PriQStats, self).__init__(stats)
        self.queue = queue

    def _from_struct(self, s):
        """Initialize attributes from a priq_classstats structure."""
        self.packets = (s.xmitcnt.packets, s.dropcnt.packets)
        self.bytes   = (s.xmitcnt.bytes, s.dropcnt.bytes)
        self.length  = s.qlength
        self.limit   = s.qlimit

    def _to_string(self):
        """Return the string representation of the statistics."""
        s  = "{0.queue}\n"
        s += "  [ pkts: {0.packets[0]:10}  bytes: {0.bytes[0]:10}"
        s += "  dropped pkts: {0.packets[1]:6} bytes: {0.bytes[1]:6} ]\n"
        s += "  [ qlength: {0.length:3}/{0.limit:3} ]"
        return s.format(self)


class HFSCStats(PFObject):
    """Class representing statistics for a HFSC queue."""

    _struct_type = hfsc_classstats

    def __init__(self, queue, stats):
        """Check argument and initialize class attributes."""
        super(HFSCStats, self).__init__(stats)
        self.queue = queue

    def _from_struct(self, s):
        """Initialize attributes from a hfsc_classstats structure."""
        self.packets = (s.xmit_cnt.packets, s.drop_cnt.packets)
        self.bytes   = (s.xmit_cnt.bytes, s.drop_cnt.bytes)
        self.length  = s.qlength
        self.limit   = s.qlimit

    def _to_string(self):
        """Return the string representation of the statistics."""
        s  = "{0.queue}\n"
        s += "  [ pkts: {0.packets[0]:10}  bytes: {0.bytes[0]:10}"
        s += "  dropped pkts: {0.packets[1]:6} bytes: {0.bytes[1]:6} ]\n"
        s += "  [ qlength: {0.length:3}/{0.limit:3} ]"
        return s.format(self)
