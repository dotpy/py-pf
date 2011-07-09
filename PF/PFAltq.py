"""Classes to represent Packet Filter's queueing schedulers."""

from PF._PFStruct import pf_altq
from PF.PFConstants import *
from PF.PFUtils import *
from PF import PFError


__all__ = ['PFAltqCBQ',
           'PFAltqHFSC',
           'PFAltqPriQ']


# PFAltq class #################################################################
class PFAltq(PFObject):
    """ """

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
                raise PFError("No ifbandwidth for interface '{0.ifname}'")
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
        """ """
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
        """ """
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
        """ """
        raise NotImplementedError()

    def _opts_to_struct(self, q):
        """ """
        raise NotImplementedError()

    def _str_opts(self):
        raise NotImplementedError()

    def _str_altq(self):
        """ """
        altqs = {ALTQT_CBQ: "cbq", ALTQT_PRIQ: "priq", ALTQT_HFSC: "hfsc"}

        s  = "altq on {0.ifname} ".format(self)
        s += "{0} {1}".format(altqs[self.scheduler], self._str_opts())

        if (0 < self.bandwidth < 100):
            s += "bandwidth {0.bandwidth}% ".format(self)
        elif (self.bandwidth >= 100):
            s += "bandwidth {0} ".format(rate2str(self.bandwidth))
        if self.qlimit != DEFAULT_QLIMIT:
            s += "qlimit {0.qlimit:d} ".format(self)
        s += "tbrsize {0.tbrsize:d}".format(self)

        return s

    def _str_queue(self):
        """ """
        altqs = {ALTQT_CBQ: "cbq", ALTQT_PRIQ: "priq", ALTQT_HFSC: "hfsc"}
        opts = self._str_opts()

        s = "queue {0.qname} on {0.ifname} ".format(self)

        if self.scheduler in (ALTQT_CBQ, ALTQT_HFSC):
            if (0 < self.bandwidth < 100):
                s += "bandwidth {0.bandwidth}% ".format(self)
            elif (self.bandwidth >= 100):
                s += "bandwidth {0} ".format(rate2str(self.bandwidth))
        if self.priority != DEFAULT_PRIORITY:
            s += "priority {0.priority:d} ".format(self)
        if self.qlimit != DEFAULT_QLIMIT:
            s += "qlimit {0.qlimit:d} ".format(self)
        if opts:
            s += "{0}{1}".format(altqs[self.scheduler], opts)

        return s

    def _to_string(self):
        """ """
        return (self._str_queue() if self.qname else self._str_altq())


class PFAltqCBQ(PFAltq):
    """ """

    def __init__(self, altq=None, **kw):
        """ """
        super(PFAltqCBQ, self).__init__(altq, scheduler=ALTQT_CBQ, **kw)
        if (altq is None or isinstance(altq, basestring)) and self.qname:
            self._set_opts()
        if self.qname and not self.parent:
            self.optflags |= (CBQCLF_ROOTCLASS | CBQCLF_WRR)

    def _opts_from_struct(self, q):
        """ """
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
        """ """
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
        """ """
        opts = []
        if self.optflags & CBQCLF_RED:
            opts.append("red")
        if self.optflags & CBQCLF_ECN:
            opts.append("ecn")
        if self.optflags & CBQCLF_RIO:
            opts.append("rio")
        if self.optflags & CBQCLF_CLEARDSCP:
            opts.append("cleardscp")
        if self.optflags & CBQCLF_FLOWVALVE:
            opts.append("flowvalve")
        if self.optflags & CBQCLF_BORROW:
            opts.append("borrow")
        if self.optflags & CBQCLF_WRR:
            opts.append("wrr")
        if self.optflags & CBQCLF_EFFICIENT:
            opts.append("efficient")
        if self.optflags & CBQCLF_ROOTCLASS:
            opts.append("root")
        if self.optflags & CBQCLF_DEFCLASS:
            opts.append("default")

        return ("( {0} ) ".format(" ".join(opts)) if opts else "")


class PFAltqHFSC(PFAltq):
    """ """

    def __init__(self, altq=None, **kw):
        """ """
        super(PFAltqHFSC, self).__init__(altq, scheduler=ALTQT_HFSC, **kw)

    def _opts_from_struct(self, q):
        """ """
        self.rtsc = (q.pq_u.hfsc_opts.rtsc_m1, q.pq_u.hfsc_opts.rtsc_d,
                     q.pq_u.hfsc_opts.rtsc_m2)
        self.lssc = (q.pq_u.hfsc_opts.lssc_m1, q.pq_u.hfsc_opts.lssc_d,
                     q.pq_u.hfsc_opts.lssc_m2)
        self.ulsc = (q.pq_u.hfsc_opts.ulsc_m1, q.pq_u.hfsc_opts.ulsc_d,
                     q.pq_u.hfsc_opts.ulsc_m2)
        self.optflags = q.pq_u.hfsc_opts.flags

    def _opts_to_struct(self, q):
        """ """
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

    def _str_opts(self):
        """ """
        opts = []
        if (self.optflags or self.rtsc[2] or self.ulsc[2] or
            (self.lssc[2] and (self.lssc[2] != self.bandwidth or
                               self.lssc[1]))):
            if self.optflags & HFCF_RED:
                opts.append("red")
            if self.optflags & HFCF_ECN:
                opts.append("ecn")
            if self.optflags & HFCF_RIO:
                opts.append("rio")
            if self.optflags & HFCF_CLEARDSCP:
                opts.append("cleardscp")
            if self.optflags & HFCF_DEFAULTCLASS:
                opts.append("default")
            if self.rtsc[2]:
                opts.append("realtime")
                #opts
            if (self.lssc[2] and (self.lssc[2] != self.bandwidth or
                                  self.lssc[1])):
                opts.append("linkshare")
                #opts
            if self.ulsc[2]:
                opts.append("upperlimit")
                #opts

        return ("( {0} ) ".format(" ".join(opts)) if opts else "")


class PFAltqPriQ(PFAltq):
    """ """

    def __init__(self, altq=None, **kw):
        """ """
        super(PFAltqPriQ, self).__init__(altq, scheduler=ALTQT_PRIQ, **kw)

    def _opts_from_struct(self, q):
        """ """
        self.optflags = q.pq_u.priq_opts.flags

    def _opts_to_struct(self, q):
        """ """
        q.pq_u.priq_opts.flags = self.optflags

    def _str_opts(self):
        """ """
        opts = []
        if self.optflags & PRCF_RED:
            opts.append("red")
        if self.optflags & PRCF_ECN:
            opts.append("ecn")
        if self.optflags & PRCF_RIO:
            opts.append("rio")
        if self.optflags & PRCF_CLEARDSCP:
            opts.append("cleardscp")
        if self.optflags & PRCF_DEFAULTCLASS:
            opts.append("default")

        return ("( {0} ) ".format(" ".join(opts)) if opts else "")
