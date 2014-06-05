"""Classes to represent Packet Filter's queueing schedulers and statistics."""

from pf._base import PFObject
from pf.constants import *
from pf._struct import pf_queue_scspec, pf_queuespec, class_stats
from pf._utils import rate2str


__all__ = ["ServiceCurve",
           "PFQueue",
           "PFQueueStats"]


class ServiceCurve(PFObject):
    """ """

    _struct_type = pf_queue_scspec

    def __init__(self, bandwidth, burst=0, time=0):
        """ """
        if isinstance(bandwidth, pf_queue_scspec):
            self._from_struct(bandwidth)
        else:
            self.bandwidth = bandwidth
            self.burst = burst
            self.time = time

    def _from_struct(self, sc):
        """ """
        self.bandwidth = self._get_bandwidth(sc.m2)
        self.burst = self._get_bandwidth(sc.m1)
        self.time = sc.d

    def _to_struct(self):
        """ """
        sc = pf_queue_scspec()
        if (isinstance(self.bandwidth, basestring) and
            self.bandwidth.endswith("%")):
            sc.m2.percent = int(self.bandwidth[:-1])
        else:
            sc.m2.absolute = self.bandwidth
        if (isinstance(self.burst, basestring) and
            self.burst.endswith("%")):
            sc.m1.percent = int(self.burst[:-1])
        else:
            sc.m1.absolute = self.burst
        sc.d = self.time
        return sc

    def _get_bandwidth(self, bw):
        """ """
        return "{}%".format(bw.percent) if bw.percent else bw.absolute

    def _str_bandwidth(self, bw):
        """ """
        return bw if isinstance(bw, basestring) else rate2str(bw)

    def _to_string(self):
        """ """
        s = self._str_bandwidth(self.bandwidth)
        if self.time:
            s += " burst {}".format(self._str_bandwidth(self.burst))
            s += " for {.time}ms".format(self)

        return s


class PFQueue(PFObject):
    """ """

    _struct_type = pf_queuespec

    def __init__(self, queue=None, **kw):
        """ """
        if isinstance(queue, basestring):
            queue = pf_queuespec(qname=queue, qlimit=DEFAULT_QLIMIT)
        elif queue is None:
            queue = pf_queuespec()
        super(PFQueue, self).__init__(queue, **kw)
        self.stats = PFQueueStats()

    def _from_struct(self, q):
        """ """
        self.qname      = q.qname
        self.parent     = q.parent
        self.ifname     = q.ifname
        self.flags      = q.flags
        self.qlimit     = q.qlimit
        self.qid        = q.qid
        self.parent_qid = q.parent_qid
        self.realtime   = ServiceCurve(q.realtime)
        self.linkshare  = ServiceCurve(q.linkshare)
        self.upperlimit = ServiceCurve(q.upperlimit)

    def _to_struct(self):
        """ """
        q = pf_queuespec()
        q.qname      = self.qname
        q.parent     = self.parent
        q.ifname     = self.ifname
        q.flags      = self.flags
        q.qlimit     = self.qlimit
        q.qid        = self.qid
        q.parent_qid = self.parent_qid
        q.realtime   = self.realtime._to_struct()
        q.linkshare  = self.linkshare._to_struct()
        q.upperlimit = self.upperlimit._to_struct()
        return q

    def _to_string(self):
        """ """
        s = "queue {.qname}".format(self)
        if self.parent and not self.parent.startswith("_"):
            s += " parent {.parent}".format(self)
        if self.ifname:
            s += " on {.ifname}".format(self)
        if self.flags & HFSC_DEFAULTCLASS:
            s += " default"
        if self.linkshare.bandwidth:
            s += " bandwidth {}".format(self.linkshare)
        if self.realtime.bandwidth:
            s += ", min {}".format(self.realtime)
        if self.upperlimit.bandwidth:
            s += ", max {}".format(self.upperlimit)
        if self.qlimit:
            s += " qlimit {.qlimit}".format(self)

        return s


class PFQueueStats(PFObject):
    """ """

    _struct_type = class_stats

    def __init__(self, stats=None):
        """ """
        if stats is None:
            stats = class_stats()
        super(PFQueueStats, self).__init__(stats)

    def _from_struct(self, s):
        """ """
        stats = s.hfsc_stats
        self.qlength = stats.qlength
        self.qlimit  = stats.qlimit
        self.packets = (stats.xmit_cnt.packets, stats.drop_cnt.packets)
        self.bytes   = (stats.xmit_cnt.bytes, stats.drop_cnt.bytes)

    def _to_string(self):
        """ """
        s = "  [ pkts: {0.packets[0]:10}  bytes: {0.bytes[0]:10}  "    + \
            "dropped pkts: {0.packets[1]:6} bytes: {0.bytes[1]:6} ]\n" + \
            "  [ qlength: {0.qlength:3}/{0.qlimit:3} ]"

        return s.format(self)
            