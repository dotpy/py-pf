"""Classes to represent Packet Filter's queueing schedulers and statistics."""

import pf._struct
from pf._base import PFObject
from pf.constants import *
from pf._utils import rate2str


__all__ = ["ServiceCurve",
           "FlowQueue",
           "PFQueue",
           "PFQueueStats"]


class ServiceCurve(PFObject):
    """ """

    _struct_type = pf._struct.pf_queue_scspec

    def __init__(self, bandwidth, burst=0, time=0):
        """ """
        if isinstance(bandwidth, pf._struct.pf_queue_scspec):
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
        sc = pf._struct.pf_queue_scspec()
        if (isinstance(self.bandwidth, str) and
            self.bandwidth.endswith("%")):
            sc.m2.percent = int(self.bandwidth[:-1])
        else:
            sc.m2.absolute = self.bandwidth
        if (isinstance(self.burst, str) and
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
        return bw if isinstance(bw, str) else rate2str(bw)

    def _to_string(self):
        """ """
        s = self._str_bandwidth(self.bandwidth)
        if self.time:
            s += " burst {}".format(self._str_bandwidth(self.burst))
            s += " for {.time}ms".format(self)

        return s


class FlowQueue(PFObject):
    """ """

    _struct_type = pf._struct.pf_queue_fqspec

    def __init__(self, flows, quantum=0, target=0, interval=0):
        """ """
        if isinstance(flows, pf._struct.pf_queue_fqspec):
            self._from_struct(flows)
        else:
            self.flows    = flows
            self.quantum  = quantum
            self.target   = target * 1000000
            self.interval = interval * 1000000

    def _from_struct(self, fq):
        """ """
        self.flows    = fq.flows
        self.quantum  = fq.quantum
        self.target   = fq.target
        self.interval = fq.interval

    def _to_struct(self):
        """ """
        fq = pf._struct.pf_queue_fqspec()
        fq.flows    = self.flows
        fq.quantum  = self.quantum
        fq.target   = self.target
        fq.interval = self.interval
        return fq

    def _to_string(self):
        """ """
        s = "flows {.flows}".format(self)
        if self.quantum:
            s += " quantum {.quantum}".format(self)
        if self.interval:
            s += " interval {}ms".format(self.interval / 1000000)
        if self.target:
            s += " target {}ms".format(self.target / 1000000)
        return s


class PFQueue(PFObject):
    """ """

    _struct_type = pf._struct.pf_queuespec

    def __init__(self, queue=None, **kw):
        """ """
        if isinstance(queue, str):
            queue = pf._struct.pf_queuespec(qname=queue, qlimit=DEFAULT_QLIMIT)
        elif queue is None:
            queue = pf._struct.pf_queuespec()
        super(PFQueue, self).__init__(queue, **kw)
        self.stats = PFQueueStats()

    def _from_struct(self, q):
        """ """
        self.qname      = q.qname.decode()
        self.parent     = q.parent.decode()
        self.ifname     = q.ifname.decode()
        self.flags      = q.flags
        self.qlimit     = q.qlimit
        self.qid        = q.qid
        self.parent_qid = q.parent_qid
        self.realtime   = ServiceCurve(q.realtime)
        self.linkshare  = ServiceCurve(q.linkshare)
        self.upperlimit = ServiceCurve(q.upperlimit)
        self.flowqueue  = FlowQueue(q.flowqueue)

    def _to_struct(self):
        """ """
        q = pf._struct.pf_queuespec()
        q.qname      = self.qname.encode()
        q.parent     = self.parent.encode()
        q.ifname     = self.ifname.encode()
        q.flags      = self.flags
        q.qlimit     = self.qlimit
        q.qid        = self.qid
        q.parent_qid = self.parent_qid
        q.realtime   = self.realtime._to_struct()
        q.linkshare  = self.linkshare._to_struct()
        q.upperlimit = self.upperlimit._to_struct()
        q.flowqueue  = self.flowqueue._to_struct()
        return q

    def _to_string(self):
        """ """
        s = "queue {.qname}".format(self)
        if self.parent and not self.parent.startswith("_"):
            s += " parent {.parent}".format(self)
        elif self.ifname:
            s += " on {.ifname}".format(self)
        if self.flags & PFQS_FLOWQUEUE:
            s += " {.flowqueue}".format(self)
        if self.linkshare.bandwidth or self.linkshare.burst:
            s += " bandwidth {}".format(self.linkshare)
        if self.realtime.bandwidth:
            s += ", min {}".format(self.realtime)
        if self.upperlimit.bandwidth:
            s += ", max {}".format(self.upperlimit)
        if self.flags & PFQS_DEFAULT:
            s += " default"
        if self.qlimit:
            s += " qlimit {.qlimit}".format(self)

        return s


class PFQueueStats(PFObject):
    """ """

    _struct_type = pf._struct.hfsc_class_stats

    def __init__(self, stats=None):
        """ """
        if stats is None:
            stats = pf._struct.hfsc_class_stats()
        super(PFQueueStats, self).__init__(stats)

    def _from_struct(self, s):
        """ """
        self.qlength = s.qlength
        self.qlimit  = s.qlimit
        self.packets = (s.xmit_cnt.packets, s.drop_cnt.packets)
        self.bytes   = (s.xmit_cnt.bytes, s.drop_cnt.bytes)

    def _to_string(self):
        """ """
        s = "  [ pkts: {0.packets[0]:10}  bytes: {0.bytes[0]:10}  "    + \
            "dropped pkts: {0.packets[1]:6} bytes: {0.bytes[1]:6} ]\n" + \
            "  [ qlength: {0.qlength:3}/{0.qlimit:3} ]"

        return s.format(self)

