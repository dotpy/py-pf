"""Test suite for the PacketFilter class"""

import os
import time
import unittest
import subprocess
from socket import *

import pf


class TestPacketFilter(unittest.TestCase):
    """Test case class for pf.PacketFilter"""

    testif = "lo0"

    def setUp(self):
        self.pf = pf.PacketFilter()
        self._init_state = {"enabled": self.pf.get_status().running,
                            "ruleset": self.pf.get_ruleset()}
        if not self._init_state["enabled"]:
            self.pf.enable()
#            self.pf.enable_altq()
        self.pf.clear_rules()

    def tearDown(self):
        self.pf.clear_rules()
        if not self._init_state["enabled"]:
#            self.pf.disable_altq()
            self.pf.disable()
        else:
            self.pf.load_ruleset(self._init_state["ruleset"])

    def test_enable(self):
        self.pf.disable()
        self.assertFalse(self.pf.get_status().running)
        self.pf.enable()
        self.assertTrue(self.pf.get_status().running)

#    def test_enable_altq(self):
#        self.pf.disable_altq()
#        self.pf.enable_altq()

    def test_set_debug(self):
        _dbg = self.pf.get_status().debug
        for dbg in (pf.LOG_DEBUG, pf.LOG_ERR, _dbg):
            self.pf.set_debug(dbg)
            self.assertEqual(self.pf.get_status().debug , dbg)

    def test_set_hostid(self):
        _id = self.pf.get_status().hostid
        for id in (1234, _id):
            self.pf.set_hostid(id)
            self.assertEqual(self.pf.get_status().hostid , id)

    def test_set_reassembly(self):
        _flags = self.pf.get_status().reass
        flags = pf.PF_REASS_ENABLED | pf.PF_REASS_NODF
        self.pf.set_reassembly(flags)
        self.assertEqual(self.pf.get_status().reass, flags)
        self.pf.set_reassembly(_flags)

    def test_set_limit(self):
        limits = {"states": 5000, "tables": 2000}
        for limit, value in limits.iteritems():
            _value = self.pf.get_limit(limit)
            self.pf.set_limit(limit, value)
            self.assertEqual(self.pf.get_limit(limit), value)
            self.pf.set_limit(limit, _value)

    def test_set_timeout(self):
        timeouts = {"frag": 25, "interval": 20}
        for tmout, value in timeouts.iteritems():
            _value = self.pf.get_timeout(tmout)
            self.pf.set_timeout(tmout, value)
            self.assertEqual(self.pf.get_timeout(tmout), value)
            self.pf.set_timeout(tmout, _value)

    def test_set_ifflags(self):
        _flags = self.pf.get_ifaces(self.testif).flags
        self.pf.clear_ifflags(self.testif)
        self.pf.set_ifflags(self.testif, pf.PFI_IFLAG_SKIP)
        self.assertEqual(self.pf.get_ifaces(self.testif).flags,
                         pf.PFI_IFLAG_SKIP)
        self.pf.set_ifflags(self.testif, _flags)

    def test_set_status_if(self):
        _ifname = self.pf.get_status().ifname
        self.pf.set_status_if(self.testif)
        self.assertEqual(self.pf.get_status().ifname, self.testif)
        self.pf.set_status_if(_ifname)

    def test_clear_status(self):
        self.pf.clear_status()
        self.assertEqual(self.pf.get_status().since, int(time.time()))

    def test_clear_states(self):
        self.pf.clear_rules()
        self._create_state()
        self.assertIsNotNone(filter(lambda s: s.proto == IPPROTO_UDP,
                                    self.pf.get_states()))
        self.pf.clear_states()
        for state in self.pf.get_states():
            self.assertNotEqual(state.proto, IPPROTO_UDP)

    def test_kill_states(self):
        self.pf.clear_rules()
        self._create_state()
        self.assertEqual(self.pf.kill_states(proto=IPPROTO_UDP), 1)

    def test_clear_rules(self):
        ruleset = pf.PFRuleset()
        ruleset.append(pf.PFRule(action=pf.PF_PASS,
                                 flags="S", flagset="SA",
                                 keep_state=pf.PF_STATE_NORMAL))
        self.pf.load_ruleset(ruleset)
        self.pf.clear_rules()
        self.assertFalse(self.pf.get_ruleset().rules)

    def test_load_queues(self):
        # Rules to load in pf.conf format:
        #   queue std on em0 bandwidth 100M
        #   queue ssh parent std bandwidth 10M burst 90M for 100ms
        #   queue mail parent std bandwidth 10M, min 5M, max 25M
        #   queue http parent std bandwidth 80M default
        ifname  = self.testif
        parentq = "root_" + ifname
        MB = 10**6
        queues = [pf.PFQueue(qname=parentq, ifname=ifname),
                  pf.PFQueue(qname="std", parent=parentq, ifname=ifname,
                             linkshare=pf.ServiceCurve(bandwidth=100*MB)),
                  pf.PFQueue(qname="ssh", parent="std", ifname=ifname,
                             linkshare=pf.ServiceCurve(10*MB, 90*MB, 100)),
                  pf.PFQueue(qname="mail", parent="std", ifname=ifname,
                             linkshare=pf.ServiceCurve(bandwidth=10*MB),
                             realtime=pf.ServiceCurve(bandwidth=5*MB),
                             upperlimit=pf.ServiceCurve(bandwidth=25*MB)),
                  pf.PFQueue(qname="http", parent="std", ifname=ifname,
                             linkshare=pf.ServiceCurve(bandwidth=80*MB),
                             flags=pf.HFSC_DEFAULTCLASS)]
        self.pf.clear_rules()
        self.pf.load_queues(*queues)
        self.assertEqual(len(self.pf.get_queues()), len(queues))
        for queue in self.pf.get_queues():
            self.assertIn(queue.qname, map(lambda q: q.qname, queues))

    def test_load_ruleset(self):
        iface = pf.PFAddr(type=pf.PF_ADDR_DYNIFTL, ifname=self.testif)
        tables = [pf.PFTable("web_srv", "10.0.1.20", "10.0.1.21", "10.0.1.22")]
        rules = [
            # match out on $ifname inet from !($ifname) to any nat-to ($ifname)
            pf.PFRule(action=pf.PF_MATCH,
                      direction=pf.PF_OUT,
                      ifname=self.testif,
                      af=AF_INET,
                      src=pf.PFRuleAddr(iface, neg=True),
                      nat=pf.PFPool(pf.PF_POOL_NAT, iface)),
            # pass out quick
            pf.PFRule(action=pf.PF_PASS,
                      direction=pf.PF_OUT,
                      quick=True,
                      flags="S", flagset="SA",
                      keep_state=pf.PF_STATE_NORMAL),
            # anchor "test_anchor"
            pf.PFRuleset("test_anchor"),
            # pass in on $ifname inet proto tcp from any to $ifname port ssh
            pf.PFRule(action=pf.PF_PASS,
                      direction=pf.PF_IN,
                      ifname=self.testif,
                      af=AF_INET,
                      proto=IPPROTO_TCP,
                      dst=pf.PFRuleAddr(iface, pf.PFPort("ssh", IPPROTO_TCP)),
                      flags="S", flagset="SA",
                      keep_state=pf.PF_STATE_NORMAL),
            # pass in on $ifname inet proto tcp to $ifname port www \
            #     rdr-to <web_srv> round-robin sticky-address
            pf.PFRule(action=pf.PF_PASS,
                      direction=pf.PF_IN,
                      ifname=self.testif,
                      af=AF_INET,
                      proto=IPPROTO_TCP,
                      dst=pf.PFRuleAddr(iface, pf.PFPort("www", IPPROTO_TCP)),
                      flags="S", flagset="SA",
                      keep_state=pf.PF_STATE_NORMAL,
                      rdr=pf.PFPool(pf.PF_POOL_RDR, pf.PFAddr("<web_srv>"),
                                    opts=(pf.PF_POOL_ROUNDROBIN|
                                          pf.PF_POOL_STICKYADDR))),
            # pass in inet proto icmp all icmp-type echoreq
            pf.PFRule(action=pf.PF_PASS,
                      direction=pf.PF_IN,
                      af=AF_INET,
                      proto=IPPROTO_ICMP,
                      type=pf.ICMP_ECHO+1,
                      keep_state=pf.PF_STATE_NORMAL)]

        rules[2].append(
            pf.PFTable("spammers", flags=pf.PFR_TFLAG_PERSIST),
            # pass in on $ifname inet proto tcp from ! <spammers> \
            #    to $ifname port 25 rdr-to 10.0.1.23
            pf.PFRule(action=pf.PF_PASS,
                      direction=pf.PF_IN,
                      ifname=self.testif,
                      af=AF_INET,
                      proto=IPPROTO_TCP,
                      src=pf.PFRuleAddr(pf.PFAddr("<spammers>"), neg=True),
                      dst=pf.PFRuleAddr(iface, pf.PFPort(25, IPPROTO_TCP)),
                      flags="S", flagset="SA",
                      keep_state=pf.PF_STATE_NORMAL,
                      rdr=pf.PFPool(pf.PF_POOL_RDR, pf.PFAddr("10.0.1.23"))))
            
        self.pf.clear_rules()
        rs = pf.PFRuleset()
        rs.append(*tables)
        rs.append(*rules)
        self.pf.load_ruleset(rs)
        self.assertEqual(len(self.pf.get_ruleset().rules), len(rules))

    def test_add_tables(self):
        tblname = "test_table"
        self.assertEqual(self._add_table(tblname), 1)
        self.assertEqual(self.pf.get_tables()[0].name, tblname)

    def test_clear_tables(self):
        self.assertEqual(self._add_table(), 1)
        self.pf.clear_tables()
        self.assertFalse(self.pf.get_tables())

    def test_del_tables(self):
        self.assertEqual(self._add_table(), 1)
        table = self.pf.get_tables()[0]
        self.pf.del_tables(table)
        self.assertFalse(self.pf.get_tables())

    def test_add_addrs(self):
        self.assertEqual(self._add_table(), 1)
        table = self.pf.get_tables()[0]
        addrs = ["10.0.1.11", "10.0.1.12"]
        self.pf.clear_addrs(table)
        self.assertEqual(self.pf.add_addrs(table, *addrs), len(addrs))
        self.assertEqual(len(self.pf.get_addrs(table)), len(addrs))

    def test_clear_addrs(self):
        self.assertEqual(self._add_table(), 1)
        table = self.pf.get_tables()[0]
        self.assertTrue(self.pf.clear_addrs(table))
        self.assertFalse(self.pf.get_addrs(table))

    def test_del_addrs(self):
        self.assertEqual(self._add_table(), 1)
        table = self.pf.get_tables()[0]
        addrs = ["10.0.1.11", "10.0.1.12"]
        self.assertEqual(self.pf.set_addrs(table, *addrs)[1], len(addrs))
        self.assertEqual(self.pf.del_addrs(table, addrs.pop()), 1)
        self.assertEqual(len(self.pf.get_addrs(table)), len(addrs))

    def test_set_addrs(self):
        self.assertEqual(self._add_table(), 1)
        table = self.pf.get_tables()[0]
        addrs = ["10.0.1.11", "10.0.1.12"]
        self.assertEqual(self.pf.set_addrs(table, *addrs)[1], len(addrs))
        self.assertEqual(len(self.pf.get_addrs(table)), len(addrs))

    def test_get_tstats(self):
        self.assertEqual(self._add_table(), 1)
        self.assertTrue(self.pf.get_tstats())

    def test_clear_tstats(self):
        self.assertEqual(self._add_table(), 1)
        table = self.pf.get_tables()[0]
        self.assertEqual(self.pf.clear_tstats(table), 1)

#    def _load_altq(self):
#        ifbw    = 5 * 1000 * 1000      # Max bandwidth (5Mb)
#        altqs = [pf.PFAltqPriQ(ifname=self.testif,
#                               ifbandwidth=ifbw),
#                 pf.PFAltqPriQ("std_out",
#                               ifname=self.testif,
#                               ifbandwidth=ifbw,
#                               optflags=pf.PRCF_DEFAULTCLASS)]
#        self.pf.add_altqs(*altqs)

    def _add_table(self, tblname="test_table"):
        table = pf.PFTable(tblname, "10.0.1.10",
                           flags=pf.PFR_TFLAG_PERSIST)
        self.pf.clear_tables()
        return self.pf.add_tables(table)

    def _create_state(self):
        ruleset = pf.PFRuleset()
        ruleset.append(pf.PFRule(action=pf.PF_PASS,
                                 flags="S", flagset="SA",
                                 proto=IPPROTO_UDP,
                                 keep_state=pf.PF_STATE_NORMAL))
        self.pf.load_ruleset(ruleset)
        self.pf.clear_states()
        with open(os.devnull, "w") as n:
            subprocess.call(["/usr/sbin/nslookup", "google.com"],
                            stdout=n, stderr=n)
