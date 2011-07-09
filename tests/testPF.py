#!/usr/bin/env python

"""Some very basic tests for py-PF.

Make sure you correctly set the configuration parameters.
"""


import time
from socket import *

from PF import *


# Configuration ################################################################
IFNAME = "vic1"       # Harmless interface for tests
EXT_IF = "vic0"
INT_IF = "vic1"
LO_IF  = "lo0"


# Exceptions and helper functions ##############################################
class TestError(Exception):
    pass


def test(func_name):
    def _test(test_func):
        print "Testing %-53s" % func_name,
        try:
            test_func()
        except Exception:
            print "failed"
        else:
            print "successful"

    return _test


# Main #########################################################################
pf = PacketFilter()

@test("PacketFilter.disable()")
def test_disable():
    pf.disable()
    if pf.get_status().running:
        raise TestError

@test("PacketFilter.enable()")
def test_enable():
    pf.enable()
    if not pf.get_status().running:
        raise TestError

@test("PacketFilter.disable_altq()")
def test_disable_altq():
    pf.disable_altq()

@test("PacketFilter.enable_altq()")
def test_enable_altq():
    pf.enable_altq()

@test("PacketFilter.clear_ifflags()")
def test_clear_ifflags():
    pf.clear_ifflags(LO_IF)

@test("PacketFilter.clear_rules()")
def test_clear_rules():
    pf.clear_rules()

@test("PacketFilter.set_ifflag()")
def test_set_ifflag():
    pf.set_ifflag(LO_IF, PFI_IFLAG_SKIP)

@test("PacketFilter.set_debug()")
def test_set_debug():
    dbgs = [LOG_DEBUG, LOG_ERR]
    for dbg in dbgs:
        pf.set_debug(dbg)
        if pf.get_status().debug != dbg:
            raise TestError

@test("PacketFilter.set_hostid()")
def test_set_hostid():
    hostid = 1234
    pf.set_hostid(hostid)
    if pf.get_status().hostid != hostid:
        raise TestError

@test("PacketFilter.set_reassembly()")
def test_set_reassembly():
    flags = PF_REASS_ENABLED | PF_REASS_NODF
    pf.set_reassembly(flags)
    if pf.get_status().reass != flags:
        raise TestError

@test("PacketFilter.set_limit()")
def test_set_limit():
    limits = {"states": 5000, "tables": 2000}
    for k,v in limits.iteritems():
        pf.set_limit(k, v)
        if pf.get_limit(k) != v:
            raise TestError

@test("PacketFilter.set_timeout()")
def test_set_timeout():
    timeouts = {"frag": 25, "interval": 20}
    for k,v in timeouts.iteritems():
        pf.set_timeout(k, v)
        if pf.get_timeout(k) != v:
            raise TestError

@test("PacketFilter.set_status_if()")
def test_set_status_if():
    pf.set_status_if(IFNAME)
    if pf.get_status().ifname != IFNAME:
        raise TestError

@test("PacketFilter.clear_status()")
def test_clear_status():
    since = pf.get_status().since
    time.sleep(1)
    pf.clear_status()
    if pf.get_status().since <= since:
        raise TestError

@test("PacketFilter.get_states()")
def test_get_states():
    for s in pf.get_states():
        if not isinstance(s, PFState):
            raise TestError

@test("PacketFilter.clear_states()")
def test_clear_states():
    pf.clear_states(IFNAME)

@test("PacketFilter.kill_states()")
def test_kill_states():
    pf.kill_states(af=AF_INET, proto=IPPROTO_TCP, ifname=IFNAME)

@test("PacketFilter.clear_altqs()")
def test_clear_altqs():
    pf.clear_altqs()
    if pf.get_altqs():
        raise TestError

@test("PacketFilter.add_altqs()")
def test_add_altqs():
    altqs = [PFAltqCBQ(ifname=IFNAME, ifbandwidth=5000000),
             PFAltqCBQ(ifname=IFNAME, qname="std", bandwidth=10,
             optflags=CBQCLF_DEFCLASS),
             PFAltqCBQ(ifname=IFNAME, qname="http", bandwidth=60, priority=2,
             optflags=CBQCLF_BORROW|CBQCLF_RED),
             PFAltqCBQ(ifname=IFNAME, qname="employees", parent="http",
             bandwidth=15),
             PFAltqCBQ(ifname=IFNAME, qname="developers", parent="http",
             bandwidth=75, optflags=CBQCLF_BORROW),
             PFAltqCBQ(ifname=IFNAME, qname="mail", bandwidth=10, priority=0,
             optflags=CBQCLF_BORROW|CBQCLF_ECN)]
    pf.add_altqs(*altqs)
    if not pf.get_altqs():
        raise TestError

@test("PacketFilter.load_ruleset()")
def test_load_ruleset():
    ext_if = PFAddr(type=PF_ADDR_DYNIFTL, ifname=EXT_IF)

    r2 = {PF_RULESET_TABLE:
              [PFTable("test3", "15.0.0.0/24", "! 10.1.2.3")],
          PF_RULESET_NAT:
              [PFRule(action=PF_NAT,
                      ifname=EXT_IF,
                      src=PFRuleAddr(ext_if, neg=True),
                      dst=PFRuleAddr(PFAddr("<test3>"),
                                     PFPort("pop3", IPPROTO_TCP)),
                      rpool=PFPool(PF_NAT, ext_if))],
          PF_RULESET_FILTER:
              [PFRule(action=PF_DROP,
                      ifname=INT_IF,
                      proto=IPPROTO_ICMP,
                      type=ICMP_UNREACH+1,
                      code=ICMP_UNREACH_NEEDFRAG+1,
                      keep_state=PF_STATE_NORMAL)]}

    r1 = {PF_RULESET_TABLE:
              [PFTable("test1", "10.0.0.1", "10.0.0.2", "172.16.1.0/24"),
               PFTable("test2", "192.168.10.0/27", flags=PFR_TFLAG_CONST)],
          PF_RULESET_NAT:
              [PFRule(action=PF_NAT,
                      ifname=EXT_IF,
                      src=PFRuleAddr(ext_if, neg=True),
                      rpool=PFPool(PF_NAT, ext_if))],
          PF_RULESET_RDR:
              [PFRule(action=PF_RDR,
                      ifname=INT_IF,
                      af=AF_INET,
                      dst=PFRuleAddr(PFAddr(type=PF_ADDR_DYNIFTL,
                                            af=AF_INET,
                                            ifname=INT_IF,
                                            mask="255.255.255.255"),
                                     PFPort("www", IPPROTO_TCP)),
                      rpool=PFPool(PF_RDR, "<test2>",
                      opts=PF_POOL_ROUNDROBIN|PF_POOL_STICKYADDR))],
          PF_RULESET_FILTER:
              [PFRule(action=PF_DROP,
                      direction=PF_IN,
                      quick=True,
                      src=PFRuleAddr(PFAddr(type=PF_ADDR_URPFFAILED))),
               PFRule(action=PF_PASS,
                      direction=PF_IN,
                      ifname=EXT_IF,
                      proto=IPPROTO_TCP,
                      dst=PFRuleAddr(PFAddr("<test1>"),
                                     PFPort("www", IPPROTO_TCP)),
                      flagset="S", flags="SA",
                      keep_state=PF_STATE_NORMAL),
               PFRule(action=PF_DROP,
                      direction=PF_IN,
                      ifname=EXT_IF,
                      proto=IPPROTO_TCP,
                      dst=PFRuleAddr(PFAddr("<test2>"),
                                     PFPort("smtp", IPPROTO_TCP)),
                      flagset="S", flags="SA",
                      keep_state=PF_STATE_NORMAL),
               PFRule(action=PF_PASS,
                      ifname=EXT_IF,
                      proto=IPPROTO_ICMP)]}

    rs1 = PFRuleset()
    for k,v in r1.iteritems():
        rs1.append(k, *v)

    rs2 = PFRuleset("test_rs")
    for k,v in r2.iteritems():
        rs2.append(k, *v)

    rs1.insert(PF_RULESET_FILTER, 2, rs2)
    pf.load_ruleset(rs1)

@test("PacketFilter.get_ruleset()")
def test_get_ruleset():
    rs = pf.get_ruleset()
    if len(rs.rules[PF_RULESET_FILTER]) != 5:
        raise TestError

@test("PacketFilter.add_tables()")
def test_add_tables():
    t = PFTable("test4", "192.168.23.34", "10.0.4.0/27", anchor="test_rs",
                flags=PFR_TFLAG_PERSIST)
    pf.add_tables(t)

@test("PacketFilter.del_tables()")
def test_del_tables():
    if pf.del_tables(PFTable("test4", anchor="test_rs")) != 1:
        raise TestError

@test("PacketFilter.clear_tables()")
def test_clear_tables():
    if pf.clear_tables(PFTable(anchor="test_rs")) != 2:
        raise TestError

@test("PacketFilter.get_tables()")
def test_get_tables():
    t = PFTable("test5", anchor="test_rs", flags=PFR_TFLAG_PERSIST)
    pf.add_tables(t)
    if len(pf.get_tables(t)) != 1:
        raise TestError

@test("PacketFilter.add_addrs()")
def test_add_addrs():
    t = PFTable("test5", anchor="test_rs", flags=PFR_TFLAG_PERSIST)
    if pf.add_addrs(t, "9.8.7.6", "196.64.23.0/26") != 2:
        raise TestError

@test("PacketFilter.del_addrs()")
def test_del_addrs():
    t = PFTable("test5", anchor="test_rs", flags=PFR_TFLAG_PERSIST)
    if pf.del_addrs(t, "196.64.23.0/26") != 1:
        raise TestError

@test("PacketFilter.clear_addrs()")
def test_clear_addrs():
    t = PFTable("test5", anchor="test_rs", flags=PFR_TFLAG_PERSIST)
    if pf.clear_addrs(t) != 1:
        raise TestError

@test("PacketFilter.set_addrs()")
def test_set_addrs():
    t = PFTable("test5", anchor="test_rs", flags=PFR_TFLAG_PERSIST)
    if pf.set_addrs(t, "9.8.7.6", "196.64.23.0/26") != (0, 2, 0):
        raise TestError

@test("PacketFilter.get_addrs()")
def test_get_addrs():
    t = PFTable("test5", anchor="test_rs", flags=PFR_TFLAG_PERSIST)
    if len(pf.get_addrs(t)) != 2:
        raise TestError

@test("PacketFilter.get_tstats()")
def test_get_tstats():
    stats = pf.get_tstats(PFTable(anchor="test_rs"))
    if len(stats) != 2:
        raise TestError

@test("PacketFilter.clear_tstats()")
def test_clear_tstats():
    if pf.clear_tstats(PFTable("test3", anchor="test_rs")) != 1:
        raise TestError

