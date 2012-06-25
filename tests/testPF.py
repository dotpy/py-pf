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
        except Exception, e:
            print "failed"
            print "    ", e
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
    i = pf.get_ifaces(LO_IF)
    if i.flags & PFI_IFLAG_SKIP:
        raise TestError

@test("PacketFilter.set_ifflag()")
def test_set_ifflags():
    pf.set_ifflags(LO_IF, PFI_IFLAG_SKIP)
    ifs = pf.get_ifaces()
    i = [i for i in ifs if i.name == LO_IF][0]
    if not (i.flags & PFI_IFLAG_SKIP):
        raise TestError

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

@test("PacketFilter.clear_altqs()")
def test_clear_altqs():
    pf.clear_altqs()
    if pf.get_altqs():
        raise TestError

@test("PacketFilter.add_altqs()")
def test_add_altqs():
    ifbw = 5000000   # ifbandwidth
    altqs = [PFAltqCBQ(ifname=IFNAME, ifbandwidth=ifbw),
             PFAltqCBQ(ifname=IFNAME, qname="root_vic1",
                       ifbandwidth=ifbw, bandwidth=ifbw,
                       optflags=CBQCLF_ROOTCLASS|CBQCLF_WRR),
             PFAltqCBQ(ifname=IFNAME, qname="std", parent="root_vic1",
                       ifbandwidth=ifbw, bandwidth=10,
                       optflags=CBQCLF_DEFCLASS),
             PFAltqCBQ(ifname=IFNAME, qname="http", parent="root_vic1",
                       ifbandwidth=ifbw, bandwidth=60, priority=2,
                       optflags=CBQCLF_BORROW|CBQCLF_RED),
             PFAltqCBQ(ifname=IFNAME, qname="employees", parent="http",
                       ifbandwidth=ifbw, bandwidth=15),
             PFAltqCBQ(ifname=IFNAME, qname="developers", parent="http",
                       ifbandwidth=ifbw, bandwidth=75,
                       optflags=CBQCLF_BORROW),
             PFAltqCBQ(ifname=IFNAME, qname="mail", parent="root_vic1",
                       ifbandwidth=ifbw, bandwidth=10, priority=0,
                       optflags=CBQCLF_BORROW|CBQCLF_ECN)]

    pf.add_altqs(*altqs)
    if not pf.get_altqs():
        raise TestError

@test("PacketFilter.clear_rules()")
def test_clear_rules():
    pf.clear_rules()
    if pf.get_ruleset().rules:
        raise TestError

@test("PacketFilter.load_ruleset()")
def test_load_ruleset():
    ext_if = PFAddr(type=PF_ADDR_DYNIFTL, ifname=EXT_IF)

    tables = [PFTable("web_srv", "10.0.1.20", "10.0.1.21", "10.0.1.22")]
    rules = [
        # match out on $ext_if inet from !($ext_if) to any nat-to ($ext_if)
        PFRule(action=PF_MATCH,
               direction=PF_OUT,
               ifname=EXT_IF,
               af=AF_INET,
               src=PFRuleAddr(ext_if, neg=True),
               nat=PFPool(PF_POOL_NAT, ext_if)),
        # block in log
        PFRule(action=PF_DROP,
               direction=PF_IN,
               log=PF_LOG),
        # pass out quick
        PFRule(action=PF_PASS,
               direction=PF_OUT,
               quick=True,
               flags="S", flagset="SA",
               keep_state=PF_STATE_NORMAL),
        # anchor "test_rs"
        PFRuleset("test_rs"),
        # pass in on $ext_if inet proto tcp from any to $ext_if port ssh
        PFRule(action=PF_PASS,
               direction=PF_IN,
               ifname=EXT_IF,
               af=AF_INET,
               proto=IPPROTO_TCP,
               dst=PFRuleAddr(ext_if, PFPort("ssh", IPPROTO_TCP)),
               flags="S", flagset="SA",
               keep_state=PF_STATE_NORMAL),
        # pass in on $ext_if inet proto tcp to $ext_if port 80 \
        #     rdr-to <web_srv> round-robin sticky-address
        PFRule(action=PF_PASS,
               direction=PF_IN,
               ifname=EXT_IF,
               af=AF_INET,
               proto=IPPROTO_TCP,
               dst=PFRuleAddr(ext_if, PFPort(80, IPPROTO_TCP)),
               flags="S", flagset="SA",
               keep_state=PF_STATE_NORMAL,
               rdr=PFPool(PF_POOL_RDR, PFAddr("<web_srv>"),
                          opts=PF_POOL_ROUNDROBIN|PF_POOL_STICKYADDR)),
        # pass in inet proto icmp all icmp-type echoreq
        PFRule(action=PF_PASS,
               direction=PF_IN,
               af=AF_INET,
               proto=IPPROTO_ICMP,
               type=ICMP_ECHO+1,
               keep_state=PF_STATE_NORMAL),
        # pass in on $int_if
        PFRule(action=PF_PASS,
               direction=PF_IN,
               ifname=INT_IF,
               flags="S", flagset="SA",
               keep_state=PF_STATE_NORMAL)]

    rules[3].append(PFTable("spammers", flags=PFR_TFLAG_PERSIST),
                    # pass in on $ext_if inet proto tcp from ! <spammers> \
                    #    to $ext_if port 25 rdr-to 10.0.1.23
                    PFRule(action=PF_PASS,
                           direction=PF_IN,
                           ifname=EXT_IF,
                           af=AF_INET,
                           proto=IPPROTO_TCP,
                           src=PFRuleAddr(PFAddr("<spammers>"), neg=True),
                           dst=PFRuleAddr(ext_if, PFPort(25, IPPROTO_TCP)),
                           flags="S", flagset="SA",
                           keep_state=PF_STATE_NORMAL,
                           rdr=PFPool(PF_POOL_RDR, PFAddr("10.0.1.23"))))

    rs = PFRuleset()
    rs.append(*tables)
    rs.append(*rules)
    pf.load_ruleset(rs)

@test("PacketFilter.get_ruleset()")
def test_get_ruleset():
    rs = pf.get_ruleset()
    if not pf.get_ruleset().rules:
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
    if pf.clear_tstats(PFTable("test5", anchor="test_rs")) != 1:
        raise TestError

@test("PacketFilter.get_states()")
def test_get_states():
    pf.get_states()

@test("PacketFilter.clear_states()")
def test_clear_states():
    pf.clear_states(IFNAME)

@test("PacketFilter.kill_states()")
def test_kill_states():
    pf.kill_states(af=AF_INET, proto=IPPROTO_TCP, ifname=IFNAME)