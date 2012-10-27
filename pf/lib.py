"""High-level classes to load rules more easily."""

import socket

from pf.rule import PFRule, PFPool, PFPort
from pf._utils import icmp_codes, icmp6_codes
from pf.constants import *


__all__ = ["Rule",
           "BlockRule",
           "BlockInRule",
           "BlockOutRule",
           "PassRule",
           "PassInRule",
           "PassOutRule",
           "MatchRule",
           "MatchInRule",
           "MatchOutRule",
           "NATPool",
           "RDRPool",
           "TCPPort",
           "UDPPort"]


# Rules
class Rule(PFRule):
    """Generic Rule"""

    af = socket.AF_INET

    def __init__(self, **kw):
        kw.setdefault("af", self.af)

        # Try to guess protocol
        if not kw.has_key("proto"):
            kw.setdefault("proto", 0)
            if not kw["proto"] and kw.has_key("src"):
                kw["proto"] = kw["src"].port.proto or 0
            if not kw["proto"] and kw.has_key("dst"):
                kw["proto"] = kw["dst"].port.proto or 0
        # Set default flags on TCP 'pass' rules
        if kw["proto"] == socket.IPPROTO_TCP and kw["action"] == PF_PASS and \
           not kw.has_key("flags"):
            kw.update({"flags": "S", "flagset": "SA"})

        # Convert ICMP type string to constant
        if kw.has_key("type") and isinstance(kw["type"], basestring):
            types = icmp6_types if (kw["af"]==socket.AF_INET6) else icmp_types
            for key, value in types.iteritems():
                if value == kw["type"]:
                    kw["type"] = key + 1
                    break
            else:
                raise ValueError("Invalid ICMP type: {.type}".format(kw))

        # Convert ICMP code string to constants
        if kw.has_key("code") and isinstance(kw["code"], basestring):
            codes = icmp6_codes if (kw["af"]==socket.AF_INET6) else icmp_codes
            for key, value in codes.iteritems():
                if value == kw["code"]:
                    kw["type"], kw["code"] = key[0]+1, key[1]+1
                    break
            else:
                raise ValueError("Invalid ICMP code: {.code}".format(kw))

        super(Rule, self).__init__(**kw)


class BlockRule(Rule):
    """Block (drop) all traffic"""

    def __init__(self, **kw):
        super(BlockRule, self).__init__(action=PF_DROP, **kw)


class BlockInRule(BlockRule):
    """Block incoming traffic"""

    def __init__(self, **kw):
        super(BlockInRule, self).__init__(direction=PF_IN, **kw)


class BlockOutRule(BlockRule):
    """Block outgoing traffic"""

    def __init__(self, **kw):
        super(BlockOutRule, self).__init__(direction=PF_OUT, **kw)


class PassRule(Rule):
    """Pass traffic"""

    def __init__(self, **kw):
        kw.setdefault("keep_state", PF_STATE_NORMAL)
        super(PassRule, self).__init__(action=PF_PASS, **kw)


class PassInRule(PassRule):
    """Pass incoming traffic"""

    def __init__(self, **kw):
        super(PassInRule, self).__init__(direction=PF_IN, **kw)


class PassOutRule(PassRule):
    """Pass outgoing traffic"""

    def __init__(self, **kw):
        super(PassOutRule, self).__init__(direction=PF_OUT, **kw)


class MatchRule(Rule):
    """Match traffic"""

    def __init__(self, **kw):
        super(MatchRule, self).__init__(action=PF_MATCH, **kw)


class MatchInRule(MatchRule):
    """Match incoming traffic"""

    def __init__(self, **kw):
        super(MatchInRule, self).__init__(direction=PF_IN, **kw)


class MatchOutRule(MatchRule):
    """Match outgoing traffic"""

    def __init__(self, **kw):
        super(MatchOutRule, self).__init__(direction=PF_OUT, **kw)


# Pools
class NATPool(PFPool):
    """ """

    def __init__(self, pool, **kw):
        super(NATPool, self).__init__(PF_POOL_NAT, pool, **kw)


class RDRPool(PFPool):
    """ """

    def __init__(self, pool, **kw):
        super(RDRPool, self).__init__(PF_POOL_RDR, pool, **kw)


# Ports
class TCPPort(PFPort):
    """ """

    def __init__(self, num, op=PF_OP_EQ):
        super(TCPPort, self).__init__(num, socket.IPPROTO_TCP, op)


class UDPPort(PFPort):
    """ """

    def __init__(self, num, op=PF_OP_EQ):
        super(UDPPort, self).__init__(num, socket.IPPROTO_UDP, op)
