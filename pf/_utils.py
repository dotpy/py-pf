"""Miscellaneous network and PF-related utilities"""


import re
from socket import *
from ctypes import addressof
from fcntl import ioctl

from pf.constants import *
from pf._struct import ifreq, if_data


# Dictionaries for mapping strings to constants
# Debug levels
dbg_levels = {
    "emerg":  LOG_EMERG,
    "alert":  LOG_ALERT,
    "crit":   LOG_CRIT,
    "err":    LOG_ERR,
    "warn":   LOG_WARNING,
    "notice": LOG_NOTICE,
    "info":   LOG_INFO,
    "debug":  LOG_DEBUG
}

# Memory limits
pf_limits = {
    "states":        PF_LIMIT_STATES,
    "src-nodes":     PF_LIMIT_SRC_NODES,
    "frags":         PF_LIMIT_FRAGS,
    "tables":        PF_LIMIT_TABLES,
    "table-entries": PF_LIMIT_TABLE_ENTRIES
}

# Ports, UIDs and GIDs operators
pf_ops = {
    "":   PF_OP_NONE,
    "><": PF_OP_IRG,
    "<>": PF_OP_XRG,
    "=":  PF_OP_EQ,
    "!=": PF_OP_NE,
    "<":  PF_OP_LT,
    "<=": PF_OP_LE,
    ">":  PF_OP_GT,
    ">=": PF_OP_GE,
    ":":  PF_OP_RRG
}

# Interface modifiers
pf_if_mods = {
    "network":   PFI_AFLAG_NETWORK,
    "broadcast": PFI_AFLAG_BROADCAST,
    "peer":      PFI_AFLAG_PEER,
    "0":         PFI_AFLAG_NOALIAS
}

# Global timeouts
pf_timeouts = {
    "tcp.first":       PFTM_TCP_FIRST_PACKET,
    "tcp.opening":     PFTM_TCP_OPENING,
    "tcp.established": PFTM_TCP_ESTABLISHED,
    "tcp.closing":     PFTM_TCP_CLOSING,
    "tcp.finwait":     PFTM_TCP_FIN_WAIT,
    "tcp.closed":      PFTM_TCP_CLOSED,
    "tcp.tsdiff":      PFTM_TS_DIFF,
    "udp.first":       PFTM_UDP_FIRST_PACKET,
    "udp.single":      PFTM_UDP_SINGLE,
    "udp.multiple":    PFTM_UDP_MULTIPLE,
    "icmp.first":      PFTM_ICMP_FIRST_PACKET,
    "icmp.error":      PFTM_ICMP_ERROR_REPLY,
    "other.first":     PFTM_OTHER_FIRST_PACKET,
    "other.single":    PFTM_OTHER_SINGLE,
    "other.multiple":  PFTM_OTHER_MULTIPLE,
    "frag":            PFTM_FRAG,
    "interval":        PFTM_INTERVAL,
    "adaptive.start":  PFTM_ADAPTIVE_START,
    "adaptive.end":    PFTM_ADAPTIVE_END,
    "src.track":       PFTM_SRC_NODE
}

# PF Optimization Hints
pf_hint_normal = {
    "tcp.first": 2 * 60,
    "tcp.opening": 30,
    "tcp.established": 24 * 60 * 60,
    "tcp.closing": 15 * 60,
    "tcp.finwait": 45,
    "tcp.closed": 90,
    "tcp.tsdiff": 30
}

pf_hint_sattelite = {
    "tcp.first": 3 * 60,
    "tcp.opening": 30 + 5,
    "tcp.established": 24 * 60 * 60,
    "tcp.closing": 15 * 60 + 5,
    "tcp.finwait": 45 + 5,
    "tcp.closed": 90 + 5,
    "tcp.tsdiff": 60
}

pf_hint_conservative = {
    "tcp.first": 60 * 60,
    "tcp.opening": 15 * 60,
    "tcp.established": 5 * 24 * 60 * 60,
    "tcp.closing": 60 * 60,
    "tcp.finwait": 10 * 60,
    "tcp.closed": 3 * 90,
    "tcp.tsdiff": 60
}

pf_hint_aggressive = {
    "tcp.first": 30,
    "tcp.opening": 5,
    "tcp.established": 5 * 60 * 60,
    "tcp.closing": 60,
    "tcp.finwait": 30,
    "tcp.closed": 30,
    "tcp.tsdiff": 10
}

pf_hints = {
    "normal": pf_hint_normal,
    "sattelite": pf_hint_sattelite,
    "high-latency": pf_hint_sattelite,
    "conservative": pf_hint_conservative,
    "aggressive": pf_hint_aggressive
}


# Dictionaries for mapping constants to strings
# TCP states
tcpstates = {TCPS_CLOSED:       "CLOSED",
             TCPS_LISTEN:       "LISTEN",
             TCPS_SYN_SENT:     "SYN_SENT",
             TCPS_SYN_RECEIVED: "SYN_RCVD",
             TCPS_ESTABLISHED:  "ESTABLISHED",
             TCPS_CLOSE_WAIT:   "CLOSE_WAIT",
             TCPS_FIN_WAIT_1:   "FIN_WAIT_1",
             TCPS_CLOSING:      "CLOSING",
             TCPS_LAST_ACK:     "LAST_ACK",
             TCPS_FIN_WAIT_2:   "FIN_WAIT_2",
             TCPS_TIME_WAIT:    "TIME_WAIT"}

# UDP states
udpstates = {PFUDPS_NO_TRAFFIC: "NO_TRAFFIC",
             PFUDPS_SINGLE:     "SINGLE",
             PFUDPS_MULTIPLE:   "MULTIPLE"}

# ICMP and ICMPv6 codes and types
icmp_codes = {
    (ICMP_UNREACH,        ICMP_UNREACH_NET):                 "net-unr",
    (ICMP_UNREACH,        ICMP_UNREACH_HOST):                "host-unr",
    (ICMP_UNREACH,        ICMP_UNREACH_PROTOCOL):            "proto-unr",
    (ICMP_UNREACH,        ICMP_UNREACH_PORT):                "port-unr",
    (ICMP_UNREACH,        ICMP_UNREACH_NEEDFRAG):            "needfrag",
    (ICMP_UNREACH,        ICMP_UNREACH_SRCFAIL):             "srcfail",
    (ICMP_UNREACH,        ICMP_UNREACH_NET_UNKNOWN):         "net-unk",
    (ICMP_UNREACH,        ICMP_UNREACH_HOST_UNKNOWN):        "host-unk",
    (ICMP_UNREACH,        ICMP_UNREACH_ISOLATED):            "isolate",
    (ICMP_UNREACH,        ICMP_UNREACH_NET_PROHIB):          "net-prohib",
    (ICMP_UNREACH,        ICMP_UNREACH_HOST_PROHIB):         "host-prohib",
    (ICMP_UNREACH,        ICMP_UNREACH_TOSNET):              "net-tos",
    (ICMP_UNREACH,        ICMP_UNREACH_TOSHOST):             "host-tos",
    (ICMP_UNREACH,        ICMP_UNREACH_FILTER_PROHIB):       "filter-prohib",
    (ICMP_UNREACH,        ICMP_UNREACH_HOST_PRECEDENCE):     "host-preced",
    (ICMP_UNREACH,        ICMP_UNREACH_PRECEDENCE_CUTOFF):   "cutoff-preced",
    (ICMP_REDIRECT,       ICMP_REDIRECT_NET):                "redir-net",
    (ICMP_REDIRECT,       ICMP_REDIRECT_HOST):               "redir-host",
    (ICMP_REDIRECT,       ICMP_REDIRECT_TOSNET):             "redir-tos-net",
    (ICMP_REDIRECT,       ICMP_REDIRECT_TOSHOST):            "redir-tos-host",
    (ICMP_ROUTERADVERT,   ICMP_ROUTERADVERT_NORMAL):         "normal-adv",
    (ICMP_ROUTERADVERT,   ICMP_ROUTERADVERT_NOROUTE_COMMON): "common-adv",
    (ICMP_TIMXCEED,       ICMP_TIMXCEED_INTRANS):            "transit",
    (ICMP_TIMXCEED,       ICMP_TIMXCEED_REASS):              "reassemb",
    (ICMP_PARAMPROB,      ICMP_PARAMPROB_ERRATPTR):          "badhead",
    (ICMP_PARAMPROB,      ICMP_PARAMPROB_OPTABSENT):         "optmiss",
    (ICMP_PARAMPROB,      ICMP_PARAMPROB_LENGTH):            "badlen",
    (ICMP_PHOTURIS,       ICMP_PHOTURIS_UNKNOWN_INDEX):      "unknown-ind",
    (ICMP_PHOTURIS,       ICMP_PHOTURIS_AUTH_FAILED):        "auth-fail",
    (ICMP_PHOTURIS,       ICMP_PHOTURIS_DECRYPT_FAILED):     "decrypt-fail"}

icmp6_codes = {
    (ICMP6_DST_UNREACH,   ICMP6_DST_UNREACH_ADMIN):          "admin-unr",
    (ICMP6_DST_UNREACH,   ICMP6_DST_UNREACH_NOROUTE):        "noroute-unr",
    (ICMP6_DST_UNREACH,   ICMP6_DST_UNREACH_NOTNEIGHBOR):    "notnbr-unr",
    (ICMP6_DST_UNREACH,   ICMP6_DST_UNREACH_BEYONDSCOPE):    "beyond-unr",
    (ICMP6_DST_UNREACH,   ICMP6_DST_UNREACH_ADDR):           "addr-unr",
    (ICMP6_DST_UNREACH,   ICMP6_DST_UNREACH_NOPORT):         "port-unr",
    (ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_TRANSIT):        "transit",
    (ICMP6_TIME_EXCEEDED, ICMP6_TIME_EXCEED_REASSEMBLY):     "reassemb",
    (ICMP6_PARAM_PROB,    ICMP6_PARAMPROB_HEADER):           "badhead",
    (ICMP6_PARAM_PROB,    ICMP6_PARAMPROB_NEXTHEADER):       "nxthdr",
    (ND_REDIRECT,         ND_REDIRECT_ONLINK):               "redironlink",
    (ND_REDIRECT,         ND_REDIRECT_ROUTER):               "redirrouter"}

icmp_types = {
    ICMP_ECHO:                  "echoreq",
    ICMP_ECHOREPLY:             "echorep",
    ICMP_UNREACH:               "unreach",
    ICMP_SOURCEQUENCH:          "squench",
    ICMP_REDIRECT:              "redir",
    ICMP_ALTHOSTADDR:           "althost",
    ICMP_ROUTERADVERT:          "routeradv",
    ICMP_ROUTERSOLICIT:         "routersol",
    ICMP_TIMXCEED:              "timex",
    ICMP_PARAMPROB:             "paramprob",
    ICMP_TSTAMP:                "timereq",
    ICMP_TSTAMPREPLY:           "timerep",
    ICMP_IREQ:                  "inforeq",
    ICMP_IREQREPLY:             "inforep",
    ICMP_MASKREQ:               "maskreq",
    ICMP_MASKREPLY:             "maskrep",
    ICMP_TRACEROUTE:            "trace",
    ICMP_DATACONVERR:           "dataconv",
    ICMP_MOBILE_REDIRECT:       "mobredir",
    ICMP_IPV6_WHEREAREYOU:      "ipv6-where",
    ICMP_IPV6_IAMHERE:          "ipv6-here",
    ICMP_MOBILE_REGREQUEST:     "mobregreq",
    ICMP_MOBILE_REGREPLY:       "mobregrep",
    ICMP_SKIP:                  "skip",
    ICMP_PHOTURIS:              "photuris"}

icmp6_types = {
    ICMP6_DST_UNREACH:          "unreach",
    ICMP6_PACKET_TOO_BIG:       "toobig",
    ICMP6_TIME_EXCEEDED:        "timex",
    ICMP6_PARAM_PROB:           "paramprob",
    ICMP6_ECHO_REQUEST:         "echoreq",
    ICMP6_ECHO_REPLY:           "echorep",
    ICMP6_MEMBERSHIP_QUERY:     "groupqry",
    MLD_LISTENER_QUERY:         "listqry",
    ICMP6_MEMBERSHIP_REPORT:    "grouprep",
    MLD_LISTENER_REPORT:        "listenrep",
    ICMP6_MEMBERSHIP_REDUCTION: "groupterm",
    MLD_LISTENER_DONE:          "listendone",
    ND_ROUTER_SOLICIT:          "routersol",
    ND_ROUTER_ADVERT:           "routeradv",
    ND_NEIGHBOR_SOLICIT:        "neighbrsol",
    ND_NEIGHBOR_ADVERT:         "neighbradv",
    ND_REDIRECT:                "redir",
    ICMP6_ROUTER_RENUMBERING:   "routrrenum",
    ICMP6_WRUREQUEST:           "wrureq",
    ICMP6_WRUREPLY:             "wrurep",
    ICMP6_FQDN_QUERY:           "fqdnreq",
    ICMP6_FQDN_REPLY:           "fqdnrep",
    ICMP6_NI_QUERY:             "niqry",
    ICMP6_NI_REPLY:             "nirep",
    MLD_MTRACE_RESP:            "mtraceresp",
    MLD_MTRACE:                 "mtrace"}


# Helper functions
def getprotobynumber(number, file="/etc/protocols"):
    """Map a protocol number to a name.

    Return the protocol name or None if no match is found.
    """
    r = re.compile("(?P<proto>\S+)\s+(?P<num>\d+)")
    with open(file, 'r') as f:
        for line in f:
            m = r.match(line)
            if m and int(m.group("num")) == number:
                return m.group("proto")


def geticmpcodebynumber(type, code, af):
    """Return the ICMP code as a string."""
    ic = icmp_codes if (af != AF_INET6) else icmp6_codes
    try:
        return ic[(type, code)]
    except KeyError:
        return None


def geticmptypebynumber(type, af):
    """Return the ICMP type as a string."""
    it = icmp_types if (af != AF_INET6) else icmp6_types
    try:
        return it[type]
    except KeyError:
        return None


def ctonm(cidr, af):
    """Convert netmask from CIDR to dotted decimal notation."""
    try:
        l = {AF_INET: 32, AF_INET6: 128}[af]
    except KeyError:
        raise ValueError("Invalid address family")

    b = "1" * cidr + "0" * (l - cidr)
    mask = "".join([chr(int(b[i:i+8], 2)) for i in range(0, l, 8)])

    return inet_ntop(af, mask)


def nmtoc(netmask, af):
    """Convert netmask from dotted decimal to CIDR notation."""
    cidr = 0
    for b in map(ord, inet_pton(af, netmask)):
        while b:
            cidr += b & 1
            b >>= 1

    return cidr


def rate2str(bw):
    """Return the string representation of the network speed rate."""
    units = [" ", "K", "M", "G"]
    for i in range(len(units)):
        if bw >= 1000:
            bw /= 1000.0
        else:
            break

    if int(bw * 100 % 100):
        return "{:.2f}{}".format(bw, units[i])
    else:
        return "{}{}".format(int(bw), units[i])


def getifmtu(ifname):
    """Quick hack to get MTU and speed for a specified interface."""
    from pf.filter import _IOWR
    SIOCGIFMTU = _IOWR('i', 126, ifreq)
    s = socket(AF_INET, SOCK_DGRAM)
    ifrdat = if_data()
    ifr = ifreq(ifr_name=ifname, ifru_data=addressof(ifrdat))

    try:
        ioctl(s, SIOCGIFMTU, ifr.asBuffer())
    except IOError:
        pass

    s.close()
    mtu = (ifr.ifru_metric if (ifr.ifru_metric > 0) else 1500)
    speed = ifrdat.ifi_baudrate

    return (mtu, speed)
