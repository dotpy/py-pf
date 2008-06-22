"""Miscellaneous network and PF-related utilities"""

import re
from socket import *

from PFConstants import *


__all__ = ['getprotobynumber',
           'geticmpcodebynumber',
           'geticmptypebynumber']

 
# Dictionaries for mapping strings to constants ################################
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


# Functions ####################################################################
def getprotobynumber(number, file="/etc/protocols"):
    """Map a protocol number to a name.

    Return the protocol name or None if no match is found."""
    try:
        f = open(file, "r")
    except:
        return None     # Fail silently

    r = re.compile("(\S+)\s+(\d+)")

    for line in f:
        m = r.match(line.split("#")[0].strip())
        if m:
            proto, num = m.groups()
            if int(num) == number:
                return proto

    return None

def geticmpcodebynumber(type, code, af):
    """Return the ICMP code as a string."""
    try:
        if af != AF_INET6:
            return icmp_codes[(type, code)]
        else:
            return icmp6_codes[(type, code)]
    except KeyError:
        return None

def geticmptypebynumber(type, af):
    """Return the ICMP type as a string."""
    try:
        if af != AF_INET6:
            return icmp_types[type]
        else:
            return icmp6_types[type]
    except KeyError:
        return None

