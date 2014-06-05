"""Export constants shared by all classes of the module."""

from sys import maxint


# Actions (from /usr/include/net/pfvar.h)
PF_PASS                 = 0
PF_DROP                 = 1
PF_SCRUB                = 2
PF_NOSCRUB              = 3
PF_NAT                  = 4
PF_NONAT                = 5
PF_BINAT                = 6
PF_NOBINAT              = 7
PF_RDR                  = 8
PF_NORDR                = 9
PF_SYNPROXY_DROP        = 10
PF_DEFER                = 11
PF_MATCH                = 12
PF_DIVERT               = 13
PF_RT                   = 14
PF_AFRT                 = 15

# PF transaction types (from /usr/include/net/pfvar.h)
PF_TRANS_RULESET        = 0
PF_TRANS_ALTQ           = 1
PF_TRANS_TABLE          = 2

# PF rule flags (from /usr/include/net/pfvar.h)
PFRULE_DROP             = 0x0000
PFRULE_RETURNRST        = 0x0001
PFRULE_FRAGMENT         = 0x0002
PFRULE_RETURNICMP       = 0x0004
PFRULE_RETURN           = 0x0008
PFRULE_NOSYNC           = 0x0010
PFRULE_SRCTRACK         = 0x0020
PFRULE_RULESRCTRACK     = 0x0040

# PF rule flags (from /usr/include/net/pfvar.h)
PFRULE_IFBOUND          = 0x00010000
PFRULE_STATESLOPPY      = 0x00020000
PFRULE_PFLOW            = 0x00040000
PFRULE_ONCE             = 0x00100000
PFRULE_AFTO             = 0x00200000

# Port comparison operators (from /usr/include/net/pfvar.h)
PF_OP_NONE              = 0
PF_OP_IRG               = 1
PF_OP_EQ                = 2
PF_OP_NE                = 3
PF_OP_LT                = 4
PF_OP_LE                = 5
PF_OP_GT                = 6
PF_OP_GE                = 7
PF_OP_XRG               = 8
PF_OP_RRG               = 9

# Rules retrieval options (from /usr/include/net/pfvar.h)
PF_GET_NONE             = 0
PF_GET_CLR_CNTR         = 1

# PF keep states (from /usr/include/net/pfvar.h)
PF_STATE_NORMAL         = 0x1
PF_STATE_MODULATE       = 0x2
PF_STATE_SYNPROXY       = 0x3

# Routing options (from /usr/include/net/pfvar.h)
PF_NOPFROUTE            = 0
PF_ROUTETO              = 1
PF_DUPTO                = 2
PF_REPLYTO              = 3

# State keys (from /usr/include/net/pfvar.h)
PF_SK_WIRE              = 0
PF_SK_STACK             = 1
PF_SK_BOTH              = 2

# Log options (from /usr/include/net/pfvar.h)
PF_LOG                  = 0x01
PF_LOG_ALL              = 0x02
PF_LOG_SOCKET_LOOKUP    = 0x04
PF_LOG_FORCE            = 0x08
PF_LOG_MATCHES          = 0x10

# Address types (from /usr/include/net/pfvar.h)
PF_ADDR_ADDRMASK        = 0
PF_ADDR_NOROUTE         = 1
PF_ADDR_DYNIFTL         = 2
PF_ADDR_TABLE           = 3
PF_ADDR_RTLABEL         = 4
PF_ADDR_URPFFAILED      = 5
PF_ADDR_RANGE           = 6
PF_ADDR_NONE            = 7

# OS fingerprints matches (from /usr/include/net/pfvar.h)
PF_OSFP_ANY             = 0
PF_OSFP_UNKNOWN         = -1
PF_OSFP_NOMATCH         = -2

# Interface flags (from /usr/include/net/pfvar.h)
PFI_AFLAG_NETWORK       = 0x01
PFI_AFLAG_BROADCAST     = 0x02
PFI_AFLAG_PEER          = 0x04
PFI_AFLAG_MODEMASK      = 0x07
PFI_AFLAG_NOALIAS       = 0x08

# Traffic directions (from /usr/include/net/pfvar.h)
PF_INOUT                = 0
PF_IN                   = 1
PF_OUT                  = 2
PF_FWD                  = 3

# Flush options (from /usr/include/net/pfvar.h)
PF_FLUSH                = 0x01
PF_FLUSH_GLOBAL         = 0x02

# IP type of service (from /usr/include/netinet/ip.h)
IPTOS_LOWDELAY          = 0x10
IPTOS_THROUGHPUT        = 0x08
IPTOS_RELIABILITY       = 0x04

# NAT ports range (from /usr/src/sbin/pfctl/pfctl_parser.h)
PF_NAT_PROXY_PORT_LOW   = 50001
PF_NAT_PROXY_PORT_HIGH  = 65535

# Pool IDs (from /usr/src/sbin/pfctl/pfctl_parser.c)
PF_POOL_ROUTE           = 0
PF_POOL_NAT             = 1
PF_POOL_RDR             = 2

# Pool options (from /usr/include/net/pfvar.h)
PF_POOL_TYPEMASK        = 0x0f
PF_POOL_STICKYADDR      = 0x20

# Pool types (from /usr/include/net/pfvar.h)
PF_POOL_NONE            = 0
PF_POOL_BITMASK         = 1
PF_POOL_RANDOM          = 2
PF_POOL_SRCHASH         = 3
PF_POOL_ROUNDROBIN      = 4
PF_POOL_LEASTSTATES     = 5

# Mask for window scaling factor (from /usr/include/net/pfvar.h)
PF_WSCALE_MASK          = 0x0f

# Debug levels (from /usr/include/sys/syslog.h)
LOG_EMERG               = 0
LOG_ALERT               = 1
LOG_CRIT                = 2
LOG_ERR                 = 3
LOG_WARNING             = 4
LOG_NOTICE              = 5
LOG_INFO                = 6
LOG_DEBUG               = 7

# The 'unlimited' value for limits on the memory pools
UINT_MAX                = 0xffffffff

# Limits (from /usr/include/net/pfvar.h)
PF_LIMIT_STATES         = 0
PF_LIMIT_SRC_NODES      = 1
PF_LIMIT_FRAGS          = 2
PF_LIMIT_TABLES         = 3
PF_LIMIT_TABLE_ENTRIES  = 4
PF_LIMIT_MAX            = 5

# Timeouts (from /usr/include/net/pfvar.h)
PFTM_TCP_FIRST_PACKET   = 0
PFTM_TCP_OPENING        = 1
PFTM_TCP_ESTABLISHED    = 2
PFTM_TCP_CLOSING        = 3
PFTM_TCP_FIN_WAIT       = 4
PFTM_TCP_CLOSED         = 5
PFTM_UDP_FIRST_PACKET   = 6
PFTM_UDP_SINGLE         = 7
PFTM_UDP_MULTIPLE       = 8
PFTM_ICMP_FIRST_PACKET  = 9
PFTM_ICMP_ERROR_REPLY   = 10
PFTM_OTHER_FIRST_PACKET = 11
PFTM_OTHER_SINGLE       = 12
PFTM_OTHER_MULTIPLE     = 13
PFTM_FRAG               = 14
PFTM_INTERVAL           = 15
PFTM_ADAPTIVE_START     = 16
PFTM_ADAPTIVE_END       = 17
PFTM_SRC_NODE           = 18
PFTM_TS_DIFF            = 19
PFTM_MAX                = 20
PFTM_PURGE              = 21
PFTM_UNLINKED           = 22

# TCP States (from /usr/include/netinet/tcp_fsm.h)
TCPS_CLOSED             = 0
TCPS_LISTEN             = 1
TCPS_SYN_SENT           = 2
TCPS_SYN_RECEIVED       = 3
TCPS_ESTABLISHED        = 4
TCPS_CLOSE_WAIT         = 5
TCPS_FIN_WAIT_1         = 6
TCPS_CLOSING            = 7
TCPS_LAST_ACK           = 8
TCPS_FIN_WAIT_2         = 9
TCPS_TIME_WAIT          = 10
TCP_NSTATES             = 11

# From /usr/include/net/pfvar.h
PF_TCPS_PROXY_SRC       = TCP_NSTATES + 0
PF_TCPS_PROXY_DST       = TCP_NSTATES + 1

# UDP state enumeration (from /usr/include/net/pfvar.h)
PFUDPS_NO_TRAFFIC       = 0
PFUDPS_SINGLE           = 1
PFUDPS_MULTIPLE         = 2
PFUDPS_NSTATES          = 3

# States for non-TCP protocols (from /usr/include/net/pfvar.h)
PFOTHERS_NO_TRAFFIC     = 0
PFOTHERS_SINGLE         = 1
PFOTHERS_MULTIPLE       = 2
PFOTHERS_NSTATES        = 3

# Pfsync flags (from /usr/include/net/pfvar.h)
PFSYNC_FLAG_SRCNODE     = 0x04
PFSYNC_FLAG_NATSRCNODE  = 0x08

# PF states flags (from /usr/include/net/pfvar.h)
PFSTATE_ALLOWOPTS       = 0x0001
PFSTATE_SLOPPY          = 0x0002
PFSTATE_PFLOW           = 0x0004
PFSTATE_NOSYNC          = 0x0008
PFSTATE_ACK             = 0x0010
PFSTATE_NODF            = 0x0020
PFSTATE_SETTOS          = 0x0040
PFSTATE_RANDOMID        = 0x0080
PFSTATE_SCRUB_TCP       = 0x0100
PFSTATE_SETPRIO         = 0x0200
PFSTATE_SCRUBMASK       = PFSTATE_NODF|PFSTATE_RANDOMID|PFSTATE_SCRUB_TCP
PFSTATE_SETMASK         = PFSTATE_SETTOS|PFSTATE_SETPRIO

# Reassembly flags (from /usr/include/net/pfvar.h)
PF_REASS_ENABLED        = 0x01
PF_REASS_NODF           = 0x02

# Table flags (from /usr/include/net/pfvar.h)
PFR_TFLAG_PERSIST       = 0x01
PFR_TFLAG_CONST         = 0x02
PFR_TFLAG_ACTIVE        = 0x04
PFR_TFLAG_INACTIVE      = 0x08
PFR_TFLAG_REFERENCED    = 0x10
PFR_TFLAG_REFDANCHOR    = 0x20
PFR_TFLAG_COUNTERS      = 0x40
PFR_TFLAG_USRMASK       = 0x43
PFR_TFLAG_SETMASK       = 0x3C
PFR_TFLAG_ALLMASK       = 0x7F

PFR_FLAG_DUMMY          = 0x00000002
PFR_FLAG_FEEDBACK       = 0x00000004
PFR_FLAG_CLSTATS        = 0x00000008
PFR_FLAG_ADDRSTOO       = 0x00000010
PFR_FLAG_REPLACE        = 0x00000020
PFR_FLAG_ALLRSETS       = 0x00000040
PFR_FLAG_ALLMASK        = 0x0000007f

PFR_DIR_IN              = 0
PFR_DIR_OUT             = 1
PFR_DIR_MAX             = 2

PFR_OP_BLOCK            = 0
PFR_OP_MATCH            = 1
PFR_OP_PASS             = 2
PFR_OP_ADDR_MAX         = 3
PFR_OP_TABLE_MAX        = 4
PFR_OP_XPASS            = PFR_OP_ADDR_MAX

PFR_REFCNT_RULE         = 0
PFR_REFCNT_ANCHOR       = 1
PFR_REFCNT_MAX          = 2

# pfrke type (from /usr/include/net/pfvar.h)
PFRKE_PLAIN             = 0
PFRKE_ROUTE             = 1
PFRKE_COST              = 2
PFRKE_MAX               = 3

# Interface flags (from /usr/include/net/pfvar.h)
PFI_IFLAG_SKIP          = 0x0100
PFI_IFLAG_ANY		    = 0x0200

# From /usr/src/sbin/pfctl/pfctl.h
DEFAULT_PRIORITY        = 1
DEFAULT_QLIMIT          = 50

# HFSC class flags (from /usr/include/altq/altq_hfsc.h)
HFSC_RED                = 0x0001
HFSC_ECN                = 0x0002
HFSC_RIO                = 0x0004
HFSC_DEFAULTCLASS       = 0x1000

# ICMP types (from /usr/include/netinet/ip_icmp.h)
ICMP_ECHO                        = 8
ICMP_ECHOREPLY                   = 0
ICMP_UNREACH                     = 3
ICMP_SOURCEQUENCH                = 4
ICMP_REDIRECT                    = 5
ICMP_ALTHOSTADDR                 = 6
ICMP_ROUTERADVERT                = 9
ICMP_ROUTERSOLICIT               = 10
ICMP_TIMXCEED                    = 11
ICMP_PARAMPROB                   = 12
ICMP_TSTAMP                      = 13
ICMP_TSTAMPREPLY                 = 14
ICMP_IREQ                        = 15
ICMP_IREQREPLY                   = 16
ICMP_MASKREQ                     = 17
ICMP_MASKREPLY                   = 18
ICMP_TRACEROUTE                  = 30
ICMP_DATACONVERR                 = 31
ICMP_MOBILE_REDIRECT             = 32
ICMP_IPV6_WHEREAREYOU            = 33
ICMP_IPV6_IAMHERE                = 34
ICMP_MOBILE_REGREQUEST           = 35
ICMP_MOBILE_REGREPLY             = 36
ICMP_SKIP                        = 39
ICMP_PHOTURIS                    = 40

# ICMP codes (from /usr/include/netinet/ip_icmp.h)
ICMP_UNREACH_NET                 = 0    # Destination unreachable
ICMP_UNREACH_HOST                = 1
ICMP_UNREACH_PROTOCOL            = 2
ICMP_UNREACH_PORT                = 3
ICMP_UNREACH_NEEDFRAG            = 4
ICMP_UNREACH_SRCFAIL             = 5
ICMP_UNREACH_NET_UNKNOWN         = 6
ICMP_UNREACH_HOST_UNKNOWN        = 7
ICMP_UNREACH_ISOLATED            = 8
ICMP_UNREACH_NET_PROHIB          = 9
ICMP_UNREACH_HOST_PROHIB         = 10
ICMP_UNREACH_TOSNET              = 11
ICMP_UNREACH_TOSHOST             = 12
ICMP_UNREACH_FILTER_PROHIB       = 13
ICMP_UNREACH_HOST_PRECEDENCE     = 14
ICMP_UNREACH_PRECEDENCE_CUTOFF   = 15
ICMP_REDIRECT_NET                = 0    # Shorter route
ICMP_REDIRECT_HOST               = 1
ICMP_REDIRECT_TOSNET             = 2
ICMP_REDIRECT_TOSHOST            = 3
ICMP_ROUTERADVERT_NORMAL         = 0    # Router advertisement
ICMP_ROUTERADVERT_NOROUTE_COMMON = 16
ICMP_TIMXCEED_INTRANS            = 0    # Time exceeded
ICMP_TIMXCEED_REASS              = 1
ICMP_PARAMPROB_ERRATPTR          = 0    # IP header bad
ICMP_PARAMPROB_OPTABSENT         = 1
ICMP_PARAMPROB_LENGTH            = 2
ICMP_PHOTURIS_UNKNOWN_INDEX      = 1    # Photuris
ICMP_PHOTURIS_AUTH_FAILED        = 2
ICMP_PHOTURIS_DECRYPT_FAILED     = 3

# ICMP6 types (from /usr/include/netinet/icmp6.h)
ICMP6_DST_UNREACH                = 1
ICMP6_PACKET_TOO_BIG             = 2
ICMP6_TIME_EXCEEDED              = 3
ICMP6_PARAM_PROB                 = 4
ICMP6_ECHO_REQUEST               = 128
ICMP6_ECHO_REPLY                 = 129
ICMP6_MEMBERSHIP_QUERY           = 130
MLD_LISTENER_QUERY               = 130
ICMP6_MEMBERSHIP_REPORT          = 131
MLD_LISTENER_REPORT              = 131
ICMP6_MEMBERSHIP_REDUCTION       = 132
MLD_LISTENER_DONE                = 132
ND_ROUTER_SOLICIT                = 133
ND_ROUTER_ADVERT                 = 134
ND_NEIGHBOR_SOLICIT              = 135
ND_NEIGHBOR_ADVERT               = 136
ND_REDIRECT                      = 137
ICMP6_ROUTER_RENUMBERING         = 138
ICMP6_WRUREQUEST                 = 139
ICMP6_WRUREPLY                   = 140
ICMP6_FQDN_QUERY                 = 139
ICMP6_FQDN_REPLY                 = 140
ICMP6_NI_QUERY                   = 139
ICMP6_NI_REPLY                   = 140
MLD_MTRACE_RESP                  = 200
MLD_MTRACE                       = 201

# ICMP6 codes (from /usr/include/netinet/icmp6.h)
ICMP6_DST_UNREACH_NOROUTE        = 0
ICMP6_DST_UNREACH_ADMIN          = 1
ICMP6_DST_UNREACH_NOTNEIGHBOR    = 2
ICMP6_DST_UNREACH_BEYONDSCOPE    = 2
ICMP6_DST_UNREACH_ADDR           = 3
ICMP6_DST_UNREACH_NOPORT         = 4
ICMP6_TIME_EXCEED_TRANSIT        = 0
ICMP6_TIME_EXCEED_REASSEMBLY     = 1
ICMP6_PARAMPROB_HEADER           = 0
ICMP6_PARAMPROB_NEXTHEADER       = 1
ICMP6_PARAMPROB_OPTION           = 2
ND_REDIRECT_ONLINK               = 0
ND_REDIRECT_ROUTER               = 1
