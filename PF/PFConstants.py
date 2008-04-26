"""Export constants shared by all classes of the module."""


import sys


UINT_MAX                = sys.maxint * 2 + 1

# Actions
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

# Address types
PF_ADDR_ADDRMASK        = 0
PF_ADDR_NOROUTE         = 1
PF_ADDR_DYNIFTL         = 2
PF_ADDR_TABLE           = 3
PF_ADDR_RTLABEL         = 4
PF_ADDR_URPFFAILED      = 5

# Interface flags
PFI_AFLAG_NETWORK       = 0x01
PFI_AFLAG_BROADCAST     = 0x02
PFI_AFLAG_PEER          = 0x04
PFI_AFLAG_MODEMASK      = 0x07
PFI_AFLAG_NOALIAS       = 0x08

# Port comparison operators
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

# Traffic directions
PF_INOUT                = 0
PF_IN                   = 1
PF_OUT                  = 2

# Debug levels
PF_DEBUG_NONE           = 0
PF_DEBUG_URGENT         = 1
PF_DEBUG_MISC           = 2
PF_DEBUG_NOISY          = 3

# Limits
PF_LIMIT_STATES         = 0
PF_LIMIT_SRC_NODES      = 1
PF_LIMIT_FRAGS          = 2
PF_LIMIT_TABLES         = 3
PF_LIMIT_TABLE_ENTRIES  = 4
PF_LIMIT_MAX            = 5

# Timeouts
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
PFTM_UNTIL_PACKET       = 23

# TCP States
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

PF_TCPS_PROXY_SRC       = TCP_NSTATES + 0
PF_TCPS_PROXY_DST       = TCP_NSTATES + 1

# UDP state enumeration
PFUDPS_NO_TRAFFIC       = 0
PFUDPS_SINGLE           = 1
PFUDPS_MULTIPLE         = 2
PFUDPS_NSTATES          = 3

# States for non-TCP protocols
PFOTHERS_NO_TRAFFIC     = 0
PFOTHERS_SINGLE         = 1
PFOTHERS_MULTIPLE       = 2
PFOTHERS_NSTATES        = 3

# Pfsync flags
PFSYNC_FLAG_COMPRESS    = 0x01
PFSYNC_FLAG_STALE       = 0x02
PFSYNC_FLAG_SRCNODE     = 0x04
PFSYNC_FLAG_NATSRCNODE  = 0x08

# PF States
PFSTATE_NOSYNC          = 0x01
PFSTATE_FROMSYNC        = 0x02
PFSTATE_STALE           = 0x04

