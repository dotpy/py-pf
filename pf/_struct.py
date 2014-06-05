"""Mapping of C structs, required by ioctl() calls, to ctypes."""

from ctypes import *

from pf.constants import *


__all__ = ['pfioc_limit',
           'pfioc_tm',
           'pf_status',
           'pf_addr_wrap',
           'pf_rule_addr',
           'pfsync_state_peer',
           'pfsync_state_key',
           'pfsync_state',
           'pfioc_states',
           'pfioc_state_kill',
           'pf_pool',
           'pf_rule_uid',
           'pf_rule_gid',
           'pf_rule',
           'pfioc_rule',
           'pfioc_trans_e',
           'pfioc_trans',
           'pfr_addr',
           'pfr_table',
           'pfioc_table',
           'pfr_tstats',
           'pfi_kif',
           'pfioc_iface',
           'pf_queue_bwspec',
           'pf_queue_scspec',
           'pf_queuespec',
           'pfioc_qstats',
           'pfioc_queue',
           'class_stats_t',
           'priq_classstats',
           'hfsc_classstats',
           'class_stats',
           'queue_stats',
           'ifreq',
           'if_data']


# Constants
IFNAMSIZ             = 16               # From /usr/include/net/if.h
PFRES_MAX            = 16               # From /usr/include/net/pfvar.h
LCNT_MAX             = 7                # From /usr/include/net/pfvar.h
FCNT_MAX             = 3                # From /usr/include/net/pfvar.h
SCNT_MAX             = 3                # From /usr/include/net/pfvar.h
PF_MD5_DIGEST_LENGTH = 16               # From /usr/include/net/pfvar.h
PF_TABLE_NAME_SIZE   = 32               # From /usr/include/net/pfvar.h
PF_RULE_LABEL_SIZE   = 64               # From /usr/include/net/pfvar.h
PF_QNAME_SIZE        = 64               # From /usr/include/net/pfvar.h
PF_TAG_NAME_SIZE     = 64               # From /usr/include/net/pfvar.h
PF_SKIP_COUNT        = 9                # From /usr/include/net/pfvar.h
RTLABEL_LEN          = 32               # From /usr/include/net/route.h
PATH_MAX             = 1024             # From /usr/include/sys/syslimits.h
MAXPATHLEN           = PATH_MAX         # From /usr/include/sys/param.h


class BufferStructure(Structure):
    """A subclass of ctypes.Structure to simplify ioctl() system calls."""

    def __init__(self, **kw):
        """Call the parent constructor"""
        super(BufferStructure, self).__init__(**kw)

    def asBuffer(self):
        """Return a buffer pointing to the Structure.

        This allows ioctl() to write directly to the structure, even if bigger
        than 1024 bytes.
        """
        return (c_char * sizeof(self)).from_address(addressof(self))


class pfioc_limit(BufferStructure):     # From /usr/include/net/pfvar.h
    _fields_ = [("index",             c_int),
                ("limit",             c_uint)]


class pfioc_tm(BufferStructure):        # From /usr/include/net/pfvar.h
    _fields_ = [("timeout",           c_int),
                ("seconds",           c_int)]


class pf_status(BufferStructure):       # From /usr/include/net/pfvar.h
    _fields_ = [("counters",          c_uint64 * PFRES_MAX),
                ("lcounters",         c_uint64 * LCNT_MAX),
                ("fcounters",         c_uint64 * FCNT_MAX),
                ("scounters",         c_uint64 * SCNT_MAX),
                ("pcounters",         c_uint64 * 3 * 2 * 2),
                ("bcounters",         c_uint64 * 2 * 2),
                ("stateid",           c_uint64),
				("since",             c_int64),       # time_t
                ("running",           c_uint32),
                ("states",            c_uint32),
                ("src_nodes",         c_uint32),
                ("debug",             c_uint32),
                ("hostid",            c_uint32),
                ("reass",             c_uint32),
                ("ifname",            c_char * IFNAMSIZ),
                ("pf_chksum",         c_uint8 * PF_MD5_DIGEST_LENGTH)]


class pf_addr(Structure):               # From /usr/include/net/pfvar.h
    class _pfa(Union):
        _fields_ = [("v4",            c_uint32),      # struct in_addr
                    ("v6",            c_uint32 * 4),  # struct in6_addr
                    ("addr8",         c_uint8 * 16),
                    ("addr16",        c_uint16 * 8),
                    ("addr32",        c_uint32 * 4)]

    _fields_ = [("pfa",               _pfa)]
    _anonymous_ = ("pfa",)


class pf_addr_wrap(Structure):          # From /usr/include/net/pfvar.h
    class _v(Union):
        class _a(Structure):
            _fields_ = [("addr",      pf_addr),
                        ("mask",      pf_addr)]

        _fields_ = [("a",             _a),
                    ("ifname",        c_char * IFNAMSIZ),
                    ("tblname",       c_char * PF_TABLE_NAME_SIZE),
                    ("rtlabelname",   c_char * RTLABEL_LEN),
                    ("rtlabel",       c_uint32)]

    class _p(Union):
        _fields_ = [("dyn",           c_void_p),      # (struct pfi_dynaddr *)
                    ("tbl",           c_void_p),      # (struct pfr_ktable *)
                    ("dyncnt",        c_int),
                    ("tblcnt",        c_int)]

    _fields_ = [("v",                 _v),
                ("p",                 _p),
                ("type",              c_uint8),
                ("iflags",            c_uint8)]


class pf_rule_addr(Structure):          # From /usr/include/net/pfvar.h
    _fields_ = [("addr",              pf_addr_wrap),
                ("port",              c_uint16 * 2),
                ("neg",               c_uint8),
                ("port_op",           c_uint8),
                ("weight",            c_uint16)]


class pfsync_state_scrub(Structure):    # From /usr/include/net/pfvar.h
    _fields_ = [("pfss_flags",        c_uint16),
                ("pfss_ttl",          c_uint8),
                ("scrub_flag",        c_uint8),
                ("pfss_ts_mod",       c_uint32)]


class pfsync_state_peer(Structure):     # From /usr/include/net/pfvar.h
    _fields_ = [("scrub",             pfsync_state_scrub),
                ("seqlo",             c_uint32),
                ("seqhi",             c_uint32),
                ("seqdiff",           c_uint32),
                ("max_win",           c_uint16),
                ("mss",               c_uint16),
                ("state",             c_uint8),
                ("wscale",            c_uint8),
                ("pad",               c_uint8 * 6)]


class pfsync_state_key(Structure):      # From /usr/include/net/pfvar.h
    _fields_ = [("addr",              pf_addr * 2),
                ("port",              c_uint16 * 2),
                ("rdomain",           c_uint16),
                ("af",                c_uint8),       # sa_family_t
                ("pad",               c_uint8)]


class pfsync_state(Structure):          # From /usr/include/net/pfvar.h
    _fields_ = [("id",                c_uint64),
                ("ifname",            c_char * IFNAMSIZ),
                ("key",               pfsync_state_key * 2),
                ("src",               pfsync_state_peer),
                ("dst",               pfsync_state_peer),
                ("rt_addr",           pf_addr),
                ("rule",              c_uint32),
                ("anchor",            c_uint32),
                ("nat_rule",          c_uint32),
                ("creation",          c_uint32),
                ("expire",            c_uint32),
                ("packets",           c_uint32 * 2 * 2),
                ("bytes",             c_uint32 * 2 * 2),
                ("creatorid",         c_uint32),
                ("rtableid",          c_int32 * 2),
                ("max_mss",           c_uint16),
                ("af",                c_uint8),       # sa_family_t
                ("proto",             c_uint8),
                ("direction",         c_uint8),
                ("log",               c_uint8),
                ("pad0",              c_uint8),
                ("timeout",           c_uint8),
                ("sync_flags",        c_uint8),
                ("updates",           c_uint8),
                ("min_ttl",           c_uint8),
                ("set_tos",           c_uint8),
                ("state_flags",       c_uint16),
                ("pad",               c_uint8 * 2)]


class pfioc_states(BufferStructure):    # From /usr/include/net/pfvar.h
    class _ps_u(Union):
        _fields_ = [("ps_buf",        c_void_p),      # caddr_t
                    ("ps_states",     c_void_p)]      # struct pfsync_state *

    _fields_ = [("ps_len",            c_int),
                ("ps_u",              _ps_u)]
    _anonymous_ =  ("ps_u",)


class pf_state_cmp(Structure):          # From /usr/include/net/pfvar.h
    _fields_ = [("id",                c_uint64),
                ("creatorid",         c_uint32),
                ("direction",         c_uint8),
                ("pad",               c_uint8 * 3)]


class pfioc_state_kill(BufferStructure): # From /usr/include/net/pfvar.h
    _fields_ = [("psk_pfcmp",         pf_state_cmp),
                ("psk_af",            c_uint8),       # sa_family_t
                ("psk_proto",         c_int),
                ("psk_src",           pf_rule_addr),
                ("psk_dst",           pf_rule_addr),
                ("psk_ifname",        c_char * IFNAMSIZ),
                ("psk_label",         c_char * PF_RULE_LABEL_SIZE),
                ("psk_killed",        c_uint),
                ("psk_rdomain",       c_uint16)]


class pf_poolhashkey(Structure):        # From /usr/include/net/pfvar.h
    class _pfk(Union):
        _fields_ = [("key8",          c_uint8 * 16),
                    ("key16",         c_uint16 * 8),
                    ("key32",         c_uint32 * 4)]

    _fields_ = [("pfk",               _pfk)]
    _anonymous_ = ("pfk",)


class pf_pool(Structure):               # From /usr/include/net/pfvar.h
    _fields_ = [("addr",              pf_addr_wrap),
                ("key",               pf_poolhashkey),
                ("counter",           pf_addr),
                ("ifname",            c_char * IFNAMSIZ),
                ("kif",               c_void_p),      # struct pfi_kif *
                ("tblidx",            c_int),
                ("states",            c_uint64),
                ("curweight",         c_int),
                ("weight",            c_uint16),
                ("proxy_port",        c_uint16 * 2),
                ("port_op",           c_uint8),
                ("opts",              c_uint8)]


class pf_rule_ptr(Union):               # From /usr/include/net/pfvar.h
    _fields_ = [("ptr",               c_void_p),      # struct pf_rule *
                ("nr",                c_uint32)]


class pf_rule_uid(Structure):           # From /usr/include/net/pfvar.h
    _fields_ = [("uid",               c_uint32 * 2),  # uid_t
                ("op",                c_uint8)]


class pf_rule_gid(Structure):           # From /usr/include/net/pfvar.h
    _fields_ = [("gid",               c_uint32 * 2),  # uid_t
                ("op",                c_uint8)]


class pf_rule(Structure):               # From /usr/include/net/pfvar.h
    class _conn_rate(Structure):
        _fields_ = [("limit",         c_uint32),
                    ("seconds",       c_uint32)]

    class _divert(Structure):
        _fields_ = [("addr",          pf_addr),
                    ("port",          c_uint16)]

    _fields_ = [("src",               pf_rule_addr),
                ("dst",               pf_rule_addr),
                ("skip",              pf_rule_ptr * PF_SKIP_COUNT),
                ("label",             c_char * PF_RULE_LABEL_SIZE),
                ("ifname",            c_char * IFNAMSIZ),
                ("rcv_ifname",        c_char * IFNAMSIZ),
                ("qname",             c_char * PF_QNAME_SIZE),
                ("pqname",            c_char * PF_QNAME_SIZE),
                ("tagname",           c_char * PF_TAG_NAME_SIZE),
                ("match_tagname",     c_char * PF_TAG_NAME_SIZE),
                ("overload_tblname",  c_char * PF_TABLE_NAME_SIZE),
                ("entries",           c_void_p * 2),  # TAILQ_ENTRY(pf_rule)
                ("nat",               pf_pool),
                ("rdr",               pf_pool),
                ("route",             pf_pool),
                ("evaluations",       c_uint64),
                ("packets",           c_uint64 * 2),
                ("bytes",             c_uint64 * 2),
                ("kif",               c_void_p),      # (struct pki_kif *)
                ("rcv_kif",           c_void_p),      # (struct pki_kif *)
                ("anchor",            c_void_p),      # (struct pf_anchor *)
                ("overload_tbl",      c_void_p),      # (struct pfr_ktable *)
                ("os_fingerprint",    c_uint32),      # pf_osfp_t
                ("rtableid",          c_int),
                ("onrdomain",         c_int),
                ("timeout",           c_uint32 * PFTM_MAX),
                ("states_cur",        c_uint32),
                ("states_tot",        c_uint32),
                ("max_states",        c_uint32),
                ("src_nodes",         c_uint32),
                ("max_src_nodes",     c_uint32),
                ("max_src_states",    c_uint32),
                ("max_src_conn",      c_uint32),
                ("max_src_conn_rate", _conn_rate),
                ("qid",               c_uint32),
                ("pqid",              c_uint32),
                ("rt_listid",         c_uint32),
                ("nr",                c_uint32),
                ("prob",              c_uint32),
                ("cuid",              c_uint32),      # uid_t
                ("cpid",              c_int32),       # pid_t
                ("return_icmp",       c_uint16),
                ("return_icmp6",      c_uint16),
                ("max_mss",           c_uint16),
                ("tag",               c_uint16),
                ("match_tag",         c_uint16),
                ("scrub_flags",       c_uint16),
                ("uid",               pf_rule_uid),
                ("gid",               pf_rule_gid),
                ("rule_flag",         c_uint32),
                ("action",            c_uint8),
                ("direction",         c_uint8),
                ("log",               c_uint8),
                ("logif",             c_uint8),
                ("quick",             c_uint8),
                ("ifnot",             c_uint8),
                ("match_tag_not",     c_uint8),
                ("keep_state",        c_uint8),
                ("af",                c_uint8),       # sa_family_t
                ("proto",             c_uint8),
                ("type",              c_uint8),
                ("code",              c_uint8),
                ("flags",             c_uint8),
                ("flagset",           c_uint8),
                ("min_ttl",           c_uint8),
                ("allow_opts",        c_uint8),
                ("rt",                c_uint8),
                ("return_ttl",        c_uint8),
                ("tos",               c_uint8),
                ("set_tos",           c_uint8),
                ("anchor_relative",   c_uint8),
                ("anchor_wildcard",   c_uint8),
                ("flush",             c_uint8),
                ("set_prio",          c_uint8 * 2),
                ("naf",               c_uint8),       # sa_family_t
                ("rcvifnot",          c_uint8),
                ("pad",               c_uint8 * 3),
                ("divert",            _divert),
                ("divert_packet",     _divert)]


class pfioc_rule(BufferStructure):      # From /usr/include/net/pfvar.h
    _fields_ = [("action",            c_uint32),
                ("ticket",            c_uint32),
                ("nr",                c_uint32),
                ("anchor",            c_char * MAXPATHLEN),
                ("anchor_call",       c_char * MAXPATHLEN),
                ("rule",              pf_rule)]


class pfioc_trans_e(Structure):         # From /usr/include/net/pfvar.h
    _fields_ = [("type",              c_int),
                ("anchor",            c_char * MAXPATHLEN),
                ("ticket",            c_uint32)]


class pfioc_trans(BufferStructure):     # From /usr/include/net/pfvar.h
    _fields_ = [("size",              c_int),
                ("esize",             c_int),
                ("array",             c_void_p)]      # struct pfioc_trans_e *


class pfr_addr(Structure):              # From /usr/include/net/pfvar.h
    class _pfra_u(Union):
        _fields_ = [("pfra_ip4addr",  c_uint32),      # struct in_addr
                    ("pfra_ip6addr",  c_uint32 * 4)]  # struct in6_addr

    _fields_ = [("pfra_u",            _pfra_u),
                ("pfra_ifname",       c_char * IFNAMSIZ),
                ("pfra_states",       c_uint32),
                ("pfra_weight",       c_uint16),
                ("pfra_af",           c_uint8),
                ("pfra_net",          c_uint8),
                ("pfra_not",          c_uint8),
                ("pfra_fback",        c_uint8),
                ("pfra_type",         c_uint8),
                ("pad",               c_uint8 * 7)]
    _anonymous_ = ("pfra_u",)


class pfr_table(Structure):             # From /usr/include/net/pfvar.h
    _fields_ = [("pfrt_anchor",       c_char * MAXPATHLEN),
                ("pfrt_name",         c_char * PF_TABLE_NAME_SIZE),
                ("pfrt_flags",        c_uint32),
                ("pfrt_fback",        c_uint8)]


class pfioc_table(BufferStructure):     # From /usr/include/net/pfvar.h
    _fields_ = [("pfrio_table",       pfr_table),
                ("pfrio_buffer",      c_void_p),
                ("pfrio_esize",       c_int),
                ("pfrio_size",        c_int),
                ("pfrio_size2",       c_int),
                ("pfrio_nadd",        c_int),
                ("pfrio_ndel",        c_int),
                ("pfrio_nchange",     c_int),
                ("pfrio_flags",       c_int),
                ("pfrio_ticket",      c_uint32)]


class pfr_tstats(Structure):            # From /usr/include/net/pfvar.h
    _fields_ = [("pfrts_t",           pfr_table),
                ("pfrts_packets",    c_uint64 * PFR_OP_TABLE_MAX * PFR_DIR_MAX),
                ("pfrts_bytes",      c_uint64 * PFR_OP_TABLE_MAX * PFR_DIR_MAX),
                ("pfrts_match",       c_uint64),
                ("pfrts_nomatch",     c_uint64),
                ("pfrts_tzero",       c_int64),         # time_t
                ("pfrts_cnt",         c_int),
                ("pfrts_refcnt",      c_int * PFR_REFCNT_MAX)]


class pfi_kif(Structure):               # From /usr/include/net/pfvar.h
    class _RB_ENTRY(Structure):
        _fields_ = [("rbe_left",      c_void_p),
                    ("rbe_right",     c_void_p),
                    ("rbe_parent",    c_void_p),
                    ("rbe_color",     c_int)]

    _fields_ = [("pfik_name",         c_char * IFNAMSIZ),
                ("pfik_tree",         _RB_ENTRY),
                ("pfik_packets",      c_uint64 * 2 * 2 * 2),
                ("pfik_bytes",        c_uint64 * 2 * 2 * 2),
                ("pfik_tzero",        c_int64),       # time_t
                ("pfik_flags",        c_int),
                ("pfik_flags_new",    c_int),
                ("pfik_ah_cookie",    c_void_p),
                ("pfik_ifp",          c_void_p),      # (struct ifnet *)
                ("pfik_group",        c_void_p),      # (struct ifg_group *)
                ("pfik_states",       c_int),
                ("pfik_rules",        c_int),
                ("pfik_routes",       c_int),
                ("pfik_dynaddrs",     c_void_p * 2)]  # TAILQ_HEAD(,pfi_dynaddr)


class pfioc_iface(BufferStructure):     # From /usr/include/net/pfvar.h
    _fields_ = [("pfiio_name",        c_char * IFNAMSIZ),
                ("pfiio_buffer",      c_void_p),
                ("pfiio_esize",       c_int),
                ("pfiio_size",        c_int),
                ("pfiio_nzero",       c_int),
                ("pfiio_flags",       c_int)]


class timeval(Structure):               # From /usr/include/sys/time.h
    _fields_ = [("tv_sec",            c_int64),       # time_t
                ("tv_usec",           c_long)]        # suseconds_t


class pf_queue_bwspec(Structure):       # From /usr/include/net/pfvar.h
    _fields_ = [("absolute",          c_uint),
                ("percent",           c_uint)]


class pf_queue_scspec(Structure):       # From /usr/include/net/pfvar.h
    _fields_ = [("m1",                pf_queue_bwspec),
                ("m2",                pf_queue_bwspec),
                ("d",                 c_uint)]


class pf_queuespec(Structure):          # From /usr/include/net/pfvar.h
    _fields_ = [("entries",           c_void_p * 2), # TAILQ_ENTRY(pf_queuespec)
                ("qname",             c_char * PF_QNAME_SIZE),
                ("parent",            c_char * PF_QNAME_SIZE),
                ("ifname",            c_char * IFNAMSIZ),
                ("realtime",          pf_queue_scspec),
                ("linkshare",         pf_queue_scspec),
                ("upperlimit",        pf_queue_scspec),
                ("kif",               c_void_p),      # struct pfi_kif *
                ("flags",             c_uint),
                ("qlimit",            c_uint),
                ("qid",               c_uint32),
                ("parent_qid",        c_uint32)]


class pfioc_qstats(BufferStructure):    # From /usr/include/net/pfvar.h
    _fields_ = [("ticket",            c_uint32),
                ("nr",                c_uint32),
                ("queue",             pf_queuespec),
                ("buf",               c_void_p),
                ("nbytes",            c_int)]


class pfioc_queue(Structure):           # From /usr/include/net/pfvar.h
    _fields_ = [("ticket",            c_uint32),
                ("nr",                c_uint),
                ("queue",             pf_queuespec)]


class service_curve(Structure):         # From /usr/include/altq/altq_hfsc.h
    _fields_ = [("m1",                c_uint),
                ("d",                 c_uint),
                ("m2",                c_uint)]


class pktcntr(Structure):               # From /usr/include/altq/altq.h
    _fields_ = [("packets",           c_uint64),
                ("bytes",             c_uint64)]


class redstats(Structure):              # From /usr/include/altq/altq_red.h
    _fields_ = [("q_avg",             c_int),
                ("xmit_cnt",          pktcntr),
                ("drop_cnt",          pktcntr),
                ("drop_forced",       c_uint),
                ("drop_unforced",     c_uint),
                ("marked_packets",    c_uint)]


class class_stats_t(Structure):         # From /usr/include/altq/altq_cbq.h
    _fields_ = [("handle",            c_uint32),
                ("depth",             c_uint),
                ("xmit_cnt",          pktcntr),
                ("drop_cnt",          pktcntr),
                ("over",              c_uint), 
                ("borrows",           c_uint),
                ("overactions",       c_uint),
                ("delays",            c_uint),
                ("priority",          c_int),
                ("maxidle",           c_int),
                ("minidle",           c_int),
                ("offtime",           c_int),
                ("qmax",              c_int),
                ("ns_per_byte",       c_int),
                ("wrr_allot",         c_int),
                ("qcnt",              c_int),
                ("avgidle",           c_int),
                ("qtype",             redstats * 3)]


class priq_classstats(Structure):       # From /usr/include/altq/altq_priq.h
    _fields_ = [("class_handle",      c_uint32),
                ("qlength",           c_uint),
                ("qlimit",            c_uint),
                ("period",            c_uint),
                ("xmitcnt",           pktcntr),
                ("dropcnt",           pktcntr),
                ("qtype",             c_int),
                ("red",               redstats * 3)]


class hfsc_classstats(Structure):       # From /usr/include/altq/altq_hfsc.h
    _fields_ = [("class_id",          c_uint),
                ("class_handle",      c_uint32),
                ("rsc",               service_curve),
                ("fsc",               service_curve),
                ("usc",               service_curve),
                ("total",             c_uint64),
                ("cumul",             c_uint64),
                ("d",                 c_uint64),
                ("e",                 c_uint64),
                ("vt",                c_uint64),
                ("f",                 c_uint64),
                ("initvt",            c_uint64),
                ("vtoff",             c_uint64),
                ("cvtmax",            c_uint64),
                ("myf",               c_uint64),
                ("cfmin",             c_uint64),
                ("cvtmin",            c_uint64),
                ("myfadj",            c_uint64),
                ("vtadj",             c_uint64),
                ("cur_time",          c_uint64),
                ("machclk_freq",      c_uint32),
                ("qlength",           c_uint),
                ("qlimit",            c_uint),
                ("xmit_cnt",          pktcntr),
                ("drop_cnt",          pktcntr),
                ("period",            c_uint),
                ("vtperiod",          c_uint),
                ("parentperiod",      c_uint),
                ("nactive",           c_int),
                ("qtype",             c_int),
                ("red",               redstats * 3)]


class class_stats(Union):             # From /usr/include/pfctl/pfctl_qstats.c
    _fields_ = [("cbq_stats",         class_stats_t),
                ("priq_stats",        priq_classstats),
                ("hfsc_stats",        hfsc_classstats)]


class queue_stats(Structure):         # From /usr/src/sbin/pfctl/pfctl_qstats.c
    _fields_ = [("data",              class_stats),
                ("avgn",              c_int),
                ("avg_bytes",         c_double),
                ("avg_packets",       c_double),
                ("prev_bytes",        c_uint64),
                ("prev_packets",      c_uint64)]


class ifreq(BufferStructure):           # From /usr/include/net/if.h
    class _ifr_ifru(Union):
        class _sockaddr(Structure):     # From /usr/include/sys/socket.h
            _fields_ = [("sa_len",    c_uint8),
                        ("sa_family", c_uint8),       # sa_family_t
                        ("sa_data",   c_char * 14)]

        _fields_ = [("ifru_addr",     _sockaddr),
                    ("ifru_dstaddr",  _sockaddr),
                    ("ifru_broadaddr", _sockaddr),
                    ("ifru_flags",    c_short),
                    ("ifru_metric",   c_int),
                    ("ifru_data",     c_char_p)]      # caddr_t

    _fields_ = [("ifr_name",          c_char * IFNAMSIZ),
                ("ifr_ifru",          _ifr_ifru)]
    _anonymous_ = ("ifr_ifru",)


class if_data(Structure):               # From /usr/include/net/if.h
    _MCLPOOLS = 7

    class _mclpool(Structure):          # From /usr/include/net/if.h
        _fields_ = [("mcl_grown",    c_uint),
                    ("mcl_alive",    c_ushort),
                    ("mcl_hwm",      c_ushort),
                    ("mcl_cwm",      c_ushort),
                    ("mcl_lwm",      c_ushort)]

    _fields_ = [("ifi_type",         c_ubyte),
                ("ifi_addrlen",      c_ubyte),
                ("ifi_hdrlen",       c_ubyte),
                ("ifi_link_state",   c_ubyte),
                ("ifi_mtu",          c_uint32),
                ("ifi_metric",       c_uint32),
                ("ifi_pad",          c_uint32),
                ("ifi_baudrate",     c_uint64),
                ("ifi_ipackets",     c_uint64),
                ("ifi_ierrors",      c_uint64),
                ("ifi_opackets",     c_uint64),
                ("ifi_oerrors",      c_uint64),
                ("ifi_collisions",   c_uint64),
                ("ifi_ibytes",       c_uint64),
                ("ifi_obytes",       c_uint64),
                ("ifi_imcasts",      c_uint64),
                ("ifi_omcasts",      c_uint64),
                ("ifi_iqdrops",      c_uint64),
                ("ifi_noproto",      c_uint64),
                ("ifi_capabilities", c_uint32),
                ("ifi_lastchange",   timeval),
                ("ifi_mclpool",      _mclpool * _MCLPOOLS)]
