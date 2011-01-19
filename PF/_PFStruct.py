"""Mapping of C structs, required by ioctl() calls, to ctypes."""


from ctypes import *

from PFConstants import *

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
           'pfioc_iface',
           'pf_altq',
           'pfioc_altq']


# Constants ####################################################################
IFNAMSIZ             = 16
PFRES_MAX            = 15
LCNT_MAX             = 7
FCNT_MAX             = 3
SCNT_MAX             = 3
PF_MD5_DIGEST_LENGTH = 16
PF_TABLE_NAME_SIZE   = 32
PF_RULE_LABEL_SIZE   = 64
RTLABEL_LEN          = 32
MAXPATHLEN           = 1024
PF_SKIP_COUNT        = 8
PF_RULE_LABEL_SIZE   = 64
PF_QNAME_SIZE        = 64
PF_TAG_NAME_SIZE     = 64


# BufferStructure Class ########################################################
class BufferStructure(Structure):
    """A subclass of ctypes.Structure to simplify ioctl() system calls."""

    def __init__(self, **kw):
        """Call the parent constructor."""
        super(BufferStructure, self).__init__(**kw)

    def asBuffer(self):
        """Return a buffer pointing to the Structure.

        This allows ioctl() to write directly to the structure, even if bigger
        than 1024 bytes.
        """
        return (c_char * sizeof(self)).from_address(addressof(self))


# Structures ###################################################################
class pfioc_limit(BufferStructure):
    _fields_ = [("index",             c_int),
                ("limit",             c_uint)]

class pfioc_tm(BufferStructure):
    _fields_ = [("timeout",           c_int),
                ("seconds",           c_int)]


class pf_status(BufferStructure):
    _fields_ = [("counters",          c_uint64 * PFRES_MAX),
                ("lcounters",         c_uint64 * LCNT_MAX),
                ("fcounters",         c_uint64 * FCNT_MAX),
                ("scounters",         c_uint64 * SCNT_MAX),
                ("pcounters",         c_uint64 * 3 * 2 * 2),
                ("bcounters",         c_uint64 * 2 * 2),
                ("stateid",           c_uint64),
                ("running",           c_uint32),
                ("states",            c_uint32),
                ("src_nodes",         c_uint32),
                ("since",             c_uint32),
                ("debug",             c_uint32),
                ("hostid",            c_uint32),
                ("reass",             c_uint32),
                ("ifname",            c_char * IFNAMSIZ),
                ("pf_chksum",         c_uint8 * PF_MD5_DIGEST_LENGTH)]


class pf_addr(Structure):
    class _pfa(Union):
        _fields_ = [("v4",            c_uint32),
                    ("v6",            c_uint32 * 4),
                    ("addr8",         c_uint8 * 16),
                    ("addr16",        c_uint16 * 8),
                    ("addr32",        c_uint32 * 4)]

    _fields_ = [("pfa",               _pfa)]
    _anonymous_ = ("pfa",)

class pf_addr_wrap(Structure):
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

class pf_rule_addr(Structure):
    _fields_ = [("addr",              pf_addr_wrap),
                ("port",              c_uint16 * 2),
                ("neg",               c_uint8),
                ("port_op",           c_uint8)]


class pfsync_state_scrub(Structure):
    _fields_ = [("pfss_flags",        c_uint16),
                ("pfss_ttl",          c_uint8),
                ("scrub_flag",        c_uint8),
                ("pfss_ts_mod",       c_uint32)]

class pfsync_state_peer(Structure):
    _fields_ = [("scrub",             pfsync_state_scrub),
                ("seqlo",             c_uint32),
                ("seqhi",             c_uint32),
                ("seqdiff",           c_uint32),
                ("max_win",           c_uint16),
                ("mss",               c_uint16),
                ("state",             c_uint8),
                ("wscale",            c_uint8),
                ("pad",               c_uint8 * 6)]

class pfsync_state_key(Structure):
    _fields_ = [("addr",              pf_addr * 2),
                ("port",              c_uint16 * 2),
                ("rdomain",           c_uint16),
                ("pad",               c_uint8 * 2)]

class pfsync_state(Structure):
    _fields_ = [("id",                c_uint32 * 2),
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
                ("af",                c_uint8),
                ("proto",             c_uint8),
                ("direction",         c_uint8),
                ("log",               c_uint8),
                ("state_flags",       c_uint8),
                ("timeout",           c_uint8),
                ("sync_flags",        c_uint8),
                ("updates",           c_uint8),
                ("min_ttl",           c_uint8),
                ("set_tos",           c_uint8),
                ("pad",               c_uint8 * 4)]

class pfioc_states(BufferStructure):
    class _ps_u(Union):
        _fields_ = [("ps_buf",        c_void_p),
                    ("ps_states",     c_void_p)]      # (struct pfsync_state *)

    _fields_ = [("ps_len",            c_int),
                ("ps_u",              _ps_u)]
    _anonymous_ =  ("ps_u",)

class pf_state_cmp(Structure):
    _fields_ = [("id",                c_uint64),
                ("creatorid",         c_uint32),
                ("direction",         c_uint8),
                ("pad",               c_uint8 * 3)]

class pfioc_state_kill(BufferStructure):
    _fields_ = [("psk_pfcmp",         pf_state_cmp),
                ("psk_af",            c_uint8),
                ("psk_proto",         c_int),
                ("psk_src",           pf_rule_addr),
                ("psk_dst",           pf_rule_addr),
                ("psk_ifname",        c_char * IFNAMSIZ),
                ("psk_label",         c_char * PF_RULE_LABEL_SIZE),
                ("psk_killed",        c_uint),
                ("psk_rdomain",       c_uint16)]


class pf_poolhashkey(Structure):
    class _pfk(Union):
        _fields_ = [("key8",          c_uint8 * 16),
                    ("key16",         c_uint16 * 8),
                    ("key32",         c_uint32 * 4)]

    _fields_ = [("pfk",               _pfk)]
    _anonymous_ = ("pfk",)

class pf_pool(Structure):
    _fields_ = [("addr",              pf_addr_wrap),
                ("key",               pf_poolhashkey),
                ("counter",           pf_addr),
                ("ifname",            c_char * IFNAMSIZ),
                ("kif",               c_void_p),      # (struct pfi_kif *)
                ("tblidx",            c_int),
                ("proxy_port",        c_uint16 * 2),
                ("port_op",           c_uint8),
                ("opts",              c_uint8)]

class pf_rule_ptr(Union):
    _fields_ = [("ptr",               c_void_p),      # (struct pf_rule *)
                ("nr",                c_uint32)]

class pf_rule_uid(Structure):
    _fields_ = [("uid",               c_uint32 * 2),
                ("op",                c_uint8)]

class pf_rule_gid(Structure):
    _fields_ = [("gid",               c_uint32 * 2),
                ("op",                c_uint8)]

class pf_rule(Structure):
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
                ("overload_tbl",      c_void_p),      # (struct pfr_table *)
                ("os_fingerprint",    c_uint32),
                ("rtableid",          c_int),
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
                ("cuid",              c_uint32),
                ("cpid",              c_int32),
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
                ("af",                c_uint8),
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
                ("pad2",              c_uint8 * 3),
                ("divert",            _divert),
                ("divert_packet",     _divert)]

class pfioc_rule(BufferStructure):
    _fields_ = [("action",            c_uint32),
                ("ticket",            c_uint32),
                ("nr",                c_uint32),
                ("anchor",            c_char * MAXPATHLEN),
                ("anchor_call",       c_char * MAXPATHLEN),
                ("rule",              pf_rule)]

class pfioc_trans_e(Structure):
    _fields_ = [("type",              c_int),
                ("anchor",            c_char * MAXPATHLEN),
                ("ticket",            c_uint32)]

class pfioc_trans(BufferStructure):
    _fields_ = [("size",              c_int),
                ("esize",             c_int),
                ("array",             c_void_p)]      # (struct pfioc_trans_e *)

class pfr_addr(Structure):
    class _pfra_u(Union):
        _fields_ = [("pfra_ip4addr",  c_uint32),
                    ("pfra_ip6addr",  c_uint32 * 4)]

    _fields_ = [("pfra_u",            _pfra_u),
                ("pfra_ifname",       c_char * IFNAMSIZ),
                ("pfra_af",           c_uint8),
                ("pfra_net",          c_uint8),
                ("pfra_not",          c_uint8),
                ("pfra_fback",        c_uint8),
                ("pfra_type",         c_uint8),
                ("pad",               c_uint8 * 7)]
    _anonymous_ = ("pfra_u",)

class pfr_table(Structure):
    _fields_ = [("pfrt_anchor",       c_char * MAXPATHLEN),
                ("pfrt_name",         c_char * PF_TABLE_NAME_SIZE),
                ("pfrt_flags",        c_uint32),
                ("pfrt_fback",        c_uint8)]

class pfioc_table(BufferStructure):
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

class pfr_tstats(Structure):
    _fields_ = [("pfrts_t",           pfr_table),
                ("pfrts_packets",     c_uint64 * PFR_OP_TABLE_MAX * PFR_DIR_MAX),
                ("pfrts_bytes",       c_uint64 * PFR_OP_TABLE_MAX * PFR_DIR_MAX),
                ("pfrts_match",       c_uint64),
                ("pfrts_nomatch",     c_uint64),
                ("pfrts_tzero",       c_long),
                ("pfrts_cnt",         c_int),
                ("pfrts_refcnt",      c_int * PFR_REFCNT_MAX)]

class pfioc_iface(BufferStructure):
    _fields_ = [("pfiio_name",        c_char * IFNAMSIZ),
                ("pfiio_buffer",      c_void_p),
                ("pfiio_esize",       c_int),
                ("pfiio_size",        c_int),
                ("pfiio_nzero",       c_int),
                ("pfiio_flags",       c_int)]

class pf_altq(Structure):
    class pq_u(Union):
        class cbq_opts(Structure):
            _fields_ = [("minburst",  c_uint),
                        ("maxburst",  c_uint),
                        ("pktsize",   c_uint),
                        ("maxpktsize", c_uint),
                        ("ns_per_byte", c_uint),
                        ("maxidle",   c_uint),
                        ("minidle",   c_int),
                        ("offtime",   c_uint),
                        ("flags",     c_int)]

        class priq_opts(Structure):
            _fields_ = [("flags",     c_int)]

        class hfsc_opts(Structure):
            _fields_ = [("rtsc_m1",   c_uint),
                        ("rtsc_d",    c_uint),
                        ("rtsc_m2",   c_uint),
                        ("lssc_m1",   c_uint),
                        ("lssc_d",    c_uint),
                        ("lssc_m2",   c_uint),
                        ("ulsc_m1",   c_uint),
                        ("ulsc_d",    c_uint),
                        ("ulsc_m2",   c_uint),
                        ("flags",     c_int)]

        _fields_ = [("cbq_opts",      cbq_opts),
                    ("priq_opts",     priq_opts),
                    ("hfsc_opts",     hfsc_opts)]

    _fields_ = [("ifname",            c_char * IFNAMSIZ),
                ("altq_disc",         c_void_p),
                ("entries",           c_void_p * 2),  # TAILQ_ENTRY(pf_altq)
                ("scheduler",         c_uint8),
                ("tbrsize",           c_uint16),
                ("ifbandwidth",       c_uint32),
                ("qname",             c_char * PF_QNAME_SIZE),
                ("parent",            c_char * PF_QNAME_SIZE),
                ("parent_qid",        c_uint32),
                ("bandwidth",         c_uint32),
                ("priority",          c_uint8),
                ("qlimit",            c_uint16),
                ("flags",             c_uint16),
                ("pq_u",              pq_u),
                ("qid",               c_uint32)]

class pfioc_altq(BufferStructure):
    _fields_ = [("action",            c_uint32),
                ("ticket",            c_uint32),
                ("nr",                c_uint32),
                ("altq",              pf_altq)]
