//! Port of params.h / params.c: desync profiles and global parameters.
//! Config is plain data filled while parsing the command line; runtime state that Lua
//! callbacks touch lives in RefCells so re-entrant calls never alias a borrow.

use crate::conntrack::Conntrack;
use crate::dlog_err;
use crate::pools::{
    Blobs, FuncItem, HostFailPool, HostlistCollection, HostlistFileRef, HostlistFiles, IcmpFilters,
    IpCache, IppFilters, IpsetCollection, IpsetFiles, PortFilters,
};
use crate::protocol::L7P_NONE;
use crate::timer::TimerPool;
use std::cell::{Cell, RefCell};
use std::rc::Rc;

pub const Q_MAXLEN: u32 = 4096;
pub const Q_RCVBUF: i32 = 1024 * 1024;
pub const HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT: i32 = 3;
pub const HOSTLIST_AUTO_FAIL_TIME_DEFAULT: i32 = 60;
pub const HOSTLIST_AUTO_RETRANS_THRESHOLD_DEFAULT: i32 = 3;
pub const HOSTLIST_AUTO_RETRANS_MAXSEQ: u32 = 32768;
pub const HOSTLIST_AUTO_INCOMING_MAXSEQ: u32 = 4096;
pub const HOSTLIST_AUTO_UDP_OUT: i32 = 4;
pub const HOSTLIST_AUTO_UDP_IN: i32 = 1;
pub const IPCACHE_LIFETIME: u32 = 7200;
pub const MAX_GIDS: usize = 64;
pub const MAX_BLOB_SIZE: usize = 16 * 1024;
pub const BLOB_EXTRA_BYTES: usize = 128;
pub const DEFAULT_MSS: u16 = 1220;
pub const RECONSTRUCT_MAX_SIZE: usize = 65536;
pub const LUA_GC_INTERVAL: u64 = 60;
pub const DPI_DESYNC_FWMARK_DEFAULT: u32 = 0x40000000;
pub const LUA_COMPAT_VER: u32 = 6;
pub const PROGNAME: &str = "nfqws2";

pub const FAKE_HTTP_REQUEST_DEFAULT: &str = "GET / HTTP/1.1\r\nHost: www.iana.org\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate, br\r\n\r\n";

pub static FAKE_TLS_CLIENTHELLO_DEFAULT: [u8; 680] = [
    0x16, 0x03, 0x01, 0x02, 0xa3, 0x01, 0x00, 0x02, 0x9f, 0x03, 0x03, 0x41, 0x88, 0x82, 0x2d, 0x4f,
    0xfd, 0x81, 0x48, 0x9e, 0xe7, 0x90, 0x65, 0x1f, 0xba, 0x05, 0x7b, 0xff, 0xa7, 0x5a, 0xf9, 0x5b,
    0x8a, 0x8f, 0x45, 0x8b, 0x41, 0xf0, 0x3d, 0x1b, 0xdd, 0xe3, 0xf8, 0x20, 0x9b, 0x23, 0xa5, 0xd2,
    0x21, 0x1e, 0x9f, 0xe7, 0x85, 0x6c, 0xfc, 0x61, 0x80, 0x3a, 0x3f, 0xba, 0xb9, 0x60, 0xba, 0xb3,
    0x0e, 0x98, 0x27, 0x6c, 0xf7, 0x38, 0x28, 0x65, 0x80, 0x5d, 0x40, 0x38, 0x00, 0x22, 0x13, 0x01,
    0x13, 0x03, 0x13, 0x02, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x2c, 0xc0, 0x30,
    0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35,
    0x01, 0x00, 0x02, 0x34, 0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x00, 0x00, 0x11, 0x77, 0x77, 0x77,
    0x2e, 0x6d, 0x69, 0x63, 0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x17,
    0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x1d, 0x00,
    0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74,
    0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22,
    0x00, 0x0a, 0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x00, 0x12, 0x00, 0x00,
    0x00, 0x33, 0x00, 0x6b, 0x00, 0x69, 0x00, 0x1d, 0x00, 0x20, 0x69, 0x15, 0x16, 0x29, 0x6d, 0xad,
    0xd5, 0x68, 0x88, 0x27, 0x2f, 0xde, 0xaf, 0xac, 0x3c, 0x4c, 0xa4, 0xe4, 0xd8, 0xc8, 0xfb, 0x41,
    0x87, 0xf4, 0x76, 0x4e, 0x0e, 0xfa, 0x64, 0xc4, 0xe9, 0x29, 0x00, 0x17, 0x00, 0x41, 0x04, 0xfe,
    0x62, 0xb9, 0x08, 0xc8, 0xc3, 0x2a, 0xb9, 0x87, 0x37, 0x84, 0x42, 0x6b, 0x5c, 0xcd, 0xc9, 0xca,
    0x62, 0x38, 0xd3, 0xd9, 0x99, 0x8a, 0xc4, 0x2d, 0xc6, 0xd0, 0xa3, 0x60, 0xb2, 0x12, 0x54, 0x41,
    0x8e, 0x52, 0x5e, 0xe3, 0xab, 0xf9, 0xc2, 0x07, 0x81, 0xdc, 0xf8, 0xf2, 0x6a, 0x91, 0x40, 0x2f,
    0xcb, 0xa4, 0xff, 0x6f, 0x24, 0xc7, 0x4d, 0x77, 0x77, 0x2d, 0x6f, 0xe0, 0x77, 0xaa, 0x92, 0x00,
    0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x0d, 0x00, 0x18, 0x00, 0x16, 0x04, 0x03,
    0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
    0x02, 0x03, 0x02, 0x01, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01,
    0x00, 0x1b, 0x00, 0x07, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0xfe, 0x0d, 0x01, 0x19, 0x00,
    0x00, 0x01, 0x00, 0x03, 0x21, 0x00, 0x20, 0x62, 0xe8, 0x83, 0xd8, 0x97, 0x05, 0x8a, 0xbe, 0xa1,
    0xf2, 0x63, 0x4e, 0xce, 0x93, 0x84, 0x8e, 0xcf, 0xe7, 0xdd, 0xb2, 0xe4, 0x87, 0x06, 0xac, 0x11,
    0x19, 0xbe, 0x0e, 0x71, 0x87, 0xf1, 0xa6, 0x00, 0xef, 0xd8, 0x6b, 0x27, 0x5e, 0xc0, 0xa7, 0x5d,
    0x42, 0x4e, 0x8c, 0xdc, 0xf3, 0x9f, 0x1c, 0x51, 0x62, 0xef, 0xff, 0x5b, 0xed, 0xc8, 0xfd, 0xee,
    0x6f, 0xbb, 0x88, 0x9b, 0xb1, 0x30, 0x9c, 0x66, 0x42, 0xab, 0x0f, 0x66, 0x89, 0x18, 0x8b, 0x11,
    0xc1, 0x6d, 0xe7, 0x2a, 0xeb, 0x96, 0x3b, 0x7f, 0x52, 0x78, 0xdb, 0xf8, 0x6d, 0x04, 0xf7, 0x95,
    0x1a, 0xa8, 0xf0, 0x64, 0x52, 0x07, 0x39, 0xf0, 0xa8, 0x1d, 0x0d, 0x16, 0x36, 0xb7, 0x18, 0x0e,
    0xc8, 0x44, 0x27, 0xfe, 0xf3, 0x31, 0xf0, 0xde, 0x8c, 0x74, 0xf5, 0xa1, 0xd8, 0x8f, 0x6f, 0x45,
    0x97, 0x69, 0x79, 0x5e, 0x2e, 0xd4, 0xb0, 0x2c, 0x0c, 0x1a, 0x6f, 0xcc, 0xce, 0x90, 0xc7, 0xdd,
    0xc6, 0x60, 0x95, 0xf3, 0xc2, 0x19, 0xde, 0x50, 0x80, 0xbf, 0xde, 0xf2, 0x25, 0x63, 0x15, 0x26,
    0x63, 0x09, 0x1f, 0xc5, 0xdf, 0x32, 0xf5, 0xea, 0x9c, 0xd2, 0xff, 0x99, 0x4e, 0x67, 0xa2, 0xe5,
    0x1a, 0x94, 0x85, 0xe3, 0xdf, 0x36, 0xa5, 0x83, 0x4b, 0x0a, 0x1c, 0xaf, 0xd7, 0x48, 0xc9, 0x4b,
    0x8a, 0x27, 0xdd, 0x58, 0x7f, 0x95, 0xf2, 0x6b, 0xde, 0x2b, 0x12, 0xd3, 0xec, 0x4d, 0x69, 0x37,
    0x9c, 0x13, 0x9b, 0x16, 0xb0, 0x45, 0x52, 0x38, 0x77, 0x69, 0xef, 0xaa, 0x65, 0x19, 0xbc, 0xc2,
    0x93, 0x4d, 0xb0, 0x1b, 0x7f, 0x5b, 0x41, 0xff, 0xaf, 0xba, 0x50, 0x51, 0xc3, 0xf1, 0x27, 0x09,
    0x25, 0xf5, 0x60, 0x90, 0x09, 0xb1, 0xe5, 0xc0, 0xc7, 0x42, 0x78, 0x54, 0x3b, 0x23, 0x19, 0x7d,
    0x8e, 0x72, 0x13, 0xb4, 0xd3, 0xcd, 0x63, 0xb6, 0xc4, 0x4a, 0x28, 0x3d, 0x45, 0x3e, 0x8b, 0xdb,
    0x84, 0x4f, 0x78, 0x64, 0x30, 0x69, 0xe2, 0x1b,
];

#[derive(Clone, Debug)]
pub struct DesyncProfile {
    pub n: u32,
    pub name: Option<String>,
    pub cookie: Option<String>,
    pub filter_ipv4: bool,
    pub filter_ipv6: bool,
    pub pf_tcp: PortFilters,
    pub pf_udp: PortFilters,
    pub icf: IcmpFilters,
    pub ipf: IppFilters,
    pub filter_l7: u64,
    /// LIST_INSERT_HEAD order
    pub filter_ssid: Vec<String>,
    pub filter_ssid_neg: bool,
    pub filter_mark: u32,
    pub filter_mark_mask: u32,
    pub ips_collection: IpsetCollection,
    pub ips_collection_exclude: IpsetCollection,
    pub hl_collection: HostlistCollection,
    pub hl_collection_exclude: HostlistCollection,
    pub hostlist_auto: Option<HostlistFileRef>,
    pub hostlist_auto_fail_threshold: i32,
    pub hostlist_auto_fail_time: i32,
    pub hostlist_auto_retrans_threshold: i32,
    pub hostlist_auto_udp_in: i32,
    pub hostlist_auto_udp_out: i32,
    pub hostlist_auto_retrans_maxseq: u32,
    pub hostlist_auto_incoming_maxseq: u32,
    pub hostlist_auto_retrans_reset: bool,
    pub hostlist_auto_fail_counters: HostFailPool,
    pub hostlist_auto_last_purge: i64,
    /// tail inserted
    pub lua_desync: Vec<FuncItem>,
    pub b_hostlist_auto_fail_threshold: bool,
    pub b_hostlist_auto_fail_time: bool,
    pub b_hostlist_auto_retrans_threshold: bool,
    pub b_hostlist_auto_retrans_maxseq: bool,
    pub b_hostlist_auto_incoming_maxseq: bool,
    pub b_hostlist_auto_retrans_reset: bool,
    pub b_hostlist_auto_udp_out: bool,
    pub b_hostlist_auto_udp_in: bool,
    pub b_filter_l3: bool,
    pub b_filter_l7: bool,
}

pub const FASTPATH_WORKAROUND_OFF: u8 = 0;
pub const FASTPATH_WORKAROUND_ON: u8 = 1;
pub const FASTPATH_WORKAROUND_AUTO: u8 = 2;

pub type ProfileRef = Rc<RefCell<DesyncProfile>>;

impl Default for DesyncProfile {
    fn default() -> Self {
        DesyncProfile {
            n: 0,
            name: None,
            cookie: None,
            filter_ipv4: false,
            filter_ipv6: false,
            pf_tcp: PortFilters::default(),
            pf_udp: PortFilters::default(),
            icf: IcmpFilters::default(),
            ipf: IppFilters::default(),
            filter_l7: 0,
            filter_ssid: Vec::new(),
            filter_ssid_neg: false,
            filter_mark: 0,
            filter_mark_mask: 0,
            ips_collection: IpsetCollection::default(),
            ips_collection_exclude: IpsetCollection::default(),
            hl_collection: HostlistCollection::default(),
            hl_collection_exclude: HostlistCollection::default(),
            hostlist_auto: None,
            hostlist_auto_fail_threshold: HOSTLIST_AUTO_FAIL_THRESHOLD_DEFAULT,
            hostlist_auto_fail_time: HOSTLIST_AUTO_FAIL_TIME_DEFAULT,
            hostlist_auto_retrans_threshold: HOSTLIST_AUTO_RETRANS_THRESHOLD_DEFAULT,
            hostlist_auto_udp_in: HOSTLIST_AUTO_UDP_IN,
            hostlist_auto_udp_out: HOSTLIST_AUTO_UDP_OUT,
            hostlist_auto_retrans_maxseq: HOSTLIST_AUTO_RETRANS_MAXSEQ,
            hostlist_auto_incoming_maxseq: HOSTLIST_AUTO_INCOMING_MAXSEQ,
            hostlist_auto_retrans_reset: true,
            hostlist_auto_fail_counters: HostFailPool::default(),
            hostlist_auto_last_purge: 0,
            lua_desync: Vec::new(),
            b_hostlist_auto_fail_threshold: false,
            b_hostlist_auto_fail_time: false,
            b_hostlist_auto_retrans_threshold: false,
            b_hostlist_auto_retrans_maxseq: false,
            b_hostlist_auto_incoming_maxseq: false,
            b_hostlist_auto_retrans_reset: false,
            b_hostlist_auto_udp_out: false,
            b_hostlist_auto_udp_in: false,
            b_filter_l3: false,
            b_filter_l7: false,
        }
    }
}

impl DesyncProfile {
    pub fn name_str(&self) -> &str {
        self.name.as_deref().unwrap_or("noname")
    }
    pub fn ipsets_absent(&self) -> bool {
        self.ips_collection.0.is_empty() && self.ips_collection_exclude.0.is_empty()
    }
    pub fn ipsets_empty(&self) -> bool {
        self.ips_collection.is_empty_sets() && self.ips_collection_exclude.is_empty_sets()
    }
    pub fn hostlists_empty(&self) -> bool {
        self.hl_collection.is_empty_lists() && self.hl_collection_exclude.is_empty_lists()
    }

    /// dp_copy: apply a template.
    pub fn copy_from(&mut self, from: &DesyncProfile) -> bool {
        macro_rules! simple {
            ($v:ident, $b:ident) => {
                if from.$b {
                    self.$v = from.$v.clone();
                    self.$b = true;
                }
            };
        }
        simple!(hostlist_auto_fail_threshold, b_hostlist_auto_fail_threshold);
        simple!(hostlist_auto_fail_time, b_hostlist_auto_fail_time);
        simple!(
            hostlist_auto_retrans_threshold,
            b_hostlist_auto_retrans_threshold
        );
        simple!(hostlist_auto_retrans_maxseq, b_hostlist_auto_retrans_maxseq);
        simple!(
            hostlist_auto_incoming_maxseq,
            b_hostlist_auto_incoming_maxseq
        );
        simple!(hostlist_auto_retrans_reset, b_hostlist_auto_retrans_reset);
        simple!(hostlist_auto_udp_out, b_hostlist_auto_udp_out);
        simple!(hostlist_auto_udp_in, b_hostlist_auto_udp_in);
        simple!(filter_l7, b_filter_l7);
        if from.b_filter_l3 {
            if self.b_filter_l3 {
                self.filter_ipv4 |= from.filter_ipv4;
                self.filter_ipv6 |= from.filter_ipv6;
            } else {
                self.filter_ipv4 = from.filter_ipv4;
                self.filter_ipv6 = from.filter_ipv6;
                self.b_filter_l3 = true;
            }
        }
        if from.cookie.is_some() {
            self.cookie = from.cookie.clone();
        }
        if let Some(ha) = &from.hostlist_auto {
            let same = self
                .hostlist_auto
                .as_ref()
                .is_some_and(|t| Rc::ptr_eq(t, ha));
            if !same {
                if self.hostlist_auto.is_some() {
                    dlog_err!("autohostlist replacement is not supported\n");
                    return false;
                }
                self.hostlist_auto = Some(ha.clone());
            }
        }
        self.filter_ssid.extend(from.filter_ssid.iter().cloned());
        self.lua_desync.extend(from.lua_desync.iter().cloned());
        self.ips_collection.copy_from(&from.ips_collection);
        self.ips_collection_exclude
            .copy_from(&from.ips_collection_exclude);
        self.hl_collection.copy_from(&from.hl_collection);
        self.hl_collection_exclude
            .copy_from(&from.hl_collection_exclude);
        self.pf_tcp.0.extend(from.pf_tcp.0.iter().cloned());
        self.pf_udp.0.extend(from.pf_udp.0.iter().cloned());
        self.icf.0.extend(from.icf.0.iter().cloned());
        self.ipf.0.extend(from.ipf.0.iter().cloned());
        true
    }
}

/// Profile list (tail-inserted).
pub type ProfileList = Vec<ProfileRef>;

pub fn dp_list_search_name(l: &ProfileList, name: &str) -> Option<ProfileRef> {
    l.iter()
        .find(|p| p.borrow().name.as_deref() == Some(name))
        .cloned()
}
pub fn dp_list_have_autohostlist(l: &ProfileList) -> bool {
    l.iter().any(|p| p.borrow().hostlist_auto.is_some())
}

pub struct Params {
    pub verstr: String,
    pub daemon: bool,
    pub intercept: bool,
    pub fuzz: u32,
    pub qnum: i32,
    pub bind_fix4: bool,
    pub bind_fix6: bool,
    pub desync_fwmark: u32,
    pub desync_profiles: RefCell<ProfileList>,
    pub desync_templates: RefCell<ProfileList>,
    pub droproot: bool,
    pub user: Option<String>,
    pub uid: u32,
    pub gid: Vec<u32>,
    pub pidfile: String,
    pub hostlists: RefCell<HostlistFiles>,
    pub ipsets: RefCell<IpsetFiles>,
    pub blobs: RefCell<Blobs>,
    pub ctrack_t_syn: u32,
    pub ctrack_t_est: u32,
    pub ctrack_t_fin: u32,
    pub ctrack_t_udp: u32,
    pub conntrack: RefCell<Conntrack>,
    pub ctrack_disable: bool,
    pub server: bool,
    pub filter_ssid_present: bool,
    /// --fastpath-workaround (nfqws2-keenetic patch): 0 off, 1 on, 2 auto
    pub fastpath_workaround: u8,
    /// retransmissions during incomplete TLS reasm (process-wide, auto mode)
    pub fastpath_retrans_count: std::cell::Cell<u8>,
    pub cache_hostname: bool,
    pub ipcache_lifetime: u32,
    pub ipcache: RefCell<IpCache>,
    pub reasm_payload_disable: u64,
    pub payload_disable: u64,
    /// LIST_INSERT_HEAD? no: tail order as added by strlist_add_tail
    pub lua_init_scripts: Vec<String>,
    pub writable_dir_enable: bool,
    pub writable_dir: String,
    pub timers: RefCell<TimerPool>,
    pub timers_dirty: Cell<bool>,
    pub lua_gc: u64,
}

impl Default for Params {
    fn default() -> Self {
        let can_drop = crate::sec::can_drop_root();
        Params {
            verstr: String::new(),
            daemon: false,
            intercept: true,
            fuzz: 0,
            qnum: -1,
            bind_fix4: false,
            bind_fix6: false,
            desync_fwmark: DPI_DESYNC_FWMARK_DEFAULT,
            desync_profiles: RefCell::new(Vec::new()),
            desync_templates: RefCell::new(Vec::new()),
            droproot: can_drop,
            user: None,
            uid: if can_drop { 0x7FFFFFFF } else { 0 },
            gid: if can_drop {
                vec![0x7FFFFFFF]
            } else {
                Vec::new()
            },
            pidfile: String::new(),
            hostlists: RefCell::new(HostlistFiles::default()),
            ipsets: RefCell::new(IpsetFiles::default()),
            blobs: RefCell::new(Blobs::default()),
            ctrack_t_syn: crate::conntrack::CTRACK_T_SYN,
            ctrack_t_est: crate::conntrack::CTRACK_T_EST,
            ctrack_t_fin: crate::conntrack::CTRACK_T_FIN,
            ctrack_t_udp: crate::conntrack::CTRACK_T_UDP,
            conntrack: RefCell::new(Conntrack::default()),
            ctrack_disable: false,
            server: false,
            filter_ssid_present: false,
            fastpath_workaround: FASTPATH_WORKAROUND_OFF,
            fastpath_retrans_count: std::cell::Cell::new(0),
            cache_hostname: false,
            ipcache_lifetime: IPCACHE_LIFETIME,
            ipcache: RefCell::new(IpCache::default()),
            reasm_payload_disable: 1u64 << L7P_NONE,
            payload_disable: 1u64 << L7P_NONE,
            lua_init_scripts: Vec::new(),
            writable_dir_enable: false,
            writable_dir: String::new(),
            timers: RefCell::new(TimerPool::default()),
            timers_dirty: Cell::new(false),
            lua_gc: LUA_GC_INTERVAL * 1000,
        }
    }
}

thread_local! {
    static PARAMS: RefCell<Option<Rc<Params>>> = const { RefCell::new(None) };
}

pub fn set_params(p: Rc<Params>) {
    PARAMS.with(|x| *x.borrow_mut() = Some(p));
}

/// The global params (like the C `params`). Valid after set_params.
pub fn params() -> Rc<Params> {
    // INFALLIBLE: set once in main before any use
    PARAMS
        .with(|x| x.borrow().clone())
        .expect("params not initialized")
}

pub fn params_opt() -> Option<Rc<Params>> {
    PARAMS.with(|x| x.borrow().clone())
}
