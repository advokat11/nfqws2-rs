//! Port of pools.c (+ uthash.h, kavl.h).
//! uthash tables iterate in insertion order: IndexMap with shift_remove keeps that.
//! The kavl prefix tree holds disjoint prefixes ordered by address: a BTreeMap of intervals.
//! BSD LIST_INSERT_HEAD lists are Vecs with the head at index 0.

use crate::filter::{
    icf_match, icf_parse, ipp_match, ipp_parse, pf_match, pf_parse, str_cidr4, str_cidr6, Cidr4,
    Cidr6, IcmpFilter, IppFilter, PacketRange, PortFilter, PACKET_RANGE_ALWAYS,
};
use crate::helpers::{boottime, expand_bits, FileModSig};
use indexmap::IndexMap;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

pub const HOSTLIST_POOL_FLAG_STRICT_MATCH: u32 = 1;
pub const HOSTLIST_POOL_FLAG_EXCEMPT: u32 = 2;

/// uthash uses a fixed (unseeded) hash; a fixed-key hasher also keeps getrandom() calls
/// identical to the C original, which LuaJIT's seeded string hash depends on (ADR-007).
pub type FixedState = std::hash::BuildHasherDefault<std::collections::hash_map::DefaultHasher>;
pub type IMap<K, V> = IndexMap<K, V, FixedState>;

pub type HostlistPool = IMap<Vec<u8>, u32>;

pub fn hostlist_pool_add(p: &mut HostlistPool, s: &[u8], flags: u32) {
    if !p.contains_key(s) {
        p.insert(s.to_vec(), flags);
    }
}

#[derive(Clone, Debug)]
pub struct HostFail {
    pub counter: i32,
    pub expire: i64,
}

pub type HostFailPool = IMap<Vec<u8>, HostFail>;

pub fn hostfail_pool_add<'a>(
    p: &'a mut HostFailPool,
    s: &[u8],
    fail_time: i32,
) -> &'a mut HostFail {
    // ADD_STR_POOL adds without a duplicate check; callers check first.
    p.insert(
        s.to_vec(),
        HostFail {
            counter: 0,
            expire: boottime() + fail_time as i64,
        },
    );
    // INFALLIBLE: just inserted
    p.get_mut(s).expect("inserted")
}

pub fn hostfail_pool_purge(p: &mut HostFailPool) {
    let now = boottime();
    p.retain(|_, e| now < e.expire);
}

pub fn hostfail_pool_purge_rate_limited(p: &mut HostFailPool, purge_prev: &mut i64) {
    let now = boottime();
    if *purge_prev != now {
        hostfail_pool_purge(p);
        *purge_prev = now;
    }
}

pub fn hostfail_pool_dump(p: &HostFailPool) -> String {
    let now = boottime();
    let mut s = String::new();
    for (k, e) in p {
        s += &format!(
            "host={} counter={} time_left={}\n",
            String::from_utf8_lossy(k),
            e.counter,
            e.expire - now
        );
    }
    s
}

#[derive(Clone, Debug, Default)]
pub struct Str2 {
    pub str1: Option<String>,
    pub str2: Option<String>,
}

#[derive(Clone, Debug)]
pub struct FuncItem {
    pub func: String,
    pub payload_type: u64,
    pub range_in: PacketRange,
    pub range_out: PacketRange,
    /// LIST_INSERT_HEAD order: index 0 is the last added
    pub args: Vec<Str2>,
}

impl FuncItem {
    pub fn new(func: &str) -> FuncItem {
        FuncItem {
            func: func.to_string(),
            payload_type: 0,
            range_in: PACKET_RANGE_ALWAYS,
            range_out: PACKET_RANGE_ALWAYS,
            args: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
pub struct HostlistFile {
    pub filename: Option<String>,
    pub mod_sig: FileModSig,
    pub hostlist: Option<HostlistPool>,
}

pub type HostlistFileRef = Rc<RefCell<HostlistFile>>;

/// LIST_INSERT_HEAD order.
#[derive(Default, Debug)]
pub struct HostlistFiles(pub Vec<HostlistFileRef>);

impl HostlistFiles {
    pub fn add(&mut self, filename: Option<&str>) -> HostlistFileRef {
        let e = Rc::new(RefCell::new(HostlistFile {
            filename: filename.map(str::to_string),
            ..Default::default()
        }));
        self.0.insert(0, e.clone());
        e
    }
    pub fn search(&self, filename: &str) -> Option<HostlistFileRef> {
        self.0
            .iter()
            .find(|h| h.borrow().filename.as_deref() == Some(filename))
            .cloned()
    }
    pub fn reset_modtime(&self) {
        for h in &self.0 {
            h.borrow_mut().mod_sig = FileModSig::default();
        }
    }
}

#[derive(Clone, Debug)]
pub struct HostlistItem {
    pub hfile: HostlistFileRef,
    pub b_autolist: bool,
}

#[derive(Clone, Default, Debug)]
pub struct HostlistCollection(pub Vec<HostlistItem>);

impl HostlistCollection {
    pub fn add(&mut self, hfile: HostlistFileRef, b_autolist: bool) {
        self.0.insert(0, HostlistItem { hfile, b_autolist });
    }
    pub fn copy_from(&mut self, from: &HostlistCollection) {
        self.0.extend(from.0.iter().cloned());
    }
    pub fn search(&self, filename: &str) -> Option<&HostlistItem> {
        self.0
            .iter()
            .find(|i| i.hfile.borrow().filename.as_deref() == Some(filename))
    }
    pub fn is_empty_lists(&self) -> bool {
        self.0.iter().all(|i| i.hfile.borrow().hostlist.is_none())
    }
}

/// Disjoint prefixes keyed by the first address of their range.
#[derive(Clone, Debug, Default)]
pub struct PrefixSet {
    bits: u32, // 32 or 128
    map: BTreeMap<u128, (u128, u8)>,
}

fn addr_to_u128(a: &[u8], bits: u32) -> u128 {
    let mut v: u128 = 0;
    for b in a.iter().take((bits / 8) as usize) {
        v = v << 8 | *b as u128;
    }
    v
}

impl PrefixSet {
    pub fn new(bits: u32) -> PrefixSet {
        PrefixSet {
            bits,
            map: BTreeMap::new(),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    fn range(&self, a: &[u8], preflen: u8) -> (u128, u128) {
        let v = addr_to_u128(a, self.bits);
        let host = self.bits - preflen as u32;
        let mask: u128 = if host >= 128 {
            u128::MAX
        } else {
            (1u128 << host) - 1
        };
        let lo = v & !mask;
        (lo, lo | mask)
    }
    fn overlapping(&self, lo: u128, hi: u128) -> Option<(u128, u128, u8)> {
        self.map
            .range(..=hi)
            .next_back()
            .filter(|(_, (h, _))| *h >= lo)
            .map(|(l, (h, p))| (*l, *h, *p))
    }
    pub fn add(&mut self, a: &[u8], preflen: u8) -> bool {
        if preflen as u32 > self.bits {
            return false;
        }
        let (lo, hi) = self.range(a, preflen);
        while let Some((ol, _, op)) = self.overlapping(lo, hi) {
            if preflen < op {
                self.map.remove(&ol);
            } else {
                return true;
            }
        }
        self.map.insert(lo, (hi, preflen));
        true
    }
    pub fn check(&self, a: &[u8], preflen: u8) -> bool {
        let (lo, hi) = self.range(a, preflen);
        self.overlapping(lo, hi).is_some()
    }
    pub fn print(&self) -> String {
        let mut s = String::new();
        for (lo, (_, p)) in &self.map {
            let full = lo.to_be_bytes();
            if self.bits == 32 {
                let mut addr = [0u8; 4];
                expand_bits(&mut addr, &full[12..], *p as u32);
                s += &str_cidr4(&Cidr4 { addr, preflen: *p });
            } else {
                let mut addr = [0u8; 16];
                expand_bits(&mut addr, &full, *p as u32);
                s += &str_cidr6(&Cidr6 { addr, preflen: *p });
            }
            s.push('\n');
        }
        s
    }
}

#[derive(Clone, Debug)]
pub struct IpSet {
    pub ips4: PrefixSet,
    pub ips6: PrefixSet,
}

impl Default for IpSet {
    fn default() -> Self {
        IpSet {
            ips4: PrefixSet::new(32),
            ips6: PrefixSet::new(128),
        }
    }
}

impl IpSet {
    pub fn is_empty(&self) -> bool {
        self.ips4.is_empty() && self.ips6.is_empty()
    }
    pub fn print(&self) -> String {
        self.ips4.print() + &self.ips6.print()
    }
}

#[derive(Debug, Default)]
pub struct IpsetFile {
    pub filename: Option<String>,
    pub mod_sig: FileModSig,
    pub ipset: IpSet,
}

pub type IpsetFileRef = Rc<RefCell<IpsetFile>>;

#[derive(Default, Debug)]
pub struct IpsetFiles(pub Vec<IpsetFileRef>);

impl IpsetFiles {
    pub fn add(&mut self, filename: Option<&str>) -> IpsetFileRef {
        let e = Rc::new(RefCell::new(IpsetFile {
            filename: filename.map(str::to_string),
            ..Default::default()
        }));
        self.0.insert(0, e.clone());
        e
    }
    pub fn search(&self, filename: &str) -> Option<IpsetFileRef> {
        self.0
            .iter()
            .find(|h| h.borrow().filename.as_deref() == Some(filename))
            .cloned()
    }
    pub fn reset_modtime(&self) {
        for h in &self.0 {
            h.borrow_mut().mod_sig = FileModSig::default();
        }
    }
}

#[derive(Clone, Default, Debug)]
pub struct IpsetCollection(pub Vec<IpsetFileRef>);

impl IpsetCollection {
    pub fn add(&mut self, f: IpsetFileRef) {
        self.0.insert(0, f);
    }
    pub fn copy_from(&mut self, from: &IpsetCollection) {
        self.0.extend(from.0.iter().cloned());
    }
    pub fn search(&self, filename: &str) -> Option<&IpsetFileRef> {
        self.0
            .iter()
            .find(|i| i.borrow().filename.as_deref() == Some(filename))
    }
    pub fn is_empty_sets(&self) -> bool {
        self.0.iter().all(|i| i.borrow().ipset.is_empty())
    }
}

#[derive(Clone, Default, Debug)]
pub struct PortFilters(pub Vec<PortFilter>);
impl PortFilters {
    pub fn add(&mut self, pf: PortFilter) {
        self.0.insert(0, pf);
    }
    pub fn matches(&self, port: u16) -> bool {
        self.0.is_empty() || self.0.iter().any(|pf| pf_match(port, pf))
    }
    pub fn deny_if_empty(&mut self) -> bool {
        if self.0.is_empty() {
            if let Some(pf) = pf_parse("0") {
                self.add(pf);
            }
        }
        true
    }
}

#[derive(Clone, Default, Debug)]
pub struct IcmpFilters(pub Vec<IcmpFilter>);
impl IcmpFilters {
    pub fn add(&mut self, f: IcmpFilter) {
        self.0.insert(0, f);
    }
    pub fn matches(&self, t: u8, c: u8) -> bool {
        self.0.is_empty() || self.0.iter().any(|f| icf_match(t, c, f))
    }
    pub fn deny_if_empty(&mut self) -> bool {
        if self.0.is_empty() {
            if let Some(f) = icf_parse("-") {
                self.add(f);
            }
        }
        true
    }
}

#[derive(Clone, Default, Debug)]
pub struct IppFilters(pub Vec<IppFilter>);
impl IppFilters {
    pub fn add(&mut self, f: IppFilter) {
        self.0.insert(0, f);
    }
    pub fn matches(&self, p: u8) -> bool {
        self.0.is_empty() || self.0.iter().any(|f| ipp_match(p, f))
    }
    pub fn deny_if_empty(&mut self) -> bool {
        if self.0.is_empty() {
            if let Some(f) = ipp_parse("-") {
                self.add(f);
            }
        }
        true
    }
}

#[derive(Clone, Debug, Default)]
pub struct Blob {
    pub data: Vec<u8>,
    /// allocated size (size + reserve)
    pub size_buf: usize,
    pub name: Option<String>,
    pub extra: Option<Vec<u8>>,
}

/// Tail-inserted list.
#[derive(Clone, Default, Debug)]
pub struct Blobs(pub Vec<Blob>);
impl Blobs {
    pub fn add_blob(&mut self, data: &[u8], reserve: usize) -> &mut Blob {
        self.0.push(Blob {
            data: data.to_vec(),
            size_buf: data.len() + reserve,
            name: None,
            extra: None,
        });
        // INFALLIBLE: just pushed
        self.0.last_mut().expect("pushed")
    }
    pub fn search_name(&self, name: &str) -> Option<&Blob> {
        self.0.iter().find(|b| b.name.as_deref() == Some(name))
    }
    pub fn search_name_mut(&mut self, name: &str) -> Option<&mut Blob> {
        self.0.iter_mut().find(|b| b.name.as_deref() == Some(name))
    }
}

#[derive(Clone, Debug, Default)]
pub struct IpCacheItem {
    pub last: i64,
    pub hostname: Option<Vec<u8>>,
    pub hostname_is_ip: bool,
    pub ttl: u8,
}

fn iface_key(iface: Option<&str>) -> String {
    // snprintf into IFNAMSIZ (16): at most 15 chars
    let s = iface.unwrap_or("");
    let mut end = s.len().min(15);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[derive(Default, Debug)]
pub struct IpCache {
    pub c4: IMap<([u8; 4], String), IpCacheItem>,
    pub c6: IMap<([u8; 16], String), IpCacheItem>,
    purge_prev: i64,
}

impl IpCache {
    pub fn find(
        &mut self,
        a4: Option<&[u8; 4]>,
        a6: Option<&[u8; 16]>,
        iface: Option<&str>,
    ) -> Option<&mut IpCacheItem> {
        if let Some(a) = a4 {
            self.c4.get_mut(&(*a, iface_key(iface)))
        } else if let Some(a) = a6 {
            self.c6.get_mut(&(*a, iface_key(iface)))
        } else {
            None
        }
    }
    pub fn touch(
        &mut self,
        a4: Option<&[u8; 4]>,
        a6: Option<&[u8; 16]>,
        iface: Option<&str>,
    ) -> Option<&mut IpCacheItem> {
        let now = boottime();
        let item = if let Some(a) = a4 {
            self.c4
                .entry((*a, iface_key(iface)))
                .or_insert_with(|| IpCacheItem {
                    last: now,
                    ..Default::default()
                })
        } else if let Some(a) = a6 {
            self.c6
                .entry((*a, iface_key(iface)))
                .or_insert_with(|| IpCacheItem {
                    last: now,
                    ..Default::default()
                })
        } else {
            return None;
        };
        item.last = now;
        Some(item)
    }
    pub fn purge_rate_limited(&mut self, lifetime: i64) {
        let now = boottime();
        if self.purge_prev != now {
            if lifetime != 0 {
                self.c4.retain(|_, e| now < e.last + lifetime);
                self.c6.retain(|_, e| now < e.last + lifetime);
            }
            self.purge_prev = now;
        }
    }
    pub fn print(&self) -> String {
        let now = boottime();
        let mut s = String::new();
        let line = |ip: String, iface: &str, d: &IpCacheItem| {
            format!(
                "{} iface={} : ttl {} hostname={} hostname_is_ip={} now=last+{}\n",
                ip,
                iface,
                d.ttl,
                d.hostname
                    .as_deref()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default(),
                d.hostname_is_ip as u8,
                (now - d.last) as u64
            )
        };
        for ((a, i), d) in &self.c4 {
            s += &line(crate::helpers::ntop4(a), i, d);
        }
        for ((a, i), d) in &self.c6 {
            s += &line(crate::helpers::ntop6(a), i, d);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prefixes() {
        let mut s = PrefixSet::new(32);
        assert!(s.add(&[10, 1, 2, 3], 32));
        assert!(s.add(&[10, 1, 0, 0], 16));
        assert_eq!(s.len(), 1);
        assert!(s.add(&[10, 1, 5, 5], 24));
        assert_eq!(s.len(), 1);
        assert!(s.check(&[10, 1, 200, 1], 32));
        assert!(!s.check(&[10, 2, 0, 1], 32));
        assert_eq!(s.print(), "10.1.0.0/16\n");
    }
}
