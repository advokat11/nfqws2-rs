//! Port of hostlist.c and ipset.c: list loading, reload checks, matching, registration.

use crate::filter::{parse_cidr4, parse_cidr6};
use crate::gzip::{is_gzip_file, z_readfile, Z_STREAM_END};
use crate::helpers::{file_mod_signature, file_open_test, file_size, ntop4, ntop6};
use crate::log::{debug, dlog_perror};
use crate::params::{params, DesyncProfile};
use crate::pools::{
    hostlist_pool_add, HostlistCollection, HostlistFileRef, HostlistPool, IpSet, IpsetCollection,
    IpsetFileRef, HOSTLIST_POOL_FLAG_EXCEMPT, HOSTLIST_POOL_FLAG_STRICT_MATCH,
};
use crate::{dlog, dlog_condup, dlog_err};
use std::io::{BufRead, BufReader, Read};

/// fgets(s, size) semantics: yields chunks of at most size-1 bytes, splitting at '\n'.
fn fgets_lines<R: Read>(r: R, size: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut br = BufReader::new(r);
    loop {
        let mut line = Vec::new();
        // read until newline or size-1 bytes
        while let Ok(buf) = br.fill_buf() {
            if buf.is_empty() {
                break;
            }
            let room = size - 1 - line.len();
            let take = buf
                .iter()
                .take(room)
                .position(|&c| c == b'\n')
                .map(|p| p + 1);
            match take {
                Some(n) => {
                    line.extend_from_slice(&buf[..n]);
                    br.consume(n);
                    break;
                }
                None => {
                    let n = buf.len().min(room);
                    line.extend_from_slice(&buf[..n]);
                    br.consume(n);
                    if line.len() == size - 1 {
                        break;
                    }
                }
            }
        }
        if line.is_empty() {
            break;
        }
        // fgets result is a C string: content after an embedded NUL is invisible
        if let Some(p) = line.iter().position(|&c| c == 0) {
            line.truncate(p);
        }
        out.push(line);
    }
    out
}

fn at(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

/// hostlist addpool on b[*s..end]
fn hl_addpool(pool: &mut HostlistPool, b: &mut [u8], s: &mut usize, end: usize, ct: &mut i32) {
    let mut p = *s;
    while p < end && (b[p] == b' ' || b[p] == b'\t') {
        p += 1;
    }
    *s = p;
    if p < end && !matches!(b[p], b'#' | b';' | b'/' | b'\r' | b'\n') {
        let mut flags = 0;
        while at(b, p) == b'^' || at(b, p) == b'!' {
            if b[p] == b'^' {
                flags |= HOSTLIST_POOL_FLAG_STRICT_MATCH;
            } else {
                flags |= HOSTLIST_POOL_FLAG_EXCEMPT;
            }
            *s += 1;
            p = *s;
        }
        while p < end && !matches!(b[p], 0 | b' ' | b'\t' | b'\r' | b'\n') {
            b[p] = b[p].to_ascii_lowercase();
            p += 1;
        }
        let key = if p >= *s {
            b[*s..p].to_vec()
        } else {
            Vec::new()
        };
        hostlist_pool_add(pool, &key, flags);
        *ct += 1;
    }
    while p < end && !matches!(b[p], 0 | b'\r' | b'\n') {
        p += 1;
    }
    while p < end && matches!(b[p], 0 | b'\r' | b'\n') {
        p += 1;
    }
    *s = p;
}

pub fn append_hostlist_item(pool: &mut HostlistPool, s: &str) {
    let mut b = s.as_bytes().to_vec();
    let end = b.len();
    let mut p = 0;
    let mut ct = 0;
    hl_addpool(pool, &mut b, &mut p, end, &mut ct);
}

pub fn append_hostlist(pool: &mut Option<HostlistPool>, filename: &str) -> bool {
    dlog_condup!("Loading hostlist {}\n", filename);
    let f = match std::fs::File::open(filename) {
        Ok(f) => f,
        Err(_) => {
            dlog_err!("Could not open {}\n", filename);
            return false;
        }
    };
    let mut ct = 0;
    let pl = pool.get_or_insert_with(HostlistPool::default);
    if is_gzip_file(filename) {
        let mut f = f;
        let (r, mut z) = z_readfile(&mut f);
        if r == Z_STREAM_END {
            dlog_condup!(
                "zlib compression detected. uncompressed size : {}\n",
                z.len()
            );
            let end = z.len();
            let mut p = 0;
            while p < end {
                hl_addpool(pl, &mut z, &mut p, end, &mut ct);
            }
        } else {
            dlog_err!("zlib decompression failed : result {}\n", r);
            if pl.is_empty() {
                *pool = None;
            }
            return false;
        }
    } else {
        dlog_condup!("loading plain text list\n");
        for mut line in fgets_lines(f, 4096) {
            let end = line.len();
            let mut p = 0;
            hl_addpool(pl, &mut line, &mut p, end, &mut ct);
        }
    }
    if pl.is_empty() {
        *pool = None;
    }
    dlog_condup!("Loaded {} hosts from {}\n", ct, filename);
    true
}

fn load_hostlist(h: &HostlistFileRef, changed: &mut bool) -> bool {
    let fname = h.borrow().filename.clone();
    let Some(fname) = fname else { return true };
    let Some(sig) = file_mod_signature(&fname) else {
        dlog_perror("file_mod_signature");
        dlog_err!(
            "cannot access hostlist file '{}'. in-memory content remains unchanged.\n",
            fname
        );
        return true;
    };
    if h.borrow().mod_sig == sig {
        return true;
    }
    if !file_open_test(&fname, libc::O_RDONLY) {
        dlog_perror("file_open_test");
        dlog_err!(
            "cannot access hostlist file '{}'. in-memory content remains unchanged.\n",
            fname
        );
        return true;
    }
    *changed = true;
    let mut hb = h.borrow_mut();
    hb.hostlist = None;
    if !append_hostlist(&mut hb.hostlist, &fname) {
        hb.hostlist = None;
        return false;
    }
    hb.mod_sig = sig;
    true
}

pub fn non_empty_hostlist(pool: &mut Option<HostlistPool>) {
    if pool.is_none() {
        let mut p = HostlistPool::default();
        hostlist_pool_add(&mut p, b"@&()", 0);
        *pool = Some(p);
    }
}

fn make_autolists_non_empty() {
    let p = params();
    for dp in p.desync_profiles.borrow().iter() {
        if let Some(ha) = &dp.borrow().hostlist_auto {
            non_empty_hostlist(&mut ha.borrow_mut().hostlist);
        }
    }
}

pub fn load_all_hostlists() -> bool {
    let p = params();
    let mut changed = false;
    let files: Vec<HostlistFileRef> = p.hostlists.borrow().0.clone();
    let mut res = true;
    for h in &files {
        if !load_hostlist(h, &mut changed) {
            res = false;
        }
    }
    if !res {
        return false;
    }
    if changed {
        make_autolists_non_empty();
    }
    true
}

fn search_hostlist(
    pool: Option<&HostlistPool>,
    host: &[u8],
    no_match_subdomains: bool,
    excempted: &mut bool,
) -> bool {
    *excempted = false;
    let Some(pool) = pool else { return false };
    let mut p = Some(0usize);
    let mut full = true;
    while let Some(o) = p {
        let cur = &host[o..];
        dlog!("hostlist check for {} : ", String::from_utf8_lossy(cur));
        if let Some(&flags) = pool.get(cur) {
            if flags & HOSTLIST_POOL_FLAG_STRICT_MATCH != 0 && !full {
                dlog!(
                    "negative : strict_mismatch : {} != {}\n",
                    String::from_utf8_lossy(cur),
                    String::from_utf8_lossy(host)
                );
            } else if flags & HOSTLIST_POOL_FLAG_EXCEMPT != 0 {
                dlog!("negative : excemption : {}\n", String::from_utf8_lossy(cur));
                *excempted = true;
                break;
            } else {
                dlog!("positive\n");
                return true;
            }
        } else {
            dlog!("negative\n");
        }
        if no_match_subdomains {
            break;
        }
        p = cur.iter().position(|&c| c == b'.').map(|i| o + i + 1);
        full = false;
    }
    false
}

fn hostlists_reload_check(c: &HostlistCollection) -> bool {
    let mut changed = false;
    for item in &c.0 {
        if !load_hostlist(&item.hfile, &mut changed) {
            return false;
        }
    }
    if changed {
        make_autolists_non_empty();
    }
    true
}

pub fn hostlists_reload_check_for_profile(dp: &DesyncProfile) -> bool {
    hostlists_reload_check(&dp.hl_collection) && hostlists_reload_check(&dp.hl_collection_exclude)
}

fn fname_or_fixed(f: &Option<String>) -> &str {
    f.as_deref().unwrap_or("fixed")
}

/// HostlistCheck: true = apply fooling.
pub fn hostlist_check(
    dp: &DesyncProfile,
    host: &[u8],
    no_match_subdomains: bool,
    excluded: &mut bool,
    skip_reload_check: bool,
) -> bool {
    dlog!(
        "* hostlist check for profile {} ({})\n",
        dp.n,
        dp.name_str()
    );
    *excluded = false;
    if !skip_reload_check
        && (!hostlists_reload_check(&dp.hl_collection)
            || !hostlists_reload_check(&dp.hl_collection_exclude))
    {
        return false;
    }
    let mut exc = false;
    for item in &dp.hl_collection_exclude.0 {
        let h = item.hfile.borrow();
        dlog!("[{}] exclude ", fname_or_fixed(&h.filename));
        if search_hostlist(h.hostlist.as_ref(), host, no_match_subdomains, &mut exc) {
            *excluded = true;
            return false;
        }
    }
    if !dp.hl_collection.is_empty_lists() {
        for item in &dp.hl_collection.0 {
            let h = item.hfile.borrow();
            dlog!("[{}] include ", fname_or_fixed(&h.filename));
            if search_hostlist(h.hostlist.as_ref(), host, no_match_subdomains, &mut exc) {
                return true;
            } else if exc && item.b_autolist {
                *excluded = true;
            }
        }
        return false;
    }
    true
}

pub fn realpath(f: &str) -> Option<String> {
    std::fs::canonicalize(f)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

pub fn register_hostlist(
    files: &std::cell::RefCell<crate::pools::HostlistFiles>,
    dp: &mut DesyncProfile,
    exclude: bool,
    filename: Option<&str>,
    b_autolist: bool,
) -> Option<HostlistFileRef> {
    if let Some(f) = filename {
        if file_size(f).is_none() {
            dlog_err!("cannot access hostlist file '{}'\n", f);
            return None;
        }
    }
    let coll = if exclude {
        &mut dp.hl_collection_exclude
    } else {
        &mut dp.hl_collection
    };
    match filename {
        Some(f) => {
            let pabs = realpath(f)?;
            let h = {
                let mut hl = files.borrow_mut();
                match hl.search(&pabs) {
                    Some(h) => h,
                    None => hl.add(Some(&pabs)),
                }
            };
            if coll.search(&pabs).is_some() {
                return None;
            }
            coll.add(h.clone(), b_autolist);
            Some(h)
        }
        None => {
            let h = files.borrow_mut().add(None);
            coll.add(h.clone(), false);
            Some(h)
        }
    }
}

fn hostlists_debug_profile(dp: &DesyncProfile, entity: &str) {
    let empty = |h: &crate::pools::HostlistFile| if h.hostlist.is_some() { "" } else { " (empty)" };
    for item in &dp.hl_collection.0 {
        if dp
            .hostlist_auto
            .as_ref()
            .is_some_and(|a| std::rc::Rc::ptr_eq(a, &item.hfile))
        {
            continue;
        }
        let h = item.hfile.borrow();
        match &h.filename {
            Some(f) => dlog!(
                "{} {} ({}) include hostlist {}{}\n",
                entity,
                dp.n,
                dp.name_str(),
                f,
                empty(&h)
            ),
            None => dlog!(
                "{} {} ({}) include fixed hostlist{}\n",
                entity,
                dp.n,
                dp.name_str(),
                empty(&h)
            ),
        }
    }
    for item in &dp.hl_collection_exclude.0 {
        let h = item.hfile.borrow();
        match &h.filename {
            Some(f) => dlog!(
                "{} {} ({}) exclude hostlist {}{}\n",
                entity,
                dp.n,
                dp.name_str(),
                f,
                empty(&h)
            ),
            None => dlog!(
                "{} {} ({}) exclude fixed hostlist{}\n",
                entity,
                dp.n,
                dp.name_str(),
                empty(&h)
            ),
        }
    }
    if let Some(ha) = &dp.hostlist_auto {
        let h = ha.borrow();
        dlog!(
            "{} {} ({}) auto hostlist {}{}\n",
            entity,
            dp.n,
            dp.name_str(),
            h.filename.as_deref().unwrap_or("(null)"),
            empty(&h)
        );
    }
}

pub fn hostlists_debug() {
    if !debug() {
        return;
    }
    let p = params();
    for h in p.hostlists.borrow().0.iter() {
        let h = h.borrow();
        let e = if h.hostlist.is_some() { "" } else { " (empty)" };
        match &h.filename {
            Some(f) => dlog!("hostlist file {}{}\n", f, e),
            None => dlog!("hostlist fixed{}\n", e),
        }
    }
    for dp in p.desync_profiles.borrow().iter() {
        hostlists_debug_profile(&dp.borrow(), "profile");
    }
    for dp in p.desync_templates.borrow().iter() {
        hostlists_debug_profile(&dp.borrow(), "template");
    }
}

// ---------------- ipset ----------------

fn ip_addpool(ips: &mut IpSet, b: &[u8], s: &mut usize, end: usize, ct: &mut i32) {
    let mut p = *s;
    while p < end && (b[p] == b' ' || b[p] == b'\t') {
        p += 1;
    }
    if p < end && !matches!(b[p], b'#' | b';' | b'/' | b'\r' | b'\n') {
        *s = p;
        while p < end && !matches!(b[p], 0 | b' ' | b'\t' | b'\r' | b'\n') {
            p += 1;
        }
        let l = (p - *s).min(127);
        let cidr = &b[*s..*s + l];
        // C string semantics for parse functions
        let cidr = &cidr[..cidr.iter().position(|&c| c == 0).unwrap_or(cidr.len())];
        if let Some(c4) = parse_cidr4(cidr) {
            ips.ips4.add(&c4.addr, c4.preflen);
            *ct += 1;
        } else if let Some(c6) = parse_cidr6(cidr) {
            ips.ips6.add(&c6.addr, c6.preflen);
            *ct += 1;
        } else {
            dlog_err!("bad ip or subnet : {}\n", String::from_utf8_lossy(cidr));
        }
    }
    while p < end && !matches!(b[p], 0 | b'\r' | b'\n') {
        p += 1;
    }
    while p < end && matches!(b[p], 0 | b'\r' | b'\n') {
        p += 1;
    }
    *s = p;
}

pub fn append_ipset_item(ips: &mut IpSet, s: &str) {
    let b = s.as_bytes();
    let mut p = 0;
    let mut ct = 0;
    ip_addpool(ips, b, &mut p, b.len(), &mut ct);
}

fn append_ipset(ips: &mut IpSet, filename: &str) -> bool {
    dlog_condup!("Loading ipset {}\n", filename);
    let f = match std::fs::File::open(filename) {
        Ok(f) => f,
        Err(_) => {
            dlog_err!("Could not open {}\n", filename);
            return false;
        }
    };
    let mut ct = 0;
    if is_gzip_file(filename) {
        let mut f = f;
        let (r, z) = z_readfile(&mut f);
        if r == Z_STREAM_END {
            dlog_condup!(
                "zlib compression detected. uncompressed size : {}\n",
                z.len()
            );
            let mut p = 0;
            while p < z.len() {
                ip_addpool(ips, &z, &mut p, z.len(), &mut ct);
            }
        } else {
            dlog_err!("zlib decompression failed : result {}\n", r);
            return false;
        }
    } else {
        dlog_condup!("loading plain text list\n");
        for line in fgets_lines(f, 4095) {
            let mut p = 0;
            ip_addpool(ips, &line, &mut p, line.len(), &mut ct);
        }
    }
    dlog_condup!("Loaded {} ip/subnets from {}\n", ct, filename);
    true
}

fn load_ipset(h: &IpsetFileRef) -> bool {
    let fname = h.borrow().filename.clone();
    let Some(fname) = fname else { return true };
    let Some(sig) = file_mod_signature(&fname) else {
        dlog_perror("file_mod_signature");
        dlog_err!(
            "cannot access ipset file '{}'. in-memory content remains unchanged.\n",
            fname
        );
        return true;
    };
    if h.borrow().mod_sig == sig {
        return true;
    }
    if !file_open_test(&fname, libc::O_RDONLY) {
        dlog_perror("file_open_test");
        dlog_err!(
            "cannot access ipset file '{}'. in-memory content remains unchanged.\n",
            fname
        );
        return true;
    }
    let mut hb = h.borrow_mut();
    hb.ipset = IpSet::default();
    if !append_ipset(&mut hb.ipset, &fname) {
        hb.ipset = IpSet::default();
        return false;
    }
    hb.mod_sig = sig;
    true
}

pub fn load_all_ipsets() -> bool {
    let files: Vec<IpsetFileRef> = params().ipsets.borrow().0.clone();
    let mut res = true;
    for h in &files {
        if !load_ipset(h) {
            res = false;
        }
    }
    res
}

fn search_ipset(ips: &IpSet, ip4: Option<&[u8; 4]>, ip6: Option<&[u8; 16]>) -> bool {
    let mut in_set = false;
    if ip4.is_some() != ip6.is_some() {
        let mut s = String::new();
        if let Some(a) = ip4 {
            if debug() {
                s = ntop4(a);
            }
            if !ips.ips4.is_empty() {
                in_set = ips.ips4.check(a, 32);
            }
        }
        if let Some(a) = ip6 {
            if debug() {
                s = ntop6(a);
            }
            if !ips.ips6.is_empty() {
                in_set = ips.ips6.check(a, 128);
            }
        }
        dlog!(
            "ipset check for {} : {}\n",
            s,
            if in_set { "positive" } else { "negative" }
        );
    } else {
        dlog!(
            "ipset check error !!!!!!!! ipv4={} ipv6={}\n",
            if ip4.is_some() { "(ptr)" } else { "(nil)" },
            if ip6.is_some() { "(ptr)" } else { "(nil)" }
        );
    }
    in_set
}

fn ipsets_reload_check(c: &IpsetCollection) -> bool {
    c.0.iter().all(load_ipset)
}

pub fn ipsets_reload_check_for_profile(dp: &DesyncProfile) -> bool {
    ipsets_reload_check(&dp.ips_collection) && ipsets_reload_check(&dp.ips_collection_exclude)
}

pub fn ipset_check(
    dp: &DesyncProfile,
    ip4: Option<&[u8; 4]>,
    ip6: Option<&[u8; 16]>,
    ip4r: Option<&[u8; 4]>,
    ip6r: Option<&[u8; 16]>,
) -> bool {
    if dp.ipsets_absent() {
        return true;
    }
    dlog!("* ipset check for profile {} ({})\n", dp.n, dp.name_str());
    if !ipsets_reload_check(&dp.ips_collection) || !ipsets_reload_check(&dp.ips_collection_exclude)
    {
        return false;
    }
    let has_r = ip4r.is_some() || ip6r.is_some();
    for f in &dp.ips_collection_exclude.0 {
        let h = f.borrow();
        dlog!("[{}] exclude ", fname_or_fixed(&h.filename));
        if search_ipset(&h.ipset, ip4, ip6) {
            return false;
        }
        if has_r {
            dlog!("[{}] exclude ", fname_or_fixed(&h.filename));
            if search_ipset(&h.ipset, ip4r, ip6r) {
                return false;
            }
        }
    }
    if !dp.ips_collection.is_empty_sets() {
        for f in &dp.ips_collection.0 {
            let h = f.borrow();
            dlog!("[{}] include ", fname_or_fixed(&h.filename));
            if search_ipset(&h.ipset, ip4, ip6) {
                return true;
            }
            if has_r {
                dlog!("[{}] include ", fname_or_fixed(&h.filename));
                if search_ipset(&h.ipset, ip4r, ip6r) {
                    return true;
                }
            }
        }
        return false;
    }
    true
}

pub fn register_ipset(
    files: &std::cell::RefCell<crate::pools::IpsetFiles>,
    dp: &mut DesyncProfile,
    exclude: bool,
    filename: Option<&str>,
) -> Option<IpsetFileRef> {
    if let Some(f) = filename {
        if file_size(f).is_none() {
            dlog_err!("cannot access ipset file '{}'\n", f);
            return None;
        }
    }
    let coll = if exclude {
        &mut dp.ips_collection_exclude
    } else {
        &mut dp.ips_collection
    };
    match filename {
        Some(f) => {
            let pabs = realpath(f)?;
            let h = {
                let mut l = files.borrow_mut();
                match l.search(&pabs) {
                    Some(h) => h,
                    None => l.add(Some(&pabs)),
                }
            };
            if coll.search(&pabs).is_some() {
                return None;
            }
            coll.add(h.clone());
            Some(h)
        }
        None => {
            let h = files.borrow_mut().add(None);
            coll.add(h.clone());
            Some(h)
        }
    }
}

fn ipset_fill(ips: &IpSet) -> &'static str {
    match (!ips.ips4.is_empty(), !ips.ips6.is_empty()) {
        (true, true) => "ipv4+ipv6",
        (true, false) => "ipv4",
        (false, true) => "ipv6",
        (false, false) => "empty",
    }
}

fn ipsets_debug_profile(dp: &DesyncProfile, entity: &str) {
    for (coll, what) in [
        (&dp.ips_collection, "include"),
        (&dp.ips_collection_exclude, "exclude"),
    ] {
        for f in &coll.0 {
            let h = f.borrow();
            match &h.filename {
                Some(n) => dlog!(
                    "{} {} ({}) {} ipset {} ({})\n",
                    entity,
                    dp.n,
                    dp.name_str(),
                    what,
                    n,
                    ipset_fill(&h.ipset)
                ),
                None => dlog!(
                    "{} {} ({}) {} fixed ipset ({})\n",
                    entity,
                    dp.n,
                    dp.name_str(),
                    what,
                    ipset_fill(&h.ipset)
                ),
            }
        }
    }
}

pub fn ipsets_debug() {
    if !debug() {
        return;
    }
    let p = params();
    for h in p.ipsets.borrow().0.iter() {
        let h = h.borrow();
        match &h.filename {
            Some(f) => dlog!("ipset file {} ({})\n", f, ipset_fill(&h.ipset)),
            None => dlog!("ipset fixed ({})\n", ipset_fill(&h.ipset)),
        }
    }
    for dp in p.desync_profiles.borrow().iter() {
        ipsets_debug_profile(&dp.borrow(), "profile");
    }
    for dp in p.desync_templates.borrow().iter() {
        ipsets_debug_profile(&dp.borrow(), "template");
    }
}
