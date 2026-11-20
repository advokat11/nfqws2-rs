//! Port of nfqws.c (Linux): entry point, option parsing, NFQUEUE and no-intercept loops.

use crate::cffi::{fflush_all, fwrite_std, set_console_io_buffering};
use crate::darkmagic::*;
use crate::desync::dpi_desync_packet;
use crate::filter::*;
use crate::helpers::*;
use crate::hostlist::*;
use crate::log::{debug, dlog_perror, LogTarget, LOG};
use crate::lua;
use crate::params::*;
use crate::pools::*;
use crate::protocol::*;
use crate::timer::{timer_pool_next, timer_pool_run};
use crate::{dlog, dlog_condup, dlog_err};
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

pub static QUIT: AtomicBool = AtomicBool::new(false);
static RELOAD: AtomicBool = AtomicBool::new(false);
static DUMP_CT: AtomicBool = AtomicBool::new(false);
static DUMP_HF: AtomicBool = AtomicBool::new(false);

pub fn quit_requested() -> bool {
    QUIT.load(Ordering::Relaxed)
}

const HELP: &str = include_str!("help.txt");
const MAX_CONFIG_FILE_SIZE: usize = 16384;
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
const NFQ_MAX_RECV_SIZE: usize = RECONSTRUCT_MAX_SIZE + 4096;
const FUZZ_MAX_PACKET_SIZE: usize = RECONSTRUCT_MAX_SIZE + 4096;

#[repr(C)]
struct GetoptOption {
    name: *const c_char,
    has_arg: c_int,
    flag: *mut c_int,
    val: c_int,
}

#[repr(C)]
struct WordExp {
    we_wordc: usize,
    we_wordv: *mut *mut c_char,
    we_offs: usize,
}

extern "C" {
    static mut optarg: *mut c_char;
    fn getopt_long_only(
        argc: c_int,
        argv: *const *mut c_char,
        opts: *const c_char,
        lo: *const GetoptOption,
        idx: *mut c_int,
    ) -> c_int;
    fn wordexp(words: *const c_char, we: *mut WordExp, flags: c_int) -> c_int;
}

// libnetfilter_queue (same system library as the C original)
#[repr(C)]
struct NfqnlMsgPacketHdr {
    packet_id: u32,
    hw_protocol: u16,
    hook: u8,
}
type NfqCallback =
    unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void, *mut c_void) -> c_int;
extern "C" {
    fn nfq_open() -> *mut c_void;
    fn nfq_close(h: *mut c_void) -> c_int;
    fn nfq_unbind_pf(h: *mut c_void, pf: u16) -> c_int;
    fn nfq_bind_pf(h: *mut c_void, pf: u16) -> c_int;
    fn nfq_create_queue(
        h: *mut c_void,
        num: u16,
        cb: NfqCallback,
        data: *mut c_void,
    ) -> *mut c_void;
    fn nfq_destroy_queue(qh: *mut c_void) -> c_int;
    fn nfq_set_mode(qh: *mut c_void, mode: u8, range: u32) -> c_int;
    fn nfq_set_queue_maxlen(qh: *mut c_void, len: u32) -> c_int;
    fn nfq_set_queue_flags(qh: *mut c_void, mask: u32, flags: u32) -> c_int;
    fn nfq_nfnlh(h: *mut c_void) -> *mut c_void;
    fn nfnl_rcvbufsiz(nfnlh: *mut c_void, size: u32) -> u32;
    fn nfq_fd(h: *mut c_void) -> c_int;
    fn nfq_handle_packet(h: *mut c_void, buf: *mut c_char, len: c_int) -> c_int;
    fn nfq_set_verdict2(
        qh: *mut c_void,
        id: u32,
        verdict: u32,
        mark: u32,
        len: u32,
        buf: *const u8,
    ) -> c_int;
    fn nfq_get_msg_packet_hdr(nfad: *mut c_void) -> *mut NfqnlMsgPacketHdr;
    fn nfq_get_nfmark(nfad: *mut c_void) -> u32;
    fn nfq_get_payload(nfad: *mut c_void, data: *mut *mut u8) -> c_int;
    fn nfq_get_indev(nfad: *mut c_void) -> u32;
    fn nfq_get_outdev(nfad: *mut c_void) -> u32;
}
const NFQNL_COPY_PACKET: u8 = 2;
const NFQA_CFG_F_FAIL_OPEN: u32 = 1;

fn exit_clean(code: i32) -> ! {
    lua::lua_shutdown();
    fflush_all();
    std::process::exit(code);
}

fn exithelp() -> ! {
    fwrite_std(false, HELP.as_bytes());
    fflush_all();
    std::process::exit(1);
}

fn exithelp_clean() -> ! {
    lua::lua_shutdown();
    exithelp();
}

fn is_hexstring(s: &str) -> bool {
    s.starts_with("0x")
}

/// parse_filespec: (filename, offset)
fn parse_filespec(f: &str) -> Option<(&str, u64)> {
    let mut f = f;
    let mut ofs: u64 = 0;
    if let Some(r) = f.strip_prefix('+') {
        f = r;
        match scan_ull(f.as_bytes()) {
            Some(v) => ofs = v,
            None => {
                dlog!("offset read error: {}\n", f);
                return None;
            }
        }
        let at = f.find('@').map(|i| i + 1).unwrap_or(f.len());
        f = &f[at..];
    } else if let Some(r) = f.strip_prefix('@') {
        f = r;
    }
    Some((f, ofs))
}

fn scan_ull(s: &[u8]) -> Option<u64> {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let st = i;
    let mut v: u64 = 0;
    let mut ov = false;
    while i < s.len() && s[i].is_ascii_digit() {
        match v
            .checked_mul(10)
            .and_then(|x| x.checked_add((s[i] - b'0') as u64))
        {
            Some(x) => v = x,
            None => ov = true,
        }
        i += 1;
    }
    if i == st {
        return None;
    }
    Some(if ov {
        u64::MAX
    } else if neg {
        v.wrapping_neg()
    } else {
        v
    })
}

/// load_file_or_exit with a buffer of `max` bytes.
fn load_file_or_exit(filename: &str, max: usize) -> Vec<u8> {
    if is_hexstring(filename) {
        match parse_hex_str(&filename.as_bytes()[2..], max) {
            Ok(v) if !v.is_empty() => {
                dlog!("read {} bytes from hex string\n", v.len());
                v
            }
            _ => {
                dlog_err!("invalid hex string: {}\n", &filename[2..]);
                exit_clean(1);
            }
        }
    } else {
        let Some((f, ofs)) = parse_filespec(filename) else {
            exit_clean(1)
        };
        match load_file(f, ofs, max) {
            Some(v) => {
                dlog!("read {} bytes from '{}'. offset={}\n", v.len(), f, ofs);
                v
            }
            None => {
                dlog_err!("could not read '{}'\n", f);
                exit_clean(1);
            }
        }
    }
}

/// item_name: returns (name, rest)
fn item_name(s: &str) -> Option<(String, &str)> {
    let (name, rest) = match s.find(':') {
        Some(i) => (&s[..i], &s[i + 1..]),
        None => (s, ""),
    };
    if !is_identifier(name) {
        dlog_err!("bad identifier '{}'\n", name);
        return None;
    }
    Some((name.to_string(), rest))
}

fn load_blob_to_collection(spec: &str, blobs: &mut Blobs, max_size: usize, reserve: usize) {
    let Some((name, filename)) = item_name(spec) else {
        exit_clean(1)
    };
    let mut max_size = max_size;
    if !is_hexstring(filename) {
        let Some((fname, ofs)) = parse_filespec(filename) else {
            exit_clean(1)
        };
        let Some(fsize) = file_size(fname) else {
            dlog_err!("cannot access file '{}'\n", fname);
            exit_clean(1);
        };
        if fsize != 0 {
            if ofs >= fsize {
                dlog_err!("offset {} is beyond file size {}\n", ofs, fsize);
                exit_clean(1);
            }
            max_size = (fsize - ofs) as usize;
        }
    }
    if blobs.search_name(&name).is_some() {
        dlog_err!("duplicate blob name '{}'\n", name);
        exit_clean(1);
    }
    let data = load_file_or_exit(filename, max_size);
    let b = blobs.add_blob(&data, reserve);
    b.name = Some(name);
}

fn load_const_blob(name: &str, data: &[u8], blobs: &mut Blobs, reserve: usize) {
    if blobs.search_name(name).is_some() {
        dlog_err!("duplicate blob name '{}'\n", name);
        exit_clean(1);
    }
    let b = blobs.add_blob(data, reserve);
    b.name = Some(name.to_string());
}

fn apply_default_blobs(blobs: &mut Blobs) {
    load_const_blob(
        "fake_default_tls",
        &FAKE_TLS_CLIENTHELLO_DEFAULT,
        blobs,
        BLOB_EXTRA_BYTES,
    );
    load_const_blob(
        "fake_default_http",
        FAKE_HTTP_REQUEST_DEFAULT.as_bytes(),
        blobs,
        0,
    );
    let mut q = vec![0u8; 620];
    q[0] = 0x40;
    load_const_blob("fake_default_quic", &q, blobs, 0);
}

fn parse_uid(opt: &str) -> Option<(u32, Vec<u32>)> {
    let (u, g) = match opt.find(':') {
        Some(i) => (&opt[..i], Some(&opt[i + 1..])),
        None => (opt, None),
    };
    let (uid, _) = scan_u(u.as_bytes())?;
    let mut gids = Vec::new();
    if let Some(g) = g {
        for part in g.split(',') {
            let (v, _) = scan_u(part.as_bytes())?;
            if gids.len() >= MAX_GIDS {
                return None;
            }
            gids.push(v);
        }
    }
    Some((uid, gids))
}

fn parse_l7_list(opt: &str) -> Option<u64> {
    let mut l7 = 0u64;
    for p in opt.split(',') {
        let proto = l7proto_from_name(p);
        if proto == L7_INVALID {
            return None;
        } else if proto == L7_ALL {
            l7 = 0;
            break;
        }
        l7 |= 1u64 << proto;
    }
    Some(l7)
}
fn parse_l7p_list(opt: &str) -> Option<u64> {
    let mut l7 = 0u64;
    for p in opt.split(',') {
        let pl = l7payload_from_name(p);
        if pl == L7P_INVALID {
            return None;
        } else if pl == L7P_ALL {
            l7 = 0;
            break;
        }
        l7 |= 1u64 << pl;
    }
    Some(l7)
}

fn lua_call_param_add(opt: &str, args: &mut Vec<Str2>) -> bool {
    let (k, v) = match opt.find('=') {
        Some(i) => (&opt[..i], Some(&opt[i + 1..])),
        None => (opt, None),
    };
    if !is_identifier(k) {
        return false;
    }
    args.insert(
        0,
        Str2 {
            str1: Some(k.to_string()),
            str2: v.map(str::to_string),
        },
    );
    true
}

/// parse_lua_call. Like the C code it swallows `\:` escapes in place: on error the caller
/// prints the (possibly modified) argument, returned as Err (ADR-009).
fn parse_lua_call(opt: &str, flist: &mut Vec<FuncItem>) -> Result<(), String> {
    let Some((name, _)) = item_name(opt) else {
        return Err(opt.to_string());
    };
    let mut buf = opt.as_bytes().to_vec();
    buf.push(0);
    let mut p = opt.find(':').map_or(opt.len(), |i| i + 1);
    let mut f = FuncItem::new(&name);
    let err = |buf: &Vec<u8>| {
        Err(
            String::from_utf8_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())])
                .into_owned(),
        )
    };
    while buf[p] != 0 {
        let mut e = p;
        while buf[e] != 0 && buf[e] != b':' {
            if buf[e] == b'\\' && buf[e + 1] == b':' {
                buf.remove(e); // memmove(e, e+1, strlen(e))
                buf.push(0);
            }
            e += 1;
        }
        let last = buf[e] == 0;
        let param = String::from_utf8_lossy(&buf[p..e]).into_owned();
        let ok = lua_call_param_add(&param, &mut f.args);
        if !last {
            e += 1;
        }
        if !ok {
            return err(&buf);
        }
        p = e;
    }
    flist.push(f);
    Ok(())
}

fn wf_make_l3(opt: &str, v4: &mut bool, v6: &mut bool) -> bool {
    for p in opt.split(',') {
        match p {
            "ipv4" => *v4 = true,
            "ipv6" => *v6 = true,
            _ => return false,
        }
    }
    true
}

fn lua_desync_debug(dp: &DesyncProfile, entity: &str) {
    if !debug() {
        return;
    }
    for f in &dp.lua_desync {
        dlog!("{} {} ({}) lua {}(", entity, dp.n, dp.name_str(), f.func);
        for (n, a) in f.args.iter().enumerate() {
            if n != 0 {
                dlog!(",");
            }
            match &a.str2 {
                Some(v) => dlog!("{}=\"{}\"", a.str1.as_deref().unwrap_or(""), v),
                None => dlog!("{}=\"\"", a.str1.as_deref().unwrap_or("")),
            }
        }
        let r = |x: &PacketRange| {
            format!(
                "{}{}{}{}{}",
                x.from.mode as char,
                x.from.pos,
                if x.upper_cutoff { '<' } else { '-' },
                x.to.mode as char,
                x.to.pos
            )
        };
        dlog!(
            " range_in={} range_out={} payload_type=",
            r(&f.range_in),
            r(&f.range_out)
        );
        if f.payload_type != 0 {
            for i in 0..L7P_LAST {
                if f.payload_type & (1u64 << i) != 0 {
                    dlog!(" {}", l7payload_str(i).unwrap_or(""));
                }
            }
        } else {
            dlog!(" all");
        }
        dlog!(")\n");
    }
}

fn filter_defaults(dp: &mut DesyncProfile) -> bool {
    if !dp.b_filter_l3 {
        dp.filter_ipv4 = true;
        dp.filter_ipv6 = true;
    }
    if !dp.pf_tcp.0.is_empty()
        || !dp.pf_udp.0.is_empty()
        || !dp.icf.0.is_empty()
        || !dp.ipf.0.is_empty()
    {
        return dp.pf_tcp.deny_if_empty()
            && dp.pf_udp.deny_if_empty()
            && dp.icf.deny_if_empty()
            && dp.ipf.deny_if_empty();
    }
    true
}

fn blob_debug() {
    for b in params().blobs.borrow().0.iter() {
        dlog!(
            "blob '{}' : size={} alloc={}\n",
            b.name.as_deref().unwrap_or("(null)"),
            b.data.len(),
            b.size_buf
        );
    }
}

fn test_list_files() -> bool {
    let p = params();
    for h in p.hostlists.borrow().0.iter() {
        if let Some(f) = &h.borrow().filename {
            if !file_open_test(f, libc::O_RDONLY) {
                dlog_perror("file_open_test");
                dlog_err!("cannot access hostlist file '{}'\n", f);
                return false;
            }
        }
    }
    for h in p.ipsets.borrow().0.iter() {
        if let Some(f) = &h.borrow().filename {
            if !file_open_test(f, libc::O_RDONLY) {
                dlog_perror("file_open_test");
                dlog_err!("cannot access ipset file '{}'\n", f);
                return false;
            }
        }
    }
    true
}

// ---- signals ----
fn raw_write(s: &str) {
    // SAFETY: write(2) is async-signal-safe.
    unsafe { libc::write(1, s.as_ptr() as *const c_void, s.len()) };
}
extern "C" fn onhup(_: c_int) {
    if QUIT.load(Ordering::Relaxed) {
        return;
    }
    raw_write("HUP received ! Lists will be reloaded.\n");
    RELOAD.store(true, Ordering::Relaxed);
}
extern "C" fn onusr1(_: c_int) {
    if !QUIT.load(Ordering::Relaxed) {
        DUMP_CT.store(true, Ordering::Relaxed);
    }
}
extern "C" fn onusr2(_: c_int) {
    if !QUIT.load(Ordering::Relaxed) {
        DUMP_HF.store(true, Ordering::Relaxed);
    }
}
extern "C" fn onint(_: c_int) {
    if QUIT.load(Ordering::Relaxed) {
        return;
    }
    raw_write("INT received !\n");
    QUIT.store(true, Ordering::Relaxed);
    lua::lua_req_quit();
}
extern "C" fn onterm(_: c_int) {
    if QUIT.load(Ordering::Relaxed) {
        return;
    }
    raw_write("TERM received !\n");
    QUIT.store(true, Ordering::Relaxed);
    lua::lua_req_quit();
}

fn catch_signals() {
    let set = |sig: c_int, h: extern "C" fn(c_int)| {
        // SAFETY: installing plain handlers with an empty mask and no flags, as the C code.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_sigaction = h as usize;
            sa.sa_flags = 0;
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    };
    set(libc::SIGHUP, onhup);
    set(libc::SIGUSR1, onusr1);
    set(libc::SIGUSR2, onusr2);
    set(libc::SIGINT, onint);
    set(libc::SIGTERM, onterm);
}

/// Debug dumps requested by SIGUSR1/2 (done outside the handler; see DECISIONS ADR-010).
fn process_dumps() {
    if DUMP_CT.swap(false, Ordering::Relaxed) {
        let p = params();
        let s = format!("\nCONNTRACK DUMP\n{}\n", p.conntrack.borrow().dump());
        fwrite_std(false, s.as_bytes());
    }
    if DUMP_HF.swap(false, Ordering::Relaxed) {
        let p = params();
        let mut s = String::from("\nHOSTFAIL POOL DUMP\n");
        for dp in p.desync_profiles.borrow().iter() {
            let d = dp.borrow();
            s += &format!("\nDESYNC profile {} ({})\n", d.n, d.name_str());
            s += &hostfail_pool_dump(&d.hostlist_auto_fail_counters);
        }
        s += "\nIPCACHE\n";
        s += &p.ipcache.borrow().print();
        s += "\n";
        fwrite_std(false, s.as_bytes());
    }
}

fn reload_check() {
    process_dumps();
    if RELOAD.load(Ordering::Relaxed) {
        let p = params();
        p.hostlists.borrow().reset_modtime();
        if !load_all_hostlists() {
            dlog_err!("hostlists load failed. this is fatal.\n");
            std::process::exit(200);
        }
        p.ipsets.borrow().reset_modtime();
        if !load_all_ipsets() {
            dlog_err!("ipset load failed. this is fatal.\n");
            std::process::exit(200);
        }
        RELOAD.store(false, Ordering::Relaxed);
    }
}

fn process_packet_data(
    mark: u32,
    ifin: Option<&str>,
    ifout: Option<&str>,
    pkt: &[u8],
    modp: &mut Vec<u8>,
    mod_max: usize,
) -> u8 {
    if mark & params().desync_fwmark != 0 {
        dlog!("ignoring generated packet\n");
        return VERDICT_PASS;
    }
    dpi_desync_packet(mark, ifin, ifout, pkt, modp, mod_max)
}

fn fuzz_packet_data(count: u32) {
    let mut mbuf: Vec<u8> = Vec::new();
    for k in 0..count {
        if quit_requested() {
            break;
        }
        if k % 1000 == 0 {
            dlog_condup!("fuzz ct={}\n", k);
        }
        let len = (random() as u64 % (FUZZ_MAX_PACKET_SIZE as u64 + 1)) as usize;
        let mut packet = vec![0u8; len];
        fill_random_bytes(&mut packet);
        if len > 0 {
            let b = packet[0];
            packet[0] = if b != 0 {
                if b & 1 != 0 {
                    0x40
                } else {
                    0x60 | (b & 0x0F)
                }
            } else {
                random() as u8
            };
        }
        let modlen = (random() as u64 % (FUZZ_MAX_PACKET_SIZE as u64 + 1)) as usize;
        // C passes both as call arguments; gcc/x86-64 evaluates them right to left
        let ifout = if random() & 1 != 0 {
            Some("ifout")
        } else {
            None
        };
        let ifin = if random() & 1 != 0 {
            Some("ifin")
        } else {
            None
        };
        process_packet_data(0, ifin, ifout, &packet, &mut mbuf, modlen);
    }
}

fn do_fuzz() {
    let n = params().fuzz;
    if n != 0 {
        dlog_condup!("fuzz packet data count={}\n", n);
        fuzz_packet_data(n);
    }
}

fn no_intercept_loop() {
    let p = params();
    if !p.timers.borrow().is_empty() {
        dlog!("processing timers\n");
        let mut bt_next = timer_pool_next();
        while !p.timers.borrow().is_empty() {
            if quit_requested() {
                dlog_condup!("quit requested\n");
                return;
            }
            let bt = boottime_ms();
            if bt_next > bt {
                let d = bt_next - bt;
                let ts = libc::timespec {
                    tv_sec: (d / 1000) as i64,
                    tv_nsec: (d % 1000 * 1000000) as i64,
                };
                // SAFETY: valid timespec.
                unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
                if quit_requested() {
                    dlog_condup!("quit requested\n");
                    return;
                }
            }
            reload_check();
            lua::lua_do_gc();
            bt_next = timer_pool_run(0);
        }
    }
}

fn write_pidfile(f: &mut Option<std::fs::File>) -> bool {
    if let Some(mut fh) = f.take() {
        use std::io::Write;
        // SAFETY: getpid has no preconditions.
        let pid = unsafe { libc::getpid() };
        if fh.write_all(pid.to_string().as_bytes()).is_err() {
            dlog_perror("write pidfile");
            return false;
        }
    }
    true
}

struct CbData {
    sock: i32,
    modbuf: Vec<u8>,
}

fn ifname_of(sock: i32, idx: u32) -> String {
    if idx == 0 {
        return String::new();
    }
    // SAFETY: ifreq is plain data; ioctl fills the name for the index.
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        ifr.ifr_ifru.ifru_ifindex = idx as i32;
        if libc::ioctl(sock, libc::SIOCGIFNAME, &mut ifr) < 0 {
            dlog_perror("ioctl(SIOCGIFNAME)");
            return String::new();
        }
        CStr::from_ptr(ifr.ifr_name.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

unsafe extern "C" fn nfq_cb(
    qh: *mut c_void,
    _nfmsg: *mut c_void,
    nfa: *mut c_void,
    cookie: *mut c_void,
) -> c_int {
    // SAFETY: cookie is the CbData passed to nfq_create_queue; nfa is valid for this call.
    let cb = &mut *(cookie as *mut CbData);
    let ph = nfq_get_msg_packet_hdr(nfa);
    if ph.is_null() {
        return 0;
    }
    let id = u32::from_be((*ph).packet_id);
    let mut mark = nfq_get_nfmark(nfa);
    let mut data: *mut u8 = std::ptr::null_mut();
    let ilen = nfq_get_payload(nfa, &mut data);
    let outdev = nfq_get_outdev(nfa);
    let ifout = ifname_of(cb.sock, outdev);
    let indev = nfq_get_indev(nfa);
    let ifin = ifname_of(cb.sock, indev);
    dlog!(
        "\npacket: id={} len={} mark={:08X} ifin={}({}) ifout={}({})\n",
        id as i32,
        ilen,
        mark,
        ifin,
        indev,
        ifout,
        outdev
    );
    if ilen >= 0 {
        let pkt = std::slice::from_raw_parts(data, ilen as usize);
        cb.modbuf.clear();
        let v = process_packet_data(
            mark,
            Some(&ifin),
            Some(&ifout),
            pkt,
            &mut cb.modbuf,
            RECONSTRUCT_MAX_SIZE,
        );
        let _ = &mut mark;
        match v & VERDICT_MASK {
            VERDICT_MODIFY => {
                dlog!(
                    "packet: id={} pass modified. len {} => {}\n",
                    id as i32,
                    ilen,
                    cb.modbuf.len()
                );
                return nfq_set_verdict2(
                    qh,
                    id,
                    NF_ACCEPT,
                    mark,
                    cb.modbuf.len() as u32,
                    cb.modbuf.as_ptr(),
                );
            }
            VERDICT_DROP => {
                dlog!("packet: id={} drop\n", id as i32);
                return nfq_set_verdict2(qh, id, NF_DROP, mark, 0, std::ptr::null());
            }
            _ => {}
        }
    }
    dlog!("packet: id={} pass unmodified\n", id as i32);
    nfq_set_verdict2(qh, id, NF_ACCEPT, mark, 0, std::ptr::null())
}

struct Nfq {
    h: *mut c_void,
    qh: *mut c_void,
}

impl Nfq {
    fn deinit(&mut self) {
        let p = params();
        if !self.qh.is_null() {
            dlog_condup!("unbinding from queue {}\n", p.qnum);
            // SAFETY: handle created by nfq_create_queue.
            unsafe { nfq_destroy_queue(self.qh) };
            self.qh = std::ptr::null_mut();
        }
        if !self.h.is_null() {
            dlog_condup!("closing nfq library handle\n");
            // SAFETY: handle created by nfq_open.
            unsafe { nfq_close(self.h) };
            self.h = std::ptr::null_mut();
        }
    }
    fn init(&mut self, cb: *mut CbData) -> bool {
        self.deinit();
        let p = params();
        // SAFETY: libnetfilter_queue API used as in the C original.
        unsafe {
            dlog_condup!("opening nfq library handle\n");
            self.h = nfq_open();
            if self.h.is_null() {
                dlog_perror("nfq_open()");
                self.deinit();
                return false;
            }
            dlog_condup!("unbinding existing nf_queue handler for AF_INET (if any)\n");
            if nfq_unbind_pf(self.h, libc::AF_INET as u16) < 0 {
                dlog_perror("nfq_unbind_pf(AF_INET)");
                self.deinit();
                return false;
            }
            dlog_condup!("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
            if nfq_bind_pf(self.h, libc::AF_INET as u16) < 0 {
                dlog_perror("nfq_bind_pf(AF_INET)");
                self.deinit();
                return false;
            }
            dlog_condup!("unbinding existing nf_queue handler for AF_INET6 (if any)\n");
            if nfq_unbind_pf(self.h, libc::AF_INET6 as u16) < 0 {
                dlog_perror("nfq_unbind_pf(AF_INET6)");
            }
            dlog_condup!("binding nfnetlink_queue as nf_queue handler for AF_INET6\n");
            if nfq_bind_pf(self.h, libc::AF_INET6 as u16) < 0 {
                dlog_perror("nfq_bind_pf(AF_INET6)");
            }
            dlog_condup!("binding this socket to queue '{}'\n", p.qnum);
            self.qh = nfq_create_queue(self.h, p.qnum as u16, nfq_cb, cb as *mut c_void);
            if self.qh.is_null() {
                dlog_perror("nfq_create_queue()");
                self.deinit();
                return false;
            }
            dlog_condup!("setting copy_packet mode\n");
            if nfq_set_mode(self.qh, NFQNL_COPY_PACKET, 0xffff) < 0 {
                dlog_perror("can't set packet_copy mode");
                self.deinit();
                return false;
            }
            if nfq_set_queue_maxlen(self.qh, Q_MAXLEN) < 0 {
                dlog_perror("can't set queue maxlen");
                self.deinit();
                return false;
            }
            if nfq_set_queue_flags(self.qh, NFQA_CFG_F_FAIL_OPEN, NFQA_CFG_F_FAIL_OPEN) != 0 {
                dlog_err!("can't set queue flags. its OK on linux <3.6\n");
            }
            let rcvbuf = nfnl_rcvbufsiz(nfq_nfnlh(self.h), Q_RCVBUF as u32) / 2;
            if rcvbuf == Q_RCVBUF as u32 {
                dlog!("set receive buffer size to {}\n", rcvbuf);
            } else {
                dlog_condup!(
                    "could not set receive buffer size to {}. real size is {}\n",
                    Q_RCVBUF,
                    rcvbuf
                );
            }
            let fd = nfq_fd(self.h);
            let yes: c_int = 1;
            if libc::setsockopt(
                fd,
                libc::SOL_NETLINK,
                libc::NETLINK_NO_ENOBUFS,
                &yes as *const c_int as *const c_void,
                4,
            ) == -1
            {
                dlog_perror("setsockopt(NETLINK_NO_ENOBUFS)");
            }
        }
        true
    }
}

fn nfq_main() -> i32 {
    let p = params();
    let mut fpid: Option<std::fs::File> = None;
    if !p.pidfile.is_empty() {
        match std::fs::File::create(&p.pidfile) {
            Ok(f) => fpid = Some(f),
            Err(_) => {
                dlog_perror("create pidfile");
                return 1;
            }
        }
    }
    let mut cb = Box::new(CbData {
        sock: -1,
        modbuf: Vec::with_capacity(RECONSTRUCT_MAX_SIZE),
    });
    let mut nfq = Nfq {
        h: std::ptr::null_mut(),
        qh: std::ptr::null_mut(),
    };
    let res = (|| -> i32 {
        if (p.droproot && !crate::sec::droproot(p.uid, p.user.as_deref(), &p.gid))
            || !crate::sec::dropcaps()
        {
            return 1;
        }
        crate::sec::print_id();
        if p.droproot && !test_list_files() {
            return 1;
        }
        if !lua::lua_test_init_script_files() {
            return 1;
        }
        crate::sec::sec_harden();
        dlog_condup!(
            "initializing raw sockets bind-fix4={} bind-fix6={}\n",
            p.bind_fix4 as u8,
            p.bind_fix6 as u8
        );
        if !rawsend_preinit(p.bind_fix4, p.bind_fix6) {
            return 1;
        }
        if !p.intercept {
            if p.daemon {
                crate::sec::daemonize();
            }
            if !write_pidfile(&mut fpid) {
                return 1;
            }
        }
        catch_signals();
        if !lua::lua_init() {
            return 1;
        }
        do_fuzz();
        if !p.intercept {
            no_intercept_loop();
            dlog_condup!("no intercept quit\n");
            return 0;
        }
        // SAFETY: plain socket call.
        cb.sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if cb.sock < 0 {
            dlog_perror("socket");
            return 1;
        }
        if !nfq.init(&mut *cb as *mut CbData) {
            return 1;
        }
        if p.filter_ssid_present {
            if !crate::wlan::wlan_info_init() {
                dlog_err!("cannot initialize wlan info capture\n");
                return 1;
            }
            dlog!("wlan info capture initialized\n");
        }
        if p.daemon {
            crate::sec::daemonize();
        }
        if !write_pidfile(&mut fpid) {
            return 1;
        }
        // SAFETY: handle is open.
        let fd = unsafe { nfq_fd(nfq.h) };
        let mut buf = vec![0u8; NFQ_MAX_RECV_SIZE];
        let mut bt_next: u64 = 0;
        let mut rd: isize;
        loop {
            if quit_requested() {
                dlog_condup!("quit requested\n");
                return 0;
            }
            loop {
                let res: i32;
                if !p.timers.borrow().is_empty() {
                    if bt_next == 0 {
                        bt_next = timer_pool_next();
                    }
                    let bt = boottime_ms();
                    let dbt = bt_next.saturating_sub(bt);
                    let mut tv = libc::timeval {
                        tv_sec: (dbt / 1000) as i64,
                        tv_usec: (dbt % 1000 * 1000) as i64,
                    };
                    // SAFETY: fd_set manipulation and select on a valid fd.
                    let r = unsafe {
                        let mut set: libc::fd_set = std::mem::zeroed();
                        libc::FD_ZERO(&mut set);
                        libc::FD_SET(fd, &mut set);
                        libc::select(
                            fd + 1,
                            &mut set,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                            &mut tv,
                        )
                    };
                    if quit_requested() {
                        dlog_condup!("quit requested\n");
                        return 0;
                    }
                    if r == -1 {
                        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                            continue;
                        }
                        dlog_perror("select");
                        return 1;
                    }
                    res = r;
                } else {
                    bt_next = 0;
                    if quit_requested() {
                        dlog_condup!("quit requested\n");
                        return 0;
                    }
                    res = 1;
                }
                lua::lua_do_gc();
                reload_check();
                if res != 0 {
                    // SAFETY: buf is valid for its length.
                    rd = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
                    if rd < 0 {
                        break;
                    }
                    if rd == 0 {
                        dlog_err!("recv from nfq returned 0 !\n");
                        return 1;
                    }
                    if p.filter_ssid_present && !crate::wlan::wlan_info_get_rate_limited() {
                        dlog_err!("cannot get wlan info\n");
                    }
                    // SAFETY: buffer holds rd bytes read from the queue socket.
                    let r = unsafe {
                        nfq_handle_packet(nfq.h, buf.as_mut_ptr() as *mut c_char, rd as c_int)
                    };
                    if r < 0 {
                        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                        dlog_err!(
                            "nfq_handle_packet result {}, errno {} : {}\n",
                            r,
                            e,
                            crate::log::strerror(e)
                        );
                    }
                }
                if !p.timers.borrow().is_empty() {
                    let bt = boottime_ms();
                    if bt >= bt_next {
                        bt_next = timer_pool_run(bt);
                    } else if p.timers_dirty.get() {
                        bt_next = 0;
                    }
                }
            }
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EINTR {
                continue;
            }
            dlog_err!("recv: recv={} errno {}\n", rd, e);
            crate::log::dlog_perror_errno("recv", e);
            if e != libc::ENOBUFS {
                return 1;
            }
        }
    })();
    drop(fpid);
    nfq.deinit();
    if cb.sock >= 0 {
        // SAFETY: our socket.
        unsafe { libc::close(cb.sock) };
    }
    lua::lua_shutdown();
    crate::wlan::wlan_info_deinit();
    rawsend_cleanup();
    res
}

struct OptDef {
    name: &'static CStr,
    has_arg: c_int,
}
const NO: c_int = 0;
const REQ: c_int = 1;
const OPT: c_int = 2;

const OPTS: &[OptDef] = &[
    OptDef {
        name: c"debug",
        has_arg: OPT,
    },
    OptDef {
        name: c"dry-run",
        has_arg: NO,
    },
    OptDef {
        name: c"intercept",
        has_arg: OPT,
    },
    OptDef {
        name: c"fuzz",
        has_arg: REQ,
    },
    OptDef {
        name: c"version",
        has_arg: NO,
    },
    OptDef {
        name: c"comment",
        has_arg: OPT,
    },
    OptDef {
        name: c"qnum",
        has_arg: REQ,
    },
    OptDef {
        name: c"bind-fix4",
        has_arg: NO,
    },
    OptDef {
        name: c"bind-fix6",
        has_arg: NO,
    },
    OptDef {
        name: c"daemon",
        has_arg: NO,
    },
    OptDef {
        name: c"chdir",
        has_arg: OPT,
    },
    OptDef {
        name: c"pidfile",
        has_arg: REQ,
    },
    OptDef {
        name: c"user",
        has_arg: REQ,
    },
    OptDef {
        name: c"uid",
        has_arg: REQ,
    },
    OptDef {
        name: c"ctrack-timeouts",
        has_arg: REQ,
    },
    OptDef {
        name: c"ctrack-disable",
        has_arg: OPT,
    },
    OptDef {
        name: c"payload-disable",
        has_arg: OPT,
    },
    OptDef {
        name: c"server",
        has_arg: OPT,
    },
    OptDef {
        name: c"ipcache-lifetime",
        has_arg: REQ,
    },
    OptDef {
        name: c"ipcache-hostname",
        has_arg: OPT,
    },
    OptDef {
        name: c"reasm-disable",
        has_arg: OPT,
    },
    OptDef {
        name: c"fwmark",
        has_arg: REQ,
    },
    OptDef {
        name: c"writable",
        has_arg: OPT,
    },
    OptDef {
        name: c"blob",
        has_arg: REQ,
    },
    OptDef {
        name: c"lua-init",
        has_arg: REQ,
    },
    OptDef {
        name: c"lua-gc",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist-domains",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist-exclude",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist-exclude-domains",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist-auto",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist-auto-fail-threshold",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist-auto-fail-time",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist-auto-retrans-threshold",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist-auto-retrans-maxseq",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist-auto-retrans-reset",
        has_arg: OPT,
    },
    OptDef {
        name: c"hostlist-auto-incoming-maxseq",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist-auto-udp-in",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist-auto-udp-out",
        has_arg: REQ,
    },
    OptDef {
        name: c"hostlist-auto-debug",
        has_arg: REQ,
    },
    OptDef {
        name: c"new",
        has_arg: OPT,
    },
    OptDef {
        name: c"skip",
        has_arg: NO,
    },
    OptDef {
        name: c"name",
        has_arg: REQ,
    },
    OptDef {
        name: c"template",
        has_arg: OPT,
    },
    OptDef {
        name: c"import",
        has_arg: REQ,
    },
    OptDef {
        name: c"cookie",
        has_arg: REQ,
    },
    OptDef {
        name: c"filter-l3",
        has_arg: REQ,
    },
    OptDef {
        name: c"filter-tcp",
        has_arg: REQ,
    },
    OptDef {
        name: c"filter-udp",
        has_arg: REQ,
    },
    OptDef {
        name: c"filter-icmp",
        has_arg: REQ,
    },
    OptDef {
        name: c"filter-ipp",
        has_arg: REQ,
    },
    OptDef {
        name: c"filter-l7",
        has_arg: REQ,
    },
    OptDef {
        name: c"filter-ssid",
        has_arg: REQ,
    },
    OptDef {
        name: c"filter-ssid-neg",
        has_arg: OPT,
    },
    OptDef {
        name: c"filter-mark",
        has_arg: REQ,
    },
    OptDef {
        name: c"ipset",
        has_arg: REQ,
    },
    OptDef {
        name: c"ipset-ip",
        has_arg: REQ,
    },
    OptDef {
        name: c"ipset-exclude",
        has_arg: REQ,
    },
    OptDef {
        name: c"ipset-exclude-ip",
        has_arg: REQ,
    },
    OptDef {
        name: c"payload",
        has_arg: REQ,
    },
    OptDef {
        name: c"in-range",
        has_arg: REQ,
    },
    OptDef {
        name: c"out-range",
        has_arg: REQ,
    },
    OptDef {
        name: c"lua-desync",
        has_arg: REQ,
    },
];

/// sscanf("0x%X") then ("%u") as the C fwmark/filter-mark parsing does.
fn scan_hex_or_u(s: &str) -> Option<u32> {
    if let Some(r) = s.strip_prefix("0x") {
        let b = r.as_bytes();
        let mut i = 0;
        while i < b.len() && matches!(b[i], b' ' | b'\t' | b'\n') {
            i += 1;
        }
        let mut neg = false;
        if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
            neg = b[i] == b'-';
            i += 1;
        }
        // %X accepts an optional 0x prefix too
        if i + 1 < b.len()
            && b[i] == b'0'
            && (b[i + 1] == b'x' || b[i + 1] == b'X')
            && b.get(i + 2).is_some_and(|c| c.is_ascii_hexdigit())
        {
            i += 2;
        }
        let st = i;
        let mut v: u64 = 0;
        let mut ov = false;
        while i < b.len() && b[i].is_ascii_hexdigit() {
            match v
                .checked_mul(16)
                .and_then(|x| x.checked_add((b[i] as char).to_digit(16).unwrap_or(0) as u64))
            {
                Some(x) => v = x,
                None => ov = true,
            }
            i += 1;
        }
        if i > st {
            let v = if ov {
                u64::MAX
            } else if neg {
                v.wrapping_neg()
            } else {
                v
            };
            return Some(v as u32);
        }
    }
    scan_u(s.as_bytes()).map(|(v, _)| v)
}

pub fn main() -> i32 {
    let mut args: Vec<CString> = std::env::args_os()
        .map(|a| {
            CString::new(std::os::unix::ffi::OsStrExt::as_bytes(a.as_os_str())).unwrap_or_default()
        })
        .collect();
    let verstr = format!(
        "self-built version {} lua_compat_ver {}",
        env!("NFQWS2_BUILD_DATE_TIME"),
        LUA_COMPAT_VER
    );
    fwrite_std(false, format!("{verstr}\n\n").as_bytes());

    if args.len() < 2 {
        exithelp();
    }
    srandom(time_now() as u32);
    set_env_exedir(&args[0].to_string_lossy());
    set_console_io_buffering();

    let mut p = Params {
        verstr,
        ..Default::default()
    };
    apply_default_blobs(&mut p.blobs.borrow_mut());

    let mut profile_count: u32 = 0;
    let mut template_count: u32 = 0;
    let mut b_template = false;
    let mut b_skip = false;
    let mut b_dry = false;
    let mut dp = Rc::new(RefCell::new(DesyncProfile::default()));
    p.desync_profiles.borrow_mut().push(dp.clone());
    profile_count += 1;
    dp.borrow_mut().n = profile_count;

    let mut wexp = WordExp {
        we_wordc: 0,
        we_wordv: std::ptr::null_mut(),
        we_offs: 0,
    };
    let first = args[1].as_bytes().first().copied();
    let mut argv: Vec<*mut c_char>;
    if first == Some(b'@') || first == Some(b'$') {
        let fname = String::from_utf8_lossy(&args[1].as_bytes()[1..]).into_owned();
        let Some(data) = load_file(&fname, 0, MAX_CONFIG_FILE_SIZE - 3) else {
            dlog_err!("could not load config file '{}'\n", fname);
            exit_clean(1);
        };
        let mut b = b"x ".to_vec();
        b.extend_from_slice(&data);
        let b: Vec<u8> = b
            .iter()
            .map(|&c| {
                if c == b'\n' || c == b'\r' || c == b'\t' {
                    b' '
                } else {
                    c
                }
            })
            .collect();
        let b = b.split(|&c| c == 0).next().unwrap_or(&[]).to_vec();
        let c = CString::new(b).unwrap_or_default();
        // SAFETY: c is a valid C string; wexp is initialized by wordexp.
        if unsafe {
            wordexp(c.as_ptr(), &mut wexp, 4 /* WRDE_NOCMD */)
        } != 0
        {
            dlog_err!(
                "failed to split command line options from file '{}'\n",
                fname
            );
            exit_clean(1);
        }
        // SAFETY: wordexp produced we_wordc valid pointers.
        argv = unsafe { std::slice::from_raw_parts(wexp.we_wordv, wexp.we_wordc).to_vec() };
    } else {
        argv = args.iter_mut().map(|a| a.as_ptr() as *mut c_char).collect();
    }
    let argc = argv.len() as c_int;
    argv.push(std::ptr::null_mut());

    let mut long: Vec<GetoptOption> = OPTS
        .iter()
        .map(|o| GetoptOption {
            name: o.name.as_ptr(),
            has_arg: o.has_arg,
            flag: std::ptr::null_mut(),
            val: 0,
        })
        .collect();
    long.push(GetoptOption {
        name: std::ptr::null(),
        has_arg: 0,
        flag: std::ptr::null_mut(),
        val: 0,
    });

    let mut anon_hl: Option<HostlistFileRef> = None;
    let mut anon_hl_ex: Option<HostlistFileRef> = None;
    let mut anon_ips: Option<IpsetFileRef> = None;
    let mut anon_ips_ex: Option<IpsetFileRef> = None;
    let mut payload_type: u64 = 0;
    let mut range_in = PACKET_RANGE_NEVER;
    let mut range_out = PACKET_RANGE_ALWAYS;

    loop {
        let mut idx: c_int = 0;
        // SAFETY: argv is a NULL-terminated array of C strings that outlives the loop.
        let v =
            unsafe { getopt_long_only(argc, argv.as_ptr(), c"".as_ptr(), long.as_ptr(), &mut idx) };
        if v == -1 {
            break;
        }
        if v != 0 {
            if b_dry {
                exit_clean(1);
            } else {
                exithelp_clean();
            }
        }
        // SAFETY: optarg is set by getopt for options with arguments.
        let oa: Option<String> = unsafe {
            if optarg.is_null() {
                None
            } else {
                Some(CStr::from_ptr(optarg).to_string_lossy().into_owned())
            }
        };
        let arg = || oa.clone().unwrap_or_default();
        let name = OPTS[idx as usize].name.to_str().unwrap_or("");
        let atoi_ = |s: &str| atoi(s.as_bytes());
        match name {
            "debug" => match &oa {
                Some(a) if a.starts_with('@') => {
                    let Some(f) = realpath_any(&a[1..]) else {
                        dlog_err!("bad file '{}'\n", &a[1..]);
                        exit_clean(1);
                    };
                    if std::fs::File::create(&f).is_err() {
                        fwrite_std(true, format!("cannot create {f}\n").as_bytes());
                        exit_clean(1);
                    }
                    LOG.with(|l| {
                        let mut l = l.borrow_mut();
                        l.debug = true;
                        l.target = LogTarget::File;
                        l.logfile = f;
                    });
                }
                Some(a) if a == "syslog" => {
                    LOG.with(|l| {
                        let mut l = l.borrow_mut();
                        l.debug = true;
                        l.target = LogTarget::Syslog;
                    });
                    // SAFETY: progname is a static C string.
                    unsafe { libc::openlog(c"nfqws2".as_ptr(), libc::LOG_PID, libc::LOG_USER) };
                }
                Some(a) if matches!(a.as_bytes().first(), Some(b'0'..=b'1')) => {
                    let d = atoi_(a) != 0;
                    LOG.with(|l| {
                        let mut l = l.borrow_mut();
                        l.debug = d;
                        l.target = LogTarget::Console;
                    });
                }
                Some(a) => {
                    fwrite_std(true, format!("invalid debug mode : {a}\n").as_bytes());
                    exit_clean(1);
                }
                None => LOG.with(|l| {
                    let mut l = l.borrow_mut();
                    l.debug = true;
                    l.target = LogTarget::Console;
                }),
            },
            "dry-run" => b_dry = true,
            "intercept" => p.intercept = oa.as_deref().is_none_or(|a| atoi_(a) != 0),
            "fuzz" => {
                p.fuzz = atoi_(&arg()) as u32;
                p.intercept = false;
            }
            "version" => exit_clean(0),
            "comment" => {}
            "qnum" => {
                p.qnum = atoi_(&arg());
                if p.qnum < 0 || p.qnum > 65535 {
                    dlog_err!("bad qnum\n");
                    exit_clean(1);
                }
            }
            "bind-fix4" => p.bind_fix4 = true,
            "bind-fix6" => p.bind_fix6 = true,
            "daemon" => p.daemon = true,
            "chdir" => {
                let d = oa.clone().or_else(|| std::env::var("EXEDIR").ok());
                let Some(d) = d else {
                    dlog_err!("chdir: directory unknown\n");
                    exit_clean(1);
                };
                dlog!("changing dir to '{}'\n", d);
                if std::env::set_current_dir(&d).is_err() {
                    dlog_perror("chdir");
                    exit_clean(1);
                }
            }
            "pidfile" => match realpath_any(&arg()) {
                Some(f) => p.pidfile = f,
                None => {
                    dlog_err!("bad file '{}'\n", arg());
                    exit_clean(1);
                }
            },
            "user" => {
                p.user = None;
                let c = CString::new(arg()).unwrap_or_default();
                // SAFETY: valid C string; result is read immediately.
                let pw = unsafe { libc::getpwnam(c.as_ptr()) };
                if pw.is_null() {
                    dlog_err!("non-existent username supplied\n");
                    exit_clean(1);
                }
                // SAFETY: pw is non-null.
                unsafe {
                    p.uid = (*pw).pw_uid;
                    p.gid = vec![(*pw).pw_gid];
                }
                p.user = Some(arg());
                p.droproot = true;
            }
            "uid" => {
                p.user = None;
                let Some((u, mut g)) = parse_uid(&arg()) else {
                    dlog_err!("--uid should be : uid[:gid,gid,...]\n");
                    exit_clean(1);
                };
                p.uid = u;
                if g.is_empty() {
                    g.push(0x7FFFFFFF);
                }
                p.gid = g;
                p.droproot = true;
            }
            "ctrack-timeouts" => {
                let a = arg();
                let mut vals = [
                    p.ctrack_t_syn,
                    p.ctrack_t_est,
                    p.ctrack_t_fin,
                    p.ctrack_t_udp,
                ];
                let mut n = 0;
                let mut rest = a.as_bytes();
                while n < 4 {
                    match scan_u(rest) {
                        Some((v, r)) => {
                            vals[n] = v;
                            n += 1;
                            match r.strip_prefix(b":") {
                                Some(r2) => rest = r2,
                                None => break,
                            }
                        }
                        None => break,
                    }
                }
                [
                    p.ctrack_t_syn,
                    p.ctrack_t_est,
                    p.ctrack_t_fin,
                    p.ctrack_t_udp,
                ] = vals;
                if n < 3 {
                    dlog_err!("invalid ctrack-timeouts value\n");
                    exit_clean(1);
                }
            }
            "ctrack-disable" => p.ctrack_disable = oa.as_deref().is_none_or(|a| atoi_(a) != 0),
            "server" => p.server = oa.as_deref().is_none_or(|a| atoi_(a) != 0),
            "ipcache-lifetime" => match scan_u(arg().as_bytes()) {
                Some((v, _)) => p.ipcache_lifetime = v,
                None => {
                    dlog_err!("invalid ipcache-lifetime value\n");
                    exit_clean(1);
                }
            },
            "ipcache-hostname" => p.cache_hostname = oa.as_deref().is_none_or(|a| atoi_(a) != 0),
            "payload-disable" => match &oa {
                Some(a) => match parse_l7p_list(a) {
                    Some(v) => p.payload_disable = v,
                    None => {
                        dlog_err!("Invalid payload filter : {}\n", a);
                        exit_clean(1);
                    }
                },
                None => p.payload_disable = L7P_ALL as u64,
            },
            "reasm-disable" => match &oa {
                Some(a) => match parse_l7p_list(a) {
                    Some(v) => p.reasm_payload_disable = v,
                    None => {
                        dlog_err!("Invalid l7 protocol list : {}\n", a);
                        exit_clean(1);
                    }
                },
                None => p.reasm_payload_disable = L7P_ALL as u64,
            },
            "fwmark" => {
                p.desync_fwmark = scan_hex_or_u(&arg()).unwrap_or(0);
                if p.desync_fwmark == 0 {
                    dlog_err!("fwmark/sockarg should be decimal or 0xHEX and should not be zero\n");
                    exit_clean(1);
                }
            }
            "writable" => {
                p.writable_dir_enable = true;
                match &oa {
                    Some(a) => match realpath_any(a) {
                        Some(d) => p.writable_dir = d,
                        None => {
                            dlog_err!("bad file '{}'\n", a);
                            exit_clean(1);
                        }
                    },
                    None => p.writable_dir.clear(),
                }
            }
            "blob" => load_blob_to_collection(
                &arg(),
                &mut p.blobs.borrow_mut(),
                MAX_BLOB_SIZE,
                BLOB_EXTRA_BYTES,
            ),
            "lua-init" => {
                let a = arg();
                let s = if let Some(f) = a.strip_prefix('@') {
                    match realpath_any(f) {
                        Some(r) => format!("@{}", trunc(r, 4096)),
                        None => {
                            dlog_err!("bad file '{}'\n", f);
                            exit_clean(1);
                        }
                    }
                } else {
                    a
                };
                p.lua_init_scripts.push(s);
            }
            "lua-gc" => {
                let i = atoi_(&arg());
                if i < 0 {
                    dlog_err!("lua-gc must be >=0\n");
                    exit_clean(1);
                }
                p.lua_gc = (i as u64).wrapping_mul(1000);
            }
            "hostlist" | "hostlist-exclude" => {
                if b_skip {
                    continue;
                }
                let ex = name == "hostlist-exclude";
                if register_hostlist(&p.hostlists, &mut dp.borrow_mut(), ex, Some(&arg()), false)
                    .is_none()
                {
                    dlog_err!("failed to register hostlist '{}'\n", arg());
                    exit_clean(1);
                }
            }
            "hostlist-domains" | "hostlist-exclude-domains" => {
                if b_skip {
                    continue;
                }
                let ex = name == "hostlist-exclude-domains";
                let slot = if ex { &mut anon_hl_ex } else { &mut anon_hl };
                if slot.is_none() {
                    match register_hostlist(&p.hostlists, &mut dp.borrow_mut(), ex, None, false) {
                        Some(h) => *slot = Some(h),
                        None => {
                            dlog_err!("failed to register anonymous hostlist\n");
                            exit_clean(1);
                        }
                    }
                }
                if let Some(h) = slot {
                    let mut hb = h.borrow_mut();
                    for d in arg().split(',') {
                        if !d.is_empty() {
                            append_hostlist_item(
                                hb.hostlist.get_or_insert_with(Default::default),
                                d,
                            );
                        }
                    }
                }
            }
            "hostlist-auto" => {
                if b_skip {
                    continue;
                }
                if dp.borrow().hostlist_auto.is_some() {
                    dlog_err!("only one auto hostlist per profile is supported\n");
                    exit_clean(1);
                }
                let a = arg();
                let f = std::fs::OpenOptions::new()
                    .append(true)
                    .read(true)
                    .create(true)
                    .open(&a);
                match f {
                    Err(_) => {
                        dlog_err!("cannot create {}\n", a);
                        exit_clean(1);
                    }
                    Ok(_) => {
                        if is_gzip_file_any(&a) {
                            dlog_err!("gzipped auto hostlists are not supported\n");
                            exit_clean(1);
                        }
                    }
                }
                let r =
                    register_hostlist(&p.hostlists, &mut dp.borrow_mut(), false, Some(&a), true);
                match r {
                    Some(h) => dp.borrow_mut().hostlist_auto = Some(h),
                    None => {
                        dlog_err!("failed to register hostlist '{}'\n", a);
                        exit_clean(1);
                    }
                }
            }
            "hostlist-auto-fail-threshold" => {
                let v = atoi_(&arg());
                let mut d = dp.borrow_mut();
                d.hostlist_auto_fail_threshold = v;
                if !(1..=20).contains(&v) {
                    dlog_err!("auto hostlist fail threshold must be within 1..20\n");
                    exit_clean(1);
                }
                d.b_hostlist_auto_fail_threshold = true;
            }
            "hostlist-auto-fail-time" => {
                let v = atoi_(&arg());
                let mut d = dp.borrow_mut();
                d.hostlist_auto_fail_time = v;
                if v < 1 {
                    dlog_err!("auto hostlist fail time is not valid\n");
                    exit_clean(1);
                }
                d.b_hostlist_auto_fail_time = true;
            }
            "hostlist-auto-retrans-threshold" => {
                let v = atoi_(&arg());
                let mut d = dp.borrow_mut();
                d.hostlist_auto_retrans_threshold = v;
                if !(2..=10).contains(&v) {
                    dlog_err!("auto hostlist fail threshold must be within 2..10\n");
                    exit_clean(1);
                }
                d.b_hostlist_auto_retrans_threshold = true;
            }
            "hostlist-auto-retrans-maxseq" => {
                let mut d = dp.borrow_mut();
                d.hostlist_auto_retrans_maxseq = atoi_(&arg()) as u32;
                d.b_hostlist_auto_retrans_maxseq = true;
            }
            "hostlist-auto-incoming-maxseq" => {
                let mut d = dp.borrow_mut();
                d.hostlist_auto_incoming_maxseq = atoi_(&arg()) as u32;
                d.b_hostlist_auto_incoming_maxseq = true;
            }
            "hostlist-auto-retrans-reset" => {
                let mut d = dp.borrow_mut();
                d.hostlist_auto_retrans_reset = oa.as_deref().is_none_or(|a| atoi_(a) != 0);
                d.b_hostlist_auto_retrans_reset = true;
            }
            "hostlist-auto-udp-out" => {
                let mut d = dp.borrow_mut();
                d.hostlist_auto_udp_out = atoi_(&arg());
                d.b_hostlist_auto_udp_out = true;
            }
            "hostlist-auto-udp-in" => {
                let mut d = dp.borrow_mut();
                d.hostlist_auto_udp_in = atoi_(&arg());
                d.b_hostlist_auto_udp_in = true;
            }
            "hostlist-auto-debug" => {
                let a = arg();
                let Some(f) = realpath_any(&a) else {
                    dlog_err!("bad file '{}'\n", a);
                    exit_clean(1);
                };
                if std::fs::OpenOptions::new()
                    .append(true)
                    .read(true)
                    .create(true)
                    .open(&f)
                    .is_err()
                {
                    dlog_err!("cannot create {}\n", a);
                    exit_clean(1);
                }
                LOG.with(|l| l.borrow_mut().hostlist_auto_debuglog = f);
            }
            "new" => {
                if b_skip {
                    let mut d = dp.borrow_mut();
                    *d = DesyncProfile::default();
                    d.n = profile_count;
                    b_skip = false;
                } else {
                    if b_template {
                        let nm = dp.borrow().name.clone();
                        if let Some(nm) = &nm {
                            if dp_list_search_name(&p.desync_templates.borrow(), nm).is_some() {
                                dlog_err!("template '{}' already present\n", nm);
                                exit_clean(1);
                            }
                        }
                        template_count += 1;
                        dp.borrow_mut().n = template_count;
                        p.desync_profiles
                            .borrow_mut()
                            .retain(|x| !Rc::ptr_eq(x, &dp));
                        p.desync_templates.borrow_mut().push(dp.clone());
                    } else {
                        profile_count += 1;
                    }
                    dp = Rc::new(RefCell::new(DesyncProfile::default()));
                    p.desync_profiles.borrow_mut().push(dp.clone());
                    dp.borrow_mut().n = profile_count;
                }
                if let Some(a) = &oa {
                    dp.borrow_mut().name = Some(a.clone());
                }
                anon_hl = None;
                anon_hl_ex = None;
                anon_ips = None;
                anon_ips_ex = None;
                payload_type = 0;
                range_in = PACKET_RANGE_NEVER;
                range_out = PACKET_RANGE_ALWAYS;
                b_template = false;
            }
            "skip" => b_skip = true,
            "template" | "name" => {
                if name == "template" {
                    b_template = true;
                }
                if let Some(a) = &oa {
                    dp.borrow_mut().name = Some(a.clone());
                }
            }
            "cookie" => dp.borrow_mut().cookie = Some(arg()),
            "import" => {
                let a = arg();
                let Some(tpl) = dp_list_search_name(&p.desync_templates.borrow(), &a) else {
                    dlog_err!("template '{}' not found\n", a);
                    exit_clean(1);
                };
                let t = tpl.borrow().clone();
                if !dp.borrow_mut().copy_from(&t) {
                    dlog_err!("could not copy template\n");
                    exit_clean(1);
                }
                dp.borrow_mut().n = profile_count;
            }
            "filter-l3" => {
                let mut d = dp.borrow_mut();
                let (mut v4, mut v6) = (d.filter_ipv4, d.filter_ipv6);
                if !wf_make_l3(&arg(), &mut v4, &mut v6) {
                    dlog_err!("bad value for --filter-l3\n");
                    exit_clean(1);
                }
                d.filter_ipv4 = v4;
                d.filter_ipv6 = v6;
                d.b_filter_l3 = true;
            }
            "filter-tcp" | "filter-udp" => {
                let mut d = dp.borrow_mut();
                let list = if name == "filter-tcp" {
                    &mut d.pf_tcp
                } else {
                    &mut d.pf_udp
                };
                for s in arg().split(',') {
                    match pf_parse(s) {
                        Some(pf) => list.add(pf),
                        None => {
                            dlog_err!("Invalid port filter : {}\n", arg());
                            exit_clean(1);
                        }
                    }
                }
            }
            "filter-icmp" => {
                let mut d = dp.borrow_mut();
                for s in arg().split(',') {
                    match icf_parse(s) {
                        Some(f) => d.icf.add(f),
                        None => {
                            dlog_err!("Invalid icmp filter : {}\n", arg());
                            exit_clean(1);
                        }
                    }
                }
            }
            "filter-ipp" => {
                let mut d = dp.borrow_mut();
                for s in arg().split(',') {
                    match ipp_parse(s) {
                        Some(f) => d.ipf.add(f),
                        None => {
                            dlog_err!("Invalid ip protocol filter : {}\n", arg());
                            exit_clean(1);
                        }
                    }
                }
            }
            "filter-l7" => match parse_l7_list(&arg()) {
                Some(v) => {
                    let mut d = dp.borrow_mut();
                    d.filter_l7 = v;
                    d.b_filter_l7 = true;
                }
                None => {
                    dlog_err!("Invalid l7 filter : {}\n", arg());
                    exit_clean(1);
                }
            },
            "filter-ssid" => {
                let mut d = dp.borrow_mut();
                for s in arg().split(',') {
                    if !s.is_empty() {
                        d.filter_ssid.insert(0, s.to_string());
                    }
                }
                p.filter_ssid_present = true;
            }
            "filter-ssid-neg" => {
                dp.borrow_mut().filter_ssid_neg = oa.as_deref().is_none_or(|a| atoi_(a) != 0)
            }
            "filter-mark" => {
                let a = arg();
                let (m, mask) = match a.find('/') {
                    Some(i) => (a[..i].to_string(), Some(a[i + 1..].to_string())),
                    None => (a.clone(), None),
                };
                let Some(mv) = scan_hex_or_u(&m) else {
                    dlog_err!("filter mark or mask format error\n");
                    exit_clean(1);
                };
                let mut d = dp.borrow_mut();
                d.filter_mark = mv;
                match mask {
                    Some(mk) => match scan_hex_or_u(&mk) {
                        Some(v) => d.filter_mark_mask = v,
                        None => {
                            dlog_err!("filter mark or mask format error\n");
                            exit_clean(1);
                        }
                    },
                    None => d.filter_mark_mask = 0xFFFFFFFF,
                }
            }
            "ipset" | "ipset-exclude" => {
                if b_skip {
                    continue;
                }
                let ex = name == "ipset-exclude";
                if register_ipset(&p.ipsets, &mut dp.borrow_mut(), ex, Some(&arg())).is_none() {
                    dlog_err!("failed to register ipset '{}'\n", arg());
                    exit_clean(1);
                }
            }
            "ipset-ip" | "ipset-exclude-ip" => {
                if b_skip {
                    continue;
                }
                let ex = name == "ipset-exclude-ip";
                let slot = if ex { &mut anon_ips_ex } else { &mut anon_ips };
                if slot.is_none() {
                    match register_ipset(&p.ipsets, &mut dp.borrow_mut(), ex, None) {
                        Some(h) => *slot = Some(h),
                        None => {
                            dlog_err!("failed to register anonymous ipset\n");
                            exit_clean(1);
                        }
                    }
                }
                if let Some(h) = slot {
                    let mut hb = h.borrow_mut();
                    for d in arg().split(',') {
                        if !d.is_empty() {
                            append_ipset_item(&mut hb.ipset, d);
                        }
                    }
                }
            }
            "payload" => match parse_l7p_list(&arg()) {
                Some(v) => payload_type = v,
                None => {
                    dlog_err!("Invalid payload filter : {}\n", arg());
                    exit_clean(1);
                }
            },
            "out-range" | "in-range" => match packet_range_parse(&arg()) {
                Some(r) => {
                    if name == "out-range" {
                        range_out = r
                    } else {
                        range_in = r
                    }
                }
                None => {
                    dlog_err!("invalid packet range value : {}\n", arg());
                    exit_clean(1);
                }
            },
            "lua-desync" => {
                let mut d = dp.borrow_mut();
                if let Err(shown) = parse_lua_call(&arg(), &mut d.lua_desync) {
                    dlog_err!("invalid lua function call : {}\n", shown);
                    exit_clean(1);
                }
                // INFALLIBLE: parse_lua_call just pushed an entry
                if let Some(f) = d.lua_desync.last_mut() {
                    f.payload_type = payload_type;
                    f.range_in = range_in;
                    f.range_out = range_out;
                }
            }
            _ => {}
        }
    }
    if b_skip {
        p.desync_profiles
            .borrow_mut()
            .retain(|x| !Rc::ptr_eq(x, &dp));
        profile_count -= 1;
    } else if b_template {
        let nm = dp.borrow().name.clone();
        if let Some(nm) = &nm {
            if dp_list_search_name(&p.desync_templates.borrow(), nm).is_some() {
                dlog_err!("template '{}' already present\n", nm);
                exit_clean(1);
            }
        }
        template_count += 1;
        dp.borrow_mut().n = template_count;
        p.desync_profiles
            .borrow_mut()
            .retain(|x| !Rc::ptr_eq(x, &dp));
        p.desync_templates.borrow_mut().push(dp.clone());
        profile_count -= 1;
    }
    drop(argv);

    if p.intercept && p.qnum < 0 {
        dlog_err!("Need queue number (--qnum)\n");
        exit_clean(1);
    }

    dlog!("adding low-priority default empty desync profile\n");
    let def = Rc::new(RefCell::new(DesyncProfile {
        name: Some("no_action".into()),
        ..Default::default()
    }));
    p.desync_profiles.borrow_mut().push(def);

    dlog_condup!(
        "we have {} user defined desync profile(s) and default low priority profile 0\n",
        profile_count
    );
    dlog_condup!(
        "we have {} user defined desync template(s)\n",
        template_count
    );

    if p.writable_dir_enable {
        if !make_writable_dir(&p.writable_dir, p.uid) {
            dlog_err!("could not make writable dir for LUA\n");
            exit_clean(1);
        }
        dlog!(
            "LUA writable dir : {}\n",
            std::env::var("WRITABLE").unwrap_or_default()
        );
    }

    let p = Rc::new(p);
    set_params(p.clone());

    if p.droproot {
        let (target, logfile, ahdl) = LOG.with(|l| {
            let l = l.borrow();
            (
                l.target,
                l.logfile.clone(),
                l.hostlist_auto_debuglog.clone(),
            )
        });
        if target == LogTarget::File && !ensure_file_access(&logfile, p.uid) {
            dlog_err!("could not make '{}' accessible. log file may not be writable after privilege drop\n", logfile);
        }
        if !ahdl.is_empty() && !ensure_file_access(&ahdl, p.uid) {
            dlog_err!("could not make '{}' accessible. auto hostlist debug log may not be writable after privilege drop\n", ahdl);
        }
    }
    let profiles = p.desync_profiles.borrow().clone();
    for dpr in &profiles {
        let mut d = dpr.borrow_mut();
        if p.server && d.hostlist_auto.is_some() {
            dlog_err!("autohostlists not supported in server mode\n");
            exit_clean(1);
        }
        if p.droproot {
            if let Some(ha) = &d.hostlist_auto {
                let f = ha.borrow().filename.clone().unwrap_or_default();
                if !ensure_file_access(&f, p.uid) {
                    dlog_err!("could not make '{}' accessible. auto hostlist file may not be writable after privilege drop\n", f);
                }
            }
        }
        if !filter_defaults(&mut d) {
            exit_clean(1);
        }
        lua_desync_debug(&d, "profile");
    }
    for dpr in p.desync_templates.borrow().iter() {
        lua_desync_debug(&dpr.borrow(), "template");
    }
    if !test_list_files() {
        exit_clean(1);
    }
    if !lua::lua_test_init_script_files() {
        exit_clean(1);
    }
    if !load_all_hostlists() {
        dlog_err!("hostlists load failed\n");
        exit_clean(1);
    }
    if !load_all_ipsets() {
        dlog_err!("ipset load failed\n");
        exit_clean(1);
    }
    dlog!("\nlists summary:\n");
    hostlists_debug();
    ipsets_debug();
    dlog!("\nblobs summary:\n");
    blob_debug();
    dlog!("\n");
    p.desync_templates.borrow_mut().clear();

    if b_dry {
        if p.droproot {
            if !crate::sec::droproot(p.uid, p.user.as_deref(), &p.gid) {
                exit_clean(1);
            }
            if !crate::sec::dropcaps() {
                exit_clean(1);
            }
            crate::sec::print_id();
            if !test_list_files() || !lua::lua_test_init_script_files() {
                exit_clean(1);
            }
        }
        dlog_condup!("command line parameters verified\n");
        exit_clean(0);
    }

    if p.ctrack_disable {
        dlog_condup!(
            "conntrack disabled ! some functions will not work. make sure it's what you want.\n"
        );
    } else {
        dlog!(
            "initializing conntrack with timeouts tcp={}:{}:{} udp={}\n",
            p.ctrack_t_syn,
            p.ctrack_t_est,
            p.ctrack_t_fin,
            p.ctrack_t_udp
        );
        p.conntrack.borrow_mut().init(
            10,
            p.ctrack_t_syn,
            p.ctrack_t_est,
            p.ctrack_t_fin,
            p.ctrack_t_udp,
        );
    }
    dlog!("ipcache lifetime {}s\n", p.ipcache_lifetime);
    let r = nfq_main();
    lua::lua_shutdown();
    fflush_all();
    r
}

fn is_gzip_file_any(path: &str) -> bool {
    crate::gzip::is_gzip_file(path)
}
