//! Port of lua.c: embedded LuaJIT, the C API exposed to scripts, init and teardown.
//! SAFETY: the Lua state pointer is created here, used only on this thread, and closed in
//! lua_shutdown; all raw API use goes through lj.rs (ADR-008).

pub mod api;
pub mod lj;
pub mod push;
pub mod zlib;

use crate::conntrack::CtrackRef;
use crate::darkmagic::*;
use crate::gzip::{Z_STREAM_END, is_gzip_bytes, z_readfile};
use crate::helpers::boottime_ms;
use crate::params::{DEFAULT_MSS, LUA_COMPAT_VER, ProfileRef, params};
use crate::{dlog, dlog_condup, dlog_err};
use lj::L;
use push::{guard_enter, guard_leave};
use std::cell::{Cell, RefCell};

thread_local! {
    static STATE: Cell<Option<L>> = const { Cell::new(None) };
    static REF_DESYNC_CTX: Cell<i32> = const { Cell::new(0) };
    static CTX: RefCell<DesyncCtx> = RefCell::new(DesyncCtx::default());
    static GC_TIME: Cell<u64> = const { Cell::new(0) };
}

/// t_lua_desync_context. The Lua side holds a marker userdata; the data lives here.
#[derive(Default)]
pub struct DesyncCtx {
    pub func_n: u32,
    pub func: String,
    pub instance: String,
    pub dp: Option<ProfileRef>,
    pub dp_n: u32,
    pub pkt: Vec<u8>,
    pub dis: Dissect,
    pub ctrack: Option<CtrackRef>,
    pub incoming: bool,
    pub cancel: bool,
    pub valid: bool,
}

pub fn ctx_with<T>(f: impl FnOnce(&mut DesyncCtx) -> T) -> T {
    CTX.with(|c| f(&mut c.borrow_mut()))
}

const MT_CTX: &std::ffi::CStr = c"desync_ctx";

/// Layout of the C original's t_lua_desync_context (lua.h); only its size is used:
/// 56 bytes on 64-bit targets, 28 on 32-bit ones.
#[repr(C)]
#[allow(dead_code)]
struct CDesyncCtx {
    func_n: std::os::raw::c_uint,
    func: *const u8,
    instance: *const u8,
    dp: *const u8,
    dis: *const u8,
    ctrack: *const u8,
    incoming: bool,
    cancel: bool,
    valid: bool,
}

/// lua_desync_ctx(): validates arg 1.
pub fn desync_ctx_check(l: L) {
    if lj::isnil(l, 1) {
        lj::error(l, "missing ctx");
    }
    lj::checkudata(l, 1, MT_CTX);
    if !ctx_with(|c| c.valid) {
        lj::error(l, "ctx is invalid");
    }
}

/// The process Lua state, if initialized.
pub fn state_opt() -> Option<L> {
    STATE.with(|s| s.get())
}
/// The process Lua state. Only called while Lua is initialized (desync runs after lua_init).
pub fn state() -> L {
    // INFALLIBLE: callers run only between lua_init and lua_shutdown
    state_opt().expect("lua state")
}
pub fn ref_desync_ctx() -> i32 {
    REF_DESYNC_CTX.with(|c| c.get())
}

/// New empty table stored in the registry (conntrack lua_state / instance cutoff).
pub fn new_table_ref() -> i32 {
    let Some(l) = state_opt() else {
        return lj::LUA_NOREF;
    };
    lj::newtable(l);
    lj::ref_(l)
}
pub fn unref(r: i32) {
    if let Some(l) = state_opt() {
        lj::unref(l, r)
    }
}

/// lua_dlog_error: report and pop the error at the top of the stack.
pub fn lua_dlog_error() {
    let l = state();
    lua_perror(l);
}

/// Run a timer callback: func(name, data). False on Lua error (already reported).
pub fn call_timer(func_ref: i32, name: &str, data_ref: i32) -> bool {
    let l = state();
    lj::rawgeti(l, lj::LUA_REGISTRYINDEX, func_ref as i64);
    lj::pushstr(l, name);
    lj::rawgeti(l, lj::LUA_REGISTRYINDEX, data_ref as i64);
    if lj::pcall(l, 2, 0) != 0 {
        lua_dlog_error();
        return false;
    }
    true
}

fn lua_perror(l: L) {
    if lj::isstring(l, -1) {
        let m = lj::tobytes(l, -1)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default();
        dlog_err!("LUA ERROR: {}\n", m);
    }
    lj::pop(l, 1);
}

fn lua_panic(l: L) -> i32 {
    lua_perror(l);
    dlog_err!("LUA PANIC: THIS IS FATAL. DYING.\n");
    crate::cffi::fflush_all();
    std::process::exit(100);
}

pub fn lua_shutdown() {
    let Some(l) = state_opt() else {
        return;
    };
    dlog!("LUA SHUTDOWN\n");
    // lua_cleanup
    let r = ref_desync_ctx();
    if r != 0 {
        lj::unref(l, r);
        REF_DESYNC_CTX.with(|c| c.set(0));
    }
    if let Some(p) = crate::params::params_opt() {
        p.conntrack.borrow_mut().pool.clear();
        p.timers.borrow_mut().0.clear();
    }
    // SAFETY: closing the state we created; nothing uses it afterwards.
    STATE.with(|s| s.set(None));
    // SAFETY: the only stored copy was just cleared; callers hold no copy past shutdown.
    unsafe { lj::close(l) };
}

fn lua_basic_init() -> bool {
    lua_shutdown();
    let Some(l) = lj::newstate() else {
        dlog_err!("LUA INIT ERROR\n");
        return false;
    };
    STATE.with(|s| s.set(Some(l)));
    lj::atpanic(l, crate::cfn!(lua_panic));
    lj::openlibs(l);
    dlog_condup!("LUA v{}.{} {}\n", 5, 1, env!("NFQWS2_LUAJIT_VERSION"));
    lj::getfield(l, lj::LUA_REGISTRYINDEX, "_LOADED");
    if lj::typ(l, -1) == lj::LUA_TTABLE {
        lj::getfield(l, -1, "jit");
        if lj::typ(l, -1) == lj::LUA_TTABLE {
            lj::getfield(l, -1, "status");
            if lj::typ(l, -1) == lj::LUA_TFUNCTION {
                let mut n = lj::gettop(l);
                lj::call(l, 0, lj::LUA_MULTRET);
                dlog_condup!(
                    "{}",
                    if lj::toboolean(l, n) {
                        "JIT: ON"
                    } else {
                        "JIT: OFF"
                    }
                );
                n += 1;
                while let Some(s) = lj::tobytes(l, n) {
                    dlog_condup!(" {}", String::from_utf8_lossy(&s));
                    n += 1;
                }
                dlog_condup!("\n");
            }
        }
    }
    lj::settop(l, 0);
    true
}

fn lua_sec_harden(l: L) {
    let g = guard_enter!(l);
    dlog!("LUA REMOVE:");
    let bad: [(&str, Option<&str>, Option<&str>); 5] = [
        ("os", Some("execute"), None),
        ("io", Some("popen"), None),
        ("package", Some("loadlib"), None),
        ("debug", None, None),
        ("package", Some("loaded"), Some("debug")),
    ];
    for (gname, f, f2) in bad {
        if let Some(f) = f {
            lj::getglobal(l, gname);
            if let Some(f2) = f2 {
                lj::getfield(l, -1, f);
                lj::pushstr(l, f2);
                dlog!(" {}.{}.{}", gname, f, f2);
            } else {
                lj::pushstr(l, f);
                dlog!(" {}.{}", gname, f);
            }
            lj::pushnil(l);
            lj::rawset(l, -3);
            lj::pop(l, 1 + f2.is_some() as i32);
        } else {
            lj::pushnil(l);
            lj::setglobal(l, gname);
            dlog!(" {}", gname);
        }
    }
    dlog!("\n");
    guard_leave!(l, g, 0);
}

fn lua_init_blobs(l: L) {
    let p = params();
    let blobs = std::mem::take(&mut p.blobs.borrow_mut().0);
    for b in blobs {
        let name = b.name.clone().unwrap_or_default();
        dlog!("LUA BLOB: {} (size={})\n", name, b.data.len());
        lj::pushbytes(l, &b.data);
        lj::setglobal(l, &name);
    }
}

fn lua_init_const(l: L) {
    let p = params();
    dlog!("LUA STR:");
    // ADR-009: the original's params.verstr is wiped by init_params() before Lua sees it
    let _ = &p.verstr;
    lj::pushstr(l, "");
    lj::setglobal(l, "NFQWS2_VER");
    dlog!(" {}", "NFQWS2_VER");
    let cuint: &[(&str, u32)] = &[
        ("qnum", p.qnum as u32),
        ("desync_fwmark", p.desync_fwmark),
        ("NFQWS2_COMPAT_VER", LUA_COMPAT_VER),
        ("VERDICT_PASS", VERDICT_PASS as u32),
        ("VERDICT_MODIFY", VERDICT_MODIFY as u32),
        ("VERDICT_DROP", VERDICT_DROP as u32),
        ("VERDICT_MASK", VERDICT_MASK as u32),
        ("VERDICT_PRESERVE_NEXT", VERDICT_PRESERVE_NEXT as u32),
        ("DEFAULT_MSS", DEFAULT_MSS as u32),
        ("IP_BASE_LEN", 20),
        ("IP6_BASE_LEN", 40),
        ("TCP_BASE_LEN", 20),
        ("UDP_BASE_LEN", 8),
        ("ICMP_BASE_LEN", 8),
        ("TCP_KIND_END", 0),
        ("TCP_KIND_NOOP", 1),
        ("TCP_KIND_MSS", 2),
        ("TCP_KIND_SCALE", 3),
        ("TCP_KIND_SACK_PERM", 4),
        ("TCP_KIND_SACK", 5),
        ("TCP_KIND_TS", 8),
        ("TCP_KIND_MD5", 19),
        ("TCP_KIND_AO", 29),
        ("TCP_KIND_FASTOPEN", 34),
        ("TH_FIN", 0x01),
        ("TH_SYN", 0x02),
        ("TH_RST", 0x04),
        ("TH_PUSH", 0x08),
        ("TH_ACK", 0x10),
        ("TH_FIN", 0x01),
        ("TH_URG", 0x20),
        ("TH_ECE", 0x40),
        ("TH_CWR", 0x80),
        ("IP_RF", 0x8000),
        ("IP_DF", 0x4000),
        ("IP_MF", 0x2000),
        ("IP_OFFMASK", 0x1fff),
        ("IP_FLAGMASK", 0xE000),
        ("IPTOS_ECN_MASK", 0x03),
        ("IPTOS_ECN_NOT_ECT", 0),
        ("IPTOS_ECN_ECT1", 0x01),
        ("IPTOS_ECN_ECT0", 0x02),
        ("IPTOS_ECN_CE", 0x03),
        ("IPTOS_DSCP_MASK", 0xFC),
        ("IP6F_MORE_FRAG", 0x0001),
        ("IPV6_FLOWLABEL_MASK", 0x000FFFFF),
        ("IPV6_FLOWINFO_MASK", 0x0FFFFFFF),
        ("IPPROTO_IP", 0),
        ("IPPROTO_IPIP", 4),
        ("IPPROTO_IPV6", 41),
        ("IPPROTO_ICMP", 1),
        ("IPPROTO_TCP", 6),
        ("IPPROTO_UDP", 17),
        ("IPPROTO_ICMPV6", 58),
        ("IPPROTO_SCTP", 132),
        ("IPPROTO_HOPOPTS", 0),
        ("IPPROTO_ROUTING", 43),
        ("IPPROTO_FRAGMENT", 44),
        ("IPPROTO_AH", 51),
        ("IPPROTO_ESP", 50),
        ("IPPROTO_DSTOPTS", 60),
        ("IPPROTO_MH", 135),
        ("IPPROTO_HIP", 139),
        ("IPPROTO_SHIM6", 140),
        ("IPPROTO_NONE", 59),
        ("ICMP_ECHOREPLY", 0),
        ("ICMP_DEST_UNREACH", 3),
        ("ICMP_REDIRECT", 5),
        ("ICMP_ECHO", 8),
        ("ICMP_TIME_EXCEEDED", 11),
        ("ICMP_PARAMETERPROB", 12),
        ("ICMP_TIMESTAMP", 13),
        ("ICMP_TIMESTAMPREPLY", 14),
        ("ICMP_INFO_REQUEST", 15),
        ("ICMP_INFO_REPLY", 16),
        ("ICMP_UNREACH_NET", 0),
        ("ICMP_UNREACH_HOST", 1),
        ("ICMP_UNREACH_PROTOCOL", 2),
        ("ICMP_UNREACH_PORT", 3),
        ("ICMP_UNREACH_NEEDFRAG", 4),
        ("ICMP_UNREACH_SRCFAIL", 5),
        ("ICMP_UNREACH_NET_UNKNOWN", 6),
        ("ICMP_UNREACH_HOST_UNKNOWN", 7),
        ("ICMP_UNREACH_NET_PROHIB", 9),
        ("ICMP_UNREACH_HOST_PROHIB", 10),
        ("ICMP_UNREACH_TOSNET", 11),
        ("ICMP_UNREACH_TOSHOST", 12),
        ("ICMP_UNREACH_FILTER_PROHIB", 13),
        ("ICMP_UNREACH_HOST_PRECEDENCE", 14),
        ("ICMP_UNREACH_PRECEDENCE_CUTOFF", 15),
        ("ICMP_REDIRECT_NET", 0),
        ("ICMP_REDIRECT_HOST", 1),
        ("ICMP_REDIRECT_TOSNET", 2),
        ("ICMP_REDIRECT_TOSHOST", 3),
        ("ICMP_TIMXCEED_INTRANS", 0),
        ("ICMP_TIMXCEED_REASS", 1),
        ("ICMP6_ECHO_REQUEST", 128),
        ("ICMP6_ECHO_REPLY", 129),
        ("ICMP6_DST_UNREACH", 1),
        ("ICMP6_PACKET_TOO_BIG", 2),
        ("ICMP6_TIME_EXCEEDED", 3),
        ("ICMP6_PARAM_PROB", 4),
        ("MLD_LISTENER_QUERY", 130),
        ("MLD_LISTENER_REPORT", 131),
        ("MLD_LISTENER_REDUCTION", 132),
        ("ND_ROUTER_SOLICIT", 133),
        ("ND_ROUTER_ADVERT", 134),
        ("ND_NEIGHBOR_SOLICIT", 135),
        ("ND_NEIGHBOR_ADVERT", 136),
        ("ND_REDIRECT", 137),
        ("ICMP6_DST_UNREACH_NOROUTE", 0),
        ("ICMP6_DST_UNREACH_ADMIN", 1),
        ("ICMP6_DST_UNREACH_BEYONDSCOPE", 2),
        ("ICMP6_DST_UNREACH_ADDR", 3),
        ("ICMP6_DST_UNREACH_NOPORT", 4),
        ("ICMP6_TIME_EXCEED_TRANSIT", 0),
        ("ICMP6_TIME_EXCEED_REASSEMBLY", 1),
        ("ICMP6_PARAMPROB_HEADER", 0),
        ("ICMP6_PARAMPROB_NEXTHEADER", 1),
        ("ICMP6_PARAMPROB_OPTION", 2),
    ];
    dlog!("\nLUA NUMERIC:");
    for (n, v) in cuint {
        lj::pushinteger(l, *v as i64);
        lj::setglobal(l, n);
        dlog!(" {}", n);
    }
    dlog!("\nLUA BOOL:");
    let cbool = [
        ("b_debug", crate::log::debug()),
        ("b_daemon", p.daemon),
        ("b_server", p.server),
        ("b_ipcache_hostname", p.cache_hostname),
        ("b_ctrack_disable", p.ctrack_disable),
    ];
    for (n, v) in cbool {
        lj::pushboolean(l, v);
        lj::setglobal(l, n);
        dlog!(" {}", n);
    }
    dlog!("\n");
}

fn lua_init_mt(l: L) {
    zlib::mt_init(l);
    lj::newmetatable(l, MT_CTX);
    lj::pop(l, 1);
    if ref_desync_ctx() == 0 {
        let g = guard_enter!(l);
        // The data lives in CTX; the userdata only has the C size (Lua heap accounting).
        lj::newuserdata(l, std::mem::size_of::<CDesyncCtx>());
        lj::getmetatable_reg(l, MT_CTX);
        lj::setmetatable(l, -2);
        REF_DESYNC_CTX.with(|c| c.set(lj::ref_(l)));
        ctx_with(|c| *c = DesyncCtx::default());
        guard_leave!(l, g, 0);
    }
}

/// lua_file_open_test: (exists, is_gzip, actual filename)
fn file_open_test(filename: &str) -> Option<(bool, String)> {
    let try_open = |f: &str| {
        std::fs::File::open(f).ok().map(|mut fh| {
            use std::io::Read;
            let mut m = [0u8; 2];
            let n = fh.read(&mut m).unwrap_or(0);
            is_gzip_bytes(&m[..n])
        })
    };
    if let Some(gz) = try_open(filename) {
        return Some((gz, filename.to_string()));
    }
    let fngz = format!("{filename}.gz");
    try_open(&fngz).map(|gz| (gz, fngz))
}

pub fn lua_test_init_script_files() -> bool {
    for s in &params().lua_init_scripts {
        if let Some(f) = s.strip_prefix('@')
            && file_open_test(f).is_none()
        {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            dlog_err!("LUA file '{}' or '{}.gz' not accessible\n", f, f);
            if e == libc::EACCES {
                dlog_err!(
                    "I drop my privileges and do not run Lua as root\ncheck file permissions and +x rights on all directories in the path\n"
                );
            }
            return false;
        }
    }
    true
}

/// The C original raises luaL_error outside any protected call here, which ends in the
/// panic handler: report and exit(100) the same way.
fn unprotected_error(l: L, msg: &str) -> ! {
    lj::pushstr(l, msg);
    lua_panic(l);
    std::process::exit(100);
}

/// luaL_doZfile
fn do_zfile(l: L, filename: &str) -> i32 {
    let Some((gz, fname)) = file_open_test(filename) else {
        unprotected_error(
            l,
            &format!("could not open lua file '{filename}' or '{filename}.gz'"),
        );
    };
    if gz {
        let Ok(mut f) = std::fs::File::open(&fname) else {
            unprotected_error(l, &format!("could not open lua file '{fname}'"));
        };
        let (r, buf) = z_readfile(&mut f);
        if r != Z_STREAM_END {
            unprotected_error(l, &format!("could not unzip lua file '{fname}'"));
        }
        let r = lj::loadbuffer(l, &buf, &fname);
        if r != 0 {
            return r;
        }
        lj::pcall(l, 0, lj::LUA_MULTRET)
    } else {
        lj::dofile(l, &fname)
    }
}

fn lua_init_scripts(l: L) -> bool {
    let scripts = params().lua_init_scripts.clone();
    for s in scripts {
        if crate::nfqws::quit_requested() {
            return false;
        }
        if crate::log::debug() {
            if let Some(f) = s.strip_prefix('@') {
                dlog!("LUA RUN FILE: {}\n", f);
            } else {
                dlog!("LUA RUN STR: {}\n", trunc(s.clone(), 128));
            }
        }
        let st = match s.strip_prefix('@') {
            Some(f) => do_zfile(l, f),
            None => lj::dostring(l, s.as_bytes()),
        };
        if st != 0 {
            lua_perror(l);
            return false;
        }
    }
    true
}

fn lua_desync_functions_exist(l: L) -> bool {
    for dp in params().desync_profiles.borrow().iter() {
        for f in &dp.borrow().lua_desync {
            lj::getglobal(l, &f.func);
            if !lj::isfunction(l, -1) {
                lj::pop(l, 1);
                dlog_err!("desync function '{}' does not exist\n", f.func);
                return false;
            }
            lj::pop(l, 1);
        }
    }
    true
}

pub fn lua_init() -> bool {
    dlog!("\nLUA INIT\n");
    if !lua_basic_init() {
        return false;
    }
    let l = state();
    let g = lj::gettop(l);
    lua_sec_harden(l);
    lua_init_blobs(l);
    lua_init_const(l);
    for (n, f) in api::functions() {
        lj::register(l, n, f);
    }
    lua_init_mt(l);
    let ok = lua_init_scripts(l) && lua_desync_functions_exist(l);
    if g != lj::gettop(l) {
        lj::error(l, "stack guard failure");
    }
    if !ok {
        lua_shutdown();
        return false;
    }
    dlog!("LUA INIT DONE\n\n");
    true
}

unsafe extern "C-unwind" fn interrupt_hook(p: *mut lj::lua_State, _ar: *mut lj::lua_Debug) {
    // SAFETY: LuaJIT calls hooks with its live state.
    if let Some(l) = unsafe { L::from_raw(p) } {
        lj::sethook(l, None, 0, 0);
        lj::error(l, "INTERRUPT");
    }
}

pub fn lua_req_quit() {
    if let Some(l) = state_opt() {
        // lua_sethook is the one Lua API call meant to be made from a signal handler.
        lj::sethook(
            l,
            Some(interrupt_hook),
            lj::LUA_MASKCALL | lj::LUA_MASKRET | lj::LUA_MASKCOUNT | lj::LUA_MASKLINE,
            1,
        );
    }
}

pub fn lua_do_gc() {
    let p = params();
    if p.lua_gc != 0 {
        let now = boottime_ms();
        if now.wrapping_sub(GC_TIME.with(|g| g.get())) >= p.lua_gc {
            let l = state();
            let kb1 = lj::gc(l, lj::LUA_GCCOUNT, 0);
            lj::gc(l, lj::LUA_GCCOLLECT, 0);
            let kb2 = lj::gc(l, lj::LUA_GCCOUNT, 0);
            dlog!("\nLUA GARBAGE COLLECT: {}K => {}K\n", kb1, kb2);
            GC_TIME.with(|g| g.set(now));
        }
    }
}
