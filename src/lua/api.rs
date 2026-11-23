//! lua.c luacall_* functions exposed to Lua scripts.
//! SAFETY: every function here is a lua_CFunction called by LuaJIT with a valid state;
//! arguments are validated with luaL_check* exactly like the C original.

#![allow(clippy::missing_safety_doc)]

use super::lj::{self, L};
use super::push::*;
use super::{ctx_with, desync_ctx_check};
use crate::crypto;
use crate::darkmagic::*;
use crate::helpers::*;
use crate::params::{params, RECONSTRUCT_MAX_SIZE};
use crate::protocol::*;
use crate::{dlog, dlog_condup, dlog_err};
use std::os::raw::c_int;

type R = c_int;

fn check_argc(l: L, where_: &str, argc: i32) {
    let n = lj::gettop(l);
    if n != argc {
        lj::error_argc(l, where_, argc, n);
    }
}
fn check_argc_range(l: L, where_: &str, min: i32, max: i32) {
    let n = lj::gettop(l);
    if n < min || n > max {
        lj::error_argc_range(l, where_, min, max, n);
    }
}
pub fn reqlstring(l: L, i: i32) -> Vec<u8> {
    lj::checktype(l, i, lj::LUA_TSTRING);
    lj::tobytes(l, i).unwrap_or_default()
}
fn reqstring(l: L, i: i32) -> String {
    let b = &reqlstring(l, i)[..];
    let e = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..e]).into_owned()
}
fn cstrpart(b: impl AsRef<[u8]>) -> String {
    let b = b.as_ref();
    let e = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..e]).into_owned()
}

const M48: i64 = 0xFFFFFFFFFFFF;

fn dlog_(l: L) -> R {
    check_argc(l, "DLOG", 1);
    let s = cstrpart(lj::checkstring(l, 1));
    dlog!("LUA: {}\n", s);
    0
}
fn dlog_err_(l: L) -> R {
    check_argc(l, "DLOG_ERR", 1);
    let s = cstrpart(lj::checkstring(l, 1));
    dlog_err!("LUA: {}\n", s);
    0
}
fn dlog_condup_(l: L) -> R {
    check_argc(l, "DLOG_CONDUP", 1);
    let s = cstrpart(lj::checkstring(l, 1));
    dlog_condup!("LUA: {}\n", s);
    0
}

fn range48(l: L, v: i64) {
    if !(-M48..=M48).contains(&v) {
        lj::error(l, "out of range");
    }
}

fn bitlshift(l: L) -> R {
    check_argc(l, "bitlshift", 2);
    let v = lj::checklint(l, 1);
    let sh = lj::checkinteger(l, 2);
    if !(0..=48).contains(&sh) || !(-M48..=M48).contains(&v) {
        lj::error(l, "out of range");
    }
    let u = (v as u64) & M48 as u64;
    lj::pushlint(l, ((u << sh) & M48 as u64) as i64);
    1
}
fn bitrshift(l: L) -> R {
    check_argc(l, "bitrshift", 2);
    let v = lj::checklint(l, 1);
    let sh = lj::checkinteger(l, 2);
    if !(0..=48).contains(&sh) || !(-M48..=M48).contains(&v) {
        lj::error(l, "out of range");
    }
    let u = (v as u64) & M48 as u64;
    lj::pushlint(l, (u >> sh) as i64);
    1
}
fn bitand(l: L) -> R {
    check_argc_range(l, "bitand", 2, 100);
    let n = lj::gettop(l);
    let mut sum: u64 = M48 as u64;
    for i in 1..=n {
        let v = lj::checklint(l, i);
        range48(l, v);
        sum &= v as u64;
    }
    lj::pushlint(l, sum as i64);
    1
}
fn bitorxor(l: L, name: &str, xor: bool) -> R {
    check_argc_range(l, name, 1, 100);
    let n = lj::gettop(l);
    let mut sum: u64 = 0;
    for i in 1..=n {
        let v = lj::checklint(l, i);
        range48(l, v);
        let v = (v & M48) as u64;
        if xor {
            sum ^= v
        } else {
            sum |= v
        }
    }
    lj::pushlint(l, sum as i64);
    1
}
fn bitor(l: L) -> R {
    bitorxor(l, "bitor", false)
}
fn bitxor(l: L) -> R {
    bitorxor(l, "bitxor", true)
}
fn bitnotx(l: L, name: &str, max: i64) -> R {
    check_argc(l, name, 1);
    check_argc(l, "bitnot", 1);
    let v = lj::checklint(l, 1);
    if v > max || v < -max {
        lj::error(l, "out of range");
    }
    lj::pushlint(l, (!(v as u64) & max as u64) as i64);
    1
}
fn bitnot8(l: L) -> R {
    bitnotx(l, "bitnot8", 0xFF)
}
fn bitnot16(l: L) -> R {
    bitnotx(l, "bitnot16", 0xFFFF)
}
fn bitnot24(l: L) -> R {
    bitnotx(l, "bitnot24", 0xFFFFFF)
}
fn bitnot32(l: L) -> R {
    bitnotx(l, "bitnot32", 0xFFFFFFFF)
}
fn bitnot48(l: L) -> R {
    bitnotx(l, "bitnot48", M48)
}
fn bitget(l: L) -> R {
    check_argc(l, "bitget", 3);
    let iw = lj::checklint(l, 1);
    range48(l, iw);
    let from = lj::checkinteger(l, 2);
    let to = lj::checkinteger(l, 3);
    if from < 0 || to < 0 || from > to || from > 47 || to > 47 {
        lj::error(l, "bit range invalid");
    }
    let what = ((iw as u64) >> from) & !(u64::MAX << (to - from + 1));
    lj::pushlint(l, what as i64);
    1
}
fn bitset(l: L) -> R {
    check_argc(l, "bitset", 4);
    let iw = lj::checklint(l, 1);
    range48(l, iw);
    let from = lj::checkinteger(l, 2);
    let to = lj::checkinteger(l, 3);
    let is = lj::checklint(l, 4);
    range48(l, is);
    if from < 0 || to < 0 || from > to || from > 47 || to > 47 {
        lj::error(l, "bit range invalid");
    }
    let mut mask = !(u64::MAX << (to - from + 1));
    let set = ((is as u64) & mask) << from;
    mask <<= from;
    lj::pushlint(l, (((iw as u64) & !mask) | set) as i64);
    1
}

fn ux(l: L, name: &str, sz: usize) -> R {
    check_argc_range(l, name, 1, 2);
    let n = lj::gettop(l);
    let p = &reqlstring(l, 1)[..];
    let off = if n >= 2 && lj::typ(l, 2) != lj::LUA_TNIL {
        lj::checkinteger(l, 2) - 1
    } else {
        0
    };
    if off < 0 || (off as u64 + sz as u64) > p.len() as u64 {
        lj::error(l, "out of range");
    }
    let o = off as usize;
    let v: i64 = match sz {
        1 => p[o] as i64,
        2 => pntoh16(&p[o..]) as i64,
        3 => pntoh24(&p[o..]) as i64,
        4 => pntoh32(&p[o..]) as i64,
        _ => pntoh48(&p[o..]) as i64,
    };
    // u8/u16/u24 use lua_pushinteger, u32/u48 lua_pushlint
    if sz >= 4 {
        lj::pushlint(l, v);
    } else {
        lj::pushinteger(l, v);
    }
    1
}
fn u8_(l: L) -> R {
    ux(l, "u8", 1)
}
fn u16_(l: L) -> R {
    ux(l, "u16", 2)
}
fn u24_(l: L) -> R {
    ux(l, "u24", 3)
}
fn u32_(l: L) -> R {
    ux(l, "u32", 4)
}
fn u48_(l: L) -> R {
    ux(l, "u48", 6)
}
fn swapx(l: L, name: &str, max: i64) -> i64 {
    check_argc(l, name, 1);
    let v = lj::checklint(l, 1);
    if v > max || v < -max {
        lj::error(l, "out of range");
    }
    v
}
fn swap16(l: L) -> R {
    let v = swapx(l, "swap16", 0xFFFF);
    lj::pushinteger(l, bswap16(v as u16) as i64);
    1
}
fn swap24(l: L) -> R {
    let v = swapx(l, "swap24", 0xFFFFFF);
    lj::pushlint(l, bswap24(v as u32) as i64);
    1
}
fn swap32(l: L) -> R {
    let v = swapx(l, "swap32", 0xFFFFFFFF);
    lj::pushlint(l, (v as u32).swap_bytes() as i64);
    1
}
fn swap48(l: L) -> R {
    let v = swapx(l, "swap48", M48);
    lj::pushlint(l, bswap48(v as u64) as i64);
    1
}
fn uxadd(l: L, name: &str, max: i64) -> R {
    check_argc_range(l, name, 1, 100);
    let n = lj::gettop(l);
    let mut sum: u64 = 0;
    for i in 1..=n {
        let v = lj::checklint(l, i);
        if v > max || v < -max {
            lj::error(l, "out of range");
        }
        sum = sum.wrapping_add(v as u64);
    }
    lj::pushlint(l, (sum & max as u64) as i64);
    1
}
fn u8add(l: L) -> R {
    uxadd(l, "u8add", 0xFF)
}
fn u16add(l: L) -> R {
    uxadd(l, "u16add", 0xFFFF)
}
fn u24add(l: L) -> R {
    uxadd(l, "u24add", 0xFFFFFF)
}
fn u32add(l: L) -> R {
    uxadd(l, "u32add", 0xFFFFFFFF)
}
fn u48add(l: L) -> R {
    uxadd(l, "u48add", M48)
}
fn bux(l: L, name: &str, sz: usize, max: i64) -> R {
    check_argc(l, name, 1);
    let v = lj::checklint(l, 1);
    if v > max || v < -max {
        lj::error(l, "out of range");
    }
    let b = (v as u64).to_be_bytes();
    lj::pushbytes(l, &b[8 - sz..]);
    1
}
fn bu8(l: L) -> R {
    bux(l, "bu8", 1, 0xFF)
}
fn bu16(l: L) -> R {
    bux(l, "bu16", 2, 0xFFFF)
}
fn bu24(l: L) -> R {
    bux(l, "bu24", 3, 0xFFFFFF)
}
fn bu32(l: L) -> R {
    bux(l, "bu32", 4, 0xFFFFFFFF)
}
fn bu48(l: L) -> R {
    bux(l, "bu48", 6, M48)
}
fn divint(l: L) -> R {
    check_argc(l, "divint", 2);
    let a = lj::checklint(l, 1);
    let b = lj::checklint(l, 2);
    if b != 0 {
        lj::pushlint(l, a.wrapping_div(b));
    } else {
        lj::pushnil(l);
    }
    1
}

fn brandom_x(l: L, name: &str, f: fn(&mut [u8])) -> R {
    check_argc(l, name, 1);
    let g = guard_enter!(l);
    let len = lj::checkinteger(l, 1);
    if len < 0 {
        lj::error(l, "brandom: invalid arg");
    }
    lj::newuserdata(l, len as usize); // C scratch buffer (Lua heap accounting)
    let mut v = vec![0u8; len as usize];
    f(&mut v);
    lj::pushbytes(l, &v);
    lj::remove(l, -2);
    guard_leave!(l, g, 1);
    1
}
fn brandom(l: L) -> R {
    brandom_x(l, "brandom", fill_random_bytes)
}
fn brandom_az(l: L) -> R {
    brandom_x(l, "brandom_az", fill_random_az)
}
fn brandom_az09(l: L) -> R {
    brandom_x(l, "brandom_az09", fill_random_az09)
}

fn parse_hex(l: L) -> R {
    check_argc(l, "parse_hex", 1);
    let g = guard_enter!(l);
    let hex = &reqlstring(l, 1)[..];
    if hex.len() & 1 != 0 {
        lj::pushnil(l);
    } else {
        lj::newuserdata(l, hex.len() >> 1);
        match parse_hex_str(hex, hex.len() >> 1) {
            Ok(v) => {
                lj::pushbytes(l, &v);
                lj::remove(l, -2);
            }
            Err(_) => {
                lj::pop(l, 1);
                lj::pushnil(l);
            }
        }
    }
    guard_leave!(l, g, 1);
    1
}

fn hash_type(l: L, s: &str) -> crypto::ShaVer {
    match crypto::ShaVer::from_name(s) {
        Some(v) => v,
        None => lj::error(l, &format!("unsupported hash type {s}")),
    }
}

fn bcryptorandom(l: L) -> R {
    check_argc(l, "bcryptorandom", 1);
    let g = guard_enter!(l);
    let len = lj::checkinteger(l, 1);
    if len < 0 {
        lj::error(l, "bcryptorandom: invalid arg");
    }
    lj::newuserdata(l, len as usize);
    let mut v = vec![0u8; len as usize];
    if !fill_crypto_random_bytes(&mut v) {
        lj::error(l, "could not get entropy bytes");
    }
    lj::pushbytes(l, &v);
    lj::remove(l, -2);
    guard_leave!(l, g, 1);
    1
}
fn bop(l: L, name: &str, op: fn(&[u8], &[u8]) -> Vec<u8>) -> R {
    check_argc(l, name, 2);
    let g = guard_enter!(l);
    let a = &reqlstring(l, 1)[..];
    let b = &reqlstring(l, 2)[..];
    if a.len() != b.len() {
        lj::error(l, "string lengths must be the same\n");
    }
    lj::newuserdata(l, a.len());
    let r = op(a, b);
    lj::pushbytes(l, &r);
    lj::remove(l, -2);
    guard_leave!(l, g, 1);
    1
}
fn bxor_(l: L) -> R {
    bop(l, "bxor", bxor)
}
fn bor_(l: L) -> R {
    bop(l, "bor", bor)
}
fn band_(l: L) -> R {
    bop(l, "band", band)
}
fn hash(l: L) -> R {
    check_argc(l, "hash", 2);
    let g = guard_enter!(l);
    let t = cstrpart(lj::checkstring(l, 1));
    let v = hash_type(l, &t);
    let d = &reqlstring(l, 2)[..];
    lj::pushbytes(l, &crypto::hash(v, d));
    guard_leave!(l, g, 1);
    1
}
fn aes(l: L) -> R {
    check_argc(l, "aes", 3);
    let g = guard_enter!(l);
    let enc = lj::toboolean(l, 1);
    let key = &reqlstring(l, 2)[..];
    if !matches!(key.len(), 16 | 24 | 32) {
        lj::error_u(
            l,
            c"aes: wrong key length %u. should be 16,24,32.",
            (key.len()) as u32,
        );
    }
    let input = &reqlstring(l, 3)[..];
    if input.len() != 16 {
        lj::error_u(
            l,
            c"aes: wrong data length %u. should be 16.",
            (input.len()) as u32,
        );
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(input);
    match crypto::aes_block(enc, key, &b) {
        Some(o) => lj::pushbytes(l, &o),
        None => lj::pushnil(l),
    }
    guard_leave!(l, g, 1);
    1
}
fn aes_gcm(l: L) -> R {
    check_argc_range(l, "aes_gcm", 4, 5);
    let g = guard_enter!(l);
    let enc = lj::toboolean(l, 1);
    let key = &reqlstring(l, 2)[..];
    if !matches!(key.len(), 16 | 24 | 32) {
        lj::error_u(
            l,
            c"aes_gcm: wrong key length %u. should be 16,24,32.",
            (key.len()) as u32,
        );
    }
    let iv = &reqlstring(l, 3)[..];
    if iv.is_empty() {
        lj::error(l, "aes_gcm: zero iv length");
    }
    let input = &reqlstring(l, 4)[..];
    let add = if lj::isnoneornil(l, 5) {
        Vec::new()
    } else {
        reqlstring(l, 5)
    };
    lj::newuserdata(l, input.len());
    match crypto::aes_gcm(enc, key, iv, input, &add) {
        Some((o, tag)) => {
            lj::pushbytes(l, &o);
            lj::pushbytes(l, &tag);
        }
        None => {
            lj::pushnil(l);
            lj::pushnil(l);
        }
    }
    lj::remove(l, -3);
    guard_leave!(l, g, 2);
    2
}
fn aes_ctr(l: L) -> R {
    check_argc(l, "aes_ctr", 3);
    let g = guard_enter!(l);
    let key = &reqlstring(l, 1)[..];
    if !matches!(key.len(), 16 | 24 | 32) {
        lj::error_u(
            l,
            c"aes_ctr: wrong key length %u. should be 16,24,32.",
            (key.len()) as u32,
        );
    }
    let iv = &reqlstring(l, 2)[..];
    if iv.len() != 16 {
        lj::error_u(
            l,
            c"aes_ctr: wrong iv length %u. should be 16.",
            (iv.len()) as u32,
        );
    }
    let input = &lj::checklstring(l, 3)[..];
    let mut ivb = [0u8; 16];
    ivb.copy_from_slice(iv);
    lj::newuserdata(l, input.len());
    match crypto::aes_ctr(key, &ivb, input) {
        Some(o) => lj::pushbytes(l, &o),
        None => lj::pushnil(l),
    }
    lj::remove(l, -2);
    guard_leave!(l, g, 1);
    1
}
fn hkdf(l: L) -> R {
    check_argc(l, "hkdf", 5);
    let g = guard_enter!(l);
    let t = cstrpart(lj::checkstring(l, 1));
    let v = hash_type(l, &t);
    let opt = |i: i32| {
        if lj::typ(l, i) == lj::LUA_TNIL {
            None
        } else {
            Some(lj::checklstring(l, i))
        }
    };
    let salt = opt(2);
    let ikm = opt(3).unwrap_or_default();
    let info = opt(4).unwrap_or_default();
    let okm_len = lj::checkinteger(l, 5);
    if okm_len < 0 {
        lj::error(l, "hkdf: invalid arg");
    }
    lj::newuserdata(l, okm_len as usize);
    match crypto::hkdf(v, salt.as_deref(), &ikm, &info, okm_len as usize) {
        Some(o) => lj::pushbytes(l, &o),
        None => lj::pushnil(l),
    }
    lj::remove(l, -2);
    guard_leave!(l, g, 1);
    1
}

fn getpid(l: L) -> R {
    check_argc(l, "getpid", 0);
    lj::pushinteger(l, std::process::id() as i64);
    1
}
fn gettid(l: L) -> R {
    check_argc(l, "gettid", 0);
    lj::pushinteger(l, crate::sys::gettid());
    1
}
fn uname(l: L) -> R {
    check_argc(l, "uname", 0);
    let g = guard_enter!(l);
    match crate::sys::uname() {
        None => lj::pushnil(l),
        Some([sysname, nodename, release, version, machine]) => {
            lj::createtable(l, 0, 5);
            pushf_str(l, "sysname", Some(&sysname));
            pushf_str(l, "nodename", Some(&nodename));
            pushf_str(l, "release", Some(&release));
            pushf_str(l, "version", Some(&version));
            pushf_str(l, "machine", Some(&machine));
        }
    }
    guard_leave!(l, g, 1);
    1
}
fn clock_gettime(l: L) -> R {
    check_argc(l, "clock_gettime", 0);
    match realtime() {
        Some(t) => {
            lj::pushlint(l, t.tv_sec as i64);
            lj::pushinteger(l, t.tv_nsec as i64);
        }
        None => {
            lj::pushnil(l);
            lj::pushnil(l);
        }
    }
    2
}
fn clock_getfloattime(l: L) -> R {
    check_argc(l, "clock_getfloattime", 0);
    match realtime() {
        Some(t) => lj::pushnumber(l, t.tv_sec as f64 + t.tv_nsec as f64 / 1000000000.),
        None => lj::pushnil(l),
    }
    1
}

fn instance_cutoff(l: L) -> R {
    check_argc_range(l, "instance_cutoff", 1, 2);
    let g = guard_enter!(l);
    if lj::isnil(l, 1) {
        dlog!("instance cutoff not possible because missing ctx\n");
    } else {
        desync_ctx_check(l);
        let n = lj::gettop(l);
        let (bin, bout) = if n >= 2 && lj::typ(l, 2) != lj::LUA_TNIL {
            lj::checktype(l, 2, lj::LUA_TBOOLEAN);
            let o = lj::toboolean(l, 2);
            (!o, o)
        } else {
            (true, true)
        };
        let (instance, dpn, ct) = ctx_with(|c| (c.instance.clone(), c.dp_n, c.ctrack.clone()));
        match ct {
            Some(ct) => {
                dlog!("instance cutoff for '{}' in={} out={}\n", instance, bin as u8, bout as u8);
                let r = ct.borrow().lua_instance_cutoff;
                lj::rawgeti(l, lj::LUA_REGISTRYINDEX, r as i64);
                lj::getfield(l, -1, &instance);
                if !lj::istable(l, -1) {
                    lj::pop(l, 1);
                    pushf_table(l, &instance);
                    lj::getfield(l, -1, &instance);
                }
                lj::rawgeti(l, -1, dpn as i64);
                if !lj::istable(l, -1) {
                    lj::pop(l, 1);
                    pushi_table(l, dpn as i64);
                    lj::rawgeti(l, -1, dpn as i64);
                }
                if bout {
                    pushi_bool(l, 0, true);
                }
                if bin {
                    pushi_bool(l, 1, true);
                }
                lj::pop(l, 3);
            }
            None => dlog!(
                "instance cutoff requested for '{}' in={} out={} but not possible without conntrack\n",
                instance,
                bin as u8,
                bout as u8
            ),
        }
    }
    guard_leave!(l, g, 0);
    0
}

fn lua_cutoff(l: L) -> R {
    check_argc_range(l, "lua_cutoff", 1, 2);
    let g = guard_enter!(l);
    desync_ctx_check(l);
    let n = lj::gettop(l);
    let (bin, bout) = if n >= 2 && lj::typ(l, 2) != lj::LUA_TNIL {
        lj::checktype(l, 2, lj::LUA_TBOOLEAN);
        let o = lj::toboolean(l, 2);
        (!o, o)
    } else {
        (true, true)
    };
    let (instance, ct) = ctx_with(|c| (c.instance.clone(), c.ctrack.clone()));
    match ct {
        Some(ct) => {
            dlog!(
                "lua cutoff from '{}' in={} out={}\n",
                instance,
                bin as u8,
                bout as u8
            );
            let mut c = ct.borrow_mut();
            if bin {
                c.b_lua_in_cutoff = true;
            }
            if bout {
                c.b_lua_out_cutoff = true;
            }
        }
        None => dlog!(
            "lua cutoff requested from '{}' in={} out={} but not possible without conntrack\n",
            instance,
            bin as u8,
            bout as u8
        ),
    }
    guard_leave!(l, g, 0);
    0
}

pub fn desync_instance(func: &str, dp_n: u32, func_n: u32) -> String {
    crate::darkmagic::trunc(format!("{func}_{dp_n}_{func_n}"), 256)
}

fn execution_plan(l: L) -> R {
    check_argc(l, "execution_plan", 1);
    let g = guard_enter!(l);
    desync_ctx_check(l);
    let (dp, func_n, incoming) = ctx_with(|c| (c.dp.clone(), c.func_n, c.incoming));
    lj::newtable(l);
    if let Some(dp) = dp {
        let dp = dp.borrow();
        let mut n = 1u32;
        for f in &dp.lua_desync {
            if n > func_n {
                let instance = desync_instance(&f.func, dp.n, n);
                let range = if incoming { &f.range_in } else { &f.range_out };
                lj::pushinteger(l, (n - func_n) as i64);
                lj::createtable(l, 0, 7);
                pushf_args(l, &f.args, -1, false);
                pushf_str(l, "func", Some(f.func.as_bytes()));
                pushf_int(l, "func_n", n as i64);
                pushf_str(l, "func_instance", Some(instance.as_bytes()));
                pushf_range(l, "range", range);
                lj::pushstr(l, "payload");
                lj::newtable(l);
                if f.payload_type == L7P_ALL as u64 {
                    lj::pushstr(l, "all");
                    lj::pushboolean(l, true);
                    lj::rawset(l, -3);
                } else {
                    for pl in 0..L7P_LAST {
                        if f.payload_type & (1u64 << pl) != 0 {
                            if let Some(s) = l7payload_str(pl) {
                                lj::pushstr(l, s);
                                lj::pushboolean(l, true);
                                lj::rawset(l, -3);
                            }
                        }
                    }
                }
                lj::rawset(l, -3);
                match l7_payload_str_list(f.payload_type, 2048) {
                    Some(s) => pushf_str(l, "payload_filter", Some(s.as_bytes())),
                    None => pushf_nil(l, "payload_filter"),
                }
                lj::rawset(l, -3);
            }
            n += 1;
        }
    }
    guard_leave!(l, g, 1);
    1
}
fn execution_plan_cancel(l: L) -> R {
    check_argc(l, "execution_plan_cancel", 1);
    desync_ctx_check(l);
    let inst = ctx_with(|c| {
        c.cancel = true;
        c.instance.clone()
    });
    dlog!("execution plan cancel from '{}'\n", inst);
    0
}
fn raw_packet(l: L) -> R {
    check_argc(l, "raw_packet", 1);
    let g = guard_enter!(l);
    desync_ctx_check(l);
    let pkt = ctx_with(|c| c.pkt.clone());
    lj::pushbytes(l, &pkt);
    guard_leave!(l, g, 1);
    1
}

fn dissect_x(l: L, name: &str, f: fn(L, Option<&[u8]>, usize)) -> R {
    check_argc(l, name, 1);
    let g = guard_enter!(l);
    let d = reqlstring(l, 1).to_vec();
    f(l, Some(&d), d.len());
    guard_leave!(l, g, 1);
    1
}
fn dissect_tcphdr(l: L) -> R {
    dissect_x(l, "dissect_tcphdr", push_tcphdr)
}
fn dissect_udphdr(l: L) -> R {
    dissect_x(l, "dissect_udphdr", push_udphdr)
}
fn dissect_icmphdr(l: L) -> R {
    dissect_x(l, "dissect_icmphdr", push_icmphdr)
}
fn dissect_iphdr(l: L) -> R {
    dissect_x(l, "dissect_iphdr", push_iphdr)
}
fn dissect_ip6hdr(l: L) -> R {
    dissect_x(l, "dissect_ip6hdr", push_ip6hdr)
}

fn reconstruct_ip6hdr_(l: L) -> R {
    check_argc_range(l, "reconstruct_ip6hdr", 1, 2);
    let g = guard_enter!(l);
    let o = reconstruct_extract_options(l, 2);
    let mut buf = vec![0u8; 512];
    match reconstruct_ip6hdr(l, 1, &mut buf, o.ip6_last_proto, o.ip6_preserve_next) {
        Some(n) => lj::pushbytes(l, &buf[..n]),
        None => lj::error(l, "invalid data for ip6hdr"),
    }
    guard_leave!(l, g, 1);
    1
}
fn reconstruct_iphdr_(l: L) -> R {
    check_argc(l, "reconstruct_iphdr", 1);
    let g = guard_enter!(l);
    let mut buf = vec![0u8; 60];
    match reconstruct_iphdr(l, 1, &mut buf) {
        Some(n) => lj::pushbytes(l, &buf[..n]),
        None => lj::error(l, "invalid data for iphdr"),
    }
    guard_leave!(l, g, 1);
    1
}
fn reconstruct_tcphdr_(l: L) -> R {
    check_argc(l, "reconstruct_tcphdr", 1);
    let g = guard_enter!(l);
    let mut buf = vec![0u8; 60];
    match reconstruct_tcphdr(l, 1, &mut buf) {
        Some(n) => lj::pushbytes(l, &buf[..n]),
        None => lj::error(l, "invalid data for tcphdr"),
    }
    guard_leave!(l, g, 1);
    1
}
fn reconstruct_udphdr_(l: L) -> R {
    let g = guard_enter!(l);
    check_argc(l, "reconstruct_udphdr", 1);
    let mut buf = [0u8; 8];
    if !reconstruct_udphdr(l, 1, &mut buf) {
        lj::error(l, "invalid data for udphdr");
    }
    lj::pushbytes(l, &buf);
    guard_leave!(l, g, 1);
    1
}
fn reconstruct_icmphdr_(l: L) -> R {
    let g = guard_enter!(l);
    check_argc(l, "reconstruct_icmphdr", 1);
    let mut buf = [0u8; 8];
    if !reconstruct_icmphdr(l, 1, &mut buf) {
        lj::error(l, "invalid data for icmphdr");
    }
    lj::pushbytes(l, &buf);
    guard_leave!(l, g, 1);
    1
}
fn reconstruct_dissect_(l: L) -> R {
    check_argc_range(l, "reconstruct_dissect", 1, 2);
    let g = guard_enter!(l);
    let o = reconstruct_extract_options(l, 2);
    let mut buf = vec![0u8; RECONSTRUCT_MAX_SIZE];
    match reconstruct_dissect(l, 1, &mut buf, &o) {
        Some(n) => lj::pushbytes(l, &buf[..n]),
        None => lj::error(l, "invalid dissect data"),
    }
    guard_leave!(l, g, 1);
    1
}
fn dissect(l: L) -> R {
    check_argc_range(l, "dissect", 1, 2);
    let g = guard_enter!(l);
    let d = reqlstring(l, 1).to_vec();
    let n = lj::gettop(l);
    let npc = n >= 2 && lj::toboolean(l, 2);
    let dis = proto_dissect_l3l4(&d, npc);
    push_dissect(l, &d, Some(&dis));
    guard_leave!(l, g, 1);
    1
}

fn csum_ip4_fix(l: L) -> R {
    check_argc(l, "csum_ip4_fix", 1);
    let g = guard_enter!(l);
    let d = &reqlstring(l, 1)[..];
    if d.len() > 60 || !proto_check_ipv4(d) {
        lj::error(l, "invalid ip header");
    }
    let mut v = d.to_vec();
    crate::checksum::ip4_fix_checksum(&mut v);
    lj::pushbytes(l, &v);
    guard_leave!(l, g, 1);
    1
}
fn csum_l4(l: L, name: &str, kind: u8) -> R {
    check_argc(l, name, 3);
    let g = guard_enter!(l);
    let ip = reqlstring(l, 1).to_vec();
    let is4 = proto_check_ipv4(&ip);
    let is6 = !is4 && proto_check_ipv6(&ip);
    if !is4 && !is6 {
        lj::error(l, "invalid ip header");
    }
    let hdr = &reqlstring(l, 2)[..];
    let ok = match kind {
        0 => proto_check_tcp(hdr),
        1 => proto_check_udp(hdr),
        _ => proto_check_icmp(hdr),
    };
    if !ok {
        lj::error(
            l,
            [
                "invalid tcp header",
                "invalid udp header",
                "invalid icmp header",
            ][kind as usize],
        );
    }
    let pl = &reqlstring(l, 3)[..];
    if pl.len() > 0xFFFF {
        lj::error(l, "invalid payload length");
    }
    let lh = hdr.len();
    lj::newuserdata(l, lh + pl.len());
    let mut t = Vec::with_capacity(lh + pl.len());
    t.extend_from_slice(hdr);
    t.extend_from_slice(pl);
    let tl = t.len();
    let addrs = if is4 {
        crate::checksum::L3Addrs::V4(&ip[12..16], &ip[16..20])
    } else {
        crate::checksum::L3Addrs::V6(&ip[8..24], &ip[24..40])
    };
    match kind {
        0 => crate::checksum::tcp_fix_checksum(&mut t, tl, addrs),
        1 => crate::checksum::udp_fix_checksum(&mut t, tl, addrs),
        _ => crate::checksum::icmp_fix_checksum(
            &mut t,
            tl,
            if is6 {
                addrs
            } else {
                crate::checksum::L3Addrs::None
            },
        ),
    }
    lj::pushbytes(l, &t[..lh]);
    lj::remove(l, -2);
    guard_leave!(l, g, 1);
    1
}
fn csum_tcp_fix(l: L) -> R {
    csum_l4(l, "csum_tcp_fix", 0)
}
fn csum_udp_fix(l: L) -> R {
    csum_l4(l, "csum_udp_fix", 1)
}
fn csum_icmp_fix(l: L) -> R {
    csum_l4(l, "csum_icmp_fix", 2)
}

fn ntop(l: L) -> R {
    check_argc(l, "ntop", 1);
    let g = guard_enter!(l);
    let p = &reqlstring(l, 1)[..];
    match p.len() {
        4 => lj::pushstr(l, &ntop4(p)),
        16 => lj::pushstr(l, &ntop6(p)),
        _ => {
            lj::pushnil(l);
            return 1;
        }
    }
    guard_leave!(l, g, 1);
    1
}
fn pton(l: L) -> R {
    check_argc(l, "pton", 1);
    let g = guard_enter!(l);
    let s = &reqlstring(l, 1)[..];
    let s = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
    if let Some(a) = inet_pton4(s) {
        lj::pushbytes(l, &a);
    } else if let Some(a) = inet_pton6(s) {
        lj::pushbytes(l, &a);
    } else {
        lj::pushnil(l);
    }
    guard_leave!(l, g, 1);
    1
}

fn rawsend_extract_options(l: L, idx: i32) -> (i32, u32, Option<String>) {
    let p = params();
    if lj::isnoneornil(l, idx) {
        return (1, p.desync_fwmark, None);
    }
    lj::checktype(l, idx, lj::LUA_TTABLE);
    lj::getfield(l, idx, "repeats");
    let mut rep = lj::tointeger(l, -1) as i32;
    if rep < 0 {
        lj::error(l, "rawsend: negative repeats");
    }
    if rep == 0 {
        rep = 1;
    }
    lj::pop(l, 1);
    lj::getfield(l, idx, "fwmark");
    let fw = (lj::tolint(l, -1) as u32) | p.desync_fwmark;
    lj::pop(l, 1);
    lj::getfield(l, idx, "ifout");
    let ifout = if lj::typ(l, -1) == lj::LUA_TSTRING {
        lj::tobytes(l, -1).map(cstrpart)
    } else {
        None
    };
    lj::pop(l, 1);
    (rep, fw, ifout)
}

fn rawsend_(l: L) -> R {
    check_argc_range(l, "rawsend", 1, 2);
    let g = guard_enter!(l);
    let data = reqlstring(l, 1).to_vec();
    let (rep, fw, ifout) = rawsend_extract_options(l, 2);
    let Some(sa) = extract_dst(&data) else {
        lj::error(l, "bad ip4/ip6 header")
    };
    dlog!(
        "rawsend repeats={} size={} ifout={} fwmark={:08X}\n",
        rep,
        data.len(),
        ifout.as_deref().unwrap_or(""),
        fw
    );
    let b = rawsend_rep(rep, &sa, fw, ifout.as_deref(), &data);
    lj::pushboolean(l, b);
    guard_leave!(l, g, 1);
    1
}
fn rawsend_dissect(l: L) -> R {
    check_argc_range(l, "rawsend_dissect", 1, 3);
    let g = guard_enter!(l);
    lj::checktype(l, 1, lj::LUA_TTABLE);
    let (rep, fw, ifout) = rawsend_extract_options(l, 2);
    let o = reconstruct_extract_options(l, 3);
    let mut buf = vec![0u8; RECONSTRUCT_MAX_SIZE];
    let Some(n) = reconstruct_dissect(l, 1, &mut buf, &o) else {
        lj::error(l, "invalid dissect data")
    };
    buf.truncate(n);
    let Some(sa) = extract_dst(&buf) else {
        lj::error(l, "bad ip4/ip6 header")
    };
    dlog!(
        "rawsend_dissect repeats={} size={} badsum={} ifout={} fwmark={:08X}\n",
        rep,
        n,
        o.badsum as u8,
        ifout.as_deref().unwrap_or(""),
        fw
    );
    let b = rawsend_rep(rep, &sa, fw, ifout.as_deref(), &buf);
    lj::pushboolean(l, b);
    guard_leave!(l, g, 1);
    1
}

fn conntrack_feed(l: L) -> R {
    check_argc_range(l, "conntrack_feed", 1, 2);
    let g = guard_enter!(l);
    let p = params();
    let mut ok = false;
    if !p.ctrack_disable {
        let pkt: Vec<u8> = match lj::typ(l, 1) {
            lj::LUA_TTABLE => {
                let o = reconstruct_extract_options(l, 2);
                let mut buf = vec![0u8; RECONSTRUCT_MAX_SIZE];
                let Some(n) = reconstruct_dissect(l, 1, &mut buf, &o) else {
                    lj::error(l, "invalid dissect data")
                };
                buf.truncate(n);
                buf
            }
            lj::LUA_TSTRING => lj::tobytes(l, 1).unwrap_or_default(),
            _ => lj::error(l, "invalid packet data type"),
        };
        let dis = proto_dissect_l3l4(&pkt, false);
        p.conntrack.borrow_mut().purge();
        let fed = p.conntrack.borrow_mut().feed(&pkt, &dis);
        if let Some((ct, rev)) = fed {
            push_ctrack(l, Some(&ct.borrow()), None, rev, p.server);
            lj::pushboolean(l, !rev);
            let created = ctx_with(|c| {
                if c.ctrack.is_none() {
                    c.ctrack = Some(ct.clone());
                    c.incoming = rev;
                    true
                } else {
                    false
                }
            });
            if created {
                dlog!("conntrack record created\n");
            }
            ok = true;
        }
    }
    if !ok {
        lj::pushnil(l);
        lj::pushnil(l);
    }
    guard_leave!(l, g, 2);
    2
}

fn get_source_ip(l: L) -> R {
    check_argc(l, "get_source_ip", 1);
    let g = guard_enter!(l);
    let d = &reqlstring(l, 1)[..];
    match d.len() {
        4 => {
            let mut a = [0u8; 4];
            a.copy_from_slice(d);
            match get_source_ip4(&a) {
                Some(s) => lj::pushbytes(l, &s),
                None => lj::pushnil(l),
            }
        }
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(d);
            match get_source_ip6(&a) {
                Some(s) => lj::pushbytes(l, &s),
                None => lj::pushnil(l),
            }
        }
        n => lj::error_u(l, c"invalid IP length %u", n as u32),
    }
    guard_leave!(l, g, 1);
    1
}

fn get_ifaddrs(l: L) -> R {
    check_argc(l, "get_ifaddrs", 0);
    let g = guard_enter!(l);
    match crate::sys::getifaddrs() {
        None => lj::pushnil(l),
        Some(addrs) => {
            let sock = crate::sys::dgram_socket();
            lj::newtable(l);
            for ai in addrs {
                if !(ai.family == libc::AF_INET || ai.family == libc::AF_INET6)
                    || ai.name.is_empty()
                {
                    continue;
                }
                let ifname = &ai.name;
                lj::getfield(l, -1, ifname);
                if lj::isnil(l, -1) {
                    lj::pop(l, 1);
                    pushf_table(l, ifname);
                    lj::getfield(l, -1, ifname);
                    let index = crate::sys::if_nametoindex(&ai.cname);
                    if index != 0 {
                        pushf_int(l, "index", index as i64);
                    }
                    pushf_int(l, "flags", ai.flags as i64);
                    let ssid = crate::wlan::ssid_search_ifname(ifname);
                    pushf_str(l, "ssid", ssid.as_deref().map(str::as_bytes));
                    if let Some(mtu) = sock.as_ref().and_then(|s| crate::sys::if_mtu(s, ifname)) {
                        pushf_int(l, "mtu", mtu as i64);
                    }
                    pushf_table(l, "addr");
                }
                lj::getfield(l, -1, "addr");
                let li = lj::rawlen(l, -1) as i64 + 1;
                pushi_table(l, li);
                lj::rawgeti(l, -1, li);
                pushf_ipaddr(l, "addr", &ai.addr);
                pushf_ipaddr(l, "netmask", &ai.netmask);
                pushf_ipaddr(l, "broadcast", &ai.ifu);
                pushf_ipaddr(l, "dst", &ai.ifu);
                lj::pop(l, 3);
            }
        }
    }
    guard_leave!(l, g, 1);
    1
}

fn payload_type_arg(l: L, i: i32) -> (u32, String) {
    let s = reqstring(l, i);
    let t = l7payload_from_name(&s);
    if t == L7P_INVALID {
        lj::error(l, &format!("bad payload type : '{s}'"));
    }
    (t, s)
}

fn resolve_pos_(l: L) -> R {
    check_argc_range(l, "resolve_pos", 3, 4);
    let g = guard_enter!(l);
    let n = lj::gettop(l);
    let data = &reqlstring(l, 1)[..];
    let (t, _) = payload_type_arg(l, 2);
    let sm = reqstring(l, 3);
    let zb = n >= 4 && lj::toboolean(l, 4);
    let Some(m) = posmarker_parse(&sm) else {
        lj::error(l, &format!("bad marker : '{sm}'"))
    };
    let pos = resolve_pos(data, t, &m);
    if pos == POS_NOT_FOUND {
        lj::pushnil(l);
    } else {
        lj::pushinteger(l, pos as i64 + !zb as i64);
    }
    guard_leave!(l, g, 1);
    1
}
fn resolve_multi_pos_(l: L) -> R {
    check_argc_range(l, "resolve_multi_pos", 3, 4);
    let g = guard_enter!(l);
    let n = lj::gettop(l);
    let data = &reqlstring(l, 1)[..];
    let (t, _) = payload_type_arg(l, 2);
    let sm = reqstring(l, 3);
    let zb = n >= 4 && lj::toboolean(l, 4);
    let Some(ms) = posmarker_list_parse(&sm, 128) else {
        lj::error(l, "bad marker list")
    };
    let pos = resolve_multi_pos(data, t, &ms);
    lj::newtable(l);
    for (i, p) in pos.iter().enumerate() {
        pushi_int(l, i as i64 + 1, *p as i64 + !zb as i64);
    }
    guard_leave!(l, g, 1);
    1
}
fn resolve_range(l: L) -> R {
    check_argc_range(l, "resolve_range", 3, 5);
    let g = guard_enter!(l);
    let n = lj::gettop(l);
    let data = &reqlstring(l, 1)[..];
    let (t, _) = payload_type_arg(l, 2);
    let sm = reqstring(l, 3);
    let strict = n >= 4 && lj::toboolean(l, 4);
    let zb = n >= 5 && lj::toboolean(l, 5);
    let Some(ms) = posmarker_list_parse(&sm, 2) else {
        lj::error(l, "bad marker list")
    };
    if ms.len() != 2 {
        lj::error(l, "resolve_range require 2 markers");
    }
    let mut p0 = resolve_pos(data, t, &ms[0]);
    let mut p1 = resolve_pos(data, t, &ms[1]);
    if (p0 == POS_NOT_FOUND && p1 == POS_NOT_FOUND)
        || (strict && (p0 == POS_NOT_FOUND || p1 == POS_NOT_FOUND))
    {
        lj::pushnil(l);
        return 1;
    }
    if p0 == POS_NOT_FOUND {
        p0 = 0;
    }
    if p1 == POS_NOT_FOUND {
        p1 = data.len() as isize - 1;
    }
    if p0 > p1 {
        lj::pushnil(l);
        return 1;
    }
    lj::newtable(l);
    pushi_int(l, 1, p0 as i64 + !zb as i64);
    pushi_int(l, 2, p1 as i64 + !zb as i64);
    guard_leave!(l, g, 1);
    1
}
fn tls_mod_(l: L) -> R {
    check_argc_range(l, "tls_mod", 2, 3);
    let g = guard_enter!(l);
    let n = lj::gettop(l);
    let fake = &reqlstring(l, 1)[..];
    let modlist = reqstring(l, 2);
    let payload = if n >= 3 && lj::typ(l, 3) != lj::LUA_TNIL {
        Some(reqlstring(l, 3))
    } else {
        None
    };
    let Some(m) = tls_mod_parse_list(&modlist) else {
        lj::error(l, &format!("invalid tls mod list : '{modlist}'"))
    };
    if m.modf != 0 {
        let maxlen = fake.len() + 256 + 4;
        lj::newuserdata(l, maxlen);
        let mut nt = fake.to_vec();
        if tls_mod(&m, payload.as_deref(), &mut nt, maxlen) {
            lj::pushbytes(l, &nt);
        } else {
            lj::pushnil(l);
        }
        lj::remove(l, -2);
    } else {
        lj::pushbytes(l, fake);
    }
    guard_leave!(l, g, 1);
    1
}

fn stat(l: L) -> R {
    check_argc(l, "stat", 1);
    let f = &lj::checkstring(l, 1)[..];
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let path: &std::ffi::OsStr = std::os::unix::ffi::OsStrExt::from_bytes(
        &f[..f.iter().position(|&x| x == 0).unwrap_or(f.len())],
    );
    let st = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) => {
            let e = e.raw_os_error().unwrap_or(0);
            lj::pushnil(l);
            lj::pushstr(l, &crate::log::strerror(e));
            lj::pushinteger(l, e as i64);
            return 3;
        }
    };
    lj::createtable(l, 0, 5);
    pushf_lint(l, "dev", st.dev() as i64);
    pushf_lint(l, "inode", st.ino() as i64);
    pushf_lint(l, "size", st.size() as i64);
    pushf_number(
        l,
        "mtime",
        st.mtime() as f64 + st.mtime_nsec() as f64 / 1000000000.,
    );
    let ft = st.file_type();
    let t = if ft.is_file() {
        "file"
    } else if ft.is_dir() {
        "dir"
    } else if ft.is_symlink() {
        "symlink"
    } else if ft.is_socket() {
        "socket"
    } else if ft.is_block_device() {
        "blockdev"
    } else if ft.is_char_device() {
        "chardev"
    } else if ft.is_fifo() {
        "fifo"
    } else {
        "unknown"
    };
    pushf_str(l, "type", Some(t.as_bytes()));
    1
}

fn xtime(l: L, gm: bool) {
    let Some(t) = crate::sys::breakdown(lj::checklint(l, 1), gm) else {
        lj::pushnil(l);
        return;
    };
    lj::createtable(l, 0, 11);
    pushf_int(l, "sec", t.sec as i64);
    pushf_int(l, "min", t.min as i64);
    pushf_int(l, "hour", t.hour as i64);
    pushf_int(l, "mday", t.mday as i64);
    pushf_int(l, "mon", t.mon as i64);
    pushf_int(l, "year", t.year as i64 + 1900);
    pushf_int(l, "wday", t.wday as i64);
    pushf_int(l, "yday", t.yday as i64);
    pushf_int(l, "isdst", t.isdst as i64);
    pushf_str(l, "zone", t.zone.as_deref());
    let s = format!(
        "{:02}.{:02}.{:04} {:02}:{:02}:{:02}",
        t.mday,
        t.mon + 1,
        t.year + 1900,
        t.hour,
        t.min,
        t.sec
    );
    pushf_str(l, "str", Some(s.as_bytes()));
}
fn localtime(l: L) -> R {
    check_argc(l, "localtime", 1);
    xtime(l, false);
    1
}
fn gmtime(l: L) -> R {
    check_argc(l, "gmtime", 1);
    xtime(l, true);
    1
}
fn timex(l: L, gm: bool) {
    if lj::typ(l, 1) != lj::LUA_TTABLE {
        lj::error(l, "invalid tm structure");
    }
    let mut t = crate::sys::Tm::default();
    let val = |f: &str| -> i32 {
        lj::getfield(l, 1, f);
        if lj::typ(l, -1) != lj::LUA_TNUMBER {
            lj::error(l, &format!("invalid tm.{f}"));
        }
        let v = lj::tointeger(l, -1) as i32;
        lj::pop(l, 1);
        v
    };
    t.sec = val("sec");
    t.min = val("min");
    t.hour = val("hour");
    t.mday = val("mday");
    t.mon = val("mon");
    t.year = val("year") - 1900;
    t.isdst = val("isdst");
    let u = crate::sys::compose(&t, gm);
    if u == -1 {
        lj::pushnil(l);
    } else {
        lj::pushlint(l, u);
    }
}
fn timelocal(l: L) -> R {
    check_argc(l, "timelocal", 1);
    timex(l, false);
    1
}
fn timegm(l: L) -> R {
    check_argc(l, "timegm", 1);
    timex(l, true);
    1
}

fn timer_set(l: L) -> R {
    check_argc_range(l, "timer_set", 3, 5);
    let g = guard_enter!(l);
    let n = lj::gettop(l);
    let name = cstrpart(lj::checkstring(l, 1));
    let period = lj::checkinteger(l, 3);
    if period < 10 {
        lj::error(l, "invalid timer period. must be >=10 ms");
    }
    let oneshot = n >= 4 && lj::toboolean(l, 4);
    match lj::typ(l, 2) {
        lj::LUA_TSTRING => {
            let f = cstrpart(lj::tobytes(l, 2).unwrap_or_default());
            lj::getglobal(l, &f);
            if !lj::isfunction(l, -1) {
                lj::pop(l, 1);
                lj::error(l, &format!("timer function '{f}' does not exist"));
            }
        }
        lj::LUA_TFUNCTION => lj::pushvalue(l, 2),
        _ => lj::error(l, "invalid timer function type"),
    }
    let p = params();
    let action = if p.timers.borrow().0.contains_key(&name) {
        p.timers.borrow_mut().del(&name);
        p.timers_dirty.set(true);
        "replaced"
    } else {
        "created"
    };
    let fref = lj::ref_(l);
    let dref = if n >= 5 {
        lj::pushvalue(l, 5);
        lj::ref_(l)
    } else {
        lj::LUA_NOREF
    };
    {
        let mut tp = p.timers.borrow_mut();
        let t = tp.add(&name, period as u64, oneshot);
        t.func_ref = fref;
        t.lua_ref = dref;
    }
    p.timers_dirty.set(true);
    dlog!(
        "timer: '{}' {}. period {} oneshot {}\n",
        name,
        action,
        period as u64,
        oneshot as u8
    );
    guard_leave!(l, g, 0);
    0
}
fn timer_del(l: L) -> R {
    check_argc(l, "timer_del", 1);
    let g = guard_enter!(l);
    let name = cstrpart(lj::checkstring(l, 1));
    let p = params();
    let found = p.timers.borrow().0.contains_key(&name);
    if found {
        dlog!("timer: '{}' deleted\n", name);
        p.timers.borrow_mut().del(&name);
        p.timers_dirty.set(true);
    } else {
        dlog!("timer: '{}' not found\n", name);
    }
    lj::pushboolean(l, found);
    guard_leave!(l, g, 1);
    1
}
fn timer_info(l: L) -> R {
    check_argc(l, "timer_info", 1);
    let g = guard_enter!(l);
    let name = cstrpart(lj::checkstring(l, 1));
    let p = params();
    let info = p
        .timers
        .borrow()
        .0
        .get(&name)
        .map(|t| (t.func_ref, t.period, t.oneshot, t.fires));
    match info {
        Some((fref, period, oneshot, fires)) => {
            lj::newtable(l);
            pushf_str(l, "name", Some(name.as_bytes()));
            if fref != lj::LUA_NOREF {
                lj::pushstr(l, "func");
                lj::rawgeti(l, lj::LUA_REGISTRYINDEX, fref as i64);
                lj::rawset(l, -3);
            }
            pushf_lint(l, "period", period as i64);
            pushf_bool(l, "oneshot", oneshot);
            pushf_lint(l, "fires", fires as i64);
        }
        None => lj::pushnil(l),
    }
    guard_leave!(l, g, 1);
    1
}
fn timer_enum(l: L) -> R {
    check_argc(l, "timer_enum", 0);
    let g = guard_enter!(l);
    lj::newtable(l);
    let names: Vec<String> = params().timers.borrow().0.keys().cloned().collect();
    for (i, n) in names.iter().enumerate() {
        pushi_str(l, i as i64 + 1, n.as_bytes());
    }
    guard_leave!(l, g, 1);
    1
}

pub fn functions() -> Vec<(&'static str, lj::lua_CFunction)> {
    let mut v: Vec<(&'static str, lj::lua_CFunction)> = vec![
        ("DLOG", crate::cfn!(dlog_)),
        ("DLOG_ERR", crate::cfn!(dlog_err_)),
        ("DLOG_CONDUP", crate::cfn!(dlog_condup_)),
        ("ntop", crate::cfn!(ntop)),
        ("pton", crate::cfn!(pton)),
        ("bitlshift", crate::cfn!(bitlshift)),
        ("bitrshift", crate::cfn!(bitrshift)),
        ("bitand", crate::cfn!(bitand)),
        ("bitor", crate::cfn!(bitor)),
        ("bitxor", crate::cfn!(bitxor)),
        ("bitget", crate::cfn!(bitget)),
        ("bitset", crate::cfn!(bitset)),
        ("bitnot", crate::cfn!(bitnot48)),
        ("bitnot8", crate::cfn!(bitnot8)),
        ("bitnot16", crate::cfn!(bitnot16)),
        ("bitnot24", crate::cfn!(bitnot24)),
        ("bitnot32", crate::cfn!(bitnot32)),
        ("bitnot48", crate::cfn!(bitnot48)),
        ("u8", crate::cfn!(u8_)),
        ("u16", crate::cfn!(u16_)),
        ("u24", crate::cfn!(u24_)),
        ("u32", crate::cfn!(u32_)),
        ("u48", crate::cfn!(u48_)),
        ("u8add", crate::cfn!(u8add)),
        ("u16add", crate::cfn!(u16add)),
        ("u24add", crate::cfn!(u24add)),
        ("u32add", crate::cfn!(u32add)),
        ("u48add", crate::cfn!(u48add)),
        ("bu8", crate::cfn!(bu8)),
        ("bu16", crate::cfn!(bu16)),
        ("bu24", crate::cfn!(bu24)),
        ("bu32", crate::cfn!(bu32)),
        ("bu48", crate::cfn!(bu48)),
        ("swap16", crate::cfn!(swap16)),
        ("swap24", crate::cfn!(swap24)),
        ("swap32", crate::cfn!(swap32)),
        ("swap48", crate::cfn!(swap48)),
        ("divint", crate::cfn!(divint)),
        ("brandom", crate::cfn!(brandom)),
        ("brandom_az", crate::cfn!(brandom_az)),
        ("brandom_az09", crate::cfn!(brandom_az09)),
        ("bcryptorandom", crate::cfn!(bcryptorandom)),
        ("bxor", crate::cfn!(bxor_)),
        ("bor", crate::cfn!(bor_)),
        ("band", crate::cfn!(band_)),
        ("hash", crate::cfn!(hash)),
        ("aes", crate::cfn!(aes)),
        ("aes_gcm", crate::cfn!(aes_gcm)),
        ("aes_ctr", crate::cfn!(aes_ctr)),
        ("hkdf", crate::cfn!(hkdf)),
        ("parse_hex", crate::cfn!(parse_hex)),
        ("instance_cutoff", crate::cfn!(instance_cutoff)),
        ("lua_cutoff", crate::cfn!(lua_cutoff)),
        ("execution_plan", crate::cfn!(execution_plan)),
        ("execution_plan_cancel", crate::cfn!(execution_plan_cancel)),
        ("raw_packet", crate::cfn!(raw_packet)),
        ("uname", crate::cfn!(uname)),
        ("clock_gettime", crate::cfn!(clock_gettime)),
        ("clock_getfloattime", crate::cfn!(clock_getfloattime)),
        ("getpid", crate::cfn!(getpid)),
        ("gettid", crate::cfn!(gettid)),
        ("reconstruct_tcphdr", crate::cfn!(reconstruct_tcphdr_)),
        ("reconstruct_udphdr", crate::cfn!(reconstruct_udphdr_)),
        ("reconstruct_icmphdr", crate::cfn!(reconstruct_icmphdr_)),
        ("reconstruct_ip6hdr", crate::cfn!(reconstruct_ip6hdr_)),
        ("reconstruct_iphdr", crate::cfn!(reconstruct_iphdr_)),
        ("reconstruct_dissect", crate::cfn!(reconstruct_dissect_)),
        ("dissect_tcphdr", crate::cfn!(dissect_tcphdr)),
        ("dissect_udphdr", crate::cfn!(dissect_udphdr)),
        ("dissect_icmphdr", crate::cfn!(dissect_icmphdr)),
        ("dissect_ip6hdr", crate::cfn!(dissect_ip6hdr)),
        ("dissect_iphdr", crate::cfn!(dissect_iphdr)),
        ("dissect", crate::cfn!(dissect)),
        ("csum_ip4_fix", crate::cfn!(csum_ip4_fix)),
        ("csum_tcp_fix", crate::cfn!(csum_tcp_fix)),
        ("csum_udp_fix", crate::cfn!(csum_udp_fix)),
        ("csum_icmp_fix", crate::cfn!(csum_icmp_fix)),
        ("rawsend", crate::cfn!(rawsend_)),
        ("rawsend_dissect", crate::cfn!(rawsend_dissect)),
        ("conntrack_feed", crate::cfn!(conntrack_feed)),
        ("get_source_ip", crate::cfn!(get_source_ip)),
        ("get_ifaddrs", crate::cfn!(get_ifaddrs)),
        ("resolve_pos", crate::cfn!(resolve_pos_)),
        ("resolve_multi_pos", crate::cfn!(resolve_multi_pos_)),
        ("resolve_range", crate::cfn!(resolve_range)),
        ("tls_mod", crate::cfn!(tls_mod_)),
    ];
    v.extend(super::zlib::functions());
    v.extend([
        ("stat", crate::cfn!(stat)),
        ("localtime", crate::cfn!(localtime)),
        ("gmtime", crate::cfn!(gmtime)),
        ("timelocal", crate::cfn!(timelocal)),
        ("timegm", crate::cfn!(timegm)),
        ("timer_set", crate::cfn!(timer_set)),
        ("timer_del", crate::cfn!(timer_del)),
        ("timer_info", crate::cfn!(timer_info)),
        ("timer_enum", crate::cfn!(timer_enum)),
    ]);
    v
}
