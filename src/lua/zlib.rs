//! lua.c gzip/gunzip stream bindings. The z_stream lives inside Lua userdata (LuaJIT's GC
//! does not move objects), exactly like the C original, and uses the same system zlib.
//! SAFETY: lua_CFunctions called by LuaJIT with a valid state; the userdata is checked
//! with luaL_checkudata before it is touched; zlib calls follow zlib's documented contract.

#![allow(clippy::missing_safety_doc)]

use super::lj::{self, L};
use super::push::{guard_enter, guard_leave};
use libz_sys as z;
use std::os::raw::{c_int, c_uint};

#[repr(C)]
struct Uzs {
    valid: bool,
    inflate: bool,
    zs: z::z_stream,
}

const MT: &std::ffi::CStr = c"userdata_zstream";
const BUFMIN: usize = 64;
const Z_INFL_BUF_INCREMENT: usize = 16384;
const Z_DEFL_BUF_INCREMENT: usize = 8192;

extern "C" fn z_alloc(_o: z::voidpf, items: z::uInt, size: z::uInt) -> z::voidpf {
    // SAFETY: plain allocation, freed by z_free.
    unsafe { libc::malloc(items as usize * size as usize) }
}
extern "C" fn z_free(_o: z::voidpf, a: z::voidpf) {
    // SAFETY: a was allocated by z_alloc (or is NULL).
    unsafe { libc::free(a) }
}

unsafe fn new_uzs(l: L) -> *mut Uzs {
    let u = lj::newuserdata(l, std::mem::size_of::<Uzs>()) as *mut Uzs;
    std::ptr::write_bytes(u as *mut u8, 0, std::mem::size_of::<Uzs>());
    (*u).zs.zalloc = z_alloc;
    (*u).zs.zfree = z_free;
    u
}

unsafe extern "C-unwind" fn gc(l: L) -> c_int {
    let u = lj::checkudata(l, 1, MT) as *mut Uzs;
    if (*u).valid {
        if (*u).inflate {
            z::inflateEnd(&mut (*u).zs);
        } else {
            z::deflateEnd(&mut (*u).zs);
        }
        (*u).valid = false;
    }
    0
}

pub unsafe fn mt_init(l: L) {
    let g = guard_enter!(l);
    lj::newmetatable(l, MT);
    lj::pushcfunction(l, gc);
    lj::setfield(l, -2, "__gc");
    lj::pushcfunction(l, gc);
    lj::setfield(l, -2, "__close");
    lj::pop(l, 1);
    guard_leave!(l, g, 0);
}

unsafe fn uzs(l: L, idx: c_int, inflate: bool) -> *mut Uzs {
    let u = lj::checkudata(l, idx, MT) as *mut Uzs;
    if !(*u).valid {
        lj::error(l, "gzip stream is not valid");
    }
    if inflate != (*u).inflate {
        lj::error(l, "gzip stream role mismatch");
    }
    u
}

unsafe fn argc_range(l: L, name: &str, a: i32, b: i32) {
    let n = lj::gettop(l);
    if n < a || n > b {
        lj::error(
            l,
            &format!("{name} expect from {a} to {b} arguments, got {n}"),
        );
    }
}
unsafe fn argc(l: L, name: &str, a: i32) {
    let n = lj::gettop(l);
    if n != a {
        lj::error(l, &format!("{name} expect exactly {a} arguments, got {n}"));
    }
}

unsafe extern "C-unwind" fn gunzip_init(l: L) -> c_int {
    argc_range(l, "gunzip_init", 0, 1);
    let g = guard_enter!(l);
    let n = lj::gettop(l);
    let wb = if n >= 1 && !lj::isnil(l, 1) {
        lj::checkinteger(l, 1) as c_int
    } else {
        47
    };
    let u = new_uzs(l);
    let r = z::inflateInit2_(
        &mut (*u).zs,
        wb,
        z::zlibVersion(),
        std::mem::size_of::<z::z_stream>() as c_int,
    );
    if r == z::Z_OK {
        (*u).inflate = true;
        (*u).valid = true;
        lj::getmetatable_reg(l, MT);
        lj::setmetatable(l, -2);
    } else {
        lj::pop(l, 1);
        lj::pushnil(l);
    }
    guard_leave!(l, g, 1);
    1
}
unsafe extern "C-unwind" fn gunzip_end(l: L) -> c_int {
    argc(l, "gunzip_end", 1);
    let u = uzs(l, 1, true);
    z::inflateEnd(&mut (*u).zs);
    (*u).valid = false;
    0
}
unsafe extern "C-unwind" fn gunzip_inflate(l: L) -> c_int {
    argc_range(l, "gunzip_inflate", 2, 3);
    let g = guard_enter!(l);
    let n = lj::gettop(l);
    let u = uzs(l, 1, true);
    let input = lj::checklstring(l, 2);
    (*u).zs.next_in = input.as_ptr() as *mut u8;
    (*u).zs.avail_in = input.len() as c_uint;
    let bufchunk = if n >= 3 {
        lj::checkinteger(l, 3) as usize
    } else {
        input.len() * 4
    };
    let inc = (bufchunk / 2).max(Z_INFL_BUF_INCREMENT);
    let mut buf: Vec<u8> = Vec::new();
    let mut bufsize = 0usize;
    let mut size = 0usize;
    let mut r;
    let mut allocated = false;
    let ok = loop {
        if bufsize - size < BUFMIN {
            bufsize += if allocated { inc } else { bufchunk };
            allocated = true;
            buf.resize(bufsize, 0);
        }
        (*u).zs.avail_out = (bufsize - size) as c_uint;
        (*u).zs.next_out = buf.as_mut_ptr().add(size);
        r = z::inflate(&mut (*u).zs, z::Z_NO_FLUSH);
        size = bufsize - (*u).zs.avail_out as usize;
        if r == z::Z_STREAM_END {
            break true;
        }
        if r == z::Z_BUF_ERROR {
            break (*u).zs.avail_in == 0;
        }
        if r != z::Z_OK {
            break false;
        }
    };
    if ok {
        lj::pushbytes(l, &buf[..size]);
        lj::pushboolean(l, r == z::Z_STREAM_END);
    } else {
        lj::pushnil(l);
        lj::pushnil(l);
    }
    guard_leave!(l, g, 2);
    2
}
unsafe extern "C-unwind" fn gzip_init(l: L) -> c_int {
    argc_range(l, "gzip_init", 0, 3);
    let g = guard_enter!(l);
    let n = lj::gettop(l);
    let wb = if n >= 1 && !lj::isnil(l, 1) {
        lj::checkinteger(l, 1) as c_int
    } else {
        31
    };
    let level = if n >= 2 && !lj::isnil(l, 2) {
        lj::checkinteger(l, 2) as c_int
    } else {
        9
    };
    let memlevel = if n >= 3 && !lj::isnil(l, 3) {
        lj::checkinteger(l, 3) as c_int
    } else {
        8
    };
    let u = new_uzs(l);
    let r = z::deflateInit2_(
        &mut (*u).zs,
        level,
        z::Z_DEFLATED,
        wb,
        memlevel,
        z::Z_DEFAULT_STRATEGY,
        z::zlibVersion(),
        std::mem::size_of::<z::z_stream>() as c_int,
    );
    if r == z::Z_OK {
        (*u).inflate = false;
        (*u).valid = true;
        lj::newmetatable(l, MT);
        lj::setmetatable(l, -2);
    } else {
        lj::pop(l, 1);
        lj::pushnil(l);
    }
    guard_leave!(l, g, 1);
    1
}
unsafe extern "C-unwind" fn gzip_end(l: L) -> c_int {
    argc(l, "gzip_end", 1);
    let u = uzs(l, 1, false);
    z::deflateEnd(&mut (*u).zs);
    (*u).valid = false;
    0
}
unsafe extern "C-unwind" fn gzip_deflate(l: L) -> c_int {
    argc_range(l, "gzip_deflate", 1, 3);
    let g = guard_enter!(l);
    let n = lj::gettop(l);
    let u = uzs(l, 1, false);
    let mut inl = 0usize;
    if n >= 2 && !lj::isnil(l, 2) {
        let input = lj::checklstring(l, 2);
        inl = input.len();
        (*u).zs.next_in = input.as_ptr() as *mut u8;
        (*u).zs.avail_in = inl as c_uint;
    }
    let bufchunk = BUFMIN
        + if n >= 3 {
            lj::checkinteger(l, 3) as usize
        } else {
            inl / 2
        };
    let inc = (bufchunk / 2).max(Z_DEFL_BUF_INCREMENT);
    let flush = if inl != 0 { z::Z_NO_FLUSH } else { z::Z_FINISH };
    let mut buf: Vec<u8> = Vec::new();
    let mut bufsize = 0usize;
    let mut size = 0usize;
    let mut r;
    let mut allocated = false;
    let ok = loop {
        if bufsize - size < BUFMIN {
            bufsize += if allocated { inc } else { bufchunk };
            allocated = true;
            buf.resize(bufsize, 0);
        }
        (*u).zs.avail_out = (bufsize - size) as c_uint;
        (*u).zs.next_out = buf.as_mut_ptr().add(size);
        r = z::deflate(&mut (*u).zs, flush);
        size = bufsize - (*u).zs.avail_out as usize;
        if r == z::Z_STREAM_END {
            break true;
        }
        if r == z::Z_OK {
            if (*u).zs.avail_out != 0 && (*u).zs.avail_in == 0 && flush != z::Z_FINISH {
                break true;
            }
        } else {
            break false;
        }
    };
    if ok {
        lj::pushbytes(l, &buf[..size]);
        lj::pushboolean(l, r == z::Z_STREAM_END);
    } else {
        lj::pushnil(l);
        lj::pushnil(l);
    }
    guard_leave!(l, g, 2);
    2
}

pub fn functions() -> Vec<(&'static str, lj::lua_CFunction)> {
    vec![
        ("gunzip_init", gunzip_init as lj::lua_CFunction),
        ("gunzip_end", gunzip_end),
        ("gunzip_inflate", gunzip_inflate),
        ("gzip_init", gzip_init),
        ("gzip_end", gzip_end),
        ("gzip_deflate", gzip_deflate),
    ]
}
