//! lua.c gzip/gunzip stream bindings over the same system zlib as the C original.
//! The Lua side holds a userdata of the C struct's size (so the Lua heap accounting is
//! unchanged); it stores a handle into a per-thread table of `ZStream`s.

use super::lj::{self, L};
use super::push::{guard_enter, guard_leave};
use libz_sys as z;
use std::cell::RefCell;
use std::os::raw::{c_int, c_uint};

/// The C original's userdata layout; only its size is used here.
#[repr(C)]
#[allow(dead_code)]
struct CUzs {
    valid: bool,
    inflate: bool,
    zs: z::z_stream,
}
const UDATA_SIZE: usize = std::mem::size_of::<CUzs>();
const MT: &std::ffi::CStr = c"userdata_zstream";
const BUFMIN: usize = 64;
const Z_INFL_BUF_INCREMENT: usize = 16384;
const Z_DEFL_BUF_INCREMENT: usize = 8192;

/// An initialized zlib stream. The z_stream is boxed: zlib keeps a back pointer to it.
struct ZStream {
    zs: Box<z::z_stream>,
    inflate: bool,
}

extern "C" fn z_alloc(_o: z::voidpf, items: z::uInt, size: z::uInt) -> z::voidpf {
    // SAFETY: plain allocation, freed by z_free.
    unsafe { libc::malloc(items as usize * size as usize) }
}
extern "C" fn z_free(_o: z::voidpf, a: z::voidpf) {
    // SAFETY: a was allocated by z_alloc (or is NULL).
    unsafe { libc::free(a) }
}

fn zeroed_stream() -> Box<z::z_stream> {
    Box::new(z::z_stream {
        next_in: std::ptr::null_mut(),
        avail_in: 0,
        total_in: 0,
        next_out: std::ptr::null_mut(),
        avail_out: 0,
        total_out: 0,
        msg: std::ptr::null_mut(),
        state: std::ptr::null_mut(),
        zalloc: z_alloc,
        zfree: z_free,
        opaque: std::ptr::null_mut(),
        data_type: 0,
        adler: 0,
        reserved: 0,
    })
}

impl ZStream {
    fn inflate_init(wb: c_int) -> Result<Self, c_int> {
        let mut zs = zeroed_stream();
        // SAFETY: zs is a fresh boxed stream with allocators set.
        let r = unsafe {
            z::inflateInit2_(
                &mut *zs,
                wb,
                z::zlibVersion(),
                std::mem::size_of::<z::z_stream>() as c_int,
            )
        };
        if r == z::Z_OK {
            Ok(ZStream { zs, inflate: true })
        } else {
            Err(r)
        }
    }
    fn deflate_init(level: c_int, wb: c_int, memlevel: c_int) -> Result<Self, c_int> {
        let mut zs = zeroed_stream();
        // SAFETY: zs is a fresh boxed stream with allocators set.
        let r = unsafe {
            z::deflateInit2_(
                &mut *zs,
                level,
                z::Z_DEFLATED,
                wb,
                memlevel,
                z::Z_DEFAULT_STRATEGY,
                z::zlibVersion(),
                std::mem::size_of::<z::z_stream>() as c_int,
            )
        };
        if r == z::Z_OK {
            Ok(ZStream { zs, inflate: false })
        } else {
            Err(r)
        }
    }
    /// One inflate()/deflate() call over `input` into `out`.
    /// Returns (zlib result, bytes consumed, bytes produced).
    fn step(&mut self, input: &[u8], out: &mut [u8], flush: c_int) -> (c_int, usize, usize) {
        let zs = &mut *self.zs;
        zs.next_in = input.as_ptr() as *mut u8;
        zs.avail_in = input.len() as c_uint;
        zs.next_out = out.as_mut_ptr();
        zs.avail_out = out.len() as c_uint;
        // SAFETY: initialized stream; next_in/next_out describe live buffers for this call.
        let r = unsafe {
            if self.inflate {
                z::inflate(zs, flush)
            } else {
                z::deflate(zs, flush)
            }
        };
        let used = input.len() - zs.avail_in as usize;
        let made = out.len() - zs.avail_out as usize;
        zs.next_in = std::ptr::null_mut();
        zs.avail_in = 0;
        zs.next_out = std::ptr::null_mut();
        zs.avail_out = 0;
        (r, used, made)
    }
}

impl Drop for ZStream {
    fn drop(&mut self) {
        // SAFETY: the stream was successfully initialized and is ended exactly once.
        unsafe {
            if self.inflate {
                z::inflateEnd(&mut *self.zs);
            } else {
                z::deflateEnd(&mut *self.zs);
            }
        }
    }
}

thread_local! {
    /// Streams by handle (handle = index + 1; 0 means none). None = ended or collected.
    static STREAMS: RefCell<Vec<Option<ZStream>>> = const { RefCell::new(Vec::new()) };
}

fn store(s: ZStream) -> usize {
    STREAMS.with(|t| {
        let mut t = t.borrow_mut();
        match t.iter().position(Option::is_none) {
            Some(i) => {
                t[i] = Some(s);
                i + 1
            }
            None => {
                t.push(Some(s));
                t.len()
            }
        }
    })
}
fn release(id: usize) {
    let s = STREAMS.with(|t| {
        t.borrow_mut()
            .get_mut(id.wrapping_sub(1))
            .and_then(Option::take)
    });
    drop(s);
}

/// Run `f` on the valid stream of the role `inflate` at `idx`; raises like the C original.
fn with_stream<T>(l: L, idx: c_int, inflate: bool, f: impl FnOnce(&mut ZStream) -> T) -> T {
    let id = lj::checkudata_id(l, idx, MT);
    let r = STREAMS.with(|t| {
        let mut t = t.borrow_mut();
        match t.get_mut(id.wrapping_sub(1)).and_then(Option::as_mut) {
            None => Err("gzip stream is not valid"),
            Some(s) if s.inflate != inflate => Err("gzip stream role mismatch"),
            Some(s) => Ok(f(s)),
        }
    });
    r.unwrap_or_else(|e| lj::error(l, e))
}

fn gc(l: L) -> c_int {
    release(lj::checkudata_id(l, 1, MT));
    0
}

pub fn mt_init(l: L) {
    let g = guard_enter!(l);
    lj::newmetatable(l, MT);
    lj::pushcfunction(l, crate::cfn!(gc));
    lj::setfield(l, -2, "__gc");
    lj::pushcfunction(l, crate::cfn!(gc));
    lj::setfield(l, -2, "__close");
    lj::pop(l, 1);
    guard_leave!(l, g, 0);
}

fn argc_range(l: L, name: &str, a: i32, b: i32) {
    let n = lj::gettop(l);
    if n < a || n > b {
        lj::error_argc_range(l, name, a, b, n);
    }
}
fn argc(l: L, name: &str, a: i32) {
    let n = lj::gettop(l);
    if n != a {
        lj::error_argc(l, name, a, n);
    }
}

/// Push the userdata for a freshly initialized stream (or nil when init failed).
fn push_stream(l: L, s: Result<ZStream, c_int>) {
    // One userdata either way, like the C original (it becomes garbage on failure).
    match s {
        Ok(s) => {
            lj::newuserdata_id(l, UDATA_SIZE, store(s));
            lj::getmetatable_reg(l, MT);
            lj::setmetatable(l, -2);
        }
        Err(_) => {
            lj::newuserdata_id(l, UDATA_SIZE, 0);
            lj::pop(l, 1);
            lj::pushnil(l);
        }
    }
}

fn gunzip_init(l: L) -> c_int {
    argc_range(l, "gunzip_init", 0, 1);
    let g = guard_enter!(l);
    let n = lj::gettop(l);
    let wb = if n >= 1 && !lj::isnil(l, 1) {
        lj::checkinteger(l, 1) as c_int
    } else {
        47
    };
    push_stream(l, ZStream::inflate_init(wb));
    guard_leave!(l, g, 1);
    1
}
fn gunzip_end(l: L) -> c_int {
    argc(l, "gunzip_end", 1);
    with_stream(l, 1, true, |_| ());
    release(lj::checkudata_id(l, 1, MT));
    0
}

/// The C buffer growth loop shared by inflate and deflate.
/// `done(r, input_left, out_left)` decides: Some(ok) stops, None continues.
fn pump(
    s: &mut ZStream,
    input: &[u8],
    bufchunk: usize,
    inc: usize,
    flush: c_int,
    done: impl Fn(c_int, usize, usize) -> Option<bool>,
) -> (bool, c_int, Vec<u8>) {
    let mut buf: Vec<u8> = Vec::new();
    let mut size = 0usize;
    let mut pos = 0usize;
    let mut allocated = false;
    loop {
        if buf.len() - size < BUFMIN {
            let add = if allocated { inc } else { bufchunk };
            allocated = true;
            buf.resize(buf.len() + add, 0);
        }
        let (r, used, made) = s.step(&input[pos..], &mut buf[size..], flush);
        pos += used;
        size += made;
        if let Some(ok) = done(r, input.len() - pos, buf.len() - size) {
            buf.truncate(size);
            return (ok, r, buf);
        }
    }
}

fn push_result(l: L, (ok, r, buf): (bool, c_int, Vec<u8>)) {
    if ok {
        lj::pushbytes(l, &buf);
        lj::pushboolean(l, r == z::Z_STREAM_END);
    } else {
        lj::pushnil(l);
        lj::pushnil(l);
    }
}

fn gunzip_inflate(l: L) -> c_int {
    argc_range(l, "gunzip_inflate", 2, 3);
    let g = guard_enter!(l);
    let n = lj::gettop(l);
    with_stream(l, 1, true, |_| ());
    let input = lj::checklstring(l, 2);
    let bufchunk = if n >= 3 {
        lj::checkinteger(l, 3) as usize
    } else {
        input.len() * 4
    };
    let inc = (bufchunk / 2).max(Z_INFL_BUF_INCREMENT);
    let res = with_stream(l, 1, true, |s| {
        pump(
            s,
            &input,
            bufchunk,
            inc,
            z::Z_NO_FLUSH,
            |r, in_left, _| match r {
                z::Z_STREAM_END => Some(true),
                z::Z_BUF_ERROR => Some(in_left == 0),
                z::Z_OK => None,
                _ => Some(false),
            },
        )
    });
    push_result(l, res);
    guard_leave!(l, g, 2);
    2
}
fn gzip_init(l: L) -> c_int {
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
    push_stream(l, ZStream::deflate_init(level, wb, memlevel));
    guard_leave!(l, g, 1);
    1
}
fn gzip_end(l: L) -> c_int {
    argc(l, "gzip_end", 1);
    with_stream(l, 1, false, |_| ());
    release(lj::checkudata_id(l, 1, MT));
    0
}
fn gzip_deflate(l: L) -> c_int {
    argc_range(l, "gzip_deflate", 1, 3);
    let g = guard_enter!(l);
    let n = lj::gettop(l);
    with_stream(l, 1, false, |_| ());
    let input = if n >= 2 && !lj::isnil(l, 2) {
        lj::checklstring(l, 2)
    } else {
        Vec::new()
    };
    let inl = input.len();
    let bufchunk = BUFMIN
        + if n >= 3 {
            lj::checkinteger(l, 3) as usize
        } else {
            inl / 2
        };
    let inc = (bufchunk / 2).max(Z_DEFL_BUF_INCREMENT);
    let flush = if inl != 0 { z::Z_NO_FLUSH } else { z::Z_FINISH };
    let res = with_stream(l, 1, false, |s| {
        pump(
            s,
            &input,
            bufchunk,
            inc,
            flush,
            |r, in_left, out_left| match r {
                z::Z_STREAM_END => Some(true),
                z::Z_OK if out_left != 0 && in_left == 0 && flush != z::Z_FINISH => Some(true),
                z::Z_OK => None,
                _ => Some(false),
            },
        )
    });
    push_result(l, res);
    guard_leave!(l, g, 2);
    2
}

pub fn functions() -> Vec<(&'static str, lj::lua_CFunction)> {
    vec![
        ("gunzip_init", crate::cfn!(gunzip_init)),
        ("gunzip_end", crate::cfn!(gunzip_end)),
        ("gunzip_inflate", crate::cfn!(gunzip_inflate)),
        ("gzip_init", crate::cfn!(gzip_init)),
        ("gzip_end", crate::cfn!(gzip_end)),
        ("gzip_deflate", crate::cfn!(gzip_deflate)),
    ]
}
