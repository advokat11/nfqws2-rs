//! glibc functions the libc crate does not bind. Same symbols as the C original uses,
//! so LD_PRELOAD shims and RNG streams behave identically (ADR-007).

use std::os::raw::{c_char, c_int, c_long, c_uint, c_void};

unsafe extern "C" {
    pub fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
    pub fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: u32) -> *const c_char;
    pub fn random() -> c_long;
    pub fn srandom(seed: c_uint);
}

unsafe extern "C" {
    pub static mut stdout: *mut libc::FILE;
    pub static mut stderr: *mut libc::FILE;
}

/// Write bytes to libc's stdout or stderr FILE (shared with Lua's io/print).
pub fn fwrite_std(err: bool, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    // SAFETY: stdout/stderr are valid glibc FILE pointers for the whole process lifetime.
    unsafe {
        let f = if err { stderr } else { stdout };
        libc::fwrite(data.as_ptr() as *const _, 1, data.len(), f);
    }
}

pub fn set_console_io_buffering() {
    // SAFETY: setvbuf on the standard streams before other output, as the C code does.
    unsafe {
        libc::setvbuf(stdout, std::ptr::null_mut(), libc::_IOLBF, 0);
        libc::setvbuf(stderr, std::ptr::null_mut(), libc::_IOLBF, 0);
    }
}

pub fn fflush_all() {
    // SAFETY: fflush(NULL) flushes all streams.
    unsafe {
        libc::fflush(std::ptr::null_mut());
    }
}
