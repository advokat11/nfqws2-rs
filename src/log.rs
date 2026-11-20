//! Port of the DLOG family in params.c. Output goes through libc stdio like the original.

use crate::cffi::fwrite_std;
use std::cell::RefCell;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum LogTarget {
    #[default]
    Console,
    File,
    Syslog,
}

#[derive(Default)]
pub struct LogCfg {
    pub debug: bool,
    pub target: LogTarget,
    pub logfile: String,
    pub hostlist_auto_debuglog: String,
    buf: Vec<u8>,
}

thread_local! {
    pub static LOG: RefCell<LogCfg> = RefCell::new(LogCfg::default());
}

pub fn debug() -> bool {
    LOG.with(|l| l.borrow().debug)
}

const LOG_ERR: i32 = 3;
const LOG_DEBUG: i32 = 7;

fn log_buffered(cfg: &mut LogCfg, prio: i32, s: &[u8]) {
    // vsnprintf into a 4096 buffer leaving 1 byte
    let room = 4096 - cfg.buf.len() - 1;
    if s.is_empty() {
        return;
    }
    let take = s.len().min(room.saturating_sub(1));
    cfg.buf.extend_from_slice(&s[..take]);
    // strlen semantics: stop at embedded NUL
    if let Some(p) = cfg.buf.iter().position(|&c| c == 0) {
        cfg.buf.truncate(p);
    }
    let flush = if cfg.buf.len() == 4096 - 2 {
        cfg.buf.push(b'\n');
        true
    } else {
        cfg.buf.last() == Some(&b'\n')
    };
    if flush {
        let line = std::mem::take(&mut cfg.buf);
        match cfg.target {
            LogTarget::File => {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(&cfg.logfile)
                {
                    let _ = f.write_all(&line);
                }
            }
            LogTarget::Syslog => {
                if let Ok(c) = std::ffi::CString::new(line) {
                    // SAFETY: format string and argument are valid C strings.
                    unsafe { libc::syslog(prio, c"%s".as_ptr(), c.as_ptr()) };
                }
            }
            LogTarget::Console => {}
        }
    }
}

pub fn dlog_va(s: &[u8], prio: i32, condup: bool) {
    LOG.with(|l| {
        let mut cfg = l.borrow_mut();
        if condup && !(cfg.debug && cfg.target == LogTarget::Console) {
            fwrite_std(prio == LOG_ERR, s);
        }
        if cfg.debug {
            match cfg.target {
                LogTarget::Console => fwrite_std(prio == LOG_ERR, s),
                _ => log_buffered(&mut cfg, prio, s),
            }
        }
    })
}

pub fn dlog_str(s: &str) {
    dlog_va(s.as_bytes(), LOG_DEBUG, false)
}
pub fn dlog_bytes(s: &[u8]) {
    dlog_va(s, LOG_DEBUG, false)
}
pub fn dlog_condup_str(s: &str) {
    dlog_va(s.as_bytes(), LOG_DEBUG, true)
}
pub fn dlog_err_str(s: &str) {
    dlog_va(s.as_bytes(), LOG_ERR, true)
}
pub fn dlog_perror(s: &str) {
    let e = std::io::Error::last_os_error();
    dlog_err_str(&format!(
        "{}: {}\n",
        s,
        strerror(e.raw_os_error().unwrap_or(0))
    ));
}
pub fn dlog_perror_errno(s: &str, errno: i32) {
    dlog_err_str(&format!("{}: {}\n", s, strerror(errno)));
}

pub fn strerror(errno: i32) -> String {
    // SAFETY: strerror returns a valid static C string.
    unsafe {
        std::ffi::CStr::from_ptr(libc::strerror(errno))
            .to_string_lossy()
            .into_owned()
    }
}

/// HOSTLIST_DEBUGLOG_APPEND
pub fn hostlist_debuglog_append(s: &str) {
    let path = LOG.with(|l| l.borrow().hostlist_auto_debuglog.clone());
    if path.is_empty() {
        return;
    }
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
    {
        let _ = writeln!(f, "{} : {}", crate::helpers::localtime_str(), s);
    }
}

pub fn hexdump_limited_dlog(data: &[u8], limit: usize) {
    let (size, cut) = if data.len() > limit {
        (limit, true)
    } else {
        (data.len(), false)
    };
    if size == 0 {
        return;
    }
    let mut b = Vec::with_capacity(size * 4 + 16);
    for &c in &data[..size] {
        b.push(crate::helpers::hex_digit(c >> 4));
        b.push(crate::helpers::hex_digit(c & 0xF));
        b.push(b' ');
    }
    if cut {
        b.extend_from_slice(b"... ");
    }
    b.extend_from_slice(b": ");
    for &c in &data[..size] {
        b.push(if (0x20..=0x7F).contains(&c) { c } else { b'.' });
    }
    if cut {
        b.extend_from_slice(b" ...");
    }
    dlog_bytes(&b);
}

#[macro_export]
macro_rules! dlog {
    ($($a:tt)*) => { if $crate::log::debug() { $crate::log::dlog_str(&format!($($a)*)) } };
}
#[macro_export]
macro_rules! dlog_err {
    ($($a:tt)*) => { $crate::log::dlog_err_str(&format!($($a)*)) };
}
#[macro_export]
macro_rules! dlog_condup {
    ($($a:tt)*) => { $crate::log::dlog_condup_str(&format!($($a)*)) };
}
