//! Port of helpers.c: byte-order helpers, string helpers, files, randomness, time.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::Ipv4Addr;

pub fn unique_sorted<T: PartialEq + Copy>(v: &mut Vec<T>) {
    v.dedup();
}

pub fn str_index(strs: &[&str], s: &str) -> Option<usize> {
    strs.iter().position(|x| *x == s)
}

/// Strip trailing CR/LF.
pub fn rtrim(s: &mut Vec<u8>) {
    while matches!(s.last(), Some(b'\n') | Some(b'\r')) {
        s.pop();
    }
}

/// Case-insensitive search of `find` inside the first `s.len()` bytes of `s`.
/// Returns the byte offset of the match.
pub fn strncasestr(s: &[u8], find: &[u8]) -> Option<usize> {
    if find.is_empty() {
        return Some(0);
    }
    // C semantics: stops at NUL inside s as well (strncasecmp)
    let n = find.len();
    if n > s.len() {
        return None;
    }
    (0..=s.len() - n).find(|&i| {
        s[i..i + n]
            .iter()
            .zip(find)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

pub fn is_identifier(p: &str) -> bool {
    let b = p.as_bytes();
    if b.is_empty() || !(b[0] == b'_' || b[0].is_ascii_alphabetic()) {
        return false;
    }
    b[1..]
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

pub fn load_file(filename: &str, offset: u64, max: usize) -> Option<Vec<u8>> {
    let mut f = File::open(filename).ok()?;
    if offset != 0 {
        f.seek(SeekFrom::Start(offset)).ok()?;
    }
    let mut buf = Vec::new();
    f.take(max as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

pub fn save_file(filename: &str, data: &[u8]) -> bool {
    match File::create(filename) {
        Ok(mut f) => f.write_all(data).is_ok(),
        Err(_) => false,
    }
}

pub fn append_to_list_file(filename: &str, s: &[u8]) -> bool {
    let f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(filename);
    match f {
        Ok(mut f) => {
            let mut v = s.to_vec();
            v.push(b'\n');
            f.write_all(&v).is_ok()
        }
        Err(_) => false,
    }
}

pub fn expand_bits(target: &mut [u8], source: &[u8], source_bitlen: u32) {
    let target_bytelen = target.len() as u32;
    let target_bitlen = target_bytelen << 3;
    let mut bitlen = target_bitlen.min(source_bitlen);
    let bytelen = (bitlen >> 3) as usize;
    for b in target[bytelen..].iter_mut() {
        *b = 0;
    }
    target[..bytelen].copy_from_slice(&source[..bytelen]);
    bitlen &= 7;
    if bitlen != 0 {
        target[bytelen] = source[bytelen] & !(((1u32 << (8 - bitlen)) - 1) as u8);
    }
}

pub fn inet_pton4(s: &[u8]) -> Option<[u8; 4]> {
    // glibc inet_pton AF_INET: strict dotted quad, no leading zeros beyond a single 0
    let mut out = [0u8; 4];
    let mut octets = 0usize;
    let mut saw_digit = false;
    let mut cur: u32 = 0;
    for &c in s {
        if c.is_ascii_digit() {
            if saw_digit && cur == 0 {
                return None;
            }
            cur = cur * 10 + (c - b'0') as u32;
            if cur > 255 {
                return None;
            }
            if !saw_digit {
                octets += 1;
                if octets > 4 {
                    return None;
                }
                saw_digit = true;
            }
        } else if c == b'.' && saw_digit {
            if octets == 4 {
                return None;
            }
            out[octets - 1] = cur as u8;
            cur = 0;
            saw_digit = false;
        } else {
            return None;
        }
    }
    if octets < 4 || !saw_digit {
        return None;
    }
    out[3] = cur as u8;
    Some(out)
}

pub fn inet_pton6(s: &[u8]) -> Option<[u8; 16]> {
    let cs = CString::new(s).ok()?;
    let mut a = [0u8; 16];
    // SAFETY: cs is NUL-terminated and `a` has room for an in6_addr.
    let r =
        unsafe { crate::cffi::inet_pton(libc::AF_INET6, cs.as_ptr(), a.as_mut_ptr() as *mut _) };
    (r > 0).then_some(a)
}

pub fn ntop4(a: &[u8]) -> String {
    Ipv4Addr::new(a[0], a[1], a[2], a[3]).to_string()
}

/// inet_ntop(AF_INET6) with glibc formatting.
pub fn ntop6(a: &[u8]) -> String {
    let mut buf = [0 as libc::c_char; 64];
    // SAFETY: `a` holds 16 bytes, buf is large enough for INET6_ADDRSTRLEN.
    unsafe {
        crate::cffi::inet_ntop(
            libc::AF_INET6,
            a.as_ptr() as *const _,
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        std::ffi::CStr::from_ptr(buf.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

pub fn ntopa46(ip4: Option<&[u8]>, ip6: Option<&[u8]>) -> String {
    if let Some(a) = ip4 {
        ntop4(a)
    } else if let Some(a) = ip6 {
        ntop6(a)
    } else {
        "UNKNOWN_FAMILY".into()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SockAddr {
    #[default]
    None,
    V4([u8; 4], u16),
    V6([u8; 16], u16),
}

impl SockAddr {
    pub fn ntop(&self) -> String {
        match self {
            SockAddr::V4(a, _) => ntop4(a),
            SockAddr::V6(a, _) => ntop6(a),
            SockAddr::None => "UNKNOWN_FAMILY".into(),
        }
    }
    pub fn ntop_port(&self) -> String {
        match self {
            SockAddr::V4(a, p) => format!("{}:{}", ntop4(a), p),
            SockAddr::V6(a, p) => format!("[{}]:{}", ntop6(a), p),
            SockAddr::None => self.ntop(),
        }
    }
    pub fn port(&self) -> u16 {
        match self {
            SockAddr::V4(_, p) | SockAddr::V6(_, p) => *p,
            SockAddr::None => 0,
        }
    }
    pub fn has_addr(&self) -> bool {
        match self {
            SockAddr::V4(a, _) => *a != [0; 4],
            SockAddr::V6(a, _) => *a != [0; 16],
            SockAddr::None => false,
        }
    }
    pub fn is_v4(&self) -> bool {
        matches!(self, SockAddr::V4(..))
    }
    pub fn is_v6(&self) -> bool {
        matches!(self, SockAddr::V6(..))
    }
}

/// "[fd00::1]:8000" => "fd00::1" etc. Returns (stripped host, is_ip).
pub fn strip_host_to_ip(host: &[u8]) -> (Vec<u8>, bool) {
    let mut h = host;
    while let Some(b' ' | b'\t') = h.first() {
        h = &h[1..];
    }
    // C semantics treat the string up to the first NUL
    let nul = h.iter().position(|&c| c == 0).unwrap_or(h.len());
    let h = &h[..nul];
    if h.len() >= 2 {
        if h[0] == b'[' {
            let rest = &h[1..];
            if let Some(p) = rest.iter().position(|&c| c == b']') {
                let s = rest[..p].to_vec();
                let ip = inet_pton6(&s).is_some();
                return (s, ip);
            }
            // no closing bracket: unchanged, not ip (falls through in C)
            return (host.to_vec(), false);
        } else if inet_pton6(h).is_some() {
            return (h.to_vec(), true);
        } else {
            let p = h.iter().position(|&c| c == b':').unwrap_or(h.len());
            let s = h[..p].to_vec();
            let ip = inet_pton4(&s).is_some();
            return (s, ip);
        }
    }
    (host.to_vec(), false)
}

pub fn seq_within(s: u32, s1: u32, s2: u32) -> bool {
    (s2 >= s1 && s >= s1 && s <= s2) || (s2 < s1 && (s <= s2 || s >= s1))
}

#[inline]
pub fn pntoh16(p: &[u8]) -> u16 {
    u16::from_be_bytes([p[0], p[1]])
}
#[inline]
pub fn phton16(p: &mut [u8], v: u16) {
    p[..2].copy_from_slice(&v.to_be_bytes());
}
#[inline]
pub fn pntoh24(p: &[u8]) -> u32 {
    (p[0] as u32) << 16 | (p[1] as u32) << 8 | p[2] as u32
}
#[inline]
pub fn phton24(p: &mut [u8], v: u32) {
    p[0] = (v >> 16) as u8;
    p[1] = (v >> 8) as u8;
    p[2] = v as u8;
}
#[inline]
pub fn pntoh32(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[0], p[1], p[2], p[3]])
}
#[inline]
pub fn phton32(p: &mut [u8], v: u32) {
    p[..4].copy_from_slice(&v.to_be_bytes());
}
#[inline]
pub fn pntoh48(p: &[u8]) -> u64 {
    (p[0] as u64) << 40
        | (p[1] as u64) << 32
        | (p[2] as u64) << 24
        | (p[3] as u64) << 16
        | (p[4] as u64) << 8
        | p[5] as u64
}
#[inline]
pub fn phton48(p: &mut [u8], v: u64) {
    p[..6].copy_from_slice(&v.to_be_bytes()[2..]);
}
#[inline]
pub fn pntoh64(p: &[u8]) -> u64 {
    u64::from_be_bytes(p[..8].try_into().unwrap_or([0; 8]))
}
#[inline]
pub fn phton64(p: &mut [u8], v: u64) {
    p[..8].copy_from_slice(&v.to_be_bytes());
}
pub fn bswap16(u: u16) -> u16 {
    u.swap_bytes()
}
pub fn bswap24(u: u32) -> u32 {
    ((u >> 16) & 0xFF) | (u & 0xFF00) | ((u << 16) & 0xFF0000)
}
pub fn bswap48(u: u64) -> u64 {
    ((u & 0xFF0000000000) >> 40)
        | ((u & 0xFF00000000) >> 24)
        | ((u & 0xFF000000) >> 8)
        | ((u & 0xFF0000) << 8)
        | ((u & 0xFF00) << 24)
        | ((u & 0xFF) << 40)
}

fn parse_hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parses hex into at most `max` bytes. Err(partial) on bad digit (C returns false).
pub fn parse_hex_str(s: &[u8], max: usize) -> Result<Vec<u8>, Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while out.len() < max && i < s.len() && s[i] != 0 {
        let u = parse_hex_digit(s[i]);
        let l = s.get(i + 1).copied().and_then(parse_hex_digit);
        match (u, l) {
            (Some(u), Some(l)) => out.push(u << 4 | l),
            _ => return Err(out),
        }
        i += 2;
    }
    Ok(out)
}

pub fn hex_digit(v: u8) -> u8 {
    if v <= 9 {
        b'0' + v
    } else if v <= 0xF {
        v + b'A' - 0xA
    } else {
        b'?'
    }
}

pub fn localtime_str() -> String {
    // SAFETY: plain libc calls with valid out-pointers.
    unsafe {
        let mut now: libc::time_t = 0;
        libc::time(&mut now);
        let mut t: libc::tm = std::mem::zeroed();
        libc::localtime_r(&now, &mut t);
        format!(
            "{:02}.{:02}.{:04} {:02}:{:02}:{:02}",
            t.tm_mday,
            t.tm_mon + 1,
            t.tm_year + 1900,
            t.tm_hour,
            t.tm_min,
            t.tm_sec
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileModSig {
    pub sec: i64,
    pub nsec: i64,
    pub size: i64,
}

pub fn file_mod_signature(filename: &str) -> Option<FileModSig> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(filename).ok()?;
    Some(FileModSig {
        sec: m.mtime(),
        nsec: m.mtime_nsec(),
        size: m.size() as i64,
    })
}

pub fn file_size(filename: &str) -> Option<u64> {
    std::fs::metadata(filename).ok().map(|m| m.len())
}

pub fn file_open_test(filename: &str, flags: i32) -> bool {
    let Ok(c) = CString::new(filename) else {
        return false;
    };
    // SAFETY: c is a valid C string.
    let fd = unsafe { libc::open(c.as_ptr(), flags) };
    if fd >= 0 {
        // SAFETY: fd was just opened.
        unsafe { libc::close(fd) };
        true
    } else {
        false
    }
}

#[inline]
pub fn random() -> i64 {
    // SAFETY: glibc random() has no preconditions.
    unsafe { crate::cffi::random() as i64 }
}

pub fn srandom(seed: u32) {
    // SAFETY: glibc srandom() has no preconditions.
    unsafe { crate::cffi::srandom(seed) }
}

/// Same consumption pattern of random() as the C version, which depends on pointer parity.
pub fn fill_random_bytes(p: &mut [u8]) {
    let mut sz = p.len();
    if sz == 0 {
        return;
    }
    let mut off = 0;
    if (p.as_ptr() as usize) & 1 != 0 {
        p[0] = random() as u8;
        sz -= 1;
        off = 1;
    }
    let mut k = 0;
    while k + 1 < sz {
        let r = (random() as u16).to_le_bytes();
        p[off + k] = r[0];
        p[off + k + 1] = r[1];
        k += 2;
    }
    if sz & 1 != 0 {
        p[off + sz - 1] = random() as u8;
    }
}

pub fn fill_random_az(p: &mut [u8]) {
    for b in p.iter_mut() {
        *b = b'a' + (random() % 26) as u8;
    }
}

pub fn fill_random_az09(p: &mut [u8]) {
    for b in p.iter_mut() {
        let rnd = (random() % 36) as u8;
        *b = if rnd < 10 {
            rnd + b'0'
        } else {
            b'a' + rnd - 10
        };
    }
}

pub fn fill_crypto_random_bytes(p: &mut [u8]) -> bool {
    let mut off = 0;
    while off < p.len() {
        // SAFETY: writing into the remaining part of p.
        let rd = unsafe {
            libc::getrandom(
                p[off..].as_mut_ptr() as *mut _,
                p.len() - off,
                libc::GRND_NONBLOCK,
            )
        };
        if rd <= 0 {
            break;
        }
        off += rd as usize;
    }
    if off < p.len() {
        for dev in ["/dev/random", "/dev/urandom"] {
            if off >= p.len() {
                break;
            }
            if let Ok(mut f) = File::open(dev) {
                while off < p.len() {
                    match f.read(&mut p[off..]) {
                        Ok(n) if n > 0 => off += n,
                        _ => break,
                    }
                }
            }
        }
    }
    off == p.len()
}

pub fn bxor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}
pub fn bor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x | y).collect()
}
pub fn band(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| x & y).collect()
}

pub fn set_env_exedir(argv0: &str) -> bool {
    let p = std::path::Path::new(argv0);
    let d = match p.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    let d = std::fs::canonicalize(&d).unwrap_or(d);
    std::env::set_var("EXEDIR", d);
    true
}

/// realpath that also works for files that do not exist yet.
pub fn realpath_any(file: &str) -> Option<String> {
    if let Ok(p) = std::fs::canonicalize(file) {
        return Some(p.to_string_lossy().into_owned());
    }
    let path = std::path::Path::new(file);
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => std::path::Path::new("."),
    };
    let pa = std::fs::canonicalize(dir).ok()?;
    let base = basename(file);
    let pa = pa.to_string_lossy();
    Some(if pa.ends_with('/') {
        format!("{pa}{base}")
    } else {
        format!("{pa}/{base}")
    })
}

fn basename(s: &str) -> String {
    let t = s.trim_end_matches('/');
    if t.is_empty() {
        return if s.is_empty() { ".".into() } else { "/".into() };
    }
    t.rsplit('/').next().unwrap_or(t).to_string()
}

/// C atoi semantics: leading whitespace, sign, digits; stops at first non-digit.
pub fn atoi(s: &[u8]) -> i32 {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut v: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add((s[i] - b'0') as i64);
        i += 1;
    }
    (if neg { v.wrapping_neg() } else { v }) as i32
}

pub fn parse_int16(p: &str) -> Option<i16> {
    let b = p.as_bytes();
    match b.first() {
        Some(b'+' | b'-' | b'0'..=b'9') => {
            let i = atoi(b);
            let v = i as i16;
            (v as i32 == i).then_some(v)
        }
        _ => None,
    }
}

fn clock(clk: libc::clockid_t) -> Option<libc::timespec> {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid out-pointer.
    (unsafe { libc::clock_gettime(clk, &mut ts) } == 0).then_some(ts)
}

pub fn boottime() -> i64 {
    clock(libc::CLOCK_BOOTTIME).map_or(0, |t| t.tv_sec as i64)
}

pub fn boottime_ms() -> u64 {
    clock(libc::CLOCK_BOOTTIME).map_or(0, |t| t.tv_sec as u64 * 1000 + t.tv_nsec as u64 / 1_000_000)
}

pub fn boottime_ts() -> libc::timespec {
    clock(libc::CLOCK_BOOTTIME).unwrap_or(libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    })
}

pub fn realtime() -> Option<libc::timespec> {
    clock(libc::CLOCK_REALTIME)
}

pub fn time_now() -> i64 {
    // SAFETY: NULL is allowed.
    unsafe { libc::time(std::ptr::null_mut()) as i64 }
}

/// sscanf "%u" semantics on glibc/LP64: skips whitespace, optional sign, decimal digits.
/// Returns the value truncated to u32 and the rest of the input.
pub fn scan_u(s: &[u8]) -> Option<(u32, &[u8])> {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let start = i;
    let mut v: u64 = 0;
    let mut overflow = false;
    while i < s.len() && s[i].is_ascii_digit() {
        match v
            .checked_mul(10)
            .and_then(|x| x.checked_add((s[i] - b'0') as u64))
        {
            Some(x) => v = x,
            None => overflow = true,
        }
        i += 1;
    }
    if i == start {
        return None;
    }
    if overflow {
        v = u64::MAX;
    } else if neg {
        v = v.wrapping_neg();
    }
    Some((v as u32, &s[i..]))
}

/// sscanf "%d" semantics (strtol, truncated to int).
pub fn scan_d(s: &[u8]) -> Option<(i32, &[u8])> {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let start = i;
    let mut v: i128 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = (v * 10 + (s[i] - b'0') as i128).min(i64::MAX as i128 + 1);
        i += 1;
    }
    if i == start {
        return None;
    }
    let v = if neg { -v } else { v };
    let v = v.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
    Some((v as i32, &s[i..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strip() {
        assert_eq!(
            strip_host_to_ip(b"[fd00::1]:8000"),
            (b"fd00::1".to_vec(), true)
        );
        assert_eq!(
            strip_host_to_ip(b" 127.0.0.1:8000"),
            (b"127.0.0.1".to_vec(), true)
        );
        assert_eq!(
            strip_host_to_ip(b" vk.com:8000"),
            (b"vk.com".to_vec(), false)
        );
    }
    #[test]
    fn seq() {
        assert!(seq_within(5, 0xFFFFFFF0, 10));
        assert!(!seq_within(11, 0xFFFFFFF0, 10));
    }
    #[test]
    fn i16p() {
        assert_eq!(parse_int16("-5"), Some(-5));
        assert_eq!(parse_int16("40000"), None);
        assert_eq!(parse_int16("x"), None);
    }
}
