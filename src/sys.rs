//! Safe wrappers over the few libc calls the Lua API exposes (uname, getifaddrs, ioctl,
//! gmtime/localtime, timegm/mktime). Each wrapper owns its unsafe call.

use crate::helpers::SockAddr;
use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub fn gettid() -> i64 {
    // SAFETY: gettid takes no arguments and cannot fail.
    unsafe { libc::syscall(libc::SYS_gettid) as i64 }
}

fn cbytes(a: &[libc::c_char]) -> Vec<u8> {
    a.iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect()
}

/// sysname, nodename, release, version, machine.
pub fn uname() -> Option<[Vec<u8>; 5]> {
    // SAFETY: utsname is plain data; uname fills it.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: valid out pointer.
    if unsafe { libc::uname(&mut u) } != 0 {
        return None;
    }
    Some([
        cbytes(&u.sysname),
        cbytes(&u.nodename),
        cbytes(&u.release),
        cbytes(&u.version),
        cbytes(&u.machine),
    ])
}

pub struct IfAddr {
    pub name: String,
    pub cname: std::ffi::CString,
    pub flags: u32,
    pub family: i32,
    pub addr: SockAddr,
    pub netmask: SockAddr,
    pub ifu: SockAddr,
}

/// # Safety
/// `sa` is NULL or points to a sockaddr of its sa_family's size.
unsafe fn sockaddr_of(sa: *const libc::sockaddr) -> SockAddr {
    if sa.is_null() {
        return SockAddr::None;
    }
    match (*sa).sa_family as i32 {
        libc::AF_INET => {
            let s = &*(sa as *const libc::sockaddr_in);
            SockAddr::V4(s.sin_addr.s_addr.to_ne_bytes(), 0)
        }
        libc::AF_INET6 => {
            let s = &*(sa as *const libc::sockaddr_in6);
            SockAddr::V6(s.sin6_addr.s6_addr, 0)
        }
        _ => SockAddr::None,
    }
}

/// getifaddrs() as owned entries, in kernel order.
pub fn getifaddrs() -> Option<Vec<IfAddr>> {
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: valid out pointer.
    if unsafe { libc::getifaddrs(&mut addrs) } < 0 {
        return None;
    }
    let mut v = Vec::new();
    let mut a = addrs;
    while !a.is_null() {
        // SAFETY: a is a node of the list getifaddrs returned, freed only below; every
        // pointer in it is NULL or valid per getifaddrs(3).
        unsafe {
            let ai = &*a;
            let family = if ai.ifa_addr.is_null() {
                0
            } else {
                (*ai.ifa_addr).sa_family as i32
            };
            let cname = if ai.ifa_name.is_null() {
                Default::default()
            } else {
                CStr::from_ptr(ai.ifa_name).to_owned()
            };
            v.push(IfAddr {
                name: cname.to_string_lossy().into_owned(),
                cname,
                flags: ai.ifa_flags,
                family,
                addr: sockaddr_of(ai.ifa_addr),
                netmask: sockaddr_of(ai.ifa_netmask),
                ifu: sockaddr_of(ai.ifa_ifu),
            });
            a = ai.ifa_next;
        }
    }
    // SAFETY: the list from getifaddrs, freed once.
    unsafe { libc::freeifaddrs(addrs) };
    Some(v)
}

pub fn if_nametoindex(name: &CStr) -> u32 {
    // SAFETY: NUL-terminated name.
    unsafe { libc::if_nametoindex(name.as_ptr()) }
}

/// An AF_INET datagram socket for interface ioctls.
pub fn dgram_socket() -> Option<OwnedFd> {
    // SAFETY: plain socket(2); the fd is owned by the returned value.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    // SAFETY: fd is a fresh descriptor we own.
    (fd >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fd) })
}

/// SIOCGIFMTU.
pub fn if_mtu(sock: &OwnedFd, name: &str) -> Option<i32> {
    // SAFETY: ifreq is plain data.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.bytes().take(libc::IFNAMSIZ - 1).enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    // SAFETY: valid socket and ifreq; SIOCGIFMTU writes ifru_mtu.
    unsafe {
        (libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFMTU, &mut ifr) == 0)
            .then_some(ifr.ifr_ifru.ifru_mtu)
    }
}

/// Broken-down time.
#[derive(Default, Clone)]
pub struct Tm {
    pub sec: i32,
    pub min: i32,
    pub hour: i32,
    pub mday: i32,
    pub mon: i32,
    /// years since 1900
    pub year: i32,
    pub wday: i32,
    pub yday: i32,
    pub isdst: i32,
    pub zone: Option<Vec<u8>>,
}

/// gmtime_r / localtime_r.
pub fn breakdown(t: i64, gm: bool) -> Option<Tm> {
    let t0 = t as libc::time_t;
    // SAFETY: tm is plain data.
    let mut t: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: valid in/out pointers.
    let r = unsafe {
        if gm {
            libc::gmtime_r(&t0, &mut t)
        } else {
            libc::localtime_r(&t0, &mut t)
        }
    };
    if r.is_null() {
        return None;
    }
    let zone = (!t.tm_zone.is_null())
        // SAFETY: tm_zone points to a static NUL-terminated zone name.
        .then(|| unsafe { CStr::from_ptr(t.tm_zone) }.to_bytes().to_vec());
    Some(Tm {
        sec: t.tm_sec,
        min: t.tm_min,
        hour: t.tm_hour,
        mday: t.tm_mday,
        mon: t.tm_mon,
        year: t.tm_year,
        wday: t.tm_wday,
        yday: t.tm_yday,
        isdst: t.tm_isdst,
        zone,
    })
}

/// timegm / mktime. -1 on error, like libc.
pub fn compose(tm: &Tm, gm: bool) -> i64 {
    // SAFETY: tm is plain data.
    let mut t: libc::tm = unsafe { std::mem::zeroed() };
    t.tm_sec = tm.sec;
    t.tm_min = tm.min;
    t.tm_hour = tm.hour;
    t.tm_mday = tm.mday;
    t.tm_mon = tm.mon;
    t.tm_year = tm.year;
    t.tm_isdst = tm.isdst;
    // SAFETY: valid tm pointer.
    unsafe {
        if gm {
            libc::timegm(&mut t) as i64
        } else {
            libc::mktime(&mut t) as i64
        }
    }
}
