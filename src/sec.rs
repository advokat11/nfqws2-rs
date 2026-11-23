//! Port of sec.c (Linux): capabilities, privilege drop, seccomp hardening, daemonize.

use crate::log::{dlog_perror, dlog_perror_errno};
use crate::{dlog_condup, dlog_err};

const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;
const CAP_SETPCAP: u32 = 8;
const CAP_NET_ADMIN: u32 = 12;
const CAP_NET_RAW: u32 = 13;
const CAP_LAST_CAP: i32 = 40;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
const SECBIT_NO_SETUID_FIXUP: i32 = 1 << 2;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn capget(cd: &mut [CapData; 2]) -> bool {
    // SAFETY: getpid has no preconditions.
    let mut h = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: unsafe { libc::getpid() },
    };
    // SAFETY: header and 2-element data array match the kernel ABI for version 3.
    unsafe { libc::syscall(libc::SYS_capget, &mut h as *mut CapHeader, cd.as_mut_ptr()) == 0 }
}

fn capset(cd: &[CapData; 2]) -> bool {
    // SAFETY: getpid has no preconditions.
    let mut h = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: unsafe { libc::getpid() },
    };
    // SAFETY: header and 2-element data array match the kernel ABI for version 3.
    unsafe { libc::syscall(libc::SYS_capset, &mut h as *mut CapHeader, cd.as_ptr()) == 0 }
}

pub fn checkpcap(caps: u64) -> bool {
    if caps == 0 {
        return true;
    }
    let mut cd = [CapData::default(); 2];
    let (c0, c1) = (caps as u32, (caps >> 32) as u32);
    capget(&mut cd) && cd[0].effective & c0 == c0 && cd[1].effective & c1 == c1
}

pub fn setpcap(caps: u64) -> bool {
    let cd = [
        CapData {
            effective: caps as u32,
            permitted: caps as u32,
            inheritable: 0,
        },
        CapData {
            effective: (caps >> 32) as u32,
            permitted: (caps >> 32) as u32,
            inheritable: 0,
        },
    ];
    capset(&cd)
}

pub fn getmaxcap() -> i32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| crate::helpers::scan_d(s.as_bytes()).map(|(v, _)| v))
        .unwrap_or(CAP_LAST_CAP)
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

pub fn dropcaps() -> bool {
    let caps = (1u64 << CAP_NET_ADMIN) | (1u64 << CAP_NET_RAW);
    let maxcap = getmaxcap();
    if setpcap(caps | (1u64 << CAP_SETPCAP)) {
        for cap in 0..=maxcap {
            // SAFETY: prctl with integer args.
            if unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong) } < 0 {
                let e = errno();
                dlog_err!("could not drop bound cap {}\n", cap);
                dlog_perror_errno("cap_drop_bound", e);
            }
        }
    }
    if !setpcap(caps) {
        dlog_perror("setpcap");
        return checkpcap(caps);
    }
    true
}

fn is_setgroups_denied() -> bool {
    match std::fs::read("/proc/self/setgroups") {
        Ok(b) => b.starts_with(b"deny"),
        Err(_) => false,
    }
}

pub fn can_drop_root() -> bool {
    checkpcap((1u64 << CAP_SETUID) | (1u64 << CAP_SETGID)) && !is_setgroups_denied()
}

pub fn droproot(uid: u32, user: Option<&str>, gid: &[u32]) -> bool {
    if gid.is_empty() {
        dlog_err!("droproot: no groups specified");
        return false;
    }
    // SAFETY: prctl with integer args.
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1 as libc::c_ulong) } != 0 {
        let e = errno();
        // SAFETY: prctl with integer args.
        let bits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS) };
        if bits < 0 || bits & SECBIT_NO_SETUID_FIXUP == 0 {
            dlog_perror_errno("prctl(PR_SET_KEEPCAPS)", e);
            return false;
        }
    }
    if let Some(u) = user {
        let Ok(cu) = std::ffi::CString::new(u) else {
            return false;
        };
        // SAFETY: valid C string.
        if unsafe { libc::initgroups(cu.as_ptr(), gid[0]) } != 0 {
            dlog_perror("initgroups");
            return false;
        }
    } else {
        // SAFETY: gid slice pointer/len are valid.
        if unsafe { libc::setgroups(gid.len(), gid.as_ptr()) } != 0 {
            dlog_perror("setgroups");
            return false;
        }
    }
    // SAFETY: plain syscalls.
    if unsafe { libc::setgid(gid[0]) } != 0 {
        dlog_perror("setgid");
        return false;
    }
    // SAFETY: plain syscall.
    if unsafe { libc::setuid(uid) } != 0 {
        dlog_perror("setuid");
        return false;
    }
    true
}

pub fn print_id() {
    // SAFETY: getuid/getgid cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    dlog_condup!("Running as UID={} GID=", uid);
    let mut g = [0u32; 128];
    // SAFETY: g has room for 128 entries.
    let n = unsafe { libc::getgroups(128, g.as_mut_ptr()) };
    if n > 0 {
        let n = n as usize;
        for (i, gid) in g.iter().take(n).enumerate() {
            if i == n - 1 {
                dlog_condup!("{}", gid);
            } else {
                dlog_condup!("{},", gid);
            }
        }
        dlog_condup!("\n");
    } else {
        dlog_condup!("{}\n", gid);
    }
}

// ---- seccomp ----
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGT: u16 = 0x20;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;
const SECCOMP_RET_KILL: u32 = 0;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

// ARCH_NR, X32_SYSCALL_BIT and BLOCKED_SYSCALLS for the target, generated by build.rs
// from the target's C headers with sec.c's #ifdef list.
include!(concat!(env!("OUT_DIR"), "/seccomp.rs"));

fn set_seccomp() -> bool {
    let b = BLOCKED_SYSCALLS;
    let n = b.len();
    let f = |code: u16, jt: u8, jf: u8, k: u32| SockFilter { code, jt, jf, k };
    let mut p = Vec::with_capacity(n + 6);
    p.push(f(BPF_LD + BPF_W + BPF_ABS, 0, 0, 4)); // arch_nr
    if let Some(x32) = X32_SYSCALL_BIT {
        p.push(f(BPF_JMP + BPF_JEQ + BPF_K, 0, (3 + n) as u8, ARCH_NR));
        p.push(f(BPF_LD + BPF_W + BPF_ABS, 0, 0, 0)); // syscall_nr
        p.push(f(BPF_JMP + BPF_JGT + BPF_K, (1 + n) as u8, 0, x32 - 1));
    } else {
        p.push(f(BPF_JMP + BPF_JEQ + BPF_K, 0, (2 + n) as u8, ARCH_NR));
        p.push(f(BPF_LD + BPF_W + BPF_ABS, 0, 0, 0)); // syscall_nr
    }
    for (i, s) in b.iter().enumerate() {
        p.push(f(BPF_JMP + BPF_JEQ + BPF_K, (n - i) as u8, 0, *s));
    }
    p.push(f(BPF_RET + BPF_K, 0, 0, SECCOMP_RET_ALLOW));
    p.push(f(BPF_RET + BPF_K, 0, 0, SECCOMP_RET_KILL));
    let prog = SockFprog {
        len: p.len() as u16,
        filter: p.as_ptr(),
    };
    // SAFETY: prog points to a valid filter array that outlives the call.
    unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER as libc::c_ulong,
            &prog as *const SockFprog as libc::c_ulong,
        ) >= 0
    }
}

pub fn sec_harden() -> bool {
    let mut ok = true;
    // SAFETY: prctl with integer args.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) } != 0 {
        dlog_perror("PR_SET_NO_NEW_PRIVS(prctl)");
        ok = false;
    }
    if ARCH_NR != 0 && !set_seccomp() {
        let e = errno();
        dlog_perror_errno("seccomp", e);
        if e == libc::EINVAL {
            dlog_err!("seccomp: this can be safely ignored if kernel does not support seccomp\n");
        }
        ok = false;
    }
    ok
}

pub fn daemonize() {
    let cwd = std::env::current_dir().ok();
    if cwd.is_none() {
        dlog_perror("getcwd");
    }
    crate::cffi::fflush_all();
    // SAFETY: fork in a single-threaded process.
    let pid = unsafe { libc::fork() };
    if pid == -1 {
        dlog_perror("fork");
        std::process::exit(20);
    } else if pid != 0 {
        std::process::exit(0);
    }
    if let Some(c) = cwd {
        if std::env::set_current_dir(c).is_err() {
            dlog_perror("chdir");
        }
    }
    // SAFETY: setsid has no preconditions.
    if unsafe { libc::setsid() } == -1 {
        dlog_perror("setsid");
        std::process::exit(21);
    }
    for (fd, name) in [
        (0, "close(stdin)"),
        (1, "close(stdout)"),
        (2, "close(stderr)"),
    ] {
        // SAFETY: detaching from the standard descriptors; nothing else owns them.
        if unsafe { libc::close(fd) } < 0 && errno() != libc::EBADF {
            dlog_perror(name);
            std::process::exit(22);
        }
    }
    // SAFETY: NUL-terminated path; becomes fd 0.
    if unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) } < 0 {
        dlog_perror("open(stdin)");
        std::process::exit(23);
    }
    // SAFETY: duplicating fd 0 onto the lowest free descriptors (1, 2).
    if unsafe { libc::dup(0) } < 0 {
        dlog_perror("dup(stdout)");
        std::process::exit(24);
    }
    // SAFETY: as above.
    if unsafe { libc::dup(0) } < 0 {
        dlog_perror("dup(stderr)");
        std::process::exit(25);
    }
}
