fn main() {
    // Same system libraries as the C original (ADR-007/009).
    println!("cargo:rustc-link-lib=netfilter_queue");
    println!("cargo:rustc-link-lib=nfnetlink");
    // libnetfilter_queue uses libmnl; a static link needs it named (the C Makefile has -lmnl)
    println!("cargo:rustc-link-lib=mnl");
    let now = std::process::Command::new("date")
        .arg("+%b %e %Y %H:%M:%S")
        .output()
        .ok();
    let s = now
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    // __DATE__ pads the day with a space: "Nov  9 2026"
    let mut parts = s.splitn(2, ' ');
    let mon = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("").trim_start();
    let (day, tail) = rest.split_once(' ').unwrap_or(("", ""));
    let date_time = format!("{mon} {day:>2} {tail}");
    println!("cargo:rustc-env=NFQWS2_BUILD_DATE_TIME={date_time}");
    // The target's luajit.h (pkg-config honors cross settings), like the C build's -I.
    let ljinc =
        std::process::Command::new(std::env::var("PKG_CONFIG").unwrap_or("pkg-config".into()))
            .args(["--variable=includedir", "luajit"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "/usr/include/luajit-2.1".into());
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_LIBDIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    let ljv = std::fs::read_to_string(format!("{ljinc}/luajit.h"))
        .ok()
        .and_then(|h| {
            h.lines()
                .find(|l| {
                    l.starts_with("#define LUAJIT_VERSION\t")
                        || l.starts_with("#define LUAJIT_VERSION ")
                })
                .and_then(|l| l.split('"').nth(1).map(str::to_string))
        })
        .unwrap_or_default();
    // lua.c appends LJSUBVER: " OpenResty" when luajit.h defines OPENRESTY_LUAJIT
    let openresty = std::fs::read_to_string(format!("{ljinc}/luajit.h"))
        .map(|h| {
            h.lines()
                .any(|l| l.trim_start().starts_with("#define OPENRESTY_LUAJIT"))
        })
        .unwrap_or(false);
    let ljv = if openresty {
        format!("{ljv} OpenResty")
    } else {
        ljv
    };
    println!("cargo:rustc-env=NFQWS2_LUAJIT_VERSION={ljv}");
    seccomp_tables();
    socket_consts();
    println!("cargo:rerun-if-changed=build.rs");
}

/// sec.c's blocked syscall list, with its #ifdefs, verbatim (including the
/// `SYS_oldmount`/`SYS_oldumount` mismatch, which leaves oldumount out everywhere).
const BLOCKED_SYSCALLS_C: &str = "
#ifdef SYS_execv
SYS_execv,
#endif
SYS_execve,
#ifdef SYS_execveat
SYS_execveat,
#endif
#ifdef SYS_exec_with_loader
SYS_exec_with_loader,
#endif
#ifdef SYS_osf_execve
SYS_osf_execve,
#endif
#ifdef SYS_unshare
SYS_unshare,
#endif
#ifdef SYS_setns
SYS_setns,
#endif
#ifdef SYS_bpf
SYS_bpf,
#endif
#ifdef SYS_io_uring_setup
SYS_io_uring_setup,
#endif
#ifdef SYS_io_uring_enter
SYS_io_uring_enter,
#endif
#ifdef SYS_io_uring_register
SYS_io_uring_register,
#endif
#ifdef SYS_userfaultfd
SYS_userfaultfd,
#endif
#ifdef SYS_memfd_create
SYS_memfd_create,
#endif
SYS_mount,SYS_umount2,
#ifdef SYS_oldmount
SYS_oldumount,
#endif
#ifdef SYS_mount_setattr
SYS_mount_setattr,
#endif
#ifdef SYS_move_mount
SYS_move_mount,
#endif
#ifdef SYS_fsmount
SYS_fsmount,
#endif
#ifdef SYS_fsopen
SYS_fsopen,
#endif
#ifdef SYS_fsconfig
SYS_fsconfig,
#endif
#ifdef SYS_fsmount
SYS_fsmount,
#endif
#ifdef SYS_fspick
SYS_fspick,
#endif
SYS_chroot,SYS_pivot_root,
SYS_fchmod,SYS_fchmodat,
#ifdef SYS_chmod
SYS_chmod,
#endif
#ifdef SYS_chown
SYS_chown,
#endif
#ifdef SYS_chown32
SYS_chown32,
#endif
SYS_fchown,
#ifdef SYS_fchown32
SYS_fchown32,
#endif
#ifdef SYS_lchown
SYS_lchown,
#endif
#ifdef SYS_lchown32
SYS_lchown32,
#endif
SYS_fchownat,
#ifdef SYS_symlink
SYS_symlink,
#endif
SYS_symlinkat,
#ifdef SYS_link
SYS_link,
#endif
SYS_linkat,
#ifdef SYS_mknod
SYS_mknod,
#endif
SYS_mknodat,
#ifdef SYS_mkdir
SYS_mkdir,
#endif
SYS_mkdirat,
#ifdef SYS_rmdir
SYS_rmdir,
#endif
#ifdef SYS_readdir
SYS_readdir,
#endif
#ifdef SYS_getdents
SYS_getdents,
#endif
#ifdef SYS_getdents64
SYS_getdents64,
#endif
#ifdef SYS_process_vm_readv
SYS_process_vm_readv,
#endif
#ifdef SYS_process_vm_writev
SYS_process_vm_writev,
#endif
#ifdef SYS_process_madvise
SYS_process_madvise,
#endif
#ifdef SYS_tkill
SYS_tkill,
#endif
#ifdef SYS_tgkill
SYS_tgkill,
#endif
SYS_kill, SYS_ptrace
";

/// sec.h's ARCH_NR selection, except that an unknown platform gets 0 (no filter)
/// instead of #error.
const ARCH_NR_C: &str = r#"
#ifndef __AUDIT_ARCH_64BIT
#define __AUDIT_ARCH_64BIT 0x80000000
#endif
#ifndef __AUDIT_ARCH_LE
#define __AUDIT_ARCH_LE    0x40000000
#endif
#ifndef EM_RISCV
#define EM_RISCV 243
#endif
#ifndef AUDIT_ARCH_RISCV64
#define AUDIT_ARCH_RISCV64 (EM_RISCV | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#endif
#ifndef EM_LOONGARCH
#define EM_LOONGARCH 258
#endif
#ifndef AUDIT_ARCH_LOONGARCH64
#define AUDIT_ARCH_LOONGARCH64 (EM_LOONGARCH | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE)
#endif
#if defined(__aarch64__)
# define ARCH_NR AUDIT_ARCH_AARCH64
#elif defined(__amd64__)
# define ARCH_NR AUDIT_ARCH_X86_64
#elif defined(__arm__) && (defined(__ARM_EABI__) || defined(__thumb__))
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define ARCH_NR AUDIT_ARCH_ARM
# else
#  define ARCH_NR AUDIT_ARCH_ARMEB
# endif
#elif defined(__i386__)
# define ARCH_NR AUDIT_ARCH_I386
#elif defined(__mips__)
# if _MIPS_SIM == _MIPS_SIM_ABI32
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define ARCH_NR AUDIT_ARCH_MIPSEL
#  else
#   define ARCH_NR AUDIT_ARCH_MIPS
#  endif
# elif _MIPS_SIM == _MIPS_SIM_ABI64
#  if __BYTE_ORDER == __LITTLE_ENDIAN
#   define ARCH_NR AUDIT_ARCH_MIPSEL64
#  else
#   define ARCH_NR AUDIT_ARCH_MIPS64
#  endif
# else
#  define ARCH_NR 0
# endif
#elif defined(__PPC64__)
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define ARCH_NR AUDIT_ARCH_PPC64LE
# else
#  define ARCH_NR AUDIT_ARCH_PPC64
# endif
#elif defined(__PPC__)
# define ARCH_NR AUDIT_ARCH_PPC
#elif __riscv && __riscv_xlen == 64
# define ARCH_NR AUDIT_ARCH_RISCV64
#elif defined(__loongarch__) && __loongarch_grlen == 64
# define ARCH_NR AUDIT_ARCH_LOONGARCH64
#elif defined(__e2k__)
# define ARCH_NR AUDIT_ARCH_E2K
#else
# define ARCH_NR 0
#endif
"#;

/// Generate the seccomp constants of sec.c for the target from the target's own C headers
/// (run through the target C compiler's preprocessor), so syscall numbers and ARCH_NR are
/// exactly what the C original gets on that platform.
fn seccomp_tables() {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let mut c = String::from(
        "#define _GNU_SOURCE\n#include <endian.h>\n#include <elf.h>\n#include <sys/syscall.h>\n\
         #include <linux/audit.h>\n#include <linux/unistd.h>\n",
    );
    c += ARCH_NR_C;
    c += "NFQ_ARCH ARCH_NR NFQ_END\n#ifdef __X32_SYSCALL_BIT\nNFQ_X32 __X32_SYSCALL_BIT NFQ_END\n#endif\n";
    for line in BLOCKED_SYSCALLS_C.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            c += t;
        } else {
            for s in t.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                c += &format!("NFQ_SYS {s} NFQ_END\n");
            }
            continue;
        }
        c += "\n";
    }
    let probe = out.join("seccomp_probe.c");
    std::fs::write(&probe, c).expect("write probe");
    let pp = cc::Build::new()
        .file(&probe)
        .cargo_metadata(false)
        .cargo_warnings(false)
        .expand();
    // Expansions from system headers come split over several lines with line markers:
    // drop the markers, join everything and cut at the NFQ_END sentinels.
    let pp: String = String::from_utf8_lossy(&pp)
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ");
    let (mut arch, mut x32, mut sys) = (0u64, None, Vec::new());
    for item in pp.split("NFQ_END") {
        let Some(at) = item.find("NFQ_") else {
            continue;
        };
        let l = item[at..].trim();
        let (tag, expr) = l.split_once(char::is_whitespace).unwrap_or((l, ""));
        let val = || eval(expr).unwrap_or_else(|| panic!("seccomp probe: cannot evaluate '{l}'"));
        match tag {
            "NFQ_ARCH" => arch = val(),
            "NFQ_X32" => x32 = Some(val()),
            "NFQ_SYS" => sys.push(val()),
            _ => {}
        }
    }
    if arch == 0 {
        println!("cargo:warning=no seccomp ARCH_NR for this target: syscall filter disabled");
    }
    let x32 = x32.map_or("None".to_string(), |v| format!("Some({v:#x})"));
    let list: Vec<String> = sys.iter().map(|v| v.to_string()).collect();
    let rs = format!(
        "/// sec.h ARCH_NR (0: no filter on this platform).\npub const ARCH_NR: u32 = {arch:#x};\n\
         /// __X32_SYSCALL_BIT when the platform defines it.\npub const X32_SYSCALL_BIT: Option<u32> = {x32};\n\
         /// sec.c blocked_syscalls.\npub const BLOCKED_SYSCALLS: &[u32] = &[{}];\n",
        list.join(", ")
    );
    std::fs::write(out.join("seccomp.rs"), rs).expect("write seccomp.rs");
}

/// Socket option numbers from the target's <sys/socket.h>. They differ on MIPS, and the libc
/// crate gets them wrong for mips64 (it applies the MIPS values to 32-bit MIPS only).
fn socket_consts() {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let names = [
        "SOL_SOCKET",
        "SO_RCVBUF",
        "SO_SNDBUF",
        "SO_PRIORITY",
        "SO_MARK",
        "SO_BINDTODEVICE",
    ];
    let mut c = String::from("#include <sys/socket.h>\n");
    for n in names {
        c += &format!("NFQ_{n} {n} NFQ_END\n");
    }
    let probe = out.join("socket_probe.c");
    std::fs::write(&probe, c).expect("write probe");
    let pp = cc::Build::new()
        .file(&probe)
        .cargo_metadata(false)
        .cargo_warnings(false)
        .expand();
    let pp: String = String::from_utf8_lossy(&pp)
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join(" ");
    let mut rs = String::new();
    for n in names {
        let tag = format!("NFQ_{n} ");
        let v = pp
            .split("NFQ_END")
            .find_map(|i| i.find(&tag).map(|p| i[p + tag.len()..].trim().to_string()))
            .and_then(|e| eval(&e))
            .unwrap_or_else(|| panic!("socket probe: cannot evaluate {n}"));
        rs += &format!("pub const {n}: std::os::raw::c_int = {v};\n");
    }
    std::fs::write(out.join("socket_consts.rs"), rs).expect("write socket_consts.rs");
}

/// Evaluate the integer constant expressions the kernel headers use in syscall and audit
/// macros: literals (with U/L suffixes), parentheses, unary - ~, and * + - << >> & ^ |.
fn eval(s: &str) -> Option<u64> {
    let toks = tokenize(s)?;
    let mut p = 0;
    let v = expr(&toks, &mut p, 0)?;
    (p == toks.len()).then_some(v as u64 & 0xffff_ffff)
}
#[derive(Clone, PartialEq, Debug)]
enum Tok {
    Num(i128),
    Op(&'static str),
}
fn tokenize(s: &str) -> Option<Vec<Tok>> {
    let b = s.as_bytes();
    let mut v = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() {
            let st = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            let t = s[st..i].trim_end_matches(['u', 'U', 'l', 'L']);
            let n = if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                i128::from_str_radix(h, 16).ok()?
            } else if t.len() > 1 && t.starts_with('0') {
                i128::from_str_radix(&t[1..], 8).ok()?
            } else {
                t.parse().ok()?
            };
            v.push(Tok::Num(n));
        } else {
            let two = s.get(i..i + 2).unwrap_or("");
            let op = ["<<", ">>"].into_iter().find(|o| *o == two);
            if let Some(o) = op {
                v.push(Tok::Op(o));
                i += 2;
            } else {
                let o = ["(", ")", "+", "-", "*", "&", "^", "|", "~"]
                    .into_iter()
                    .find(|o| o.as_bytes()[0] == c)?;
                v.push(Tok::Op(o));
                i += 1;
            }
        }
    }
    Some(v)
}
fn prec(o: &str) -> Option<u8> {
    Some(match o {
        "|" => 1,
        "^" => 2,
        "&" => 3,
        "<<" | ">>" => 4,
        "+" | "-" => 5,
        "*" => 6,
        _ => return None,
    })
}
fn atom(t: &[Tok], p: &mut usize) -> Option<i128> {
    match t.get(*p)? {
        Tok::Num(n) => {
            *p += 1;
            Some(*n)
        }
        Tok::Op("(") => {
            *p += 1;
            let v = expr(t, p, 0)?;
            (t.get(*p)? == &Tok::Op(")")).then(|| *p += 1)?;
            Some(v)
        }
        Tok::Op("-") => {
            *p += 1;
            Some(-atom(t, p)?)
        }
        Tok::Op("~") => {
            *p += 1;
            Some(!atom(t, p)?)
        }
        _ => None,
    }
}
fn expr(t: &[Tok], p: &mut usize, min: u8) -> Option<i128> {
    let mut l = atom(t, p)?;
    while let Some(Tok::Op(o)) = t.get(*p) {
        let Some(pr) = prec(o) else { break };
        if pr < min {
            break;
        }
        *p += 1;
        let r = expr(t, p, pr + 1)?;
        l = match *o {
            "|" => l | r,
            "^" => l ^ r,
            "&" => l & r,
            "<<" => l << r,
            ">>" => l >> r,
            "+" => l + r,
            "-" => l - r,
            _ => l * r,
        };
    }
    Some(l)
}
