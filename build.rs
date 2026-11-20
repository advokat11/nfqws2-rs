fn main() {
    // Same system libraries as the C original (ADR-007/009).
    println!("cargo:rustc-link-lib=netfilter_queue");
    println!("cargo:rustc-link-lib=nfnetlink");
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
    let ljv = std::fs::read_to_string("/usr/include/luajit-2.1/luajit.h")
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
    println!("cargo:rustc-env=NFQWS2_LUAJIT_VERSION={ljv}");
    println!("cargo:rerun-if-changed=build.rs");
}
