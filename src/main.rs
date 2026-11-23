//! nfqws2: Rust port of zapret2 nfq2 (Linux NFQUEUE target).
#![allow(dead_code)]
// time_t, c_long and friends are i32 on 32-bit targets (mipsel, arm): the `as i64` casts
// that look redundant on 64-bit hosts are required there.
#![allow(clippy::unnecessary_cast)]

mod cffi;
mod checksum;
mod conntrack;
mod crypto;
mod darkmagic;
mod desync;
mod filter;
mod gzip;
mod helpers;
mod hostlist;
mod log;
mod params;
mod pools;
mod protocol;
mod sec;
mod sys;
mod timer;
mod wf;

mod lua;
mod nfqws;
#[cfg(target_os = "cygwin")]
mod win;
#[cfg(target_os = "linux")]
mod wlan;
/// No per-interface SSIDs outside Linux (HAS_FILTER_SSID is Linux-only in the C code).
#[cfg(not(target_os = "linux"))]
mod wlan {
    pub fn ssid_search_ifname(_ifname: &str) -> Option<String> {
        None
    }
}

fn main() {
    let r = nfqws::main();
    cffi::fflush_all();
    std::process::exit(r);
}
