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

mod lua;
mod nfqws;
mod wlan;

fn main() {
    let r = nfqws::main();
    cffi::fflush_all();
    std::process::exit(r);
}
