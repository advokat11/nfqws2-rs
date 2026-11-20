//! nfqws2: Rust port of zapret2 nfq2 (Linux NFQUEUE target).
#![allow(dead_code)]

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
mod timer;

mod lua;
mod nfqws;
mod wlan;

fn main() {
    let r = nfqws::main();
    cffi::fflush_all();
    std::process::exit(r);
}
