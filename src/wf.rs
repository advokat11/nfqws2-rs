//! WinDivert filter construction from the --wf-* options (nfqws.c wf_make_*), and the
//! uthash Jenkins hash used for the duplicate-instance check. Pure string logic, built on
//! every target so it can be tested anywhere; only winws2 (Cygwin) uses it.
//!
//! The C code builds the filter with snprintf/strncat into fixed buffers; `CBuf` reproduces
//! that truncation (a buffer of `cap` bytes holds at most `cap - 1` characters).

use crate::filter::{FLTMODE_ANY, FLTMODE_FILTER, icf_parse, ipp_parse, pf_parse};

/// params.h
pub const WINDIVERT_MAX: usize = 16384;
pub const WINDIVERT_PORTFILTER_MAX: usize = 4096;

/// A NUL-terminated C char buffer of fixed capacity.
pub struct CBuf {
    pub data: Vec<u8>,
    cap: usize,
}

impl CBuf {
    pub fn new(cap: usize) -> Self {
        CBuf {
            data: Vec::new(),
            cap,
        }
    }
    /// snprintf(buf + strlen(buf), cap - strlen(buf), "%s", s) and strncat(buf, s, cap - strlen(buf) - 1)
    pub fn push(&mut self, s: &[u8]) {
        let room = self.cap.saturating_sub(1).saturating_sub(self.data.len());
        let s = cstr(s);
        self.data.extend_from_slice(&s[..s.len().min(room)]);
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// The C string view of a buffer (up to the first NUL).
pub fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// snprintf(s1, size, ...) into a local buffer of `size` bytes.
fn trunc(s: String, size: usize) -> Vec<u8> {
    let mut b = s.into_bytes();
    b.truncate(size - 1);
    b
}

/// wf_make_pf: port filter list -> "((tcp.DstPort == 443) or ...)"
pub fn make_pf(opt: &str, l4: &str, portname: &str, len: usize) -> Option<Vec<u8>> {
    if len < 3 {
        return None;
    }
    let mut buf = CBuf::new(len);
    buf.push(b"(");
    for (n, item) in opt.split(',').enumerate() {
        let pf = pf_parse(item)?;
        let s1 = if pf.from == pf.to {
            format!(
                "({}.{} {} {})",
                l4,
                portname,
                if pf.neg { "!=" } else { "==" },
                pf.from
            )
        } else {
            format!(
                "({}.{} {} {} {} {}.{} {} {})",
                l4,
                portname,
                if pf.neg { "<" } else { ">=" },
                pf.from,
                if pf.neg { "or" } else { "and" },
                l4,
                portname,
                if pf.neg { ">" } else { "<=" },
                pf.to
            )
        };
        if n != 0 {
            buf.push(b" or ");
        }
        buf.push(&trunc(s1, 64));
    }
    buf.push(b")");
    Some(buf.data)
}

/// wf_make_icf: ICMP filter list
pub fn make_icf(opt: &str, len: usize) -> Option<Vec<u8>> {
    if len < 3 {
        return None;
    }
    let mut buf = CBuf::new(len);
    buf.push(b"(");
    for item in opt.split(',') {
        let icf = icf_parse(item)?;
        let s1 = match icf.mode {
            FLTMODE_FILTER if icf.code_valid => format!(
                "icmp.Type=={} and icmp.Code=={} or icmpv6.Type=={} and icmpv6.Code=={}",
                icf.typ, icf.code, icf.typ, icf.code
            ),
            FLTMODE_FILTER => format!("icmp.Type=={} or icmpv6.Type=={}", icf.typ, icf.typ),
            FLTMODE_ANY => "icmp or icmpv6".to_string(),
            _ => continue,
        };
        if buf.data.len() > 1 {
            buf.push(b" or ");
        }
        buf.push(&trunc(s1, 80));
    }
    if buf.data.len() <= 1 {
        return None; // nothing added
    }
    buf.push(b")");
    Some(buf.data)
}

/// wf_make_ipf: IP protocol filter list
pub fn make_ipf(opt: &str, len: usize) -> Option<Vec<u8>> {
    if len < 3 {
        return None;
    }
    let mut buf = CBuf::new(len);
    buf.push(b"(");
    for item in opt.split(',') {
        let ipf = ipp_parse(item)?;
        let s1 = match ipf.mode {
            // windivert can't walk ipv6 extension headers: the first ext header type matches
            FLTMODE_FILTER => format!("ip.Protocol=={} or ipv6.NextHdr=={}", ipf.proto, ipf.proto),
            FLTMODE_ANY => "ip or ipv6".to_string(),
            _ => continue,
        };
        if buf.data.len() > 1 {
            buf.push(b" or ");
        }
        buf.push(&trunc(s1, 40));
    }
    if buf.data.len() <= 1 {
        return None;
    }
    buf.push(b")");
    Some(buf.data)
}

const NO_LOCALNETS_V4_DST: &str = "(\
(ip.DstAddr < 10.0.0.0 or ip.DstAddr > 10.255.255.255) and \
(ip.DstAddr < 192.168.0.0 or ip.DstAddr > 192.168.255.255) and \
(ip.DstAddr < 172.16.0.0 or ip.DstAddr > 172.31.255.255) and \
(ip.DstAddr < 169.254.0.0 or ip.DstAddr > 169.254.255.255))";
const NO_LOCALNETS_V4_SRC: &str = "(\
(ip.SrcAddr < 10.0.0.0 or ip.SrcAddr > 10.255.255.255) and \
(ip.SrcAddr < 192.168.0.0 or ip.SrcAddr > 192.168.255.255) and \
(ip.SrcAddr < 172.16.0.0 or ip.SrcAddr > 172.31.255.255) and \
(ip.SrcAddr < 169.254.0.0 or ip.SrcAddr > 169.254.255.255))";
const NO_LOCALNETS_V6_DST: &str = "(\
(ipv6.DstAddr < 2001::0 or ipv6.DstAddr >= 2001:1::0) and \
(ipv6.DstAddr < fc00::0 or ipv6.DstAddr >= fe00::0) and \
(ipv6.DstAddr < fe80::0 or ipv6.DstAddr >= fec0::0) and \
(ipv6.DstAddr < ff00::0 or ipv6.DstAddr >= ffff::0))";
const NO_LOCALNETS_V6_SRC: &str = "(\
(ipv6.SrcAddr < 2001::0 or ipv6.SrcAddr >= 2001:1::0) and \
(ipv6.SrcAddr < fc00::0 or ipv6.SrcAddr >= fe00::0) and \
(ipv6.SrcAddr < fe80::0 or ipv6.SrcAddr >= fec0::0) and \
(ipv6.SrcAddr < ff00::0 or ipv6.SrcAddr >= ffff::0))";
const TCP_NOT_EMPTY: &str = "(!tcp or tcp.Syn or tcp.Rst or tcp.Fin or tcp.PayloadLength>0)";
const TCP_ALWAYS: &str = "(tcp.Syn or tcp.Rst or tcp.Fin)";
/// HTTP/1.? 30(2|7)
const HTTP_REDIRECT: &str = "tcp.PayloadLength>=12 and tcp.Payload32[0]==0x48545450 and tcp.Payload16[2]==0x2F31 and tcp.Payload[6]==0x2E and tcp.Payload16[4]==0x2033 and tcp.Payload[10]==0x30 and (tcp.Payload[11]==0x32 or tcp.Payload[11]==0x37)";

/// The per-direction partial filters wf_make_filter combines (already swapped for server
/// mode by the caller, as in the C code).
pub struct WfParts<'a> {
    pub tcp_src_out: &'a [u8],
    pub tcp_dst_out: &'a [u8],
    pub tcp_src_in: &'a [u8],
    pub tcp_dst_in: &'a [u8],
    pub udp_src_in: &'a [u8],
    pub udp_dst_out: &'a [u8],
    pub icf_out: &'a [u8],
    pub icf_in: &'a [u8],
    pub ipf_out: &'a [u8],
    pub ipf_in: &'a [u8],
    pub raw_filter: &'a [u8],
    pub raw_part: &'a [Vec<u8>],
}

/// wf_make_filter
#[allow(clippy::too_many_arguments)]
pub fn make_filter(
    len: usize,
    if_idx: u32,
    sub_if_idx: u32,
    ipv4: bool,
    ipv6: bool,
    tcp_empty: bool,
    p: &WfParts,
    filter_out_lan: bool,
    filter_out_loopback: bool,
) -> Vec<u8> {
    let mut wf = CBuf::new(len);
    let have_tcp = !cstr(p.tcp_src_in).is_empty() || !cstr(p.tcp_dst_out).is_empty();
    let s = |b: &[u8]| String::from_utf8_lossy(cstr(b)).into_owned();
    wf.push(b"!impostor");
    if filter_out_loopback {
        wf.push(b"\nand !loopback");
    }
    if if_idx != 0 {
        wf.push(format!("\nand ifIdx={if_idx} and subIfIdx={sub_if_idx}").as_bytes());
    }
    if ipv4 ^ ipv6 {
        wf.push(format!("\nand {}", if ipv4 { "ip" } else { "ipv6" }).as_bytes());
    }
    if have_tcp && !tcp_empty {
        wf.push(format!("\nand {TCP_NOT_EMPTY}").as_bytes());
    }
    if !cstr(p.raw_filter).is_empty() {
        wf.push(b"\nand\n(\n");
        wf.push(cstr(p.raw_filter));
        wf.push(b"\n)");
    }
    wf.push(b"\nand\n(\n false");
    if have_tcp {
        // may be required by orchestrators - always redirect
        wf.push(format!(" or\n {HTTP_REDIRECT}").as_bytes());
    }
    for part in p.raw_part {
        wf.push(b" or\n (\n");
        wf.push(cstr(part));
        wf.push(b"\n )");
    }
    if !cstr(p.tcp_dst_out).is_empty() {
        wf.push(format!(" or\n outbound and {}", s(p.tcp_dst_out)).as_bytes());
        // always redirect opposite syn,fin,rst for conntrack
        wf.push(format!(" or\n inbound and {TCP_ALWAYS} and {}", s(p.tcp_src_out)).as_bytes());
    }
    if !cstr(p.tcp_src_in).is_empty() {
        wf.push(format!(" or\n inbound and {}", s(p.tcp_src_in)).as_bytes());
        wf.push(format!(" or\n outbound and {TCP_ALWAYS} and {}", s(p.tcp_dst_in)).as_bytes());
    }
    for (b, dir) in [
        (p.udp_dst_out, "outbound"),
        (p.udp_src_in, "inbound"),
        (p.icf_in, "inbound"),
        (p.icf_out, "outbound"),
        (p.ipf_in, "inbound"),
        (p.ipf_out, "outbound"),
    ] {
        if !cstr(b).is_empty() {
            wf.push(format!(" or\n {dir} and {}", s(b)).as_bytes());
        }
    }
    wf.push(b"\n)");
    if filter_out_lan {
        let (dst, src) = match (ipv4, ipv6) {
            (true, true) => (
                format!("({NO_LOCALNETS_V4_DST} or {NO_LOCALNETS_V6_DST})"),
                format!("({NO_LOCALNETS_V4_SRC} or {NO_LOCALNETS_V6_SRC})"),
            ),
            (true, false) => (NO_LOCALNETS_V4_DST.into(), NO_LOCALNETS_V4_SRC.into()),
            _ => (NO_LOCALNETS_V6_DST.into(), NO_LOCALNETS_V6_SRC.into()),
        };
        wf.push(format!("\nand\n(\n outbound and {dst}\n or\n inbound and {src}\n)\n").as_bytes());
    }
    wf.data
}

/// uthash HASH_JEN (Bob Jenkins' lookup2), as hash_jen() in nfqws.c.
pub fn hash_jen(key: &[u8]) -> u32 {
    fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
        *a = a.wrapping_sub(*b).wrapping_sub(*c) ^ (*c >> 13);
        *b = b.wrapping_sub(*c).wrapping_sub(*a) ^ (*a << 8);
        *c = c.wrapping_sub(*a).wrapping_sub(*b) ^ (*b >> 13);
        *a = a.wrapping_sub(*b).wrapping_sub(*c) ^ (*c >> 12);
        *b = b.wrapping_sub(*c).wrapping_sub(*a) ^ (*a << 16);
        *c = c.wrapping_sub(*a).wrapping_sub(*b) ^ (*b >> 5);
        *a = a.wrapping_sub(*b).wrapping_sub(*c) ^ (*c >> 3);
        *b = b.wrapping_sub(*c).wrapping_sub(*a) ^ (*a << 10);
        *c = c.wrapping_sub(*a).wrapping_sub(*b) ^ (*b >> 15);
    }
    let w = |k: &[u8]| u32::from_le_bytes([k[0], k[1], k[2], k[3]]);
    let (mut i, mut j, mut h) = (0x9e3779b9u32, 0x9e3779b9u32, 0xfeedbeefu32);
    let mut k = key;
    while k.len() >= 12 {
        i = i.wrapping_add(w(&k[0..4]));
        j = j.wrapping_add(w(&k[4..8]));
        h = h.wrapping_add(w(&k[8..12]));
        mix(&mut i, &mut j, &mut h);
        k = &k[12..];
    }
    h = h.wrapping_add(key.len() as u32);
    let b = |n: usize| k[n] as u32;
    let r = k.len();
    if r >= 11 {
        h = h.wrapping_add(b(10) << 24);
    }
    if r >= 10 {
        h = h.wrapping_add(b(9) << 16);
    }
    if r >= 9 {
        h = h.wrapping_add(b(8) << 8);
    }
    if r >= 8 {
        j = j.wrapping_add(b(7) << 24);
    }
    if r >= 7 {
        j = j.wrapping_add(b(6) << 16);
    }
    if r >= 6 {
        j = j.wrapping_add(b(5) << 8);
    }
    if r >= 5 {
        j = j.wrapping_add(b(4));
    }
    if r >= 4 {
        i = i.wrapping_add(b(3) << 24);
    }
    if r >= 3 {
        i = i.wrapping_add(b(2) << 16);
    }
    if r >= 2 {
        i = i.wrapping_add(b(1) << 8);
    }
    if r >= 1 {
        i = i.wrapping_add(b(0));
    }
    mix(&mut i, &mut j, &mut h);
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Differential check against the C functions: WF_CASES is a file of
    /// `<kind> <arg>` lines (see rust lab wfcheck), results go to WF_OUT.
    #[test]
    #[ignore]
    fn dump_cases() {
        let (Ok(cases), Ok(out)) = (std::env::var("WF_CASES"), std::env::var("WF_OUT")) else {
            return;
        };
        let esc = |b: &[u8]| {
            let mut s = Vec::new();
            for &c in b {
                if c == b'\n' {
                    s.extend_from_slice(b"\\n");
                } else {
                    s.push(c);
                }
            }
            String::from_utf8_lossy(&s).into_owned()
        };
        let mut res = String::new();
        for line in std::fs::read_to_string(cases).unwrap().lines() {
            let (kind, arg) = line.split_once(' ').unwrap_or((line, ""));
            let arg = arg.replace("\\n", "\n");
            let r: Option<Vec<u8>> = match kind {
                "pf" => make_pf(&arg, "tcp", "DstPort", WINDIVERT_PORTFILTER_MAX),
                "icf" => make_icf(&arg, WINDIVERT_PORTFILTER_MAX),
                "ipf" => make_ipf(&arg, WINDIVERT_PORTFILTER_MAX),
                "hash" => Some(hash_jen(arg.as_bytes()).to_string().into_bytes()),
                "filter" => {
                    let mut f: Vec<&str> = arg.splitn(11, '|').collect();
                    f.resize(11, "");
                    let fl: u32 = f[0].parse().unwrap();
                    let pf = |o: &str, l4: &str, port: &str| {
                        if o.is_empty() {
                            Vec::new()
                        } else {
                            make_pf(o, l4, port, WINDIVERT_PORTFILTER_MAX).unwrap_or_default()
                        }
                    };
                    let icf = |o: &str| {
                        if o.is_empty() {
                            Vec::new()
                        } else {
                            make_icf(o, WINDIVERT_PORTFILTER_MAX).unwrap_or_default()
                        }
                    };
                    let ipf = |o: &str| {
                        if o.is_empty() {
                            Vec::new()
                        } else {
                            make_ipf(o, WINDIVERT_PORTFILTER_MAX).unwrap_or_default()
                        }
                    };
                    let parts: Vec<Vec<u8>> = if f[10].is_empty() {
                        Vec::new()
                    } else {
                        f[10].split(';').map(|s| s.as_bytes().to_vec()).collect()
                    };
                    let (a, b, c, d) = (
                        pf(f[1], "tcp", "SrcPort"),
                        pf(f[1], "tcp", "DstPort"),
                        pf(f[2], "tcp", "SrcPort"),
                        pf(f[2], "tcp", "DstPort"),
                    );
                    let (uo, ui) = (pf(f[3], "udp", "DstPort"), pf(f[4], "udp", "SrcPort"));
                    let (io, ii, po, pi) = (icf(f[5]), icf(f[6]), ipf(f[7]), ipf(f[8]));
                    let parts_ref = WfParts {
                        tcp_src_out: &a,
                        tcp_dst_out: &b,
                        tcp_src_in: &c,
                        tcp_dst_in: &d,
                        udp_src_in: &ui,
                        udp_dst_out: &uo,
                        icf_out: &io,
                        icf_in: &ii,
                        ipf_out: &po,
                        ipf_in: &pi,
                        raw_filter: f[9].as_bytes(),
                        raw_part: &parts,
                    };
                    Some(make_filter(
                        WINDIVERT_MAX,
                        (fl >> 8) & 0xff,
                        (fl >> 16) & 0xff,
                        fl & 1 != 0,
                        fl & 2 != 0,
                        fl & 4 != 0,
                        &parts_ref,
                        fl & 8 != 0,
                        fl & 16 != 0,
                    ))
                }
                _ => None,
            };
            match r {
                Some(b) => res += &format!("{}\n", esc(&b)),
                None => res += "FAIL\n",
            }
        }
        std::fs::write(out, res).unwrap();
    }
}
