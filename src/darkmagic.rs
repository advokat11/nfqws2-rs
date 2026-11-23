//! Port of darkmagic.c (Linux parts): header parsing, dissect, printing, raw sockets.
//! Packets are byte slices; headers are addressed by offset instead of struct pointers.

use crate::dlog;
use crate::helpers::{ntop4, ntop6, pntoh16, pntoh32, SockAddr};
use crate::log::{dlog_perror, dlog_perror_errno};
use std::cell::Cell;

pub const IPPROTO_IP: u8 = 0;
pub const IPPROTO_HOPOPTS: u8 = 0;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_IGMP: u8 = 2;
pub const IPPROTO_IPIP: u8 = 4;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_IPV6: u8 = 41;
pub const IPPROTO_ROUTING: u8 = 43;
pub const IPPROTO_FRAGMENT: u8 = 44;
pub const IPPROTO_GRE: u8 = 47;
pub const IPPROTO_ESP: u8 = 50;
pub const IPPROTO_AH: u8 = 51;
pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_NONE: u8 = 59;
pub const IPPROTO_DSTOPTS: u8 = 60;
pub const IPPROTO_SCTP: u8 = 132;
pub const IPPROTO_MH: u8 = 135;
pub const IPPROTO_HIP: u8 = 139;
pub const IPPROTO_SHIM6: u8 = 140;

pub const TH_FIN: u8 = 0x01;
pub const TH_SYN: u8 = 0x02;
pub const TH_RST: u8 = 0x04;
pub const TH_PUSH: u8 = 0x08;
pub const TH_ACK: u8 = 0x10;
pub const TH_URG: u8 = 0x20;

pub const TCP_KIND_END: u8 = 0;
pub const TCP_KIND_NOOP: u8 = 1;
pub const TCP_KIND_MSS: u8 = 2;
pub const TCP_KIND_SCALE: u8 = 3;
pub const TCP_KIND_SACK_PERM: u8 = 4;
pub const TCP_KIND_SACK: u8 = 5;
pub const TCP_KIND_TS: u8 = 8;
pub const TCP_KIND_MD5: u8 = 19;
pub const TCP_KIND_AO: u8 = 29;
pub const TCP_KIND_FASTOPEN: u8 = 34;

pub const SCALE_NONE: u8 = 0xFF;

pub const VERDICT_PASS: u8 = 0;
pub const VERDICT_MODIFY: u8 = 1;
pub const VERDICT_DROP: u8 = 2;
pub const VERDICT_MASK: u8 = 3;
pub const VERDICT_PRESERVE_NEXT: u8 = 4;
pub const VERDICT_MASK_VALID_LUA: u8 = VERDICT_MASK | VERDICT_PRESERVE_NEXT;
pub const VERDICT_NOCSUM: u8 = 8;
pub const VERDICT_MASK_VALID: u8 = 15;

pub const IP_HDR_LEN: usize = 20;
pub const IP6_HDR_LEN: usize = 40;
pub const TCP_HDR_LEN: usize = 20;
pub const UDP_HDR_LEN: usize = 8;
pub const ICMP_HDR_LEN: usize = 8;

pub const RAW_SNDBUF: i32 = 64 * 1024;

pub fn net32_add(v: u32, inc: u32) -> u32 {
    v.wrapping_add(inc)
}

// ---- tcp options (tcp = slice starting at the tcp header) ----
/// Offset of the option inside `tcp`, or None.
pub fn tcp_find_option(tcp: &[u8], kind: u8) -> Option<usize> {
    let end = ((tcp[12] >> 4) as usize) << 2;
    let end = end.min(tcp.len());
    let mut t = TCP_HDR_LEN;
    while t < end {
        match tcp[t] {
            TCP_KIND_END => return None,
            TCP_KIND_NOOP => t += 1,
            k => {
                if t + 1 >= end || tcp[t + 1] < 2 || t + tcp[t + 1] as usize > end {
                    return None;
                }
                if k == kind {
                    return Some(t);
                }
                t += tcp[t + 1] as usize;
            }
        }
    }
    None
}
pub fn tcp_find_scale_factor(tcp: &[u8]) -> u8 {
    match tcp_find_option(tcp, TCP_KIND_SCALE) {
        Some(o) if tcp[o + 1] == 3 => tcp[o + 2],
        _ => SCALE_NONE,
    }
}
pub fn tcp_find_mss(tcp: &[u8]) -> u16 {
    match tcp_find_option(tcp, TCP_KIND_MSS) {
        Some(o) if tcp[o + 1] == 4 => pntoh16(&tcp[o + 2..]),
        _ => 0,
    }
}
pub fn tcp_flags(tcp: &[u8]) -> u8 {
    tcp[13]
}
pub fn tcp_synack_segment(tcp: &[u8]) -> bool {
    tcp[13] & (TH_URG | TH_ACK | TH_PUSH | TH_RST | TH_SYN | TH_FIN) == (TH_ACK | TH_SYN)
}
pub fn tcp_syn_segment(tcp: &[u8]) -> bool {
    tcp[13] & (TH_URG | TH_ACK | TH_PUSH | TH_RST | TH_SYN | TH_FIN) == TH_SYN
}

pub fn proto_name(p: u8) -> Option<&'static str> {
    Some(match p {
        IPPROTO_TCP => "tcp",
        IPPROTO_UDP => "udp",
        IPPROTO_ICMP => "icmp",
        IPPROTO_ICMPV6 => "icmp6",
        IPPROTO_IGMP => "igmp",
        IPPROTO_ESP => "esp",
        IPPROTO_IPV6 => "6in4",
        IPPROTO_IPIP => "4in4",
        IPPROTO_GRE => "gre",
        IPPROTO_SCTP => "sctp",
        _ => return None,
    })
}
pub fn str_proto_name(p: u8) -> String {
    proto_name(p).map_or_else(|| p.to_string(), str::to_string)
}
pub const AF_UNSPEC: u16 = 0;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub fn family_from_proto(l3: u8) -> u16 {
    match l3 {
        IPPROTO_IP => AF_INET,
        IPPROTO_IPV6 => AF_INET6,
        _ => AF_UNSPEC,
    }
}

pub fn icmp_type_name(v6: bool, t: u8) -> Option<&'static str> {
    Some(if v6 {
        match t {
            128 => "echo_req6",
            129 => "echo_reply6",
            1 => "dest_unreach6",
            2 => "packet_too_big",
            3 => "time_exceeded6",
            4 => "param_problem6",
            130 => "mld_listener_query",
            131 => "mld_listener_report",
            132 => "mld_listener_reduction",
            133 => "router_sol",
            134 => "router_adv",
            135 => "neigh_sol",
            136 => "neigh_adv",
            137 => "redirect6",
            _ => return None,
        }
    } else {
        match t {
            0 => "echo_reply",
            3 => "dest_unreach",
            5 => "redirect",
            8 => "echo_req",
            11 => "time_exceeded",
            12 => "param_problem",
            13 => "ts",
            14 => "ts_reply",
            15 => "info_req",
            16 => "info_reply",
            _ => return None,
        }
    })
}
pub fn str_icmp_type_name(v6: bool, t: u8) -> String {
    icmp_type_name(v6, t).map_or_else(|| t.to_string(), str::to_string)
}

/// snprintf truncation to a C buffer of `n` bytes.
pub fn trunc(mut s: String, n: usize) -> String {
    if n == 0 {
        return String::new();
    }
    if s.len() > n - 1 {
        let mut e = n - 1;
        while !s.is_char_boundary(e) {
            e -= 1;
        }
        s.truncate(e);
    }
    s
}

pub fn str_ip(ip: &[u8]) -> String {
    let ss = trunc(
        format!("{} => {}", ntop4(&ip[12..16]), ntop4(&ip[16..20])),
        35,
    );
    trunc(
        format!(
            "{} proto={} ttl={}",
            ss,
            trunc(str_proto_name(ip[9]), 16),
            ip[8]
        ),
        66,
    )
}
pub fn str_srcdst_ip6(s: &[u8], d: &[u8]) -> String {
    format!("{} => {}", ntop6(s), ntop6(d))
}
pub fn str_ip6hdr(ip6: &[u8], proto: u8) -> String {
    let ss = trunc(str_srcdst_ip6(&ip6[8..24], &ip6[24..40]), 100);
    trunc(
        format!(
            "{} proto={} ttl={}",
            ss,
            trunc(str_proto_name(proto), 16),
            ip6[7]
        ),
        132,
    )
}
pub fn str_tcphdr(t: &[u8]) -> String {
    let fl = t[13];
    let mut f = String::new();
    for (b, c) in [
        (TH_SYN, 'S'),
        (TH_ACK, 'A'),
        (TH_RST, 'R'),
        (TH_FIN, 'F'),
        (TH_PUSH, 'P'),
        (TH_URG, 'U'),
    ] {
        if fl & b != 0 {
            f.push(c);
        }
    }
    trunc(
        format!(
            "sport={} dport={} flags={} seq={} ack_seq={}",
            pntoh16(t),
            pntoh16(&t[2..]),
            f,
            pntoh32(&t[4..]),
            pntoh32(&t[8..])
        ),
        80,
    )
}
pub fn str_udphdr(u: &[u8]) -> String {
    trunc(
        format!("sport={} dport={}", pntoh16(u), pntoh16(&u[2..])),
        30,
    )
}
pub fn str_icmphdr(v6: bool, i: &[u8]) -> String {
    trunc(str_icmphdr_full(v6, i), 48)
}
pub fn str_icmphdr_full(v6: bool, i: &[u8]) -> String {
    let st = trunc(str_icmp_type_name(v6, i[0]), 32);
    let t = i[0];
    let s = if t == 8 || t == 0 || t == 128 || t == 129 {
        format!(
            "icmp_type={} icmp_code={} id=0x{:04X} seq={}",
            st,
            i[1],
            pntoh16(&i[4..]),
            pntoh16(&i[6..])
        )
    } else {
        format!(
            "icmp_type={} icmp_code={} data=0x{:08X}",
            st,
            i[1],
            pntoh32(&i[4..])
        )
    };
    s
}

// ---- protocol checks ----
pub fn proto_check_ipv4(d: &[u8]) -> bool {
    if d.len() < IP_HDR_LEN || d[0] >> 4 != 4 {
        return false;
    }
    let iplen = pntoh16(&d[2..]) as usize;
    let off = (((d[0] & 0xF) as usize) << 2) & 0xFF;
    off >= IP_HDR_LEN && iplen >= off && d.len() >= off
}
pub fn proto_check_ipv4_payload(d: &[u8]) -> bool {
    d.len() >= pntoh16(&d[2..]) as usize
}
pub fn proto_check_tcp(d: &[u8]) -> bool {
    if d.len() < TCP_HDR_LEN {
        return false;
    }
    let off = ((d[12] >> 4) as usize) << 2;
    off >= TCP_HDR_LEN && d.len() >= off
}
pub fn proto_check_udp(d: &[u8]) -> bool {
    d.len() >= UDP_HDR_LEN
}
pub fn proto_check_udp_payload(d: &[u8]) -> bool {
    let l = pntoh16(&d[4..]) as usize;
    l >= UDP_HDR_LEN && d.len() >= l
}
pub fn proto_check_icmp(d: &[u8]) -> bool {
    d.len() >= ICMP_HDR_LEN
}
pub fn proto_check_ipv6(d: &[u8]) -> bool {
    d.len() >= IP6_HDR_LEN && d[0] & 0xF0 == 0x60
}
pub fn proto_check_ipv6_payload(d: &[u8]) -> bool {
    d.len() >= pntoh16(&d[4..]) as usize + IP6_HDR_LEN
}

/// ipv4 fragment info: (frag, frag_off)
pub fn ip4_frag(ip: &[u8]) -> (bool, u16) {
    let off = pntoh16(&ip[6..]);
    (off & (0x1FFF | 0x2000) != 0, (off & 0x1FFF) << 3)
}

/// proto_skip_ipv6. `d` starts at the ipv6 header. Returns
/// (offset of transport after ext headers relative to d, remaining len, proto_type, frag, frag_off).
pub fn proto_skip_ipv6(d: &[u8]) -> (usize, usize, u8, bool, u16) {
    let mut fr_off: u16 = 0;
    let mut fr = false;
    let mut frag = false;
    let mut frag_off = 0;
    let mut ht = d[6];
    let mut proto_type = ht;
    let plen = pntoh16(&d[4..]) as usize;
    let mut pos = IP6_HDR_LEN;
    let mut len = d.len() - IP6_HDR_LEN;
    if plen < len {
        len = plen;
    }
    while len > 0 {
        let hdrlen;
        match ht {
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS | IPPROTO_MH | IPPROTO_HIP
            | IPPROTO_SHIM6 => {
                if len < 2 {
                    return (pos, len, proto_type, frag, frag_off);
                }
                hdrlen = 8 + ((d[pos + 1] as usize) << 3);
            }
            IPPROTO_FRAGMENT => {
                hdrlen = 8;
                if len < hdrlen {
                    return (pos, len, proto_type, frag, frag_off);
                }
                let offlg = pntoh16(&d[pos + 2..]);
                fr_off = offlg & 0xFFF8;
                fr = offlg & 0xFFF9 != 0;
                frag_off = fr_off;
                frag = fr;
            }
            IPPROTO_AH => {
                if len < 2 {
                    return (pos, len, proto_type, frag, frag_off);
                }
                hdrlen = 8 + ((d[pos + 1] as usize) << 2);
            }
            IPPROTO_NONE => return (pos, len, proto_type, frag, frag_off),
            _ => {
                proto_type = ht;
                return (pos, len, proto_type, frag, frag_off);
            }
        }
        if len < hdrlen {
            return (pos, len, proto_type, frag, frag_off);
        }
        ht = d[pos];
        len -= hdrlen;
        pos += hdrlen;
        if fr && fr_off != 0 {
            proto_type = ht;
            return (pos, len, proto_type, frag, frag_off);
        }
    }
    (pos, len, proto_type, frag, frag_off)
}

/// proto_find_ip6_exthdr: offset of the ext header of type `proto` inside the packet `d`.
pub fn proto_find_ip6_exthdr(d: &[u8], proto: u8) -> Option<usize> {
    if d.len() < IP6_HDR_LEN {
        return None;
    }
    let plen = pntoh16(&d[4..]) as usize;
    let mut last = d[6];
    let mut pos = IP6_HDR_LEN;
    let mut len = d.len() - IP6_HDR_LEN;
    if plen < len {
        len = plen;
    }
    let (mut fr, mut fr_off) = (false, 0u16);
    while len > 0 && !(fr && fr_off != 0) {
        if last == proto {
            return Some(pos);
        }
        let hdrlen = match last {
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS | IPPROTO_MH | IPPROTO_HIP
            | IPPROTO_SHIM6 => {
                if len < 2 {
                    return None;
                }
                8 + ((d[pos + 1] as usize) << 3)
            }
            IPPROTO_FRAGMENT => {
                if len < 8 {
                    return None;
                }
                let offlg = pntoh16(&d[pos + 2..]);
                fr_off = offlg & 0xFFF8;
                fr = offlg & 0xFFF9 != 0;
                8
            }
            IPPROTO_AH => {
                if len < 2 {
                    return None;
                }
                8 + ((d[pos + 1] as usize) << 2)
            }
            _ => return None,
        };
        if len < hdrlen {
            return None;
        }
        last = d[pos];
        len -= hdrlen;
        pos += hdrlen;
    }
    None
}

/// Parsed view of a packet: offsets into the packet buffer it was built from.
#[derive(Clone, Copy, Debug, Default)]
pub struct Dissect {
    pub len_pkt: usize,
    pub ip: bool,
    pub ip6: bool,
    pub len_l3: usize,
    pub proto: u8,
    pub tcp: Option<usize>,
    pub udp: Option<usize>,
    pub icmp: Option<usize>,
    pub len_l4: usize,
    pub transport_len: usize,
    pub payload: usize,
    pub len_payload: usize,
    pub frag: bool,
    pub frag_off: u16,
}

impl Dissect {
    pub fn l4(&self) -> usize {
        self.len_l3
    }
    pub fn has_l3(&self) -> bool {
        self.ip || self.ip6
    }
}

pub fn proto_dissect_l3l4(data: &[u8], no_payload_check: bool) -> Dissect {
    let mut dis = Dissect {
        len_pkt: data.len(),
        ..Default::default()
    };
    let mut len = data.len();
    let mut pos;
    if proto_check_ipv4(data) && (no_payload_check || proto_check_ipv4_payload(data)) {
        dis.ip = true;
        dis.proto = data[9];
        let iplen = pntoh16(&data[2..]) as usize;
        if iplen < len {
            len = iplen;
            dis.len_pkt = len;
        }
        let off = ((data[0] & 0xF) as usize) << 2;
        let (f, fo) = ip4_frag(data);
        dis.frag = f;
        dis.frag_off = fo;
        pos = off;
        len -= off;
        dis.len_l3 = off;
    } else if proto_check_ipv6(data) && (no_payload_check || proto_check_ipv6_payload(data)) {
        dis.ip6 = true;
        let iplen = pntoh16(&data[4..]) as usize + IP6_HDR_LEN;
        if iplen < len {
            len = iplen;
            dis.len_pkt = len;
        }
        let (p, l, pt, f, fo) = proto_skip_ipv6(&data[..len]);
        pos = p;
        len = l;
        dis.proto = pt;
        dis.frag = f;
        dis.frag_off = fo;
        dis.len_l3 = pos;
    } else {
        return dis;
    }
    dis.transport_len = len;
    dis.len_l4 = 0;
    let d = &data[pos..pos + len];
    if !dis.frag {
        if dis.proto == IPPROTO_TCP && proto_check_tcp(d) {
            dis.tcp = Some(pos);
            let off = ((d[12] >> 4) as usize) << 2;
            pos += off;
            len -= off;
            dis.len_l4 = off;
        } else if dis.proto == IPPROTO_UDP
            && proto_check_udp(d)
            && (no_payload_check || proto_check_udp_payload(d))
        {
            dis.udp = Some(pos);
            pos += UDP_HDR_LEN;
            len -= UDP_HDR_LEN;
            dis.len_l4 = UDP_HDR_LEN;
        } else if (dis.proto == IPPROTO_ICMP || dis.proto == IPPROTO_ICMPV6) && proto_check_icmp(d)
        {
            dis.icmp = Some(pos);
            pos += ICMP_HDR_LEN;
            len -= ICMP_HDR_LEN;
            dis.len_l4 = ICMP_HDR_LEN;
        }
    }
    dis.payload = pos;
    dis.len_payload = len;
    dis
}

pub fn ttl46(pkt: &[u8], dis: &Dissect) -> u8 {
    if dis.ip {
        pkt[8]
    } else if dis.ip6 {
        pkt[7]
    } else {
        0
    }
}

/// extract_endpoints: (src, dst) with ports from tcp/udp if present.
pub fn extract_endpoints(pkt: &[u8], dis: &Dissect) -> (SockAddr, SockAddr) {
    let ports = |o: Option<usize>| o.map(|o| (pntoh16(&pkt[o..]), pntoh16(&pkt[o + 2..])));
    let (sp, dp) = ports(dis.tcp).or(ports(dis.udp)).unwrap_or((0, 0));
    if dis.ip {
        let mut s = [0u8; 4];
        let mut d = [0u8; 4];
        s.copy_from_slice(&pkt[12..16]);
        d.copy_from_slice(&pkt[16..20]);
        (SockAddr::V4(s, sp), SockAddr::V4(d, dp))
    } else if dis.ip6 {
        let mut s = [0u8; 16];
        let mut d = [0u8; 16];
        s.copy_from_slice(&pkt[8..24]);
        d.copy_from_slice(&pkt[24..40]);
        (SockAddr::V6(s, sp), SockAddr::V6(d, dp))
    } else {
        (SockAddr::None, SockAddr::None)
    }
}

pub fn extract_dst(d: &[u8]) -> Option<SockAddr> {
    if proto_check_ipv4(d) {
        let mut a = [0u8; 4];
        a.copy_from_slice(&d[16..20]);
        Some(SockAddr::V4(a, 0))
    } else if proto_check_ipv6(d) {
        let mut a = [0u8; 16];
        a.copy_from_slice(&d[24..40]);
        Some(SockAddr::V6(a, 0))
    } else {
        None
    }
}

fn sockaddr_bytes(sa: &SockAddr) -> (Vec<u8>, libc::socklen_t) {
    match sa {
        SockAddr::V4(a, p) => {
            let s = libc::sockaddr_in {
                sin_family: libc::AF_INET as u16,
                sin_port: p.to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(*a),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: plain-old-data struct reinterpreted as bytes.
            let b = unsafe {
                std::slice::from_raw_parts(
                    &s as *const _ as *const u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                )
            };
            (
                b.to_vec(),
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        }
        SockAddr::V6(a, p) => {
            let s = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: p.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: *a },
                sin6_scope_id: 0,
            };
            // SAFETY: plain-old-data struct reinterpreted as bytes.
            let b = unsafe {
                std::slice::from_raw_parts(
                    &s as *const _ as *const u8,
                    std::mem::size_of::<libc::sockaddr_in6>(),
                )
            };
            (
                b.to_vec(),
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            )
        }
        SockAddr::None => (Vec::new(), 0),
    }
}

fn get_source_ip(target: &SockAddr) -> Option<SockAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
    // Same as the C code: a datagram socket "connected" to target port 0xFFFF tells which
    // local address the kernel routes from. No packet is sent.
    let (any, dst): (IpAddr, IpAddr) = match target {
        SockAddr::V4(a, _) => (Ipv4Addr::UNSPECIFIED.into(), Ipv4Addr::from(*a).into()),
        SockAddr::V6(a, _) => (Ipv6Addr::UNSPECIFIED.into(), Ipv6Addr::from(*a).into()),
        SockAddr::None => return None,
    };
    let s = UdpSocket::bind(SocketAddr::new(any, 0)).ok()?;
    s.connect(SocketAddr::new(dst, 0xFFFF)).ok()?;
    match s.local_addr().ok()?.ip() {
        IpAddr::V4(a) => Some(SockAddr::V4(a.octets(), 0)),
        IpAddr::V6(a) => Some(SockAddr::V6(a.octets(), 0)),
    }
}
pub fn get_source_ip4(t: &[u8; 4]) -> Option<[u8; 4]> {
    match get_source_ip(&SockAddr::V4(*t, 0))? {
        SockAddr::V4(a, _) => Some(a),
        _ => None,
    }
}
pub fn get_source_ip6(t: &[u8; 16]) -> Option<[u8; 16]> {
    match get_source_ip(&SockAddr::V6(*t, 0))? {
        SockAddr::V6(a, _) => Some(a),
        _ => None,
    }
}

// ---- raw sockets ----
thread_local! {
    static SOCK4: Cell<i32> = const { Cell::new(-1) };
    static SOCK6: Cell<i32> = const { Cell::new(-1) };
    static BIND_FIX4: Cell<bool> = const { Cell::new(false) };
    static BIND_FIX6: Cell<bool> = const { Cell::new(false) };
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn setsockopt_int(fd: i32, level: i32, opt: i32, v: i32) -> bool {
    // SAFETY: passing a valid int pointer and size.
    unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &v as *const i32 as *const _,
            std::mem::size_of::<i32>() as u32,
        ) != -1
    }
}

pub fn dbgprint_socket_buffers(fd: i32) {
    if crate::log::debug() {
        for (opt, name) in [
            (libc::SO_RCVBUF, "SO_RCVBUF"),
            (libc::SO_SNDBUF, "SO_SNDBUF"),
        ] {
            let mut v: i32 = 0;
            let mut sz = std::mem::size_of::<i32>() as u32;
            // SAFETY: valid out-pointers.
            if unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    opt,
                    &mut v as *mut i32 as *mut _,
                    &mut sz,
                )
            } == 0
            {
                dlog!("fd={} {}={}\n", fd, name, v);
            }
        }
    }
}

pub fn set_socket_buffers(fd: i32, rcvbuf: i32, sndbuf: i32) -> bool {
    dlog!(
        "set_socket_buffers fd={} rcvbuf={} sndbuf={}\n",
        fd,
        rcvbuf,
        sndbuf
    );
    if rcvbuf != 0 && !setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, rcvbuf) {
        dlog_perror("setsockopt (SO_RCVBUF)");
        return false;
    }
    if sndbuf != 0 && !setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_SNDBUF, sndbuf) {
        dlog_perror("setsockopt (SO_SNDBUF)");
        return false;
    }
    dbgprint_socket_buffers(fd);
    true
}

fn rawsend_socket_raw(domain: i32, proto: i32) -> i32 {
    // SAFETY: socket() with constant args.
    let fd = unsafe { libc::socket(domain, libc::SOCK_RAW, proto) };
    if fd != -1 && !set_socket_buffers(fd, 2048, RAW_SNDBUF / 2) {
        // SAFETY: fd is ours.
        unsafe { libc::close(fd) };
        return -1;
    }
    fd
}

fn family_cell(v6: bool) -> &'static std::thread::LocalKey<Cell<i32>> {
    if v6 {
        &SOCK6
    } else {
        &SOCK4
    }
}

fn rawsend_socket(v6: bool) -> i32 {
    let cell = family_cell(v6);
    let cur = cell.with(|c| c.get());
    if cur != -1 {
        return cur;
    }
    let fam = if v6 { libc::AF_INET6 } else { libc::AF_INET };
    let fd = rawsend_socket_raw(fam, libc::IPPROTO_RAW);
    if fd == -1 {
        dlog_perror("rawsend: socket()");
        return -1;
    }
    cell.with(|c| c.set(fd));
    let fail = |s: &str| {
        dlog_perror(s);
        // SAFETY: fd is ours.
        unsafe { libc::close(fd) };
        cell.with(|c| c.set(-1));
        -1
    };
    if !setsockopt_int(fd, libc::SOL_SOCKET, libc::SO_PRIORITY, 6) {
        return fail("rawsend: setsockopt(SO_PRIORITY)");
    }
    if !v6 && !setsockopt_int(fd, libc::IPPROTO_IP, 22 /* IP_NODEFRAG */, 1) {
        dlog_perror("rawsend: setsockopt(IP_NODEFRAG)");
    }
    if !v6 && !setsockopt_int(fd, libc::IPPROTO_IP, libc::IP_FREEBIND, 1) {
        return fail("rawsend: setsockopt(IP_FREEBIND)");
    }
    if v6 {
        let _ = setsockopt_int(fd, libc::SOL_IPV6, 78 /* IPV6_FREEBIND */, 1);
    }
    fd
}

pub fn rawsend_cleanup() {
    for c in [&SOCK4, &SOCK6] {
        c.with(|c| {
            if c.get() != -1 {
                // SAFETY: fd is ours.
                unsafe { libc::close(c.get()) };
                c.set(-1);
            }
        });
    }
}

pub fn rawsend_preinit(bind_fix4: bool, bind_fix6: bool) -> bool {
    BIND_FIX4.with(|c| c.set(bind_fix4));
    BIND_FIX6.with(|c| c.set(bind_fix6));
    rawsend_socket(false) != -1 && (rawsend_socket(true) != -1 || errno() == libc::EAFNOSUPPORT)
}

pub fn rawsend(dst: &SockAddr, fwmark: u32, ifout: Option<&str>, data: &[u8]) -> bool {
    let v6 = match dst {
        SockAddr::V4(..) => false,
        SockAddr::V6(..) => true,
        SockAddr::None => {
            // C: rawsend_family_sock returns NULL => -1
            return false;
        }
    };
    let sock = rawsend_socket(v6);
    if sock == -1 {
        return false;
    }
    if !setsockopt_int(sock, libc::SOL_SOCKET, libc::SO_MARK, fwmark as i32) {
        dlog_perror("rawsend: setsockopt(SO_MARK)");
        return false;
    }
    let dst2 = match dst {
        SockAddr::V6(a, _) => SockAddr::V6(*a, 0),
        x => *x,
    };
    let (sa, salen) = sockaddr_bytes(&dst2);
    let fix = if v6 {
        BIND_FIX6.with(|c| c.get())
    } else {
        BIND_FIX4.with(|c| c.get())
    };
    if fix {
        let (p, l) = match ifout {
            Some(s) => {
                let mut v = s.as_bytes().to_vec();
                v.push(0);
                (v, s.len() + 1)
            }
            None => (Vec::new(), 0),
        };
        // SAFETY: pointer/len pair describes the buffer (or NULL,0).
        let r = unsafe {
            libc::setsockopt(
                sock,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                if l > 0 {
                    p.as_ptr() as *const _
                } else {
                    std::ptr::null()
                },
                l as u32,
            )
        };
        if r == -1 {
            dlog_perror("rawsend: setsockopt(SO_BINDTODEVICE)");
            return false;
        }
    }
    loop {
        // SAFETY: data and sockaddr buffers are valid for the given lengths.
        let r = unsafe {
            libc::sendto(
                sock,
                data.as_ptr() as *const _,
                data.len(),
                0,
                sa.as_ptr() as *const libc::sockaddr,
                salen,
            )
        };
        if r < 0 {
            let e = errno();
            if e == libc::EINTR {
                continue;
            }
            dlog_perror_errno(&format!("rawsend: sendto ({})", data.len()), e);
            return false;
        }
        return true;
    }
}

pub fn rawsend_rep(
    repeats: i32,
    dst: &SockAddr,
    fwmark: u32,
    ifout: Option<&str>,
    data: &[u8],
) -> bool {
    for _ in 0..repeats {
        if !rawsend(dst, fwmark, ifout, data) {
            return false;
        }
    }
    true
}

/// ensure_file_access: chown to the drop-root uid.
pub fn ensure_file_access(filename: &str, uid: u32) -> bool {
    let Ok(c) = std::ffi::CString::new(filename) else {
        return false;
    };
    // SAFETY: valid C string; gid -1 means unchanged.
    unsafe { libc::chown(c.as_ptr(), uid, u32::MAX) == 0 }
}

pub fn make_writable_dir(writable_dir: &str, uid: u32) -> bool {
    let wrdir = if !writable_dir.is_empty() {
        writable_dir.to_string()
    } else {
        let env = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        format!("{env}/zapret2")
    };
    let Ok(c) = std::ffi::CString::new(wrdir.clone()) else {
        return false;
    };
    // SAFETY: valid C string.
    if unsafe { libc::mkdir(c.as_ptr(), 0o755) } != 0 && errno() != libc::EEXIST {
        return false;
    }
    let mut b = ensure_file_access(&wrdir, uid);
    if !b {
        let mut tmpl = format!("{wrdir}/test_XXXXXX").into_bytes();
        tmpl.push(0);
        // SAFETY: tmpl is a writable NUL-terminated template.
        let fd = unsafe { libc::mkstemp(tmpl.as_mut_ptr() as *mut libc::c_char) };
        if fd >= 0 {
            // SAFETY: fd/template are ours.
            unsafe {
                libc::close(fd);
                libc::unlink(tmpl.as_ptr() as *const libc::c_char);
            }
            b = true;
        }
    }
    if b {
        std::env::set_var("WRITABLE", &wrdir);
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dissect_tcp() {
        let mut p = vec![0u8; 44];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&44u16.to_be_bytes());
        p[9] = 6;
        p[20 + 12] = 5 << 4;
        let d = proto_dissect_l3l4(&p, false);
        assert!(d.ip);
        assert_eq!(d.tcp, Some(20));
        assert_eq!(d.payload, 40);
        assert_eq!(d.len_payload, 4);
    }
}
