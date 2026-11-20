//! Port of protocol.c: L7 protocol and payload detection, position markers, TLS mods, QUIC.

use crate::crypto;
use crate::helpers::{
    fill_random_az, fill_random_az09, fill_random_bytes, parse_int16, phton16, phton24, phton64,
    pntoh16, pntoh24, pntoh32, pntoh64, random, strncasestr,
};
use crate::{dlog, dlog_err};

// ---- L7 protocols ----
pub const L7_ALL: u32 = 0;
pub const L7_UNKNOWN: u32 = 1;
pub const L7_KNOWN: u32 = 2;
pub const L7_HTTP: u32 = 3;
pub const L7_TLS: u32 = 4;
pub const L7_DTLS: u32 = 5;
pub const L7_QUIC: u32 = 6;
pub const L7_WIREGUARD: u32 = 7;
pub const L7_DHT: u32 = 8;
pub const L7_DISCORD: u32 = 9;
pub const L7_STUN: u32 = 10;
pub const L7_XMPP: u32 = 11;
pub const L7_DNS: u32 = 12;
pub const L7_MTPROTO: u32 = 13;
pub const L7_BT: u32 = 14;
pub const L7_UTP_BT: u32 = 15;
pub const L7_LAST: u32 = 16;
pub const L7_INVALID: u32 = L7_LAST;
pub const L7_NONE: u32 = L7_LAST;

const L7PROTO_NAME: [&str; 16] = [
    "all",
    "unknown",
    "known",
    "http",
    "tls",
    "dtls",
    "quic",
    "wireguard",
    "dht",
    "discord",
    "stun",
    "xmpp",
    "dns",
    "mtproto",
    "bt",
    "utp_bt",
];

pub fn l7proto_str(l7: u32) -> Option<&'static str> {
    L7PROTO_NAME.get(l7 as usize).copied()
}
pub fn l7proto_from_name(name: &str) -> u32 {
    L7PROTO_NAME
        .iter()
        .position(|n| *n == name)
        .map_or(L7_INVALID, |i| i as u32)
}
pub fn l7_proto_match(l7proto: u32, filter_l7: u64) -> bool {
    filter_l7 == L7_ALL as u64
        || (l7proto < 64 && filter_l7 & (1u64 << l7proto) != 0)
        || (filter_l7 & (1u64 << L7_KNOWN) != 0 && l7proto > L7_KNOWN && l7proto < L7_LAST)
}

// ---- L7 payloads ----
pub const L7P_ALL: u32 = 0;
pub const L7P_UNKNOWN: u32 = 1;
pub const L7P_EMPTY: u32 = 2;
pub const L7P_KNOWN: u32 = 3;
pub const L7P_IPV4: u32 = 4;
pub const L7P_IPV6: u32 = 5;
pub const L7P_ICMP: u32 = 6;
pub const L7P_HTTP_REQ: u32 = 7;
pub const L7P_HTTP_REPLY: u32 = 8;
pub const L7P_TLS_CLIENT_HELLO: u32 = 9;
pub const L7P_TLS_SERVER_HELLO: u32 = 10;
pub const L7P_DTLS_CLIENT_HELLO: u32 = 11;
pub const L7P_DTLS_SERVER_HELLO: u32 = 12;
pub const L7P_QUIC_INITIAL: u32 = 13;
pub const L7P_WIREGUARD_INITIATION: u32 = 14;
pub const L7P_WIREGUARD_RESPONSE: u32 = 15;
pub const L7P_WIREGUARD_COOKIE: u32 = 16;
pub const L7P_WIREGUARD_KEEPALIVE: u32 = 17;
pub const L7P_WIREGUARD_DATA: u32 = 18;
pub const L7P_DHT: u32 = 19;
pub const L7P_DISCORD_IP_DISCOVERY: u32 = 20;
pub const L7P_STUN: u32 = 21;
pub const L7P_XMPP_STREAM: u32 = 22;
pub const L7P_XMPP_STARTTLS: u32 = 23;
pub const L7P_XMPP_PROCEED: u32 = 24;
pub const L7P_XMPP_FEATURES: u32 = 25;
pub const L7P_DNS_QUERY: u32 = 26;
pub const L7P_DNS_RESPONSE: u32 = 27;
pub const L7P_MTPROTO_INITIAL: u32 = 28;
pub const L7P_BT_HANDSHAKE: u32 = 29;
pub const L7P_UTP_BT_HANDSHAKE: u32 = 30;
pub const L7P_LAST: u32 = 31;
pub const L7P_INVALID: u32 = L7P_LAST;
pub const L7P_NONE: u32 = L7P_LAST;

const L7PAYLOAD_NAME: [&str; 31] = [
    "all",
    "unknown",
    "empty",
    "known",
    "ipv4",
    "ipv6",
    "icmp",
    "http_req",
    "http_reply",
    "tls_client_hello",
    "tls_server_hello",
    "dtls_client_hello",
    "dtls_server_hello",
    "quic_initial",
    "wireguard_initiation",
    "wireguard_response",
    "wireguard_cookie",
    "wireguard_keepalive",
    "wireguard_data",
    "dht",
    "discord_ip_discovery",
    "stun",
    "xmpp_stream",
    "xmpp_starttls",
    "xmpp_proceed",
    "xmpp_features",
    "dns_query",
    "dns_response",
    "mtproto_initial",
    "bt_handshake",
    "utp_bt_handshake",
];

pub fn l7payload_from_name(name: &str) -> u32 {
    L7PAYLOAD_NAME
        .iter()
        .position(|n| *n == name)
        .map_or(L7P_INVALID, |i| i as u32)
}
pub fn l7payload_str(l7: u32) -> Option<&'static str> {
    L7PAYLOAD_NAME.get(l7 as usize).copied()
}
pub fn l7_payload_match(l7payload: u32, filter: u64) -> bool {
    filter == L7P_ALL as u64
        || (l7payload < 64 && filter & (1u64 << l7payload) != 0)
        || (filter & (1u64 << L7P_KNOWN) != 0 && l7payload > L7P_KNOWN && l7payload < L7P_LAST)
}
/// l7_payload_str_list with a buffer of `size` bytes. None when it does not fit.
pub fn l7_payload_str_list(l7p: u64, size: usize) -> Option<String> {
    if size == 0 {
        return None;
    }
    if l7p == L7P_ALL as u64 {
        return (size >= 4).then(|| "all".to_string());
    }
    let mut s = String::new();
    for pl in 0..L7P_LAST {
        if l7p & (1u64 << pl) != 0 {
            let p = L7PAYLOAD_NAME[pl as usize];
            let need = s.len() + (!s.is_empty()) as usize + p.len() + 1;
            if need > size {
                return None;
            }
            if !s.is_empty() {
                s.push(',');
            }
            s += p;
        }
    }
    Some(s)
}

// ---- position markers ----
pub const PM_ABS: u8 = 0;
pub const PM_HOST: u8 = 1;
pub const PM_HOST_END: u8 = 2;
pub const PM_HOST_SLD: u8 = 3;
pub const PM_HOST_MIDSLD: u8 = 4;
pub const PM_HOST_ENDSLD: u8 = 5;
pub const PM_HTTP_METHOD: u8 = 6;
pub const PM_EXT_LEN: u8 = 7;
pub const PM_SNI_EXT: u8 = 8;
pub const PM_LAST: u8 = 9;
pub const PM_INVALID: u8 = PM_LAST;

const POSMARKER_NAMES: [&str; 9] = [
    "abs", "host", "endhost", "sld", "midsld", "endsld", "method", "extlen", "sniext",
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProtoPos {
    pub pos: i16,
    pub marker: u8,
}

pub fn posmarker_name(m: u8) -> Option<&'static str> {
    POSMARKER_NAMES.get(m as usize).copied()
}
pub fn posmarker_from_name(name: &[u8]) -> u8 {
    POSMARKER_NAMES
        .iter()
        .position(|n| n.as_bytes() == name)
        .map_or(PM_INVALID, |i| i as u8)
}
pub fn posmarker_parse(s: &str) -> Option<ProtoPos> {
    if let Some(v) = parse_int16(s) {
        return Some(ProtoPos {
            pos: v,
            marker: PM_ABS,
        });
    }
    let b = s.as_bytes();
    let p = b
        .iter()
        .position(|&c| c == b'+' || c == b'-')
        .unwrap_or(b.len());
    if p >= 32 {
        return None;
    }
    let marker = posmarker_from_name(&b[..p]);
    if marker == PM_INVALID {
        return None;
    }
    if p < b.len() {
        Some(ProtoPos {
            pos: parse_int16(&s[p..])?,
            marker,
        })
    } else {
        Some(ProtoPos { pos: 0, marker })
    }
}
/// Parses at most `max` comma separated markers.
pub fn posmarker_list_parse(s: &str, max: usize) -> Option<Vec<ProtoPos>> {
    if s.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    let mut rest = s;
    for _ in 0..max {
        let (item, next) = match rest.find(',') {
            Some(e) => {
                if e >= 32 {
                    return None;
                }
                (&rest[..e], Some(&rest[e + 1..]))
            }
            None => (rest, None),
        };
        out.push(posmarker_parse(item)?);
        match next {
            None => return Some(out),
            Some(n) => rest = n,
        }
    }
    None
}

pub const POS_NOT_FOUND: isize = -1;

fn check_pos(sz: usize, offset: isize) -> isize {
    if offset >= 0 && (offset as usize) < sz {
        offset
    } else {
        POS_NOT_FOUND
    }
}

/// Find N level domain inside dom. Returns (offset in dom, len).
fn find_nld(dom: &[u8], level: i32) -> Option<(usize, usize)> {
    if level < 1 {
        return None;
    }
    let mut p2 = dom.len() as isize;
    for _ in 1..level {
        p2 -= 1;
        while p2 > 0 && dom[p2 as usize] != b'.' {
            p2 -= 1;
        }
        if p2 <= 0 {
            return None;
        }
    }
    let mut p1 = p2 - 1;
    while p1 > 0 && dom[p1 as usize] != b'.' {
        p1 -= 1;
    }
    if p1 < 0 {
        return None;
    }
    if dom[p1 as usize] == b'.' {
        p1 += 1;
    }
    Some((p1 as usize, (p2 - p1) as usize))
}

pub fn any_proto_pos(marker: u8, pos: i16, sz: usize) -> isize {
    match marker {
        PM_ABS => {
            let off = if pos < 0 {
                sz as isize + pos as isize
            } else {
                pos as isize
            };
            check_pos(sz, off)
        }
        _ => POS_NOT_FOUND,
    }
}

fn host_pos(marker: u8, pos: i16, data: &[u8], offset_host: usize, len_host: usize) -> isize {
    let sz = data.len();
    let pos = pos as isize;
    let off = match marker {
        PM_HOST => offset_host as isize + pos,
        PM_HOST_END => (offset_host + len_host) as isize + pos,
        PM_HOST_SLD | PM_HOST_MIDSLD | PM_HOST_ENDSLD => {
            if offset_host + len_host > sz {
                return POS_NOT_FOUND;
            }
            let Some((p, slen)) = find_nld(&data[offset_host..offset_host + len_host], 2) else {
                return POS_NOT_FOUND;
            };
            let p = (offset_host + p) as isize;
            let slen = slen as isize;
            (match marker {
                PM_HOST_SLD => p,
                PM_HOST_ENDSLD => p + slen,
                _ => {
                    if slen == 1 {
                        p + 1
                    } else {
                        p + slen / 2
                    }
                }
            }) + pos
        }
        _ => return POS_NOT_FOUND,
    };
    check_pos(sz, off)
}

pub fn resolve_pos(data: &[u8], l7payload: u32, sp: &ProtoPos) -> isize {
    match l7payload {
        L7P_HTTP_REQ => http_pos(sp.marker, sp.pos, data),
        L7P_TLS_CLIENT_HELLO => tls_pos(sp.marker, sp.pos, data),
        _ => any_proto_pos(sp.marker, sp.pos, data.len()),
    }
}

pub fn resolve_multi_pos(data: &[u8], l7payload: u32, markers: &[ProtoPos]) -> Vec<isize> {
    let mut v: Vec<isize> = markers
        .iter()
        .map(|m| resolve_pos(data, l7payload, m))
        .filter(|&p| p != POS_NOT_FOUND)
        .collect();
    v.sort();
    v.dedup();
    v
}

// ---- HTTP ----
const HTTP_METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"OPTIONS ",
    b"PUT ",
    b"DELETE ",
    b"CONNECT ",
    b"TRACE ",
    b"PATCH ",
];

fn http_method(data: &[u8]) -> Option<&'static [u8]> {
    if data.len() >= 4 {
        HTTP_METHODS.iter().copied().find(|m| data.starts_with(m))
    } else {
        None
    }
}

pub fn is_http(data: &[u8]) -> bool {
    if http_method(data).is_none() {
        return false;
    }
    let mut i = 0;
    let n = data.len();
    while i < n && !matches!(data[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    if i >= n || !matches!(data[i], b' ' | b'\t') {
        return false;
    }
    while i < n && matches!(data[i], b' ' | b'\t') {
        i += 1;
    }
    while i < n && !matches!(data[i], b' ' | b'\t' | b'\r' | b'\n') {
        i += 1;
    }
    if i >= n || !matches!(data[i], b' ' | b'\t') {
        return false;
    }
    while i < n && matches!(data[i], b' ' | b'\t') {
        i += 1;
    }
    if n - i < 10 || data[i] == b'\r' || data[i] == b'\n' {
        return false;
    }
    data[i..].starts_with(b"HTTP/1.")
}

fn is_host_at(p: &[u8]) -> bool {
    p[0] == b'\n'
        && (p[1] == b'H' || p[1] == b'h')
        && (p[2] == b'o' || p[2] == b'O')
        && (p[3] == b's' || p[3] == b'S')
        && (p[4] == b't' || p[4] == b'T')
        && p[5] == b':'
}

/// Offset of "Host:" (after the newline) or None.
pub fn http_find_host(buf: &[u8]) -> Option<usize> {
    if buf.len() < 6 {
        return None;
    }
    (0..=buf.len() - 6)
        .find(|&p| is_host_at(&buf[p..]))
        .map(|p| p + 1)
}

pub fn is_http_reply(d: &[u8]) -> bool {
    d.len() > 14
        && d.starts_with(b"HTTP/1.")
        && (d[7] == b'0' || d[7] == b'1')
        && d[8] == b' '
        && d[9].is_ascii_digit()
        && d[10].is_ascii_digit()
        && d[11].is_ascii_digit()
}

pub fn http_reply_code(d: &[u8]) -> i32 {
    (d[9] as i32 - b'0' as i32) * 100
        + (d[10] as i32 - b'0' as i32) * 10
        + (d[11] as i32 - b'0' as i32)
}

/// HttpExtractHeader. `len_buf` limits the copied value like the C buffer (len_buf-1 chars).
pub fn http_extract_header(data: &[u8], header: &[u8], len_buf: usize) -> Option<Vec<u8>> {
    let p = strncasestr(data, header)? + header.len();
    let mut p = p;
    while p < data.len() && (data[p] == b' ' || data[p] == b'\t') {
        p += 1;
    }
    let mut s = p;
    while s < data.len() && !matches!(data[s], b'\r' | b'\n' | b' ' | b'\t') {
        s += 1;
    }
    if s > p {
        let mut slen = s - p;
        if len_buf > 0 && slen >= len_buf {
            slen = len_buf - 1;
        }
        Some(
            data[p..p + slen]
                .iter()
                .map(|c| c.to_ascii_lowercase())
                .collect(),
        )
    } else {
        None
    }
}

pub fn http_extract_host(data: &[u8], len_host: usize) -> Option<Vec<u8>> {
    http_extract_header(data, b"\nHost:", len_host)
}

pub fn http_reply_looks_like_dpi_redirect(data: &[u8], host: &[u8]) -> bool {
    if host.is_empty() || !is_http_reply(data) {
        return false;
    }
    let code = http_reply_code(data);
    if code != 302 && code != 307 {
        return false;
    }
    let Some(loc) = http_extract_header(data, b"\nLocation:", 256) else {
        return false;
    };
    let rh = if loc.starts_with(b"http://") {
        &loc[7..]
    } else if loc.starts_with(b"https://") {
        &loc[8..]
    } else {
        return false;
    };
    let e = rh
        .iter()
        .position(|&c| c == b'/' || c == b'?' || c == b'#' || c == 0)
        .unwrap_or(rh.len());
    let rh = &rh[..e];
    if rh.is_empty() {
        return false;
    }
    let Some((dr, _)) = find_nld(rh, 2) else {
        return false;
    };
    let host = &host[..host.iter().position(|&c| c == 0).unwrap_or(host.len())];
    let Some((dh, _)) = find_nld(host, 2) else {
        return true;
    };
    !rh[dr..].eq_ignore_ascii_case(&host[dh..])
}

pub fn http_pos(marker: u8, pos: i16, data: &[u8]) -> isize {
    let sz = data.len();
    match marker {
        PM_HTTP_METHOD => {
            if sz < 12 {
                return POS_NOT_FOUND;
            }
            let mut m = 0usize;
            if data[m] == b'\n' || data[m] == b'\r' {
                m += 1;
            }
            if data[m] == b'\n' || data[m] == b'\r' {
                m += 1;
            }
            let mut p = m;
            let mut i = 0;
            while i < 9 && data[p].is_ascii_uppercase() {
                i += 1;
                p += 1;
            }
            if i < 3 || data[p] != b' ' {
                return POS_NOT_FOUND;
            }
            check_pos(sz, m as isize + pos as isize)
        }
        PM_HOST | PM_HOST_END | PM_HOST_SLD | PM_HOST_MIDSLD | PM_HOST_ENDSLD => {
            if let Some(h) = http_find_host(data) {
                if h + 7 < sz {
                    let mut h = h + 5;
                    if data[h] == b' ' || data[h] == b'\t' {
                        h += 1;
                    }
                    let mut len_host = 0;
                    if marker != PM_HOST {
                        while h + len_host < sz
                            && data[h + len_host] != b'\r'
                            && data[h + len_host] != b'\n'
                        {
                            len_host += 1;
                        }
                    }
                    return host_pos(marker, pos, data, h, len_host);
                }
            }
            POS_NOT_FOUND
        }
        _ => any_proto_pos(marker, pos, sz),
    }
}

// ---- TLS ----
pub fn tls_version_str(v: u16) -> &'static str {
    match v {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => {
            if (v & 0x0F0F) == 0x0A0A && (v >> 12) == ((v >> 4) & 0xF) {
                "GREASE"
            } else {
                "UNKNOWN"
            }
        }
    }
}

pub fn tls_handshake_data_len(d: &[u8]) -> usize {
    pntoh24(&d[1..]) as usize
}
pub fn tls_handshake_len(d: &[u8]) -> usize {
    tls_handshake_data_len(d) + 4
}
pub fn is_tls_handshake_full(d: &[u8]) -> bool {
    tls_handshake_len(d) <= d.len()
}
pub fn tls_record_data_len(d: &[u8]) -> u16 {
    pntoh16(&d[3..])
}
pub fn tls_record_len(d: &[u8]) -> usize {
    tls_record_data_len(d) as usize + 5
}
pub fn is_tls_record_full(d: &[u8]) -> bool {
    tls_record_len(d) <= d.len()
}
pub fn is_tls_handshake_hello(d: &[u8], typ: u8, partial_ok: bool) -> bool {
    d.len() >= 6
        && ((typ != 0 && d[0] == typ) || (typ == 0 && (d[0] == 1 || d[0] == 2)))
        && d[4] == 0x03
        && d[5] <= 0x03
        && (partial_ok || is_tls_handshake_full(d))
}
pub fn is_tls_handshake_client_hello(d: &[u8], partial_ok: bool) -> bool {
    is_tls_handshake_hello(d, 1, partial_ok)
}
pub fn is_tls_handshake_server_hello(d: &[u8], partial_ok: bool) -> bool {
    is_tls_handshake_hello(d, 2, partial_ok)
}
pub fn is_tls_hello(d: &[u8], typ: u8, partial_ok: bool) -> bool {
    d.len() >= 6
        && d[0] == 0x16
        && d[1] == 0x03
        && d[2] <= 0x03
        && (partial_ok || is_tls_record_full(d))
        && is_tls_handshake_hello(&d[5..], typ, partial_ok)
}
pub fn is_tls_client_hello(d: &[u8], partial_ok: bool) -> bool {
    is_tls_hello(d, 1, partial_ok)
}
pub fn is_tls_server_hello(d: &[u8], partial_ok: bool) -> bool {
    is_tls_hello(d, 2, partial_ok)
}

pub fn tls_find_ext_len_offset_in_handshake(d: &[u8]) -> Option<usize> {
    let len = d.len();
    let mut l = 1 + 3 + 2 + 32;
    if len < l + 1 {
        return None;
    }
    l += d[l] as usize + 1;
    if len < l + 2 {
        return None;
    }
    if d[0] == 1 {
        l += pntoh16(&d[l..]) as usize;
    }
    l += 2;
    if len < l + 1 {
        return None;
    }
    if d[0] == 1 {
        l += d[l] as usize;
    }
    l += 1;
    if len < l + 2 {
        return None;
    }
    Some(l)
}

pub fn tls_find_ext_len(d: &[u8]) -> Option<usize> {
    if d.len() < 5 {
        return None;
    }
    tls_find_ext_len_offset_in_handshake(&d[5..]).map(|o| o + 5)
}

/// Returns (offset of ext data relative to `d`, ext len).
pub fn tls_find_ext_in_handshake(d: &[u8], typ: u16, partial_ok: bool) -> Option<(usize, usize)> {
    if !partial_ok && !is_tls_handshake_full(d) {
        return None;
    }
    let off = tls_find_ext_len_offset_in_handshake(d)?;
    let mut pos = off;
    let mut len = d.len() - off;
    let mut l = pntoh16(&d[pos..]) as usize;
    pos += 2;
    len -= 2;
    if partial_ok {
        if len < l {
            l = len;
        }
    } else if len < l {
        return None;
    }
    while l >= 4 {
        let etype = pntoh16(&d[pos..]);
        let elen = pntoh16(&d[pos + 2..]) as usize;
        pos += 4;
        l -= 4;
        if l < elen {
            break;
        }
        if etype == typ {
            return Some((pos, elen));
        }
        pos += elen;
        l -= elen;
    }
    None
}

pub fn tls_find_ext(d: &[u8], typ: u16, partial_ok: bool) -> Option<(usize, usize)> {
    if !is_tls_hello(d, 0, partial_ok) {
        return None;
    }
    let mut len = d.len();
    let reclen = tls_record_len(d);
    if reclen < len {
        len = reclen;
    }
    tls_find_ext_in_handshake(&d[5..len], typ, partial_ok).map(|(o, l)| (o + 5, l))
}

/// TLSAdvanceToHostInSNI: given ext (offset, len) returns (host offset, remaining elen, slen).
pub fn tls_advance_to_host_in_sni(
    d: &[u8],
    ext: usize,
    elen: usize,
) -> Option<(usize, usize, usize)> {
    if elen < 5 || d[ext + 2] != 0 {
        return None;
    }
    let nll = pntoh16(&d[ext..]) as usize;
    let slen = pntoh16(&d[ext + 3..]) as usize;
    if nll < slen + 3 || nll > elen - 2 {
        return None;
    }
    Some((ext + 5, elen - 5, slen))
}

fn tls_extract_host_from_ext(
    d: &[u8],
    ext: usize,
    elen: usize,
    len_host: usize,
) -> Option<Vec<u8>> {
    let (h, _, mut slen) = tls_advance_to_host_in_sni(d, ext, elen)?;
    if len_host > 0 && slen >= len_host {
        slen = len_host - 1;
    }
    Some(
        d[h..h + slen]
            .iter()
            .map(|c| c.to_ascii_lowercase())
            .collect(),
    )
}

pub fn tls_hello_extract_host(d: &[u8], len_host: usize, partial_ok: bool) -> Option<Vec<u8>> {
    let (e, l) = tls_find_ext(d, 0, partial_ok)?;
    tls_extract_host_from_ext(d, e, l, len_host)
}

pub fn tls_hello_extract_host_from_handshake(
    d: &[u8],
    len_host: usize,
    partial_ok: bool,
) -> Option<Vec<u8>> {
    let (e, l) = tls_find_ext_in_handshake(d, 0, partial_ok)?;
    tls_extract_host_from_ext(d, e, l, len_host)
}

pub fn tls_pos(marker: u8, pos: i16, data: &[u8]) -> isize {
    let sz = data.len();
    match marker {
        PM_HOST | PM_HOST_END | PM_HOST_SLD | PM_HOST_MIDSLD | PM_HOST_ENDSLD | PM_SNI_EXT => {
            if let Some((ext, elen)) = tls_find_ext(data, 0, true) {
                if marker == PM_SNI_EXT {
                    return check_pos(sz, ext as isize + pos as isize);
                }
                let Some((h, _, len)) = tls_advance_to_host_in_sni(data, ext, elen) else {
                    return POS_NOT_FOUND;
                };
                return host_pos(marker, pos, data, h, len);
            }
            POS_NOT_FOUND
        }
        PM_EXT_LEN => match tls_find_ext_len(data) {
            Some(o) => check_pos(sz, o as isize + pos as isize),
            None => POS_NOT_FOUND,
        },
        _ => any_proto_pos(marker, pos, sz),
    }
}

pub const FAKE_TLS_MOD_RND: u32 = 0x01;
pub const FAKE_TLS_MOD_RND_SNI: u32 = 0x02;
pub const FAKE_TLS_MOD_SNI: u32 = 0x04;
pub const FAKE_TLS_MOD_DUP_SID: u32 = 0x08;
pub const FAKE_TLS_MOD_PADENCAP: u32 = 0x10;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeTlsMod {
    pub sni: Vec<u8>,
    pub modf: u32,
}

pub fn tls_mod_parse_list(modlist: &str) -> Option<FakeTlsMod> {
    let mut m = FakeTlsMod::default();
    let b = modlist.as_bytes();
    let mut p = 0;
    while p < b.len() {
        let e = b[p..]
            .iter()
            .position(|&c| c == b',')
            .map_or(b.len(), |x| p + x);
        let opt = &b[p..e.min(p + 139)];
        let (name, val) = match opt.iter().position(|&c| c == b'=') {
            Some(i) => (&opt[..i], Some(&opt[i + 1..])),
            None => (opt, None),
        };
        match name {
            b"rnd" => m.modf |= FAKE_TLS_MOD_RND,
            b"rndsni" => m.modf |= FAKE_TLS_MOD_RND_SNI,
            b"dupsid" => m.modf |= FAKE_TLS_MOD_DUP_SID,
            b"padencap" => m.modf |= FAKE_TLS_MOD_PADENCAP,
            b"sni" => {
                m.modf |= FAKE_TLS_MOD_SNI;
                match val {
                    Some(v) if !v.is_empty() => m.sni = v[..v.len().min(255)].to_vec(),
                    _ => return None,
                }
            }
            b"none" => {}
            _ => return None,
        }
        p = if e < b.len() { e + 1 } else { e };
    }
    Some(m)
}

pub const TLD: [&str; 6] = ["com", "org", "net", "edu", "gov", "biz"];

/// TLSMod. `fake` holds the fake (len = current size), `buf_size` is the C buffer size.
pub fn tls_mod(
    m: &FakeTlsMod,
    payload: Option<&[u8]>,
    fake: &mut Vec<u8>,
    buf_size: usize,
) -> bool {
    let mut extlen_offset = 0usize;
    if !is_tls_client_hello(fake, false) || fake.len() < 44 + fake[43] as usize {
        dlog_err!("cannot apply tls mod. tls structure invalid\n");
        return false;
    }
    if m.modf & (FAKE_TLS_MOD_RND_SNI | FAKE_TLS_MOD_SNI | FAKE_TLS_MOD_PADENCAP) != 0 {
        match tls_find_ext_len(fake) {
            Some(o) => extlen_offset = o,
            None => {
                dlog_err!("cannot apply tls mod. tls structure invalid\n");
                return false;
            }
        }
        dlog!("tls extensions length offset : {}\n", extlen_offset);
    }
    if m.modf & (FAKE_TLS_MOD_RND_SNI | FAKE_TLS_MOD_SNI) != 0 {
        let Some((sniext, extlen)) = tls_find_ext(fake, 0, false) else {
            dlog_err!("cannot apply tls mod. sni mod is set but tls does not have SNI\n");
            return false;
        };
        let Some((sni, _, mut slen)) = tls_advance_to_host_in_sni(fake, sniext, extlen) else {
            dlog_err!("cannot apply tls mod. sni set but tls has invalid SNI structure\n");
            return false;
        };
        if m.modf & FAKE_TLS_MOD_SNI != 0 {
            let slen_new = m.sni.len();
            let delta = slen_new as isize - slen as isize;
            let s1 = fake[sni..sni + slen].to_vec();
            if delta != 0 {
                if (fake.len() as isize + delta) as usize > buf_size {
                    dlog_err!("cannot apply sni tls mod. not enough space for new SNI\n");
                    return false;
                }
                let tail = fake[sni + slen..].to_vec();
                fake.truncate(sni);
                fake.resize(sni + slen_new, 0);
                fake.extend_from_slice(&tail);
                let add16 = |f: &mut Vec<u8>, o: usize| {
                    let v = (pntoh16(&f[o..]) as isize + delta) as u16;
                    phton16(&mut f[o..], v);
                };
                add16(fake, 3);
                let v = (pntoh24(&fake[6..]) as isize + delta) as u32;
                phton24(&mut fake[6..], v);
                add16(fake, extlen_offset);
                add16(fake, sniext - 2);
                add16(fake, sniext);
                add16(fake, sni - 2);
                slen = slen_new;
            }
            dlog!(
                "change SNI : {} => {} size_delta={}\n",
                String::from_utf8_lossy(&s1),
                String::from_utf8_lossy(&m.sni),
                delta
            );
            fake[sni..sni + slen_new].copy_from_slice(&m.sni);
        }
        if m.modf & FAKE_TLS_MOD_RND_SNI != 0 {
            if slen == 0 {
                dlog_err!("cannot apply rndsni tls mod. tls has zero sized SNI\n");
                return false;
            }
            let s1 = fake[sni..sni + slen].to_vec();
            fill_random_az(&mut fake[sni..sni + 1]);
            if slen >= 7 {
                fill_random_az09(&mut fake[sni + 1..sni + 1 + slen - 5]);
                fake[sni + slen - 4] = b'.';
                let t = TLD[(random() % 6) as usize].as_bytes();
                fake[sni + slen - 3..sni + slen].copy_from_slice(t);
            } else {
                fill_random_az09(&mut fake[sni + 1..sni + slen]);
            }
            dlog!(
                "generated random SNI : {} -> {}\n",
                String::from_utf8_lossy(&s1),
                String::from_utf8_lossy(&fake[sni..sni + slen])
            );
        }
    }
    if m.modf & FAKE_TLS_MOD_RND != 0 {
        fill_random_bytes(&mut fake[11..43]);
        let sl = fake[43] as usize;
        fill_random_bytes(&mut fake[44..44 + sl]);
        dlog!("applied rnd tls mod\n");
    }
    if let Some(payload) = payload {
        if m.modf & FAKE_TLS_MOD_DUP_SID != 0 {
            if is_tls_client_hello(payload, true) {
                if payload.len() < 44 {
                    dlog!("(nonfatal) cannot apply dupsid tls mod. data payload is too short.\n");
                } else if fake[43] != payload[43] {
                    dlog!(
                        "(nonfatal) cannot apply dupsid tls mod. fake and orig session id length mismatch : {}!={}.\n",
                        fake[43],
                        payload[43]
                    );
                } else if payload.len() < 44 + payload[43] as usize {
                    dlog!("(nonfatal) cannot apply dupsid tls mod. data payload is not valid.\n");
                } else {
                    let sl = fake[43] as usize;
                    fake[44..44 + sl].copy_from_slice(&payload[44..44 + sl]);
                    dlog!("applied dupsid tls mod\n");
                }
            } else {
                dlog_err!("(nonfatal) cannot apply dupsid tls mod. payload is not valid tls.\n");
            }
        }
        if m.modf & FAKE_TLS_MOD_PADENCAP != 0 {
            let padlen_offset;
            if let Some((ext, extlen)) = tls_find_ext(fake, 21, false) {
                if ext + extlen != fake.len() {
                    dlog_err!(
                        "cannot apply padencap tls mod. tls padding ext is present but it's not at the end. padding ext offset {}, padding ext size {}, fake size {}\n",
                        ext,
                        extlen,
                        fake.len()
                    );
                    return false;
                }
                padlen_offset = ext - 2;
                dlog!(
                    "tls padding ext is present, padding length offset {}\n",
                    padlen_offset
                );
            } else {
                if fake.len() + 4 > buf_size {
                    dlog_err!("tls padding is absent and there's no space to add it\n");
                    return false;
                }
                fake.extend_from_slice(&[0, 21]);
                padlen_offset = fake.len();
                fake.extend_from_slice(&[0, 0]);
                let v = pntoh16(&fake[extlen_offset..]).wrapping_add(4);
                phton16(&mut fake[extlen_offset..], v);
                let v = pntoh16(&fake[3..]).wrapping_add(4);
                phton16(&mut fake[3..], v);
                let v = pntoh24(&fake[6..]).wrapping_add(4);
                phton24(&mut fake[6..], v);
                dlog!(
                    "tls padding is absent. added. padding length offset {}\n",
                    padlen_offset
                );
            }
            let pl = payload.len();
            let sz_rec = pntoh16(&fake[3..]) as usize + pl;
            let sz_hs = pntoh24(&fake[6..]) as usize + pl;
            let sz_ext = pntoh16(&fake[extlen_offset..]) as usize + pl;
            let sz_pad = pntoh16(&fake[padlen_offset..]) as usize + pl;
            if sz_rec & !0xFFFF != 0
                || sz_hs & !0xFFFFFF != 0
                || sz_ext & !0xFFFF != 0
                || sz_pad & !0xFFFF != 0
            {
                dlog!("(nonfatal) cannot apply padencap tls mod. length overflow.\n");
            } else {
                phton16(&mut fake[3..], sz_rec as u16);
                phton24(&mut fake[6..], sz_hs as u32);
                phton16(&mut fake[extlen_offset..], sz_ext as u16);
                phton16(&mut fake[padlen_offset..], sz_pad as u16);
                dlog!(
                    "applied padencap tls mod. sizes increased by {} bytes.\n",
                    pl
                );
            }
        }
    }
    true
}

// ---- QUIC ----
fn tvb_get_varint(d: &[u8]) -> (usize, u64) {
    match d[0] >> 6 {
        0 => (1, (d[0] & 0x3F) as u64),
        1 => (2, (pntoh16(d) & 0x3FFF) as u64),
        2 => (4, (pntoh32(d) & 0x3FFFFFFF) as u64),
        _ => (8, pntoh64(d) & 0x3FFFFFFFFFFFFFFF),
    }
}
fn tvb_get_size(b: u8) -> usize {
    1 << (b >> 6)
}

/// Returns (hello_offset, hello_len).
pub fn is_quic_crypto_hello(d: &[u8]) -> Option<(usize, usize)> {
    let len = d.len();
    let mut off = 1usize;
    if len < 3 || d[0] != 6 {
        return None;
    }
    if off + tvb_get_size(d[off]) >= len {
        return None;
    }
    let (n, coff) = tvb_get_varint(&d[off..]);
    off += n;
    if coff != 0 || off + tvb_get_size(d[off]) >= len {
        return None;
    }
    let (n, clen) = tvb_get_varint(&d[off..]);
    off += n;
    if off as u64 + clen > len as u64
        || !is_tls_handshake_client_hello(&d[off..off + clen as usize], true)
    {
        return None;
    }
    Some((off, clen as usize))
}

fn is_quic_v2(v: u32) -> bool {
    v == 0x709A50C4 || v == 0x6b3343cf
}

pub fn quic_draft_version(v: u32) -> u8 {
    if (v >> 8) == 0xff0000 {
        return v as u8;
    }
    if v == 0xfaceb001 {
        return 22;
    }
    if v == 0xfaceb002 || v == 0xfaceb00e {
        return 27;
    }
    if v == 0x51303530 || v == 0x54303530 || v == 0x54303531 {
        return 27;
    }
    if (v & 0x0F0F0F0F) == 0x0a0a0a0a {
        return 29;
    }
    if v == 1 {
        return 34;
    }
    if is_quic_v2(v) {
        return 100;
    }
    0
}

fn is_quic_draft_max(dv: u8, max: u8) -> bool {
    dv != 0 && dv <= max
}

fn quic_hkdf_expand_label(secret: &[u8], label: &str, out_len: usize) -> Option<Vec<u8>> {
    let lb = label.as_bytes();
    let mut l = Vec::with_capacity(4 + lb.len());
    l.extend_from_slice(&(out_len as u16).to_be_bytes());
    l.push(lb.len() as u8);
    l.extend_from_slice(lb);
    l.push(0);
    if l.len() > 64 {
        return None;
    }
    crypto::hkdf_expand(crypto::ShaVer::Sha256, secret, &l, out_len)
}

fn quic_derive_initial_secret(cid: &[u8], version: u32) -> Option<Vec<u8>> {
    const S22: [u8; 20] = [
        0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a, 0x96, 0xcd, 0x21, 0x51, 0x9e,
        0xbd, 0x7a, 0x02, 0x64, 0x4a,
    ];
    const S23: [u8; 20] = [
        0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63,
        0x65, 0xbe, 0xf9, 0xf5, 0x02,
    ];
    const S29: [u8; 20] = [
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11,
        0xe0, 0x43, 0x90, 0xa8, 0x99,
    ];
    const SV1: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    const SQ50: [u8; 20] = [
        0x50, 0x45, 0x74, 0xEF, 0xD0, 0x66, 0xFE, 0x2F, 0x9D, 0x94, 0x5C, 0xFC, 0xDB, 0xD3, 0xA7,
        0xF0, 0xD3, 0xB5, 0x6B, 0x45,
    ];
    const ST50: [u8; 20] = [
        0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80, 0x30, 0x4c, 0x43, 0xa2, 0x36,
        0x7c, 0x60, 0x48, 0x83, 0x10,
    ];
    const ST51: [u8; 20] = [
        0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50, 0x6c, 0x19, 0x12, 0x4f, 0xc8,
        0xcc, 0xda, 0x6e, 0x03, 0x3d,
    ];
    const SV2: [u8; 20] = [
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d,
        0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
    ];
    let dv = quic_draft_version(version);
    let salt: &[u8] = if version == 0x51303530 {
        &SQ50
    } else if version == 0x54303530 {
        &ST50
    } else if version == 0x54303531 {
        &ST51
    } else if is_quic_draft_max(dv, 22) {
        &S22
    } else if is_quic_draft_max(dv, 28) {
        &S23
    } else if is_quic_draft_max(dv, 32) {
        &S29
    } else if is_quic_draft_max(dv, 34) {
        &SV1
    } else {
        &SV2
    };
    let secret = crypto::hkdf_extract(crypto::ShaVer::Sha256, salt, cid);
    quic_hkdf_expand_label(&secret, "tls13 client in", 32)
}

pub fn quic_is_long_header(d: &[u8]) -> bool {
    d.len() >= 9 && d[0] & 0x80 != 0
}
pub fn quic_extract_version(d: &[u8]) -> u32 {
    if quic_is_long_header(d) {
        pntoh32(&d[1..])
    } else {
        0
    }
}
pub fn quic_extract_dcid(d: &[u8]) -> Option<Vec<u8>> {
    if !quic_is_long_header(d) || d[5] == 0 || d[5] > 20 || 6 + d[5] as usize > d.len() {
        return None;
    }
    Some(d[6..6 + d[5] as usize].to_vec())
}

/// QUICDecryptInitial. `clean_max` is the caller's buffer size.
pub fn quic_decrypt_initial(data: &[u8], clean_max: usize) -> Option<Vec<u8>> {
    let dlen = data.len();
    let ver = quic_extract_version(data);
    if ver == 0 {
        return None;
    }
    let dcid = quic_extract_dcid(data)?;
    let cis = quic_derive_initial_secret(&dcid, ver)?;
    let v1 = !is_quic_v2(ver);
    let key = quic_hkdf_expand_label(
        &cis,
        if v1 {
            "tls13 quic key"
        } else {
            "tls13 quicv2 key"
        },
        16,
    )?;
    let mut iv = quic_hkdf_expand_label(
        &cis,
        if v1 {
            "tls13 quic iv"
        } else {
            "tls13 quicv2 iv"
        },
        12,
    )?;
    let hp = quic_hkdf_expand_label(
        &cis,
        if v1 {
            "tls13 quic hp"
        } else {
            "tls13 quicv2 hp"
        },
        16,
    )?;

    let mut pn: u64 = 1 + 4 + 1 + data[5] as u64;
    if pn >= dlen as u64 {
        return None;
    }
    pn += 1 + data[pn as usize] as u64;
    if pn >= dlen as u64 || pn + tvb_get_size(data[pn as usize]) as u64 >= dlen as u64 {
        return None;
    }
    let (n, token_len) = tvb_get_varint(&data[pn as usize..]);
    pn = pn.wrapping_add(n as u64).wrapping_add(token_len);
    if pn >= dlen as u64 || pn + tvb_get_size(data[pn as usize]) as u64 >= dlen as u64 {
        return None;
    }
    let (n, payload_len) = tvb_get_varint(&data[pn as usize..]);
    pn += n as u64;
    if payload_len < 20 || pn.wrapping_add(payload_len) > dlen as u64 {
        return None;
    }
    let pn = pn as usize;
    let sample: [u8; 16] = data[pn + 4..pn + 20].try_into().ok()?;
    let mask = crypto::aes_block(true, &hp, &sample)?;
    let packet0 = data[0] ^ (mask[0] & 0x0f);
    let pkn_len = (packet0 & 3) as usize + 1;
    let mut pkn: u32 = 0;
    for i in 0..pkn_len {
        pkn |= ((data[pn + i] ^ mask[1 + i]) as u32) << (8 * (pkn_len - 1 - i));
    }
    let v = pntoh64(&iv[4..]) ^ pkn as u64;
    phton64(&mut iv[4..], v);
    let cryptlen = payload_len - pkn_len as u64 - 16;
    if cryptlen > clean_max as u64 {
        return None;
    }
    let cryptlen = cryptlen as usize;
    let header_len = pn + pkn_len;
    if header_len > 2048 {
        return None;
    }
    let mut header = data[..header_len].to_vec();
    header[0] = packet0;
    for i in 0..pkn_len {
        header[header_len - 1 - i] = (pkn >> (8 * i)) as u8;
    }
    let ct = &data[header_len..header_len + cryptlen];
    let (clean, tag) = crypto::aes_gcm(false, &key, &iv, ct, &header)?;
    (data[header_len + cryptlen..header_len + cryptlen + 16] == tag).then_some(clean)
}

/// QUICDefragCrypto. Returns (defrag buffer, full coverage) when crypto frames were found.
/// `defrag_max` is the caller's buffer size.
pub fn quic_defrag_crypto(clean: &[u8], defrag_max: usize) -> Option<(Vec<u8>, bool)> {
    if defrag_max < 10 {
        return None;
    }
    let ddl = (defrag_max - 10) as u64;
    let mut defrag = vec![0u8; defrag_max];
    let clen = clean.len();
    let (mut szmax, mut zeropos, mut pos) = (0u64, 0u64, 0usize);
    let mut found = false;
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    while pos < clen {
        let ft = clean[pos];
        pos += 1;
        if ft > 1 {
            if ft != 6 || pos >= clen || ranges.len() >= 128 {
                return None;
            }
            if pos + tvb_get_size(clean[pos]) >= clen {
                return None;
            }
            let (n, offset) = tvb_get_varint(&clean[pos..]);
            pos += n;
            if pos + tvb_get_size(clean[pos]) > clen {
                return None;
            }
            let (n, sz) = tvb_get_varint(&clean[pos..]);
            pos += n;
            if pos as u64 + sz > clen as u64 || offset + sz > ddl {
                return None;
            }
            if !ranges.iter().any(|r| r.0 == offset && r.1 == sz) {
                if zeropos < offset {
                    defrag[10 + zeropos as usize..10 + offset as usize].fill(0);
                }
                if offset + sz > zeropos {
                    zeropos = offset + sz;
                }
                found = true;
                szmax = szmax.max(offset + sz);
                defrag[10 + offset as usize..10 + (offset + sz) as usize]
                    .copy_from_slice(&clean[pos..pos + sz as usize]);
                ranges.push((offset, sz));
            }
            pos += sz as usize;
        }
    }
    if !found {
        return None;
    }
    // qsort is not stable; ranges with equal offsets differ only in len, merging is order independent
    // for the result we compute (coverage), so a stable sort is equivalent.
    ranges.sort_by_key(|r| r.0);
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for r in ranges {
        if let Some(last) = merged.last_mut() {
            let cur_end = last.0 + last.1;
            if r.0 <= cur_end {
                last.1 = (r.0 + r.1).max(cur_end) - last.0;
                continue;
            }
        }
        merged.push(r);
    }
    defrag[0] = 6;
    defrag[1] = 0;
    phton64(&mut defrag[2..], szmax);
    defrag[2] |= 0xC0;
    defrag.truncate((szmax + 10) as usize);
    let full = merged.len() == 1 && merged[0].0 == 0;
    Some((defrag, full))
}

pub fn is_quic_initial(d: &[u8]) -> bool {
    let len = d.len() as u64;
    if len < 128 {
        return false;
    }
    let ver = quic_extract_version(d);
    if quic_draft_version(ver) < 11 {
        return false;
    }
    if (d[0] & 0xF0) != (if is_quic_v2(ver) { 0xD0 } else { 0xC0 }) {
        return false;
    }
    let mut off: u64 = 5;
    if d[off as usize] > 20 {
        return false;
    }
    off += 1 + d[off as usize] as u64;
    if off >= len {
        return false;
    }
    if d[off as usize] > 20 {
        return false;
    }
    off += 1 + d[off as usize] as u64;
    if off >= len || off + tvb_get_size(d[off as usize]) as u64 > len {
        return false;
    }
    let (n, sz) = tvb_get_varint(&d[off as usize..]);
    off = off.wrapping_add(n as u64).wrapping_add(sz);
    if off >= len {
        return false;
    }
    let sz2 = tvb_get_size(d[off as usize]) as u64;
    if off + sz2 > len {
        return false;
    }
    let (_, sz) = tvb_get_varint(&d[off as usize..]);
    off = off.wrapping_add(sz2).wrapping_add(sz);
    off <= len
}

fn memmem(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

pub fn is_xmpp_stream(d: &[u8]) -> bool {
    (d.len() >= 16 && d.starts_with(b"<stream:stream "))
        || (d.len() >= 36 && d.starts_with(b"<?xml ") && memmem(&d[21..], b"<stream:stream "))
}
pub fn is_xmpp_starttls(d: &[u8]) -> bool {
    d.len() >= 10 && d.starts_with(b"<starttls ")
}
pub fn is_xmpp_proceed_tls(d: &[u8]) -> bool {
    d.len() >= 9 && d.starts_with(b"<proceed ")
}
pub fn is_xmpp_features(d: &[u8]) -> bool {
    d.len() >= 17 && d.starts_with(b"<stream:features")
}
pub fn is_dns_query(d: &[u8]) -> bool {
    d.len() >= 12 && d[2] & 0xFE == 0 && d[4..10] == [0, 1, 0, 0, 0, 0] && pntoh16(&d[10..]) <= 3
}
pub fn is_dns_response(d: &[u8]) -> bool {
    d.len() >= 12
        && (d[2] & 0xF8) == 0x80
        && pntoh16(&d[4..]) == 1
        && pntoh16(&d[6..]) <= 100
        && pntoh16(&d[8..]) <= 100
        && pntoh16(&d[10..]) <= 100
}
pub fn is_wireguard_handshake_initiation(d: &[u8]) -> bool {
    d.len() == 148 && pntoh32(d) == 0x01000000
}
pub fn is_wireguard_handshake_response(d: &[u8]) -> bool {
    d.len() == 92 && pntoh32(d) == 0x02000000
}
pub fn is_wireguard_handshake_cookie(d: &[u8]) -> bool {
    d.len() == 64 && pntoh32(d) == 0x03000000
}
pub fn is_wireguard_data(d: &[u8]) -> bool {
    d.len() >= 52 && pntoh32(d) == 0x04000000
}
pub fn is_wireguard_keepalive(d: &[u8]) -> bool {
    d.len() == 32 && pntoh32(d) == 0x04000000
}
#[allow(clippy::nonminimal_bool)] // mirrors the C expression
pub fn is_dht(d: &[u8]) -> bool {
    d.len() >= 5
        && d[0] == b'd'
        && d[2] == b':'
        && d[d.len() - 1] == b'e'
        && ((d[1] == b'1' && d[3] == b'a' && d[4] == b'd')
            || (d[1] == b'1' && d[3] == b'r' && d[4] == b'd')
            || (d[1] == b'2' && d[3] == b'i' && d[4] == b'p')
            || (d[1] == b'1' && d[3] == b'e' && d[4] == b'l'))
}
pub fn is_discord_ip_discovery_request(d: &[u8]) -> bool {
    d.len() == 74
        && d[0] == 0
        && d[1] == 1
        && d[2] == 0
        && d[3] == 70
        && d[8..72].iter().all(|&c| c == 0)
}
pub fn is_stun_message(d: &[u8]) -> bool {
    d.len() >= 20
        && d[0] & 0xC0 == 0
        && d[3] & 3 == 0
        && pntoh32(&d[4..]) == 0x2112A442
        && pntoh16(&d[2..]) as usize <= d.len() - 20
}
pub fn is_mtproto(d: &[u8]) -> bool {
    if d.len() < 64 {
        return false;
    }
    let mut iv: [u8; 16] = match d[40..56].try_into() {
        Ok(v) => v,
        Err(_) => return false,
    };
    // ctr_add(iv, 3): 128-bit big endian add
    let v = u128::from_be_bytes(iv).wrapping_add(3);
    iv = v.to_be_bytes();
    match crypto::aes_block(true, &d[8..40], &iv) {
        Some(dec) => (0..4).all(|i| dec[8 + i] ^ d[56 + i] == 0xEF),
        None => false,
    }
}
#[allow(clippy::nonminimal_bool)] // mirrors the C expression
pub fn is_dtls(d: &[u8]) -> bool {
    d.len() > 13
        && (0x14..=0x17).contains(&d[0])
        && ((d[1] == 0xfe && d[2] == 0xff)
            || (d[1] == 0xfe && d[2] == 0xfd)
            || (d[1] == 0xfe && d[2] == 0xfc)
            || (d[1] == 0x01 && d[2] == 0x00))
        && pntoh16(&d[11..]) as usize + 13 <= d.len()
}
pub fn is_dtls_client_hello(d: &[u8]) -> bool {
    is_dtls(d) && d[0] == 0x16 && d[13] == 1
}
pub fn is_dtls_server_hello(d: &[u8]) -> bool {
    is_dtls(d) && d[0] == 0x16 && d[13] == 2
}
pub fn is_bt_handshake(d: &[u8]) -> bool {
    d.len() >= 68 && d.starts_with(b"\x13BitTorrent protocol")
}
pub fn is_utp_bt_handshake(d: &[u8]) -> bool {
    d.len() >= 88 && d[0] == 1 && d[20..40] == *b"\x13BitTorrent protocol"
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nld() {
        assert_eq!(find_nld(b"www.example.com", 2), Some((4, 7)));
        assert_eq!(find_nld(b"com", 2), None);
        assert_eq!(find_nld(b"com", 1), Some((0, 3)));
    }
    #[test]
    fn http() {
        let r = b"GET / HTTP/1.1\r\nHost: www.iana.org\r\n\r\n";
        assert!(is_http(r));
        assert_eq!(http_extract_host(r, 256), Some(b"www.iana.org".to_vec()));
        assert_eq!(http_pos(PM_HOST, 0, r), 22);
        assert_eq!(http_pos(PM_HOST_MIDSLD, 0, r), 28);
    }
    #[test]
    fn markers() {
        assert_eq!(
            posmarker_parse("midsld+1"),
            Some(ProtoPos {
                pos: 1,
                marker: PM_HOST_MIDSLD
            })
        );
        assert_eq!(
            posmarker_parse("-5"),
            Some(ProtoPos {
                pos: -5,
                marker: PM_ABS
            })
        );
        assert!(posmarker_parse("foo").is_none());
    }
}
