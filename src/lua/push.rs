//! lua.c push/reconstruct helpers: table <-> header conversions.
//! SAFETY: see lj.rs; all functions take a live lua_State and keep the C stack discipline.

use super::lj::{self, L};
use crate::checksum::{
    icmp_fix_checksum, ip4_fix_checksum, tcp_fix_checksum, udp_fix_checksum, L3Addrs,
};
use crate::conntrack::{Ctrack, CtrackPosition, CtrackPositions};
use crate::darkmagic::*;
use crate::dlog_err;
use crate::filter::{PacketPos, PacketRange};
use crate::helpers::{pntoh16, pntoh32, random, SockAddr};
use crate::pools::Str2;
use crate::protocol::l7proto_str;

macro_rules! guard_enter {
    ($l:expr) => {
        lj::gettop($l)
    };
}
macro_rules! guard_leave {
    ($l:expr, $g:expr, $n:expr) => {
        if $g + $n != lj::gettop($l) {
            lj::error($l, "stack guard failure");
        }
    };
}
pub(crate) use {guard_enter, guard_leave};

pub fn pushf_nil(l: L, f: &str) {
    lj::pushstr(l, f);
    lj::pushnil(l);
    lj::rawset(l, -3);
}
/// lua_pushf_int: the value is a lua_Integer (32-bit on 32-bit targets), pushed with
/// lua_pushlint.
pub fn pushf_int(l: L, f: &str, v: i64) {
    lj::pushstr(l, f);
    lj::pushlint(l, v as lj::lua_Integer as i64);
    lj::rawset(l, -3);
}
/// lua_pushf_lint: a full 64-bit value.
pub fn pushf_lint(l: L, f: &str, v: i64) {
    lj::pushstr(l, f);
    lj::pushlint(l, v);
    lj::rawset(l, -3);
}
/// lua_pushi_int
pub fn pushi_int(l: L, i: i64, v: i64) {
    lj::pushinteger(l, i);
    lj::pushlint(l, v as lj::lua_Integer as i64);
    lj::rawset(l, -3);
}
pub fn pushf_number(l: L, f: &str, v: f64) {
    lj::pushstr(l, f);
    lj::pushnumber(l, v);
    lj::rawset(l, -3);
}
pub fn pushf_bool(l: L, f: &str, b: bool) {
    lj::pushstr(l, f);
    lj::pushboolean(l, b);
    lj::rawset(l, -3);
}
pub fn pushi_bool(l: L, i: i64, b: bool) {
    lj::pushinteger(l, i);
    lj::pushboolean(l, b);
    lj::rawset(l, -3);
}
/// lua_pushf_str: pushes nil for NULL.
pub fn pushf_str(l: L, f: &str, s: Option<&[u8]>) {
    lj::pushstr(l, f);
    match s {
        Some(s) => {
            // lua_pushstring stops at NUL
            let e = s.iter().position(|&c| c == 0).unwrap_or(s.len());
            lj::pushbytes(l, &s[..e]);
        }
        None => lj::pushnil(l),
    }
    lj::rawset(l, -3);
}
pub fn pushi_str(l: L, i: i64, s: &[u8]) {
    lj::pushinteger(l, i);
    lj::pushbytes(l, s);
    lj::rawset(l, -3);
}
pub fn pushf_raw(l: L, f: &str, v: Option<&[u8]>) {
    lj::pushstr(l, f);
    match v {
        Some(v) => lj::pushbytes(l, v),
        None => lj::pushnil(l),
    }
    lj::rawset(l, -3);
}
pub fn pushf_reg(l: L, f: &str, r: i32) {
    lj::pushstr(l, f);
    lj::rawgeti(l, lj::LUA_REGISTRYINDEX, r as i64);
    lj::rawset(l, -3);
}
pub fn pushf_table(l: L, f: &str) {
    lj::pushstr(l, f);
    lj::newtable(l);
    lj::rawset(l, -3);
}
pub fn pushi_table(l: L, i: i64) {
    lj::pushinteger(l, i);
    lj::newtable(l);
    lj::rawset(l, -3);
}

pub fn push_blob(l: L, idx_desync: i32, blob: &str) -> bool {
    lj::getfield(l, idx_desync, blob);
    if lj::typ(l, -1) == lj::LUA_TNIL {
        lj::pop(l, 1);
        lj::getglobal(l, blob);
        if lj::typ(l, -1) == lj::LUA_TNIL {
            lj::pop(l, 1);
            dlog_err!("blob '{}' unavailable\n", blob);
            return false;
        }
    }
    let _ = lj::tobytes(l, -1);
    true
}
pub fn pushf_blob(l: L, idx_desync: i32, f: &str, blob: &str) -> bool {
    lj::pushstr(l, f);
    if !push_blob(l, idx_desync, blob) {
        lj::pop(l, 1);
        return false;
    }
    lj::rawset(l, -3);
    true
}

pub fn push_ipaddr(l: L, sa: &SockAddr) {
    match sa {
        SockAddr::V4(a, _) => lj::pushbytes(l, a),
        SockAddr::V6(a, _) => lj::pushbytes(l, a),
        SockAddr::None => lj::pushnil(l),
    }
}
pub fn pushf_ipaddr(l: L, f: &str, sa: &SockAddr) {
    lj::pushstr(l, f);
    push_ipaddr(l, sa);
    lj::rawset(l, -3);
}

/// tcp: slice from the tcp header start, len: available length (dis.len_l4 or blob len)
pub fn pushf_tcphdr_options(l: L, tcp: &[u8], len: usize) {
    let g = guard_enter!(l);
    lj::pushstr(l, "options");
    lj::newtable(l);
    let mut end = (((tcp[12] >> 4) as usize) << 2).min(len).min(tcp.len());
    let mut t = TCP_HDR_LEN;
    let mut ee = end;
    while t < end {
        let opt = tcp[t];
        if opt == TCP_KIND_END {
            if ee == end {
                ee = t;
            }
        } else {
            ee = end;
        }
        if opt == TCP_KIND_NOOP || opt == TCP_KIND_END {
            t += 1;
        } else {
            if t + 1 >= end || tcp[t + 1] < 2 || t + tcp[t + 1] as usize > end {
                break;
            }
            t += tcp[t + 1] as usize;
        }
    }
    end = ee;
    t = TCP_HDR_LEN;
    let mut idx = 1i64;
    while t < end {
        let opt = tcp[t];
        if opt == TCP_KIND_NOOP || opt == TCP_KIND_END {
            lj::pushinteger(l, idx);
            lj::newtable(l);
            pushf_int(l, "kind", opt as i64);
            t += 1;
        } else {
            if t + 1 >= end || tcp[t + 1] < 2 || t + tcp[t + 1] as usize > end {
                break;
            }
            lj::pushinteger(l, idx);
            lj::newtable(l);
            pushf_int(l, "kind", opt as i64);
            pushf_raw(l, "data", Some(&tcp[t + 2..t + tcp[t + 1] as usize]));
            t += tcp[t + 1] as usize;
        }
        lj::rawset(l, -3);
        idx += 1;
    }
    lj::rawset(l, -3);
    guard_leave!(l, g, 0);
}

pub fn push_tcphdr(l: L, tcp: Option<&[u8]>, len: usize) {
    let g = guard_enter!(l);
    match tcp {
        Some(t) if len >= TCP_HDR_LEN => {
            lj::createtable(l, 0, 11);
            pushf_int(l, "th_sport", pntoh16(t) as i64);
            pushf_int(l, "th_dport", pntoh16(&t[2..]) as i64);
            pushf_lint(l, "th_seq", pntoh32(&t[4..]) as i64);
            pushf_lint(l, "th_ack", pntoh32(&t[8..]) as i64);
            pushf_int(l, "th_x2", (t[12] & 0xF) as i64);
            pushf_int(l, "th_off", (t[12] >> 4) as i64);
            pushf_int(l, "th_flags", t[13] as i64);
            pushf_int(l, "th_win", pntoh16(&t[14..]) as i64);
            pushf_int(l, "th_sum", pntoh16(&t[16..]) as i64);
            pushf_int(l, "th_urp", pntoh16(&t[18..]) as i64);
            pushf_tcphdr_options(l, t, len);
        }
        _ => lj::pushnil(l),
    }
    guard_leave!(l, g, 1);
}
pub fn pushf_tcphdr(l: L, tcp: Option<&[u8]>, len: usize) {
    lj::pushstr(l, "tcp");
    push_tcphdr(l, tcp, len);
    lj::rawset(l, -3);
}
pub fn push_udphdr(l: L, udp: Option<&[u8]>, len: usize) {
    match udp {
        Some(u) if len >= UDP_HDR_LEN => {
            lj::createtable(l, 0, 4);
            pushf_int(l, "uh_sport", pntoh16(u) as i64);
            pushf_int(l, "uh_dport", pntoh16(&u[2..]) as i64);
            pushf_int(l, "uh_ulen", pntoh16(&u[4..]) as i64);
            pushf_int(l, "uh_sum", pntoh16(&u[6..]) as i64);
        }
        _ => lj::pushnil(l),
    }
}
pub fn pushf_udphdr(l: L, udp: Option<&[u8]>, len: usize) {
    lj::pushstr(l, "udp");
    push_udphdr(l, udp, len);
    lj::rawset(l, -3);
}
pub fn push_icmphdr(l: L, icmp: Option<&[u8]>, len: usize) {
    match icmp {
        Some(i) if len >= ICMP_HDR_LEN => {
            lj::createtable(l, 0, 4);
            pushf_int(l, "icmp_type", i[0] as i64);
            pushf_int(l, "icmp_code", i[1] as i64);
            pushf_int(l, "icmp_cksum", pntoh16(&i[2..]) as i64);
            pushf_lint(l, "icmp_data", pntoh32(&i[4..]) as i64);
        }
        _ => lj::pushnil(l),
    }
}
pub fn pushf_icmphdr(l: L, icmp: Option<&[u8]>, len: usize) {
    lj::pushstr(l, "icmp");
    push_icmphdr(l, icmp, len);
    lj::rawset(l, -3);
}
pub fn push_iphdr(l: L, ip: Option<&[u8]>, len: usize) {
    match ip {
        Some(ip) if len >= IP_HDR_LEN => {
            let hl = ((ip[0] & 0xF) as usize) << 2;
            let has_opt = hl > IP_HDR_LEN && hl <= len;
            lj::createtable(l, 0, 11 + has_opt as i32);
            pushf_int(l, "ip_v", (ip[0] >> 4) as i64);
            pushf_int(l, "ip_hl", (ip[0] & 0xF) as i64);
            pushf_int(l, "ip_tos", ip[1] as i64);
            pushf_int(l, "ip_len", pntoh16(&ip[2..]) as i64);
            pushf_int(l, "ip_id", pntoh16(&ip[4..]) as i64);
            pushf_int(l, "ip_off", pntoh16(&ip[6..]) as i64);
            pushf_int(l, "ip_ttl", ip[8] as i64);
            pushf_int(l, "ip_p", ip[9] as i64);
            pushf_int(l, "ip_sum", pntoh16(&ip[10..]) as i64);
            pushf_raw(l, "ip_src", Some(&ip[12..16]));
            pushf_raw(l, "ip_dst", Some(&ip[16..20]));
            if has_opt {
                pushf_raw(l, "options", Some(&ip[IP_HDR_LEN..hl]));
            }
        }
        _ => lj::pushnil(l),
    }
}
pub fn pushf_iphdr(l: L, ip: Option<&[u8]>, len: usize) {
    lj::pushstr(l, "ip");
    push_iphdr(l, ip, len);
    lj::rawset(l, -3);
}
fn pushf_ip6exthdr(l: L, ip6: &[u8], len: usize) {
    lj::pushstr(l, "exthdr");
    lj::newtable(l);
    if len >= IP6_HDR_LEN {
        let mut ht = ip6[6];
        let mut pos = IP6_HDR_LEN;
        let mut len = len - IP6_HDR_LEN;
        let plen = pntoh16(&ip6[4..]) as usize;
        if plen < len {
            len = plen;
        }
        let (mut fr, mut fr_off) = (false, 0u16);
        let mut idx = 1i64;
        while len > 0 && !(fr && fr_off != 0) {
            let hdrlen = match ht {
                IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS | IPPROTO_MH | IPPROTO_HIP
                | IPPROTO_SHIM6 => {
                    if len < 2 {
                        break;
                    }
                    8 + ((ip6[pos + 1] as usize) << 3)
                }
                IPPROTO_FRAGMENT => {
                    if len < 8 {
                        break;
                    }
                    let offlg = pntoh16(&ip6[pos + 2..]);
                    fr_off = offlg & 0xFFF8;
                    fr = offlg & 0xFFF9 != 0;
                    8
                }
                IPPROTO_AH => {
                    if len < 2 {
                        break;
                    }
                    8 + ((ip6[pos + 1] as usize) << 2)
                }
                _ => break,
            };
            if len < hdrlen {
                break;
            }
            lj::pushinteger(l, idx);
            idx += 1;
            lj::createtable(l, 0, 3);
            pushf_int(l, "type", ht as i64);
            ht = ip6[pos];
            pushf_int(l, "next", ht as i64);
            pushf_raw(l, "data", Some(&ip6[pos + 2..pos + hdrlen]));
            lj::rawset(l, -3);
            len -= hdrlen;
            pos += hdrlen;
        }
    }
    lj::rawset(l, -3);
}
pub fn push_ip6hdr(l: L, ip6: Option<&[u8]>, len: usize) {
    match ip6 {
        Some(ip6) if len >= IP6_HDR_LEN => {
            lj::createtable(l, 0, 7);
            pushf_lint(l, "ip6_flow", pntoh32(ip6) as i64);
            pushf_lint(l, "ip6_plen", pntoh16(&ip6[4..]) as i64);
            pushf_int(l, "ip6_nxt", ip6[6] as i64);
            pushf_int(l, "ip6_hlim", ip6[7] as i64);
            pushf_raw(l, "ip6_src", Some(&ip6[8..24]));
            pushf_raw(l, "ip6_dst", Some(&ip6[24..40]));
            pushf_ip6exthdr(l, ip6, len);
        }
        _ => lj::pushnil(l),
    }
}
pub fn pushf_ip6hdr(l: L, ip6: Option<&[u8]>, len: usize) {
    lj::pushstr(l, "ip6");
    push_ip6hdr(l, ip6, len);
    lj::rawset(l, -3);
}

pub fn push_dissect(l: L, pkt: &[u8], dis: Option<&Dissect>) {
    let g = guard_enter!(l);
    match dis {
        Some(d) => {
            lj::createtable(l, 0, 10 + d.frag as i32);
            pushf_int(l, "l4proto", d.proto as i64);
            pushf_int(l, "transport_len", d.transport_len as i64);
            pushf_int(l, "l3_len", d.len_l3 as i64);
            pushf_int(l, "l4_len", d.len_l4 as i64);
            // data_payload is NULL when no l3 was found
            let pl = if d.has_l3() {
                Some(&pkt[d.payload..d.payload + d.len_payload])
            } else {
                None
            };
            pushf_raw(l, "payload", pl);
            if d.frag {
                pushf_int(l, "frag_off", d.frag_off as i64);
            }
            pushf_iphdr(l, if d.ip { Some(pkt) } else { None }, d.len_l3);
            pushf_ip6hdr(l, if d.ip6 { Some(pkt) } else { None }, d.len_l3);
            pushf_tcphdr(l, d.tcp.map(|o| &pkt[o..]), d.len_l4);
            pushf_udphdr(l, d.udp.map(|o| &pkt[o..]), d.len_l4);
            pushf_icmphdr(l, d.icmp.map(|o| &pkt[o..]), d.len_l4);
        }
        None => lj::pushnil(l),
    }
    guard_leave!(l, g, 1);
}

fn pushf_ctrack_pos(l: L, ipproto: u8, p: &CtrackPosition) {
    pushf_lint(l, "pcounter", p.pcounter as i64);
    pushf_lint(l, "pdcounter", p.pdcounter as i64);
    pushf_lint(l, "pbcounter", p.pbcounter as i64);
    if p.ip6flow != 0 {
        pushf_int(l, "ip6_flow", p.ip6flow as i64);
    }
    if ipproto == IPPROTO_TCP {
        lj::pushstr(l, "tcp");
        lj::createtable(l, 0, 11);
        pushf_lint(l, "seq0", p.seq0 as i64);
        pushf_lint(l, "seq", p.seq_last as i64);
        pushf_lint(l, "rseq", p.seq_last.wrapping_sub(p.seq0) as i64);
        pushf_bool(l, "rseq_over_2G", p.rseq_over_2g);
        pushf_int(l, "pos", p.pos.wrapping_sub(p.seq0) as i64);
        pushf_int(l, "uppos", p.uppos.wrapping_sub(p.seq0) as i64);
        pushf_int(l, "uppos_prev", p.uppos_prev.wrapping_sub(p.seq0) as i64);
        pushf_int(l, "winsize", p.winsize as i64);
        pushf_int(l, "winsize_calc", p.winsize_calc as i64);
        pushf_int(l, "scale", p.scale as i64);
        pushf_int(l, "mss", p.mss as i64);
        lj::rawset(l, -3);
    }
}

pub fn push_ctrack(
    l: L,
    ct: Option<&Ctrack>,
    tpos: Option<&CtrackPositions>,
    incoming: bool,
    server: bool,
) {
    let g = guard_enter!(l);
    match ct {
        Some(c) => {
            let tpos = tpos.unwrap_or(&c.pos);
            lj::createtable(l, 0, 9);
            if c.incoming_ttl != 0 {
                pushf_int(l, "incoming_ttl", c.incoming_ttl as i64);
            }
            pushf_str(l, "l7proto", l7proto_str(c.l7proto).map(str::as_bytes));
            pushf_str(l, "hostname", c.hostname.as_deref());
            if c.hostname.is_some() {
                pushf_bool(l, "hostname_is_ip", c.hostname_is_ip);
            }
            pushf_reg(l, "lua_state", c.lua_state);
            pushf_bool(l, "lua_in_cutoff", c.b_lua_in_cutoff);
            pushf_bool(l, "lua_out_cutoff", c.b_lua_out_cutoff);
            pushf_number(
                l,
                "t_start",
                c.t_start.tv_sec as f64 + c.t_start.tv_nsec as f64 / 1000000000.,
            );
            lj::pushstr(l, "pos");
            lj::createtable(l, 0, 5);
            pushf_number(
                l,
                "dt",
                tpos.t_last.tv_sec as f64 - c.t_start.tv_sec as f64
                    + (tpos.t_last.tv_nsec - c.t_start.tv_nsec) as f64 / 1000000000.,
            );
            lj::pushstr(l, "client");
            lj::newtable(l);
            pushf_ctrack_pos(l, c.pos.ipproto, &tpos.client);
            lj::rawset(l, -3);
            lj::pushstr(l, "server");
            lj::newtable(l);
            pushf_ctrack_pos(l, c.pos.ipproto, &tpos.server);
            lj::rawset(l, -3);
            lj::pushstr(l, "direct");
            lj::getfield(
                l,
                -2,
                if server ^ incoming {
                    "server"
                } else {
                    "client"
                },
            );
            lj::rawset(l, -3);
            lj::pushstr(l, "reverse");
            lj::getfield(
                l,
                -2,
                if server ^ incoming {
                    "client"
                } else {
                    "server"
                },
            );
            lj::rawset(l, -3);
            lj::rawset(l, -3);
        }
        None => lj::pushnil(l),
    }
    guard_leave!(l, g, 1);
}

/// lua_pushf_args. `args` in LIST order.
pub fn pushf_args(l: L, args: &[Str2], idx_desync: i32, subst_prefix: bool) -> bool {
    let g = guard_enter!(l);
    let idx_desync = lj::absindex(l, idx_desync);
    lj::pushstr(l, "arg");
    lj::newtable(l);
    for a in args {
        let var = a.str1.as_deref().unwrap_or("");
        let val = a.str2.as_deref().unwrap_or("");
        let vb = val.as_bytes();
        if subst_prefix {
            if vb.first() == Some(&b'\\') && matches!(vb.get(1), Some(b'%') | Some(b'#')) {
                pushf_str(l, var, Some(&vb[1..]));
            } else if vb.first() == Some(&b'%') {
                if !pushf_blob(l, idx_desync, var, &val[1..]) {
                    lj::pop(l, 2);
                    guard_leave!(l, g, 0);
                    return false;
                }
            } else if vb.first() == Some(&b'#') {
                if !push_blob(l, idx_desync, &val[1..]) {
                    lj::pop(l, 2);
                    guard_leave!(l, g, 0);
                    return false;
                }
                let len = lj::rawlen(l, -1) as i64;
                lj::pop(l, 1);
                lj::pushstr(l, var);
                lj::pushinteger(l, len);
                let _ = lj::tobytes(l, -1);
                lj::rawset(l, -3);
            } else {
                pushf_str(l, var, Some(vb));
            }
        } else {
            pushf_str(l, var, Some(vb));
        }
    }
    lj::rawset(l, -3);
    guard_leave!(l, g, 0);
    true
}

fn pushf_pos(l: L, name: &str, p: &PacketPos) {
    pushf_table(l, name);
    lj::getfield(l, -1, name);
    pushf_str(l, "mode", Some(&[p.mode]));
    pushf_lint(l, "pos", p.pos as i64);
    lj::pop(l, 1);
}
pub fn pushf_range(l: L, name: &str, r: &PacketRange) {
    pushf_table(l, name);
    lj::getfield(l, -1, name);
    pushf_bool(l, "upper_cutoff", r.upper_cutoff);
    pushf_pos(l, "from", &r.from);
    pushf_pos(l, "to", &r.to);
    lj::pop(l, 1);
}

pub struct ReconOpts {
    pub keepsum: bool,
    pub badsum: bool,
    pub ip6_preserve_next: bool,
    pub ip6_last_proto: u8,
}

pub fn reconstruct_extract_options(l: L, idx: i32) -> ReconOpts {
    if lj::isnoneornil(l, idx) {
        return ReconOpts {
            keepsum: false,
            badsum: false,
            ip6_preserve_next: false,
            ip6_last_proto: IPPROTO_NONE,
        };
    }
    lj::checktype(l, idx, lj::LUA_TTABLE);
    let flag = |name: &str| {
        lj::getfield(l, idx, name);
        let t = lj::typ(l, -1);
        let b = t != lj::LUA_TNIL && (t != lj::LUA_TBOOLEAN || lj::toboolean(l, -1));
        lj::pop(l, 1);
        b
    };
    let keepsum = flag("keepsum");
    let badsum = flag("badsum");
    let ip6_preserve_next = flag("ip6_preserve_next");
    lj::getfield(l, idx, "ip6_last_proto");
    let ip6_last_proto = if lj::typ(l, -1) == lj::LUA_TNIL {
        IPPROTO_NONE
    } else {
        lj::tointeger(l, -1) as u8
    };
    lj::pop(l, 1);
    ReconOpts {
        keepsum,
        badsum,
        ip6_preserve_next,
        ip6_last_proto,
    }
}

fn get_num_field(l: L, idx: i32, f: &str) -> Option<i64> {
    lj::getfield(l, idx, f);
    let r = (lj::typ(l, -1) == lj::LUA_TNUMBER).then(|| lj::tointeger(l, -1));
    lj::pop(l, 1);
    r
}
/// Like get_num_field, read with lua_tolint (32-bit header fields).
fn get_lint_field(l: L, idx: i32, f: &str) -> Option<i64> {
    lj::getfield(l, idx, f);
    let r = (lj::typ(l, -1) == lj::LUA_TNUMBER).then(|| lj::tolint(l, -1));
    lj::pop(l, 1);
    r
}
fn get_int_field(l: L, idx: i32, f: &str) -> i64 {
    lj::getfield(l, idx, f);
    let v = lj::tointeger(l, -1);
    lj::pop(l, 1);
    v
}

/// buf: output buffer with buf.len() == C buffer size. Returns used length.
fn reconstruct_ip6exthdr(
    l: L,
    idx: i32,
    buf: &mut [u8],
    proto: u8,
    preserve_next: bool,
) -> Option<usize> {
    let g = guard_enter!(l);
    if buf.len() < IP6_HDR_LEN {
        return None;
    }
    let mut last_proto_pos = 6usize;
    let mut filled = IP6_HDR_LEN;
    lj::getfield(l, idx, "exthdr");
    if lj::typ(l, -1) == lj::LUA_TTABLE {
        let mut i = 0i64;
        let mut data = IP6_HDR_LEN;
        let mut left = buf.len() - filled;
        loop {
            i += 1;
            lj::rawgeti(l, -1, i);
            if lj::typ(l, -1) == lj::LUA_TNIL {
                lj::pop(l, 1);
                break;
            }
            if lj::typ(l, -1) != lj::LUA_TTABLE {
                lj::settop(l, g);
                return None;
            }
            lj::getfield(l, -1, "type");
            if lj::typ(l, -1) != lj::LUA_TNUMBER {
                lj::settop(l, g);
                return None;
            }
            let typ = lj::tointeger(l, -1) as u8;
            lj::pop(l, 1);
            lj::getfield(l, -1, "next");
            let next = if lj::typ(l, -1) == lj::LUA_TNUMBER {
                lj::tointeger(l, -1) as u8
            } else {
                IPPROTO_NONE
            };
            lj::pop(l, 1);
            lj::getfield(l, -1, "data");
            if lj::typ(l, -1) != lj::LUA_TSTRING {
                lj::settop(l, g);
                return None;
            }
            let p = lj::tobytes(l, -1).unwrap_or_default();
            let mut ln = p.len();
            if ln < 6 || ln + 2 > left {
                lj::settop(l, g);
                return None;
            }
            if typ == IPPROTO_AH {
                if ln >= 1024 || (ln + 2) & 3 != 0 {
                    lj::settop(l, g);
                    return None;
                }
                buf[data + 2..data + 2 + ln].copy_from_slice(&p);
                ln += 2;
                buf[data + 1] = ((ln >> 2) - 2) as u8;
            } else {
                if ln >= 2048 || (ln + 2) & 7 != 0 {
                    lj::settop(l, g);
                    return None;
                }
                buf[data + 2..data + 2 + ln].copy_from_slice(&p);
                ln += 2;
                buf[data + 1] = ((ln >> 3) - 1) as u8;
            }
            buf[data] = next;
            if !preserve_next {
                buf[last_proto_pos] = typ;
            }
            last_proto_pos = data;
            left -= ln;
            data += ln;
            filled += ln;
            lj::pop(l, 2);
        }
    }
    if !preserve_next {
        buf[last_proto_pos] = proto;
    }
    lj::pop(l, 1);
    guard_leave!(l, g, 0);
    Some(filled)
}

pub fn reconstruct_ip6hdr(
    l: L,
    idx: i32,
    buf: &mut [u8],
    last_proto: u8,
    preserve_next: bool,
) -> Option<usize> {
    let g = guard_enter!(l);
    if buf.len() < IP6_HDR_LEN || lj::typ(l, idx) != lj::LUA_TTABLE {
        return None;
    }
    let idx = lj::absindex(l, idx);
    lj::getfield(l, idx, "ip6_flow");
    let flow = if lj::typ(l, -1) == lj::LUA_TNUMBER {
        lj::tolint(l, -1) as u32
    } else {
        0x60000000
    };
    buf[0..4].copy_from_slice(&flow.to_be_bytes());
    lj::pop(l, 1);
    buf[6] = get_int_field(l, idx, "ip6_nxt") as u8;
    buf[7] = get_int_field(l, idx, "ip6_hlim") as u8;
    for (f, o) in [("ip6_src", 8usize), ("ip6_dst", 24usize)] {
        lj::getfield(l, idx, f);
        if lj::typ(l, -1) != lj::LUA_TSTRING {
            lj::pop(l, 1);
            guard_leave!(l, g, 0);
            return None;
        }
        match lj::tobytes(l, -1) {
            Some(p) if p.len() == 16 => buf[o..o + 16].copy_from_slice(&p),
            _ => {
                lj::pop(l, 1);
                guard_leave!(l, g, 0);
                return None;
            }
        }
        lj::pop(l, 1);
    }
    let mut have_plen = false;
    lj::getfield(l, idx, "ip6_plen");
    match lj::typ(l, -1) {
        lj::LUA_TNIL => {}
        lj::LUA_TNUMBER => {
            let v = lj::checkinteger(l, -1) as u16;
            buf[4..6].copy_from_slice(&v.to_be_bytes());
            have_plen = true;
        }
        _ => lj::error(l, "reconstruct_ip6hdr: ip6_plen wrong type"),
    }
    lj::pop(l, 1);
    let r = reconstruct_ip6exthdr(l, idx, buf, last_proto, preserve_next);
    if let Some(len) = r {
        if !have_plen {
            buf[4..6].copy_from_slice(&((len - IP6_HDR_LEN) as u16).to_be_bytes());
        }
    }
    guard_leave!(l, g, 0);
    r
}

pub fn reconstruct_iphdr(l: L, idx: i32, buf: &mut [u8]) -> Option<usize> {
    let g = guard_enter!(l);
    if buf.len() < IP_HDR_LEN || lj::typ(l, idx) != lj::LUA_TTABLE {
        return None;
    }
    let fail = |l: L| {
        lj::pop(l, 1);
        guard_leave!(l, g, 0);
        None
    };
    buf[0] = (buf[0] & 0x0F) | 0x40;
    buf[1] = get_int_field(l, idx, "ip_tos") as u8;
    buf[2..4].copy_from_slice(&(get_int_field(l, idx, "ip_len") as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&(get_int_field(l, idx, "ip_id") as u16).to_be_bytes());
    buf[6..8].copy_from_slice(&(get_int_field(l, idx, "ip_off") as u16).to_be_bytes());
    lj::getfield(l, idx, "ip_ttl");
    if lj::typ(l, -1) != lj::LUA_TNUMBER {
        return fail(l);
    }
    buf[8] = lj::tointeger(l, -1) as u8;
    lj::pop(l, 1);
    lj::getfield(l, idx, "ip_p");
    if lj::typ(l, -1) != lj::LUA_TNUMBER {
        return fail(l);
    }
    buf[9] = lj::tointeger(l, -1) as u8;
    lj::pop(l, 1);
    for (f, o) in [("ip_src", 12usize), ("ip_dst", 16usize)] {
        lj::getfield(l, idx, f);
        if lj::typ(l, -1) != lj::LUA_TSTRING {
            return fail(l);
        }
        match lj::tobytes(l, -1) {
            Some(p) if p.len() == 4 => buf[o..o + 4].copy_from_slice(&p),
            _ => return fail(l),
        }
        lj::pop(l, 1);
    }
    let mut lopt = 0usize;
    lj::getfield(l, idx, "options");
    if lj::typ(l, -1) == lj::LUA_TSTRING {
        if let Some(p) = lj::tobytes(l, -1) {
            if !p.is_empty() {
                lopt = p.len();
                if lopt > 40 || IP_HDR_LEN + ((lopt + 3) & !3) > buf.len() {
                    return fail(l);
                }
                buf[IP_HDR_LEN..IP_HDR_LEN + lopt].copy_from_slice(&p);
                let pad = (4 - (lopt & 3)) & 3;
                buf[IP_HDR_LEN + lopt..IP_HDR_LEN + lopt + pad].fill(0);
                lopt = (lopt + 3) & !3;
            }
        }
    }
    lj::pop(l, 1);
    let len = IP_HDR_LEN + lopt;
    buf[0] = (buf[0] & 0xF0) | ((len >> 2) as u8 & 0xF);
    ip4_fix_checksum(&mut buf[..len]);
    guard_leave!(l, g, 0);
    Some(len)
}

fn reconstruct_tcphdr_options(l: L, idx: i32, buf: &mut [u8]) -> Option<usize> {
    if buf.len() < TCP_HDR_LEN {
        return None;
    }
    let g = guard_enter!(l);
    let mut filled = TCP_HDR_LEN as u8;
    lj::getfield(l, idx, "options");
    if lj::typ(l, -1) == lj::LUA_TTABLE {
        let mut i = 0i64;
        let mut data = TCP_HDR_LEN;
        let mut left = (buf.len() - filled as usize).min(40);
        loop {
            i += 1;
            lj::rawgeti(l, -1, i);
            if lj::typ(l, -1) == lj::LUA_TNIL {
                lj::pop(l, 1);
                break;
            }
            if left == 0 || lj::typ(l, -1) != lj::LUA_TTABLE {
                lj::settop(l, g);
                return None;
            }
            lj::getfield(l, -1, "kind");
            if lj::typ(l, -1) != lj::LUA_TNUMBER {
                lj::settop(l, g);
                return None;
            }
            let kind = lj::tointeger(l, -1) as u8;
            lj::pop(l, 1);
            match kind {
                TCP_KIND_END | TCP_KIND_NOOP => {
                    buf[data] = kind;
                    data += 1;
                    left -= 1;
                    filled = filled.wrapping_add(1);
                }
                _ => {
                    lj::getfield(l, -1, "data");
                    let p = if lj::typ(l, -1) == lj::LUA_TSTRING {
                        lj::tobytes(l, -1)
                    } else {
                        None
                    };
                    let ln = p.as_ref().map_or(0, |p| p.len());
                    if 2 + ln > left {
                        lj::settop(l, g);
                        return None;
                    }
                    if let Some(p) = p {
                        buf[data + 2..data + 2 + ln].copy_from_slice(&p);
                    }
                    let ln = ln + 2;
                    buf[data] = kind;
                    buf[data + 1] = ln as u8;
                    left -= ln;
                    data += ln;
                    filled = filled.wrapping_add(ln as u8);
                    lj::pop(l, 1);
                }
            }
            lj::pop(l, 1);
        }
        let pad = ((4 - (filled & 3)) & 3) as usize;
        if left < pad {
            lj::settop(l, g);
            return None;
        }
        buf[data..data + pad].fill(0);
        filled += pad as u8;
    }
    buf[12] = (buf[12] & 0x0F) | ((filled >> 2) << 4);
    lj::pop(l, 1);
    guard_leave!(l, g, 0);
    Some(filled as usize)
}

pub fn reconstruct_tcphdr(l: L, idx: i32, buf: &mut [u8]) -> Option<usize> {
    if buf.len() < TCP_HDR_LEN || lj::typ(l, idx) != lj::LUA_TTABLE {
        return None;
    }
    let g = guard_enter!(l);
    let idx = lj::absindex(l, idx);
    let fail = |l: L| {
        guard_leave!(l, g, 0);
        None
    };
    let Some(v) = get_num_field(l, idx, "th_sport") else {
        return fail(l);
    };
    buf[0..2].copy_from_slice(&(v as u16).to_be_bytes());
    let Some(v) = get_num_field(l, idx, "th_dport") else {
        return fail(l);
    };
    buf[2..4].copy_from_slice(&(v as u16).to_be_bytes());
    let Some(v) = get_lint_field(l, idx, "th_seq") else {
        return fail(l);
    };
    buf[4..8].copy_from_slice(&(v as u32).to_be_bytes());
    let Some(v) = get_lint_field(l, idx, "th_ack") else {
        return fail(l);
    };
    buf[8..12].copy_from_slice(&(v as u32).to_be_bytes());
    let x2 = get_int_field(l, idx, "th_x2") as u8;
    buf[12] = (buf[12] & 0xF0) | (x2 & 0x0F);
    let Some(v) = get_num_field(l, idx, "th_flags") else {
        return fail(l);
    };
    buf[13] = v as u8;
    let Some(v) = get_num_field(l, idx, "th_win") else {
        return fail(l);
    };
    buf[14..16].copy_from_slice(&(v as u16).to_be_bytes());
    buf[16..18].copy_from_slice(&(get_int_field(l, idx, "th_sum") as u16).to_be_bytes());
    buf[18..20].copy_from_slice(&(get_int_field(l, idx, "th_urp") as u16).to_be_bytes());
    buf[12] = (buf[12] & 0x0F) | (5 << 4);
    let r = reconstruct_tcphdr_options(l, idx, buf);
    guard_leave!(l, g, 0);
    r
}

pub fn reconstruct_udphdr(l: L, idx: i32, buf: &mut [u8]) -> bool {
    if lj::typ(l, idx) != lj::LUA_TTABLE {
        return false;
    }
    let Some(v) = get_num_field(l, idx, "uh_sport") else {
        return false;
    };
    buf[0..2].copy_from_slice(&(v as u16).to_be_bytes());
    let Some(v) = get_num_field(l, idx, "uh_dport") else {
        return false;
    };
    buf[2..4].copy_from_slice(&(v as u16).to_be_bytes());
    buf[4..6].copy_from_slice(&(get_int_field(l, idx, "uh_ulen") as u16).to_be_bytes());
    buf[6..8].copy_from_slice(&(get_int_field(l, idx, "uh_sum") as u16).to_be_bytes());
    true
}

pub fn reconstruct_icmphdr(l: L, idx: i32, buf: &mut [u8]) -> bool {
    if lj::typ(l, idx) != lj::LUA_TTABLE {
        return false;
    }
    let Some(v) = get_num_field(l, idx, "icmp_type") else {
        return false;
    };
    buf[0] = v as u8;
    let Some(v) = get_num_field(l, idx, "icmp_code") else {
        return false;
    };
    buf[1] = v as u8;
    let Some(v) = get_lint_field(l, idx, "icmp_data") else {
        return false;
    };
    buf[4..8].copy_from_slice(&(v as u32).to_be_bytes());
    buf[2..4].copy_from_slice(&(get_int_field(l, idx, "icmp_cksum") as u16).to_be_bytes());
    true
}

fn ip6_l4proto_from_dissect(l: L, idx: i32) -> u8 {
    let is_table = |f: &str| {
        lj::getfield(l, idx, f);
        let t = lj::typ(l, -1);
        lj::pop(l, 1);
        t == lj::LUA_TTABLE
    };
    if is_table("tcp") {
        return IPPROTO_TCP;
    }
    if is_table("udp") {
        return IPPROTO_UDP;
    }
    if is_table("icmp") {
        if is_table("ip") {
            return IPPROTO_ICMP;
        }
        if is_table("ip6") {
            return IPPROTO_ICMPV6;
        }
    }
    IPPROTO_NONE
}

/// lua_reconstruct_dissect into `buf` (its length is the C buffer size). Returns packet length.
pub fn reconstruct_dissect(l: L, idx: i32, buf: &mut [u8], o: &ReconOpts) -> Option<usize> {
    let g = guard_enter!(l);
    let idx = lj::absindex(l, idx);
    let mut preserve_next = o.ip6_preserve_next;
    let err = |l: L| {
        lj::settop(l, g);
        None
    };
    lj::getfield(l, idx, "frag_off");
    let frag = if lj::typ(l, -1) != lj::LUA_TNIL {
        lj::checkinteger(l, -1);
        true
    } else {
        false
    };
    lj::pop(l, 1);
    if frag {
        preserve_next = true;
    }
    let mut left = buf.len();
    let (mut is_ip, mut is_ip6) = (false, false);
    lj::getfield(l, idx, "ip");
    let l3;
    if lj::typ(l, -1) == lj::LUA_TTABLE {
        is_ip = true;
        match reconstruct_iphdr(l, -1, &mut buf[..left]) {
            Some(n) => l3 = n,
            None => {
                dlog_err!("reconstruct_dissect: bad ip\n");
                return err(l);
            }
        }
        ip4_fix_checksum(&mut buf[..l3]);
    } else {
        lj::pop(l, 1);
        lj::getfield(l, idx, "ip6");
        if lj::typ(l, -1) != lj::LUA_TTABLE {
            return err(l);
        }
        is_ip6 = true;
        let lp = if o.ip6_last_proto == IPPROTO_NONE {
            ip6_l4proto_from_dissect(l, idx)
        } else {
            o.ip6_last_proto
        };
        match reconstruct_ip6hdr(l, -1, &mut buf[..left], lp, preserve_next) {
            Some(n) => l3 = n,
            None => {
                dlog_err!("reconstruct_dissect: bad ip6\n");
                return err(l);
            }
        }
    }
    let mut data = l3;
    left -= l3;
    lj::pop(l, 1);
    let total;
    if frag {
        lj::getfield(l, idx, "payload");
        if let Some(p) = lj::tobytes(l, -1) {
            if p.len() > 0xFFFF {
                dlog_err!("reconstruct_dissect: payload too large : {}\n", p.len());
                return err(l);
            }
            if left < p.len() {
                dlog_err!("reconstruct_dissect: payload does not fit into the buffer : payload {} buffer_left {}\n", p.len(), left);
                return err(l);
            }
            buf[data..data + p.len()].copy_from_slice(&p);
            data += p.len();
        }
        lj::pop(l, 1);
        total = data;
    } else {
        let (mut tcp, mut udp, mut icmp) = (None, None, None);
        let mut ln = 0usize;
        lj::getfield(l, idx, "tcp");
        if lj::typ(l, -1) == lj::LUA_TTABLE {
            match reconstruct_tcphdr(l, -1, &mut buf[data..data + left]) {
                Some(n) => {
                    ln = n;
                    tcp = Some(data);
                }
                None => {
                    dlog_err!("reconstruct_dissect: bad tcp\n");
                    return err(l);
                }
            }
        } else {
            lj::pop(l, 1);
            lj::getfield(l, idx, "udp");
            if lj::typ(l, -1) == lj::LUA_TTABLE {
                ln = UDP_HDR_LEN;
                if left < ln {
                    dlog_err!("reconstruct_dissect: no space for udp header\n");
                    return err(l);
                }
                if !reconstruct_udphdr(l, -1, &mut buf[data..data + ln]) {
                    dlog_err!("reconstruct_dissect: bad udp\n");
                    return err(l);
                }
                udp = Some(data);
            } else {
                lj::pop(l, 1);
                lj::getfield(l, idx, "icmp");
                if lj::typ(l, -1) == lj::LUA_TTABLE {
                    ln = ICMP_HDR_LEN;
                    if left < ln {
                        dlog_err!("reconstruct_dissect: no space for icmp header\n");
                        return err(l);
                    }
                    if !reconstruct_icmphdr(l, -1, &mut buf[data..data + ln]) {
                        dlog_err!("reconstruct_dissect: bad icmp\n");
                        return err(l);
                    }
                    icmp = Some(data);
                }
            }
        }
        data += ln;
        left -= ln;
        lj::pop(l, 1);
        let mut lpayload = 0usize;
        lj::getfield(l, idx, "payload");
        if let Some(p) = lj::tobytes(l, -1) {
            lpayload = p.len();
            if lpayload > 0xFFFF {
                dlog_err!("reconstruct_dissect: payload too large : {}\n", lpayload);
                return err(l);
            }
            if left < lpayload {
                dlog_err!("reconstruct_dissect: payload does not fit into the buffer : payload {} buffer_left {}\n", lpayload, left);
                return err(l);
            }
            buf[data..data + lpayload].copy_from_slice(&p);
            data += lpayload;
        }
        lj::pop(l, 1);
        let mut len = data;
        if !o.keepsum {
            let (s, d, _) = crate::checksum::l3_addrs(buf, is_ip.then_some(0), is_ip6.then_some(0));
            let addrs = if is_ip {
                L3Addrs::V4(&s[..4], &d[..4])
            } else {
                L3Addrs::V6(&s, &d)
            };
            if let Some(t) = tcp {
                tcp_fix_checksum(&mut buf[t..len], len - l3, addrs);
                if o.badsum {
                    let x = 1 + (random() % 0xFFFF) as u16;
                    let v = pntoh16(&buf[t + 16..]) ^ x.swap_bytes();
                    buf[t + 16..t + 18].copy_from_slice(&v.to_be_bytes());
                }
            } else if let Some(u) = udp {
                let sz = lpayload + UDP_HDR_LEN;
                if sz > 0xFFFF {
                    dlog_err!("reconstruct_dissect: invalid payload length\n");
                    return err(l);
                }
                buf[u + 4..u + 6].copy_from_slice(&(sz as u16).to_be_bytes());
                udp_fix_checksum(&mut buf[u..len], len - l3, addrs);
                if o.badsum {
                    let x = 1 + (random() % 0xFFFF) as u16;
                    let v = pntoh16(&buf[u + 6..]) ^ x.swap_bytes();
                    buf[u + 6..u + 8].copy_from_slice(&v.to_be_bytes());
                }
            } else if let Some(i) = icmp {
                icmp_fix_checksum(
                    &mut buf[i..len],
                    len - l3,
                    if is_ip6 { addrs } else { L3Addrs::None },
                );
                if o.badsum {
                    let x = 1 + (random() % 0xFFFF) as u16;
                    let v = pntoh16(&buf[i + 2..]) ^ x.swap_bytes();
                    buf[i + 2..i + 4].copy_from_slice(&v.to_be_bytes());
                }
            }
        }
        if is_ip {
            let ip_off = pntoh16(&buf[6..]);
            if ip_off & (0x1FFF | 0x2000) != 0 {
                let iplen = pntoh16(&buf[2..]) as usize;
                let off = ((ip_off & 0x1FFF) as usize) << 3;
                let frag_start = l3 + off;
                if iplen < l3 || iplen > len {
                    dlog_err!("ipv4 frag : invalid ip_len\n");
                    return err(l);
                }
                let frag_len = iplen - l3;
                if frag_start + frag_len > len {
                    dlog_err!("ipv4 frag : fragment end is outside of the packet\n");
                    return err(l);
                }
                if off != 0 {
                    buf.copy_within(frag_start..frag_start + frag_len, l3);
                }
                len = iplen;
            } else {
                buf[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            }
            ip4_fix_checksum(&mut buf[..l3]);
        } else if is_ip6 {
            if let Some(fr) = proto_find_ip6_exthdr(&buf[..len], IPPROTO_FRAGMENT) {
                let plen = pntoh16(&buf[4..]) as usize;
                let off = (pntoh16(&buf[fr + 2..]) & 0xFFF8) as usize;
                let endfrag = fr + 8;
                let unfr = endfrag - IP6_HDR_LEN;
                if unfr > plen {
                    dlog_err!("ipv6 frag : invalid ip6_plen\n");
                    return err(l);
                }
                let fragable = plen - unfr;
                if endfrag + off + fragable > data {
                    dlog_err!("ipv6 frag : fragmentable part is outside of the packet\n");
                    return err(l);
                }
                if off != 0 {
                    buf.copy_within(endfrag + off..endfrag + off + fragable, endfrag);
                }
                len = IP6_HDR_LEN + plen;
            } else {
                buf[4..6].copy_from_slice(&((len - IP6_HDR_LEN) as u16).to_be_bytes());
            }
        }
        total = len;
    }
    guard_leave!(l, g, 0);
    Some(total)
}
