//! Port of conntrack.c, conntrack_base.h and packet_queue.c.

use crate::darkmagic::{
    Dissect, IPPROTO_IP, IPPROTO_IPV6, IPPROTO_NONE, IPPROTO_TCP, IPPROTO_UDP, SCALE_NONE, TH_FIN,
    TH_RST, tcp_find_mss, tcp_find_scale_factor, tcp_syn_segment, tcp_synack_segment,
};
use crate::helpers::{SockAddr, boottime, boottime_ts, ntop4, ntop6, pntoh16, pntoh32};
use crate::protocol::{L7_UNKNOWN, L7P_UNKNOWN, l7proto_str};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

pub const CTRACK_T_SYN: u32 = 60;
pub const CTRACK_T_FIN: u32 = 60;
pub const CTRACK_T_EST: u32 = 300;
pub const CTRACK_T_UDP: u32 = 60;

pub const SYN: u8 = 0;
pub const ESTABLISHED: u8 = 1;
pub const FIN: u8 = 2;
const CONNSTATE_S: [&str; 3] = ["SYN", "ESTABLISHED", "FIN"];
pub fn connstate_str(s: u8) -> &'static str {
    CONNSTATE_S[s as usize % 3]
}

pub const RETRANS_COUNTER_STOP: u8 = 0xFF;
pub const RAW_PACKET_QUEUE_DELAYED_MAX: usize = 64;

#[derive(Clone, Copy, Debug, Default)]
pub struct CtrackPosition {
    pub pcounter: u64,
    pub pdcounter: u64,
    pub pbcounter: u64,
    pub ip6flow: u32,
    pub pos: u32,
    pub uppos: u32,
    pub uppos_prev: u32,
    pub seq_last: u32,
    pub seq0: u32,
    pub winsize: u16,
    pub mss: u16,
    pub winsize_calc: u32,
    pub scale: u8,
    pub rseq_over_2g: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct CtrackPositions {
    pub t_last: libc::timespec,
    pub state: u8,
    pub client: CtrackPosition,
    pub server: CtrackPosition,
    pub ipproto: u8,
}

impl Default for CtrackPositions {
    fn default() -> Self {
        CtrackPositions {
            t_last: crate::helpers::timespec(0, 0),
            state: SYN,
            client: CtrackPosition::default(),
            server: CtrackPosition::default(),
            ipproto: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Conn {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub sport: u16,
    pub dport: u16,
    pub l3proto: u8,
    pub l4proto: u8,
}

impl Conn {
    fn swap(&self) -> Conn {
        Conn {
            src: self.dst,
            dst: self.src,
            sport: self.dport,
            dport: self.sport,
            l3proto: self.l3proto,
            l4proto: self.l4proto,
        }
    }
    pub fn addr_str(&self, a: &[u8; 16]) -> String {
        if self.l3proto == IPPROTO_IP {
            ntop4(&a[..4])
        } else if self.l3proto == IPPROTO_IPV6 {
            ntop6(a)
        } else {
            String::new()
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Reassemble {
    pub packet: Vec<u8>,
    pub seq: u32,
    pub size: usize,
    pub size_present: usize,
}

const REASM_MAX_NEG: u32 = 0x100000;

impl Reassemble {
    pub fn clear(&mut self) {
        self.packet = Vec::new();
        self.size = 0;
        self.size_present = 0;
    }
    pub fn init(&mut self, size: usize, seq: u32) -> bool {
        self.packet = vec![0u8; size];
        self.size = size;
        self.size_present = 0;
        self.seq = seq;
        true
    }
    pub fn resize(&mut self, new_size: usize) -> bool {
        if new_size < self.size_present {
            return false;
        }
        self.packet.resize(new_size, 0);
        self.size = new_size;
        true
    }
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }
    pub fn is_full(&self) -> bool {
        !self.is_empty() && self.size == self.size_present
    }
    pub fn has_space(&self, len: usize) -> bool {
        self.size_present + len <= self.size
    }
    pub fn feed(&mut self, seq: u32, payload: &[u8]) -> bool {
        let dseq = seq.wrapping_sub(self.seq);
        if dseq != 0 && dseq < REASM_MAX_NEG {
            return false;
        }
        let mut neg = self.seq.wrapping_sub(seq);
        if neg > REASM_MAX_NEG {
            return false;
        }
        let len = payload.len();
        let szignore = (neg as usize).saturating_sub(self.size_present);
        if szignore >= len {
            return true;
        }
        let szcopy = len - szignore;
        neg -= szignore as u32;
        if self.size_present - neg as usize + szcopy > self.size {
            return false;
        }
        let at = self.size_present - neg as usize;
        self.packet[at..at + szcopy].copy_from_slice(&payload[szignore..]);
        if szcopy > neg as usize {
            self.size_present += szcopy - neg as usize;
            self.seq = self.seq.wrapping_add(szcopy as u32 - neg);
        }
        true
    }
}

#[derive(Clone, Debug)]
pub struct RawPacket {
    pub dst: SockAddr,
    pub ifin: String,
    pub ifout: String,
    pub fwmark_orig: u32,
    pub fwmark: u32,
    pub packet: Vec<u8>,
    pub len_payload: usize,
    pub tpos: Option<CtrackPositions>,
    pub server_side: bool,
}

#[derive(Clone, Debug, Default)]
pub struct RawPacketQueue {
    pub q: VecDeque<RawPacket>,
    pub max_packets: usize,
}

impl RawPacketQueue {
    pub fn new(max: usize) -> Self {
        RawPacketQueue {
            q: VecDeque::new(),
            max_packets: max,
        }
    }
    pub fn push(&mut self, rp: RawPacket) -> bool {
        if self.max_packets != 0 && self.q.len() >= self.max_packets {
            return false;
        }
        self.q.push_back(rp);
        true
    }
    pub fn pop(&mut self) -> Option<RawPacket> {
        self.q.pop_front()
    }
    pub fn count(&self) -> usize {
        self.q.len()
    }
    pub fn is_empty(&self) -> bool {
        self.q.is_empty()
    }
    pub fn clear(&mut self) {
        self.q.clear()
    }
}

/// IFNAMSIZ-limited copy, as snprintf into char[16].
pub fn ifname_copy(s: Option<&str>) -> String {
    let s = s.unwrap_or("");
    let mut e = s.len().min(15);
    while !s.is_char_boundary(e) {
        e -= 1;
    }
    s[..e].to_string()
}

pub struct Ctrack {
    pub b_check_done: bool,
    pub b_check_result: bool,
    pub b_check_excluded: bool,
    pub t_start: libc::timespec,
    pub pos: CtrackPositions,
    pub dp: Option<crate::params::ProfileRef>,
    pub dp_search_complete: bool,
    pub req_retrans_counter: u8,
    pub failure_detect_finalized: bool,
    pub incoming_ttl: u8,
    pub b_cutoff: bool,
    pub b_lua_in_cutoff: bool,
    pub b_lua_out_cutoff: bool,
    pub l7proto: u32,
    pub l7proto_discovered: bool,
    pub hostname: Option<Vec<u8>>,
    pub hostname_is_ip: bool,
    pub hostname_discovered: bool,
    pub hostname_ah_check: bool,
    pub lua_state: i32,
    pub lua_instance_cutoff: i32,
    pub reasm_client_payload: u32,
    pub reasm_client: Reassemble,
    pub delayed: RawPacketQueue,
}

pub type CtrackRef = Rc<RefCell<Ctrack>>;

impl Drop for Ctrack {
    fn drop(&mut self) {
        crate::lua::unref(self.lua_state);
        crate::lua::unref(self.lua_instance_cutoff);
    }
}

impl Ctrack {
    fn new() -> Ctrack {
        Ctrack {
            b_check_done: false,
            b_check_result: false,
            b_check_excluded: false,
            t_start: crate::helpers::timespec(0, 0),
            pos: CtrackPositions::default(),
            dp: None,
            dp_search_complete: false,
            req_retrans_counter: 0,
            failure_detect_finalized: false,
            incoming_ttl: 0,
            b_cutoff: false,
            b_lua_in_cutoff: false,
            b_lua_out_cutoff: false,
            l7proto: L7_UNKNOWN,
            l7proto_discovered: false,
            hostname: None,
            hostname_is_ip: false,
            hostname_discovered: false,
            hostname_ah_check: false,
            lua_state: crate::lua::new_table_ref(),
            lua_instance_cutoff: crate::lua::new_table_ref(),
            reasm_client_payload: L7P_UNKNOWN,
            reasm_client: Reassemble::default(),
            delayed: RawPacketQueue::new(RAW_PACKET_QUEUE_DELAYED_MAX),
        }
    }
    pub fn clear_hostname(&mut self) {
        self.hostname = None;
        self.hostname_is_ip = false;
    }
}

pub fn extract_conn(pkt: &[u8], dis: &Dissect, rev: bool) -> Option<Conn> {
    let mut c = Conn::default();
    if dis.ip {
        c.l3proto = IPPROTO_IP;
        let (s, d) = (&pkt[12..16], &pkt[16..20]);
        c.dst[..4].copy_from_slice(if rev { s } else { d });
        c.src[..4].copy_from_slice(if rev { d } else { s });
    } else if dis.ip6 {
        c.l3proto = IPPROTO_IPV6;
        let (s, d) = (&pkt[8..24], &pkt[24..40]);
        c.dst.copy_from_slice(if rev { s } else { d });
        c.src.copy_from_slice(if rev { d } else { s });
    } else {
        return None;
    }
    let l4 = dis.tcp.or(dis.udp);
    let (sp, dp) = l4.map_or((0, 0), |o| (pntoh16(&pkt[o..]), pntoh16(&pkt[o + 2..])));
    c.l4proto = if dis.tcp.is_some() {
        IPPROTO_TCP
    } else if dis.udp.is_some() {
        IPPROTO_UDP
    } else {
        IPPROTO_NONE
    };
    if rev {
        c.dport = sp;
        c.sport = dp;
    } else {
        c.sport = sp;
        c.dport = dp;
    }
    (c.l4proto != IPPROTO_NONE).then_some(c)
}

#[derive(Default)]
pub struct Conntrack {
    pub timeout_syn: u32,
    pub timeout_established: u32,
    pub timeout_fin: u32,
    pub timeout_udp: u32,
    pub t_purge_interval: i64,
    pub t_last_purge: i64,
    pub pool: crate::pools::IMap<Conn, CtrackRef>,
}

fn apply_pos(t: &mut Ctrack, rev: bool, pkt: &[u8], dis: &Dissect) {
    // INFALLIBLE: called only for tcp packets
    let Some(to) = dis.tcp else { return };
    let tcp = &pkt[to..];
    let state = t.pos.state;
    let flow = if dis.ip6 { Some(pntoh32(pkt)) } else { None };
    let (direct, reverse) = if rev {
        (&mut t.pos.server, &mut t.pos.client)
    } else {
        (&mut t.pos.client, &mut t.pos.server)
    };
    if let Some(f) = flow {
        direct.ip6flow = f;
    }
    direct.winsize = pntoh16(&tcp[14..]);
    direct.winsize_calc = direct.winsize as u32;
    if state == SYN {
        let scale = tcp_find_scale_factor(tcp);
        if scale != SCALE_NONE {
            direct.scale = scale.min(14);
        }
        direct.mss = tcp_find_mss(tcp);
    } else {
        direct.winsize_calc = direct.winsize_calc.wrapping_shl(direct.scale as u32);
    }
    direct.seq_last = pntoh32(&tcp[4..]);
    direct.pos = direct.seq_last.wrapping_add(dis.len_payload as u32);
    reverse.seq_last = pntoh32(&tcp[8..]);
    reverse.pos = reverse.seq_last;
    if state == SYN {
        direct.uppos = direct.pos;
        direct.uppos_prev = direct.pos;
    } else if dis.len_payload != 0 {
        direct.uppos_prev = direct.uppos;
        if direct.pos.wrapping_sub(direct.uppos) & 0x80000000 == 0 {
            direct.uppos = direct.pos;
        }
    }
    if !direct.rseq_over_2g && direct.seq_last.wrapping_sub(direct.seq0) & 0x80000000 != 0 {
        direct.rseq_over_2g = true;
    }
    if !reverse.rseq_over_2g && reverse.seq_last.wrapping_sub(reverse.seq0) & 0x80000000 != 0 {
        reverse.rseq_over_2g = true;
    }
}

fn feed_packet(t: &mut Ctrack, rev: bool, pkt: &[u8], dis: &Dissect) {
    if let Some(to) = dis.tcp {
        let tcp = &pkt[to..];
        if tcp_syn_segment(tcp) {
            if t.pos.state != SYN {
                *t = Ctrack::new();
            }
            t.pos.client.seq0 = pntoh32(&tcp[4..]);
        } else if tcp_synack_segment(tcp) {
            let seq0 = pntoh32(&tcp[8..]).wrapping_sub(1);
            if t.pos.state != SYN && t.pos.client.seq0 != seq0 {
                *t = Ctrack::new();
            }
            if t.pos.client.seq0 == 0 {
                t.pos.client.seq0 = seq0;
            }
            t.pos.server.seq0 = pntoh32(&tcp[4..]);
        } else if tcp[13] & (TH_FIN | TH_RST) != 0 {
            t.pos.state = FIN;
        } else if t.pos.state == SYN {
            t.pos.state = ESTABLISHED;
            if !rev && t.pos.server.seq0 == 0 {
                t.pos.server.seq0 = pntoh32(&tcp[8..]).wrapping_sub(1);
            }
        }
        apply_pos(t, rev, pkt, dis);
    }
    let p = if rev {
        &mut t.pos.server
    } else {
        &mut t.pos.client
    };
    p.pcounter += 1;
    p.pdcounter += (dis.len_payload != 0) as u64;
    p.pbcounter += dis.len_payload as u64;
    t.pos.t_last = boottime_ts();
    if t.t_start.tv_sec == 0 {
        t.t_start = t.pos.t_last;
    }
}

impl Conntrack {
    pub fn init(&mut self, purge_interval: i64, syn: u32, est: u32, fin: u32, udp: u32) {
        self.timeout_syn = syn;
        self.timeout_established = est;
        self.timeout_fin = fin;
        self.timeout_udp = udp;
        self.t_purge_interval = purge_interval;
        self.t_last_purge = boottime();
        self.pool.clear();
    }

    pub fn double_search(&self, pkt: &[u8], dis: &Dissect) -> Option<(CtrackRef, bool)> {
        let c = extract_conn(pkt, dis, false)?;
        if let Some(t) = self.pool.get(&c) {
            return Some((t.clone(), false));
        }
        self.pool.get(&c.swap()).map(|t| (t.clone(), true))
    }

    pub fn feed(&mut self, pkt: &[u8], dis: &Dissect) -> Option<(CtrackRef, bool)> {
        let proto = if dis.tcp.is_some() {
            IPPROTO_TCP
        } else if dis.udp.is_some() {
            IPPROTO_UDP
        } else {
            IPPROTO_NONE
        };
        let conn = extract_conn(pkt, dis, false)?;
        let swp = conn.swap();
        let (t, rev) = match self.pool.get(&conn).cloned() {
            Some(t) => {
                feed_packet(&mut t.borrow_mut(), false, pkt, dis);
                (t, false)
            }
            _ => match self.pool.get(&swp).cloned() {
                Some(t) => {
                    feed_packet(&mut t.borrow_mut(), true, pkt, dis);
                    (t, true)
                }
                _ => {
                    let tcp = dis.tcp.map(|o| &pkt[o..]);
                    let b_rev = tcp.is_some_and(tcp_synack_segment);
                    if tcp.is_some_and(tcp_syn_segment) || b_rev || dis.udp.is_some() {
                        let t = Rc::new(RefCell::new(Ctrack::new()));
                        self.pool.insert(if b_rev { swp } else { conn }, t.clone());
                        feed_packet(&mut t.borrow_mut(), b_rev, pkt, dis);
                        (t, b_rev)
                    } else {
                        return None;
                    }
                }
            },
        };
        t.borrow_mut().pos.ipproto = proto;
        Some((t, rev))
    }

    pub fn drop_conn(&mut self, pkt: &[u8], dis: &Dissect) -> bool {
        let Some(c) = extract_conn(pkt, dis, false) else {
            return false;
        };
        if self.pool.shift_remove(&c).is_some() {
            return true;
        }
        self.pool.shift_remove(&c.swap()).is_some()
    }

    pub fn purge(&mut self) {
        let tnow = boottime();
        if tnow == 0 {
            return;
        }
        if tnow - self.t_last_purge >= self.t_purge_interval {
            let (syn, est, fin, udp) = (
                self.timeout_syn as i64,
                self.timeout_established as i64,
                self.timeout_fin as i64,
                self.timeout_udp as i64,
            );
            self.pool.retain(|c, t| {
                let t = t.borrow();
                let tidle = tnow - t.pos.t_last.tv_sec as i64;
                let del = t.b_cutoff
                    || (c.l4proto == IPPROTO_TCP
                        && ((t.pos.state == SYN && tidle >= syn)
                            || (t.pos.state == ESTABLISHED && tidle >= est)
                            || (t.pos.state == FIN && tidle >= fin)))
                    || (c.l4proto == IPPROTO_UDP && tidle >= udp);
                !del
            });
            self.t_last_purge = tnow;
        }
    }

    pub fn dump(&self) -> String {
        let tnow = boottime();
        let mut s = String::new();
        if tnow == 0 {
            return s;
        }
        for (c, t) in &self.pool {
            let t = t.borrow();
            let p = &t.pos;
            s += &format!(
                "{} [{}]:{} => [{}]:{} : {} : t0={} last=t0+{} now=last+{} client=d{}/n{}/b{} server=d{}/n{}/b{} ",
                crate::darkmagic::proto_name(c.l4proto).unwrap_or("(null)"),
                c.addr_str(&c.src),
                c.sport,
                c.addr_str(&c.dst),
                c.dport,
                if c.l4proto == IPPROTO_TCP {
                    connstate_str(p.state)
                } else {
                    "-"
                },
                t.t_start.tv_sec as u64,
                (p.t_last.tv_sec - t.t_start.tv_sec) as u64,
                (tnow - p.t_last.tv_sec as i64) as u64,
                p.client.pdcounter,
                p.client.pcounter,
                p.client.pbcounter,
                p.server.pdcounter,
                p.server.pcounter,
                p.server.pbcounter
            );
            if c.l4proto == IPPROTO_TCP {
                s += &format!(
                    "seq0={} rseq={} client.pos={} ack0={} rack={} server.pos={} client.mss={} server.mss={} client.wsize={}:{} server.wsize={}:{}",
                    p.client.seq0,
                    p.client.seq_last.wrapping_sub(p.client.seq0),
                    p.client.pos.wrapping_sub(p.client.seq0),
                    p.server.seq0,
                    p.server.seq_last.wrapping_sub(p.server.seq0),
                    p.server.pos.wrapping_sub(p.server.seq0),
                    p.client.mss,
                    p.server.mss,
                    p.client.winsize,
                    p.client.scale,
                    p.server.winsize,
                    p.server.scale
                );
            } else {
                s += &format!(
                    "rseq={} client.pos={} rack={} server.pos={}",
                    p.client.seq_last, p.client.pos, p.server.seq_last, p.server.pos
                );
            }
            s += &format!(
                " req_retrans={} cutoff={} lua_in_cutoff={} lua_out_cutoff={} hostname={} l7proto={}\n",
                t.req_retrans_counter,
                t.b_cutoff as u8,
                t.b_lua_in_cutoff as u8,
                t.b_lua_out_cutoff as u8,
                t.hostname
                    .as_deref()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default(),
                l7proto_str(t.l7proto).unwrap_or("(null)")
            );
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reasm() {
        let mut r = Reassemble::default();
        r.init(10, 100);
        assert!(r.feed(100, b"abcd"));
        assert!(r.feed(102, b"cdef"));
        assert_eq!(r.size_present, 6);
        assert!(!r.feed(200, b"x"));
        assert!(r.feed(106, b"ghij"));
        assert!(r.is_full());
        assert_eq!(&r.packet, b"abcdefghij");
    }
}
