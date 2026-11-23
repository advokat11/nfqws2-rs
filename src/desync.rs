//! Port of desync.c: per-packet decision engine (profile matching, reassembly, Lua desync).

use crate::checksum::{ip4_fix_checksum, tcp_fix_checksum_addrs};
use crate::conntrack::{
    CtrackPosition, CtrackPositions, CtrackRef, RETRANS_COUNTER_STOP, RawPacket, RawPacketQueue,
    SYN,
};
use crate::darkmagic::*;
use crate::helpers::*;
use crate::hostlist::{hostlist_check, hostlists_reload_check_for_profile, ipset_check};
use crate::log::{debug, dlog_perror, hexdump_limited_dlog, hostlist_debuglog_append};
use crate::lua::lj;
use crate::lua::push::*;
use crate::params::{
    FASTPATH_WORKAROUND_AUTO, FASTPATH_WORKAROUND_OFF, FASTPATH_WORKAROUND_ON, ProfileRef,
    RECONSTRUCT_MAX_SIZE, params,
};
use crate::pools::{hostfail_pool_add, hostfail_pool_purge_rate_limited, hostlist_pool_add};
use crate::protocol::*;
use crate::{dlog, dlog_err};

const PKTDATA_MAXDUMP: usize = 32;
const TCP_MAX_REASM: usize = 16384;
const UDP_MAX_REASM: usize = 16384;

type Check = fn(&[u8]) -> bool;
struct Probe {
    l7p: u32,
    l7: u32,
    check: Check,
    l7match: bool,
}

fn protocol_probe(
    probes: &[Probe],
    data: &[u8],
    ctrack: Option<&CtrackRef>,
    l7proto: &mut u32,
    l7payload: &mut u32,
) {
    let pd = params().payload_disable;
    for p in probes {
        if !l7_payload_match(p.l7p, pd) && (!p.l7match || *l7proto == p.l7) && (p.check)(data) {
            *l7payload = p.l7p;
            if *l7proto == L7_UNKNOWN {
                *l7proto = p.l7;
                if let Some(c) = ctrack {
                    let mut c = c.borrow_mut();
                    if c.l7proto == L7_UNKNOWN {
                        c.l7proto = *l7proto;
                    }
                }
            }
            dlog!(
                "packet contains {} payload\n",
                l7payload_str(*l7payload).unwrap_or("(null)")
            );
            break;
        }
    }
}

fn tls_debug_handshake(tls: &[u8]) {
    if !debug() || tls.len() < 6 {
        return;
    }
    let server = is_tls_handshake_server_hello(tls, true);
    dlog!(
        "TLS handshake version : {}\n",
        tls_version_str(pntoh16(&tls[4..]))
    );
    if let Some((e, len)) = tls_find_ext_in_handshake(tls, 43, false) {
        let ext = &tls[e..e + len];
        if server {
            if len >= 2 {
                dlog!(
                    "TLS supported versions ext : {}\n",
                    tls_version_str(pntoh16(ext))
                );
            }
        } else if len > 0 {
            let mut l2 = ext[0] as usize;
            if l2 < len {
                l2 &= !1;
                let mut o = 1;
                while l2 > 0 {
                    dlog!(
                        "TLS supported versions ext : {}\n",
                        tls_version_str(pntoh16(&ext[o..]))
                    );
                    l2 -= 2;
                    o += 2;
                }
            }
        }
    } else {
        dlog!("TLS supported versions ext : not present\n");
    }
    if !server {
        if let Some((e, len)) = tls_find_ext_in_handshake(tls, 16, false) {
            let ext = &tls[e..e + len];
            if len >= 2 {
                let mut l2 = pntoh16(ext) as usize;
                if l2 <= len - 2 {
                    let mut o = 2;
                    while l2 > 0 {
                        let v = ext[o] as usize;
                        o += 1;
                        l2 -= 1;
                        if v <= l2 {
                            let v2 = v.min(31);
                            let s = &ext[o..o + v2];
                            let s = &s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())];
                            dlog!("TLS ALPN ext : {}\n", String::from_utf8_lossy(s));
                            l2 -= v;
                            o += v;
                        } else {
                            break;
                        }
                    }
                }
            }
        } else {
            dlog!("TLS ALPN ext : not present\n");
        }
        dlog!(
            "TLS ECH ext : {}\n",
            if tls_find_ext_in_handshake(tls, 65037, false).is_some() {
                "present"
            } else {
                "not present"
            }
        );
    }
}

fn tls_debug(tls: &[u8]) {
    if !debug() || tls.len() < 11 {
        return;
    }
    dlog!(
        "TLS record layer version : {}\n",
        tls_version_str(pntoh16(&tls[1..]))
    );
    let mut sz = tls.len();
    let rl = tls_record_len(tls);
    if rl < sz {
        sz = rl;
    }
    tls_debug_handshake(&tls[5..sz]);
}

pub fn packet_debug(replay: bool, pkt: &[u8], dis: &Dissect) {
    if !debug() {
        return;
    }
    if replay {
        dlog!("REPLAY ");
    }
    if dis.ip {
        dlog!("IP4: {}", str_ip(pkt));
    } else if dis.ip6 {
        dlog!("IP6: {}", trunc(str_ip6hdr(pkt, dis.proto), 128));
    }
    let pl = &pkt[dis.payload..dis.payload + dis.len_payload];
    if let Some(t) = dis.tcp {
        dlog!(" {}\n", str_tcphdr(&pkt[t..]));
        if dis.len_payload != 0 {
            dlog!("TCP: len={} : ", dis.len_payload);
            hexdump_limited_dlog(pl, PKTDATA_MAXDUMP);
            dlog!("\n");
        }
    } else if let Some(u) = dis.udp {
        dlog!(" {}\n", str_udphdr(&pkt[u..]));
        if dis.len_payload != 0 {
            dlog!("UDP: len={} : ", dis.len_payload);
            hexdump_limited_dlog(pl, PKTDATA_MAXDUMP);
            dlog!("\n");
        }
    } else if let Some(i) = dis.icmp {
        dlog!(
            " {}\nICMP: len={} : ",
            trunc(str_icmphdr_full(dis.ip6, &pkt[i..]), 72),
            dis.len_payload
        );
        hexdump_limited_dlog(pl, PKTDATA_MAXDUMP);
        dlog!("\n");
    } else if dis.len_payload != 0 {
        let sp = trunc(str_proto_name(dis.proto), 16);
        if dis.frag {
            dlog!(
                "\nIP FRAG off={} PROTO {}: len={} : ",
                dis.frag_off,
                sp,
                dis.len_payload
            );
        } else {
            dlog!("\nIP PROTO {}: len={} : ", sp, dis.len_payload);
        }
        hexdump_limited_dlog(pl, PKTDATA_MAXDUMP);
        dlog!("\n");
    } else {
        dlog!("\n");
    }
}

#[derive(Clone, Copy, Default)]
struct CheckState {
    done: bool,
    result: bool,
    excluded: bool,
}

#[allow(clippy::too_many_arguments)]
struct MatchData<'a> {
    ip: Option<&'a [u8; 4]>,
    ip6: Option<&'a [u8; 16]>,
    ipr: Option<&'a [u8; 4]>,
    ipr6: Option<&'a [u8; 16]>,
    hostname: Option<&'a [u8]>,
    ssid: Option<&'a [u8]>,
    l7proto: u32,
    fwmark: u32,
    port: u16,
    icmp_type: u8,
    icmp_code: u8,
    no_subdom: bool,
    l3proto: u8,
}

fn dp_match(dp: &ProfileRef, m: &MatchData, cs: Option<&mut CheckState>) -> bool {
    let mut cs = cs;
    if let Some(c) = cs.as_deref_mut() {
        c.done = false;
    }
    let d = dp.borrow();
    if (m.fwmark & d.filter_mark_mask) != d.filter_mark {
        return false;
    }
    if (m.ip.is_some() && !d.filter_ipv4) || (m.ip6.is_some() && !d.filter_ipv6) {
        return false;
    }
    if !l7_proto_match(m.l7proto, d.filter_l7) {
        return false;
    }
    let ok = match m.l3proto {
        IPPROTO_TCP => d.pf_tcp.matches(m.port),
        IPPROTO_UDP => d.pf_udp.matches(m.port),
        IPPROTO_ICMP | IPPROTO_ICMPV6 => d.icf.matches(m.icmp_type, m.icmp_code),
        p => d.ipf.matches(p),
    };
    if !ok {
        return false;
    }
    if !d.filter_ssid.is_empty() {
        let found = m
            .ssid
            .is_some_and(|s| d.filter_ssid.iter().any(|x| x.as_bytes() == s));
        if !found ^ d.filter_ssid_neg {
            return false;
        }
    }
    if !hostlists_reload_check_for_profile(&d) {
        return false;
    }
    let hl_empty = d.hostlists_empty();
    if d.hostlist_auto.is_none() && m.hostname.is_none() && !hl_empty {
        return false;
    }
    if !ipset_check(&d, m.ip, m.ip6, m.ipr, m.ipr6) {
        return false;
    }
    if d.hostlist_auto.is_some() && m.hostname.is_some() {
        dlog!(
            "autohostlist profile {} ({}) wins because hostname is known\n",
            d.n,
            d.name_str()
        );
        return true;
    }
    if hl_empty {
        return true;
    }
    if let Some(h) = m.hostname {
        let mut excl = false;
        let b = hostlist_check(&d, h, m.no_subdom, &mut excl, true);
        if let Some(c) = cs {
            c.done = true;
            c.result = b;
            c.excluded = excl;
        }
        return b;
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn dp_find(
    l3proto: u8,
    ip: Option<&[u8; 4]>,
    ip6: Option<&[u8; 16]>,
    ipr: Option<&[u8; 4]>,
    ipr6: Option<&[u8; 16]>,
    port: u16,
    icmp_type: u8,
    icmp_code: u8,
    hostname: Option<&[u8]>,
    no_subdom: bool,
    l7proto: u32,
    ssid: Option<&[u8]>,
    fwmark: u32,
    mut cs: Option<&mut CheckState>,
) -> Option<ProfileRef> {
    let m = MatchData {
        ip,
        ip6,
        ipr,
        ipr6,
        hostname,
        ssid,
        l7proto,
        fwmark,
        port,
        icmp_type,
        icmp_code,
        no_subdom,
        l3proto,
    };
    if debug() {
        let s = ntopa46(ip.map(|a| &a[..]), ip6.map(|a| &a[..]));
        let sp = trunc(str_proto_name(l3proto), 16);
        let ssid_s = ssid
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default();
        let hn = hostname
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default();
        let l7 = l7proto_str(l7proto).unwrap_or("(null)");
        if ipr.is_some() || ipr6.is_some() {
            let sr = ntopa46(ipr.map(|a| &a[..]), ipr6.map(|a| &a[..]));
            dlog!(
                "desync profile search for {} ip1={} ip2={} port={} icmp={}:{} l7proto={} ssid='{}' mark=0x{:08X} hostname='{}'\n",
                sp,
                s,
                sr,
                port,
                icmp_type,
                icmp_code,
                l7,
                ssid_s,
                fwmark,
                hn
            );
        } else {
            dlog!(
                "desync profile search for {} ip={} port={} icmp={}:{} l7proto={} ssid='{}' mark=0x{:08X} hostname='{}'\n",
                sp,
                s,
                port,
                icmp_type,
                icmp_code,
                l7,
                ssid_s,
                fwmark,
                hn
            );
        }
    }
    if let Some(c) = cs.as_deref_mut() {
        c.done = false;
    }
    let profiles = params().desync_profiles.borrow().clone();
    for dp in &profiles {
        if dp_match(dp, &m, cs.as_deref_mut()) {
            let d = dp.borrow();
            dlog!("desync profile {} ({}) matches\n", d.n, d.name_str());
            return Some(dp.clone());
        }
    }
    dlog!("desync profile not found\n");
    None
}

fn ctrack_stop_retrans_counter(ct: Option<&CtrackRef>) {
    if let Some(c) = ct {
        let mut c = c.borrow_mut();
        if c.hostname_ah_check {
            c.req_retrans_counter = RETRANS_COUNTER_STOP;
        }
    }
}

fn hs(h: &[u8]) -> String {
    String::from_utf8_lossy(h).into_owned()
}
fn l7s(l: u32) -> &'static str {
    l7proto_str(l).unwrap_or("(null)")
}

fn auto_hostlist_reset_fail_counter(
    dp: &ProfileRef,
    hostname: Option<&[u8]>,
    client: &str,
    l7proto: u32,
) {
    let Some(h) = hostname else { return };
    let mut d = dp.borrow_mut();
    if d.hostlist_auto_fail_counters.shift_remove(h).is_some() {
        dlog!(
            "auto hostlist (profile {} ({})) : {} : fail counter reset. website is working.\n",
            d.n,
            d.name_str(),
            hs(h)
        );
        hostlist_debuglog_append(&format!(
            "{} : profile {} ({}) : client {} : proto {} : fail counter reset. website is working.",
            hs(h),
            d.n,
            d.name_str(),
            client,
            l7s(l7proto)
        ));
    }
}

fn is_retransmission(p: &CtrackPosition) -> bool {
    p.uppos_prev.wrapping_sub(p.pos) & 0x80000000 == 0
}

#[allow(clippy::too_many_arguments)]
fn auto_hostlist_retrans(
    ct: &CtrackRef,
    pkt: &[u8],
    dis: &Dissect,
    threshold: i32,
    client_ip_port: &str,
    l7proto: u32,
    client: &SockAddr,
    ifclient: Option<&str>,
) -> bool {
    let (dp, ok) = {
        let c = ct.borrow();
        (
            c.dp.clone(),
            c.hostname_ah_check
                && !c.failure_detect_finalized
                && c.req_retrans_counter != RETRANS_COUNTER_STOP,
        )
    };
    let Some(dp) = dp else { return false };
    if !ok {
        return false;
    }
    if dis.proto == IPPROTO_TCP && ct.borrow().pos.state != SYN {
        let (seq_last, seq0) = {
            let c = ct.borrow();
            (c.pos.client.seq_last, c.pos.client.seq0)
        };
        let maxseq = dp.borrow().hostlist_auto_retrans_maxseq;
        if !seq_within(seq_last, seq0, seq0.wrapping_add(maxseq)) {
            ct.borrow_mut().failure_detect_finalized = true;
            dlog!(
                "retrans : tcp seq {} not within range {}-{}. stop tracking.\n",
                seq_last,
                seq0,
                seq0.wrapping_add(maxseq)
            );
            ctrack_stop_retrans_counter(Some(ct));
            let h = ct.borrow().hostname.clone();
            auto_hostlist_reset_fail_counter(&dp, h.as_deref(), client_ip_port, l7proto);
            return false;
        }
        if !is_retransmission(&ct.borrow().pos.client) {
            return false;
        }
    }
    let cnt = {
        let mut c = ct.borrow_mut();
        c.req_retrans_counter = c.req_retrans_counter.wrapping_add(1);
        c.req_retrans_counter
    };
    if cnt as i32 >= threshold {
        dlog!("retrans threshold reached : {}/{}\n", cnt, threshold);
        ctrack_stop_retrans_counter(Some(ct));
        ct.borrow_mut().failure_detect_finalized = true;
        let reset = dp.borrow().hostlist_auto_retrans_reset;
        if let Some(to) = dis.tcp
            && reset
            && (dis.ip || dis.ip6)
        {
            let (srv_flow, srv_win) = {
                let c = ct.borrow();
                (c.pos.server.ip6flow, c.pos.server.winsize)
            };
            let mut p;
            let l3;
            if dis.ip {
                l3 = 20;
                p = vec![0u8; 40];
                p[..20].copy_from_slice(&pkt[..20]);
                p[0] = (p[0] & 0xF0) | 5;
                p[2..4].copy_from_slice(&40u16.to_be_bytes());
                p[4] = 0;
                p[5] = 0;
                p[20..40].copy_from_slice(&pkt[to..to + 20]);
                // reverse_ip + checksum
                let (s, d) = (p[12..16].to_vec(), p[16..20].to_vec());
                p[12..16].copy_from_slice(&d);
                p[16..20].copy_from_slice(&s);
                ip4_fix_checksum(&mut p[..20]);
            } else {
                l3 = 40;
                p = vec![0u8; 60];
                p[..40].copy_from_slice(&pkt[..40]);
                p[4..6].copy_from_slice(&20u16.to_be_bytes());
                p[6] = IPPROTO_TCP;
                let f = if srv_flow != 0 { srv_flow } else { 0x60000000 };
                p[0..4].copy_from_slice(&f.to_be_bytes());
                p[40..60].copy_from_slice(&pkt[to..to + 20]);
                let (s, d) = (p[8..24].to_vec(), p[24..40].to_vec());
                p[8..24].copy_from_slice(&d);
                p[24..40].copy_from_slice(&s);
            }
            // reverse_tcp
            let t = l3;
            let (sp, dp_) = (p[t..t + 2].to_vec(), p[t + 2..t + 4].to_vec());
            p[t..t + 2].copy_from_slice(&dp_);
            p[t + 2..t + 4].copy_from_slice(&sp);
            let (sq, ak) = (p[t + 4..t + 8].to_vec(), p[t + 8..t + 12].to_vec());
            p[t + 4..t + 8].copy_from_slice(&ak);
            p[t + 8..t + 12].copy_from_slice(&sq);
            p[t + 12] = (p[t + 12] & 0x0F) | (5 << 4);
            p[t + 13] = TH_RST;
            p[t + 14..t + 16].copy_from_slice(&srv_win.to_be_bytes());
            let (s, d) = if l3 == 20 {
                (p[12..16].to_vec(), p[16..20].to_vec())
            } else {
                (p[8..24].to_vec(), p[24..40].to_vec())
            };
            tcp_fix_checksum_addrs(&mut p[t..t + 20], 20, &s, &d);
            dlog!(
                "sending RST to retransmitter. ifname={}\n",
                ifclient.unwrap_or("")
            );
            rawsend(client, 0, ifclient, &p);
        }
        return true;
    }
    dlog!("retrans counter : {}/{}\n", cnt, threshold);
    false
}

fn auto_hostlist_failed(
    dp: &ProfileRef,
    hostname: &[u8],
    no_subdom: bool,
    client: &str,
    l7proto: u32,
) {
    let (n, name, thr, counter) = {
        let mut d = dp.borrow_mut();
        let ft = d.hostlist_auto_fail_time;
        if !d.hostlist_auto_fail_counters.contains_key(hostname) {
            hostfail_pool_add(&mut d.hostlist_auto_fail_counters, hostname, ft);
        }
        let c = {
            // INFALLIBLE: present after the insert above
            let e = d
                .hostlist_auto_fail_counters
                .get_mut(hostname)
                .expect("fail counter");
            e.counter += 1;
            e.counter
        };
        (
            d.n,
            d.name_str().to_string(),
            d.hostlist_auto_fail_threshold,
            c,
        )
    };
    dlog!(
        "auto hostlist (profile {} ({})) : {} : fail counter {}/{}\n",
        n,
        name,
        hs(hostname),
        counter,
        thr
    );
    hostlist_debuglog_append(&format!(
        "{} : profile {} ({}) : client {} : proto {} : fail counter {}/{}",
        hs(hostname),
        n,
        name,
        client,
        l7s(l7proto),
        counter,
        thr
    ));
    if counter >= thr {
        dlog!(
            "auto hostlist (profile {} ({})) : fail threshold reached. about to add {} to auto hostlist\n",
            n,
            name,
            hs(hostname)
        );
        dp.borrow_mut()
            .hostlist_auto_fail_counters
            .shift_remove(hostname);
        dlog!(
            "auto hostlist (profile {} ({})) : rechecking {} to avoid duplicates\n",
            n,
            name,
            hs(hostname)
        );
        let mut excl = false;
        let chk = hostlist_check(&dp.borrow(), hostname, no_subdom, &mut excl, false);
        let ha = dp.borrow().hostlist_auto.clone();
        // INFALLIBLE: auto hostlist failure tracking runs only for profiles with an autohostlist
        let Some(ha) = ha else { return };
        let fname = ha.borrow().filename.clone().unwrap_or_default();
        if !chk && !excl {
            dlog!(
                "auto hostlist (profile {}) : adding {} to {}\n",
                n,
                hs(hostname),
                fname
            );
            hostlist_debuglog_append(&format!(
                "{} : profile {} ({}) : client {} : proto {} : adding to {}",
                hs(hostname),
                n,
                name,
                client,
                l7s(l7proto),
                fname
            ));
            {
                let mut h = ha.borrow_mut();
                hostlist_pool_add(h.hostlist.get_or_insert_with(Default::default), hostname, 0);
            }
            if !append_to_list_file(&fname, hostname) {
                dlog_perror("write to auto hostlist");
                return;
            }
            match file_mod_signature(&fname) {
                Some(s) => ha.borrow_mut().mod_sig = s,
                None => {
                    ha.borrow_mut().mod_sig = FileModSig::default();
                    dlog_perror("file_mod_signature");
                }
            }
        } else {
            dlog!(
                "auto hostlist (profile {}) : NOT adding {}\n",
                n,
                hs(hostname)
            );
            hostlist_debuglog_append(&format!(
                "{} : profile {} ({}) : client {} : proto {} : NOT adding, duplicate detected",
                hs(hostname),
                n,
                name,
                client,
                l7s(l7proto)
            ));
        }
    }
}

fn fill_client_ip_port(client: &SockAddr) -> String {
    let dl = crate::log::LOG.with(|l| !l.borrow().hostlist_auto_debuglog.is_empty());
    if dl {
        trunc(client.ntop_port(), 48)
    } else {
        String::new()
    }
}

fn process_retrans_fail(
    ct: Option<&CtrackRef>,
    pkt: &[u8],
    dis: &Dissect,
    client: &SockAddr,
    ifclient: Option<&str>,
) {
    if params().server {
        return;
    }
    let cip = fill_client_ip_port(client);
    let Some(ct) = ct else { return };
    let (dp, host, l7, hip) = {
        let c = ct.borrow();
        (
            c.dp.clone(),
            c.hostname.clone(),
            c.l7proto,
            c.hostname_is_ip,
        )
    };
    let (Some(dp), Some(host)) = (dp, host) else {
        return;
    };
    let thr = dp.borrow().hostlist_auto_retrans_threshold;
    if auto_hostlist_retrans(ct, pkt, dis, thr, &cip, l7, client, ifclient) {
        let (n, name) = {
            let d = dp.borrow();
            (d.n, d.name_str().to_string())
        };
        hostlist_debuglog_append(&format!(
            "{} : profile {} ({}) : client {} : proto {} : retrans threshold reached",
            hs(&host),
            n,
            name,
            cip,
            l7s(l7)
        ));
        auto_hostlist_failed(&dp, &host, hip, &cip, l7);
    }
}

fn process_udp_fail(ct: &CtrackRef, tpos: Option<&CtrackPositions>, client: &SockAddr) {
    if params().server {
        return;
    }
    let (dp, host, ah, fin, l7, hip, cpos) = {
        let c = ct.borrow();
        (
            c.dp.clone(),
            c.hostname.clone(),
            c.hostname_ah_check,
            c.failure_detect_finalized,
            c.l7proto,
            c.hostname_is_ip,
            c.pos,
        )
    };
    let (Some(dp), Some(host)) = (dp, host) else {
        return;
    };
    let (udp_out, udp_in) = {
        let d = dp.borrow();
        (d.hostlist_auto_udp_out, d.hostlist_auto_udp_in)
    };
    if !ah || fin || udp_out == 0 {
        return;
    }
    let tp = tpos.copied().unwrap_or(cpos);
    if tp.server.pcounter > udp_in as u64 {
        ct.borrow_mut().failure_detect_finalized = true;
        dlog!("udp_in {} > {}\n", tp.server.pcounter as u32, udp_in);
        let cip = fill_client_ip_port(client);
        auto_hostlist_reset_fail_counter(&dp, Some(&host), &cip, l7);
    } else if tp.client.pcounter >= udp_out as u64 {
        ct.borrow_mut().failure_detect_finalized = true;
        dlog!(
            "udp_in {} <= {}, udp_out {} >= {}\n",
            tp.server.pcounter as u32,
            udp_in,
            tp.client.pcounter as u32,
            udp_out
        );
        let cip = fill_client_ip_port(client);
        let (n, name) = {
            let d = dp.borrow();
            (d.n, d.name_str().to_string())
        };
        hostlist_debuglog_append(&format!(
            "{} : profile {} ({}) : client {} : proto {} : udp_in {}<={} udp_out {}>={}",
            hs(&host),
            n,
            name,
            cip,
            l7s(l7),
            tp.server.pcounter as u32,
            udp_in,
            tp.client.pcounter as u32,
            udp_out
        ));
        auto_hostlist_failed(&dp, &host, hip, &cip, l7);
    }
}

fn rawsend_queue(q: &mut RawPacketQueue) -> bool {
    let mut b = true;
    while let Some(rp) = q.pop() {
        b &= rawsend(
            &rp.dst,
            rp.fwmark,
            if rp.ifout.is_empty() {
                None
            } else {
                Some(&rp.ifout)
            },
            &rp.packet,
        );
    }
    b
}

fn send_delayed(ct: &CtrackRef) -> bool {
    let n = ct.borrow().delayed.count();
    if n > 0 {
        dlog!("SENDING {} delayed packets\n", n);
        let mut q = std::mem::take(&mut ct.borrow_mut().delayed);
        let r = rawsend_queue(&mut q);
        ct.borrow_mut().delayed.max_packets = q.max_packets;
        return r;
    }
    true
}

fn reasm_client_start(
    ct: Option<&CtrackRef>,
    proto: u8,
    pl: u32,
    sz: usize,
    szmax: usize,
    data: &[u8],
) -> bool {
    let Some(ct) = ct else { return false };
    let mut c = ct.borrow_mut();
    if proto == IPPROTO_TCP
        && c.pos.server.pcounter != 0
        && (c.pos.server.winsize_calc as usize) < sz
    {
        dlog!(
            "reasm cancelled because server window size {} is smaller than expected reasm size {}\n",
            c.pos.server.winsize_calc,
            sz
        );
        return false;
    }
    c.reasm_client_payload = pl;
    let seq = if proto == IPPROTO_TCP {
        c.pos.client.seq_last
    } else {
        0
    };
    c.reasm_client.clear();
    if sz <= szmax {
        c.reasm_client.init(sz, seq);
        c.reasm_client.feed(seq, data);
        dlog!(
            "starting reassemble. now we have {}/{}\n",
            c.reasm_client.size_present,
            c.reasm_client.size
        );
        true
    } else {
        dlog!("unexpected large payload for reassemble: size={}\n", sz);
        false
    }
}

fn reasm_client_feed(ct: Option<&CtrackRef>, proto: u8, data: &[u8]) -> bool {
    let Some(ct) = ct else { return false };
    let failed = {
        let mut c = ct.borrow_mut();
        if c.reasm_client.is_empty() {
            return false;
        }
        let seq = if proto == IPPROTO_TCP {
            c.pos.client.seq_last
        } else {
            c.reasm_client.size_present as u32
        };
        if c.reasm_client.feed(seq, data) {
            dlog!(
                "reassemble : feeding data payload size={}. now we have {}/{}\n",
                data.len(),
                c.reasm_client.size_present,
                c.reasm_client.size
            );
            return true;
        }
        c.reasm_client.clear();
        true
    };
    if failed {
        dlog!("reassemble session failed\n");
        send_delayed(ct);
    }
    false
}

fn reasm_client_stop(ct: Option<&CtrackRef>, msg: &str) {
    if let Some(ct) = ct {
        let had = {
            let mut c = ct.borrow_mut();
            if !c.reasm_client.is_empty() {
                c.reasm_client.clear();
                c.reasm_client_payload = L7P_UNKNOWN;
                true
            } else {
                false
            }
        };
        if had {
            dlog!("{}", msg);
        }
        send_delayed(ct);
    }
}
fn reasm_client_cancel(ct: Option<&CtrackRef>) {
    reasm_client_stop(ct, "reassemble session cancelled\n");
}
// discard delayed originals when falling back to a retransmitted fragment
fn reasm_client_cancel_discard(ct: &CtrackRef) {
    let mut c = ct.borrow_mut();
    c.reasm_client.clear();
    c.reasm_client_payload = L7P_UNKNOWN;
    c.delayed.clear();
    dlog!("reassemble session cancelled, delayed packets discarded\n");
}

const FASTPATH_RETRANS_THRESHOLD: u8 = 2;
// fastpath belongs to the local datapath, so autodetection is process-wide
fn fastpath_detected() -> bool {
    params().fastpath_retrans_count.get() >= FASTPATH_RETRANS_THRESHOLD
}
fn fastpath_update() {
    if fastpath_detected() {
        return;
    }
    let p = params();
    p.fastpath_retrans_count
        .set(p.fastpath_retrans_count.get() + 1);
    dlog!(
        "updated fastpath counter {}/{}\n",
        p.fastpath_retrans_count.get(),
        FASTPATH_RETRANS_THRESHOLD
    );
}

/// A payload-less ACK occupies no sequence space and reveals no payload.
fn make_tcp_ack_only(pkt: &[u8], dis: &Dissect, modp: &mut Vec<u8>, mod_max: usize) -> bool {
    let Some(t) = dis.tcp else { return false };
    if !dis.ip && !dis.ip6 {
        return false;
    }
    // all L3 headers (incl. ip6 ext) + TCP header with options
    let len = dis.len_l3 + dis.len_l4;
    if mod_max < len {
        return false;
    }
    modp.clear();
    modp.extend_from_slice(&pkt[..len]);
    modp[t + 13] &= !TH_PUSH; // PSH without payload is meaningless
    if dis.ip {
        modp[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        ip4_fix_checksum(modp);
    } else {
        modp[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    }
    let (s, d) = if dis.ip {
        (modp[12..16].to_vec(), modp[16..20].to_vec())
    } else {
        (modp[8..24].to_vec(), modp[24..40].to_vec())
    };
    tcp_fix_checksum_addrs(&mut modp[t..len], dis.len_l4, &s, &d);
    true
}

fn reasm_client_fin(ct: Option<&CtrackRef>) {
    reasm_client_stop(ct, "reassemble session finished\n");
}

fn ct_new_postnat_fix(
    ct: Option<&CtrackRef>,
    pkt: &[u8],
    dis: &Dissect,
    modp: &mut Vec<u8>,
    mod_max: usize,
) -> u8 {
    let server = params().server;
    let first = match ct {
        Some(c) => {
            let c = c.borrow();
            (if server {
                c.pos.server.pcounter
            } else {
                c.pos.client.pcounter
            }) == 1
        }
        None => dis
            .tcp
            .is_some_and(|t| tcp_syn_segment(&pkt[t..]) || tcp_synack_segment(&pkt[t..])),
    };
    if first {
        if dis.len_pkt > mod_max {
            dlog_err!("linux postnat conntrack workaround cannot be applied\n");
        } else {
            modp.clear();
            modp.extend_from_slice(&pkt[..dis.len_pkt]);
            dlog!("applying linux postnat conntrack workaround\n");
            if dis.ip6 {
                modp[6] = 255;
                modp[7] = 1;
            }
            if dis.ip {
                modp[9] = 255;
                modp[8] = 1;
            }
            return VERDICT_MODIFY | VERDICT_NOCSUM;
        }
    }
    VERDICT_DROP
}

fn pos_overflow(pos: Option<&CtrackPosition>, mode: u8) -> bool {
    (mode == b's' || mode == b'p') && pos.is_some_and(|p| p.rseq_over_2g)
}
fn pos_get(pos: Option<&CtrackPosition>, mode: u8) -> u64 {
    match pos {
        Some(p) => match mode {
            b'n' => p.pcounter,
            b'd' => p.pdcounter,
            b's' => p.seq_last.wrapping_sub(p.seq0) as u64,
            b'p' => p.pos.wrapping_sub(p.seq0) as u64,
            b'b' => p.pbcounter,
            _ => 0,
        },
        None => 0,
    }
}
fn check_pos_from(pos: Option<&CtrackPosition>, r: &crate::filter::PacketRange) -> bool {
    if r.from.mode == b'x' || pos_overflow(pos, r.from.mode) {
        return false;
    }
    if r.from.mode != b'a' {
        return match pos {
            Some(_) => pos_get(pos, r.from.mode) >= r.from.pos as u64,
            None => false,
        };
    }
    true
}
fn check_pos_to(pos: Option<&CtrackPosition>, r: &crate::filter::PacketRange) -> bool {
    if r.to.mode == b'x' || pos_overflow(pos, r.to.mode) {
        return false;
    }
    if r.to.mode != b'a' {
        return match pos {
            Some(_) => {
                let ps = pos_get(pos, r.to.mode);
                ps < r.to.pos as u64 || (!r.upper_cutoff && ps == r.to.pos as u64)
            }
            None => false,
        };
    }
    true
}
fn check_pos_cutoff(pos: Option<&CtrackPosition>, r: &crate::filter::PacketRange) -> bool {
    let bto = check_pos_to(pos, r);
    if pos.is_some() {
        !bto
    } else {
        !bto || !check_pos_from(pos, r)
    }
}
fn check_pos_range(pos: Option<&CtrackPosition>, r: &crate::filter::PacketRange) -> bool {
    check_pos_from(pos, r) && check_pos_to(pos, r)
}

fn ipcache_put_hostname(
    a4: Option<&[u8; 4]>,
    a6: Option<&[u8; 16]>,
    hostname: &[u8],
    is_ip: bool,
) -> bool {
    let p = params();
    if !p.cache_hostname {
        return true;
    }
    let mut c = p.ipcache.borrow_mut();
    let Some(ipc) = c.touch(a4, a6, None) else {
        dlog_err!("ipcache_put_hostname: out of memory\n");
        return false;
    };
    if ipc.hostname.as_deref() != Some(hostname) {
        ipc.hostname = Some(hostname.to_vec());
        ipc.hostname_is_ip = is_ip;
        dlog!(
            "hostname cached (is_ip={}): {}\n",
            is_ip as u8,
            hs(hostname)
        );
    }
    true
}

fn ipcache_get_hostname(a4: Option<&[u8; 4]>, a6: Option<&[u8; 16]>) -> Option<(Vec<u8>, bool)> {
    let p = params();
    if !p.cache_hostname {
        return None;
    }
    let s = ntopa46(a4.map(|a| &a[..]), a6.map(|a| &a[..]));
    dlog!("ipcache hostname search for {}\n", s);
    let mut c = p.ipcache.borrow_mut();
    let r = c
        .find(a4, a6, None)
        .and_then(|i| i.hostname.clone().map(|h| (h, i.hostname_is_ip)));
    if let Some((h, ip)) = &r {
        dlog!(
            "got cached hostname for {} : {} (is_ip={})\n",
            s,
            hs(h),
            *ip as u8
        );
        // snprintf into the 256 byte host buffer
        let mut h = h.clone();
        h.truncate(255);
        if h.is_empty() {
            return None;
        }
        return Some((h, *ip));
    }
    None
}

fn ipcache_update_ttl(
    ct: Option<&CtrackRef>,
    a4: Option<&[u8; 4]>,
    a6: Option<&[u8; 16]>,
    iface: Option<&str>,
) {
    let p = params();
    let Some(ct) = ct else { return };
    if p.server {
        return;
    }
    let ttl = ct.borrow().incoming_ttl;
    let mut c = p.ipcache.borrow_mut();
    if ttl != 0 {
        let Some(ipc) = c.touch(a4, a6, iface) else {
            dlog_err!("ipcache: out of memory\n");
            return;
        };
        if ipc.ttl != ttl {
            dlog!("updated ttl cache\n");
            ipc.ttl = ttl;
        }
    } else if let Some(ipc) = c.find(a4, a6, iface)
        && ipc.ttl != 0
    {
        dlog!("got cached ttl {}\n", ipc.ttl);
        ct.borrow_mut().incoming_ttl = ipc.ttl;
    }
}

fn ipcache_get_ttl(
    ct: Option<&CtrackRef>,
    a4: Option<&[u8; 4]>,
    a6: Option<&[u8; 16]>,
    iface: Option<&str>,
) {
    let p = params();
    let Some(ct) = ct else { return };
    if ct.borrow().incoming_ttl != 0 || p.server {
        return;
    }
    let mut c = p.ipcache.borrow_mut();
    if let Some(ipc) = c.find(a4, a6, iface)
        && ipc.ttl != 0
    {
        dlog!("got cached ttl {}\n", ipc.ttl);
        ct.borrow_mut().incoming_ttl = ipc.ttl;
    }
}

fn desync_get_result(l: lj::L) -> Option<u8> {
    let rc = lj::gettop(l);
    let r = if rc > 1 {
        dlog_err!("desync function returned more than one result : {}\n", rc);
        None
    } else if rc == 1 {
        if lj::isnil(l, -1) {
            Some(VERDICT_PASS)
        } else if !lj::isnumber(l, -1) {
            dlog_err!("desync function returned non-int result\n");
            None
        } else {
            let lv = lj::tointeger(l, -1);
            if lv & !(VERDICT_MASK_VALID_LUA as i64) != 0 {
                dlog_err!("desync function returned bad int result\n");
                None
            } else {
                Some(lv as u8)
            }
        }
    } else {
        Some(VERDICT_PASS)
    };
    lj::pop(l, rc);
    r
}

fn verdict_aggregate(v1: u8, v2: u8) -> u8 {
    let mut a = v1 & VERDICT_MASK;
    match v2 & VERDICT_MASK {
        VERDICT_MODIFY => {
            if a == VERDICT_PASS {
                a = VERDICT_MODIFY
            }
        }
        VERDICT_DROP => a = VERDICT_DROP,
        _ => {}
    }
    (v1 & !VERDICT_MASK) | a | (v2 & VERDICT_PRESERVE_NEXT)
}

pub struct Out<'a> {
    pub buf: &'a mut Vec<u8>,
    pub max: usize,
}

/// Current position view: replayed copy or live ctrack positions.
fn cur_tpos(tpos: Option<&CtrackPositions>, ct: Option<&CtrackRef>) -> Option<CtrackPositions> {
    match tpos {
        Some(t) => Some(*t),
        None => ct.map(|c| c.borrow().pos),
    }
}

#[allow(clippy::too_many_arguments)]
fn desync(
    dp: &ProfileRef,
    fwmark: u32,
    ifin: Option<&str>,
    ifout: Option<&str>,
    mut incoming: bool,
    mut ctrack: Option<CtrackRef>,
    tpos_in: Option<&CtrackPositions>,
    l7payload: u32,
    l7proto: u32,
    pkt: &[u8],
    dis: &Dissect,
    sdp4: Option<&[u8; 4]>,
    sdp6: Option<&[u8; 16]>,
    sdport: u16,
    out: &mut Out,
    replay_piece: u32,
    replay_piece_count: u32,
    reasm_offset: usize,
    rdata: Option<&[u8]>,
    ddata: Option<&[u8]>,
) -> u8 {
    let p = params();
    let mut verdict = VERDICT_PASS;
    if let Some(c) = &ctrack {
        let c = c.borrow();
        if incoming && c.b_lua_in_cutoff {
            dlog!("lua in cutoff\n");
            return verdict;
        }
        if !incoming && c.b_lua_out_cutoff {
            dlog!("lua out cutoff\n");
            return verdict;
        }
    }
    let mut tpos_fixed: Option<CtrackPositions> = tpos_in.copied();
    let side = |incoming: bool, t: &CtrackPositions| -> (CtrackPosition, CtrackPosition) {
        if incoming ^ p.server {
            (t.server, t.client)
        } else {
            (t.client, t.server)
        }
    };
    let s_dir = if incoming { "in" } else { "out" };
    let l = crate::lua::state();
    let g = lj::gettop(l);
    let funcs = dp.borrow().lua_desync.clone();
    let (dpn, dpname, dpcookie) = {
        let d = dp.borrow();
        (d.n, d.name.clone(), d.cookie.clone())
    };
    let mut ref_arg = lj::LUA_NOREF;
    let mut err = false;
    if !funcs.is_empty() {
        crate::lua::ctx_with(|c| {
            c.dp = Some(dp.clone());
            c.dp_n = dpn;
            c.ctrack = ctrack.clone();
            c.pkt = pkt[..dis.len_pkt].to_vec();
            c.dis = *dis;
            c.cancel = false;
            c.incoming = incoming;
        });
        let mut cutoff_all = true;
        let mut unwanted = true;
        let tp = cur_tpos(tpos_fixed.as_ref(), ctrack.as_ref());
        let (pos, _rpos) = match &tp {
            Some(t) => {
                let (a, b) = side(incoming, t);
                (Some(a), Some(b))
            }
            None => (None, None),
        };
        for (i, f) in funcs.iter().enumerate() {
            let fnn = i as u32 + 1;
            let instance = crate::lua::api::desync_instance(&f.func, dpn, fnn);
            crate::lua::ctx_with(|c| {
                c.func_n = fnn;
                c.func = f.func.clone();
                c.instance = instance.clone();
            });
            let range = if incoming { &f.range_in } else { &f.range_out };
            if unwanted {
                unwanted &= !l7_payload_match(l7payload, f.payload_type);
            }
            if cutoff_all {
                if instance_cutoff_check(l, &ctrack, &instance, dpn, incoming) {
                    dlog!("* lua '{}' : voluntary cutoff\n", instance);
                } else if check_pos_cutoff(pos.as_ref(), range) {
                    dlog!(
                        "* lua '{}' : {} pos {}{} {}{} overflow {} {} is beyond range {}{}{}{}{} (ctrack {})\n",
                        instance,
                        s_dir,
                        range.from.mode as char,
                        pos_get(pos.as_ref(), range.from.mode),
                        range.to.mode as char,
                        pos_get(pos.as_ref(), range.to.mode),
                        pos_overflow(pos.as_ref(), range.from.mode) as u8,
                        pos_overflow(pos.as_ref(), range.to.mode) as u8,
                        range.from.mode as char,
                        range.from.pos,
                        if range.upper_cutoff { '<' } else { '-' },
                        range.to.mode as char,
                        range.to.pos,
                        if ctrack.is_some() {
                            "enabled"
                        } else {
                            "disabled"
                        }
                    );
                } else {
                    cutoff_all = false;
                }
            }
        }
        if cutoff_all {
            dlog!("all {} desync functions reached cutoff condition\n", s_dir);
            if let Some(c) = &ctrack {
                let mut c = c.borrow_mut();
                if incoming {
                    c.b_lua_in_cutoff = true;
                } else {
                    c.b_lua_out_cutoff = true;
                }
            }
        } else if unwanted {
            dlog!(
                "all {} desync functions do not want `{}` payload\n",
                s_dir,
                l7payload_str(l7payload).unwrap_or("(null)")
            );
        } else {
            lj::newtable(l);
            lj::pushstr(l, "dis");
            push_dissect(l, pkt, Some(dis));
            lj::rawset(l, -3);
            lj::pushstr(l, "track");
            {
                let cb = ctrack.as_ref().map(|c| c.borrow());
                push_ctrack(l, cb.as_deref(), tpos_fixed.as_ref(), incoming, p.server);
            }
            lj::rawset(l, -3);
            pushf_int(l, "profile_n", dpn as i64);
            if let Some(n) = &dpname {
                pushf_str(l, "profile_name", Some(n.as_bytes()));
            }
            if let Some(c) = &dpcookie {
                pushf_str(l, "cookie", Some(c.as_bytes()));
            }
            pushf_bool(l, "outgoing", !incoming);
            pushf_str(l, "ifin", ifin.filter(|s| !s.is_empty()).map(str::as_bytes));
            pushf_str(
                l,
                "ifout",
                ifout.filter(|s| !s.is_empty()).map(str::as_bytes),
            );
            pushf_lint(l, "fwmark", fwmark as i64);
            pushf_table(l, "target");
            lj::getfield(l, -1, "target");
            if sdport != 0 {
                pushf_int(l, "port", sdport as i64);
            }
            if let Some(a) = sdp4 {
                pushf_raw(l, "ip", Some(a));
            }
            if let Some(a) = sdp6 {
                pushf_raw(l, "ip6", Some(a));
            }
            lj::pop(l, 1);
            pushf_bool(l, "replay", replay_piece_count != 0);
            if replay_piece_count != 0 {
                pushf_int(l, "replay_piece", replay_piece as i64 + 1);
                pushf_int(l, "replay_piece_count", replay_piece_count as i64);
                pushf_bool(
                    l,
                    "replay_piece_last",
                    replay_piece + 1 >= replay_piece_count,
                );
            }
            pushf_str(l, "l7payload", l7payload_str(l7payload).map(str::as_bytes));
            pushf_str(l, "l7proto", l7proto_str(l7proto).map(str::as_bytes));
            pushf_int(l, "reasm_offset", reasm_offset as i64);
            pushf_raw(l, "reasm_data", rdata);
            pushf_raw(l, "decrypt_data", ddata);
            if dis.tcp.is_some() {
                let t = cur_tpos(tpos_fixed.as_ref(), ctrack.as_ref());
                let pr = t.map(|t| side(incoming, &t));
                match pr {
                    Some((ps, rp)) if ps.mss != 0 && rp.mss != 0 => {
                        pushf_int(l, "tcp_mss", rp.mss.min(ps.mss) as i64);
                    }
                    _ => {
                        lj::pushstr(l, "tcp_mss");
                        lj::getglobal(l, "DEFAULT_MSS");
                        lj::rawset(l, -3);
                    }
                }
            }
            ref_arg = lj::ref_(l);
            for (i, f) in funcs.iter().enumerate() {
                let fnn = i as u32 + 1;
                let instance = crate::lua::api::desync_instance(&f.func, dpn, fnn);
                crate::lua::ctx_with(|c| {
                    c.func_n = fnn;
                    c.func = f.func.clone();
                    c.instance = instance.clone();
                });
                if !instance_cutoff_check(l, &ctrack, &instance, dpn, incoming) {
                    let range = if incoming { &f.range_in } else { &f.range_out };
                    let t = cur_tpos(tpos_fixed.as_ref(), ctrack.as_ref());
                    let pos = t.map(|t| side(incoming, &t).0);
                    let msg = |w: &str| {
                        dlog!(
                            "* lua '{}' : {} pos {}{} {}{} {} range {}{}{}{}{}\n",
                            instance,
                            s_dir,
                            range.from.mode as char,
                            pos_get(pos.as_ref(), range.from.mode),
                            range.to.mode as char,
                            pos_get(pos.as_ref(), range.to.mode),
                            w,
                            range.from.mode as char,
                            range.from.pos,
                            if range.upper_cutoff { '<' } else { '-' },
                            range.to.mode as char,
                            range.to.pos
                        )
                    };
                    if check_pos_range(pos.as_ref(), range) {
                        msg("in");
                        let pls = l7payload_str(l7payload).unwrap_or("(null)");
                        if l7_payload_match(l7payload, f.payload_type) {
                            dlog!(
                                "* lua '{}' : payload_type '{}' satisfy filter\n",
                                instance,
                                pls
                            );
                            dlog!("* lua '{}' : desync\n", instance);
                            lj::getglobal(l, &f.func);
                            if !lj::isfunction(l, -1) {
                                lj::pop(l, 1);
                                dlog_err!("desync function '{}' does not exist\n", f.func);
                                err = true;
                                break;
                            }
                            lj::rawgeti(
                                l,
                                lj::LUA_REGISTRYINDEX,
                                crate::lua::ref_desync_ctx() as i64,
                            );
                            lj::rawgeti(l, lj::LUA_REGISTRYINDEX, ref_arg as i64);
                            if !pushf_args(l, &f.args, -1, true) {
                                lj::pop(l, 3);
                                err = true;
                                break;
                            }
                            pushf_str(l, "func", Some(f.func.as_bytes()));
                            pushf_int(l, "func_n", fnn as i64);
                            pushf_str(l, "func_instance", Some(instance.as_bytes()));
                            crate::lua::ctx_with(|c| c.valid = true);
                            let base = lj::gettop(l) - 3;
                            let st = lj::pcall(l, 2, lj::LUA_MULTRET);
                            let _ = base;
                            crate::lua::ctx_with(|c| c.valid = false);
                            if st != 0 {
                                crate::lua::lua_dlog_error();
                                err = true;
                                break;
                            }
                            // results are on top of the guard base
                            let nres = lj::gettop(l) - g;
                            let vf = {
                                // desync_get_result works on the whole stack top above guard
                                let _ = nres;
                                desync_get_result(l)
                            };
                            let Some(vf) = vf else {
                                err = true;
                                break;
                            };
                            verdict = verdict_aggregate(verdict, vf);
                            if ctrack.is_none() {
                                let (cc, ci) =
                                    crate::lua::ctx_with(|c| (c.ctrack.clone(), c.incoming));
                                if cc.is_some() {
                                    ctrack = cc;
                                    incoming = ci;
                                    tpos_fixed = None;
                                }
                            }
                        } else {
                            dlog!(
                                "* lua '{}' : payload_type '{}' does not satisfy filter\n",
                                instance,
                                pls
                            );
                        }
                    } else {
                        msg("out of");
                    }
                }
                if crate::lua::ctx_with(|c| c.cancel) {
                    break;
                }
            }
        }
        if !err && (verdict & VERDICT_MASK) == VERDICT_MODIFY {
            lj::rawgeti(l, lj::LUA_REGISTRYINDEX, ref_arg as i64);
            lj::getfield(l, -1, "dis");
            if lj::typ(l, -1) != lj::LUA_TTABLE {
                lj::pop(l, 2);
                dlog_err!("dissect data is bad. VERDICT_MODIFY cancel.\n");
                err = true;
            } else {
                let o = ReconOpts {
                    keepsum: false,
                    badsum: false,
                    ip6_preserve_next: verdict & VERDICT_PRESERVE_NEXT != 0,
                    ip6_last_proto: IPPROTO_NONE,
                };
                let mut buf = vec![0u8; out.max];
                let r = reconstruct_dissect(l, -1, &mut buf, &o);
                lj::pop(l, 2);
                match r {
                    Some(n) => {
                        buf.truncate(n);
                        *out.buf = buf;
                        dlog!(
                            "reconstructed packet due to VERDICT_MODIFY. size {} => {}\n",
                            dis.len_pkt,
                            n
                        );
                        verdict |= VERDICT_NOCSUM;
                    }
                    None => {
                        dlog_err!("failed to reconstruct packet after VERDICT_MODIFY\n");
                        verdict = VERDICT_PASS;
                    }
                }
            }
        }
    } else {
        dlog!("no lua functions in this profile\n");
    }
    if err {
        dlog_err!("desync ERROR. passing packet unmodified.\n");
        verdict = VERDICT_PASS;
    }
    lj::unref(l, ref_arg);
    if g != lj::gettop(l) {
        lj::error(l, "stack guard failure");
    }
    verdict
}

/// lua_instance_cutoff_check
fn instance_cutoff_check(
    l: lj::L,
    ct: &Option<CtrackRef>,
    instance: &str,
    dpn: u32,
    incoming: bool,
) -> bool {
    let Some(ct) = ct else { return false };
    let r = ct.borrow().lua_instance_cutoff;
    lj::rawgeti(l, lj::LUA_REGISTRYINDEX, r as i64);
    lj::getfield(l, -1, instance);
    if !lj::istable(l, -1) {
        lj::pop(l, 2);
        return false;
    }
    lj::rawgeti(l, -1, dpn as i64);
    if !lj::istable(l, -1) {
        lj::pop(l, 3);
        return false;
    }
    lj::rawgeti(l, -1, incoming as i64);
    let b = lj::toboolean(l, -1);
    lj::pop(l, 4);
    b
}

struct Endpoints {
    src: SockAddr,
    dst: SockAddr,
    sdip4: Option<[u8; 4]>,
    sdip6: Option<[u8; 16]>,
    sdport: u16,
}

fn setup_direction(pkt: &[u8], dis: &Dissect, rev_fixed: bool) -> Endpoints {
    let (src, dst) = extract_endpoints(pkt, dis);
    let mut e = Endpoints {
        src,
        dst,
        sdip4: None,
        sdip6: None,
        sdport: 0,
    };
    if dis.ip6 {
        let o = if rev_fixed { 8 } else { 24 };
        let mut a = [0u8; 16];
        a.copy_from_slice(&pkt[o..o + 16]);
        e.sdip6 = Some(a);
    } else if dis.ip {
        let o = if rev_fixed { 12 } else { 16 };
        let mut a = [0u8; 4];
        a.copy_from_slice(&pkt[o..o + 4]);
        e.sdip4 = Some(a);
    } else {
        return e;
    }
    let server = params().server;
    e.sdport = if rev_fixed ^ server {
        src.port()
    } else {
        dst.port()
    };
    if debug() {
        let ip = ntopa46(
            e.sdip4.as_ref().map(|a| &a[..]),
            e.sdip6.as_ref().map(|a| &a[..]),
        );
        dlog!(
            "{} mode desync profile/ipcache search target ip={} port={}\n",
            if server { "server" } else { "client" },
            ip,
            e.sdport
        );
    }
    e
}

fn dp_changed(ct: Option<&CtrackRef>) {
    if let Some(c) = ct {
        let mut c = c.borrow_mut();
        if c.b_lua_in_cutoff {
            dlog!("clearing lua in cutoff because of profile change\n");
            c.b_lua_in_cutoff = false;
        }
        if c.b_lua_out_cutoff {
            dlog!("clearing lua out cutoff because of profile change\n");
            c.b_lua_out_cutoff = false;
        }
    }
}

struct PlayState {
    dp: Option<ProfileRef>,
    tpos: Option<CtrackPositions>,
    ctrack: Option<CtrackRef>,
    ctrack_replay: Option<CtrackRef>,
    ep: Endpoints,
    verdict: u8,
    host: Vec<u8>,
    l7proto: u32,
    l7payload: u32,
    ssid: Option<Vec<u8>>,
    fwmark: u32,
    rev: bool,
    rev_fixed: bool,
    have_host: bool,
}

fn ssid_for(ifname: Option<&str>) -> Option<Vec<u8>> {
    let s = ifname
        .and_then(crate::wlan::ssid_search_ifname)
        .map(String::into_bytes);
    if let Some(s) = &s {
        dlog!("found ssid for {} : {}\n", ifname.unwrap_or(""), hs(s));
    }
    s
}

fn a4(o: &Option<[u8; 4]>) -> Option<&[u8; 4]> {
    o.as_ref()
}
fn a6(o: &Option<[u8; 16]>) -> Option<&[u8; 16]> {
    o.as_ref()
}

fn play_prolog(
    pkt: &[u8],
    dis: &Dissect,
    tpos: Option<&CtrackPositions>,
    replay: bool,
    ifin: Option<&str>,
    ifout: Option<&str>,
    fwmark: u32,
) -> Result<PlayState, u8> {
    if dis.ip == dis.ip6 {
        return Err(VERDICT_PASS);
    }
    let p = params();
    let mut ps = PlayState {
        dp: None,
        tpos: tpos.copied(),
        ctrack: None,
        ctrack_replay: None,
        ep: Endpoints {
            src: SockAddr::None,
            dst: SockAddr::None,
            sdip4: None,
            sdip6: None,
            sdport: 0,
        },
        verdict: VERDICT_PASS,
        host: Vec::new(),
        l7proto: L7_UNKNOWN,
        l7payload: if dis.len_payload != 0 {
            L7P_UNKNOWN
        } else {
            L7P_EMPTY
        },
        ssid: None,
        fwmark,
        rev: false,
        rev_fixed: false,
        have_host: false,
    };
    if replay {
        let found = p.conntrack.borrow().double_search(pkt, dis);
        let Some((ct, rev)) = found else {
            return Err(VERDICT_PASS);
        };
        if rev {
            return Err(VERDICT_PASS);
        }
        ps.ctrack_replay = Some(ct.clone());
        ps.rev = rev;
        ps.rev_fixed = rev ^ p.server;
        ps.ep = setup_direction(pkt, dis, ps.rev_fixed);
        ps.ssid = ssid_for(if ps.rev_fixed { ifin } else { ifout });
        let (l7, dp, done, host, hip) = {
            let c = ct.borrow();
            (
                c.l7proto,
                c.dp.clone(),
                c.dp_search_complete,
                c.hostname.clone(),
                c.hostname_is_ip,
            )
        };
        ps.l7proto = l7;
        ps.dp = dp;
        if let Some(d) = &ps.dp {
            let d = d.borrow();
            dlog!("using cached desync profile {} ({})\n", d.n, d.name_str());
        } else if !done {
            ps.dp = dp_find(
                dis.proto,
                a4(&ps.ep.sdip4),
                a6(&ps.ep.sdip6),
                None,
                None,
                ps.ep.sdport,
                0xFF,
                0xFF,
                host.as_deref(),
                hip,
                ps.l7proto,
                ps.ssid.as_deref(),
                ps.fwmark,
                None,
            );
            let mut c = ct.borrow_mut();
            c.dp = ps.dp.clone();
            c.dp_search_complete = true;
        }
        if ps.dp.is_none() {
            dlog!("matching desync profile not found\n");
            return Err(VERDICT_PASS);
        }
    } else {
        if !p.ctrack_disable {
            p.conntrack.borrow_mut().purge();
            let fed = p.conntrack.borrow_mut().feed(pkt, dis);
            if let Some((ct, rev)) = fed {
                ps.dp = ct.borrow().dp.clone();
                ps.ctrack = Some(ct.clone());
                ps.ctrack_replay = Some(ct);
                ps.rev = rev;
            }
        }
        ps.rev_fixed = if ps.ctrack.is_some() {
            ps.rev ^ p.server
        } else {
            ps.rev = ifin.is_some_and(|s| !s.is_empty()) && ifout.is_none_or(|s| s.is_empty());
            ps.rev
        };
        ps.ep = setup_direction(pkt, dis, ps.rev_fixed);
        ps.ssid = ssid_for(if ps.rev_fixed { ifin } else { ifout });
        if let Some(c) = &ps.ctrack {
            ps.l7proto = c.borrow().l7proto;
        }
        if let Some(d) = &ps.dp {
            let d = d.borrow();
            dlog!("using cached desync profile {} ({})\n", d.n, d.name_str());
        } else if ps
            .ctrack
            .as_ref()
            .is_none_or(|c| !c.borrow().dp_search_complete)
        {
            let mut hostname: Option<Vec<u8>> = None;
            let mut hip = false;
            if let Some(c) = &ps.ctrack {
                let (h, i) = {
                    let cb = c.borrow();
                    (cb.hostname.clone(), cb.hostname_is_ip)
                };
                hostname = h;
                hip = i;
                if hostname.is_none()
                    && !ps.rev
                    && let Some((h, i)) = ipcache_get_hostname(a4(&ps.ep.sdip4), a6(&ps.ep.sdip6))
                {
                    hip = i;
                    ps.host = h.clone();
                    c.borrow_mut().hostname = Some(h.clone());
                    hostname = Some(h);
                }
            }
            ps.dp = dp_find(
                dis.proto,
                a4(&ps.ep.sdip4),
                a6(&ps.ep.sdip6),
                None,
                None,
                ps.ep.sdport,
                0xFF,
                0xFF,
                hostname.as_deref(),
                hip,
                ps.l7proto,
                ps.ssid.as_deref(),
                ps.fwmark,
                None,
            );
            if let Some(c) = &ps.ctrack {
                let mut c = c.borrow_mut();
                c.dp = ps.dp.clone();
                c.dp_search_complete = true;
            }
        }
        let Some(dp) = ps.dp.clone() else {
            dlog!("matching desync profile not found\n");
            return Err(VERDICT_PASS);
        };
        {
            let mut d = dp.borrow_mut();
            let mut lp = d.hostlist_auto_last_purge;
            hostfail_pool_purge_rate_limited(&mut d.hostlist_auto_fail_counters, &mut lp);
            d.hostlist_auto_last_purge = lp;
        }
        if ps.rev_fixed {
            if let Some(c) = &ps.ctrack {
                let mut cb = c.borrow_mut();
                if cb.incoming_ttl == 0 {
                    cb.incoming_ttl = ttl46(pkt, dis);
                    dlog!("incoming TTL {}\n", cb.incoming_ttl);
                }
            }
            ipcache_update_ttl(ps.ctrack.as_ref(), a4(&ps.ep.sdip4), a6(&ps.ep.sdip6), ifin);
        } else {
            ipcache_get_ttl(
                ps.ctrack.as_ref(),
                a4(&ps.ep.sdip4),
                a6(&ps.ep.sdip6),
                ifout,
            );
        }
    }
    Ok(ps)
}

fn dp_rediscovery(ps: &mut PlayState, dis: &Dissect) -> bool {
    let mut host_is_ip = false;
    if ps.have_host {
        let (h, ip) = strip_host_to_ip(&ps.host);
        ps.host = h;
        host_is_ip = ip;
        dlog!("hostname: {}\n", hs(&ps.host));
    }
    let disc_l7 = match &ps.ctrack_replay {
        Some(c) => {
            let mut c = c.borrow_mut();
            let d = !c.l7proto_discovered && c.l7proto != L7_UNKNOWN;
            if d {
                c.l7proto_discovered = true;
            }
            d
        }
        None => ps.l7proto != L7_UNKNOWN,
    };
    if disc_l7 {
        dlog!("discovered l7 protocol\n");
    }
    let disc_host = ps.have_host
        && !ps
            .ctrack_replay
            .as_ref()
            .is_some_and(|c| c.borrow().hostname_discovered);
    if disc_host {
        dlog!("discovered hostname\n");
        if let Some(c) = &ps.ctrack_replay {
            {
                let mut c = c.borrow_mut();
                c.hostname = Some(ps.host.clone());
                c.hostname_is_ip = host_is_ip;
                c.hostname_discovered = true;
            }
            if !ipcache_put_hostname(a4(&ps.ep.sdip4), a6(&ps.ep.sdip6), &ps.host, host_is_ip) {
                return false;
            }
        }
    }
    let mut cs = match &ps.ctrack_replay {
        Some(c) => {
            let c = c.borrow();
            CheckState {
                done: c.b_check_done,
                result: c.b_check_result,
                excluded: c.b_check_excluded,
            }
        }
        None => CheckState::default(),
    };
    if disc_l7 || disc_host {
        let dp_prev = ps.dp.clone();
        let (h, hip) = match &ps.ctrack_replay {
            Some(c) => {
                let c = c.borrow();
                (c.hostname.clone(), c.hostname_is_ip)
            }
            None => (
                if ps.have_host {
                    Some(ps.host.clone())
                } else {
                    None
                },
                host_is_ip,
            ),
        };
        ps.dp = dp_find(
            dis.proto,
            a4(&ps.ep.sdip4),
            a6(&ps.ep.sdip6),
            None,
            None,
            ps.ep.sdport,
            0xFF,
            0xFF,
            h.as_deref(),
            hip,
            ps.l7proto,
            ps.ssid.as_deref(),
            ps.fwmark,
            Some(&mut cs),
        );
        if let Some(c) = &ps.ctrack_replay {
            let mut c = c.borrow_mut();
            c.dp = ps.dp.clone();
            c.dp_search_complete = true;
            c.b_check_done = cs.done;
            c.b_check_result = cs.result;
            c.b_check_excluded = cs.excluded;
        }
        let Some(dp) = &ps.dp else { return false };
        let same = dp_prev.as_ref().is_some_and(|p| std::rc::Rc::ptr_eq(p, dp));
        if !same {
            dp_changed(ps.ctrack_replay.as_ref());
            dlog!("desync profile changed by revealed l7 protocol or hostname !\n");
        }
    }
    // INFALLIBLE: play_prolog only continues with a profile, rediscovery returns above when None
    let Some(dp) = ps.dp.clone() else {
        return false;
    };
    if ps.have_host && !dp.borrow().hostlists_empty() {
        if !cs.done {
            let mut ex = false;
            cs.result = hostlist_check(&dp.borrow(), &ps.host, host_is_ip, &mut ex, false);
            cs.excluded = ex;
            cs.done = true;
            if let Some(c) = &ps.ctrack_replay {
                let mut c = c.borrow_mut();
                c.b_check_done = cs.done;
                c.b_check_result = cs.result;
                c.b_check_excluded = cs.excluded;
            }
        }
        if let Some(c) = &ps.ctrack_replay {
            if cs.result {
                if dis.proto == IPPROTO_TCP {
                    ctrack_stop_retrans_counter(Some(c));
                }
            } else {
                let ah = dp.borrow().hostlist_auto.is_some() && !cs.excluded;
                c.borrow_mut().hostname_ah_check = ah;
                if dis.proto == IPPROTO_TCP && !ah {
                    ctrack_stop_retrans_counter(Some(c));
                }
            }
        }
    }
    if let Some(c) = &ps.ctrack_replay
        && dis.proto == IPPROTO_UDP
    {
        process_udp_fail(c, ps.tpos.as_ref(), &ps.ep.src);
    }
    if cs.done && !cs.result {
        dlog!("not applying tampering because of previous negative hostlist check\n");
        return false;
    }
    if debug() {
        dlog!(
            "dpi desync src={} dst={} track_direction={} fixed_direction={} connection_proto={} payload_type={}\n",
            trunc(ps.ep.src.ntop_port(), 48),
            trunc(ps.ep.dst.ntop_port(), 48),
            if ps.rev { "in" } else { "out" },
            if ps.rev_fixed { "in" } else { "out" },
            l7proto_str(ps.l7proto).unwrap_or("(null)"),
            l7payload_str(ps.l7payload).unwrap_or("(null)")
        );
    }
    true
}

fn host_trunc(v: Option<Vec<u8>>) -> Option<Vec<u8>> {
    v
}

#[allow(clippy::too_many_arguments)]
fn tcp_packet_play(
    replay_piece: u32,
    replay_count: u32,
    reasm_offset: usize,
    fwmark: u32,
    ifin: Option<&str>,
    ifout: Option<&str>,
    tpos: Option<&CtrackPositions>,
    pkt: &[u8],
    dis: &Dissect,
    out: &mut Out,
) -> u8 {
    let mut ps = match play_prolog(pkt, dis, tpos, replay_count != 0, ifin, ifout, fwmark) {
        Ok(ps) => ps,
        Err(v) => return v,
    };
    let p = params();
    let desync_fwmark = fwmark | p.desync_fwmark;
    // INFALLIBLE: dis.tcp is set for tcp packets
    let to = dis.tcp.unwrap_or(0);
    let tflags = pkt[to + 13];
    let payload = &pkt[dis.payload..dis.payload + dis.len_payload];
    let mut rdata: Vec<u8> = payload.to_vec();

    enum Next {
        Rediscover,
        ReasmCancelRediscover,
        /// fastpath workaround: reasm discarded, desync this fragment on its own
        DiscardRediscover,
        /// fastpath workaround: replace the held fragment with a payload-less ACK
        AckOnly,
        Return(u8),
    }
    let next = (|| -> Next {
        if ps.rev {
            if tflags & TH_SYN == 0 && dis.len_payload != 0 {
                let probes = [
                    Probe {
                        l7p: L7P_TLS_SERVER_HELLO,
                        l7: L7_TLS,
                        check: |d| is_tls_server_hello(d, true),
                        l7match: false,
                    },
                    Probe {
                        l7p: L7P_HTTP_REPLY,
                        l7: L7_HTTP,
                        check: is_http_reply,
                        l7match: false,
                    },
                    Probe {
                        l7p: L7P_XMPP_STREAM,
                        l7: L7_XMPP,
                        check: is_xmpp_stream,
                        l7match: false,
                    },
                    Probe {
                        l7p: L7P_XMPP_PROCEED,
                        l7: L7_XMPP,
                        check: is_xmpp_proceed_tls,
                        l7match: false,
                    },
                    Probe {
                        l7p: L7P_XMPP_FEATURES,
                        l7: L7_XMPP,
                        check: is_xmpp_features,
                        l7match: false,
                    },
                    Probe {
                        l7p: L7P_BT_HANDSHAKE,
                        l7: L7_BT,
                        check: is_bt_handshake,
                        l7match: false,
                    },
                ];
                protocol_probe(
                    &probes,
                    payload,
                    ps.ctrack.as_ref(),
                    &mut ps.l7proto,
                    &mut ps.l7payload,
                );
                if ps.l7payload == L7P_TLS_SERVER_HELLO {
                    tls_debug(payload);
                }
            }
            if let (false, Some(ct), Some(dp)) = (p.server, ps.ctrack.clone(), ps.dp.clone()) {
                let (ah, fin, sl, s0, host, hip) = {
                    let c = ct.borrow();
                    (
                        c.hostname_ah_check,
                        c.failure_detect_finalized,
                        c.pos.server.seq_last,
                        c.pos.server.seq0,
                        c.hostname.clone(),
                        c.hostname_is_ip,
                    )
                };
                let imax = dp.borrow().hostlist_auto_incoming_maxseq;
                if ah && !fin && imax != 0 {
                    let rseq = sl.wrapping_sub(s0);
                    if rseq != 0 {
                        let cip = fill_client_ip_port(&ps.ep.dst);
                        let hstr = host.as_deref().map(hs).unwrap_or_else(|| "(null)".into());
                        let (n, name) = {
                            let ctdp = ct.borrow().dp.clone();
                            let n = ctdp.map(|d| d.borrow().n).unwrap_or(0);
                            (n, dp.borrow().name_str().to_string())
                        };
                        if seq_within(sl, s0.wrapping_add(1), s0.wrapping_add(imax)) {
                            let mut fail = false;
                            if tflags & TH_RST != 0 {
                                dlog!(
                                    "incoming RST detected for hostname {} rseq {}\n",
                                    hstr,
                                    rseq
                                );
                                hostlist_debuglog_append(&format!(
                                    "{} : profile {} ({}) : client {} : proto {} : rseq {} : incoming RST",
                                    hstr,
                                    n,
                                    name,
                                    cip,
                                    l7s(ps.l7proto),
                                    rseq
                                ));
                                fail = true;
                            } else if dis.len_payload != 0 && ps.l7payload == L7P_HTTP_REPLY {
                                dlog!(
                                    "incoming HTTP reply detected for hostname {} rseq {}\n",
                                    hstr,
                                    rseq
                                );
                                fail = http_reply_looks_like_dpi_redirect(
                                    payload,
                                    host.as_deref().unwrap_or(b""),
                                );
                                if fail {
                                    dlog!(
                                        "redirect to another domain detected. possibly DPI redirect.\n"
                                    );
                                    hostlist_debuglog_append(&format!(
                                        "{} : profile {} ({}) : client {} : proto {} : rseq {} : redirect to another domain",
                                        hstr,
                                        n,
                                        name,
                                        cip,
                                        l7s(ps.l7proto),
                                        rseq
                                    ));
                                } else {
                                    dlog!(
                                        "local or in-domain redirect detected. it's not a DPI redirect.\n"
                                    );
                                }
                            }
                            if fail {
                                if let Some(h) = &host {
                                    auto_hostlist_failed(&dp, h, hip, &cip, ps.l7proto);
                                }
                                ct.borrow_mut().failure_detect_finalized = true;
                            }
                        } else {
                            dlog!("incoming rseq {} > {}\n", rseq, imax);
                            auto_hostlist_reset_fail_counter(
                                &dp,
                                host.as_deref(),
                                &cip,
                                ps.l7proto,
                            );
                            ct.borrow_mut().failure_detect_finalized = true;
                        }
                    }
                }
            }
        } else if tflags & TH_SYN == 0 && dis.len_payload != 0 {
            if replay_count != 0 {
                if let Some(c) = &ps.ctrack_replay {
                    let c = c.borrow();
                    rdata = c.reasm_client.packet[..c.reasm_client.size_present].to_vec();
                }
            } else if reasm_client_feed(ps.ctrack.as_ref(), IPPROTO_TCP, payload)
                && let Some(c) = &ps.ctrack
            {
                let c = c.borrow();
                rdata = c.reasm_client.packet[..c.reasm_client.size_present].to_vec();
            }
            process_retrans_fail(ps.ctrack.as_ref(), pkt, dis, &ps.ep.src, ifin);
            if ps
                .ctrack_replay
                .as_ref()
                .is_none_or(|c| c.borrow().reasm_client.is_empty())
            {
                let probes = [
                    Probe {
                        l7p: L7P_TLS_CLIENT_HELLO,
                        l7: L7_TLS,
                        check: |d| is_tls_client_hello(d, true),
                        l7match: false,
                    },
                    Probe {
                        l7p: L7P_HTTP_REQ,
                        l7: L7_HTTP,
                        check: is_http,
                        l7match: false,
                    },
                    Probe {
                        l7p: L7P_XMPP_STREAM,
                        l7: L7_XMPP,
                        check: is_xmpp_stream,
                        l7match: false,
                    },
                    Probe {
                        l7p: L7P_XMPP_STARTTLS,
                        l7: L7_XMPP,
                        check: is_xmpp_starttls,
                        l7match: false,
                    },
                    Probe {
                        l7p: L7P_BT_HANDSHAKE,
                        l7: L7_BT,
                        check: is_bt_handshake,
                        l7match: false,
                    },
                ];
                protocol_probe(
                    &probes,
                    &rdata,
                    ps.ctrack_replay.as_ref(),
                    &mut ps.l7proto,
                    &mut ps.l7payload,
                );
                if ps.l7payload == L7P_UNKNOWN {
                    let t = cur_tpos(ps.tpos.as_ref(), ps.ctrack_replay.as_ref());
                    if t.is_some_and(|t| t.client.seq_last.wrapping_sub(t.client.seq0) == 1) {
                        let probes = [Probe {
                            l7p: L7P_MTPROTO_INITIAL,
                            l7: L7_MTPROTO,
                            check: is_mtproto,
                            l7match: false,
                        }];
                        protocol_probe(
                            &probes,
                            &rdata,
                            ps.ctrack_replay.as_ref(),
                            &mut ps.l7proto,
                            &mut ps.l7payload,
                        );
                    }
                }
            }
            let reasm_tls = ps.ctrack_replay.as_ref().is_some_and(|c| {
                let c = c.borrow();
                c.reasm_client_payload == L7P_TLS_CLIENT_HELLO && !c.reasm_client.is_empty()
            });
            if ps.l7payload == L7P_TLS_CLIENT_HELLO || reasm_tls {
                ps.l7payload = L7P_TLS_CLIENT_HELLO;
                let full = is_tls_record_full(&rdata);
                dlog!(
                    "{}",
                    if full {
                        "TLS client hello is FULL\n"
                    } else {
                        "TLS client hello is PARTIAL\n"
                    }
                );
                if full {
                    tls_debug(&rdata);
                }
                if let Some(ct) = ps.ctrack.clone()
                    && !l7_payload_match(ps.l7payload, p.reasm_payload_disable)
                {
                    let (empty, retr) = {
                        let c = ct.borrow();
                        (c.reasm_client.is_empty(), is_retransmission(&c.pos.client))
                    };
                    if !full
                        && empty
                        && !retr
                        && !reasm_client_start(
                            Some(&ct),
                            IPPROTO_TCP,
                            L7P_TLS_CLIENT_HELLO,
                            tls_record_len(payload),
                            TCP_MAX_REASM,
                            payload,
                        )
                    {
                        return Next::Rediscover;
                    }
                    if !ct.borrow().reasm_client.is_empty() {
                        // Treat retransmission during incomplete reasm as a fastpath bypass.
                        // Discard queued originals to avoid exposing SNI and retry this
                        // fragment normally.
                        if p.fastpath_workaround != FASTPATH_WORKAROUND_OFF
                            && is_retransmission(&ct.borrow().pos.client)
                        {
                            if p.fastpath_workaround == FASTPATH_WORKAROUND_AUTO {
                                fastpath_update();
                            }
                            dlog!(
                                "retransmission while reasm is incomplete (fastpath steals further fragments). discarding reasm, falling back to single packet desync\n"
                            );
                            reasm_client_cancel_discard(&ct);
                            return Next::DiscardRediscover;
                        }
                        let pos = ct.borrow().pos;
                        let rp = RawPacket {
                            dst: ps.ep.dst,
                            ifin: crate::conntrack::ifname_copy(ifin),
                            ifout: crate::conntrack::ifname_copy(ifout),
                            fwmark_orig: fwmark,
                            fwmark: desync_fwmark,
                            packet: pkt[..dis.len_pkt].to_vec(),
                            len_payload: dis.len_payload,
                            tpos: Some(pos),
                            server_side: false,
                        };
                        if ct.borrow_mut().delayed.push(rp) {
                            dlog!(
                                "DELAY desync until reasm is complete (#{})\n",
                                ct.borrow().delayed.count()
                            );
                        } else {
                            dlog_err!("rawpacket_queue failed !\n");
                            return Next::ReasmCancelRediscover;
                        }
                        if ct.borrow().reasm_client.is_full() {
                            if p.fastpath_workaround == FASTPATH_WORKAROUND_AUTO
                                && !fastpath_detected()
                            {
                                p.fastpath_retrans_count.set(0);
                            }
                            let mut q = std::mem::take(&mut ct.borrow_mut().delayed);
                            replay_queue(&mut q);
                            ct.borrow_mut().delayed.max_packets = q.max_packets;
                            reasm_client_fin(Some(&ct));
                            return Next::Return(VERDICT_DROP);
                        }
                        // On affected hardware DROP activates RTCACHE and later fragments
                        // bypass NFQUEUE. ACK-only placeholders keep the flow on the slow
                        // path until replay.
                        if p.fastpath_workaround == FASTPATH_WORKAROUND_ON
                            || (p.fastpath_workaround == FASTPATH_WORKAROUND_AUTO
                                && fastpath_detected())
                        {
                            // control flags are unsafe after removing the payload or before replay
                            if tflags & (TH_FIN | TH_RST | TH_URG) != 0 {
                                dlog!(
                                    "not replacing incomplete reasm fragment with ACK-only because TCP control flags are set\n"
                                );
                                return Next::Return(VERDICT_DROP);
                            }
                            return Next::AckOnly;
                        }
                        return Next::Return(VERDICT_DROP);
                    }
                }
                let h = tls_hello_extract_host(&rdata, 256, true);
                ps.have_host = h.is_some();
                ps.host = host_trunc(h).unwrap_or_default();
            } else {
                reasm_client_cancel(ps.ctrack.as_ref());
                if ps.l7payload == L7P_HTTP_REQ {
                    let h = http_extract_host(&rdata, 256);
                    ps.have_host = h.is_some();
                    ps.host = h.unwrap_or_default();
                }
            }
        }
        Next::Rediscover
    })();
    match next {
        Next::Return(v) => return v,
        Next::ReasmCancelRediscover => {
            reasm_client_cancel(ps.ctrack.as_ref());
            rdata = payload.to_vec();
            ps.l7payload = L7P_UNKNOWN;
        }
        Next::DiscardRediscover => {
            rdata = payload.to_vec();
            let h = tls_hello_extract_host(&rdata, 256, true);
            ps.have_host = h.is_some();
            ps.host = host_trunc(h).unwrap_or_default();
        }
        Next::AckOnly => {
            let max = out.max;
            if make_tcp_ack_only(pkt, dis, out.buf, max) {
                dlog!(
                    "replacing incomplete reasm fragment with ACK-only packet (hardware fastpath workaround)\n"
                );
                return VERDICT_MODIFY | VERDICT_NOCSUM;
            }
            dlog_err!("failed to build ACK-only reasm placeholder. dropping\n");
            return VERDICT_DROP;
        }
        Next::Rediscover => {}
    }
    if !dp_rediscovery(&mut ps, dis) {
        reasm_client_cancel(ps.ctrack.as_ref());
    } else {
        // INFALLIBLE: dp_rediscovery returns true only with a profile
        let Some(dp) = ps.dp.clone() else {
            return VERDICT_PASS;
        };
        ps.verdict = desync(
            &dp,
            fwmark,
            ifin,
            ifout,
            ps.rev_fixed,
            ps.ctrack_replay.clone(),
            tpos,
            ps.l7payload,
            ps.l7proto,
            pkt,
            dis,
            a4(&ps.ep.sdip4),
            a6(&ps.ep.sdip6),
            ps.ep.sdport,
            out,
            replay_piece,
            replay_count,
            reasm_offset,
            Some(&rdata),
            None,
        );
    }
    if !ps.rev_fixed && (ps.verdict & VERDICT_MASK) == VERDICT_DROP {
        let max = out.max;
        ct_new_postnat_fix(ps.ctrack.as_ref(), pkt, dis, out.buf, max)
    } else {
        ps.verdict
    }
}

fn dns_extract_name(b: &[u8], a: usize, e: usize, name_size: usize) -> Option<(usize, Vec<u8>)> {
    if name_size == 0 {
        return None;
    }
    let bptr = b[a] & 0xC0 == 0xC0;
    let mut p = if bptr {
        if a + 1 >= e {
            return None;
        }
        (((b[a] & 0x3F) as usize) << 8) | b[a + 1] as usize
    } else {
        a
    };
    if p >= e {
        return None;
    }
    let mut name: Vec<u8> = Vec::new();
    while b[p] != 0 {
        if !name.is_empty() {
            if name.len() >= name_size {
                return None;
            }
            name.push(b'.');
        }
        let y = b[p] as usize;
        if b[p] & 0xC0 != 0 || p + y + 1 >= e || y + 1 >= name_size - name.len() {
            return None;
        }
        p += 1;
        for x in 0..y {
            name.push(b[p + x].to_ascii_lowercase());
        }
        p += y;
    }
    if name.len() >= name_size {
        return None;
    }
    Some((if bptr { a + 2 } else { p + 1 }, name))
}

fn dns_skip_name(b: &[u8], a: &mut usize, len: &mut usize) -> bool {
    loop {
        if *len < 2 {
            return false;
        }
        if b[*a] & 0xC0 == 0xC0 {
            *a += 2;
            *len -= 2;
            break;
        }
        if b[*a] == 0 {
            *a += 1;
            *len -= 1;
            break;
        }
        let l = b[*a] as usize + 1;
        if *len < l {
            return false;
        }
        *len -= l;
        *a += l;
    }
    true
}

fn feed_dns_response(b: &[u8]) -> bool {
    let p = params();
    if !p.cache_hostname {
        return true;
    }
    let mut len = b.len();
    let qcount = (b[4] as u16) << 8 | b[5] as u16;
    let acount = (b[6] as u16) << 8 | b[7] as u16;
    if qcount == 0 || len < 12 || b[2] & 0x80 == 0 {
        return false;
    }
    if acount == 0 {
        dlog!("skipping DNS response without answer\n");
        return false;
    }
    let e = b.len();
    let mut a = 12usize;
    len -= 12;
    let mut name: Vec<u8> = Vec::new();
    for _ in 0..qcount {
        if !name.is_empty() {
            return false;
        }
        let Some((pp, n)) = dns_extract_name(b, a, e, 256) else {
            return false;
        };
        name = n;
        len = len.wrapping_sub(pp - a);
        if len < 4 || b[pp + 2] != 0 || b[pp + 3] != 1 {
            return false;
        }
        let typ = pntoh16(&b[pp..]);
        if typ != 1 && typ != 28 {
            dlog!("skipping DNS query type {} for '{}'\n", typ, hs(&name));
            return false;
        } else {
            dlog!("DNS query type {} for '{}'\n", typ, hs(&name));
        }
        a = pp + 4;
        len -= 4;
    }
    if name.is_empty() {
        return false;
    }
    for _ in 0..acount {
        if !dns_skip_name(b, &mut a, &mut len) {
            return false;
        }
        if len < 10 {
            return false;
        }
        let dlen = (b[a + 8] as usize) << 8 | b[a + 9] as usize;
        if len < dlen + 10 {
            return false;
        }
        if b[a + 2] == 0 && b[a + 3] == 1 {
            let typ = pntoh16(&b[a..]);
            match typ {
                1 => {
                    if dlen == 4 {
                        dlog!(
                            "DNS response type {} : {}\n",
                            typ,
                            ntop4(&b[a + 10..a + 14])
                        );
                        let mut ip = [0u8; 4];
                        ip.copy_from_slice(&b[a + 10..a + 14]);
                        ipcache_put_hostname(Some(&ip), None, &name, false);
                    }
                }
                28 => {
                    if dlen == 16 {
                        dlog!(
                            "DNS response type {} : {}\n",
                            typ,
                            ntop6(&b[a + 10..a + 26])
                        );
                        let mut ip = [0u8; 16];
                        ip.copy_from_slice(&b[a + 10..a + 26]);
                        ipcache_put_hostname(None, Some(&ip), &name, false);
                    }
                }
                _ => dlog!("skipping DNS response type {}\n", typ),
            }
        }
        len -= 10 + dlen;
        a += 10 + dlen;
    }
    true
}

fn udp_standard_probes() -> Vec<Probe> {
    vec![
        Probe {
            l7p: L7P_QUIC_INITIAL,
            l7: L7_QUIC,
            check: is_quic_initial,
            l7match: false,
        },
        Probe {
            l7p: L7P_DISCORD_IP_DISCOVERY,
            l7: L7_DISCORD,
            check: is_discord_ip_discovery_request,
            l7match: false,
        },
        Probe {
            l7p: L7P_STUN,
            l7: L7_STUN,
            check: is_stun_message,
            l7match: false,
        },
        Probe {
            l7p: L7P_DNS_QUERY,
            l7: L7_DNS,
            check: is_dns_query,
            l7match: false,
        },
        Probe {
            l7p: L7P_DNS_RESPONSE,
            l7: L7_DNS,
            check: is_dns_response,
            l7match: false,
        },
        Probe {
            l7p: L7P_DHT,
            l7: L7_DHT,
            check: is_dht,
            l7match: false,
        },
        Probe {
            l7p: L7P_DTLS_CLIENT_HELLO,
            l7: L7_DTLS,
            check: is_dtls_client_hello,
            l7match: false,
        },
        Probe {
            l7p: L7P_DTLS_SERVER_HELLO,
            l7: L7_DTLS,
            check: is_dtls_server_hello,
            l7match: false,
        },
        Probe {
            l7p: L7P_UTP_BT_HANDSHAKE,
            l7: L7_UTP_BT,
            check: is_utp_bt_handshake,
            l7match: false,
        },
        Probe {
            l7p: L7P_WIREGUARD_INITIATION,
            l7: L7_WIREGUARD,
            check: is_wireguard_handshake_initiation,
            l7match: false,
        },
        Probe {
            l7p: L7P_WIREGUARD_RESPONSE,
            l7: L7_WIREGUARD,
            check: is_wireguard_handshake_response,
            l7match: false,
        },
        Probe {
            l7p: L7P_WIREGUARD_COOKIE,
            l7: L7_WIREGUARD,
            check: is_wireguard_handshake_cookie,
            l7match: false,
        },
        Probe {
            l7p: L7P_WIREGUARD_KEEPALIVE,
            l7: L7_WIREGUARD,
            check: is_wireguard_keepalive,
            l7match: false,
        },
        Probe {
            l7p: L7P_WIREGUARD_DATA,
            l7: L7_WIREGUARD,
            check: is_wireguard_data,
            l7match: true,
        },
    ]
}

fn quic_reasm_cancel(ct: Option<&CtrackRef>, reason: &str) {
    reasm_client_cancel(ct);
    dlog!("{}\n", reason);
}

#[allow(clippy::too_many_arguments)]
fn udp_packet_play(
    replay_piece: u32,
    replay_count: u32,
    reasm_offset: usize,
    fwmark: u32,
    ifin: Option<&str>,
    ifout: Option<&str>,
    tpos: Option<&CtrackPositions>,
    pkt: &[u8],
    dis: &Dissect,
    out: &mut Out,
) -> u8 {
    let mut ps = match play_prolog(pkt, dis, tpos, replay_count != 0, ifin, ifout, fwmark) {
        Ok(ps) => ps,
        Err(v) => return v,
    };
    let p = params();
    let desync_fwmark = fwmark | p.desync_fwmark;
    let payload = &pkt[dis.payload..dis.payload + dis.len_payload];
    let mut ddata: Option<Vec<u8>> = None;

    let early = (|| -> Option<u8> {
        if dis.len_payload == 0 {
            return None;
        }
        udp_standard_protocol_probe(
            payload,
            ps.ctrack.as_ref(),
            &mut ps.l7proto,
            &mut ps.l7payload,
        );
        if !ps.rev && ps.l7payload == L7P_QUIC_INITIAL {
            let mut pclean: Option<Vec<u8>> = if replay_count != 0 {
                ps.ctrack_replay.as_ref().map(|c| {
                    let c = c.borrow();
                    c.reasm_client.packet[..c.reasm_client.size_present].to_vec()
                })
            } else {
                quic_decrypt_initial(payload, UDP_MAX_REASM)
            };
            // `clean` in C is the freshly decrypted buffer (or uninitialised in replay mode)
            let clean_orig = pclean.clone().unwrap_or_default();
            match pclean.take() {
                Some(mut clean) => {
                    let reasm_disable = l7_payload_match(ps.l7payload, p.reasm_payload_disable);
                    if let Some(ct) = ps.ctrack.clone()
                        && !reasm_disable
                        && !ct.borrow().reasm_client.is_empty()
                    {
                        if ct.borrow().reasm_client.has_space(clean.len()) {
                            reasm_client_feed(Some(&ct), IPPROTO_UDP, &clean_orig);
                            let c = ct.borrow();
                            clean = c.reasm_client.packet[..c.reasm_client.size_present].to_vec();
                        } else {
                            dlog!("QUIC reasm is too long. cancelling.\n");
                            return None;
                        }
                    }
                    match quic_defrag_crypto(&clean, UDP_MAX_REASM) {
                        Some((defrag, full)) => {
                            if full {
                                dlog!("QUIC initial contains CRYPTO with full fragment coverage\n");
                                let hello = is_quic_crypto_hello(&defrag);
                                let req_full = hello
                                    .is_some_and(|(o, l)| is_tls_handshake_full(&defrag[o..o + l]));
                                dlog!(
                                    "{}",
                                    if hello.is_some() {
                                        if req_full {
                                            "packet contains full TLS ClientHello\n"
                                        } else {
                                            "packet contains partial TLS ClientHello\n"
                                        }
                                    } else {
                                        "packet does not contain TLS ClientHello\n"
                                    }
                                );
                                if req_full && let Some((o, l)) = hello {
                                    tls_debug_handshake(&defrag[o..o + l]);
                                }
                                if let Some(ct) = ps.ctrack.clone()
                                    && !reasm_disable
                                {
                                    if hello.is_some()
                                        && !req_full
                                        && ct.borrow().reasm_client.is_empty()
                                        && !reasm_client_start(
                                            Some(&ct),
                                            IPPROTO_UDP,
                                            L7P_QUIC_INITIAL,
                                            UDP_MAX_REASM,
                                            UDP_MAX_REASM,
                                            &clean_orig,
                                        )
                                    {
                                        return None;
                                    }
                                    if !ct.borrow().reasm_client.is_empty() {
                                        let pos = ct.borrow().pos;
                                        let rp = RawPacket {
                                            dst: ps.ep.dst,
                                            ifin: crate::conntrack::ifname_copy(ifin),
                                            ifout: crate::conntrack::ifname_copy(ifout),
                                            fwmark_orig: fwmark,
                                            fwmark: desync_fwmark,
                                            packet: pkt[..dis.len_pkt].to_vec(),
                                            len_payload: dis.len_payload,
                                            tpos: Some(pos),
                                            server_side: false,
                                        };
                                        if ct.borrow_mut().delayed.push(rp) {
                                            dlog!(
                                                "DELAY desync until reasm is complete (#{})\n",
                                                ct.borrow().delayed.count()
                                            );
                                        } else {
                                            dlog_err!("rawpacket_queue failed !\n");
                                            return None;
                                        }
                                        if req_full {
                                            let mut q =
                                                std::mem::take(&mut ct.borrow_mut().delayed);
                                            replay_queue(&mut q);
                                            ct.borrow_mut().delayed.max_packets = q.max_packets;
                                            reasm_client_fin(Some(&ct));
                                        }
                                        let max = out.max;
                                        return Some(ct_new_postnat_fix(
                                            Some(&ct),
                                            pkt,
                                            dis,
                                            out.buf,
                                            max,
                                        ));
                                    }
                                }
                                match hello {
                                    Some((o, l)) => {
                                        let d = defrag[o..o + l].to_vec();
                                        let h =
                                            tls_hello_extract_host_from_handshake(&d, 256, true);
                                        ps.have_host = h.is_some();
                                        ps.host = h.unwrap_or_default();
                                        ddata = Some(d);
                                    }
                                    None => quic_reasm_cancel(
                                        ps.ctrack.as_ref(),
                                        "QUIC initial without ClientHello",
                                    ),
                                }
                            } else {
                                dlog!(
                                    "QUIC initial contains CRYPTO with partial fragment coverage\n"
                                );
                                if let Some(ct) = ps.ctrack.clone()
                                    && !reasm_disable
                                {
                                    if ct.borrow().reasm_client.is_empty()
                                        && !reasm_client_start(
                                            Some(&ct),
                                            IPPROTO_UDP,
                                            L7P_QUIC_INITIAL,
                                            UDP_MAX_REASM,
                                            UDP_MAX_REASM,
                                            &clean_orig,
                                        )
                                    {
                                        return None;
                                    }
                                    let pos = ct.borrow().pos;
                                    let rp = RawPacket {
                                        dst: ps.ep.dst,
                                        ifin: crate::conntrack::ifname_copy(ifin),
                                        ifout: crate::conntrack::ifname_copy(ifout),
                                        fwmark_orig: fwmark,
                                        fwmark: desync_fwmark,
                                        packet: pkt[..dis.len_pkt].to_vec(),
                                        len_payload: dis.len_payload,
                                        tpos: Some(pos),
                                        server_side: false,
                                    };
                                    if ct.borrow_mut().delayed.push(rp) {
                                        dlog!(
                                            "DELAY desync until reasm is complete (#{})\n",
                                            ct.borrow().delayed.count()
                                        );
                                    } else {
                                        dlog_err!("rawpacket_queue failed !\n");
                                        return None;
                                    }
                                    let max = out.max;
                                    return Some(ct_new_postnat_fix(
                                        Some(&ct),
                                        pkt,
                                        dis,
                                        out.buf,
                                        max,
                                    ));
                                }
                                quic_reasm_cancel(
                                    ps.ctrack.as_ref(),
                                    "QUIC initial fragmented CRYPTO",
                                );
                            }
                        }
                        None => quic_reasm_cancel(
                            ps.ctrack.as_ref(),
                            "QUIC initial defrag CRYPTO failed",
                        ),
                    }
                }
                None => quic_reasm_cancel(ps.ctrack.as_ref(), "QUIC initial decryption failed"),
            }
        }
        if ps.l7payload == L7P_DNS_RESPONSE {
            feed_dns_response(payload);
        }
        None
    })();
    if let Some(v) = early {
        return v;
    }
    reasm_client_cancel(ps.ctrack.as_ref());
    if dp_rediscovery(&mut ps, dis) {
        // INFALLIBLE: dp_rediscovery returns true only with a profile
        let Some(dp) = ps.dp.clone() else {
            return VERDICT_PASS;
        };
        ps.verdict = desync(
            &dp,
            fwmark,
            ifin,
            ifout,
            ps.rev_fixed,
            ps.ctrack_replay.clone(),
            tpos,
            ps.l7payload,
            ps.l7proto,
            pkt,
            dis,
            a4(&ps.ep.sdip4),
            a6(&ps.ep.sdip6),
            ps.ep.sdport,
            out,
            replay_piece,
            replay_count,
            reasm_offset,
            None,
            ddata.as_deref(),
        );
    }
    if !ps.rev_fixed && (ps.verdict & VERDICT_MASK) == VERDICT_DROP {
        let max = out.max;
        ct_new_postnat_fix(ps.ctrack.as_ref(), pkt, dis, out.buf, max)
    } else {
        ps.verdict
    }
}

fn udp_standard_protocol_probe(d: &[u8], ct: Option<&CtrackRef>, l7: &mut u32, l7p: &mut u32) {
    protocol_probe(&udp_standard_probes(), d, ct, l7, l7p);
}

fn ip_addrs(pkt: &[u8], dis: &Dissect, src: bool) -> (Option<[u8; 4]>, Option<[u8; 16]>) {
    if dis.ip {
        let o = if src { 12 } else { 16 };
        let mut a = [0u8; 4];
        a.copy_from_slice(&pkt[o..o + 4]);
        (Some(a), None)
    } else if dis.ip6 {
        let o = if src { 8 } else { 24 };
        let mut a = [0u8; 16];
        a.copy_from_slice(&pkt[o..o + 16]);
        (None, Some(a))
    } else {
        (None, None)
    }
}

fn icmp_packet(
    fwmark: u32,
    ifin: Option<&str>,
    ifout: Option<&str>,
    pkt: &[u8],
    dis: &Dissect,
    out: &mut Out,
) -> u8 {
    if dis.ip == dis.ip6 {
        return VERDICT_PASS;
    }
    let p = params();
    // INFALLIBLE: icmp packets carry an icmp header offset
    let io = dis.icmp.unwrap_or(0);
    let (ity, icode) = (pkt[io], pkt[io + 1]);
    let mut dp: Option<ProfileRef> = None;
    let mut l7payload = L7P_ICMP;
    let mut ctrack: Option<CtrackRef> = None;
    let mut rev = false;
    let attached = matches!(ity, 3 | 11 | 12 | 5 | 1 | 2 | 4);
    if attached {
        let att = &pkt[dis.payload..dis.payload + dis.len_payload];
        let adis = proto_dissect_l3l4(att, true);
        if !adis.ip && !adis.ip6 {
            dlog!("attached packet is invalid\n");
        } else {
            l7payload = if adis.ip { L7P_IPV4 } else { L7P_IPV6 };
            dlog!("attached packet\n");
            packet_debug(false, att, &adis);
            let found = p.conntrack.borrow().double_search(att, &adis);
            match found {
                Some((ct, r)) => {
                    rev = !r;
                    dlog!("found conntrack entry. inverted reverse={}\n", rev as u8);
                    {
                        let c = ct.borrow();
                        if c.dp_search_complete
                            && let Some(d) = &c.dp
                        {
                            dp = Some(d.clone());
                            let db = d.borrow();
                            dlog!(
                                "using desync profile {} ({}) from conntrack entry\n",
                                db.n,
                                db.name_str()
                            );
                        }
                    }
                    ctrack = Some(ct);
                }
                None => dlog!("conntrack entry not found\n"),
            }
        }
    }
    let rev_fixed = if ctrack.is_some() {
        rev ^ p.server
    } else {
        rev = ifin.is_some_and(|s| !s.is_empty()) && ifout.is_none_or(|s| s.is_empty());
        rev
    };
    let mut ifname = if rev { ifin } else { ifout };
    let mut ssid = ifname
        .and_then(crate::wlan::ssid_search_ifname)
        .map(String::into_bytes);
    if let Some(s) = &ssid {
        dlog!("found ssid for {} : {}\n", ifname.unwrap_or(""), hs(s));
    } else if ctrack.is_none() {
        ifname = if rev { ifout } else { ifin };
        ssid = ifname
            .and_then(crate::wlan::ssid_search_ifname)
            .map(String::into_bytes);
        if let Some(s) = &ssid {
            dlog!("found ssid for {} : {}\n", ifname.unwrap_or(""), hs(s));
        }
    }
    let (d4, d6) = ip_addrs(pkt, dis, false);
    let (s4, s6) = ip_addrs(pkt, dis, true);
    if dp.is_none() {
        let mut hip = false;
        let mut hostname: Option<Vec<u8>> = None;
        if let Some(h) = ctrack.as_ref().and_then(|c| {
            let c = c.borrow();
            c.hostname.clone().map(|h| (h, c.hostname_is_ip))
        }) {
            hostname = Some(h.0);
            hip = h.1;
        } else if let Some((h, i)) = ipcache_get_hostname(a4(&d4), a6(&d6))
            .or_else(|| ipcache_get_hostname(a4(&s4), a6(&s6)))
        {
            hostname = Some(h);
            hip = i;
        }
        dp = dp_find(
            dis.proto,
            a4(&d4),
            a6(&d6),
            a4(&s4),
            a6(&s6),
            0,
            ity,
            icode,
            hostname.as_deref(),
            hip,
            L7_UNKNOWN,
            ssid.as_deref(),
            fwmark,
            None,
        );
        if dp.is_none() {
            dlog!("matching desync profile not found\n");
            return VERDICT_PASS;
        }
    }
    let sd6 = if dis.ip6 {
        if rev_fixed { s6 } else { d6 }
    } else {
        None
    };
    let sd4 = if dis.ip {
        if rev_fixed { s4 } else { d4 }
    } else {
        None
    };
    let l7 = ctrack.as_ref().map_or(L7_UNKNOWN, |c| c.borrow().l7proto);
    // INFALLIBLE: dp is Some here
    let Some(dp) = dp else { return VERDICT_PASS };
    desync(
        &dp,
        fwmark,
        ifin,
        ifout,
        rev_fixed,
        ctrack,
        None,
        l7payload,
        l7,
        pkt,
        dis,
        a4(&sd4),
        a6(&sd6),
        0,
        out,
        0,
        0,
        0,
        None,
        None,
    )
}

fn ip_packet(
    fwmark: u32,
    ifin: Option<&str>,
    ifout: Option<&str>,
    pkt: &[u8],
    dis: &Dissect,
    out: &mut Out,
) -> u8 {
    if dis.ip == dis.ip6 {
        return VERDICT_PASS;
    }
    let mut ssid = ifin
        .and_then(crate::wlan::ssid_search_ifname)
        .map(String::into_bytes);
    if let Some(s) = &ssid {
        dlog!("found ssid for {} : {}\n", ifin.unwrap_or(""), hs(s));
    } else {
        ssid = ifout
            .and_then(crate::wlan::ssid_search_ifname)
            .map(String::into_bytes);
        if let Some(s) = &ssid {
            dlog!("found ssid for {} : {}\n", ifout.unwrap_or(""), hs(s));
        }
    }
    let (d4, d6) = ip_addrs(pkt, dis, false);
    let (s4, s6) = ip_addrs(pkt, dis, true);
    let mut hip = false;
    let mut hostname = None;
    if let Some((h, i)) =
        ipcache_get_hostname(a4(&d4), a6(&d6)).or_else(|| ipcache_get_hostname(a4(&s4), a6(&s6)))
    {
        hostname = Some(h);
        hip = i;
    }
    let Some(dp) = dp_find(
        dis.proto,
        a4(&d4),
        a6(&d6),
        a4(&s4),
        a6(&s6),
        0,
        0xFF,
        0xFF,
        hostname.as_deref(),
        hip,
        L7_UNKNOWN,
        ssid.as_deref(),
        fwmark,
        None,
    ) else {
        dlog!("matching desync profile not found\n");
        return VERDICT_PASS;
    };
    let rev = ifin.is_some_and(|s| !s.is_empty()) && ifout.is_none_or(|s| s.is_empty());
    let sd6 = if dis.ip6 {
        if rev { s6 } else { d6 }
    } else {
        None
    };
    let sd4 = if dis.ip {
        if rev { s4 } else { d4 }
    } else {
        None
    };
    desync(
        &dp,
        fwmark,
        ifin,
        ifout,
        rev,
        None,
        None,
        L7P_UNKNOWN,
        L7_UNKNOWN,
        pkt,
        dis,
        a4(&sd4),
        a6(&sd6),
        0,
        out,
        0,
        0,
        0,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn packet_play(
    replay_piece: u32,
    replay_count: u32,
    reasm_offset: usize,
    fwmark: u32,
    ifin: Option<&str>,
    ifout: Option<&str>,
    tpos: Option<&CtrackPositions>,
    pkt: &[u8],
    out: &mut Out,
) -> u8 {
    let dis = proto_dissect_l3l4(pkt, false);
    if dis.ip != dis.ip6 {
        packet_debug(replay_count != 0, pkt, &dis);
        if dis.tcp.is_some() {
            tcp_packet_play(
                replay_piece,
                replay_count,
                reasm_offset,
                fwmark,
                ifin,
                ifout,
                tpos,
                pkt,
                &dis,
                out,
            )
        } else if dis.udp.is_some() {
            udp_packet_play(
                replay_piece,
                replay_count,
                reasm_offset,
                fwmark,
                ifin,
                ifout,
                tpos,
                pkt,
                &dis,
                out,
            )
        } else if dis.icmp.is_some() {
            icmp_packet(fwmark, ifin, ifout, pkt, &dis, out)
        } else {
            ip_packet(fwmark, ifin, ifout, pkt, &dis, out)
        }
    } else {
        dlog!("invalid packet - neither ipv4 or ipv6\n");
        VERDICT_PASS
    }
}

/// dpi_desync_packet: returns verdict; modified packet (if any) goes into `modp`
/// (its capacity limit is `mod_max`, like the C len_mod_pkt).
pub fn dpi_desync_packet(
    fwmark: u32,
    ifin: Option<&str>,
    ifout: Option<&str>,
    pkt: &[u8],
    modp: &mut Vec<u8>,
    mod_max: usize,
) -> u8 {
    let p = params();
    p.ipcache
        .borrow_mut()
        .purge_rate_limited(p.ipcache_lifetime as i64);
    let mut out = Out {
        buf: modp,
        max: mod_max,
    };
    packet_play(0, 0, 0, fwmark, ifin, ifout, None, pkt, &mut out)
}

fn replay_queue(q: &mut RawPacketQueue) -> bool {
    let count = q.count() as u32;
    let mut offset = 0usize;
    let mut seq0 = 0u32;
    let mut b = true;
    let mut i = 0u32;
    while let Some(rp) = q.pop() {
        let bseq = rp.tpos.is_some_and(|t| t.ipproto == IPPROTO_TCP);
        if bseq {
            // INFALLIBLE: bseq implies tpos
            if let Some(t) = &rp.tpos {
                let pos = if rp.server_side { &t.server } else { &t.client };
                if i != 0 {
                    offset = pos.seq_last.wrapping_sub(seq0) as usize;
                } else {
                    seq0 = pos.seq_last;
                }
            }
        }
        dlog!("REPLAYING delayed packet #{} offset {}\n", i + 1, offset);
        let mut m: Vec<u8> = Vec::new();
        let ifin = if rp.ifin.is_empty() {
            Some("")
        } else {
            Some(rp.ifin.as_str())
        };
        let ifout = if rp.ifout.is_empty() {
            Some("")
        } else {
            Some(rp.ifout.as_str())
        };
        let v = {
            let mut out = Out {
                buf: &mut m,
                max: RECONSTRUCT_MAX_SIZE,
            };
            packet_play(
                i,
                count,
                offset,
                rp.fwmark_orig,
                ifin,
                ifout,
                rp.tpos.as_ref(),
                &rp.packet,
                &mut out,
            )
        };
        let ifo = if rp.ifout.is_empty() {
            None
        } else {
            Some(rp.ifout.as_str())
        };
        match v & VERDICT_MASK {
            VERDICT_MODIFY => {
                dlog!("SENDING delayed packet #{} modified\n", i + 1);
                b &= rawsend(&rp.dst, rp.fwmark, ifo, &m);
            }
            VERDICT_PASS => {
                dlog!("SENDING delayed packet #{} unmodified\n", i + 1);
                b &= rawsend(&rp.dst, rp.fwmark, ifo, &rp.packet);
            }
            VERDICT_DROP => dlog!("DROPPING delayed packet #{}\n", i + 1),
            _ => {}
        }
        if !bseq {
            offset += rp.len_payload;
        }
        i += 1;
    }
    b
}
