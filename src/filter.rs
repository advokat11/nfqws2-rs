//! Port of filter.c: port, icmp, ip-protocol filters, packet ranges, CIDRs.

use crate::helpers::{inet_pton4, inet_pton6, ntop4, ntop6, scan_u};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortFilter {
    pub from: u16,
    pub to: u16,
    pub neg: bool,
}

pub fn pf_match(port: u16, pf: &PortFilter) -> bool {
    port != 0 && (((pf.from == 0 && pf.to == 0) || (port >= pf.from && port <= pf.to)) ^ pf.neg)
}

pub fn pf_parse(s: &str) -> Option<PortFilter> {
    let mut s = s.as_bytes();
    if s == b"*" {
        return Some(PortFilter {
            from: 1,
            to: 0xFFFF,
            neg: false,
        });
    }
    let mut pf = PortFilter::default();
    if s.first() == Some(&b'~') {
        pf.neg = true;
        s = &s[1..];
    }
    // "%u-%u%c" == 2
    let range = scan_u(s).and_then(|(v1, r)| {
        let r = r.strip_prefix(b"-")?;
        let (v2, r) = scan_u(r)?;
        r.is_empty().then_some((v1, v2))
    });
    if let Some((v1, v2)) = range {
        if v1 > 65535 || v2 > 65535 || v1 > v2 {
            return None;
        }
        pf.from = v1 as u16;
        pf.to = v2 as u16;
    } else if let Some((v1, r)) = scan_u(s) {
        if !r.is_empty() || v1 > 65535 {
            return None;
        }
        pf.from = v1 as u16;
        pf.to = v1 as u16;
    } else {
        return None;
    }
    if pf.from == 0 && pf.to == 0 {
        pf.neg = true;
    }
    Some(pf)
}

pub const FLTMODE_SKIP: u8 = 0;
pub const FLTMODE_ANY: u8 = 1;
pub const FLTMODE_FILTER: u8 = 2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IcmpFilter {
    pub mode: u8,
    pub typ: u8,
    pub code: u8,
    pub code_valid: bool,
}

fn fltmode_parse(s: &str) -> Option<u8> {
    match s {
        "*" => Some(FLTMODE_ANY),
        "-" => Some(FLTMODE_SKIP),
        _ => None,
    }
}

pub fn icf_match(typ: u8, code: u8, icf: &IcmpFilter) -> bool {
    icf.mode == FLTMODE_ANY
        || (icf.mode == FLTMODE_FILTER && icf.typ == typ && (!icf.code_valid || icf.code == code))
}

pub fn icf_parse(s: &str) -> Option<IcmpFilter> {
    let mut icf = IcmpFilter::default();
    if let Some(m) = fltmode_parse(s) {
        icf.mode = m;
        return Some(icf);
    }
    // sscanf("%u%c%u%c") count
    let b = s.as_bytes();
    let (u1, r) = scan_u(b)?;
    if r.is_empty() {
        if u1 > 0xFF {
            return None;
        }
        icf.typ = u1 as u8;
        icf.mode = FLTMODE_FILTER;
        return Some(icf);
    }
    let c1 = r[0];
    let (u2, r2) = scan_u(&r[1..])?; // count 2 => default branch => false
    if !r2.is_empty() {
        return None; // count 4
    }
    if c1 != b':' || u1 > 0xFF || u2 > 0xFF {
        return None;
    }
    icf.typ = u1 as u8;
    icf.code = u2 as u8;
    icf.code_valid = true;
    icf.mode = FLTMODE_FILTER;
    Some(icf)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IppFilter {
    pub mode: u8,
    pub proto: u8,
}

pub fn ipp_match(proto: u8, ipp: &IppFilter) -> bool {
    ipp.mode == FLTMODE_ANY || (ipp.mode == FLTMODE_FILTER && ipp.proto == proto)
}

pub fn ipp_parse(s: &str) -> Option<IppFilter> {
    if let Some(m) = fltmode_parse(s) {
        return Some(IppFilter {
            mode: m,
            proto: 0xFF,
        });
    }
    let (u1, r) = scan_u(s.as_bytes())?;
    if !r.is_empty() || u1 > 0xFF {
        return None;
    }
    Some(IppFilter {
        mode: FLTMODE_FILTER,
        proto: u1 as u8,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketPos {
    pub mode: u8,
    pub pos: u32,
}

pub const PACKET_POS_NEVER: PacketPos = PacketPos { mode: b'x', pos: 0 };
pub const PACKET_POS_ALWAYS: PacketPos = PacketPos { mode: b'a', pos: 0 };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketRange {
    pub from: PacketPos,
    pub to: PacketPos,
    pub upper_cutoff: bool,
}

pub const PACKET_RANGE_NEVER: PacketRange = PacketRange {
    from: PACKET_POS_NEVER,
    to: PACKET_POS_NEVER,
    upper_cutoff: false,
};
pub const PACKET_RANGE_ALWAYS: PacketRange = PacketRange {
    from: PACKET_POS_ALWAYS,
    to: PACKET_POS_ALWAYS,
    upper_cutoff: false,
};

fn packet_pos_parse(s: &[u8]) -> Option<PacketPos> {
    let m = *s.first()?;
    if !b"ndspbxa".contains(&m) {
        return None;
    }
    if m == b'x' || m == b'a' {
        return Some(PacketPos { mode: m, pos: 0 });
    }
    let (v, _) = scan_u(&s[1..])?;
    Some(PacketPos { mode: m, pos: v })
}

pub fn packet_range_parse(s: &str) -> Option<PacketRange> {
    let mut s = s.as_bytes();
    let mut r = PacketRange {
        from: PACKET_POS_ALWAYS,
        to: PACKET_POS_ALWAYS,
        upper_cutoff: false,
    };
    if matches!(s.first(), Some(b'-') | Some(b'<')) {
        r.from = PACKET_POS_ALWAYS;
        r.upper_cutoff = s[0] == b'<';
    } else {
        r.from = packet_pos_parse(s)?;
        if r.from.mode == b'x' {
            r.to = r.from;
            return Some(r);
        }
        let p = s
            .iter()
            .position(|&c| c == b'-')
            .or_else(|| s.iter().position(|&c| c == b'<'));
        match p {
            Some(p) => {
                s = &s[p..];
                r.upper_cutoff = s[0] == b'<';
            }
            None => {
                if r.from.mode == b'a' {
                    r.to = r.from;
                    return Some(r);
                }
                return None;
            }
        }
    }
    s = &s[1..];
    if !s.is_empty() {
        r.to = packet_pos_parse(s)?;
    } else {
        r.to = PACKET_POS_ALWAYS;
    }
    Some(r)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cidr4 {
    pub addr: [u8; 4],
    pub preflen: u8,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cidr6 {
    pub addr: [u8; 16],
    pub preflen: u8,
}

pub fn str_cidr4(c: &Cidr4) -> String {
    if c.preflen < 32 {
        format!("{}/{}", ntop4(&c.addr), c.preflen)
    } else {
        ntop4(&c.addr)
    }
}
pub fn str_cidr6(c: &Cidr6) -> String {
    if c.preflen < 128 {
        format!("{}/{}", ntop6(&c.addr), c.preflen)
    } else {
        ntop6(&c.addr)
    }
}

fn split_pref(s: &[u8], max: u32) -> Option<(&[u8], u8)> {
    match s.iter().position(|&c| c == b'/') {
        Some(p) => {
            let (plen, _) = scan_u(&s[p + 1..])?;
            if plen > max {
                return None;
            }
            Some((&s[..p], plen as u8))
        }
        None => Some((s, max as u8)),
    }
}

pub fn parse_cidr4(s: &[u8]) -> Option<Cidr4> {
    let (a, p) = split_pref(s, 32)?;
    Some(Cidr4 {
        addr: inet_pton4(a)?,
        preflen: p,
    })
}
pub fn parse_cidr6(s: &[u8]) -> Option<Cidr6> {
    let (a, p) = split_pref(s, 128)?;
    Some(Cidr6 {
        addr: inet_pton6(a)?,
        preflen: p,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges() {
        assert_eq!(
            packet_range_parse("n2-d5").unwrap().to,
            PacketPos { mode: b'd', pos: 5 }
        );
        assert!(packet_range_parse("n2").is_none());
        assert_eq!(packet_range_parse("a").unwrap(), PACKET_RANGE_ALWAYS);
        assert!(packet_range_parse("<s100").unwrap().upper_cutoff);
    }
    #[test]
    fn ports() {
        assert_eq!(
            pf_parse("80-443"),
            Some(PortFilter {
                from: 80,
                to: 443,
                neg: false
            })
        );
        assert_eq!(
            pf_parse("~0"),
            Some(PortFilter {
                from: 0,
                to: 0,
                neg: true
            })
        );
        assert!(pf_parse("443x").is_none());
    }
}
