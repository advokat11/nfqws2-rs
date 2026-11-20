//! Port of checksum.c. Internet checksums over byte slices.
//! Results are returned as the 16-bit value whose big-endian bytes go into the header,
//! which is what the C code stores in memory.

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMPV6: u8 = 58;

/// One's complement sum of 16-bit big-endian words, not inverted, folded to 16 bits.
pub fn csum_partial(buf: &[u8]) -> u16 {
    let mut sum: u64 = 0;
    let mut chunks = buf.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u64;
    }
    if let [b] = chunks.remainder() {
        sum += (*b as u64) << 8;
    }
    fold(sum)
}

fn fold(mut x: u64) -> u16 {
    while x >> 16 != 0 {
        x = (x & 0xFFFF) + (x >> 16);
    }
    x as u16
}

fn pseudo_sum(src: &[u8], dst: &[u8], len: usize, proto: u8) -> u64 {
    let mut s: u64 = 0;
    for c in src.chunks_exact(2).chain(dst.chunks_exact(2)) {
        s += u16::from_be_bytes([c[0], c[1]]) as u64;
    }
    let l = (len as u32).wrapping_add(proto as u32);
    s += (l >> 16) as u64 + (l & 0xFFFF) as u64;
    s
}

fn magic(src: &[u8], dst: &[u8], len: usize, proto: u8, sum: u16) -> u16 {
    !fold(pseudo_sum(src, dst, len, proto) + sum as u64)
}

pub fn ip4_compute_csum(buf: &[u8]) -> u16 {
    !csum_partial(buf)
}

/// Fix the IPv4 header checksum of the header at the start of `ip`.
pub fn ip4_fix_checksum(ip: &mut [u8]) {
    let hl = ((ip[0] & 0x0F) as usize) << 2;
    ip[10] = 0;
    ip[11] = 0;
    let hl = hl.min(ip.len());
    let c = ip4_compute_csum(&ip[..hl]);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
}

/// `l4` is the transport header + payload, `len` bytes are summed.
fn l4_fix(
    l4: &mut [u8],
    len: usize,
    src: &[u8],
    dst: &[u8],
    proto: u8,
    csum_off: usize,
    udp: bool,
) {
    if l4.len() < csum_off + 2 {
        return;
    }
    l4[csum_off] = 0;
    l4[csum_off + 1] = 0;
    let len_sum = len.min(l4.len());
    let mut c = magic(src, dst, len, proto, csum_partial(&l4[..len_sum]));
    if udp && c == 0 {
        c = 0xFFFF;
    }
    l4[csum_off..csum_off + 2].copy_from_slice(&c.to_be_bytes());
}

pub fn tcp_fix_checksum_addrs(tcp: &mut [u8], len: usize, src: &[u8], dst: &[u8]) {
    l4_fix(tcp, len, src, dst, IPPROTO_TCP, 16, false);
}

pub fn udp_fix_checksum_addrs(udp: &mut [u8], len: usize, src: &[u8], dst: &[u8]) {
    l4_fix(udp, len, src, dst, IPPROTO_UDP, 6, true);
}

pub fn icmp4_fix_checksum(icmp: &mut [u8], len: usize) {
    if icmp.len() < 4 {
        return;
    }
    icmp[2] = 0;
    icmp[3] = 0;
    let c = !csum_partial(&icmp[..len.min(icmp.len())]);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
}

pub fn icmp6_fix_checksum(icmp: &mut [u8], len: usize, src: &[u8], dst: &[u8]) {
    l4_fix(icmp, len, src, dst, IPPROTO_ICMPV6, 2, false);
}

/// Addresses of the enclosing IP header: v4 (4-byte) or v6 (16-byte) src/dst.
#[derive(Clone, Copy)]
pub enum L3Addrs<'a> {
    V4(&'a [u8], &'a [u8]),
    V6(&'a [u8], &'a [u8]),
    None,
}

/// Extract address slices from a packet buffer given ip/ip6 header offsets.
pub fn l3_addrs(pkt: &[u8], ip4: Option<usize>, ip6: Option<usize>) -> ([u8; 16], [u8; 16], u8) {
    let mut s = [0u8; 16];
    let mut d = [0u8; 16];
    if let Some(o) = ip4 {
        s[..4].copy_from_slice(&pkt[o + 12..o + 16]);
        d[..4].copy_from_slice(&pkt[o + 16..o + 20]);
        (s, d, 4)
    } else if let Some(o) = ip6 {
        s.copy_from_slice(&pkt[o + 8..o + 24]);
        d.copy_from_slice(&pkt[o + 24..o + 40]);
        (s, d, 6)
    } else {
        (s, d, 0)
    }
}

pub fn tcp_fix_checksum(tcp: &mut [u8], len: usize, a: L3Addrs) {
    match a {
        L3Addrs::V4(s, d) | L3Addrs::V6(s, d) => tcp_fix_checksum_addrs(tcp, len, s, d),
        L3Addrs::None => {}
    }
}

pub fn udp_fix_checksum(udp: &mut [u8], len: usize, a: L3Addrs) {
    match a {
        L3Addrs::V4(s, d) | L3Addrs::V6(s, d) => udp_fix_checksum_addrs(udp, len, s, d),
        L3Addrs::None => {}
    }
}

pub fn icmp_fix_checksum(icmp: &mut [u8], len: usize, a: L3Addrs) {
    match a {
        L3Addrs::V6(s, d) => icmp6_fix_checksum(icmp, len, s, d),
        _ => icmp4_fix_checksum(icmp, len),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv4_header() {
        let mut h = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        ip4_fix_checksum(&mut h);
        assert_eq!(&h[10..12], &[0xb8, 0x61]);
    }
}
