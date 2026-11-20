//! Port of the Linux wlan SSID retrieval in darkmagic.c (nl80211 over generic netlink).
//! libmnl's message/attribute walking and validation rules are reproduced on a raw socket.

use crate::helpers::boottime;
use crate::log::{dlog_perror, dlog_perror_errno};
use std::cell::{Cell, RefCell};

const NETLINK_GENERIC: i32 = 16;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_NOOP: u16 = 1;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_MIN_TYPE: u16 = 0x10;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_MAX: u16 = 10;
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_CMD_GET_SCAN: u8 = 32;
const NL80211_ATTR_IFINDEX: u16 = 3;
const NL80211_ATTR_IFNAME: u16 = 4;
const NL80211_ATTR_SSID: u16 = 52;
const NL80211_ATTR_BSS: u16 = 47;
const NL80211_BSS_INFORMATION_ELEMENTS: u16 = 6;
const NL80211_BSS_STATUS: u16 = 9;
const MNL_SOCKET_BUFFER_SIZE: usize = 8192;
const CB_ERROR: i32 = -1;
const CB_STOP: i32 = 0;
const CB_OK: i32 = 1;

pub const WLAN_INTERFACE_MAX: usize = 16;

#[derive(Clone, Debug, Default)]
pub struct WlanInterface {
    pub ifindex: i32,
    pub ifname: String,
    pub ssid: Vec<u8>,
}

thread_local! {
    static SOCK: Cell<i32> = const { Cell::new(-1) };
    static FAMILY: Cell<u16> = const { Cell::new(0) };
    static LAST: Cell<i64> = const { Cell::new(0) };
    pub static WLANS: RefCell<Vec<WlanInterface>> = const { RefCell::new(Vec::new()) };
}

fn set_errno(e: i32) {
    // SAFETY: errno location is thread-local and always valid.
    unsafe { *libc::__errno_location() = e };
}

struct Attr<'a> {
    typ: u16,
    payload: &'a [u8],
}

/// Iterate attributes in `b` (mnl_attr_for_each semantics: stop at malformed attr).
fn attrs(b: &[u8]) -> Vec<Attr<'_>> {
    let mut v = Vec::new();
    let mut o = 0;
    while o + 4 <= b.len() {
        let len = u16::from_ne_bytes([b[o], b[o + 1]]) as usize;
        let typ = u16::from_ne_bytes([b[o + 2], b[o + 3]]) & 0x3fff;
        if len < 4 || o + len > b.len() {
            break;
        }
        v.push(Attr {
            typ,
            payload: &b[o + 4..o + len],
        });
        o += (len + 3) & !3;
    }
    v
}

/// mnl_attr_validate for fixed sized types: exact payload length.
fn validate_len(a: &Attr, exp: usize) -> bool {
    if a.payload.len() != exp {
        set_errno(libc::ERANGE);
        return false;
    }
    true
}

fn u32_of(p: &[u8]) -> u32 {
    u32::from_ne_bytes([p[0], p[1], p[2], p[3]])
}

fn put_attr(buf: &mut Vec<u8>, typ: u16, data: &[u8]) {
    let len = 4 + data.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&typ.to_ne_bytes());
    buf.extend_from_slice(data);
    while buf.len() % 4 != 0 {
        buf.push(0);
    }
}

/// netlink_genl_simple_transact. `cb` returns MNL_CB_* for each data message (genl payload).
fn transact(
    sock: i32,
    typ: u16,
    flags: u16,
    cmd: u8,
    ver: u8,
    attrs_in: &[(u16, Vec<u8>)],
    cb: &mut dyn FnMut(&[u8]) -> i32,
) -> bool {
    let mut msg = vec![0u8; 16];
    msg.extend_from_slice(&[cmd, ver, 0, 0]);
    for (t, d) in attrs_in {
        put_attr(&mut msg, *t, d);
    }
    let len = msg.len() as u32;
    msg[0..4].copy_from_slice(&len.to_ne_bytes());
    msg[4..6].copy_from_slice(&typ.to_ne_bytes());
    msg[6..8].copy_from_slice(&flags.to_ne_bytes());
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: valid buffer and sockaddr.
    let r = unsafe {
        libc::sendto(
            sock,
            msg.as_ptr() as *const _,
            msg.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    };
    if r < 0 {
        dlog_perror("mnl_socket_sendto");
        return false;
    }
    let mut buf = vec![0u8; MNL_SOCKET_BUFFER_SIZE];
    loop {
        let mut from: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut fl = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        // SAFETY: valid buffers.
        let rd = unsafe {
            libc::recvfrom(
                sock,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                0,
                &mut from as *mut _ as *mut libc::sockaddr,
                &mut fl,
            )
        };
        if rd <= 0 {
            return false;
        }
        if from.nl_pid != 0 {
            set_errno(libc::ENOSPC);
            return false;
        }
        match cb_run(&buf[..rd as usize], cb) {
            CB_STOP => return true,
            CB_OK => {}
            _ => return false,
        }
    }
}

fn cb_run(b: &[u8], cb: &mut dyn FnMut(&[u8]) -> i32) -> i32 {
    let mut o = 0;
    let mut ret = CB_OK;
    while o + 16 <= b.len() {
        let len = u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as usize;
        if len < 16 || o + len > b.len() {
            break;
        }
        let typ = u16::from_ne_bytes([b[o + 4], b[o + 5]]);
        let m = &b[o..o + len];
        if typ >= NLMSG_MIN_TYPE {
            ret = cb(&m[16..]);
            if ret <= CB_STOP {
                return ret;
            }
        } else {
            match typ {
                NLMSG_NOOP => ret = CB_OK,
                NLMSG_ERROR => {
                    if len < 16 + 4 {
                        set_errno(libc::EBADMSG);
                        return CB_ERROR;
                    }
                    let err = i32::from_ne_bytes([m[16], m[17], m[18], m[19]]);
                    if err < 0 {
                        set_errno(-err);
                    } else {
                        set_errno(err);
                    }
                    return if err == 0 { CB_STOP } else { CB_ERROR };
                }
                NLMSG_DONE => return CB_STOP,
                _ => ret = CB_OK,
            }
        }
        o += (len + 3) & !3;
    }
    ret
}

/// mnl_attr_parse over the genl payload (skip the 4 byte genl header).
fn attr_parse(genl: &[u8], cb: &mut dyn FnMut(&Attr) -> i32) -> i32 {
    if genl.len() < 4 {
        return CB_OK;
    }
    for a in attrs(&genl[4..]) {
        let r = cb(&a);
        if r <= CB_STOP {
            return r;
        }
    }
    CB_OK
}

fn get_family_id(sock: i32) -> u16 {
    let mut id: u16 = 0;
    let ok = transact(
        sock,
        GENL_ID_CTRL,
        NLM_F_REQUEST | NLM_F_ACK,
        CTRL_CMD_GETFAMILY,
        1,
        &[(CTRL_ATTR_FAMILY_NAME, b"nl80211\0".to_vec())],
        &mut |g| {
            attr_parse(g, &mut |a| {
                if a.typ > CTRL_ATTR_MAX {
                    set_errno(libc::EOPNOTSUPP);
                    dlog_perror("mnl_attr_type_valid");
                    return CB_ERROR;
                }
                if a.typ == CTRL_ATTR_FAMILY_ID {
                    if !validate_len(a, 2) {
                        dlog_perror("mnl_attr_validate(family_id)");
                        return CB_ERROR;
                    }
                    id = u16::from_ne_bytes([a.payload[0], a.payload[1]]);
                }
                CB_OK
            })
        },
    );
    if ok {
        id
    } else {
        0
    }
}

fn cstr_bytes(p: &[u8]) -> &[u8] {
    &p[..p.iter().position(|&c| c == 0).unwrap_or(p.len())]
}

fn wlan_info(sock: i32, fam: u16, out: &mut Vec<WlanInterface>, req_ssid: bool) -> bool {
    transact(
        sock,
        fam,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP,
        NL80211_CMD_GET_INTERFACE,
        0,
        &[],
        &mut |g| {
            if out.len() >= WLAN_INTERFACE_MAX {
                return CB_OK;
            }
            let mut w = WlanInterface::default();
            let r = attr_parse(g, &mut |a| {
                match a.typ {
                    NL80211_ATTR_IFINDEX => {
                        if !validate_len(a, 4) {
                            dlog_perror("mnl_attr_validate(ifindex)");
                            return CB_ERROR;
                        }
                        w.ifindex = u32_of(a.payload) as i32;
                    }
                    NL80211_ATTR_SSID => {
                        w.ssid = a.payload[..a.payload.len().min(32)].to_vec();
                        w.ssid = cstr_bytes(&w.ssid).to_vec();
                    }
                    NL80211_ATTR_IFNAME => {
                        if a.payload.is_empty() {
                            set_errno(libc::ERANGE);
                            dlog_perror("mnl_attr_validate(ifname)");
                            return CB_ERROR;
                        }
                        let s = cstr_bytes(a.payload);
                        w.ifname = String::from_utf8_lossy(&s[..s.len().min(15)]).into_owned();
                    }
                    _ => {}
                }
                CB_OK
            });
            if r >= 0 && (!req_ssid || !w.ssid.is_empty()) && !w.ifname.is_empty() && w.ifindex != 0
            {
                out.push(w);
            }
            r
        },
    )
}

fn find_ie(b: &[u8], ie: u8) -> Option<&[u8]> {
    let mut o = 0;
    while b.len() - o >= 2 {
        let l = b[o + 1] as usize;
        if b.len() - o < 2 + l {
            break;
        }
        if b[o] == ie {
            return Some(&b[o..]);
        }
        o += l + 2;
    }
    None
}

fn scan_info(sock: i32, fam: u16, out: &mut Vec<WlanInterface>) -> bool {
    let mut all = Vec::new();
    if !wlan_info(sock, fam, &mut all, false) {
        return false;
    }
    out.clear();
    for w0 in &all {
        let ok = transact(
            sock,
            fam,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP,
            NL80211_CMD_GET_SCAN,
            0,
            &[(
                NL80211_ATTR_IFINDEX,
                (w0.ifindex as u32).to_ne_bytes().to_vec(),
            )],
            &mut |g| {
                if out.len() >= WLAN_INTERFACE_MAX {
                    return CB_OK;
                }
                let mut w = WlanInterface::default();
                let r = attr_parse(g, &mut |a| {
                    match a.typ {
                        NL80211_ATTR_IFINDEX => {
                            if !validate_len(a, 4) {
                                dlog_perror("mnl_attr_validate");
                                return CB_ERROR;
                            }
                            w.ifindex = u32_of(a.payload) as i32;
                            let mut name = [0 as libc::c_char; 16];
                            // SAFETY: name is IFNAMSIZ long.
                            let p = unsafe {
                                libc::if_indextoname(w.ifindex as u32, name.as_mut_ptr())
                            };
                            if p.is_null() {
                                dlog_perror("if_indextoname");
                            } else {
                                // SAFETY: if_indextoname wrote a NUL-terminated name.
                                w.ifname = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
                                    .to_string_lossy()
                                    .into_owned();
                            }
                        }
                        NL80211_ATTR_BSS => {
                            if !a.payload.is_empty() && a.payload.len() < 4 {
                                set_errno(libc::ERANGE);
                                dlog_perror("mnl_attr_validate");
                                return CB_ERROR;
                            }
                            let nested = attrs(a.payload);
                            let ok = nested.iter().any(|n| {
                                n.typ == NL80211_BSS_STATUS
                                    && n.payload.len() >= 4
                                    && matches!(u32_of(n.payload), 0..=2)
                            });
                            if ok {
                                for n in &nested {
                                    if n.typ == NL80211_BSS_INFORMATION_ELEMENTS {
                                        if let Some(ie) = find_ie(n.payload, 0) {
                                            let l = (ie[1] as usize).min(32);
                                            w.ssid = cstr_bytes(&ie[2..2 + l]).to_vec();
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    CB_OK
                });
                if r >= 0 && !w.ssid.is_empty() && !w.ifname.is_empty() && w.ifindex != 0 {
                    out.push(w);
                }
                r
            },
        );
        if !ok {
            return false;
        }
    }
    true
}

pub fn wlan_info_deinit() {
    SOCK.with(|s| {
        if s.get() >= 0 {
            // SAFETY: our socket.
            unsafe { libc::close(s.get()) };
            s.set(-1);
        }
    });
}

pub fn wlan_info_init() -> bool {
    wlan_info_deinit();
    // SAFETY: plain socket calls.
    let s = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_GENERIC) };
    if s < 0 {
        dlog_perror("mnl_socket_open");
        return false;
    }
    SOCK.with(|c| c.set(s));
    let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    sa.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: valid sockaddr.
    if unsafe {
        libc::bind(
            s,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    } != 0
    {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        dlog_perror_errno("mnl_socket_bind", e);
        return false;
    }
    let id = get_family_id(s);
    if id == 0 {
        wlan_info_deinit();
        return false;
    }
    FAMILY.with(|f| f.set(id));
    true
}

pub fn wlan_info_get_rate_limited() -> bool {
    let now = boottime();
    if LAST.with(|l| l.get()) == now {
        return true;
    }
    let s = SOCK.with(|c| c.get());
    let fam = FAMILY.with(|f| f.get());
    let mut v = WLANS.with(|w| w.borrow().clone());
    let r = scan_info(s, fam, &mut v);
    WLANS.with(|w| *w.borrow_mut() = v);
    LAST.with(|l| l.set(now));
    r
}

pub fn ssid_search_ifname(ifname: &str) -> Option<String> {
    WLANS.with(|w| {
        w.borrow()
            .iter()
            .find(|x| x.ifname == ifname)
            .map(|x| String::from_utf8_lossy(&x.ssid).into_owned())
    })
}

pub fn ssid_search_ifidx(idx: i32) -> Option<Vec<u8>> {
    WLANS.with(|w| {
        w.borrow()
            .iter()
            .find(|x| x.ifindex == idx)
            .map(|x| x.ssid.clone())
    })
}
