//! Decoding of Windows API values for `dflive state` on Windows. Kept free of
//! Windows calls so the tests run on every host.
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::{Ipv4Addr, Ipv6Addr};

/// 100 ns intervals from 1601-01-01 to 1970-01-01
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// A FILETIME (100 ns since 1601, UTC) as RFC 3339; `None` for 0 (never)
pub fn filetime(t: u64) -> Option<String> {
    if t == 0 {
        return None;
    }
    let unix = t as i64 - FILETIME_UNIX_EPOCH as i64;
    Some(crate::rfc3339(
        unix.div_euclid(10_000_000),
        (unix.rem_euclid(10_000_000) / 10_000) as u32,
    ))
}

/// A port as IP Helper stores it: network byte order in the low 16 bits of a DWORD
pub fn port(dw: u32) -> u16 {
    (((dw & 0xff) << 8) | ((dw >> 8) & 0xff)) as u16
}

/// An IPv4 address as IP Helper stores it: network byte order in a DWORD
pub fn ipv4(dw: u32) -> Ipv4Addr {
    Ipv4Addr::from(dw.to_le_bytes())
}

pub fn endpoint(ip: &str, port: u16, v6: bool) -> String {
    if v6 {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

pub fn ipv6(bytes: [u8; 16], scope: u32) -> String {
    let ip = Ipv6Addr::from(bytes);
    if scope != 0 {
        format!("{ip}%{scope}")
    } else {
        ip.to_string()
    }
}

/// A SOCKADDR (SOCKADDR_IN or SOCKADDR_IN6, also inside SOCKADDR_INET) as
/// address and port
pub fn sockaddr(b: &[u8]) -> Option<(String, u16)> {
    let family = u16::from_le_bytes(b.get(..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(b.get(2..4)?.try_into().ok()?);
    match family {
        2 => Some((
            Ipv4Addr::from(<[u8; 4]>::try_from(b.get(4..8)?).ok()?).to_string(),
            port,
        )),
        23 => Some((
            ipv6(
                b.get(8..24)?.try_into().ok()?,
                u32::from_le_bytes(b.get(24..28)?.try_into().ok()?),
            ),
            port,
        )),
        _ => None,
    }
}

pub fn mac(b: &[u8]) -> Option<String> {
    (!b.is_empty()).then(|| {
        b.iter()
            .map(|x| format!("{x:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

/// MIB_TCP_STATE, in the names Linux uses
pub fn tcp_state(n: u32) -> &'static str {
    match n {
        1 => "CLOSE",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RECV",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "?",
    }
}

pub fn service_state(n: u32) -> &'static str {
    match n {
        1 => "stopped",
        2 => "start_pending",
        3 => "stop_pending",
        4 => "running",
        5 => "continue_pending",
        6 => "pause_pending",
        7 => "paused",
        _ => "?",
    }
}

pub fn session_state(n: i32) -> &'static str {
    match n {
        0 => "active",
        1 => "connected",
        2 => "connect_query",
        3 => "shadow",
        4 => "disconnected",
        5 => "idle",
        6 => "listen",
        7 => "reset",
        8 => "down",
        9 => "init",
        _ => "?",
    }
}

pub fn oper_status(n: i32) -> &'static str {
    match n {
        1 => "up",
        2 => "down",
        3 => "testing",
        4 => "unknown",
        5 => "dormant",
        6 => "notpresent",
        7 => "lowerlayerdown",
        _ => "?",
    }
}

pub fn neighbor_state(n: i32) -> &'static str {
    match n {
        0 => "unreachable",
        1 => "incomplete",
        2 => "probe",
        3 => "delay",
        4 => "stale",
        5 => "reachable",
        6 => "permanent",
        _ => "?",
    }
}

/// GetDriveTypeW
pub fn drive_type(n: u32) -> &'static str {
    match n {
        1 => "no_root_dir",
        2 => "removable",
        3 => "fixed",
        4 => "remote",
        5 => "cdrom",
        6 => "ramdisk",
        _ => "unknown",
    }
}

/// STORAGE_BUS_TYPE
pub fn bus_type(n: i32) -> &'static str {
    match n {
        1 => "SCSI",
        2 => "ATAPI",
        3 => "ATA",
        4 => "1394",
        5 => "SSA",
        6 => "FibreChannel",
        7 => "USB",
        8 => "RAID",
        9 => "iSCSI",
        10 => "SAS",
        11 => "SATA",
        12 => "SD",
        13 => "MMC",
        14 => "Virtual",
        15 => "FileBackedVirtual",
        16 => "Spaces",
        17 => "NVMe",
        18 => "SCM",
        19 => "UFS",
        _ => "unknown",
    }
}

/// UTF-16 up to the first NUL
pub fn utf16(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetimes() {
        assert_eq!(filetime(0), None);
        assert_eq!(
            filetime(FILETIME_UNIX_EPOCH).as_deref(),
            Some("1970-01-01T00:00:00.000Z")
        );
        // 2024-02-29T12:34:56.789Z
        let t = FILETIME_UNIX_EPOCH + 1_709_210_096_789 * 10_000;
        assert_eq!(filetime(t).as_deref(), Some("2024-02-29T12:34:56.789Z"));
    }

    #[test]
    fn ip_helper_ports_and_addresses() {
        // port 443 = 0x01bb, stored as bytes 01 bb 00 00
        assert_eq!(port(u32::from_le_bytes([0x01, 0xbb, 0, 0])), 443);
        assert_eq!(
            ipv4(u32::from_le_bytes([192, 0, 2, 7])).to_string(),
            "192.0.2.7"
        );
        assert_eq!(endpoint("::1", 80, true), "[::1]:80");
    }

    #[test]
    fn sockaddrs() {
        let mut v4 = [0u8; 16];
        v4[..2].copy_from_slice(&2u16.to_le_bytes());
        v4[2..4].copy_from_slice(&8080u16.to_be_bytes());
        v4[4..8].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(sockaddr(&v4), Some(("10.0.0.1".into(), 8080)));
        let mut v6 = [0u8; 28];
        v6[..2].copy_from_slice(&23u16.to_le_bytes());
        v6[8] = 0xfe;
        v6[9] = 0x80;
        v6[23] = 1;
        v6[24..28].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(sockaddr(&v6), Some(("fe80::1%5".into(), 0)));
        assert_eq!(sockaddr(&[0u8; 28]), None);
        assert_eq!(sockaddr(&v6[..20]), None);
    }

    #[test]
    fn names_and_strings() {
        assert_eq!(tcp_state(2), "LISTEN");
        assert_eq!(service_state(4), "running");
        assert_eq!(session_state(0), "active");
        assert_eq!(drive_type(4), "remote");
        assert_eq!(bus_type(7), "USB");
        assert_eq!(bus_type(17), "NVMe");
        assert_eq!(
            mac(&[0, 0x1b, 0x21, 0xaa, 0xbb, 0xcc]).as_deref(),
            Some("00:1b:21:aa:bb:cc")
        );
        assert_eq!(mac(&[]), None);
        assert_eq!(utf16(&[0x41, 0x42, 0, 0x43]), "AB");
    }
}
