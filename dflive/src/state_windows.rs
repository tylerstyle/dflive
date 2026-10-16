//! `dflive state` on Windows: the volatile state read with dflive's own API
//! calls (Toolhelp, IP Helper, WTS, the service manager, psapi), not through
//! the suspect's `tasklist`, `netstat` or `query user`.

use crate::winfmt::{self, endpoint, sockaddr, utf16};
use serde_json::{json, Map, Value};
use std::{
    collections::HashMap,
    ffi::c_void,
    io::Read,
    mem::{offset_of, size_of, zeroed},
    os::windows::fs::OpenOptionsExt,
    ptr,
};
use windows_sys::{
    Wdk::System::{
        SystemServices::RtlGetVersion,
        Threading::{
            NtQueryInformationProcess, ProcessBasicInformation, ProcessCommandLineInformation,
        },
    },
    Win32::{
        Foundation::{
            CloseHandle, LocalFree, ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER,
            ERROR_MORE_DATA, FILETIME, HANDLE, INVALID_HANDLE_VALUE,
        },
        NetworkManagement::IpHelper::{
            FreeMibTable, GetAdaptersAddresses, GetExtendedTcpTable, GetExtendedUdpTable,
            GetIpForwardTable2, GetIpNetTable2, GAA_FLAG_INCLUDE_GATEWAYS, IP_ADAPTER_ADDRESSES_LH,
            MIB_IPFORWARD_TABLE2, MIB_IPNET_TABLE2, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
            MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
            MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID,
            TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
        },
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET, SOCKET_ADDRESS},
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, LookupAccountSidW,
            TokenUser, TOKEN_QUERY, TOKEN_USER,
        },
        System::{
            Diagnostics::Debug::ReadProcessMemory,
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverFileNameW},
            Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ},
            RemoteDesktop::{
                ProcessIdToSessionId, WTSClientAddress, WTSClientName, WTSDomainName,
                WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW, WTSSessionInfo,
                WTSUserName, WTSINFOW, WTS_CLIENT_ADDRESS, WTS_CURRENT_SERVER_HANDLE,
                WTS_SESSION_INFOW,
            },
            Services::{
                CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW,
                ENUM_SERVICE_STATUS_PROCESSW, SC_ENUM_PROCESS_INFO, SC_MANAGER_ENUMERATE_SERVICE,
                SERVICE_ACTIVE, SERVICE_DRIVER, SERVICE_WIN32,
            },
            SystemInformation::{GetTickCount64, OSVERSIONINFOW},
            Threading::{
                GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
                PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_VM_READ,
            },
            Time::{GetDynamicTimeZoneInformation, DYNAMIC_TIME_ZONE_INFORMATION},
        },
    },
};

/// Executables larger than this are not hashed
const HASH_LIMIT: u64 = 512 << 20;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// A NUL-terminated UTF-16 string owned by Windows
fn from_pwstr(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: Windows hands out NUL-terminated strings
    let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
    Some(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(p, len)
    }))
}

fn filetime(ft: FILETIME) -> Option<String> {
    winfmt::filetime((u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime))
}

/// A buffer that a "how much do you need" API fills, 8-byte aligned. `call`
/// gets the buffer and its size and returns the API's error code.
fn sized_buffer(mut size: u32, call: impl Fn(*mut c_void, &mut u32) -> u32) -> Option<Vec<u64>> {
    for _ in 0..4 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8).max(1)];
        let mut len = (buf.len() * 8) as u32;
        match call(buf.as_mut_ptr().cast(), &mut len) {
            0 => return Some(buf),
            ERROR_INSUFFICIENT_BUFFER | ERROR_BUFFER_OVERFLOW | ERROR_MORE_DATA => {
                // The table may grow between the calls
                size = len.max(size) + 4096;
            }
            _ => return None,
        }
    }
    None
}

/// The rows of a `{ count: u32, rows: [Row; count] }` table in `buf`
fn rows<Row: Copy>(buf: &[u64], offset: usize) -> Vec<Row> {
    let bytes = buf.len() * 8;
    // SAFETY: the count is the table's own; the bound check keeps the slice in the buffer
    let n = unsafe { *(buf.as_ptr() as *const u32) } as usize;
    if offset + n.saturating_mul(size_of::<Row>()) > bytes {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts((buf.as_ptr() as *const u8).add(offset).cast::<Row>(), n) }
        .to_vec()
}

fn sha256_file(path: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    // Read-only, sharing everything so the running image is not disturbed
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(7)
        .open(path)
        .ok()?;
    if f.metadata().ok()?.len() > HASH_LIMIT {
        return None;
    }
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

struct Owner {
    sid: Option<String>,
    account: Option<String>,
}

fn token_owner(process: HANDLE, accounts: &mut HashMap<String, Option<String>>) -> Owner {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: plain query calls on handles we own; buffers are sized by the API
    unsafe {
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            return Owner {
                sid: None,
                account: None,
            };
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            (buf.len() * 8) as u32,
            &mut len,
        );
        CloseHandle(token);
        if ok == 0 {
            return Owner {
                sid: None,
                account: None,
            };
        }
        let sid = (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid;
        let mut s: *mut u16 = ptr::null_mut();
        let sid_string = if ConvertSidToStringSidW(sid, &mut s) != 0 {
            let r = from_pwstr(s);
            LocalFree(s.cast());
            r
        } else {
            None
        };
        let account = match &sid_string {
            Some(k) => accounts
                .entry(k.clone())
                .or_insert_with(|| {
                    let (mut name, mut domain) = ([0u16; 256], [0u16; 256]);
                    let (mut nl, mut dl, mut use_) = (256u32, 256u32, 0);
                    (LookupAccountSidW(
                        ptr::null(),
                        sid,
                        name.as_mut_ptr(),
                        &mut nl,
                        domain.as_mut_ptr(),
                        &mut dl,
                        &mut use_,
                    ) != 0)
                        .then(|| {
                            let (d, n) = (utf16(&domain), utf16(&name));
                            if d.is_empty() {
                                n
                            } else {
                                format!("{d}\\{n}")
                            }
                        })
                })
                .clone(),
            None => None,
        };
        Owner {
            sid: sid_string,
            account,
        }
    }
}

fn command_line(process: HANDLE) -> Option<String> {
    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }
    // STATUS_INFO_LENGTH_MISMATCH, STATUS_BUFFER_TOO_SMALL, STATUS_BUFFER_OVERFLOW
    const TOO_SMALL: [u32; 3] = [0xC000_0004, 0xC000_0023, 0x8000_0005];
    let mut size = 4096u32;
    // SAFETY: the API writes at most `size` bytes into an 8-byte aligned buffer
    unsafe {
        let mut buf;
        let mut tries = 0;
        loop {
            buf = vec![0u64; (size as usize).div_ceil(8)];
            let mut len = 0u32;
            let st = NtQueryInformationProcess(
                process,
                ProcessCommandLineInformation,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut len,
            );
            if st >= 0 {
                break;
            }
            tries += 1;
            if !TOO_SMALL.contains(&(st as u32)) || tries > 4 {
                return None;
            }
            size = len.max(size.saturating_mul(4));
        }
        let us = &*(buf.as_ptr() as *const UnicodeString);
        let start = us.buffer as usize;
        let (lo, hi) = (buf.as_ptr() as usize, buf.as_ptr() as usize + buf.len() * 8);
        if us.buffer.is_null() || start < lo || start + us.length as usize > hi {
            return None;
        }
        Some(String::from_utf16_lossy(std::slice::from_raw_parts(
            us.buffer,
            us.length as usize / 2,
        )))
    }
}

/// Windows before 8.1 (and Wine) lack ProcessCommandLineInformation: read
/// the command line from the process's PEB instead (read-only; 64-bit layout:
/// PEB.ProcessParameters at 0x20, RTL_USER_PROCESS_PARAMETERS.CommandLine at 0x70)
#[cfg(target_pointer_width = "64")]
fn command_line_from_peb(pid: u32) -> Option<String> {
    #[repr(C)]
    struct BasicInformation {
        exit_status: i32,
        peb: usize,
        affinity: usize,
        base_priority: i32,
        pid: usize,
        parent: usize,
    }
    // SAFETY: a query-and-read handle we close; every read is bounded by its buffer
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if h.is_null() {
            return None;
        }
        let read = |addr: usize, buf: &mut [u8]| {
            let mut n = 0usize;
            ReadProcessMemory(
                h,
                addr as *const c_void,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut n,
            ) != 0
                && n == buf.len()
        };
        let line = (|| {
            let mut bi: BasicInformation = zeroed();
            let mut len = 0u32;
            if NtQueryInformationProcess(
                h,
                ProcessBasicInformation,
                (&mut bi as *mut BasicInformation).cast(),
                size_of::<BasicInformation>() as u32,
                &mut len,
            ) < 0
                || bi.peb == 0
            {
                return None;
            }
            let mut p = [0u8; 8];
            if !read(bi.peb + 0x20, &mut p) {
                return None;
            }
            let params = usize::from_le_bytes(p);
            let mut us = [0u8; 16];
            if params == 0 || !read(params + 0x70, &mut us) {
                return None;
            }
            let length = usize::from(u16::from_le_bytes([us[0], us[1]]));
            let buffer = usize::from_le_bytes(us[8..16].try_into().ok()?);
            if buffer == 0 || length == 0 {
                return None;
            }
            let mut raw = vec![0u8; length];
            if !read(buffer, &mut raw) {
                return None;
            }
            let w: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            Some(String::from_utf16_lossy(&w))
        })();
        CloseHandle(h);
        line
    }
}

#[cfg(not(target_pointer_width = "64"))]
fn command_line_from_peb(_pid: u32) -> Option<String> {
    None
}

pub fn processes(hash: bool) -> Vec<Value> {
    let mut out = Vec::new();
    let mut accounts = HashMap::new();
    let mut hashes: HashMap<String, Option<String>> = HashMap::new();
    // SAFETY: Toolhelp walk over a snapshot we close; every handle is closed
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = zeroed();
        e.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut more = Process32FirstW(snap, &mut e) != 0;
        while more {
            let pid = e.th32ProcessID;
            let mut session = 0u32;
            let session = (ProcessIdToSessionId(pid, &mut session) != 0).then_some(session);
            let mut entry = json!({
                "pid": pid,
                "ppid": e.th32ParentProcessID,
                "name": utf16(&e.szExeFile),
                "threads": e.cntThreads,
                "session": session,
            });
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if !h.is_null() {
                let mut path = vec![0u16; 32768];
                let mut len = path.len() as u32;
                let exe = (QueryFullProcessImageNameW(
                    h,
                    PROCESS_NAME_WIN32,
                    path.as_mut_ptr(),
                    &mut len,
                ) != 0)
                    .then(|| String::from_utf16_lossy(&path[..len as usize]));
                let (mut c, mut x, mut k, mut u): (FILETIME, FILETIME, FILETIME, FILETIME) =
                    (zeroed(), zeroed(), zeroed(), zeroed());
                let start = (GetProcessTimes(h, &mut c, &mut x, &mut k, &mut u) != 0)
                    .then(|| filetime(c))
                    .flatten();
                let owner = token_owner(h, &mut accounts);
                let exe_sha256 = match (&exe, hash) {
                    (Some(p), true) => hashes
                        .entry(p.to_lowercase())
                        .or_insert_with(|| sha256_file(p))
                        .clone(),
                    _ => None,
                };
                let m = entry.as_object_mut().expect("object");
                m.insert("exe".into(), json!(exe));
                m.insert("exe_sha256".into(), json!(exe_sha256));
                m.insert(
                    "cmdline".into(),
                    json!(command_line(h).or_else(|| command_line_from_peb(pid))),
                );
                m.insert("start".into(), json!(start));
                m.insert("user_sid".into(), json!(owner.sid));
                m.insert("user".into(), json!(owner.account));
                CloseHandle(h);
            } else {
                entry.as_object_mut().expect("object").insert(
                    "note".into(),
                    json!("not opened (protected process or access denied)"),
                );
            }
            out.push(entry);
            more = Process32NextW(snap, &mut e) != 0;
        }
        CloseHandle(snap);
    }
    out
}

fn tcp_table(family: u16) -> Option<Vec<u64>> {
    // SAFETY: the API writes at most `len` bytes into the buffer
    sized_buffer(16384, |buf, len| unsafe {
        GetExtendedTcpTable(buf, len, 1, u32::from(family), TCP_TABLE_OWNER_PID_ALL, 0)
    })
}

fn udp_table(family: u16) -> Option<Vec<u64>> {
    // SAFETY: as above
    sized_buffer(16384, |buf, len| unsafe {
        GetExtendedUdpTable(buf, len, 1, u32::from(family), UDP_TABLE_OWNER_PID, 0)
    })
}

pub fn sockets() -> Vec<Value> {
    let mut out = Vec::new();
    if let Some(buf) = tcp_table(AF_INET) {
        for r in rows::<MIB_TCPROW_OWNER_PID>(&buf, offset_of!(MIB_TCPTABLE_OWNER_PID, table)) {
            out.push(json!({
                "proto": "tcp",
                "local": endpoint(&winfmt::ipv4(r.dwLocalAddr).to_string(), winfmt::port(r.dwLocalPort), false),
                "remote": endpoint(&winfmt::ipv4(r.dwRemoteAddr).to_string(), winfmt::port(r.dwRemotePort), false),
                "state": winfmt::tcp_state(r.dwState),
                "pids": [r.dwOwningPid],
            }));
        }
    }
    if let Some(buf) = tcp_table(AF_INET6) {
        for r in rows::<MIB_TCP6ROW_OWNER_PID>(&buf, offset_of!(MIB_TCP6TABLE_OWNER_PID, table)) {
            out.push(json!({
                "proto": "tcp6",
                "local": endpoint(&winfmt::ipv6(r.ucLocalAddr, r.dwLocalScopeId), winfmt::port(r.dwLocalPort), true),
                "remote": endpoint(&winfmt::ipv6(r.ucRemoteAddr, r.dwRemoteScopeId), winfmt::port(r.dwRemotePort), true),
                "state": winfmt::tcp_state(r.dwState),
                "pids": [r.dwOwningPid],
            }));
        }
    }
    if let Some(buf) = udp_table(AF_INET) {
        for r in rows::<MIB_UDPROW_OWNER_PID>(&buf, offset_of!(MIB_UDPTABLE_OWNER_PID, table)) {
            out.push(json!({
                "proto": "udp",
                "local": endpoint(&winfmt::ipv4(r.dwLocalAddr).to_string(), winfmt::port(r.dwLocalPort), false),
                "remote": "*:*",
                "state": "",
                "pids": [r.dwOwningPid],
            }));
        }
    }
    if let Some(buf) = udp_table(AF_INET6) {
        for r in rows::<MIB_UDP6ROW_OWNER_PID>(&buf, offset_of!(MIB_UDP6TABLE_OWNER_PID, table)) {
            out.push(json!({
                "proto": "udp6",
                "local": endpoint(&winfmt::ipv6(r.ucLocalAddr, r.dwLocalScopeId), winfmt::port(r.dwLocalPort), true),
                "remote": "*:*",
                "state": "",
                "pids": [r.dwOwningPid],
            }));
        }
    }
    out
}

/// # Safety
/// `a` must come from a live GetAdaptersAddresses or MIB table
unsafe fn socket_address(a: &SOCKET_ADDRESS) -> Option<String> {
    if a.lpSockaddr.is_null() || a.iSockaddrLength <= 0 {
        return None;
    }
    let b = std::slice::from_raw_parts(a.lpSockaddr as *const u8, a.iSockaddrLength as usize);
    sockaddr(b).map(|(ip, _)| ip)
}

fn inet(a: &SOCKADDR_INET) -> Option<String> {
    // SAFETY: SOCKADDR_INET is a plain union of the two sockaddr layouts
    let b = unsafe {
        std::slice::from_raw_parts(a as *const _ as *const u8, size_of::<SOCKADDR_INET>())
    };
    sockaddr(b).map(|(ip, _)| ip)
}

pub fn interfaces() -> Vec<Value> {
    let mut out = Vec::new();
    // SAFETY: the API writes at most `len` bytes
    let Some(buf) = sized_buffer(32768, |buf, len| unsafe {
        GetAdaptersAddresses(
            u32::from(AF_UNSPEC),
            GAA_FLAG_INCLUDE_GATEWAYS,
            ptr::null(),
            buf.cast(),
            len,
        )
    }) else {
        return out;
    };
    // SAFETY: walking the linked lists inside our buffer as Windows built them
    unsafe {
        let mut a = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !a.is_null() {
            let ad = &*a;
            let mut addresses = Vec::new();
            let mut u = ad.FirstUnicastAddress;
            while !u.is_null() {
                if let Some(ip) = socket_address(&(*u).Address) {
                    addresses.push(format!("{ip}/{}", (*u).OnLinkPrefixLength));
                }
                u = (*u).Next;
            }
            let mut gateways = Vec::new();
            let mut g = ad.FirstGatewayAddress;
            while !g.is_null() {
                gateways.extend(socket_address(&(*g).Address));
                g = (*g).Next;
            }
            let mut dns = Vec::new();
            let mut d = ad.FirstDnsServerAddress;
            while !d.is_null() {
                dns.extend(socket_address(&(*d).Address));
                d = (*d).Next;
            }
            let mac_len = (ad.PhysicalAddressLength as usize).min(8);
            out.push(json!({
                "name": from_pwstr(ad.FriendlyName),
                "adapter": (!ad.AdapterName.is_null())
                    .then(|| std::ffi::CStr::from_ptr(ad.AdapterName.cast()).to_string_lossy().into_owned()),
                "description": from_pwstr(ad.Description),
                "mac": winfmt::mac(&ad.PhysicalAddress[..mac_len]),
                "state": winfmt::oper_status(ad.OperStatus),
                "addresses": addresses,
                "gateways": gateways,
                "dns_servers": dns,
                "dns_suffix": from_pwstr(ad.DnsSuffix),
                "dhcp_server": socket_address(&ad.Dhcpv4Server),
            }));
            a = ad.Next;
        }
    }
    out
}

pub fn routes() -> Vec<Value> {
    let mut out = Vec::new();
    let mut table: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
    // SAFETY: Windows allocates the table; FreeMibTable releases it
    unsafe {
        if GetIpForwardTable2(AF_UNSPEC, &mut table) != 0 || table.is_null() {
            return out;
        }
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for r in rows {
            out.push(json!({
                "destination": inet(&r.DestinationPrefix.Prefix).map(|p| format!("{p}/{}", r.DestinationPrefix.PrefixLength)),
                "next_hop": inet(&r.NextHop),
                "interface_index": r.InterfaceIndex,
                "metric": r.Metric,
                "protocol": r.Protocol,
            }));
        }
        FreeMibTable(table.cast());
    }
    out
}

pub fn neighbors() -> Vec<Value> {
    let mut out = Vec::new();
    let mut table: *mut MIB_IPNET_TABLE2 = ptr::null_mut();
    // SAFETY: as in routes()
    unsafe {
        if GetIpNetTable2(AF_UNSPEC, &mut table) != 0 || table.is_null() {
            return out;
        }
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for r in rows {
            let len = (r.PhysicalAddressLength as usize).min(32);
            out.push(json!({
                "address": inet(&r.Address),
                "mac": winfmt::mac(&r.PhysicalAddress[..len]),
                "interface_index": r.InterfaceIndex,
                "state": winfmt::neighbor_state(r.State),
            }));
        }
        FreeMibTable(table.cast());
    }
    out
}

/// # Safety
/// Calls WTSQuerySessionInformationW and frees its buffer
unsafe fn wts_query(session: u32, class: i32) -> Option<Vec<u8>> {
    let mut p: *mut u16 = ptr::null_mut();
    let mut len = 0u32;
    if WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, session, class, &mut p, &mut len) == 0
        || p.is_null()
    {
        return None;
    }
    let v = std::slice::from_raw_parts(p as *const u8, len as usize).to_vec();
    WTSFreeMemory(p.cast());
    Some(v)
}

fn wts_string(session: u32, class: i32) -> Option<String> {
    // SAFETY: see wts_query
    let b = unsafe { wts_query(session, class)? };
    let w: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    Some(utf16(&w)).filter(|s| !s.is_empty())
}

/// Logon sessions (console and RDP) with user, client and times
pub fn users() -> Vec<Value> {
    let mut out = Vec::new();
    // SAFETY: WTS enumeration; the list is freed with WTSFreeMemory
    unsafe {
        let mut list: *mut WTS_SESSION_INFOW = ptr::null_mut();
        let mut n = 0u32;
        if WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut list, &mut n) == 0
            || list.is_null()
        {
            return out;
        }
        for s in std::slice::from_raw_parts(list, n as usize) {
            let id = s.SessionId;
            let info = wts_query(id, WTSSessionInfo)
                .filter(|b| b.len() >= size_of::<WTSINFOW>())
                .map(|b| ptr::read_unaligned(b.as_ptr() as *const WTSINFOW));
            let time = |t: i64| winfmt::filetime(t as u64);
            let client = wts_query(id, WTSClientAddress)
                .filter(|b| b.len() >= size_of::<WTS_CLIENT_ADDRESS>())
                .map(|b| ptr::read_unaligned(b.as_ptr() as *const WTS_CLIENT_ADDRESS))
                .and_then(|c| match c.AddressFamily {
                    2 => Some(
                        std::net::Ipv4Addr::new(
                            c.Address[2],
                            c.Address[3],
                            c.Address[4],
                            c.Address[5],
                        )
                        .to_string(),
                    ),
                    _ => None,
                });
            out.push(json!({
                "session": id,
                "station": from_pwstr(s.pWinStationName),
                "state": winfmt::session_state(s.State),
                "user": wts_string(id, WTSUserName),
                "domain": wts_string(id, WTSDomainName),
                "client_name": wts_string(id, WTSClientName),
                "client_address": client,
                "logon": info.as_ref().and_then(|i| time(i.LogonTime)),
                "connect": info.as_ref().and_then(|i| time(i.ConnectTime)),
                "disconnect": info.as_ref().and_then(|i| time(i.DisconnectTime)),
                "last_input": info.as_ref().and_then(|i| time(i.LastInputTime)),
            }));
        }
        WTSFreeMemory(list.cast());
    }
    out
}

/// Active services and kernel drivers with their processes
pub fn services() -> Vec<Value> {
    let mut out = Vec::new();
    // SAFETY: read-only service manager handle, closed below; the buffer is sized by the API
    unsafe {
        let scm = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_ENUMERATE_SERVICE);
        if scm.is_null() {
            return out;
        }
        let mut resume = 0u32;
        loop {
            let mut buf = vec![0u64; 32768];
            let (mut needed, mut count) = (0u32, 0u32);
            let ok = EnumServicesStatusExW(
                scm,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32 | SERVICE_DRIVER,
                SERVICE_ACTIVE,
                buf.as_mut_ptr().cast(),
                (buf.len() * 8) as u32,
                &mut needed,
                &mut count,
                &mut resume,
                ptr::null(),
            );
            let more = ok == 0 && windows_sys::Win32::Foundation::GetLastError() == ERROR_MORE_DATA;
            if ok == 0 && !more {
                break;
            }
            for s in std::slice::from_raw_parts(
                buf.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW,
                count as usize,
            ) {
                let st = &s.ServiceStatusProcess;
                out.push(json!({
                    "name": from_pwstr(s.lpServiceName),
                    "display_name": from_pwstr(s.lpDisplayName),
                    "type": st.dwServiceType,
                    "state": winfmt::service_state(st.dwCurrentState),
                    "pid": (st.dwProcessId != 0).then_some(st.dwProcessId),
                }));
            }
            if !more {
                break;
            }
        }
        CloseServiceHandle(scm);
    }
    out
}

/// Loaded kernel images (EnumDeviceDrivers), with or without a service entry
pub fn drivers() -> Vec<Value> {
    let mut out = Vec::new();
    // SAFETY: psapi fills our array of base addresses; names go into a local buffer
    unsafe {
        let mut bases = vec![ptr::null_mut::<c_void>(); 4096];
        let mut needed = 0u32;
        if EnumDeviceDrivers(
            bases.as_mut_ptr(),
            (bases.len() * size_of::<usize>()) as u32,
            &mut needed,
        ) == 0
        {
            return out;
        }
        let n = (needed as usize / size_of::<usize>()).min(bases.len());
        for &b in &bases[..n] {
            let mut name = [0u16; 1024];
            let len = GetDeviceDriverFileNameW(b, name.as_mut_ptr(), name.len() as u32) as usize;
            out.push(json!({
                "base": format!("{:#x}", b as usize),
                "file": (len > 0).then(|| String::from_utf16_lossy(&name[..len.min(name.len())])),
            }));
        }
    }
    out
}

fn reg_string(key: &str, value: &str) -> Option<String> {
    let (k, v) = (wide(key), wide(value));
    let mut buf = [0u16; 512];
    let mut len = (buf.len() * 2) as u32;
    // SAFETY: RegGetValueW writes at most `len` bytes into `buf`
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            k.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    (r == 0).then(|| utf16(&buf))
}

fn reg_dword(key: &str, value: &str) -> Option<u32> {
    let (k, v) = (wide(key), wide(value));
    let mut d = 0u32;
    let mut len = 4u32;
    // SAFETY: as above, four bytes
    let r = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            k.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            (&mut d as *mut u32).cast(),
            &mut len,
        )
    };
    (r == 0).then_some(d)
}

/// Everything, as one JSON document (the same top-level names as on Linux
/// where the meaning is the same).
pub fn collect(hash_executables: bool) -> Value {
    const CV: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let mut m = Map::new();
    m.insert("collected_at".into(), json!(crate::now_rfc3339()));
    m.insert("host".into(), json!(crate::host_name()));
    // SAFETY: RtlGetVersion and the time-zone query fill caller-owned structs
    let (version, tz) = unsafe {
        let mut v: OSVERSIONINFOW = zeroed();
        v.dwOSVersionInfoSize = size_of::<OSVERSIONINFOW>() as u32;
        let version = (RtlGetVersion(&mut v) >= 0).then(|| {
            format!(
                "{}.{}.{}",
                v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber
            )
        });
        let mut tz: DYNAMIC_TIME_ZONE_INFORMATION = zeroed();
        let tz_id = GetDynamicTimeZoneInformation(&mut tz);
        let tz = (tz_id != u32::MAX).then(|| {
            json!({
                "key": utf16(&tz.TimeZoneKeyName),
                "bias_minutes": tz.Bias,
                "daylight_saving_in_effect": tz_id == 2,
            })
        });
        (version, tz)
    };
    m.insert(
        "os".into(),
        json!({
            "version": version,
            "product": reg_string(CV, "ProductName"),
            "display_version": reg_string(CV, "DisplayVersion"),
            "update_revision": reg_dword(CV, "UBR"),
        }),
    );
    m.insert("time_zone".into(), json!(tz));
    // SAFETY: no arguments
    let uptime_ms = unsafe { GetTickCount64() };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let boot_ms = now.as_millis() as i64 - uptime_ms as i64;
    m.insert(
        "boot_time".into(),
        json!(crate::rfc3339(
            boot_ms.div_euclid(1000),
            boot_ms.rem_euclid(1000) as u32
        )),
    );
    m.insert("uptime_seconds".into(), json!(uptime_ms as f64 / 1000.0));
    m.insert("users".into(), json!(users()));
    m.insert("processes".into(), json!(processes(hash_executables)));
    m.insert("sockets".into(), json!(sockets()));
    m.insert("interfaces".into(), json!(interfaces()));
    m.insert("routes".into(), json!(routes()));
    m.insert("neighbors".into(), json!(neighbors()));
    m.insert("services".into(), json!(services()));
    m.insert("drivers".into(), json!(drivers()));
    m.insert(
        "ntfs_last_access_updates".into(),
        json!(reg_dword(
            r"SYSTEM\CurrentControlSet\Control\FileSystem",
            "NtfsDisableLastAccessUpdate"
        )
        .map(|v| format!("NtfsDisableLastAccessUpdate = {v:#x}"))),
    );
    m.insert(
        "footprint".into(),
        json!({
            "read": "process, token, socket, adapter, route, neighbour, session, service and driver lists through the Windows API; two registry values",
            "hashed": if hash_executables {
                "the image of every process it could open, read-only; NTFS updates last-access times only when ntfs_last_access_updates allows it, and running images were accessed at their start"
            } else { "nothing" },
            "written": "only the output file",
        }),
    );
    Value::Object(m)
}
