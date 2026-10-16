//! `dflive state`: the volatile state of a running Linux system, read with
//! dflive's own code from /proc, /sys, utmp and getifaddrs, not through the
//! suspect's `ps`, `netstat` or `who`, which a rootkit may have replaced.

use serde_json::{json, Map, Value};
use std::{
    collections::HashMap,
    fs,
    io::Read,
    net::{Ipv4Addr, Ipv6Addr},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

/// Executables larger than this are not hashed
const HASH_LIMIT: u64 = 512 << 20;

fn read(path: impl AsRef<Path>) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn sha256_file(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    // O_NOATIME where permitted: hashing must not change the access time
    let open = |flags| {
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)
    };
    let mut f = open(libc::O_NOATIME).or_else(|_| open(0)).ok()?;
    if f.metadata().ok()?.len() > HASH_LIMIT {
        return None;
    }
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Fields of /proc/<pid>/stat after the `(comm)`, which may hold spaces.
fn stat_fields(stat: &str) -> Option<Vec<&str>> {
    let after = &stat[stat.rfind(')')? + 1..];
    Some(after.split_whitespace().collect())
}

fn clock_ticks() -> u64 {
    // SAFETY: sysconf has no preconditions
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 {
        t as u64
    } else {
        100
    }
}

fn boot_time() -> Option<u64> {
    read("/proc/stat")?
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())
}

pub fn processes(hash: bool) -> Vec<Value> {
    let ticks = clock_ticks();
    let btime = boot_time();
    let mut hashes: HashMap<(u64, u64), Option<String>> = HashMap::new();
    let mut out = Vec::new();
    let Ok(dir) = fs::read_dir("/proc") else {
        return out;
    };
    let mut pids: Vec<u32> = dir
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();
    for pid in pids {
        let base = Path::new("/proc").join(pid.to_string());
        let Some(stat) = read(base.join("stat")) else {
            continue;
        };
        let Some(f) = stat_fields(&stat) else {
            continue;
        };
        let name = read(base.join("comm")).map(|s| s.trim_end().to_string());
        let cmdline: Vec<String> = fs::read(base.join("cmdline"))
            .unwrap_or_default()
            .split(|&b| b == 0)
            .filter(|a| !a.is_empty())
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let uid = read(base.join("status")).and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|v| v.split_whitespace().next()?.parse::<u32>().ok())
        });
        let exe = fs::read_link(base.join("exe")).ok();
        let exe_sha256 = if hash {
            fs::metadata(base.join("exe")).ok().and_then(|md| {
                hashes
                    .entry((md.dev(), md.ino()))
                    .or_insert_with(|| sha256_file(&base.join("exe")))
                    .clone()
            })
        } else {
            None
        };
        let start = match (btime, f.get(19).and_then(|v| v.parse::<u64>().ok())) {
            (Some(b), Some(t)) => Some(crate::rfc3339((b + t / ticks) as i64, 0)),
            _ => None,
        };
        out.push(json!({
            "pid": pid,
            "ppid": f.get(1).and_then(|v| v.parse::<u32>().ok()),
            "state": f.first(),
            "uid": uid,
            "name": name,
            "cmdline": cmdline,
            "exe": exe.map(|p| p.to_string_lossy().into_owned()),
            "exe_sha256": exe_sha256,
            "cwd": fs::read_link(base.join("cwd")).ok().map(|p| p.to_string_lossy().into_owned()),
            "start": start,
        }));
    }
    out
}

/// socket inode -> pids holding it
fn socket_owners() -> HashMap<u64, Vec<u32>> {
    let mut map: HashMap<u64, Vec<u32>> = HashMap::new();
    let Ok(dir) = fs::read_dir("/proc") else {
        return map;
    };
    for e in dir.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fds) = fs::read_dir(e.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };
            let link = link.to_string_lossy();
            if let Some(inode) = link
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse().ok())
            {
                let pids = map.entry(inode).or_default();
                if !pids.contains(&pid) {
                    pids.push(pid);
                }
            }
        }
    }
    map
}

/// `0100007F:0016` (IPv4) or 32 hex digits (IPv6) as /proc/net/{tcp,udp}* print
/// them: each 32-bit word in host byte order.
fn proc_addr(s: &str) -> Option<String> {
    let (addr, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let words: Vec<u32> = (0..addr.len() / 8)
        .map(|i| u32::from_str_radix(&addr[i * 8..i * 8 + 8], 16))
        .collect::<Result<_, _>>()
        .ok()?;
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
    match bytes.len() {
        4 => Some(format!(
            "{}:{port}",
            Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
        )),
        16 => {
            let b: [u8; 16] = bytes.try_into().ok()?;
            Some(format!("[{}]:{port}", Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

const TCP_STATES: [&str; 12] = [
    "",
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING",
];

fn parse_proc_net(proto: &str, content: &str, owners: &HashMap<u64, Vec<u32>>) -> Vec<Value> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let state = usize::from_str_radix(f.get(3)?, 16).ok()?;
            let inode: u64 = f.get(9)?.parse().ok()?;
            Some(json!({
                "proto": proto,
                "local": proc_addr(f.get(1)?)?,
                "remote": proc_addr(f.get(2)?)?,
                "state": if proto.starts_with("tcp") { TCP_STATES.get(state).copied().unwrap_or("?") } else { "" },
                "uid": f.get(7)?.parse::<u32>().ok(),
                "inode": inode,
                "pids": owners.get(&inode).cloned().unwrap_or_default(),
            }))
        })
        .collect()
}

pub fn sockets() -> Vec<Value> {
    let owners = socket_owners();
    let mut out = Vec::new();
    for proto in ["tcp", "tcp6", "udp", "udp6"] {
        if let Some(c) = read(format!("/proc/net/{proto}")) {
            out.extend(parse_proc_net(proto, &c, &owners));
        }
    }
    out
}

/// Addresses of every interface (getifaddrs), with MAC and state from sysfs.
pub fn interfaces() -> Vec<Value> {
    let mut addrs: HashMap<String, Vec<String>> = HashMap::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a list we walk and free below
    if unsafe { libc::getifaddrs(&mut ifap) } == 0 {
        let mut cur = ifap;
        while !cur.is_null() {
            // SAFETY: cur is a node of the list getifaddrs returned
            let ifa = unsafe { &*cur };
            if !ifa.ifa_addr.is_null() {
                // SAFETY: ifa_name is a NUL-terminated string
                let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                    .to_string_lossy()
                    .into_owned();
                // SAFETY: the family says which sockaddr type ifa_addr points to
                let family = unsafe { (*ifa.ifa_addr).sa_family } as i32;
                let addr = match family {
                    libc::AF_INET => {
                        let sa = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                        Some(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)).to_string())
                    }
                    libc::AF_INET6 => {
                        let sa = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                        Some(Ipv6Addr::from(sa.sin6_addr.s6_addr).to_string())
                    }
                    _ => None,
                };
                if let Some(a) = addr {
                    addrs.entry(name).or_default().push(a);
                }
            }
            cur = ifa.ifa_next;
        }
        // SAFETY: frees the list from getifaddrs exactly once
        unsafe { libc::freeifaddrs(ifap) };
    }
    // Names from sysfs and from getifaddrs: either can be missing (no /sys in
    // a container, no address on an interface)
    let mut names: Vec<String> = fs::read_dir("/sys/class/net")
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.extend(addrs.keys().cloned());
    names.sort();
    names.dedup();
    names
        .into_iter()
        .map(|n| {
            let sys = Path::new("/sys/class/net").join(&n);
            json!({
                "name": n,
                "mac": read(sys.join("address")).map(|s| s.trim().to_string()),
                "state": read(sys.join("operstate")).map(|s| s.trim().to_string()),
                "addresses": addrs.remove(&n).unwrap_or_default(),
            })
        })
        .collect()
}

/// Logged-in users from utmp (glibc layout, 384-byte records).
pub fn users() -> Vec<Value> {
    let data = fs::read("/run/utmp")
        .or_else(|_| fs::read("/var/run/utmp"))
        .unwrap_or_default();
    let text = |b: &[u8]| {
        String::from_utf8_lossy(b.split(|&c| c == 0).next().unwrap_or_default()).into_owned()
    };
    let (records, _) = data.as_chunks::<384>();
    records
        .iter()
        .filter(|r| i16::from_ne_bytes([r[0], r[1]]) == 7) // USER_PROCESS
        .map(|r| {
            let secs = i32::from_ne_bytes(r[340..344].try_into().unwrap_or_default());
            json!({
                "user": text(&r[44..76]),
                "line": text(&r[8..40]),
                "host": text(&r[76..332]),
                "pid": i32::from_ne_bytes(r[4..8].try_into().unwrap_or_default()),
                "login": crate::rfc3339(i64::from(secs), 0),
            })
        })
        .collect()
}

fn lines_of(path: &str) -> Vec<String> {
    read(path)
        .map(|c| c.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Everything, as one JSON document.
pub fn collect(hash_executables: bool) -> Value {
    let mut m = Map::new();
    m.insert("collected_at".into(), json!(crate::now_rfc3339()));
    m.insert("host".into(), json!(crate::host_name()));
    m.insert(
        "kernel".into(),
        json!({
            "release": read("/proc/sys/kernel/osrelease").map(|s| s.trim().to_string()),
            "version": read("/proc/sys/kernel/version").map(|s| s.trim().to_string()),
            "cmdline": read("/proc/cmdline").map(|s| s.trim().to_string()),
        }),
    );
    m.insert(
        "boot_time".into(),
        json!(boot_time().map(|b| crate::rfc3339(b as i64, 0))),
    );
    m.insert(
        "uptime_seconds".into(),
        json!(read("/proc/uptime").and_then(|u| u.split_whitespace().next()?.parse::<f64>().ok())),
    );
    m.insert("users".into(), json!(users()));
    m.insert("processes".into(), json!(processes(hash_executables)));
    m.insert("sockets".into(), json!(sockets()));
    m.insert("interfaces".into(), json!(interfaces()));
    m.insert("routes".into(), json!(lines_of("/proc/net/route")));
    m.insert("routes6".into(), json!(lines_of("/proc/net/ipv6_route")));
    m.insert("arp".into(), json!(lines_of("/proc/net/arp")));
    m.insert("resolv_conf".into(), json!(read("/etc/resolv.conf")));
    m.insert("mounts".into(), json!(lines_of("/proc/self/mountinfo")));
    m.insert("swaps".into(), json!(lines_of("/proc/swaps")));
    m.insert(
        "modules".into(),
        json!(lines_of("/proc/modules")
            .iter()
            .filter_map(|l| l.split_whitespace().next().map(str::to_string))
            .collect::<Vec<_>>()),
    );
    m.insert(
        "footprint".into(),
        json!({
            "read": ["/proc", "/sys/class/net", "/run/utmp", "/etc/resolv.conf"],
            "hashed": if hash_executables { "the executable of every running process, opened O_NOATIME where permitted" } else { "nothing" },
            "written": "only the output file",
        }),
    );
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_addresses() {
        assert_eq!(proc_addr("0100007F:0016").unwrap(), "127.0.0.1:22");
        assert_eq!(proc_addr("00000000:1F90").unwrap(), "0.0.0.0:8080");
        assert_eq!(
            proc_addr("00000000000000000000000001000000:0035").unwrap(),
            "[::1]:53"
        );
        assert!(proc_addr("zz:1").is_none());
    }

    #[test]
    fn proc_net_lines() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n";
        let owners = HashMap::from([(4242u64, vec![1u32, 77])]);
        let v = parse_proc_net("tcp", tcp, &owners);
        assert_eq!(v[0]["local"], "127.0.0.1:22");
        assert_eq!(v[0]["state"], "LISTEN");
        assert_eq!(v[0]["pids"], json!([1, 77]));
    }

    #[test]
    fn stat_with_spaces_in_the_name() {
        let f = stat_fields(
            "42 (my (odd) proc) S 1 42 42 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 12345 0",
        )
        .unwrap();
        assert_eq!(f[0], "S");
        assert_eq!(f[1], "1");
        assert_eq!(f[19], "12345");
    }

    #[test]
    fn this_process_and_its_socket_are_seen() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let me = std::process::id();
        // Hashing every executable of the host takes long; check our own
        let procs = processes(false);
        let mine = procs.iter().find(|p| p["pid"] == me).unwrap();
        assert!(mine["exe"].as_str().is_some());
        assert_eq!(sha256_file(Path::new("/proc/self/exe")).unwrap().len(), 64);
        let socks = sockets();
        let s = socks
            .iter()
            .find(|s| s["local"] == format!("127.0.0.1:{port}"))
            .unwrap();
        assert_eq!(s["state"], "LISTEN");
        assert!(s["pids"].as_array().unwrap().contains(&json!(me)));
        assert!(interfaces().iter().any(|i| i["name"] == "lo"));
    }
}
