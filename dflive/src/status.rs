//! `dflive status`: the scene record. Quick and read-only: the system clock
//! against a reference time the examiner enters, the OS, uptime, who is logged
//! in and with which rights dflive runs, disks and volumes, encryption at a
//! glance, and running cloud sync clients with their folders. It lists no user
//! directories: sync folders are found by looking up known names.

use serde_json::{json, Value};
use std::path::Path;

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant)
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// RFC 3339 with an offset ("2026-10-16T17:05:00+02:00", "…T15:05:00.250Z";
/// a space may replace the T) as Unix milliseconds
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| t.parse().ok())?
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&mo)
        || d < 1
        || d > month_days[(mo - 1) as usize]
        || h > 23
        || mi > 59
        || sec > 60
    {
        return None;
    }
    let mut i = 19;
    let mut millis = 0;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        let mut j = start;
        while j < b.len() && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == start {
            return None;
        }
        let frac = &s[start..j.min(start + 3)];
        millis = frac.parse::<i64>().ok()? * 10i64.pow(3 - frac.len() as u32);
        i = j;
    }
    let offset_minutes = match *b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        c @ (b'+' | b'-') if b.len() == i + 6 && b[i + 3] == b':' => {
            let v = num(i + 1..i + 3)? * 60 + num(i + 4..i + 6)?;
            if c == b'-' {
                -v
            } else {
                v
            }
        }
        _ => return None,
    };
    Some(
        (days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec - offset_minutes * 60)
            * 1000
            + millis,
    )
}

/// The clock record: the system clock at the moment the command was given
/// against the reference the examiner typed with it.
pub fn clock(system_ms: i64, reference: Option<&str>) -> anyhow::Result<Value> {
    let fmt = |ms: i64| crate::rfc3339(ms.div_euclid(1000), ms.rem_euclid(1000) as u32);
    let Some(r) = reference else {
        return Ok(json!({
            "system_utc": fmt(system_ms),
            "note": "no --reference-time given: compare the system clock with a reference by hand",
        }));
    };
    let ref_ms = parse_rfc3339(r).ok_or_else(|| {
        anyhow::anyhow!("--reference-time {r:?}: expected RFC 3339 with an offset, e.g. 2026-10-16T17:05:00+02:00")
    })?;
    Ok(json!({
        "system_utc": fmt(system_ms),
        "reference": r,
        "reference_utc": fmt(ref_ms),
        "offset_seconds": (system_ms - ref_ms) as f64 / 1000.0,
        "note": "positive: the system clock is ahead of the reference; the reference was typed with the command, so allow for a second or two",
    }))
}

/// Process names (lower case, without .exe) of cloud sync clients
const SYNC_CLIENTS: &[(&str, &str)] = &[
    ("onedrive", "OneDrive"),
    ("dropbox", "Dropbox"),
    ("maestral", "Dropbox (Maestral)"),
    ("googledrivefs", "Google Drive"),
    ("icloudservices", "iCloud"),
    ("iclouddrive", "iCloud"),
    ("bird", "iCloud Drive"),
    ("nextcloud", "Nextcloud"),
    ("owncloud", "ownCloud"),
    ("megasync", "MEGA"),
    ("box", "Box"),
    ("boxsync", "Box"),
    ("syncthing", "Syncthing"),
    ("pcloud", "pCloud"),
    ("rclone", "rclone"),
    ("seaf-daemon", "Seafile"),
    ("tresorit", "Tresorit"),
    ("cloud-drive-daemon", "Synology Drive"),
    ("insync", "Insync"),
];

/// The sync client a process name belongs to. Linux truncates names to 15
/// characters, so a 15-character name matches by prefix.
pub fn sync_client(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    let n = n.strip_suffix(".exe").unwrap_or(&n);
    SYNC_CLIENTS
        .iter()
        .find(|(p, _)| *p == n || (n.len() == 15 && p.starts_with(n)))
        .map(|(_, c)| *c)
}

/// Folder names below a user profile that sync clients create
const SYNC_FOLDERS: &[&str] = &[
    "OneDrive",
    "Dropbox",
    "Google Drive",
    "iCloudDrive",
    "Nextcloud",
    "ownCloud",
    "MEGA",
    "MEGAsync",
    "Box",
    "Box Sync",
    "Sync",
    "pCloud Drive",
    "Tresorit",
    "SynologyDrive",
    "Seafile",
    ".config/rclone/rclone.conf",
    "Library/CloudStorage",
    "Library/Mobile Documents",
];

/// Known sync folders under each profile, found by lookup (stat), not listing
pub fn sync_folders(profiles: &[String]) -> Vec<Value> {
    let mut out = Vec::new();
    for p in profiles {
        for f in SYNC_FOLDERS {
            let path = Path::new(p).join(f);
            if std::fs::symlink_metadata(&path).is_ok() {
                out.push(json!({ "profile": p, "path": path.display().to_string() }));
            }
        }
    }
    out
}

fn running_sync_clients(processes: &[Value]) -> Vec<Value> {
    processes
        .iter()
        .filter_map(|p| {
            let client = sync_client(p["name"].as_str()?)?;
            Some(json!({
                "client": client,
                "pid": p["pid"],
                "name": p["name"],
                "user": p.get("user").or(p.get("uid")),
            }))
        })
        .collect()
}

#[cfg(target_os = "linux")]
mod os {
    use serde_json::{json, Value};
    use std::{fs, io::Read, path::Path};

    fn read(p: impl AsRef<Path>) -> Option<String> {
        fs::read_to_string(p).ok().map(|s| s.trim().to_string())
    }

    /// Home directories of login accounts from /etc/passwd
    pub fn profiles() -> Vec<String> {
        let mut homes: Vec<String> = read("/etc/passwd")
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                let uid: u32 = f.get(2)?.parse().ok()?;
                let shell = f.get(6)?;
                ((uid == 0 || uid >= 1000)
                    && !shell.ends_with("nologin")
                    && !shell.ends_with("false"))
                .then(|| f.get(5).map(|h| h.to_string()))?
            })
            .filter(|h| h != "/" && !h.is_empty())
            .collect();
        homes.sort();
        homes.dedup();
        homes
    }

    pub fn system() -> Value {
        let os_release = read("/etc/os-release").unwrap_or_default();
        let pretty = os_release
            .lines()
            .find_map(|l| l.strip_prefix("PRETTY_NAME="))
            .map(|v| v.trim_matches('"').to_string());
        json!({
            "os": pretty,
            "kernel": read("/proc/sys/kernel/osrelease"),
            "time_zone": fs::read_link("/etc/localtime").ok().map(|p| p.display().to_string()),
            // SAFETY: no arguments
            "elevated": unsafe { libc::geteuid() } == 0,
            "uid": unsafe { libc::geteuid() },
        })
    }

    /// Block devices from sysfs, with mount points and a LUKS check
    pub fn disks() -> Vec<Value> {
        let mut mounts: Vec<(String, String, String)> = Vec::new();
        for l in read("/proc/self/mountinfo").unwrap_or_default().lines() {
            let f: Vec<&str> = l.split_whitespace().collect();
            let Some(dash) = f.iter().position(|x| *x == "-") else {
                continue;
            };
            if let (Some(dev), Some(mp), Some(fs)) = (f.get(2), f.get(4), f.get(dash + 1)) {
                mounts.push((dev.to_string(), mp.to_string(), fs.to_string()));
            }
        }
        let mut names: Vec<String> = fs::read_dir("/sys/class/block")
            .map(|d| {
                d.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        let list = |p: &Path| -> Vec<String> {
            fs::read_dir(p)
                .map(|d| {
                    d.flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default()
        };
        names
            .into_iter()
            .filter(|n| !n.starts_with("ram") && !n.starts_with("zram"))
            .filter_map(|n| {
                let sys = Path::new("/sys/class/block").join(&n);
                let sectors: u64 = read(sys.join("size"))?.parse().ok()?;
                if sectors == 0 {
                    return None;
                }
                let dev = read(sys.join("dev"));
                let mut head = [0u8; 6];
                let luks = fs::File::open(format!("/dev/{n}"))
                    .and_then(|mut f| f.read_exact(&mut head))
                    .is_ok()
                    && &head == b"LUKS\xba\xbe";
                let dm_uuid = read(sys.join("dm/uuid"));
                let mounted: Vec<Value> = mounts
                    .iter()
                    .filter(|(d, _, _)| Some(d) == dev.as_ref())
                    .map(|(_, mp, fs)| json!({ "mount_point": mp, "fs": fs }))
                    .collect();
                let device = sys.join("device");
                Some(json!({
                    "name": n,
                    "bytes": sectors * 512,
                    "partition": sys.join("partition").exists(),
                    "read_only": read(sys.join("ro")).as_deref() == Some("1"),
                    "removable": read(sys.join("removable")).as_deref() == Some("1"),
                    "rotational": read(sys.join("queue/rotational")).as_deref() == Some("1"),
                    "vendor": read(device.join("vendor")),
                    "model": read(device.join("model")),
                    "serial": read(device.join("serial")).or_else(|| read(device.join("wwid"))),
                    "transport": read(sys.join("device/transport")),
                    "dm_name": read(sys.join("dm/name")),
                    "dm_crypt": dm_uuid.as_deref().is_some_and(|u| u.starts_with("CRYPT-")),
                    "luks_header": luks,
                    "holders": list(&sys.join("holders")),
                    "backing": list(&sys.join("slaves")),
                    "mounts": mounted,
                }))
            })
            .collect()
    }

    pub fn encryption(disks: &[Value]) -> Value {
        json!({
            "luks_devices": disks.iter().filter(|d| d["luks_header"] == true).map(|d| d["name"].clone()).collect::<Vec<_>>(),
            "open_dm_crypt": disks.iter().filter(|d| d["dm_crypt"] == true).map(|d| d["dm_name"].clone()).collect::<Vec<_>>(),
        })
    }
}

#[cfg(windows)]
mod os {
    use crate::winfmt::utf16;
    use serde_json::{json, Value};
    use std::{mem::size_of, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        NetworkManagement::WNet::WNetGetConnectionW,
        Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
        Storage::FileSystem::{
            CreateFileW, GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDriveStringsW,
            GetVolumeInformationW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::{
            Ioctl::{
                PropertyStandardQuery, StorageDeviceProperty, DISK_GEOMETRY_EX,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_STORAGE_QUERY_PROPERTY,
                STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_QUERY,
            },
            Registry::{
                RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE,
                KEY_READ, RRF_RT_REG_SZ,
            },
            Threading::{GetCurrentProcess, OpenProcessToken},
            IO::DeviceIoControl,
        },
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Profile paths from the registry's ProfileList (no directory listing)
    pub fn profiles() -> Vec<String> {
        const LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
        let mut out = Vec::new();
        // SAFETY: a read-only key we close; names and values go into local buffers
        unsafe {
            let mut key: HKEY = ptr::null_mut();
            if RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wide(LIST).as_ptr(),
                0,
                KEY_READ,
                &mut key,
            ) != 0
            {
                return out;
            }
            for i in 0.. {
                let mut name = [0u16; 256];
                let mut len = name.len() as u32;
                if RegEnumKeyExW(
                    key,
                    i,
                    name.as_mut_ptr(),
                    &mut len,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                ) != 0
                {
                    break;
                }
                let sid = String::from_utf16_lossy(&name[..len as usize]);
                // Service accounts (S-1-5-18/19/20) have no user profile worth checking
                if !sid.starts_with("S-1-5-21-") {
                    continue;
                }
                let sub = wide(&sid);
                let value = wide("ProfileImagePath");
                let mut buf = [0u16; 1024];
                let mut bytes = (buf.len() * 2) as u32;
                if RegGetValueW(
                    key,
                    sub.as_ptr(),
                    value.as_ptr(),
                    RRF_RT_REG_SZ,
                    ptr::null_mut(),
                    buf.as_mut_ptr().cast(),
                    &mut bytes,
                ) == 0
                {
                    out.push(utf16(&buf));
                }
            }
            RegCloseKey(key);
        }
        out
    }

    pub fn system() -> Value {
        // SAFETY: a query on our own token, closed below
        let elevated = unsafe {
            let mut token = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                None
            } else {
                let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
                let mut len = 0u32;
                let ok = GetTokenInformation(
                    token,
                    TokenElevation,
                    (&mut e as *mut TOKEN_ELEVATION).cast(),
                    size_of::<TOKEN_ELEVATION>() as u32,
                    &mut len,
                );
                CloseHandle(token);
                (ok != 0).then_some(e.TokenIsElevated != 0)
            }
        };
        json!({
            "os": crate::state::os_info(),
            "time_zone": crate::state::time_zone(),
            "elevated": elevated,
            "user": std::env::var("USERNAME").ok(),
            "domain": std::env::var("USERDOMAIN").ok(),
        })
    }

    fn volumes() -> Vec<Value> {
        let mut out = Vec::new();
        let mut buf = [0u16; 512];
        // SAFETY: the API fills our buffer with NUL-separated roots
        let n = unsafe { GetLogicalDriveStringsW(buf.len() as u32, buf.as_mut_ptr()) } as usize;
        for root in buf[..n.min(buf.len())]
            .split(|&c| c == 0)
            .filter(|r| !r.is_empty())
        {
            let root_s = String::from_utf16_lossy(root);
            let root_w = wide(&root_s);
            // SAFETY: plain queries on a drive root with local buffers
            unsafe {
                let kind = GetDriveTypeW(root_w.as_ptr());
                let (mut label, mut fs) = ([0u16; 261], [0u16; 261]);
                let (mut serial, mut maxlen, mut flags) = (0u32, 0u32, 0u32);
                let info = GetVolumeInformationW(
                    root_w.as_ptr(),
                    label.as_mut_ptr(),
                    label.len() as u32,
                    &mut serial,
                    &mut maxlen,
                    &mut flags,
                    fs.as_mut_ptr(),
                    fs.len() as u32,
                ) != 0;
                let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
                let space =
                    GetDiskFreeSpaceExW(root_w.as_ptr(), &mut avail, &mut total, &mut free) != 0;
                let remote = if kind == 4 {
                    let local = wide(root_s.trim_end_matches('\\'));
                    let mut r = [0u16; 1024];
                    let mut len = r.len() as u32;
                    (WNetGetConnectionW(local.as_ptr(), r.as_mut_ptr(), &mut len) == 0)
                        .then(|| utf16(&r))
                } else {
                    None
                };
                out.push(json!({
                    "root": root_s,
                    "type": crate::winfmt::drive_type(kind),
                    "label": info.then(|| utf16(&label)),
                    "fs": info.then(|| utf16(&fs)),
                    "serial": info.then(|| format!("{:04X}-{:04X}", serial >> 16, serial & 0xffff)),
                    "bytes": space.then_some(total),
                    "free_bytes": space.then_some(free),
                    "remote": remote,
                }));
            }
        }
        out
    }

    /// Physical drives: model, serial and bus from IOCTL_STORAGE_QUERY_PROPERTY
    /// and the size from the drive geometry, on a handle opened for queries only
    fn physical_drives() -> Vec<Value> {
        let mut out = Vec::new();
        for i in 0..32 {
            let path = wide(&format!(r"\\.\PhysicalDrive{i}"));
            // SAFETY: a query-only handle (no read or write access), closed below
            unsafe {
                let h = CreateFileW(
                    path.as_ptr(),
                    0,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    ptr::null(),
                    OPEN_EXISTING,
                    0,
                    ptr::null_mut(),
                );
                if h == INVALID_HANDLE_VALUE {
                    continue;
                }
                let q = STORAGE_PROPERTY_QUERY {
                    PropertyId: StorageDeviceProperty,
                    QueryType: PropertyStandardQuery,
                    AdditionalParameters: [0],
                };
                let mut buf = vec![0u64; 512];
                let mut n = 0u32;
                let desc = (DeviceIoControl(
                    h,
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    (&q as *const STORAGE_PROPERTY_QUERY).cast(),
                    size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                    buf.as_mut_ptr().cast(),
                    (buf.len() * 8) as u32,
                    &mut n,
                    ptr::null_mut(),
                ) != 0
                    && n as usize >= size_of::<STORAGE_DEVICE_DESCRIPTOR>())
                .then(|| {
                    let bytes = std::slice::from_raw_parts(buf.as_ptr() as *const u8, n as usize);
                    let d = &*(buf.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR);
                    let text = |off: u32| -> Option<String> {
                        let s = bytes.get(off as usize..).filter(|_| off != 0)?;
                        let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
                        Some(String::from_utf8_lossy(&s[..end]).trim().to_string())
                            .filter(|t| !t.is_empty())
                    };
                    json!({
                        "vendor": text(d.VendorIdOffset),
                        "model": text(d.ProductIdOffset),
                        "revision": text(d.ProductRevisionOffset),
                        "serial": text(d.SerialNumberOffset),
                        "bus": crate::winfmt::bus_type(d.BusType),
                        "removable": d.RemovableMedia,
                    })
                });
                let mut g = vec![0u64; 32];
                let size = (DeviceIoControl(
                    h,
                    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                    ptr::null(),
                    0,
                    g.as_mut_ptr().cast(),
                    (g.len() * 8) as u32,
                    &mut n,
                    ptr::null_mut(),
                ) != 0)
                    .then(|| (*(g.as_ptr() as *const DISK_GEOMETRY_EX)).DiskSize as u64);
                CloseHandle(h);
                let mut entry =
                    json!({ "device": format!(r"\\.\PhysicalDrive{i}"), "bytes": size });
                if let (Some(m), Some(Value::Object(d))) = (entry.as_object_mut(), desc) {
                    m.extend(d);
                }
                out.push(entry);
            }
        }
        out
    }

    pub fn disks() -> Vec<Value> {
        let mut d = physical_drives();
        d.extend(volumes());
        d
    }

    pub fn encryption(_disks: &[Value]) -> Value {
        // manage-bde -status lists protection per volume without key material
        json!({ "manage_bde_status": crate::keys::run("manage-bde", &["-status"]) })
    }
}

#[cfg(target_os = "macos")]
mod os {
    use serde_json::{json, Value};

    pub fn profiles() -> Vec<String> {
        Vec::new()
    }

    pub fn system() -> Value {
        json!({
            "sw_vers": crate::keys::run("sw_vers", &[]),
            "boottime": crate::keys::run("sysctl", &["-n", "kern.boottime"]),
            // SAFETY: no arguments
            "elevated": unsafe { libc::geteuid() } == 0,
        })
    }

    pub fn disks() -> Vec<Value> {
        vec![crate::keys::run("diskutil", &["list"])]
    }

    pub fn encryption(_disks: &[Value]) -> Value {
        json!({ "fdesetup_status": crate::keys::run("fdesetup", &["status"]) })
    }
}

/// Everything, as one JSON document
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub fn collect(system_ms: i64, reference: Option<&str>) -> anyhow::Result<Value> {
    let clock = clock(system_ms, reference)?;
    #[cfg(any(target_os = "linux", windows))]
    let (users, processes) = (crate::state::users(), crate::state::processes(false));
    #[cfg(target_os = "macos")]
    let (users, processes): (Vec<Value>, Vec<Value>) =
        (vec![crate::keys::run("who", &[])], Vec::new());
    let disks = os::disks();
    let profiles = os::profiles();
    Ok(json!({
        "collected_at": crate::now_rfc3339(),
        "host": crate::host_name(),
        "clock": clock,
        "system": os::system(),
        "users": users,
        "disks": disks,
        "encryption": os::encryption(&disks),
        "sync_clients": running_sync_clients(&processes),
        "profiles": profiles,
        "sync_folders": sync_folders(&profiles),
        "process_count": processes.len(),
        "footprint": "reads system information, block-device headers (6 bytes) and two registry keys on Windows; looks up known folder names in user profiles without listing them; writes only the output file",
    }))
}

/// The few lines an examiner needs at the scene, on stderr
pub fn summary(doc: &Value) {
    let c = &doc["clock"];
    match c["offset_seconds"].as_f64() {
        Some(o) => eprintln!(
            "[*] Clock: system {} vs reference {} -> system is {:.1} s {}",
            c["system_utc"].as_str().unwrap_or("?"),
            c["reference_utc"].as_str().unwrap_or("?"),
            o.abs(),
            if o >= 0.0 { "ahead" } else { "behind" }
        ),
        None => eprintln!(
            "[!] Clock: system {} (no --reference-time: compare by hand and note it)",
            c["system_utc"].as_str().unwrap_or("?")
        ),
    }
    let sys = &doc["system"];
    if sys["elevated"] != true {
        eprintln!("[!] Not running as root/administrator: keys and mem will see less");
    }
    let users: Vec<String> = doc["users"]
        .as_array()
        .map(|u| {
            u.iter()
                .filter_map(|x| x["user"].as_str().filter(|s| !s.is_empty()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    eprintln!(
        "[*] Logged in: {}",
        if users.is_empty() {
            "nobody".to_string()
        } else {
            users.join(", ")
        }
    );
    if let Some(e) = doc["encryption"].as_object() {
        for (k, v) in e {
            match v {
                Value::Array(a) if !a.is_empty() => {
                    eprintln!("[!] Encryption: {k}: {}", Value::Array(a.clone()))
                }
                _ => {}
            }
        }
    }
    for s in doc["sync_clients"].as_array().into_iter().flatten() {
        eprintln!(
            "[!] Sync client running: {} (pid {}): data may change or arrive from the cloud",
            s["client"].as_str().unwrap_or("?"),
            s["pid"]
        );
    }
    for f in doc["sync_folders"].as_array().into_iter().flatten() {
        eprintln!("[*] Sync folder: {}", f["path"].as_str().unwrap_or("?"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_parsing() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(parse_rfc3339("1969-12-31T19:00:00-05:00"), Some(0));
        assert_eq!(
            parse_rfc3339("2026-10-16 17:05:00.25+02:00"),
            Some(1_792_163_100_250)
        );
        assert_eq!(
            parse_rfc3339("2024-02-29T12:34:56.789Z"),
            Some(1_709_210_096_789)
        );
        assert_eq!(parse_rfc3339("2023-02-29T00:00:00Z"), None);
        assert_eq!(parse_rfc3339("2026-10-16T17:05:00"), None);
        assert_eq!(parse_rfc3339("2026-10-16T17:05:00+0200"), None);
        assert_eq!(parse_rfc3339("2026-13-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339("2026-10-16T17:05:00.Z"), None);
        assert_eq!(parse_rfc3339("+026-10-16T17:05:00Z"), None);
        // round trip through the formatter
        let ms = 1_792_163_100_250;
        let s = crate::rfc3339(ms / 1000, (ms % 1000) as u32);
        assert_eq!(parse_rfc3339(&s), Some(ms));
    }

    #[test]
    fn clock_offset() {
        let c = clock(1_000_000_002_500, Some("2001-09-09T01:46:40Z")).unwrap();
        assert_eq!(c["offset_seconds"], 2.5);
        assert!(clock(0, Some("yesterday")).is_err());
        assert!(clock(0, None).unwrap()["note"].is_string());
    }

    #[test]
    fn sync_clients_by_process_name() {
        assert_eq!(sync_client("OneDrive.exe"), Some("OneDrive"));
        assert_eq!(sync_client("dropbox"), Some("Dropbox"));
        assert_eq!(sync_client("cloud-drive-dae"), Some("Synology Drive"));
        assert_eq!(sync_client("boxer"), None);
        assert_eq!(sync_client("explorer.exe"), None);
        let procs = vec![
            json!({"pid": 7, "name": "OneDrive.exe", "user": "PC\\a"}),
            json!({"pid": 8, "name": "bash"}),
        ];
        let found = running_sync_clients(&procs);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["pid"], 7);
    }

    #[test]
    fn sync_folders_by_lookup() {
        let dir = std::env::temp_dir().join(format!("dflive-sync-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("Dropbox")).unwrap();
        let found = sync_folders(&[dir.display().to_string()]);
        assert_eq!(found.len(), 1);
        assert!(found[0]["path"].as_str().unwrap().ends_with("Dropbox"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
