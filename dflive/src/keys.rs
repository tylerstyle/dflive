//! `dflive keys`: encryption state and key material of a running system,
//! taken while the volumes are unlocked, before anything else.
//!
//! Everything goes into one JSON document. With `--recipient` (an age public
//! key of the examiner) only its age-encrypted form is ever written, so key
//! material never lies in plain text on the kit stick.

use serde_json::{json, Value};
use std::process::Command;

/// Run a system command, record exactly what it said, and note it in the
/// footprint log.
pub(crate) fn run(program: &str, args: &[&str]) -> Value {
    let command = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    let started = crate::now_rfc3339();
    match Command::new(program).args(args).output() {
        Ok(out) => {
            crate::footprint::child(&command, &started, out.status.code(), None);
            json!({
                "command": command,
                "exit": out.status.code(),
                "stdout": String::from_utf8_lossy(&out.stdout),
                "stderr": String::from_utf8_lossy(&out.stderr),
            })
        }
        Err(e) => {
            crate::footprint::child(&command, &started, None, Some(&e.to_string()));
            json!({ "command": command, "error": e.to_string() })
        }
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (k, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            out.push(if k <= chunk.len() {
                T[((n >> shift) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

/// The LUKS header area to back up: LUKS1 up to the payload offset, LUKS2 up
/// to the first data segment (binary headers, JSON areas and keyslots).
/// `None` if `head` (the device's first 4096 bytes and more) is not LUKS.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn luks_header_len(
    head: &[u8],
    json_area: impl FnOnce(u64) -> Option<Vec<u8>>,
) -> Option<(u32, u64)> {
    if head.len() < 512 || &head[..6] != b"LUKS\xba\xbe" {
        return None;
    }
    let version = u16::from_be_bytes([head[6], head[7]]);
    match version {
        1 => {
            let payload = u32::from_be_bytes(head[104..108].try_into().ok()?);
            Some((1, u64::from(payload) * 512))
        }
        2 => {
            let hdr_size = u64::from_be_bytes(head[8..16].try_into().ok()?);
            let area = json_area(hdr_size)?;
            // The JSON area follows the 4096-byte binary header
            let json_bytes = area.get(4096..)?;
            let end = json_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(json_bytes.len());
            let meta: Value = serde_json::from_slice(&json_bytes[..end]).ok()?;
            let offset = meta["segments"]
                .as_object()?
                .values()
                .filter_map(|s| s["offset"].as_str()?.parse::<u64>().ok())
                .min()?;
            Some((2, offset))
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn linux() -> Value {
    use std::{fs, io::Read, path::Path};
    const LIMIT: u64 = 64 << 20;
    let mut headers = Vec::new();
    let mut names: Vec<String> = fs::read_dir("/sys/class/block")
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    for name in names {
        if name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram") {
            continue;
        }
        let dev = format!("/dev/{name}");
        let Ok(mut f) = fs::File::open(&dev) else {
            continue;
        };
        let mut head = vec![0u8; 4096];
        if f.read_exact(&mut head).is_err() {
            continue;
        }
        let read_area = |len: u64| -> Option<Vec<u8>> {
            let mut f = fs::File::open(&dev).ok()?;
            let mut buf = vec![0u8; len.min(LIMIT) as usize];
            f.read_exact(&mut buf).ok()?;
            Some(buf)
        };
        let Some((version, len)) = luks_header_len(&head, read_area) else {
            continue;
        };
        let backup = (len <= LIMIT).then(|| read_area(len)).flatten();
        headers.push(json!({
            "device": dev,
            "luks_version": version,
            "header_bytes": len,
            "header_base64": backup.as_deref().map(base64),
            "note": if backup.is_none() { Some("header area larger than 64 MiB or unreadable; back it up with cryptsetup luksHeaderBackup") } else { None },
        }));
    }
    // Mappings with their keys: hex for LUKS1/plain, a keyring reference for LUKS2
    let table = run("dmsetup", &["table", "--showkeys"]);
    let keyring = table["stdout"]
        .as_str()
        .is_some_and(|s| s.contains(":logon:") || s.contains(":user:"));
    let mut mappings = Vec::new();
    if let Ok(dir) = fs::read_dir("/sys/class/block") {
        for e in dir.flatten() {
            let dm = e.path().join("dm");
            if !Path::new(&dm).exists() {
                continue;
            }
            let read = |f: &str| {
                fs::read_to_string(dm.join(f))
                    .ok()
                    .map(|s| s.trim().to_string())
            };
            let slaves: Vec<String> = fs::read_dir(e.path().join("slaves"))
                .map(|d| {
                    d.flatten()
                        .map(|s| s.file_name().to_string_lossy().into_owned())
                        .collect()
                })
                .unwrap_or_default();
            mappings.push(json!({
                "kernel_name": e.file_name().to_string_lossy(),
                "name": read("name"),
                "uuid": read("uuid"),
                "backing": slaves,
            }));
        }
    }
    json!({
        "luks_headers": headers,
        "dm_mappings": mappings,
        "keyring_keys": keyring,
        "keyring_note": if keyring { Some("LUKS2 keeps volume keys in the kernel keyring (logon keys cannot be read from user space): take memory (dflive mem / AVML) and stream the unlocked /dev/mapper devices (dflive send) before power-off") } else { None },
        "commands": [
            table,
            run("cryptsetup", &["--version"]),
            run("zfs", &["get", "-H", "-o", "name,property,value", "encryption,keystatus,keyformat,keylocation"]),
            run("cat", &["/etc/crypttab"]),
        ],
    })
}

#[cfg(windows)]
fn windows() -> Value {
    let status = run("manage-bde", &["-status"]);
    // "Volume C: [OS]" lines name the volumes
    let mut volumes: Vec<String> = status["stdout"]
        .as_str()
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().strip_prefix("Volume "))
        .filter_map(|v| v.split_whitespace().next())
        .filter(|v| v.ends_with(':'))
        .map(str::to_string)
        .collect();
    volumes.dedup();
    let mut commands = vec![status];
    for v in &volumes {
        commands.push(run("manage-bde", &["-protectors", "-get", v]));
    }
    json!({ "volumes": volumes, "commands": commands })
}

#[cfg(target_os = "macos")]
fn macos() -> Value {
    json!({
        "commands": [
            run("fdesetup", &["status"]),
            run("fdesetup", &["list", "-extended"]),
            run("diskutil", &["apfs", "list"]),
            run("diskutil", &["apfs", "listCryptoUsers", "/"]),
        ],
    })
}

/// Everything, as one JSON document.
pub fn collect() -> Value {
    #[cfg(target_os = "linux")]
    let details = linux();
    #[cfg(windows)]
    let details = windows();
    #[cfg(target_os = "macos")]
    let details = macos();
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    let details = json!({ "note": "no key capture for this OS" });
    json!({
        "collected_at": crate::now_rfc3339(),
        "host": crate::host_name(),
        "os": format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        "details": details,
        "footprint": "runs the system's own encryption tools (listed under commands) and reads block devices; writes only the output file",
    })
}

/// The document, encrypted to `recipients` (age X25519 public keys) if any.
pub fn seal(doc: &[u8], recipients: &[String]) -> anyhow::Result<Vec<u8>> {
    use std::io::Write;
    if recipients.is_empty() {
        return Ok(doc.to_vec());
    }
    let parsed: Vec<age::x25519::Recipient> = recipients
        .iter()
        .map(|r| {
            r.parse()
                .map_err(|e| anyhow::anyhow!("not an age X25519 public key: {r}: {e}"))
        })
        .collect::<anyhow::Result<_>>()?;
    let encryptor =
        age::Encryptor::with_recipients(parsed.iter().map(|r| r as &dyn age::Recipient))
            .map_err(|e| anyhow::anyhow!("age: {e}"))?;
    let mut out = Vec::new();
    let mut w = encryptor.wrap_output(&mut out)?;
    w.write_all(doc)?;
    w.finish()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn luks1(payload_sectors: u32) -> Vec<u8> {
        let mut h = vec![0u8; 4096];
        h[..6].copy_from_slice(b"LUKS\xba\xbe");
        h[6..8].copy_from_slice(&1u16.to_be_bytes());
        h[104..108].copy_from_slice(&payload_sectors.to_be_bytes());
        h
    }

    #[test]
    fn luks_header_areas() {
        assert_eq!(
            luks_header_len(&luks1(4096), |_| None),
            Some((1, 4096 * 512))
        );
        assert_eq!(luks_header_len(&[0u8; 4096], |_| None), None);

        let mut h = vec![0u8; 4096];
        h[..6].copy_from_slice(b"LUKS\xba\xbe");
        h[6..8].copy_from_slice(&2u16.to_be_bytes());
        h[8..16].copy_from_slice(&16384u64.to_be_bytes());
        let mut area = vec![0u8; 16384];
        area[..4096].copy_from_slice(&h);
        let meta = br#"{"segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic"}}}"#;
        area[4096..4096 + meta.len()].copy_from_slice(meta);
        assert_eq!(
            luks_header_len(&h, |len| {
                assert_eq!(len, 16384);
                Some(area.clone())
            }),
            Some((2, 16 << 20))
        );
    }

    #[test]
    fn sealed_documents_open_only_with_the_identity() {
        use std::io::Read;
        let id = age::x25519::Identity::generate();
        let sealed = seal(b"{\"secret\":1}", &[id.to_public().to_string()]).unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"secret"));
        let dec = age::Decryptor::new(&sealed[..]).unwrap();
        let mut r = dec
            .decrypt(std::iter::once(&id as &dyn age::Identity))
            .unwrap();
        let mut plain = Vec::new();
        r.read_to_end(&mut plain).unwrap();
        assert_eq!(plain, b"{\"secret\":1}");
        assert!(seal(b"x", &["not-a-key".into()]).is_err());
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }
}
