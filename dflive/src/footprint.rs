//! The footprint log: one JSON line per dflive run, appended to `--log` (on
//! the kit's output partition or the target drive). It records dflive's own
//! SHA-256 and the kit it ran from, every child command with its exit status,
//! every file written with its SHA-256, and the outcome, so the report can
//! account for everything dflive did on the suspect system.

use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

static CHILDREN: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static WRITTEN: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static RESULT: Mutex<Option<Value>> = Mutex::new(None);

/// A child process dflive ran (system tools, AVML, WinPmem).
pub fn child(command: &str, started: &str, exit: Option<i32>, error: Option<&str>) {
    if let Ok(mut c) = CHILDREN.lock() {
        c.push(json!({
            "command": command,
            "started": started,
            "finished": crate::now_rfc3339(),
            "exit": exit,
            "error": error,
        }));
    }
}

/// A file dflive wrote.
pub fn wrote(path: &str, bytes: u64, sha256: &str) {
    if let Ok(mut w) = WRITTEN.lock() {
        w.push(json!({ "path": path, "bytes": bytes, "sha256": sha256 }));
    }
}

/// The action's own summary (send: the stream and the receiver's verdict).
pub fn result(v: Value) {
    if let Ok(mut r) = RESULT.lock() {
        *r = Some(v);
    }
}

pub fn sha256_file(path: &Path) -> Option<(u64, String)> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    Some((
        total,
        h.finalize().iter().map(|b| format!("{b:02x}")).collect(),
    ))
}

/// The expected hash of `rel` (forward slashes) in a KIT-MANIFEST.sha256
/// (`sha256sum` output: hash, two spaces, path).
pub fn listed_hash(manifest: &str, rel: &str) -> Option<String> {
    manifest.lines().find_map(|l| {
        let (hash, path) = l.split_once("  ")?;
        let path = path.strip_prefix('*').unwrap_or(path);
        (path == rel || path.eq_ignore_ascii_case(rel)).then(|| hash.to_ascii_lowercase())
    })
}

/// "dfnix Field-Kit Stick v0 (0.1.0) — ..." → "0.1.0"
pub fn kit_version(sources_txt: &str) -> Option<String> {
    sources_txt.lines().find_map(|l| {
        let rest = l.split_once("Field-Kit Stick")?.1;
        let v = rest.split_once('(')?.1.split_once(')')?.0;
        Some(v.trim().to_string())
    })
}

/// dflive's executable, its hash, and the kit partition it ran from (the
/// nearest ancestor directory holding KIT-MANIFEST.sha256), with whether the
/// kit lists dflive with exactly this hash.
pub fn identity() -> Value {
    let exe = std::env::current_exe().ok();
    let own = exe.as_deref().and_then(sha256_file);
    let kit = exe.as_deref().and_then(|exe| {
        let root: PathBuf = exe
            .ancestors()
            .skip(1)
            .take(4)
            .find(|d| d.join("KIT-MANIFEST.sha256").is_file())?
            .to_path_buf();
        let manifest = std::fs::read_to_string(root.join("KIT-MANIFEST.sha256")).ok()?;
        let rel = exe
            .strip_prefix(&root)
            .ok()?
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        let listed = listed_hash(&manifest, &rel);
        Some(json!({
            "root": root.display().to_string(),
            "version": std::fs::read_to_string(root.join("SOURCES.txt")).ok().as_deref().and_then(kit_version),
            "manifest_sha256": sha256_file(&root.join("KIT-MANIFEST.sha256")).map(|(_, h)| h),
            "dflive_path": rel,
            "dflive_listed_sha256": listed,
            "dflive_matches_kit": match (&listed, &own) {
                (Some(l), Some((_, o))) => Some(l == o),
                _ => None,
            },
        }))
    });
    json!({
        "exe": exe.map(|p| p.display().to_string()),
        "exe_sha256": own.map(|(_, h)| h),
        "kit": kit,
    })
}

/// Append this run's record to `log`.
pub fn append(
    log: &str,
    action: &str,
    started: &str,
    outcome: &Result<u8, String>,
) -> anyhow::Result<()> {
    let take = |m: &Mutex<Vec<Value>>| {
        m.lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
    };
    let record = json!({
        "tool": "dflive",
        "version": crate::VERSION,
        "action": action,
        "arguments": std::env::args().skip(1).collect::<Vec<_>>(),
        "host": crate::host_name(),
        "os": format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        "started": started,
        "finished": crate::now_rfc3339(),
        "self": identity(),
        "children": take(&CHILDREN),
        "written": take(&WRITTEN),
        "result": RESULT.lock().ok().and_then(|mut r| r.take()),
        "exit_code": outcome.as_ref().ok(),
        "error": outcome.as_ref().err(),
    });
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)?;
    writeln!(f, "{record}")?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kit_manifest_lookup() {
        let m = "aa11  SOURCES.txt\nBB22  dflive/x86_64/dflive\ncc33 *winpmem/winpmem_mini_x64_rc2.exe\n";
        assert_eq!(
            listed_hash(m, "dflive/x86_64/dflive").as_deref(),
            Some("bb22")
        );
        assert_eq!(
            listed_hash(m, "DFLIVE/X86_64/DFLIVE").as_deref(),
            Some("bb22")
        );
        assert_eq!(listed_hash(m, "dflive/aarch64/dflive"), None);
        assert_eq!(
            kit_version("====\ndfnix Field-Kit Stick v0 (0.1.0) — Component Licences\n").as_deref(),
            Some("0.1.0")
        );
        assert_eq!(kit_version("nothing"), None);
    }

    #[test]
    fn records_children_and_files() {
        let dir = std::env::temp_dir().join(format!("dflive-fp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("log.jsonl");
        child("true", "2026-01-01T00:00:00.000Z", Some(0), None);
        wrote("/x", 3, "abc");
        result(json!({"k": 1}));
        append(
            log.to_str().unwrap(),
            "test",
            "2026-01-01T00:00:00.000Z",
            &Ok(0),
        )
        .unwrap();
        append(
            log.to_str().unwrap(),
            "test",
            "2026-01-01T00:00:01.000Z",
            &Err("boom".into()),
        )
        .unwrap();
        let lines: Vec<Value> = std::fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["children"][0]["command"], "true");
        assert_eq!(lines[0]["written"][0]["sha256"], "abc");
        assert_eq!(lines[0]["result"]["k"], 1);
        assert_eq!(
            lines[0]["self"]["exe_sha256"].as_str().map(str::len),
            Some(64)
        );
        // the second run starts empty
        assert_eq!(lines[1]["children"], json!([]));
        assert_eq!(lines[1]["error"], "boom");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
