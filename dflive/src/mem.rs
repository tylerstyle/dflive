//! `dflive mem`: physical memory through the kit's tool (AVML on Linux,
//! WinPmem on Windows), with the capture window (start and end: memory changes
//! while it is read), the tool's own hash, its exit status and the dump's
//! SHA-256 recorded next to the dump.

use crate::footprint::{self, sha256_file};
use anyhow::{bail, Context, Result};
use serde_json::json;
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

/// Where the kit keeps the memory tool, relative to dflive's own directory
/// (`dflive/<arch>/dflive` and `avml/<arch>/avml` on KIT-LNX,
/// `dflive\dflive.exe` and `winpmem\` on KIT-WIN), then `PATH`.
fn find_tool(explicit: Option<&str>) -> Result<PathBuf> {
    if let Some(t) = explicit {
        return Ok(PathBuf::from(t));
    }
    let exe_dir = std::env::current_exe()?
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    let arch = std::env::consts::ARCH;
    let candidates: Vec<PathBuf> = if cfg!(windows) {
        let name = if arch == "x86" {
            "winpmem_mini_x86.exe"
        } else {
            "winpmem_mini_x64_rc2.exe"
        };
        vec![
            exe_dir.join(name),
            exe_dir.join("..").join("winpmem").join(name),
        ]
    } else {
        // dflive at the root, one or two levels deep on KIT-LNX
        let kit = |up: &[&str]| {
            up.iter()
                .fold(exe_dir.clone(), |p, u| p.join(u))
                .join("avml")
                .join(arch)
                .join("avml")
        };
        vec![
            exe_dir.join("avml"),
            kit(&[]),
            kit(&[".."]),
            kit(&["..", ".."]),
        ]
    };
    for c in &candidates {
        if c.is_file() {
            return Ok(c.clone());
        }
    }
    let name = if cfg!(windows) {
        "winpmem_mini_x64_rc2.exe"
    } else {
        "avml"
    };
    Ok(PathBuf::from(name))
}

pub fn run(out: &str, tool: Option<&str>, compress: bool) -> Result<u8> {
    if cfg!(target_os = "macos") {
        bail!("no reliable memory tool exists for current macOS; record that and continue with the next step");
    }
    let out_path = Path::new(out);
    if out_path.exists() {
        bail!("{out} exists already; memory is never written over an earlier dump");
    }
    let record_path = PathBuf::from(format!("{out}.json"));
    if record_path.exists() {
        bail!("{} exists already", record_path.display());
    }
    let tool = find_tool(tool)?;
    let tool_hash = sha256_file(&tool).map(|(_, h)| h);
    // AVML (0.20): `acquire [--compress] FILE`; WinPmem mini: `FILE`
    let mut args: Vec<String> = Vec::new();
    if !cfg!(windows) {
        args.push("acquire".into());
        if compress {
            args.push("--compress".into());
        }
    }
    args.push(out.to_string());

    let start = crate::now_rfc3339();
    eprintln!(
        "[*] {} {} (started {start})",
        tool.display(),
        args.join(" ")
    );
    let command = format!("{} {}", tool.display(), args.join(" "));
    let output = match Command::new(&tool).args(&args).output() {
        Ok(o) => o,
        Err(e) => {
            footprint::child(&command, &start, None, Some(&e.to_string()));
            return Err(e).with_context(|| format!("Cannot run {}", tool.display()));
        }
    };
    footprint::child(&command, &start, output.status.code(), None);
    let end = crate::now_rfc3339();
    let dump = sha256_file(out_path);
    if let Some((bytes, sha)) = &dump {
        footprint::wrote(out, *bytes, sha);
    }
    let tail = |b: &[u8]| {
        let s = String::from_utf8_lossy(b);
        let lines: Vec<&str> = s.lines().collect();
        lines[lines.len().saturating_sub(20)..].join("\n")
    };
    let record = json!({
        "tool": "dflive",
        "version": crate::VERSION,
        "action": "memory",
        "host": crate::host_name(),
        "memory_tool": tool.display().to_string(),
        "memory_tool_sha256": tool_hash,
        "arguments": args,
        "started": start,
        "finished": end,
        "note": "memory changes while it is read: the capture covers the window from started to finished",
        "exit_code": output.status.code(),
        "stdout_tail": tail(&output.stdout),
        "stderr_tail": tail(&output.stderr),
        "dump": out,
        "dump_bytes": dump.as_ref().map(|d| d.0),
        "dump_sha256": dump.as_ref().map(|d| d.1.clone()),
        "footprint": if cfg!(windows) {
            "WinPmem loads its signed kernel driver as a temporary service (System event 7045) and unloads it at the end"
        } else {
            "AVML reads /proc/kcore, /dev/crash or /dev/mem; no kernel module is loaded"
        },
    });
    let record_bytes = serde_json::to_string_pretty(&record)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&record_path)?;
    f.write_all(record_bytes.as_bytes())?;
    f.sync_all()?;
    {
        use sha2::Digest;
        let digest: String = sha2::Sha256::digest(record_bytes.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        footprint::wrote(
            &record_path.display().to_string(),
            record_bytes.len() as u64,
            &digest,
        );
    }
    match (&dump, output.status.success()) {
        (Some((bytes, sha)), true) => {
            eprintln!(
                "[✓] {out}: {bytes} bytes, SHA-256 {sha} ({start} .. {end}); record {}",
                record_path.display()
            );
            Ok(0)
        }
        _ => {
            eprintln!(
                "[!] the memory tool failed (exit {:?}); see {}",
                output.status.code(),
                record_path.display()
            );
            Ok(4)
        }
    }
}
