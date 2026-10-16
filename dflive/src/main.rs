//! dflive: companion for running suspect systems. This first part is `send`:
//! stream a disk, a volume, a file or stdin to `dfnet stream` on dfnix over
//! an authenticated, encrypted dfstream/1 connection.

mod keys;
mod mem;
mod source;
#[cfg(target_os = "linux")]
mod state;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dfstream::{Hello, Role, Start, BYE, HELLO};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{BufRead, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "dflive",
    version,
    about = "Companion for running systems: authenticated streams to dfnix"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Stream a disk, volume, file or stdin (`-`) to `dfnet stream` on dfnix
    Send {
        /// What to send: a device (/dev/sda, \\.\PhysicalDrive0), a file or `-`
        source: String,
        /// The receiver, as dfnet shows it: ADDRESS:PORT
        #[arg(long)]
        to: String,
        /// The pairing code dfnet shows (asked on the terminal if not given)
        #[arg(long)]
        code: Option<String>,
        /// Name for the receiver's file (default: from the source)
        #[arg(long)]
        name: Option<String>,
        /// disk, volume, memory or file (default: from the source)
        #[arg(long)]
        kind: Option<String>,
        /// Append a JSON record of this run to this file (e.g. on the kit's output partition)
        #[arg(long)]
        log: Option<String>,
        /// Network timeout in seconds
        #[arg(long, default_value = "120")]
        timeout: u64,
        /// End the stream at the first read error instead of replacing
        /// unreadable sectors by zeros (disks and volumes)
        #[arg(long)]
        stop_on_error: bool,
    },
    /// Capture encryption state and key material (LUKS headers and dm-crypt
    /// keys, BitLocker protectors, FileVault/APFS state) while volumes are unlocked
    Keys {
        /// New output file, e.g. on the kit's output partition (`.age` when encrypted)
        #[arg(long, short = 'o')]
        out: String,
        /// Encrypt to this age public key of the examiner (repeatable)
        #[arg(long = "recipient", required_unless_present = "plaintext")]
        recipients: Vec<String>,
        /// Write the key material unencrypted (only when no examiner key is at hand)
        #[arg(long, conflicts_with = "recipients")]
        plaintext: bool,
    },
    /// Dump physical memory with the kit's tool (AVML on Linux, WinPmem on
    /// Windows) and record the capture window, the tool's hash and the dump's SHA-256
    Mem {
        /// New dump file on a target drive (memory is as large as the RAM)
        #[arg(long, short = 'o')]
        out: String,
        /// The memory tool (default: the kit's, next to dflive, then PATH)
        #[arg(long)]
        tool: Option<String>,
        /// Compress the dump (AVML's snappy format; Volatility 3 reads it)
        #[arg(long)]
        compress: bool,
    },
    /// Record the volatile state with dflive's own code (Linux so far): processes
    /// with executable hashes, sockets with their processes, interfaces, routes,
    /// ARP, users, mounts, modules
    State {
        /// Write the JSON here (a new file, e.g. on the kit's output partition);
        /// default: stdout
        #[arg(long, short = 'o')]
        out: Option<String>,
        /// Do not hash the executables of running processes
        #[arg(long)]
        no_hash: bool,
    },
}

/// RFC 3339 UTC of a Unix time with milliseconds.
pub(crate) fn rfc3339(secs: i64, millis: u32) -> String {
    let (days, tod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        tod / 3600,
        tod % 3600 / 60,
        tod % 60
    )
}

/// The system clock, RFC 3339 UTC with milliseconds.
pub(crate) fn now_rfc3339() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    rfc3339(d.as_secs() as i64, d.subsec_millis())
}

pub(crate) fn host_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default()
}

/// What the source is, as far as the OS tells.
struct SourceInfo {
    kind: &'static str,
    size: Option<u64>,
    /// Logical sector size: the unit of the zero-fill retry (4096 on 4Kn disks)
    sector: usize,
    identity: Value,
}

#[cfg(target_os = "linux")]
fn describe(path: &str, file: &File) -> Result<SourceInfo> {
    use std::os::unix::{fs::FileTypeExt, io::AsRawFd};
    let md = file.metadata()?;
    if !md.file_type().is_block_device() {
        return Ok(SourceInfo {
            kind: "file",
            size: md.is_file().then_some(md.len()),
            sector: 512,
            identity: json!({ "path": path }),
        });
    }
    const BLKGETSIZE64: u64 = 0x8008_1272;
    let mut size: u64 = 0;
    // The request type differs between glibc (c_ulong) and musl (c_int); the
    // bit pattern is what counts.
    // SAFETY: BLKGETSIZE64 writes one u64 into `size`
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), BLKGETSIZE64 as _, &mut size) };
    let name = std::fs::canonicalize(path)?
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let sys = Path::new("/sys/class/block").join(&name);
    let read = |p: &str| {
        std::fs::read_to_string(sys.join(p))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    const BLKSSZGET: u64 = 0x1268;
    let mut sector: libc::c_int = 0;
    // SAFETY: BLKSSZGET writes one int into `sector`
    let sector_ok = unsafe { libc::ioctl(file.as_raw_fd(), BLKSSZGET as _, &mut sector) } == 0;
    let partition = sys.join("partition").exists();
    let disk_dir = if partition { "../device" } else { "device" };
    Ok(SourceInfo {
        kind: if partition { "volume" } else { "disk" },
        size: (rc == 0).then_some(size),
        sector: if sector_ok && sector >= 512 {
            sector as usize
        } else {
            512
        },
        identity: json!({
            "path": path,
            "kernel_name": name,
            "model": read(&format!("{disk_dir}/model")),
            "serial": read(&format!("{disk_dir}/serial")),
        }),
    })
}

/// `\\.\PhysicalDriveN` is a disk, `\\.\C:` a volume; their size comes from
/// IOCTL_DISK_GET_LENGTH_INFO (file metadata does not apply to them).
#[cfg(windows)]
fn describe(path: &str, file: &File) -> Result<SourceInfo> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::{
        Ioctl::{
            DISK_GEOMETRY, GET_LENGTH_INFORMATION, IOCTL_DISK_GET_DRIVE_GEOMETRY,
            IOCTL_DISK_GET_LENGTH_INFO,
        },
        IO::DeviceIoControl,
    };
    if !path.starts_with(r"\\.\") {
        let md = file.metadata()?;
        return Ok(SourceInfo {
            kind: "file",
            size: md.is_file().then_some(md.len()),
            sector: 512,
            identity: json!({ "path": path }),
        });
    }
    let mut info = GET_LENGTH_INFORMATION { Length: 0 };
    let mut returned = 0u32;
    // SAFETY: the output buffer is one GET_LENGTH_INFORMATION; no overlapped I/O
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as _,
            IOCTL_DISK_GET_LENGTH_INFO,
            std::ptr::null(),
            0,
            (&mut info as *mut GET_LENGTH_INFORMATION).cast(),
            std::mem::size_of::<GET_LENGTH_INFORMATION>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    // SAFETY: all-zero is a valid DISK_GEOMETRY (integers and an enum value 0)
    let mut geometry: DISK_GEOMETRY = unsafe { std::mem::zeroed() };
    // SAFETY: the output buffer is one DISK_GEOMETRY; no overlapped I/O
    let geo_ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as _,
            IOCTL_DISK_GET_DRIVE_GEOMETRY,
            std::ptr::null(),
            0,
            (&mut geometry as *mut DISK_GEOMETRY).cast(),
            std::mem::size_of::<DISK_GEOMETRY>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let sector = geometry.BytesPerSector as usize;
    Ok(SourceInfo {
        kind: if path.to_ascii_lowercase().contains("physicaldrive") {
            "disk"
        } else {
            "volume"
        },
        size: (ok != 0 && info.Length > 0).then_some(info.Length as u64),
        sector: if geo_ok != 0 && sector >= 512 {
            sector
        } else {
            512
        },
        identity: json!({ "path": path }),
    })
}

#[cfg(not(any(target_os = "linux", windows)))]
fn describe(path: &str, file: &File) -> Result<SourceInfo> {
    let md = file.metadata()?;
    Ok(SourceInfo {
        kind: if md.is_file() { "file" } else { "disk" },
        size: md.is_file().then_some(md.len()),
        sector: 512,
        identity: json!({ "path": path }),
    })
}

fn ask_code() -> Result<String> {
    eprint!("Pairing code shown by dfnet: ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

struct SendArgs {
    source: String,
    to: String,
    code: Option<String>,
    name: Option<String>,
    kind: Option<String>,
    log: Option<String>,
    timeout: u64,
    stop_on_error: bool,
}

fn send(a: SendArgs) -> Result<u8> {
    let code = dfstream::normalize_code(&match a.code {
        Some(c) => c,
        None => ask_code()?,
    })?;
    // Disks and volumes of known size are read so that an unreadable sector
    // is replaced by zeros and listed, keeping every later offset
    let mut zero_filled = None;
    let (mut reader, info): (Box<dyn Read>, SourceInfo) = if a.source == "-" {
        (
            Box::new(std::io::stdin()),
            SourceInfo {
                kind: "file",
                size: None,
                sector: 512,
                identity: json!({ "path": "stdin" }),
            },
        )
    } else {
        let file = File::open(&a.source).with_context(|| format!("Cannot open {}", a.source))?;
        let info = describe(&a.source, &file)?;
        match (info.kind, info.size) {
            ("disk" | "volume", Some(size)) if !a.stop_on_error => {
                let r = source::ZeroFill::new(file, size, info.sector);
                zero_filled = Some(r.errors());
                (Box::new(r), info)
            }
            _ => (Box::new(file), info),
        }
    };
    let addr =
        a.to.to_socket_addrs()
            .with_context(|| format!("Cannot resolve {}", a.to))?
            .next()
            .context("no address")?;
    let timeout = Duration::from_secs(a.timeout);
    let tcp = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("Cannot connect to {}", a.to))?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    let started = now_rfc3339();
    let mut ch = dfstream::handshake(tcp, &code, Role::Sender)?;
    eprintln!(
        "[✓] Paired with {} (session {})",
        a.to,
        &ch.session_id[..16]
    );
    ch.send_json(
        HELLO,
        &Hello {
            tool: "dflive".into(),
            version: VERSION.into(),
            host: host_name(),
            os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            clock: now_rfc3339(),
        },
    )?;
    let default_name = Path::new(&a.source)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "stream".into());
    let start = Start {
        id: 1,
        kind: a.kind.unwrap_or_else(|| info.kind.to_string()),
        name: a.name.unwrap_or(default_name),
        source: info.identity,
        size: info.size,
    };
    let (end, outcome) = dfstream::send_stream(&mut ch, &start, &mut reader, || {
        zero_filled.map(|e| e.borrow().clone()).unwrap_or_default()
    })?;
    if !end.read_errors.is_empty() {
        eprintln!(
            "[!] {} unreadable area(s) replaced by zeros",
            end.read_errors.len()
        );
    }
    ch.send(BYE, &[])?;
    ch.flush()?;
    eprintln!(
        "[{}] {} bytes, SHA-256 {}; receiver: {} ({} bytes)",
        if outcome.status == "complete" {
            "✓"
        } else {
            "!"
        },
        end.bytes,
        end.sha256,
        outcome.status,
        outcome.bytes
    );
    if let Some(log) = a.log {
        let record = json!({
            "tool": "dflive",
            "version": VERSION,
            "action": "send",
            "started": started,
            "finished": now_rfc3339(),
            "receiver": a.to,
            "session": ch.session_id,
            "stream": start,
            "end": end,
            "outcome": outcome,
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)?;
        writeln!(f, "{record}")?;
    }
    Ok(match outcome.status.as_str() {
        "complete" => 0,
        "mismatch" => 5,
        _ => 6,
    })
}

/// Write a new file (never overwrite), sync it and report its SHA-256.
fn write_new(path: &str, data: &[u8]) -> Result<()> {
    use sha2::Digest;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("Cannot create {path} (existing files are not overwritten)"))?;
    f.write_all(data)?;
    f.sync_all()?;
    let digest: String = sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    eprintln!("[✓] {path}: {} bytes, SHA-256 {digest}", data.len());
    Ok(())
}

fn keys_cmd(out: &str, recipients: &[String]) -> Result<u8> {
    let doc = serde_json::to_vec_pretty(&keys::collect())?;
    // Parse the recipients before anything is written
    let sealed = keys::seal(&doc, recipients)?;
    if recipients.is_empty() {
        eprintln!("[!] --plaintext: the key material is written UNENCRYPTED; treat {out} as sealed evidence");
    }
    write_new(out, &sealed)?;
    Ok(0)
}

#[cfg(target_os = "linux")]
fn state_cmd(out: Option<String>, hash: bool) -> Result<u8> {
    let doc = serde_json::to_vec_pretty(&state::collect(hash))?;
    match out {
        Some(path) => write_new(&path, &doc)?,
        None => std::io::stdout().write_all(&doc)?,
    }
    Ok(0)
}

#[cfg(not(target_os = "linux"))]
fn state_cmd(_out: Option<String>, _hash: bool) -> Result<u8> {
    anyhow::bail!(
        "dflive state is not available on this OS yet; use the checklist's built-in commands"
    )
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Send {
            source,
            to,
            code,
            name,
            kind,
            log,
            timeout,
            stop_on_error,
        } => send(SendArgs {
            source,
            to,
            code,
            name,
            kind,
            log,
            timeout,
            stop_on_error,
        }),
        Command::State { out, no_hash } => state_cmd(out, !no_hash),
        Command::Keys {
            out, recipients, ..
        } => keys_cmd(&out, &recipients),
        Command::Mem {
            out,
            tool,
            compress,
        } => mem::run(&out, tool.as_deref(), compress),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::from(4)
        }
    }
}
