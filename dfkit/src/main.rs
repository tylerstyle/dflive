//! `dfkit`: write and verify multi-partition forensic field-kit USB sticks on `dfnix`.
//!
//! - `dfkit write IMAGE_DIR DEVICE... [--confirm NAME...]`:
//!   Verifies whole-disk safety guards (refuses system/protected disks, mounted disks,
//!   4Kn disks, or write-blocked disks where `blockdev --getro != 0`), prompts for typed
//!   kernel-name confirmation, re-verifies stick identity right before opening with
//!   `O_EXCL`, writes `fieldkit.img`, moves the backup GPT header to the end of the stick
//!   (`sgdisk -e`), grows partition 4 (`KIT-OUT`) to fill the stick, probes `KIT-OUT` with
//!   `O_DIRECT` to catch counterfeit-capacity sticks, formats `KIT-OUT` as exFAT with the
//!   fixed volume GUID, recreates `.metadata_never_index` and `.fseventsd/no_log`, writes
//!   `KIT-ID.json`, reads back partitions 1–3 with `O_DIRECT` to verify their SHA-256
//!   digests against `fieldkit.img`, and records a `fieldkit_write` audit entry.
//! - `dfkit verify DEVICE [IMAGE_DIR]`:
//!   Mounts partitions 1–3 read-only (`ntfs3`/`ntfs-3g ro`, `hfsplus ro`, `ext4 ro,noload`),
//!   verifies every tool file and symlink against `manifest.json`, separates allowlisted
//!   OS-added noise (`System Volume Information/**`, `.Spotlight-V100/**`, `.fseventsd/**`, …)
//!   from changed/missing tool files and planted unexpected files (`[UNEXPECTED]`), inspects
//!   `KIT-OUT` read-only and suggests `dfcollect files`, records `fieldkit_verify` in the
//!   audit log, and exits `0` (all tool files intact and no unexpected files) or `5`
//!   (tool file changed/missing or unexpected file present).

mod gpt;
mod manifest;

use anyhow::{bail, ensure, Context, Result};
use clap::{Parser, Subcommand};
use dfcore::{
    audit::{Event, Outcome},
    lsblk::{DeviceIdentity, FlatDevice},
    Refusal,
};
use gpt::{partition_dev_path, read_gpt, validate_fieldkit_gpt, GptTable, SECTOR_SIZE};
use manifest::{
    compare_partition, scan_mounted_tree, sha256_file, ChangedEntry, FieldkitManifest,
    MissingEntry, ObservedEntry, OsAddedEntry, UnexpectedEntry,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, IsTerminal, Read, Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    ptr,
    sync::atomic::{AtomicU64, Ordering},
};

const TOOL: &str = "dfkit";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const KIT_OUT_EXFAT_GUID: &str = "44464e49-5800-4b49-5400-000000000004";
const DIRECT_ALIGN: usize = 4096;

#[derive(Parser, Debug)]
#[command(
    name = "dfkit",
    version,
    about = "Write and verify dfnix forensic field-kit USB sticks"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Write the field-kit image to one or more unblocked USB sticks, grow KIT-OUT, and verify partitions 1–3
    Write {
        /// Path to the `nix build .#fieldkit` output directory (containing fieldkit.img and manifest.json)
        image_dir: PathBuf,
        /// Target whole-disk device node(s), e.g. /dev/sdX (must be unblocked first with `dfmount unblock`)
        #[arg(required = true)]
        devices: Vec<String>,
        /// Confirm writing by kernel device name (e.g. --confirm sdb); repeatable or comma-separated
        #[arg(long = "confirm", value_delimiter = ',')]
        confirm: Vec<String>,
        /// Skip zeroing KIT-OUT before mkfs.exfat (only safe on brand-new sticks; records kit_out_zeroed=false)
        #[arg(long = "no-wipe")]
        no_wipe: bool,
    },
    /// Verify a field-kit stick after deployment against manifest.json and report KIT-OUT contents
    Verify {
        /// Whole-disk device node of the field-kit stick (e.g. /dev/sdX)
        device: String,
        /// Path to the `nix build .#fieldkit` directory (defaults to $DFNIX_FIELDKIT_DIR or /etc/dfnix/fieldkit)
        image_dir: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PartitionRangeHash {
    number: u32,
    label: String,
    offset_bytes: u64,
    size_bytes: u64,
    expected_sha256: String,
    actual_sha256: String,
    matches: bool,
}

#[derive(Debug)]
struct ValidatedStick {
    requested: String,
    dev_path: String,
    kernel_name: String,
    identity: DeviceIdentity,
    disk_bytes: u64,
}

/// 4096-byte aligned buffer for `O_DIRECT` device reads and counterfeit-capacity probes.
struct AlignedBuf {
    ptr: *mut u8,
    len: usize,
}

impl AlignedBuf {
    fn new(len: usize) -> Result<Self> {
        assert!(
            len > 0 && len.is_multiple_of(DIRECT_ALIGN),
            "AlignedBuf length must be a non-zero multiple of {DIRECT_ALIGN}"
        );
        let mut raw: *mut libc::c_void = ptr::null_mut();
        // SAFETY: posix_memalign allocates `len` bytes aligned to `DIRECT_ALIGN` (power of two >= sizeof(void*))
        let rc = unsafe { libc::posix_memalign(&mut raw, DIRECT_ALIGN, len) };
        ensure!(
            rc == 0 && !raw.is_null(),
            "posix_memalign({len}) failed: rc={rc}"
        );
        // SAFETY: `raw` is valid for `len` bytes
        unsafe {
            ptr::write_bytes(raw.cast::<u8>(), 0, len);
        }
        Ok(Self {
            ptr: raw.cast::<u8>(),
            len,
        })
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: `self.ptr` is valid and initialized for `self.len` bytes
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `self.ptr` is uniquely owned, valid, and initialized for `self.len` bytes
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: allocated by `libc::posix_memalign`
            unsafe {
                libc::free(self.ptr.cast());
            }
        }
    }
}

struct TempMount {
    mountpoint: PathBuf,
    mounted: bool,
}

impl TempMount {
    fn new(tag: &str) -> Result<Self> {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("dfkit-{tag}-{}-{n}", std::process::id()));
        fs::create_dir_all(&dir)
            .with_context(|| format!("Cannot create temporary mountpoint {}", dir.display()))?;
        Ok(Self {
            mountpoint: dir,
            mounted: false,
        })
    }

    fn path(&self) -> &Path {
        &self.mountpoint
    }

    fn unmount(&mut self) -> Result<()> {
        if self.mounted {
            let status = Command::new("umount")
                .arg(&self.mountpoint)
                .status()
                .with_context(|| format!("Failed to run umount {}", self.mountpoint.display()))?;
            ensure!(
                status.success(),
                "umount {} failed with status {status}",
                self.mountpoint.display()
            );
            self.mounted = false;
        }
        let _ = fs::remove_dir(&self.mountpoint);
        Ok(())
    }
}

impl Drop for TempMount {
    fn drop(&mut self) {
        if self.mounted {
            let _ = Command::new("umount").arg(&self.mountpoint).status();
            self.mounted = false;
        }
        let _ = fs::remove_dir(&self.mountpoint);
    }
}

fn run_cmd(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute {program} {}", args.join(" ")))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        bail!("{program} {} failed: {detail}", args.join(" "));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn blockdev_getro(dev: &str) -> Result<bool> {
    let out = run_cmd("blockdev", &["--getro", dev])?;
    match out.as_str() {
        "1" => Ok(true),
        "0" => Ok(false),
        other => bail!("blockdev --getro {dev} returned unexpected value '{other}'"),
    }
}

fn blockdev_getsize64(dev: &str) -> Result<u64> {
    let out = run_cmd("blockdev", &["--getsize64", dev])?;
    out.parse::<u64>()
        .with_context(|| format!("Invalid byte size '{out}' from blockdev --getsize64 {dev}"))
}

fn blockdev_getss(dev: &str) -> Result<u64> {
    let out = run_cmd("blockdev", &["--getss", dev])?;
    out.parse::<u64>()
        .with_context(|| format!("Invalid logical sector size '{out}' from blockdev --getss {dev}"))
}

fn sha256_range(path: &Path, offset: u64, length: u64, direct: bool) -> Result<String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    if direct {
        opts.custom_flags(libc::O_DIRECT);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("Cannot open {} for hashing", path.display()))?;
    f.seek(SeekFrom::Start(offset))
        .with_context(|| format!("Cannot seek to {offset} in {}", path.display()))?;
    let mut h = Sha256::new();
    let mut remaining = length;
    let mut buf = AlignedBuf::new(4 << 20)?;
    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len);
        let n = f.read(&mut buf.as_mut_slice()[..to_read])?;
        if n == 0 {
            bail!(
                "Unexpected EOF reading {} at offset {} ({} bytes remaining)",
                path.display(),
                offset + (length - remaining),
                remaining
            );
        }
        h.update(&buf.as_slice()[..n]);
        remaining -= n as u64;
    }
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Fill a 1 MiB buffer deterministically from `(probe_index, byte_offset, total_bytes)`
/// so that wrap-around aliasing or dropped writes on counterfeit sticks fail verification.
fn fill_probe_block(buf: &mut [u8], probe_idx: usize, offset: u64, total_bytes: u64) {
    let mut state = 0x4446_4E49_584B_4954u64
        ^ ((probe_idx as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15))
        ^ offset.rotate_left(17)
        ^ total_bytes.rotate_right(11);
    if state == 0 {
        state = 0xA5A5_5A5A_F0F0_0F0F;
    }
    let (chunks, _) = buf.as_chunks_mut::<8>();
    for chunk in chunks {
        // xorshift64*
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let word = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        *chunk = word.to_le_bytes();
    }
}

/// Write up to 16 distinct 1 MiB blocks spread across `KIT-OUT` (including the last
/// 4096-aligned 1 MiB block at the end of the partition), flush, and read all 16 back
/// with `O_DIRECT` to detect counterfeit-capacity / wrap-around sticks before formatting.
fn probe_kit_out_capacity(part4_dev: &str, kit_out_bytes: u64) -> Result<usize> {
    const BLOCK_SIZE: u64 = 1 << 20;
    const NUM_PROBES: usize = 16;
    let aligned_end = (kit_out_bytes / DIRECT_ALIGN as u64) * DIRECT_ALIGN as u64;
    if aligned_end < BLOCK_SIZE {
        return Ok(0);
    }
    let last_offset = aligned_end - BLOCK_SIZE;
    let mut offsets = Vec::with_capacity(NUM_PROBES);
    for i in 0..NUM_PROBES {
        let raw = if i + 1 == NUM_PROBES {
            last_offset
        } else {
            (last_offset * i as u64) / (NUM_PROBES as u64 - 1)
        };
        let aligned = (raw / DIRECT_ALIGN as u64) * DIRECT_ALIGN as u64;
        if offsets.last().copied() != Some(aligned) {
            offsets.push(aligned);
        }
    }

    let mut buf = AlignedBuf::new(BLOCK_SIZE as usize)?;
    {
        let mut f = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_DIRECT)
            .open(part4_dev)
            .with_context(|| format!("Cannot open {part4_dev} with O_DIRECT for capacity probe"))?;
        for (idx, &off) in offsets.iter().enumerate() {
            fill_probe_block(buf.as_mut_slice(), idx, off, kit_out_bytes);
            f.seek(SeekFrom::Start(off))?;
            f.write_all(buf.as_slice())?;
        }
        f.sync_all()?;
    }
    run_cmd("blockdev", &["--flushbufs", part4_dev])?;

    {
        let mut expected = vec![0u8; BLOCK_SIZE as usize];
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECT)
            .open(part4_dev)
            .with_context(|| {
                format!("Cannot open {part4_dev} with O_DIRECT for capacity verify")
            })?;
        for (idx, &off) in offsets.iter().enumerate() {
            fill_probe_block(&mut expected, idx, off, kit_out_bytes);
            f.seek(SeekFrom::Start(off))?;
            f.read_exact(buf.as_mut_slice())?;
            ensure!(
                buf.as_slice() == expected.as_slice(),
                "Counterfeit or defective stick detected on {part4_dev}: 1 MiB capacity probe #{idx} at offset {off} failed read-back verification"
            );
        }
    }
    Ok(offsets.len())
}

fn resolve_image_dir(dir_or_file: &Path) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let base = if dir_or_file.is_file() {
        dir_or_file
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        dir_or_file.to_path_buf()
    };
    let img_path = if dir_or_file.is_file() {
        dir_or_file.to_path_buf()
    } else {
        base.join("fieldkit.img")
    };
    let manifest_path = base.join("manifest.json");
    ensure!(
        img_path.is_file(),
        "Field-kit image not found at {}",
        img_path.display()
    );
    ensure!(
        manifest_path.is_file(),
        "Field-kit manifest not found at {}",
        manifest_path.display()
    );
    Ok((base, img_path, manifest_path))
}

fn resolve_default_image_dir(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Some(env_dir) = std::env::var_os("DFNIX_FIELDKIT_DIR") {
        return Ok(PathBuf::from(env_dir));
    }
    let etc = PathBuf::from("/etc/dfnix/fieldkit");
    if etc.exists() {
        return Ok(etc);
    }
    bail!(
        "No IMAGE_DIR specified and neither $DFNIX_FIELDKIT_DIR nor /etc/dfnix/fieldkit exists; pass IMAGE_DIR"
    )
}

fn append_audit(
    action: &str,
    identity: Option<DeviceIdentity>,
    details: Map<String, Value>,
    outcome: Outcome,
    message: Option<String>,
) {
    let mut ev = Event::new(TOOL, VERSION, action).outcome(outcome, message);
    ev.details = details;
    if let Some(id) = identity {
        ev = ev.device(id);
    }
    if let Err(e) = dfcore::audit::append(ev) {
        eprintln!("[!] Warning: could not append audit record: {e:#}");
    }
}

/// Validate a target device before writing. Refuses:
/// - unknown devices or devices protected by `/run/dfnix/protected.json`
/// - partitions or non-`disk` devices (whole disk only)
/// - system disks or disks with any system descendant
/// - disks with any mounted partition or holder
/// - write-blocked disks (`blockdev --getro != 0`)
/// - 4Kn disks (`blockdev --getss != 512`)
/// - disks smaller than `fieldkit.img`
/// - unconfirmed kernel names
fn validate_stick_for_write(
    flat: &[FlatDevice],
    requested: &str,
    image_size: u64,
    confirm_list: &[String],
) -> Result<ValidatedStick> {
    let canon = fs::canonicalize(requested)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| requested.to_string());
    let dev_num = dfcore::sysfs::dev_num_of_path(Path::new(&canon));

    // 1. Fail-closed lsblk membership & boot-time protected registry check
    dfcore::protected::check(flat, &canon)?;

    let hits = dfcore::lsblk::lookup(flat, &canon, dev_num);
    if hits.is_empty() {
        return Err(Refusal(format!(
            "ABORT: {requested} is not a block device reported by lsblk"
        ))
        .into());
    }

    // 2. Whole disk only (level == 0 and type == "disk")
    let entry = hits[0];
    if entry.level != 0 || !entry.device.is_type("disk") {
        let dev_type = entry.device.dev_type.as_deref().unwrap_or("unknown");
        return Err(Refusal(format!(
            "ABORT: {} is not a whole disk (type: {dev_type}, level: {}); specify a whole disk such as /dev/sdX",
            entry.device.dev_path(),
            entry.level
        ))
        .into());
    }

    let dev_path = entry.device.dev_path();
    let kernel_name = entry.device.name.clone();
    let identity = entry.device.identity();

    // 3. System device check (live lsblk tree + descendants)
    if entry.is_system {
        let reasons = dfcore::lsblk::system_reasons(&entry.device);
        let detail = if reasons.is_empty() {
            "marked as system device".to_string()
        } else {
            reasons.join("; ")
        };
        return Err(Refusal(format!(
            "ABORT: {dev_path} belongs to the running system ({detail})"
        ))
        .into());
    }

    // 4. Refuse anything mounted on the disk or any descendant
    for d in std::iter::once(entry).chain(dfcore::lsblk::descendants(flat, &dev_path)) {
        if let Some(m) = d.device.mounts().next() {
            return Err(Refusal(format!(
                "ABORT: {} is mounted at {m}; unmount all partitions before writing a field-kit stick",
                d.device.dev_path()
            ))
            .into());
        }
    }

    // 5. Must already be unblocked (blockdev --getro == 0)
    if blockdev_getro(&dev_path)? {
        return Err(Refusal(format!(
            "ABORT: {dev_path} is write-blocked (blockdev --getro is 1); unblock it first with: dfmount unblock {dev_path}"
        ))
        .into());
    }

    // 6. Logical sector size must be 512 bytes (fieldkit.img GPT is built for 512B LBAs)
    let sector_size = blockdev_getss(&dev_path)?;
    if sector_size != SECTOR_SIZE {
        return Err(Refusal(format!(
            "ABORT: {dev_path} has logical sector size {sector_size} bytes; fieldkit.img requires {SECTOR_SIZE}-byte logical sectors"
        ))
        .into());
    }

    // 7. Big enough for the image
    let disk_bytes = blockdev_getsize64(&dev_path)?;
    if disk_bytes < image_size {
        return Err(Refusal(format!(
            "ABORT: {dev_path} is too small ({disk_bytes} bytes < fieldkit.img {image_size} bytes)"
        ))
        .into());
    }

    // 8. Typed confirmation of the kernel name
    let confirmed_by_flag = confirm_list.iter().any(|c| {
        let c = c.trim();
        c == kernel_name || c.strip_prefix("/dev/") == Some(kernel_name.as_str())
    });
    if !confirmed_by_flag {
        if !confirm_list.is_empty() {
            return Err(Refusal(format!(
                "Confirmation {:?} did not match '{kernel_name}'; nothing was written",
                confirm_list
            ))
            .into());
        }
        if !io::stdin().is_terminal() {
            return Err(Refusal(format!(
                "stdin is not a terminal; pass --confirm {kernel_name} to confirm writing {dev_path}"
            ))
            .into());
        }
        eprintln!(
            "[!] Will overwrite WHOLE DISK {dev_path} ({}, {} bytes) with field-kit image",
            identity.model.as_deref().unwrap_or("unknown model"),
            disk_bytes
        );
        eprint!("[?] Type '{kernel_name}' to confirm: ");
        io::stderr().flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        if line.trim() != kernel_name {
            return Err(Refusal(format!(
                "Confirmation '{}' did not match '{kernel_name}'; nothing was written",
                line.trim()
            ))
            .into());
        }
    }

    Ok(ValidatedStick {
        requested: requested.to_string(),
        dev_path,
        kernel_name,
        identity,
        disk_bytes,
    })
}

/// Re-check the target stick right before opening it for writing, ensuring a
/// stick was not swapped or mounted while `fieldkit.img` was hashed or while an
/// earlier stick was written.
fn reverify_stick_before_open(stick: &ValidatedStick) -> Result<()> {
    let flat = dfcore::lsblk::scan()?;
    let dev = &stick.dev_path;
    dfcore::protected::check(&flat, dev)?;

    let dev_num = dfcore::sysfs::dev_num_of_path(Path::new(dev));
    let hits = dfcore::lsblk::lookup(&flat, dev, dev_num);
    let Some(entry) = hits.first().copied() else {
        return Err(Refusal(format!("ABORT: {dev} disappeared before write")).into());
    };
    if entry.level != 0 || !entry.device.is_type("disk") || entry.is_system {
        return Err(Refusal(format!(
            "ABORT: {dev} changed topology or system status before write"
        ))
        .into());
    }
    for d in std::iter::once(entry).chain(dfcore::lsblk::descendants(&flat, dev)) {
        if let Some(m) = d.device.mounts().next() {
            return Err(Refusal(format!(
                "ABORT: {} became mounted at {m} before write",
                d.device.dev_path()
            ))
            .into());
        }
    }
    let live_id = entry.device.identity();
    if live_id.serial != stick.identity.serial || live_id.model != stick.identity.model {
        return Err(Refusal(format!(
            "ABORT: {dev} identity changed since confirmation (expected serial={:?} model={:?}, found serial={:?} model={:?})",
            stick.identity.serial,
            stick.identity.model,
            live_id.serial,
            live_id.model
        ))
        .into());
    }
    let live_bytes = blockdev_getsize64(dev)?;
    if live_bytes != stick.disk_bytes {
        return Err(Refusal(format!(
            "ABORT: {dev} size changed since confirmation (expected {} bytes, found {live_bytes} bytes)",
            stick.disk_bytes
        ))
        .into());
    }
    Ok(())
}

fn write_one_stick(
    stick: &ValidatedStick,
    img_path: &Path,
    manifest: &FieldkitManifest,
    gpt: &GptTable,
    expected_part_hashes: &[(u32, String, u64, u64, String)],
    wipe: bool,
) -> Result<(Vec<PartitionRangeHash>, u64)> {
    let dev = &stick.dev_path;
    reverify_stick_before_open(stick)?;

    eprintln!(
        "[*] Writing {} ({} bytes) -> {dev}...",
        img_path.display(),
        manifest.image.size
    );

    // 1. Copy fieldkit.img to the whole disk (opened O_EXCL) and sync
    {
        let mut src = File::open(img_path)?;
        let mut dst = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_EXCL)
            .open(dev)
            .with_context(|| format!("Cannot open {dev} exclusively (O_EXCL) for writing"))?;
        let mut buf = vec![0u8; 4 << 20];
        let mut written = 0u64;
        loop {
            let n = src.read(&mut buf)?;
            if n == 0 {
                break;
            }
            dst.write_all(&buf[..n])?;
            written += n as u64;
        }
        ensure!(
            written == manifest.image.size,
            "Wrote {written} bytes to {dev}, expected {}",
            manifest.image.size
        );
        dst.sync_all()
            .with_context(|| format!("Failed to sync {dev}"))?;
    }
    run_cmd("blockdev", &["--flushbufs", dev])?;

    // 2. Move GPT backup header to the end of the disk and grow partition 4 (KIT-OUT)
    let p4 = gpt
        .partition(4)
        .context("GPT missing partition 4 (KIT-OUT)")?;
    let p4_spec = manifest
        .partition(4)
        .context("Manifest missing partition 4 (KIT-OUT)")?;
    let new_p4_arg = format!("4:{}:0", p4.first_lba);
    let type_p4_arg = format!("4:{}", p4_spec.gpt_type_code);
    let name_p4_arg = format!("4:{}", p4.name);
    let guid_p4_arg = format!("4:{}", p4.part_guid);

    eprintln!(
        "[*] Moving GPT backup header to end of {dev} and growing partition 4 ({}) from LBA {}...",
        p4.name, p4.first_lba
    );
    run_cmd("sgdisk", &["-e", dev])?;
    run_cmd(
        "sgdisk",
        &[
            "-d",
            "4",
            "-n",
            &new_p4_arg,
            "-t",
            &type_p4_arg,
            "-c",
            &name_p4_arg,
            "-u",
            &guid_p4_arg,
            dev,
        ],
    )?;

    // Inform kernel of updated partition table and wait for udev
    if run_cmd("partx", &["-u", dev]).is_err() {
        let _ = run_cmd("blockdev", &["--rereadpt", dev]);
    }
    let _ = Command::new("udevadm")
        .args(["settle", "--timeout=10"])
        .status();

    let part1_dev = partition_dev_path(dev, 1);
    let part2_dev = partition_dev_path(dev, 2);
    let part3_dev = partition_dev_path(dev, 3);
    let part4_dev = partition_dev_path(dev, 4);

    // Wait briefly if udev is still creating the partition node
    for _ in 0..20 {
        if Path::new(&part4_dev).exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    ensure!(
        Path::new(&part4_dev).exists(),
        "Partition node {part4_dev} did not appear after partx -u {dev}"
    );

    // On dfnix, udev write-blocking rules may mark newly created partition nodes
    // read-only on add uevents; ensure disk + part4 are rw for probing/mkfs.exfat,
    // and lock partitions 1-3 read-only.
    run_cmd("blockdev", &["--setrw", dev])?;
    run_cmd("blockdev", &["--setrw", &part4_dev])?;
    for pdev in [&part1_dev, &part2_dev, &part3_dev] {
        if Path::new(pdev).exists() {
            let _ = run_cmd("blockdev", &["--setro", pdev]);
        }
    }

    let kit_out_bytes = blockdev_getsize64(&part4_dev)?;

    // 3. Probe KIT-OUT capacity with O_DIRECT across 16 positions up to the end of the stick
    let probes = probe_kit_out_capacity(&part4_dev, kit_out_bytes)?;
    if probes > 0 {
        eprintln!(
            "[*] Verified {part4_dev} capacity across {probes} O_DIRECT probe block(s) ({} MiB).",
            kit_out_bytes >> 20
        );
    }

    // 4. Zero KIT-OUT completely before mkfs.exfat so residual bytes from any previous
    //    case cannot remain in unallocated exFAT clusters (unless opted out with --no-wipe).
    if wipe {
        let mib = kit_out_bytes >> 20;
        let est_low_s = mib / 150;
        let est_high_s = (mib / 50).max(1);
        eprintln!(
            "[*] Zeroing {part4_dev} (KIT-OUT, {mib} MiB; est. {est_low_s}–{est_high_s}s at 50–150 MB/s)..."
        );
        run_cmd("blkdiscard", &["--zeroout", &part4_dev])?;
        run_cmd("blockdev", &["--flushbufs", &part4_dev])?;
        let _ = Command::new("udevadm")
            .args(["settle", "--timeout=10"])
            .status();
        run_cmd("blockdev", &["--setrw", &part4_dev])?;
    } else {
        eprintln!(
            "[!] --no-wipe: skipping KIT-OUT zeroing on {part4_dev} (only safe on brand-new sticks; recording kit_out_zeroed=false)."
        );
    }

    // 5. Recreate exFAT on partition 4 (KIT-OUT) with fixed volume GUID, markers, and KIT-ID.json
    eprintln!(
        "[*] Formatting {part4_dev} (KIT-OUT, {} MiB) as exFAT...",
        kit_out_bytes >> 20
    );
    run_cmd(
        "mkfs.exfat",
        &["-L", "KIT-OUT", "-U", KIT_OUT_EXFAT_GUID, &part4_dev],
    )?;

    // Settle & ensure rw again in case mkfs triggered a change uevent
    let _ = Command::new("udevadm")
        .args(["settle", "--timeout=10"])
        .status();
    run_cmd("blockdev", &["--setrw", &part4_dev])?;

    {
        let mut mnt = TempMount::new("kit-out-write")?;
        run_cmd(
            "mount",
            &["-t", "exfat", &part4_dev, &mnt.path().to_string_lossy()],
        )?;
        mnt.mounted = true;

        fs::write(mnt.path().join(".metadata_never_index"), b"")?;
        fs::create_dir_all(mnt.path().join(".fseventsd"))?;
        fs::write(mnt.path().join(".fseventsd/no_log"), b"")?;

        let kit_id = json!({
            "schema": "dfnix.fieldkit.id/v0",
            "kit_version": manifest.version,
            "image_sha256": manifest.image.sha256,
            "serial": stick.identity.serial,
            "model": stick.identity.model,
            "device": stick.identity,
            "dfnix_revision": dfcore::release::system_revision(),
            "written_at": dfcore::host::rfc3339_utc(dfcore::host::unix_now()),
            "kit_out_bytes": kit_out_bytes,
            "kit_out_zeroed": wipe,
        });
        let kit_id_path = mnt.path().join("KIT-ID.json");
        {
            let mut id_file = File::create(&kit_id_path)?;
            id_file.write_all(serde_json::to_string_pretty(&kit_id)?.as_bytes())?;
            id_file.write_all(b"\n")?;
            id_file.sync_all()?;
        }

        mnt.unmount()?;
    }

    // 6. Flush caches and read partitions 1-3 back from the stick with O_DIRECT
    run_cmd("blockdev", &["--flushbufs", dev])?;
    let mut part_results = Vec::new();
    for (num, label, offset, size, expected_sha) in expected_part_hashes {
        eprintln!(
            "[*] Verifying partition {num} ({label}, {} MiB) O_DIRECT read-back SHA-256...",
            size >> 20
        );
        let actual_sha = sha256_range(Path::new(dev), *offset, *size, true)?;
        let matches = actual_sha == *expected_sha;
        part_results.push(PartitionRangeHash {
            number: *num,
            label: label.clone(),
            offset_bytes: *offset,
            size_bytes: *size,
            expected_sha256: expected_sha.clone(),
            actual_sha256: actual_sha,
            matches,
        });
    }

    for pr in &part_results {
        ensure!(
            pr.matches,
            "Read-back verification failed on {dev} partition {} ({}): expected SHA-256 {}, got {}",
            pr.number,
            pr.label,
            pr.expected_sha256,
            pr.actual_sha256
        );
    }

    Ok((part_results, kit_out_bytes))
}

fn cmd_write(image_dir: &Path, devices: &[String], confirm: &[String], wipe: bool) -> Result<u8> {
    let (resolved_dir, img_path, manifest_path) = resolve_image_dir(image_dir)?;
    let manifest = FieldkitManifest::load(&manifest_path)?;

    let gpt = read_gpt(File::open(&img_path)?)?;
    validate_fieldkit_gpt(&gpt)?;

    // Validate ALL requested target sticks before hashing or writing the full image
    let flat = dfcore::lsblk::scan()?;
    let mut sticks = Vec::new();
    for dev in devices {
        match validate_stick_for_write(&flat, dev, manifest.image.size, confirm) {
            Ok(s) => sticks.push(s),
            Err(e) => {
                let canon = fs::canonicalize(dev)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| dev.clone());
                let dev_num = dfcore::sysfs::dev_num_of_path(Path::new(&canon));
                let id = dfcore::lsblk::lookup(&flat, &canon, dev_num)
                    .first()
                    .map(|f| f.device.identity());
                let mut details = Map::new();
                details.insert("requested".into(), dev.clone().into());
                details.insert(
                    "image_dir".into(),
                    resolved_dir.to_string_lossy().into_owned().into(),
                );
                details.insert("kit_version".into(), manifest.version.clone().into());
                details.insert("image_sha256".into(), manifest.image.sha256.clone().into());
                let outcome = if dfcore::is_refusal(&e) {
                    Outcome::Refused
                } else {
                    Outcome::Error
                };
                append_audit(
                    "fieldkit_write",
                    id,
                    details,
                    outcome,
                    Some(format!("{e:#}")),
                );
                return Err(e);
            }
        }
    }

    // Verify fieldkit.img size and SHA-256 against manifest.json before touching any device
    let (actual_img_size, actual_img_sha) = sha256_file(&img_path)?;
    ensure!(
        actual_img_size == manifest.image.size,
        "fieldkit.img size mismatch: expected {} bytes, got {actual_img_size} bytes",
        manifest.image.size
    );
    ensure!(
        actual_img_sha == manifest.image.sha256,
        "fieldkit.img SHA-256 mismatch: expected {}, got {actual_img_sha}",
        manifest.image.sha256
    );

    // Pre-compute byte-range SHA-256 for partitions 1..=3 in fieldkit.img
    let mut expected_part_hashes = Vec::new();
    for num in 1..=3u32 {
        let p = gpt
            .partition(num)
            .with_context(|| format!("Missing partition {num} in GPT"))?;
        let sha = sha256_range(&img_path, p.offset_bytes(), p.size_bytes(), false)?;
        expected_part_hashes.push((num, p.name.clone(), p.offset_bytes(), p.size_bytes(), sha));
    }

    for stick in &sticks {
        let mut details = Map::new();
        details.insert("requested".into(), stick.requested.clone().into());
        details.insert(
            "image_dir".into(),
            resolved_dir.to_string_lossy().into_owned().into(),
        );
        details.insert("kit_version".into(), manifest.version.clone().into());
        details.insert("image_sha256".into(), manifest.image.sha256.clone().into());
        details.insert("confirmed_as".into(), stick.kernel_name.clone().into());
        details.insert("disk_bytes".into(), stick.disk_bytes.into());
        details.insert("kit_out_zeroed".into(), wipe.into());

        match write_one_stick(
            stick,
            &img_path,
            &manifest,
            &gpt,
            &expected_part_hashes,
            wipe,
        ) {
            Ok((part_hashes, kit_out_bytes)) => {
                details.insert(
                    "partition_hashes".into(),
                    serde_json::to_value(&part_hashes)?,
                );
                details.insert("kit_out_bytes".into(), kit_out_bytes.into());
                append_audit(
                    "fieldkit_write",
                    Some(stick.identity.clone()),
                    details,
                    Outcome::Ok,
                    None,
                );
                println!(
                    "[✓] Field-kit stick {} (serial: {}, KIT-OUT: {} MiB) written and partitions 1–3 verified.",
                    stick.dev_path,
                    stick.identity.serial.as_deref().unwrap_or("none"),
                    kit_out_bytes >> 20
                );
            }
            Err(e) => {
                let outcome = if dfcore::is_refusal(&e) {
                    Outcome::Refused
                } else {
                    Outcome::Error
                };
                append_audit(
                    "fieldkit_write",
                    Some(stick.identity.clone()),
                    details,
                    outcome,
                    Some(format!("{e:#}")),
                );
                return Err(e);
            }
        }
    }

    Ok(0)
}

fn mount_partition_ro(part_dev: &str, fstype: &str, tag: &str) -> Result<TempMount> {
    let _ = run_cmd("blockdev", &["--setro", part_dev]);
    let mut mnt = TempMount::new(tag)?;
    let mnt_str = mnt.path().to_string_lossy().into_owned();

    match fstype {
        "ntfs" => {
            // Try kernel ntfs3 (ro), then ntfs-3g (ro), then mount -t ntfs -o ro
            if run_cmd("mount", &["-t", "ntfs3", "-o", "ro", part_dev, &mnt_str]).is_ok()
                || run_cmd("ntfs-3g", &["-o", "ro", part_dev, &mnt_str]).is_ok()
                || run_cmd("mount", &["-t", "ntfs", "-o", "ro", part_dev, &mnt_str]).is_ok()
            {
                mnt.mounted = true;
                return Ok(mnt);
            }
            bail!("Failed to mount NTFS partition {part_dev} read-only (tried ntfs3 and ntfs-3g)");
        }
        "hfsplus" => {
            run_cmd("mount", &["-t", "hfsplus", "-o", "ro", part_dev, &mnt_str])?;
            mnt.mounted = true;
            Ok(mnt)
        }
        "ext4" => {
            run_cmd(
                "mount",
                &["-t", "ext4", "-o", "ro,noload", part_dev, &mnt_str],
            )?;
            mnt.mounted = true;
            Ok(mnt)
        }
        "exfat" => {
            run_cmd("mount", &["-t", "exfat", "-o", "ro", part_dev, &mnt_str])?;
            mnt.mounted = true;
            Ok(mnt)
        }
        other => bail!("Unsupported partition filesystem '{other}'"),
    }
}

fn cmd_verify(device: &str, image_dir_opt: Option<PathBuf>) -> Result<u8> {
    let image_dir = resolve_default_image_dir(image_dir_opt)?;
    let manifest_path = if image_dir.is_file() && image_dir.ends_with("manifest.json") {
        image_dir.clone()
    } else {
        image_dir.join("manifest.json")
    };
    let manifest = FieldkitManifest::load(&manifest_path)?;

    let canon = fs::canonicalize(device)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| device.to_string());
    let flat = dfcore::lsblk::scan().unwrap_or_default();
    let dev_num = dfcore::sysfs::dev_num_of_path(Path::new(&canon));
    let identity = dfcore::lsblk::lookup(&flat, &canon, dev_num)
        .first()
        .map(|f| f.device.identity())
        .unwrap_or_else(|| DeviceIdentity {
            path: canon.clone(),
            kernel_name: Path::new(&canon)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| device.to_string()),
            ..Default::default()
        });

    let mut total_intact_files = 0usize;
    let mut total_intact_symlinks = 0usize;
    let mut all_changed: Vec<ChangedEntry> = Vec::new();
    let mut all_missing: Vec<MissingEntry> = Vec::new();
    let mut all_os_added: Vec<OsAddedEntry> = Vec::new();
    let mut all_unexpected: Vec<UnexpectedEntry> = Vec::new();
    let mut tools_intact = true;

    // 1. Verify tool partitions 1..=3 read-only
    for num in 1..=3u32 {
        let exp = manifest
            .partition(num)
            .with_context(|| format!("Manifest is missing partition {num}"))?;
        let part_dev = partition_dev_path(&canon, num);
        ensure!(
            Path::new(&part_dev).exists(),
            "Partition device {part_dev} does not exist"
        );
        let mut mnt = mount_partition_ro(&part_dev, &exp.filesystem, &exp.label)?;
        let observed = scan_mounted_tree(mnt.path())?;
        mnt.unmount()?;

        let diff = compare_partition(exp, &observed);
        tools_intact &= diff.tools_intact();
        println!(
            "[*] Partition {num} ({}, {}): {} file(s) intact, {} symlink(s) intact, {} changed, {} missing, {} unexpected, {} OS-added",
            exp.label,
            exp.filesystem,
            diff.intact_files,
            diff.intact_symlinks,
            diff.changed.len(),
            diff.missing.len(),
            diff.unexpected.len(),
            diff.os_added.len()
        );
        for c in &diff.changed {
            println!("    [CHANGED] {}: {} ({})", c.partition, c.path, c.reason);
        }
        for m in &diff.missing {
            println!("    [MISSING] {}: {} ({})", m.partition, m.path, m.kind);
        }
        for u in &diff.unexpected {
            println!(
                "    [UNEXPECTED] {}: {} ({}{})",
                u.partition,
                u.path,
                u.kind,
                u.size.map(|s| format!(", {s} bytes")).unwrap_or_default()
            );
        }
        for a in &diff.os_added {
            println!(
                "    [OS-ADDED] {}: {} ({}{})",
                a.partition,
                a.path,
                a.kind,
                a.size.map(|s| format!(", {s} bytes")).unwrap_or_default()
            );
        }

        total_intact_files += diff.intact_files;
        total_intact_symlinks += diff.intact_symlinks;
        all_changed.extend(diff.changed);
        all_missing.extend(diff.missing);
        all_unexpected.extend(diff.unexpected);
        all_os_added.extend(diff.os_added);
    }

    // 2. Inspect Partition 4 (KIT-OUT) read-only and report captured case files
    let part4_dev = partition_dev_path(&canon, 4);
    let mut kit_id_val: Option<Value> = None;
    let mut kit_out_files: Vec<Value> = Vec::new();
    let mut case_files_count = 0usize;
    if Path::new(&part4_dev).exists() {
        let mut mnt4 = mount_partition_ro(&part4_dev, "exfat", "KIT-OUT")?;
        let kit_id_path = mnt4.path().join("KIT-ID.json");
        if kit_id_path.is_file() {
            if let Ok(bytes) = fs::read(&kit_id_path) {
                kit_id_val = serde_json::from_slice(&bytes).ok();
            }
        }
        let observed4 = scan_mounted_tree(mnt4.path())?;
        mnt4.unmount()?;

        println!(
            "[*] Partition 4 (KIT-OUT, exfat): {} entries",
            observed4.len()
        );
        for (path, entry) in &observed4 {
            let is_marker = matches!(
                path.as_str(),
                ".metadata_never_index" | ".fseventsd/no_log" | "KIT-ID.json"
            );
            let (size, sha256) = match entry {
                ObservedEntry::File { size, sha256 } => (Some(*size), Some(sha256.clone())),
                ObservedEntry::Symlink { .. } | ObservedEntry::Other { .. } => (None, None),
            };
            if !is_marker {
                case_files_count += 1;
                println!(
                    "    [KIT-OUT] {path} ({} bytes, sha256: {})",
                    size.unwrap_or(0),
                    sha256.as_deref().unwrap_or("-")
                );
            }
            kit_out_files.push(json!({
                "path": path,
                "size": size,
                "sha256": sha256,
                "kit_marker": is_marker,
            }));
        }
        println!(
            "[*] To ingest KIT-OUT artifacts ({} case file(s)) into the case, mount {part4_dev} read-only (`dfmount evidence {part4_dev}`) and run:\n    dfcollect files /media/evidence/{} -o <CASE_DIR>/kit-out --case-id <CASE> --examiner <EXAMINER>",
            case_files_count,
            Path::new(&part4_dev)
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "kit-out".into())
        );
    }

    let mut details = Map::new();
    details.insert(
        "manifest_path".into(),
        manifest_path.to_string_lossy().into_owned().into(),
    );
    details.insert("kit_version".into(), manifest.version.into());
    details.insert("intact_files".into(), total_intact_files.into());
    details.insert("intact_symlinks".into(), total_intact_symlinks.into());
    details.insert("changed".into(), serde_json::to_value(&all_changed)?);
    details.insert("missing".into(), serde_json::to_value(&all_missing)?);
    details.insert("unexpected".into(), serde_json::to_value(&all_unexpected)?);
    details.insert("os_added".into(), serde_json::to_value(&all_os_added)?);
    details.insert("kit_id".into(), json!(kit_id_val));
    details.insert("kit_out_files".into(), Value::Array(kit_out_files));
    details.insert("tools_intact".into(), tools_intact.into());

    if tools_intact {
        append_audit(
            "fieldkit_verify",
            Some(identity),
            details,
            Outcome::Ok,
            None,
        );
        println!(
            "[✓] Field-kit verification PASSED on {canon}: all {total_intact_files} tool files and {total_intact_symlinks} symlinks intact ({} OS-added file(s)).",
            all_os_added.len()
        );
        Ok(0)
    } else {
        let msg = format!(
            "{} tool file(s) changed, {} missing, {} unexpected on {canon}",
            all_changed.len(),
            all_missing.len(),
            all_unexpected.len()
        );
        append_audit(
            "fieldkit_verify",
            Some(identity),
            details,
            Outcome::Error,
            Some(msg.clone()),
        );
        eprintln!("[!] Field-kit verification FAILED: {msg}");
        Ok(5)
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let res = match cli.command {
        Commands::Write {
            image_dir,
            devices,
            confirm,
            no_wipe,
        } => cmd_write(&image_dir, &devices, &confirm, !no_wipe),
        Commands::Verify { device, image_dir } => cmd_verify(&device, image_dir),
    };
    match res {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("Error: {e:#}");
            if dfcore::is_refusal(&e) {
                ExitCode::from(2)
            } else {
                ExitCode::from(1)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dfcore::lsblk::parse as parse_lsblk;

    const SAMPLE_LSBLK: &str = r#"{"blockdevices":[
      {"name":"nvme0n1","path":"/dev/nvme0n1","maj:min":"259:0","type":"disk","serial":"SYS001","model":"System NVMe","mountpoints":[null],"children":[
        {"name":"nvme0n1p1","path":"/dev/nvme0n1p1","maj:min":"259:1","type":"part","fstype":"ext4","mountpoints":["/"]}
      ]},
      {"name":"sdb","path":"/dev/sdb","maj:min":"8:16","type":"disk","serial":"MOUNTED01","model":"Mounted USB","mountpoints":[null],"children":[
        {"name":"sdb1","path":"/dev/sdb1","maj:min":"8:17","type":"part","fstype":"exfat","mountpoints":["/media/target/sdb1"]}
      ]}
    ]}"#;

    #[test]
    fn refuses_system_disk_partition_and_mounted_disk() {
        let flat = parse_lsblk(SAMPLE_LSBLK.as_bytes()).unwrap();
        let no_reg_env = std::env::temp_dir().join("dfkit_nonexistent_reg.json");
        std::env::set_var("DFNIX_PROTECTED_FILE", &no_reg_env);

        // System disk refused
        let err =
            validate_stick_for_write(&flat, "/dev/nvme0n1", 1024, &["nvme0n1".into()]).unwrap_err();
        assert!(dfcore::is_refusal(&err), "{err:#}");
        assert!(err.to_string().contains("system"), "{err}");

        // Partition refused (whole disk only)
        let err = validate_stick_for_write(&flat, "/dev/sdb1", 1024, &["sdb1".into()]).unwrap_err();
        assert!(dfcore::is_refusal(&err), "{err:#}");
        assert!(err.to_string().contains("not a whole disk"), "{err}");

        // Mounted disk refused
        let err = validate_stick_for_write(&flat, "/dev/sdb", 1024, &["sdb".into()]).unwrap_err();
        assert!(dfcore::is_refusal(&err), "{err:#}");
        assert!(err.to_string().contains("mounted at"), "{err}");
    }

    #[test]
    fn write_cli_parses_default_wipe_and_no_wipe_flag() {
        let cli_default =
            Cli::try_parse_from(["dfkit", "write", "/etc/dfnix/fieldkit", "/dev/sdb"]).unwrap();
        match cli_default.command {
            Commands::Write { no_wipe, .. } => assert!(!no_wipe),
            _ => panic!("expected Write"),
        }

        let cli_no_wipe = Cli::try_parse_from([
            "dfkit",
            "write",
            "--no-wipe",
            "/etc/dfnix/fieldkit",
            "/dev/sdb",
            "--confirm",
            "sdb",
        ])
        .unwrap();
        match cli_no_wipe.command {
            Commands::Write { no_wipe, .. } => assert!(no_wipe),
            _ => panic!("expected Write"),
        }
    }
}
