//! Pure manifest deserialization and comparison logic for `dfkit verify`.
//!
//! Compares actual files and symlinks on a mounted partition against
//! `manifest.json`, separating changed/missing tool files and planted
//! unexpected files from known OS-added noise (`System Volume Information/**`,
//! `$RECYCLE.BIN/**`, `.fseventsd/**`, `.Spotlight-V100/**`, `.Trashes/**`,
//! `.TemporaryItems/**`, `.DocumentRevisions-V100/**`, `.Trash-*/**`,
//! `**/.DS_Store`, `**/._*`).

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    os::unix::fs::FileTypeExt,
    path::Path,
};

pub const MANIFEST_SCHEMA: &str = "dfnix.fieldkit.manifest/v0";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldkitManifest {
    pub schema: String,
    pub version: String,
    pub gpt_disk_guid: String,
    pub image: ManifestImage,
    pub partitions: Vec<ManifestPartition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestImage {
    pub file: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestPartition {
    pub number: u32,
    pub label: String,
    pub filesystem: String,
    pub gpt_type_code: String,
    pub gpt_type_guid: String,
    pub gpt_partition_guid: String,
    pub gpt_readonly_bit60: bool,
    pub file_count: usize,
    pub symlink_count: usize,
    pub files: Vec<ManifestFile>,
    pub symlinks: Vec<ManifestSymlink>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub package: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub license: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSymlink {
    pub path: String,
    pub target: String,
    #[serde(default)]
    pub package: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub license: String,
}

impl FieldkitManifest {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes =
            fs::read(path).with_context(|| format!("Cannot read manifest {}", path.display()))?;
        Self::from_slice(&bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let m: Self = serde_json::from_slice(bytes).context("Invalid fieldkit manifest JSON")?;
        ensure!(
            m.schema == MANIFEST_SCHEMA,
            "Unsupported fieldkit manifest schema '{}' (expected '{MANIFEST_SCHEMA}')",
            m.schema
        );
        Ok(m)
    }

    pub fn partition(&self, number: u32) -> Option<&ManifestPartition> {
        self.partitions.iter().find(|p| p.number == number)
    }
}

/// Observed state of a single entry on a mounted partition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedEntry {
    File { size: u64, sha256: String },
    Symlink { target: String },
    Other { kind: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangedEntry {
    pub partition: String,
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingEntry {
    pub partition: String,
    pub path: String,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsAddedEntry {
    pub partition: String,
    pub path: String,
    pub size: Option<u64>,
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnexpectedEntry {
    pub partition: String,
    pub path: String,
    pub size: Option<u64>,
    pub kind: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionDiff {
    pub label: String,
    pub intact_files: usize,
    pub intact_symlinks: usize,
    pub changed: Vec<ChangedEntry>,
    pub missing: Vec<MissingEntry>,
    pub os_added: Vec<OsAddedEntry>,
    pub unexpected: Vec<UnexpectedEntry>,
}

impl PartitionDiff {
    /// True when every expected tool file and symlink in `manifest.json` is intact
    /// and no unexpected (non-OS-noise) files or special nodes were added.
    pub fn tools_intact(&self) -> bool {
        self.changed.is_empty() && self.missing.is_empty() && self.unexpected.is_empty()
    }
}

/// Strict allowlist of known suspect-OS indexer, recycle, and metadata paths:
/// - `System Volume Information/**`
/// - `$RECYCLE.BIN/**`
/// - `.fseventsd/**`
/// - `.Spotlight-V100/**`
/// - `.Trashes/**`
/// - `.TemporaryItems/**`
/// - `.DocumentRevisions-V100/**`
/// - `.Trash-*/**`
/// - `**/.DS_Store`
/// - `**/._*`
pub fn is_known_os_noise(rel_path: &str) -> bool {
    let normalized = rel_path.trim_start_matches('/');
    let mut parts = normalized.split('/');
    let Some(first) = parts.next() else {
        return false;
    };
    let has_rest = parts.clone().next().is_some();
    if has_rest
        && (first.eq_ignore_ascii_case("System Volume Information")
            || first.eq_ignore_ascii_case("$RECYCLE.BIN")
            || matches!(
                first,
                ".fseventsd"
                    | ".Spotlight-V100"
                    | ".Trashes"
                    | ".TemporaryItems"
                    | ".DocumentRevisions-V100"
            )
            || first.starts_with(".Trash-"))
    {
        return true;
    }

    let base = normalized.rsplit('/').next().unwrap_or(normalized);
    base == ".DS_Store" || (base.starts_with("._") && base.len() > 2)
}

/// Pure comparison of a partition's expected manifest entries against observed entries.
pub fn compare_partition(
    expected: &ManifestPartition,
    observed: &BTreeMap<String, ObservedEntry>,
) -> PartitionDiff {
    let mut diff = PartitionDiff {
        label: expected.label.clone(),
        ..Default::default()
    };
    let mut expected_paths = BTreeSet::new();

    for exp_file in &expected.files {
        expected_paths.insert(exp_file.path.as_str());
        match observed.get(&exp_file.path) {
            None => diff.missing.push(MissingEntry {
                partition: expected.label.clone(),
                path: exp_file.path.clone(),
                kind: "file".into(),
            }),
            Some(ObservedEntry::Symlink { target }) => diff.changed.push(ChangedEntry {
                partition: expected.label.clone(),
                path: exp_file.path.clone(),
                reason: format!("expected regular file, found symlink -> {target}"),
            }),
            Some(ObservedEntry::Other { kind }) => diff.changed.push(ChangedEntry {
                partition: expected.label.clone(),
                path: exp_file.path.clone(),
                reason: format!("expected regular file, found {kind}"),
            }),
            Some(ObservedEntry::File { size, sha256 }) => {
                if *size != exp_file.size || *sha256 != exp_file.sha256 {
                    diff.changed.push(ChangedEntry {
                        partition: expected.label.clone(),
                        path: exp_file.path.clone(),
                        reason: format!(
                            "size/hash mismatch (expected {} bytes {}, got {} bytes {})",
                            exp_file.size, exp_file.sha256, size, sha256
                        ),
                    });
                } else {
                    diff.intact_files += 1;
                }
            }
        }
    }

    for exp_link in &expected.symlinks {
        expected_paths.insert(exp_link.path.as_str());
        match observed.get(&exp_link.path) {
            None => diff.missing.push(MissingEntry {
                partition: expected.label.clone(),
                path: exp_link.path.clone(),
                kind: "symlink".into(),
            }),
            Some(ObservedEntry::File { size, .. }) => diff.changed.push(ChangedEntry {
                partition: expected.label.clone(),
                path: exp_link.path.clone(),
                reason: format!(
                    "expected symlink -> {}, found regular file ({size} bytes)",
                    exp_link.target
                ),
            }),
            Some(ObservedEntry::Other { kind }) => diff.changed.push(ChangedEntry {
                partition: expected.label.clone(),
                path: exp_link.path.clone(),
                reason: format!("expected symlink -> {}, found {kind}", exp_link.target),
            }),
            Some(ObservedEntry::Symlink { target }) => {
                if *target != exp_link.target {
                    diff.changed.push(ChangedEntry {
                        partition: expected.label.clone(),
                        path: exp_link.path.clone(),
                        reason: format!(
                            "symlink target mismatch (expected '{}', got '{target}')",
                            exp_link.target
                        ),
                    });
                } else {
                    diff.intact_symlinks += 1;
                }
            }
        }
    }

    for (path, entry) in observed {
        if !expected_paths.contains(path.as_str()) {
            match entry {
                ObservedEntry::Other { kind } => {
                    diff.unexpected.push(UnexpectedEntry {
                        partition: expected.label.clone(),
                        path: path.clone(),
                        size: None,
                        kind: kind.clone(),
                    });
                }
                ObservedEntry::File { size, .. } => {
                    if is_known_os_noise(path) {
                        diff.os_added.push(OsAddedEntry {
                            partition: expected.label.clone(),
                            path: path.clone(),
                            size: Some(*size),
                            kind: "file".into(),
                        });
                    } else {
                        diff.unexpected.push(UnexpectedEntry {
                            partition: expected.label.clone(),
                            path: path.clone(),
                            size: Some(*size),
                            kind: "file".into(),
                        });
                    }
                }
                ObservedEntry::Symlink { .. } => {
                    if is_known_os_noise(path) {
                        diff.os_added.push(OsAddedEntry {
                            partition: expected.label.clone(),
                            path: path.clone(),
                            size: None,
                            kind: "symlink".into(),
                        });
                    } else {
                        diff.unexpected.push(UnexpectedEntry {
                            partition: expected.label.clone(),
                            path: path.clone(),
                            size: None,
                            kind: "symlink".into(),
                        });
                    }
                }
            }
        }
    }

    diff
}

pub fn sha256_file(path: &Path) -> Result<(u64, String)> {
    use sha2::{Digest, Sha256};
    let mut f = fs::File::open(path).with_context(|| format!("Cannot open {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok((
        total,
        h.finalize().iter().map(|b| format!("{b:02x}")).collect(),
    ))
}

/// Walk a mounted partition directory without following symlinks, skipping `lost+found`.
/// Non-regular entries (FIFOs, device nodes, sockets) are recorded as `ObservedEntry::Other`.
pub fn scan_mounted_tree(root: &Path) -> Result<BTreeMap<String, ObservedEntry>> {
    let mut out = BTreeMap::new();
    walk_dir(root, root, &mut out)?;
    Ok(out)
}

fn walk_dir(root: &Path, dir: &Path, out: &mut BTreeMap<String, ObservedEntry>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("Cannot read directory {}", dir.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "lost+found" {
            continue;
        }
        let ft = entry
            .file_type()
            .with_context(|| format!("Cannot stat {}", path.display()))?;
        if ft.is_symlink() {
            let target = fs::read_link(&path)
                .with_context(|| format!("Cannot readlink {}", path.display()))?
                .to_string_lossy()
                .into_owned();
            out.insert(rel, ObservedEntry::Symlink { target });
        } else if ft.is_dir() {
            walk_dir(root, &path, out)?;
        } else if ft.is_file() {
            let (size, sha256) = sha256_file(&path)?;
            out.insert(rel, ObservedEntry::File { size, sha256 });
        } else {
            let kind = if ft.is_fifo() {
                "fifo"
            } else if ft.is_char_device() {
                "char_device"
            } else if ft.is_block_device() {
                "block_device"
            } else if ft.is_socket() {
                "socket"
            } else {
                "other"
            };
            out.insert(
                rel,
                ObservedEntry::Other {
                    kind: kind.to_string(),
                },
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_partition() -> ManifestPartition {
        ManifestPartition {
            number: 1,
            label: "KIT-WIN".into(),
            filesystem: "ntfs".into(),
            gpt_type_code: "0700".into(),
            gpt_type_guid: "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7".into(),
            gpt_partition_guid: "44464E49-5800-4B49-5400-000000000001".into(),
            gpt_readonly_bit60: true,
            file_count: 2,
            symlink_count: 1,
            files: vec![
                ManifestFile {
                    path: "live-windows.md".into(),
                    size: 100,
                    sha256: "aaaa".into(),
                    package: "dfnix-fieldkit".into(),
                    version: "0.1.0".into(),
                    license: "MIT".into(),
                },
                ManifestFile {
                    path: "winpmem/winpmem_mini_x64_rc2.exe".into(),
                    size: 200,
                    sha256: "bbbb".into(),
                    package: "winpmem".into(),
                    version: "4.0.rc1".into(),
                    license: "Apache-2.0".into(),
                },
            ],
            symlinks: vec![ManifestSymlink {
                path: "uac/bin/sh".into(),
                target: "busybox".into(),
                package: "busybox".into(),
                version: "1.37.0".into(),
                license: "GPL-2.0-only".into(),
            }],
        }
    }

    #[test]
    fn intact_partition_with_allowlisted_os_noise_passes_tool_integrity() {
        let exp = sample_partition();
        let mut observed = BTreeMap::new();
        observed.insert(
            "live-windows.md".into(),
            ObservedEntry::File {
                size: 100,
                sha256: "aaaa".into(),
            },
        );
        observed.insert(
            "winpmem/winpmem_mini_x64_rc2.exe".into(),
            ObservedEntry::File {
                size: 200,
                sha256: "bbbb".into(),
            },
        );
        observed.insert(
            "uac/bin/sh".into(),
            ObservedEntry::Symlink {
                target: "busybox".into(),
            },
        );
        for noise in [
            "System Volume Information/WPSettings.dat",
            "$RECYCLE.BIN/S-1-5-18/desktop.ini",
            ".Spotlight-V100/Store-V2",
            ".fseventsd/fseventsd-uuid",
            ".Trashes/501/item",
            ".TemporaryItems/folders.501",
            ".DocumentRevisions-V100/PerUID/1",
            ".Trash-1000/files/foo",
            "winpmem/.DS_Store",
            "winpmem/._winpmem_mini_x64_rc2.exe",
        ] {
            observed.insert(
                noise.into(),
                ObservedEntry::File {
                    size: 12,
                    sha256: "1234".into(),
                },
            );
        }

        let diff = compare_partition(&exp, &observed);
        assert!(diff.tools_intact());
        assert_eq!(diff.intact_files, 2);
        assert_eq!(diff.intact_symlinks, 1);
        assert!(diff.changed.is_empty());
        assert!(diff.missing.is_empty());
        assert!(diff.unexpected.is_empty());
        assert_eq!(diff.os_added.len(), 10);
    }

    #[test]
    fn planted_files_and_special_nodes_fail_tool_integrity() {
        let exp = sample_partition();
        let mut observed = BTreeMap::new();
        observed.insert(
            "live-windows.md".into(),
            ObservedEntry::File {
                size: 100,
                sha256: "aaaa".into(),
            },
        );
        observed.insert(
            "winpmem/winpmem_mini_x64_rc2.exe".into(),
            ObservedEntry::File {
                size: 200,
                sha256: "bbbb".into(),
            },
        );
        observed.insert(
            "uac/bin/sh".into(),
            ObservedEntry::Symlink {
                target: "busybox".into(),
            },
        );
        // Planted DLL hijack, autorun.inf, root desktop.ini, and a special node (FIFO)
        observed.insert(
            "winpmem/version.dll".into(),
            ObservedEntry::File {
                size: 4096,
                sha256: "deadbeef".into(),
            },
        );
        observed.insert(
            "autorun.inf".into(),
            ObservedEntry::File {
                size: 64,
                sha256: "bad0".into(),
            },
        );
        observed.insert(
            "desktop.ini".into(),
            ObservedEntry::File {
                size: 32,
                sha256: "bad1".into(),
            },
        );
        observed.insert(
            "System Volume Information/planted.fifo".into(),
            ObservedEntry::Other {
                kind: "fifo".into(),
            },
        );

        let diff = compare_partition(&exp, &observed);
        assert!(!diff.tools_intact());
        assert_eq!(diff.unexpected.len(), 4);
        assert!(diff.os_added.is_empty());
    }

    #[test]
    fn modified_or_missing_tool_file_is_flagged_separately_from_os_noise() {
        let exp = sample_partition();
        let mut observed = BTreeMap::new();
        // Modified file
        observed.insert(
            "live-windows.md".into(),
            ObservedEntry::File {
                size: 105,
                sha256: "cccc".into(),
            },
        );
        // winpmem is missing
        // symlink target changed
        observed.insert(
            "uac/bin/sh".into(),
            ObservedEntry::Symlink {
                target: "/bin/sh".into(),
            },
        );
        // OS noise
        observed.insert(
            ".Spotlight-V100/Store-V2".into(),
            ObservedEntry::File {
                size: 42,
                sha256: "9999".into(),
            },
        );

        let diff = compare_partition(&exp, &observed);
        assert!(!diff.tools_intact());
        assert_eq!(diff.intact_files, 0);
        assert_eq!(diff.intact_symlinks, 0);
        assert_eq!(diff.changed.len(), 2);
        assert_eq!(diff.changed[0].path, "live-windows.md");
        assert_eq!(diff.changed[1].path, "uac/bin/sh");
        assert_eq!(diff.missing.len(), 1);
        assert_eq!(diff.missing[0].path, "winpmem/winpmem_mini_x64_rc2.exe");
        assert_eq!(diff.os_added.len(), 1);
        assert_eq!(diff.os_added[0].path, ".Spotlight-V100/Store-V2");
    }
}
