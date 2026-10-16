//! Pure GPT header and partition table parsing and geometry calculations for
//! the 4-partition dfnix field-kit image (`KIT-WIN`, `KIT-MAC`, `KIT-LNX`, `KIT-OUT`).

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Seek, SeekFrom};

pub const SECTOR_SIZE: u64 = 512;
pub const GPT_READONLY_BIT60: u64 = 1u64 << 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GptPartition {
    pub number: u32,
    pub type_guid: String,
    pub part_guid: String,
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    pub name: String,
}

impl GptPartition {
    pub fn offset_bytes(&self) -> u64 {
        self.first_lba * SECTOR_SIZE
    }

    pub fn size_sectors(&self) -> u64 {
        self.last_lba.saturating_sub(self.first_lba) + 1
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_sectors() * SECTOR_SIZE
    }

    pub fn is_readonly_bit60(&self) -> bool {
        (self.attributes & GPT_READONLY_BIT60) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GptTable {
    pub disk_guid: String,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub backup_lba: u64,
    pub partitions: Vec<GptPartition>,
}

impl GptTable {
    pub fn partition(&self, number: u32) -> Option<&GptPartition> {
        self.partitions.iter().find(|p| p.number == number)
    }
}

/// Format a 16-byte mixed-endian GPT GUID as `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`.
pub fn format_guid(b: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    )
}

/// Parse the primary GPT header (LBA 1) and partition entry array from a reader.
pub fn read_gpt<R: Read + Seek>(mut r: R) -> Result<GptTable> {
    r.seek(SeekFrom::Start(SECTOR_SIZE))
        .context("Failed to seek to GPT header at LBA 1")?;
    let mut hdr = [0u8; 512];
    r.read_exact(&mut hdr)
        .context("Failed to read GPT header at LBA 1")?;

    ensure!(
        &hdr[0..8] == b"EFI PART",
        "Missing GPT signature ('EFI PART') at LBA 1"
    );
    let current_lba = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
    let backup_lba = u64::from_le_bytes(hdr[32..40].try_into().unwrap());
    let first_usable_lba = u64::from_le_bytes(hdr[40..48].try_into().unwrap());
    let last_usable_lba = u64::from_le_bytes(hdr[48..56].try_into().unwrap());
    let disk_guid = format_guid(hdr[56..72].try_into().unwrap());
    let entries_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let num_entries = u32::from_le_bytes(hdr[80..84].try_into().unwrap());
    let entry_size = u32::from_le_bytes(hdr[84..88].try_into().unwrap());

    ensure!(current_lba == 1, "Unexpected GPT current_lba {current_lba}");
    ensure!(
        (128..=4096).contains(&entry_size),
        "Unsupported GPT partition entry size {entry_size}"
    );
    ensure!(
        num_entries <= 1024,
        "Unreasonable GPT partition entry count {num_entries}"
    );

    let table_bytes = (num_entries as usize) * (entry_size as usize);
    r.seek(SeekFrom::Start(entries_lba * SECTOR_SIZE))
        .context("Failed to seek to GPT partition entries")?;
    let mut raw_entries = vec![0u8; table_bytes];
    r.read_exact(&mut raw_entries)
        .context("Failed to read GPT partition entries")?;

    let mut partitions = Vec::new();
    for i in 0..num_entries {
        let off = (i as usize) * (entry_size as usize);
        let entry = &raw_entries[off..off + (entry_size as usize)];
        let type_raw: [u8; 16] = entry[0..16].try_into().unwrap();
        if type_raw == [0u8; 16] {
            continue;
        }
        let part_raw: [u8; 16] = entry[16..32].try_into().unwrap();
        let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
        let last_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());
        let attributes = u64::from_le_bytes(entry[48..56].try_into().unwrap());
        ensure!(
            first_lba <= last_lba && first_lba >= first_usable_lba,
            "Invalid LBA range {first_lba}..={last_lba} for partition {}",
            i + 1
        );
        let mut utf16 = Vec::with_capacity(36);
        let (pairs, _) = entry[56..128].as_chunks::<2>();
        for &c in pairs {
            let u = u16::from_le_bytes(c);
            if u == 0 {
                break;
            }
            utf16.push(u);
        }
        let name = String::from_utf16_lossy(&utf16);
        partitions.push(GptPartition {
            number: i + 1,
            type_guid: format_guid(&type_raw),
            part_guid: format_guid(&part_raw),
            first_lba,
            last_lba,
            attributes,
            name,
        });
    }

    Ok(GptTable {
        disk_guid,
        first_usable_lba,
        last_usable_lba,
        backup_lba,
        partitions,
    })
}

/// Validate that a parsed GPT matches the 4-partition field-kit layout:
/// 1: KIT-WIN (RO bit 60), 2: KIT-MAC (RO bit 60), 3: KIT-LNX (RO bit 60), 4: KIT-OUT (RW).
pub fn validate_fieldkit_gpt(gpt: &GptTable) -> Result<()> {
    let expected = [
        (1u32, "KIT-WIN", true),
        (2u32, "KIT-MAC", true),
        (3u32, "KIT-LNX", true),
        (4u32, "KIT-OUT", false),
    ];
    for (num, label, want_ro) in expected {
        let Some(p) = gpt.partition(num) else {
            bail!("GPT is missing partition {num} ({label})");
        };
        ensure!(
            p.name == label,
            "Partition {num} has label '{}', expected '{label}'",
            p.name
        );
        ensure!(
            p.is_readonly_bit60() == want_ro,
            "Partition {num} ({label}) read-only bit 60 is {}, expected {want_ro}",
            p.is_readonly_bit60()
        );
    }
    Ok(())
}

/// Compute the partition device node path on Linux for a whole disk path and 1-based partition number.
/// Disks ending in a digit (`nvme0n1`, `mmcblk0`, `loop0`) use `<disk>p<N>`;
/// disks ending in a letter (`sdb`, `vdb`) use `<disk><N>`.
pub fn partition_dev_path(disk_path: &str, part_num: u32) -> String {
    let needs_p = disk_path.chars().last().is_some_and(|c| c.is_ascii_digit());
    if needs_p {
        format!("{disk_path}p{part_num}")
    } else {
        format!("{disk_path}{part_num}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn put_guid_le(dst: &mut [u8], d1: u32, d2: u16, d3: u16, tail: [u8; 8]) {
        dst[0..4].copy_from_slice(&d1.to_le_bytes());
        dst[4..6].copy_from_slice(&d2.to_le_bytes());
        dst[6..8].copy_from_slice(&d3.to_le_bytes());
        dst[8..16].copy_from_slice(&tail);
    }

    fn put_utf16_name(dst: &mut [u8], name: &str) {
        for (i, u) in name.encode_utf16().take(36).enumerate() {
            dst[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
    }

    fn synthetic_fieldkit_gpt() -> Vec<u8> {
        let mut img = vec![0u8; 34 * 512];
        // LBA 1: GPT header
        let hdr = &mut img[512..1024];
        hdr[0..8].copy_from_slice(b"EFI PART");
        hdr[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        hdr[12..16].copy_from_slice(&92u32.to_le_bytes());
        hdr[24..32].copy_from_slice(&1u64.to_le_bytes());
        hdr[32..40].copy_from_slice(&1253375u64.to_le_bytes());
        hdr[40..48].copy_from_slice(&34u64.to_le_bytes());
        hdr[48..56].copy_from_slice(&1253342u64.to_le_bytes());
        put_guid_le(
            &mut hdr[56..72],
            0x4446_4E49,
            0x5800,
            0x4B49,
            [0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        hdr[72..80].copy_from_slice(&2u64.to_le_bytes());
        hdr[80..84].copy_from_slice(&128u32.to_le_bytes());
        hdr[84..88].copy_from_slice(&128u32.to_le_bytes());

        let specs = [
            (1u8, "KIT-WIN", 2048u64, 395263u64, GPT_READONLY_BIT60),
            (2u8, "KIT-MAC", 395264u64, 591871u64, GPT_READONLY_BIT60),
            (3u8, "KIT-LNX", 591872u64, 1116159u64, GPT_READONLY_BIT60),
            (4u8, "KIT-OUT", 1116160u64, 1247231u64, 0u64),
        ];
        for (idx, (id, name, first, last, attr)) in specs.into_iter().enumerate() {
            let off = 1024 + idx * 128;
            let e = &mut img[off..off + 128];
            put_guid_le(
                &mut e[0..16],
                0xEBD0_A0A2,
                0xB9E5,
                0x4433,
                [0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7],
            );
            put_guid_le(
                &mut e[16..32],
                0x4446_4E49,
                0x5800,
                0x4B49,
                [0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, id],
            );
            e[32..40].copy_from_slice(&first.to_le_bytes());
            e[40..48].copy_from_slice(&last.to_le_bytes());
            e[48..56].copy_from_slice(&attr.to_le_bytes());
            put_utf16_name(&mut e[56..128], name);
        }
        img
    }

    #[test]
    fn parses_and_validates_fieldkit_gpt_geometry() {
        let raw = synthetic_fieldkit_gpt();
        let gpt = read_gpt(Cursor::new(&raw)).unwrap();
        assert_eq!(gpt.disk_guid, "44464E49-5800-4B49-5400-000000000000");
        assert_eq!(gpt.partitions.len(), 4);
        validate_fieldkit_gpt(&gpt).unwrap();

        let p1 = gpt.partition(1).unwrap();
        assert_eq!(p1.name, "KIT-WIN");
        assert_eq!(p1.offset_bytes(), 2048 * 512);
        assert_eq!(p1.size_bytes(), 192 * 1024 * 1024);
        assert!(p1.is_readonly_bit60());

        let p2 = gpt.partition(2).unwrap();
        assert_eq!(p2.name, "KIT-MAC");
        assert_eq!(p2.size_bytes(), 96 * 1024 * 1024);
        assert!(p2.is_readonly_bit60());

        let p3 = gpt.partition(3).unwrap();
        assert_eq!(p3.name, "KIT-LNX");
        assert_eq!(p3.size_bytes(), 256 * 1024 * 1024);
        assert!(p3.is_readonly_bit60());

        let p4 = gpt.partition(4).unwrap();
        assert_eq!(p4.name, "KIT-OUT");
        assert_eq!(p4.first_lba, 1116160);
        assert_eq!(p4.size_bytes(), 64 * 1024 * 1024);
        assert_eq!(p4.part_guid, "44464E49-5800-4B49-5400-000000000004");
        assert!(!p4.is_readonly_bit60());
    }

    #[test]
    fn rejects_gpt_when_tool_partition_lacks_bit60() {
        let mut raw = synthetic_fieldkit_gpt();
        // Clear attribute flags on partition 2 (KIT-MAC)
        let off = 1024 + 128;
        raw[off + 48..off + 56].copy_from_slice(&0u64.to_le_bytes());
        let gpt = read_gpt(Cursor::new(&raw)).unwrap();
        let err = validate_fieldkit_gpt(&gpt).unwrap_err();
        assert!(err.to_string().contains("KIT-MAC"), "{err}");
    }

    #[test]
    fn partition_device_naming_handles_letter_and_digit_disks() {
        assert_eq!(partition_dev_path("/dev/sdb", 1), "/dev/sdb1");
        assert_eq!(partition_dev_path("/dev/vdb", 4), "/dev/vdb4");
        assert_eq!(partition_dev_path("/dev/nvme0n1", 4), "/dev/nvme0n1p4");
        assert_eq!(partition_dev_path("/dev/mmcblk0", 2), "/dev/mmcblk0p2");
        assert_eq!(partition_dev_path("/dev/loop0", 3), "/dev/loop0p3");
    }
}
