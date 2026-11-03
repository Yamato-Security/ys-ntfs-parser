// Copyright (C) 2026 Shirofune Security Co., Ltd.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! The NTFS boot sector: the first sector of a volume, and of its `$Boot` file.
//!
//! Its BIOS parameter block gives the volume's sector and cluster sizes, its size, where the `$MFT`
//! and `$MFTMirr` start, the sizes of FILE and INDX records, and the volume serial number. The low
//! 32 bits of that serial number are what Windows shows as `XXXX-XXXX` and what LNK files, Jump
//! Lists and Prefetch files record of the volume a file was on.
//!
//! The rest of the sector and of `$Boot` (8 KiB) is the boot code that starts Windows: the same on
//! volumes formatted by the same Windows, so a [`boot_code`] that differs from other hosts' calls
//! for a look (volume boot record bootkits change it, or the hidden sectors field).
//!
//! [`BootSector::parse`] reads any 512 bytes; [`BootSector::problems`] says what about them Windows
//! would not mount, so damaged and carved sectors can still be shown.
//!
//! ```
//! # let mut data = [0u8; 512];
//! # data[3..11].copy_from_slice(b"NTFS    ");
//! # data[11..13].copy_from_slice(&512u16.to_le_bytes());
//! # data[13] = 8;
//! # data[0x28..0x30].copy_from_slice(&82_757_631u64.to_le_bytes());
//! # data[0x30..0x38].copy_from_slice(&786_432u64.to_le_bytes());
//! # data[0x38..0x40].copy_from_slice(&2u64.to_le_bytes());
//! # data[0x40] = 0xf6;
//! # data[0x44] = 1;
//! # data[0x48..0x50].copy_from_slice(&0x3418_8f60_188f_1fcau64.to_le_bytes());
//! # data[510..512].copy_from_slice(&[0x55, 0xaa]);
//! let boot = boot::BootSector::parse(&data)?;
//! assert_eq!(boot.cluster_size(), Some(4096));
//! assert_eq!(boot.mft_offset(), Some(786_432 * 4096));
//! assert_eq!(boot.volume_serial_number(), 0x188f_1fca);
//! assert!(boot.problems().is_empty());
//! # Ok::<(), boot::TooShort>(())
//! ```

use std::fmt;

/// The size of the boot sector, whatever the volume's sector size: the BIOS parameter block and
/// the start of the boot code, ending with the `55 AA` signature.
pub const BOOT_SECTOR_SIZE: usize = 512;
/// The size of `$Boot` on volumes formatted by Windows: the boot sector and the boot loader after it.
pub const BOOT_FILE_SIZE: usize = 8192;
/// An NTFS volume's OEM ID, after the jump instruction.
pub const NTFS_OEM_ID: &[u8; 8] = b"NTFS    ";
/// The signature at the end of the boot sector (`55 AA` on disk).
pub const END_SIGNATURE: u16 = 0xaa55;
/// The largest cluster Windows formats NTFS with (2 MiB).
pub const MAX_CLUSTER_SIZE: u64 = 2 << 20;

/// Fewer than [`BOOT_SECTOR_SIZE`] bytes were given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooShort {
    /// How many bytes there were.
    pub len: usize,
}

impl fmt::Display for TooShort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a boot sector is {BOOT_SECTOR_SIZE} bytes; only {} were read",
            self.len
        )
    }
}

impl std::error::Error for TooShort {}

/// The fields of an NTFS boot sector, as recorded. The methods give what they mean.
///
/// The FAT fields that NTFS keeps at zero are kept too, since Windows does not mount a volume
/// whose boot sector has them set ([`Problem::FatFields`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSector {
    /// The jump to the boot code (`EB 52 90` on volumes Windows formats).
    pub jump: [u8; 3],
    /// The OEM ID: [`NTFS_OEM_ID`] on NTFS volumes.
    pub oem_id: [u8; 8],
    /// Bytes per sector (offset 0x0B).
    pub bytes_per_sector: u16,
    /// Sectors per cluster as recorded (0x0D): the count up to 0x80, else 2 to the power of
    /// 256 minus it. See [`BootSector::sectors_per_cluster`].
    pub sectors_per_cluster_code: u8,
    /// Reserved sectors (0x0E): zero on NTFS.
    pub reserved_sectors: u16,
    /// Number of FATs (0x10): zero on NTFS.
    pub fats: u8,
    /// FAT root directory entries (0x11): zero on NTFS.
    pub root_entries: u16,
    /// FAT 16-bit sector count (0x13): zero on NTFS.
    pub sectors_16: u16,
    /// Media descriptor (0x15): `F8` for a hard disk.
    pub media_descriptor: u8,
    /// Sectors per FAT (0x16): zero on NTFS.
    pub sectors_per_fat: u16,
    /// Sectors per track (0x18), of the disk's legacy geometry.
    pub sectors_per_track: u16,
    /// Heads (0x1A), of the disk's legacy geometry.
    pub heads: u16,
    /// Hidden sectors (0x1C): the sectors on the disk before the volume, that is where its
    /// partition starts. The boot code reads the rest of `$Boot` from there.
    pub hidden_sectors: u32,
    /// FAT 32-bit sector count (0x20): zero on NTFS.
    pub sectors_32: u32,
    /// The BIOS drive number (0x24): `80` for the first hard disk.
    pub drive_number: u8,
    /// Sectors in the volume (0x28), without the copy of the boot sector at its end.
    pub total_sectors: u64,
    /// The `$MFT`'s first cluster (0x30).
    pub mft_cluster: u64,
    /// The `$MFTMirr`'s first cluster (0x38).
    pub mft_mirror_cluster: u64,
    /// The size of a FILE record as recorded (0x40): clusters if positive, else 2 to the power of
    /// minus it. See [`BootSector::file_record_size`].
    pub file_record_size_code: i8,
    /// The size of an INDX record as recorded (0x44), like `file_record_size_code`.
    pub index_record_size_code: i8,
    /// The volume serial number (0x48).
    pub serial_number: u64,
    /// The checksum (0x50): not used, zero.
    pub checksum: u32,
    /// The signature at 0x1FE: [`END_SIGNATURE`].
    pub end_signature: u16,
}

/// What about a boot sector Windows would not mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Problem {
    /// The OEM ID is not `NTFS    `.
    NotNtfs,
    /// The sector does not end with `55 AA`.
    NoEndSignature,
    /// Bytes per sector is not a power of two from 256 to 4096.
    BytesPerSector,
    /// Sectors per cluster is zero, not a power of two, or makes clusters over 2 MiB.
    SectorsPerCluster,
    /// One of the FAT fields NTFS keeps at zero (reserved sectors, FATs, root entries, sector
    /// counts, sectors per FAT) is not zero.
    FatFields,
    /// The FILE record size is zero, or not a power of two from 256 bytes to 2 MiB.
    FileRecordSize,
    /// The INDX record size is zero, or not a power of two from 256 bytes to 2 MiB.
    IndexRecordSize,
    /// The volume has no sectors.
    NoSectors,
    /// The `$MFT` starts past the end of the volume.
    MftOutsideVolume,
    /// The `$MFTMirr` starts past the end of the volume.
    MftMirrorOutsideVolume,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Problem::NotNtfs => "the OEM ID is not NTFS",
            Problem::NoEndSignature => "the sector does not end with 55 AA",
            Problem::BytesPerSector => "bytes per sector is not a power of two from 256 to 4096",
            Problem::SectorsPerCluster => {
                "sectors per cluster is not a power of two giving clusters of up to 2 MiB"
            }
            Problem::FatFields => "a FAT field that NTFS keeps at zero is not zero",
            Problem::FileRecordSize => {
                "the FILE record size is not a power of two from 256 bytes to 2 MiB"
            }
            Problem::IndexRecordSize => {
                "the INDX record size is not a power of two from 256 bytes to 2 MiB"
            }
            Problem::NoSectors => "the volume has no sectors",
            Problem::MftOutsideVolume => "the $MFT starts past the end of the volume",
            Problem::MftMirrorOutsideVolume => "the $MFTMirr starts past the end of the volume",
        })
    }
}

impl BootSector {
    /// Read the fields of the boot sector at the start of `data` (at least 512 bytes: `$Boot`, or
    /// a volume or its image). Any bytes are read; [`BootSector::problems`] says whether they look
    /// like a sector Windows would mount.
    ///
    /// # Errors
    ///
    /// If `data` is shorter than [`BOOT_SECTOR_SIZE`].
    pub fn parse(data: &[u8]) -> Result<Self, TooShort> {
        let Some(s) = data.get(..BOOT_SECTOR_SIZE) else {
            return Err(TooShort { len: data.len() });
        };
        let u16_at = |at: usize| u16::from_le_bytes([s[at], s[at + 1]]);
        let u32_at = |at: usize| u32::from_le_bytes([s[at], s[at + 1], s[at + 2], s[at + 3]]);
        let u64_at = |at: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&s[at..at + 8]);
            u64::from_le_bytes(b)
        };
        Ok(Self {
            jump: [s[0], s[1], s[2]],
            oem_id: [s[3], s[4], s[5], s[6], s[7], s[8], s[9], s[10]],
            bytes_per_sector: u16_at(0x0b),
            sectors_per_cluster_code: s[0x0d],
            reserved_sectors: u16_at(0x0e),
            fats: s[0x10],
            root_entries: u16_at(0x11),
            sectors_16: u16_at(0x13),
            media_descriptor: s[0x15],
            sectors_per_fat: u16_at(0x16),
            sectors_per_track: u16_at(0x18),
            heads: u16_at(0x1a),
            hidden_sectors: u32_at(0x1c),
            sectors_32: u32_at(0x20),
            drive_number: s[0x24],
            total_sectors: u64_at(0x28),
            mft_cluster: u64_at(0x30),
            mft_mirror_cluster: u64_at(0x38),
            file_record_size_code: i8::from_le_bytes([s[0x40]]),
            index_record_size_code: i8::from_le_bytes([s[0x44]]),
            serial_number: u64_at(0x48),
            checksum: u32_at(0x50),
            end_signature: u16_at(0x1fe),
        })
    }

    /// Whether the OEM ID is NTFS's.
    #[must_use]
    pub fn is_ntfs(&self) -> bool {
        &self.oem_id == NTFS_OEM_ID
    }

    /// The OEM ID as text (`NTFS    `), with bytes that are not printable ASCII as `\xNN`.
    #[must_use]
    pub fn oem_id_text(&self) -> String {
        self.oem_id
            .iter()
            .map(|&b| {
                if b == b' ' || b.is_ascii_graphic() {
                    char::from(b).to_string()
                } else {
                    format!("\\x{b:02X}")
                }
            })
            .collect()
    }

    /// Bytes per sector, if it is a power of two from 256 to 4096.
    #[must_use]
    pub fn sector_size(&self) -> Option<u64> {
        let n = self.bytes_per_sector;
        (n.is_power_of_two() && (256..=4096).contains(&n)).then_some(u64::from(n))
    }

    /// Sectors per cluster: the recorded count up to 0x80, else 2 to the power of 256 minus it
    /// (for clusters over 64 KiB). `None` if zero or not a power of two.
    #[must_use]
    pub fn sectors_per_cluster(&self) -> Option<u64> {
        let code = self.sectors_per_cluster_code;
        match code {
            0 => None,
            1..=0x80 => code.is_power_of_two().then_some(u64::from(code)),
            _ => {
                let shift = 256 - u32::from(code);
                (shift < 32).then(|| 1u64 << shift)
            }
        }
    }

    /// Bytes per cluster, if the sector size and sectors per cluster are valid and give at most
    /// [`MAX_CLUSTER_SIZE`].
    #[must_use]
    pub fn cluster_size(&self) -> Option<u64> {
        let size = self.sector_size()? * self.sectors_per_cluster()?;
        (size <= MAX_CLUSTER_SIZE).then_some(size)
    }

    /// Bytes per FILE record (usually 1024), if valid.
    #[must_use]
    pub fn file_record_size(&self) -> Option<u64> {
        self.record_size(self.file_record_size_code)
    }

    /// Bytes per INDX record (usually 4096), if valid.
    #[must_use]
    pub fn index_record_size(&self) -> Option<u64> {
        self.record_size(self.index_record_size_code)
    }

    fn record_size(&self, code: i8) -> Option<u64> {
        let size = match code {
            0 => return None,
            1.. => u64::try_from(code).ok()? * self.cluster_size()?,
            _ => {
                let shift = code.unsigned_abs();
                if shift >= 32 {
                    return None;
                }
                1u64 << shift
            }
        };
        (size.is_power_of_two() && (256..=MAX_CLUSTER_SIZE).contains(&size)).then_some(size)
    }

    /// Bytes in the volume ([`BootSector::total_sectors`] sectors), without the copy of the boot
    /// sector after them.
    #[must_use]
    pub fn volume_size(&self) -> Option<u64> {
        self.total_sectors.checked_mul(self.sector_size()?)
    }

    /// Clusters in the volume.
    #[must_use]
    pub fn total_clusters(&self) -> Option<u64> {
        Some(self.total_sectors / self.sectors_per_cluster()?)
    }

    /// Where the `$MFT` starts, in bytes from the start of the volume.
    #[must_use]
    pub fn mft_offset(&self) -> Option<u64> {
        self.mft_cluster.checked_mul(self.cluster_size()?)
    }

    /// Where the `$MFTMirr` starts, in bytes from the start of the volume.
    #[must_use]
    pub fn mft_mirror_offset(&self) -> Option<u64> {
        self.mft_mirror_cluster.checked_mul(self.cluster_size()?)
    }

    /// The 32-bit volume serial number: the low half of [`BootSector::serial_number`]. Windows
    /// shows it as `XXXX-XXXX` (high word first), and LNK files, Jump Lists and Prefetch files
    /// record it for the volume a file was on.
    #[must_use]
    pub fn volume_serial_number(&self) -> u32 {
        (self.serial_number & 0xffff_ffff) as u32
    }

    /// What about the sector Windows would not mount, if anything.
    #[must_use]
    pub fn problems(&self) -> Vec<Problem> {
        let mut problems = Vec::new();
        if !self.is_ntfs() {
            problems.push(Problem::NotNtfs);
        }
        if self.end_signature != END_SIGNATURE {
            problems.push(Problem::NoEndSignature);
        }
        if self.sector_size().is_none() {
            problems.push(Problem::BytesPerSector);
        }
        if self.sectors_per_cluster().is_none()
            || (self.sector_size().is_some() && self.cluster_size().is_none())
        {
            problems.push(Problem::SectorsPerCluster);
        }
        if self.reserved_sectors != 0
            || self.fats != 0
            || self.root_entries != 0
            || self.sectors_16 != 0
            || self.sectors_per_fat != 0
            || self.sectors_32 != 0
        {
            problems.push(Problem::FatFields);
        }
        let clusters_known = self.cluster_size().is_some();
        if (clusters_known || self.file_record_size_code <= 0) && self.file_record_size().is_none()
        {
            problems.push(Problem::FileRecordSize);
        }
        if (clusters_known || self.index_record_size_code <= 0)
            && self.index_record_size().is_none()
        {
            problems.push(Problem::IndexRecordSize);
        }
        if self.total_sectors == 0 {
            problems.push(Problem::NoSectors);
        }
        if let Some(clusters) = self.total_clusters().filter(|_| self.total_sectors != 0) {
            if self.mft_cluster >= clusters {
                problems.push(Problem::MftOutsideVolume);
            }
            if self.mft_mirror_cluster >= clusters {
                problems.push(Problem::MftMirrorOutsideVolume);
            }
        }
        problems
    }
}

/// The boot code in `data` (`$Boot`, or the start of a volume): the code in the boot sector
/// (0x54 to 0x1FD, after the BIOS parameter block and before the signature) and the boot loader
/// after the sector, up to [`BOOT_FILE_SIZE`]. Volumes formatted by the same Windows have the same
/// boot code; hash both parts together to compare hosts.
#[must_use]
pub fn boot_code(data: &[u8]) -> [&[u8]; 2] {
    let end = data.len().min(BOOT_FILE_SIZE);
    [
        data.get(0x54..0x1fe).unwrap_or_default(),
        data.get(BOOT_SECTOR_SIZE..end).unwrap_or_default(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A boot sector as Windows writes it: 512-byte sectors, 4 KiB clusters, 1 KiB FILE records,
    /// 4 KiB INDX records.
    fn sector() -> Vec<u8> {
        let mut s = vec![0u8; BOOT_SECTOR_SIZE];
        s[..3].copy_from_slice(&[0xeb, 0x52, 0x90]);
        s[3..11].copy_from_slice(NTFS_OEM_ID);
        s[0x0b..0x0d].copy_from_slice(&512u16.to_le_bytes());
        s[0x0d] = 8;
        s[0x15] = 0xf8;
        s[0x18..0x1a].copy_from_slice(&63u16.to_le_bytes());
        s[0x1a..0x1c].copy_from_slice(&255u16.to_le_bytes());
        s[0x1c..0x20].copy_from_slice(&239_616u32.to_le_bytes());
        s[0x24] = 0x80;
        s[0x28..0x30].copy_from_slice(&82_757_631u64.to_le_bytes());
        s[0x30..0x38].copy_from_slice(&786_432u64.to_le_bytes());
        s[0x38..0x40].copy_from_slice(&2u64.to_le_bytes());
        s[0x40] = 0xf6;
        s[0x44] = 1;
        s[0x48..0x50].copy_from_slice(&0x3418_8f60_188f_1fcau64.to_le_bytes());
        s[0x1fe..].copy_from_slice(&[0x55, 0xaa]);
        s
    }

    #[test]
    fn fields_and_what_they_mean() {
        let boot = BootSector::parse(&sector()).unwrap();
        assert_eq!(boot.jump, [0xeb, 0x52, 0x90]);
        assert!(boot.is_ntfs());
        assert_eq!(boot.oem_id_text(), "NTFS    ");
        assert_eq!(boot.sector_size(), Some(512));
        assert_eq!(boot.sectors_per_cluster(), Some(8));
        assert_eq!(boot.cluster_size(), Some(4096));
        assert_eq!(boot.file_record_size(), Some(1024));
        assert_eq!(boot.index_record_size(), Some(4096));
        assert_eq!(boot.volume_size(), Some(82_757_631 * 512));
        assert_eq!(boot.total_clusters(), Some(82_757_631 / 8));
        assert_eq!(boot.mft_offset(), Some(786_432 * 4096));
        assert_eq!(boot.mft_mirror_offset(), Some(8192));
        assert_eq!(boot.hidden_sectors, 239_616);
        assert_eq!(boot.serial_number, 0x3418_8f60_188f_1fca);
        assert_eq!(boot.volume_serial_number(), 0x188f_1fca);
        assert_eq!(boot.end_signature, END_SIGNATURE);
        assert_eq!(boot.problems(), []);
    }

    #[test]
    fn large_clusters_and_records_in_clusters() {
        let mut s = sector();
        // 2 MiB clusters: 2^12 sectors of 512 bytes
        s[0x0d] = 0xf4;
        let boot = BootSector::parse(&s).unwrap();
        assert_eq!(boot.sectors_per_cluster(), Some(4096));
        assert_eq!(boot.cluster_size(), Some(2 << 20));
        // 4 MiB clusters are more than Windows formats
        s[0x0d] = 0xf3;
        let boot = BootSector::parse(&s).unwrap();
        assert_eq!(boot.cluster_size(), None);
        assert!(boot.problems().contains(&Problem::SectorsPerCluster));
        // an INDX record of one 4 KiB cluster, a FILE record of 2^12 bytes
        s[0x0d] = 8;
        s[0x40] = 0xf4;
        let boot = BootSector::parse(&s).unwrap();
        assert_eq!(boot.file_record_size(), Some(4096));
        assert_eq!(boot.problems(), []);
    }

    #[test]
    fn what_windows_would_not_mount() {
        let mut s = sector();
        s[3..11].copy_from_slice(b"MSDOS5.0");
        s[0x0b..0x0d].copy_from_slice(&500u16.to_le_bytes());
        s[0x0e] = 32;
        s[0x40] = 0;
        s[0x44] = 3;
        s[0x1fe] = 0;
        let boot = BootSector::parse(&s).unwrap();
        assert_eq!(
            boot.problems(),
            [
                Problem::NotNtfs,
                Problem::NoEndSignature,
                Problem::BytesPerSector,
                Problem::FatFields,
                Problem::FileRecordSize,
            ]
        );
        assert_eq!(boot.volume_size(), None);
        assert_eq!(boot.mft_offset(), None);

        let mut s = sector();
        s[0x30..0x38].copy_from_slice(&u64::MAX.to_le_bytes());
        s[0x44] = 3;
        let boot = BootSector::parse(&s).unwrap();
        assert_eq!(
            boot.problems(),
            [Problem::IndexRecordSize, Problem::MftOutsideVolume]
        );
        assert_eq!(boot.mft_offset(), None);

        let empty = BootSector::parse(&[0u8; 512]).unwrap();
        assert_eq!(
            empty.problems(),
            [
                Problem::NotNtfs,
                Problem::NoEndSignature,
                Problem::BytesPerSector,
                Problem::SectorsPerCluster,
                Problem::FileRecordSize,
                Problem::IndexRecordSize,
                Problem::NoSectors,
            ]
        );
    }

    #[test]
    fn short_data_and_odd_oem_ids() {
        assert_eq!(BootSector::parse(&[0u8; 511]), Err(TooShort { len: 511 }));
        assert_eq!(
            TooShort { len: 3 }.to_string(),
            "a boot sector is 512 bytes; only 3 were read"
        );
        let mut s = sector();
        s[3..11].copy_from_slice(b"NTFS\0\xff  ");
        let boot = BootSector::parse(&s).unwrap();
        assert_eq!(boot.oem_id_text(), "NTFS\\x00\\xFF  ");
    }

    #[test]
    fn boot_code_parts() {
        let mut data = sector();
        data.resize(BOOT_FILE_SIZE + 100, 7);
        let [sector_code, loader] = boot_code(&data);
        assert_eq!(sector_code.len(), 0x1fe - 0x54);
        assert_eq!(loader.len(), BOOT_FILE_SIZE - BOOT_SECTOR_SIZE);
        let [sector_code, loader] = boot_code(&data[..0x100]);
        assert!(sector_code.is_empty() && loader.is_empty());
    }
}
