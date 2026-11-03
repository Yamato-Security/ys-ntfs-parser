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

//! `$SDS`, the stream of `$Secure` that holds the security descriptors.
//!
//! The stream is in 256 KiB blocks, and each block of entries is followed by a copy of it, its
//! mirror: entries are in blocks 0, 2, 4, … Each entry is a 20-byte header (the descriptor's hash,
//! its security ID, the entry's offset in the stream and its size with the header) and then the
//! self-relative security descriptor, padded to 16 bytes. Entries do not cross a block. After a
//! block's entries come zeros; the stream's last block is mirrored only as far as its entries go,
//! and past that it may hold whatever was on the disk before.
//!
//! [`read`] reads each block's entries in order, compares each with its mirror copy, reads the
//! mirror copy of an entry that is damaged, and steps over bytes that are not entries to the next
//! one, saying so in [`Sds::problems`].

use crate::descriptor::{self, Error, SecurityDescriptor};
use std::collections::HashMap;
use std::fmt;

/// The size of a block of entries, and of its mirror (256 KiB).
pub const BLOCK_SIZE: usize = 0x40000;
/// The size of an entry's header.
pub const ENTRY_HEADER_SIZE: usize = 20;
/// The security ID NTFS gives the first descriptor of a volume.
pub const FIRST_SECURITY_ID: u32 = 0x100;
/// The smallest entry: a header and a descriptor's header.
const MIN_ENTRY_SIZE: usize = ENTRY_HEADER_SIZE + descriptor::HEADER_SIZE;

/// An entry of `$SDS`: a security ID and its descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<'a> {
    /// Where the entry was read in the stream: in the mirror block for a mirror copy.
    pub position: u64,
    /// The hash recorded with the descriptor (see [`descriptor_hash`]).
    pub hash: u32,
    /// The security ID, by which `$STANDARD_INFORMATION` names the descriptor.
    pub security_id: u32,
    /// The entry's offset in the stream, as recorded: where the entry is, outside the mirror.
    pub offset: u64,
    /// The entry's size, header included.
    pub size: u32,
    /// The self-relative security descriptor.
    pub descriptor: &'a [u8],
    /// Read from the mirror block: the copy there differs from the entry, or the entry is
    /// damaged and this copy is not.
    pub from_mirror: bool,
}

impl<'a> Entry<'a> {
    /// Whether the recorded hash is the descriptor's. NTFS finds descriptors by hash (`$SDH`),
    /// so a descriptor changed on disk without its hash would not be found by it.
    #[must_use]
    pub fn hash_matches(&self) -> bool {
        descriptor_hash(self.descriptor) == self.hash
    }

    /// Decode the security descriptor.
    ///
    /// # Errors
    ///
    /// As [`SecurityDescriptor::parse`].
    pub fn security_descriptor(&self) -> Result<SecurityDescriptor<'a>, Error> {
        SecurityDescriptor::parse(self.descriptor)
    }
}

/// Something about the stream other than its entries: bytes that are not entries, a damaged entry
/// read from its mirror, a security ID that appears again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Where in the stream.
    pub position: u64,
    /// What.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:x}: {}", self.position, self.message)
    }
}

/// The entries of an `$SDS` stream, in stream order, each mirror copy that differs right after its
/// entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sds<'a> {
    /// The entries.
    pub entries: Vec<Entry<'a>>,
    /// What else was found.
    pub problems: Vec<Problem>,
}

/// The hash NTFS records with a security descriptor: for each little-endian 32-bit word, the hash
/// rotated left by 3, plus the word.
#[must_use]
pub fn descriptor_hash(descriptor: &[u8]) -> u32 {
    descriptor
        .as_chunks::<4>()
        .0
        .iter()
        .fold(0u32, |hash, word| {
            hash.rotate_left(3).wrapping_add(u32::from_le_bytes(*word))
        })
}

/// Whether `data` starts like an `$SDS` stream: an entry at offset 0 that holds a self-relative
/// security descriptor. The first entry is small: 4 KiB of the stream are enough.
#[must_use]
pub fn looks_like_sds(data: &[u8]) -> bool {
    entry_at(data, 0, 0, data.len().min(BLOCK_SIZE), false)
        .is_some_and(|entry| entry.security_descriptor().is_ok())
}

/// Read the entries of an `$SDS` stream (the whole stream, mirror blocks included).
#[must_use]
pub fn read(data: &[u8]) -> Sds<'_> {
    let mut sds = Sds::default();
    let mut seen: HashMap<u32, u64> = HashMap::new();
    let len = data.len();
    let mut block = 0;
    while block < len {
        let block_end = (block + BLOCK_SIZE).min(len);
        let mirror_end = (block_end + BLOCK_SIZE).min(len);
        // the last block's entries end where its mirror ends; past that is not the stream's data
        let used_end = if len >= block + 2 * BLOCK_SIZE {
            block_end
        } else if len > block + BLOCK_SIZE {
            len - BLOCK_SIZE
        } else {
            len
        };
        let mut pos = block;
        while pos < used_end && pos + ENTRY_HEADER_SIZE <= block_end {
            if is_zero(&data[pos..pos + ENTRY_HEADER_SIZE]) {
                // the rest of the block is unused
                break;
            }
            let entry = if let Some(entry) = entry_at(data, pos, pos, block_end, false) {
                let size = entry.size as usize;
                let mirror = pos + BLOCK_SIZE;
                let copy = data.get(mirror..mirror + size);
                let differs = copy.is_some_and(|copy| copy != &data[pos..pos + size]);
                let id = entry.security_id;
                sds.entries.push(entry);
                if differs {
                    match entry_at(data, mirror, pos, mirror_end, true) {
                        Some(copy) => sds.entries.push(copy),
                        None => sds.problems.push(Problem {
                            position: mirror as u64,
                            message: format!(
                                "the mirror copy of security ID {id} differs and is not an entry"
                            ),
                        }),
                    }
                }
                Some((id, size))
            } else if let Some(copy) = entry_at(data, pos + BLOCK_SIZE, pos, mirror_end, true) {
                sds.problems.push(Problem {
                    position: pos as u64,
                    message: format!(
                        "the entry is damaged; its mirror copy at 0x{:x} is read instead",
                        pos + BLOCK_SIZE
                    ),
                });
                let found = (copy.security_id, copy.size as usize);
                sds.entries.push(copy);
                Some(found)
            } else {
                None
            };
            if let Some((id, size)) = entry {
                if let Some(first) = seen.insert(id, pos as u64) {
                    sds.problems.push(Problem {
                        position: pos as u64,
                        message: format!("security ID {id} is already at 0x{first:x}"),
                    });
                }
                pos += size.next_multiple_of(16);
                continue;
            }
            // step over what is not an entry, 16 bytes at a time
            let start = pos;
            pos += 16;
            while pos < used_end
                && pos + ENTRY_HEADER_SIZE <= block_end
                && !is_zero(&data[pos..pos + ENTRY_HEADER_SIZE])
                && entry_at(data, pos, pos, block_end, false).is_none()
            {
                pos += 16;
            }
            let end = pos.min(used_end);
            sds.problems.push(Problem {
                position: start as u64,
                message: format!("0x{start:x} to 0x{end:x} is not an entry"),
            });
        }
        block += 2 * BLOCK_SIZE;
    }
    sds
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// The entry at `at`, if its header is one: a security ID, `offset` as its offset (where the entry
/// is, outside the mirror), and a size that holds a descriptor's header and ends by `limit`.
fn entry_at(
    data: &[u8],
    at: usize,
    offset: usize,
    limit: usize,
    from_mirror: bool,
) -> Option<Entry<'_>> {
    let header = data.get(at..at.checked_add(ENTRY_HEADER_SIZE)?)?;
    let u32_at =
        |i: usize| u32::from_le_bytes([header[i], header[i + 1], header[i + 2], header[i + 3]]);
    let mut recorded = [0u8; 8];
    recorded.copy_from_slice(&header[8..16]);
    let recorded = u64::from_le_bytes(recorded);
    let (hash, security_id, size) = (u32_at(0), u32_at(4), u32_at(16));
    let end = at.checked_add(size as usize)?;
    if security_id == 0
        || recorded != offset as u64
        || (size as usize) < MIN_ENTRY_SIZE
        || end > limit.min(data.len())
    {
        return None;
    }
    Some(Entry {
        position: at as u64,
        hash,
        security_id,
        offset: recorded,
        size,
        descriptor: &data[at + ENTRY_HEADER_SIZE..end],
        from_mirror,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An owner-only descriptor for `rid` (S-1-5-21-1-2-3-rid).
    fn descriptor_for(rid: u32) -> Vec<u8> {
        let mut d = vec![1, 0, 0x00, 0x80, 20, 0, 0, 0];
        d.extend_from_slice(&[0; 12]);
        d.extend_from_slice(&[1, 5, 0, 0, 0, 0, 0, 5]);
        for sub in [21, 1, 2, 3, rid] {
            d.extend_from_slice(&u32::to_le_bytes(sub));
        }
        d
    }

    fn put(stream: &mut Vec<u8>, at: usize, id: u32, rid: u32) -> usize {
        let d = descriptor_for(rid);
        let size = ENTRY_HEADER_SIZE + d.len();
        if stream.len() < at + size {
            stream.resize(at + size, 0);
        }
        stream[at..at + 4].copy_from_slice(&descriptor_hash(&d).to_le_bytes());
        stream[at + 4..at + 8].copy_from_slice(&id.to_le_bytes());
        stream[at + 8..at + 16].copy_from_slice(&(at as u64).to_le_bytes());
        stream[at + 16..at + 20].copy_from_slice(&(size as u32).to_le_bytes());
        stream[at + 20..at + size].copy_from_slice(&d);
        at + size.next_multiple_of(16)
    }

    /// Two blocks of entries with their mirrors; the second mirror ends with its entries, and the
    /// block it mirrors has leftover bytes past them.
    fn stream() -> Vec<u8> {
        let mut s = vec![0u8; 2 * BLOCK_SIZE];
        let mut at = 0;
        for id in 0x100..0x103 {
            at = put(&mut s, at, id, 1000 + id);
        }
        let second = 2 * BLOCK_SIZE;
        let end = put(&mut s, second, 0x103, 500);
        s.resize(second + BLOCK_SIZE, 0);
        s[end..end + 64].fill(0xcc);
        let (primary, mirror) = s.split_at_mut(BLOCK_SIZE);
        mirror[..BLOCK_SIZE].copy_from_slice(&primary[..BLOCK_SIZE]);
        let used = end - 12 - second;
        let copy = s[second..second + used].to_vec();
        s.extend_from_slice(&copy);
        s
    }

    #[test]
    fn entries_of_a_stream() {
        let s = stream();
        assert!(looks_like_sds(&s));
        let sds = read(&s);
        assert_eq!(sds.problems, []);
        let ids: Vec<(u32, u64)> = sds
            .entries
            .iter()
            .map(|e| (e.security_id, e.position))
            .collect();
        assert_eq!(
            ids,
            [(0x100, 0), (0x101, 80), (0x102, 160), (0x103, 0x80000)]
        );
        for entry in &sds.entries {
            assert!(entry.hash_matches());
            assert!(!entry.from_mirror);
            assert_eq!(entry.offset, entry.position);
            assert_eq!(entry.size, 68);
        }
        let sd = sds.entries[3].security_descriptor().unwrap();
        let owner = sd.owner.unwrap().unwrap();
        assert_eq!(owner.to_string(), "S-1-5-21-1-2-3-500");
    }

    #[test]
    fn mirror_copies_and_damage() {
        // the second entry's mirror copy differs; the third entry is damaged, its copy is not
        let mut s = stream();
        s[BLOCK_SIZE + 80 + 60] ^= 0xff;
        s[160 + 8] = 0x77;
        // a hash that is not the descriptor's, in both copies
        s[0] ^= 1;
        s[BLOCK_SIZE] ^= 1;
        let sds = read(&s);
        let found: Vec<(u32, u64, bool, bool)> = sds
            .entries
            .iter()
            .map(|e| (e.security_id, e.position, e.from_mirror, e.hash_matches()))
            .collect();
        assert_eq!(
            found,
            [
                (0x100, 0, false, false),
                (0x101, 80, false, true),
                (0x101, BLOCK_SIZE as u64 + 80, true, false),
                (0x102, BLOCK_SIZE as u64 + 160, true, true),
                (0x103, 0x80000, false, true),
            ]
        );
        assert_eq!(sds.entries[2].offset, 80);
        assert_eq!(
            sds.problems,
            [Problem {
                position: 160,
                message: "the entry is damaged; its mirror copy at 0x400a0 is read instead".into()
            }]
        );
    }

    #[test]
    fn bytes_that_are_not_entries_and_repeated_ids() {
        let mut s = stream();
        // junk between the second and third entries, in both copies; the third entry repeats 0x100
        for base in [0, BLOCK_SIZE] {
            s[base + 80..base + 160].fill(0x5a);
            s[base + 160 + 4..base + 160 + 8].copy_from_slice(&0x100u32.to_le_bytes());
        }
        let sds = read(&s);
        let ids: Vec<u32> = sds.entries.iter().map(|e| e.security_id).collect();
        assert_eq!(ids, [0x100, 0x100, 0x103]);
        let problems: Vec<String> = sds.problems.iter().map(ToString::to_string).collect();
        assert_eq!(
            problems,
            [
                "0x50: 0x50 to 0xa0 is not an entry",
                "0xa0: security ID 256 is already at 0x0",
            ]
        );
    }

    #[test]
    fn short_and_empty_streams() {
        assert_eq!(read(&[]), Sds::default());
        assert!(!looks_like_sds(&[0u8; 64]));
        // an entry header, but not a descriptor
        let mut s = Vec::new();
        put(&mut s, 0, 0x100, 1);
        assert!(looks_like_sds(&s));
        s[ENTRY_HEADER_SIZE + 3] = 0;
        assert!(!looks_like_sds(&s));
        // without its mirror, a block is read to its end
        let mut s = Vec::new();
        put(&mut s, 0, 0x100, 1);
        let sds = read(&s);
        assert_eq!(sds.entries.len(), 1);
        assert_eq!(sds.problems, []);
        // a cut-off entry is not one
        let sds = read(&s[..60]);
        assert_eq!(sds.entries, []);
        assert_eq!(sds.problems.len(), 1);
    }

    #[test]
    fn the_hash() {
        assert_eq!(descriptor_hash(&[]), 0);
        assert_eq!(descriptor_hash(&[1, 0, 0, 0, 1, 0, 0, 0]), 9);
        assert_eq!(descriptor_hash(&[0, 0, 0, 0x80, 0, 0, 0, 0]), 4);
    }
}
