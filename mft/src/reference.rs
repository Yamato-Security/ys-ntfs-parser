// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2019 Omer Ben-Amram
//
// This file is changed from omerbenamram/winstructs (https://github.com/omerbenamram/winstructs),
// whose code is under the MIT License or the Apache License 2.0 (LICENSE-MIT, LICENSE-APACHE).
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

//! File references: the record number and sequence number that NTFS packs into one `u64` wherever
//! a record points at another (a FILE record's base record, a `$FILE_NAME`'s parent directory, an
//! index entry's file, an `$ATTRIBUTE_LIST` entry's record).

use std::io::{self, Read};

use serde::Serialize;

/// A file reference (`MFT_SEGMENT_REFERENCE`): the number of a FILE record, and the sequence
/// number that record had when the reference was written.
#[derive(Serialize, Debug, Hash, Eq, PartialEq, Copy, Clone)]
pub struct MftReference {
    /// The record number: the low 48 bits.
    pub entry: u64,
    /// The sequence number: the high 16 bits.
    pub sequence: u16,
}

impl MftReference {
    pub const fn new(entry: u64, sequence: u16) -> Self {
        MftReference { entry, sequence }
    }

    /// Reads a reference: one little-endian `u64`.
    pub fn from_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut raw = [0u8; 8];
        reader.read_exact(&mut raw)?;
        Ok(Self::from(u64::from_le_bytes(raw)))
    }
}

impl From<u64> for MftReference {
    fn from(raw: u64) -> Self {
        MftReference {
            entry: raw & 0x0000_ffff_ffff_ffff,
            sequence: (raw >> 48) as u16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MftReference;
    use std::io::Cursor;

    #[test]
    fn splits_the_record_number_from_the_sequence() {
        let raw = [0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x91];
        let reference = MftReference::from_reader(&mut Cursor::new(raw)).unwrap();
        assert_eq!(reference, MftReference::new(115, 37224));
        assert_eq!(
            MftReference::from(u64::MAX),
            MftReference::new((1 << 48) - 1, u16::MAX)
        );
        assert_eq!(MftReference::from(0), MftReference::new(0, 0));
    }

    #[test]
    fn a_short_read_is_an_error() {
        let error = MftReference::from_reader(&mut Cursor::new([0u8; 7])).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
