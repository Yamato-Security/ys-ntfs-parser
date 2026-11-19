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

//! GUIDs as NTFS stores them: the Windows `GUID` structure, little-endian, in `$OBJECT_ID` and in
//! the header of a reparse point whose tag is not Microsoft's.

use std::fmt;
use std::io::{self, Cursor, Read};

use serde::ser;

/// A Windows `GUID`: `Data1`, `Data2` and `Data3` little-endian, then eight bytes.
///
/// # Example
///
/// ```
/// # use mft::guid::Guid;
/// let raw: &[u8] = &[
///     0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49, 0xa5, 0xba, 0x3e, 0x3b, 0x3, 0x28, 0xc3, 0xd,
/// ];
/// let guid = Guid::from_buffer(raw).unwrap();
/// assert_eq!(guid.to_string(), "54849625-5478-4994-A5BA-3E3B0328C30D");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Guid {
    /// The first 8 hexadecimal digits.
    data1: u32,
    /// The first group of 4 hexadecimal digits.
    data2: u16,
    /// The second group of 4 hexadecimal digits.
    data3: u16,
    /// The third group of 4 hexadecimal digits, then the final 12.
    data4: [u8; 8],
}

impl Guid {
    pub const fn new(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
        Guid {
            data1,
            data2,
            data3,
            data4,
        }
    }

    /// Reads the 16 bytes of a GUID from the start of `buffer`.
    pub fn from_buffer(buffer: &[u8]) -> io::Result<Guid> {
        Self::from_reader(&mut Cursor::new(buffer))
    }

    /// Reads the 16 bytes of a GUID.
    pub fn from_reader<R: Read>(reader: &mut R) -> io::Result<Guid> {
        let mut bytes = [0u8; 16];
        reader.read_exact(&mut bytes)?;
        let mut data4 = [0u8; 8];
        data4.copy_from_slice(&bytes[8..16]);
        Ok(Guid::new(
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u16::from_le_bytes([bytes[4], bytes[5]]),
            u16::from_le_bytes([bytes[6], bytes[7]]),
            data4,
        ))
    }
}

/// The registry format, upper case: `54849625-5478-4994-A5BA-3E3B0328C30D`.
impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

/// A GUID serializes as its string.
impl ser::Serialize for Guid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::Guid;

    const RAW: [u8; 16] = [
        0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49, 0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28, 0xc3,
        0x0d,
    ];

    #[test]
    fn reads_little_endian_fields_and_prints_the_registry_format() {
        let guid = Guid::from_buffer(&RAW).unwrap();
        assert_eq!(
            guid,
            Guid::new(
                0x5484_9625,
                0x5478,
                0x4994,
                [0xa5, 0xba, 0x3e, 0x3b, 0x03, 0x28, 0xc3, 0x0d]
            )
        );
        assert_eq!(guid.to_string(), "54849625-5478-4994-A5BA-3E3B0328C30D");
        assert_eq!(
            serde_json::to_string(&guid).unwrap(),
            "\"54849625-5478-4994-A5BA-3E3B0328C30D\""
        );
    }

    #[test]
    fn a_short_buffer_is_an_error() {
        let error = Guid::from_buffer(&RAW[..15]).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}
