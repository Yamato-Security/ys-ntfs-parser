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

//! Yamato Security's parsers for NTFS forensic artifacts, used by
//! [Juntei](https://github.com/Yamato-Security/juntei):
//!
//! | Module | Artifact | Crate |
//! | --- | --- | --- |
//! | [`mft`] | The Master File Table (`$MFT`): entries, attributes, full paths, `$I30` directory indexes and the names left in FILE record slack | `ys-ntfs-parser-mft` (`mft/`) |
//! | [`usn`] | The USN change journal (`$Extend\$UsnJrnl:$J`): every V2, V3 and V4 record, paths rewound to each record's time (seeded from the `$MFT`) and carving | `ys-ntfs-parser-usn` (`usn/`) |
//! | [`ntfslog`] | The transaction journal (`$LogFile`): restart areas, log records with their redo and undo operations, and what they say about files | `ys-ntfs-parser-logfile` (`logfile/`) |
//! | [`boot`] | The boot sector (`$Boot`): the volume's geometry, where its `$MFT` is, its serial number, its boot code, and whether Windows would mount it | `ys-ntfs-parser-boot` (`boot/`) |
//!
//! Each module is its crate, re-exported: `ys_ntfs_parser::mft::MftParser` is `mft::MftParser`.
//! The `ys-ntfs-parser` command (feature `cli`, on by default) reads `$MFT` files; libraries
//! depend on this crate with `default-features = false`.

pub use boot;
pub use mft;
pub use ntfslog;
pub use usn;
