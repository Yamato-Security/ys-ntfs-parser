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

//! A Windows 11 `$Boot` from the DFIR Artifact Museum (see `fixtures/museum-win11/NOTICE`).

use boot::{BOOT_FILE_SIZE, BootSector, boot_code};

#[test]
fn a_windows_11_boot_file() {
    let data = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/museum-win11/Boot"
    ))
    .unwrap();
    assert_eq!(data.len(), BOOT_FILE_SIZE);
    let boot = BootSector::parse(&data).unwrap();
    assert_eq!(boot.jump, [0xeb, 0x52, 0x90]);
    assert_eq!(boot.oem_id_text(), "NTFS    ");
    assert_eq!(boot.sector_size(), Some(512));
    assert_eq!(boot.cluster_size(), Some(4096));
    assert_eq!(boot.total_sectors, 124_370_943);
    assert_eq!(boot.volume_size(), Some(63_677_922_816));
    assert_eq!(boot.mft_cluster, 786_432);
    assert_eq!(boot.mft_offset(), Some(3_221_225_472));
    assert_eq!(boot.mft_mirror_cluster, 2);
    assert_eq!(boot.file_record_size(), Some(1024));
    assert_eq!(boot.index_record_size(), Some(4096));
    assert_eq!(boot.hidden_sectors, 239_616);
    assert_eq!(boot.serial_number, 0xea18_0b53_180b_1e67);
    assert_eq!(boot.volume_serial_number(), 0x180b_1e67);
    assert_eq!(boot.problems(), []);
    let [sector, loader] = boot_code(&data);
    assert_eq!((sector.len(), loader.len()), (426, 7680));
}
