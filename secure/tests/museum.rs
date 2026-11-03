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

//! A Windows 11 `$Secure:$SDS` from the DFIR Artifact Museum (see
//! `fixtures/museum-win11/NOTICE`). Every entry was compared with an independent parser and with
//! dissect.ntfs: security IDs, hashes, offsets, owners, groups, control flags and every ACE.

use flate2::read::GzDecoder;
use secure::Acl;
use std::collections::HashMap;
use std::io::Read;

fn sds() -> Vec<u8> {
    let gz = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/museum-win11/SDS.gz"
    ))
    .unwrap();
    let mut data = Vec::new();
    GzDecoder::new(gz.as_slice())
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn a_windows_11_sds() {
    let data = sds();
    assert_eq!(data.len(), 1_473_492);
    assert!(secure::sds::looks_like_sds(&data));
    let sds = secure::sds::read(&data);
    // the bytes past the last block's mirrored entries are not reported
    assert_eq!(sds.problems, []);
    assert_eq!(sds.entries.len(), 1716);
    assert_eq!(sds.entries[0].security_id, secure::sds::FIRST_SECURITY_ID);
    let last = sds.entries.last().unwrap();
    assert_eq!((last.security_id, last.position), (1971, 1_211_168));

    let mut owners: HashMap<String, usize> = HashMap::new();
    let (mut sacls, mut callbacks, mut trust_labels, mut resource_attributes) = (0, 0, 0, 0);
    for entry in &sds.entries {
        assert!(entry.hash_matches(), "security ID {}", entry.security_id);
        assert!(!entry.from_mirror);
        assert_eq!(entry.offset, entry.position);
        let sd = entry.security_descriptor().unwrap();
        assert_eq!(sd.problems(), Vec::<String>::new());
        // every descriptor, conditions and claims included, has SDDL
        let sddl = sd.sddl().unwrap();
        callbacks += usize::from(sddl.contains("(XA;"));
        trust_labels += usize::from(sddl.contains("(TL;"));
        resource_attributes += usize::from(sddl.contains("(RA;"));
        if let Ok(Some(owner)) = &sd.owner {
            *owners.entry(owner.to_string()).or_default() += 1;
        }
        sacls += usize::from(matches!(sd.sacl, Ok(Acl::Entries { .. })));
    }
    assert_eq!(owners["S-1-5-18"], 761);
    assert_eq!(owners["S-1-5-32-544"], 593);
    assert_eq!(owners["S-1-5-21-4063860464-1508573791-632671957-1001"], 215);
    assert_eq!(
        (sacls, callbacks, trust_labels, resource_attributes),
        (578, 789, 399, 2)
    );

    let first = sds.entries[0].security_descriptor().unwrap();
    assert_eq!(
        first.sddl().unwrap(),
        "O:S-1-5-18G:S-1-5-32-544D:(A;;0x00120089;;;S-1-5-18)(A;;0x00120089;;;S-1-5-32-544)"
    );
    let claim = sds.entries.iter().find(|e| e.security_id == 1695).unwrap();
    let sddl = claim.security_descriptor().unwrap().sddl().unwrap();
    assert!(sddl.ends_with("S:AI(RA;OICIIO;0x00000000;;;S-1-1-0;(\"IMAGELOAD\",TU,0x0,1))"));
}

#[test]
fn a_damaged_copy_of_it() {
    let mut data = sds();
    // the first entry's offset field, and the second entry's mirror copy
    data[8] ^= 0xff;
    data[secure::sds::BLOCK_SIZE + 128 + 40] ^= 0xff;
    let sds = secure::sds::read(&data);
    assert_eq!(sds.entries.len(), 1717);
    assert!(sds.entries[0].from_mirror);
    assert!(sds.entries[0].hash_matches());
    assert!(!sds.entries[1].from_mirror);
    assert!(sds.entries[2].from_mirror);
    assert!(!sds.entries[2].hash_matches());
    assert_eq!(
        sds.problems[0].to_string(),
        "0x0: the entry is damaged; its mirror copy at 0x40000 is read instead"
    );
}
