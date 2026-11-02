// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2019 Omer Ben-Amram
//
// This file is changed from omerbenamram/mft (https://github.com/omerbenamram/mft), whose code is
// under the MIT License or the Apache License 2.0 (LICENSE-MIT, LICENSE-APACHE).
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

//! Snapshot tests for the serialized output of selected sample entries.
//!
//! These guard the JSON and CSV output formats against accidental changes. When a change to the
//! output is intentional, review and accept the new snapshots with `cargo insta review`.
mod fixtures;

use fixtures::*;
use mft::mft::MftParser;

/// Entries chosen to cover different record shapes in `samples/MFT`.
const JSON_ENTRIES: &[(u64, &str)] = &[
    (0, "mft"),
    (3, "volume"),
    (5, "root_directory"),
    (9, "secure"),
    (462, "object_id"),
    (3498, "attribute_list"),
    (8671, "alternate_data_stream"),
    (11600, "deleted"),
];

#[test]
fn test_json_output_snapshots() {
    ensure_env_logger_initialized();
    let mut parser = MftParser::from_path(mft_sample()).unwrap();

    for &(entry_id, name) in JSON_ENTRIES {
        let entry = parser.get_entry(entry_id).unwrap();
        let json = serde_json::to_string_pretty(&entry).unwrap();
        insta::assert_snapshot!(format!("json_entry_{entry_id}_{name}"), json);
    }
}
