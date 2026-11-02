# mft (ys-ntfs-parser-mft)

The `$MFT` crate of [ys-ntfs-parser](../README.md): Yamato Security's maintained fork of Omer
Ben-Amram's [mft](https://github.com/omerbenamram/mft) crate, the Windows Master File Table parser
used by [Juntei](https://github.com/Yamato-Security/juntei). It was ys-mft-parser until it moved here. The complete upstream history is retained, and
upstream's code stays under its MIT / Apache-2.0 license (see [License](#license)); everything below
this section is upstream's README.

The fork follows upstream (currently 0.8.0) and adds fixes found while building Juntei, so that
damaged, crafted or partly reused `$MFT` files are parsed correctly instead of crashing the process:

| Change | Source |
| --- | --- |
| A file whose parent directory's record was reused is `[Orphaned]` instead of getting the new owner's path (1,242 entries of DFIRArtifactMuseum's Win10 RathbunVM `$MFT` were placed in the wrong directory) | upstream #150 (mcardonaes), open |
| A deleted file in a deleted directory keeps its path (the parent's sequence number is one ahead) | fork |
| The entry size is probed over the first 4 MiB and checked against the update sequence array, so MFTs whose first entries are wiped still open (upstream probes 64 KiB) | upstream #119 (Joel Uckelman) + fork |
| Huge entry numbers, a data run before LCN 0 and `FlatMftEntryWithName` no longer wrap or panic | fork |
| `ys-ntfs-parser -e` names resident stream files deterministically and sanitizes the stream name (an alternate data stream named `../../x` was written outside the output directory) | fork |
| A parent whose record was reused is still named when its old version left an extension record behind (Harel Segev's "orphaned attributes") | fork |

Paths that can't be fully resolved start with a placeholder, as upstream's do:

- `[Orphaned]`: the parent is gone. The name points at entry 0 or at itself, the parents form a
  cycle (cut at its lowest entry), or the parent's record was reused and its old version left no
  name behind.
- `[Unknown]`: the parent's record can't be read (damaged, or beyond the end of the MFT) or isn't a
  directory.
- No path: the entry has no `$FILE_NAME` and isn't an extension record. Its parent may still
  exist, so it isn't called an orphan.

`tests/test_path_pitfalls.rs` builds an MFT for each of the pitfalls in Harel Segev's
[Resolving File Paths Using the MFT](https://harelsegev.github.io/posts/resolving-file-paths-using-the-mft/).

Use it from Cargo by commit:

```toml
mft = { package = "ys-ntfs-parser-mft", git = "https://github.com/Yamato-Security/ys-ntfs-parser", rev = "<commit>" }
```

or the whole workspace, as `ys_ntfs_parser::mft` (see [ys-ntfs-parser](../README.md)). The library
keeps the name `mft`; the crate is not published to crates.io, and its versions are the fork's own.
See [CHANGELOG.md](CHANGELOG.md). Its command is the workspace's `ys-ntfs-parser` (`../src/main.rs`).


## License

This crate is copyright Shirofune Security Co., Ltd. and released under the [Reciprocal Public
License 1.5](LICENSE) (RPL-1.5); its source code was published under MIT / Apache-2.0 before version
1.0.0. It is changed from [mft](https://github.com/omerbenamram/mft) (copyright Omer
Ben-Amram), whose code stays under the MIT License or the Apache License 2.0 (`LICENSE-MIT`,
`LICENSE-APACHE`): each Rust file changed from it says so in its header.

---

[![Build Status](https://dev.azure.com/benamram/DFIR/_apis/build/status/omerbenamram.mft?branchName=master)](https://dev.azure.com/benamram/DFIR/_build/latest?definitionId=5&branchName=master)
![crates.io](https://img.shields.io/crates/v/mft.svg)

# MFT

This is a parser for the MFT (master file table) format.

MSRV is latest stable rust.

[Documentation](https://docs.rs/mft)

Python bindings are available as well at https://github.com/omerbenamram/pymft-rs (and at PyPi https://pypi.org/project/mft/)

## Features
 - Implemented using 100% safe rust - and works on all platforms supported by rust (that have stdlib).
 - Supports JSON and CSV outputs.
 - Supports extracting resident data streams.
 - Directory indexes (`$I30`, `mft::i30`): the entries of INDX records, and the entries of deleted or renamed files left in their slack (whole, without their header, or without their parent).
- File names left in the slack of FILE records (`MftEntry::slack_file_names`): `$FILE_NAME` attributes and index entries a record had before.

## Installation (associated binary utility):
  - Build from sources using `cargo install --git https://github.com/Yamato-Security/ys-ntfs-parser ys-ntfs-parser`
    (upstream's releases at https://github.com/omerbenamram/mft/releases are upstream's `mft_dump`,
    without this fork's changes)

# `ys-ntfs-parser` (Binary utility):
The binary utility for this crate is `ys-ntfs-parser`, the workspace's command (named after the repository;
upstream's is `mft_dump`), and it provides a quick way to convert mft snapshots to different output formats.

Some examples
  - `ys-ntfs-parser <input_file>` will dump contents of mft entries as JSON.
  - `ys-ntfs-parser -o csv <input_file>` will dump contents of mft entries as CSV.
  - `ys-ntfs-parser --extract-resident-streams <output_directory> -o json <input_file>` will extract all resident streams in MFT to files in <output_directory>.

# Library usage:
```rust,no_run
use mft::MftParser;
use mft::attribute::MftAttributeContent;
use std::path::PathBuf;

fn main() {
    // Change this to a path of your MFT sample.
    let fp = PathBuf::from(format!("{}/samples/MFT", std::env::var("CARGO_MANIFEST_DIR").unwrap()));

    let mut parser = MftParser::from_path(fp).unwrap();
    for entry in parser.iter_entries() {
        match entry {
            Ok(e) =>  {
                for attribute in e.iter_attributes().filter_map(|attr| attr.ok()) {
                    match attribute.data {
                        MftAttributeContent::AttrX10(standard_info) => {
                            println!("\tX10 attribute: {:#?}", standard_info)
                        },
                        MftAttributeContent::AttrX30(filename_attribute) => {
                            println!("\tX30 attribute: {:#?}", filename_attribute)
                        },
                        _ => {
                            println!("\tSome other attribute: {:#?}", attribute)
                        }
                    }

                }
            }
            Err(err) => eprintln!("{}", err),
        }
    }
}
```

## Performance profiling (samply)

The repo ships with a small sample MFT (`samples/MFT`, ~13MB) which makes a good fixed workload.

### Baseline timings (hyperfine)

```bash
cargo build --release --bin ys-ntfs-parser

# End-to-end CLI throughput (write output to /dev/null to avoid terminal overhead).
hyperfine --warmup 3 --runs 20 \
  './target/release/ys-ntfs-parser mft/samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite' \
  './target/release/ys-ntfs-parser mft/samples/MFT -o csv -f /dev/null --no-confirm-overwrite'
```

### CPU profiling (samply)

```bash
cargo build --release --bin ys-ntfs-parser
mkdir -p target/samply

# End-to-end (parsing + serialization) profile.
samply record --save-only --unstable-presymbolicate \
  -o target/samply/ys_mft_parser_jsonl.profile.json.gz \
  --iteration-count 200 -- \
  ./target/release/ys-ntfs-parser mft/samples/MFT -o jsonl -f /dev/null --no-confirm-overwrite

# Parser-only profile (no serialization/output), long single-process run.
# View in the Firefox Profiler UI.
samply load target/samply/ys_mft_parser_jsonl.profile.json.gz
```

In the Firefox Profiler UI:
- Use the **Call Tree** tab with **Invert call stack** to identify top leaf frames.
- Keep **Invert call stack** off to see inclusive hot functions (top-down).
- Use **Filter stack** to focus on crate frames (for example, `mft::` or `ys_ntfs_parser::`).

## Thanks/Resources:
 - https://docs.microsoft.com/en-us/windows/desktop/DevNotes/master-file-table
 - https://github.com/libyal/libfsntfs/blob/master/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc
 - https://github.com/forensicmatt/RustyMft
