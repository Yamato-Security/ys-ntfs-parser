# ys-ntfs-parser

Yamato Security's parsers for NTFS forensic artifacts, used by
[Juntei](https://github.com/Yamato-Security/juntei): the Master File Table, the USN change journal,
the transaction journal, the boot sector and the security descriptors, in one Cargo workspace, with
the `ys-ntfs-parser` command.

| Directory | Crate (library) | What it reads | Came from |
| --- | --- | --- | --- |
| [`mft/`](mft/) | `ys-ntfs-parser-mft` (`mft`) | `$MFT`: entries, attributes and full paths, `$I30` directory indexes and the entries in their slack, the names left in FILE record slack; JSON, CSV and bodyfile output | ys-mft-parser, a fork of Omer Ben-Amram's [mft](https://github.com/omerbenamram/mft) |
| [`usn/`](usn/) | `ys-ntfs-parser-usn` (`usn`) | `$Extend\$UsnJrnl:$J`: every V2, V3 and V4 record, read through sparse zeros and damage, with paths rewound to each record's time (seeded from the `$MFT`) and carving | ys-usn-journal-parser, a fork of [sootmark-usn](https://github.com/Sootmark/usn) |
| [`logfile/`](logfile/) | `ys-ntfs-parser-logfile` (`ntfslog`) | `$LogFile`: restart areas, every log record with its redo and undo operations and targets, and what they say about files (names, times, USN journal writes) | ys-logfile-parser, a fork of [sootmark-ntfslog](https://github.com/Sootmark/ntfslog) |
| [`boot/`](boot/) | `ys-ntfs-parser-boot` (`boot`) | `$Boot`: the volume's sector and cluster sizes, where its `$MFT` and `$MFTMirr` are, its serial number (the one LNK and Prefetch files record), its boot code, and what about it Windows would not mount | Yamato Security |
| [`secure/`](secure/) | `ys-ntfs-parser-secure` (`secure`) | `$Secure:$SDS`: every security descriptor by security ID (owner, group, DACL, SACL, SDDL), with hash and mirror checks; and a decoder of self-relative security descriptors | Yamato Security |
| [`common/`](common/) | `ys-ntfs-parser-common` (`ntfs_common`) | What the usn and logfile crates share: a byte cursor that never panics, UTF-16 decoding that never loses information, and Windows FILETIMEs | [sootmark-common](https://github.com/Sootmark/common)'s byte reader, UTF-16 decoder and time type |
| `.` | `ys-ntfs-parser` (`ys_ntfs_parser`) | The libraries, re-exported, and the `ys-ntfs-parser` command | ys-mft-parser's command |

Each crate's README says what it reads, how it was checked against other parsers and real data, and
what the fork changed from its upstream.

## Use

As a library, without the command:

```toml
[dependencies]
ys-ntfs-parser = { git = "https://github.com/Yamato-Security/ys-ntfs-parser", rev = "<commit>", default-features = false }
```

```rust
use ys_ntfs_parser::{boot, mft, ntfslog, secure, usn};
```

A single crate can be used on its own as well, for example
`usn = { package = "ys-ntfs-parser-usn", git = "https://github.com/Yamato-Security/ys-ntfs-parser", rev = "<commit>" }`.
None of them is published to crates.io. MSRV: Rust 1.99 (edition 2024).

The command reads `$MFT` files and writes their entries as JSON, JSONL, CSV or a bodyfile, and can
extract resident data streams (see [mft/README.md](mft/README.md)):

```sh
cargo install --git https://github.com/Yamato-Security/ys-ntfs-parser ys-ntfs-parser
ys-ntfs-parser -o csv -f mft.csv '$MFT'
```

## Development

```sh
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

CI runs these on Linux, macOS and Windows, the tests on the MSRV, a wasm32 build of the libraries,
cargo-deny (`deny.toml`) and a check that every Rust file carries the license notice. The `$MFT`
parser's fuzz targets are in `mft/fuzz` (cargo-fuzz, with its own workspace).

Each directory keeps its own history and its upstream's, so an upstream's changes can be merged into
its directory:

```sh
git fetch https://github.com/omerbenamram/mft master
git merge -X subtree=mft FETCH_HEAD
```

and likewise `usn` from https://github.com/Sootmark/usn and `logfile` from
https://github.com/Sootmark/ntfslog. Upstream mft's repository also holds disk image crates (`aff`,
`ewf`, `forensic-image`, `dfxml`, `ntfs`), a GUI, their test images and its own tooling, which this
workspace doesn't take: leave them out of such a merge, and move a change to upstream's command
(`src/bin/mft_dump.rs`) to `src/main.rs`.

## License

ys-ntfs-parser is copyright Shirofune Security Co., Ltd. and released under the
[Reciprocal Public License 1.5](LICENSE) (RPL-1.5). The mft, usn, logfile and common crates are changed from
upstream code that stays under the MIT License or the Apache License 2.0: each of their directories
has its upstream's `LICENSE-MIT` and `LICENSE-APACHE`, and each Rust file changed from upstream says
so in its header. The boot and secure crates are Yamato Security's own, under the RPL alone.
The command (`src/main.rs`) and its tests come from Omer Ben-Amram's mft, whose licenses are the
`LICENSE-MIT` and `LICENSE-APACHE` here. The test data keeps its licenses, each beside it in its
crate.
