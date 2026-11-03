# boot (ys-ntfs-parser-boot)

The `$Boot` crate of [ys-ntfs-parser](../README.md): the NTFS boot sector, for
[Juntei](https://github.com/Yamato-Security/juntei)'s `parse-ntfs boot`. Written by Yamato Security.

The first sector of an NTFS volume (and of its `$Boot` file, the volume's first 8 KiB) holds the
BIOS parameter block:

- the sector and cluster sizes, the volume's size, and the sectors before it on the disk (where
  its partition starts);
- where the `$MFT` and `$MFTMirr` start, and the sizes of FILE and INDX records, needed to read the
  `$MFT` and directory indexes of an image;
- the 64-bit volume serial number. Its low 32 bits are what Windows shows as `XXXX-XXXX`, and what
  LNK files, Jump Lists and Prefetch files record of the volume a file was on, so they tie those
  artifacts to this volume.

The rest of `$Boot` is the boot code. It is the same on volumes formatted by the same Windows: it is
byte for byte the same on the five Windows 10, 11 and Server 2012 R2 `$Boot` files of the DFIR
Artifact Museum. A volume boot record bootkit changes it (or the hidden sectors field), so
[`boot_code`](src/lib.rs) hashed and compared across hosts is worth a look.

```rust
let data = std::fs::read("$Boot")?;
let boot = boot::BootSector::parse(&data)?;
println!(
    "serial {:08X}, $MFT at byte {:?}, clusters of {:?} bytes",
    boot.volume_serial_number(),
    boot.mft_offset(),
    boot.cluster_size()
);
for problem in boot.problems() {
    eprintln!("{problem}");
}
```

`BootSector::parse` reads any 512 bytes, from `$Boot`, a volume, or a volume image.
`BootSector::problems` says what about them Windows would not mount: an OEM ID other than `NTFS`,
no `55 AA` signature, sector or cluster sizes that are not powers of two, FAT fields NTFS keeps at
zero that are not, record sizes out of range, and the `$MFT` or `$MFTMirr` past the end of the
volume. Damaged and carved sectors are read all the same.

Use it from Cargo by commit, or as `ys_ntfs_parser::boot` (see [ys-ntfs-parser](../README.md)):

```toml
[dependencies]
boot = { package = "ys-ntfs-parser-boot", git = "https://github.com/Yamato-Security/ys-ntfs-parser" }
```

## Checked against

- The five `$Boot` files of the [DFIR Artifact Museum](https://github.com/AndrewRathbun/DFIRArtifactMuseum)
  (Windows 10, 11 and Server 2012 R2): every field the same as an independent parser's.
- Volumes made by `mkntfs` with 512-, 1024- and 4096-byte sectors and 4 KiB to 64 KiB clusters: the
  same sizes, `$MFT` and `$MFTMirr` clusters and serial number as The Sleuth Kit's `fsstat`.
- Clusters over 64 KiB (sectors per cluster recorded as a power of two), which `mkntfs` does not
  make, in unit tests.

`tests/fixtures/museum-win11` is the Museum's Windows 11 `$Boot` (MIT License, see its `NOTICE`).

## License

Copyright Shirofune Security Co., Ltd., released under the
[Reciprocal Public License 1.5](LICENSE) (RPL-1.5). The test data keeps its license, beside it.
