# secure (ys-ntfs-parser-secure)

The `$Secure` crate of [ys-ntfs-parser](../README.md): the security descriptors of an NTFS volume,
for [Juntei](https://github.com/Yamato-Security/juntei)'s `parse-ntfs secure-sds`. Written by Yamato
Security.

NTFS keeps each distinct security descriptor of a volume once, in the `$SDS` stream of `$Secure`
(MFT entry 9), and a file's `$STANDARD_INFORMATION` names its descriptor by security ID. With
`$SDS`, the `SecurityId` of an `$MFT` entry says who owns the file and who may do what with it. An
attacker's account owning files it dropped, an ACL letting everyone write to a directory, a
descriptor that only one suspicious file uses: all are there. Descriptors usually stay in `$SDS`
after the files that used them are deleted.

- [`sds::read`](src/sds.rs) lists the entries of `$SDS`: each security ID, its descriptor, whether
  the hash recorded with it is the descriptor's, and the copy in the mirror block when it differs.
  It reads the mirror copy of an entry that is damaged, and steps over bytes that are not entries,
  saying where.
- [`SecurityDescriptor::parse`](src/descriptor.rs) decodes a self-relative security descriptor,
  from `$SDS` or elsewhere (the registry, Defender's quarantine): owner, group, control flags, DACL
  and SACL with every ACE. Each part that cannot be decoded is an `Err` of its own, so the rest can
  be shown. `SecurityDescriptor::sddl` writes it in SDDL, callback ACEs' conditions
  (`(WIN://SYSAPPID Contains "…")`, on Windows' own files) and resource attribute claims
  included, or not at all if anything in it is not decoded. `Sid::well_known_name` names the
  well-known SIDs (`NT AUTHORITY\SYSTEM`, `NT SERVICE\TrustedInstaller`, …).

```rust
let data = std::fs::read("$Secure_$SDS")?;
let sds = secure::sds::read(&data);
for entry in &sds.entries {
    let sd = entry.security_descriptor()?;
    if let Ok(Some(owner)) = &sd.owner {
        println!("{} {owner} {:?}", entry.security_id, sd.sddl());
    }
}
for problem in &sds.problems {
    eprintln!("{problem}");
}
```

Use it from Cargo by commit, or as `ys_ntfs_parser::secure` (see [ys-ntfs-parser](../README.md)):

```toml
[dependencies]
secure = { package = "ys-ntfs-parser-secure", git = "https://github.com/Yamato-Security/ys-ntfs-parser" }
```

## Checked against

The five `$SDS` streams of the [DFIR Artifact Museum](https://github.com/AndrewRathbun/DFIRArtifactMuseum)
(Windows 10, 11 and Server 2012 R2: 7,808 descriptors, 60,781 ACEs):

- an independent parser: the same entries, security IDs, hashes, offsets, owners, groups, control
  flags and ACE counts;
- [dissect.ntfs](https://github.com/fox-it/dissect.ntfs): the same owners, groups and control flags,
  and every ACE's type, flags, mask, SID and object types;
- every recorded hash is the descriptor's, every mirror copy is the same as its entry, and every
  descriptor has SDDL. The 3,384 callback ACEs' conditions all decode.

`tests/fixtures/museum-win11` is the Museum's Windows 11 `$SDS` (MIT License, see its `NOTICE`).

## License

Copyright Shirofune Security Co., Ltd., released under the
[Reciprocal Public License 1.5](LICENSE) (RPL-1.5). The test data keeps its license, beside it.
