# Changelog

## 1.0.0 (Unreleased)

First version: one workspace for Yamato Security's NTFS parsers. (@YamatoSecurity)

### Added
- ys-mft-parser (`mft/`, with the FILE record slack of its `ys/file-record-slack` branch),
  ys-usn-journal-parser (`usn/`) and ys-logfile-parser (`logfile/`), with their histories and their
  upstreams'. Their crates are now `ys-ntfs-parser-mft`, `ys-ntfs-parser-usn` and
  `ys-ntfs-parser-logfile`; their libraries keep their names (`mft`, `usn`, `ntfslog`), and each
  crate's CHANGELOG goes on. (@YamatoSecurity)
- `ys-ntfs-parser` re-exports the three libraries, and builds the command (feature `cli`, on by
  default): ys-mft-parser's command, named `ys-ntfs-parser`. (@YamatoSecurity)
- `ys-ntfs-parser-common` (`common/`, library `ntfs_common`): the byte cursor, UTF-16 decoding and
  `Filetime` that the usn and logfile crates each had a copy of, so `usn::Filetime` and
  `ntfslog::Filetime` are now the same type. (@YamatoSecurity)
- License: copyright Shirofune Security Co., Ltd., released under the Reciprocal Public License 1.5
  (RPL-1.5). Upstream's code stays under MIT OR Apache-2.0. (@YamatoSecurity)
