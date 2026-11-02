# Changelog

## 1.0.0 (Unreleased)

First version: one workspace for Yamato Security's NTFS parsers. (@YamatoSecurity)

### Fixed
- The command refuses to overwrite its input, including hard-link and symlink aliases, even with
  `--no-confirm-overwrite`. Resident stream extraction creates files exclusively and does not follow
  pre-existing dangling symlinks. Invalid range options are rejected before touching an existing
  export. (@YamatoSecurity)
- Final buffered write/flush failures propagate in CSV, JSON, JSONL and bodyfile exports, preventing
  a successful exit for incomplete output. (@YamatoSecurity)
- Subcrate package include lists retain their RPL license text alongside upstream licenses. (@YamatoSecurity)

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
