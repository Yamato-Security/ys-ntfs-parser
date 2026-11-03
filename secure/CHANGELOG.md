# Changelog

## 1.0.0 (Unreleased)

First version.

### Added
- `sds::read`: the entries of `$Secure:$SDS`, with hash checks, mirror copies that differ, damaged
  entries read from their mirror copy, and the bytes that are not entries. (@YamatoSecurity)
- `SecurityDescriptor`: a decoder of self-relative security descriptors (owner, group, control
  flags, DACL, SACL, every ACE layout of MS-DTYP), with SDDL that includes callback ACEs' conditions
  and resource attribute claims, and the names of well-known SIDs. (@YamatoSecurity)
