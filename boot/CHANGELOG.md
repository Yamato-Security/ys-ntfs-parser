# Changelog

## 1.0.0 (Unreleased)

First version.

### Added
- `BootSector`: the NTFS boot sector's fields, and what they mean: sector and cluster sizes
  (clusters over 64 KiB included), the volume's size, where the `$MFT` and `$MFTMirr` start, FILE and
  INDX record sizes, and the 64-bit and 32-bit volume serial numbers. `BootSector::problems`: what
  Windows would not mount. `boot_code`: the boot code, to hash and compare across hosts.
  (@YamatoSecurity)
