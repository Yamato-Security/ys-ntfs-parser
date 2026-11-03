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

//! `$Secure`: the security descriptors of an NTFS volume.
//!
//! NTFS keeps each distinct security descriptor once, in the `$SDS` stream of `$Secure` (MFT entry
//! 9), and a file's `$STANDARD_INFORMATION` names it by security ID. [`sds::read`] lists the
//! entries of `$SDS`: each security ID with its descriptor, whether the hash recorded with it is
//! the descriptor's, and the mirror copy when it differs. [`SecurityDescriptor::parse`] decodes a
//! self-relative security descriptor (owner, group, DACL, SACL, and SDDL), from `$SDS` or anywhere
//! else, and never fails on what it can read around: each part that cannot be decoded is an
//! `Err` of its own, and each ACE whose payload is not decoded keeps its bytes.
//!
//! ```no_run
//! let data = std::fs::read("$Secure_$SDS")?;
//! let sds = secure::sds::read(&data);
//! for entry in &sds.entries {
//!     let descriptor = entry.security_descriptor()?;
//!     if let Ok(Some(owner)) = &descriptor.owner {
//!         println!("{} {owner} {}", entry.security_id, owner.well_known_name().unwrap_or(""));
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod condition;
pub mod descriptor;
pub mod sds;

pub use descriptor::{Ace, AceData, Acl, Control, Error, Guid, SecurityDescriptor, Sid};
