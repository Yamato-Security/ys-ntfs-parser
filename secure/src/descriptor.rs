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

//! Self-relative security descriptors, as `$SDS`, the registry and Defender's quarantine keep them
//! ([MS-DTYP] 2.4.6): the owner, the primary group, and the ACLs, decoded with bounds checks and
//! without Windows APIs. Accounts are SIDs; only well-known SIDs have names.
//!
//! [MS-DTYP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/

use std::fmt::{self, Write as _};

/// Why a security descriptor, or a part of one, could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// The size of a self-relative security descriptor's header.
pub const HEADER_SIZE: usize = 20;

/// A security descriptor's control flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Control(pub u16);

impl Control {
    /// The owner was set by default.
    pub const OWNER_DEFAULTED: u16 = 0x0001;
    /// The group was set by default.
    pub const GROUP_DEFAULTED: u16 = 0x0002;
    /// There is a DACL (if its offset is zero, a NULL DACL: no restriction).
    pub const DACL_PRESENT: u16 = 0x0004;
    /// The DACL was set by default.
    pub const DACL_DEFAULTED: u16 = 0x0008;
    /// There is a SACL.
    pub const SACL_PRESENT: u16 = 0x0010;
    /// The SACL was set by default.
    pub const SACL_DEFAULTED: u16 = 0x0020;
    /// The DACL is protected from inheritable ACEs of the parent.
    pub const DACL_PROTECTED: u16 = 0x1000;
    /// The SACL is protected from inheritable ACEs of the parent.
    pub const SACL_PROTECTED: u16 = 0x2000;
    /// The resource manager control byte is valid.
    pub const RM_CONTROL_VALID: u16 = 0x4000;
    /// The descriptor is self-relative: its parts are at offsets in it.
    pub const SELF_RELATIVE: u16 = 0x8000;

    /// Whether every bit of `flags` is set.
    #[must_use]
    pub const fn contains(self, flags: u16) -> bool {
        self.0 & flags == flags
    }

    /// The names of the flags set (`SE_DACL_PRESENT`, …), in bit order.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        CONTROL_FLAGS
            .iter()
            .filter(|(bit, _)| self.0 & bit != 0)
            .map(|(_, name)| *name)
            .collect()
    }
}

const CONTROL_FLAGS: [(u16, &str); 16] = [
    (0x0001, "SE_OWNER_DEFAULTED"),
    (0x0002, "SE_GROUP_DEFAULTED"),
    (0x0004, "SE_DACL_PRESENT"),
    (0x0008, "SE_DACL_DEFAULTED"),
    (0x0010, "SE_SACL_PRESENT"),
    (0x0020, "SE_SACL_DEFAULTED"),
    (0x0040, "SE_DACL_UNTRUSTED"),
    (0x0080, "SE_SERVER_SECURITY"),
    (0x0100, "SE_DACL_AUTO_INHERIT_REQ"),
    (0x0200, "SE_SACL_AUTO_INHERIT_REQ"),
    (0x0400, "SE_DACL_AUTO_INHERITED"),
    (0x0800, "SE_SACL_AUTO_INHERITED"),
    (0x1000, "SE_DACL_PROTECTED"),
    (0x2000, "SE_SACL_PROTECTED"),
    (0x4000, "SE_RM_CONTROL_VALID"),
    (0x8000, "SE_SELF_RELATIVE"),
];

/// A security identifier: an account, a group, a capability or an integrity level.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sid {
    /// The revision (1).
    pub revision: u8,
    /// The identifier authority (48 bits): 5 for `NT AUTHORITY`, 16 for integrity levels, …
    pub authority: u64,
    /// The subauthorities; the last of an account's is its RID.
    pub sub_authorities: Vec<u32>,
}

impl Sid {
    /// Read the SID at the start of `bytes`.
    ///
    /// # Errors
    ///
    /// If its revision is not 1, it has more than 15 subauthorities, or `bytes` ends inside it.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let header = bytes
            .get(..8)
            .ok_or_else(|| Error::new("the SID is cut off in its header"))?;
        if header[0] != 1 || header[1] > 15 {
            return Err(Error::new(format!(
                "SID revision {} with {} subauthorities is not a SID",
                header[0], header[1]
            )));
        }
        let size = 8 + usize::from(header[1]) * 4;
        let body = bytes
            .get(8..size)
            .ok_or_else(|| Error::new("the SID's subauthorities are cut off"))?;
        Ok(Self {
            revision: header[0],
            authority: header[2..8]
                .iter()
                .fold(0u64, |a, &b| (a << 8) | u64::from(b)),
            sub_authorities: body
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_le_bytes(*c))
                .collect(),
        })
    }

    /// Its size in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        8 + self.sub_authorities.len() * 4
    }

    /// The name Windows gives a well-known SID (`NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`,
    /// `NT SERVICE\TrustedInstaller`, …), and the built-in accounts of a machine or domain
    /// (`Administrator`, `Guest`, `Domain Admins`, …). `None` for other accounts, whose names only
    /// the host that made them knows.
    #[must_use]
    pub fn well_known_name(&self) -> Option<&'static str> {
        let s = self.sub_authorities.as_slice();
        Some(match (self.authority, s) {
            (0, [0]) => "NULL SID",
            (1, [0]) => "Everyone",
            (2, [0]) => "LOCAL",
            (2, [1]) => "CONSOLE LOGON",
            (3, [0]) => "CREATOR OWNER",
            (3, [1]) => "CREATOR GROUP",
            (3, [2]) => "CREATOR OWNER SERVER",
            (3, [3]) => "CREATOR GROUP SERVER",
            (3, [4]) => "OWNER RIGHTS",
            (5, [1]) => "NT AUTHORITY\\DIALUP",
            (5, [2]) => "NT AUTHORITY\\NETWORK",
            (5, [3]) => "NT AUTHORITY\\BATCH",
            (5, [4]) => "NT AUTHORITY\\INTERACTIVE",
            (5, [6]) => "NT AUTHORITY\\SERVICE",
            (5, [7]) => "NT AUTHORITY\\ANONYMOUS LOGON",
            (5, [8]) => "NT AUTHORITY\\PROXY",
            (5, [9]) => "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS",
            (5, [10]) => "NT AUTHORITY\\SELF",
            (5, [11]) => "NT AUTHORITY\\Authenticated Users",
            (5, [12]) => "NT AUTHORITY\\RESTRICTED",
            (5, [13]) => "NT AUTHORITY\\TERMINAL SERVER USER",
            (5, [14]) => "NT AUTHORITY\\REMOTE INTERACTIVE LOGON",
            (5, [15]) => "NT AUTHORITY\\This Organization",
            (5, [17]) => "NT AUTHORITY\\IUSR",
            (5, [18]) => "NT AUTHORITY\\SYSTEM",
            (5, [19]) => "NT AUTHORITY\\LOCAL SERVICE",
            (5, [20]) => "NT AUTHORITY\\NETWORK SERVICE",
            (5, [32, rid]) => builtin(*rid)?,
            (5, [33]) => "NT AUTHORITY\\WRITE RESTRICTED",
            (5, [80, 0]) => "NT SERVICE\\ALL SERVICES",
            (
                5,
                [
                    80,
                    956_008_885,
                    3_418_522_649,
                    1_831_038_044,
                    1_853_292_631,
                    2_271_478_464,
                ],
            ) => "NT SERVICE\\TrustedInstaller",
            (5, [83, 0]) => "NT VIRTUAL MACHINE\\Virtual Machines",
            (5, [84, 0, 0, 0, 0, 0]) => "NT AUTHORITY\\USER MODE DRIVERS",
            (5, [113]) => "NT AUTHORITY\\Local account",
            (5, [114]) => "NT AUTHORITY\\Local account and member of Administrators group",
            (5, [21, _, _, _, rid]) => account(*rid)?,
            (15, [2, 1]) => "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES",
            (15, [2, 2]) => "APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES",
            (16, [0]) => "Mandatory Label\\Untrusted Mandatory Level",
            (16, [4096]) => "Mandatory Label\\Low Mandatory Level",
            (16, [8192]) => "Mandatory Label\\Medium Mandatory Level",
            (16, [8448]) => "Mandatory Label\\Medium Plus Mandatory Level",
            (16, [12288]) => "Mandatory Label\\High Mandatory Level",
            (16, [16384]) => "Mandatory Label\\System Mandatory Level",
            (16, [20480]) => "Mandatory Label\\Protected Process Mandatory Level",
            _ => return None,
        })
    }
}

/// `BUILTIN` groups (S-1-5-32-RID).
fn builtin(rid: u32) -> Option<&'static str> {
    Some(match rid {
        544 => "BUILTIN\\Administrators",
        545 => "BUILTIN\\Users",
        546 => "BUILTIN\\Guests",
        547 => "BUILTIN\\Power Users",
        548 => "BUILTIN\\Account Operators",
        549 => "BUILTIN\\Server Operators",
        550 => "BUILTIN\\Print Operators",
        551 => "BUILTIN\\Backup Operators",
        552 => "BUILTIN\\Replicator",
        554 => "BUILTIN\\Pre-Windows 2000 Compatible Access",
        555 => "BUILTIN\\Remote Desktop Users",
        556 => "BUILTIN\\Network Configuration Operators",
        558 => "BUILTIN\\Performance Monitor Users",
        559 => "BUILTIN\\Performance Log Users",
        560 => "BUILTIN\\Windows Authorization Access Group",
        562 => "BUILTIN\\Distributed COM Users",
        568 => "BUILTIN\\IIS_IUSRS",
        569 => "BUILTIN\\Cryptographic Operators",
        573 => "BUILTIN\\Event Log Readers",
        574 => "BUILTIN\\Certificate Service DCOM Access",
        575 => "BUILTIN\\RDS Remote Access Servers",
        576 => "BUILTIN\\RDS Endpoint Servers",
        577 => "BUILTIN\\RDS Management Servers",
        578 => "BUILTIN\\Hyper-V Administrators",
        579 => "BUILTIN\\Access Control Assistance Operators",
        580 => "BUILTIN\\Remote Management Users",
        582 => "BUILTIN\\Storage Replica Administrators",
        583 => "BUILTIN\\Device Owners",
        _ => return None,
    })
}

/// The built-in accounts and groups of a machine or domain (S-1-5-21-…-RID) that have the same
/// name on every host. RID 513 is left out: "Domain Users" in a domain, "None" on a workstation.
fn account(rid: u32) -> Option<&'static str> {
    Some(match rid {
        500 => "Administrator",
        501 => "Guest",
        502 => "krbtgt",
        503 => "DefaultAccount",
        504 => "WDAGUtilityAccount",
        512 => "Domain Admins",
        514 => "Domain Guests",
        515 => "Domain Computers",
        516 => "Domain Controllers",
        518 => "Schema Admins",
        519 => "Enterprise Admins",
        520 => "Group Policy Creator Owners",
        _ => return None,
    })
}

impl fmt::Display for Sid {
    /// `S-1-5-18`; an authority of 2^32 or more in hexadecimal, as Windows writes it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-{}-", self.revision)?;
        if u32::try_from(self.authority).is_ok() {
            write!(f, "{}", self.authority)?;
        } else {
            write!(f, "0x{:012x}", self.authority)?;
        }
        for sub in &self.sub_authorities {
            write!(f, "-{sub}")?;
        }
        Ok(())
    }
}

/// A GUID, as an object ACE names an object type with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Guid(pub [u8; 16]);

impl fmt::Display for Guid {
    /// `bf967aba-0de6-11d0-a285-00aa003049e2`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9]
        )?;
        b[10..].iter().try_for_each(|x| write!(f, "{x:02x}"))
    }
}

/// A DACL or a SACL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Acl<'a> {
    /// The descriptor has none: its control flag (`SE_DACL_PRESENT`, `SE_SACL_PRESENT`) is not set.
    Absent,
    /// A NULL ACL: the flag is set, but no ACL is recorded. A NULL DACL restricts no access.
    Null,
    /// An ACL and its entries, in order. A DACL without entries grants no access.
    Entries {
        /// The ACL revision: 2, or 4 if it may hold object ACEs.
        revision: u8,
        /// The entries.
        aces: Vec<Ace<'a>>,
    },
}

impl<'a> Acl<'a> {
    /// The entries (none if absent or NULL).
    #[must_use]
    pub fn aces(&self) -> &[Ace<'a>] {
        match self {
            Acl::Entries { aces, .. } => aces,
            Acl::Absent | Acl::Null => &[],
        }
    }
}

/// An access control entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace<'a> {
    /// The ACE type: 0 access allowed, 1 access denied, 2 system audit, 17 mandatory label, …
    pub ace_type: u8,
    /// The ACE flags: inheritance (`OI`, `CI`, `NP`, `IO`, `ID`) and audit (`SA`, `FA`).
    pub flags: u8,
    /// The whole ACE, header included.
    pub raw: &'a [u8],
    /// The access mask and the account, and the object types of an object ACE. `None` for a type
    /// whose layout is not known (compound ACEs, types past 0x15) or an object ACE with unknown
    /// flags: their bytes are in `raw`.
    pub data: Option<AceData<'a>>,
}

/// What an ACE says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AceData<'a> {
    /// The access mask.
    pub mask: u32,
    /// The account it applies to.
    pub sid: Sid,
    /// An object ACE's object type.
    pub object_type: Option<Guid>,
    /// An object ACE's inherited object type.
    pub inherited_object_type: Option<Guid>,
    /// What follows the SID: a callback ACE's condition, a resource attribute, … Empty for the
    /// ACEs of files.
    pub application_data: &'a [u8],
}

const ACE_FLAGS: [(u8, &str); 8] = [
    (0x01, "OI"),
    (0x02, "CI"),
    (0x04, "NP"),
    (0x08, "IO"),
    (0x10, "ID"),
    (0x20, "CR"),
    (0x40, "SA"),
    (0x80, "FA"),
];

/// Types with a mask, then a SID.
const fn standard_layout(ace_type: u8) -> bool {
    matches!(ace_type, 0..=3 | 9 | 10 | 13 | 14 | 17..=21)
}

/// Types with a mask, object flags and up to two GUIDs, then a SID.
const fn object_layout(ace_type: u8) -> bool {
    matches!(ace_type, 5..=8 | 11 | 12 | 15 | 16)
}

impl Ace<'_> {
    /// The type's name in [MS-DTYP] without `_ACE_TYPE`: `ACCESS_ALLOWED`, `SYSTEM_AUDIT`, …
    ///
    /// [MS-DTYP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self.ace_type {
            0 => "ACCESS_ALLOWED",
            1 => "ACCESS_DENIED",
            2 => "SYSTEM_AUDIT",
            3 => "SYSTEM_ALARM",
            4 => "ACCESS_ALLOWED_COMPOUND",
            5 => "ACCESS_ALLOWED_OBJECT",
            6 => "ACCESS_DENIED_OBJECT",
            7 => "SYSTEM_AUDIT_OBJECT",
            8 => "SYSTEM_ALARM_OBJECT",
            9 => "ACCESS_ALLOWED_CALLBACK",
            10 => "ACCESS_DENIED_CALLBACK",
            11 => "ACCESS_ALLOWED_CALLBACK_OBJECT",
            12 => "ACCESS_DENIED_CALLBACK_OBJECT",
            13 => "SYSTEM_AUDIT_CALLBACK",
            14 => "SYSTEM_ALARM_CALLBACK",
            15 => "SYSTEM_AUDIT_CALLBACK_OBJECT",
            16 => "SYSTEM_ALARM_CALLBACK_OBJECT",
            17 => "SYSTEM_MANDATORY_LABEL",
            18 => "SYSTEM_RESOURCE_ATTRIBUTE",
            19 => "SYSTEM_SCOPED_POLICY_ID",
            20 => "SYSTEM_PROCESS_TRUST_LABEL",
            21 => "SYSTEM_ACCESS_FILTER",
            _ => "UNKNOWN",
        }
    }

    /// The type's SDDL token: `A`, `D`, `AU`, `AL`, `OA`, `OD`, `OU`, `OL`, `ML`, the callback
    /// ACEs' `XA`, `XD`, `ZA`, `XU`, and `RA`, `SP`, `TL`.
    #[must_use]
    pub fn sddl_type(&self) -> Option<&'static str> {
        Some(match self.ace_type {
            0 => "A",
            1 => "D",
            2 => "AU",
            3 => "AL",
            5 => "OA",
            6 => "OD",
            7 => "OU",
            8 => "OL",
            9 => "XA",
            10 => "XD",
            11 => "ZA",
            13 => "XU",
            17 => "ML",
            18 => "RA",
            19 => "SP",
            20 => "TL",
            _ => return None,
        })
    }

    /// A callback ACE's condition in SDDL, such as
    /// `(WIN://SYSAPPID Contains "Microsoft.WindowsStore_8wekyb3d8bbwe")`. `None` for other ACEs,
    /// or if its application data is not a conditional expression.
    #[must_use]
    pub fn condition(&self) -> Option<String> {
        let data = self
            .data
            .as_ref()
            .filter(|_| matches!(self.ace_type, 9..=16))?;
        crate::condition::expression(data.application_data)
    }

    /// A resource attribute ACE's claim in SDDL, such as `("IMAGELOAD",TU,0x0,1)`. `None` for
    /// other ACEs, or if its application data is not a claim.
    #[must_use]
    pub fn resource_attribute(&self) -> Option<String> {
        let data = self.data.as_ref().filter(|_| self.ace_type == 18)?;
        crate::condition::resource_attribute(data.application_data)
    }

    /// The SDDL tokens of the flags set (`OI`, `CI`, `ID`, …), in bit order.
    #[must_use]
    pub fn flag_names(&self) -> Vec<&'static str> {
        ACE_FLAGS
            .iter()
            .filter(|(bit, _)| self.flags & bit != 0)
            .map(|(_, name)| *name)
            .collect()
    }

    /// The ACE in SDDL: `(A;OICIID;0x001f01ff;;;S-1-5-18)`, with a callback ACE's condition or a
    /// resource attribute ACE's claim after the SID. `None` if it is not decoded, is of a type
    /// without an SDDL token, or has application data that is not decoded.
    #[must_use]
    pub fn sddl(&self) -> Option<String> {
        let data = self.data.as_ref()?;
        let token = self.sddl_type()?;
        let extra = match self.ace_type {
            9..=16 => Some(self.condition()?),
            18 => Some(self.resource_attribute()?),
            _ if data.application_data.is_empty() => None,
            _ => return None,
        };
        let guid = |g: Option<Guid>| g.map(|g| g.to_string()).unwrap_or_default();
        let mut sddl = format!(
            "({token};{};0x{:08x};{};{};{}",
            self.flag_names().concat(),
            data.mask,
            guid(data.object_type),
            guid(data.inherited_object_type),
            data.sid
        );
        if let Some(extra) = extra {
            sddl.push(';');
            sddl.push_str(&extra);
        }
        sddl.push(')');
        Some(sddl)
    }
}

/// A self-relative security descriptor. Each part that could not be decoded is an `Err` of its
/// own, so the others can still be shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityDescriptor<'a> {
    /// The revision (1).
    pub revision: u8,
    /// The resource manager control byte (`Sbz1`), meaningful with `SE_RM_CONTROL_VALID`.
    pub resource_manager_control: u8,
    /// The control flags.
    pub control: Control,
    /// The owner, or `None` if not recorded.
    pub owner: Result<Option<Sid>, Error>,
    /// The primary group, or `None` if not recorded.
    pub group: Result<Option<Sid>, Error>,
    /// The system ACL: auditing and the mandatory integrity label.
    pub sacl: Result<Acl<'a>, Error>,
    /// The discretionary ACL: who may do what.
    pub dacl: Result<Acl<'a>, Error>,
}

impl<'a> SecurityDescriptor<'a> {
    /// Decode the self-relative security descriptor at the start of `bytes`. Fails only if its
    /// header cannot be read.
    ///
    /// # Errors
    ///
    /// If `bytes` is shorter than 20 bytes, the revision is not 1, or the descriptor is not
    /// self-relative.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let header = bytes.get(..HEADER_SIZE).ok_or_else(|| {
            Error::new(format!(
                "the descriptor is {} bytes, shorter than its {HEADER_SIZE}-byte header",
                bytes.len()
            ))
        })?;
        if header[0] != 1 {
            return Err(Error::new(format!(
                "descriptor revision {} is not 1",
                header[0]
            )));
        }
        let control = Control(u16::from_le_bytes([header[2], header[3]]));
        if !control.contains(Control::SELF_RELATIVE) {
            return Err(Error::new(
                "the descriptor is not self-relative: its parts are pointers in the memory of the \
                 process that made it",
            ));
        }
        let offset = |at: usize| {
            u32::from_le_bytes([header[at], header[at + 1], header[at + 2], header[at + 3]])
        };
        Ok(Self {
            revision: header[0],
            resource_manager_control: header[1],
            control,
            owner: optional_sid(bytes, offset(4)),
            group: optional_sid(bytes, offset(8)),
            sacl: acl(bytes, control.contains(Control::SACL_PRESENT), offset(12)),
            dacl: acl(bytes, control.contains(Control::DACL_PRESENT), offset(16)),
        })
    }

    /// What could not be decoded: the parts that are `Err`, and the ACEs without
    /// [`Ace::data`]. Empty if the whole descriptor is decoded.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for (name, sid) in [("owner", &self.owner), ("group", &self.group)] {
            if let Err(e) = sid {
                problems.push(format!("{name}: {e}"));
            }
        }
        for (name, acl) in [("DACL", &self.dacl), ("SACL", &self.sacl)] {
            match acl {
                Err(e) => problems.push(format!("{name}: {e}")),
                Ok(acl) => {
                    for (i, ace) in acl.aces().iter().enumerate() {
                        if ace.data.is_none() {
                            problems.push(format!(
                                "{name} entry {}: {} ACE (type 0x{:02x}) not decoded",
                                i + 1,
                                ace.type_name(),
                                ace.ace_type
                            ));
                        }
                    }
                }
            }
        }
        problems
    }

    /// The descriptor in SDDL, with SIDs (not aliases) and masks in hexadecimal:
    /// `O:S-1-5-18G:S-1-5-18D:PAI(A;OICI;0x001f01ff;;;S-1-5-18)`. `None` if a part is not decoded,
    /// or an ACE cannot be written in SDDL ([`Ace::sddl`]), since SDDL leaving it out would
    /// say something else.
    #[must_use]
    pub fn sddl(&self) -> Option<String> {
        let mut sddl = String::new();
        for (token, sid) in [("O:", &self.owner), ("G:", &self.group)] {
            if let Some(sid) = sid.as_ref().ok()? {
                let _ = write!(sddl, "{token}{sid}");
            }
        }
        for (token, acl, shift) in [("D:", &self.dacl, 0), ("S:", &self.sacl, 1)] {
            let acl = acl.as_ref().ok()?;
            if matches!(acl, Acl::Absent) {
                continue;
            }
            sddl.push_str(token);
            for (bit, flag) in [(0x1000u16, "P"), (0x0100, "AR"), (0x0400, "AI")] {
                if self.control.0 & (bit << shift) != 0 {
                    sddl.push_str(flag);
                }
            }
            if matches!(acl, Acl::Null) {
                sddl.push_str("NO_ACCESS_CONTROL");
            }
            for ace in acl.aces() {
                sddl.push_str(&ace.sddl()?);
            }
        }
        Some(sddl)
    }
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, Error> {
    bytes
        .get(at..at.saturating_add(2))
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| Error::new("a 16-bit field is cut off"))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Error> {
    bytes
        .get(at..at.saturating_add(4))
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| Error::new("a 32-bit field is cut off"))
}

/// The bytes of a part of the descriptor, from its offset on.
fn component(bytes: &[u8], offset: u32) -> Result<&[u8], Error> {
    let at = usize::try_from(offset).map_err(|_| Error::new("the offset is too large"))?;
    if at < HEADER_SIZE || at % 4 != 0 {
        return Err(Error::new(format!(
            "offset {offset} is inside the header or not DWORD-aligned"
        )));
    }
    bytes
        .get(at..)
        .filter(|rest| !rest.is_empty())
        .ok_or_else(|| Error::new(format!("offset {offset} is past the end of the descriptor")))
}

fn optional_sid(bytes: &[u8], offset: u32) -> Result<Option<Sid>, Error> {
    if offset == 0 {
        return Ok(None);
    }
    Sid::parse(component(bytes, offset)?).map(Some)
}

fn acl(bytes: &[u8], present: bool, offset: u32) -> Result<Acl<'_>, Error> {
    if !present {
        return Ok(Acl::Absent);
    }
    if offset == 0 {
        return Ok(Acl::Null);
    }
    let bytes = component(bytes, offset)?;
    let header = bytes
        .get(..8)
        .ok_or_else(|| Error::new("the ACL header is cut off"))?;
    let revision = header[0];
    if !matches!(revision, 2 | 4) {
        return Err(Error::new(format!("ACL revision {revision} is not 2 or 4")));
    }
    let size = usize::from(u16_at(header, 2)?);
    if size < 8 {
        return Err(Error::new(format!(
            "the ACL's size, {size}, is smaller than its header"
        )));
    }
    let bytes = bytes.get(..size).ok_or_else(|| {
        Error::new(format!(
            "the ACL's size, {size}, runs past the end of the descriptor"
        ))
    })?;
    let count = usize::from(u16_at(header, 4)?);
    if count > (size - 8) / 4 {
        return Err(Error::new(format!(
            "{count} ACEs cannot fit in an ACL of {size} bytes"
        )));
    }
    let mut aces = Vec::with_capacity(count);
    let mut at = 8;
    for index in 1..=count {
        let header = bytes
            .get(at..at + 4)
            .ok_or_else(|| Error::new(format!("ACE {index}'s header is cut off")))?;
        let length = usize::from(u16_at(header, 2)?);
        if length < 4 || length % 4 != 0 {
            return Err(Error::new(format!(
                "ACE {index}'s size, {length}, is not valid"
            )));
        }
        let raw = bytes
            .get(at..at + length)
            .ok_or_else(|| Error::new(format!("ACE {index} runs past the end of the ACL")))?;
        let ace_type = header[0];
        if object_layout(ace_type) && revision != 4 {
            return Err(Error::new(format!(
                "ACE {index} is an object ACE, in an ACL of revision {revision}, not 4"
            )));
        }
        let data = decode_ace(raw).map_err(|e| Error::new(format!("ACE {index}: {e}")))?;
        aces.push(Ace {
            ace_type,
            flags: header[1],
            raw,
            data,
        });
        at += length;
    }
    Ok(Acl::Entries { revision, aces })
}

fn decode_ace(raw: &[u8]) -> Result<Option<AceData<'_>>, Error> {
    let ace_type = raw[0];
    let object = object_layout(ace_type);
    if !object && !standard_layout(ace_type) {
        return Ok(None);
    }
    let mask = u32_at(raw, 4)?;
    let mut at = 8;
    let (mut object_type, mut inherited_object_type) = (None, None);
    if object {
        let flags = u32_at(raw, 8)?;
        if flags & !3 != 0 {
            return Ok(None);
        }
        at = 12;
        for (bit, guid) in [(1, &mut object_type), (2, &mut inherited_object_type)] {
            if flags & bit != 0 {
                let bytes = raw
                    .get(at..at + 16)
                    .ok_or_else(|| Error::new("an object type GUID is cut off"))?;
                let mut g = [0u8; 16];
                g.copy_from_slice(bytes);
                *guid = Some(Guid(g));
                at += 16;
            }
        }
    }
    let sid = Sid::parse(raw.get(at..).unwrap_or_default())?;
    let application_data = &raw[at + sid.size()..];
    Ok(Some(AceData {
        mask,
        sid,
        object_type,
        inherited_object_type,
        application_data,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid_bytes(authority: u8, subs: &[u32]) -> Vec<u8> {
        let mut b = vec![1, subs.len() as u8, 0, 0, 0, 0, 0, authority];
        for s in subs {
            b.extend_from_slice(&s.to_le_bytes());
        }
        b
    }

    fn ace(ace_type: u8, flags: u8, mask: u32, body: &[u8]) -> Vec<u8> {
        let length = (8 + body.len()) as u16;
        let mut b = vec![ace_type, flags];
        b.extend_from_slice(&length.to_le_bytes());
        b.extend_from_slice(&mask.to_le_bytes());
        b.extend_from_slice(body);
        b
    }

    fn acl_bytes(revision: u8, aces: &[Vec<u8>]) -> Vec<u8> {
        let size = 8 + aces.iter().map(Vec::len).sum::<usize>();
        let mut b = vec![revision, 0];
        b.extend_from_slice(&(size as u16).to_le_bytes());
        b.extend_from_slice(&(aces.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        for a in aces {
            b.extend_from_slice(a);
        }
        b
    }

    /// A descriptor with its parts in this order: SACL, DACL, owner, group.
    fn descriptor(
        control: u16,
        owner: Option<&[u8]>,
        group: Option<&[u8]>,
        sacl: Option<&[u8]>,
        dacl: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut b = vec![0u8; HEADER_SIZE];
        b[0] = 1;
        b[2..4].copy_from_slice(&control.to_le_bytes());
        for (at, part) in [(12, sacl), (16, dacl), (4, owner), (8, group)] {
            if let Some(part) = part {
                let offset = b.len() as u32;
                b[at..at + 4].copy_from_slice(&offset.to_le_bytes());
                b.extend_from_slice(part);
            }
        }
        b
    }

    const SYSTEM: [u32; 1] = [18];
    const ADMINISTRATORS: [u32; 2] = [32, 544];

    #[test]
    fn a_files_descriptor() {
        let dacl = acl_bytes(
            2,
            &[
                ace(0, 0x13, 0x001f_01ff, &sid_bytes(5, &SYSTEM)),
                ace(0, 0x13, 0x001f_01ff, &sid_bytes(5, &ADMINISTRATORS)),
                ace(0, 0x1b, 0x1000_0000, &sid_bytes(3, &[0])),
                ace(1, 0x00, 0x0001_0000, &sid_bytes(1, &[0])),
            ],
        );
        let control = Control::SELF_RELATIVE | Control::DACL_PRESENT | 0x1000 | 0x0400;
        let bytes = descriptor(
            control,
            Some(&sid_bytes(5, &ADMINISTRATORS)),
            Some(&sid_bytes(5, &SYSTEM)),
            None,
            Some(&dacl),
        );
        let sd = SecurityDescriptor::parse(&bytes).unwrap();
        assert_eq!(sd.revision, 1);
        assert_eq!(
            sd.control.names(),
            [
                "SE_DACL_PRESENT",
                "SE_DACL_AUTO_INHERITED",
                "SE_DACL_PROTECTED",
                "SE_SELF_RELATIVE"
            ]
        );
        let owner = sd.owner.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(owner.to_string(), "S-1-5-32-544");
        assert_eq!(owner.well_known_name(), Some("BUILTIN\\Administrators"));
        assert_eq!(sd.sacl, Ok(Acl::Absent));
        let aces = sd.dacl.as_ref().unwrap().aces();
        assert_eq!(aces.len(), 4);
        assert_eq!(aces[0].type_name(), "ACCESS_ALLOWED");
        assert_eq!(aces[0].flag_names(), ["OI", "CI", "ID"]);
        assert_eq!(aces[3].type_name(), "ACCESS_DENIED");
        assert_eq!(sd.problems(), Vec::<String>::new());
        assert_eq!(
            sd.sddl().unwrap(),
            "O:S-1-5-32-544G:S-1-5-18D:PAI\
             (A;OICIID;0x001f01ff;;;S-1-5-18)\
             (A;OICIID;0x001f01ff;;;S-1-5-32-544)\
             (A;OICIIOID;0x10000000;;;S-1-3-0)\
             (D;;0x00010000;;;S-1-1-0)"
        );
    }

    #[test]
    fn null_empty_and_absent_acls() {
        let control = Control::SELF_RELATIVE | Control::DACL_PRESENT | Control::SACL_PRESENT;
        let empty = acl_bytes(2, &[]);
        let bytes = descriptor(control, None, None, Some(&empty), None);
        let sd = SecurityDescriptor::parse(&bytes).unwrap();
        assert_eq!(sd.owner, Ok(None));
        assert_eq!(sd.dacl, Ok(Acl::Null));
        assert_eq!(
            sd.sacl,
            Ok(Acl::Entries {
                revision: 2,
                aces: vec![]
            })
        );
        assert_eq!(sd.sddl().unwrap(), "D:NO_ACCESS_CONTROLS:");
    }

    #[test]
    fn a_label_an_object_ace_and_a_callback() {
        let label = ace(17, 0, 1, &sid_bytes(16, &[12288]));
        let mut object = 3u32.to_le_bytes().to_vec();
        object.extend_from_slice(&[0x11; 16]);
        object.extend_from_slice(&[0x22; 16]);
        object.extend_from_slice(&sid_bytes(5, &[11]));
        let object_ace = ace(5, 0, 0x100, &object);
        // Exists WIN://PKG, and a condition that is not one
        let mut callback = sid_bytes(1, &[0]);
        callback.extend_from_slice(b"artx\xf8\x12\0\0\0");
        callback.extend("WIN://PKG".encode_utf16().flat_map(u16::to_le_bytes));
        callback.push(0x87);
        let callback_ace = ace(9, 0, 0x0012_00a9, &callback);
        let mut odd = sid_bytes(1, &[0]);
        odd.extend_from_slice(b"artx");
        let odd_ace = ace(10, 0, 1, &odd);
        let sacl = acl_bytes(2, &[label]);
        let dacl = acl_bytes(4, &[object_ace.clone(), callback_ace.clone()]);
        let control = Control::SELF_RELATIVE | Control::DACL_PRESENT | Control::SACL_PRESENT;
        let bytes = descriptor(control, None, None, Some(&sacl), Some(&dacl));
        let sd = SecurityDescriptor::parse(&bytes).unwrap();
        let label = &sd.sacl.as_ref().unwrap().aces()[0];
        let label_sid = &label.data.as_ref().unwrap().sid;
        assert_eq!(
            label_sid.well_known_name(),
            Some("Mandatory Label\\High Mandatory Level")
        );
        let aces = sd.dacl.as_ref().unwrap().aces();
        let object = aces[0].data.as_ref().unwrap();
        assert_eq!(
            object.object_type.unwrap().to_string(),
            "11111111-1111-1111-1111-111111111111"
        );
        assert!(object.inherited_object_type.is_some());
        assert_eq!(aces[1].type_name(), "ACCESS_ALLOWED_CALLBACK");
        let data = aces[1].data.as_ref().unwrap();
        assert_eq!(data.sid.to_string(), "S-1-1-0");
        assert_eq!(data.application_data.len(), 28);
        assert_eq!(aces[1].condition().unwrap(), "(Exists WIN://PKG)");
        assert_eq!(sd.problems(), Vec::<String>::new());
        assert_eq!(
            sd.sddl().unwrap(),
            "D:(OA;;0x00000100;11111111-1111-1111-1111-111111111111;\
             22222222-2222-2222-2222-222222222222;S-1-5-11)\
             (XA;;0x001200a9;;;S-1-1-0;(Exists WIN://PKG))\
             S:(ML;;0x00000001;;;S-1-16-12288)"
        );

        // a callback ACE whose condition is not decoded: no SDDL, since leaving the condition out
        // would grant more
        let dacl = acl_bytes(4, &[object_ace, callback_ace, odd_ace]);
        let control = Control::SELF_RELATIVE | Control::DACL_PRESENT;
        let bytes = descriptor(control, None, None, None, Some(&dacl));
        let sd = SecurityDescriptor::parse(&bytes).unwrap();
        let odd = &sd.dacl.as_ref().unwrap().aces()[2];
        assert_eq!(odd.condition(), None);
        assert_eq!(odd.sddl(), None);
        assert_eq!(sd.sddl(), None);
    }

    #[test]
    fn damage_stays_in_its_part() {
        // the owner's offset is past the end, the group is cut off, the DACL counts too many ACEs
        let mut dacl = acl_bytes(2, &[ace(0, 0, 1, &sid_bytes(5, &SYSTEM))]);
        dacl[4] = 9;
        let control = Control::SELF_RELATIVE | Control::DACL_PRESENT | Control::SACL_PRESENT;
        let mut bytes = descriptor(control, None, None, None, Some(&dacl));
        bytes[4..8].copy_from_slice(&4096u32.to_le_bytes());
        let group = bytes.len() as u32;
        bytes[8..12].copy_from_slice(&group.to_le_bytes());
        bytes.extend_from_slice(&[1, 5, 0, 0, 0, 0, 0, 5]);
        let sd = SecurityDescriptor::parse(&bytes).unwrap();
        assert_eq!(
            sd.problems(),
            [
                "owner: offset 4096 is past the end of the descriptor",
                "group: the SID's subauthorities are cut off",
                "DACL: 9 ACEs cannot fit in an ACL of 28 bytes",
            ]
        );
        assert_eq!(sd.sacl, Ok(Acl::Null));
        assert_eq!(sd.sddl(), None);

        // an unknown ACE type keeps its bytes
        let dacl = acl_bytes(2, &[ace(0x30, 0, 0, &[1, 2, 3, 4])]);
        let bytes = descriptor(
            Control::SELF_RELATIVE | Control::DACL_PRESENT,
            None,
            None,
            None,
            Some(&dacl),
        );
        let sd = SecurityDescriptor::parse(&bytes).unwrap();
        let unknown = &sd.dacl.as_ref().unwrap().aces()[0];
        assert_eq!(unknown.data, None);
        assert_eq!(unknown.raw.len(), 12);
        assert_eq!(
            sd.problems(),
            ["DACL entry 1: UNKNOWN ACE (type 0x30) not decoded"]
        );
    }

    #[test]
    fn headers_that_cannot_be_read() {
        assert!(SecurityDescriptor::parse(&[1, 0, 0, 0x80]).is_err());
        let mut bytes = descriptor(Control::SELF_RELATIVE, None, None, None, None);
        bytes[0] = 2;
        assert_eq!(
            SecurityDescriptor::parse(&bytes).unwrap_err().to_string(),
            "descriptor revision 2 is not 1"
        );
        let bytes = descriptor(Control::DACL_PRESENT, None, None, None, None);
        assert!(SecurityDescriptor::parse(&bytes).is_err());
    }

    #[test]
    fn sids() {
        let sid = Sid::parse(&sid_bytes(5, &[21, 1, 2, 3, 500])).unwrap();
        assert_eq!(sid.to_string(), "S-1-5-21-1-2-3-500");
        assert_eq!(sid.well_known_name(), Some("Administrator"));
        assert_eq!(sid.size(), 28);
        let sid = Sid::parse(&sid_bytes(5, &[21, 1, 2, 3, 513])).unwrap();
        assert_eq!(sid.well_known_name(), None);
        let trusted = Sid::parse(&sid_bytes(
            5,
            &[
                80,
                956_008_885,
                3_418_522_649,
                1_831_038_044,
                1_853_292_631,
                2_271_478_464,
            ],
        ))
        .unwrap();
        assert_eq!(
            trusted.well_known_name(),
            Some("NT SERVICE\\TrustedInstaller")
        );
        let mut wide = sid_bytes(0, &[7]);
        wide[2] = 1;
        assert_eq!(
            Sid::parse(&wide).unwrap().to_string(),
            "S-1-0x010000000000-7"
        );
        assert!(Sid::parse(&[1, 16, 0, 0, 0, 0, 0, 5]).is_err());
        assert!(Sid::parse(&[1, 1, 0, 0, 0, 0, 0, 5, 1]).is_err());
    }
}
