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

//! The application data of ACEs, in SDDL: the conditions of callback ACEs ([MS-DTYP] 2.4.4.17),
//! such as `(WIN://SYSAPPID Contains "Microsoft.WindowsStore_8wekyb3d8bbwe")` on Windows' own
//! files, and the claims of resource attribute ACEs (2.4.10.1), such as `("IMAGELOAD",TU,0x0,1)`.
//!
//! [MS-DTYP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/

use crate::descriptor::Sid;
use std::fmt::Write as _;

/// The signature of a conditional expression.
const SIGNATURE: &[u8; 4] = b"artx";
/// How deep composite literals may nest.
const MAX_DEPTH: usize = 32;

/// A callback ACE's conditional expression in SDDL, parenthesized: `None` if `data` is not one
/// (no `artx` signature, an unknown token, or not exactly one expression).
pub(crate) fn expression(data: &[u8]) -> Option<String> {
    let mut at = SIGNATURE.len();
    if data.get(..at)? != SIGNATURE {
        return None;
    }
    let mut stack: Vec<String> = Vec::new();
    while let Some(&token) = data.get(at) {
        match token {
            // padding to the ACE's DWORD boundary
            0x00 => {
                if data[at..].iter().any(|&byte| byte != 0) {
                    return None;
                }
                break;
            }
            0x01..=0x04 | 0x10 | 0x18 | 0x50 | 0x51 => {
                let (text, next) = literal(data, at, 0)?;
                stack.push(text);
                at = next;
            }
            0xf8..=0xfb => {
                let (name, next) = string(data, at + 1)?;
                let prefix = match token {
                    0xf9 => "@User.",
                    0xfa => "@Resource.",
                    0xfb => "@Device.",
                    _ => "",
                };
                stack.push(format!("{prefix}{}", attribute_name(&name, token != 0xf8)?));
                at = next;
            }
            _ => {
                if let Some(op) = binary(token) {
                    let right = stack.pop()?;
                    let left = stack.pop()?;
                    stack.push(format!("({left} {op} {right})"));
                } else if token == 0xa2 {
                    let operand = stack.pop()?;
                    stack.push(format!("(!{operand})"));
                } else {
                    let op = unary(token)?;
                    let operand = stack.pop()?;
                    stack.push(format!("({op} {operand})"));
                }
                at += 1;
            }
        }
    }
    match stack.as_slice() {
        [one] if one.starts_with('(') => Some(one.clone()),
        [one] => Some(format!("({one})")),
        _ => None,
    }
}

fn binary(token: u8) -> Option<&'static str> {
    Some(match token {
        0x80 => "==",
        0x81 => "!=",
        0x82 => "<",
        0x83 => "<=",
        0x84 => ">",
        0x85 => ">=",
        0x86 => "Contains",
        0x88 => "Any_of",
        0x8e => "Not_Contains",
        0x8f => "Not_Any_of",
        0xa0 => "&&",
        0xa1 => "||",
        _ => return None,
    })
}

fn unary(token: u8) -> Option<&'static str> {
    Some(match token {
        0x87 => "Exists",
        0x89 => "Member_of",
        0x8a => "Device_Member_of",
        0x8b => "Member_of_Any",
        0x8c => "Device_Member_of_Any",
        0x8d => "Not_Exists",
        0x90 => "Not_Member_of",
        0x91 => "Not_Device_Member_of",
        0x92 => "Not_Member_of_Any",
        0x93 => "Not_Device_Member_of_Any",
        _ => return None,
    })
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    let b = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    let b = data.get(at..at.checked_add(8)?)?;
    let mut v = [0u8; 8];
    v.copy_from_slice(b);
    Some(u64::from_le_bytes(v))
}

/// The bytes of a length-prefixed value at `at`, and where the next token starts.
fn counted(data: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let len = u32_at(data, at)? as usize;
    let start = at + 4;
    let end = start.checked_add(len)?;
    Some((data.get(start..end)?, end))
}

fn utf16(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|u| u16::from_le_bytes(*u))
        .collect();
    String::from_utf16(&units).ok()
}

/// A length-prefixed UTF-16 string at `at`.
fn string(data: &[u8], at: usize) -> Option<(String, usize)> {
    let (bytes, next) = counted(data, at)?;
    Some((utf16(bytes)?, next))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// SDDL has no escape for a quote inside a Unicode literal. Keep such data as undecoded,
/// rather than returning a syntactically different or truncated descriptor.
fn quoted(text: &str) -> Option<String> {
    (!text.contains(['"', '\0'])).then(|| format!("\"{text}\""))
}

fn attribute_name(name: &str, prefixed: bool) -> Option<String> {
    if name.is_empty() || name.contains('\0') {
        return None;
    }
    let mut output = String::new();
    for (index, unit) in name.encode_utf16().enumerate() {
        let simple =
            u8::try_from(unit).is_ok_and(|c| c.is_ascii_alphanumeric() || b":./_".contains(&c));
        if simple || (unit == u16::from(b'@') && (prefixed || index != 0)) {
            output.push(char::from_u32(u32::from(unit))?);
        } else if !prefixed {
            return None;
        } else if (unit >= 0x80 && !(0xd800..=0xdfff).contains(&unit))
            || u8::try_from(unit).is_ok_and(|c| b"#$'*+-:;?@[\\]^_`{}~".contains(&c))
        {
            output.push(char::from_u32(u32::from(unit))?);
        } else {
            let _ = write!(output, "%%{unit:04x}");
        }
    }
    Some(output)
}

/// The literal token at `at` in SDDL, and where the next token starts.
fn literal(data: &[u8], at: usize, depth: usize) -> Option<(String, usize)> {
    match *data.get(at)? {
        0x01..=0x04 => {
            let value = u64_at(data, at + 1)?.cast_signed();
            let sign = *data.get(at + 9)?;
            let base = *data.get(at + 10)?;
            let magnitude = value.unsigned_abs();
            let digits = match base {
                0x01 => format!("0{magnitude:o}"),
                0x03 => format!("0x{magnitude:x}"),
                _ => magnitude.to_string(),
            };
            let sign = if value < 0 {
                "-"
            } else if sign == 0x01 {
                "+"
            } else {
                ""
            };
            Some((format!("{sign}{digits}"), at + 11))
        }
        0x10 => {
            let (text, next) = string(data, at + 1)?;
            Some((quoted(&text)?, next))
        }
        0x18 => {
            let (bytes, next) = counted(data, at + 1)?;
            Some((format!("#{}", hex(bytes)), next))
        }
        0x51 => {
            let (bytes, next) = counted(data, at + 1)?;
            let sid = Sid::parse(bytes).ok().filter(|s| s.size() == bytes.len())?;
            Some((format!("SID({sid})"), next))
        }
        0x50 if depth < MAX_DEPTH => {
            let (items, next) = counted(data, at + 1)?;
            let mut texts = Vec::new();
            let mut i = 0;
            while i < items.len() {
                let (text, after) = literal(items, i, depth + 1)?;
                texts.push(text);
                i = after;
            }
            Some((format!("{{{}}}", texts.join(", ")), next))
        }
        _ => None,
    }
}

/// A resource attribute ACE's claim in SDDL, `("IMAGELOAD",TU,0x0,1)`: `None` if `data` is not a
/// claim of a known value type.
pub(crate) fn resource_attribute(data: &[u8]) -> Option<String> {
    let name = terminated(data, u32_at(data, 0)? as usize)?;
    let value_type = u16::from_le_bytes([*data.get(4)?, *data.get(5)?]);
    let flags = u32_at(data, 8)?;
    let count = u32_at(data, 12)? as usize;
    if count > data.len() / 4 {
        return None;
    }
    let token = match value_type {
        0x01 => "TI",
        0x02 => "TU",
        0x03 => "TS",
        0x05 => "TD",
        0x06 => "TB",
        0x10 => "TX",
        _ => return None,
    };
    let mut text = format!("({},{token},0x{flags:x}", quoted(&name)?);
    for i in 0..count {
        let at = u32_at(data, 16 + 4 * i)? as usize;
        let value = match value_type {
            0x01 => u64_at(data, at)?.cast_signed().to_string(),
            0x02 | 0x06 => u64_at(data, at)?.to_string(),
            0x03 => quoted(&terminated(data, at)?)?,
            0x05 => {
                let (bytes, _) = counted(data, at)?;
                let sid = Sid::parse(bytes).ok().filter(|s| s.size() == bytes.len())?;
                format!("SID({sid})")
            }
            _ => format!("#{}", hex(counted(data, at)?.0)),
        };
        let _ = write!(text, ",{value}");
    }
    text.push(')');
    Some(text)
}

/// A NUL-terminated UTF-16 string at `at`.
fn terminated(data: &[u8], at: usize) -> Option<String> {
    let rest = data.get(at..)?;
    let len = rest
        .as_chunks::<2>()
        .0
        .iter()
        .position(|u| u == &[0, 0])
        .map(|units| units * 2)?;
    utf16(&rest[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_token(token: u8, text: &str) -> Vec<u8> {
        let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut b = vec![token];
        b.extend_from_slice(&(units.len() as u32).to_le_bytes());
        b.extend_from_slice(&units);
        b
    }

    fn int(value: i64, sign: u8, base: u8) -> Vec<u8> {
        let mut b = vec![0x04];
        b.extend_from_slice(&value.to_le_bytes());
        b.extend_from_slice(&[sign, base]);
        b
    }

    #[test]
    fn an_app_container_condition() {
        // WIN://SYSAPPID Contains "Microsoft.WindowsStore_8wekyb3d8bbwe", padded to a DWORD
        let mut data = b"artx".to_vec();
        data.extend(text_token(0xf8, "WIN://SYSAPPID"));
        data.extend(text_token(0x10, "Microsoft.WindowsStore_8wekyb3d8bbwe"));
        data.extend([0x86, 0, 0]);
        assert_eq!(
            expression(&data).unwrap(),
            "(WIN://SYSAPPID Contains \"Microsoft.WindowsStore_8wekyb3d8bbwe\")"
        );
    }

    #[test]
    fn operators_and_literals() {
        // (@User.clearance >= 0x10) && !(Member_of {SID(S-1-5-32-544), "x"}) || Exists WIN://PKG
        let mut data = b"artx".to_vec();
        data.extend(text_token(0xf9, "clearance"));
        data.extend(int(16, 3, 3));
        data.push(0x85);
        let sid = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0];
        let mut sid_token = vec![0x51];
        sid_token.extend_from_slice(&(sid.len() as u32).to_le_bytes());
        sid_token.extend_from_slice(&sid);
        let mut items = sid_token;
        items.extend(text_token(0x10, "x"));
        data.push(0x50);
        data.extend_from_slice(&(items.len() as u32).to_le_bytes());
        data.extend(items);
        data.extend([0x89, 0xa2, 0xa0]);
        data.extend(text_token(0xf8, "WIN://PKG"));
        data.extend([0x87, 0xa1]);
        assert_eq!(
            expression(&data).unwrap(),
            "(((@User.clearance >= 0x10) && (!(Member_of {SID(S-1-5-32-544), \"x\"}))) \
             || (Exists WIN://PKG))"
        );
        let mut negative = b"artx".to_vec();
        negative.extend(text_token(0xfb, "level"));
        negative.extend(int(-8, 2, 1));
        negative.push(0x82);
        assert_eq!(expression(&negative).unwrap(), "(@Device.level < -010)");
    }

    #[test]
    fn what_is_not_an_expression() {
        assert_eq!(expression(b"xtra"), None);
        assert_eq!(expression(b"artx"), None);
        // an operator without operands, an unknown token, two expressions left
        assert_eq!(expression(b"artx\x80"), None);
        assert_eq!(expression(b"artx\x77"), None);
        let mut two = b"artx".to_vec();
        two.extend(text_token(0x10, "a"));
        two.extend(text_token(0x10, "b"));
        assert_eq!(expression(&two), None);
        // a length past the end
        assert_eq!(expression(b"artx\x10\xff\0\0\0ab"), None);
        // composites nested deeper than allowed
        let mut nested = text_token(0x10, "a");
        for _ in 0..40 {
            let mut outer = vec![0x50];
            outer.extend_from_slice(&(nested.len() as u32).to_le_bytes());
            outer.extend(nested);
            nested = outer;
        }
        let mut deep = b"artx".to_vec();
        deep.extend(nested);
        assert_eq!(expression(&deep), None);
    }

    #[test]
    fn claims() {
        // "IMAGELOAD", a uint64 of 1, as Windows sets it on its own files
        let name: Vec<u8> = "IMAGELOAD\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(&20u32.to_le_bytes());
        data[4..6].copy_from_slice(&2u16.to_le_bytes());
        data[12..16].copy_from_slice(&1u32.to_le_bytes());
        data.extend(&name);
        let value_at = data.len() as u32;
        data[16..20].copy_from_slice(&value_at.to_le_bytes());
        data.extend(1u64.to_le_bytes());
        assert_eq!(
            resource_attribute(&data).unwrap(),
            "(\"IMAGELOAD\",TU,0x0,1)"
        );
        data[4] = 0x7f;
        assert_eq!(resource_attribute(&data), None);
        assert_eq!(resource_attribute(&[0; 8]), None);
    }
    #[test]
    fn quoted_or_nul_strings_cannot_be_claimed_as_exact_sddl() {
        for text in ["a\"b", "a\0b"] {
            let mut data = b"artx".to_vec();
            data.extend(text_token(0xf9, "name"));
            data.extend(text_token(0x10, text));
            data.push(0x80);
            assert_eq!(expression(&data), None);
        }
    }

    #[test]
    fn padding_cannot_hide_tokens_inside_a_condition() {
        let mut data = b"artx".to_vec();
        data.extend(text_token(0xf9, "name"));
        data.push(0);
        data.extend(text_token(0x10, "value"));
        data.push(0x80);
        assert_eq!(expression(&data), None);
    }

    #[test]
    fn prefixed_attribute_names_escape_reserved_sddl_characters() {
        let mut data = b"artx".to_vec();
        data.extend(text_token(0xf9, "department name%"));
        data.push(0x87);
        assert_eq!(
            expression(&data).as_deref(),
            Some("(Exists @User.department%%0020name%%0025)")
        );
    }
}
