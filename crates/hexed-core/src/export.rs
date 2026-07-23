//! Encode a byte range for pasting elsewhere: plain hex, a YARA hex string,
//! a C array, or base64. All hand-rolled (no extra deps).

use std::fmt::Write;

use crate::ioc::Ioc;
use crate::strings::{FoundString, StringKind};

/// Space-separated uppercase hex, e.g. `"6A 40 1F"`.
pub fn to_hex_string(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 3);
    for (i, b) in data.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// A YARA hex string, e.g. `"{ 6A 40 1F }"`, ready to drop into a rule body.
pub fn to_yara_hex(data: &[u8]) -> String {
    format!("{{ {} }}", to_hex_string(data))
}

/// A YARA condition fragment asserting the file's magic bytes, so a generated
/// rule only fires on files of the detected type. Big-endian reads keep the
/// magic in natural byte order. Returns `None` for unrecognized data.
pub fn yara_file_magic(data: &[u8]) -> Option<&'static str> {
    let s = |sig: &[u8]| data.len() >= sig.len() && &data[..sig.len()] == sig;
    if s(b"MZ") {
        Some("uint16be(0) == 0x4D5A") // PE / DOS executable (MZ)
    } else if s(&[0x7F, b'E', b'L', b'F']) {
        Some("uint32be(0) == 0x7F454C46") // ELF
    } else if s(&[0x89, b'P', b'N', b'G']) {
        Some("uint32be(0) == 0x89504E47") // PNG
    } else if s(b"GIF8") {
        Some("uint32be(0) == 0x47494638") // GIF
    } else if s(b"BM") {
        Some("uint16be(0) == 0x424D") // BMP
    } else if s(b"PK\x03\x04") {
        Some("uint32be(0) == 0x504B0304") // ZIP / Office / JAR
    } else if s(b"RIFF") {
        Some("uint32be(0) == 0x52494646") // RIFF (WAV/AVI/WEBP)
    } else if s(b"\x25PDF") {
        Some("uint32be(0) == 0x25504446") // PDF
    } else {
        None
    }
}

/// A complete, ready-to-edit YARA rule whose single string is the given bytes.
/// When `author` is set, a meta block is emitted (with `date`, defaulting to a
/// placeholder); when `magic` is set (e.g. from [`yara_file_magic`]), the
/// condition is anchored to the file type.
pub fn to_yara_rule(
    data: &[u8],
    name: &str,
    author: Option<&str>,
    date: Option<&str>,
    magic: Option<&str>,
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "rule {name}");
    let _ = writeln!(s, "{{");
    if let Some(a) = author {
        let _ = writeln!(s, "    meta:");
        let _ = writeln!(s, "        author = \"{a}\"");
        let _ = writeln!(s, "        description = \"auto-generated from selection\"");
        let _ = writeln!(s, "        date = \"{}\"", date.unwrap_or("YYYY-MM-DD"));
    }
    let _ = writeln!(s, "    strings:");
    let _ = writeln!(s, "        $a = {}", to_yara_hex(data));
    let _ = writeln!(s, "    condition:");
    match magic {
        Some(m) => {
            let _ = writeln!(s, "        {m} and $a");
        }
        None => {
            let _ = writeln!(s, "        $a");
        }
    }
    let _ = writeln!(s, "}}");
    s
}

/// Escape one extracted printable string for a YARA quoted text literal.
fn yara_text_literal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => {
                let _ = write!(out, "\\x{:02X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// A complete YARA rule built from analyst-selected extracted strings. ASCII
/// and UTF-16LE strings retain their encoding through explicit `ascii`/`wide`
/// modifiers. The condition requires every selected string and optionally
/// anchors the rule to the detected file magic.
pub fn to_yara_strings_rule(
    strings: &[FoundString],
    name: &str,
    author: Option<&str>,
    date: Option<&str>,
    magic: Option<&str>,
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "rule {name}");
    let _ = writeln!(s, "{{");
    if let Some(a) = author {
        let _ = writeln!(s, "    meta:");
        let _ = writeln!(s, "        author = \"{a}\"");
        let _ = writeln!(
            s,
            "        description = \"auto-generated from selected strings\""
        );
        let _ = writeln!(s, "        date = \"{}\"", date.unwrap_or("YYYY-MM-DD"));
    }
    let _ = writeln!(s, "    strings:");
    for (i, found) in strings.iter().enumerate() {
        let modifier = match found.kind {
            StringKind::Ascii => "ascii",
            StringKind::Utf16Le => "wide",
        };
        let _ = writeln!(
            s,
            "        $s{} = \"{}\" {}",
            i + 1,
            yara_text_literal(&found.text),
            modifier
        );
    }
    let _ = writeln!(s, "    condition:");
    let selected = if strings.is_empty() {
        "false"
    } else {
        "all of ($s*)"
    };
    match magic {
        Some(m) => {
            let _ = writeln!(s, "        {m} and {selected}");
        }
        None => {
            let _ = writeln!(s, "        {selected}");
        }
    }
    let _ = writeln!(s, "}}");
    s
}

/// A complete YARA rule built from analyst-selected indicators. IOC values are
/// emitted in their original (never defanged) form and retain the ASCII or
/// UTF-16LE encoding of the bytes from which they were extracted.
pub fn to_yara_iocs_rule(
    iocs: &[Ioc],
    name: &str,
    author: Option<&str>,
    date: Option<&str>,
    magic: Option<&str>,
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "rule {name}");
    let _ = writeln!(s, "{{");
    if let Some(a) = author {
        let _ = writeln!(s, "    meta:");
        let _ = writeln!(s, "        author = \"{a}\"");
        let _ = writeln!(
            s,
            "        description = \"auto-generated from selected IOCs\""
        );
        let _ = writeln!(s, "        date = \"{}\"", date.unwrap_or("YYYY-MM-DD"));
    }
    let _ = writeln!(s, "    strings:");
    for (i, ioc) in iocs.iter().enumerate() {
        let modifier = match ioc.encoding {
            StringKind::Ascii => "ascii",
            StringKind::Utf16Le => "wide",
        };
        let _ = writeln!(
            s,
            "        $ioc{} = \"{}\" {} // {}",
            i + 1,
            yara_text_literal(&ioc.value),
            modifier,
            ioc.kind.label()
        );
    }
    let _ = writeln!(s, "    condition:");
    let selected = if iocs.is_empty() {
        "false"
    } else {
        "all of ($ioc*)"
    };
    match magic {
        Some(m) => {
            let _ = writeln!(s, "        {m} and {selected}");
        }
        None => {
            let _ = writeln!(s, "        {selected}");
        }
    }
    let _ = writeln!(s, "}}");
    s
}

/// A C array declaration with 12 bytes per line, e.g.
/// `unsigned char data[3] = {\n    0x6A, 0x40, 0x1F\n};`.
pub fn to_c_array(data: &[u8], name: &str) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "unsigned char {name}[{}] = {{", data.len());
    for (i, b) in data.iter().enumerate() {
        if i % 12 == 0 {
            s.push_str("    ");
        }
        let _ = write!(s, "0x{b:02X}");
        if i + 1 != data.len() {
            s.push(',');
        }
        if i % 12 == 11 || i + 1 == data.len() {
            s.push('\n');
        } else {
            s.push(' ');
        }
    }
    s.push_str("};\n");
    s
}

/// Interpret the bytes as text for pasting: printable ASCII kept as-is,
/// everything else shown as '.', matching the hex view's ASCII pane.
pub fn to_text(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// Standard base64 (RFC 4648, with `=` padding).
pub fn to_base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests_yara {
    use super::*;

    #[test]
    fn magic_by_type() {
        assert_eq!(
            yara_file_magic(b"MZ\x90\x00"),
            Some("uint16be(0) == 0x4D5A")
        );
        assert_eq!(
            yara_file_magic(&[0x7F, b'E', b'L', b'F']),
            Some("uint32be(0) == 0x7F454C46")
        );
        assert_eq!(yara_file_magic(b"random"), None);
    }

    #[test]
    fn rule_has_dynamic_condition_and_meta() {
        let pe = to_yara_rule(
            &[0x90, 0x90],
            "r",
            Some("Ada"),
            Some("2026-07-13"),
            yara_file_magic(b"MZ\x00\x00"),
        );
        assert!(pe.contains("author = \"Ada\""));
        assert!(pe.contains("date = \"2026-07-13\""));
        assert!(pe.contains("uint16be(0) == 0x4D5A and $a"));
        // Unknown type → plain condition, no meta.
        let plain = to_yara_rule(&[0x90], "r", None, None, None);
        assert!(plain.contains("condition:\n        $a\n"));
        assert!(!plain.contains("meta:"));
    }

    #[test]
    fn selected_strings_keep_encoding_and_escape_literals() {
        let strings = vec![
            FoundString {
                offset: 0x20,
                len: 9,
                kind: StringKind::Ascii,
                text: "say \"hi\"\\".into(),
            },
            FoundString {
                offset: 0x80,
                len: 14,
                kind: StringKind::Utf16Le,
                text: "payload".into(),
            },
        ];
        let rule = to_yara_strings_rule(
            &strings,
            "selected",
            Some("hexed"),
            Some("2026-07-23"),
            Some("uint16be(0) == 0x4D5A"),
        );
        assert!(rule.contains("$s1 = \"say \\\"hi\\\"\\\\\" ascii"));
        assert!(rule.contains("$s2 = \"payload\" wide"));
        assert!(rule.contains("uint16be(0) == 0x4D5A and all of ($s*)"));
    }

    #[test]
    fn empty_selected_strings_rule_never_matches() {
        let rule = to_yara_strings_rule(&[], "empty", None, None, None);
        assert!(rule.contains("condition:\n        false\n"));
    }

    #[test]
    fn selected_ascii_and_wide_rule_compiles_and_matches() {
        let strings = vec![
            FoundString {
                offset: 2,
                len: 5,
                kind: StringKind::Ascii,
                text: "alpha".into(),
            },
            FoundString {
                offset: 8,
                len: 8,
                kind: StringKind::Utf16Le,
                text: "beta".into(),
            },
        ];
        let rule = to_yara_strings_rule(
            &strings,
            "selected_encodings",
            Some("hexed"),
            Some("2026-07-23"),
            yara_file_magic(b"MZ"),
        );
        let mut sample = b"MZalpha\0".to_vec();
        sample.extend_from_slice(b"b\0e\0t\0a\0");
        let matches = crate::yara::yara_scan(&rule, &sample).expect("rule should compile");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "selected_encodings");
    }

    #[test]
    fn selected_iocs_keep_original_values_and_compile() {
        let iocs = vec![
            Ioc {
                kind: crate::ioc::IocKind::Url,
                value: "https://evil.example/drop".into(),
                encoding: StringKind::Ascii,
                offset: 2,
                byte_len: 25,
            },
            Ioc {
                kind: crate::ioc::IocKind::WinPath,
                value: r"C:\Temp\drop.exe".into(),
                encoding: StringKind::Utf16Le,
                offset: 32,
                byte_len: 32,
            },
        ];
        let rule = to_yara_iocs_rule(
            &iocs,
            "selected_iocs",
            Some("hexed"),
            Some("2026-07-23"),
            yara_file_magic(b"MZ"),
        );
        assert!(rule.contains(r#"$ioc1 = "https://evil.example/drop" ascii // URL"#));
        assert!(rule.contains(r#"$ioc2 = "C:\\Temp\\drop.exe" wide // Windows path"#));
        assert!(!rule.contains("hxxp"));

        let mut sample = b"MZhttps://evil.example/drop\0".to_vec();
        for byte in br"C:\Temp\drop.exe" {
            sample.extend_from_slice(&[*byte, 0]);
        }
        let matches = crate::yara::yara_scan(&rule, &sample).expect("rule should compile");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "selected_iocs");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_yara() {
        assert_eq!(to_hex_string(&[0x6A, 0x40, 0x1F]), "6A 40 1F");
        assert_eq!(to_yara_hex(&[0x6A, 0x40, 0x1F]), "{ 6A 40 1F }");
        assert_eq!(to_hex_string(&[]), "");
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(to_base64(b""), "");
        assert_eq!(to_base64(b"f"), "Zg==");
        assert_eq!(to_base64(b"fo"), "Zm8=");
        assert_eq!(to_base64(b"foo"), "Zm9v");
        assert_eq!(to_base64(b"Man"), "TWFu");
        assert_eq!(to_base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn text_dots_nonprintable() {
        assert_eq!(to_text(b"ab\x00c\xff"), "ab.c.");
    }

    #[test]
    fn yara_rule_shape() {
        let r = to_yara_rule(&[0x6A, 0x40], "sig", None, None, None);
        assert!(r.starts_with("rule sig\n{"));
        assert!(r.contains("$a = { 6A 40 }"));
        assert!(r.contains("condition:"));
    }

    #[test]
    fn c_array_shape() {
        let s = to_c_array(&[0x01, 0x02], "buf");
        assert!(s.starts_with("unsigned char buf[2] = {"));
        assert!(s.contains("0x01, 0x02"));
        assert!(s.trim_end().ends_with("};"));
    }
}
