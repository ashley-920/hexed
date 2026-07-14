//! Pattern search: hex byte patterns with `??` wildcards, exact byte strings,
//! and ASCII text (optionally case-insensitive).

/// One element of a hex search pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatByte {
    Byte(u8),
    /// `??` — matches any single byte.
    Any,
}

/// Parse a hex pattern such as `"6A ?? 40"` or `"6a??40"` into elements.
/// Returns `None` for malformed input (odd nibble count or bad hex digit).
pub fn parse_hex_pattern(s: &str) -> Option<Vec<PatByte>> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return None;
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let a = bytes[i] as char;
        let b = bytes[i + 1] as char;
        if a == '?' && b == '?' {
            out.push(PatByte::Any);
        } else {
            let hi = a.to_digit(16)?;
            let lo = b.to_digit(16)?;
            out.push(PatByte::Byte(((hi << 4) | lo) as u8));
        }
        i += 2;
    }
    Some(out)
}

/// All offsets in `data` where `pattern` matches (overlapping matches included).
pub fn find_pattern(data: &[u8], pattern: &[PatByte]) -> Vec<usize> {
    let mut hits = Vec::new();
    if pattern.is_empty() || data.len() < pattern.len() {
        return hits;
    }
    let last = data.len() - pattern.len();
    for start in 0..=last {
        let matched = pattern.iter().enumerate().all(|(j, p)| match p {
            PatByte::Byte(b) => data[start + j] == *b,
            PatByte::Any => true,
        });
        if matched {
            hits.push(start);
        }
    }
    hits
}

/// All offsets of an exact byte string.
pub fn find_bytes(data: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() {
        return Vec::new();
    }
    let pat: Vec<PatByte> = needle.iter().map(|&b| PatByte::Byte(b)).collect();
    find_pattern(data, &pat)
}

/// All offsets of ASCII `text`, optionally case-insensitive.
pub fn find_text(data: &[u8], text: &str, case_insensitive: bool) -> Vec<usize> {
    let needle = text.as_bytes();
    if needle.is_empty() || data.len() < needle.len() {
        return Vec::new();
    }
    if !case_insensitive {
        return find_bytes(data, needle);
    }
    let mut hits = Vec::new();
    for start in 0..=data.len() - needle.len() {
        if data[start..start + needle.len()]
            .iter()
            .zip(needle)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
        {
            hits.push(start);
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_with_wildcards() {
        let p = parse_hex_pattern("6A ?? 40").unwrap();
        assert_eq!(p, vec![PatByte::Byte(0x6A), PatByte::Any, PatByte::Byte(0x40)]);
        assert!(parse_hex_pattern("6A 4").is_none()); // odd nibbles
        assert!(parse_hex_pattern("XY").is_none()); // bad hex
    }

    #[test]
    fn pattern_matches_with_wildcard() {
        let data = &[0x00, 0x6A, 0x11, 0x40, 0x6A, 0x99, 0x40];
        let p = parse_hex_pattern("6A ?? 40").unwrap();
        assert_eq!(find_pattern(data, &p), vec![1, 4]);
    }

    #[test]
    fn exact_bytes_and_text() {
        let data = b"the Cat sat on the CAT";
        assert_eq!(find_bytes(data, b"the"), vec![0, 15]);
        assert_eq!(find_text(data, "cat", true), vec![4, 19]);
        assert_eq!(find_text(data, "cat", false), Vec::<usize>::new());
    }
}
