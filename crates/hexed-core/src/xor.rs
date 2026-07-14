//! XOR key parsing, (non-)mutating application, and single-byte brute force.

/// Parse a user-entered key. Accepts hex (`"6A 40"`, `"6a40"`, `"0x6A,0x40"`)
/// and, when the text isn't clean hex, falls back to raw ASCII bytes
/// (`"secret"` -> its UTF-8 bytes). Returns `None` only for an empty key.
pub fn parse_key(s: &str) -> Option<Vec<u8>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(bytes) = parse_hex_key(trimmed) {
        if !bytes.is_empty() {
            return Some(bytes);
        }
    }
    Some(trimmed.as_bytes().to_vec())
}

fn parse_hex_key(s: &str) -> Option<Vec<u8>> {
    let cleaned: String = s
        .replace("0x", "")
        .replace("0X", "")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',')
        .collect();
    if cleaned.is_empty() || cleaned.len() % 2 != 0 {
        return None;
    }
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = cleaned.as_bytes();
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// XOR `data` in place with a repeating `key`. No-op for an empty key.
pub fn xor_into(data: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}

/// XOR a copy of `src` with a repeating `key` and return it (non-mutating).
pub fn xor_preview(src: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out = src.to_vec();
    xor_into(&mut out, key);
    out
}

#[derive(Clone, Copy, Debug)]
pub struct ScoredKey {
    pub key: u8,
    /// Text-likeness of the decoded bytes, 0.0..=1.0 (1.0 = all letters/spaces).
    pub score: f32,
}

/// Per-byte "looks like text" weight. Letters and spaces score highest so that
/// genuine plaintext outranks byte strings that merely happen to be printable
/// (e.g. runs of punctuation or digits).
#[inline]
fn text_weight(d: u8) -> i32 {
    match d {
        b'a'..=b'z' | b'A'..=b'Z' | b' ' => 6,
        b'0'..=b'9' => 3,
        b'.' | b',' | b'!' | b'?' | b'\'' | b'"' | b'-' | b':' | b';' | b'/' | b'(' | b')'
        | b'\n' | b'\r' | b'\t' => 2,
        0x20..=0x7e => 1,
        _ => -2,
    }
}

const MAX_WEIGHT: i32 = 6;

/// Try all 256 single-byte keys against `src`, ranked best-first by how much
/// the decoded output looks like text. The quick "which key reveals strings?"
/// heuristic for malware triage.
pub fn brute_force_single_byte(src: &[u8]) -> Vec<ScoredKey> {
    let mut scored = Vec::with_capacity(256);
    if src.is_empty() {
        return scored;
    }
    let denom = (src.len() as i32 * MAX_WEIGHT) as f32;
    for k in 0u16..256 {
        let key = k as u8;
        let sum: i32 = src.iter().map(|&b| text_weight(b ^ key)).sum();
        let score = (sum.max(0) as f32 / denom).clamp(0.0, 1.0);
        scored.push(ScoredKey { key, score });
    }
    scored.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    scored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_key_variants() {
        assert_eq!(parse_key("6A 40"), Some(vec![0x6A, 0x40]));
        assert_eq!(parse_key("6a40"), Some(vec![0x6A, 0x40]));
        assert_eq!(parse_key("0x6A,0x40"), Some(vec![0x6A, 0x40]));
        assert_eq!(parse_key(""), None);
    }

    #[test]
    fn falls_back_to_ascii() {
        // "zzz" is not valid even-length hex ('z' not a hex digit) -> ASCII bytes
        assert_eq!(parse_key("zzz"), Some(b"zzz".to_vec()));
    }

    #[test]
    fn xor_roundtrips() {
        let plain = b"hello world";
        let key = [0x6A, 0x40, 0x1F];
        let enc = xor_preview(plain, &key);
        let dec = xor_preview(&enc, &key);
        assert_eq!(&dec, plain);
    }

    #[test]
    fn brute_force_recovers_single_byte_key() {
        let plain = b"The quick brown fox jumps over the lazy dog";
        let enc = xor_preview(plain, &[0x5A]);
        let ranked = brute_force_single_byte(&enc);
        assert_eq!(ranked[0].key, 0x5A);
    }
}
