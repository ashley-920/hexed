//! Printable-string extraction (ASCII and naive UTF-16LE), like `strings(1)`.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StringKind {
    Ascii,
    Utf16Le,
}

#[derive(Clone, Debug)]
pub struct FoundString {
    /// Byte offset of the string within the scanned buffer.
    pub offset: usize,
    /// Length in bytes within the buffer (2x char count for UTF-16LE).
    pub len: usize,
    pub kind: StringKind,
    pub text: String,
}

#[inline]
fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t'
}

/// Extract ASCII and/or UTF-16LE strings of at least `min_len` characters,
/// returned sorted by offset.
pub fn find_strings(data: &[u8], min_len: usize, ascii: bool, utf16: bool) -> Vec<FoundString> {
    let min_len = min_len.max(1);
    let mut out = Vec::new();

    if ascii {
        let mut start = 0usize;
        let mut run = 0usize;
        for i in 0..data.len() {
            if is_printable(data[i]) {
                if run == 0 {
                    start = i;
                }
                run += 1;
            } else {
                if run >= min_len {
                    push_ascii(&mut out, data, start, run);
                }
                run = 0;
            }
        }
        if run >= min_len {
            push_ascii(&mut out, data, start, run);
        }
    }

    if utf16 {
        // Naive UTF-16LE: runs of <printable ascii><0x00>.
        let mut i = 0usize;
        while i + 1 < data.len() {
            if is_printable(data[i]) && data[i + 1] == 0 {
                let start = i;
                let mut s = String::new();
                while i + 1 < data.len() && is_printable(data[i]) && data[i + 1] == 0 {
                    s.push(data[i] as char);
                    i += 2;
                }
                if s.chars().count() >= min_len {
                    out.push(FoundString {
                        offset: start,
                        len: i - start,
                        kind: StringKind::Utf16Le,
                        text: s,
                    });
                }
            } else {
                i += 1;
            }
        }
    }

    out.sort_by_key(|f| f.offset);
    out
}

fn push_ascii(out: &mut Vec<FoundString>, data: &[u8], start: usize, run: usize) {
    let text: String = data[start..start + run]
        .iter()
        .map(|&b| b as char)
        .collect();
    out.push(FoundString {
        offset: start,
        len: run,
        kind: StringKind::Ascii,
        text,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ascii_runs() {
        let data = b"\x00\x01hello\x00world\xff!!";
        let s = find_strings(data, 4, true, false);
        let texts: Vec<&str> = s.iter().map(|f| f.text.as_str()).collect();
        assert_eq!(texts, vec!["hello", "world"]);
        assert_eq!(s[0].offset, 2);
    }

    #[test]
    fn respects_min_len() {
        // NUL bytes break the runs: "ab"(2), "CDEF"(4), "gh"(2); min_len 4 keeps one.
        let data = b"ab\x00CDEF\x00gh";
        let s = find_strings(data, 4, true, false);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].text, "CDEF");
    }

    #[test]
    fn finds_utf16le() {
        let data = b"h\x00e\x00l\x00l\x00o\x00";
        let s = find_strings(data, 4, false, true);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].text, "hello");
        assert_eq!(s[0].kind, StringKind::Utf16Le);
    }
}
