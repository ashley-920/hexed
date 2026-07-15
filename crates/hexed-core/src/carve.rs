//! Embedded-file detection ("carving").
//!
//! Scans a buffer for well-known file magic so an analyst can spot payloads
//! hidden inside a sample — an appended PE, a resource ZIP, a dropped image.
//! `MZ` is validated through to the `PE\0\0` signature (and given a size hint
//! from its section table) so random `MZ` byte pairs don't create noise.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Embedded {
    /// Human label, e.g. "PE/EXE", "ZIP", "PNG".
    pub kind: &'static str,
    /// Byte offset of the magic within the buffer.
    pub offset: usize,
    /// On-disk size, when cheaply derivable from headers (PE only for now).
    pub size: Option<usize>,
}

/// Upper bound on reported hits, so a pathological file can't flood the UI.
// Cap on carved hits. The scan is front-to-back and stops at the cap, so a low
// cap lets many junk matches near the start hide a real payload deeper in the
// file; keep it high enough that realistic samples (lots of resources / small
// magics) are never truncated, while still bounding memory on a hostile flood.
const MAX_HITS: usize = 4096;

/// Find embedded files by magic. Results are sorted by offset. The match at
/// offset 0 (the container's own header) is included and labeled like any other.
pub fn find_embedded(data: &[u8]) -> Vec<Embedded> {
    let mut out: Vec<Embedded> = Vec::new();
    let n = data.len();

    // Fixed-signature formats: (magic, label).
    const SIGS: &[(&[u8], &str)] = &[
        (b"PK\x03\x04", "ZIP"),
        (b"PK\x05\x06", "ZIP (empty)"),
        (b"\x1f\x8b\x08", "GZIP"),
        (b"BZh", "BZIP2"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
        (b"Rar!\x1a\x07\x00", "RAR"),
        (b"Rar!\x1a\x07\x01\x00", "RAR5"),
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"GIF87a", "GIF"),
        (b"GIF89a", "GIF"),
        (b"%PDF-", "PDF"),
        (b"MSCF", "CAB"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE/MSI/DOC"),
        (b"{\\rtf", "RTF"),
        (b"\x7fELF", "ELF"),
        (b"\xca\xfe\xba\xbe", "Mach-O FAT / Java class"),
        (b"\xce\xfa\xed\xfe", "Mach-O (32)"),
        (b"\xcf\xfa\xed\xfe", "Mach-O (64)"),
        (b"\xed\xab\xee\xdb", "RPM"),
        (b"ustar", "TAR"),
    ];

    for i in 0..n {
        if out.len() >= MAX_HITS {
            break;
        }
        // MZ → validate to PE\0\0.
        if data[i] == b'M' && i + 1 < n && data[i + 1] == b'Z' {
            if let Some(size) = validate_pe(data, i) {
                out.push(Embedded { kind: "PE/EXE", offset: i, size });
                continue;
            }
        }
        // JPEG: FF D8 FF.
        if i + 3 <= n && data[i] == 0xFF && data[i + 1] == 0xD8 && data[i + 2] == 0xFF {
            out.push(Embedded { kind: "JPEG", offset: i, size: None });
            continue;
        }
        for (magic, kind) in SIGS {
            if data[i..].starts_with(magic) {
                // TAR "ustar" lives at offset 257 of a block; report the block start.
                let off = if *kind == "TAR" && i >= 257 { i - 257 } else { i };
                out.push(Embedded { kind, offset: off, size: None });
                break;
            }
        }
    }

    out.sort_by_key(|e| e.offset);
    out.dedup_by(|a, b| a.offset == b.offset && a.kind == b.kind);
    out
}

/// If `data[at..]` is a valid PE, return `Some(size)` where size is the extent
/// of the section table on disk (overlay excluded); `Some(None)` if it parses
/// but the size can't be derived; `None` if it isn't a PE.
fn validate_pe(data: &[u8], at: usize) -> Option<Option<usize>> {
    let e_lfanew_pos = at + 0x3c;
    if e_lfanew_pos + 4 > data.len() {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data[e_lfanew_pos..e_lfanew_pos + 4].try_into().ok()?) as usize;
    let pe = at.checked_add(e_lfanew)?;
    if pe + 24 > data.len() || &data[pe..pe + 4] != b"PE\0\0" {
        return None;
    }
    let num_sections = u16::from_le_bytes(data[pe + 6..pe + 8].try_into().ok()?) as usize;
    let opt_size = u16::from_le_bytes(data[pe + 20..pe + 22].try_into().ok()?) as usize;
    let sec_table = pe + 24 + opt_size;
    // Walk section headers (40 bytes each) for max(raw_ptr + raw_size).
    let mut end = 0usize;
    for s in 0..num_sections {
        let h = sec_table + s * 40;
        if h + 40 > data.len() {
            break;
        }
        let raw_size = u32::from_le_bytes(data[h + 16..h + 20].try_into().ok()?) as usize;
        let raw_ptr = u32::from_le_bytes(data[h + 20..h + 24].try_into().ok()?) as usize;
        end = end.max(raw_ptr + raw_size);
    }
    // size is relative to the PE's own start (`at`); clamp to buffer.
    let size = if end > 0 { Some(end.min(data.len().saturating_sub(at))) } else { None };
    Some(size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_png_and_zip() {
        let mut data = vec![0u8; 32];
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n....");
        data.extend_from_slice(b"PK\x03\x04zipbody");
        let hits = find_embedded(&data);
        assert!(hits.iter().any(|e| e.kind == "PNG" && e.offset == 32));
        assert!(hits.iter().any(|e| e.kind == "ZIP"));
    }

    #[test]
    fn mz_without_pe_is_ignored() {
        // "MZ" followed by garbage (no valid PE header) must not be reported.
        let data = b"junk MZ more random bytes with no pe header at all........";
        let hits = find_embedded(data);
        assert!(!hits.iter().any(|e| e.kind == "PE/EXE"), "got {hits:?}");
    }

    #[test]
    fn finds_valid_embedded_pe() {
        // Minimal PE: MZ header, e_lfanew -> "PE\0\0", 0 sections.
        let mut data = vec![0u8; 64];
        data[0] = b'M';
        data[1] = b'Z';
        let e_lfanew: u32 = 64;
        data[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        // PE header at 64: "PE\0\0", machine, num_sections=0, ... opt_size=0
        data.extend_from_slice(b"PE\0\0"); // 64..68
        data.extend_from_slice(&[0u8; 20]); // COFF header rest (num_sections=0 at +6)
        let hits = find_embedded(&data);
        assert!(hits.iter().any(|e| e.kind == "PE/EXE" && e.offset == 0), "got {hits:?}");
    }
}
