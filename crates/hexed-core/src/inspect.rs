//! Data inspector: interpret the bytes at an offset as common numeric types,
//! in the chosen byte order — the 010 Editor "Inspector" pane.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Clone, Debug)]
pub struct Interpretation {
    pub label: &'static str,
    pub value: String,
}

fn take<const N: usize>(rest: &[u8]) -> Option<[u8; N]> {
    if rest.len() >= N {
        let mut b = [0u8; N];
        b.copy_from_slice(&rest[..N]);
        Some(b)
    } else {
        None
    }
}

/// Format a float compactly. Arbitrary bytes reinterpreted as a float are
/// often subnormal or enormous, and `Display` then expands them to hundreds of
/// digits — so fall back to scientific notation past a sane length.
fn fmt_float<T: std::fmt::Display + std::fmt::LowerExp>(f: T) -> String {
    let s = format!("{f}");
    if s.len() <= 24 {
        s
    } else {
        format!("{f:e}")
    }
}

/// Interpret the bytes at `offset` as int/uint 8..64, float32/64 and a couple
/// of common time formats. Only interpretations that fit within the buffer are
/// returned.
pub fn inspect(data: &[u8], offset: usize, endian: Endian) -> Vec<Interpretation> {
    let mut out = Vec::new();
    if offset >= data.len() {
        return out;
    }
    let rest = &data[offset..];
    let le = matches!(endian, Endian::Little);

    macro_rules! push {
        ($label:expr, $v:expr) => {
            out.push(Interpretation {
                label: $label,
                value: $v,
            });
        };
    }

    push!("int8", (rest[0] as i8).to_string());
    push!("uint8", rest[0].to_string());
    push!("binary", format!("{:08b}", rest[0]));

    // LEB128 variable-length integers (WASM / DWARF / protobuf).
    if let Some((v, n)) = read_uleb128(rest) {
        push!("ULEB128", format!("{v}  ({n}B)"));
    }
    if let Some((v, n)) = read_sleb128(rest) {
        push!("SLEB128", format!("{v}  ({n}B)"));
    }

    if let Some(b) = take::<2>(rest) {
        let i = if le {
            i16::from_le_bytes(b)
        } else {
            i16::from_be_bytes(b)
        };
        let u = if le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        };
        push!("int16", i.to_string());
        push!("uint16", u.to_string());
    }

    // Color interpretations (rendered with a swatch in the UI).
    if rest.len() >= 3 {
        push!(
            "RGB",
            format!("#{:02X}{:02X}{:02X}", rest[0], rest[1], rest[2])
        );
    }
    if rest.len() >= 4 {
        push!(
            "RGBA",
            format!(
                "#{:02X}{:02X}{:02X}{:02X}",
                rest[0], rest[1], rest[2], rest[3]
            )
        );
    }
    if let Some(b) = take::<4>(rest) {
        let i = if le {
            i32::from_le_bytes(b)
        } else {
            i32::from_be_bytes(b)
        };
        let u = if le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        };
        let f = if le {
            f32::from_le_bytes(b)
        } else {
            f32::from_be_bytes(b)
        };
        push!("int32", i.to_string());
        push!("uint32", u.to_string());
        push!("float32", fmt_float(f));
        // Unix time_t (seconds since 1970) is often a 32-bit LE value.
        push!("time_t (UTC)", format_unix(u as i64));
        // MS-DOS packed date/time (ZIP/FAT): time word then date word, LE.
        let dos_time = u16::from_le_bytes([b[0], b[1]]);
        let dos_date = u16::from_le_bytes([b[2], b[3]]);
        push!("DOS date/time", format_dos(dos_date, dos_time));
    }
    if let Some(b) = take::<8>(rest) {
        let i = if le {
            i64::from_le_bytes(b)
        } else {
            i64::from_be_bytes(b)
        };
        let u = if le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        };
        let f = if le {
            f64::from_le_bytes(b)
        } else {
            f64::from_be_bytes(b)
        };
        push!("int64", i.to_string());
        push!("uint64", u.to_string());
        push!("float64", fmt_float(f));
        // Windows FILETIME: 100ns ticks since 1601-01-01.
        push!("FILETIME (UTC)", format_filetime(u));
    }

    if let Some(b) = take::<16>(rest) {
        // GUID: first three fields little-endian, last eight bytes as-is.
        let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let d2 = u16::from_le_bytes([b[4], b[5]]);
        let d3 = u16::from_le_bytes([b[6], b[7]]);
        push!(
            "GUID",
            format!(
                "{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
            )
        );
    }

    out
}

/// Format Unix seconds as a UTC calendar date `"YYYY-MM-DD"` (no chrono dep).
pub fn ymd_utc(secs: i64) -> String {
    let (y, mo, d, _, _, _) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02}")
}

/// Very small UTC date formatter (no chrono dependency): seconds since the
/// Unix epoch -> "YYYY-MM-DD HH:MM:SS". Returns "-" for clearly out-of-range
/// values so the inspector stays readable.
pub(crate) fn format_unix(secs: i64) -> String {
    if !(0..=253_402_300_799).contains(&secs) {
        return "-".to_string();
    }
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// Decode an unsigned LEB128 varint from the front of `bytes`; returns the
/// value and the number of bytes consumed (max 10).
fn read_uleb128(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for (i, &b) in bytes.iter().enumerate().take(10) {
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

/// Decode a signed LEB128 varint from the front of `bytes`.
fn read_sleb128(bytes: &[u8]) -> Option<(i64, usize)> {
    let mut result = 0i64;
    let mut shift = 0u32;
    for (i, &b) in bytes.iter().enumerate().take(10) {
        result |= ((b & 0x7f) as i64) << shift;
        shift += 7;
        if b & 0x80 == 0 {
            if shift < 64 && (b & 0x40) != 0 {
                result |= -1i64 << shift; // sign-extend
            }
            return Some((result, i + 1));
        }
    }
    None
}

/// Format an MS-DOS packed date + time (as used in ZIP/FAT) as UTC-ish text.
fn format_dos(date: u16, time: u16) -> String {
    let year = 1980 + ((date >> 9) & 0x7f) as u32;
    let month = ((date >> 5) & 0x0f) as u32;
    let day = (date & 0x1f) as u32;
    let hour = ((time >> 11) & 0x1f) as u32;
    let min = ((time >> 5) & 0x3f) as u32;
    let sec = ((time & 0x1f) * 2) as u32;
    if month == 0 || month > 12 || day == 0 || day > 31 {
        return "-".to_string();
    }
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}")
}

fn format_filetime(ticks: u64) -> String {
    // FILETIME epoch (1601) is 11644473600 seconds before the Unix epoch.
    const OFFSET: i64 = 11_644_473_600;
    let secs = (ticks / 10_000_000) as i64 - OFFSET;
    if !(0..=253_402_300_799).contains(&secs) {
        return "-".to_string();
    }
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// Convert Unix seconds to a civil UTC date. Algorithm from Howard Hinnant's
/// `civil_from_days`, which is exact for the proleptic Gregorian calendar.
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, h as u32, mi as u32, s as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_and_big_endian() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let le = inspect(&data, 0, Endian::Little);
        let be = inspect(&data, 0, Endian::Big);
        let get =
            |v: &[Interpretation], l: &str| v.iter().find(|i| i.label == l).unwrap().value.clone();
        assert_eq!(get(&le, "uint32"), 0x0403_0201u32.to_string());
        assert_eq!(get(&be, "uint32"), 0x0102_0304u32.to_string());
        assert_eq!(get(&le, "uint8"), "1");
    }

    #[test]
    fn truncates_at_buffer_end() {
        let data = [0xFFu8];
        let v = inspect(&data, 0, Endian::Little);
        // only 8-bit interpretations fit
        assert!(v.iter().any(|i| i.label == "uint8"));
        assert!(!v.iter().any(|i| i.label == "uint16"));
    }

    #[test]
    fn floats_stay_compact() {
        // Arbitrary bytes as floats must never produce a huge string (the bug
        // that pushed the hex grid off-screen).
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        for it in inspect(&data, 0, Endian::Little) {
            assert!(it.value.len() < 40, "{} too long: {}", it.label, it.value);
        }
    }

    #[test]
    fn reads_guid() {
        let b = [
            0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x0A, 0x0B,
        ];
        let v = inspect(&b, 0, Endian::Little);
        let g = v.iter().find(|i| i.label == "GUID").unwrap();
        assert_eq!(g.value, "{00000001-0002-0003-0405-060708090A0B}");
    }

    #[test]
    fn leb128_varints() {
        // 0xE5 0x8E 0x26 = 624485 unsigned LEB128.
        assert_eq!(read_uleb128(&[0xE5, 0x8E, 0x26]), Some((624485, 3)));
        // 0x9B 0xF1 0x59 = -624485 signed LEB128.
        assert_eq!(read_sleb128(&[0x9B, 0xF1, 0x59]), Some((-624485, 3)));
        // single-byte small values
        assert_eq!(read_uleb128(&[0x08]), Some((8, 1)));
        assert_eq!(read_sleb128(&[0x7F]), Some((-1, 1)));
    }

    #[test]
    fn rgb_and_color() {
        let data = [0xFF, 0x80, 0x00, 0xC0];
        let v = inspect(&data, 0, Endian::Little);
        let get = |l: &str| v.iter().find(|i| i.label == l).unwrap().value.clone();
        assert_eq!(get("RGB"), "#FF8000");
        assert_eq!(get("RGBA"), "#FF8000C0");
    }

    #[test]
    fn dos_datetime() {
        // date=0x5A3D (2025-01-29), time=0x6000 (12:00:00).
        // year=1980+((0x5A3D>>9)&0x7f)=1980+45=2025, month=(0x5A3D>>5)&0xf=1, day=0x5A3D&0x1f=29
        // hour=(0x6000>>11)&0x1f=12, min=(0x6000>>5)&0x3f=0, sec=0
        assert_eq!(super::format_dos(0x5A3D, 0x6000), "2025-01-29 12:00:00");
        assert_eq!(super::format_dos(0, 0), "-"); // month/day 0 => invalid
    }

    #[test]
    fn unix_epoch_formats() {
        // 0 -> 1970-01-01 00:00:00
        assert_eq!(super::format_unix(0), "1970-01-01 00:00:00");
        // 1_700_000_000 -> 2023-11-14 22:13:20 UTC
        assert_eq!(super::format_unix(1_700_000_000), "2023-11-14 22:13:20");
    }
}
