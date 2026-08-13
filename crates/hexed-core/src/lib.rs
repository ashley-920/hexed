//! hexed-core — UI-agnostic core for the hexed hex editor.
//!
//! P0 surface: an in-memory byte [`Buffer`] with undo, printable-string
//! extraction ([`find_strings`]), and XOR key parsing / application / brute
//! force. Deliberately free of any GUI dependency so the eventual `.bt`
//! template engine and a headless CLI can build on the same primitives.

pub mod authenticode;
pub mod buffer;
pub mod carve;
pub mod diff;
pub mod disasm;
pub mod entropy;
pub mod export;
pub mod hashes;
pub mod histogram;
pub mod inspect;
pub mod ioc;
pub mod ops;
pub mod pe;
pub mod search;
pub mod signatures;
pub mod strings;
pub mod xor;
pub mod yara;

pub use authenticode::{PeAuthenticode, PeCertificate};
pub use buffer::Buffer;
pub use carve::{find_embedded, Embedded};
pub use diff::{diff_aligned, DiffResult, DiffRun};
pub use entropy::{entropy_profile, shannon_entropy};
pub use export::{
    to_base64, to_c_array, to_hex_string, to_text, to_yara_hex, to_yara_iocs_rule, to_yara_rule,
    to_yara_strings_rule, yara_file_magic,
};
pub use hashes::{adler32, crc16, crc32, hash_all, md5_hex, sha256_hex, Hashes};
pub use histogram::{byte_histogram, Histogram};
pub use inspect::{inspect, ymd_utc, Endian, Interpretation};
pub use ioc::{defang, extract_iocs, Ioc, IocKind};
pub use ops::{apply as apply_block_op, BlockOp};
pub use pe::{imphash, parse_pe, suspicious_apis, ApiFlag, PeExport, PeImport, PeInfo, PeSection};
pub use search::{find_bytes, find_pattern, find_text, parse_hex_pattern, PatByte};
pub use signatures::{scan_signatures, SigHit};
pub use strings::{find_strings, FoundString, StringKind};
pub use xor::{brute_force_single_byte, parse_key, xor_into, xor_preview, ScoredKey};
pub use yara::{yara_scan, YaraMatch};

#[cfg(test)]
mod empty_input_tests {
    use super::*;

    /// Every analysis entry point the UI runs over a document's bytes, called on
    /// a zero-length buffer.
    ///
    /// File > New makes "0 bytes" a routine state rather than something you can
    /// only reach by deleting every byte, and the derived-analysis pass fires on
    /// a blank tab before anything is typed. None of these may panic, divide by
    /// zero, or index out of bounds.
    #[test]
    fn whole_analysis_pipeline_survives_a_zero_byte_buffer() {
        let d: &[u8] = &[];

        assert!(find_strings(d, 4, true, true).is_empty());
        assert!(entropy_profile(d, 256).is_empty());
        assert_eq!(shannon_entropy(d), 0.0);
        assert_eq!(byte_histogram(d).total, 0);
        assert!(parse_pe(d).is_none());
        assert!(extract_iocs(d).is_empty());
        assert!(find_embedded(d).is_empty());
        assert!(scan_signatures(d).is_empty());
        assert!(disasm::disassemble(d, 64, 0, 64).is_empty());
        assert!(brute_force_single_byte(d).is_empty());
        assert!(xor_preview(d, b"key").is_empty());
        assert!(find_text(d, "anything", false).is_empty());
        assert!(find_pattern(d, &parse_hex_pattern("4D 5A").unwrap()).is_empty());

        // Hashes of nothing are still well-defined, not a crash.
        let h = hash_all(d);
        assert_eq!(
            h.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // Export/copy paths over an empty selection.
        assert_eq!(to_hex_string(d), "");
        assert_eq!(to_base64(d), "");
        assert_eq!(to_yara_hex(d), "{  }"); // braces always emitted, no bytes
        let _ = to_text(d);
        let _ = to_c_array(d, "data");

        // Comparing a blank document against a real one.
        let _ = diff_aligned(d, b"MZ\x90\x00");
        let _ = diff_aligned(d, d);
    }

    /// Growing a blank buffer the two ways the UI offers, then re-running the
    /// analysis that fires after an edit.
    #[test]
    fn a_blank_buffer_can_be_filled_and_reanalyzed() {
        let mut b = Buffer::from_bytes(Vec::new());
        b.insert(0, b"MZ");
        b.replace_all(b"MZ\x90\x00http://evil.example/x".to_vec());
        let data = b.data();
        assert!(
            !extract_iocs(data).is_empty(),
            "IOCs must scan a grown buffer"
        );
        assert_eq!(byte_histogram(data).total, data.len() as u64);
        assert!(!entropy_profile(data, 64).is_empty());
    }
}
