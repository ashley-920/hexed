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
