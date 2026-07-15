//! Detection of well-known crypto constants and packer markers.
//!
//! Finding an AES S-box, SHA-256 round constants, or a base64 alphabet inside a
//! binary is a fast tell for what cryptography (or encoding) a sample uses —
//! often the quickest route to the decryptor. Each signature is a distinctive
//! byte prefix of the full table, matched anywhere in the buffer.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigHit {
    pub name: &'static str,
    pub offset: usize,
    pub note: &'static str,
}

struct Sig {
    name: &'static str,
    needle: &'static [u8],
    note: &'static str,
}

/// Per-signature cap, so a table that repeats can't flood the list.
const PER_SIG_MAX: usize = 16;

const SIGS: &[Sig] = &[
    Sig {
        name: "AES S-box",
        needle: &[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
            0x9c, 0xa4, 0x72, 0xc0,
        ],
        note: "Rijndael forward S-box — AES encryption",
    },
    Sig {
        name: "AES inverse S-box",
        needle: &[
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
            0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        ],
        note: "Rijndael inverse S-box — AES decryption",
    },
    Sig {
        name: "SHA-256 constants",
        needle: &[
            0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91, 0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5,
            0xdb, 0xa5,
        ],
        note: "SHA-256 round constants K (big-endian)",
    },
    Sig {
        name: "SHA-256 init",
        needle: &[
            0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f,
            0xf5, 0x3a,
        ],
        note: "SHA-256 initial hash values H (big-endian)",
    },
    Sig {
        name: "MD5 constants",
        needle: &[
            0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8, 0xdb, 0x70, 0x20, 0x24, 0xee, 0xce,
            0xbd, 0xc1,
        ],
        note: "MD5 sine table T (little-endian)",
    },
    Sig {
        name: "SHA-1 init state",
        needle: &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10, 0xf0, 0xe1, 0xd2, 0xc3,
        ],
        note: "SHA-1 initial state (little-endian; MD4/MD5 share the first 4 words)",
    },
    Sig {
        name: "CRC32 table",
        needle: &[
            0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77, 0x2c, 0x61, 0x0e, 0xee,
        ],
        note: "Standard reflected CRC-32 lookup table (poly 0xEDB88320)",
    },
    Sig {
        name: "Base64 alphabet",
        needle: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        note: "Standard base64 encoding table",
    },
    Sig {
        name: "Base64 URL-safe alphabet",
        needle: b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        note: "URL-safe base64 encoding table",
    },
    Sig {
        name: "DOS stub",
        needle: b"This program cannot be run in DOS mode",
        note: "MS-DOS stub string — start of a PE/MZ header",
    },
    Sig {
        name: "UPX",
        needle: b"UPX!",
        note: "UPX packer magic",
    },
];

/// Scan a buffer for known crypto constants and markers, sorted by offset.
pub fn scan_signatures(data: &[u8]) -> Vec<SigHit> {
    let mut out = Vec::new();
    for sig in SIGS {
        if sig.needle.len() > data.len() {
            continue;
        }
        let mut count = 0;
        let mut start = 0;
        while start + sig.needle.len() <= data.len() {
            match data[start..]
                .windows(sig.needle.len())
                .position(|w| w == sig.needle)
            {
                Some(p) => {
                    let off = start + p;
                    out.push(SigHit {
                        name: sig.name,
                        offset: off,
                        note: sig.note,
                    });
                    count += 1;
                    if count >= PER_SIG_MAX {
                        break;
                    }
                    start = off + sig.needle.len();
                }
                None => break,
            }
        }
    }
    out.sort_by_key(|h| h.offset);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_aes_sbox() {
        let mut data = vec![0u8; 16];
        data.extend_from_slice(&[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
            0x9c, 0xa4, 0x72, 0xc0,
        ]);
        let hits = scan_signatures(&data);
        assert!(hits.iter().any(|h| h.name == "AES S-box" && h.offset == 16));
    }

    #[test]
    fn finds_base64_alphabet() {
        let data = b"xx ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/ yy";
        let hits = scan_signatures(data);
        assert!(hits.iter().any(|h| h.name == "Base64 alphabet"));
    }

    #[test]
    fn clean_buffer_has_no_hits() {
        let data = vec![0xABu8; 4096];
        assert!(scan_signatures(&data).is_empty());
    }
}
