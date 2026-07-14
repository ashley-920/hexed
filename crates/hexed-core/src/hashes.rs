//! File / selection digests for IOC generation: CRC-32 plus MD5, SHA-1,
//! SHA-256.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Default)]
pub struct Hashes {
    pub crc16: u16,
    pub crc32: u32,
    pub adler32: u32,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

/// CRC-16/ARC (a.k.a. CRC-16/IBM): poly 0x8005 reflected, init 0, no xor-out.
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

/// Adler-32 checksum (the zlib checksum).
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a = 1u32;
    let mut b = 0u32;
    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

/// CRC-32/ISO-HDLC (the zlib / PNG "IEEE" CRC), computed table-free.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// MD5 of `data` as a lowercase hex string (used for imphash and section hashes).
pub fn md5_hex(data: &[u8]) -> String {
    hex(&Md5::digest(data))
}

/// SHA-256 of `data` as a lowercase hex string (used for VirusTotal lookups).
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Compute CRC-32, MD5, SHA-1 and SHA-256 over `data`.
pub fn hash_all(data: &[u8]) -> Hashes {
    Hashes {
        crc16: crc16(data),
        crc32: crc32(data),
        adler32: adler32(data),
        md5: hex(&Md5::digest(data)),
        sha1: hex(&Sha1::digest(data)),
        sha256: hex(&Sha256::digest(data)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn crc16_and_adler32_known_vectors() {
        // CRC-16/ARC check value.
        assert_eq!(crc16(b"123456789"), 0xBB3D);
        assert_eq!(crc16(b""), 0);
        // Adler-32: empty = 1; "abc" = 0x024D0127.
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"abc"), 0x024D_0127);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn md5_and_sha_known_vectors() {
        let empty = hash_all(b"");
        assert_eq!(empty.md5, "d41d8cd98f00b204e9800998ecf8427e");

        let abc = hash_all(b"abc");
        assert_eq!(abc.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            abc.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
