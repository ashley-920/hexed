//! Defensive parsing of the PE Attribute Certificate Table (Authenticode).
//!
//! This module inventories embedded PKCS#7/X.509 material. It deliberately does
//! not claim that a signature, certificate chain, timestamp, or file digest has
//! been cryptographically verified.

use std::collections::HashSet;

use x509_parser::parse_x509_certificate;

const MAX_WIN_CERTIFICATE_ENTRIES: usize = 64;
const MAX_PKCS7_CERTIFICATE_CHOICES: usize = 256;
const MAX_X509_DER_SIZE: usize = 1024 * 1024;

/// An X.509 certificate embedded in an Authenticode PKCS#7 SignedData object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeCertificate {
    pub common_name: Option<String>,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: String,
    pub not_after: String,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub sha256: String,
    pub is_ca: bool,
    pub code_signing: bool,
}

/// Summary of a PE Security Directory / Attribute Certificate Table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeAuthenticode {
    /// File offset from Data Directory entry 4 (this directory is not an RVA).
    pub file_offset: usize,
    /// Size declared by the PE optional header.
    pub declared_size: usize,
    /// Number of bounded `WIN_CERTIFICATE` records walked.
    pub entries: usize,
    /// Number of `WIN_CERT_TYPE_PKCS_SIGNED_DATA` records.
    pub pkcs7_entries: usize,
    /// X.509 certificates recovered from all bounded PKCS#7 records.
    pub certificates: Vec<PeCertificate>,
    /// Malformation/truncation note. Certificate presence remains useful even
    /// when another entry in the table is malformed.
    pub warning: Option<String>,
}

impl PeAuthenticode {
    /// A PKCS#7 Authenticode record is present. This does not verify its digest,
    /// signature, chain, timestamp, revocation status, or platform trust.
    pub fn signature_present(&self) -> bool {
        self.pkcs7_entries > 0
    }

    /// Best-effort display choice: prefer a non-CA code-signing certificate,
    /// then any non-CA certificate, then the first embedded certificate.
    pub fn likely_signer(&self) -> Option<&PeCertificate> {
        self.certificates
            .iter()
            .find(|c| c.code_signing && !c.is_ca)
            .or_else(|| self.certificates.iter().find(|c| !c.is_ca))
            .or_else(|| self.certificates.first())
    }
}

/// A bounded DER TLV location within one input buffer.
#[derive(Clone, Copy, Debug)]
struct Tlv {
    tag: u8,
    value_start: usize,
    value_end: usize,
    total_end: usize,
}

/// Parse one definite-length, single-octet-tag DER TLV.
fn der_tlv(data: &[u8], at: usize, limit: usize) -> Option<Tlv> {
    let limit = limit.min(data.len());
    if at.checked_add(2)? > limit {
        return None;
    }
    let tag = data[at];
    // The Authenticode structures used here have single-octet tags. Reject
    // high-tag-number form instead of trying to skip attacker-controlled bytes.
    if tag & 0x1f == 0x1f {
        return None;
    }
    let first_len = data[at + 1];
    let (header_len, value_len) = if first_len & 0x80 == 0 {
        (2usize, first_len as usize)
    } else {
        let n = (first_len & 0x7f) as usize;
        // DER forbids indefinite length (n=0); cap the length width to usize.
        if n == 0 || n > std::mem::size_of::<usize>() || at.checked_add(2 + n)? > limit {
            return None;
        }
        let mut len = 0usize;
        for &b in &data[at + 2..at + 2 + n] {
            len = len.checked_shl(8)?.checked_add(b as usize)?;
        }
        (2 + n, len)
    };
    let value_start = at.checked_add(header_len)?;
    let value_end = value_start.checked_add(value_len)?;
    if value_end > limit {
        return None;
    }
    Some(Tlv {
        tag,
        value_start,
        value_end,
        total_end: value_end,
    })
}

fn next_tlv(data: &[u8], pos: &mut usize, limit: usize) -> Option<Tlv> {
    let tlv = der_tlv(data, *pos, limit)?;
    *pos = tlv.total_end;
    Some(tlv)
}

fn certificate_info(der: &[u8]) -> Option<PeCertificate> {
    let (rem, cert) = parse_x509_certificate(der).ok()?;
    if !rem.is_empty() {
        return None;
    }
    let common_name = cert
        .subject()
        .iter_common_name()
        .find_map(|cn| cn.as_str().ok().map(ToOwned::to_owned));
    let code_signing = cert
        .extended_key_usage()
        .ok()
        .flatten()
        .map(|eku| eku.value.code_signing)
        .unwrap_or(false);
    let validity = cert.validity();
    let algorithm_name = |oid: &x509_parser::der_parser::oid::Oid<'_>| {
        let id = oid.to_id_string();
        x509_parser::objects::oid2sn(oid, x509_parser::objects::oid_registry())
            .map(|name| format!("{name} ({id})"))
            .unwrap_or(id)
    };
    Some(PeCertificate {
        common_name,
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        not_before: validity
            .not_before
            .to_rfc2822()
            .unwrap_or_else(|_| validity.not_before.to_string()),
        not_after: validity
            .not_after
            .to_rfc2822()
            .unwrap_or_else(|_| validity.not_after.to_string()),
        signature_algorithm: algorithm_name(&cert.signature_algorithm.algorithm),
        public_key_algorithm: algorithm_name(&cert.public_key().algorithm.algorithm),
        sha256: crate::hashes::sha256_hex(der),
        is_ca: cert.is_ca(),
        code_signing,
    })
}

/// Extract the CertificateSet from a PKCS#7 ContentInfo containing SignedData.
fn pkcs7_certificates(data: &[u8]) -> Result<Vec<PeCertificate>, String> {
    const SIGNED_DATA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

    let content = der_tlv(data, 0, data.len()).ok_or("malformed PKCS#7 ContentInfo")?;
    if content.tag != 0x30 {
        return Err("PKCS#7 ContentInfo is not a sequence".into());
    }
    let mut p = content.value_start;
    let oid = next_tlv(data, &mut p, content.value_end).ok_or("missing PKCS#7 content type")?;
    if oid.tag != 0x06 || &data[oid.value_start..oid.value_end] != SIGNED_DATA_OID {
        return Err("PKCS#7 content is not SignedData".into());
    }
    let wrapped =
        next_tlv(data, &mut p, content.value_end).ok_or("missing PKCS#7 SignedData content")?;
    if wrapped.tag != 0xa0 {
        return Err("PKCS#7 SignedData content is not [0]".into());
    }
    let signed = der_tlv(data, wrapped.value_start, wrapped.value_end)
        .ok_or("malformed PKCS#7 SignedData")?;
    if signed.tag != 0x30 {
        return Err("PKCS#7 SignedData is not a sequence".into());
    }

    // SignedData starts with version, digestAlgorithms, and encapContentInfo.
    let mut q = signed.value_start;
    for expected in [0x02, 0x31, 0x30] {
        let field =
            next_tlv(data, &mut q, signed.value_end).ok_or("truncated PKCS#7 SignedData")?;
        if field.tag != expected {
            return Err("unexpected PKCS#7 SignedData layout".into());
        }
    }

    while q < signed.value_end {
        let field = next_tlv(data, &mut q, signed.value_end)
            .ok_or("malformed optional PKCS#7 SignedData field")?;
        if field.tag != 0xa0 {
            continue;
        }
        // CertificateSet is [0] IMPLICIT, so its value is a concatenation of
        // CertificateChoices rather than an inner SET TLV.
        let mut certs = Vec::new();
        let mut cpos = field.value_start;
        let mut choices = 0usize;
        while cpos < field.value_end {
            if choices >= MAX_PKCS7_CERTIFICATE_CHOICES {
                return Err("PKCS#7 certificate set exceeds 256-entry limit".into());
            }
            choices += 1;
            let start = cpos;
            let choice = next_tlv(data, &mut cpos, field.value_end)
                .ok_or("malformed PKCS#7 certificate choice")?;
            if choice.tag == 0x30 {
                if choice.total_end - start > MAX_X509_DER_SIZE {
                    return Err("X.509 certificate exceeds 1 MiB limit".into());
                }
                if let Some(cert) = certificate_info(&data[start..choice.total_end]) {
                    certs.push(cert);
                }
            }
        }
        return Ok(certs);
    }
    Err("PKCS#7 SignedData has no certificate set".into())
}

fn push_warning(warnings: &mut Vec<String>, warning: impl Into<String>) {
    let warning = warning.into();
    if !warnings.iter().any(|w| w == &warning) {
        warnings.push(warning);
    }
}

/// Parse a PE Security Directory. `offset` and `size` are both taken directly
/// from optional-header Data Directory entry 4.
pub(crate) fn parse_security_directory(data: &[u8], offset: usize, size: usize) -> PeAuthenticode {
    let mut out = PeAuthenticode {
        file_offset: offset,
        declared_size: size,
        entries: 0,
        pkcs7_entries: 0,
        certificates: Vec::new(),
        warning: None,
    };
    let mut warnings = Vec::new();
    let Some(declared_end) = offset.checked_add(size) else {
        out.warning = Some("certificate table range overflows".into());
        return out;
    };
    if offset >= data.len() {
        out.warning = Some("certificate table starts beyond end of file".into());
        return out;
    }
    let end = declared_end.min(data.len());
    if declared_end > data.len() {
        push_warning(&mut warnings, "certificate table is truncated");
    }

    let mut pos = offset;
    let mut fingerprints = HashSet::new();
    for _ in 0..MAX_WIN_CERTIFICATE_ENTRIES {
        if pos >= end || data[pos..end].iter().all(|&b| b == 0) {
            break;
        }
        if pos.saturating_add(8) > end {
            push_warning(&mut warnings, "truncated WIN_CERTIFICATE header");
            break;
        }
        let length = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        let certificate_type = u16::from_le_bytes(data[pos + 6..pos + 8].try_into().unwrap());
        if length < 8 {
            push_warning(&mut warnings, "invalid WIN_CERTIFICATE length");
            break;
        }
        let Some(entry_end) = pos.checked_add(length) else {
            push_warning(&mut warnings, "WIN_CERTIFICATE range overflows");
            break;
        };
        if entry_end > end {
            push_warning(&mut warnings, "truncated WIN_CERTIFICATE record");
            break;
        }
        out.entries += 1;
        if certificate_type == 0x0002 {
            out.pkcs7_entries += 1;
            match pkcs7_certificates(&data[pos + 8..entry_end]) {
                Ok(certs) => {
                    for cert in certs {
                        if fingerprints.insert(cert.sha256.clone()) {
                            out.certificates.push(cert);
                        }
                    }
                }
                Err(e) => push_warning(&mut warnings, e),
            }
        }
        let Some(next) = entry_end.checked_add(7).map(|v| v & !7) else {
            push_warning(&mut warnings, "WIN_CERTIFICATE alignment overflows");
            break;
        };
        if next <= pos {
            push_warning(&mut warnings, "WIN_CERTIFICATE parser made no progress");
            break;
        }
        pos = next;
    }
    if out.entries == MAX_WIN_CERTIFICATE_ENTRIES
        && pos < end
        && data[pos..end].iter().any(|&b| b != 0)
    {
        push_warning(&mut warnings, "certificate table exceeds 64-entry limit");
    }
    if out.entries == 0 && warnings.is_empty() {
        push_warning(&mut warnings, "empty certificate table");
    }
    if !warnings.is_empty() {
        out.warning = Some(warnings.join("; "));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        assert!(value.len() < 128);
        let mut out = vec![tag, value.len() as u8];
        out.extend_from_slice(value);
        out
    }

    fn minimal_signed_data() -> Vec<u8> {
        let mut signed_fields = Vec::new();
        signed_fields.extend(tlv(0x02, &[1])); // version
        signed_fields.extend(tlv(0x31, &[])); // digestAlgorithms
        signed_fields.extend(tlv(0x30, &[])); // encapContentInfo
        signed_fields.extend(tlv(0x31, &[])); // signerInfos
        let signed = tlv(0x30, &signed_fields);
        let wrapped = tlv(0xa0, &signed);
        let mut content = tlv(
            0x06,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02],
        );
        content.extend(wrapped);
        tlv(0x30, &content)
    }

    #[test]
    fn inventories_pkcs7_entry_without_claiming_verification() {
        let pkcs7 = minimal_signed_data();
        let length = 8 + pkcs7.len();
        let padded = (length + 7) & !7;
        let mut data = vec![0u8; 16 + padded];
        data[16..20].copy_from_slice(&(length as u32).to_le_bytes());
        data[20..22].copy_from_slice(&0x0200u16.to_le_bytes());
        data[22..24].copy_from_slice(&0x0002u16.to_le_bytes());
        data[24..24 + pkcs7.len()].copy_from_slice(&pkcs7);

        let info = parse_security_directory(&data, 16, padded);
        assert!(info.signature_present());
        assert_eq!(info.entries, 1);
        assert_eq!(info.pkcs7_entries, 1);
        assert!(info.certificates.is_empty());
        assert!(info
            .warning
            .as_deref()
            .unwrap()
            .contains("no certificate set"));
    }

    #[test]
    fn rejects_out_of_file_directory_without_panicking() {
        let info = parse_security_directory(&[0u8; 32], usize::MAX - 4, 16);
        assert!(!info.signature_present());
        assert_eq!(
            info.warning.as_deref(),
            Some("certificate table range overflows")
        );
    }

    #[test]
    fn caps_win_certificate_entry_count() {
        let entries = MAX_WIN_CERTIFICATE_ENTRIES + 1;
        let mut data = vec![0u8; entries * 8];
        for record in data.chunks_exact_mut(8) {
            record[..4].copy_from_slice(&8u32.to_le_bytes());
            record[4..6].copy_from_slice(&0x0200u16.to_le_bytes());
            record[6..8].copy_from_slice(&0x0001u16.to_le_bytes());
        }
        let info = parse_security_directory(&data, 0, data.len());
        assert_eq!(info.entries, MAX_WIN_CERTIFICATE_ENTRIES);
        assert!(info
            .warning
            .as_deref()
            .unwrap()
            .contains("exceeds 64-entry limit"));
    }
}
