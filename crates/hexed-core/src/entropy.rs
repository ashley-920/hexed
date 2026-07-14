//! Shannon entropy in bits per byte (0.0..=8.0). High values (> ~7.0) indicate
//! compressed / encrypted / packed data — a classic malware-triage signal.

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Downsample `data` into `samples` chunks and return each chunk's entropy —
/// a compact profile for a visual entropy strip / minimap.
pub fn entropy_profile(data: &[u8], samples: usize) -> Vec<f32> {
    if data.is_empty() || samples == 0 {
        return Vec::new();
    }
    let chunk = data.len().div_ceil(samples);
    let mut out = Vec::with_capacity(samples);
    let mut i = 0;
    while i < data.len() {
        let end = (i + chunk).min(data.len());
        out.push(shannon_entropy(&data[i..end]) as f32);
        i = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_has_expected_shape() {
        // 512 low-entropy bytes then 512 high-entropy -> low then high samples
        let mut d = vec![0u8; 512];
        d.extend((0..512).map(|i| (i * 61 + 7) as u8));
        let p = entropy_profile(&d, 2);
        assert_eq!(p.len(), 2);
        assert!(p[0] < 1.0 && p[1] > 5.0);
    }

    #[test]
    fn bounds_and_known_values() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[0x41; 100]), 0.0); // one symbol -> 0 bits

        // every byte value once -> maximal 8 bits/byte
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-9);

        // two equiprobable symbols -> 1 bit/byte
        assert!((shannon_entropy(b"ABABAB") - 1.0).abs() < 1e-9);
    }
}
