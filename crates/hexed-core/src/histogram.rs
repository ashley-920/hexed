//! Byte-frequency analysis: a 256-bin count of how often each byte value
//! occurs. Useful for spotting padding, dominant XOR keys, and encoded regions
//! at a glance (e.g. a huge `0x00` bar for zero-padding, a flat spread for
//! compressed/encrypted data).

/// A 256-bin histogram over a byte slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Histogram {
    pub counts: [u64; 256],
    pub total: u64,
}

impl Default for Histogram {
    fn default() -> Self {
        Histogram {
            counts: [0; 256],
            total: 0,
        }
    }
}

impl Histogram {
    /// The largest single-value count (for scaling a bar chart).
    pub fn max_count(&self) -> u64 {
        self.counts.iter().copied().max().unwrap_or(0)
    }

    /// How many distinct byte values appear at least once (0..=256).
    pub fn distinct(&self) -> usize {
        self.counts.iter().filter(|&&c| c > 0).count()
    }

    /// The `n` most frequent byte values as `(value, count)`, descending.
    pub fn top(&self, n: usize) -> Vec<(u8, u64)> {
        let mut pairs: Vec<(u8, u64)> = self
            .counts
            .iter()
            .enumerate()
            .filter(|(_, &c)| c > 0)
            .map(|(v, &c)| (v as u8, c))
            .collect();
        // Descending by count, then ascending by value for a stable order.
        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        pairs.truncate(n);
        pairs
    }

    /// Fraction (0.0..=1.0) of the data made up of byte value `v`.
    pub fn fraction(&self, v: u8) -> f32 {
        if self.total == 0 {
            0.0
        } else {
            self.counts[v as usize] as f32 / self.total as f32
        }
    }
}

/// Count byte frequencies over `data`.
pub fn byte_histogram(data: &[u8]) -> Histogram {
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    Histogram {
        counts,
        total: data.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_and_total() {
        let h = byte_histogram(b"AAABBC");
        assert_eq!(h.total, 6);
        assert_eq!(h.counts[b'A' as usize], 3);
        assert_eq!(h.counts[b'B' as usize], 2);
        assert_eq!(h.counts[b'C' as usize], 1);
        assert_eq!(h.max_count(), 3);
        assert_eq!(h.distinct(), 3);
    }

    #[test]
    fn top_values_ordered() {
        let h = byte_histogram(b"AAABBC");
        assert_eq!(h.top(2), vec![(b'A', 3), (b'B', 2)]);
        // fraction of 'A' is 3/6 = 0.5
        assert!((h.fraction(b'A') - 0.5).abs() < 1e-6);
    }

    #[test]
    fn empty() {
        let h = byte_histogram(&[]);
        assert_eq!(h.total, 0);
        assert_eq!(h.max_count(), 0);
        assert_eq!(h.distinct(), 0);
        assert!(h.top(4).is_empty());
        assert_eq!(h.fraction(0), 0.0);
    }

    #[test]
    fn all_same_byte() {
        let h = byte_histogram(&[0xFFu8; 10]);
        assert_eq!(h.distinct(), 1);
        assert_eq!(h.top(3), vec![(0xFF, 10)]);
        assert_eq!(h.fraction(0xFF), 1.0);
    }
}
