//! Byte-level binary diff.
//!
//! An **aligned** comparison: byte *i* of A is compared to byte *i* of B (no
//! insertion/deletion realignment). This is the fast, predictable default of
//! most hex-diff tools and is O(n) — ideal for spotting patched bytes between
//! two variants of the same file. Differing bytes are coalesced into runs so
//! the UI can tint and step through them.

/// A maximal run of consecutive differing byte offsets in the aligned region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiffRun {
    pub start: usize,
    pub len: usize,
}

impl DiffRun {
    pub fn end(&self) -> usize {
        self.start + self.len
    }
}

/// The result of an aligned diff of two buffers.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DiffResult {
    pub len_a: usize,
    pub len_b: usize,
    /// Bytes actually compared: `min(len_a, len_b)`.
    pub compared: usize,
    /// Equal bytes within the compared region.
    pub equal: usize,
    /// Differing bytes within the compared region.
    pub differing: usize,
    /// First differing offset, if any.
    pub first_diff: Option<usize>,
    /// Coalesced runs of differing bytes.
    pub runs: Vec<DiffRun>,
    /// Bytes present only in the longer file (`|len_a - len_b|`).
    pub tail_extra: usize,
}

impl DiffResult {
    /// True if the buffers are byte-for-byte identical.
    pub fn identical(&self) -> bool {
        self.differing == 0 && self.tail_extra == 0
    }
    /// Fraction of the compared region that matched (1.0 if nothing to compare).
    pub fn similarity(&self) -> f32 {
        if self.compared == 0 {
            1.0
        } else {
            self.equal as f32 / self.compared as f32
        }
    }
}

/// Aligned byte diff of `a` and `b`.
pub fn diff_aligned(a: &[u8], b: &[u8]) -> DiffResult {
    let compared = a.len().min(b.len());
    let mut runs: Vec<DiffRun> = Vec::new();
    let mut differing = 0usize;
    let mut first_diff = None;
    let mut run_start: Option<usize> = None;

    for i in 0..compared {
        if a[i] != b[i] {
            differing += 1;
            if first_diff.is_none() {
                first_diff = Some(i);
            }
            if run_start.is_none() {
                run_start = Some(i);
            }
        } else if let Some(s) = run_start.take() {
            runs.push(DiffRun { start: s, len: i - s });
        }
    }
    if let Some(s) = run_start {
        runs.push(DiffRun { start: s, len: compared - s });
    }

    DiffResult {
        len_a: a.len(),
        len_b: b.len(),
        compared,
        equal: compared - differing,
        differing,
        first_diff,
        runs,
        tail_extra: a.len().abs_diff(b.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_buffers() {
        let d = diff_aligned(b"hello", b"hello");
        assert!(d.identical());
        assert_eq!(d.differing, 0);
        assert_eq!(d.first_diff, None);
        assert!(d.runs.is_empty());
        assert_eq!(d.similarity(), 1.0);
    }

    #[test]
    fn single_and_coalesced_runs() {
        //             0123456789
        let a = b"AAAAAAAAAA";
        let b = b"AABBAAABBA";
        let d = diff_aligned(a, b);
        assert_eq!(d.first_diff, Some(2));
        assert_eq!(d.differing, 4);
        assert_eq!(d.equal, 6);
        // runs: [2..4) and [7..9)
        assert_eq!(
            d.runs,
            vec![
                DiffRun { start: 2, len: 2 },
                DiffRun { start: 7, len: 2 },
            ]
        );
        assert_eq!(d.runs[1].end(), 9);
    }

    #[test]
    fn different_lengths() {
        let d = diff_aligned(b"ABC", b"ABCDEF");
        assert_eq!(d.compared, 3);
        assert_eq!(d.differing, 0);
        assert_eq!(d.tail_extra, 3);
        assert!(!d.identical()); // tail makes them non-identical
        assert_eq!(d.len_a, 3);
        assert_eq!(d.len_b, 6);
    }

    #[test]
    fn all_different() {
        let d = diff_aligned(&[0, 0, 0], &[1, 1, 1]);
        assert_eq!(d.differing, 3);
        assert_eq!(d.runs, vec![DiffRun { start: 0, len: 3 }]);
        assert_eq!(d.similarity(), 0.0);
    }

    #[test]
    fn empty_inputs() {
        let d = diff_aligned(&[], &[]);
        assert!(d.identical());
        assert_eq!(d.compared, 0);
        assert_eq!(d.similarity(), 1.0);
    }
}
