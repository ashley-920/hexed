//! In-place block transforms over a selected byte range: the bitwise and
//! arithmetic operations 010 Editor exposes under Edit ▸ Operations.

/// A reversible-or-not block operation, handy for wiring buttons and for
/// recording an applied transform for undo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockOp {
    Add(u8),
    Sub(u8),
    And(u8),
    Or(u8),
    Xor(u8),
    Not,
    /// Two's-complement negation, per byte.
    Neg,
    /// Rotate left by n bits (n mod 8), per byte.
    Rol(u32),
    /// Rotate right by n bits (n mod 8), per byte.
    Ror(u32),
    /// Reverse the entire selection.
    Reverse,
    /// Swap bytes within each 2-byte group.
    ByteSwap16,
    /// Swap bytes within each 4-byte group.
    ByteSwap32,
}

/// Apply a [`BlockOp`] to `data` in place.
pub fn apply(op: BlockOp, data: &mut [u8]) {
    match op {
        BlockOp::Add(k) => data.iter_mut().for_each(|b| *b = b.wrapping_add(k)),
        BlockOp::Sub(k) => data.iter_mut().for_each(|b| *b = b.wrapping_sub(k)),
        BlockOp::And(k) => data.iter_mut().for_each(|b| *b &= k),
        BlockOp::Or(k) => data.iter_mut().for_each(|b| *b |= k),
        BlockOp::Xor(k) => data.iter_mut().for_each(|b| *b ^= k),
        BlockOp::Not => data.iter_mut().for_each(|b| *b = !*b),
        BlockOp::Neg => data
            .iter_mut()
            .for_each(|b| *b = (*b as i8).wrapping_neg() as u8),
        BlockOp::Rol(n) => {
            let n = n % 8;
            data.iter_mut().for_each(|b| *b = b.rotate_left(n));
        }
        BlockOp::Ror(n) => {
            let n = n % 8;
            data.iter_mut().for_each(|b| *b = b.rotate_right(n));
        }
        BlockOp::Reverse => data.reverse(),
        BlockOp::ByteSwap16 => data.chunks_exact_mut(2).for_each(|c| c.swap(0, 1)),
        BlockOp::ByteSwap32 => data.chunks_exact_mut(4).for_each(|c| {
            c.swap(0, 3);
            c.swap(1, 2);
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_sub_roundtrip() {
        let mut d = vec![0u8, 1, 250, 255];
        apply(BlockOp::Add(10), &mut d);
        apply(BlockOp::Sub(10), &mut d);
        assert_eq!(d, vec![0, 1, 250, 255]);
    }

    #[test]
    fn not_is_involution() {
        let mut d = vec![0x00, 0xAA, 0xFF];
        apply(BlockOp::Not, &mut d);
        assert_eq!(d, vec![0xFF, 0x55, 0x00]);
        apply(BlockOp::Not, &mut d);
        assert_eq!(d, vec![0x00, 0xAA, 0xFF]);
    }

    #[test]
    fn rol_ror_roundtrip() {
        let mut d = vec![0b1000_0001u8, 0x3C];
        apply(BlockOp::Rol(3), &mut d);
        apply(BlockOp::Ror(3), &mut d);
        assert_eq!(d, vec![0b1000_0001, 0x3C]);
    }

    #[test]
    fn byteswap_variants() {
        let mut d = vec![0x01, 0x02, 0x03, 0x04];
        apply(BlockOp::ByteSwap16, &mut d);
        assert_eq!(d, vec![0x02, 0x01, 0x04, 0x03]);

        let mut e = vec![0x01, 0x02, 0x03, 0x04];
        apply(BlockOp::ByteSwap32, &mut e);
        assert_eq!(e, vec![0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn neg_is_twos_complement() {
        let mut d = vec![1u8, 255, 0];
        apply(BlockOp::Neg, &mut d);
        // -1 -> 0xFF, -(-1) -> 1, -0 -> 0
        assert_eq!(d, vec![255, 1, 0]);
    }
}
