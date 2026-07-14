//! x86/x64 disassembly, built on the pure-Rust `iced-x86` decoder.
//!
//! Decodes a raw byte slice at a chosen bitness (16/32/64) and base address
//! into a flat list of [`Insn`]s — each carrying its address, file offset, raw
//! bytes, decoded text, and length. UI-agnostic: the app renders these rows and
//! maps `offset`/`len` back to a hex-grid selection.

use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

/// One decoded instruction.
#[derive(Clone, Debug, PartialEq)]
pub struct Insn {
    /// Virtual/display address (`base + offset`).
    pub address: u64,
    /// Byte offset within the input slice.
    pub offset: usize,
    /// The instruction's raw bytes.
    pub bytes: Vec<u8>,
    /// Formatted mnemonic + operands, e.g. `mov rbp,rsp`.
    pub text: String,
    /// Instruction length in bytes.
    pub len: usize,
    /// True if the decoder could not decode a valid instruction here.
    pub invalid: bool,
}

impl Insn {
    /// The raw bytes as space-separated hex, e.g. `48 89 E5`.
    pub fn bytes_hex(&self) -> String {
        let mut s = String::with_capacity(self.bytes.len() * 3);
        for (i, b) in self.bytes.iter().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push_str(&format!("{b:02X}"));
        }
        s
    }
}

/// Valid x86 decode widths.
pub fn valid_bitness(bitness: u32) -> u32 {
    match bitness {
        16 | 32 | 64 => bitness,
        _ => 64,
    }
}

/// Disassemble `code` at `bitness` (16/32/64), starting the address counter at
/// `base`. Stops after `max_insns` instructions (0 = unlimited) or when the
/// input is exhausted.
pub fn disassemble(code: &[u8], bitness: u32, base: u64, max_insns: usize) -> Vec<Insn> {
    let bitness = valid_bitness(bitness);
    let mut decoder = Decoder::with_ip(bitness, code, base, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    {
        let o = formatter.options_mut();
        o.set_uppercase_hex(false);
        o.set_space_after_operand_separator(false);
    }
    let mut out = Vec::new();
    let mut instr = Instruction::default();
    let mut text = String::new();
    while decoder.can_decode() {
        if max_insns != 0 && out.len() >= max_insns {
            break;
        }
        let pos = decoder.position();
        decoder.decode_out(&mut instr);
        let len = instr.len().max(1);
        let end = (pos + len).min(code.len());
        text.clear();
        formatter.format(&instr, &mut text);
        out.push(Insn {
            address: instr.ip(),
            offset: pos,
            bytes: code[pos..end].to_vec(),
            text: text.clone(),
            len,
            invalid: instr.is_invalid(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_x64_prologue() {
        // push rbp ; mov rbp,rsp ; nop ; ret
        let code = [0x55, 0x48, 0x89, 0xE5, 0x90, 0xC3];
        let insns = disassemble(&code, 64, 0x1000, 0);
        assert_eq!(insns.len(), 4);
        assert_eq!(insns[0].address, 0x1000);
        assert_eq!(insns[0].text, "push rbp");
        assert_eq!(insns[1].text, "mov rbp,rsp");
        assert_eq!(insns[1].offset, 1);
        assert_eq!(insns[1].len, 3);
        assert_eq!(insns[1].bytes_hex(), "48 89 E5");
        assert_eq!(insns[2].text, "nop");
        assert_eq!(insns[3].text, "ret");
        // addresses advance by instruction length
        assert_eq!(insns[3].address, 0x1000 + 5);
    }

    #[test]
    fn respects_bitness() {
        // 0x48 in 32-bit mode is `dec eax`, not a REX prefix.
        let code = [0x48];
        let insns = disassemble(&code, 32, 0, 0);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].text, "dec eax");
    }

    #[test]
    fn caps_instruction_count() {
        let code = [0x90; 100]; // 100 nops
        let insns = disassemble(&code, 64, 0, 10);
        assert_eq!(insns.len(), 10);
    }

    #[test]
    fn call_shows_target_address() {
        // e8 rel32 call, relative to the address after the instruction.
        let code = [0xE8, 0x00, 0x00, 0x00, 0x00]; // call $+5 (target 0x1005)
        let insns = disassemble(&code, 64, 0x1000, 0);
        assert_eq!(insns.len(), 1);
        assert!(insns[0].text.contains("1005"), "got {}", insns[0].text);
    }
}
