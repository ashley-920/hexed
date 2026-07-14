//! hexed-bt — the `.bt` binary-template engine (P2).
//!
//! 010 Editor's template language is a C dialect: `struct`/`union`/`enum`,
//! typedefs, control flow, functions, and file-mapped variable declarations
//! that consume bytes as they run. This crate builds it up in layers — lexer
//! first, then parser, then a tree-walking interpreter over a byte buffer.

pub mod ast;
pub mod interp;
pub mod lexer;
pub mod parser;

pub use interp::{interpret, run, Node, RunError, Template, Value};
pub use lexer::{tokenize, LexError, TokKind, Token};
pub use parser::{parse, ParseError};
