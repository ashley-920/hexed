//! Lexer for the `.bt` template language (a C dialect).
//!
//! Produces a flat token stream (ending in [`TokKind::Eof`]) with byte spans,
//! handling identifiers, integer/float literals (decimal + `0x` hex), string
//! and char literals with escapes, `//` and `/* */` comments, and C-style
//! operators via maximal munch. Keywords are left as identifiers for the parser
//! to classify.

#[derive(Clone, Debug, PartialEq)]
pub enum TokKind {
    Ident(String),
    Int(i64),
    Float(f64),
    Str(String),
    Char(char),
    /// An operator or delimiter, e.g. `"=="`, `"<<"`, `"{"`, `";"`.
    Punct(&'static str),
    Eof,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Token {
    pub kind: TokKind,
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub enum LexError {
    /// Unterminated string, char, or block comment (byte offset of the start).
    Unterminated(usize),
    /// Malformed number literal.
    BadNumber(usize),
    /// Unexpected character.
    Unexpected(usize, char),
}

impl std::fmt::Display for LexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LexError::Unterminated(o) => write!(f, "unterminated literal at byte {o}"),
            LexError::BadNumber(o) => write!(f, "invalid number at byte {o}"),
            LexError::Unexpected(o, c) => write!(f, "unexpected character {c:?} at byte {o}"),
        }
    }
}

/// Operators/delimiters, longest first so maximal munch picks `>>=` over `>>`.
const PUNCTS: &[&str] = &[
    ">>=", "<<=", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>", "++", "--", "+=", "-=", "*=",
    "/=", "%=", "&=", "|=", "^=", "->", "::", "+", "-", "*", "/", "%", "=", "<", ">", "!", "&",
    "|", "^", "~", "?", "(", ")", "{", "}", "[", "]", ";", ",", ".", ":",
];

pub fn tokenize(src: &str) -> Result<Vec<Token>, LexError> {
    let mut lx = Lexer {
        src: src.as_bytes(),
        pos: 0,
    };
    let mut out = Vec::new();
    loop {
        let tok = lx.next_token()?;
        let eof = tok.kind == TokKind::Eof;
        out.push(tok);
        if eof {
            return Ok(out);
        }
    }
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl Lexer<'_> {
    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }
    fn peek2(&self) -> Option<u8> {
        self.src.get(self.pos + 1).copied()
    }

    fn skip_trivia(&mut self) -> Result<(), LexError> {
        loop {
            match self.peek() {
                Some(c) if c.is_ascii_whitespace() => self.pos += 1,
                Some(b'/') if self.peek2() == Some(b'/') => {
                    while !matches!(self.peek(), Some(b'\n') | None) {
                        self.pos += 1;
                    }
                }
                Some(b'/') if self.peek2() == Some(b'*') => {
                    let start = self.pos;
                    self.pos += 2;
                    loop {
                        match self.peek() {
                            None => return Err(LexError::Unterminated(start)),
                            Some(b'*') if self.peek2() == Some(b'/') => {
                                self.pos += 2;
                                break;
                            }
                            _ => self.pos += 1,
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn next_token(&mut self) -> Result<Token, LexError> {
        self.skip_trivia()?;
        let start = self.pos;
        let Some(c) = self.peek() else {
            return Ok(Token { kind: TokKind::Eof, start, end: start });
        };

        if c == b'_' || c.is_ascii_alphabetic() {
            while matches!(self.peek(), Some(ch) if ch == b'_' || ch.is_ascii_alphanumeric()) {
                self.pos += 1;
            }
            let s = String::from_utf8_lossy(&self.src[start..self.pos]).into_owned();
            return Ok(Token { kind: TokKind::Ident(s), start, end: self.pos });
        }
        if c.is_ascii_digit() {
            return self.lex_number(start);
        }
        if c == b'"' {
            return self.lex_string(start);
        }
        if c == b'\'' {
            return self.lex_char(start);
        }

        for p in PUNCTS {
            if self.src[self.pos..].starts_with(p.as_bytes()) {
                self.pos += p.len();
                return Ok(Token { kind: TokKind::Punct(p), start, end: self.pos });
            }
        }
        Err(LexError::Unexpected(start, c as char))
    }

    fn lex_number(&mut self, start: usize) -> Result<Token, LexError> {
        // Hex.
        if self.peek() == Some(b'0') && matches!(self.peek2(), Some(b'x') | Some(b'X')) {
            self.pos += 2;
            let hs = self.pos;
            while matches!(self.peek(), Some(ch) if (ch as char).is_ascii_hexdigit()) {
                self.pos += 1;
            }
            if self.pos == hs {
                return Err(LexError::BadNumber(start));
            }
            let text = std::str::from_utf8(&self.src[hs..self.pos]).unwrap();
            let v = u64::from_str_radix(text, 16).map_err(|_| LexError::BadNumber(start))? as i64;
            self.skip_num_suffix();
            return Ok(Token { kind: TokKind::Int(v), start, end: self.pos });
        }

        let mut is_float = false;
        while matches!(self.peek(), Some(ch) if ch.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.peek() == Some(b'.')
            && matches!(self.peek2(), Some(d) if d.is_ascii_digit())
        {
            is_float = true;
            self.pos += 1;
            while matches!(self.peek(), Some(ch) if ch.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(ch) if ch.is_ascii_digit()) {
                self.pos += 1;
            }
        }

        let text = std::str::from_utf8(&self.src[start..self.pos]).unwrap();
        let kind = if is_float {
            TokKind::Float(text.parse().map_err(|_| LexError::BadNumber(start))?)
        } else {
            TokKind::Int(text.parse().map_err(|_| LexError::BadNumber(start))?)
        };
        self.skip_num_suffix();
        Ok(Token { kind, start, end: self.pos })
    }

    fn skip_num_suffix(&mut self) {
        while matches!(self.peek(), Some(b'u' | b'U' | b'l' | b'L' | b'f' | b'F')) {
            self.pos += 1;
        }
    }

    fn lex_string(&mut self, start: usize) -> Result<Token, LexError> {
        self.pos += 1; // opening quote
        let mut s = String::new();
        loop {
            match self.peek() {
                None => return Err(LexError::Unterminated(start)),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(Token { kind: TokKind::Str(s), start, end: self.pos });
                }
                Some(b'\\') => {
                    self.pos += 1;
                    s.push(self.escape(start)?);
                }
                Some(ch) => {
                    s.push(ch as char);
                    self.pos += 1;
                }
            }
        }
    }

    fn lex_char(&mut self, start: usize) -> Result<Token, LexError> {
        self.pos += 1; // opening quote
        let ch = match self.peek() {
            None => return Err(LexError::Unterminated(start)),
            Some(b'\\') => {
                self.pos += 1;
                self.escape(start)?
            }
            Some(c) => {
                self.pos += 1;
                c as char
            }
        };
        if self.peek() != Some(b'\'') {
            return Err(LexError::Unterminated(start));
        }
        self.pos += 1;
        Ok(Token { kind: TokKind::Char(ch), start, end: self.pos })
    }

    /// Decode the escape sequence after a backslash (which has been consumed).
    fn escape(&mut self, start: usize) -> Result<char, LexError> {
        let e = self.peek().ok_or(LexError::Unterminated(start))?;
        self.pos += 1;
        Ok(match e {
            b'n' => '\n',
            b't' => '\t',
            b'r' => '\r',
            b'0' => '\0',
            b'\\' => '\\',
            b'"' => '"',
            b'\'' => '\'',
            b'x' => {
                let mut v = 0u32;
                let mut n = 0;
                while n < 2 {
                    match self.peek().map(|c| (c as char).to_digit(16)) {
                        Some(Some(d)) => {
                            v = v * 16 + d;
                            self.pos += 1;
                            n += 1;
                        }
                        _ => break,
                    }
                }
                char::from_u32(v).unwrap_or('\u{FFFD}')
            }
            other => other as char,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(src: &str) -> Vec<TokKind> {
        tokenize(src).unwrap().into_iter().map(|t| t.kind).collect()
    }

    #[test]
    fn idents_numbers_puncts() {
        assert_eq!(
            kinds("uint32 length = 0x10 + 3;"),
            vec![
                TokKind::Ident("uint32".into()),
                TokKind::Ident("length".into()),
                TokKind::Punct("="),
                TokKind::Int(16),
                TokKind::Punct("+"),
                TokKind::Int(3),
                TokKind::Punct(";"),
                TokKind::Eof,
            ]
        );
    }

    #[test]
    fn maximal_munch_operators() {
        assert_eq!(
            kinds("a >>= b << c == d"),
            vec![
                TokKind::Ident("a".into()),
                TokKind::Punct(">>="),
                TokKind::Ident("b".into()),
                TokKind::Punct("<<"),
                TokKind::Ident("c".into()),
                TokKind::Punct("=="),
                TokKind::Ident("d".into()),
                TokKind::Eof,
            ]
        );
    }

    #[test]
    fn strings_chars_escapes() {
        assert_eq!(
            kinds(r#""a\tb\x41" 'Z' '\n'"#),
            vec![
                TokKind::Str("a\tbA".into()),
                TokKind::Char('Z'),
                TokKind::Char('\n'),
                TokKind::Eof,
            ]
        );
    }

    #[test]
    fn floats_and_suffixes() {
        assert_eq!(
            kinds("1.5 2.0e3 10u 0xFFL"),
            vec![
                TokKind::Float(1.5),
                TokKind::Float(2000.0),
                TokKind::Int(10),
                TokKind::Int(255),
                TokKind::Eof,
            ]
        );
    }

    #[test]
    fn comments_skipped() {
        assert_eq!(
            kinds("a // line\n b /* block\n spanning */ c"),
            vec![
                TokKind::Ident("a".into()),
                TokKind::Ident("b".into()),
                TokKind::Ident("c".into()),
                TokKind::Eof,
            ]
        );
    }

    #[test]
    fn real_struct_snippet() {
        let src = r#"
            typedef struct {
                uint32 length <format=decimal>;
                char   type[4];
                byte   data[length];
            } CHUNK <bgcolor=cLtBlue>;
        "#;
        let toks = tokenize(src).unwrap();
        assert_eq!(toks.last().unwrap().kind, TokKind::Eof);
        // spot check a few tokens exist
        assert!(toks.iter().any(|t| t.kind == TokKind::Ident("typedef".into())));
        assert!(toks.iter().any(|t| t.kind == TokKind::Ident("CHUNK".into())));
        assert!(toks.iter().any(|t| t.kind == TokKind::Punct("<")));
    }

    #[test]
    fn errors() {
        assert_eq!(tokenize(r#""oops"#), Err(LexError::Unterminated(0)));
        assert!(matches!(tokenize("@"), Err(LexError::Unexpected(0, '@'))));
        assert_eq!(tokenize("/* unclosed"), Err(LexError::Unterminated(0)));
    }
}
