//! Lightweight, dependency-free syntax highlighting for the Text view.
//!
//! A single generic tokenizer (driven by a per-language [`Spec`]) covers the
//! script / C-like languages malware analysts actually meet — JS, PowerShell,
//! VBScript, Python, shell, batch, PHP, and friends — plus small dedicated
//! tokenizers for JSON, XML/HTML, and Markdown. The language is auto-detected
//! from the file extension, falling back to a content sniff. Everything is byte
//! offsets into the text, and every span boundary lands on an ASCII byte (words
//! and strings absorb any UTF-8 continuation bytes), so slicing is always valid.

use eframe::egui::{self, text::LayoutJob, Color32, FontId, TextFormat};

use crate::theme::Palette;

/// Detected source language for the Text view.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Lang {
    Plain,
    Generic(Spec),
    Json,
    Xml,
    Markdown,
    Yara,
}

/// A token class, mapped to a colour by [`SyntaxColors::of`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tok {
    Comment,
    Str,
    Keyword,
    Number,
    Literal,
    Func,
    Prop,
    Tag,
    Attr,
    Heading,
    Link,
}

/// Syntax colours, derived from the active [`Palette`] so highlighting adapts to
/// every theme. `Hash`/`Eq`/`Copy` so it can key the frame cache.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SyntaxColors {
    comment: Color32,
    string: Color32,
    keyword: Color32,
    number: Color32,
    literal: Color32,
    func: Color32,
    prop: Color32,
    tag: Color32,
    attr: Color32,
    heading: Color32,
    link: Color32,
    normal: Color32,
}

impl SyntaxColors {
    pub fn from(pal: &Palette) -> Self {
        // Keywords / tags / headings normally take the theme accent. But on a
        // theme whose accent is itself green (≈ strings) or amber (≈ numbers) that
        // would be unreadable — and the palette has no other vivid hue that clears
        // BOTH green and amber (salmon is too close to amber) — so fall back to a
        // fixed, dark-background-legible blue there. Carbon (cyan) and Violet keep
        // their accent; Amber and Phosphor use the blue.
        let keyword = if near(pal.accent, pal.ok) || near(pal.accent, pal.warn) {
            Color32::from_rgb(0x82, 0xaa, 0xff)
        } else {
            pal.accent
        };
        let func = pal.b_high;
        SyntaxColors {
            comment: pal.faint,
            string: pal.ok,
            keyword,
            number: pal.warn,
            literal: pal.warn,
            func,
            prop: pal.b_print,
            tag: keyword,
            attr: pal.b_other,
            heading: keyword,
            link: pal.b_print,
            normal: pal.text,
        }
    }
    fn of(&self, t: Tok) -> Color32 {
        match t {
            Tok::Comment => self.comment,
            Tok::Str => self.string,
            Tok::Keyword => self.keyword,
            Tok::Number => self.number,
            Tok::Literal => self.literal,
            Tok::Func => self.func,
            Tok::Prop => self.prop,
            Tok::Tag => self.tag,
            Tok::Attr => self.attr,
            Tok::Heading => self.heading,
            Tok::Link => self.link,
        }
    }
}

/// Whether two colours are close enough (squared RGB distance) to read as the
/// same on screen — used to detect a theme accent that collides with the fixed
/// string/number colours.
fn near(a: Color32, b: Color32) -> bool {
    let sq = |x: u8, y: u8| (x as i32 - y as i32).pow(2);
    sq(a.r(), b.r()) + sq(a.g(), b.g()) + sq(a.b(), b.b()) < 3600
}

/// A coloured run: `[start, end)` bytes → token class.
struct Span {
    start: usize,
    end: usize,
    tok: Tok,
    italic: bool,
    underline: bool,
}
impl Span {
    fn new(start: usize, end: usize, tok: Tok) -> Self {
        Span {
            start,
            end,
            tok,
            italic: false,
            underline: false,
        }
    }
}

/// A language spec for the generic tokenizer: comment/​string/​keyword shapes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Spec {
    line_comments: &'static [&'static str],
    block: Option<(&'static str, &'static str)>,
    strings: &'static [u8],
    keywords: &'static [&'static str],
    /// Keyword match ignores case (PowerShell, VBScript, SQL, batch).
    ci_keywords: bool,
    /// Sigil that starts a variable token (`$` for PS/shell/PHP/Perl).
    var_sigil: Option<u8>,
}

// ---- language table ---------------------------------------------------------

const KW_C: &[&str] = &[
    "if",
    "else",
    "for",
    "while",
    "do",
    "switch",
    "case",
    "default",
    "break",
    "continue",
    "return",
    "goto",
    "struct",
    "union",
    "enum",
    "typedef",
    "sizeof",
    "static",
    "const",
    "extern",
    "void",
    "int",
    "char",
    "long",
    "short",
    "float",
    "double",
    "unsigned",
    "signed",
    "class",
    "public",
    "private",
    "protected",
    "new",
    "delete",
    "this",
    "namespace",
    "using",
    "template",
    "try",
    "catch",
    "throw",
    "true",
    "false",
    "null",
    "nullptr",
];
const KW_JS: &[&str] = &[
    "var",
    "let",
    "const",
    "function",
    "return",
    "if",
    "else",
    "for",
    "while",
    "do",
    "switch",
    "case",
    "default",
    "break",
    "continue",
    "new",
    "delete",
    "typeof",
    "instanceof",
    "in",
    "of",
    "this",
    "class",
    "extends",
    "super",
    "try",
    "catch",
    "finally",
    "throw",
    "async",
    "await",
    "yield",
    "import",
    "export",
    "from",
    "as",
    "void",
    "null",
    "undefined",
    "true",
    "false",
    "eval",
    "window",
    "document",
];
const KW_PY: &[&str] = &[
    "def",
    "class",
    "return",
    "if",
    "elif",
    "else",
    "for",
    "while",
    "break",
    "continue",
    "pass",
    "import",
    "from",
    "as",
    "with",
    "try",
    "except",
    "finally",
    "raise",
    "lambda",
    "yield",
    "global",
    "nonlocal",
    "in",
    "is",
    "not",
    "and",
    "or",
    "None",
    "True",
    "False",
    "self",
    "async",
    "await",
    "print",
    "exec",
    "eval",
    "__import__",
];
const KW_PS: &[&str] = &[
    "function",
    "param",
    "begin",
    "process",
    "end",
    "if",
    "else",
    "elseif",
    "switch",
    "foreach",
    "for",
    "while",
    "do",
    "until",
    "return",
    "break",
    "continue",
    "try",
    "catch",
    "finally",
    "throw",
    "filter",
    "in",
    "trap",
    "class",
    "enum",
    "using",
    "invoke-expression",
    "iex",
    "invoke-webrequest",
    "iwr",
    "downloadstring",
    "frombase64string",
    "start-process",
    "new-object",
    "add-type",
    "get-item",
    "set-item",
];
const KW_SH: &[&str] = &[
    "if", "then", "elif", "else", "fi", "for", "while", "until", "do", "done", "case", "esac",
    "in", "function", "return", "break", "continue", "local", "export", "readonly", "declare",
    "echo", "eval", "exec", "source", "curl", "wget", "chmod", "base64", "bash", "sh", "python",
];
const KW_BAT: &[&str] = &[
    "echo",
    "set",
    "if",
    "else",
    "for",
    "goto",
    "call",
    "exit",
    "rem",
    "setlocal",
    "endlocal",
    "start",
    "cmd",
    "powershell",
    "del",
    "copy",
    "move",
    "reg",
    "not",
    "exist",
    "errorlevel",
];
const KW_VBS: &[&str] = &[
    "dim",
    "set",
    "if",
    "then",
    "else",
    "elseif",
    "end",
    "for",
    "each",
    "next",
    "do",
    "loop",
    "while",
    "wend",
    "function",
    "sub",
    "call",
    "return",
    "class",
    "new",
    "with",
    "select",
    "case",
    "on",
    "error",
    "resume",
    "createobject",
    "wscript",
    "shell",
    "execute",
    "eval",
    "chr",
    "asc",
    "true",
    "false",
    "nothing",
];
const KW_PHP: &[&str] = &[
    "function",
    "return",
    "if",
    "else",
    "elseif",
    "for",
    "foreach",
    "while",
    "do",
    "switch",
    "case",
    "break",
    "continue",
    "class",
    "new",
    "public",
    "private",
    "protected",
    "static",
    "echo",
    "print",
    "require",
    "include",
    "namespace",
    "use",
    "try",
    "catch",
    "throw",
    "as",
    "true",
    "false",
    "null",
    "array",
    "eval",
    "system",
    "exec",
    "base64_decode",
    "gzinflate",
];

const fn spec(
    line_comments: &'static [&'static str],
    block: Option<(&'static str, &'static str)>,
    strings: &'static [u8],
    keywords: &'static [&'static str],
    ci_keywords: bool,
    var_sigil: Option<u8>,
) -> Spec {
    Spec {
        line_comments,
        block,
        strings,
        keywords,
        ci_keywords,
        var_sigil,
    }
}

const C_LIKE: Spec = spec(&["//"], Some(("/*", "*/")), b"\"'", KW_C, false, None);
const JS: Spec = spec(&["//"], Some(("/*", "*/")), b"\"'`", KW_JS, false, None);
const PY: Spec = spec(&["#"], None, b"\"'", KW_PY, false, None);
const PS: Spec = spec(&["#"], Some(("<#", "#>")), b"\"'", KW_PS, true, Some(b'$'));
const SH: Spec = spec(&["#"], None, b"\"'", KW_SH, false, Some(b'$'));
const BAT: Spec = spec(&["::"], None, b"\"", KW_BAT, true, Some(b'%'));
const VBS: Spec = spec(&["'"], None, b"\"", KW_VBS, true, None);
const PHP: Spec = spec(
    &["//", "#"],
    Some(("/*", "*/")),
    b"\"'",
    KW_PHP,
    false,
    Some(b'$'),
);

/// Detect the language from the file name, falling back to a content sniff.
pub fn detect(file_name: &str, text: &str) -> Lang {
    let ext = file_name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "js" | "mjs" | "cjs" | "ts" | "jsx" | "tsx" | "json5" => return Lang::Generic(JS),
        "c" | "h" | "cpp" | "cc" | "hpp" | "cs" | "java" | "go" | "rs" | "swift" | "kt" => {
            return Lang::Generic(C_LIKE)
        }
        "py" | "pyw" => return Lang::Generic(PY),
        "ps1" | "psm1" | "psd1" => return Lang::Generic(PS),
        "sh" | "bash" | "zsh" | "ksh" => return Lang::Generic(SH),
        "bat" | "cmd" => return Lang::Generic(BAT),
        "vbs" | "vbe" | "wsf" | "vb" => return Lang::Generic(VBS),
        "php" | "php5" | "phtml" | "pl" | "pm" | "rb" => return Lang::Generic(PHP),
        "json" => return Lang::Json,
        "xml" | "html" | "htm" | "xhtml" | "svg" | "xaml" | "plist" | "hta" | "config" => {
            return Lang::Xml
        }
        "md" | "markdown" | "mdown" => return Lang::Markdown,
        "yar" | "yara" => return Lang::Yara,
        _ => {}
    }
    sniff(text)
}

/// Content-based guess for files with no / unknown extension (common for dropped
/// payloads). Looks only at the leading bytes.
fn sniff(text: &str) -> Lang {
    // Only look at a bounded, char-boundary-safe prefix so detection is cheap
    // even on a large extensionless blob.
    let mut cap = text.len().min(4096);
    while cap > 0 && !text.is_char_boundary(cap) {
        cap -= 1;
    }
    let head = text[..cap].trim_start();
    let lower_first = head.lines().next().unwrap_or("").to_ascii_lowercase();
    if head.starts_with("#!") {
        if lower_first.contains("python") {
            return Lang::Generic(PY);
        }
        if lower_first.contains("php") {
            return Lang::Generic(PHP);
        }
        if lower_first.contains("node") {
            return Lang::Generic(JS);
        }
        return Lang::Generic(SH);
    }
    if head.starts_with("<?php") {
        return Lang::Generic(PHP);
    }
    // YARA: a `rule <name> {` / `import "..."` header with a condition section.
    if (head.starts_with("rule ")
        || head.starts_with("import \"")
        || head.starts_with("private rule"))
        && head.contains("condition:")
    {
        return Lang::Yara;
    }
    if head.starts_with("<?xml") || head.starts_with("<!DOCTYPE") || head.starts_with('<') {
        return Lang::Xml;
    }
    if head.starts_with('{') || head.starts_with('[') {
        return Lang::Json;
    }
    if lower_first.contains("function ") || head.contains("=>") || head.contains("var ") {
        return Lang::Generic(JS);
    }
    if head.starts_with("# ") || head.starts_with("## ") {
        return Lang::Markdown;
    }
    Lang::Plain
}

/// The languages offered in the manual override picker, with display names.
pub fn selectable() -> &'static [(&'static str, Lang)] {
    &[
        ("JavaScript / TS", Lang::Generic(JS)),
        ("C / C++ / C#", Lang::Generic(C_LIKE)),
        ("Python", Lang::Generic(PY)),
        ("PowerShell", Lang::Generic(PS)),
        ("Shell / Bash", Lang::Generic(SH)),
        ("Batch / CMD", Lang::Generic(BAT)),
        ("VBScript / VBA", Lang::Generic(VBS)),
        ("PHP / Perl", Lang::Generic(PHP)),
        ("JSON", Lang::Json),
        ("XML / HTML", Lang::Xml),
        ("Markdown", Lang::Markdown),
        ("YARA", Lang::Yara),
        ("Plain text", Lang::Plain),
    ]
}

/// Display name for a detected or picked language.
pub fn name(lang: Lang) -> &'static str {
    match lang {
        Lang::Plain => "Plain text",
        Lang::Json => "JSON",
        Lang::Xml => "XML / HTML",
        Lang::Markdown => "Markdown",
        Lang::Yara => "YARA",
        Lang::Generic(s) => selectable()
            .iter()
            .find(|(_, l)| *l == Lang::Generic(s))
            .map(|(nm, _)| *nm)
            .unwrap_or("Code"),
    }
}

// ---- job builder ------------------------------------------------------------

/// Build a coloured [`LayoutJob`] for `text` in `lang`. `wrap` is left at the
/// default; the caller sets `job.wrap.max_width` before laying it out.
pub fn layout_job(text: &str, lang: Lang, colors: &SyntaxColors, font: FontId) -> LayoutJob {
    let mut spans = Vec::new();
    match lang {
        Lang::Plain => {}
        Lang::Generic(s) => tokenize_generic(text.as_bytes(), &s, &mut spans),
        Lang::Json => tokenize_json(text.as_bytes(), &mut spans),
        Lang::Xml => tokenize_xml(text.as_bytes(), &mut spans),
        Lang::Markdown => tokenize_markdown(text.as_bytes(), &mut spans),
        Lang::Yara => tokenize_yara(text.as_bytes(), &mut spans),
    }

    let mut job = LayoutJob::default();
    let mut cursor = 0usize;
    for sp in spans {
        if sp.start < cursor || sp.end > text.len() || sp.start >= sp.end {
            continue; // defensive: never emit an out-of-order / OOB slice
        }
        if sp.start > cursor {
            append(
                &mut job,
                &text[cursor..sp.start],
                colors.normal,
                &font,
                false,
                false,
            );
        }
        let mut c = colors.of(sp.tok);
        if sp.underline {
            c = colors.link;
        }
        append(
            &mut job,
            &text[sp.start..sp.end],
            c,
            &font,
            sp.italic,
            sp.underline,
        );
        cursor = sp.end;
    }
    if cursor < text.len() {
        append(
            &mut job,
            &text[cursor..],
            colors.normal,
            &font,
            false,
            false,
        );
    }
    job
}

fn append(
    job: &mut LayoutJob,
    s: &str,
    color: Color32,
    font: &FontId,
    italics: bool,
    underline: bool,
) {
    let mut fmt = TextFormat::simple(font.clone(), color);
    fmt.italics = italics;
    if underline {
        fmt.underline = egui::Stroke::new(1.0, color);
    }
    job.append(s, 0.0, fmt);
}

// ---- generic tokenizer ------------------------------------------------------

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

fn tokenize_generic(src: &[u8], spec: &Spec, out: &mut Vec<Span>) {
    let n = src.len();
    let mut i = 0;
    while i < n {
        let b = src[i];
        // block comment
        if let Some((open, close)) = spec.block {
            if src[i..].starts_with(open.as_bytes()) {
                let start = i;
                i += open.len();
                while i < n && !src[i..].starts_with(close.as_bytes()) {
                    i += 1;
                }
                i = (i + close.len()).min(n);
                out.push(Span::new(start, i, Tok::Comment));
                continue;
            }
        }
        // line comments
        let mut lc = false;
        for m in spec.line_comments {
            if src[i..].starts_with(m.as_bytes()) {
                let start = i;
                while i < n && src[i] != b'\n' {
                    i += 1;
                }
                out.push(Span::new(start, i, Tok::Comment));
                lc = true;
                break;
            }
        }
        if lc {
            continue;
        }
        // strings
        if spec.strings.contains(&b) {
            let start = i;
            i += 1;
            while i < n {
                if src[i] == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                if src[i] == b {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push(Span::new(start, i, Tok::Str));
            continue;
        }
        // variable sigil ($x, %x%)
        if spec.var_sigil == Some(b) {
            let start = i;
            i += 1;
            while i < n && is_word(src[i]) {
                i += 1;
            }
            if i > start + 1 {
                out.push(Span::new(start, i, Tok::Prop));
                continue;
            }
        }
        // numbers
        if b.is_ascii_digit() {
            let start = i;
            while i < n && (src[i].is_ascii_alphanumeric() || src[i] == b'.' || src[i] == b'x') {
                i += 1;
            }
            out.push(Span::new(start, i, Tok::Number));
            continue;
        }
        // identifiers / keywords / calls
        if is_word(b) && !b.is_ascii_digit() {
            let start = i;
            while i < n && is_word(src[i]) {
                i += 1;
            }
            let word = &src[start..i];
            if is_keyword(word, spec) {
                out.push(Span::new(start, i, Tok::Keyword));
            } else {
                // a following '(' makes it a call
                let mut j = i;
                while j < n && (src[j] == b' ' || src[j] == b'\t') {
                    j += 1;
                }
                if j < n && src[j] == b'(' {
                    out.push(Span::new(start, i, Tok::Func));
                }
            }
            continue;
        }
        i += 1;
    }
}

fn is_keyword(word: &[u8], spec: &Spec) -> bool {
    let matches = |kw: &str| {
        if spec.ci_keywords {
            kw.len() == word.len() && kw.bytes().zip(word).all(|(a, b)| a.eq_ignore_ascii_case(b))
        } else {
            kw.as_bytes() == word
        }
    };
    spec.keywords.iter().any(|kw| matches(kw))
}

// ---- YARA -------------------------------------------------------------------

const YARA_KW: &[&str] = &[
    "rule",
    "private",
    "global",
    "import",
    "include",
    "meta",
    "strings",
    "condition",
    "and",
    "or",
    "not",
    "all",
    "any",
    "none",
    "of",
    "them",
    "for",
    "in",
    "at",
    "entrypoint",
    "filesize",
    "matches",
    "contains",
    "icontains",
    "startswith",
    "istartswith",
    "endswith",
    "iendswith",
    "defined",
    "nocase",
    "wide",
    "ascii",
    "xor",
    "base64",
    "base64wide",
    "fullword",
    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "int8",
    "int16",
    "int32",
    "int64",
    "uint8be",
    "uint16be",
    "uint32be",
    "uint64be",
    "int8be",
    "int16be",
    "int32be",
    "int64be",
];

/// If `{` at `open` begins a hex byte-pattern (only hex digits, wildcards, jumps
/// and alternation inside), return the index just past its `}`. Rule bodies —
/// whose braces hold section labels and text — return `None`, so a bare `{` is
/// left as normal punctuation.
fn yara_hex_end(src: &[u8], open: usize) -> Option<usize> {
    let n = src.len();
    let mut j = open + 1;
    let mut saw_hex = false;
    while j < n {
        let c = src[j];
        if c == b'}' {
            return if saw_hex { Some(j + 1) } else { None };
        }
        if c.is_ascii_hexdigit() {
            saw_hex = true;
        } else if !matches!(
            c,
            b' ' | b'\t'
                | b'\r'
                | b'\n'
                | b'?'
                | b'['
                | b']'
                | b'-'
                | b'('
                | b')'
                | b'|'
                | b','
                | b'~'
        ) {
            return None; // anything else -> this is a rule body, not a hex string
        }
        j += 1;
    }
    None
}

fn tokenize_yara(src: &[u8], out: &mut Vec<Span>) {
    let n = src.len();
    let mut i = 0;
    while i < n {
        let b = src[i];
        // block comment
        if src[i..].starts_with(b"/*") {
            let start = i;
            i += 2;
            while i < n && !src[i..].starts_with(b"*/") {
                i += 1;
            }
            i = (i + 2).min(n);
            out.push(Span::new(start, i, Tok::Comment));
            continue;
        }
        // line comment
        if src[i..].starts_with(b"//") {
            let start = i;
            while i < n && src[i] != b'\n' {
                i += 1;
            }
            out.push(Span::new(start, i, Tok::Comment));
            continue;
        }
        // regex  /.../modifiers  (a '/' not starting a comment and not a spaced
        // division operator, closed by an unescaped '/' on the same line)
        if b == b'/' && i + 1 < n && !matches!(src[i + 1], b'/' | b'*' | b' ' | b'\t') {
            let mut j = i + 1;
            let mut ok = false;
            while j < n && src[j] != b'\n' {
                if src[j] == b'\\' && j + 1 < n {
                    j += 2;
                    continue;
                }
                if src[j] == b'/' {
                    j += 1;
                    ok = true;
                    break;
                }
                j += 1;
            }
            if ok {
                while j < n && src[j].is_ascii_alphabetic() {
                    j += 1; // regex modifiers (i, s, ...)
                }
                out.push(Span::new(i, j, Tok::Str));
                i = j;
                continue;
            }
        }
        // text string
        if b == b'"' {
            let start = i;
            i += 1;
            while i < n {
                if src[i] == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                if src[i] == b'"' || src[i] == b'\n' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push(Span::new(start, i, Tok::Str));
            continue;
        }
        // hex byte-pattern  { .. }
        if b == b'{' {
            if let Some(end) = yara_hex_end(src, i) {
                out.push(Span::new(i, end, Tok::Str));
                i = end;
                continue;
            }
        }
        // string identifiers: $name #name @name !name
        if matches!(b, b'$' | b'#' | b'@' | b'!') {
            let start = i;
            i += 1;
            while i < n && (is_word(src[i]) || src[i] == b'*') {
                i += 1;
            }
            out.push(Span::new(start, i, Tok::Prop));
            continue;
        }
        // numbers (decimal / 0x hex, optional KB/MB suffix)
        if b.is_ascii_digit() {
            let start = i;
            while i < n && (src[i].is_ascii_alphanumeric() || src[i] == b'.') {
                i += 1;
            }
            out.push(Span::new(start, i, Tok::Number));
            continue;
        }
        // identifiers / keywords / literals
        if is_word(b) && !b.is_ascii_digit() {
            let start = i;
            while i < n && is_word(src[i]) {
                i += 1;
            }
            let word = &src[start..i];
            if word == b"true" || word == b"false" {
                out.push(Span::new(start, i, Tok::Literal));
            } else if YARA_KW.iter().any(|k| k.as_bytes() == word) {
                out.push(Span::new(start, i, Tok::Keyword));
            }
            continue;
        }
        i += 1;
    }
}

// ---- JSON -------------------------------------------------------------------

fn tokenize_json(src: &[u8], out: &mut Vec<Span>) {
    let n = src.len();
    let mut i = 0;
    while i < n {
        let b = src[i];
        if b == b'"' {
            let start = i;
            i += 1;
            while i < n {
                if src[i] == b'\\' && i + 1 < n {
                    i += 2;
                    continue;
                }
                if src[i] == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            // a following ':' makes this string an object key
            let mut j = i;
            while j < n && (src[j] == b' ' || src[j] == b'\t' || src[j] == b'\n' || src[j] == b'\r')
            {
                j += 1;
            }
            let tok = if j < n && src[j] == b':' {
                Tok::Prop
            } else {
                Tok::Str
            };
            out.push(Span::new(start, i, tok));
            continue;
        }
        if b.is_ascii_digit() || (b == b'-' && i + 1 < n && src[i + 1].is_ascii_digit()) {
            let start = i;
            i += 1;
            while i < n
                && (src[i].is_ascii_digit() || matches!(src[i], b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                i += 1;
            }
            out.push(Span::new(start, i, Tok::Number));
            continue;
        }
        if b.is_ascii_alphabetic() {
            let start = i;
            while i < n && src[i].is_ascii_alphabetic() {
                i += 1;
            }
            if matches!(&src[start..i], b"true" | b"false" | b"null") {
                out.push(Span::new(start, i, Tok::Literal));
            }
            continue;
        }
        i += 1;
    }
}

// ---- XML / HTML -------------------------------------------------------------

fn tokenize_xml(src: &[u8], out: &mut Vec<Span>) {
    let n = src.len();
    let mut i = 0;
    while i < n {
        if src[i..].starts_with(b"<!--") {
            let start = i;
            i += 4;
            while i < n && !src[i..].starts_with(b"-->") {
                i += 1;
            }
            i = (i + 3).min(n);
            out.push(Span::new(start, i, Tok::Comment));
            continue;
        }
        if src[i] == b'<' {
            let lt = i;
            i += 1;
            if i < n && (src[i] == b'/' || src[i] == b'!' || src[i] == b'?') {
                i += 1;
            }
            let name_start = i;
            while i < n && (src[i].is_ascii_alphanumeric() || matches!(src[i], b'_' | b'-' | b':'))
            {
                i += 1;
            }
            out.push(Span::new(lt, i.max(name_start), Tok::Tag));
            // attributes until '>'
            while i < n && src[i] != b'>' {
                if src[i] == b'"' || src[i] == b'\'' {
                    let q = src[i];
                    let s = i;
                    i += 1;
                    while i < n && src[i] != q {
                        i += 1;
                    }
                    i = (i + 1).min(n);
                    out.push(Span::new(s, i, Tok::Str));
                } else if src[i].is_ascii_alphabetic() {
                    let s = i;
                    while i < n && (src[i].is_ascii_alphanumeric() || matches!(src[i], b'-' | b':'))
                    {
                        i += 1;
                    }
                    out.push(Span::new(s, i, Tok::Attr));
                } else {
                    i += 1;
                }
            }
            continue;
        }
        i += 1;
    }
}

// ---- Markdown ---------------------------------------------------------------

fn tokenize_markdown(src: &[u8], out: &mut Vec<Span>) {
    let n = src.len();
    let mut i = 0;
    let mut at_line_start = true;
    while i < n {
        let b = src[i];
        if at_line_start && b == b'#' {
            let start = i;
            while i < n && src[i] != b'\n' {
                i += 1;
            }
            out.push(Span::new(start, i, Tok::Heading));
            continue;
        }
        if at_line_start
            && matches!(b, b'-' | b'*' | b'+' | b'>')
            && i + 1 < n
            && src[i + 1] == b' '
        {
            out.push(Span::new(i, i + 1, Tok::Keyword));
            i += 1;
            at_line_start = false;
            continue;
        }
        at_line_start = b == b'\n';
        // inline code `...`
        if b == b'`' {
            let start = i;
            i += 1;
            while i < n && src[i] != b'`' && src[i] != b'\n' {
                i += 1;
            }
            i = (i + 1).min(n);
            out.push(Span::new(start, i, Tok::Str));
            continue;
        }
        // emphasis *..* or **..**
        if b == b'*' || b == b'_' {
            let start = i;
            let mark = b;
            let double = i + 1 < n && src[i + 1] == mark;
            i += if double { 2 } else { 1 };
            while i < n && src[i] != mark && src[i] != b'\n' {
                i += 1;
            }
            i += if double && i + 1 < n { 2 } else { 1 };
            i = i.min(n);
            let mut sp = Span::new(start, i, Tok::Attr);
            sp.italic = true;
            out.push(sp);
            continue;
        }
        // link [text](url)
        if b == b'[' {
            if let Some(close) = src[i..].iter().position(|&c| c == b']') {
                let after = i + close + 1;
                if after < n && src[after] == b'(' {
                    if let Some(end) = src[after..].iter().position(|&c| c == b')') {
                        let mut sp = Span::new(i, after + end + 1, Tok::Link);
                        sp.underline = true;
                        out.push(sp);
                        i = after + end + 1;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(text: &str, lang: Lang) -> Vec<(usize, usize, Tok)> {
        let mut v = Vec::new();
        match lang {
            Lang::Plain => {}
            Lang::Generic(s) => tokenize_generic(text.as_bytes(), &s, &mut v),
            Lang::Json => tokenize_json(text.as_bytes(), &mut v),
            Lang::Xml => tokenize_xml(text.as_bytes(), &mut v),
            Lang::Markdown => tokenize_markdown(text.as_bytes(), &mut v),
            Lang::Yara => tokenize_yara(text.as_bytes(), &mut v),
        }
        v.iter().map(|s| (s.start, s.end, s.tok)).collect()
    }

    /// Token class covering the first byte of `needle` in `text`.
    fn tok_of(text: &str, lang: Lang, needle: &str) -> Option<Tok> {
        let at = text.find(needle)?;
        spans(text, lang)
            .into_iter()
            .find(|(s, e, _)| *s <= at && at < *e)
            .map(|(_, _, t)| t)
    }

    /// The invariant `layout_job` relies on: spans are ordered, non-overlapping,
    /// in-bounds, and land on char boundaries so slicing can never panic.
    fn assert_clean(text: &str, lang: Lang) {
        let mut cursor = 0;
        for (s, e, _) in spans(text, lang) {
            assert!(s >= cursor, "out-of-order span {s} < {cursor} in {text:?}");
            assert!(e > s, "empty/reversed span {s}..{e} in {text:?}");
            assert!(e <= text.len(), "span end {e} > len in {text:?}");
            assert!(
                text.is_char_boundary(s) && text.is_char_boundary(e),
                "non-char-boundary span {s}..{e} in {text:?}"
            );
            cursor = e;
        }
    }

    #[test]
    fn detection_by_extension() {
        assert_eq!(detect("a.js", ""), Lang::Generic(JS));
        assert_eq!(detect("a.ps1", ""), Lang::Generic(PS));
        assert_eq!(detect("a.vbs", ""), Lang::Generic(VBS));
        assert_eq!(detect("a.py", ""), Lang::Generic(PY));
        assert_eq!(detect("a.json", ""), Lang::Json);
        assert_eq!(detect("a.html", ""), Lang::Xml);
        assert_eq!(detect("a.md", ""), Lang::Markdown);
        assert_eq!(detect("rules.yar", ""), Lang::Yara);
        assert_eq!(detect("noext", ""), Lang::Plain);
    }

    #[test]
    fn detection_by_content() {
        assert_eq!(detect("x", "#!/bin/bash\necho hi"), Lang::Generic(SH));
        assert_eq!(detect("x", "#!/usr/bin/env python3\n"), Lang::Generic(PY));
        assert_eq!(detect("x", "<?php echo 1;"), Lang::Generic(PHP));
        assert_eq!(detect("x", "<?xml version=\"1.0\"?>"), Lang::Xml);
        assert_eq!(detect("x", "{\n  \"a\": 1\n}"), Lang::Json);
        assert_eq!(detect("x", "rule Foo {\n condition: true\n}"), Lang::Yara);
    }

    #[test]
    fn generic_js_tokens() {
        let src = "// c\nlet x = \"str\";\nfoo(42);";
        let l = Lang::Generic(JS);
        assert_eq!(tok_of(src, l, "// c"), Some(Tok::Comment));
        assert_eq!(tok_of(src, l, "let"), Some(Tok::Keyword));
        assert_eq!(tok_of(src, l, "\"str\""), Some(Tok::Str));
        assert_eq!(tok_of(src, l, "42"), Some(Tok::Number));
        assert_eq!(tok_of(src, l, "foo"), Some(Tok::Func));
        assert_clean(src, l);
    }

    #[test]
    fn ci_keywords_vbscript() {
        // VBScript keywords match case-insensitively.
        let src = "Dim x\nSet y = Nothing\nIf a Then\nEnd Function";
        let l = Lang::Generic(VBS);
        assert_eq!(tok_of(src, l, "Dim"), Some(Tok::Keyword));
        assert_eq!(tok_of(src, l, "Then"), Some(Tok::Keyword));
        assert_eq!(tok_of(src, l, "Function"), Some(Tok::Keyword));
    }

    #[test]
    fn json_tokens() {
        let src = "{ \"key\": \"val\", \"n\": 42, \"ok\": true, \"x\": null }";
        assert_eq!(tok_of(src, Lang::Json, "\"key\""), Some(Tok::Prop));
        assert_eq!(tok_of(src, Lang::Json, "\"val\""), Some(Tok::Str));
        assert_eq!(tok_of(src, Lang::Json, "42"), Some(Tok::Number));
        assert_eq!(tok_of(src, Lang::Json, "true"), Some(Tok::Literal));
        assert_eq!(tok_of(src, Lang::Json, "null"), Some(Tok::Literal));
        assert_clean(src, Lang::Json);
    }

    #[test]
    fn xml_tokens() {
        let src = "<!-- c --><a href=\"u\">t</a>";
        assert_eq!(tok_of(src, Lang::Xml, "<!--"), Some(Tok::Comment));
        assert_eq!(tok_of(src, Lang::Xml, "<a"), Some(Tok::Tag));
        assert_eq!(tok_of(src, Lang::Xml, "href"), Some(Tok::Attr));
        assert_eq!(tok_of(src, Lang::Xml, "\"u\""), Some(Tok::Str));
        assert_clean(src, Lang::Xml);
    }

    #[test]
    fn markdown_tokens() {
        let src = "# Head\n- item `code`\n[t](http://u)";
        assert_eq!(tok_of(src, Lang::Markdown, "# Head"), Some(Tok::Heading));
        assert_eq!(tok_of(src, Lang::Markdown, "`code`"), Some(Tok::Str));
        assert_eq!(tok_of(src, Lang::Markdown, "[t]"), Some(Tok::Link));
        assert_clean(src, Lang::Markdown);
    }

    #[test]
    fn yara_tokens() {
        let src = "rule R { strings:\n $a = \"s\" nocase\n $b = { 4D 5A [2-4] ?? }\n condition: $a and filesize < 10 }";
        let l = Lang::Yara;
        assert_eq!(tok_of(src, l, "rule"), Some(Tok::Keyword));
        assert_eq!(tok_of(src, l, "condition"), Some(Tok::Keyword));
        assert_eq!(tok_of(src, l, "nocase"), Some(Tok::Keyword));
        assert_eq!(tok_of(src, l, "and"), Some(Tok::Keyword));
        assert_eq!(tok_of(src, l, "$a"), Some(Tok::Prop));
        assert_eq!(tok_of(src, l, "\"s\""), Some(Tok::Str));
        assert_eq!(tok_of(src, l, "{ 4D"), Some(Tok::Str)); // hex byte-pattern
        assert_eq!(tok_of(src, l, "10"), Some(Tok::Number));
        assert_clean(src, l);
    }

    #[test]
    fn yara_regex_is_not_a_comment() {
        // The trickiest YARA case: `/.../ ` is a string, `//` is a comment.
        let src = "$re = /gate\\.php\\?id=[0-9]+/ ascii\n// a comment";
        assert_eq!(tok_of(src, Lang::Yara, "/gate"), Some(Tok::Str));
        assert_eq!(tok_of(src, Lang::Yara, "// a"), Some(Tok::Comment));
    }

    #[test]
    fn yara_rule_body_brace_is_not_a_hex_string() {
        // The `{` opening a rule body (text inside) must NOT be read as hex.
        let src = "rule R {\n condition: true\n}";
        assert_eq!(tok_of(src, Lang::Yara, "{\n con"), None);
    }

    #[test]
    fn adversarial_inputs_stay_clean() {
        // Unterminated / malformed input must not panic and must keep the span
        // invariant (bounded scans, valid boundaries).
        let cases = [
            "\"unterminated string",
            "/* unterminated block",
            "{ 6A 40 no closing brace",
            "$",
            "///",
            "<tag unterminated",
            "[link](no close",
            "",
            "   ",
        ];
        let langs = [
            Lang::Generic(JS),
            Lang::Generic(VBS),
            Lang::Json,
            Lang::Xml,
            Lang::Markdown,
            Lang::Yara,
        ];
        for c in cases {
            for l in langs {
                assert_clean(c, l);
            }
        }
    }

    #[test]
    fn keyword_colour_distinct_on_every_theme() {
        // The theme sanity-check: keywords must never collapse into the string or
        // number colour on any theme (Amber's amber accent ≈ numbers, Phosphor's
        // green accent ≈ strings), and keyword must differ from func.
        for t in crate::theme::Theme::ALL {
            let c = SyntaxColors::from(&crate::theme::palette(t));
            assert!(!near(c.keyword, c.string), "keyword ≈ string on {t:?}");
            assert!(!near(c.keyword, c.number), "keyword ≈ number on {t:?}");
            assert!(!near(c.func, c.keyword), "func ≈ keyword on {t:?}");
        }
    }

    #[test]
    fn multibyte_utf8_is_safe() {
        // Non-ASCII bytes inside words/strings must not split a codepoint.
        let src = "let café = \"naïve → 日本語\"; // 你好";
        assert_clean(src, Lang::Generic(JS));
        assert_clean("# 标题 `代码`", Lang::Markdown);
        assert_clean("{ \"café\": \"naïve\" }", Lang::Json);
    }
}
